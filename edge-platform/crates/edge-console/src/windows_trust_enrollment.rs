//! W4 trust enrollment by the already installed Windows LocalSystem dispatcher.
//! An accepted protected Git registry and exact current immutable ReleaseSet
//! are the ONLY authority for trust. Neither the local Administrator nor the
//! unprivileged runner may supply Worker public key, receipt public key,
//! registry, spec, or trust bytes. No SCM, network/TUN or resource mutation.
use super::*;
use edge_shared_types::{
    FleetHostAction, FleetHostIntent, FleetHostKind, FleetHostRunState, FleetNativeTrustSnapshot,
    FleetWindowsTrustEnrollment, HostRegistry, ReleaseSet,
    host_journal::require_windows_local_administrator_first_use,
    host_journal::verify_native_journal_protection,
    host_lifecycle::{digest_host_desired, verify_windows_signed_git_prerequisites},
};
use prost::Message;
use ring::digest::{SHA256, digest};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

const HOST: &str = "sing-box-windows-lab";
const SPEC: &str = "infra/production/production.textproto";
const TRUST_FILE: &str = "trust.pb";
const PUBLIC: &str = "receipt-public-key.bin";
const PRIVATE: &str = "receipt-key.pk8";
const COMPLETED: &str = "receipt-enrollment.completed.pb";
const MARKER: &str = "trust-enrollment.pb";
const DONE: &str = "trust-enrollment.completed.pb";
const MAX_JSON: usize = 262_144;
const MAX_RELEASE: usize = 65_536;
const MAX_REGISTRY: usize = 65_536;
const MAX_SPEC: usize = 65_536;

pub(super) fn verify_enrollment_marker(
    bytes: &[u8],
    active: &WindowsActivationState,
) -> Result<(), &'static str> {
    if bytes.is_empty() || bytes.len() > 512 {
        return Err("HOST_WINDOWS_TRUST_ENROLL_MARKER_SIZE_INVALID");
    }
    let request = FleetWindowsTrustEnrollment::decode(bytes)
        .map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_MARKER_PROTO_INVALID")?;
    if request.encode_to_vec() != bytes
        || request.schema_version != 1
        || request.machine_id != HOST
        || request.source_revision != active.source_revision
        || request.release_set_sha256 != active.release_set_sha256
    {
        return Err("HOST_WINDOWS_TRUST_ENROLL_MARKER_SOURCE_MISMATCH");
    }
    Ok(())
}

/// One local elevated Administrator request for exact current Git trust.
/// Keys, registry and signer identity cannot be passed by the caller.
/// Only the existing SYSTEM dispatcher is permitted to construct trust.pb.
pub(super) fn prepare(install_root: &Path) -> Result<(), String> {
    prepare_exact(install_root, false)
}

/// Authorize future Git trust in the SAME local operation as receipt identity.
/// Only the already installed SYSTEM owner performs Git verification and
/// creates trust.pb once its own Ed25519 identity exists.
pub(super) fn prepare_pending(install_root: &Path) -> Result<(), String> {
    prepare_exact(install_root, true)
}

fn prepare_exact(install_root: &Path, allow_pending_identity: bool) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let active = load_verified_activation(install_root).map_err(|e| e.to_string())?;
    require_offline_windows_owner(install_root, &active)?;
    verify_offline_bootstrap_dispatcher(&active.console_path, "Ready")?;
    let root = install_root.join("native-host");
    if allow_pending_identity {
        windows_receipt_enrollment::require_identity_request_for_trust(install_root, &active)?;
    } else {
        let proof = fs::symlink_metadata(root.join(COMPLETED))
            .map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_RECEIPT_IDENTITY_UNPROVEN")?;
        if !proof.file_type().is_file() || proof.len() == 0 || proof.len() > 512 {
            return Err("HOST_WINDOWS_TRUST_ENROLL_RECEIPT_IDENTITY_INVALID".into());
        }
        windows_receipt_enrollment::require_identity_request_for_trust(install_root, &active)?;
    }
    if root.join(TRUST_FILE).exists() || root.join(DONE).exists() {
        return Err("HOST_WINDOWS_TRUST_ENROLL_ALREADY_COMPLETED".into());
    }
    if install_root
        .join("exchange")
        .join("requests")
        .join("host-intent.pb")
        .exists()
        || privileged_request_path(install_root).exists()
    {
        return Err("HOST_WINDOWS_TRUST_ENROLL_COMPETING_REQUEST".into());
    }
    let request = FleetWindowsTrustEnrollment {
        schema_version: 1,
        machine_id: HOST.to_owned(),
        source_revision: active.source_revision.clone(),
        release_set_sha256: active.release_set_sha256.clone(),
    };
    let bytes = request.encode_to_vec();
    verify_enrollment_marker(&bytes, &active).map_err(str::to_owned)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(MARKER))
        .map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_ALREADY_REQUESTED")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_MARKER_UNCERTAIN_NO_REPLAY")?;
    println!("native_trust=PREPARED_EXACT_LOCAL_ADMIN");
    println!("native_trust_next=EXISTING_LOCALSYSTEM_TASK");
    println!("scm_mutations=0");
    println!("network_mutations=0");
    Ok(())
}

/// A pending first-use trust marker may cross an approved exact offline
/// handoff, but only once and with the same receipt identity.
pub(super) fn preflight_pending_trust_handoff(
    install_root: &Path,
    predecessor: &WindowsActivationState,
) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    let root = install_root.join("native-host");
    verify_native_journal_protection(&root.join("journal")).map_err(str::to_owned)?;
    for name in [DONE, TRUST_FILE] {
        if windows_receipt_enrollment::checked_regular_exists(
            &root.join(name),
            if name == TRUST_FILE {
                9 * 1024 * 1024
            } else {
                512
            },
        )? {
            return Err("HOST_WINDOWS_PENDING_TRUST_ALREADY_COMPLETED".into());
        }
    }
    let marker = root.join(MARKER);
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&marker, true)
        .map_err(str::to_owned)?;
    let bytes = windows_signed_host::bounded_regular_file(&marker, 512)?;
    verify_enrollment_marker(&bytes, predecessor).map_err(str::to_owned)?;
    let archive = root.join(format!(
        "{MARKER}.predecessor-{}",
        predecessor.release_set_sha256
    ));
    match fs::symlink_metadata(archive) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err("HOST_WINDOWS_PENDING_TRUST_PREDECESSOR_ALREADY_RECORDED".into()),
    }
}

/// Archive exact predecessor intent before replacing the pending marker. This
/// is an irreversible no-replay handoff under the SAME disabled SYSTEM task.
pub(super) fn rebind_pending_trust_after_offline_handoff(
    install_root: &Path,
    predecessor: &WindowsActivationState,
) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let current = load_verified_activation(install_root).map_err(|e| e.to_string())?;
    if current.release_set_sha256 == predecessor.release_set_sha256 {
        return Err("HOST_WINDOWS_PENDING_TRUST_HANDOFF_NOT_DISTINCT".into());
    }
    require_offline_windows_owner(install_root, &current)?;
    verify_offline_bootstrap_dispatcher(&current.console_path, "Disabled")?;
    preflight_pending_trust_handoff(install_root, predecessor)?;
    let root = install_root.join("native-host");
    let marker = root.join(MARKER);
    let before = windows_signed_host::bounded_regular_file(&marker, 512)?;
    let archive = root.join(format!(
        "{MARKER}.predecessor-{}",
        predecessor.release_set_sha256
    ));
    fs::hard_link(&marker, &archive)
        .map_err(|_| "HOST_WINDOWS_PENDING_TRUST_ARCHIVE_UNKNOWN_NO_REPLAY")?;
    if windows_signed_host::bounded_regular_file(&archive, 512)? != before {
        return Err("HOST_WINDOWS_PENDING_TRUST_ARCHIVE_CHANGED_NO_REPLAY".into());
    }
    File::open(&archive)
        .and_then(|file| file.sync_all())
        .map_err(|_| "HOST_WINDOWS_PENDING_TRUST_ARCHIVE_SYNC_UNKNOWN_NO_REPLAY")?;
    let next = FleetWindowsTrustEnrollment {
        schema_version: 1,
        machine_id: HOST.into(),
        source_revision: current.source_revision.clone(),
        release_set_sha256: current.release_set_sha256.clone(),
    };
    let bytes = next.encode_to_vec();
    verify_enrollment_marker(&bytes, &current).map_err(str::to_owned)?;
    fs::remove_file(&marker).map_err(|_| "HOST_WINDOWS_PENDING_TRUST_UNLINK_UNKNOWN_NO_REPLAY")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .map_err(|_| "HOST_WINDOWS_PENDING_TRUST_CREATE_UNKNOWN_NO_REPLAY")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "HOST_WINDOWS_PENDING_TRUST_WRITE_UNKNOWN_NO_REPLAY")?;
    if windows_signed_host::bounded_regular_file(&marker, 512)? != bytes {
        return Err("HOST_WINDOWS_PENDING_TRUST_READBACK_UNPROVEN_NO_REPLAY".into());
    }
    Ok(())
}

/// Derived read-only state, never a second journal or source of authority.
pub(super) fn first_use_trust_present(root: &Path) -> Result<bool, String> {
    for name in [MARKER, DONE, TRUST_FILE] {
        if windows_receipt_enrollment::checked_regular_exists(
            &root.join(name),
            if name == TRUST_FILE {
                9 * 1024 * 1024
            } else {
                512
            },
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn read_only_first_use_trust_stage(
    root: &Path,
    active: &WindowsActivationState,
) -> Result<&'static str, String> {
    let marker = root.join(MARKER);
    let done = root.join(DONE);
    let has_marker = windows_receipt_enrollment::checked_regular_exists(&marker, 512)?;
    let has_done = windows_receipt_enrollment::checked_regular_exists(&done, 512)?;
    let has_trust = windows_receipt_enrollment::checked_regular_exists(
        &root.join(TRUST_FILE),
        9 * 1024 * 1024,
    )?;
    if has_marker {
        let bytes =
            fs::read(&marker).map_err(|_| "HOST_WINDOWS_FIRST_USE_TRUST_MARKER_UNREADABLE")?;
        verify_enrollment_marker(&bytes, active).map_err(str::to_owned)?;
        if has_done
            && fs::read(&done).map_err(|_| "HOST_WINDOWS_FIRST_USE_TRUST_DONE_UNREADABLE")? != bytes
        {
            return Err("HOST_WINDOWS_FIRST_USE_TRUST_MARKER_MISMATCH_NO_REPLAY".into());
        }
    } else if has_done {
        let bytes = fs::read(&done).map_err(|_| "HOST_WINDOWS_FIRST_USE_TRUST_DONE_UNREADABLE")?;
        if verify_enrollment_marker(&bytes, active).is_err() {
            let marker = FleetWindowsTrustEnrollment::decode(bytes.as_slice())
                .map_err(|_| "HOST_WINDOWS_TRUST_HISTORY_MARKER_INVALID")?;
            let install = root
                .parent()
                .ok_or("HOST_WINDOWS_TRUST_HISTORY_ROOT_INVALID")?;
            let historical = windows_receipt_enrollment::historical_marker_activation(
                install,
                &marker.source_revision,
                &marker.release_set_sha256,
            )?;
            verify_enrollment_marker(&bytes, &historical)?;
        }
    }
    if !has_trust && has_done {
        return Err("HOST_WINDOWS_FIRST_USE_TRUST_DONE_WITHOUT_SNAPSHOT".into());
    }
    if has_trust {
        if !has_marker && !has_done {
            return Err("HOST_WINDOWS_FIRST_USE_ORPHAN_TRUST_SNAPSHOT".into());
        }
        let bytes = fs::read(root.join(TRUST_FILE))
            .map_err(|_| "HOST_WINDOWS_FIRST_USE_TRUST_SNAPSHOT_UNREADABLE")?;
        let snapshot = FleetNativeTrustSnapshot::decode(bytes.as_slice())
            .map_err(|_| "HOST_WINDOWS_FIRST_USE_TRUST_SNAPSHOT_PROTO_INVALID")?;
        if snapshot.encode_to_vec() != bytes
            || snapshot.schema_version != 1
            || snapshot.machine_id != HOST
            || snapshot.pinned_worker_public_key.len() != 32
            || snapshot.release_set_pb.is_empty()
        {
            return Err("HOST_WINDOWS_FIRST_USE_TRUST_SNAPSHOT_INVALID".into());
        }
        let recorded = sha_hex(&snapshot.release_set_pb);
        if recorded != active.release_set_sha256 {
            let old = ReleaseSet::decode(snapshot.release_set_pb.as_slice())
                .map_err(|_| "HOST_WINDOWS_FIRST_USE_TRUST_HISTORY_RELEASE_INVALID")?;
            let install = root
                .parent()
                .ok_or("HOST_WINDOWS_FIRST_USE_TRUST_HISTORY_ROOT_INVALID")?;
            windows_receipt_enrollment::historical_marker_activation(
                install,
                &old.source_revision,
                &recorded,
            )?;
        }
        // This read-only local projection is NOT live Worker attestation.
        return Ok("TRUST_RECORDED_UNVERIFIED");
    }
    if has_marker {
        Ok("AWAITING_GIT_AUTHORITY_OR_SYSTEM")
    } else {
        Ok("RECEIPT_READY_TRUST_NOT_REQUESTED")
    }
}

fn complete_trust_marker(root: &Path) -> Result<(), String> {
    let marker = root.join(MARKER);
    let completed = root.join(DONE);
    match fs::symlink_metadata(&completed) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::hard_link(&marker, &completed)
                .map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_ARCHIVE_UNCERTAIN_NO_REPLAY")?;
        }
        Err(_) => return Err("HOST_WINDOWS_TRUST_ENROLL_ARCHIVE_METADATA_UNAVAILABLE".into()),
        Ok(meta) if !meta.file_type().is_file() => {
            return Err("HOST_WINDOWS_TRUST_ENROLL_ARCHIVE_INVALID".into());
        }
        Ok(_) => {
            if fs::read(&completed).map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_ARCHIVE_UNREADABLE")?
                != fs::read(&marker).map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_MARKER_UNREADABLE")?
            {
                return Err("HOST_WINDOWS_TRUST_ENROLL_ARCHIVE_MISMATCH".into());
            }
        }
    }
    fs::remove_file(marker)
        .map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_UNLINK_UNCERTAIN_NO_REPLAY".into())
}

fn sha_hex(data: &[u8]) -> String {
    digest(&SHA256, data)
        .as_ref()
        .iter()
        .map(|n| format!("{n:02x}"))
        .collect()
}

fn exact_github_provenance(
    head: &serde_json::Value,
    release: &serde_json::Value,
    tag_ref: &serde_json::Value,
    active: &WindowsActivationState,
) -> Result<(), &'static str> {
    let tag = format!("edge-release-{}", active.release_set_sha256);
    let protected_main = head["object"]["sha"].as_str();
    // Historical installed release must be an authentic immutable published
    // release. Git HEAD may advance when registering PUBLIC host pins; its
    // ancestry is verified independently before any new registry is trusted.
    let old_merge = release["target_commitish"].as_str();
    if head["object"]["type"].as_str() != Some("commit")
        || !protected_main.is_some_and(exact_git_revision)
        || !old_merge.is_some_and(exact_git_revision)
        || release["tag_name"].as_str() != Some(tag.as_str())
        || release["draft"].as_bool() != Some(false)
        || release["prerelease"].as_bool() != Some(false)
        || release["published_at"].as_str().is_none()
        || tag_ref["object"]["type"].as_str() != Some("commit")
        || tag_ref["object"]["sha"].as_str() != old_merge
    {
        return Err("HOST_WINDOWS_TRUST_GITHUB_MAIN_RELEASE_TAG_NOT_EXACT");
    }
    Ok(())
}

fn exact_git_revision(sha: &str) -> bool {
    sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The new protected Git registry is released independently of the old
/// installed Windows binaries; no reinstallation merely to publish a key.
fn exact_current_registry_release(
    head: &serde_json::Value,
    release: &serde_json::Value,
    tag_ref: &serde_json::Value,
) -> Result<String, &'static str> {
    let protected_main = head["object"]["sha"].as_str();
    let published = release["tag_name"].as_str();
    let released_digest = published.and_then(|tag| tag.strip_prefix("edge-release-"));
    if head["object"]["type"].as_str() != Some("commit")
        || !protected_main.is_some_and(exact_git_revision)
        || !released_digest.is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || release["target_commitish"].as_str() != protected_main
        || release["draft"].as_bool() != Some(false)
        || release["prerelease"].as_bool() != Some(false)
        || release["published_at"].as_str().is_none()
        || tag_ref["object"]["type"].as_str() != Some("commit")
        || tag_ref["object"]["sha"].as_str() != protected_main
    {
        return Err("HOST_WINDOWS_TRUST_CURRENT_GIT_RELEASE_NOT_EXACT");
    }
    Ok(released_digest.unwrap_or_default().to_owned())
}

fn exact_installed_git_ancestor(
    compare: &serde_json::Value,
    installed_merge: &str,
    current_main: &str,
) -> Result<(), &'static str> {
    let status = compare["status"].as_str();
    if !exact_git_revision(installed_merge)
        || !exact_git_revision(current_main)
        || !matches!(status, Some("ahead" | "identical"))
        || compare["base_commit"]["sha"].as_str() != Some(installed_merge)
        || compare["merge_base_commit"]["sha"].as_str() != Some(installed_merge)
    {
        return Err("HOST_WINDOWS_TRUST_INSTALLED_GIT_NOT_CANONICAL_ANCESTOR");
    }
    Ok(())
}

pub(super) async fn fetch_bounded(
    client: &reqwest::Client,
    url: &str,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "HOST_WINDOWS_TRUST_SOURCE_URL_INVALID")?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("HOST_WINDOWS_TRUST_SOURCE_URL_NOT_HTTPS".into());
    }
    let mut reply = client
        .get(parsed)
        .header("User-Agent", "sing-box-windows-native-trust")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "HOST_WINDOWS_TRUST_SOURCE_FETCH_FAILED")?;
    if !reply.status().is_success()
        || reply
            .content_length()
            .is_some_and(|n| n == 0 || n > limit as u64)
    {
        return Err("HOST_WINDOWS_TRUST_SOURCE_RESPONSE_REJECTED".into());
    }
    let mut bytes = Vec::new();
    while let Some(part) = reply
        .chunk()
        .await
        .map_err(|_| "HOST_WINDOWS_TRUST_SOURCE_RESPONSE_INCOMPLETE")?
    {
        if part.len() > limit.saturating_sub(bytes.len()) {
            return Err("HOST_WINDOWS_TRUST_SOURCE_TOO_LARGE".into());
        }
        bytes.extend_from_slice(&part);
    }
    if bytes.is_empty() {
        return Err("HOST_WINDOWS_TRUST_SOURCE_EMPTY".into());
    }
    Ok(bytes)
}

pub(super) async fn fetch_json(
    client: &reqwest::Client,
    url: &str,
) -> Result<serde_json::Value, String> {
    let bytes = fetch_bounded(client, url, MAX_JSON).await?;
    serde_json::from_slice(&bytes).map_err(|_| "HOST_WINDOWS_TRUST_SOURCE_JSON_INVALID".into())
}

async fn accepted_asset(
    client: &reqwest::Client,
    release: &serde_json::Value,
    tag: &str,
    name: &str,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let assets = release["assets"]
        .as_array()
        .ok_or("HOST_WINDOWS_TRUST_RELEASE_ASSETS_MISSING")?;
    let found: Vec<_> = assets
        .iter()
        .filter(|a| a["name"].as_str() == Some(name))
        .collect();
    if found.len() != 1 {
        return Err("HOST_WINDOWS_TRUST_RELEASE_ASSET_NOT_UNIQUE".into());
    }
    let url = format!("https://github.com/iamaman11/sing-box/releases/download/{tag}/{name}");
    if found[0]["browser_download_url"].as_str() != Some(url.as_str()) {
        return Err("HOST_WINDOWS_TRUST_RELEASE_ASSET_URL_MISMATCH".into());
    }
    let expected = found[0]["digest"]
        .as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .ok_or("HOST_WINDOWS_TRUST_RELEASE_DIGEST_MISSING")?;
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("HOST_WINDOWS_TRUST_RELEASE_DIGEST_INVALID".into());
    }
    let bytes = fetch_bounded(client, &url, limit).await?;
    if sha_hex(&bytes) != expected {
        return Err("HOST_WINDOWS_TRUST_RELEASE_ASSET_DIGEST_MISMATCH".into());
    }
    Ok(bytes)
}

fn exact_windows_registration(
    registry_pb: &[u8],
    release_pb: &[u8],
    spec: &[u8],
    active: &WindowsActivationState,
    receipt_private: &[u8],
    receipt_public: &[u8],
) -> Result<FleetNativeTrustSnapshot, String> {
    if registry_pb.is_empty()
        || registry_pb.len() > MAX_REGISTRY
        || release_pb.is_empty()
        || release_pb.len() > MAX_RELEASE
        || spec.is_empty()
        || spec.len() > MAX_SPEC
    {
        return Err("HOST_WINDOWS_TRUST_ARTIFACT_SIZE_INVALID".into());
    }
    if sha_hex(release_pb) != active.release_set_sha256 {
        return Err("HOST_WINDOWS_TRUST_INSTALLED_RELEASE_MISMATCH".into());
    }
    let release =
        ReleaseSet::decode(release_pb).map_err(|_| "HOST_WINDOWS_TRUST_RELEASE_PROTO_INVALID")?;
    if release.encode_to_vec() != release_pb || release.source_revision != active.source_revision {
        return Err("HOST_WINDOWS_TRUST_RELEASE_SOURCE_MISMATCH".into());
    }
    let registry: HostRegistry = edge_shared_types::decode_host_registry(registry_pb)
        .map_err(|_| "HOST_WINDOWS_TRUST_REGISTRY_INVALID")?;
    let host = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == HOST && h.kind == FleetHostKind::Windows as i32)
        .ok_or("HOST_WINDOWS_TRUST_MACHINE_NOT_REGISTERED")?;
    if host.desired_spec_path != SPEC
        || host.windows_runner_label != "sing-box-windows-lab"
        || !matches!(host.owner.as_ref(), Some(edge_shared_types::managed_host::Owner::WindowsRunnerName(n)) if n == "DESKTOP-0E1F6UQ")
        || !matches!(host.target.as_ref(),
            Some(target) if target.run_state == FleetHostRunState::Stopped as i32)
    {
        return Err("HOST_WINDOWS_TRUST_GIT_OWNER_OR_TARGET_INVALID".into());
    }
    // Enroll the existing stopped owner against the exact Git mode, whether
    // ProxyOnly or ManagedTun. Trust enrollment never starts a TUN; actual
    // route-capturing effects remain blocked at the native SYSTEM gate.
    let desired = edge_shared_types::parse_production_desired_text(spec)?;
    edge_shared_types::host_lifecycle::validate_windows_mode_target_and_spec(host, &desired)?;
    verify_windows_signed_git_prerequisites(host).map_err(str::to_owned)?;
    if receipt_public.len() != 32 || host.native_receipt_public_key != receipt_public {
        return Err("HOST_WINDOWS_TRUST_GIT_RECEIPT_PIN_MISMATCH".into());
    }
    edge_shared_types::host_receipt::check_native_receipt_key(host, receipt_private)
        .map_err(str::to_owned)?;
    let pinned = host.worker_authority_public_key.clone();
    let intent = FleetHostIntent {
        schema_version: 1,
        machine_id: HOST.to_owned(),
        kind: FleetHostKind::Windows as i32,
        resource_id: "sing-box".into(),
        operation_id: "windows-trust-enrollment".into(),
        action: FleetHostAction::Stop as i32,
        requested_at_unix: 1,
        registry_sha256: digest(&SHA256, registry_pb).as_ref().to_vec(),
        desired_sha256: digest_host_desired(host, spec).map_err(str::to_owned)?,
        release_set_sha256: digest(&SHA256, release_pb).as_ref().to_vec(),
        ..Default::default()
    };
    let trust = FleetNativeTrustSnapshot {
        schema_version: 1,
        machine_id: HOST.into(),
        registry_pb: registry_pb.to_vec(),
        release_set_pb: release_pb.to_vec(),
        selected_spec_bytes: spec.to_vec(),
        application_bundle_pb: Vec::new(),
        pinned_worker_public_key: pinned,
    };
    windows_signed_host::verify_system_trust(
        &trust.encode_to_vec(),
        &intent,
        &active.release_set_sha256,
        receipt_private,
    )
    .map_err(str::to_owned)?;
    Ok(trust)
}

pub(super) async fn fetch_exact_protected_git(
    active: &WindowsActivationState,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|_| "HOST_WINDOWS_TRUST_TLS_CLIENT_UNAVAILABLE")?;
    let base = "https://api.github.com/repos/iamaman11/sing-box";
    let tag = format!("edge-release-{}", active.release_set_sha256);
    let main_url = format!("{base}/git/ref/heads/main");
    let release_url = format!("{base}/releases/tags/{tag}");
    let tag_url = format!("{base}/git/ref/tags/{tag}");
    let current_release_url = format!("{base}/releases/latest");
    let (head, installed_release, installed_tag, current_release) = tokio::try_join!(
        fetch_json(&client, &main_url),
        fetch_json(&client, &release_url),
        fetch_json(&client, &tag_url),
        fetch_json(&client, &current_release_url),
    )?;
    exact_github_provenance(&head, &installed_release, &installed_tag, active)
        .map_err(str::to_owned)?;
    let current_main = head["object"]["sha"]
        .as_str()
        .ok_or("HOST_WINDOWS_TRUST_GITHUB_MAIN_MISSING")?;
    let installed_merge = installed_release["target_commitish"]
        .as_str()
        .ok_or("HOST_WINDOWS_TRUST_INSTALLED_MERGE_MISSING")?;
    let current_tag = current_release["tag_name"]
        .as_str()
        .ok_or("HOST_WINDOWS_TRUST_CURRENT_RELEASE_TAG_MISSING")?;
    // Reject malformed tag BEFORE using untrusted release metadata in a URL.
    let candidate_digest = current_tag
        .strip_prefix("edge-release-")
        .ok_or("HOST_WINDOWS_TRUST_CURRENT_RELEASE_TAG_INVALID")?;
    if candidate_digest.len() != 64
        || !candidate_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("HOST_WINDOWS_TRUST_CURRENT_RELEASE_TAG_INVALID".into());
    }
    // Neither the runner nor the Administrator supplies registry bytes.
    // The published latest release must point EXACTLY at protected Git main.
    let current_tag_url = format!("{base}/git/ref/tags/{current_tag}");
    let compare_url = format!("{base}/compare/{installed_merge}...{current_main}");
    let (current_tag_ref, ancestry) = tokio::try_join!(
        fetch_json(&client, &current_tag_url),
        fetch_json(&client, &compare_url),
    )?;
    let current_digest = exact_current_registry_release(&head, &current_release, &current_tag_ref)
        .map_err(str::to_owned)?;
    exact_installed_git_ancestor(&ancestry, installed_merge, current_main)
        .map_err(str::to_owned)?;
    let spec_url = format!(
        "https://raw.githubusercontent.com/iamaman11/sing-box/{}/{}",
        current_main, SPEC
    );
    let (installed_release_pb, current_release_pb, registry_pb, spec) = tokio::try_join!(
        accepted_asset(
            &client,
            &installed_release,
            &tag,
            "release-set.pb",
            MAX_RELEASE
        ),
        accepted_asset(
            &client,
            &current_release,
            current_tag,
            "release-set.pb",
            MAX_RELEASE
        ),
        accepted_asset(
            &client,
            &current_release,
            current_tag,
            "fleet-registry.pb",
            MAX_REGISTRY
        ),
        fetch_bounded(&client, &spec_url, MAX_SPEC),
    )?;
    if sha_hex(&installed_release_pb) != active.release_set_sha256
        || sha_hex(&current_release_pb) != current_digest
    {
        return Err("HOST_WINDOWS_TRUST_RELEASE_DIGEST_MISMATCH".into());
    }
    let current_provenance = ReleaseSet::decode(current_release_pb.as_slice())
        .map_err(|_| "HOST_WINDOWS_TRUST_CURRENT_RELEASE_PROTO_INVALID")?;
    if current_provenance.encode_to_vec() != current_release_pb
        || current_provenance.source_revision != current_main
    {
        return Err("HOST_WINDOWS_TRUST_CURRENT_RELEASE_SOURCE_MISMATCH".into());
    }
    // Fail closed if protected main moved during the multi-source fetch.
    // A later SYSTEM tick can evaluate the new state; no bytes are committed.
    let current_head_again = fetch_json(&client, &main_url).await?;
    if current_head_again != head {
        return Err("HOST_WINDOWS_TRUST_GIT_CHANGED_DURING_FETCH".into());
    }
    Ok((installed_release_pb, current_release_pb, registry_pb, spec))
}

/// Called ONLY from the existing periodic LocalSystem task, never a new
/// endpoint. Absence of an enrolled receipt identity is a normal NOOP.
/// An accepted exact protected Git source with both public keys is mandatory
/// before creating trust.pb. A GitHub runner cannot supply trust material.
pub(super) async fn dispatch_if_needed(install_root: &Path) -> Result<(), String> {
    if install_root != Path::new(r"C:\sing-box") {
        return Err("HOST_WINDOWS_TRUST_ROOT_INVALID".into());
    }
    let root = install_root.join("native-host");
    let marker = root.join(MARKER);
    let marker_meta = match fs::symlink_metadata(&marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("HOST_WINDOWS_TRUST_ENROLL_MARKER_METADATA_UNAVAILABLE".into()),
        Ok(meta) => meta,
    };
    if !marker_meta.file_type().is_file() || marker_meta.len() == 0 || marker_meta.len() > 512 {
        return Err("HOST_WINDOWS_TRUST_ENROLL_MARKER_INVALID".into());
    }
    if !root.join(COMPLETED).is_file() {
        // Trust and receipt markers may have been created by ONE local
        // enrollment. On the first tick SYSTEM creates the key; on a later
        // tick this existing trust marker resumes without a second admin.
        let installed = load_verified_activation(install_root)
            .map_err(|_| "HOST_WINDOWS_TRUST_ACTIVATION_UNAVAILABLE")?;
        windows_receipt_enrollment::require_identity_request_for_trust(install_root, &installed)?;
        println!("native_trust=AWAITING_SYSTEM_RECEIPT_IDENTITY");
        return Ok(());
    }
    // Never synthesize authority when a pending native mutation exists.
    if install_root
        .join("exchange")
        .join("requests")
        .join("host-intent.pb")
        .exists()
        || privileged_request_path(install_root).exists()
    {
        return Ok(());
    }
    require_exact_immutable_activation_console(install_root)?;
    verify_native_journal_protection(&root.join("journal")).map_err(str::to_owned)?;
    let active = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    require_offline_windows_owner(install_root, &active)?;
    let marker_bytes =
        fs::read(&marker).map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_MARKER_UNREADABLE")?;
    verify_enrollment_marker(&marker_bytes, &active).map_err(str::to_owned)?;
    let public =
        fs::read(root.join(PUBLIC)).map_err(|_| "HOST_WINDOWS_TRUST_PUBLIC_IDENTITY_MISSING")?;
    let key_path = root.join(PRIVATE);
    let key_meta = fs::symlink_metadata(&key_path)
        .map_err(|_| "HOST_WINDOWS_TRUST_PRIVATE_IDENTITY_MISSING")?;
    if !key_meta.file_type().is_file() || key_meta.len() == 0 || key_meta.len() > 4096 {
        return Err("HOST_WINDOWS_TRUST_PRIVATE_IDENTITY_INVALID".into());
    }
    let private =
        fs::read(&key_path).map_err(|_| "HOST_WINDOWS_TRUST_PRIVATE_IDENTITY_UNREADABLE")?;
    let (release_pb, _current_release_pb, registry_pb, spec) =
        fetch_exact_protected_git(&active).await?;
    let trust = match exact_windows_registration(
        &registry_pb,
        &release_pb,
        &spec,
        &active,
        &private,
        &public,
    ) {
        Ok(snapshot) => snapshot,
        Err(reason)
            if matches!(
                reason.as_str(),
                "HOST_GIT_WORKER_SIGNER_KEY_REQUIRED"
                    | "HOST_WINDOWS_GIT_RECEIPT_REGISTRATION_REQUIRED"
            ) =>
        {
            // The public pin is not yet in the new protected Git release.
            // This is a recoverable waiting state, not permission to use an
            // unpinned key or repeat an earlier native mutation.
            println!("native_trust=AWAITING_GIT_AUTHORITY");
            println!("native_trust_reason={reason}");
            return Ok(());
        }
        Err(reason) => return Err(reason),
    };
    // The trust is created ONLY after this currently serving Worker has
    // signed our fresh nonce with the exact public key in protected Git.
    // This GET never mints HostAuthorization and cannot change SCM or network.
    edge_secrets::prove_canonical_host_signer(
        &install_root
            .join("state")
            .join("secrets")
            .join(ACCESS_IDENTITY_FILE_NAME),
        &trust.pinned_worker_public_key,
    )
    .await?;
    // GitHub GETs can take seconds. Re-observe the physical installed
    // authority, owner and immutable typed request immediately before the
    // only trust write; a concurrent release/task/marker change is a denial.
    let current = load_verified_activation(install_root).map_err(|e| e.to_string())?;
    if current != active {
        return Err("HOST_WINDOWS_TRUST_ENROLL_ACTIVATION_CHANGED_BEFORE_WRITE".into());
    }
    require_offline_windows_owner(install_root, &current)?;
    verify_native_journal_protection(&root.join("journal")).map_err(str::to_owned)?;
    let request_now =
        fs::read(&marker).map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_MARKER_CHANGED_BEFORE_WRITE")?;
    if request_now != marker_bytes {
        return Err("HOST_WINDOWS_TRUST_ENROLL_MARKER_CHANGED_BEFORE_WRITE".into());
    }
    let bytes = trust.encode_to_vec();
    let dest = root.join(TRUST_FILE);
    // The canonical native-host ACL already restricts write to SYSTEM and
    // BUILTIN Administrators. Trust is created ONCE and never overwritten by
    // periodic checks. The native signed handler revalidates it per request.
    if dest.exists() {
        let previous = fs::read(&dest).map_err(|_| "HOST_WINDOWS_TRUST_EXISTING_UNREADABLE")?;
        if previous != bytes {
            return Err("HOST_WINDOWS_TRUST_EXISTING_MISMATCH_NO_REPLAY".into());
        }
    } else {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
            .map_err(|_| "HOST_WINDOWS_TRUST_CREATE_ONLY_REFUSED")?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "HOST_WINDOWS_TRUST_WRITE_UNCERTAIN_NO_REPLAY")?;
    }
    run_icacls(&dest, &["/inheritance:r", "/Q"])?;
    run_icacls(&dest, &["/grant:r", "*S-1-5-18:F", "/Q"])?;
    run_icacls(&dest, &["/remove:g", "*S-1-5-32-544", "/Q"])?;
    run_icacls(&dest, &["/setowner", "*S-1-5-18", "/Q"])?;
    complete_trust_marker(&root)?;
    println!("native_trust=ENROLLED_EXACT_PROTECTED_GIT");
    println!("native_trust_machine={HOST}");
    println!("native_trust_release={}", active.release_set_sha256);
    println!(
        "native_trust_worker_key_sha256={}",
        sha_hex(&trust.pinned_worker_public_key)
    );
    println!("scm_mutations=0");
    println!("network_mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_only_trust_stage_never_calls_a_recorded_snapshot_authorized() {
        let dir = std::env::temp_dir().join(format!("w4-trust-readonly-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let release = b"old installed immutable bytes";
        let active = WindowsActivationState {
            schema_version: 1,
            source_revision: "a".repeat(40),
            release_set_sha256: sha_hex(release),
            ..Default::default()
        };
        assert_eq!(
            read_only_first_use_trust_stage(&dir, &active),
            Ok("RECEIPT_READY_TRUST_NOT_REQUESTED")
        );
        let marker = FleetWindowsTrustEnrollment {
            schema_version: 1,
            machine_id: HOST.into(),
            source_revision: active.source_revision.clone(),
            release_set_sha256: active.release_set_sha256.clone(),
        };
        std::fs::write(dir.join(MARKER), marker.encode_to_vec()).unwrap();
        assert_eq!(
            read_only_first_use_trust_stage(&dir, &active),
            Ok("AWAITING_GIT_AUTHORITY_OR_SYSTEM")
        );
        let snapshot = FleetNativeTrustSnapshot {
            schema_version: 1,
            machine_id: HOST.into(),
            release_set_pb: release.to_vec(),
            pinned_worker_public_key: vec![7; 32],
            ..Default::default()
        };
        std::fs::write(dir.join(TRUST_FILE), snapshot.encode_to_vec()).unwrap();
        assert_eq!(
            read_only_first_use_trust_stage(&dir, &active),
            Ok("TRUST_RECORDED_UNVERIFIED")
        );
        std::fs::write(dir.join(TRUST_FILE), b"bad protobuf").unwrap();
        assert!(read_only_first_use_trust_stage(&dir, &active).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn trust_marker_binds_exact_host_and_installed_release() {
        let active = WindowsActivationState {
            source_revision: "a".repeat(40),
            release_set_sha256: "b".repeat(64),
            ..Default::default()
        };
        let req = FleetWindowsTrustEnrollment {
            schema_version: 1,
            machine_id: HOST.into(),
            source_revision: active.source_revision.clone(),
            release_set_sha256: active.release_set_sha256.clone(),
        };
        let bytes = req.encode_to_vec();
        assert_eq!(verify_enrollment_marker(&bytes, &active), Ok(()));
        let mut wrong = req.clone();
        wrong.machine_id = "foreign-host".into();
        assert!(verify_enrollment_marker(&wrong.encode_to_vec(), &active).is_err());
        wrong = req.clone();
        wrong.release_set_sha256 = "c".repeat(64);
        assert!(verify_enrollment_marker(&wrong.encode_to_vec(), &active).is_err());
        wrong = req.clone();
        wrong.source_revision = "d".repeat(40);
        assert!(verify_enrollment_marker(&wrong.encode_to_vec(), &active).is_err());
        wrong = req;
        wrong.schema_version = 2;
        assert!(verify_enrollment_marker(&wrong.encode_to_vec(), &active).is_err());
        assert!(verify_enrollment_marker(b"not-protobuf", &active).is_err());
        assert!(verify_enrollment_marker(&[], &active).is_err());
    }

    #[test]
    fn completed_trust_request_is_archived_once_without_replay() {
        let dir = std::env::temp_dir().join(format!("w4-trust-marker-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(MARKER), b"exact durable marker").unwrap();
        complete_trust_marker(&dir).unwrap();
        assert!(!dir.join(MARKER).exists());
        assert_eq!(
            std::fs::read(dir.join(DONE)).unwrap(),
            b"exact durable marker"
        );
        std::fs::hard_link(dir.join(DONE), dir.join(MARKER)).unwrap();
        complete_trust_marker(&dir).unwrap();
        assert!(dir.join(DONE).exists());
        assert!(!dir.join(MARKER).exists());
        std::fs::write(dir.join(MARKER), b"foreign marker").unwrap();
        assert!(complete_trust_marker(&dir).is_err());
        assert!(dir.join(MARKER).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trust_distinguishes_protected_merge_from_compiled_source() {
        let active = WindowsActivationState {
            // Source of the actual Windows binaries, before the protected merge.
            source_revision: "a".repeat(40),
            release_set_sha256: "b".repeat(64),
            ..Default::default()
        };
        let merged_main = "c".repeat(40);
        assert_ne!(merged_main, active.source_revision);
        let tag = format!("edge-release-{}", active.release_set_sha256);
        let head = serde_json::json!({"object":{"type":"commit","sha":merged_main}});
        let release = serde_json::json!({
            "target_commitish":merged_main,
            "tag_name":tag,"draft":false,"prerelease":false,
            "published_at":"2026-10-28T00:00:00Z"
        });
        let git_tag = serde_json::json!({"object":{"type":"commit","sha":merged_main}});
        assert_eq!(
            exact_github_provenance(&head, &release, &git_tag, &active),
            Ok(())
        );
        // Git HEAD legitimately advances after PUBLIC pin registration:
        // old immutable release remains valid, ancestry is checked separately.
        let mut advanced = head.clone();
        advanced["object"]["sha"] = serde_json::json!("d".repeat(40));
        assert!(exact_github_provenance(&advanced, &release, &git_tag, &active).is_ok());
        let mut invalid_head = head.clone();
        invalid_head["object"]["type"] = serde_json::json!("tree");
        assert!(exact_github_provenance(&invalid_head, &release, &git_tag, &active).is_err());
        let mut wrong_release = release.clone();
        wrong_release["target_commitish"] = serde_json::json!(active.source_revision);
        assert!(exact_github_provenance(&head, &wrong_release, &git_tag, &active).is_err());
        let mut draft = release.clone();
        draft["draft"] = serde_json::json!(true);
        assert!(exact_github_provenance(&head, &draft, &git_tag, &active).is_err());
        let mut foreign = git_tag.clone();
        foreign["object"]["sha"] = serde_json::json!("e".repeat(40));
        assert!(exact_github_provenance(&head, &release, &foreign, &active).is_err());
        let mut missing_published = release;
        missing_published["published_at"] = serde_json::Value::Null;
        assert!(exact_github_provenance(&head, &missing_published, &git_tag, &active).is_err());
    }

    #[test]
    fn current_git_registration_requires_its_own_exact_release_and_tag() {
        let head_sha = "a".repeat(40);
        let head = serde_json::json!({"object":{"type":"commit","sha":head_sha}});
        let tag = format!("edge-release-{}", "b".repeat(64));
        let release = serde_json::json!({
            "target_commitish":head_sha,"tag_name":tag,
            "draft":false,"prerelease":false,"published_at":"2026-10-29T00:00:00Z"
        });
        let tag_ref = serde_json::json!({"object":{"type":"commit","sha":head_sha}});
        assert_eq!(
            exact_current_registry_release(&head, &release, &tag_ref),
            Ok("b".repeat(64))
        );
        let mut moved = head.clone();
        moved["object"]["sha"] = serde_json::json!("c".repeat(40));
        assert!(exact_current_registry_release(&moved, &release, &tag_ref).is_err());
        let mut wrong_tag = tag_ref.clone();
        wrong_tag["object"]["sha"] = serde_json::json!("d".repeat(40));
        assert!(exact_current_registry_release(&head, &release, &wrong_tag).is_err());
        let mut draft = release.clone();
        draft["draft"] = serde_json::json!(true);
        assert!(exact_current_registry_release(&head, &draft, &tag_ref).is_err());
    }

    #[test]
    fn old_installed_git_merge_must_be_ancestor_of_new_pin_registry() {
        let old = "a".repeat(40);
        let current = "b".repeat(40);
        let mut compare = serde_json::json!({
            "status":"ahead", "base_commit":{"sha":old},
            "merge_base_commit":{"sha":old}
        });
        assert!(exact_installed_git_ancestor(&compare, &old, &current).is_ok());
        compare["merge_base_commit"]["sha"] = serde_json::json!("c".repeat(40));
        assert!(exact_installed_git_ancestor(&compare, &old, &current).is_err());
        compare["merge_base_commit"]["sha"] = serde_json::json!(old);
        compare["status"] = serde_json::json!("diverged");
        assert!(exact_installed_git_ancestor(&compare, &old, &current).is_err());
    }

    #[test]
    fn local_first_use_cli_never_accepts_a_human_source_revision() {
        use crate::cli::{Cli, Command};
        use clap::Parser as _;
        let identity = Cli::try_parse_from(["edge-console", "offline-receipt-identity-prepare"])
            .expect("identity enrollment only requires installed immutable owner");
        assert!(matches!(
            identity.command,
            Some(Command::OfflineReceiptIdentityPrepare(_))
        ));
        let trust = Cli::try_parse_from(["edge-console", "offline-host-trust-prepare"])
            .expect("trust enrollment only requires installed immutable owner");
        assert!(matches!(
            trust.command,
            Some(Command::OfflineHostTrustPrepare(_))
        ));
        assert!(
            Cli::try_parse_from([
                "edge-console",
                "offline-receipt-identity-prepare",
                &"a".repeat(40),
                &"b".repeat(64)
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "edge-console",
                "offline-host-trust-prepare",
                &"a".repeat(40),
                &"b".repeat(64)
            ])
            .is_err()
        );
    }
}
