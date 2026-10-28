//! W4 trust enrollment by the already installed Windows LocalSystem dispatcher.
//! An accepted protected Git registry and exact current immutable ReleaseSet
//! are the ONLY authority for trust. Neither the local Administrator nor the
//! unprivileged runner may supply Worker public key, receipt public key,
//! registry, spec, or trust bytes. No SCM, network/TUN or resource mutation.
use super::*;
use edge_shared_types::{
    FleetHostAction, FleetHostIntent, FleetHostKind, FleetHostMode, FleetHostRunState,
    FleetNativeTrustSnapshot, FleetWindowsTrustEnrollment, HostRegistry, ReleaseSet,
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

fn verify_enrollment_marker(
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
pub(super) fn prepare(
    install_root: &Path,
    source_revision: &str,
    release_sha256: &str,
) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let active = load_verified_activation(install_root).map_err(|e| e.to_string())?;
    if active.source_revision != source_revision || active.release_set_sha256 != release_sha256 {
        return Err("HOST_WINDOWS_TRUST_ENROLL_SOURCE_PIN_MISMATCH".into());
    }
    require_offline_windows_owner(install_root, &active)?;
    verify_offline_bootstrap_dispatcher(&active.console_path, "Ready")?;
    let root = install_root.join("native-host");
    let proof = fs::symlink_metadata(root.join(COMPLETED))
        .map_err(|_| "HOST_WINDOWS_TRUST_ENROLL_RECEIPT_IDENTITY_UNPROVEN")?;
    if !proof.file_type().is_file() || proof.len() == 0 || proof.len() > 512 {
        return Err("HOST_WINDOWS_TRUST_ENROLL_RECEIPT_IDENTITY_INVALID".into());
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
        source_revision: source_revision.to_owned(),
        release_set_sha256: release_sha256.to_owned(),
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
    if head["object"]["type"].as_str() != Some("commit")
        || head["object"]["sha"].as_str() != Some(active.source_revision.as_str())
        || release["target_commitish"].as_str() != Some(active.source_revision.as_str())
        || release["tag_name"].as_str() != Some(tag.as_str())
        || release["draft"].as_bool() != Some(false)
        || release["prerelease"].as_bool() != Some(false)
        || release["published_at"].as_str().is_none()
        || tag_ref["object"]["type"].as_str() != Some("commit")
        || tag_ref["object"]["sha"].as_str() != Some(active.source_revision.as_str())
    {
        return Err("HOST_WINDOWS_TRUST_GITHUB_MAIN_RELEASE_TAG_NOT_EXACT");
    }
    Ok(())
}

async fn fetch_bounded(
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

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<serde_json::Value, String> {
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
            Some(target) if target.run_state == FleetHostRunState::Stopped as i32
                && target.windows_mode == FleetHostMode::ProxyOnly as i32)
    {
        return Err("HOST_WINDOWS_TRUST_GIT_OWNER_OR_TARGET_INVALID".into());
    }
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

async fn fetch_exact_protected_git(
    active: &WindowsActivationState,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|_| "HOST_WINDOWS_TRUST_TLS_CLIENT_UNAVAILABLE")?;
    let base = "https://api.github.com/repos/iamaman11/sing-box";
    let tag = format!("edge-release-{}", active.release_set_sha256);
    let (head, release, tag_ref) = tokio::try_join!(
        fetch_json(&client, &format!("{base}/git/ref/heads/main")),
        fetch_json(&client, &format!("{base}/releases/tags/{tag}")),
        fetch_json(&client, &format!("{base}/git/ref/tags/{tag}")),
    )?;
    exact_github_provenance(&head, &release, &tag_ref, active).map_err(str::to_owned)?;
    let (release_pb, registry_pb, spec) = tokio::try_join!(
        accepted_asset(&client, &release, &tag, "release-set.pb", MAX_RELEASE),
        accepted_asset(&client, &release, &tag, "fleet-registry.pb", MAX_REGISTRY),
        fetch_bounded(
            &client,
            &format!(
                "https://raw.githubusercontent.com/iamaman11/sing-box/{}/{}",
                active.source_revision, SPEC
            ),
            MAX_SPEC
        ),
    )?;
    if sha_hex(&release_pb) != active.release_set_sha256 {
        return Err("HOST_WINDOWS_TRUST_RELEASE_DIGEST_MISMATCH".into());
    }
    Ok((release_pb, registry_pb, spec))
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
        return Err("HOST_WINDOWS_TRUST_ENROLL_RECEIPT_IDENTITY_NOT_COMPLETED".into());
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
    let (release_pb, registry_pb, spec) = fetch_exact_protected_git(&active).await?;
    let trust =
        exact_windows_registration(&registry_pb, &release_pb, &spec, &active, &private, &public)?;
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
    fn trust_rejects_stale_main_unpublished_release_and_wrong_tag() {
        let active = WindowsActivationState {
            source_revision: "a".repeat(40),
            release_set_sha256: "b".repeat(64),
            ..Default::default()
        };
        let tag = format!("edge-release-{}", active.release_set_sha256);
        let head = serde_json::json!({"object":{"type":"commit","sha":active.source_revision}});
        let release = serde_json::json!({
            "target_commitish":active.source_revision,
            "tag_name":tag,"draft":false,"prerelease":false,
            "published_at":"2026-10-28T00:00:00Z"
        });
        let git_tag = serde_json::json!({"object":{"type":"commit","sha":active.source_revision}});
        assert!(exact_github_provenance(&head, &release, &git_tag, &active).is_ok());
        let mut stale = head.clone();
        stale["object"]["sha"] = serde_json::json!("c".repeat(40));
        assert!(exact_github_provenance(&stale, &release, &git_tag, &active).is_err());
        let mut draft = release.clone();
        draft["draft"] = serde_json::json!(true);
        assert!(exact_github_provenance(&head, &draft, &git_tag, &active).is_err());
        let mut foreign = git_tag.clone();
        foreign["object"]["sha"] = serde_json::json!("d".repeat(40));
        assert!(exact_github_provenance(&head, &release, &foreign, &active).is_err());
        let mut missing_published = release;
        missing_published["published_at"] = serde_json::Value::Null;
        assert!(exact_github_provenance(&head, &missing_published, &git_tag, &active).is_err());
    }
}
