//! First-use trust enrollment for the existing VM root Agent. No runner
//! permissions, credentials, containers, routes, DNS or other runtime writes.
//! Immutable published GitHub assets and an out-of-band PINNED Worker public
//! key are mandatory. A second enrollment never overwrites the first.
use super::*;
use edge_shared_types::{
    FleetHostIntent, FleetHostKind, FleetNativeTrustSnapshot, ReleaseSet, managed_host,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

unsafe extern "C" {
    fn geteuid() -> u32;
}

use super::host_native::HOST_PARENT;
const MAX_RELEASE_SET: usize = 65536;
const MAX_BUNDLE: usize = 8 * 1024 * 1024;
const MAX_REGISTRY: usize = 65536;
const MAX_GITHUB_REPLY: usize = 262144;

fn lowercase_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn checked_root_directory(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "HOST_ENROLL_PARENT_MISSING")?;
    if !meta.file_type().is_dir() || meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
        return Err("HOST_ENROLL_PARENT_NOT_TRUSTED".into());
    }
    Ok(())
}

async fn bounded_https_get(
    client: &reqwest::Client,
    url: &str,
    max: usize,
) -> Result<Vec<u8>, String> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "HOST_ENROLL_URL_INVALID")?;
    if parsed.scheme() != "https" || parsed.username() != "" || parsed.password().is_some() {
        return Err("HOST_ENROLL_URL_NOT_HTTPS".into());
    }
    let mut response = client
        .get(parsed)
        .header("User-Agent", "sing-box-native-enroll")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "HOST_ENROLL_GITHUB_FETCH_UNAVAILABLE")?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|size| size == 0 || size > max as u64)
    {
        return Err("HOST_ENROLL_GITHUB_RESPONSE_REJECTED".into());
    }
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "HOST_ENROLL_GITHUB_RESPONSE_INTERRUPTED")?
    {
        if chunk.len() > max.saturating_sub(data.len()) {
            return Err("HOST_ENROLL_GITHUB_RESPONSE_TOO_LARGE".into());
        }
        data.extend_from_slice(&chunk);
    }
    if data.is_empty() {
        return Err("HOST_ENROLL_GITHUB_RESPONSE_EMPTY".into());
    }
    Ok(data)
}

async fn accepted_release_asset(
    client: &reqwest::Client,
    release: &serde_json::Value,
    tag: &str,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let assets = release["assets"]
        .as_array()
        .ok_or("HOST_ENROLL_RELEASE_ASSETS_MISSING")?;
    let mut matching = assets
        .iter()
        .filter(|asset| asset["name"].as_str() == Some(name));
    let asset = matching.next().ok_or("HOST_ENROLL_ASSET_MISSING")?;
    if matching.next().is_some() {
        return Err("HOST_ENROLL_DUPLICATE_RELEASE_ASSET".into());
    }
    let url = format!("https://github.com/iamaman11/sing-box/releases/download/{tag}/{name}");
    let published_url = asset["browser_download_url"]
        .as_str()
        .ok_or("HOST_ENROLL_ASSET_URL_MISSING")?;
    if published_url != url {
        return Err("HOST_ENROLL_ASSET_URL_MISMATCH".into());
    }
    let digest = asset["digest"]
        .as_str()
        .ok_or("HOST_ENROLL_ASSET_DIGEST_MISSING")?;
    if !digest.starts_with("sha256:") || !lowercase_sha(&digest[7..]) {
        return Err("HOST_ENROLL_ASSET_DIGEST_INVALID".into());
    }
    let bytes = bounded_https_get(client, &url, maximum).await?;
    if digest != format!("sha256:{}", super::host_native::sha256_hex(&bytes)) {
        return Err("HOST_ENROLL_ASSET_DIGEST_MISMATCH".into());
    }
    Ok(bytes)
}

fn write_protected_file(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err("HOST_ENROLL_FILE_INVALID".into());
    }
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "HOST_ENROLL_FILE_CREATE_FAILED")?;
    file.write_all(bytes)
        .map_err(|_| "HOST_ENROLL_FILE_WRITE_FAILED")?;
    file.sync_all()
        .map_err(|_| "HOST_ENROLL_FILE_SYNC_FAILED")?;
    Ok(())
}

/// A VM generates its own long-lived native receipt identity exactly once,
/// under local root. Only the public key is returned for subsequent protected
/// Git registry registration. A pre-registered key cannot be matched by
/// generating a fresh private key: refusing is safer than substituting trust.
fn generate_receipt_identity(git_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if !git_public_key.is_empty() {
        return Err("HOST_ENROLL_RECEIPT_KEY_ALREADY_REGISTERED_WITHOUT_LOCAL_IDENTITY".into());
    }
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "HOST_ENROLL_RECEIPT_KEY_GENERATION_FAILED")?;
    let identity =
        Ed25519KeyPair::from_pkcs8(key.as_ref()).map_err(|_| "HOST_ENROLL_RECEIPT_KEY_INVALID")?;
    Ok((
        key.as_ref().to_vec(),
        identity.public_key().as_ref().to_vec(),
    ))
}

/// Existing local signing key is never overwritten, even on release refresh.
fn read_existing_receipt_identity(trusted: &Path) -> Result<Vec<u8>, String> {
    let key = super::host_native::root_file(&trusted.join("receipt-key.pk8"), 4096)?;
    let identity =
        Ed25519KeyPair::from_pkcs8(&key).map_err(|_| "HOST_ENROLL_EXISTING_RECEIPT_KEY_INVALID")?;
    Ok(identity.public_key().as_ref().to_vec())
}

/// Both zero-registration and exact public-key registration are valid
/// enrollment states. Zero-registration never authorizes a host mutation:
/// native apply requires the exact Git-pinned public key before BEGIN.
fn verify_receipt_registration(registered: &[u8], local_public_key: &[u8]) -> Result<bool, String> {
    if registered.is_empty() {
        return Ok(false);
    }
    if registered.len() != 32
        || registered.iter().all(|b| *b == 0)
        || registered != local_public_key
    {
        return Err("HOST_ENROLL_GIT_RECEIPT_KEY_MISMATCH".into());
    }
    Ok(true)
}

fn receipt_public_key_hex(public_key: &[u8]) -> String {
    public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A signed, immutable code/trust refresh is NOT a native resource
/// mutation. Preserve the complete prior journal byte-for-byte even when a
/// previous operation is UNKNOWN_NO_REPLAY or an entry is untrusted. Otherwise
/// a failed journal write permanently prevents shipping the diagnostic owner
/// that must inspect that very failure (root/refresh deadlock).
///
/// Identity, receipt pin, root-owned private journal directory, accepted Git
/// ReleaseSet and root owner lock remain mandatory. Mutation admission still
/// performs the full fail-closed journal scan in host_native/host_journal;
/// an upgrade NEVER releases pending, repairs entries or authorizes replay.
/// A root-owned private directory is a prerequisite for safe owner upgrade;
/// pending and malformed *entries* are deliberately not inspected here.
fn private_journal_directory_metadata(is_directory: bool, uid: u32, mode: u32) -> bool {
    is_directory && uid == 0 && mode & 0o077 == 0
}

fn validate_existing_trust_for_refresh(
    trusted: &Path,
    machine_id: &str,
    pinned_key: &[u8],
) -> Result<(), String> {
    let previous = super::host_native::root_file(&trusted.join("trust.pb"), 9 * 1024 * 1024)?;
    let previous = super::host_native::decode_native_trust_snapshot(&previous)?;
    if previous.machine_id != machine_id || previous.pinned_worker_public_key != pinned_key {
        return Err("HOST_ENROLL_IMMUTABLE_IDENTITY_OR_KEY_MISMATCH".into());
    }
    let journal = trusted.join("journal");
    checked_root_directory(&journal)?;
    let meta =
        fs::symlink_metadata(&journal).map_err(|_| "HOST_ENROLL_JOURNAL_DIRECTORY_UNAVAILABLE")?;
    if !private_journal_directory_metadata(
        meta.file_type().is_dir(),
        meta.uid(),
        meta.permissions().mode(),
    ) {
        return Err("HOST_ENROLL_JOURNAL_ROOT_NOT_PRIVATE".into());
    }
    // Do not touch any journal entry here. Only signed *resource mutations*
    // may consult durable BEGIN/pending/terminal records for admission.
    Ok(())
}

/// Replace one immutable typed snapshot via atomic rename. The journal,
/// machine ID and signer key remain protected by root, not runner artifacts.
fn refresh_release_snapshots(trusted: &Path, trust_pb: &[u8]) -> Result<(), String> {
    let staging = format!(".trust-next-{}.pb", std::process::id());
    write_protected_file(trusted, &staging, trust_pb)?;
    fs::rename(trusted.join(staging), trusted.join("trust.pb"))
        .map_err(|_| "HOST_ENROLL_REFRESH_UNCERTAIN")?;
    fs::File::open(trusted)
        .and_then(|file| file.sync_all())
        .map_err(|_| "HOST_ENROLL_REFRESH_UNCERTAIN")?;
    Ok(())
}

/// One strictly explicit root install of trust files, not a host mutation.
/// Signing authority and GitHub runner cannot choose the public-key trust
/// anchor: ONLY the accepted Git registry supplies the Worker public key.
/// An enrollment never starts containers, writes credential slots or
/// alters a running application. Rollout remains an independently signed
/// apply/recover request with a fresh operation ID.
pub(crate) async fn enroll(machine_id: &str, release_digest: &str) -> Result<(), String> {
    let _resource_lock = super::host_native::owner_operation_lock()?;
    enroll_locked(machine_id, release_digest).await
}

async fn enroll_locked(machine_id: &str, release_digest: &str) -> Result<(), String> {
    if unsafe { geteuid() } != 0 {
        return Err("HOST_ENROLL_REQUIRES_LOCAL_ROOT".into());
    }
    if !lowercase_sha(release_digest) {
        return Err("HOST_ENROLL_RELEASE_SHA_INVALID".into());
    }
    if machine_id.is_empty()
        || machine_id.len() > 64
        || !machine_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("HOST_ENROLL_MACHINE_ID_INVALID".into());
    }
    checked_root_directory(Path::new("/opt"))?;
    checked_root_directory(Path::new(HOST_PARENT))?;
    // Caller holds the single native root lock through trust + binary update.
    let trusted = Path::new(super::host_native::TRUSTED_ROOT);
    let refreshing = match fs::symlink_metadata(trusted) {
        Ok(meta) => {
            if !meta.file_type().is_dir()
                || meta.uid() != 0
                || meta.permissions().mode() & 0o077 != 0
            {
                return Err("HOST_ENROLL_EXISTING_TRUST_UNPROVEN".into());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err("HOST_ENROLL_TRUST_UNAVAILABLE".into()),
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|_| "HOST_ENROLL_TLS_CLIENT_UNAVAILABLE")?;
    let tag = format!("edge-release-{release_digest}");
    let api = format!("https://api.github.com/repos/iamaman11/sing-box/releases/tags/{tag}");
    let published = bounded_https_get(&client, &api, MAX_GITHUB_REPLY).await?;
    let release: serde_json::Value =
        serde_json::from_slice(&published).map_err(|_| "HOST_ENROLL_RELEASE_INVALID_JSON")?;
    if release["tag_name"].as_str() != Some(tag.as_str())
        || release["draft"].as_bool() != Some(false)
        || release["prerelease"].as_bool() != Some(false)
    {
        return Err("HOST_ENROLL_RELEASE_NOT_ACCEPTED".into());
    }
    let (release_pb, registry_pb, bundle_pb) = tokio::try_join!(
        accepted_release_asset(&client, &release, &tag, "release-set.pb", MAX_RELEASE_SET),
        accepted_release_asset(&client, &release, &tag, "fleet-registry.pb", MAX_REGISTRY),
        accepted_release_asset(&client, &release, &tag, "application-bundle.pb", MAX_BUNDLE),
    )?;
    if super::host_native::sha256_hex(&release_pb) != release_digest {
        return Err("HOST_ENROLL_RELEASE_TAG_DIGEST_MISMATCH".into());
    }
    let release_set = ReleaseSet::decode(release_pb.as_slice())
        .map_err(|_| "HOST_ENROLL_RELEASE_PROTO_INVALID")?;
    if release_set.encode_to_vec() != release_pb {
        return Err("HOST_ENROLL_RELEASE_NONCANONICAL".into());
    }
    // An already enrolled VM must not require the OLD binary to understand
    // NEW Windows modes or unrelated fleet resource fields. Its immutable
    // signed release/Git provenance is attested below; this is code-only.
    // Fresh enrollment and later native resource admission still validate
    // the complete CURRENT fleet using the accepted code.
    let host = if refreshing {
        previous_vm_for_code_only_refresh(&registry_pb, machine_id)?
    } else {
        let registry = edge_shared_types::decode_host_registry(&registry_pb)
            .map_err(|_| "HOST_ENROLL_REGISTRY_INVALID")?;
        registry
            .hosts
            .into_iter()
            .find(|host| host.machine_id == machine_id && host.kind == FleetHostKind::Vm as i32)
            .ok_or("HOST_ENROLL_MACHINE_NOT_IN_ACCEPTED_REGISTRY")?
    };
    if !matches!(
        host.owner.as_ref(),
        Some(managed_host::Owner::VmMachineId(owner)) if owner == machine_id
    ) {
        return Err("HOST_ENROLL_ROOT_OWNER_MISMATCH".into());
    }
    // A missing Git signer is an explicit first-use blocker, never an
    // invitation to take a key from the caller or a Worker HTTP response.
    let public_key = host.worker_authority_public_key.clone();
    edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(&host, &public_key)
        .map_err(str::to_owned)?;
    let source_revision = &release_set.source_revision;
    let spec_path = &host.desired_spec_path;
    if source_revision.len() != 40
        || !source_revision.bytes().all(|b| b.is_ascii_hexdigit())
        || !super::host_native::git_owned_host_spec_path(spec_path)
    {
        return Err("HOST_ENROLL_GIT_SPEC_INVALID".into());
    }
    let spec_url = format!(
        "https://raw.githubusercontent.com/iamaman11/sing-box/{source_revision}/{spec_path}"
    );
    let spec = bounded_https_get(&client, &spec_url, 65536).await?;
    let unsigned_provenance_intent = FleetHostIntent {
        release_set_sha256: ring::digest::digest(&ring::digest::SHA256, &release_pb)
            .as_ref()
            .to_vec(),
        ..Default::default()
    };
    // Full tag, accepted commit/tree, asset digests and exact Git spec proof.
    // This call DOES NOT authorize an operation; it verifies a root bootstrap.
    super::host_native::attest_published_github_source(
        &unsigned_provenance_intent,
        &registry_pb,
        &release_pb,
        &bundle_pb,
        &spec,
        spec_path,
    )
    .await?;

    // Exact Git source is verified before even comparing an earlier trust
    // signer. An existing protected identity cannot be silently rotated.
    if refreshing {
        validate_existing_trust_for_refresh(trusted, machine_id, &public_key)?;
    }
    // Generation is strictly local root-only, after verifying the exact
    // published Git release, and before publishing protected trust. The
    // public key must be registered in protected Git and released again
    // before any signed apply can pass receipt-key preadmission.
    let (new_receipt_key, receipt_public_key) = if refreshing {
        (None, read_existing_receipt_identity(trusted)?)
    } else {
        let (private, public) = generate_receipt_identity(&host.native_receipt_public_key)?;
        (Some(private), public)
    };
    let receipt_registered =
        verify_receipt_registration(&host.native_receipt_public_key, &receipt_public_key)?;

    let snapshot = FleetNativeTrustSnapshot {
        schema_version: 1,
        machine_id: machine_id.to_owned(),
        registry_pb,
        release_set_pb: release_pb,
        application_bundle_pb: bundle_pb,
        selected_spec_bytes: spec,
        pinned_worker_public_key: public_key,
    };
    let trust_pb = snapshot.encode_to_vec();
    super::host_native::decode_native_trust_snapshot(&trust_pb)?;
    if refreshing {
        validate_existing_trust_for_refresh(
            trusted,
            machine_id,
            &snapshot.pinned_worker_public_key,
        )?;
        // An exact trusted snapshot is already converged: do not rewrite it
        // on the next /host apply, even after an earlier lost refresh ACK.
        let already_current =
            super::host_native::root_file(&trusted.join("trust.pb"), 9 * 1024 * 1024)? == trust_pb;
        if !already_current {
            refresh_release_snapshots(trusted, &trust_pb)?;
        }
        println!(
            "host_enroll={}",
            if already_current {
                "PROTECTED_TRUST_CURRENT"
            } else {
                "PROTECTED_TRUST_REFRESHED"
            }
        );
        println!("host_machine_id={machine_id}");
        println!("host_release_set_sha256={release_digest}");
        println!(
            "host_native_receipt_public_key_hex={}",
            receipt_public_key_hex(&receipt_public_key)
        );
        println!(
            "host_native_receipt_registration={}",
            if receipt_registered {
                "PINNED_GIT_MATCH"
            } else {
                "AWAITING_PROTECTED_GIT"
            }
        );
        println!("host_mutations=0");
        return Ok(());
    }

    // First enrollment uses atomic publication. No existing trust or journal
    // may be overwritten, even when a previous first-use attempt crashed.
    let stage = Path::new(HOST_PARENT).join(format!(".native-host-new-{}", std::process::id()));
    DirBuilder::new()
        .mode(0o700)
        .create(&stage)
        .map_err(|_| "HOST_ENROLL_STAGE_EXISTS_OR_UNWRITABLE")?;
    write_protected_file(&stage, "trust.pb", &trust_pb)?;
    // Same atomic root-owned staging directory: never publish a trust
    // snapshot that silently lacks its private native receipt identity.
    let receipt_key = new_receipt_key
        .as_deref()
        .ok_or("HOST_ENROLL_RECEIPT_KEY_MISSING_FOR_FIRST_USE")?;
    write_protected_file(&stage, "receipt-key.pk8", receipt_key)?;
    // Fresh first-use receiver is native root-only. The public half is
    // later signed by the receipt key and carried via the existing runner.
    // Never rotate this private receiver on a Git trust refresh.
    let (bootstrap_private, _bootstrap_public) =
        edge_shared_types::vm_bootstrap::fresh_recipient().map_err(str::to_owned)?;
    write_protected_file(&stage, "bootstrap-x25519.secret", &bootstrap_private)?;
    let journal = stage.join("journal");
    DirBuilder::new()
        .mode(0o700)
        .create(&journal)
        .map_err(|_| "HOST_ENROLL_JOURNAL_CREATE_FAILED")?;
    fs::File::open(&journal)
        .and_then(|file| file.sync_all())
        .map_err(|_| "HOST_ENROLL_JOURNAL_SYNC_FAILED")?;
    fs::File::open(&stage)
        .and_then(|file| file.sync_all())
        .map_err(|_| "HOST_ENROLL_STAGE_SYNC_FAILED")?;
    if fs::symlink_metadata(trusted).is_ok() {
        return Err("HOST_ENROLL_CONCURRENT_TRUST_EXISTS".into());
    }
    fs::rename(&stage, trusted).map_err(|_| "HOST_ENROLL_ATOMIC_PUBLISH_FAILED")?;
    fs::File::open(HOST_PARENT)
        .and_then(|file| file.sync_all())
        .map_err(|_| "HOST_ENROLL_PARENT_SYNC_UNCERTAIN")?;
    println!("host_enroll=PROTECTED_TRUST_STAGED");
    println!("host_machine_id={machine_id}");
    println!("host_release_set_sha256={release_digest}");
    println!(
        "host_native_receipt_public_key_hex={}",
        receipt_public_key_hex(&receipt_public_key)
    );
    println!(
        "host_native_receipt_registration={}",
        if receipt_registered {
            "PINNED_GIT_MATCH"
        } else {
            "AWAITING_PROTECTED_GIT"
        }
    );
    println!(
        "host_worker_public_key_sha256={}",
        super::host_native::sha256_hex(&snapshot.pinned_worker_public_key)
    );
    println!("host_mutations=0");
    Ok(())
}

/// A root owner refresh reads only its own PREVIOUS root-protected identity.
/// Git-accepted CURRENT full fleet semantics are checked by enroll_locked()
/// after the target release is obtained. New Windows/other-host fields must
/// never make an already enrolled VM unable to update its own code.
/// This narrow read is NOT an admission to apply resources or migrate trust.
fn previous_vm_for_code_only_refresh(
    bytes: &[u8],
    machine_id: &str,
) -> Result<edge_shared_types::FleetHost, String> {
    if bytes.is_empty() || bytes.len() > MAX_REGISTRY {
        return Err("HOST_REFRESH_PREVIOUS_REGISTRY_INVALID".into());
    }
    let registry = edge_shared_types::HostRegistry::decode(bytes)
        .map_err(|_| "HOST_REFRESH_PREVIOUS_REGISTRY_INVALID")?;
    if registry.schema_version != 1 || registry.hosts.is_empty() {
        return Err("HOST_REFRESH_PREVIOUS_REGISTRY_INVALID".into());
    }
    // Duplicate machine selectors could silently select another VM identity.
    // Never infer ownership from order or from unrelated host fields.
    let mut machine_ids = std::collections::BTreeSet::new();
    if registry
        .hosts
        .iter()
        .any(|host| !machine_ids.insert(host.machine_id.as_str()))
    {
        return Err("HOST_REFRESH_PREVIOUS_REGISTRY_DUPLICATE_IDENTITY".into());
    }
    let vm = registry
        .hosts
        .iter()
        .find(|host| host.machine_id == machine_id)
        .ok_or("HOST_REFRESH_PREVIOUS_OWNER_ABSENT")?;
    if vm.kind != FleetHostKind::Vm as i32
        || !matches!(
            vm.owner.as_ref(),
            Some(managed_host::Owner::VmMachineId(owner)) if owner == machine_id
        )
    {
        return Err("HOST_REFRESH_PREVIOUS_OWNER_MISMATCH".into());
    }
    if vm.worker_authority_public_key.len() != 32
        || vm.worker_authority_public_key.iter().all(|byte| *byte == 0)
        || (!vm.native_receipt_public_key.is_empty()
            && (vm.native_receipt_public_key.len() != 32
                || vm.native_receipt_public_key.iter().all(|byte| *byte == 0)))
    {
        return Err("HOST_REFRESH_PREVIOUS_IDENTITY_INVALID".into());
    }
    Ok(vm.clone())
}

/// Refresh the CURRENT protected main release using the EXISTING native root
/// owner, with NO SSH, no caller-supplied path, release SHA or trust bytes.
/// Only this binary can update its root-owned trust and binary. It never
/// mutates Docker, credentials, routes, DNS or the resource operation journal.
pub(crate) async fn refresh_current() -> Result<(), String> {
    let _guard = super::host_native::owner_operation_lock()?;
    let trusted = Path::new(super::host_native::TRUSTED_ROOT);
    let previous = super::host_native::root_file(&trusted.join("trust.pb"), 9 * 1024 * 1024)?;
    let previous = super::host_native::decode_native_trust_snapshot(&previous)?;
    // A pre-enrollment runner cannot create trust. Only completed root
    // receipt enrollment is eligible for native release refresh.
    let identity = read_existing_receipt_identity(trusted)?;
    let host = previous_vm_for_code_only_refresh(&previous.registry_pb, &previous.machine_id)?;
    // First-use root trust precedes public receipt registration. The
    // protected merge is allowed to advance that EMPTY prior pin to the
    // exact existing local key, but may never substitute another key.
    if (!host.native_receipt_public_key.is_empty() && host.native_receipt_public_key != identity)
        || previous.pinned_worker_public_key != host.worker_authority_public_key
    {
        return Err("HOST_REFRESH_PREVIOUS_GIT_IDENTITY_UNPROVEN".into());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "HOST_REFRESH_HTTPS_CLIENT_UNAVAILABLE")?;
    let base = "https://api.github.com/repos/iamaman11/sing-box";
    let head_url = format!("{base}/git/ref/heads/main");
    let latest_url = format!("{base}/releases/latest");
    let (head_bytes, latest_bytes) = tokio::try_join!(
        bounded_https_get(&client, &head_url, 32768),
        bounded_https_get(&client, &latest_url, MAX_GITHUB_REPLY)
    )?;
    let head: serde_json::Value =
        serde_json::from_slice(&head_bytes).map_err(|_| "HOST_REFRESH_MAIN_REF_INVALID")?;
    let latest: serde_json::Value =
        serde_json::from_slice(&latest_bytes).map_err(|_| "HOST_REFRESH_LATEST_RELEASE_INVALID")?;
    let release_digest = current_published_release_digest(&head, &latest)?;
    let tag = format!("edge-release-{release_digest}");
    // This path belongs to the EXACT existing root Agent. No target is
    // accepted from the unprivileged GitHub runner.
    let binary = Path::new("/usr/local/libexec/sing-box/edge-agent");
    let parent = binary
        .parent()
        .ok_or("HOST_REFRESH_OWNER_BINARY_PATH_INVALID")?;
    checked_root_directory(parent)?;
    let meta = fs::symlink_metadata(binary).map_err(|_| "HOST_REFRESH_OWNER_BINARY_UNAVAILABLE")?;
    if !meta.file_type().is_file()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o777 != 0o755
        || meta.len() == 0
        || meta.len() > 32 * 1024 * 1024
    {
        return Err("HOST_REFRESH_OWNER_BINARY_NOT_PROTECTED".into());
    }
    let installed = fs::read(binary).map_err(|_| "HOST_REFRESH_OWNER_BINARY_UNREADABLE")?;
    let asset = latest["assets"]
        .as_array()
        .ok_or("HOST_REFRESH_RELEASE_ASSETS_MISSING")?
        .iter()
        .filter(|entry| entry["name"].as_str() == Some("edge-agent-linux-amd64"))
        .collect::<Vec<_>>();
    if asset.len() != 1 {
        return Err("HOST_REFRESH_OWNER_ASSET_NOT_EXACT".into());
    }
    let published_digest = asset[0]["digest"]
        .as_str()
        .and_then(|value| value.strip_prefix("sha256:"))
        .ok_or("HOST_REFRESH_OWNER_ASSET_SHA_MISSING")?;
    if !lowercase_sha(published_digest) {
        return Err("HOST_REFRESH_OWNER_ASSET_SHA_INVALID".into());
    }
    let binary_changed = super::host_native::sha256_hex(&installed) != published_digest;
    let next_binary = if binary_changed {
        Some(
            accepted_release_asset(
                &client,
                &latest,
                &tag,
                "edge-agent-linux-amd64",
                32 * 1024 * 1024,
            )
            .await?,
        )
    } else {
        None
    };
    // Shared enrollment validation proves ReleaseSet, source tree, registry,
    // Worker signer and stable native receipt; preserves journal and key.
    // A suspicious or pending resource journal does NOT veto diagnostics-only
    // binary delivery. It remains a strict veto for any subsequent host-apply.
    // No second lock is acquired; this lock spans the entire upgrade.
    enroll_locked(&previous.machine_id, &release_digest).await?;
    if let Some(bytes) = next_binary {
        let stage_name = format!(".edge-agent-next-{}", std::process::id());
        write_protected_file(parent, &stage_name, &bytes)?;
        let stage = parent.join(stage_name);
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755))
            .map_err(|_| "HOST_REFRESH_OWNER_BINARY_STAGE_INVALID")?;
        fs::File::open(&stage)
            .and_then(|file| file.sync_all())
            .map_err(|_| "HOST_REFRESH_OWNER_BINARY_STAGE_SYNC_UNCERTAIN")?;
        fs::rename(&stage, binary).map_err(|_| "HOST_REFRESH_OWNER_BINARY_REPLACE_UNCERTAIN")?;
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "HOST_REFRESH_OWNER_BINARY_SYNC_UNCERTAIN")?;
    }
    println!("host_native_trust_refresh=CURRENT_PROTECTED_MAIN");
    println!(
        "host_native_binary_refresh={}",
        if binary_changed {
            "UPDATED"
        } else {
            "UNCHANGED"
        }
    );
    println!("host_resource_mutations=0");
    println!("host_release_set_sha256={release_digest}");
    Ok(())
}

/// Never allow a runner to select an old accepted release as new local trust.
/// GitHub latest must represent the exact protected main commit, not a tag or
/// a historic release that merely passed CI.
fn current_published_release_digest(
    head: &serde_json::Value,
    release: &serde_json::Value,
) -> Result<String, String> {
    let main = head["object"]["sha"]
        .as_str()
        .ok_or("HOST_REFRESH_MAIN_SHA_UNPROVEN")?;
    if head["object"]["type"].as_str() != Some("commit")
        || main.len() != 40
        || !main.bytes().all(|b| b.is_ascii_hexdigit())
        || release["target_commitish"].as_str() != Some(main)
        || release["draft"].as_bool() != Some(false)
        || release["prerelease"].as_bool() != Some(false)
    {
        return Err("HOST_REFRESH_CURRENT_MAIN_RELEASE_MISMATCH".into());
    }
    let digest = release["tag_name"]
        .as_str()
        .and_then(|value| value.strip_prefix("edge-release-"))
        .ok_or("HOST_REFRESH_LATEST_TAG_INVALID")?;
    if !lowercase_sha(digest) {
        return Err("HOST_REFRESH_LATEST_DIGEST_INVALID".into());
    }
    Ok(digest.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn previous_release_refresh_only_requires_exact_vm_identity_not_new_windows_semantics() {
        use edge_shared_types::{
            FleetHost, FleetHostMode, FleetHostRunState, FleetHostTarget, HostRegistry,
        };
        let vm = FleetHost {
            machine_id: "application-acceptance-5".into(),
            kind: FleetHostKind::Vm as i32,
            owner: Some(managed_host::Owner::VmMachineId(
                "application-acceptance-5".into(),
            )),
            worker_authority_public_key: vec![7; 32],
            desired_spec_path: "infra/production/production.textproto".into(),
            ..Default::default()
        };
        let windows = FleetHost {
            machine_id: "sing-box-windows-lab".into(),
            kind: FleetHostKind::Windows as i32,
            owner: Some(managed_host::Owner::WindowsRunnerName(
                "DESKTOP-0E1F6UQ".into(),
            )),
            windows_runner_label: "sing-box-windows-lab".into(),
            desired_spec_path: "infra/production/production.textproto".into(),
            target: Some(FleetHostTarget {
                run_state: FleetHostRunState::Stopped as i32,
                windows_mode: FleetHostMode::ProxyOnly as i32,
            }),
            ..Default::default()
        };
        let prior = HostRegistry {
            schema_version: 1,
            hosts: vec![vm, windows],
            ..Default::default()
        };
        let machine_id = "application-acceptance-5";
        assert!(edge_shared_types::decode_host_registry(&prior.encode_to_vec()).is_err());
        let current =
            previous_vm_for_code_only_refresh(&prior.encode_to_vec(), machine_id).unwrap();
        assert_eq!(current.machine_id, machine_id);
        assert_eq!(current.worker_authority_public_key, vec![7; 32]);

        // A future Windows protobuf mode/kind/target cannot prevent VM code
        // refresh. Current desired validation remains strict in enroll_locked.
        let mut foreign = prior.clone();
        foreign.hosts[1].target.as_mut().unwrap().windows_mode = 999;
        foreign.hosts[1].kind = 999;
        foreign.hosts[1].desired_spec_path = "../unrecognized-new-field".into();
        assert!(previous_vm_for_code_only_refresh(&foreign.encode_to_vec(), machine_id).is_ok());

        let mut wrong_signer = prior.clone();
        wrong_signer.hosts[0].worker_authority_public_key = vec![1; 31];
        assert!(
            previous_vm_for_code_only_refresh(&wrong_signer.encode_to_vec(), machine_id).is_err()
        );
        wrong_signer.hosts[0].worker_authority_public_key = vec![0; 32];
        assert!(
            previous_vm_for_code_only_refresh(&wrong_signer.encode_to_vec(), machine_id).is_err()
        );

        let mut wrong_kind = prior.clone();
        wrong_kind.hosts[0].kind = FleetHostKind::Windows as i32;
        assert!(
            previous_vm_for_code_only_refresh(&wrong_kind.encode_to_vec(), machine_id).is_err()
        );

        let mut wrong_owner = prior.clone();
        wrong_owner.hosts[0].owner = Some(managed_host::Owner::VmMachineId("foreign-vm".into()));
        assert!(
            previous_vm_for_code_only_refresh(&wrong_owner.encode_to_vec(), machine_id).is_err()
        );

        let mut wrong_receipt = prior.clone();
        wrong_receipt.hosts[0].native_receipt_public_key = vec![3; 31];
        assert!(
            previous_vm_for_code_only_refresh(&wrong_receipt.encode_to_vec(), machine_id).is_err()
        );

        let mut duplicate = prior.clone();
        duplicate.hosts.push(duplicate.hosts[0].clone());
        assert!(previous_vm_for_code_only_refresh(&duplicate.encode_to_vec(), machine_id).is_err());

        let mut unsupported_schema = prior.clone();
        unsupported_schema.schema_version = 55;
        assert!(
            previous_vm_for_code_only_refresh(&unsupported_schema.encode_to_vec(), machine_id)
                .is_err()
        );
        assert!(previous_vm_for_code_only_refresh(&[], machine_id).is_err());
        assert!(previous_vm_for_code_only_refresh(&[0xff], machine_id).is_err());
        assert!(previous_vm_for_code_only_refresh(&prior.encode_to_vec(), "absent-vm").is_err());
    }

    #[test]
    fn refreshed_owner_still_requires_private_root_owned_journal_directory() {
        assert!(private_journal_directory_metadata(true, 0, 0o40700));
        assert!(!private_journal_directory_metadata(true, 0, 0o40755));
        assert!(!private_journal_directory_metadata(true, 1000, 0o40700));
        assert!(!private_journal_directory_metadata(false, 0, 0o100600));
        assert!(!private_journal_directory_metadata(true, 0, 0o40770));
    }

    #[test]
    fn native_refresh_accepts_only_exact_latest_main_release() {
        let sha = "a".repeat(40);
        let digest = "b".repeat(64);
        let head = serde_json::json!({"object":{"type":"commit","sha":sha}});
        let latest = serde_json::json!({
            "target_commitish":sha,
            "draft":false,
            "prerelease":false,
            "tag_name":format!("edge-release-{digest}")
        });
        assert_eq!(
            current_published_release_digest(&head, &latest).unwrap(),
            digest
        );
        let mut stale = latest.clone();
        stale["target_commitish"] = serde_json::json!("c".repeat(40));
        assert!(current_published_release_digest(&head, &stale).is_err());
        let mut draft = latest.clone();
        draft["draft"] = serde_json::json!(true);
        assert!(current_published_release_digest(&head, &draft).is_err());
        let mut unsafe_tag = latest.clone();
        unsafe_tag["tag_name"] = serde_json::json!("edge-release-../escape");
        assert!(current_published_release_digest(&head, &unsafe_tag).is_err());
        let mut invalid_head = head;
        invalid_head["object"]["type"] = serde_json::json!("tag");
        assert!(current_published_release_digest(&invalid_head, &latest).is_err());
    }

    #[test]
    fn enrollment_can_never_choose_a_worker_signer_outside_protected_git() {
        let mut host = edge_shared_types::FleetHost {
            kind: FleetHostKind::Vm as i32,
            ..Default::default()
        };
        let signer_a = [7u8; 32];
        let signer_b = [9u8; 32];
        assert_eq!(
            edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(&host, &signer_a),
            Err("HOST_GIT_WORKER_SIGNER_KEY_REQUIRED")
        );
        host.worker_authority_public_key = signer_a.to_vec();
        assert_eq!(
            edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(&host, &signer_a),
            Ok(())
        );
        assert_eq!(
            edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(&host, &signer_b),
            Err("HOST_WORKER_SIGNER_DIFFERS_FROM_PROTECTED_GIT")
        );
        host.kind = FleetHostKind::Windows as i32;
        assert!(
            edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(&host, &signer_a)
                .is_err()
        );
        host.kind = FleetHostKind::Vm as i32;
        host.worker_authority_public_key = vec![0; 32];
        assert!(
            edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(&host, &signer_a)
                .is_err()
        );
    }

    #[test]
    fn first_use_key_and_digest_are_exact_and_nonzero() {
        assert!(!lowercase_sha(&"AB".repeat(32)));
        assert!(lowercase_sha(&"ab".repeat(32)));
    }

    #[test]
    fn receipt_identity_is_root_local_and_requires_exact_git_registration() {
        let (private, public) = generate_receipt_identity(&[]).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(&private).unwrap();
        assert_eq!(key.public_key().as_ref(), public.as_slice());
        assert_eq!(public.len(), 32);
        assert_eq!(receipt_public_key_hex(&public).len(), 64);
        assert!(!verify_receipt_registration(&[], &public).unwrap());
        assert!(verify_receipt_registration(&public, &public).unwrap());
        assert!(verify_receipt_registration(&[1; 32], &public).is_err());
        assert!(verify_receipt_registration(&[0; 32], &public).is_err());
        assert!(verify_receipt_registration(&[1; 12], &public).is_err());
        assert!(generate_receipt_identity(&public).is_err());
    }
}
