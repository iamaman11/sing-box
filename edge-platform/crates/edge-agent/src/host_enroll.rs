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
fn pinned_worker_key(value: &str) -> Result<(), String> {
    if !lowercase_sha(value) || value.bytes().all(|b| b == b'0') {
        return Err("HOST_ENROLL_PINNED_WORKER_KEY_REQUIRED".into());
    }
    Ok(())
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

/// Native trust may adopt only the exact Worker public key already accepted
/// by protected Git. The out-of-band CLI value cannot select a signer.
fn verify_git_worker_signer_pin(
    host: &edge_shared_types::FleetHost,
    supplied: &[u8],
) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || host.worker_authority_public_key.len() != 32
        || host.worker_authority_public_key.iter().all(|b| *b == 0)
    {
        return Err("HOST_ENROLL_GIT_WORKER_SIGNER_KEY_REQUIRED");
    }
    if supplied != host.worker_authority_public_key {
        return Err("HOST_ENROLL_WORKER_KEY_DIFFERS_FROM_PROTECTED_GIT");
    }
    Ok(())
}

fn receipt_public_key_hex(public_key: &[u8]) -> String {
    public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Root-owned trust can advance to a NEW accepted immutable ReleaseSet
/// without replacing the stable journal. Pending UNKNOWN_NO_REPLAY is an
/// explicit gate: an update must never erase the record that forbids replay.
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
    if super::host_native::protected_journal_has_pending(&journal)? {
        return Err("HOST_ENROLL_UNRESOLVED_RESOURCE_NO_REPLAY".into());
    }
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
/// anchor: root operator must supply the exact Worker Ed25519 public key.
/// An enrollment never starts containers, writes credential slots or
/// alters a running application. Rollout remains an independently signed
/// apply/recover request with a fresh operation ID.
pub(crate) async fn enroll(
    machine_id: &str,
    release_digest: &str,
    worker_public_key_hex: &str,
) -> Result<(), String> {
    if unsafe { geteuid() } != 0 {
        return Err("HOST_ENROLL_REQUIRES_LOCAL_ROOT".into());
    }
    if !lowercase_sha(release_digest) {
        return Err("HOST_ENROLL_RELEASE_SHA_INVALID".into());
    }
    pinned_worker_key(worker_public_key_hex)?;
    let public_key = (0..64)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&worker_public_key_hex[i..i + 2], 16)
                .map_err(|_| "HOST_ENROLL_PINNED_WORKER_KEY_INVALID".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
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
    // Apply and refresh are mutually exclusive. The same lock protects the
    // permanent native journal; no new scheduler, watchdog or ledger.
    let _resource_lock = super::host_native::owner_operation_lock()?;
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
    if refreshing {
        validate_existing_trust_for_refresh(trusted, machine_id, &public_key)?;
    }

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
    let registry = edge_shared_types::decode_host_registry(&registry_pb)
        .map_err(|_| "HOST_ENROLL_REGISTRY_INVALID")?;
    let host = registry
        .hosts
        .iter()
        .find(|host| host.machine_id == machine_id && host.kind == FleetHostKind::Vm as i32)
        .ok_or("HOST_ENROLL_MACHINE_NOT_IN_ACCEPTED_REGISTRY")?;
    if !matches!(
        host.owner.as_ref(),
        Some(managed_host::Owner::VmMachineId(owner)) if owner == machine_id
    ) {
        return Err("HOST_ENROLL_ROOT_OWNER_MISMATCH".into());
    }
    verify_git_worker_signer_pin(host, &public_key).map_err(str::to_owned)?;
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
        refresh_release_snapshots(trusted, &trust_pb)?;
        println!("host_enroll=PROTECTED_TRUST_REFRESHED");
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
        super::host_native::sha256_hex(
            &(0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&worker_public_key_hex[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        )
    );
    println!("host_mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrollment_can_never_choose_a_worker_signer_outside_protected_git() {
        let mut host = edge_shared_types::FleetHost {
            kind: FleetHostKind::Vm as i32,
            ..Default::default()
        };
        let signer_a = [7u8; 32];
        let signer_b = [9u8; 32];
        assert_eq!(
            verify_git_worker_signer_pin(&host, &signer_a),
            Err("HOST_ENROLL_GIT_WORKER_SIGNER_KEY_REQUIRED")
        );
        host.worker_authority_public_key = signer_a.to_vec();
        assert_eq!(verify_git_worker_signer_pin(&host, &signer_a), Ok(()));
        assert_eq!(
            verify_git_worker_signer_pin(&host, &signer_b),
            Err("HOST_ENROLL_WORKER_KEY_DIFFERS_FROM_PROTECTED_GIT")
        );
        host.kind = FleetHostKind::Windows as i32;
        assert!(verify_git_worker_signer_pin(&host, &signer_a).is_err());
        host.kind = FleetHostKind::Vm as i32;
        host.worker_authority_public_key = vec![0; 32];
        assert!(verify_git_worker_signer_pin(&host, &signer_a).is_err());
    }

    #[test]
    fn first_use_key_and_digest_are_exact_and_nonzero() {
        assert!(pinned_worker_key(&"ab".repeat(32)).is_ok());
        assert!(pinned_worker_key(&"00".repeat(32)).is_err());
        assert!(pinned_worker_key(&"AB".repeat(32)).is_err());
        assert!(pinned_worker_key("not-a-key").is_err());
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
