//! First-use trust enrollment for the existing VM root Agent. No runner
//! permissions, credentials, containers, routes, DNS or other runtime writes.
//! Immutable published GitHub assets and an out-of-band PINNED Worker public
//! key are mandatory. A second enrollment never overwrites the first.
use super::*;
use edge_shared_types::{FleetHostIntent, FleetHostKind, ReleaseSet, managed_host};
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

unsafe extern "C" {
    fn geteuid() -> u32;
}

const HOST_PARENT: &str = "/opt/vultr-edge-stack";
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
    let trusted = Path::new(super::host_native::TRUSTED_ROOT);
    if fs::symlink_metadata(trusted).is_ok() {
        return Err("HOST_ENROLL_EXISTING_TRUST_NEVER_OVERWRITTEN".into());
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

    // Root-only first-use atomic publication. Never mutate or replace an
    // existing native-host trust tree, including an uncertain prior install.
    let stage = Path::new(HOST_PARENT).join(format!(".native-host-new-{}", std::process::id()));
    DirBuilder::new()
        .mode(0o700)
        .create(&stage)
        .map_err(|_| "HOST_ENROLL_STAGE_EXISTS_OR_UNWRITABLE")?;
    write_protected_file(&stage, "machine-id", format!("{machine_id}\n").as_bytes())?;
    write_protected_file(&stage, "fleet-registry.pb", &registry_pb)?;
    write_protected_file(&stage, "release-set.pb", &release_pb)?;
    write_protected_file(&stage, "application-bundle.pb", &bundle_pb)?;
    write_protected_file(&stage, "desired.textproto", &spec)?;
    write_protected_file(
        &stage,
        "worker-public-key.hex",
        format!("{worker_public_key_hex}\n").as_bytes(),
    )?;
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
    fn first_use_key_and_digest_are_exact_and_nonzero() {
        assert!(pinned_worker_key(&"ab".repeat(32)).is_ok());
        assert!(pinned_worker_key(&"00".repeat(32)).is_err());
        assert!(pinned_worker_key(&"AB".repeat(32)).is_err());
        assert!(pinned_worker_key("not-a-key").is_err());
        assert!(!lowercase_sha(&"AB".repeat(32)));
        assert!(lowercase_sha(&"ab".repeat(32)));
    }
}
