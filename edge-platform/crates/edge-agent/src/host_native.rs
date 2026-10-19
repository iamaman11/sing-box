//! One root-owned VM host command. Runner stdin carries ONLY the canonical
//! operation identifier; native release and desired bytes are never accepted
//! from a workflow artifact or the caller's path arguments.
use super::*;
use edge_shared_types::host_journal::execute_native_host_once;
use edge_shared_types::host_lifecycle::decode_host_intent;
use edge_shared_types::{FleetHostKind, FleetHostPlannedStep};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const TRUSTED_ROOT: &str = "/opt/vultr-edge-stack/native-host";
const JOURNAL_ROOT: &str = "/opt/vultr-edge-stack/native-host/journal";

fn root_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if !path.starts_with(TRUSTED_ROOT) {
        return Err("HOST_NATIVE_PATH_OUTSIDE_OWNER_ROOT".into());
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "HOST_NATIVE_OWNER_FILE_MISSING")?;
    if !meta.file_type().is_file()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o077 != 0
        || meta.len() == 0
        || meta.len() > limit
    {
        return Err("HOST_NATIVE_OWNER_FILE_NOT_PROTECTED".into());
    }
    fs::read(path).map_err(|_| "HOST_NATIVE_OWNER_FILE_UNREADABLE".into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One canonical GitHub release is the source of owner artifacts. The owner
/// independently checks published tag -> accepted Git commit, exact asset
/// digests and the selected source-revision Git desired. The runner does NOT
/// get to supply a replacement registry, release URL or arbitrary Git ref.
async fn attest_published_github_source(
    intent: &edge_shared_types::FleetHostIntent,
    registry_pb: &[u8],
    release_pb: &[u8],
    bundle_pb: &[u8],
    exact_spec: &[u8],
    spec_path: &str,
) -> Result<(), String> {
    let release_digest = sha256_hex(release_pb);
    if intent.release_set_sha256.as_slice()
        != ring::digest::digest(&ring::digest::SHA256, release_pb).as_ref()
    {
        return Err("HOST_NATIVE_RELEASE_INTENT_SHA_MISMATCH".into());
    }
    let release = edge_shared_types::ReleaseSet::decode(release_pb)
        .map_err(|_| "HOST_NATIVE_RELEASE_INVALID")?;
    let revision = release.source_revision.as_str();
    if revision.len() != 40
        || !revision.bytes().all(|c| c.is_ascii_hexdigit())
        || spec_path.is_empty()
        || !spec_path.starts_with("infra/")
        || spec_path.contains("..")
        || !spec_path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'.' | b'-' | b'_'))
    {
        return Err("HOST_NATIVE_CANONICAL_SOURCE_INVALID".into());
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "HOST_NATIVE_GITHUB_CLIENT_INVALID")?;
    let base = "https://api.github.com/repos/iamaman11/sing-box";
    let tag = format!("edge-release-{release_digest}");
    let uri = format!("{base}/releases/tags/{tag}");
    let response = client
        .get(&uri)
        .header("User-Agent", "sing-box-native-owner")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "HOST_NATIVE_RELEASE_LOOKUP_UNAVAILABLE")?;
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 262144) {
        return Err("HOST_NATIVE_PUBLISHED_RELEASE_NOT_VERIFIED".into());
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| "HOST_NATIVE_RELEASE_RESPONSE_UNAVAILABLE")?;
    if body.len() > 262144 {
        return Err("HOST_NATIVE_RELEASE_RESPONSE_TOO_LARGE".into());
    }
    let published: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| "HOST_NATIVE_RELEASE_METADATA_INVALID")?;
    let accepted = published["target_commitish"]
        .as_str()
        .ok_or("HOST_NATIVE_ACCEPTED_REVISION_MISSING")?;
    if accepted.len() != 40
        || !accepted.bytes().all(|c| c.is_ascii_hexdigit())
        || published["tag_name"].as_str() != Some(tag.as_str())
        || published["draft"].as_bool() != Some(false)
        || published["prerelease"].as_bool() != Some(false)
    {
        return Err("HOST_NATIVE_RELEASE_METADATA_NOT_ACCEPTED".into());
    }
    let ref_response = client
        .get(format!("{base}/git/ref/tags/{tag}"))
        .header("User-Agent", "sing-box-native-owner")
        .send()
        .await
        .map_err(|_| "HOST_NATIVE_RELEASE_REF_UNAVAILABLE")?;
    if !ref_response.status().is_success() {
        return Err("HOST_NATIVE_RELEASE_REF_NOT_ACCEPTED".into());
    }
    let ref_bytes = ref_response
        .bytes()
        .await
        .map_err(|_| "HOST_NATIVE_RELEASE_REF_UNAVAILABLE")?;
    if ref_bytes.len() > 32768 {
        return Err("HOST_NATIVE_RELEASE_REF_TOO_LARGE".into());
    }
    let git_ref: serde_json::Value =
        serde_json::from_slice(&ref_bytes).map_err(|_| "HOST_NATIVE_RELEASE_REF_INVALID")?;
    if git_ref["object"]["type"].as_str() != Some("commit")
        || git_ref["object"]["sha"].as_str() != Some(accepted)
    {
        return Err("HOST_NATIVE_RELEASE_GIT_REF_MISMATCH".into());
    }
    let assets = published["assets"]
        .as_array()
        .ok_or("HOST_NATIVE_RELEASE_ASSETS_INVALID")?;
    for (name, bytes) in [
        ("release-set.pb", release_pb),
        ("application-bundle.pb", bundle_pb),
        ("fleet-registry.pb", registry_pb),
    ] {
        let mut matches = assets
            .iter()
            .filter(|asset| asset["name"].as_str() == Some(name));
        let asset = matches.next().ok_or("HOST_NATIVE_RELEASE_ASSET_MISSING")?;
        if matches.next().is_some()
            || asset["digest"].as_str() != Some(format!("sha256:{}", sha256_hex(bytes)).as_str())
        {
            return Err("HOST_NATIVE_RELEASE_ASSET_DIGEST_MISMATCH".into());
        }
    }
    // Exactly the accepted candidate source tree supplies host desired.
    // The fetched contents are compared with the protected local snapshot,
    // which also binds into the signed intent's desired digest.
    let raw_url =
        format!("https://raw.githubusercontent.com/iamaman11/sing-box/{revision}/{spec_path}");
    let source = client
        .get(raw_url)
        .header("User-Agent", "sing-box-native-owner")
        .send()
        .await
        .map_err(|_| "HOST_NATIVE_GIT_DESIRED_UNAVAILABLE")?;
    if !source.status().is_success() || source.content_length().is_some_and(|n| n > 65536) {
        return Err("HOST_NATIVE_GIT_DESIRED_NOT_ACCEPTED".into());
    }
    let desired = source
        .bytes()
        .await
        .map_err(|_| "HOST_NATIVE_GIT_DESIRED_UNAVAILABLE")?;
    if desired.as_ref() != exact_spec || desired.len() > 65536 {
        return Err("HOST_NATIVE_GIT_DESIRED_MISMATCH".into());
    }
    Ok(())
}

fn parse_hex_key(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let hex = std::str::from_utf8(bytes)
        .map_err(|_| "HOST_NATIVE_KEY_INVALID")?
        .trim_end_matches('\n');
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("HOST_NATIVE_KEY_INVALID".into());
    }
    (0..64)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "HOST_NATIVE_KEY_INVALID".into())
        })
        .collect()
}

/// The existing installed root agent is the *only* mutation authority.
/// Fail closed while the native root has not received the exact immutable
/// release and pinned signer material; no implicit provision or fetch.
pub async fn apply(stack_dir: &Path) -> Result<(), String> {
    let mut intent_pb = Vec::new();
    io::stdin()
        .take(4097)
        .read_to_end(&mut intent_pb)
        .map_err(|_| "HOST_NATIVE_INTENT_STDIN_UNAVAILABLE")?;
    let intent = decode_host_intent(&intent_pb).map_err(str::to_owned)?;
    if intent.kind != FleetHostKind::Vm as i32 {
        return Err("HOST_NATIVE_VM_KIND_REQUIRED".into());
    }
    let trust_root = Path::new(TRUSTED_ROOT);
    let trust_meta =
        fs::symlink_metadata(trust_root).map_err(|_| "HOST_NATIVE_OWNER_ROOT_NOT_PROVISIONED")?;
    if !trust_meta.file_type().is_dir()
        || trust_meta.uid() != 0
        || trust_meta.permissions().mode() & 0o077 != 0
    {
        return Err("HOST_NATIVE_OWNER_ROOT_NOT_PROTECTED".into());
    }
    let machine_id = String::from_utf8(root_file(&trust_root.join("machine-id"), 128)?)
        .map_err(|_| "HOST_NATIVE_MACHINE_ID_INVALID")?;
    let machine_id = machine_id.trim_end_matches('\n');
    if machine_id != intent.machine_id {
        return Err("HOST_NATIVE_MACHINE_ID_MISMATCH".into());
    }
    let registry_pb = root_file(&trust_root.join("fleet-registry.pb"), 65536)?;
    let release_pb = root_file(&trust_root.join("release-set.pb"), 65536)?;
    let bundle_pb = root_file(&trust_root.join("application-bundle.pb"), 8 * 1024 * 1024)?;
    let signer_key = parse_hex_key(&root_file(&trust_root.join("worker-public-key.hex"), 128)?)?;
    // No unprivileged desired override: the native root first confirms the
    // spec path is the registered Git-owned one, staged with the accepted
    // release by the owner installation procedure.
    let registry = edge_shared_types::decode_host_registry(&registry_pb)
        .map_err(|_| "HOST_NATIVE_REGISTRY_INVALID")?;
    let host = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == intent.machine_id && h.kind == intent.kind)
        .ok_or("HOST_NATIVE_MACHINE_UNREGISTERED")?;
    if host.desired_spec_path.is_empty()
        || !host
            .desired_spec_path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        || host.desired_spec_path.contains("..")
        || !host.desired_spec_path.starts_with("infra/")
    {
        return Err("HOST_NATIVE_SPEC_PATH_INVALID".into());
    }
    let spec = root_file(&trust_root.join("desired.textproto"), 65536)?;
    attest_published_github_source(
        &intent,
        &registry_pb,
        &release_pb,
        &bundle_pb,
        &spec,
        &host.desired_spec_path,
    )
    .await?;
    let identity = super::vm_credential_access_identity_path(stack_dir)?;
    // POST is never retried after an ambiguous result.
    let authorization =
        edge_secrets::request_canonical_host_authorization(&intent_pb, &identity).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_CLOCK_UNAVAILABLE")?
        .as_secs();
    let journal = Path::new(JOURNAL_ROOT);
    let handle = tokio::runtime::Handle::current();
    let result = tokio::task::block_in_place(|| {
        execute_native_host_once(
            &intent,
            &authorization,
            &registry_pb,
            &spec,
            &release_pb,
            Some(&bundle_pb),
            &signer_key,
            machine_id,
            FleetHostKind::Vm as i32,
            now,
            journal,
            || {
                handle
                    .block_on(super::capture_local_host_observation(stack_dir))
                    .map_err(|_| "HOST_NATIVE_READBACK_FAILED")
            },
            |step| match step {
                FleetHostPlannedStep::Start => {
                    let completion = handle.block_on(super::run_bootstrap(
                        stack_dir,
                        BootstrapMode::BootstrapFull,
                    ));
                    if completion.success {
                        Ok(())
                    } else {
                        Err("HOST_NATIVE_START_UNCERTAIN_NO_REPLAY")
                    }
                }
                FleetHostPlannedStep::Install | FleetHostPlannedStep::ReplaceRelease => {
                    let request = ApplyBundleRequest::decode(bundle_pb.as_slice())
                        .map_err(|_| "HOST_NATIVE_BUNDLE_INVALID")?;
                    super::apply_bundle(stack_dir, request)
                        .map_err(|_| "HOST_NATIVE_BUNDLE_APPLY_UNCERTAIN_NO_REPLAY")?;
                    let completion = handle.block_on(super::run_bootstrap(
                        stack_dir,
                        BootstrapMode::BootstrapFull,
                    ));
                    if completion.success {
                        Ok(())
                    } else {
                        Err("HOST_NATIVE_BOOTSTRAP_UNCERTAIN_NO_REPLAY")
                    }
                }
                _ => Err("HOST_NATIVE_STEP_UNSUPPORTED_NO_REPLAY"),
            },
        )
    })
    .map_err(str::to_owned)?;
    io::stdout()
        .write_all(&result.encode_to_vec())
        .map_err(|_| "HOST_NATIVE_RESULT_STDOUT_UNCERTAIN_NO_REPLAY".into())
}
