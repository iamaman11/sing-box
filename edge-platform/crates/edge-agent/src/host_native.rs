//! One root-owned VM host command. Runner stdin carries ONLY the canonical
//! operation identifier; native release and desired bytes are never accepted
//! from a workflow artifact or the caller's path arguments.
use super::*;
use edge_shared_types::{FleetHostKind, FleetHostPlannedStep};
use edge_shared_types::host_lifecycle::decode_host_intent;
use edge_shared_types::host_journal::execute_native_host_once;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const TRUSTED_ROOT: &str = "/opt/vultr-edge-stack/native-host";
const JOURNAL_ROOT: &str = "/opt/vultr-edge-stack/native-host/journal";

fn root_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if !path.starts_with(TRUSTED_ROOT) {
        return Err("HOST_NATIVE_PATH_OUTSIDE_OWNER_ROOT".into());
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "HOST_NATIVE_OWNER_FILE_MISSING")?;
    if !meta.file_type().is_file() || meta.uid() != 0
        || meta.permissions().mode() & 0o077 != 0
        || meta.len() == 0 || meta.len() > limit
    {
        return Err("HOST_NATIVE_OWNER_FILE_NOT_PROTECTED".into());
    }
    fs::read(path).map_err(|_| "HOST_NATIVE_OWNER_FILE_UNREADABLE".into())
}

fn parse_hex_key(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let hex = std::str::from_utf8(bytes).map_err(|_| "HOST_NATIVE_KEY_INVALID")?.trim_end_matches('\n');
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("HOST_NATIVE_KEY_INVALID".into());
    }
    (0..64).step_by(2).map(|i| {
        u8::from_str_radix(&hex[i..i+2], 16).map_err(|_| "HOST_NATIVE_KEY_INVALID".into())
    }).collect()
}

/// The existing installed root agent is the *only* mutation authority.
/// Fail closed while the native root has not received the exact immutable
/// release and pinned signer material; no implicit provision or fetch.
pub async fn apply(stack_dir: &Path) -> Result<(), String> {
    let mut intent_pb = Vec::new();
    io::stdin().take(4097).read_to_end(&mut intent_pb)
        .map_err(|_| "HOST_NATIVE_INTENT_STDIN_UNAVAILABLE")?;
    let intent = decode_host_intent(&intent_pb).map_err(str::to_owned)?;
    if intent.kind != FleetHostKind::Vm as i32 {
        return Err("HOST_NATIVE_VM_KIND_REQUIRED".into());
    }
    let trust_root = Path::new(TRUSTED_ROOT);
    let trust_meta = fs::symlink_metadata(trust_root)
        .map_err(|_| "HOST_NATIVE_OWNER_ROOT_NOT_PROVISIONED")?;
    if !trust_meta.file_type().is_dir() || trust_meta.uid() != 0
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
    let host = registry.hosts.iter()
        .find(|h| h.machine_id == intent.machine_id && h.kind == intent.kind)
        .ok_or("HOST_NATIVE_MACHINE_UNREGISTERED")?;
    if host.desired_spec_path.is_empty() || !host.desired_spec_path
        .bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/'|b'.'|b'_'|b'-'))
        || host.desired_spec_path.contains("..")
        || !host.desired_spec_path.starts_with("infra/")
    {
        return Err("HOST_NATIVE_SPEC_PATH_INVALID".into());
    }
    let spec = root_file(&trust_root.join("desired.textproto"), 65536)?;
    let identity = super::vm_credential_access_identity_path(stack_dir)?;
    // POST is never retried after an ambiguous result.
    let authorization = edge_secrets::request_canonical_host_authorization(&intent_pb, &identity)
        .await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_CLOCK_UNAVAILABLE")?.as_secs();
    let journal = Path::new(JOURNAL_ROOT);
    let handle = tokio::runtime::Handle::current();
    let result = tokio::task::block_in_place(|| execute_native_host_once(
        &intent, &authorization, &registry_pb, &spec, &release_pb, Some(&bundle_pb),
        &signer_key, machine_id, FleetHostKind::Vm as i32, now, journal,
        || tokio::task::block_in_place(|| handle.block_on(super::capture_local_host_observation(stack_dir)))
            .map_err(|_| "HOST_NATIVE_READBACK_FAILED"),
        |step| {
            match step {
                FleetHostPlannedStep::Start => {
                    let completion = handle.block_on(super::run_bootstrap(
                        stack_dir, BootstrapMode::BootstrapFull
                    ));
                    if completion.success { Ok(()) } else { Err("HOST_NATIVE_START_UNCERTAIN_NO_REPLAY") }
                }
                FleetHostPlannedStep::Install | FleetHostPlannedStep::ReplaceRelease => {
                    let request = ApplyBundleRequest::decode(bundle_pb.as_slice())
                        .map_err(|_| "HOST_NATIVE_BUNDLE_INVALID")?;
                    super::apply_bundle(stack_dir, request)
                        .map_err(|_| "HOST_NATIVE_BUNDLE_APPLY_UNCERTAIN_NO_REPLAY")?;
                    let completion = handle.block_on(super::run_bootstrap(
                        stack_dir, BootstrapMode::BootstrapFull
                    ));
                    if completion.success { Ok(()) } else { Err("HOST_NATIVE_BOOTSTRAP_UNCERTAIN_NO_REPLAY") }
                }
                _ => Err("HOST_NATIVE_STEP_UNSUPPORTED_NO_REPLAY"),
            }
        }
    )).map_err(str::to_owned)?;
    io::stdout().write_all(&result.encode_to_vec())
        .map_err(|_| "HOST_NATIVE_RESULT_STDOUT_UNCERTAIN_NO_REPLAY".into())
}
