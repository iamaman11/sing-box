//! Uses the SAME Root Agent observation and Docker collectors as native apply.
//! Read-only, signed with the existing root key; never writes the resource journal.
use super::*;
use edge_shared_types::FleetNativeDiagnosticSnapshot;
use edge_shared_types::host_diagnostic_snapshot;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(super) async fn run(stack_dir: &Path) -> Result<(), String> {
    // The source comment is correlation, not authorization. The native signer
    // attests to its own fresh physical readback, never to runner claims.
    let mut source = String::new();
    io::stdin().take(24).read_to_string(&mut source)
        .map_err(|_| "HOST_SNAPSHOT_REQUEST_UNREADABLE")?;
    if source.is_empty() || source.len() > 20 || source.starts_with('0')
        || !source.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("HOST_SNAPSHOT_REQUEST_INVALID".into());
    }
    let comment_id = source.parse::<u64>()
        .map_err(|_| "HOST_SNAPSHOT_REQUEST_INVALID")?;
    if comment_id == 0 { return Err("HOST_SNAPSHOT_REQUEST_INVALID".into()); }
    let root = Path::new(host_native::TRUSTED_ROOT);
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| "HOST_SNAPSHOT_TRUST_UNAVAILABLE")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
        return Err("HOST_SNAPSHOT_TRUST_UNPROVEN".into());
    }
    let trust_bytes = host_native::root_file(&root.join("trust.pb"), 9 * 1024 * 1024)?;
    let trust = host_native::decode_native_trust_snapshot(&trust_bytes)?;
    let host = host_native::registered_vm_host()?;
    if trust.machine_id != host.machine_id {
        return Err("HOST_SNAPSHOT_MACHINE_MISMATCH".into());
    }
    let key = host_native::root_file(&root.join("receipt-key.pk8"), 4096)?;
    let observation = capture_local_host_observation(stack_dir).await?;
    let resources = docker_observation::observe_vm_resource_report(&host, stack_dir).await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_SNAPSHOT_CLOCK_INVALID")?.as_secs();
    let mut snapshot = FleetNativeDiagnosticSnapshot {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        operation_id: format!("issue1-comment-{comment_id}"),
        release_set_sha256: ring::digest::digest(
            &ring::digest::SHA256, &trust.release_set_pb).as_ref().to_vec(),
        observation: Some(observation),
        resources: Some(resources),
        ed25519_signature: Vec::new(),
    };
    host_diagnostic_snapshot::sign(&mut snapshot, &host, &key, now)
        .map_err(str::to_owned)?;
    io::stdout().write_all(&snapshot.encode_to_vec())
        .map_err(|_| "HOST_SNAPSHOT_STDOUT_UNAVAILABLE".to_owned())
}
