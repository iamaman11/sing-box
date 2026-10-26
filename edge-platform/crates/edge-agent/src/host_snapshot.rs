//! Root-signed, pending-safe READ-ONLY evidence from the existing Agent.
//! No alternate root executor, no journal mutation and no credential output.
use super::*;
use base64::Engine;
use edge_shared_types::host_lifecycle::decode_host_intent;
use edge_shared_types::{FleetNativeDiagnosticSnapshot, host_diagnostic_snapshot};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Default)]
struct PendingEvidence {
    count: u32,
    operation_id: String,
    resource_id: String,
    request_sha256: Vec<u8>,
    action: i32,
    original_release_sha256: Vec<u8>,
    original_desired_sha256: Vec<u8>,
    begin_record_sha256: Vec<u8>,
}

fn pending_scope(root: &Path) -> Result<PendingEvidence, String> {
    let journal = root.join("journal");
    let metadata =
        fs::symlink_metadata(&journal).map_err(|_| "HOST_SNAPSHOT_JOURNAL_UNAVAILABLE")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
        return Err("HOST_SNAPSHOT_JOURNAL_UNTRUSTED".into());
    }
    // The full journal scan rejects forged entries; it does not block on BEGIN.
    let _has_pending = host_native::protected_journal_has_pending(&journal)?;
    let mut pending = Vec::new();
    for entry in fs::read_dir(&journal).map_err(|_| "HOST_SNAPSHOT_JOURNAL_UNAVAILABLE")? {
        let entry = entry.map_err(|_| "HOST_SNAPSHOT_JOURNAL_UNAVAILABLE")?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("HOST_SNAPSHOT_JOURNAL_NAME_INVALID")?;
        if name.ends_with(".pending.pb") {
            let meta = fs::symlink_metadata(entry.path())
                .map_err(|_| "HOST_SNAPSHOT_JOURNAL_UNAVAILABLE")?;
            if !meta.is_file() || meta.uid() != 0 || meta.permissions().mode() & 0o077 != 0 {
                return Err("HOST_SNAPSHOT_JOURNAL_ENTRY_UNTRUSTED".into());
            }
            pending.push((name.to_owned(), entry.path()));
        }
    }
    pending.sort_by(|left, right| left.0.cmp(&right.0));
    if pending.len() > 64 {
        return Err("HOST_SNAPSHOT_PENDING_LIMIT_EXCEEDED".into());
    }
    let count = pending.len() as u32;
    let Some((name, path)) = pending.first() else {
        return Ok(PendingEvidence::default());
    };
    // An admin pending is not interpreted as a resource intent.
    if !name.starts_with("resource-") {
        return Ok(PendingEvidence {
            count,
            operation_id: "UNPROVEN_PENDING_RECORD".into(),
            ..Default::default()
        });
    }
    let bytes = host_native::root_file(path, 4096)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .to_vec();
    let intent = decode_host_intent(&bytes).map_err(str::to_owned)?;
    // SHA-256 file name is exactly the native journal's existing stable
    // operation key, not a new index or mutable state.
    let id_sha = ring::digest::digest(&ring::digest::SHA256, intent.operation_id.as_bytes());
    let id = id_sha
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let begin_bytes = host_native::root_file(&journal.join(format!("{id}.pb")), 8192)?;
    let begin = edge_shared_types::host_lifecycle::decode_host_result(&begin_bytes)
        .map_err(str::to_owned)?;
    if begin.schema_version != 1
        || begin.state != edge_shared_types::FleetHostResultState::Authorized as i32
        || begin.physical_readback
        || !begin.error_class.is_empty()
        || begin.operation_id != intent.operation_id
        || begin.machine_id != intent.machine_id
        || begin.resource_id != intent.resource_id
        || begin.action != intent.action
        || begin.release_set_sha256 != intent.release_set_sha256
        || begin.desired_sha256 != intent.desired_sha256
        || begin.reason
            != edge_shared_types::FleetHostResultReason::AuthorizedAwaitNativeReadback as i32
        || edge_shared_types::host_lifecycle::validate_host_result_reason(&begin).is_err()
    {
        return Err("HOST_SNAPSHOT_ORIGINAL_BEGIN_MISMATCH".into());
    }
    Ok(PendingEvidence {
        count,
        operation_id: intent.operation_id,
        resource_id: intent.resource_id,
        request_sha256: digest,
        action: intent.action,
        original_release_sha256: intent.release_set_sha256,
        original_desired_sha256: intent.desired_sha256,
        begin_record_sha256: ring::digest::digest(&ring::digest::SHA256, &begin_bytes)
            .as_ref()
            .to_vec(),
    })
}

/// Optional source-comment correlation on stdin. Existing `local diagnose`
/// callers supplying no stdin still work unchanged, without an extra service
/// or sudoers entry. Only bounded signed protobuf is exported.
pub(super) async fn emit_if_requested(stack_dir: &Path) -> Result<(), String> {
    let mut source = String::new();
    io::stdin()
        .take(24)
        .read_to_string(&mut source)
        .map_err(|_| "HOST_SNAPSHOT_REQUEST_UNREADABLE")?;
    if source.is_empty() {
        return Ok(());
    }
    if source.len() > 20 || source.starts_with('0') || !source.bytes().all(|b| b.is_ascii_digit()) {
        return Err("HOST_SNAPSHOT_REQUEST_INVALID".into());
    }
    let comment_id: u64 = source
        .parse()
        .map_err(|_| "HOST_SNAPSHOT_REQUEST_INVALID")?;
    if comment_id == 0 {
        return Err("HOST_SNAPSHOT_REQUEST_INVALID".into());
    }
    let root = Path::new(host_native::TRUSTED_ROOT);
    let metadata = fs::symlink_metadata(root).map_err(|_| "HOST_SNAPSHOT_TRUST_UNAVAILABLE")?;
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
    let pending = pending_scope(root)?;
    let observation = capture_local_host_observation(stack_dir).await?;
    let resources = docker_observation::observe_vm_resource_report(&host, stack_dir).await?;
    let mut line2_code = String::new();
    let mut line2_digest = Vec::new();
    let mut line2_restarts = 0;
    let mut line2_exit = -1;
    if let Some(line2) = host
        .vm_containers
        .iter()
        .find(|c| c.container_name.contains("line2"))
    {
        match observe_container_runtime(&line2.container_name).await {
            Ok(evidence) => {
                line2_code = local_dispatch::classify_native_container_failure(
                    evidence.runtime_error.as_deref(),
                    &evidence.log_tail,
                )
                .to_owned();
                line2_digest = ring::digest::digest(
                    &ring::digest::SHA256,
                    evidence.log_tail.join("\n").as_bytes(),
                )
                .as_ref()
                .to_vec();
                line2_restarts = evidence.restart_count.unwrap_or(0);
                line2_exit = evidence.exit_code.unwrap_or(-1);
            }
            Err(_) => line2_code = "DOCKER_READBACK_UNAVAILABLE".into(),
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_SNAPSHOT_CLOCK_INVALID")?
        .as_secs();
    let mut snapshot = FleetNativeDiagnosticSnapshot {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        operation_id: format!("issue1-comment-{comment_id}"),
        release_set_sha256: ring::digest::digest(&ring::digest::SHA256, &trust.release_set_pb)
            .as_ref()
            .to_vec(),
        observation: Some(observation),
        resources: Some(resources),
        ed25519_signature: Vec::new(),
        pending_resource_count: pending.count,
        pending_operation_id: pending.operation_id,
        pending_resource_id: pending.resource_id,
        pending_request_sha256: pending.request_sha256,
        pending_action: pending.action,
        pending_original_release_sha256: pending.original_release_sha256,
        pending_original_desired_sha256: pending.original_desired_sha256,
        pending_begin_record_sha256: pending.begin_record_sha256,
        line2_failure_code: line2_code,
        line2_log_sha256: line2_digest,
        line2_restart_count: line2_restarts,
        line2_last_exit_code: line2_exit,
    };
    host_diagnostic_snapshot::sign(&mut snapshot, &host, &key, now).map_err(str::to_owned)?;
    let bytes = snapshot.encode_to_vec();
    println!(
        "host_root_signed_snapshot_b64={}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    );
    println!(
        "host_root_signed_snapshot_has_pending={}",
        snapshot.pending_resource_count > 0
    );
    println!("host_root_signed_snapshot_mutations=0");
    Ok(())
}
