//! One Windows LocalSystem execution path for the already-installed
//! EdgePlatformPrivilegedDispatch task. GitHub is transport, never SCM owner.
//! The protected trust + journal must be enrolled separately by SYSTEM;
//! their absence is a hard denial, not permission for a runner fallback.

use super::*;
use edge_shared_types::{
    FleetHostAction, FleetHostAuthorization, FleetHostIntent, FleetHostKind, FleetHostMode,
    FleetHostPlannedStep, FleetNativeObservation, FleetNativeTrustSnapshot,
    host_journal::{execute_native_host_once, verify_native_journal_protection},
    host_lifecycle::{bind_native_host_artifacts, decode_host_intent},
    host_receipt::{check_native_receipt_key, sign_native_receipt},
};
use prost::Message;
use ring::digest::{SHA256, digest};

const INTENT_FILE: &str = "host-intent.pb";
const RECEIPT_FILE: &str = "host-receipt.pb";
const TRUST_FILE: &str = "trust.pb";
const RECEIPT_KEY_FILE: &str = "receipt-key.pk8";

fn bounded_regular_file(path: &Path, max: u64) -> Result<Vec<u8>, &'static str> {
    let meta = fs::symlink_metadata(path).map_err(|_| "HOST_WINDOWS_NATIVE_FILE_MISSING")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > max {
        return Err("HOST_WINDOWS_NATIVE_FILE_NOT_BOUNDED_REGULAR");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "HOST_WINDOWS_NATIVE_FILE_UNREADABLE")?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "HOST_WINDOWS_NATIVE_FILE_UNREADABLE")?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err("HOST_WINDOWS_NATIVE_FILE_NOT_BOUNDED_REGULAR");
    }
    Ok(bytes)
}

fn lowercase_sha(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

/// Only the installed SYSTEM trust supplies the Git registry, exact spec,
/// release and public signer. No runner-provided trust fields are accepted.
/// A Windows trust snapshot uses the existing FleetNativeTrustSnapshot without
/// VM bundle bytes; VM first-use retains its own stricter VM-only decoder.
fn verify_system_trust(
    bytes: &[u8],
    intent: &FleetHostIntent,
    installed_release_sha256: &str,
    private_key: &[u8],
) -> Result<FleetNativeTrustSnapshot, &'static str> {
    if bytes.is_empty() || bytes.len() > 9 * 1024 * 1024 {
        return Err("HOST_WINDOWS_SYSTEM_TRUST_SIZE_INVALID");
    }
    let trust = FleetNativeTrustSnapshot::decode(bytes)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_TRUST_PROTO_INVALID")?;
    if trust.encode_to_vec() != bytes
        || trust.schema_version != 1
        || trust.machine_id != intent.machine_id
        || intent.kind != FleetHostKind::Windows as i32
        || !trust.application_bundle_pb.is_empty()
        || trust.pinned_worker_public_key.len() != 32
        || trust.pinned_worker_public_key.iter().all(|key| *key == 0)
    {
        return Err("HOST_WINDOWS_SYSTEM_TRUST_IDENTITY_INVALID");
    }
    let (registry, bound) = bind_native_host_artifacts(
        intent, &trust.registry_pb, &trust.selected_spec_bytes,
        &trust.release_set_pb, None,
    )?;
    let host = registry.hosts.iter()
        .find(|host| host.machine_id == intent.machine_id && host.kind == intent.kind)
        .ok_or("HOST_WINDOWS_SYSTEM_HOST_NOT_REGISTERED")?;
    edge_shared_types::host_lifecycle::verify_git_host_worker_signer_pin(
        host, &trust.pinned_worker_public_key,
    )?;
    check_native_receipt_key(host, private_key)?;
    if lowercase_sha(&bound.release_set_sha256) != installed_release_sha256 {
        return Err("HOST_WINDOWS_INSTALLED_SOURCE_RELEASE_DRIFT");
    }
    Ok(trust)
}

fn system_native_observation(install_root: &Path) -> Result<FleetNativeObservation, &'static str> {
    let active = load_verified_activation(install_root)
        .map_err(|_| "HOST_WINDOWS_NATIVE_ACTIVATION_UNPROVEN")?;
    // The exact native binary's typed host-observe is required. An older
    // doctor stdout cannot be interpreted as an authenticated protobuf.
    let child = Command::new(&active.diagnostic_path)
        .arg("host-observe")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "HOST_WINDOWS_NATIVE_READBACK_EXEC_FAILED")?;
    if !child.status.success() || child.stdout.is_empty() || child.stdout.len() > 4096 {
        return Err("HOST_WINDOWS_NATIVE_READBACK_UNPROVEN");
    }
    let readback = FleetNativeObservation::decode(child.stdout.as_slice())
        .map_err(|_| "HOST_WINDOWS_NATIVE_READBACK_PROTO_INVALID")?;
    if readback.encode_to_vec() != child.stdout {
        return Err("HOST_WINDOWS_NATIVE_READBACK_NONCANONICAL");
    }
    edge_shared_types::host_lifecycle::validate_native_observation(&readback)?;
    if readback.host_kind != FleetHostKind::Windows as i32 {
        return Err("HOST_WINDOWS_NATIVE_READBACK_KIND_MISMATCH");
    }
    Ok(readback)
}

#[cfg(windows)]
fn apply_exact_proxyonly_scm_step(step: FleetHostPlannedStep) -> Result<(), &'static str> {
    let scm = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_SCM_UNAVAILABLE")?;
    let service = scm.open_service(
        WINDOWS_CONTROLLER_SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
    ).map_err(|_| "HOST_WINDOWS_SYSTEM_CONTROLLER_UNAVAILABLE")?;
    match step {
        FleetHostPlannedStep::Start => {
            service.start::<&str>(&[])
                .map_err(|_| "HOST_WINDOWS_SYSTEM_START_FAILED")?;
            wait_for_service_state(
                &service, ServiceState::Running,
                Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
            ).map_err(|_| "HOST_WINDOWS_SYSTEM_START_POSTSTATE_UNPROVEN")?;
        }
        FleetHostPlannedStep::Stop => {
            service.stop().map_err(|_| "HOST_WINDOWS_SYSTEM_STOP_FAILED")?;
            wait_for_service_state(
                &service, ServiceState::Stopped,
                Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
            ).map_err(|_| "HOST_WINDOWS_SYSTEM_STOP_POSTSTATE_UNPROVEN")?;
        }
        _ => return Err("HOST_WINDOWS_SYSTEM_UNSUPPORTED_STEP"),
    }
    Ok(())
}

/// Returns false when the existing task should process the legacy, read-only
/// Ping/RuntimeEvidence. A signed request cannot coexist with the old format.
pub(super) async fn dispatch_if_present(install_root: &Path) -> Result<bool, String> {
    let request = install_root.join("exchange").join("requests").join(INTENT_FILE);
    match fs::symlink_metadata(&request) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("HOST_WINDOWS_SYSTEM_REQUEST_METADATA_UNAVAILABLE".into()),
        Ok(meta) if !meta.file_type().is_file() => {
            return Err("HOST_WINDOWS_SYSTEM_REQUEST_NOT_REGULAR".into());
        }
        Ok(_) => {}
    }
    if privileged_request_path(install_root).exists() {
        return Err("HOST_WINDOWS_SYSTEM_COMPETING_LEGACY_REQUEST".into());
    }
    // Already-retargeted immutable console, not mutable bin/edge-console.exe.
    require_exact_immutable_activation_console(install_root)?;
    let protected = install_root.join("native-host");
    let journal = protected.join("journal");
    verify_native_journal_protection(&journal).map_err(str::to_owned)?;
    let intent_bytes = bounded_regular_file(
        &request, edge_shared_types::host_lifecycle::MAX_HOST_INTENT_BYTES as u64,
    ).map_err(str::to_owned)?;
    let intent = decode_host_intent(&intent_bytes).map_err(str::to_owned)?;
    if intent.kind != FleetHostKind::Windows as i32
        || intent.resource_id != "sing-box"
        || !matches!(
            FleetHostAction::try_from(intent.action),
            Ok(FleetHostAction::Start | FleetHostAction::Stop)
        )
    {
        return Err("HOST_WINDOWS_SYSTEM_ACTION_NOT_ACCEPTED".into());
    }
    let trust_bytes = bounded_regular_file(&protected.join(TRUST_FILE), 9 * 1024 * 1024)
        .map_err(str::to_owned)?;
    let receipt_private = bounded_regular_file(
        &protected.join(RECEIPT_KEY_FILE), 4096,
    ).map_err(str::to_owned)?;
    let installed = load_verified_activation(install_root)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_ACTIVATION_UNPROVEN")?;
    let trust = verify_system_trust(
        &trust_bytes, &intent, &installed.release_set_sha256, &receipt_private,
    ).map_err(str::to_owned)?;
    let registry = edge_shared_types::decode_host_registry(&trust.registry_pb)?;
    let selected = registry.hosts.iter()
        .find(|host| host.machine_id == intent.machine_id && host.kind == intent.kind)
        .ok_or("HOST_WINDOWS_SYSTEM_HOST_NOT_REGISTERED")?;
    let mode = selected.target.as_ref()
        .map(|target| FleetHostMode::try_from(target.windows_mode))
        .transpose().map_err(|_| "HOST_WINDOWS_SYSTEM_TARGET_MODE_INVALID")?;
    if mode != Some(FleetHostMode::ProxyOnly) {
        return Err("HOST_WINDOWS_SYSTEM_PROXY_ONLY_REQUIRED".into());
    }
    // A pre-BEGIN native SCM/readback failure never creates journal state.
    system_native_observation(install_root).map_err(str::to_owned)?;
    let identity = install_root.join("state").join("secrets").join(ACCESS_IDENTITY_FILE_NAME);
    edge_secrets::diagnose_canonical_host_access(&identity)
        .await.map_err(str::to_owned)?;
    // Worker POST is one-shot; no fallback to a runner-supplied signature.
    let auth: FleetHostAuthorization =
        edge_secrets::request_canonical_host_authorization(&intent_bytes, &identity).await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_CLOCK_UNAVAILABLE")?.as_secs();
    let result = tokio::task::block_in_place(|| {
        execute_native_host_once(
            &intent, &auth, &trust.registry_pb, &trust.selected_spec_bytes,
            &trust.release_set_pb, None, &trust.pinned_worker_public_key,
            &trust.machine_id, FleetHostKind::Windows as i32, now, &journal,
            || system_native_observation(install_root),
            |step| match step {
                FleetHostPlannedStep::Start | FleetHostPlannedStep::Stop => Ok(()),
                _ => Err("HOST_WINDOWS_SYSTEM_NATIVE_STEP_NOT_ACCEPTED"),
            },
            apply_exact_proxyonly_scm_step,
        )
    }).map_err(str::to_owned)?;
    // Native journal has already fsynced terminal before SYSTEM signs.
    let signed = sign_native_receipt(&intent, &result, selected, &receipt_private)
        .map_err(str::to_owned)?;
    let receipt_path = install_root.join("exchange").join("results").join(RECEIPT_FILE);
    write_atomic(&receipt_path, &signed.encode_to_vec())
        .map_err(|_| "HOST_WINDOWS_SYSTEM_RECEIPT_PUBLISH_UNCERTAIN")?;
    fs::remove_file(request)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_REQUEST_CONSUMPTION_UNCERTAIN")?;
    println!("status=PASS");
    println!("native_system_receipt=SIGNED_TERMINAL");
    println!("native_system_operation_id={}", intent.operation_id);
    println!("native_system_replay_allowed=false");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_system_trust_can_be_synthesized_from_a_runner_intent() {
        let intent = FleetHostIntent {
            schema_version: 1,
            kind: FleetHostKind::Windows as i32,
            machine_id: "sing-box-windows-lab".into(),
            ..Default::default()
        };
        assert_eq!(
            verify_system_trust(&[], &intent, &"a".repeat(64), &[]),
            Err("HOST_WINDOWS_SYSTEM_TRUST_SIZE_INVALID"),
        );
        let wrong_kind = FleetHostIntent {
            kind: FleetHostKind::Vm as i32,
            ..intent.clone()
        };
        let snapshot = FleetNativeTrustSnapshot {
            schema_version: 1,
            machine_id: intent.machine_id.clone(),
            pinned_worker_public_key: vec![4; 32],
            ..Default::default()
        };
        assert_eq!(
            verify_system_trust(&snapshot.encode_to_vec(), &wrong_kind, &"a".repeat(64), &[]),
            Err("HOST_WINDOWS_SYSTEM_TRUST_IDENTITY_INVALID"),
        );
        let no_pin = FleetNativeTrustSnapshot {
            pinned_worker_public_key: vec![],
            ..snapshot.clone()
        };
        assert_eq!(
            verify_system_trust(&no_pin.encode_to_vec(), &intent, &"a".repeat(64), &[]),
            Err("HOST_WINDOWS_SYSTEM_TRUST_IDENTITY_INVALID"),
        );
    }
}
