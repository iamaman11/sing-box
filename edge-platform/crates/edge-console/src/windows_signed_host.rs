//! One Windows LocalSystem execution path for the already-installed
//! EdgePlatformPrivilegedDispatch task. GitHub is transport, never SCM owner.
//! The protected trust + journal must be enrolled separately by SYSTEM;
//! their absence is a hard denial, not permission for a runner fallback.

use super::*;
use edge_shared_types::{
    FleetHostAction, FleetHostAuthorization, FleetHostIntent, FleetHostKind, FleetHostPlannedStep,
    FleetNativeObservation, FleetNativeTrustSnapshot,
    host_journal::verify_native_journal_protection,
    host_lifecycle::{bind_native_host_artifacts, decode_host_intent},
    host_receipt::{check_native_receipt_key, sign_native_receipt},
};
use prost::Message;
use ring::digest::{SHA256, digest};

const INTENT_FILE: &str = "host-intent.pb";
const RECEIPT_FILE: &str = "host-receipt.pb";
const RECEIPT_KEY_FILE: &str = "receipt-key.pk8";

/// Keep the exact exchange object non-writable and non-replaceable while
/// authorizing/executing. Consume by handle, never unlink a swapped pathname.
pub(super) struct TransportRequest {
    file: File,
    pub(super) bytes: Vec<u8>,
}
impl TransportRequest {
    pub(super) fn open(path: &Path, max: u64) -> Result<Self, &'static str> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let mut file = OpenOptions::new()
            .read(true)
            .access_mode(0x80000000 | 0x00010000)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(path)
            .map_err(|_| "HOST_WINDOWS_TRANSPORT_REQUEST_LOCK_UNAVAILABLE")?;
        let meta = file
            .metadata()
            .map_err(|_| "HOST_WINDOWS_TRANSPORT_REQUEST_METADATA_UNAVAILABLE")?;
        if !meta.is_file()
            || meta.file_attributes() & 0x400 != 0
            || meta.len() == 0
            || meta.len() > max
        {
            return Err("HOST_WINDOWS_TRANSPORT_REQUEST_NOT_BOUNDED_REGULAR");
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "HOST_WINDOWS_TRANSPORT_REQUEST_READ_UNAVAILABLE")?;
        if bytes.len() as u64 != meta.len() {
            return Err("HOST_WINDOWS_TRANSPORT_REQUEST_CHANGED");
        }
        Ok(Self { file, bytes })
    }
    pub(super) fn consume(self) -> Result<(), &'static str> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };
        let delete = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                FileDispositionInfo,
                (&delete as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&delete) as u32,
            )
        } == 0
        {
            return Err("HOST_WINDOWS_REQUEST_CONSUMPTION_UNKNOWN_NO_REPLAY");
        }
        Ok(())
    }
}

pub(super) fn bounded_regular_file(path: &Path, max: u64) -> Result<Vec<u8>, &'static str> {
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

/// Common authority loader for lifecycle and universal admin. The local
/// bootstrap anchors the installed runtime; independently fetched protected
/// Git anchors current authority. The binding intent is NEVER executed.
pub(super) async fn current_authority(
    install_root: &Path,
    machine_id: &str,
    operation_id: &str,
    requested_at: u64,
    private: &[u8],
) -> Result<
    (
        FleetNativeTrustSnapshot,
        edge_shared_types::FleetHost,
        Vec<u8>,
    ),
    String,
> {
    let installed = load_verified_activation(install_root)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_ACTIVATION_UNPROVEN")?;
    let trust_path = install_root.join("native-host/trust.pb");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&trust_path, true)?;
    let bytes = bounded_regular_file(&trust_path, 9 * 1024 * 1024)?;
    let boot = FleetNativeTrustSnapshot::decode(bytes.as_slice())
        .map_err(|_| "HOST_WINDOWS_SYSTEM_TRUST_PROTO_INVALID")?;
    fn binding(
        machine: &str,
        op: &str,
        when: u64,
        registry: &[u8],
        spec: &[u8],
        release: &[u8],
        historical_windows_trust: bool,
    ) -> Result<FleetHostIntent, String> {
        let hosts = if historical_windows_trust {
            edge_shared_types::host_lifecycle::decode_historical_windows_trust_registry(
                registry, spec, machine,
            )
            .map_err(str::to_owned)?
        } else {
            edge_shared_types::decode_host_registry(registry)?
        };
        let host = hosts
            .hosts
            .iter()
            .find(|h| h.machine_id == machine && h.kind == FleetHostKind::Windows as i32)
            .ok_or("HOST_WINDOWS_SYSTEM_HOST_NOT_REGISTERED")?;
        Ok(FleetHostIntent {
            schema_version: 1,
            machine_id: machine.into(),
            kind: FleetHostKind::Windows as i32,
            resource_id: "sing-box".into(),
            operation_id: op.into(),
            action: FleetHostAction::Stop as i32,
            registry_sha256: digest(&SHA256, registry).as_ref().to_vec(),
            desired_sha256: edge_shared_types::host_lifecycle::digest_host_desired(host, spec)?,
            release_set_sha256: digest(&SHA256, release).as_ref().to_vec(),
            requested_at_unix: when,
            ..Default::default()
        })
    }
    let historical = binding(
        machine_id,
        operation_id,
        requested_at,
        &boot.registry_pb,
        &boot.selected_spec_bytes,
        &boot.release_set_pb,
        true,
    )?;
    let boot = verify_system_trust(&bytes, &historical, &installed.release_set_sha256, private)?;
    let (installed_pb, current_pb, registry_pb, spec) =
        windows_trust_enrollment::fetch_exact_protected_git(&installed).await?;
    if installed_pb != boot.release_set_pb {
        return Err("HOST_WINDOWS_SYSTEM_INSTALLED_GIT_RELEASE_CHANGED".into());
    }
    let binding = binding(
        machine_id,
        operation_id,
        requested_at,
        &registry_pb,
        &spec,
        &current_pb,
        false,
    )?;
    let (registry, _) =
        bind_native_host_artifacts(&binding, &registry_pb, &spec, &current_pb, None)?;
    let selected = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == machine_id && h.kind == FleetHostKind::Windows as i32)
        .ok_or("HOST_WINDOWS_SYSTEM_HOST_NOT_REGISTERED")?
        .clone();
    edge_shared_types::host_lifecycle::verify_windows_signed_git_prerequisites(&selected)?;
    if selected.worker_authority_public_key != boot.pinned_worker_public_key {
        return Err("HOST_WINDOWS_SYSTEM_SIGNER_ROTATION_UNPROVEN".into());
    }
    check_native_receipt_key(&selected, private)?;
    Ok((
        FleetNativeTrustSnapshot {
            registry_pb,
            selected_spec_bytes: spec,
            release_set_pb: current_pb,
            ..boot
        },
        selected,
        digest(&SHA256, &installed_pb).as_ref().to_vec(),
    ))
}

fn lowercase_sha(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

/// Only the installed SYSTEM trust supplies the Git registry, exact spec,
/// release and public signer. No runner-provided trust fields are accepted.
/// A Windows trust snapshot uses the existing FleetNativeTrustSnapshot without
/// VM bundle bytes; VM first-use retains its own stricter VM-only decoder.
pub(super) fn verify_system_trust(
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
    let (registry, bound) =
        edge_shared_types::host_lifecycle::bind_historical_windows_trust_artifacts(
            intent,
            &trust.registry_pb,
            &trust.selected_spec_bytes,
            &trust.release_set_pb,
        )?;
    let host = registry
        .hosts
        .iter()
        .find(|host| host.machine_id == intent.machine_id && host.kind == intent.kind)
        .ok_or("HOST_WINDOWS_SYSTEM_HOST_NOT_REGISTERED")?;
    edge_shared_types::host_lifecycle::verify_git_host_worker_signer_pin(
        host,
        &trust.pinned_worker_public_key,
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
    let mut readback = FleetNativeObservation::decode(child.stdout.as_slice())
        .map_err(|_| "HOST_WINDOWS_NATIVE_READBACK_PROTO_INVALID")?;
    if readback.encode_to_vec() != child.stdout {
        return Err("HOST_WINDOWS_NATIVE_READBACK_NONCANONICAL");
    }
    readback.windows_config_sha256 = windows_config::observed_digest(install_root)?;
    edge_shared_types::host_lifecycle::validate_native_observation(&readback)?;
    if readback.host_kind != FleetHostKind::Windows as i32 {
        return Err("HOST_WINDOWS_NATIVE_READBACK_KIND_MISMATCH");
    }
    if readback.owner_state == edge_shared_types::FleetNativeOwnerState::Running as i32 {
        let config = local_singbox_config_path(install_root);
        let processes = edge_local_runtime::exact_managed_runtime_processes(&config);
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|_| "HOST_WINDOWS_SCM_READBACK_UNAVAILABLE")?;
        let service = manager
            .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .map_err(|_| "HOST_WINDOWS_SCM_READBACK_UNAVAILABLE")?;
        let pid = service
            .query_status()
            .map_err(|_| "HOST_WINDOWS_SCM_READBACK_UNAVAILABLE")?
            .process_id;
        let owned = processes.len() == 1
            && pid.is_some()
            && processes[0].parent_pid == pid
            && processes[0].executable_path.as_ref().is_some_and(|p| {
                Path::new(p).canonicalize().ok()
                    == Path::new(&active.sing_box_path).canonicalize().ok()
            });
        if owned {
            let ready = tokio::runtime::Handle::current().block_on(proxy_traffic_ready());
            readback.runtime_ready_proven = ready;
            readback.runtime_ready = ready;
        } else {
            readback
                .reason_codes
                .push("WINDOWS_NATIVE_CHILD_OWNERSHIP_UNPROVEN".into());
        }
    }
    Ok(readback)
}

/// TLS+HTTPS through the actual local proxy, never a direct fallback. This is
/// runtime connectivity proof only, not full Line1/Line2/IPv6/WARP acceptance.
async fn proxy_traffic_ready() -> bool {
    let proxy = match reqwest::Proxy::all(format!("http://127.0.0.1:{STAGE2_DESKTOP_PROXY_PORT}")) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let client = match reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    for url in [
        "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com/generate_204",
    ] {
        match client.get(url).send().await {
            Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {}
            _ => return false,
        }
    }
    true
}

#[cfg(windows)]
fn apply_exact_proxyonly_scm_step(
    step: FleetHostPlannedStep,
    root: &Path,
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    private: &[u8],
    installed_sha: &[u8],
    config: Option<&windows_config::Configuration>,
    trust: &FleetNativeTrustSnapshot,
) -> Result<(), &'static str> {
    let scm = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_SCM_UNAVAILABLE")?;
    let service = scm
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
        )
        .map_err(|_| "HOST_WINDOWS_SYSTEM_CONTROLLER_UNAVAILABLE")?;
    match step {
        FleetHostPlannedStep::Start => {
            let config = config.ok_or("HOST_WINDOWS_RUNTIME_CONFIGURATION_REQUIRED")?;
            windows_config::apply(root, config, &intent.operation_id)?;
            windows_config::prepare_runtime_logs(root)?;
            service
                .start::<&str>(&[])
                .map_err(|_| "HOST_WINDOWS_SYSTEM_START_FAILED")?;
            wait_for_service_state(
                &service,
                ServiceState::Running,
                Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
            )
            .map_err(|_| "HOST_WINDOWS_SYSTEM_START_POSTSTATE_UNPROVEN")?;
            // SCM owns the persistent Controller; the scheduled task must not
            // leave an unsupervised sing-box child behind when it exits.
            let pid = service
                .query_status()
                .map_err(|_| "HOST_WINDOWS_CONTROLLER_PID_UNPROVEN")?
                .process_id
                .ok_or("HOST_WINDOWS_CONTROLLER_PID_UNPROVEN")?;
            tokio::runtime::Handle::current().block_on(async {
                let channel = tonic::transport::Endpoint::from_static(WINDOWS_CONTROLLER_ENDPOINT)
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(45))
                    .connect()
                    .await
                    .map_err(|_| "HOST_WINDOWS_CONTROLLER_CHANNEL_UNAVAILABLE")?;
                let mut client = ControllerServiceClient::new(channel);
                let challenge = client
                    .get_native_runtime_challenge(Empty {})
                    .await
                    .map_err(|_| "HOST_WINDOWS_CONTROLLER_CHALLENGE_UNAVAILABLE")?
                    .into_inner();
                if challenge.process_id != pid as u64
                    || challenge.installed_release_sha256 != installed_sha
                    || challenge.nonce.len() != 32
                {
                    return Err("HOST_WINDOWS_CONTROLLER_CHALLENGE_IDENTITY_MISMATCH");
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "HOST_WINDOWS_EFFECT_CLOCK_INVALID")?
                    .as_secs();
                let mut effect = edge_shared_types::FleetWindowsRuntimeEffect {
                    schema_version: 1,
                    intent: Some(intent.clone()),
                    authorization: Some(authorization.clone()),
                    challenge: Some(challenge),
                    config_sha256: config.digest.clone(),
                    expires_at_unix: now.saturating_add(60).min(authorization.expires_at_unix),
                    registry_pb: trust.registry_pb.clone(),
                    selected_spec_bytes: trust.selected_spec_bytes.clone(),
                    ..Default::default()
                };
                edge_shared_types::windows_runtime_effect::sign(&mut effect, private)?;
                let response = client
                    .start_local_runtime(StartLocalRuntimeRequest {
                        native_system_effect: effect.encode_to_vec(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|_| "HOST_WINDOWS_CONTROLLER_NATIVE_EFFECT_UNPROVEN")?
                    .into_inner();
                if !response.success || response.pid.is_none() {
                    return Err("HOST_WINDOWS_CONTROLLER_NATIVE_CHILD_UNPROVEN");
                }
                Ok(())
            })?;
        }
        FleetHostPlannedStep::Stop => {
            service
                .stop()
                .map_err(|_| "HOST_WINDOWS_SYSTEM_STOP_FAILED")?;
            wait_for_service_state(
                &service,
                ServiceState::Stopped,
                Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
            )
            .map_err(|_| "HOST_WINDOWS_SYSTEM_STOP_POSTSTATE_UNPROVEN")?;
        }
        _ => return Err("HOST_WINDOWS_SYSTEM_UNSUPPORTED_STEP"),
    }
    Ok(())
}

/// Returns false when the existing task should process the legacy, read-only
/// Ping/RuntimeEvidence. A signed request cannot coexist with the old format.
pub(super) async fn dispatch_if_present(install_root: &Path) -> Result<bool, String> {
    let request = install_root
        .join("exchange")
        .join("requests")
        .join(INTENT_FILE);
    match fs::symlink_metadata(&request) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("HOST_WINDOWS_SYSTEM_REQUEST_METADATA_UNAVAILABLE".into()),
        Ok(meta) if !meta.file_type().is_file() => {
            return Err("HOST_WINDOWS_SYSTEM_REQUEST_NOT_REGULAR".into());
        }
        Ok(_) => {}
    }
    windows_admin::reject_competing_request(&privileged_request_path(install_root))?;
    windows_admin::reject_competing_request(
        &install_root.join("exchange/requests/admin-request.pb"),
    )?;
    // Already-retargeted immutable console, not mutable bin/edge-console.exe.
    require_exact_immutable_activation_console(install_root)?;
    let protected = install_root.join("native-host");
    let journal = protected.join("journal");
    verify_native_journal_protection(&journal).map_err(str::to_owned)?;
    let transport = TransportRequest::open(
        &request,
        edge_shared_types::host_lifecycle::MAX_HOST_INTENT_BYTES as u64,
    )
    .map_err(str::to_owned)?;
    let intent_bytes = &transport.bytes;
    let intent = decode_host_intent(&intent_bytes).map_err(str::to_owned)?;
    if intent.kind != FleetHostKind::Windows as i32
        || intent.resource_id != "sing-box"
        || !matches!(
            FleetHostAction::try_from(intent.action),
            Ok(FleetHostAction::Start
                | FleetHostAction::Stop
                | FleetHostAction::Apply
                | FleetHostAction::Recover)
        )
    {
        return Err("HOST_WINDOWS_SYSTEM_ACTION_NOT_ACCEPTED".into());
    }
    windows_admin::request_available(
        &journal,
        &intent.operation_id,
        false,
        intent.action == FleetHostAction::Recover as i32,
    )?;
    edge_shared_types::host_journal::verify_windows_protected_path_acl(
        &protected.join(RECEIPT_KEY_FILE),
        true,
    )?;
    let receipt_private =
        bounded_regular_file(&protected.join(RECEIPT_KEY_FILE), 4096).map_err(str::to_owned)?;
    let (trust, selected, installed_runtime_sha256) = current_authority(
        install_root,
        &intent.machine_id,
        &intent.operation_id,
        intent.requested_at_unix,
        &receipt_private,
    )
    .await?;
    bind_native_host_artifacts(
        &intent,
        &trust.registry_pb,
        &trust.selected_spec_bytes,
        &trust.release_set_pb,
        None,
    )?;
    // Independently re-check the exact Git host target against the exact
    // signed desired spec. The runner's preflight is never trusted here.
    let desired = edge_shared_types::parse_production_desired_text(&trust.selected_spec_bytes)?;
    let mode = edge_shared_types::host_lifecycle::validate_windows_mode_target_and_spec(
        &selected, &desired,
    )?;
    // The native readback is a pre-BEGIN proof, not runner-supplied state.
    // ManagedTun may be STAGED while stopped, but no TUN activation or
    // running-owner reconfiguration is authorized by this operation.
    let observed = tokio::task::block_in_place(|| system_native_observation(install_root))
        .map_err(str::to_owned)?;
    let action = FleetHostAction::try_from(intent.action)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_ACTION_NOT_ACCEPTED")?;
    let run = selected
        .target
        .as_ref()
        .ok_or("HOST_TARGET_UNSET_OBSERVE_ONLY")
        .and_then(|target| {
            edge_shared_types::FleetHostRunState::try_from(target.run_state)
                .map_err(|_| "HOST_TARGET_RUN_STATE_INVALID")
        })?;
    let owner = edge_shared_types::FleetNativeOwnerState::try_from(observed.owner_state)
        .map_err(|_| "HOST_WINDOWS_NATIVE_OWNER_STATE_INVALID")?;
    edge_shared_types::host_lifecycle::validate_windows_datapath_prebegin(
        mode, action, run, owner,
    )?;
    let update = if intent.action == FleetHostAction::Apply as i32
        && digest(&SHA256, &trust.release_set_pb).as_ref() != installed_runtime_sha256
    {
        windows_update::preflight(install_root)?;
        Some(windows_update::prepare(&trust.release_set_pb).await?)
    } else {
        None
    };
    let config = if matches!(
        FleetHostAction::try_from(intent.action),
        Ok(FleetHostAction::Apply | FleetHostAction::Recover | FleetHostAction::Start)
    ) && update.is_none()
    {
        windows_config::prepare(install_root, &trust.selected_spec_bytes)?
    } else {
        None
    };
    let identity = install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    edge_secrets::diagnose_canonical_host_access(&identity)
        .await
        .map_err(str::to_owned)?;
    // Worker POST is one-shot; no fallback to a runner-supplied signature.
    let auth: FleetHostAuthorization =
        edge_secrets::request_canonical_host_authorization(&intent_bytes, &identity).await?;
    let mut now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_CLOCK_UNAVAILABLE")?
        .as_secs();
    edge_shared_types::host_lifecycle::verify_host_authorization(
        &intent,
        &auth,
        &trust.pinned_worker_public_key,
        now,
    )?;
    if let Some(config) = &config
        && matches!(
            FleetHostAction::try_from(intent.action),
            Ok(FleetHostAction::Apply | FleetHostAction::Start)
        )
    {
        windows_config::validate(install_root, config, &intent.operation_id)?;
        now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "HOST_WINDOWS_SYSTEM_CLOCK_UNAVAILABLE")?
            .as_secs();
    }
    let result = tokio::task::block_in_place(|| {
        edge_shared_types::host_journal::execute_native_windows_host_once(
            &intent,
            &auth,
            &trust.registry_pb,
            &trust.selected_spec_bytes,
            &trust.release_set_pb,
            None,
            &trust.pinned_worker_public_key,
            &trust.machine_id,
            FleetHostKind::Windows as i32,
            &installed_runtime_sha256,
            config.as_ref().map(|c| c.digest.as_slice()),
            now,
            &journal,
            || system_native_observation(install_root),
            |step| match step {
                FleetHostPlannedStep::Start if config.is_some() => {
                    windows_update::preflight(install_root).map(|_| ())
                }
                FleetHostPlannedStep::Stop => Ok(()),
                FleetHostPlannedStep::ReplaceRelease if update.is_some() => {
                    windows_update::preflight(install_root).map(|_| ())
                }
                FleetHostPlannedStep::Configure if config.is_some() => {
                    windows_update::preflight(install_root).map(|_| ())
                }
                _ => Err("HOST_WINDOWS_SYSTEM_NATIVE_STEP_NOT_ACCEPTED"),
            },
            |step| match step {
                FleetHostPlannedStep::ReplaceRelease => windows_update::apply(
                    install_root,
                    update.as_ref().ok_or("HOST_WINDOWS_UPDATE_NOT_PREPARED")?,
                    &trust,
                    &intent.operation_id,
                ),
                FleetHostPlannedStep::Configure => windows_config::apply(
                    install_root,
                    config.as_ref().ok_or("HOST_WINDOWS_CONFIG_NOT_PREPARED")?,
                    &intent.operation_id,
                ),
                _ => apply_exact_proxyonly_scm_step(
                    step,
                    install_root,
                    &intent,
                    &auth,
                    &receipt_private,
                    &installed_runtime_sha256,
                    config.as_ref(),
                    &trust,
                ),
            },
        )
    })
    .map_err(str::to_owned)?;
    // Native journal has already fsynced terminal before SYSTEM signs.
    let signed = sign_native_receipt(&intent, &result, &selected, &receipt_private)
        .map_err(str::to_owned)?;
    let receipt_path = install_root
        .join("exchange")
        .join("results")
        .join(RECEIPT_FILE);
    write_atomic(&receipt_path, &signed.encode_to_vec())
        .map_err(|_| "HOST_WINDOWS_SYSTEM_RECEIPT_PUBLISH_UNCERTAIN")?;
    transport.consume()?;
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
    fn transport_request_cannot_be_swapped_during_execution() {
        let dir =
            std::env::temp_dir().join(format!("edge-transport-request-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("request.pb");
        fs::write(&path, b"exact").unwrap();
        let request = TransportRequest::open(&path, 32).unwrap();
        assert_eq!(request.bytes, b"exact");
        assert!(fs::write(&path, b"changed").is_err());
        assert!(fs::rename(&path, dir.join("swapped")).is_err());
        request.consume().unwrap();
        assert!(!path.exists());
        fs::remove_dir(dir).unwrap();
    }

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
