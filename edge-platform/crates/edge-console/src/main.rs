mod console_reporting;
mod controller_client;
use console_reporting::*;
use controller_client::*;

mod cli;
mod command_dispatch;
mod credential_access_bootstrap;
mod credential_transition;
mod error;
mod initial_line1_witness;
#[cfg(windows)]
mod windows_admin;
#[cfg(windows)]
mod windows_clean_install;
#[cfg(windows)]
mod windows_config;
#[cfg(windows)]
mod windows_receipt_enrollment;
#[cfg(windows)]
mod windows_signed_host;
#[cfg(windows)]
mod windows_trust_enrollment;
#[cfg(windows)]
mod windows_update;

use clap::Parser;
use command_dispatch::run;
use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
};
use edge_local_runtime::{
    RuntimeProcessClassification, classify_runtime_process, observe_process,
    run_non_tun_loopback_smoke, stop_local_runtime as stop_runtime_process,
};
use edge_observability::init as init_observability;
use edge_secrets::{
    ACCESS_IDENTITY_FILE_NAME, CredentialOriginSelection, CredentialStore,
    attest_worker_credential_origin, fetch_canonical_credential_bundle,
    verify_canonical_dummy_ab_slots, verify_initial_selected_dummy_slot,
};
use edge_singbox::{STAGE2_CLASH_API_PORT, STAGE2_DESKTOP_PROXY_PORT, STAGE2_WSL_PROXY_PORT};
use error::ConsoleError;
use rusqlite::Connection;
use std::env;
#[cfg(windows)]
use std::ffi::{OsString, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::{
    ControllerStatus, CredentialTransitionAction, DoctorRequest, DoctorResponse, Empty,
    GetOperationRequest, GetSecretRefRequest, GetSelectorStateRequest, GetTraceRequest,
    ListOperationEventsRequest, ListSecretRefsRequest, LocalRuntimeResponse, OperationStatus,
    RestartLocalRuntimeRequest, SecretRefEntry, SelectorState, SetSecretRefRequest,
    SetSelectorRequest, SetSelectorResponse, StartLocalRuntimeRequest, StopLocalRuntimeRequest,
    TraceObservation, UbuntuProxyState, WINDOWS_CONTROLLER_ADDR, WINDOWS_CONTROLLER_ENDPOINT,
    WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS, WindowsActivationState, WindowsDatapathMode,
    WindowsPrivilegedOperation, WindowsPrivilegedRequest, WindowsPrivilegedResult,
    WindowsRuntimeState, WindowsTunnelBinding, canonical_production_desired_state,
    decode_windows_activation_state, decode_windows_privileged_request,
    decode_windows_privileged_result, decode_windows_runtime_state,
    encode_windows_activation_state, encode_windows_privileged_request,
    encode_windows_privileged_result, encode_windows_runtime_state,
    parse_credential_transition_action, verify_windows_activation_files,
};
use tonic::Request;
use tonic::transport::Channel;
#[cfg(windows)]
use windows::Win32::Foundation::WAIT_IO_COMPLETION;
#[cfg(windows)]
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
#[cfg(windows)]
use windows::Win32::System::Services::{
    NotifyServiceStatusChangeW, SC_HANDLE, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_RUNNING,
    SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_NOTIFY_STOPPED,
};
#[cfg(windows)]
use windows::Win32::System::TaskScheduler::ITaskService;
#[cfg(windows)]
use windows::Win32::System::Threading::SleepEx;
#[cfg(windows)]
use windows::Win32::System::Variant::VARIANT;
#[cfg(windows)]
use windows::core::{BSTR, GUID, IUnknown};
#[cfg(windows)]
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceSidType,
    ServiceStartType, ServiceState, ServiceType,
};
#[cfg(windows)]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const DEFAULT_CONTROLLER_ENDPOINT: &str = "http://127.0.0.1:50051";
#[cfg(windows)]
const INSTALLED_CONTROLLER_ADDR: &str = WINDOWS_CONTROLLER_ADDR;
#[cfg(windows)]
const WINDOWS_CONTROLLER_SERVICE_NAME: &str = "EdgePlatformController";
#[cfg(windows)]
const WINDOWS_CONTROLLER_SERVICE_ACCOUNT: &str = r"NT SERVICE\EdgePlatformController";
const PRIVILEGED_REQUEST_SCHEMA_VERSION: u32 = 1;
const PRIVILEGED_RESULT_SCHEMA_VERSION: u32 = 1;
const PRIVILEGED_TASK_NAME: &str = "EdgePlatformPrivilegedDispatch";
#[cfg(windows)]
const HANDOFF_TASK_NAMES: [&str; 4] = [
    "EdgePlatformController",
    "EdgePlatformReconcile",
    "EdgePlatformShutdown",
    "EdgePlatformPrivilegedDispatch",
];
const PRIVILEGED_SHORT_WAIT_SECS: u64 = 180;
const PRIVILEGED_ACTIVATE_WAIT_SECS: u64 = 12 * 60;
const RUNTIME_EVIDENCE_MAX_BYTES: u64 = 16 * 1024;
const RUNTIME_EVIDENCE_MAX_LINES: usize = 80;
// Fixed bounded protobuf evidence, including a persistent first-use credential cursor.
// The former 1024-byte cap rejected valid stopped Windows candidates when the
// exact four scheduled-task hashes and recovered credential proof coexisted.
const RUNTIME_EVIDENCE_RESULT_MAX_BYTES: usize = 2048;
const PRIVILEGED_CHILD_EVIDENCE_MAX_BYTES: usize = 960;
const WINDOWS_TRACE_REOBSERVE_ATTEMPTS: usize = 3;
const WINDOWS_TRACE_REOBSERVE_DELAY: Duration = Duration::from_secs(1);
const DESKTOP_SELECTOR_GROUP: &str = "proxy-selector";
const UBUNTU_SELECTOR_GROUP: &str = "wsl-selector";

pub(crate) fn default_controller_endpoint() -> &'static str {
    #[cfg(windows)]
    {
        if installed_root_from_console().is_ok() {
            return WINDOWS_CONTROLLER_ENDPOINT;
        }
    }
    DEFAULT_CONTROLLER_ENDPOINT
}

#[tokio::main]
async fn main() -> ExitCode {
    let telemetry = init_observability("edge-console");
    let parsed = match cli::Cli::try_parse() {
        Ok(parsed) => parsed,
        Err(err) => {
            let code = err.exit_code();
            let _ = err.print();
            return ExitCode::from(code as u8);
        }
    };
    let command = parsed.command_name();
    tracing::info!(
        component = "edge-console",
        correlation_id = %telemetry.id(),
        command,
        event = "command.start",
        "command started"
    );

    match run(parsed).await {
        Ok(()) => {
            tracing::info!(
                component = "edge-console",
                correlation_id = %telemetry.id(),
                command,
                event = "command.success",
                "command completed"
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(
                component = "edge-console",
                correlation_id = %telemetry.id(),
                command,
                error_category = err.category(),
                event = "command.failure",
                "command failed"
            );
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

/// Routine console actions are read-only. The sole first-use exception is
/// an exact immutable local Administrator invocation of offline-bootstrap,
/// never a legacy SYSTEM request or runner capability. That Rust handler
/// proves local SCM CHANGE_CONFIG, Git release identity and no-replay BEGIN.
/// Subsequent remote mutations require Worker-signed native HostIntent.
fn legacy_console_entrypoint_allowed(command: &cli::Command) -> bool {
    use cli::Command;
    #[cfg(windows)]
    if matches!(
        command,
        Command::OfflineBootstrap(_)
            | Command::OfflineBootstrapPreflight(_)
            | Command::OfflineReceiptIdentityPrepare(_)
            | Command::OfflineCleanInstall(_)
            | Command::OfflineReceiptIdentityObserve(_)
            | Command::OfflineFirstUseStatus(_)
            | Command::OfflineHostTrustPrepare(_)
    ) {
        return true;
    }
    matches!(
        command,
        Command::Status(_)
            | Command::Doctor(_)
            | Command::CredentialState(_)
            | Command::CredentialInitialProbe(_)
            | Command::PrivilegedPing(_)
            | Command::PrivilegedRuntimeEvidence(_)
            | Command::PrivilegedDispatch(_)
            | Command::VerifyRuntime
            | Command::QualityLine1
            | Command::Secrets(_)
            | Command::GetSelector(_)
            | Command::GetUbuntuSelector(_)
            | Command::Trace(_)
            | Command::TraceUbuntu(_)
            | Command::GetOperation(_)
            | Command::WatchOperation(_)
    )
}

/// SYSTEM privilege alone is not authorization. A legacy privileged
/// request can only inspect evidence; actual release/credential/SCM writes
/// must be expressed as a new signed HostIntent and native journal BEGIN.
fn legacy_privileged_read_only(operation: i32) -> bool {
    matches!(
        WindowsPrivilegedOperation::try_from(operation),
        Ok(WindowsPrivilegedOperation::Ping | WindowsPrivilegedOperation::RuntimeEvidence)
    )
}

fn unproven_runtime_evidence(request_id: &str) -> String {
    format!(
        "status=UNPROVEN\nrequest_id={request_id}\ncode=RUNTIME_EVIDENCE_EXCHANGE_UNPROVEN\nerror_class=SYSTEM_RESULT_NOT_OBSERVED\ndetail=EVIDENCE_NOT_RECORDED_OR_UNAVAILABLE\noperation_outcome=UNKNOWN_NO_REPLAY\n"
    )
}

fn privileged_request_path(install_root: &Path) -> PathBuf {
    install_root
        .join("exchange")
        .join("requests")
        .join("request.pb")
}

fn privileged_result_path(install_root: &Path) -> PathBuf {
    install_root
        .join("exchange")
        .join("results")
        .join("result.pb")
}

fn required_provision_env<F>(get: &F, name: &str) -> Result<String, String>
where
    F: Fn(&str) -> Option<String>,
{
    let value = get(name).ok_or_else(|| format!("{name} is required"))?;
    if value.is_empty() || value.trim() != value {
        return Err(format!("{name} must be a non-empty canonical value"));
    }
    Ok(value)
}

fn optional_provision_env<F>(get: &F, name: &str) -> Result<Option<String>, String>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(value) = get(name) else {
        return Ok(None);
    };
    if value.is_empty() || value.trim() != value {
        return Err(format!(
            "{name} must be a non-empty canonical value when provided"
        ));
    }
    Ok(Some(value))
}

fn required_provision_port<F>(get: &F, name: &str) -> Result<u32, String>
where
    F: Fn(&str) -> Option<String>,
{
    required_provision_env(get, name)?
        .parse::<u32>()
        .map_err(|err| format!("{name} must be an integer port: {err}"))
}

fn windows_runtime_state_from_provision_env<F>(get: F) -> Result<WindowsRuntimeState, String>
where
    F: Fn(&str) -> Option<String>,
{
    let direct = WindowsTunnelBinding {
        domain: required_provision_env(&get, "EDGE_WINDOWS_DIRECT_DOMAIN")?,
        hy2_port: required_provision_port(&get, "EDGE_WINDOWS_DIRECT_HY2_PORT")?,
        hy2_password: required_provision_env(&get, "HY2_PASSWORD")?,
        vless_port: required_provision_port(&get, "EDGE_WINDOWS_DIRECT_VLESS_PORT")?,
        vless_uuid: required_provision_env(&get, "VLESS_UUID")?,
        reality_public_key: required_provision_env(&get, "REALITY_PUBLIC_KEY")?,
        reality_short_id: required_provision_env(&get, "REALITY_SHORT_ID")?,
    };
    let warp = WindowsTunnelBinding {
        domain: required_provision_env(&get, "EDGE_WINDOWS_WARP_DOMAIN")?,
        hy2_port: required_provision_port(&get, "EDGE_WINDOWS_WARP_HY2_PORT")?,
        hy2_password: required_provision_env(&get, "HY2_WARP_PASSWORD")?,
        vless_port: required_provision_port(&get, "EDGE_WINDOWS_WARP_VLESS_PORT")?,
        vless_uuid: required_provision_env(&get, "VLESS_WARP_UUID")?,
        reality_public_key: required_provision_env(&get, "REALITY_WARP_PUBLIC_KEY")?,
        reality_short_id: required_provision_env(&get, "REALITY_WARP_SHORT_ID")?,
    };
    let state = WindowsRuntimeState {
        schema_version: 1,
        deployment_label: optional_provision_env(&get, "EDGE_WINDOWS_DEPLOYMENT_LABEL")?,
        instance_id: required_provision_env(&get, "EDGE_WINDOWS_INSTANCE_ID")?,
        server_ip: required_provision_env(&get, "EDGE_WINDOWS_SERVER_IP")?,
        direct: Some(direct),
        warp: Some(warp),
    };
    encode_windows_runtime_state(&state)?;
    Ok(state)
}

fn provision_windows_runtime_state(install_root: &Path) -> Result<(), ConsoleError> {
    if !install_root.join("current.pb").is_file() || !install_root.join("releases").is_dir() {
        return Err(ConsoleError::Command(
            "runtime-state provisioning requires an installed Windows application root".to_owned(),
        ));
    }

    let secret_dir = install_root.join("state").join("secrets");
    if !secret_dir.is_dir() {
        return Err(ConsoleError::Command(format!(
            "controller-private secret directory is missing: {}",
            secret_dir.display()
        )));
    }

    let target = secret_dir.join("runtime-state.pb");
    if target.exists() {
        return Err(ConsoleError::Command(
            "runtime-state.pb already exists; credential rotation requires a separate explicit operation"
                .to_owned(),
        ));
    }
    let staged = target.with_extension("pb.new");
    if staged.exists() {
        return Err(ConsoleError::Command(format!(
            "staged runtime state already exists: {}",
            staged.display()
        )));
    }

    let state = windows_runtime_state_from_provision_env(|name| env::var(name).ok())
        .map_err(ConsoleError::Command)?;
    let bytes = encode_windows_runtime_state(&state).map_err(ConsoleError::Command)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(|err| {
            ConsoleError::Command(format!(
                "failed to create staged runtime state {}: {err}",
                staged.display()
            ))
        })?;
    if let Err(err) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&staged);
        return Err(ConsoleError::Command(format!(
            "failed to write staged runtime state {}: {err}",
            staged.display()
        )));
    }
    drop(file);

    if let Err(err) = fs::rename(&staged, &target) {
        let _ = fs::remove_file(&staged);
        return Err(ConsoleError::Command(format!(
            "failed to publish runtime state {}: {err}",
            target.display()
        )));
    }

    let observed = fs::read(&target).map_err(|err| {
        let _ = fs::remove_file(&target);
        ConsoleError::Command(format!(
            "failed to verify published runtime state {}: {err}",
            target.display()
        ))
    })?;
    if let Err(err) = decode_windows_runtime_state(&observed) {
        let _ = fs::remove_file(&target);
        return Err(ConsoleError::Command(format!(
            "published runtime state failed canonical verification: {err}"
        )));
    }

    println!("status=PASS");
    println!("runtime_state=PROVISIONED");
    println!("runtime_state_schema=1");
    println!("runtime_secret_store=controller_private");
    println!("runtime_secret_consumer=controller_service");
    println!("runner_secret_access=false");
    Ok(())
}

fn new_privileged_request_id() -> Result<String, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(format!("{}-{}", now.as_millis(), std::process::id()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().ok_or("atomic write path has no parent")?;
    fs::create_dir_all(parent)?;
    let temp = path.with_extension("pb.new");
    fs::write(&temp, bytes)?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn privileged_wait_secs(request: &WindowsPrivilegedRequest) -> u64 {
    match WindowsPrivilegedOperation::try_from(request.operation) {
        Ok(
            WindowsPrivilegedOperation::ActivateRelease
            | WindowsPrivilegedOperation::RollbackPreviousRelease
            | WindowsPrivilegedOperation::ReinstallAcceptedRelease
            | WindowsPrivilegedOperation::OfflineActivateRelease
            | WindowsPrivilegedOperation::OfflineRollbackPreviousRelease,
        ) => PRIVILEGED_ACTIVATE_WAIT_SECS,
        _ => PRIVILEGED_SHORT_WAIT_SECS,
    }
}

fn read_matching_privileged_result(
    result_path: &Path,
    request_id: &str,
) -> Result<Option<WindowsPrivilegedResult>, Box<dyn std::error::Error>> {
    match fs::read(result_path) {
        Ok(bytes) => {
            let result = decode_windows_privileged_result(&bytes)?;
            if result.request_id == request_id {
                Ok(Some(result))
            } else {
                Ok(None)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn activation_matches_request(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Option<WindowsActivationState> {
    if !matches!(
        WindowsPrivilegedOperation::try_from(request.operation).ok(),
        Some(WindowsPrivilegedOperation::ActivateRelease)
    ) {
        return None;
    }
    let target_release = request.release_set_sha256.as_deref()?;
    let activation = load_verified_activation(install_root).ok()?;
    (activation.release_set_sha256 == target_release).then_some(activation)
}

fn reconcile_completed_privileged_exchange(
    install_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_path = privileged_request_path(install_root);
    if !request_path.exists() {
        return Ok(());
    }

    let pending_bytes = fs::read(&request_path)?;
    let pending = decode_windows_privileged_request(&pending_bytes)?;
    let result_path = privileged_result_path(install_root);

    if read_matching_privileged_result(&result_path, &pending.request_id)?.is_some() {
        fs::remove_file(&request_path)?;
        return Ok(());
    }

    let age = fs::metadata(&request_path)?
        .modified()?
        .elapsed()
        .unwrap_or_default();
    if age >= Duration::from_secs(PRIVILEGED_ACTIVATE_WAIT_SECS)
        && activation_matches_request(install_root, &pending).is_some()
    {
        fs::remove_file(&request_path)?;
        return Ok(());
    }

    Err(format!(
        "privileged Windows request is still pending: request_id={} operation={}; do not retry blindly",
        pending.request_id, pending.operation
    )
    .into())
}

fn submit_privileged_request(
    install_root: &Path,
    request: WindowsPrivilegedRequest,
) -> Result<WindowsPrivilegedResult, Box<dyn std::error::Error>> {
    reconcile_completed_privileged_exchange(install_root)?;

    let request_path = privileged_request_path(install_root);
    let bytes = encode_windows_privileged_request(&request)?;
    write_atomic(&request_path, &bytes)?;

    let result_path = privileged_result_path(install_root);
    let wait_secs = privileged_wait_secs(&request);
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    while Instant::now() < deadline {
        if let Some(result) = read_matching_privileged_result(&result_path, &request.request_id)? {
            return Ok(result);
        }
        thread::sleep(Duration::from_millis(500));
    }

    if let Some(result) = read_matching_privileged_result(&result_path, &request.request_id)? {
        return Ok(result);
    }

    if let Some(activation) = activation_matches_request(install_root, &request) {
        reconcile_completed_privileged_exchange(install_root)?;
        return Ok(WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: request.request_id,
            success: true,
            code: "RELEASE_CONVERGED_REOBSERVED".to_owned(),
            detail: "exact target ReleaseSet is active after bounded activation wait".to_owned(),
            active_release_set_sha256: Some(activation.release_set_sha256),
        });
    }

    Err(format!(
        "privileged Windows request outcome is uncertain after {wait_secs} seconds: request_id={} operation={}; do not retry blindly",
        request.request_id, request.operation
    )
    .into())
}

async fn dispatch_privileged_request(
    install_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // One process-wide owner for the existing scheduled task. A second task
    // instance must never race enrollment, signed host or admin admission.
    #[cfg(windows)]
    let _owner_lock = windows_admin::owner_lock(install_root)?;
    // The same periodic LocalSystem task first handles an explicit protected
    // local-Administrator first-use IDENTITY marker, never SCM/network actions.
    // No runner writes to native-host; key material is generated by SYSTEM.
    #[cfg(windows)]
    if windows_receipt_enrollment::dispatch_if_present(install_root)? {
        return Ok(());
    }
    // Git is the only trusted source. This optional first-use stage runs in
    // the same SYSTEM dispatcher and creates trust.pb once, without a runner
    // supplied key, alternate task, or network resource effect.
    #[cfg(windows)]
    windows_trust_enrollment::dispatch_if_needed(install_root).await?;
    #[cfg(windows)]
    if windows_admin::dispatch_if_present(install_root).await? {
        return Ok(());
    }
    // The SAME installed SYSTEM Task accepts bounded Worker-signed native
    // HostIntent, never a runner's legacy mutation code or arbitrary PowerShell.
    #[cfg(windows)]
    if windows_signed_host::dispatch_if_present(install_root).await? {
        return Ok(());
    }
    let request_path = privileged_request_path(install_root);
    let bytes = match fs::read(&request_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("status=PASS");
            println!("privileged_dispatch=NOOP");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let request = decode_windows_privileged_request(&bytes)?;
    let result = process_privileged_request(install_root, &request).await;
    let result_bytes = encode_windows_privileged_result(&result)?;
    write_atomic(&privileged_result_path(install_root), &result_bytes)?;
    fs::remove_file(&request_path)?;

    print_privileged_result(&result);
    finish_privileged_result(&result)?;
    Ok(())
}

async fn process_privileged_request(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> WindowsPrivilegedResult {
    // Checked inside the exact SYSTEM task: even a forged/scheduled old
    // request cannot activate a release or change credentials without the
    // new native one-shot authorization. No cleanup/retry mutation occurs.
    if !legacy_privileged_read_only(request.operation) {
        return WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            success: false,
            code: "HOST_WINDOWS_LEGACY_PRIVILEGED_MUTATION_DISABLED".to_owned(),
            detail: "Use signed native HostIntent; legacy operation is denied".to_owned(),
            active_release_set_sha256: None,
        };
    }
    let outcome = match WindowsPrivilegedOperation::try_from(request.operation) {
        Ok(WindowsPrivilegedOperation::Ping) => {
            let active = load_verified_activation(install_root)
                .ok()
                .map(|state| state.release_set_sha256);
            Ok((
                "PING_PASS".to_owned(),
                "privileged dispatcher is reachable".to_owned(),
                active,
            ))
        }
        Ok(WindowsPrivilegedOperation::RuntimeEvidence) => {
            let active = load_verified_activation(install_root)
                .ok()
                .map(|state| state.release_set_sha256);
            let evidence = read_bounded_windows_runtime_evidence(install_root);
            #[cfg(windows)]
            let evidence = match evidence {
                Ok(detail)
                    if (detail
                        .contains("credential_lifecycle_state=EXISTING_ACTIVE_UNVERIFIED")
                        || detail.contains(
                            "credential_lifecycle_state=EXISTING_TRANSITION_UNVERIFIED",
                        ))
                        && require_stopped_proxy_only_initial_commit_owner(install_root)
                            .is_ok() =>
                {
                    let identity = install_root
                        .join("state")
                        .join("secrets")
                        .join(ACCESS_IDENTITY_FILE_NAME);
                    let store = windows_credential_store_path(install_root);
                    // For a staged A/B transition BOTH immutable projections
                    // must remain exact Worker-v2. No read-only result grants
                    // local or cross-host mutation authority.
                    let active_proof = attest_worker_credential_origin(
                        &store,
                        &identity,
                        edge_shared_types::CredentialProjectionKind::Windows,
                        CredentialOriginSelection::Active,
                    )
                    .await;
                    let staged = detail
                        .contains("credential_lifecycle_state=EXISTING_TRANSITION_UNVERIFIED");
                    let candidate_ok = if staged && active_proof.is_ok() {
                        attest_worker_credential_origin(
                            &store,
                            &identity,
                            edge_shared_types::CredentialProjectionKind::Windows,
                            CredentialOriginSelection::Candidate,
                        )
                        .await
                        .is_ok()
                    } else {
                        !staged
                    };
                    if active_proof.is_ok() && candidate_ok {
                        Ok(detail
                            .replace("credential_origin=UNPROVEN", "credential_origin=WORKER_OK")
                            .replace(
                                "credential_next_action=READ_ONLY_ORIGIN_RECONCILE",
                                "credential_next_action=PAIR_VM_PROOF",
                            ))
                    } else {
                        Ok(detail)
                    }
                }
                other => other,
            };
            evidence.map(|detail| ("RUNTIME_EVIDENCE_READ".to_owned(), detail, active))
        }
        Ok(_) | Err(_) => Err("HOST_WINDOWS_LEGACY_PRIVILEGED_MUTATION_DISABLED".to_owned()),
    };

    match outcome {
        Ok((code, detail, active)) => WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            success: true,
            code,
            detail,
            active_release_set_sha256: active,
        },
        Err(detail) => WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            success: false,
            code: "PRIVILEGED_OPERATION_FAILED".to_owned(),
            detail,
            active_release_set_sha256: load_verified_activation(install_root)
                .ok()
                .map(|state| state.release_set_sha256),
        },
    }
}

fn bounded_privileged_child_evidence(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout =
        compact_runtime_evidence_line(&redact_runtime_evidence(&String::from_utf8_lossy(stdout)));
    let stderr =
        compact_runtime_evidence_line(&redact_runtime_evidence(&String::from_utf8_lossy(stderr)));
    let detail = format!(
        "installer_evidence=BOUNDED;stderr={};stdout={}",
        if stderr.is_empty() { "EMPTY" } else { &stderr },
        if stdout.is_empty() { "EMPTY" } else { &stdout }
    );
    truncate_runtime_evidence(&detail, PRIVILEGED_CHILD_EVIDENCE_MAX_BYTES)
}

// SYSTEM-owned, read-only projection of the persistent Windows cursor. A
// partially created store is UNKNOWN, never treated as a fresh first-use slot.
// The GitHub runner cannot read private state or any credential bundle.
fn read_bounded_windows_credential_cursor(install_root: &Path) -> Result<String, String> {
    let root = windows_credential_store_path(install_root);
    let Some(store) =
        CredentialStore::open_existing(root, edge_shared_types::CredentialProjectionKind::Windows)?
    else {
        return Ok("credential_cursor=ABSENT".to_owned());
    };
    let state = store.read_state()?.ok_or_else(|| {
        "persistent Windows credential directory has no durable cursor; first-use is UNKNOWN"
            .to_owned()
    })?;
    let active = state.active.as_ref();
    let candidate = state.candidate.as_ref();
    let previous = state.previous.as_ref();
    let slot = match candidate.map(|value| value.slot) {
        Some(value) if value == edge_shared_types::CredentialDeliverySlot::A as i32 => "A",
        Some(value) if value == edge_shared_types::CredentialDeliverySlot::B as i32 => "B",
        Some(_) => "UNKNOWN",
        None => "NONE",
    };
    let active_slot = match active.map(|value| value.slot) {
        Some(value) if value == edge_shared_types::CredentialDeliverySlot::A as i32 => "A",
        Some(value) if value == edge_shared_types::CredentialDeliverySlot::B as i32 => "B",
        Some(_) => "UNKNOWN",
        None => "NONE",
    };
    let receipt = store.read_initial_pair_receipt()?;
    let recovery = store.read_initial_pair_recovery_receipt()?;
    // Only sanitized durable hashes; malformed or torn receipts yield
    // UNKNOWN, never an invented "not attempted" state.
    let existing_prepare = store.read_windows_existing_join_prepare_receipt()?;
    let existing_join = store.read_existing_join_receipt()?;
    let existing_prepare_begin = existing_prepare
        .as_deref()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("begin_sha256="))
        })
        .unwrap_or("ABSENT");
    let existing_commit_intent = existing_join
        .as_deref()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("intent_sha256="))
        })
        .unwrap_or("ABSENT");
    let recovery_sha = recovery
        .as_deref()
        .and_then(|value| {
            value
                .lines()
                .find_map(|line| line.strip_prefix("recovery_intent_sha256="))
        })
        .unwrap_or("ABSENT");
    let receipt_sha = receipt
        .as_deref()
        .and_then(|value| {
            value
                .lines()
                .find_map(|line| line.strip_prefix("intent_sha256="))
        })
        .unwrap_or("ABSENT");
    Ok(format!(
        "credential_cursor=VALID;credential_active_present={};credential_candidate_present={};credential_candidate_generation={};credential_candidate_slot={slot};credential_previous_present={};credential_active_generation={};credential_active_slot={active_slot};credential_active_sha256={};credential_candidate_sha256={};credential_initial_commit_receipt_present={};credential_initial_commit_intent_sha256={receipt_sha};credential_initial_recovery_receipt_present={};credential_initial_recovery_intent_sha256={recovery_sha};credential_existing_join_prepare_receipt_present={};credential_existing_join_prepare_begin_sha256={existing_prepare_begin};credential_existing_join_receipt_present={};credential_existing_join_intent_sha256={existing_commit_intent};credential_previous_generation={};credential_previous_slot={};credential_previous_sha256={}",
        active.is_some(),
        candidate.is_some(),
        candidate.map(|value| value.generation).unwrap_or(0),
        previous.is_some(),
        active.map(|value| value.generation).unwrap_or(0),
        active
            .map(|value| value.sha256.as_str())
            .unwrap_or("ABSENT"),
        candidate
            .map(|value| value.sha256.as_str())
            .unwrap_or("ABSENT"),
        receipt.is_some(),
        recovery.is_some(),
        existing_prepare.is_some(),
        existing_join.is_some(),
        previous.map(|value| value.generation).unwrap_or(0),
        previous.map(|value| value.slot).unwrap_or(0),
        previous
            .map(|value| value.sha256.as_str())
            .unwrap_or("ABSENT"),
    ))
}

/// Non-secret SYSTEM cursor proof from the serving installation. A disposable
/// Line1 test must use its own isolated root and prove it tested this same B.
/// This function never reads private credential files as the GitHub runner.
#[cfg(windows)]
fn existing_line1_serving_candidate(
    serving_root: &Path,
    generation: u64,
    expected_b: &str,
) -> Result<String, String> {
    let activation = load_verified_activation(serving_root)
        .map_err(|_| "existing Line1 source ReleaseSet unverified".to_owned())?;
    let child = Command::new(&activation.console_path)
        .arg("privileged-runtime-evidence")
        .arg("--install-root")
        .arg(serving_root)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "SYSTEM candidate evidence unavailable".to_owned())?;
    if !child.status.success() {
        return Err("SYSTEM candidate evidence failed".to_owned());
    }
    let text = String::from_utf8(child.stdout)
        .map_err(|_| "SYSTEM evidence encoding invalid".to_owned())?;
    parse_existing_line1_system_result(&text, generation, expected_b)
}

/// Pure, fail-closed decoding of the bounded SYSTEM projection. No secret,
/// local file or operator-declared witness can authorize a mutation.
#[cfg(any(windows, test))]
fn parse_existing_line1_system_result(
    text: &str,
    generation: u64,
    expected_b: &str,
) -> Result<String, String> {
    if text.lines().filter(|line| *line == "status=PASS").count() != 1 {
        return Err("SYSTEM evidence success marker missing or duplicate".to_owned());
    }
    let details: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("detail=runtime_evidence=BOUNDED_READ_ONLY;"))
        .collect();
    if details.len() != 1 {
        return Err("SYSTEM cursor result absent or ambiguous".to_owned());
    }
    // The SYSTEM runtime projection contains bounded SCM, process and log
    // evidence alongside credential fields. Only the typed credential keys
    // belong to this witness; unrelated diagnostic fragments may be truncated
    // or lack '='. Duplicate credential keys are still always rejected.
    let mut observed = std::collections::BTreeMap::new();
    for entry in details[0].split(';') {
        let Some((key, value)) = entry.split_once('=') else {
            continue;
        };
        if !key.starts_with("credential_") {
            continue;
        }
        if observed.insert(key, value).is_some() {
            return Err("SYSTEM cursor field duplicated".to_owned());
        }
    }
    for (field, expected) in [
        ("credential_cursor", "VALID"),
        ("credential_origin", "WORKER_OK"),
        ("credential_active_present", "true"),
        ("credential_active_slot", "A"),
        ("credential_candidate_present", "true"),
        ("credential_candidate_slot", "B"),
        ("credential_candidate_sha256", expected_b),
        ("credential_previous_present", "false"),
        ("credential_existing_join_prepare_receipt_present", "true"),
        ("credential_existing_join_receipt_present", "false"),
    ] {
        if observed.get(field).copied() != Some(expected) {
            return Err(format!("SYSTEM existing B witness mismatch: {field}"));
        }
    }
    if observed
        .get("credential_candidate_generation")
        .and_then(|value| value.parse::<u64>().ok())
        != Some(generation)
    {
        return Err("SYSTEM B candidate generation changed".to_owned());
    }
    let begin = observed
        .get("credential_existing_join_prepare_begin_sha256")
        .copied()
        .ok_or_else(|| "SYSTEM BEGIN preparation receipt unknown".to_owned())?;
    if begin.len() != 64
        || !begin
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err("SYSTEM BEGIN preparation SHA-256 invalid".to_owned());
    }
    Ok(begin.to_owned())
}

#[cfg(windows)]
fn require_stopped_proxy_only_initial_commit_owner(install_root: &Path) -> Result<(), String> {
    let target = canonical_production_desired_state()?;
    if target.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32
        || !install_root
            .to_string_lossy()
            .eq_ignore_ascii_case(r"C:\sing-box")
    {
        return Err("initial Windows paired commit requires canonical ProxyOnly root".to_owned());
    }
    let activation = load_verified_activation(install_root).map_err(|_| {
        "initial Windows commit requires exact immutable installed release".to_owned()
    })?;
    let doctor = Command::new(&activation.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "initial Windows commit requires installed native doctor".to_owned())?;
    let evidence = String::from_utf8(doctor.stdout)
        .map_err(|_| "initial Windows commit native doctor is not UTF-8".to_owned())?;
    for expected in [
        "exact_release_files=PASS",
        "windows_datapath_mode=ProxyOnly",
        "scm_state=Stopped",
        "scm_start_type=OnDemand",
        "managed_tun_present=false",
        "managed_singbox_process_count=0",
        "orphan_singbox_process_count=0",
        "conflicting_singbox_process_count=0",
        "unknown_singbox_process_count=0",
    ] {
        if !evidence.lines().any(|line| line == expected) {
            return Err(format!(
                "initial Windows paired commit missing native stopped owner evidence: {expected}"
            ));
        }
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "initial Windows commit cannot inspect SCM".to_owned())?;
    let service = manager
        .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(|_| "initial Windows commit cannot inspect owner service".to_owned())?;
    let status = service
        .query_status()
        .map_err(|_| "initial Windows commit SCM status uncertain".to_owned())?;
    if status.current_state != ServiceState::Stopped
        || status.process_id.is_some()
        || !matches!(
            classify_runtime_process(&local_singbox_config_path(install_root)),
            RuntimeProcessClassification::Absent
        )
    {
        return Err(
            "initial Windows paired commit requires exact stopped/zero-process SCM".to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn require_offline_first_use_stage_owner(install_root: &Path) -> Result<(), String> {
    let target = canonical_production_desired_state()?;
    if target.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32
        || !install_root
            .to_string_lossy()
            .eq_ignore_ascii_case(r"C:\sing-box")
    {
        return Err("first-use persistent staging is confined to canonical ProxyOnly intent and C:\\sing-box".to_owned());
    }
    let activation = load_verified_activation(install_root).map_err(|_| {
        "persistent first-use staging requires an exact installed ReleaseSet".to_owned()
    })?;
    let doctor = Command::new(&activation.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "persistent first-use staging requires native read-only doctor".to_owned())?;
    // A stopped old ManagedTun can cause a nonzero doctor exit. Require
    // affirmative OS/file evidence, never treat that exit as permission.
    let observation = String::from_utf8(doctor.stdout)
        .map_err(|_| "persistent first-use doctor evidence is not UTF-8".to_owned())?;
    for evidence in [
        "exact_release_files=PASS",
        "scm_state=Stopped",
        "managed_tun_present=false",
        "managed_singbox_process_count=0",
        "orphan_singbox_process_count=0",
        "conflicting_singbox_process_count=0",
        "unknown_singbox_process_count=0",
    ] {
        if !observation.lines().any(|line| line == evidence) {
            return Err(
                "persistent first-use denies missing stopped/no-TUN native evidence".to_owned(),
            );
        }
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "first-use persistent staging cannot inspect SCM".to_owned())?;
    let service = manager
        .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(|_| "first-use persistent staging cannot inspect owner service".to_owned())?;
    let status = service
        .query_status()
        .map_err(|_| "first-use persistent staging cannot read SCM status".to_owned())?;
    if status.current_state != ServiceState::Stopped
        || status.process_id.is_some()
        || !matches!(
            classify_runtime_process(&local_singbox_config_path(install_root)),
            RuntimeProcessClassification::Absent
        )
    {
        return Err(
            "first-use persistent staging refuses a running or ambiguous Windows owner".to_owned(),
        );
    }
    if windows_runtime_state_path(install_root).exists()
        || local_singbox_config_path(install_root).exists()
        || windows_credential_store_path(install_root).exists()
    {
        return Err("first-use persistent staging refuses pre-existing or incomplete managed credential/runtime state".to_owned());
    }
    Ok(())
}

// Classify the existing local cursor before choosing any mutation path. These
// are ownership observations, never proof that a Worker/VM generation matches.
// No parser of historical log text may grant first-use or active authority.
fn classify_windows_credential_lifecycle(
    cursor: &str,
    runtime: &str,
    config: &str,
    identity: &str,
) -> (&'static str, &'static str) {
    if cursor == "credential_cursor=ABSENT" {
        if runtime != "ABSENT" || config != "ABSENT" {
            return ("PARTIAL", "READ_ONLY_RECONCILE");
        }
        return if identity == "PRESENT_NONEMPTY_UNVERIFIED" {
            ("FRESH_LOCAL_ONLY", "JOURNAL_AUTHORIZATION_REQUIRED")
        } else {
            ("FRESH_NEEDS_IDENTITY", "NATIVE_IDENTITY_BOOTSTRAP_REQUIRED")
        };
    }
    let field = |name: &str| {
        let mut matches = cursor.split(';').filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            (key == name).then_some(value)
        });
        let value = matches.next();
        if matches.next().is_some() {
            None
        } else {
            value
        }
    };
    if field("credential_cursor") != Some("VALID") {
        return ("UNKNOWN", "READ_ONLY_RECONCILE");
    }
    match (
        field("credential_active_present"),
        field("credential_candidate_present"),
    ) {
        (Some("true"), Some("false")) if runtime == "PRESENT" && config == "PRESENT" => {
            ("EXISTING_ACTIVE_UNVERIFIED", "READ_ONLY_ORIGIN_RECONCILE")
        }
        (Some("false"), Some("true")) => (
            "EXISTING_CANDIDATE_UNVERIFIED",
            "READ_ONLY_ORIGIN_RECONCILE",
        ),
        (Some("true"), Some("true")) => (
            "EXISTING_TRANSITION_UNVERIFIED",
            "READ_ONLY_ORIGIN_RECONCILE",
        ),
        _ => ("PARTIAL", "READ_ONLY_RECONCILE"),
    }
}

fn read_bounded_windows_runtime_evidence(install_root: &Path) -> Result<String, String> {
    let runtime_root = install_root.join("runtime");
    #[cfg(windows)]
    let controller_error = read_controller_service_error_evidence(install_root)?;
    #[cfg(not(windows))]
    let controller_error = "controller_service_error=WINDOWS_ONLY".to_owned();
    #[cfg(windows)]
    let process_classification = read_runtime_process_classification_evidence(install_root)?;
    #[cfg(not(windows))]
    let process_classification = "process_classification=WINDOWS_ONLY".to_owned();
    #[cfg(windows)]
    let scheduled_tasks = read_handoff_task_evidence()?;
    #[cfg(not(windows))]
    let scheduled_tasks = "scheduled_tasks=WINDOWS_ONLY".to_owned();
    #[cfg(windows)]
    let external_owner = read_external_owner_restore_evidence(install_root)?;
    #[cfg(not(windows))]
    let external_owner = "external_owner_evidence=WINDOWS_ONLY".to_owned();
    let cursor = read_bounded_windows_credential_cursor(install_root)?;
    // SYSTEM-only metadata, not an authentication claim. ENOENT is distinct
    // from an ACL/read failure so GitHub cannot infer an empty first-use root.
    let state_file = windows_runtime_state_path(install_root);
    let config_file = local_singbox_config_path(install_root);
    let identity_file = install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    let known_file = |path: &Path| -> Result<Option<fs::Metadata>, String> {
        match fs::metadata(path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("persistent Windows first-use file status unreadable".to_owned()),
        }
    };
    let runtime = if known_file(&state_file)?.is_none() {
        "ABSENT"
    } else {
        "PRESENT"
    };
    let config = if known_file(&config_file)?.is_none() {
        "ABSENT"
    } else {
        "PRESENT"
    };
    let identity = match known_file(&identity_file)? {
        Some(metadata) if metadata.is_file() && metadata.len() > 0 => "PRESENT_NONEMPTY_UNVERIFIED",
        Some(_) => "INVALID",
        None => "ABSENT",
    };
    let (lifecycle, next_action) =
        classify_windows_credential_lifecycle(&cursor, runtime, config, identity);
    let critical = format!(
        "runtime_evidence=BOUNDED_READ_ONLY;{controller_error};{process_classification};{scheduled_tasks};{external_owner};{cursor};credential_lifecycle_state={lifecycle};credential_next_action={next_action};credential_origin=UNPROVEN;first_use_runtime={runtime};first_use_config={config};first_use_access_identity={identity}"
    );
    if critical.len() > RUNTIME_EVIDENCE_RESULT_MAX_BYTES {
        return Err(format!(
            "critical runtime evidence exceeds bounded result contract: {} > {}",
            critical.len(),
            RUNTIME_EVIDENCE_RESULT_MAX_BYTES
        ));
    }

    let stderr =
        read_bounded_runtime_log_tail(&runtime_root.join("sing-box.stderr.log"), "stderr")?;
    let stdout =
        read_bounded_runtime_log_tail(&runtime_root.join("sing-box.stdout.log"), "stdout")?;
    let optional = format!(";{stderr};{stdout}");
    let remaining = RUNTIME_EVIDENCE_RESULT_MAX_BYTES - critical.len();
    if optional.len() <= remaining {
        return Ok(format!("{critical}{optional}"));
    }
    if remaining <= 32 {
        return Ok(critical);
    }
    Ok(format!(
        "{critical}{}",
        truncate_runtime_evidence(&optional, remaining)
    ))
}

#[cfg(windows)]
fn read_controller_service_error_evidence(install_root: &Path) -> Result<String, String> {
    let path = install_root
        .join("logs")
        .join("controller-service-error.txt");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok("controller_service_error=ABSENT".to_owned());
        }
        Err(err) => {
            return Err(format!(
                "failed to read controller service error evidence: {err}"
            ));
        }
    };
    if bytes.len() > 512 {
        return Ok("controller_service_error=INVALID_OVERSIZE".to_owned());
    }
    let text = String::from_utf8_lossy(&bytes);
    let compact = compact_runtime_evidence_line(&redact_runtime_evidence(&text));
    Ok(format!(
        "controller_service_error={}",
        evidence_field(&truncate_runtime_evidence(&compact, 192))
    ))
}

#[cfg(windows)]
fn current_controller_service_pid() -> Result<Option<u32>, String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("failed to open Windows SCM for process evidence: {err}"))?;
    let service = manager
        .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(|err| format!("failed to open controller service for process evidence: {err}"))?;
    service
        .query_status()
        .map(|status| status.process_id)
        .map_err(|err| format!("failed to query controller service process evidence: {err}"))
}

#[cfg(windows)]
fn read_runtime_process_classification_evidence(install_root: &Path) -> Result<String, String> {
    let managed_config = local_singbox_config_path(install_root);
    let controller_pid = current_controller_service_pid()?;
    let (classification, complete, count, pid, parent_pid) =
        match classify_runtime_process(&managed_config) {
            RuntimeProcessClassification::Absent => ("ABSENT", true, 0usize, None, None),
            RuntimeProcessClassification::Managed(process) => {
                let is_current_child =
                    controller_pid.is_some() && process.parent_pid == controller_pid;
                let complete = process.executable_path.is_some()
                    && !process.command_line.is_empty()
                    && process.config_path.is_some();
                (
                    if is_current_child {
                        "MANAGED"
                    } else {
                        "ORPHAN"
                    },
                    complete,
                    1,
                    Some(process.pid),
                    process.parent_pid,
                )
            }
            RuntimeProcessClassification::Conflicting(processes) => {
                let complete = processes.iter().all(|process| {
                    process.executable_path.is_some() && !process.command_line.is_empty()
                });
                ("CONFLICTING", complete, processes.len(), None, None)
            }
        };
    Ok(format!(
        "process_classification={classification};process_evidence_complete={complete};process_count={count};managed_pid={};managed_parent_pid={};controller_pid={}",
        pid.map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        parent_pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        controller_pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
    ))
}

#[cfg(windows)]
struct TaskSchedulerComGuard;

#[cfg(windows)]
impl Drop for TaskSchedulerComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

#[cfg(windows)]
fn sha256_evidence(value: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(windows)]
fn read_handoff_task_evidence() -> Result<String, String> {
    let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if hr.is_err() {
        return Err(format!(
            "failed to initialize COM for privileged Task Scheduler evidence: {hr:?}"
        ));
    }
    let _guard = TaskSchedulerComGuard;

    let task_scheduler_clsid = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
    let service: ITaskService = unsafe {
        CoCreateInstance(
            &task_scheduler_clsid,
            None::<&IUnknown>,
            CLSCTX_INPROC_SERVER,
        )
    }
    .map_err(|err| format!("failed to create Task Scheduler service: {err}"))?;

    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|err| format!("failed to connect Task Scheduler service: {err}"))?;
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|err| format!("failed to open Task Scheduler root folder: {err}"))?;

    let mut observed = Vec::with_capacity(HANDOFF_TASK_NAMES.len());
    for name in HANDOFF_TASK_NAMES {
        let task = unsafe { root.GetTask(&BSTR::from(name)) }
            .map_err(|err| format!("failed to query scheduled task {name}: {err}"))?;
        let enabled = unsafe { task.Enabled() }
            .map_err(|err| format!("failed to query scheduled task {name} enabled state: {err}"))?;
        let state = unsafe { task.State() }
            .map_err(|err| format!("failed to query scheduled task {name} state: {err}"))?;
        let xml = unsafe { task.Xml() }
            .map_err(|err| format!("failed to query scheduled task {name} definition: {err}"))?;
        observed.push(format!(
            "{name}|{}|{}|{}",
            if enabled.0 != 0 { "1" } else { "0" },
            state.0,
            sha256_evidence(&xml.to_string())
        ));
    }
    Ok(format!("tasks={}", observed.join(",")))
}

#[cfg(windows)]
fn evidence_path_matches(observed: &str, expected: &Path) -> bool {
    let observed = Path::new(observed);
    if observed == expected {
        return true;
    }
    match (observed.canonicalize(), expected.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(windows)]
fn evidence_field(value: &str) -> String {
    compact_runtime_evidence_line(value).replace(';', "%3B")
}

#[cfg(windows)]
fn external_startup_owner_kind(
    parent: Option<&edge_local_runtime::ProcessObservation>,
) -> &'static str {
    let Some(parent) = parent else {
        return "PARENT_ABSENT";
    };
    let name = parent.name.to_ascii_lowercase();
    let command = parent.command_line.to_ascii_lowercase();
    if name.contains("powershell") || name == "pwsh.exe" || name == "pwsh" {
        if command.contains("singbox-dual-menu.ps1") {
            "POWERSHELL_MENU"
        } else if command.contains("start-vultr-edge-session.ps1") {
            "POWERSHELL_SESSION"
        } else if command.contains("sing-box") {
            "POWERSHELL_DIRECT"
        } else {
            "POWERSHELL_PARENT"
        }
    } else if name == "cmd.exe" || name == "cmd" {
        "CMD_PARENT"
    } else {
        "OTHER_LIVE_PARENT"
    }
}

#[cfg(windows)]
fn read_external_owner_restore_evidence(install_root: &Path) -> Result<String, String> {
    let managed_config = local_singbox_config_path(install_root);
    let observed = match classify_runtime_process(&managed_config) {
        RuntimeProcessClassification::Managed(process) => vec![process],
        RuntimeProcessClassification::Conflicting(processes) => processes,
        RuntimeProcessClassification::Absent => Vec::new(),
    };
    let external = observed
        .into_iter()
        .filter(|process| {
            !process
                .config_path
                .as_deref()
                .is_some_and(|path| evidence_path_matches(path, &managed_config))
        })
        .collect::<Vec<_>>();
    if external.len() != 1 {
        return Ok(format!(
            "external_owner_evidence=INCOMPLETE;external_count={}",
            external.len()
        ));
    }

    let process = &external[0];
    let parent = process.parent_pid.and_then(observe_process);
    let executable = process.executable_path.as_deref().unwrap_or("UNKNOWN");
    let config = process.config_path.as_deref().unwrap_or("UNKNOWN");
    let executable_exists = executable != "UNKNOWN" && Path::new(executable).is_file();
    let config_exists = config != "UNKNOWN" && Path::new(config).is_file();
    let command_shape = process.command_line.to_ascii_lowercase().contains(" run ")
        && process.config_path.is_some();

    let check_pass = if executable_exists && config_exists {
        Command::new(executable)
            .args(["check", "-c", config])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    } else {
        false
    };
    let owner_kind = external_startup_owner_kind(parent.as_ref());
    let parent_alive = parent.is_some();
    let restore_preflight =
        executable_exists && config_exists && command_shape && check_pass && parent_alive;

    Ok(format!(
        "external_owner_evidence=BOUNDED_READ_ONLY;external_pid={};external_exe={};external_config={};external_run_shape={};external_exe_exists={};external_config_exists={};external_check={};parent_pid={};parent_name={};parent_exe={};startup_owner={};restore_preflight={}",
        process.pid,
        evidence_field(executable),
        evidence_field(config),
        command_shape,
        executable_exists,
        config_exists,
        if check_pass { "PASS" } else { "FAIL" },
        process
            .parent_pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        parent
            .as_ref()
            .map(|value| evidence_field(&value.name))
            .unwrap_or_else(|| "ABSENT".to_owned()),
        parent
            .as_ref()
            .and_then(|value| value.executable_path.as_deref())
            .map(evidence_field)
            .unwrap_or_else(|| "ABSENT".to_owned()),
        owner_kind,
        if restore_preflight { "PASS" } else { "FAIL" },
    ))
}

fn read_bounded_runtime_log_tail(path: &Path, label: &str) -> Result<String, String> {
    if !path.is_file() {
        return Ok(format!("{label}=MISSING"));
    }

    let mut file = File::open(path).map_err(|err| {
        format!(
            "failed to open managed runtime log {}: {err}",
            path.display()
        )
    })?;
    let len = file
        .metadata()
        .map_err(|err| {
            format!(
                "failed to stat managed runtime log {}: {err}",
                path.display()
            )
        })?
        .len();
    let start = len.saturating_sub(RUNTIME_EVIDENCE_MAX_BYTES);
    file.seek(SeekFrom::Start(start)).map_err(|err| {
        format!(
            "failed to seek managed runtime log {}: {err}",
            path.display()
        )
    })?;

    let mut bytes = Vec::with_capacity((len - start) as usize);
    file.read_to_end(&mut bytes).map_err(|err| {
        format!(
            "failed to read managed runtime log {}: {err}",
            path.display()
        )
    })?;
    let text = String::from_utf8_lossy(&bytes);
    let lines = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .rev()
        .take(RUNTIME_EVIDENCE_MAX_LINES)
        .collect::<Vec<_>>();

    let prioritized = lines
        .iter()
        .copied()
        .filter(|line| is_runtime_evidence_priority(line))
        .take(6)
        .collect::<Vec<_>>();
    let selected = if prioritized.is_empty() {
        lines.iter().copied().take(4).collect::<Vec<_>>()
    } else {
        prioritized
    };

    let compact = selected
        .into_iter()
        .map(redact_runtime_evidence)
        .map(|line| compact_runtime_evidence_line(&line))
        .collect::<Vec<_>>()
        .join(" | ");
    Ok(format!(
        "{label}=truncated:{} bytes:{} {}",
        start > 0,
        bytes.len(),
        compact
    ))
}

fn is_runtime_evidence_priority(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "error",
        "fail",
        "warn",
        "dial",
        "connect",
        "dns",
        "tls",
        "hysteria",
        "vless",
        "timeout",
        "refused",
        "unreachable",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn compact_runtime_evidence_line(line: &str) -> String {
    line.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate_runtime_evidence(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    const SUFFIX: &str = "...[truncated]";
    let mut truncated = value[..end].to_owned();
    while truncated.len() + SUFFIX.len() > max_bytes {
        truncated.pop();
    }
    truncated.push_str(SUFFIX);
    truncated
}

fn redact_runtime_evidence(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut token = String::new();

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            token.push(ch);
        } else {
            append_redacted_runtime_token(&mut output, &mut token);
            output.push(ch);
        }
    }
    append_redacted_runtime_token(&mut output, &mut token);
    output
}

fn append_redacted_runtime_token(output: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }
    let is_uuid = token.len() == 36
        && token.chars().enumerate().all(|(index, ch)| match index {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit(),
        });
    let is_long_hex = token.len() >= 16 && token.bytes().all(|byte| byte.is_ascii_hexdigit());

    if is_uuid {
        output.push_str("<redacted-uuid>");
    } else if is_long_hex {
        output.push_str("<redacted-hex>");
    } else {
        output.push_str(token);
    }
    token.clear();
}

fn require_initial_windows_credential_host(install_root: &Path) -> Result<(), String> {
    // Any existing store directory, even with missing/corrupt cursor, is
    // ambiguous. Never interpret it as an unused first-enrollment slot.
    let store_present = windows_credential_store_path(install_root).exists();
    let runtime_present = windows_runtime_state_path(install_root).exists();
    let config_present = local_singbox_config_path(install_root).exists();
    initial_windows_credential_eligibility(store_present, runtime_present, config_present)?;
    load_verified_activation(install_root).map_err(|err| {
        format!("initial Windows proof requires an exact immutable release: {err}")
    })?;
    Ok(())
}

fn initial_windows_credential_eligibility(
    store_present: bool,
    runtime_present: bool,
    config_present: bool,
) -> Result<(), String> {
    if store_present {
        return Err(
            "initial Windows proof refuses an existing or incomplete v2 credential store"
                .to_owned(),
        );
    }
    if runtime_present {
        return Err("initial Windows proof refuses an existing managed runtime state".to_owned());
    }
    if config_present {
        return Err(
            "initial Windows proof refuses an existing rendered sing-box config".to_owned(),
        );
    }
    Ok(())
}

async fn run_windows_initial_credential_probe(install_root: &Path) -> Result<(), String> {
    require_initial_windows_credential_host(install_root)?;
    let identity_path = install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    verify_canonical_dummy_ab_slots(
        edge_shared_types::CredentialProjectionKind::Windows,
        &identity_path,
    )
    .await?;
    println!("operation=CREDENTIAL_INITIAL_PROBE");
    println!("credential_projection=WINDOWS");
    println!("credential_slot_A=EXACT_DUMMY");
    println!("credential_slot_B=EXACT_DUMMY");
    println!("credential_store_present=false");
    println!("credential_provider_mutations=0");
    println!("credential_runtime_mutations=0");
    println!("windows_tun_mutations=0");
    println!("windows_dns_mutations=0");
    println!("credential_initial_authority=NOT_COMMITTED");
    Ok(())
}

async fn stage_windows_credential_candidate_from_worker(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    let generation = request
        .credential_generation
        .ok_or_else(|| "credential_generation is required".to_owned())?;
    if generation == 0 {
        return Err("credential_generation must be greater than zero".to_owned());
    }
    let identity_path = install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    let bundle = fetch_canonical_credential_bundle(
        edge_shared_types::CredentialProjectionKind::Windows,
        generation,
        &identity_path,
    )
    .await?;
    let store_root = windows_credential_store_path(install_root);
    if !store_root.exists() {
        // Existing rotation is untouched. First enrollment is one-shot and
        // must remain stopped inside SYSTEM, irrespective of GitHub preflight.
        #[cfg(windows)]
        require_offline_first_use_stage_owner(install_root)?;
        #[cfg(not(windows))]
        return Err("persistent first-use staging requires Windows SYSTEM owner".to_owned());
    } else {
        let prior = CredentialStore::open_existing(
            &store_root,
            edge_shared_types::CredentialProjectionKind::Windows,
        )?
        .ok_or_else(|| "Windows v2 store disappeared during staging".to_owned())?;
        if prior
            .read_state()?
            .as_ref()
            .and_then(|state| state.active.as_ref())
            .is_none()
        {
            return Err(
                "persistent first-use candidate already attempted or incomplete: never restage"
                    .to_owned(),
            );
        }
    }
    let store = CredentialStore::new(
        windows_credential_store_path(install_root),
        edge_shared_types::CredentialProjectionKind::Windows,
    )?;
    let state = store.stage_delivery_candidate(&bundle)?;
    let candidate = state
        .candidate
        .ok_or_else(|| "credential candidate was not persisted".to_owned())?;
    let active = load_verified_activation(install_root)
        .ok()
        .map(|value| value.release_set_sha256);
    Ok((
        "CREDENTIAL_CANDIDATE_STAGED".to_owned(),
        format!(
            "credential candidate staged generation={} slot={}",
            candidate.generation, candidate.slot
        ),
        active,
    ))
}

fn require_supported_reinstall_authority() -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "canonical production Windows datapath mode is invalid".to_owned())?;
    match mode {
        WindowsDatapathMode::ProxyOnly | WindowsDatapathMode::ManagedTun => Ok(()),
        WindowsDatapathMode::Unspecified => Err(
            "accepted-release reinstall requires an explicit supported Windows datapath mode"
                .to_owned(),
        ),
    }
}

// Both the submitting CLI and the privileged dispatcher must execute from
// the verified immutable release directory. Calling from bin/edge-console.exe
// would lock the very stable EXE the installer needs to replace, but only
// AFTER the old sing-box has already been stopped.
fn require_exact_immutable_activation_console(install_root: &Path) -> Result<(), String> {
    let active = load_verified_activation(install_root)
        .map_err(|err| format!("cannot verify active release before activation: {err}"))?;
    let running = env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|err| format!("cannot verify invoking console path before activation: {err}"))?;
    let expected = Path::new(&active.console_path)
        .canonicalize()
        .map_err(|err| format!("cannot resolve exact active immutable console path: {err}"))?;
    if running != expected {
        return Err(format!(
            "activation requires exact immutable console {}; never invoke from the stable bin/edge-console.exe, which cannot be replaced while running",
            expected.display()
        ));
    }
    Ok(())
}

fn activate_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
    force_rematerialize: bool,
) -> Result<(String, String, Option<String>), String> {
    // This runs again inside privileged dispatch, BEFORE touching sing-box.
    // Updating the stable console fails on Windows if the same EXE is loaded.
    require_exact_immutable_activation_console(install_root)?;
    let accepted_revision = request
        .accepted_revision
        .as_deref()
        .ok_or_else(|| "accepted_revision is required".to_owned())?;
    let target_release = request
        .release_set_sha256
        .as_deref()
        .ok_or_else(|| "release_set_sha256 is required".to_owned())?;

    // An accepted ProxyOnly target cannot silently retire the current managed TUN.
    // Do not infer independent foreign WARP DNS/control recovery from a release pointer.
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode == WindowsDatapathMode::ProxyOnly as i32 {
        edge_local_runtime::reject_unproven_windows_tun_teardown("managed-tun-to-proxy-only")?;
    }

    let before_activation = load_verified_activation(install_root).ok();
    let mut previous_bytes_before = None;

    let restore_verified_owner = |activation: &WindowsActivationState| -> Result<(), String> {
        sync_stable_windows_release_tools(install_root, activation)?;
        reconcile_activation_owner(install_root, activation)
    };

    if force_rematerialize {
        require_supported_reinstall_authority()?;
        let current = before_activation.as_ref().ok_or_else(|| {
            "accepted-release reinstall requires a verified current activation".to_owned()
        })?;
        if current.release_set_sha256 != target_release {
            return Err(
                "accepted-release reinstall target must equal the exact current ReleaseSet"
                    .to_owned(),
            );
        }
        let (_, previous) = load_previous_release_rollback_pair(install_root)?;
        if previous.release_set_sha256 == target_release {
            return Err(
                "accepted-release reinstall requires a distinct verified previous.pb rollback target"
                    .to_owned(),
            );
        }
        previous_bytes_before =
            Some(fs::read(install_root.join("previous.pb")).map_err(|err| {
                format!("failed to snapshot previous.pb before reinstall: {err}")
            })?);
    } else if let Some(activation) = before_activation.as_ref()
        && activation.release_set_sha256 == target_release
    {
        reconcile_activation_owner(install_root, activation)?;
        return Ok((
            "RELEASE_ALREADY_CONVERGED".to_owned(),
            "exact target ReleaseSet is already locally verified; installer not invoked; exact owner handoff reconciled".to_owned(),
            Some(activation.release_set_sha256.clone()),
        ));
    }

    let installer = install_root
        .join("bootstrap")
        .join("install-windows-release.ps1");
    if !installer.is_file() {
        return Err(format!(
            "protected Windows installer is missing: {}",
            installer.display()
        ));
    }
    let root = install_root
        .to_str()
        .ok_or_else(|| "Windows install root is not UTF-8".to_owned())?;

    stop_runtime_process(&local_singbox_config_path(install_root), true).map_err(|err| {
        format!("failed to stop exact managed proxy before release transition: {err}")
    })?;

    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&installer)
        .args([
            "-AcceptedRevision",
            accepted_revision,
            "-ReleaseSetSha256",
            target_release,
            "-InstallRoot",
            root,
        ]);
    if force_rematerialize {
        command.arg("-ForceRematerialize");
    }
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("failed to start protected Windows installer: {err}"))?;

    if !output.status.success() {
        if force_rematerialize {
            if let Ok(observed) = load_verified_activation(install_root)
                && observed.release_set_sha256 == target_release
                && before_activation
                    .as_ref()
                    .is_some_and(|before| before.release_dir != observed.release_dir)
            {
                if let Some(expected_previous) = previous_bytes_before.as_ref()
                    && fs::read(install_root.join("previous.pb")).ok().as_ref()
                        != Some(expected_previous)
                {
                    let _ = write_atomic(&install_root.join("previous.pb"), expected_previous);
                    reconcile_activation_owner(install_root, &observed)?;
                    return Err(
                        "accepted release rematerialized but previous.pb changed unexpectedly; rollback authority was restored"
                            .to_owned(),
                    );
                }
                reconcile_activation_owner(install_root, &observed)?;
                return Ok((
                    "RELEASE_REINSTALLED_REOBSERVED".to_owned(),
                    "alternate immutable release slot committed despite installer exit failure; exact authority was reobserved and owner handoff reconciled"
                        .to_owned(),
                    Some(observed.release_set_sha256),
                ));
            }

            if let Some(before) = before_activation.as_ref() {
                restore_verified_owner(before)?;
            }
            return Err(format!(
                "protected Windows reinstall failed with exit code {}; {}",
                output.status.code().unwrap_or(-1),
                bounded_privileged_child_evidence(&output.stdout, &output.stderr)
            ));
        }

        if let Ok(activation) = load_verified_activation(install_root)
            && activation.release_set_sha256 == target_release
        {
            reconcile_activation_owner(install_root, &activation)?;
            return Ok((
                "RELEASE_CONVERGED_REOBSERVED".to_owned(),
                "exact target ReleaseSet committed despite installer failure; local owner handoff reconciled"
                    .to_owned(),
                Some(activation.release_set_sha256),
            ));
        }

        if let Some(before) = before_activation.as_ref() {
            restore_verified_owner(before)?;
        }
        return Err(format!(
            "protected Windows installer failed with exit code {}; {}",
            output.status.code().unwrap_or(-1),
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        ));
    }

    let activation = load_verified_activation(install_root)
        .map_err(|err| format!("updated Windows activation failed verification: {err}"))?;
    if activation.release_set_sha256 != target_release {
        return Err("updated Windows activation does not match requested ReleaseSet".to_owned());
    }

    if force_rematerialize {
        let before = before_activation
            .as_ref()
            .ok_or_else(|| "reinstall lost its pre-mutation activation snapshot".to_owned())?;
        if activation.release_dir == before.release_dir {
            reconcile_activation_owner(install_root, &activation)?;
            return Err(
                "accepted-release reinstall did not switch to the alternate immutable release slot"
                    .to_owned(),
            );
        }
        if let Some(expected_previous) = previous_bytes_before.as_ref() {
            let observed_previous = fs::read(install_root.join("previous.pb"))
                .map_err(|err| format!("failed to verify previous.pb after reinstall: {err}"))?;
            if &observed_previous != expected_previous {
                write_atomic(&install_root.join("previous.pb"), expected_previous).map_err(
                    |err| format!("failed to restore previous.pb after reinstall: {err}"),
                )?;
                reconcile_activation_owner(install_root, &activation)?;
                return Err(
                    "accepted-release reinstall changed previous.pb; exact prior rollback authority was restored"
                        .to_owned(),
                );
            }
        }
    }

    reconcile_activation_owner(install_root, &activation)?;
    Ok((
        if force_rematerialize {
            "RELEASE_REINSTALLED".to_owned()
        } else {
            "RELEASE_CONVERGED".to_owned()
        },
        if force_rematerialize {
            "exact accepted ReleaseSet was downloaded again, verified, activated from the alternate immutable slot, and previous.pb was preserved"
                .to_owned()
        } else {
            "exact accepted ReleaseSet and controller service are active".to_owned()
        },
        Some(activation.release_set_sha256),
    ))
}

fn offline_handoff_gate(
    stopped: bool,
    no_runtime_processes: bool,
    no_managed_tun: bool,
    exact_service_owner: bool,
) -> Result<(), String> {
    if stopped && no_runtime_processes && no_managed_tun && exact_service_owner {
        Ok(())
    } else {
        Err("OFFLINE_HANDOFF_BLOCKED: stopped SCM, zero runtime owners, absent TUN and exact executable/account are mandatory".to_owned())
    }
}

#[cfg(windows)]
fn require_offline_windows_owner(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    require_offline_windows_owner_at(install_root, activation, &install_root.join("current.pb"))
}

#[cfg(windows)]
fn require_offline_windows_owner_at(
    install_root: &Path,
    activation: &WindowsActivationState,
    authority_path: &Path,
) -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    if !matches!(
        WindowsDatapathMode::try_from(desired.windows_datapath_mode),
        Ok(WindowsDatapathMode::ProxyOnly | WindowsDatapathMode::ManagedTun)
    ) {
        return Err("OFFLINE_HANDOFF_BLOCKED: canonical mode unsupported".to_owned());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("offline SCM manager unavailable: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|err| format!("offline SCM owner unavailable: {err}"))?;
    let config = service
        .query_config()
        .map_err(|err| format!("offline SCM configuration unavailable: {err}"))?;
    let status = service
        .query_status()
        .map_err(|err| format!("offline SCM state unavailable: {err}"))?;
    let expected_command = format!(
        "{} windows-service {} {}",
        activation.controller_path,
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR
    );
    let account = config
        .account_name
        .as_deref()
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    // A stopped former ManagedTun may be safely retired into ProxyOnly only
    // after this very owner proves zero TUN and processes. The new owner
    // remains manual-start until separate accepted service activation.
    let start_type_allowed = config.start_type == ServiceStartType::OnDemand
        || config.start_type == ServiceStartType::AutoStart;
    let exact = config.executable_path.to_string_lossy() == expected_command
        && account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)
        && start_type_allowed;
    let no_processes = matches!(
        classify_runtime_process(&local_singbox_config_path(install_root)),
        RuntimeProcessClassification::Absent
    );
    let output = Command::new(&activation.diagnostic_path)
        .arg("doctor")
        .arg(authority_path)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("offline exact native diagnostic unavailable: {err}"))?;
    // Doctor can exit non-zero when a deliberately stopped ManagedTun is
    // not in its desired running state. Its exact OS observations remain useful.
    let doctor = String::from_utf8_lossy(&output.stdout);
    let has_field = |field: &str| doctor.lines().any(|line| line.trim() == field);
    let attested_mode = has_field("windows_datapath_mode=ManagedTun")
        || (has_field("windows_datapath_mode=ProxyOnly")
            && desired.windows_datapath_mode == WindowsDatapathMode::ProxyOnly as i32);
    let exact_release = has_field(&format!(
        "release_set_sha256={}",
        activation.release_set_sha256
    ));
    let no_tun = attested_mode
        && exact_release
        && has_field("managed_tun_present=false")
        && has_field("managed_singbox_process_count=0")
        && has_field("orphan_singbox_process_count=0")
        && has_field("conflicting_singbox_process_count=0")
        && has_field("unknown_singbox_process_count=0")
        && has_field("exact_release_files=PASS");
    offline_handoff_gate(
        status.current_state == ServiceState::Stopped && status.process_id.is_none(),
        no_processes,
        no_tun,
        exact,
    )
}

#[cfg(windows)]
fn offline_retarget_controller_service(
    install_root: &Path,
    from: &WindowsActivationState,
    to: &WindowsActivationState,
) -> Result<(), String> {
    offline_retarget_controller_service_checked(install_root, from, to, false)
}

#[cfg(windows)]
fn offline_retarget_controller_service_checked(
    install_root: &Path,
    from: &WindowsActivationState,
    to: &WindowsActivationState,
    _restore_from_verified_snapshot: bool,
) -> Result<(), String> {
    // current.pb already points at the newly installed version. Prove the
    // outgoing owner against its immutable snapshot, not the new pointer.
    require_offline_windows_owner_from_snapshot(install_root, from)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("offline SCM manager unavailable: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|err| format!("offline SCM owner unavailable: {err}"))?;
    let next = ServiceInfo {
        name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(&to.controller_path),
        launch_arguments: vec![
            OsString::from("windows-service"),
            install_root.as_os_str().to_owned(),
            OsString::from(INSTALLED_CONTROLLER_ADDR),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)),
        account_password: None,
    };
    service
        .change_config(&next)
        .map_err(|err| format!("offline SCM retarget failed: {err}"))?;
    let updated = service
        .query_config()
        .map_err(|err| format!("offline SCM config readback failed: {err}"))?;
    let state = service
        .query_status()
        .map_err(|err| format!("offline SCM state readback failed: {err}"))?;
    let expected = format!(
        "{} windows-service {} {}",
        to.controller_path,
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR
    );
    if updated.executable_path.to_string_lossy() != expected
        || updated.start_type != ServiceStartType::OnDemand
        || state.current_state != ServiceState::Stopped
        || state.process_id.is_some()
    {
        return Err(
            "OFFLINE_HANDOFF_BLOCKED: SCM retarget has no exact stopped readback".to_owned(),
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn offline_retarget_controller_service_checked(
    _install_root: &Path,
    _from: &WindowsActivationState,
    _to: &WindowsActivationState,
    _restore_from_verified_snapshot: bool,
) -> Result<(), String> {
    Err("offline SCM recovery handoff is Windows-only".to_owned())
}

#[cfg(not(windows))]
fn require_offline_windows_owner(
    _install_root: &Path,
    _activation: &WindowsActivationState,
) -> Result<(), String> {
    Err("offline Windows ReleaseSet handoff is Windows-only".to_owned())
}

#[cfg(not(windows))]
fn offline_retarget_controller_service(
    _install_root: &Path,
    _from: &WindowsActivationState,
    _to: &WindowsActivationState,
) -> Result<(), String> {
    Err("offline Windows SCM retarget is Windows-only".to_owned())
}

// A saved, previously verified activation is independent of a torn current.pb.
// Use a single exclusive temporary proof in the SAME install root (the native
// diagnostic derives its root from authority_path.parent()). Never overwrite a
// leftover proof after a crash, and never trust a caller-provided executable.
#[cfg(windows)]
fn require_offline_windows_owner_from_snapshot(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    verify_windows_activation_files(activation)?;
    let proof = install_root.join("offline-recovery-proof.pb");
    let bytes = encode_windows_activation_state(activation)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&proof)
        .map_err(|err| format!("exclusive offline recovery proof unavailable: {err}"))?;
    let written = file.write_all(&bytes).and_then(|_| file.sync_all());
    drop(file);
    let result = written
        .map_err(|err| format!("failed to persist bounded offline recovery proof: {err}"))
        .and_then(|_| require_offline_windows_owner_at(install_root, activation, &proof));
    let cleanup = fs::remove_file(&proof)
        .map_err(|err| format!("offline recovery proof cleanup failed: {err}"));
    result?;
    cleanup
}

#[cfg(not(windows))]
fn require_offline_windows_owner_from_snapshot(
    _install_root: &Path,
    _activation: &WindowsActivationState,
) -> Result<(), String> {
    Err("offline recovery proof is Windows-only".to_owned())
}

// Snapshot an existing rollback authority without collapsing read errors into
// absence. Only ENOENT is a legitimate missing previous.pb.
fn snapshot_offline_previous(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "OFFLINE_PREVIOUS_SNAPSHOT_BLOCKED: cannot read existing rollback authority: {err}"
        )),
    }
}

fn restore_offline_previous(
    path: &Path,
    old_current_bytes: &[u8],
    previous: &Option<Vec<u8>>,
) -> Result<(), String> {
    if let Some(bytes) = previous {
        return write_atomic(path, bytes)
            .map_err(|err| format!("offline previous authority restoration failed: {err}"));
    }
    // Only the protected installer is permitted to create previous.pb when
    // none existed. It copies exact old current.pb, so a different new file
    // must not be deleted by compensation.
    match fs::read(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "OFFLINE_PREVIOUS_RESTORE_BLOCKED: previous state unreadable: {err}"
        )),
        Ok(bytes) if bytes == old_current_bytes => fs::remove_file(path)
            .map_err(|err| format!("offline generated previous authority removal failed: {err}")),
        Ok(_) => Err(
            "OFFLINE_PREVIOUS_RESTORE_BLOCKED: new previous.pb is not the exact saved current authority"
                .to_owned(),
        ),
    }
}

// This bounded pointer-only compensation can be fault-injected on any OS.
// It never calls SCM or starts a process. Every failure stops before the
// current authority is rewritten, leaving an inspectable split state.
fn restore_offline_authority_pointers(
    install_root: &Path,
    old_current_bytes: &[u8],
    previous: &Option<Vec<u8>>,
) -> Result<(), String> {
    restore_offline_previous(
        &install_root.join("previous.pb"),
        old_current_bytes,
        previous,
    )?;
    write_atomic(&install_root.join("current.pb"), old_current_bytes)
        .map_err(|err| format!("offline current authority restoration failed: {err}"))
}

// A failed or uncertain offline handoff never starts either controller or
// sing-box. Restore exact previous authority only from locally verified bytes.
fn restore_offline_release(
    install_root: &Path,
    before: &WindowsActivationState,
    current_bytes: &[u8],
    previous_bytes: &Option<Vec<u8>>,
    alternate_scm_owner: Option<&WindowsActivationState>,
) -> Result<(), String> {
    // Never read the possibly torn current.pb to decide whether compensation
    // is safe. Each SCM candidate must be a verified immutable activation:
    // the old snapshot, or the exact new/rollback candidate supplied above.
    // Any third owner must fail closed without writing the release pointers.
    if require_offline_windows_owner_from_snapshot(install_root, before).is_err() {
        let replacement = alternate_scm_owner.ok_or_else(|| {
            "OFFLINE_RESTORE_BLOCKED: current SCM does not match saved old authority and no exact replacement was proved".to_owned()
        })?;
        require_offline_windows_owner_from_snapshot(install_root, replacement)?;
        if replacement.controller_path != before.controller_path {
            offline_retarget_controller_service_checked(install_root, replacement, before, true)?;
        }
    }
    // Restore previous first; a failed prerequisite never overwrites current.
    restore_offline_authority_pointers(install_root, current_bytes, previous_bytes)?;
    sync_stable_windows_release_tools(install_root, before)?;
    retarget_privileged_task(install_root, &before.console_path)?;
    require_offline_windows_owner(install_root, before)?;
    Ok(())
}

#[cfg(windows)]
fn offline_hold_controller_stopped(
    install_root: &Path,
    before: &WindowsActivationState,
) -> Result<(), String> {
    require_offline_windows_owner(install_root, before)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("offline SCM manager unavailable: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|err| format!("offline SCM owner unavailable: {err}"))?;
    let config = service.query_config().map_err(|err| err.to_string())?;
    let account = config
        .account_name
        .as_ref()
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT) {
        return Err("OFFLINE_HANDOFF_BLOCKED: SCM identity changed".to_owned());
    }
    let next = ServiceInfo {
        name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(&before.controller_path),
        launch_arguments: vec![
            OsString::from("windows-service"),
            install_root.as_os_str().to_owned(),
            OsString::from(INSTALLED_CONTROLLER_ADDR),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)),
        account_password: None,
    };
    service
        .change_config(&next)
        .map_err(|err| format!("offline SCM hold failed: {err}"))?;
    let observed = service.query_config().map_err(|err| err.to_string())?;
    let status = service.query_status().map_err(|err| err.to_string())?;
    if observed.start_type != ServiceStartType::OnDemand
        || status.current_state != ServiceState::Stopped
        || status.process_id.is_some()
    {
        return Err("OFFLINE_HANDOFF_BLOCKED: stopped manual-start SCM readback failed".to_owned());
    }
    require_offline_windows_owner(install_root, before)
}

#[cfg(not(windows))]
fn offline_hold_controller_stopped(
    _install_root: &Path,
    _before: &WindowsActivationState,
) -> Result<(), String> {
    Err("offline SCM hold is Windows-only".to_owned())
}

fn offline_activate_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    require_exact_immutable_activation_console(install_root)?;
    offline_activate_privileged_release_with_installer(install_root, request, None)
}

fn offline_activate_privileged_release_with_installer(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
    verified_bootstrap_installer: Option<&Path>,
) -> Result<(String, String, Option<String>), String> {
    let before = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    require_offline_windows_owner(install_root, &before)?;
    let revision = request
        .accepted_revision
        .as_deref()
        .ok_or_else(|| "offline activation requires accepted revision".to_owned())?;
    let target = request
        .release_set_sha256
        .as_deref()
        .ok_or_else(|| "offline activation requires exact ReleaseSet SHA256".to_owned())?;
    if target.len() != 64
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(
            "offline activation requires exact lowercase canonical revision and SHA256".to_owned(),
        );
    }
    if before.release_set_sha256 == target {
        return Err(
            "offline activation target already current; use read-only diagnose, do not replay"
                .to_owned(),
        );
    }
    let current_bytes = fs::read(install_root.join("current.pb")).map_err(|err| err.to_string())?;
    let previous_path = install_root.join("previous.pb");
    let previous_bytes = snapshot_offline_previous(&previous_path)?;
    if previous_bytes.is_some() {
        load_verified_activation_path(install_root, &previous_path, "previous.pb")
            .map_err(|err| format!("OFFLINE_PREVIOUS_SNAPSHOT_BLOCKED: {err}"))?;
    }
    // This is the first mutation. Hold SCM on manual start BEFORE modifying
    // release pointers so an unexpected reboot cannot start ManagedTun.
    offline_hold_controller_stopped(install_root, &before)?;
    let installer = verified_bootstrap_installer
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            install_root
                .join("bootstrap")
                .join("install-windows-release.ps1")
        });
    if !installer.is_file() {
        return Err("protected offline installer missing".to_owned());
    }
    // Revalidation after the offline handoff must use the same direct
    // GitHub policy; Windows PowerShell 5.1 lacks -NoProxy.
    let output = Command::new("pwsh.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&installer)
        .args([
            "-AcceptedRevision",
            revision,
            "-ReleaseSetSha256",
            target,
            "-InstallRoot",
        ])
        .arg(install_root)
        .arg("-Offline")
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("offline protected installer invocation failed: {err}"))?;
    let post = match load_verified_activation(install_root) {
        Ok(value) => value,
        Err(err) => {
            let compensation = restore_offline_release(
                install_root,
                &before,
                &current_bytes,
                &previous_bytes,
                None,
            );
            return Err(format!(
                "offline installer outcome uncertain, current.pb unreadable: {err}; compensation={compensation:?}; do not retry blindly"
            ));
        }
    };
    if !output.status.success() || post.release_set_sha256 != target {
        // No blind replay of installer after an unknown result.
        let restore =
            restore_offline_release(install_root, &before, &current_bytes, &previous_bytes, None);
        return Err(format!(
            "offline installer not accepted; exit={}; restore={restore:?}; {}",
            output.status.code().unwrap_or(-1),
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        ));
    }
    let handoff = offline_retarget_controller_service(install_root, &before, &post)
        // The new signed dispatcher assumes this protected native host root,
        // even when ProxyOnly is STOPPED and SCM is never started.
        .and_then(|_| {
            #[cfg(windows)]
            {
                converge_native_host_acl(install_root)?;
                converge_windows_system_authority_acl(install_root, Path::new(&post.console_path))?;
            }
            Ok(())
        })
        .and_then(|_| retarget_privileged_task(install_root, &post.console_path))
        .and_then(|_| {
            #[cfg(windows)]
            if verified_bootstrap_installer.is_some() {
                verify_offline_bootstrap_dispatcher(&post.console_path, "Disabled")?;
            }
            Ok(())
        });
    if let Err(err) = handoff {
        let restore = restore_offline_release(
            install_root,
            &before,
            &current_bytes,
            &previous_bytes,
            Some(&post),
        );
        return Err(format!(
            "offline owner handoff failed: {err}; compensation={restore:?}; do not blindly retry"
        ));
    }
    if let Err(err) = require_offline_windows_owner(install_root, &post) {
        let compensation = restore_offline_release(
            install_root,
            &before,
            &current_bytes,
            &previous_bytes,
            Some(&post),
        );
        return Err(format!(
            "offline post-handoff owner not verified: {err}; compensation={compensation:?}; do not retry blindly"
        ));
    }
    Ok((
        "OFFLINE_RELEASE_ACTIVATED".to_owned(),
        "exact ReleaseSet installed; SCM remains Stopped; no TUN/DNS/routes changed and no service started".to_owned(),
        Some(post.release_set_sha256),
    ))
}

#[cfg(windows)]
fn encoded_powershell_command(script: &str) -> String {
    // -EncodedCommand is the native PowerShell contract for programmatic
    // invocation: UTF-16LE base64, with no ambiguity from Windows argv quoting.
    use base64::Engine as _;
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(windows)]
fn require_offline_bootstrap_installer_archive_identity(
    verified_zip: &Path,
    candidate_installer: &Path,
) -> Result<(), String> {
    // No install, SCM, task, or BEGIN mutation. The target ZIP and binaries
    // have already passed verify-windows; prove installer identity separately.
    // Phase-labelled evidence is bounded and never includes installer bytes.
    let verify_script = r#"
$ErrorActionPreference = 'Stop'
$phase = 'LOAD_COMPRESSION'
try {
    # Keep the verified host-specific ZIP assembly loader. The local digest
    # below uses direct .NET streams instead of module-autoloaded Get-FileHash.
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $phase = 'OPEN_ZIP'
    $archive = [IO.Compression.ZipFile]::OpenRead($env:EDGE_BOOTSTRAP_VERIFIED_ZIP)
    try {
        $phase = 'FIND_UNIQUE_ENTRY'
        $entries = @($archive.Entries | Where-Object {
            [string]$_.FullName.Replace('\','/') -ceq 'bootstrap/install-windows-release.ps1'
        })
        if ($entries.Count -ne 1) { throw 'ZIP_ENTRY_COUNT_INVALID' }
        $phase = 'HASH_ZIP_ENTRY'
        $stream = $entries[0].Open()
        try {
            $hasher = [Security.Cryptography.SHA256]::Create()
            try { $expected = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-','') }
            finally { $hasher.Dispose() }
        } finally { $stream.Dispose() }
    } finally { $archive.Dispose() }
    $phase = 'HASH_LOCAL_INSTALLER'
    $fileStream = [IO.File]::OpenRead($env:EDGE_BOOTSTRAP_TARGET_INSTALLER)
    try {
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $actual = ([BitConverter]::ToString($hasher.ComputeHash($fileStream))).Replace('-','') }
        finally { $hasher.Dispose() }
    } finally { $fileStream.Dispose() }
    $phase = 'COMPARE_DIGEST'
    if ($actual -cne $expected) { throw 'candidate installer hash differs from verified ZIP' }
} catch {
    # Do not print paths, ZIP entries, credentials, or complete PowerShell
    # exception messages. The phase and stable error ID suffice for forensics.
    $id = [string]$_.FullyQualifiedErrorId
    if ($id -notmatch '^[a-zA-Z0-9,._-]{1,96}$') { $id = 'UNCLASSIFIED' }
    [Console]::Error.WriteLine("ZIP_PROOF_PHASE=$phase;ERROR_ID=$id")
    exit 82
}
"#;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_powershell_command(verify_script),
        ])
        .env("EDGE_BOOTSTRAP_VERIFIED_ZIP", verified_zip)
        .env("EDGE_BOOTSTRAP_TARGET_INSTALLER", candidate_installer)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: ZIP proof host unavailable: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "OFFLINE_BOOTSTRAP_BLOCKED: ZIP-to-installer verification failed; child_exit={}; {}",
            output.status.code().unwrap_or(-1),
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_offline_bootstrap_dispatcher(
    exact_console: &str,
    expected_state: &str,
) -> Result<(), String> {
    // Readback after retargeting the ONE existing task is required before
    // committing a successful offline handoff; never trust schtasks exit alone.
    let proof = r#"
$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName 'EdgePlatformPrivilegedDispatch' -ErrorAction Stop
if ($null -eq $task) { throw 'existing SYSTEM dispatcher missing' }
# Localized principal names (e.g. 'СИСТЕМА') are never authority:
# resolve by Windows itself and compare only the immutable LocalSystem SID.
$principalName = [string]$task.Principal.UserId
try {
    $principalSid = if ($principalName -ceq 'S-1-5-18') {
        'S-1-5-18'
    } else {
        ([System.Security.Principal.NTAccount]::new($principalName)).Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    }
} catch {
    throw 'existing SYSTEM dispatcher principal SID cannot be resolved'
}
if ($principalSid -cne 'S-1-5-18' -or
    [string]$task.State -cne $env:EDGE_BOOTSTRAP_EXPECTED_TASK_STATE -or
    [string]$task.Principal.RunLevel -cne 'Highest' -or
    [string]$task.Principal.LogonType -cne 'ServiceAccount' -or
    @($task.Actions).Count -ne 1) {
    throw 'existing SYSTEM dispatcher principal/state changed'
}
$action = @($task.Actions)[0]
if ([string]$action.Execute.Trim('"') -cne $env:EDGE_BOOTSTRAP_EXPECTED_CONSOLE -or
    [string]$action.Arguments -notmatch '^privileged-dispatch --install-root "?C:\\sing-box"?$') {
    throw 'exact immutable dispatcher action/arguments changed'
}
"#;
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", proof])
        .env("EDGE_BOOTSTRAP_EXPECTED_CONSOLE", exact_console)
        .env("EDGE_BOOTSTRAP_EXPECTED_TASK_STATE", expected_state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: dispatcher proof unavailable: {err}"))?;
    if !status.success() {
        return Err(
            "OFFLINE_BOOTSTRAP_BLOCKED: exact SYSTEM dispatcher readback failed".to_owned(),
        );
    }
    Ok(())
}

// Pure, testable source admission. Caller separately proves immutable doctor
// identity, stopped SCM, zero processes and no managed TUN.
fn require_offline_bootstrap_supported_source(doctor: &str) -> Result<(), String> {
    let modes: Vec<_> = doctor
        .lines()
        .filter_map(|line| line.trim().strip_prefix("windows_datapath_mode="))
        .collect();
    if modes.len() != 1
        || !matches!(modes[0], "ManagedTun" | "ProxyOnly")
        || (modes[0] == "ProxyOnly"
            && !doctor
                .lines()
                .any(|line| line.trim() == "scm_start_type=OnDemand"))
    {
        return Err(
            "OFFLINE_BOOTSTRAP_BLOCKED: exact stopped ProxyOnly/ManagedTun source unproven"
                .to_owned(),
        );
    }
    Ok(())
}

// A historical first-use BEGIN is a real durable transaction record.
// In normal mode it blocks forever, even when the current owner is healthy.
// Explicit local Administrator supersession can archive exact old bytes as
// UNKNOWN_SUPERSEDED, never as a fabricated terminal success or replay proof.
#[derive(Debug, Clone)]
struct RetainedOfflineBootstrapSupersession {
    expected_intent_sha256: String,
    expected_current_release_set_sha256: String,
}

#[derive(Debug)]
struct VerifiedRetainedOfflineBootstrap {
    original_bytes: Vec<u8>,
    sha256: String,
    from: String,
    to: String,
    accepted_revision: String,
}

fn inspect_retained_offline_bootstrap_intent(
    install_root: &Path,
    approval: &RetainedOfflineBootstrapSupersession,
    observed_current: &str,
) -> Result<VerifiedRetainedOfflineBootstrap, String> {
    // Both independent digests are exact lowercase SHA-256 identities.
    if approval.expected_intent_sha256.len() != 64
        || approval.expected_current_release_set_sha256.len() != 64
        || ![
            &approval.expected_intent_sha256,
            &approval.expected_current_release_set_sha256,
        ]
        .iter()
        .all(|value| {
            value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_SHA_INVALID".to_owned());
    }
    if observed_current != approval.expected_current_release_set_sha256 {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_INSTALLED_RELEASE_DRIFT".to_owned());
    }
    let path = install_root.join("offline-bootstrap-intent-v1");
    let metadata = fs::symlink_metadata(&path).map_err(|err| {
        format!("OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_INTENT_MISSING_OR_UNPROVEN: {err}")
    })?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 512 {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_INTENT_NOT_REGULAR_BOUNDED".to_owned());
    }
    let bytes = fs::read(&path)
        .map_err(|_| "OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_INTENT_UNREADABLE".to_owned())?;
    if bytes.len() as u64 != metadata.len() {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_INTENT_CHANGED".to_owned());
    }
    let sha256: String = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    if sha256 != approval.expected_intent_sha256 {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_INTENT_SHA_MISMATCH".to_owned());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_INTENT_NOT_UTF8".to_owned())?;
    let lines: Vec<_> = text.split('\n').collect();
    let [schema, from_line, to_line, revision_line, ""] = lines.as_slice() else {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_INTENT_NONCANONICAL".to_owned());
    };
    if *schema != "schema=sing-box.windows-offline-bootstrap/v1" {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_SCHEMA_INVALID".to_owned());
    }
    let (Some(from), Some(to), Some(revision)) = (
        from_line.strip_prefix("from="),
        to_line.strip_prefix("to="),
        revision_line.strip_prefix("accepted_revision="),
    ) else {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_FIELDS_INVALID".to_owned());
    };
    if !offline_bootstrap_identifiers_valid(revision, from)
        || !offline_bootstrap_identifiers_valid(revision, to)
        || from == to
    {
        return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_IDENTITY_INVALID".to_owned());
    }
    let from = from.to_owned();
    let to = to.to_owned();
    let accepted_revision = revision.to_owned();
    Ok(VerifiedRetainedOfflineBootstrap {
        original_bytes: bytes,
        sha256,
        from,
        to,
        accepted_revision,
    })
}

// A new, separately approved release can supersede a previously compensated
// UNKNOWN. It must never be the release/revision already named by the pending
// BEGIN, and the BEGIN must originate from the still-installed old owner.
// The existing task must independently prove its exact Disabled state.
fn require_distinct_offline_bootstrap_successor(
    retained: &VerifiedRetainedOfflineBootstrap,
    installed_release: &str,
    next_revision: &str,
    next_target: &str,
) -> Result<(), String> {
    if retained.from != installed_release
        || retained.to == next_target
        || retained.accepted_revision == next_revision
        || !offline_bootstrap_identifiers_valid(next_revision, next_target)
    {
        return Err("OFFLINE_BOOTSTRAP_DISABLED_SUCCESSOR_NOT_DISTINCT_NO_REPLAY".to_owned());
    }
    Ok(())
}

fn require_offline_bootstrap_other_pending_absent(install_root: &Path) -> Result<(), String> {
    for relative in [
        "exchange/requests/request.pb",
        "exchange/requests/host-intent.pb",
        "current.pb.new",
        "previous.pb.new",
        "offline-recovery-proof.pb",
    ] {
        match fs::symlink_metadata(install_root.join(relative)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(format!(
                    "OFFLINE_BOOTSTRAP_BLOCKED: unresolved existing operation at {relative}; no replay"
                ));
            }
            Err(_) => {
                return Err(format!(
                    "OFFLINE_BOOTSTRAP_BLOCKED: pending state cannot be read at {relative}"
                ));
            }
        }
    }
    Ok(())
}

// A crash between archiving the historical BEGIN and creating a new BEGIN
// must NEVER look like a clean install. The SHA-addressed immutable archive
// itself proves that a supersession was attempted. A normal new bootstrap
// cannot consume it or infer that the earlier operation finished.
fn require_no_historical_bootstrap_supersession(install_root: &Path) -> Result<(), String> {
    let entries = fs::read_dir(install_root).map_err(|_| {
        "OFFLINE_BOOTSTRAP_BLOCKED: historical archive inventory unreadable; no replay".to_owned()
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            "OFFLINE_BOOTSTRAP_BLOCKED: historical archive entry unreadable; no replay".to_owned()
        })?;
        if entry
            .file_name()
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("offline-bootstrap-intent-v1.historical-")
        {
            return Err(
                "OFFLINE_BOOTSTRAP_BLOCKED: historical supersession record exists; no replay"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

// Never begin with a queued legacy mutation, signed request, torn activation,
// retained historical proof, or earlier first-use intent.
fn require_offline_bootstrap_quiescent(install_root: &Path) -> Result<(), String> {
    require_offline_bootstrap_other_pending_absent(install_root)?;
    require_no_historical_bootstrap_supersession(install_root)?;
    let path = install_root.join("offline-bootstrap-intent-v1");
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(
            "OFFLINE_BOOTSTRAP_BLOCKED: unresolved existing operation at offline-bootstrap-intent-v1; no replay"
                .to_owned(),
        ),
        Err(_) => Err(
            "OFFLINE_BOOTSTRAP_BLOCKED: pending state cannot be read at offline-bootstrap-intent-v1"
                .to_owned(),
        ),
    }
}

// The archiving step is an explicitly approved, non-replaying supersession
// of a historical UNKNOWN, not a claim that the old operation was VERIFIED.
// It is performed only after the same local read-only owner proof and exact
// candidate preflight as the new transaction. Archive is immutable by
// deterministic digest and never silently overwritten or removed.
fn archive_retained_offline_bootstrap_intent(
    install_root: &Path,
    approval: &RetainedOfflineBootstrapSupersession,
    observed_current: &str,
) -> Result<(), String> {
    require_offline_bootstrap_other_pending_absent(install_root)?;
    let verified =
        inspect_retained_offline_bootstrap_intent(install_root, approval, observed_current)?;
    let archive = install_root.join(format!(
        "offline-bootstrap-intent-v1.historical-{}",
        verified.sha256
    ));
    match fs::symlink_metadata(&archive) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(
                "OFFLINE_BOOTSTRAP_SUPERSESSION_ARCHIVE_ALREADY_EXISTS_NO_REPLAY".to_owned(),
            );
        }
        Err(_) => return Err("OFFLINE_BOOTSTRAP_SUPERSESSION_ARCHIVE_STATE_UNPROVEN".to_owned()),
    }
    let original = install_root.join("offline-bootstrap-intent-v1");
    // Create the archive as a hard link FIRST. Unlike a rename, hard_link
    // refuses to overwrite an existing destination atomically. Until the
    // old name is removed, a crash leaves the original BEGIN in place.
    // After removal, the archive itself is a durable fail-closed witness.
    fs::hard_link(&original, &archive).map_err(|_| {
        "OFFLINE_BOOTSTRAP_UNKNOWN: create-only historical archive failed; no replay".to_owned()
    })?;
    let readback = fs::read(&archive).map_err(|_| {
        "OFFLINE_BOOTSTRAP_UNKNOWN: archived intent unreadable; no replay".to_owned()
    })?;
    if readback != verified.original_bytes {
        return Err("OFFLINE_BOOTSTRAP_UNKNOWN: archived intent changed; no replay".to_owned());
    }
    // Flush the same immutable contents before unlinking the old name.
    // On Windows FlushFileBuffers needs a writable file handle.
    OpenOptions::new()
        .write(true)
        .open(&archive)
        .and_then(|file| file.sync_all())
        .map_err(|_| {
            "OFFLINE_BOOTSTRAP_UNKNOWN: archived intent durability unproven; no replay".to_owned()
        })?;
    fs::remove_file(&original).map_err(|_| {
        "OFFLINE_BOOTSTRAP_UNKNOWN: historical BEGIN unlink failed; no replay".to_owned()
    })?;
    match fs::symlink_metadata(&original) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        _ => return Err("OFFLINE_BOOTSTRAP_UNKNOWN: old BEGIN not absent; no replay".to_owned()),
    }
    // We deliberately DO NOT require full quiescence here: the historical
    // archive must stay visible so that a crash before the fresh create_new
    // BEGIN is blocked on every future unpinned bootstrap attempt.
    require_offline_bootstrap_other_pending_absent(install_root)?;
    Ok(())
}

// After BEGIN a native HostIntent and any old mutation are forbidden until
// the SAME SYSTEM task has been retargeted to the new signed-capable owner.
fn require_offline_bootstrap_request_queue_empty(install_root: &Path) -> Result<(), String> {
    for relative in [
        "exchange/requests/request.pb",
        "exchange/requests/host-intent.pb",
    ] {
        match fs::symlink_metadata(install_root.join(relative)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(format!(
                    "OFFLINE_BOOTSTRAP_UNKNOWN: request appeared during disabled handoff at {relative}; no replay"
                ));
            }
            Err(_) => {
                return Err(format!(
                    "OFFLINE_BOOTSTRAP_UNKNOWN: request state unreadable at {relative}; no replay"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn change_offline_bootstrap_task_enabled(enable: bool) -> Result<(), String> {
    let flag = if enable { "/ENABLE" } else { "/DISABLE" };
    let status = Command::new("schtasks.exe")
        .args(["/Change", "/TN", PRIVILEGED_TASK_NAME, flag])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_UNKNOWN: task state change failed: {err}; no replay")
        })?;
    if !status.success() {
        return Err(format!(
            "OFFLINE_BOOTSTRAP_UNKNOWN: task state change exit={}; no replay",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn require_no_running_legacy_dispatcher(legacy_console: &str) -> Result<(), String> {
    // Disabled does not terminate already-running Task Scheduler instances.
    // A local elevated process inventory must prove the outgoing console is
    // gone before the first installer or SCM effect. No polling or blind sleep.
    let proof = r#"
$ErrorActionPreference = 'Stop'
foreach ($process in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='edge-console.exe'" -ErrorAction Stop)) {
    if (-not $process.ExecutablePath -or
        [string]$process.ExecutablePath -ieq $env:EDGE_BOOTSTRAP_OLD_CONSOLE) {
        throw 'legacy dispatcher active or executable identity unreadable'
    }
}
"#;
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", proof])
        .env("EDGE_BOOTSTRAP_OLD_CONSOLE", legacy_console)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_UNKNOWN: legacy process proof failed: {err}; no replay")
        })?;
    if !status.success() {
        return Err("OFFLINE_BOOTSTRAP_UNKNOWN: legacy dispatcher quiescence unproven; task remains disabled; no replay".to_owned());
    }
    Ok(())
}

fn offline_bootstrap_identifiers_valid(revision: &str, digest: &str) -> bool {
    revision.len() == 40
        && digest.len() == 64
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(windows)]
fn require_explicit_local_administrator_first_use() -> Result<(), String> {
    // Use the actual kernel token, not a PowerShell child or SCM DACL.
    // A NetworkService runner cannot spoof a local elevated Administrator.
    edge_shared_types::host_journal::require_windows_local_administrator_first_use()
        .map_err(str::to_owned)
}

#[cfg(windows)]
fn read_only_windows_first_use_source(
    install_root: &Path,
    approval: Option<&RetainedOfflineBootstrapSupersession>,
    next_revision: &str,
    next_target: &str,
) -> Result<(WindowsActivationState, bool), String> {
    // A purely observational reuse of the SAME strict native pre-BEGIN
    // owner, old-doctor, task and pending-state guards as offline bootstrap.
    // No file creation, task execution, SCM change or key enrollment.
    require_explicit_local_administrator_first_use()?;
    if install_root != Path::new(r"C:\sing-box") {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: unexpected Windows root".to_owned());
    }
    let before = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    require_offline_windows_owner(install_root, &before)?;
    let old_doctor = Command::new(&before.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: old doctor missing: {err}"))?;
    let old_readout = String::from_utf8_lossy(&old_doctor.stdout);
    require_offline_bootstrap_supported_source(&old_readout)?;
    let previously_disabled = if let Some(approval) = approval {
        require_offline_bootstrap_other_pending_absent(install_root)?;
        let retained = inspect_retained_offline_bootstrap_intent(
            install_root,
            approval,
            &before.release_set_sha256,
        )?;
        if verify_offline_bootstrap_dispatcher(&before.console_path, "Ready").is_ok() {
            false
        } else {
            // A compensated UNKNOWN handoff can leave the exact previous
            // SYSTEM task Disabled. Accept ONLY a new, distinct canonical
            // release (never the already-attempted operation), with the same
            // exact task principal/action and pinned BEGIN readback.
            verify_offline_bootstrap_dispatcher(&before.console_path, "Disabled")?;
            require_distinct_offline_bootstrap_successor(
                &retained,
                &before.release_set_sha256,
                next_revision,
                next_target,
            )?;
            true
        }
    } else {
        require_offline_bootstrap_quiescent(install_root)?;
        verify_offline_bootstrap_dispatcher(&before.console_path, "Ready")?;
        false
    };
    require_no_running_legacy_dispatcher(&before.console_path)?;
    Ok((before, previously_disabled))
}

/// The already registered SYSTEM identity is immutable across an approved
/// offline release update. Only the still-pending TRUST request can be moved
/// to the new release, and only while the old task is disabled.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExistingIdentityHandoff {
    TrustNotRequested,
    TrustPending,
    TrustRecorded,
}

#[cfg(windows)]
fn classify_completed_identity_for_handoff(
    stage: &str,
) -> Result<Option<ExistingIdentityHandoff>, String> {
    match stage {
        "RECEIPT_READY_TRUST_NOT_REQUESTED" => {
            Ok(Some(ExistingIdentityHandoff::TrustNotRequested))
        }
        "AWAITING_GIT_AUTHORITY_OR_SYSTEM" => {
            Ok(Some(ExistingIdentityHandoff::TrustPending))
        }
        "TRUST_RECORDED_UNVERIFIED" => Ok(Some(ExistingIdentityHandoff::TrustRecorded)),
        "SYSTEM_PENDING" => Ok(None),
        "NOT_STARTED" => Err("HOST_WINDOWS_FIRST_USE_IDENTITY_SLOT_INCONSISTENT".into()),
        _ => Err("HOST_WINDOWS_FIRST_USE_UPGRADE_STAGE_INVALID".into()),
    }
}

#[cfg(windows)]
fn offline_bootstrap_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
    supersession: Option<&RetainedOfflineBootstrapSupersession>,
    enroll_receipt: bool,
) -> Result<(String, String, Option<String>), String> {
    // One operator-authorized local admin invocation from the independently
    // verified NEW immutable console. The installed legacy SYSTEM dispatcher
    // never sees a wire operation it does not understand.
    require_explicit_local_administrator_first_use()?;
    if install_root != Path::new(r"C:\sing-box") {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: unexpected Windows root".to_owned());
    }
    let revision = request
        .accepted_revision
        .as_deref()
        .ok_or_else(|| "OFFLINE_BOOTSTRAP_BLOCKED: accepted revision missing".to_owned())?;
    let target = request
        .release_set_sha256
        .as_deref()
        .ok_or_else(|| "OFFLINE_BOOTSTRAP_BLOCKED: ReleaseSet missing".to_owned())?;
    if !offline_bootstrap_identifiers_valid(revision, target) {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: malformed exact revision or digest".to_owned());
    }
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32 {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: canonical target is not ProxyOnly".to_owned());
    }
    let (before, previously_disabled) =
        read_only_windows_first_use_source(install_root, supersession, revision, target)?;
    // One-shot approved offline bootstrap must NOT generate a second Ed25519
    // identity on an already-enrolled physical Windows host. Determine its
    // exact prior stage before the irreversible native BEGIN.
    let mut existing_identity_stage = None;
    let pending_identity_rebind = if enroll_receipt {
        match windows_receipt_enrollment::preflight_fresh_identity_slot(install_root) {
            Ok(()) => None,
            Err(refused) if refused == "HOST_WINDOWS_RECEIPT_ENROLL_SLOT_NOT_EMPTY_NO_REKEY" => {
                let stage = windows_receipt_enrollment::read_only_first_use_stage(install_root)?;
                if let Some(existing) = classify_completed_identity_for_handoff(stage)? {
                    windows_receipt_enrollment::verify_existing_receipt_identity_slot(
                        install_root,
                    )?;
                    if existing == ExistingIdentityHandoff::TrustPending {
                        windows_trust_enrollment::preflight_pending_trust_handoff(
                            install_root,
                            &before,
                        )?;
                    }
                    existing_identity_stage = Some(existing);
                    None
                } else {
                    if supersession.is_none() {
                        return Err(
                            "HOST_WINDOWS_FIRST_USE_REBIND_EXPLICIT_BEGIN_APPROVAL_REQUIRED"
                                .into(),
                        );
                    }
                    Some(windows_receipt_enrollment::preflight_pending_rebind(
                        install_root,
                        &before,
                    )?)
                }
            }
            Err(reason) => return Err(reason),
        }
    } else {
        // Do not abandon any pending first-use request just to replace code.
        for marker in ["receipt-enrollment.pb", "trust-enrollment.pb"] {
            match fs::symlink_metadata(install_root.join("native-host").join(marker)) {
                Ok(_) => {
                    return Err(
                        "HOST_WINDOWS_FIRST_USE_PENDING_REQUIRES_EXPLICIT_APPROVED_REBIND".into(),
                    );
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err("HOST_WINDOWS_FIRST_USE_PENDING_METADATA_UNPROVEN_NO_REPLAY".into());
                }
            }
        }
        None
    };
    if before.release_set_sha256 == target {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: exact distinct legacy release required".to_owned());
    }

    let candidate = install_root.join("releases").join(target);
    let console = candidate.join("bin").join("edge-console.exe");
    let current_exe = env::current_exe().map_err(|err| err.to_string())?;
    if current_exe.canonicalize().map_err(|err| err.to_string())?
        != console.canonicalize().map_err(|err| err.to_string())?
    {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: not exact verified target console".to_owned());
    }
    let stage_installer = candidate
        .join("bootstrap")
        .join("install-windows-release.ps1");
    if !stage_installer.is_file() {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: target installer missing".to_owned());
    }
    // The native verifier checks manifest, ZIP and ALL exact target binaries.
    // Never accept a caller-provided executable/installer or download command.
    let verification = Command::new(candidate.join("bin").join("edge-release-set.exe"))
        .args(["verify-windows", "--input"])
        .arg(candidate.join("release-set.pb"))
        .arg("--sha256-file")
        .arg(candidate.join("release-set.pb.sha256"))
        .arg("--windows-artifact")
        .arg(candidate.join("edge-platform-windows.zip"))
        .arg("--windows-controller")
        .arg(candidate.join("bin").join("edge-controller.exe"))
        .arg("--windows-console")
        .arg(&console)
        .arg("--windows-diagnostic")
        .arg(candidate.join("bin").join("edge-diagnostic.exe"))
        .arg("--windows-sing-box")
        .arg(candidate.join("bin").join("sing-box.exe"))
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: verifier unavailable: {err}"))?;
    if !verification.status.success() {
        return Err(
            "OFFLINE_BOOTSTRAP_BLOCKED: target ReleaseSet or binary verification failed".to_owned(),
        );
    }
    require_offline_bootstrap_installer_archive_identity(
        &candidate.join("edge-platform-windows.zip"),
        &stage_installer,
    )?;

    // Only an elevated local Windows admin can open CHANGE_CONFIG on this
    // SCM owner. Prove permission before creating the non-replayable intent.
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: SCM unavailable: {err}"))?;
    let _authorized_service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_BLOCKED: local admin authorization absent: {err}")
        })?;

    // The accepted protected main, immutable release tag, merge-parent source
    // tree, and target package are verified by the existing installer BEFORE
    // any SCM, current.pb or dispatcher mutation.
    let root = install_root
        .to_str()
        .ok_or_else(|| "OFFLINE_BOOTSTRAP_BLOCKED: invalid Windows root".to_owned())?;
    // The canonical offline installer requires PowerShell 7 -NoProxy.
    // Reject an unavailable pwsh before its irreversible BEGIN, never fall
    // back to Windows PowerShell 5.1 or the broken ambient proxy path.
    let mut preflight = Command::new("pwsh.exe");
    preflight
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&stage_installer)
        .args([
            "-AcceptedRevision",
            revision,
            "-ReleaseSetSha256",
            target,
            "-InstallRoot",
            root,
            "-Offline",
            "-StageOnly",
        ]);
    if let Some(approval) = supersession {
        preflight
            .arg("-RetainedIntentSha256")
            .arg(&approval.expected_intent_sha256)
            .arg("-ExpectedCurrentReleaseSetSha256")
            .arg(&approval.expected_current_release_set_sha256);
    }
    let preflight = preflight.stdin(Stdio::null()).output().map_err(|err| {
        format!("OFFLINE_BOOTSTRAP_BLOCKED: release preflight unavailable: {err}")
    })?;
    if !preflight.status.success() {
        return Err(format!(
            "OFFLINE_BOOTSTRAP_BLOCKED: accepted release preflight failed: {}",
            bounded_privileged_child_evidence(&preflight.stdout, &preflight.stderr)
        ));
    }
    require_offline_windows_owner(install_root, &before)?;

    require_offline_bootstrap_installer_archive_identity(
        &candidate.join("edge-platform-windows.zip"),
        &stage_installer,
    )?;

    verify_offline_bootstrap_dispatcher(
        &before.console_path,
        if previously_disabled {
            "Disabled"
        } else {
            "Ready"
        },
    )?;
    require_no_running_legacy_dispatcher(&before.console_path)?;
    if let Some(approval) = supersession {
        // The prior BEGIN remains UNKNOWN_NO_REPLAY. After an independent
        // explicit local Administrator decision, preserve its exact bytes
        // in a deterministic immutable archive; never claim old SUCCESS.
        archive_retained_offline_bootstrap_intent(
            install_root,
            approval,
            &before.release_set_sha256,
        )?;
    } else {
        require_offline_bootstrap_quiescent(install_root)?;
    }

    // Create exactly one durable BEGIN before the first SCM mutation.
    // Never replay after a lost result, even if the old release was restored.
    let intent = install_root.join("offline-bootstrap-intent-v1");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&intent)
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_BLOCKED: intent already exists or cannot be created: {err}")
        })?;
    let marker = format!(
        "schema=sing-box.windows-offline-bootstrap/v1\nfrom={}\nto={target}\naccepted_revision={revision}\n",
        before.release_set_sha256,
    );
    file.write_all(marker.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_UNKNOWN: durable intent failure: {err}; do not replay")
        })?;
    drop(file);

    // A legacy LocalSystem task that polls an unsigned, NetworkService-writable
    // request path MUST NOT remain scheduled while authority is being replaced.
    // Disable the SAME task after durable BEGIN and prove no legacy console is
    // still running. On any failure leave it disabled: UNKNOWN_NO_REPLAY.
    change_offline_bootstrap_task_enabled(false)?;
    verify_offline_bootstrap_dispatcher(&before.console_path, "Disabled")?;
    require_no_running_legacy_dispatcher(&before.console_path)?;
    require_offline_bootstrap_request_queue_empty(install_root)?;

    let activated = offline_activate_privileged_release_with_installer(
        install_root,
        request,
        Some(&stage_installer),
    )?;
    // Both predecessor intents are still durable and unconsumed. Preserve
    // their exact bytes and write the new exact-release typed pair only while
    // the ORIGINAL SYSTEM task is Disabled, before it can observe either
    // intermediate state. A failure is UNKNOWN/NO-REPLAY, never an implicit
    // instruction to generate another key.
    if let Some(ref pending) = pending_identity_rebind {
        windows_receipt_enrollment::rebind_pending_after_offline_handoff(
            install_root,
            pending,
            &before,
        )
        .map_err(|reason| {
            format!("OFFLINE_BOOTSTRAP_PENDING_IDENTITY_REBIND_UNKNOWN_NO_REPLAY: {reason}")
        })?;
    }
    if existing_identity_stage == Some(ExistingIdentityHandoff::TrustPending) {
        windows_trust_enrollment::rebind_pending_trust_after_offline_handoff(
            install_root,
            &before,
        )
        .map_err(|reason| {
            format!("OFFLINE_BOOTSTRAP_PENDING_TRUST_REBIND_UNKNOWN_NO_REPLAY: {reason}")
        })?;
    }
    // New main rejects legacy mutation opcodes; re-enable only after the
    // exact immutable signed-capable replacement and pending requests pass
    // readback. If re-enable fails the one-shot marker remains; never replay.
    change_offline_bootstrap_task_enabled(true)?;
    verify_offline_bootstrap_dispatcher(&console.to_string_lossy(), "Ready")?;
    if enroll_receipt && pending_identity_rebind.is_none() {
        match existing_identity_stage {
            None => {
                // First-use: only the existing task generates the private key.
                windows_receipt_enrollment::prepare(install_root).map_err(|reason| {
                    format!("OFFLINE_BOOTSTRAP_IDENTITY_STEP_UNCERTAIN_NO_REPLAY: {reason}; inspect current.pb and native identity status before any new action")
                })?;
                windows_trust_enrollment::prepare_pending(install_root).map_err(|reason| {
                    format!("OFFLINE_BOOTSTRAP_TRUST_INTENT_UNKNOWN_NO_REPLAY: {reason}; preserve the same key and journal")
                })?;
            }
            Some(ExistingIdentityHandoff::TrustNotRequested) => {
                // Completed receipt is historical; request ONLY Worker trust.
                windows_trust_enrollment::prepare(install_root).map_err(|reason| {
                    format!("OFFLINE_BOOTSTRAP_REGISTERED_TRUST_PREPARE_UNKNOWN_NO_REPLAY: {reason}")
                })?;
            }
            Some(ExistingIdentityHandoff::TrustPending)
            | Some(ExistingIdentityHandoff::TrustRecorded) => {
                // Pending marker was re-bound while task was disabled, or
                // previously recorded trust remains byte-for-byte immutable.
            }
        }
    }
    Ok(activated)
}

fn offline_rollback_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    require_exact_immutable_activation_console(install_root)?;
    let (current, previous) = load_previous_release_rollback_pair(install_root)?;
    require_managed_tun_rollback_pair(request, &current, &previous)?;
    require_offline_windows_owner(install_root, &current)?;
    let current_bytes = fs::read(install_root.join("current.pb")).map_err(|err| err.to_string())?;
    let previous_bytes =
        fs::read(install_root.join("previous.pb")).map_err(|err| err.to_string())?;
    offline_retarget_controller_service(install_root, &current, &previous)?;
    if let Err(err) = write_atomic(&install_root.join("current.pb"), &previous_bytes)
        .map_err(|err| err.to_string())
        .and_then(|_| sync_stable_windows_release_tools(install_root, &previous))
        .and_then(|_| retarget_privileged_task(install_root, &previous.console_path))
    {
        let restored = restore_offline_release(
            install_root,
            &current,
            &current_bytes,
            &Some(previous_bytes),
            Some(&previous),
        );
        return Err(format!(
            "offline rollback handoff failed: {err}; compensation={restored:?}; do not retry blindly"
        ));
    }
    require_offline_windows_owner(install_root, &previous)?;
    Ok((
        "OFFLINE_PREVIOUS_RELEASE_RESTORED".to_owned(),
        "exact previous ReleaseSet restored with stopped SCM; no service or TUN started".to_owned(),
        Some(previous.release_set_sha256),
    ))
}

fn load_previous_release_rollback_pair(
    install_root: &Path,
) -> Result<(WindowsActivationState, WindowsActivationState), String> {
    let current_path = install_root.join("current.pb");
    let previous_path = install_root.join("previous.pb");
    if !previous_path.is_file() {
        return Err(
            "previous.pb is absent; bounded Windows ReleaseSet rollback has no target".to_owned(),
        );
    }

    let current = load_verified_activation_path(install_root, &current_path, "current.pb")
        .map_err(|err| err.to_string())?;
    let previous = load_verified_activation_path(install_root, &previous_path, "previous.pb")
        .map_err(|err| err.to_string())?;
    if current.release_set_sha256 == previous.release_set_sha256 {
        return Err("current.pb and previous.pb identify the same ReleaseSet".to_owned());
    }
    Ok((current, previous))
}

fn sync_stable_windows_release_tools(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    let bin_dir = install_root.join("bin");
    fs::create_dir_all(&bin_dir)
        .map_err(|err| format!("failed to prepare stable Windows binary directory: {err}"))?;

    for (source, target_name, label) in [
        (&activation.console_path, "edge-console.exe", "console"),
        (
            &activation.diagnostic_path,
            "edge-diagnostic.exe",
            "diagnostic",
        ),
    ] {
        let bytes = fs::read(source).map_err(|err| {
            format!("failed to read exact {label} for stable rollback boundary: {err}")
        })?;
        let target = bin_dir.join(target_name);
        write_atomic(&target, &bytes)
            .map_err(|err| format!("failed to refresh stable Windows {label}: {err}"))?;
        let observed = fs::read(&target)
            .map_err(|err| format!("failed to verify stable Windows {label}: {err}"))?;
        if observed != bytes {
            return Err(format!(
                "stable Windows {label} does not match the exact activation after refresh"
            ));
        }
    }
    Ok(())
}

// An explicit previous-release rollback is a ManagedTun-to-ManagedTun release
// handoff, never a general permission to remove TUN or use an unknown target.
// The submitted exact authority pair is checked again by the privileged owner
// BEFORE sing-box is stopped; a changed previous.pb fails without mutation.
fn require_managed_tun_rollback_pair(
    request: &WindowsPrivilegedRequest,
    current: &WindowsActivationState,
    previous: &WindowsActivationState,
) -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode != WindowsDatapathMode::ManagedTun as i32 {
        return Err("rollback refuses a non-ManagedTun accepted desired mode".to_owned());
    }
    require_exact_rollback_authority_pair(request, current, previous)
}

fn require_exact_rollback_authority_pair(
    request: &WindowsPrivilegedRequest,
    current: &WindowsActivationState,
    previous: &WindowsActivationState,
) -> Result<(), String> {
    if current.release_set_sha256 == previous.release_set_sha256 {
        return Err("rollback refuses identical current and previous release".to_owned());
    }
    if request.accepted_revision.as_deref() != Some(current.source_revision.as_str())
        || request.release_set_sha256.as_deref() != Some(previous.release_set_sha256.as_str())
    {
        return Err(
            "rollback authority changed since exact submitted current/previous proof".to_owned(),
        );
    }
    Ok(())
}

fn rollback_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    require_exact_immutable_activation_console(install_root)?;
    let current_path = install_root.join("current.pb");
    let previous_path = install_root.join("previous.pb");
    let (current, previous) = load_previous_release_rollback_pair(install_root)?;
    require_managed_tun_rollback_pair(request, &current, &previous)?;

    let managed_config = local_singbox_config_path(install_root);
    stop_runtime_process(&managed_config, true)
        .map_err(|err| format!("failed to stop exact managed runtime before rollback: {err}"))?;

    let current_bytes = fs::read(&current_path)
        .map_err(|err| format!("failed to snapshot current.pb before rollback: {err}"))?;
    let previous_bytes = fs::read(&previous_path)
        .map_err(|err| format!("failed to snapshot previous.pb before rollback: {err}"))?;

    if let Err(err) = write_atomic(&current_path, &previous_bytes) {
        let _ = write_atomic(&current_path, &current_bytes);
        return Err(format!(
            "failed to activate exact previous Windows authority; original current activation restored: {err}"
        ));
    }

    let handoff = (|| -> Result<(), String> {
        sync_stable_windows_release_tools(install_root, &previous)?;
        reconcile_activation_owner(install_root, &previous)
    })();
    if let Err(err) = handoff {
        let pointer_restore = write_atomic(&current_path, &current_bytes);
        let owner_restore = sync_stable_windows_release_tools(install_root, &current)
            .and_then(|_| reconcile_activation_owner(install_root, &current));
        return Err(format!(
            "previous ReleaseSet activation handoff failed: {err}; pointer_restore={pointer_restore:?}; owner_restore={owner_restore:?}"
        ));
    }

    let verified = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    if verified.release_set_sha256 != previous.release_set_sha256 {
        return Err(
            "post-rollback activation verification did not match exact previous.pb".to_owned(),
        );
    }

    Ok((
        "PREVIOUS_RELEASE_ROLLED_BACK".to_owned(),
        "exact previous ReleaseSet restored locally without swapping rollback authority; repeated rollback is fail-closed because current.pb now equals previous.pb"
            .to_owned(),
        Some(verified.release_set_sha256),
    ))
}

fn reconcile_activation_owner(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    retarget_privileged_task(install_root, &activation.console_path)?;
    #[cfg(windows)]
    converge_controller_service_with_activation_console(install_root, activation)?;
    Ok(())
}

fn retarget_privileged_task(install_root: &Path, console_path: &str) -> Result<(), String> {
    let action = format!(
        "\"{}\" privileged-dispatch --install-root \"{}\"",
        console_path,
        install_root.display()
    );
    let status = Command::new("schtasks.exe")
        .args(["/Change", "/TN", PRIVILEGED_TASK_NAME, "/TR", &action])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to retarget privileged Windows task: {err}"))?;
    if !status.success() {
        return Err(format!(
            "failed to retarget privileged Windows task, exit code {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn print_privileged_result(result: &WindowsPrivilegedResult) {
    println!("status={}", if result.success { "PASS" } else { "FAIL" });
    println!("request_id={}", result.request_id);
    println!("code={}", result.code);
    println!("detail={}", result.detail);
    if let Some(release) = result.active_release_set_sha256.as_deref() {
        println!("active_release_set_sha256={release}");
    }
}

fn submit_windows_credential_transition(
    install_root: &Path,
    action: CredentialTransitionAction,
) -> Result<WindowsPrivilegedResult, String> {
    submit_privileged_request(
        install_root,
        WindowsPrivilegedRequest {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            request_id: new_privileged_request_id().map_err(|err| err.to_string())?,
            operation: WindowsPrivilegedOperation::CredentialTransition as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: Some(action as i32),
            initial_commit_intent_sha256: None,
            initial_commit_slot: None,
            initial_recovery_intent_sha256: None,
            initial_candidate_sha256: None,
            existing_join_vm_candidate_sha256: None,
            existing_join_windows_active_sha256: None,
            existing_join_windows_candidate_sha256: None,
            existing_join_intent_sha256: None,
            existing_join_slot: None,
        },
    )
    .map_err(|err| err.to_string())
}

async fn verify_windows_tunnel_route(
    endpoint: &str,
    route: &str,
    expected_warp: &str,
) -> Result<(), String> {
    let response = set_selector(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP, route)
        .await
        .map_err(|err| err.to_string())?;
    if !response.success {
        return Err(format!("selector update failed for route {route}"));
    }

    let mut last_unavailable = "trace unavailable without provider detail".to_owned();
    for attempt in 1..=WINDOWS_TRACE_REOBSERVE_ATTEMPTS {
        match fetch_trace(endpoint.to_owned()).await {
            Ok(trace) if trace.available && trace.ip.is_some() => {
                if trace.warp.as_deref() != Some(expected_warp) {
                    return Err(format!(
                        "route {route} expected Cloudflare warp={expected_warp}, observed {:?}",
                        trace.warp
                    ));
                }
                return Ok(());
            }
            Ok(trace) => {
                last_unavailable = trace
                    .note
                    .unwrap_or_else(|| "trace unavailable without provider detail".to_owned());
            }
            Err(err) => {
                last_unavailable = format!("controller trace RPC failed: {err}");
            }
        }

        if attempt < WINDOWS_TRACE_REOBSERVE_ATTEMPTS {
            tokio::time::sleep(WINDOWS_TRACE_REOBSERVE_DELAY).await;
        }
    }

    Err(format!(
        "Cloudflare trace is unavailable for route {route} after {WINDOWS_TRACE_REOBSERVE_ATTEMPTS} bounded observations: {last_unavailable}"
    ))
}

// Always run the restore after a bounded route check, even if either trace fails.
// This is in-process compensation, not a durable promise across forced termination.
async fn verify_routes_with_restore<F, Fut, R, RestoreFut>(
    original: String,
    mut verify: F,
    restore: R,
) -> Result<(), String>
where
    F: FnMut(&'static str, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
    R: FnOnce(String) -> RestoreFut,
    RestoreFut: std::future::Future<Output = Result<(), String>>,
{
    let result = async {
        verify("auto-direct-tunnel", "off").await?;
        verify("auto-warp-tunnel", "on").await
    }
    .await;
    // Explicitly compensate after either success or failure of the checks.
    let restored = restore(original).await;
    match (result, restored) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(verification_error), Ok(())) => Err(format!(
            "Windows tunnel verification failed; original selector restored: {verification_error}"
        )),
        (Ok(()), Err(restore_error)) => Err(format!(
            "Windows tunnel checks passed but original selector restoration is unverified: {restore_error}"
        )),
        (Err(verification_error), Err(restore_error)) => Err(format!(
            "Windows tunnel verification failed: {verification_error}; original selector restoration is unverified: {restore_error}"
        )),
    }
}

async fn restore_windows_tunnel_selector(endpoint: &str, original: &str) -> Result<(), String> {
    let restore = set_selector(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP, original)
        .await
        .map_err(|err| err.to_string())?;
    if !restore.success {
        return Err(format!("selector restore RPC rejected route {original}"));
    }
    let observed = fetch_selector_state(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP)
        .await
        .map_err(|err| err.to_string())?;
    if observed.observed_main_route.as_deref() != Some(original) {
        return Err(format!(
            "selector restore read-back mismatch: expected {original}, observed {:?}",
            observed.observed_main_route
        ));
    }
    Ok(())
}

fn observed_restore_route(selector: SelectorState) -> Result<String, String> {
    // Policy is NOT a safe fallback if the live current selector is unknown.
    selector.observed_main_route.ok_or_else(|| {
        "Windows selector has no observed restorable route; no mutation made".to_owned()
    })
}

async fn verify_windows_tunnels(endpoint: &str) -> Result<(), String> {
    let selector = fetch_selector_state(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP)
        .await
        .map_err(|err| err.to_string())?;
    let original = observed_restore_route(selector)?;
    verify_routes_with_restore(
        original,
        |route, expected_warp| verify_windows_tunnel_route(endpoint, route, expected_warp),
        |original| async move { restore_windows_tunnel_selector(endpoint, &original).await },
    )
    .await
}

async fn restart_and_verify_windows_tunnels(endpoint: &str) -> Result<(), String> {
    let restart = restart_local(endpoint.to_owned())
        .await
        .map_err(|err| err.to_string())?;
    if !restart.success {
        // A failed restart is already an uncertain runtime state. Do not issue
        // an unrelated stop as "cleanup" on a shared Windows network host.
        return Err(format!(
            "Windows local runtime restart failed; no automatic stop attempted: {}",
            restart.note
        ));
    }
    verify_windows_tunnels(endpoint).await
}

fn verify_stage2_isolated_prerequisites(install_root: &Path) -> Result<(), String> {
    let managed_state = windows_runtime_state_path(install_root);
    if managed_state.exists() {
        return Err(format!(
            "Stage 2 requires no pre-existing managed Windows runtime state at {}",
            managed_state.display()
        ));
    }
    let managed_config = local_singbox_config_path(install_root);
    if managed_config.exists() {
        return Err(format!(
            "Stage 2 requires no pre-existing managed Windows runtime config at {}",
            managed_config.display()
        ));
    }

    let endpoints = [
        (
            "desktop proxy",
            format!("127.0.0.1:{STAGE2_DESKTOP_PROXY_PORT}"),
        ),
        ("WSL proxy", format!("0.0.0.0:{STAGE2_WSL_PROXY_PORT}")),
        ("Clash API", format!("127.0.0.1:{STAGE2_CLASH_API_PORT}")),
    ];
    let mut listeners = Vec::with_capacity(endpoints.len());
    for (name, endpoint) in endpoints {
        let listener = TcpListener::bind(&endpoint)
            .map_err(|err| format!("Stage 2 {name} endpoint {endpoint} is unavailable: {err}"))?;
        listeners.push(listener);
    }
    drop(listeners);
    Ok(())
}

async fn run_windows_credential_transition(
    install_root: &Path,
    action: CredentialTransitionAction,
) -> Result<(), String> {
    let endpoint = cli::controller_endpoint(None);
    let result = submit_windows_credential_transition(install_root, action)?;
    print_privileged_result(&result);
    finish_privileged_result(&result).map_err(|err| err.to_string())?;

    if !matches!(
        action,
        CredentialTransitionAction::ApplyCandidate | CredentialTransitionAction::ApplyActive
    ) {
        return Ok(());
    }

    restart_and_verify_windows_tunnels(&endpoint).await?;

    println!("credential_transition_functional=PASS");
    println!("credential_transition_direct=PASS");
    println!("credential_transition_warp=PASS");
    Ok(())
}

fn finish_privileged_result(
    result: &WindowsPrivilegedResult,
) -> Result<(), Box<dyn std::error::Error>> {
    if result.success {
        Ok(())
    } else {
        Err(format!("privileged Windows operation failed: {}", result.code).into())
    }
}

fn installed_root_from_console() -> Result<PathBuf, Box<dyn std::error::Error>> {
    installed_root_from_executable(&env::current_exe()?)
}

fn installed_root_from_executable(
    executable: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let bin_dir = executable
        .parent()
        .ok_or("failed to resolve edge-console binary directory")?;
    if bin_dir.file_name().and_then(|value| value.to_str()) != Some("bin") {
        return Err(
            "edge-console installed startup requires <install-root>\\releases\\<release-set>\\bin\\edge-console.exe"
                .into(),
        );
    }
    let release_dir = bin_dir
        .parent()
        .ok_or("failed to resolve immutable release directory")?;
    let releases_dir = release_dir
        .parent()
        .ok_or("failed to resolve immutable releases root")?;
    if releases_dir.file_name().and_then(|value| value.to_str()) != Some("releases") {
        return Err(
            "edge-console installed startup requires <install-root>\\releases\\<release-set>\\bin\\edge-console.exe"
                .into(),
        );
    }
    let root = releases_dir
        .parent()
        .ok_or("failed to resolve edge-platform install root")?
        .to_path_buf();
    Ok(root)
}

fn load_verified_activation(
    install_root: &Path,
) -> Result<WindowsActivationState, Box<dyn std::error::Error>> {
    load_verified_activation_path(install_root, &install_root.join("current.pb"), "current.pb")
}

fn load_verified_activation_path(
    install_root: &Path,
    state_path: &Path,
    label: &str,
) -> Result<WindowsActivationState, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(state_path)?;
    let state = decode_windows_activation_state(&bytes)?;
    verify_windows_activation_files(&state)?;

    let releases_root = install_root.join("releases").canonicalize()?;
    let release_dir = PathBuf::from(&state.release_dir).canonicalize()?;
    let controller = PathBuf::from(&state.controller_path).canonicalize()?;
    if !release_dir.starts_with(&releases_root) {
        return Err(format!("{label} release_dir is outside the immutable releases root").into());
    }
    if !controller.starts_with(&release_dir) {
        return Err(
            format!("{label} controller_path is outside its immutable release directory").into(),
        );
    }
    Ok(state)
}

fn parse_loopback_addr(endpoint: &str) -> Option<SocketAddr> {
    let value = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    let addr: SocketAddr = value.parse().ok()?;
    if addr.ip().is_loopback() {
        Some(addr)
    } else {
        None
    }
}

fn controller_is_listening(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

fn ensure_controller_running(endpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    let Some(addr) = parse_loopback_addr(endpoint) else {
        return Ok(());
    };
    if controller_is_listening(addr) {
        return Ok(());
    }

    let install_root = installed_root_from_console()?;
    let _activation = load_verified_activation(&install_root)?;
    Err(format!(
        "SCM-owned EdgePlatformController is not listening on {addr}; edge-console does not own controller startup"
    )
    .into())
}

#[cfg(windows)]
unsafe extern "system" fn service_status_notification_callback(_parameter: *const c_void) {}

#[cfg(windows)]
fn wait_for_service_state(
    service: &Service,
    expected: ServiceState,
    timeout: Duration,
) -> Result<(), String> {
    wait_for_service_state_any(service, &[expected], timeout).map(|_| ())
}

#[cfg(windows)]
fn wait_for_service_state_any(
    service: &Service,
    expected: &[ServiceState],
    timeout: Duration,
) -> Result<ServiceState, String> {
    let notify_mask = match expected {
        [ServiceState::Running] => SERVICE_NOTIFY_RUNNING,
        [ServiceState::Stopped] => SERVICE_NOTIFY_STOPPED,
        [ServiceState::Running, ServiceState::Stopped]
        | [ServiceState::Stopped, ServiceState::Running] => {
            SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED
        }
        _ => {
            return Err(format!(
                "unsupported controller service notification targets: {expected:?}"
            ));
        }
    };

    let initial = service
        .query_status()
        .map_err(|err| format!("failed to query controller service state: {err}"))?;
    if expected.contains(&initial.current_state) {
        return Ok(initial.current_state);
    }

    let monitor_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|err| format!("failed to open SCM for status notification: {err}"))?;
    let monitor = monitor_manager
        .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(|err| format!("failed to open controller service notification handle: {err}"))?;
    let mut notification = SERVICE_NOTIFY_2W {
        dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
        pfnNotifyCallback: Some(service_status_notification_callback),
        ..Default::default()
    };
    let registration = unsafe {
        NotifyServiceStatusChangeW(
            SC_HANDLE(monitor.raw_handle()),
            notify_mask,
            &mut notification,
        )
    };
    if registration != 0 {
        return Err(format!(
            "failed to register controller service status notification: win32={registration}"
        ));
    }

    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let wait_ms = u32::try_from(remaining.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        let wait_result = unsafe { SleepEx(wait_ms, true) };
        if wait_result == 0 {
            break;
        }
        if wait_result != WAIT_IO_COMPLETION.0 {
            drop(monitor);
            return Err(format!(
                "unexpected alertable SCM wait result: {wait_result}"
            ));
        }
        if notification.dwNotificationTriggered & notify_mask.0 == 0 {
            continue;
        }
        if notification.dwNotificationStatus != 0 {
            drop(monitor);
            return Err(format!(
                "controller service status notification failed: win32={}",
                notification.dwNotificationStatus
            ));
        }

        let observed = monitor
            .query_status()
            .map_err(|err| format!("failed to query notified controller service state: {err}"))?;
        if expected.contains(&observed.current_state) {
            return Ok(observed.current_state);
        }
        drop(monitor);
        return Err(format!(
            "controller service notification targeted {expected:?} but observed {:?}",
            observed.current_state
        ));
    }

    drop(monitor);
    let observed = service.query_status().map_err(|err| {
        format!("failed to query controller service after notification timeout: {err}")
    })?;
    Err(format!(
        "controller service did not reach {expected:?} within {} seconds; observed {:?}",
        timeout.as_secs(),
        observed.current_state
    ))
}

#[cfg(windows)]
fn run_icacls(path: &Path, arguments: &[&str]) -> Result<(), String> {
    let mut command = Command::new("icacls.exe");
    command.arg(path);
    command.args(arguments);
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to start icacls for {}: {err}", path.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "icacls failed for {} with exit code {}",
            path.display(),
            status.code().unwrap_or(-1)
        ))
    }
}

#[cfg(windows)]
fn protect_controller_owned_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|err| {
        format!(
            "failed to create controller-owned {}: {err}",
            path.display()
        )
    })?;
    run_icacls(
        path,
        &[
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            r"NT SERVICE\EdgePlatformController:(OI)(CI)M",
            "/Q",
        ],
    )?;
    run_icacls(path, &["/remove:g", "*S-1-5-20", "/Q"])?;
    run_icacls(path, &["/inheritance:r", "/Q"])?;
    let descendants = path.join("*");
    run_icacls(&descendants, &["/reset", "/T", "/Q"])?;
    Ok(())
}

#[cfg(windows)]
fn converge_application_acl(install_root: &Path) -> Result<(), String> {
    for path in [
        install_root.join("state"),
        install_root.join("state").join("secrets"),
        install_root.join("runtime"),
        install_root.join("logs"),
        install_root.join("exchange").join("requests"),
        install_root.join("exchange").join("results"),
    ] {
        fs::create_dir_all(&path)
            .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
    }

    run_icacls(
        install_root,
        &[
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-20:(OI)(CI)RX",
            r"NT SERVICE\EdgePlatformController:(OI)(CI)RX",
            "/Q",
        ],
    )?;
    run_icacls(install_root, &["/inheritance:r", "/Q"])?;
    // Never recursively reset all descendants: native-host may already hold
    // a SYSTEM-only Ed25519 PKCS8 whose sealed DACL must survive routine SCM
    // convergence. The scoped controller directories below and immutable
    // SYSTEM authority paths have independent, explicit ACL convergence.
    for path in [
        install_root.join("state"),
        install_root.join("runtime"),
        install_root.join("logs"),
    ] {
        protect_controller_owned_directory(&path)?;
    }

    run_icacls(
        &install_root.join("exchange").join("requests"),
        &["/grant:r", "*S-1-5-20:(OI)(CI)M", "/Q"],
    )?;
    run_icacls(
        &install_root.join("exchange").join("results"),
        &["/grant:r", "*S-1-5-20:(OI)(CI)RX", "/Q"],
    )?;
    // Same protected SYSTEM root for normal service setup AND offline
    // first-use. One owner, one journal; do not depend on SCM START.
    converge_native_host_acl(install_root)?;
    Ok(())
}

#[cfg(windows)]
fn native_host_acl_paths(install_root: &Path) -> [PathBuf; 2] {
    [
        install_root.join("native-host"),
        install_root.join("native-host").join("journal"),
    ]
}

#[cfg(windows)]
fn existing_native_host_directory_is_safe(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    // Windows junctions/reparse points are not trusted filesystem roots.
    meta.file_type().is_dir() && meta.file_attributes() & 0x400 == 0
}

// Protect the ACTUAL executable chain used by the pre-existing SYSTEM task,
// not only native-host/journal. A user-owned installation root with FullControl
// is not trusted even when the journal's two leaf directories look protected.
// This does not create a second owner or enrollment marker.
#[cfg(windows)]
fn harden_system_authority_path(
    path: &Path,
    recursive: bool,
    directory: bool,
) -> Result<(), String> {
    harden_system_authority_path_for_reader(path, recursive, directory, "S-1-5-20")
}

#[cfg(windows)]
fn harden_system_authority_path_for_reader(
    path: &Path,
    recursive: bool,
    directory: bool,
    reader_sid: &str,
) -> Result<(), String> {
    if reader_sid != "S-1-5-20"
        && (!reader_sid.starts_with("S-1-5-80-")
            || !reader_sid[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-'))
    {
        return Err("HOST_WINDOWS_SYSTEM_AUTHORITY_READER_INVALID".into());
    }
    use std::os::windows::fs::MetadataExt;
    let meta =
        fs::symlink_metadata(path).map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_PATH_MISSING")?;
    if meta.file_type().is_symlink()
        || meta.file_attributes() & 0x400 != 0
        || (directory && !meta.file_type().is_dir())
        || (!directory && !meta.file_type().is_file())
    {
        return Err("HOST_WINDOWS_SYSTEM_AUTHORITY_REPARSE_OR_WRONG_TYPE".into());
    }
    // Hold non-DELETE-sharing Windows HANDLEs for the whole immutable tree
    // throughout the existing icacls operations and final kernel readback.
    // Path-only metadata checks followed by icacls permit a rename/junction
    // swap. Sharing READ/WRITE but NOT DELETE protects each opened pathname
    // against delete/rename without blocking the security descriptor update.
    use std::os::windows::fs::OpenOptionsExt;
    fn guard_tree(path: &Path, recursive: bool, handles: &mut Vec<File>) -> Result<(), String> {
        use std::os::windows::fs::MetadataExt;
        let meta = fs::symlink_metadata(path)
            .map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_TREE_UNREADABLE")?;
        if meta.file_type().is_symlink()
            || meta.file_attributes() & 0x400 != 0
            || (!meta.file_type().is_dir() && !meta.file_type().is_file())
        {
            return Err("HOST_WINDOWS_SYSTEM_AUTHORITY_TREE_REPARSE".into());
        }
        let guard = OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001 | 0x0000_0002) // FILE_SHARE_READ | FILE_SHARE_WRITE; NOT DELETE
            .custom_flags(0x0200_0000 | 0x0020_0000) // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
            .open(path)
            .map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_HANDLE_UNAVAILABLE")?;
        let guarded = guard
            .metadata()
            .map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_HANDLE_METADATA_UNAVAILABLE")?;
        if guarded.file_attributes() & 0x400 != 0
            || guarded.file_type().is_dir() != meta.file_type().is_dir()
        {
            return Err("HOST_WINDOWS_SYSTEM_AUTHORITY_HANDLE_CHANGED".into());
        }
        handles.push(guard);
        if recursive && meta.file_type().is_dir() {
            for entry in
                fs::read_dir(path).map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_TREE_UNREADABLE")?
            {
                let entry = entry.map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_TREE_UNREADABLE")?;
                guard_tree(&entry.path(), true, handles)?;
            }
        }
        Ok(())
    }
    let mut _protected_handles = Vec::new();
    guard_tree(path, recursive, &mut _protected_handles)?;
    let original_owner = edge_shared_types::host_journal::windows_native_acl_owner_sid(path)
        .map_err(str::to_owned)?;
    // Keep existing NetworkService read access; no NetworkService write
    // access is granted to the SYSTEM console, release, current.pb or root.
    let system = if directory {
        "*S-1-5-18:(OI)(CI)F"
    } else {
        "*S-1-5-18:F"
    };
    let admins = if directory {
        "*S-1-5-32-544:(OI)(CI)F"
    } else {
        "*S-1-5-32-544:F"
    };
    let reader = if directory {
        format!("*{reader_sid}:(OI)(CI)RX")
    } else {
        format!("*{reader_sid}:RX")
    };
    run_icacls(path, &["/grant:r", system, admins, &reader, "/Q"])?;
    run_icacls(path, &["/inheritance:r", "/Q"])?;
    if reader_sid != "S-1-5-20" {
        run_icacls(path, &["/remove:g", "*S-1-5-20", "/Q"])?;
    }
    if original_owner != "S-1-5-18"
        && original_owner != "S-1-5-32-544"
        && original_owner != reader_sid
    {
        let sid = format!("*{original_owner}");
        if recursive {
            run_icacls(path, &["/remove:g", &sid, "/T", "/Q"])?;
        } else {
            run_icacls(path, &["/remove:g", &sid, "/Q"])?;
        }
    }
    if recursive {
        // Only the immutable releases/ and stable bin/bootstrap trees enter
        // this branch. There are NO identity keys or journals beneath them.
        // Reset inherited child DACLs from an already protected parent,
        // rather than allowing an older explicit user-writable DLL/script.
        run_icacls(path, &["/reset", "/T", "/Q"])?;
        run_icacls(path, &["/setowner", "*S-1-5-32-544", "/T", "/Q"])?;
    } else {
        run_icacls(path, &["/setowner", "*S-1-5-32-544", "/Q"])?;
    }
    edge_shared_types::host_journal::verify_windows_protected_path_acl(path, !directory)
        .map_err(str::to_owned)?;
    if recursive {
        fn verify_immutable_tree(path: &Path) -> Result<(), String> {
            for entry in
                fs::read_dir(path).map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_TREE_UNREADABLE")?
            {
                let entry = entry.map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_TREE_UNREADABLE")?;
                let child = entry.path();
                let meta = fs::symlink_metadata(&child)
                    .map_err(|_| "HOST_WINDOWS_SYSTEM_AUTHORITY_TREE_UNREADABLE")?;
                let dir = meta.file_type().is_dir();
                edge_shared_types::host_journal::verify_windows_protected_path_acl(&child, !dir)
                    .map_err(str::to_owned)?;
                if dir {
                    verify_immutable_tree(&child)?;
                }
            }
            Ok(())
        }
        verify_immutable_tree(path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn converge_windows_system_authority_acl(
    install_root: &Path,
    immutable_console: &Path,
) -> Result<(), String> {
    if install_root != Path::new(r"C:\sing-box")
        || !immutable_console.starts_with(install_root.join("releases"))
        || immutable_console.file_name().and_then(|x| x.to_str()) != Some("edge-console.exe")
    {
        return Err("HOST_WINDOWS_SYSTEM_AUTHORITY_SCOPE_INVALID".into());
    }
    harden_system_authority_path(install_root, false, true)?;
    let releases = install_root.join("releases");
    let console_owner =
        edge_shared_types::host_journal::windows_native_acl_owner_sid(immutable_console)
            .map_err(str::to_owned)?;
    harden_system_authority_path(&releases, true, true)?;
    // A new release may have been staged by a local Administrator even when
    // the releases/ directory already has an Administrators owner.
    if console_owner != "S-1-5-18" && console_owner != "S-1-5-32-544" {
        let sid = format!("*{console_owner}");
        run_icacls(&releases, &["/remove:g", &sid, "/T", "/Q"])?;
    }
    for directory in [install_root.join("bin"), install_root.join("bootstrap")] {
        if directory.is_dir() {
            harden_system_authority_path(&directory, true, true)?;
        }
    }
    for file in [
        install_root.join("current.pb"),
        install_root.join("previous.pb"),
        install_root.join("offline-bootstrap-intent-v1"),
    ] {
        if file.exists() {
            harden_system_authority_path(&file, false, false)?;
        }
    }
    edge_shared_types::host_journal::verify_windows_protected_path_acl(immutable_console, true)
        .map_err(str::to_owned)?;
    let diagnostic = install_root.join("bin").join("edge-diagnostic.exe");
    if diagnostic.is_file() {
        edge_shared_types::host_journal::verify_windows_protected_path_acl(&diagnostic, true)
            .map_err(str::to_owned)?;
    }
    edge_shared_types::host_journal::verify_windows_protected_path_acl(
        &install_root.join("native-host").join("journal"),
        false,
    )
    .map_err(str::to_owned)?;
    Ok(())
}

#[cfg(windows)]
fn converge_native_host_acl(install_root: &Path) -> Result<(), String> {
    // This is invoked during the ONE authorized offline native transaction,
    // before the existing SYSTEM task is re-enabled. No key or trust is made.
    for path in native_host_acl_paths(install_root) {
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&path)
                    .map_err(|_| "HOST_WINDOWS_SYSTEM_NATIVE_ROOT_CREATE_FAILED")?;
                fs::symlink_metadata(&path)
                    .map_err(|_| "HOST_WINDOWS_SYSTEM_NATIVE_ROOT_READBACK_FAILED")?
            }
            Err(_) => return Err("HOST_WINDOWS_SYSTEM_NATIVE_ROOT_METADATA_UNAVAILABLE".into()),
        };
        if !existing_native_host_directory_is_safe(&meta) {
            return Err("HOST_WINDOWS_SYSTEM_NATIVE_ROOT_REPARSE_OR_NOT_DIR".into());
        }
        // Ensure SYSTEM/Administrators remain authorized before inheritance
        // is removed; NetworkService and the controller must not write here.
        run_icacls(
            &path,
            &[
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
                "/Q",
            ],
        )?;
        run_icacls(&path, &["/inheritance:r", "/Q"])?;
        run_icacls(&path, &["/remove:g", "*S-1-5-20", "/Q"])?;
        run_icacls(&path, &["/setowner", "*S-1-5-32-544", "/Q"])?;
    }
    Ok(())
}

#[cfg(windows)]
fn converge_controller_tun_authority() -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "canonical production Windows datapath mode is invalid".to_owned())?;
    if mode != WindowsDatapathMode::ManagedTun {
        return Ok(());
    }

    let script = r#"
$ErrorActionPreference = 'Stop'
$administrators = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$account = New-Object System.Security.Principal.NTAccount('NT SERVICE', 'EdgePlatformController')
$serviceSid = $account.Translate([System.Security.Principal.SecurityIdentifier])
$members = @(Get-LocalGroupMember -SID $administrators)
if (-not ($members | Where-Object { $_.SID -eq $serviceSid })) {
    Add-LocalGroupMember -SID $administrators -Member $serviceSid.Value
}
$verified = @(Get-LocalGroupMember -SID $administrators | Where-Object { $_.SID -eq $serviceSid })
if ($verified.Count -ne 1) {
    throw 'EdgePlatformController service SID is not a member of the local Administrators group'
}
"#;

    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| {
            format!("failed to start bounded Windows TUN authority convergence: {err}")
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "failed to converge EdgePlatformController administrator-class TUN authority: exit={}",
            status.code().unwrap_or(-1)
        ))
    }
}

#[cfg(windows)]
fn converge_controller_service_with_activation_console(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    let console = Path::new(&activation.console_path);
    if !console.is_file() {
        return Err(format!(
            "exact activation console is missing for controller handoff: {}",
            console.display()
        ));
    }
    let root = install_root
        .to_str()
        .ok_or_else(|| "Windows install root is not UTF-8".to_owned())?;
    let output = Command::new(console)
        .args([
            "privileged-converge-controller-service",
            "--install-root",
            root,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|err| {
            format!("failed to start exact activation console for controller handoff: {err}")
        })?;
    if !output.status.success() {
        return Err(format!(
            "exact activation console controller handoff failed: {}",
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn controller_service_binary_path(command: &Path) -> PathBuf {
    let text = command.to_string_lossy();
    if let Some(rest) = text.strip_prefix('"')
        && let Some(end) = rest.find('"')
    {
        return PathBuf::from(&rest[..end]);
    }
    PathBuf::from(text.split_whitespace().next().unwrap_or_default())
}

#[cfg(windows)]
fn proxy_only_controller_service_lifecycle(
    install_root: &Path,
    start: bool,
) -> Result<(String, String, Option<String>), String> {
    // Exactly one SYSTEM dispatcher owns the SCM mutation. A GitHub runner
    // never gets SCM privileges and the normal console cannot start a service.
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32 {
        return Err("PROXY_ONLY_SCM_BLOCKED: accepted desired mode is not ProxyOnly".to_owned());
    }
    let active = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    let diagnostic = Command::new(&active.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("PROXY_ONLY_SCM_BLOCKED: exact diagnostic failed: {err}"))?;
    let fields = String::from_utf8_lossy(&diagnostic.stdout);
    let has = |line: &str| fields.lines().any(|value| value.trim() == line);
    if !has("windows_datapath_mode=ProxyOnly")
        || !has("managed_tun_present=false")
        || !has("exact_release_files=PASS")
        || !has(&format!("release_set_sha256={}", active.release_set_sha256))
    {
        return Err("PROXY_ONLY_SCM_BLOCKED: exact release / no-TUN evidence missing".to_owned());
    }
    let observed = classify_runtime_process(&local_singbox_config_path(install_root));
    if matches!(observed, RuntimeProcessClassification::Conflicting(_)) {
        return Err("PROXY_ONLY_SCM_BLOCKED: conflicting sing-box owner".to_owned());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("PROXY_ONLY_SCM_BLOCKED: SCM unavailable: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::START
                | ServiceAccess::STOP,
        )
        .map_err(|err| format!("PROXY_ONLY_SCM_BLOCKED: owner unavailable: {err}"))?;
    let config = service.query_config().map_err(|err| err.to_string())?;
    let exact_command = format!(
        "{} windows-service {} {}",
        active.controller_path,
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR,
    );
    let account = config
        .account_name
        .as_deref()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();
    if config.executable_path.to_string_lossy() != exact_command
        || !account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)
        || config.start_type != ServiceStartType::OnDemand
    {
        return Err("PROXY_ONLY_SCM_BLOCKED: exact immutable Manual SCM owner mismatch".to_owned());
    }
    let before = service.query_status().map_err(|err| err.to_string())?;
    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse::<SocketAddr>()
        .map_err(|err| err.to_string())?;
    let code = if start {
        match before.current_state {
            ServiceState::Stopped => {
                if before.process_id.is_some()
                    || !matches!(observed, RuntimeProcessClassification::Absent)
                    || controller_is_listening(addr)
                {
                    return Err(
                        "PROXY_ONLY_SCM_BLOCKED: stopped owner has residual runtime/listener"
                            .to_owned(),
                    );
                }
                service
                    .start::<&str>(&[])
                    .map_err(|err| format!("PROXY_ONLY_SCM_START_UNKNOWN: {err}"))?;
                wait_for_service_state(
                    &service,
                    ServiceState::Running,
                    Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
                )?;
                "PROXY_ONLY_SCM_STARTED"
            }
            ServiceState::Running
                if before.process_id.is_some() && controller_is_listening(addr) =>
            {
                "PROXY_ONLY_SCM_ALREADY_RUNNING"
            }
            other => {
                return Err(format!(
                    "PROXY_ONLY_SCM_BLOCKED: unsafe start state {other:?}"
                ));
            }
        }
    } else {
        match before.current_state {
            ServiceState::Stopped
                if before.process_id.is_none()
                    && matches!(observed, RuntimeProcessClassification::Absent)
                    && !controller_is_listening(addr) =>
            {
                "PROXY_ONLY_SCM_ALREADY_STOPPED"
            }
            ServiceState::Running
                if before.process_id.is_some() && controller_is_listening(addr) =>
            {
                // Stop the exact SCM owner FIRST. While the controller is
                // Running its supervisor may relaunch a child immediately
                // after a direct process stop (physically observed on Windows).
                // SCM shutdown sets STOP_REQUESTED, aborts supervision and
                // terminates only its owned child before reporting Stopped.
                // Never kill a process from this caller or touch TUN, DNS,
                // routes, foreign sing-box or CloudflareWARP.
                service
                    .stop()
                    .map_err(|err| format!("PROXY_ONLY_SCM_STOP_UNKNOWN: {err}"))?;
                wait_for_service_state(
                    &service,
                    ServiceState::Stopped,
                    Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
                )
                .map_err(|err| format!("PROXY_ONLY_SCM_STOP_UNKNOWN: {err}"))?;
                if !matches!(
                    classify_runtime_process(&local_singbox_config_path(install_root)),
                    RuntimeProcessClassification::Absent
                ) {
                    return Err(
                        "PROXY_ONLY_SCM_STOP_UNKNOWN: managed child remains after SCM stop"
                            .to_owned(),
                    );
                }
                "PROXY_ONLY_SCM_STOPPED"
            }
            other => {
                return Err(format!(
                    "PROXY_ONLY_SCM_BLOCKED: unsafe stop state {other:?}"
                ));
            }
        }
    };
    let after = service.query_status().map_err(|err| err.to_string())?;
    let after_config = service.query_config().map_err(|err| err.to_string())?;
    let expected = if start {
        ServiceState::Running
    } else {
        ServiceState::Stopped
    };
    if after.current_state != expected
        || (start && (after.process_id.is_none() || !controller_is_listening(addr)))
        || (!start
            && (after.process_id.is_some()
                || controller_is_listening(addr)
                || !matches!(
                    classify_runtime_process(&local_singbox_config_path(install_root)),
                    RuntimeProcessClassification::Absent
                )))
        || after_config.start_type != ServiceStartType::OnDemand
    {
        return Err("PROXY_ONLY_SCM_UNKNOWN: SCM readback failed; do not replay".to_owned());
    }
    Ok((
        code.to_owned(),
        format!("mode=ProxyOnly;scm={expected:?};startup=OnDemand;tun=ABSENT;network_mutations=0"),
        Some(active.release_set_sha256),
    ))
}

#[cfg(windows)]
fn restart_controller_service(
    install_root: &Path,
) -> Result<(String, String, Option<String>), String> {
    let activation = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    let expected_controller = Path::new(&activation.controller_path);
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("failed to open Windows Service Control Manager: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::START
                | ServiceAccess::STOP,
        )
        .map_err(|err| format!("failed to open exact controller service: {err}"))?;
    let config = service
        .query_config()
        .map_err(|err| format!("failed to query exact controller service config: {err}"))?;
    let configured_binary = controller_service_binary_path(&config.executable_path);
    if !evidence_path_matches(&configured_binary.to_string_lossy(), expected_controller) {
        return Err("controller service binary does not match current ReleaseSet".to_owned());
    }
    let account = config
        .account_name
        .as_deref()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "LocalSystem".to_owned());
    if !account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT) {
        return Err(format!("unexpected controller service account: {account}"));
    }
    let expected_command = format!(
        "{} windows-service {} {}",
        activation.controller_path,
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR
    );
    if config.executable_path.to_string_lossy() != expected_command {
        return Err("controller service command does not match exact current authority".to_owned());
    }

    let before = service
        .query_status()
        .map_err(|err| format!("failed to query controller service before restart: {err}"))?;
    if before.current_state != ServiceState::Running {
        return Err(format!(
            "controller restart requires Running pre-state, observed {:?}",
            before.current_state
        ));
    }
    let before_pid = before
        .process_id
        .ok_or_else(|| "Running controller service has no PID".to_owned())?;

    service
        .stop()
        .map_err(|err| format!("failed to stop exact controller service: {err}"))?;
    wait_for_service_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
    service
        .start::<&str>(&[])
        .map_err(|err| format!("failed to start exact controller service: {err}"))?;
    wait_for_service_state(
        &service,
        ServiceState::Running,
        Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
    )?;

    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse()
        .map_err(|err| format!("invalid installed controller address: {err}"))?;
    if !controller_is_listening(addr) {
        return Err(format!(
            "restarted controller service is not listening on {INSTALLED_CONTROLLER_ADDR}"
        ));
    }

    let after = service
        .query_status()
        .map_err(|err| format!("failed to query controller service after restart: {err}"))?;
    let after_pid = after
        .process_id
        .ok_or_else(|| "restarted controller service has no PID".to_owned())?;
    if after_pid == before_pid {
        return Err("controller service restart did not change controller PID".to_owned());
    }

    Ok((
        "CONTROLLER_SERVICE_RESTARTED".to_owned(),
        format!(
            "controller_restart=PASS;before_pid={before_pid};after_pid={after_pid};endpoint={INSTALLED_CONTROLLER_ADDR}"
        ),
        Some(activation.release_set_sha256),
    ))
}

#[cfg(windows)]
fn converge_controller_service(install_root: &Path, controller_path: &Path) -> Result<(), String> {
    if !controller_path.is_file() {
        return Err(format!(
            "exact controller binary is missing: {}",
            controller_path.display()
        ));
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|err| format!("failed to open Windows Service Control Manager: {err}"))?;

    let service_info = ServiceInfo {
        name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: controller_path.to_path_buf(),
        launch_arguments: vec![
            OsString::from("windows-service"),
            install_root.as_os_str().to_owned(),
            OsString::from(INSTALLED_CONTROLLER_ADDR),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)),
        account_password: None,
    };
    let access = ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP;
    let service = manager
        .create_service(&service_info, access)
        .or_else(|_| manager.open_service(WINDOWS_CONTROLLER_SERVICE_NAME, access))
        .map_err(|err| format!("failed to create or open controller service: {err}"))?;

    let current_config = service.query_config().map_err(|err| {
        format!("failed to query controller service config before convergence: {err}")
    })?;
    let current_account = current_config
        .account_name
        .as_deref()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "LocalSystem".to_owned());
    let expected_command = format!(
        "{} windows-service {} {}",
        controller_path.display(),
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR
    );
    let current_status = service
        .query_status()
        .map_err(|err| format!("failed to query controller service before convergence: {err}"))?;
    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse()
        .map_err(|err| format!("invalid installed controller address: {err}"))?;
    if current_config.executable_path.to_string_lossy() == expected_command
        && current_account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)
        && current_config.start_type == ServiceStartType::AutoStart
        && current_status.current_state == ServiceState::Running
        && controller_is_listening(addr)
    {
        return Ok(());
    }

    converge_controller_tun_authority()?;

    let status = service
        .query_status()
        .map_err(|err| format!("failed to query controller service before convergence: {err}"))?;
    let observed = if status.current_state == ServiceState::StartPending {
        wait_for_service_state_any(
            &service,
            &[ServiceState::Running, ServiceState::Stopped],
            Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
        )?
    } else {
        status.current_state
    };
    match observed {
        ServiceState::Stopped => {}
        ServiceState::StopPending => {
            wait_for_service_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
        }
        ServiceState::Running | ServiceState::Paused => {
            service.stop().map_err(|err| {
                format!("failed to stop controller service from {observed:?}: {err:?}")
            })?;
            wait_for_service_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
        }
        other => {
            return Err(format!(
                "controller service is not safely stoppable for owner handoff: {other:?}"
            ));
        }
    }

    service
        .change_config(&service_info)
        .map_err(|err| format!("failed to retarget controller service: {err}"))?;
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .map_err(|err| format!("failed to enable controller service SID: {err}"))?;
    service
        .set_delayed_auto_start(true)
        .map_err(|err| format!("failed to enable delayed controller auto-start: {err}"))?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(15),
                },
            ]),
        })
        .map_err(|err| format!("failed to configure controller service recovery: {err}"))?;
    service
        .set_failure_actions_on_non_crash_failures(false)
        .map_err(|err| format!("failed to limit controller recovery to crash failures: {err}"))?;

    converge_application_acl(install_root)?;
    // Only a verified immutable SYSTEM executable path may be bound to SCM.
    let active = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    converge_windows_system_authority_acl(install_root, Path::new(&active.console_path))?;

    service
        .start::<&str>(&[])
        .map_err(|err| format!("failed to start controller service: {err}"))?;
    wait_for_service_state(
        &service,
        ServiceState::Running,
        Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
    )?;

    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse()
        .map_err(|err| format!("invalid installed controller address: {err}"))?;
    if !controller_is_listening(addr) {
        return Err(format!(
            "controller service is Running but is not listening on {INSTALLED_CONTROLLER_ADDR}"
        ));
    }
    Ok(())
}

async fn reconcile_installed_runtime(endpoint: String) -> Result<(), Box<dyn std::error::Error>> {
    ensure_controller_running(&endpoint)?;
    let status = fetch_status(endpoint.clone()).await?;
    let Some(local) = status.local_singbox.as_ref() else {
        return Err("controller status has no local sing-box observation".into());
    };
    if !local.managed_config {
        println!("status=PASS");
        println!("reconcile=NOOP");
        println!("reason=no_managed_local_config");
        return Ok(());
    }
    if local.process_running {
        println!("status=PASS");
        println!("reconcile=NOOP");
        println!("reason=local_runtime_already_running");
        return Ok(());
    }

    let response = start_local(endpoint).await?;
    if !response.success {
        return Err(format!("local runtime reconcile failed: {}", response.note).into());
    }
    println!("status=PASS");
    println!("reconcile=STARTED_LOCAL_RUNTIME");
    Ok(())
}

#[cfg(test)]
mod legacy_windows_privileged_ingress_tests {
    use super::*;

    #[test]
    fn old_system_dispatcher_rejects_every_mutation_opcode() {
        assert!(legacy_privileged_read_only(
            WindowsPrivilegedOperation::Ping as i32
        ));
        assert!(legacy_privileged_read_only(
            WindowsPrivilegedOperation::RuntimeEvidence as i32
        ));
        for operation in [
            WindowsPrivilegedOperation::ActivateRelease,
            WindowsPrivilegedOperation::RollbackPreviousRelease,
            WindowsPrivilegedOperation::ReinstallAcceptedRelease,
            WindowsPrivilegedOperation::OfflineActivateRelease,
            WindowsPrivilegedOperation::OfflineRollbackPreviousRelease,
            WindowsPrivilegedOperation::RestartControllerService,
            WindowsPrivilegedOperation::StartProxyOnlyController,
            WindowsPrivilegedOperation::StopProxyOnlyController,
            WindowsPrivilegedOperation::StageCredential,
        ] {
            assert!(!legacy_privileged_read_only(operation as i32));
        }
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

// The original W4 failed after an exact durable BEGIN and disabled its SYSTEM
// task, but pointer compensation restored the old immutable ReleaseSet.
// A DIFFERENT signed release may be explicitly approved as successor;
// replaying the already-attempted target or accepting an unrelated BEGIN is
// forbidden, even when the task is Disabled.
#[cfg(test)]
mod offline_disabled_successor_tests {
    use super::{VerifiedRetainedOfflineBootstrap, require_distinct_offline_bootstrap_successor};

    const INSTALLED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const INTERRUPTED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEXT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const OLD_REVISION: &str = "1111111111111111111111111111111111111111";
    const NEXT_REVISION: &str = "2222222222222222222222222222222222222222";

    fn pending() -> VerifiedRetainedOfflineBootstrap {
        VerifiedRetainedOfflineBootstrap {
            original_bytes: Vec::new(),
            sha256: String::new(),
            from: INSTALLED.to_owned(),
            to: INTERRUPTED.to_owned(),
            accepted_revision: OLD_REVISION.to_owned(),
        }
    }

    #[test]
    fn new_exact_successor_only_does_not_replay_interrupted_install() {
        let p = pending();
        assert!(
            require_distinct_offline_bootstrap_successor(&p, INSTALLED, NEXT_REVISION, NEXT)
                .is_ok()
        );
        assert_eq!(
            require_distinct_offline_bootstrap_successor(&p, INSTALLED, NEXT_REVISION, INTERRUPTED),
            Err("OFFLINE_BOOTSTRAP_DISABLED_SUCCESSOR_NOT_DISTINCT_NO_REPLAY".to_owned())
        );
        assert_eq!(
            require_distinct_offline_bootstrap_successor(&p, INSTALLED, OLD_REVISION, NEXT),
            Err("OFFLINE_BOOTSTRAP_DISABLED_SUCCESSOR_NOT_DISTINCT_NO_REPLAY".to_owned())
        );
        assert_eq!(
            require_distinct_offline_bootstrap_successor(&p, INTERRUPTED, NEXT_REVISION, NEXT),
            Err("OFFLINE_BOOTSTRAP_DISABLED_SUCCESSOR_NOT_DISTINCT_NO_REPLAY".to_owned())
        );
        assert!(
            require_distinct_offline_bootstrap_successor(
                &p,
                INSTALLED,
                NEXT_REVISION,
                "not-a-release"
            )
            .is_err()
        );
    }
}
