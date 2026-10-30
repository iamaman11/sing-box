mod legacy_provider_support;
#[cfg(windows)]
mod windows_native_runtime;
use legacy_provider_support::*;

use std::env;
use std::fs;
use std::future::Future;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(windows)]
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(windows)]
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
#[cfg(windows)]
use windows_service::service_dispatcher;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

mod cli;
mod controller_rpc;
mod deploy_orchestrator;
mod error;

use clap::Parser;
use edge_bundle::{
    BuildBundleRequest, PreparedDeploymentBundle, build_bundle, generate_deployment_label,
};
use edge_clash::{
    default_aux_groups, get_selector_state as get_live_selector_state,
    set_selector as set_live_selector,
};
use edge_controller_core::{
    collect_controller_status, controller_state_db_path, is_installed_windows_root,
    local_singbox_config_path, validate_deploy_transition, windows_credential_store_path,
    windows_runtime_state_path,
};
use edge_local_runtime::{
    LocalRuntimePaths, RuntimeProcessClassification, classify_runtime_process,
    exact_managed_runtime_processes, inspect_local_runtime,
    restart_local_runtime as restart_runtime_process,
    restart_local_runtime_visible as restart_runtime_process_visible,
    start_local_runtime as start_runtime_process, stop_local_runtime as stop_runtime_process,
};
use edge_observability::init as init_observability;
use edge_provider_cloudflare::mock_upsert_a_record;
use edge_provider_vultr::mock_instance;
use edge_secrets::{CredentialStore, default_env_ref, resolve_secret_path};
use edge_shared_types::agent_service_client::AgentServiceClient;
use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::controller_service_server::{ControllerService, ControllerServiceServer};
use edge_shared_types::{
    AgentState, AppReadinessPhase, ApplyBundleRequest, BootstrapMode, BootstrapRuntimeRequest,
    BootstrapRuntimeResponse, BundleFile, CheckStatus, ControllerStatus, CredentialProjectionKind,
    CredentialStateObservation, DeployPhase, DeployRequest, DeployResponse, DestroyRequest,
    DestroyResponse, DiagnosticEvidence, DiagnosticSubsystem, DoctorCheck, DoctorRequest,
    DoctorResponse, Empty, GetOperationRequest, GetSecretRefRequest, GetSelectorStateRequest,
    GetTraceRequest, ListOperationEventsRequest, ListOperationEventsResponse,
    ListSecretRefsRequest, ListSecretRefsResponse, LocalRuntimeResponse, Operation, OperationEvent,
    OperationEventKind, OperationKind, OperationLifecycleStatus, OperationPhase, OperationStatus,
    PlatformError, ProviderObservation, RestartLocalRuntimeRequest, RuntimeObservation,
    SecretRefEntry, SelectorState, SetSecretRefRequest, SetSelectorRequest, SetSelectorResponse,
    StageCredentialCandidateRequest, StartLocalRuntimeRequest, StopLocalRuntimeRequest,
    TraceObservation, VerifyRuntimeRequest, WINDOWS_CONTROLLER_ADDR,
    WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS, WindowsDatapathMode, WindowsPrivilegedOperation,
    canonical_production_desired_state, decode_windows_activation_state,
    decode_windows_privileged_request, decode_windows_privileged_result,
    decode_windows_runtime_state, timestamp_from_unix_seconds,
};
use edge_singbox::{default_trace_proxy_url, sync_local_config};
use edge_state::{
    AppReadinessUpdate, ControllerStateTransition, DestroyAuthorityTransition, EdgeState,
    NewControllerState, NewTrustEntry, OperationJournalUpdate, StoredDeployment, StoredOperation,
    StoredOperationEvent, StoredTrustEntry,
};
use edge_trace::trace_via_proxy;
use edge_trust::{
    AgentClientTlsPaths, agent_client_tls_from_paths, agent_endpoint_scheme,
    optional_agent_client_tls_from_env,
};
use error::ControllerError;
use prost::Message;
use serde_json::Value;
use tokio::time::{sleep, timeout};
#[cfg(windows)]
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};

const DEFAULT_CONTROLLER_ADDR: &str = "127.0.0.1:50051";
#[cfg(windows)]
const WINDOWS_CONTROLLER_SERVICE_NAME: &str = "EdgePlatformController";
#[cfg(windows)]
const WINDOWS_SERVICE_START_WAIT_HINT: Duration =
    Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS);
#[cfg(windows)]
const WINDOWS_CONTROLLER_INIT_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const CONTROLLER_SERVICE_ERROR_FILE: &str = "controller-service-error.txt";
#[cfg(windows)]
const CONTROLLER_SERVICE_ERROR_MESSAGE_MAX_CHARS: usize = 384;
const DEFAULT_STATE_DB: &str = "edge-platform/.runtime/controller-state.sqlite";
const DEFAULT_AGENT_ENDPOINT: &str = "http://127.0.0.1:50061";
const DEFAULT_LOCAL_CONFIG_PATH: &str = "win/windows/edge-dns-clean-vultr-dual.json";
const DEFAULT_LIVE_STATE_PATH: &str = "win/vultr-waw/current-edge.json";
const DEFAULT_CLOUDFLARE_ZONE: &str = "alegria.by";
const DEFAULT_DNS_RECORD: &str = "edge.alegria.by";
const DEFAULT_REGION: &str = "waw";

const DEFAULT_PLAN: &str = "vc2-1c-1gb";
const DEFAULT_TRACE_PROXY_URL: &str = "http://127.0.0.1:7890";
const DESKTOP_SELECTOR_GROUP: &str = "proxy-selector";
const UBUNTU_SELECTOR_GROUP: &str = "wsl-selector";
const DEFAULT_AGENT_REMOTE_PORT: u16 = 50061;
const DEFAULT_SSH_USER: &str = "root";
const DEFAULT_SSH_KNOWN_HOSTS_PATH: &str = "edge-platform/.runtime/ssh-known_hosts";
const BASE_BOOTSTRAP_TIMEOUT_SECS: u64 = 300;
const TUNNEL_BOOTSTRAP_TIMEOUT_SECS: u64 = 900;
const EGRESS_TRACE_TIMEOUT_SECS: u64 = 60;
const BOOTSTRAP_RPC_ATTEMPTS: usize = 3;
const SECRET_SSH_PRIVATE_KEY_PATH: &str = "bootstrap.ssh.private_key_path";
const KNOWN_SECRET_NAMES: &[&str] = &[SECRET_SSH_PRIVATE_KEY_PATH];

#[cfg(windows)]
#[derive(Debug, Clone)]
struct WindowsServiceConfig {
    repo_root: PathBuf,
    addr: SocketAddr,
}

#[cfg(windows)]
static WINDOWS_SERVICE_CONFIG: OnceLock<WindowsServiceConfig> = OnceLock::new();
#[cfg(windows)]
static CONTROLLER_SERVICE_ERROR_WRITTEN: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
static WINDOWS_SERVICE_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
static WINDOWS_RUNTIME_REPLACEMENT_GENERATION: AtomicU64 = AtomicU64::new(0);
#[cfg(windows)]
static WINDOWS_RUNTIME_OWNER_GATE: Mutex<()> = Mutex::new(());

#[cfg(windows)]
windows_service::define_windows_service!(
    ffi_edge_controller_service_main,
    edge_controller_service_main
);

#[derive(Debug, Clone)]
struct ResolvedDeployTarget {
    instance_id: String,
    target_ip: String,
}

#[derive(Debug, Clone)]
struct BootstrapAccessConfig {
    private_key_path: PathBuf,
    agent_binary_path: PathBuf,
    ssh_user: String,
    remote_port: u16,
    known_hosts_path: PathBuf,
}

#[derive(Debug)]
struct AgentTransport {
    endpoint: String,
    tls_paths: Option<AgentClientTlsPaths>,
    _tunnel: Option<SshTunnelGuard>,
}

#[derive(Debug)]
struct SshTunnelGuard {
    child: Child,
}

#[derive(Debug, Clone)]
struct AgentConnectionTarget {
    endpoint: String,
    tls_paths: Option<AgentClientTlsPaths>,
}

#[derive(Debug, Clone)]
struct DeployRollbackContext {
    deployment_label: String,
    previous_live_state: Option<String>,
    previous_controller_state: Option<edge_state::StoredControllerState>,
    dns_updated: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let telemetry = init_observability("edge-controller");
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
        component = "edge-controller",
        correlation_id = %telemetry.id(),
        command,
        event = "command.start",
        "command started"
    );

    match run(parsed).await {
        Ok(()) => {
            tracing::info!(
                component = "edge-controller",
                correlation_id = %telemetry.id(),
                command,
                event = "command.success",
                "command completed"
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(
                component = "edge-controller",
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

async fn run(parsed: cli::Cli) -> Result<(), ControllerError> {
    use cli::Command;

    match parsed
        .command
        .unwrap_or_else(|| Command::Serve(cli::ServeArgs::default()))
    {
        Command::Serve(args) => {
            let (repo_root, addr) = resolve_serve_config(args)?;
            serve(repo_root, addr).await?;
            Ok(())
        }
        #[cfg(windows)]
        Command::WindowsService(args) => {
            run_windows_service(args)?;
            Ok(())
        }
        Command::GetStatus(args) => {
            let status = fetch_status(args.resolve()).await?;
            io::stdout().write_all(&status.encode_proto())?;
            Ok(())
        }
        Command::GetSelector(args) => {
            let selector = fetch_selector_state(args.resolve()).await?;
            io::stdout().write_all(&selector.encode_to_vec())?;
            Ok(())
        }
        Command::Trace(args) => {
            let trace = get_trace_via_controller(args.resolve()).await?;
            io::stdout().write_all(&trace.encode_to_vec())?;
            Ok(())
        }
    }
}

fn resolve_serve_config(
    args: cli::ServeArgs,
) -> Result<(PathBuf, SocketAddr), Box<dyn std::error::Error>> {
    let repo_root = resolve_repo_root(args.repo_root)?;
    let addr = match args.addr {
        Some(addr) => addr,
        None => DEFAULT_CONTROLLER_ADDR
            .parse::<SocketAddr>()
            .map_err(|err| {
                format!("invalid built-in controller address {DEFAULT_CONTROLLER_ADDR}: {err}")
            })?,
    };
    Ok((repo_root, addr))
}

async fn controller_server(
    repo_root: PathBuf,
) -> Result<ControllerServerImpl, Box<dyn std::error::Error>> {
    if is_installed_windows_root(&repo_root) {
        fs::create_dir_all(repo_root.join("state"))?;
        fs::create_dir_all(repo_root.join("state").join("secrets"))?;
        fs::create_dir_all(repo_root.join("runtime"))?;
        let runtime_state_path = windows_runtime_state_path(&repo_root);
        if runtime_state_path.is_file() {
            let runtime_state = fs::read(&runtime_state_path)?;
            decode_windows_runtime_state(&runtime_state)?;
        }
        CredentialStore::open_existing(
            windows_credential_store_path(&repo_root),
            CredentialProjectionKind::Windows,
        )
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    }
    let db_path = controller_state_db_path(&repo_root);
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path)?));
    normalize_runtime_secret_refs(&state)?;
    interrupt_stale_running_operations(&state)?;
    if !is_installed_windows_root(&repo_root) {
        reconcile_active_deployment_state(&repo_root, &state)?;
    }
    Ok(ControllerServerImpl {
        repo_root,
        state,
        agent_endpoint: agent_endpoint_from_env(),
    })
}

/// The Windows SYSTEM Controller is the native owner, not a second
/// RPC mutation authority. Old gRPC endpoints retain schema compatibility
/// but have no right to modify credentials, SCM or runtime.
fn deny_legacy_windows_rpc_mutation() -> Result<(), Status> {
    Err(Status::permission_denied(
        "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
    ))
}

async fn serve(repo_root: PathBuf, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let service = controller_server(repo_root).await?;
    Server::builder()
        .add_service(ControllerServiceServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}

#[cfg(windows)]
async fn serve_prebound_with_shutdown<F>(
    service: ControllerServerImpl,
    listener: tokio::net::TcpListener,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: Future<Output = ()> + Send + 'static,
{
    let incoming = TcpListenerStream::new(listener);
    Server::builder()
        .add_service(ControllerServiceServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await?;
    Ok(())
}

#[cfg(windows)]
fn controller_service_error_path(repo_root: &Path) -> PathBuf {
    repo_root.join("logs").join(CONTROLLER_SERVICE_ERROR_FILE)
}

#[cfg(windows)]
fn sanitize_controller_service_error(message: &str) -> String {
    message
        .chars()
        .map(|ch| {
            if ch.is_ascii_graphic() || ch == ' ' {
                if ch == ';' { ',' } else { ch }
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(CONTROLLER_SERVICE_ERROR_MESSAGE_MAX_CHARS)
        .collect()
}

#[cfg(windows)]
fn write_controller_service_error(
    repo_root: &Path,
    stage: &str,
    message: &str,
) -> Result<(), String> {
    let logs = repo_root.join("logs");
    fs::create_dir_all(&logs)
        .map_err(|err| format!("failed to create controller log directory: {err}"))?;
    let body = format!(
        "stage={};message={}",
        stage,
        sanitize_controller_service_error(message)
    );
    fs::write(controller_service_error_path(repo_root), body.as_bytes())
        .map_err(|err| format!("failed to persist controller service error: {err}"))?;
    CONTROLLER_SERVICE_ERROR_WRITTEN.store(true, Ordering::Release);
    Ok(())
}

#[cfg(windows)]
fn clear_controller_service_error(repo_root: &Path) -> Result<(), String> {
    match fs::remove_file(controller_service_error_path(repo_root)) {
        Ok(()) => {
            CONTROLLER_SERVICE_ERROR_WRITTEN.store(false, Ordering::Release);
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            CONTROLLER_SERVICE_ERROR_WRITTEN.store(false, Ordering::Release);
            Ok(())
        }
        Err(err) => Err(format!(
            "failed to clear stale controller service error: {err}"
        )),
    }
}

#[cfg(any(windows, test))]
fn controller_service_panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string Rust panic payload".to_owned()
    }
}

#[cfg(windows)]
fn write_controller_service_boundary_error(stage: &str, message: &str, overwrite: bool) {
    let Some(config) = WINDOWS_SERVICE_CONFIG.get() else {
        return;
    };
    if !overwrite && CONTROLLER_SERVICE_ERROR_WRITTEN.load(Ordering::Acquire) {
        return;
    }
    let _ = write_controller_service_error(&config.repo_root, stage, message);
}

// One service-owned kernel process-exit wait per observed child. This uses no
// periodic health poll, independent task scheduler, or blind launch retry.
#[cfg(windows)]
fn wait_for_windows_child_exit(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("refusing Windows child-exit wait on pid 0".to_owned());
    }
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return Err(format!(
            "cannot acquire exact child pid {pid} process-exit handle: {}",
            unsafe { GetLastError() }
        ));
    }
    let result = unsafe { WaitForSingleObject(handle, u32::MAX) };
    let error = if result == WAIT_OBJECT_0 {
        0
    } else {
        unsafe { GetLastError() }
    };
    unsafe { CloseHandle(handle) };
    if result == WAIT_OBJECT_0 {
        Ok(())
    } else {
        Err(format!(
            "native child-exit wait failed: pid={pid} result={result:#x} error={error}"
        ))
    }
}

#[cfg(any(windows, test))]
fn child_exit_auto_recovery_allowed(
    shutdown: bool,
    privileged_handoff: bool,
    explicit_replacement: bool,
    recovery_consumed: bool,
    exact_absent: bool,
) -> bool {
    !shutdown && !privileged_handoff && !explicit_replacement && !recovery_consumed && exact_absent
}

// A read-only runtime-evidence/ping request does not intentionally stop the
// child and must not disable native recovery if the child fails concurrently.
#[cfg(windows)]
fn destructive_windows_handoff_pending(repo_root: &Path) -> Result<bool, String> {
    let path = repo_root.join("exchange/requests/request.pb");
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("cannot verify typed privileged request: {err}")),
    };
    let request = decode_windows_privileged_request(&bytes)?;
    let operation = WindowsPrivilegedOperation::try_from(request.operation)
        .map_err(|_| "unknown privileged operation during child-exit check".to_owned())?;
    Ok(matches!(
        operation,
        WindowsPrivilegedOperation::ActivateRelease
            | WindowsPrivilegedOperation::ReinstallAcceptedRelease
            | WindowsPrivilegedOperation::RollbackPreviousRelease
            | WindowsPrivilegedOperation::RestartControllerService
    ))
}

#[cfg(windows)]
fn read_windows_privileged_result_marker(repo_root: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(repo_root.join("exchange/results/result.pb")) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "cannot independently read durable privileged handoff result: {err}"
        )),
    }
}

#[cfg(windows)]
async fn supervise_windows_managed_child(
    repo_root: PathBuf,
    baseline: Option<edge_shared_types::windows_native_network::NativeNetworkIdentity>,
) -> Result<(), String> {
    if !is_installed_windows_root(&repo_root) {
        return Ok(());
    }
    let config_path = default_local_config_path(&repo_root);
    if !windows_runtime_state_path(&repo_root).is_file() || !config_path.is_file() {
        return Ok(());
    }
    let initial = exact_managed_runtime_processes(&config_path);
    if initial.is_empty() {
        return Ok(());
    } // signed start arrives after SCM is Running
    if initial.len() != 1 || initial[0].parent_pid != Some(std::process::id()) {
        return Err(
            "SCM startup did not expose one exact child owned by this controller".to_owned(),
        );
    }
    let mut pid = initial[0].pid;
    let mut recovered = false;
    loop {
        let observed_generation = WINDOWS_RUNTIME_REPLACEMENT_GENERATION.load(Ordering::Acquire);
        // A privileged request may complete and disappear before this wait
        // wakes. Snapshot its durable result to fence that entire handoff.
        let prior_result = read_windows_privileged_result_marker(&repo_root)?;
        // A detached native process-event waiter must not keep Tokio's
        // blocking pool alive after SCM shutdown if exact child cleanup fails.
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("managed-sing-box-exit".to_owned())
            .spawn(move || {
                let _ = tx.send(wait_for_windows_child_exit(pid));
            })
            .map_err(|err| format!("failed to register native child wait: {err}"))?;
        rx.await
            .map_err(|_| "native child event thread ended without observation".to_owned())??;

        match reconcile_windows_child_exit(
            &repo_root,
            pid,
            observed_generation,
            recovered,
            prior_result.as_deref(),
        )? {
            Some((next_pid, did_recover)) => {
                pid = next_pid;
                recovered |= did_recover;
            }
            None => {
                if let Some(baseline) = &baseline {
                    // The signed ProxyOnly effect owns a prelaunch native
                    // snapshot. On any child exit, including SCM STOP, verify
                    // the OS really restored the exact routes, DNS order and
                    // Cloudflare One interface. Never repair foreign routes.
                    let (_, after) =
                        edge_shared_types::windows_native_network::observe_native_network_identity(
                        )
                        .map_err(str::to_owned)?;
                    baseline.require_restored(&after).map_err(str::to_owned)?;
                }
                return Ok(());
            }
        }
    }
}

// Synchronous ownership decision under one in-process gate. The guard never
// crosses an async suspension; it also protects existing runtime RPC starts.
#[cfg(windows)]
fn reconcile_windows_child_exit(
    repo_root: &Path,
    exited_pid: u32,
    observed_generation: u64,
    recovery_consumed: bool,
    prior_privileged_result: Option<&[u8]>,
) -> Result<Option<(u32, bool)>, String> {
    let _owner_gate = WINDOWS_RUNTIME_OWNER_GATE
        .lock()
        .map_err(|_| "Windows runtime owner gate poisoned".to_owned())?;
    if WINDOWS_SERVICE_STOP_REQUESTED.load(Ordering::Acquire) {
        return Ok(None);
    }
    // Legacy child-exit recovery was an implicit SCM mutation. A restarted
    // service cannot acquire a new signed HostIntent merely by seeing an
    // exited PID; read-only status remains available, never silent replay.
    if is_installed_windows_root(repo_root) {
        return Ok(None);
    }
    // The exact privileged request exists BEFORE its intended sing-box stop
    // and remains until successful SCM handoff (or a recorded failure).
    if destructive_windows_handoff_pending(repo_root)? {
        return Ok(None);
    }
    let completed_result = read_windows_privileged_result_marker(repo_root)?;
    if completed_result.as_deref() != prior_privileged_result {
        // A new controller starts while a successful release handoff is
        // finishing. Do not permanently disarm that NEW SCM owner merely
        // because the privileged result became durable after SCM startup.
        // The old owner, a failed handoff or an unverified pointer is fenced.
        let Some(bytes) = completed_result.as_deref() else {
            return Ok(None);
        };
        let result = decode_windows_privileged_result(bytes)?;
        if !result.success {
            return Ok(None);
        }
        let activation_bytes = fs::read(repo_root.join("current.pb"))
            .map_err(|err| format!("cannot verify authority after privileged handoff: {err}"))?;
        let active = decode_windows_activation_state(&activation_bytes)?;
        if result.active_release_set_sha256.as_deref() != Some(active.release_set_sha256.as_str()) {
            return Ok(None);
        }
        let executable = std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .map_err(|err| format!("cannot verify SCM image after handoff: {err}"))?;
        let expected = Path::new(&active.controller_path)
            .canonicalize()
            .map_err(|err| format!("cannot verify exact controller after handoff: {err}"))?;
        if executable != expected {
            return Ok(None);
        }
    }
    let explicit_replacement =
        WINDOWS_RUNTIME_REPLACEMENT_GENERATION.load(Ordering::Acquire) != observed_generation;
    let config_path = default_local_config_path(repo_root);
    let owners = exact_managed_runtime_processes(&config_path);
    if owners.len() == 1 {
        if owners[0].pid == exited_pid {
            return Err(format!(
                "exit event for pid {exited_pid} still reports same live exact owner"
            ));
        }
        if owners[0].parent_pid != Some(std::process::id()) {
            return Err("replacement process is not owned by current SCM controller".to_owned());
        }
        return Ok(Some((owners[0].pid, false)));
    }
    if owners.len() > 1
        || !matches!(
            classify_runtime_process(&config_path),
            RuntimeProcessClassification::Absent
        )
    {
        return Err("child exited with conflicting or ambiguous sing-box ownership".to_owned());
    }
    if !child_exit_auto_recovery_allowed(
        false,
        false,
        explicit_replacement,
        recovery_consumed,
        true,
    ) {
        return if recovery_consumed && !explicit_replacement {
            Err("one-shot native child recovery budget exhausted".to_owned())
        } else {
            Ok(None) // An explicit failed restart is owned by its RPC caller.
        };
    }
    if !repo_root.join("current.pb").is_file() {
        return Err(
            "exact installed release authority disappeared; refusing auto recovery".to_owned(),
        );
    }
    let paths = LocalRuntimePaths {
        singbox_binary_path: default_singbox_binary_path(repo_root),
        config_path,
        state_path: windows_runtime_state_path(repo_root),
        runtime_root: default_runtime_root(repo_root),
    };
    // One-shot recovery cannot bypass the same pre-TUN barrier as SCM startup.
    require_native_windows_runtime_launch_safety(repo_root)?;
    let result = start_runtime_process(&paths, false)
        .map_err(|err| format!("one-shot native child recovery failed: {err}"))?;
    let pid = result
        .pid
        .ok_or("one-shot native child recovery returned no exact process identity")?;
    eprintln!("Windows SCM one-shot managed sing-box child recovery succeeded");
    Ok(Some((pid, true)))
}

#[cfg(windows)]
fn run_windows_service(args: cli::ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let (repo_root, addr) = resolve_serve_config(args)?;
    if is_installed_windows_root(&repo_root) {
        let canonical = WINDOWS_CONTROLLER_ADDR.parse::<SocketAddr>()?;
        if addr != canonical {
            return Err(format!(
                "installed Windows controller must bind canonical endpoint {WINDOWS_CONTROLLER_ADDR}, observed {addr}"
            )
            .into());
        }
    }
    WINDOWS_SERVICE_CONFIG
        .set(WindowsServiceConfig { repo_root, addr })
        .map_err(|_| "Windows controller service configuration is already initialized")?;
    service_dispatcher::start(
        WINDOWS_CONTROLLER_SERVICE_NAME,
        ffi_edge_controller_service_main,
    )?;
    Ok(())
}

#[cfg(windows)]
fn edge_controller_service_main(_arguments: Vec<OsString>) {
    CONTROLLER_SERVICE_ERROR_WRITTEN.store(false, Ordering::Release);
    match catch_unwind(AssertUnwindSafe(run_edge_controller_service)) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            let message = err.to_string();
            write_controller_service_boundary_error("service_entry", &message, false);
            eprintln!("EdgePlatformController service failed: {message}");
        }
        Err(payload) => {
            let message = controller_service_panic_message(payload.as_ref());
            write_controller_service_boundary_error("panic", &message, true);
            eprintln!("EdgePlatformController service panicked: {message}");
        }
    }
}

// Startup failure must never clean up a foreign or orphaned child merely
// because its command line points to our config. Only this SCM's unique
// exact child may be torn down; an absent child requires no mutation.
#[cfg(any(windows, test))]
fn failed_windows_scm_start_owns_child(
    exact_children: &[edge_local_runtime::ProcessObservation],
    scm_pid: u32,
) -> bool {
    exact_children.len() == 1 && exact_children[0].parent_pid == Some(scm_pid)
}

#[cfg(windows)]
fn stop_only_owned_child_after_failed_scm_start(repo_root: &Path) {
    let config_path = default_local_config_path(repo_root);
    let children = exact_managed_runtime_processes(&config_path);
    if failed_windows_scm_start_owns_child(&children, std::process::id()) {
        let _ = stop_runtime_process(&config_path, true);
    }
}

#[cfg(windows)]
fn run_edge_controller_service() -> Result<(), Box<dyn std::error::Error>> {
    WINDOWS_SERVICE_STOP_REQUESTED.store(false, Ordering::Release);
    let config = WINDOWS_SERVICE_CONFIG
        .get()
        .cloned()
        .ok_or("Windows controller service configuration is unavailable")?;
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                WINDOWS_SERVICE_STOP_REQUESTED.store(true, Ordering::Release);
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle =
        service_control_handler::register(WINDOWS_CONTROLLER_SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: WINDOWS_SERVICE_START_WAIT_HINT,
        process_id: None,
    })?;

    // SetServiceStatus(SERVICE_STOPPED) closes the RPC context even when
    // subsequent application cleanup fails. Never attempt a second call.
    let stopped_attempted = std::cell::Cell::new(false);
    let set_stopped = |failed: bool| -> Result<(), io::Error> {
        if stopped_attempted.replace(true) {
            return Err(io::Error::other(
                "SCM terminal status was already attempted",
            ));
        }
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(if failed { 1 } else { 0 }),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .map_err(|err| io::Error::other(err.to_string()))
    };
    let startup_failure = |stage: &str, message: String| -> Box<dyn std::error::Error> {
        let detail = match write_controller_service_error(&config.repo_root, stage, &message) {
            Ok(()) => message,
            Err(evidence_err) => format!("{message}; {evidence_err}"),
        };
        let detail = match set_stopped(true) {
            Ok(()) => detail,
            Err(status_err) => format!("{detail}; failed to report SCM Stopped: {status_err}"),
        };
        io::Error::other(detail).into()
    };

    // The service has registered its SCM status handle. A Rust panic must not
    // escape this scope without publishing a terminal service state.
    let service_result = catch_unwind(AssertUnwindSafe(
        || -> Result<(), Box<dyn std::error::Error>> {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => return Err(startup_failure("runtime_init", err.to_string())),
            };

            let service = match runtime.block_on(async {
                timeout(
                    WINDOWS_CONTROLLER_INIT_TIMEOUT,
                    controller_server(config.repo_root.clone()),
                )
                .await
            }) {
                Ok(Ok(service)) => service,
                Ok(Err(err)) => return Err(startup_failure("controller_init", err.to_string())),
                Err(_) => {
                    return Err(startup_failure(
                        "controller_init",
                        format!(
                            "controller initialization exceeded {} seconds",
                            WINDOWS_CONTROLLER_INIT_TIMEOUT.as_secs()
                        ),
                    ));
                }
            };

            let listener = match runtime
                .block_on(async { tokio::net::TcpListener::bind(config.addr).await })
            {
                Ok(listener) => listener,
                Err(err) => return Err(startup_failure("controller_bind", err.to_string())),
            };

            if let Err(err) = converge_windows_runtime_on_service_start(&config.repo_root) {
                stop_only_owned_child_after_failed_scm_start(&config.repo_root);
                return Err(startup_failure(
                    "runtime_converge",
                    format!("Windows managed runtime startup convergence failed: {err}"),
                ));
            }

            if let Err(err) = clear_controller_service_error(&config.repo_root) {
                stop_only_owned_child_after_failed_scm_start(&config.repo_root);
                return Err(startup_failure("error_evidence_clear", err));
            }

            if let Err(err) = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            }) {
                stop_only_owned_child_after_failed_scm_start(&config.repo_root);
                return Err(startup_failure("scm_running", err.to_string()));
            }

            let repo_root = config.repo_root.clone();
            // An OS process-handle wait, not a timer or a second Windows owner.
            // The controller's own child is supervised while this SCM service runs.
            let supervisor_root = repo_root.clone();
            let supervisor = runtime.spawn(async move {
                if let Err(err) =
                    supervise_windows_managed_child(supervisor_root.clone(), None).await
                {
                    let _ = write_controller_service_error(&supervisor_root, "child_exit", &err);
                    eprintln!("Windows managed child supervision stopped fail-closed: {err}");
                }
            });
            let serve_result = runtime.block_on(serve_prebound_with_shutdown(
                service,
                listener,
                async move {
                    let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
                },
            ));
            WINDOWS_SERVICE_STOP_REQUESTED.store(true, Ordering::Release);
            supervisor.abort();
            // Never return early from SCM cleanup: terminal SERVICE_STOPPED
            // must still be reported exactly once even if this gate is poisoned.
            let cleanup_result = match WINDOWS_RUNTIME_OWNER_GATE.lock() {
                Ok(_gate) => stop_runtime_process(&default_local_config_path(&repo_root), true)
                    .map(|_| ())
                    .map_err(|err| {
                        format!("failed to stop exact managed runtime on controller exit: {err}")
                    }),
                Err(_) => Err("Windows runtime owner gate poisoned on SCM cleanup".to_owned()),
            };

            let (result, failure) = match (serve_result, cleanup_result) {
                (Ok(()), Ok(())) => (Ok(()), None),
                (Err(err), Ok(())) => {
                    let message = err.to_string();
                    (
                        Err(io::Error::other(message.clone()).into()),
                        Some(("serve", message)),
                    )
                }
                (Ok(()), Err(cleanup_err)) => (
                    Err(io::Error::other(cleanup_err.clone()).into()),
                    Some(("cleanup", cleanup_err)),
                ),
                (Err(err), Err(cleanup_err)) => {
                    let message = format!("controller runtime failed: {err}; {cleanup_err}");
                    (
                        Err(io::Error::other(message.clone()).into()),
                        Some(("serve_cleanup", message)),
                    )
                }
            };

            if let Some((stage, message)) = failure {
                let _ = write_controller_service_error(&repo_root, stage, &message);
            } else {
                let _ = clear_controller_service_error(&repo_root);
            }

            // Report SERVICE_STOPPED exactly once, as the last SCM operation.
            set_stopped(result.is_err())?;
            result
        },
    ));
    match service_result {
        Ok(result) => result,
        Err(payload) => {
            let message = controller_service_panic_message(payload.as_ref());
            let detail = match write_controller_service_error(&config.repo_root, "panic", &message)
            {
                Ok(()) => message,
                Err(evidence_err) => format!("{message}; {evidence_err}"),
            };
            // SetServiceStatus(SERVICE_STOPPED) closes the SCM RPC context.
            // Persist bounded failure evidence before calling it, and never
            // issue a second terminal status update.
            set_stopped(true).map_err(|err| {
                io::Error::other(format!(
                    "Windows controller service panic; failed to report SCM Stopped: {err}"
                ))
            })?;
            Err(io::Error::other(detail).into())
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsStartupDecision {
    NoopManaged,
    RestartOrphanManaged,
    BlockedConflict,
    BlockedUnprovenLine1,
    StartAbsent,
}

#[cfg(any(windows, test))]
fn require_native_windows_route_capture_safety(mode: WindowsDatapathMode) -> Result<(), String> {
    match mode {
        WindowsDatapathMode::ProxyOnly => Ok(()),
        WindowsDatapathMode::ManagedTun => Err(
            "NATIVE_MANAGED_TUN_PREAUTH_BLOCKED: independently authenticated Line1 \
             and no-TUN DNS/control restoration are not proved; refusing route capture"
                .to_owned(),
        ),
        WindowsDatapathMode::Unspecified => {
            Err("NATIVE_MANAGED_TUN_PREAUTH_BLOCKED: unspecified Windows datapath mode".to_owned())
        }
    }
}

#[cfg(windows)]
fn require_native_windows_runtime_launch_safety(repo_root: &Path) -> Result<(), String> {
    if !is_installed_windows_root(repo_root) {
        return Ok(());
    }
    let desired = canonical_production_desired_state()?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "installed Windows datapath mode is invalid".to_owned())?;
    require_native_windows_route_capture_safety(mode)?;
    // The desired mode is NOT the current routing state. A previous
    // ManagedTun config may survive a Git switch back to ProxyOnly. Never
    // automatically restart that exact sing-box process after an SCM child
    // exit: it would recapture Windows routes without a fresh HostIntent.
    let path = default_local_config_path(repo_root);
    let bytes = fs::read(&path).map_err(|_| "HOST_WINDOWS_RECOVERY_EXISTING_CONFIG_UNPROVEN")?;
    edge_singbox::require_no_windows_route_capture_config(&bytes)
        .map_err(|_| "HOST_WINDOWS_RECOVERY_EXISTING_TUN_NETWORK_RESTORATION_REQUIRED")?;
    edge_shared_types::windows_native_network::observe_native_network_identity()
        .map_err(|error| error.to_owned())?;
    Ok(())
}

#[cfg(any(windows, test))]
fn windows_startup_decision(
    classification: &RuntimeProcessClassification,
    managed_count: usize,
    managed_parent_is_current_controller: bool,
    mode: WindowsDatapathMode,
) -> WindowsStartupDecision {
    if managed_count > 1 {
        return WindowsStartupDecision::BlockedConflict;
    }

    match mode {
        WindowsDatapathMode::ProxyOnly => {
            if managed_count == 1 {
                if managed_parent_is_current_controller {
                    WindowsStartupDecision::NoopManaged
                } else {
                    WindowsStartupDecision::RestartOrphanManaged
                }
            } else {
                match classification {
                    RuntimeProcessClassification::Managed(_) => {
                        if managed_parent_is_current_controller {
                            WindowsStartupDecision::NoopManaged
                        } else {
                            WindowsStartupDecision::RestartOrphanManaged
                        }
                    }
                    RuntimeProcessClassification::Conflicting(_)
                    | RuntimeProcessClassification::Absent => WindowsStartupDecision::StartAbsent,
                }
            }
        }
        WindowsDatapathMode::ManagedTun => match classification {
            RuntimeProcessClassification::Managed(_) => {
                if managed_parent_is_current_controller {
                    WindowsStartupDecision::NoopManaged
                } else {
                    WindowsStartupDecision::BlockedUnprovenLine1
                }
            }
            RuntimeProcessClassification::Conflicting(_) => WindowsStartupDecision::BlockedConflict,
            RuntimeProcessClassification::Absent => WindowsStartupDecision::BlockedUnprovenLine1,
        },
        WindowsDatapathMode::Unspecified => WindowsStartupDecision::BlockedConflict,
    }
}

#[cfg(windows)]
fn converge_windows_runtime_on_service_start(repo_root: &Path) -> Result<&'static str, String> {
    if !is_installed_windows_root(repo_root) {
        return Ok("NOT_INSTALLED");
    }

    let config_path = default_local_config_path(repo_root);
    let state_path = windows_runtime_state_path(repo_root);
    let state_present = state_path.is_file();
    let config_present = config_path.is_file();
    if !state_present && !config_present {
        return Ok("NOT_CONFIGURED");
    }
    if state_present != config_present {
        return Err(format!(
            "managed Windows runtime is partially configured: runtime_state_present={state_present} config_present={config_present}"
        ));
    }

    let state_bytes = fs::read(&state_path)
        .map_err(|err| format!("failed to read installed Windows runtime state: {err}"))?;
    decode_windows_runtime_state(&state_bytes)?;

    // A Windows service start is not a signed host apply. Until the native
    // SYSTEM HostIntent handler is accepted, expose controller diagnostics
    // but never launch, restart or adopt the managed sing-box process.
    if is_installed_windows_root(repo_root) {
        return Ok("HOST_WINDOWS_UNSIGNED_SCM_AUTOSTART_BLOCKED");
    }

    let desired = canonical_production_desired_state()
        .map_err(|err| format!("failed to load canonical production desired state: {err}"))?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "canonical production Windows datapath mode is invalid".to_owned())?;
    if mode == WindowsDatapathMode::Unspecified {
        return Err("canonical production Windows datapath mode is unspecified".to_owned());
    }

    let classification = classify_runtime_process(&config_path);
    let managed_processes = exact_managed_runtime_processes(&config_path);
    let managed_count = managed_processes.len();
    let managed_parent_is_current_controller = managed_processes
        .first()
        .and_then(|process| process.parent_pid)
        == Some(std::process::id());
    match windows_startup_decision(
        &classification,
        managed_count,
        managed_parent_is_current_controller,
        mode,
    ) {
        WindowsStartupDecision::NoopManaged => Ok("NOOP_MANAGED_RUNNING"),
        WindowsStartupDecision::RestartOrphanManaged => {
            require_native_windows_route_capture_safety(mode)?;
            stop_runtime_process(&config_path, true)
                .map_err(|err| format!("failed to stop orphaned exact managed runtime: {err}"))?;
            let paths = LocalRuntimePaths {
                singbox_binary_path: default_singbox_binary_path(repo_root),
                config_path,
                state_path,
                runtime_root: default_runtime_root(repo_root),
            };
            start_runtime_process(&paths, false).map_err(|err| {
                format!("failed to restart orphaned exact managed runtime: {err}")
            })?;
            Ok("RESTARTED_ORPHAN_MANAGED")
        }
        WindowsStartupDecision::BlockedUnprovenLine1 => {
            require_native_windows_route_capture_safety(mode)?;
            Err("ManagedTun startup is blocked until pre-TUN Line1 and DNS/control recovery are independently verified".to_owned())
        }
        WindowsStartupDecision::BlockedConflict => {
            match &classification {
                RuntimeProcessClassification::Conflicting(processes) => {
                    eprintln!(
                        "managed Windows runtime startup is fail-closed because conflicting sing-box ownership exists: {}",
                        processes
                            .iter()
                            .map(|process| format!(
                                "pid={} cmd={}",
                                process.pid, process.command_line
                            ))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    );
                }
                RuntimeProcessClassification::Managed(process) => {
                    eprintln!(
                        "managed Windows runtime startup is fail-closed because ownership evidence is inconsistent: managed_count={managed_count} pid={} cmd={}",
                        process.pid, process.command_line
                    );
                }
                RuntimeProcessClassification::Absent => {
                    eprintln!(
                        "managed Windows runtime startup is fail-closed because ownership evidence is inconsistent: managed_count={managed_count} classification=ABSENT"
                    );
                }
            }
            Ok("BLOCKED_CONFLICT")
        }
        WindowsStartupDecision::StartAbsent => {
            require_native_windows_route_capture_safety(mode)?;
            let paths = LocalRuntimePaths {
                singbox_binary_path: default_singbox_binary_path(repo_root),
                config_path,
                state_path,
                runtime_root: default_runtime_root(repo_root),
            };
            start_runtime_process(&paths, false)
                .map_err(|err| format!("failed to start validated managed runtime: {err}"))?;
            Ok("STARTED")
        }
    }
}

fn normalize_runtime_secret_refs(state: &Arc<Mutex<EdgeState>>) -> Result<(), String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;

    // The SSH private-key reference is a path, not key material. Convert a
    // legacy literal path only when it resolves to an existing local file.
    if let Some(stored) = guard
        .get_secret_ref(SECRET_SSH_PRIVATE_KEY_PATH)
        .map_err(|err| format!("failed to read SSH key path ref: {err}"))?
        && let Some(path) = stored.secret_ref.strip_prefix("literal:")
        && Path::new(path).is_file()
    {
        guard
            .upsert_secret_ref(SECRET_SSH_PRIVATE_KEY_PATH, &format!("path:{path}"))
            .map_err(|err| format!("failed to normalize SSH key path ref: {err}"))?;
    }
    Ok(())
}

async fn fetch_status(endpoint: String) -> Result<ControllerStatus, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client.get_status(Request::new(Empty {})).await?;
    Ok(response.into_inner())
}

async fn controller_bootstrap_runtime(
    endpoint: String,
    mode: BootstrapMode,
) -> Result<BootstrapRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .bootstrap_runtime(Request::new(BootstrapRuntimeRequest { mode: mode as i32 }))
        .await?;
    Ok(response.into_inner())
}

async fn start_local_runtime_via_controller(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .start_local_runtime(Request::new(StartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            force_restart: false,
            visible_window: false,
            native_system_effect: Vec::new(),
        }))
        .await?;
    Ok(response.into_inner())
}

async fn stop_local_runtime_via_controller(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .stop_local_runtime(Request::new(StopLocalRuntimeRequest {
            config_path: None,
            expected_config_only: true,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn restart_local_runtime_via_controller(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .restart_local_runtime(Request::new(RestartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            visible_window: false,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn fetch_selector_state(
    endpoint: String,
) -> Result<SelectorState, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .get_selector_state(Request::new(GetSelectorStateRequest { group: None }))
        .await?;
    Ok(response.into_inner())
}

async fn set_selector_via_controller(
    endpoint: String,
    group: &str,
    name: &str,
) -> Result<SetSelectorResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .set_selector(Request::new(SetSelectorRequest {
            group: group.to_owned(),
            name: name.to_owned(),
        }))
        .await?;
    Ok(response.into_inner())
}

async fn get_trace_via_controller(
    endpoint: String,
) -> Result<TraceObservation, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .get_trace(Request::new(GetTraceRequest { proxy_url: None }))
        .await?;
    Ok(response.into_inner())
}

async fn deploy_via_controller(
    endpoint: String,
    request: DeployRequest,
) -> Result<DeployResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client.deploy(Request::new(request)).await?;
    Ok(response.into_inner())
}

async fn destroy_via_controller(
    endpoint: String,
    request: DestroyRequest,
) -> Result<DestroyResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client.destroy(Request::new(request)).await?;
    Ok(response.into_inner())
}

async fn bootstrap_runtime(
    endpoint: String,
    mode: BootstrapMode,
) -> Result<BootstrapRuntimeResponse, String> {
    let target = AgentConnectionTarget {
        endpoint,
        tls_paths: None,
    };
    bootstrap_runtime_with_tls(target, mode).await
}

async fn bootstrap_runtime_with_tls(
    target: AgentConnectionTarget,
    mode: BootstrapMode,
) -> Result<BootstrapRuntimeResponse, String> {
    let channel = connect_to_agent_target(&target)
        .await
        .map_err(|err| format!("failed to connect to edge-agent: {err}"))?;
    let mut client = AgentServiceClient::<Channel>::new(channel);
    let timeout_secs = match mode {
        BootstrapMode::BootstrapBase => BASE_BOOTSTRAP_TIMEOUT_SECS,
        BootstrapMode::BootstrapTunnel | BootstrapMode::BootstrapFull => {
            TUNNEL_BOOTSTRAP_TIMEOUT_SECS
        }
        BootstrapMode::Unspecified => TUNNEL_BOOTSTRAP_TIMEOUT_SECS,
    };
    let response = timeout(
        Duration::from_secs(timeout_secs),
        client.bootstrap_runtime(Request::new(BootstrapRuntimeRequest { mode: mode as i32 })),
    )
    .await
    .map_err(|_| {
        format!(
            "edge-agent bootstrap RPC timed out after {timeout_secs}s for mode {}",
            mode.as_str_name()
        )
    })?
    .map_err(|err| format!("edge-agent bootstrap RPC failed: {err}"))?;
    Ok(response.into_inner())
}

fn is_retryable_bootstrap_transport_error(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("transport error")
        || normalized.contains("connection reset")
        || normalized.contains("broken pipe")
        || normalized.contains("connection refused")
        || normalized.contains("unavailable")
}

async fn bootstrap_runtime_with_tls_resilient(
    state: &Arc<Mutex<EdgeState>>,
    operation_id: i64,
    target: AgentConnectionTarget,
    mode: BootstrapMode,
) -> Result<BootstrapRuntimeResponse, String> {
    let mut last_error = None;
    for attempt in 1..=BOOTSTRAP_RPC_ATTEMPTS {
        match bootstrap_runtime_with_tls(target.clone(), mode).await {
            Ok(response) => return Ok(response),
            Err(err)
                if attempt < BOOTSTRAP_RPC_ATTEMPTS
                    && is_retryable_bootstrap_transport_error(&err) =>
            {
                let _ = append_operation_event(
                    state,
                    operation_id,
                    &format!(
                        "edge-agent bootstrap RPC transient failure for {} on attempt {attempt}; retrying: {}",
                        mode.as_str_name(),
                        err
                    ),
                );
                last_error = Some(err);
                sleep(Duration::from_secs((attempt as u64) * 2)).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_error
        .unwrap_or_else(|| format!("edge-agent bootstrap RPC failed for {}", mode.as_str_name())))
}

fn format_bootstrap_failure(response: &BootstrapRuntimeResponse) -> String {
    let mode = BootstrapMode::try_from(response.mode)
        .map(|value| value.as_str_name().to_owned())
        .unwrap_or_else(|_| format!("UNKNOWN({})", response.mode));
    let mut parts = vec![format!(
        "bootstrap-runtime {mode} failed with exit code {}",
        response.exit_code
    )];
    if !response.stderr.trim().is_empty() {
        parts.push(response.stderr.trim().to_owned());
    }
    if !response.warnings.is_empty() {
        parts.push(format!("warnings: {}", response.warnings.join("; ")));
    }
    parts.join(": ")
}

fn resolve_path_secret(
    state: &Arc<Mutex<EdgeState>>,
    name: &str,
    default_reference: &str,
) -> Result<PathBuf, String> {
    let reference = get_or_seed_secret_ref(state, name, default_reference)?;
    resolve_secret_path(&reference)
        .map_err(|err| format!("failed to resolve secret path {name} via {reference}: {err}"))
}

fn get_or_seed_secret_ref(
    state: &Arc<Mutex<EdgeState>>,
    name: &str,
    default_reference: &str,
) -> Result<String, String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    if let Some(secret_ref) = guard
        .get_secret_ref(name)
        .map_err(|err| format!("failed to read secret ref {name}: {err}"))?
    {
        return Ok(secret_ref.secret_ref);
    }
    guard
        .upsert_secret_ref(name, default_reference)
        .map_err(|err| format!("failed to store secret ref {name}: {err}"))?;
    Ok(default_reference.to_owned())
}

fn has_configured_secret_ref(state: &Arc<Mutex<EdgeState>>, name: &str) -> bool {
    state
        .lock()
        .ok()
        .and_then(|guard| guard.get_secret_ref(name).ok().flatten())
        .is_some()
        || env::var_os(secret_name_to_env(name)).is_some()
}

fn validate_secret_name(name: &str) -> Result<(), Status> {
    if name.trim().is_empty() {
        return Err(Status::invalid_argument("secret name is required"));
    }
    if KNOWN_SECRET_NAMES.contains(&name) {
        return Ok(());
    }
    Err(Status::invalid_argument(format!(
        "unsupported secret name: {name}"
    )))
}

fn list_secret_refs(state: &Arc<Mutex<EdgeState>>) -> Result<Vec<SecretRefEntry>, Status> {
    for name in KNOWN_SECRET_NAMES {
        let default_ref = default_env_ref(secret_name_to_env(name));
        let _ = get_or_seed_secret_ref(state, name, &default_ref);
    }

    let rows = state
        .lock()
        .map_err(|_| Status::internal("controller state mutex poisoned"))?
        .list_secret_refs()
        .map_err(|err| Status::internal(format!("failed to list secret refs: {err}")))?;

    Ok(rows
        .into_iter()
        .filter(|entry| KNOWN_SECRET_NAMES.contains(&entry.name.as_str()))
        .map(|entry| SecretRefEntry {
            name: entry.name,
            secret_ref: entry.secret_ref,
            updated_at_unix: entry.updated_at_unix,
        })
        .collect())
}

fn secret_name_to_env(name: &str) -> &'static str {
    match name {
        SECRET_SSH_PRIVATE_KEY_PATH => "EDGE_SSH_PRIVATE_KEY_PATH",
        _ => "",
    }
}

fn resolve_repo_root(explicit: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = explicit {
        return Ok(path);
    }

    let cwd = env::current_dir()?;
    if looks_like_repo_root(&cwd) {
        return Ok(cwd);
    }

    if let Some(parent) = cwd.parent()
        && looks_like_repo_root(parent)
    {
        return Ok(parent.to_path_buf());
    }

    Ok(cwd)
}

fn looks_like_repo_root(path: &Path) -> bool {
    path.join("RUST-ULTIMATE-PLATFORM-PLAN.md").exists()
}

struct ControllerServerImpl {
    repo_root: PathBuf,
    state: Arc<Mutex<EdgeState>>,
    agent_endpoint: String,
}

fn require_installed_windows_credential_owner(repo_root: &Path) -> Result<(), String> {
    if !is_installed_windows_root(repo_root) {
        return Err(
            "Windows credential staging requires the installed EdgePlatformController authority layout"
                .to_owned(),
        );
    }
    Ok(())
}

fn stage_windows_credential_candidate(
    repo_root: &Path,
    bundle: edge_shared_types::CredentialDeliveryBundle,
) -> Result<edge_shared_types::LocalCredentialState, String> {
    require_installed_windows_credential_owner(repo_root)?;
    if bundle.projection != CredentialProjectionKind::Windows as i32 {
        return Err("Windows credential owner rejects non-Windows projection".to_owned());
    }
    let store = CredentialStore::new(
        windows_credential_store_path(repo_root),
        CredentialProjectionKind::Windows,
    )?;
    store.stage_delivery_candidate(&bundle)
}

fn observe_windows_credential_state(
    repo_root: &Path,
) -> Result<Option<edge_shared_types::LocalCredentialState>, String> {
    require_installed_windows_credential_owner(repo_root)?;
    let Some(store) = CredentialStore::open_existing(
        windows_credential_store_path(repo_root),
        CredentialProjectionKind::Windows,
    )?
    else {
        return Ok(None);
    };
    store.read_state()
}

fn default_local_config_path(repo_root: &Path) -> PathBuf {
    local_singbox_config_path(repo_root)
}

fn default_live_state_path(repo_root: &Path) -> PathBuf {
    if is_installed_windows_root(repo_root) {
        windows_runtime_state_path(repo_root)
    } else {
        repo_root.join(DEFAULT_LIVE_STATE_PATH)
    }
}

fn default_runtime_root(repo_root: &Path) -> PathBuf {
    if is_installed_windows_root(repo_root) {
        repo_root.join("runtime")
    } else if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
        PathBuf::from(local_app_data)
            .join("sing-box-vultr-dual")
            .join("runtime")
    } else {
        repo_root
            .join("edge-platform")
            .join(".runtime")
            .join("local-runtime")
    }
}

fn default_singbox_binary_path(repo_root: &Path) -> PathBuf {
    if let Ok(explicit) = env::var("EDGE_SINGBOX_BINARY_PATH") {
        return PathBuf::from(explicit);
    }
    if is_installed_windows_root(repo_root)
        && let Ok(current) = env::current_exe()
        && let Some(parent) = current.parent()
    {
        let installed = parent.join("sing-box.exe");
        if installed.is_file() {
            return installed;
        }
    }

    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("sing-box-vultr-dual")
            .join("runtime")
            .join("sing-box.exe");
    }

    PathBuf::from("edge-platform")
        .join(".runtime")
        .join("local-runtime")
        .join("sing-box.exe")
}

fn local_runtime_paths_from_start(
    repo_root: &Path,
    request: &StartLocalRuntimeRequest,
) -> LocalRuntimePaths {
    LocalRuntimePaths {
        singbox_binary_path: request
            .singbox_binary_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| default_singbox_binary_path(repo_root)),
        config_path: request
            .config_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| default_local_config_path(repo_root)),
        state_path: request
            .state_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| default_live_state_path(repo_root)),
        runtime_root: default_runtime_root(repo_root),
    }
}

fn local_runtime_paths_from_restart(
    repo_root: &Path,
    request: &RestartLocalRuntimeRequest,
) -> LocalRuntimePaths {
    LocalRuntimePaths {
        singbox_binary_path: request
            .singbox_binary_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| default_singbox_binary_path(repo_root)),
        config_path: request
            .config_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| default_local_config_path(repo_root)),
        state_path: request
            .state_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| default_live_state_path(repo_root)),
        runtime_root: default_runtime_root(repo_root),
    }
}

fn merge_local_runtime(
    base: Option<edge_shared_types::LocalSingboxState>,
    observed: edge_shared_types::LocalSingboxState,
) -> edge_shared_types::LocalSingboxState {
    let Some(base) = base else {
        return observed;
    };

    let mut merged = observed;
    merged.managed_config = merged.managed_config || base.managed_config;
    merged.expected_config_path = base.expected_config_path;
    merged.clash_api_port = base.clash_api_port.or(merged.clash_api_port);
    if merged.active_config_path.is_none() {
        merged.active_config_path = base.active_config_path;
    }
    merged.warnings.extend(base.warnings);
    merged
}

async fn observe_selector_state(
    local_singbox: edge_shared_types::LocalSingboxState,
    base_selector: Option<SelectorState>,
    group: &str,
) -> SelectorState {
    let mut selector = base_selector.unwrap_or_else(SelectorState::placeholder);
    let Some(controller_url) = clash_controller_url(&local_singbox) else {
        selector.degraded = true;
        selector
            .warnings
            .push("clash API endpoint is not configured".to_owned());
        return selector;
    };

    match get_live_selector_state(&controller_url, group, default_aux_groups()).await {
        Ok(live) => merge_selector_state(selector, live),
        Err(err) => {
            selector.degraded = true;
            selector.warnings.push(err);
            selector
        }
    }
}

fn normalize_selector_group(group: Option<&str>) -> Result<&'static str, Status> {
    match group {
        Some(value) if value == UBUNTU_SELECTOR_GROUP => Ok(UBUNTU_SELECTOR_GROUP),
        Some(value) if value == DESKTOP_SELECTOR_GROUP => Ok(DESKTOP_SELECTOR_GROUP),
        Some(value) if value.trim().is_empty() => Ok(DESKTOP_SELECTOR_GROUP),
        None => Ok(DESKTOP_SELECTOR_GROUP),
        Some(value) => Err(Status::invalid_argument(format!(
            "unknown selector group: {value}"
        ))),
    }
}

fn selector_state_for_group<'a>(
    status: &'a ControllerStatus,
    group: &str,
) -> Option<&'a SelectorState> {
    if group == UBUNTU_SELECTOR_GROUP {
        status.ubuntu_selector.as_ref()
    } else {
        status.selector.as_ref()
    }
}

fn merge_selector_state(mut base: SelectorState, live: SelectorState) -> SelectorState {
    base.observed_main_route = live.observed_main_route;
    base.degraded = base.degraded || live.degraded;
    base.proxy_groups = live.proxy_groups;
    base.warnings.extend(live.warnings);
    base
}

fn clash_controller_url(local_singbox: &edge_shared_types::LocalSingboxState) -> Option<String> {
    local_singbox
        .clash_api_port
        .map(|port| format!("http://127.0.0.1:{port}"))
}

fn operation_with_status(operation: StoredOperation, status: &str) -> Operation {
    let typed_kind = operation_kind(&operation.kind);
    let phase = operation_phase(status);
    Operation {
        id: operation.id,
        kind: operation.kind,
        status: lifecycle_status(status) as i32,
        created_at_unix: operation.created_at_unix,
        typed_kind: typed_kind as i32,
        phase: phase as i32,
        created_at: Some(timestamp_from_unix_seconds(operation.created_at_unix)),
    }
}

fn lifecycle_status(value: &str) -> OperationLifecycleStatus {
    match value {
        "RUNNING" => OperationLifecycleStatus::Running,
        "SUCCEEDED" => OperationLifecycleStatus::Succeeded,
        "FAILED" => OperationLifecycleStatus::Failed,
        _ => OperationLifecycleStatus::Requested,
    }
}

fn operation_kind(value: &str) -> OperationKind {
    match value {
        "doctor" => OperationKind::Doctor,
        "deploy" => OperationKind::Deploy,
        "destroy" => OperationKind::Destroy,
        "start_local_runtime" => OperationKind::StartLocalRuntime,
        "stop_local_runtime" => OperationKind::StopLocalRuntime,
        "restart_local_runtime" => OperationKind::RestartLocalRuntime,
        "set_selector" => OperationKind::SetSelector,
        "bootstrap_runtime" => OperationKind::BootstrapRuntime,
        "production_plan" => OperationKind::ProductionPlan,
        "production_apply" => OperationKind::ProductionApply,
        "production_verify" => OperationKind::ProductionVerify,
        _ => OperationKind::Unspecified,
    }
}

fn operation_phase(status: &str) -> OperationPhase {
    match status {
        "RUNNING" => OperationPhase::Apply,
        "SUCCEEDED" | "FAILED" => OperationPhase::Completed,
        _ => OperationPhase::RequestedPhase,
    }
}

fn stored_operation_to_proto(operation: StoredOperation) -> Operation {
    let typed_kind = operation_kind(&operation.kind);
    let phase = operation_phase(&operation.status);
    Operation {
        id: operation.id,
        kind: operation.kind,
        status: lifecycle_status(&operation.status) as i32,
        created_at_unix: operation.created_at_unix,
        typed_kind: typed_kind as i32,
        phase: phase as i32,
        created_at: Some(timestamp_from_unix_seconds(operation.created_at_unix)),
    }
}

fn stored_event_to_proto(event: StoredOperationEvent) -> OperationEvent {
    OperationEvent {
        id: event.id,
        operation_id: event.operation_id,
        message: event.message,
        created_at_unix: event.created_at_unix,
        event_kind: OperationEventKind::LegacyMessage as i32,
        phase: OperationPhase::Unspecified as i32,
        occurred_at: Some(timestamp_from_unix_seconds(event.created_at_unix)),
        code: "legacy.message".to_owned(),
    }
}

fn append_operation_event(
    state: &Arc<Mutex<EdgeState>>,
    operation_id: i64,
    message: &str,
) -> Result<(), Status> {
    state
        .lock()
        .map_err(|_| Status::internal("controller state mutex poisoned"))?
        .append_operation_event(operation_id, message)
        .map_err(|err| Status::internal(format!("failed to append operation event: {err}")))?;
    Ok(())
}

fn update_operation_status(
    state: &Arc<Mutex<EdgeState>>,
    operation_id: i64,
    status: &str,
) -> Result<(), Status> {
    state
        .lock()
        .map_err(|_| Status::internal("controller state mutex poisoned"))?
        .update_operation_status(operation_id, status)
        .map_err(|err| Status::internal(format!("failed to update operation: {err}")))?;
    Ok(())
}

fn fail_destroy_operation(
    state: &Arc<Mutex<EdgeState>>,
    operation_id: i64,
    stage: &str,
    status: Status,
) -> Status {
    let note = format!("destroy failed at {stage}: {}", status.message());
    let _ = append_operation_event(state, operation_id, &note);
    let _ = update_operation_status(state, operation_id, "FAILED");
    status
}

fn store_local_response(
    state: &Arc<Mutex<EdgeState>>,
    kind: &str,
    payload: &[u8],
) -> Result<(), Status> {
    state
        .lock()
        .map_err(|_| Status::internal("controller state mutex poisoned"))?
        .store_local_observation(kind, payload)
        .map_err(|err| Status::internal(format!("failed to store local response: {err}")))?;
    Ok(())
}

fn interrupt_stale_running_operations(state: &Arc<Mutex<EdgeState>>) -> Result<(), String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    let running = guard
        .list_operations_by_status("RUNNING")
        .map_err(|err| format!("failed to list running operations: {err}"))?;
    for operation in running {
        guard
            .append_operation_event(
                operation.id,
                "controller restarted while operation was still RUNNING; marked as INTERRUPTED/FAILED",
            )
            .map_err(|err| format!("failed to append interrupted operation event: {err}"))?;
        guard
            .update_operation_status(operation.id, "FAILED")
            .map_err(|err| format!("failed to mark interrupted operation failed: {err}"))?;
    }
    Ok(())
}

fn reconcile_active_deployment_state(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
) -> Result<(), String> {
    let live_state_raw = read_live_state_raw(repo_root).ok().flatten();
    if live_state_raw.is_none() {
        return Ok(());
    }
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    let existing = guard
        .get_controller_state()
        .map_err(|err| format!("failed to read controller state: {err}"))?;
    if existing.as_ref().is_some_and(|value| {
        value.active_deployment_label.is_some()
            || value.active_instance_id.is_some()
            || value.active_server_ip.is_some()
            || value.active_deployment_state_json.is_some()
    }) {
        return Ok(());
    }

    let Some(latest) = guard
        .latest_deployment()
        .map_err(|err| format!("failed to read latest deployment: {err}"))?
    else {
        return Ok(());
    };

    let tunnel_domain = live_state_raw
        .as_deref()
        .map(parse_tunnel_domain_from_state_json)
        .transpose()?
        .flatten();
    guard
        .upsert_controller_state(NewControllerState {
            active_deployment_label: Some(&latest.deployment_label),
            active_instance_id: Some(&latest.instance_id),
            active_server_ip: Some(&latest.server_ip),
            active_tunnel_domain: tunnel_domain.as_deref(),
            active_deployment_state_json: live_state_raw.as_deref(),
            deploy_phase: DeployPhase::DeploymentPublished,
            app_readiness_phase: AppReadinessPhase::ServerRuntimeReady,
            last_error_code: None,
            last_error_message: None,
        })
        .map_err(|err| format!("failed to reconcile controller state: {err}"))?;
    Ok(())
}

fn is_allowed_selector_route(route: &str) -> bool {
    matches!(
        route,
        "auto-direct-tunnel"
            | "hysteria2-direct"
            | "vless-reality-direct"
            | "auto-warp-tunnel"
            | "hysteria2-warp"
            | "vless-reality-warp"
    )
}

async fn refresh_app_readiness_phase(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    local_singbox: &edge_shared_types::LocalSingboxState,
) -> Result<(), String> {
    let base_status = collect_controller_status(repo_root)
        .map_err(|err| format!("failed to collect controller status: {}", err.message))?;
    let desktop_selector = observe_selector_state(
        local_singbox.clone(),
        base_status.selector.clone(),
        DESKTOP_SELECTOR_GROUP,
    )
    .await;
    let ubuntu_selector = observe_selector_state(
        local_singbox.clone(),
        base_status.ubuntu_selector.clone(),
        UBUNTU_SELECTOR_GROUP,
    )
    .await;

    if !local_singbox.process_running {
        return upsert_app_readiness_phase(
            state,
            AppReadinessPhase::AppReadinessFailed,
            Some("local_runtime_not_running"),
            Some("local sing-box is not running"),
        );
    }
    if !selector_is_converged(&desktop_selector) || !selector_is_converged(&ubuntu_selector) {
        return upsert_app_readiness_phase(state, AppReadinessPhase::LocalRuntimeReady, None, None);
    }

    let desktop_proxy = default_trace_proxy_url(&default_local_config_path(repo_root))
        .ok()
        .flatten()
        .unwrap_or_else(|| DEFAULT_TRACE_PROXY_URL.to_owned());
    let desktop_trace = trace_via_proxy(&desktop_proxy).await;
    let ubuntu_trace = match base_status
        .ubuntu_proxy
        .as_ref()
        .and_then(|proxy| proxy.url.clone())
    {
        Some(url) => trace_via_proxy(&url).await,
        None => TraceObservation::unavailable("ubuntu proxy endpoint unavailable"),
    };
    if desktop_trace.available && ubuntu_trace.available {
        upsert_app_readiness_phase(state, AppReadinessPhase::AppReady, None, None)
    } else {
        upsert_app_readiness_phase(state, AppReadinessPhase::SelectorsReady, None, None)
    }
}

fn refresh_app_readiness_from_observed_status(
    state: &Arc<Mutex<EdgeState>>,
    status: &mut ControllerStatus,
) -> Result<(), Status> {
    let phase = if status
        .deployment
        .as_ref()
        .is_none_or(|deployment| !deployment.live_state_present)
    {
        AppReadinessPhase::DeploymentAbsent
    } else if status
        .local_singbox
        .as_ref()
        .is_none_or(|local| !local.process_running)
    {
        AppReadinessPhase::AppReadinessFailed
    } else if status
        .selector
        .as_ref()
        .is_none_or(|selector| !selector_is_converged(selector))
        || status
            .ubuntu_selector
            .as_ref()
            .is_none_or(|selector| !selector_is_converged(selector))
    {
        AppReadinessPhase::LocalRuntimeReady
    } else {
        AppReadinessPhase::AppReady
    };

    upsert_app_readiness_phase(state, phase, None, None)
        .map_err(|err| Status::internal(format!("failed to refresh app readiness: {err}")))?;
    status.app_readiness_phase = phase as i32;
    Ok(())
}

fn ubuntu_proxy_url_from_status(status: &ControllerStatus) -> Option<String> {
    status
        .ubuntu_proxy
        .as_ref()
        .and_then(|proxy| proxy.url.clone())
}

async fn wait_for_trace_via_proxy(proxy_url: &str, timeout_secs: u64) -> TraceObservation {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut last_observation = trace_via_proxy(proxy_url).await;
    if last_observation.available {
        return last_observation;
    }

    loop {
        if Instant::now() >= deadline {
            break;
        }
        sleep(Duration::from_secs(2)).await;
        last_observation = trace_via_proxy(proxy_url).await;
        if last_observation.available {
            return last_observation;
        }
    }

    if last_observation.available {
        return last_observation;
    }

    let timeout_note = match last_observation.note.clone() {
        Some(note) if !note.is_empty() => format!(
            "trace did not become available within {}s; last error: {}",
            timeout_secs, note
        ),
        _ => format!("trace did not become available within {}s", timeout_secs),
    };
    TraceObservation {
        note: Some(timeout_note),
        ..last_observation
    }
}

fn build_doctor_checks(
    repo_root: &Path,
    status: &ControllerStatus,
    desktop_trace: Option<&TraceObservation>,
    ubuntu_trace: Option<&TraceObservation>,
    request: &DoctorRequest,
) -> Vec<DoctorCheck> {
    let deployment = status.deployment.as_ref();
    let runtime = status.runtime.as_ref();
    let local = status.local_singbox.as_ref();
    let selector = status.selector.as_ref();
    let ubuntu_selector = status.ubuntu_selector.as_ref();
    let ubuntu_proxy = status.ubuntu_proxy.as_ref();
    let live_state_artifact_present = live_state_artifact_present(repo_root);

    let mut checks = vec![
        DoctorCheck {
            name: "state.active_deployment_present".to_owned(),
            ok: deployment.is_some_and(|value| value.live_state_present),
            detail: deployment
                .and_then(|value| value.deployment_label.clone())
                .unwrap_or_else(|| "no active deployment".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        },
        DoctorCheck {
            name: "state.git_selector_defaults_observed".to_owned(),
            ok: selector
                .and_then(|value| value.desired_main_route.as_ref())
                .is_some()
                && ubuntu_selector
                    .and_then(|value| value.desired_main_route.as_ref())
                    .is_some(),
            detail:
                "Git-owned desktop and WSL route defaults must be present in the rendered config"
                    .to_owned(),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        },
        DoctorCheck {
            name: "state.live_state_artifact_present".to_owned(),
            ok: live_state_artifact_present,
            detail: default_live_state_path(repo_root).display().to_string(),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        },
        DoctorCheck {
            name: "local.singbox_running".to_owned(),
            ok: local.is_some_and(|value| value.process_running),
            detail: local
                .map(|value| value.warnings.join("; "))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "local sing-box runtime inspected".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        },
        DoctorCheck {
            name: "selector.desktop_converged".to_owned(),
            ok: selector.is_some_and(|value| {
                value.desired_main_route.is_some()
                    && value.desired_main_route == value.observed_main_route
                    && !value.degraded
            }),
            detail: selector
                .map(|value| {
                    format!(
                        "desired={:?}, observed={:?}",
                        value.desired_main_route, value.observed_main_route
                    )
                })
                .unwrap_or_else(|| "desktop selector state unavailable".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        },
        DoctorCheck {
            name: "selector.ubuntu_converged".to_owned(),
            ok: ubuntu_selector.is_some_and(|value| {
                value.desired_main_route.is_some()
                    && value.desired_main_route == value.observed_main_route
                    && !value.degraded
            }),
            detail: ubuntu_selector
                .map(|value| {
                    format!(
                        "desired={:?}, observed={:?}",
                        value.desired_main_route, value.observed_main_route
                    )
                })
                .unwrap_or_else(|| "ubuntu selector state unavailable".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        },
        DoctorCheck {
            name: "ubuntu.proxy_available".to_owned(),
            ok: ubuntu_proxy.is_some_and(|value| value.available),
            detail: ubuntu_proxy
                .and_then(|value| value.url.clone())
                .unwrap_or_else(|| "ubuntu proxy URL unavailable".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        },
    ];

    if !is_installed_windows_root(repo_root) {
        checks.push(DoctorCheck {
            name: "server.edge_agent_reachable".to_owned(),
            ok: runtime.is_some_and(|value| value.edge_agent_reachable),
            detail: runtime
                .map(|value| value.warnings.join("; "))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "edge-agent status unavailable".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        });
    }

    if request.require_server_ready && !is_installed_windows_root(repo_root) {
        checks.push(DoctorCheck {
            name: "server.runtime_ready".to_owned(),
            ok: runtime.is_some_and(|value| {
                value.edge_agent_reachable
                    && value.docker_reachable
                    && value.compose_file_present
                    && value.missing_containers.is_empty()
            }),
            detail: runtime
                .map(|value| {
                    format!(
                        "docker={}, compose={}, missing={}",
                        value.docker_reachable,
                        value.compose_file_present,
                        value.missing_containers.join(", ")
                    )
                })
                .unwrap_or_else(|| "server runtime unavailable".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        });
    }
    if request.require_local_runtime {
        checks.push(DoctorCheck {
            name: "local.managed_config_active".to_owned(),
            ok: local.is_some_and(|value| value.managed_config),
            detail: local
                .and_then(|value| value.active_config_path.clone())
                .unwrap_or_else(|| "active local config unavailable".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        });
    }
    if request.require_egress_traces {
        checks.push(DoctorCheck {
            name: "egress.desktop_trace_available".to_owned(),
            ok: desktop_trace.is_some_and(|value| value.available),
            detail: desktop_trace
                .and_then(|value| value.ip.clone())
                .or_else(|| desktop_trace.and_then(|value| value.note.clone()))
                .unwrap_or_else(|| "desktop trace unavailable".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        });
        checks.push(DoctorCheck {
            name: "egress.ubuntu_trace_available".to_owned(),
            ok: ubuntu_trace.is_some_and(|value| value.available),
            detail: ubuntu_trace
                .and_then(|value| value.ip.clone())
                .or_else(|| ubuntu_trace.and_then(|value| value.note.clone()))
                .unwrap_or_else(|| "ubuntu trace unavailable".to_owned()),

            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        });
    }

    for check in &mut checks {
        enrich_doctor_check(check);
    }
    checks
}

fn enrich_doctor_check(check: &mut DoctorCheck) {
    check.check_id = check.name.clone();
    check.status = if check.ok {
        CheckStatus::Pass as i32
    } else {
        CheckStatus::Fail as i32
    };
    check.subsystem = diagnostic_subsystem(&check.name) as i32;
    check.evidence = vec![DiagnosticEvidence {
        code: format!("{}.{}", check.name, if check.ok { "pass" } else { "fail" }),
        summary: if check.ok {
            "bounded diagnostic check passed".to_owned()
        } else {
            "bounded diagnostic check failed".to_owned()
        },
    }];
}

fn diagnostic_subsystem(check_id: &str) -> DiagnosticSubsystem {
    if check_id.starts_with("state.") {
        DiagnosticSubsystem::DiagnosticState
    } else if check_id.starts_with("server.") {
        DiagnosticSubsystem::ServerRuntime
    } else if check_id.starts_with("local.") {
        DiagnosticSubsystem::LocalRuntime
    } else if check_id.starts_with("selector.") || check_id.starts_with("ubuntu.") {
        DiagnosticSubsystem::Selector
    } else if check_id.starts_with("egress.") {
        DiagnosticSubsystem::Egress
    } else {
        DiagnosticSubsystem::Unspecified
    }
}

fn selector_is_converged(selector: &SelectorState) -> bool {
    selector.desired_main_route.is_some()
        && selector.desired_main_route == selector.observed_main_route
        && !selector.degraded
}

fn upsert_app_readiness_phase(
    state: &Arc<Mutex<EdgeState>>,
    app_readiness_phase: AppReadinessPhase,
    last_error_code: Option<&str>,
    last_error_message: Option<&str>,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?
        .update_app_readiness_phase(AppReadinessUpdate {
            app_readiness_phase,
            last_error_code,
            last_error_message,
        })
        .map_err(|err| format!("failed to update app readiness phase: {err}"))?;
    Ok(())
}

fn upsert_controller_phases_with_journal(
    state: &Arc<Mutex<EdgeState>>,
    deploy_phase: DeployPhase,
    app_readiness_phase: AppReadinessPhase,
    last_error_code: Option<&str>,
    last_error_message: Option<&str>,
    journal: Option<OperationJournalUpdate<'_>>,
) -> Result<(), String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    let existing = guard
        .get_controller_state()
        .map_err(|err| format!("failed to read controller state: {err}"))?;
    if let Some(current) = existing.as_ref()
        && current.deploy_phase != deploy_phase
    {
        validate_deploy_transition(current.deploy_phase, deploy_phase)
            .map_err(|err| format!("invalid controller phase transition: {}", err.message))?;
    }
    guard
        .transition_controller_state_with_operation(ControllerStateTransition {
            deploy_phase,
            app_readiness_phase,
            last_error_code,
            last_error_message,
            journal,
        })
        .map_err(|err| format!("failed to update controller state phases: {err}"))?;
    Ok(())
}

fn agent_endpoint_from_env() -> String {
    env::var("EDGE_AGENT_ENDPOINT").unwrap_or_else(|_| DEFAULT_AGENT_ENDPOINT.to_owned())
}

async fn observe_agent(
    state: &Arc<Mutex<EdgeState>>,
    default_endpoint: &str,
) -> (AgentState, RuntimeObservation) {
    let target = match resolve_agent_connection_target(state, default_endpoint) {
        Ok(target) => target,
        Err(err) => {
            let agent_state = AgentState {
                healthy: false,
                ready: false,
                topology_version: "agent-target-resolution-failed".to_owned(),
                active_bundle_id: None,
                degraded_reasons: vec![err.clone()],
                docker_reachable: false,
                compose_file_present: false,
                observed_stack_path: None,
                running_containers: Vec::new(),
                missing_containers: Vec::new(),
                listening_tcp_ports: Vec::new(),
                listening_udp_ports: Vec::new(),
                direct_egress_ready: None,
                warp_egress_ready: None,
                mesh_runtime_ready: None,
                containers: Vec::new(),
            };
            return (agent_state, RuntimeObservation::agent_unreachable(err));
        }
    };

    let Ok(channel) = connect_to_agent_target(&target).await else {
        let reason = format!("edge-agent is unreachable at {}", target.endpoint);
        let agent_state = AgentState {
            healthy: false,
            ready: false,
            topology_version: "unreachable".to_owned(),
            active_bundle_id: None,
            degraded_reasons: vec![reason.clone()],
            docker_reachable: false,
            compose_file_present: false,
            observed_stack_path: None,
            running_containers: Vec::new(),
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            direct_egress_ready: None,
            warp_egress_ready: None,
            mesh_runtime_ready: None,
            containers: Vec::new(),
        };
        return (agent_state, RuntimeObservation::agent_unreachable(reason));
    };
    let mut client = AgentServiceClient::<Channel>::new(channel);

    let health = client.get_health(Request::new(Empty {})).await;
    let readiness = client.get_readiness(Request::new(Empty {})).await;
    let runtime = client.get_runtime_state(Request::new(Empty {})).await;
    let version = client.get_version(Request::new(Empty {})).await;

    let Ok(runtime_response) = runtime else {
        let reason = format!("edge-agent runtime RPC failed at {}", target.endpoint);
        let agent_state = AgentState {
            healthy: false,
            ready: false,
            topology_version: "runtime-rpc-failed".to_owned(),
            active_bundle_id: None,
            degraded_reasons: vec![reason.clone()],
            docker_reachable: false,
            compose_file_present: false,
            observed_stack_path: None,
            running_containers: Vec::new(),
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            direct_egress_ready: None,
            warp_egress_ready: None,
            mesh_runtime_ready: None,
            containers: Vec::new(),
        };
        return (agent_state, RuntimeObservation::agent_unreachable(reason));
    };

    let mut agent_state = runtime_response.into_inner();
    if let Ok(health_response) = health {
        agent_state.healthy = health_response.into_inner().healthy;
    }
    if let Ok(readiness_response) = readiness {
        agent_state.ready = readiness_response.into_inner().ready;
    }
    if let Ok(version_response) = version {
        agent_state.topology_version = format!(
            "{}@{}",
            agent_state.topology_version,
            version_response.into_inner().version
        );
    }

    let runtime = RuntimeObservation::from_agent_state(&agent_state);
    (agent_state, runtime)
}

async fn connect_to_agent_target(
    target: &AgentConnectionTarget,
) -> Result<Channel, Box<dyn std::error::Error>> {
    let tls = match &target.tls_paths {
        Some(paths) => Some(agent_client_tls_from_paths(paths).map_err(|err| {
            format!("failed to load persisted controller TLS configuration: {err}")
        })?),
        None => optional_agent_client_tls_from_env()
            .map_err(|err| format!("failed to load controller TLS configuration: {err}"))?,
    };
    let endpoint = agent_endpoint_scheme(&target.endpoint, tls.is_some());
    let mut transport = Endpoint::from_shared(endpoint)?;
    if let Some(tls) = tls {
        transport = transport.tls_config(tls)?;
    }
    Ok(transport.connect().await?)
}

fn resolve_agent_connection_target(
    state: &Arc<Mutex<EdgeState>>,
    default_endpoint: &str,
) -> Result<AgentConnectionTarget, String> {
    if env::var_os("EDGE_AGENT_ENDPOINT").is_some() || default_endpoint != DEFAULT_AGENT_ENDPOINT {
        return Ok(AgentConnectionTarget {
            endpoint: default_endpoint.to_owned(),
            tls_paths: None,
        });
    }

    if let Some(target) = resolve_persisted_agent_connection_target(state)? {
        return Ok(target);
    }

    Ok(AgentConnectionTarget {
        endpoint: default_endpoint.to_owned(),
        tls_paths: None,
    })
}

fn resolve_persisted_agent_connection_target(
    state: &Arc<Mutex<EdgeState>>,
) -> Result<Option<AgentConnectionTarget>, String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    if let Some(controller) = guard
        .get_controller_state()
        .map_err(|err| format!("failed to load controller state: {err}"))?
        && let (Some(instance_id), Some(server_ip)) = (
            controller.active_instance_id.as_deref(),
            controller.active_server_ip.as_deref(),
        )
    {
        if let Some(trust) = guard
            .find_latest_trust_entry(instance_id, server_ip)
            .map_err(|err| format!("failed to load persisted trust entry: {err}"))?
        {
            let deployment = StoredDeployment {
                id: 0,
                deployment_label: controller
                    .active_deployment_label
                    .clone()
                    .unwrap_or_else(|| trust.deployment_id.clone()),
                instance_id: instance_id.to_owned(),
                server_ip: server_ip.to_owned(),
                created_at_unix: trust.updated_at_unix,
            };
            drop(guard);
            return persisted_agent_connection_target(&deployment, &trust).map(Some);
        }

        let remote_port = env::var("EDGE_AGENT_REMOTE_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(DEFAULT_AGENT_REMOTE_PORT);
        return Err(format!(
            "no persisted agent trust for active deployment {} ({instance_id}, {server_ip}); expected edge-agent target https://{server_ip}:{remote_port}",
            controller
                .active_deployment_label
                .unwrap_or_else(|| "<unknown>".to_owned())
        ));
    }
    let Some(deployment) = guard
        .latest_deployment()
        .map_err(|err| format!("failed to load latest deployment: {err}"))?
    else {
        return Ok(None);
    };
    let Some(trust) = guard
        .get_trust_entry(
            &deployment.deployment_label,
            &deployment.instance_id,
            &deployment.server_ip,
        )
        .map_err(|err| format!("failed to load persisted trust entry: {err}"))?
    else {
        return Ok(None);
    };
    drop(guard);

    persisted_agent_connection_target(&deployment, &trust).map(Some)
}

fn resolve_targeted_agent_connection_target(
    state: &Arc<Mutex<EdgeState>>,
    instance_id: &str,
    target_ip: &str,
) -> Result<Option<AgentConnectionTarget>, String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    let Some(trust) = guard
        .find_latest_trust_entry(instance_id, target_ip)
        .map_err(|err| format!("failed to load targeted trust entry: {err}"))?
    else {
        return Ok(None);
    };
    let deployment = StoredDeployment {
        id: 0,
        deployment_label: trust.deployment_id.clone(),
        instance_id: trust.instance_id.clone(),
        server_ip: trust.ip.clone(),
        created_at_unix: trust.updated_at_unix,
    };
    drop(guard);

    persisted_agent_connection_target(&deployment, &trust).map(Some)
}

fn resolve_targeted_agent_connection_target_for_endpoint(
    state: &Arc<Mutex<EdgeState>>,
    instance_id: &str,
    target_ip: &str,
    endpoint: &str,
) -> Result<Option<AgentConnectionTarget>, String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    let Some(trust) = guard
        .find_latest_trust_entry(instance_id, target_ip)
        .map_err(|err| format!("failed to load targeted trust entry: {err}"))?
    else {
        return Ok(None);
    };
    let tls_paths = persisted_agent_tls_paths(&trust)?;
    Ok(Some(AgentConnectionTarget {
        endpoint: endpoint.to_owned(),
        tls_paths,
    }))
}

fn retarget_agent_connection_target(
    target: &AgentConnectionTarget,
    endpoint: String,
) -> AgentConnectionTarget {
    AgentConnectionTarget {
        endpoint,
        tls_paths: target.tls_paths.clone(),
    }
}

fn persisted_agent_connection_target(
    deployment: &StoredDeployment,
    trust: &StoredTrustEntry,
) -> Result<AgentConnectionTarget, String> {
    let tls_paths = persisted_agent_tls_paths(trust)?.ok_or_else(|| {
        format!(
            "persisted trust entry for {} is missing client TLS material",
            deployment.instance_id
        )
    })?;
    let remote_port = env::var("EDGE_AGENT_REMOTE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_AGENT_REMOTE_PORT);
    Ok(AgentConnectionTarget {
        endpoint: format!("https://{}:{remote_port}", deployment.server_ip),
        tls_paths: Some(tls_paths),
    })
}

fn persisted_agent_tls_paths(
    trust: &StoredTrustEntry,
) -> Result<Option<AgentClientTlsPaths>, String> {
    match (
        trust.ca_cert_path.as_deref(),
        trust.client_cert_path.as_deref(),
        trust.client_key_path.as_deref(),
    ) {
        (Some(ca_cert_path), Some(client_cert_path), Some(client_key_path)) => {
            Ok(Some(AgentClientTlsPaths {
                ca_cert_path: PathBuf::from(ca_cert_path),
                client_cert_path: PathBuf::from(client_cert_path),
                client_key_path: PathBuf::from(client_key_path),
                domain_name: trust
                    .domain_name
                    .clone()
                    .unwrap_or_else(|| "edge-agent".to_owned()),
            }))
        }
        (None, None, None) => Ok(None),
        _ => Err(format!(
            "persisted trust entry for deployment {} has incomplete client TLS paths",
            trust.deployment_id
        )),
    }
}

fn require_nonrestarting_start(force_restart: bool) -> Result<(), Status> {
    if force_restart {
        Err(Status::failed_precondition(
            "StartLocalRuntime never restarts a managed process; use the explicit RestartLocalRuntime operation",
        ))
    } else {
        Ok(())
    }
}

fn platform_error_to_status(err: PlatformError) -> Status {
    Status::internal(format!("{} [{}]: {}", err.code, err.stage, err.message))
}

#[cfg(test)]
mod legacy_windows_rpc_boundary_tests {
    use super::*;

    #[test]
    fn windows_legacy_rpc_mutations_are_denied() {
        assert!(matches!(
            deny_legacy_windows_rpc_mutation(),
            Err(status) if status.code() == tonic::Code::PermissionDenied
        ));
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
