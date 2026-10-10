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
    WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS, WindowsDatapathMode,
    canonical_production_desired_state, decode_windows_runtime_state, timestamp_from_unix_seconds,
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
        Command::ControllerBootstrapRuntime(args) => {
            let response = controller_bootstrap_runtime(
                cli::controller_endpoint(args.endpoint),
                args.mode.into(),
            )
            .await?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(ControllerError::Command(format_bootstrap_failure(
                    &response,
                )))
            }
        }
        Command::BootstrapRuntime(args) => {
            let response = bootstrap_runtime(cli::agent_endpoint(args.endpoint), args.mode.into())
                .await
                .map_err(ControllerError::Command)?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(ControllerError::Command(format_bootstrap_failure(
                    &response,
                )))
            }
        }
        Command::StartLocal(args) => {
            let response = start_local_runtime_via_controller(args.resolve()).await?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(ControllerError::Command(response.note))
            }
        }
        Command::StopLocal(args) => {
            let response = stop_local_runtime_via_controller(args.resolve()).await?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(ControllerError::Command(response.note))
            }
        }
        Command::RestartLocal(args) => {
            let response = restart_local_runtime_via_controller(args.resolve()).await?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(ControllerError::Command(response.note))
            }
        }
        Command::GetSelector(args) => {
            let selector = fetch_selector_state(args.resolve()).await?;
            io::stdout().write_all(&selector.encode_to_vec())?;
            Ok(())
        }
        Command::SetSelector(args) => {
            let response = set_selector_via_controller(
                cli::controller_endpoint(args.endpoint),
                "proxy-selector",
                &args.name,
            )
            .await?;
            io::stdout().write_all(&response.encode_to_vec())?;
            if response.success {
                Ok(())
            } else {
                Err(ControllerError::Command(
                    "selector update failed".to_owned(),
                ))
            }
        }
        Command::Trace(args) => {
            let trace = get_trace_via_controller(args.resolve()).await?;
            io::stdout().write_all(&trace.encode_to_vec())?;
            Ok(())
        }
        Command::Deploy(args) => {
            let (request, endpoint) = args.into_parts();
            let response = deploy_via_controller(endpoint, request).await?;
            io::stdout().write_all(&response.encode_to_vec())?;
            if response.success {
                Ok(())
            } else {
                Err(ControllerError::Command("deploy failed".to_owned()))
            }
        }
        Command::Destroy(args) => {
            let (request, endpoint) = args.into_parts();
            let response = destroy_via_controller(endpoint, request).await?;
            io::stdout().write_all(&response.encode_to_vec())?;
            if response.success {
                Ok(())
            } else {
                Err(ControllerError::Command("destroy failed".to_owned()))
            }
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
async fn supervise_windows_managed_child(repo_root: PathBuf) -> Result<(), String> {
    if !is_installed_windows_root(&repo_root) {
        return Ok(());
    }
    let config_path = default_local_config_path(&repo_root);
    if !windows_runtime_state_path(&repo_root).is_file() || !config_path.is_file() {
        return Ok(());
    }
    let initial = exact_managed_runtime_processes(&config_path);
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
        tokio::task::spawn_blocking(move || wait_for_windows_child_exit(pid))
            .await
            .map_err(|err| format!("native child wait join failed: {err}"))??;

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
            None => return Ok(()),
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
    // The exact privileged request exists BEFORE its intended sing-box stop
    // and remains until successful SCM handoff (or a recorded failure).
    if repo_root
        .join("exchange/requests/request.pb")
        .try_exists()
        .map_err(|err| format!("cannot verify privileged handoff state: {err}"))?
        || read_windows_privileged_result_marker(repo_root)?.as_deref()
            != prior_privileged_result
    {
        return Ok(None);
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
                let _ = stop_runtime_process(&default_local_config_path(&config.repo_root), true);
                return Err(startup_failure(
                    "runtime_converge",
                    format!("Windows managed runtime startup convergence failed: {err}"),
                ));
            }

            if let Err(err) = clear_controller_service_error(&config.repo_root) {
                let _ = stop_runtime_process(&default_local_config_path(&config.repo_root), true);
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
                let _ = stop_runtime_process(&default_local_config_path(&config.repo_root), true);
                return Err(startup_failure("scm_running", err.to_string()));
            }

            let repo_root = config.repo_root.clone();
            // An OS process-handle wait, not a timer or a second Windows owner.
            // The controller's own child is supervised while this SCM service runs.
            let supervisor_root = repo_root.clone();
            let supervisor = runtime.spawn(async move {
                if let Err(err) = supervise_windows_managed_child(supervisor_root.clone()).await {
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
            let cleanup_result = {
                let _gate = WINDOWS_RUNTIME_OWNER_GATE
                    .lock()
                    .map_err(|_| "Windows runtime owner gate poisoned")?;
                stop_runtime_process(&default_local_config_path(&repo_root), true)
            }
            .map(|_| ())
            .map_err(|err| {
                format!("failed to stop exact managed runtime on controller exit: {err}")
            });

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
    StartAbsent,
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
                    WindowsStartupDecision::RestartOrphanManaged
                }
            }
            RuntimeProcessClassification::Conflicting(_) => WindowsStartupDecision::BlockedConflict,
            RuntimeProcessClassification::Absent => WindowsStartupDecision::StartAbsent,
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

#[tonic::async_trait]
impl ControllerService for ControllerServerImpl {
    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ControllerStatus>, Status> {
        let reconcile_warning = if is_installed_windows_root(&self.repo_root) {
            None
        } else {
            reconcile_active_deployment_state(&self.repo_root, &self.state)
                .err()
                .map(|err| format!("local deployment-state reconciliation unavailable: {err}"))
        };
        let mut status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let backend_ready_from_state = status
            .deployment
            .as_ref()
            .is_some_and(|deployment| deployment.live_state_present);
        let live_state_artifact_present = live_state_artifact_present(&self.repo_root);

        if is_installed_windows_root(&self.repo_root) {
            // Persistent Windows runtime ownership is local to EdgePlatformController.
            // The retired server-agent RPC endpoint is not a Windows health dependency.
            status.agent_state = None;
            status.runtime = None;
        } else {
            let (agent_state, runtime) = observe_agent(&self.state, &self.agent_endpoint).await;
            if !agent_state.ready && !backend_ready_from_state {
                status
                    .status_notes
                    .push("server agent has not reached runtime readiness".to_owned());
            }
            if !runtime.edge_agent_reachable && !backend_ready_from_state {
                status.status_notes.push(
                    "server runtime observation is running in degraded fallback mode".to_owned(),
                );
            } else if !runtime.edge_agent_reachable && backend_ready_from_state {
                status.status_notes.push(
                    "server runtime observation is unavailable; using persisted live deployment state"
                        .to_owned(),
                );
            }
            status.agent_state = Some(agent_state);
            status.runtime = Some(runtime);
        }
        if backend_ready_from_state && !live_state_artifact_present {
            status.status_notes.push(
                if is_installed_windows_root(&self.repo_root) {
                    "typed Windows runtime-state.pb is missing; start-local cannot be trusted"
                } else {
                    "legacy local runtime artifact current-edge.json is missing; start-local cannot be trusted"
                }
                .to_owned(),
            );
        }

        let local_config_path = default_local_config_path(&self.repo_root);
        let merged_local = merge_local_runtime(
            status.local_singbox.take(),
            inspect_local_runtime(&local_config_path),
        );
        let merged_selector = observe_selector_state(
            merged_local.clone(),
            status.selector.take(),
            DESKTOP_SELECTOR_GROUP,
        )
        .await;
        let merged_ubuntu_selector = observe_selector_state(
            merged_local.clone(),
            status.ubuntu_selector.take(),
            UBUNTU_SELECTOR_GROUP,
        )
        .await;
        status.local_singbox = Some(merged_local);
        status.selector = Some(merged_selector);
        status.ubuntu_selector = Some(merged_ubuntu_selector);
        refresh_app_readiness_from_observed_status(&self.state, &mut status)?;
        if let Some(warning) = reconcile_warning {
            status.status_notes.push(warning);
        }

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("controller_status", &status.encode_proto())
            .map_err(|err| Status::internal(format!("failed to store status snapshot: {err}")))?;

        Ok(Response::new(status))
    }

    async fn doctor(
        &self,
        request: Request<DoctorRequest>,
    ) -> Result<Response<DoctorResponse>, Status> {
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("doctor", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "doctor requested")?;

        let status = self.get_status(Request::new(Empty {})).await?.into_inner();
        let desktop_trace = if request.require_egress_traces {
            Some(
                trace_via_proxy(
                    &default_trace_proxy_url(&default_local_config_path(&self.repo_root))
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| DEFAULT_TRACE_PROXY_URL.to_owned()),
                )
                .await,
            )
        } else {
            None
        };
        let ubuntu_trace = if request.require_egress_traces {
            match ubuntu_proxy_url_from_status(&status) {
                Some(url) => Some(trace_via_proxy(&url).await),
                None => Some(TraceObservation::unavailable(
                    "ubuntu proxy endpoint is not available in controller status",
                )),
            }
        } else {
            None
        };

        let checks = build_doctor_checks(
            &self.repo_root,
            &status,
            desktop_trace.as_ref(),
            ubuntu_trace.as_ref(),
            &request,
        );
        let ok = checks.iter().all(|check| check.ok);
        append_operation_event(
            &self.state,
            operation.id,
            if ok {
                "doctor completed: all checks passed"
            } else {
                "doctor completed: one or more checks failed"
            },
        )?;
        update_operation_status(
            &self.state,
            operation.id,
            if ok { "SUCCEEDED" } else { "FAILED" },
        )?;

        Ok(Response::new(DoctorResponse {
            ok,
            checks,
            status: Some(status),
            desktop_trace,
            ubuntu_trace,
            operation: Some(operation_with_status(
                operation,
                if ok { "SUCCEEDED" } else { "FAILED" },
            )),
        }))
    }

    async fn get_secret_ref(
        &self,
        request: Request<GetSecretRefRequest>,
    ) -> Result<Response<SecretRefEntry>, Status> {
        let name = request.into_inner().name;
        validate_secret_name(&name)?;
        let default_ref = default_env_ref(secret_name_to_env(&name));
        let secret_ref =
            get_or_seed_secret_ref(&self.state, &name, &default_ref).map_err(|err| {
                Status::internal(format!("failed to resolve secret ref {name}: {err}"))
            })?;
        let entry = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .get_secret_ref(&name)
            .map_err(|err| Status::internal(format!("failed to read secret ref {name}: {err}")))?
            .map(|value| SecretRefEntry {
                name: value.name,
                secret_ref: value.secret_ref,
                updated_at_unix: value.updated_at_unix,
            })
            .unwrap_or(SecretRefEntry {
                name,
                secret_ref,
                updated_at_unix: 0,
            });
        Ok(Response::new(entry))
    }

    async fn set_secret_ref(
        &self,
        request: Request<SetSecretRefRequest>,
    ) -> Result<Response<SecretRefEntry>, Status> {
        let request = request.into_inner();
        validate_secret_name(&request.name)?;
        edge_secrets::parse_secret_reference(&request.secret_ref)
            .map_err(Status::invalid_argument)?;
        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .upsert_secret_ref(&request.name, &request.secret_ref)
            .map_err(|err| Status::internal(format!("failed to store secret ref: {err}")))?;
        let stored = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .get_secret_ref(&request.name)
            .map_err(|err| Status::internal(format!("failed to reload secret ref: {err}")))?
            .ok_or_else(|| Status::internal("stored secret ref is missing"))?;
        Ok(Response::new(SecretRefEntry {
            name: stored.name,
            secret_ref: stored.secret_ref,
            updated_at_unix: stored.updated_at_unix,
        }))
    }

    async fn list_secret_refs(
        &self,
        _request: Request<ListSecretRefsRequest>,
    ) -> Result<Response<ListSecretRefsResponse>, Status> {
        Ok(Response::new(ListSecretRefsResponse {
            secrets: list_secret_refs(&self.state)?,
        }))
    }

    async fn bootstrap_runtime(
        &self,
        request: Request<BootstrapRuntimeRequest>,
    ) -> Result<Response<BootstrapRuntimeResponse>, Status> {
        let mode = BootstrapMode::try_from(request.into_inner().mode)
            .map_err(|_| Status::invalid_argument("unknown bootstrap mode"))?;
        if mode == BootstrapMode::Unspecified {
            return Err(Status::invalid_argument("bootstrap mode is required"));
        }

        let target = resolve_agent_connection_target(&self.state, &self.agent_endpoint)
            .map_err(|err| Status::internal(format!("failed to resolve agent target: {err}")))?;
        let response = bootstrap_runtime_with_tls(target, mode)
            .await
            .map_err(|err| Status::internal(format!("agent bootstrap RPC failed: {err}")))?;

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("bootstrap_runtime_response", &response.encode_proto())
            .map_err(|err| {
                Status::internal(format!(
                    "failed to store bootstrap response snapshot: {err}"
                ))
            })?;

        Ok(Response::new(response))
    }

    async fn start_local_runtime(
        &self,
        request: Request<StartLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        let request = request.into_inner();
        require_nonrestarting_start(request.force_restart)?;
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("start_local_runtime", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "start local runtime requested")?;

        let (agent_state, _) = observe_agent(&self.state, &self.agent_endpoint).await;
        if !agent_state.ready && !backend_ready_for_local_runtime(&self.repo_root) {
            append_operation_event(
                &self.state,
                operation.id,
                "backend is not ready; refusing to start local runtime",
            )?;
            update_operation_status(&self.state, operation.id, "FAILED")?;
            let local_singbox = inspect_local_runtime(&default_local_config_path(&self.repo_root));
            return Ok(Response::new(LocalRuntimeResponse {
                success: false,
                pid: None,
                note: "backend is not ready; local runtime start refused".to_owned(),
                warnings: vec!["server runtime is not ready".to_owned()],
                operation: Some(operation_with_status(operation, "FAILED")),
                local_singbox: Some(local_singbox),
            }));
        }

        let paths = local_runtime_paths_from_start(&self.repo_root, &request);
        #[cfg(windows)]
        let started = {
            let _owner_gate = WINDOWS_RUNTIME_OWNER_GATE
                .lock()
                .map_err(|_| Status::internal("Windows runtime owner gate poisoned"))?;
            if self.repo_root.join("exchange/requests/request.pb").exists() {
                return Err(Status::failed_precondition(
                    "privileged release handoff pending: refusing competing runtime start",
                ));
            }
            start_runtime_process(&paths, request.visible_window)
        };
        #[cfg(not(windows))]
        let started = start_runtime_process(&paths, request.visible_window);
        let response = match started {
            Ok(mut result) => {
                let _ = refresh_app_readiness_phase(
                    &self.repo_root,
                    &self.state,
                    &result.local_singbox,
                )
                .await;
                let observed_after_start = inspect_local_runtime(&paths.config_path);
                if !observed_after_start.process_running {
                    result
                        .warnings
                        .push("local sing-box stopped before start operation completed".to_owned());
                    result
                        .warnings
                        .extend(observed_after_start.warnings.clone());
                    append_operation_event(
                        &self.state,
                        operation.id,
                        "local sing-box stopped before start operation completed",
                    )?;
                    update_operation_status(&self.state, operation.id, "FAILED")?;
                    LocalRuntimeResponse {
                        success: false,
                        pid: result.pid,
                        note: "local sing-box stopped before start operation completed".to_owned(),
                        warnings: result.warnings,
                        operation: Some(operation_with_status(operation, "FAILED")),
                        local_singbox: Some(observed_after_start),
                    }
                } else {
                    result.local_singbox = observed_after_start;
                    append_operation_event(&self.state, operation.id, &result.note)?;
                    update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
                    LocalRuntimeResponse {
                        success: true,
                        pid: result.pid,
                        note: result.note,
                        warnings: result.warnings,
                        operation: Some(operation_with_status(operation, "SUCCEEDED")),
                        local_singbox: Some(result.local_singbox),
                    }
                }
            }
            Err(err) => {
                append_operation_event(&self.state, operation.id, &err)?;
                update_operation_status(&self.state, operation.id, "FAILED")?;
                let local_singbox = inspect_local_runtime(&paths.config_path);
                LocalRuntimeResponse {
                    success: false,
                    pid: None,
                    note: err,
                    warnings: local_singbox.warnings.clone(),
                    operation: Some(operation_with_status(operation, "FAILED")),
                    local_singbox: Some(local_singbox),
                }
            }
        };

        store_local_response(
            &self.state,
            "start_local_runtime_response",
            &response.encode_proto(),
        )?;
        Ok(Response::new(response))
    }

    async fn stop_local_runtime(
        &self,
        request: Request<StopLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        #[cfg(windows)]
        edge_local_runtime::reject_unproven_windows_tun_teardown("stop-local")
            .map_err(Status::failed_precondition)?;
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("stop_local_runtime", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "stop local runtime requested")?;

        let config_path = request
            .config_path
            .map(PathBuf::from)
            .unwrap_or_else(|| default_local_config_path(&self.repo_root));
        let response = match stop_runtime_process(&config_path, request.expected_config_only) {
            Ok(result) => {
                append_operation_event(&self.state, operation.id, &result.note)?;
                update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
                LocalRuntimeResponse {
                    success: true,
                    pid: result.pid,
                    note: result.note,
                    warnings: result.warnings,
                    operation: Some(operation_with_status(operation, "SUCCEEDED")),
                    local_singbox: Some(result.local_singbox),
                }
            }
            Err(err) => {
                append_operation_event(&self.state, operation.id, &err)?;
                update_operation_status(&self.state, operation.id, "FAILED")?;
                let local_singbox = inspect_local_runtime(&config_path);
                LocalRuntimeResponse {
                    success: false,
                    pid: None,
                    note: err,
                    warnings: local_singbox.warnings.clone(),
                    operation: Some(operation_with_status(operation, "FAILED")),
                    local_singbox: Some(local_singbox),
                }
            }
        };

        store_local_response(
            &self.state,
            "stop_local_runtime_response",
            &response.encode_proto(),
        )?;
        Ok(Response::new(response))
    }

    async fn restart_local_runtime(
        &self,
        request: Request<RestartLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("restart_local_runtime", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "restart local runtime requested")?;

        let (agent_state, _) = observe_agent(&self.state, &self.agent_endpoint).await;
        if !agent_state.ready && !backend_ready_for_local_runtime(&self.repo_root) {
            append_operation_event(
                &self.state,
                operation.id,
                "backend is not ready; refusing to restart local runtime",
            )?;
            update_operation_status(&self.state, operation.id, "FAILED")?;
            let local_singbox = inspect_local_runtime(&default_local_config_path(&self.repo_root));
            return Ok(Response::new(LocalRuntimeResponse {
                success: false,
                pid: None,
                note: "backend is not ready; local runtime restart refused".to_owned(),
                warnings: vec!["server runtime is not ready".to_owned()],
                operation: Some(operation_with_status(operation, "FAILED")),
                local_singbox: Some(local_singbox),
            }));
        }

        let paths = local_runtime_paths_from_restart(&self.repo_root, &request);
        #[cfg(windows)]
        let restarted = {
            let _owner_gate = WINDOWS_RUNTIME_OWNER_GATE
                .lock()
                .map_err(|_| Status::internal("Windows runtime owner gate poisoned"))?;
            if self.repo_root.join("exchange/requests/request.pb").exists() {
                return Err(Status::failed_precondition(
                    "privileged release handoff pending: refusing competing runtime restart",
                ));
            }
            WINDOWS_RUNTIME_REPLACEMENT_GENERATION.fetch_add(1, Ordering::AcqRel);
            if request.visible_window {
                restart_runtime_process_visible(&paths)
            } else {
                restart_runtime_process(&paths)
            }
        };
        #[cfg(not(windows))]
        let restarted = if request.visible_window {
            restart_runtime_process_visible(&paths)
        } else {
            restart_runtime_process(&paths)
        };
        let response = match restarted {
            Ok(mut result) => {
                let _ = refresh_app_readiness_phase(
                    &self.repo_root,
                    &self.state,
                    &result.local_singbox,
                )
                .await;
                let observed_after_start = inspect_local_runtime(&paths.config_path);
                if !observed_after_start.process_running {
                    result.warnings.push(
                        "local sing-box stopped before restart operation completed".to_owned(),
                    );
                    result
                        .warnings
                        .extend(observed_after_start.warnings.clone());
                    append_operation_event(
                        &self.state,
                        operation.id,
                        "local sing-box stopped before restart operation completed",
                    )?;
                    update_operation_status(&self.state, operation.id, "FAILED")?;
                    LocalRuntimeResponse {
                        success: false,
                        pid: result.pid,
                        note: "local sing-box stopped before restart operation completed"
                            .to_owned(),
                        warnings: result.warnings,
                        operation: Some(operation_with_status(operation, "FAILED")),
                        local_singbox: Some(observed_after_start),
                    }
                } else {
                    result.local_singbox = observed_after_start;
                    append_operation_event(&self.state, operation.id, &result.note)?;
                    update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
                    LocalRuntimeResponse {
                        success: true,
                        pid: result.pid,
                        note: result.note,
                        warnings: result.warnings,
                        operation: Some(operation_with_status(operation, "SUCCEEDED")),
                        local_singbox: Some(result.local_singbox),
                    }
                }
            }
            Err(err) => {
                append_operation_event(&self.state, operation.id, &err)?;
                update_operation_status(&self.state, operation.id, "FAILED")?;
                let local_singbox = inspect_local_runtime(&paths.config_path);
                LocalRuntimeResponse {
                    success: false,
                    pid: None,
                    note: err,
                    warnings: local_singbox.warnings.clone(),
                    operation: Some(operation_with_status(operation, "FAILED")),
                    local_singbox: Some(local_singbox),
                }
            }
        };

        store_local_response(
            &self.state,
            "restart_local_runtime_response",
            &response.encode_proto(),
        )?;
        Ok(Response::new(response))
    }

    async fn get_selector_state(
        &self,
        request: Request<GetSelectorStateRequest>,
    ) -> Result<Response<SelectorState>, Status> {
        let request = request.into_inner();
        let group = normalize_selector_group(request.group.as_deref())?;
        let base_status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let local_singbox = merge_local_runtime(
            base_status.local_singbox.clone(),
            inspect_local_runtime(&default_local_config_path(&self.repo_root)),
        );
        let base_selector = if group == UBUNTU_SELECTOR_GROUP {
            base_status.ubuntu_selector
        } else {
            base_status.selector
        };
        let selector = observe_selector_state(local_singbox, base_selector, group).await;

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation(
                &format!("selector_state::{group}"),
                &selector.encode_to_vec(),
            )
            .map_err(|err| {
                Status::internal(format!("failed to store selector observation: {err}"))
            })?;

        Ok(Response::new(selector))
    }

    async fn set_selector(
        &self,
        request: Request<SetSelectorRequest>,
    ) -> Result<Response<SetSelectorResponse>, Status> {
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("set_selector", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(
            &self.state,
            operation.id,
            &format!("setting selector {} -> {}", request.group, request.name),
        )?;
        let group = normalize_selector_group(Some(&request.group))?.to_owned();
        if !is_allowed_selector_route(&request.name) {
            update_operation_status(&self.state, operation.id, "FAILED")?;
            return Err(Status::invalid_argument(format!(
                "unknown selector route: {}",
                request.name
            )));
        }

        let base_status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let local_singbox = merge_local_runtime(
            base_status.local_singbox.clone(),
            inspect_local_runtime(&default_local_config_path(&self.repo_root)),
        );
        let Some(controller_url) = clash_controller_url(&local_singbox) else {
            update_operation_status(&self.state, operation.id, "FAILED")?;
            return Ok(Response::new(SetSelectorResponse {
                success: false,
                previous: None,
                current: None,
                warnings: vec!["clash API endpoint is not configured".to_owned()],
                operation: Some(operation_with_status(operation, "FAILED")),
                selector: Some(
                    selector_state_for_group(&base_status, &group)
                        .cloned()
                        .unwrap_or_else(SelectorState::placeholder),
                ),
            }));
        };

        let response =
            match set_live_selector(&controller_url, &group, &request.name, default_aux_groups())
                .await
            {
                Ok((previous, mut selector)) => {
                    // SetSelector is a transient live switch. The durable default is
                    // rendered from the protected Git route policy, never SQLite.
                    selector.desired_main_route = selector_state_for_group(&base_status, &group)
                        .and_then(|state| state.desired_main_route.clone());
                    append_operation_event(
                        &self.state,
                        operation.id,
                        "transient live selector updated; no durable intent recorded",
                    )?;
                    update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
                    SetSelectorResponse {
                        success: true,
                        previous,
                        current: selector.observed_main_route.clone(),
                        warnings: selector.warnings.clone(),
                        operation: Some(operation_with_status(operation, "SUCCEEDED")),
                        selector: Some(selector),
                    }
                }
                Err(err) => {
                    append_operation_event(&self.state, operation.id, &err)?;
                    update_operation_status(&self.state, operation.id, "FAILED")?;
                    let mut selector = selector_state_for_group(&base_status, &group)
                        .cloned()
                        .unwrap_or_else(SelectorState::placeholder);
                    selector.degraded = true;
                    selector.warnings.push(err.clone());
                    SetSelectorResponse {
                        success: false,
                        previous: selector.observed_main_route.clone(),
                        current: selector.observed_main_route.clone(),
                        warnings: selector.warnings.clone(),
                        operation: Some(operation_with_status(operation, "FAILED")),
                        selector: Some(selector),
                    }
                }
            };

        Ok(Response::new(response))
    }

    async fn get_trace(
        &self,
        request: Request<GetTraceRequest>,
    ) -> Result<Response<TraceObservation>, Status> {
        let request = request.into_inner();
        let config_path = default_local_config_path(&self.repo_root);
        let proxy_url = request.proxy_url.unwrap_or_else(|| {
            default_trace_proxy_url(&config_path)
                .ok()
                .flatten()
                .unwrap_or_else(|| DEFAULT_TRACE_PROXY_URL.to_owned())
        });
        let trace = trace_via_proxy(&proxy_url).await;

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("trace_observation", &trace.encode_to_vec())
            .map_err(|err| Status::internal(format!("failed to store trace observation: {err}")))?;

        Ok(Response::new(trace))
    }

    async fn deploy(
        &self,
        request: Request<DeployRequest>,
    ) -> Result<Response<DeployResponse>, Status> {
        let request = request.into_inner();
        if !request.mock_provider {
            return Err(Status::failed_precondition(
                "legacy Deploy RPC no longer owns server deployment; use the canonical GitHub VM Application Lifecycle",
            ));
        }
        let result = deploy_orchestrator::execute(
            self,
            deploy_orchestrator::DeployCommand { request },
            deploy_orchestrator::RollbackPolicy::STRICT,
        )
        .await?;
        Ok(Response::new(result.response))
    }

    async fn destroy(
        &self,
        request: Request<DestroyRequest>,
    ) -> Result<Response<DestroyResponse>, Status> {
        let mut request = request.into_inner();
        request.instance_id = blank_option(request.instance_id.take());
        request.target_ip = blank_option(request.target_ip.take());
        request.dns_record_name = blank_option(request.dns_record_name.take());
        request.cloudflare_zone_name = blank_option(request.cloudflare_zone_name.take());
        request.lifecycle_reason = blank_option(request.lifecycle_reason.take());
        if !request.mock_provider {
            return Err(Status::failed_precondition(
                "legacy Destroy RPC no longer owns server or DNS mutation; use the canonical GitHub lifecycle",
            ));
        }
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("destroy", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "destroy requested")?;
        if let Some(reason) = request.lifecycle_reason.as_deref() {
            append_operation_event(
                &self.state,
                operation.id,
                &format!("lifecycle reason: {reason}"),
            )?;
        }

        let existing = match read_live_deployment_summary(&self.repo_root) {
            Ok(existing) => existing,
            Err(err) => {
                return Err(fail_destroy_operation(
                    &self.state,
                    operation.id,
                    "read recorded deployment",
                    Status::internal(format!("failed to read current state: {err}")),
                ));
            }
        };
        let target_ip = request
            .target_ip
            .clone()
            .or_else(|| existing.server_ip.clone())
            .unwrap_or_default();
        let instance_id = request
            .instance_id
            .clone()
            .or_else(|| existing.instance_id.clone())
            .unwrap_or_default();
        if let Err(err) = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .set_operation_target(
                operation.id,
                existing.deployment_label.as_deref(),
                (!instance_id.is_empty()).then_some(instance_id.as_str()),
                (!target_ip.is_empty()).then_some(target_ip.as_str()),
            )
        {
            return Err(fail_destroy_operation(
                &self.state,
                operation.id,
                "store recorded target",
                Status::internal(format!("failed to store destroy target: {err}")),
            ));
        }
        if let Err(status) = append_operation_event(
            &self.state,
            operation.id,
            &format!(
                "destroy target recorded: id={instance_id} label={} ip={target_ip}",
                existing.deployment_label.as_deref().unwrap_or("<missing>")
            ),
        ) {
            return Err(fail_destroy_operation(
                &self.state,
                operation.id,
                "record target event",
                status,
            ));
        }
        let mut warnings = Vec::new();

        if request.delete_dns {
            let note = match delete_dns_record(&self.state, &request).await {
                Ok(note) => note,
                Err(err) => {
                    return Err(fail_destroy_operation(
                        &self.state,
                        operation.id,
                        "delete DNS record",
                        Status::internal(err),
                    ));
                }
            };
            if let Err(status) = append_operation_event(&self.state, operation.id, &note) {
                return Err(fail_destroy_operation(
                    &self.state,
                    operation.id,
                    "record DNS deletion",
                    status,
                ));
            }
        }
        if let Err(status) = stop_local_runtime_for_destroy(
            &self.repo_root,
            &self.state,
            operation.id,
            &mut warnings,
        ) {
            return Err(fail_destroy_operation(
                &self.state,
                operation.id,
                "stop local runtime",
                status,
            ));
        }

        if let Err(err) = clear_live_deployment_state(
            &self.repo_root,
            &self.state,
            existing.deployment_label.as_deref(),
            &instance_id,
            &target_ip,
            operation.id,
        ) {
            return Err(fail_destroy_operation(
                &self.state,
                operation.id,
                "clear local deployment state",
                Status::internal(format!("failed to clear deployment state: {err}")),
            ));
        }
        let response = DestroyResponse {
            success: true,
            warnings: {
                if target_ip.trim().is_empty() {
                    warnings.push("destroy completed without a known target IP".to_owned());
                }
                warnings
            },
            operation: Some(operation_with_status(operation, "SUCCEEDED")),
            deployment: if existing.live_state_present {
                Some(existing)
            } else {
                None
            },
        };
        store_local_response(&self.state, "destroy_response", &response.encode_to_vec())?;
        Ok(Response::new(response))
    }

    async fn get_operation(
        &self,
        request: Request<GetOperationRequest>,
    ) -> Result<Response<OperationStatus>, Status> {
        let operation_id = request.into_inner().operation_id;
        let state = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?;
        let Some(operation) = state
            .get_operation(operation_id)
            .map_err(|err| Status::internal(format!("failed to read operation: {err}")))?
        else {
            return Err(Status::not_found(format!(
                "operation not found: {operation_id}"
            )));
        };
        let events = state
            .list_operation_events(operation_id)
            .map_err(|err| Status::internal(format!("failed to read operation events: {err}")))?;
        Ok(Response::new(OperationStatus {
            operation: Some(stored_operation_to_proto(operation)),
            recent_events: events.into_iter().map(stored_event_to_proto).collect(),
        }))
    }

    async fn list_operation_events(
        &self,
        request: Request<ListOperationEventsRequest>,
    ) -> Result<Response<ListOperationEventsResponse>, Status> {
        let operation_id = request.into_inner().operation_id;
        let events = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .list_operation_events(operation_id)
            .map_err(|err| Status::internal(format!("failed to list operation events: {err}")))?;
        Ok(Response::new(ListOperationEventsResponse {
            events: events.into_iter().map(stored_event_to_proto).collect(),
        }))
    }

    async fn stage_credential_candidate(
        &self,
        request: Request<StageCredentialCandidateRequest>,
    ) -> Result<Response<CredentialStateObservation>, Status> {
        let bundle = request
            .into_inner()
            .bundle
            .ok_or_else(|| Status::invalid_argument("credential candidate bundle is required"))?;
        let state = stage_windows_credential_candidate(&self.repo_root, bundle)
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(CredentialStateObservation {
            state: Some(state),
        }))
    }

    async fn get_credential_state(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<CredentialStateObservation>, Status> {
        let state = observe_windows_credential_state(&self.repo_root)
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(CredentialStateObservation { state }))
    }
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

impl Drop for SshTunnelGuard {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

async fn resolve_deploy_target(
    _state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
) -> Result<ResolvedDeployTarget, String> {
    if !request.mock_provider {
        return Err(
            "legacy deploy target resolution is test-only; real server deployment is owned by the canonical GitHub VM Application Lifecycle"
                .to_owned(),
        );
    }

    let label = request
        .label_prefix
        .clone()
        .unwrap_or_else(|| "mock-edge".to_owned());
    let target_ip = request
        .target_ip
        .clone()
        .unwrap_or_else(|| "203.0.113.10".to_owned());
    let instance = mock_instance(&label, DEFAULT_REGION, DEFAULT_PLAN, &target_ip);
    Ok(ResolvedDeployTarget {
        instance_id: instance.id,
        target_ip: instance.main_ip,
    })
}

fn status_for_target_resolution_error(message: String) -> Status {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("transport")
        || normalized.contains("timeout")
        || normalized.contains("http 429")
        || normalized.contains("http 5")
    {
        Status::unavailable(message)
    } else {
        Status::invalid_argument(message)
    }
}

fn select_unique_vultr_instance_by_label(
    instances: &[edge_provider_vultr::VultrInstance],
    deployment_label: &str,
) -> Result<Option<edge_provider_vultr::VultrInstance>, String> {
    let mut matches = instances
        .iter()
        .filter(|instance| instance.label == deployment_label);
    let first = matches.next();
    if let Some(second) = matches.next() {
        let first_id = first
            .map(|instance| instance.id.as_str())
            .unwrap_or("<missing>");
        return Err(format!(
            "ambiguous Vultr instance identity for label {deployment_label}: at least {first_id} and {}",
            second.id
        ));
    }
    Ok(first.cloned())
}

struct PrepareAgentTransportContext<'a> {
    repo_root: &'a Path,
    direct_endpoint: &'a str,
    request: &'a DeployRequest,
    target: &'a ResolvedDeployTarget,
    preexisting_agent_target: Option<AgentConnectionTarget>,
    preexisting_agent_trust: bool,
    operation_id: i64,
    state: &'a Arc<Mutex<EdgeState>>,
}

async fn prepare_agent_transport(
    context: PrepareAgentTransportContext<'_>,
) -> Result<AgentTransport, String> {
    if !should_bootstrap_via_ssh(
        context.state,
        context.request,
        context.preexisting_agent_trust,
    ) {
        let connection_target = context.preexisting_agent_target.clone().unwrap_or(
            resolve_operation_agent_connection_target(
                context.state,
                context.target,
                context.direct_endpoint,
            )?,
        );
        if should_fallback_to_ssh_bootstrap(context.direct_endpoint, context.state)
            && connect_to_agent_target(&connection_target).await.is_err()
        {
            append_operation_event(
                context.state,
                context.operation_id,
                "direct edge-agent transport is unavailable; falling back to SSH bootstrap",
            )
            .map_err(|status| status.message().to_owned())?;
        } else {
            return Ok(AgentTransport {
                endpoint: connection_target.endpoint,
                tls_paths: connection_target.tls_paths,
                _tunnel: None,
            });
        }
    }

    let config = resolve_bootstrap_access_config(context.repo_root, context.state)?;
    append_operation_event(
        context.state,
        context.operation_id,
        "waiting for SSH reachability",
    )
    .map_err(|status| status.message().to_owned())?;
    accept_ssh_host_key(context.target, &config).await?;
    append_operation_event(
        context.state,
        context.operation_id,
        "strict pre-existing SSH host trust verified",
    )
    .map_err(|status| status.message().to_owned())?;
    wait_for_docker_runtime(context.target, &config).await?;
    append_operation_event(
        context.state,
        context.operation_id,
        "cloud-init and docker are ready",
    )
    .map_err(|status| status.message().to_owned())?;
    ensure_edge_agent_service(context.target, &config).await?;
    append_operation_event(
        context.state,
        context.operation_id,
        "edge-agent service is running",
    )
    .map_err(|status| status.message().to_owned())?;

    let local_port = reserve_local_port()?;
    let tunnel = start_ssh_tunnel(context.target, &config, local_port)?;
    let tunnel_endpoint = format!("http://127.0.0.1:{local_port}");
    if let Some(connection_target) = context
        .preexisting_agent_target
        .as_ref()
        .map(|value| retarget_agent_connection_target(value, tunnel_endpoint.clone()))
        && connect_to_agent_target(&connection_target).await.is_ok()
    {
        return Ok(AgentTransport {
            endpoint: connection_target.endpoint,
            tls_paths: connection_target.tls_paths,
            _tunnel: Some(tunnel),
        });
    }

    Ok(AgentTransport {
        endpoint: tunnel_endpoint,
        tls_paths: None,
        _tunnel: Some(tunnel),
    })
}

fn should_fallback_to_ssh_bootstrap(direct_endpoint: &str, state: &Arc<Mutex<EdgeState>>) -> bool {
    env::var_os("EDGE_AGENT_ENDPOINT").is_none()
        && direct_endpoint == DEFAULT_AGENT_ENDPOINT
        && has_configured_secret_ref(state, SECRET_SSH_PRIVATE_KEY_PATH)
}

fn resolve_operation_agent_connection_target(
    state: &Arc<Mutex<EdgeState>>,
    target: &ResolvedDeployTarget,
    default_endpoint: &str,
) -> Result<AgentConnectionTarget, String> {
    if env::var_os("EDGE_AGENT_ENDPOINT").is_some() || default_endpoint != DEFAULT_AGENT_ENDPOINT {
        return Ok(AgentConnectionTarget {
            endpoint: default_endpoint.to_owned(),
            tls_paths: None,
        });
    }

    if let Some(connection_target) =
        resolve_targeted_agent_connection_target(state, &target.instance_id, &target.target_ip)?
    {
        return Ok(connection_target);
    }

    Err(format!(
        "no persisted agent trust was found for instance {} at {}; set EDGE_AGENT_ENDPOINT explicitly or bootstrap via SSH",
        target.instance_id, target.target_ip
    ))
}

fn should_bootstrap_via_ssh(
    state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
    preexisting_agent_trust: bool,
) -> bool {
    let ssh_available = has_configured_secret_ref(state, SECRET_SSH_PRIVATE_KEY_PATH);
    let missing_persisted_trust = !preexisting_agent_trust;

    env::var("EDGE_BOOTSTRAP_VIA_SSH")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        || (request
            .target_ip
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            && ssh_available)
        || (missing_persisted_trust && ssh_available)
}

fn resolve_bootstrap_access_config(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
) -> Result<BootstrapAccessConfig, String> {
    let source_private_key_path = resolve_path_secret(
        state,
        SECRET_SSH_PRIVATE_KEY_PATH,
        &default_env_ref("EDGE_SSH_PRIVATE_KEY_PATH"),
    )
    .map_err(|_| {
        "a configured SSH private key path secret is required for SSH bootstrap".to_owned()
    })?;
    if !source_private_key_path.is_file() {
        return Err(format!(
            "SSH private key was not found: {}",
            source_private_key_path.display()
        ));
    }
    let private_key_path = stage_ssh_private_key(repo_root, &source_private_key_path)?;

    let agent_binary_path = env::var("EDGE_AGENT_BINARY_PATH")
        .map(PathBuf::from)
        .ok()
        .or_else(|| default_edge_agent_binary_path(repo_root))
        .ok_or_else(|| {
            "EDGE_AGENT_BINARY_PATH is required or a Linux edge-agent binary must exist under edge-platform/target"
                .to_owned()
        })?;
    if !agent_binary_path.is_file() {
        return Err(format!(
            "edge-agent binary was not found: {}",
            agent_binary_path.display()
        ));
    }
    if cfg!(windows)
        && agent_binary_path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err(format!(
            "Windows deploy requires a Linux edge-agent binary, but resolved {}",
            agent_binary_path.display()
        ));
    }

    let known_hosts_path = ensure_known_hosts_file(repo_root)?;
    let ssh_user = env::var("EDGE_SSH_USER").unwrap_or_else(|_| DEFAULT_SSH_USER.to_owned());
    let remote_port = env::var("EDGE_AGENT_REMOTE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_AGENT_REMOTE_PORT);

    Ok(BootstrapAccessConfig {
        private_key_path,
        agent_binary_path,
        ssh_user,
        remote_port,
        known_hosts_path,
    })
}

fn backend_ready_for_local_runtime(repo_root: &Path) -> bool {
    if !live_state_artifact_present(repo_root) {
        return false;
    }
    if is_installed_windows_root(repo_root) {
        let Ok(bytes) = fs::read(windows_runtime_state_path(repo_root)) else {
            return false;
        };
        return decode_windows_runtime_state(&bytes).is_ok()
            && default_local_config_path(repo_root).is_file();
    }
    let db_path = controller_state_db_path(repo_root);
    let Ok(state) = EdgeState::open_or_create(&db_path) else {
        return false;
    };
    state
        .get_controller_state()
        .ok()
        .flatten()
        .is_some_and(|value| value.active_instance_id.is_some() || value.active_server_ip.is_some())
}

fn live_state_artifact_present(repo_root: &Path) -> bool {
    default_live_state_path(repo_root).is_file()
}

fn default_edge_agent_binary_path(repo_root: &Path) -> Option<PathBuf> {
    let target_dir = repo_root.join("edge-platform").join("target");
    let candidates = if cfg!(windows) {
        vec![
            target_dir
                .join("x86_64-unknown-linux-gnu")
                .join("debug")
                .join("edge-agent"),
            target_dir
                .join("x86_64-unknown-linux-musl")
                .join("debug")
                .join("edge-agent"),
            target_dir
                .join("x86_64-unknown-linux-gnu")
                .join("release")
                .join("edge-agent"),
            target_dir
                .join("x86_64-unknown-linux-musl")
                .join("release")
                .join("edge-agent"),
            repo_root
                .join("recovered")
                .join("vm")
                .join("vultr-edge-stack")
                .join("bin")
                .join("edge-agent"),
        ]
    } else {
        vec![
            target_dir.join("debug").join("edge-agent"),
            target_dir.join("release").join("edge-agent"),
        ]
    };
    candidates.into_iter().find(|candidate| candidate.is_file())
}

fn stage_ssh_private_key(repo_root: &Path, source_path: &Path) -> Result<PathBuf, String> {
    let runtime_dir = repo_root.join("edge-platform").join(".runtime");
    fs::create_dir_all(&runtime_dir)
        .map_err(|err| format!("failed to create {}: {err}", runtime_dir.display()))?;
    let staged_path = runtime_dir.join(format!("bootstrap-staged-key-{}", unix_timestamp()));
    fs::copy(source_path, &staged_path).map_err(|err| {
        format!(
            "failed to stage SSH private key from {} to {}: {err}",
            source_path.display(),
            staged_path.display()
        )
    })?;

    if cfg!(windows) {
        let username = env::var("USERNAME")
            .map_err(|_| "USERNAME is required to secure staged SSH private key".to_owned())?;
        let staged_str = staged_path.display().to_string();

        let status = Command::new("icacls")
            .args([&staged_str, "/inheritance:r"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| {
                format!(
                    "failed to start icacls for {}: {err}",
                    staged_path.display()
                )
            })?;
        if !status.success() {
            return Err(format!(
                "icacls failed to disable inheritance for staged SSH key {} with status {status}",
                staged_path.display()
            ));
        }

        let grant_target = format!("{username}:R");
        let status = Command::new("icacls")
            .args([&staged_str, "/grant:r", &grant_target])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| {
                format!(
                    "failed to start icacls grant for {}: {err}",
                    staged_path.display()
                )
            })?;
        if !status.success() {
            return Err(format!(
                "icacls failed to grant access to staged SSH key {} with status {status}",
                staged_path.display()
            ));
        }
    }

    Ok(staged_path)
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or_default()
}

fn ensure_known_hosts_file(repo_root: &Path) -> Result<PathBuf, String> {
    let path = repo_root.join(DEFAULT_SSH_KNOWN_HOSTS_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    if !path.exists() {
        fs::write(&path, b"")
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    }
    Ok(path)
}

async fn accept_ssh_host_key(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<(), String> {
    for _ in 0..60 {
        let result = run_command_capture(
            "ssh",
            &[
                "-i".to_owned(),
                config.private_key_path.display().to_string(),
                "-o".to_owned(),
                "BatchMode=yes".to_owned(),
                "-o".to_owned(),
                "StrictHostKeyChecking=yes".to_owned(),
                "-o".to_owned(),
                format!("UserKnownHostsFile={}", config.known_hosts_path.display()),
                "-o".to_owned(),
                "IdentitiesOnly=yes".to_owned(),
                "-o".to_owned(),
                "ConnectTimeout=5".to_owned(),
                format!("{}@{}", config.ssh_user, target.target_ip),
                "exit".to_owned(),
            ],
        );
        if result.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_secs(5)).await;
    }
    Err(format!(
        "timed out waiting for strictly trusted SSH on {}; legacy bootstrap never enrolls or refreshes host keys",
        target.target_ip
    ))
}

async fn wait_for_docker_runtime(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<(), String> {
    for _ in 0..90 {
        let result = run_command(
            "ssh",
            &ssh_args(
                config,
                &target.target_ip,
                "if command -v cloud-init >/dev/null 2>&1; then cloud-init status --wait >/dev/null 2>&1; fi; command -v docker >/dev/null 2>&1 && docker --version >/dev/null 2>&1",
            ),
        );
        if result.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_secs(5)).await;
    }
    Err(format!(
        "docker runtime was not ready on {} after waiting for cloud-init",
        target.target_ip
    ))
}

async fn ensure_edge_agent_service(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<(), String> {
    if config
        .agent_binary_path
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err(format!(
            "refusing to upload non-Linux edge-agent binary: {}",
            config.agent_binary_path.display()
        ));
    }

    run_command(
        "ssh",
        &ssh_args(
            config,
            &target.target_ip,
            "mkdir -p /opt/vultr-edge-stack/bin",
        ),
    )?;
    run_command(
        "scp",
        &scp_args(
            config,
            &target.target_ip,
            &config.agent_binary_path,
            "/opt/vultr-edge-stack/bin/edge-agent.tmp",
        ),
    )?;
    run_command(
        "ssh",
        &ssh_args(
            config,
            &target.target_ip,
            "install -m 0755 /opt/vultr-edge-stack/bin/edge-agent.tmp /opt/vultr-edge-stack/bin/edge-agent && rm -f /opt/vultr-edge-stack/bin/edge-agent.tmp && systemctl daemon-reload && systemctl enable edge-agent.service && systemctl restart edge-agent.service && systemctl is-active --quiet edge-agent.service",
        ),
    )?;
    Ok(())
}

fn restart_edge_agent_service(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<(), String> {
    run_command(
        "ssh",
        &ssh_args(
            config,
            &target.target_ip,
            "systemctl daemon-reload && systemctl restart edge-agent.service && systemctl is-active --quiet edge-agent.service",
        ),
    )
}

fn reserve_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|err| format!("failed to reserve local agent tunnel port: {err}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|err| format!("failed to read local tunnel port: {err}"))
}

fn start_ssh_tunnel(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
    local_port: u16,
) -> Result<SshTunnelGuard, String> {
    let mut child = Command::new("ssh")
        .args([
            "-i",
            &config.private_key_path.display().to_string(),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            &format!("UserKnownHostsFile={}", config.known_hosts_path.display()),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-N",
            "-L",
            &format!("{local_port}:127.0.0.1:{}", config.remote_port),
            &format!("{}@{}", config.ssh_user, target.target_ip),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("failed to start SSH tunnel: {err}"))?;

    let probe_addr = SocketAddr::from(([127, 0, 0, 1], local_port));
    for _ in 0..40 {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to read SSH tunnel status: {err}"))?
        {
            return Err(format!("SSH tunnel exited early with status {status}"));
        }
        if TcpStream::connect_timeout(&probe_addr, Duration::from_millis(250)).is_ok() {
            return Ok(SshTunnelGuard { child });
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let _ = child.kill();
    let _ = child.wait();
    Err(format!(
        "timed out waiting for local SSH tunnel on 127.0.0.1:{local_port}"
    ))
}

fn ssh_args(config: &BootstrapAccessConfig, target_ip: &str, command: &str) -> Vec<String> {
    vec![
        "-i".to_owned(),
        config.private_key_path.display().to_string(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", config.known_hosts_path.display()),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        format!("{}@{}", config.ssh_user, target_ip),
        command.to_owned(),
    ]
}

fn scp_args(
    config: &BootstrapAccessConfig,
    target_ip: &str,
    source_path: &Path,
    remote_path: &str,
) -> Vec<String> {
    vec![
        "-i".to_owned(),
        config.private_key_path.display().to_string(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", config.known_hosts_path.display()),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        source_path.display().to_string(),
        format!("{}@{}:{remote_path}", config.ssh_user, target_ip),
    ]
}

fn run_command(program: &str, args: &[String]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to start {program}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} exited with status {status} ({})",
            args.join(" ")
        ))
    }
}

fn run_command_capture(program: &str, args: &[String]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("failed to start {program}: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if output.status.success() {
        if stdout.is_empty() {
            Ok(stderr)
        } else if stderr.is_empty() {
            Ok(stdout)
        } else {
            Ok(format!("{stdout} | {stderr}"))
        }
    } else {
        Err(format!(
            "{program} exited with status {}: {} {}",
            output.status, stdout, stderr
        ))
    }
}

fn collect_edge_agent_diagnostics(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<String, String> {
    let status = run_command_capture(
        "ssh",
        &ssh_args(
            config,
            &target.target_ip,
            "systemctl is-active edge-agent.service && journalctl -u edge-agent.service -n 20 --no-pager",
        ),
    )?;
    Ok(status.replace('\n', " | "))
}

async fn apply_bundle_to_agent_target(
    target: &AgentConnectionTarget,
    bundle: &PreparedDeploymentBundle,
) -> Result<edge_shared_types::ApplyBundleResponse, String> {
    let channel = connect_to_agent_target(target)
        .await
        .map_err(|err| format!("failed to connect to edge-agent: {err}"))?;
    let mut client = AgentServiceClient::<Channel>::new(channel);
    let response = client
        .apply_bundle(Request::new(ApplyBundleRequest {
            stack_files: bundle
                .stack_files
                .iter()
                .map(bundle_file_payload_to_proto)
                .collect(),
            host_files: bundle
                .host_files
                .iter()
                .map(bundle_file_payload_to_proto)
                .collect(),
            deployment_summary: Some(BundleFile {
                relative_path: "deployment-summary.json".to_owned(),
                content: bundle.deployment_summary_json.as_bytes().to_vec(),
                executable: false,
                sensitive: true,
            }),
            agent_env_file: Some(BundleFile {
                relative_path: "edge-agent.env".to_owned(),
                content: bundle.agent_env_content.as_bytes().to_vec(),
                executable: false,
                sensitive: false,
            }),
            prune_existing: true,
            bundle_id: None,
            bundle_digest: None,
        }))
        .await
        .map_err(|err| format!("edge-agent apply bundle RPC failed: {err}"))?;
    Ok(response.into_inner())
}

async fn verify_agent_runtime_target(
    target: &AgentConnectionTarget,
    require_readiness: bool,
) -> Result<AgentState, String> {
    let channel = connect_to_agent_target(target)
        .await
        .map_err(|err| format!("failed to connect to edge-agent: {err}"))?;
    let mut client = AgentServiceClient::<Channel>::new(channel);
    let response = client
        .verify_runtime(Request::new(VerifyRuntimeRequest {
            require_readiness,
            mode: BootstrapMode::Unspecified as i32,
        }))
        .await
        .map_err(|err| format!("edge-agent verify runtime RPC failed: {err}"))?;
    Ok(response.into_inner())
}

async fn wait_for_agent_runtime_target(
    target: &AgentConnectionTarget,
    require_readiness: bool,
) -> Result<AgentState, String> {
    let mut last_error = None;
    for _ in 0..20 {
        match verify_agent_runtime_target(target, require_readiness).await {
            Ok(state) if !require_readiness || state.ready => return Ok(state),
            Ok(state) => {
                last_error = Some(format!(
                    "edge-agent responded but readiness is false: {}",
                    state.degraded_reasons.join("; ")
                ));
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
    Err(last_error.unwrap_or_else(|| {
        "edge-agent did not become reachable before readiness timeout".to_owned()
    }))
}

fn bundle_file_payload_to_proto(file: &edge_bundle::BundleFilePayload) -> BundleFile {
    BundleFile {
        relative_path: file.relative_path.clone(),
        content: file.content.clone(),
        executable: file.executable,
        sensitive: file.sensitive,
    }
}

fn bundle_to_proto_summary(
    bundle: &PreparedDeploymentBundle,
    target: &ResolvedDeployTarget,
) -> edge_shared_types::DeploymentSummary {
    edge_shared_types::DeploymentSummary {
        live_state_present: true,
        source_state_path: None,
        deployment_label: Some(bundle.label.clone()),
        instance_id: Some(target.instance_id.clone()),
        server_ip: Some(target.target_ip.clone()),
        tunnel_domain: if bundle.deployment.tunnel.enabled {
            Some(bundle.deployment.tunnel.domain.clone())
        } else {
            None
        },
    }
}

fn provider_observation_from_request(
    request: &DeployRequest,
    target_ip: &str,
) -> ProviderObservation {
    let mut warnings = Vec::new();
    if request.mock_provider {
        warnings.push("provider operations were executed in mock mode".to_owned());
    }
    if request.skip_dns {
        warnings.push("DNS cutover was skipped for this deployment".to_owned());
    }
    if target_ip.trim().is_empty() {
        warnings.push("target IP is empty".to_owned());
    }
    ProviderObservation {
        configured: !request.mock_provider,
        compute_provider: "vultr".to_owned(),
        dns_provider: "cloudflare".to_owned(),
        warnings,
    }
}

fn should_update_dns(request: &DeployRequest) -> bool {
    !request.skip_dns
        && request
            .dns_record_name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
}

async fn apply_dns_update(
    _state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
    target_ip: &str,
) -> Result<String, String> {
    if !request.mock_provider {
        return Err("legacy controller DNS mutation is retired; use canonical GitHub-owned application control".to_owned());
    }
    let zone_name = request
        .cloudflare_zone_name
        .clone()
        .unwrap_or_else(|| DEFAULT_CLOUDFLARE_ZONE.to_owned());
    let record_name = request
        .dns_record_name
        .clone()
        .unwrap_or_else(|| DEFAULT_DNS_RECORD.to_owned());
    let record = mock_upsert_a_record(&zone_name, &record_name, target_ip);
    Ok(format!(
        "mock DNS updated: {} -> {} ({})",
        record.record_name, record.ip, record.zone_id
    ))
}

async fn delete_dns_record(
    _state: &Arc<Mutex<EdgeState>>,
    request: &DestroyRequest,
) -> Result<String, String> {
    if !request.mock_provider {
        return Err("legacy controller DNS deletion is retired; use canonical GitHub-owned application control".to_owned());
    }
    let record_name = request
        .dns_record_name
        .clone()
        .unwrap_or_else(|| DEFAULT_DNS_RECORD.to_owned());
    Ok(format!("mock DNS delete requested for {}", record_name))
}

fn write_private_state_file(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set {} mode 600: {err}", path.display()))?;
    }
    Ok(())
}

fn persist_bundle_locally(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    bundle: &PreparedDeploymentBundle,
    target: &ResolvedDeployTarget,
) -> Result<(), String> {
    let live_state_path = default_live_state_path(repo_root);
    write_private_state_file(&live_state_path, bundle.current_state_json.as_bytes())?;

    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    guard
        .clear_destroy_tombstones(Some(&bundle.label), Some(&target.instance_id))
        .map_err(|err| format!("failed to clear destroy tombstones: {err}"))?;
    guard
        .record_deployment(&bundle.label, &target.instance_id, &target.target_ip)
        .map_err(|err| format!("failed to record deployment: {err}"))?;
    let live_state: Value = serde_json::from_str(&bundle.current_state_json)
        .map_err(|err| format!("failed to parse rendered current state JSON: {err}"))?;
    let tunnel_domain = live_state
        .get("tunnel")
        .and_then(Value::as_object)
        .and_then(|tunnel| tunnel.get("domain"))
        .and_then(Value::as_str);
    guard
        .upsert_controller_state(NewControllerState {
            active_deployment_label: Some(&bundle.label),
            active_instance_id: Some(&target.instance_id),
            active_server_ip: Some(&target.target_ip),
            active_tunnel_domain: tunnel_domain,
            active_deployment_state_json: Some(&bundle.current_state_json),
            deploy_phase: DeployPhase::DeploymentPublished,
            app_readiness_phase: AppReadinessPhase::ServerRuntimeReady,
            last_error_code: None,
            last_error_message: None,
        })
        .map_err(|err| format!("failed to update controller state: {err}"))?;
    guard
        .upsert_trust_entry(NewTrustEntry {
            deployment_id: &bundle.label,
            instance_id: &target.instance_id,
            ip: &target.target_ip,
            known_host_line: "",
            domain_name: Some("edge-agent"),
            ca_cert_path: Some(
                bundle
                    .local_trust_material
                    .ca_cert_path
                    .to_string_lossy()
                    .as_ref(),
            ),
            server_cert_path: Some(
                bundle
                    .local_trust_material
                    .server_cert_path
                    .to_string_lossy()
                    .as_ref(),
            ),
            client_cert_path: Some(
                bundle
                    .local_trust_material
                    .client_cert_path
                    .to_string_lossy()
                    .as_ref(),
            ),
            client_key_path: Some(
                bundle
                    .local_trust_material
                    .client_key_path
                    .to_string_lossy()
                    .as_ref(),
            ),
        })
        .map_err(|err| format!("failed to record trust entry: {err}"))?;
    Ok(())
}

fn read_live_deployment_summary(
    repo_root: &Path,
) -> Result<edge_shared_types::DeploymentSummary, String> {
    let db_path = repo_root.join(DEFAULT_STATE_DB);
    if db_path.is_file() {
        let state = EdgeState::open_or_create(&db_path)
            .map_err(|err| format!("failed to open {}: {err}", db_path.display()))?;
        if let Some(controller) = state
            .get_controller_state()
            .map_err(|err| format!("failed to read controller state: {err}"))?
        {
            if let Some(raw) = controller.active_deployment_state_json.as_deref() {
                let value: Value = serde_json::from_str(raw).map_err(|err| {
                    format!("failed to parse controller deployment state JSON: {err}")
                })?;
                let live_state_present = controller.active_deployment_label.is_some()
                    || controller.active_instance_id.is_some()
                    || controller.active_server_ip.is_some()
                    || value.get("label").is_some()
                    || value.get("instance_id").is_some()
                    || value.get("ip").is_some();
                if live_state_present {
                    return Ok(edge_shared_types::DeploymentSummary {
                        live_state_present: true,
                        source_state_path: Some(db_path.display().to_string()),
                        deployment_label: controller.active_deployment_label.or_else(|| {
                            value
                                .get("label")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                        instance_id: controller.active_instance_id.or_else(|| {
                            value
                                .get("instance_id")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                        server_ip: controller.active_server_ip.or_else(|| {
                            value
                                .get("ip")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                        tunnel_domain: controller.active_tunnel_domain.or_else(|| {
                            value
                                .get("tunnel")
                                .and_then(Value::as_object)
                                .and_then(|tunnel| tunnel.get("domain"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                    });
                }
            }
            let live_state_present = controller.active_deployment_label.is_some()
                || controller.active_instance_id.is_some()
                || controller.active_server_ip.is_some();
            if live_state_present {
                return Ok(edge_shared_types::DeploymentSummary {
                    live_state_present: true,
                    source_state_path: Some(db_path.display().to_string()),
                    deployment_label: controller.active_deployment_label,
                    instance_id: controller.active_instance_id,
                    server_ip: controller.active_server_ip,
                    tunnel_domain: controller.active_tunnel_domain,
                });
            }
            return Ok(edge_shared_types::DeploymentSummary::missing());
        }
    }

    let path = default_live_state_path(repo_root);
    if !path.is_file() {
        return Ok(edge_shared_types::DeploymentSummary::missing());
    }
    let raw = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    Ok(edge_shared_types::DeploymentSummary {
        live_state_present: true,
        source_state_path: Some(path.display().to_string()),
        deployment_label: value
            .get("label")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        instance_id: value
            .get("instance_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        server_ip: value
            .get("ip")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        tunnel_domain: value
            .get("tunnel")
            .and_then(Value::as_object)
            .and_then(|tunnel| tunnel.get("domain"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn read_live_state_raw(repo_root: &Path) -> Result<Option<String>, String> {
    let path = default_live_state_path(repo_root);
    if !path.is_file() {
        return Ok(None);
    }
    fs::read_to_string(&path)
        .map(Some)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn parse_tunnel_domain_from_state_json(raw: &str) -> Result<Option<String>, String> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|err| format!("failed to parse deployment state JSON: {err}"))?;
    Ok(value
        .get("tunnel")
        .and_then(Value::as_object)
        .and_then(|tunnel| tunnel.get("domain"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
}

fn restore_controller_state_snapshot(
    state: &Arc<Mutex<EdgeState>>,
    snapshot: Option<&edge_state::StoredControllerState>,
) -> Result<(), String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    match snapshot {
        Some(value) => guard
            .upsert_controller_state(NewControllerState {
                active_deployment_label: value.active_deployment_label.as_deref(),
                active_instance_id: value.active_instance_id.as_deref(),
                active_server_ip: value.active_server_ip.as_deref(),
                active_tunnel_domain: value.active_tunnel_domain.as_deref(),
                active_deployment_state_json: value.active_deployment_state_json.as_deref(),
                deploy_phase: value.deploy_phase,
                app_readiness_phase: value.app_readiness_phase,
                last_error_code: value.last_error_code.as_deref(),
                last_error_message: value.last_error_message.as_deref(),
            })
            .map(|_| ())
            .map_err(|err| format!("failed to restore controller state snapshot: {err}")),
        None => guard
            .clear_controller_state()
            .map_err(|err| format!("failed to clear controller state: {err}")),
    }
}

fn clear_live_deployment_state(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    deployment_label: Option<&str>,
    instance_id: &str,
    target_ip: &str,
    operation_id: i64,
) -> Result<(), String> {
    let live_state_path = default_live_state_path(repo_root);
    if live_state_path.is_file() {
        fs::remove_file(&live_state_path)
            .map_err(|err| format!("failed to remove {}: {err}", live_state_path.display()))?;
    }

    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    let event_message = format!("cleared deployment state for {instance_id}");
    guard
        .mark_authoritative_absent_for_destroy(DestroyAuthorityTransition {
            deployment_label,
            instance_id: Some(instance_id),
            server_ip: Some(target_ip),
            operation_id,
            operation_status: Some("SUCCEEDED"),
            event_message: Some(&event_message),
        })
        .map_err(|err| format!("failed to mark deployment absent: {err}"))?;
    Ok(())
}

fn stop_local_runtime_for_destroy(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    operation_id: i64,
    warnings: &mut Vec<String>,
) -> Result<(), Status> {
    let config_path = default_local_config_path(repo_root);
    match stop_runtime_process(&config_path, true) {
        Ok(result) => {
            append_operation_event(
                state,
                operation_id,
                &format!("destroy local runtime stop: {}", result.note),
            )?;
            warnings.extend(
                result
                    .warnings
                    .into_iter()
                    .filter(|warning| warning != "sing-box process is not running"),
            );
            Ok(())
        }
        Err(err) => {
            let warning = format!("destroy local runtime stop failed: {err}");
            append_operation_event(state, operation_id, &warning)?;
            warnings.push(warning);
            Ok(())
        }
    }
}

fn is_tombstoned_candidate(
    state: &EdgeState,
    deployment_label: &str,
    instance_id: &str,
) -> Result<bool, String> {
    state
        .find_destroy_tombstone(Some(deployment_label), Some(instance_id))
        .map(|value| value.is_some())
        .map_err(|err| format!("failed to query destroy tombstones: {err}"))
}

fn blank_option(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn rollback_live_deployment_state(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    deployment_label: &str,
    instance_id: &str,
    target_ip: &str,
    previous_live_state: Option<&str>,
    previous_controller_state: Option<&edge_state::StoredControllerState>,
) -> Result<(), String> {
    let live_state_path = default_live_state_path(repo_root);
    let previous_state_json = previous_live_state.or_else(|| {
        previous_controller_state.and_then(|value| value.active_deployment_state_json.as_deref())
    });
    match previous_state_json {
        Some(raw) => write_private_state_file(&live_state_path, raw.as_bytes())?,
        None if live_state_path.is_file() => fs::remove_file(&live_state_path)
            .map_err(|err| format!("failed to remove {}: {err}", live_state_path.display()))?,
        None => {}
    }

    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    guard
        .clear_deployment_by_label(deployment_label)
        .map_err(|err| format!("failed to clear deployment row: {err}"))?;
    guard
        .clear_trust_entry(deployment_label, instance_id, target_ip)
        .map_err(|err| format!("failed to clear trust row: {err}"))?;
    match previous_controller_state {
        Some(snapshot) => {
            let snapshot_state_json = snapshot
                .active_deployment_state_json
                .as_deref()
                .or(previous_state_json);
            let snapshot_tunnel_domain = snapshot.active_tunnel_domain.clone().or_else(|| {
                snapshot_state_json
                    .and_then(|raw| parse_tunnel_domain_from_state_json(raw).ok())
                    .flatten()
            });
            guard
                .upsert_controller_state(NewControllerState {
                    active_deployment_label: snapshot.active_deployment_label.as_deref(),
                    active_instance_id: snapshot.active_instance_id.as_deref(),
                    active_server_ip: snapshot.active_server_ip.as_deref(),
                    active_tunnel_domain: snapshot_tunnel_domain.as_deref(),
                    active_deployment_state_json: snapshot_state_json,
                    deploy_phase: snapshot.deploy_phase,
                    app_readiness_phase: snapshot.app_readiness_phase,
                    last_error_code: snapshot.last_error_code.as_deref(),
                    last_error_message: snapshot.last_error_message.as_deref(),
                })
                .map_err(|err| format!("failed to restore controller state: {err}"))?;
        }
        None => {
            let parsed_value = previous_state_json
                .map(|raw| {
                    serde_json::from_str::<Value>(raw).map_err(|err| {
                        format!("failed to parse rollback current state JSON: {err}")
                    })
                })
                .transpose()?;
            let has_previous_state = previous_state_json.is_some();
            let deployment_label = parsed_value.as_ref().and_then(|value| {
                value
                    .get("label")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
            let active_instance_id = parsed_value.as_ref().and_then(|value| {
                value
                    .get("instance_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
            let active_server_ip = parsed_value.as_ref().and_then(|value| {
                value
                    .get("ip")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
            let tunnel_domain = previous_state_json
                .map(parse_tunnel_domain_from_state_json)
                .transpose()?
                .flatten();
            guard
                .upsert_controller_state(NewControllerState {
                    active_deployment_label: deployment_label.as_deref(),
                    active_instance_id: active_instance_id.as_deref(),
                    active_server_ip: active_server_ip.as_deref(),
                    active_tunnel_domain: tunnel_domain.as_deref(),
                    active_deployment_state_json: previous_state_json,
                    deploy_phase: if has_previous_state {
                        DeployPhase::DeploymentPublished
                    } else {
                        DeployPhase::Unspecified
                    },
                    app_readiness_phase: if has_previous_state {
                        AppReadinessPhase::ServerRuntimeReady
                    } else {
                        AppReadinessPhase::DeploymentAbsent
                    },
                    last_error_code: None,
                    last_error_message: None,
                })
                .map_err(|err| format!("failed to restore controller state: {err}"))?;
        }
    }
    Ok(())
}

async fn rollback_failed_deploy(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
    target: &ResolvedDeployTarget,
    rollback: &DeployRollbackContext,
    operation_id: i64,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let _ = append_operation_event(state, operation_id, "rollback started");

    if rollback.dns_updated {
        let destroy_request = DestroyRequest {
            instance_id: Some(target.instance_id.clone()),
            target_ip: Some(target.target_ip.clone()),
            dns_record_name: request.dns_record_name.clone(),
            cloudflare_zone_name: request.cloudflare_zone_name.clone(),
            mock_provider: request.mock_provider,
            delete_dns: true,
            delete_instance: false,
            lifecycle_reason: Some("deploy_rollback".to_owned()),
        };
        match delete_dns_record(state, &destroy_request).await {
            Ok(note) => {
                let _ = append_operation_event(state, operation_id, &note);
            }
            Err(err) => {
                warnings.push(format!("rollback DNS cleanup failed: {err}"));
            }
        }
    }

    if let Err(err) = rollback_live_deployment_state(
        repo_root,
        state,
        &rollback.deployment_label,
        &target.instance_id,
        &target.target_ip,
        rollback.previous_live_state.as_deref(),
        rollback.previous_controller_state.as_ref(),
    ) {
        warnings.push(format!("rollback state restore failed: {err}"));
    } else {
        let _ = append_operation_event(
            state,
            operation_id,
            "rollback restored local deployment state",
        );
    }

    if warnings.is_empty() {
        let _ = append_operation_event(state, operation_id, "rollback completed");
    } else {
        let _ = append_operation_event(
            state,
            operation_id,
            &format!("rollback completed with warnings: {}", warnings.join("; ")),
        );
    }

    warnings
}

fn merge_warnings(mut primary: Vec<String>, mut secondary: Vec<String>) -> Vec<String> {
    primary.append(&mut secondary);
    primary
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
mod tests {
    #[cfg(windows)]
    #[test]
    fn windows_child_exit_notification_is_native_process_handle_event() {
        let mut child = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 1"])
            .spawn()
            .expect("spawn isolated Windows process");
        let result = super::wait_for_windows_child_exit(child.id());
        let exit = child.wait().expect("reap isolated Windows process");
        assert!(result.is_ok(), "OS event wait failed: {result:?}");
        assert!(exit.success());
    }

    #[test]
    fn managed_child_exit_recovery_is_one_shot_and_refuses_all_intended_handoffs() {
        use super::child_exit_auto_recovery_allowed;
        assert!(child_exit_auto_recovery_allowed(
            false, false, false, false, true
        ));
        assert!(!child_exit_auto_recovery_allowed(
            true, false, false, false, true
        ));
        assert!(!child_exit_auto_recovery_allowed(
            false, true, false, false, true
        ));
        assert!(!child_exit_auto_recovery_allowed(
            false, false, true, false, true
        ));
        assert!(!child_exit_auto_recovery_allowed(
            false, false, false, true, true
        ));
        assert!(!child_exit_auto_recovery_allowed(
            false, false, false, false, false
        ));
    }

    use super::*;
    use edge_shared_types::{
        CredentialDeliveryBundle, CredentialDeliverySlot, RealityPublicIdentity,
        RealityPublicIdentityGeneration, TunnelAuthentication, TunnelAuthenticationGeneration,
        WindowsCredentialProjection, credential_delivery_bundle,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn start_rpc_rejects_force_restart_and_accepts_ordinary_idempotent_start() {
        assert!(require_nonrestarting_start(false).is_ok());
        let error = require_nonrestarting_start(true).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn windows_service_startup_decision_is_mode_scoped_and_fail_closed() {
        use edge_local_runtime::ProcessObservation;

        let managed = ProcessObservation {
            pid: 10,
            name: "sing-box".to_owned(),
            executable_path: Some("sing-box".to_owned()),
            parent_pid: Some(1),
            command_line: "sing-box run -c managed.json".to_owned(),
            config_path: Some("managed.json".to_owned()),
        };
        let external = ProcessObservation {
            pid: 11,
            name: "sing-box".to_owned(),
            executable_path: Some("sing-box".to_owned()),
            parent_pid: Some(2),
            command_line: "sing-box run -c external.json".to_owned(),
            config_path: Some("external.json".to_owned()),
        };

        assert_eq!(
            windows_startup_decision(
                &RuntimeProcessClassification::Managed(managed.clone()),
                1,
                true,
                WindowsDatapathMode::ProxyOnly,
            ),
            WindowsStartupDecision::NoopManaged
        );
        assert_eq!(
            windows_startup_decision(
                &RuntimeProcessClassification::Managed(managed.clone()),
                1,
                false,
                WindowsDatapathMode::ManagedTun,
            ),
            WindowsStartupDecision::RestartOrphanManaged
        );
        assert_eq!(
            windows_startup_decision(
                &RuntimeProcessClassification::Absent,
                0,
                false,
                WindowsDatapathMode::ProxyOnly,
            ),
            WindowsStartupDecision::StartAbsent
        );
        assert_eq!(
            windows_startup_decision(
                &RuntimeProcessClassification::Conflicting(vec![external.clone()]),
                0,
                false,
                WindowsDatapathMode::ProxyOnly,
            ),
            WindowsStartupDecision::StartAbsent
        );
        assert_eq!(
            windows_startup_decision(
                &RuntimeProcessClassification::Conflicting(
                    vec![managed.clone(), external.clone(),]
                ),
                1,
                true,
                WindowsDatapathMode::ProxyOnly,
            ),
            WindowsStartupDecision::NoopManaged
        );
        assert_eq!(
            windows_startup_decision(
                &RuntimeProcessClassification::Conflicting(vec![external.clone()]),
                0,
                false,
                WindowsDatapathMode::ManagedTun,
            ),
            WindowsStartupDecision::BlockedConflict
        );
        assert_eq!(
            windows_startup_decision(
                &RuntimeProcessClassification::Conflicting(vec![managed.clone(), external]),
                1,
                false,
                WindowsDatapathMode::ManagedTun,
            ),
            WindowsStartupDecision::BlockedConflict
        );
        assert_eq!(
            windows_startup_decision(
                &RuntimeProcessClassification::Conflicting(vec![managed.clone(), managed]),
                2,
                true,
                WindowsDatapathMode::ProxyOnly,
            ),
            WindowsStartupDecision::BlockedConflict
        );
    }

    #[test]
    fn controller_service_panic_payload_is_bounded_to_safe_text_input() {
        let string_payload: Box<dyn std::any::Any + Send> = Box::new("service panic".to_owned());
        assert_eq!(
            controller_service_panic_message(string_payload.as_ref()),
            "service panic"
        );

        let static_payload: Box<dyn std::any::Any + Send> = Box::new("static panic");
        assert_eq!(
            controller_service_panic_message(static_payload.as_ref()),
            "static panic"
        );

        let opaque_payload: Box<dyn std::any::Any + Send> = Box::new(7_u32);
        assert_eq!(
            controller_service_panic_message(opaque_payload.as_ref()),
            "non-string Rust panic payload"
        );
    }

    #[test]
    fn resolves_repo_root_from_workspace() {
        let repo_root = resolve_repo_root(None).unwrap();
        assert!(repo_root.exists());
    }

    #[tokio::test]
    async fn installed_controller_stages_candidate_without_changing_active_state() {
        let root = installed_windows_test_root();
        let store = CredentialStore::new(
            windows_credential_store_path(&root),
            CredentialProjectionKind::Windows,
        )
        .unwrap();
        store
            .stage_candidate(&windows_test_credential_bundle(
                100,
                CredentialDeliverySlot::A,
            ))
            .unwrap();
        let active = store.promote_candidate().unwrap().active.unwrap();

        let db_path = root.join("state/test-controller-state.sqlite");
        let server = ControllerServerImpl {
            repo_root: root.clone(),
            state: Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap())),
            agent_endpoint: DEFAULT_AGENT_ENDPOINT.to_owned(),
        };
        let staged = server
            .stage_credential_candidate(Request::new(StageCredentialCandidateRequest {
                bundle: Some(windows_test_credential_bundle(
                    101,
                    CredentialDeliverySlot::B,
                )),
            }))
            .await
            .unwrap()
            .into_inner()
            .state
            .unwrap();

        assert_eq!(staged.active.as_ref().unwrap(), &active);
        assert_eq!(staged.candidate.as_ref().unwrap().generation, 101);
        assert_eq!(
            staged.candidate.as_ref().unwrap().slot,
            CredentialDeliverySlot::B as i32
        );

        let observed = server
            .get_credential_state(Request::new(Empty {}))
            .await
            .unwrap()
            .into_inner()
            .state
            .unwrap();
        assert_eq!(observed, staged);

        drop(server);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repo_controller_cannot_stage_windows_credentials() {
        let root = temp_repo_root();
        let error = stage_windows_credential_candidate(
            &root,
            windows_test_credential_bundle(101, CredentialDeliverySlot::B),
        )
        .unwrap_err();
        assert!(error.contains("installed EdgePlatformController authority layout"));
    }

    #[test]
    fn invalid_windows_candidate_has_no_store_side_effect() {
        let root = installed_windows_test_root();
        let store_root = windows_credential_store_path(&root);

        let mut invalid = windows_test_credential_bundle(101, CredentialDeliverySlot::B);
        invalid.dummy_non_secret = true;
        assert!(stage_windows_credential_candidate(&root, invalid).is_err());
        assert!(!store_root.exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_bootstrap_mode_names_are_stable() {
        assert_eq!(BootstrapMode::BootstrapBase.as_str_name(), "BOOTSTRAP_BASE");
        assert_eq!(
            BootstrapMode::BootstrapTunnel.as_str_name(),
            "BOOTSTRAP_TUNNEL"
        );
        assert_eq!(BootstrapMode::BootstrapFull.as_str_name(), "BOOTSTRAP_FULL");
    }

    #[tokio::test]
    async fn installed_windows_status_does_not_probe_legacy_agent_rpc() {
        let root = installed_windows_test_root();
        std::fs::create_dir_all(root.join("state")).unwrap();
        let db_path = controller_state_db_path(&root);
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        let service = ControllerServerImpl {
            repo_root: root.clone(),
            state,
            agent_endpoint: "http://127.0.0.1:59999".to_owned(),
        };

        let response = service.get_status(Request::new(Empty {})).await.unwrap();
        let status = response.get_ref();
        assert!(status.agent_state.is_none());
        assert!(status.runtime.is_none());
        assert!(
            status
                .status_notes
                .iter()
                .all(|note| !note.contains("server agent")
                    && !note.contains("server runtime observation"))
        );

        drop(service);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installed_windows_doctor_omits_legacy_server_rpc_checks() {
        let root = installed_windows_test_root();
        std::fs::create_dir_all(root.join("state")).unwrap();
        let status = collect_controller_status(&root).unwrap();
        let checks = build_doctor_checks(
            &root,
            &status,
            None,
            None,
            &DoctorRequest {
                require_server_ready: true,
                ..DoctorRequest::default()
            },
        );

        assert!(
            checks
                .iter()
                .all(|check| check.name != "server.edge_agent_reachable"
                    && check.name != "server.runtime_ready")
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn typed_diagnostic_evidence_does_not_copy_legacy_detail() {
        let mut check = DoctorCheck {
            name: "server.edge_agent_reachable".to_owned(),
            ok: false,
            detail: "provider_token=super-secret arbitrary transport exception".to_owned(),
            check_id: String::new(),
            status: CheckStatus::Unspecified as i32,
            subsystem: DiagnosticSubsystem::Unspecified as i32,
            evidence: Vec::new(),
        };

        enrich_doctor_check(&mut check);

        assert_eq!(check.check_id, "server.edge_agent_reachable");
        assert_eq!(check.status, CheckStatus::Fail as i32);
        assert_eq!(check.evidence.len(), 1);
        assert_eq!(check.evidence[0].code, "server.edge_agent_reachable.fail");
        assert!(!check.evidence[0].summary.contains("super-secret"));
        assert!(!check.evidence[0].summary.contains("exception"));
    }

    #[test]
    fn formats_bootstrap_failure_message() {
        let message = format_bootstrap_failure(&BootstrapRuntimeResponse {
            success: false,
            mode: BootstrapMode::BootstrapTunnel as i32,
            exit_code: 12,
            stdout: String::new(),
            stderr: "container missing".to_owned(),
            post_state: None,
            warnings: vec!["tunnel container was not ready".to_owned()],
        });
        assert!(message.contains("bootstrap-runtime BOOTSTRAP_TUNNEL failed with exit code 12"));
        assert!(message.contains("container missing"));
        assert!(message.contains("tunnel container was not ready"));
    }

    #[test]
    fn selects_unique_vultr_instance_and_fails_closed_on_ambiguity() {
        let first = mock_instance("edge-a", "waw", "vc2-1c-1gb", "203.0.113.10");
        let second = edge_provider_vultr::VultrInstance {
            id: "mock-second".to_owned(),
            ..first.clone()
        };

        assert!(
            select_unique_vultr_instance_by_label(&[], "edge-a")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            select_unique_vultr_instance_by_label(&[first.clone()], "edge-a")
                .unwrap()
                .unwrap()
                .id,
            first.id
        );
        let error = select_unique_vultr_instance_by_label(&[first, second], "edge-a").unwrap_err();
        assert!(error.contains("ambiguous Vultr instance identity"));
    }

    #[test]
    fn blank_option_normalizes_empty_strings() {
        assert_eq!(blank_option(Some("".to_owned())), None);
        assert_eq!(blank_option(Some("   ".to_owned())), None);
        assert_eq!(
            blank_option(Some("  edge.alegria.by  ".to_owned())),
            Some("edge.alegria.by".to_owned())
        );
    }

    #[test]
    fn merges_local_runtime_status() {
        let merged = merge_local_runtime(
            Some(edge_shared_types::LocalSingboxState {
                process_running: false,
                managed_config: true,
                expected_config_path: "config.json".to_owned(),
                active_config_path: None,
                clash_api_port: Some(9090),
                warnings: vec!["from config".to_owned()],
            }),
            edge_shared_types::LocalSingboxState {
                process_running: true,
                managed_config: false,
                expected_config_path: "other.json".to_owned(),
                active_config_path: Some("config.json".to_owned()),
                clash_api_port: None,
                warnings: vec!["from process".to_owned()],
            },
        );
        assert!(merged.managed_config);
        assert_eq!(merged.expected_config_path, "config.json");
        assert_eq!(merged.clash_api_port, Some(9090));
        assert_eq!(merged.warnings.len(), 2);
    }

    #[tokio::test]
    async fn collects_status_through_service_impl() {
        let repo_root = temp_repo_root();
        std::fs::create_dir_all(repo_root.join("edge-platform/crates/edge-agent/src")).unwrap();
        std::fs::create_dir_all(repo_root.join("edge-platform/crates/edge-controller/src"))
            .unwrap();
        std::fs::create_dir_all(repo_root.join("edge-platform/crates/edge-console/src")).unwrap();
        std::fs::create_dir_all(repo_root.join("edge-platform/proto")).unwrap();
        std::fs::create_dir_all(repo_root.join("win/vultr-waw/stack/tunnel-edge")).unwrap();
        std::fs::create_dir_all(repo_root.join("win/windows")).unwrap();
        std::fs::write(repo_root.join("edge-platform/Cargo.toml"), "").unwrap();
        std::fs::write(repo_root.join("edge-platform/README.md"), "").unwrap();
        std::fs::write(repo_root.join("edge-platform/FINALIZATION-PLAN.md"), "").unwrap();
        std::fs::write(
            repo_root.join("edge-platform/proto/edge_platform.proto"),
            "",
        )
        .unwrap();
        std::fs::write(
            repo_root.join("edge-platform/crates/edge-agent/src/main.rs"),
            "",
        )
        .unwrap();
        std::fs::write(
            repo_root.join("edge-platform/crates/edge-controller/src/main.rs"),
            "",
        )
        .unwrap();
        std::fs::write(
            repo_root.join("edge-platform/crates/edge-console/src/main.rs"),
            "",
        )
        .unwrap();
        std::fs::write(
            repo_root.join("win/vultr-waw/cloud-init.yaml"),
            "edge-agent.service",
        )
        .unwrap();
        std::fs::write(
            repo_root.join("win/vultr-waw/stack/docker-compose.yml"),
            "services: {}",
        )
        .unwrap();
        std::fs::write(
            repo_root.join("win/vultr-waw/stack/tunnel-edge/config.template.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(
            repo_root.join("win/windows/edge-dns-clean-vultr-dual.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(repo_root.join("win/vultr-waw/current-edge.json"), "{}").unwrap();
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-status-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        let service = ControllerServerImpl {
            repo_root: repo_root.clone(),
            state,
            agent_endpoint: "http://127.0.0.1:59999".to_owned(),
        };

        let response = service.get_status(Request::new(Empty {})).await.unwrap();
        assert!(response.get_ref().inventory.is_some());
        assert!(response.get_ref().runtime.is_some());
        let _ = std::fs::remove_dir_all(repo_root);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn formats_unknown_bootstrap_failure_message() {
        let message = format_bootstrap_failure(&BootstrapRuntimeResponse {
            success: false,
            mode: 99,
            exit_code: 8,
            stdout: String::new(),
            stderr: String::new(),
            post_state: None,
            warnings: vec![],
        });
        assert!(message.contains("UNKNOWN(99)"));
    }

    #[tokio::test]
    async fn resolves_mock_deploy_target() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-resolve-target-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        let target = resolve_deploy_target(
            &state,
            &DeployRequest {
                label_prefix: Some("mock-edge".to_owned()),
                target_ip: None,
                instance_id: None,
                tunnel_domain: None,
                acme_email: None,
                dns_record_name: None,
                cloudflare_zone_name: None,
                mock_provider: true,
                skip_dns: true,
                snapshot_id: None,
            },
        )
        .await
        .unwrap();

        assert!(target.instance_id.starts_with("mock-"));
        assert_eq!(target.target_ip, "203.0.113.10");
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn reads_live_deployment_summary_from_state_file() {
        let root = temp_repo_root();
        let state_dir = root.join("win/vultr-waw");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            state_dir.join("current-edge.json"),
            r#"{"label":"edge-a","instance_id":"instance-1","ip":"203.0.113.5","tunnel":{"domain":"edge.example.com"}}"#,
        )
        .unwrap();

        let summary = read_live_deployment_summary(&root).unwrap();
        assert_eq!(summary.deployment_label.as_deref(), Some("edge-a"));
        assert_eq!(summary.instance_id.as_deref(), Some("instance-1"));
        assert_eq!(summary.server_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(summary.tunnel_domain.as_deref(), Some("edge.example.com"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolves_persisted_agent_target_from_state() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-state-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .record_deployment("deploy-1", "instance-1", "203.0.113.10")
                .unwrap();
            guard
                .upsert_trust_entry(NewTrustEntry {
                    deployment_id: "deploy-1",
                    instance_id: "instance-1",
                    ip: "203.0.113.10",
                    known_host_line: "",
                    domain_name: Some("edge-agent"),
                    ca_cert_path: Some("/tmp/ca.pem"),
                    server_cert_path: Some("/tmp/agent-server.pem"),
                    client_cert_path: Some("/tmp/controller-client.pem"),
                    client_key_path: Some("/tmp/controller-client.key"),
                })
                .unwrap();
        }

        let target = resolve_persisted_agent_connection_target(&state)
            .unwrap()
            .unwrap();
        assert_eq!(target.endpoint, "https://203.0.113.10:50061");
        let tls_paths = target.tls_paths.unwrap();
        assert_eq!(
            tls_paths.client_key_path,
            PathBuf::from("/tmp/controller-client.key")
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn resolves_persisted_agent_target_from_authoritative_controller_state() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-authoritative-target-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .upsert_controller_state(NewControllerState {
                    active_deployment_label: Some("deploy-auth"),
                    active_instance_id: Some("instance-auth"),
                    active_server_ip: Some("203.0.113.77"),
                    active_tunnel_domain: Some("edge.example.com"),
                    active_deployment_state_json: None,
                    deploy_phase: DeployPhase::InstanceAddressAssigned,
                    app_readiness_phase: AppReadinessPhase::DeploymentAbsent,
                    last_error_code: None,
                    last_error_message: None,
                })
                .unwrap();
            guard
                .upsert_trust_entry(NewTrustEntry {
                    deployment_id: "deploy-auth",
                    instance_id: "instance-auth",
                    ip: "203.0.113.77",
                    known_host_line: "",
                    domain_name: Some("edge-agent"),
                    ca_cert_path: Some("/tmp/ca-auth.pem"),
                    server_cert_path: Some("/tmp/agent-server-auth.pem"),
                    client_cert_path: Some("/tmp/controller-client-auth.pem"),
                    client_key_path: Some("/tmp/controller-client-auth.key"),
                })
                .unwrap();
        }

        let target = resolve_persisted_agent_connection_target(&state)
            .unwrap()
            .unwrap();
        assert_eq!(target.endpoint, "https://203.0.113.77:50061");
        assert_eq!(
            target.tls_paths.unwrap().client_key_path,
            PathBuf::from("/tmp/controller-client-auth.key")
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn rejects_active_controller_target_without_persisted_trust() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-active-missing-trust-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .upsert_controller_state(NewControllerState {
                    active_deployment_label: Some("deploy-missing"),
                    active_instance_id: Some("instance-missing"),
                    active_server_ip: Some("203.0.113.88"),
                    active_tunnel_domain: Some("edge.example.com"),
                    active_deployment_state_json: None,
                    deploy_phase: DeployPhase::InstanceAddressAssigned,
                    app_readiness_phase: AppReadinessPhase::DeploymentAbsent,
                    last_error_code: None,
                    last_error_message: None,
                })
                .unwrap();
        }

        let error = resolve_persisted_agent_connection_target(&state).unwrap_err();
        assert!(error.contains("instance-missing"));
        assert!(error.contains("203.0.113.88"));

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn resolves_targeted_agent_target_for_redeploy() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-targeted-state-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .upsert_trust_entry(NewTrustEntry {
                    deployment_id: "deploy-old",
                    instance_id: "instance-9",
                    ip: "203.0.113.19",
                    known_host_line: "",
                    domain_name: Some("edge-agent"),
                    ca_cert_path: Some("/tmp/ca-old.pem"),
                    server_cert_path: Some("/tmp/agent-server-old.pem"),
                    client_cert_path: Some("/tmp/controller-client-old.pem"),
                    client_key_path: Some("/tmp/controller-client-old.key"),
                })
                .unwrap();
        }

        let target = resolve_targeted_agent_connection_target(&state, "instance-9", "203.0.113.19")
            .unwrap()
            .unwrap();
        assert_eq!(target.endpoint, "https://203.0.113.19:50061");
        assert_eq!(
            target.tls_paths.unwrap().client_cert_path,
            PathBuf::from("/tmp/controller-client-old.pem")
        );

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn rejects_operation_target_without_persisted_trust_or_override() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-missing-trust-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        let target = ResolvedDeployTarget {
            instance_id: "instance-missing".to_owned(),
            target_ip: "203.0.113.99".to_owned(),
        };

        let error =
            resolve_operation_agent_connection_target(&state, &target, DEFAULT_AGENT_ENDPOINT)
                .unwrap_err();
        assert!(error.contains("no persisted agent trust"));

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn bootstraps_existing_instance_via_ssh_when_trust_is_missing() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-bootstrap-ssh-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .upsert_secret_ref(SECRET_SSH_PRIVATE_KEY_PATH, "path:/tmp/id_rsa")
                .unwrap();
        }
        let request = DeployRequest {
            label_prefix: Some("waw-edge".to_owned()),
            target_ip: None,
            instance_id: Some("instance-bootstrap".to_owned()),
            tunnel_domain: None,
            acme_email: None,
            dns_record_name: None,
            cloudflare_zone_name: None,
            mock_provider: false,
            skip_dns: true,
            snapshot_id: None,
        };

        assert!(should_bootstrap_via_ssh(&state, &request, false));

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn rejects_partial_persisted_tls_material() {
        let trust = StoredTrustEntry {
            id: 1,
            deployment_id: "deploy-1".to_owned(),
            instance_id: "instance-1".to_owned(),
            ip: "203.0.113.10".to_owned(),
            known_host_line: String::new(),
            domain_name: Some("edge-agent".to_owned()),
            ca_cert_path: Some("/tmp/ca.pem".to_owned()),
            server_cert_path: None,
            client_cert_path: Some("/tmp/controller-client.pem".to_owned()),
            client_key_path: None,
            updated_at_unix: 0,
        };
        let error = persisted_agent_tls_paths(&trust).unwrap_err();
        assert!(error.contains("incomplete client TLS paths"));
    }

    #[test]
    fn rollback_restores_previous_live_state_and_clears_new_rows() {
        let root = temp_repo_root();
        let state_dir = root.join("win/vultr-waw");
        std::fs::create_dir_all(&state_dir).unwrap();
        let live_state_path = state_dir.join("current-edge.json");
        std::fs::write(
            &live_state_path,
            r#"{"label":"old","instance_id":"instance-1"}"#,
        )
        .unwrap();

        let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .record_deployment("deploy-new", "instance-1", "203.0.113.10")
                .unwrap();
            guard
                .upsert_trust_entry(NewTrustEntry {
                    deployment_id: "deploy-new",
                    instance_id: "instance-1",
                    ip: "203.0.113.10",
                    known_host_line: "",
                    domain_name: Some("edge-agent"),
                    ca_cert_path: Some("/tmp/ca.pem"),
                    server_cert_path: Some("/tmp/agent-server.pem"),
                    client_cert_path: Some("/tmp/controller-client.pem"),
                    client_key_path: Some("/tmp/controller-client.key"),
                })
                .unwrap();
        }

        std::fs::write(
            &live_state_path,
            r#"{"label":"deploy-new","instance_id":"instance-1"}"#,
        )
        .unwrap();

        rollback_live_deployment_state(
            &root,
            &state,
            "deploy-new",
            "instance-1",
            "203.0.113.10",
            Some(r#"{"label":"old","instance_id":"instance-1"}"#),
            None,
        )
        .unwrap();

        let restored = std::fs::read_to_string(&live_state_path).unwrap();
        assert!(restored.contains(r#""label":"old""#));
        let guard = state.lock().unwrap();
        assert!(guard.latest_deployment().unwrap().is_none());
        assert!(guard.list_trust_entries().unwrap().is_empty());
        drop(guard);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rollback_restores_controller_snapshot_when_file_snapshot_is_missing() {
        let root = temp_repo_root();
        let state_dir = root.join("win/vultr-waw");
        std::fs::create_dir_all(&state_dir).unwrap();
        let live_state_path = state_dir.join("current-edge.json");
        std::fs::write(
            &live_state_path,
            r#"{"label":"deploy-new","instance_id":"instance-9"}"#,
        )
        .unwrap();

        let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        let previous_controller_state = {
            let guard = state.lock().unwrap();
            guard
                .upsert_controller_state(NewControllerState {
                    active_deployment_label: Some("edge-old"),
                    active_instance_id: Some("instance-old"),
                    active_server_ip: Some("203.0.113.50"),
                    active_tunnel_domain: Some("edge.example.com"),
                    active_deployment_state_json: Some(
                        r#"{"label":"edge-old","instance_id":"instance-old","ip":"203.0.113.50","tunnel":{"domain":"edge.example.com"}}"#,
                    ),
                    deploy_phase: DeployPhase::DeploymentPublished,
                    app_readiness_phase: AppReadinessPhase::ServerRuntimeReady,
                    last_error_code: None,
                    last_error_message: None,
                })
                .unwrap();
            guard
                .record_deployment("deploy-new", "instance-9", "203.0.113.10")
                .unwrap();
            guard
                .upsert_trust_entry(NewTrustEntry {
                    deployment_id: "deploy-new",
                    instance_id: "instance-9",
                    ip: "203.0.113.10",
                    known_host_line: "",
                    domain_name: Some("edge-agent"),
                    ca_cert_path: Some("/tmp/ca.pem"),
                    server_cert_path: Some("/tmp/agent-server.pem"),
                    client_cert_path: Some("/tmp/controller-client.pem"),
                    client_key_path: Some("/tmp/controller-client.key"),
                })
                .unwrap();
            guard.get_controller_state().unwrap().unwrap()
        };

        rollback_live_deployment_state(
            &root,
            &state,
            "deploy-new",
            "instance-9",
            "203.0.113.10",
            None,
            Some(&previous_controller_state),
        )
        .unwrap();

        let restored = std::fs::read_to_string(&live_state_path).unwrap();
        assert!(restored.contains(r#""label":"edge-old""#));
        let guard = state.lock().unwrap();
        let controller_state = guard.get_controller_state().unwrap().unwrap();
        assert_eq!(
            controller_state.active_deployment_label.as_deref(),
            Some("edge-old")
        );
        assert!(guard.list_trust_entries().unwrap().is_empty());
        drop(guard);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rollback_is_idempotent_for_same_snapshot() {
        let root = temp_repo_root();
        let state_dir = root.join("win/vultr-waw");
        std::fs::create_dir_all(&state_dir).unwrap();
        let live_state_path = state_dir.join("current-edge.json");
        std::fs::write(
            &live_state_path,
            r#"{"label":"deploy-new","instance_id":"instance-9"}"#,
        )
        .unwrap();

        let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        let previous_controller_state = {
            let guard = state.lock().unwrap();
            guard
                .upsert_controller_state(NewControllerState {
                    active_deployment_label: Some("edge-old"),
                    active_instance_id: Some("instance-old"),
                    active_server_ip: Some("203.0.113.50"),
                    active_tunnel_domain: Some("edge.example.com"),
                    active_deployment_state_json: Some(
                        r#"{"label":"edge-old","instance_id":"instance-old","ip":"203.0.113.50","tunnel":{"domain":"edge.example.com"}}"#,
                    ),
                    deploy_phase: DeployPhase::DeploymentPublished,
                    app_readiness_phase: AppReadinessPhase::ServerRuntimeReady,
                    last_error_code: None,
                    last_error_message: None,
                })
                .unwrap();
            guard.get_controller_state().unwrap().unwrap()
        };

        rollback_live_deployment_state(
            &root,
            &state,
            "deploy-new",
            "instance-9",
            "203.0.113.10",
            None,
            Some(&previous_controller_state),
        )
        .unwrap();
        rollback_live_deployment_state(
            &root,
            &state,
            "deploy-new",
            "instance-9",
            "203.0.113.10",
            None,
            Some(&previous_controller_state),
        )
        .unwrap();

        let restored = std::fs::read_to_string(&live_state_path).unwrap();
        assert!(restored.contains(r#""label":"edge-old""#));
        let guard = state.lock().unwrap();
        let controller_state = guard.get_controller_state().unwrap().unwrap();
        assert_eq!(
            controller_state.active_deployment_label.as_deref(),
            Some("edge-old")
        );
        assert!(guard.latest_deployment().unwrap().is_none());
        assert!(guard.list_trust_entries().unwrap().is_empty());
        drop(guard);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_restores_active_deployment_from_latest_deployment() {
        let root = temp_repo_root();
        let state_dir = root.join("win/vultr-waw");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            state_dir.join("current-edge.json"),
            r#"{"label":"edge-recovered","instance_id":"instance-7","ip":"203.0.113.7","tunnel":{"domain":"edge.example.com"}}"#,
        )
        .unwrap();
        let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .record_deployment("edge-recovered", "instance-7", "203.0.113.7")
                .unwrap();
            guard.clear_controller_state().unwrap();
        }

        reconcile_active_deployment_state(&root, &state).unwrap();

        let guard = state.lock().unwrap();
        let controller_state = guard.get_controller_state().unwrap().unwrap();
        assert_eq!(
            controller_state.active_deployment_label.as_deref(),
            Some("edge-recovered")
        );
        assert!(
            controller_state
                .active_deployment_state_json
                .as_deref()
                .is_some_and(|value| value.contains(r#""instance_id":"instance-7""#))
        );
        drop(guard);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_does_not_restore_authority_without_live_state_artifact() {
        let root = temp_repo_root();
        std::fs::create_dir_all(root.join("win/vultr-waw")).unwrap();
        let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .record_deployment("edge-stale", "instance-stale", "203.0.113.44")
                .unwrap();
            guard.clear_controller_state().unwrap();
        }

        reconcile_active_deployment_state(&root, &state).unwrap();

        let guard = state.lock().unwrap();
        let controller_state = guard.get_controller_state().unwrap().unwrap();
        assert!(controller_state.active_deployment_label.is_none());
        assert!(controller_state.active_instance_id.is_none());
        assert!(controller_state.active_server_ip.is_none());
        drop(guard);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lists_seeded_secret_refs() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-controller-secrets-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        {
            let guard = state.lock().unwrap();
            guard
                .upsert_secret_ref("bootstrap.vultr.ssh_key_id", "env:EDGE_VULTR_SSH_KEY_ID")
                .unwrap();
        }
        let secrets = list_secret_refs(&state).unwrap();
        assert!(secrets.iter().any(|entry| {
            entry.name == SECRET_SSH_PRIVATE_KEY_PATH
                && entry.secret_ref == "env:EDGE_SSH_PRIVATE_KEY_PATH"
        }));
        assert!(
            secrets
                .iter()
                .all(|entry| entry.name != "bootstrap.vultr.ssh_key_id")
        );
        assert!(validate_secret_name("bootstrap.vultr.ssh_key_id").is_err());
        let _ = std::fs::remove_file(db_path);
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_startup_leaves_unconfigured_install_root_untouched() {
        let root = installed_windows_test_root();
        let runtime_state = windows_runtime_state_path(&root);
        let config = local_singbox_config_path(&root);
        let _ = std::fs::remove_file(&runtime_state);
        let _ = std::fs::remove_file(&config);
        assert_eq!(
            converge_windows_runtime_on_service_start(&root).unwrap(),
            "NOT_CONFIGURED"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn installed_windows_test_root() -> PathBuf {
        let root = temp_repo_root();
        std::fs::create_dir_all(root.join("releases")).unwrap();
        std::fs::write(root.join("current.pb"), b"test-activation").unwrap();
        root
    }

    fn windows_test_credential_bundle(
        generation: u64,
        slot: CredentialDeliverySlot,
    ) -> CredentialDeliveryBundle {
        let tunnel_auth = TunnelAuthenticationGeneration {
            generation: 7,
            direct: Some(TunnelAuthentication {
                vless_uuid: "00000000-0000-4000-8000-000000000001".to_owned(),
                hysteria2_password: "a".repeat(64),
                reality_short_id: "b".repeat(16),
            }),
            warp: Some(TunnelAuthentication {
                vless_uuid: "00000000-0000-4000-8000-000000000002".to_owned(),
                hysteria2_password: "c".repeat(64),
                reality_short_id: "d".repeat(16),
            }),
        };
        CredentialDeliveryBundle {
            schema_version: 1,
            generation,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: false,
            slot: slot as i32,
            payload: Some(credential_delivery_bundle::Payload::Windows(
                WindowsCredentialProjection {
                    tunnel_auth: Some(tunnel_auth),
                    reality_identity: Some(RealityPublicIdentityGeneration {
                        generation: 3,
                        direct: Some(RealityPublicIdentity {
                            public_key: "A".repeat(43),
                        }),
                        warp: Some(RealityPublicIdentity {
                            public_key: "B".repeat(43),
                        }),
                    }),
                },
            )),
        }
    }

    fn temp_repo_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-controller-test-{unique}"))
    }
}
