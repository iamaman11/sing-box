use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod deploy_orchestrator;

use edge_bundle::{
    BuildBundleRequest, PreparedDeploymentBundle, build_bundle, generate_deployment_label,
};
use edge_clash::{
    default_aux_groups, get_selector_state as get_live_selector_state,
    set_selector as set_live_selector,
};
use edge_controller_core::{collect_controller_status, validate_deploy_transition};
use edge_local_runtime::{
    LocalRuntimePaths, inspect_local_runtime, restart_local_runtime as restart_runtime_process,
    restart_local_runtime_visible as restart_runtime_process_visible, restore_windows_dns_if_owned,
    start_local_runtime as start_runtime_process, stop_local_runtime as stop_runtime_process,
};
use edge_provider_cloudflare::{delete_a_record, mock_upsert_a_record, upsert_a_record};
use edge_provider_vultr::{
    CreateInstanceRequest, create_instance_typed, destroy_instance_typed, get_instance_typed,
    list_instances_typed, mock_instance,
};
use edge_secrets::{default_env_ref, resolve_secret_path, resolve_secret_text};
use edge_shared_types::agent_service_client::AgentServiceClient;
use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::controller_service_server::{ControllerService, ControllerServiceServer};
use edge_shared_types::{
    AgentState, AppReadinessPhase, ApplyBundleRequest, BootstrapMode, BootstrapRuntimeRequest,
    BootstrapRuntimeResponse, BundleFile, ControllerStatus, DeployPhase, DeployRequest,
    DeployResponse, DestroyRequest, DestroyResponse, DoctorCheck, DoctorRequest, DoctorResponse,
    Empty, GetOperationRequest, GetSecretRefRequest, GetSelectorStateRequest, GetTraceRequest,
    ListOperationEventsRequest, ListOperationEventsResponse, ListSecretRefsRequest,
    ListSecretRefsResponse, LocalRuntimeResponse, Operation, OperationEvent,
    OperationLifecycleStatus, OperationStatus, PlatformError, ProviderObservation,
    RestartLocalRuntimeRequest, RuntimeObservation, SecretRefEntry, SelectorState,
    SetSecretRefRequest, SetSelectorRequest, SetSelectorResponse, StartLocalRuntimeRequest,
    StopLocalRuntimeRequest, TraceObservation, VerifyRuntimeRequest,
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
use prost::Message;
use serde_json::Value;
use tokio::time::{sleep, timeout};
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};

const DEFAULT_CONTROLLER_ADDR: &str = "127.0.0.1:50051";
const DEFAULT_STATE_DB: &str = "edge-platform/.runtime/controller-state.sqlite";
const DEFAULT_AGENT_ENDPOINT: &str = "http://127.0.0.1:50061";
const DEFAULT_LOCAL_CONFIG_PATH: &str = "win/windows/edge-dns-clean-vultr-dual.json";
const DEFAULT_LIVE_STATE_PATH: &str = "win/vultr-waw/current-edge.json";
const DEFAULT_CLOUDFLARE_ZONE: &str = "alegria.by";
const DEFAULT_DNS_RECORD: &str = "edge.alegria.by";
const DEFAULT_REGION: &str = "waw";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestroyInstanceOutcome {
    Requested,
    AlreadyAbsent,
}
const DEFAULT_PLAN: &str = "vc2-1c-1gb";
const DEFAULT_VULTR_OS_ID: u32 = 2625;
const DEFAULT_CLOUD_INIT_PATH: &str = "win/vultr-waw/cloud-init.yaml";
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
const VULTR_CREATE_ATTEMPTS: usize = 3;
const VULTR_CREATE_REOBSERVATION_ATTEMPTS: usize = 30;
const VULTR_DESTROY_REOBSERVATION_ATTEMPTS: usize = 180;
const VULTR_MUTATION_REOBSERVATION_DELAY_SECS: u64 = 2;
const SECRET_VULTR_API_KEY: &str = "provider.vultr.api_key";
const SECRET_CLOUDFLARE_API_TOKEN: &str = "provider.cloudflare.api_token";
const SECRET_VULTR_SSH_KEY_ID: &str = "bootstrap.vultr.ssh_key_id";
const SECRET_SSH_PRIVATE_KEY_PATH: &str = "bootstrap.ssh.private_key_path";
const DEPLOY_ENDPOINT_ARG_INDEX: usize = 10;
const DESTROY_ENDPOINT_ARG_INDEX: usize = 6;
const KNOWN_SECRET_NAMES: &[&str] = &[
    SECRET_VULTR_API_KEY,
    SECRET_CLOUDFLARE_API_TOKEN,
    SECRET_VULTR_SSH_KEY_ID,
    SECRET_SSH_PRIVATE_KEY_PATH,
];

#[derive(Debug, Clone)]
struct ResolvedDeployTarget {
    instance_id: String,
    target_ip: String,
    created_instance: bool,
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
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = env::args().nth(1).unwrap_or_else(|| "serve".to_owned());

    match command.as_str() {
        "serve" => {
            let repo_root = repo_root_from_args(2)?;
            let addr = controller_addr_from_args(3)?;
            serve(repo_root, addr).await
        }
        "get-status" => {
            let endpoint = controller_endpoint_from_args(2);
            let status = fetch_status(endpoint).await?;
            io::stdout().write_all(&status.encode_proto())?;
            Ok(())
        }
        "controller-bootstrap-runtime" => {
            let mode = bootstrap_mode_from_args(2)?;
            let endpoint = controller_endpoint_from_args(3);
            let response = controller_bootstrap_runtime(endpoint, mode).await?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(format_bootstrap_failure(&response).into())
            }
        }
        "bootstrap-runtime" => {
            let mode = bootstrap_mode_from_args(2)?;
            let endpoint = agent_endpoint_from_args(3);
            let response = bootstrap_runtime(endpoint, mode)
                .await
                .map_err(|err| -> Box<dyn std::error::Error> { err.into() })?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(format_bootstrap_failure(&response).into())
            }
        }
        "start-local" => {
            let endpoint = controller_endpoint_from_args(2);
            let response = start_local_runtime_via_controller(endpoint).await?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(response.note.into())
            }
        }
        "stop-local" => {
            let endpoint = controller_endpoint_from_args(2);
            let response = stop_local_runtime_via_controller(endpoint).await?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(response.note.into())
            }
        }
        "restart-local" => {
            let endpoint = controller_endpoint_from_args(2);
            let response = restart_local_runtime_via_controller(endpoint).await?;
            io::stdout().write_all(&response.encode_proto())?;
            if response.success {
                Ok(())
            } else {
                Err(response.note.into())
            }
        }
        "get-selector" => {
            let endpoint = controller_endpoint_from_args(2);
            let selector = fetch_selector_state(endpoint).await?;
            io::stdout().write_all(&selector.encode_to_vec())?;
            Ok(())
        }
        "set-selector" => {
            let name = env::args()
                .nth(2)
                .ok_or("set-selector requires a selector target name")?;
            let endpoint = controller_endpoint_from_args(3);
            let response = set_selector_via_controller(endpoint, "proxy-selector", &name).await?;
            io::stdout().write_all(&response.encode_to_vec())?;
            if response.success {
                Ok(())
            } else {
                Err("selector update failed".into())
            }
        }
        "trace" => {
            let endpoint = controller_endpoint_from_args(2);
            let trace = get_trace_via_controller(endpoint).await?;
            io::stdout().write_all(&trace.encode_to_vec())?;
            Ok(())
        }
        "deploy" => {
            let request = deploy_request_from_args()?;
            let endpoint = controller_endpoint_from_args(DEPLOY_ENDPOINT_ARG_INDEX);
            let response = deploy_via_controller(endpoint, request).await?;
            io::stdout().write_all(&response.encode_to_vec())?;
            if response.success {
                Ok(())
            } else {
                Err("deploy failed".into())
            }
        }
        "destroy" => {
            let request = destroy_request_from_args()?;
            let endpoint = controller_endpoint_from_args(DESTROY_ENDPOINT_ARG_INDEX);
            let response = destroy_via_controller(endpoint, request).await?;
            io::stdout().write_all(&response.encode_to_vec())?;
            if response.success {
                Ok(())
            } else {
                Err("destroy failed".into())
            }
        }
        other => Err(format!("unsupported command: {other}").into()),
    }
}

async fn serve(repo_root: PathBuf, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = repo_root.join(DEFAULT_STATE_DB);
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path)?));
    normalize_runtime_secret_refs(&state)?;
    interrupt_stale_running_operations(&state)?;
    reconcile_active_deployment_state(&repo_root, &state)?;
    ensure_selector_intents_seeded(&repo_root, &state).await?;
    let service = ControllerServerImpl {
        repo_root,
        state,
        agent_endpoint: agent_endpoint_from_env(),
    };

    Server::builder()
        .add_service(ControllerServiceServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}

fn normalize_runtime_secret_refs(state: &Arc<Mutex<EdgeState>>) -> Result<(), String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;

    // Runtime credentials are supplied by the DPAPI launcher. Never retain a
    // token value in SQLite, including values written by an older literal-ref
    // implementation.
    for (name, env_name) in [
        (SECRET_VULTR_API_KEY, "VULTR_API_KEY"),
        (SECRET_CLOUDFLARE_API_TOKEN, "CLOUDFLARE_API_TOKEN"),
        (SECRET_VULTR_SSH_KEY_ID, "EDGE_VULTR_SSH_KEY_ID"),
    ] {
        guard
            .upsert_secret_ref(name, &default_env_ref(env_name))
            .map_err(|err| format!("failed to normalize runtime secret ref {name}: {err}"))?;
    }

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

fn controller_addr_from_args(index: usize) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr = env::args()
        .nth(index)
        .unwrap_or_else(|| DEFAULT_CONTROLLER_ADDR.to_owned());
    Ok(addr.parse()?)
}

fn controller_endpoint_from_args(index: usize) -> String {
    env::args()
        .nth(index)
        .or_else(|| env::var("EDGE_CONTROLLER_ENDPOINT").ok())
        .unwrap_or_else(|| format!("http://{DEFAULT_CONTROLLER_ADDR}"))
}

fn optional_arg(index: usize) -> Option<String> {
    env::args().nth(index).and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn agent_endpoint_from_args(index: usize) -> String {
    env::args()
        .nth(index)
        .or_else(|| env::var("EDGE_AGENT_ENDPOINT").ok())
        .unwrap_or_else(|| DEFAULT_AGENT_ENDPOINT.to_owned())
}

fn bootstrap_mode_from_args(index: usize) -> Result<BootstrapMode, Box<dyn std::error::Error>> {
    let mode = env::args()
        .nth(index)
        .ok_or("bootstrap-runtime requires mode: base, tunnel, or full")?;
    match mode.as_str() {
        "base" => Ok(BootstrapMode::BootstrapBase),
        "tunnel" => Ok(BootstrapMode::BootstrapTunnel),
        "full" => Ok(BootstrapMode::BootstrapFull),
        _ => Err(format!("unsupported bootstrap mode: {mode}").into()),
    }
}

fn deploy_request_from_args() -> Result<DeployRequest, Box<dyn std::error::Error>> {
    Ok(DeployRequest {
        label_prefix: optional_arg(2),
        target_ip: optional_arg(3),
        instance_id: optional_arg(4),
        tunnel_domain: optional_arg(5),
        acme_email: optional_arg(6),
        dns_record_name: optional_arg(7),
        cloudflare_zone_name: optional_arg(8),
        mock_provider: env::var("EDGE_MOCK_PROVIDER")
            .ok()
            .is_some_and(|value| value == "1"),
        skip_dns: env::var("EDGE_SKIP_DNS")
            .ok()
            .is_some_and(|value| value == "1"),
        snapshot_id: optional_arg(9),
    })
}

fn destroy_request_from_args() -> Result<DestroyRequest, Box<dyn std::error::Error>> {
    Ok(DestroyRequest {
        instance_id: optional_arg(2),
        target_ip: optional_arg(3),
        dns_record_name: optional_arg(4),
        cloudflare_zone_name: optional_arg(5),
        mock_provider: env::var("EDGE_MOCK_PROVIDER")
            .ok()
            .is_some_and(|value| value == "1"),
        delete_dns: env::var("EDGE_DELETE_DNS")
            .ok()
            .is_none_or(|value| value == "1"),
        delete_instance: env::var("EDGE_DELETE_INSTANCE")
            .ok()
            .is_none_or(|value| value == "1"),
        lifecycle_reason: env::var("EDGE_LIFECYCLE_REASON").ok(),
    })
}

fn resolve_text_secret(
    state: &Arc<Mutex<EdgeState>>,
    name: &str,
    default_reference: &str,
) -> Result<String, String> {
    let reference = get_or_seed_secret_ref(state, name, default_reference)?;
    resolve_secret_text(&reference)
        .map_err(|err| format!("failed to resolve secret {name} via {reference}: {err}"))
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
        .map(|entry| SecretRefEntry {
            name: entry.name,
            secret_ref: entry.secret_ref,
            updated_at_unix: entry.updated_at_unix,
        })
        .collect())
}

fn secret_name_to_env(name: &str) -> &'static str {
    match name {
        SECRET_VULTR_API_KEY => "VULTR_API_KEY",
        SECRET_CLOUDFLARE_API_TOKEN => "CLOUDFLARE_API_TOKEN",
        SECRET_VULTR_SSH_KEY_ID => "EDGE_VULTR_SSH_KEY_ID",
        SECRET_SSH_PRIVATE_KEY_PATH => "EDGE_SSH_PRIVATE_KEY_PATH",
        _ => "",
    }
}

fn repo_root_from_args(index: usize) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = env::args().nth(index) {
        return Ok(PathBuf::from(path));
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
        let reconcile_warning =
            match reconcile_authoritative_deployment_state(&self.repo_root, &self.state).await {
                Ok(()) => None,
                Err(err) => Some(format!(
                    "authoritative provider reconciliation unavailable: {err}"
                )),
            };
        ensure_selector_intents_seeded(&self.repo_root, &self.state)
            .await
            .map_err(Status::internal)?;
        let mut status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let (agent_state, runtime) = observe_agent(&self.state, &self.agent_endpoint).await;
        let backend_ready_from_state = status
            .deployment
            .as_ref()
            .is_some_and(|deployment| deployment.live_state_present);
        let live_state_artifact_present = live_state_artifact_present(&self.repo_root);

        if !agent_state.ready && !backend_ready_from_state {
            status
                .status_notes
                .push("server agent has not reached runtime readiness".to_owned());
        }
        if !runtime.edge_agent_reachable && !backend_ready_from_state {
            status
                .status_notes
                .push("server runtime observation is running in degraded fallback mode".to_owned());
        } else if !runtime.edge_agent_reachable && backend_ready_from_state {
            status.status_notes.push(
                "server runtime observation is unavailable; using persisted live deployment state"
                    .to_owned(),
            );
        }
        if backend_ready_from_state && !live_state_artifact_present {
            status.status_notes.push(
                "local runtime artifact current-edge.json is missing; start-local cannot be trusted"
                    .to_owned(),
            );
        }
        status.agent_state = Some(agent_state);
        status.runtime = Some(runtime);

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
        let response = match start_runtime_process(&paths, request.visible_window) {
            Ok(mut result) => {
                let _ = reconcile_selector_intents_for_running_local(
                    &self.repo_root,
                    &self.state,
                    &result.local_singbox,
                )
                .await
                .map(|warnings| result.warnings.extend(warnings));
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
                    result.warnings.extend(restore_windows_dns_if_owned());
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
        let response = match if request.visible_window {
            restart_runtime_process_visible(&paths)
        } else {
            restart_runtime_process(&paths)
        } {
            Ok(mut result) => {
                let _ = reconcile_selector_intents_for_running_local(
                    &self.repo_root,
                    &self.state,
                    &result.local_singbox,
                )
                .await
                .map(|warnings| result.warnings.extend(warnings));
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
                    result.warnings.extend(restore_windows_dns_if_owned());
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
        ensure_selector_intents_seeded(&self.repo_root, &self.state)
            .await
            .map_err(Status::internal)?;
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
                    if let Err(err) = upsert_selector_intent(&self.state, &group, &request.name) {
                        append_operation_event(&self.state, operation.id, &err)?;
                        update_operation_status(&self.state, operation.id, "FAILED")?;
                        selector.degraded = true;
                        selector.warnings.push(err.clone());
                        return Ok(Response::new(SetSelectorResponse {
                            success: false,
                            previous,
                            current: selector.observed_main_route.clone(),
                            warnings: selector.warnings.clone(),
                            operation: Some(operation_with_status(operation, "FAILED")),
                            selector: Some(selector),
                        }));
                    }
                    selector.desired_main_route = Some(request.name.clone());
                    append_operation_event(
                        &self.state,
                        operation.id,
                        "selector updated successfully",
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
        let result = deploy_orchestrator::execute(
            self,
            deploy_orchestrator::DeployCommand {
                request: request.into_inner(),
            },
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

        // Destruction is fail-closed: the authoritative provider object must
        // still be exactly the deployment recorded by this controller.
        if request.delete_instance && !request.mock_provider {
            let Some(expected_label) = existing.deployment_label.clone() else {
                return Err(fail_destroy_operation(
                    &self.state,
                    operation.id,
                    "read recorded label",
                    Status::failed_precondition(
                        "refusing destroy: recorded deployment label is absent",
                    ),
                ));
            };
            let Some(expected_instance_id) = existing.instance_id.clone() else {
                return Err(fail_destroy_operation(
                    &self.state,
                    operation.id,
                    "read recorded instance id",
                    Status::failed_precondition("refusing destroy: recorded instance id is absent"),
                ));
            };
            if instance_id != expected_instance_id
                || target_ip.trim().is_empty()
                || !expected_label.starts_with("waw-edge-")
            {
                return Err(fail_destroy_operation(
                    &self.state,
                    operation.id,
                    "target validation",
                    Status::failed_precondition(
                        "refusing destroy: target does not match the recorded managed deployment",
                    ),
                ));
            }
            let api_key = match resolve_text_secret(
                &self.state,
                SECRET_VULTR_API_KEY,
                &default_env_ref("VULTR_API_KEY"),
            ) {
                Ok(api_key) => api_key,
                Err(err) => {
                    return Err(fail_destroy_operation(
                        &self.state,
                        operation.id,
                        "resolve Vultr credential",
                        Status::internal(err),
                    ));
                }
            };
            let remote = match get_instance_typed(&api_key, &instance_id).await {
                Ok(remote) => remote,
                Err(err) => {
                    return Err(fail_destroy_operation(
                        &self.state,
                        operation.id,
                        "read VM from Vultr",
                        Status::internal(err.to_string()),
                    ));
                }
            };
            if remote.id != expected_instance_id
                || remote.label != expected_label
                || !remote.label.starts_with("waw-edge-")
                || remote.main_ip != target_ip
            {
                let note = format!(
                    "destroy refused: expected id={expected_instance_id} label={expected_label} ip={target_ip}; provider returned id={} label={} ip={}",
                    remote.id, remote.label, remote.main_ip
                );
                append_operation_event(&self.state, operation.id, &note)?;
                return Err(fail_destroy_operation(
                    &self.state,
                    operation.id,
                    "provider identity verification",
                    Status::failed_precondition(note),
                ));
            }
            append_operation_event(
                &self.state,
                operation.id,
                &format!(
                    "destroy target verified: id={instance_id} label={expected_label} ip={target_ip}"
                ),
            )?;
        }

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
        if request.delete_instance && !instance_id.trim().is_empty() && !request.mock_provider {
            let api_key = match resolve_text_secret(
                &self.state,
                SECRET_VULTR_API_KEY,
                &default_env_ref("VULTR_API_KEY"),
            ) {
                Ok(api_key) => api_key,
                Err(err) => {
                    return Err(fail_destroy_operation(
                        &self.state,
                        operation.id,
                        "resolve Vultr credential for deletion",
                        Status::internal(err),
                    ));
                }
            };
            let destroy_outcome =
                match destroy_vultr_instance_reconciled(&api_key, &instance_id).await {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        return Err(fail_destroy_operation(
                            &self.state,
                            operation.id,
                            "delete VM at Vultr",
                            Status::internal(err),
                        ));
                    }
                };
            match destroy_outcome {
                DestroyInstanceOutcome::Requested => {
                    append_operation_event(
                        &self.state,
                        operation.id,
                        "Vultr instance destroy requested",
                    )?;
                }
                DestroyInstanceOutcome::AlreadyAbsent => {
                    let warning = format!(
                        "Vultr instance {instance_id} was already absent; authoritative state was reconciled locally"
                    );
                    warnings.push(warning.clone());
                    append_operation_event(&self.state, operation.id, &warning)?;
                }
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
}

fn default_local_config_path(repo_root: &Path) -> PathBuf {
    repo_root.join(DEFAULT_LOCAL_CONFIG_PATH)
}

fn default_live_state_path(repo_root: &Path) -> PathBuf {
    repo_root.join(DEFAULT_LIVE_STATE_PATH)
}

fn default_runtime_root(repo_root: &Path) -> PathBuf {
    if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("sing-box-vultr-dual")
            .join("runtime");
    }

    repo_root
        .join("edge-platform")
        .join(".runtime")
        .join("local-runtime")
}

fn default_singbox_binary_path() -> PathBuf {
    if let Ok(explicit) = env::var("EDGE_SINGBOX_BINARY_PATH") {
        return PathBuf::from(explicit);
    }

    let runtime_path = if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        PathBuf::from(local_app_data)
            .join("sing-box-vultr-dual")
            .join("runtime")
            .join("sing-box.exe")
    } else {
        PathBuf::from("edge-platform")
            .join(".runtime")
            .join("local-runtime")
            .join("sing-box.exe")
    };

    if runtime_path.is_file() {
        return runtime_path;
    }

    runtime_path
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
            .unwrap_or_else(default_singbox_binary_path),
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
            .unwrap_or_else(default_singbox_binary_path),
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
    Operation {
        id: operation.id,
        kind: operation.kind,
        status: lifecycle_status(status) as i32,
        created_at_unix: operation.created_at_unix,
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

fn stored_operation_to_proto(operation: StoredOperation) -> Operation {
    Operation {
        id: operation.id,
        kind: operation.kind,
        status: lifecycle_status(&operation.status) as i32,
        created_at_unix: operation.created_at_unix,
    }
}

fn stored_event_to_proto(event: StoredOperationEvent) -> OperationEvent {
    OperationEvent {
        id: event.id,
        operation_id: event.operation_id,
        message: event.message,
        created_at_unix: event.created_at_unix,
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

async fn reconcile_authoritative_deployment_state(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
) -> Result<(), String> {
    reconcile_active_deployment_state(repo_root, state)?;
    reconcile_provider_active_deployment_state(state).await
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

async fn reconcile_provider_active_deployment_state(
    state: &Arc<Mutex<EdgeState>>,
) -> Result<(), String> {
    let api_key = match resolve_text_secret(
        state,
        SECRET_VULTR_API_KEY,
        &default_env_ref("VULTR_API_KEY"),
    ) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    let instances = list_instances_typed(&api_key)
        .await
        .map_err(|err| err.to_string())?;
    if instances.is_empty() {
        return Ok(());
    }

    let current_state = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?
        .get_controller_state()
        .map_err(|err| format!("failed to read controller state: {err}"))?;
    let latest_requested_label = latest_deploy_attempt_label(state)?;
    let current_instance_id = current_state
        .as_ref()
        .and_then(|value| value.active_instance_id.as_deref());
    let current_exists = current_instance_id
        .is_some_and(|instance_id| instances.iter().any(|instance| instance.id == instance_id));
    let candidate = if let Some(label) = latest_requested_label.as_deref() {
        select_unique_vultr_instance_by_label(&instances, label)?
    } else if current_exists {
        None
    } else {
        choose_single_reconcilable_instance(&instances).cloned()
    };
    let Some(candidate) = candidate else {
        return Ok(());
    };
    let tombstoned = {
        let guard = state
            .lock()
            .map_err(|_| "controller state mutex poisoned".to_owned())?;
        is_tombstoned_candidate(&guard, &candidate.label, &candidate.id)?
    };
    if tombstoned {
        return Ok(());
    }
    if current_state.as_ref().is_some_and(|value| {
        value.active_instance_id.as_deref() == Some(candidate.id.as_str())
            && value.active_server_ip.as_deref() == Some(candidate.main_ip.as_str())
            && value.active_deployment_label.as_deref() == Some(candidate.label.as_str())
    }) {
        return Ok(());
    }

    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    if guard
        .find_deployment_by_instance(&candidate.id)
        .map_err(|err| format!("failed to query deployment rows: {err}"))?
        .is_none()
    {
        guard
            .record_deployment(&candidate.label, &candidate.id, &candidate.main_ip)
            .map_err(|err| format!("failed to record provider-reconciled deployment: {err}"))?;
    }
    let active_state_json = current_state
        .as_ref()
        .and_then(|value| value.active_deployment_state_json.as_deref())
        .filter(|_| {
            current_state
                .as_ref()
                .and_then(|value| value.active_instance_id.as_deref())
                == Some(candidate.id.as_str())
        });
    let active_tunnel_domain = current_state
        .as_ref()
        .and_then(|value| value.active_tunnel_domain.as_deref())
        .or(Some(DEFAULT_DNS_RECORD));
    guard
        .upsert_controller_state(NewControllerState {
            active_deployment_label: Some(&candidate.label),
            active_instance_id: Some(&candidate.id),
            active_server_ip: Some(&candidate.main_ip),
            active_tunnel_domain,
            active_deployment_state_json: active_state_json,
            deploy_phase: if active_state_json.is_some() {
                DeployPhase::DeploymentPublished
            } else {
                DeployPhase::InstanceAddressAssigned
            },
            app_readiness_phase: if active_state_json.is_some() {
                current_state
                    .as_ref()
                    .map(|value| value.app_readiness_phase)
                    .unwrap_or(AppReadinessPhase::ServerRuntimeReady)
            } else {
                AppReadinessPhase::DeploymentAbsent
            },
            last_error_code: None,
            last_error_message: None,
        })
        .map_err(|err| format!("failed to persist provider-reconciled controller state: {err}"))?;
    Ok(())
}

fn latest_deploy_attempt_label(state: &Arc<Mutex<EdgeState>>) -> Result<Option<String>, String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    let Some(operation) = guard
        .latest_operation_by_kind("deploy")
        .map_err(|err| format!("failed to read latest deploy operation: {err}"))?
    else {
        return Ok(None);
    };
    let events = guard
        .list_operation_events(operation.id)
        .map_err(|err| format!("failed to read latest deploy events: {err}"))?;
    Ok(events.into_iter().find_map(|event| {
        event
            .message
            .strip_prefix("deployment label reserved: ")
            .map(ToOwned::to_owned)
    }))
}

fn choose_single_reconcilable_instance(
    instances: &[edge_provider_vultr::VultrInstance],
) -> Option<&edge_provider_vultr::VultrInstance> {
    let mut reconcilable = instances.iter().filter(|instance| {
        instance.status == "active"
            && instance.server_status == "ok"
            && !instance.main_ip.trim().is_empty()
            && instance.label.contains("edge")
    });
    let first = reconcilable.next()?;
    if reconcilable.next().is_some() {
        return None;
    }
    Some(first)
}

fn upsert_selector_intent(
    state: &Arc<Mutex<EdgeState>>,
    group: &str,
    route: &str,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?
        .upsert_selector_intent(group, route)
        .map_err(|err| format!("failed to store selector intent: {err}"))
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

async fn ensure_selector_intents_seeded(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
) -> Result<(), String> {
    let missing_groups = {
        let guard = state
            .lock()
            .map_err(|_| "controller state mutex poisoned".to_owned())?;
        [DESKTOP_SELECTOR_GROUP, UBUNTU_SELECTOR_GROUP]
            .into_iter()
            .filter(|group| guard.get_selector_intent(group).ok().flatten().is_none())
            .collect::<Vec<_>>()
    };
    if missing_groups.is_empty() {
        return Ok(());
    }

    let local = inspect_local_runtime(&default_local_config_path(repo_root));
    let controller_url = clash_controller_url(&local);
    for group in missing_groups {
        let desired = if let Some(url) = controller_url.as_ref() {
            get_live_selector_state(url, group, default_aux_groups())
                .await
                .ok()
                .and_then(|selector| selector.observed_main_route)
        } else {
            None
        }
        .or_else(|| {
            let status = collect_controller_status(repo_root).ok()?;
            selector_state_for_group(&status, group)?
                .desired_main_route
                .clone()
        })
        .unwrap_or_else(|| "auto-direct-tunnel".to_owned());
        upsert_selector_intent(state, group, &desired)?;
    }
    Ok(())
}

async fn reconcile_selector_intents_for_running_local(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    local_singbox: &edge_shared_types::LocalSingboxState,
) -> Result<Vec<String>, String> {
    ensure_selector_intents_seeded(repo_root, state).await?;
    let Some(controller_url) = clash_controller_url(local_singbox) else {
        return Ok(vec!["clash API endpoint is not configured".to_owned()]);
    };

    let intents = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?
        .list_selector_intents()
        .map_err(|err| format!("failed to list selector intents: {err}"))?;
    let mut warnings = Vec::new();
    for intent in intents {
        match set_live_selector(
            &controller_url,
            &intent.group_name,
            &intent.desired_route,
            default_aux_groups(),
        )
        .await
        {
            Ok(_) => {}
            Err(err) => warnings.push(format!(
                "{} -> {} reconciliation failed: {}",
                intent.group_name, intent.desired_route, err
            )),
        }
    }
    Ok(warnings)
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
        },
        DoctorCheck {
            name: "state.selector_intents_present".to_owned(),
            ok: selector
                .and_then(|value| value.desired_main_route.as_ref())
                .is_some()
                && ubuntu_selector
                    .and_then(|value| value.desired_main_route.as_ref())
                    .is_some(),
            detail: "desktop and ubuntu desired routes must be persisted".to_owned(),
        },
        DoctorCheck {
            name: "state.live_state_artifact_present".to_owned(),
            ok: live_state_artifact_present,
            detail: default_live_state_path(repo_root).display().to_string(),
        },
        DoctorCheck {
            name: "server.edge_agent_reachable".to_owned(),
            ok: runtime.is_some_and(|value| value.edge_agent_reachable),
            detail: runtime
                .map(|value| value.warnings.join("; "))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "edge-agent status unavailable".to_owned()),
        },
        DoctorCheck {
            name: "local.singbox_running".to_owned(),
            ok: local.is_some_and(|value| value.process_running),
            detail: local
                .map(|value| value.warnings.join("; "))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "local sing-box runtime inspected".to_owned()),
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
        },
        DoctorCheck {
            name: "ubuntu.proxy_available".to_owned(),
            ok: ubuntu_proxy.is_some_and(|value| value.available),
            detail: ubuntu_proxy
                .and_then(|value| value.url.clone())
                .unwrap_or_else(|| "ubuntu proxy URL unavailable".to_owned()),
        },
    ];

    if request.require_server_ready {
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
        });
    }
    if request.require_local_runtime {
        checks.push(DoctorCheck {
            name: "local.managed_config_active".to_owned(),
            ok: local.is_some_and(|value| value.managed_config),
            detail: local
                .and_then(|value| value.active_config_path.clone())
                .unwrap_or_else(|| "active local config unavailable".to_owned()),
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
        });
        checks.push(DoctorCheck {
            name: "egress.ubuntu_trace_available".to_owned(),
            ok: ubuntu_trace.is_some_and(|value| value.available),
            detail: ubuntu_trace
                .and_then(|value| value.ip.clone())
                .or_else(|| ubuntu_trace.and_then(|value| value.note.clone()))
                .unwrap_or_else(|| "ubuntu trace unavailable".to_owned()),
        });
    }

    checks
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
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
    deployment_label: &str,
) -> Result<ResolvedDeployTarget, String> {
    if request.mock_provider {
        let label = request
            .label_prefix
            .clone()
            .unwrap_or_else(|| "mock-edge".to_owned());
        let target_ip = request
            .target_ip
            .clone()
            .unwrap_or_else(|| "203.0.113.10".to_owned());
        let instance = mock_instance(&label, DEFAULT_REGION, DEFAULT_PLAN, &target_ip);
        return Ok(ResolvedDeployTarget {
            instance_id: instance.id,
            target_ip: instance.main_ip,
            created_instance: false,
        });
    }

    if let Some(instance_id) = request.instance_id.as_deref()
        && let Ok(api_key) = resolve_text_secret(
            state,
            SECRET_VULTR_API_KEY,
            &default_env_ref("VULTR_API_KEY"),
        )
    {
        let instance = get_instance_typed(&api_key, instance_id)
            .await
            .map_err(|err| err.to_string())?;
        if !instance.main_ip.trim().is_empty() {
            return Ok(ResolvedDeployTarget {
                instance_id: instance.id,
                target_ip: instance.main_ip,
                created_instance: false,
            });
        }
    }

    if let Some(target_ip) = request
        .target_ip
        .clone()
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(ResolvedDeployTarget {
            instance_id: request
                .instance_id
                .clone()
                .unwrap_or_else(|| format!("manual-{}", target_ip.replace('.', "-"))),
            target_ip,
            created_instance: false,
        });
    }

    let api_key = resolve_text_secret(
        state,
        SECRET_VULTR_API_KEY,
        &default_env_ref("VULTR_API_KEY"),
    )
    .map_err(|_| {
        "deploy requires target_ip, a resolvable instance_id, or a configured Vultr API key secret"
            .to_owned()
    })?;
    let ssh_key_id = resolve_text_secret(
        state,
        SECRET_VULTR_SSH_KEY_ID,
        &default_env_ref("EDGE_VULTR_SSH_KEY_ID"),
    )
    .map_err(|_| {
        "deploy requires a configured Vultr SSH key id secret when creating a fresh host".to_owned()
    })?;
    let cloud_init = read_cloud_init_template(repo_root)?;
    let region = env::var("EDGE_VULTR_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_owned());
    let plan = env::var("EDGE_VULTR_PLAN").unwrap_or_else(|_| DEFAULT_PLAN.to_owned());
    let snapshot_id = request
        .snapshot_id
        .clone()
        .filter(|value| !value.trim().is_empty());
    let os_id = if snapshot_id.is_none() {
        Some(
            env::var("EDGE_VULTR_OS_ID")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(DEFAULT_VULTR_OS_ID),
        )
    } else {
        None
    };

    let instance = create_or_adopt_vultr_instance(
        &api_key,
        &CreateInstanceRequest {
            region: &region,
            plan: &plan,
            os_id,
            snapshot_id: snapshot_id.as_deref(),
            label: deployment_label,
            ssh_key_id: &ssh_key_id,
            cloud_init: &cloud_init,
            firewall_group_id: None,
            tags: vec!["managed-by-sing-box", deployment_label],
            enable_ipv6: true,
        },
        deployment_label,
    )
    .await?;
    let ready = wait_for_instance_ready(&api_key, &instance.id).await?;
    if ready.main_ip.trim().is_empty() {
        return Err(format!(
            "created instance {} did not report a main IP after provisioning",
            ready.id
        ));
    }
    Ok(ResolvedDeployTarget {
        instance_id: ready.id,
        target_ip: ready.main_ip,
        created_instance: true,
    })
}

async fn wait_for_instance_ready(
    api_key: &str,
    instance_id: &str,
) -> Result<edge_provider_vultr::VultrInstance, String> {
    let mut last = None;
    for _ in 0..60 {
        let current = get_instance_typed(api_key, instance_id)
            .await
            .map_err(|err| err.to_string())?;
        if current.status == "active"
            && current.power_status == "running"
            && current.server_status == "ok"
            && !current.main_ip.trim().is_empty()
        {
            return Ok(current);
        }
        last = Some(current);
        sleep(Duration::from_secs(5)).await;
    }

    let Some(last) = last else {
        return Err(format!(
            "instance {instance_id} never returned a readable provisioning status"
        ));
    };
    Err(format!(
        "instance {} did not become ready in time: status={}, server_status={}, main_ip={}",
        last.id, last.status, last.server_status, last.main_ip
    ))
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

fn instance_matches_create_request(
    instance: &edge_provider_vultr::VultrInstance,
    request: &CreateInstanceRequest<'_>,
) -> bool {
    instance.label == request.label
        && instance.region == request.region
        && instance.plan == request.plan
        && request
            .os_id
            .is_none_or(|expected_os_id| instance.os_id == expected_os_id)
        && request
            .firewall_group_id
            .is_none_or(|expected_firewall| instance.firewall_group_id == expected_firewall)
        && request
            .tags
            .iter()
            .all(|expected_tag| instance.tags.iter().any(|tag| tag == expected_tag))
}

async fn observe_vultr_create_identity(
    api_key: &str,
    request: &CreateInstanceRequest<'_>,
) -> Result<Option<edge_provider_vultr::VultrInstance>, String> {
    let instances = list_instances_typed(api_key)
        .await
        .map_err(|err| err.to_string())?;
    let instance = select_unique_vultr_instance_by_label(&instances, request.label)?;
    match instance {
        Some(instance) if instance_matches_create_request(&instance, request) => Ok(Some(instance)),
        Some(instance) => Err(format!(
            "Vultr instance identity conflict for label {}: id={} region={} plan={} os_id={} firewall_group_id={}",
            request.label,
            instance.id,
            instance.region,
            instance.plan,
            instance.os_id,
            instance.firewall_group_id
        )),
        None => Ok(None),
    }
}

async fn reobserve_uncertain_vultr_create(
    api_key: &str,
    request: &CreateInstanceRequest<'_>,
) -> Result<Option<edge_provider_vultr::VultrInstance>, String> {
    for attempt in 0..VULTR_CREATE_REOBSERVATION_ATTEMPTS {
        if let Some(instance) = observe_vultr_create_identity(api_key, request).await? {
            return Ok(Some(instance));
        }
        if attempt + 1 < VULTR_CREATE_REOBSERVATION_ATTEMPTS {
            sleep(Duration::from_secs(VULTR_MUTATION_REOBSERVATION_DELAY_SECS)).await;
        }
    }
    Ok(None)
}

async fn create_or_adopt_vultr_instance(
    api_key: &str,
    request: &CreateInstanceRequest<'_>,
    deployment_label: &str,
) -> Result<edge_provider_vultr::VultrInstance, String> {
    if request.label != deployment_label {
        return Err(format!(
            "Vultr create identity mismatch: request label {} does not match deployment label {deployment_label}",
            request.label
        ));
    }

    if let Some(instance) = observe_vultr_create_identity(api_key, request).await? {
        return Ok(instance);
    }

    let mut last_error = None;
    for attempt in 1..=VULTR_CREATE_ATTEMPTS {
        match create_instance_typed(api_key, request).await {
            Ok(instance) => return Ok(instance),
            Err(err) if err.requires_mutation_reobservation() => {
                last_error = Some(err.to_string());
                if let Some(instance) = reobserve_uncertain_vultr_create(api_key, request).await? {
                    return Ok(instance);
                }
                if attempt < VULTR_CREATE_ATTEMPTS {
                    continue;
                }
            }
            Err(err) => return Err(err.to_string()),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        format!("failed to create or adopt Vultr instance for {deployment_label}")
    }))
}

fn read_cloud_init_template(repo_root: &Path) -> Result<String, String> {
    let path = repo_root.join(DEFAULT_CLOUD_INIT_PATH);
    fs::read_to_string(&path).map_err(|err| format!("failed to read {}: {err}", path.display()))
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
        context.target,
        context.preexisting_agent_trust,
    ) {
        let connection_target = context.preexisting_agent_target.clone().unwrap_or(
            resolve_operation_agent_connection_target(
                context.state,
                context.target,
                context.direct_endpoint,
            )?,
        );
        if should_fallback_to_ssh_bootstrap(context.direct_endpoint, context.state, context.target)
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
    accept_ssh_host_key(
        context.target,
        &config,
        context.target.created_instance || !context.preexisting_agent_trust,
    )
    .await?;
    append_operation_event(context.state, context.operation_id, "SSH host key pinned")
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

fn should_fallback_to_ssh_bootstrap(
    direct_endpoint: &str,
    state: &Arc<Mutex<EdgeState>>,
    target: &ResolvedDeployTarget,
) -> bool {
    env::var_os("EDGE_AGENT_ENDPOINT").is_none()
        && direct_endpoint == DEFAULT_AGENT_ENDPOINT
        && !target.created_instance
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
    target: &ResolvedDeployTarget,
    preexisting_agent_trust: bool,
) -> bool {
    let ssh_available = has_configured_secret_ref(state, SECRET_SSH_PRIVATE_KEY_PATH);
    let missing_persisted_trust = !preexisting_agent_trust;

    target.created_instance
        || env::var("EDGE_BOOTSTRAP_VIA_SSH")
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
    let db_path = repo_root.join(DEFAULT_STATE_DB);
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

fn remove_known_host_entry(target_ip: &str, known_hosts_path: &Path) -> Result<(), String> {
    let known_hosts = known_hosts_path.display().to_string();
    let status = Command::new("ssh-keygen")
        .args(["-R", target_ip, "-f", &known_hosts])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to start ssh-keygen for {target_ip}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ssh-keygen failed to prune known host entry for {target_ip} from {} with status {status}",
            known_hosts_path.display()
        ))
    }
}

fn is_stale_known_host_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("remote host identification has changed")
        || lower.contains("host key verification failed")
        || lower.contains("offending")
}

async fn accept_ssh_host_key(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
    allow_host_key_refresh: bool,
) -> Result<(), String> {
    if target.created_instance {
        let _ = remove_known_host_entry(&target.target_ip, &config.known_hosts_path);
    }

    let mut refreshed_host_key = false;
    for _ in 0..60 {
        let result = run_command_capture(
            "ssh",
            &[
                "-i".to_owned(),
                config.private_key_path.display().to_string(),
                "-o".to_owned(),
                "BatchMode=yes".to_owned(),
                "-o".to_owned(),
                "StrictHostKeyChecking=accept-new".to_owned(),
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
        match result {
            Ok(_) => return Ok(()),
            Err(err)
                if allow_host_key_refresh
                    && !refreshed_host_key
                    && is_stale_known_host_error(&err) =>
            {
                remove_known_host_entry(&target.target_ip, &config.known_hosts_path)?;
                refreshed_host_key = true;
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            Err(_) => {}
        }
        sleep(Duration::from_secs(5)).await;
    }
    Err(format!("timed out waiting for SSH on {}", target.target_ip))
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
            }),
            agent_env_file: Some(BundleFile {
                relative_path: "edge-agent.env".to_owned(),
                content: bundle.agent_env_content.as_bytes().to_vec(),
                executable: false,
            }),
            prune_existing: true,
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
        .verify_runtime(Request::new(VerifyRuntimeRequest { require_readiness }))
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
    state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
    target_ip: &str,
) -> Result<String, String> {
    let zone_name = request
        .cloudflare_zone_name
        .clone()
        .unwrap_or_else(|| DEFAULT_CLOUDFLARE_ZONE.to_owned());
    let record_name = request
        .dns_record_name
        .clone()
        .unwrap_or_else(|| DEFAULT_DNS_RECORD.to_owned());

    if request.mock_provider {
        let record = mock_upsert_a_record(&zone_name, &record_name, target_ip);
        return Ok(format!(
            "mock DNS updated: {} -> {} ({})",
            record.record_name, record.ip, record.zone_id
        ));
    }

    let api_token = resolve_text_secret(
        state,
        SECRET_CLOUDFLARE_API_TOKEN,
        &default_env_ref("CLOUDFLARE_API_TOKEN"),
    )
    .map_err(|_| {
        "a configured Cloudflare API token secret is required for DNS cutover".to_owned()
    })?;
    let record = upsert_a_record(&api_token, &zone_name, &record_name, target_ip).await?;
    Ok(format!(
        "DNS updated: {} -> {} ({})",
        record.record_name, record.ip, record.zone_id
    ))
}

async fn delete_dns_record(
    state: &Arc<Mutex<EdgeState>>,
    request: &DestroyRequest,
) -> Result<String, String> {
    let zone_name = request
        .cloudflare_zone_name
        .clone()
        .unwrap_or_else(|| DEFAULT_CLOUDFLARE_ZONE.to_owned());
    let record_name = request
        .dns_record_name
        .clone()
        .unwrap_or_else(|| DEFAULT_DNS_RECORD.to_owned());

    if request.mock_provider {
        return Ok(format!("mock DNS delete requested for {}", record_name));
    }

    let api_token = resolve_text_secret(
        state,
        SECRET_CLOUDFLARE_API_TOKEN,
        &default_env_ref("CLOUDFLARE_API_TOKEN"),
    )
    .map_err(|_| {
        "a configured Cloudflare API token secret is required to delete DNS record".to_owned()
    })?;
    delete_a_record(&api_token, &zone_name, &record_name).await?;
    Ok(format!("DNS delete requested for {}", record_name))
}

fn persist_bundle_locally(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    bundle: &PreparedDeploymentBundle,
    target: &ResolvedDeployTarget,
) -> Result<(), String> {
    let live_state_path = default_live_state_path(repo_root);
    if let Some(parent) = live_state_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&live_state_path, bundle.current_state_json.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", live_state_path.display()))?;

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

async fn wait_for_vultr_instance_absence(api_key: &str, instance_id: &str) -> Result<bool, String> {
    for attempt in 0..VULTR_DESTROY_REOBSERVATION_ATTEMPTS {
        match get_instance_typed(api_key, instance_id).await {
            Ok(_) => {}
            Err(err) if err.is_not_found() => return Ok(true),
            Err(err) => return Err(err.to_string()),
        }
        if attempt + 1 < VULTR_DESTROY_REOBSERVATION_ATTEMPTS {
            sleep(Duration::from_secs(VULTR_MUTATION_REOBSERVATION_DELAY_SECS)).await;
        }
    }
    Ok(false)
}

async fn destroy_vultr_instance_reconciled(
    api_key: &str,
    instance_id: &str,
) -> Result<DestroyInstanceOutcome, String> {
    match get_instance_typed(api_key, instance_id).await {
        Ok(_) => {}
        Err(err) if err.is_not_found() => return Ok(DestroyInstanceOutcome::AlreadyAbsent),
        Err(err) => return Err(err.to_string()),
    }

    match destroy_instance_typed(api_key, instance_id).await {
        Ok(()) => {
            if wait_for_vultr_instance_absence(api_key, instance_id).await? {
                Ok(DestroyInstanceOutcome::Requested)
            } else {
                Err(format!(
                    "Vultr instance {instance_id} remained present after a successful DELETE request; refusing to clear local authority"
                ))
            }
        }
        Err(err) if err.is_not_found() => Ok(DestroyInstanceOutcome::AlreadyAbsent),
        Err(err) if err.requires_mutation_reobservation() => {
            let original = err.to_string();
            if wait_for_vultr_instance_absence(api_key, instance_id).await? {
                Ok(DestroyInstanceOutcome::Requested)
            } else {
                Err(format!(
                    "{original}; exact instance {instance_id} remained present after bounded re-observation, and DELETE was not replayed blindly"
                ))
            }
        }
        Err(err) => Err(err.to_string()),
    }
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
    if let Some(parent) = live_state_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let previous_state_json = previous_live_state.or_else(|| {
        previous_controller_state.and_then(|value| value.active_deployment_state_json.as_deref())
    });
    match previous_state_json {
        Some(raw) => fs::write(&live_state_path, raw.as_bytes())
            .map_err(|err| format!("failed to restore {}: {err}", live_state_path.display()))?,
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

    if target.created_instance && !request.mock_provider {
        match resolve_text_secret(
            state,
            SECRET_VULTR_API_KEY,
            &default_env_ref("VULTR_API_KEY"),
        ) {
            Ok(api_key) => {
                match destroy_vultr_instance_reconciled(&api_key, &target.instance_id).await {
                    Ok(DestroyInstanceOutcome::Requested) => {
                        let _ = append_operation_event(
                            state,
                            operation_id,
                            "rollback requested instance destroy",
                        );
                    }
                    Ok(DestroyInstanceOutcome::AlreadyAbsent) => {
                        let _ = append_operation_event(
                            state,
                            operation_id,
                            "rollback observed instance already absent; local state restore continues",
                        );
                    }
                    Err(err) => warnings.push(format!("rollback instance destroy failed: {err}")),
                }
            }
            Err(err) => warnings.push(format!(
                "rollback could not resolve Vultr API key secret: {err}"
            )),
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

fn platform_error_to_status(err: PlatformError) -> Status {
    Status::internal(format!("{} [{}]: {}", err.code, err.stage, err.message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn resolves_repo_root_from_workspace() {
        let repo_root = repo_root_from_args(usize::MAX).unwrap();
        assert!(repo_root.exists());
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
    fn matches_create_request_using_provider_identity_fields() {
        let mut instance = mock_instance("edge-a", "waw", "vc2-1c-1gb", "203.0.113.10");
        instance.os_id = 2625;
        instance.firewall_group_id = "fw-1".to_owned();
        instance.tags = vec!["managed-by-sing-box".to_owned(), "edge-a".to_owned()];

        let request = CreateInstanceRequest {
            region: "waw",
            plan: "vc2-1c-1gb",
            os_id: Some(2625),
            snapshot_id: None,
            label: "edge-a",
            ssh_key_id: "ssh-1",
            cloud_init: "#cloud-config\n",
            firewall_group_id: Some("fw-1"),
            tags: vec!["managed-by-sing-box", "edge-a"],
            enable_ipv6: true,
        };
        assert!(instance_matches_create_request(&instance, &request));

        instance.plan = "vc2-1c-2gb".to_owned();
        assert!(!instance_matches_create_request(&instance, &request));
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
    fn command_endpoint_indices_match_positional_contracts() {
        assert_eq!(DEPLOY_ENDPOINT_ARG_INDEX, 10);
        assert_eq!(DESTROY_ENDPOINT_ARG_INDEX, 6);
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
            Path::new("/home/bose/projects/sing-box"),
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
            "mock-edge-1",
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
    fn reads_cloud_init_template_from_repo() {
        let root = temp_repo_root();
        std::fs::create_dir_all(root.join("win/vultr-waw")).unwrap();
        std::fs::write(
            root.join("win/vultr-waw/cloud-init.yaml"),
            "edge-agent.service\ninstall-docker.sh\n",
        )
        .unwrap();
        let template = read_cloud_init_template(&root).unwrap();
        assert!(template.contains("edge-agent.service"));
        assert!(template.contains("install-docker.sh"));
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
            created_instance: false,
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
        let target = ResolvedDeployTarget {
            instance_id: "instance-bootstrap".to_owned(),
            target_ip: "203.0.113.120".to_owned(),
            created_instance: false,
        };
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

        assert!(should_bootstrap_via_ssh(&state, &request, &target, false));

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
        let secrets = list_secret_refs(&state).unwrap();
        assert!(secrets.iter().any(|entry| {
            entry.name == SECRET_VULTR_API_KEY && entry.secret_ref == "env:VULTR_API_KEY"
        }));
        assert!(secrets.iter().any(|entry| {
            entry.name == SECRET_SSH_PRIVATE_KEY_PATH
                && entry.secret_ref == "env:EDGE_SSH_PRIVATE_KEY_PATH"
        }));
        let _ = std::fs::remove_file(db_path);
    }

    fn temp_repo_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-controller-test-{unique}"))
    }
}
