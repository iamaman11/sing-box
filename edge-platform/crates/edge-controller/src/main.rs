use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use edge_bundle::{BuildBundleRequest, PreparedDeploymentBundle, build_bundle};
use edge_clash::{
    get_selector_state as get_live_selector_state, set_selector as set_live_selector,
};
use edge_controller_core::collect_controller_status;
use edge_local_runtime::{
    LocalRuntimePaths, inspect_local_runtime, restart_local_runtime as restart_runtime_process,
    start_local_runtime as start_runtime_process, stop_local_runtime as stop_runtime_process,
};
use edge_provider_cloudflare::{delete_a_record, mock_upsert_a_record, upsert_a_record};
use edge_provider_vultr::{destroy_instance, get_instance, mock_instance};
use edge_shared_types::agent_service_client::AgentServiceClient;
use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::controller_service_server::{ControllerService, ControllerServiceServer};
use edge_shared_types::{
    AgentState, ApplyBundleRequest, BootstrapMode, BootstrapRuntimeRequest,
    BootstrapRuntimeResponse, BundleFile, ControllerStatus, DeployRequest, DeployResponse,
    DestroyRequest, DestroyResponse, Empty, GetOperationRequest, GetSelectorStateRequest,
    GetTraceRequest, ListOperationEventsRequest, ListOperationEventsResponse, LocalRuntimeResponse,
    Operation, OperationEvent, OperationLifecycleStatus, OperationStatus, PlatformError,
    ProviderObservation, RestartLocalRuntimeRequest, RuntimeObservation, SelectorState,
    SetSelectorRequest, SetSelectorResponse, StartLocalRuntimeRequest, StopLocalRuntimeRequest,
    TraceObservation, VerifyRuntimeRequest,
};
use edge_singbox::{default_trace_proxy_url, sync_local_config};
use edge_state::{EdgeState, NewTrustEntry, StoredOperation, StoredOperationEvent};
use edge_trace::trace_via_proxy;
use edge_trust::{agent_endpoint_scheme, optional_agent_client_tls_from_env};
use prost::Message;
use serde_json::Value;
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
const DEFAULT_PLAN: &str = "vc2-1c-1gb";
const DEFAULT_SINGBOX_BINARY_PATH: &str =
    "V:\\code\\sing-box-cl\\auto-route-sing-box\\sing-box.exe";
const DEFAULT_TRACE_PROXY_URL: &str = "http://127.0.0.1:7890";

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
            let response = bootstrap_runtime(endpoint, mode).await?;
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
            let endpoint = controller_endpoint_from_args(9);
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
            let endpoint = controller_endpoint_from_args(7);
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
) -> Result<BootstrapRuntimeResponse, Box<dyn std::error::Error>> {
    let channel = connect_to_agent(endpoint).await?;
    let mut client = AgentServiceClient::<Channel>::new(channel);
    let response = client
        .bootstrap_runtime(Request::new(BootstrapRuntimeRequest { mode: mode as i32 }))
        .await?;
    Ok(response.into_inner())
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
        label_prefix: env::args().nth(2),
        target_ip: env::args().nth(3),
        instance_id: env::args().nth(4),
        tunnel_domain: env::args().nth(5),
        acme_email: env::args().nth(6),
        dns_record_name: env::args().nth(7),
        cloudflare_zone_name: env::args().nth(8),
        mock_provider: env::var("EDGE_MOCK_PROVIDER")
            .ok()
            .is_some_and(|value| value == "1"),
        skip_dns: env::var("EDGE_SKIP_DNS")
            .ok()
            .is_some_and(|value| value == "1"),
    })
}

fn destroy_request_from_args() -> Result<DestroyRequest, Box<dyn std::error::Error>> {
    Ok(DestroyRequest {
        instance_id: env::args().nth(2),
        target_ip: env::args().nth(3),
        dns_record_name: env::args().nth(4),
        cloudflare_zone_name: env::args().nth(5),
        mock_provider: env::var("EDGE_MOCK_PROVIDER")
            .ok()
            .is_some_and(|value| value == "1"),
        delete_dns: env::var("EDGE_DELETE_DNS")
            .ok()
            .is_none_or(|value| value == "1"),
        delete_instance: env::var("EDGE_DELETE_INSTANCE")
            .ok()
            .is_none_or(|value| value == "1"),
    })
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
        let mut status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let (agent_state, runtime) = observe_agent(&self.agent_endpoint).await;

        if !agent_state.ready {
            status
                .status_notes
                .push("server agent has not reached runtime readiness".to_owned());
        }
        if !runtime.edge_agent_reachable {
            status
                .status_notes
                .push("server runtime observation is running in degraded fallback mode".to_owned());
        }
        status.agent_state = Some(agent_state);
        status.runtime = Some(runtime);

        let local_config_path = default_local_config_path(&self.repo_root);
        let merged_local = merge_local_runtime(
            status.local_singbox.take(),
            inspect_local_runtime(&local_config_path),
        );
        let merged_selector =
            observe_selector_state(merged_local.clone(), status.selector.take()).await;
        status.local_singbox = Some(merged_local);
        status.selector = Some(merged_selector);

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("controller_status", &status.encode_proto())
            .map_err(|err| Status::internal(format!("failed to store status snapshot: {err}")))?;

        Ok(Response::new(status))
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

        let response = bootstrap_runtime(self.agent_endpoint.clone(), mode)
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

        let (agent_state, _) = observe_agent(&self.agent_endpoint).await;
        if !agent_state.ready {
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
        let response = match start_runtime_process(&paths) {
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

        let (agent_state, _) = observe_agent(&self.agent_endpoint).await;
        if !agent_state.ready {
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
        let response = match restart_runtime_process(&paths) {
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
        _request: Request<GetSelectorStateRequest>,
    ) -> Result<Response<SelectorState>, Status> {
        let base_status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let local_singbox = merge_local_runtime(
            base_status.local_singbox,
            inspect_local_runtime(&default_local_config_path(&self.repo_root)),
        );
        let selector = observe_selector_state(local_singbox, base_status.selector).await;

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("selector_state", &selector.encode_to_vec())
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

        let base_status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let local_singbox = merge_local_runtime(
            base_status.local_singbox,
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
                    base_status
                        .selector
                        .unwrap_or_else(SelectorState::placeholder),
                ),
            }));
        };

        let response = match set_live_selector(&controller_url, &request.group, &request.name).await
        {
            Ok((previous, mut selector)) => {
                let desired = base_status
                    .selector
                    .and_then(|selector| selector.desired_main_route);
                selector.desired_main_route =
                    desired.or_else(|| selector.observed_main_route.clone());
                append_operation_event(&self.state, operation.id, "selector updated successfully")?;
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
                let mut selector = base_status
                    .selector
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
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("deploy", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "deploy requested")?;

        let target = resolve_deploy_target(&request).await.map_err(|err| {
            let _ = append_operation_event(&self.state, operation.id, &err);
            let _ = update_operation_status(&self.state, operation.id, "FAILED");
            Status::invalid_argument(err)
        })?;
        append_operation_event(
            &self.state,
            operation.id,
            &format!(
                "target resolved: {} ({})",
                target.instance_id, target.target_ip
            ),
        )?;

        let bundle = build_bundle(&BuildBundleRequest {
            repo_root: &self.repo_root,
            target_ip: &target.target_ip,
            instance_id: &target.instance_id,
            tunnel_domain: request.tunnel_domain.as_deref(),
            acme_email: request.acme_email.as_deref(),
            cloudflare_zone_name: request.cloudflare_zone_name.as_deref(),
            dns_record_name: request.dns_record_name.as_deref(),
            label_prefix: request.label_prefix.as_deref(),
        })
        .map_err(|err| {
            let _ = append_operation_event(&self.state, operation.id, &err);
            let _ = update_operation_status(&self.state, operation.id, "FAILED");
            Status::internal(format!("failed to build deployment bundle: {err}"))
        })?;
        append_operation_event(
            &self.state,
            operation.id,
            &format!("bundle rendered: {}", bundle.label),
        )?;

        persist_bundle_locally(&self.repo_root, &self.state, &bundle, &target).map_err(|err| {
            Status::internal(format!("failed to persist deployment state: {err}"))
        })?;
        append_operation_event(
            &self.state,
            operation.id,
            "local trust and deployment state persisted",
        )?;

        let apply_response = apply_bundle_to_agent(&self.agent_endpoint, &bundle)
            .await
            .map_err(|err| {
                let _ = append_operation_event(&self.state, operation.id, &err);
                let _ = update_operation_status(&self.state, operation.id, "FAILED");
                Status::internal(format!("failed to apply bundle to agent: {err}"))
            })?;
        for path in &apply_response.written_paths {
            append_operation_event(&self.state, operation.id, &format!("wrote {path}"))?;
        }

        let base = bootstrap_runtime(self.agent_endpoint.clone(), BootstrapMode::BootstrapBase)
            .await
            .map_err(|err| {
                let _ = append_operation_event(&self.state, operation.id, &err.to_string());
                let _ = update_operation_status(&self.state, operation.id, "FAILED");
                Status::internal(format!("base bootstrap failed: {err}"))
            })?;
        if !base.success {
            let _ =
                append_operation_event(&self.state, operation.id, &format_bootstrap_failure(&base));
            let _ = update_operation_status(&self.state, operation.id, "FAILED");
            return Ok(Response::new(DeployResponse {
                success: false,
                deployment: Some(bundle_to_proto_summary(&bundle, &target)),
                provider: Some(provider_observation_from_request(
                    &request,
                    &target.target_ip,
                )),
                runtime: Some(RuntimeObservation::from_agent_state(
                    &base
                        .post_state
                        .clone()
                        .unwrap_or_else(AgentState::bootstrap_placeholder),
                )),
                warnings: base.warnings,
                operation: Some(operation_with_status(operation, "FAILED")),
            }));
        }
        append_operation_event(&self.state, operation.id, "base bootstrap completed")?;

        if should_update_dns(&request) {
            let dns_note = apply_dns_update(&request, &target.target_ip)
                .await
                .map_err(|err| {
                    let _ = append_operation_event(&self.state, operation.id, &err);
                    let _ = update_operation_status(&self.state, operation.id, "FAILED");
                    Status::internal(err)
                })?;
            append_operation_event(&self.state, operation.id, &dns_note)?;
        }

        if request
            .tunnel_domain
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            && request
                .acme_email
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
        {
            let tunnel =
                bootstrap_runtime(self.agent_endpoint.clone(), BootstrapMode::BootstrapTunnel)
                    .await
                    .map_err(|err| {
                        let _ = append_operation_event(&self.state, operation.id, &err.to_string());
                        let _ = update_operation_status(&self.state, operation.id, "FAILED");
                        Status::internal(format!("tunnel bootstrap failed: {err}"))
                    })?;
            if !tunnel.success {
                let _ = append_operation_event(
                    &self.state,
                    operation.id,
                    &format_bootstrap_failure(&tunnel),
                );
                let _ = update_operation_status(&self.state, operation.id, "FAILED");
                return Ok(Response::new(DeployResponse {
                    success: false,
                    deployment: Some(bundle_to_proto_summary(&bundle, &target)),
                    provider: Some(provider_observation_from_request(
                        &request,
                        &target.target_ip,
                    )),
                    runtime: Some(RuntimeObservation::from_agent_state(
                        &tunnel
                            .post_state
                            .clone()
                            .unwrap_or_else(AgentState::bootstrap_placeholder),
                    )),
                    warnings: tunnel.warnings,
                    operation: Some(operation_with_status(operation, "FAILED")),
                }));
            }
            append_operation_event(&self.state, operation.id, "tunnel bootstrap completed")?;
        }

        let runtime_state = verify_agent_runtime(&self.agent_endpoint, true)
            .await
            .map_err(|err| {
                Status::internal(format!("failed to verify runtime readiness: {err}"))
            })?;
        let runtime = RuntimeObservation::from_agent_state(&runtime_state);

        let sync = sync_local_config(
            &default_local_config_path(&self.repo_root),
            &default_live_state_path(&self.repo_root),
            &default_runtime_root(&self.repo_root),
        )
        .map_err(|err| Status::internal(format!("failed to sync local config: {err}")))?;
        append_operation_event(
            &self.state,
            operation.id,
            &format!(
                "local config synced for instance {}",
                sync.instance_id.unwrap_or_default()
            ),
        )?;

        update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
        let response = DeployResponse {
            success: true,
            deployment: Some(bundle_to_proto_summary(&bundle, &target)),
            provider: Some(provider_observation_from_request(
                &request,
                &target.target_ip,
            )),
            runtime: Some(runtime),
            warnings: apply_response.warnings,
            operation: Some(operation_with_status(operation, "SUCCEEDED")),
        };
        store_local_response(&self.state, "deploy_response", &response.encode_to_vec())?;
        Ok(Response::new(response))
    }

    async fn destroy(
        &self,
        request: Request<DestroyRequest>,
    ) -> Result<Response<DestroyResponse>, Status> {
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("destroy", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "destroy requested")?;

        let existing = read_live_deployment_summary(&self.repo_root)
            .map_err(|err| Status::internal(format!("failed to read current state: {err}")))?;
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

        if request.delete_dns {
            let note = delete_dns_record(&request)
                .await
                .map_err(Status::internal)?;
            append_operation_event(&self.state, operation.id, &note)?;
        }
        if request.delete_instance && !instance_id.trim().is_empty() && !request.mock_provider {
            if let Ok(api_key) = env::var("VULTR_API_KEY") {
                destroy_instance(&api_key, &instance_id)
                    .await
                    .map_err(Status::internal)?;
                append_operation_event(
                    &self.state,
                    operation.id,
                    "Vultr instance destroy requested",
                )?;
            }
        }

        clear_live_deployment_state(&self.repo_root, &self.state, &instance_id)
            .map_err(|err| Status::internal(format!("failed to clear deployment state: {err}")))?;
        append_operation_event(
            &self.state,
            operation.id,
            &format!("cleared deployment state for {}", instance_id),
        )?;

        update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
        let response = DestroyResponse {
            success: true,
            warnings: if target_ip.trim().is_empty() {
                vec!["destroy completed without a known target IP".to_owned()]
            } else {
                Vec::new()
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
    env::var("EDGE_SINGBOX_BINARY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SINGBOX_BINARY_PATH))
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
) -> SelectorState {
    let mut selector = base_selector.unwrap_or_else(SelectorState::placeholder);
    let Some(controller_url) = clash_controller_url(&local_singbox) else {
        selector.degraded = true;
        selector
            .warnings
            .push("clash API endpoint is not configured".to_owned());
        return selector;
    };

    match get_live_selector_state(&controller_url).await {
        Ok(live) => merge_selector_state(selector, live),
        Err(err) => {
            selector.degraded = true;
            selector.warnings.push(err);
            selector
        }
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

#[derive(Debug, Clone)]
struct ResolvedDeployTarget {
    instance_id: String,
    target_ip: String,
}

async fn resolve_deploy_target(request: &DeployRequest) -> Result<ResolvedDeployTarget, String> {
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
        });
    }

    if let (Some(instance_id), Ok(api_key)) =
        (request.instance_id.as_deref(), env::var("VULTR_API_KEY"))
    {
        let instance = get_instance(&api_key, instance_id).await?;
        if !instance.main_ip.trim().is_empty() {
            return Ok(ResolvedDeployTarget {
                instance_id: instance.id,
                target_ip: instance.main_ip,
            });
        }
    }

    let Some(target_ip) = request
        .target_ip
        .clone()
        .filter(|value| !value.trim().is_empty())
    else {
        return Err(
            "deploy requires target_ip or a resolvable instance_id; new host bootstrap is not wired into Rust yet"
                .to_owned(),
        );
    };

    Ok(ResolvedDeployTarget {
        instance_id: request
            .instance_id
            .clone()
            .unwrap_or_else(|| format!("manual-{}", target_ip.replace('.', "-"))),
        target_ip,
    })
}

async fn apply_bundle_to_agent(
    endpoint: &str,
    bundle: &PreparedDeploymentBundle,
) -> Result<edge_shared_types::ApplyBundleResponse, String> {
    let channel = connect_to_agent(endpoint.to_owned())
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

async fn verify_agent_runtime(
    endpoint: &str,
    require_readiness: bool,
) -> Result<AgentState, String> {
    let channel = connect_to_agent(endpoint.to_owned())
        .await
        .map_err(|err| format!("failed to connect to edge-agent: {err}"))?;
    let mut client = AgentServiceClient::<Channel>::new(channel);
    let response = client
        .verify_runtime(Request::new(VerifyRuntimeRequest { require_readiness }))
        .await
        .map_err(|err| format!("edge-agent verify runtime RPC failed: {err}"))?;
    Ok(response.into_inner())
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

async fn apply_dns_update(request: &DeployRequest, target_ip: &str) -> Result<String, String> {
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

    let api_token = env::var("CLOUDFLARE_API_TOKEN")
        .map_err(|_| "CLOUDFLARE_API_TOKEN is required for DNS cutover".to_owned())?;
    let record = upsert_a_record(&api_token, &zone_name, &record_name, target_ip).await?;
    Ok(format!(
        "DNS updated: {} -> {} ({})",
        record.record_name, record.ip, record.zone_id
    ))
}

async fn delete_dns_record(request: &DestroyRequest) -> Result<String, String> {
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

    let api_token = env::var("CLOUDFLARE_API_TOKEN")
        .map_err(|_| "CLOUDFLARE_API_TOKEN is required to delete DNS record".to_owned())?;
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
        .record_deployment(&bundle.label, &target.instance_id, &target.target_ip)
        .map_err(|err| format!("failed to record deployment: {err}"))?;
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
        })
        .map_err(|err| format!("failed to record trust entry: {err}"))?;
    Ok(())
}

fn read_live_deployment_summary(
    repo_root: &Path,
) -> Result<edge_shared_types::DeploymentSummary, String> {
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

fn clear_live_deployment_state(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    instance_id: &str,
) -> Result<(), String> {
    let live_state_path = default_live_state_path(repo_root);
    if live_state_path.is_file() {
        fs::remove_file(&live_state_path)
            .map_err(|err| format!("failed to remove {}: {err}", live_state_path.display()))?;
    }

    state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?
        .clear_deployment_by_instance(instance_id)
        .map_err(|err| format!("failed to clear deployment row: {err}"))?;
    Ok(())
}

fn agent_endpoint_from_env() -> String {
    env::var("EDGE_AGENT_ENDPOINT").unwrap_or_else(|_| DEFAULT_AGENT_ENDPOINT.to_owned())
}

async fn observe_agent(endpoint: &str) -> (AgentState, RuntimeObservation) {
    let Ok(channel) = connect_to_agent(endpoint.to_owned()).await else {
        let reason = format!("edge-agent is unreachable at {endpoint}");
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
        let reason = format!("edge-agent runtime RPC failed at {endpoint}");
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

async fn connect_to_agent(endpoint: String) -> Result<Channel, Box<dyn std::error::Error>> {
    let tls = optional_agent_client_tls_from_env()
        .map_err(|err| format!("failed to load controller TLS configuration: {err}"))?;
    let endpoint = agent_endpoint_scheme(&endpoint, tls.is_some());
    let mut transport = Endpoint::from_shared(endpoint)?;
    if let Some(tls) = tls {
        transport = transport.tls_config(tls)?;
    }
    Ok(transport.connect().await?)
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
        let repo_root = PathBuf::from("/home/bose/projects/sing-box");
        let db_path = repo_root.join("edge-platform/.runtime/test-controller-state.sqlite");
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        let service = ControllerServerImpl {
            repo_root,
            state,
            agent_endpoint: "http://127.0.0.1:59999".to_owned(),
        };

        let response = service.get_status(Request::new(Empty {})).await.unwrap();
        assert!(response.get_ref().inventory.is_some());
        assert!(response.get_ref().runtime.is_some());
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
        let target = resolve_deploy_target(&DeployRequest {
            label_prefix: Some("mock-edge".to_owned()),
            target_ip: None,
            instance_id: None,
            tunnel_domain: None,
            acme_email: None,
            dns_record_name: None,
            cloudflare_zone_name: None,
            mock_provider: true,
            skip_dns: true,
        })
        .await
        .unwrap();

        assert!(target.instance_id.starts_with("mock-"));
        assert_eq!(target.target_ip, "203.0.113.10");
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

    fn temp_repo_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-controller-test-{unique}"))
    }
}
