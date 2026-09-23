mod cli;
mod docker_observation;
mod error;
mod host_diagnostics;
mod mesh_network_diagnostics;
mod network_observation;
mod runtime_probe;

use crate::docker_observation::{
    ContainerRuntimeEvidence, DockerObservation, observe_container_runtime, observe_docker,
};
use crate::host_diagnostics::collect_host_runtime_diagnostics;
use crate::mesh_network_diagnostics::{
    collect_container_network_diagnostics, collect_host_network_diagnostics, extract_route_events,
};
use crate::runtime_probe::{BoundedCommandProbe, bounded_command_probe};
use clap::Parser;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use edge_observability::init as init_observability;
use edge_secrets::ApplicationRuntimeSecrets;
use edge_shared_types::agent_service_server::{AgentService, AgentServiceServer};
use edge_shared_types::{
    AgentState, AgentVersion, ApplyBundleRequest, ApplyBundleResponse, BootstrapMode,
    BootstrapRuntimeRequest, BootstrapRuntimeResponse, BundleFile, Empty, FileCategory,
    FilePresence, Ipv4NetworkObservation, MeshContainerDiagnostics, MeshRuntimeConvergeRequest,
    MeshRuntimeDiagnostics, MeshRuntimeFailureSnapshot, MeshRuntimeState,
    ReadBundleIdentityRequest, ReadBundleIdentityResponse, ReadRenderedArtifactsRequest,
    ReadRenderedArtifactsResponse, RollbackBundleRequest, RollbackBundleResponse,
    RuntimeProbeEvidence, RuntimeProbeStatus, VerifyRuntimeRequest, canonical_apply_bundle_digest,
};
use edge_trust::optional_agent_server_tls_from_env;
use error::AgentError;
use serde::{Deserialize, Serialize};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const DEFAULT_AGENT_ADDR: &str = "127.0.0.1:50061";
const DEFAULT_STACK_DIR: &str = "/opt/vultr-edge-stack/stack";
const APPLICATION_RELEASE_MARKER: &str = ".application-release.json";
const PREVIOUS_STACK_DIR: &str = "stack.previous";
const STAGING_STACK_DIR: &str = "stack.next";
const ROLLBACK_STACK_DIR: &str = "stack.rollback";
const RUNTIME_POLICY_FILE: &str = ".env.runtime.policy";
const RUNTIME_ENV_FILE: &str = ".env.runtime";
const RUNTIME_SECRET_DIR: &str = "runtime-secrets";
const RUNTIME_SECRET_FILE: &str = "application-runtime-v1.env";
const MESH_RUNTIME_SECRET_FILE: &str = "mesh-node-v1.env";
const MESH_RUNTIME_FAILURE_FILE: &str = "last-readiness-failure-v1.json";
const MAX_MESH_FAILURE_REASONS: usize = 12;
const MAX_MESH_FAILURE_REASON_CHARS: usize = 512;
const IMAGE_ENV_FILE: &str = ".images.env";
const MESH_NODE_TOKEN_KEY: &str = "MESH_NODE_TOKEN";
const EDGE_GATEWAY_IMAGE_KEY: &str = "EDGE_GATEWAY_IMAGE";
const EDGE_WARP_EGRESS_IMAGE_KEY: &str = "EDGE_WARP_EGRESS_IMAGE";
const EDGE_MESH_IMAGE_KEY: &str = "CLOUDFLARE_MESH_IMAGE";
const WARP_CONTAINER: &str = "vultr-warp-egress";
const LINE1_CONTAINER: &str = "vultr-line1-gateway";
const LINE2_CONTAINER: &str = "vultr-line2-proxy";
const MESH_CONTAINER: &str = "vultr-cloudflare-mesh";
const CLOUDFLARE_TRACE_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";

#[tokio::main]
async fn main() -> ExitCode {
    let telemetry = init_observability("edge-agent");
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
        component = "edge-agent",
        correlation_id = %telemetry.id(),
        command,
        event = "command.start",
        "command started"
    );

    match run(parsed).await {
        Ok(()) => {
            tracing::info!(
                component = "edge-agent",
                correlation_id = %telemetry.id(),
                command,
                event = "command.success",
                "command completed"
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(
                component = "edge-agent",
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

async fn run(parsed: cli::Cli) -> Result<(), AgentError> {
    use cli::Command;

    match parsed
        .command
        .unwrap_or_else(|| Command::Serve(cli::ServeArgs::default()))
    {
        Command::Serve(args) => {
            let (addr, stack_dir) = args.resolve().map_err(AgentError::Command)?;
            serve(addr, stack_dir).await?;
            Ok(())
        }
    }
}

async fn serve(addr: SocketAddr, stack_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = Server::builder();
    if let Some(tls) = optional_agent_server_tls_from_env()
        .map_err(|err| format!("failed to load edge-agent TLS configuration: {err}"))?
    {
        builder = builder
            .tls_config(tls)
            .map_err(|err| format!("failed to apply edge-agent TLS configuration: {err}"))?;
    }

    builder
        .add_service(AgentServiceServer::new(AgentServerImpl { stack_dir }))
        .serve(addr)
        .await?;
    Ok(())
}

struct AgentServerImpl {
    stack_dir: PathBuf,
}

#[tonic::async_trait]
impl AgentService for AgentServerImpl {
    async fn get_health(&self, _request: Request<Empty>) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(
            inspect_runtime(&self.stack_dir, AgentMode::Health).await,
        ))
    }

    async fn get_readiness(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(
            inspect_runtime(&self.stack_dir, AgentMode::Readiness).await,
        ))
    }

    async fn get_runtime_state(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(
            inspect_runtime(&self.stack_dir, AgentMode::Runtime).await,
        ))
    }

    async fn get_version(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentVersion>, Status> {
        Ok(Response::new(AgentVersion {
            name: "edge-agent".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }))
    }

    async fn observe_ipv4_network(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Ipv4NetworkObservation>, Status> {
        let observation = network_observation::observe_ipv4_network()
            .await
            .map_err(|err| Status::internal(format!("IPv4 network observation failed: {err}")))?;
        Ok(Response::new(observation))
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

        Ok(Response::new(run_bootstrap(&self.stack_dir, mode).await))
    }

    async fn apply_bundle(
        &self,
        request: Request<ApplyBundleRequest>,
    ) -> Result<Response<ApplyBundleResponse>, Status> {
        let response = apply_bundle(&self.stack_dir, request.into_inner())
            .map_err(|err| Status::internal(format!("failed to apply bundle: {err}")))?;
        Ok(Response::new(response))
    }

    async fn rollback_bundle(
        &self,
        request: Request<RollbackBundleRequest>,
    ) -> Result<Response<RollbackBundleResponse>, Status> {
        let response = rollback_bundle(&self.stack_dir, request.into_inner()).map_err(|err| {
            Status::failed_precondition(format!("bundle rollback refused: {err}"))
        })?;
        Ok(Response::new(response))
    }

    async fn verify_runtime(
        &self,
        request: Request<VerifyRuntimeRequest>,
    ) -> Result<Response<AgentState>, Status> {
        let request = request.into_inner();
        let inspection_mode = if request.require_readiness {
            AgentMode::Readiness
        } else {
            AgentMode::Runtime
        };
        let mut state = inspect_runtime(&self.stack_dir, inspection_mode).await;
        let bootstrap_mode = BootstrapMode::try_from(request.mode)
            .map_err(|_| Status::invalid_argument("unknown bootstrap verification mode"))?;
        if bootstrap_mode != BootstrapMode::Unspecified {
            let verified = verify_bootstrap_post_state(&self.stack_dir, bootstrap_mode, &state);
            if request.require_readiness {
                state.ready = verified.success;
            }
            for warning in verified.warnings {
                if !state.degraded_reasons.iter().any(|value| value == &warning) {
                    state.degraded_reasons.push(warning);
                }
            }
        }
        Ok(Response::new(state))
    }

    async fn read_bundle_identity(
        &self,
        _request: Request<ReadBundleIdentityRequest>,
    ) -> Result<Response<ReadBundleIdentityResponse>, Status> {
        let summary_path = self
            .stack_dir
            .parent()
            .map(|parent| parent.join("deployment-summary.json"));
        let summary = summary_path
            .as_ref()
            .filter(|path| path.is_file())
            .and_then(|path| read_bundle_summary(path));

        let active_release = read_application_release(&self.stack_dir);
        let previous_release = read_application_release(&previous_stack_dir(&self.stack_dir));

        Ok(Response::new(ReadBundleIdentityResponse {
            active_bundle_id: active_release
                .as_ref()
                .map(|release| release.bundle_id.clone())
                .or_else(|| summary.as_ref().and_then(|summary| summary.label.clone())),
            topology_version: summary
                .as_ref()
                .and_then(|summary| summary.instance_id.clone())
                .map(|instance_id| format!("vultr-edge:{instance_id}")),
            deployment_summary_path: summary_path.map(|path| path.display().to_string()),
            active_bundle_digest: active_release
                .as_ref()
                .map(|release| release.bundle_digest.clone()),
            previous_bundle_id: previous_release
                .as_ref()
                .map(|release| release.bundle_id.clone()),
            previous_bundle_digest: previous_release
                .as_ref()
                .map(|release| release.bundle_digest.clone()),
        }))
    }

    async fn read_rendered_artifacts(
        &self,
        _request: Request<ReadRenderedArtifactsRequest>,
    ) -> Result<Response<ReadRenderedArtifactsResponse>, Status> {
        Ok(Response::new(ReadRenderedArtifactsResponse {
            files: collect_rendered_artifacts(&self.stack_dir),
        }))
    }

    async fn converge_mesh_runtime(
        &self,
        request: Request<MeshRuntimeConvergeRequest>,
    ) -> Result<Response<MeshRuntimeState>, Status> {
        let state = converge_mesh_runtime(&self.stack_dir, &request.into_inner().node_token)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!("Mesh runtime convergence failed: {err}"))
            })?;
        Ok(Response::new(state))
    }

    async fn verify_mesh_runtime(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<MeshRuntimeState>, Status> {
        Ok(Response::new(
            inspect_mesh_runtime(&self.stack_dir, MeshDiagnosticDepth::Deep).await,
        ))
    }

    async fn cleanup_mesh_runtime(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<MeshRuntimeState>, Status> {
        let state = cleanup_mesh_runtime(&self.stack_dir).await.map_err(|err| {
            Status::failed_precondition(format!("Mesh runtime cleanup failed: {err}"))
        })?;
        Ok(Response::new(state))
    }
}

#[derive(Clone, Copy)]
enum AgentMode {
    Health,
    Readiness,
    Runtime,
}

async fn inspect_runtime(stack_dir: &Path, mode: AgentMode) -> AgentState {
    let mut state = AgentState {
        healthy: true,
        ready: false,
        topology_version: "vultr-edge".to_owned(),
        active_bundle_id: stack_dir
            .file_name()
            .map(|name| name.to_string_lossy().to_string()),
        degraded_reasons: Vec::new(),
        docker_reachable: false,
        compose_file_present: false,
        observed_stack_path: Some(stack_dir.display().to_string()),
        running_containers: Vec::new(),
        missing_containers: Vec::new(),
        listening_tcp_ports: Vec::new(),
        listening_udp_ports: Vec::new(),
        direct_egress_ready: None,
        warp_egress_ready: None,
        mesh_runtime_ready: None,
    };

    inspect_bundle_artifacts(stack_dir, &mut state);

    let compose_path = stack_dir.join("docker-compose.yml");
    let enabled_profiles = enabled_application_profiles(stack_dir);
    let line2_enabled = line2_runtime_enabled(stack_dir);
    let Some(compose) =
        inspect_compose(&compose_path, &mut state, &enabled_profiles, line2_enabled)
    else {
        state.healthy = false;
        return state;
    };

    let docker = observe_docker()
        .await
        .unwrap_or_else(|_| DockerObservation::unreachable());
    state.docker_reachable = docker.reachable;
    state.running_containers = docker.running_containers.clone();
    state.listening_tcp_ports = docker.listening_tcp_ports.clone();
    state.listening_udp_ports = docker.listening_udp_ports.clone();

    state.missing_containers = compose
        .expected_containers
        .iter()
        .filter(|name| {
            !docker
                .running_containers
                .iter()
                .any(|running| running == *name)
        })
        .cloned()
        .collect();

    if !docker.reachable {
        state
            .degraded_reasons
            .push("docker runtime is not reachable from edge-agent".to_owned());
    }
    if !state.missing_containers.is_empty() {
        state.degraded_reasons.push(format!(
            "expected containers are not running: {}",
            state.missing_containers.join(", ")
        ));
    }

    let expected_tcp = compose.expected_tcp_ports;
    let expected_udp = compose.expected_udp_ports;
    let missing_tcp = expected_tcp
        .iter()
        .filter(|port| !state.listening_tcp_ports.iter().any(|value| value == *port))
        .copied()
        .collect::<Vec<_>>();
    let missing_udp = expected_udp
        .iter()
        .filter(|port| !state.listening_udp_ports.iter().any(|value| value == *port))
        .copied()
        .collect::<Vec<_>>();

    if !missing_tcp.is_empty() {
        state.degraded_reasons.push(format!(
            "expected TCP ports are not listening: {}",
            join_ports(&missing_tcp)
        ));
    }
    if !missing_udp.is_empty() {
        state.degraded_reasons.push(format!(
            "expected UDP ports are not listening: {}",
            join_ports(&missing_udp)
        ));
    }

    let datapaths_ready = if matches!(mode, AgentMode::Health) {
        true
    } else {
        inspect_datapath_readiness(&mut state, &docker).await
    };

    state.ready = state.compose_file_present
        && !state
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("bundle artifact"))
        && state.docker_reachable
        && state.missing_containers.is_empty()
        && missing_tcp.is_empty()
        && missing_udp.is_empty()
        && datapaths_ready;

    if matches!(mode, AgentMode::Health) {
        state.ready = false;
    }
    if matches!(mode, AgentMode::Readiness) {
        state.healthy = state.compose_file_present && state.docker_reachable;
    }

    state
}

fn apply_bundle(
    stack_dir: &Path,
    request: ApplyBundleRequest,
) -> Result<ApplyBundleResponse, String> {
    match (
        request.bundle_id.as_deref(),
        request.bundle_digest.as_deref(),
    ) {
        (Some(_), Some(_)) => apply_digest_bound_bundle(stack_dir, request),
        (None, None) => apply_legacy_bundle(stack_dir, request),
        _ => Err(
            "bundle_id and bundle_digest must either both be present or both be absent".to_owned(),
        ),
    }
}

fn apply_legacy_bundle(
    stack_dir: &Path,
    request: ApplyBundleRequest,
) -> Result<ApplyBundleResponse, String> {
    let host_root = stack_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| stack_dir.to_path_buf());
    let mut written_paths = Vec::new();
    let mut warnings = Vec::new();

    if request.prune_existing && stack_dir.exists() {
        fs::remove_dir_all(stack_dir)
            .map_err(|err| format!("failed to remove {}: {err}", stack_dir.display()))?;
    }
    fs::create_dir_all(stack_dir)
        .map_err(|err| format!("failed to create {}: {err}", stack_dir.display()))?;

    for file in request.stack_files {
        write_bundle_file(stack_dir, &file, &mut written_paths)?;
    }
    for file in request.host_files {
        write_bundle_file(&host_root, &file, &mut written_paths)?;
    }
    if let Some(file) = request.deployment_summary {
        write_bundle_file(&host_root, &file, &mut written_paths)?;
    } else {
        warnings.push("deployment summary was not provided".to_owned());
    }
    if let Some(file) = request.agent_env_file {
        write_bundle_file(&host_root, &file, &mut written_paths)?;
    } else {
        warnings.push("edge-agent environment file was not provided".to_owned());
    }

    Ok(ApplyBundleResponse {
        success: true,
        written_paths,
        stack_dir: Some(stack_dir.display().to_string()),
        warnings,
        active_bundle_id: None,
        active_bundle_digest: None,
        previous_bundle_id: None,
        previous_bundle_digest: None,
    })
}

fn apply_digest_bound_bundle(
    stack_dir: &Path,
    request: ApplyBundleRequest,
) -> Result<ApplyBundleResponse, String> {
    if !request.prune_existing {
        return Err("digest-bound application bundles require prune_existing=true".to_owned());
    }
    if !request.host_files.is_empty()
        || request.deployment_summary.is_some()
        || request.agent_env_file.is_some()
    {
        return Err(
            "digest-bound application bundles may contain only stack_files; host mutation remains a separate typed operation"
                .to_owned(),
        );
    }

    let bundle_id = request
        .bundle_id
        .clone()
        .ok_or_else(|| "bundle_id is required".to_owned())?;
    let expected_digest = request
        .bundle_digest
        .clone()
        .ok_or_else(|| "bundle_digest is required".to_owned())?;
    validate_lower_hex("bundle_digest", &expected_digest, 64)?;
    let computed_digest = canonical_apply_bundle_digest(&request)?;
    if computed_digest != expected_digest {
        return Err(format!(
            "bundle digest mismatch: expected {expected_digest}, computed {computed_digest}"
        ));
    }

    if let Some(current) = read_application_release(stack_dir)
        && current.bundle_id == bundle_id
        && current.bundle_digest == expected_digest
    {
        let previous = read_application_release(&previous_stack_dir(stack_dir));
        return Ok(bundle_apply_response(
            stack_dir,
            Vec::new(),
            Vec::new(),
            &current,
            previous.as_ref(),
        ));
    }

    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no parent".to_owned())?;
    let staging = parent.join(STAGING_STACK_DIR);
    let previous = parent.join(PREVIOUS_STACK_DIR);
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|err| {
            format!(
                "failed to clear stale staging stack {}: {err}",
                staging.display()
            )
        })?;
    }
    fs::create_dir_all(&staging).map_err(|err| {
        format!(
            "failed to create staging stack {}: {err}",
            staging.display()
        )
    })?;

    let mut written_paths = Vec::new();
    for file in &request.stack_files {
        write_bundle_file(&staging, file, &mut written_paths)?;
    }
    materialize_vm_owned_runtime_environment(&staging)?;

    let release = ApplicationBundleRelease {
        schema: 1,
        bundle_id,
        bundle_digest: expected_digest,
    };
    write_application_release(&staging, &release)?;

    let old_release = read_application_release(stack_dir);
    if stack_dir.exists() {
        if previous.exists() {
            fs::remove_dir_all(&previous).map_err(|err| {
                format!(
                    "failed to remove previous application stack {}: {err}",
                    previous.display()
                )
            })?;
        }
        fs::rename(stack_dir, &previous).map_err(|err| {
            format!(
                "failed to rotate active stack {} to {}: {err}",
                stack_dir.display(),
                previous.display()
            )
        })?;
    }

    if let Err(err) = fs::rename(&staging, stack_dir) {
        if previous.exists() && !stack_dir.exists() {
            let _ = fs::rename(&previous, stack_dir);
        }
        return Err(format!(
            "failed to atomically activate staged stack {}: {err}",
            staging.display()
        ));
    }

    Ok(bundle_apply_response(
        stack_dir,
        written_paths,
        Vec::new(),
        &release,
        old_release.as_ref(),
    ))
}

fn rollback_bundle(
    stack_dir: &Path,
    request: RollbackBundleRequest,
) -> Result<RollbackBundleResponse, String> {
    validate_lower_hex(
        "expected_current_bundle_digest",
        &request.expected_current_bundle_digest,
        64,
    )?;
    let current = read_application_release(stack_dir)
        .ok_or_else(|| "active application release marker is missing".to_owned())?;
    if current.bundle_digest != request.expected_current_bundle_digest {
        return Err(
            "current bundle digest changed since rollback authorization; refusing stale rollback"
                .to_owned(),
        );
    }

    let previous = previous_stack_dir(stack_dir);
    let previous_release = read_application_release(&previous)
        .ok_or_else(|| "previous application release is unavailable".to_owned())?;
    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no parent".to_owned())?;
    let rollback = parent.join(ROLLBACK_STACK_DIR);
    if rollback.exists() {
        return Err(format!(
            "rollback scratch path already exists: {}; refusing to guess recovery state",
            rollback.display()
        ));
    }

    fs::rename(stack_dir, &rollback).map_err(|err| {
        format!(
            "failed to stage current stack for rollback {}: {err}",
            stack_dir.display()
        )
    })?;
    if let Err(err) = fs::rename(&previous, stack_dir) {
        let _ = fs::rename(&rollback, stack_dir);
        return Err(format!(
            "failed to activate previous stack {}: {err}",
            previous.display()
        ));
    }
    if let Err(err) = fs::rename(&rollback, &previous) {
        let _ = fs::rename(stack_dir, &previous);
        let _ = fs::rename(&rollback, stack_dir);
        return Err(format!(
            "failed to complete rollback stack swap; attempted restoration: {err}"
        ));
    }

    Ok(RollbackBundleResponse {
        success: true,
        active_bundle_id: Some(previous_release.bundle_id.clone()),
        active_bundle_digest: Some(previous_release.bundle_digest.clone()),
        previous_bundle_id: Some(current.bundle_id),
        previous_bundle_digest: Some(current.bundle_digest),
        warnings: Vec::new(),
    })
}

fn bundle_apply_response(
    stack_dir: &Path,
    written_paths: Vec<String>,
    warnings: Vec<String>,
    active: &ApplicationBundleRelease,
    previous: Option<&ApplicationBundleRelease>,
) -> ApplyBundleResponse {
    ApplyBundleResponse {
        success: true,
        written_paths,
        stack_dir: Some(stack_dir.display().to_string()),
        warnings,
        active_bundle_id: Some(active.bundle_id.clone()),
        active_bundle_digest: Some(active.bundle_digest.clone()),
        previous_bundle_id: previous.map(|release| release.bundle_id.clone()),
        previous_bundle_digest: previous.map(|release| release.bundle_digest.clone()),
    }
}

fn previous_stack_dir(stack_dir: &Path) -> PathBuf {
    stack_dir
        .parent()
        .map(|parent| parent.join(PREVIOUS_STACK_DIR))
        .unwrap_or_else(|| PathBuf::from(PREVIOUS_STACK_DIR))
}

fn read_application_release(stack_dir: &Path) -> Option<ApplicationBundleRelease> {
    let raw = fs::read_to_string(stack_dir.join(APPLICATION_RELEASE_MARKER)).ok()?;
    let release: ApplicationBundleRelease = serde_json::from_str(&raw).ok()?;
    (release.schema == 1 && validate_lower_hex("bundle_digest", &release.bundle_digest, 64).is_ok())
        .then_some(release)
}

fn write_application_release(
    stack_dir: &Path,
    release: &ApplicationBundleRelease,
) -> Result<(), String> {
    let raw = serde_json::to_vec(release)
        .map_err(|err| format!("failed to encode application release marker: {err}"))?;
    fs::write(stack_dir.join(APPLICATION_RELEASE_MARKER), raw)
        .map_err(|err| format!("failed to write application release marker: {err}"))
}

fn materialize_vm_owned_runtime_environment(stack_dir: &Path) -> Result<(), String> {
    let policy_path = stack_dir.join(RUNTIME_POLICY_FILE);
    if !policy_path.is_file() {
        return Ok(());
    }

    let policy = fs::read_to_string(&policy_path).map_err(|err| {
        format!(
            "failed to read runtime policy {}: {err}",
            policy_path.display()
        )
    })?;
    validate_runtime_policy_env(&policy)?;

    let secrets = ensure_vm_runtime_secret_store(stack_dir)?;
    let mut runtime = policy;
    if !runtime.ends_with('\n') {
        runtime.push('\n');
    }
    runtime.push_str(&secrets.render_env());

    let runtime_path = stack_dir.join(RUNTIME_ENV_FILE);
    fs::write(&runtime_path, runtime.as_bytes()).map_err(|err| {
        format!(
            "failed to write derived runtime environment {}: {err}",
            runtime_path.display()
        )
    })?;
    set_bundle_file_permissions(&runtime_path, false, true)?;
    Ok(())
}

fn validate_runtime_policy_env(raw: &str) -> Result<(), String> {
    let line2 = ["PROXY_USERNAME", "PROXY_CERT_CN"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let line1 = [
        "REALITY_SERVER_NAME",
        "TUNNEL_DOMAIN",
        "ACME_EMAIL",
        "ACME_PROVIDER",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let full = line1.union(&line2).copied().collect::<BTreeSet<_>>();
    let allowed = full.clone();
    let mut observed = BTreeSet::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "runtime policy line {} must use KEY=VALUE syntax",
                index + 1
            )
        })?;
        if !allowed.contains(key) {
            return Err(format!("unsupported runtime policy key: {key}"));
        }
        if value.is_empty()
            || value.len() > 253
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b':' | b'@' | b'%' | b'+' | b'/' | b'-')
            })
        {
            return Err(format!(
                "runtime policy {key} must be a non-empty shell-safe policy value"
            ));
        }
        if !observed.insert(key) {
            return Err(format!("runtime policy key is duplicated: {key}"));
        }
    }
    if observed != line2 && observed != line1 && observed != full {
        return Err(
            "runtime policy key set must exactly match base, tunnel, or full application policy"
                .to_owned(),
        );
    }
    Ok(())
}

fn ensure_vm_runtime_secret_store(stack_dir: &Path) -> Result<ApplicationRuntimeSecrets, String> {
    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no parent".to_owned())?;
    let dir = parent.join(RUNTIME_SECRET_DIR);
    let path = dir.join(RUNTIME_SECRET_FILE);

    if path.exists() {
        let raw = fs::read_to_string(&path).map_err(|err| {
            format!(
                "failed to read VM runtime secret store {}: {err}",
                path.display()
            )
        })?;
        return ApplicationRuntimeSecrets::parse_env(&raw).map_err(|err| {
            format!(
                "VM runtime secret store {} is invalid: {err}",
                path.display()
            )
        });
    }

    fs::create_dir_all(&dir).map_err(|err| {
        format!(
            "failed to create runtime secret directory {}: {err}",
            dir.display()
        )
    })?;
    set_private_directory_permissions(&dir)?;

    let generated = ApplicationRuntimeSecrets::generate();
    generated.validate()?;
    let temporary = dir.join(format!("{RUNTIME_SECRET_FILE}.new"));
    fs::write(&temporary, generated.render_env().as_bytes()).map_err(|err| {
        format!(
            "failed to write staged VM runtime secret store {}: {err}",
            temporary.display()
        )
    })?;
    set_bundle_file_permissions(&temporary, false, true)?;
    fs::rename(&temporary, &path).map_err(|err| {
        format!(
            "failed to atomically publish VM runtime secret store {}: {err}",
            path.display()
        )
    })?;

    let observed = fs::read_to_string(&path).map_err(|err| {
        format!(
            "failed to re-read VM runtime secret store {}: {err}",
            path.display()
        )
    })?;
    ApplicationRuntimeSecrets::parse_env(&observed).map_err(|err| {
        format!(
            "published VM runtime secret store {} failed validation: {err}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("failed to set {} mode 700: {err}", path.display()))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn validate_lower_hex(label: &str, value: &str, expected_len: usize) -> Result<(), String> {
    if value.len() != expected_len
        || !value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must be exactly {expected_len} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationBundleRelease {
    schema: u32,
    bundle_id: String,
    bundle_digest: String,
}

async fn run_bootstrap(stack_dir: &Path, mode: BootstrapMode) -> BootstrapRuntimeResponse {
    let operation = execute_typed_bootstrap(stack_dir, mode).await;
    let post_state = inspect_runtime(stack_dir, AgentMode::Runtime).await;
    let verified = verify_bootstrap_post_state(stack_dir, mode, &post_state);
    let success = operation.is_ok() && verified.success;
    let mut warnings = verified.warnings;
    if let Err(err) = operation {
        warnings.insert(0, err);
    }

    BootstrapRuntimeResponse {
        success,
        mode: mode as i32,
        exit_code: if success { 0 } else { 1 },
        stdout: String::new(),
        stderr: String::new(),
        post_state: Some(post_state),
        warnings,
    }
}

async fn execute_typed_bootstrap(stack_dir: &Path, mode: BootstrapMode) -> Result<(), String> {
    if mode == BootstrapMode::Unspecified {
        return Err("typed bootstrap mode is required".to_owned());
    }

    let runtime = read_typed_runtime_environment(stack_dir)?;
    let images = read_exact_image_environment(stack_dir)?;
    prepare_runtime_directories(stack_dir)?;
    start_warp_egress(stack_dir, &images)?;
    wait_for_warp_datapath()?;

    match mode {
        BootstrapMode::BootstrapBase => {
            require_line2_policy(&runtime)?;
            prepare_base_proxy_certificate(stack_dir, &runtime)?;
            render_line2_runtime(stack_dir, &runtime)?;
            start_line2_proxy(stack_dir, &images)?;
        }
        BootstrapMode::BootstrapTunnel => {
            require_tunnel_policy(&runtime)?;
            render_line1_runtime(stack_dir, &runtime)?;
            start_line1_gateway(stack_dir, &images)?;
            wait_for_owned_certificate(stack_dir).await?;
        }
        BootstrapMode::BootstrapFull => {
            require_line2_policy(&runtime)?;
            require_tunnel_policy(&runtime)?;
            render_line1_runtime(stack_dir, &runtime)?;
            start_line1_gateway(stack_dir, &images)?;
            wait_for_owned_certificate(stack_dir).await?;
            render_line2_runtime(stack_dir, &runtime)?;
            start_line2_proxy(stack_dir, &images)?;
        }
        BootstrapMode::Unspecified => unreachable!("validated above"),
    }

    Ok(())
}

fn read_typed_runtime_environment(stack_dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = stack_dir.join(RUNTIME_ENV_FILE);
    let values = read_strict_env_file(&path)?;

    let allowed = BTreeSet::from([
        "PROXY_USERNAME",
        "PROXY_CERT_CN",
        "REALITY_SERVER_NAME",
        "TUNNEL_DOMAIN",
        "ACME_EMAIL",
        "ACME_PROVIDER",
        "PROXY_PASSWORD",
        "VLESS_UUID",
        "HY2_PASSWORD",
        "REALITY_PRIVATE_KEY",
        "REALITY_PUBLIC_KEY",
        "REALITY_SHORT_ID",
        "VLESS_WARP_UUID",
        "HY2_WARP_PASSWORD",
        "REALITY_WARP_PRIVATE_KEY",
        "REALITY_WARP_PUBLIC_KEY",
        "REALITY_WARP_SHORT_ID",
    ]);
    if let Some(key) = values.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(format!(
            "runtime environment contains unsupported key: {key}"
        ));
    }

    let secret_keys = [
        "PROXY_PASSWORD",
        "VLESS_UUID",
        "HY2_PASSWORD",
        "REALITY_PRIVATE_KEY",
        "REALITY_PUBLIC_KEY",
        "REALITY_SHORT_ID",
        "VLESS_WARP_UUID",
        "HY2_WARP_PASSWORD",
        "REALITY_WARP_PRIVATE_KEY",
        "REALITY_WARP_PUBLIC_KEY",
        "REALITY_WARP_SHORT_ID",
    ];
    let mut secret_env = String::new();
    for key in secret_keys {
        let value = values
            .get(key)
            .ok_or_else(|| format!("runtime environment is missing VM-owned credential: {key}"))?;
        secret_env.push_str(key);
        secret_env.push('=');
        secret_env.push_str(value);
        secret_env.push('\n');
    }
    ApplicationRuntimeSecrets::parse_env(&secret_env)
        .map_err(|err| format!("VM-owned runtime credentials are invalid: {err}"))?;

    let line2_count = ["PROXY_USERNAME", "PROXY_CERT_CN"]
        .into_iter()
        .filter(|key| values.contains_key(*key))
        .count();
    if line2_count != 0 && line2_count != 2 {
        return Err("runtime environment contains incomplete Line 2 policy".to_owned());
    }
    let line1_count = ["REALITY_SERVER_NAME", "TUNNEL_DOMAIN", "ACME_EMAIL"]
        .into_iter()
        .filter(|key| values.contains_key(*key))
        .count();
    if line1_count != 0 && line1_count != 3 {
        return Err("runtime environment contains incomplete Line 1 policy".to_owned());
    }
    if line1_count == 0 && line2_count == 0 {
        return Err("runtime environment contains no enabled application capability".to_owned());
    }

    Ok(values)
}

fn read_exact_image_environment(stack_dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = stack_dir.join(IMAGE_ENV_FILE);
    let values = read_strict_env_file(&path)?;
    let expected = BTreeSet::from([
        EDGE_GATEWAY_IMAGE_KEY,
        EDGE_WARP_EGRESS_IMAGE_KEY,
        EDGE_MESH_IMAGE_KEY,
    ]);
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(format!(
            "{IMAGE_ENV_FILE} must contain exactly {EDGE_GATEWAY_IMAGE_KEY}, {EDGE_WARP_EGRESS_IMAGE_KEY}, and {EDGE_MESH_IMAGE_KEY}"
        ));
    }

    validate_exact_image_ref(
        EDGE_GATEWAY_IMAGE_KEY,
        values.get(EDGE_GATEWAY_IMAGE_KEY).unwrap(),
        "ghcr.io/iamaman11/vultr-edge-gateway",
    )?;
    validate_exact_image_ref(
        EDGE_WARP_EGRESS_IMAGE_KEY,
        values.get(EDGE_WARP_EGRESS_IMAGE_KEY).unwrap(),
        "ghcr.io/iamaman11/vultr-warp-egress",
    )?;
    validate_exact_image_ref(
        EDGE_MESH_IMAGE_KEY,
        values.get(EDGE_MESH_IMAGE_KEY).unwrap(),
        "docker.io/cloudflare/mesh",
    )?;
    Ok(values)
}

fn read_strict_env_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read required environment {}: {err}",
            path.display()
        )
    })?;
    let mut values = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "environment {} line {} must use KEY=VALUE syntax",
                path.display(),
                index + 1
            )
        })?;
        if key.is_empty() || key.trim() != key || value.is_empty() {
            return Err(format!(
                "environment {} line {} contains an invalid key or empty value",
                path.display(),
                index + 1
            ));
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!(
                "environment {} contains duplicate key: {key}",
                path.display()
            ));
        }
    }
    Ok(values)
}

fn validate_exact_image_ref(label: &str, value: &str, repository: &str) -> Result<(), String> {
    let prefix = format!("{repository}@sha256:");
    let digest = value
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("{label} must reference exact repository {repository} by digest"))?;
    validate_lower_hex(label, digest, 64)
}

fn prepare_runtime_directories(stack_dir: &Path) -> Result<(), String> {
    for relative in ["certs", "rendered"] {
        fs::create_dir_all(stack_dir.join(relative)).map_err(|err| {
            format!(
                "failed to create typed runtime directory {}: {err}",
                stack_dir.join(relative).display()
            )
        })?;
    }
    set_private_directory_permissions(&stack_dir.join("certs"))?;
    set_private_directory_permissions(&stack_dir.join("rendered"))?;

    let warp_state = warp_runtime_state_dir(stack_dir)?;
    fs::create_dir_all(&warp_state).map_err(|err| {
        format!(
            "failed to create host-level WARP runtime state {}: {err}",
            warp_state.display()
        )
    })?;
    set_private_directory_permissions(&warp_state)?;

    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no host-state parent".to_owned())?;
    let certificate_state = parent.join("certificate-state");
    fs::create_dir_all(&certificate_state).map_err(|err| {
        format!(
            "failed to create certificate owner state {}: {err}",
            certificate_state.display()
        )
    })?;
    set_private_directory_permissions(&certificate_state)?;
    Ok(())
}

fn validate_mesh_node_token(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 16 * 1024
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err("Mesh node token must be a non-empty bounded single-line value".to_owned());
    }
    Ok(())
}

fn warp_runtime_state_dir(stack_dir: &Path) -> Result<PathBuf, String> {
    let host_root = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no host-state parent".to_owned())?;
    Ok(host_root.join("warp-state"))
}

fn mesh_runtime_secret_path(stack_dir: &Path) -> Result<PathBuf, String> {
    let host_root = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no host-state parent".to_owned())?;
    Ok(host_root
        .join(RUNTIME_SECRET_DIR)
        .join(MESH_RUNTIME_SECRET_FILE))
}

fn mesh_runtime_state_dir(stack_dir: &Path) -> Result<PathBuf, String> {
    let host_root = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no host-state parent".to_owned())?;
    Ok(host_root.join("mesh-state"))
}

fn read_mesh_node_token(stack_dir: &Path) -> Result<String, String> {
    let path = mesh_runtime_secret_path(stack_dir)?;
    let raw = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read Mesh runtime secret store: {err}"))?;
    let line = raw
        .strip_suffix('\n')
        .ok_or_else(|| "Mesh runtime secret store must end with one newline".to_owned())?;
    if line.contains('\n') || line.contains('\r') {
        return Err("Mesh runtime secret store must contain exactly one line".to_owned());
    }
    let value = line
        .strip_prefix("MESH_NODE_TOKEN=")
        .ok_or_else(|| "Mesh runtime secret store has an invalid schema".to_owned())?;
    validate_mesh_node_token(value)?;
    Ok(value.to_owned())
}

fn persist_mesh_node_token(stack_dir: &Path, value: &str) -> Result<(), String> {
    validate_mesh_node_token(value)?;
    let path = mesh_runtime_secret_path(stack_dir)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Mesh runtime secret store has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create Mesh runtime secret directory: {err}"))?;
    set_private_directory_permissions(parent)?;

    if path.exists() {
        let observed = read_mesh_node_token(stack_dir)?;
        if observed == value {
            set_bundle_file_permissions(&path, false, true)?;
            return Ok(());
        }
    }

    let temporary = path.with_extension("tmp");
    fs::write(&temporary, format!("{MESH_NODE_TOKEN_KEY}={value}\n"))
        .map_err(|err| format!("failed to write temporary Mesh runtime secret store: {err}"))?;
    set_bundle_file_permissions(&temporary, false, true)?;
    fs::rename(&temporary, &path)
        .map_err(|err| format!("failed to atomically publish Mesh runtime secret store: {err}"))?;
    if read_mesh_node_token(stack_dir)? != value {
        return Err("published Mesh runtime secret store failed exact verification".to_owned());
    }
    Ok(())
}

fn prepare_mesh_runtime_state(stack_dir: &Path) -> Result<(), String> {
    let state = mesh_runtime_state_dir(stack_dir)?;
    fs::create_dir_all(&state)
        .map_err(|err| format!("failed to create host-level Mesh runtime state: {err}"))?;
    set_private_directory_permissions(&state)
}

fn run_mesh_compose(
    stack_dir: &Path,
    images: &BTreeMap<String, String>,
    node_token: &str,
    args: &[&str],
) -> Result<(), String> {
    validate_mesh_node_token(node_token)?;
    let mut command = Command::new("docker");
    command
        .arg("compose")
        .arg("-f")
        .arg("docker-compose.yml")
        .args(args)
        .current_dir(stack_dir)
        .env(
            EDGE_GATEWAY_IMAGE_KEY,
            images.get(EDGE_GATEWAY_IMAGE_KEY).unwrap(),
        )
        .env(
            EDGE_WARP_EGRESS_IMAGE_KEY,
            images.get(EDGE_WARP_EGRESS_IMAGE_KEY).unwrap(),
        )
        .env(
            EDGE_MESH_IMAGE_KEY,
            images.get(EDGE_MESH_IMAGE_KEY).unwrap(),
        )
        .env(MESH_NODE_TOKEN_KEY, node_token)
        .env_remove("COMPOSE_FILE")
        .env_remove("COMPOSE_PROFILES")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = command
        .status()
        .map_err(|err| format!("fixed Mesh compose operation could not start: {err}"))?;
    if !status.success() {
        return Err(format!(
            "fixed Mesh compose operation failed with exit_code={}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshDiagnosticDepth {
    Basic,
    Deep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedMeshRuntimeFailureSnapshot {
    observed_unix_time_seconds: u64,
    reasons: Vec<String>,
    warp_connection_state: Option<String>,
    tunnel_protocol: Option<String>,
    warp_status: i32,
    warp_settings: i32,
    tun_device_status: i32,
    ipv4_forwarding_status: i32,
    container_present: bool,
    container_running: bool,
    container_exit_code: Option<i64>,
    container_restart_count: Option<u64>,
    container_oom_killed: Option<bool>,
}

fn mesh_runtime_failure_snapshot_path(stack_dir: &Path) -> Result<PathBuf, String> {
    Ok(mesh_runtime_state_dir(stack_dir)?.join(MESH_RUNTIME_FAILURE_FILE))
}

fn read_mesh_runtime_failure_snapshot(
    stack_dir: &Path,
) -> Result<Option<MeshRuntimeFailureSnapshot>, String> {
    let path = mesh_runtime_failure_snapshot_path(stack_dir)?;
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read persisted Mesh readiness failure snapshot: {err}"
            ));
        }
    };
    let persisted: PersistedMeshRuntimeFailureSnapshot =
        serde_json::from_str(&raw).map_err(|err| {
            format!("failed to parse persisted Mesh readiness failure snapshot: {err}")
        })?;
    Ok(Some(MeshRuntimeFailureSnapshot {
        observed_unix_time_seconds: persisted.observed_unix_time_seconds,
        reasons: persisted.reasons,
        warp_connection_state: persisted.warp_connection_state,
        tunnel_protocol: persisted.tunnel_protocol,
        warp_status: persisted.warp_status,
        warp_settings: persisted.warp_settings,
        tun_device_status: persisted.tun_device_status,
        ipv4_forwarding_status: persisted.ipv4_forwarding_status,
        container_present: persisted.container_present,
        container_running: persisted.container_running,
        container_exit_code: persisted.container_exit_code,
        container_restart_count: persisted.container_restart_count,
        container_oom_killed: persisted.container_oom_killed,
    }))
}

fn build_mesh_runtime_failure_snapshot(
    diagnostics: Option<&MeshRuntimeDiagnostics>,
    warnings: &[String],
) -> MeshRuntimeFailureSnapshot {
    let container = diagnostics.and_then(|value| value.container.as_ref());
    MeshRuntimeFailureSnapshot {
        observed_unix_time_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        reasons: warnings
            .iter()
            .take(MAX_MESH_FAILURE_REASONS)
            .map(|value| bounded_secret_safe_failure_reason(value))
            .collect(),
        warp_connection_state: diagnostics.and_then(|value| value.warp_connection_state.clone()),
        tunnel_protocol: diagnostics.and_then(|value| value.tunnel_protocol.clone()),
        warp_status: diagnostics
            .and_then(|value| value.warp_status_probe.as_ref())
            .map(|value| value.status)
            .unwrap_or(RuntimeProbeStatus::Unspecified as i32),
        warp_settings: diagnostics
            .and_then(|value| value.warp_settings_probe.as_ref())
            .map(|value| value.status)
            .unwrap_or(RuntimeProbeStatus::Unspecified as i32),
        tun_device_status: diagnostics
            .and_then(|value| value.tun_device_probe.as_ref())
            .map(|value| value.status)
            .unwrap_or(RuntimeProbeStatus::Unspecified as i32),
        ipv4_forwarding_status: diagnostics
            .and_then(|value| value.ipv4_forwarding_probe.as_ref())
            .map(|value| value.status)
            .unwrap_or(RuntimeProbeStatus::Unspecified as i32),
        container_present: container.is_some_and(|value| value.present),
        container_running: container.is_some_and(|value| value.running),
        container_exit_code: container.and_then(|value| value.exit_code),
        container_restart_count: container.and_then(|value| value.restart_count),
        container_oom_killed: container.and_then(|value| value.oom_killed),
    }
}

fn persist_mesh_runtime_failure_snapshot(
    stack_dir: &Path,
    snapshot: &MeshRuntimeFailureSnapshot,
) -> Result<(), String> {
    prepare_mesh_runtime_state(stack_dir)?;
    let persisted = PersistedMeshRuntimeFailureSnapshot {
        observed_unix_time_seconds: snapshot.observed_unix_time_seconds,
        reasons: snapshot.reasons.clone(),
        warp_connection_state: snapshot.warp_connection_state.clone(),
        tunnel_protocol: snapshot.tunnel_protocol.clone(),
        warp_status: snapshot.warp_status,
        warp_settings: snapshot.warp_settings,
        tun_device_status: snapshot.tun_device_status,
        ipv4_forwarding_status: snapshot.ipv4_forwarding_status,
        container_present: snapshot.container_present,
        container_running: snapshot.container_running,
        container_exit_code: snapshot.container_exit_code,
        container_restart_count: snapshot.container_restart_count,
        container_oom_killed: snapshot.container_oom_killed,
    };
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|err| format!("failed to encode Mesh readiness failure snapshot: {err}"))?;
    let path = mesh_runtime_failure_snapshot_path(stack_dir)?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|err| format!("failed to write Mesh readiness failure snapshot: {err}"))?;
    set_bundle_file_permissions(&temporary, false, true)?;
    fs::rename(&temporary, &path)
        .map_err(|err| format!("failed to publish Mesh readiness failure snapshot: {err}"))?;
    Ok(())
}

fn bounded_secret_safe_failure_reason(value: &str) -> String {
    let lowered = value.to_ascii_lowercase();
    if [
        "authorization",
        "bearer ",
        "password",
        "private_key",
        "private key",
        "credential",
        "mesh_node_token",
        "token=",
        "secret=",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        return "[REDACTED_SENSITIVE_REASON]".to_owned();
    }
    value.chars().take(MAX_MESH_FAILURE_REASON_CHARS).collect()
}

async fn inspect_mesh_runtime(
    stack_dir: &Path,
    diagnostic_depth: MeshDiagnosticDepth,
) -> MeshRuntimeState {
    let token_store_path = mesh_runtime_secret_path(stack_dir).ok();
    let token_store_present = token_store_path.as_ref().is_some_and(|path| path.is_file());
    let token_valid = read_mesh_node_token(stack_dir).is_ok();
    let (docker, docker_error) = match observe_docker().await {
        Ok(observation) => (observation, None),
        Err(err) => (DockerObservation::unreachable(), Some(err)),
    };
    let container_running = docker.container_running(MESH_CONTAINER);
    let expected_image = read_exact_image_environment(stack_dir)
        .ok()
        .and_then(|images| images.get(EDGE_MESH_IMAGE_KEY).cloned());
    let exact_image_ready = expected_image
        .as_deref()
        .is_some_and(|expected| docker.container_exact_image_ready(MESH_CONTAINER, expected));
    let diagnostics = if container_running && exact_image_ready {
        Some(collect_mesh_runtime_diagnostics(&docker, diagnostic_depth).await)
    } else {
        None
    };
    let runtime_ready = token_valid
        && container_running
        && exact_image_ready
        && diagnostics
            .as_ref()
            .is_some_and(mesh_runtime_diagnostics_ready);

    let mut warnings = Vec::new();
    if let Some(err) = docker_error {
        warnings.push(format!("Docker runtime observation failed: {err}"));
    }
    if !token_store_present {
        warnings.push("Mesh runtime token store is absent".to_owned());
    } else if !token_valid {
        warnings.push("Mesh runtime token store is invalid".to_owned());
    }
    if !container_running {
        warnings.push("Mesh runtime container is not running".to_owned());
    }
    if container_running && !exact_image_ready {
        warnings.push("Mesh runtime container does not use the exact accepted image".to_owned());
    }
    if let Some(diagnostics) = diagnostics.as_ref()
        && !mesh_runtime_diagnostics_ready(diagnostics)
    {
        append_mesh_runtime_diagnostic_warnings(diagnostics, &mut warnings);
        if let Some(container) = diagnostics.container.as_ref() {
            warnings.push(format!(
                "Mesh runtime container evidence: {}",
                mesh_container_diagnostic_summary(container)
            ));
        }
        warnings.push(mesh_tunnel_protocol_evidence_from_diagnostics(diagnostics));
    }

    let mut last_failure_snapshot = read_mesh_runtime_failure_snapshot(stack_dir).unwrap_or(None);
    if !runtime_ready && diagnostic_depth == MeshDiagnosticDepth::Deep {
        let snapshot = build_mesh_runtime_failure_snapshot(diagnostics.as_ref(), &warnings);
        if let Err(err) = persist_mesh_runtime_failure_snapshot(stack_dir, &snapshot) {
            warnings.push(format!(
                "Mesh readiness failure snapshot persistence failed: {}",
                bounded_secret_safe_failure_reason(&err)
            ));
        }
        last_failure_snapshot = Some(snapshot);
    }

    MeshRuntimeState {
        token_store_present,
        container_running,
        exact_image_ready,
        runtime_ready,
        warnings,
        diagnostics,
        last_failure_snapshot,
    }
}

async fn converge_mesh_runtime(
    stack_dir: &Path,
    node_token: &str,
) -> Result<MeshRuntimeState, String> {
    validate_mesh_node_token(node_token)?;
    let images = read_exact_image_environment(stack_dir)?;
    prepare_mesh_runtime_state(stack_dir)?;
    persist_mesh_node_token(stack_dir, node_token)?;
    run_mesh_compose(
        stack_dir,
        &images,
        node_token,
        &["--profile", "mesh", "pull", "cloudflare-mesh"],
    )?;
    run_mesh_compose(
        stack_dir,
        &images,
        node_token,
        &[
            "--profile",
            "mesh",
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "cloudflare-mesh",
        ],
    )?;

    let mut last = inspect_mesh_runtime(stack_dir, MeshDiagnosticDepth::Basic).await;
    for _ in 0..45 {
        if last.runtime_ready {
            return Ok(last);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        last = inspect_mesh_runtime(stack_dir, MeshDiagnosticDepth::Basic).await;
    }
    Ok(inspect_mesh_runtime(stack_dir, MeshDiagnosticDepth::Deep).await)
}

async fn cleanup_mesh_runtime(stack_dir: &Path) -> Result<MeshRuntimeState, String> {
    let before = observe_docker()
        .await
        .map_err(|err| format!("Mesh runtime cleanup requires observable Docker state: {err}"))?;
    let mutation = if before.container_present(MESH_CONTAINER) {
        Some(
            Command::new("docker")
                .args(["rm", "-f", MESH_CONTAINER])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|err| format!("fixed Mesh container removal could not start: {err}"))?,
        )
    } else {
        None
    };

    let after = observe_docker()
        .await
        .map_err(|err| format!("Mesh runtime cleanup re-observation failed: {err}"))?;
    if after.container_present(MESH_CONTAINER) {
        return Err(format!(
            "Mesh runtime container remains present after one bounded removal attempt; exit_code={}",
            mutation.and_then(|status| status.code()).unwrap_or(-1)
        ));
    }

    let token_path = mesh_runtime_secret_path(stack_dir)?;
    if token_path.exists() {
        fs::remove_file(&token_path)
            .map_err(|err| format!("failed to remove Mesh runtime token store: {err}"))?;
    }
    let state_dir = mesh_runtime_state_dir(stack_dir)?;
    if state_dir.exists() {
        fs::remove_dir_all(&state_dir)
            .map_err(|err| format!("failed to remove Mesh runtime state: {err}"))?;
    }

    let state = inspect_mesh_runtime(stack_dir, MeshDiagnosticDepth::Basic).await;
    if state.token_store_present || state.container_running {
        return Err("Mesh runtime cleanup did not converge to absence".to_owned());
    }
    Ok(state)
}

fn require_line2_policy(runtime: &BTreeMap<String, String>) -> Result<(), String> {
    for key in ["PROXY_USERNAME", "PROXY_CERT_CN"] {
        if !runtime.contains_key(key) {
            return Err(format!(
                "Line 2 bootstrap requires runtime policy key: {key}"
            ));
        }
    }
    Ok(())
}

fn require_tunnel_policy(runtime: &BTreeMap<String, String>) -> Result<(), String> {
    for key in [
        "REALITY_SERVER_NAME",
        "TUNNEL_DOMAIN",
        "ACME_EMAIL",
        "ACME_PROVIDER",
    ] {
        if !runtime.contains_key(key) {
            return Err(format!(
                "tunnel bootstrap requires runtime policy key: {key}"
            ));
        }
    }
    let domain = runtime.get("TUNNEL_DOMAIN").unwrap();
    if !valid_certificate_domain(domain) {
        return Err("TUNNEL_DOMAIN is invalid for certificate owner state".to_owned());
    }
    validate_acme_provider(runtime.get("ACME_PROVIDER").unwrap())?;
    Ok(())
}

fn render_line1_runtime(
    stack_dir: &Path,
    runtime: &BTreeMap<String, String>,
) -> Result<(), String> {
    render_runtime_template(
        stack_dir,
        "line1-gateway/config.template.json",
        "rendered/line1-gateway.json",
        runtime,
        &[
            "VLESS_UUID",
            "HY2_PASSWORD",
            "REALITY_SERVER_NAME",
            "REALITY_PRIVATE_KEY",
            "REALITY_SHORT_ID",
            "VLESS_WARP_UUID",
            "HY2_WARP_PASSWORD",
            "REALITY_WARP_PRIVATE_KEY",
            "REALITY_WARP_SHORT_ID",
            "TUNNEL_DOMAIN",
            "ACME_EMAIL",
            "ACME_PROVIDER",
        ],
    )
}

fn render_line2_runtime(
    stack_dir: &Path,
    runtime: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut values = runtime.clone();
    let (certificate_path, key_path) = line2_certificate_container_paths(runtime)?;
    values.insert("PROXY_CERT_PATH".to_owned(), certificate_path);
    values.insert("PROXY_KEY_PATH".to_owned(), key_path);
    render_runtime_template(
        stack_dir,
        "line2-proxy/config.template.json",
        "rendered/line2-proxy.json",
        &values,
        &[
            "PROXY_USERNAME",
            "PROXY_PASSWORD",
            "PROXY_CERT_PATH",
            "PROXY_KEY_PATH",
        ],
    )
}

fn render_runtime_template(
    stack_dir: &Path,
    template_relative: &str,
    target_relative: &str,
    values: &BTreeMap<String, String>,
    required_keys: &[&str],
) -> Result<(), String> {
    let template_path = stack_dir.join(template_relative);
    let mut rendered = fs::read_to_string(&template_path).map_err(|err| {
        format!(
            "failed to read runtime template {}: {err}",
            template_path.display()
        )
    })?;
    for key in required_keys {
        let value = values
            .get(*key)
            .ok_or_else(|| format!("runtime template value is missing: {key}"))?;
        let token = format!("${{{key}}}");
        if !rendered.contains(&token) {
            return Err(format!(
                "runtime template {} is missing required placeholder {token}",
                template_path.display()
            ));
        }
        rendered = rendered.replace(&token, value);
    }
    if rendered.contains("${") {
        return Err(format!(
            "runtime template {} contains unresolved placeholders",
            template_path.display()
        ));
    }

    let target = stack_dir.join(target_relative);
    fs::write(&target, rendered.as_bytes()).map_err(|err| {
        format!(
            "failed to write rendered runtime {}: {err}",
            target.display()
        )
    })?;
    set_bundle_file_permissions(&target, false, true)
}

fn line2_certificate_container_paths(
    runtime: &BTreeMap<String, String>,
) -> Result<(String, String), String> {
    if let Some(domain) = runtime.get("TUNNEL_DOMAIN") {
        if !valid_certificate_domain(domain) {
            return Err("TUNNEL_DOMAIN is invalid for Line 2 certificate paths".to_owned());
        }
        let provider = runtime
            .get("ACME_PROVIDER")
            .ok_or_else(|| "ACME_PROVIDER is required for Line 2 certificate paths".to_owned())?;
        let directory = acme_certificate_directory(provider)?;
        let base = format!("/var/lib/sing-box/acme/certificates/{directory}/{domain}");
        return Ok((
            format!("{base}/{domain}.crt"),
            format!("{base}/{domain}.key"),
        ));
    }
    Ok(("/certs/proxy.crt".to_owned(), "/certs/proxy.key".to_owned()))
}

fn prepare_base_proxy_certificate(
    stack_dir: &Path,
    runtime: &BTreeMap<String, String>,
) -> Result<(), String> {
    if runtime.contains_key("TUNNEL_DOMAIN") {
        return Err(
            "base certificate fallback is forbidden when tunnel policy is enabled".to_owned(),
        );
    }
    let cert = stack_dir.join("certs/proxy.crt");
    let key = stack_dir.join("certs/proxy.key");
    match (cert.is_file(), key.is_file()) {
        (true, true) => {
            if certificate_is_valid(&cert, 300) {
                return Ok(());
            }
            return Err("existing base fallback certificate is invalid or expired".to_owned());
        }
        (true, false) | (false, true) => {
            return Err("base fallback certificate state is partial".to_owned());
        }
        (false, false) => {}
    }

    let common_name = runtime
        .get("PROXY_CERT_CN")
        .ok_or_else(|| "base certificate requires PROXY_CERT_CN".to_owned())?;
    let args = vec![
        "req".to_owned(),
        "-x509".to_owned(),
        "-nodes".to_owned(),
        "-newkey".to_owned(),
        "rsa:2048".to_owned(),
        "-keyout".to_owned(),
        key.display().to_string(),
        "-out".to_owned(),
        cert.display().to_string(),
        "-days".to_owned(),
        "3650".to_owned(),
        "-subj".to_owned(),
        format!("/CN={common_name}"),
    ];
    run_fixed_command(
        stack_dir,
        "openssl",
        &args,
        &BTreeMap::new(),
        "generate base certificate",
    )?;
    set_bundle_file_permissions(&key, false, true)?;
    set_bundle_file_permissions(&cert, false, false)?;
    if !certificate_is_valid(&cert, 300) || !key.is_file() {
        return Err("generated base fallback certificate failed validation".to_owned());
    }
    Ok(())
}

fn start_warp_egress(stack_dir: &Path, images: &BTreeMap<String, String>) -> Result<(), String> {
    run_compose(stack_dir, images, &["pull", "warp-egress"])?;
    run_compose(
        stack_dir,
        images,
        &["up", "-d", "--force-recreate", "warp-egress"],
    )
}

fn start_line1_gateway(stack_dir: &Path, images: &BTreeMap<String, String>) -> Result<(), String> {
    run_compose(
        stack_dir,
        images,
        &["--profile", "tunnel", "pull", "line1-gateway"],
    )?;
    run_compose(
        stack_dir,
        images,
        &[
            "--profile",
            "tunnel",
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "line1-gateway",
        ],
    )
}

fn start_line2_proxy(stack_dir: &Path, images: &BTreeMap<String, String>) -> Result<(), String> {
    run_compose(stack_dir, images, &["pull", "line2-proxy"])?;
    run_compose(
        stack_dir,
        images,
        &["up", "-d", "--force-recreate", "--no-deps", "line2-proxy"],
    )
}

fn run_compose(
    stack_dir: &Path,
    images: &BTreeMap<String, String>,
    args: &[&str],
) -> Result<(), String> {
    let mut command = Command::new("docker");
    command
        .arg("compose")
        .arg("-f")
        .arg("docker-compose.yml")
        .args(args)
        .current_dir(stack_dir)
        .env(
            EDGE_GATEWAY_IMAGE_KEY,
            images.get(EDGE_GATEWAY_IMAGE_KEY).unwrap(),
        )
        .env(
            EDGE_WARP_EGRESS_IMAGE_KEY,
            images.get(EDGE_WARP_EGRESS_IMAGE_KEY).unwrap(),
        )
        .env(
            EDGE_MESH_IMAGE_KEY,
            images.get(EDGE_MESH_IMAGE_KEY).unwrap(),
        )
        .env_remove("COMPOSE_FILE")
        .env_remove("COMPOSE_PROFILES")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = command
        .status()
        .map_err(|err| format!("fixed docker compose operation could not start: {err}"))?;
    if !status.success() {
        return Err(format!(
            "fixed docker compose operation failed with exit_code={}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn run_fixed_command(
    stack_dir: &Path,
    program: &str,
    args: &[String],
    environment: &BTreeMap<String, String>,
    operation: &str,
) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(stack_dir)
        .envs(environment)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("{operation} could not start: {err}"))?;
    if !status.success() {
        return Err(format!(
            "{operation} failed with exit_code={}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct CertificateReadinessEvidence {
    cert_present: bool,
    key_present: bool,
    key_nonempty: bool,
    cert_valid: bool,
    line1: Option<ContainerRuntimeEvidence>,
    docker_observation_error: Option<String>,
}

impl CertificateReadinessEvidence {
    fn ready(&self) -> bool {
        self.cert_present && self.key_present && self.key_nonempty && self.cert_valid
    }

    fn summary(&self) -> String {
        let line1 = self
            .line1
            .as_ref()
            .map(ContainerRuntimeEvidence::summary)
            .unwrap_or_else(|| "unavailable".to_owned());
        let docker_error = self.docker_observation_error.as_deref().unwrap_or("none");
        format!(
            "certificate={{present:{} key_present:{} key_nonempty:{} valid:{}}} line1={{ {line1} }} docker_observation_error={docker_error}",
            self.cert_present, self.key_present, self.key_nonempty, self.cert_valid
        )
    }
}

async fn observe_certificate_readiness(cert: &Path, key: &Path) -> CertificateReadinessEvidence {
    let cert_present = cert.is_file();
    let key_present = key.is_file();
    let key_nonempty = key_present && fs::metadata(key).is_ok_and(|metadata| metadata.len() > 0);
    let cert_valid = cert_present && certificate_is_valid(cert, 300);

    match observe_container_runtime(LINE1_CONTAINER).await {
        Ok(line1) => CertificateReadinessEvidence {
            cert_present,
            key_present,
            key_nonempty,
            cert_valid,
            line1: Some(line1),
            docker_observation_error: None,
        },
        Err(err) => CertificateReadinessEvidence {
            cert_present,
            key_present,
            key_nonempty,
            cert_valid,
            line1: None,
            docker_observation_error: Some(err),
        },
    }
}

async fn wait_for_owned_certificate(stack_dir: &Path) -> Result<(), String> {
    let [cert, key] = expected_proxy_certificate_paths(stack_dir)?;
    let mut consecutive_not_running = 0u8;
    let mut last = observe_certificate_readiness(&cert, &key).await;

    for _ in 0..90 {
        if last.ready() {
            return Ok(());
        }

        if let Some(line1) = last.line1.as_ref() {
            if !line1.present || !line1.running {
                consecutive_not_running = consecutive_not_running.saturating_add(1);
            } else {
                consecutive_not_running = 0;
            }
        } else {
            consecutive_not_running = 0;
        }

        if consecutive_not_running >= 3 {
            return Err(format!(
                "Line 1 certificate owner is not running after three bounded observations; {}",
                last.summary()
            ));
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
        last = observe_certificate_readiness(&cert, &key).await;
    }

    Err(format!(
        "Line 1 certificate owner did not publish a valid certificate within 180 seconds; {}",
        last.summary()
    ))
}

fn certificate_is_valid(path: &Path, minimum_validity_seconds: u64) -> bool {
    let checkend = minimum_validity_seconds.to_string();
    Command::new("openssl")
        .args(["x509", "-checkend", &checkend, "-noout", "-in"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn verify_bootstrap_post_state(
    stack_dir: &Path,
    mode: BootstrapMode,
    post_state: &AgentState,
) -> BootstrapVerification {
    let mut warnings = Vec::new();

    if !post_state.compose_file_present {
        warnings.push("compose file was not observed after bootstrap".to_owned());
    }
    if !post_state.docker_reachable {
        warnings.push("docker runtime is not reachable after bootstrap".to_owned());
    }

    let tunnel_expected = tunnel_runtime_enabled(stack_dir);
    let line2_expected = line2_runtime_enabled(stack_dir);

    let mut expected = vec!["vultr-warp-egress"];
    if matches!(
        mode,
        BootstrapMode::BootstrapBase | BootstrapMode::BootstrapFull
    ) && line2_expected
    {
        expected.push("vultr-line2-proxy");
    }
    if matches!(
        mode,
        BootstrapMode::BootstrapTunnel | BootstrapMode::BootstrapFull
    ) && tunnel_expected
    {
        expected.push("vultr-line1-gateway");
    }

    for container in expected {
        if !post_state
            .running_containers
            .iter()
            .any(|running| running == container)
        {
            warnings.push(format!(
                "expected container is not running after bootstrap: {container}"
            ));
        }
    }

    if matches!(
        mode,
        BootstrapMode::BootstrapTunnel | BootstrapMode::BootstrapFull
    ) && !tunnel_expected
    {
        warnings.push(
            "tunnel bootstrap requested but TUNNEL_DOMAIN/ACME_EMAIL are not configured".to_owned(),
        );
    }
    if matches!(
        mode,
        BootstrapMode::BootstrapBase | BootstrapMode::BootstrapFull
    ) && !line2_expected
    {
        warnings.push(
            "Line 2 bootstrap requested but PROXY_USERNAME/PROXY_CERT_CN are not configured"
                .to_owned(),
        );
    }
    if post_state.direct_egress_ready != Some(true) {
        warnings.push("direct egress datapath is not ready after bootstrap".to_owned());
    }
    if post_state.warp_egress_ready != Some(true) {
        warnings.push("WARP egress datapath is not ready after bootstrap".to_owned());
    }
    if post_state.mesh_runtime_ready == Some(false) {
        warnings.push("enabled Mesh runtime is not ready after bootstrap".to_owned());
    }

    BootstrapVerification {
        success: warnings.is_empty(),
        warnings,
    }
}

fn inspect_bundle_artifacts(stack_dir: &Path, state: &mut AgentState) {
    let runtime_env = stack_dir.join(".env.runtime");
    if !runtime_env.is_file() {
        state.degraded_reasons.push(format!(
            "bundle artifact missing: {}",
            runtime_env.display()
        ));
    }

    let rendered_dir = stack_dir.join("rendered");
    let mut expected_rendered = Vec::new();
    if line2_runtime_enabled(stack_dir) {
        expected_rendered.push("line2-proxy.json");
    }
    if tunnel_runtime_enabled(stack_dir) {
        expected_rendered.push("line1-gateway.json");
    }
    let missing_rendered = expected_rendered
        .iter()
        .filter(|name| !rendered_dir.join(name).is_file())
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if !missing_rendered.is_empty() {
        state.degraded_reasons.push(format!(
            "bundle artifact missing: rendered/{}",
            missing_rendered.join(", rendered/")
        ));
    }

    match expected_proxy_certificate_paths(stack_dir) {
        Ok(paths) => {
            let missing = paths
                .iter()
                .filter(|path| !path.is_file())
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                state.degraded_reasons.push(format!(
                    "bundle artifact missing: certificate {}",
                    missing.join(", ")
                ));
            }
        }
        Err(reason) => state
            .degraded_reasons
            .push(format!("bundle artifact invalid: {reason}")),
    }

    if let Some(summary_path) = stack_dir
        .parent()
        .map(|parent| parent.join("deployment-summary.json"))
        .filter(|path| path.is_file())
        && let Some(summary) = read_bundle_summary(&summary_path)
    {
        if let Some(label) = summary.label {
            state.active_bundle_id = Some(label);
        }
        if let Some(instance_id) = summary.instance_id {
            state.topology_version = format!("{}:{}", state.topology_version, instance_id);
        }
    }
}

fn inspect_compose(
    compose_path: &Path,
    state: &mut AgentState,
    enabled_profiles: &BTreeSet<String>,
    line2_enabled: bool,
) -> Option<ComposeObservation> {
    let raw = match fs::read_to_string(compose_path) {
        Ok(raw) => {
            state.compose_file_present = true;
            raw
        }
        Err(err) => {
            state.degraded_reasons.push(format!(
                "compose file is not readable at {}: {err}",
                compose_path.display()
            ));
            return None;
        }
    };

    let compose: ComposeFile = match serde_yaml::from_str(&raw) {
        Ok(compose) => compose,
        Err(err) => {
            state.degraded_reasons.push(format!(
                "compose file is not valid YAML at {}: {err}",
                compose_path.display()
            ));
            return None;
        }
    };

    let mut expected_containers = Vec::new();
    let mut expected_tcp_ports = BTreeSet::new();
    let mut expected_udp_ports = BTreeSet::new();

    for (service_name, service) in compose.services {
        if service_name == "line2-proxy" && !line2_enabled {
            continue;
        }
        if !service.profiles.is_empty()
            && !service
                .profiles
                .iter()
                .any(|profile| enabled_profiles.contains(profile))
        {
            continue;
        }
        if let Some(name) = service.container_name {
            expected_containers.push(name);
        }
        for port in service.ports {
            if let Some(parsed) = parse_compose_port(&port) {
                match parsed.protocol {
                    Protocol::Tcp => {
                        expected_tcp_ports.insert(parsed.host_port);
                    }
                    Protocol::Udp => {
                        expected_udp_ports.insert(parsed.host_port);
                    }
                }
            }
        }
    }

    Some(ComposeObservation {
        expected_containers,
        expected_tcp_ports: expected_tcp_ports.into_iter().collect(),
        expected_udp_ports: expected_udp_ports.into_iter().collect(),
    })
}

async fn inspect_datapath_readiness(state: &mut AgentState, docker: &DockerObservation) -> bool {
    let direct_ready = probe_direct_egress(&state.running_containers);
    state.direct_egress_ready = Some(direct_ready);
    if !direct_ready {
        state
            .degraded_reasons
            .push("direct egress datapath probe failed".to_owned());
    }

    let warp_ready = probe_warp_egress(&state.running_containers);
    state.warp_egress_ready = Some(warp_ready);
    if !warp_ready {
        state
            .degraded_reasons
            .push("WARP egress datapath probe failed".to_owned());
    }

    let mesh_ready = if docker.container_present(MESH_CONTAINER) {
        let diagnostics =
            collect_mesh_runtime_diagnostics(docker, MeshDiagnosticDepth::Basic).await;
        let ready = mesh_runtime_diagnostics_ready(&diagnostics);
        if !ready {
            append_mesh_runtime_diagnostic_warnings(&diagnostics, &mut state.degraded_reasons);
        }
        Some(ready)
    } else {
        None
    };
    state.mesh_runtime_ready = mesh_ready;

    direct_ready && warp_ready && mesh_ready != Some(false)
}

fn wait_for_warp_datapath() -> Result<(), String> {
    for _ in 0..45 {
        if probe_warp_service_local() {
            return Ok(());
        }
        sleep(Duration::from_secs(2));
    }
    Err("WARP egress datapath did not become ready within 90 seconds".to_owned())
}

fn runtime_probe_consumer(running_containers: &[String]) -> Option<&'static str> {
    if running_containers
        .iter()
        .any(|name| name == LINE2_CONTAINER)
    {
        return Some(LINE2_CONTAINER);
    }
    if running_containers
        .iter()
        .any(|name| name == LINE1_CONTAINER)
    {
        return Some(LINE1_CONTAINER);
    }
    None
}

fn probe_direct_egress(running_containers: &[String]) -> bool {
    let Some(consumer) = runtime_probe_consumer(running_containers) else {
        return false;
    };
    bounded_command_output(
        "docker",
        &[
            "exec",
            consumer,
            "curl",
            "-4",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            CLOUDFLARE_TRACE_URL,
        ],
        12,
    )
    .is_some_and(|output| cloudflare_trace_has_warp_mode(&output, "off"))
}

fn warp_client_connected() -> bool {
    bounded_command_output(
        "docker",
        &["exec", WARP_CONTAINER, "warp-cli", "--accept-tos", "status"],
        8,
    )
    .is_some_and(|output| output.lines().any(|line| line.contains("Connected")))
}

fn probe_warp_service_local() -> bool {
    if !warp_client_connected() {
        return false;
    }
    bounded_command_output(
        "docker",
        &[
            "exec",
            WARP_CONTAINER,
            "curl",
            "-4",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            "--socks5-hostname",
            "127.0.0.1:11080",
            CLOUDFLARE_TRACE_URL,
        ],
        12,
    )
    .is_some_and(|output| {
        cloudflare_trace_has_warp_mode(&output, "on")
            || cloudflare_trace_has_warp_mode(&output, "plus")
    })
}

fn probe_warp_egress(running_containers: &[String]) -> bool {
    if !warp_client_connected() {
        return false;
    }
    let Some(consumer) = runtime_probe_consumer(running_containers) else {
        return false;
    };
    bounded_command_output(
        "docker",
        &[
            "exec",
            consumer,
            "curl",
            "-4",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            "--socks5-hostname",
            "warp-egress:11080",
            CLOUDFLARE_TRACE_URL,
        ],
        12,
    )
    .is_some_and(|output| {
        cloudflare_trace_has_warp_mode(&output, "on")
            || cloudflare_trace_has_warp_mode(&output, "plus")
    })
}

fn parse_warp_connection_state(probe: &BoundedCommandProbe) -> Option<String> {
    if !matches!(
        probe.status,
        RuntimeProbeStatus::Ok | RuntimeProbeStatus::NonZero
    ) {
        return None;
    }
    let lowered = probe.stdout.to_ascii_lowercase();
    if lowered
        .lines()
        .any(|line| line.contains("disconnected") || line.contains("not connected"))
    {
        Some("DISCONNECTED".to_owned())
    } else if lowered.lines().any(|line| line.contains("connecting")) {
        Some("CONNECTING".to_owned())
    } else if lowered.lines().any(|line| line.contains("connected")) {
        Some("CONNECTED".to_owned())
    } else if probe.status == RuntimeProbeStatus::Ok {
        Some("UNKNOWN".to_owned())
    } else {
        None
    }
}

fn parse_tunnel_protocol(probe: &BoundedCommandProbe) -> Option<String> {
    if !matches!(
        probe.status,
        RuntimeProbeStatus::Ok | RuntimeProbeStatus::NonZero
    ) {
        return None;
    }
    let lowered = probe.stdout.to_ascii_lowercase();
    if lowered.contains("masque") {
        Some("MASQUE".to_owned())
    } else if lowered.contains("wireguard") {
        Some("WIREGUARD".to_owned())
    } else if probe.status == RuntimeProbeStatus::Ok {
        Some("NOT_REPORTED".to_owned())
    } else {
        None
    }
}

fn parse_binary_bool_probe(probe: &mut BoundedCommandProbe) -> Option<bool> {
    if probe.status != RuntimeProbeStatus::Ok {
        return None;
    }
    match probe.stdout.trim() {
        "1" | "present" => Some(true),
        "0" | "absent" => Some(false),
        _ => {
            probe.status = RuntimeProbeStatus::ParseError;
            None
        }
    }
}

fn mesh_warp_cli_probe_args(command: &'static str) -> [&'static str; 5] {
    ["exec", MESH_CONTAINER, "warp-cli", "--accept-tos", command]
}

async fn collect_mesh_runtime_diagnostics(
    docker: &DockerObservation,
    diagnostic_depth: MeshDiagnosticDepth,
) -> MeshRuntimeDiagnostics {
    let warp_status_args = mesh_warp_cli_probe_args("status");
    let warp_status = bounded_command_probe("docker", &warp_status_args, 8, true);
    let warp_connection_state = parse_warp_connection_state(&warp_status);

    let warp_settings_args = mesh_warp_cli_probe_args("settings");
    let warp_settings = bounded_command_probe("docker", &warp_settings_args, 8, true);
    let tunnel_protocol = parse_tunnel_protocol(&warp_settings);

    let mut tun_device = bounded_command_probe(
        "docker",
        &[
            "exec",
            MESH_CONTAINER,
            "sh",
            "-c",
            "if [ -c /dev/net/tun ]; then printf present; else printf absent; fi",
        ],
        6,
        true,
    );
    let tun_device_present = parse_binary_bool_probe(&mut tun_device);

    let mut ipv4_forwarding = bounded_command_probe(
        "docker",
        &[
            "exec",
            MESH_CONTAINER,
            "cat",
            "/proc/sys/net/ipv4/ip_forward",
        ],
        6,
        true,
    );
    let ipv4_forwarding_value = parse_binary_bool_probe(&mut ipv4_forwarding);

    let capability_probe = bounded_command_probe(
        "docker",
        &[
            "inspect",
            "--format",
            "{{json .HostConfig.CapAdd}}",
            MESH_CONTAINER,
        ],
        6,
        true,
    );
    let (net_admin_present, net_raw_present) = if capability_probe.status == RuntimeProbeStatus::Ok
    {
        let upper = capability_probe.stdout.to_ascii_uppercase();
        (
            Some(upper.contains("NET_ADMIN")),
            Some(upper.contains("NET_RAW")),
        )
    } else {
        (None, None)
    };

    let container_evidence = observe_container_runtime(MESH_CONTAINER).await.ok();
    let route_events = container_evidence
        .as_ref()
        .map(|evidence| extract_route_events(&evidence.log_tail))
        .unwrap_or_default();
    let container = container_evidence.map(|evidence| MeshContainerDiagnostics {
        present: evidence.present,
        running: evidence.running,
        exit_code: evidence.exit_code,
        runtime_error_present: evidence.runtime_error.is_some(),
        recent_events: evidence.log_tail,
        name: evidence.name,
        image: evidence.image,
        restart_count: evidence.restart_count,
        oom_killed: evidence.oom_killed,
        networks: evidence.networks,
    });

    let (host_network, container_network, host) = match diagnostic_depth {
        MeshDiagnosticDepth::Basic => (None, None, None),
        MeshDiagnosticDepth::Deep => (
            Some(collect_host_network_diagnostics()),
            Some(collect_container_network_diagnostics(MESH_CONTAINER)),
            Some(collect_host_runtime_diagnostics()),
        ),
    };

    MeshRuntimeDiagnostics {
        warp_status_probe: Some(warp_status.diagnostic_evidence()),
        warp_connection_state,
        warp_settings_probe: Some(warp_settings.diagnostic_evidence()),
        tunnel_protocol,
        tun_device_probe: Some(tun_device.evidence()),
        tun_device_present,
        ipv4_forwarding_probe: Some(ipv4_forwarding.evidence()),
        ipv4_forwarding: ipv4_forwarding_value,
        mesh_network_attached: docker.container_on_mesh_network(MESH_CONTAINER),
        container,
        capability_probe: Some(capability_probe.evidence()),
        net_admin_present,
        net_raw_present,
        host_network,
        container_network,
        route_events,
        host,
    }
}

fn mesh_runtime_diagnostics_ready(diagnostics: &MeshRuntimeDiagnostics) -> bool {
    diagnostics.warp_connection_state.as_deref() == Some("CONNECTED")
        && diagnostics.ipv4_forwarding == Some(true)
        && diagnostics.mesh_network_attached
}

fn append_mesh_runtime_diagnostic_warnings(
    diagnostics: &MeshRuntimeDiagnostics,
    warnings: &mut Vec<String>,
) {
    match diagnostics.warp_connection_state.as_deref() {
        Some("CONNECTED") => {}
        Some(state) => warnings.push(format!("Mesh runtime connection state is {state}")),
        None => warnings.push("Mesh runtime connection state unavailable".to_owned()),
    }
    if diagnostics.ipv4_forwarding != Some(true) {
        warnings.push("Mesh runtime IPv4 forwarding is not enabled".to_owned());
    }
    if !diagnostics.mesh_network_attached {
        warnings
            .push("Mesh runtime container is not attached to the expected mesh network".to_owned());
    }
    if let Some(probe) = diagnostics.warp_status_probe.as_ref()
        && probe.status != RuntimeProbeStatus::Ok as i32
    {
        warnings.push(format!(
            "Mesh runtime WARP status probe failed: {}",
            runtime_probe_failure_summary(probe)
        ));
    }
    if let Some(probe) = diagnostics.warp_settings_probe.as_ref()
        && probe.status != RuntimeProbeStatus::Ok as i32
    {
        warnings.push(format!(
            "Mesh runtime WARP settings probe failed: {}",
            runtime_probe_failure_summary(probe)
        ));
    }
    if let Some(probe) = diagnostics.ipv4_forwarding_probe.as_ref()
        && probe.status != RuntimeProbeStatus::Ok as i32
    {
        warnings.push(format!(
            "Mesh runtime IPv4 forwarding probe failed: {}",
            runtime_probe_failure_summary(probe)
        ));
    }
}

fn runtime_probe_failure_summary(probe: &RuntimeProbeEvidence) -> String {
    let mut details = Vec::new();
    if let Some(exit_code) = probe.exit_code {
        details.push(format!("exit_code={exit_code}"));
    }
    if let Some(stdout) = probe.diagnostic_stdout.as_deref() {
        details.push(format!("stdout={stdout:?}"));
    }
    if let Some(stderr) = probe.diagnostic_stderr.as_deref() {
        details.push(format!("stderr={stderr:?}"));
    }
    let status = runtime_probe_status_label(probe.status);
    if details.is_empty() {
        status.to_owned()
    } else {
        format!("{status} {}", details.join(" "))
    }
}

fn runtime_probe_status_label(value: i32) -> &'static str {
    match RuntimeProbeStatus::try_from(value).unwrap_or(RuntimeProbeStatus::Unspecified) {
        RuntimeProbeStatus::Unspecified => "UNSPECIFIED",
        RuntimeProbeStatus::Ok => "OK",
        RuntimeProbeStatus::Timeout => "TIMEOUT",
        RuntimeProbeStatus::CommandNotFound => "COMMAND_NOT_FOUND",
        RuntimeProbeStatus::PermissionDenied => "PERMISSION_DENIED",
        RuntimeProbeStatus::Unsupported => "UNSUPPORTED",
        RuntimeProbeStatus::NonZero => "NON_ZERO",
        RuntimeProbeStatus::Empty => "EMPTY",
        RuntimeProbeStatus::ParseError => "PARSE_ERROR",
        RuntimeProbeStatus::OutputLimit => "OUTPUT_LIMIT",
    }
}

fn mesh_tunnel_protocol_evidence_from_diagnostics(diagnostics: &MeshRuntimeDiagnostics) -> String {
    match diagnostics.tunnel_protocol.as_deref() {
        Some(protocol) => format!("Mesh runtime tunnel protocol evidence: {protocol}"),
        None => format!(
            "Mesh runtime tunnel protocol evidence unavailable: settings_probe={}",
            diagnostics
                .warp_settings_probe
                .as_ref()
                .map(|probe| runtime_probe_status_label(probe.status))
                .unwrap_or("UNSPECIFIED")
        ),
    }
}

fn mesh_container_diagnostic_summary(evidence: &MeshContainerDiagnostics) -> String {
    let exit_code = evidence
        .exit_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let start = evidence.recent_events.len().saturating_sub(8);
    let logs = if evidence.recent_events.is_empty() {
        "none".to_owned()
    } else {
        evidence.recent_events[start..].join(" | ")
    };
    format!(
        "name={} present={} running={} exit_code={} restart_count={} oom_killed={} image={} networks={:?} runtime_error_present={} log_tail={}",
        evidence.name,
        evidence.present,
        evidence.running,
        exit_code,
        evidence
            .restart_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        evidence
            .oom_killed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        evidence.image.as_deref().unwrap_or("unknown"),
        evidence.networks,
        evidence.runtime_error_present,
        logs
    )
}

fn bounded_container_runtime_summary(evidence: &ContainerRuntimeEvidence) -> String {
    let exit_code = evidence
        .exit_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let runtime_error = evidence.runtime_error.as_deref().unwrap_or("none");
    let start = evidence.log_tail.len().saturating_sub(8);
    let logs = if evidence.log_tail.is_empty() {
        "none".to_owned()
    } else {
        evidence.log_tail[start..].join(" | ")
    };
    format!(
        "present={} running={} exit_code={} runtime_error={} log_tail={}",
        evidence.present, evidence.running, exit_code, runtime_error, logs
    )
}

fn bounded_command_output(program: &str, args: &[&str], timeout_seconds: u64) -> Option<String> {
    let timeout = format!("{timeout_seconds}s");
    let output = Command::new("timeout")
        .arg(timeout)
        .arg(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 16 * 1024 {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn cloudflare_trace_has_warp_mode(raw: &str, expected: &str) -> bool {
    let mut warp = None;
    let mut ip_present = false;
    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "warp" if warp.is_none() => warp = Some(value),
            "warp" => return false,
            "ip" if !value.trim().is_empty() => ip_present = true,
            _ => {}
        }
    }
    ip_present && warp == Some(expected)
}

fn parse_compose_port(value: &str) -> Option<PortMapping> {
    let protocol = if value.ends_with("/udp") {
        Protocol::Udp
    } else {
        Protocol::Tcp
    };
    let base = value.split('/').next()?;
    let host_port = base.split(':').next()?.parse().ok()?;
    Some(PortMapping {
        host_port,
        protocol,
    })
}

fn join_ports(ports: &[u32]) -> String {
    ports
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn write_bundle_file(
    root: &Path,
    file: &BundleFile,
    written_paths: &mut Vec<String>,
) -> Result<(), String> {
    validate_bundle_relative_path(&file.relative_path)?;
    let sensitive = file.sensitive || intrinsically_sensitive_bundle_path(&file.relative_path);
    if file.executable && sensitive {
        return Err(format!(
            "bundle file {} cannot be both executable and sensitive",
            file.relative_path
        ));
    }

    let path = root.join(&file.relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(&path, &file.content)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    set_bundle_file_permissions(&path, file.executable, sensitive)?;
    written_paths.push(path.display().to_string());
    Ok(())
}

fn intrinsically_sensitive_bundle_path(value: &str) -> bool {
    value == ".env.runtime"
        || value == "deployment-summary.json"
        || value.ends_with(".key")
        || value.starts_with("tunnel-state/acme/")
}

fn validate_bundle_relative_path(value: &str) -> Result<(), String> {
    if value.is_empty() || value.contains('\\') {
        return Err(format!(
            "bundle path must be a normalized relative path without traversal: {value}"
        ));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "bundle path must be a normalized relative path without traversal: {value}"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_bundle_file_permissions(
    path: &Path,
    executable: bool,
    sensitive: bool,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if sensitive {
        0o600
    } else if executable {
        0o755
    } else {
        0o644
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("failed to set {} mode {mode:o}: {err}", path.display()))
}

#[cfg(not(unix))]
fn set_bundle_file_permissions(
    _path: &Path,
    _executable: bool,
    _sensitive: bool,
) -> Result<(), String> {
    Ok(())
}

fn collect_rendered_artifacts(stack_dir: &Path) -> Vec<FilePresence> {
    let mut required = vec![
        (
            stack_dir.join("docker-compose.yml"),
            FileCategory::RequiredRepoInput,
        ),
        (
            stack_dir.join(RUNTIME_POLICY_FILE),
            FileCategory::RequiredRepoInput,
        ),
        (
            stack_dir.join(RUNTIME_ENV_FILE),
            FileCategory::LocalOnlySensitive,
        ),
    ];
    if line2_runtime_enabled(stack_dir) {
        required.push((
            stack_dir.join("rendered/line2-proxy.json"),
            FileCategory::LocalOnlySensitive,
        ));
    }
    if tunnel_runtime_enabled(stack_dir) {
        required.push((
            stack_dir.join("rendered/line1-gateway.json"),
            FileCategory::LocalOnlySensitive,
        ));
    }
    if let Ok(paths) = expected_proxy_certificate_paths(stack_dir) {
        required.extend(
            paths
                .into_iter()
                .map(|path| (path, FileCategory::LocalOnlySensitive)),
        );
    }

    required
        .into_iter()
        .map(|(path, category)| FilePresence {
            path: rendered_artifact_display_path(stack_dir, &path),
            present: path.is_file(),
            category: category as i32,
        })
        .collect()
}

fn rendered_artifact_display_path(stack_dir: &Path, path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(stack_dir) {
        return relative.to_string_lossy().replace('\\', "/");
    }
    if let Some(parent) = stack_dir.parent()
        && let Ok(relative) = path.strip_prefix(parent)
    {
        return format!("../{}", relative.to_string_lossy().replace('\\', "/"));
    }
    path.display().to_string()
}

fn read_runtime_env(path: &Path) -> Option<std::collections::BTreeMap<String, String>> {
    let raw = fs::read_to_string(path).ok()?;
    let mut values = std::collections::BTreeMap::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            values.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }

    Some(values)
}

fn env_flag_present(values: &std::collections::BTreeMap<String, String>, key: &str) -> bool {
    values
        .get(key)
        .is_some_and(|value| !value.trim().is_empty())
}

fn line2_runtime_enabled(stack_dir: &Path) -> bool {
    read_runtime_env(&stack_dir.join(".env.runtime")).is_some_and(|values| {
        env_flag_present(&values, "PROXY_USERNAME") && env_flag_present(&values, "PROXY_CERT_CN")
    })
}

fn tunnel_runtime_enabled(stack_dir: &Path) -> bool {
    read_runtime_env(&stack_dir.join(".env.runtime")).is_some_and(|values| {
        env_flag_present(&values, "TUNNEL_DOMAIN") && env_flag_present(&values, "ACME_EMAIL")
    })
}

fn validate_acme_provider(value: &str) -> Result<(), String> {
    acme_certificate_directory(value).map(|_| ())
}

fn acme_certificate_directory(value: &str) -> Result<&'static str, String> {
    match value {
        "letsencrypt" => Ok("acme-v02.api.letsencrypt.org-directory"),
        "https://acme-staging-v02.api.letsencrypt.org/directory" => {
            Ok("acme-staging-v02.api.letsencrypt.org-directory")
        }
        _ => Err(
            "ACME_PROVIDER must be letsencrypt or the exact Let’s Encrypt staging directory"
                .to_owned(),
        ),
    }
}

fn valid_certificate_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn expected_proxy_certificate_paths(stack_dir: &Path) -> Result<[PathBuf; 2], String> {
    let runtime = read_runtime_env(&stack_dir.join(".env.runtime")).ok_or_else(|| {
        "runtime environment is unavailable for certificate observation".to_owned()
    })?;
    if env_flag_present(&runtime, "TUNNEL_DOMAIN") {
        let domain = runtime
            .get("TUNNEL_DOMAIN")
            .map(String::as_str)
            .unwrap_or_default();
        if !valid_certificate_domain(domain) {
            return Err("TUNNEL_DOMAIN is invalid for certificate owner state".to_owned());
        }
        let provider = runtime
            .get("ACME_PROVIDER")
            .ok_or_else(|| "ACME_PROVIDER is required for certificate owner state".to_owned())?;
        let directory = acme_certificate_directory(provider)?;
        let owner = stack_dir
            .parent()
            .ok_or_else(|| "application stack path has no certificate-state parent".to_owned())?
            .join("certificate-state")
            .join("acme")
            .join("certificates")
            .join(directory)
            .join(domain);
        return Ok([
            owner.join(format!("{domain}.crt")),
            owner.join(format!("{domain}.key")),
        ]);
    }

    let certs = stack_dir.join("certs");
    Ok([certs.join("proxy.crt"), certs.join("proxy.key")])
}

fn enabled_application_profiles(stack_dir: &Path) -> BTreeSet<String> {
    let mut profiles = BTreeSet::new();
    if tunnel_runtime_enabled(stack_dir) {
        profiles.insert("tunnel".to_owned());
    }
    profiles
}

fn read_bundle_summary(path: &Path) -> Option<BundleSummary> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

#[derive(Debug)]
struct BootstrapVerification {
    success: bool,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct ComposeObservation {
    expected_containers: Vec<String>,
    expected_tcp_ports: Vec<u32>,
    expected_udp_ports: Vec<u32>,
}

#[derive(Debug)]
struct PortMapping {
    host_port: u32,
    protocol: Protocol,
}

#[derive(Debug)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Deserialize)]
struct ComposeFile {
    services: std::collections::BTreeMap<String, ComposeService>,
}

#[derive(Debug, Deserialize)]
struct ComposeService {
    container_name: Option<String>,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BundleSummary {
    label: Option<String>,
    instance_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::agent_service_server::AgentService;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn returns_health_state() {
        let server = AgentServerImpl {
            stack_dir: unique_test_dir(),
        };
        let response = server.get_health(Request::new(Empty {})).await.unwrap();
        assert!(response.get_ref().observed_stack_path.is_some());
    }

    #[test]
    fn applies_bundle_files_to_stack_and_host_roots() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();

        let response = apply_bundle(
            &stack,
            ApplyBundleRequest {
                stack_files: vec![BundleFile {
                    relative_path: "docker-compose.yml".to_owned(),
                    content: b"services: {}\n".to_vec(),
                    executable: false,
                    sensitive: false,
                }],
                host_files: vec![BundleFile {
                    relative_path: "tls/ca.pem".to_owned(),
                    content: b"ca".to_vec(),
                    executable: false,
                    sensitive: false,
                }],
                deployment_summary: Some(BundleFile {
                    relative_path: "deployment-summary.json".to_owned(),
                    content: br#"{"label":"bundle-a","instance_id":"instance-1"}"#.to_vec(),
                    executable: false,
                    sensitive: false,
                }),
                agent_env_file: Some(BundleFile {
                    relative_path: "edge-agent.env".to_owned(),
                    content: b"EDGE_AGENT_TLS_CA_CERT_PATH=/opt/vultr-edge-stack/tls/ca.pem\n"
                        .to_vec(),
                    executable: false,
                    sensitive: false,
                }),
                prune_existing: true,
                bundle_id: None,
                bundle_digest: None,
            },
        )
        .unwrap();

        assert!(response.success);
        assert!(stack.join("docker-compose.yml").is_file());
        assert!(root.join("tls/ca.pem").is_file());
        assert!(root.join("deployment-summary.json").is_file());
        assert!(root.join("edge-agent.env").is_file());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn digest_bound_bundle_is_idempotent_and_rollback_swaps_exact_release() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();

        let make_request = |bundle_id: &str, body: &[u8]| {
            let mut request = ApplyBundleRequest {
                stack_files: vec![BundleFile {
                    relative_path: "docker-compose.yml".to_owned(),
                    content: body.to_vec(),
                    executable: false,
                    sensitive: false,
                }],
                host_files: Vec::new(),
                deployment_summary: None,
                agent_env_file: None,
                prune_existing: true,
                bundle_id: Some(bundle_id.to_owned()),
                bundle_digest: None,
            };
            let digest = canonical_apply_bundle_digest(&request).unwrap();
            request.bundle_digest = Some(digest.clone());
            (request, digest)
        };

        let (first, first_digest) = make_request("release-a", b"services: {a: {}}\n");
        let first_response = apply_bundle(&stack, first.clone()).unwrap();
        assert_eq!(
            first_response.active_bundle_digest.as_deref(),
            Some(first_digest.as_str())
        );

        let noop_response = apply_bundle(&stack, first).unwrap();
        assert!(noop_response.written_paths.is_empty());

        let (second, second_digest) = make_request("release-b", b"services: {b: {}}\n");
        let second_response = apply_bundle(&stack, second).unwrap();
        assert_eq!(
            second_response.previous_bundle_digest.as_deref(),
            Some(first_digest.as_str())
        );

        let rolled_back = rollback_bundle(
            &stack,
            RollbackBundleRequest {
                expected_current_bundle_digest: second_digest.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            rolled_back.active_bundle_digest.as_deref(),
            Some(first_digest.as_str())
        );
        assert_eq!(
            rolled_back.previous_bundle_digest.as_deref(),
            Some(second_digest.as_str())
        );
        assert_eq!(
            fs::read_to_string(stack.join("docker-compose.yml")).unwrap(),
            "services: {a: {}}\n"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mesh_warp_cli_probes_accept_tos_non_interactively() {
        assert_eq!(
            mesh_warp_cli_probe_args("status"),
            ["exec", MESH_CONTAINER, "warp-cli", "--accept-tos", "status"]
        );
        assert_eq!(
            mesh_warp_cli_probe_args("settings"),
            [
                "exec",
                MESH_CONTAINER,
                "warp-cli",
                "--accept-tos",
                "settings",
            ]
        );
    }

    #[test]
    fn typed_mesh_probe_does_not_confuse_disconnected_with_connected() {
        let disconnected = BoundedCommandProbe {
            status: RuntimeProbeStatus::Ok,
            exit_code: Some(0),
            stdout: "Status update: Disconnected\n".to_owned(),
            stderr: String::new(),
        };
        assert_eq!(
            parse_warp_connection_state(&disconnected).as_deref(),
            Some("DISCONNECTED")
        );

        let connected = BoundedCommandProbe {
            status: RuntimeProbeStatus::Ok,
            exit_code: Some(0),
            stdout: "Status update: Connected\n".to_owned(),
            stderr: String::new(),
        };
        assert_eq!(
            parse_warp_connection_state(&connected).as_deref(),
            Some("CONNECTED")
        );
    }

    #[test]
    fn failed_warp_observation_is_not_explicit_disconnection() {
        let failed = BoundedCommandProbe {
            status: RuntimeProbeStatus::NonZero,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "daemon IPC unavailable".to_owned(),
        };
        assert_eq!(parse_warp_connection_state(&failed), None);

        let explicit = BoundedCommandProbe {
            status: RuntimeProbeStatus::NonZero,
            exit_code: Some(1),
            stdout: "Status update: Disconnected\n".to_owned(),
            stderr: "non-zero CLI status".to_owned(),
        };
        assert_eq!(
            parse_warp_connection_state(&explicit).as_deref(),
            Some("DISCONNECTED")
        );
    }

    #[test]
    fn non_zero_warp_probe_can_preserve_explicit_connected_state() {
        let connected = BoundedCommandProbe {
            status: RuntimeProbeStatus::NonZero,
            exit_code: Some(1),
            stdout: "Status update: Connected\n".to_owned(),
            stderr: "non-zero CLI status".to_owned(),
        };
        assert_eq!(
            parse_warp_connection_state(&connected).as_deref(),
            Some("CONNECTED")
        );
    }

    #[test]
    fn typed_mesh_probe_normalizes_known_tunnel_protocols() {
        let masque = BoundedCommandProbe {
            status: RuntimeProbeStatus::Ok,
            exit_code: Some(0),
            stdout: "tunnel protocol: MASQUE\n".to_owned(),
            stderr: String::new(),
        };
        assert_eq!(parse_tunnel_protocol(&masque).as_deref(), Some("MASQUE"));

        let wireguard = BoundedCommandProbe {
            status: RuntimeProbeStatus::Ok,
            exit_code: Some(0),
            stdout: "protocol = WireGuard\n".to_owned(),
            stderr: String::new(),
        };
        assert_eq!(
            parse_tunnel_protocol(&wireguard).as_deref(),
            Some("WIREGUARD")
        );
    }

    #[test]
    fn mesh_failure_snapshot_is_bounded_secret_safe_and_persistent() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();

        let mut diagnostics = MeshRuntimeDiagnostics::default();
        diagnostics.warp_connection_state = Some("DISCONNECTED".to_owned());
        diagnostics.tunnel_protocol = Some("MASQUE".to_owned());
        diagnostics.warp_status_probe = Some(RuntimeProbeEvidence {
            status: RuntimeProbeStatus::NonZero as i32,
            exit_code: Some(1),
            diagnostic_stdout: None,
            diagnostic_stderr: None,
        });
        diagnostics.container = Some(MeshContainerDiagnostics {
            present: true,
            running: false,
            exit_code: Some(137),
            runtime_error_present: true,
            recent_events: Vec::new(),
            name: MESH_CONTAINER.to_owned(),
            image: Some("docker.io/cloudflare/mesh@sha256:test".to_owned()),
            restart_count: Some(3),
            oom_killed: Some(true),
            networks: vec!["mesh_net".to_owned()],
        });

        let reasons = vec![
            "Authorization: Bearer should-not-escape".to_owned(),
            "x".repeat(MAX_MESH_FAILURE_REASON_CHARS * 2),
        ];
        let snapshot = build_mesh_runtime_failure_snapshot(Some(&diagnostics), &reasons);
        assert_eq!(snapshot.reasons[0], "[REDACTED_SENSITIVE_REASON]");
        assert_eq!(
            snapshot.reasons[1].chars().count(),
            MAX_MESH_FAILURE_REASON_CHARS
        );
        assert_eq!(snapshot.container_restart_count, Some(3));
        assert_eq!(snapshot.container_oom_killed, Some(true));

        persist_mesh_runtime_failure_snapshot(&stack, &snapshot).unwrap();
        let restored = read_mesh_runtime_failure_snapshot(&stack).unwrap().unwrap();
        assert_eq!(restored.reasons, snapshot.reasons);
        assert_eq!(
            restored.warp_connection_state.as_deref(),
            Some("DISCONNECTED")
        );
        assert_eq!(restored.container_exit_code, Some(137));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn certificate_readiness_requires_complete_valid_material() {
        let mut evidence = CertificateReadinessEvidence {
            cert_present: true,
            key_present: true,
            key_nonempty: true,
            cert_valid: false,
            line1: Some(ContainerRuntimeEvidence {
                present: true,
                running: true,
                exit_code: None,
                runtime_error: None,
                log_tail: Vec::new(),
                name: LINE1_CONTAINER.to_owned(),
                image: None,
                restart_count: Some(0),
                oom_killed: Some(false),
                networks: Vec::new(),
            }),
            docker_observation_error: None,
        };
        assert!(!evidence.ready());

        evidence.cert_valid = true;
        assert!(evidence.ready());
        assert!(evidence.summary().contains("running=true"));
    }

    #[test]
    fn runtime_policy_rejects_incomplete_or_shell_unsafe_values() {
        assert!(validate_runtime_policy_env("PROXY_USERNAME=acceptance\n").is_err());
        assert!(
            validate_runtime_policy_env(
                "PROXY_USERNAME=$(touch/tmp/pwn)\nPROXY_CERT_CN=acceptance.local\n"
            )
            .is_err()
        );
        assert!(
            validate_runtime_policy_env(
                "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n"
            )
            .is_ok()
        );
        assert!(
            validate_runtime_policy_env(
                "REALITY_SERVER_NAME=reality.example.com\nTUNNEL_DOMAIN=tunnel.example.com\nACME_EMAIL=edge@example.com\n"
            )
            .is_err()
        );
        assert!(
            validate_runtime_policy_env(
                "REALITY_SERVER_NAME=reality.example.com\nTUNNEL_DOMAIN=tunnel.example.com\nACME_EMAIL=edge@example.com\nACME_PROVIDER=letsencrypt\n"
            )
            .is_ok()
        );
        assert!(
            validate_runtime_policy_env(
                "REALITY_SERVER_NAME=reality.example.com\nTUNNEL_DOMAIN=tunnel.example.com\nACME_EMAIL=edge@example.com\nACME_PROVIDER=https://acme-staging-v02.api.letsencrypt.org/directory\nPROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n"
            )
            .is_ok()
        );
        assert!(
            validate_runtime_policy_env(
                "REALITY_SERVER_NAME=reality.example.com\nTUNNEL_DOMAIN=tunnel.example.com\nACME_EMAIL=edge@example.com\nACME_PROVIDER=letsencrypt\nUNKNOWN_POLICY=value\n"
            )
            .is_err()
        );
    }

    #[test]
    fn vm_runtime_secret_store_is_generated_once_and_reused() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(
            stack.join(RUNTIME_POLICY_FILE),
            "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
        )
        .unwrap();

        materialize_vm_owned_runtime_environment(&stack).unwrap();
        let first = fs::read_to_string(stack.join(RUNTIME_ENV_FILE)).unwrap();
        let secret_dir = root.join(RUNTIME_SECRET_DIR);
        let secret_path = secret_dir.join(RUNTIME_SECRET_FILE);
        let store = fs::read_to_string(&secret_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&secret_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&secret_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        fs::remove_file(stack.join(RUNTIME_ENV_FILE)).unwrap();
        materialize_vm_owned_runtime_environment(&stack).unwrap();
        let second = fs::read_to_string(stack.join(RUNTIME_ENV_FILE)).unwrap();

        assert_eq!(first, second);
        assert!(first.contains("PROXY_USERNAME=acceptance\n"));
        assert!(first.contains("PROXY_PASSWORD="));
        assert_eq!(
            ApplicationRuntimeSecrets::parse_env(&store)
                .unwrap()
                .render_env(),
            store
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn certificate_observation_uses_owner_state_for_tunnel_runtime() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        let owner = root
            .join("certificate-state/acme/certificates/acme-v02.api.letsencrypt.org-directory")
            .join("edge.example.com");
        fs::create_dir_all(stack.join("rendered")).unwrap();
        fs::create_dir_all(&owner).unwrap();
        fs::write(
            stack.join(RUNTIME_ENV_FILE),
            "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=letsencrypt\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/line2-proxy.json"), "{}\n").unwrap();
        fs::write(stack.join("rendered/line1-gateway.json"), "{}\n").unwrap();
        fs::write(owner.join("edge.example.com.crt"), "certificate").unwrap();
        fs::write(owner.join("edge.example.com.key"), "private-key").unwrap();

        let mut state = AgentState::bootstrap_placeholder();
        state.degraded_reasons.clear();
        inspect_bundle_artifacts(&stack, &mut state);

        assert!(state.degraded_reasons.is_empty());
        assert!(!stack.join("certs/proxy.crt").exists());
        assert!(!stack.join("certs/proxy.key").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn certificate_observation_uses_staging_provider_directory() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        let owner = root
            .join(
                "certificate-state/acme/certificates/acme-staging-v02.api.letsencrypt.org-directory",
            )
            .join("edge.example.com");
        fs::create_dir_all(stack.join("rendered")).unwrap();
        fs::create_dir_all(&owner).unwrap();
        fs::write(
            stack.join(RUNTIME_ENV_FILE),
            "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=https://acme-staging-v02.api.letsencrypt.org/directory\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/line2-proxy.json"), "{}\n").unwrap();
        fs::write(stack.join("rendered/line1-gateway.json"), "{}\n").unwrap();
        fs::write(owner.join("edge.example.com.crt"), "certificate").unwrap();
        fs::write(owner.join("edge.example.com.key"), "private-key").unwrap();

        let paths = expected_proxy_certificate_paths(&stack).unwrap();
        assert_eq!(paths[0], owner.join("edge.example.com.crt"));
        assert_eq!(paths[1], owner.join("edge.example.com.key"));

        let mut state = AgentState::bootstrap_placeholder();
        state.degraded_reasons.clear();
        inspect_bundle_artifacts(&stack, &mut state);
        assert!(state.degraded_reasons.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn certificate_observation_rejects_unsafe_tunnel_domain() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(stack.join("rendered")).unwrap();
        fs::write(
            stack.join(RUNTIME_ENV_FILE),
            "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=../escape\nACME_EMAIL=ops@example.com\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/line2-proxy.json"), "{}\n").unwrap();
        fs::write(stack.join("rendered/line1-gateway.json"), "{}\n").unwrap();

        let mut state = AgentState::bootstrap_placeholder();
        state.degraded_reasons.clear();
        inspect_bundle_artifacts(&stack, &mut state);

        assert!(
            state
                .degraded_reasons
                .iter()
                .any(|reason| reason.contains("TUNNEL_DOMAIN is invalid"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tunnel_only_policy_does_not_require_line2_artifacts() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(stack.join("rendered")).unwrap();
        fs::write(
            stack.join(RUNTIME_ENV_FILE),
            "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=letsencrypt\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/line1-gateway.json"), "{}\n").unwrap();

        assert!(tunnel_runtime_enabled(&stack));
        assert!(!line2_runtime_enabled(&stack));

        let mut state = AgentState::bootstrap_placeholder();
        state.degraded_reasons.clear();
        inspect_bundle_artifacts(&stack, &mut state);

        assert!(
            !state
                .degraded_reasons
                .iter()
                .any(|reason| reason.contains("line2-proxy.json"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_bundle_path_traversal() {
        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        let mut written = Vec::new();

        for path in [
            "../escape",
            "/tmp/escape",
            "nested/../escape",
            r"nested\escape",
        ] {
            let error = write_bundle_file(
                &root,
                &BundleFile {
                    relative_path: path.to_owned(),
                    content: b"secret".to_vec(),
                    executable: false,
                    sensitive: true,
                },
                &mut written,
            )
            .unwrap_err();
            assert!(error.contains("normalized relative path"));
        }
        assert!(written.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn known_secret_paths_are_private_even_without_sensitive_flag() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        let mut written = Vec::new();
        write_bundle_file(
            &root,
            &BundleFile {
                relative_path: ".env.runtime".to_owned(),
                content: b"MESH_NODE_TOKEN=secret\n".to_vec(),
                executable: false,
                sensitive: false,
            },
            &mut written,
        )
        .unwrap();
        let mode = fs::metadata(root.join(".env.runtime"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_executable_sensitive_bundle_files() {
        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        let mut written = Vec::new();
        let error = write_bundle_file(
            &root,
            &BundleFile {
                relative_path: "secret.sh".to_owned(),
                content: b"#!/bin/sh\n".to_vec(),
                executable: true,
                sensitive: true,
            },
            &mut written,
        )
        .unwrap_err();
        assert!(error.contains("both executable and sensitive"));
        assert!(!root.join("secret.sh").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn applies_explicit_bundle_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        let mut written = Vec::new();
        for (name, executable, sensitive, expected) in [
            ("regular.txt", false, false, 0o644),
            ("fixed-tool", true, false, 0o755),
            (".env.runtime", false, true, 0o600),
        ] {
            write_bundle_file(
                &root,
                &BundleFile {
                    relative_path: name.to_owned(),
                    content: b"x".to_vec(),
                    executable,
                    sensitive,
                },
                &mut written,
            )
            .unwrap();
            let mode = fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, expected, "{name}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_rendered_artifacts_for_base_capability() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(stack.join("rendered")).unwrap();
        fs::create_dir_all(stack.join("certs")).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
        fs::write(
            stack.join(RUNTIME_POLICY_FILE),
            "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
        )
        .unwrap();
        fs::write(
            stack.join(RUNTIME_ENV_FILE),
            "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/line2-proxy.json"), "{}").unwrap();
        fs::write(stack.join("certs/proxy.crt"), "crt").unwrap();
        fs::write(stack.join("certs/proxy.key"), "key").unwrap();

        let artifacts = collect_rendered_artifacts(&stack);
        assert!(artifacts.iter().all(|entry| entry.present));
        assert!(
            artifacts
                .iter()
                .any(|entry| entry.path == "rendered/line2-proxy.json")
        );
        assert!(
            artifacts
                .iter()
                .all(|entry| !entry.path.contains("line1-gateway"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_host_certificate_state_for_tunnel_capability() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        let owner = root
            .join("certificate-state/acme/certificates/acme-v02.api.letsencrypt.org-directory")
            .join("edge.example.com");
        fs::create_dir_all(stack.join("rendered")).unwrap();
        fs::create_dir_all(&owner).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
        fs::write(
            stack.join(RUNTIME_POLICY_FILE),
            "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=letsencrypt\n",
        )
        .unwrap();
        fs::write(
            stack.join(RUNTIME_ENV_FILE),
            "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=letsencrypt\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/line1-gateway.json"), "{}").unwrap();
        fs::write(owner.join("edge.example.com.crt"), "crt").unwrap();
        fs::write(owner.join("edge.example.com.key"), "key").unwrap();

        let artifacts = collect_rendered_artifacts(&stack);
        assert!(artifacts.iter().all(|entry| entry.present));
        assert!(
            artifacts
                .iter()
                .any(|entry| entry.path == "rendered/line1-gateway.json")
        );
        assert!(
            artifacts
                .iter()
                .any(|entry| entry.path.starts_with("../certificate-state/"))
        );
        assert!(
            artifacts
                .iter()
                .all(|entry| !entry.path.contains("line2-proxy"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_compose_ports() {
        let tcp = parse_compose_port("3128:3128/tcp").unwrap();
        assert!(matches!(tcp.protocol, Protocol::Tcp));
        assert_eq!(tcp.host_port, 3128);

        let udp = parse_compose_port("8443:8443/udp").unwrap();
        assert!(matches!(udp.protocol, Protocol::Udp));
        assert_eq!(udp.host_port, 8443);
    }

    #[test]
    fn inspects_compose_expectations() {
        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("docker-compose.yml"),
            r#"services:
  line2-proxy:
    container_name: vultr-line2-proxy
    ports:
      - "3128:3128/tcp"
  line1-gateway:
    container_name: vultr-line1-gateway
    ports:
      - "8443:8443/udp"
"#,
        )
        .unwrap();

        let mut state = AgentState::bootstrap_placeholder();
        let observation = inspect_compose(
            &root.join("docker-compose.yml"),
            &mut state,
            &BTreeSet::new(),
            true,
        )
        .unwrap();
        assert!(state.compose_file_present);
        assert_eq!(observation.expected_containers.len(), 2);
        assert_eq!(observation.expected_tcp_ports, vec![3128]);
        assert_eq!(observation.expected_udp_ports, vec![8443]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compose_observation_honors_enabled_application_profiles() {
        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("docker-compose.yml"),
            r#"services:
  line2-proxy:
    container_name: vultr-line2-proxy
    ports:
      - "3128:3128/tcp"
  line1-gateway:
    profiles: [tunnel]
    container_name: vultr-line1-gateway
    ports:
      - "8443:8443/udp"
  cloudflare-mesh:
    profiles: [mesh]
    container_name: vultr-cloudflare-mesh
"#,
        )
        .unwrap();

        let mut state = AgentState::bootstrap_placeholder();
        let enabled_profiles = BTreeSet::from(["tunnel".to_owned()]);
        let observation = inspect_compose(
            &root.join("docker-compose.yml"),
            &mut state,
            &enabled_profiles,
            true,
        )
        .unwrap();
        assert_eq!(
            observation.expected_containers,
            vec!["vultr-line1-gateway", "vultr-line2-proxy"]
        );
        assert_eq!(observation.expected_tcp_ports, vec![3128]);
        assert_eq!(observation.expected_udp_ports, vec![8443]);

        let tunnel_only = inspect_compose(
            &root.join("docker-compose.yml"),
            &mut AgentState::bootstrap_placeholder(),
            &enabled_profiles,
            false,
        )
        .unwrap();
        assert_eq!(tunnel_only.expected_containers, vec!["vultr-line1-gateway"]);
        assert!(tunnel_only.expected_tcp_ports.is_empty());
        assert_eq!(tunnel_only.expected_udp_ports, vec![8443]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reads_bundle_summary_and_artifacts() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(stack.join("rendered")).unwrap();
        let owner = root
            .join("certificate-state/acme/certificates/acme-v02.api.letsencrypt.org-directory")
            .join("edge.example.com");
        fs::create_dir_all(&owner).unwrap();
        fs::write(
            stack.join(".env.runtime"),
            "TUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=admin@example.com\nACME_PROVIDER=letsencrypt\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/line1-gateway.json"), "{}").unwrap();
        fs::write(owner.join("edge.example.com.crt"), "crt").unwrap();
        fs::write(owner.join("edge.example.com.key"), "key").unwrap();
        fs::write(
            root.join("deployment-summary.json"),
            r#"{"label":"bundle-a","instance_id":"instance-1"}"#,
        )
        .unwrap();

        let mut state = AgentState::bootstrap_placeholder();
        inspect_bundle_artifacts(&stack, &mut state);
        assert_eq!(state.active_bundle_id.as_deref(), Some("bundle-a"));
        assert!(state.topology_version.contains("instance-1"));
        assert!(
            !state
                .degraded_reasons
                .iter()
                .any(|reason| reason.contains("bundle artifact"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mesh_token_validation_is_closed_and_secret_safe() {
        assert!(validate_mesh_node_token("opaque-token-value").is_ok());
        assert!(validate_mesh_node_token("").is_err());
        assert!(validate_mesh_node_token(" token").is_err());
        assert!(validate_mesh_node_token("token\ninjected").is_err());
        assert!(validate_mesh_node_token("token\rinjected").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn mesh_token_store_is_host_level_private_and_not_release_local() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        persist_mesh_node_token(&stack, "opaque-token-value").unwrap();

        let path = root.join("runtime-secrets/mesh-node-v1.env");
        assert!(path.is_file());
        assert!(!stack.join("runtime-secrets/mesh-node-v1.env").exists());
        assert_eq!(read_mesh_node_token(&stack).unwrap(), "opaque-token-value");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn warp_state_is_host_level_across_release_swap_names() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        let previous = root.join("stack.previous");
        assert_eq!(
            warp_runtime_state_dir(&stack).unwrap(),
            root.join("warp-state")
        );
        assert_eq!(
            warp_runtime_state_dir(&previous).unwrap(),
            root.join("warp-state")
        );

        let compose = include_str!("../../../../win/vultr-waw/stack/docker-compose.yml");
        assert!(compose.contains("- ../warp-state:/var/lib/cloudflare-warp"));
        assert!(!compose.contains("- ./warp-state:/var/lib/cloudflare-warp"));

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn mesh_state_is_host_level_across_release_swap_names() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        let previous = root.join("stack.previous");
        assert_eq!(
            mesh_runtime_state_dir(&stack).unwrap(),
            root.join("mesh-state")
        );
        assert_eq!(
            mesh_runtime_state_dir(&previous).unwrap(),
            root.join("mesh-state")
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn typed_image_environment_requires_exact_digests() {
        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(IMAGE_ENV_FILE),
            concat!(
                "EDGE_GATEWAY_IMAGE=ghcr.io/iamaman11/vultr-edge-gateway@sha256:",
                "1111111111111111111111111111111111111111111111111111111111111111\n",
                "EDGE_WARP_EGRESS_IMAGE=ghcr.io/iamaman11/vultr-warp-egress@sha256:",
                "2222222222222222222222222222222222222222222222222222222222222222\n",
                "CLOUDFLARE_MESH_IMAGE=docker.io/cloudflare/mesh@sha256:",
                "3333333333333333333333333333333333333333333333333333333333333333\n",
            ),
        )
        .unwrap();

        let images = read_exact_image_environment(&root).unwrap();
        assert_eq!(images.len(), 3);

        fs::write(
            root.join(IMAGE_ENV_FILE),
            "EDGE_GATEWAY_IMAGE=ghcr.io/iamaman11/vultr-edge-gateway:latest\n",
        )
        .unwrap();
        assert!(read_exact_image_environment(&root).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn typed_runtime_environment_accepts_vm_owned_credentials() {
        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        let mut runtime = "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n".to_owned();
        runtime.push_str(&ApplicationRuntimeSecrets::generate().render_env());
        fs::write(root.join(RUNTIME_ENV_FILE), runtime).unwrap();

        let values = read_typed_runtime_environment(&root).unwrap();
        assert_eq!(
            values.get("PROXY_USERNAME").map(String::as_str),
            Some("acceptance")
        );
        assert!(values.contains_key("REALITY_PRIVATE_KEY"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn renders_line2_runtime_without_shell_expansion() {
        let root = unique_test_dir();
        fs::create_dir_all(root.join("line2-proxy")).unwrap();
        fs::create_dir_all(root.join("rendered")).unwrap();
        fs::write(
            root.join("line2-proxy/config.template.json"),
            r#"{"username":"${PROXY_USERNAME}","password":"${PROXY_PASSWORD}","cert":"${PROXY_CERT_PATH}","key":"${PROXY_KEY_PATH}"}"#,
        )
        .unwrap();

        let values = BTreeMap::from([
            ("PROXY_USERNAME".to_owned(), "acceptance".to_owned()),
            ("PROXY_PASSWORD".to_owned(), "secret-value".to_owned()),
        ]);
        render_line2_runtime(&root, &values).unwrap();

        let rendered = fs::read_to_string(root.join("rendered/line2-proxy.json")).unwrap();
        assert!(rendered.contains("\"username\":\"acceptance\""));
        assert!(rendered.contains("\"password\":\"secret-value\""));
        assert!(!rendered.contains("${"));
        let mode = fs::metadata(root.join("rendered/line2-proxy.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn datapath_probe_uses_an_enabled_gateway_consumer() {
        assert_eq!(
            runtime_probe_consumer(&["vultr-line1-gateway".to_owned()]),
            Some(LINE1_CONTAINER)
        );
        assert_eq!(
            runtime_probe_consumer(&[
                "vultr-line1-gateway".to_owned(),
                "vultr-line2-proxy".to_owned(),
            ]),
            Some(LINE2_CONTAINER)
        );
        assert_eq!(
            runtime_probe_consumer(&["vultr-warp-egress".to_owned()]),
            None
        );
    }

    #[test]
    fn classifies_cloudflare_trace_without_exposing_addresses() {
        let direct = "fl=123\nip=203.0.113.10\nwarp=off\ncolo=WAW\n";
        let warp = "fl=123\nip=198.51.100.20\nwarp=on\ncolo=WAW\n";
        let plus = "fl=123\nip=198.51.100.21\nwarp=plus\ncolo=WAW\n";
        assert!(cloudflare_trace_has_warp_mode(direct, "off"));
        assert!(cloudflare_trace_has_warp_mode(warp, "on"));
        assert!(cloudflare_trace_has_warp_mode(plus, "plus"));
        assert!(!cloudflare_trace_has_warp_mode(warp, "off"));
        assert!(!cloudflare_trace_has_warp_mode("warp=on\n", "on"));
        assert!(!cloudflare_trace_has_warp_mode(
            "ip=203.0.113.10\nwarp=on\nwarp=off\n",
            "on"
        ));
    }

    #[test]
    fn verifies_base_bootstrap_from_running_container_state() {
        let state = AgentState {
            healthy: true,
            ready: true,
            topology_version: "v1".to_owned(),
            active_bundle_id: None,
            degraded_reasons: Vec::new(),
            docker_reachable: true,
            compose_file_present: true,
            observed_stack_path: Some("/opt/vultr-edge-stack/stack".to_owned()),
            running_containers: vec![
                "vultr-warp-egress".to_owned(),
                "vultr-line2-proxy".to_owned(),
            ],
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            direct_egress_ready: Some(true),
            warp_egress_ready: Some(true),
            mesh_runtime_ready: None,
        };

        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(".env.runtime"),
            "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
        )
        .unwrap();

        let verification = verify_bootstrap_post_state(&root, BootstrapMode::BootstrapBase, &state);
        assert!(verification.success);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn requires_tunnel_containers_for_tunnel_bootstrap() {
        let state = AgentState {
            healthy: true,
            ready: true,
            topology_version: "v1".to_owned(),
            active_bundle_id: None,
            degraded_reasons: Vec::new(),
            docker_reachable: true,
            compose_file_present: true,
            observed_stack_path: Some("/opt/vultr-edge-stack/stack".to_owned()),
            running_containers: vec![
                "vultr-warp-egress".to_owned(),
                "vultr-line2-proxy".to_owned(),
            ],
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            direct_egress_ready: Some(true),
            warp_egress_ready: Some(true),
            mesh_runtime_ready: None,
        };

        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(".env.runtime"),
            "TUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=admin@example.com\n",
        )
        .unwrap();

        let verification =
            verify_bootstrap_post_state(&root, BootstrapMode::BootstrapTunnel, &state);
        assert!(!verification.success);
        assert!(
            verification
                .warnings
                .iter()
                .any(|warning| warning.contains("vultr-line1-gateway"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    fn unique_test_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-agent-test-{unique}"))
    }
}
