use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

use edge_secrets::ApplicationRuntimeSecrets;
use edge_shared_types::agent_service_server::{AgentService, AgentServiceServer};
use edge_shared_types::{
    AgentState, AgentVersion, ApplyBundleRequest, ApplyBundleResponse, BootstrapMode,
    BootstrapRuntimeRequest, BootstrapRuntimeResponse, BundleFile, Empty, FileCategory,
    FilePresence, ReadBundleIdentityRequest, ReadBundleIdentityResponse,
    ReadRenderedArtifactsRequest, ReadRenderedArtifactsResponse, RollbackBundleRequest,
    RollbackBundleResponse, VerifyRuntimeRequest, canonical_apply_bundle_digest,
};
use edge_trust::optional_agent_server_tls_from_env;
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
            let addr = agent_addr_from_args(2)?;
            let stack_dir = stack_dir_from_args(3);
            serve(addr, stack_dir).await
        }
        other => Err(format!("unsupported command: {other}").into()),
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

fn agent_addr_from_args(index: usize) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr = env::args()
        .nth(index)
        .or_else(|| env::var("EDGE_AGENT_ADDR").ok())
        .unwrap_or_else(|| DEFAULT_AGENT_ADDR.to_owned());
    Ok(addr.parse()?)
}

fn stack_dir_from_args(index: usize) -> PathBuf {
    if let Some(path) = env::args().nth(index) {
        return PathBuf::from(path);
    }
    if let Ok(path) = env::var("EDGE_STACK_DIR") {
        return PathBuf::from(path);
    }
    PathBuf::from(DEFAULT_STACK_DIR)
}

struct AgentServerImpl {
    stack_dir: PathBuf,
}

#[tonic::async_trait]
impl AgentService for AgentServerImpl {
    async fn get_health(&self, _request: Request<Empty>) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(inspect_runtime(
            &self.stack_dir,
            AgentMode::Health,
        )))
    }

    async fn get_readiness(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(inspect_runtime(
            &self.stack_dir,
            AgentMode::Readiness,
        )))
    }

    async fn get_runtime_state(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(inspect_runtime(
            &self.stack_dir,
            AgentMode::Runtime,
        )))
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

    async fn bootstrap_runtime(
        &self,
        request: Request<BootstrapRuntimeRequest>,
    ) -> Result<Response<BootstrapRuntimeResponse>, Status> {
        let mode = BootstrapMode::try_from(request.into_inner().mode)
            .map_err(|_| Status::invalid_argument("unknown bootstrap mode"))?;
        if mode == BootstrapMode::Unspecified {
            return Err(Status::invalid_argument("bootstrap mode is required"));
        }

        Ok(Response::new(run_bootstrap(&self.stack_dir, mode)))
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
        let mut state = inspect_runtime(&self.stack_dir, inspection_mode);
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
}

#[derive(Clone, Copy)]
enum AgentMode {
    Health,
    Readiness,
    Runtime,
}

fn inspect_runtime(stack_dir: &Path, mode: AgentMode) -> AgentState {
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
    };

    inspect_bundle_artifacts(stack_dir, &mut state);

    let compose_path = stack_dir.join("docker-compose.yml");
    let enabled_profiles = enabled_application_profiles(stack_dir);
    let Some(compose) = inspect_compose(&compose_path, &mut state, &enabled_profiles) else {
        state.healthy = false;
        return state;
    };

    let docker = inspect_docker();
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

    state.ready = state.compose_file_present
        && !state
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("bundle artifact"))
        && state.docker_reachable
        && state.missing_containers.is_empty()
        && missing_tcp.is_empty()
        && missing_udp.is_empty();

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
    let line1 = ["REALITY_SERVER_NAME", "TUNNEL_DOMAIN", "ACME_EMAIL"]
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

fn run_bootstrap(stack_dir: &Path, mode: BootstrapMode) -> BootstrapRuntimeResponse {
    let script = stack_dir.join("bootstrap.sh");
    let mut warnings = Vec::new();

    if !script.is_file() {
        warnings.push(format!("bootstrap script is missing: {}", script.display()));
        return BootstrapRuntimeResponse {
            success: false,
            mode: mode as i32,
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            post_state: Some(inspect_runtime(stack_dir, AgentMode::Runtime)),
            warnings,
        };
    }

    let output = Command::new(&script)
        .arg(bootstrap_mode_arg(mode))
        .current_dir(stack_dir)
        .output();

    match output {
        Ok(output) => {
            let post_state = inspect_runtime(stack_dir, AgentMode::Runtime);
            let verified = verify_bootstrap_post_state(stack_dir, mode, &post_state);
            warnings.extend(verified.warnings);
            BootstrapRuntimeResponse {
                success: output.status.success() && verified.success,
                mode: mode as i32,
                exit_code: output.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                post_state: Some(post_state),
                warnings,
            }
        }
        Err(err) => {
            warnings.push(format!("failed to execute bootstrap script: {err}"));
            BootstrapRuntimeResponse {
                success: false,
                mode: mode as i32,
                exit_code: -1,
                stdout: String::new(),
                stderr: String::new(),
                post_state: Some(inspect_runtime(stack_dir, AgentMode::Runtime)),
                warnings,
            }
        }
    }
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

    let mut expected = vec!["vultr-warp-egress", "vultr-line2-proxy"];
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

    BootstrapVerification {
        success: warnings.is_empty(),
        warnings,
    }
}

fn bootstrap_mode_arg(mode: BootstrapMode) -> &'static str {
    match mode {
        BootstrapMode::BootstrapBase => "base",
        BootstrapMode::BootstrapTunnel => "tunnel",
        BootstrapMode::BootstrapFull => "full",
        BootstrapMode::Unspecified => "full",
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
    let mut expected_rendered = vec!["line2-proxy.json"];
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

    let certs_dir = stack_dir.join("certs");
    let missing_certs = ["proxy.crt", "proxy.key"]
        .iter()
        .filter(|name| !certs_dir.join(name).is_file())
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if !missing_certs.is_empty() {
        state.degraded_reasons.push(format!(
            "bundle artifact missing: certs/{}",
            missing_certs.join(", certs/")
        ));
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

    for service in compose.services.into_values() {
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

fn inspect_docker() -> DockerObservation {
    let names_output = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output();
    let ports_output = Command::new("docker")
        .args(["ps", "--format", "{{.Ports}}"])
        .output();

    let (Ok(names_output), Ok(ports_output)) = (names_output, ports_output) else {
        return DockerObservation::unreachable();
    };
    if !names_output.status.success() || !ports_output.status.success() {
        return DockerObservation::unreachable();
    }

    let running_containers = String::from_utf8_lossy(&names_output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    let mut listening_tcp_ports = BTreeSet::new();
    let mut listening_udp_ports = BTreeSet::new();
    for line in String::from_utf8_lossy(&ports_output.stdout).lines() {
        for mapping in line.split(',') {
            if let Some(parsed) = parse_docker_port_mapping(mapping.trim()) {
                match parsed.protocol {
                    Protocol::Tcp => {
                        listening_tcp_ports.insert(parsed.host_port);
                    }
                    Protocol::Udp => {
                        listening_udp_ports.insert(parsed.host_port);
                    }
                }
            }
        }
    }

    DockerObservation {
        reachable: true,
        running_containers,
        listening_tcp_ports: listening_tcp_ports.into_iter().collect(),
        listening_udp_ports: listening_udp_ports.into_iter().collect(),
    }
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

fn parse_docker_port_mapping(value: &str) -> Option<PortMapping> {
    let protocol = if value.ends_with("/udp") {
        Protocol::Udp
    } else {
        Protocol::Tcp
    };
    let host_side = value.split("->").next()?;
    let host_port = host_side.rsplit(':').next()?.parse().ok()?;
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
        ("docker-compose.yml", FileCategory::RequiredRepoInput),
        (RUNTIME_POLICY_FILE, FileCategory::RequiredRepoInput),
        (RUNTIME_ENV_FILE, FileCategory::LocalOnlySensitive),
        ("rendered/line2-proxy.json", FileCategory::RequiredRepoInput),
        ("certs/proxy.crt", FileCategory::RequiredRepoInput),
        ("certs/proxy.key", FileCategory::RequiredRepoInput),
    ];
    if tunnel_runtime_enabled(stack_dir) {
        required.insert(
            3,
            (
                "rendered/line1-gateway.json",
                FileCategory::RequiredRepoInput,
            ),
        );
    }

    required
        .into_iter()
        .map(|(path, category)| FilePresence {
            path: path.to_owned(),
            present: stack_dir.join(path).is_file(),
            category: category as i32,
        })
        .collect()
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

fn tunnel_runtime_enabled(stack_dir: &Path) -> bool {
    read_runtime_env(&stack_dir.join(".env.runtime")).is_some_and(|values| {
        env_flag_present(&values, "TUNNEL_DOMAIN") && env_flag_present(&values, "ACME_EMAIL")
    })
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
struct DockerObservation {
    reachable: bool,
    running_containers: Vec<String>,
    listening_tcp_ports: Vec<u32>,
    listening_udp_ports: Vec<u32>,
}

impl DockerObservation {
    fn unreachable() -> Self {
        Self {
            reachable: false,
            running_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
        }
    }
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

        fs::rename(&stack, root.join("stack.previous")).unwrap();
        fs::create_dir_all(&stack).unwrap();
        fs::write(
            stack.join(RUNTIME_POLICY_FILE),
            "PROXY_USERNAME=acceptance-v2\nPROXY_CERT_CN=acceptance.local\n",
        )
        .unwrap();
        materialize_vm_owned_runtime_environment(&stack).unwrap();
        let upgraded = fs::read_to_string(stack.join(RUNTIME_ENV_FILE)).unwrap();
        let upgraded_store =
            fs::read_to_string(root.join(RUNTIME_SECRET_DIR).join(RUNTIME_SECRET_FILE)).unwrap();

        assert_ne!(first, upgraded);
        assert!(upgraded.contains("PROXY_USERNAME=acceptance-v2\n"));
        assert_eq!(store, upgraded_store);

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
            ("bootstrap.sh", true, false, 0o755),
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
    fn reports_rendered_artifacts() {
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
        fs::write(stack.join(RUNTIME_ENV_FILE), "").unwrap();
        fs::write(stack.join("rendered/line2-proxy.json"), "{}").unwrap();
        fs::write(stack.join("certs/proxy.crt"), "crt").unwrap();
        fs::write(stack.join("certs/proxy.key"), "key").unwrap();

        let artifacts = collect_rendered_artifacts(&stack);
        assert!(artifacts.iter().all(|entry| entry.present));

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
        )
        .unwrap();
        assert_eq!(
            observation.expected_containers,
            vec!["vultr-line1-gateway", "vultr-line2-proxy"]
        );
        assert_eq!(observation.expected_tcp_ports, vec![3128]);
        assert_eq!(observation.expected_udp_ports, vec![8443]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reads_bundle_summary_and_artifacts() {
        let root = unique_test_dir();
        let stack = root.join("stack");
        fs::create_dir_all(stack.join("rendered")).unwrap();
        fs::create_dir_all(stack.join("certs")).unwrap();
        fs::write(
            stack.join(".env.runtime"),
            "TUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=admin@example.com\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/line2-proxy.json"), "{}").unwrap();
        fs::write(stack.join("rendered/line1-gateway.json"), "{}").unwrap();
        fs::write(stack.join("certs/proxy.crt"), "crt").unwrap();
        fs::write(stack.join("certs/proxy.key"), "key").unwrap();
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
    #[cfg(unix)]
    fn runs_bootstrap_script_by_mode() {
        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".env.runtime"), "TUNNEL_DOMAIN=\nACME_EMAIL=\n").unwrap();
        let script = root.join("bootstrap.sh");
        fs::write(
            &script,
            "#!/usr/bin/env bash\nset -euo pipefail\nmode=\"$1\"\nprintf '%s\n' \"$mode\" > .mode\ntouch docker-compose.yml\necho mode:$mode\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();

        let response = run_bootstrap(&root, BootstrapMode::BootstrapBase);
        assert!(!response.success);
        assert_eq!(response.mode, BootstrapMode::BootstrapBase as i32);
        assert!(response.stdout.contains("mode:base"));
        assert!(
            response
                .warnings
                .iter()
                .any(|warning| warning.contains("vultr-warp-egress"))
        );

        fs::remove_dir_all(root).unwrap();
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
        };

        let root = unique_test_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".env.runtime"), "TUNNEL_DOMAIN=\nACME_EMAIL=\n").unwrap();

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
