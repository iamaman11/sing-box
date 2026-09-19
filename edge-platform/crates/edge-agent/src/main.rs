use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

use edge_shared_types::agent_service_server::{AgentService, AgentServiceServer};
use edge_shared_types::{
    AgentState, AgentVersion, ApplyBundleRequest, ApplyBundleResponse, BootstrapMode,
    BootstrapRuntimeRequest, BootstrapRuntimeResponse, BundleFile, Empty, FileCategory,
    FilePresence, ReadBundleIdentityRequest, ReadBundleIdentityResponse,
    ReadRenderedArtifactsRequest, ReadRenderedArtifactsResponse, VerifyRuntimeRequest,
};
use edge_trust::optional_agent_server_tls_from_env;
use serde::Deserialize;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const DEFAULT_AGENT_ADDR: &str = "127.0.0.1:50061";
const DEFAULT_STACK_DIR: &str = "/opt/vultr-edge-stack/stack";

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

    async fn verify_runtime(
        &self,
        request: Request<VerifyRuntimeRequest>,
    ) -> Result<Response<AgentState>, Status> {
        let mode = if request.into_inner().require_readiness {
            AgentMode::Readiness
        } else {
            AgentMode::Runtime
        };
        Ok(Response::new(inspect_runtime(&self.stack_dir, mode)))
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

        Ok(Response::new(ReadBundleIdentityResponse {
            active_bundle_id: summary.as_ref().and_then(|summary| summary.label.clone()),
            topology_version: summary
                .as_ref()
                .and_then(|summary| summary.instance_id.clone())
                .map(|instance_id| format!("vultr-edge:{instance_id}")),
            deployment_summary_path: summary_path.map(|path| path.display().to_string()),
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
    let Some(compose) = inspect_compose(&compose_path, &mut state) else {
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
    })
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

    let runtime_env = read_runtime_env(&stack_dir.join(".env.runtime"));
    let tunnel_expected = runtime_env
        .as_ref()
        .map(|values| {
            env_flag_present(values, "TUNNEL_DOMAIN") && env_flag_present(values, "ACME_EMAIL")
        })
        .unwrap_or(false);

    let mut expected = vec![
        "vultr-warp-egress",
        "vultr-edge-gateway",
        "vultr-edge-gateway-direct",
    ];
    if matches!(
        mode,
        BootstrapMode::BootstrapTunnel | BootstrapMode::BootstrapFull
    ) && tunnel_expected
    {
        expected.push("vultr-tunnel-edge");
        expected.push("vultr-tunnel-edge-warp");
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
    let missing_rendered = [
        "edge-gateway.json",
        "edge-gateway-direct.json",
        "tunnel-edge.json",
        "tunnel-edge-warp.json",
    ]
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

fn inspect_compose(compose_path: &Path, state: &mut AgentState) -> Option<ComposeObservation> {
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
    [
        ("docker-compose.yml", FileCategory::RequiredRepoInput),
        (".env.runtime", FileCategory::RequiredRepoInput),
        (
            "rendered/edge-gateway.json",
            FileCategory::RequiredRepoInput,
        ),
        (
            "rendered/edge-gateway-direct.json",
            FileCategory::RequiredRepoInput,
        ),
        ("rendered/tunnel-edge.json", FileCategory::RequiredRepoInput),
        (
            "rendered/tunnel-edge-warp.json",
            FileCategory::RequiredRepoInput,
        ),
        ("certs/proxy.crt", FileCategory::RequiredRepoInput),
        ("certs/proxy.key", FileCategory::RequiredRepoInput),
    ]
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
        fs::write(stack.join(".env.runtime"), "").unwrap();
        fs::write(stack.join("rendered/edge-gateway.json"), "{}").unwrap();
        fs::write(stack.join("rendered/edge-gateway-direct.json"), "{}").unwrap();
        fs::write(stack.join("rendered/tunnel-edge.json"), "{}").unwrap();
        fs::write(stack.join("rendered/tunnel-edge-warp.json"), "{}").unwrap();
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
  edge-gateway:
    container_name: vultr-edge-gateway
    ports:
      - "3128:3128/tcp"
  tunnel-edge:
    container_name: vultr-tunnel-edge
    ports:
      - "8443:8443/udp"
"#,
        )
        .unwrap();

        let mut state = AgentState::bootstrap_placeholder();
        let observation = inspect_compose(&root.join("docker-compose.yml"), &mut state).unwrap();
        assert!(state.compose_file_present);
        assert_eq!(observation.expected_containers.len(), 2);
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
            "TUNNEL_DOMAIN=edge.example.com\n",
        )
        .unwrap();
        fs::write(stack.join("rendered/edge-gateway.json"), "{}").unwrap();
        fs::write(stack.join("rendered/edge-gateway-direct.json"), "{}").unwrap();
        fs::write(stack.join("rendered/tunnel-edge.json"), "{}").unwrap();
        fs::write(stack.join("rendered/tunnel-edge-warp.json"), "{}").unwrap();
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
                "vultr-edge-gateway".to_owned(),
                "vultr-edge-gateway-direct".to_owned(),
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
                "vultr-edge-gateway".to_owned(),
                "vultr-edge-gateway-direct".to_owned(),
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
                .any(|warning| warning.contains("vultr-tunnel-edge"))
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
