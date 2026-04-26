use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use edge_shared_types::agent_service_server::{AgentService, AgentServiceServer};
use edge_shared_types::{AgentState, AgentVersion, Empty};
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
    Server::builder()
        .add_service(AgentServiceServer::new(AgentServerImpl { stack_dir }))
        .serve(addr)
        .await?;
    Ok(())
}

fn agent_addr_from_args(index: usize) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr = env::args()
        .nth(index)
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

fn read_bundle_summary(path: &Path) -> Option<BundleSummary> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
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

    fn unique_test_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-agent-test-{unique}"))
    }
}
