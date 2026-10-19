use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use bollard::{
    API_DEFAULT_VERSION, Docker,
    errors::Error as BollardError,
    models::{
        ContainerSummary, ContainerSummaryNetworkSettings, ContainerSummaryStateEnum, PortSummary,
        PortSummaryTypeEnum,
    },
    query_parameters::{ListContainersOptionsBuilder, LogsOptionsBuilder},
};
use futures_util::TryStreamExt;

const DOCKER_SOCKET: &str = "unix:///var/run/docker.sock";
const DOCKER_API_TIMEOUT_SECONDS: u64 = 6;

#[derive(Debug, Clone)]
struct DockerContainerObservation {
    name: String,
    running: bool,
    image: Option<String>,
    networks: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DockerObservation {
    pub(crate) reachable: bool,
    pub(crate) running_containers: Vec<String>,
    pub(crate) listening_tcp_ports: Vec<u32>,
    pub(crate) listening_udp_ports: Vec<u32>,
    containers: Vec<DockerContainerObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerRuntimeEvidence {
    pub(crate) present: bool,
    pub(crate) running: bool,
    pub(crate) exit_code: Option<i64>,
    pub(crate) runtime_error: Option<String>,
    pub(crate) log_tail: Vec<String>,
    pub(crate) name: String,
    pub(crate) image: Option<String>,
    pub(crate) restart_count: Option<u64>,
    pub(crate) oom_killed: Option<bool>,
    pub(crate) health: Option<String>,
    pub(crate) networks: Vec<String>,
    pub(crate) published_ports: Vec<String>,
    pub(crate) mounts: Vec<String>,
}

impl ContainerRuntimeEvidence {
    pub(crate) fn summary(&self) -> String {
        let exit_code = self
            .exit_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        let runtime_error = self.runtime_error.as_deref().unwrap_or("none");
        let logs = if self.log_tail.is_empty() {
            "none".to_owned()
        } else {
            self.log_tail.join(" | ")
        };
        format!(
            "present={} running={} exit_code={} restart_count={} oom_killed={} health={} image={} networks={:?} ports={:?} mounts={:?} runtime_error={} log_tail={}",
            self.present,
            self.running,
            exit_code,
            self.restart_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_owned()),
            self.oom_killed
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_owned()),
            self.health.as_deref().unwrap_or("unknown"),
            self.image.as_deref().unwrap_or("unknown"),
            self.networks,
            self.published_ports,
            self.mounts,
            runtime_error,
            logs
        )
    }
}

impl DockerObservation {
    pub(crate) fn unreachable() -> Self {
        Self {
            reachable: false,
            running_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            containers: Vec::new(),
        }
    }

    pub(crate) fn container_present(&self, name: &str) -> bool {
        self.containers
            .iter()
            .any(|container| container.name == name)
    }

    pub(crate) fn container_running(&self, name: &str) -> bool {
        self.containers
            .iter()
            .any(|container| container.name == name && container.running)
    }

    pub(crate) fn container_exact_image_ready(&self, name: &str, expected: &str) -> bool {
        self.containers.iter().any(|container| {
            container.name == name
                && container.running
                && container.image.as_deref() == Some(expected)
        })
    }

    pub(crate) fn container_on_mesh_network(&self, name: &str) -> bool {
        self.containers.iter().any(|container| {
            container.name == name
                && container.running
                && container
                    .networks
                    .iter()
                    .any(|network| network == "mesh_net" || network.ends_with("_mesh_net"))
        })
    }
}

async fn docker_connection() -> Result<Docker, String> {
    Docker::connect_with_unix(
        DOCKER_SOCKET,
        DOCKER_API_TIMEOUT_SECONDS,
        API_DEFAULT_VERSION,
    )
    .map_err(|err| format!("failed to open Docker Engine Unix socket: {err}"))?
    .negotiate_version()
    .await
    .map_err(|err| format!("failed to negotiate Docker Engine API version: {err}"))
}

/// Prevent the native lifecycle from ever adopting a same-named container
/// belonging to another Compose project. Foreign Mesh/other containers are
/// outside our resource scope and must not be inspected or mutated here.
fn exact_application_compose_owner(
    name: &str,
    labels: &HashMap<String, String>,
) -> Result<(), &'static str> {
    let service = match name {
        "vultr-warp-egress" => "warp-egress",
        "vultr-line1-gateway" => "line1-gateway",
        "vultr-line2-proxy" => "line2-proxy",
        _ => return Err("HOST_NATIVE_CONTAINER_OUTSIDE_APPLICATION_SCOPE"),
    };
    if labels.get("com.docker.compose.project").map(String::as_str) != Some("vultr-edge")
        || labels.get("com.docker.compose.service").map(String::as_str) != Some(service)
    {
        return Err("HOST_NATIVE_CONTAINER_OWNERSHIP_UNPROVEN");
    }
    Ok(())
}

/// Root-only, read-only preadmission check. Docker names alone do not prove
/// ownership; verify Compose project AND service before the signed BEGIN.
/// A missing container is valid on fresh installs and optional profiles.
pub(crate) async fn verify_owned_application_containers() -> Result<(), String> {
    let docker = docker_connection().await?;
    for name in [
        "vultr-warp-egress",
        "vultr-line1-gateway",
        "vultr-line2-proxy",
    ] {
        let inspect = match docker.inspect_container(name, None).await {
            Ok(value) => value,
            Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => continue,
            Err(_) => return Err("HOST_NATIVE_DOCKER_IDENTITY_UNAVAILABLE".into()),
        };
        if inspect.name.as_deref() != Some(format!("/{name}").as_str()) {
            return Err("HOST_NATIVE_CONTAINER_NAME_UNPROVEN".into());
        }
        let config = inspect
            .config
            .as_ref()
            .ok_or("HOST_NATIVE_CONTAINER_CONFIG_MISSING")?;
        let labels = config
            .labels
            .as_ref()
            .ok_or("HOST_NATIVE_CONTAINER_LABELS_MISSING")?;
        exact_application_compose_owner(name, labels).map_err(str::to_owned)?;
    }
    Ok(())
}

pub(crate) async fn observe_docker() -> Result<DockerObservation, String> {
    let docker = docker_connection().await?;

    let options = ListContainersOptionsBuilder::default().all(true).build();
    let containers = docker
        .list_containers(Some(options))
        .await
        .map_err(|err| format!("failed to list Docker containers: {err}"))?;

    Ok(normalize_containers(containers))
}

pub(crate) async fn observe_container_runtime(
    container_name: &str,
) -> Result<ContainerRuntimeEvidence, String> {
    let docker = docker_connection().await?;
    let inspect = match docker.inspect_container(container_name, None).await {
        Ok(inspect) => inspect,
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            return Ok(ContainerRuntimeEvidence {
                present: false,
                running: false,
                exit_code: None,
                runtime_error: None,
                log_tail: Vec::new(),
                name: container_name.to_owned(),
                image: None,
                restart_count: None,
                oom_killed: None,
                health: None,
                networks: Vec::new(),
                published_ports: Vec::new(),
                mounts: Vec::new(),
            });
        }
        Err(err) => {
            return Err(format!(
                "failed to inspect Docker container {container_name}: {err}"
            ));
        }
    };

    let state = inspect.state.unwrap_or_default();
    let image = inspect
        .config
        .and_then(|config| config.image)
        .or(inspect.image);
    let restart_count = inspect
        .restart_count
        .and_then(|value| u64::try_from(value).ok());
    let oom_killed = state.oom_killed;
    let health = state
        .health
        .as_ref()
        .and_then(|health| health.status.as_ref())
        .map(|status| format!("{status:?}"));

    let network_settings = inspect.network_settings.unwrap_or_default();
    let mut networks = network_settings
        .networks
        .unwrap_or_default()
        .into_keys()
        .collect::<Vec<_>>();
    networks.sort();
    networks.dedup();

    let mut published_ports = network_settings
        .ports
        .unwrap_or_default()
        .into_iter()
        .flat_map(|(container_port, bindings)| {
            bindings
                .unwrap_or_default()
                .into_iter()
                .map(move |binding| match binding.host_port {
                    Some(host_port) => format!("{container_port}->{host_port}"),
                    None => container_port.clone(),
                })
        })
        .collect::<Vec<_>>();
    published_ports.sort();
    published_ports.dedup();

    let mut mounts = inspect
        .mounts
        .unwrap_or_default()
        .into_iter()
        .map(|mount| {
            let kind = mount.typ.unwrap_or_else(|| "UNKNOWN".to_owned());
            let destination = mount.destination.unwrap_or_else(|| "<unknown>".to_owned());
            let rw = mount
                .rw
                .map(|value| value.to_string())
                .unwrap_or_else(|| "UNKNOWN".to_owned());
            format!("{kind}:{destination}:rw={rw}")
        })
        .collect::<Vec<_>>();
    mounts.sort();
    mounts.dedup();

    let options = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .timestamps(false)
        .tail("40")
        .build();
    let log_tail = match docker
        .logs(container_name, Some(options))
        .try_collect::<Vec<_>>()
        .await
    {
        Ok(outputs) => {
            bounded_redacted_log_tail(outputs.into_iter().map(|output| output.to_string()))
        }
        Err(err) => vec![format!("[docker log observation unavailable: {err}]")],
    };

    Ok(ContainerRuntimeEvidence {
        present: true,
        running: state.running.unwrap_or(false),
        exit_code: state.exit_code,
        runtime_error: state.error.filter(|value| !value.is_empty()),
        log_tail,
        name: container_name.to_owned(),
        image,
        restart_count,
        oom_killed,
        health,
        networks,
        published_ports,
        mounts,
    })
}

// Bollard 0.21.1 models Docker inspect MountPoint.Type as Option<String>,
// not MountPointTypeEnum. Debug-formatting it adds quotes (\x22bind\x22) and
// therefore falsely rejects a genuine read-only bind. Check the exact wire
// representation directly, and keep missing/writable evidence fail-closed.
fn require_exact_readonly_config_bind(
    container: &str,
    kind: Option<&str>,
    writable: Option<bool>,
) -> Result<(), String> {
    match kind {
        Some("bind") => {}
        Some(_) => {
            return Err(format!(
                "runtime config proof {container} config mount type=NON_BIND"
            ));
        }
        None => {
            return Err(format!(
                "runtime config proof {container} config mount type=UNAVAILABLE"
            ));
        }
    }
    match writable {
        Some(false) => Ok(()),
        Some(true) => Err(format!(
            "runtime config proof {container} config mount writable=TRUE"
        )),
        None => Err(format!(
            "runtime config proof {container} config mount writable=UNAVAILABLE"
        )),
    }
}

/// Read-only proof of the *file visible to the running process*. This does
/// not claim that sing-box reloaded that file into its in-memory configuration.
/// Authentication is an independent network-level proof.
pub(crate) async fn verify_running_container_config_binding(
    name: &str,
    expected_host_file: &Path,
) -> Result<(), String> {
    const CONTAINER_CONFIG: &str = "/etc/sing-box/config.json";
    const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
    if !matches!(name, "vultr-line1-gateway" | "vultr-line2-proxy") {
        return Err("runtime credential proof refuses an unknown container".to_owned());
    }
    let docker = docker_connection().await?;
    let before = docker
        .inspect_container(name, None)
        .await
        .map_err(|_| "runtime config proof cannot inspect the named container".to_owned())?;
    let state = before
        .state
        .as_ref()
        .ok_or("runtime config proof requires observed container state")?;
    if state.running != Some(true) {
        return Err("runtime config proof refuses a non-running container".to_owned());
    }
    let pid = state
        .pid
        .filter(|pid| *pid > 1)
        .ok_or("runtime config proof requires exact running Linux process PID")?;
    let started_at = state
        .started_at
        .clone()
        .ok_or("runtime config proof requires Docker process start identity")?;

    let config_mounts = before
        .mounts
        .as_ref()
        .ok_or("runtime config proof requires Docker bind mount evidence")?
        .iter()
        .filter(|mount| mount.destination.as_deref() == Some(CONTAINER_CONFIG))
        .collect::<Vec<_>>();
    if config_mounts.len() != 1 {
        return Err("runtime config proof requires exactly one config bind mount".to_owned());
    }
    let mount = config_mounts[0];
    require_exact_readonly_config_bind(name, mount.typ.as_deref(), mount.rw)?;
    let expected = fs::canonicalize(expected_host_file)
        .map_err(|_| "runtime config proof cannot resolve expected host file".to_owned())?;
    let bound = mount
        .source
        .as_deref()
        .ok_or("runtime config proof has no Docker source path")?;
    if fs::canonicalize(bound).ok().as_deref() != Some(expected.as_path()) {
        return Err("runtime config proof refuses a different bind source".to_owned());
    }
    let metadata = fs::metadata(&expected)
        .map_err(|_| "runtime config proof cannot stat expected file".to_owned())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
        return Err("runtime config proof refuses a missing or oversized config".to_owned());
    }
    let visible = PathBuf::from(format!("/proc/{pid}/root{CONTAINER_CONFIG}"));
    let in_container = fs::read(&visible)
        .map_err(|_| "runtime config proof cannot read running process mount view".to_owned())?;
    if in_container.len() as u64 != metadata.len()
        || in_container
            != fs::read(&expected)
                .map_err(|_| "runtime config proof cannot re-read expected host file".to_owned())?
    {
        return Err(
            "running process sees different config bytes than the exact host bind".to_owned(),
        );
    }
    let after = docker
        .inspect_container(name, None)
        .await
        .map_err(|_| "runtime config proof cannot re-inspect the named container".to_owned())?;
    let stable = after.state.as_ref().is_some_and(|state| {
        state.running == Some(true)
            && state.pid == Some(pid)
            && state.started_at.as_ref() == Some(&started_at)
    });
    if !stable {
        return Err("running container restarted during config-source attestation".to_owned());
    }
    Ok(())
}

fn bounded_redacted_log_tail<I>(lines: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut normalized = lines
        .into_iter()
        .flat_map(|chunk| {
            chunk
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(redact_runtime_log_line)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    if normalized.len() > 40 {
        normalized.drain(..normalized.len() - 40);
    }
    normalized
}

fn redact_runtime_log_line(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    if [
        "password",
        "private_key",
        "private key",
        "authorization",
        "credential",
        "mesh_node_token",
        "bearer ",
        "token=",
        "uuid=",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        return "[redacted sensitive runtime log line]".to_owned();
    }
    line.chars().take(320).collect()
}

fn normalize_containers(summaries: Vec<ContainerSummary>) -> DockerObservation {
    let mut containers = Vec::new();
    let mut running_containers = BTreeSet::new();
    let mut listening_tcp_ports = BTreeSet::new();
    let mut listening_udp_ports = BTreeSet::new();

    for summary in summaries {
        let running = matches!(summary.state, Some(ContainerSummaryStateEnum::RUNNING));
        let mut names = summary
            .names
            .unwrap_or_default()
            .into_iter()
            .map(|name| name.trim_start_matches('/').to_owned())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();

        if running {
            running_containers.extend(names.iter().cloned());
            for port in summary.ports.unwrap_or_default() {
                let Some(public_port) = port.public_port else {
                    continue;
                };
                match port.typ {
                    Some(PortSummaryTypeEnum::TCP) => {
                        listening_tcp_ports.insert(u32::from(public_port));
                    }
                    Some(PortSummaryTypeEnum::UDP) => {
                        listening_udp_ports.insert(u32::from(public_port));
                    }
                    _ => {}
                }
            }
        }

        let image = summary.image;
        let mut networks = summary
            .network_settings
            .and_then(|settings| settings.networks)
            .map(|networks| networks.into_keys().collect::<Vec<_>>())
            .unwrap_or_default();
        networks.sort();
        networks.dedup();

        for name in names {
            containers.push(DockerContainerObservation {
                name,
                running,
                image: image.clone(),
                networks: networks.clone(),
            });
        }
    }

    containers.sort_by(|left, right| left.name.cmp(&right.name));
    DockerObservation {
        reachable: true,
        running_containers: running_containers.into_iter().collect(),
        listening_tcp_ports: listening_tcp_ports.into_iter().collect(),
        listening_udp_ports: listening_udp_ports.into_iter().collect(),
        containers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_owner_requires_exact_compose_service_identity() {
        let mut labels = HashMap::from([
            (
                "com.docker.compose.project".to_owned(),
                "vultr-edge".to_owned(),
            ),
            (
                "com.docker.compose.service".to_owned(),
                "line1-gateway".to_owned(),
            ),
        ]);
        assert_eq!(
            exact_application_compose_owner("vultr-line1-gateway", &labels),
            Ok(())
        );
        assert_eq!(
            exact_application_compose_owner("vultr-line2-proxy", &labels),
            Err("HOST_NATIVE_CONTAINER_OWNERSHIP_UNPROVEN")
        );
        assert_eq!(
            exact_application_compose_owner("vultr-cloudflare-mesh", &labels),
            Err("HOST_NATIVE_CONTAINER_OUTSIDE_APPLICATION_SCOPE")
        );
        labels.insert("com.docker.compose.project".into(), "foreign-stack".into());
        assert_eq!(
            exact_application_compose_owner("vultr-line1-gateway", &labels),
            Err("HOST_NATIVE_CONTAINER_OWNERSHIP_UNPROVEN")
        );
        labels.remove("com.docker.compose.project");
        assert!(exact_application_compose_owner("vultr-line1-gateway", &labels).is_err());
        labels.insert("com.docker.compose.project".into(), "vultr-edge".into());
        labels.insert("com.docker.compose.service".into(), "warp-egress".into());
        assert_eq!(
            exact_application_compose_owner("vultr-warp-egress", &labels),
            Ok(())
        );
    }

    #[test]
    fn bollard_inspect_string_mount_type_is_exactly_bind_without_debug_quotes() {
        use bollard::models::MountPoint;

        let real_readonly_mount = MountPoint {
            typ: Some("bind".to_owned()),
            rw: Some(false),
            ..Default::default()
        };
        let positive = require_exact_readonly_config_bind(
            "vultr-line1-gateway",
            real_readonly_mount.typ.as_deref(),
            real_readonly_mount.rw,
        );
        assert_eq!(positive, Ok(()));
        // The previous Debug-based comparison quoted this String.
        assert_ne!(format!("{:?}", "bind"), "bind");

        for kind in [None, Some("volume"), Some("tmpfs"), Some("BIND"), Some("")] {
            let result =
                require_exact_readonly_config_bind("vultr-line1-gateway", kind, Some(false));
            assert!(result.is_err());
        }
        for writable in [Some(true), None] {
            let result =
                require_exact_readonly_config_bind("vultr-line2-proxy", Some("bind"), writable);
            assert!(result.is_err());
        }
        let positive =
            require_exact_readonly_config_bind("vultr-line2-proxy", Some("bind"), Some(false));
        assert_eq!(positive, Ok(()));
    }

    fn container_summary(
        name: &str,
        running: bool,
        image: &str,
        tcp_port: Option<u16>,
        udp_port: Option<u16>,
        networks: &[&str],
    ) -> ContainerSummary {
        let mut ports = Vec::new();
        if let Some(public_port) = tcp_port {
            ports.push(PortSummary {
                private_port: public_port,
                public_port: Some(public_port),
                typ: Some(PortSummaryTypeEnum::TCP),
                ..Default::default()
            });
        }
        if let Some(public_port) = udp_port {
            ports.push(PortSummary {
                private_port: public_port,
                public_port: Some(public_port),
                typ: Some(PortSummaryTypeEnum::UDP),
                ..Default::default()
            });
        }

        ContainerSummary {
            names: Some(vec![format!("/{name}")]),
            image: Some(image.to_owned()),
            state: Some(if running {
                ContainerSummaryStateEnum::RUNNING
            } else {
                ContainerSummaryStateEnum::EXITED
            }),
            ports: Some(ports),
            network_settings: Some(ContainerSummaryNetworkSettings {
                networks: Some(
                    networks
                        .iter()
                        .map(|network| ((*network).to_owned(), Default::default()))
                        .collect::<HashMap<_, _>>(),
                ),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn typed_container_models_normalize_running_names_ports_image_and_networks() {
        let observation = normalize_containers(vec![
            container_summary(
                "vultr-cloudflare-mesh",
                true,
                "docker.io/cloudflare/mesh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                None,
                None,
                &["z-net", "vultr-edge_mesh_net", "a-net"],
            ),
            container_summary(
                "vultr-line2-proxy",
                true,
                "example.invalid/line2@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                Some(3128),
                Some(8443),
                &["vultr-edge_edge_net"],
            ),
            container_summary(
                "stopped-container",
                false,
                "example.invalid/stopped@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                Some(9999),
                None,
                &["vultr-edge_edge_net"],
            ),
        ]);

        assert!(observation.reachable);
        assert_eq!(
            observation.running_containers,
            vec!["vultr-cloudflare-mesh", "vultr-line2-proxy"]
        );
        assert_eq!(observation.listening_tcp_ports, vec![3128]);
        assert_eq!(observation.listening_udp_ports, vec![8443]);
        assert!(observation.container_present("stopped-container"));
        assert!(!observation.container_running("stopped-container"));
        let mesh = observation
            .containers
            .iter()
            .find(|container| container.name == "vultr-cloudflare-mesh")
            .unwrap();
        assert_eq!(
            mesh.networks,
            vec![
                "a-net".to_owned(),
                "vultr-edge_mesh_net".to_owned(),
                "z-net".to_owned()
            ]
        );
        assert!(observation.container_on_mesh_network("vultr-cloudflare-mesh"));
        assert!(observation.container_exact_image_ready(
            "vultr-cloudflare-mesh",
            "docker.io/cloudflare/mesh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn runtime_log_tail_is_bounded_and_redacts_sensitive_lines() {
        let input = (0..45)
            .map(|index| {
                if index == 44 {
                    "password=should-not-escape".to_owned()
                } else {
                    format!("safe-line-{index}")
                }
            })
            .collect::<Vec<_>>();
        let tail = bounded_redacted_log_tail(input);

        assert_eq!(tail.len(), 40);
        assert_eq!(tail.first().map(String::as_str), Some("safe-line-5"));
        assert_eq!(
            tail.last().map(String::as_str),
            Some("[redacted sensitive runtime log line]")
        );
        assert_eq!(
            redact_runtime_log_line("MESH_NODE_TOKEN secret-value"),
            "[redacted sensitive runtime log line]"
        );
        assert_eq!(
            redact_runtime_log_line("Authorization: Bearer secret-value"),
            "[redacted sensitive runtime log line]"
        );
    }

    #[test]
    fn unrelated_network_does_not_satisfy_mesh_membership() {
        let observation = normalize_containers(vec![container_summary(
            "vultr-cloudflare-mesh",
            true,
            "docker.io/cloudflare/mesh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            None,
            None,
            &["vultr-edge_edge_net"],
        )]);
        assert!(!observation.container_on_mesh_network("vultr-cloudflare-mesh"));
    }
}
