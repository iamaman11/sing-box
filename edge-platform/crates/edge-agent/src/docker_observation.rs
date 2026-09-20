use std::collections::{BTreeSet, HashMap};

use bollard::{
    API_DEFAULT_VERSION, Docker,
    models::{
        ContainerSummary, ContainerSummaryNetworkSettings, ContainerSummaryStateEnum, PortSummary,
        PortSummaryTypeEnum,
    },
    query_parameters::ListContainersOptionsBuilder,
};

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
        self.containers.iter().any(|container| container.name == name)
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

pub(crate) async fn observe_docker() -> Result<DockerObservation, String> {
    let docker = Docker::connect_with_unix(
        DOCKER_SOCKET,
        DOCKER_API_TIMEOUT_SECONDS,
        API_DEFAULT_VERSION,
    )
    .map_err(|err| format!("failed to open Docker Engine Unix socket: {err}"))?
    .negotiate_version()
    .await
    .map_err(|err| format!("failed to negotiate Docker Engine API version: {err}"))?;

    let options = ListContainersOptionsBuilder::default().all(true).build();
    let containers = docker
        .list_containers(Some(options))
        .await
        .map_err(|err| format!("failed to list Docker containers: {err}"))?;

    Ok(normalize_containers(containers))
}

fn normalize_containers(summaries: Vec<ContainerSummary>) -> DockerObservation {
    let mut containers = Vec::new();
    let mut running_containers = BTreeSet::new();
    let mut listening_tcp_ports = BTreeSet::new();
    let mut listening_udp_ports = BTreeSet::new();

    for summary in summaries {
        let running = matches!(
            summary.state,
            Some(ContainerSummaryStateEnum::RUNNING)
        );
        let names = summary
            .names
            .unwrap_or_default()
            .into_iter()
            .map(|name| name.trim_start_matches('/').to_owned())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();

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
        let networks = summary
            .network_settings
            .and_then(|settings| settings.networks)
            .map(|networks| networks.into_keys().collect::<Vec<_>>())
            .unwrap_or_default();

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
                &["vultr-edge_mesh_net"],
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
        assert!(observation.container_on_mesh_network("vultr-cloudflare-mesh"));
        assert!(observation.container_exact_image_ready(
            "vultr-cloudflare-mesh",
            "docker.io/cloudflare/mesh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
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
