pub mod edge {
    pub mod platform {
        pub mod v1 {
            tonic::include_proto!("edge.platform.v1");
        }
    }
}

pub use edge::platform::v1::*;
use prost::Message;

impl PlatformError {
    pub fn new(
        code: impl Into<String>,
        stage: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
        subsystem: ErrorSubsystem,
    ) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            message: message.into(),
            retryable,
            subsystem: subsystem as i32,
        }
    }

    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl AgentState {
    pub fn bootstrap_placeholder() -> Self {
        Self {
            healthy: true,
            ready: false,
            topology_version: "unknown".to_owned(),
            active_bundle_id: None,
            degraded_reasons: vec!["runtime inspection not implemented in phase 0".to_owned()],
            docker_reachable: false,
            compose_file_present: false,
            observed_stack_path: None,
            running_containers: Vec::new(),
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
        }
    }

    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl BootstrapRuntimeResponse {
    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl LocalRuntimeResponse {
    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl LocalSingboxState {
    pub fn placeholder(expected_config_path: impl Into<String>) -> Self {
        Self {
            process_running: false,
            managed_config: false,
            expected_config_path: expected_config_path.into(),
            active_config_path: None,
            clash_api_port: Some(9090),
            warnings: Vec::new(),
        }
    }
}

impl DeploymentSummary {
    pub fn missing() -> Self {
        Self {
            live_state_present: false,
            source_state_path: None,
            deployment_label: None,
            instance_id: None,
            server_ip: None,
            tunnel_domain: None,
        }
    }
}

impl ProviderObservation {
    pub fn placeholder() -> Self {
        Self {
            configured: false,
            compute_provider: "vultr".to_owned(),
            dns_provider: "cloudflare".to_owned(),
            warnings: vec!["provider probing not implemented in phase A".to_owned()],
        }
    }
}

impl RuntimeObservation {
    pub fn placeholder() -> Self {
        Self {
            edge_agent_reachable: false,
            runtime_kind: "docker-compose".to_owned(),
            warnings: vec!["edge-agent gRPC probing not implemented in phase A".to_owned()],
            docker_reachable: false,
            observed_stack_path: None,
            running_containers: Vec::new(),
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            topology_version: None,
            active_bundle_id: None,
            compose_file_present: false,
        }
    }

    pub fn from_agent_state(agent_state: &AgentState) -> Self {
        Self {
            edge_agent_reachable: true,
            runtime_kind: "docker-compose".to_owned(),
            warnings: agent_state.degraded_reasons.clone(),
            docker_reachable: agent_state.docker_reachable,
            observed_stack_path: agent_state.observed_stack_path.clone(),
            running_containers: agent_state.running_containers.clone(),
            missing_containers: agent_state.missing_containers.clone(),
            listening_tcp_ports: agent_state.listening_tcp_ports.clone(),
            listening_udp_ports: agent_state.listening_udp_ports.clone(),
            topology_version: Some(agent_state.topology_version.clone()),
            active_bundle_id: agent_state.active_bundle_id.clone(),
            compose_file_present: agent_state.compose_file_present,
        }
    }

    pub fn agent_unreachable(reason: impl Into<String>) -> Self {
        Self {
            edge_agent_reachable: false,
            runtime_kind: "docker-compose".to_owned(),
            warnings: vec![reason.into()],
            docker_reachable: false,
            observed_stack_path: None,
            running_containers: Vec::new(),
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            topology_version: None,
            active_bundle_id: None,
            compose_file_present: false,
        }
    }
}

impl SelectorState {
    pub fn placeholder() -> Self {
        Self {
            desired_main_route: None,
            observed_main_route: None,
            degraded: false,
            warnings: vec!["selector observation not implemented in phase A".to_owned()],
            proxy_groups: Vec::new(),
        }
    }
}

impl ControllerStatus {
    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl TraceObservation {
    pub fn unavailable(note: impl Into<String>) -> Self {
        Self {
            available: false,
            ip: None,
            warp: None,
            colo: None,
            note: Some(note.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn encodes_agent_state_with_prost() {
        let bytes = AgentState::bootstrap_placeholder().encode_to_vec();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn encodes_controller_status_with_prost() {
        let status = ControllerStatus {
            inventory: Some(InventoryReport {
                repo_root: "/tmp/repo".to_owned(),
                rust_workspace_present: true,
                required_repo_files: Vec::new(),
                local_only_files: Vec::new(),
                blockers: Vec::new(),
                warnings: Vec::new(),
            }),
            agent_state: Some(AgentState::bootstrap_placeholder()),
            local_singbox: Some(LocalSingboxState::placeholder("config.json")),
            deployment: Some(DeploymentSummary::missing()),
            provider: Some(ProviderObservation::placeholder()),
            runtime: Some(RuntimeObservation::placeholder()),
            selector: Some(SelectorState::placeholder()),
            status_notes: vec!["ok".to_owned()],
        };
        assert!(!status.encode_to_vec().is_empty());
    }
}
