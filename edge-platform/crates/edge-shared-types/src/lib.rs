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
            warnings: Vec::new(),
            proxy_groups: Vec::new(),
        }
    }
}

impl UbuntuProxyState {
    pub fn unavailable(note: impl Into<String>) -> Self {
        Self {
            available: false,
            host: None,
            port: None,
            url: None,
            warnings: vec![note.into()],
        }
    }
}

impl ControllerStatus {
    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl DoctorResponse {
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

pub fn canonical_apply_bundle_digest(request: &ApplyBundleRequest) -> Result<String, String> {
    use ring::digest::{Context, SHA256};

    let bundle_id = request
        .bundle_id
        .as_deref()
        .ok_or_else(|| "digest-bound bundle requires bundle_id".to_owned())?;
    if bundle_id.is_empty()
        || bundle_id.len() > 160
        || !bundle_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err("bundle_id contains unsupported characters".to_owned());
    }

    struct Entry<'a> {
        scope: u8,
        file: &'a BundleFile,
    }

    let mut entries = Vec::new();
    entries.extend(
        request
            .stack_files
            .iter()
            .map(|file| Entry { scope: 1, file }),
    );
    entries.extend(
        request
            .host_files
            .iter()
            .map(|file| Entry { scope: 2, file }),
    );
    if let Some(file) = request.deployment_summary.as_ref() {
        entries.push(Entry { scope: 3, file });
    }
    if let Some(file) = request.agent_env_file.as_ref() {
        entries.push(Entry { scope: 4, file });
    }

    entries.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then_with(|| left.file.relative_path.cmp(&right.file.relative_path))
    });

    for pair in entries.windows(2) {
        if pair[0].scope == pair[1].scope
            && pair[0].file.relative_path == pair[1].file.relative_path
        {
            return Err(format!(
                "duplicate bundle path in scope {}: {}",
                pair[0].scope, pair[0].file.relative_path
            ));
        }
    }

    fn feed_field(context: &mut Context, bytes: &[u8]) {
        context.update(&(bytes.len() as u64).to_be_bytes());
        context.update(bytes);
    }

    let mut context = Context::new(&SHA256);
    context.update(b"sing-box-application-bundle-v1\0");
    feed_field(&mut context, bundle_id.as_bytes());
    context.update(&[u8::from(request.prune_existing)]);

    for entry in entries {
        context.update(&[entry.scope]);
        feed_field(&mut context, entry.file.relative_path.as_bytes());
        context.update(&[
            u8::from(entry.file.executable),
            u8::from(entry.file.sensitive),
        ]);
        feed_field(&mut context, &entry.file.content);
    }

    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
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
            ubuntu_selector: Some(SelectorState::placeholder()),
            ubuntu_proxy: Some(UbuntuProxyState::unavailable("unavailable")),
            status_notes: vec!["ok".to_owned()],
            app_readiness_phase: AppReadinessPhase::DeploymentAbsent as i32,
        };
        assert!(!status.encode_to_vec().is_empty());
    }
}
