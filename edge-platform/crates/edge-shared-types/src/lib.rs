use core::fmt;

pub mod proto {
    pub fn encode_key(buffer: &mut Vec<u8>, field_number: u32, wire_type: u8) {
        encode_varint(buffer, ((field_number << 3) | u32::from(wire_type)) as u64);
    }

    pub fn encode_varint(buffer: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            buffer.push((value as u8) | 0x80);
            value >>= 7;
        }
        buffer.push(value as u8);
    }

    pub fn encode_bool(buffer: &mut Vec<u8>, field_number: u32, value: bool) {
        encode_key(buffer, field_number, 0);
        encode_varint(buffer, u64::from(value));
    }

    pub fn encode_enum(buffer: &mut Vec<u8>, field_number: u32, value: i32) {
        encode_key(buffer, field_number, 0);
        encode_varint(buffer, value as u64);
    }

    pub fn encode_string(buffer: &mut Vec<u8>, field_number: u32, value: &str) {
        encode_key(buffer, field_number, 2);
        encode_varint(buffer, value.len() as u64);
        buffer.extend_from_slice(value.as_bytes());
    }

    pub fn encode_message(buffer: &mut Vec<u8>, field_number: u32, value: &[u8]) {
        encode_key(buffer, field_number, 2);
        encode_varint(buffer, value.len() as u64);
        buffer.extend_from_slice(value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Direct,
    Warp,
}

impl Profile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Warp => "warp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Requested,
    Running,
    Succeeded,
    Failed,
}

impl OperationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployPhase {
    Requested,
    InstanceCreateRequested,
    InstanceProvisioning,
    InstanceAddressAssigned,
    InstanceRuntimeReady,
    HostTrustInitialized,
    BundleRendered,
    BundleUploaded,
    BaseBootstrapStarted,
    BaseReadyVerified,
    DnsCutoverStarted,
    DnsCutoverVerified,
    TunnelBootstrapStarted,
    TunnelReadyVerified,
    DeploymentPublished,
    LocalConfigSynced,
    Completed,
    Failed,
    RollbackStarted,
    RollbackCompleted,
}

impl DeployPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::InstanceCreateRequested => "instance_create_requested",
            Self::InstanceProvisioning => "instance_provisioning",
            Self::InstanceAddressAssigned => "instance_address_assigned",
            Self::InstanceRuntimeReady => "instance_runtime_ready",
            Self::HostTrustInitialized => "host_trust_initialized",
            Self::BundleRendered => "bundle_rendered",
            Self::BundleUploaded => "bundle_uploaded",
            Self::BaseBootstrapStarted => "base_bootstrap_started",
            Self::BaseReadyVerified => "base_ready_verified",
            Self::DnsCutoverStarted => "dns_cutover_started",
            Self::DnsCutoverVerified => "dns_cutover_verified",
            Self::TunnelBootstrapStarted => "tunnel_bootstrap_started",
            Self::TunnelReadyVerified => "tunnel_ready_verified",
            Self::DeploymentPublished => "deployment_published",
            Self::LocalConfigSynced => "local_config_synced",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::RollbackStarted => "rollback_started",
            Self::RollbackCompleted => "rollback_completed",
        }
    }
}

impl fmt::Display for DeployPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSubsystem {
    ProviderCompute,
    ProviderDns,
    RuntimeCompose,
    TransportSsh,
    LocalSingBox,
    ServerAgent,
    State,
}

impl ErrorSubsystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderCompute => "provider.compute",
            Self::ProviderDns => "provider.dns",
            Self::RuntimeCompose => "runtime.compose",
            Self::TransportSsh => "transport.ssh",
            Self::LocalSingBox => "local.singbox",
            Self::ServerAgent => "server.agent",
            Self::State => "state",
        }
    }

    pub const fn proto_number(self) -> i32 {
        match self {
            Self::ProviderCompute => 1,
            Self::ProviderDns => 2,
            Self::RuntimeCompose => 3,
            Self::TransportSsh => 4,
            Self::LocalSingBox => 5,
            Self::ServerAgent => 6,
            Self::State => 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformError {
    pub code: &'static str,
    pub stage: &'static str,
    pub message: String,
    pub retryable: bool,
    pub subsystem: ErrorSubsystem,
}

impl PlatformError {
    pub fn new(
        code: &'static str,
        stage: &'static str,
        message: impl Into<String>,
        retryable: bool,
        subsystem: ErrorSubsystem,
    ) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
            retryable,
            subsystem,
        }
    }

    pub fn encode_proto(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        proto::encode_string(&mut buffer, 1, self.code);
        proto::encode_string(&mut buffer, 2, self.stage);
        proto::encode_string(&mut buffer, 3, &self.message);
        proto::encode_bool(&mut buffer, 4, self.retryable);
        proto::encode_enum(&mut buffer, 5, self.subsystem.proto_number());
        buffer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentState {
    pub healthy: bool,
    pub ready: bool,
    pub topology_version: String,
    pub active_bundle_id: Option<String>,
    pub degraded_reasons: Vec<String>,
}

impl AgentState {
    pub fn bootstrap_placeholder() -> Self {
        Self {
            healthy: true,
            ready: false,
            topology_version: "unknown".to_owned(),
            active_bundle_id: None,
            degraded_reasons: vec!["runtime inspection not implemented in phase 0".to_owned()],
        }
    }

    pub fn encode_proto(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        proto::encode_bool(&mut buffer, 1, self.healthy);
        proto::encode_bool(&mut buffer, 2, self.ready);
        proto::encode_string(&mut buffer, 3, &self.topology_version);
        if let Some(active_bundle_id) = &self.active_bundle_id {
            proto::encode_string(&mut buffer, 4, active_bundle_id);
        }
        for reason in &self.degraded_reasons {
            proto::encode_string(&mut buffer, 5, reason);
        }
        buffer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileCategory {
    RequiredRepoInput,
    LocalOnlySensitive,
}

impl FileCategory {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RequiredRepoInput => "required_repo_input",
            Self::LocalOnlySensitive => "local_only_sensitive",
        }
    }

    pub const fn proto_number(&self) -> i32 {
        match self {
            Self::RequiredRepoInput => 1,
            Self::LocalOnlySensitive => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePresence {
    pub path: String,
    pub present: bool,
    pub category: FileCategory,
}

impl FilePresence {
    pub fn encode_proto(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        proto::encode_string(&mut buffer, 1, &self.path);
        proto::encode_bool(&mut buffer, 2, self.present);
        proto::encode_enum(&mut buffer, 3, self.category.proto_number());
        buffer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryReport {
    pub repo_root: String,
    pub rust_workspace_present: bool,
    pub required_repo_files: Vec<FilePresence>,
    pub local_only_files: Vec<FilePresence>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

impl InventoryReport {
    pub fn encode_proto(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        proto::encode_string(&mut buffer, 1, &self.repo_root);
        proto::encode_bool(&mut buffer, 2, self.rust_workspace_present);
        for file in &self.required_repo_files {
            proto::encode_message(&mut buffer, 3, &file.encode_proto());
        }
        for file in &self.local_only_files {
            proto::encode_message(&mut buffer, 4, &file.encode_proto());
        }
        for blocker in &self.blockers {
            proto::encode_string(&mut buffer, 5, blocker);
        }
        for warning in &self.warnings {
            proto::encode_string(&mut buffer, 6, warning);
        }
        buffer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerStatus {
    pub inventory: InventoryReport,
    pub agent_state: AgentState,
    pub status_notes: Vec<String>,
}

impl ControllerStatus {
    pub fn encode_proto(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        proto::encode_message(&mut buffer, 1, &self.inventory.encode_proto());
        proto::encode_message(&mut buffer, 2, &self.agent_state.encode_proto());
        for note in &self.status_notes {
            proto::encode_string(&mut buffer, 3, note);
        }
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_agent_state_as_proto() {
        let bytes = AgentState::bootstrap_placeholder().encode_proto();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x08);
    }

    #[test]
    fn encodes_platform_error_as_proto() {
        let error = PlatformError::new("code", "stage", "message", true, ErrorSubsystem::State);
        let bytes = error.encode_proto();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x0a);
    }

    #[test]
    fn encodes_controller_status_as_proto() {
        let status = ControllerStatus {
            inventory: InventoryReport {
                repo_root: "/tmp/repo".to_owned(),
                rust_workspace_present: true,
                required_repo_files: Vec::new(),
                local_only_files: Vec::new(),
                blockers: Vec::new(),
                warnings: Vec::new(),
            },
            agent_state: AgentState::bootstrap_placeholder(),
            status_notes: vec!["note".to_owned()],
        };
        let bytes = status.encode_proto();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x0a);
    }
}
