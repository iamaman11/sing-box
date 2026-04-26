use core::fmt;

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
}
