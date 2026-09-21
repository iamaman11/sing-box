use clap::{Args, Parser, Subcommand, ValueEnum};
use edge_shared_types::{BootstrapMode, DeployRequest, DestroyRequest};
use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "edge-controller",
    version,
    about = "Typed edge platform controller"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    pub fn command_name(&self) -> &'static str {
        self.command.as_ref().map(Command::name).unwrap_or("serve")
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    ApplicationLifecycle {
        #[command(subcommand)]
        command: ApplicationLifecycleCommand,
    },
    CloudflareDns {
        #[command(subcommand)]
        command: CloudflareDnsCommand,
    },
    CloudflareZeroTrust {
        #[command(subcommand)]
        command: CloudflareZeroTrustCommand,
    },
    #[command(name = "line3-mesh")]
    Line3Mesh {
        #[command(subcommand)]
        command: MeshCommand,
    },
    VultrLifecycle {
        #[command(subcommand)]
        command: VultrLifecycleCommand,
    },
    VultrVpc {
        #[command(subcommand)]
        command: VultrVpcCommand,
    },
    Serve(ServeArgs),
    GetStatus(ControllerEndpointArgs),
    ControllerBootstrapRuntime(ControllerBootstrapArgs),
    BootstrapRuntime(AgentBootstrapArgs),
    StartLocal(ControllerEndpointArgs),
    StopLocal(ControllerEndpointArgs),
    RestartLocal(ControllerEndpointArgs),
    GetSelector(ControllerEndpointArgs),
    SetSelector(SetSelectorArgs),
    Trace(ControllerEndpointArgs),
    Deploy(DeployArgs),
    Destroy(DestroyArgs),
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::ApplicationLifecycle { .. } => "application-lifecycle",
            Self::CloudflareDns { .. } => "cloudflare-dns",
            Self::CloudflareZeroTrust { .. } => "cloudflare-zero-trust",
            Self::Line3Mesh { .. } => "line3-mesh",
            Self::VultrLifecycle { .. } => "vultr-lifecycle",
            Self::VultrVpc { .. } => "vultr-vpc",
            Self::Serve(_) => "serve",
            Self::GetStatus(_) => "get-status",
            Self::ControllerBootstrapRuntime(_) => "controller-bootstrap-runtime",
            Self::BootstrapRuntime(_) => "bootstrap-runtime",
            Self::StartLocal(_) => "start-local",
            Self::StopLocal(_) => "stop-local",
            Self::RestartLocal(_) => "restart-local",
            Self::GetSelector(_) => "get-selector",
            Self::SetSelector(_) => "set-selector",
            Self::Trace(_) => "trace",
            Self::Deploy(_) => "deploy",
            Self::Destroy(_) => "destroy",
        }
    }
}

#[derive(Debug, Args, Default)]
pub(crate) struct ServeArgs {
    pub repo_root: Option<PathBuf>,
    pub addr: Option<SocketAddr>,
}

#[derive(Debug, Args, Default)]
pub(crate) struct ControllerEndpointArgs {
    pub endpoint: Option<String>,
}

impl ControllerEndpointArgs {
    pub fn resolve(self) -> String {
        controller_endpoint(self.endpoint)
    }
}

#[derive(Debug, Args)]
pub(crate) struct SetSelectorArgs {
    pub name: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum BootstrapModeArg {
    Base,
    Tunnel,
    Full,
}

impl From<BootstrapModeArg> for BootstrapMode {
    fn from(value: BootstrapModeArg) -> Self {
        match value {
            BootstrapModeArg::Base => BootstrapMode::BootstrapBase,
            BootstrapModeArg::Tunnel => BootstrapMode::BootstrapTunnel,
            BootstrapModeArg::Full => BootstrapMode::BootstrapFull,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ControllerBootstrapArgs {
    #[arg(value_enum)]
    pub mode: BootstrapModeArg,
    pub endpoint: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct AgentBootstrapArgs {
    #[arg(value_enum)]
    pub mode: BootstrapModeArg,
    pub endpoint: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct DeployArgs {
    pub label_prefix: Option<String>,
    pub target_ip: Option<String>,
    pub instance_id: Option<String>,
    pub tunnel_domain: Option<String>,
    pub acme_email: Option<String>,
    pub dns_record_name: Option<String>,
    pub cloudflare_zone_name: Option<String>,
    pub snapshot_id: Option<String>,
    pub endpoint: Option<String>,
}

impl DeployArgs {
    pub fn into_parts(self) -> (DeployRequest, String) {
        let request = DeployRequest {
            label_prefix: normalized(self.label_prefix),
            target_ip: normalized(self.target_ip),
            instance_id: normalized(self.instance_id),
            tunnel_domain: normalized(self.tunnel_domain),
            acme_email: normalized(self.acme_email),
            dns_record_name: normalized(self.dns_record_name),
            cloudflare_zone_name: normalized(self.cloudflare_zone_name),
            mock_provider: env_flag("EDGE_MOCK_PROVIDER", false),
            skip_dns: env_flag("EDGE_SKIP_DNS", false),
            snapshot_id: normalized(self.snapshot_id),
        };
        (request, controller_endpoint(self.endpoint))
    }
}

#[derive(Debug, Args)]
pub(crate) struct DestroyArgs {
    pub instance_id: Option<String>,
    pub target_ip: Option<String>,
    pub dns_record_name: Option<String>,
    pub cloudflare_zone_name: Option<String>,
    pub endpoint: Option<String>,
}

impl DestroyArgs {
    pub fn into_parts(self) -> (DestroyRequest, String) {
        let request = DestroyRequest {
            instance_id: normalized(self.instance_id),
            target_ip: normalized(self.target_ip),
            dns_record_name: normalized(self.dns_record_name),
            cloudflare_zone_name: normalized(self.cloudflare_zone_name),
            mock_provider: env_flag("EDGE_MOCK_PROVIDER", false),
            delete_dns: env_flag("EDGE_DELETE_DNS", true),
            delete_instance: env_flag("EDGE_DELETE_INSTANCE", false),
            lifecycle_reason: env::var("EDGE_LIFECYCLE_REASON").ok().and_then(non_blank),
        };
        (request, controller_endpoint(self.endpoint))
    }
}

#[derive(Debug, Args, Clone)]
pub(crate) struct DesiredApplicationArgs {
    pub spec_path: PathBuf,
    pub artifact_manifest_path: PathBuf,
    pub edge_agent_artifact_path: PathBuf,
}

impl DesiredApplicationArgs {
    fn into_legacy(self, operation: &str) -> Vec<String> {
        vec![
            operation.to_owned(),
            path(self.spec_path),
            path(self.artifact_manifest_path),
            path(self.edge_agent_artifact_path),
        ]
    }
}

#[derive(Debug, Args, Clone)]
pub(crate) struct DesiredApplicationAuthorizedArgs {
    pub spec_path: PathBuf,
    pub artifact_manifest_path: PathBuf,
    pub edge_agent_artifact_path: PathBuf,
    pub authorized_plan_sha256: String,
}

impl DesiredApplicationAuthorizedArgs {
    fn into_legacy(self, operation: &str) -> Vec<String> {
        vec![
            operation.to_owned(),
            path(self.spec_path),
            path(self.artifact_manifest_path),
            path(self.edge_agent_artifact_path),
            self.authorized_plan_sha256,
        ]
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum ApplicationLifecycleCommand {
    Plan(DesiredApplicationArgs),
    Apply(DesiredApplicationAuthorizedArgs),
    Verify(DesiredApplicationArgs),
    Upgrade(DesiredApplicationAuthorizedArgs),
    RollbackPlan(SpecArgs),
    RollbackApply(CleanupApplyArgs),
}

impl ApplicationLifecycleCommand {
    pub fn into_legacy_args(self) -> Vec<String> {
        match self {
            Self::Plan(args) => args.into_legacy("plan"),
            Self::Apply(args) => args.into_legacy("apply"),
            Self::Verify(args) => args.into_legacy("verify"),
            Self::Upgrade(args) => args.into_legacy("upgrade"),
            Self::RollbackPlan(args) => vec!["rollback-plan".to_owned(), path(args.spec_path)],
            Self::RollbackApply(args) => destructive_apply("rollback-apply", args),
        }
    }
}

#[derive(Debug, Args, Clone)]
pub(crate) struct SpecArgs {
    pub spec_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct AuthorizedSpecArgs {
    pub spec_path: PathBuf,
    pub authorized_plan_sha256: String,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct CleanupApplyArgs {
    pub spec_path: PathBuf,
    pub digest: String,
    pub authorized_plan_sha256: String,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct DnsTargetArgs {
    pub spec_path: PathBuf,
    pub target_ipv4: Ipv4Addr,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct DnsTargetAuthorizedArgs {
    pub spec_path: PathBuf,
    pub target_ipv4: Ipv4Addr,
    pub authorized_plan_sha256: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CloudflareDnsCommand {
    Inventory(SpecArgs),
    Plan(DnsTargetArgs),
    Apply(DnsTargetAuthorizedArgs),
    CleanupPlan(SpecArgs),
    CleanupApply(CleanupApplyArgs),
}

impl CloudflareDnsCommand {
    pub fn into_legacy_args(self) -> Vec<String> {
        match self {
            Self::Inventory(args) => vec!["inventory".to_owned(), path(args.spec_path)],
            Self::Plan(args) => vec![
                "plan".to_owned(),
                path(args.spec_path),
                args.target_ipv4.to_string(),
            ],
            Self::Apply(args) => vec![
                "apply".to_owned(),
                path(args.spec_path),
                args.target_ipv4.to_string(),
                args.authorized_plan_sha256,
            ],
            Self::CleanupPlan(args) => vec!["cleanup-plan".to_owned(), path(args.spec_path)],
            Self::CleanupApply(args) => destructive_apply("cleanup-apply", args),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum CloudflareZeroTrustCommand {
    Doctor(SpecArgs),
    Inventory(SpecArgs),
    Plan(SpecArgs),
    Apply(AuthorizedSpecArgs),
    Verify(SpecArgs),
}

impl CloudflareZeroTrustCommand {
    pub fn into_legacy_args(self) -> Vec<String> {
        match self {
            Self::Doctor(args) => vec!["doctor".to_owned(), path(args.spec_path)],
            Self::Inventory(args) => vec!["inventory".to_owned(), path(args.spec_path)],
            Self::Plan(args) => vec!["plan".to_owned(), path(args.spec_path)],
            Self::Apply(args) => args.into_legacy("apply"),
            Self::Verify(args) => vec!["verify".to_owned(), path(args.spec_path)],
        }
    }
}

#[derive(Debug, Args, Clone)]
pub(crate) struct MeshVpcArgs {
    pub mesh_base_spec_path: PathBuf,
    pub vpc_spec_path: PathBuf,
    pub application_spec_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct MeshVpcAuthorizedArgs {
    pub mesh_base_spec_path: PathBuf,
    pub vpc_spec_path: PathBuf,
    pub application_spec_path: PathBuf,
    pub authorized_plan_sha256: String,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct MeshRuntimeArgs {
    pub mesh_spec_path: PathBuf,
    pub application_spec_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct RuntimeCleanupArgs {
    pub application_spec_path: PathBuf,
}

#[derive(Debug, Subcommand)]
pub(crate) enum MeshCommand {
    Inventory(SpecArgs),
    Plan(SpecArgs),
    Apply(AuthorizedSpecArgs),
    VpcPlan(MeshVpcArgs),
    VpcApply(MeshVpcAuthorizedArgs),
    CleanupPlan(SpecArgs),
    CleanupApply(CleanupApplyArgs),
    RuntimeApply(MeshRuntimeArgs),
    VpcRuntimeApply(MeshVpcArgs),
    RuntimeVerify(MeshRuntimeArgs),
    VpcRuntimeVerify(MeshVpcArgs),
    RuntimeCleanup(RuntimeCleanupArgs),
}

impl MeshCommand {
    pub fn into_legacy_args(self) -> Vec<String> {
        match self {
            Self::Inventory(args) => one("inventory", args),
            Self::Plan(args) => one("plan", args),
            Self::Apply(args) => authorized_spec("apply", args),
            Self::VpcPlan(args) => mesh_vpc("vpc-plan", args),
            Self::VpcApply(args) => vec![
                "vpc-apply".to_owned(),
                path(args.mesh_base_spec_path),
                path(args.vpc_spec_path),
                path(args.application_spec_path),
                args.authorized_plan_sha256,
            ],
            Self::CleanupPlan(args) => one("cleanup-plan", args),
            Self::CleanupApply(args) => destructive_apply("cleanup-apply", args),
            Self::RuntimeApply(args) => vec![
                "runtime-apply".to_owned(),
                path(args.mesh_spec_path),
                path(args.application_spec_path),
            ],
            Self::VpcRuntimeApply(args) => mesh_vpc("vpc-runtime-apply", args),
            Self::RuntimeVerify(args) => vec![
                "runtime-verify".to_owned(),
                path(args.mesh_spec_path),
                path(args.application_spec_path),
            ],
            Self::VpcRuntimeVerify(args) => mesh_vpc("vpc-runtime-verify", args),
            Self::RuntimeCleanup(args) => vec![
                "runtime-cleanup".to_owned(),
                path(args.application_spec_path),
            ],
        }
    }
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrPlanArgs {
    pub spec_path: PathBuf,
    pub machine_id: Option<String>,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrMachineArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrAuthorizedMachineArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub authorized_plan_sha256: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum VultrActionArg {
    Start,
    Halt,
    Reboot,
}

impl VultrActionArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Halt => "halt",
            Self::Reboot => "reboot",
        }
    }
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrActionArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    #[arg(value_enum)]
    pub action: VultrActionArg,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrAuthorizedActionArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    #[arg(value_enum)]
    pub action: VultrActionArg,
    pub authorized_plan_sha256: String,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrDestroyPlanArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub source_revision: String,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrDestroyApplyArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub source_revision: String,
    pub destroy_digest: String,
    pub authorized_plan_sha256: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum VultrLifecycleCommand {
    Doctor(SpecArgs),
    Inventory(SpecArgs),
    Plan(VultrPlanArgs),
    Apply(VultrAuthorizedMachineArgs),
    AcquireAccessPlan(VultrMachineArgs),
    AcquireAccess(VultrAuthorizedMachineArgs),
    ReleaseAccessPlan(VultrMachineArgs),
    ReleaseAccess(VultrAuthorizedMachineArgs),
    ActionPlan(VultrActionArgs),
    Action(VultrAuthorizedActionArgs),
    DestroyPlan(VultrDestroyPlanArgs),
    DestroyApply(VultrDestroyApplyArgs),
    CleanupPlan(SpecArgs),
    Cleanup(AuthorizedSpecArgs),
}

impl VultrLifecycleCommand {
    pub fn into_legacy_args(self) -> Vec<String> {
        match self {
            Self::Doctor(args) => one("doctor", args),
            Self::Inventory(args) => one("inventory", args),
            Self::Plan(args) => {
                let mut out = vec!["plan".to_owned(), path(args.spec_path)];
                if let Some(machine_id) = normalized(args.machine_id) {
                    out.push(machine_id);
                }
                out
            }
            Self::Apply(args) => vec![
                "apply".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.authorized_plan_sha256,
            ],
            Self::AcquireAccessPlan(args) => machine("acquire-access-plan", args),
            Self::AcquireAccess(args) => vec![
                "acquire-access".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.authorized_plan_sha256,
            ],
            Self::ReleaseAccessPlan(args) => machine("release-access-plan", args),
            Self::ReleaseAccess(args) => vec![
                "release-access".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.authorized_plan_sha256,
            ],
            Self::ActionPlan(args) => vec![
                "action-plan".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.action.as_str().to_owned(),
            ],
            Self::Action(args) => vec![
                "action".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.action.as_str().to_owned(),
                args.authorized_plan_sha256,
            ],
            Self::DestroyPlan(args) => vec![
                "destroy-plan".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.source_revision,
            ],
            Self::DestroyApply(args) => vec![
                "destroy-apply".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.source_revision,
                args.destroy_digest,
                args.authorized_plan_sha256,
            ],
            Self::CleanupPlan(args) => one("cleanup-plan", args),
            Self::Cleanup(args) => authorized_spec("cleanup", args),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum VultrVpcCommand {
    Inventory(SpecArgs),
    Plan(SpecArgs),
    Apply(AuthorizedSpecArgs),
    AttachmentPlan(SpecArgs),
    AttachmentApply(AuthorizedSpecArgs),
    Verify(SpecArgs),
    CleanupPlan(SpecArgs),
    CleanupApply(CleanupApplyArgs),
}

impl VultrVpcCommand {
    pub fn into_legacy_args(self) -> Vec<String> {
        match self {
            Self::Inventory(args) => one("inventory", args),
            Self::Plan(args) => one("plan", args),
            Self::Apply(args) => authorized_spec("apply", args),
            Self::AttachmentPlan(args) => one("attachment-plan", args),
            Self::AttachmentApply(args) => authorized_spec("attachment-apply", args),
            Self::Verify(args) => one("verify", args),
            Self::CleanupPlan(args) => one("cleanup-plan", args),
            Self::CleanupApply(args) => destructive_apply("cleanup-apply", args),
        }
    }
}

pub(crate) fn controller_endpoint(value: Option<String>) -> String {
    normalized(value)
        .or_else(|| {
            env::var("EDGE_CONTROLLER_ENDPOINT")
                .ok()
                .and_then(non_blank)
        })
        .unwrap_or_else(|| format!("http://{}", crate::DEFAULT_CONTROLLER_ADDR))
}

pub(crate) fn agent_endpoint(value: Option<String>) -> String {
    normalized(value)
        .or_else(|| env::var("EDGE_AGENT_ENDPOINT").ok().and_then(non_blank))
        .unwrap_or_else(|| crate::DEFAULT_AGENT_ENDPOINT.to_owned())
}

fn one(operation: &str, args: SpecArgs) -> Vec<String> {
    vec![operation.to_owned(), path(args.spec_path)]
}

fn authorized_spec(operation: &str, args: AuthorizedSpecArgs) -> Vec<String> {
    vec![
        operation.to_owned(),
        path(args.spec_path),
        args.authorized_plan_sha256,
    ]
}

fn destructive_apply(operation: &str, args: CleanupApplyArgs) -> Vec<String> {
    vec![
        operation.to_owned(),
        path(args.spec_path),
        args.digest,
        args.authorized_plan_sha256,
    ]
}

fn machine(operation: &str, args: VultrMachineArgs) -> Vec<String> {
    vec![operation.to_owned(), path(args.spec_path), args.machine_id]
}

fn mesh_vpc(operation: &str, args: MeshVpcArgs) -> Vec<String> {
    vec![
        operation.to_owned(),
        path(args.mesh_base_spec_path),
        path(args.vpc_spec_path),
        path(args.application_spec_path),
    ]
}

fn path(value: PathBuf) -> String {
    value.to_string_lossy().into_owned()
}

fn normalized(value: Option<String>) -> Option<String> {
    value.and_then(|value| non_blank(value))
}

fn non_blank(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn env_flag(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| value == "1")
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_typed_controller_commands() {
        let digest = "a".repeat(64);
        let cases = [
            vec![
                "edge-controller",
                "application-lifecycle",
                "apply",
                "infra/application/production.json",
                "artifact.json",
                "edge-agent",
                &digest,
            ],
            vec![
                "edge-controller",
                "application-lifecycle",
                "rollback-apply",
                "infra/application/production.json",
                &digest,
                &digest,
            ],
            vec![
                "edge-controller",
                "cloudflare-dns",
                "apply",
                "infra/cloudflare/dns.json",
                "203.0.113.10",
                &digest,
            ],
            vec![
                "edge-controller",
                "cloudflare-dns",
                "cleanup-apply",
                "infra/cloudflare/dns.json",
                &digest,
                &digest,
            ],
            vec![
                "edge-controller",
                "line3-mesh",
                "apply",
                "infra/cloudflare/mesh.json",
                &digest,
            ],
            vec![
                "edge-controller",
                "line3-mesh",
                "vpc-apply",
                "infra/cloudflare/mesh.json",
                "infra/vultr/vpc.json",
                "infra/application/production.json",
                &digest,
            ],
            vec![
                "edge-controller",
                "line3-mesh",
                "cleanup-apply",
                "infra/cloudflare/mesh.json",
                &digest,
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-lifecycle",
                "apply",
                "infra/vultr/production.json",
                "primary",
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-lifecycle",
                "acquire-access",
                "infra/vultr/production.json",
                "primary",
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-lifecycle",
                "release-access",
                "infra/vultr/production.json",
                "primary",
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-lifecycle",
                "action",
                "infra/vultr/production.json",
                "primary",
                "reboot",
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-lifecycle",
                "destroy-apply",
                "infra/vultr/production.json",
                "primary",
                "0123456789012345678901234567890123456789",
                &digest,
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-lifecycle",
                "cleanup",
                "infra/vultr/production.json",
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-vpc",
                "apply",
                "infra/vultr/vpc.json",
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-vpc",
                "attachment-apply",
                "infra/vultr/vpc.json",
                &digest,
            ],
            vec![
                "edge-controller",
                "vultr-vpc",
                "cleanup-apply",
                "infra/vultr/vpc.json",
                &digest,
                &digest,
            ],
        ];

        for args in cases {
            assert!(
                Cli::try_parse_from(args).is_ok(),
                "authority-bearing typed command must parse"
            );
        }

        assert!(
            Cli::try_parse_from([
                "edge-controller",
                "vultr-lifecycle",
                "action-plan",
                "infra/vultr/production.json",
                "primary",
                "reboot",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "edge-controller",
                "vultr-lifecycle",
                "acquire-access-plan",
                "infra/vultr/production.json",
                "primary",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "edge-controller",
                "vultr-lifecycle",
                "release-access-plan",
                "infra/vultr/production.json",
                "primary",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "edge-controller",
                "vultr-lifecycle",
                "cleanup-plan",
                "infra/vultr/production.json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_command_before_mutation() {
        assert!(Cli::try_parse_from(["edge-controller", "shell"]).is_err());
    }

    #[test]
    fn rejects_invalid_bootstrap_mode() {
        assert!(
            Cli::try_parse_from(["edge-controller", "bootstrap-runtime", "arbitrary"]).is_err()
        );
    }
}
