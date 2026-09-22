use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "edge-orchestrator",
    version,
    about = "GitHub-only typed provider and VM lifecycle orchestrator"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub fn command_name(&self) -> &'static str {
        self.command.name()
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
        }
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
pub(crate) struct DnsDerivedArgs {
    pub spec_path: PathBuf,
    pub application_spec_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct DnsDerivedAuthorizedArgs {
    pub spec_path: PathBuf,
    pub application_spec_path: PathBuf,
    pub authorized_plan_sha256: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CloudflareDnsCommand {
    Inventory(SpecArgs),
    Plan(DnsDerivedArgs),
    Apply(DnsDerivedAuthorizedArgs),
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
                path(args.application_spec_path),
            ],
            Self::Apply(args) => vec![
                "apply".to_owned(),
                path(args.spec_path),
                path(args.application_spec_path),
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
            Self::Apply(args) => vec![
                "apply".to_owned(),
                path(args.spec_path),
                args.authorized_plan_sha256,
            ],
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
    SubstratePlan(VultrMachineArgs),
    SubstrateApply(VultrAuthorizedMachineArgs),
    SubstrateVerify(VultrMachineArgs),
    AcquireAccessPlan(VultrMachineArgs),
    AcquireAccess(VultrAuthorizedMachineArgs),
    LeaseAcquire(VultrMachineArgs),
    ReleaseAccessPlan(VultrMachineArgs),
    ReleaseAccess(VultrAuthorizedMachineArgs),
    LeaseRelease(VultrMachineArgs),
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
            Self::SubstratePlan(args) => machine("substrate-plan", args),
            Self::SubstrateApply(args) => vec![
                "substrate-apply".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.authorized_plan_sha256,
            ],
            Self::SubstrateVerify(args) => machine("substrate-verify", args),
            Self::AcquireAccessPlan(args) => machine("acquire-access-plan", args),
            Self::AcquireAccess(args) => vec![
                "acquire-access".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.authorized_plan_sha256,
            ],
            Self::LeaseAcquire(args) => machine("lease-acquire", args),
            Self::ReleaseAccessPlan(args) => machine("release-access-plan", args),
            Self::ReleaseAccess(args) => vec![
                "release-access".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.authorized_plan_sha256,
            ],
            Self::LeaseRelease(args) => machine("lease-release", args),
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
    value.and_then(non_blank)
}

fn non_blank(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_typed_orchestrator_commands() {
        let digest = "a".repeat(64);
        let cases = [
            vec![
                "edge-orchestrator",
                "application-lifecycle",
                "apply",
                "infra/application/production.json",
                "artifact.json",
                "edge-agent",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "application-lifecycle",
                "rollback-apply",
                "infra/application/production.json",
                &digest,
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "cloudflare-dns",
                "apply",
                "infra/cloudflare/dns.json",
                "infra/application/production.json",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "cloudflare-dns",
                "cleanup-apply",
                "infra/cloudflare/dns.json",
                &digest,
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "line3-mesh",
                "apply",
                "infra/cloudflare/mesh.json",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "line3-mesh",
                "vpc-apply",
                "infra/cloudflare/mesh.json",
                "infra/vultr/vpc.json",
                "infra/application/production.json",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "line3-mesh",
                "cleanup-apply",
                "infra/cloudflare/mesh.json",
                &digest,
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "apply",
                "infra/vultr/production.json",
                "primary",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "acquire-access",
                "infra/vultr/production.json",
                "primary",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "release-access",
                "infra/vultr/production.json",
                "primary",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "lease-acquire",
                "infra/vultr/production.json",
                "primary",
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "lease-release",
                "infra/vultr/production.json",
                "primary",
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "action",
                "infra/vultr/production.json",
                "primary",
                "reboot",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "destroy-apply",
                "infra/vultr/production.json",
                "primary",
                "0123456789012345678901234567890123456789",
                &digest,
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "cleanup",
                "infra/vultr/production.json",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "vultr-vpc",
                "apply",
                "infra/vultr/vpc.json",
                &digest,
            ],
            vec![
                "edge-orchestrator",
                "vultr-vpc",
                "attachment-apply",
                "infra/vultr/vpc.json",
                &digest,
            ],
            vec![
                "edge-orchestrator",
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
                "edge-orchestrator",
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
                "edge-orchestrator",
                "vultr-lifecycle",
                "acquire-access-plan",
                "infra/vultr/production.json",
                "primary",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "edge-orchestrator",
                "vultr-lifecycle",
                "release-access-plan",
                "infra/vultr/production.json",
                "primary",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "edge-orchestrator",
                "vultr-lifecycle",
                "cleanup-plan",
                "infra/vultr/production.json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_command_before_mutation() {
        assert!(Cli::try_parse_from(["edge-orchestrator", "shell"]).is_err());
    }
}
