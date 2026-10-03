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
    ApplicationAcceptance(ApplicationAcceptanceArgs),
    ApplicationBundleBuild(ApplicationBundleBuildArgs),
    ApplicationCleanup(ApplicationCleanupArgs),
    CloudflareTargetPlane {
        #[command(subcommand)]
        command: CloudflareTargetPlaneCommand,
    },
    CloudflareZeroTrust {
        #[command(subcommand)]
        command: CloudflareZeroTrustCommand,
    },
    Credentials {
        #[command(subcommand)]
        command: CredentialDeliveryCommand,
    },
    Production {
        #[command(subcommand)]
        command: ProductionCommand,
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
            Self::ApplicationAcceptance(_) => "application-acceptance",
            Self::ApplicationBundleBuild(_) => "application-bundle-build",
            Self::ApplicationCleanup(_) => "application-cleanup",
            Self::CloudflareTargetPlane { .. } => "cloudflare-target-plane",
            Self::CloudflareZeroTrust { .. } => "cloudflare-zero-trust",
            Self::Credentials { .. } => "credentials",
            Self::Production { .. } => "production",
            Self::VultrLifecycle { .. } => "vultr-lifecycle",
            Self::VultrVpc { .. } => "vultr-vpc",
        }
    }
}

#[derive(Debug, Args, Clone)]
pub(crate) struct ApplicationAcceptanceArgs {
    pub spec_path: PathBuf,
    pub artifact_manifest_path: PathBuf,
    pub edge_agent_artifact_path: PathBuf,
    pub dns_spec_path: PathBuf,
    pub mesh_base_spec_path: PathBuf,
    pub vpc_spec_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct ApplicationBundleBuildArgs {
    pub spec_path: PathBuf,
    pub runtime_source_revision: String,
    pub edge_agent_artifact_path: PathBuf,
    pub edge_gateway_image: String,
    pub edge_warp_egress_image: String,
    pub mesh_image: String,
    pub output_protobuf_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct ApplicationCleanupArgs {
    pub spec_path: PathBuf,
    pub dns_spec_path: PathBuf,
    pub mesh_base_spec_path: PathBuf,
    pub vpc_spec_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct DesiredApplicationArgs {
    pub spec_path: PathBuf,
    pub artifact_manifest_path: PathBuf,
    pub edge_agent_artifact_path: PathBuf,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ApplicationLifecycleCommand {
    Materialize(DesiredApplicationArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProductionCommand {
    Validate,
    Diagnose,
    EnrollRuntime(ProductionEnrollRuntimeArgs),
    Converge(ProductionRuntimeArgs),
    Verify(ProductionRuntimeArgs),
}

#[derive(Debug, Args, Clone)]
pub(crate) struct ProductionEnrollRuntimeArgs {
    pub edge_agent_artifact_path: PathBuf,
    pub runner_installer_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct ProductionRuntimeArgs {
    pub edge_agent_artifact_path: PathBuf,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CredentialRotationClassArg {
    TunnelAuth,
    RealityIdentity,
    Line2ProxyAuth,
}

impl CredentialRotationClassArg {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::TunnelAuth => "tunnel-auth",
            Self::RealityIdentity => "reality-identity",
            Self::Line2ProxyAuth => "line2-proxy-auth",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CredentialDeliverySlotArg {
    A,
    B,
}

impl CredentialDeliverySlotArg {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(crate) enum CredentialDeliveryCommand {
    ContractVerify,
    HostBootstrapConverge,
    RotateApplication {
        #[arg(value_enum)]
        class: CredentialRotationClassArg,
        active_generation: u64,
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(crate) enum CloudflareTargetPlaneCommand {
    Inventory,
    Plan,
    Converge,
    ActiveConverge,
    Verify,
    VerifyActive,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CloudflareZeroTrustCommand {
    Doctor(SpecArgs),
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

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrTransportProofArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub agent_artifact_path: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrRunnerBootstrapArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub installer_path: PathBuf,
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
    TransportProof(VultrTransportProofArgs),
    RunnerBootstrap(VultrRunnerBootstrapArgs),
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
            Self::TransportProof(args) => vec![
                "transport-proof".to_owned(),
                path(args.spec_path),
                args.machine_id,
                path(args.agent_artifact_path),
            ],
            Self::RunnerBootstrap(args) => vec![
                "runner-bootstrap".to_owned(),
                path(args.spec_path),
                args.machine_id,
                path(args.installer_path),
            ],
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
            vec!["edge-orchestrator", "production", "diagnose"],
            vec!["edge-orchestrator", "credentials", "contract-verify"],
            vec![
                "edge-orchestrator",
                "credentials",
                "rotate-application",
                "tunnel-auth",
                "100",
                "101",
                "b",
            ],
            vec![
                "edge-orchestrator",
                "application-cleanup",
                "infra/application/disposable-acceptance.json",
                "infra/cloudflare/application-acceptance-dns.json",
                "infra/cloudflare/application-acceptance-mesh.json",
                "infra/vultr/application-acceptance-vpc.json",
            ],
            vec![
                "edge-orchestrator",
                "application-lifecycle",
                "materialize",
                "infra/application/disposable-acceptance.json",
                "artifact.json",
                "edge-agent",
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
                "transport-proof",
                "infra/vultr/production.json",
                "primary",
                "/tmp/edge-agent-linux-amd64",
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "runner-bootstrap",
                "infra/vultr/disposable-acceptance.json",
                "lifecycle-acceptance-1",
                "edge-platform/scripts/install-vultr-production-runner.sh",
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
