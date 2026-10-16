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

impl DesiredApplicationArgs {
    fn into_legacy(self) -> Vec<String> {
        vec![
            "materialize".to_owned(),
            path(self.spec_path),
            path(self.artifact_manifest_path),
            path(self.edge_agent_artifact_path),
        ]
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum ApplicationLifecycleCommand {
    Materialize(DesiredApplicationArgs),
}

impl ApplicationLifecycleCommand {
    pub fn into_legacy_args(self) -> Vec<String> {
        match self {
            Self::Materialize(args) => args.into_legacy(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProductionCommand {
    Validate,
    Diagnose,
    // Internal read-only provider preflight used by the existing production workflow.
    // Never exposed as a new comment command or a DNS mutation authority.
    DnsNoop,
    EnrollRuntime(ProductionEnrollRuntimeArgs),
}

#[derive(Debug, Args, Clone)]
pub(crate) struct ProductionEnrollRuntimeArgs {
    pub edge_agent_artifact_path: PathBuf,
    pub runner_installer_path: PathBuf,
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

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum CredentialDeliveryCommand {
    ContractVerify,
    /// Bounded independent GitHub-runner vantage; public VM port probes only.
    InitialLine2ExternalWitness {
        generation: u64,
        vm_ipv4: String,
        tls_domain: String,
        username: String,
        vm_access_identity_path: std::path::PathBuf,
    },
    // One non-replayable, code-only migration of existing Workers; preserves
    // opaque A/B secret bindings and enables exact fixed-slot proof.
    // Restricted to the original first-use GitHub job and immutable ReleaseSet.
    InitialWorkerProofPlan {
        run_id: u64,
        journal_history_path: std::path::PathBuf,
        record_output_path: std::path::PathBuf,
    },
    InitialWorkerProofUpgrade {
        run_id: u64,
        journal_history_path: std::path::PathBuf,
        exact_record_path: std::path::PathBuf,
    },
    // Strictly read-only provider half of an initial paired transaction.
    InitialPairPreflight {
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
    },
    // Non-mutating plan; requires separately authenticated host evidence.
    // Never opens the Cloudflare write capability or commits the GitHub journal.
    // Read-only inspection of the complete GitHub Issue #26 attempt history.
    InitialPairJournalObserve {
        journal_history_path: std::path::PathBuf,
    },
    // Strictly read-only reconciliation AFTER durable GitHub comment write.
    InitialPairJournalReadback {
        journal_history_path: std::path::PathBuf,
        exact_record_path: std::path::PathBuf,
    },
    // Non-secret local policy ONLY: no Worker token, no GitHub POST, no
    // VM/Windows credential pointer mutation. The protected workflow must
    // separately authenticate each real host's prepared-state evidence.
    InitialPairCommitPlan {
        original_run_id: u64,
        commit_run_id: u64,
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
        vm_prepared_sha256: String,
        windows_prepared_sha256: String,
        journal_history_path: std::path::PathBuf,
        original_begin_path: std::path::PathBuf,
        record_output_path: std::path::PathBuf,
    },
    InitialPairCommitReadback {
        original_run_id: u64,
        commit_run_id: u64,
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
        vm_prepared_sha256: String,
        windows_prepared_sha256: String,
        journal_history_path: std::path::PathBuf,
        original_begin_path: std::path::PathBuf,
        exact_intent_path: std::path::PathBuf,
    },
    InitialPairCommitReconcile {
        original_run_id: u64,
        commit_run_id: u64,
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
        vm_prepared_sha256: String,
        windows_prepared_sha256: String,
        journal_history_path: std::path::PathBuf,
        original_begin_path: std::path::PathBuf,
        exact_intent_path: std::path::PathBuf,
        host_readback_path: std::path::PathBuf,
    },
    InitialPairJournalPlan {
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
        provider_intent_sha256: String,
        vm_attestation_sha256: String,
        windows_attestation_sha256: String,
        run_id: u64,
        journal_history_path: std::path::PathBuf,
        record_output_path: std::path::PathBuf,
    },
    // Single-use initial provider mutation, reachable only from the same-run
    // canonical VM installation workflow after BOTH authenticated host
    // origins and the exact durable GitHub BEGIN have been proven.
    InitialPairPublish {
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
        provider_intent_sha256: String,
        vm_attestation_sha256: String,
        windows_attestation_sha256: String,
        run_id: u64,
        journal_history_path: std::path::PathBuf,
        exact_record_path: std::path::PathBuf,
    },
    // Bounded independent Windows first-use host Access credential.
    // Mint once, publish only to GitHub's short-lived environment escrow,
    // then revoke on the exact same authorized run (including failure).
    InitialWindowsAcceptanceIssue {
        run_id: u64,
        private_output_path: std::path::PathBuf,
        token_id_output_path: std::path::PathBuf,
    },
    InitialWindowsAcceptanceCleanup {
        run_id: u64,
    },
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

#[derive(Debug, Subcommand)]
pub(crate) enum CloudflareTargetPlaneCommand {
    Inventory,
    Plan,
    Converge,
    ActiveConverge,
    Verify,
    VerifyActive,
    AcceptanceProfile {
        #[command(subcommand)]
        command: MeshProfileCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum CloudflareZeroTrustCommand {
    Doctor(ZeroTrustDoctorArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum MeshProfileCommand {
    Plan,
    Apply { authorized_plan_sha256: String },
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ZeroTrustReadinessScope {
    AndroidClient,
    VmServer,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct ZeroTrustDoctorArgs {
    pub spec_path: PathBuf,
    #[arg(long, value_enum, default_value = "android-client")]
    pub scope: ZeroTrustReadinessScope,
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
    pub local_owner_artifact_path: PathBuf,
}

// Immutable ReleaseSet owner installation is distinct from runner enrollment.
// Public Clap grammar must match the typed workflow, not merely the Rust dispatch.
#[derive(Debug, Args, Clone)]
pub(crate) struct VultrOwnerUpgradeArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub agent_artifact_path: PathBuf,
    pub observed_previous_sha256: String,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct VultrOwnerRollbackArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub observed_current_sha256: String,
    pub observed_previous_sha256: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum InitialVmCredentialSlotArg {
    A,
    B,
}
impl InitialVmCredentialSlotArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}
#[derive(Debug, Args, Clone)]
pub(crate) struct InitialVmDnsArgs {
    pub dns_spec_path: PathBuf,
    pub application_spec_path: PathBuf,
}
#[derive(Debug, Args, Clone)]
pub(crate) struct InitialVmPolicyArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub application_spec_path: PathBuf,
    pub agent_manifest_path: PathBuf,
    pub agent_artifact_path: PathBuf,
}
#[derive(Debug, Args, Clone)]
pub(crate) struct InitialVmHostProbeArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub generation: u64,
    #[arg(value_enum)]
    pub slot: InitialVmCredentialSlotArg,
    pub provider_intent_sha256: String,
    pub release_set_sha256: String,
    pub github_run_id: u64,
    pub agent_artifact_path: PathBuf,
}
#[derive(Debug, Args, Clone)]
pub(crate) struct InitialVmRuntimeArgs {
    pub spec_path: PathBuf,
    pub machine_id: String,
    pub generation: u64,
    pub release_set_sha256: String,
    pub github_run_id: u64,
    pub journal_history_path: PathBuf,
    pub exact_begin_path: PathBuf,
    pub agent_artifact_path: PathBuf,
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
    InitialDnsConverge(InitialVmDnsArgs),
    InitialPolicyStage(InitialVmPolicyArgs),
    InitialHostProbe(InitialVmHostProbeArgs),
    InitialRuntimeApply(InitialVmRuntimeArgs),
    InitialRuntimeVerify(InitialVmRuntimeArgs),
    RunnerBootstrap(VultrRunnerBootstrapArgs),
    OwnerUpgrade(VultrOwnerUpgradeArgs),
    OwnerRollback(VultrOwnerRollbackArgs),
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
            Self::InitialDnsConverge(args) => vec![
                "initial-dns-converge".to_owned(),
                path(args.dns_spec_path),
                path(args.application_spec_path),
            ],
            Self::InitialPolicyStage(args) => vec![
                "initial-policy-stage".to_owned(),
                path(args.spec_path),
                args.machine_id,
                path(args.application_spec_path),
                path(args.agent_manifest_path),
                path(args.agent_artifact_path),
            ],
            Self::InitialHostProbe(args) => vec![
                "initial-host-probe".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.generation.to_string(),
                args.slot.as_str().to_owned(),
                args.provider_intent_sha256,
                args.release_set_sha256,
                args.github_run_id.to_string(),
                path(args.agent_artifact_path),
            ],
            Self::InitialRuntimeApply(args) => initial_runtime_args("initial-runtime-apply", args),
            Self::InitialRuntimeVerify(args) => {
                initial_runtime_args("initial-runtime-verify", args)
            }
            Self::RunnerBootstrap(args) => vec![
                "runner-bootstrap".to_owned(),
                path(args.spec_path),
                args.machine_id,
                path(args.installer_path),
                path(args.local_owner_artifact_path),
            ],
            Self::OwnerUpgrade(args) => vec![
                "owner-upgrade".to_owned(),
                path(args.spec_path),
                args.machine_id,
                path(args.agent_artifact_path),
                args.observed_previous_sha256,
            ],
            Self::OwnerRollback(args) => vec![
                "owner-rollback".to_owned(),
                path(args.spec_path),
                args.machine_id,
                args.observed_current_sha256,
                args.observed_previous_sha256,
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

fn initial_runtime_args(operation: &str, args: InitialVmRuntimeArgs) -> Vec<String> {
    vec![
        operation.to_owned(),
        path(args.spec_path),
        args.machine_id,
        args.generation.to_string(),
        args.release_set_sha256,
        args.github_run_id.to_string(),
        path(args.journal_history_path),
        path(args.exact_begin_path),
        path(args.agent_artifact_path),
    ]
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
    fn owner_transition_workflow_commands_reach_exact_public_clap_dispatch() {
        let old = "b".repeat(64);
        let new = "a".repeat(64);
        let cases = [
            vec![
                "owner-upgrade",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "edge-agent-linux-amd64",
                &old,
            ],
            vec![
                "owner-rollback",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                &new,
                &old,
            ],
        ];
        for args in cases {
            let mut argv = vec!["edge-orchestrator", "vultr-lifecycle"];
            argv.extend(args.iter().copied());
            let parsed = Cli::try_parse_from(argv)
                .expect("every owner transition GitHub workflow command must reach public Clap");
            let Command::VultrLifecycle { command } = parsed.command else {
                panic!("expected Vultr lifecycle owner");
            };
            assert_eq!(command.into_legacy_args(), args);
        }
        for args in [
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "owner-upgrade",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "edge-agent-linux-amd64",
            ],
            vec![
                "edge-orchestrator",
                "vultr-lifecycle",
                "owner-rollback",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "old-hash",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn every_first_use_workflow_command_is_reachable_through_typed_cli() {
        // This is the public Clap entrypoint invoked by GitHub Actions. The
        // private native handler alone is not proof the binary accepts it.
        let cases = vec![
            vec![
                "initial-dns-converge",
                "infra/cloudflare/application-acceptance-dns.json",
                "infra/application/disposable-acceptance.json",
            ],
            vec![
                "initial-policy-stage",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "infra/application/disposable-acceptance.json",
                "policy.json",
                "edge-agent",
            ],
            vec![
                "initial-host-probe",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "101",
                "b",
                "intent",
                "release",
                "1234",
                "edge-agent",
            ],
            vec![
                "initial-runtime-apply",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "101",
                "release",
                "1234",
                "history.json",
                "exact-begin.txt",
                "edge-agent",
            ],
            vec![
                "initial-runtime-verify",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "101",
                "release",
                "1234",
                "history.json",
                "exact-begin.txt",
                "edge-agent",
            ],
        ];
        for args in cases {
            let mut argv = vec!["edge-orchestrator", "vultr-lifecycle"];
            argv.extend(&args);
            let parsed = Cli::try_parse_from(argv)
                .expect("first-use workflow must reach public typed orchestrator CLI");
            let Command::VultrLifecycle { command } = parsed.command else {
                panic!("expected exact Vultr lifecycle command owner");
            };
            let encoded = command.into_legacy_args();
            assert_eq!(encoded, args, "native argument order must not drift");
        }
        assert!(
            Cli::try_parse_from([
                "edge-orchestrator",
                "vultr-lifecycle",
                "initial-host-probe",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "101",
                "invalid-slot",
                "intent",
                "release",
                "1234",
                "edge-agent",
            ])
            .is_err(),
            "the initial credential slot must be a typed exact a/b"
        );
    }

    #[test]
    fn initial_pair_preflight_rejects_missing_or_invalid_parameters() {
        for args in [
            vec!["edge-orchestrator", "credentials", "initial-pair-preflight"],
            vec![
                "edge-orchestrator",
                "credentials",
                "initial-pair-preflight",
                "101",
            ],
            vec![
                "edge-orchestrator",
                "credentials",
                "initial-pair-preflight",
                "101",
                "other",
            ],
            vec![
                "edge-orchestrator",
                "credentials",
                "initial-pair-publish",
                "101",
                "a",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn parses_typed_orchestrator_commands() {
        let digest = "a".repeat(64);
        let cases = [
            vec!["edge-orchestrator", "production", "diagnose"],
            vec![
                "edge-orchestrator",
                "cloudflare-target-plane",
                "acceptance-profile",
                "plan",
            ],
            vec![
                "edge-orchestrator",
                "cloudflare-target-plane",
                "acceptance-profile",
                "verify",
            ],
            vec![
                "edge-orchestrator",
                "cloudflare-target-plane",
                "acceptance-profile",
                "apply",
                &digest,
            ],
            vec!["edge-orchestrator", "credentials", "contract-verify"],
            vec![
                "edge-orchestrator",
                "credentials",
                "initial-pair-preflight",
                "101",
                "a",
            ],
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
                "/tmp/edge-agent-linux-amd64",
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

        // The normal GitHub self-hosted runner bootstrap passes the exact
        // accepted local-owner artifact as a fourth positional argument.
        // Reject the historical three-argument CLI before provider mutation.
        assert!(
            Cli::try_parse_from([
                "edge-orchestrator",
                "vultr-lifecycle",
                "runner-bootstrap",
                "infra/vultr/application-acceptance.json",
                "application-acceptance-1",
                "edge-platform/scripts/install-vultr-production-runner.sh",
            ])
            .is_err()
        );

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
    fn rejects_retired_application_lifecycle_mutation_commands() {
        for operation in [
            "plan",
            "apply",
            "verify",
            "upgrade",
            "recover-plan",
            "recover-apply",
            "rollback-plan",
            "rollback-apply",
            "export-bundle",
        ] {
            assert!(
                Cli::try_parse_from(["edge-orchestrator", "application-lifecycle", operation])
                    .is_err(),
                "retired standalone application lifecycle command must stay absent: {operation}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_hosted_production_mutation_surface() {
        use clap::Parser;

        for operation in ["converge", "verify"] {
            assert!(
                Cli::try_parse_from(["edge-orchestrator", "production", operation, "agent.bin"])
                    .is_err(),
                "formerly valid direct hosted production operation must be absent: {operation}"
            );
        }
        assert!(Cli::try_parse_from(["edge-orchestrator", "production", "rollback"]).is_err());
        assert!(Cli::try_parse_from(["edge-orchestrator", "production", "dns-noop"]).is_ok());
    }

    #[test]
    fn rejects_unknown_command_before_mutation() {
        assert!(Cli::try_parse_from(["edge-orchestrator", "shell"]).is_err());
    }
}
