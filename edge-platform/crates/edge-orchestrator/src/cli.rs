use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "edge-orchestrator",
    version,
    about = "Git-owned host lifecycle; legacy domain mutations disabled"
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
    #[command(hide = true)]
    ApplicationBundleBuild(ApplicationBundleBuildArgs),
    #[command(hide = true)]
    CloudflareTargetPlane {
        #[command(subcommand)]
        command: CloudflareTargetPlaneCommand,
    },
    #[command(hide = true)]
    CloudflareZeroTrust {
        #[command(subcommand)]
        command: CloudflareZeroTrustCommand,
    },
    #[command(hide = true)]
    Credentials {
        #[command(subcommand)]
        command: CredentialReadOnlyCommand,
    },
    Host {
        #[arg(long)]
        hosts_pb: PathBuf,
        #[arg(long)]
        hosts_sha256: String,
        #[arg(long)]
        github_output: Option<PathBuf>,
        #[arg(long)]
        runner_inventory_json: Option<PathBuf>,
        #[arg(long)]
        source_comment_id: Option<u64>,
        #[arg(long)]
        intent_output: Option<PathBuf>,
        #[command(subcommand)]
        command: HostCommand,
    },
    #[command(hide = true)]
    Production {
        #[command(subcommand)]
        command: ProductionCommand,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::ApplicationBundleBuild(_) => "application-bundle-build",
            Self::CloudflareTargetPlane { .. } => "cloudflare-target-plane",
            Self::CloudflareZeroTrust { .. } => "cloudflare-zero-trust",
            Self::Credentials { .. } => "credentials",
            Self::Host { .. } => "host",
            Self::Production { .. } => "production",
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum CredentialReadOnlyCommand {
    ContractVerify,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum HostCommand {
    /// All registered hosts, or the one machine selected by machine_id.
    Status {
        machine_id: Option<String>,
        #[arg(long)]
        deep: bool,
    },
    /// Bounded VM diagnostic, validated by Rust on both ends.
    Diagnose {
        machine_id: String,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Exact GitHub-approved native root program, encoded as base64url JSON argv.
    Admin {
        machine_id: String,
        argv_base64: String,
    },
    /// Hosted verification of an exact root-signed administrative receipt.
    #[command(hide = true)]
    AdminResult {
        machine_id: String,
        #[arg(long)]
        request_path: PathBuf,
        #[arg(long)]
        result_path: PathBuf,
    },
    /// Verify first-use public root proof before protected receipt merge.
    /// This is a signed *self-attestation*, not independent provider proof.
    #[command(hide = true)]
    BootstrapProofCheck {
        machine_id: String,
        #[arg(long)]
        proof_path: PathBuf,
    },
    /// Internal hosted-only seal of Access secrets for an exact Git-pinned
    /// signed native recipient. Reads plaintext from stdin, writes only
    /// encrypted protobuf to the supplied private artifact path.
    #[command(hide = true)]
    BootstrapSeal {
        machine_id: String,
        #[arg(long)]
        proof_path: PathBuf,
        #[arg(long)]
        output_path: PathBuf,
    },
    /// Internal read-only ingestion of a native protobuf observation.
    /// GitHub runner output is NOT independent proof of native owner identity.
    #[command(hide = true)]
    Readback {
        machine_id: String,
        #[arg(long)]
        observation_path: PathBuf,
        /// Internal, runner-copied VM diagnostic; never a native receipt.
        #[arg(long)]
        resources_path: Option<PathBuf>,
    },
    /// Internal-only correlation of two runner-copied protobufs. Neither
    /// artifact authenticates SYSTEM/root or promotes a physical receipt.
    #[command(hide = true)]
    NativeResult {
        machine_id: String,
        #[arg(long)]
        intent_path: PathBuf,
        #[arg(long)]
        result_path: PathBuf,
    },
    /// The same host apply operation may specify one exact signed config node.
    Apply {
        machine_id: String,
        #[arg(long)]
        resource_id: Option<String>,
    },
    /// One bounded fresh typed recovery preflight; never replays previous effects.
    Recover {
        machine_id: String,
        /// Explicitly finish the root-only Access handoff on an already-enrolled VM.
        /// No new VM, container or INSTALL execution is authorized.
        #[arg(long)]
        bootstrap_access: bool,
    },
    /// Internal, bounded public-key-only Git registration proposal. Never
    /// writes protected Git and never authorizes a native mutation.
    #[command(hide = true)]
    RegisterReceipt {
        machine_id: String,
        #[arg(long)]
        receipt_public_key_hex: String,
        #[arg(long)]
        output_path: PathBuf,
    },
    /// Verify the Git textproto -> Buf protobuf candidate changes ONLY the
    /// expected receipt public identity. Encoding byte order is irrelevant.
    #[command(hide = true)]
    VerifyReceipt {
        machine_id: String,
        #[arg(long)]
        receipt_public_key_hex: String,
        #[arg(long)]
        candidate_path: PathBuf,
    },
    /// Confirm a protected Git merge registers only the root public identity
    /// of a previously enrolled VM, without changing unrelated desired state.
    #[command(hide = true)]
    VerifyMergedReceipt {
        machine_id: String,
        #[arg(long)]
        previous_path: PathBuf,
    },
    /// Protected GET-only proof of an existing, journal-bound VM credential
    /// candidate. Never reads a secret from Cloudflare management APIs or
    /// authorizes VM CREATE. Output contains only nonsecret identity.
    #[command(hide = true)]
    VmCredentialProof {
        machine_id: String,
        /// Optional explicit candidate for a first-read; otherwise the
        /// exact public pointer comes from the accepted Git host registry.
        #[arg(long)]
        generation: Option<u64>,
        #[arg(long)]
        bundle_sha256: Option<String>,
    },
    /// Internal continuation of one authenticated /host apply: update only
    /// the existing VM Worker code, inheriting all existing secret bindings.
    /// It never writes credentials, authorizes VM CREATE, or touches Windows.
    #[command(hide = true)]
    VmWorkerAuthorizerUpgrade {
        machine_id: String,
        /// Internal GET-only admission before a durable provider BEGIN.
        #[arg(long)]
        plan_only: bool,
    },
    /// Internal protected-worker owner: prepare a single ephemeral Ed25519
    /// key; no provider mutation, public bytes only in a Git draft.
    #[command(hide = true)]
    VmWorkerSignerPrepare {
        machine_id: String,
        #[arg(long)]
        key_path: PathBuf,
        #[arg(long)]
        public_path: PathBuf,
    },
    /// Once the exact public-key Git draft is durably reserved, install the
    /// five fixed Host guards into the existing VM Worker, never Windows.
    #[command(hide = true)]
    VmWorkerSignerCommit {
        machine_id: String,
        #[arg(long)]
        key_path: PathBuf,
        #[arg(long)]
        public_path: PathBuf,
    },
    /// Re-decode a compiled Git textproto and verify EXACTLY one public
    /// signer key changed; code generator ordering is not an identity.
    #[command(hide = true)]
    VerifySigner {
        machine_id: String,
        #[arg(long)]
        signer_public_key_hex: String,
        #[arg(long)]
        candidate_path: PathBuf,
    },
    /// Internal Git candidate: change ONLY the selected VM public signer
    /// pin, without touching receipt, credentials or another host.
    #[command(hide = true)]
    RegisterSigner {
        machine_id: String,
        #[arg(long)]
        signer_public_key_hex: String,
        #[arg(long)]
        output_path: PathBuf,
    },
    /// Internal read-only Vultr provider plan before any Git receipt reservation.
    /// No VM/provider mutation and no alternate accepted desired.
    #[command(hide = true)]
    FirstUsePreflight { machine_id: String },
    /// Internal provider GET-proven user-data cleanup after native runner proof.
    #[command(hide = true)]
    FirstUseScrub { machine_id: String },
    /// Internal GitHub-hosted first-use of a new, absent VM. This shares
    /// the host ingress and existing Rust Vultr owner, never a legacy workflow.
    #[command(hide = true)]
    FirstUse {
        machine_id: String,
        #[arg(long)]
        installer_path: PathBuf,
        #[arg(long)]
        agent_path: PathBuf,
    },
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

#[derive(Debug, Subcommand)]
pub(crate) enum ProductionCommand {
    Validate,
    Diagnose,
    /// Bounded read-only Cloudflare/Vultr DNS preflight, not a mutation.
    DnsNoop,
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
    // Native read-only plan/readback for ONE durable existing-ACTIVE -> B
    // join. Never accepts credentials or grants mutation authority.
    ExistingJoinBeginPlan {
        spec_path: std::path::PathBuf,
        journal_history_path: std::path::PathBuf,
        record_output_path: std::path::PathBuf,
    },
    ExistingJoinBeginReadback {
        spec_path: std::path::PathBuf,
        journal_history_path: std::path::PathBuf,
        exact_record_path: std::path::PathBuf,
    },
    ExistingJoinPlan {
        spec_path: std::path::PathBuf,
        journal_history_path: std::path::PathBuf,
        record_output_path: std::path::PathBuf,
    },
    ExistingJoinReadback {
        spec_path: std::path::PathBuf,
        journal_history_path: std::path::PathBuf,
        exact_record_path: std::path::PathBuf,
    },
    // Existing native status/recover policy, read-only regardless of result.
    ExistingJoinJournalInspect {
        journal_history_path: std::path::PathBuf,
    },
    ExistingJoinReconcile {
        spec_path: std::path::PathBuf,
        journal_history_path: std::path::PathBuf,
        exact_record_path: std::path::PathBuf,
        snapshot_path: std::path::PathBuf,
    },
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
    // No provider, GitHub, or host mutation. A SECOND one-shot recovery
    // journal decision requires independently authenticated partial host
    // readback after the FIRST paired COMMIT_INTENT has already been recorded.
    InitialPairRecoveryPlan {
        original_run_id: u64,
        commit_run_id: u64,
        recovery_run_id: u64,
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
        vm_prepared_sha256: String,
        windows_prepared_sha256: String,
        vm_active_sha256: String,
        windows_candidate_sha256: String,
        journal_history_path: std::path::PathBuf,
        original_begin_path: std::path::PathBuf,
        original_intent_path: std::path::PathBuf,
        host_readback_path: std::path::PathBuf,
        recovery_output_path: std::path::PathBuf,
    },
    InitialPairRecoveryReadback {
        original_run_id: u64,
        commit_run_id: u64,
        recovery_run_id: u64,
        generation: u64,
        #[arg(value_enum)]
        slot: CredentialDeliverySlotArg,
        vm_prepared_sha256: String,
        windows_prepared_sha256: String,
        vm_active_sha256: String,
        windows_candidate_sha256: String,
        journal_history_path: std::path::PathBuf,
        original_begin_path: std::path::PathBuf,
        original_intent_path: std::path::PathBuf,
        host_readback_path: std::path::PathBuf,
        recovery_output_path: std::path::PathBuf,
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
    Verify,
    VerifyActive,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CloudflareZeroTrustCommand {
    Doctor(ZeroTrustDoctorArgs),
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn host_status_apply_recover_remain_parseable_and_bounded() {
        let base = [
            "edge-orchestrator",
            "host",
            "--hosts-pb",
            "registry.pb",
            "--hosts-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        for operation in ["status", "apply", "recover"] {
            let mut command = base.to_vec();
            command.push(operation);
            command.push("application-acceptance-3");
            assert!(Cli::try_parse_from(command).is_ok(), "{operation}");
        }
        let mut diagnostic = base.to_vec();
        diagnostic.extend([
            "diagnose",
            "application-acceptance-4",
            "--",
            "ip",
            "-6",
            "route",
            "show",
            "table",
            "all",
        ]);
        assert!(Cli::try_parse_from(diagnostic).is_ok());
        let mut batch = base.to_vec();
        batch.extend([
            "diagnose",
            "application-acceptance-4",
            "--",
            "ip",
            "-4",
            "address",
            "show",
            "--next",
            "ip",
            "-6",
            "route",
            "show",
            "table",
            "all",
            "--next",
            "ss",
            "-tln",
        ]);
        assert!(Cli::try_parse_from(batch).is_ok());
        let mut scoped = base.to_vec();
        scoped.extend([
            "apply",
            "application-acceptance-3",
            "--resource-id",
            "config/vultr-edge/line2-proxy",
        ]);
        assert!(Cli::try_parse_from(scoped).is_ok());
    }

    #[test]
    fn historical_provider_and_credential_mutations_are_not_public_or_hidden_cli() {
        for args in [
            vec!["edge-orchestrator", "vultr-lifecycle", "create"],
            vec!["edge-orchestrator", "vultr-vpc", "apply"],
            vec!["edge-orchestrator", "application-acceptance", "some-spec"],
            vec!["edge-orchestrator", "application-cleanup", "some-spec"],
            vec!["edge-orchestrator", "application-lifecycle", "materialize"],
            vec!["edge-orchestrator", "cloudflare-target-plane", "converge"],
            vec![
                "edge-orchestrator",
                "cloudflare-target-plane",
                "active-converge",
            ],
            vec![
                "edge-orchestrator",
                "credentials",
                "host-bootstrap-converge",
            ],
            vec![
                "edge-orchestrator",
                "credentials",
                "initial-pair-commit-plan",
            ],
            vec!["edge-orchestrator", "production", "enroll-runtime"],
            vec!["edge-orchestrator", "shell"],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_err(), "{args:?}");
        }
        assert!(
            Cli::try_parse_from(["edge-orchestrator", "credentials", "contract-verify"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["edge-orchestrator", "cloudflare-target-plane", "verify"]).is_ok()
        );
    }
}
