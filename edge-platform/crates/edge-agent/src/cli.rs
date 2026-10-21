use clap::{Args, Parser, Subcommand};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "edge-agent",
    version,
    about = "Bounded edge host runtime owner"
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
    AcceptanceServe(AcceptanceServeArgs),
    Local {
        #[command(subcommand)]
        command: LocalCommand,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::AcceptanceServe(_) => "acceptance-serve",
            Self::Local { command } => command.name(),
        }
    }
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum LocalCommand {
    Status {
        #[arg(long)]
        fast: bool,
    },
    Verify,
    Diagnose,
    /// Native read-only protobuf observation; not a mutation receipt.
    HostObserve,
    /// Read-only typed per-container Docker evidence from protected Git trust.
    HostResources,
    /// One native VM host transaction, with an exact protobuf intent on stdin.
    HostApply,
    /// First-use root-only trust enrollment. Never exposed by the runner sudoers.
    HostEnroll {
        machine_id: String,
        release_set_sha256: String,
    },
    QualityLine2,
    // Read-only unique public IPv4 observed on VM's live kernel interfaces.
    CredentialPublicEndpoint,
    // Read-only binding of Worker-v2 projection to actual running file mounts.
    CredentialRuntimeSource,
    BootstrapBase,
    BootstrapTunnel,
    BootstrapFull,
    BundleConverge,
    BundleStageInitial,
    BundleVerify,
    BundleRollback,
    MeshVerify,
    MeshCleanup,
    CredentialState,
    // Read-only Access-authenticated fixed A/B dummy proof for a fresh VM.
    CredentialInitialProbe,
    CredentialInitialAttest {
        generation: u64,
        slot: String,
        provider_intent_sha256: String,
        release_set_sha256: String,
        expected_agent_sha256: String,
        run_id: u64,
    },
    // Strictly fresh, non-serving VM only; never a rotation or legacy handoff.
    CredentialInitialApply {
        generation: u64,
    },
    // Authenticated Line2 proof of unpromoted exact first-use VM candidate.
    CredentialInitialVerify {
        generation: u64,
    },
    // First-use ONLY: protected two-host coordinator must have independently
    // proven and durably journalled one exact GitHub COMMIT_INTENT.
    CredentialInitialCommit {
        generation: u64,
        slot: u32,
        intent_sha256: String,
    },
    // Internal, GitHub-authorized existing Windows ACTIVE -> VM B join.
    CredentialExistingJoin {
        generation: u64,
        slot: u32,
        candidate_sha256: String,
        windows_active_generation: u64,
        windows_active_slot: u32,
        windows_active_sha256: String,
        windows_candidate_sha256: String,
        intent_sha256: String,
    },
    CredentialStage {
        generation: u64,
    },
    CredentialTransition {
        action: String,
    },
}

impl LocalCommand {
    fn name(&self) -> &'static str {
        match self {
            Self::Status { .. } => "local-status",
            Self::Verify => "local-verify",
            Self::Diagnose => "local-diagnose",
            Self::HostObserve => "local-host-observe",
            Self::HostResources => "local-host-resources",
            Self::HostApply => "local-host-apply",
            Self::HostEnroll { .. } => "local-host-enroll",
            Self::QualityLine2 => "local-quality-line2",
            Self::CredentialPublicEndpoint => "local-credential-public-endpoint",
            Self::CredentialRuntimeSource => "local-credential-runtime-source",
            Self::BootstrapBase => "local-bootstrap-base",
            Self::BootstrapTunnel => "local-bootstrap-tunnel",
            Self::BootstrapFull => "local-bootstrap-full",
            Self::BundleConverge => "local-bundle-converge",
            Self::BundleStageInitial => "local-bundle-stage-initial",
            Self::BundleVerify => "local-bundle-verify",
            Self::BundleRollback => "local-bundle-rollback",
            Self::MeshVerify => "local-mesh-verify",
            Self::MeshCleanup => "local-mesh-cleanup",
            Self::CredentialState => "local-credential-state",
            Self::CredentialInitialProbe => "local-credential-initial-probe",
            Self::CredentialInitialAttest { .. } => "local-credential-initial-attest",
            Self::CredentialInitialApply { .. } => "local-credential-initial-apply",
            Self::CredentialInitialVerify { .. } => "local-credential-initial-verify",
            Self::CredentialInitialCommit { .. } => "local-credential-initial-commit",
            Self::CredentialExistingJoin { .. } => "local-credential-existing-join",
            Self::CredentialStage { .. } => "local-credential-stage",
            Self::CredentialTransition { .. } => "local-credential-transition",
        }
    }
}

#[derive(Debug, Args, Default)]
pub(crate) struct AcceptanceServeArgs {
    pub addr: Option<SocketAddr>,
    pub stack_dir: Option<PathBuf>,
}

impl AcceptanceServeArgs {
    pub fn resolve(self) -> Result<(SocketAddr, PathBuf), String> {
        let addr = match self.addr {
            Some(addr) => addr,
            None => env::var("EDGE_AGENT_ADDR")
                .unwrap_or_else(|_| crate::DEFAULT_ACCEPTANCE_AGENT_ADDR.to_owned())
                .parse()
                .map_err(|err| format!("invalid EDGE_AGENT_ADDR: {err}"))?,
        };
        let stack_dir = self
            .stack_dir
            .or_else(|| env::var("EDGE_STACK_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(crate::DEFAULT_STACK_DIR));
        Ok((addr, stack_dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn agent_cli_is_closed() {
        assert!(Cli::try_parse_from(["edge-agent", "acceptance-serve"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "serve"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "local", "status", "--fast"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "status"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "verify"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "diagnose"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "host-observe"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "host-resources"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "host-resources", "stop"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "local", "host-apply"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "host-apply", "unsafe"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "local", "host-observe", "write"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "local", "quality-line2"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-runtime-source"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "bootstrap-base"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "bundle-converge"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "bundle-stage-initial"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "bundle-verify"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "bundle-rollback"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "mesh-cleanup"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-admit", "101"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-stage", "101"]).is_ok());
        assert!(
            Cli::try_parse_from(["edge-agent", "local", "credential-initial-verify", "101"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-initial-verify"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-initial-probe"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-initial-attest"]).is_err());
        assert!(
            Cli::try_parse_from([
                "edge-agent",
                "local",
                "credential-initial-attest",
                "101",
                "a",
                &"a".repeat(64),
                &"b".repeat(64),
                &"c".repeat(64),
                "1011",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["edge-agent", "local", "credential-initial-apply", "101"]).is_ok()
        );
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-initial-apply"]).is_err());
        assert!(
            Cli::try_parse_from(["edge-agent", "local", "credential-initial-promote", "101"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "edge-agent",
                "local",
                "credential-transition",
                "validate-candidate"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["edge-agent", "local", "exec"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "exec", "whoami"]).is_err());
    }
}
