use clap::{Parser, Subcommand};

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
    Local {
        #[command(subcommand)]
        command: LocalCommand,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
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
    /// One explicitly approved arbitrary root administrative request.
    HostAdmin,
    /// Signed public-only bootstrap recipient proof, no secret or mutation.
    HostBootstrapProof,
    /// One-shot root-only Access install from an encrypted protobuf on stdin.
    HostBootstrapAccess,
    /// Read-only unprivileged native probe from a typed same-run request on stdin.
    HostProbe,
    /// Refresh the exact protected main release from the installed root
    /// owner; no caller-selected SHA/path and no SSH.
    HostRefresh,
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
    MeshVerify,
    CredentialState,
    // Read-only Access-authenticated fixed A/B dummy proof for a fresh VM.
    CredentialInitialProbe,
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
            Self::HostAdmin => "local-host-admin",
            Self::HostBootstrapProof => "local-host-bootstrap-proof",
            Self::HostBootstrapAccess => "local-host-bootstrap-access",
            Self::HostProbe => "local-host-probe",
            Self::HostRefresh => "local-host-refresh",
            Self::HostEnroll { .. } => "local-host-enroll",
            Self::QualityLine2 => "local-quality-line2",
            Self::CredentialPublicEndpoint => "local-credential-public-endpoint",
            Self::CredentialRuntimeSource => "local-credential-runtime-source",
            Self::MeshVerify => "local-mesh-verify",
            Self::CredentialState => "local-credential-state",
            Self::CredentialInitialProbe => "local-credential-initial-probe",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn native_owner_exposes_signed_unrestricted_admin_without_runner_shell() {
        for op in [
            "status",
            "verify",
            "diagnose",
            "host-observe",
            "host-resources",
            "host-apply",
            "host-admin",
            "host-probe",
            "host-refresh",
            "quality-line2",
            "credential-public-endpoint",
            "credential-runtime-source",
            "mesh-verify",
            "credential-state",
            "credential-initial-probe",
        ] {
            assert!(
                Cli::try_parse_from(["edge-agent", "local", op]).is_ok(),
                "{op}"
            );
        }
        assert!(
            Cli::try_parse_from([
                "edge-agent",
                "local",
                "host-enroll",
                "acceptance-3",
                &"a".repeat(64)
            ])
            .is_ok()
        );
        for op in [
            "acceptance-serve",
            "serve",
            "bootstrap-base",
            "bootstrap-tunnel",
            "bootstrap-full",
            "bundle-converge",
            "bundle-stage-initial",
            "bundle-verify",
            "bundle-rollback",
            "mesh-cleanup",
            "credential-initial-attest",
            "credential-initial-apply",
            "credential-initial-verify",
            "credential-initial-commit",
            "credential-existing-join",
            "credential-stage",
            "credential-transition",
            "exec",
        ] {
            assert!(
                Cli::try_parse_from(["edge-agent", "local", op]).is_err(),
                "{op}"
            );
        }
        assert!(Cli::try_parse_from(["edge-agent", "acceptance-serve"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "local", "host-apply", "arbitrary"]).is_err());
        assert!(Cli::try_parse_from(["edge-agent", "local", "host-refresh", "sha"]).is_err());
    }
}
