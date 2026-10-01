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
    Status,
    Verify,
    Diagnose,
    BootstrapBase,
    BootstrapTunnel,
    BootstrapFull,
    MeshVerify,
    MeshCleanup,
    CredentialState,
    CredentialAdmit { generation: u64 },
    CredentialStage { generation: u64 },
    CredentialTransition { action: String },
}

impl LocalCommand {
    fn name(&self) -> &'static str {
        match self {
            Self::Status => "local-status",
            Self::Verify => "local-verify",
            Self::Diagnose => "local-diagnose",
            Self::BootstrapBase => "local-bootstrap-base",
            Self::BootstrapTunnel => "local-bootstrap-tunnel",
            Self::BootstrapFull => "local-bootstrap-full",
            Self::MeshVerify => "local-mesh-verify",
            Self::MeshCleanup => "local-mesh-cleanup",
            Self::CredentialState => "local-credential-state",
            Self::CredentialAdmit { .. } => "local-credential-admit",
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
        assert!(Cli::try_parse_from(["edge-agent", "local", "status"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "verify"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "diagnose"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "bootstrap-base"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "mesh-cleanup"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-admit", "101"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "local", "credential-stage", "101"]).is_ok());
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
