use clap::{Args, Parser, Subcommand, ValueEnum};
use edge_shared_types::{BootstrapMode, DeployRequest, DestroyRequest};
use std::env;
use std::net::SocketAddr;
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
    fn parses_local_controller_commands() {
        for args in [
            vec!["edge-controller", "get-status"],
            vec!["edge-controller", "start-local"],
            vec!["edge-controller", "stop-local"],
            vec!["edge-controller", "restart-local"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn rejects_provider_lifecycle_commands() {
        for command in [
            "application-lifecycle",
            "cloudflare-dns",
            "cloudflare-zero-trust",
            "line3-mesh",
            "vultr-lifecycle",
            "vultr-vpc",
        ] {
            assert!(Cli::try_parse_from(["edge-controller", command]).is_err());
        }
    }

    #[test]
    fn rejects_unknown_command_before_mutation() {
        assert!(Cli::try_parse_from(["edge-controller", "shell"]).is_err());
    }

    #[test]
    fn rejects_invalid_bootstrap_mode() {
        assert!(Cli::try_parse_from(["edge-controller", "bootstrap-runtime", "arbitrary"]).is_err());
    }
}
