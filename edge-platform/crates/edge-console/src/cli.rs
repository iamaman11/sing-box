use clap::{Args, Parser, Subcommand};
use std::env;

#[derive(Debug, Parser)]
#[command(
    name = "edge-console",
    version,
    about = "Typed local edge operator console"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    pub fn command_name(&self) -> &'static str {
        self.command.as_ref().map(Command::name).unwrap_or("menu")
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Menu(EndpointArgs),
    EnsureController(EndpointArgs),
    Reconcile(EndpointArgs),
    Status(EndpointArgs),
    Doctor(EndpointArgs),
    SmokeRuntime,
    Secrets(EndpointArgs),
    GetSecret(NameEndpointArgs),
    SetSecret(SetSecretArgs),
    StartLocal(EndpointArgs),
    StartLocalVisible(EndpointArgs),
    StopLocal(EndpointArgs),
    RestartLocal(EndpointArgs),
    RestartLocalVisible(EndpointArgs),
    GetSelector(EndpointArgs),
    GetUbuntuSelector(EndpointArgs),
    SetSelector(NameEndpointArgs),
    SetUbuntuSelector(NameEndpointArgs),
    Trace(EndpointArgs),
    TraceUbuntu(EndpointArgs),
    GetOperation(OperationEndpointArgs),
    WatchOperation(OperationEndpointArgs),
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Menu(_) => "menu",
            Self::EnsureController(_) => "ensure-controller",
            Self::Reconcile(_) => "reconcile",
            Self::Status(_) => "status",
            Self::Doctor(_) => "doctor",
            Self::SmokeRuntime => "smoke-runtime",
            Self::Secrets(_) => "secrets",
            Self::GetSecret(_) => "get-secret",
            Self::SetSecret(_) => "set-secret",
            Self::StartLocal(_) => "start-local",
            Self::StartLocalVisible(_) => "start-local-visible",
            Self::StopLocal(_) => "stop-local",
            Self::RestartLocal(_) => "restart-local",
            Self::RestartLocalVisible(_) => "restart-local-visible",
            Self::GetSelector(_) => "get-selector",
            Self::GetUbuntuSelector(_) => "get-ubuntu-selector",
            Self::SetSelector(_) => "set-selector",
            Self::SetUbuntuSelector(_) => "set-ubuntu-selector",
            Self::Trace(_) => "trace",
            Self::TraceUbuntu(_) => "trace-ubuntu",
            Self::GetOperation(_) => "get-operation",
            Self::WatchOperation(_) => "watch-operation",
        }
    }
}

#[derive(Debug, Args, Default)]
pub(crate) struct EndpointArgs {
    pub endpoint: Option<String>,
}

impl EndpointArgs {
    pub fn resolve(self) -> String {
        controller_endpoint(self.endpoint)
    }
}

#[derive(Debug, Args)]
pub(crate) struct NameEndpointArgs {
    pub name: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SetSecretArgs {
    pub name: String,
    pub secret_ref: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct OperationEndpointArgs {
    pub operation_id: i64,
    pub endpoint: Option<String>,
}

pub(crate) fn controller_endpoint(value: Option<String>) -> String {
    value
        .and_then(non_blank)
        .or_else(|| {
            env::var("EDGE_CONTROLLER_ENDPOINT")
                .ok()
                .and_then(non_blank)
        })
        .unwrap_or_else(|| crate::DEFAULT_CONTROLLER_ENDPOINT.to_owned())
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
    fn parses_installed_automation_commands() {
        assert!(Cli::try_parse_from(["edge-console", "ensure-controller"]).is_ok());
        assert!(Cli::try_parse_from(["edge-console", "reconcile"]).is_ok());
        assert!(Cli::try_parse_from(["edge-console", "smoke-runtime"]).is_ok());
    }

    #[test]
    fn parses_operation_id_as_typed_integer() {
        let cli = Cli::try_parse_from(["edge-console", "get-operation", "42"]).unwrap();
        assert_eq!(cli.command_name(), "get-operation");
    }

    #[test]
    fn rejects_unknown_console_command() {
        assert!(Cli::try_parse_from(["edge-console", "powershell"]).is_err());
    }
}
