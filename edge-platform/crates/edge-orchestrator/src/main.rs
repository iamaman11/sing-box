use std::process::ExitCode;

mod application_acceptance_command;
mod application_lifecycle_command;
mod application_lifecycle_service;
mod cli;
mod cloudflare_dns_lifecycle_command;
mod cloudflare_dns_lifecycle_service;
mod cloudflare_mesh_lifecycle_command;
mod cloudflare_mesh_lifecycle_service;
mod cloudflare_zero_trust_doctor;
mod cloudflare_zero_trust_lifecycle_command;
mod cloudflare_zero_trust_lifecycle_service;
mod vultr_host_bootstrap;
mod vultr_host_substrate_service;
mod vultr_lifecycle_adapter;
mod vultr_lifecycle_command;
mod vultr_lifecycle_service;
mod vultr_support_resources;
mod vultr_vpc_lifecycle_command;
mod vultr_vpc_lifecycle_service;

use clap::Parser;
use edge_observability::init as init_observability;

#[tokio::main]
async fn main() -> ExitCode {
    let telemetry = init_observability("edge-orchestrator");
    let parsed = match cli::Cli::try_parse() {
        Ok(parsed) => parsed,
        Err(err) => {
            let code = err.exit_code();
            let _ = err.print();
            return ExitCode::from(code as u8);
        }
    };
    let command = parsed.command_name();
    let release_context = match edge_orchestrator::OrchestrationContext::from_process_env() {
        Ok(context) => context,
        Err(err) => {
            tracing::error!(
                component = "edge-orchestrator",
                correlation_id = %telemetry.id(),
                command,
                event = "release_context.failure",
                "release context validation failed"
            );
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    tracing::info!(
        component = "edge-orchestrator",
        correlation_id = %telemetry.id(),
        command,
        release_set_sha256 = %release_context.release().release_set_sha256,
        source_revision = %release_context.release().source_revision,
        event = "release_context.accepted",
        "exact durable release context accepted"
    );
    tracing::info!(
        component = "edge-orchestrator",
        correlation_id = %telemetry.id(),
        command,
        event = "command.start",
        "command started"
    );

    match run(parsed, &release_context).await {
        Ok(()) => {
            tracing::info!(
                component = "edge-orchestrator",
                correlation_id = %telemetry.id(),
                command,
                event = "command.success",
                "command completed"
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(
                component = "edge-orchestrator",
                correlation_id = %telemetry.id(),
                command,
                event = "command.failure",
                "command failed"
            );
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

async fn run(
    parsed: cli::Cli,
    release_context: &edge_orchestrator::OrchestrationContext,
) -> Result<(), String> {
    use cli::Command;

    match parsed.command {
        Command::ApplicationAcceptance(args) => {
            application_acceptance_command::run(args, release_context).await
        }
        Command::ApplicationCleanup(args) => {
            application_acceptance_command::run_cleanup(args, release_context).await
        }
        Command::ApplicationLifecycle { command } => {
            application_lifecycle_command::run(command.into_legacy_args(), release_context).await
        }
        Command::CloudflareDns { command } => {
            cloudflare_dns_lifecycle_command::run(command.into_legacy_args()).await
        }
        Command::CloudflareZeroTrust { command } => {
            cloudflare_zero_trust_lifecycle_command::run(command.into_legacy_args()).await
        }
        Command::Line3Mesh { command } => {
            cloudflare_mesh_lifecycle_command::run(command.into_legacy_args()).await
        }
        Command::VultrLifecycle { command } => {
            vultr_lifecycle_command::run(command.into_legacy_args()).await
        }
        Command::VultrVpc { command } => {
            vultr_vpc_lifecycle_command::run(command.into_legacy_args()).await
        }
    }
}
