use std::process::ExitCode;

mod application_acceptance_command;
mod application_lifecycle_command;
mod application_lifecycle_service;
mod cli;
mod cloudflare_credential_plane_command;
mod cloudflare_dns_lifecycle_command;
mod cloudflare_dns_lifecycle_service;
mod cloudflare_mesh_lifecycle_command;
mod cloudflare_mesh_lifecycle_service;
mod cloudflare_production_inventory;
mod cloudflare_target_plane_command;
mod cloudflare_zero_trust_doctor;
mod production_command;
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
    if let cli::Command::ApplicationBundleBuild(args) = &parsed.command {
        let result = application_lifecycle_command::build_candidate_application_bundle(
            &args.spec_path,
            &args.runtime_source_revision,
            &args.edge_agent_artifact_path,
            &args.edge_gateway_image,
            &args.edge_warp_egress_image,
            &args.mesh_image,
            &args.output_protobuf_path,
        );
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                tracing::error!(
                    component = "edge-orchestrator",
                    correlation_id = %telemetry.id(),
                    command,
                    event = "candidate_bundle.failure",
                    "candidate application bundle build failed"
                );
                eprintln!("{err}");
                ExitCode::from(1)
            }
        };
    }
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
        Command::ApplicationBundleBuild(_) => Err(
            "application-bundle-build must execute before durable runtime context resolution"
                .to_owned(),
        ),
        Command::ApplicationCleanup(args) => {
            application_acceptance_command::run_cleanup(args, release_context).await
        }
        Command::ApplicationLifecycle { command } => {
            application_lifecycle_command::run(command.into_legacy_args(), release_context).await
        }
        Command::CloudflareTargetPlane { command } => match command {
            cli::CloudflareTargetPlaneCommand::Inventory => {
                cloudflare_target_plane_command::inventory().await
            }
            cli::CloudflareTargetPlaneCommand::Plan => {
                cloudflare_target_plane_command::plan_command().await
            }
            cli::CloudflareTargetPlaneCommand::Converge => {
                cloudflare_target_plane_command::converge().await
            }
            cli::CloudflareTargetPlaneCommand::ActiveConverge => {
                cloudflare_target_plane_command::converge_active().await
            }
            cli::CloudflareTargetPlaneCommand::Verify => {
                cloudflare_target_plane_command::verify().await
            }
            cli::CloudflareTargetPlaneCommand::VerifyActive => {
                cloudflare_target_plane_command::verify_active_invariant().await
            }
        },
        Command::CloudflareZeroTrust { command } => match command {
            cli::CloudflareZeroTrustCommand::Doctor(args) => {
                cloudflare_zero_trust_doctor::run(&args.spec_path, args.scope).await
            }
        },
        Command::Credentials { command } => {
            cloudflare_credential_plane_command::run_delivery(command).await
        }
        Command::Production { command } => match command {
            cli::ProductionCommand::Validate => production_command::validate(release_context),
            cli::ProductionCommand::Diagnose => cloudflare_production_inventory::run().await,
            cli::ProductionCommand::EnrollRuntime(args) => {
                production_command::enroll_runtime(
                    release_context,
                    &args.edge_agent_artifact_path,
                    &args.runner_installer_path,
                )
                .await
            }
            cli::ProductionCommand::Converge(args) => {
                production_command::converge(release_context, &args.edge_agent_artifact_path).await
            }
            cli::ProductionCommand::Verify(args) => {
                production_command::verify(release_context, &args.edge_agent_artifact_path).await
            }
        },
        Command::VultrLifecycle { command } => {
            vultr_lifecycle_command::run(command.into_legacy_args(), release_context).await
        }
        Command::VultrVpc { command } => {
            vultr_vpc_lifecycle_command::run(command.into_legacy_args()).await
        }
    }
}
