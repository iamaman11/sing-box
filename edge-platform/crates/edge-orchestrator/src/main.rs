use std::process::ExitCode;

mod application_lifecycle_command;
mod application_lifecycle_service;
mod cli;
mod cloudflare_credential_plane_command;
mod cloudflare_dns_lifecycle_command;
mod cloudflare_dns_lifecycle_service;
mod cloudflare_mesh_lifecycle_service;
mod cloudflare_production_inventory;
mod cloudflare_target_plane_command;
mod cloudflare_zero_trust_doctor;
mod credential_existing_join;
mod credential_initial_journal;
mod host_command;
mod host_dispatch;
mod line2_external_witness;
mod production_command;
mod vm_host_desired;
mod vm_line2_acceptance;
mod vm_worker_begin_reconciliation;
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

    // Exhaustive CLI variants are the ingress boundary. Unreachable legacy
    // mutation commands are not defined as top-level CLI variants anymore.
    match parsed.command {
        Command::ApplicationBundleBuild(_) => Err(
            "application-bundle-build must execute before durable runtime context resolution"
                .to_owned(),
        ),
        Command::CloudflareTargetPlane { command } => match command {
            cli::CloudflareTargetPlaneCommand::Inventory => {
                cloudflare_target_plane_command::inventory().await
            }
            cli::CloudflareTargetPlaneCommand::Plan => {
                cloudflare_target_plane_command::plan_command().await
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
        Command::Credentials { command } => match command {
            cli::CredentialReadOnlyCommand::ContractVerify => {
                cloudflare_credential_plane_command::run_delivery(
                    cli::CredentialDeliveryCommand::ContractVerify,
                    release_context,
                )
                .await
            }
            cli::CredentialReadOnlyCommand::HostAccessObserve => {
                cloudflare_credential_plane_command::run_delivery(
                    cli::CredentialDeliveryCommand::HostAccessObserve,
                    release_context,
                )
                .await
            }
        },
        Command::Host {
            command,
            hosts_pb,
            hosts_sha256,
            github_output,
            runner_inventory_json,
            source_comment_id,
            intent_output,
        } => {
            host_dispatch::run(
                command,
                hosts_pb,
                hosts_sha256,
                github_output,
                runner_inventory_json,
                source_comment_id,
                intent_output,
                release_context,
            )
            .await
        }
        Command::Production { command } => match command {
            cli::ProductionCommand::Validate => production_command::validate(release_context),
            cli::ProductionCommand::Diagnose => cloudflare_production_inventory::run().await,
            cli::ProductionCommand::DnsNoop => {
                production_command::verify_dns_noop(release_context).await
            }
            cli::ProductionCommand::DnsReconcile { machine_id, apply } => {
                production_command::dns_reconcile(release_context, &machine_id, apply).await
            }
        },
    }
}

#[cfg(test)]
mod canonical_host_ingress_tests {
    use super::*;
    #[test]
    fn read_only_and_host_commands_are_the_only_cli_routes() {
        use clap::Parser;
        let required = [
            "edge-orchestrator",
            "host",
            "--hosts-pb",
            "hosts.pb",
            "--hosts-sha256",
        ];
        let mut status = required.to_vec();
        status.extend([
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "status",
            "application-acceptance-3",
            "--deep",
        ]);
        assert!(cli::Cli::try_parse_from(status).is_ok());
        for (command, argument) in [
            ("vultr-lifecycle", "inventory"),
            ("vultr-vpc", "verify"),
            ("application-lifecycle", "materialize"),
            ("application-acceptance", "--help"),
            ("application-cleanup", "--help"),
            ("credentials", "host-bootstrap-converge"),
            ("cloudflare-target-plane", "converge"),
            ("production", "enroll-runtime"),
        ] {
            assert!(
                cli::Cli::try_parse_from(["edge-orchestrator", command, argument]).is_err(),
                "legacy entrypoint must not be parseable: {command} {argument}"
            );
        }
        assert!(
            cli::Cli::try_parse_from(["edge-orchestrator", "credentials", "contract-verify"])
                .is_ok()
        );
        assert!(cli::Cli::try_parse_from(["edge-orchestrator", "production", "diagnose"]).is_ok());
    }
}
