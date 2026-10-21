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
mod cloudflare_mesh_profile_command;
mod cloudflare_production_inventory;
mod cloudflare_target_plane_command;
mod cloudflare_zero_trust_doctor;
mod credential_existing_join;
mod credential_initial_journal;
mod host_command;
mod line2_external_witness;
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

// Only the host chain may mutate installed resources. Legacy domain modules
// stay compiled for release-input tests/read-only diagnostics, but their
// mutation commands have no CLI authority. Check before release-context load
// AND within run(): hiding a clap command alone is not a security boundary.
fn legacy_entrypoint_allowed(command: &cli::Command) -> bool {
    use cli::Command;
    match command {
        Command::Host { .. } | Command::ApplicationBundleBuild(_) => true,
        Command::CloudflareZeroTrust {
            command: cli::CloudflareZeroTrustCommand::Doctor(_),
        } => true,
        Command::CloudflareTargetPlane { command } => matches!(
            command,
            cli::CloudflareTargetPlaneCommand::Inventory
                | cli::CloudflareTargetPlaneCommand::Plan
                | cli::CloudflareTargetPlaneCommand::Verify
                | cli::CloudflareTargetPlaneCommand::VerifyActive
        ),
        Command::Production { command } => matches!(
            command,
            cli::ProductionCommand::Validate
                | cli::ProductionCommand::Diagnose
                | cli::ProductionCommand::DnsNoop
        ),
        Command::Credentials {
            command: cli::CredentialDeliveryCommand::ContractVerify,
        } => true,
        _ => false,
    }
}

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
    if !legacy_entrypoint_allowed(&parsed.command) {
        eprintln!("HOST_LEGACY_MUTATION_INGRESS_DISABLED_USE_HOST");
        return ExitCode::from(1);
    }
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

    // Defense in depth if run() is invoked without the top-level CLI gate.
    if !legacy_entrypoint_allowed(&parsed.command) {
        return Err("HOST_LEGACY_MUTATION_INGRESS_DISABLED_USE_HOST".to_owned());
    }
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
            cli::CloudflareTargetPlaneCommand::AcceptanceProfile { command } => {
                cloudflare_mesh_profile_command::run(command).await
            }
        },
        Command::CloudflareZeroTrust { command } => match command {
            cli::CloudflareZeroTrustCommand::Doctor(args) => {
                cloudflare_zero_trust_doctor::run(&args.spec_path, args.scope).await
            }
        },
        Command::Credentials { command } => {
            cloudflare_credential_plane_command::run_delivery(command, release_context).await
        }
        Command::Host {
            command,
            hosts_pb,
            hosts_sha256,
            github_output,
            runner_inventory_json,
            source_comment_id,
            intent_output,
        } => match command {
            cli::HostCommand::FirstUse {
                machine_id,
                installer_path,
                agent_path,
            } => {
                vultr_lifecycle_command::host_first_use(
                    &machine_id,
                    &installer_path,
                    &agent_path,
                    release_context,
                )
                .await
            }
            other => host_command::run(
                other,
                release_context,
                &hosts_pb,
                &hosts_sha256,
                github_output.as_deref(),
                runner_inventory_json.as_deref(),
                source_comment_id,
                intent_output.as_deref(),
            ),
        },
        Command::Production { command } => match command {
            cli::ProductionCommand::Validate => production_command::validate(release_context),
            cli::ProductionCommand::Diagnose => cloudflare_production_inventory::run().await,
            cli::ProductionCommand::DnsNoop => {
                production_command::verify_dns_noop(release_context).await
            }
            cli::ProductionCommand::EnrollRuntime(args) => {
                production_command::enroll_runtime(
                    release_context,
                    &args.edge_agent_artifact_path,
                    &args.runner_installer_path,
                )
                .await
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

#[cfg(test)]
mod canonical_host_ingress_tests {
    use super::*;
    use cli::{CloudflareTargetPlaneCommand as Cloudflare, ProductionCommand as Production};

    #[test]
    fn legacy_mutations_blocked_before_release_context_and_dispatch() {
        let blocked = [
            cli::Command::CloudflareTargetPlane {
                command: Cloudflare::Converge,
            },
            cli::Command::CloudflareTargetPlane {
                command: Cloudflare::ActiveConverge,
            },
            cli::Command::Production {
                command: Production::EnrollRuntime(cli::ProductionEnrollRuntimeArgs {
                    edge_agent_artifact_path: "agent".into(),
                    runner_installer_path: "runner".into(),
                }),
            },
            cli::Command::Credentials {
                command: cli::CredentialDeliveryCommand::HostBootstrapConverge,
            },
            cli::Command::VultrLifecycle {
                command: cli::VultrLifecycleCommand::Inventory(cli::SpecArgs {
                    spec_path: "spec".into(),
                }),
            },
        ];
        for cmd in &blocked {
            assert!(!legacy_entrypoint_allowed(cmd));
        }
        assert!(legacy_entrypoint_allowed(
            &cli::Command::CloudflareTargetPlane {
                command: Cloudflare::Inventory
            }
        ));
        assert!(legacy_entrypoint_allowed(&cli::Command::Production {
            command: Production::Diagnose
        }));
        assert!(legacy_entrypoint_allowed(&cli::Command::Credentials {
            command: cli::CredentialDeliveryCommand::ContractVerify
        }));
        assert!(legacy_entrypoint_allowed(&cli::Command::Host {
            hosts_pb: "hosts.pb".into(),
            hosts_sha256: "test".into(),
            github_output: None,
            runner_inventory_json: None,
            source_comment_id: None,
            intent_output: None,
            command: cli::HostCommand::Status {
                machine_id: None,
                deep: false,
                credential_pair_windows: None,
            },
        }));
    }
}
