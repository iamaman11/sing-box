use super::*;

/// Exactly one typed Host lifecycle dispatcher. Non-host/legacy commands have
/// no route to this module and cannot mutate via hidden CLI variants.
pub(super) async fn run(
    command: cli::HostCommand,
    hosts_pb: std::path::PathBuf,
    hosts_sha256: String,
    github_output: Option<std::path::PathBuf>,
    runner_inventory_json: Option<std::path::PathBuf>,
    source_comment_id: Option<u64>,
    intent_output: Option<std::path::PathBuf>,
    release_context: &edge_orchestrator::OrchestrationContext,
) -> Result<(), String> {
    match command {
        cli::HostCommand::VmWorkerAuthorizerUpgrade {
            machine_id,
            plan_only,
        } => {
            cloudflare_credential_plane_command::host_vm_worker_authorizer_upgrade(
                &machine_id,
                release_context,
                plan_only,
            )
            .await
        }
        cli::HostCommand::VmCredentialProof {
            machine_id,
            generation,
            bundle_sha256,
        } => {
            // Normal GET-only deep status uses the single Git-protected
            // pointer. Explicit values are retained solely for a candidate
            // read before Git pin; neither path authorizes CREATE.
            let (generation, sha256) = match (generation, bundle_sha256) {
                (None, None) => {
                    let host = release_context.verified_vm_first_use_host(&machine_id)?;
                    let pin = host
                        .vm_first_use_credential
                        .as_ref()
                        .ok_or("HOST_VM_FIRST_USE_CREDENTIAL_GIT_REQUIRED")?;
                    (pin.generation, pin.bundle_sha256.clone())
                }
                (Some(generation), Some(sha256)) => (generation, sha256),
                _ => return Err("HOST_VM_CREDENTIAL_PROOF_CANDIDATE_PAIR_REQUIRED".into()),
            };
            cloudflare_credential_plane_command::host_vm_credential_proof(
                &machine_id,
                release_context,
                generation,
                &sha256,
            )
            .await
        }
        cli::HostCommand::VmWorkerSignerPrepare {
            machine_id,
            key_path,
            public_path,
        } => {
            cloudflare_credential_plane_command::host_vm_signer_prepare(
                &machine_id,
                release_context,
                &key_path,
                &public_path,
            )
            .await
        }
        cli::HostCommand::VmWorkerSignerCommit {
            machine_id,
            key_path,
            public_path,
        } => {
            cloudflare_credential_plane_command::host_vm_signer_commit(
                &machine_id,
                release_context,
                &key_path,
                &public_path,
            )
            .await
        }
        cli::HostCommand::FirstUseScrub { machine_id } => {
            vultr_lifecycle_command::host_first_use_scrub(&machine_id, release_context).await
        }
        cli::HostCommand::FirstUsePreflight { machine_id } => {
            vultr_lifecycle_command::host_first_use_provider_preflight(&machine_id, release_context)
                .await
        }
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
    }
}
