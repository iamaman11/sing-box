use super::*;

pub(super) async fn run_local(command: cli::LocalCommand) -> Result<(), AgentError> {
    if !native_local_entrypoint_allowed(&command) {
        return Err(AgentError::Command(
            "HOST_VM_LEGACY_LOCAL_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT".to_owned(),
        ));
    }
    let stack_dir = PathBuf::from(DEFAULT_STACK_DIR);
    match command {
        cli::LocalCommand::Status { fast } => {
            if fast {
                return run_local_fast(&stack_dir).map_err(AgentError::Command);
            }
            let state = inspect_runtime(&stack_dir, AgentMode::Runtime).await;
            print_agent_state_evidence("STATUS", &state);
            println!("host_native_trust={}", host_native::local_trust_preflight());
            Ok(())
        }
        cli::LocalCommand::HostObserve => run_local_host_observe(&stack_dir)
            .await
            .map_err(AgentError::Command),
        cli::LocalCommand::HostResources => {
            let host = host_native::registered_vm_host().map_err(AgentError::Command)?;
            let report = docker_observation::observe_vm_resource_report(&host, &stack_dir)
                .await
                .map_err(AgentError::Command)?;
            io::stdout()
                .write_all(&report.encode_to_vec())
                .map_err(|_| AgentError::Command("HOST_RESOURCE_REPORT_STDOUT_FAILED".into()))
        }
        cli::LocalCommand::HostApply => host_native::apply(&stack_dir)
            .await
            .map_err(AgentError::Command),
        cli::LocalCommand::HostRefresh => host_enroll::refresh_current()
            .await
            .map_err(AgentError::Command),
        cli::LocalCommand::HostEnroll {
            machine_id,
            release_set_sha256,
        } => host_enroll::enroll(&machine_id, &release_set_sha256)
            .await
            .map_err(AgentError::Command),
        cli::LocalCommand::Verify => {
            let state = inspect_runtime(&stack_dir, AgentMode::Readiness).await;
            print_agent_state_evidence("VERIFY", &state);
            if state.ready {
                Ok(())
            } else {
                Err(AgentError::Command(
                    "local runtime verification did not reach READY".to_owned(),
                ))
            }
        }
        cli::LocalCommand::CredentialPublicEndpoint => {
            // This locator is read from the same kernel namespace as the
            // root-owned runtime, not from an operator or cloud API token.
            let observation = network_observation::observe_ipv4_network()
                .await
                .map_err(AgentError::Command)?;
            let ip = network_observation::unique_public_serving_ipv4(&observation)
                .map_err(AgentError::Command)?;
            println!("credential_vm_public_endpoint={ip}");
            println!("credential_endpoint_origin=VM_KERNEL_READ_ONLY");
            println!("credential_mutations=0");
            Ok(())
        }
        cli::LocalCommand::QualityLine2 => {
            line2_quality::measure(&stack_dir, read_typed_runtime_environment)
                .map(|_| ())
                .map_err(AgentError::Command)
        }
        cli::LocalCommand::CredentialRuntimeSource => attest_vm_running_config_source(&stack_dir)
            .await
            .map_err(AgentError::Command),
        cli::LocalCommand::Diagnose => {
            let state = inspect_runtime(&stack_dir, AgentMode::Runtime).await;
            print_agent_state_evidence("DIAGNOSE", &state);
            println!("host_native_trust={}", host_native::local_trust_preflight());
            let network = network_observation::observe_ipv4_network()
                .await
                .map_err(AgentError::Command)?;
            println!("network_link_count={}", network.links.len());
            println!("network_address_count={}", network.addresses.len());
            println!("network_route_count={}", network.routes.len());
            let mesh = inspect_mesh_runtime(&stack_dir, MeshDiagnosticDepth::Deep).await;
            print_mesh_state_evidence(&mesh);
            let credential_source = observe_vm_rendered_credential_source(&stack_dir);
            print_vm_rendered_credential_source(&credential_source);
            // Same typed, non-secret cursor assessment as Windows Fleet doctor.
            // A local A/B observation never closes a two-owner transaction.
            if let Ok(store_root) = vm_credential_store_root(&stack_dir) {
                let safety = edge_secrets::observe_credential_safety(
                    &store_root,
                    CredentialProjectionKind::Vm,
                );
                for line in safety.report_lines() {
                    println!("{line}");
                }
            } else {
                println!("credential_safety_state=UNKNOWN_NO_REPLAY");
                println!("credential_pair_terminal=UNPROVEN");
                println!("credential_replay_authorized=false");
                println!("credential_mutations=0");
            }
            println!(
                "application_operational_verdict={}",
                vm_application_operational_verdict(state.ready, &credential_source)
            );
            // The installed production runner already has a bounded sudo
            // allowlist for local diagnose. Do not expand it or bootstrap a
            // second owner just to observe live process-visible credentials.
            // General diagnose remains read-only and reports an unproven gate
            // instead of failing the entire VM inventory on missing evidence.
            if let Err(err) = attest_vm_running_config_source(&stack_dir).await {
                println!("credential_runtime_proof=UNPROVEN");
                println!("credential_runtime_proof_reason={err}");
            }
            Ok(())
        }
        cli::LocalCommand::BootstrapBase => {
            run_local_bootstrap(&stack_dir, BootstrapMode::BootstrapBase).await
        }
        cli::LocalCommand::BootstrapTunnel => {
            run_local_bootstrap(&stack_dir, BootstrapMode::BootstrapTunnel).await
        }
        cli::LocalCommand::BootstrapFull => {
            run_local_bootstrap(&stack_dir, BootstrapMode::BootstrapFull).await
        }
        cli::LocalCommand::BundleConverge => run_local_bundle_converge(&stack_dir).await,
        cli::LocalCommand::BundleStageInitial => run_local_bundle_stage_initial(&stack_dir).await,
        cli::LocalCommand::BundleVerify => run_local_bundle_verify(&stack_dir).await,
        cli::LocalCommand::BundleRollback => run_local_bundle_rollback(&stack_dir).await,
        cli::LocalCommand::MeshVerify => {
            let state = inspect_mesh_runtime(&stack_dir, MeshDiagnosticDepth::Deep).await;
            print_mesh_state_evidence(&state);
            if state.runtime_ready {
                Ok(())
            } else {
                Err(AgentError::Command(
                    "local Mesh runtime verification did not reach READY".to_owned(),
                ))
            }
        }
        cli::LocalCommand::MeshCleanup => {
            let state = cleanup_mesh_runtime(&stack_dir)
                .await
                .map_err(AgentError::Command)?;
            print_mesh_state_evidence(&state);
            Ok(())
        }
        cli::LocalCommand::CredentialState => {
            let state = observe_vm_credential_state(&stack_dir).map_err(AgentError::Command)?;
            print_credential_state_evidence(state.as_ref());
            let root = vm_credential_store_root(&stack_dir).map_err(AgentError::Command)?;
            if let Some(store) = CredentialStore::open_existing(root, CredentialProjectionKind::Vm)
                .map_err(AgentError::Command)?
            {
                let join = store
                    .read_existing_join_receipt()
                    .map_err(AgentError::Command)?;
                println!(
                    "credential_existing_join_receipt_present={}",
                    join.is_some()
                );
                if let Some(text) = join {
                    let intent = text
                        .lines()
                        .find_map(|line| line.strip_prefix("intent_sha256="))
                        .ok_or_else(|| {
                            AgentError::Command(
                                "existing join receipt missing intent digest; outcome UNKNOWN"
                                    .to_owned(),
                            )
                        })?;
                    println!("credential_existing_join_intent_sha256={intent}");
                } else {
                    println!("credential_existing_join_intent_sha256=ABSENT");
                }
                let receipt = store
                    .read_initial_pair_receipt()
                    .map_err(AgentError::Command)?;
                println!(
                    "credential_initial_commit_receipt_present={}",
                    receipt.is_some()
                );
                let recovery = store
                    .read_initial_pair_recovery_receipt()
                    .map_err(AgentError::Command)?;
                println!(
                    "credential_initial_recovery_receipt_present={}",
                    recovery.is_some()
                );
                if let Some(text) = recovery {
                    let digest = text
                        .lines()
                        .find_map(|line| line.strip_prefix("recovery_intent_sha256="))
                        .ok_or_else(|| {
                            AgentError::Command(
                                "initial VM recovery receipt missing digest".to_owned(),
                            )
                        })?;
                    println!("credential_initial_recovery_intent_sha256={digest}");
                }
                if let Some(text) = receipt {
                    let digest = text
                        .lines()
                        .find_map(|line| line.strip_prefix("intent_sha256="))
                        .ok_or_else(|| {
                            AgentError::Command(
                                "initial VM commit receipt missing digest".to_owned(),
                            )
                        })?;
                    println!("credential_initial_commit_intent_sha256={digest}");
                }
            } else {
                println!("credential_initial_commit_receipt_present=false");
                println!("credential_initial_recovery_receipt_present=false");
                println!("credential_existing_join_receipt_present=false");
                println!("credential_existing_join_intent_sha256=ABSENT");
            }
            // Existing root owner; a single authenticated read-only GET
            // proves the selected local projection without exporting secrets.
            // Failed/ambiguous evidence is never treated as migration authority.
            let role = match state.as_ref() {
                Some(cursor)
                    if cursor.active.is_none()
                        && cursor.candidate.is_some()
                        && cursor.previous.is_none() =>
                {
                    Some(CredentialOriginSelection::Candidate)
                }
                Some(cursor)
                    if cursor.active.is_some()
                        && cursor.candidate.is_none()
                        && cursor.previous.is_none() =>
                {
                    Some(CredentialOriginSelection::Active)
                }
                _ => None,
            };
            let exact = if let Some(role) = role {
                let root = vm_credential_store_root(&stack_dir).map_err(AgentError::Command)?;
                let identity =
                    vm_credential_access_identity_path(&stack_dir).map_err(AgentError::Command)?;
                attest_worker_credential_origin(
                    &root,
                    &identity,
                    CredentialProjectionKind::Vm,
                    role,
                )
                .await
                .is_ok()
            } else {
                false
            };
            println!(
                "credential_worker_origin={}",
                if exact { "WORKER_OK" } else { "UNPROVEN" }
            );
            Ok(())
        }
        cli::LocalCommand::CredentialInitialProbe => {
            verify_initial_vm_dummy_probe(&stack_dir)
                .await
                .map_err(AgentError::Command)?;
            println!("operation=CREDENTIAL_INITIAL_PROBE");
            println!("credential_projection=VM");
            println!("credential_slot_A=EXACT_DUMMY");
            println!("credential_slot_B=EXACT_DUMMY");
            println!("credential_store_present=false");
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            Ok(())
        }
        cli::LocalCommand::CredentialInitialAttest {
            generation,
            slot,
            provider_intent_sha256,
            release_set_sha256,
            expected_agent_sha256,
            run_id,
        } => {
            let slot = parse_first_use_slot(&slot).map_err(AgentError::Command)?;
            let (digest, proof) = attest_initial_vm_host(
                &stack_dir,
                generation,
                slot,
                &provider_intent_sha256,
                &release_set_sha256,
                &expected_agent_sha256,
                run_id,
            )
            .await
            .map_err(AgentError::Command)?;
            println!("operation=CREDENTIAL_INITIAL_ATTEST");
            println!("credential_projection=VM");
            println!("credential_generation={generation}");
            println!("credential_host_attestation_sha256={digest}");
            println!("credential_slot_A={}", proof.slot_a_observation);
            println!("credential_slot_B={}", proof.slot_b_observation);
            println!("credential_selected_slot_exact_dummy=true");
            println!("credential_github_run_id={run_id}");
            println!("credential_exact_agent_binary=true");
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            Ok(())
        }
        cli::LocalCommand::CredentialInitialVerify { generation } => {
            verify_initial_vm_credential_functional(&stack_dir, generation)
                .await
                .map_err(AgentError::Command)?;
            println!("operation=CREDENTIAL_INITIAL_VERIFY");
            println!("credential_generation={generation}");
            println!("credential_initial_state=APPLIED_NOT_PROMOTED");
            println!("line2_authenticated_endpoints=6");
            println!("line2_egress_identity=UNPROVEN");
            println!("external_tls_chain=UNPROVEN");
            println!("line1_authenticated_endpoints=UNPROVEN");
            println!("credential_pair_committed=false");
            println!("credential_runtime_mutations=0");
            Ok(())
        }
        cli::LocalCommand::CredentialInitialApply { generation } => {
            initial_apply_vm_credential(&stack_dir, generation)
                .await
                .map_err(AgentError::Command)?;
            println!("operation=CREDENTIAL_INITIAL_APPLY");
            println!("credential_projection=VM");
            println!("credential_generation={generation}");
            println!("credential_initial_state=APPLIED_NOT_PROMOTED");
            println!("credential_initial_authentication=UNPROVEN");
            println!("runner_secret_access=false");
            Ok(())
        }
        cli::LocalCommand::CredentialInitialCommit {
            generation,
            slot,
            intent_sha256,
        } => {
            // The protected GitHub caller must verify original BEGIN,
            // both prepared host origins and exactly-one COMMIT_INTENT before
            // this root-owned local first-use pointer mutation. The hash alone
            // is NOT authorization and no runtime restart/secret export occurs.
            initial_commit_vm_credential(&stack_dir, generation, slot, &intent_sha256)
                .await
                .map_err(AgentError::Command)?;
            println!("operation=CREDENTIAL_INITIAL_COMMIT");
            println!("credential_generation={generation}");
            println!("credential_slot={slot}");
            println!("credential_initial_pointer_commit=ACTIVE_LOCAL_ONLY");
            println!("credential_pair_committed=false");
            println!("runner_secret_access=false");
            Ok(())
        }
        cli::LocalCommand::CredentialExistingJoin {
            generation,
            slot,
            candidate_sha256,
            windows_active_generation,
            windows_active_slot,
            windows_active_sha256,
            windows_candidate_sha256,
            intent_sha256,
        } => {
            // Protected GitHub caller verifies the original Windows A owner and
            // exactly-one join intent. This local operation cannot infer either
            // authorization from user-supplied digests.
            verify_initial_vm_credential_functional(&stack_dir, generation)
                .await
                .map_err(AgentError::Command)?;
            let origin = attest_worker_credential_origin(
                &vm_credential_store_root(&stack_dir).map_err(AgentError::Command)?,
                &vm_credential_access_identity_path(&stack_dir).map_err(AgentError::Command)?,
                CredentialProjectionKind::Vm,
                CredentialOriginSelection::Candidate,
            )
            .await
            .map_err(AgentError::Command)?;
            let slot_name = match slot {
                1 => "A",
                2 => "B",
                _ => return Err(AgentError::Command("join VM slot invalid".to_owned())),
            };
            if origin.generation != generation
                || origin.slot != slot_name
                || origin.bundle_sha256 != candidate_sha256
            {
                return Err(AgentError::Command(
                    "existing-active join Worker origin differs from selected VM candidate"
                        .to_owned(),
                ));
            }
            let store = open_vm_credential_store(&stack_dir).map_err(AgentError::Command)?;
            let committed = store
                .promote_existing_active_join(
                    generation,
                    slot as i32,
                    &candidate_sha256,
                    windows_active_generation,
                    windows_active_slot as i32,
                    &windows_active_sha256,
                    &windows_candidate_sha256,
                    &intent_sha256,
                )
                .map_err(AgentError::Command)?;
            if committed.active.as_ref().map(|v| v.sha256.as_str())
                != Some(candidate_sha256.as_str())
                || committed.previous.is_some()
                || committed.candidate.is_some()
            {
                return Err(AgentError::Command(
                    "existing-active join pointer UNKNOWN; no replay".to_owned(),
                ));
            }
            println!("operation=CREDENTIAL_EXISTING_JOIN");
            println!("vm_credential_generation={generation}");
            println!("vm_credential_slot={slot}");
            println!("vm_credential_join=ACTIVE_LOCAL_ONLY");
            println!("windows_mutations=0");
            println!("credential_pair_committed=false");
            println!("credential_replay_authorized=false");
            Ok(())
        }
        cli::LocalCommand::CredentialStage { generation } => {
            let state = fetch_and_stage_vm_credential_candidate(&stack_dir, generation)
                .await
                .map_err(AgentError::Command)?;
            println!("operation=CREDENTIAL_STAGE");
            println!("credential_projection=VM");
            println!("credential_generation={generation}");
            println!("runner_secret_access=false");
            print_credential_state_evidence(Some(&state));
            Ok(())
        }
        cli::LocalCommand::CredentialTransition { action } => {
            let action =
                parse_credential_transition_action(&action).map_err(AgentError::Command)?;
            let state = transition_vm_credential(&stack_dir, action)
                .await
                .map_err(AgentError::Command)?;
            println!("operation=CREDENTIAL_TRANSITION");
            println!("credential_projection=VM");
            println!("credential_transition_action={}", action.as_str_name());
            println!("runner_secret_access=false");
            print_credential_state_evidence(state.as_ref());
            Ok(())
        }
    }
}
