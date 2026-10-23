use super::*;

pub(super) async fn run(parsed: cli::Cli) -> Result<(), ConsoleError> {
    use cli::Command;

    if parsed
        .command
        .as_ref()
        .is_none_or(|command| !legacy_console_entrypoint_allowed(command))
    {
        return Err(ConsoleError::Command(
            "HOST_WINDOWS_LEGACY_CONSOLE_MUTATION_DISABLED_USE_HOST".to_owned(),
        ));
    }
    match parsed
        .command
        .unwrap_or_else(|| Command::Menu(cli::EndpointArgs::default()))
    {
        Command::Menu(args) => {
            run_menu(args.resolve()).await?;
            Ok(())
        }
        Command::EnsureController(args) => {
            ensure_controller_running(&args.resolve())?;
            println!("status=PASS");
            println!("controller_start_owner=windows_scm");
            println!("activation_authority=current.pb");
            Ok(())
        }
        Command::Reconcile(args) => {
            reconcile_installed_runtime(args.resolve()).await?;
            Ok(())
        }
        Command::Status(args) => {
            let status = fetch_status(args.resolve()).await?;
            print_status(&status);
            Ok(())
        }
        Command::Doctor(args) => {
            let doctor = fetch_doctor(args.resolve()).await?;
            print_doctor(&doctor);
            if doctor.ok {
                Ok(())
            } else {
                Err(ConsoleError::Command(
                    "doctor reported failing checks".to_owned(),
                ))
            }
        }
        Command::CredentialInitialProbe(args) => {
            run_windows_initial_credential_probe(Path::new(&args.install_root))
                .await
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::CredentialInitialAttest(args) => {
            let root = Path::new(&args.install_root);
            require_initial_windows_credential_host(root).map_err(ConsoleError::Command)?;
            let activation = load_verified_activation(root).map_err(|err| {
                ConsoleError::Command(format!(
                    "Windows first-use attestation release is unverified: {err}"
                ))
            })?;
            if activation.release_set_sha256 != args.release_set_sha256 {
                return Err(ConsoleError::Command(
                    "Windows first-use attestation refuses a different local ReleaseSet".to_owned(),
                ));
            }
            let slot = match args.slot.as_str() {
                "a" => edge_shared_types::CredentialDeliverySlot::A,
                "b" => edge_shared_types::CredentialDeliverySlot::B,
                _ => {
                    return Err(ConsoleError::Command(
                        "initial slot must be a or b".to_owned(),
                    ));
                }
            };
            let proof = verify_initial_selected_dummy_slot(
                edge_shared_types::CredentialProjectionKind::Windows,
                slot,
                &root
                    .join("state")
                    .join("secrets")
                    .join(ACCESS_IDENTITY_FILE_NAME),
            )
            .await
            .map_err(ConsoleError::Command)?;
            let machine = env::var("COMPUTERNAME").map_err(|_| {
                ConsoleError::Command("Windows machine identity unavailable".to_owned())
            })?;
            let digest = edge_shared_types::first_use_host_attestation_sha256(
                edge_shared_types::CredentialProjectionKind::Windows,
                args.generation,
                slot,
                &args.provider_intent_sha256,
                &args.release_set_sha256,
                &machine,
                args.run_id,
            )
            .map_err(ConsoleError::Command)?;
            println!("operation=CREDENTIAL_INITIAL_ATTEST");
            println!("credential_projection=WINDOWS");
            println!("credential_generation={}", args.generation);
            println!("credential_host_attestation_sha256={digest}");
            println!("credential_slot_A={}", proof.slot_a_observation);
            println!("credential_slot_B={}", proof.slot_b_observation);
            println!("credential_selected_slot_exact_dummy=true");
            println!("credential_github_run_id={}", args.run_id);
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            println!("windows_tun_mutations=0");
            println!("windows_dns_mutations=0");
            Ok(())
        }
        Command::CredentialInitialAcceptanceBootstrap(args) => {
            let root = Path::new(&args.install_root);
            load_verified_activation(root).map_err(|err| {
                ConsoleError::Command(format!("isolated Windows release unverified: {err}"))
            })?;
            initial_line1_witness::bootstrap_access(root).map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::CredentialInitialAcceptanceStage(args) => {
            let root = Path::new(&args.install_root);
            load_verified_activation(root).map_err(|err| {
                ConsoleError::Command(format!("isolated Windows release unverified: {err}"))
            })?;
            initial_line1_witness::stage_from_worker(root, args.generation)
                .await
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::CredentialInitialLine1Witness(args) => {
            let root = Path::new(&args.install_root);
            let activation = load_verified_activation(root).map_err(|err| {
                ConsoleError::Command(format!("Line1 witness release is unverified: {err}"))
            })?;
            initial_line1_witness::run(
                root,
                Path::new(&activation.sing_box_path),
                args.generation,
                args.target_ipv4,
                &args.target_domain,
            )
            .map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::CredentialExistingLine1Witness(args) => {
            #[cfg(windows)]
            {
                let root = Path::new(&args.install_root);
                initial_line1_witness::require_isolated_root(root)
                    .map_err(ConsoleError::Command)?;
                if args.windows_candidate_sha256.len() != 64
                    || !args
                        .windows_candidate_sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(ConsoleError::Command(
                        "existing B witness requires exact Windows candidate SHA-256".to_owned(),
                    ));
                }
                let isolated = load_verified_activation(root)?;
                let serving = Path::new(r"C:\sing-box");
                let serving_release = load_verified_activation(serving)?;
                if isolated.release_set_sha256 != serving_release.release_set_sha256 {
                    return Err(ConsoleError::Command(
                        "isolated Line1 witness ReleaseSet differs from serving SYSTEM release"
                            .to_owned(),
                    ));
                }
                require_stopped_proxy_only_initial_commit_owner(serving)
                    .map_err(ConsoleError::Command)?;
                let before = existing_line1_serving_candidate(
                    serving,
                    args.generation,
                    &args.windows_candidate_sha256,
                )
                .map_err(ConsoleError::Command)?;
                let store = windows_credential_store_path(root);
                let identity = root
                    .join("state")
                    .join("secrets")
                    .join(ACCESS_IDENTITY_FILE_NAME);
                let worker = attest_worker_credential_origin(
                    &store,
                    &identity,
                    edge_shared_types::CredentialProjectionKind::Windows,
                    CredentialOriginSelection::Candidate,
                )
                .await
                .map_err(ConsoleError::Command)?;
                if worker.generation != args.generation
                    || worker.slot != "B"
                    || worker.bundle_sha256 != args.windows_candidate_sha256
                {
                    return Err(ConsoleError::Command(
                        "isolated Windows B differs from serving SYSTEM candidate".to_owned(),
                    ));
                }
                // Reuse the existing bounded transient witness; never use
                // serving C:\sing-box as a disposable sing-box install root.
                initial_line1_witness::run(
                    root,
                    Path::new(&isolated.sing_box_path),
                    args.generation,
                    args.target_ipv4,
                    &args.target_domain,
                )
                .map_err(ConsoleError::Command)?;
                require_stopped_proxy_only_initial_commit_owner(serving)
                    .map_err(ConsoleError::Command)?;
                if existing_line1_serving_candidate(
                    serving,
                    args.generation,
                    &args.windows_candidate_sha256,
                )
                .map_err(ConsoleError::Command)?
                    != before
                {
                    return Err(ConsoleError::Command(
                        "serving SYSTEM A/B changed during isolated Line1 witness".to_owned(),
                    ));
                }
                let after = attest_worker_credential_origin(
                    &store,
                    &identity,
                    edge_shared_types::CredentialProjectionKind::Windows,
                    CredentialOriginSelection::Candidate,
                )
                .await
                .map_err(ConsoleError::Command)?;
                if after != worker {
                    return Err(ConsoleError::Command(
                        "isolated B Worker origin drifted during physical witness".to_owned(),
                    ));
                }
                println!("existing_join_begin_sha256={before}");
                println!("existing_join_line1_external_4_of_4=PASS");
                println!("existing_join_windows_b_worker_exact=true");
                println!("existing_join_windows_system_stopped_proxyonly=true");
                println!(
                    "existing_join_candidate_sha256={}",
                    args.windows_candidate_sha256
                );
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = args;
                Err(ConsoleError::Command(
                    "existing B physical Line1 witness requires Windows".to_owned(),
                ))
            }
        }
        Command::CredentialState(args) => {
            let state = fetch_credential_state(args.resolve()).await?;
            print_windows_credential_state(state.as_ref());
            Ok(())
        }
        Command::SmokeRuntime => {
            let install_root = installed_root_from_console()?;
            let activation = load_verified_activation(&install_root)?;
            let result = run_non_tun_loopback_smoke(
                Path::new(&activation.sing_box_path),
                &install_root.join("runtime"),
            )?;
            println!("status=PASS");
            println!("mode=NON_TUN_LOOPBACK");
            println!("release_set_sha256={}", activation.release_set_sha256);
            println!("sing_box_path={}", activation.sing_box_path);
            println!("sing_box_pid={}", result.singbox_pid);
            println!("proxy_port={}", result.proxy_port);
            println!("origin_port={}", result.origin_port);
            println!("proxy_round_trip=PASS");
            println!("tun_enabled=false");
            println!("system_proxy_mutated=false");
            println!("dns_mutated=false");
            println!("routes_mutated=false");
            println!("cleanup=PASS");
            Ok(())
        }
        Command::Stage2Preflight => {
            let install_root = installed_root_from_console()?;
            verify_stage2_isolated_prerequisites(&install_root).map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("stage2_proxy_ports=AVAILABLE");
            println!("stage2_desktop_proxy_port={STAGE2_DESKTOP_PROXY_PORT}");
            println!("stage2_wsl_proxy_port={STAGE2_WSL_PROXY_PORT}");
            println!("stage2_clash_api_port={STAGE2_CLASH_API_PORT}");
            println!("tun_enabled=false");
            Ok(())
        }
        Command::ProvisionRuntimeState(args) => {
            provision_windows_runtime_state(Path::new(&args.install_root))?;
            Ok(())
        }
        Command::PrivilegedPing(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::Ping as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedRuntimeEvidence(args) => {
            let install_root = PathBuf::from(args.install_root);
            let request_id = new_privileged_request_id()?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: request_id.clone(),
                    operation: WindowsPrivilegedOperation::RuntimeEvidence as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            );
            let result = match result {
                Ok(value) => value,
                Err(_) => {
                    // A client-side exchange error has no verified SYSTEM
                    // result. Report this exact request ID without exposing
                    // transport errors or claiming that the operation failed.
                    print!("{}", unproven_runtime_evidence(&request_id));
                    return Err(ConsoleError::Command(
                        "RUNTIME_EVIDENCE_EXCHANGE_UNPROVEN".to_owned(),
                    ));
                }
            };
            if result.success {
                print_privileged_result(&result);
            } else {
                // SYSTEM may have recorded an error containing private paths
                // or secret material. The opaque native result stays on the
                // owner; only a stable reason code crosses this boundary.
                println!("status=FAIL");
                println!("request_id={}", result.request_id);
                println!("code={}", result.code);
                println!("error_class=RUNTIME_EVIDENCE_COLLECTION_FAILED");
                println!("detail=WITHHELD_PRIVATE_NATIVE_RESULT");
            }
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedActivate(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::ActivateRelease as i32,
                    accepted_revision: Some(args.accepted_revision),
                    release_set_sha256: Some(args.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineBootstrap(args) => {
            let install_root = PathBuf::from(args.install_root);
            let request = WindowsPrivilegedRequest {
                schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                request_id: new_privileged_request_id()?,
                operation: WindowsPrivilegedOperation::OfflineActivateRelease as i32,
                accepted_revision: Some(args.accepted_revision),
                release_set_sha256: Some(args.release_set_sha256),
                credential_generation: None,
                credential_transition_action: None,
                initial_commit_intent_sha256: None,
                initial_commit_slot: None,
                initial_recovery_intent_sha256: None,
                initial_candidate_sha256: None,
                existing_join_vm_candidate_sha256: None,
                existing_join_windows_active_sha256: None,
                existing_join_windows_candidate_sha256: None,
                existing_join_intent_sha256: None,
                existing_join_slot: None,
            };
            let (code, detail, release) =
                offline_bootstrap_privileged_release(&install_root, &request)
                    .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("code={code}");
            println!("detail={detail}");
            if let Some(release) = release {
                println!("active_release_set_sha256={release}");
            }
            Ok(())
        }
        Command::PrivilegedOfflineActivate(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::OfflineActivateRelease as i32,
                    accepted_revision: Some(args.accepted_revision),
                    release_set_sha256: Some(args.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedOfflineRollbackPrevious(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let (current, previous) = load_previous_release_rollback_pair(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::OfflineRollbackPreviousRelease as i32,
                    accepted_revision: Some(current.source_revision),
                    release_set_sha256: Some(previous.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedRollbackPrevious(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let (current, previous) = load_previous_release_rollback_pair(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::RollbackPreviousRelease as i32,
                    accepted_revision: Some(current.source_revision),
                    release_set_sha256: Some(previous.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedReinstallAccepted(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::ReinstallAcceptedRelease as i32,
                    accepted_revision: Some(args.accepted_revision),
                    release_set_sha256: Some(args.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedRestartControllerService(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::RestartControllerService as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedStartProxyOnlyController(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::StartProxyOnlyController as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedStopProxyOnlyController(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::StopProxyOnlyController as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedStageCredential(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::StageCredential as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: Some(args.generation),
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedInitialCredentialCommit(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::InitialCredentialCommit as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: Some(args.generation),
                    credential_transition_action: None,
                    initial_commit_intent_sha256: Some(args.intent_sha256),
                    initial_commit_slot: Some(args.slot),
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedInitialCredentialRecover(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::InitialCredentialRecover as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: Some(args.generation),
                    credential_transition_action: None,
                    initial_commit_intent_sha256: Some(args.original_intent_sha256),
                    initial_commit_slot: Some(args.slot),
                    initial_recovery_intent_sha256: Some(args.recovery_intent_sha256),
                    initial_candidate_sha256: Some(args.candidate_sha256),
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedExistingPrepare(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::ExistingCredentialPrepare as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: Some(args.generation),
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: Some(args.vm_candidate_sha256),
                    existing_join_windows_active_sha256: Some(args.windows_active_sha256),
                    existing_join_windows_candidate_sha256: Some(args.windows_candidate_sha256),
                    existing_join_intent_sha256: Some(args.begin_sha256),
                    existing_join_slot: Some(args.slot),
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedExistingJoin(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::ExistingCredentialJoin as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: Some(args.generation),
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: Some(args.vm_candidate_sha256),
                    existing_join_windows_active_sha256: Some(args.windows_active_sha256),
                    existing_join_windows_candidate_sha256: Some(args.windows_candidate_sha256),
                    existing_join_intent_sha256: Some(args.intent_sha256),
                    existing_join_slot: Some(args.slot),
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::CredentialTransition(args) => {
            let action = parse_credential_transition_action(&args.action)?;
            run_windows_credential_transition(Path::new(&args.install_root), action)
                .await
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::RestartVerifyRuntime => {
            let endpoint = cli::controller_endpoint(None);
            restart_and_verify_windows_tunnels(&endpoint)
                .await
                .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("runtime_restart_functional=PASS");
            println!("runtime_restart_direct=PASS");
            println!("runtime_restart_warp=PASS");
            Ok(())
        }
        Command::VerifyRuntime => {
            let endpoint = cli::controller_endpoint(None);
            verify_windows_tunnels(&endpoint)
                .await
                .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("runtime_functional=PASS");
            println!("runtime_direct=PASS");
            println!("runtime_warp=PASS");
            Ok(())
        }
        Command::QualityLine1 => {
            let install_root = installed_root_from_console()?;
            let active = load_verified_activation(&install_root)?;
            let installed_console = Path::new(&active.console_path)
                .canonicalize()
                .map_err(|err| format!("Line1 quality cannot verify active console path: {err}"))?;
            let invoked_console = env::current_exe()
                .and_then(|path| path.canonicalize())
                .map_err(|err| {
                    format!("Line1 quality cannot verify invoked console path: {err}")
                })?;
            if installed_console != invoked_console {
                return Err("Line1 quality requires the exact active installed console".into());
            }
            let desired = canonical_production_desired_state()?;
            if desired.windows_datapath_mode != WindowsDatapathMode::ManagedTun as i32 {
                return Err("Line1 quality requires the accepted ManagedTun mode".into());
            }
            let clash = format!("http://127.0.0.1:{STAGE2_CLASH_API_PORT}");
            let report = edge_clash::measure_line1_quality(&clash).await?;
            let observed_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| format!("Line1 quality cannot timestamp observation: {err}"))?
                .as_secs();
            println!("quality_schema=line1-native-delay/v1");
            println!("vantage=WINDOWS");
            println!("observed_at_unix_seconds={observed_at}");
            println!("release_set_sha256={}", active.release_set_sha256);
            println!("probe=sing-box-native-clash-named-outbound-delay");
            println!("metric=HTTPS_URL_TEST_DELAY_ONLY");
            println!(
                "sample_budget_per_outbound={}",
                edge_clash::LINE1_QUALITY_SAMPLES
            );
            println!("selector_mutations=0");
            println!("tunnel_mutations=0");
            println!("selector_before_after=IDENTICAL");
            let mut failures = 0;
            for row in report.rows {
                failures += row.failures;
                let stats = edge_clash::line1_latency_summary(&row.success_ms);
                let (min, median, max) = stats
                    .map(|(min, median, max)| {
                        (min.to_string(), median.to_string(), max.to_string())
                    })
                    .unwrap_or_else(|| {
                        (
                            "UNAVAILABLE".to_owned(),
                            "UNAVAILABLE".to_owned(),
                            "UNAVAILABLE".to_owned(),
                        )
                    });
                println!(
                    "candidate={} successes={} failures={} min_ms={} median_ms={} max_ms={}",
                    row.tag,
                    row.success_ms.len(),
                    row.failures,
                    min,
                    median,
                    max
                );
            }
            if failures > 0 {
                return Err(format!(
                    "Line1 native delay quality had {failures} failed HTTP probes"
                )
                .into());
            }
            println!("quality_status=PASS");
            Ok(())
        }
        Command::PrivilegedPrepareCredentialAccess(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::PrepareCredentialAccessBootstrap as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedInstallCredentialAccess(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::InstallCredentialAccessBootstrap as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                    existing_join_vm_candidate_sha256: None,
                    existing_join_windows_active_sha256: None,
                    existing_join_windows_candidate_sha256: None,
                    existing_join_intent_sha256: None,
                    existing_join_slot: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::PrivilegedConvergeControllerService(args) => {
            let install_root = PathBuf::from(args.install_root);
            let activation = load_verified_activation(&install_root)?;
            converge_controller_service(&install_root, Path::new(&activation.controller_path))
                .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("controller_service={WINDOWS_CONTROLLER_SERVICE_NAME}");
            println!("controller_start_owner=windows_scm");
            println!("secret_authority=controller_service");
            println!("runner_secret_access=false");
            Ok(())
        }
        Command::PrivilegedDispatch(args) => {
            let install_root = PathBuf::from(args.install_root);
            dispatch_privileged_request(&install_root).await?;
            Ok(())
        }
        Command::Secrets(args) => {
            let secrets = list_secret_refs(args.resolve()).await?;
            print_secret_refs(&secrets);
            Ok(())
        }
        Command::GetSecret(args) => {
            let entry = get_secret_ref(cli::controller_endpoint(args.endpoint), &args.name).await?;
            print_secret_ref(&entry);
            Ok(())
        }
        Command::SetSecret(args) => {
            let entry = set_secret_ref(
                cli::controller_endpoint(args.endpoint),
                &args.name,
                &args.secret_ref,
            )
            .await?;
            print_secret_ref(&entry);
            Ok(())
        }
        Command::StartLocal(args) => {
            let response = start_local(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::StartLocalVisible(args) => {
            let response = start_local_visible(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::StopLocal(args) => {
            let response = stop_local(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::RestartLocal(args) => {
            let response = restart_local(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::RestartLocalVisible(args) => {
            let response = restart_local_visible(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::GetSelector(args) => {
            let selector = fetch_selector_state(args.resolve(), DESKTOP_SELECTOR_GROUP).await?;
            print_selector_state(&selector);
            Ok(())
        }
        Command::GetUbuntuSelector(args) => {
            let selector = fetch_selector_state(args.resolve(), UBUNTU_SELECTOR_GROUP).await?;
            print_selector_state_with_label("Ubuntu selector", &selector);
            Ok(())
        }
        Command::SetSelector(args) => {
            let response = set_selector(
                cli::controller_endpoint(args.endpoint),
                DESKTOP_SELECTOR_GROUP,
                &args.name,
            )
            .await?;
            print_set_selector_result(&response);
            finish_selector_result(response)?;
            Ok(())
        }
        Command::SetUbuntuSelector(args) => {
            let response = set_selector(
                cli::controller_endpoint(args.endpoint),
                UBUNTU_SELECTOR_GROUP,
                &args.name,
            )
            .await?;
            print_set_selector_result(&response);
            finish_selector_result(response)?;
            Ok(())
        }
        Command::Trace(args) => {
            let trace = fetch_trace(args.resolve()).await?;
            print_trace(&trace);
            Ok(())
        }
        Command::TraceUbuntu(args) => {
            let endpoint = args.resolve();
            let status = fetch_status(endpoint.clone()).await?;
            let proxy_url = ubuntu_proxy_url_from_status(&status).ok_or_else(|| {
                ConsoleError::Command(
                    "ubuntu proxy endpoint is not available in controller status".to_owned(),
                )
            })?;
            let trace = fetch_trace_with_proxy(endpoint, Some(proxy_url)).await?;
            print_trace_with_label("Ubuntu egress IP", &trace);
            Ok(())
        }
        Command::GetOperation(args) => {
            let status =
                get_operation(cli::controller_endpoint(args.endpoint), args.operation_id).await?;
            print_operation_status(&status);
            Ok(())
        }
        Command::WatchOperation(args) => {
            watch_operation(cli::controller_endpoint(args.endpoint), args.operation_id).await?;
            Ok(())
        }
    }
}
