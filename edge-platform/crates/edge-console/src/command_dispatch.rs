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
    let command = parsed
        .command
        .ok_or_else(|| ConsoleError::Command("HOST_WINDOWS_NO_COMMAND".to_owned()))?;
    match command {
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
        Command::CredentialState(args) => {
            let state = fetch_credential_state(args.resolve()).await?;
            print_windows_credential_state(state.as_ref());
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
        Command::PrivilegedDispatch(args) => {
            let install_root = PathBuf::from(args.install_root);
            dispatch_privileged_request(&install_root).await?;
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineCleanInstall(args) => {
            windows_clean_install::install(Path::new(&args.install_root))
                .await
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineReceiptIdentityPrepare(args) => {
            let root = Path::new(&args.install_root);
            let active = load_verified_activation(root)?;
            let machine = windows_trust_enrollment::resolve_local_windows_machine(&active)
                .await
                .map_err(ConsoleError::Command)?;
            windows_receipt_enrollment::prepare(root, &machine).map_err(ConsoleError::Command)?;
            windows_trust_enrollment::prepare_pending(root).map_err(|reason| {
                ConsoleError::Command(format!(
                    "HOST_WINDOWS_FIRST_USE_TRUST_MARKER_UNKNOWN_NO_REPLAY: {reason}"
                ))
            })?;
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineReceiptIdentityObserve(args) => {
            windows_receipt_enrollment::observe(Path::new(&args.install_root))
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineFirstUseStatus(args) => {
            let root = Path::new(&args.install_root);
            let active = load_verified_activation(root)?;
            // Keep diagnosis available even when one independent reader fails.
            // An unavailable identity stage never suppresses task/API evidence.
            let stage_result = windows_receipt_enrollment::read_only_first_use_stage(root);
            let stage = stage_result.as_ref().copied().unwrap_or("UNPROVEN");
            // The machine binding is independent of trust visibility. Do not
            // let its failure suppress the already read Task/SYSTEM/BEGIN
            // report: every probe must retain its own explicit error code.
            let machine_result = windows_receipt_enrollment::bound_machine_id(root);
            let task_status = match windows_handoff::observe() {
                Ok(task) => {
                    let identity = task.validate(&active.console_path, task.enabled);
                    serde_json::json!({"state": task.state, "enabled": task.enabled,
                        "instances": task.instances, "exact_identity": identity.is_ok(),
                        "error_code": identity.err(), "system_execution_proven": false})
                }
                Err(code) => serde_json::json!({"state": "UNPROVEN", "error_code": code}),
            };
            // Report the EXISTING durable BEGIN independently from Task Scheduler.
            // Metadata is not a signed receipt, does not establish completion
            // and never permits replay of an interrupted handoff.
            let begin_marker = root.join("offline-bootstrap-intent-v1");
            let retained_begin = match fs::symlink_metadata(&begin_marker) {
                Ok(meta) if meta.is_file() => serde_json::json!({
                    "state": "PRESENT_UNADJUDICATED",
                    "authority": "UNAUTHENTICATED_LOCAL_METADATA",
                    "replay_allowed": false
                }),
                Ok(_) => serde_json::json!({"state": "INVALID_TYPE_NO_REPLAY"}),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    serde_json::json!({"state": "NOT_FOUND_READ_ONLY"})
                }
                Err(_) => serde_json::json!({"state": "METADATA_UNPROVEN_NO_REPLAY"}),
            };
            // Advisory, typed LocalSystem evidence from the SAME protected
            // native journal. Never infer a failure from Task exit=1 alone.
            let system_failure =
                match read_system_dispatch_failure(root, &active.release_set_sha256) {
                    Ok(Some(failure)) => serde_json::json!({
                        "state": "RECORDED_SYSTEM_ERROR",
                        "phase": failure.phase,
                        "error_code": failure.error_code,
                        "observed_at_unix": failure.observed_at_unix,
                    }),
                    Ok(None) => serde_json::json!({"state": "NOT_RECORDED"}),
                    Err(reason) => serde_json::json!({
                        "state": "UNPROVEN",
                        "reason": reason,
                    }),
                };
            println!(
                "{}",
                serde_json::json!({
                    "schema": "sing-box.windows-first-use-status/v1",
                    "system_dispatch_failure": system_failure,
                    "system_task": task_status,
                    "retained_begin": retained_begin,
                    "stage": stage,
                    "stage_error": stage_result.as_ref().err(),
                    "machine_id": machine_result.as_ref().ok(),
                    "machine_id_error": machine_result.as_ref().err(),
                    "installed_release_set_sha256": active.release_set_sha256,
                    "trusted_remote_execution": false,
                    "mutations": 0
                })
            );
            // The complete bounded report has been emitted even when either
            // independent reader fails; preserve nonzero exit for callers.
            stage_result.map_err(ConsoleError::Command)?;
            machine_result.map_err(ConsoleError::Command)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineHostTrustPrepare(args) => {
            windows_trust_enrollment::prepare(Path::new(&args.install_root))
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineBootstrapPreflight(args) => {
            let root = PathBuf::from(args.install_root);
            let (before, _) = read_only_windows_first_use_source(&root, None, "", "")
                .map_err(ConsoleError::Command)?;
            // JSON is used only at the LOCAL CLI boundary, not as a persisted
            // desired-state, native journal, or mutation contract. This proof
            // reports observation, not signed SYSTEM authority or authorization.
            println!(
                "{}",
                serde_json::json!({
                    "schema": "sing-box.windows-first-use-preflight/v1",
                    "status": "PASS",
                    "installed_release_set_sha256": before.release_set_sha256,
                    "source": "EXACT_STOPPED_PROXY_ONLY_OR_MANAGED_TUN",
                    "task": "EXACT_READY",
                    "pending": "NONE_OBSERVED_AT_THIS_INSTANT",
                    "old_dispatcher_running": false,
                    "w4_signer_and_receipt_enrollment": "NOT_PROVEN",
                    "native_signed_authority": false,
                    "host_mutations": 0,
                    "replay_authorized": false
                })
            );
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineBootstrap(args) => {
            // One locally elevated Administrator invocation against the exact
            // preverified immutable candidate. This NEVER writes request.pb
            // for the unsigned installed SYSTEM dispatcher. After bootstrap,
            // all remote changes require signed native HostIntent.
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
            let supersession = match (
                args.retained_intent_sha256,
                args.expected_current_release_set_sha256,
            ) {
                (None, None) => None,
                (Some(expected_intent_sha256), Some(expected_current_release_set_sha256)) => {
                    Some(RetainedOfflineBootstrapSupersession {
                        expected_intent_sha256,
                        expected_current_release_set_sha256,
                    })
                }
                _ => {
                    return Err(ConsoleError::Command(
                        "OFFLINE_BOOTSTRAP_SUPERSESSION_BOTH_PINS_REQUIRED".to_owned(),
                    ));
                }
            };
            let (code, _detail, active) = offline_bootstrap_privileged_release(
                &install_root,
                &request,
                supersession.as_ref(),
                args.enroll_receipt,
            )
            .await
            .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("code={code}");
            if let Some(sha) = active {
                println!("active_release_set_sha256={sha}");
            }
            println!("native_owner=SYSTEM_TASK_RETARGETED");
            if args.enroll_receipt {
                println!("w4_receipt_identity=LOCAL_ADMIN_REQUEST_DURABLE");
                println!("w4_next=EXISTING_SYSTEM_TASK_ONLY");
            }
            println!("native_signed_trust=REQUIRES_SEPARATE_GIT_ENROLLMENT");
            println!("network_mutations=0");
            Ok(())
        }
        Command::Secrets(args) => {
            let secrets = list_secret_refs(args.resolve()).await?;
            print_secret_refs(&secrets);
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
