use super::*;

/// Closed, secret-free failure classification shared by every registered VM
/// container. Docker State.Error and stdout/stderr are untrusted, potentially
/// secret-bearing strings; never copy a byte of either into operator reports.
fn classify_native_container_failure(
    runtime_error: Option<&str>,
    lines: &[String],
) -> &'static str {
    for source in runtime_error
        .into_iter()
        .chain(lines.iter().rev().take(40).map(String::as_str))
    {
        let normalized = source
            .chars()
            .take(4096)
            .collect::<String>()
            .to_ascii_lowercase();
        if normalized.contains("invalid config")
            || normalized.contains("failed to parse")
            || normalized.contains("config parse")
            || normalized.contains("json:")
            || normalized.contains("unknown field")
        {
            return "CONFIG_PARSE_HINT";
        }
        if normalized.contains("permission denied") || normalized.contains("access denied") {
            return "PERMISSION_HINT";
        }
        if normalized.contains("address already in use") || normalized.contains("bind:") {
            return "LISTENER_BIND_HINT";
        }
        if normalized.contains("no such host") || normalized.contains("dns lookup") {
            return "DNS_HINT";
        }
        if normalized.contains("connection refused") {
            return "UPSTREAM_REFUSED_HINT";
        }
        if normalized.contains("tls:") || normalized.contains("certificate") {
            return "TLS_HINT";
        }
        if normalized.contains("panic") || normalized.contains("segmentation fault") {
            return "PROCESS_CRASH_HINT";
        }
        if normalized.contains("no such file or directory") {
            return "FILE_MISSING_HINT";
        }
    }
    if runtime_error.is_some_and(|reason| !reason.is_empty()) {
        "UNCLASSIFIED_DOCKER_STATE_ERROR"
    } else {
        "UNCLASSIFIED_OR_NO_LOG"
    }
}

fn native_container_health_class(health: Option<&str>) -> &'static str {
    match health {
        None => "NO_HEALTHCHECK",
        Some("Healthy" | "healthy") => "HEALTHY",
        Some("Unhealthy" | "unhealthy") => "UNHEALTHY",
        Some("Starting" | "starting") => "STARTING",
        Some(_) => "UNKNOWN_HEALTH_STATE",
    }
}

pub(super) async fn run_local(command: cli::LocalCommand) -> Result<(), AgentError> {
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
        cli::LocalCommand::HostProbe => host_probe::run_host_probe().map_err(AgentError::Command),
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
            host_native::print_native_journal_diagnostic();
            // Snapshot uses the very same native readback as physical apply,
            // without an intent or completion authority. Preserve every
            // bounded non-sensitive reason, not only POSTSTATE_UNPROVEN.
            match capture_local_host_observation(&stack_dir).await {
                Ok(observed) => {
                    println!("host_native_poststate_origin=LOCAL_OBSERVATION_NOT_RECEIPT");
                    println!("host_native_poststate_host_kind={}", observed.host_kind);
                    println!("host_native_poststate_owner_state={}", observed.owner_state);
                    println!(
                        "host_native_poststate_release_proof={}",
                        observed.release_proof
                    );
                    println!(
                        "host_native_poststate_runtime_ready={}",
                        observed.runtime_ready
                    );
                    println!(
                        "host_native_poststate_runtime_ready_proven={}",
                        observed.runtime_ready_proven
                    );
                    println!(
                        "host_native_poststate_observed_at_unix={}",
                        observed.observed_at_unix
                    );
                    println!(
                        "host_native_poststate_reason_count={}",
                        observed.reason_codes.len()
                    );
                    for code in observed.reason_codes.iter().take(16) {
                        if code.len() <= 96
                            && !code.is_empty()
                            && code.bytes().all(|byte| {
                                byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                            })
                        {
                            println!("host_native_poststate_reason={code}");
                        } else {
                            println!("host_native_poststate_reason=UNSAFE_OR_NONCANONICAL");
                        }
                    }
                }
                Err(_) => println!("host_native_poststate_snapshot=UNAVAILABLE_READ_ONLY"),
            }
            // Every exact Git-owned VM container has bounded root-local
            // diagnostics, independent of Docker healthchecks. No arbitrary
            // container selector arrives from the runner, no raw Docker logs.
            // Transport is explicitly UNAUTHENTICATED runner copy; signed
            // native receipts remain separate from read-only observations.
            match host_native::registered_vm_host() {
                Ok(host) => {
                    println!("host_vm_diagnostic_origin=ROOT_LOCAL_RUNNER_COPIED_UNAUTHENTICATED");
                    println!("host_vm_diagnostic_scope=REGISTERED_VM_CONTAINERS_ONLY");
                    println!("host_vm_diagnostic_count={}", host.vm_containers.len());
                    for container in host.vm_containers.iter().take(16) {
                        let name = &container.container_name;
                        if name.len() > 96
                            || name.is_empty()
                            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        {
                            println!("host_vm_container_diagnostic=UNSAFE_REGISTERED_NAME");
                            continue;
                        }
                        match observe_container_runtime(name).await {
                            Ok(state) => {
                                let hint = classify_native_container_failure(
                                    state.runtime_error.as_deref(),
                                    &state.log_tail,
                                );
                                println!(
                                    "host_vm_container_diagnostic={} present={} running={} exit_code={} restarts={} oom={} health={} state_error={} failure_hint={} network_count={} published_port_count={} mount_count={}",
                                    name,
                                    state.present,
                                    state.running,
                                    state
                                        .exit_code
                                        .map(|n| n.to_string())
                                        .unwrap_or("UNPROVEN".into()),
                                    state
                                        .restart_count
                                        .map(|n| n.to_string())
                                        .unwrap_or("UNPROVEN".into()),
                                    state
                                        .oom_killed
                                        .map(|v| v.to_string())
                                        .unwrap_or("UNPROVEN".into()),
                                    native_container_health_class(state.health.as_deref()),
                                    state
                                        .runtime_error
                                        .as_ref()
                                        .is_some_and(|error| !error.is_empty()),
                                    hint,
                                    state.networks.len(),
                                    state.published_ports.len(),
                                    state.mounts.len(),
                                );
                            }
                            Err(_) => {
                                println!(
                                    "host_vm_container_diagnostic={} state=UNPROVEN_DOCKER_READBACK",
                                    name,
                                );
                            }
                        }
                    }
                    if host.vm_containers.len() > 16 {
                        println!("host_vm_container_diagnostic=TRUNCATED_LIMIT_16");
                    }
                }
                Err(_) => println!("host_vm_diagnostic_scope=UNPROVEN_GIT_REGISTERED_OWNER"),
            }
            // Read-only verification of the SAME Cloudflare Access JWT used
            // by signed INSTALL. No HostIntent, POST, or second owner.
            let worker_access = match vm_credential_access_identity_path(&stack_dir) {
                Ok(path) => match edge_secrets::diagnose_canonical_host_access(&path).await {
                    Ok(()) => "HOST_WORKER_JWT_VERIFIED_READ_ONLY",
                    Err(reason) => reason,
                },
                Err(_) => "HOST_WORKER_ACCESS_IDENTITY_UNAVAILABLE",
            };
            println!("host_worker_access_proof={worker_access}");
            println!("host_worker_access_mutations=0");
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
    }
}

#[cfg(test)]
mod native_read_only_diagnostics_tests {
    use super::*;

    #[test]
    fn line2_log_classification_never_returns_raw_content() {
        let lines = vec!["FATAL invalid config with credential=secret".to_owned()];
        assert_eq!(
            classify_native_container_failure(None, &lines),
            "CONFIG_PARSE_HINT"
        );
        assert_eq!(
            classify_native_container_failure(None, &[]),
            "UNCLASSIFIED_OR_NO_LOG"
        );
        assert_eq!(
            classify_native_container_failure(Some("permission denied with token=secret"), &[]),
            "PERMISSION_HINT"
        );
        assert_eq!(native_container_health_class(None), "NO_HEALTHCHECK");
        assert_eq!(
            native_container_health_class(Some("unhealthy")),
            "UNHEALTHY"
        );
    }
}
