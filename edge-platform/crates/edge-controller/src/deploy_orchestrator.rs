use super::*;

#[derive(Debug, Clone)]
pub(crate) struct DeployCommand {
    pub(crate) request: DeployRequest,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RollbackPolicy {
    pub(crate) restore_live_state: bool,
    pub(crate) restore_controller_snapshot: bool,
    pub(crate) clear_new_state_rows: bool,
}

impl RollbackPolicy {
    pub(crate) const STRICT: Self = Self {
        restore_live_state: true,
        restore_controller_snapshot: true,
        clear_new_state_rows: true,
    };
}

#[derive(Debug)]
pub(crate) struct DeployExecutionResult {
    pub(crate) response: DeployResponse,
}

pub(crate) async fn execute(
    server: &ControllerServerImpl,
    command: DeployCommand,
    rollback_policy: RollbackPolicy,
) -> Result<DeployExecutionResult, Status> {
    let request = command.request;
    let previous_controller_state = server
        .state
        .lock()
        .map_err(|_| Status::internal("controller state mutex poisoned"))?
        .get_controller_state()
        .map_err(|err| Status::internal(format!("failed to read controller state: {err}")))?;
    let operation = server
        .state
        .lock()
        .map_err(|_| Status::internal("controller state mutex poisoned"))?
        .start_operation("deploy", "RUNNING")
        .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
    append_operation_event(&server.state, operation.id, "deploy requested")?;
    let _ = upsert_controller_phases_with_journal(
        &server.state,
        DeployPhase::Requested,
        AppReadinessPhase::DeploymentAbsent,
        None,
        None,
        Some(phase_journal(operation.id, None, DeployPhase::Requested)),
    );

    let deployment_label = generate_deployment_label(request.label_prefix.as_deref());
    append_operation_event(
        &server.state,
        operation.id,
        &format!("deployment label reserved: {deployment_label}"),
    )?;
    let previous_live_state = read_live_state_raw(&server.repo_root)
        .map_err(|err| Status::internal(format!("failed to snapshot live state: {err}")))?;
    let mut rollback = DeployRollbackContext {
        deployment_label: deployment_label.clone(),
        previous_live_state,
        previous_controller_state,
        dns_updated: false,
    };

    let target = resolve_deploy_target(
        &server.repo_root,
        &server.state,
        &request,
        &deployment_label,
    )
    .await
    .map_err(|err| {
        let _ = upsert_controller_phases_with_journal(
            &server.state,
            DeployPhase::Failed,
            AppReadinessPhase::AppReadinessFailed,
            Some("target_resolution_failed"),
            Some(err.as_str()),
            Some(phase_journal(
                operation.id,
                Some("FAILED"),
                DeployPhase::Failed,
            )),
        );
        if rollback_policy.restore_controller_snapshot {
            let _ = restore_controller_state_snapshot(
                &server.state,
                rollback.previous_controller_state.as_ref(),
            );
        }
        let _ = append_operation_event(&server.state, operation.id, &err);
        let _ = update_operation_status(&server.state, operation.id, "FAILED");
        status_for_target_resolution_error(err)
    })?;
    append_operation_event(
        &server.state,
        operation.id,
        &format!(
            "target resolved: {} ({}){}",
            target.instance_id,
            target.target_ip,
            if target.created_instance {
                " [created]"
            } else {
                ""
            }
        ),
    )?;

    let bundle = build_bundle(&BuildBundleRequest {
        repo_root: &server.repo_root,
        target_ip: &target.target_ip,
        instance_id: &target.instance_id,
        tunnel_domain: request.tunnel_domain.as_deref(),
        acme_email: request.acme_email.as_deref(),
        cloudflare_zone_name: request.cloudflare_zone_name.as_deref(),
        dns_record_name: request.dns_record_name.as_deref(),
        label_prefix: request.label_prefix.as_deref(),
        deployment_label: Some(&deployment_label),
    })
    .map_err(|err| {
        let _ = append_operation_event(&server.state, operation.id, &err);
        let _ = update_operation_status(&server.state, operation.id, "FAILED");
        Status::internal(format!("failed to build deployment bundle: {err}"))
    })?;
    append_operation_event(
        &server.state,
        operation.id,
        &format!("bundle rendered: {}", bundle.label),
    )?;

    let preexisting_agent_target = resolve_targeted_agent_connection_target(
        &server.state,
        &target.instance_id,
        &target.target_ip,
    )
    .map_err(|err| {
        let _ = append_operation_event(&server.state, operation.id, &err);
        let _ = update_operation_status(&server.state, operation.id, "FAILED");
        Status::internal(format!(
            "failed to resolve persisted agent target before deploy: {err}"
        ))
    })?;
    let preexisting_agent_trust = preexisting_agent_target.is_some();

    if let Err(err) = persist_bundle_locally(&server.repo_root, &server.state, &bundle, &target) {
        let rollback_warnings = apply_failure_rollback(
            rollback_policy,
            server,
            &request,
            &target,
            &rollback,
            operation.id,
        )
        .await;
        let _ = append_operation_event(&server.state, operation.id, &err);
        let _ = update_operation_status(&server.state, operation.id, "FAILED");
        return Err(Status::internal(format!(
            "failed to persist deployment state: {}{}",
            err,
            format_rollback_warnings(&rollback_warnings),
        )));
    }
    append_operation_event(
        &server.state,
        operation.id,
        "local trust and deployment state persisted",
    )?;

    let agent_transport = match prepare_agent_transport(PrepareAgentTransportContext {
        repo_root: &server.repo_root,
        direct_endpoint: &server.agent_endpoint,
        request: &request,
        target: &target,
        preexisting_agent_target,
        preexisting_agent_trust,
        operation_id: operation.id,
        state: &server.state,
    })
    .await
    {
        Ok(agent_transport) => agent_transport,
        Err(err) => {
            let rollback_warnings = apply_failure_rollback(
                rollback_policy,
                server,
                &request,
                &target,
                &rollback,
                operation.id,
            )
            .await;
            let _ = append_operation_event(&server.state, operation.id, &err);
            let _ = update_operation_status(&server.state, operation.id, "FAILED");
            return Err(Status::internal(format!(
                "failed to prepare agent transport: {}{}",
                err,
                format_rollback_warnings(&rollback_warnings),
            )));
        }
    };
    append_operation_event(
        &server.state,
        operation.id,
        &format!("agent transport ready via {}", agent_transport.endpoint),
    )?;

    let apply_response = match apply_bundle_to_agent_target(
        &AgentConnectionTarget {
            endpoint: agent_transport.endpoint.clone(),
            tls_paths: agent_transport.tls_paths.clone(),
        },
        &bundle,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            let rollback_warnings = apply_failure_rollback(
                rollback_policy,
                server,
                &request,
                &target,
                &rollback,
                operation.id,
            )
            .await;
            let _ = append_operation_event(&server.state, operation.id, &err);
            let _ = update_operation_status(&server.state, operation.id, "FAILED");
            return Err(Status::internal(format!(
                "failed to apply bundle to agent: {}{}",
                err,
                format_rollback_warnings(&rollback_warnings),
            )));
        }
    };
    for path in &apply_response.written_paths {
        append_operation_event(&server.state, operation.id, &format!("wrote {path}"))?;
    }

    let base = match bootstrap_runtime_with_tls_resilient(
        &server.state,
        operation.id,
        AgentConnectionTarget {
            endpoint: agent_transport.endpoint.clone(),
            tls_paths: agent_transport.tls_paths.clone(),
        },
        BootstrapMode::BootstrapBase,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            let rollback_warnings = apply_failure_rollback(
                rollback_policy,
                server,
                &request,
                &target,
                &rollback,
                operation.id,
            )
            .await;
            let _ = append_operation_event(&server.state, operation.id, &err);
            let _ = update_operation_status(&server.state, operation.id, "FAILED");
            return Err(Status::internal(format!(
                "base bootstrap failed: {}{}",
                err,
                format_rollback_warnings(&rollback_warnings),
            )));
        }
    };
    if !base.success {
        let rollback_warnings = apply_failure_rollback(
            rollback_policy,
            server,
            &request,
            &target,
            &rollback,
            operation.id,
        )
        .await;
        let _ = append_operation_event(
            &server.state,
            operation.id,
            &format_bootstrap_failure(&base),
        );
        let _ = update_operation_status(&server.state, operation.id, "FAILED");
        return Ok(DeployExecutionResult {
            response: DeployResponse {
                success: false,
                deployment: Some(bundle_to_proto_summary(&bundle, &target)),
                provider: Some(provider_observation_from_request(
                    &request,
                    &target.target_ip,
                )),
                runtime: Some(RuntimeObservation::from_agent_state(
                    &base
                        .post_state
                        .clone()
                        .unwrap_or_else(AgentState::bootstrap_placeholder),
                )),
                warnings: merge_warnings(base.warnings, rollback_warnings),
                operation: Some(operation_with_status(operation, "FAILED")),
            },
        });
    }
    append_operation_event(&server.state, operation.id, "base bootstrap completed")?;

    if should_update_dns(&request) {
        let dns_note = match apply_dns_update(&server.state, &request, &target.target_ip).await {
            Ok(note) => note,
            Err(err) => {
                let rollback_warnings = apply_failure_rollback(
                    rollback_policy,
                    server,
                    &request,
                    &target,
                    &rollback,
                    operation.id,
                )
                .await;
                let _ = append_operation_event(&server.state, operation.id, &err);
                let _ = update_operation_status(&server.state, operation.id, "FAILED");
                return Err(Status::internal(format!(
                    "{}{}",
                    err,
                    format_rollback_warnings(&rollback_warnings),
                )));
            }
        };
        append_operation_event(&server.state, operation.id, &dns_note)?;
        rollback.dns_updated = true;
    }

    if request
        .tunnel_domain
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && request
            .acme_email
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    {
        let tunnel = match bootstrap_runtime_with_tls_resilient(
            &server.state,
            operation.id,
            AgentConnectionTarget {
                endpoint: agent_transport.endpoint.clone(),
                tls_paths: agent_transport.tls_paths.clone(),
            },
            BootstrapMode::BootstrapTunnel,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => {
                let rollback_warnings = apply_failure_rollback(
                    rollback_policy,
                    server,
                    &request,
                    &target,
                    &rollback,
                    operation.id,
                )
                .await;
                let _ = append_operation_event(&server.state, operation.id, &err);
                let _ = update_operation_status(&server.state, operation.id, "FAILED");
                return Err(Status::internal(format!(
                    "tunnel bootstrap failed: {}{}",
                    err,
                    format_rollback_warnings(&rollback_warnings),
                )));
            }
        };
        if !tunnel.success {
            let rollback_warnings = apply_failure_rollback(
                rollback_policy,
                server,
                &request,
                &target,
                &rollback,
                operation.id,
            )
            .await;
            let _ = append_operation_event(
                &server.state,
                operation.id,
                &format_bootstrap_failure(&tunnel),
            );
            let _ = update_operation_status(&server.state, operation.id, "FAILED");
            return Ok(DeployExecutionResult {
                response: DeployResponse {
                    success: false,
                    deployment: Some(bundle_to_proto_summary(&bundle, &target)),
                    provider: Some(provider_observation_from_request(
                        &request,
                        &target.target_ip,
                    )),
                    runtime: Some(RuntimeObservation::from_agent_state(
                        &tunnel
                            .post_state
                            .clone()
                            .unwrap_or_else(AgentState::bootstrap_placeholder),
                    )),
                    warnings: merge_warnings(tunnel.warnings, rollback_warnings),
                    operation: Some(operation_with_status(operation, "FAILED")),
                },
            });
        }
        append_operation_event(&server.state, operation.id, "tunnel bootstrap completed")?;
    }

    let final_agent_target =
        if has_configured_secret_ref(&server.state, SECRET_SSH_PRIVATE_KEY_PATH) {
            let restart_result = resolve_bootstrap_access_config(&server.repo_root, &server.state)
                .and_then(|config| restart_edge_agent_service(&target, &config));
            if let Err(err) = restart_result {
                let rollback_warnings = apply_failure_rollback(
                    rollback_policy,
                    server,
                    &request,
                    &target,
                    &rollback,
                    operation.id,
                )
                .await;
                let _ = update_operation_status(&server.state, operation.id, "FAILED");
                return Err(Status::internal(format!(
                    "failed to restart edge-agent with deployment TLS env: {}{}",
                    err,
                    format_rollback_warnings(&rollback_warnings),
                )));
            }
            append_operation_event(
                &server.state,
                operation.id,
                "edge-agent service restarted with deployment TLS env",
            )?;
            if agent_transport._tunnel.is_some() {
                resolve_targeted_agent_connection_target_for_endpoint(
                    &server.state,
                    &target.instance_id,
                    &target.target_ip,
                    &agent_transport.endpoint,
                )
                .map_err(|err| {
                    Status::internal(format!("failed to resolve final agent target: {err}"))
                })?
                .unwrap_or_else(|| AgentConnectionTarget {
                    endpoint: agent_transport.endpoint.clone(),
                    tls_paths: agent_transport.tls_paths.clone(),
                })
            } else {
                resolve_targeted_agent_connection_target(
                    &server.state,
                    &target.instance_id,
                    &target.target_ip,
                )
                .map_err(|err| {
                    Status::internal(format!("failed to resolve final agent target: {err}"))
                })?
                .unwrap_or_else(|| AgentConnectionTarget {
                    endpoint: agent_transport.endpoint.clone(),
                    tls_paths: agent_transport.tls_paths.clone(),
                })
            }
        } else {
            AgentConnectionTarget {
                endpoint: agent_transport.endpoint.clone(),
                tls_paths: agent_transport.tls_paths.clone(),
            }
        };

    let runtime_state = match wait_for_agent_runtime_target(&final_agent_target, true).await {
        Ok(state) => state,
        Err(err) => {
            if let Ok(config) = resolve_bootstrap_access_config(&server.repo_root, &server.state)
                && let Ok(diag) = collect_edge_agent_diagnostics(&target, &config)
            {
                let _ = append_operation_event(
                    &server.state,
                    operation.id,
                    &format!("edge-agent diagnostics: {diag}"),
                );
            }
            let _ = append_operation_event(&server.state, operation.id, &err);
            let rollback_warnings = apply_failure_rollback(
                rollback_policy,
                server,
                &request,
                &target,
                &rollback,
                operation.id,
            )
            .await;
            let _ = update_operation_status(&server.state, operation.id, "FAILED");
            return Err(Status::internal(format!(
                "failed to verify runtime readiness: {}{}",
                err,
                format_rollback_warnings(&rollback_warnings),
            )));
        }
    };
    let runtime = RuntimeObservation::from_agent_state(&runtime_state);
    let _ = upsert_controller_phases_with_journal(
        &server.state,
        DeployPhase::TunnelReadyVerified,
        AppReadinessPhase::ServerRuntimeReady,
        None,
        None,
        Some(phase_journal(
            operation.id,
            None,
            DeployPhase::TunnelReadyVerified,
        )),
    );

    let sync = match sync_local_config(
        &default_local_config_path(&server.repo_root),
        &default_live_state_path(&server.repo_root),
        &default_runtime_root(&server.repo_root),
    ) {
        Ok(sync) => sync,
        Err(err) => {
            let rollback_warnings = apply_failure_rollback(
                rollback_policy,
                server,
                &request,
                &target,
                &rollback,
                operation.id,
            )
            .await;
            let _ = update_operation_status(&server.state, operation.id, "FAILED");
            return Err(Status::internal(format!(
                "failed to sync local config: {}{}",
                err,
                format_rollback_warnings(&rollback_warnings),
            )));
        }
    };
    append_operation_event(
        &server.state,
        operation.id,
        &format!(
            "local config synced for instance {}",
            sync.instance_id.unwrap_or_default()
        ),
    )?;
    let _ = upsert_controller_phases_with_journal(
        &server.state,
        DeployPhase::LocalConfigSynced,
        AppReadinessPhase::ServerRuntimeReady,
        None,
        None,
        Some(phase_journal(
            operation.id,
            None,
            DeployPhase::LocalConfigSynced,
        )),
    );

    let _ = upsert_controller_phases_with_journal(
        &server.state,
        DeployPhase::LocalRuntimeStartStarted,
        AppReadinessPhase::ServerRuntimeReady,
        None,
        None,
        Some(phase_journal(
            operation.id,
            None,
            DeployPhase::LocalRuntimeStartStarted,
        )),
    );
    let local_paths = LocalRuntimePaths {
        singbox_binary_path: default_singbox_binary_path(),
        config_path: default_local_config_path(&server.repo_root),
        state_path: default_live_state_path(&server.repo_root),
        runtime_root: default_runtime_root(&server.repo_root),
    };
    let local_runtime = match restart_runtime_process(&local_paths) {
        Ok(result) => result,
        Err(err) => {
            let _ = upsert_controller_phases_with_journal(
                &server.state,
                DeployPhase::Failed,
                AppReadinessPhase::AppReadinessFailed,
                Some("local_runtime_start_failed"),
                Some(err.as_str()),
                Some(phase_journal(
                    operation.id,
                    Some("FAILED"),
                    DeployPhase::Failed,
                )),
            );
            let _ = append_operation_event(
                &server.state,
                operation.id,
                &format!("local sing-box start failed: {err}"),
            );
            let _ = update_operation_status(&server.state, operation.id, "FAILED");
            return Ok(DeployExecutionResult {
                response: DeployResponse {
                    success: false,
                    deployment: Some(bundle_to_proto_summary(&bundle, &target)),
                    provider: Some(provider_observation_from_request(
                        &request,
                        &target.target_ip,
                    )),
                    runtime: Some(runtime),
                    warnings: vec![err],
                    operation: Some(operation_with_status(operation, "FAILED")),
                },
            });
        }
    };
    append_operation_event(&server.state, operation.id, &local_runtime.note)?;
    let local_reconcile_warnings = reconcile_selector_intents_for_running_local(
        &server.repo_root,
        &server.state,
        &local_runtime.local_singbox,
    )
    .await
    .unwrap_or_else(|err| vec![err]);
    let _ = upsert_controller_phases_with_journal(
        &server.state,
        DeployPhase::LocalRuntimeReadyVerified,
        AppReadinessPhase::LocalRuntimeReady,
        None,
        None,
        Some(phase_journal(
            operation.id,
            None,
            DeployPhase::LocalRuntimeReadyVerified,
        )),
    );

    let base_status =
        collect_controller_status(&server.repo_root).map_err(platform_error_to_status)?;
    let observed_local = merge_local_runtime(
        base_status.local_singbox.clone(),
        inspect_local_runtime(&default_local_config_path(&server.repo_root)),
    );
    let desktop_selector = observe_selector_state(
        observed_local.clone(),
        base_status.selector.clone(),
        DESKTOP_SELECTOR_GROUP,
    )
    .await;
    let ubuntu_selector = observe_selector_state(
        observed_local.clone(),
        base_status.ubuntu_selector.clone(),
        UBUNTU_SELECTOR_GROUP,
    )
    .await;
    let selectors_ok =
        selector_is_converged(&desktop_selector) && selector_is_converged(&ubuntu_selector);
    if !selectors_ok {
        let _ = upsert_controller_phases_with_journal(
            &server.state,
            DeployPhase::Completed,
            AppReadinessPhase::AppReadinessFailed,
            Some("selector_reconcile_failed"),
            Some("one or more selector groups did not converge to persisted intent"),
            Some(phase_journal(
                operation.id,
                Some("SUCCEEDED"),
                DeployPhase::Completed,
            )),
        );
        let _ = append_operation_event(
            &server.state,
            operation.id,
            "selector verification failed after local runtime start; deployment completed in degraded state",
        );
        let mut warnings = local_reconcile_warnings;
        warnings.push(format!(
            "desktop desired={:?} observed={:?}; ubuntu desired={:?} observed={:?}",
            desktop_selector.desired_main_route,
            desktop_selector.observed_main_route,
            ubuntu_selector.desired_main_route,
            ubuntu_selector.observed_main_route
        ));
        let response = DeployResponse {
            success: true,
            deployment: Some(bundle_to_proto_summary(&bundle, &target)),
            provider: Some(provider_observation_from_request(
                &request,
                &target.target_ip,
            )),
            runtime: Some(runtime),
            warnings,
            operation: Some(operation_with_status(operation, "SUCCEEDED")),
        };
        store_local_response(&server.state, "deploy_response", &response.encode_to_vec())?;
        return Ok(DeployExecutionResult { response });
    }
    let _ = upsert_controller_phases_with_journal(
        &server.state,
        DeployPhase::SelectorsVerified,
        AppReadinessPhase::SelectorsReady,
        None,
        None,
        Some(phase_journal(
            operation.id,
            None,
            DeployPhase::SelectorsVerified,
        )),
    );

    let _ = append_operation_event(
        &server.state,
        operation.id,
        "waiting for desktop and ubuntu egress trace convergence",
    );
    let desktop_proxy = default_trace_proxy_url(&default_local_config_path(&server.repo_root))
        .ok()
        .flatten()
        .unwrap_or_else(|| DEFAULT_TRACE_PROXY_URL.to_owned());
    let desktop_trace = wait_for_trace_via_proxy(&desktop_proxy, EGRESS_TRACE_TIMEOUT_SECS).await;
    let ubuntu_trace = match ubuntu_proxy_url_from_status(&ControllerStatus {
        inventory: base_status.inventory.clone(),
        agent_state: base_status.agent_state.clone(),
        local_singbox: Some(observed_local.clone()),
        deployment: base_status.deployment.clone(),
        provider: base_status.provider.clone(),
        runtime: base_status.runtime.clone(),
        selector: Some(desktop_selector.clone()),
        status_notes: base_status.status_notes.clone(),
        ubuntu_selector: Some(ubuntu_selector.clone()),
        ubuntu_proxy: base_status.ubuntu_proxy.clone(),
        app_readiness_phase: base_status.app_readiness_phase,
    }) {
        Some(url) => wait_for_trace_via_proxy(&url, EGRESS_TRACE_TIMEOUT_SECS).await,
        None => TraceObservation::unavailable(
            "ubuntu proxy endpoint is not available in controller status",
        ),
    };
    if !desktop_trace.available || !ubuntu_trace.available {
        let _ = upsert_controller_phases_with_journal(
            &server.state,
            DeployPhase::Completed,
            AppReadinessPhase::AppReadinessFailed,
            Some("egress_trace_failed"),
            Some("desktop or ubuntu egress trace failed"),
            Some(phase_journal(
                operation.id,
                Some("SUCCEEDED"),
                DeployPhase::Completed,
            )),
        );
        let _ = append_operation_event(
            &server.state,
            operation.id,
            "egress trace verification failed; deployment completed in degraded state",
        );
        let mut warnings = local_reconcile_warnings;
        warnings.push(
            desktop_trace
                .note
                .clone()
                .unwrap_or_else(|| "desktop trace unavailable".to_owned()),
        );
        warnings.push(
            ubuntu_trace
                .note
                .clone()
                .unwrap_or_else(|| "ubuntu trace unavailable".to_owned()),
        );
        let response = DeployResponse {
            success: true,
            deployment: Some(bundle_to_proto_summary(&bundle, &target)),
            provider: Some(provider_observation_from_request(
                &request,
                &target.target_ip,
            )),
            runtime: Some(runtime),
            warnings,
            operation: Some(operation_with_status(operation, "SUCCEEDED")),
        };
        store_local_response(&server.state, "deploy_response", &response.encode_to_vec())?;
        return Ok(DeployExecutionResult { response });
    }
    let _ = upsert_controller_phases_with_journal(
        &server.state,
        DeployPhase::AppEgressVerified,
        AppReadinessPhase::AppEgressReady,
        None,
        None,
        Some(phase_journal(
            operation.id,
            None,
            DeployPhase::AppEgressVerified,
        )),
    );
    let _ = upsert_controller_phases_with_journal(
        &server.state,
        DeployPhase::AppReadyCompleted,
        AppReadinessPhase::AppReady,
        None,
        None,
        Some(phase_journal(
            operation.id,
            Some("SUCCEEDED"),
            DeployPhase::AppReadyCompleted,
        )),
    );

    update_operation_status(&server.state, operation.id, "SUCCEEDED")?;
    let response = DeployResponse {
        success: true,
        deployment: Some(bundle_to_proto_summary(&bundle, &target)),
        provider: Some(provider_observation_from_request(
            &request,
            &target.target_ip,
        )),
        runtime: Some(runtime),
        warnings: merge_warnings(apply_response.warnings, local_reconcile_warnings),
        operation: Some(operation_with_status(operation, "SUCCEEDED")),
    };
    store_local_response(&server.state, "deploy_response", &response.encode_to_vec())?;
    Ok(DeployExecutionResult { response })
}

async fn apply_failure_rollback(
    rollback_policy: RollbackPolicy,
    server: &ControllerServerImpl,
    request: &DeployRequest,
    target: &ResolvedDeployTarget,
    rollback: &DeployRollbackContext,
    operation_id: i64,
) -> Vec<String> {
    if rollback_policy.restore_live_state
        && rollback_policy.restore_controller_snapshot
        && rollback_policy.clear_new_state_rows
    {
        rollback_failed_deploy(
            &server.repo_root,
            &server.state,
            request,
            target,
            rollback,
            operation_id,
        )
        .await
    } else {
        vec!["rollback policy skipped one or more cleanup dimensions".to_owned()]
    }
}

fn format_rollback_warnings(warnings: &[String]) -> String {
    if warnings.is_empty() {
        String::new()
    } else {
        format!("; rollback warnings: {}", warnings.join("; "))
    }
}

fn phase_journal(
    operation_id: i64,
    operation_status: Option<&'static str>,
    deploy_phase: DeployPhase,
) -> OperationJournalUpdate<'static> {
    OperationJournalUpdate {
        operation_id,
        operation_status,
        message: Some(deploy_phase.as_str_name()),
    }
}
