use super::*;

#[tonic::async_trait]
impl ControllerService for ControllerServerImpl {
    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ControllerStatus>, Status> {
        let reconcile_warning = if is_installed_windows_root(&self.repo_root) {
            None
        } else {
            reconcile_active_deployment_state(&self.repo_root, &self.state)
                .err()
                .map(|err| format!("local deployment-state reconciliation unavailable: {err}"))
        };
        let mut status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let backend_ready_from_state = status
            .deployment
            .as_ref()
            .is_some_and(|deployment| deployment.live_state_present);
        let live_state_artifact_present = live_state_artifact_present(&self.repo_root);

        if is_installed_windows_root(&self.repo_root) {
            // Persistent Windows runtime ownership is local to EdgePlatformController.
            // The retired server-agent RPC endpoint is not a Windows health dependency.
            status.agent_state = None;
            status.runtime = None;
        } else {
            let (agent_state, runtime) = observe_agent(&self.state, &self.agent_endpoint).await;
            if !agent_state.ready && !backend_ready_from_state {
                status
                    .status_notes
                    .push("server agent has not reached runtime readiness".to_owned());
            }
            if !runtime.edge_agent_reachable && !backend_ready_from_state {
                status.status_notes.push(
                    "server runtime observation is running in degraded fallback mode".to_owned(),
                );
            } else if !runtime.edge_agent_reachable && backend_ready_from_state {
                status.status_notes.push(
                    "server runtime observation is unavailable; using persisted live deployment state"
                        .to_owned(),
                );
            }
            status.agent_state = Some(agent_state);
            status.runtime = Some(runtime);
        }
        if backend_ready_from_state && !live_state_artifact_present {
            status.status_notes.push(
                if is_installed_windows_root(&self.repo_root) {
                    "typed Windows runtime-state.pb is missing; start-local cannot be trusted"
                } else {
                    "legacy local runtime artifact current-edge.json is missing; start-local cannot be trusted"
                }
                .to_owned(),
            );
        }

        let local_config_path = default_local_config_path(&self.repo_root);
        let merged_local = merge_local_runtime(
            status.local_singbox.take(),
            inspect_local_runtime(&local_config_path),
        );
        let merged_selector = observe_selector_state(
            merged_local.clone(),
            status.selector.take(),
            DESKTOP_SELECTOR_GROUP,
        )
        .await;
        let merged_ubuntu_selector = observe_selector_state(
            merged_local.clone(),
            status.ubuntu_selector.take(),
            UBUNTU_SELECTOR_GROUP,
        )
        .await;
        status.local_singbox = Some(merged_local);
        status.selector = Some(merged_selector);
        status.ubuntu_selector = Some(merged_ubuntu_selector);
        refresh_app_readiness_from_observed_status(&self.state, &mut status)?;
        if let Some(warning) = reconcile_warning {
            status.status_notes.push(warning);
        }

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("controller_status", &status.encode_proto())
            .map_err(|err| Status::internal(format!("failed to store status snapshot: {err}")))?;

        Ok(Response::new(status))
    }

    async fn doctor(
        &self,
        request: Request<DoctorRequest>,
    ) -> Result<Response<DoctorResponse>, Status> {
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("doctor", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "doctor requested")?;

        let status = self.get_status(Request::new(Empty {})).await?.into_inner();
        let desktop_trace = if request.require_egress_traces {
            Some(
                trace_via_proxy(
                    &default_trace_proxy_url(&default_local_config_path(&self.repo_root))
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| DEFAULT_TRACE_PROXY_URL.to_owned()),
                )
                .await,
            )
        } else {
            None
        };
        let ubuntu_trace = if request.require_egress_traces {
            match ubuntu_proxy_url_from_status(&status) {
                Some(url) => Some(trace_via_proxy(&url).await),
                None => Some(TraceObservation::unavailable(
                    "ubuntu proxy endpoint is not available in controller status",
                )),
            }
        } else {
            None
        };

        let checks = build_doctor_checks(
            &self.repo_root,
            &status,
            desktop_trace.as_ref(),
            ubuntu_trace.as_ref(),
            &request,
        );
        let ok = checks.iter().all(|check| check.ok);
        append_operation_event(
            &self.state,
            operation.id,
            if ok {
                "doctor completed: all checks passed"
            } else {
                "doctor completed: one or more checks failed"
            },
        )?;
        update_operation_status(
            &self.state,
            operation.id,
            if ok { "SUCCEEDED" } else { "FAILED" },
        )?;

        Ok(Response::new(DoctorResponse {
            ok,
            checks,
            status: Some(status),
            desktop_trace,
            ubuntu_trace,
            operation: Some(operation_with_status(
                operation,
                if ok { "SUCCEEDED" } else { "FAILED" },
            )),
        }))
    }

    async fn get_secret_ref(
        &self,
        request: Request<GetSecretRefRequest>,
    ) -> Result<Response<SecretRefEntry>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let name = request.into_inner().name;
        validate_secret_name(&name)?;
        let default_ref = default_env_ref(secret_name_to_env(&name));
        let secret_ref =
            get_or_seed_secret_ref(&self.state, &name, &default_ref).map_err(|err| {
                Status::internal(format!("failed to resolve secret ref {name}: {err}"))
            })?;
        let entry = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .get_secret_ref(&name)
            .map_err(|err| Status::internal(format!("failed to read secret ref {name}: {err}")))?
            .map(|value| SecretRefEntry {
                name: value.name,
                secret_ref: value.secret_ref,
                updated_at_unix: value.updated_at_unix,
            })
            .unwrap_or(SecretRefEntry {
                name,
                secret_ref,
                updated_at_unix: 0,
            });
        Ok(Response::new(entry))
    }

    async fn set_secret_ref(
        &self,
        request: Request<SetSecretRefRequest>,
    ) -> Result<Response<SecretRefEntry>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let request = request.into_inner();
        validate_secret_name(&request.name)?;
        edge_secrets::parse_secret_reference(&request.secret_ref)
            .map_err(Status::invalid_argument)?;
        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .upsert_secret_ref(&request.name, &request.secret_ref)
            .map_err(|err| Status::internal(format!("failed to store secret ref: {err}")))?;
        let stored = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .get_secret_ref(&request.name)
            .map_err(|err| Status::internal(format!("failed to reload secret ref: {err}")))?
            .ok_or_else(|| Status::internal("stored secret ref is missing"))?;
        Ok(Response::new(SecretRefEntry {
            name: stored.name,
            secret_ref: stored.secret_ref,
            updated_at_unix: stored.updated_at_unix,
        }))
    }

    async fn list_secret_refs(
        &self,
        _request: Request<ListSecretRefsRequest>,
    ) -> Result<Response<ListSecretRefsResponse>, Status> {
        Ok(Response::new(ListSecretRefsResponse {
            secrets: list_secret_refs(&self.state)?,
        }))
    }

    async fn bootstrap_runtime(
        &self,
        request: Request<BootstrapRuntimeRequest>,
    ) -> Result<Response<BootstrapRuntimeResponse>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let mode = BootstrapMode::try_from(request.into_inner().mode)
            .map_err(|_| Status::invalid_argument("unknown bootstrap mode"))?;
        if mode == BootstrapMode::Unspecified {
            return Err(Status::invalid_argument("bootstrap mode is required"));
        }

        let target = resolve_agent_connection_target(&self.state, &self.agent_endpoint)
            .map_err(|err| Status::internal(format!("failed to resolve agent target: {err}")))?;
        let response = bootstrap_runtime_with_tls(target, mode)
            .await
            .map_err(|err| Status::internal(format!("agent bootstrap RPC failed: {err}")))?;

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("bootstrap_runtime_response", &response.encode_proto())
            .map_err(|err| {
                Status::internal(format!(
                    "failed to store bootstrap response snapshot: {err}"
                ))
            })?;

        Ok(Response::new(response))
    }

    async fn start_local_runtime(
        &self,
        request: Request<StartLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let request = request.into_inner();
        require_nonrestarting_start(request.force_restart)?;
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("start_local_runtime", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "start local runtime requested")?;

        let (agent_state, _) = observe_agent(&self.state, &self.agent_endpoint).await;
        if !agent_state.ready && !backend_ready_for_local_runtime(&self.repo_root) {
            append_operation_event(
                &self.state,
                operation.id,
                "backend is not ready; refusing to start local runtime",
            )?;
            update_operation_status(&self.state, operation.id, "FAILED")?;
            let local_singbox = inspect_local_runtime(&default_local_config_path(&self.repo_root));
            return Ok(Response::new(LocalRuntimeResponse {
                success: false,
                pid: None,
                note: "backend is not ready; local runtime start refused".to_owned(),
                warnings: vec!["server runtime is not ready".to_owned()],
                operation: Some(operation_with_status(operation, "FAILED")),
                local_singbox: Some(local_singbox),
            }));
        }

        let paths = local_runtime_paths_from_start(&self.repo_root, &request);
        #[cfg(windows)]
        let started = {
            let _owner_gate = WINDOWS_RUNTIME_OWNER_GATE
                .lock()
                .map_err(|_| Status::internal("Windows runtime owner gate poisoned"))?;
            if self.repo_root.join("exchange/requests/request.pb").exists() {
                return Err(Status::failed_precondition(
                    "privileged release handoff pending: refusing competing runtime start",
                ));
            }
            require_native_windows_runtime_launch_safety(&self.repo_root)
                .and_then(|_| start_runtime_process(&paths, request.visible_window))
        };
        #[cfg(not(windows))]
        let started = start_runtime_process(&paths, request.visible_window);
        let response = match started {
            Ok(mut result) => {
                let _ = refresh_app_readiness_phase(
                    &self.repo_root,
                    &self.state,
                    &result.local_singbox,
                )
                .await;
                let observed_after_start = inspect_local_runtime(&paths.config_path);
                if !observed_after_start.process_running {
                    result
                        .warnings
                        .push("local sing-box stopped before start operation completed".to_owned());
                    result
                        .warnings
                        .extend(observed_after_start.warnings.clone());
                    append_operation_event(
                        &self.state,
                        operation.id,
                        "local sing-box stopped before start operation completed",
                    )?;
                    update_operation_status(&self.state, operation.id, "FAILED")?;
                    LocalRuntimeResponse {
                        success: false,
                        pid: result.pid,
                        note: "local sing-box stopped before start operation completed".to_owned(),
                        warnings: result.warnings,
                        operation: Some(operation_with_status(operation, "FAILED")),
                        local_singbox: Some(observed_after_start),
                    }
                } else {
                    result.local_singbox = observed_after_start;
                    append_operation_event(&self.state, operation.id, &result.note)?;
                    update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
                    LocalRuntimeResponse {
                        success: true,
                        pid: result.pid,
                        note: result.note,
                        warnings: result.warnings,
                        operation: Some(operation_with_status(operation, "SUCCEEDED")),
                        local_singbox: Some(result.local_singbox),
                    }
                }
            }
            Err(err) => {
                append_operation_event(&self.state, operation.id, &err)?;
                update_operation_status(&self.state, operation.id, "FAILED")?;
                let local_singbox = inspect_local_runtime(&paths.config_path);
                LocalRuntimeResponse {
                    success: false,
                    pid: None,
                    note: err,
                    warnings: local_singbox.warnings.clone(),
                    operation: Some(operation_with_status(operation, "FAILED")),
                    local_singbox: Some(local_singbox),
                }
            }
        };

        store_local_response(
            &self.state,
            "start_local_runtime_response",
            &response.encode_proto(),
        )?;
        Ok(Response::new(response))
    }

    async fn stop_local_runtime(
        &self,
        request: Request<StopLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        #[cfg(windows)]
        edge_local_runtime::reject_unproven_windows_tun_teardown("stop-local")
            .map_err(Status::failed_precondition)?;
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("stop_local_runtime", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "stop local runtime requested")?;

        let config_path = request
            .config_path
            .map(PathBuf::from)
            .unwrap_or_else(|| default_local_config_path(&self.repo_root));
        let response = match stop_runtime_process(&config_path, request.expected_config_only) {
            Ok(result) => {
                append_operation_event(&self.state, operation.id, &result.note)?;
                update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
                LocalRuntimeResponse {
                    success: true,
                    pid: result.pid,
                    note: result.note,
                    warnings: result.warnings,
                    operation: Some(operation_with_status(operation, "SUCCEEDED")),
                    local_singbox: Some(result.local_singbox),
                }
            }
            Err(err) => {
                append_operation_event(&self.state, operation.id, &err)?;
                update_operation_status(&self.state, operation.id, "FAILED")?;
                let local_singbox = inspect_local_runtime(&config_path);
                LocalRuntimeResponse {
                    success: false,
                    pid: None,
                    note: err,
                    warnings: local_singbox.warnings.clone(),
                    operation: Some(operation_with_status(operation, "FAILED")),
                    local_singbox: Some(local_singbox),
                }
            }
        };

        store_local_response(
            &self.state,
            "stop_local_runtime_response",
            &response.encode_proto(),
        )?;
        Ok(Response::new(response))
    }

    async fn restart_local_runtime(
        &self,
        request: Request<RestartLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("restart_local_runtime", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "restart local runtime requested")?;

        let (agent_state, _) = observe_agent(&self.state, &self.agent_endpoint).await;
        if !agent_state.ready && !backend_ready_for_local_runtime(&self.repo_root) {
            append_operation_event(
                &self.state,
                operation.id,
                "backend is not ready; refusing to restart local runtime",
            )?;
            update_operation_status(&self.state, operation.id, "FAILED")?;
            let local_singbox = inspect_local_runtime(&default_local_config_path(&self.repo_root));
            return Ok(Response::new(LocalRuntimeResponse {
                success: false,
                pid: None,
                note: "backend is not ready; local runtime restart refused".to_owned(),
                warnings: vec!["server runtime is not ready".to_owned()],
                operation: Some(operation_with_status(operation, "FAILED")),
                local_singbox: Some(local_singbox),
            }));
        }

        let paths = local_runtime_paths_from_restart(&self.repo_root, &request);
        #[cfg(windows)]
        let restarted = {
            let _owner_gate = WINDOWS_RUNTIME_OWNER_GATE
                .lock()
                .map_err(|_| Status::internal("Windows runtime owner gate poisoned"))?;
            if self.repo_root.join("exchange/requests/request.pb").exists() {
                return Err(Status::failed_precondition(
                    "privileged release handoff pending: refusing competing runtime restart",
                ));
            }
            // Reject before changing replacement generation or stopping any child.
            require_native_windows_runtime_launch_safety(&self.repo_root).and_then(|_| {
                WINDOWS_RUNTIME_REPLACEMENT_GENERATION.fetch_add(1, Ordering::AcqRel);
                if request.visible_window {
                    restart_runtime_process_visible(&paths)
                } else {
                    restart_runtime_process(&paths)
                }
            })
        };
        #[cfg(not(windows))]
        let restarted = if request.visible_window {
            restart_runtime_process_visible(&paths)
        } else {
            restart_runtime_process(&paths)
        };
        let response = match restarted {
            Ok(mut result) => {
                let _ = refresh_app_readiness_phase(
                    &self.repo_root,
                    &self.state,
                    &result.local_singbox,
                )
                .await;
                let observed_after_start = inspect_local_runtime(&paths.config_path);
                if !observed_after_start.process_running {
                    result.warnings.push(
                        "local sing-box stopped before restart operation completed".to_owned(),
                    );
                    result
                        .warnings
                        .extend(observed_after_start.warnings.clone());
                    append_operation_event(
                        &self.state,
                        operation.id,
                        "local sing-box stopped before restart operation completed",
                    )?;
                    update_operation_status(&self.state, operation.id, "FAILED")?;
                    LocalRuntimeResponse {
                        success: false,
                        pid: result.pid,
                        note: "local sing-box stopped before restart operation completed"
                            .to_owned(),
                        warnings: result.warnings,
                        operation: Some(operation_with_status(operation, "FAILED")),
                        local_singbox: Some(observed_after_start),
                    }
                } else {
                    result.local_singbox = observed_after_start;
                    append_operation_event(&self.state, operation.id, &result.note)?;
                    update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
                    LocalRuntimeResponse {
                        success: true,
                        pid: result.pid,
                        note: result.note,
                        warnings: result.warnings,
                        operation: Some(operation_with_status(operation, "SUCCEEDED")),
                        local_singbox: Some(result.local_singbox),
                    }
                }
            }
            Err(err) => {
                append_operation_event(&self.state, operation.id, &err)?;
                update_operation_status(&self.state, operation.id, "FAILED")?;
                let local_singbox = inspect_local_runtime(&paths.config_path);
                LocalRuntimeResponse {
                    success: false,
                    pid: None,
                    note: err,
                    warnings: local_singbox.warnings.clone(),
                    operation: Some(operation_with_status(operation, "FAILED")),
                    local_singbox: Some(local_singbox),
                }
            }
        };

        store_local_response(
            &self.state,
            "restart_local_runtime_response",
            &response.encode_proto(),
        )?;
        Ok(Response::new(response))
    }

    async fn get_selector_state(
        &self,
        request: Request<GetSelectorStateRequest>,
    ) -> Result<Response<SelectorState>, Status> {
        let request = request.into_inner();
        let group = normalize_selector_group(request.group.as_deref())?;
        let base_status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let local_singbox = merge_local_runtime(
            base_status.local_singbox.clone(),
            inspect_local_runtime(&default_local_config_path(&self.repo_root)),
        );
        let base_selector = if group == UBUNTU_SELECTOR_GROUP {
            base_status.ubuntu_selector
        } else {
            base_status.selector
        };
        let selector = observe_selector_state(local_singbox, base_selector, group).await;

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation(
                &format!("selector_state::{group}"),
                &selector.encode_to_vec(),
            )
            .map_err(|err| {
                Status::internal(format!("failed to store selector observation: {err}"))
            })?;

        Ok(Response::new(selector))
    }

    async fn set_selector(
        &self,
        request: Request<SetSelectorRequest>,
    ) -> Result<Response<SetSelectorResponse>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let request = request.into_inner();
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("set_selector", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(
            &self.state,
            operation.id,
            &format!("setting selector {} -> {}", request.group, request.name),
        )?;
        let group = normalize_selector_group(Some(&request.group))?.to_owned();
        if !is_allowed_selector_route(&request.name) {
            update_operation_status(&self.state, operation.id, "FAILED")?;
            return Err(Status::invalid_argument(format!(
                "unknown selector route: {}",
                request.name
            )));
        }

        let base_status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;
        let local_singbox = merge_local_runtime(
            base_status.local_singbox.clone(),
            inspect_local_runtime(&default_local_config_path(&self.repo_root)),
        );
        let Some(controller_url) = clash_controller_url(&local_singbox) else {
            update_operation_status(&self.state, operation.id, "FAILED")?;
            return Ok(Response::new(SetSelectorResponse {
                success: false,
                previous: None,
                current: None,
                warnings: vec!["clash API endpoint is not configured".to_owned()],
                operation: Some(operation_with_status(operation, "FAILED")),
                selector: Some(
                    selector_state_for_group(&base_status, &group)
                        .cloned()
                        .unwrap_or_else(SelectorState::placeholder),
                ),
            }));
        };

        let response =
            match set_live_selector(&controller_url, &group, &request.name, default_aux_groups())
                .await
            {
                Ok((previous, mut selector)) => {
                    // SetSelector is a transient live switch. The durable default is
                    // rendered from the protected Git route policy, never SQLite.
                    selector.desired_main_route = selector_state_for_group(&base_status, &group)
                        .and_then(|state| state.desired_main_route.clone());
                    append_operation_event(
                        &self.state,
                        operation.id,
                        "transient live selector updated; no durable intent recorded",
                    )?;
                    update_operation_status(&self.state, operation.id, "SUCCEEDED")?;
                    SetSelectorResponse {
                        success: true,
                        previous,
                        current: selector.observed_main_route.clone(),
                        warnings: selector.warnings.clone(),
                        operation: Some(operation_with_status(operation, "SUCCEEDED")),
                        selector: Some(selector),
                    }
                }
                Err(err) => {
                    append_operation_event(&self.state, operation.id, &err)?;
                    update_operation_status(&self.state, operation.id, "FAILED")?;
                    let mut selector = selector_state_for_group(&base_status, &group)
                        .cloned()
                        .unwrap_or_else(SelectorState::placeholder);
                    selector.degraded = true;
                    selector.warnings.push(err.clone());
                    SetSelectorResponse {
                        success: false,
                        previous: selector.observed_main_route.clone(),
                        current: selector.observed_main_route.clone(),
                        warnings: selector.warnings.clone(),
                        operation: Some(operation_with_status(operation, "FAILED")),
                        selector: Some(selector),
                    }
                }
            };

        Ok(Response::new(response))
    }

    async fn get_trace(
        &self,
        request: Request<GetTraceRequest>,
    ) -> Result<Response<TraceObservation>, Status> {
        let request = request.into_inner();
        let config_path = default_local_config_path(&self.repo_root);
        let proxy_url = request.proxy_url.unwrap_or_else(|| {
            default_trace_proxy_url(&config_path)
                .ok()
                .flatten()
                .unwrap_or_else(|| DEFAULT_TRACE_PROXY_URL.to_owned())
        });
        let trace = trace_via_proxy(&proxy_url).await;

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("trace_observation", &trace.encode_to_vec())
            .map_err(|err| Status::internal(format!("failed to store trace observation: {err}")))?;

        Ok(Response::new(trace))
    }

    async fn deploy(
        &self,
        request: Request<DeployRequest>,
    ) -> Result<Response<DeployResponse>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let request = request.into_inner();
        if !request.mock_provider {
            return Err(Status::failed_precondition(
                "legacy Deploy RPC no longer owns server deployment; use the canonical GitHub VM Application Lifecycle",
            ));
        }
        let result = deploy_orchestrator::execute(
            self,
            deploy_orchestrator::DeployCommand { request },
            deploy_orchestrator::RollbackPolicy::STRICT,
        )
        .await?;
        Ok(Response::new(result.response))
    }

    async fn destroy(
        &self,
        request: Request<DestroyRequest>,
    ) -> Result<Response<DestroyResponse>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let mut request = request.into_inner();
        request.instance_id = blank_option(request.instance_id.take());
        request.target_ip = blank_option(request.target_ip.take());
        request.dns_record_name = blank_option(request.dns_record_name.take());
        request.cloudflare_zone_name = blank_option(request.cloudflare_zone_name.take());
        request.lifecycle_reason = blank_option(request.lifecycle_reason.take());
        if !request.mock_provider {
            return Err(Status::failed_precondition(
                "legacy Destroy RPC no longer owns server or DNS mutation; use the canonical GitHub lifecycle",
            ));
        }
        let operation = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .start_operation("destroy", "RUNNING")
            .map_err(|err| Status::internal(format!("failed to create operation: {err}")))?;
        append_operation_event(&self.state, operation.id, "destroy requested")?;
        if let Some(reason) = request.lifecycle_reason.as_deref() {
            append_operation_event(
                &self.state,
                operation.id,
                &format!("lifecycle reason: {reason}"),
            )?;
        }

        let existing = match read_live_deployment_summary(&self.repo_root) {
            Ok(existing) => existing,
            Err(err) => {
                return Err(fail_destroy_operation(
                    &self.state,
                    operation.id,
                    "read recorded deployment",
                    Status::internal(format!("failed to read current state: {err}")),
                ));
            }
        };
        let target_ip = request
            .target_ip
            .clone()
            .or_else(|| existing.server_ip.clone())
            .unwrap_or_default();
        let instance_id = request
            .instance_id
            .clone()
            .or_else(|| existing.instance_id.clone())
            .unwrap_or_default();
        if let Err(err) = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .set_operation_target(
                operation.id,
                existing.deployment_label.as_deref(),
                (!instance_id.is_empty()).then_some(instance_id.as_str()),
                (!target_ip.is_empty()).then_some(target_ip.as_str()),
            )
        {
            return Err(fail_destroy_operation(
                &self.state,
                operation.id,
                "store recorded target",
                Status::internal(format!("failed to store destroy target: {err}")),
            ));
        }
        if let Err(status) = append_operation_event(
            &self.state,
            operation.id,
            &format!(
                "destroy target recorded: id={instance_id} label={} ip={target_ip}",
                existing.deployment_label.as_deref().unwrap_or("<missing>")
            ),
        ) {
            return Err(fail_destroy_operation(
                &self.state,
                operation.id,
                "record target event",
                status,
            ));
        }
        let mut warnings = Vec::new();

        if request.delete_dns {
            let note = match delete_dns_record(&self.state, &request).await {
                Ok(note) => note,
                Err(err) => {
                    return Err(fail_destroy_operation(
                        &self.state,
                        operation.id,
                        "delete DNS record",
                        Status::internal(err),
                    ));
                }
            };
            if let Err(status) = append_operation_event(&self.state, operation.id, &note) {
                return Err(fail_destroy_operation(
                    &self.state,
                    operation.id,
                    "record DNS deletion",
                    status,
                ));
            }
        }
        if let Err(status) = stop_local_runtime_for_destroy(
            &self.repo_root,
            &self.state,
            operation.id,
            &mut warnings,
        ) {
            return Err(fail_destroy_operation(
                &self.state,
                operation.id,
                "stop local runtime",
                status,
            ));
        }

        if let Err(err) = clear_live_deployment_state(
            &self.repo_root,
            &self.state,
            existing.deployment_label.as_deref(),
            &instance_id,
            &target_ip,
            operation.id,
        ) {
            return Err(fail_destroy_operation(
                &self.state,
                operation.id,
                "clear local deployment state",
                Status::internal(format!("failed to clear deployment state: {err}")),
            ));
        }
        let response = DestroyResponse {
            success: true,
            warnings: {
                if target_ip.trim().is_empty() {
                    warnings.push("destroy completed without a known target IP".to_owned());
                }
                warnings
            },
            operation: Some(operation_with_status(operation, "SUCCEEDED")),
            deployment: if existing.live_state_present {
                Some(existing)
            } else {
                None
            },
        };
        store_local_response(&self.state, "destroy_response", &response.encode_to_vec())?;
        Ok(Response::new(response))
    }

    async fn get_operation(
        &self,
        request: Request<GetOperationRequest>,
    ) -> Result<Response<OperationStatus>, Status> {
        let operation_id = request.into_inner().operation_id;
        let state = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?;
        let Some(operation) = state
            .get_operation(operation_id)
            .map_err(|err| Status::internal(format!("failed to read operation: {err}")))?
        else {
            return Err(Status::not_found(format!(
                "operation not found: {operation_id}"
            )));
        };
        let events = state
            .list_operation_events(operation_id)
            .map_err(|err| Status::internal(format!("failed to read operation events: {err}")))?;
        Ok(Response::new(OperationStatus {
            operation: Some(stored_operation_to_proto(operation)),
            recent_events: events.into_iter().map(stored_event_to_proto).collect(),
        }))
    }

    async fn list_operation_events(
        &self,
        request: Request<ListOperationEventsRequest>,
    ) -> Result<Response<ListOperationEventsResponse>, Status> {
        let operation_id = request.into_inner().operation_id;
        let events = self
            .state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .list_operation_events(operation_id)
            .map_err(|err| Status::internal(format!("failed to list operation events: {err}")))?;
        Ok(Response::new(ListOperationEventsResponse {
            events: events.into_iter().map(stored_event_to_proto).collect(),
        }))
    }

    async fn stage_credential_candidate(
        &self,
        request: Request<StageCredentialCandidateRequest>,
    ) -> Result<Response<CredentialStateObservation>, Status> {
        deny_legacy_windows_rpc_mutation()?;
        let bundle = request
            .into_inner()
            .bundle
            .ok_or_else(|| Status::invalid_argument("credential candidate bundle is required"))?;
        let state = stage_windows_credential_candidate(&self.repo_root, bundle)
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(CredentialStateObservation {
            state: Some(state),
        }))
    }

    async fn get_credential_state(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<CredentialStateObservation>, Status> {
        let state = observe_windows_credential_state(&self.repo_root)
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(CredentialStateObservation { state }))
    }
}
