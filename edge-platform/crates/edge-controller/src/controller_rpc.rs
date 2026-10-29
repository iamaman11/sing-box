use super::*;

#[tonic::async_trait]
impl ControllerService for ControllerServerImpl {
    async fn get_native_runtime_challenge(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<edge_shared_types::FleetWindowsRuntimeChallenge>, Status> {
        #[cfg(windows)]
        {
            return windows_native_runtime::challenge(&self.repo_root)
                .map(Response::new)
                .map_err(Status::permission_denied);
        }
        #[cfg(not(windows))]
        {
            Err(Status::unimplemented(
                "HOST_WINDOWS_EFFECT_WINDOWS_REQUIRED",
            ))
        }
    }
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
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
    }

    async fn set_secret_ref(
        &self,
        request: Request<SetSecretRefRequest>,
    ) -> Result<Response<SecretRefEntry>, Status> {
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
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
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
    }

    async fn start_local_runtime(
        &self,
        request: Request<StartLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        #[cfg(windows)]
        if !request.get_ref().native_system_effect.is_empty() {
            return windows_native_runtime::execute(&self.repo_root, request.into_inner())
                .await
                .map(Response::new)
                .map_err(Status::permission_denied);
        }
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
    }

    async fn stop_local_runtime(
        &self,
        request: Request<StopLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
    }

    async fn restart_local_runtime(
        &self,
        request: Request<RestartLocalRuntimeRequest>,
    ) -> Result<Response<LocalRuntimeResponse>, Status> {
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
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
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
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
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
    }

    async fn destroy(
        &self,
        request: Request<DestroyRequest>,
    ) -> Result<Response<DestroyResponse>, Status> {
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
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
        Err(Status::permission_denied(
            "HOST_WINDOWS_LEGACY_RPC_MUTATION_DISABLED_USE_SIGNED_HOST_INTENT",
        ))
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
