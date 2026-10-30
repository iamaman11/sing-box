#[cfg(windows)]
#[test]
fn windows_child_exit_notification_is_native_process_handle_event() {
    let mut child = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 1",
        ])
        .spawn()
        .expect("spawn isolated Windows process");
    let result = super::wait_for_windows_child_exit(child.id());
    let exit = child.wait().expect("reap isolated Windows process");
    assert!(result.is_ok(), "OS event wait failed: {result:?}");
    assert!(exit.success());
}

#[test]
fn managed_child_exit_recovery_is_one_shot_and_refuses_all_intended_handoffs() {
    use super::child_exit_auto_recovery_allowed;
    assert!(child_exit_auto_recovery_allowed(
        false, false, false, false, true
    ));
    assert!(!child_exit_auto_recovery_allowed(
        true, false, false, false, true
    ));
    assert!(!child_exit_auto_recovery_allowed(
        false, true, false, false, true
    ));
    assert!(!child_exit_auto_recovery_allowed(
        false, false, true, false, true
    ));
    assert!(!child_exit_auto_recovery_allowed(
        false, false, false, true, true
    ));
    assert!(!child_exit_auto_recovery_allowed(
        false, false, false, false, false
    ));
}

use super::*;
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialDeliverySlot, RealityPublicIdentity,
    RealityPublicIdentityGeneration, TunnelAuthentication, TunnelAuthenticationGeneration,
    WindowsCredentialProjection, credential_delivery_bundle,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn start_rpc_rejects_force_restart_and_accepts_ordinary_idempotent_start() {
    assert!(require_nonrestarting_start(false).is_ok());
    let error = require_nonrestarting_start(true).unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
}

#[test]
fn windows_recovery_rejects_existing_tun_even_under_proxyonly_desired() {
    assert!(edge_singbox::require_no_windows_route_capture_config(
        br#"{"inbounds":[{"type":"mixed"},{"type":"socks"}]}"#
    )
    .is_ok());
    for sample in [
        br#"{"inbounds":[{"type":"tun","auto_route":true}]}"#.as_slice(),
        br#"{"inbounds":[{"type":"mixed"},{"type":"tun"}]}"#.as_slice(),
        br#"{"inbounds":[{"type":"redirect"}]}"#.as_slice(),
        b"corrupt".as_slice(),
    ] {
        assert!(
            edge_singbox::require_no_windows_route_capture_config(sample).is_err(),
            "a stale route-capturing config must not be restarted by SCM recovery"
        );
    }
}

#[test]
fn windows_service_startup_decision_is_mode_scoped_and_fail_closed() {
    use edge_local_runtime::ProcessObservation;

    let managed = ProcessObservation {
        pid: 10,
        name: "sing-box".to_owned(),
        executable_path: Some("sing-box".to_owned()),
        parent_pid: Some(1),
        command_line: "sing-box run -c managed.json".to_owned(),
        config_path: Some("managed.json".to_owned()),
    };
    let external = ProcessObservation {
        pid: 11,
        name: "sing-box".to_owned(),
        executable_path: Some("sing-box".to_owned()),
        parent_pid: Some(2),
        command_line: "sing-box run -c external.json".to_owned(),
        config_path: Some("external.json".to_owned()),
    };

    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Managed(managed.clone()),
            1,
            true,
            WindowsDatapathMode::ProxyOnly,
        ),
        WindowsStartupDecision::NoopManaged
    );
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Managed(managed.clone()),
            1,
            false,
            WindowsDatapathMode::ManagedTun,
        ),
        WindowsStartupDecision::BlockedUnprovenLine1
    );
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Absent,
            0,
            false,
            WindowsDatapathMode::ProxyOnly,
        ),
        WindowsStartupDecision::StartAbsent
    );
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Conflicting(vec![external.clone()]),
            0,
            false,
            WindowsDatapathMode::ProxyOnly,
        ),
        WindowsStartupDecision::StartAbsent
    );
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Conflicting(vec![managed.clone(), external.clone(),]),
            1,
            true,
            WindowsDatapathMode::ProxyOnly,
        ),
        WindowsStartupDecision::NoopManaged
    );
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Conflicting(vec![external.clone()]),
            0,
            false,
            WindowsDatapathMode::ManagedTun,
        ),
        WindowsStartupDecision::BlockedConflict
    );
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Conflicting(vec![managed.clone(), external]),
            1,
            false,
            WindowsDatapathMode::ManagedTun,
        ),
        WindowsStartupDecision::BlockedConflict
    );
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Conflicting(vec![managed.clone(), managed]),
            2,
            true,
            WindowsDatapathMode::ProxyOnly,
        ),
        WindowsStartupDecision::BlockedConflict
    );
}

#[test]
fn failed_scm_start_cleanup_is_exact_single_child_of_current_owner_only() {
    use edge_local_runtime::ProcessObservation;
    let own = ProcessObservation {
        pid: 20,
        name: "sing-box".to_owned(),
        executable_path: Some("sing-box".to_owned()),
        parent_pid: Some(10),
        command_line: "sing-box run -c owned.json".to_owned(),
        config_path: Some("owned.json".to_owned()),
    };
    let mut other = own.clone();
    other.pid = 21;
    other.parent_pid = Some(15);
    assert!(!failed_windows_scm_start_owns_child(&[], 10));
    assert!(failed_windows_scm_start_owns_child(&[own.clone()], 10));
    assert!(!failed_windows_scm_start_owns_child(&[own.clone()], 11));
    assert!(!failed_windows_scm_start_owns_child(&[other.clone()], 10));
    assert!(!failed_windows_scm_start_owns_child(&[own, other], 10));
}

#[test]
fn native_managed_tun_requires_real_pre_tun_authentication_on_every_start() {
    use edge_local_runtime::ProcessObservation;

    assert!(require_native_windows_route_capture_safety(WindowsDatapathMode::ProxyOnly).is_ok());
    for unsafe_mode in [
        WindowsDatapathMode::ManagedTun,
        WindowsDatapathMode::Unspecified,
    ] {
        assert!(
            require_native_windows_route_capture_safety(unsafe_mode)
                .unwrap_err()
                .contains("NATIVE_MANAGED_TUN_PREAUTH_BLOCKED"),
        );
    }
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Absent,
            0,
            false,
            WindowsDatapathMode::ManagedTun,
        ),
        WindowsStartupDecision::BlockedUnprovenLine1,
    );
    let orphan = ProcessObservation {
        pid: 77,
        name: "sing-box".to_owned(),
        executable_path: Some("sing-box".to_owned()),
        parent_pid: Some(12),
        command_line: "sing-box run -c orphan.json".to_owned(),
        config_path: Some("orphan.json".to_owned()),
    };
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Managed(orphan.clone()),
            1,
            false,
            WindowsDatapathMode::ManagedTun,
        ),
        WindowsStartupDecision::BlockedUnprovenLine1,
    );
    assert_eq!(
        windows_startup_decision(
            &RuntimeProcessClassification::Managed(orphan),
            1,
            true,
            WindowsDatapathMode::ManagedTun,
        ),
        WindowsStartupDecision::NoopManaged,
    );
}

#[test]
fn controller_service_panic_payload_is_bounded_to_safe_text_input() {
    let string_payload: Box<dyn std::any::Any + Send> = Box::new("service panic".to_owned());
    assert_eq!(
        controller_service_panic_message(string_payload.as_ref()),
        "service panic"
    );

    let static_payload: Box<dyn std::any::Any + Send> = Box::new("static panic");
    assert_eq!(
        controller_service_panic_message(static_payload.as_ref()),
        "static panic"
    );

    let opaque_payload: Box<dyn std::any::Any + Send> = Box::new(7_u32);
    assert_eq!(
        controller_service_panic_message(opaque_payload.as_ref()),
        "non-string Rust panic payload"
    );
}

#[test]
fn resolves_repo_root_from_workspace() {
    let repo_root = resolve_repo_root(None).unwrap();
    assert!(repo_root.exists());
}

#[tokio::test]
async fn installed_controller_legacy_rpc_stage_denied_without_changing_active_state() {
    let root = installed_windows_test_root();
    let store = CredentialStore::new(
        windows_credential_store_path(&root),
        CredentialProjectionKind::Windows,
    )
    .unwrap();
    store
        .stage_candidate(&windows_test_credential_bundle(
            100,
            CredentialDeliverySlot::A,
        ))
        .unwrap();
    let active = store.promote_candidate().unwrap().active.unwrap();

    let db_path = root.join("state/test-controller-state.sqlite");
    let server = ControllerServerImpl {
        repo_root: root.clone(),
        state: Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap())),
        agent_endpoint: DEFAULT_AGENT_ENDPOINT.to_owned(),
    };
    let denied = server
        .stage_credential_candidate(Request::new(StageCredentialCandidateRequest {
            bundle: Some(windows_test_credential_bundle(
                101,
                CredentialDeliverySlot::B,
            )),
        }))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    let observed = server
        .get_credential_state(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner()
        .state
        .unwrap();
    assert_eq!(observed.active.as_ref(), Some(&active));
    assert!(observed.candidate.is_none());
    assert!(observed.previous.is_none());

    drop(server);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn repo_controller_cannot_stage_windows_credentials() {
    let root = temp_repo_root();
    let error = stage_windows_credential_candidate(
        &root,
        windows_test_credential_bundle(101, CredentialDeliverySlot::B),
    )
    .unwrap_err();
    assert!(error.contains("installed EdgePlatformController authority layout"));
}

#[test]
fn invalid_windows_candidate_has_no_store_side_effect() {
    let root = installed_windows_test_root();
    let store_root = windows_credential_store_path(&root);

    let mut invalid = windows_test_credential_bundle(101, CredentialDeliverySlot::B);
    invalid.dummy_non_secret = true;
    assert!(stage_windows_credential_candidate(&root, invalid).is_err());
    assert!(!store_root.exists());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn generated_bootstrap_mode_names_are_stable() {
    assert_eq!(BootstrapMode::BootstrapBase.as_str_name(), "BOOTSTRAP_BASE");
    assert_eq!(
        BootstrapMode::BootstrapTunnel.as_str_name(),
        "BOOTSTRAP_TUNNEL"
    );
    assert_eq!(BootstrapMode::BootstrapFull.as_str_name(), "BOOTSTRAP_FULL");
}

#[tokio::test]
async fn installed_windows_status_does_not_probe_legacy_agent_rpc() {
    let root = installed_windows_test_root();
    std::fs::create_dir_all(root.join("state")).unwrap();
    let db_path = controller_state_db_path(&root);
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    let service = ControllerServerImpl {
        repo_root: root.clone(),
        state,
        agent_endpoint: "http://127.0.0.1:59999".to_owned(),
    };

    let response = service.get_status(Request::new(Empty {})).await.unwrap();
    let status = response.get_ref();
    assert!(status.agent_state.is_none());
    assert!(status.runtime.is_none());
    assert!(
        status
            .status_notes
            .iter()
            .all(|note| !note.contains("server agent")
                && !note.contains("server runtime observation"))
    );

    drop(service);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn installed_windows_doctor_omits_legacy_server_rpc_checks() {
    let root = installed_windows_test_root();
    std::fs::create_dir_all(root.join("state")).unwrap();
    let status = collect_controller_status(&root).unwrap();
    let checks = build_doctor_checks(
        &root,
        &status,
        None,
        None,
        &DoctorRequest {
            require_server_ready: true,
            ..DoctorRequest::default()
        },
    );

    assert!(
        checks
            .iter()
            .all(|check| check.name != "server.edge_agent_reachable"
                && check.name != "server.runtime_ready")
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn typed_diagnostic_evidence_does_not_copy_legacy_detail() {
    let mut check = DoctorCheck {
        name: "server.edge_agent_reachable".to_owned(),
        ok: false,
        detail: "provider_token=super-secret arbitrary transport exception".to_owned(),
        check_id: String::new(),
        status: CheckStatus::Unspecified as i32,
        subsystem: DiagnosticSubsystem::Unspecified as i32,
        evidence: Vec::new(),
    };

    enrich_doctor_check(&mut check);

    assert_eq!(check.check_id, "server.edge_agent_reachable");
    assert_eq!(check.status, CheckStatus::Fail as i32);
    assert_eq!(check.evidence.len(), 1);
    assert_eq!(check.evidence[0].code, "server.edge_agent_reachable.fail");
    assert!(!check.evidence[0].summary.contains("super-secret"));
    assert!(!check.evidence[0].summary.contains("exception"));
}

#[test]
fn formats_bootstrap_failure_message() {
    let message = format_bootstrap_failure(&BootstrapRuntimeResponse {
        success: false,
        mode: BootstrapMode::BootstrapTunnel as i32,
        exit_code: 12,
        stdout: String::new(),
        stderr: "container missing".to_owned(),
        post_state: None,
        warnings: vec!["tunnel container was not ready".to_owned()],
    });
    assert!(message.contains("bootstrap-runtime BOOTSTRAP_TUNNEL failed with exit code 12"));
    assert!(message.contains("container missing"));
    assert!(message.contains("tunnel container was not ready"));
}

#[test]
fn selects_unique_vultr_instance_and_fails_closed_on_ambiguity() {
    let first = mock_instance("edge-a", "waw", "vc2-1c-1gb", "203.0.113.10");
    let second = edge_provider_vultr::VultrInstance {
        id: "mock-second".to_owned(),
        ..first.clone()
    };

    assert!(
        select_unique_vultr_instance_by_label(&[], "edge-a")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        select_unique_vultr_instance_by_label(&[first.clone()], "edge-a")
            .unwrap()
            .unwrap()
            .id,
        first.id
    );
    let error = select_unique_vultr_instance_by_label(&[first, second], "edge-a").unwrap_err();
    assert!(error.contains("ambiguous Vultr instance identity"));
}

#[test]
fn blank_option_normalizes_empty_strings() {
    assert_eq!(blank_option(Some("".to_owned())), None);
    assert_eq!(blank_option(Some("   ".to_owned())), None);
    assert_eq!(
        blank_option(Some("  edge.alegria.by  ".to_owned())),
        Some("edge.alegria.by".to_owned())
    );
}

#[test]
fn merges_local_runtime_status() {
    let merged = merge_local_runtime(
        Some(edge_shared_types::LocalSingboxState {
            process_running: false,
            managed_config: true,
            expected_config_path: "config.json".to_owned(),
            active_config_path: None,
            clash_api_port: Some(9090),
            warnings: vec!["from config".to_owned()],
        }),
        edge_shared_types::LocalSingboxState {
            process_running: true,
            managed_config: false,
            expected_config_path: "other.json".to_owned(),
            active_config_path: Some("config.json".to_owned()),
            clash_api_port: None,
            warnings: vec!["from process".to_owned()],
        },
    );
    assert!(merged.managed_config);
    assert_eq!(merged.expected_config_path, "config.json");
    assert_eq!(merged.clash_api_port, Some(9090));
    assert_eq!(merged.warnings.len(), 2);
}

#[tokio::test]
async fn collects_status_through_service_impl() {
    let repo_root = temp_repo_root();
    std::fs::create_dir_all(repo_root.join("edge-platform/crates/edge-agent/src")).unwrap();
    std::fs::create_dir_all(repo_root.join("edge-platform/crates/edge-controller/src")).unwrap();
    std::fs::create_dir_all(repo_root.join("edge-platform/crates/edge-console/src")).unwrap();
    std::fs::create_dir_all(repo_root.join("edge-platform/proto")).unwrap();
    std::fs::create_dir_all(repo_root.join("win/vultr-waw/stack/tunnel-edge")).unwrap();
    std::fs::create_dir_all(repo_root.join("win/windows")).unwrap();
    std::fs::write(repo_root.join("edge-platform/Cargo.toml"), "").unwrap();
    std::fs::write(repo_root.join("edge-platform/README.md"), "").unwrap();
    std::fs::write(repo_root.join("edge-platform/FINALIZATION-PLAN.md"), "").unwrap();
    std::fs::write(
        repo_root.join("edge-platform/proto/edge_platform.proto"),
        "",
    )
    .unwrap();
    std::fs::write(
        repo_root.join("edge-platform/crates/edge-agent/src/main.rs"),
        "",
    )
    .unwrap();
    std::fs::write(
        repo_root.join("edge-platform/crates/edge-controller/src/main.rs"),
        "",
    )
    .unwrap();
    std::fs::write(
        repo_root.join("edge-platform/crates/edge-console/src/main.rs"),
        "",
    )
    .unwrap();
    std::fs::write(
        repo_root.join("win/vultr-waw/cloud-init.yaml"),
        "edge-agent.service",
    )
    .unwrap();
    std::fs::write(
        repo_root.join("win/vultr-waw/stack/docker-compose.yml"),
        "services: {}",
    )
    .unwrap();
    std::fs::write(
        repo_root.join("win/vultr-waw/stack/tunnel-edge/config.template.json"),
        "{}",
    )
    .unwrap();
    std::fs::write(
        repo_root.join("win/windows/edge-dns-clean-vultr-dual.json"),
        "{}",
    )
    .unwrap();
    std::fs::write(repo_root.join("win/vultr-waw/current-edge.json"), "{}").unwrap();
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-status-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    let service = ControllerServerImpl {
        repo_root: repo_root.clone(),
        state,
        agent_endpoint: "http://127.0.0.1:59999".to_owned(),
    };

    let response = service.get_status(Request::new(Empty {})).await.unwrap();
    assert!(response.get_ref().inventory.is_some());
    assert!(response.get_ref().runtime.is_some());
    let _ = std::fs::remove_dir_all(repo_root);
    let _ = std::fs::remove_file(db_path);
}

#[test]
fn formats_unknown_bootstrap_failure_message() {
    let message = format_bootstrap_failure(&BootstrapRuntimeResponse {
        success: false,
        mode: 99,
        exit_code: 8,
        stdout: String::new(),
        stderr: String::new(),
        post_state: None,
        warnings: vec![],
    });
    assert!(message.contains("UNKNOWN(99)"));
}

#[tokio::test]
async fn resolves_mock_deploy_target() {
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-resolve-target-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    let target = resolve_deploy_target(
        &state,
        &DeployRequest {
            label_prefix: Some("mock-edge".to_owned()),
            target_ip: None,
            instance_id: None,
            tunnel_domain: None,
            acme_email: None,
            dns_record_name: None,
            cloudflare_zone_name: None,
            mock_provider: true,
            skip_dns: true,
            snapshot_id: None,
        },
    )
    .await
    .unwrap();

    assert!(target.instance_id.starts_with("mock-"));
    assert_eq!(target.target_ip, "203.0.113.10");
    let _ = std::fs::remove_file(db_path);
}

#[test]
fn reads_live_deployment_summary_from_state_file() {
    let root = temp_repo_root();
    let state_dir = root.join("win/vultr-waw");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("current-edge.json"),
        r#"{"label":"edge-a","instance_id":"instance-1","ip":"203.0.113.5","tunnel":{"domain":"edge.example.com"}}"#,
    )
    .unwrap();

    let summary = read_live_deployment_summary(&root).unwrap();
    assert_eq!(summary.deployment_label.as_deref(), Some("edge-a"));
    assert_eq!(summary.instance_id.as_deref(), Some("instance-1"));
    assert_eq!(summary.server_ip.as_deref(), Some("203.0.113.5"));
    assert_eq!(summary.tunnel_domain.as_deref(), Some("edge.example.com"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn resolves_persisted_agent_target_from_state() {
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-state-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .record_deployment("deploy-1", "instance-1", "203.0.113.10")
            .unwrap();
        guard
            .upsert_trust_entry(NewTrustEntry {
                deployment_id: "deploy-1",
                instance_id: "instance-1",
                ip: "203.0.113.10",
                known_host_line: "",
                domain_name: Some("edge-agent"),
                ca_cert_path: Some("/tmp/ca.pem"),
                server_cert_path: Some("/tmp/agent-server.pem"),
                client_cert_path: Some("/tmp/controller-client.pem"),
                client_key_path: Some("/tmp/controller-client.key"),
            })
            .unwrap();
    }

    let target = resolve_persisted_agent_connection_target(&state)
        .unwrap()
        .unwrap();
    assert_eq!(target.endpoint, "https://203.0.113.10:50061");
    let tls_paths = target.tls_paths.unwrap();
    assert_eq!(
        tls_paths.client_key_path,
        PathBuf::from("/tmp/controller-client.key")
    );

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn resolves_persisted_agent_target_from_authoritative_controller_state() {
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-authoritative-target-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .upsert_controller_state(NewControllerState {
                active_deployment_label: Some("deploy-auth"),
                active_instance_id: Some("instance-auth"),
                active_server_ip: Some("203.0.113.77"),
                active_tunnel_domain: Some("edge.example.com"),
                active_deployment_state_json: None,
                deploy_phase: DeployPhase::InstanceAddressAssigned,
                app_readiness_phase: AppReadinessPhase::DeploymentAbsent,
                last_error_code: None,
                last_error_message: None,
            })
            .unwrap();
        guard
            .upsert_trust_entry(NewTrustEntry {
                deployment_id: "deploy-auth",
                instance_id: "instance-auth",
                ip: "203.0.113.77",
                known_host_line: "",
                domain_name: Some("edge-agent"),
                ca_cert_path: Some("/tmp/ca-auth.pem"),
                server_cert_path: Some("/tmp/agent-server-auth.pem"),
                client_cert_path: Some("/tmp/controller-client-auth.pem"),
                client_key_path: Some("/tmp/controller-client-auth.key"),
            })
            .unwrap();
    }

    let target = resolve_persisted_agent_connection_target(&state)
        .unwrap()
        .unwrap();
    assert_eq!(target.endpoint, "https://203.0.113.77:50061");
    assert_eq!(
        target.tls_paths.unwrap().client_key_path,
        PathBuf::from("/tmp/controller-client-auth.key")
    );

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn rejects_active_controller_target_without_persisted_trust() {
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-active-missing-trust-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .upsert_controller_state(NewControllerState {
                active_deployment_label: Some("deploy-missing"),
                active_instance_id: Some("instance-missing"),
                active_server_ip: Some("203.0.113.88"),
                active_tunnel_domain: Some("edge.example.com"),
                active_deployment_state_json: None,
                deploy_phase: DeployPhase::InstanceAddressAssigned,
                app_readiness_phase: AppReadinessPhase::DeploymentAbsent,
                last_error_code: None,
                last_error_message: None,
            })
            .unwrap();
    }

    let error = resolve_persisted_agent_connection_target(&state).unwrap_err();
    assert!(error.contains("instance-missing"));
    assert!(error.contains("203.0.113.88"));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn resolves_targeted_agent_target_for_redeploy() {
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-targeted-state-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .upsert_trust_entry(NewTrustEntry {
                deployment_id: "deploy-old",
                instance_id: "instance-9",
                ip: "203.0.113.19",
                known_host_line: "",
                domain_name: Some("edge-agent"),
                ca_cert_path: Some("/tmp/ca-old.pem"),
                server_cert_path: Some("/tmp/agent-server-old.pem"),
                client_cert_path: Some("/tmp/controller-client-old.pem"),
                client_key_path: Some("/tmp/controller-client-old.key"),
            })
            .unwrap();
    }

    let target = resolve_targeted_agent_connection_target(&state, "instance-9", "203.0.113.19")
        .unwrap()
        .unwrap();
    assert_eq!(target.endpoint, "https://203.0.113.19:50061");
    assert_eq!(
        target.tls_paths.unwrap().client_cert_path,
        PathBuf::from("/tmp/controller-client-old.pem")
    );

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn rejects_operation_target_without_persisted_trust_or_override() {
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-missing-trust-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    let target = ResolvedDeployTarget {
        instance_id: "instance-missing".to_owned(),
        target_ip: "203.0.113.99".to_owned(),
    };

    let error = resolve_operation_agent_connection_target(&state, &target, DEFAULT_AGENT_ENDPOINT)
        .unwrap_err();
    assert!(error.contains("no persisted agent trust"));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn bootstraps_existing_instance_via_ssh_when_trust_is_missing() {
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-bootstrap-ssh-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .upsert_secret_ref(SECRET_SSH_PRIVATE_KEY_PATH, "path:/tmp/id_rsa")
            .unwrap();
    }
    let request = DeployRequest {
        label_prefix: Some("waw-edge".to_owned()),
        target_ip: None,
        instance_id: Some("instance-bootstrap".to_owned()),
        tunnel_domain: None,
        acme_email: None,
        dns_record_name: None,
        cloudflare_zone_name: None,
        mock_provider: false,
        skip_dns: true,
        snapshot_id: None,
    };

    assert!(should_bootstrap_via_ssh(&state, &request, false));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn rejects_partial_persisted_tls_material() {
    let trust = StoredTrustEntry {
        id: 1,
        deployment_id: "deploy-1".to_owned(),
        instance_id: "instance-1".to_owned(),
        ip: "203.0.113.10".to_owned(),
        known_host_line: String::new(),
        domain_name: Some("edge-agent".to_owned()),
        ca_cert_path: Some("/tmp/ca.pem".to_owned()),
        server_cert_path: None,
        client_cert_path: Some("/tmp/controller-client.pem".to_owned()),
        client_key_path: None,
        updated_at_unix: 0,
    };
    let error = persisted_agent_tls_paths(&trust).unwrap_err();
    assert!(error.contains("incomplete client TLS paths"));
}

#[test]
fn rollback_restores_previous_live_state_and_clears_new_rows() {
    let root = temp_repo_root();
    let state_dir = root.join("win/vultr-waw");
    std::fs::create_dir_all(&state_dir).unwrap();
    let live_state_path = state_dir.join("current-edge.json");
    std::fs::write(
        &live_state_path,
        r#"{"label":"old","instance_id":"instance-1"}"#,
    )
    .unwrap();

    let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .record_deployment("deploy-new", "instance-1", "203.0.113.10")
            .unwrap();
        guard
            .upsert_trust_entry(NewTrustEntry {
                deployment_id: "deploy-new",
                instance_id: "instance-1",
                ip: "203.0.113.10",
                known_host_line: "",
                domain_name: Some("edge-agent"),
                ca_cert_path: Some("/tmp/ca.pem"),
                server_cert_path: Some("/tmp/agent-server.pem"),
                client_cert_path: Some("/tmp/controller-client.pem"),
                client_key_path: Some("/tmp/controller-client.key"),
            })
            .unwrap();
    }

    std::fs::write(
        &live_state_path,
        r#"{"label":"deploy-new","instance_id":"instance-1"}"#,
    )
    .unwrap();

    rollback_live_deployment_state(
        &root,
        &state,
        "deploy-new",
        "instance-1",
        "203.0.113.10",
        Some(r#"{"label":"old","instance_id":"instance-1"}"#),
        None,
    )
    .unwrap();

    let restored = std::fs::read_to_string(&live_state_path).unwrap();
    assert!(restored.contains(r#""label":"old""#));
    let guard = state.lock().unwrap();
    assert!(guard.latest_deployment().unwrap().is_none());
    assert!(guard.list_trust_entries().unwrap().is_empty());
    drop(guard);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rollback_restores_controller_snapshot_when_file_snapshot_is_missing() {
    let root = temp_repo_root();
    let state_dir = root.join("win/vultr-waw");
    std::fs::create_dir_all(&state_dir).unwrap();
    let live_state_path = state_dir.join("current-edge.json");
    std::fs::write(
        &live_state_path,
        r#"{"label":"deploy-new","instance_id":"instance-9"}"#,
    )
    .unwrap();

    let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    let previous_controller_state = {
        let guard = state.lock().unwrap();
        guard
            .upsert_controller_state(NewControllerState {
                active_deployment_label: Some("edge-old"),
                active_instance_id: Some("instance-old"),
                active_server_ip: Some("203.0.113.50"),
                active_tunnel_domain: Some("edge.example.com"),
                active_deployment_state_json: Some(
                    r#"{"label":"edge-old","instance_id":"instance-old","ip":"203.0.113.50","tunnel":{"domain":"edge.example.com"}}"#,
                ),
                deploy_phase: DeployPhase::DeploymentPublished,
                app_readiness_phase: AppReadinessPhase::ServerRuntimeReady,
                last_error_code: None,
                last_error_message: None,
            })
            .unwrap();
        guard
            .record_deployment("deploy-new", "instance-9", "203.0.113.10")
            .unwrap();
        guard
            .upsert_trust_entry(NewTrustEntry {
                deployment_id: "deploy-new",
                instance_id: "instance-9",
                ip: "203.0.113.10",
                known_host_line: "",
                domain_name: Some("edge-agent"),
                ca_cert_path: Some("/tmp/ca.pem"),
                server_cert_path: Some("/tmp/agent-server.pem"),
                client_cert_path: Some("/tmp/controller-client.pem"),
                client_key_path: Some("/tmp/controller-client.key"),
            })
            .unwrap();
        guard.get_controller_state().unwrap().unwrap()
    };

    rollback_live_deployment_state(
        &root,
        &state,
        "deploy-new",
        "instance-9",
        "203.0.113.10",
        None,
        Some(&previous_controller_state),
    )
    .unwrap();

    let restored = std::fs::read_to_string(&live_state_path).unwrap();
    assert!(restored.contains(r#""label":"edge-old""#));
    let guard = state.lock().unwrap();
    let controller_state = guard.get_controller_state().unwrap().unwrap();
    assert_eq!(
        controller_state.active_deployment_label.as_deref(),
        Some("edge-old")
    );
    assert!(guard.list_trust_entries().unwrap().is_empty());
    drop(guard);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rollback_is_idempotent_for_same_snapshot() {
    let root = temp_repo_root();
    let state_dir = root.join("win/vultr-waw");
    std::fs::create_dir_all(&state_dir).unwrap();
    let live_state_path = state_dir.join("current-edge.json");
    std::fs::write(
        &live_state_path,
        r#"{"label":"deploy-new","instance_id":"instance-9"}"#,
    )
    .unwrap();

    let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    let previous_controller_state = {
        let guard = state.lock().unwrap();
        guard
            .upsert_controller_state(NewControllerState {
                active_deployment_label: Some("edge-old"),
                active_instance_id: Some("instance-old"),
                active_server_ip: Some("203.0.113.50"),
                active_tunnel_domain: Some("edge.example.com"),
                active_deployment_state_json: Some(
                    r#"{"label":"edge-old","instance_id":"instance-old","ip":"203.0.113.50","tunnel":{"domain":"edge.example.com"}}"#,
                ),
                deploy_phase: DeployPhase::DeploymentPublished,
                app_readiness_phase: AppReadinessPhase::ServerRuntimeReady,
                last_error_code: None,
                last_error_message: None,
            })
            .unwrap();
        guard.get_controller_state().unwrap().unwrap()
    };

    rollback_live_deployment_state(
        &root,
        &state,
        "deploy-new",
        "instance-9",
        "203.0.113.10",
        None,
        Some(&previous_controller_state),
    )
    .unwrap();
    rollback_live_deployment_state(
        &root,
        &state,
        "deploy-new",
        "instance-9",
        "203.0.113.10",
        None,
        Some(&previous_controller_state),
    )
    .unwrap();

    let restored = std::fs::read_to_string(&live_state_path).unwrap();
    assert!(restored.contains(r#""label":"edge-old""#));
    let guard = state.lock().unwrap();
    let controller_state = guard.get_controller_state().unwrap().unwrap();
    assert_eq!(
        controller_state.active_deployment_label.as_deref(),
        Some("edge-old")
    );
    assert!(guard.latest_deployment().unwrap().is_none());
    assert!(guard.list_trust_entries().unwrap().is_empty());
    drop(guard);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn reconcile_restores_active_deployment_from_latest_deployment() {
    let root = temp_repo_root();
    let state_dir = root.join("win/vultr-waw");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("current-edge.json"),
        r#"{"label":"edge-recovered","instance_id":"instance-7","ip":"203.0.113.7","tunnel":{"domain":"edge.example.com"}}"#,
    )
    .unwrap();
    let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .record_deployment("edge-recovered", "instance-7", "203.0.113.7")
            .unwrap();
        guard.clear_controller_state().unwrap();
    }

    reconcile_active_deployment_state(&root, &state).unwrap();

    let guard = state.lock().unwrap();
    let controller_state = guard.get_controller_state().unwrap().unwrap();
    assert_eq!(
        controller_state.active_deployment_label.as_deref(),
        Some("edge-recovered")
    );
    assert!(
        controller_state
            .active_deployment_state_json
            .as_deref()
            .is_some_and(|value| value.contains(r#""instance_id":"instance-7""#))
    );
    drop(guard);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn reconcile_does_not_restore_authority_without_live_state_artifact() {
    let root = temp_repo_root();
    std::fs::create_dir_all(root.join("win/vultr-waw")).unwrap();
    let db_path = root.join("edge-platform/.runtime/test-controller-state.sqlite");
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .record_deployment("edge-stale", "instance-stale", "203.0.113.44")
            .unwrap();
        guard.clear_controller_state().unwrap();
    }

    reconcile_active_deployment_state(&root, &state).unwrap();

    let guard = state.lock().unwrap();
    let controller_state = guard.get_controller_state().unwrap().unwrap();
    assert!(controller_state.active_deployment_label.is_none());
    assert!(controller_state.active_instance_id.is_none());
    assert!(controller_state.active_server_ip.is_none());
    drop(guard);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn lists_seeded_secret_refs() {
    let db_path = std::env::temp_dir().join(format!(
        "edge-controller-secrets-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
    {
        let guard = state.lock().unwrap();
        guard
            .upsert_secret_ref("bootstrap.vultr.ssh_key_id", "env:EDGE_VULTR_SSH_KEY_ID")
            .unwrap();
    }
    let secrets = list_secret_refs(&state).unwrap();
    assert!(secrets.iter().any(|entry| {
        entry.name == SECRET_SSH_PRIVATE_KEY_PATH
            && entry.secret_ref == "env:EDGE_SSH_PRIVATE_KEY_PATH"
    }));
    assert!(
        secrets
            .iter()
            .all(|entry| entry.name != "bootstrap.vultr.ssh_key_id")
    );
    assert!(validate_secret_name("bootstrap.vultr.ssh_key_id").is_err());
    let _ = std::fs::remove_file(db_path);
}

#[cfg(windows)]
#[test]
fn windows_service_startup_leaves_unconfigured_install_root_untouched() {
    let root = installed_windows_test_root();
    let runtime_state = windows_runtime_state_path(&root);
    let config = local_singbox_config_path(&root);
    let _ = std::fs::remove_file(&runtime_state);
    let _ = std::fs::remove_file(&config);
    assert_eq!(
        converge_windows_runtime_on_service_start(&root).unwrap(),
        "NOT_CONFIGURED"
    );
    let _ = std::fs::remove_dir_all(root);
}

fn installed_windows_test_root() -> PathBuf {
    let root = temp_repo_root();
    std::fs::create_dir_all(root.join("releases")).unwrap();
    std::fs::write(root.join("current.pb"), b"test-activation").unwrap();
    root
}

fn windows_test_credential_bundle(
    generation: u64,
    slot: CredentialDeliverySlot,
) -> CredentialDeliveryBundle {
    let tunnel_auth = TunnelAuthenticationGeneration {
        generation: 7,
        direct: Some(TunnelAuthentication {
            vless_uuid: "00000000-0000-4000-8000-000000000001".to_owned(),
            hysteria2_password: "a".repeat(64),
            reality_short_id: "b".repeat(16),
        }),
        warp: Some(TunnelAuthentication {
            vless_uuid: "00000000-0000-4000-8000-000000000002".to_owned(),
            hysteria2_password: "c".repeat(64),
            reality_short_id: "d".repeat(16),
        }),
    };
    CredentialDeliveryBundle {
        schema_version: 1,
        generation,
        projection: CredentialProjectionKind::Windows as i32,
        dummy_non_secret: false,
        slot: slot as i32,
        payload: Some(credential_delivery_bundle::Payload::Windows(
            WindowsCredentialProjection {
                tunnel_auth: Some(tunnel_auth),
                reality_identity: Some(RealityPublicIdentityGeneration {
                    generation: 3,
                    direct: Some(RealityPublicIdentity {
                        public_key: "A".repeat(43),
                    }),
                    warp: Some(RealityPublicIdentity {
                        public_key: "B".repeat(43),
                    }),
                }),
            },
        )),
    }
}

fn temp_repo_root() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("edge-controller-test-{unique}"))
}
