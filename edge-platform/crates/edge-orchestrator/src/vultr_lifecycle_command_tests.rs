#[test]
fn host_substrate_is_projected_from_one_validated_release_not_process_env() {
    use super::*;
    use edge_controller_core::orchestration::ReleaseContext;
    let release = ReleaseContext {
        accepted_revision: "f".repeat(40),
        source_revision: "a".repeat(40),
        release_set_sha256: "b".repeat(64),
        orchestrator_sha256: "1".repeat(64),
        agent_sha256: "2".repeat(64),
        docker_engine_version: "5:29.8.1-1~debian.13~trixie".to_owned(),
        containerd_version: "2.3.5-1~debian.13~trixie".to_owned(),
        compose_version: "5.5.1-1~debian.13~trixie".to_owned(),
        gateway_image: format!("ghcr.io/example/gateway@sha256:{}", "c".repeat(64)),
        warp_egress_image: format!("ghcr.io/example/warp@sha256:{}", "d".repeat(64)),
        mesh_image: format!("docker.io/cloudflare/mesh@sha256:{}", "e".repeat(64)),
    };
    let context = OrchestrationContext::new(release).expect("validated ReleaseSet");
    let substrate = pinned_host_substrate_versions(&context).expect("typed substrate");
    assert_eq!(
        substrate.docker_engine_version,
        "5:29.8.1-1~debian.13~trixie"
    );
    assert_eq!(substrate.containerd_version, "2.3.5-1~debian.13~trixie");
    assert_eq!(substrate.compose_version, "5.5.1-1~debian.13~trixie");
    assert!(
        HostSubstrateVersions::new(
            "untrusted;command".to_owned(),
            substrate.containerd_version,
            substrate.compose_version,
        )
        .is_err()
    );
}

#[test]
fn first_use_provider_plan_does_not_reserve_for_existing_or_ambiguous_vm() {
    use super::*;
    assert_eq!(
        admit_vm_first_use_provider_plan(Some(&PlanClass::Create), 1, false),
        Ok(())
    );
    for state in [
        PlanClass::Noop,
        PlanClass::UpdateInPlace,
        PlanClass::BlockedAmbiguous,
        PlanClass::BlockedDrift,
    ] {
        assert_eq!(
            admit_vm_first_use_provider_plan(Some(&state), 1, false),
            Err("HOST_FIRST_USE_PROVIDER_NOT_EXACT_CREATE_NO_REPLAY")
        );
    }
    assert_eq!(
        admit_vm_first_use_provider_plan(Some(&PlanClass::Create), 2, false),
        Err("HOST_FIRST_USE_PROVIDER_NOT_EXACT_CREATE_NO_REPLAY")
    );
    assert_eq!(
        admit_vm_first_use_provider_plan(None, 0, false),
        Err("HOST_FIRST_USE_PROVIDER_NOT_EXACT_CREATE_NO_REPLAY")
    );
    assert_eq!(
        admit_vm_first_use_provider_plan(Some(&PlanClass::Create), 1, true),
        Err("HOST_FIRST_USE_PROVIDER_OWNED_VM_ALREADY_PRESENT")
    );
}

#[test]
fn initial_reboot_can_only_reobserve_not_reapply_credentials() {
    assert!(super::authorize_initial_runtime_job("initial_vm_runtime", true).is_ok());
    assert!(super::authorize_initial_runtime_job("initial_vm_runtime", false).is_ok());
    assert!(super::authorize_initial_runtime_job("initial_reboot", false).is_ok());
    assert!(super::authorize_initial_runtime_job("initial_reboot", true).is_err());
    assert!(super::authorize_initial_runtime_job("initial_cleanup", false).is_err());
    assert!(super::authorize_initial_runtime_job("initial_pair_publish", true).is_err());
}

#[test]
fn vm_first_use_line2_evidence_refuses_aggregate_and_incomplete_claims() {
    let mut response = InitialVmCredentialRuntimeResponse::default();
    response.vm_local_line2 = [
        ("http-direct", "http", 4128),
        ("socks5-direct", "socks5h", 4080),
        ("https-direct", "https", 4443),
        ("http-warp", "http", 3128),
        ("socks5-warp", "socks5h", 1080),
        ("https-warp", "https", 9443),
    ]
    .iter()
    .map(
        |(name, protocol, port)| edge_shared_types::InitialVmLine2EndpointResult {
            endpoint: (*name).to_owned(),
            protocol: (*protocol).to_owned(),
            port: *port,
            successful_samples: 5,
            failed_samples: 0,
            negative_auth_rejected: true,
        },
    )
    .collect();
    assert!(require_six_exact_vm_local_line2(&response).is_ok());
    response.vm_local_line2[2].negative_auth_rejected = false;
    assert!(require_six_exact_vm_local_line2(&response).is_err());
    response.vm_local_line2[2].negative_auth_rejected = true;
    response.vm_local_line2[2].failed_samples = 1;
    assert!(require_six_exact_vm_local_line2(&response).is_err());
    response.vm_local_line2.pop();
    assert!(require_six_exact_vm_local_line2(&response).is_err());
}

#[test]
fn initial_vm_existing_access_reuse_demands_exact_bytes_and_root_owner() {
    let payload = initial_vm_access_identity_payload("client-id", "protected-secret").unwrap();
    let hash = ring::digest::digest(&ring::digest::SHA256, payload.as_bytes());
    let sha: String = hash.as_ref().iter().map(|x| format!("{x:02x}")).collect();
    assert!(
        validate_initial_vm_existing_identity("0:0:700", "0:0:600", &sha, payload.as_bytes())
            .is_ok()
    );
    for (dir, file, observed, bytes) in [
        ("0:0:755", "0:0:600", sha.as_str(), payload.as_bytes()),
        ("0:0:700", "1000:1000:600", sha.as_str(), payload.as_bytes()),
        ("0:0:700", "0:0:644", sha.as_str(), payload.as_bytes()),
        ("LINK", "0:0:600", sha.as_str(), payload.as_bytes()),
        ("0:0:700", "LINK", sha.as_str(), payload.as_bytes()),
        ("0:0:700", "0:0:600", "a", payload.as_bytes()),
        ("0:0:700", "0:0:600", sha.as_str(), b"other"),
    ] {
        assert!(validate_initial_vm_existing_identity(dir, file, observed, bytes).is_err());
    }
}

#[test]
fn initial_vm_access_payload_is_fixed_and_rejects_invalid_secrets() {
    let payload = initial_vm_access_identity_payload("id-123", "opaque-secret").unwrap();
    assert_eq!(
        payload,
        "CF_ACCESS_CLIENT_ID=id-123\nCF_ACCESS_CLIENT_SECRET=opaque-secret\n"
    );
    for (id, secret) in [
        ("", "valid"),
        ("valid", ""),
        ("valid\nCF_ACCESS_CLIENT_ID=forged", "valid"),
        ("valid", "not\nsafe"),
        ("has space", "valid"),
    ] {
        assert!(initial_vm_access_identity_payload(id, secret).is_err());
    }
}

#[test]
fn initial_native_host_attestation_never_targets_production_or_wrong_vm() {
    assert!(
        require_disposable_initial_probe_target(
            "infra/vultr/application-acceptance.json",
            "application-acceptance-1"
        )
        .is_ok()
    );
    for (spec, machine) in [
        ("infra/vultr/application-acceptance.json", "production-1"),
        (
            "infra/vultr/disposable-acceptance.json",
            "lifecycle-acceptance-1",
        ),
        ("infra/production/production.textproto", "production-1"),
        ("infra/vultr/application-acceptance.json", "wrong-machine"),
    ] {
        assert!(require_disposable_initial_probe_target(spec, machine).is_err());
    }
}

#[test]
fn disposable_ssh_forensics_never_target_production_or_wrong_machine() {
    assert!(is_disposable_ssh_forensic_target(
        "lifecycle-acceptance",
        "lifecycle-acceptance-1"
    ));
    assert!(is_disposable_ssh_forensic_target(
        "application-acceptance",
        "application-acceptance-1"
    ));
    assert!(!is_disposable_ssh_forensic_target(
        "production",
        "production-1"
    ));
    assert!(!is_disposable_ssh_forensic_target(
        "lifecycle-acceptance",
        "production-1"
    ));
    assert!(!is_disposable_ssh_forensic_target(
        "production",
        "lifecycle-acceptance-1"
    ));
}

use super::*;

#[test]
fn forensic_tcp_probe_is_single_attempt_and_never_mutates() {
    let policy = TcpReadinessPolicy {
        max_attempts: 1,
        max_elapsed: Duration::from_secs(3),
        connect_timeout: Duration::from_secs(3),
        backoff: Duration::ZERO,
    };
    assert_eq!(policy.max_attempts, 1);
    assert!(policy.validate().is_ok());
    assert_eq!(policy.backoff, Duration::ZERO);
}

#[tokio::test]
async fn forensic_tcp_failure_is_classified_without_retry() {
    let mut calls = 0usize;
    let observed = observe_tcp_readiness_with_probe(
        TcpReadinessPolicy {
            max_attempts: 1,
            max_elapsed: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(3),
            backoff: Duration::ZERO,
        },
        |_| {
            calls += 1;
            async { Err(TcpReadinessFailureClass::ConnectTimeout) }
        },
    )
    .await
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(observed.final_state, TcpReadinessState::Timeout);
    assert_eq!(
        observed.last_error_class,
        Some(TcpReadinessFailureClass::ConnectTimeout)
    );
}

#[test]
fn linux_boot_id_validation_is_strict() {
    assert!(validate_linux_boot_id("930df168-8e6b-4dff-ba80-3c24ed12fd86").is_ok());
    assert!(validate_linux_boot_id("").is_err());
    assert!(validate_linux_boot_id("same-boot").is_err());
    assert!(validate_linux_boot_id("930df168-8e6b-4dff-ba80-3c24ed12fd8z").is_err());
}

#[test]
fn firewall_binding_must_match_desired_profile() {
    let desired = DesiredState::parse_json(
        r#"{
  "schema": 1,
  "environment": "production",
  "machines": [
    {
      "id": "edge-1",
      "role": "edge",
      "provider": {
        "region": "waw",
        "plan": "vc2-1c-1gb",
        "os_id": 2625,
        "enable_ipv6": false,
        "firewall_profile": "edge"
      },
      "bootstrap_profile": "singbox-host-v2"
    }
  ]
}"#,
    )
    .unwrap();
    let resolved = ResolvedFirewallProfile {
        id: "fw-1".to_owned(),
        profile_name: "other".to_owned(),
    };

    let error = resolve_create_prerequisites(
        &desired.machines[0],
        "ssh-1",
        Some(&resolved),
        "#cloud-config\n".to_owned(),
    )
    .unwrap_err();
    assert!(error.contains("does not match desired profile"));
}

#[test]
fn production_support_access_profile_is_derived_from_protobuf_authority() {
    let desired = ProductionComposition::canonical().unwrap().machines;
    let (profiles, material) = load_access_authority_profile_source(&desired).unwrap();
    let profile = profiles.profile("production").unwrap();

    assert!(profile.rules.iter().any(|rule| {
        rule.protocol == "tcp"
            && rule.port == "22"
            && rule.subnet == "@controller-ipv4"
            && rule.subnet_size == 32
    }));
    assert_eq!(
        material,
        serde_json::Value::String(format!(
            "production-desired-state-sha256:{}",
            canonical_production_desired_state_sha256()
        ))
    );
}

#[test]
fn production_support_access_rejects_detached_machine_state() {
    let mut desired = ProductionComposition::canonical().unwrap().machines;
    desired.machines[0].tags.push("detached".to_owned());

    let error = load_access_authority_profile_source(&desired).unwrap_err();
    assert!(
        error.contains("does not match canonical ProductionDesiredState"),
        "{error}"
    );
}

#[test]
fn stale_support_access_authority_is_rejected_before_mutation() {
    let desired = serde_json::json!({
        "environment": "production",
        "machine_id": "edge-1",
        "operation": "ACQUIRE",
        "controller_ipv4": "203.0.113.50"
    });
    let plan = serde_json::json!({
        "action": "ACQUIRE",
        "machine_id": "edge-1",
        "firewall_profile": "edge"
    });
    let before = authorize_plan(
        "vultr_support_access",
        &desired,
        &serde_json::json!({"rules": []}),
        plan.clone(),
        PlanDisposition::Mutate,
    )
    .unwrap();
    let changed = authorize_plan(
        "vultr_support_access",
        &desired,
        &serde_json::json!({"rules": [{"id": 42, "subnet": "203.0.113.50/32"}]}),
        plan,
        PlanDisposition::Mutate,
    )
    .unwrap();

    let error =
        verify_exact_authority(&before.authority.authority_digest, &changed.authority).unwrap_err();
    assert!(error.to_string().contains("stale"));
}

#[test]
fn access_reconcile_allows_only_firewall_only_update() {
    use edge_controller_core::vultr_lifecycle::MachinePlan;

    let firewall_only = MachinePlan {
        machine_id: "edge-1".to_owned(),
        class: PlanClass::UpdateInPlace,
        provider_id: Some("provider-1".to_owned()),
        desired_spec_digest: "0".repeat(64),
        reasons: vec!["firewall profile differs or is not provider-verified".to_owned()],
    };
    assert_eq!(
        access_reconcile_class(&firewall_only),
        AccessReconcileClass::FirewallOnly
    );

    let mut mixed = firewall_only.clone();
    mixed.reasons.push("managed tags differ".to_owned());
    assert_eq!(
        access_reconcile_class(&mixed),
        AccessReconcileClass::Blocked
    );

    let mut create = firewall_only;
    create.class = PlanClass::Create;
    create.reasons = vec!["no exact owned provider resource exists".to_owned()];
    assert_eq!(
        access_reconcile_class(&create),
        AccessReconcileClass::Blocked
    );
}

fn operational_instance(power_status: &str, status: &str, server_status: &str) -> VultrInstance {
    VultrInstance {
        id: "instance-1".to_owned(),
        label: "edge-1".to_owned(),
        region: "waw".to_owned(),
        plan: "vc2-1c-1gb".to_owned(),
        status: status.to_owned(),
        server_status: server_status.to_owned(),
        power_status: power_status.to_owned(),
        main_ip: "203.0.113.10".to_owned(),
        v6_main_ip: String::new(),
        firewall_group_id: "fw-1".to_owned(),
        date_created: "2026-09-20T00:00:00Z".to_owned(),
        tags: Vec::new(),
        os_id: 2625,
        snapshot_id: None,
        enable_ipv6: false,
    }
}

#[test]
fn instance_action_disposition_uses_operational_state() {
    let running = operational_instance("running", "active", "ok");
    assert_eq!(
        instance_action_disposition(InstanceAction::Start, &running),
        (PlanDisposition::Noop, "NOOP")
    );
    assert_eq!(
        instance_action_disposition(InstanceAction::Halt, &running),
        (PlanDisposition::Mutate, "HALT")
    );
    assert_eq!(
        instance_action_disposition(InstanceAction::Reboot, &running),
        (PlanDisposition::Mutate, "REBOOT")
    );

    let stopped = operational_instance("stopped", "active", "ok");
    assert_eq!(
        instance_action_disposition(InstanceAction::Start, &stopped),
        (PlanDisposition::Mutate, "START")
    );
    assert_eq!(
        instance_action_disposition(InstanceAction::Halt, &stopped),
        (PlanDisposition::Noop, "NOOP")
    );
    assert_eq!(
        instance_action_disposition(InstanceAction::Reboot, &stopped),
        (PlanDisposition::Blocked, "BLOCKED")
    );
}

#[test]
fn timeout_provider_evidence_requires_exact_rule_and_attachment() {
    let target = crate::vultr_support_resources::FirewallRuleSpec {
        ip_type: "v4".to_owned(),
        protocol: "tcp".to_owned(),
        subnet: "203.0.113.25".to_owned(),
        subnet_size: 32,
        port: "22".to_owned(),
        source: String::new(),
        notes: "application acceptance controller SSH".to_owned(),
    };
    let targets = std::collections::BTreeSet::from([target.clone()]);
    let observed = VultrFirewallRule {
        id: 41,
        ip_type: target.ip_type.clone(),
        protocol: target.protocol.clone(),
        subnet: target.subnet.clone(),
        subnet_size: target.subnet_size,
        port: target.port.clone(),
        source: target.source.clone(),
        notes: target.notes.clone(),
    };

    let evidence = classify_support_access_provider_evidence(
        "203.0.113.25".to_owned(),
        Some("fw-1".to_owned()),
        &[observed],
        &targets,
        Some("fw-1".to_owned()),
        PlanDisposition::Noop,
    )
    .unwrap();

    assert_eq!(evidence.matching_rule_ids, vec![41]);
    assert!(evidence.exact_controller_rules_present_once);
    assert!(evidence.firewall_group_attached_to_machine);
    assert_eq!(evidence.acquire_plan_disposition, "NOOP");
}

#[test]
fn timeout_provider_evidence_exposes_missing_rule_and_detached_group() {
    let target = crate::vultr_support_resources::FirewallRuleSpec {
        ip_type: "v4".to_owned(),
        protocol: "tcp".to_owned(),
        subnet: "203.0.113.25".to_owned(),
        subnet_size: 32,
        port: "22".to_owned(),
        source: String::new(),
        notes: "application acceptance controller SSH".to_owned(),
    };
    let targets = std::collections::BTreeSet::from([target]);

    let evidence = classify_support_access_provider_evidence(
        "203.0.113.25".to_owned(),
        Some("fw-1".to_owned()),
        &[],
        &targets,
        Some("fw-other".to_owned()),
        PlanDisposition::Mutate,
    )
    .unwrap();

    assert!(evidence.matching_rule_ids.is_empty());
    assert!(!evidence.exact_controller_rules_present_once);
    assert!(!evidence.firewall_group_attached_to_machine);
    assert_eq!(evidence.acquire_plan_disposition, "MUTATE");
}

#[tokio::test]
async fn tcp_readiness_retries_probe_only_until_bounded_timeout() {
    let policy = TcpReadinessPolicy {
        max_attempts: 3,
        max_elapsed: Duration::from_secs(1),
        connect_timeout: Duration::from_millis(1),
        backoff: Duration::ZERO,
    };
    let mut calls = 0usize;
    let observation = observe_tcp_readiness_with_probe(policy, |_| {
        calls += 1;
        std::future::ready(Err(TcpReadinessFailureClass::ConnectionRefused))
    })
    .await
    .unwrap();

    assert_eq!(calls, 3);
    assert_eq!(observation.attempts, 3);
    assert_eq!(observation.final_state, TcpReadinessState::Timeout);
    assert_eq!(
        observation.last_error_class,
        Some(TcpReadinessFailureClass::ConnectionRefused)
    );
}

#[tokio::test]
async fn tcp_readiness_accepts_late_network_path_before_strict_ssh() {
    let policy = TcpReadinessPolicy {
        max_attempts: 4,
        max_elapsed: Duration::from_secs(1),
        connect_timeout: Duration::from_millis(1),
        backoff: Duration::ZERO,
    };
    let mut calls = 0usize;
    let observation = observe_tcp_readiness_with_probe(policy, |_| {
        calls += 1;
        std::future::ready(if calls < 3 {
            Err(TcpReadinessFailureClass::ConnectTimeout)
        } else {
            Ok(())
        })
    })
    .await
    .unwrap();

    assert_eq!(calls, 3);
    assert_eq!(observation.attempts, 3);
    assert_eq!(observation.final_state, TcpReadinessState::Ready);
    assert_eq!(
        observation.last_error_class,
        Some(TcpReadinessFailureClass::ConnectTimeout)
    );
}

#[test]
fn strict_ssh_failure_after_tcp_ready_keeps_protocol_failure_distinct() {
    let tcp = TcpReadinessObservation {
        attempts: 7,
        elapsed_ms: 1234,
        final_state: TcpReadinessState::Ready,
        last_error_class: Some(TcpReadinessFailureClass::ConnectTimeout),
    };
    let error =
        strict_ssh_error_after_tcp_ready(&tcp, "HOST_TRUST: certificate mismatch".to_owned());

    assert!(error.contains("TCP readiness passed"));
    assert!(error.contains("final_state=Ready"));
    assert!(error.contains("HOST_TRUST: certificate mismatch"));
    assert!(!error.contains("TCP readiness failed"));
}

#[test]
fn runner_registration_token_validation_is_secret_safe_and_bounded() {
    assert!(validate_runner_registration_token("A".repeat(32).as_str()).is_ok());
    assert!(validate_runner_registration_token("short").is_err());
    assert!(validate_runner_registration_token("token with space").is_err());
    assert!(validate_runner_registration_token(&"x".repeat(513)).is_err());
}

#[test]
fn retired_direct_vultr_mutation_cli_is_absent_from_compiled_source() {
    let source = include_str!("vultr_lifecycle_command.rs");
    assert!(!source.contains("pub async fn run(args: Vec<String>"));
    for mutation in [
        "run_destroy_apply(",
        "run_cleanup(",
        "run_action(",
        "run_substrate_apply(",
        "run_initial_vm_runtime(",
        "run_runner_bootstrap(",
    ] {
        assert!(
            !source.contains(mutation),
            "retired direct mutation {mutation}"
        );
    }
}
