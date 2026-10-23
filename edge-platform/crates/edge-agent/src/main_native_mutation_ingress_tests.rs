use super::*;

#[test]
fn vm_direct_mutation_cli_does_not_parse() {
    use clap::Parser;
    for name in [
        "bootstrap-base",
        "bootstrap-full",
        "bundle-converge",
        "bundle-rollback",
        "mesh-cleanup",
        "credential-stage",
        "credential-initial-apply",
        "credential-transition",
        "credential-existing-join",
    ] {
        assert!(cli::Cli::try_parse_from(["edge-agent", "local", name]).is_err());
    }
}

fn vm_scope_test() -> Vec<edge_shared_types::FleetVmContainer> {
    [
        ("vultr-line1-gateway", "line1-gateway"),
        ("vultr-line2-proxy", "line2-proxy"),
        ("vultr-warp-egress", "warp-egress"),
    ]
    .into_iter()
    .map(|(name, service)| edge_shared_types::FleetVmContainer {
        container_name: name.to_owned(),
        compose_project: "vultr-edge".to_owned(),
        compose_service: service.to_owned(),
    })
    .collect()
}

#[test]
fn foreign_same_named_container_never_proves_native_owner() {
    use edge_shared_types::FleetNativeOwnerState;
    let names = vec!["vultr-line2-proxy".to_owned()];
    assert_eq!(
        native_vm_owner_state(true, false, &names, &vm_scope_test()),
        FleetNativeOwnerState::Unproven
    );
    assert_eq!(
        native_vm_owner_state(true, true, &names, &vm_scope_test()),
        FleetNativeOwnerState::Running
    );
    assert_eq!(
        native_vm_owner_state(false, true, &names, &vm_scope_test()),
        FleetNativeOwnerState::Unproven
    );
    assert_eq!(
        native_vm_owner_state(
            true,
            true,
            &["vultr-cloudflare-mesh".to_owned()],
            &vm_scope_test()
        ),
        FleetNativeOwnerState::Stopped
    );
}
#[test]
fn vm_owned_runtime_scope_excludes_unrelated_docker_workloads() {
    let foreign = vec![
        "vultr-cloudflare-mesh".to_owned(),
        "unrelated-project-db".to_owned(),
        "some-other-sing-box".to_owned(),
    ];
    assert!(!owned_application_container_running(
        &foreign,
        &vm_scope_test()
    ));
    for own in [
        "vultr-warp-egress",
        "vultr-line1-gateway",
        "vultr-line2-proxy",
    ] {
        let mut names = foreign.clone();
        names.push(own.to_owned());
        assert!(owned_application_container_running(
            &names,
            &vm_scope_test()
        ));
    }
    // Names must match exactly, not by substring or prefix.
    assert!(!owned_application_container_running(
        &[
            "vultr-line1-gateway-other".into(),
            "prefix-vultr-warp-egress".into(),
        ],
        &vm_scope_test()
    ));
}

use super::*;
use edge_shared_types::agent_service_server::AgentService;
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialDeliverySlot, ProxyCredentialGeneration,
    RealityPrivateIdentity, RealityPrivateIdentityGeneration, TunnelAuthentication,
    TunnelAuthenticationGeneration, VmCredentialProjection, credential_delivery_bundle,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

fn initial_policy_test_bundle() -> ApplyBundleRequest {
    let mut request = ApplyBundleRequest {
        stack_files: vec![
            BundleFile {
                relative_path: "docker-compose.yml".to_owned(),
                content: b"services: {}\n".to_vec(),
                executable: false,
                sensitive: false,
            },
            BundleFile {
                relative_path: RUNTIME_POLICY_FILE.to_owned(),
                content: b"PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n"
                    .to_vec(),
                executable: false,
                sensitive: false,
            },
            BundleFile {
                relative_path: IMAGE_ENV_FILE.to_owned(),
                content: concat!(
                    "EDGE_GATEWAY_IMAGE=ghcr.io/iamaman11/vultr-edge-gateway@sha256:",
                    "1111111111111111111111111111111111111111111111111111111111111111\n",
                    "EDGE_WARP_EGRESS_IMAGE=ghcr.io/iamaman11/vultr-warp-egress@sha256:",
                    "2222222222222222222222222222222222222222222222222222222222222222\n",
                    "CLOUDFLARE_MESH_IMAGE=docker.io/cloudflare/mesh@sha256:",
                    "3333333333333333333333333333333333333333333333333333333333333333\n",
                )
                .as_bytes()
                .to_vec(),
                executable: false,
                sensitive: false,
            },
        ],
        host_files: Vec::new(),
        deployment_summary: None,
        agent_env_file: None,
        prune_existing: true,
        bundle_id: Some("fresh-n1".to_owned()),
        bundle_digest: None,
    };
    request.bundle_digest = Some(canonical_apply_bundle_digest(&request).unwrap());
    request
}

#[test]
fn fresh_policy_only_bundle_stages_without_credentials_and_cannot_replay() {
    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    let stack = root.join("stack");
    let request = initial_policy_test_bundle();

    validate_initial_policy_bundle_request(&request).unwrap();
    require_empty_vm_initial_bundle_host(&stack).unwrap();
    let staged = apply_digest_bound_bundle(&stack, request.clone(), true).unwrap();
    assert_eq!(staged.active_bundle_id.as_deref(), Some("fresh-n1"));
    assert!(stack.join("docker-compose.yml").is_file());
    assert!(stack.join(RUNTIME_POLICY_FILE).is_file());
    assert!(stack.join(IMAGE_ENV_FILE).is_file());
    assert!(!stack.join(RUNTIME_ENV_FILE).exists());
    assert!(!root.join(PREVIOUS_STACK_DIR).exists());
    require_initial_vm_policy_bundle_ready(&stack).unwrap();

    assert!(
        apply_digest_bound_bundle(&stack, request, true)
            .unwrap_err()
            .contains("existing application stack content")
    );
    assert!(observe_vm_credential_state(&stack).unwrap().is_none());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fresh_policy_only_bundle_rejects_secrets_incomplete_digest_and_partial_host() {
    let mut request = initial_policy_test_bundle();
    request
        .stack_files
        .retain(|file| file.relative_path != IMAGE_ENV_FILE);
    assert!(validate_initial_policy_bundle_request(&request).is_err());

    let mut request = initial_policy_test_bundle();
    request.stack_files.push(BundleFile {
        relative_path: RUNTIME_ENV_FILE.to_owned(),
        content: b"PROXY_PASSWORD=forbidden\n".to_vec(),
        executable: false,
        sensitive: true,
    });
    assert!(
        validate_initial_policy_bundle_request(&request)
            .unwrap_err()
            .contains("must not contain credentials")
    );

    let mut request = initial_policy_test_bundle();
    request.stack_files.push(request.stack_files[0].clone());
    assert!(
        validate_initial_policy_bundle_request(&request)
            .unwrap_err()
            .contains("duplicate")
    );

    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&root).unwrap();
    let staged = root.join(STAGING_STACK_DIR);
    fs::create_dir_all(&staged).unwrap();
    assert!(require_empty_vm_initial_bundle_host(&stack).is_err());
    assert!(apply_digest_bound_bundle(&stack, initial_policy_test_bundle(), true).is_err());
    assert!(!stack.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn initial_vm_enrollment_refuses_unobservable_docker_state() {
    assert!(
        require_no_vm_application_containers(&DockerObservation::unreachable())
            .unwrap_err()
            .contains("unknown Docker daemon state")
    );
}

#[test]
fn initial_vm_enrollment_refuses_legacy_runtime_or_partial_state() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    assert!(require_empty_vm_initial_credential_host(&stack).is_ok());

    let env = stack.join(RUNTIME_ENV_FILE);
    fs::write(&env, "LEGACY_SECRET=opaque\\n").unwrap();
    assert!(
        require_empty_vm_initial_credential_host(&stack)
            .unwrap_err()
            .contains("runtime artifact")
    );
    fs::remove_file(&env).unwrap();

    let old = legacy_vm_runtime_secret_path(&stack).unwrap();
    fs::create_dir_all(old.parent().unwrap()).unwrap();
    fs::write(&old, "opaque").unwrap();
    assert!(
        require_empty_vm_initial_credential_host(&stack)
            .unwrap_err()
            .contains("legacy runtime")
    );
    fs::remove_file(&old).unwrap();

    let rendered = stack.join("rendered/line1-gateway.json");
    fs::create_dir_all(rendered.parent().unwrap()).unwrap();
    fs::write(&rendered, "{}").unwrap();
    assert!(
        require_empty_vm_initial_credential_host(&stack)
            .unwrap_err()
            .contains("runtime artifact")
    );
    fs::remove_file(&rendered).unwrap();

    let store = vm_credential_store_root(&stack).unwrap();
    fs::create_dir_all(&store).unwrap();
    assert!(
        require_empty_vm_initial_credential_host(&stack)
            .unwrap_err()
            .contains("absent v2 store")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn invalid_vm_candidate_has_no_store_side_effect() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    let store_root = vm_credential_store_root(&stack).unwrap();

    let mut invalid = vm_test_credential_bundle(101, CredentialDeliverySlot::B);
    invalid.dummy_non_secret = true;
    assert!(stage_vm_credential_candidate(&stack, invalid).is_err());
    assert!(!store_root.exists());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn application_rpc_refuses_legacy_bundle_and_host_file_writes() {
    let root = unique_test_dir();
    let stack = root.join("stack");

    let legacy = ApplyBundleRequest {
        stack_files: vec![BundleFile {
            relative_path: "docker-compose.yml".to_owned(),
            content: b"services: {}\\n".to_vec(),
            executable: false,
            sensitive: false,
        }],
        host_files: vec![BundleFile {
            relative_path: "tls/ca.pem".to_owned(),
            content: b"ca".to_vec(),
            executable: false,
            sensitive: false,
        }],
        deployment_summary: None,
        agent_env_file: None,
        prune_existing: true,
        bundle_id: None,
        bundle_digest: None,
    };
    assert!(apply_bundle(&stack, legacy.clone()).is_err());
    assert!(!stack.exists());
    assert!(!root.join("tls/ca.pem").exists());

    let mut partially_bound = legacy.clone();
    partially_bound.bundle_id = Some("release-a".to_owned());
    assert!(apply_bundle(&stack, partially_bound).is_err());
    assert!(!stack.exists());

    let mut forged = legacy;
    forged.bundle_id = Some("release-a".to_owned());
    let digest = canonical_apply_bundle_digest(&forged).unwrap();
    forged.bundle_digest = Some(digest);
    assert!(apply_bundle(&stack, forged).is_err());
    assert!(!stack.exists());
    assert!(!root.join("tls/ca.pem").exists());
}

#[test]
fn digest_bound_bundle_is_idempotent_and_rollback_swaps_exact_release() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();

    let make_request = |bundle_id: &str, body: &[u8]| {
        let mut request = ApplyBundleRequest {
            stack_files: vec![BundleFile {
                relative_path: "docker-compose.yml".to_owned(),
                content: body.to_vec(),
                executable: false,
                sensitive: false,
            }],
            host_files: Vec::new(),
            deployment_summary: None,
            agent_env_file: None,
            prune_existing: true,
            bundle_id: Some(bundle_id.to_owned()),
            bundle_digest: None,
        };
        let digest = canonical_apply_bundle_digest(&request).unwrap();
        request.bundle_digest = Some(digest.clone());
        (request, digest)
    };

    let (first, first_digest) = make_request("release-a", b"services: {a: {}}\n");
    let first_response = apply_bundle(&stack, first.clone()).unwrap();
    assert_eq!(
        first_response.active_bundle_digest.as_deref(),
        Some(first_digest.as_str())
    );

    let noop_response = apply_bundle(&stack, first).unwrap();
    assert!(noop_response.written_paths.is_empty());

    let (second, second_digest) = make_request("release-b", b"services: {b: {}}\n");
    let second_response = apply_bundle(&stack, second).unwrap();
    assert_eq!(
        second_response.previous_bundle_digest.as_deref(),
        Some(first_digest.as_str())
    );

    let rolled_back = rollback_bundle(
        &stack,
        RollbackBundleRequest {
            expected_current_bundle_digest: second_digest.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        rolled_back.active_bundle_digest.as_deref(),
        Some(first_digest.as_str())
    );
    assert_eq!(
        rolled_back.previous_bundle_digest.as_deref(),
        Some(second_digest.as_str())
    );
    assert_eq!(
        fs::read_to_string(stack.join("docker-compose.yml")).unwrap(),
        "services: {a: {}}\n"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_bundle_transport_accepts_only_exact_digest_bound_stack_bundle() {
    let mut request = ApplyBundleRequest {
        stack_files: vec![BundleFile {
            relative_path: "docker-compose.yml".to_owned(),
            content: b"services: {}\n".to_vec(),
            executable: false,
            sensitive: false,
        }],
        host_files: Vec::new(),
        deployment_summary: None,
        agent_env_file: None,
        prune_existing: true,
        bundle_id: Some("release-a".to_owned()),
        bundle_digest: None,
    };
    let digest = canonical_apply_bundle_digest(&request).unwrap();
    request.bundle_digest = Some(digest.clone());

    let (bundle_id, observed_digest) = validate_digest_bound_bundle_request(&request).unwrap();
    assert_eq!(bundle_id, "release-a");
    assert_eq!(observed_digest, digest);

    let mut tampered = request.clone();
    tampered.stack_files[0].content = b"services: {changed: {}}\n".to_vec();
    assert!(validate_digest_bound_bundle_request(&tampered).is_err());

    let mut host_mutation = request;
    host_mutation.host_files.push(BundleFile {
        relative_path: "forbidden".to_owned(),
        content: Vec::new(),
        executable: false,
        sensitive: false,
    });
    assert!(validate_digest_bound_bundle_request(&host_mutation).is_err());
}

#[test]
fn mesh_warp_cli_probes_accept_tos_non_interactively() {
    assert_eq!(
        mesh_warp_cli_probe_args("status"),
        ["exec", MESH_CONTAINER, "warp-cli", "--accept-tos", "status"]
    );
    assert_eq!(
        mesh_warp_cli_probe_args("settings"),
        [
            "exec",
            MESH_CONTAINER,
            "warp-cli",
            "--accept-tos",
            "settings",
        ]
    );
}

#[test]
fn typed_mesh_probe_does_not_confuse_disconnected_with_connected() {
    let disconnected = BoundedCommandProbe {
        status: RuntimeProbeStatus::Ok,
        exit_code: Some(0),
        stdout: "Status update: Disconnected\n".to_owned(),
        stderr: String::new(),
    };
    assert_eq!(
        parse_warp_connection_state(&disconnected).as_deref(),
        Some("DISCONNECTED")
    );

    let connected = BoundedCommandProbe {
        status: RuntimeProbeStatus::Ok,
        exit_code: Some(0),
        stdout: "Status update: Connected\n".to_owned(),
        stderr: String::new(),
    };
    assert_eq!(
        parse_warp_connection_state(&connected).as_deref(),
        Some("CONNECTED")
    );
}

#[test]
fn failed_warp_observation_is_not_explicit_disconnection() {
    let failed = BoundedCommandProbe {
        status: RuntimeProbeStatus::NonZero,
        exit_code: Some(1),
        stdout: String::new(),
        stderr: "daemon IPC unavailable".to_owned(),
    };
    assert_eq!(parse_warp_connection_state(&failed), None);

    let explicit = BoundedCommandProbe {
        status: RuntimeProbeStatus::NonZero,
        exit_code: Some(1),
        stdout: "Status update: Disconnected\n".to_owned(),
        stderr: "non-zero CLI status".to_owned(),
    };
    assert_eq!(
        parse_warp_connection_state(&explicit).as_deref(),
        Some("DISCONNECTED")
    );
}

#[test]
fn non_zero_warp_probe_can_preserve_explicit_connected_state() {
    let connected = BoundedCommandProbe {
        status: RuntimeProbeStatus::NonZero,
        exit_code: Some(1),
        stdout: "Status update: Connected\n".to_owned(),
        stderr: "non-zero CLI status".to_owned(),
    };
    assert_eq!(
        parse_warp_connection_state(&connected).as_deref(),
        Some("CONNECTED")
    );
}

#[test]
fn typed_mesh_probe_normalizes_known_tunnel_protocols() {
    let masque = BoundedCommandProbe {
        status: RuntimeProbeStatus::Ok,
        exit_code: Some(0),
        stdout: "tunnel protocol: MASQUE\n".to_owned(),
        stderr: String::new(),
    };
    assert_eq!(parse_tunnel_protocol(&masque).as_deref(), Some("MASQUE"));

    let wireguard = BoundedCommandProbe {
        status: RuntimeProbeStatus::Ok,
        exit_code: Some(0),
        stdout: "protocol = WireGuard\n".to_owned(),
        stderr: String::new(),
    };
    assert_eq!(
        parse_tunnel_protocol(&wireguard).as_deref(),
        Some("WIREGUARD")
    );
}

#[test]
fn mesh_failure_snapshot_is_bounded_secret_safe_and_persistent() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();

    let mut diagnostics = MeshRuntimeDiagnostics::default();
    diagnostics.warp_connection_state = Some("DISCONNECTED".to_owned());
    diagnostics.tunnel_protocol = Some("MASQUE".to_owned());
    diagnostics.warp_status_probe = Some(RuntimeProbeEvidence {
        status: RuntimeProbeStatus::NonZero as i32,
        exit_code: Some(1),
        diagnostic_stdout: None,
        diagnostic_stderr: None,
    });
    diagnostics.container = Some(MeshContainerDiagnostics {
        present: true,
        running: false,
        exit_code: Some(137),
        runtime_error_present: true,
        recent_events: Vec::new(),
        name: MESH_CONTAINER.to_owned(),
        image: Some("docker.io/cloudflare/mesh@sha256:test".to_owned()),
        restart_count: Some(3),
        oom_killed: Some(true),
        networks: vec!["mesh_net".to_owned()],
    });

    let reasons = vec![
        "Authorization: Bearer should-not-escape".to_owned(),
        "x".repeat(MAX_MESH_FAILURE_REASON_CHARS * 2),
    ];
    let snapshot = build_mesh_runtime_failure_snapshot(Some(&diagnostics), &reasons, false);
    assert_eq!(snapshot.reasons[0], "[REDACTED_SENSITIVE_REASON]");
    assert_eq!(
        snapshot.reasons[1].chars().count(),
        MAX_MESH_FAILURE_REASON_CHARS
    );
    assert_eq!(snapshot.container_restart_count, Some(3));
    assert_eq!(snapshot.container_oom_killed, Some(true));
    assert_eq!(
        snapshot.container_image.as_deref(),
        Some("docker.io/cloudflare/mesh@sha256:test")
    );
    assert_eq!(snapshot.container_networks, vec!["mesh_net"]);
    assert!(!snapshot.exact_image_ready);

    persist_mesh_runtime_failure_snapshot(&stack, &snapshot).unwrap();
    let restored = read_mesh_runtime_failure_snapshot(&stack).unwrap().unwrap();
    assert_eq!(restored.reasons, snapshot.reasons);
    assert_eq!(
        restored.warp_connection_state.as_deref(),
        Some("DISCONNECTED")
    );
    assert_eq!(restored.container_exit_code, Some(137));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn certificate_readiness_requires_complete_valid_material() {
    let mut evidence = CertificateReadinessEvidence {
        cert_present: true,
        key_present: true,
        key_nonempty: true,
        cert_valid: false,
        line1: Some(ContainerRuntimeEvidence {
            present: true,
            running: true,
            exit_code: None,
            runtime_error: None,
            log_tail: Vec::new(),
            name: LINE1_CONTAINER.to_owned(),
            image: None,
            restart_count: Some(0),
            oom_killed: Some(false),
            health: Some("HEALTHY".to_owned()),
            networks: Vec::new(),
            published_ports: Vec::new(),
            mounts: Vec::new(),
        }),
        docker_observation_error: None,
    };
    assert!(!evidence.ready());

    evidence.cert_valid = true;
    assert!(evidence.ready());
    assert!(evidence.summary().contains("running=true"));
}

#[test]
fn runtime_policy_rejects_incomplete_or_shell_unsafe_values() {
    assert!(validate_runtime_policy_env("PROXY_USERNAME=acceptance\n").is_err());
    assert!(
        validate_runtime_policy_env(
            "PROXY_USERNAME=$(touch/tmp/pwn)\nPROXY_CERT_CN=acceptance.local\n"
        )
        .is_err()
    );
    assert!(
        validate_runtime_policy_env(
            "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n"
        )
        .is_ok()
    );
    assert!(
        validate_runtime_policy_env(
            "REALITY_SERVER_NAME=reality.example.com\nTUNNEL_DOMAIN=tunnel.example.com\nACME_EMAIL=edge@example.com\n"
        )
        .is_err()
    );
    assert!(
        validate_runtime_policy_env(
            "REALITY_SERVER_NAME=reality.example.com\nTUNNEL_DOMAIN=tunnel.example.com\nACME_EMAIL=edge@example.com\nACME_PROVIDER=letsencrypt\n"
        )
        .is_ok()
    );
    assert!(
        validate_runtime_policy_env(
            "REALITY_SERVER_NAME=reality.example.com\nTUNNEL_DOMAIN=tunnel.example.com\nACME_EMAIL=edge@example.com\nACME_PROVIDER=https://acme-staging-v02.api.letsencrypt.org/directory\nPROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n"
        )
        .is_ok()
    );
    assert!(
        validate_runtime_policy_env(
            "REALITY_SERVER_NAME=reality.example.com\nTUNNEL_DOMAIN=tunnel.example.com\nACME_EMAIL=edge@example.com\nACME_PROVIDER=letsencrypt\nUNKNOWN_POLICY=value\n"
        )
        .is_err()
    );
}

#[test]
fn vm_v2_credential_store_stays_inside_runtime_secret_boundary() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    assert_eq!(
        vm_credential_store_root(&stack).unwrap(),
        root.join("runtime-secrets/application-v2")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn first_use_vm_runtime_response_never_claims_external_acceptance() {
    let response = initial_vm_runtime_response(
        101,
        true,
        vec![line2_quality::EndpointProof {
            name: "http-direct",
            protocol: "http",
            port: 4128,
            successes: 5,
            failures: 0,
            negative_auth_rejected: true,
        }],
    );
    assert!(response.candidate_unpromoted);
    assert!(response.vm_local_line2[0].negative_auth_rejected);
    assert!(response.candidate_materialized);
    assert_eq!(response.vm_local_line2.len(), 1);
    assert!(!response.external_line1_proven);
    assert!(!response.external_line2_proven);
    assert!(!response.direct_warp_egress_distinct_proven);
}

#[test]
fn vm_initial_functional_gate_requires_exact_unpromoted_candidate() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    let store = CredentialStore::new(
        vm_credential_store_root(&stack).unwrap(),
        CredentialProjectionKind::Vm,
    )
    .unwrap();
    let empty = LocalCredentialState::default();
    assert!(validate_unpromoted_vm_initial_state(&empty, 109).is_err());
    let bundle = vm_test_credential_bundle(109, CredentialDeliverySlot::A);
    let state = store.stage_delivery_candidate(&bundle).unwrap();
    assert!(validate_unpromoted_vm_initial_state(&state, 109).is_ok());
    assert!(validate_unpromoted_vm_initial_state(&state, 110).is_err());
    assert!(validate_unpromoted_vm_initial_state(&state, 0).is_err());
    let mut unexpected_active = state.clone();
    unexpected_active.active = unexpected_active.candidate.take();
    assert!(validate_unpromoted_vm_initial_state(&unexpected_active, 109).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn vm_initial_promotion_cannot_adopt_unproven_legacy_runtime() {
    let no_active_v2 = LocalCredentialState::default();
    let err = require_vm_active_v2_for_promotion(&no_active_v2).unwrap_err();
    assert!(err.contains("refuses initial enrollment"));
}

#[test]
fn vm_candidate_promotion_cannot_commit_an_unapplied_worker_generation() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    fs::write(
        stack.join(RUNTIME_POLICY_FILE),
        "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
    )
    .unwrap();
    let candidate = vm_test_credential_bundle(109, CredentialDeliverySlot::A);
    assert!(verify_vm_candidate_runtime_materialized(&stack, &candidate).is_err());

    fs::write(stack.join(RUNTIME_ENV_FILE), "arbitrary=other-source\n").unwrap();
    let error = verify_vm_candidate_runtime_materialized(&stack, &candidate).unwrap_err();
    assert!(error.contains("differs from candidate"));

    let secrets = ApplicationRuntimeSecrets::from_vm_bundle(&candidate).unwrap();
    write_vm_runtime_environment(&stack, &secrets).unwrap();
    verify_vm_candidate_runtime_materialized(&stack, &candidate).unwrap();

    // Distinct delivery metadata may legitimately describe identical runtime
    // bytes (e.g. a class-scoped delta with no VM-facing change). Only a
    // credential-value mismatch is evidence of an unapplied VM candidate.
    let mut second = vm_test_credential_bundle(110, CredentialDeliverySlot::B);
    verify_vm_candidate_runtime_materialized(&stack, &second).unwrap();
    let edge_shared_types::credential_delivery_bundle::Payload::Vm(vm) =
        second.payload.as_mut().unwrap()
    else {
        unreachable!("VM-only fixture")
    };
    vm.tunnel_auth
        .as_mut()
        .unwrap()
        .direct
        .as_mut()
        .unwrap()
        .hysteria2_password = "f".repeat(64);
    assert!(verify_vm_candidate_runtime_materialized(&stack, &second).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn vm_runtime_materialization_refuses_legacy_and_requires_explicit_active_v2() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    fs::write(
        stack.join(RUNTIME_POLICY_FILE),
        "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
    )
    .unwrap();
    fs::write(stack.join(RUNTIME_ENV_FILE), "existing=untouched\n").unwrap();
    let private_dir = root.join(RUNTIME_SECRET_DIR);
    fs::create_dir_all(&private_dir).unwrap();
    fs::write(
        private_dir.join(RUNTIME_SECRET_FILE),
        "legacy=not-authority\n",
    )
    .unwrap();
    assert!(
        materialize_vm_owned_runtime_environment(&stack)
            .unwrap_err()
            .contains("active Cloudflare Worker v2 credential")
    );
    assert_eq!(
        fs::read_to_string(stack.join(RUNTIME_ENV_FILE)).unwrap(),
        "existing=untouched\n"
    );
    let store = CredentialStore::new(
        vm_credential_store_root(&stack).unwrap(),
        CredentialProjectionKind::Vm,
    )
    .unwrap();
    let delivery = vm_test_credential_bundle(100, CredentialDeliverySlot::A);
    store.stage_candidate(&delivery).unwrap();
    assert!(materialize_vm_owned_runtime_environment(&stack).is_err());
    store.promote_candidate().unwrap();
    materialize_vm_owned_runtime_environment(&stack).unwrap();
    let expected = vm_runtime_environment(
        &stack,
        &ApplicationRuntimeSecrets::from_vm_bundle(&delivery).unwrap(),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(stack.join(RUNTIME_ENV_FILE)).unwrap(),
        expected
    );
    assert_eq!(
        fs::read_to_string(private_dir.join(RUNTIME_SECRET_FILE)).unwrap(),
        "legacy=not-authority\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn certificate_observation_uses_owner_state_for_tunnel_runtime() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    let owner = root
        .join("certificate-state/acme/certificates/acme-v02.api.letsencrypt.org-directory")
        .join("edge.example.com");
    fs::create_dir_all(stack.join("rendered")).unwrap();
    fs::create_dir_all(&owner).unwrap();
    fs::write(
        stack.join(RUNTIME_ENV_FILE),
        "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=letsencrypt\n",
    )
    .unwrap();
    fs::write(stack.join("rendered/line2-proxy.json"), "{}\n").unwrap();
    fs::write(stack.join("rendered/line1-gateway.json"), "{}\n").unwrap();
    fs::write(owner.join("edge.example.com.crt"), "certificate").unwrap();
    fs::write(owner.join("edge.example.com.key"), "private-key").unwrap();

    let mut state = AgentState::bootstrap_placeholder();
    state.degraded_reasons.clear();
    inspect_bundle_artifacts(&stack, &mut state);

    assert!(state.degraded_reasons.is_empty());
    assert!(!stack.join("certs/proxy.crt").exists());
    assert!(!stack.join("certs/proxy.key").exists());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn certificate_observation_uses_staging_provider_directory() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    let owner = root
        .join(
            "certificate-state/acme/certificates/acme-staging-v02.api.letsencrypt.org-directory",
        )
        .join("edge.example.com");
    fs::create_dir_all(stack.join("rendered")).unwrap();
    fs::create_dir_all(&owner).unwrap();
    fs::write(
        stack.join(RUNTIME_ENV_FILE),
        "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=https://acme-staging-v02.api.letsencrypt.org/directory\n",
    )
    .unwrap();
    fs::write(stack.join("rendered/line2-proxy.json"), "{}\n").unwrap();
    fs::write(stack.join("rendered/line1-gateway.json"), "{}\n").unwrap();
    fs::write(owner.join("edge.example.com.crt"), "certificate").unwrap();
    fs::write(owner.join("edge.example.com.key"), "private-key").unwrap();

    let paths = expected_proxy_certificate_paths(&stack).unwrap();
    assert_eq!(paths[0], owner.join("edge.example.com.crt"));
    assert_eq!(paths[1], owner.join("edge.example.com.key"));

    let mut state = AgentState::bootstrap_placeholder();
    state.degraded_reasons.clear();
    inspect_bundle_artifacts(&stack, &mut state);
    assert!(state.degraded_reasons.is_empty());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn certificate_observation_rejects_unsafe_tunnel_domain() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(stack.join("rendered")).unwrap();
    fs::write(
        stack.join(RUNTIME_ENV_FILE),
        "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=../escape\nACME_EMAIL=ops@example.com\n",
    )
    .unwrap();
    fs::write(stack.join("rendered/line2-proxy.json"), "{}\n").unwrap();
    fs::write(stack.join("rendered/line1-gateway.json"), "{}\n").unwrap();

    let mut state = AgentState::bootstrap_placeholder();
    state.degraded_reasons.clear();
    inspect_bundle_artifacts(&stack, &mut state);

    assert!(
        state
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("TUNNEL_DOMAIN is invalid"))
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tunnel_only_policy_does_not_require_line2_artifacts() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(stack.join("rendered")).unwrap();
    fs::write(
        stack.join(RUNTIME_ENV_FILE),
        "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=letsencrypt\n",
    )
    .unwrap();
    fs::write(stack.join("rendered/line1-gateway.json"), "{}\n").unwrap();

    assert!(tunnel_runtime_enabled(&stack));
    assert!(!line2_runtime_enabled(&stack));

    let mut state = AgentState::bootstrap_placeholder();
    state.degraded_reasons.clear();
    inspect_bundle_artifacts(&stack, &mut state);

    assert!(
        !state
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("line2-proxy.json"))
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_bundle_path_traversal() {
    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    let mut written = Vec::new();

    for path in [
        "../escape",
        "/tmp/escape",
        "nested/../escape",
        r"nested\escape",
    ] {
        let error = write_bundle_file(
            &root,
            &BundleFile {
                relative_path: path.to_owned(),
                content: b"secret".to_vec(),
                executable: false,
                sensitive: true,
            },
            &mut written,
        )
        .unwrap_err();
        assert!(error.contains("normalized relative path"));
    }
    assert!(written.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn known_secret_paths_are_private_even_without_sensitive_flag() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    let mut written = Vec::new();
    write_bundle_file(
        &root,
        &BundleFile {
            relative_path: ".env.runtime".to_owned(),
            content: b"MESH_NODE_TOKEN=secret\n".to_vec(),
            executable: false,
            sensitive: false,
        },
        &mut written,
    )
    .unwrap();
    let mode = fs::metadata(root.join(".env.runtime"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_executable_sensitive_bundle_files() {
    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    let mut written = Vec::new();
    let error = write_bundle_file(
        &root,
        &BundleFile {
            relative_path: "secret.sh".to_owned(),
            content: b"#!/bin/sh\n".to_vec(),
            executable: true,
            sensitive: true,
        },
        &mut written,
    )
    .unwrap_err();
    assert!(error.contains("both executable and sensitive"));
    assert!(!root.join("secret.sh").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn applies_explicit_bundle_file_modes() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    let mut written = Vec::new();
    for (name, executable, sensitive, expected) in [
        ("regular.txt", false, false, 0o644),
        ("fixed-tool", true, false, 0o755),
        (".env.runtime", false, true, 0o600),
    ] {
        write_bundle_file(
            &root,
            &BundleFile {
                relative_path: name.to_owned(),
                content: b"x".to_vec(),
                executable,
                sensitive,
            },
            &mut written,
        )
        .unwrap();
        let mode = fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, expected, "{name}");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reports_rendered_artifacts_for_base_capability() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(stack.join("rendered")).unwrap();
    fs::create_dir_all(stack.join("certs")).unwrap();
    fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
    fs::write(
        stack.join(RUNTIME_POLICY_FILE),
        "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
    )
    .unwrap();
    fs::write(
        stack.join(RUNTIME_ENV_FILE),
        "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
    )
    .unwrap();
    fs::write(stack.join("rendered/line2-proxy.json"), "{}").unwrap();
    fs::write(stack.join("certs/proxy.crt"), "crt").unwrap();
    fs::write(stack.join("certs/proxy.key"), "key").unwrap();

    let artifacts = collect_rendered_artifacts(&stack);
    assert!(artifacts.iter().all(|entry| entry.present));
    assert!(
        artifacts
            .iter()
            .any(|entry| entry.path == "rendered/line2-proxy.json")
    );
    assert!(
        artifacts
            .iter()
            .all(|entry| !entry.path.contains("line1-gateway"))
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reports_host_certificate_state_for_tunnel_capability() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    let owner = root
        .join("certificate-state/acme/certificates/acme-v02.api.letsencrypt.org-directory")
        .join("edge.example.com");
    fs::create_dir_all(stack.join("rendered")).unwrap();
    fs::create_dir_all(&owner).unwrap();
    fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
    fs::write(
        stack.join(RUNTIME_POLICY_FILE),
        "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=letsencrypt\n",
    )
    .unwrap();
    fs::write(
        stack.join(RUNTIME_ENV_FILE),
        "REALITY_SERVER_NAME=www.example.com\nTUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=ops@example.com\nACME_PROVIDER=letsencrypt\n",
    )
    .unwrap();
    fs::write(stack.join("rendered/line1-gateway.json"), "{}").unwrap();
    fs::write(owner.join("edge.example.com.crt"), "crt").unwrap();
    fs::write(owner.join("edge.example.com.key"), "key").unwrap();

    let artifacts = collect_rendered_artifacts(&stack);
    assert!(artifacts.iter().all(|entry| entry.present));
    assert!(
        artifacts
            .iter()
            .any(|entry| entry.path == "rendered/line1-gateway.json")
    );
    assert!(
        artifacts
            .iter()
            .any(|entry| entry.path.starts_with("../certificate-state/"))
    );
    assert!(
        artifacts
            .iter()
            .all(|entry| !entry.path.contains("line2-proxy"))
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parses_compose_ports() {
    let tcp = parse_compose_port("3128:3128/tcp").unwrap();
    assert!(matches!(tcp.protocol, Protocol::Tcp));
    assert_eq!(tcp.host_port, 3128);

    let udp = parse_compose_port("8443:8443/udp").unwrap();
    assert!(matches!(udp.protocol, Protocol::Udp));
    assert_eq!(udp.host_port, 8443);
}

#[test]
fn inspects_compose_expectations() {
    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("docker-compose.yml"),
        r#"services:
  line2-proxy:
container_name: vultr-line2-proxy
ports:
  - "3128:3128/tcp"
  line1-gateway:
container_name: vultr-line1-gateway
ports:
  - "8443:8443/udp"
"#,
    )
    .unwrap();

    let mut state = AgentState::bootstrap_placeholder();
    let observation = inspect_compose(
        &root.join("docker-compose.yml"),
        &mut state,
        &BTreeSet::new(),
        true,
    )
    .unwrap();
    assert!(state.compose_file_present);
    assert_eq!(observation.expected_containers.len(), 2);
    assert_eq!(observation.expected_tcp_ports, vec![3128]);
    assert_eq!(observation.expected_udp_ports, vec![8443]);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn compose_observation_honors_enabled_application_profiles() {
    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("docker-compose.yml"),
        r#"services:
  line2-proxy:
container_name: vultr-line2-proxy
ports:
  - "3128:3128/tcp"
  line1-gateway:
profiles: [tunnel]
container_name: vultr-line1-gateway
ports:
  - "8443:8443/udp"
  cloudflare-mesh:
profiles: [mesh]
container_name: vultr-cloudflare-mesh
"#,
    )
    .unwrap();

    let mut state = AgentState::bootstrap_placeholder();
    let enabled_profiles = BTreeSet::from(["tunnel".to_owned()]);
    let observation = inspect_compose(
        &root.join("docker-compose.yml"),
        &mut state,
        &enabled_profiles,
        true,
    )
    .unwrap();
    assert_eq!(
        observation.expected_containers,
        vec!["vultr-line1-gateway", "vultr-line2-proxy"]
    );
    assert_eq!(observation.expected_tcp_ports, vec![3128]);
    assert_eq!(observation.expected_udp_ports, vec![8443]);

    let tunnel_only = inspect_compose(
        &root.join("docker-compose.yml"),
        &mut AgentState::bootstrap_placeholder(),
        &enabled_profiles,
        false,
    )
    .unwrap();
    assert_eq!(tunnel_only.expected_containers, vec!["vultr-line1-gateway"]);
    assert!(tunnel_only.expected_tcp_ports.is_empty());
    assert_eq!(tunnel_only.expected_udp_ports, vec![8443]);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reads_bundle_summary_and_artifacts() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(stack.join("rendered")).unwrap();
    let owner = root
        .join("certificate-state/acme/certificates/acme-v02.api.letsencrypt.org-directory")
        .join("edge.example.com");
    fs::create_dir_all(&owner).unwrap();
    fs::write(
        stack.join(".env.runtime"),
        "TUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=admin@example.com\nACME_PROVIDER=letsencrypt\n",
    )
    .unwrap();
    fs::write(stack.join("rendered/line1-gateway.json"), "{}").unwrap();
    fs::write(owner.join("edge.example.com.crt"), "crt").unwrap();
    fs::write(owner.join("edge.example.com.key"), "key").unwrap();
    fs::write(
        root.join("deployment-summary.json"),
        r#"{"label":"bundle-a","instance_id":"instance-1"}"#,
    )
    .unwrap();

    let mut state = AgentState::bootstrap_placeholder();
    inspect_bundle_artifacts(&stack, &mut state);
    assert_eq!(state.active_bundle_id.as_deref(), Some("bundle-a"));
    assert!(state.topology_version.contains("instance-1"));
    assert!(
        !state
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("bundle artifact"))
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn mesh_token_validation_is_closed_and_secret_safe() {
    assert!(validate_mesh_node_token("opaque-token-value").is_ok());
    assert!(validate_mesh_node_token("").is_err());
    assert!(validate_mesh_node_token(" token").is_err());
    assert!(validate_mesh_node_token("token\ninjected").is_err());
    assert!(validate_mesh_node_token("token\rinjected").is_err());
}

#[test]
#[cfg(unix)]
fn mesh_token_store_is_host_level_private_and_not_release_local() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    persist_mesh_node_token(&stack, "opaque-token-value").unwrap();

    let path = root.join("runtime-secrets/mesh-node-v1.env");
    assert!(path.is_file());
    assert!(!stack.join("runtime-secrets/mesh-node-v1.env").exists());
    assert_eq!(read_mesh_node_token(&stack).unwrap(), "opaque-token-value");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn warp_state_is_host_level_across_release_swap_names() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    let previous = root.join("stack.previous");
    assert_eq!(
        warp_runtime_state_dir(&stack).unwrap(),
        root.join("warp-state")
    );
    assert_eq!(
        warp_runtime_state_dir(&previous).unwrap(),
        root.join("warp-state")
    );

    let compose = include_str!("../../../../win/vultr-waw/stack/docker-compose.yml");
    assert!(compose.contains("- ../warp-state:/var/lib/cloudflare-warp"));
    assert!(!compose.contains("- ./warp-state:/var/lib/cloudflare-warp"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn mesh_state_is_host_level_across_release_swap_names() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    let previous = root.join("stack.previous");
    assert_eq!(
        mesh_runtime_state_dir(&stack).unwrap(),
        root.join("mesh-state")
    );
    assert_eq!(
        mesh_runtime_state_dir(&previous).unwrap(),
        root.join("mesh-state")
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn mesh_registration_state_is_scoped_by_exact_provider_identity() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    let historical = "93b6f3a7-2dd5-4a72-8258-34c32ce5be69";
    let target = "11111111-2222-4333-8444-555555555555";

    assert_eq!(
        mesh_registration_state_dir(&stack, historical).unwrap(),
        root.join("mesh-state").join(historical)
    );
    assert_eq!(
        mesh_registration_state_dir(&stack, target).unwrap(),
        root.join("mesh-state").join(target)
    );
    assert_ne!(
        mesh_registration_state_dir(&stack, historical).unwrap(),
        mesh_registration_state_dir(&stack, target).unwrap()
    );
    assert!(mesh_registration_state_dir(&stack, "../escape").is_err());

    let compose = include_str!("../../../../win/vultr-waw/stack/docker-compose.yml");
    assert!(compose.contains("${MESH_STATE_DIR:-../mesh-state}:/var/lib/cloudflare-warp"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn active_mesh_registration_identity_is_exact_and_non_secret() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    let registration_id = "11111111-2222-4333-8444-555555555555";

    persist_mesh_registration_id(&stack, registration_id).unwrap();
    assert_eq!(
        read_mesh_registration_id(&stack).unwrap().as_deref(),
        Some(registration_id)
    );
    assert!(root.join("mesh-state/active-registration-v1").is_file());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn typed_image_environment_requires_exact_digests() {
    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join(IMAGE_ENV_FILE),
        concat!(
            "EDGE_GATEWAY_IMAGE=ghcr.io/iamaman11/vultr-edge-gateway@sha256:",
            "1111111111111111111111111111111111111111111111111111111111111111\n",
            "EDGE_WARP_EGRESS_IMAGE=ghcr.io/iamaman11/vultr-warp-egress@sha256:",
            "2222222222222222222222222222222222222222222222222222222222222222\n",
            "CLOUDFLARE_MESH_IMAGE=docker.io/cloudflare/mesh@sha256:",
            "3333333333333333333333333333333333333333333333333333333333333333\n",
        ),
    )
    .unwrap();

    let images = read_exact_image_environment(&root).unwrap();
    assert_eq!(images.len(), 3);

    fs::write(
        root.join(IMAGE_ENV_FILE),
        "EDGE_GATEWAY_IMAGE=ghcr.io/iamaman11/vultr-edge-gateway:latest\n",
    )
    .unwrap();
    assert!(read_exact_image_environment(&root).is_err());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn typed_runtime_environment_accepts_vm_owned_credentials() {
    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    let mut runtime = "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n".to_owned();
    runtime.push_str(&ApplicationRuntimeSecrets::generate().render_env());
    fs::write(root.join(RUNTIME_ENV_FILE), runtime).unwrap();

    let values = read_typed_runtime_environment(&root).unwrap();
    assert_eq!(
        values.get("PROXY_USERNAME").map(String::as_str),
        Some("acceptance")
    );
    assert!(values.contains_key("REALITY_PRIVATE_KEY"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn renders_line2_runtime_without_shell_expansion() {
    let root = unique_test_dir();
    fs::create_dir_all(root.join("line2-proxy")).unwrap();
    fs::create_dir_all(root.join("rendered")).unwrap();
    fs::write(
        root.join("line2-proxy/config.template.json"),
        r#"{"username":"${PROXY_USERNAME}","password":"${PROXY_PASSWORD}","cert":"${PROXY_CERT_PATH}","key":"${PROXY_KEY_PATH}"}"#,
    )
    .unwrap();

    let values = BTreeMap::from([
        ("PROXY_USERNAME".to_owned(), "acceptance".to_owned()),
        ("PROXY_PASSWORD".to_owned(), "secret-value".to_owned()),
    ]);
    render_line2_runtime(&root, &values).unwrap();

    let rendered = fs::read_to_string(root.join("rendered/line2-proxy.json")).unwrap();
    assert!(rendered.contains("\"username\":\"acceptance\""));
    assert!(rendered.contains("\"password\":\"secret-value\""));
    assert!(!rendered.contains("${"));
    let mode = fs::metadata(root.join("rendered/line2-proxy.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn datapath_probe_requires_every_enabled_gateway_consumer() {
    assert_eq!(
        runtime_probe_consumers(&["vultr-line1-gateway".to_owned()]),
        vec![LINE1_CONTAINER]
    );
    assert_eq!(
        runtime_probe_consumers(&[
            "vultr-line1-gateway".to_owned(),
            "vultr-line2-proxy".to_owned(),
        ]),
        vec![LINE1_CONTAINER, LINE2_CONTAINER]
    );
    assert!(runtime_probe_consumers(&["vultr-warp-egress".to_owned()]).is_empty());
}

fn assert_gateway_uses_docker_local_warp_resolver(raw: &str) {
    let config: serde_json::Value = serde_json::from_str(raw).unwrap();
    let servers = config
        .pointer("/dns/servers")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    let local = servers
        .iter()
        .find(|server| {
            server.get("tag").and_then(serde_json::Value::as_str) == Some("docker-local")
        })
        .unwrap();
    assert_eq!(
        local.get("type").and_then(serde_json::Value::as_str),
        Some("local")
    );
    assert_eq!(
        local.get("prefer_go").and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let outbounds = config
        .get("outbounds")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    let warp = outbounds
        .iter()
        .find(|outbound| {
            outbound.get("tag").and_then(serde_json::Value::as_str) == Some("warp-local")
        })
        .unwrap();
    assert_eq!(
        warp.get("server").and_then(serde_json::Value::as_str),
        Some("warp-egress")
    );
    assert_eq!(
        warp.get("domain_resolver")
            .and_then(serde_json::Value::as_str),
        Some("docker-local")
    );
}

#[test]
fn line1_gateway_warp_outbound_uses_container_local_dns() {
    assert_gateway_uses_docker_local_warp_resolver(include_str!(
        "../../../../win/vultr-waw/stack/line1-gateway/config.template.json"
    ));
}

#[test]
fn line2_gateway_warp_outbound_uses_container_local_dns() {
    assert_gateway_uses_docker_local_warp_resolver(include_str!(
        "../../../../win/vultr-waw/stack/line2-proxy/config.template.json"
    ));
}

#[test]
fn classifies_cloudflare_trace_without_exposing_addresses() {
    let direct = "fl=123\nip=203.0.113.10\nwarp=off\ncolo=WAW\n";
    let warp = "fl=123\nip=198.51.100.20\nwarp=on\ncolo=WAW\n";
    let plus = "fl=123\nip=198.51.100.21\nwarp=plus\ncolo=WAW\n";
    assert!(cloudflare_trace_has_warp_mode(direct, "off"));
    assert!(cloudflare_trace_has_warp_mode(warp, "on"));
    assert!(cloudflare_trace_has_warp_mode(plus, "plus"));
    assert!(!cloudflare_trace_has_warp_mode(warp, "off"));
    assert!(!cloudflare_trace_has_warp_mode("warp=on\n", "on"));
    assert!(!cloudflare_trace_has_warp_mode(
        "ip=203.0.113.10\nwarp=on\nwarp=off\n",
        "on"
    ));
}

#[test]
fn post_bootstrap_reobservation_is_bounded_and_stops_when_ready() {
    let not_ready = BootstrapVerification {
        success: false,
        warnings: vec!["consumer datapath not converged".to_owned()],
    };
    assert!(should_reobserve_bootstrap_post_state(&not_ready, 0));
    assert!(should_reobserve_bootstrap_post_state(
        &not_ready,
        POST_BOOTSTRAP_REOBSERVE_ATTEMPTS - 2
    ));
    assert!(!should_reobserve_bootstrap_post_state(
        &not_ready,
        POST_BOOTSTRAP_REOBSERVE_ATTEMPTS - 1
    ));

    let ready = BootstrapVerification {
        success: true,
        warnings: Vec::new(),
    };
    assert!(!should_reobserve_bootstrap_post_state(&ready, 0));
}

#[test]
fn verifies_base_bootstrap_from_running_container_state() {
    let state = AgentState {
        healthy: true,
        ready: true,
        topology_version: "v1".to_owned(),
        active_bundle_id: None,
        degraded_reasons: Vec::new(),
        docker_reachable: true,
        compose_file_present: true,
        observed_stack_path: Some("/opt/vultr-edge-stack/stack".to_owned()),
        running_containers: vec![
            "vultr-warp-egress".to_owned(),
            "vultr-line2-proxy".to_owned(),
        ],
        missing_containers: Vec::new(),
        listening_tcp_ports: Vec::new(),
        listening_udp_ports: Vec::new(),
        direct_egress_ready: Some(true),
        warp_egress_ready: Some(true),
        mesh_runtime_ready: None,
        containers: Vec::new(),
    };

    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join(".env.runtime"),
        "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
    )
    .unwrap();

    let verification = verify_bootstrap_post_state(&root, BootstrapMode::BootstrapBase, &state);
    assert!(verification.success);
    let mut without_mesh = state;
    without_mesh.mesh_runtime_ready = Some(false);
    let independent =
        verify_bootstrap_post_state(&root, BootstrapMode::BootstrapBase, &without_mesh);
    assert!(
        independent.success,
        "Line 3 must not gate Line 1/2 readiness"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn requires_tunnel_containers_for_tunnel_bootstrap() {
    let state = AgentState {
        healthy: true,
        ready: true,
        topology_version: "v1".to_owned(),
        active_bundle_id: None,
        degraded_reasons: Vec::new(),
        docker_reachable: true,
        compose_file_present: true,
        observed_stack_path: Some("/opt/vultr-edge-stack/stack".to_owned()),
        running_containers: vec![
            "vultr-warp-egress".to_owned(),
            "vultr-line2-proxy".to_owned(),
        ],
        missing_containers: Vec::new(),
        listening_tcp_ports: Vec::new(),
        listening_udp_ports: Vec::new(),
        direct_egress_ready: Some(true),
        warp_egress_ready: Some(true),
        mesh_runtime_ready: None,
        containers: Vec::new(),
    };

    let root = unique_test_dir();
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join(".env.runtime"),
        "TUNNEL_DOMAIN=edge.example.com\nACME_EMAIL=admin@example.com\n",
    )
    .unwrap();

    let verification =
        verify_bootstrap_post_state(&root, BootstrapMode::BootstrapTunnel, &state);
    assert!(!verification.success);
    assert!(
        verification
            .warnings
            .iter()
            .any(|warning| warning.contains("vultr-line1-gateway"))
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn candidate_rendered_configs_must_equal_exact_template_projection() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    for part in ["line1-gateway", "line2-proxy", "rendered"] {
        fs::create_dir_all(stack.join(part)).unwrap();
    }
    let mut runtime = BTreeMap::new();
    for key in LINE1_RUNTIME_TEMPLATE_KEYS {
        runtime.insert(key.to_owned(), "value".to_owned());
    }
    for key in LINE2_RUNTIME_TEMPLATE_KEYS {
        runtime.insert(key.to_owned(), "value".to_owned());
    }
    runtime.insert("TUNNEL_DOMAIN".to_owned(), "example.com".to_owned());
    runtime.insert("ACME_PROVIDER".to_owned(), "letsencrypt".to_owned());
    runtime.insert("PROXY_CERT_CN".to_owned(), "example.com".to_owned());
    for (part, keys) in [
        ("line1-gateway", LINE1_RUNTIME_TEMPLATE_KEYS.as_slice()),
        ("line2-proxy", LINE2_RUNTIME_TEMPLATE_KEYS.as_slice()),
    ] {
        let template = keys
            .iter()
            .map(|key| format!("${{{key}}}"))
            .collect::<Vec<_>>()
            .join(",");
        fs::write(stack.join(part).join("config.template.json"), template).unwrap();
    }
    let line1 = expand_runtime_template(
        &stack,
        "line1-gateway/config.template.json",
        &runtime,
        &LINE1_RUNTIME_TEMPLATE_KEYS,
    )
    .unwrap();
    let (cert, key) = line2_certificate_container_paths(&runtime).unwrap();
    let mut line2_env = runtime.clone();
    line2_env.insert("PROXY_CERT_PATH".to_owned(), cert);
    line2_env.insert("PROXY_KEY_PATH".to_owned(), key);
    let line2 = expand_runtime_template(
        &stack,
        "line2-proxy/config.template.json",
        &line2_env,
        &LINE2_RUNTIME_TEMPLATE_KEYS,
    )
    .unwrap();
    fs::write(stack.join("rendered/line1-gateway.json"), line1).unwrap();
    fs::write(stack.join("rendered/line2-proxy.json"), line2).unwrap();
    assert!(verify_rendered_config_matches_vm_projection(&stack, &runtime).is_ok());

    fs::write(stack.join("rendered/line1-gateway.json"), "stale").unwrap();
    assert!(verify_rendered_config_matches_vm_projection(&stack, &runtime).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn read_only_credential_origin_distinguishes_legacy_v2_and_unproven() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    fs::write(
        stack.join(RUNTIME_POLICY_FILE),
        "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
    )
    .unwrap();

    assert_eq!(
        observe_vm_rendered_credential_source(&stack),
        VmRenderedCredentialSource::Unproven("RUNTIME_ENV_ABSENT")
    );

    // No real credential values are returned by this classification.
    let private_dir = root.join(RUNTIME_SECRET_DIR);
    fs::create_dir_all(&private_dir).unwrap();
    fs::write(private_dir.join(RUNTIME_SECRET_FILE), "legacy=private\n").unwrap();
    fs::write(stack.join(RUNTIME_ENV_FILE), "legacy=not-authorized\n").unwrap();
    assert_eq!(
        observe_vm_rendered_credential_source(&stack),
        VmRenderedCredentialSource::LegacyStorePresent
    );

    let store = CredentialStore::new(
        vm_credential_store_root(&stack).unwrap(),
        CredentialProjectionKind::Vm,
    )
    .unwrap();
    let delivery = vm_test_credential_bundle(100, CredentialDeliverySlot::A);
    store.stage_candidate(&delivery).unwrap();
    store.promote_candidate().unwrap();

    // A pointer update alone cannot claim the rendered runtime has switched,
    // even with an unrelated legacy store still present as evidence.
    assert_eq!(
        observe_vm_rendered_credential_source(&stack),
        VmRenderedCredentialSource::Unproven("V2_ACTIVE_RENDER_MISMATCH")
    );

    let v2 = ApplicationRuntimeSecrets::from_vm_bundle(&delivery).unwrap();
    write_vm_runtime_environment(&stack, &v2).unwrap();
    assert_eq!(
        observe_vm_rendered_credential_source(&stack),
        VmRenderedCredentialSource::V2Active {
            delivery_generation: 100,
            tunnel_auth_generation: 7,
            reality_generation: 3,
            line2_generation: 2,
        }
    );

    fs::remove_file(private_dir.join(RUNTIME_SECRET_FILE)).unwrap();
    fs::write(stack.join(RUNTIME_ENV_FILE), "unrelated=not-a-runtime\n").unwrap();
    assert_eq!(
        observe_vm_rendered_credential_source(&stack),
        VmRenderedCredentialSource::Unproven("V2_ACTIVE_RENDER_MISMATCH")
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn application_verdict_never_conflates_runtime_ready_with_active_credentials() {
    assert_eq!(
        vm_application_operational_verdict(
            true,
            &VmRenderedCredentialSource::V2Candidate {
                delivery_generation: 101,
                tunnel_auth_generation: 2,
                reality_generation: 3,
                line2_generation: 4,
            }
        ),
        "NETWORK_READY_INITIAL_CUTOVER_PENDING"
    );
    assert_eq!(
        vm_application_operational_verdict(
            false,
            &VmRenderedCredentialSource::Unproven("RUNTIME_ENV_ABSENT")
        ),
        "BLOCKED_RUNTIME_NOT_READY"
    );
    assert_eq!(
        vm_application_operational_verdict(
            true,
            &VmRenderedCredentialSource::Unproven("V2_ACTIVE_RENDER_MISMATCH")
        ),
        "BLOCKED_CREDENTIAL_SOURCE_UNPROVEN"
    );
}

#[test]
fn first_use_candidate_rendered_is_proven_on_disk_but_not_active_or_running() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    fs::write(
        stack.join(RUNTIME_POLICY_FILE),
        "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
    )
    .unwrap();
    let store = CredentialStore::new(
        vm_credential_store_root(&stack).unwrap(),
        CredentialProjectionKind::Vm,
    )
    .unwrap();
    let candidate = vm_test_credential_bundle(38_503_639_351, CredentialDeliverySlot::B);
    store.stage_candidate(&candidate).unwrap();
    let secrets = ApplicationRuntimeSecrets::from_vm_bundle(&candidate).unwrap();
    write_vm_runtime_environment(&stack, &secrets).unwrap();

    assert_eq!(
        observe_vm_rendered_credential_source(&stack),
        VmRenderedCredentialSource::V2Candidate {
            delivery_generation: 38_503_639_351,
            tunnel_auth_generation: 7,
            reality_generation: 3,
            line2_generation: 2,
        }
    );
    let state = store.read_state().unwrap().unwrap();
    assert!(state.active.is_none());
    assert_eq!(state.candidate.unwrap().generation, 38_503_639_351);

    fs::write(stack.join(RUNTIME_ENV_FILE), "UNRELATED=source\\n").unwrap();
    assert_eq!(
        observe_vm_rendered_credential_source(&stack),
        VmRenderedCredentialSource::Unproven("V2_CANDIDATE_RENDER_MISMATCH")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rotated_candidate_does_not_override_active_render_authority() {
    let root = unique_test_dir();
    let stack = root.join("stack");
    fs::create_dir_all(&stack).unwrap();
    fs::write(
        stack.join(RUNTIME_POLICY_FILE),
        "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=acceptance.local\n",
    )
    .unwrap();
    let store = CredentialStore::new(
        vm_credential_store_root(&stack).unwrap(),
        CredentialProjectionKind::Vm,
    )
    .unwrap();
    let active = vm_test_credential_bundle(100, CredentialDeliverySlot::A);
    store.stage_candidate(&active).unwrap();
    store.promote_candidate().unwrap();
    let mut candidate = vm_test_credential_bundle(101, CredentialDeliverySlot::B);
    let edge_shared_types::credential_delivery_bundle::Payload::Vm(vm) =
        candidate.payload.as_mut().unwrap()
    else {
        unreachable!()
    };
    vm.tunnel_auth
        .as_mut()
        .unwrap()
        .direct
        .as_mut()
        .unwrap()
        .hysteria2_password = "f".repeat(64);
    store.stage_candidate(&candidate).unwrap();
    let secrets = ApplicationRuntimeSecrets::from_vm_bundle(&candidate).unwrap();
    write_vm_runtime_environment(&stack, &secrets).unwrap();
    assert_eq!(
        observe_vm_rendered_credential_source(&stack),
        VmRenderedCredentialSource::Unproven("V2_ACTIVE_RENDER_MISMATCH")
    );
    fs::remove_dir_all(root).unwrap();
}

fn vm_test_credential_bundle(
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
        projection: CredentialProjectionKind::Vm as i32,
        dummy_non_secret: false,
        slot: slot as i32,
        payload: Some(credential_delivery_bundle::Payload::Vm(
            VmCredentialProjection {
                tunnel_auth: Some(tunnel_auth),
                reality_identity: Some(RealityPrivateIdentityGeneration {
                    generation: 3,
                    direct: Some(RealityPrivateIdentity {
                        private_key: "A".repeat(43),
                    }),
                    warp: Some(RealityPrivateIdentity {
                        private_key: "Q".repeat(43),
                    }),
                }),
                line2_proxy: Some(ProxyCredentialGeneration {
                    generation: 2,
                    password: "e".repeat(64),
                }),
            },
        )),
    }
}

fn unique_test_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("edge-agent-test-{unique}"))
}