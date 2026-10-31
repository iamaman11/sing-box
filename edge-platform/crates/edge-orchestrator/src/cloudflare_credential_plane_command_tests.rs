#[test]
fn host_github_app_private_key_validation_fails_closed_without_disclosure() {
    for value in [
        "",
        "not_a_pkcs8_key",
        "-----BEGIN PRIVATE KEY-----",
        "BAD+STANDARD/BASE64==",
        &"a".repeat(9000),
    ] {
        assert!(validate_host_github_app_private_key(value).is_err());
    }
}

#[test]
fn vm_signer_requires_exact_eight_and_accepted_active_module() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "vm");
    let source = delivery_worker_material("vm").unwrap().source;
    let accepted = sha256_hex(source.as_bytes());
    let current = observed
        .projections
        .iter_mut()
        .find(|p| p.projection == "vm")
        .unwrap();
    let names = [
        "EDGE_CREDENTIAL_BUNDLE_A",
        "EDGE_CREDENTIAL_BUNDLE_B",
        "EDGE_HOST_SIGNING_PKCS8_BASE64",
        "EDGE_HOST_SIGNING_KEY_ID",
        "EDGE_HOST_GITHUB_ACTOR_ID",
        "EDGE_HOST_ACCESS_ISSUER",
        "EDGE_HOST_ACCESS_AUD",
        "EDGE_HOST_GITHUB_APP_PKCS8_BASE64",
    ];
    current.worker_binding_count = Some(8);
    current.worker_secret_bindings = names
        .iter()
        .map(|name| cloudflare::CloudflareWorkerSecretBinding {
            name: (*name).into(),
            binding_type: "secret_text".into(),
        })
        .collect();
    assert!(
        verify_exact_vm_signer_source(&desired, &observed, &accepted, source.as_bytes()).is_ok()
    );
    assert_eq!(
        verify_exact_vm_signer_source(&desired, &observed, &accepted, b"foreign code"),
        Err("HOST_SIGNER_VM_WORKER_SOURCE_NOT_ACCEPTED_RELEASE".into())
    );
    let mut missing = observed.clone();
    missing
        .projections
        .iter_mut()
        .find(|p| p.projection == "vm")
        .unwrap()
        .worker_secret_bindings
        .pop();
    assert!(
        verify_exact_vm_signer_source(&desired, &missing, &accepted, source.as_bytes()).is_err()
    );
    let mut seven = missing.clone();
    seven
        .projections
        .iter_mut()
        .find(|p| p.projection == "vm")
        .unwrap()
        .worker_binding_count = Some(7);
    assert!(verify_exact_vm_signer_source(&desired, &seven, &accepted, source.as_bytes()).is_err());
    let mut two = observed.clone();
    let vm = two
        .projections
        .iter_mut()
        .find(|p| p.projection == "vm")
        .unwrap();
    vm.worker_binding_count = Some(2);
    vm.worker_secret_bindings.truncate(2);
    assert!(verify_exact_vm_signer_source(&desired, &two, &accepted, source.as_bytes()).is_err());
    let mut foreign = observed.clone();
    foreign
        .projections
        .iter_mut()
        .find(|p| p.projection == "vm")
        .unwrap()
        .worker_secret_bindings[0]
        .name = "UNAUTHORIZED_SECRET".into();
    assert!(
        verify_exact_vm_signer_source(&desired, &foreign, &accepted, source.as_bytes()).is_err()
    );
    let mut split = observed.clone();
    split
        .projections
        .iter_mut()
        .find(|p| p.projection == "vm")
        .unwrap()
        .worker_active_version_ids
        .push("unapproved".into());
    assert!(verify_exact_vm_signer_source(&desired, &split, &accepted, source.as_bytes()).is_err());
}

#[test]
fn vm_github_app_binding_scope_requires_exact_eighth_secret() {
    let mut seven = vec![
        "EDGE_CREDENTIAL_BUNDLE_A",
        "EDGE_CREDENTIAL_BUNDLE_B",
        "EDGE_HOST_SIGNING_PKCS8_BASE64",
        "EDGE_HOST_SIGNING_KEY_ID",
        "EDGE_HOST_GITHUB_ACTOR_ID",
        "EDGE_HOST_ACCESS_ISSUER",
        "EDGE_HOST_ACCESS_AUD",
    ]
    .into_iter()
    .map(|name| cloudflare::CloudflareWorkerSecretBinding {
        name: name.to_owned(),
        binding_type: "secret_text".to_owned(),
    })
    .collect::<Vec<_>>();
    require_exact_secret_bindings("sing-box-credentials-vm", "vm", &seven).unwrap();
    seven.push(cloudflare::CloudflareWorkerSecretBinding {
        name: "EDGE_HOST_GITHUB_APP_PKCS8_BASE64".to_owned(),
        binding_type: "secret_text".to_owned(),
    });
    require_exact_secret_bindings("sing-box-credentials-vm", "vm", &seven).unwrap();
    assert!(
        require_exact_secret_bindings("sing-box-credentials-windows", "windows", &seven).is_err()
    );
    seven.push(cloudflare::CloudflareWorkerSecretBinding {
        name: "AN_UNEXPECTED_SECRET".to_owned(),
        binding_type: "secret_text".to_owned(),
    });
    assert!(require_exact_secret_bindings("sing-box-credentials-vm", "vm", &seven).is_err());
}

use super::*;

#[test]
fn vm_worker_readonly_proof_rechecks_existing_git_pin_without_granting_mutation() {
    let mut host = edge_shared_types::FleetHost {
        machine_id: "acceptance".into(),
        ..Default::default()
    };
    let digest = "a".repeat(64);
    assert_eq!(
        vm_worker_readonly_proof_git_state(&host, "acceptance", 27, &digest),
        Ok("NOT_YET_REGISTERED")
    );
    host.vm_first_use_credential = Some(edge_shared_types::FleetVmFirstUseCredential {
        generation: 27,
        bundle_sha256: digest.clone(),
    });
    assert_eq!(
        vm_worker_readonly_proof_git_state(&host, "acceptance", 27, &digest),
        Ok("PROTECTED_GIT_EXACT")
    );
    host.native_receipt_public_key = vec![7; 32];
    assert_eq!(
        vm_worker_readonly_proof_git_state(&host, "acceptance", 27, &digest),
        Ok("PROTECTED_GIT_EXACT")
    );
    assert_eq!(
        vm_worker_readonly_proof_git_state(&host, "wrong", 27, &digest),
        Err("HOST_VM_CREDENTIAL_PROOF_MACHINE_MISMATCH")
    );
    assert_eq!(
        vm_worker_readonly_proof_git_state(&host, "acceptance", 28, &digest),
        Err("HOST_VM_CREDENTIAL_PROOF_GIT_PIN_MISMATCH")
    );
    assert_eq!(
        vm_worker_readonly_proof_git_state(&host, "acceptance", 27, &"b".repeat(64)),
        Err("HOST_VM_CREDENTIAL_PROOF_GIT_PIN_MISMATCH")
    );
    host.vm_first_use_credential = None;
    assert_eq!(
        vm_worker_readonly_proof_git_state(&host, "acceptance", 27, &digest),
        Err("HOST_VM_CREDENTIAL_PROOF_REGISTERED_RECEIPT_WITHOUT_SOURCE")
    );
}

#[test]
fn first_use_credential_proof_rejects_empty_dummy_or_incorrect_identity() {
    let malformed = &[0x00, 0x01, 0x02];
    let digest = sha256_hex(malformed);
    assert!(attest_vm_first_use_credential_bytes(malformed, 42, &digest).is_err());
    let dummy = CredentialDeliveryBundle {
        schema_version: 1,
        generation: 321_654,
        projection: CredentialProjectionKind::Vm as i32,
        dummy_non_secret: true,
        slot: CredentialDeliverySlot::Unspecified as i32,
        payload: None,
    }
    .encode_to_vec();
    let sha = sha256_hex(&dummy);
    assert_eq!(
        attest_vm_first_use_credential_bytes(&dummy, 321_654, &sha).unwrap_err(),
        "HOST_VM_FIRST_USE_CREDENTIAL_NOT_FULL_VM_PAYLOAD"
    );
    assert!(attest_vm_first_use_credential_bytes(&dummy, 321_655, &sha).is_err());
    assert!(
        attest_vm_first_use_credential_bytes(&dummy, CREDENTIAL_DUMMY_PROBE_GENERATION_A, &sha)
            .is_err()
    );
}

#[test]
fn worker_host_signer_pkcs8_uses_exact_urlsafe_base64_contract() {
    use base64::Engine as _;
    use ring::signature::KeyPair;

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let original = pkcs8.as_ref();
    let encoded = encode_worker_host_signer_pkcs8(original);
    assert!(!encoded.is_empty());
    assert!(
        encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap(),
        original
    );
    let restored = ring::signature::Ed25519KeyPair::from_pkcs8(original).unwrap();
    assert_eq!(restored.public_key().as_ref().len(), 32);

    // Bytes that STANDARD would encode using '/' and '+' must still be
    // decodable with the same alphabet as the deployed Worker B64().
    let edge = encode_worker_host_signer_pkcs8(&[0xff, 0xef, 0xfb]);
    assert_eq!(edge, "_-_7");
}

#[test]
fn only_one_vm_worker_may_hold_host_signer_secrets() {
    let names = [
        SLOT_A,
        SLOT_B,
        "EDGE_HOST_ACCESS_AUD",
        "EDGE_HOST_ACCESS_ISSUER",
        "EDGE_HOST_GITHUB_ACTOR_ID",
        "EDGE_HOST_SIGNING_KEY_ID",
        "EDGE_HOST_SIGNING_PKCS8_BASE64",
    ];
    let extra = names
        .iter()
        .map(|name| cloudflare::CloudflareWorkerSecretBinding {
            name: (*name).to_owned(),
            binding_type: "secret_text".to_owned(),
        })
        .collect::<Vec<_>>();
    assert!(require_exact_secret_bindings("sing-box-credentials-vm", "vm", &extra).is_ok());
    // Host route Access audience may be added ONLY to the eight-binding
    // VM signer, and it never grants Windows token access to VM credentials.
    let mut isolated = extra.clone();
    isolated.push(cloudflare::CloudflareWorkerSecretBinding {
        name: "EDGE_HOST_GITHUB_APP_PKCS8_BASE64".to_owned(),
        binding_type: "secret_text".to_owned(),
    });
    isolated.push(cloudflare::CloudflareWorkerSecretBinding {
        name: "EDGE_HOST_ROUTE_ACCESS_AUD".to_owned(),
        binding_type: "secret_text".to_owned(),
    });
    assert!(require_exact_secret_bindings("sing-box-credentials-vm", "vm", &isolated).is_ok());
    assert!(
        require_exact_secret_bindings("sing-box-credentials-windows", "windows", &isolated)
            .is_err()
    );
    isolated.last_mut().unwrap().name = "UNREVIEWED_ACCESS_SECRET".to_owned();
    assert!(require_exact_secret_bindings("sing-box-credentials-vm", "vm", &isolated).is_err());
    assert!(
        require_exact_secret_bindings("sing-box-credentials-windows", "windows", &extra).is_err()
    );
    let mut injected = extra;
    injected[3].name = "ATTACKER_EXTRA_SECRET".to_owned();
    assert!(require_exact_secret_bindings("sing-box-credentials-vm", "vm", &injected).is_err());
}

#[test]
fn host_authorization_is_closed_by_default_exact_and_access_bound() {
    // Source for BOTH existing projection Workers; not a new Worker,
    // key store, publisher or agent. No signer material is ever embedded
    // in this public Git repository.
    for projection in ["vm", "windows"] {
        let source = delivery_worker_material(projection).unwrap().source;
        assert!(source.contains("/v1/host/authorize"));
        assert!(source.contains("if(P!=="));
        assert!(!source.contains("__HOST_SIGNER_PROJECTION__"));
        assert!(source.contains("if(q.method!==\"POST\""));
        assert!(source.contains("EDGE_HOST_SIGNING_PKCS8_BASE64"));
        assert!(source.contains("EDGE_HOST_SIGNING_KEY_ID"));
        assert!(source.contains("EDGE_HOST_GITHUB_ACTOR_ID"));
        assert!(source.contains("EDGE_HOST_ACCESS_ISSUER"));
        assert!(source.contains("EDGE_HOST_ACCESS_AUD"));
        assert!(source.contains("EDGE_HOST_ROUTE_ACCESS_AUD"));
        assert!(source.contains("hostRoute"));
        assert!(source.contains("Cf-Access-Jwt-Assertion"));
        assert!(source.contains("RSASSA-PKCS1-v1_5"));
        assert!(source.contains("sing-box/native-host-authorization/v1:"));
        assert!(source.contains("U32(raw.length),raw,U32(kid.length),kid"));
        assert!(source.contains("U64(issued),U64(expires)"));
        assert!(source.contains("crypto.subtle.sign(\"Ed25519\""));
        assert!(source.contains("GITHUB(info,e"));
        assert!(source.contains("c.nbf!==undefined"));
        assert!(!source.contains("||!Number.isInteger(c.nbf)"));
        assert!(source.contains("X-Host-Authorization-Reason"));
        for reason in [
            "JWT_MISSING",
            "JWT_MALFORMED",
            "JWT_NOT_YET_VALID",
            "JWT_EXPIRED",
            "JWT_ISSUER_MISMATCH",
            "JWT_AUDIENCE_MISMATCH",
            "JWT_SIGNATURE_REJECTED",
            "JWT_JWKS_FETCH_FAILED",
            "JWT_JWKS_HTTP_UNAVAILABLE",
            "JWT_JWKS_INVALID",
            "JWT_KID_NOT_FOUND",
            "JWT_KEY_IMPORT_FAILED",
            "JWT_SIGNATURE_MALFORMED",
            "JWT_SIGNATURE_VERIFY_FAILED",
            "WORKER_CONFIG_UNPROVEN",
        ] {
            assert!(
                source.contains(reason),
                "Worker must expose {reason} safely"
            );
        }
        assert!(source.contains("GITHUB_APPROVAL_DENIED"));
        assert!(source.contains("GITHUB_DEPENDENCY_UNAVAILABLE"));
        // A closed decision drives the response; diagnostic headers cannot
        // authorize a signature or silently change fail-closed semantics.
        assert!(source.contains("decision===\"UNAVAILABLE\"?503:403"));
        assert!(source.contains("X-Host-Github-Operation-Id"));
        for stage in [
            "GITHUB_COMMENT",
            "GITHUB_RELEASE",
            "GITHUB_MAIN",
            "GITHUB_PULLS",
        ] {
            assert!(source.contains(stage));
        }
        for kind in ["HTTP", "REDIRECT", "FETCH_EXCEPTION", "RESPONSE_DECODE"] {
            assert!(source.contains(kind));
        }
        assert!(source.contains("issued+120"));
        // Credential GET and dummy A/B proof route must remain in the
        // original Worker, never copied to a second privileged service.
        assert!(source.contains("/v1/proof-slot"));
        assert!(source.contains("u.pathname!==\"/v1/credentials\""));
        assert!(!source.contains("console.log"));
    }
}

#[test]
fn first_use_begin_file_create_new_has_no_overwrite_path() {
    let record = "<!-- sing-box-credential-initial-attempt/v1 -->\n{}";
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sing-box-initial-attempt-{}-{unique}",
        std::process::id()
    ));
    write_new_initial_record(&path, record).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), record);
    assert!(write_new_initial_record(&path, record).is_err());
    fs::remove_file(&path).unwrap();
    assert!(write_new_initial_record(&path, "INVALID").is_err());
}

fn desired() -> ProductionCredentialPlaneOwnership {
    ProductionCredentialPlaneOwnership {
        target_account_id: "6be6e4b6340822dbeb18cb6c2f09c660".to_owned(),
        access_organization_name: "sing-box".to_owned(),
        access_auth_domain: "sing-box-6be6e4b6.cloudflareaccess.com".to_owned(),
        windows_worker_name: "sing-box-credentials-windows".to_owned(),
        vm_worker_name: "sing-box-credentials-vm".to_owned(),
        windows_access_application_name: "sing-box-credentials-windows-access".to_owned(),
        vm_access_application_name: "sing-box-credentials-vm-access".to_owned(),
        windows_access_policy_name: "sing-box-credentials-windows-service-auth".to_owned(),
        vm_access_policy_name: "sing-box-credentials-vm-service-auth".to_owned(),
        windows_host_service_token_name: "sing-box-credentials-windows-host".to_owned(),
        vm_host_service_token_name: "sing-box-credentials-vm-host".to_owned(),
        worker_compatibility_date: "2026-09-28".to_owned(),
        host_service_token_duration: "forever".to_owned(),
        workers_dev_subdomain: "sing-box-6be6e4b6340822dbeb18cb6c2f09c660".to_owned(),
    }
}

fn projection_observation(
    desired: &ProductionCredentialPlaneOwnership,
    projection_name: &str,
) -> ProjectionObservation {
    let projection = projection_desired(desired, projection_name).unwrap();
    let host_token_id = format!("{projection_name}-host-token-id");
    ProjectionObservation {
        projection: projection.projection.clone(),
        worker_name: projection.worker_name.clone(),
        worker_script_present: true,
        worker_identity_present: true,
        worker_id: Some(format!("{projection_name}-worker-id")),
        worker_binding_count: Some(0),
        worker_secret_bindings: Vec::new(),
        worker_version_tag: Some(legacy_worker_version_tag(projection_name).unwrap()),
        worker_latest_version_id: Some(format!("{projection_name}-version-id")),
        worker_latest_version_tag: Some(legacy_worker_version_tag(projection_name).unwrap()),
        worker_active_deployment_id: Some(format!("{projection_name}-deployment-id")),
        worker_active_version_ids: vec![format!("{projection_name}-version-id")],
        workers_dev_enabled: Some(true),
        previews_enabled: Some(false),
        custom_domain_count: 0,
        host_service_token_id: Some(host_token_id.clone()),
        host_service_token_client_id: Some(format!("{projection_name}-host-client-id")),
        host_service_token_enabled: Some(true),
        host_service_token_duration: Some(desired.host_service_token_duration.clone()),
        access_application_id: Some(format!("{projection_name}-app-id")),
        access_application_type: Some("self_hosted".to_owned()),
        access_service_auth_401_redirect: Some(true),
        access_destination_type: Some("public".to_owned()),
        access_destination_worker_id: None,
        access_destination_uri: Some(workers_dev_hostname(desired, &projection)),
        access_destination_has_overrides: Some(false),
        access_policies: vec![cloudflare::CloudflareAccessPolicy {
            id: format!("{projection_name}-policy-id"),
            name: projection.access_policy_name,
            decision: Some("non_identity".to_owned()),
            include_service_token_ids: vec![host_token_id],
            has_extra_rules: false,
            precedence: Some(1),
            reusable: Some(false),
            app_count: None,
        }],
    }
}

fn observation(desired: &ProductionCredentialPlaneOwnership) -> CredentialPlaneObservation {
    CredentialPlaneObservation {
        control_token_identity: cloudflare::CloudflareApiTokenIdentity {
            id: "control-token-id".to_owned(),
            status: "active".to_owned(),
        },
        access_organization: Some(cloudflare::CloudflareAccessOrganization {
            name: desired.access_organization_name.clone(),
            auth_domain: desired.access_auth_domain.clone(),
            deny_unmatched_requests: Some(true),
        }),
        workers_dev_subdomain: Some(desired.workers_dev_subdomain.clone()),
        projections: vec![
            projection_observation(desired, "windows"),
            projection_observation(desired, "vm"),
        ],
    }
}

#[test]
fn exact_patch_readback_blocks_foreign_versions_or_implicit_deploy() {
    let d = desired();
    let mut state = observation(&d);
    make_terminal(&mut state, "vm");
    let original = state
        .projections
        .iter()
        .find(|p| p.projection == "vm")
        .unwrap()
        .clone();
    let mut pending = original.clone();
    pending.worker_latest_version_id = Some("fresh-version".to_owned());
    assert!(verify_exact_pending_worker_version(&original, &pending, "fresh-version").is_ok());

    let mut changed = pending.clone();
    changed.worker_latest_version_id = Some("foreign-version".to_owned());
    assert!(verify_exact_pending_worker_version(&original, &changed, "fresh-version").is_err());
    changed = pending.clone();
    changed.worker_active_version_ids = vec!["fresh-version".to_owned()];
    assert!(verify_exact_pending_worker_version(&original, &changed, "fresh-version").is_err());
    changed = pending.clone();
    changed.worker_active_deployment_id = Some("foreign-deployment".to_owned());
    assert!(verify_exact_pending_worker_version(&original, &changed, "fresh-version").is_err());
    changed = pending.clone();
    changed.worker_id = Some("foreign-worker".to_owned());
    assert!(verify_exact_pending_worker_version(&original, &changed, "fresh-version").is_err());
    changed = pending.clone();
    changed.worker_secret_bindings.pop();
    assert!(verify_exact_pending_worker_version(&original, &changed, "fresh-version").is_err());
    assert!(verify_exact_pending_worker_version(&original, &original, "fresh-version").is_err());
}

#[test]
fn exact_deployment_readback_never_accepts_old_or_foreign_latest() {
    let d = desired();
    let mut state = observation(&d);
    make_terminal(&mut state, "windows");
    let mut active = state
        .projections
        .iter()
        .find(|p| p.projection == "windows")
        .unwrap()
        .clone();
    active.worker_latest_version_id = Some("fresh-version".to_owned());
    active.worker_active_version_ids = vec!["fresh-version".to_owned()];
    assert!(verify_exact_active_worker_version(&active, "fresh-version").is_ok());
    active.worker_latest_version_id = Some("foreign-version".to_owned());
    assert!(verify_exact_active_worker_version(&active, "fresh-version").is_err());
    active.worker_latest_version_id = Some("fresh-version".to_owned());
    active.worker_active_version_ids = vec!["old-version".to_owned()];
    assert!(verify_exact_active_worker_version(&active, "fresh-version").is_err());
    active.worker_active_version_ids = vec!["fresh-version".to_owned()];
    active.worker_active_deployment_id = None;
    assert!(verify_exact_active_worker_version(&active, "fresh-version").is_err());
}

fn make_terminal(observed: &mut CredentialPlaneObservation, projection_name: &str) {
    let current = observed
        .projections
        .iter_mut()
        .find(|projection| projection.projection == projection_name)
        .unwrap();
    current.worker_binding_count = Some(2);
    current.worker_secret_bindings = vec![
        cloudflare::CloudflareWorkerSecretBinding {
            name: SLOT_A.to_owned(),
            binding_type: "secret_text".to_owned(),
        },
        cloudflare::CloudflareWorkerSecretBinding {
            name: SLOT_B.to_owned(),
            binding_type: "secret_text".to_owned(),
        },
    ];
    let version_tag = delivery_worker_material(projection_name)
        .unwrap()
        .version_tag;
    current.worker_version_tag = Some(version_tag.clone());
    current.worker_latest_version_tag = Some(version_tag);
}

#[test]
fn initial_provider_intent_is_exact_version_and_identity_bound() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "vm");
    make_terminal(&mut observed, "windows");

    let initial =
        initial_pair_provider_intent_sha256(&desired, &observed, 207, CredentialDeliverySlotArg::A)
            .unwrap();
    assert_eq!(initial.len(), 64);
    assert!(initial.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        initial,
        initial_pair_provider_intent_sha256(&desired, &observed, 207, CredentialDeliverySlotArg::A)
            .unwrap()
    );
    assert_ne!(
        initial,
        initial_pair_provider_intent_sha256(&desired, &observed, 208, CredentialDeliverySlotArg::A)
            .unwrap()
    );
    assert_ne!(
        initial,
        initial_pair_provider_intent_sha256(&desired, &observed, 207, CredentialDeliverySlotArg::B)
            .unwrap()
    );

    // Even a fully valid new Worker deployment invalidates all previously
    // observed attestations. Never reuse an intent under a changed version.
    observed.projections[0].worker_latest_version_id = Some("windows-updated-version".to_owned());
    observed.projections[0].worker_active_version_ids = vec!["windows-updated-version".to_owned()];
    let changed =
        initial_pair_provider_intent_sha256(&desired, &observed, 207, CredentialDeliverySlotArg::A)
            .unwrap();
    assert_ne!(initial, changed);
    observed.projections[0].worker_active_version_ids = vec!["windows-version-id".to_owned()];
    assert!(
        initial_pair_provider_intent_sha256(&desired, &observed, 207, CredentialDeliverySlotArg::A)
            .is_err()
    );
    observed.projections[0].worker_latest_version_id = Some("windows-version-id".to_owned());
    observed.projections[0].host_service_token_client_id =
        Some("replaced-access-client-id".to_owned());
    assert_ne!(
        initial,
        initial_pair_provider_intent_sha256(&desired, &observed, 207, CredentialDeliverySlotArg::A)
            .unwrap()
    );
}

#[test]
fn initial_pair_provider_gate_rejects_any_identity_or_version_drift() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "vm");
    make_terminal(&mut observed, "windows");
    assert!(
        validate_initial_pair_provider_observation(
            &desired,
            &observed,
            101,
            CredentialDeliverySlotArg::A,
        )
        .is_ok()
    );
    for invalid in [
        0,
        CREDENTIAL_DUMMY_PROBE_GENERATION_A,
        CREDENTIAL_DUMMY_PROBE_GENERATION_B,
    ] {
        assert!(
            validate_initial_pair_provider_observation(
                &desired,
                &observed,
                invalid,
                CredentialDeliverySlotArg::A,
            )
            .is_err()
        );
    }
    let client = observed.projections[0].host_service_token_client_id.clone();
    observed.projections[1].host_service_token_client_id = client;
    assert!(
        validate_initial_pair_provider_observation(
            &desired,
            &observed,
            101,
            CredentialDeliverySlotArg::A,
        )
        .is_err()
    );
    observed.projections[1].host_service_token_client_id = Some("distinct-client-id".to_owned());
    observed.projections[1].worker_active_version_ids = vec!["stale-active-version".to_owned()];
    assert!(
        validate_initial_pair_provider_observation(
            &desired,
            &observed,
            101,
            CredentialDeliverySlotArg::A,
        )
        .is_err()
    );
    observed.projections[1].worker_active_version_ids = vec!["vm-version-id".to_owned()];
    observed.projections[0].host_service_token_id =
        observed.projections[1].host_service_token_id.clone();
    assert!(
        validate_initial_pair_provider_observation(
            &desired,
            &observed,
            101,
            CredentialDeliverySlotArg::A,
        )
        .is_err()
    );
}

#[test]
fn temporary_access_identity_requires_exact_distinct_run_and_policy_set() {
    assert!(initial_acceptance_token_name(0).is_err());
    assert!(initial_acceptance_token_name(12).is_err());
    assert_eq!(
        initial_acceptance_token_name(38491677249).unwrap(),
        "sing-box-first-use-windows-38491677249"
    );
    let mut policy = cloudflare::CloudflareAccessPolicy {
        id: "policy-id".to_owned(),
        name: "windows-host-policy".to_owned(),
        decision: Some("non_identity".to_owned()),
        include_service_token_ids: vec!["host".to_owned(), "acceptance".to_owned()],
        has_extra_rules: false,
        precedence: None,
        reusable: None,
        app_count: None,
    };
    let expected = vec!["host".to_owned(), "acceptance".to_owned()];
    assert!(exact_service_auth_ids(&policy, &expected).is_ok());
    policy.include_service_token_ids.push("foreign".to_owned());
    assert!(exact_service_auth_ids(&policy, &expected).is_err());
    policy.include_service_token_ids = vec!["host".to_owned(), "host".to_owned()];
    assert!(exact_service_auth_ids(&policy, &["host".to_owned(), "host".to_owned()]).is_err());
    policy.include_service_token_ids = expected.clone();
    policy.has_extra_rules = true;
    assert!(exact_service_auth_ids(&policy, &expected).is_err());
    policy.has_extra_rules = false;
    policy.decision = Some("allow".to_owned());
    assert!(exact_service_auth_ids(&policy, &expected).is_err());
}

#[test]
fn host_bootstrap_policy_allows_only_exact_host_or_empty_create_once_state() {
    let host = "host-token-id";
    assert!(bootstrap_policy_is_safe(Some(host), &[host.to_owned()],));
    assert!(!bootstrap_policy_is_safe(
        Some(host),
        &["foreign-token-id".to_owned()],
    ));
    assert!(bootstrap_policy_is_safe(None, &[]));
    assert!(!bootstrap_policy_is_safe(
        None,
        &["foreign-token-id".to_owned()],
    ));
}

#[test]
fn bounded_transition_accepts_exact_legacy_and_exact_mixed_state() {
    let desired = desired();
    let mut observed = observation(&desired);
    assert_eq!(
        projection_delivery_state(
            &desired,
            &projection_desired(&desired, "windows").unwrap(),
            &observed,
        )
        .unwrap(),
        ProjectionDeliveryState::LegacyLocked
    );
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::InstallDummyAbContract {
            projection: "windows".to_owned(),
        }
    );

    make_terminal(&mut observed, "windows");
    assert_eq!(
        projection_delivery_state(
            &desired,
            &projection_desired(&desired, "windows").unwrap(),
            &observed,
        )
        .unwrap(),
        ProjectionDeliveryState::FixedAb
    );
    assert_eq!(
        projection_delivery_state(
            &desired,
            &projection_desired(&desired, "vm").unwrap(),
            &observed,
        )
        .unwrap(),
        ProjectionDeliveryState::LegacyLocked
    );
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::InstallDummyAbContract {
            projection: "vm".to_owned(),
        }
    );
}

#[test]
fn host_identity_must_be_enabled_forever_and_policy_bound() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "windows");
    make_terminal(&mut observed, "vm");
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::Noop
    );

    observed.projections[0].host_service_token_enabled = Some(false);
    assert!(plan(&desired, &observed).is_err());
    observed.projections[0].host_service_token_enabled = Some(true);

    observed.projections[0].host_service_token_duration = Some("1h".to_owned());
    assert!(plan(&desired, &observed).is_err());
    observed.projections[0].host_service_token_duration =
        Some(desired.host_service_token_duration.clone());

    observed.projections[0].access_policies[0]
        .include_service_token_ids
        .pop();
    assert!(plan(&desired, &observed).is_err());
}

#[test]
fn delivery_plan_is_one_atomic_mutation_per_projection() {
    let desired = desired();
    let mut observed = observation(&desired);

    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::InstallDummyAbContract {
            projection: "windows".to_owned(),
        }
    );

    make_terminal(&mut observed, "windows");
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::InstallDummyAbContract {
            projection: "vm".to_owned(),
        }
    );

    make_terminal(&mut observed, "vm");
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::Noop
    );
}

#[test]
fn delivery_material_is_typed_projection_specific_and_not_embedded_in_code() {
    let windows = delivery_worker_material("windows").unwrap();
    let vm = delivery_worker_material("vm").unwrap();
    assert_eq!(windows.slots.len(), 2);
    assert_eq!(vm.slots.len(), 2);
    assert_ne!(windows.source, vm.source);
    assert_ne!(windows.version_tag, vm.version_tag);

    for (material, projection) in [
        (&windows, CredentialProjectionKind::Windows),
        (&vm, CredentialProjectionKind::Vm),
    ] {
        for slot in &material.slots {
            let decoded = CredentialDeliveryBundle::decode(slot.payload.as_slice()).unwrap();
            assert_eq!(decoded.encode_to_vec(), slot.payload);
            assert_eq!(decoded.schema_version, 1);
            assert_eq!(decoded.generation, slot.generation);
            assert_eq!(decoded.projection, projection as i32);
            assert!(decoded.dummy_non_secret);
            assert_eq!(decoded.slot, CredentialDeliverySlot::Unspecified as i32);
            assert!(decoded.payload.is_none());
            assert_eq!(slot.secret_text, hex_encode(&slot.payload));
            assert!(!material.source.contains(&slot.secret_text));
        }
    }
    assert!(windows.source.contains(SLOT_A));
    assert!(windows.source.contains(SLOT_B));
    for worker in [&windows, &vm] {
        assert!(worker.source.contains("/v1/proof-slot"));
        assert!(
            worker
                .source
                .contains("crypto.subtle.digest(\"SHA-256\",b)")
        );
        assert!(!worker.source.contains("__DUMMY_A_DIGEST__"));
        assert!(!worker.source.contains("__DUMMY_B_DIGEST__"));
        for slot in &worker.slots {
            assert!(worker.source.contains(&sha256_hex(&slot.payload)));
            assert!(!worker.source.contains(&slot.secret_text));
        }
    }
    assert!(!windows.source.contains("private_key"));
    assert!(!windows.source.contains("password"));
}

#[test]
fn worker_proof_begin_is_exact_one_shot_and_rejects_unknown_history() {
    let record = WorkerProofAttempt {
        schema: "sing-box.worker-proof-upgrade/v1".to_owned(),
        phase: "BEGIN".to_owned(),
        github_run_id: 42,
        source_revision: "a".repeat(40),
        release_set_sha256: "b".repeat(64),
        baseline_sha256: "c".repeat(64),
    };
    let exact = format!(
        "{WORKER_PROOF_MARKER}\n{}",
        serde_json::to_string(&record).unwrap()
    );
    let history = serde_json::json!([{"body": exact}]).to_string();
    assert!(worker_proof_record("[]", None).unwrap().is_none());
    assert!(worker_proof_record(&history, None).is_err());
    assert_eq!(
        worker_proof_record(&history, Some(&exact))
            .unwrap()
            .unwrap()
            .github_run_id,
        42
    );
    assert!(worker_proof_record(&history, Some("wrong")).is_err());
    assert!(
        worker_proof_record(
            &serde_json::json!([{"body": exact}, {"body": exact}]).to_string(),
            Some(&exact)
        )
        .is_err()
    );
    assert!(
        worker_proof_record(
            &serde_json::json!([{"body": format!("prefix {exact}")}]).to_string(),
            Some(&exact)
        )
        .is_err()
    );
    assert!(worker_proof_record("truncated-json", None).is_err());
    assert!(worker_proof_record("[{}]", None).is_err());
}

#[test]
fn worker_code_reconcile_is_version_agnostic_but_exact_owner_and_binding_fenced() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let d = desired();
    let mut obs = observation(&d);
    make_terminal(&mut obs, "vm");
    let vm = projection_desired(&d, "vm").unwrap();
    let original = obs
        .projections
        .iter_mut()
        .find(|p| p.projection == "vm")
        .unwrap();
    original.worker_version_tag = Some("older-valid-worker-version".into());
    original.worker_latest_version_tag = original.worker_version_tag.clone();
    original.worker_binding_count = Some(8);
    original.worker_secret_bindings = [
        SLOT_A,
        SLOT_B,
        "EDGE_HOST_ACCESS_AUD",
        "EDGE_HOST_ACCESS_ISSUER",
        "EDGE_HOST_GITHUB_ACTOR_ID",
        "EDGE_HOST_GITHUB_APP_PKCS8_BASE64",
        "EDGE_HOST_SIGNING_KEY_ID",
        "EDGE_HOST_SIGNING_PKCS8_BASE64",
    ]
    .iter()
    .map(|name| cloudflare::CloudflareWorkerSecretBinding {
        name: (*name).to_owned(),
        binding_type: "secret_text".to_owned(),
    })
    .collect();
    let current = super::projection_observation(&obs, "vm").unwrap().clone();
    assert!(verify_vm_worker_reconcilable_current(&vm, &current).is_ok());
    let raw = b"observed old but valid code";
    let exact = cloudflare::CloudflareWorkerExactModule {
        id: current.worker_active_version_ids[0].clone(),
        created_on: "2026-10-29T14:20:00Z".into(),
        version_tag: "different-old-version-tag".into(),
        content_base64: STANDARD.encode(raw),
        secret_bindings: current.worker_secret_bindings.clone(),
    };
    assert_eq!(
        verified_vm_worker_active_code(&vm, &current, &exact),
        Ok(raw.to_vec())
    );
    let mut drift = current.clone();
    drift.worker_active_version_ids = vec!["foreign".into()];
    assert!(verify_vm_worker_reconcilable_current(&vm, &drift).is_err());
    drift = current.clone();
    drift.worker_binding_count = Some(7);
    assert!(verify_vm_worker_reconcilable_current(&vm, &drift).is_err());
    drift = current.clone();
    drift.worker_secret_bindings.pop();
    assert!(verify_vm_worker_reconcilable_current(&vm, &drift).is_err());
    drift = current.clone();
    drift.worker_active_deployment_id = None;
    assert!(verify_vm_worker_reconcilable_current(&vm, &drift).is_err());
    let windows = projection_desired(&d, "windows").unwrap();
    assert!(verify_vm_worker_reconcilable_current(&windows, &current).is_err());
    let mut invalid = exact.clone();
    invalid.id = "foreign-version".into();
    assert!(verified_vm_worker_active_code(&vm, &current, &invalid).is_err());
    invalid = exact.clone();
    invalid.secret_bindings.pop();
    assert!(verified_vm_worker_active_code(&vm, &current, &invalid).is_err());
    invalid = exact;
    invalid.content_base64 = "not-base64".into();
    assert!(verified_vm_worker_active_code(&vm, &current, &invalid).is_err());
}

#[test]
fn vm_only_upgrade_keeps_unknown_but_consistent_windows_code_read_only() {
    let d = desired();
    let mut obs = observation(&d);
    make_terminal(&mut obs, "windows");
    let windows = obs
        .projections
        .iter_mut()
        .find(|p| p.projection == "windows")
        .unwrap();
    // This is an intentionally unrecognized code tag. It is NOT a
    // Worker-version allowlist and does not authorize a Windows write.
    windows.worker_version_tag = Some("independent-windows-release-abc".to_owned());
    windows.worker_latest_version_tag = windows.worker_version_tag.clone();
    assert!(
        projection_delivery_state(&d, &projection_desired(&d, "windows").unwrap(), &obs).is_err()
    );
    assert!(verify_vm_only_windows_neighbour(&d, &obs).is_ok());
    let baseline = super::projection_observation(&obs, "windows")
        .unwrap()
        .clone();

    let mut conflicting = obs.clone();
    conflicting.projections[0].worker_latest_version_tag = Some("conflicting-tag".to_owned());
    assert_eq!(
        verify_vm_only_windows_neighbour(&d, &conflicting).unwrap_err(),
        "HOST_VM_WORKER_WINDOWS_TAG_READBACK_INCONSISTENT"
    );
    conflicting = obs.clone();
    conflicting.projections[0].worker_active_version_ids =
        vec!["foreign-active-version".to_owned()];
    assert_eq!(
        verify_vm_only_windows_neighbour(&d, &conflicting).unwrap_err(),
        "HOST_VM_WORKER_WINDOWS_DEPLOYMENT_AMBIGUOUS"
    );
    conflicting = obs.clone();
    conflicting.projections[0].worker_secret_bindings[0].binding_type = "plain_text".to_owned();
    assert!(verify_vm_only_windows_neighbour(&d, &conflicting).is_err());
    conflicting = obs.clone();
    conflicting.projections[0].worker_secret_bindings.push(
        cloudflare::CloudflareWorkerSecretBinding {
            name: "EDGE_HOST_SIGNING_PKCS8_BASE64".to_owned(),
            binding_type: "secret_text".to_owned(),
        },
    );
    conflicting.projections[0].worker_binding_count = Some(3);
    assert_eq!(
        verify_vm_only_windows_neighbour(&d, &conflicting).unwrap_err(),
        "HOST_VM_WORKER_WINDOWS_AB_BINDING_COUNT_INVALID"
    );
    // A VM projection change must never implicitly mutate Windows.
    let mut changed_vm = obs.clone();
    changed_vm.projections[1].worker_latest_version_id =
        Some("vm-code-only-pending-version".to_owned());
    assert_eq!(
        super::projection_observation(&changed_vm, "windows").unwrap(),
        &baseline
    );
    assert!(verify_vm_only_windows_neighbour(&d, &changed_vm).is_ok());
}

#[test]
fn old_generation_search_worker_requires_explicit_code_only_migration() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "vm");
    make_terminal(&mut observed, "windows");
    for projection in ["windows", "vm"] {
        let old = previous_fixed_ab_version_tag(projection)
            .unwrap()
            .to_owned();
        let current = observed
            .projections
            .iter_mut()
            .find(|value| value.projection == projection)
            .unwrap();
        current.worker_version_tag = Some(old.clone());
        current.worker_latest_version_tag = Some(old);
    }
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::UpgradeSlotProofCode {
            projection: "windows".to_owned(),
        }
    );
    assert!(
        validate_initial_pair_provider_observation(
            &desired,
            &observed,
            207,
            CredentialDeliverySlotArg::B,
        )
        .is_err()
    );
}

#[test]
fn delivery_plan_repairs_only_missing_fixed_ab_version_tags() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "windows");
    make_terminal(&mut observed, "vm");

    observed.projections[0].worker_version_tag = None;
    observed.projections[0].worker_latest_version_tag = None;
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::RestoreFixedAbVersionTag {
            projection: "windows".to_owned(),
        }
    );

    let windows_tag = delivery_worker_material("windows").unwrap().version_tag;
    observed.projections[0].worker_version_tag = Some(windows_tag.clone());
    observed.projections[0].worker_latest_version_tag = Some(windows_tag);
    observed.projections[1].worker_version_tag = None;
    observed.projections[1].worker_latest_version_tag = None;
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::RestoreFixedAbVersionTag {
            projection: "vm".to_owned(),
        }
    );
}

#[test]
fn delivery_plan_rejects_wrong_nonempty_fixed_ab_version_tag() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "windows");
    make_terminal(&mut observed, "vm");
    observed.projections[0].worker_version_tag = Some("unexpected-version".to_owned());
    assert!(plan(&desired, &observed).is_err());
}

#[test]
fn delivery_contract_recovers_tagged_latest_version_pending_deployment() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "windows");
    make_terminal(&mut observed, "vm");

    observed.projections[0].worker_active_version_ids = vec!["older-active-version".to_owned()];
    assert_eq!(
        projection_delivery_state(
            &desired,
            &projection_desired(&desired, "windows").unwrap(),
            &observed,
        )
        .unwrap(),
        ProjectionDeliveryState::FixedAbLatestPendingDeployment
    );
    assert_eq!(
        plan(&desired, &observed).unwrap(),
        CredentialDeliveryAction::RestoreFixedAbBaseline {
            projection: "windows".to_owned(),
        }
    );
}

#[test]
fn delivery_contract_rejects_disagreement_between_settings_and_latest_version_tags() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "windows");
    make_terminal(&mut observed, "vm");

    observed.projections[0].worker_latest_version_tag = None;
    assert!(plan(&desired, &observed).is_err());

    let expected = delivery_worker_material("windows").unwrap().version_tag;
    observed.projections[0].worker_latest_version_tag = Some(expected);
    observed.projections[0].worker_version_tag = None;
    assert!(plan(&desired, &observed).is_err());
}

#[test]
fn delivery_contract_rejects_extra_bindings() {
    let desired = desired();
    let mut observed = observation(&desired);
    make_terminal(&mut observed, "windows");
    observed.projections[0].worker_secret_bindings.push(
        cloudflare::CloudflareWorkerSecretBinding {
            name: "UNEXPECTED".to_owned(),
            binding_type: "secret_text".to_owned(),
        },
    );
    observed.projections[0].worker_binding_count = Some(3);
    assert!(plan(&desired, &observed).is_err());
}

#[test]
fn vm_worker_upgrade_decision_is_closed_and_fail_closed() {
    use VmWorkerUpgradeDecision as Decision;

    let accepted = Decision::from_verified_state(ProjectionDeliveryState::FixedAb).unwrap();
    assert_eq!(accepted, Decision::AlreadyAccepted);
    assert_eq!(accepted.workflow_required(), "false");

    let upgrade =
        Decision::from_verified_state(ProjectionDeliveryState::FixedAbProofUpgradeRequired)
            .unwrap();
    assert_eq!(upgrade, Decision::UpgradeRequired);
    assert_eq!(upgrade.workflow_required(), "true");

    for unproven in [
        ProjectionDeliveryState::LegacyLocked,
        ProjectionDeliveryState::FixedAbVersionTagMissing,
        ProjectionDeliveryState::FixedAbLatestPendingDeployment,
    ] {
        assert_eq!(
            Decision::from_verified_state(unproven),
            Err("HOST_VM_WORKER_PLAN_STATE_NOT_ADMITTED")
        );
    }
}

#[test]
fn pending_vm_worker_reconciliation_refuses_unbound_or_drifted_code() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let d = desired();
    let vm = projection_desired(&d, "vm").unwrap();
    let mut state = observation(&d);
    make_terminal(&mut state, "vm");
    let mut current = state
        .projections
        .iter()
        .find(|projection| projection.projection == "vm")
        .unwrap()
        .clone();
    current.worker_active_version_ids = vec!["old-version".into()];
    current.worker_latest_version_id = Some("pending-version".into());
    let names = [
        "EDGE_CREDENTIAL_BUNDLE_A",
        "EDGE_CREDENTIAL_BUNDLE_B",
        "EDGE_HOST_ACCESS_AUD",
        "EDGE_HOST_ACCESS_ISSUER",
        "EDGE_HOST_GITHUB_ACTOR_ID",
        "EDGE_HOST_GITHUB_APP_PKCS8_BASE64",
        "EDGE_HOST_SIGNING_KEY_ID",
        "EDGE_HOST_SIGNING_PKCS8_BASE64",
    ];
    current.worker_binding_count = Some(8);
    current.worker_secret_bindings = names
        .iter()
        .map(|name| cloudflare::CloudflareWorkerSecretBinding {
            name: (*name).into(),
            binding_type: "secret_text".into(),
        })
        .collect();
    let old_source = "old version JavaScript";
    let new_source = "new accepted exact JavaScript";
    let accepted = AcceptedVmWorkerSource {
        desired: sha256_hex(new_source.as_bytes()),
        predecessor: sha256_hex(old_source.as_bytes()),
    };
    let tag = format!("sing-box-phase6-ab-vm-{}", &accepted.desired[..16]);
    current.worker_latest_version_tag = Some(tag.clone());
    let material = DeliveryWorkerMaterial {
        source: new_source.into(),
        version_tag: tag.clone(),
        slots: vec![],
    };
    let old = cloudflare::CloudflareWorkerExactModule {
        id: "old-version".into(),
        created_on: "2026-10-24T20:07:44Z".into(),
        version_tag: format!("sing-box-phase6-ab-vm-{}", &accepted.predecessor[..16]),
        content_base64: STANDARD.encode(old_source.as_bytes()),
        secret_bindings: current.worker_secret_bindings.clone(),
    };
    let pending = cloudflare::CloudflareWorkerExactModule {
        id: "pending-version".into(),
        created_on: "2026-10-24T21:22:15Z".into(),
        version_tag: tag,
        content_base64: STANDARD.encode(new_source.as_bytes()),
        secret_bindings: current.worker_secret_bindings.clone(),
    };
    assert!(
        verify_pending_vm_worker_exact_modules(&vm, &current, &accepted, &material, &old, &pending)
            .is_ok()
    );
    // Legitimate deployed predecessor may be an older accepted release.
    // Only active version ID, bindings and pending desired bytes matter.
    let mut arbitrary_old = old.clone();
    arbitrary_old.version_tag = "older-registered-worker".into();
    assert!(
        verify_pending_vm_worker_exact_modules(
            &vm,
            &current,
            &accepted,
            &material,
            &arbitrary_old,
            &pending
        )
        .is_ok()
    );
    let mut foreign_old = old.clone();
    foreign_old.content_base64 = "!!!".into();
    assert!(
        verify_pending_vm_worker_exact_modules(
            &vm,
            &current,
            &accepted,
            &material,
            &foreign_old,
            &pending
        )
        .is_err()
    );
    let mut foreign = pending.clone();
    foreign.id = "foreign-version".into();
    assert!(
        verify_pending_vm_worker_exact_modules(&vm, &current, &accepted, &material, &old, &foreign)
            .is_err()
    );
    foreign = pending.clone();
    foreign.content_base64 = STANDARD.encode("wrong source bytes");
    assert!(
        verify_pending_vm_worker_exact_modules(&vm, &current, &accepted, &material, &old, &foreign)
            .is_err()
    );
    foreign = pending.clone();
    foreign.secret_bindings.pop();
    assert!(
        verify_pending_vm_worker_exact_modules(&vm, &current, &accepted, &material, &old, &foreign)
            .is_err()
    );
    let mut wrong_active = current.clone();
    wrong_active.worker_active_version_ids = vec!["old", "second"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert!(
        verify_pending_vm_worker_exact_modules(
            &vm,
            &wrong_active,
            &accepted,
            &material,
            &old,
            &pending
        )
        .is_err()
    );
    let mut wrong_deploy = current;
    wrong_deploy.worker_active_deployment_id = None;
    assert!(
        verify_pending_vm_worker_exact_modules(
            &vm,
            &wrong_deploy,
            &accepted,
            &material,
            &old,
            &pending
        )
        .is_err()
    );
}
