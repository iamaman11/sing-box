//! One continuation of the existing protected Worker owner and Issue #26 BEGIN.
//! Every provider error terminates this transaction. No retry or cleanup writes.
use super::*;

fn unchanged_credentials(
    before: &CredentialPlaneObservation,
    after: &CredentialPlaneObservation,
) -> Result<(), String> {
    for projection in ["vm", "windows"] {
        let mut left = projection_observation(before, projection)?.clone();
        let mut right = projection_observation(after, projection)?.clone();
        if projection == "vm" {
            // Only the VM version and the one additional audience may change.
            left.worker_binding_count = None;
            right.worker_binding_count = None;
            left.worker_secret_bindings.clear();
            right.worker_secret_bindings.clear();
            left.worker_latest_version_id = None;
            right.worker_latest_version_id = None;
            left.worker_active_version_ids.clear();
            right.worker_active_version_ids.clear();
            left.worker_active_deployment_id = None;
            right.worker_active_deployment_id = None;
        }
        if left != right {
            return Err("HOST_ACCESS_CREDENTIAL_NEIGHBOUR_DRIFT_NO_REPLAY".into());
        }
    }
    Ok(())
}

async fn prove_vm_host(host: &edge_shared_types::FleetHost) -> Result<(), String> {
    let id = required_env("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID")?;
    let secret = required_env("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET")?;
    edge_secrets::prove_canonical_host_signer_with_service_identity(
        &id,
        &secret,
        &host.worker_authority_public_key,
    )
    .await?;
    verify_current_vm_first_use_worker_source(host).await
}

async fn prove_vm_authorization(
    host: &edge_shared_types::FleetHost,
    release: &edge_orchestrator::OrchestrationContext,
) -> Result<(), String> {
    use edge_shared_types::{FleetHostAction, FleetHostIntent, ManagedHostKind};
    let context = std::path::PathBuf::from(required_env("EDGE_RELEASE_CONTEXT_PATH")?);
    let registry = fs::read(
        context
            .parent()
            .ok_or("HOST_ACCESS_RELEASE_PATH_REQUIRED")?
            .join("fleet-registry.pb"),
    )
    .map_err(|_| "HOST_ACCESS_REGISTRY_UNREADABLE")?;
    let desired =
        fs::read(&host.desired_spec_path).map_err(|_| "HOST_ACCESS_DESIRED_UNREADABLE")?;
    let release_sha = &release.release().release_set_sha256;
    let release_bytes = (0..release_sha.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&release_sha[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "HOST_ACCESS_RELEASE_INVALID")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "HOST_ACCESS_CLOCK_UNAVAILABLE")?
        .as_secs();
    let intent = FleetHostIntent {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        kind: ManagedHostKind::Vm as i32,
        resource_id: "sing-box".into(),
        operation_id: format!("issue1-comment-{}", required_env("SOURCE_COMMENT_ID")?),
        action: FleetHostAction::Apply as i32,
        registry_sha256: digest(&SHA256, &registry).as_ref().to_vec(),
        desired_sha256: edge_shared_types::host_lifecycle::digest_host_desired(host, &desired)
            .map_err(str::to_owned)?,
        release_set_sha256: release_bytes,
        requested_mode: 0,
        requested_at_unix: now,
        network_admission: None,
    };
    // Only obtain and verify detached authorization. It is never transported
    // to Root Agent and cannot execute an administrative action in this job.
    let authorization = edge_secrets::request_canonical_host_authorization_with_service_identity(
        &intent.encode_to_vec(),
        &required_env("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID")?,
        &required_env("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET")?,
    )
    .await?;
    edge_shared_types::host_lifecycle::verify_host_authorization(
        &intent,
        &authorization,
        &host.worker_authority_public_key,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "HOST_ACCESS_CLOCK_UNAVAILABLE")?
            .as_secs(),
    )
    .map_err(str::to_owned)?;
    println!("host_access_vm_authorization=VERIFIED_NOT_EXECUTED");
    Ok(())
}

pub(super) async fn apply(
    machine_id: &str,
    release: &edge_orchestrator::OrchestrationContext,
    desired: &ProductionCredentialPlaneOwnership,
    control: &str,
    worker_write: &str,
) -> Result<(), String> {
    let host = release.verified_vm_first_use_host(machine_id)?;
    let baseline = observe(control, desired).await?;
    require_host_access_control_identity(desired, &baseline.control_token_identity)?;
    let phase = host_access_readback(desired, &baseline)?;
    if phase == HostAccessReadback::ActiveAwaitSignedHostProof {
        prove_vm_host(&host).await?;
        println!("host_access_cutover=ACTIVE_AWAIT_SIGNED_HOST_PROOF");
        return Ok(());
    }
    // A previous partial cutover must be reconciled explicitly, never resumed
    // by minting a fresh Issue #26 transaction over its unknown effects.
    if phase != HostAccessReadback::NotProvisionedLegacyVmPreserved {
        return Err("HOST_ACCESS_EXISTING_TRANSITION_REQUIRES_RECONCILIATION_NO_REPLAY".into());
    }
    let vm = projection_observation(&baseline, "vm")?;
    let win = projection_observation(&baseline, "windows")?;
    let active = vm
        .worker_active_version_ids
        .first()
        .ok_or("HOST_ACCESS_ACTIVE_VERSION_REQUIRED")?;
    if vm.worker_active_version_ids.len() != 1
        || vm.worker_latest_version_id.as_ref() != Some(active)
    {
        return Err("HOST_ACCESS_PENDING_DEPLOYMENT_NO_REPLAY".into());
    }
    let old_module = cloudflare::get_worker_exact_version_module(
        control,
        &desired.target_account_id,
        &vm.worker_name,
        active,
    )
    .await?;
    prove_vm_host(&host).await?;
    // All prerequisite crypto/credential/authority failures must occur before
    // creating the staged application. Repeat after binding and after cutover.
    prove_vm_authorization(&host, release).await?;
    crate::vm_worker_begin_reconciliation::verify_current_vm_worker_begin(machine_id).await?;
    if observe(control, desired).await? != baseline {
        return Err("HOST_ACCESS_PREFLIGHT_CHANGED_NO_REPLAY".into());
    }
    let hostname = format!(
        "{}.{}.workers.dev",
        desired.vm_worker_name, desired.workers_dev_subdomain
    );
    let app_id = cloudflare::create_host_access_staged_application(
        control,
        &desired.target_account_id,
        &desired.host_access_application_name,
        &hostname,
    )
    .await
    .map_err(|_| "HOST_ACCESS_STAGE_UNKNOWN_NO_REPLAY")?;
    let staged = observe(control, desired).await?;
    unchanged_credentials(&baseline, &staged)?;
    if host_access_readback(desired, &staged)? != HostAccessReadback::StagedAwaitExactPolicy
        || staged.host_access.as_ref().map(|a| a.app.id.as_str()) != Some(app_id.as_str())
    {
        return Err("HOST_ACCESS_STAGE_READBACK_NO_REPLAY".into());
    }
    let policy_id = cloudflare::create_host_access_exact_service_auth_policy(
        control,
        &desired.target_account_id,
        &app_id,
        &desired.host_access_policy_name,
        vm.host_service_token_id
            .as_deref()
            .ok_or("HOST_ACCESS_VM_TOKEN_REQUIRED")?,
        win.host_service_token_id
            .as_deref()
            .ok_or("HOST_ACCESS_WINDOWS_TOKEN_REQUIRED")?,
    )
    .await
    .map_err(|_| "HOST_ACCESS_POLICY_UNKNOWN_NO_REPLAY")?;
    let policy = observe(control, desired).await?;
    unchanged_credentials(&baseline, &policy)?;
    if host_access_readback(desired, &policy)? != HostAccessReadback::StagedAwaitWorkerAudience {
        return Err("HOST_ACCESS_POLICY_READBACK_NO_REPLAY".into());
    }
    let audience = &policy
        .host_access
        .as_ref()
        .ok_or("HOST_ACCESS_APP_REQUIRED")?
        .audience;
    let version = cloudflare::patch_latest_worker_version_secrets(
        worker_write,
        &desired.target_account_id,
        &vm.worker_name,
        &old_module.version_tag,
        &[("EDGE_HOST_ROUTE_ACCESS_AUD", audience)],
    )
    .await
    .map_err(|_| "HOST_ACCESS_BINDING_UNKNOWN_NO_REPLAY")?;
    let pending = cloudflare::get_worker_exact_version_module(
        control,
        &desired.target_account_id,
        &vm.worker_name,
        &version,
    )
    .await?;
    if pending.content_base64 != old_module.content_base64
        || pending.version_tag != old_module.version_tag
        || pending.secret_bindings.len() != 9
    {
        return Err("HOST_ACCESS_SOURCE_OR_BINDINGS_DRIFT_NO_REPLAY".into());
    }
    cloudflare::deploy_worker_version(
        worker_write,
        &desired.target_account_id,
        &vm.worker_name,
        &version,
    )
    .await
    .map_err(|_| "HOST_ACCESS_DEPLOYMENT_UNKNOWN_NO_REPLAY")?;
    let bound = observe(control, desired).await?;
    unchanged_credentials(&baseline, &bound)?;
    if host_access_readback(desired, &bound)? != HostAccessReadback::StagedAwaitSignerProof
        || bound.host_access != policy.host_access
        || projection_observation(&bound, "vm")?.worker_active_version_ids != vec![version.clone()]
    {
        return Err("HOST_ACCESS_DEPLOYMENT_READBACK_NO_REPLAY".into());
    }
    let deployed = cloudflare::get_worker_exact_version_module(
        control,
        &desired.target_account_id,
        &vm.worker_name,
        &version,
    )
    .await?;
    if deployed != pending {
        return Err("HOST_ACCESS_DEPLOYED_SOURCE_DRIFT_NO_REPLAY".into());
    }
    // Cryptographic proof and exact credential protobuf GET are mandatory
    // while the production Host route still uses its original Access policy.
    prove_vm_host(&host).await?;
    prove_vm_authorization(&host, release).await?;
    if observe(control, desired).await? != bound {
        return Err("HOST_ACCESS_PRECUTOVER_CHANGED_NO_REPLAY".into());
    }
    cloudflare::activate_exact_host_access_path(
        control,
        &desired.target_account_id,
        &app_id,
        &desired.host_access_application_name,
        &hostname,
        &policy_id,
    )
    .await
    .map_err(|_| "HOST_ACCESS_CUTOVER_UNKNOWN_NO_REPLAY")?;
    let final_state = observe(control, desired).await?;
    unchanged_credentials(&baseline, &final_state)?;
    if host_access_readback(desired, &final_state)?
        != HostAccessReadback::ActiveAwaitSignedHostProof
    {
        return Err("HOST_ACCESS_CUTOVER_READBACK_NO_REPLAY".into());
    }
    if final_state.projections != bound.projections
        || final_state
            .host_access
            .as_ref()
            .map(|r| (r.app.id.as_str(), r.audience.as_str()))
            != Some((app_id.as_str(), audience.as_str()))
    {
        return Err("HOST_ACCESS_FINAL_AUTHORITY_DRIFT_NO_REPLAY".into());
    }
    prove_vm_host(&host).await?;
    prove_vm_authorization(&host, release).await?;
    println!("host_access_cutover=ACTIVE_AWAIT_SIGNED_HOST_PROOF");
    println!("host_access_credentials=EXACT_ISOLATED");
    println!("host_access_windows_acceptance=PENDING_SYSTEM_SIGNED_READBACK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_signer_enrollment_remains_a_separate_existing_owner() {
        let phase = HostAccessReadback::NotProvisionedLegacyVmPreserved;
        assert_eq!(requires_host_access_transition(&[], phase), Ok(false));
        assert_eq!(requires_host_access_transition(&[7; 32], phase), Ok(true));
        assert!(requires_host_access_transition(&[7; 31], phase).is_err());
        assert_eq!(
            requires_host_access_transition(
                &[7; 32],
                HostAccessReadback::ActiveAwaitSignedHostProof
            ),
            Ok(false)
        );
    }
    #[test]
    fn control_identity_is_git_pinned_and_active() {
        let mut desired = super::super::tests::desired();
        let identity = cloudflare::CloudflareApiTokenIdentity {
            id: "1234567890abcdef1234567890abcdef".into(),
            status: "active".into(),
        };
        desired.host_access_control_identity_sha256 = sha256_hex(identity.id.as_bytes());
        assert!(require_host_access_control_identity(&desired, &identity).is_ok());
        desired.host_access_control_identity_sha256 = "0".repeat(64);
        assert!(require_host_access_control_identity(&desired, &identity).is_err());
        desired.host_access_control_identity_sha256 = sha256_hex(identity.id.as_bytes());
        let inactive = cloudflare::CloudflareApiTokenIdentity {
            status: "disabled".into(),
            ..identity
        };
        assert!(require_host_access_control_identity(&desired, &inactive).is_err());
    }

    #[test]
    fn cutover_cannot_change_either_credential_policy_or_windows_worker() {
        let desired = super::super::tests::desired();
        let before = super::super::tests::observation(&desired);
        assert!(unchanged_credentials(&before, &before).is_ok());
        for projection in ["vm", "windows"] {
            let mut drift = before.clone();
            let p = drift
                .projections
                .iter_mut()
                .find(|p| p.projection == projection)
                .unwrap();
            p.access_policies[0]
                .include_service_token_ids
                .push("foreign-token".into());
            assert!(unchanged_credentials(&before, &drift).is_err());
            let mut drift = before.clone();
            let p = drift
                .projections
                .iter_mut()
                .find(|p| p.projection == projection)
                .unwrap();
            p.host_service_token_id = Some("substituted".into());
            assert!(unchanged_credentials(&before, &drift).is_err());
        }
        let mut drift = before.clone();
        drift
            .projections
            .iter_mut()
            .find(|p| p.projection == "windows")
            .unwrap()
            .worker_latest_version_id = Some("unexpected-version".into());
        assert!(unchanged_credentials(&before, &drift).is_err());
    }
}
