//! VM first-use credential attestations, independent of Worker signer rotation.
//! Git public pin alone never authorizes Vultr CREATE. This module is GET-only.
use super::*;

pub(super) fn attest_vm_first_use_credential_bytes(
    bytes: &[u8],
    generation: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    if generation == 0
        || matches!(
            generation,
            CREDENTIAL_DUMMY_PROBE_GENERATION_A | CREDENTIAL_DUMMY_PROBE_GENERATION_B
        )
        || expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || expected_sha256.bytes().all(|b| b == b'0')
    {
        return Err("HOST_VM_FIRST_USE_CANDIDATE_IDENTITY_INVALID".to_owned());
    }
    let bundle = edge_shared_types::decode_credential_delivery_bundle(bytes)
        .map_err(|_| "HOST_VM_FIRST_USE_CREDENTIAL_PROTOBUF_INVALID".to_owned())?;
    if bundle.generation != generation
        || bundle.projection != CredentialProjectionKind::Vm as i32
        || bundle.dummy_non_secret
        || !matches!(
            bundle.payload,
            Some(edge_shared_types::credential_delivery_bundle::Payload::Vm(
                _
            ))
        )
        || !matches!(
            CredentialDeliverySlot::try_from(bundle.slot),
            Ok(CredentialDeliverySlot::A | CredentialDeliverySlot::B)
        )
    {
        return Err("HOST_VM_FIRST_USE_CREDENTIAL_NOT_FULL_VM_PAYLOAD".to_owned());
    }
    if sha256_hex(bytes) != expected_sha256 {
        return Err("HOST_VM_FIRST_USE_CREDENTIAL_DIGEST_MISMATCH".to_owned());
    }
    Ok(())
}

/// Read-only Worker origin checks remain valid after the exact public Git pin.
/// A registered receipt is NOT a provider CREATE or INSTALL permit.
pub(super) fn vm_worker_readonly_proof_git_state(
    host: &edge_shared_types::FleetHost,
    machine_id: &str,
    generation: u64,
    sha256: &str,
) -> Result<&'static str, &'static str> {
    if host.machine_id != machine_id {
        return Err("HOST_VM_CREDENTIAL_PROOF_MACHINE_MISMATCH");
    }
    match host.vm_first_use_credential.as_ref() {
        Some(pin) if pin.generation == generation && pin.bundle_sha256 == sha256 => {
            Ok("PROTECTED_GIT_EXACT")
        }
        Some(_) => Err("HOST_VM_CREDENTIAL_PROOF_GIT_PIN_MISMATCH"),
        None if host.native_receipt_public_key.is_empty() => Ok("NOT_YET_REGISTERED"),
        None => Err("HOST_VM_CREDENTIAL_PROOF_REGISTERED_RECEIPT_WITHOUT_SOURCE"),
    }
}

/// One source of truth for authenticated, bounded VM credential readback.
/// This is GET-only and validates a full typed non-dummy Worker payload.
async fn fetch_and_attest_vm_first_use_worker_source(
    generation: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let plane = &production.cloudflare.credential_plane;
    if production.cloudflare.active_account_id != plane.target_account_id
        || production.cloudflare.migration_target_account_id.is_some()
    {
        return Err("HOST_VM_CREDENTIAL_PROOF_CLOUDFLARE_ACCOUNT_DRIFT".to_owned());
    }
    let id = required_env("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID")?;
    let secret = required_env("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET")?;
    let bytes = cloudflare::get_vm_credential_bundle_with_access(
        &plane.vm_worker_name,
        &plane.workers_dev_subdomain,
        generation,
        &id,
        &secret,
    )
    .await?;
    attest_vm_first_use_credential_bytes(&bytes, generation, expected_sha256)?;
    Ok(())
}

/// Called at both protected first-use preflight and the actual CREATE edge.
/// Git-only public metadata never authorizes a VM until this real Worker
/// Access GET matches the complete VM payload and exact SHA-256.
pub(crate) async fn verify_current_vm_first_use_worker_source(
    host: &edge_shared_types::FleetHost,
) -> Result<(), String> {
    edge_shared_types::host_lifecycle::verify_vm_first_use_git_prerequisites(host)
        .map_err(str::to_owned)?;
    let pinned = host
        .vm_first_use_credential
        .as_ref()
        .ok_or("HOST_VM_FIRST_USE_CREDENTIAL_GIT_REQUIRED")?;
    fetch_and_attest_vm_first_use_worker_source(pinned.generation, &pinned.bundle_sha256).await?;
    println!("host_vm_first_use_worker_source=GIT_PIN_VERIFIED_WITH_ACCESS_GET");
    println!("host_worker_mutations=0");
    Ok(())
}

pub(crate) async fn host_vm_credential_proof(
    machine_id: &str,
    release: &edge_orchestrator::OrchestrationContext,
    generation: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    for (key, expected) in [
        ("GITHUB_REPOSITORY", "iamaman11/sing-box"),
        ("GITHUB_REPOSITORY_ID", "1221750822"),
        ("GITHUB_EVENT_NAME", "issue_comment"),
        ("GITHUB_ACTOR_ID", "44100369"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("GITHUB_JOB", "host_capabilities"),
    ] {
        if env::var(key).ok().as_deref() != Some(expected) {
            return Err(format!("HOST_VM_CREDENTIAL_PROOF_UNTRUSTED_{key}"));
        }
    }
    if env::var("GITHUB_SHA").ok().as_deref() != Some(release.release().accepted_revision.as_str())
        || env::var("HOST_ORIGINAL_COMMAND").ok().as_deref()
            != Some(format!("/host status {machine_id} --deep").as_str())
    {
        return Err("HOST_VM_CREDENTIAL_PROOF_SOURCE_UNTRUSTED".to_owned());
    }
    let host = release.verified_vm_first_use_host(machine_id)?;
    let git_pin =
        vm_worker_readonly_proof_git_state(&host, machine_id, generation, expected_sha256)
            .map_err(str::to_owned)?;
    fetch_and_attest_vm_first_use_worker_source(generation, expected_sha256).await?;
    println!("host_vm_first_use_credential_proof=EXACT_NON_DUMMY_VM_WORKER_PAYLOAD");
    println!("host_vm_first_use_generation={generation}");
    println!("host_vm_first_use_bundle_sha256={expected_sha256}");
    println!("host_vm_first_use_worker_owner=CANONICAL_CLOUDFLARE_VM");
    println!("host_vm_first_use_credential_git_pin={git_pin}");
    println!("host_vm_create=NOT_AUTHORIZED");
    println!("host_mutations=0");
    Ok(())
}

