//! One typed, release-bound lifecycle contract shared by Windows, VM and fleet.
//!
//! Parsing or validating an intent is never authorization to mutate. The
//! privileged native owner must independently authenticate admission, check its
//! durable operation ledger, and read back the affected resource before it can
//! issue a VERIFIED receipt. No compatibility with legacy A/B dispatcher.

use crate::{
    FleetHost, FleetHostAction, FleetHostAuthorization, FleetHostIntent, FleetHostKind,
    FleetHostMode, FleetHostResult, FleetHostResultState, HostRegistry, managed_host,
};
use prost::Message;

pub const MAX_HOST_INTENT_BYTES: usize = 8192;
pub const MAX_HOST_RESULT_BYTES: usize = 8192;

pub const MAX_NATIVE_OBSERVATION_BYTES: usize = 4096;

/// Returns a local typed readback, not a signed mutation receipt. Kind and
/// release digest semantics are fixed: Windows activation records are NOT
/// interchangeable with VM application bundle digests.
pub fn build_native_observation(
    kind: crate::FleetHostKind,
    state: crate::FleetNativeOwnerState,
    proof: crate::FleetNativeReleaseProof,
    release_digest_hex: Option<&str>,
    runtime_ready: Option<bool>,
    observed_at_unix: u64,
    reason_codes: &[&str],
) -> Result<crate::FleetNativeObservation, &'static str> {
    use crate::{FleetHostKind, FleetNativeObservation, FleetNativeReleaseProof};
    let mut release = Vec::new();
    if let Some(value) = release_digest_hex {
        if value.len() != 64
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("HOST_OBSERVATION_RELEASE_DIGEST_INVALID");
        }
        for chunk in value.as_bytes().chunks_exact(2) {
            let high = (chunk[0] as char)
                .to_digit(16)
                .ok_or("HOST_OBSERVATION_DIGEST_INVALID")?;
            let low = (chunk[1] as char)
                .to_digit(16)
                .ok_or("HOST_OBSERVATION_DIGEST_INVALID")?;
            release.push(((high << 4) | low) as u8);
        }
    }
    let expected = match kind {
        FleetHostKind::Windows => FleetNativeReleaseProof::ActivationRecord,
        FleetHostKind::Vm => FleetNativeReleaseProof::ApplicationBundle,
        FleetHostKind::Unspecified => return Err("HOST_OBSERVATION_KIND_INVALID"),
    };
    if !matches!(
        proof,
        FleetNativeReleaseProof::Unproven | FleetNativeReleaseProof::VerifiedAbsent
    ) && proof != expected
    {
        return Err("HOST_OBSERVATION_PROOF_KIND_MISMATCH");
    }
    if release.is_empty()
        != matches!(
            proof,
            FleetNativeReleaseProof::Unproven | FleetNativeReleaseProof::VerifiedAbsent
        )
    {
        return Err("HOST_OBSERVATION_RELEASE_PROOF_INCOMPLETE");
    }
    let observation = FleetNativeObservation {
        schema_version: 1,
        host_kind: kind as i32,
        observed_at_unix,
        owner_state: state as i32,
        release_proof: proof as i32,
        observed_release_sha256: release,
        runtime_ready: runtime_ready.unwrap_or(false),
        runtime_ready_proven: runtime_ready.is_some(),
        reason_codes: reason_codes.iter().map(|s| (*s).to_owned()).collect(),
    };
    validate_native_observation(&observation)?;
    Ok(observation)
}

pub fn validate_native_observation(
    observed: &crate::FleetNativeObservation,
) -> Result<(), &'static str> {
    use crate::{FleetHostKind, FleetNativeOwnerState, FleetNativeReleaseProof};
    let kind =
        FleetHostKind::try_from(observed.host_kind).map_err(|_| "HOST_OBSERVATION_KIND_INVALID")?;
    let state = FleetNativeOwnerState::try_from(observed.owner_state)
        .map_err(|_| "HOST_OBSERVATION_STATE_INVALID")?;
    let proof = FleetNativeReleaseProof::try_from(observed.release_proof)
        .map_err(|_| "HOST_OBSERVATION_PROOF_INVALID")?;
    if observed.schema_version != 1
        || observed.observed_at_unix == 0
        || kind == FleetHostKind::Unspecified
        || matches!(state, FleetNativeOwnerState::Unspecified)
        || matches!(proof, FleetNativeReleaseProof::Unspecified)
        || (kind == FleetHostKind::Windows && proof == FleetNativeReleaseProof::ApplicationBundle)
        || (kind == FleetHostKind::Vm && proof == FleetNativeReleaseProof::ActivationRecord)
        || (observed.observed_release_sha256.is_empty()
            != matches!(
                proof,
                FleetNativeReleaseProof::Unproven | FleetNativeReleaseProof::VerifiedAbsent
            ))
        || (proof == FleetNativeReleaseProof::VerifiedAbsent
            && (state != FleetNativeOwnerState::Stopped || observed.runtime_ready))
        || (!observed.observed_release_sha256.is_empty()
            && observed.observed_release_sha256.len() != 32)
        || (observed.runtime_ready && !observed.runtime_ready_proven)
        || observed.reason_codes.len() > 12
        || observed.reason_codes.iter().any(|code| {
            code.is_empty()
                || code.len() > 96
                || !code
                    .bytes()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == b'_')
        })
        || observed.encode_to_vec().len() > MAX_NATIVE_OBSERVATION_BYTES
    {
        return Err("HOST_OBSERVATION_EVIDENCE_INVALID");
    }
    Ok(())
}

/// Historical reconciliation may release an old BEGIN only when the
/// independently observed baseline has no readiness defects, or when the
/// sole defect is an *addressed* WARP consumer datapath probe. Generic
/// egress, absent consumers/ports, missing resources, unknown and truncated
/// evidence can conceal an incomplete Docker effect and must remain pending.
/// This does not claim that the original effect succeeded or authorize replay.
pub(crate) fn known_runtime_only_historical_reasons(observed: &crate::FleetNativeObservation) -> bool {
    if !observed.runtime_ready_proven {
        return false;
    }
    if observed.runtime_ready {
        return observed.reason_codes.is_empty();
    }
    !observed.reason_codes.is_empty()
        && observed.reason_codes.iter().all(|code| {
            matches!(
                code.as_str(),
                "WARP_LINE1_CONSUMER_EGRESS_FAILED" | "WARP_LINE2_CONSUMER_EGRESS_FAILED"
            )
        })
}

pub fn decode_native_observation(
    bytes: &[u8],
) -> Result<crate::FleetNativeObservation, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_OBSERVATION_BYTES {
        return Err("HOST_OBSERVATION_SIZE_INVALID");
    }
    let observed = crate::FleetNativeObservation::decode(bytes)
        .map_err(|_| "HOST_OBSERVATION_PROTO_INVALID")?;
    if observed.encode_to_vec() != bytes {
        return Err("HOST_OBSERVATION_NONCANONICAL");
    }
    validate_native_observation(&observed)?;
    Ok(observed)
}

/// One host-specific desired digest binds the protobuf machine/run-state/mode
/// and the exact protected Git spec bytes. A shared VM spec alone can never
/// act as desired identity for a Windows host or override STOPPED.
pub fn digest_host_desired(
    host: &crate::FleetHost,
    spec_bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if spec_bytes.is_empty() || spec_bytes.len() > 1_048_576 {
        return Err("HOST_DESIRED_SPEC_SIZE_INVALID");
    }
    let host_bytes = host.encode_to_vec();
    let mut payload = b"sing-box/host-desired/v1:".to_vec();
    payload.extend_from_slice(&(host_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&host_bytes);
    payload.extend_from_slice(&(spec_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(spec_bytes);
    Ok(ring::digest::digest(&ring::digest::SHA256, &payload)
        .as_ref()
        .to_vec())
}

/// ReleaseSet v7+ hashes the transported ApplyBundleRequest protobuf; the
/// VM release marker stores a different, logical domain-separated digest.
/// Derive the physical expected digest ONLY from the verified exact bundle.
pub fn native_vm_bundle_runtime_digest(
    release: &crate::ReleaseSet,
    vm_bundle_pb: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if !(7..=crate::RELEASE_SET_SCHEMA_VERSION).contains(&release.schema_version)
        || vm_bundle_pb.is_empty()
        || vm_bundle_pb.len() > 8 * 1024 * 1024
    {
        return Err("HOST_NATIVE_VM_BUNDLE_ARTIFACT_INVALID");
    }
    let published = &release
        .vm_runtime
        .as_ref()
        .ok_or("HOST_NATIVE_VM_RUNTIME_UNAVAILABLE")?
        .application_bundle_sha256;
    if !sha(published)
        || ring::digest::digest(&ring::digest::SHA256, vm_bundle_pb).as_ref()
            != published.as_slice()
    {
        return Err("HOST_NATIVE_VM_BUNDLE_TRANSPORT_MISMATCH");
    }
    let request = crate::ApplyBundleRequest::decode(vm_bundle_pb)
        .map_err(|_| "HOST_NATIVE_VM_BUNDLE_PROTO_INVALID")?;
    if request.encode_to_vec() != vm_bundle_pb
        || !request.prune_existing
        || !request.host_files.is_empty()
        || request.deployment_summary.is_some()
        || request.agent_env_file.is_some()
    {
        return Err("HOST_NATIVE_VM_BUNDLE_NONCANONICAL");
    }
    let logical = request
        .bundle_digest
        .as_deref()
        .ok_or("HOST_NATIVE_VM_BUNDLE_LOGICAL_DIGEST_MISSING")?;
    let computed = crate::canonical_apply_bundle_digest(&request)
        .map_err(|_| "HOST_NATIVE_VM_BUNDLE_LOGICAL_DIGEST_INVALID")?;
    if logical != computed || logical.len() != 64 {
        return Err("HOST_NATIVE_VM_BUNDLE_LOGICAL_DIGEST_MISMATCH");
    }
    let mut decoded = Vec::with_capacity(32);
    for pair in logical.as_bytes().chunks_exact(2) {
        let h = (pair[0] as char)
            .to_digit(16)
            .ok_or("HOST_NATIVE_VM_BUNDLE_HEX_INVALID")?;
        let l = (pair[1] as char)
            .to_digit(16)
            .ok_or("HOST_NATIVE_VM_BUNDLE_HEX_INVALID")?;
        decoded.push(((h << 4) | l) as u8);
    }
    if !sha(&decoded) {
        return Err("HOST_NATIVE_VM_BUNDLE_LOGICAL_DIGEST_INVALID");
    }
    Ok(decoded)
}

/// The single Worker public signer contract shared by root enrollment,
/// native execution and read-only first-use diagnosis. No caller-provided
/// public key may override protected Git desired.
pub fn verify_git_worker_signer_pin(host: &FleetHost, supplied: &[u8]) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || host.worker_authority_public_key.len() != 32
        || host.worker_authority_public_key.iter().all(|b| *b == 0)
    {
        return Err("HOST_GIT_WORKER_SIGNER_KEY_REQUIRED");
    }
    if supplied != host.worker_authority_public_key {
        return Err("HOST_WORKER_SIGNER_DIFFERS_FROM_PROTECTED_GIT");
    }
    Ok(())
}

/// One typed resource-scope prerequisite shared across the first-use
/// registration and the later signed native transaction.
fn verify_vm_git_resource_scope(host: &FleetHost) -> Result<(), &'static str> {
    if host.vm_containers.is_empty() {
        return Err("HOST_VM_GIT_RESOURCE_SCOPE_REQUIRED");
    }
    Ok(())
}

/// First-use does not have a receipt key yet. It is generated once inside
/// the protected native root and registered through the next Git ReleaseSet.
pub fn verify_vm_first_use_git_prerequisites(host: &FleetHost) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32 {
        return Err("HOST_VM_FIRST_USE_KIND_REQUIRED");
    }
    verify_git_worker_signer_pin(host, &host.worker_authority_public_key)?;
    verify_vm_git_resource_scope(host)?;
    if host.vm_provider_spec_path.is_empty() {
        return Err("HOST_VM_GIT_PROVIDER_SPEC_REQUIRED");
    }
    if !matches!(
        host.target.as_ref(),
        Some(t) if t.run_state == crate::FleetHostRunState::Running as i32
    ) {
        return Err("HOST_VM_GIT_RUNNING_TARGET_REQUIRED");
    }
    Ok(())
}

/// The existing Vultr substrate engine can bootstrap only the provider
/// spec already selected in the exact protected Git FleetHost.
pub fn verify_vm_first_use_provider_spec(
    host: &FleetHost,
    provider_spec_path: &str,
) -> Result<(), &'static str> {
    verify_vm_first_use_git_prerequisites(host)?;
    if provider_spec_path != host.vm_provider_spec_path {
        return Err("HOST_BOOTSTRAP_GIT_PROVIDER_SPEC_MISMATCH");
    }
    Ok(())
}

/// Preserve the established signed-admission reason order: Git signer, then
/// receipt registration, then application resource scope. The same primitive
/// checks also govern first-use, with no independent bootstrap policy.
pub fn verify_vm_signed_git_prerequisites(host: &FleetHost) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32 {
        return Ok(());
    }
    verify_git_worker_signer_pin(host, &host.worker_authority_public_key)?;
    if host.native_receipt_public_key.len() != 32
        || host.native_receipt_public_key.iter().all(|b| *b == 0)
    {
        return Err("HOST_VM_GIT_RECEIPT_REGISTRATION_REQUIRED");
    }
    verify_vm_git_resource_scope(host)
}

/// Exact artifact digests computed from the supplied Git registry, host
/// desired bytes, and immutable ReleaseSet. This is structural integrity,
/// NOT Git provenance: only an existing privileged owner may supply these
/// bytes after independently resolving the accepted canonical Git revision
/// and release. Runner-provided bytes do not become trustworthy here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundNativeHostArtifacts {
    pub registry_sha256: Vec<u8>,
    pub desired_sha256: Vec<u8>,
    pub release_set_sha256: Vec<u8>,
    pub runtime_release_sha256: Vec<u8>,
}

pub fn bind_native_host_artifacts(
    intent: &FleetHostIntent,
    registry_pb: &[u8],
    exact_spec_bytes: &[u8],
    release_set_pb: &[u8],
    vm_bundle_pb: Option<&[u8]>,
) -> Result<(HostRegistry, BoundNativeHostArtifacts), &'static str> {
    fn digest_bytes(bytes: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .to_vec()
    }
    if registry_pb.is_empty()
        || registry_pb.len() > 65536
        || release_set_pb.is_empty()
        || release_set_pb.len() > 65536
    {
        return Err("HOST_NATIVE_ARTIFACT_SIZE_INVALID");
    }
    let registry =
        crate::decode_host_registry(registry_pb).map_err(|_| "HOST_NATIVE_REGISTRY_INVALID")?;
    let host = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == intent.machine_id && h.kind == intent.kind)
        .ok_or("HOST_NATIVE_MACHINE_UNREGISTERED")?;
    let release = crate::release::v1::ReleaseSet::decode(release_set_pb)
        .map_err(|_| "HOST_NATIVE_RELEASE_PROTO_INVALID")?;
    if !(7..=crate::RELEASE_SET_SCHEMA_VERSION).contains(&release.schema_version)
        || release.source_revision.len() != 40
        || !release
            .source_revision
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
    {
        return Err("HOST_NATIVE_RELEASE_SCHEMA_INVALID");
    }
    if release.encode_to_vec() != release_set_pb {
        return Err("HOST_NATIVE_RELEASE_NONCANONICAL");
    }
    let runtime_release_sha256 = match FleetHostKind::try_from(intent.kind) {
        Ok(FleetHostKind::Windows) => {
            if vm_bundle_pb.is_some() {
                return Err("HOST_NATIVE_WINDOWS_VM_ARTIFACT_FORBIDDEN");
            }
            digest_bytes(release_set_pb)
        }
        Ok(FleetHostKind::Vm) => native_vm_bundle_runtime_digest(
            &release,
            vm_bundle_pb.ok_or("HOST_NATIVE_VM_BUNDLE_REQUIRED")?,
        )?,
        _ => return Err("HOST_NATIVE_OWNER_KIND_INVALID"),
    };
    if !sha(&runtime_release_sha256) {
        return Err("HOST_NATIVE_RUNTIME_RELEASE_INVALID");
    }
    let bound = BoundNativeHostArtifacts {
        registry_sha256: digest_bytes(registry_pb),
        desired_sha256: digest_host_desired(host, exact_spec_bytes)?,
        release_set_sha256: digest_bytes(release_set_pb),
        runtime_release_sha256,
    };
    validate_host_intent(
        intent,
        &registry,
        &bound.registry_sha256,
        &bound.desired_sha256,
        &bound.release_set_sha256,
    )?;
    Ok((registry, bound))
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn sha(value: &[u8]) -> bool {
    value.len() == 32 && value.iter().any(|b| *b != 0)
}

/// A scoped signature cannot select an arbitrary Docker or filesystem path.
/// Only registered VM gateway configuration children have native effectors.
pub fn validate_scoped_vm_resource_id(
    host: &crate::FleetHost,
    resource_id: &str,
) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32 {
        return Err("HOST_SCOPE_VM_OWNER_REQUIRED");
    }
    if resource_id.len() > 128
        || host
            .vm_containers
            .iter()
            .filter(|selector| {
                matches!(
                    selector.compose_service.as_str(),
                    "line1-gateway" | "line2-proxy"
                ) && format!(
                    "config/{}/{}",
                    selector.compose_project, selector.compose_service
                ) == resource_id
            })
            .count()
            != 1
    {
        return Err("HOST_SCOPE_RESOURCE_NOT_REGISTERED");
    }
    Ok(())
}

pub fn validate_host_intent(
    intent: &FleetHostIntent,
    registry: &HostRegistry,
    exact_registry_sha256: &[u8],
    exact_desired_sha256: &[u8],
    exact_release_set_sha256: &[u8],
) -> Result<(), &'static str> {
    // This executor still plans the WHOLE application. A forged resource ID
    // must never make a global START/STOP appear to be scoped to a container.
    // Per-resource execution needs its own native plan and physical readback.
    if intent.schema_version != 1
        || !token(&intent.machine_id)
        || intent.resource_id.is_empty()
        || !token(&intent.operation_id)
        || intent.requested_at_unix == 0
    {
        return Err("HOST_INTENT_IDENTITY_INVALID");
    }
    if !sha(exact_registry_sha256)
        || !sha(exact_desired_sha256)
        || !sha(exact_release_set_sha256)
        || intent.registry_sha256 != exact_registry_sha256
        || intent.desired_sha256 != exact_desired_sha256
        || intent.release_set_sha256 != exact_release_set_sha256
    {
        return Err("HOST_INTENT_DIGEST_MISMATCH");
    }
    let host = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == intent.machine_id)
        .ok_or("HOST_INTENT_UNKNOWN_MACHINE")?;
    if host.kind != intent.kind
        || !matches!(
            (FleetHostKind::try_from(host.kind), host.owner.as_ref()),
            (
                Ok(FleetHostKind::Windows),
                Some(managed_host::Owner::WindowsRunnerName(_))
            ) | (
                Ok(FleetHostKind::Vm),
                Some(managed_host::Owner::VmMachineId(_))
            )
        )
    {
        return Err("HOST_INTENT_OWNER_MISMATCH");
    }
    let action =
        FleetHostAction::try_from(intent.action).map_err(|_| "HOST_INTENT_ACTION_INVALID")?;
    if intent.resource_id != "sing-box" {
        if action != FleetHostAction::Apply {
            return Err("HOST_SCOPE_ACTION_NOT_APPLY");
        }
        validate_scoped_vm_resource_id(host, &intent.resource_id)?;
    }
    let mode =
        FleetHostMode::try_from(intent.requested_mode).map_err(|_| "HOST_INTENT_MODE_INVALID")?;
    if action == FleetHostAction::Unspecified
        || (action == FleetHostAction::SetMode
            && (host.kind != FleetHostKind::Windows as i32 || mode == FleetHostMode::Unspecified))
        || (action != FleetHostAction::SetMode && mode != FleetHostMode::Unspecified)
    {
        return Err("HOST_INTENT_ACTION_MODE_MISMATCH");
    }
    Ok(())
}

/// Decide one native operation against a single Git-owned target. There
/// is never an implicit START from an installed service, old runtime profile,
/// production VM spec or GitHub runner text.
pub fn validate_intent_against_target(
    intent: &FleetHostIntent,
    registry: &HostRegistry,
) -> Result<(), &'static str> {
    use crate::FleetHostRunState;
    let host = registry
        .hosts
        .iter()
        .find(|host| host.machine_id == intent.machine_id)
        .ok_or("HOST_INTENT_UNKNOWN_MACHINE")?;
    let target = host
        .target
        .as_ref()
        .ok_or("HOST_TARGET_UNSET_OBSERVE_ONLY")?;
    let action =
        FleetHostAction::try_from(intent.action).map_err(|_| "HOST_INTENT_ACTION_INVALID")?;
    let state = FleetHostRunState::try_from(target.run_state)
        .map_err(|_| "HOST_TARGET_RUN_STATE_INVALID")?;
    if state == FleetHostRunState::Unspecified {
        return Err("HOST_TARGET_RUN_STATE_REQUIRED");
    }
    let mode =
        FleetHostMode::try_from(target.windows_mode).map_err(|_| "HOST_TARGET_MODE_INVALID")?;
    if (host.kind == FleetHostKind::Windows as i32 && mode == FleetHostMode::Unspecified)
        || (host.kind == FleetHostKind::Vm as i32 && mode != FleetHostMode::Unspecified)
    {
        return Err("HOST_TARGET_MODE_KIND_MISMATCH");
    }
    if (action == FleetHostAction::Start && state != FleetHostRunState::Running)
        || (action == FleetHostAction::Stop && state != FleetHostRunState::Stopped)
        || (action == FleetHostAction::SetMode && intent.requested_mode != target.windows_mode)
    {
        return Err("HOST_ACTION_CONFLICTS_WITH_DESIRED");
    }
    // TUN is never inferred or admitted from an APPLY/RECOVER alone. Exact
    // typed SET_MODE and a separate physical gate are both required.
    if mode == FleetHostMode::ManagedTun
        && action != FleetHostAction::SetMode
        && matches!(
            action,
            FleetHostAction::Start
                | FleetHostAction::Apply
                | FleetHostAction::Install
                | FleetHostAction::Reinstall
                | FleetHostAction::Recover
                | FleetHostAction::Configure
        )
    {
        return Err("HOST_TUN_EXPLICIT_MODE_GATE_REQUIRED");
    }
    Ok(())
}

pub fn decode_host_intent(bytes: &[u8]) -> Result<FleetHostIntent, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_HOST_INTENT_BYTES {
        return Err("HOST_INTENT_SIZE_INVALID");
    }
    let intent = FleetHostIntent::decode(bytes).map_err(|_| "HOST_INTENT_PROTO_INVALID")?;
    if intent.encode_to_vec() != bytes {
        return Err("HOST_INTENT_NONCANONICAL");
    }
    Ok(intent)
}

pub const MAX_HOST_AUTHORIZATION_BYTES: usize = 2048;

/// A detached, exact protobuf authorization. Parsing is not a privilege:
/// the pinned native owner MUST call verify_host_authorization and reserve its
/// no-replay journal before executing any operation.
pub fn decode_host_authorization(bytes: &[u8]) -> Result<FleetHostAuthorization, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_HOST_AUTHORIZATION_BYTES {
        return Err("HOST_AUTHORIZATION_SIZE_INVALID");
    }
    let value =
        FleetHostAuthorization::decode(bytes).map_err(|_| "HOST_AUTHORIZATION_PROTO_INVALID")?;
    if value.encode_to_vec() != bytes {
        return Err("HOST_AUTHORIZATION_NONCANONICAL");
    }
    if value.schema_version != 1
        || !token(&value.key_id)
        || !token(&value.operation_id)
        || value.issued_at_unix == 0
        || value.expires_at_unix <= value.issued_at_unix
        || value.expires_at_unix - value.issued_at_unix > 300
        || value.ed25519_signature.len() != 64
    {
        return Err("HOST_AUTHORIZATION_FIELDS_INVALID");
    }
    Ok(value)
}

pub fn decode_host_result(bytes: &[u8]) -> Result<FleetHostResult, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_HOST_RESULT_BYTES {
        return Err("HOST_RESULT_SIZE_INVALID");
    }
    let result = FleetHostResult::decode(bytes).map_err(|_| "HOST_RESULT_PROTO_INVALID")?;
    if result.encode_to_vec() != bytes {
        return Err("HOST_RESULT_NONCANONICAL");
    }
    Ok(result)
}

/// Exactly one typed reason, with two derived diagnostic projections.
/// Neither the enum nor either projection grants physical mutation authority.
pub fn set_host_result_reason(result: &mut FleetHostResult, reason: crate::FleetHostResultReason) {
    let (error, action) = host_result_reason_projection(reason);
    result.reason = reason as i32;
    result.error_class = error.to_owned();
    result.next_action = action.to_owned();
}

fn host_result_reason_projection(
    reason: crate::FleetHostResultReason,
) -> (&'static str, &'static str) {
    use crate::FleetHostResultReason as Reason;
    match reason {
        Reason::Unspecified => ("", "UNSPECIFIED"),
        Reason::PreparedNeedsOwnerTrust => (
            "NATIVE_INSTALL_AUTHORITY_NOT_ACCEPTED",
            "NEED_TRUSTED_OWNER_BOOTSTRAP",
        ),
        Reason::AuthorizedAwaitNativeReadback => ("", "NATIVE_OWNER_READBACK_REQUIRED"),
        Reason::NoFurtherAction => ("", "NONE"),
        Reason::RecoveredNativeRunning => ("", "RECOVERED_NATIVE_RUNNING"),
        Reason::RecoveredNativeStopped => ("", "RECOVERED_NATIVE_STOPPED"),
        Reason::StoppedReleaseDriftRequiresInstallTarget => {
            ("", "STOPPED_RELEASE_DRIFT_REQUIRES_INSTALL_TARGET")
        }
        Reason::HistoricalPartialRequiresFreshApply => {
            ("", "HISTORICAL_PARTIAL_REQUIRES_FRESH_APPLY")
        }
    }
}

pub fn validate_host_result_reason(result: &FleetHostResult) -> Result<(), &'static str> {
    use crate::{FleetHostResultReason as Reason, FleetHostResultState as State};
    let reason = Reason::try_from(result.reason).map_err(|_| "HOST_RESULT_REASON_UNKNOWN")?;
    let state = State::try_from(result.state).map_err(|_| "HOST_RESULT_STATE_INVALID")?;
    let allowed = match reason {
        Reason::Unspecified => false,
        Reason::PreparedNeedsOwnerTrust => state == State::Prepared,
        Reason::AuthorizedAwaitNativeReadback => state == State::Authorized,
        Reason::HistoricalPartialRequiresFreshApply => {
            matches!(state, State::UnknownNoReplay | State::Observed)
        }
        _ => matches!(state, State::Observed | State::Verified),
    };
    let (error, action) = host_result_reason_projection(reason);
    if !allowed || result.error_class != error || result.next_action != action {
        return Err("HOST_RESULT_REASON_STATE_OR_PROJECTION_MISMATCH");
    }
    Ok(())
}

/// Only a structural comparison of a runner-copied native result. This
/// NEVER authenticates the origin or upgrades a remote status to VERIFIED.
/// The published exact intent and immutable digest must match byte-for-byte.
pub fn validate_unattested_native_result(
    result: &FleetHostResult,
    intent: &FleetHostIntent,
) -> Result<(), &'static str> {
    if result.schema_version != 1
        || result.machine_id != intent.machine_id
        || result.resource_id != intent.resource_id
        || result.operation_id != intent.operation_id
        || result.action != intent.action
        || result.release_set_sha256 != intent.release_set_sha256
        || result.desired_sha256 != intent.desired_sha256
    {
        return Err("HOST_NATIVE_RESULT_CORRELATION_MISMATCH");
    }
    validate_host_result_reason(result).map_err(|_| "HOST_NATIVE_RESULT_STRUCTURE_INVALID")?;
    let state = FleetHostResultState::try_from(result.state)
        .map_err(|_| "HOST_NATIVE_RESULT_STATE_INVALID")?;
    if !matches!(
        state,
        FleetHostResultState::Observed | FleetHostResultState::Verified
    ) || result.observed_at_unix == 0
        || result.physical_readback != (state == FleetHostResultState::Verified)
        || !result.error_class.is_empty()
        || result.next_action.len() > 128
        || !result
            .next_action
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err("HOST_NATIVE_RESULT_STRUCTURE_INVALID");
    }
    Ok(())
}

pub fn validate_host_result(
    result: &FleetHostResult,
    intent: &FleetHostIntent,
) -> Result<(), &'static str> {
    if result.schema_version != 1
        || result.machine_id != intent.machine_id
        || result.resource_id != intent.resource_id
        || result.operation_id != intent.operation_id
        || result.action != intent.action
        || result.release_set_sha256 != intent.release_set_sha256
        || result.desired_sha256 != intent.desired_sha256
    {
        return Err("HOST_RESULT_CORRELATION_MISMATCH");
    }
    let state =
        FleetHostResultState::try_from(result.state).map_err(|_| "HOST_RESULT_STATE_INVALID")?;
    // Public protobuf data is NOT an authenticated physical result.
    // A privileged native owner can create its own journal record, but
    // external observers may never promote caller-supplied AUTHORIZED/VERIFIED
    // just by flipping a boolean or timestamp in FleetHostResult.
    if matches!(
        state,
        FleetHostResultState::Authorized | FleetHostResultState::Verified
    ) {
        return Err("HOST_NATIVE_RECEIPT_ATTESTATION_REQUIRED");
    }
    validate_host_result_reason(result).map_err(|_| "HOST_RESULT_EVIDENCE_INVALID")?;
    if state == FleetHostResultState::Unspecified
        || (state == FleetHostResultState::Verified
            && (!result.physical_readback
                || result.observed_at_unix == 0
                || !result.error_class.is_empty()))
        || (state != FleetHostResultState::Verified && result.physical_readback)
        || result.error_class.len() > 128
        || result.next_action.len() > 128
        || !result
            .error_class
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        || !result
            .next_action
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err("HOST_RESULT_EVIDENCE_INVALID");
    }
    Ok(())
}

pub fn prepared_host_result(intent: &FleetHostIntent) -> FleetHostResult {
    let mut result = FleetHostResult {
        schema_version: 1,
        machine_id: intent.machine_id.clone(),
        resource_id: intent.resource_id.clone(),
        operation_id: intent.operation_id.clone(),
        action: intent.action,
        state: FleetHostResultState::Prepared as i32,
        release_set_sha256: intent.release_set_sha256.clone(),
        desired_sha256: intent.desired_sha256.clone(),
        observed_at_unix: 0,
        error_class: String::new(),
        next_action: String::new(),
        physical_readback: false,
        reason: 0,
    };
    set_host_result_reason(
        &mut result,
        crate::FleetHostResultReason::PreparedNeedsOwnerTrust,
    );
    result
}

/// The existing Cloudflare Worker is the sole issuer of this detached
/// authorization; the native owner pins the public key in its accepted
/// immutable release. Neither the GitHub runner nor the caller can mint it.
///
/// This function does not inspect or modify the host. A privileged executor
/// MUST additionally enforce a durable operation-id no-replay ledger and
/// exact local machine/owner identity before performing even one mutation.
pub fn verify_host_authorization(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    trusted_ed25519_public_key: &[u8],
    now_unix: u64,
) -> Result<(), &'static str> {
    if authorization.schema_version != 1
        || !token(&authorization.key_id)
        || authorization.operation_id != intent.operation_id
        || trusted_ed25519_public_key.len() != 32
        || authorization.ed25519_signature.len() != 64
    {
        return Err("HOST_AUTHORIZATION_IDENTITY_INVALID");
    }
    // Short lived, exact operation. No open-ended capabilities or
    // time-of-check/time-of-use reuse across installs, mode changes or hosts.
    if authorization.expires_at_unix <= authorization.issued_at_unix
        || authorization.expires_at_unix - authorization.issued_at_unix > 300
        || now_unix.saturating_add(60) < authorization.issued_at_unix
        || now_unix > authorization.expires_at_unix.saturating_add(60)
    {
        return Err("HOST_AUTHORIZATION_EXPIRED_OR_FUTURE");
    }
    let signed = host_authorization_payload(intent, authorization);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, trusted_ed25519_public_key)
        .verify(&signed, &authorization.ed25519_signature)
        .map_err(|_| "HOST_AUTHORIZATION_SIGNATURE_INVALID")
}

/// Identical domain-separated byte sequence must be signed by the existing
/// Worker secret authority. No untrusted JSON canonicalization or free-form
/// command text participates in authentication.
pub fn host_authorization_payload(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
) -> Vec<u8> {
    let intent_bytes = intent.encode_to_vec();
    let mut bytes = b"sing-box/native-host-authorization/v1:".to_vec();
    bytes.extend_from_slice(&(intent_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&intent_bytes);
    bytes.extend_from_slice(&(authorization.key_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(authorization.key_id.as_bytes());
    bytes.extend_from_slice(&(authorization.operation_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(authorization.operation_id.as_bytes());
    bytes.extend_from_slice(&authorization.issued_at_unix.to_be_bytes());
    bytes.extend_from_slice(&authorization.expires_at_unix.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    #[test]
    fn runner_copied_verified_result_is_only_structurally_correlated() {
        let intent = FleetHostIntent {
            schema_version: 1,
            machine_id: "vm-1".to_owned(),
            kind: FleetHostKind::Vm as i32,
            resource_id: "sing-box".to_owned(),
            operation_id: "issue1-comment-123".to_owned(),
            action: FleetHostAction::Apply as i32,
            release_set_sha256: vec![1; 32],
            desired_sha256: vec![2; 32],
            ..Default::default()
        };
        let mut result = FleetHostResult {
            schema_version: 1,
            machine_id: intent.machine_id.clone(),
            resource_id: intent.resource_id.clone(),
            operation_id: intent.operation_id.clone(),
            action: intent.action,
            state: FleetHostResultState::Verified as i32,
            release_set_sha256: intent.release_set_sha256.clone(),
            desired_sha256: intent.desired_sha256.clone(),
            observed_at_unix: 1500,
            error_class: String::new(),
            next_action: "NONE".to_owned(),
            physical_readback: true,
            reason: crate::FleetHostResultReason::NoFurtherAction as i32,
        };
        assert!(validate_unattested_native_result(&result, &intent).is_ok());
        let mut forged = result.clone();
        forged.next_action = "SHELL_COMMAND".into();
        assert_eq!(
            validate_unattested_native_result(&forged, &intent),
            Err("HOST_NATIVE_RESULT_STRUCTURE_INVALID")
        );
        forged = result.clone();
        forged.reason = 999;
        assert_eq!(
            validate_unattested_native_result(&forged, &intent),
            Err("HOST_NATIVE_RESULT_STRUCTURE_INVALID")
        );
        forged = result.clone();
        forged.reason = crate::FleetHostResultReason::AuthorizedAwaitNativeReadback as i32;
        assert_eq!(
            validate_unattested_native_result(&forged, &intent),
            Err("HOST_NATIVE_RESULT_STRUCTURE_INVALID")
        );
        assert_eq!(
            validate_host_result(&result, &intent),
            Err("HOST_NATIVE_RECEIPT_ATTESTATION_REQUIRED")
        );
        result.desired_sha256[0] ^= 1;
        assert_eq!(
            validate_unattested_native_result(&result, &intent),
            Err("HOST_NATIVE_RESULT_CORRELATION_MISMATCH")
        );
        result.desired_sha256 = intent.desired_sha256.clone();
        result.physical_readback = false;
        assert_eq!(
            validate_unattested_native_result(&result, &intent),
            Err("HOST_NATIVE_RESULT_STRUCTURE_INVALID")
        );
    }

    use super::*;
    use crate::{FleetHost, HostRegistry, encode_host_registry};

    #[test]
    fn one_git_vm_first_use_gate_preserves_receipt_registration_boundary() {
        let mut host = FleetHost {
            kind: crate::FleetHostKind::Vm as i32,
            ..Default::default()
        };
        assert_eq!(
            verify_vm_first_use_git_prerequisites(&host),
            Err("HOST_GIT_WORKER_SIGNER_KEY_REQUIRED")
        );
        host.worker_authority_public_key = vec![8; 32];
        assert_eq!(
            verify_vm_first_use_git_prerequisites(&host),
            Err("HOST_VM_GIT_RESOURCE_SCOPE_REQUIRED")
        );
        host.vm_containers.push(crate::FleetVmContainer {
            container_name: "vultr-line1-gateway".into(),
            compose_project: "vultr-edge".into(),
            compose_service: "line1-gateway".into(),
        });
        assert_eq!(
            verify_vm_first_use_git_prerequisites(&host),
            Err("HOST_VM_GIT_PROVIDER_SPEC_REQUIRED")
        );
        host.vm_provider_spec_path = "infra/vultr/acceptance.json".into();
        assert_eq!(
            verify_vm_first_use_git_prerequisites(&host),
            Err("HOST_VM_GIT_RUNNING_TARGET_REQUIRED")
        );
        host.target = Some(crate::FleetHostTarget {
            run_state: crate::FleetHostRunState::Running as i32,
            windows_mode: crate::FleetHostMode::Unspecified as i32,
        });
        assert_eq!(verify_vm_first_use_git_prerequisites(&host), Ok(()));
        assert_eq!(
            verify_vm_first_use_provider_spec(&host, "infra/vultr/foreign.json"),
            Err("HOST_BOOTSTRAP_GIT_PROVIDER_SPEC_MISMATCH")
        );
        assert_eq!(
            verify_vm_first_use_provider_spec(&host, "infra/vultr/acceptance.json"),
            Ok(())
        );
        assert_eq!(
            verify_vm_signed_git_prerequisites(&host),
            Err("HOST_VM_GIT_RECEIPT_REGISTRATION_REQUIRED")
        );
        host.native_receipt_public_key = vec![9; 32];
        assert_eq!(verify_vm_signed_git_prerequisites(&host), Ok(()));
        host.kind = crate::FleetHostKind::Windows as i32;
        assert_eq!(
            verify_vm_first_use_git_prerequisites(&host),
            Err("HOST_VM_FIRST_USE_KIND_REQUIRED")
        );
        assert_eq!(verify_vm_signed_git_prerequisites(&host), Ok(()));
    }

    #[test]
    fn exact_native_artifacts_bind_all_digests_or_fail_closed() {
        use crate::release::v1::{ReleaseSet, VmRuntime};
        use crate::{FleetHostKind, HostRegistry, ManagedHost, ManagedHostKind, managed_host};
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![ManagedHost {
                machine_id: "vm-one".to_owned(),
                kind: ManagedHostKind::Vm as i32,
                owner: Some(managed_host::Owner::VmMachineId("vm-one".to_owned())),
                windows_runner_label: String::new(),
                vm_containers: Vec::new(),
                desired_spec_path: "infra/hosts/specs/vm-one.textproto".to_owned(),
                target: None,
                native_receipt_public_key: Vec::new(),
                vm_first_use_credential: None,
                worker_authority_public_key: Vec::new(),
                vm_provider_spec_path: String::new(),
            }],
        };
        let registry_pb = crate::encode_host_registry(&registry).unwrap();
        let spec = b"typed exact desired";
        let mut bundle_request = crate::ApplyBundleRequest {
            bundle_id: Some("vm-exact".to_owned()),
            prune_existing: true,
            ..Default::default()
        };
        bundle_request.bundle_digest =
            Some(crate::canonical_apply_bundle_digest(&bundle_request).unwrap());
        let bundle_pb = bundle_request.encode_to_vec();
        let transport_sha256 = ring::digest::digest(&ring::digest::SHA256, &bundle_pb)
            .as_ref()
            .to_vec();
        let release = ReleaseSet {
            schema_version: 7,
            source_revision: "a".repeat(40),
            vm_runtime: Some(VmRuntime {
                application_bundle_sha256: transport_sha256,
                ..Default::default()
            }),
            ..Default::default()
        };
        let release_pb = release.encode_to_vec();
        let mut intent = FleetHostIntent {
            schema_version: 1,
            machine_id: "vm-one".to_owned(),
            kind: FleetHostKind::Vm as i32,
            resource_id: "sing-box".to_owned(),
            operation_id: "issue1-comment-123".to_owned(),
            action: FleetHostAction::Apply as i32,
            registry_sha256: ring::digest::digest(&ring::digest::SHA256, &registry_pb)
                .as_ref()
                .to_vec(),
            desired_sha256: digest_host_desired(&registry.hosts[0], spec).unwrap(),
            release_set_sha256: ring::digest::digest(&ring::digest::SHA256, &release_pb)
                .as_ref()
                .to_vec(),
            requested_mode: FleetHostMode::Unspecified as i32,
            requested_at_unix: 1000,
        };
        let (_, bound) =
            bind_native_host_artifacts(&intent, &registry_pb, spec, &release_pb, Some(&bundle_pb))
                .unwrap();
        assert_eq!(
            bound.runtime_release_sha256,
            native_vm_bundle_runtime_digest(&release, &bundle_pb).unwrap()
        );
        // A v8 release changes Worker provenance metadata, NOT the VM bundle
        // transport or logical digest contract. Enforce the same byte-level
        // binding on both accepted schemas, and fail closed for unknown ones.
        let mut v8 = release.clone();
        v8.schema_version = crate::RELEASE_SET_SCHEMA_VERSION;
        assert_eq!(
            native_vm_bundle_runtime_digest(&v8, &bundle_pb).unwrap(),
            bound.runtime_release_sha256
        );
        let mut v8_intent = intent.clone();
        let v8_bytes = v8.encode_to_vec();
        v8_intent.release_set_sha256 = ring::digest::digest(&ring::digest::SHA256, &v8_bytes)
            .as_ref()
            .to_vec();
        let (_, v8_bound) =
            bind_native_host_artifacts(&v8_intent, &registry_pb, spec, &v8_bytes, Some(&bundle_pb))
                .unwrap();
        assert_eq!(
            v8_bound.runtime_release_sha256,
            bound.runtime_release_sha256
        );
        assert_eq!(
            bind_native_host_artifacts(&v8_intent, &registry_pb, spec, &v8_bytes, Some(b"wrong"))
                .unwrap_err(),
            "HOST_NATIVE_VM_BUNDLE_TRANSPORT_MISMATCH"
        );
        let mut future = v8.clone();
        future.schema_version = crate::RELEASE_SET_SCHEMA_VERSION + 1;
        assert_eq!(
            native_vm_bundle_runtime_digest(&future, &bundle_pb),
            Err("HOST_NATIVE_VM_BUNDLE_ARTIFACT_INVALID")
        );
        assert_eq!(
            bind_native_host_artifacts(
                &v8_intent,
                &registry_pb,
                spec,
                &future.encode_to_vec(),
                Some(&bundle_pb),
            )
            .unwrap_err(),
            "HOST_NATIVE_RELEASE_SCHEMA_INVALID"
        );
        assert_ne!(
            bound.runtime_release_sha256,
            release
                .vm_runtime
                .as_ref()
                .unwrap()
                .application_bundle_sha256
        );
        assert_eq!(
            bind_native_host_artifacts(&intent, &registry_pb, spec, &release_pb, None).unwrap_err(),
            "HOST_NATIVE_VM_BUNDLE_REQUIRED"
        );
        assert_eq!(
            bind_native_host_artifacts(&intent, &registry_pb, spec, &release_pb, Some(b"wrong"))
                .unwrap_err(),
            "HOST_NATIVE_VM_BUNDLE_TRANSPORT_MISMATCH"
        );
        assert_eq!(
            bind_native_host_artifacts(
                &intent,
                &registry_pb,
                b"tampered",
                &release_pb,
                Some(&bundle_pb)
            )
            .unwrap_err(),
            "HOST_INTENT_DIGEST_MISMATCH"
        );
        let mut wrong_release = release.clone();
        wrong_release.source_revision = "b".repeat(40);
        assert_eq!(
            bind_native_host_artifacts(
                &intent,
                &registry_pb,
                spec,
                &wrong_release.encode_to_vec(),
                Some(&bundle_pb)
            )
            .unwrap_err(),
            "HOST_INTENT_DIGEST_MISMATCH"
        );
        let mut missing_bundle = release;
        missing_bundle
            .vm_runtime
            .as_mut()
            .unwrap()
            .application_bundle_sha256
            .clear();
        intent.release_set_sha256 =
            ring::digest::digest(&ring::digest::SHA256, &missing_bundle.encode_to_vec())
                .as_ref()
                .to_vec();
        assert_eq!(
            bind_native_host_artifacts(
                &intent,
                &registry_pb,
                spec,
                &missing_bundle.encode_to_vec(),
                Some(&bundle_pb),
            )
            .unwrap_err(),
            "HOST_NATIVE_VM_BUNDLE_TRANSPORT_MISMATCH"
        );
    }

    fn fixture() -> (HostRegistry, FleetHostIntent, Vec<u8>, Vec<u8>, Vec<u8>) {
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![FleetHost {
                machine_id: "windows-1".to_owned(),
                kind: FleetHostKind::Windows as i32,
                owner: Some(managed_host::Owner::WindowsRunnerName("WIN-1".to_owned())),
                windows_runner_label: "windows-1".to_owned(),
                vm_containers: Vec::new(),
                desired_spec_path: "infra/production/production.textproto".to_owned(),
                target: None,
                native_receipt_public_key: Vec::new(),
                vm_first_use_credential: None,
                worker_authority_public_key: Vec::new(),
                vm_provider_spec_path: String::new(),
            }],
        };
        let bytes = encode_host_registry(&registry).unwrap();
        let registry_sha = ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .to_vec();
        let desired = vec![11u8; 32];
        let release = vec![22u8; 32];
        let intent = FleetHostIntent {
            schema_version: 1,
            machine_id: "windows-1".to_owned(),
            kind: FleetHostKind::Windows as i32,
            resource_id: "sing-box".to_owned(),
            operation_id: "gh-comment-123".to_owned(),
            action: FleetHostAction::Apply as i32,
            registry_sha256: registry_sha.clone(),
            desired_sha256: desired.clone(),
            release_set_sha256: release.clone(),
            requested_mode: FleetHostMode::Unspecified as i32,
            requested_at_unix: 1,
        };
        (registry, intent, registry_sha, desired, release)
    }

    #[test]
    fn native_readback_is_bounded_typed_and_not_a_mutation_receipt() {
        use crate::{FleetNativeOwnerState, FleetNativeReleaseProof};
        let observed = build_native_observation(
            FleetHostKind::Vm,
            FleetNativeOwnerState::Running,
            FleetNativeReleaseProof::ApplicationBundle,
            Some(&"a".repeat(64)),
            Some(false),
            3000,
            &["VM_RUNTIME_NOT_READY"],
        )
        .unwrap();
        let bytes = observed.encode_to_vec();
        assert_eq!(decode_native_observation(&bytes).unwrap(), observed);
        assert_eq!(observed.observed_release_sha256, vec![0xaa; 32]);
        assert!(!observed.runtime_ready);
        assert!(observed.runtime_ready_proven);
        assert_eq!(
            build_native_observation(
                FleetHostKind::Windows,
                FleetNativeOwnerState::Stopped,
                FleetNativeReleaseProof::ApplicationBundle,
                Some(&"b".repeat(64)),
                None,
                3000,
                &[],
            )
            .unwrap_err(),
            "HOST_OBSERVATION_PROOF_KIND_MISMATCH"
        );
        assert_eq!(
            build_native_observation(
                FleetHostKind::Vm,
                FleetNativeOwnerState::Unproven,
                FleetNativeReleaseProof::ApplicationBundle,
                None,
                None,
                3000,
                &[],
            )
            .unwrap_err(),
            "HOST_OBSERVATION_RELEASE_PROOF_INCOMPLETE"
        );
        let mut forged = observed.clone();
        forged.runtime_ready_proven = false;
        forged.runtime_ready = true;
        assert!(validate_native_observation(&forged).is_err());
        forged = observed;
        forged.reason_codes.push("user-supplied-json".to_owned());
        assert!(validate_native_observation(&forged).is_err());
        let mut noncanonical = bytes;
        noncanonical.extend_from_slice(&[8, 1]);
        assert!(decode_native_observation(&noncanonical).is_err());
    }

    #[test]
    fn desired_digest_changes_for_machine_mode_and_spec() {
        use crate::{FleetHostRunState, FleetHostTarget};
        let (registry, _, _, _, _) = fixture();
        let original = digest_host_desired(&registry.hosts[0], b"spec-v1").unwrap();
        let mut changed = registry.hosts[0].clone();
        changed.target = Some(FleetHostTarget {
            run_state: FleetHostRunState::Stopped as i32,
            windows_mode: FleetHostMode::ProxyOnly as i32,
        });
        assert_ne!(original, digest_host_desired(&changed, b"spec-v1").unwrap());
        assert_ne!(
            original,
            digest_host_desired(&registry.hosts[0], b"spec-v2").unwrap()
        );
        changed.machine_id = "another-windows".to_owned();
        assert_ne!(
            digest_host_desired(&registry.hosts[0], b"spec-v1").unwrap(),
            digest_host_desired(&changed, b"spec-v1").unwrap()
        );
    }

    #[test]
    fn detached_worker_auth_is_canonical_bounded_and_cannot_grant_privilege() {
        let mut a = FleetHostAuthorization {
            schema_version: 1,
            key_id: "vm-worker-key-v1".into(),
            operation_id: "issue1-comment-123".into(),
            issued_at_unix: 1000,
            expires_at_unix: 1120,
            ed25519_signature: vec![42; 64],
        };
        let bytes = a.encode_to_vec();
        assert_eq!(decode_host_authorization(&bytes).unwrap(), a);
        let mut noncanonical = bytes;
        noncanonical.extend_from_slice(&[8, 1]);
        assert_eq!(
            decode_host_authorization(&noncanonical).unwrap_err(),
            "HOST_AUTHORIZATION_NONCANONICAL"
        );
        a.ed25519_signature.pop();
        assert_eq!(
            decode_host_authorization(&a.encode_to_vec()).unwrap_err(),
            "HOST_AUTHORIZATION_FIELDS_INVALID"
        );
        a.ed25519_signature.push(42);
        a.expires_at_unix = 2000;
        assert!(decode_host_authorization(&a.encode_to_vec()).is_err());
    }

    #[test]
    fn exact_scoped_intent_and_prepared_receipt() {
        let (registry, intent, inv, desired, release) = fixture();
        validate_host_intent(&intent, &registry, &inv, &desired, &release).unwrap();
        let encoded = intent.encode_to_vec();
        assert_eq!(decode_host_intent(&encoded).unwrap(), intent);
        let receipt = prepared_host_result(&intent);
        validate_host_result(&receipt, &intent).unwrap();
        assert_eq!(
            decode_host_result(&receipt.encode_to_vec()).unwrap(),
            receipt
        );
    }

    #[test]
    fn reject_wrong_machine_mode_digest_and_unknown_action() {
        let (registry, intent, inv, desired, release) = fixture();
        let check = |candidate: &FleetHostIntent| {
            validate_host_intent(candidate, &registry, &inv, &desired, &release).is_err()
        };
        let mut invalid = intent.clone();
        invalid.machine_id = "windows-2".to_owned();
        assert!(check(&invalid));
        invalid = intent.clone();
        invalid.kind = FleetHostKind::Vm as i32;
        assert!(check(&invalid));
        invalid = intent.clone();
        invalid.resource_id = "container.vultr-line2-proxy".to_owned();
        // A nominal container ID cannot invoke the host-wide effector.
        assert!(check(&invalid));
        invalid = intent.clone();
        invalid.release_set_sha256[0] ^= 1;
        assert!(check(&invalid));
        invalid = intent.clone();
        invalid.action = 91234;
        assert!(check(&invalid));
        invalid = intent.clone();
        invalid.requested_mode = FleetHostMode::ManagedTun as i32;
        assert!(check(&invalid));
        invalid.action = FleetHostAction::SetMode as i32;
        assert!(!check(&invalid));
        invalid = intent.clone();
        invalid.operation_id = "../forged".to_owned();
        assert!(check(&invalid));
    }

    #[test]
    fn only_registered_vm_config_can_be_signed() {
        let (mut registry, mut intent, reg, desired, release) = fixture();
        registry.hosts[0].kind = FleetHostKind::Vm as i32;
        registry.hosts[0].owner = Some(crate::managed_host::Owner::VmMachineId(
            intent.machine_id.clone(),
        ));
        registry.hosts[0].vm_containers = vec![crate::FleetVmContainer {
            container_name: "vultr-line2-proxy".into(),
            compose_project: "vultr-edge".into(),
            compose_service: "line2-proxy".into(),
        }];
        intent.kind = FleetHostKind::Vm as i32;
        intent.resource_id = "config/vultr-edge/line2-proxy".into();
        assert!(validate_host_intent(&intent, &registry, &reg, &desired, &release).is_ok());
        for scope in [
            "config/vultr-edge/foreign",
            "container/vultr-edge/line2-proxy",
            "config/vultr-edge/../line2-proxy",
            "host/vm",
            "config/foreign/line2-proxy",
        ] {
            intent.resource_id = scope.into();
            assert!(validate_host_intent(&intent, &registry, &reg, &desired, &release).is_err());
        }
        intent.resource_id = "config/vultr-edge/line2-proxy".into();
        intent.action = FleetHostAction::Recover as i32;
        assert_eq!(
            validate_host_intent(&intent, &registry, &reg, &desired, &release),
            Err("HOST_SCOPE_ACTION_NOT_APPLY")
        );
    }

    #[test]
    fn never_start_stopped_windows_or_implicit_vm() {
        use crate::{FleetHostRunState, FleetHostTarget};
        let (mut registry, mut intent, _, _, _) = fixture();
        assert_eq!(
            validate_intent_against_target(&intent, &registry).unwrap_err(),
            "HOST_TARGET_UNSET_OBSERVE_ONLY"
        );
        registry.hosts[0].target = Some(FleetHostTarget {
            run_state: FleetHostRunState::Stopped as i32,
            windows_mode: FleetHostMode::ProxyOnly as i32,
        });
        intent.action = FleetHostAction::Start as i32;
        assert_eq!(
            validate_intent_against_target(&intent, &registry).unwrap_err(),
            "HOST_ACTION_CONFLICTS_WITH_DESIRED"
        );
        intent.action = FleetHostAction::Stop as i32;
        validate_intent_against_target(&intent, &registry).unwrap();
        intent.action = FleetHostAction::SetMode as i32;
        intent.requested_mode = FleetHostMode::ManagedTun as i32;
        assert_eq!(
            validate_intent_against_target(&intent, &registry).unwrap_err(),
            "HOST_ACTION_CONFLICTS_WITH_DESIRED"
        );
    }

    #[test]
    fn prohibit_unproven_success_or_mismatched_result() {
        let (_, intent, _, _, _) = fixture();
        let mut result = prepared_host_result(&intent);
        result.state = FleetHostResultState::Verified as i32;
        assert!(validate_host_result(&result, &intent).is_err());
        result.physical_readback = true;
        result.observed_at_unix = 100;
        result.error_class.clear();
        // A bool and timestamp are not independently authenticated proof.
        assert_eq!(
            validate_host_result(&result, &intent).unwrap_err(),
            "HOST_NATIVE_RECEIPT_ATTESTATION_REQUIRED"
        );
        result.state = FleetHostResultState::Authorized as i32;
        result.physical_readback = false;
        assert_eq!(
            validate_host_result(&result, &intent).unwrap_err(),
            "HOST_NATIVE_RECEIPT_ATTESTATION_REQUIRED"
        );
        result.operation_id.push('x');
        assert!(validate_host_result(&result, &intent).is_err());
    }

    #[test]
    fn only_pinned_worker_signature_can_authorize_exact_intent() {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let (_, intent, _, _, _) = fixture();
        let rng = SystemRandom::new();
        let pair =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let mut auth = FleetHostAuthorization {
            schema_version: 1,
            key_id: "worker-v1".to_owned(),
            operation_id: intent.operation_id.clone(),
            issued_at_unix: 1_000,
            expires_at_unix: 1_180,
            ed25519_signature: Vec::new(),
        };
        assert!(
            verify_host_authorization(&intent, &auth, pair.public_key().as_ref(), 1_060).is_err()
        );
        auth.ed25519_signature = pair
            .sign(&host_authorization_payload(&intent, &auth))
            .as_ref()
            .to_vec();
        verify_host_authorization(&intent, &auth, pair.public_key().as_ref(), 1_060).unwrap();
        let mut forged = intent.clone();
        forged.machine_id = "other-host".to_owned();
        assert!(
            verify_host_authorization(&forged, &auth, pair.public_key().as_ref(), 1_060).is_err()
        );
        assert!(verify_host_authorization(&intent, &auth, &[7u8; 32], 1_060).is_err());
        assert!(
            verify_host_authorization(&intent, &auth, pair.public_key().as_ref(), 9_999).is_err()
        );
        auth.operation_id = "other-operation".to_owned();
        assert!(
            verify_host_authorization(&intent, &auth, pair.public_key().as_ref(), 1_060).is_err()
        );
    }

    #[test]
    fn refuse_noncanonical_and_oversized_wire() {
        let (_, intent, _, _, _) = fixture();
        let mut bytes = intent.encode_to_vec();
        bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(decode_host_intent(&bytes).is_err());
        assert!(decode_host_intent(&vec![0u8; MAX_HOST_INTENT_BYTES + 1]).is_err());
    }
}
