//! One typed, release-bound lifecycle contract shared by Windows, VM and fleet.
//!
//! Parsing or validating an intent is never authorization to mutate. The
//! privileged native owner must independently authenticate admission, check its
//! durable operation ledger, and read back the affected resource before it can
//! issue a VERIFIED receipt. No compatibility with legacy A/B dispatcher.

use crate::{
    FleetHostAction, FleetHostAuthorization, FleetHostIntent, FleetHostKind, FleetHostMode,
    FleetHostResult, FleetHostResultState, HostRegistry, managed_host,
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
    if !matches!(proof, FleetNativeReleaseProof::Unproven | FleetNativeReleaseProof::VerifiedAbsent)
        && proof != expected
    {
        return Err("HOST_OBSERVATION_PROOF_KIND_MISMATCH");
    }
    if release.is_empty()
        != matches!(proof, FleetNativeReleaseProof::Unproven | FleetNativeReleaseProof::VerifiedAbsent)
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
            != matches!(proof, FleetNativeReleaseProof::Unproven | FleetNativeReleaseProof::VerifiedAbsent))
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

pub fn validate_host_intent(
    intent: &FleetHostIntent,
    registry: &HostRegistry,
    exact_registry_sha256: &[u8],
    exact_desired_sha256: &[u8],
    exact_release_set_sha256: &[u8],
) -> Result<(), &'static str> {
    if intent.schema_version != 1
        || !token(&intent.machine_id)
        || !token(&intent.resource_id)
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
    FleetHostResult {
        schema_version: 1,
        machine_id: intent.machine_id.clone(),
        resource_id: intent.resource_id.clone(),
        operation_id: intent.operation_id.clone(),
        action: intent.action,
        state: FleetHostResultState::Prepared as i32,
        release_set_sha256: intent.release_set_sha256.clone(),
        desired_sha256: intent.desired_sha256.clone(),
        observed_at_unix: 0,
        error_class: "NATIVE_INSTALL_AUTHORITY_NOT_ACCEPTED".to_owned(),
        next_action: "NEED_TRUSTED_OWNER_BOOTSTRAP".to_owned(),
        physical_readback: false,
    }
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
    use super::*;
    use crate::{FleetHost, HostRegistry, encode_host_registry};

    fn fixture() -> (HostRegistry, FleetHostIntent, Vec<u8>, Vec<u8>, Vec<u8>) {
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![FleetHost {
                machine_id: "windows-1".to_owned(),
                kind: FleetHostKind::Windows as i32,
                owner: Some(managed_host::Owner::WindowsRunnerName("WIN-1".to_owned())),
                windows_runner_label: "windows-1".to_owned(),
                desired_spec_path: "infra/production/production.textproto".to_owned(),
                target: None,
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
