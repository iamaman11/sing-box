//! One typed, release-bound lifecycle contract shared by Windows, VM and fleet.
//!
//! Parsing or validating an intent is never authorization to mutate. The
//! privileged native owner must independently authenticate admission, check its
//! durable operation ledger, and read back the affected resource before it can
//! issue a VERIFIED receipt. No compatibility with legacy A/B dispatcher.

use crate::{
    FleetHostAction, FleetHostIntent, FleetHostKind, FleetHostMode, FleetHostResult,
    FleetHostResultState, HostRegistry, managed_host,
};
use prost::Message;

pub const MAX_HOST_INTENT_BYTES: usize = 8192;
pub const MAX_HOST_RESULT_BYTES: usize = 8192;

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
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
    if intent.schema_version != 1 || !token(&intent.machine_id)
        || !token(&intent.resource_id) || !token(&intent.operation_id)
        || intent.requested_at_unix == 0
    {
        return Err("HOST_INTENT_IDENTITY_INVALID");
    }
    if !sha(exact_registry_sha256) || !sha(exact_desired_sha256) || !sha(exact_release_set_sha256)
        || intent.registry_sha256 != exact_registry_sha256
        || intent.desired_sha256 != exact_desired_sha256
        || intent.release_set_sha256 != exact_release_set_sha256
    {
        return Err("HOST_INTENT_DIGEST_MISMATCH");
    }
    let host = registry.hosts.iter()
        .find(|h| h.machine_id == intent.machine_id)
        .ok_or("HOST_INTENT_UNKNOWN_MACHINE")?;
    if host.kind != intent.kind
        || !matches!(
            (FleetHostKind::try_from(host.kind), host.owner.as_ref()),
            (Ok(FleetHostKind::Windows), Some(managed_host::Owner::WindowsRunnerName(_)))
                | (Ok(FleetHostKind::Vm), Some(managed_host::Owner::VmMachineId(_)))
        )
    {
        return Err("HOST_INTENT_OWNER_MISMATCH");
    }
    let action = FleetHostAction::try_from(intent.action)
        .map_err(|_| "HOST_INTENT_ACTION_INVALID")?;
    let mode = FleetHostMode::try_from(intent.requested_mode)
        .map_err(|_| "HOST_INTENT_MODE_INVALID")?;
    if action == FleetHostAction::Unspecified
        || (action == FleetHostAction::SetMode
            && (host.kind != FleetHostKind::Windows as i32
                || mode == FleetHostMode::Unspecified))
        || (action != FleetHostAction::SetMode && mode != FleetHostMode::Unspecified)
    {
        return Err("HOST_INTENT_ACTION_MODE_MISMATCH");
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
    let state = FleetHostResultState::try_from(result.state)
        .map_err(|_| "HOST_RESULT_STATE_INVALID")?;
    if state == FleetHostResultState::Unspecified
        || (state == FleetHostResultState::Verified
            && (!result.physical_readback
                || result.observed_at_unix == 0
                || !result.error_class.is_empty()))
        || (state != FleetHostResultState::Verified && result.physical_readback)
        || result.error_class.len() > 128
        || result.next_action.len() > 128
        || !result.error_class.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        || !result.next_action.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
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
            }],
        };
        let bytes = encode_host_registry(&registry).unwrap();
        let registry_sha = ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref().to_vec();
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
    fn exact_scoped_intent_and_prepared_receipt() {
        let (registry, intent, inv, desired, release) = fixture();
        validate_host_intent(&intent, &registry, &inv, &desired, &release).unwrap();
        let encoded = intent.encode_to_vec();
        assert_eq!(decode_host_intent(&encoded).unwrap(), intent);
        let receipt = prepared_host_result(&intent);
        validate_host_result(&receipt, &intent).unwrap();
        assert_eq!(decode_host_result(&receipt.encode_to_vec()).unwrap(), receipt);
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
    fn prohibit_unproven_success_or_mismatched_result() {
        let (_, intent, _, _, _) = fixture();
        let mut result = prepared_host_result(&intent);
        result.state = FleetHostResultState::Verified as i32;
        assert!(validate_host_result(&result, &intent).is_err());
        result.physical_readback = true;
        result.observed_at_unix = 100;
        result.error_class.clear();
        assert!(validate_host_result(&result, &intent).is_ok());
        result.operation_id.push('x');
        assert!(validate_host_result(&result, &intent).is_err());
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
