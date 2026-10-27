//! One signed, read-only native snapshot. A transport copy alone proves nothing.
//! Domain separation forbids reusing this signature as a mutation receipt.
use crate::host_receipt::check_native_receipt_key;
use crate::host_resources::validate_vm_resource_report;
use crate::{FleetHost, FleetHostKind, FleetNativeDiagnosticSnapshot};
use prost::Message;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};

pub const MAX_SNAPSHOT_BYTES: usize = 65_536;
const DOMAIN: &[u8] = b"sing-box/native-diagnostic-snapshot/v1:";

fn payload(snapshot: &FleetNativeDiagnosticSnapshot) -> Vec<u8> {
    let mut unsigned = snapshot.clone();
    unsigned.ed25519_signature.clear();
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&unsigned.encode_to_vec());
    bytes
}

fn validate_scope(
    snapshot: &FleetNativeDiagnosticSnapshot,
    host: &FleetHost,
    expected_operation_id: &str,
    expected_release_sha256: &[u8],
    now: u64,
) -> Result<(), &'static str> {
    if snapshot.schema_version != 1
        || host.kind != FleetHostKind::Vm as i32
        || snapshot.machine_id != host.machine_id
        || snapshot.operation_id != expected_operation_id
        || !expected_operation_id.starts_with("issue1-comment-")
        || expected_operation_id[15..].parse::<u64>().is_err()
        || snapshot.release_set_sha256 != expected_release_sha256
        || expected_release_sha256.len() != 32
    {
        return Err("HOST_SNAPSHOT_CORRELATION_OR_RELEASE_INVALID");
    }
    // A pending BEGIN remains a no-replay constraint; a signed readback does
    // not confer any permission to finish, clear or repeat its effects.
    if snapshot.pending_resource_count > 64
        || snapshot.pending_operation_id.len() > 128
        || snapshot.pending_resource_id.len() > 128
        || snapshot
            .pending_operation_id
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'.' | b':'))
        || snapshot
            .pending_resource_id
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'.' | b'/'))
        || !(snapshot.pending_request_sha256.is_empty()
            || snapshot.pending_request_sha256.len() == 32)
        || snapshot.line2_failure_code.len() > 96
        || snapshot
            .line2_failure_code
            .bytes()
            .any(|b| !b.is_ascii_uppercase() && !b.is_ascii_digit() && b != b'_')
        || !(snapshot.line2_log_sha256.is_empty() || snapshot.line2_log_sha256.len() == 32)
        || !(snapshot.pending_original_release_sha256.is_empty()
            || snapshot.pending_original_release_sha256.len() == 32)
        || !(snapshot.pending_original_desired_sha256.is_empty()
            || snapshot.pending_original_desired_sha256.len() == 32)
        || !(snapshot.pending_begin_record_sha256.is_empty()
            || snapshot.pending_begin_record_sha256.len() == 32)
        || (snapshot.pending_operation_id.starts_with("issue1-comment-")
            && (snapshot.pending_original_release_sha256.len() != 32
                || snapshot.pending_original_desired_sha256.len() != 32
                || snapshot.pending_begin_record_sha256.len() != 32))
        || (snapshot.pending_operation_id == "UNPROVEN_PENDING_RECORD"
            && (!snapshot.pending_original_release_sha256.is_empty()
                || !snapshot.pending_original_desired_sha256.is_empty()
                || !snapshot.pending_begin_record_sha256.is_empty()))
        || (snapshot.pending_resource_count == 0
            && (!snapshot.pending_operation_id.is_empty()
                || !snapshot.pending_resource_id.is_empty()
                || !snapshot.pending_request_sha256.is_empty()
                || !snapshot.pending_original_release_sha256.is_empty()
                || !snapshot.pending_original_desired_sha256.is_empty()
                || !snapshot.pending_begin_record_sha256.is_empty()))
    {
        return Err("HOST_SNAPSHOT_PENDING_DIAGNOSTIC_INVALID");
    }
    let observation = snapshot
        .observation
        .as_ref()
        .ok_or("HOST_SNAPSHOT_OBSERVATION_MISSING")?;
    let resources = snapshot
        .resources
        .as_ref()
        .ok_or("HOST_SNAPSHOT_RESOURCES_MISSING")?;
    if observation.schema_version != 1
        || observation.host_kind != host.kind
        || observation.observed_at_unix == 0
        || observation.observed_at_unix > now.saturating_add(60)
        || now.saturating_sub(observation.observed_at_unix) > 300
        || resources.observed_at_unix > now.saturating_add(60)
        || now.saturating_sub(resources.observed_at_unix) > 300
        || observation
            .observed_at_unix
            .abs_diff(resources.observed_at_unix)
            > 90
    {
        return Err("HOST_SNAPSHOT_STALE_OR_SCOPE_INVALID");
    }
    validate_vm_resource_report(resources, host)?;
    if snapshot.encode_to_vec().len() > MAX_SNAPSHOT_BYTES {
        return Err("HOST_SNAPSHOT_TOO_LARGE");
    }
    Ok(())
}

pub fn sign(
    snapshot: &mut FleetNativeDiagnosticSnapshot,
    host: &FleetHost,
    key: &[u8],
    now: u64,
) -> Result<(), &'static str> {
    check_native_receipt_key(host, key)?;
    if !snapshot.ed25519_signature.is_empty() {
        return Err("HOST_SNAPSHOT_ALREADY_SIGNED");
    }
    let expected_operation = snapshot.operation_id.clone();
    let expected_release = snapshot.release_set_sha256.clone();
    validate_scope(snapshot, host, &expected_operation, &expected_release, now)?;
    let pair = Ed25519KeyPair::from_pkcs8(key).map_err(|_| "HOST_SNAPSHOT_KEY_INVALID")?;
    snapshot.ed25519_signature = pair.sign(&payload(snapshot)).as_ref().to_vec();
    if snapshot.encode_to_vec().len() > MAX_SNAPSHOT_BYTES {
        return Err("HOST_SNAPSHOT_TOO_LARGE");
    }
    Ok(())
}

pub fn verify(
    bytes: &[u8],
    host: &FleetHost,
    operation_id: &str,
    release_sha256: &[u8],
    now: u64,
) -> Result<FleetNativeDiagnosticSnapshot, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err("HOST_SNAPSHOT_SIZE_INVALID");
    }
    let snapshot =
        FleetNativeDiagnosticSnapshot::decode(bytes).map_err(|_| "HOST_SNAPSHOT_PROTO_INVALID")?;
    if snapshot.encode_to_vec() != bytes
        || snapshot.ed25519_signature.len() != 64
        || host.native_receipt_public_key.len() != 32
        || host.native_receipt_public_key.iter().all(|b| *b == 0)
    {
        return Err("HOST_SNAPSHOT_NONCANONICAL_OR_UNPINNED");
    }
    validate_scope(&snapshot, host, operation_id, release_sha256, now)?;
    UnparsedPublicKey::new(&ED25519, &host.native_receipt_public_key)
        .verify(&payload(&snapshot), &snapshot.ed25519_signature)
        .map_err(|_| "HOST_SNAPSHOT_SIGNATURE_INVALID")?;
    Ok(snapshot)
}

/// Authenticate the *installed owner's* pending-safe read-only snapshot
/// with the Git-pinned native receipt key, even when its exact installed
/// ReleaseSet predates current Git desired. This NEVER authorizes APPLY,
/// upgrades, journal changes or resource parity. A signed historical digest
/// is an owner observation, not independent proof of a published artifact.
pub fn verify_installed_read_only(
    bytes: &[u8],
    host: &FleetHost,
    operation_id: &str,
    current_release_sha256: &[u8],
    now: u64,
) -> Result<(FleetNativeDiagnosticSnapshot, bool), &'static str> {
    if current_release_sha256.len() != 32 {
        return Err("HOST_SNAPSHOT_EXPECTED_RELEASE_INVALID");
    }
    if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err("HOST_SNAPSHOT_SIZE_INVALID");
    }
    let claimed = FleetNativeDiagnosticSnapshot::decode(bytes)
        .map_err(|_| "HOST_SNAPSHOT_PROTO_INVALID")?;
    if claimed.release_set_sha256.len() != 32
        || claimed.release_set_sha256.iter().all(|byte| *byte == 0)
    {
        return Err("HOST_SNAPSHOT_INSTALLED_RELEASE_INVALID");
    }
    // verify() still enforces exact machine/comment, canonical bytes, freshness,
    // resources and Ed25519 signature, using this Git-pinned owner's key.
    let accepted = verify(bytes, host, operation_id, &claimed.release_set_sha256, now)?;
    let current = accepted.release_set_sha256 == current_release_sha256;
    Ok((accepted, current))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::KeyPair};
    #[test]
    fn historical_pending_begin_requires_exact_three_hashes() {
        let host = FleetHost {
            machine_id: "vm5".into(),
            kind: FleetHostKind::Vm as i32,
            ..Default::default()
        };
        let mut snapshot = FleetNativeDiagnosticSnapshot {
            schema_version: 1,
            machine_id: "vm5".into(),
            operation_id: "issue1-comment-43".into(),
            release_set_sha256: vec![5; 32],
            pending_resource_count: 1,
            pending_operation_id: "issue1-comment-40".into(),
            pending_resource_id: "sing-box".into(),
            pending_request_sha256: vec![1; 32],
            pending_original_release_sha256: vec![2; 32],
            pending_original_desired_sha256: vec![3; 32],
            pending_begin_record_sha256: vec![4; 32],
            ..Default::default()
        };
        // The next rejection is for absent observation, NOT for a truncated
        // historical BEGIN. No fabricated physical acceptance is possible.
        assert_eq!(
            validate_scope(&snapshot, &host, "issue1-comment-43", &[5; 32], 100),
            Err("HOST_SNAPSHOT_OBSERVATION_MISSING")
        );
        snapshot.pending_begin_record_sha256.clear();
        assert_eq!(
            validate_scope(&snapshot, &host, "issue1-comment-43", &[5; 32], 100),
            Err("HOST_SNAPSHOT_PENDING_DIAGNOSTIC_INVALID")
        );
        snapshot.pending_begin_record_sha256 = vec![4; 32];
        snapshot.pending_resource_count = 0;
        assert_eq!(
            validate_scope(&snapshot, &host, "issue1-comment-43", &[5; 32], 100),
            Err("HOST_SNAPSHOT_PENDING_DIAGNOSTIC_INVALID")
        );
    }

    #[test]
    fn stale_installed_snapshot_is_signed_read_only_not_current_parity() {
        use crate::{
            FleetNativeObservation, FleetNativeOwnerState, FleetNativeReleaseProof,
            FleetVmContainer, FleetVmCredentialReadback, FleetVmCredentialState,
            FleetVmResourceReadback, FleetVmResourceReport,
        };
        let pair_bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pair_bytes.as_ref()).unwrap();
        let resource = FleetVmContainer {
            container_name: "my-proxy".into(),
            compose_project: "my-app".into(),
            compose_service: "proxy".into(),
        };
        let host = FleetHost {
            machine_id: "vm5".into(),
            kind: FleetHostKind::Vm as i32,
            native_receipt_public_key: signer.public_key().as_ref().to_vec(),
            vm_containers: vec![resource.clone()],
            ..Default::default()
        };
        let installed = vec![5; 32];
        let current = vec![6; 32];
        let mut snapshot = FleetNativeDiagnosticSnapshot {
            schema_version: 1,
            machine_id: "vm5".into(),
            operation_id: "issue1-comment-42".into(),
            release_set_sha256: installed.clone(),
            observation: Some(FleetNativeObservation {
                schema_version: 1,
                host_kind: FleetHostKind::Vm as i32,
                observed_at_unix: 100,
                owner_state: FleetNativeOwnerState::Running as i32,
                release_proof: FleetNativeReleaseProof::ApplicationBundle as i32,
                observed_release_sha256: vec![9; 32],
                runtime_ready: true,
                runtime_ready_proven: true,
                ..Default::default()
            }),
            resources: Some(FleetVmResourceReport {
                schema_version: 2,
                machine_id: "vm5".into(),
                observed_at_unix: 100,
                resources: vec![FleetVmResourceReadback {
                    resource: Some(resource),
                    present: true,
                    ownership_proven: true,
                    running: true,
                    running_proven: true,
                    container_id: "a".repeat(64),
                    reason_code: "HEALTHY".into(),
                    observed_reason: crate::FleetVmObservedReason::Healthy as i32,
                    health: "HEALTHY".into(),
                    ..Default::default()
                }],
                credential: Some(FleetVmCredentialReadback {
                    state: FleetVmCredentialState::ActiveLocalValid as i32,
                    active_generation: 42,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        sign(&mut snapshot, &host, pair_bytes.as_ref(), 100).unwrap();
        let bytes = snapshot.encode_to_vec();
        let (signed_old, parity) = verify_installed_read_only(
            &bytes, &host, "issue1-comment-42", &current, 100,
        )
        .unwrap();
        assert_eq!(signed_old.release_set_sha256, installed);
        assert!(!parity);
        assert!(verify(&bytes, &host, "issue1-comment-42", &current, 100).is_err());
        assert!(verify_installed_read_only(
            &bytes, &host, "issue1-comment-42", &installed, 100,
        ).unwrap().1);
        assert_eq!(verify_installed_read_only(
            &bytes, &host, "issue1-comment-43", &current, 100,
        ).unwrap_err(), "HOST_SNAPSHOT_CORRELATION_OR_RELEASE_INVALID");
        let other = FleetHost {
            machine_id: "other".into(),
            ..host.clone()
        };
        assert_eq!(verify_installed_read_only(
            &bytes, &other, "issue1-comment-42", &current, 100,
        ).unwrap_err(), "HOST_SNAPSHOT_CORRELATION_OR_RELEASE_INVALID");
        let mut tampered = snapshot.clone();
        tampered.release_set_sha256 = vec![7; 32];
        assert_eq!(verify_installed_read_only(
            &tampered.encode_to_vec(), &host, "issue1-comment-42", &current, 100,
        ).unwrap_err(), "HOST_SNAPSHOT_SIGNATURE_INVALID");
        let mut other_key = host.clone();
        other_key.native_receipt_public_key = vec![8; 32];
        assert_eq!(verify_installed_read_only(
            &bytes, &other_key, "issue1-comment-42", &current, 100,
        ).unwrap_err(), "HOST_SNAPSHOT_SIGNATURE_INVALID");
        assert_eq!(verify_installed_read_only(
            &bytes, &host, "issue1-comment-42", &current, 501,
        ).unwrap_err(), "HOST_SNAPSHOT_STALE_OR_SCOPE_INVALID");
    }

    #[test]
    fn snapshot_requires_full_signed_scope() {
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
        let host = FleetHost {
            machine_id: "vm5".into(),
            kind: FleetHostKind::Vm as i32,
            native_receipt_public_key: pair.public_key().as_ref().to_vec(),
            ..Default::default()
        };
        // Missing native resources must never be authenticated as healthy.
        let mut snapshot = FleetNativeDiagnosticSnapshot {
            schema_version: 1,
            machine_id: "vm5".into(),
            operation_id: "issue1-comment-42".into(),
            release_set_sha256: vec![4; 32],
            ..Default::default()
        };
        assert!(sign(&mut snapshot, &host, key.as_ref(), 100).is_err());
        assert!(
            verify(
                &snapshot.encode_to_vec(),
                &host,
                "issue1-comment-42",
                &[4; 32],
                100
            )
            .is_err()
        );
        assert!(
            verify(
                &snapshot.encode_to_vec(),
                &host,
                "issue1-comment-43",
                &[4; 32],
                100
            )
            .is_err()
        );
    }
}
