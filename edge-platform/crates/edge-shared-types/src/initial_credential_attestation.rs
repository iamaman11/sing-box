//! Identical non-secret first-use host evidence fingerprint on VM and Windows.
//! The verified job/host owner supplies provenance; hashing alone is not a
//! signature or permission to publish new credentials.
use crate::{
    CREDENTIAL_DUMMY_PROBE_GENERATION_A, CREDENTIAL_DUMMY_PROBE_GENERATION_B,
    CredentialDeliverySlot, CredentialProjectionKind,
};
use ring::digest::{SHA256, digest};

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

/// Only call this AFTER the owner's independent authenticated dummy A/B probes
/// and exact immutable local release verification pass. The caller is trusted
/// to have checked the origin of these input fields.
pub fn first_use_host_attestation_sha256(
    projection: CredentialProjectionKind,
    generation: u64,
    slot: CredentialDeliverySlot,
    provider_intent_sha256: &str,
    release_set_sha256: &str,
    host_identity: &str,
    github_run_id: u64,
) -> Result<String, String> {
    if !matches!(
        projection,
        CredentialProjectionKind::Vm | CredentialProjectionKind::Windows
    ) || !matches!(slot, CredentialDeliverySlot::A | CredentialDeliverySlot::B)
        || generation == 0
        || generation == CREDENTIAL_DUMMY_PROBE_GENERATION_A
        || generation == CREDENTIAL_DUMMY_PROBE_GENERATION_B
    {
        return Err(
            "initial attestation requires a real generation, projection and fixed slot".to_owned(),
        );
    }
    if !lowercase_sha256(provider_intent_sha256) || !lowercase_sha256(release_set_sha256) {
        return Err("initial attestation requires exact lowercase SHA-256 inputs".to_owned());
    }
    if github_run_id == 0 {
        return Err("initial attestation requires non-zero GitHub run identity".to_owned());
    }
    let machine = host_identity.trim();
    if machine.is_empty() || machine.len() > 256 || machine.contains(['\n', '\r']) {
        return Err("initial attestation needs a bounded local machine identity".to_owned());
    }
    // Domain separation and per-field lengths prevent ambiguous concatenation.
    let mut bytes = b"sing-box.initial-owner-probe/v1".to_vec();
    for field in [
        projection.as_str_name().as_bytes(),
        &generation.to_be_bytes(),
        slot.as_str_name().as_bytes(),
        provider_intent_sha256.as_bytes(),
        release_set_sha256.as_bytes(),
        machine.as_bytes(),
        &github_run_id.to_be_bytes(),
    ] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    let hash = digest(&SHA256, &bytes);
    Ok(hash
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_is_provenance_scoped_not_interchangeable() {
        let arguments = ("a".repeat(64), "b".repeat(64));
        let digest = |projection, generation, slot, machine| {
            first_use_host_attestation_sha256(
                projection,
                generation,
                slot,
                &arguments.0,
                &arguments.1,
                machine,
                1011,
            )
            .unwrap()
        };
        let vm = digest(
            CredentialProjectionKind::Vm,
            101,
            CredentialDeliverySlot::A,
            "vm-machine",
        );
        assert_eq!(vm.len(), 64);
        assert_eq!(
            vm,
            digest(
                CredentialProjectionKind::Vm,
                101,
                CredentialDeliverySlot::A,
                "vm-machine"
            )
        );
        assert_ne!(
            vm,
            digest(
                CredentialProjectionKind::Windows,
                101,
                CredentialDeliverySlot::A,
                "vm-machine"
            )
        );
        assert_ne!(
            vm,
            digest(
                CredentialProjectionKind::Vm,
                102,
                CredentialDeliverySlot::A,
                "vm-machine"
            )
        );
        assert_ne!(
            vm,
            digest(
                CredentialProjectionKind::Vm,
                101,
                CredentialDeliverySlot::B,
                "vm-machine"
            )
        );
        assert_ne!(
            vm,
            digest(
                CredentialProjectionKind::Vm,
                101,
                CredentialDeliverySlot::A,
                "other-machine"
            )
        );
    }

    #[test]
    fn attestation_binds_github_run_identity() {
        let compute = |run_id| {
            first_use_host_attestation_sha256(
                CredentialProjectionKind::Vm,
                101,
                CredentialDeliverySlot::A,
                &"a".repeat(64),
                &"b".repeat(64),
                "vm-machine",
                run_id,
            )
        };
        assert_ne!(compute(1011).unwrap(), compute(1012).unwrap());
        assert!(compute(0).is_err());
    }

    #[test]
    fn malformed_or_reserved_first_use_evidence_is_rejected() {
        for generation in [
            0,
            CREDENTIAL_DUMMY_PROBE_GENERATION_A,
            CREDENTIAL_DUMMY_PROBE_GENERATION_B,
        ] {
            assert!(
                first_use_host_attestation_sha256(
                    CredentialProjectionKind::Vm,
                    generation,
                    CredentialDeliverySlot::A,
                    &"a".repeat(64),
                    &"b".repeat(64),
                    "vm-machine",
                    1011,
                )
                .is_err()
            );
        }
        for identity in ["", "with\nnewline"] {
            assert!(
                first_use_host_attestation_sha256(
                    CredentialProjectionKind::Windows,
                    101,
                    CredentialDeliverySlot::B,
                    &"a".repeat(64),
                    &"b".repeat(64),
                    identity,
                    1011,
                )
                .is_err()
            );
        }
        assert!(
            first_use_host_attestation_sha256(
                CredentialProjectionKind::Windows,
                101,
                CredentialDeliverySlot::B,
                &"a".repeat(63),
                &"b".repeat(64),
                "win-machine",
                1011,
            )
            .is_err()
        );
    }
}
