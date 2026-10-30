//! Ephemeral delegation to the existing Controller, not a second authorizer.
//! SYSTEM signs only after durable BEGIN; Controller cannot read the private
//! receipt key. A process nonce + consumed operation ID prevent local RPC replay.
use crate::{
    FleetHostAction, FleetHostKind, FleetHostRunState,
    FleetWindowsRuntimeChallenge as Challenge, FleetWindowsRuntimeEffect as Effect, HostRegistry,
};
use prost::Message;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};

const DOMAIN: &[u8] = b"sing-box/windows-runtime-effect/v1:";
pub const MAX_BYTES: usize = 262144;
fn payload(effect: &Effect) -> Vec<u8> {
    let mut unsigned = effect.clone();
    unsigned.system_signature.clear();
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(unsigned.encode_to_vec());
    bytes
}
pub fn sign(effect: &mut Effect, private: &[u8]) -> Result<(), &'static str> {
    let pair =
        Ed25519KeyPair::from_pkcs8(private).map_err(|_| "HOST_WINDOWS_EFFECT_KEY_INVALID")?;
    effect.system_signature = pair.sign(&payload(effect)).as_ref().to_vec();
    Ok(())
}
pub fn decode(bytes: &[u8]) -> Result<Effect, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("HOST_WINDOWS_EFFECT_SIZE_INVALID");
    }
    let effect = Effect::decode(bytes).map_err(|_| "HOST_WINDOWS_EFFECT_PROTO_INVALID")?;
    if effect.encode_to_vec() != bytes {
        return Err("HOST_WINDOWS_EFFECT_NONCANONICAL");
    }
    Ok(effect)
}
pub fn verify_system_signature(
    effect: &Effect,
    trusted_local_public: &[u8],
) -> Result<(), &'static str> {
    if trusted_local_public.len() != 32 || effect.system_signature.len() != 64 {
        return Err("HOST_WINDOWS_EFFECT_SYSTEM_IDENTITY_INVALID");
    }
    UnparsedPublicKey::new(&ED25519, trusted_local_public)
        .verify(&payload(effect), &effect.system_signature)
        .map_err(|_| "HOST_WINDOWS_EFFECT_SYSTEM_SIGNATURE_REJECTED")
}
pub fn verify(
    effect: &Effect,
    challenge: &Challenge,
    registry: &HostRegistry,
    registry_sha256: &[u8],
    spec: &[u8],
    config_sha256: &[u8],
    now: u64,
) -> Result<(), &'static str> {
    let intent = effect
        .intent
        .as_ref()
        .ok_or("HOST_WINDOWS_EFFECT_INTENT_MISSING")?;
    let auth = effect
        .authorization
        .as_ref()
        .ok_or("HOST_WINDOWS_EFFECT_AUTH_MISSING")?;
    if effect.schema_version != 1
        || effect.encoded_len() > MAX_BYTES
        || effect.challenge.as_ref() != Some(challenge)
        || effect.registry_pb != registry.encode_to_vec()
        || effect.selected_spec_bytes != spec
        || challenge.nonce.len() != 32
        || challenge.nonce.iter().all(|b| *b == 0)
        || challenge.process_id == 0
        || challenge.installed_release_sha256.len() != 32
        || config_sha256.len() != 32
        || effect.config_sha256 != config_sha256
        || effect.expires_at_unix <= now
        || effect.expires_at_unix > now.saturating_add(120)
        || effect.expires_at_unix > auth.expires_at_unix
        || effect.system_signature.len() != 64
        || intent.kind != FleetHostKind::Windows as i32
        || intent.resource_id != "sing-box"
        || !matches!(
            FleetHostAction::try_from(intent.action),
            Ok(FleetHostAction::Start | FleetHostAction::Apply)
        )
    {
        return Err("HOST_WINDOWS_EFFECT_BINDING_OR_FRESHNESS_INVALID");
    }
    let host = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == intent.machine_id && h.kind == intent.kind)
        .ok_or("HOST_WINDOWS_EFFECT_MACHINE_UNREGISTERED")?;
    let desired = crate::parse_production_desired_text(spec)?;
    let mode = crate::host_lifecycle::validate_windows_mode_target_and_spec(host, &desired)?;
    if !matches!(host.target.as_ref(),
        Some(t) if t.run_state == FleetHostRunState::Running as i32)
        || mode != crate::WindowsDatapathMode::ProxyOnly
    {
        return Err("HOST_WINDOWS_EFFECT_PROXY_ONLY_RUNNING_TARGET_REQUIRED");
    }
    crate::host_lifecycle::verify_windows_signed_git_prerequisites(host)?;
    crate::host_lifecycle::validate_host_intent(
        intent,
        registry,
        registry_sha256,
        &crate::host_lifecycle::digest_host_desired(host, spec)?,
        &intent.release_set_sha256,
    )?;
    crate::host_lifecycle::validate_intent_against_target(intent, registry)?;
    crate::host_lifecycle::verify_host_authorization(
        intent,
        auth,
        &host.worker_authority_public_key,
        now,
    )?;
    UnparsedPublicKey::new(&ED25519, &host.native_receipt_public_key)
        .verify(&payload(effect), &effect.system_signature)
        .map_err(|_| "HOST_WINDOWS_EFFECT_SYSTEM_SIGNATURE_REJECTED")
}

/// Only verified, unexpired effects reach this bounded per-process replay set.
pub fn consume(
    used: &mut std::collections::BTreeMap<String, u64>,
    operation: &str,
    expiry: u64,
    now: u64,
) -> Result<(), &'static str> {
    used.retain(|_, deadline| *deadline > now);
    if used.contains_key(operation) {
        return Err("HOST_WINDOWS_EFFECT_ALREADY_CONSUMED_NO_REPLAY");
    }
    if used.len() >= 128 {
        return Err("HOST_WINDOWS_EFFECT_ADMISSION_BUSY");
    }
    used.insert(operation.into(), expiry);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FleetHost, FleetHostAuthorization, FleetHostIntent, FleetHostTarget, managed_host,
    };
    use ring::{rand::SystemRandom, signature::KeyPair};
    fn sha(b: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, b)
            .as_ref()
            .to_vec()
    }
    #[test]
    fn delegation_requires_both_signatures_exact_nonce_config_and_single_use() {
        let private = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let system = Ed25519KeyPair::from_pkcs8(private.as_ref()).unwrap();
        let worker = Ed25519KeyPair::from_pkcs8(
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let host = FleetHost {
            machine_id: "windows-test".into(),
            kind: FleetHostKind::Windows as i32,
            owner: Some(managed_host::Owner::WindowsRunnerName("TEST".into())),
            windows_runner_label: "windows-test".into(),
            desired_spec_path: "infra/production/production.textproto".into(),
            target: Some(FleetHostTarget {
                run_state: FleetHostRunState::Running as i32,
                windows_mode: crate::FleetHostMode::Unspecified as i32,
            }),
            native_receipt_public_key: system.public_key().as_ref().to_vec(),
            worker_authority_public_key: worker.public_key().as_ref().to_vec(),
            ..Default::default()
        };
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![host.clone()],
        };
        let spec = b"windows_datapath_mode: WINDOWS_DATAPATH_MODE_PROXY_ONLY\n";
        let registry_sha = sha(&registry.encode_to_vec());
        let intent = FleetHostIntent {
            schema_version: 1,
            machine_id: host.machine_id,
            kind: host.kind,
            resource_id: "sing-box".into(),
            operation_id: "issue1-comment-42".into(),
            action: FleetHostAction::Start as i32,
            registry_sha256: registry_sha.clone(),
            desired_sha256: crate::host_lifecycle::digest_host_desired(&registry.hosts[0], spec)
                .unwrap(),
            release_set_sha256: vec![1; 32],
            requested_at_unix: 100,
            ..Default::default()
        };
        let mut auth = FleetHostAuthorization {
            schema_version: 1,
            key_id: "worker".into(),
            operation_id: intent.operation_id.clone(),
            issued_at_unix: 100,
            expires_at_unix: 200,
            ..Default::default()
        };
        auth.ed25519_signature = worker
            .sign(&crate::host_lifecycle::host_authorization_payload(
                &intent, &auth,
            ))
            .as_ref()
            .to_vec();
        let challenge = Challenge {
            nonce: vec![2; 32],
            process_id: 123,
            installed_release_sha256: vec![1; 32],
        };
        let mut effect = Effect {
            schema_version: 1,
            intent: Some(intent),
            authorization: Some(auth),
            challenge: Some(challenge.clone()),
            config_sha256: vec![3; 32],
            expires_at_unix: 180,
            registry_pb: registry.encode_to_vec(),
            selected_spec_bytes: spec.to_vec(),
            ..Default::default()
        };
        sign(&mut effect, private.as_ref()).unwrap();
        verify(
            &effect,
            &challenge,
            &registry,
            &registry_sha,
            spec,
            &[3; 32],
            150,
        )
        .unwrap();
        let mut changed = effect.clone();
        changed.challenge.as_mut().unwrap().nonce[0] ^= 1;
        assert!(
            verify(
                &changed,
                &challenge,
                &registry,
                &registry_sha,
                spec,
                &[3; 32],
                150
            )
            .is_err()
        );
        changed = effect.clone();
        changed.config_sha256[0] ^= 1;
        assert!(
            verify(
                &changed,
                &challenge,
                &registry,
                &registry_sha,
                spec,
                &[3; 32],
                150
            )
            .is_err()
        );
        changed = effect.clone();
        changed.system_signature[0] ^= 1;
        assert!(
            verify(
                &changed,
                &challenge,
                &registry,
                &registry_sha,
                spec,
                &[3; 32],
                150
            )
            .is_err()
        );
        assert!(
            verify(
                &effect,
                &challenge,
                &registry,
                &registry_sha,
                spec,
                &[3; 32],
                181
            )
            .is_err()
        );
        let mut used = std::collections::BTreeMap::new();
        consume(&mut used, "id", 180, 150).unwrap();
        assert!(consume(&mut used, "id", 180, 150).is_err());
        let mut restarted = challenge;
        restarted.nonce[0] ^= 1;
        assert!(
            verify(
                &effect,
                &restarted,
                &registry,
                &registry_sha,
                spec,
                &[3; 32],
                150
            )
            .is_err()
        );
    }
}
