//! Exact native-owner receipts. The GitHub runner is transport only.
//! A structurally valid FleetHostResult is never authenticated by itself.
use crate::{FleetHost, FleetHostIntent, FleetHostReceipt, FleetHostResult};
use crate::host_lifecycle::validate_unattested_native_result;
use prost::Message;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

pub const MAX_NATIVE_RECEIPT_BYTES: usize = 8192;
const DOMAIN: &[u8] = b"sing-box/native-owner-receipt/v1:";

fn payload(intent: &FleetHostIntent, result: &FleetHostResult) -> Vec<u8> {
    let i = intent.encode_to_vec();
    let r = result.encode_to_vec();
    let mut bytes = Vec::with_capacity(DOMAIN.len() + i.len() + r.len() + 8);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(i.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&i);
    bytes.extend_from_slice(&(r.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&r);
    bytes
}

pub fn check_native_receipt_key(
    host: &FleetHost,
    pkcs8: &[u8],
) -> Result<(), &'static str> {
    let expected = &host.native_receipt_public_key;
    if expected.len() != 32 || expected.iter().all(|b| *b == 0) {
        return Err("HOST_NATIVE_RECEIPT_GIT_PUBLIC_KEY_MISSING");
    }
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8)
        .map_err(|_| "HOST_NATIVE_RECEIPT_SIGNER_INVALID")?;
    if pair.public_key().as_ref() != expected.as_slice() {
        return Err("HOST_NATIVE_RECEIPT_PUBLIC_KEY_MISMATCH");
    }
    Ok(())
}

/// Called by SYSTEM/root only, AFTER native terminal journal fsync. Native
/// admission checks the same root-only key and pinned Git public key pre-BEGIN.
pub fn sign_native_receipt(
    intent: &FleetHostIntent,
    result: &FleetHostResult,
    host: &FleetHost,
    pkcs8: &[u8],
) -> Result<FleetHostReceipt, &'static str> {
    check_native_receipt_key(host, pkcs8)?;
    validate_unattested_native_result(result, intent)?;
    if host.machine_id != intent.machine_id || host.kind != intent.kind {
        return Err("HOST_NATIVE_RECEIPT_HOST_MISMATCH");
    }
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8)
        .map_err(|_| "HOST_NATIVE_RECEIPT_SIGNER_INVALID")?;
    let receipt = FleetHostReceipt {
        schema_version: 1,
        result: Some(result.clone()),
        ed25519_signature: pair.sign(&payload(intent, result)).as_ref().to_vec(),
    };
    if receipt.encode_to_vec().len() > MAX_NATIVE_RECEIPT_BYTES {
        return Err("HOST_NATIVE_RECEIPT_TOO_LARGE");
    }
    Ok(receipt)
}

pub fn decode_native_receipt(bytes: &[u8]) -> Result<FleetHostReceipt, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_RECEIPT_BYTES {
        return Err("HOST_NATIVE_RECEIPT_SIZE_INVALID");
    }
    let receipt = FleetHostReceipt::decode(bytes)
        .map_err(|_| "HOST_NATIVE_RECEIPT_PROTO_INVALID")?;
    if receipt.encode_to_vec() != bytes {
        return Err("HOST_NATIVE_RECEIPT_NONCANONICAL");
    }
    Ok(receipt)
}

pub fn verify_native_receipt(
    intent: &FleetHostIntent,
    receipt: &FleetHostReceipt,
    host: &FleetHost,
) -> Result<FleetHostResult, &'static str> {
    if receipt.schema_version != 1 || receipt.ed25519_signature.len() != 64
        || host.machine_id != intent.machine_id || host.kind != intent.kind
        || host.native_receipt_public_key.len() != 32
        || host.native_receipt_public_key.iter().all(|b| *b == 0)
    {
        return Err("HOST_NATIVE_RECEIPT_IDENTITY_UNPROVEN");
    }
    let result = receipt.result.as_ref().ok_or("HOST_NATIVE_RECEIPT_RESULT_MISSING")?;
    validate_unattested_native_result(result, intent)?;
    UnparsedPublicKey::new(&ED25519, &host.native_receipt_public_key)
        .verify(&payload(intent, result), &receipt.ed25519_signature)
        .map_err(|_| "HOST_NATIVE_RECEIPT_SIGNATURE_INVALID")?;
    Ok(result.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FleetHostAction, FleetHostKind, FleetHostResultState};
    use ring::rand::SystemRandom;

    #[test]
    fn signed_receipt_binds_machine_resource_release_and_exact_state() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let host = FleetHost {
            machine_id: "vm-1".into(),
            kind: FleetHostKind::Vm as i32,
            native_receipt_public_key: pair.public_key().as_ref().to_vec(),
            ..Default::default()
        };
        let intent = FleetHostIntent {
            schema_version: 1, machine_id: "vm-1".into(),
            kind: FleetHostKind::Vm as i32,
            resource_id: "config/vultr-edge/line2-proxy".into(),
            operation_id: "issue1-comment-123".into(),
            action: FleetHostAction::Apply as i32,
            desired_sha256: vec![2; 32],
            release_set_sha256: vec![3; 32],
            ..Default::default()
        };
        let result = FleetHostResult {
            schema_version: 1, machine_id: intent.machine_id.clone(),
            resource_id: intent.resource_id.clone(),
            operation_id: intent.operation_id.clone(), action: intent.action,
            state: FleetHostResultState::Verified as i32,
            desired_sha256: intent.desired_sha256.clone(),
            release_set_sha256: intent.release_set_sha256.clone(),
            observed_at_unix: 123, physical_readback: true,
            next_action: "NONE".into(), ..Default::default()
        };
        let receipt = sign_native_receipt(&intent, &result, &host, pkcs8.as_ref()).unwrap();
        assert_eq!(verify_native_receipt(&intent, &receipt, &host), Ok(result));
        assert!(decode_native_receipt(&receipt.encode_to_vec()).is_ok());
        let mut changed = receipt.clone();
        changed.result.as_mut().unwrap().observed_at_unix += 1;
        assert_eq!(verify_native_receipt(&intent, &changed, &host),
            Err("HOST_NATIVE_RECEIPT_SIGNATURE_INVALID"));
        let mut foreign = intent.clone();
        foreign.resource_id = "sing-box".into();
        assert!(verify_native_receipt(&foreign, &receipt, &host).is_err());
        foreign = intent.clone();
        foreign.release_set_sha256 = vec![9; 32];
        assert!(verify_native_receipt(&foreign, &receipt, &host).is_err());
        let mut unknown = host.clone();
        unknown.native_receipt_public_key.clear();
        assert!(check_native_receipt_key(&unknown, pkcs8.as_ref()).is_err());
        assert!(verify_native_receipt(&intent, &receipt, &unknown).is_err());
        let mut different = host.clone();
        different.native_receipt_public_key = vec![8; 32];
        assert!(check_native_receipt_key(&different, pkcs8.as_ref()).is_err());
    }
}
