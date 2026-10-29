//! One signed challenge-response from the actually serving Cloudflare Worker.
//! This is identity evidence, never an authority to perform a host operation.
//! Only the protected Git registry may provide the accepted Ed25519 public key.
use crate::FleetHostSignerAttestation;
use prost::Message;
use ring::signature::{ED25519, UnparsedPublicKey};

const DOMAIN: &[u8] = b"sing-box/host-signer-identity/v1:";
pub const MAX_ATTESTATION_BYTES: usize = 512;

fn message(proof: &FleetHostSignerAttestation) -> Vec<u8> {
    let id = proof.key_id.as_bytes();
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 32 + 4 + id.len() + 8);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&proof.challenge);
    out.extend_from_slice(&proof.public_key);
    out.extend_from_slice(&(id.len() as u32).to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&proof.issued_at_unix.to_be_bytes());
    out
}

pub fn verify_active_worker_identity(
    raw: &[u8],
    challenge: &[u8; 32],
    git_public_key: &[u8],
    now: u64,
) -> Result<(), &'static str> {
    if raw.is_empty() || raw.len() > MAX_ATTESTATION_BYTES {
        return Err("HOST_SIGNER_ATTESTATION_SIZE_INVALID");
    }
    let proof = FleetHostSignerAttestation::decode(raw)
        .map_err(|_| "HOST_SIGNER_ATTESTATION_PROTO_INVALID")?;
    if proof.encode_to_vec() != raw
        || proof.schema_version != 1
        || proof.challenge.as_slice() != challenge
        || proof.public_key.len() != 32
        || proof.public_key.iter().all(|v| *v == 0)
        || git_public_key.len() != 32
        || git_public_key.iter().all(|v| *v == 0)
        || proof.public_key != git_public_key
        || proof.key_id.is_empty()
        || proof.key_id.len() > 128
        || !proof
            .key_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
        || proof.issued_at_unix == 0
        || proof.issued_at_unix > now.saturating_add(30)
        || now.saturating_sub(proof.issued_at_unix) > 120
        || proof.ed25519_signature.len() != 64
    {
        return Err("HOST_SIGNER_ATTESTATION_IDENTITY_OR_FRESHNESS_INVALID");
    }
    UnparsedPublicKey::new(&ED25519, git_public_key)
        .verify(&message(&proof), &proof.ed25519_signature)
        .map_err(|_| "HOST_SIGNER_ATTESTATION_SIGNATURE_INVALID")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    #[test]
    fn exact_active_worker_identity_only_and_no_replay() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let nonce = [0x5c; 32];
        let mut proof = FleetHostSignerAttestation {
            schema_version: 1,
            challenge: nonce.to_vec(),
            public_key: key.public_key().as_ref().to_vec(),
            key_id: "vm-host-identity".into(),
            issued_at_unix: 1000,
            ..Default::default()
        };
        proof.ed25519_signature = key.sign(&message(&proof)).as_ref().to_vec();
        let raw = proof.encode_to_vec();
        assert_eq!(
            verify_active_worker_identity(&raw, &nonce, key.public_key().as_ref(), 1020),
            Ok(())
        );
        assert!(
            verify_active_worker_identity(&raw, &[0x5d; 32], key.public_key().as_ref(), 1020)
                .is_err()
        );
        assert!(verify_active_worker_identity(&raw, &nonce, &[0x33; 32], 1020).is_err());
        assert!(
            verify_active_worker_identity(&raw, &nonce, key.public_key().as_ref(), 1201).is_err()
        );
        assert!(
            verify_active_worker_identity(&raw, &nonce, key.public_key().as_ref(), 900).is_err()
        );
        assert!(verify_active_worker_identity(&raw, &nonce, &[], 1020).is_err());
        proof.ed25519_signature[0] ^= 0x01;
        assert_eq!(
            verify_active_worker_identity(
                &proof.encode_to_vec(),
                &nonce,
                key.public_key().as_ref(),
                1020
            ),
            Err("HOST_SIGNER_ATTESTATION_SIGNATURE_INVALID")
        );
        let mut oversized = raw.clone();
        oversized.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(
            verify_active_worker_identity(&oversized, &nonce, key.public_key().as_ref(), 1020)
                .is_err()
        );
    }
}
