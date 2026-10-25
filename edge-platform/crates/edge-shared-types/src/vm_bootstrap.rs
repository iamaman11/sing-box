//! One typed, encrypted first-use Access identity envelope.
//! The existing GitHub runner transports bytes only. The recipient secret
//! exists exclusively under the VM native Root Agent's protected trust.
//! This is NOT authorization to install a credential or create a VM: the
//! native owner additionally verifies the pinned Git receipt and Worker GET.
use crate::{FleetVmBootstrapAccessEnvelope, FleetVmBootstrapKeyProof};
use prost::Message;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest::{SHA256, digest};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use x25519_dalek::{PublicKey, StaticSecret};

const PURPOSE: &[u8] = b"sing-box/vm-first-use-access/v1";
const MAX_IDENTITY_BYTES: usize = 1024;

pub fn fresh_recipient() -> Result<([u8; 32], [u8; 32]), &'static str> {
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "BOOTSTRAP_RANDOM_FAILED")?;
    let secret = StaticSecret::from(random);
    Ok((secret.to_bytes(), PublicKey::from(&secret).to_bytes()))
}

fn unsigned_proof_bytes(proof: &FleetVmBootstrapKeyProof) -> Vec<u8> {
    let mut unsigned = proof.clone();
    unsigned.native_signature.clear();
    unsigned.encode_to_vec()
}

pub fn sign_root_proof(
    machine_id: &str,
    release_digest: &[u8],
    recipient_public_key: &[u8; 32],
    root_receipt_pkcs8: &[u8],
) -> Result<FleetVmBootstrapKeyProof, &'static str> {
    let key = Ed25519KeyPair::from_pkcs8(root_receipt_pkcs8)
        .map_err(|_| "BOOTSTRAP_RECEIPT_KEY_INVALID")?;
    let mut proof = FleetVmBootstrapKeyProof {
        schema_version: 1,
        machine_id: machine_id.to_owned(),
        release_set_sha256: release_digest.to_vec(),
        native_receipt_public_key: key.public_key().as_ref().to_vec(),
        recipient_x25519_public_key: recipient_public_key.to_vec(),
        native_signature: Vec::new(),
    };
    validate_fields(&proof)?;
    proof.native_signature = key.sign(&unsigned_proof_bytes(&proof)).as_ref().to_vec();
    Ok(proof)
}

fn validate_fields(p: &FleetVmBootstrapKeyProof) -> Result<(), &'static str> {
    if p.schema_version != 1
        || p.machine_id.is_empty()
        || p.machine_id.len() > 63
        || !p
            .machine_id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || p.machine_id.starts_with('-')
        || p.machine_id.ends_with('-')
        || p.release_set_sha256.len() != 32
        || p.native_receipt_public_key.len() != 32
        || p.recipient_x25519_public_key.len() != 32
        || p.release_set_sha256.iter().all(|x| *x == 0)
        || p.native_receipt_public_key.iter().all(|x| *x == 0)
        || p.recipient_x25519_public_key.iter().all(|x| *x == 0)
    {
        return Err("BOOTSTRAP_RECIPIENT_SCOPE_INVALID");
    }
    Ok(())
}

pub fn verify_root_proof(proof: &FleetVmBootstrapKeyProof) -> Result<(), &'static str> {
    validate_fields(proof)?;
    if proof.native_signature.len() != 64 {
        return Err("BOOTSTRAP_ROOT_SIGNATURE_INVALID");
    }
    UnparsedPublicKey::new(&ED25519, &proof.native_receipt_public_key)
        .verify(&unsigned_proof_bytes(proof), &proof.native_signature)
        .map_err(|_| "BOOTSTRAP_ROOT_SIGNATURE_INVALID")
}

fn derived_key(
    shared: &[u8; 32],
    proof: &FleetVmBootstrapKeyProof,
) -> Result<LessSafeKey, &'static str> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err("BOOTSTRAP_DH_INVALID");
    }
    let salt_value = digest(&SHA256, &proof.encode_to_vec());
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_value.as_ref());
    let info = [PURPOSE];
    let mut bytes = [0u8; 32];
    salt.extract(shared)
        .expand(&info, &aead::CHACHA20_POLY1305)
        .map_err(|_| "BOOTSTRAP_KDF_INVALID")?
        .fill(&mut bytes)
        .map_err(|_| "BOOTSTRAP_KDF_INVALID")?;
    let key =
        UnboundKey::new(&aead::CHACHA20_POLY1305, &bytes).map_err(|_| "BOOTSTRAP_AEAD_INVALID")?;
    Ok(LessSafeKey::new(key))
}

pub fn seal_for_native_root(
    proof: &FleetVmBootstrapKeyProof,
    secret_identity: &[u8],
) -> Result<FleetVmBootstrapAccessEnvelope, &'static str> {
    verify_root_proof(proof)?;
    if secret_identity.is_empty() || secret_identity.len() > MAX_IDENTITY_BYTES {
        return Err("BOOTSTRAP_IDENTITY_LENGTH_INVALID");
    }
    let (sender_private, sender_public) = fresh_recipient()?;
    let recipient_public: [u8; 32] = proof
        .recipient_x25519_public_key
        .as_slice()
        .try_into()
        .map_err(|_| "BOOTSTRAP_RECIPIENT_SCOPE_INVALID")?;
    let shared = StaticSecret::from(sender_private)
        .diffie_hellman(&PublicKey::from(recipient_public))
        .to_bytes();
    let key = derived_key(&shared, proof)?;
    let mut nonce = [0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "BOOTSTRAP_RANDOM_FAILED")?;
    let mut ciphertext = secret_identity.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(proof.encode_to_vec()),
        &mut ciphertext,
    )
    .map_err(|_| "BOOTSTRAP_ENCRYPT_FAILED")?;
    Ok(FleetVmBootstrapAccessEnvelope {
        schema_version: 1,
        recipient: Some(proof.clone()),
        sender_x25519_public_key: sender_public.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

pub fn open_for_native_root(
    envelope: &FleetVmBootstrapAccessEnvelope,
    recipient_secret: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    if envelope.schema_version != 1
        || envelope.sender_x25519_public_key.len() != 32
        || envelope.nonce.len() != 12
        || envelope.ciphertext.len() < 17
        || envelope.ciphertext.len() > MAX_IDENTITY_BYTES + 16
    {
        return Err("BOOTSTRAP_ENVELOPE_INVALID");
    }
    let proof = envelope
        .recipient
        .as_ref()
        .ok_or("BOOTSTRAP_RECIPIENT_MISSING")?;
    verify_root_proof(proof)?;
    let local_pub = PublicKey::from(&StaticSecret::from(*recipient_secret)).to_bytes();
    if proof.recipient_x25519_public_key != local_pub {
        return Err("BOOTSTRAP_RECIPIENT_MISMATCH");
    }
    let sender_pub: [u8; 32] = envelope
        .sender_x25519_public_key
        .as_slice()
        .try_into()
        .map_err(|_| "BOOTSTRAP_ENVELOPE_INVALID")?;
    let shared = StaticSecret::from(*recipient_secret)
        .diffie_hellman(&PublicKey::from(sender_pub))
        .to_bytes();
    let key = derived_key(&shared, proof)?;
    let nonce_bytes: [u8; 12] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| "BOOTSTRAP_ENVELOPE_INVALID")?;
    let mut ciphertext = envelope.ciphertext.clone();
    let clear = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(proof.encode_to_vec()),
            &mut ciphertext,
        )
        .map_err(|_| "BOOTSTRAP_AUTHENTICATION_FAILED")?;
    Ok(clear.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_identity_only_opens_on_exact_signed_native_root() {
        let (private, public) = fresh_recipient().unwrap();
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let proof =
            sign_root_proof("application-acceptance-5", &[7; 32], &public, key.as_ref()).unwrap();
        verify_root_proof(&proof).unwrap();
        let sealed = seal_for_native_root(
            &proof,
            b"CF_ACCESS_CLIENT_ID=x\nCF_ACCESS_CLIENT_SECRET=y\n",
        )
        .unwrap();
        assert_ne!(
            sealed.ciphertext,
            b"CF_ACCESS_CLIENT_ID=x\nCF_ACCESS_CLIENT_SECRET=y\n"
        );
        assert_eq!(
            open_for_native_root(&sealed, &private).unwrap(),
            b"CF_ACCESS_CLIENT_ID=x\nCF_ACCESS_CLIENT_SECRET=y\n"
        );
        let (other, _) = fresh_recipient().unwrap();
        assert_eq!(
            open_for_native_root(&sealed, &other).unwrap_err(),
            "BOOTSTRAP_RECIPIENT_MISMATCH"
        );
        let mut altered = sealed.clone();
        altered.ciphertext[0] ^= 1;
        assert!(open_for_native_root(&altered, &private).is_err());
        altered = sealed.clone();
        altered.recipient.as_mut().unwrap().machine_id.push('x');
        assert_eq!(
            open_for_native_root(&altered, &private).unwrap_err(),
            "BOOTSTRAP_ROOT_SIGNATURE_INVALID"
        );
        altered = sealed;
        altered.nonce[0] ^= 1;
        assert_eq!(
            open_for_native_root(&altered, &private).unwrap_err(),
            "BOOTSTRAP_AUTHENTICATION_FAILED"
        );
    }
}
