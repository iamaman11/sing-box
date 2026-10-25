//! One authenticated and single-use administrative request. GitHub is only
//! transport; these typed bytes have NO native authority until Worker signature.
use crate::{
    FleetNativeAdministrativeAuthorization, FleetNativeAdministrativeRequest,
    FleetNativeAdministrativeResult,
};
use prost::Message;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

pub const MAX_REQUEST_BYTES: usize = 8192;
const DOMAIN: &[u8] = b"sing-box/native-administrative-authorization/v1:";
const RESULT_DOMAIN: &[u8] = b"sing-box/native-administrative-result/v1:";

pub fn validate(request: &FleetNativeAdministrativeRequest) -> Result<(), &'static str> {
    if request.schema_version != 1
        || request.machine_id.is_empty()
        || request.machine_id.len() > 64
        || !request.machine_id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        || request.source_comment_id == 0
        || request.operation_id != format!("issue1-comment-{}", request.source_comment_id)
        || request.argv.is_empty()
        || request.argv.len() > 64
        || !request.argv[0].starts_with('/')
        || request.argv[0].contains("..")
        || request.argv.iter().any(|arg| arg.is_empty()
            || arg.len() > 4096
            || arg.as_bytes().contains(&0))
        || request.encode_to_vec().len() > MAX_REQUEST_BYTES
    {
        return Err("HOST_ADMIN_REQUEST_INVALID");
    }
    Ok(())
}

pub fn decode(raw: &[u8]) -> Result<FleetNativeAdministrativeRequest, &'static str> {
    if raw.is_empty() || raw.len() > MAX_REQUEST_BYTES {
        return Err("HOST_ADMIN_SIZE_INVALID");
    }
    let request = FleetNativeAdministrativeRequest::decode(raw)
        .map_err(|_| "HOST_ADMIN_PROTO_INVALID")?;
    if request.encode_to_vec() != raw {
        return Err("HOST_ADMIN_PROTO_NONCANONICAL");
    }
    validate(&request)?;
    Ok(request)
}

pub fn authorization_payload(
    request: &FleetNativeAdministrativeRequest,
    auth: &FleetNativeAdministrativeAuthorization,
) -> Vec<u8> {
    let bytes = request.encode_to_vec();
    let mut out = Vec::with_capacity(bytes.len() + 256);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    out.extend_from_slice(&(auth.key_id.len() as u32).to_be_bytes());
    out.extend_from_slice(auth.key_id.as_bytes());
    out.extend_from_slice(&(auth.operation_id.len() as u32).to_be_bytes());
    out.extend_from_slice(auth.operation_id.as_bytes());
    out.extend_from_slice(&auth.issued_at_unix.to_be_bytes());
    out.extend_from_slice(&auth.expires_at_unix.to_be_bytes());
    out
}

pub fn verify(
    request: &FleetNativeAdministrativeRequest,
    auth: &FleetNativeAdministrativeAuthorization,
    public_key: &[u8],
    now: u64,
) -> Result<(), &'static str> {
    validate(request)?;
    if auth.schema_version != 1
        || auth.key_id.is_empty()
        || auth.key_id.len() > 128
        || !auth.key_id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':'))
        || auth.operation_id != request.operation_id
        || public_key.len() != 32
        || auth.ed25519_signature.len() != 64
        || auth.expires_at_unix <= auth.issued_at_unix
        || auth.expires_at_unix - auth.issued_at_unix > 180
        || now.saturating_add(60) < auth.issued_at_unix
        || now > auth.expires_at_unix
    {
        return Err("HOST_ADMIN_AUTHORIZATION_INVALID_OR_EXPIRED");
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&authorization_payload(request, auth), &auth.ed25519_signature)
        .map_err(|_| "HOST_ADMIN_AUTHORIZATION_SIGNATURE_INVALID")
}

pub fn sign_result(
    request: &FleetNativeAdministrativeRequest,
    result: &mut FleetNativeAdministrativeResult,
    root_pkcs8: &[u8],
) -> Result<(), &'static str> {
    if result.schema_version != 1
        || result.machine_id != request.machine_id
        || result.operation_id != request.operation_id
        || result.request_sha256 != ring::digest::digest(&ring::digest::SHA256, &request.encode_to_vec()).as_ref()
    {
        return Err("HOST_ADMIN_RESULT_IDENTITY_INVALID");
    }
    let pair = Ed25519KeyPair::from_pkcs8(root_pkcs8)
        .map_err(|_| "HOST_ADMIN_ROOT_SIGNER_INVALID")?;
    result.ed25519_signature.clear();
    let payload = result.encode_to_vec();
    let mut signed = RESULT_DOMAIN.to_vec();
    signed.extend_from_slice(&(request.encode_to_vec().len() as u32).to_be_bytes());
    signed.extend_from_slice(&request.encode_to_vec());
    signed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    signed.extend_from_slice(&payload);
    result.ed25519_signature = pair.sign(&signed).as_ref().to_vec();
    Ok(())
}

pub fn verify_result(
    request: &FleetNativeAdministrativeRequest,
    result: &FleetNativeAdministrativeResult,
    root_public_key: &[u8],
) -> Result<(), &'static str> {
    if result.schema_version != 1
        || result.machine_id != request.machine_id
        || result.operation_id != request.operation_id
        || root_public_key.len() != 32
        || result.ed25519_signature.len() != 64
    {
        return Err("HOST_ADMIN_RESULT_UNPROVEN");
    }
    let mut unsigned = result.clone();
    unsigned.ed25519_signature.clear();
    let payload = unsigned.encode_to_vec();
    let mut signed = RESULT_DOMAIN.to_vec();
    signed.extend_from_slice(&(request.encode_to_vec().len() as u32).to_be_bytes());
    signed.extend_from_slice(&request.encode_to_vec());
    signed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    signed.extend_from_slice(&payload);
    UnparsedPublicKey::new(&ED25519, root_public_key)
        .verify(&signed, &result.ed25519_signature)
        .map_err(|_| "HOST_ADMIN_RESULT_SIGNATURE_INVALID")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::KeyPair};

    fn request() -> FleetNativeAdministrativeRequest {
        FleetNativeAdministrativeRequest {
            schema_version: 1,
            machine_id: "vm-1".to_owned(),
            operation_id: "issue1-comment-42".to_owned(),
            source_comment_id: 42,
            argv: vec!["/usr/bin/true".to_owned()],
        }
    }
    #[test]
    fn one_signed_exact_request_cannot_be_retargeted_or_replayed_after_expiry() {
        let pk = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pk.as_ref()).unwrap();
        let request = request();
        let mut auth = FleetNativeAdministrativeAuthorization {
            schema_version: 1, key_id: "key-1".into(),
            operation_id: request.operation_id.clone(),
            issued_at_unix: 100, expires_at_unix: 200,
            ed25519_signature: Vec::new(),
        };
        auth.ed25519_signature = pair.sign(&authorization_payload(&request, &auth)).as_ref().to_vec();
        assert_eq!(verify(&request, &auth, pair.public_key().as_ref(), 150), Ok(()));
        assert!(verify(&request, &auth, pair.public_key().as_ref(), 201).is_err());
        let mut changed = request.clone();
        changed.argv.push("--help".into());
        assert!(verify(&changed, &auth, pair.public_key().as_ref(), 150).is_err());
        changed = request.clone();
        changed.machine_id = "vm-2".into();
        assert!(verify(&changed, &auth, pair.public_key().as_ref(), 150).is_err());
    }
}
