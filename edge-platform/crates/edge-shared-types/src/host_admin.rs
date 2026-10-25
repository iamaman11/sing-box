//! Canonical, exact, short-lived root-administration authorization.
//! This module never executes a command. Untrusted runner inputs confer no
//! privilege; the installed owner must verify the independent Worker signature.
use crate::{
    FleetHostAdministrativeAuthorization as Authorization,
    FleetHostAdministrativeReceipt as Receipt,
    FleetHostAdministrativeRequest as Request,
};
use prost::Message;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

pub const MAX_REQUEST_BYTES: usize = 8192;
const AUTH_DOMAIN: &[u8] = b"sing-box/native-admin-authorization/v1:";
const RECEIPT_DOMAIN: &[u8] = b"sing-box/native-admin-receipt/v1:";

pub fn validate(request: &Request) -> Result<(), &'static str> {
    if request.schema_version != 1
        || request.machine_id.is_empty()
        || request.machine_id.len() > 64
        || !request.machine_id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        || request.source_comment_id == 0
        || request.requested_at_unix == 0
        || request.comment_sha256.len() != 32
        || request.release_set_sha256.len() != 32
        || request.argv.is_empty()
        || request.argv.len() > 64
        || !request.argv[0].starts_with('/')
        || request.argv[0].contains("..")
        || request.argv.iter().any(|arg| arg.is_empty() || arg.len() > 4096 || arg.bytes().any(|c| c == 0))
        || request.encoded_len() > MAX_REQUEST_BYTES
    {
        return Err("HOST_ADMIN_REQUEST_INVALID");
    }
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<Request, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err("HOST_ADMIN_REQUEST_SIZE_INVALID");
    }
    let request = Request::decode(bytes).map_err(|_| "HOST_ADMIN_REQUEST_PROTOBUF_INVALID")?;
    if request.encode_to_vec() != bytes {
        return Err("HOST_ADMIN_REQUEST_NONCANONICAL");
    }
    validate(&request)?;
    Ok(request)
}

pub fn operation_id(request: &Request) -> String {
    format!("issue1-comment-{}", request.source_comment_id)
}

pub fn auth_payload(request: &Request, auth: &Authorization) -> Vec<u8> {
    let bytes = request.encode_to_vec();
    let mut payload = AUTH_DOMAIN.to_vec();
    payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&bytes);
    payload.extend_from_slice(&(auth.key_id.len() as u32).to_be_bytes());
    payload.extend_from_slice(auth.key_id.as_bytes());
    let id = operation_id(request);
    payload.extend_from_slice(&(id.len() as u32).to_be_bytes());
    payload.extend_from_slice(id.as_bytes());
    payload.extend_from_slice(&auth.issued_at_unix.to_be_bytes());
    payload.extend_from_slice(&auth.expires_at_unix.to_be_bytes());
    payload
}

pub fn verify_authorization(
    request: &Request,
    auth: &Authorization,
    pinned_worker_public_key: &[u8],
    now: u64,
) -> Result<(), &'static str> {
    validate(request)?;
    if auth.schema_version != 1
        || auth.operation_id != operation_id(request)
        || auth.key_id.is_empty()
        || auth.key_id.len() > 128
        || !auth.key_id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':'))
        || pinned_worker_public_key.len() != 32
        || auth.ed25519_signature.len() != 64
        || auth.expires_at_unix <= auth.issued_at_unix
        || auth.expires_at_unix - auth.issued_at_unix > 180
        || now.saturating_add(60) < auth.issued_at_unix
        || now > auth.expires_at_unix
    {
        return Err("HOST_ADMIN_AUTHORIZATION_INVALID_OR_EXPIRED");
    }
    UnparsedPublicKey::new(&ED25519, pinned_worker_public_key)
        .verify(&auth_payload(request, auth), &auth.ed25519_signature)
        .map_err(|_| "HOST_ADMIN_AUTHORIZATION_SIGNATURE_INVALID")
}

fn receipt_payload(request: &Request, receipt: &Receipt) -> Vec<u8> {
    let mut unsigned = receipt.clone();
    unsigned.root_signature.clear();
    let request_bytes = request.encode_to_vec();
    let result_bytes = unsigned.encode_to_vec();
    let mut payload = RECEIPT_DOMAIN.to_vec();
    payload.extend_from_slice(&(request_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&request_bytes);
    payload.extend_from_slice(&(result_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&result_bytes);
    payload
}

fn check_receipt_identity(request: &Request, receipt: &Receipt) -> Result<(), &'static str> {
    if receipt.schema_version != 1
        || receipt.machine_id != request.machine_id
        || receipt.operation_id != operation_id(request)
        || receipt.request_sha256 != ring::digest::digest(
            &ring::digest::SHA256, &request.encode_to_vec()).as_ref()
        || receipt.stdout_sha256.len() != 32
        || receipt.stderr_sha256.len() != 32
        || receipt.observed_at_unix < request.requested_at_unix
    {
        return Err("HOST_ADMIN_RECEIPT_IDENTITY_INVALID");
    }
    Ok(())
}

pub fn sign_receipt(
    request: &Request,
    receipt: &mut Receipt,
    root_pkcs8: &[u8],
) -> Result<(), &'static str> {
    validate(request)?;
    check_receipt_identity(request, receipt)?;
    let pair = Ed25519KeyPair::from_pkcs8(root_pkcs8)
        .map_err(|_| "HOST_ADMIN_RECEIPT_SIGNER_INVALID")?;
    receipt.root_signature = pair.sign(&receipt_payload(request, receipt)).as_ref().to_vec();
    Ok(())
}

pub fn verify_receipt(
    request: &Request,
    receipt: &Receipt,
    pinned_root_public_key: &[u8],
) -> Result<(), &'static str> {
    validate(request)?;
    check_receipt_identity(request, receipt)?;
    if pinned_root_public_key.len() != 32 || receipt.root_signature.len() != 64 {
        return Err("HOST_ADMIN_RECEIPT_UNPROVEN");
    }
    UnparsedPublicKey::new(&ED25519, pinned_root_public_key)
        .verify(&receipt_payload(request, receipt), &receipt.root_signature)
        .map_err(|_| "HOST_ADMIN_RECEIPT_SIGNATURE_INVALID")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    fn sample() -> Request {
        Request {
            schema_version: 1, machine_id: "application-acceptance-4".into(),
            source_comment_id: 456, argv: vec!["/usr/bin/true".into()],
            release_set_sha256: vec![1; 32], requested_at_unix: 100,
            comment_sha256: vec![2; 32],
        }
    }
    #[test]
    fn signature_exactly_binds_program_args_comment_and_release() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let request = sample();
        let mut auth = Authorization { schema_version: 1, key_id: "worker".into(),
            operation_id: operation_id(&request), issued_at_unix: 100, expires_at_unix: 200,
            ed25519_signature: Vec::new() };
        auth.ed25519_signature = signer.sign(&auth_payload(&request, &auth)).as_ref().to_vec();
        assert_eq!(verify_authorization(&request, &auth, signer.public_key().as_ref(), 150), Ok(()));
        assert!(verify_authorization(&request, &auth, signer.public_key().as_ref(), 201).is_err());
        let mut changed = request.clone();
        changed.argv.push("--unexpected".into());
        assert!(verify_authorization(&changed, &auth, signer.public_key().as_ref(), 150).is_err());
        changed = request.clone();
        changed.comment_sha256 = vec![3; 32];
        assert!(verify_authorization(&changed, &auth, signer.public_key().as_ref(), 150).is_err());
        changed = request.clone();
        changed.release_set_sha256 = vec![4; 32];
        assert!(verify_authorization(&changed, &auth, signer.public_key().as_ref(), 150).is_err());
    }
    #[test]
    fn signed_result_is_bound_to_exact_request() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let request = sample();
        let mut receipt = Receipt {
            schema_version: 1, machine_id: request.machine_id.clone(),
            operation_id: operation_id(&request),
            request_sha256: ring::digest::digest(&ring::digest::SHA256, &request.encode_to_vec()).as_ref().to_vec(),
            observed_at_unix: 200, exit_code: 0, stdout_sha256: vec![5; 32],
            stderr_sha256: vec![6; 32], terminal_verified: true, root_signature: Vec::new(),
        };
        sign_receipt(&request, &mut receipt, pkcs8.as_ref()).unwrap();
        assert_eq!(verify_receipt(&request, &receipt, signer.public_key().as_ref()), Ok(()));
        receipt.exit_code = 1;
        assert!(verify_receipt(&request, &receipt, signer.public_key().as_ref()).is_err());
    }
}
