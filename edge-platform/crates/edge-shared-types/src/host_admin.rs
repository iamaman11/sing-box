//! Byte-exact native root administrative contract. No functional allowlist:
//! any executable, interpreter, arguments, cwd, environment and stdin are
//! permitted after independent GitHub actor / Worker Ed25519 authorization.
use crate::{
    FleetNativeAdminAuthorization as Authorization, FleetNativeAdminRequest as Request,
    FleetNativeAdminResult as ResultReceipt,
};
use prost::Message;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};

pub const MAX_BYTES: usize = 32768;
const DOMAIN: &[u8] = b"sing-box/native-admin-authorization/v1:";
const RECEIPT_DOMAIN: &[u8] = b"sing-box/native-admin-receipt/v1:";

pub fn operation_id(request: &Request) -> String {
    format!("issue1-comment-{}", request.source_comment_id)
}
pub fn validate(request: &Request) -> Result<(), &'static str> {
    if request.schema_version != 1
        || request.machine_id.is_empty()
        || request.machine_id.len() > 64
        || !request
            .machine_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || request.source_comment_id == 0
        || request.release_set_sha256.len() != 32
        || request.comment_sha256.len() != 32
        || request.requested_at_unix == 0
        || request.argv.is_empty()
        || request.argv.len() > 128
        || request
            .argv
            .iter()
            .any(|arg| arg.is_empty() || arg.len() > 8192 || arg.contains('\0'))
        || request.working_directory.len() > 2048
        || request.working_directory.contains('\0')
        || (!request.working_directory.is_empty() && !request.working_directory.starts_with('/'))
        || request.environment.len() > 128
        || request.environment.iter().any(|item| {
            item.len() > 8192
                || item.contains('\0')
                || item.split_once('=').is_none_or(|(key, _)| {
                    key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
        })
        || request.timeout_seconds == 0
        || request.timeout_seconds > 3600
        || request.encoded_len() > MAX_BYTES
    {
        return Err("HOST_ADMIN_REQUEST_INVALID");
    }
    Ok(())
}
pub fn decode(bytes: &[u8]) -> Result<Request, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("HOST_ADMIN_SIZE_INVALID");
    }
    let request = Request::decode(bytes).map_err(|_| "HOST_ADMIN_PROTOBUF_INVALID")?;
    if request.encode_to_vec() != bytes {
        return Err("HOST_ADMIN_PROTOBUF_NONCANONICAL");
    }
    validate(&request)?;
    Ok(request)
}
pub fn authorization_payload(request: &Request, auth: &Authorization) -> Vec<u8> {
    let bytes = request.encode_to_vec();
    let mut payload = DOMAIN.to_vec();
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
    worker_public_key: &[u8],
    now: u64,
) -> Result<(), &'static str> {
    validate(request)?;
    if auth.schema_version != 1
        || auth.operation_id != operation_id(request)
        || auth.key_id.is_empty()
        || auth.key_id.len() > 128
        || !auth
            .key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        || worker_public_key.len() != 32
        || auth.ed25519_signature.len() != 64
        || auth.expires_at_unix <= auth.issued_at_unix
        || auth.expires_at_unix - auth.issued_at_unix > 180
        || now.saturating_add(60) < auth.issued_at_unix
        || now > auth.expires_at_unix
    {
        return Err("HOST_ADMIN_AUTHORIZATION_EXPIRED_OR_INVALID");
    }
    UnparsedPublicKey::new(&ED25519, worker_public_key)
        .verify(
            &authorization_payload(request, auth),
            &auth.ed25519_signature,
        )
        .map_err(|_| "HOST_ADMIN_SIGNATURE_REJECTED")
}
fn preview_valid(request: &Request, result: &ResultReceipt) -> bool {
    let max = 64 * 1024;
    let a = result.stdout_preview.len();
    let b = result.stderr_preview.len();
    a <= max
        && b <= max
        && result.stdout_capture_path.ends_with(".stdout.bin")
        && result.stderr_capture_path.ends_with(".stderr.bin")
        && result.stdout_capture_path.len() <= 512
        && result.stderr_capture_path.len() <= 512
        && result.stdout_capture_bytes == result.stdout_total_bytes.min((16 * 1024 * 1024) as u64)
        && result.stderr_capture_bytes == result.stderr_total_bytes.min((16 * 1024 * 1024) as u64)
        && result.stdout_capture_complete
            == (result.stdout_capture_bytes == result.stdout_total_bytes)
        && result.stderr_capture_complete
            == (result.stderr_capture_bytes == result.stderr_total_bytes)
        && (request.publish_output || (a == 0 && b == 0))
        && a as u64 <= result.stdout_total_bytes
        && b as u64 <= result.stderr_total_bytes
        && result.stdout_truncated == (result.stdout_total_bytes > max as u64)
        && result.stderr_truncated == (result.stderr_total_bytes > max as u64)
        && (!request.publish_output
            || (a as u64 == result.stdout_total_bytes.min(max as u64)
                && b as u64 == result.stderr_total_bytes.min(max as u64)))
}
fn receipt_payload(request: &Request, result: &ResultReceipt) -> Vec<u8> {
    let mut unsigned = result.clone();
    unsigned.root_signature.clear();
    let req = request.encode_to_vec();
    let res = unsigned.encode_to_vec();
    let mut payload = RECEIPT_DOMAIN.to_vec();
    payload.extend_from_slice(&(req.len() as u32).to_be_bytes());
    payload.extend_from_slice(&req);
    payload.extend_from_slice(&(res.len() as u32).to_be_bytes());
    payload.extend_from_slice(&res);
    payload
}
pub fn sign_receipt(
    request: &Request,
    receipt: &mut ResultReceipt,
    owner_pkcs8: &[u8],
) -> Result<(), &'static str> {
    let digest = ring::digest::digest(&ring::digest::SHA256, &request.encode_to_vec());
    if receipt.schema_version != 1
        || receipt.machine_id != request.machine_id
        || receipt.operation_id != operation_id(request)
        || receipt.request_sha256 != digest.as_ref()
        || receipt.stdout_sha256.len() != 32
        || receipt.stderr_sha256.len() != 32
        || !preview_valid(request, receipt)
    {
        return Err("HOST_ADMIN_RECEIPT_IDENTITY_INVALID");
    }
    let key =
        Ed25519KeyPair::from_pkcs8(owner_pkcs8).map_err(|_| "HOST_ADMIN_RECEIPT_SIGNER_INVALID")?;
    receipt.root_signature = key
        .sign(&receipt_payload(request, receipt))
        .as_ref()
        .to_vec();
    Ok(())
}
pub fn verify_receipt(
    request: &Request,
    receipt: &ResultReceipt,
    pinned_owner_public_key: &[u8],
) -> Result<(), &'static str> {
    let digest = ring::digest::digest(&ring::digest::SHA256, &request.encode_to_vec());
    if receipt.schema_version != 1
        || receipt.machine_id != request.machine_id
        || receipt.operation_id != operation_id(request)
        || receipt.request_sha256 != digest.as_ref()
        || pinned_owner_public_key.len() != 32
        || receipt.root_signature.len() != 64
        || !preview_valid(request, receipt)
    {
        return Err("HOST_ADMIN_RECEIPT_INVALID");
    }
    UnparsedPublicKey::new(&ED25519, pinned_owner_public_key)
        .verify(&receipt_payload(request, receipt), &receipt.root_signature)
        .map_err(|_| "HOST_ADMIN_RECEIPT_SIGNATURE_REJECTED")
}
#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::KeyPair};
    fn request() -> Request {
        Request {
            schema_version: 1,
            machine_id: "new-acceptance".into(),
            source_comment_id: 42,
            argv: vec![
                "/usr/bin/env".into(),
                "sh".into(),
                "-c".into(),
                "echo ok".into(),
            ],
            release_set_sha256: vec![1; 32],
            requested_at_unix: 100,
            comment_sha256: vec![2; 32],
            working_directory: "/".into(),
            environment: vec!["LANG=C".into()],
            stdin_bytes: Vec::new(),
            timeout_seconds: 60,
            publish_output: false,
        }
    }
    #[test]
    fn arbitrary_program_is_allowed_but_modified_payload_is_rejected() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let req = request();
        assert!(validate(&req).is_ok());
        let mut auth = Authorization {
            schema_version: 1,
            key_id: "worker".into(),
            operation_id: operation_id(&req),
            issued_at_unix: 100,
            expires_at_unix: 200,
            ed25519_signature: Vec::new(),
        };
        auth.ed25519_signature = signer
            .sign(&authorization_payload(&req, &auth))
            .as_ref()
            .to_vec();
        assert!(verify_authorization(&req, &auth, signer.public_key().as_ref(), 150).is_ok());
        let mut changed = req.clone();
        changed.argv[3] = "different".into();
        assert!(verify_authorization(&changed, &auth, signer.public_key().as_ref(), 150).is_err());
        assert!(verify_authorization(&req, &auth, signer.public_key().as_ref(), 201).is_err());
        changed = req.clone();
        changed.release_set_sha256[0] = 5;
        assert!(verify_authorization(&changed, &auth, signer.public_key().as_ref(), 150).is_err());
    }
}
