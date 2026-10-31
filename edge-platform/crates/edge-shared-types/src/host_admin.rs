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
        || (!request.working_directory.is_empty()
            && !request.working_directory.starts_with('/')
            && !windows_absolute_path(&request.working_directory))
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

/// Address validation only; never a functional executable allowlist. The
/// privileged owner supplies kind from independently verified Git, not wire.
pub fn windows_absolute_path(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && b[2] == b'\\'
        && !path.contains(['\0', '/', '*', '?', '"'])
        && !path
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | '|'))
        && !path[2..].contains(':')
        && (path.len() == 3
            || !path[3..]
                .split('\\')
                .any(|p| p.is_empty() || matches!(p, "." | "..") || p.ends_with(['.', ' '])))
}

pub fn validate_for_kind(
    request: &Request,
    kind: crate::FleetHostKind,
) -> Result<(), &'static str> {
    validate(request)?;
    let cwd = &request.working_directory;
    let valid = match kind {
        crate::FleetHostKind::Windows => {
            // CreateProcessW's command line bound includes CRT quoting and
            // UTF-16 terminator. Reject before BEGIN, not after admission.
            let command_units: usize = request
                .argv
                .iter()
                .map(|s| {
                    let mut n = 2 + s.encode_utf16().count();
                    let mut slashes = 0;
                    for c in s.chars() {
                        if c == '\\' {
                            slashes += 1;
                        } else {
                            if c == '"' {
                                n += slashes + 1;
                            }
                            slashes = 0;
                        }
                    }
                    n + slashes
                })
                .sum::<usize>()
                + request.argv.len();
            if command_units > 32767 {
                return Err("HOST_ADMIN_WINDOWS_COMMAND_LINE_TOO_LONG");
            }
            windows_absolute_path(&request.argv[0])
                && (cwd.is_empty() || windows_absolute_path(cwd))
        }
        crate::FleetHostKind::Vm => cwd.is_empty() || cwd.starts_with('/'),
        _ => false,
    };
    if !valid {
        return Err("HOST_ADMIN_PLATFORM_PATH_INVALID");
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
    if result.rejected_before_begin {
        let empty = ring::digest::digest(&ring::digest::SHA256, b"");
        return rejection_code_valid(&result.rejection_code)
            && result.worker_authorization.is_none()
            && (result.rejection_code != "HOST_ADMIN_REQUEST_EXPIRED_BEFORE_BEGIN"
                || expired_before_begin(request, result.observed_at_unix))
            && !result.process_exited
            && result.exit_code == 0
            && result.stdout_sha256 == empty.as_ref()
            && result.stderr_sha256 == empty.as_ref()
            && result.stdout_preview.is_empty()
            && result.stderr_preview.is_empty()
            && result.stdout_total_bytes == 0
            && result.stderr_total_bytes == 0
            && result.stdout_capture_path.is_empty()
            && result.stderr_capture_path.is_empty()
            && result.stdout_capture_bytes == 0
            && result.stderr_capture_bytes == 0
            && !result.stdout_capture_complete
            && !result.stderr_capture_complete
            && !result.stdout_stream_eof
            && !result.stderr_stream_eof
            && result.stdin_bytes_written == 0
            && !result.stdin_input_complete
            && !result.stdout_truncated
            && !result.stderr_truncated;
    }
    if !result.rejection_code.is_empty() {
        return false;
    }
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
        && result.stdin_bytes_written <= request.stdin_bytes.len() as u64
        && result.stdin_input_complete
            == (result.stdin_bytes_written == request.stdin_bytes.len() as u64)
        && (request.publish_output || (a == 0 && b == 0))
        && a as u64 <= result.stdout_total_bytes
        && b as u64 <= result.stderr_total_bytes
        && result.stdout_truncated == (result.stdout_total_bytes > max as u64)
        && result.stderr_truncated == (result.stderr_total_bytes > max as u64)
        && (!request.publish_output
            || (a as u64 == result.stdout_total_bytes.min(max as u64)
                && b as u64 == result.stderr_total_bytes.min(max as u64)))
}

pub fn expired_before_begin(request: &Request, now: u64) -> bool {
    now > request.requested_at_unix.saturating_add(300)
}

pub fn expired_rejection(request: &Request, now: u64) -> Result<ResultReceipt, &'static str> {
    validate(request)?;
    if !expired_before_begin(request, now) {
        return Err("HOST_ADMIN_REQUEST_NOT_EXPIRED");
    }
    prebegin_rejection(request, now, "HOST_ADMIN_REQUEST_EXPIRED_BEFORE_BEGIN")
}

fn rejection_code_valid(code: &str) -> bool {
    code.starts_with("HOST_")
        && code.len() <= 128
        && code
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

pub fn prebegin_rejection(
    request: &Request,
    now: u64,
    reason: &str,
) -> Result<ResultReceipt, &'static str> {
    validate(request)?;
    let code = if rejection_code_valid(reason) {
        reason
    } else {
        "HOST_ADMIN_PREBEGIN_UNCLASSIFIED"
    };
    if code == "HOST_ADMIN_REQUEST_EXPIRED_BEFORE_BEGIN" && !expired_before_begin(request, now) {
        return Err("HOST_ADMIN_REQUEST_NOT_EXPIRED");
    }
    let empty = ring::digest::digest(&ring::digest::SHA256, b"")
        .as_ref()
        .to_vec();
    Ok(ResultReceipt {
        schema_version: 1,
        machine_id: request.machine_id.clone(),
        operation_id: operation_id(request),
        request_sha256: ring::digest::digest(&ring::digest::SHA256, &request.encode_to_vec())
            .as_ref()
            .to_vec(),
        observed_at_unix: now,
        stdout_sha256: empty.clone(),
        stderr_sha256: empty,
        rejected_before_begin: true,
        rejection_code: code.into(),
        ..Default::default()
    })
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

pub fn verify_receipt_worker_authority(
    request: &Request,
    receipt: &ResultReceipt,
    worker_public_key: &[u8],
) -> Result<(), &'static str> {
    if receipt.rejected_before_begin {
        return if receipt.worker_authorization.is_none() {
            Ok(())
        } else {
            Err("HOST_ADMIN_REJECTION_CANNOT_CLAIM_AUTHORIZATION")
        };
    }
    let auth = receipt
        .worker_authorization
        .as_ref()
        .ok_or("HOST_ADMIN_RECEIPT_WORKER_AUTHORIZATION_MISSING")?;
    if receipt.observed_at_unix < auth.issued_at_unix {
        return Err("HOST_ADMIN_RECEIPT_PRECEDES_AUTHORIZATION");
    }
    // Historical receipts remain verifiable after grant expiry; the exact
    // SYSTEM/root executor verified freshness immediately before BEGIN.
    verify_authorization(request, auth, worker_public_key, auth.issued_at_unix)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::KeyPair};
    #[test]
    fn signed_prebegin_denial_never_proves_execution_or_replays_a_fresh_request() {
        let req = request();
        assert!(!expired_before_begin(&req, req.requested_at_unix + 300));
        assert!(expired_rejection(&req, req.requested_at_unix + 300).is_err());
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let owner = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
        let mut denied = expired_rejection(&req, req.requested_at_unix + 301).unwrap();
        sign_receipt(&req, &mut denied, key.as_ref()).unwrap();
        verify_receipt(&req, &denied, owner.public_key().as_ref()).unwrap();
        assert!(denied.rejected_before_begin && !denied.process_exited);
        for field in 0..5 {
            let mut bad = denied.clone();
            match field {
                0 => bad.process_exited = true,
                1 => bad.stdout_stream_eof = true,
                2 => bad.stdout_preview = vec![1],
                3 => bad.stdin_bytes_written = 1,
                _ => bad.rejected_before_begin = false,
            }
            assert!(sign_receipt(&req, &mut bad, key.as_ref()).is_err());
            assert!(verify_receipt(&req, &bad, owner.public_key().as_ref()).is_err());
        }
        let mut foreign = req.clone();
        foreign.source_comment_id += 1;
        assert!(verify_receipt(&foreign, &denied, owner.public_key().as_ref()).is_err());
        let mut bad = denied.clone();
        bad.rejection_code = "HOST_WINDOWS_OTHER_FAILURE".into();
        assert!(verify_receipt(&req, &bad, owner.public_key().as_ref()).is_err());
        let redacted = prebegin_rejection(
            &req,
            req.requested_at_unix + 1,
            "HOST_ERROR: token=do-not-store",
        )
        .unwrap();
        assert_eq!(redacted.rejection_code, "HOST_ADMIN_PREBEGIN_UNCLASSIFIED");
        let precise = prebegin_rejection(
            &req,
            req.requested_at_unix + 1,
            "HOST_WINDOWS_TRUST_ACCEPTED_CANDIDATE_UNPROVEN",
        )
        .unwrap();
        assert_eq!(
            precise.rejection_code,
            "HOST_WINDOWS_TRUST_ACCEPTED_CANDIDATE_UNPROVEN"
        );
    }
    #[test]
    fn admin_cwd_matches_git_host_kind() {
        let mut r = request();
        assert!(validate_for_kind(&r, crate::FleetHostKind::Vm).is_ok());
        assert!(validate_for_kind(&r, crate::FleetHostKind::Windows).is_err());
        r.argv = vec![r"C:\Windows\System32\cmd.exe".into()];
        r.working_directory = r"C:\Windows".into();
        assert!(validate_for_kind(&r, crate::FleetHostKind::Windows).is_ok());
        assert!(validate_for_kind(&r, crate::FleetHostKind::Vm).is_err());
        for p in [
            r"C:relative",
            r"\\server\share",
            r"\\?\C:\Windows",
            r"C:\a\..\b",
            "C:\\a\0b",
        ] {
            r.working_directory = p.into();
            assert!(
                validate_for_kind(&r, crate::FleetHostKind::Windows).is_err(),
                "{p:?}"
            );
        }
    }
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
    #[test]
    fn receipt_binds_exact_output_request_and_owner() {
        let owner_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let owner = Ed25519KeyPair::from_pkcs8(owner_key.as_ref()).unwrap();
        let mut req = request();
        req.publish_output = true;
        req.stdin_bytes = b"payload".to_vec();
        let out = b"hello";
        let mut receipt = ResultReceipt {
            schema_version: 1,
            machine_id: req.machine_id.clone(),
            operation_id: operation_id(&req),
            request_sha256: ring::digest::digest(&ring::digest::SHA256, &req.encode_to_vec())
                .as_ref()
                .to_vec(),
            observed_at_unix: 101,
            exit_code: 0,
            stdout_sha256: ring::digest::digest(&ring::digest::SHA256, out)
                .as_ref()
                .to_vec(),
            stderr_sha256: ring::digest::digest(&ring::digest::SHA256, b"")
                .as_ref()
                .to_vec(),
            process_exited: true,
            root_signature: Vec::new(),
            stdout_preview: out.to_vec(),
            stderr_preview: Vec::new(),
            stdout_total_bytes: out.len() as u64,
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_capture_path: "/root/journal/admin-42.stdout.bin".into(),
            stderr_capture_path: "/root/journal/admin-42.stderr.bin".into(),
            stdout_capture_bytes: out.len() as u64,
            stderr_capture_bytes: 0,
            stdout_capture_complete: true,
            stderr_capture_complete: true,
            stdout_stream_eof: true,
            stderr_stream_eof: true,
            stdin_bytes_written: req.stdin_bytes.len() as u64,
            stdin_input_complete: true,
            ..Default::default()
        };
        sign_receipt(&req, &mut receipt, owner_key.as_ref()).unwrap();
        verify_receipt(&req, &receipt, owner.public_key().as_ref()).unwrap();
        assert!(
            verify_receipt_worker_authority(&req, &receipt, owner.public_key().as_ref()).is_err()
        );
        let worker_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let worker = Ed25519KeyPair::from_pkcs8(worker_key.as_ref()).unwrap();
        let mut grant = Authorization {
            schema_version: 1,
            key_id: "worker".into(),
            operation_id: operation_id(&req),
            issued_at_unix: 100,
            expires_at_unix: 200,
            ..Default::default()
        };
        grant.ed25519_signature = worker
            .sign(&authorization_payload(&req, &grant))
            .as_ref()
            .to_vec();
        receipt.worker_authorization = Some(grant);
        sign_receipt(&req, &mut receipt, owner_key.as_ref()).unwrap();
        verify_receipt(&req, &receipt, owner.public_key().as_ref()).unwrap();
        verify_receipt_worker_authority(&req, &receipt, worker.public_key().as_ref()).unwrap();
        let mut forged = receipt.clone();
        forged
            .worker_authorization
            .as_mut()
            .unwrap()
            .ed25519_signature[0] ^= 1;
        sign_receipt(&req, &mut forged, owner_key.as_ref()).unwrap();
        verify_receipt(&req, &forged, owner.public_key().as_ref()).unwrap();
        assert!(
            verify_receipt_worker_authority(&req, &forged, worker.public_key().as_ref()).is_err()
        );
        let mut backwards = receipt.clone();
        backwards.observed_at_unix = 99;
        assert!(
            verify_receipt_worker_authority(&req, &backwards, worker.public_key().as_ref())
                .is_err()
        );
        let mut edited = receipt.clone();
        edited.stdout_stream_eof = false;
        assert!(verify_receipt(&req, &edited, owner.public_key().as_ref()).is_err());
        edited = receipt.clone();
        edited.stdout_preview[0] ^= 1;
        assert!(verify_receipt(&req, &edited, owner.public_key().as_ref()).is_err());
        edited = receipt.clone();
        edited.stdin_bytes_written = 999;
        assert!(verify_receipt(&req, &edited, owner.public_key().as_ref()).is_err());
        edited = receipt.clone();
        edited.stdout_capture_bytes = 999;
        assert!(verify_receipt(&req, &edited, owner.public_key().as_ref()).is_err());
        let mut altered_request = req.clone();
        altered_request.environment.push("A=B".into());
        assert!(verify_receipt(&altered_request, &receipt, owner.public_key().as_ref()).is_err());
        altered_request = req.clone();
        altered_request.timeout_seconds += 1;
        assert!(verify_receipt(&altered_request, &receipt, owner.public_key().as_ref()).is_err());
        let wrong = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let wrong_owner = Ed25519KeyPair::from_pkcs8(wrong.as_ref()).unwrap();
        assert!(verify_receipt(&req, &receipt, wrong_owner.public_key().as_ref()).is_err());
    }
}
