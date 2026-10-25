//! Native root-only first-use Access handoff.
//! No runner private key, SSH, extra service, untyped operator secret or
//! second authority: the runner transfers a bounded sealed protobuf only.
use super::*;
use edge_shared_types::{
    FleetNativeTrustSnapshot, FleetVmBootstrapAccessEnvelope, FleetVmBootstrapKeyProof,
    vm_bootstrap,
};
use ring::digest::{SHA256, digest};
use ring::signature::Ed25519KeyPair;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

const TRUSTED: &str = host_native::TRUSTED_ROOT;
const PRIVATE_KEY: &str = "bootstrap-x25519.secret";
const BEGIN: &str = "bootstrap-access.begin";
const TERMINAL: &str = "bootstrap-access.terminal";
const MAX_ENVELOPE: u64 = 4096;

fn recipient_key() -> Result<[u8; 32], String> {
    let bytes = host_native::root_file(&Path::new(TRUSTED).join(PRIVATE_KEY), 32)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "BOOTSTRAP_ROOT_KEY_INVALID".into())
}

fn native_proof() -> Result<FleetVmBootstrapKeyProof, String> {
    let trusted = Path::new(TRUSTED);
    let bytes = host_native::root_file(&trusted.join("trust.pb"), 9 * 1024 * 1024)?;
    let trust = host_native::decode_native_trust_snapshot(&bytes)?;
    let receipt_pk8 = host_native::root_file(&trusted.join("receipt-key.pk8"), 4096)?;
    let secret = recipient_key()?;
    let public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
    let release_digest = digest(&SHA256, &trust.release_set_pb);
    vm_bootstrap::sign_root_proof(
        &trust.machine_id,
        release_digest.as_ref(),
        &public,
        &receipt_pk8,
    )
    .map_err(str::to_owned)
}

/// The only public first-use information returned to the unprivileged runner.
/// The recipient public key alone is NOT proof of the provider or GH runner.
pub(crate) fn public_proof() -> Result<(), String> {
    let _lock = host_native::owner_operation_lock()?;
    let proof = native_proof()?;
    io::stdout()
        .write_all(&proof.encode_to_vec())
        .map_err(|_| "BOOTSTRAP_PROOF_STDOUT_FAILED".to_owned())
}

fn validate_plain_identity(plaintext: &[u8]) -> Result<(), String> {
    if plaintext.is_empty() || plaintext.len() > 1024 {
        return Err("BOOTSTRAP_ACCESS_IDENTITY_INVALID".into());
    }
    let text = std::str::from_utf8(plaintext).map_err(|_| "BOOTSTRAP_ACCESS_UTF8_INVALID")?;
    // Reuse the ONE production parser, including support for base64 values
    // containing '='. Never maintain another interpretation of Access keys.
    edge_secrets::AccessServiceIdentity::parse_env(text)
        .map_err(|_| "BOOTSTRAP_ACCESS_IDENTITY_INVALID")?;
    Ok(())
}

fn durable_marker(name: &str, body: &[u8]) -> Result<(), String> {
    let root = Path::new(TRUSTED);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))
        .map_err(|_| "BOOTSTRAP_ACCESS_ALREADY_BEGUN_NO_REPLAY")?;
    file.write_all(body)
        .and_then(|_| file.sync_all())
        .map_err(|_| "BOOTSTRAP_ACCESS_BEGIN_UNCERTAIN_NO_REPLAY")?;
    fs::File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|_| "BOOTSTRAP_ACCESS_BEGIN_UNCERTAIN_NO_REPLAY")?;
    Ok(())
}

/// Protected Git must already pin the receipt identity. Enrollment and
/// ciphertext readback never authorize an administrative operation. The
/// existing Worker Access GET proves that the provided identity is usable
/// before the root agent commits it to a private file.
pub(crate) async fn install() -> Result<(), String> {
    let _lock = host_native::owner_operation_lock()?;
    let mut raw = Vec::new();
    io::stdin()
        .take(MAX_ENVELOPE + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "BOOTSTRAP_ENVELOPE_STDIN_FAILED")?;
    if raw.is_empty() || raw.len() as u64 > MAX_ENVELOPE {
        return Err("BOOTSTRAP_ENVELOPE_LENGTH_INVALID".into());
    }
    let envelope = FleetVmBootstrapAccessEnvelope::decode(raw.as_slice())
        .map_err(|_| "BOOTSTRAP_ENVELOPE_PROTO_INVALID")?;
    if envelope.encode_to_vec() != raw {
        return Err("BOOTSTRAP_ENVELOPE_NONCANONICAL".into());
    }
    let expected = native_proof()?;
    let proof = envelope
        .recipient
        .as_ref()
        .ok_or("BOOTSTRAP_PROOF_MISSING")?;
    if proof != &expected {
        return Err("BOOTSTRAP_PROTECTED_RECIPIENT_MISMATCH".into());
    }
    let current_host = host_native::registered_vm_host()?;
    if current_host.native_receipt_public_key != expected.native_receipt_public_key {
        return Err("BOOTSTRAP_PROTECTED_GIT_RECEIPT_NOT_REGISTERED".into());
    }
    let destination = vm_credential_access_identity_path(Path::new(DEFAULT_STACK_DIR))?;
    let dir = destination
        .parent()
        .ok_or("BOOTSTRAP_ACCESS_PARENT_MISSING")?;
    if fs::symlink_metadata(&destination).is_ok()
        || fs::symlink_metadata(&Path::new(TRUSTED).join(BEGIN)).is_ok()
        || fs::symlink_metadata(&Path::new(TRUSTED).join(TERMINAL)).is_ok()
    {
        return Err("BOOTSTRAP_ACCESS_ALREADY_BEGUN_NO_REPLAY".into());
    }
    // Decode and authenticate the sealed envelope before committing BEGIN;
    // a corrupt/untrusted runner copy cannot consume the one-time operation.
    let clear =
        vm_bootstrap::open_for_native_root(&envelope, &recipient_key()?).map_err(str::to_owned)?;
    validate_plain_identity(&clear)?;
    let marker = digest(&SHA256, &raw);
    durable_marker(BEGIN, marker.as_ref())?;

    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() && meta.uid() == 0 && meta.permissions().mode() & 0o077 == 0 => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|_| "BOOTSTRAP_ACCESS_DIR_CREATE_UNCERTAIN_NO_REPLAY")?;
        }
        _ => return Err("BOOTSTRAP_ACCESS_DIR_NOT_PRIVATE_NO_REPLAY".into()),
    }
    let staged = dir.join(".credential-access-first-use.tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .map_err(|_| "BOOTSTRAP_ACCESS_STAGE_UNCERTAIN_NO_REPLAY")?;
    file.write_all(&clear)
        .and_then(|_| file.sync_all())
        .map_err(|_| "BOOTSTRAP_ACCESS_STAGE_UNCERTAIN_NO_REPLAY")?;
    // Use the already installed Worker Access verifier; do not invent
    // another token exchange or trust owner in this bootstrap.
    edge_secrets::diagnose_canonical_host_access(&staged)
        .await
        .map_err(|_| "BOOTSTRAP_ACCESS_WORKER_GET_NOT_PROVEN_NO_REPLAY")?;
    fs::rename(&staged, &destination).map_err(|_| "BOOTSTRAP_ACCESS_COMMIT_UNCERTAIN_NO_REPLAY")?;
    fs::File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|_| "BOOTSTRAP_ACCESS_COMMIT_UNCERTAIN_NO_REPLAY")?;
    durable_marker(TERMINAL, marker.as_ref())?;
    println!("bootstrap_access=ROOT_ONLY_INSTALLED_WORKER_GET_PROVEN");
    println!("bootstrap_access_identity_exposed_to_runner=false");
    println!("bootstrap_replay_allowed=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_two_line_credentials_can_cross_native_boundary() {
        let valid = format!(
            "CF_ACCESS_CLIENT_ID={}\nCF_ACCESS_CLIENT_SECRET={}\n",
            "x".repeat(32),
            "y".repeat(64)
        );
        assert!(validate_plain_identity(valid.as_bytes()).is_ok());
        for invalid in [
            "",
            "CF_ACCESS_CLIENT_ID=x\n",
            "CF_ACCESS_CLIENT_SECRET=x\nCF_ACCESS_CLIENT_ID=x\n",
            "CF_ACCESS_CLIENT_ID=abc\nCF_ACCESS_CLIENT_SECRET=x\n",
            "CF_ACCESS_CLIENT_ID=xxxxxxxxxxxxxxxx\nCF_ACCESS_CLIENT_SECRET=yyyyyyyyyyyyyyyy\nJUNK=1\n",
            "CF_ACCESS_CLIENT_ID=xxxxxxxxxxxxxxxx\r\nCF_ACCESS_CLIENT_SECRET=yyyyyyyyyyyyyyyy\n",
        ] {
            assert!(validate_plain_identity(invalid.as_bytes()).is_err());
        }
    }
}
