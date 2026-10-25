//! VM-native administrative executor. This is the ONLY privileged execution
//! boundary: the GitHub runner supplies protobuf bytes but cannot authorize them.
//! Every request is signed by the existing Worker after independent GitHub
//! actor/comment verification, and the native root has a durable no-replay gate.
use super::*;
use edge_shared_types::{
    FleetNativeAdministrativeResult, FleetNativeTrustSnapshot, ReleaseSet,
    host_admin,
};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::fs::OpenOptions;

fn hex_hash(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn record_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut writer = OpenOptions::new()
        .create_new(true).write(true).mode(0o600)
        .open(path)
        .map_err(|_| "HOST_ADMIN_JOURNAL_RECORD_EXISTS_NO_REPLAY")?;
    writer.write_all(bytes).map_err(|_| "HOST_ADMIN_JOURNAL_WRITE_UNKNOWN_NO_REPLAY")?;
    writer.sync_all().map_err(|_| "HOST_ADMIN_JOURNAL_SYNC_UNKNOWN_NO_REPLAY")?;
    let dir = File::open(path.parent().ok_or("HOST_ADMIN_JOURNAL_PARENT_MISSING")?)
        .map_err(|_| "HOST_ADMIN_JOURNAL_PARENT_UNAVAILABLE")?;
    dir.sync_all().map_err(|_| "HOST_ADMIN_JOURNAL_PARENT_SYNC_UNKNOWN_NO_REPLAY")?;
    Ok(())
}

fn bounded_read(mut stream: impl Read) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    stream.take(65537).read_to_end(&mut output)
        .map_err(|_| "HOST_ADMIN_IO_UNAVAILABLE")?;
    Ok(output)
}

pub(super) async fn execute() -> Result<(), String> {
    let mut raw = Vec::new();
    std::io::stdin().take((host_admin::MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut raw).map_err(|_| "HOST_ADMIN_STDIN_UNAVAILABLE")?;
    let request = host_admin::decode(&raw).map_err(str::to_owned)?;

    let _lock = host_native::owner_operation_lock()?;
    let journal_dir = Path::new(host_native::TRUSTED_ROOT).join("journal");
    let meta = fs::symlink_metadata(&journal_dir)
        .map_err(|_| "HOST_ADMIN_JOURNAL_UNAVAILABLE")?;
    if !meta.file_type().is_dir() || meta.uid() != 0
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("HOST_ADMIN_JOURNAL_UNTRUSTED".into());
    }
    if host_native::protected_journal_has_pending(&journal_dir)? {
        return Err("HOST_ADMIN_OLD_PENDING_UNKNOWN_NO_REPLAY".into());
    }

    let trust_root = Path::new(host_native::TRUSTED_ROOT);
    let trust_pb = host_native::root_file(&trust_root.join("trust.pb"), 9 * 1024 * 1024)?;
    let trust = host_native::decode_native_trust_snapshot(&trust_pb)?;
    let host = host_native::registered_vm_host()?;
    if trust.machine_id != request.machine_id || host.machine_id != request.machine_id {
        return Err("HOST_ADMIN_NATIVE_OWNER_MISMATCH".into());
    }
    if ring::digest::digest(&ring::digest::SHA256, &trust.release_set_pb).as_ref()
        != request.release_set_sha256
    {
        return Err("HOST_ADMIN_RELEASE_MISMATCH".into());
    }
    edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(
        &host, &trust.pinned_worker_public_key).map_err(str::to_owned)?;
    let root_pkcs8 = host_native::root_file(&trust_root.join("receipt-key.pk8"), 4096)?;
    edge_shared_types::host_receipt::check_native_receipt_key(&host, &root_pkcs8)
        .map_err(str::to_owned)?;
    let release = ReleaseSet::decode(trust.release_set_pb.as_slice())
        .map_err(|_| "HOST_ADMIN_RELEASE_DECODE_INVALID")?;
    let agent_digest = &release.vm_runtime.as_ref()
        .ok_or("HOST_ADMIN_RELEASE_OWNER_MISSING")?.edge_agent_sha256;
    let installed = host_native::root_file(Path::new("/usr/local/libexec/sing-box/edge-agent"), 32 * 1024 * 1024);
    // Installed binary is deliberately world executable (0755), so root_file
    // private-file policy is NOT appropriate; check identity and hash separately.
    let binary = Path::new("/usr/local/libexec/sing-box/edge-agent");
    let identity = fs::symlink_metadata(binary)
        .map_err(|_| "HOST_ADMIN_AGENT_BINARY_UNAVAILABLE")?;
    if !identity.file_type().is_file() || identity.uid() != 0
        || identity.permissions().mode() & 0o777 != 0o755
        || identity.len() == 0 || identity.len() > 32 * 1024 * 1024
    {
        return Err("HOST_ADMIN_AGENT_BINARY_UNTRUSTED".into());
    }
    let _ = installed;
    if ring::digest::digest(&ring::digest::SHA256, &fs::read(binary)
        .map_err(|_| "HOST_ADMIN_AGENT_BINARY_UNREADABLE")?).as_ref()
        != agent_digest.as_slice()
    {
        return Err("HOST_ADMIN_INSTALLED_RELEASE_DRIFT".into());
    }

    // The Worker is the independent signer and original GitHub comment verifier.
    // No automatic retry after an ambiguous POST outcome.
    let credential = super::vm_credential_access_identity_path(Path::new(DEFAULT_STACK_DIR))?;
    edge_secrets::diagnose_canonical_host_access(&credential)
        .await.map_err(str::to_owned)?;
    let auth = edge_secrets::request_canonical_native_admin_authorization(&raw, &credential).await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_ADMIN_CLOCK_UNAVAILABLE")?.as_secs();
    host_admin::verify(&request, &auth, &trust.pinned_worker_public_key, now)
        .map_err(str::to_owned)?;

    // BEGIN must be durable before the native side effect. This is the same
    // native root-owned journal and lock as resource lifecycle mutations.
    let id = hex_hash(request.operation_id.as_bytes());
    let pending = journal_dir.join(format!("admin-{id}.pending.pb"));
    let terminal = journal_dir.join(format!("admin-{id}.verified.pb"));
    record_private(&pending, &raw)?;

    let mut command = Command::new("/usr/bin/timeout");
    command.arg("--kill-after=2s").arg("30s")
        .arg(&request.argv[0]).args(&request.argv[1..])
        .env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C").current_dir("/")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| "HOST_ADMIN_EXEC_FAILED_UNKNOWN_NO_REPLAY")?;
    let stdout = child.stdout.take().ok_or("HOST_ADMIN_STDOUT_MISSING_UNKNOWN_NO_REPLAY")?;
    let stderr = child.stderr.take().ok_or("HOST_ADMIN_STDERR_MISSING_UNKNOWN_NO_REPLAY")?;
    let out_thread = std::thread::spawn(move || bounded_read(stdout));
    let err_thread = std::thread::spawn(move || bounded_read(stderr));
    let status = child.wait().map_err(|_| "HOST_ADMIN_WAIT_UNKNOWN_NO_REPLAY")?;
    let out = out_thread.join().map_err(|_| "HOST_ADMIN_STDOUT_JOIN_UNKNOWN_NO_REPLAY")??;
    let err = err_thread.join().map_err(|_| "HOST_ADMIN_STDERR_JOIN_UNKNOWN_NO_REPLAY")??;

    let done = status.success() && out.len() <= 65536 && err.len() <= 65536;
    let mut result = FleetNativeAdministrativeResult {
        schema_version: 1,
        machine_id: request.machine_id.clone(),
        operation_id: request.operation_id.clone(),
        request_sha256: ring::digest::digest(&ring::digest::SHA256, &raw).as_ref().to_vec(),
        finished_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "HOST_ADMIN_CLOCK_UNAVAILABLE")?.as_secs(),
        exit_code: status.code().unwrap_or(-1),
        stdout_sha256: ring::digest::digest(&ring::digest::SHA256, &out).as_ref().to_vec(),
        stderr_sha256: ring::digest::digest(&ring::digest::SHA256, &err).as_ref().to_vec(),
        completed: done,
        ed25519_signature: Vec::new(),
    };
    host_admin::sign_result(&request, &mut result, &root_pkcs8)
        .map_err(str::to_owned)?;
    record_private(&terminal, &result.encode_to_vec())?;
    if done {
        fs::remove_file(&pending).map_err(|_| "HOST_ADMIN_SCOPE_RELEASE_UNKNOWN_NO_REPLAY")?;
        File::open(&journal_dir).and_then(|f| f.sync_all())
            .map_err(|_| "HOST_ADMIN_SCOPE_SYNC_UNKNOWN_NO_REPLAY")?;
    }
    // Public GitHub artifacts get ONLY hashes and signed metadata; never
    // command stdout/stderr or any root-readable secret.
    io::stdout().write_all(&result.encode_to_vec())
        .map_err(|_| "HOST_ADMIN_RECEIPT_STDOUT_UNAVAILABLE")?;
    if done { Ok(()) } else { Err("HOST_ADMIN_NOT_VERIFIED_UNKNOWN_NO_REPLAY".into()) }
}
