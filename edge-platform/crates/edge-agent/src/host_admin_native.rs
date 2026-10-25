//! The installed root agent is the ONLY privileged executor. A GitHub
//! runner can forward bytes but cannot choose or approve a native operation.
//! A fresh Worker signature, exact release, owner lock and durable BEGIN are
//! mandatory before one native process is launched.
use super::*;
use edge_shared_types::{FleetHostAdministrativeReceipt, ReleaseSet, host_admin};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const JOURNAL: &str = "/opt/vultr-edge-stack/native-host/journal";
const EXECUTABLE: &str = "/usr/local/libexec/sing-box/edge-agent";
const OUTPUT_LIMIT: u64 = 65536;

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
}
fn hex_id(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref()
        .iter().map(|b| format!("{b:02x}")).collect()
}
fn durable_create(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut writer = OpenOptions::new().write(true).create_new(true)
        .mode(0o600).open(path)
        .map_err(|_| "HOST_ADMIN_DUPLICATE_OR_WRITE_UNAVAILABLE_NO_REPLAY")?;
    writer.write_all(data)
        .map_err(|_| "HOST_ADMIN_RECORD_WRITE_UNKNOWN_NO_REPLAY")?;
    writer.sync_all()
        .map_err(|_| "HOST_ADMIN_RECORD_SYNC_UNKNOWN_NO_REPLAY")?;
    let dir = File::open(path.parent().ok_or("HOST_ADMIN_RECORD_PARENT_MISSING")?)
        .map_err(|_| "HOST_ADMIN_RECORD_PARENT_UNAVAILABLE")?;
    dir.sync_all()
        .map_err(|_| "HOST_ADMIN_PARENT_SYNC_UNKNOWN_NO_REPLAY")?;
    Ok(())
}
fn bounded(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(OUTPUT_LIMIT + 1).read_to_end(&mut out)?;
    Ok(out)
}

pub(super) async fn execute() -> Result<(), String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((host_admin::MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "HOST_ADMIN_REQUEST_READ_FAILED")?;
    let req = host_admin::decode(&bytes).map_err(str::to_owned)?;
    let _exclusive = host_native::owner_operation_lock()?;
    let journal = Path::new(JOURNAL);
    let journal_meta = fs::symlink_metadata(journal)
        .map_err(|_| "HOST_ADMIN_JOURNAL_MISSING")?;
    if !journal_meta.file_type().is_dir() || journal_meta.uid() != 0
        || journal_meta.permissions().mode() & 0o077 != 0
    {
        return Err("HOST_ADMIN_JOURNAL_UNTRUSTED".into());
    }
    if host_native::protected_journal_has_pending(journal)? {
        return Err("HOST_ADMIN_EXISTING_UNKNOWN_NO_REPLAY".into());
    }
    let root = Path::new(host_native::TRUSTED_ROOT);
    let trust_bytes = host_native::root_file(&root.join("trust.pb"), 9 * 1024 * 1024)?;
    let trust = host_native::decode_native_trust_snapshot(&trust_bytes)?;
    let host = host_native::registered_vm_host()?;
    if req.machine_id != trust.machine_id || req.machine_id != host.machine_id {
        return Err("HOST_ADMIN_MACHINE_ID_MISMATCH".into());
    }
    if sha256(&trust.release_set_pb) != req.release_set_sha256 {
        return Err("HOST_ADMIN_RELEASE_SET_MISMATCH".into());
    }
    edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(
        &host, &trust.pinned_worker_public_key).map_err(str::to_owned)?;
    let root_key = host_native::root_file(&root.join("receipt-key.pk8"), 4096)?;
    edge_shared_types::host_receipt::check_native_receipt_key(&host, &root_key)
        .map_err(str::to_owned)?;
    let release = ReleaseSet::decode(trust.release_set_pb.as_slice())
        .map_err(|_| "HOST_ADMIN_RELEASE_SET_INVALID")?;
    let expected = &release.vm_runtime.as_ref()
        .ok_or("HOST_ADMIN_RELEASE_AGENT_ABSENT")?.edge_agent_sha256;
    let agent = Path::new(EXECUTABLE);
    let meta = fs::symlink_metadata(agent)
        .map_err(|_| "HOST_ADMIN_INSTALLED_AGENT_ABSENT")?;
    if !meta.file_type().is_file() || meta.uid() != 0
        || meta.permissions().mode() & 0o777 != 0o755
        || meta.len() == 0 || meta.len() > 32 * 1024 * 1024
    {
        return Err("HOST_ADMIN_INSTALLED_AGENT_UNTRUSTED".into());
    }
    if sha256(&fs::read(agent).map_err(|_| "HOST_ADMIN_AGENT_UNREADABLE")?) != *expected {
        return Err("HOST_ADMIN_AGENT_RELEASE_DRIFT".into());
    }
    let identity = vm_credential_access_identity_path(Path::new(DEFAULT_STACK_DIR))?;
    edge_secrets::diagnose_canonical_host_access(&identity).await.map_err(str::to_owned)?;
    let auth = edge_secrets::request_canonical_admin_authorization(&bytes, &identity).await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?.as_secs();
    host_admin::verify_authorization(
        &req, &auth, &trust.pinned_worker_public_key, now,
    ).map_err(str::to_owned)?;
    // No stale/replayed administrative request may execute, even after a
    // terminal receipt was already published.
    let key = hex_id(host_admin::operation_id(&req).as_bytes());
    let pending = journal.join(format!("admin-{key}.pending.pb"));
    let finished = journal.join(format!("admin-{key}.terminal.pb"));
    if fs::symlink_metadata(&finished).is_ok() {
        return Err("HOST_ADMIN_ALREADY_TERMINAL_NO_REPLAY".into());
    }
    durable_create(&pending, &bytes)?;

    // Native owner deliberately has root, not the GitHub runner. argv is
    // signed, not injected into a shell. A shell can be requested explicitly
    // as a program only by the authorized operator.
    let mut process = std::process::Command::new("/usr/bin/timeout");
    process.args(["--kill-after=2s", "30s"])
        .arg(&req.argv[0]).args(&req.argv[1..])
        .env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = process.spawn()
        .map_err(|_| "HOST_ADMIN_LAUNCH_UNKNOWN_NO_REPLAY")?;
    let stdout = child.stdout.take().ok_or("HOST_ADMIN_STDOUT_UNKNOWN_NO_REPLAY")?;
    let stderr = child.stderr.take().ok_or("HOST_ADMIN_STDERR_UNKNOWN_NO_REPLAY")?;
    let reader_out = std::thread::spawn(move || bounded(stdout));
    let reader_err = std::thread::spawn(move || bounded(stderr));
    let status = child.wait().map_err(|_| "HOST_ADMIN_WAIT_UNKNOWN_NO_REPLAY")?;
    let out = reader_out.join().map_err(|_| "HOST_ADMIN_OUT_JOIN_UNKNOWN_NO_REPLAY")?
        .map_err(|_| "HOST_ADMIN_OUT_IO_UNKNOWN_NO_REPLAY")?;
    let err = reader_err.join().map_err(|_| "HOST_ADMIN_ERR_JOIN_UNKNOWN_NO_REPLAY")?
        .map_err(|_| "HOST_ADMIN_ERR_IO_UNKNOWN_NO_REPLAY")?;
    let complete = status.success()
        && out.len() <= OUTPUT_LIMIT as usize
        && err.len() <= OUTPUT_LIMIT as usize;
    let mut receipt = FleetHostAdministrativeReceipt {
        schema_version: 1,
        machine_id: req.machine_id.clone(),
        operation_id: host_admin::operation_id(&req),
        request_sha256: sha256(&bytes),
        observed_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?.as_secs(),
        exit_code: status.code().unwrap_or(-1),
        stdout_sha256: sha256(&out),
        stderr_sha256: sha256(&err),
        process_exited_successfully: complete,
        root_signature: Vec::new(),
    };
    host_admin::sign_receipt(&req, &mut receipt, &root_key).map_err(str::to_owned)?;
    durable_create(&finished, &receipt.encode_to_vec())?;
    if complete {
        fs::remove_file(&pending)
            .map_err(|_| "HOST_ADMIN_GATE_RELEASE_UNKNOWN_NO_REPLAY")?;
        File::open(journal).and_then(|f| f.sync_all())
            .map_err(|_| "HOST_ADMIN_GATE_SYNC_UNKNOWN_NO_REPLAY")?;
    }
    // No root stdout/stderr enters GitHub logs or public issue. Only native
    // signed process exit + hashes; arbitrary resource effects remain UNPROVEN
    // until a separate physical poststate assessment.
    io::stdout().write_all(&receipt.encode_to_vec())
        .map_err(|_| "HOST_ADMIN_RECEIPT_DELIVERY_UNKNOWN_NO_REPLAY")?;
    if complete { Ok(()) }
    else { Err("HOST_ADMIN_PROCESS_UNVERIFIED_UNKNOWN_NO_REPLAY".into()) }
}
