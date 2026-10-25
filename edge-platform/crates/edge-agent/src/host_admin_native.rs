//! The sole native root executor of explicitly signed, arbitrary VM programs.
//! GitHub runner forwards protobuf stdin, never chooses root effects.
use super::*;
use edge_shared_types::{FleetNativeAdminResult, ReleaseSet, host_admin};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::process::{Command as OsCommand, Stdio as OsStdio};

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}
fn journal_key(id: &str) -> String {
    sha256(id.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn durable_create(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "HOST_ADMIN_OPERATION_ALREADY_PRESENT_OR_IO_UNAVAILABLE_NO_REPLAY")?;
    out.write_all(data)
        .and_then(|_| out.sync_all())
        .map_err(|_| "HOST_ADMIN_BEGIN_SYNC_UNCERTAIN_NO_REPLAY")?;
    File::open(path.parent().ok_or("HOST_ADMIN_NO_JOURNAL_PARENT")?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "HOST_ADMIN_PARENT_SYNC_UNCERTAIN_NO_REPLAY")?;
    Ok(())
}
// Never stop draining a pipe because the retained evidence is full.
const PREVIEW_LIMIT: usize = 64 * 1024;
struct CapturedStream {
    sha256: Vec<u8>,
    total_bytes: u64,
    preview: Vec<u8>,
}
fn capture_stream(mut input: impl Read) -> std::io::Result<CapturedStream> {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    let mut preview = Vec::new();
    loop {
        let len = input.read(&mut buffer)?;
        if len == 0 { break; }
        total_bytes = total_bytes.saturating_add(len as u64);
        hash.update(&buffer[..len]);
        let retain = PREVIEW_LIMIT.saturating_sub(preview.len()).min(len);
        preview.extend_from_slice(&buffer[..retain]);
    }
    Ok(CapturedStream {
        sha256: hash.finish().as_ref().to_vec(),
        total_bytes,
        preview,
    })
}
#[cfg(test)]
mod io_tests {
    use super::*;
    #[test]
    fn long_stream_is_fully_drained_and_hashed() {
        let bytes = vec![0x5a; 1024 * 1024];
        let result = capture_stream(bytes.as_slice()).unwrap();
        assert_eq!(result.total_bytes, bytes.len() as u64);
        assert_eq!(result.preview.len(), PREVIEW_LIMIT);
        assert_eq!(result.sha256, sha256(&bytes));
    }

    #[test]
    fn simultaneous_large_child_stdout_and_stderr_never_deadlock() {
        // Feed two real OS pipes concurrently. A reader which stops at 64 KiB
        // causes timeout(1) to return 124 rather than a successful exit.
        let mut child = OsCommand::new("/usr/bin/timeout")
            .args([
                "8s", "/bin/sh", "-c",
                "head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2",
            ])
            .stdin(OsStdio::null())
            .stdout(OsStdio::piped())
            .stderr(OsStdio::piped())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let out_thread = std::thread::spawn(move || capture_stream(out).unwrap());
        let err_thread = std::thread::spawn(move || capture_stream(err).unwrap());
        let status = child.wait().unwrap();
        let out = out_thread.join().unwrap();
        let err = err_thread.join().unwrap();
        assert!(status.success(), "child stalled before draining both pipes");
        assert_eq!(out.total_bytes, 1_048_576);
        assert_eq!(err.total_bytes, 1_048_576);
        assert_eq!(out.preview.len(), PREVIEW_LIMIT);
        assert_eq!(err.preview.len(), PREVIEW_LIMIT);
        let digest = sha256(&vec![0; 1_048_576]);
        assert_eq!(out.sha256, digest);
        assert_eq!(err.sha256, digest);
    }

    #[test]
    fn actual_child_timeout_returns_terminal_nonzero_status() {
        let status = OsCommand::new("/usr/bin/timeout")
            .args(["--kill-after=1s", "1s", "/bin/sh", "-c", "sleep 5"])
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(124));
    }
}

pub(super) async fn execute() -> Result<(), String> {
    let mut raw = Vec::new();
    io::stdin()
        .take((host_admin::MAX_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "HOST_ADMIN_REQUEST_STDIN_UNAVAILABLE")?;
    let request = host_admin::decode(&raw).map_err(str::to_owned)?;
    let _lock = host_native::owner_operation_lock()?;
    let journal = Path::new(host_native::TRUSTED_ROOT).join("journal");
    let metadata = fs::symlink_metadata(&journal).map_err(|_| "HOST_ADMIN_JOURNAL_UNAVAILABLE")?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
        || host_native::protected_journal_has_pending(&journal)?
    {
        return Err("HOST_ADMIN_JOURNAL_UNTRUSTED_OR_PENDING_NO_REPLAY".into());
    }
    let root = Path::new(host_native::TRUSTED_ROOT);
    let bytes = host_native::root_file(&root.join("trust.pb"), 9 * 1024 * 1024)?;
    let trust = host_native::decode_native_trust_snapshot(&bytes)?;
    let host = host_native::registered_vm_host()?;
    if request.machine_id != trust.machine_id || request.machine_id != host.machine_id {
        return Err("HOST_ADMIN_MACHINE_MISMATCH".into());
    }
    if sha256(&trust.release_set_pb) != request.release_set_sha256 {
        return Err("HOST_ADMIN_RELEASE_MISMATCH".into());
    }
    edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(
        &host,
        &trust.pinned_worker_public_key,
    )
    .map_err(str::to_owned)?;
    let key_bytes = host_native::root_file(&root.join("receipt-key.pk8"), 4096)?;
    edge_shared_types::host_receipt::check_native_receipt_key(&host, &key_bytes)
        .map_err(str::to_owned)?;
    let release = ReleaseSet::decode(trust.release_set_pb.as_slice())
        .map_err(|_| "HOST_ADMIN_RELEASE_PROTOBUF_INVALID")?;
    let expected = release
        .vm_runtime
        .as_ref()
        .ok_or("HOST_ADMIN_OWNER_RELEASE_MISSING")?
        .edge_agent_sha256
        .as_slice();
    let executable = Path::new("/usr/local/libexec/sing-box/edge-agent");
    let meta = fs::symlink_metadata(executable).map_err(|_| "HOST_ADMIN_OWNER_UNAVAILABLE")?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o777 != 0o755
        || meta.len() == 0
        || meta.len() > 32 * 1024 * 1024
    {
        return Err("HOST_ADMIN_OWNER_UNTRUSTED".into());
    }
    if sha256(&fs::read(executable).map_err(|_| "HOST_ADMIN_OWNER_READ_FAILED")?) != expected {
        return Err("HOST_ADMIN_OWNER_SOURCE_DRIFT".into());
    }
    let access_identity = vm_credential_access_identity_path(Path::new(DEFAULT_STACK_DIR))?;
    edge_secrets::diagnose_canonical_host_access(&access_identity)
        .await
        .map_err(str::to_owned)?;
    let auth =
        edge_secrets::request_canonical_native_admin_authorization(&raw, &access_identity).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?
        .as_secs();
    host_admin::verify_authorization(&request, &auth, &trust.pinned_worker_public_key, now)
        .map_err(str::to_owned)?;

    // One BEGIN, sync before effects. A crash or an ambiguous ACK leaves the
    // pending marker and never silently retries an arbitrary native process.
    let key = journal_key(&host_admin::operation_id(&request));
    let pending = journal.join(format!("admin-{key}.pending.pb"));
    let terminal = journal.join(format!("admin-{key}.terminal.pb"));
    if fs::symlink_metadata(&terminal).is_ok() {
        return Err("HOST_ADMIN_TERMINAL_ALREADY_EXISTS_NO_REPLAY".into());
    }
    durable_create(&pending, &raw)?;

    // FULL native root capability: no executable/interpreter/argv/cwd allowlist.
    // A script interpreter may be selected by the authenticated request.
    let mut cmd = OsCommand::new("/usr/bin/timeout");
    cmd.args(["--kill-after=5s", &format!("{}s", request.timeout_seconds)])
        .arg(&request.argv[0])
        .args(&request.argv[1..])
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C")
        .current_dir(if request.working_directory.is_empty() {
            "/"
        } else {
            request.working_directory.as_str()
        })
        .stdin(OsStdio::piped())
        .stdout(OsStdio::piped())
        .stderr(OsStdio::piped());
    for item in &request.environment {
        let (name, value) = item.split_once('=').ok_or("HOST_ADMIN_ENV_ENTRY_INVALID")?;
        cmd.env(name, value);
    }
    let mut child = cmd
        .spawn()
        .map_err(|_| "HOST_ADMIN_PROCESS_START_UNKNOWN_NO_REPLAY")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or("HOST_ADMIN_CHILD_STDIN_UNAVAILABLE")?;
    let input = request.stdin_bytes.clone();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let stdout = child
        .stdout
        .take()
        .ok_or("HOST_ADMIN_CHILD_STDOUT_UNAVAILABLE")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("HOST_ADMIN_CHILD_STDERR_UNAVAILABLE")?;
    let stdout_reader = std::thread::spawn(move || capture_stream(stdout));
    let stderr_reader = std::thread::spawn(move || capture_stream(stderr));
    let exit = child
        .wait()
        .map_err(|_| "HOST_ADMIN_CHILD_WAIT_UNKNOWN_NO_REPLAY")?;
    // A child may exit without reading its entire stdin. BrokenPipe is then
    // an ordinary child outcome, not proof of an unknown side effect.
    let input_result = writer
        .join()
        .map_err(|_| "HOST_ADMIN_STDIN_JOIN_UNKNOWN_NO_REPLAY")?;
    if let Err(error) = input_result {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            return Err("HOST_ADMIN_STDIN_IO_UNKNOWN_NO_REPLAY".into());
        }
    }
    let out = stdout_reader
        .join()
        .map_err(|_| "HOST_ADMIN_STDOUT_JOIN_UNKNOWN_NO_REPLAY")?
        .map_err(|_| "HOST_ADMIN_STDOUT_IO_UNKNOWN_NO_REPLAY")?;
    let err = stderr_reader
        .join()
        .map_err(|_| "HOST_ADMIN_STDERR_JOIN_UNKNOWN_NO_REPLAY")?
        .map_err(|_| "HOST_ADMIN_STDERR_IO_UNKNOWN_NO_REPLAY")?;

    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?
        .as_secs();
    let mut receipt = FleetNativeAdminResult {
        schema_version: 1,
        machine_id: request.machine_id.clone(),
        operation_id: host_admin::operation_id(&request),
        request_sha256: sha256(&raw),
        observed_at_unix: observed_at,
        exit_code: exit.code().unwrap_or(-1),
        stdout_sha256: out.sha256,
        stderr_sha256: err.sha256,
        process_exited: exit.code().is_some(),
        root_signature: Vec::new(),
        stdout_preview: if request.publish_output { out.preview } else { Vec::new() },
        stderr_preview: if request.publish_output { err.preview } else { Vec::new() },
        stdout_total_bytes: out.total_bytes,
        stderr_total_bytes: err.total_bytes,
        stdout_truncated: out.total_bytes > PREVIEW_LIMIT as u64,
        stderr_truncated: err.total_bytes > PREVIEW_LIMIT as u64,
    };
    host_admin::sign_receipt(&request, &mut receipt, &key_bytes).map_err(str::to_owned)?;
    durable_create(&terminal, &receipt.encode_to_vec())?;
    if receipt.process_exited {
        fs::remove_file(&pending).map_err(|_| "HOST_ADMIN_PENDING_CLEAR_UNKNOWN_NO_REPLAY")?;
        File::open(&journal)
            .and_then(|f| f.sync_all())
            .map_err(|_| "HOST_ADMIN_TERMINAL_SYNC_UNKNOWN_NO_REPLAY")?;
    }
    // Preview bytes are present only under the exact Worker-signed explicit
    // publish_output opt-in. The default result carries hashes and counts.
    io::stdout()
        .write_all(&receipt.encode_to_vec())
        .map_err(|_| "HOST_ADMIN_SIGNED_RESULT_DELIVERY_UNAVAILABLE")?;
    if receipt.process_exited {
        Ok(())
    } else {
        Err("HOST_ADMIN_COMPLETION_UNKNOWN_NO_REPLAY".into())
    }
}
