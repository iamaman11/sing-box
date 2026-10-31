//! The sole native root executor of explicitly signed, arbitrary VM programs.
//! GitHub runner forwards protobuf stdin, never chooses root effects.
use super::*;
use edge_shared_types::{FleetNativeAdminResult, ReleaseSet, host_admin};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::process::{Command as OsCommand, Stdio as OsStdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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
// A new Worker signature authenticates arbitrary root execution; it does
// NOT prove read-only behavior. No generic ADMIN may bypass a retained
// resource or ADMIN BEGIN. The existing /host diagnose and signed RECOVER
// paths remain the way to observe and reconcile an unknown mutation.
fn independent_admin_operation_available(journal: &Path, operation_id: &str) -> Result<(), String> {
    independent_admin_operation_available_for_uid(journal, operation_id, 0)
}

fn independent_admin_operation_available_for_uid(
    journal: &Path,
    operation_id: &str,
    expected_uid: u32,
) -> Result<(), String> {
    let key = journal_key(operation_id);
    let own = [
        format!("admin-{key}.pending.pb"),
        format!("admin-{key}.terminal.pb"),
        format!("{key}.pb"),
    ];
    // Full protected scan rejects an untrusted later entry even when an
    // earlier pending operation is found. Never normalize ACLs or delete it.
    if host_native::protected_journal_has_pending_for_uid(journal, expected_uid)? {
        return Err("HOST_ADMIN_PENDING_UNKNOWN_NO_REPLAY".into());
    }
    for name in own {
        match fs::symlink_metadata(journal.join(name)) {
            Ok(_) => return Err("HOST_ADMIN_SAME_OPERATION_EXISTS_NO_REPLAY".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("HOST_ADMIN_JOURNAL_UNAVAILABLE_NO_REPLAY".into()),
        }
    }
    Ok(())
}
// Never stop draining a pipe because the retained evidence is full.
const PREVIEW_LIMIT: usize = 64 * 1024;
const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
struct CapturedStream {
    sha256: Vec<u8>,
    total_bytes: u64,
    preview: Vec<u8>,
    capture_bytes: u64,
}
fn capture_stream(input: impl Read) -> std::io::Result<CapturedStream> {
    capture_stream_with_file(input, None)
}
fn capture_stream_with_file(
    mut input: impl Read,
    mut spool: Option<File>,
) -> std::io::Result<CapturedStream> {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    let mut preview = Vec::new();
    let mut capture_bytes = 0_u64;
    loop {
        let len = input.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(len as u64);
        hash.update(&buffer[..len]);
        let retain = PREVIEW_LIMIT.saturating_sub(preview.len()).min(len);
        preview.extend_from_slice(&buffer[..retain]);
        if let Some(ref mut file) = spool {
            let save = CAPTURE_LIMIT
                .saturating_sub(capture_bytes as usize)
                .min(len);
            if save > 0 {
                file.write_all(&buffer[..save])?;
                capture_bytes += save as u64;
            }
        }
    }
    if let Some(file) = spool {
        file.sync_all()?;
    }
    Ok(CapturedStream {
        sha256: hash.finish().as_ref().to_vec(),
        total_bytes,
        preview,
        capture_bytes,
    })
}
// Bounded Linux poll: a background process may inherit pipes after its
// authorized direct child exits. Never confuse a synthetic end with EOF.
#[repr(C)]
struct PipePollFd {
    fd: i32,
    events: i16,
    revents: i16,
}
unsafe extern "C" {
    fn poll(fds: *mut PipePollFd, nfds: usize, timeout_ms: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}
const POST_EXIT_DRAIN: Duration = Duration::from_secs(2);
const LINUX_F_GETFL: i32 = 3;
const LINUX_F_SETFL: i32 = 4;
const LINUX_O_NONBLOCK: i32 = 0o4000;
const POLL_OUT: i16 = 4;

/// A direct child may exit before consuming stdin while a descendant retains
/// its read descriptor. Never let a blocking write hold the root lock forever.
/// A partial write is evidence for no-replay, not an authorization to retry.
fn write_stdin_bounded(
    mut output: impl Write + AsRawFd,
    input: &[u8],
    child_exited: Arc<AtomicBool>,
) -> std::io::Result<u64> {
    if input.is_empty() {
        return Ok(0);
    }
    let fd = output.as_raw_fd();
    let flags = unsafe { fcntl(fd, LINUX_F_GETFL) };
    if flags < 0 || unsafe { fcntl(fd, LINUX_F_SETFL, flags | LINUX_O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut written = 0usize;
    let mut post_exit_started = None;
    while written < input.len() {
        if child_exited.load(Ordering::Acquire) {
            let since = *post_exit_started.get_or_insert_with(Instant::now);
            if since.elapsed() >= POST_EXIT_DRAIN {
                return Ok(written as u64);
            }
        }
        let mut ready_fd = PipePollFd {
            fd,
            events: POLL_OUT,
            revents: 0,
        };
        let ready = unsafe { poll(&mut ready_fd, 1, 100) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if ready == 0 {
            continue;
        }
        match output.write(&input[written..]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => written += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => return Ok(written as u64),
            Err(err) => return Err(err),
        }
    }
    Ok(written as u64)
}

/// A terminal receipt may coexist with a pending marker: never clear pending
/// when a child exits but input or a pipe remains observably incomplete.
fn complete_execution(
    process_exited: bool,
    input_complete: bool,
    stdout_eof: bool,
    stderr_eof: bool,
) -> bool {
    process_exited && input_complete && stdout_eof && stderr_eof
}

struct ExitBoundedPipe<R> {
    inner: R,
    child_exited: Arc<AtomicBool>,
    observed_eof: Arc<AtomicBool>,
    post_exit_started: Option<Instant>,
}
impl<R: Read + AsRawFd> Read for ExitBoundedPipe<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.child_exited.load(Ordering::Acquire) {
                let start = *self.post_exit_started.get_or_insert_with(Instant::now);
                if start.elapsed() >= POST_EXIT_DRAIN {
                    // Bounded stream ended without kernel EOF: mark incomplete.
                    return Ok(0);
                }
            }
            let mut fd = PipePollFd {
                fd: self.inner.as_raw_fd(),
                events: 1,
                revents: 0,
            };
            let ready = unsafe { poll(&mut fd, 1, 100) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            let n = self.inner.read(buffer)?;
            if n == 0 {
                self.observed_eof.store(true, Ordering::Release);
            }
            return Ok(n);
        }
    }
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
                "8s",
                "/bin/sh",
                "-c",
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
    #[test]
    fn inherited_background_pipe_is_bounded_and_marked_incomplete() {
        let mut child = OsCommand::new("/bin/sh")
            .args(["-c", "sleep 10 & exit 0"])
            .stdin(OsStdio::null())
            .stdout(OsStdio::piped())
            .stderr(OsStdio::piped())
            .spawn()
            .unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicBool::new(false));
        let source = ExitBoundedPipe {
            inner: child.stdout.take().unwrap(),
            child_exited: Arc::clone(&done),
            observed_eof: Arc::clone(&observed),
            post_exit_started: None,
        };
        let worker = std::thread::spawn(move || capture_stream(source).unwrap());
        let began = Instant::now();
        assert!(child.wait().unwrap().success());
        done.store(true, Ordering::Release);
        let result = worker.join().unwrap();
        assert!(began.elapsed() < Duration::from_secs(7));
        assert!(!observed.load(Ordering::Acquire));
        assert_eq!(result.total_bytes, 0);
    }

    #[test]
    fn inherited_stdin_reader_cannot_block_root_lock_indefinitely() {
        use std::os::unix::net::UnixStream;
        let (writer, inherited_reader) = UnixStream::pair().unwrap();
        let direct_child_exited = Arc::new(AtomicBool::new(true));
        let bytes = vec![0x41; 2 * 1024 * 1024];
        let start = Instant::now();
        let delivered = write_stdin_bounded(writer, &bytes, direct_child_exited).unwrap();
        assert!(start.elapsed() < Duration::from_secs(7));
        assert!(delivered < bytes.len() as u64);
        assert!(!complete_execution(true, false, true, true));
        drop(inherited_reader);
    }

    #[test]
    fn complete_stdin_and_all_eof_permit_terminal_marker_cleanup() {
        use std::os::unix::net::UnixStream;
        let (writer, mut reader) = UnixStream::pair().unwrap();
        let input = vec![0x42; 4096];
        let delivered =
            write_stdin_bounded(writer, &input, Arc::new(AtomicBool::new(false))).unwrap();
        assert_eq!(delivered, input.len() as u64);
        let mut actual = vec![0; input.len()];
        reader.read_exact(&mut actual).unwrap();
        assert_eq!(actual, input);
        assert!(complete_execution(true, true, true, true));
        assert!(!complete_execution(false, true, true, true));
        assert!(!complete_execution(true, true, false, true));
        assert!(!complete_execution(true, true, true, false));
    }

    #[test]
    fn arbitrary_vm_admin_never_bypasses_unknown_resource_or_other_admin() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("sing-box-independent-admin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let foreign = dir.join("resource-existing.pending.pb");
        durable_create(&foreign, b"foreign-original").unwrap();
        let current = "issue1-comment-987654321";
        let uid = std::fs::metadata(&dir).unwrap().uid();
        assert_eq!(
            independent_admin_operation_available_for_uid(&dir, current, uid),
            Err("HOST_ADMIN_PENDING_UNKNOWN_NO_REPLAY".into())
        );
        assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign-original");
        std::fs::remove_file(&foreign).unwrap();
        let other = dir.join("admin-other.pending.pb");
        durable_create(&other, b"another operation").unwrap();
        assert_eq!(
            independent_admin_operation_available_for_uid(&dir, current, uid),
            Err("HOST_ADMIN_PENDING_UNKNOWN_NO_REPLAY".into())
        );
        std::fs::remove_file(other).unwrap();
        assert!(independent_admin_operation_available_for_uid(&dir, current, uid).is_ok());
        let own = dir.join(format!("admin-{}.terminal.pb", journal_key(current)));
        durable_create(&own, b"completed").unwrap();
        assert_eq!(
            independent_admin_operation_available_for_uid(&dir, current, uid),
            Err("HOST_ADMIN_SAME_OPERATION_EXISTS_NO_REPLAY".into())
        );
        assert_eq!(std::fs::read(&own).unwrap(), b"completed");
        std::fs::remove_file(own).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn fsynced_begin_cannot_be_replayed_after_lost_ack() {
        let dir = std::env::temp_dir().join(format!("sing-box-admin-proof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("one.pending.pb");
        if marker.exists() {
            std::fs::remove_file(&marker).unwrap();
        }
        durable_create(&marker, b"original").unwrap();
        assert!(durable_create(&marker, b"retry").is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), b"original");
        std::fs::remove_file(marker).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}

pub(super) async fn execute() -> Result<(), String> {
    let mut raw = Vec::new();
    io::stdin()
        .take((host_admin::MAX_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "HOST_ADMIN_REQUEST_STDIN_UNAVAILABLE")?;
    let request = host_admin::decode(&raw).map_err(str::to_owned)?;
    host_admin::validate_for_kind(&request, edge_shared_types::FleetHostKind::Vm)
        .map_err(str::to_owned)?;
    let _lock = host_native::owner_operation_lock()?;
    let journal = Path::new(host_native::TRUSTED_ROOT).join("journal");
    let metadata = fs::symlink_metadata(&journal).map_err(|_| "HOST_ADMIN_JOURNAL_UNAVAILABLE")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
        return Err("HOST_ADMIN_JOURNAL_UNTRUSTED".into());
    }
    // Refuse unknown effects BEFORE requesting a one-shot Worker signature.
    // The existing root journal owns every mutating scope, including ADMIN.
    let operation_id = host_admin::operation_id(&request);
    independent_admin_operation_available(&journal, &operation_id)?;
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

    // Recheck after authorization, immediately before durable BEGIN. A
    // signature cannot turn a previously unknown mutation into a safe replay.
    independent_admin_operation_available(&journal, &operation_id)?;
    let key = journal_key(&operation_id);
    let pending = journal.join(format!("admin-{key}.pending.pb"));
    let terminal = journal.join(format!("admin-{key}.terminal.pb"));
    if fs::symlink_metadata(&terminal).is_ok() {
        return Err("HOST_ADMIN_TERMINAL_ALREADY_EXISTS_NO_REPLAY".into());
    }
    durable_create(&pending, &raw)?;
    let stdout_capture = journal.join(format!("admin-{key}.stdout.bin"));
    let stderr_capture = journal.join(format!("admin-{key}.stderr.bin"));
    let open_capture = |path: &Path| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "HOST_ADMIN_OUTPUT_CAPTURE_UNAVAILABLE_NO_REPLAY")
    };
    let stdout_spool = open_capture(&stdout_capture)?;
    let stderr_spool = open_capture(&stderr_capture)?;

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
    let stdin = child
        .stdin
        .take()
        .ok_or("HOST_ADMIN_CHILD_STDIN_UNAVAILABLE")?;
    let child_exited = Arc::new(AtomicBool::new(false));
    let stdin_child_exited = Arc::clone(&child_exited);
    let input = request.stdin_bytes.clone();
    let writer = std::thread::spawn(move || write_stdin_bounded(stdin, &input, stdin_child_exited));
    let stdout = child
        .stdout
        .take()
        .ok_or("HOST_ADMIN_CHILD_STDOUT_UNAVAILABLE")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("HOST_ADMIN_CHILD_STDERR_UNAVAILABLE")?;
    let stdout_eof = Arc::new(AtomicBool::new(false));
    let stderr_eof = Arc::new(AtomicBool::new(false));
    let stdout_source = ExitBoundedPipe {
        inner: stdout,
        child_exited: Arc::clone(&child_exited),
        observed_eof: Arc::clone(&stdout_eof),
        post_exit_started: None,
    };
    let stderr_source = ExitBoundedPipe {
        inner: stderr,
        child_exited: Arc::clone(&child_exited),
        observed_eof: Arc::clone(&stderr_eof),
        post_exit_started: None,
    };
    let stdout_reader =
        std::thread::spawn(move || capture_stream_with_file(stdout_source, Some(stdout_spool)));
    let stderr_reader =
        std::thread::spawn(move || capture_stream_with_file(stderr_source, Some(stderr_spool)));
    let exit = child
        .wait()
        .map_err(|_| "HOST_ADMIN_CHILD_WAIT_UNKNOWN_NO_REPLAY")?;
    child_exited.store(true, Ordering::Release);
    // A child can exit without reading stdin. Record exactly what was sent,
    // rather than declaring an unknown EPIPE or retrying partial side effects.
    let stdin_bytes_written = writer
        .join()
        .map_err(|_| "HOST_ADMIN_STDIN_JOIN_UNKNOWN_NO_REPLAY")?
        .map_err(|_| "HOST_ADMIN_STDIN_IO_UNKNOWN_NO_REPLAY")?;
    let stdin_input_complete = stdin_bytes_written == request.stdin_bytes.len() as u64;
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
        stdout_preview: if request.publish_output {
            out.preview
        } else {
            Vec::new()
        },
        stderr_preview: if request.publish_output {
            err.preview
        } else {
            Vec::new()
        },
        stdout_total_bytes: out.total_bytes,
        stderr_total_bytes: err.total_bytes,
        stdout_truncated: out.total_bytes > PREVIEW_LIMIT as u64,
        stderr_truncated: err.total_bytes > PREVIEW_LIMIT as u64,
        stdout_capture_path: stdout_capture.to_string_lossy().into_owned(),
        stderr_capture_path: stderr_capture.to_string_lossy().into_owned(),
        stdout_capture_bytes: out.capture_bytes,
        stderr_capture_bytes: err.capture_bytes,
        stdout_capture_complete: out.capture_bytes == out.total_bytes,
        stderr_capture_complete: err.capture_bytes == err.total_bytes,
        stdout_stream_eof: stdout_eof.load(Ordering::Acquire),
        stderr_stream_eof: stderr_eof.load(Ordering::Acquire),
        stdin_bytes_written,
        stdin_input_complete,
        ..Default::default()
    };
    host_admin::sign_receipt(&request, &mut receipt, &key_bytes).map_err(str::to_owned)?;
    durable_create(&terminal, &receipt.encode_to_vec())?;
    let complete = complete_execution(
        receipt.process_exited,
        receipt.stdin_input_complete,
        receipt.stdout_stream_eof,
        receipt.stderr_stream_eof,
    );
    if complete {
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
    if complete {
        Ok(())
    } else {
        Err("HOST_ADMIN_COMPLETION_INCOMPLETE_NO_REPLAY".into())
    }
}
