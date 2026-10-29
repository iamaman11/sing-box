//! Native Windows process effects for the EXISTING SYSTEM owner. No shell
//! wrapping, service, task or alternate transport. Also tested unprivileged.
use edge_shared_types::{FleetNativeAdminRequest, FleetNativeAdminResult};
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    System::{JobObjects::*, Pipes::*, Threading::*},
};

const PREVIEW: usize = 64 * 1024;
const CAPTURE: usize = 16 * 1024 * 1024;
const DRAIN: Duration = Duration::from_secs(2);
pub(crate) fn sha(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

// Microsoft CRT argv rules. lpApplicationName is independently explicit;
// cmd.exe/PowerShell syntax, if requested, belongs to signed argv, not us.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in s.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            '\\',
            if ch == '"' { slashes * 2 + 1 } else { slashes },
        ));
        out.push(ch);
        slashes = 0;
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}

fn pipe(parent_reads: bool) -> Result<(File, File), &'static str> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut r, mut w) = (std::ptr::null_mut(), std::ptr::null_mut());
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 65536) } == 0 {
        return Err("HOST_ADMIN_PIPE_CREATE_FAILED");
    }
    let read = unsafe { File::from_raw_handle(r) };
    let write = unsafe { File::from_raw_handle(w) };
    let parent = if parent_reads { r } else { w };
    if unsafe { SetHandleInformation(parent, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err("HOST_ADMIN_PIPE_INHERITANCE_FAILED");
    }
    Ok((read, write))
}
struct Attributes {
    _storage: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn handles(handles: &[HANDLE]) -> Result<Self, &'static str> {
        let mut len = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut len);
        }
        if len == 0 {
            return Err("HOST_ADMIN_HANDLE_LIST_SIZE_FAILED");
        }
        let mut storage = vec![0usize; len.div_ceil(std::mem::size_of::<usize>())];
        let list = storage.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut len) } == 0 {
            return Err("HOST_ADMIN_HANDLE_LIST_CREATE_FAILED");
        }
        let attrs = Self {
            _storage: storage,
            list,
        };
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err("HOST_ADMIN_HANDLE_LIST_SET_FAILED");
        }
        Ok(attrs)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

struct Stream {
    digest: Vec<u8>,
    total: u64,
    saved: u64,
    preview: Vec<u8>,
    eof: bool,
}
fn drain(mut input: File, mut spool: File, done: Arc<AtomicBool>) -> Result<Stream, &'static str> {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut s = Stream {
        digest: Vec::new(),
        total: 0,
        saved: 0,
        preview: Vec::new(),
        eof: false,
    };
    let mut buf = [0; 16384];
    let mut post_exit = None;
    loop {
        if done.load(Ordering::Acquire)
            && post_exit.get_or_insert_with(Instant::now).elapsed() >= DRAIN
        {
            break;
        }
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                input.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                s.eof = true;
                break;
            }
            return Err("HOST_ADMIN_PIPE_PEEK_UNKNOWN_NO_REPLAY");
        }
        if available == 0 {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        let limit = (available as usize).min(buf.len());
        let n = input
            .read(&mut buf[..limit])
            .map_err(|_| "HOST_ADMIN_PIPE_READ_UNKNOWN_NO_REPLAY")?;
        if n == 0 {
            s.eof = true;
            break;
        }
        hash.update(&buf[..n]);
        s.total += n as u64;
        s.preview
            .extend_from_slice(&buf[..n.min(PREVIEW.saturating_sub(s.preview.len()))]);
        let keep = n.min(CAPTURE.saturating_sub(s.saved as usize));
        spool
            .write_all(&buf[..keep])
            .map_err(|_| "HOST_ADMIN_CAPTURE_UNKNOWN_NO_REPLAY")?;
        s.saved += keep as u64;
    }
    spool
        .sync_all()
        .map_err(|_| "HOST_ADMIN_CAPTURE_SYNC_UNKNOWN_NO_REPLAY")?;
    s.digest = hash.finish().as_ref().to_vec();
    Ok(s)
}

/// Returns only process evidence. Caller owns authorization, BEGIN, signing
/// and terminal persistence. Closing the Job always terminates descendants.
pub(crate) fn run(
    request: &FleetNativeAdminRequest,
    out: File,
    err: File,
) -> Result<FleetNativeAdminResult, &'static str> {
    run_with_assignment(request, out, err, |job, process| unsafe {
        AssignProcessToJobObject(job, process) != 0
    })
}

fn run_with_assignment(
    request: &FleetNativeAdminRequest,
    out: File,
    err: File,
    assign: impl FnOnce(HANDLE, HANDLE) -> bool,
) -> Result<FleetNativeAdminResult, &'static str> {
    edge_shared_types::host_admin::validate_for_kind(
        request,
        edge_shared_types::FleetHostKind::Windows,
    )?;
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err("HOST_ADMIN_JOB_CREATE_FAILED_NO_REPLAY");
    }
    let job = Handle(job);
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err("HOST_ADMIN_JOB_LIMITS_FAILED_NO_REPLAY");
    }
    let (stdin_child, mut stdin_parent) = pipe(false)?;
    let (stdout_parent, stdout_child) = pipe(true)?;
    let (stderr_parent, stderr_child) = pipe(true)?;
    let handles = [
        stdin_child.as_raw_handle(),
        stdout_child.as_raw_handle(),
        stderr_child.as_raw_handle(),
    ];
    let attrs = Attributes::handles(&handles)?;
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of_val(&startup) as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attrs.list;
    let application = wide(&request.argv[0]);
    let mut command = wide(
        &request
            .argv
            .iter()
            .map(|s| quote(s))
            .collect::<Vec<_>>()
            .join(" "),
    );
    // No inherited token-bearing environment. Exact signed entries overlay
    // only essential Windows runtime locations, never hidden credentials.
    let mut env = std::collections::BTreeMap::new();
    for name in ["SystemRoot", "WINDIR"] {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.to_uppercase(), value);
        }
    }
    for entry in &request.environment {
        let (k, v) = entry.split_once('=').ok_or("HOST_ADMIN_ENV_INVALID")?;
        env.insert(k.to_uppercase(), v.into());
    }
    let mut environment: Vec<u16> = env
        .into_iter()
        .flat_map(|(k, v)| wide(&format!("{k}={v}")))
        .collect();
    environment.push(0);
    if environment.len() == 1 {
        environment.push(0);
    }
    let cwd = wide(if request.working_directory.is_empty() {
        r"C:\"
    } else {
        &request.working_directory
    });
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_NO_WINDOW
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err("HOST_ADMIN_PROCESS_START_FAILED_NO_REPLAY");
    }
    let process = Handle(info.hProcess);
    let thread = Handle(info.hThread);
    if !assign(job.0, process.0) {
        unsafe {
            TerminateProcess(process.0, 125);
            WaitForSingleObject(process.0, 5000);
        }
        return Err("HOST_ADMIN_JOB_ASSIGNMENT_FAILED_NO_EXECUTION");
    }
    drop(stdin_child);
    drop(stdout_child);
    drop(stderr_child);
    let done = Arc::new(AtomicBool::new(false));
    let out_done = done.clone();
    let err_done = done.clone();
    let stdout = std::thread::spawn(move || drain(stdout_parent, out, out_done));
    let stderr = std::thread::spawn(move || drain(stderr_parent, err, err_done));
    let input = request.stdin_bytes.clone();
    let writer = std::thread::spawn(move || {
        let mut count = 0;
        while count < input.len() {
            match stdin_parent.write(&input[count..]) {
                Ok(0) => break,
                Ok(n) => count += n,
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => break,
                Err(_) => return Err("HOST_ADMIN_STDIN_UNKNOWN_NO_REPLAY"),
            }
        }
        Ok(count as u64)
    });
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        return Err("HOST_ADMIN_RESUME_UNKNOWN_NO_REPLAY");
    }
    let wait = unsafe { WaitForSingleObject(process.0, request.timeout_seconds * 1000) };
    let timeout = wait == WAIT_TIMEOUT;
    if wait != WAIT_OBJECT_0 && !timeout {
        return Err("HOST_ADMIN_WAIT_UNKNOWN_NO_REPLAY");
    }
    // A completed direct child must not leave unbounded grandchildren alive.
    if unsafe { TerminateJobObject(job.0, if timeout { 124 } else { 125 }) } == 0 {
        return Err("HOST_ADMIN_JOB_TERMINATION_UNKNOWN_NO_REPLAY");
    }
    if unsafe { WaitForSingleObject(process.0, 5000) } != WAIT_OBJECT_0 {
        return Err("HOST_ADMIN_EXIT_UNKNOWN_NO_REPLAY");
    }
    let mut exit = 0;
    if unsafe { GetExitCodeProcess(process.0, &mut exit) } == 0 {
        return Err("HOST_ADMIN_EXIT_CODE_UNKNOWN_NO_REPLAY");
    }
    done.store(true, Ordering::Release);
    // Kernel pipe closure follows Job termination; cancellation is bounded
    // even if a foreign process acquired a pipe handle.
    let deadline = Instant::now() + Duration::from_secs(4);
    while !writer.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if !writer.is_finished() {
        use std::os::windows::io::AsRawHandle;
        unsafe {
            windows_sys::Win32::System::IO::CancelSynchronousIo(writer.as_raw_handle());
        }
        return Err("HOST_ADMIN_STDIN_DRAIN_UNKNOWN_NO_REPLAY");
    }
    let written = writer
        .join()
        .map_err(|_| "HOST_ADMIN_STDIN_JOIN_UNKNOWN_NO_REPLAY")??;
    let out = stdout
        .join()
        .map_err(|_| "HOST_ADMIN_STDOUT_JOIN_UNKNOWN_NO_REPLAY")??;
    let err = stderr
        .join()
        .map_err(|_| "HOST_ADMIN_STDERR_JOIN_UNKNOWN_NO_REPLAY")??;
    Ok(FleetNativeAdminResult {
        exit_code: if timeout { 124 } else { exit as i32 },
        process_exited: true,
        stdout_sha256: out.digest,
        stderr_sha256: err.digest,
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
        stdout_total_bytes: out.total,
        stderr_total_bytes: err.total,
        stdout_truncated: out.total > PREVIEW as u64,
        stderr_truncated: err.total > PREVIEW as u64,
        stdout_capture_bytes: out.saved,
        stderr_capture_bytes: err.saved,
        stdout_capture_complete: out.saved == out.total,
        stderr_capture_complete: err.saved == err.total,
        stdout_stream_eof: out.eof,
        stderr_stream_eof: err.eof,
        stdin_bytes_written: written,
        stdin_input_complete: written == request.stdin_bytes.len() as u64,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn command(script: &str, timeout: u32) -> FleetNativeAdminRequest {
        FleetNativeAdminRequest {
            schema_version: 1,
            machine_id: "test".into(),
            source_comment_id: 1,
            release_set_sha256: vec![1; 32],
            comment_sha256: vec![2; 32],
            requested_at_unix: 1,
            argv: vec![
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                script.into(),
            ],
            timeout_seconds: timeout,
            publish_output: true,
            ..Default::default()
        }
    }
    #[test]
    fn admin_job_assignment_precedes_execution() {
        let root =
            std::env::temp_dir().join(format!("edge-admin-job-assignment-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let sentinel = root.join("must-not-exist");
        let script = format!(
            "[IO.File]::WriteAllText('{}','executed')",
            sentinel.display()
        );
        let result = run_with_assignment(
            &command(&script, 10),
            File::create(root.join("out")).unwrap(),
            File::create(root.join("err")).unwrap(),
            |_, _| false,
        );
        assert_eq!(
            result.unwrap_err(),
            "HOST_ADMIN_JOB_ASSIGNMENT_FAILED_NO_EXECUTION"
        );
        assert!(!sentinel.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    // The native test executable is its own deterministic child fixture.
    // Neither PowerShell startup nor ShellExecute may hide a broken Job
    // assignment; all descendants must be killed by the real Windows Job.
    #[test]
    fn admin_job_descendant_helper() {
        match std::env::var("EDGE_ADMIN_JOB_TEST_STAGE").as_deref() {
            Ok("parent") => {
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "windows_admin::process::tests::admin_job_descendant_helper",
                        "--nocapture",
                    ])
                    .env("EDGE_ADMIN_JOB_TEST_STAGE", "descendant")
                    .spawn()
                    .unwrap();
                println!("EDGE_ADMIN_DESCENDANT_PID={}", child.id());
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }
            Ok("descendant") => {
                println!("EDGE_ADMIN_DESCENDANT_READY");
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }
            _ => {}
        }
    }
    #[test]
    fn admin_timeout_terminates_descendant_tree() {
        let root =
            std::env::temp_dir().join(format!("edge-admin-job-timeout-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut request = command("unused", 10);
        request.argv = vec![
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            "--exact".into(),
            "windows_admin::process::tests::admin_job_descendant_helper".into(),
            "--nocapture".into(),
        ];
        request
            .environment
            .push("EDGE_ADMIN_JOB_TEST_STAGE=parent".into());
        let began = Instant::now();
        let result = run(
            &request,
            File::create(root.join("out")).unwrap(),
            File::create(root.join("err")).unwrap(),
        )
        .unwrap();
        assert!(began.elapsed() < Duration::from_secs(20));
        assert_eq!(result.exit_code, 124);
        let stdout = String::from_utf8_lossy(&result.stdout_preview);
        let id: u32 = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("EDGE_ADMIN_DESCENDANT_PID="))
            .unwrap_or_else(|| {
                panic!(
                    "native descendant PID not observed; stdout={stdout:?}; stderr={:?}",
                    String::from_utf8_lossy(&result.stderr_preview)
                )
            })
            .parse()
            .unwrap();
        assert!(
            stdout.contains("EDGE_ADMIN_DESCENDANT_READY"),
            "native descendant never ran; stdout={stdout:?}; stderr={:?}",
            String::from_utf8_lossy(&result.stderr_preview)
        );
        let child = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                id,
            )
        };
        if !child.is_null() {
            let child = Handle(child);
            assert_eq!(unsafe { WaitForSingleObject(child.0, 5000) }, WAIT_OBJECT_0);
        } else {
            assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_PARAMETER);
        }
        assert!(result.stdout_stream_eof && result.stderr_stream_eof);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn windows_argv_quoting_preserves_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("a b"), "\"a b\"");
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote("c:\\a\\"), "\"c:\\a\\\\\"");
    }
    #[test]
    fn admin_pipes_are_bounded_and_concurrent() {
        let root = std::env::temp_dir().join(format!("edge-admin-native-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let script = r"$ErrorActionPreference='Stop';$o=[Console]::OpenStandardOutput();$e=[Console]::OpenStandardError();$b=New-Object byte[] 1048576;$o.Write($b,0,$b.Length);$e.Write($b,0,$b.Length);[Console]::In.ReadToEnd() > $null";
        let request = FleetNativeAdminRequest {
            schema_version: 1,
            machine_id: "test".into(),
            source_comment_id: 1,
            release_set_sha256: vec![1; 32],
            comment_sha256: vec![2; 32],
            requested_at_unix: 1,
            argv: vec![
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                script.into(),
            ],
            stdin_bytes: vec![b'x'; 8192],
            timeout_seconds: 30,
            ..Default::default()
        };
        let result = run(
            &request,
            File::create(root.join("out")).unwrap(),
            File::create(root.join("err")).unwrap(),
        )
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout_total_bytes, 1048576);
        assert_eq!(result.stderr_total_bytes, 1048576);
        assert!(result.stdin_input_complete);
        assert!(result.stdout_stream_eof && result.stderr_stream_eof);
        assert!(result.stdout_preview.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
