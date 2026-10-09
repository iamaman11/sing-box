use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::ptr::null_mut;

use edge_shared_types::{
    LocalSingboxState, WindowsDatapathMode, canonical_production_desired_state,
    decode_windows_runtime_state,
};
use edge_singbox::{render_windows_config, sync_local_config};
#[cfg(not(windows))]
use sysinfo::Signal;
use sysinfo::{Pid, System};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetLastError, SetLastError, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NO_WINDOW, GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

const STARTUP_OBSERVATION_SECS: u64 = 10;
const STARTUP_OBSERVATION_INTERVAL_MS: u64 = 500;
const SMOKE_STARTUP_TIMEOUT_SECS: u64 = 8;
const SMOKE_IO_TIMEOUT_SECS: u64 = 5;
const SMOKE_RESPONSE_BODY: &str = "EDGE_NON_TUN_SMOKE_OK";
/*
 * Stage 4B.2-C: no independent recovery owner currently guarantees DNS continuity
 * for foreign CloudflareWARP when managed TUN 172.19.0.1/172.19.0.2 is removed.
 * Deliberately no override flag, optimistic DNS check, or silent fallback:
 * any destructive public entrypoint must refuse before the first mutation.
 * This does NOT guard ordinary ManagedTun -> ManagedTun accepted convergence.
 */
pub fn reject_unproven_windows_tun_teardown(operation: &str) -> Result<(), String> {
    Err(format!(
        "{operation} refused before mutation: independent CloudflareWARP DNS restoration and control-channel recovery are not proven for Windows managed TUN teardown"
    ))
}

#[derive(Debug, Clone)]
pub struct LocalRuntimePaths {
    pub singbox_binary_path: PathBuf,
    pub config_path: PathBuf,
    pub state_path: PathBuf,
    pub runtime_root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProcessObservation {
    pub pid: u32,
    pub name: String,
    pub executable_path: Option<String>,
    pub parent_pid: Option<u32>,
    pub command_line: String,
    pub config_path: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RuntimeProcessClassification {
    Managed(ProcessObservation),
    Conflicting(Vec<ProcessObservation>),
    Absent,
}

#[derive(Debug, Clone)]
pub struct RuntimeOperationResult {
    pub pid: Option<u32>,
    pub note: String,
    pub warnings: Vec<String>,
    pub local_singbox: LocalSingboxState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonTunSmokeResult {
    pub singbox_pid: u32,
    pub proxy_port: u16,
    pub origin_port: u16,
}

/// A candidate configuration which has been rendered and validated while the
/// currently running TUN is still serving traffic.  The active configuration
/// is never changed until this candidate has passed `sing-box check`.
struct StagedConfig {
    candidate_path: PathBuf,
    backup_path: PathBuf,
}

pub fn run_non_tun_loopback_smoke(
    singbox_binary_path: &Path,
    runtime_root: &Path,
) -> Result<NonTunSmokeResult, String> {
    if !singbox_binary_path.is_file() {
        return Err(format!(
            "sing-box binary was not found: {}",
            singbox_binary_path.display()
        ));
    }

    let smoke_root = runtime_root.join("smoke");
    fs::create_dir_all(&smoke_root).map_err(|err| {
        format!(
            "failed to prepare non-TUN smoke directory {}: {err}",
            smoke_root.display()
        )
    })?;

    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|err| format!("failed to reserve loopback smoke origin: {err}"))?;
    origin_listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to make smoke origin nonblocking: {err}"))?;
    let origin_port = origin_listener
        .local_addr()
        .map_err(|err| format!("failed to observe smoke origin address: {err}"))?
        .port();

    let proxy_reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|err| format!("failed to reserve loopback smoke proxy port: {err}"))?;
    let proxy_port = proxy_reservation
        .local_addr()
        .map_err(|err| format!("failed to observe smoke proxy address: {err}"))?
        .port();
    drop(proxy_reservation);

    let config_path = smoke_root.join("non-tun-smoke.json");
    let config = render_non_tun_smoke_config(proxy_port);
    fs::write(&config_path, config).map_err(|err| {
        format!(
            "failed to write non-TUN smoke config {}: {err}",
            config_path.display()
        )
    })?;
    validate_singbox_config(singbox_binary_path, &config_path)?;

    let stdout = File::create(smoke_root.join("sing-box.stdout.log"))
        .map_err(|err| format!("failed to open bounded smoke stdout log: {err}"))?;
    let stderr = File::create(smoke_root.join("sing-box.stderr.log"))
        .map_err(|err| format!("failed to open bounded smoke stderr log: {err}"))?;

    let mut command = Command::new(singbox_binary_path);
    command
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .current_dir(&smoke_root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);

    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to start exact sing-box smoke runtime: {err}"))?;
    let singbox_pid = child.id();
    let proxy_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, proxy_port);

    if let Err(err) = wait_for_smoke_listener(&mut child, proxy_addr) {
        best_effort_terminate(&mut child);
        return Err(err);
    }

    let origin_thread = thread::spawn(move || serve_smoke_origin(origin_listener));
    let request_result = request_through_smoke_proxy(proxy_addr, origin_port);
    let origin_result = origin_thread
        .join()
        .map_err(|_| "smoke origin thread panicked".to_owned())?;

    let cleanup_result = terminate_smoke_child(&mut child);
    if let Err(err) = request_result {
        return Err(match cleanup_result {
            Ok(()) => err,
            Err(cleanup_err) => format!("{err}; cleanup also failed: {cleanup_err}"),
        });
    }
    origin_result?;
    cleanup_result?;

    if TcpStream::connect_timeout(&SocketAddr::V4(proxy_addr), Duration::from_millis(400)).is_ok() {
        return Err("non-TUN smoke proxy listener leaked after cleanup".to_owned());
    }

    Ok(NonTunSmokeResult {
        singbox_pid,
        proxy_port,
        origin_port,
    })
}

fn render_non_tun_smoke_config(proxy_port: u16) -> String {
    format!(
        r#"{{"log":{{"level":"info","timestamp":true}},"inbounds":[{{"type":"mixed","tag":"smoke-in","listen":"127.0.0.1","listen_port":{proxy_port}}}],"outbounds":[{{"type":"direct","tag":"direct-out"}}],"route":{{"final":"direct-out"}}}}"#
    )
}

fn wait_for_smoke_listener(child: &mut Child, address: SocketAddrV4) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(SMOKE_STARTUP_TIMEOUT_SECS);
    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to observe sing-box smoke startup: {err}"))?
        {
            return Err(format!(
                "sing-box smoke runtime exited before listener readiness with status {status}"
            ));
        }

        if TcpStream::connect_timeout(&SocketAddr::V4(address), Duration::from_millis(200)).is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "sing-box smoke listener 127.0.0.1:{} did not become ready within {} seconds",
        address.port(),
        SMOKE_STARTUP_TIMEOUT_SECS
    ))
}

fn serve_smoke_origin(listener: TcpListener) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(SMOKE_IO_TIMEOUT_SECS);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(SMOKE_IO_TIMEOUT_SECS)))
                    .map_err(|err| format!("failed to bound smoke origin read: {err}"))?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(SMOKE_IO_TIMEOUT_SECS)))
                    .map_err(|err| format!("failed to bound smoke origin write: {err}"))?;
                let mut request = [0u8; 4096];
                let read = stream
                    .read(&mut request)
                    .map_err(|err| format!("failed to read proxied smoke request: {err}"))?;
                let request = String::from_utf8_lossy(&request[..read]);
                if !request.starts_with("GET /edge-smoke HTTP/") {
                    return Err("smoke origin received an unexpected request".to_owned());
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    SMOKE_RESPONSE_BODY.len(),
                    SMOKE_RESPONSE_BODY
                );
                stream
                    .write_all(response.as_bytes())
                    .map_err(|err| format!("failed to write smoke origin response: {err}"))?;
                stream
                    .flush()
                    .map_err(|err| format!("failed to flush smoke origin response: {err}"))?;
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("smoke origin did not receive a proxied request in time".to_owned());
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(format!("smoke origin accept failed: {err}")),
        }
    }
}

fn request_through_smoke_proxy(proxy_addr: SocketAddrV4, origin_port: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::V4(proxy_addr),
        Duration::from_secs(SMOKE_IO_TIMEOUT_SECS),
    )
    .map_err(|err| format!("failed to connect to non-TUN smoke proxy: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(SMOKE_IO_TIMEOUT_SECS)))
        .map_err(|err| format!("failed to bound smoke proxy read: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(SMOKE_IO_TIMEOUT_SECS)))
        .map_err(|err| format!("failed to bound smoke proxy write: {err}"))?;

    let request = format!(
        "GET http://127.0.0.1:{origin_port}/edge-smoke HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("failed to write non-TUN smoke proxy request: {err}"))?;
    stream
        .flush()
        .map_err(|err| format!("failed to flush non-TUN smoke proxy request: {err}"))?;

    let mut response = String::new();
    stream
        .take(64 * 1024)
        .read_to_string(&mut response)
        .map_err(|err| format!("failed to read non-TUN smoke proxy response: {err}"))?;
    if !response.contains(" 200 ") || !response.contains(SMOKE_RESPONSE_BODY) {
        return Err(
            "non-TUN smoke proxy round-trip did not return the expected response".to_owned(),
        );
    }
    Ok(())
}

fn terminate_smoke_child(child: &mut Child) -> Result<(), String> {
    if let Some(status) = child
        .try_wait()
        .map_err(|err| format!("failed to inspect smoke process before cleanup: {err}"))?
    {
        return Err(format!(
            "sing-box smoke runtime exited before explicit cleanup with status {status}"
        ));
    }
    child
        .kill()
        .map_err(|err| format!("failed to terminate sing-box smoke runtime: {err}"))?;
    child
        .wait()
        .map_err(|err| format!("failed to reap sing-box smoke runtime: {err}"))?;
    Ok(())
}

fn best_effort_terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

pub fn inspect_local_runtime(config_path: &Path) -> LocalSingboxState {
    let expected_config_path = config_path.display().to_string();
    let mut local = LocalSingboxState::placeholder(expected_config_path);
    let managed = exact_managed_runtime_processes(config_path);
    if managed.len() == 1 {
        local.process_running = true;
        local.managed_config = true;
        local.active_config_path = managed[0].config_path.clone();
    } else if managed.len() > 1 {
        local.process_running = true;
        local.warnings.push(format!(
            "multiple managed sing-box processes violate single-owner runtime: {}",
            managed
                .iter()
                .map(|process| format!("pid={} cmd={}", process.pid, process.command_line))
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }

    let managed_pids = managed
        .iter()
        .map(|process| process.pid)
        .collect::<Vec<_>>();
    if let RuntimeProcessClassification::Conflicting(processes) =
        classify_runtime_process(config_path)
    {
        let external = processes
            .iter()
            .filter(|process| !managed_pids.contains(&process.pid))
            .collect::<Vec<_>>();
        if !external.is_empty() {
            local.process_running = true;
            local.warnings.push(format!(
                "external sing-box process ownership observed: {}",
                external
                    .iter()
                    .map(|process| format!("pid={} cmd={}", process.pid, process.command_line))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
        }
    }

    if !local.process_running {
        local
            .warnings
            .push("managed sing-box process is not running".to_owned());
    }
    local
}

#[cfg(any(windows, test))]
fn proxy_only_external_coexistence_allowed(paths: &LocalRuntimePaths) -> Result<bool, String> {
    if !is_typed_runtime_state(&paths.state_path) {
        return Ok(false);
    }
    let desired = canonical_production_desired_state()?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "canonical production Windows datapath mode is invalid".to_owned())?;
    Ok(mode == WindowsDatapathMode::ProxyOnly)
}

pub fn start_local_runtime(
    paths: &LocalRuntimePaths,
    visible_window: bool,
) -> Result<RuntimeOperationResult, String> {
    start_local_runtime_with_policy(paths, visible_window, false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalStartDecision {
    NoopManaged,
    Activate,
}

fn local_start_decision(managed_present: bool, explicit_restart: bool) -> LocalStartDecision {
    if managed_present && !explicit_restart {
        LocalStartDecision::NoopManaged
    } else {
        LocalStartDecision::Activate
    }
}

fn start_local_runtime_with_policy(
    paths: &LocalRuntimePaths,
    visible_window: bool,
    explicit_restart: bool,
) -> Result<RuntimeOperationResult, String> {
    let mut managed = exact_managed_runtime_processes(&paths.config_path);
    if managed.len() > 1 {
        return Err(format!(
            "refusing managed runtime start with duplicate managed owners: {}",
            managed
                .iter()
                .map(|process| format!("pid={} cmd={}", process.pid, process.command_line))
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }
    let runtime = managed.pop();
    let classification = classify_runtime_process(&paths.config_path);
    if let RuntimeProcessClassification::Conflicting(processes) = &classification {
        #[cfg(windows)]
        if !proxy_only_external_coexistence_allowed(paths)? {
            return Err(format!(
                "refusing managed runtime start while conflicting sing-box ownership exists outside PROXY_ONLY mode: {}",
                processes
                    .iter()
                    .map(|process| format!("pid={} cmd={}", process.pid, process.command_line))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
        }

        #[cfg(not(windows))]
        return Err(format!(
            "refusing managed runtime start while conflicting sing-box process ownership exists: {}",
            processes
                .iter()
                .map(|process| format!("pid={} cmd={}", process.pid, process.command_line))
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }

    if local_start_decision(runtime.is_some(), explicit_restart) == LocalStartDecision::NoopManaged {
        let process = runtime.expect("noop requires exactly one managed owner");
        let local_singbox = inspect_local_runtime(&paths.config_path);
        return Ok(RuntimeOperationResult {
            pid: Some(process.pid),
            note: "NOOP_ALREADY_RUNNING: exact managed sing-box preserved; start never replaces a running TUN"
                .to_owned(),
            warnings: local_singbox.warnings.clone(),
            local_singbox,
        });
    }

    if !paths.singbox_binary_path.is_file() {
        return Err(format!(
            "sing-box binary was not found: {}",
            paths.singbox_binary_path.display()
        ));
    }

    // Do all fallible configuration work before taking down the exact managed process.
    // External sing-box processes are never stopped by this owner.
    let staged = stage_and_validate_config(paths)?;

    if let Some(process) = runtime.as_ref()
        && let Err(err) = stop_process(process.pid)
    {
        // The old TUN may still own DNS/routes: leave its active config untouched
        // and do not leak the rendered candidate on an unsuccessful stop.
        let _ = discard_staged_config(&staged);
        return Err(err);
    }

    if let Err(err) = activate_staged_config(paths, &staged) {
        return rollback_failed_transition(paths, runtime.as_ref(), &staged, err);
    }

    let mut child = match launch_singbox(paths, visible_window) {
        Ok(child) => child,
        Err(err) => {
            return rollback_failed_transition(paths, runtime.as_ref(), &staged, err);
        }
    };

    if let Err(err) = observe_startup(&mut child) {
        return rollback_failed_transition(paths, runtime.as_ref(), &staged, err);
    }

    let _ = discard_staged_config(&staged);
    let local_singbox = inspect_local_runtime(&paths.config_path);
    Ok(RuntimeOperationResult {
        pid: Some(child.id()),
        note: if visible_window {
            "local sing-box started in a visible window (validated guarded transition)".to_owned()
        } else {
            "local sing-box started (validated guarded transition)".to_owned()
        },
        warnings: local_singbox.warnings.clone(),
        local_singbox,
    })
}

#[cfg(windows)]
fn managed_tun_debug_privilege_required() -> Result<bool, String> {
    let desired = canonical_production_desired_state()?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "canonical production Windows datapath mode is invalid".to_owned())?;
    Ok(mode == WindowsDatapathMode::ManagedTun)
}

#[cfg(windows)]
fn spawn_with_temporary_debug_privilege(command: &mut Command) -> Result<Child, String> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(format!(
                "failed to open controller token for sing-box process lookup privilege: {}",
                GetLastError()
            ));
        }

        let result = (|| -> Result<Child, String> {
            let privilege_name = "SeDebugPrivilege"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let mut luid = std::mem::zeroed();
            if LookupPrivilegeValueW(null_mut(), privilege_name.as_ptr(), &mut luid) == 0 {
                return Err(format!(
                    "failed to resolve SeDebugPrivilege for managed sing-box child: {}",
                    GetLastError()
                ));
            }

            let requested = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let mut previous: TOKEN_PRIVILEGES = std::mem::zeroed();
            let mut previous_size = 0u32;
            SetLastError(ERROR_SUCCESS);
            if AdjustTokenPrivileges(
                token,
                0,
                &requested,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut previous,
                &mut previous_size,
            ) == 0
            {
                return Err(format!(
                    "failed to enable SeDebugPrivilege for managed sing-box child: {}",
                    GetLastError()
                ));
            }
            let enable_error = GetLastError();
            if enable_error == ERROR_NOT_ALL_ASSIGNED {
                return Err(
                    "controller token does not contain SeDebugPrivilege required by managed sing-box process routing"
                        .to_owned(),
                );
            }
            if enable_error != ERROR_SUCCESS {
                return Err(format!(
                    "unexpected SeDebugPrivilege enable result for managed sing-box child: {enable_error}"
                ));
            }

            let child_result = command.spawn();

            SetLastError(ERROR_SUCCESS);
            let restored = AdjustTokenPrivileges(token, 0, &previous, 0, null_mut(), null_mut());
            let restore_error = GetLastError();
            if restored == 0 || restore_error != ERROR_SUCCESS {
                if let Ok(mut child) = child_result {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                return Err(format!(
                    "controller SeDebugPrivilege restoration failed after sing-box spawn attempt: result={restored} error={restore_error}"
                ));
            }

            child_result.map_err(|err| format!("failed to start sing-box: {err}"))
        })();

        CloseHandle(token);
        result
    }
}

fn launch_singbox(
    paths: &LocalRuntimePaths,
    visible_window: bool,
) -> Result<std::process::Child, String> {
    let mut command = Command::new(&paths.singbox_binary_path);
    command.arg("run").arg("-c").arg(&paths.config_path);
    if let Some(parent) = paths.config_path.parent() {
        command.current_dir(parent);
    }

    #[cfg(windows)]
    if visible_window {
        command.creation_flags(CREATE_NEW_CONSOLE);
    } else {
        attach_runtime_logs(&mut command, &paths.runtime_root);
    }

    #[cfg(not(windows))]
    attach_runtime_logs(&mut command, &paths.runtime_root);

    #[cfg(windows)]
    {
        if managed_tun_debug_privilege_required()? {
            return spawn_with_temporary_debug_privilege(&mut command);
        }
    }

    command
        .spawn()
        .map_err(|err| format!("failed to start sing-box: {err}"))
}

pub fn stop_local_runtime(
    config_path: &Path,
    expected_config_only: bool,
) -> Result<RuntimeOperationResult, String> {
    let mut managed = exact_managed_runtime_processes(config_path);
    if managed.len() > 1 {
        return Err(format!(
            "refusing managed runtime stop with duplicate managed owners: {}",
            managed
                .iter()
                .map(|process| format!("pid={} cmd={}", process.pid, process.command_line))
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }
    let runtime = managed.pop();

    let Some(process) = runtime else {
        let local_singbox = inspect_local_runtime(config_path);
        let warnings = local_singbox.warnings.clone();
        return Ok(RuntimeOperationResult {
            pid: None,
            note: "managed sing-box is not running".to_owned(),
            warnings,
            local_singbox,
        });
    };

    if !expected_config_only {
        return Err(
            "unbounded sing-box stop is retired; ordinary runtime ownership may stop only the exact managed process"
                .to_owned(),
        );
    }

    stop_process(process.pid);
    let local_singbox = inspect_local_runtime(config_path);
    let warnings = local_singbox.warnings.clone();
    Ok(RuntimeOperationResult {
        pid: Some(process.pid),
        note: "exact managed sing-box stopped; external sing-box ownership was not mutated"
            .to_owned(),
        warnings,
        local_singbox,
    })
}

pub fn restart_local_runtime(paths: &LocalRuntimePaths) -> Result<RuntimeOperationResult, String> {
    start_local_runtime_with_policy(paths, false, true)
}

pub fn restart_local_runtime_visible(
    paths: &LocalRuntimePaths,
) -> Result<RuntimeOperationResult, String> {
    start_local_runtime_with_policy(paths, true, true)
}

fn stage_and_validate_config(paths: &LocalRuntimePaths) -> Result<StagedConfig, String> {
    let parent = paths.config_path.parent().ok_or_else(|| {
        format!(
            "managed config has no parent directory: {}",
            paths.config_path.display()
        )
    })?;
    let stem = paths
        .config_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            format!(
                "managed config has no usable filename: {}",
                paths.config_path.display()
            )
        })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock is before Unix epoch: {err}"))?
        .as_nanos();
    let candidate_path = parent.join(format!(".{stem}.next-{nonce}.json"));
    fs::copy(&paths.config_path, &candidate_path).map_err(|err| {
        format!(
            "failed to create staged sing-box config from {}: {err}",
            paths.config_path.display()
        )
    })?;

    let preparation = if is_typed_runtime_state(&paths.state_path) {
        fs::read(&paths.state_path)
            .map_err(|err| format!("unable to read typed Windows runtime state: {err}"))
            .and_then(|bytes| decode_windows_runtime_state(&bytes))
            .and_then(|state| render_windows_config(&state))
            .and_then(|rendered| {
                fs::write(&candidate_path, rendered).map_err(|err| {
                    format!("failed to render typed Windows candidate config: {err}")
                })
            })
    } else {
        sync_local_config(&candidate_path, &paths.state_path, &paths.runtime_root).map(|_| ())
    };
    if let Err(err) = preparation {
        let _ = fs::remove_file(&candidate_path);
        return Err(err);
    }
    if let Err(err) = validate_singbox_config(&paths.singbox_binary_path, &candidate_path) {
        let _ = fs::remove_file(&candidate_path);
        return Err(err);
    }

    fs::create_dir_all(&paths.runtime_root).map_err(|err| {
        format!(
            "failed to prepare local runtime directory {}: {err}",
            paths.runtime_root.display()
        )
    })?;
    Ok(StagedConfig {
        candidate_path,
        backup_path: paths.runtime_root.join("sing-box.last-known-good.json"),
    })
}

fn is_typed_runtime_state(state_path: &Path) -> bool {
    state_path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("pb"))
}

fn validate_singbox_config(binary: &Path, config: &Path) -> Result<(), String> {
    let output = Command::new(binary)
        .args(["check", "-c"])
        .arg(config)
        .output()
        .map_err(|err| format!("failed to run sing-box config preflight: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(if detail.is_empty() {
        format!(
            "sing-box rejected staged configuration with status {}",
            output.status
        )
    } else {
        format!("sing-box rejected staged configuration: {detail}")
    })
}

fn activate_staged_config(paths: &LocalRuntimePaths, staged: &StagedConfig) -> Result<(), String> {
    fs::copy(&paths.config_path, &staged.backup_path).map_err(|err| {
        format!(
            "failed to preserve last-known-good sing-box config at {}: {err}",
            staged.backup_path.display()
        )
    })?;
    fs::copy(&staged.candidate_path, &paths.config_path).map_err(|err| {
        format!(
            "failed to activate staged sing-box config {}: {err}",
            staged.candidate_path.display()
        )
    })?;
    Ok(())
}

fn rollback_failed_transition(
    paths: &LocalRuntimePaths,
    previous_runtime: Option<&ProcessObservation>,
    staged: &StagedConfig,
    startup_error: String,
) -> Result<RuntimeOperationResult, String> {
    let _ = restore_last_known_good_config(paths, staged);
    let _ = discard_staged_config(staged);

    // A restarted TUN necessarily has a short interruption on Windows.  If
    // the replacement fails, immediately restore the previous known-good
    // configuration instead of leaving the desktop without a local route.
    let rollback = if previous_runtime.is_some() {
        match launch_singbox(paths, false).and_then(|mut child| {
            observe_startup(&mut child)?;
            Ok(child.id())
        }) {
            Ok(pid) => format!("previous local runtime restored (pid {pid})"),
            Err(err) => format!("automatic rollback also failed: {err}"),
        }
    } else {
        "no previous local runtime existed to restore".to_owned()
    };
    Err(format!(
        "guarded local restart failed: {startup_error}; {rollback}"
    ))
}

fn restore_last_known_good_config(
    paths: &LocalRuntimePaths,
    staged: &StagedConfig,
) -> Result<(), String> {
    fs::copy(&staged.backup_path, &paths.config_path).map_err(|err| {
        format!(
            "failed to restore last-known-good sing-box config from {}: {err}",
            staged.backup_path.display()
        )
    })?;
    Ok(())
}

fn discard_staged_config(staged: &StagedConfig) -> Result<(), String> {
    match fs::remove_file(&staged.candidate_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "failed to remove staged sing-box config {}: {err}",
            staged.candidate_path.display()
        )),
    }
}

pub fn exact_managed_runtime_processes(config_path: &Path) -> Vec<ProcessObservation> {
    singbox_processes()
        .into_iter()
        .filter(|process| {
            process
                .config_path
                .as_deref()
                .is_some_and(|config| same_path_string(config, config_path))
        })
        .collect()
}

pub fn find_exact_managed_runtime_process(config_path: &Path) -> Option<ProcessObservation> {
    let mut managed = exact_managed_runtime_processes(config_path);
    (managed.len() == 1).then(|| managed.remove(0))
}

pub fn inspect_runtime_process(config_path: &Path) -> Option<ProcessObservation> {
    match classify_runtime_process(config_path) {
        RuntimeProcessClassification::Managed(process) => Some(process),
        RuntimeProcessClassification::Conflicting(_) | RuntimeProcessClassification::Absent => None,
    }
}

pub fn classify_runtime_process(config_path: &Path) -> RuntimeProcessClassification {
    classify_processes(config_path, singbox_processes())
}

fn process_observation(pid: Pid, process: &sysinfo::Process) -> ProcessObservation {
    let arguments = process
        .cmd()
        .iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    ProcessObservation {
        pid: pid.as_u32(),
        name: process.name().to_string_lossy().into_owned(),
        executable_path: process.exe().map(|path| path.display().to_string()),
        parent_pid: process.parent().map(|value| value.as_u32()),
        command_line: arguments.join(" "),
        config_path: extract_config_path(&arguments),
    }
}

pub fn observe_process(pid: u32) -> Option<ProcessObservation> {
    let mut system = System::new_all();
    system.refresh_all();
    system
        .process(Pid::from_u32(pid))
        .map(|process| process_observation(Pid::from_u32(pid), process))
}

fn singbox_processes() -> Vec<ProcessObservation> {
    let mut system = System::new_all();
    system.refresh_all();
    system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let observation = process_observation(*pid, process);
            if !observation.name.to_ascii_lowercase().contains("sing-box") {
                return None;
            }
            Some(observation)
        })
        .collect()
}

fn classify_processes(
    expected_config_path: &Path,
    processes: Vec<ProcessObservation>,
) -> RuntimeProcessClassification {
    let mut managed = Vec::new();
    let mut conflicting = Vec::new();
    for process in processes {
        if process
            .config_path
            .as_deref()
            .is_some_and(|config| same_path_string(config, expected_config_path))
        {
            managed.push(process);
        } else {
            conflicting.push(process);
        }
    }
    if !conflicting.is_empty() || managed.len() > 1 {
        conflicting.extend(managed);
        return RuntimeProcessClassification::Conflicting(conflicting);
    }
    managed
        .pop()
        .map(RuntimeProcessClassification::Managed)
        .unwrap_or(RuntimeProcessClassification::Absent)
}

// Confirm the exact prior process has exited before another TUN owner can launch.
// A signal being sent (or an ignored kill error) is not completion evidence.
#[cfg(windows)]
fn stop_process(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("refusing to terminate an invalid process id".to_owned());
    }
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return Err(format!(
            "failed to open managed process pid {pid} for bounded termination: {}",
            unsafe { GetLastError() }
        ));
    }

    // This is one OS process wait, not a polling loop. A failed TerminateProcess
    // can race a naturally exited process; an actually signalled handle wins.
    let (result, last_error) = unsafe {
        let _ = TerminateProcess(handle, 1);
        let result = WaitForSingleObject(handle, 5_000);
        let last_error = if result == WAIT_OBJECT_0 {
            0
        } else {
            GetLastError()
        };
        CloseHandle(handle);
        (result, last_error)
    };
    match result {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(format!(
            "managed process pid {pid} did not exit within the bounded 5-second wait; refusing replacement"
        )),
        _ => Err(format!(
            "unable to confirm managed process pid {pid} exit; wait result {result:#x}, Windows error {last_error}; refusing replacement"
        )),
    }
}

// Linux local-runtime is not the Windows TUN owner. Still propagate failure
// to deliver the signal instead of reporting a successful stop unconditionally.
#[cfg(not(windows))]
fn stop_process(pid: u32) -> Result<(), String> {
    let mut system = System::new_all();
    system.refresh_all();
    let process = system
        .process(Pid::from_u32(pid))
        .ok_or_else(|| format!("managed process pid {pid} disappeared before stop"))?;
    if process.kill_with(Signal::Kill) != Some(true) {
        return Err(format!("failed to signal managed process pid {pid}"));
    }
    Ok(())
}

fn observe_startup(child: &mut std::process::Child) -> Result<(), String> {
    let attempts = (STARTUP_OBSERVATION_SECS * 1000) / STARTUP_OBSERVATION_INTERVAL_MS;
    for _ in 0..attempts {
        thread::sleep(Duration::from_millis(STARTUP_OBSERVATION_INTERVAL_MS));
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to observe sing-box startup: {err}"))?
        {
            return Err(format!(
                "sing-box exited during startup observation with status {status}"
            ));
        }
    }
    Ok(())
}

fn attach_runtime_logs(command: &mut Command, runtime_root: &Path) {
    if fs::create_dir_all(runtime_root).is_err() {
        return;
    }
    if let Ok(stdout) = File::create(runtime_root.join("sing-box.stdout.log")) {
        command.stdout(Stdio::from(stdout));
    }
    if let Ok(stderr) = File::create(runtime_root.join("sing-box.stderr.log")) {
        command.stderr(Stdio::from(stderr));
    }
}

fn exact_managed_config_argument(
    arguments: &[String],
    expected_config_path: &Path,
) -> Option<String> {
    let candidate = extract_config_path(arguments)?;
    same_path_string(&candidate, expected_config_path).then_some(candidate)
}

fn extract_config_path(arguments: &[String]) -> Option<String> {
    arguments.windows(2).find_map(|window| {
        if window[0] == "-c" || window[0] == "--config" {
            Some(window[1].clone())
        } else {
            None
        }
    })
}

fn same_path_string(candidate: &str, expected: &Path) -> bool {
    let candidate = PathBuf::from(candidate);
    if candidate == expected {
        return true;
    }

    match (candidate.canonicalize(), expected.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_config_argument() {
        let args = vec![
            "sing-box".to_owned(),
            "run".to_owned(),
            "-c".to_owned(),
            "config.json".to_owned(),
        ];
        assert_eq!(extract_config_path(&args).as_deref(), Some("config.json"));
    }

    #[test]
    fn same_path_matches_identical_values() {
        let path = PathBuf::from("/tmp/config.json");
        assert!(same_path_string("/tmp/config.json", &path));
    }

    #[test]
    fn process_observer_reports_current_process_identity() {
        let process =
            observe_process(std::process::id()).expect("current process must be observable");
        assert_eq!(process.pid, std::process::id());
        assert!(!process.name.is_empty());
    }

    #[test]
    fn process_ownership_requires_exact_managed_config_argument() {
        let expected = PathBuf::from("/managed/runtime/sing-box.json");
        let managed = vec![
            "sing-box".to_owned(),
            "run".to_owned(),
            "-c".to_owned(),
            "/managed/runtime/sing-box.json".to_owned(),
        ];
        let external = vec![
            "sing-box".to_owned(),
            "run".to_owned(),
            "-c".to_owned(),
            "/external/working/config.json".to_owned(),
        ];
        let unnamed = vec!["sing-box".to_owned(), "run".to_owned()];

        assert_eq!(
            exact_managed_config_argument(&managed, &expected).as_deref(),
            Some("/managed/runtime/sing-box.json")
        );
        assert!(exact_managed_config_argument(&external, &expected).is_none());
        assert!(exact_managed_config_argument(&unnamed, &expected).is_none());
    }

    #[test]
    fn process_classifier_is_fail_closed_for_external_or_duplicate_owners() {
        let expected = PathBuf::from("/managed/runtime/sing-box.json");
        let managed = ProcessObservation {
            pid: 10,
            name: "sing-box".to_owned(),
            executable_path: Some("/managed/sing-box".to_owned()),
            parent_pid: Some(1),
            command_line: "sing-box run -c /managed/runtime/sing-box.json".to_owned(),
            config_path: Some("/managed/runtime/sing-box.json".to_owned()),
        };
        let external = ProcessObservation {
            pid: 11,
            name: "sing-box".to_owned(),
            executable_path: Some("/external/sing-box".to_owned()),
            parent_pid: Some(2),
            command_line: "sing-box run -c /external/config.json".to_owned(),
            config_path: Some("/external/config.json".to_owned()),
        };

        assert!(matches!(
            classify_processes(&expected, vec![]),
            RuntimeProcessClassification::Absent
        ));
        assert!(matches!(
            classify_processes(&expected, vec![managed.clone()]),
            RuntimeProcessClassification::Managed(_)
        ));
        assert!(matches!(
            classify_processes(&expected, vec![external.clone()]),
            RuntimeProcessClassification::Conflicting(_)
        ));
        assert!(matches!(
            classify_processes(&expected, vec![managed.clone(), external]),
            RuntimeProcessClassification::Conflicting(_)
        ));
        assert!(matches!(
            classify_processes(&expected, vec![managed.clone(), managed]),
            RuntimeProcessClassification::Conflicting(_)
        ));
    }

    #[test]
    fn canonical_managed_tun_disallows_external_coexistence() {
        let root = std::env::temp_dir().join("edge-managed-tun-no-coexistence");
        let paths = LocalRuntimePaths {
            singbox_binary_path: root.join("sing-box.exe"),
            config_path: root.join("sing-box.json"),
            state_path: root.join("runtime-state.pb"),
            runtime_root: root,
        };
        assert!(!proxy_only_external_coexistence_allowed(&paths).unwrap());

        let legacy = LocalRuntimePaths {
            state_path: PathBuf::from("legacy-runtime.json"),
            ..paths
        };
        assert!(!proxy_only_external_coexistence_allowed(&legacy).unwrap());
    }

    #[test]
    fn destructive_windows_tun_teardown_requires_independent_recovery_proof() {
        for operation in [
            "stop-local",
            "rollback-previous",
            "managed-tun-to-proxy-only",
        ] {
            let failure = reject_unproven_windows_tun_teardown(operation).unwrap_err();
            assert!(failure.contains("refused before mutation"));
            assert!(failure.contains("CloudflareWARP DNS restoration"));
            assert!(failure.contains(operation));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_stop_rejects_invalid_pid_without_process_mutation() {
        assert!(stop_process(0).is_err());
    }

    #[test]
    fn ordinary_start_preserves_exact_owner_and_explicit_restart_can_replace() {
        assert_eq!(
            local_start_decision(true, false),
            LocalStartDecision::NoopManaged
        );
        assert_eq!(
            local_start_decision(true, true),
            LocalStartDecision::Activate
        );
        assert_eq!(
            local_start_decision(false, false),
            LocalStartDecision::Activate
        );
        assert_eq!(
            local_start_decision(false, true),
            LocalStartDecision::Activate
        );
    }

    #[test]
    fn typed_runtime_state_is_recognized_without_legacy_config_sync() {
        assert!(is_typed_runtime_state(Path::new("windows-runtime.pb")));
        assert!(is_typed_runtime_state(Path::new("WINDOWS-RUNTIME.PB")));
        assert!(!is_typed_runtime_state(Path::new("legacy-runtime.json")));
    }

    #[test]
    fn non_tun_smoke_config_is_loopback_mixed_only() {
        let config = render_non_tun_smoke_config(32123);
        assert!(config.contains(r#""type":"mixed""#));
        assert!(config.contains(r#""listen":"127.0.0.1""#));
        assert!(config.contains(r#""listen_port":32123"#));
        assert!(!config.contains(r#""type":"tun""#));
        assert!(!config.contains("auto_route"));
        assert!(!config.contains("strict_route"));
    }

    #[cfg(windows)]
    #[test]
    fn failed_transition_restores_last_known_good_config() {
        let root = std::env::temp_dir().join(format!(
            "edge-local-runtime-rollback-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("active.json");
        let backup_path = root.join("last-known-good.json");
        let candidate_path = root.join("candidate.json");
        fs::write(&config_path, "bad replacement").unwrap();
        fs::write(&backup_path, "known good").unwrap();
        fs::write(&candidate_path, "candidate").unwrap();
        let paths = LocalRuntimePaths {
            singbox_binary_path: std::env::var_os("COMSPEC").map(PathBuf::from).unwrap(),
            config_path: config_path.clone(),
            state_path: root.join("unused-state.json"),
            runtime_root: root.clone(),
        };
        let staged = StagedConfig {
            candidate_path: candidate_path.clone(),
            backup_path,
        };

        assert!(
            rollback_failed_transition(&paths, None, &staged, "forced failure".to_owned()).is_err()
        );
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "known good");
        assert!(!candidate_path.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
