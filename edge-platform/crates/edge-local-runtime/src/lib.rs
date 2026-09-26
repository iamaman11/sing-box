use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::ptr::null_mut;

use edge_shared_types::{LocalSingboxState, decode_windows_runtime_state};
use edge_singbox::{sync_local_config, sync_local_config_from_runtime_state};
use sysinfo::{Pid, Signal, System};

#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;

const STARTUP_OBSERVATION_SECS: u64 = 10;
const STARTUP_OBSERVATION_INTERVAL_MS: u64 = 500;
const WINDOWS_OWNED_DNS_IPV4: [[u8; 4]; 2] = [[127, 0, 2, 2], [127, 0, 2, 3]];

fn is_owned_windows_dns_ipv4(address: [u8; 4]) -> bool {
    WINDOWS_OWNED_DNS_IPV4.contains(&address)
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
    pub command_line: String,
    pub config_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeOperationResult {
    pub pid: Option<u32>,
    pub note: String,
    pub warnings: Vec<String>,
    pub local_singbox: LocalSingboxState,
}

/// A candidate configuration which has been rendered and validated while the
/// currently running TUN is still serving traffic.  The active configuration
/// is never changed until this candidate has passed `sing-box check`.
struct StagedConfig {
    candidate_path: PathBuf,
    backup_path: PathBuf,
}

pub fn restore_windows_dns_if_owned() -> Vec<String> {
    #[cfg(windows)]
    {
        restore_windows_dns_if_owned_windows()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

pub fn inspect_local_runtime(config_path: &Path) -> LocalSingboxState {
    let expected_config_path = config_path.display().to_string();
    let mut local = LocalSingboxState::placeholder(expected_config_path);
    match detect_process(config_path) {
        Some(process) => {
            local.process_running = true;
            local.active_config_path = process.config_path.clone();
            if let Some(active_config) = process.config_path {
                if same_path_string(&active_config, config_path) {
                    local.managed_config = true;
                } else {
                    local.warnings.push(format!(
                        "sing-box is running with a different config: {active_config}"
                    ));
                }
            } else {
                local.warnings.push(
                    "sing-box process detected but config path was not found in command line"
                        .to_owned(),
                );
            }
        }
        None => {
            local
                .warnings
                .push("sing-box process is not running".to_owned());
        }
    }
    local
}

pub fn start_local_runtime(
    paths: &LocalRuntimePaths,
    visible_window: bool,
) -> Result<RuntimeOperationResult, String> {
    let runtime = inspect_runtime_process(&paths.config_path);
    if let Some(process) = runtime.as_ref()
        && let Some(config) = process.config_path.as_deref()
        && !same_path_string(config, &paths.config_path)
    {
        return Err(format!(
            "another sing-box config is already running (pid {}): {}",
            process.pid, process.command_line
        ));
    }

    if !paths.singbox_binary_path.is_file() {
        return Err(format!(
            "sing-box binary was not found: {}",
            paths.singbox_binary_path.display()
        ));
    }

    // Do all fallible configuration work before taking down the active TUN.
    // This makes `restart-local` a guarded transition rather than a blind
    // stop/start operation.
    let staged = stage_and_validate_config(paths)?;

    if let Some(process) = runtime.as_ref() {
        stop_process(process.pid);
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

    command
        .spawn()
        .map_err(|err| with_dns_guard_on_failure(format!("failed to start sing-box: {err}")))
}

pub fn stop_local_runtime(
    config_path: &Path,
    expected_config_only: bool,
) -> Result<RuntimeOperationResult, String> {
    let runtime = detect_process(config_path);
    let Some(process) = runtime else {
        let local_singbox = inspect_local_runtime(config_path);
        let mut warnings = local_singbox.warnings.clone();
        warnings.extend(restore_windows_dns_if_owned());
        return Ok(RuntimeOperationResult {
            pid: None,
            note: "sing-box is not running".to_owned(),
            warnings,
            local_singbox,
        });
    };

    if expected_config_only
        && let Some(config) = process.config_path.as_deref()
        && !same_path_string(config, config_path)
    {
        return Err(format!(
            "refusing to stop sing-box because the active process is not the managed config: {}",
            process.command_line
        ));
    }

    stop_process(process.pid);
    let local_singbox = inspect_local_runtime(config_path);
    let mut warnings = local_singbox.warnings.clone();
    warnings.extend(restore_windows_dns_if_owned());
    Ok(RuntimeOperationResult {
        pid: Some(process.pid),
        note: "local sing-box stopped".to_owned(),
        warnings,
        local_singbox,
    })
}

pub fn restart_local_runtime(paths: &LocalRuntimePaths) -> Result<RuntimeOperationResult, String> {
    start_local_runtime(paths, false)
}

pub fn restart_local_runtime_visible(
    paths: &LocalRuntimePaths,
) -> Result<RuntimeOperationResult, String> {
    start_local_runtime(paths, true)
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

    let sync_result = if paths
        .state_path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("pb"))
    {
        fs::read(&paths.state_path)
            .map_err(|err| format!("unable to read typed Windows runtime state: {err}"))
            .and_then(|bytes| decode_windows_runtime_state(&bytes))
            .and_then(|state| {
                sync_local_config_from_runtime_state(&candidate_path, &state, &paths.runtime_root)
            })
    } else {
        sync_local_config(&candidate_path, &paths.state_path, &paths.runtime_root)
    };
    if let Err(err) = sync_result {
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

pub fn inspect_runtime_process(config_path: &Path) -> Option<ProcessObservation> {
    detect_process(config_path)
}

fn stop_process(pid: u32) {
    let mut system = System::new_all();
    system.refresh_all();
    if let Some(process) = system.process(Pid::from_u32(pid)) {
        let _ = process.kill_with(Signal::Kill);
        let _ = process.kill();
    }
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

fn with_dns_guard_on_failure(message: String) -> String {
    let warnings = restore_windows_dns_if_owned();
    if warnings.is_empty() {
        message
    } else {
        format!("{message}; {}", warnings.join("; "))
    }
}

#[cfg(windows)]
fn restore_windows_dns_if_owned_windows() -> Vec<String> {
    let owned_indices = match observe_owned_windows_dns_adapter_indices() {
        Ok(indices) => indices,
        Err(err) => {
            return vec![format!(
                "windows DNS guard observation failed closed before mutation: {err}"
            )];
        }
    };
    if owned_indices.is_empty() {
        return Vec::new();
    }

    let index_list = owned_indices
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$indices = @({index_list})
foreach ($index in $indices) {{
    Set-DnsClientServerAddress -InterfaceIndex ([uint32]$index) -ResetServerAddresses
}}
Clear-DnsClientCache
"#
    );

    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status();

    let mut warnings = match status {
        Ok(status) if status.success() => vec![format!(
            "windows DNS guard: reset exact owned DNS on interface index(es) {}; cleared Windows DNS client cache",
            owned_indices
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )],
        Ok(status) => {
            return vec![format!(
                "windows DNS guard reset failed with status {status}"
            )];
        }
        Err(err) => {
            return vec![format!("windows DNS guard reset failed to run: {err}")];
        }
    };

    match observe_owned_windows_dns_adapter_indices() {
        Ok(indices) if indices.is_empty() => {}
        Ok(indices) => warnings.push(format!(
            "windows DNS guard post-reset verification still observes owned DNS on interface index(es): {}",
            indices
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )),
        Err(err) => warnings.push(format!(
            "windows DNS guard post-reset verification failed: {err}"
        )),
    }

    warnings
}

#[cfg(windows)]
fn observe_owned_windows_dns_adapter_indices() -> Result<Vec<u32>, String> {
    const WORKING_BUFFER_BYTES: usize = 15 * 1024;
    const MAX_TRIES: usize = 3;

    let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut required_bytes = WORKING_BUFFER_BYTES as u32;

    for _ in 0..MAX_TRIES {
        let word_bytes = size_of::<usize>();
        let words = (required_bytes as usize).div_ceil(word_bytes).max(1);
        let mut buffer = vec![0usize; words];
        let adapters = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();

        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                null_mut(),
                adapters,
                &mut required_bytes,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if result != 0 {
            return Err(format!(
                "GetAdaptersAddresses failed with Win32 error {result}"
            ));
        }

        let mut owned_indices = Vec::new();
        let mut adapter = adapters;
        while !adapter.is_null() {
            let mut dns_server = unsafe { (*adapter).FirstDnsServerAddress };
            let mut owned = false;
            while !dns_server.is_null() {
                let socket = unsafe { (*dns_server).Address.lpSockaddr };
                if !socket.is_null() && unsafe { (*socket).sa_family } == AF_INET {
                    let ipv4 = unsafe { &*socket.cast::<SOCKADDR_IN>() };
                    let octets = unsafe { ipv4.sin_addr.S_un.S_addr.to_ne_bytes() };
                    if is_owned_windows_dns_ipv4(octets) {
                        owned = true;
                        break;
                    }
                }
                dns_server = unsafe { (*dns_server).Next };
            }

            if owned {
                let mut interface_index = 0u32;
                let status =
                    unsafe { ConvertInterfaceLuidToIndex(&(*adapter).Luid, &mut interface_index) };
                if status != 0 {
                    return Err(format!(
                        "ConvertInterfaceLuidToIndex failed with Win32 error {status}"
                    ));
                }
                if interface_index == 0 {
                    return Err("owned DNS adapter resolved to interface index 0".to_owned());
                }
                owned_indices.push(interface_index);
            }

            adapter = unsafe { (*adapter).Next };
        }

        owned_indices.sort_unstable();
        owned_indices.dedup();
        return Ok(owned_indices);
    }

    Err(format!(
        "GetAdaptersAddresses exceeded {MAX_TRIES} bounded buffer attempts"
    ))
}

fn detect_process(expected_config_path: &Path) -> Option<ProcessObservation> {
    let mut system = System::new_all();
    system.refresh_all();

    for (pid, process) in system.processes() {
        let name = process.name().to_string_lossy().to_ascii_lowercase();
        if !name.contains("sing-box") {
            continue;
        }

        let arguments = process
            .cmd()
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let command_line = arguments.join(" ");
        let config_path = extract_config_path(&arguments);

        if let Some(candidate) = config_path.as_deref()
            && same_path_string(candidate, expected_config_path)
        {
            return Some(ProcessObservation {
                pid: pid.as_u32(),
                command_line,
                config_path,
            });
        }

        if name == "sing-box" || name == "sing-box.exe" {
            return Some(ProcessObservation {
                pid: pid.as_u32(),
                command_line,
                config_path,
            });
        }
    }

    None
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
    fn windows_dns_ownership_is_exact() {
        assert!(is_owned_windows_dns_ipv4([127, 0, 2, 2]));
        assert!(is_owned_windows_dns_ipv4([127, 0, 2, 3]));
        assert!(!is_owned_windows_dns_ipv4([127, 0, 2, 4]));
        assert!(!is_owned_windows_dns_ipv4([8, 8, 8, 8]));
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
