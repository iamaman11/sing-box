use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use edge_shared_types::LocalSingboxState;
use edge_singbox::sync_local_config;
use sysinfo::{Pid, Signal, System};

const STARTUP_OBSERVATION_SECS: u64 = 10;
const STARTUP_OBSERVATION_INTERVAL_MS: u64 = 500;

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
        pid: Some(child.pid()),
        note: if visible_window {
            "local sing-box started in a visible window (validated guarded transition)".to_owned()
        } else {
            "local sing-box started (validated guarded transition)".to_owned()
        },
        warnings: local_singbox.warnings.clone(),
        local_singbox,
    })
}

fn launch_singbox(paths: &LocalRuntimePaths, visible_window: bool) -> Result<SpawnedChild, String> {
    if visible_window && cfg!(windows) {
        let config_parent = paths
            .config_path
            .parent()
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| ".".to_owned());
        let command = format!(
            "Set-Location -LiteralPath '{}'; (Start-Process -FilePath '{}' -ArgumentList @('run','-c','{}') -WorkingDirectory '{}' -PassThru).Id",
            escape_ps_single(&config_parent),
            escape_ps_single(&paths.singbox_binary_path.display().to_string()),
            escape_ps_single(&paths.config_path.display().to_string()),
            escape_ps_single(&config_parent),
        );
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &command])
            .output()
            .map_err(|err| format!("failed to start visible sing-box window: {err}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(if stderr.is_empty() {
                format!(
                    "failed to start visible sing-box window with status {}",
                    output.status
                )
            } else {
                format!("failed to start visible sing-box window: {stderr}")
            });
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pid = stdout
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .next()
            .ok_or_else(|| {
                "failed to capture sing-box pid from visible window launch".to_owned()
            })?;
        Ok(SpawnedChild::ExternalPid(pid))
    } else {
        let mut command = Command::new(&paths.singbox_binary_path);
        command.arg("run").arg("-c").arg(&paths.config_path);
        if let Some(parent) = paths.config_path.parent() {
            command.current_dir(parent);
        }
        attach_runtime_logs(&mut command, &paths.runtime_root);
        let child = command
            .spawn()
            .map_err(|err| with_dns_guard_on_failure(format!("failed to start sing-box: {err}")))?;
        Ok(SpawnedChild::Owned(child))
    }
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

    if let Err(err) = sync_local_config(&candidate_path, &paths.state_path, &paths.runtime_root) {
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
            Ok(child.pid())
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

fn observe_startup(child: &mut SpawnedChild) -> Result<(), String> {
    let attempts = (STARTUP_OBSERVATION_SECS * 1000) / STARTUP_OBSERVATION_INTERVAL_MS;
    for _ in 0..attempts {
        thread::sleep(Duration::from_millis(STARTUP_OBSERVATION_INTERVAL_MS));
        match child {
            SpawnedChild::Owned(process) => {
                if let Some(status) = process
                    .try_wait()
                    .map_err(|err| format!("failed to observe sing-box startup: {err}"))?
                {
                    return Err(format!(
                        "sing-box exited during startup observation with status {status}"
                    ));
                }
            }
            SpawnedChild::ExternalPid(pid) => {
                if !process_exists(*pid) {
                    return Err(
                        "sing-box exited during visible window startup observation".to_owned()
                    );
                }
            }
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
    let script = r#"
$owned = @('127.0.2.2', '127.0.2.3')
$adapters = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {
    $addresses = @($_.ServerAddresses)
    @($owned | Where-Object { $addresses -contains $_ }).Count -gt 0
})
foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
    "reset Windows DNS on $($adapter.InterfaceAlias) [$($adapter.InterfaceIndex)]"
}
if ($adapters.Count -gt 0) {
    Clear-DnsClientCache
    "cleared Windows DNS client cache"
}
"#;

    match Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
    {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| format!("windows DNS guard: {line}"))
            .collect(),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            vec![if stderr.is_empty() {
                format!("windows DNS guard failed with status {}", output.status)
            } else {
                format!("windows DNS guard failed: {stderr}")
            }]
        }
        Err(err) => vec![format!("windows DNS guard failed to run: {err}")],
    }
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

fn escape_ps_single(value: &str) -> String {
    value.replace('\'', "''")
}

fn process_exists(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_all();
    system.process(Pid::from_u32(pid)).is_some()
}

enum SpawnedChild {
    Owned(std::process::Child),
    ExternalPid(u32),
}

impl SpawnedChild {
    fn pid(&self) -> u32 {
        match self {
            SpawnedChild::Owned(child) => child.id(),
            SpawnedChild::ExternalPid(pid) => *pid,
        }
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
