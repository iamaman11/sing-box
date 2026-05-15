use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use edge_shared_types::LocalSingboxState;
use edge_singbox::sync_local_config;
use sysinfo::{Pid, Signal, System};

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

    sync_local_config(&paths.config_path, &paths.state_path, &paths.runtime_root)?;

    if let Some(process) = runtime {
        stop_process(process.pid);
    }

    if !paths.singbox_binary_path.is_file() {
        return Err(format!(
            "sing-box binary was not found: {}",
            paths.singbox_binary_path.display()
        ));
    }

    let mut child = if visible_window && cfg!(windows) {
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
        SpawnedChild::ExternalPid(pid)
    } else {
        let mut command = Command::new(&paths.singbox_binary_path);
        command.arg("run").arg("-c").arg(&paths.config_path);
        if let Some(parent) = paths.config_path.parent() {
            command.current_dir(parent);
        }
        let child = command
            .spawn()
            .map_err(|err| format!("failed to start sing-box: {err}"))?;
        SpawnedChild::Owned(child)
    };

    // Give sing-box a short grace period so immediate config/runtime failures
    // are surfaced to the caller instead of being reported as a false success.
    thread::sleep(Duration::from_secs(2));
    match &mut child {
        SpawnedChild::Owned(process) => {
            if let Some(status) = process
                .try_wait()
                .map_err(|err| format!("failed to observe sing-box startup: {err}"))?
            {
                return Err(format!(
                    "sing-box exited immediately with status {}",
                    status
                ));
            }
        }
        SpawnedChild::ExternalPid(pid) => {
            if !process_exists(*pid) {
                return Err("sing-box exited immediately after visible window launch".to_owned());
            }
        }
    }

    let local_singbox = inspect_local_runtime(&paths.config_path);
    Ok(RuntimeOperationResult {
        pid: Some(child.pid()),
        note: if visible_window {
            "local sing-box started in a visible window".to_owned()
        } else {
            "local sing-box started".to_owned()
        },
        warnings: local_singbox.warnings.clone(),
        local_singbox,
    })
}

pub fn stop_local_runtime(
    config_path: &Path,
    expected_config_only: bool,
) -> Result<RuntimeOperationResult, String> {
    let runtime = detect_process(config_path);
    let Some(process) = runtime else {
        let local_singbox = inspect_local_runtime(config_path);
        return Ok(RuntimeOperationResult {
            pid: None,
            note: "sing-box is not running".to_owned(),
            warnings: local_singbox.warnings.clone(),
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
    Ok(RuntimeOperationResult {
        pid: Some(process.pid),
        note: "local sing-box stopped".to_owned(),
        warnings: local_singbox.warnings.clone(),
        local_singbox,
    })
}

pub fn restart_local_runtime(paths: &LocalRuntimePaths) -> Result<RuntimeOperationResult, String> {
    let _ = stop_local_runtime(&paths.config_path, true)?;
    start_local_runtime(paths, false)
}

pub fn restart_local_runtime_visible(
    paths: &LocalRuntimePaths,
) -> Result<RuntimeOperationResult, String> {
    let _ = stop_local_runtime(&paths.config_path, true)?;
    start_local_runtime(paths, true)
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
}
