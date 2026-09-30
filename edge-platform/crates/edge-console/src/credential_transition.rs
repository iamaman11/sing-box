use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
    windows_runtime_state_from_legacy_current_edge,
};
use edge_secrets::{CredentialStore, windows_runtime_state_from_bundle, write_atomic_private};
use edge_shared_types::{
    CredentialProjectionKind, CredentialTransitionAction, LocalCredentialState,
    WindowsActivationState, decode_windows_runtime_state, encode_windows_runtime_state,
    verify_windows_activation_files,
};
use edge_singbox::sync_local_config_from_runtime_state;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const LEGACY_RUNTIME_STATE_FILE: &str = "runtime-state.legacy-v1.pb";

pub(crate) fn transition(
    install_root: &Path,
    activation: &WindowsActivationState,
    action: CredentialTransitionAction,
) -> Result<(String, String), String> {
    verify_windows_activation_files(activation)?;
    if action == CredentialTransitionAction::PrepareLegacy {
        return prepare_legacy_runtime(install_root, activation);
    }

    let store = open_store(install_root)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows v2 credential state is absent".to_owned())?;

    match action {
        CredentialTransitionAction::Unspecified => {
            Err("credential transition action is required".to_owned())
        }
        CredentialTransitionAction::PrepareLegacy => {
            unreachable!("prepare-legacy is handled before opening the v2 store")
        }
        CredentialTransitionAction::ValidateCandidate => {
            require_initial_candidate_state(&state)?;
            let candidate = state
                .candidate
                .as_ref()
                .ok_or_else(|| "Windows v2 candidate is absent".to_owned())?;
            let bundle = store.read_bundle(candidate)?;
            let base = read_runtime_state(install_root)?;
            let next = windows_runtime_state_from_bundle(&base, &bundle)?;
            validate_rendered_state(install_root, activation, &next)?;
            Ok((
                "CREDENTIAL_CANDIDATE_VALID".to_owned(),
                format!(
                    "candidate generation {} passed local validation",
                    bundle.generation
                ),
            ))
        }
        CredentialTransitionAction::ApplyCandidate => {
            require_initial_candidate_state(&state)?;
            let candidate = state
                .candidate
                .as_ref()
                .ok_or_else(|| "Windows v2 candidate is absent".to_owned())?;
            let bundle = store.read_bundle(candidate)?;
            let base = read_runtime_state(install_root)?;
            ensure_legacy_backup(install_root, &base)?;
            apply_runtime_state(
                install_root,
                activation,
                &windows_runtime_state_from_bundle(&base, &bundle)?,
            )?;
            if let Err(err) = stop_exact_legacy_runtime() {
                let restore = apply_runtime_state(install_root, activation, &base);
                return match restore {
                    Ok(()) => Err(format!(
                        "Windows candidate state was prepared but legacy runtime takeover failed and typed legacy state was restored: {err}"
                    )),
                    Err(restore_err) => Err(format!(
                        "Windows legacy runtime takeover failed: {err}; typed-state rollback also failed: {restore_err}"
                    )),
                };
            }
            Ok((
                "CREDENTIAL_CANDIDATE_APPLIED".to_owned(),
                format!(
                    "candidate generation {} applied without promotion",
                    bundle.generation
                ),
            ))
        }
        CredentialTransitionAction::Promote => {
            require_initial_candidate_state(&state)?;
            let next = store.promote_candidate()?;
            let active = next.active.as_ref().ok_or_else(|| {
                "Windows v2 active credential is absent after promotion".to_owned()
            })?;
            Ok((
                "CREDENTIAL_PROMOTED".to_owned(),
                format!("active generation {}", active.generation),
            ))
        }
        CredentialTransitionAction::ApplyLegacy => {
            let legacy = read_legacy_backup(install_root)?;
            apply_runtime_state(install_root, activation, &legacy)?;
            Ok((
                "CREDENTIAL_LEGACY_APPLIED".to_owned(),
                "legacy-v1 LKG applied without changing v2 credential pointers".to_owned(),
            ))
        }
        CredentialTransitionAction::ApplyActive => {
            if state.candidate.is_some() {
                return Err("active v2 apply refuses a staged candidate".to_owned());
            }
            let active = state
                .active
                .as_ref()
                .ok_or_else(|| "Windows v2 active credential is absent".to_owned())?;
            let bundle = store.read_bundle(active)?;
            let base = read_runtime_state(install_root)?;
            apply_runtime_state(
                install_root,
                activation,
                &windows_runtime_state_from_bundle(&base, &bundle)?,
            )?;
            Ok((
                "CREDENTIAL_ACTIVE_APPLIED".to_owned(),
                format!("active generation {} applied", bundle.generation),
            ))
        }
        CredentialTransitionAction::RetireLegacy => {
            if state.active.is_none() || state.candidate.is_some() {
                return Err(
                    "legacy retirement requires one active v2 credential and no candidate"
                        .to_owned(),
                );
            }
            let active = state.active.as_ref().unwrap();
            let bundle = store.read_bundle(active)?;
            let current = read_runtime_state(install_root)?;
            let expected = windows_runtime_state_from_bundle(&current, &bundle)?;
            if current != expected {
                return Err(
                    "legacy retirement refused because Windows runtime-state is not exact active v2"
                        .to_owned(),
                );
            }
            validate_rendered_state(install_root, activation, &current)?;
            let backup = legacy_backup_path(install_root);
            if backup.exists() {
                fs::remove_file(&backup).map_err(|err| {
                    format!(
                        "failed to retire legacy Windows runtime-state backup {}: {err}",
                        backup.display()
                    )
                })?;
            }
            Ok((
                "CREDENTIAL_LEGACY_RETIRED".to_owned(),
                "legacy-v1 Windows LKG deleted after exact active-v2 verification".to_owned(),
            ))
        }
    }
}


#[derive(Debug)]
struct LegacyWindowsRuntime {
    pid: u32,
    executable_path: PathBuf,
    config_path: PathBuf,
    state_path: PathBuf,
}

fn observe_exact_legacy_runtime() -> Result<LegacyWindowsRuntime, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$items = @(Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'")
if ($items.Count -ne 1) { throw "expected exactly one sing-box.exe process, observed $($items.Count)" }
$p = $items[0]
$cmd = [string]$p.CommandLine
$m = [regex]::Match($cmd, '(?i)(?:^|\s)(?:-c|--config)\s+(?:"([^"]+)"|(\S+))')
if (-not $m.Success) { throw 'legacy sing-box command line does not contain an exact -c/--config path' }
$config = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
[Console]::Out.WriteLine([string]$p.ProcessId)
[Console]::Out.WriteLine([string]$p.ExecutablePath)
[Console]::Out.WriteLine([string]$config)
"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("failed to observe legacy Windows sing-box process: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "legacy Windows sing-box observation failed with exit_code={}",
            output.status.code().unwrap_or(-1)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "legacy Windows sing-box observation was not UTF-8".to_owned())?;
    let lines = stdout.lines().map(str::trim).filter(|line| !line.is_empty()).collect::<Vec<_>>();
    if lines.len() != 3 {
        return Err("legacy Windows sing-box observation did not return pid/executable/config".to_owned());
    }
    let pid = lines[0]
        .parse::<u32>()
        .map_err(|_| "legacy Windows sing-box pid is invalid".to_owned())?;
    let executable_path = PathBuf::from(lines[1]);
    let config_path = PathBuf::from(lines[2]);
    if !executable_path.is_file() {
        return Err("legacy Windows sing-box executable does not exist".to_owned());
    }
    if !config_path.is_file() {
        return Err("legacy Windows sing-box config does not exist".to_owned());
    }

    let runtime_dir = executable_path
        .parent()
        .ok_or_else(|| "legacy Windows sing-box executable has no runtime parent".to_owned())?;
    if runtime_dir.file_name().and_then(|value| value.to_str()) != Some("runtime") {
        return Err("legacy Windows sing-box executable is outside the expected runtime directory".to_owned());
    }
    let app_root = runtime_dir
        .parent()
        .ok_or_else(|| "legacy Windows sing-box executable has no application root".to_owned())?;
    if app_root.file_name().and_then(|value| value.to_str()) != Some("sing-box-vultr-dual") {
        return Err("legacy Windows sing-box executable is outside sing-box-vultr-dual".to_owned());
    }
    let state_path = app_root.join("state").join("current-edge.json");
    if !state_path.is_file() {
        return Err("legacy Windows current-edge state is absent beside the observed runtime".to_owned());
    }

    Ok(LegacyWindowsRuntime {
        pid,
        executable_path,
        config_path,
        state_path,
    })
}

fn prepare_legacy_runtime(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(String, String), String> {
    let legacy = observe_exact_legacy_runtime()?;
    let raw_state = fs::read_to_string(&legacy.state_path)
        .map_err(|err| format!("failed to read legacy Windows current-edge state: {err}"))?;
    let state = windows_runtime_state_from_legacy_current_edge(&raw_state)?;

    let legacy_config = fs::read(&legacy.config_path)
        .map_err(|err| format!("failed to read legacy Windows sing-box config: {err}"))?;
    let rendered = render_validated_state_from_source(
        install_root,
        activation,
        &state,
        &legacy_config,
    )?;
    let state_bytes = encode_windows_runtime_state(&state)?;

    let state_path = windows_runtime_state_path(install_root);
    if state_path.exists() {
        let existing = fs::read(&state_path)
            .map_err(|err| format!("failed to read existing Windows runtime-state: {err}"))?;
        if existing != state_bytes {
            return Err("existing Windows runtime-state differs from exact legacy takeover state".to_owned());
        }
    } else {
        write_atomic_private(&state_path, &state_bytes)?;
    }
    ensure_legacy_backup(install_root, &state)?;

    let config_path = local_singbox_config_path(install_root);
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create managed Windows runtime directory: {err}"))?;
    }
    write_atomic_private(&config_path, &rendered)?;

    Ok((
        "CREDENTIAL_LEGACY_PREPARED".to_owned(),
        format!(
            "legacy runtime imported into typed owner without process mutation; pid={}",
            legacy.pid
        ),
    ))
}

fn render_validated_state_from_source(
    install_root: &Path,
    activation: &WindowsActivationState,
    state: &edge_shared_types::WindowsRuntimeState,
    source: &[u8],
) -> Result<Vec<u8>, String> {
    let config_path = local_singbox_config_path(install_root);
    let staged = config_path.with_extension("credential-stage.json");
    write_atomic_private(&staged, source)?;
    let result = (|| {
        sync_local_config_from_runtime_state(&staged, state, &install_root.join("runtime"))?;
        let status = Command::new(&activation.sing_box_path)
            .args(["check", "-c"])
            .arg(&staged)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("failed to execute exact sing-box check: {err}"))?;
        if !status.success() {
            return Err(format!(
                "exact sing-box check rejected migrated Windows config with exit_code={}",
                status.code().unwrap_or(-1)
            ));
        }
        fs::read(&staged)
            .map_err(|err| format!("failed to read validated staged Windows config: {err}"))
    })();
    let _ = fs::remove_file(&staged);
    result
}

fn stop_exact_legacy_runtime() -> Result<(), String> {
    let legacy = observe_exact_legacy_runtime()?;
    let executable = legacy.executable_path.to_string_lossy().to_string();
    let script = format!(
        r#"$ErrorActionPreference='Stop'; $p=Get-CimInstance Win32_Process | Where-Object {{ $_.ProcessId -eq {} -and $_.Name -ieq 'sing-box.exe' }}; if(-not $p){{throw 'legacy sing-box process disappeared before takeover'}}; if([string]$p.ExecutablePath -cne '{}'){{throw 'legacy sing-box executable changed before takeover'}}; Stop-Process -Id {} -Force; Wait-Process -Id {} -Timeout 10 -ErrorAction SilentlyContinue; if(Get-Process -Id {} -ErrorAction SilentlyContinue){{throw 'legacy sing-box process did not stop'}}"#,
        legacy.pid,
        executable.replace('\'', "''"),
        legacy.pid,
        legacy.pid,
        legacy.pid,
    );
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to stop exact legacy Windows runtime: {err}"))?;
    if !status.success() {
        return Err(format!(
            "exact legacy Windows runtime stop failed with exit_code={}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn require_initial_candidate_state(state: &LocalCredentialState) -> Result<(), String> {
    if state.active.is_some() || state.previous.is_some() {
        return Err(
            "initial fresh-v2 candidate transition requires empty active/previous state".to_owned(),
        );
    }
    if state.candidate.is_none() {
        return Err("Windows v2 candidate is absent".to_owned());
    }
    Ok(())
}

fn open_store(install_root: &Path) -> Result<CredentialStore, String> {
    CredentialStore::open_existing(
        windows_credential_store_path(install_root),
        CredentialProjectionKind::Windows,
    )?
    .ok_or_else(|| "Windows v2 credential store is absent".to_owned())
}

fn read_runtime_state(
    install_root: &Path,
) -> Result<edge_shared_types::WindowsRuntimeState, String> {
    let path = windows_runtime_state_path(install_root);
    let bytes = fs::read(&path).map_err(|err| {
        format!(
            "failed to read Windows runtime state {}: {err}",
            path.display()
        )
    })?;
    decode_windows_runtime_state(&bytes)
}

fn legacy_backup_path(install_root: &Path) -> PathBuf {
    install_root
        .join("state")
        .join("secrets")
        .join(LEGACY_RUNTIME_STATE_FILE)
}

fn ensure_legacy_backup(
    install_root: &Path,
    current: &edge_shared_types::WindowsRuntimeState,
) -> Result<(), String> {
    let path = legacy_backup_path(install_root);
    if path.exists() {
        let _ = read_legacy_backup(install_root)?;
        return Ok(());
    }
    write_atomic_private(&path, &encode_windows_runtime_state(current)?)
}

fn read_legacy_backup(
    install_root: &Path,
) -> Result<edge_shared_types::WindowsRuntimeState, String> {
    let path = legacy_backup_path(install_root);
    let bytes = fs::read(&path).map_err(|err| {
        format!(
            "legacy Windows runtime-state backup is unavailable at {}: {err}",
            path.display()
        )
    })?;
    decode_windows_runtime_state(&bytes)
}

fn validate_rendered_state(
    install_root: &Path,
    activation: &WindowsActivationState,
    state: &edge_shared_types::WindowsRuntimeState,
) -> Result<Vec<u8>, String> {
    let config_path = local_singbox_config_path(install_root);
    let current = fs::read(&config_path)
        .map_err(|err| format!("failed to read Windows sing-box config: {err}"))?;
    render_validated_state_from_source(install_root, activation, state, &current)
}

fn apply_runtime_state(
    install_root: &Path,
    activation: &WindowsActivationState,
    state: &edge_shared_types::WindowsRuntimeState,
) -> Result<(), String> {
    let state_path = windows_runtime_state_path(install_root);
    let config_path = local_singbox_config_path(install_root);
    let previous_state = fs::read(&state_path)
        .map_err(|err| format!("failed to snapshot Windows runtime state: {err}"))?;
    let previous_config = fs::read(&config_path)
        .map_err(|err| format!("failed to snapshot Windows runtime config: {err}"))?;
    let next_state = encode_windows_runtime_state(state)?;
    let next_config = validate_rendered_state(install_root, activation, state)?;

    if let Err(err) = write_atomic_private(&state_path, &next_state)
        .and_then(|_| write_atomic_private(&config_path, &next_config))
    {
        let restore = write_atomic_private(&state_path, &previous_state)
            .and_then(|_| write_atomic_private(&config_path, &previous_config));
        return match restore {
            Ok(()) => Err(format!(
                "Windows credential transition failed and was rolled back: {err}"
            )),
            Err(restore_err) => Err(format!(
                "Windows credential transition failed: {err}; rollback also failed: {restore_err}"
            )),
        };
    }
    Ok(())
}
