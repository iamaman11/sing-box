use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
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
    let store = open_store(install_root)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows v2 credential state is absent".to_owned())?;

    match action {
        CredentialTransitionAction::Unspecified => {
            Err("credential transition action is required".to_owned())
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
    let staged = config_path.with_extension("credential-stage.json");
    write_atomic_private(&staged, &current)?;
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
                "exact sing-box check rejected candidate runtime config with exit_code={}",
                status.code().unwrap_or(-1)
            ));
        }
        fs::read(&staged)
            .map_err(|err| format!("failed to read validated staged Windows config: {err}"))
    })();
    let _ = fs::remove_file(&staged);
    result
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
