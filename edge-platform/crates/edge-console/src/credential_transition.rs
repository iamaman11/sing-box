use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
};
use edge_secrets::{
    CredentialStore, windows_runtime_state_from_canonical_production_bundle, write_atomic_private,
};
use edge_shared_types::{
    CredentialProjectionKind, CredentialTransitionAction, LocalCredentialState,
    WindowsActivationState, encode_windows_runtime_state, verify_windows_activation_files,
};
use edge_singbox::render_proxy_only_windows_config;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

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
            let next = windows_runtime_state_from_canonical_production_bundle(&bundle)?;
            validate_rendered_state(install_root, activation, &next)?;
            Ok((
                "CREDENTIAL_CANDIDATE_VALID".to_owned(),
                format!(
                    "candidate generation {} passed isolated proxy-only validation",
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
            let next = windows_runtime_state_from_canonical_production_bundle(&bundle)?;
            apply_runtime_state(install_root, activation, &next)?;
            Ok((
                "CREDENTIAL_CANDIDATE_APPLIED".to_owned(),
                format!(
                    "candidate generation {} applied to isolated managed runtime without promotion",
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
        CredentialTransitionAction::ApplyActive => {
            if state.candidate.is_some() {
                return Err("active v2 apply refuses a staged candidate".to_owned());
            }
            let active = state
                .active
                .as_ref()
                .ok_or_else(|| "Windows v2 active credential is absent".to_owned())?;
            let bundle = store.read_bundle(active)?;
            let next = windows_runtime_state_from_canonical_production_bundle(&bundle)?;
            apply_runtime_state(install_root, activation, &next)?;
            Ok((
                "CREDENTIAL_ACTIVE_APPLIED".to_owned(),
                format!("active generation {} applied", bundle.generation),
            ))
        }
        CredentialTransitionAction::ApplyLegacy => Err(
            "Windows legacy runtime apply is retired; the external sing-box is not managed state"
                .to_owned(),
        ),
        CredentialTransitionAction::RetireLegacy => Err(
            "Windows legacy runtime retirement is retired; the external sing-box is out of scope"
                .to_owned(),
        ),
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

fn validate_rendered_state(
    install_root: &Path,
    activation: &WindowsActivationState,
    state: &edge_shared_types::WindowsRuntimeState,
) -> Result<Vec<u8>, String> {
    let config_path = local_singbox_config_path(install_root);
    let parent = config_path
        .parent()
        .ok_or_else(|| "Windows managed config has no parent directory".to_owned())?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "failed to create Windows managed runtime directory {}: {err}",
            parent.display()
        )
    })?;

    let staged = config_path.with_extension("credential-stage.json");
    let rendered = render_proxy_only_windows_config(state)?;
    write_atomic_private(&staged, &rendered)?;

    let result = (|| {
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
                "exact sing-box check rejected proxy-only candidate config with exit_code={}",
                status.code().unwrap_or(-1)
            ));
        }
        fs::read(&staged)
            .map_err(|err| format!("failed to read validated staged Windows config: {err}"))
    })();
    let _ = fs::remove_file(&staged);
    result
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("failed to snapshot {}: {err}", path.display())),
    }
}

fn restore_optional(path: &Path, previous: Option<&[u8]>) -> Result<(), String> {
    match previous {
        Some(bytes) => write_atomic_private(path, bytes),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!(
                "failed to remove {} during rollback: {err}",
                path.display()
            )),
        },
    }
}

fn apply_runtime_state(
    install_root: &Path,
    activation: &WindowsActivationState,
    state: &edge_shared_types::WindowsRuntimeState,
) -> Result<(), String> {
    let state_path = windows_runtime_state_path(install_root);
    let config_path = local_singbox_config_path(install_root);
    let previous_state = read_optional(&state_path)?;
    let previous_config = read_optional(&config_path)?;
    let next_state = encode_windows_runtime_state(state)?;
    let next_config = validate_rendered_state(install_root, activation, state)?;

    if let Err(err) = write_atomic_private(&state_path, &next_state)
        .and_then(|_| write_atomic_private(&config_path, &next_config))
    {
        let state_restore = restore_optional(&state_path, previous_state.as_deref());
        let config_restore = restore_optional(&config_path, previous_config.as_deref());
        return match (state_restore, config_restore) {
            (Ok(()), Ok(())) => Err(format!(
                "Windows credential transition failed and managed files were rolled back: {err}"
            )),
            (state_result, config_result) => Err(format!(
                "Windows credential transition failed: {err}; rollback state={state_result:?}; config={config_result:?}"
            )),
        };
    }
    Ok(())
}
