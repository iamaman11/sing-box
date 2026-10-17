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
use edge_singbox::render_windows_config;
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
            require_candidate_without_previous(&state)?;
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
                    "candidate generation {} passed isolated Windows datapath validation",
                    bundle.generation
                ),
            ))
        }
        CredentialTransitionAction::ApplyCandidate => {
            require_active_v2_for_rotation(&state)?;
            require_candidate_without_previous(&state)?;
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
                    "candidate generation {} applied to managed Windows runtime without promotion",
                    bundle.generation
                ),
            ))
        }
        CredentialTransitionAction::Promote => {
            require_active_v2_for_rotation(&state)?;
            require_candidate_without_previous(&state)?;
            let candidate = state
                .candidate
                .as_ref()
                .ok_or_else(|| "Windows v2 candidate is absent".to_owned())?;
            verify_exact_candidate_runtime(install_root, activation, &store, candidate)?;
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
        CredentialTransitionAction::DiscardCandidate => {
            if state.previous.is_some() {
                return Err(
                    "candidate discard refuses a state that also contains previous rollback authority"
                        .to_owned(),
                );
            }
            // A BEGIN-bound prepare receipt is durable mutation evidence.
            // The ordinary DISCARD action is not a substitute for a proven
            // two-owner ABORT and must never silently strand that receipt.
            if store.read_windows_existing_join_prepare_receipt()?.is_some()
                || store.read_existing_join_receipt()?.is_some()
            {
                return Err(
                    "BEGIN-bound candidate requires paired owner reconciliation; ordinary discard is forbidden"
                        .to_owned(),
                );
            }
            if let Some(active) = state.active.as_ref() {
                // Existing Windows may already have candidate B rendered in
                // the managed config while its credential cursor still says A.
                // Restore and verify exact ACTIVE A *before* dropping the
                // candidate reference. Preserve candidate on any failed write.
                let active_bundle = store.read_bundle(active)?;
                let active_runtime =
                    windows_runtime_state_from_canonical_production_bundle(&active_bundle)?;
                apply_runtime_state(install_root, activation, &active_runtime)?;
                verify_exact_active_runtime(install_root, activation, &store, active)?;
                store.discard_candidate()?;
                return Ok((
                    "CREDENTIAL_CANDIDATE_DISCARDED".to_owned(),
                    format!(
                        "candidate discarded after verified ACTIVE generation {} runtime restoration",
                        active.generation
                    ),
                ));
            }
            discard_candidate_and_managed_runtime(install_root, &store)?;
            Ok((
                "CREDENTIAL_CANDIDATE_DISCARDED".to_owned(),
                "unpromoted initial candidate and managed Windows runtime artifacts discarded"
                    .to_owned(),
            ))
        }
        CredentialTransitionAction::RollbackPrevious => {
            if state.candidate.is_some() {
                return Err("credential rollback refuses a staged candidate".to_owned());
            }
            let active = state
                .active
                .as_ref()
                .ok_or_else(|| "Windows active credential is absent".to_owned())?;
            let previous = state
                .previous
                .as_ref()
                .ok_or_else(|| "Windows previous credential is absent".to_owned())?;
            let active_bundle = store.read_bundle(active)?;
            let previous_bundle = store.read_bundle(previous)?;
            let active_runtime =
                windows_runtime_state_from_canonical_production_bundle(&active_bundle)?;
            let previous_runtime =
                windows_runtime_state_from_canonical_production_bundle(&previous_bundle)?;

            apply_runtime_state(install_root, activation, &previous_runtime)?;
            match store.rollback_previous() {
                Ok(next) => Ok((
                    "CREDENTIAL_ROLLED_BACK".to_owned(),
                    format!(
                        "active generation {} restored; generation {} retained as previous",
                        previous.generation, active.generation
                    ),
                )),
                Err(err) => {
                    let recovery = apply_runtime_state(install_root, activation, &active_runtime);
                    match recovery {
                        Ok(()) => Err(format!(
                            "Windows credential runtime switched to previous but pointer rollback failed; active runtime was restored: {err}"
                        )),
                        Err(recovery_err) => Err(format!(
                            "Windows credential pointer rollback failed after previous runtime apply: {err}; active runtime recovery also failed: {recovery_err}"
                        )),
                    }
                }
            }
        }
        CredentialTransitionAction::DropPrevious => {
            if state.candidate.is_some() {
                return Err(
                    "previous credential cannot be dropped while a candidate is staged".to_owned(),
                );
            }
            let active = state
                .active
                .as_ref()
                .ok_or_else(|| "Windows active credential is absent".to_owned())?;
            if state.previous.is_none() {
                return Ok((
                    "CREDENTIAL_PREVIOUS_ALREADY_ABSENT".to_owned(),
                    format!("active generation {} unchanged", active.generation),
                ));
            }
            verify_exact_active_runtime(install_root, activation, &store, active)?;
            store.drop_previous()?;
            Ok((
                "CREDENTIAL_PREVIOUS_DROPPED".to_owned(),
                format!("active generation {} preserved", active.generation),
            ))
        }
        CredentialTransitionAction::RetireLegacy => Err(
            "Windows legacy runtime retirement is retired; the external sing-box is out of scope"
                .to_owned(),
        ),
    }
}

/// Protected GH BEGIN must be independently verified by the submitting
/// workflow. SYSTEM uses stopped ProxyOnly and persists a no-replay receipt
/// BEFORE applying candidate B to the two managed files. It never starts SCM.
pub(crate) fn existing_prepare(
    install_root: &Path,
    activation: &WindowsActivationState,
    generation: u64,
    slot: i32,
    source_sha256: &str,
    target_sha256: &str,
    vm_sha256: &str,
    begin_sha256: &str,
) -> Result<(String, String), String> {
    verify_windows_activation_files(activation)?;
    let store = open_store(install_root)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows existing join prepare cursor missing".to_owned())?;
    require_active_v2_for_rotation(&state)?;
    require_candidate_without_previous(&state)?;
    let source = state
        .active
        .as_ref()
        .ok_or_else(|| "Windows join prepare ACTIVE missing".to_owned())?;
    let candidate = state
        .candidate
        .as_ref()
        .ok_or_else(|| "Windows join prepare candidate missing".to_owned())?;
    if source.sha256 != source_sha256
        || candidate.sha256 != target_sha256
        || candidate.generation != generation
        || candidate.slot != slot
    {
        return Err("Windows join prepare source or candidate changed".to_owned());
    }
    verify_exact_active_runtime(install_root, activation, &store, source)?;
    let bundle = store.read_bundle(candidate)?;
    let rendered = windows_runtime_state_from_canonical_production_bundle(&bundle)?;
    // No irreversible managed-runtime write before durable begin receipt.
    store.prepare_windows_existing_join(source, candidate, vm_sha256, begin_sha256)?;
    apply_runtime_state(install_root, activation, &rendered)?;
    verify_exact_candidate_runtime(install_root, activation, &store, candidate)?;
    Ok((
        "WINDOWS_EXISTING_JOIN_CANDIDATE_APPLIED_NO_REPLAY".to_owned(),
        format!("Windows candidate generation {generation} applied while ACTIVE A is unchanged"),
    ))
}

/// Existing ACTIVE A -> selected B only. The protected GitHub owner must
/// authenticate the exact durable A/B/VM intent before SYSTEM dispatch.
/// This native action is one-shot and keeps A as PREVIOUS. SCM/TUN stay stopped.
pub(crate) fn existing_join(
    install_root: &Path,
    activation: &WindowsActivationState,
    generation: u64,
    slot: i32,
    intent_sha256: &str,
    windows_a_sha256: &str,
    windows_b_sha256: &str,
    vm_b_sha256: &str,
) -> Result<(String, String), String> {
    verify_windows_activation_files(activation)?;
    let store = open_store(install_root)?;
    let before = store
        .read_state()?
        .ok_or_else(|| "Windows existing join cursor absent".to_owned())?;
    require_active_v2_for_rotation(&before)?;
    require_candidate_without_previous(&before)?;
    let candidate = before
        .candidate
        .as_ref()
        .ok_or_else(|| "Windows existing join candidate absent".to_owned())?;
    if candidate.generation != generation
        || candidate.slot != slot
        || candidate.sha256 != windows_b_sha256
    {
        return Err("Windows existing join target differs from immutable intent".to_owned());
    }
    verify_exact_candidate_runtime(install_root, activation, &store, candidate)?;
    // A candidate config is not permission to promote: require the exact
    // one-shot BEGIN-bound preparation receipt before COMMIT pointer mutation.
    let prepare = store
        .read_windows_existing_join_prepare_receipt()?
        .ok_or_else(|| "Windows existing join prepare receipt missing; no replay".to_owned())?;
    let fields: Vec<_> = prepare.lines().collect();
    if fields.get(4).and_then(|v| v.strip_prefix("source_sha256=")) != Some(windows_a_sha256)
        || fields.get(7).and_then(|v| v.strip_prefix("target_sha256=")) != Some(windows_b_sha256)
        || fields.get(8).and_then(|v| v.strip_prefix("vm_sha256=")) != Some(vm_b_sha256)
    {
        return Err("Windows existing join prepare differs from COMMIT; no replay".to_owned());
    }
    let next = store.promote_windows_existing_join(
        generation,
        slot,
        windows_a_sha256,
        windows_b_sha256,
        vm_b_sha256,
        intent_sha256,
    )?;
    if next.active.as_ref().map(|v| v.sha256.as_str()) != Some(windows_b_sha256)
        || next.previous.as_ref().map(|v| v.sha256.as_str()) != Some(windows_a_sha256)
        || next.candidate.is_some()
    {
        return Err("Windows existing join pointer UNKNOWN; no replay".to_owned());
    }
    verify_exact_active_runtime(
        install_root,
        activation,
        &store,
        next.active.as_ref().unwrap(),
    )?;
    Ok((
        "WINDOWS_EXISTING_JOIN_ACTIVE_LOCAL_ONLY".to_owned(),
        format!(
            "Windows generation {generation} slot {slot} ACTIVE, source A retained as PREVIOUS"
        ),
    ))
}

/// First-use ONLY: preserve the existing SYSTEM-only single-owner boundary.
/// A protected GitHub paired commit intent must be independently verified
/// before this request reaches SYSTEM. This function NEVER starts SCM/TUN.
pub(crate) fn initial_commit(
    install_root: &Path,
    activation: &WindowsActivationState,
    generation: u64,
    slot: i32,
    intent_sha256: &str,
) -> Result<(String, String), String> {
    verify_windows_activation_files(activation)?;
    let store = open_store(install_root)?;
    let state = store.read_state()?.ok_or_else(|| {
        "Windows initial commit requires existing protected candidate state".to_owned()
    })?;
    if state.active.is_some() || state.previous.is_some() {
        return Err("Windows initial commit refuses existing active or previous v2".to_owned());
    }
    let candidate = state.candidate.as_ref().ok_or_else(|| {
        "Windows initial commit requires exactly one unpromoted candidate".to_owned()
    })?;
    if candidate.generation != generation || candidate.slot != slot {
        return Err("Windows initial commit candidate differs from paired intent".to_owned());
    }
    if windows_runtime_state_path(install_root).exists()
        || local_singbox_config_path(install_root).exists()
    {
        return Err(
            "Windows initial commit refuses previously applied or incomplete managed runtime"
                .to_owned(),
        );
    }
    let bundle = store.read_bundle(candidate)?;
    let next = windows_runtime_state_from_canonical_production_bundle(&bundle)?;
    // Validate the exact signed-release sing-box config BEFORE recording
    // irreversible local commit intent. This only creates/removes a scratch.
    let _validated_config = validate_rendered_state(install_root, activation, &next)?;
    // Materialize verified candidate files while SCM is proven STOPPED,
    // BEFORE consuming the irreversible receipt. Failure here cannot create
    // ACTIVE or spend first-use commit authority. No TUN/SCM start.
    apply_runtime_state(install_root, activation, &next)?;
    verify_exact_candidate_runtime(install_root, activation, &store, candidate)?;
    // Exactly one protected non-replayable receipt, then atomic ACTIVE pointer.
    let committed = store.promote_initial_paired_candidate(generation, slot, intent_sha256)?;
    if committed.active.as_ref().map(|v| v.generation) != Some(generation)
        || committed.previous.is_some()
        || committed.candidate.is_some()
    {
        return Err("Windows initial commit pointer result UNKNOWN; no replay".to_owned());
    }
    verify_exact_active_runtime(
        install_root,
        activation,
        &store,
        committed.active.as_ref().unwrap(),
    )?;
    Ok((
        "INITIAL_CREDENTIAL_COMMIT_LOCAL_ONLY".to_owned(),
        format!(
            "Windows generation {generation} slot {slot} active; paired/serving proof still required"
        ),
    ))
}

/// Only the existing SYSTEM owner may perform this after the protected
/// coordinator has independently proven the recorded RECOVERY_INTENT,
/// VM ACTIVE exact receipt and Windows CANDIDATE exact digest. This is NOT
/// a replay of the failed first-use COMMIT request. SCM/TUN remain stopped.
pub(crate) fn initial_recover(
    install_root: &Path,
    activation: &WindowsActivationState,
    generation: u64,
    slot: i32,
    original_intent_sha256: &str,
    recovery_intent_sha256: &str,
    candidate_sha256: &str,
) -> Result<(String, String), String> {
    verify_windows_activation_files(activation)?;
    let store = open_store(install_root)?;
    if store.read_initial_pair_recovery_receipt()?.is_some() {
        return Err("Windows paired recovery already attempted; read-only reconcile".to_owned());
    }
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows paired recovery cursor missing or UNKNOWN".to_owned())?;
    if state.active.is_some() || state.previous.is_some() {
        return Err("Windows paired recovery refuses non-candidate cursor".to_owned());
    }
    let candidate = state
        .candidate
        .as_ref()
        .ok_or_else(|| "Windows paired recovery candidate absent".to_owned())?;
    if candidate.generation != generation
        || candidate.slot != slot
        || candidate.sha256 != candidate_sha256
    {
        return Err("Windows paired recovery candidate changed since journal readback".to_owned());
    }
    // A previous failed attempt may have materialized exactly one or both
    // managed files. While SCM is STOPPED, rebuild only the exact already
    // verified immutable candidate; no fallback, runtime start or rerender
    // from a new secret source. This operation has its OWN durable GitHub
    // recovery decision and never calls initial_commit a second time.
    let bundle = store.read_bundle(candidate)?;
    let next = windows_runtime_state_from_canonical_production_bundle(&bundle)?;
    validate_rendered_state(install_root, activation, &next)?;
    apply_runtime_state(install_root, activation, &next)?;
    verify_exact_candidate_runtime(install_root, activation, &store, candidate)?;
    let committed = store.recover_initial_paired_candidate(
        generation,
        slot,
        original_intent_sha256,
        recovery_intent_sha256,
        candidate_sha256,
    )?;
    if committed
        .active
        .as_ref()
        .map(|reference| reference.sha256.as_str())
        != Some(candidate_sha256)
        || committed.candidate.is_some()
        || committed.previous.is_some()
    {
        return Err("Windows paired recovery cursor UNKNOWN; no replay".to_owned());
    }
    verify_exact_active_runtime(
        install_root,
        activation,
        &store,
        committed.active.as_ref().unwrap(),
    )?;
    Ok((
        "INITIAL_CREDENTIAL_RECOVERED_LOCAL_ONLY".to_owned(),
        format!(
            "Windows exact generation {generation} slot {slot} recovered; no paired network PASS"
        ),
    ))
}

fn require_active_v2_for_rotation(state: &LocalCredentialState) -> Result<(), String> {
    if state.active.is_none() {
        return Err(
            "Windows candidate application/promotion refuses initial enrollment without an explicit paired Worker-v2 cutover"
                .to_owned(),
        );
    }
    Ok(())
}

fn require_candidate_without_previous(state: &LocalCredentialState) -> Result<(), String> {
    if state.previous.is_some() {
        return Err(
            "previous credential rollback buffer must be dropped before a new candidate transition"
                .to_owned(),
        );
    }
    if state.candidate.is_none() {
        return Err("Windows v2 candidate is absent".to_owned());
    }
    Ok(())
}

fn verify_exact_candidate_runtime(
    install_root: &Path,
    activation: &WindowsActivationState,
    store: &CredentialStore,
    candidate: &edge_shared_types::LocalCredentialBundleRef,
) -> Result<(), String> {
    verify_exact_active_runtime(install_root, activation, store, candidate).map_err(|_| {
        "Windows candidate promotion refused: rendered state or config differs from exact Worker-v2 candidate generation".to_owned()
    })
}

fn verify_exact_active_runtime(
    install_root: &Path,
    activation: &WindowsActivationState,
    store: &CredentialStore,
    active: &edge_shared_types::LocalCredentialBundleRef,
) -> Result<(), String> {
    let bundle = store.read_bundle(active)?;
    let expected_state = windows_runtime_state_from_canonical_production_bundle(&bundle)?;
    let expected_state_bytes = encode_windows_runtime_state(&expected_state)?;
    let observed_state = fs::read(windows_runtime_state_path(install_root))
        .map_err(|err| format!("failed to read active Windows runtime state: {err}"))?;
    if observed_state != expected_state_bytes {
        return Err(
            "previous credential retirement refused because Windows runtime state is not exact active generation"
                .to_owned(),
        );
    }
    let expected_config = validate_rendered_state(install_root, activation, &expected_state)?;
    let observed_config = fs::read(local_singbox_config_path(install_root))
        .map_err(|err| format!("failed to read active Windows sing-box config: {err}"))?;
    if observed_config != expected_config {
        return Err(
            "previous credential retirement refused because Windows config is not exact active generation"
                .to_owned(),
        );
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
    let rendered = render_windows_config(state)?;
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
                "exact sing-box check rejected Windows candidate config with exit_code={}",
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

fn discard_candidate_and_managed_runtime(
    install_root: &Path,
    store: &CredentialStore,
) -> Result<(), String> {
    let state_path = windows_runtime_state_path(install_root);
    let config_path = local_singbox_config_path(install_root);
    let previous_state = read_optional(&state_path)?;
    let previous_config = read_optional(&config_path)?;

    if let Err(err) = restore_optional(&state_path, None)
        .and_then(|_| restore_optional(&config_path, None))
        .and_then(|_| store.discard_candidate().map(|_| ()))
    {
        let state_restore = restore_optional(&state_path, previous_state.as_deref());
        let config_restore = restore_optional(&config_path, previous_config.as_deref());
        return match (state_restore, config_restore) {
            (Ok(()), Ok(())) => Err(format!(
                "Windows candidate discard failed and managed files were rolled back: {err}"
            )),
            (state_result, config_result) => Err(format!(
                "Windows candidate discard failed: {err}; rollback state={state_result:?}; config={config_result:?}"
            )),
        };
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_promotion_refuses_missing_active_v2() {
        let state = LocalCredentialState::default();
        let err = require_active_v2_for_rotation(&state).unwrap_err();
        assert!(err.contains("refuses initial enrollment"));
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
