//! Native-owner durable one-shot admission journal.
//!
//! This is deliberately NOT a GitHub-runner journal or a migration reader.
//! Both Windows SYSTEM and VM root owners call this ONLY after independent
//! signature, machine identity, exact release and protected-directory checks.
//! A successfully reserved operation is NEVER dispatched twice. Uncertain
//! operations remain in the journal; no automatic retry/rollback.

use crate::{
    FleetHostAuthorization, FleetHostIntent, FleetHostResult, FleetHostResultState, HostRegistry,
    host_lifecycle::{
        validate_host_intent, validate_intent_against_target, verify_host_authorization,
    },
};
use prost::Message;
use ring::digest::{SHA256, digest};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// The ONLY external native-owner entry point. A signed protobuf from a
/// runner is not enough: execution also requires a kernel-verified protected
/// local journal root. On Windows the stronger ACL/SYSTEM gate must be added
/// before this admission can be enabled; fail closed until that is accepted.
fn admit_native_host_once(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    registry: &HostRegistry,
    expected_registry_sha256: &[u8],
    expected_desired_sha256: &[u8],
    expected_release_sha256: &[u8],
    pinned_worker_public_key: &[u8],
    native_machine_id: &str,
    native_owner_kind: i32,
    now_unix: u64,
    protected_journal_dir: &Path,
) -> Result<FleetHostResult, &'static str> {
    verify_native_journal_protection(protected_journal_dir)?;
    admit_after_protected_owner_check_once(
        intent,
        authorization,
        registry,
        expected_registry_sha256,
        expected_desired_sha256,
        expected_release_sha256,
        pinned_worker_public_key,
        native_machine_id,
        native_owner_kind,
        now_unix,
        protected_journal_dir,
    )
}

#[cfg(unix)]
fn verify_native_journal_protection(path: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::MetadataExt;

    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // This gate is specific to the installed root-owned VM agent.
    if unsafe { geteuid() } != 0 || !path.is_absolute() {
        return Err("HOST_NATIVE_ROOT_OWNER_REQUIRED");
    }
    let root = fs::symlink_metadata(path).map_err(|_| "HOST_JOURNAL_ROOT_MISSING")?;
    if !root.file_type().is_dir()
        || root.file_type().is_symlink()
        || root.uid() != 0
        || root.mode() & 0o077 != 0
    {
        return Err("HOST_JOURNAL_ROOT_NOT_PROTECTED");
    }
    // Ancestors cannot be replaced by the unprivileged GitHub runner.
    // Do not silently trust /tmp, relative paths, or writable mount ancestors.
    for ancestor in path.ancestors().skip(1) {
        let meta =
            fs::symlink_metadata(ancestor).map_err(|_| "HOST_JOURNAL_ANCESTOR_UNAVAILABLE")?;
        if !meta.file_type().is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
        {
            return Err("HOST_JOURNAL_ANCESTOR_NOT_PROTECTED");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_native_journal_protection(_path: &Path) -> Result<(), &'static str> {
    // No POSIX stat approximation of a Windows ACL. The Windows SYSTEM/ACL
    // policy must be native and explicit; until then NO privileged admission.
    Err("HOST_WINDOWS_OWNER_ACL_NOT_ACCEPTED")
}

/// Internal pure admission/journal primitive; callers outside this crate
/// cannot bypass the native-owner root/ACL gate above.
fn admit_after_protected_owner_check_once(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    registry: &HostRegistry,
    expected_registry_sha256: &[u8],
    expected_desired_sha256: &[u8],
    expected_release_sha256: &[u8],
    pinned_worker_public_key: &[u8],
    native_machine_id: &str,
    native_owner_kind: i32,
    now_unix: u64,
    protected_journal_dir: &Path,
) -> Result<FleetHostResult, &'static str> {
    if intent.machine_id != native_machine_id || intent.kind != native_owner_kind {
        return Err("HOST_LOCAL_OWNER_IDENTITY_MISMATCH");
    }
    validate_host_intent(
        intent,
        registry,
        expected_registry_sha256,
        expected_desired_sha256,
        expected_release_sha256,
    )?;
    validate_intent_against_target(intent, registry)?;
    verify_host_authorization(intent, authorization, pinned_worker_public_key, now_unix)?;
    // An existing trusted owner MUST provision this directory. Creating it
    // from an unprivileged request (or following a symlink) is forbidden.
    let directory =
        fs::symlink_metadata(protected_journal_dir).map_err(|_| "HOST_JOURNAL_ROOT_MISSING")?;
    if !directory.file_type().is_dir() || directory.file_type().is_symlink() {
        return Err("HOST_JOURNAL_ROOT_INVALID");
    }
    // The caller must prove the full ancestor ACL/ownership chain separately.
    // A directory merely appearing as a regular directory is not a security
    // check and may not grant SYSTEM/root execution authority.
    let id = journal_hex(intent.operation_id.as_bytes());
    let path = protected_journal_dir.join(format!("{id}.pb"));
    // Check the permanent operation journal BEFORE taking the resource gate.
    // An already completed comment must not create a fresh orphan .pending
    // record that blocks unrelated future work on the same resource.
    match fs::symlink_metadata(&path) {
        Ok(_) => return Err("HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("HOST_OPERATION_JOURNAL_UNAVAILABLE"),
    }
    // The operation-ID journal alone cannot serialize two different comments
    // acting on the SAME resource. The scope gate is durable across process
    // crashes; it is released only by a locally verified native poststate.
    // An uncertain action retains the gate and cannot be silently retried
    // under a new operation ID.
    let scope_path = native_scope_pending_path(protected_journal_dir, intent);
    let mut scope = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&scope_path)
        .map_err(|_| "HOST_RESOURCE_PENDING_OR_UNAVAILABLE")?;
    scope
        .write_all(&intent.encode_to_vec())
        .map_err(|_| "HOST_SCOPE_WRITE_UNCERTAIN_NO_REPLAY")?;
    scope
        .sync_all()
        .map_err(|_| "HOST_SCOPE_SYNC_UNCERTAIN_NO_REPLAY")?;
    let parent =
        fs::File::open(protected_journal_dir).map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNAVAILABLE")?;
    parent
        .sync_all()
        .map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNCERTAIN_NO_REPLAY")?;
    let recorded = FleetHostResult {
        schema_version: 1,
        machine_id: intent.machine_id.clone(),
        resource_id: intent.resource_id.clone(),
        operation_id: intent.operation_id.clone(),
        action: intent.action,
        state: FleetHostResultState::Authorized as i32,
        release_set_sha256: intent.release_set_sha256.clone(),
        desired_sha256: intent.desired_sha256.clone(),
        observed_at_unix: now_unix,
        error_class: String::new(),
        next_action: "NATIVE_OWNER_READBACK_REQUIRED".to_owned(),
        physical_readback: false,
    };
    // This permanent, non-replaceable record is the BEGIN. If a process
    // crashes after create_new but before sync_all, it is UNKNOWN_NO_REPLAY,
    // never permission to resume the same mutation.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE")?;
    file.write_all(&recorded.encode_to_vec())
        .map_err(|_| "HOST_JOURNAL_WRITE_UNCERTAIN_NO_REPLAY")?;
    file.sync_all()
        .map_err(|_| "HOST_JOURNAL_SYNC_UNCERTAIN_NO_REPLAY")?;
    // Do not return an authorization if the platform cannot durably sync the
    // directory entry. This is conservative on Windows too.
    let dir =
        fs::File::open(protected_journal_dir).map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNAVAILABLE")?;
    dir.sync_all()
        .map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNCERTAIN_NO_REPLAY")?;
    Ok(recorded)
}

/// One native transaction boundary for an already independently authenticated
/// and Git/ReleaseSet-bound owner. It never accepts a runner decision about
/// what to execute: the privileged owner reads its OWN state and the common
/// Rust planner selects the single permitted action. Every mutation has one
/// durable admission followed by at most one native invocation.
///
/// The closure may use only existing typed Controller/Agent operations. In
/// particular, it must not spawn an installer, hand arbitrary shell text to
/// root/SYSTEM, or retry a partial action. An execution failure deliberately
/// retains the per-resource gate as UNKNOWN_NO_REPLAY.
pub fn execute_native_host_once<Observe, Apply>(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    // Inputs MUST originate from the native owner's independently
    // authenticated canonical Git revision and published immutable release,
    // never from runner-supplied arbitrary files.
    registry_pb: &[u8],
    selected_spec_bytes: &[u8],
    release_set_pb: &[u8],
    pinned_worker_public_key: &[u8],
    native_machine_id: &str,
    native_owner_kind: i32,
    now_unix: u64,
    protected_journal_dir: &Path,
    observe: Observe,
    apply_once: Apply,
) -> Result<FleetHostResult, &'static str>
where
    Observe: FnMut() -> Result<crate::FleetNativeObservation, &'static str>,
    Apply: FnOnce(crate::FleetHostPlannedStep) -> Result<(), &'static str>,
{
    verify_native_journal_protection(protected_journal_dir)?;
    execute_after_protected_owner_check_once(
        intent,
        authorization,
        registry_pb,
        selected_spec_bytes,
        release_set_pb,
        pinned_worker_public_key,
        native_machine_id,
        native_owner_kind,
        now_unix,
        protected_journal_dir,
        observe,
        apply_once,
    )
}

/// Private testable core; only the external entry point can authorize a
/// real mutation after checking kernel owner and protected journal ancestry.
fn execute_after_protected_owner_check_once<Observe, Apply>(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    registry_pb: &[u8],
    selected_spec_bytes: &[u8],
    release_set_pb: &[u8],
    pinned_worker_public_key: &[u8],
    native_machine_id: &str,
    native_owner_kind: i32,
    now_unix: u64,
    protected_journal_dir: &Path,
    mut observe: Observe,
    apply_once: Apply,
) -> Result<FleetHostResult, &'static str>
where
    Observe: FnMut() -> Result<crate::FleetNativeObservation, &'static str>,
    Apply: FnOnce(crate::FleetHostPlannedStep) -> Result<(), &'static str>,
{
    use crate::host_lifecycle::{
        bind_native_host_artifacts, validate_intent_against_target, validate_native_observation,
    };
    use crate::host_planner::propose_host_transition;
    use crate::{FleetHostAction, FleetHostPlannedStep, FleetHostResultState};

    // Authentication and owner identity must precede even readback-driven
    // planning. A signed APPLY/RECOVER is not the same as an arbitrary START.
    if intent.machine_id != native_machine_id || intent.kind != native_owner_kind {
        return Err("HOST_LOCAL_OWNER_IDENTITY_MISMATCH");
    }
    let (registry, bound) =
        bind_native_host_artifacts(intent, registry_pb, selected_spec_bytes, release_set_pb)?;
    validate_intent_against_target(intent, &registry)?;
    verify_host_authorization(intent, authorization, pinned_worker_public_key, now_unix)?;
    if !matches!(
        FleetHostAction::try_from(intent.action),
        Ok(FleetHostAction::Apply | FleetHostAction::Recover)
    ) {
        return Err("HOST_NATIVE_EXECUTION_ACTION_NOT_ALLOWED");
    }

    // Every operation_id is single use, including when the machine has
    // already converged. Otherwise a previously executed signed comment
    // could be reinterpreted as a fresh OBSERVED/NOOP after a lost ACK.
    let prior_operation = protected_journal_dir
        .join(format!("{}.pb", journal_hex(intent.operation_id.as_bytes())));
    match fs::symlink_metadata(prior_operation) {
        Ok(_) => return Err("HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("HOST_OPERATION_JOURNAL_UNAVAILABLE"),
    }
    // An unresolved BEGIN overrides even a seemingly healthy NOOP. Do not
    // allow another comment to hide a lost ACK/crash behind newer readback.
    match fs::symlink_metadata(native_scope_pending_path(protected_journal_dir, intent)) {
        Ok(_) => return Err("HOST_RESOURCE_PENDING_OR_UNAVAILABLE"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("HOST_RESOURCE_PENDING_OR_UNAVAILABLE"),
    }
    let selected = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == intent.machine_id && h.kind == intent.kind)
        .ok_or("HOST_INTENT_UNKNOWN_MACHINE")?;
    let before = observe()?;
    validate_native_observation(&before)?;
    let plan = propose_host_transition(
        selected,
        Some(&before),
        &bound.release_set_sha256,
        &bound.runtime_release_sha256,
        now_unix,
    );
    let step =
        FleetHostPlannedStep::try_from(plan.step).map_err(|_| "HOST_NATIVE_PLAN_STEP_INVALID")?;
    // The transaction does not allow a stale or untrusted observation to
    // trigger even an "idempotent" mutation. A NOOP has no journal mutation
    // and cannot be promoted to VERIFIED by an external caller.
    if step == FleetHostPlannedStep::Blocked {
        return Err("HOST_NATIVE_PLAN_BLOCKED");
    }
    if step == FleetHostPlannedStep::Noop {
        let mut observed = crate::host_lifecycle::prepared_host_result(intent);
        observed.state = FleetHostResultState::Observed as i32;
        observed.next_action = "NONE".to_owned();
        return Ok(observed);
    }
    if !matches!(
        step,
        FleetHostPlannedStep::Start
            | FleetHostPlannedStep::Stop
            | FleetHostPlannedStep::Install
            | FleetHostPlannedStep::ReplaceRelease
    ) {
        return Err("HOST_NATIVE_PLAN_UNSUPPORTED");
    }

    admit_after_protected_owner_check_once(
        intent,
        authorization,
        &registry,
        &bound.registry_sha256,
        &bound.desired_sha256,
        &bound.release_set_sha256,
        pinned_worker_public_key,
        native_machine_id,
        native_owner_kind,
        now_unix,
        protected_journal_dir,
    )?;
    // From this point ANY failure is an uncertain operation. The durable
    // resource gate must remain; no replay, no unapproved compensation.
    apply_once(step)?;
    finish_after_protected_owner_check_once(
        intent,
        &registry,
        native_machine_id,
        native_owner_kind,
        &bound.runtime_release_sha256,
        now_unix,
        protected_journal_dir,
        observe,
    )
}

fn journal_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// Machine/resource scope is independent of the comment/operation ID.
/// Domain-separated hashing makes the key unambiguous without trusting
/// caller-controlled path elements.
fn native_scope_pending_path(root: &Path, intent: &FleetHostIntent) -> std::path::PathBuf {
    let mut bytes = b"sing-box/native-resource-scope/v1:".to_vec();
    for field in [&intent.machine_id, &intent.resource_id] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    root.join(format!("resource-{}.pending.pb", journal_hex(&bytes)))
}

/// A final result is made durable BEFORE unlocking a resource. A missing,
/// stale or inconsistent physical poststate leaves the original scope locked
/// as UNKNOWN_NO_REPLAY. The native owner supplies a live, local readback;
/// a copied runner artifact is not acceptable evidence for this function.
fn finish_native_host_once<F>(
    intent: &FleetHostIntent,
    registry: &HostRegistry,
    native_machine_id: &str,
    native_owner_kind: i32,
    expected_runtime_digest: &[u8],
    now_unix: u64,
    journal_dir: &Path,
    native_readback: F,
) -> Result<FleetHostResult, &'static str>
where
    F: FnOnce() -> Result<crate::FleetNativeObservation, &'static str>,
{
    verify_native_journal_protection(journal_dir)?;
    finish_after_protected_owner_check_once(
        intent,
        registry,
        native_machine_id,
        native_owner_kind,
        expected_runtime_digest,
        now_unix,
        journal_dir,
        native_readback,
    )
}

fn finish_after_protected_owner_check_once<F>(
    intent: &FleetHostIntent,
    registry: &HostRegistry,
    native_machine_id: &str,
    native_owner_kind: i32,
    expected_runtime_digest: &[u8],
    now_unix: u64,
    journal_dir: &Path,
    native_readback: F,
) -> Result<FleetHostResult, &'static str>
where
    F: FnOnce() -> Result<crate::FleetNativeObservation, &'static str>,
{
    use crate::{
        FleetHostKind, FleetHostRunState, FleetNativeOwnerState, FleetNativeReleaseProof,
        host_lifecycle::{decode_host_intent, validate_native_observation},
    };

    if intent.machine_id != native_machine_id || intent.kind != native_owner_kind {
        return Err("HOST_LOCAL_OWNER_IDENTITY_MISMATCH");
    }
    crate::host_lifecycle::validate_intent_against_target(intent, registry)?;
    let target = registry
        .hosts
        .iter()
        .find(|host| host.machine_id == intent.machine_id && host.kind == intent.kind)
        .and_then(|host| host.target.as_ref())
        .ok_or("HOST_TARGET_UNSET_OBSERVE_ONLY")?;
    if expected_runtime_digest.len() != 32 || expected_runtime_digest.iter().all(|b| *b == 0) {
        return Err("HOST_EXPECTED_RUNTIME_DIGEST_INVALID");
    }
    let scope = native_scope_pending_path(journal_dir, intent);
    let bytes = fs::read(&scope).map_err(|_| "HOST_RESOURCE_PENDING_RECORD_REQUIRED")?;
    let recorded_intent = decode_host_intent(&bytes)?;
    if recorded_intent != *intent {
        return Err("HOST_RESOURCE_PENDING_IDENTITY_MISMATCH");
    }
    let id = journal_hex(intent.operation_id.as_bytes());
    let original = fs::read(journal_dir.join(format!("{id}.pb")))
        .map_err(|_| "HOST_AUTHORIZED_JOURNAL_MISSING")?;
    let recorded = FleetHostResult::decode(original.as_slice())
        .map_err(|_| "HOST_AUTHORIZED_JOURNAL_INVALID")?;
    if recorded.state != FleetHostResultState::Authorized as i32
        || recorded.machine_id != intent.machine_id
        || recorded.resource_id != intent.resource_id
        || recorded.operation_id != intent.operation_id
        || recorded.action != intent.action
        || recorded.release_set_sha256 != intent.release_set_sha256
        || recorded.desired_sha256 != intent.desired_sha256
    {
        return Err("HOST_AUTHORIZED_JOURNAL_MISMATCH");
    }
    let observed = native_readback()?;
    validate_native_observation(&observed)?;
    if observed.host_kind != intent.kind
        || observed.observed_at_unix > now_unix.saturating_add(60)
        || now_unix.saturating_sub(observed.observed_at_unix) > 300
        || !observed.reason_codes.is_empty()
    {
        return Err("HOST_NATIVE_POSTSTATE_UNPROVEN");
    }
    let kind = FleetHostKind::try_from(intent.kind).map_err(|_| "HOST_NATIVE_KIND_INVALID")?;
    let expected_proof = match kind {
        FleetHostKind::Windows => FleetNativeReleaseProof::ActivationRecord,
        FleetHostKind::Vm => FleetNativeReleaseProof::ApplicationBundle,
        FleetHostKind::Unspecified => return Err("HOST_NATIVE_KIND_INVALID"),
    };
    if observed.release_proof != expected_proof as i32
        || observed.observed_release_sha256 != expected_runtime_digest
    {
        return Err("HOST_NATIVE_RELEASE_POSTSTATE_MISMATCH");
    }
    let run = FleetHostRunState::try_from(target.run_state)
        .map_err(|_| "HOST_TARGET_RUN_STATE_INVALID")?;
    let owner = FleetNativeOwnerState::try_from(observed.owner_state)
        .map_err(|_| "HOST_NATIVE_OWNER_STATE_INVALID")?;
    if !matches!(
        (run, owner),
        (FleetHostRunState::Stopped, FleetNativeOwnerState::Stopped)
            | (FleetHostRunState::Running, FleetNativeOwnerState::Running)
    ) || (run == FleetHostRunState::Running
        && !(observed.runtime_ready_proven && observed.runtime_ready))
    {
        return Err("HOST_NATIVE_RUNTIME_POSTSTATE_MISMATCH");
    }
    let result = FleetHostResult {
        schema_version: 1,
        machine_id: intent.machine_id.clone(),
        resource_id: intent.resource_id.clone(),
        operation_id: intent.operation_id.clone(),
        action: intent.action,
        state: FleetHostResultState::Verified as i32,
        release_set_sha256: intent.release_set_sha256.clone(),
        desired_sha256: intent.desired_sha256.clone(),
        observed_at_unix: observed.observed_at_unix,
        error_class: String::new(),
        next_action: "NONE".to_owned(),
        physical_readback: true,
    };
    // A protected terminal receipt is written exactly once. It is a local
    // owner result, not yet a remotely authenticated receipt or permission
    // for GitHub to infer VERIFIED from an uploaded protobuf.
    let mut writer = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(journal_dir.join(format!("{id}.verified.pb")))
        .map_err(|_| "HOST_TERMINAL_RECEIPT_EXISTS_OR_UNAVAILABLE")?;
    writer
        .write_all(&result.encode_to_vec())
        .map_err(|_| "HOST_TERMINAL_RECEIPT_WRITE_UNCERTAIN")?;
    writer
        .sync_all()
        .map_err(|_| "HOST_TERMINAL_RECEIPT_SYNC_UNCERTAIN")?;
    let dir = fs::File::open(journal_dir).map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNAVAILABLE")?;
    dir.sync_all()
        .map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNCERTAIN_NO_REPLAY")?;
    fs::remove_file(&scope).map_err(|_| "HOST_SCOPE_RELEASE_UNCERTAIN_NO_REPLAY")?;
    dir.sync_all()
        .map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNCERTAIN_NO_REPLAY")?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_lifecycle::host_authorization_payload;
    use crate::{
        FleetHost, FleetHostAction, FleetHostKind, FleetHostMode, FleetHostRunState,
        FleetHostTarget, managed_host,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn durable_native_admission_never_replays_and_requires_signature() {
        let rng = SystemRandom::new();
        let pair =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![FleetHost {
                machine_id: "vm-one".into(),
                kind: FleetHostKind::Vm as i32,
                owner: Some(managed_host::Owner::VmMachineId("vm-one".into())),
                windows_runner_label: String::new(),
                desired_spec_path: "infra/production/production.textproto".into(),
                target: Some(FleetHostTarget {
                    run_state: FleetHostRunState::Running as i32,
                    windows_mode: FleetHostMode::Unspecified as i32,
                }),
            }],
        };
        let i = FleetHostIntent {
            schema_version: 1,
            machine_id: "vm-one".into(),
            kind: FleetHostKind::Vm as i32,
            resource_id: "sing-box".into(),
            operation_id: "issue1-comment-123".into(),
            action: FleetHostAction::Apply as i32,
            registry_sha256: vec![1; 32],
            desired_sha256: vec![2; 32],
            release_set_sha256: vec![3; 32],
            requested_mode: FleetHostMode::Unspecified as i32,
            requested_at_unix: 1000,
        };
        let mut a = FleetHostAuthorization {
            schema_version: 1,
            key_id: "worker-v1".into(),
            operation_id: i.operation_id.clone(),
            issued_at_unix: 1000,
            expires_at_unix: 1100,
            ed25519_signature: Vec::new(),
        };
        let dir = std::env::temp_dir().join(format!(
            "sing-box-native-journal-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let call = |intent: &FleetHostIntent, signed: &FleetHostAuthorization| {
            admit_after_protected_owner_check_once(
                intent,
                signed,
                &registry,
                &[1; 32],
                &[2; 32],
                &[3; 32],
                pair.public_key().as_ref(),
                "vm-one",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
            )
        };
        assert_eq!(
            call(&i, &a).unwrap_err(),
            "HOST_AUTHORIZATION_IDENTITY_INVALID"
        );
        a.ed25519_signature = pair
            .sign(&host_authorization_payload(&i, &a))
            .as_ref()
            .to_vec();
        let mut observe_only = registry.clone();
        observe_only.hosts[0].target = None;
        assert_eq!(
            admit_after_protected_owner_check_once(
                &i,
                &a,
                &observe_only,
                &[1; 32],
                &[2; 32],
                &[3; 32],
                pair.public_key().as_ref(),
                "vm-one",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
            )
            .unwrap_err(),
            "HOST_TARGET_UNSET_OBSERVE_ONLY"
        );
        let first = call(&i, &a).unwrap();
        assert_eq!(first.state, FleetHostResultState::Authorized as i32);
        assert!(!first.physical_readback);
        assert_eq!(
            call(&i, &a).unwrap_err(),
            "HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"
        );
        let mut second = i.clone();
        second.operation_id = "issue1-comment-124".into();
        let mut next_authorization = a.clone();
        next_authorization.operation_id = second.operation_id.clone();
        next_authorization.ed25519_signature = pair
            .sign(&host_authorization_payload(&second, &next_authorization))
            .as_ref()
            .to_vec();
        assert_eq!(
            call(&second, &next_authorization).unwrap_err(),
            "HOST_RESOURCE_PENDING_OR_UNAVAILABLE"
        );
        let mut wrong = i.clone();
        wrong.machine_id = "vm-two".into();
        assert_eq!(
            call(&wrong, &a).unwrap_err(),
            "HOST_LOCAL_OWNER_IDENTITY_MISMATCH"
        );
        let files = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 2); // authorized journal + durable per-resource gate
        let stopped_observation = crate::FleetNativeObservation {
            schema_version: 1,
            host_kind: FleetHostKind::Vm as i32,
            observed_at_unix: 1020,
            owner_state: crate::FleetNativeOwnerState::Stopped as i32,
            release_proof: crate::FleetNativeReleaseProof::ApplicationBundle as i32,
            observed_release_sha256: vec![4; 32],
            runtime_ready: false,
            runtime_ready_proven: true,
            reason_codes: vec![],
        };
        let mut wrong_observation = stopped_observation.clone();
        wrong_observation
            .reason_codes
            .push("VM_RUNTIME_UNPROVEN".to_owned());
        assert_eq!(
            finish_after_protected_owner_check_once(
                &i,
                &registry,
                "vm-one",
                FleetHostKind::Vm as i32,
                &[4; 32],
                1020,
                &dir,
                || Ok(wrong_observation)
            )
            .unwrap_err(),
            "HOST_NATIVE_POSTSTATE_UNPROVEN"
        );
        // Missing runtime readiness cannot complete a RUNNING desired target.
        assert_eq!(
            finish_after_protected_owner_check_once(
                &i,
                &registry,
                "vm-one",
                FleetHostKind::Vm as i32,
                &[4; 32],
                1020,
                &dir,
                || Ok(stopped_observation.clone())
            )
            .unwrap_err(),
            "HOST_NATIVE_RUNTIME_POSTSTATE_MISMATCH"
        );
        let ready_observation = crate::FleetNativeObservation {
            owner_state: crate::FleetNativeOwnerState::Running as i32,
            runtime_ready: true,
            ..stopped_observation
        };
        let completed = finish_after_protected_owner_check_once(
            &i,
            &registry,
            "vm-one",
            FleetHostKind::Vm as i32,
            &[4; 32],
            1020,
            &dir,
            || Ok(ready_observation),
        )
        .unwrap();
        assert_eq!(completed.state, FleetHostResultState::Verified as i32);
        assert!(completed.physical_readback);
        // A repeated, already verified operation cannot leave a new
        // resource gate behind or starve a different fresh operation.
        assert_eq!(
            call(&i, &a).unwrap_err(),
            "HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"
        );
        assert!(!native_scope_pending_path(&dir, &i).exists());
        assert_eq!(
            call(&second, &next_authorization).unwrap().state,
            FleetHostResultState::Authorized as i32
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn single_native_execution_calls_owner_once_and_requires_physical_poststate() {
        use crate::host_lifecycle::{
            build_native_observation, digest_host_desired, host_authorization_payload,
        };
        use crate::release::v1::{ReleaseSet, VmRuntime};
        use crate::{
            FleetHostPlannedStep, FleetNativeOwnerState, FleetNativeReleaseProof,
            encode_host_registry,
        };
        use std::cell::Cell;

        let rng = SystemRandom::new();
        let pair =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let host = FleetHost {
            machine_id: "vm-exact".into(),
            kind: FleetHostKind::Vm as i32,
            owner: Some(managed_host::Owner::VmMachineId("vm-exact".into())),
            windows_runner_label: String::new(),
            desired_spec_path: "infra/hosts/specs/vm-exact.textproto".into(),
            target: Some(FleetHostTarget {
                run_state: FleetHostRunState::Running as i32,
                windows_mode: FleetHostMode::Unspecified as i32,
            }),
        };
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![host.clone()],
        };
        let registry_pb = encode_host_registry(&registry).unwrap();
        let spec = b"exact git typed VM desired";
        let release = ReleaseSet {
            schema_version: 7,
            source_revision: "a".repeat(40),
            vm_runtime: Some(VmRuntime {
                application_bundle_sha256: vec![7; 32],
                ..Default::default()
            }),
            ..Default::default()
        };
        let release_pb = release.encode_to_vec();
        let mut intent = FleetHostIntent {
            schema_version: 1,
            machine_id: "vm-exact".into(),
            kind: FleetHostKind::Vm as i32,
            resource_id: "sing-box".into(),
            operation_id: "issue1-comment-981".into(),
            action: FleetHostAction::Apply as i32,
            registry_sha256: digest(&SHA256, &registry_pb).as_ref().to_vec(),
            desired_sha256: digest_host_desired(&host, spec).unwrap(),
            release_set_sha256: digest(&SHA256, &release_pb).as_ref().to_vec(),
            requested_mode: FleetHostMode::Unspecified as i32,
            requested_at_unix: 1000,
        };
        let mut auth = FleetHostAuthorization {
            schema_version: 1,
            key_id: "worker-v1".into(),
            operation_id: intent.operation_id.clone(),
            issued_at_unix: 1000,
            expires_at_unix: 1100,
            ed25519_signature: Vec::new(),
        };
        auth.ed25519_signature = pair
            .sign(&host_authorization_payload(&intent, &auth))
            .as_ref()
            .to_vec();
        let dir = std::env::temp_dir().join(format!(
            "sing-box-host-executor-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir(&dir).unwrap();
        let running = Cell::new(false);
        let count = Cell::new(0_u32);
        let observe = || {
            build_native_observation(
                FleetHostKind::Vm,
                if running.get() {
                    FleetNativeOwnerState::Running
                } else {
                    FleetNativeOwnerState::Stopped
                },
                FleetNativeReleaseProof::ApplicationBundle,
                Some(&"07".repeat(32)),
                Some(running.get()),
                1020,
                &[],
            )
        };
        let outcome = execute_after_protected_owner_check_once(
            &intent,
            &auth,
            &registry_pb,
            spec,
            &release_pb,
            pair.public_key().as_ref(),
            "vm-exact",
            FleetHostKind::Vm as i32,
            1020,
            &dir,
            observe,
            |step| {
                assert_eq!(step, FleetHostPlannedStep::Start);
                count.set(count.get() + 1);
                running.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count.get(), 1);
        assert_eq!(outcome.state, FleetHostResultState::Verified as i32);
        assert!(outcome.physical_readback);
        assert!(!native_scope_pending_path(&dir, &intent).exists());
        // Even if the next fresh readback would say NOOP, an already used
        // operation ID cannot be reused to conceal an executed mutation.
        assert_eq!(
            execute_after_protected_owner_check_once(
                &intent, &auth, &registry_pb, spec, &release_pb,
                pair.public_key().as_ref(), "vm-exact", FleetHostKind::Vm as i32,
                1020, &dir, observe, |_step| {
                    panic!("completed signed operation must not dispatch again");
                }
            ).unwrap_err(),
            "HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"
        );

        // A different operation against already-converged state is NOOP;
        // no mutation or fabricated VERIFIED receipt is allowed.
        intent.operation_id = "issue1-comment-982".into();
        auth.operation_id = intent.operation_id.clone();
        auth.ed25519_signature = pair
            .sign(&host_authorization_payload(&intent, &auth))
            .as_ref()
            .to_vec();
        let noop = execute_after_protected_owner_check_once(
            &intent,
            &auth,
            &registry_pb,
            spec,
            &release_pb,
            pair.public_key().as_ref(),
            "vm-exact",
            FleetHostKind::Vm as i32,
            1020,
            &dir,
            observe,
            |_step| {
                panic!("NOOP must never mutate");
            },
        )
        .unwrap();
        assert_eq!(noop.state, FleetHostResultState::Observed as i32);
        assert!(!noop.physical_readback);
        assert_eq!(count.get(), 1);
        // A new signed mutation with an uncertain outcome MUST retain its
        // durable per-resource lock. Another comment cannot replay it.
        running.set(false);
        intent.operation_id = "issue1-comment-983".into();
        auth.operation_id = intent.operation_id.clone();
        auth.ed25519_signature = pair
            .sign(&host_authorization_payload(&intent, &auth))
            .as_ref()
            .to_vec();
        assert_eq!(
            execute_after_protected_owner_check_once(
                &intent,
                &auth,
                &registry_pb,
                spec,
                &release_pb,
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |_step| {
                    count.set(count.get() + 1);
                    Err("HOST_TEST_UNKNOWN_AFTER_ADMISSION")
                }
            )
            .unwrap_err(),
            "HOST_TEST_UNKNOWN_AFTER_ADMISSION"
        );
        assert_eq!(count.get(), 2);
        assert!(native_scope_pending_path(&dir, &intent).exists());
        intent.operation_id = "issue1-comment-984".into();
        auth.operation_id = intent.operation_id.clone();
        auth.ed25519_signature = pair
            .sign(&host_authorization_payload(&intent, &auth))
            .as_ref()
            .to_vec();
        assert_eq!(
            execute_after_protected_owner_check_once(
                &intent,
                &auth,
                &registry_pb,
                spec,
                &release_pb,
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |_step| {
                    panic!("pending native resource must never replay");
                }
            )
            .unwrap_err(),
            "HOST_RESOURCE_PENDING_OR_UNAVAILABLE"
        );
        assert_eq!(count.get(), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cannot_use_an_unprivileged_journal_root_as_native_authority() {
        // The repo test runner is unprivileged. Even a perfectly signed
        // intent must not let its caller choose a permissive /tmp directory.
        let dir = std::env::temp_dir().join(format!(
            "sing-box-host-root-negative-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let outcome = verify_native_journal_protection(&dir);
        assert!(outcome.is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_requires_native_acl_acceptance() {
        assert_eq!(
            verify_native_journal_protection(Path::new(r"C:\sing-box\state\host")),
            Err("HOST_WINDOWS_OWNER_ACL_NOT_ACCEPTED")
        );
    }
}
