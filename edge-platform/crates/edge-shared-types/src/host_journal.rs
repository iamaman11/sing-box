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
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Create a single durable native journal record with private permissions at
/// creation time, even when the root agent inherited umask 022. Never chmod an
/// existing record: unknown/legacy BEGIN state must remain immutable.
fn create_private_native_record(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
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

#[cfg(windows)]
fn verify_native_journal_protection(path: &Path) -> Result<(), &'static str> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, GetAce, GetTokenInformation,
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    if !path.is_absolute() {
        return Err("HOST_WINDOWS_JOURNAL_ABSOLUTE_PATH_REQUIRED");
    }
    // The process token, not the invoking account, must be LocalSystem.
    // A GitHub runner with an Administrators group token is not an owner.
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("HOST_WINDOWS_TOKEN_UNAVAILABLE");
    }
    let system_token = (|| {
        let mut required = 0u32;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
        }
        if required == 0 || required > 65536 {
            return false;
        }
        let mut info = vec![0u8; required as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                info.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        };
        if ok == 0 {
            return false;
        }
        let user = unsafe { &*(info.as_ptr() as *const TOKEN_USER) };
        !user.User.Sid.is_null() && unsafe { IsWellKnownSid(user.User.Sid, WinLocalSystemSid) } != 0
    })();
    unsafe {
        CloseHandle(token);
    }
    if !system_token {
        return Err("HOST_WINDOWS_LOCALSYSTEM_REQUIRED");
    }

    // Examine the actual kernel DACL on every ancestor, not text output
    // from icacls, inherited assumptions, or the runner's self-report.
    // Fail closed on NULL DACL and every unknown write-capable principal.
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)
            .map_err(|_| "HOST_WINDOWS_JOURNAL_ANCESTOR_UNAVAILABLE")?;
        if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
            return Err("HOST_WINDOWS_JOURNAL_REPARSE_OR_NOT_DIRECTORY");
        }
        let mut wide: Vec<u16> = ancestor.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut owner = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err("HOST_WINDOWS_JOURNAL_SECURITY_UNAVAILABLE");
        }
        let safe = (|| {
            if owner.is_null() || dacl.is_null() {
                return false;
            }
            let privileged = |sid| unsafe {
                IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            };
            if !privileged(owner) {
                return false;
            }
            // File/dir creation, append, DELETE_CHILD, EA, ATTRIBUTES,
            // DELETE, WRITE_DAC/WRITE_OWNER and generic write/all. Bit 1
            // (list directory/read data) and bit 8 (read EA) are NOT writes.
            const WRITE_MASK: u32 = 0x0000_0002
                | 0x0000_0004
                | 0x0000_0010
                | 0x0000_0040
                | 0x0000_0100
                | 0x0001_0000
                | 0x0004_0000
                | 0x0008_0000
                | 0x1000_0000
                | 0x4000_0000;
            let acl = unsafe { &*dacl };
            for index in 0..acl.AceCount {
                let mut ace = std::ptr::null_mut();
                if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 || ace.is_null() {
                    return false;
                }
                let header = unsafe { &*(ace as *const windows_sys::Win32::Security::ACE_HEADER) };
                // Reject unsupported ACE structures, which could grant
                // rights not correctly interpreted by this narrow verifier.
                if header.AceType != 0 && header.AceType != 1 {
                    return false;
                }
                if header.AceType == 0 {
                    let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                    if allowed.Mask & WRITE_MASK != 0 {
                        let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
                        if !privileged(sid) {
                            return false;
                        }
                    }
                }
            }
            true
        })();
        unsafe {
            LocalFree(descriptor);
        }
        if !safe {
            return Err("HOST_WINDOWS_JOURNAL_DACL_NOT_PROTECTED");
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_native_journal_protection(_path: &Path) -> Result<(), &'static str> {
    Err("HOST_NATIVE_JOURNAL_PLATFORM_UNSUPPORTED")
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
    let mut scope = create_private_native_record(&scope_path)
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
    let mut recorded = FleetHostResult {
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
        next_action: String::new(),
        physical_readback: false,
        reason: 0,
    };
    crate::host_lifecycle::set_host_result_reason(
        &mut recorded,
        crate::FleetHostResultReason::AuthorizedAwaitNativeReadback,
    );
    // This permanent, non-replaceable record is the BEGIN. If a process
    // crashes after create_new but before sync_all, it is UNKNOWN_NO_REPLAY,
    // never permission to resume the same mutation.
    let mut file = create_private_native_record(&path)
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
pub fn execute_native_host_once<Observe, Allow, Apply>(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    // Inputs MUST originate from the native owner's independently
    // authenticated canonical Git revision and published immutable release,
    // never from runner-supplied arbitrary files.
    registry_pb: &[u8],
    selected_spec_bytes: &[u8],
    release_set_pb: &[u8],
    vm_bundle_pb: Option<&[u8]>,
    pinned_worker_public_key: &[u8],
    native_machine_id: &str,
    native_owner_kind: i32,
    now_unix: u64,
    protected_journal_dir: &Path,
    observe: Observe,
    allow_step: Allow,
    apply_once: Apply,
) -> Result<FleetHostResult, &'static str>
where
    Observe: FnMut() -> Result<crate::FleetNativeObservation, &'static str>,
    Allow: Fn(crate::FleetHostPlannedStep) -> Result<(), &'static str>,
    Apply: FnOnce(crate::FleetHostPlannedStep) -> Result<(), &'static str>,
{
    verify_native_journal_protection(protected_journal_dir)?;
    execute_after_protected_owner_check_once(
        intent,
        authorization,
        registry_pb,
        selected_spec_bytes,
        release_set_pb,
        vm_bundle_pb,
        pinned_worker_public_key,
        native_machine_id,
        native_owner_kind,
        now_unix,
        protected_journal_dir,
        observe,
        allow_step,
        apply_once,
    )
}

/// Private testable core; only the external entry point can authorize a
/// real mutation after checking kernel owner and protected journal ancestry.
fn execute_after_protected_owner_check_once<Observe, Allow, Apply>(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    registry_pb: &[u8],
    selected_spec_bytes: &[u8],
    release_set_pb: &[u8],
    vm_bundle_pb: Option<&[u8]>,
    pinned_worker_public_key: &[u8],
    native_machine_id: &str,
    native_owner_kind: i32,
    now_unix: u64,
    protected_journal_dir: &Path,
    mut observe: Observe,
    allow_step: Allow,
    apply_once: Apply,
) -> Result<FleetHostResult, &'static str>
where
    Observe: FnMut() -> Result<crate::FleetNativeObservation, &'static str>,
    Allow: Fn(crate::FleetHostPlannedStep) -> Result<(), &'static str>,
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
    let (registry, bound) = bind_native_host_artifacts(
        intent,
        registry_pb,
        selected_spec_bytes,
        release_set_pb,
        vm_bundle_pb,
    )?;
    validate_intent_against_target(intent, &registry)?;
    verify_host_authorization(intent, authorization, pinned_worker_public_key, now_unix)?;
    if !matches!(
        FleetHostAction::try_from(intent.action),
        Ok(FleetHostAction::Apply | FleetHostAction::Recover)
    ) {
        return Err("HOST_NATIVE_EXECUTION_ACTION_NOT_ALLOWED");
    }

    // An UNKNOWN from ANY native scope freezes further VM mutations,
    // including host-wide ones. A narrower journal filename cannot be used
    // as a workaround for an unresolved signed mutation.
    let current_scope = native_scope_pending_path(protected_journal_dir, intent);
    for item in fs::read_dir(protected_journal_dir)
        .map_err(|_| "HOST_RESOURCE_PENDING_DIRECTORY_UNAVAILABLE")?
    {
        let name = item
            .map_err(|_| "HOST_RESOURCE_PENDING_DIRECTORY_UNAVAILABLE")?
            .file_name();
        let name = name.to_string_lossy();
        if name.starts_with("resource-") && name.ends_with(".pending.pb") {
            let path = protected_journal_dir.join(name.as_ref());
            if path != current_scope {
                return Err("HOST_OTHER_RESOURCE_PENDING_UNKNOWN_NO_REPLAY");
            }
        }
    }
    // Every operation_id is single use, including when the machine has
    // already converged. Otherwise a previously executed signed comment
    // could be reinterpreted as a fresh OBSERVED/NOOP after a lost ACK.
    let prior_operation = protected_journal_dir.join(format!(
        "{}.pb",
        journal_hex(intent.operation_id.as_bytes())
    ));
    match fs::symlink_metadata(prior_operation) {
        Ok(_) => return Err("HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("HOST_OPERATION_JOURNAL_UNAVAILABLE"),
    }
    let selected = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == intent.machine_id && h.kind == intent.kind)
        .ok_or("HOST_INTENT_UNKNOWN_MACHINE")?;
    // A signed RECOVER never calls the native mutator. If a previous BEGIN
    // survived a crash/ACK loss, the existing SYSTEM/root owner may release
    // it only after independently re-observing the converged physical state.
    // A changed desired digest or uncertain readback keeps UNKNOWN_NO_REPLAY.
    match fs::symlink_metadata(native_scope_pending_path(protected_journal_dir, intent)) {
        Ok(_) if intent.action == FleetHostAction::Recover as i32 => {
            let observed = observe()?;
            return resolve_pending_native_recovery_once(
                intent,
                authorization,
                &registry,
                selected,
                &bound,
                pinned_worker_public_key,
                native_machine_id,
                native_owner_kind,
                now_unix,
                protected_journal_dir,
                &observed,
            );
        }
        Ok(_) => return Err("HOST_RESOURCE_PENDING_OR_UNAVAILABLE"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("HOST_RESOURCE_PENDING_OR_UNAVAILABLE"),
    }
    let before = observe()?;
    validate_native_observation(&before)?;
    let plan = propose_host_transition(
        selected,
        Some(&before),
        &bound.release_set_sha256,
        &bound.runtime_release_sha256,
        now_unix,
    );
    crate::host_planner::validate_host_transition_plan(&plan, selected)?;
    let step =
        FleetHostPlannedStep::try_from(plan.step).map_err(|_| "HOST_NATIVE_PLAN_STEP_INVALID")?;
    // The transaction does not allow a stale or untrusted observation to
    // trigger even an "idempotent" mutation. A NOOP has no journal mutation
    // and cannot be promoted to VERIFIED by an external caller.
    if step == FleetHostPlannedStep::Blocked {
        return Err("HOST_NATIVE_PLAN_BLOCKED");
    }
    // An exact resource signature must never be interpreted by the host
    // planner as a host-wide START/STOP/INSTALL or an unrelated NOOP.
    if intent.resource_id != "sing-box" && step != FleetHostPlannedStep::ReplaceRelease {
        return Err("HOST_SCOPED_INTENT_CANNOT_EXECUTE_HOST_WIDE_STEP");
    }
    // RECOVER may inspect a stable NOOP or settle a previously signed BEGIN,
    // but must NEVER turn into a second START/STOP/INSTALL attempt.
    if intent.action == FleetHostAction::Recover as i32 && step != FleetHostPlannedStep::Noop {
        return Err("HOST_NATIVE_RECOVER_READ_ONLY_STATE_NOT_CONVERGED");
    }
    if step == FleetHostPlannedStep::Noop {
        // A valid signed NOOP also consumes its operation ID. Otherwise an
        // old comment can be used indefinitely after the machine converges.
        // The SAME durable resource gate and BEGIN record serialize this
        // outcome against another concurrent mutation.
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
        let mut result = crate::host_lifecycle::prepared_host_result(intent);
        result.state = FleetHostResultState::Observed as i32;
        result.observed_at_unix = before.observed_at_unix;
        crate::host_lifecycle::set_host_result_reason(
            &mut result,
            crate::FleetHostResultReason::NoFurtherAction,
        );
        store_native_terminal_and_unlock_once(intent, &result, "observed", protected_journal_dir)?;
        return Ok(result);
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
    // Native owners cannot execute every valid planner proposal.
    // Check their capabilities before BEGIN so rejecting an unsupported
    // transition never strands the resource in UNKNOWN_NO_REPLAY.
    allow_step(step)?;

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
        step,
        &before.observed_release_sha256,
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

/// One pure proof gate shared by VM root and future Windows SYSTEM
/// recovery. Running requires current ReleaseSet and complete native
/// readiness; stopped requires an exact native owner with an intact release.
/// A stopped release drift is reported, never silently reconciled.
fn verify_read_only_recovery_state(
    host: &crate::FleetHost,
    observation: &crate::FleetNativeObservation,
    expected_runtime_digest: &[u8],
    now_unix: u64,
) -> Result<crate::FleetHostResultReason, &'static str> {
    use crate::{
        FleetHostKind, FleetHostMode, FleetHostRunState, FleetNativeOwnerState,
        FleetNativeReleaseProof, host_lifecycle::validate_native_observation,
    };
    validate_native_observation(observation)?;
    if observation.host_kind != host.kind
        || !observation.reason_codes.is_empty()
        || observation.observed_at_unix > now_unix.saturating_add(60)
        || now_unix.saturating_sub(observation.observed_at_unix) > 300
        || expected_runtime_digest.len() != 32
    {
        return Err("HOST_NATIVE_RECOVERY_READBACK_UNPROVEN");
    }
    let kind =
        FleetHostKind::try_from(host.kind).map_err(|_| "HOST_NATIVE_RECOVERY_KIND_INVALID")?;
    let required_proof = match kind {
        FleetHostKind::Vm => FleetNativeReleaseProof::ApplicationBundle,
        FleetHostKind::Windows => FleetNativeReleaseProof::ActivationRecord,
        FleetHostKind::Unspecified => return Err("HOST_NATIVE_RECOVERY_KIND_INVALID"),
    };
    if observation.release_proof != required_proof as i32
        || observation.observed_release_sha256.len() != 32
        || observation
            .observed_release_sha256
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err("HOST_NATIVE_RECOVERY_RELEASE_UNPROVEN");
    }
    let desired = host
        .target
        .as_ref()
        .ok_or("HOST_NATIVE_RECOVERY_TARGET_UNPROVEN")?;
    let run = FleetHostRunState::try_from(desired.run_state)
        .map_err(|_| "HOST_NATIVE_RECOVERY_TARGET_INVALID")?;
    let mode = FleetHostMode::try_from(desired.windows_mode)
        .map_err(|_| "HOST_NATIVE_RECOVERY_MODE_INVALID")?;
    if (kind == FleetHostKind::Windows && mode != FleetHostMode::ProxyOnly)
        || (kind == FleetHostKind::Vm && mode != FleetHostMode::Unspecified)
    {
        return Err("HOST_NATIVE_RECOVERY_MODE_NOT_ACCEPTED");
    }
    let owner = FleetNativeOwnerState::try_from(observation.owner_state)
        .map_err(|_| "HOST_NATIVE_RECOVERY_OWNER_UNPROVEN")?;
    match (run, owner) {
        (FleetHostRunState::Running, FleetNativeOwnerState::Running)
            if observation.runtime_ready_proven
                && observation.runtime_ready
                && observation.observed_release_sha256 == expected_runtime_digest =>
        {
            Ok(crate::FleetHostResultReason::RecoveredNativeRunning)
        }
        (FleetHostRunState::Stopped, FleetNativeOwnerState::Stopped)
            if observation.observed_release_sha256 == expected_runtime_digest =>
        {
            Ok(crate::FleetHostResultReason::RecoveredNativeStopped)
        }
        (FleetHostRunState::Stopped, FleetNativeOwnerState::Stopped) => {
            Ok(crate::FleetHostResultReason::StoppedReleaseDriftRequiresInstallTarget)
        }
        _ => Err("HOST_NATIVE_RECOVERY_NOT_CONVERGED_NO_REPLAY"),
    }
}

/// Classify an old, different Git release as incomplete. The new
/// root-signed RECOVER only proves a *known current baseline*, not that the
/// historical effect succeeded. No Docker command can be dispatched here.
fn verify_historical_partial_recovery_state(
    host: &crate::FleetHost,
    observed: &crate::FleetNativeObservation,
    current_release: &[u8],
    now_unix: u64,
) -> Result<crate::FleetHostResultReason, &'static str> {
    use crate::{
        FleetHostKind, FleetHostRunState, FleetNativeOwnerState, FleetNativeReleaseProof,
        host_lifecycle::validate_native_observation,
    };
    validate_native_observation(observed)?;
    if host.kind != FleetHostKind::Vm as i32
        || host.target.as_ref().map(|target| target.run_state)
            != Some(FleetHostRunState::Running as i32)
        || observed.host_kind != host.kind
        || observed.observed_at_unix > now_unix.saturating_add(60)
        || now_unix.saturating_sub(observed.observed_at_unix) > 300
        || !observed.reason_codes.is_empty()
        || observed.owner_state != FleetNativeOwnerState::Running as i32
        || observed.release_proof != FleetNativeReleaseProof::ApplicationBundle as i32
        || !observed.runtime_ready_proven
        || !observed.runtime_ready
        || current_release.len() != 32
        || observed.observed_release_sha256.len() != 32
        || observed.observed_release_sha256.iter().all(|byte| *byte == 0)
        || observed.observed_release_sha256 == current_release
    {
        return Err("HOST_NATIVE_HISTORICAL_BASELINE_UNPROVEN_NO_REPLAY");
    }
    Ok(crate::FleetHostResultReason::HistoricalPartialRequiresFreshApply)
}

/// Reconcile a durable previous BEGIN WITHOUT repeating its native effect.
/// The original root/SYSTEM journal remains the sole mutation authority.
/// A new separately signed RECOVER is consumed as its own read-only receipt.
fn resolve_pending_native_recovery_once(
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    registry: &HostRegistry,
    selected: &crate::FleetHost,
    bound: &crate::host_lifecycle::BoundNativeHostArtifacts,
    pinned_worker_public_key: &[u8],
    native_machine_id: &str,
    native_owner_kind: i32,
    now_unix: u64,
    journal_dir: &Path,
    observed: &crate::FleetNativeObservation,
) -> Result<FleetHostResult, &'static str> {
    use crate::{
        FleetHostAction, FleetHostResultState,
        host_lifecycle::{decode_host_intent, decode_host_result},
    };
    let scope = native_scope_pending_path(journal_dir, intent);
    let pending = fs::read(&scope).map_err(|_| "HOST_RECOVERY_PENDING_RECORD_UNREADABLE")?;
    let original = decode_host_intent(&pending)?;
    if original.machine_id != intent.machine_id
        || original.kind != intent.kind
        || original.resource_id != intent.resource_id
        || original.operation_id == intent.operation_id
        || !matches!(
            FleetHostAction::try_from(original.action),
            Ok(FleetHostAction::Apply | FleetHostAction::Recover)
        )
    {
        return Err("HOST_NATIVE_RECOVERY_PENDING_IDENTITY_MISMATCH");
    }
    let prior_id = journal_hex(original.operation_id.as_bytes());
    let original_begin = fs::read(journal_dir.join(format!("{prior_id}.pb")))
        .map_err(|_| "HOST_NATIVE_RECOVERY_BEGIN_MISSING")?;
    let begin = decode_host_result(&original_begin)?;
    if begin.schema_version != 1
        || begin.state != FleetHostResultState::Authorized as i32
        || begin.physical_readback
        || !begin.error_class.is_empty()
        || crate::host_lifecycle::validate_host_result_reason(&begin).is_err()
        || begin.reason != crate::FleetHostResultReason::AuthorizedAwaitNativeReadback as i32
        || begin.machine_id != original.machine_id
        || begin.resource_id != original.resource_id
        || begin.operation_id != original.operation_id
        || begin.action != original.action
        || begin.release_set_sha256 != original.release_set_sha256
        || begin.desired_sha256 != original.desired_sha256
    {
        return Err("HOST_NATIVE_RECOVERY_BEGIN_MISMATCH");
    }
    // Exact original release can use the existing full-convergence VERIFY.
    // If the original source differs, a fresh Worker-signed RECOVER may only
    // classify an old whole-VM APPLY as incomplete against a proven running
    // native baseline. Never misrepresent a different release as original
    // success, regardless of what Docker reports.
    let historical_drift = original.registry_sha256 != intent.registry_sha256
        || original.desired_sha256 != intent.desired_sha256
        || original.release_set_sha256 != intent.release_set_sha256;
    if historical_drift
        && (original.action != FleetHostAction::Apply as i32
            || original.resource_id != "sing-box"
            || selected.kind != crate::FleetHostKind::Vm as i32)
    {
        return Err("HOST_NATIVE_HISTORICAL_SCOPE_UNSUPPORTED_NO_REPLAY");
    }
    let verdict = if historical_drift {
        verify_historical_partial_recovery_state(
            selected,
            observed,
            &bound.runtime_release_sha256,
            now_unix,
        )?
    } else {
        verify_read_only_recovery_state(
            selected,
            observed,
            &bound.runtime_release_sha256,
            now_unix,
        )?
    };
    let partial = verdict == crate::FleetHostResultReason::HistoricalPartialRequiresFreshApply;
    let mut prior_result = FleetHostResult {
        schema_version: 1,
        machine_id: original.machine_id.clone(),
        resource_id: original.resource_id.clone(),
        operation_id: original.operation_id.clone(),
        action: original.action,
        state: if partial {
            FleetHostResultState::UnknownNoReplay as i32
        } else {
            FleetHostResultState::Verified as i32
        },
        release_set_sha256: original.release_set_sha256.clone(),
        desired_sha256: original.desired_sha256.clone(),
        observed_at_unix: observed.observed_at_unix,
        error_class: String::new(),
        next_action: String::new(),
        // An incomplete historic action has a known NEW baseline, not a
        // completed original physical effect. Never set VERIFIED evidence.
        physical_readback: !partial,
        reason: 0,
    };
    crate::host_lifecycle::set_host_result_reason(&mut prior_result, verdict);
    let terminal_name = if partial { "incomplete" } else { "verified" };
    let opposite = journal_dir.join(format!(
        "{prior_id}.{}.pb",
        if partial { "verified" } else { "incomplete" }
    ));
    if fs::symlink_metadata(opposite).is_ok() {
        return Err("HOST_NATIVE_RECOVERY_CONFLICTING_TERMINAL");
    }
    let prior_terminal = journal_dir.join(format!("{prior_id}.{terminal_name}.pb"));
    match fs::symlink_metadata(&prior_terminal) {
        Ok(_) => {
            // A crash after terminal sync but before unlocking the scope
            // is recoverable, only with the same new physical owner proof.
            let exact = decode_host_result(
                &fs::read(&prior_terminal)
                    .map_err(|_| "HOST_NATIVE_RECOVERY_TERMINAL_UNREADABLE")?,
            )?;
            if exact.state != prior_result.state
                || exact.physical_readback != prior_result.physical_readback
                || exact.reason != prior_result.reason
                || exact.error_class != prior_result.error_class
                || exact.next_action != prior_result.next_action
                || exact.machine_id != original.machine_id
                || exact.resource_id != original.resource_id
                || exact.operation_id != original.operation_id
                || exact.action != original.action
                || exact.release_set_sha256 != original.release_set_sha256
                || exact.desired_sha256 != original.desired_sha256
            {
                return Err("HOST_NATIVE_RECOVERY_TERMINAL_MISMATCH");
            }
            fs::remove_file(&scope).map_err(|_| "HOST_RECOVERY_SCOPE_UNCERTAIN_NO_REPLAY")?;
            fs::File::open(journal_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "HOST_RECOVERY_SCOPE_SYNC_UNCERTAIN_NO_REPLAY")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            store_native_terminal_and_unlock_once(
                &original,
                &prior_result,
                terminal_name,
                journal_dir,
            )?;
        }
        Err(_) => return Err("HOST_NATIVE_RECOVERY_TERMINAL_UNAVAILABLE"),
    }
    // No native action occurred for the new Recover intent.
    admit_after_protected_owner_check_once(
        intent,
        authorization,
        registry,
        &bound.registry_sha256,
        &bound.desired_sha256,
        &bound.release_set_sha256,
        pinned_worker_public_key,
        native_machine_id,
        native_owner_kind,
        now_unix,
        journal_dir,
    )?;
    let mut result = crate::host_lifecycle::prepared_host_result(intent);
    result.state = FleetHostResultState::Observed as i32;
    result.observed_at_unix = observed.observed_at_unix;
    crate::host_lifecycle::set_host_result_reason(&mut result, verdict);
    store_native_terminal_and_unlock_once(intent, &result, "observed", journal_dir)?;
    Ok(result)
}

/// Complete a locally authenticated native mutation after physical readback.
/// Failure retains the durable resource gate; no automatic replay or rollback.
fn finish_after_protected_owner_check_once<F>(
    intent: &FleetHostIntent,
    registry: &HostRegistry,
    native_machine_id: &str,
    native_owner_kind: i32,
    expected_runtime_digest: &[u8],
    executed_step: crate::FleetHostPlannedStep,
    previous_runtime_digest: &[u8],
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
    if observed.host_kind != intent.kind {
        return Err("HOST_NATIVE_POSTSTATE_KIND_MISMATCH");
    }
    if observed.observed_at_unix > now_unix.saturating_add(60) {
        return Err("HOST_NATIVE_POSTSTATE_FUTURE_TIMESTAMP");
    }
    if now_unix.saturating_sub(observed.observed_at_unix) > 300 {
        return Err("HOST_NATIVE_POSTSTATE_STALE_TIMESTAMP");
    }
    if !observed.reason_codes.is_empty() {
        // Read-only native observation retains the actual bounded reason codes;
        // a nonempty list may not be waved through as a successful INSTALL.
        return Err("HOST_NATIVE_POSTSTATE_REASONS_PRESENT");
    }
    let kind = FleetHostKind::try_from(intent.kind).map_err(|_| "HOST_NATIVE_KIND_INVALID")?;
    let expected_proof = match kind {
        FleetHostKind::Windows => FleetNativeReleaseProof::ActivationRecord,
        FleetHostKind::Vm => FleetNativeReleaseProof::ApplicationBundle,
        FleetHostKind::Unspecified => return Err("HOST_NATIVE_KIND_INVALID"),
    };
    // STOP must preserve the installed release, not fabricate activation of
    // the requested ReleaseSet. The planner intentionally prioritizes STOP
    // over release drift. Every other mutation must converge to new bytes.
    let poststate_release = if executed_step == crate::FleetHostPlannedStep::Stop {
        if previous_runtime_digest.len() != 32 {
            return Err("HOST_NATIVE_PRESTATE_RELEASE_UNPROVEN");
        }
        previous_runtime_digest
    } else {
        expected_runtime_digest
    };
    if observed.release_proof != expected_proof as i32
        || observed.observed_release_sha256 != poststate_release
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
    let mut result = FleetHostResult {
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
        next_action: String::new(),
        physical_readback: true,
        reason: 0,
    };
    let reason = if executed_step == crate::FleetHostPlannedStep::Stop
        && previous_runtime_digest != expected_runtime_digest
    {
        crate::FleetHostResultReason::StoppedReleaseDriftRequiresInstallTarget
    } else {
        crate::FleetHostResultReason::NoFurtherAction
    };
    crate::host_lifecycle::set_host_result_reason(&mut result, reason);
    // Only an existing protected native owner can reach this completion.
    // No GitHub artifact or unsigned caller-provided protobuf is a receipt.
    store_native_terminal_and_unlock_once(intent, &result, "verified", journal_dir)?;
    Ok(result)
}

/// The only terminal commit path, used for both verified physical transitions
/// and independently observed NOOPs. The result is durable BEFORE its
/// resource gate is released. A crash or uncertain write keeps the gate,
/// never an implicit permission to replay an operation.
fn store_native_terminal_and_unlock_once(
    intent: &FleetHostIntent,
    result: &FleetHostResult,
    terminal: &str,
    journal_dir: &Path,
) -> Result<(), &'static str> {
    if result.operation_id != intent.operation_id
        || result.machine_id != intent.machine_id
        || result.resource_id != intent.resource_id
        || result.release_set_sha256 != intent.release_set_sha256
        || result.desired_sha256 != intent.desired_sha256
        || !matches!(
            (terminal, FleetHostResultState::try_from(result.state)),
            ("verified", Ok(FleetHostResultState::Verified))
                | ("observed", Ok(FleetHostResultState::Observed))
                | ("incomplete", Ok(FleetHostResultState::UnknownNoReplay))
        )
        || (terminal == "observed" && result.physical_readback)
        || (terminal == "verified" && !result.physical_readback)
        || (terminal == "incomplete"
            && (result.physical_readback
                || result.reason
                    != crate::FleetHostResultReason::HistoricalPartialRequiresFreshApply as i32))
        || crate::host_lifecycle::validate_host_result_reason(result).is_err()
    {
        return Err("HOST_TERMINAL_RESULT_INVALID");
    }
    let scope = native_scope_pending_path(journal_dir, intent);
    let id = journal_hex(intent.operation_id.as_bytes());
    // The exact pending operation must still be the same one that reserved
    // this resource. Never remove a different operation's pending gate.
    let pending = fs::read(&scope).map_err(|_| "HOST_RESOURCE_PENDING_RECORD_REQUIRED")?;
    if pending != intent.encode_to_vec() {
        return Err("HOST_RESOURCE_PENDING_IDENTITY_MISMATCH");
    }
    let mut writer = create_private_native_record(&journal_dir.join(format!("{id}.{terminal}.pb")))
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_lifecycle::host_authorization_payload;
    use crate::{
        FleetHost, FleetHostAction, FleetHostKind, FleetHostMode, FleetHostPlannedStep,
        FleetHostRunState, FleetHostTarget, managed_host,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    #[test]
    fn new_native_journal_record_is_private_under_umask_022() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // umask is process-wide, so run the umask fixture in a separate test
        // process instead of changing it inside a parallel Rust test runner.
        const CHILD: &str = "SING_BOX_PRIVATE_JOURNAL_UMASK_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let executable = std::env::current_exe().unwrap();
            let output = std::process::Command::new(executable)
                .arg("--exact")
                .arg("host_journal::tests::new_native_journal_record_is_private_under_umask_022")
                .arg("--nocapture")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child umask fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        unsafe extern "C" {
            fn umask(mask: u32) -> u32;
        }
        unsafe {
            umask(0o022);
        }
        let path = std::env::temp_dir().join(format!(
            "sing-box-private-native-record-{}",
            std::process::id()
        ));
        let file = create_private_native_record(&path).unwrap();
        let meta = file.metadata().unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), unsafe { libc_geteuid_for_test() });
        assert!(create_private_native_record(&path).is_err());
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    unsafe fn libc_geteuid_for_test() -> u32 {
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() }
    }

    #[test]
    fn recovery_requires_native_convergence_and_never_accepts_unknown() {
        let host = crate::FleetHost {
            machine_id: "vm-1".into(),
            kind: crate::FleetHostKind::Vm as i32,
            target: Some(crate::FleetHostTarget {
                run_state: crate::FleetHostRunState::Running as i32,
                windows_mode: crate::FleetHostMode::Unspecified as i32,
            }),
            ..Default::default()
        };
        let mut observed = crate::FleetNativeObservation {
            schema_version: 1,
            host_kind: crate::FleetHostKind::Vm as i32,
            observed_at_unix: 1000,
            owner_state: crate::FleetNativeOwnerState::Running as i32,
            release_proof: crate::FleetNativeReleaseProof::ApplicationBundle as i32,
            observed_release_sha256: vec![1; 32],
            runtime_ready: true,
            runtime_ready_proven: true,
            reason_codes: vec![],
        };
        assert_eq!(
            verify_read_only_recovery_state(&host, &observed, &[1; 32], 1000),
            Ok(crate::FleetHostResultReason::RecoveredNativeRunning)
        );
        observed.runtime_ready = false;
        assert!(verify_read_only_recovery_state(&host, &observed, &[1; 32], 1000).is_err());
        observed.runtime_ready = true;
        observed.observed_release_sha256 = vec![2; 32];
        assert!(verify_read_only_recovery_state(&host, &observed, &[1; 32], 1000).is_err());
        observed.observed_release_sha256 = vec![1; 32];
        observed.reason_codes.push("VM_RUNTIME_UNPROVEN".into());
        assert!(verify_read_only_recovery_state(&host, &observed, &[1; 32], 1000).is_err());
        observed.reason_codes.clear();
        let mut stopped = host;
        stopped.target.as_mut().unwrap().run_state = crate::FleetHostRunState::Stopped as i32;
        observed.owner_state = crate::FleetNativeOwnerState::Stopped as i32;
        observed.runtime_ready = false;
        observed.observed_release_sha256 = vec![2; 32];
        assert_eq!(
            verify_read_only_recovery_state(&stopped, &observed, &[1; 32], 1000),
            Ok(crate::FleetHostResultReason::StoppedReleaseDriftRequiresInstallTarget)
        );
        let mut windows = stopped;
        windows.kind = crate::FleetHostKind::Windows as i32;
        windows.target.as_mut().unwrap().windows_mode = crate::FleetHostMode::ManagedTun as i32;
        observed.host_kind = crate::FleetHostKind::Windows as i32;
        observed.release_proof = crate::FleetNativeReleaseProof::ActivationRecord as i32;
        assert_eq!(
            verify_read_only_recovery_state(&windows, &observed, &[1; 32], 1000),
            Err("HOST_NATIVE_RECOVERY_MODE_NOT_ACCEPTED")
        );
    }

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
                vm_containers: Vec::new(),
                desired_spec_path: "infra/production/production.textproto".into(),
                target: Some(FleetHostTarget {
                    run_state: FleetHostRunState::Running as i32,
                    windows_mode: FleetHostMode::Unspecified as i32,
                }),
                native_receipt_public_key: Vec::new(),
                vm_first_use_credential: None,
                worker_authority_public_key: Vec::new(),
                vm_provider_spec_path: String::new(),
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
                FleetHostPlannedStep::Start,
                &[4; 32],
                1020,
                &dir,
                || Ok(wrong_observation)
            )
            .unwrap_err(),
            "HOST_NATIVE_POSTSTATE_REASONS_PRESENT"
        );
        // Missing runtime readiness cannot complete a RUNNING desired target.
        assert_eq!(
            finish_after_protected_owner_check_once(
                &i,
                &registry,
                "vm-one",
                FleetHostKind::Vm as i32,
                &[4; 32],
                FleetHostPlannedStep::Start,
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
            FleetHostPlannedStep::Start,
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
    fn stop_with_release_drift_preserves_actual_bundle_and_explains_next_action() {
        use crate::host_lifecycle::host_authorization_payload;
        use crate::{
            FleetHostKind, FleetHostMode, FleetHostRunState, FleetHostTarget, managed_host,
        };
        let rng = SystemRandom::new();
        let pair =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![FleetHost {
                machine_id: "vm-stop".into(),
                kind: FleetHostKind::Vm as i32,
                owner: Some(managed_host::Owner::VmMachineId("vm-stop".into())),
                windows_runner_label: String::new(),
                vm_containers: Vec::new(),
                desired_spec_path: "infra/production/production.textproto".into(),
                target: Some(FleetHostTarget {
                    run_state: FleetHostRunState::Stopped as i32,
                    windows_mode: FleetHostMode::Unspecified as i32,
                }),
                native_receipt_public_key: Vec::new(),
                vm_first_use_credential: None,
                worker_authority_public_key: Vec::new(),
                vm_provider_spec_path: String::new(),
            }],
        };
        let intent = FleetHostIntent {
            schema_version: 1,
            machine_id: "vm-stop".into(),
            kind: FleetHostKind::Vm as i32,
            resource_id: "sing-box".into(),
            operation_id: "issue1-comment-800".into(),
            action: FleetHostAction::Apply as i32,
            registry_sha256: vec![1; 32],
            desired_sha256: vec![2; 32],
            release_set_sha256: vec![3; 32],
            requested_mode: FleetHostMode::Unspecified as i32,
            requested_at_unix: 1000,
        };
        let mut auth = FleetHostAuthorization {
            schema_version: 1,
            key_id: "worker-test".into(),
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
            "sing-box-stop-drift-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir(&dir).unwrap();
        admit_after_protected_owner_check_once(
            &intent,
            &auth,
            &registry,
            &[1; 32],
            &[2; 32],
            &[3; 32],
            pair.public_key().as_ref(),
            "vm-stop",
            FleetHostKind::Vm as i32,
            1020,
            &dir,
        )
        .unwrap();
        let post = crate::FleetNativeObservation {
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
        // Candidate digest differs from the running release that was stopped.
        // Successful STOP must not pretend that a new release was installed.
        let done = finish_after_protected_owner_check_once(
            &intent,
            &registry,
            "vm-stop",
            FleetHostKind::Vm as i32,
            &[5; 32],
            FleetHostPlannedStep::Stop,
            &[4; 32],
            1020,
            &dir,
            || Ok(post.clone()),
        )
        .unwrap();
        assert_eq!(done.state, FleetHostResultState::Verified as i32);
        assert_eq!(
            done.next_action,
            "STOPPED_RELEASE_DRIFT_REQUIRES_INSTALL_TARGET"
        );
        assert!(!native_scope_pending_path(&dir, &intent).exists());
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
            vm_containers: Vec::new(),
            desired_spec_path: "infra/hosts/specs/vm-exact.textproto".into(),
            target: Some(FleetHostTarget {
                run_state: FleetHostRunState::Running as i32,
                windows_mode: FleetHostMode::Unspecified as i32,
            }),
            native_receipt_public_key: Vec::new(),
            vm_first_use_credential: None,
            worker_authority_public_key: Vec::new(),
            vm_provider_spec_path: String::new(),
        };
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![host.clone()],
        };
        let registry_pb = encode_host_registry(&registry).unwrap();
        let spec = b"exact git typed VM desired";
        let mut bundle_request = crate::ApplyBundleRequest {
            bundle_id: Some("vm-exact".to_owned()),
            prune_existing: true,
            ..Default::default()
        };
        bundle_request.bundle_digest =
            Some(crate::canonical_apply_bundle_digest(&bundle_request).unwrap());
        let bundle_pb = bundle_request.encode_to_vec();
        let transport_sha256 = ring::digest::digest(&ring::digest::SHA256, &bundle_pb)
            .as_ref()
            .to_vec();
        let release = ReleaseSet {
            schema_version: 7,
            source_revision: "a".repeat(40),
            vm_runtime: Some(VmRuntime {
                application_bundle_sha256: transport_sha256,
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
                Some(bundle_request.bundle_digest.as_deref().unwrap()),
                Some(running.get()),
                1020,
                &[],
            )
        };
        // A correctly signed action can be unsupported by the *installed*
        // owner. The capability refusal must occur before BEGIN and leave
        // both the operation ID and resource scope free for a corrected
        // owner implementation, without touching the native mutation.
        assert_eq!(
            execute_after_protected_owner_check_once(
                &intent,
                &auth,
                &registry_pb,
                spec,
                &release_pb,
                Some(&bundle_pb),
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |step| {
                    assert_eq!(step, FleetHostPlannedStep::Start);
                    Err("HOST_NATIVE_STEP_NOT_IMPLEMENTED")
                },
                |_step| panic!("unsupported step must never reach mutation")
            )
            .unwrap_err(),
            "HOST_NATIVE_STEP_NOT_IMPLEMENTED"
        );
        assert!(!native_scope_pending_path(&dir, &intent).exists());
        assert!(
            !dir.join(format!(
                "{}.pb",
                journal_hex(intent.operation_id.as_bytes())
            ))
            .exists()
        );

        let outcome = execute_after_protected_owner_check_once(
            &intent,
            &auth,
            &registry_pb,
            spec,
            &release_pb,
            Some(&bundle_pb),
            pair.public_key().as_ref(),
            "vm-exact",
            FleetHostKind::Vm as i32,
            1020,
            &dir,
            observe,
            |_step| Ok(()),
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
                &intent,
                &auth,
                &registry_pb,
                spec,
                &release_pb,
                Some(&bundle_pb),
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |_step| Ok(()),
                |_step| {
                    panic!("completed signed operation must not dispatch again");
                }
            )
            .unwrap_err(),
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
            Some(&bundle_pb),
            pair.public_key().as_ref(),
            "vm-exact",
            FleetHostKind::Vm as i32,
            1020,
            &dir,
            observe,
            |_step| Ok(()),
            |_step| {
                panic!("NOOP must never mutate");
            },
        )
        .unwrap();
        assert_eq!(noop.state, FleetHostResultState::Observed as i32);
        assert!(noop.error_class.is_empty());
        assert_eq!(noop.next_action, "NONE");
        assert_eq!(noop.observed_at_unix, 1020);
        assert!(!noop.physical_readback);
        assert_eq!(count.get(), 1);
        assert!(
            dir.join(format!(
                "{}.observed.pb",
                journal_hex(intent.operation_id.as_bytes())
            ))
            .exists()
        );
        assert!(!native_scope_pending_path(&dir, &intent).exists());
        assert_eq!(
            execute_after_protected_owner_check_once(
                &intent,
                &auth,
                &registry_pb,
                spec,
                &release_pb,
                Some(&bundle_pb),
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |_step| Ok(()),
                |_step| panic!("the same signed NOOP must not be accepted twice"),
            )
            .unwrap_err(),
            "HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"
        );
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
                Some(&bundle_pb),
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |_step| Ok(()),
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
                Some(&bundle_pb),
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |_step| Ok(()),
                |_step| {
                    panic!("pending native resource must never replay");
                }
            )
            .unwrap_err(),
            "HOST_RESOURCE_PENDING_OR_UNAVAILABLE"
        );
        assert_eq!(count.get(), 2);
        // Signed RECOVER must not re-run the failed operation: first it
        // refuses an unconverged state and retains the durable BEGIN.
        let original_operation = "issue1-comment-983";
        intent.operation_id = "issue1-comment-985".into();
        intent.action = FleetHostAction::Recover as i32;
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
                Some(&bundle_pb),
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |_step| panic!("Recover cannot authorize a mutation"),
                |_step| panic!("Recover cannot replay an unknown operation"),
            )
            .unwrap_err(),
            "HOST_NATIVE_RECOVERY_NOT_CONVERGED_NO_REPLAY"
        );
        assert!(native_scope_pending_path(&dir, &intent).exists());
        assert_eq!(count.get(), 2);
        // A later verified physical readback can settle the earlier
        // uncertain BEGIN without dispatching any additional mutation.
        running.set(true);
        let recovered = execute_after_protected_owner_check_once(
            &intent,
            &auth,
            &registry_pb,
            spec,
            &release_pb,
            Some(&bundle_pb),
            pair.public_key().as_ref(),
            "vm-exact",
            FleetHostKind::Vm as i32,
            1020,
            &dir,
            observe,
            |_step| panic!("Recover cannot authorize a mutation"),
            |_step| panic!("Recover cannot replay an unknown operation"),
        )
        .unwrap();
        assert_eq!(recovered.state, FleetHostResultState::Observed as i32);
        assert_eq!(recovered.next_action, "RECOVERED_NATIVE_RUNNING");
        assert_eq!(count.get(), 2);
        assert!(!native_scope_pending_path(&dir, &intent).exists());
        assert!(
            dir.join(format!(
                "{}.verified.pb",
                journal_hex(original_operation.as_bytes())
            ))
            .exists()
        );
        assert_eq!(
            execute_after_protected_owner_check_once(
                &intent,
                &auth,
                &registry_pb,
                spec,
                &release_pb,
                Some(&bundle_pb),
                pair.public_key().as_ref(),
                "vm-exact",
                FleetHostKind::Vm as i32,
                1020,
                &dir,
                observe,
                |_step| panic!("used signed recover cannot mutate"),
                |_step| panic!("used signed recover cannot mutate"),
            )
            .unwrap_err(),
            "HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"
        );
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
