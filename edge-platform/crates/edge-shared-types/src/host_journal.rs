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
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Windows flushes file metadata with write-through + FlushFileBuffers.
        // Opening a directory with std::File::open (Unix fsync) is invalid.
        options.custom_flags(0x8000_0000); // FILE_FLAG_WRITE_THROUGH
    }
    options.open(path)
}

fn sync_native_journal_directory(path: &Path) -> Result<(), &'static str> {
    #[cfg(not(windows))]
    {
        fs::File::open(path)
            .map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNAVAILABLE")?
            .sync_all()
            .map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNCERTAIN_NO_REPLAY")
    }
    #[cfg(windows)]
    {
        // All newly created journal files have WRITE_THROUGH and are synced
        // before this point (including their metadata). Completed operation
        // records are permanent. A removed scope reappearing after power loss
        // blocks admission; it can NEVER permit duplicate execution.
        if !fs::symlink_metadata(path)
            .map_err(|_| "HOST_JOURNAL_DIR_SYNC_UNAVAILABLE")?
            .is_dir()
        {
            return Err("HOST_JOURNAL_DIR_SYNC_UNAVAILABLE");
        }
        Ok(())
    }
}

#[cfg(unix)]
pub fn verify_native_journal_protection(path: &Path) -> Result<(), &'static str> {
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

/// Use the exact calling-process primary token for Administrator checks.
/// CheckTokenMembership requires an IMPERSONATION token, not a primary token.
/// Never pass NULL: that could select a different impersonating thread identity.
#[cfg(windows)]
fn windows_process_primary_admin_member(
    primary: windows_sys::Win32::Foundation::HANDLE,
) -> Result<bool, &'static str> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, DuplicateToken, SecurityImpersonation,
        WinBuiltinAdministratorsSid,
    };
    let mut admin_sid = [0u8; 68];
    let mut admin_length = admin_sid.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            admin_sid.as_mut_ptr().cast(),
            &mut admin_length,
        )
    } == 0
    {
        return Err("HOST_WINDOWS_FIRST_USE_ADMIN_SID_UNAVAILABLE");
    }
    let mut impersonation = std::ptr::null_mut();
    if unsafe { DuplicateToken(primary, SecurityImpersonation, &mut impersonation) } == 0 {
        return Err("HOST_WINDOWS_FIRST_USE_TOKEN_DUPLICATION_FAILED");
    }
    let mut enabled = 0i32;
    let checked =
        unsafe { CheckTokenMembership(impersonation, admin_sid.as_mut_ptr().cast(), &mut enabled) };
    unsafe { CloseHandle(impersonation) };
    if checked == 0 {
        return Err("HOST_WINDOWS_FIRST_USE_ADMIN_MEMBERSHIP_UNPROVEN");
    }
    Ok(enabled != 0)
}

/// The sole unsigned FIRST-USE exception requires a genuinely elevated
/// local Administrator token. A permissive SCM DACL is NOT sufficient:
/// NetworkService, LocalService, SYSTEM and UAC-filtered tokens fail even
/// when a process can query or change the Windows service.
#[cfg(windows)]
pub fn require_windows_local_administrator_first_use() -> Result<(), &'static str> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinLocalServiceSid, WinLocalSystemSid, WinNetworkServiceSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        )
    } == 0
    {
        return Err("HOST_WINDOWS_FIRST_USE_TOKEN_UNAVAILABLE");
    }
    let check = (|| {
        let mut length = 0u32;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
        }
        if length < std::mem::size_of::<TOKEN_USER>() as u32 || length > 65536 {
            return Err("HOST_WINDOWS_FIRST_USE_IDENTITY_UNPROVEN");
        }
        let mut bytes = vec![0u8; length as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                bytes.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err("HOST_WINDOWS_FIRST_USE_IDENTITY_UNPROVEN");
        }
        let identity: TOKEN_USER = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
        if identity.User.Sid.is_null()
            || unsafe { IsWellKnownSid(identity.User.Sid, WinLocalSystemSid) } != 0
            || unsafe { IsWellKnownSid(identity.User.Sid, WinLocalServiceSid) } != 0
            || unsafe { IsWellKnownSid(identity.User.Sid, WinNetworkServiceSid) } != 0
        {
            return Err("HOST_WINDOWS_FIRST_USE_SERVICE_TOKEN_FORBIDDEN");
        }
        // A UAC-filtered token cannot pass: Administrators must be ENABLED.
        if !windows_process_primary_admin_member(token)? {
            return Err("HOST_WINDOWS_FIRST_USE_ELEVATED_ADMIN_REQUIRED");
        }
        Ok(())
    })();
    unsafe { CloseHandle(token) };
    check
}

#[cfg(windows)]
fn windows_acl_owner_safe(privileged: bool, volume_root: bool, trusted_installer: bool) -> bool {
    privileged || (volume_root && trusted_installer)
}

// A normal Windows volume root can allow unprivileged users to CREATE a
// new sibling directory. That does not authorize DELETE_CHILD, rename, or
// alteration of the already protected C:\\sing-box subtree.
// INHERIT_ONLY templates on the volume root have no effective access there.
// We must still reject any inherited write ACE on C:\\sing-box or below.
#[cfg(windows)]
fn windows_acl_grant_safe(
    mask: u32,
    privileged: bool,
    volume_root: bool,
    inherit_only: bool,
) -> bool {
    if privileged || (volume_root && inherit_only) {
        // An INHERIT_ONLY ACE on the volume root is not effective on C:\\
        // itself. Even if it applies to newly created child objects, the
        // existing C:\\sing-box root and every executable/descendant are
        // checked separately and cannot grant unprivileged write access.
        return true;
    }
    const WRITE: u32 = 0x0000_0002 // FILE_ADD_FILE
        | 0x0000_0004 // FILE_ADD_SUBDIRECTORY
        | 0x0000_0010 // FILE_WRITE_EA
        | 0x0000_0040 // FILE_DELETE_CHILD
        | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
        | 0x0001_0000 // DELETE
        | 0x0004_0000 // WRITE_DAC
        | 0x0008_0000 // WRITE_OWNER
        | 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000; // GENERIC_WRITE
    let forbidden = if volume_root {
        WRITE & !0x0000_0004
    } else {
        WRITE
    };
    mask & forbidden == 0
}

#[cfg(windows)]
fn windows_trusted_installer_sid(sid: windows_sys::Win32::Security::PSID) -> bool {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::EqualSid;
    // NT SERVICE\\TrustedInstaller: a fixed service SID, never a localized name.
    const TRUSTED_INSTALLER: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    let wide: Vec<u16> = TRUSTED_INSTALLER
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut expected = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut expected) } == 0 {
        return false;
    }
    let equal = unsafe { EqualSid(sid, expected) } != 0;
    unsafe { LocalFree(expected) };
    equal
}

// This is an ACL-only readback, not permission to run a SYSTEM operation.
// The caller still needs the exact LocalSystem token / signed intent gates.
// Both directory ancestors AND the supplied leaf (including an EXE or
// current.pb) are checked. The volume-root exception never applies elsewhere.
#[cfg(windows)]
pub fn verify_windows_protected_path_acl(path: &Path, leaf_file: bool) -> Result<(), &'static str> {
    if !path.is_absolute() || !path.starts_with(Path::new(r"C:\sing-box")) {
        return Err("HOST_WINDOWS_JOURNAL_ABSOLUTE_PATH_REQUIRED");
    }
    verify_windows_acl_chain(path, leaf_file, false)
}

/// Read-only verification of an installed OS/vendor executable used by the
/// canonical owner. TrustedInstaller is a privileged writer here, while the
/// stricter application/journal owner policy above is unchanged.
#[cfg(windows)]
pub fn verify_windows_system_executable_acl(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute()
        || !(path.starts_with(r"C:\Windows") || path.starts_with(r"C:\Program Files"))
    {
        return Err("HOST_WINDOWS_SYSTEM_EXECUTABLE_SCOPE_INVALID");
    }
    verify_windows_acl_chain(path, true, true)
}

#[cfg(windows)]
fn verify_windows_acl_chain(
    path: &Path,
    leaf_file: bool,
    system_executable: bool,
) -> Result<(), &'static str> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, GetAce, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    for (index, ancestor) in path.ancestors().enumerate() {
        let meta = fs::symlink_metadata(ancestor)
            .map_err(|_| "HOST_WINDOWS_JOURNAL_ANCESTOR_UNAVAILABLE")?;
        let is_leaf_file = index == 0 && leaf_file;
        if (is_leaf_file && !meta.file_type().is_file())
            || (!is_leaf_file && !meta.file_type().is_dir())
            || meta.file_type().is_symlink()
            || meta.file_attributes() & 0x400 != 0
        {
            return Err("HOST_WINDOWS_JOURNAL_REPARSE_OR_NOT_DIRECTORY");
        }
        let volume_root = ancestor == Path::new(r"C:\");
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
                    || (system_executable && windows_trusted_installer_sid(sid))
            };
            if !windows_acl_owner_safe(
                privileged(owner),
                volume_root,
                windows_trusted_installer_sid(owner),
            ) {
                return false;
            }
            let acl = unsafe { &*dacl };
            for index in 0..acl.AceCount {
                let mut ace = std::ptr::null_mut();
                if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 || ace.is_null() {
                    return false;
                }
                let header = unsafe { &*(ace as *const windows_sys::Win32::Security::ACE_HEADER) };
                if header.AceType != 0 && header.AceType != 1 {
                    // Unknown/object-specific ACE layouts are never guessed.
                    return false;
                }
                if header.AceType == 0 {
                    let grant = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                    let sid = (&grant.SidStart as *const u32).cast_mut().cast();
                    let inherit_only = header.AceFlags & 0x08 != 0; // INHERIT_ONLY_ACE
                    if !windows_acl_grant_safe(
                        grant.Mask,
                        privileged(sid) || (volume_root && windows_trusted_installer_sid(sid)),
                        volume_root,
                        inherit_only,
                    ) {
                        return false;
                    }
                }
            }
            true
        })();
        unsafe { LocalFree(descriptor) };
        if !safe {
            return Err("HOST_WINDOWS_JOURNAL_DACL_NOT_PROTECTED");
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn windows_native_acl_owner_sid(path: &Path) -> Result<String, &'static str> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        return Err("HOST_WINDOWS_JOURNAL_SECURITY_UNAVAILABLE");
    }
    let mut string_ptr: *mut u16 = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(owner, &mut string_ptr) };
    unsafe { LocalFree(descriptor) };
    if converted == 0 || string_ptr.is_null() {
        return Err("HOST_WINDOWS_JOURNAL_SECURITY_UNAVAILABLE");
    }
    let mut len = 0usize;
    while len < 128 && unsafe { *string_ptr.add(len) } != 0 {
        len += 1;
    }
    let result = if len == 128 {
        Err("HOST_WINDOWS_JOURNAL_SECURITY_UNAVAILABLE")
    } else {
        Ok(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(string_ptr, len)
        }))
    };
    unsafe { LocalFree(string_ptr.cast()) };
    result
}

#[cfg(windows)]
pub fn verify_native_journal_protection(path: &Path) -> Result<(), &'static str> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
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

    verify_windows_protected_path_acl(path, false)
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
    sync_native_journal_directory(protected_journal_dir)?;
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
    sync_native_journal_directory(protected_journal_dir)?;
    Ok(recorded)
}

/// The existing Protobuf action and native planner must describe the SAME
/// intended effect. A signed Windows START cannot silently become STOP or
/// replace an entire release merely because the observed state drifted.
/// This is a pure guard, not a new owner or mutation protocol.
fn validate_native_action_kind(
    kind: crate::FleetHostKind,
    action: crate::FleetHostAction,
) -> Result<(), &'static str> {
    use crate::{FleetHostAction as Action, FleetHostKind as Kind};
    match (kind, action) {
        (Kind::Vm, Action::Apply | Action::Recover)
        | (Kind::Windows, Action::Apply | Action::Recover | Action::Start | Action::Stop) => Ok(()),
        (Kind::Windows, Action::SetMode) => {
            // The pure planner deliberately blocks ManagedTun until its own
            // physical gate exists. Never use START or APPLY as an alias.
            Err("HOST_WINDOWS_SIGNED_MODE_EFFECT_NOT_ACCEPTED")
        }
        _ => Err("HOST_NATIVE_EXECUTION_ACTION_NOT_ALLOWED"),
    }
}

fn validate_native_action_step(
    kind: crate::FleetHostKind,
    action: crate::FleetHostAction,
    step: crate::FleetHostPlannedStep,
) -> Result<(), &'static str> {
    use crate::{FleetHostAction as Action, FleetHostKind as Kind, FleetHostPlannedStep as Step};
    validate_native_action_kind(kind, action)?;
    match (kind, action) {
        (Kind::Windows, Action::Start) if !matches!(step, Step::Start | Step::Noop) => {
            Err("HOST_WINDOWS_SIGNED_START_STEP_MISMATCH")
        }
        (Kind::Windows, Action::Stop) if !matches!(step, Step::Stop | Step::Noop) => {
            Err("HOST_WINDOWS_SIGNED_STOP_STEP_MISMATCH")
        }
        _ => Ok(()),
    }
}

/// One native transaction boundary for an already independently authenticated
/// and Git/ReleaseSet-bound owner. It never accepts a runner decision about
/// what to execute: the privileged owner reads its OWN state and the common
/// Rust planner selects the single permitted action. Every mutation has one
/// durable admission followed by at most one native invocation.
///
/// The closure may use only existing typed Controller/Agent operations. In
/// particular, it must not run an operator-supplied installer or shell text.
/// A release transition uses only its native adapter and independently verified
/// canonical release installer. It cannot retry a partial action. Failure deliberately
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
        None,
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

/// Windows SYSTEM supplies this digest only after verifying the exact installed
/// activation. Git ReleaseSet authenticates the intent; installed runtime
/// authenticates the physical planner. VM semantics remain unchanged.
#[derive(Clone, Copy)]
pub struct WindowsExecutionBinding<'a> {
    pub installed_release_sha256: &'a [u8],
    pub expected_config_sha256: Option<&'a [u8]>,
}

pub fn execute_native_windows_host_once<Observe, Allow, Apply>(
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
    installed_release_sha256: &[u8],
    expected_config_sha256: Option<&[u8]>,
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
        Some(WindowsExecutionBinding {
            installed_release_sha256,
            expected_config_sha256,
        }),
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
    expected_windows_installed_release: Option<WindowsExecutionBinding<'_>>,
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
    use crate::{FleetHostAction, FleetHostPlannedStep, FleetHostResultState};

    // Authentication and owner identity must precede even readback-driven
    // planning. A signed APPLY/RECOVER is not the same as an arbitrary START.
    if intent.machine_id != native_machine_id || intent.kind != native_owner_kind {
        return Err("HOST_LOCAL_OWNER_IDENTITY_MISMATCH");
    }
    let (registry, mut bound) = bind_native_host_artifacts(
        intent,
        registry_pb,
        selected_spec_bytes,
        release_set_pb,
        vm_bundle_pb,
    )?;
    if let Some(binding) = expected_windows_installed_release {
        let installed = binding.installed_release_sha256;
        if binding
            .expected_config_sha256
            .is_some_and(|sha| sha.len() != 32 || sha.iter().all(|b| *b == 0))
        {
            return Err("HOST_WINDOWS_EXPECTED_CONFIG_DIGEST_INVALID");
        }
        if native_owner_kind != crate::FleetHostKind::Windows as i32
            || intent.kind != native_owner_kind
            || installed.len() != 32
            || installed.iter().all(|b| *b == 0)
        {
            return Err("HOST_WINDOWS_INSTALLED_RUNTIME_PROOF_INVALID");
        }
        if intent.action != crate::FleetHostAction::Apply as i32 {
            bound.runtime_release_sha256 = installed.to_vec();
        }
    }
    validate_intent_against_target(intent, &registry)?;
    // Windows SYSTEM must use the public signer identity from its own
    // independently accepted Git registry, not the runner's choice of key.
    if intent.kind == crate::FleetHostKind::Windows as i32 {
        let selected = registry
            .hosts
            .iter()
            .find(|host| host.machine_id == intent.machine_id && host.kind == intent.kind)
            .ok_or("HOST_INTENT_UNKNOWN_MACHINE")?;
        crate::host_lifecycle::verify_git_host_worker_signer_pin(
            selected,
            pinned_worker_public_key,
        )?;
    }
    verify_host_authorization(intent, authorization, pinned_worker_public_key, now_unix)?;
    let action = FleetHostAction::try_from(intent.action)
        .map_err(|_| "HOST_NATIVE_EXECUTION_ACTION_NOT_ALLOWED")?;
    let kind = crate::FleetHostKind::try_from(intent.kind)
        .map_err(|_| "HOST_NATIVE_EXECUTION_ACTION_NOT_ALLOWED")?;
    validate_native_action_kind(kind, action)?;

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
        if (name.starts_with("resource-") || name.starts_with("admin-"))
            && name.ends_with(".pending.pb")
        {
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
            if kind == crate::FleetHostKind::Windows {
                let expected = expected_windows_installed_release
                    .and_then(|b| b.expected_config_sha256)
                    .ok_or("HOST_WINDOWS_RECOVERY_CONFIGURATION_UNPROVEN_NO_REPLAY")?;
                if observed.windows_config_sha256 != expected {
                    return Err("HOST_WINDOWS_RECOVERY_CONFIGURATION_NOT_CONVERGED_NO_REPLAY");
                }
            }
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
    if let Some(binding) = expected_windows_installed_release {
        let installed = binding.installed_release_sha256;
        if before.release_proof != crate::FleetNativeReleaseProof::ActivationRecord as i32
            || before.observed_release_sha256.as_slice() != installed
        {
            return Err("HOST_WINDOWS_INSTALLED_RUNTIME_READBACK_MISMATCH");
        }
    }
    // Only the signed Git production spec owns the Windows datapath. The
    // in-memory projection is for the existing pure planner; journal digests
    // and receipts always use the original unmodified registry protobuf.
    let planned_host =
        crate::host_lifecycle::project_host_for_planner(selected, selected_spec_bytes)?;
    let mut plan = crate::host_planner::propose_signed_host_transition(
        &planned_host,
        &before,
        action,
        if expected_windows_installed_release.is_some() {
            &bound.runtime_release_sha256
        } else {
            &bound.release_set_sha256
        },
        &bound.runtime_release_sha256,
        now_unix,
    );
    let config = expected_windows_installed_release.and_then(|b| b.expected_config_sha256);
    if action == FleetHostAction::Apply
        && plan.step == FleetHostPlannedStep::Noop as i32
        && config.is_some_and(|sha| before.windows_config_sha256 != sha)
    {
        if kind != crate::FleetHostKind::Windows
            || before.owner_state != crate::FleetNativeOwnerState::Stopped as i32
        {
            return Err("HOST_WINDOWS_CONFIGURATION_REQUIRES_STOPPED_OWNER");
        }
        plan.step = FleetHostPlannedStep::Configure as i32;
        plan.reason = crate::FleetHostPlanReason::StoppedConfigurationDrift as i32;
        plan.reason_code = "STOPPED_CONFIGURATION_DRIFT".into();
    }
    crate::host_planner::validate_host_transition_plan(&plan, &planned_host)?;
    let step =
        FleetHostPlannedStep::try_from(plan.step).map_err(|_| "HOST_NATIVE_PLAN_STEP_INVALID")?;
    // The transaction does not allow a stale or untrusted observation to
    // trigger even an "idempotent" mutation. A NOOP has no journal mutation
    // and cannot be promoted to VERIFIED by an external caller.
    if step == FleetHostPlannedStep::Blocked {
        return Err("HOST_NATIVE_PLAN_BLOCKED");
    }
    // After independently signed admission and fresh native observation,
    // preserve the exact intent action before NOOP or durable BEGIN.
    validate_native_action_step(kind, action, step)?;
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
            | FleetHostPlannedStep::Configure
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
    let effect_started = std::time::Instant::now();
    apply_once(step)?;
    finish_after_protected_owner_check_once(
        intent,
        &registry,
        native_machine_id,
        native_owner_kind,
        &bound.runtime_release_sha256,
        step,
        &before.observed_release_sha256,
        now_unix.saturating_add(effect_started.elapsed().as_secs()),
        protected_journal_dir,
        || {
            let observed = observe()?;
            if action == FleetHostAction::Apply
                && config.is_some_and(|sha| observed.windows_config_sha256 != sha)
            {
                return Err("HOST_WINDOWS_CONFIG_POSTSTATE_MISMATCH");
            }
            Ok(observed)
        },
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
    // Historical recovery is read-only. Network mode comes from the signed
    // production spec; raw registry mode is always absent for both host kinds.
    if mode != FleetHostMode::Unspecified {
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

/// Classify a prior BEGIN as incomplete when Git release changed OR when
/// the installed bundle matches but an independently proven addressed
/// application datapath is still degraded. RECOVER only proves a known
/// current baseline; it never replays the historical Docker effect.
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
        || !(observed.owner_state == FleetNativeOwnerState::Running as i32
            && crate::host_lifecycle::known_runtime_only_historical_reasons(observed)
            || crate::host_lifecycle::known_partial_vm_resource_baseline(host, observed))
        || observed.release_proof != FleetNativeReleaseProof::ApplicationBundle as i32
        // Broken network/proxy readiness is the problem a fresh replacement
        // must repair. Its FALSE value is admissible only when an owned native
        // readback explicitly PROVES that value; never equate it with success.
        || !observed.runtime_ready_proven
        || current_release.len() != 32
        || observed.observed_release_sha256.len() != 32
        || observed
            .observed_release_sha256
            .iter()
            .all(|byte| *byte == 0)
        // A healthy readback at the current source is not a missing-ACK
        // datapath recovery proof for a different old BEGIN. Same-release
        // historical INCOMPLETE needs a specific observed runtime defect.
        || (observed.observed_release_sha256 == current_release
            && (observed.runtime_ready
                || !crate::host_lifecycle::known_runtime_only_historical_reasons(observed)))
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
    // A failed first-use or OCI pull can still be incomplete under the SAME
    // ReleaseSet. Requiring a new Git release to classify this state would
    // cause another loop. The root-observed installed digest is independent
    // of the pending source identity and must not be mistaken for convergence.
    let native_release_mismatch = observed.observed_release_sha256 != bound.runtime_release_sha256;
    let known_runtime_incomplete = selected.kind == crate::FleetHostKind::Vm as i32
        && observed.owner_state == crate::FleetNativeOwnerState::Running as i32
        && !observed.runtime_ready
        && crate::host_lifecycle::known_runtime_only_historical_reasons(observed);
    let incomplete = historical_drift || native_release_mismatch || known_runtime_incomplete;
    if incomplete
        && (original.action != FleetHostAction::Apply as i32
            || original.resource_id != "sing-box"
            || selected.kind != crate::FleetHostKind::Vm as i32)
    {
        return Err("HOST_NATIVE_HISTORICAL_SCOPE_UNSUPPORTED_NO_REPLAY");
    }
    let verdict = if incomplete {
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
            sync_native_journal_directory(journal_dir)?;
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
    sync_native_journal_directory(journal_dir)?;
    fs::remove_file(&scope).map_err(|_| "HOST_SCOPE_RELEASE_UNCERTAIN_NO_REPLAY")?;
    sync_native_journal_directory(journal_dir)?;
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
            vm_recovery_resources: None,
            windows_config_sha256: Vec::new(),
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
    fn historical_partial_recovery_preserves_original_unknown_and_never_verifies_it() {
        use crate::host_lifecycle::{
            BoundNativeHostArtifacts, host_authorization_payload, prepared_host_result,
            set_host_result_reason,
        };
        use crate::{FleetNativeOwnerState, FleetNativeReleaseProof};
        let rng = SystemRandom::new();
        let pair =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let host = FleetHost {
            machine_id: "vm-history".into(),
            kind: FleetHostKind::Vm as i32,
            owner: Some(managed_host::Owner::VmMachineId("vm-history".into())),
            target: Some(FleetHostTarget {
                run_state: FleetHostRunState::Running as i32,
                windows_mode: FleetHostMode::Unspecified as i32,
            }),
            ..Default::default()
        };
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![host.clone()],
        };
        let old = FleetHostIntent {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            kind: host.kind,
            resource_id: "sing-box".into(),
            operation_id: "issue1-comment-100".into(),
            action: FleetHostAction::Apply as i32,
            registry_sha256: vec![9; 32],
            desired_sha256: vec![8; 32],
            release_set_sha256: vec![7; 32],
            requested_at_unix: 1000,
            ..Default::default()
        };
        let mut current = old.clone();
        current.operation_id = "issue1-comment-101".into();
        current.action = FleetHostAction::Recover as i32;
        current.registry_sha256 = vec![1; 32];
        current.desired_sha256 = vec![2; 32];
        current.release_set_sha256 = vec![3; 32];
        let bound = BoundNativeHostArtifacts {
            registry_sha256: current.registry_sha256.clone(),
            desired_sha256: current.desired_sha256.clone(),
            release_set_sha256: current.release_set_sha256.clone(),
            runtime_release_sha256: vec![4; 32],
        };
        let mut authorization = FleetHostAuthorization {
            schema_version: 1,
            key_id: "worker-v1".into(),
            operation_id: current.operation_id.clone(),
            issued_at_unix: 1000,
            expires_at_unix: 1100,
            ..Default::default()
        };
        authorization.ed25519_signature = pair
            .sign(&host_authorization_payload(&current, &authorization))
            .as_ref()
            .to_vec();
        let observation = crate::FleetNativeObservation {
            schema_version: 1,
            host_kind: host.kind,
            observed_at_unix: 1020,
            owner_state: FleetNativeOwnerState::Running as i32,
            release_proof: FleetNativeReleaseProof::ApplicationBundle as i32,
            observed_release_sha256: vec![6; 32],
            runtime_ready: true,
            runtime_ready_proven: true,
            ..Default::default()
        };
        let dir = std::env::temp_dir().join(format!(
            "sing-box-partial-recovery-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(native_scope_pending_path(&dir, &old), old.encode_to_vec()).unwrap();
        let mut begin = prepared_host_result(&old);
        begin.state = FleetHostResultState::Authorized as i32;
        set_host_result_reason(
            &mut begin,
            crate::FleetHostResultReason::AuthorizedAwaitNativeReadback,
        );
        fs::write(
            dir.join(format!("{}.pb", journal_hex(old.operation_id.as_bytes()))),
            begin.encode_to_vec(),
        )
        .unwrap();
        let resolve = |observed: &crate::FleetNativeObservation| {
            resolve_pending_native_recovery_once(
                &current,
                &authorization,
                &registry,
                &host,
                &bound,
                pair.public_key().as_ref(),
                &host.machine_id,
                host.kind,
                1020,
                &dir,
                observed,
            )
        };
        let mut unproven = observation.clone();
        unproven.runtime_ready = false;
        unproven.runtime_ready_proven = false;
        assert_eq!(
            resolve(&unproven).unwrap_err(),
            "HOST_NATIVE_HISTORICAL_BASELINE_UNPROVEN_NO_REPLAY"
        );
        let mut degraded = observation.clone();
        degraded.runtime_ready = false;
        // Unexplained false readiness never settles an unknown prior effect.
        assert_eq!(
            verify_historical_partial_recovery_state(
                &host,
                &degraded,
                &bound.runtime_release_sha256,
                1020,
            ),
            Err("HOST_NATIVE_HISTORICAL_BASELINE_UNPROVEN_NO_REPLAY")
        );
        assert!(native_scope_pending_path(&dir, &old).exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        // A specific attempted consumer datapath probe is distinguishable
        // from absent resources. The old generic WARP code is NOT sufficient.
        degraded.reason_codes = vec!["WARP_LINE1_CONSUMER_EGRESS_FAILED".into()];
        let mut same_release = degraded.clone();
        same_release.observed_release_sha256 = bound.runtime_release_sha256.clone();
        assert_eq!(
            verify_historical_partial_recovery_state(
                &host,
                &same_release,
                &bound.runtime_release_sha256,
                1020,
            ),
            Ok(crate::FleetHostResultReason::HistoricalPartialRequiresFreshApply)
        );
        assert_eq!(
            verify_historical_partial_recovery_state(
                &host,
                &degraded,
                &bound.runtime_release_sha256,
                1020,
            ),
            Ok(crate::FleetHostResultReason::HistoricalPartialRequiresFreshApply)
        );
        // Any non-datapath reason, including one mixed with an accepted code,
        // cannot release the old durable scope.
        for reason in [
            "WARP_EGRESS_FAILED",
            "WARP_CONSUMERS_ABSENT",
            "WARP_CLIENT_CONNECTION_UNPROVEN",
            "DIRECT_EGRESS_FAILED",
            "TCP_PORTS_MISSING",
            "UDP_PORTS_MISSING",
            "MESH_RUNTIME_UNREADY",
            "CONTAINER_NOT_RUNNING",
            "EXACT_IMAGE_OR_CONTAINER_UNREADY",
            "DOCKER_UNAVAILABLE",
            "OTHER_UNPROVEN",
            "VM_DIAGNOSTIC_TRUNCATED",
        ] {
            degraded.reason_codes = vec!["WARP_LINE1_CONSUMER_EGRESS_FAILED".into(), reason.into()];
            assert_eq!(
                verify_historical_partial_recovery_state(
                    &host,
                    &degraded,
                    &bound.runtime_release_sha256,
                    1020,
                ),
                Err("HOST_NATIVE_HISTORICAL_BASELINE_UNPROVEN_NO_REPLAY")
            );
            // Reject at the actual journal boundary too, without consuming
            // the pending gate or emitting any terminal receipt.
            assert_eq!(
                resolve(&degraded),
                Err("HOST_NATIVE_HISTORICAL_BASELINE_UNPROVEN_NO_REPLAY")
            );
            assert!(native_scope_pending_path(&dir, &old).exists());
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        }
        degraded.reason_codes = vec!["WARP_LINE1_CONSUMER_EGRESS_FAILED".into()];
        degraded.runtime_ready_proven = false;
        assert_eq!(
            verify_historical_partial_recovery_state(
                &host,
                &degraded,
                &bound.runtime_release_sha256,
                1020,
            ),
            Err("HOST_NATIVE_HISTORICAL_BASELINE_UNPROVEN_NO_REPLAY")
        );
        degraded.runtime_ready_proven = true;
        // Recovery with a known degraded datapath can terminalize the old
        // UNKNOWN only as INCOMPLETE, never as VERIFIED.
        let recovered_degraded = resolve(&degraded).unwrap();
        assert_eq!(
            recovered_degraded.state,
            FleetHostResultState::Observed as i32
        );
        let prior_id = journal_hex(old.operation_id.as_bytes());
        let original_terminal = crate::host_lifecycle::decode_host_result(
            &fs::read(dir.join(format!("{prior_id}.incomplete.pb"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            original_terminal.state,
            FleetHostResultState::UnknownNoReplay as i32
        );
        assert!(!original_terminal.physical_readback);
        assert!(!dir.join(format!("{prior_id}.verified.pb")).exists());
        assert!(!native_scope_pending_path(&dir, &old).exists());
        fs::remove_dir_all(&dir).unwrap();
        // The existing scenario below exercises a separate fresh journal.
        let dir = std::env::temp_dir().join(format!(
            "sing-box-partial-recovery-continued-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(native_scope_pending_path(&dir, &old), old.encode_to_vec()).unwrap();
        fs::write(
            dir.join(format!("{}.pb", journal_hex(old.operation_id.as_bytes()))),
            begin.encode_to_vec(),
        )
        .unwrap();
        let resolve = |observed: &crate::FleetNativeObservation| {
            resolve_pending_native_recovery_once(
                &current,
                &authorization,
                &registry,
                &host,
                &bound,
                pair.public_key().as_ref(),
                &host.machine_id,
                host.kind,
                1020,
                &dir,
                observed,
            )
        };
        let mut wrong_release = observation.clone();
        wrong_release.observed_release_sha256 = vec![4; 32];
        assert_eq!(
            resolve(&wrong_release).unwrap_err(),
            "HOST_NATIVE_HISTORICAL_BASELINE_UNPROVEN_NO_REPLAY"
        );
        assert!(native_scope_pending_path(&dir, &old).exists());
        let result = resolve(&observation).unwrap();
        assert_eq!(result.state, FleetHostResultState::Observed as i32);
        assert!(!result.physical_readback);
        assert_eq!(
            result.reason,
            crate::FleetHostResultReason::HistoricalPartialRequiresFreshApply as i32
        );
        assert!(!native_scope_pending_path(&dir, &old).exists());
        let prior_id = journal_hex(old.operation_id.as_bytes());
        let incomplete = crate::host_lifecycle::decode_host_result(
            &fs::read(dir.join(format!("{prior_id}.incomplete.pb"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            incomplete.state,
            FleetHostResultState::UnknownNoReplay as i32
        );
        assert!(!incomplete.physical_readback);
        assert_eq!(incomplete.operation_id, old.operation_id);
        assert!(!dir.join(format!("{prior_id}.verified.pb")).exists());
        assert!(
            dir.join(format!(
                "{}.observed.pb",
                journal_hex(current.operation_id.as_bytes())
            ))
            .exists()
        );
        assert!(resolve(&observation).is_err()); // Old gate never re-created or re-executed.
        fs::remove_dir_all(dir).unwrap();
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
            vm_recovery_resources: None,
            windows_config_sha256: Vec::new(),
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
            vm_recovery_resources: None,
            windows_config_sha256: Vec::new(),
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
                None,
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
            None,
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
                None,
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
            None,
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
                None,
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
                None,
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
                None,
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
                None,
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
            None,
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
                None,
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

    #[test]
    fn windows_signed_stop_requires_exact_git_signer_and_owner_capability_before_begin() {
        use crate::host_lifecycle::{digest_host_desired, host_authorization_payload};
        use crate::release::v1::ReleaseSet;
        use crate::{
            FleetHost, FleetHostTarget, FleetNativeObservation, FleetNativeOwnerState,
            FleetNativeReleaseProof, HostRegistry, encode_host_registry,
        };
        let rng = SystemRandom::new();
        let signer =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        let host = FleetHost {
            machine_id: "windows-exact".into(),
            kind: FleetHostKind::Windows as i32,
            owner: Some(managed_host::Owner::WindowsRunnerName(
                "DESKTOP-EXACT".into(),
            )),
            windows_runner_label: "windows-exact".into(),
            desired_spec_path: "infra/production/production.textproto".into(),
            target: Some(FleetHostTarget {
                run_state: FleetHostRunState::Stopped as i32,
                windows_mode: FleetHostMode::Unspecified as i32,
            }),
            worker_authority_public_key: signer.public_key().as_ref().to_vec(),
            ..Default::default()
        };
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![host.clone()],
        };
        let registry_pb = encode_host_registry(&registry).unwrap();
        let spec = b"windows_datapath_mode: WINDOWS_DATAPATH_MODE_PROXY_ONLY\n";
        let release_pb = ReleaseSet {
            schema_version: 7,
            source_revision: "a".repeat(40),
            ..Default::default()
        }
        .encode_to_vec();
        let intent = FleetHostIntent {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            kind: host.kind,
            resource_id: "sing-box".into(),
            operation_id: "issue1-comment-881".into(),
            action: FleetHostAction::Stop as i32,
            registry_sha256: digest(&SHA256, &registry_pb).as_ref().to_vec(),
            desired_sha256: digest_host_desired(&host, spec).unwrap(),
            release_set_sha256: digest(&SHA256, &release_pb).as_ref().to_vec(),
            requested_at_unix: 1000,
            ..Default::default()
        };
        let mut auth = FleetHostAuthorization {
            schema_version: 1,
            key_id: "worker-v1".into(),
            operation_id: intent.operation_id.clone(),
            issued_at_unix: 1000,
            expires_at_unix: 1100,
            ..Default::default()
        };
        auth.ed25519_signature = signer
            .sign(&host_authorization_payload(&intent, &auth))
            .as_ref()
            .to_vec();
        let dir = std::env::temp_dir().join(format!(
            "sing-box-windows-signed-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let observe = || {
            Ok(FleetNativeObservation {
                schema_version: 1,
                host_kind: FleetHostKind::Windows as i32,
                observed_at_unix: 1020,
                owner_state: FleetNativeOwnerState::Running as i32,
                release_proof: FleetNativeReleaseProof::ActivationRecord as i32,
                observed_release_sha256: intent.release_set_sha256.clone(),
                ..Default::default()
            })
        };
        let call = |pin: &[u8]| {
            execute_after_protected_owner_check_once(
                None,
                &intent,
                &auth,
                &registry_pb,
                spec,
                &release_pb,
                None,
                pin,
                "windows-exact",
                FleetHostKind::Windows as i32,
                1020,
                &dir,
                observe,
                |step| {
                    assert_eq!(step, FleetHostPlannedStep::Stop);
                    Err("HOST_WINDOWS_SIGNED_SYSTEM_HANDLER_MISSING")
                },
                |_step| panic!("unauthorized Windows SCM mutation"),
            )
        };
        assert_eq!(
            call(&[9; 32]).unwrap_err(),
            "HOST_WORKER_SIGNER_DIFFERS_FROM_PROTECTED_GIT"
        );
        assert_eq!(
            call(signer.public_key().as_ref()).unwrap_err(),
            "HOST_WINDOWS_SIGNED_SYSTEM_HANDLER_MISSING"
        );
        // New published Git-only source cannot masquerade as the installed
        // ActivationRecord. Exact SYSTEM runtime mismatch is a denial before
        // BEGIN, even when the Worker signature and current Git are valid.
        let stale_installed = vec![7_u8; 32];
        assert_eq!(
            execute_after_protected_owner_check_once(
                Some(WindowsExecutionBinding {
                    installed_release_sha256: &stale_installed,
                    expected_config_sha256: None
                }),
                &intent,
                &auth,
                &registry_pb,
                spec,
                &release_pb,
                None,
                signer.public_key().as_ref(),
                "windows-exact",
                FleetHostKind::Windows as i32,
                1020,
                &dir,
                observe,
                |_| panic!("unverified installed runtime must not be planned"),
                |_| panic!("unverified installed runtime must not mutate"),
            )
            .unwrap_err(),
            "HOST_WINDOWS_INSTALLED_RUNTIME_READBACK_MISMATCH"
        );
        // A Git-only configuration change is a journaled CONFIGURE, never a
        // fabricated NOOP or implicit service START. Verify exact poststate.
        let mut configuration_intent = intent.clone();
        configuration_intent.action = FleetHostAction::Apply as i32;
        configuration_intent.operation_id = "issue1-comment-882".into();
        let mut configuration_auth = auth.clone();
        configuration_auth.operation_id = configuration_intent.operation_id.clone();
        configuration_auth.ed25519_signature = signer
            .sign(&host_authorization_payload(
                &configuration_intent,
                &configuration_auth,
            ))
            .as_ref()
            .to_vec();
        let applied = std::cell::Cell::new(false);
        let calls = std::cell::Cell::new(0);
        let cfg_observe = || {
            let mut o = observe()?;
            o.owner_state = FleetNativeOwnerState::Stopped as i32;
            o.windows_config_sha256 = if applied.get() {
                vec![4; 32]
            } else {
                vec![3; 32]
            };
            Ok(o)
        };
        let binding = WindowsExecutionBinding {
            installed_release_sha256: &intent.release_set_sha256,
            expected_config_sha256: Some(&[4; 32]),
        };
        let cfg_result = execute_after_protected_owner_check_once(
            Some(binding),
            &configuration_intent,
            &configuration_auth,
            &registry_pb,
            spec,
            &release_pb,
            None,
            signer.public_key().as_ref(),
            "windows-exact",
            FleetHostKind::Windows as i32,
            1020,
            &dir,
            cfg_observe,
            |s| {
                assert_eq!(s, FleetHostPlannedStep::Configure);
                Ok(())
            },
            |s| {
                assert_eq!(s, FleetHostPlannedStep::Configure);
                calls.set(calls.get() + 1);
                applied.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(cfg_result.physical_readback);
        assert_eq!(calls.get(), 1);
        assert!(
            execute_after_protected_owner_check_once(
                Some(binding),
                &configuration_intent,
                &configuration_auth,
                &registry_pb,
                spec,
                &release_pb,
                None,
                signer.public_key().as_ref(),
                "windows-exact",
                FleetHostKind::Windows as i32,
                1020,
                &dir,
                cfg_observe,
                |_| panic!("replay admission"),
                |_| panic!("replay effect")
            )
            .is_err()
        );

        // An interrupted CONFIGURE cannot be resolved by observing SCM only.
        configuration_intent.operation_id = "issue1-comment-883".into();
        configuration_auth.operation_id = configuration_intent.operation_id.clone();
        configuration_auth.ed25519_signature = signer
            .sign(&host_authorization_payload(
                &configuration_intent,
                &configuration_auth,
            ))
            .as_ref()
            .to_vec();
        applied.set(false);
        assert_eq!(
            execute_after_protected_owner_check_once(
                Some(binding),
                &configuration_intent,
                &configuration_auth,
                &registry_pb,
                spec,
                &release_pb,
                None,
                signer.public_key().as_ref(),
                "windows-exact",
                FleetHostKind::Windows as i32,
                1020,
                &dir,
                cfg_observe,
                |_| Ok(()),
                |_| Err("INJECTED_CONFIG_UNKNOWN")
            )
            .unwrap_err(),
            "INJECTED_CONFIG_UNKNOWN"
        );
        let pending = native_scope_pending_path(&dir, &configuration_intent);
        let original = fs::read(&pending).unwrap();
        let mut recovery = configuration_intent.clone();
        recovery.action = FleetHostAction::Recover as i32;
        recovery.operation_id = "issue1-comment-884".into();
        let mut recovery_auth = configuration_auth.clone();
        recovery_auth.operation_id = recovery.operation_id.clone();
        recovery_auth.ed25519_signature = signer
            .sign(&host_authorization_payload(&recovery, &recovery_auth))
            .as_ref()
            .to_vec();
        assert_eq!(
            execute_after_protected_owner_check_once(
                Some(binding),
                &recovery,
                &recovery_auth,
                &registry_pb,
                spec,
                &release_pb,
                None,
                signer.public_key().as_ref(),
                "windows-exact",
                FleetHostKind::Windows as i32,
                1020,
                &dir,
                cfg_observe,
                |_| panic!("unknown recovery admission"),
                |_| panic!("unknown recovery effect")
            )
            .unwrap_err(),
            "HOST_WINDOWS_RECOVERY_CONFIGURATION_NOT_CONVERGED_NO_REPLAY"
        );
        assert_eq!(fs::read(&pending).unwrap(), original);

        use crate::host_planner::propose_host_transition;
        // The pure planner consumes only the memory projection, never the
        // raw signed Git registry, whose deprecated mode field is absent.
        let planned_host = crate::host_lifecycle::project_host_for_planner(&host, spec).unwrap();
        let stopped = FleetNativeObservation {
            owner_state: FleetNativeOwnerState::Stopped as i32,
            observed_release_sha256: stale_installed.clone(),
            ..observe().unwrap()
        };
        assert_eq!(
            propose_host_transition(
                &planned_host,
                Some(&stopped),
                &intent.release_set_sha256,
                &intent.release_set_sha256,
                1020
            )
            .step,
            FleetHostPlannedStep::Blocked as i32,
        );
        assert_eq!(
            propose_host_transition(
                &planned_host,
                Some(&stopped),
                &stale_installed,
                &intent.release_set_sha256,
                1020
            )
            .step,
            FleetHostPlannedStep::Noop as i32,
        );
        // The injected unknown CONFIGURE deliberately retains this SAME
        // resource gate; the earlier STOP admission failures created none.
        assert_eq!(
            fs::read(native_scope_pending_path(&dir, &intent)).unwrap(),
            original
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signed_native_windows_actions_never_reinterpret_planned_effects() {
        use crate::{
            FleetHostAction as Action, FleetHostKind as Kind, FleetHostPlannedStep as Step,
        };
        assert_eq!(
            validate_native_action_kind(Kind::Vm, Action::Start),
            Err("HOST_NATIVE_EXECUTION_ACTION_NOT_ALLOWED")
        );
        assert_eq!(
            validate_native_action_kind(Kind::Vm, Action::SetMode),
            Err("HOST_NATIVE_EXECUTION_ACTION_NOT_ALLOWED")
        );
        assert_eq!(
            validate_native_action_kind(Kind::Windows, Action::SetMode),
            Err("HOST_WINDOWS_SIGNED_MODE_EFFECT_NOT_ACCEPTED")
        );
        assert_eq!(
            validate_native_action_step(Kind::Windows, Action::Start, Step::Start),
            Ok(())
        );
        assert_eq!(
            validate_native_action_step(Kind::Windows, Action::Stop, Step::Stop),
            Ok(())
        );
        assert_eq!(
            validate_native_action_step(Kind::Windows, Action::Start, Step::Noop),
            Ok(())
        );
        assert_eq!(
            validate_native_action_step(Kind::Windows, Action::Stop, Step::Noop),
            Ok(())
        );
        for forbidden in [Step::Stop, Step::ReplaceRelease, Step::Install] {
            assert_eq!(
                validate_native_action_step(Kind::Windows, Action::Start, forbidden),
                Err("HOST_WINDOWS_SIGNED_START_STEP_MISMATCH")
            );
        }
        for forbidden in [Step::Start, Step::ReplaceRelease, Step::Install] {
            assert_eq!(
                validate_native_action_step(Kind::Windows, Action::Stop, forbidden),
                Err("HOST_WINDOWS_SIGNED_STOP_STEP_MISMATCH")
            );
        }
        assert_eq!(
            validate_native_action_step(Kind::Vm, Action::Apply, Step::Start),
            Ok(())
        );
        assert_eq!(
            validate_native_action_step(Kind::Vm, Action::Recover, Step::Noop),
            Ok(())
        );
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
    fn windows_administrator_membership_queries_exact_process_primary_token() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // Any ordinary Windows CI token may be an admin or non-admin. Both
        // boolean results are valid; API failure is the regression.
        let mut primary = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut primary,
                )
            },
            0,
        );
        let member = windows_process_primary_admin_member(primary);
        unsafe { CloseHandle(primary) };
        assert!(matches!(member, Ok(true) | Ok(false)), "{member:?}");

        // Missing token must fail closed, not select a thread/runner token.
        assert_eq!(
            windows_process_primary_admin_member(std::ptr::null_mut()),
            Err("HOST_WINDOWS_FIRST_USE_TOKEN_DUPLICATION_FAILED"),
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_requires_native_acl_acceptance() {
        assert_eq!(
            verify_native_journal_protection(Path::new(r"C:\sing-box\state\host")),
            // The native suite runs as user/Administrator, not SYSTEM.
            // Refuse the token before attempting any filesystem ACL test.
            Err("HOST_WINDOWS_LOCALSYSTEM_REQUIRED")
        );
        assert_eq!(
            verify_native_journal_protection(Path::new("relative")),
            Err("HOST_WINDOWS_JOURNAL_ABSOLUTE_PATH_REQUIRED")
        );
    }
}

// Real Windows W4 projection: TrustedInstaller-owned C:\\ with an
// Authenticated Users create-directory ACE is safe ONLY if delete/replace,
// WRITE_DAC/WRITE_OWNER, and all other mutation rights remain absent.
// A user-owned application root is independently denied by the owner check.
#[cfg(all(test, windows))]
mod windows_w4_acl_tests {
    use super::{windows_acl_grant_safe, windows_acl_owner_safe};

    #[test]
    fn only_the_volume_root_accepts_trusted_installer_as_owner() {
        assert!(windows_acl_owner_safe(true, false, false));
        assert!(windows_acl_owner_safe(false, true, true));
        // Actual initial app-root owner was a normal user. The verifier
        // rejects that owner even if nested journal ACLs look protected.
        assert!(!windows_acl_owner_safe(false, false, false));
        assert!(!windows_acl_owner_safe(false, false, true));
        assert!(!windows_acl_owner_safe(false, true, false));
    }

    #[test]
    fn volume_root_create_directory_does_not_grant_replace() {
        assert!(windows_acl_grant_safe(0x0000_0004, false, true, false));
        assert!(!windows_acl_grant_safe(0x0000_0004, false, false, false));
        for bad in [
            0x0000_0002,
            0x0000_0010,
            0x0000_0040,
            0x0000_0100,
            0x0001_0000,
            0x0004_0000,
            0x0008_0000,
            0x1000_0000,
            0x4000_0000,
        ] {
            assert!(!windows_acl_grant_safe(
                0x0000_0004 | bad,
                false,
                true,
                false
            ));
        }
        assert!(windows_acl_grant_safe(u32::MAX, true, false, false));
        // Inherit-only is NOT proof of safety: arbitrary unprivileged
        // full-control inherited onto the journal or executable is unsafe.
        assert!(!windows_acl_grant_safe(u32::MAX, false, false, false));
        assert!(!windows_acl_grant_safe(u32::MAX, false, true, false));
        // Actual C:\\ root: Authenticated Users (S-1-5-11) may have
        // ACCESS_ALLOWED OI|CI|INHERIT_ONLY, mask 0xE0010000. It grants
        // no direct DELETE or GENERIC_WRITE on the volume root itself.
        const AUTHENTICATED_USERS_TEMPLATE: u32 = 0xE001_0000;
        assert!(windows_acl_grant_safe(
            AUTHENTICATED_USERS_TEMPLATE,
            false,
            true,
            true
        ));
        // An equivalent effective ACE on C:\\ is dangerous.
        assert!(!windows_acl_grant_safe(
            AUTHENTICATED_USERS_TEMPLATE,
            false,
            true,
            false
        ));
        // And ANY unprivileged write template under C:\\sing-box remains
        // prohibited, even if marked INHERIT_ONLY on the app directory.
        assert!(!windows_acl_grant_safe(
            AUTHENTICATED_USERS_TEMPLATE,
            false,
            false,
            true
        ));
        assert!(windows_acl_grant_safe(u32::MAX, false, true, true));
        assert!(!windows_acl_grant_safe(u32::MAX, false, false, true));
    }
}
