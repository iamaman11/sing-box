//! Native-owner durable one-shot admission journal.
//!
//! This is deliberately NOT a GitHub-runner journal or a migration reader.
//! Both Windows SYSTEM and VM root owners call this ONLY after independent
//! signature, machine identity, exact release and protected-directory checks.
//! A successfully reserved operation is NEVER dispatched twice. Uncertain
//! operations remain in the journal; no automatic retry/rollback.

use crate::{
    FleetHostAuthorization, FleetHostIntent, FleetHostResult, FleetHostResultState, HostRegistry,
    host_lifecycle::{validate_host_intent, verify_host_authorization},
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
pub fn admit_native_host_once(
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
    let identity = digest(&SHA256, intent.operation_id.as_bytes());
    let id = identity
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let path = protected_journal_dir.join(format!("{id}.pb"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_lifecycle::host_authorization_payload;
    use crate::{FleetHost, FleetHostAction, FleetHostKind, FleetHostMode, managed_host};
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
            target: None,
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
        let first = call(&i, &a).unwrap();
        assert_eq!(first.state, FleetHostResultState::Authorized as i32);
        assert!(!first.physical_readback);
        assert_eq!(
            call(&i, &a).unwrap_err(),
            "HOST_OPERATION_EXISTS_OR_JOURNAL_UNAVAILABLE"
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
        assert_eq!(files.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
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
