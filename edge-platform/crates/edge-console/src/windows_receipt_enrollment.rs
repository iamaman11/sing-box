//! Windows W4: one narrow first-use exception for the *identity*, not for
//! Worker trust or any runtime mutation. The local elevated Administrator may
//! reserve a typed, exact-release marker under the protected native host root.
//! Only the ALREADY INSTALLED periodic LocalSystem dispatcher generates and
//! stores the Ed25519 PRIVATE signer. NetworkService cannot write this root.
//! No extra task, service, transport, secret export or unsigned SCM operation.

use super::*;
use edge_shared_types::{
    FleetWindowsReceiptIdentityEnrollment, FleetWindowsTrustEnrollment,
    host_journal::{
        require_windows_local_administrator_first_use, verify_native_journal_protection,
    },
};
use prost::Message;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(test)]
const MACHINE: &str = "sing-box-windows-lab"; // test fixture, never runtime owner
pub(super) fn valid_machine_id(machine: &str) -> bool {
    !machine.is_empty()
        && machine.len() <= 40
        && machine
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase())
        && machine
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

// The existing typed receipt marker carries the host ID across release handoff.
// It is not an authority: signed trust separately checks current protected Git.
pub(super) fn bound_machine_id(install_root: &Path) -> Result<String, String> {
    let root = native_root(install_root)?;
    for marker in [MARKER, COMPLETED] {
        let path = root.join(marker);
        let meta = match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(meta) => meta,
            Err(_) => return Err("HOST_WINDOWS_RECEIPT_MACHINE_MARKER_UNAVAILABLE".into()),
        };
        if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 512 {
            return Err("HOST_WINDOWS_RECEIPT_MACHINE_MARKER_INVALID".into());
        }
        let bytes =
            fs::read(&path).map_err(|_| "HOST_WINDOWS_RECEIPT_MACHINE_MARKER_UNREADABLE")?;
        let request = FleetWindowsReceiptIdentityEnrollment::decode(bytes.as_slice())
            .map_err(|_| "HOST_WINDOWS_RECEIPT_MACHINE_MARKER_PROTO_INVALID")?;
        if request.encode_to_vec() != bytes || !valid_machine_id(&request.machine_id) {
            return Err("HOST_WINDOWS_RECEIPT_MACHINE_MARKER_NONCANONICAL".into());
        }
        return Ok(request.machine_id);
    }
    Ok("UNREGISTERED".into())
}

const MARKER: &str = "receipt-enrollment.pb";
const COMPLETED: &str = "receipt-enrollment.completed.pb";
const PRIVATE: &str = "receipt-key.pk8";
const PUBLIC: &str = "receipt-public-key.bin";

fn native_root(install_root: &Path) -> Result<std::path::PathBuf, String> {
    if install_root != Path::new(r"C:\sing-box") {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_ROOT_INVALID".into());
    }
    let root = install_root.join("native-host");
    for path in [&root, &root.join("journal")] {
        let meta = fs::symlink_metadata(path)
            .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PROTECTED_ROOT_MISSING")?;
        if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
            return Err("HOST_WINDOWS_RECEIPT_ENROLL_ROOT_REPARSE_OR_NOT_DIR".into());
        }
    }
    Ok(root)
}

fn request_valid(
    request: &FleetWindowsReceiptIdentityEnrollment,
    active: &WindowsActivationState,
) -> Result<(), &'static str> {
    if request.schema_version != 1
        || !valid_machine_id(&request.machine_id)
        || request.source_revision != active.source_revision
        || request.release_set_sha256 != active.release_set_sha256
        || request.source_revision.len() != 40
        || !request
            .source_revision
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || request.release_set_sha256.len() != 64
        || !request
            .release_set_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_EXACT_RELEASE_OR_HOST_MISMATCH");
    }
    Ok(())
}

fn read_marker(path: &Path, active: &WindowsActivationState) -> Result<(), String> {
    let meta =
        fs::symlink_metadata(path).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_MARKER_MISSING")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 512 {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_MARKER_NOT_BOUNDED_REGULAR".into());
    }
    let bytes = fs::read(path).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_MARKER_UNREADABLE")?;
    let request = FleetWindowsReceiptIdentityEnrollment::decode(bytes.as_slice())
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PROTO_INVALID")?;
    if request.encode_to_vec() != bytes {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_PROTO_NONCANONICAL".into());
    }
    if request_valid(&request, active).is_ok() {
        return Ok(());
    }
    // Completed first-use is historical identity evidence, not permission to
    // enroll again after every update. Preserve its original exact bytes.
    if path.file_name().and_then(|s| s.to_str()) == Some(COMPLETED) {
        let root = path
            .parent()
            .and_then(Path::parent)
            .ok_or("HOST_WINDOWS_IDENTITY_HISTORY_ROOT_INVALID")?;
        let historical = historical_marker_activation(
            root,
            &request.source_revision,
            &request.release_set_sha256,
        )?;
        return request_valid(&request, &historical).map_err(str::to_owned);
    }
    request_valid(&request, active).map_err(str::to_owned)
}

pub(super) fn historical_marker_activation(
    root: &Path,
    source: &str,
    release: &str,
) -> Result<WindowsActivationState, String> {
    if source.len() != 40
        || release.len() != 64
        || !source
            .bytes()
            .chain(release.bytes())
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("HOST_WINDOWS_IDENTITY_HISTORY_DIGEST_INVALID".into());
    }
    let path = root.join("releases").join(release).join("release-set.pb");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&path, true)?;
    let bytes = windows_signed_host::bounded_regular_file(&path, 65536)?;
    verify_historical_release_bytes(&bytes, source, release)?;
    Ok(WindowsActivationState {
        source_revision: source.into(),
        release_set_sha256: release.into(),
        ..Default::default()
    })
}

fn verify_historical_release_bytes(
    bytes: &[u8],
    source: &str,
    release: &str,
) -> Result<(), &'static str> {
    let pb = edge_shared_types::ReleaseSet::decode(bytes)
        .map_err(|_| "HOST_WINDOWS_IDENTITY_HISTORY_RELEASE_INVALID")?;
    let sha: String = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if sha != release || pb.source_revision != source || pb.encode_to_vec() != bytes {
        return Err("HOST_WINDOWS_IDENTITY_HISTORY_RELEASE_MISMATCH");
    }
    Ok(())
}

fn create_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_FILE_SIZE_INVALID".into());
    }
    // Existing content, symlink or a prior crash remains a hard non-overwrite.
    // In production parent DACL is independently verified by LocalSystem.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_FILE_EXISTS_OR_UNAVAILABLE")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_WRITE_UNCERTAIN_NO_REPLAY".to_owned())
}

// Even Administrators must not inherit ordinary read access to the
// persisted PKCS8. The private signer belongs to the existing SYSTEM owner.
// Re-apply this seal after a crash before reading a retained private key.
// SYSTEM still verifies the protected ancestor/journal kernel ACL first.
fn seal_system_private(root: &Path) -> Result<(), String> {
    let private = root.join(PRIVATE);
    let meta = fs::symlink_metadata(&private)
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PRIVATE_METADATA_UNAVAILABLE")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 4096 {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_PRIVATE_INVALID".into());
    }
    run_icacls(&private, &["/inheritance:r", "/Q"])?;
    run_icacls(&private, &["/grant:r", "*S-1-5-18:F", "/Q"])?;
    run_icacls(&private, &["/remove:g", "*S-1-5-32-544", "/Q"])?;
    run_icacls(&private, &["/setowner", "*S-1-5-18", "/Q"])
}

fn existing_private_public(root: &Path) -> Result<Option<[u8; 32]>, String> {
    let private = root.join(PRIVATE);
    let public = root.join(PUBLIC);
    let pk8 = match fs::symlink_metadata(&private) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if fs::symlink_metadata(&public).is_ok() {
                return Err("HOST_WINDOWS_RECEIPT_ENROLL_ORPHAN_PUBLIC_KEY".into());
            }
            return Ok(None);
        }
        Err(_) => return Err("HOST_WINDOWS_RECEIPT_ENROLL_PRIVATE_METADATA_UNAVAILABLE".into()),
        Ok(meta) if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 4096 => {
            return Err("HOST_WINDOWS_RECEIPT_ENROLL_PRIVATE_INVALID".into());
        }
        Ok(_) => {
            fs::read(&private).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PRIVATE_UNREADABLE")?
        }
    };
    let pair = Ed25519KeyPair::from_pkcs8(&pk8)
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PRIVATE_INVALID")?;
    let key: [u8; 32] = pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_INVALID")?;
    match fs::symlink_metadata(&public) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Crash after durable private-key creation: publish only the
            // existing identity. Never regenerate/replace a private key.
            create_only(&public, &key)?;
        }
        Err(_) => return Err("HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_METADATA_UNAVAILABLE".into()),
        Ok(meta) if !meta.file_type().is_file() || meta.len() != 32 => {
            return Err("HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_INVALID".into());
        }
        Ok(_) => {
            let stored =
                fs::read(&public).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_UNREADABLE")?;
            if stored != key {
                return Err("HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_PRIVATE_MISMATCH".into());
            }
        }
    }
    Ok(Some(key))
}

/// Pure filesystem preflight for the opt-in combined offline install/enroll.
/// Before a native bootstrap the protected directory may not exist yet; any
/// existing identity, in-flight marker, completed marker or trust file denies
/// the enrollment option BEFORE the irreversible installer BEGIN. Absence is
/// not a permission to rekey a previously enrolled machine.
pub(super) fn preflight_fresh_identity_slot(install_root: &Path) -> Result<(), String> {
    if install_root != Path::new(r"C:\sing-box") {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_ROOT_INVALID".into());
    }
    preflight_fresh_identity_root(&install_root.join("native-host"))
}

fn preflight_fresh_identity_root(root: &Path) -> Result<(), String> {
    match fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("HOST_WINDOWS_RECEIPT_ENROLL_ROOT_METADATA_UNAVAILABLE".into()),
        Ok(meta) if !meta.file_type().is_dir() || meta.file_type().is_symlink() => {
            return Err("HOST_WINDOWS_RECEIPT_ENROLL_ROOT_REPARSE_OR_NOT_DIR".into());
        }
        Ok(_) => {}
    }
    for name in [
        MARKER,
        COMPLETED,
        PRIVATE,
        PUBLIC,
        "trust.pb",
        "trust-enrollment.pb",
        "trust-enrollment.completed.pb",
    ] {
        match fs::symlink_metadata(root.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("HOST_WINDOWS_RECEIPT_ENROLL_SLOT_METADATA_UNAVAILABLE".into()),
            Ok(_) => return Err("HOST_WINDOWS_RECEIPT_ENROLL_SLOT_NOT_EMPTY_NO_REKEY".into()),
        }
    }
    Ok(())
}

/// Local Administrator pre-BEGIN proof for a *completed* identity. Never read
/// the SYSTEM private key or interpret file existence alone as authority.
pub(super) fn verify_existing_receipt_identity_slot(
    install_root: &Path,
) -> Result<Vec<u8>, String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    let root = native_root(install_root)?;
    verify_native_journal_protection(&root.join("journal")).map_err(str::to_owned)?;
    for name in [PRIVATE, PUBLIC, COMPLETED] {
        let path = root.join(name);
        edge_shared_types::host_journal::verify_windows_protected_path_acl(&path, true)
            .map_err(str::to_owned)?;
        let max = if name == PRIVATE {
            4096
        } else if name == PUBLIC {
            32
        } else {
            512
        };
        if !checked_regular_exists(&path, max)? {
            return Err("HOST_WINDOWS_RECEIPT_COMPLETED_IDENTITY_MISSING".into());
        }
    }
    match fs::symlink_metadata(root.join(MARKER)) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("HOST_WINDOWS_RECEIPT_COMPLETED_WITH_PENDING_MARKER".into()),
    }
    let public = fs::read(root.join(PUBLIC))
        .map_err(|_| "HOST_WINDOWS_RECEIPT_COMPLETED_PUBLIC_UNREADABLE")?;
    if public.len() != 32 || public.iter().all(|b| *b == 0) {
        return Err("HOST_WINDOWS_RECEIPT_COMPLETED_PUBLIC_INVALID".into());
    }
    // The next LocalSystem signed handler checks the private/public pair.
    Ok(public)
}

// An explicit retained-BEGIN supersession may carry forward ONLY an
// unconsumed first-use request pair. No key, completed marker or trust may
// already exist: this is not a credential rotation or journal replay.
pub(super) struct PendingFirstUseRebind {
    receipt_bytes: Vec<u8>,
    trust_bytes: Vec<u8>,
    predecessor_release: String,
}

fn absent_for_pending_rebind(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("HOST_WINDOWS_FIRST_USE_REBIND_SLOT_ALREADY_USED_NO_REKEY".into()),
        Err(_) => Err("HOST_WINDOWS_FIRST_USE_REBIND_SLOT_UNPROVEN".into()),
    }
}

fn pending_rebind_snapshot(
    root: &Path,
    active: &WindowsActivationState,
) -> Result<PendingFirstUseRebind, String> {
    let identity = root.join(MARKER);
    let trust = root.join("trust-enrollment.pb");
    read_marker(&identity, active)?;
    if !checked_regular_exists(&trust, 512)? {
        return Err("HOST_WINDOWS_FIRST_USE_REBIND_TRUST_REQUEST_REQUIRED".into());
    }
    let receipt_bytes =
        fs::read(&identity).map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_RECEIPT_UNREADABLE")?;
    let trust_bytes =
        fs::read(&trust).map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_TRUST_UNREADABLE")?;
    windows_trust_enrollment::verify_enrollment_marker(&trust_bytes, active)
        .map_err(str::to_owned)?;
    for name in [
        PRIVATE,
        PUBLIC,
        COMPLETED,
        "trust.pb",
        "trust-enrollment.completed.pb",
    ] {
        absent_for_pending_rebind(&root.join(name))?;
    }
    for name in [MARKER, "trust-enrollment.pb"] {
        absent_for_pending_rebind(
            &root.join(format!("{name}.predecessor-{}", active.release_set_sha256)),
        )?;
    }
    Ok(PendingFirstUseRebind {
        receipt_bytes,
        trust_bytes,
        predecessor_release: active.release_set_sha256.clone(),
    })
}

/// Pure read-only admission to be executed BEFORE another durable native
/// BEGIN. The administrator explicitly approved supersession of that BEGIN;
/// this cannot be inferred from scheduled-task failure or missing public key.
pub(super) fn preflight_pending_rebind(
    install_root: &Path,
    installed: &WindowsActivationState,
) -> Result<PendingFirstUseRebind, String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    let root = native_root(install_root)?;
    pending_rebind_snapshot(&root, installed)
}

/// Only the new exact immutable local Administrator owner, while the SAME
/// SYSTEM task is Disabled, may consume one previously authorized old-release
/// request pair. The old bytes remain preserved and are never interpreted as
/// a new key or successful prior enrollment.
pub(super) fn rebind_pending_after_offline_handoff(
    install_root: &Path,
    previously: &PendingFirstUseRebind,
    predecessor: &WindowsActivationState,
) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let current = load_verified_activation(install_root).map_err(|e| e.to_string())?;
    if current.release_set_sha256 == predecessor.release_set_sha256
        || previously.predecessor_release != predecessor.release_set_sha256
    {
        return Err("HOST_WINDOWS_FIRST_USE_REBIND_ACTIVATION_NOT_DISTINCT".into());
    }
    require_offline_windows_owner(install_root, &current)?;
    verify_offline_bootstrap_dispatcher(&current.console_path, "Disabled")?;
    let root = native_root(install_root)?;
    let observed = pending_rebind_snapshot(&root, predecessor)?;
    if observed.receipt_bytes != previously.receipt_bytes
        || observed.trust_bytes != previously.trust_bytes
    {
        return Err("HOST_WINDOWS_FIRST_USE_REBIND_ORIGINAL_CHANGED_NO_REPLAY".into());
    }
    let bound = FleetWindowsReceiptIdentityEnrollment::decode(previously.receipt_bytes.as_slice())
        .map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_HOST_ID_UNPROVEN")?;
    let new_receipt = FleetWindowsReceiptIdentityEnrollment {
        schema_version: 1,
        machine_id: bound.machine_id.clone(),
        source_revision: current.source_revision.clone(),
        release_set_sha256: current.release_set_sha256.clone(),
    };
    request_valid(&new_receipt, &current).map_err(str::to_owned)?;
    let new_trust = FleetWindowsTrustEnrollment {
        schema_version: 1,
        machine_id: bound.machine_id,
        source_revision: current.source_revision.clone(),
        release_set_sha256: current.release_set_sha256.clone(),
    };
    windows_trust_enrollment::verify_enrollment_marker(&new_trust.encode_to_vec(), &current)
        .map_err(str::to_owned)?;
    // Archive BOTH complete predecessor requests before replacing either.
    for (name, original) in [
        (MARKER, previously.receipt_bytes.as_slice()),
        ("trust-enrollment.pb", previously.trust_bytes.as_slice()),
    ] {
        let saved = root.join(format!(
            "{name}.predecessor-{}",
            previously.predecessor_release
        ));
        absent_for_pending_rebind(&saved)?;
        fs::hard_link(root.join(name), &saved)
            .map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_ARCHIVE_UNCERTAIN_NO_REPLAY")?;
        let saved_bytes = fs::read(&saved)
            .map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_ARCHIVE_UNREADABLE_NO_REPLAY")?;
        if saved_bytes != original {
            return Err("HOST_WINDOWS_FIRST_USE_REBIND_ARCHIVE_CHANGED_NO_REPLAY".into());
        }
        let file = OpenOptions::new()
            .write(true)
            .open(&saved)
            .map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_ARCHIVE_SYNC_UNAVAILABLE_NO_REPLAY")?;
        file.sync_all()
            .map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_ARCHIVE_SYNC_UNCERTAIN_NO_REPLAY")?;
    }
    // Unlink/create-only is intentionally fail-closed: if the host stops
    // between steps, never retry under a different ID or generate a key.
    fs::remove_file(root.join(MARKER))
        .map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_UNLINK_UNCERTAIN_NO_REPLAY")?;
    create_only(&root.join(MARKER), &new_receipt.encode_to_vec())?;
    fs::remove_file(root.join("trust-enrollment.pb"))
        .map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_UNLINK_UNCERTAIN_NO_REPLAY")?;
    create_only(
        &root.join("trust-enrollment.pb"),
        &new_trust.encode_to_vec(),
    )?;
    read_marker(&root.join(MARKER), &current)?;
    windows_trust_enrollment::verify_enrollment_marker(
        &fs::read(root.join("trust-enrollment.pb"))
            .map_err(|_| "HOST_WINDOWS_FIRST_USE_REBIND_TRUST_READBACK_UNAVAILABLE")?,
        &current,
    )
    .map_err(str::to_owned)?;
    Ok(())
}

/// A single first-use authorization may stage trust before SYSTEM has
/// completed its receipt key. Only the existing canonical typed identity
/// marker (active or completed) proves the intent; no caller supplies a key.
pub(super) fn require_identity_request_for_trust(
    install_root: &Path,
    active: &WindowsActivationState,
) -> Result<(), String> {
    let root = native_root(install_root)?;
    let active_marker = root.join(MARKER);
    match fs::symlink_metadata(&active_marker) {
        Ok(_) => read_marker(&active_marker, active),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            read_marker(&root.join(COMPLETED), active)
        }
        Err(_) => Err("HOST_WINDOWS_RECEIPT_ENROLL_MARKER_METADATA_UNAVAILABLE".into()),
    }
}

/// Before creating the FIRST service/task on a clean Windows host, reserve
/// the SAME typed identity marker as a durable local-authorized BEGIN. The
/// existing SYSTEM task eventually completes it. A crash cannot be treated
/// as a fresh enrollment; no other first-use store is introduced.
pub(super) fn prepare_clean_before_scm(
    install_root: &Path,
    machine_id: &str,
) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let active = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    preflight_fresh_identity_slot(install_root)?;
    // This first-use entrypoint executes with an explicitly elevated LOCAL
    // ADMINISTRATOR token. verify_native_journal_protection is intentionally
    // LocalSystem-only and must NOT run here: the existing SYSTEM dispatcher
    // verifies the kernel journal owner/DACL before consuming this marker.
    // The parent native-host/journal directories were prepared with the
    // canonical SYSTEM/Administrators ACL by converge_native_host_acl.
    let root = native_root(install_root)?;
    let request = FleetWindowsReceiptIdentityEnrollment {
        schema_version: 1,
        machine_id: machine_id.into(),
        source_revision: active.source_revision.clone(),
        release_set_sha256: active.release_set_sha256.clone(),
    };
    request_valid(&request, &active).map_err(str::to_owned)?;
    create_only(&root.join(MARKER), &request.encode_to_vec())?;
    Ok(())
}

/// Local elevated Administrator: create ONE immutable, typed request in the
/// existing protected root. No receipt PRIVATE key is generated here.
pub(super) fn prepare(install_root: &Path, registered_machine: &str) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let active = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    require_offline_windows_owner(install_root, &active)?;
    verify_offline_bootstrap_dispatcher(&active.console_path, "Ready")?;
    let root = native_root(install_root)?;
    // A pre-existing signing identity cannot be re-enrolled through this
    // unsigned local-first-use boundary, even if its public pin is unknown.
    if root.join(PRIVATE).exists() || root.join(PUBLIC).exists() || root.join(COMPLETED).exists() {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_IDENTITY_ALREADY_EXISTS".into());
    }
    if install_root
        .join("exchange")
        .join("requests")
        .join("host-intent.pb")
        .exists()
        || privileged_request_path(install_root).exists()
    {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_COMPETING_REQUEST".into());
    }
    let request = FleetWindowsReceiptIdentityEnrollment {
        schema_version: 1,
        machine_id: registered_machine.into(),
        source_revision: active.source_revision.clone(),
        release_set_sha256: active.release_set_sha256.clone(),
    };
    request_valid(&request, &active).map_err(str::to_owned)?;
    create_only(&root.join(MARKER), &request.encode_to_vec())?;
    println!("status=PREPARED");
    println!("w4_receipt_identity=LOCAL_ADMIN_REQUEST_DURABLE");
    println!("w4_next=EXISTING_SYSTEM_TASK_ONLY");
    println!("runtime_mutations=0");
    Ok(())
}

// Archive the exact immutable one-shot intent before removing its active
// marker. This prevents a completed enrollment blocking future signed
// dispatches; a crash between hard-link and unlink is recoverable without
// ever re-generating the PRIVATE key.
fn complete_marker(root: &Path) -> Result<(), String> {
    let marker = root.join(MARKER);
    let completed = root.join(COMPLETED);
    match fs::symlink_metadata(&completed) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::hard_link(&marker, &completed)
                .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_ARCHIVE_UNCERTAIN_NO_REPLAY")?;
        }
        Err(_) => return Err("HOST_WINDOWS_RECEIPT_ENROLL_ARCHIVE_METADATA_UNAVAILABLE".into()),
        Ok(meta) if !meta.file_type().is_file() => {
            return Err("HOST_WINDOWS_RECEIPT_ENROLL_ARCHIVE_INVALID".into());
        }
        Ok(_) => {
            if fs::read(&marker).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_MARKER_UNREADABLE")?
                != fs::read(&completed)
                    .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_ARCHIVE_UNREADABLE")?
            {
                return Err("HOST_WINDOWS_RECEIPT_ENROLL_ARCHIVE_MISMATCH".into());
            }
        }
    }
    fs::remove_file(marker)
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_UNLINK_UNCERTAIN_NO_REPLAY".to_owned())
}

/// Existing periodic LocalSystem task: if exact admin-created, protected
/// marker exists, generate the identity itself, never in the runner/admin.
pub(super) fn dispatch_if_present(install_root: &Path) -> Result<bool, String> {
    let root = native_root(install_root)?;
    let marker = root.join(MARKER);
    match fs::symlink_metadata(&marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("HOST_WINDOWS_RECEIPT_ENROLL_MARKER_METADATA_UNAVAILABLE".into()),
        Ok(_) => {}
    }
    require_exact_immutable_activation_console(install_root)?;
    verify_native_journal_protection(&root.join("journal")).map_err(str::to_owned)?;
    let active = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    require_offline_windows_owner(install_root, &active)?;
    read_marker(&marker, &active)?;
    if install_root
        .join("exchange")
        .join("requests")
        .join("host-intent.pb")
        .exists()
        || privileged_request_path(install_root).exists()
    {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_COMPETING_REQUEST".into());
    }
    if root.join("trust.pb").exists() {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_TRUST_ALREADY_PRESENT".into());
    }
    // Existing or newly generated keys must be SYSTEM-only on disk before
    // public identity is published; a failed ACL change is not a success.
    if root.join(PRIVATE).exists() {
        seal_system_private(&root)?;
    }
    let public = match existing_private_public(&root)? {
        Some(key) => key,
        None => {
            let secret = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_KEY_GENERATION_FAILED")?;
            let pair = Ed25519KeyPair::from_pkcs8(secret.as_ref())
                .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_KEY_GENERATION_FAILED")?;
            let key: [u8; 32] = pair
                .public_key()
                .as_ref()
                .try_into()
                .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_KEY_GENERATION_FAILED")?;
            // Fail closed on ANY uncertain write: do not generate another key
            // to recover. Future dispatcher can only rederive public identity.
            create_only(&root.join(PRIVATE), secret.as_ref())?;
            seal_system_private(&root)?;
            create_only(&root.join(PUBLIC), &key)?;
            key
        }
    };
    complete_marker(&root)?;
    println!("status=PASS");
    println!("native_receipt_identity=SYSTEM_GENERATED_OR_EXACT_EXISTING");
    println!(
        "native_receipt_public_hex={}",
        public
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("worker_trust=NOT_ENROLLED");
    println!("scm_mutations=0");
    println!("network_mutations=0");
    Ok(true)
}

/// Local read-only first-use projection: classify canonical typed markers,
/// never read PKCS8 or interpret old diagnostic stdout as authority.
/// Ordinary local first-use commands MUST run from the currently installed
/// immutable console. Offline-bootstrap is the only separately pinned reader
/// allowed to run from its distinct, already staged candidate executable.
pub(super) fn read_only_first_use_stage(install_root: &Path) -> Result<&'static str, String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let active = load_verified_activation(install_root).map_err(|e| e.to_string())?;
    require_offline_windows_owner(install_root, &active)?;
    read_only_first_use_stage_from_installed(install_root, &active)
}

/// Exact caller identity policy for the read-only pre-BEGIN exception only.
/// This never authorizes any state transition, credential replay or trust write.
fn require_exact_offline_bootstrap_reader_identity(
    installed_release: &str,
    target_release: &str,
    invoking_console: &Path,
    expected_candidate_console: &Path,
) -> Result<(), &'static str> {
    if target_release.len() != 64
        || !target_release
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || installed_release == target_release
        || invoking_console != expected_candidate_console
    {
        return Err("HOST_WINDOWS_FIRST_USE_CANDIDATE_READER_NOT_EXACT");
    }
    Ok(())
}

/// A verified, distinct release candidate is already executing this
/// offline-bootstrap command. Read the PREDECESSOR's markers without
/// requiring the candidate process to equal the installed console. The
/// installed activation/SCM and candidate path are independently pinned.
/// The normal reader and every mutating command retain the strict active
/// immutable-console requirement.
pub(super) fn read_only_first_use_stage_for_offline_bootstrap(
    install_root: &Path,
    predecessor: &WindowsActivationState,
    target_release: &str,
) -> Result<&'static str, String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    if install_root != Path::new(r"C:\sing-box") {
        return Err("HOST_WINDOWS_FIRST_USE_CANDIDATE_ROOT_INVALID".into());
    }
    let active = load_verified_activation(install_root).map_err(|e| e.to_string())?;
    if &active != predecessor {
        return Err("HOST_WINDOWS_FIRST_USE_PREDECESSOR_CHANGED_NO_REPLAY".into());
    }
    require_offline_windows_owner(install_root, &active)?;
    let releases = install_root
        .join("releases")
        .canonicalize()
        .map_err(|_| "HOST_WINDOWS_FIRST_USE_RELEASES_ROOT_UNPROVEN")?;
    // ACL verification uses the literal C:\\sing-box path; Windows
    // canonicalize() may return a \\\\?\\ prefix which is not the expected
    // absolute ownership root. Canonical paths are only for comparison.
    let candidate_dir = install_root.join("releases").join(target_release);
    let meta = fs::symlink_metadata(&candidate_dir)
        .map_err(|_| "HOST_WINDOWS_FIRST_USE_CANDIDATE_DIRECTORY_UNPROVEN")?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err("HOST_WINDOWS_FIRST_USE_CANDIDATE_DIRECTORY_NOT_EXACT".into());
    }
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&candidate_dir, false)
        .map_err(str::to_owned)?;
    let canonical_candidate = candidate_dir
        .canonicalize()
        .map_err(|_| "HOST_WINDOWS_FIRST_USE_CANDIDATE_DIRECTORY_UNPROVEN")?;
    if !canonical_candidate.starts_with(&releases) {
        return Err("HOST_WINDOWS_FIRST_USE_CANDIDATE_DIRECTORY_ESCAPED_ROOT".into());
    }
    let candidate_console = candidate_dir.join("bin").join("edge-console.exe");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&candidate_console, true)
        .map_err(str::to_owned)?;
    let expected = candidate_console
        .canonicalize()
        .map_err(|_| "HOST_WINDOWS_FIRST_USE_CANDIDATE_CONSOLE_UNPROVEN")?;
    if !expected.starts_with(&canonical_candidate) {
        return Err("HOST_WINDOWS_FIRST_USE_CANDIDATE_CONSOLE_ESCAPED_ROOT".into());
    }
    let invoking = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|_| "HOST_WINDOWS_FIRST_USE_CANDIDATE_CALLER_UNPROVEN")?;
    require_exact_offline_bootstrap_reader_identity(
        &active.release_set_sha256,
        target_release,
        &invoking,
        &expected,
    )
    .map_err(str::to_owned)?;
    read_only_first_use_stage_from_installed(install_root, &active)
}

/// Single owner for the read-only marker classification shared by both
/// correctly authorized call paths. Never inspect a new-release marker using
/// an unverified candidate activation.
fn read_only_first_use_stage_from_installed(
    install_root: &Path,
    active: &WindowsActivationState,
) -> Result<&'static str, String> {
    let root = native_root(install_root)?;
    let marker = root.join(MARKER);
    let completed = root.join(COMPLETED);
    let active_present = checked_regular_exists(&marker, 512)?;
    let completed_present = checked_regular_exists(&completed, 512)?;
    if active_present {
        read_marker(&marker, &active)?;
    }
    if completed_present {
        read_marker(&completed, &active)?;
    }
    if active_present
        && completed_present
        && fs::read(&marker).map_err(|_| "HOST_WINDOWS_FIRST_USE_MARKER_UNREADABLE")?
            != fs::read(&completed).map_err(|_| "HOST_WINDOWS_FIRST_USE_COMPLETED_UNREADABLE")?
    {
        return Err("HOST_WINDOWS_FIRST_USE_CRASH_MARKERS_DIFFER_NO_REPLAY".into());
    }
    let has_public = checked_regular_exists(&root.join(PUBLIC), 32)?;
    if !active_present && !completed_present {
        if has_public
            || checked_regular_exists(&root.join(PRIVATE), 4096)?
            || windows_trust_enrollment::first_use_trust_present(&root)?
        {
            return Err("HOST_WINDOWS_FIRST_USE_ORPHAN_IDENTITY_NO_REPLAY".into());
        }
        return Ok("NOT_STARTED");
    }
    if active_present {
        // Even if a public key exists, the SYSTEM archive has not been
        // completed. It is never permissible to start a second enrollment.
        return Ok("SYSTEM_PENDING");
    }
    if !has_public {
        return Err("HOST_WINDOWS_FIRST_USE_COMPLETED_WITHOUT_PUBLIC_NO_REPLAY".into());
    }
    windows_trust_enrollment::read_only_first_use_trust_stage(&root, active)
}

pub(super) fn checked_regular_exists(path: &Path, max_size: u64) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("HOST_WINDOWS_FIRST_USE_METADATA_UNREADABLE".into()),
        Ok(meta) => {
            if !meta.file_type().is_file()
                || meta.file_type().is_symlink()
                || meta.len() == 0
                || meta.len() > max_size
            {
                Err("HOST_WINDOWS_FIRST_USE_PROTECTED_FILE_INVALID".into())
            } else {
                Ok(true)
            }
        }
    }
}

/// Local elevated Administrator read-only: publish public identity ONLY.
/// Never open, read or copy the SYSTEM private signer from this command.
pub(super) fn observe(install_root: &Path) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let root = native_root(install_root)?;
    let active = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    // After successful SYSTEM processing the original active marker is
    // archived: reading must not recreate it or assume missing means failure.
    if root.join(MARKER).exists() {
        read_marker(&root.join(MARKER), &active)?;
    } else {
        read_marker(&root.join(COMPLETED), &active)?;
    }
    let public = root.join(PUBLIC);
    let meta = fs::symlink_metadata(&public)
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_NOT_READY")?;
    if !meta.file_type().is_file() || meta.len() != 32 {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_INVALID".into());
    }
    let bytes = fs::read(public).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_UNREADABLE")?;
    println!("w4_receipt_identity=PUBLIC_ONLY_OBSERVED");
    println!("machine_id={}", bound_machine_id(install_root)?);
    println!("release_set_sha256={}", active.release_set_sha256);
    println!(
        "native_receipt_public_hex={}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("worker_trust=NOT_ENROLLED");
    println!("host_mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_bootstrap_candidate_reader_requires_exact_distinct_target() {
        let installed = "a".repeat(64);
        let target = "b".repeat(64);
        let candidate = Path::new("C:/sing-box/releases/candidate/bin/edge-console.exe");
        let active = Path::new("C:/sing-box/releases/installed/bin/edge-console.exe");
        assert_eq!(
            require_exact_offline_bootstrap_reader_identity(
                &installed, &target, candidate, candidate
            ),
            Ok(())
        );
        for (installed_case, target_case, invoking_case) in [
            (installed.as_str(), target.as_str(), active),
            (installed.as_str(), installed.as_str(), candidate),
            (installed.as_str(), "short", candidate),
            (
                installed.as_str(),
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                candidate,
            ),
        ] {
            assert_eq!(
                require_exact_offline_bootstrap_reader_identity(
                    installed_case,
                    target_case,
                    invoking_case,
                    candidate,
                ),
                Err("HOST_WINDOWS_FIRST_USE_CANDIDATE_READER_NOT_EXACT")
            );
        }
    }
    #[test]
    fn completed_identity_history_requires_exact_original_release() {
        let original = edge_shared_types::ReleaseSet {
            schema_version: 7,
            source_revision: "a".repeat(40),
            ..Default::default()
        }
        .encode_to_vec();
        let sha: String = ring::digest::digest(&ring::digest::SHA256, &original)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        verify_historical_release_bytes(&original, &"a".repeat(40), &sha).unwrap();
        assert!(verify_historical_release_bytes(&original, &"b".repeat(40), &sha).is_err());
        assert!(
            verify_historical_release_bytes(&original, &"a".repeat(40), &"0".repeat(64)).is_err()
        );
        assert!(verify_historical_release_bytes(b"invalid", &"a".repeat(40), &sha).is_err());
    }
    #[test]
    fn pending_rebind_accepts_only_exact_unconsumed_pair() {
        let dir = std::env::temp_dir().join(format!("w4-rebind-pending-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        std::fs::create_dir(&dir).unwrap();
        let previous = WindowsActivationState {
            schema_version: 1,
            release_set_sha256: "a".repeat(64),
            source_revision: "b".repeat(40),
            ..Default::default()
        };
        let receipt = FleetWindowsReceiptIdentityEnrollment {
            schema_version: 1,
            machine_id: MACHINE.into(),
            release_set_sha256: previous.release_set_sha256.clone(),
            source_revision: previous.source_revision.clone(),
        };
        let trust = FleetWindowsTrustEnrollment {
            schema_version: 1,
            machine_id: MACHINE.into(),
            release_set_sha256: previous.release_set_sha256.clone(),
            source_revision: previous.source_revision.clone(),
        };
        create_only(&dir.join(MARKER), &receipt.encode_to_vec()).unwrap();
        assert!(pending_rebind_snapshot(&dir, &previous).is_err());
        create_only(&dir.join("trust-enrollment.pb"), &trust.encode_to_vec()).unwrap();
        let accepted = pending_rebind_snapshot(&dir, &previous).unwrap();
        assert_eq!(accepted.receipt_bytes, receipt.encode_to_vec());
        assert_eq!(accepted.trust_bytes, trust.encode_to_vec());
        assert_eq!(accepted.predecessor_release, previous.release_set_sha256);
        let mut wrong_revision = previous.clone();
        wrong_revision.source_revision = "f".repeat(40);
        assert!(pending_rebind_snapshot(&dir, &wrong_revision).is_err());
        create_only(&dir.join(PRIVATE), b"sealed-secret-not-for-rebind").unwrap();
        assert!(pending_rebind_snapshot(&dir, &previous).is_err());
        std::fs::remove_file(dir.join(PRIVATE)).unwrap();
        create_only(
            &dir.join(format!(
                "{MARKER}.predecessor-{}",
                previous.release_set_sha256
            )),
            &receipt.encode_to_vec(),
        )
        .unwrap();
        assert!(pending_rebind_snapshot(&dir, &previous).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn enrollment_is_exact_host_release_and_revision_only() {
        let active = WindowsActivationState {
            schema_version: 1,
            release_set_sha256: "a".repeat(64),
            source_revision: "b".repeat(40),
            ..Default::default()
        };
        let request = FleetWindowsReceiptIdentityEnrollment {
            schema_version: 1,
            machine_id: MACHINE.into(),
            release_set_sha256: active.release_set_sha256.clone(),
            source_revision: active.source_revision.clone(),
        };
        assert!(request_valid(&request, &active).is_ok());
        let mut altered = request.clone();
        altered.machine_id = "Invalid-Uppercase".into();
        assert!(request_valid(&altered, &active).is_err());
        altered = request.clone();
        altered.release_set_sha256 = "f".repeat(64);
        assert!(request_valid(&altered, &active).is_err());
        altered = request.clone();
        altered.source_revision = "f".repeat(40);
        assert!(request_valid(&altered, &active).is_err());
        altered = request.clone();
        altered.schema_version = 2;
        assert!(request_valid(&altered, &active).is_err());
    }

    #[test]
    fn combined_first_use_rejects_preexisting_identity_or_trust_before_begin() {
        let root = std::env::temp_dir().join(format!(
            "w4-fresh-enrollment-preflight-{}",
            std::process::id()
        ));
        assert!(preflight_fresh_identity_root(&root).is_ok());
        std::fs::create_dir(&root).unwrap();
        assert!(preflight_fresh_identity_root(&root).is_ok());
        for name in [
            MARKER,
            COMPLETED,
            PRIVATE,
            PUBLIC,
            "trust.pb",
            "trust-enrollment.pb",
            "trust-enrollment.completed.pb",
        ] {
            let path = root.join(name);
            std::fs::write(&path, b"existing protected state").unwrap();
            assert_eq!(
                preflight_fresh_identity_root(&root),
                Err("HOST_WINDOWS_RECEIPT_ENROLL_SLOT_NOT_EMPTY_NO_REKEY".into()),
                "{name}"
            );
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn read_only_first_use_file_probe_rejects_uncertain_and_empty_state() {
        let path =
            std::env::temp_dir().join(format!("windows-first-use-readonly-{}", std::process::id()));
        assert_eq!(checked_regular_exists(&path, 512), Ok(false));
        std::fs::write(&path, b"").unwrap();
        assert!(checked_regular_exists(&path, 512).is_err());
        std::fs::write(&path, b"bounded").unwrap();
        assert_eq!(checked_regular_exists(&path, 512), Ok(true));
        assert!(checked_regular_exists(&path, 1).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn completed_identity_marker_never_blocks_future_signed_dispatch() {
        let dir = std::env::temp_dir().join(format!("w4-receipt-marker-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let marker = dir.join(MARKER);
        let completed = dir.join(COMPLETED);
        create_only(&marker, b"exact immutable typed protobuf marker").unwrap();
        complete_marker(&dir).unwrap();
        assert!(!marker.exists());
        assert_eq!(
            std::fs::read(&completed).unwrap(),
            b"exact immutable typed protobuf marker"
        );
        // Simulate a crash after hard-link creation but BEFORE unlink:
        // completing the same marker may only remove its ACTIVE name.
        std::fs::hard_link(&completed, &marker).unwrap();
        complete_marker(&dir).unwrap();
        assert!(!marker.exists());
        assert!(completed.exists());
        assert!(create_only(&completed, b"replacement").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn protected_identity_never_replaces_existing_private_key() {
        let test_dir =
            std::env::temp_dir().join(format!("w4-receipt-identity-{}", std::process::id()));
        std::fs::create_dir(&test_dir).unwrap();
        let private = test_dir.join(PRIVATE);
        let public = test_dir.join(PUBLIC);
        let pk8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pk8.as_ref()).unwrap();
        create_only(&private, pk8.as_ref()).unwrap();
        // Crash-gap recovery rederives the same PUBLIC identity, no rekey.
        let observed = existing_private_public(&test_dir).unwrap().unwrap();
        assert_eq!(observed.as_slice(), pair.public_key().as_ref());
        assert_eq!(std::fs::read(&public).unwrap(), observed);
        assert_eq!(existing_private_public(&test_dir).unwrap(), Some(observed));
        assert!(create_only(&private, pk8.as_ref()).is_err());
        std::fs::write(&public, [0u8; 32]).unwrap();
        assert!(existing_private_public(&test_dir).is_err());
        std::fs::remove_dir_all(test_dir).unwrap();
    }
}
