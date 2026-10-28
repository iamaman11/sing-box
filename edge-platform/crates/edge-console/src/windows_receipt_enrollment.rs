//! Windows W4: one narrow first-use exception for the *identity*, not for
//! Worker trust or any runtime mutation. The local elevated Administrator may
//! reserve a typed, exact-release marker under the protected native host root.
//! Only the ALREADY INSTALLED periodic LocalSystem dispatcher generates and
//! stores the Ed25519 PRIVATE signer. NetworkService cannot write this root.
//! No extra task, service, transport, secret export or unsigned SCM operation.

use super::*;
use edge_shared_types::{
    FleetWindowsReceiptIdentityEnrollment,
    host_journal::{require_windows_local_administrator_first_use, verify_native_journal_protection},
};
use prost::Message;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const MACHINE: &str = "sing-box-windows-lab";
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
        || request.machine_id != MACHINE
        || request.source_revision != active.source_revision
        || request.release_set_sha256 != active.release_set_sha256
        || request.source_revision.len() != 40
        || !request.source_revision.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || request.release_set_sha256.len() != 64
        || !request.release_set_sha256.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_EXACT_RELEASE_OR_HOST_MISMATCH");
    }
    Ok(())
}

fn read_marker(path: &Path, active: &WindowsActivationState) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_MARKER_MISSING")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 512 {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_MARKER_NOT_BOUNDED_REGULAR".into());
    }
    let bytes = fs::read(path).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_MARKER_UNREADABLE")?;
    let request = FleetWindowsReceiptIdentityEnrollment::decode(bytes.as_slice())
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PROTO_INVALID")?;
    if request.encode_to_vec() != bytes {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_PROTO_NONCANONICAL".into());
    }
    request_valid(&request, active).map_err(str::to_owned)
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
        Ok(_) => fs::read(&private)
            .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PRIVATE_UNREADABLE")?,
    };
    let pair = Ed25519KeyPair::from_pkcs8(&pk8)
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PRIVATE_INVALID")?;
    let key: [u8; 32] = pair.public_key().as_ref().try_into()
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
            let stored = fs::read(&public)
                .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_UNREADABLE")?;
            if stored != key {
                return Err("HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_PRIVATE_MISMATCH".into());
            }
        }
    }
    Ok(Some(key))
}

/// Local elevated Administrator: create ONE immutable, typed request in the
/// existing protected root. No receipt PRIVATE key is generated here.
pub(super) fn prepare(
    install_root: &Path,
    accepted_revision: &str,
    release_sha256: &str,
) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let active = load_verified_activation(install_root)?;
    if active.source_revision != accepted_revision || active.release_set_sha256 != release_sha256 {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_SOURCE_PIN_MISMATCH".into());
    }
    require_offline_windows_owner(install_root, &active)?;
    verify_offline_bootstrap_dispatcher(&active.console_path, "Ready")?;
    let root = native_root(install_root)?;
    // A pre-existing signing identity cannot be re-enrolled through this
    // unsigned local-first-use boundary, even if its public pin is unknown.
    if root.join(PRIVATE).exists() || root.join(PUBLIC).exists() || root.join(COMPLETED).exists() {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_IDENTITY_ALREADY_EXISTS".into());
    }
    if install_root.join("exchange").join("requests").join("host-intent.pb").exists()
        || privileged_request_path(install_root).exists()
    {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_COMPETING_REQUEST".into());
    }
    let request = FleetWindowsReceiptIdentityEnrollment {
        schema_version: 1,
        machine_id: MACHINE.into(),
        source_revision: accepted_revision.into(),
        release_set_sha256: release_sha256.into(),
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
                != fs::read(&completed).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_ARCHIVE_UNREADABLE")?
            {
                return Err("HOST_WINDOWS_RECEIPT_ENROLL_ARCHIVE_MISMATCH".into());
            }
        }
    }
    fs::remove_file(marker).map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_UNLINK_UNCERTAIN_NO_REPLAY".to_owned())
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
    let active = load_verified_activation(install_root)?;
    require_offline_windows_owner(install_root, &active)?;
    read_marker(&marker, &active)?;
    if install_root.join("exchange").join("requests").join("host-intent.pb").exists()
        || privileged_request_path(install_root).exists()
    {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_COMPETING_REQUEST".into());
    }
    if root.join("trust.pb").exists() {
        return Err("HOST_WINDOWS_RECEIPT_ENROLL_TRUST_ALREADY_PRESENT".into());
    }
    let public = match existing_private_public(&root)? {
        Some(key) => key,
        None => {
            let secret = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_KEY_GENERATION_FAILED")?;
            let pair = Ed25519KeyPair::from_pkcs8(secret.as_ref())
                .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_KEY_GENERATION_FAILED")?;
            let key: [u8; 32] = pair.public_key().as_ref().try_into()
                .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_KEY_GENERATION_FAILED")?;
            // Fail closed on ANY uncertain write: do not generate another key
            // to recover. Future dispatcher can only rederive public identity.
            create_only(&root.join(PRIVATE), secret.as_ref())?;
            create_only(&root.join(PUBLIC), &key)?;
            key
        }
    };
    complete_marker(&root)?;
    println!("status=PASS");
    println!("native_receipt_identity=SYSTEM_GENERATED_OR_EXACT_EXISTING");
    println!("native_receipt_public_hex={}", public.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("worker_trust=NOT_ENROLLED");
    println!("scm_mutations=0");
    println!("network_mutations=0");
    Ok(true)
}

/// Local elevated Administrator read-only: publish public identity ONLY.
/// Never open, read or copy the SYSTEM private signer from this command.
pub(super) fn observe(install_root: &Path) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    require_exact_immutable_activation_console(install_root)?;
    let root = native_root(install_root)?;
    let active = load_verified_activation(install_root)?;
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
    let bytes = fs::read(public)
        .map_err(|_| "HOST_WINDOWS_RECEIPT_ENROLL_PUBLIC_UNREADABLE")?;
    println!("w4_receipt_identity=PUBLIC_ONLY_OBSERVED");
    println!("machine_id={MACHINE}");
    println!("release_set_sha256={}", active.release_set_sha256);
    println!("native_receipt_public_hex={}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("worker_trust=NOT_ENROLLED");
    println!("host_mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        altered.machine_id = "other-host".into();
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
    fn protected_identity_never_replaces_existing_private_key() {
        let test_dir = std::env::temp_dir().join(format!("w4-receipt-identity-{}", std::process::id()));
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
