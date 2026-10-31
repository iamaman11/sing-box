//! Universal administration through the same LocalSystem dispatcher, Worker
//! signature, protected journal and receipt identity as lifecycle operations.
use super::*;
use edge_shared_types::{
    FleetHostKind, host_admin, host_journal::verify_native_journal_protection,
};
use prost::Message;
use std::os::windows::fs::OpenOptionsExt;
#[path = "windows_admin_process.rs"]
pub(super) mod process;

pub(super) fn owner_lock(root: &Path) -> Result<File, String> {
    let journal = root.join("native-host/journal");
    verify_native_journal_protection(&journal)?;
    require_exact_immutable_activation_console(root)?;
    let active =
        load_verified_activation(root).map_err(|_| "HOST_WINDOWS_OWNER_ACTIVATION_UNPROVEN")?;
    for path in [
        &active.console_path,
        &active.controller_path,
        &active.diagnostic_path,
        &active.sing_box_path,
    ] {
        edge_shared_types::host_journal::verify_windows_protected_path_acl(Path::new(path), true)?;
    }
    verify_offline_bootstrap_dispatcher(&active.console_path, "Running")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(1 | 2)
        .open(journal.join("owner.lock"))
        .map_err(|_| "HOST_WINDOWS_OWNER_BUSY")?;
    lock.try_lock().map_err(|_| "HOST_WINDOWS_OWNER_BUSY")?;
    Ok(lock)
}

/// Classification is pure and shared by admission before and after Worker POST.
/// An UNKNOWN resource BEGIN freezes all mutating Windows entrypoints.
/// Arbitrary signed ADMIN may execute cmd.exe/PowerShell and therefore cannot
/// be classified read-only. Native /host status remains the diagnostic route;
/// only a separately signed RECOVER can inspect the prior resource BEGIN.
fn check_journal_entry(
    name: &str,
    id: &str,
    admin: bool,
    recovery: bool,
) -> Result<(), &'static str> {
    // ADMIN never inherits RECOVER's narrow exception, even if a caller
    // accidentally combines both flags in this internal API.
    if admin && recovery {
        return Err("HOST_WINDOWS_ADMIN_RECOVERY_SCOPE_INVALID");
    }
    if (admin
        && (name == format!("admin-{id}.pending.pb") || name == format!("admin-{id}.terminal.pb")))
        || (!admin && (name == format!("{id}.pb") || name.starts_with(&format!("{id}."))))
    {
        return Err("HOST_WINDOWS_OPERATION_EXISTS_NO_REPLAY");
    }
    if name.ends_with(".pending.pb") && !(name.starts_with("resource-") && recovery) {
        return Err("HOST_WINDOWS_PENDING_GATE_NO_REPLAY");
    }
    Ok(())
}

/// Refuse an existing operation BEFORE a one-shot Worker POST and immediately
/// before durable ADMIN BEGIN. The scheduled task must not repeatedly request
/// authorizations after an uncertain ACK.
pub(super) fn request_available(
    journal: &Path,
    operation: &str,
    admin: bool,
    recovery: bool,
) -> Result<(), &'static str> {
    let id: String = process::sha(operation.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for entry in fs::read_dir(journal).map_err(|_| "HOST_WINDOWS_JOURNAL_UNAVAILABLE")? {
        let entry = entry.map_err(|_| "HOST_WINDOWS_JOURNAL_UNAVAILABLE")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        edge_shared_types::host_journal::verify_windows_protected_path_acl(&entry.path(), true)?;
        check_journal_entry(&name, &id, admin, recovery)?;
    }
    Ok(())
}
/// Refuse another request at the single SYSTEM task boundary. Inaccessible
/// metadata is not proof of absence; never fall through to another handler.
pub(super) fn reject_competing_request(path: &Path) -> Result<(), &'static str> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err("HOST_WINDOWS_COMPETING_REQUEST"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("HOST_WINDOWS_COMPETING_REQUEST_METADATA_UNAVAILABLE"),
    }
}

pub(super) fn create(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(0x80000000)
        .open(path)
        .map_err(|_| "HOST_ADMIN_RECORD_EXISTS_OR_UNAVAILABLE_NO_REPLAY")?;
    edge_shared_types::host_journal::verify_windows_protected_path_acl(path, true)?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| "HOST_ADMIN_RECORD_SYNC_UNKNOWN_NO_REPLAY")?;
    Ok(())
}

/// Durable replacement by the existing owner. A stale temporary file is a
/// crash witness and must not be cleared or overwritten automatically.
pub(super) fn replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let next = path.with_extension("pb.new");
    create(&next, bytes)?;
    let source: Vec<u16> = next.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err("HOST_WINDOWS_PROTECTED_REPLACEMENT_UNKNOWN_NO_REPLAY".into());
    }
    Ok(())
}
pub(super) async fn dispatch_if_present(root: &Path) -> Result<bool, String> {
    let path = root.join("exchange/requests/admin-request.pb");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("HOST_ADMIN_REQUEST_METADATA_UNAVAILABLE".into()),
        Ok(_) => {}
    }
    require_exact_immutable_activation_console(root)?;
    reject_competing_request(&privileged_request_path(root))?;
    reject_competing_request(&root.join("exchange/requests/host-intent.pb"))?;
    let journal = root.join("native-host/journal");
    verify_native_journal_protection(&journal)?;
    let transport =
        windows_signed_host::TransportRequest::open(&path, host_admin::MAX_BYTES as u64)?;
    let raw = &transport.bytes;
    let request = host_admin::decode(&raw)?;
    host_admin::validate_for_kind(&request, FleetHostKind::Windows)?;
    let private_path = root.join("native-host/receipt-key.pk8");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&private_path, true)?;
    let private = windows_signed_host::bounded_regular_file(&private_path, 4096)?;
    let operation = host_admin::operation_id(&request);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?
        .as_secs();
    let id: String = process::sha(operation.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let terminal_exists =
        match fs::symlink_metadata(journal.join(format!("admin-{id}.terminal.pb"))) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err("HOST_ADMIN_TERMINAL_METADATA_UNAVAILABLE_NO_REPLAY".into()),
        };
    if host_admin::expired_before_begin(&request, now) || terminal_exists {
        return deny_before_begin(
            root,
            transport,
            &request,
            &private,
            now,
            "HOST_ADMIN_REQUEST_EXPIRED_BEFORE_BEGIN",
        );
    }
    request_available(&journal, &operation, true, false)?;
    let prepared: Result<edge_shared_types::FleetNativeAdminAuthorization, String> = async {
        let (trust, _, _) = windows_signed_host::current_authority(
            root,
            &request.machine_id,
            &operation,
            request.requested_at_unix,
            &private,
        )
        .await?;
        if process::sha(&trust.release_set_pb) != request.release_set_sha256 {
            return Err("HOST_ADMIN_RELEASE_MISMATCH".into());
        }
        let identity = root.join("state/secrets").join(ACCESS_IDENTITY_FILE_NAME);
        let auth =
            edge_secrets::request_canonical_native_admin_authorization(&raw, &identity).await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?
            .as_secs();
        host_admin::verify_authorization(&request, &auth, &trust.pinned_worker_public_key, now)?;
        Ok(auth)
    }
    .await;
    let auth = match prepared {
        Ok(auth) => auth,
        Err(reason) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?
                .as_secs();
            return deny_before_begin(root, transport, &request, &private, now, &reason);
        }
    };
    let id: String = process::sha(operation.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let pending = journal.join(format!("admin-{id}.pending.pb"));
    let terminal = journal.join(format!("admin-{id}.terminal.pb"));
    match fs::symlink_metadata(&terminal) {
        Ok(_) => return Err("HOST_ADMIN_SAME_OPERATION_EXISTS_NO_REPLAY".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("HOST_ADMIN_TERMINAL_METADATA_UNAVAILABLE_NO_REPLAY".into()),
    }
    // Recheck AFTER Worker authorization immediately before ADMIN BEGIN.
    // A signature authenticates the operator; it does not make arbitrary
    // executables read-only or release another resource's UNKNOWN BEGIN.
    request_available(&journal, &operation, true, false)?;
    create(&pending, &raw)?;
    let out_path = journal.join(format!("admin-{id}.stdout.bin"));
    let err_path = journal.join(format!("admin-{id}.stderr.bin"));
    let capture = |p: &Path| -> Result<File, String> {
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p)
            .map_err(|_| "HOST_ADMIN_CAPTURE_UNAVAILABLE_NO_REPLAY")?;
        edge_shared_types::host_journal::verify_windows_protected_path_acl(p, true)?;
        Ok(f)
    };
    let out = capture(&out_path)?;
    let err = capture(&err_path)?;
    let mut receipt = tokio::task::block_in_place(|| process::run(&request, out, err))?;
    receipt.schema_version = 1;
    receipt.machine_id = request.machine_id.clone();
    receipt.operation_id = operation;
    receipt.request_sha256 = process::sha(&raw);
    receipt.worker_authorization = Some(auth);
    receipt.observed_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?
        .as_secs();
    receipt.stdout_capture_path = out_path.to_string_lossy().into_owned();
    receipt.stderr_capture_path = err_path.to_string_lossy().into_owned();
    host_admin::sign_receipt(&request, &mut receipt, &private)?;
    let bytes = receipt.encode_to_vec();
    create(&terminal, &bytes)?;
    let complete = receipt.process_exited
        && receipt.stdin_input_complete
        && receipt.stdout_stream_eof
        && receipt.stderr_stream_eof;
    if complete {
        fs::remove_file(&pending).map_err(|_| "HOST_ADMIN_PENDING_CLEAR_UNKNOWN_NO_REPLAY")?;
    }
    write_atomic(&root.join("exchange/results/admin-result.pb"), &bytes)
        .map_err(|_| "HOST_ADMIN_RECEIPT_DELIVERY_UNKNOWN_NO_REPLAY")?;
    transport.consume()?;
    if !complete {
        return Err("HOST_ADMIN_COMPLETION_INCOMPLETE_NO_REPLAY".into());
    }
    println!("native_system_admin=SIGNED_TERMINAL");
    Ok(true)
}

/// Code handoff may preserve an expired untrusted transport request ONLY
/// when the protected journal proves it never reached native BEGIN. The new
/// SYSTEM owner signs a denial and consumes it; Administrator never deletes it.
pub(super) fn preflight_expired_transport_handoff(root: &Path) -> Result<(), String> {
    let path = root.join("exchange/requests/admin-request.pb");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("HOST_ADMIN_HANDOFF_REQUEST_METADATA_UNPROVEN".into()),
        Ok(_) => {}
    }
    let transport =
        windows_signed_host::TransportRequest::open(&path, host_admin::MAX_BYTES as u64)?;
    let request = host_admin::decode(&transport.bytes)?;
    host_admin::validate_for_kind(&request, FleetHostKind::Windows)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_ADMIN_CLOCK_INVALID")?
        .as_secs();
    if request.machine_id != windows_receipt_enrollment::bound_machine_id(root)?
        || !host_admin::expired_before_begin(&request, now)
    {
        return Err("HOST_ADMIN_HANDOFF_REQUIRES_EXPIRED_UNSTARTED_REQUEST".into());
    }
    request_available(
        &root.join("native-host/journal"),
        &host_admin::operation_id(&request),
        true,
        false,
    )?;
    Ok(())
}

fn deny_before_begin(
    root: &Path,
    transport: windows_signed_host::TransportRequest,
    request: &edge_shared_types::FleetNativeAdminRequest,
    private: &[u8],
    now: u64,
    reason: &str,
) -> Result<bool, String> {
    let journal = root.join("native-host/journal");
    let operation = host_admin::operation_id(request);
    if request.machine_id != windows_receipt_enrollment::bound_machine_id(root)? {
        return Err("HOST_ADMIN_EXPIRED_MACHINE_MISMATCH".into());
    }
    let id: String = process::sha(operation.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let terminal = journal.join(format!("admin-{id}.terminal.pb"));
    let bytes = match fs::symlink_metadata(&terminal) {
        Ok(_) => {
            // A crash after a durable denial can replay only delivery,
            // never authorization, BEGIN, process or journal creation.
            for entry in fs::read_dir(&journal).map_err(|_| "HOST_WINDOWS_JOURNAL_UNAVAILABLE")? {
                let entry = entry.map_err(|_| "HOST_WINDOWS_JOURNAL_UNAVAILABLE")?;
                edge_shared_types::host_journal::verify_windows_protected_path_acl(
                    &entry.path(),
                    true,
                )?;
                if entry.path() != terminal {
                    check_journal_entry(&entry.file_name().to_string_lossy(), &id, true, false)?;
                }
            }
            let bytes = windows_signed_host::bounded_regular_file(&terminal, 140000)?;
            let receipt = edge_shared_types::FleetNativeAdminResult::decode(bytes.as_slice())
                .map_err(|_| "HOST_ADMIN_DENIAL_PROTO_INVALID")?;
            let key = ring::signature::Ed25519KeyPair::from_pkcs8(private)
                .map_err(|_| "HOST_ADMIN_DENIAL_SIGNER_INVALID")?;
            use ring::signature::KeyPair;
            host_admin::verify_receipt(request, &receipt, key.public_key().as_ref())?;
            if !receipt.rejected_before_begin || receipt.encode_to_vec() != bytes {
                return Err("HOST_ADMIN_DENIAL_REPLAY_UNPROVEN".into());
            }
            bytes
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            request_available(&journal, &operation, true, false)?;
            let mut receipt = host_admin::prebegin_rejection(request, now, reason)?;
            host_admin::sign_receipt(request, &mut receipt, private)?;
            let bytes = receipt.encode_to_vec();
            create(&terminal, &bytes)?;
            bytes
        }
        Err(_) => return Err("HOST_ADMIN_DENIAL_METADATA_UNAVAILABLE_NO_REPLAY".into()),
    };
    write_atomic(&root.join("exchange/results/admin-result.pb"), &bytes)
        .map_err(|_| "HOST_ADMIN_DENIAL_DELIVERY_UNKNOWN_NO_REPLAY")?;
    transport.consume()?;
    println!("native_system_admin=REJECTED_BEFORE_BEGIN");
    Ok(true)
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn signed_admin_cannot_bypass_historical_resource_pending() {
        let id = "own-operation-digest";
        // Any generic ADMIN request may contain a mutable executable or
        // shell. Neither Worker authorization nor a distinct operation ID
        // proves it read-only, even for commands described as diagnostics.
        assert_eq!(
            check_journal_entry("resource-historical.pending.pb", id, true, false),
            Err("HOST_WINDOWS_PENDING_GATE_NO_REPLAY")
        );
        // Ordinary lifecycle must also refuse a resource BEGIN until its
        // separately signed RECOVER has settled the physical state.
        assert_eq!(
            check_journal_entry("resource-historical.pending.pb", id, false, false),
            Err("HOST_WINDOWS_PENDING_GATE_NO_REPLAY")
        );
        assert_eq!(
            check_journal_entry("resource-historical.pending.pb", id, false, true),
            Ok(())
        );
        // RECOVER admission is scoped later by the signed native journal;
        // it does not execute a historical mutation or grant ADMIN rights.
        assert_eq!(
            check_journal_entry("resource-other.pending.pb", id, true, true),
            Err("HOST_WINDOWS_ADMIN_RECOVERY_SCOPE_INVALID")
        );
        // Only lifecycle caller supplies recovery=true; ADMIN cannot
        // borrow this narrow exception from runner/Worker data.
        // The original request is permanently non-replayable.
        assert_eq!(
            check_journal_entry("admin-own-operation-digest.pending.pb", id, true, false),
            Err("HOST_WINDOWS_OPERATION_EXISTS_NO_REPLAY")
        );
        assert_eq!(
            check_journal_entry("admin-own-operation-digest.terminal.pb", id, true, false),
            Err("HOST_WINDOWS_OPERATION_EXISTS_NO_REPLAY")
        );
        // A second incomplete ADMIN is not silently treated as an isolated
        // resource; no guessed owner/scope or parallel arbitrary effects.
        assert_eq!(
            check_journal_entry("admin-other.pending.pb", id, true, false),
            Err("HOST_WINDOWS_PENDING_GATE_NO_REPLAY")
        );
        assert_eq!(
            check_journal_entry("unknown.pending.pb", id, true, false),
            Err("HOST_WINDOWS_PENDING_GATE_NO_REPLAY")
        );
        assert_eq!(
            check_journal_entry("admin-other.terminal.pb", id, true, false),
            Ok(())
        );
        assert_eq!(
            check_journal_entry("other-record.pb", id, true, false),
            Ok(())
        );
        assert_eq!(
            check_journal_entry("own-operation-digest.pb", id, false, false),
            Err("HOST_WINDOWS_OPERATION_EXISTS_NO_REPLAY")
        );
    }

    #[test]
    fn competing_request_is_rejected_before_authorization() {
        let dir = std::env::temp_dir().join(format!(
            "edge-windows-competing-request-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("admin-request.pb");
        assert!(reject_competing_request(&path).is_ok());
        fs::write(&path, b"pending").unwrap();
        assert_eq!(
            reject_competing_request(&path),
            Err("HOST_WINDOWS_COMPETING_REQUEST")
        );
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            reject_competing_request(&path),
            Err("HOST_WINDOWS_COMPETING_REQUEST")
        );
        fs::remove_dir(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }
}
