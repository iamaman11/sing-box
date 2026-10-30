//! Declarative configuration owned by the existing SYSTEM HostIntent path.
//! No credential COMMIT/ABORT/REPLAY, no network capture, no local policy edits.
use super::*;
use edge_shared_types::{FleetNativeAdminRequest, host_journal::verify_windows_protected_path_acl};

pub(super) struct Configuration {
    bytes: Vec<u8>,
    pub(super) digest: Vec<u8>,
    state_digest: Vec<u8>,
    _application_paths: edge_shared_types::windows_routing::NativeApplicationPaths,
}

pub(super) fn prepare(root: &Path, spec: &[u8]) -> Result<Option<Configuration>, String> {
    let path = windows_runtime_state_path(root);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if fs::symlink_metadata(local_singbox_config_path(root)).is_ok() {
                return Err("HOST_WINDOWS_CONFIG_ORPHAN_CONFIG".into());
            }
            return Ok(None);
        }
        Err(_) => return Err("HOST_WINDOWS_CONFIG_STATE_UNAVAILABLE".into()),
        Ok(_) => {}
    }
    verify_windows_protected_path_acl(&path, true)?;
    let state_bytes = windows_signed_host::bounded_regular_file(&path, 65536)?;
    let state = decode_windows_runtime_state(&state_bytes)?;
    let desired = edge_shared_types::parse_production_desired_text(spec)?;
    edge_controller_core::production::ProductionComposition::from_proto(&desired)
        .map_err(|_| "HOST_WINDOWS_CONFIG_DESIRED_INVALID")?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "HOST_WINDOWS_DATAPATH_MODE_INVALID")?;
    if mode == WindowsDatapathMode::Unspecified {
        return Err("HOST_WINDOWS_DATAPATH_MODE_INVALID".into());
    }
    // A selected-application policy is inert in ProxyOnly. Do not demand
    // installed process paths until a TUN candidate actually uses them.
    let application_paths = edge_shared_types::windows_routing::verify_native_paths(
        if mode == WindowsDatapathMode::ManagedTun {
            desired.windows_application_routing.as_ref()
        } else {
            None
        },
    )?;
    // Prepare and exact-binary-check either desired candidate with the SAME
    // renderer. Preparing ManagedTun is not authorization to activate it.
    let bytes = edge_singbox::render_windows_config_for_desired(&state, mode, &desired)?;
    Ok(Some(Configuration {
        digest: windows_admin::process::sha(&bytes),
        bytes,
        state_digest: windows_admin::process::sha(&state_bytes),
        _application_paths: application_paths,
    }))
}

pub(super) fn observed_digest(root: &Path) -> Result<Vec<u8>, &'static str> {
    let path = local_singbox_config_path(root);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("HOST_WINDOWS_CONFIG_METADATA_UNAVAILABLE"),
        Ok(_) => {}
    }
    verify_windows_protected_path_acl(&path, true)?;
    Ok(windows_admin::process::sha(
        &windows_signed_host::bounded_regular_file(&path, 1024 * 1024)?,
    ))
}

/// After signature verification, BEFORE native BEGIN. The exact pinned binary
/// validates a protected candidate; it cannot modify live config or routes.
pub(super) fn validate(root: &Path, config: &Configuration, operation: &str) -> Result<(), String> {
    let active =
        load_verified_activation(root).map_err(|_| "HOST_WINDOWS_CONFIG_ACTIVATION_UNPROVEN")?;
    let journal = root.join("native-host/journal");
    let id: String = windows_admin::process::sha(operation.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let candidate = journal.join(format!("config-{id}.candidate.json"));
    windows_admin::create(&candidate, &config.bytes)?;
    let capture = |kind: &str| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(journal.join(format!("config-{id}.check-{kind}.bin")))
            .map_err(|_| "HOST_WINDOWS_CONFIG_CHECK_CAPTURE_UNAVAILABLE")
    };
    let request = FleetNativeAdminRequest {
        schema_version: 1,
        machine_id: "native-config-check".into(),
        source_comment_id: 1,
        release_set_sha256: vec![1; 32],
        comment_sha256: vec![1; 32],
        requested_at_unix: 1,
        argv: vec![
            active.sing_box_path,
            "check".into(),
            "-c".into(),
            candidate.to_string_lossy().into_owned(),
        ],
        timeout_seconds: 30,
        ..Default::default()
    };
    let result = windows_admin::process::run(&request, capture("stdout")?, capture("stderr")?)?;
    // Keep the bounded candidate and diagnostic evidence in the SAME protected
    // journal; no secret output or extra log/transport is introduced.
    if result.exit_code != 0 || !result.stdout_stream_eof || !result.stderr_stream_eof {
        return Err("HOST_WINDOWS_CONFIG_NATIVE_VALIDATION_FAILED".into());
    }
    Ok(())
}

pub(super) fn apply(
    root: &Path,
    config: &Configuration,
    operation: &str,
) -> Result<(), &'static str> {
    let active =
        load_verified_activation(root).map_err(|_| "HOST_WINDOWS_CONFIG_ACTIVATION_UNPROVEN")?;
    require_offline_windows_owner(root, &active)
        .map_err(|_| "HOST_WINDOWS_CONFIG_STOPPED_OWNER_REQUIRED")?;
    let state =
        windows_signed_host::bounded_regular_file(&windows_runtime_state_path(root), 65536)?;
    if windows_admin::process::sha(&state) != config.state_digest {
        return Err("HOST_WINDOWS_CONFIG_CREDENTIAL_STATE_CHANGED");
    }
    let parent = local_singbox_config_path(root)
        .parent()
        .ok_or("HOST_WINDOWS_CONFIG_PARENT_INVALID")?
        .to_path_buf();
    match fs::create_dir(&parent) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("HOST_WINDOWS_CONFIG_PARENT_UNAVAILABLE"),
    }
    let reader = controller_reader_sid()?;
    harden_system_authority_path_for_reader(&parent, false, true, &reader)
        .map_err(|_| "HOST_WINDOWS_CONFIG_PARENT_UNPROVEN")?;
    let id: String = windows_admin::process::sha(operation.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let journal = root.join("native-host/journal");
    let path = local_singbox_config_path(root);
    match fs::read(&path) {
        Ok(old) => windows_admin::create(&journal.join(format!("config-{id}.previous.json")), &old)
            .map_err(|_| "HOST_WINDOWS_CONFIG_PREVIOUS_PRESERVATION_FAILED")?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("HOST_WINDOWS_CONFIG_PREVIOUS_UNAVAILABLE"),
    }
    let next = parent.join(format!(".config-{id}.new"));
    windows_admin::create(&next, &config.bytes)
        .map_err(|_| "HOST_WINDOWS_CONFIG_STAGE_UNKNOWN_NO_REPLAY")?;
    harden_system_authority_path_for_reader(&next, false, false, &reader)
        .map_err(|_| "HOST_WINDOWS_CONFIG_ACL_UNPROVEN")?;
    // Atomic replacement on the same NTFS volume. Prior content remains in
    // the protected journal; no automatic rollback/restart on unknown result.
    use std::os::windows::ffi::OsStrExt;
    let source: Vec<u16> = next.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err("HOST_WINDOWS_CONFIG_ACTIVATION_UNKNOWN_NO_REPLAY");
    }
    if observed_digest(root)? != config.digest {
        return Err("HOST_WINDOWS_CONFIG_POSTSTATE_MISMATCH");
    }
    Ok(())
}

fn controller_reader_sid() -> Result<String, &'static str> {
    // The service SID, not generic NetworkService (which also hosts the GH
    // runner), may read plaintext runtime configuration. Never grant write.
    let system = std::env::var_os("SystemRoot").ok_or("HOST_WINDOWS_SYSTEM_ROOT_UNAVAILABLE")?;
    let reply = Command::new(PathBuf::from(system).join("System32/sc.exe"))
        .args(["showsid", WINDOWS_CONTROLLER_SERVICE_NAME])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "HOST_WINDOWS_CONTROLLER_SID_UNAVAILABLE")?;
    if !reply.status.success() {
        return Err("HOST_WINDOWS_CONTROLLER_SID_UNAVAILABLE");
    }
    let text = String::from_utf8_lossy(&reply.stdout);
    let values: Vec<_> = text
        .split_whitespace()
        .filter(|s| {
            s.starts_with("S-1-5-80-")
                && s.len() <= 128
                && s[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
        })
        .collect();
    if values.len() != 1 {
        return Err("HOST_WINDOWS_CONTROLLER_SID_AMBIGUOUS");
    }
    Ok(values[0].into())
}

pub(super) fn prepare_runtime_logs(root: &Path) -> Result<(), &'static str> {
    let sid = controller_reader_sid()?;
    // Non-inheriting READ on public metadata only. Private key ACL remains
    // SYSTEM-only; generic NetworkService/runner receives no secret access.
    run_icacls(
        &root.join("native-host"),
        &["/grant:r", &format!("*{sid}:RX"), "/Q"],
    )
    .map_err(|_| "HOST_WINDOWS_RUNTIME_PUBLIC_CONTEXT_ACL_UNPROVEN")?;
    run_icacls(
        &root.join("native-host/receipt-public-key.bin"),
        &["/grant:r", &format!("*{sid}:R"), "/Q"],
    )
    .map_err(|_| "HOST_WINDOWS_RUNTIME_PUBLIC_IDENTITY_ACL_UNPROVEN")?;
    for name in ["sing-box.stdout.log", "sing-box.stderr.log"] {
        let path = root.join("runtime").join(name);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| "HOST_WINDOWS_RUNTIME_LOG_UNAVAILABLE")?;
        let meta = file
            .metadata()
            .map_err(|_| "HOST_WINDOWS_RUNTIME_LOG_UNAVAILABLE")?;
        use std::os::windows::fs::MetadataExt;
        if !meta.is_file() || meta.file_attributes() & 0x400 != 0 {
            return Err("HOST_WINDOWS_RUNTIME_LOG_UNTRUSTED");
        }
        harden_system_authority_path_for_reader(&path, false, false, &sid)
            .map_err(|_| "HOST_WINDOWS_RUNTIME_LOG_ACL_UNPROVEN")?;
        run_icacls(&path, &["/grant:r", &format!("*{sid}:(R,W)"), "/Q"])
            .map_err(|_| "HOST_WINDOWS_RUNTIME_LOG_ACL_UNPROVEN")?;
    }
    Ok(())
}
