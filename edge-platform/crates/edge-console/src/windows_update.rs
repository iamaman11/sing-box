//! Signed stopped-owner update using the ONE canonical release installer.
//! No ConnectWindows/first-use, no key creation, no retry or compensation.
use super::*;
use edge_shared_types::{FleetNativeAdminRequest, FleetNativeTrustSnapshot, ReleaseSet};
use prost::Message;

pub(super) struct Update {
    revision: String,
    target: String,
    installer: Vec<u8>,
}
pub(super) async fn prepare(release_pb: &[u8]) -> Result<Update, String> {
    let release =
        ReleaseSet::decode(release_pb).map_err(|_| "HOST_WINDOWS_UPDATE_RELEASE_INVALID")?;
    let target: String = windows_admin::process::sha(release_pb)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "HOST_WINDOWS_UPDATE_TLS_UNAVAILABLE")?;
    let base = "https://api.github.com/repos/iamaman11/sing-box";
    let main_url = format!("{base}/branches/main");
    let release_url = format!("{base}/releases/tags/edge-release-{target}");
    let (main, published) = tokio::try_join!(
        windows_trust_enrollment::fetch_json(&client, &main_url),
        windows_trust_enrollment::fetch_json(&client, &release_url),
    )?;
    let revision = main["commit"]["sha"]
        .as_str()
        .ok_or("HOST_WINDOWS_UPDATE_MAIN_MISSING")?;
    if main["protected"] != true
        || published["target_commitish"].as_str() != Some(revision)
        || published["draft"] != false
        || published["prerelease"] != false
        || release.source_revision.len() != 40
        || !release
            .source_revision
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("HOST_WINDOWS_UPDATE_MAIN_RELEASE_CHANGED".into());
    }
    // current_authority already proved this ReleaseSet's accepted source tree.
    // Fetch immutable canonical source, never the mutable local bootstrap copy.
    let source = format!(
        "https://raw.githubusercontent.com/iamaman11/sing-box/{}/edge-platform/scripts/install-windows-release.ps1",
        release.source_revision
    );
    let installer = windows_trust_enrollment::fetch_bounded(&client, &source, 262144).await?;
    Ok(Update {
        revision: revision.into(),
        target,
        installer,
    })
}

pub(super) fn preflight(root: &Path) -> Result<WindowsActivationState, &'static str> {
    let before =
        load_verified_activation(root).map_err(|_| "HOST_WINDOWS_UPDATE_INSTALLED_UNPROVEN")?;
    require_offline_windows_owner(root, &before)
        .map_err(|_| "HOST_WINDOWS_UPDATE_STOPPED_OWNER_REQUIRED")?;
    verify_offline_bootstrap_dispatcher(&before.console_path, "Running")
        .map_err(|_| "HOST_WINDOWS_UPDATE_TASK_IDENTITY_UNPROVEN")?;
    for name in [
        "current.pb.new",
        "previous.pb.new",
        "offline-recovery-proof.pb",
        "exchange/requests/request.pb",
        "exchange/requests/admin-request.pb",
        "native-host/receipt-enrollment.pb",
        "native-host/trust-enrollment.pb",
        "native-host/trust.pb.new",
    ] {
        if fs::symlink_metadata(root.join(name)).is_ok() {
            return Err("HOST_WINDOWS_UPDATE_CONFLICTING_OPERATION");
        }
    }
    for name in [
        "receipt-enrollment.completed.pb",
        "trust-enrollment.completed.pb",
    ] {
        let p = root.join("native-host").join(name);
        edge_shared_types::host_journal::verify_windows_protected_path_acl(&p, true)?;
        windows_signed_host::bounded_regular_file(&p, 512)?;
    }
    Ok(before)
}

pub(super) fn apply(
    root: &Path,
    update: &Update,
    trust: &FleetNativeTrustSnapshot,
    operation: &str,
) -> Result<(), &'static str> {
    let before = preflight(root)?;
    if before.release_set_sha256 == update.target {
        return Err("HOST_WINDOWS_UPDATE_SAME_RELEASE_NOT_AN_UPDATE");
    }
    let credentials = edge_secrets::observe_credential_safety(
        &windows_credential_store_path(root),
        edge_shared_types::CredentialProjectionKind::Windows,
    );
    if credentials.cursor_present.is_none() {
        return Err("HOST_WINDOWS_UPDATE_CREDENTIAL_BASELINE_UNPROVEN");
    }
    let public_before = windows_signed_host::bounded_regular_file(
        &root.join("native-host/receipt-public-key.bin"),
        32,
    )?;
    let journal = root.join("native-host/journal");
    let id: String = windows_admin::process::sha(operation.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let script = journal.join(format!("update-{id}.installer.ps1"));
    windows_admin::create(&script, &update.installer)
        .map_err(|_| "HOST_WINDOWS_UPDATE_INSTALLER_STAGE_UNKNOWN_NO_REPLAY")?;
    let shell = find_powershell_7()?;
    let req = FleetNativeAdminRequest {
        schema_version: 1,
        machine_id: trust.machine_id.clone(),
        source_comment_id: 1,
        release_set_sha256: windows_admin::process::sha(&trust.release_set_pb),
        comment_sha256: vec![1; 32],
        requested_at_unix: 1,
        argv: vec![
            shell,
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-File".into(),
            script.to_string_lossy().into_owned(),
            "-AcceptedRevision".into(),
            update.revision.clone(),
            "-ReleaseSetSha256".into(),
            update.target.clone(),
            "-InstallRoot".into(),
            root.to_string_lossy().into_owned(),
            "-Offline".into(),
        ],
        timeout_seconds: 900,
        ..Default::default()
    };
    let capture = |suffix: &str| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(journal.join(format!("update-{id}.{suffix}.bin")))
            .map_err(|_| "HOST_WINDOWS_UPDATE_CAPTURE_UNAVAILABLE_NO_REPLAY")
    };
    let output = windows_admin::process::run(&req, capture("stdout")?, capture("stderr")?)?;
    if output.exit_code != 0 || !output.stdout_stream_eof || !output.stderr_stream_eof {
        eprintln!("HOST_WINDOWS_UPDATE_INSTALLER_EXIT={}", output.exit_code);
        return Err("HOST_WINDOWS_UPDATE_INSTALLER_UNKNOWN_NO_REPLAY");
    }
    let after = load_verified_activation(root)
        .map_err(|_| "HOST_WINDOWS_UPDATE_POST_ACTIVATION_UNPROVEN")?;
    if after.release_set_sha256 != update.target {
        return Err("HOST_WINDOWS_UPDATE_TARGET_NOT_ACTIVE");
    }
    let previous = load_verified_activation_path(root, &root.join("previous.pb"), "previous.pb")
        .map_err(|_| "HOST_WINDOWS_UPDATE_PREVIOUS_UNPROVEN")?;
    if previous != before {
        return Err("HOST_WINDOWS_UPDATE_PREVIOUS_CHANGED");
    }
    // No start/stop, no implicit rollback. Retarget only the existing owners.
    offline_retarget_controller_service(root, &before, &after)
        .map_err(|_| "HOST_WINDOWS_UPDATE_SCM_RETARGET_UNPROVEN")?;
    converge_native_host_acl(root).map_err(|_| "HOST_WINDOWS_UPDATE_NATIVE_ACL_UNPROVEN")?;
    converge_windows_system_authority_acl(root, Path::new(&after.console_path))
        .map_err(|_| "HOST_WINDOWS_UPDATE_RELEASE_ACL_UNPROVEN")?;
    retarget_privileged_task(root, &after.console_path)
        .map_err(|_| "HOST_WINDOWS_UPDATE_TASK_RETARGET_UNPROVEN")?;
    // Preserve the exact identity and history; replace only Git-derived trust
    // after the new immutable activation has independently verified.
    windows_admin::replace(&root.join("native-host/trust.pb"), &trust.encode_to_vec())
        .map_err(|_| "HOST_WINDOWS_UPDATE_TRUST_HANDOFF_UNCERTAIN")?;
    require_offline_windows_owner(root, &after)
        .map_err(|_| "HOST_WINDOWS_UPDATE_POST_OWNER_UNPROVEN")?;
    if edge_secrets::observe_credential_safety(
        &windows_credential_store_path(root),
        edge_shared_types::CredentialProjectionKind::Windows,
    ) != credentials
    {
        return Err("HOST_WINDOWS_UPDATE_CREDENTIAL_GENERATIONS_CHANGED");
    }
    let public_after = windows_signed_host::bounded_regular_file(
        &root.join("native-host/receipt-public-key.bin"),
        32,
    )?;
    if public_after != public_before {
        return Err("HOST_WINDOWS_UPDATE_RECEIPT_IDENTITY_CHANGED");
    }
    let private_path = root.join("native-host/receipt-key.pk8");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&private_path, true)?;
    let private = windows_signed_host::bounded_regular_file(&private_path, 4096)?;
    let registry = edge_shared_types::decode_host_registry(&trust.registry_pb)
        .map_err(|_| "HOST_WINDOWS_UPDATE_REGISTRY_INVALID")?;
    let host = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == trust.machine_id)
        .ok_or("HOST_WINDOWS_UPDATE_HOST_UNREGISTERED")?;
    edge_shared_types::host_receipt::check_native_receipt_key(host, &private)?;
    verify_offline_bootstrap_dispatcher(&after.console_path, "Running")
        .map_err(|_| "HOST_WINDOWS_UPDATE_TASK_POSTSTATE_UNPROVEN")?;
    Ok(())
}

fn find_powershell_7() -> Result<String, &'static str> {
    // Never search ambient PATH as SYSTEM. The supported machine install
    // must have a kernel-verified non-reparse, privileged-owned ACL chain.
    let p = Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe");
    edge_shared_types::host_journal::verify_windows_system_executable_acl(p)
        .map_err(|_| "HOST_WINDOWS_UPDATE_PROTECTED_POWERSHELL_7_REQUIRED")?;
    Ok(p.to_string_lossy().into_owned())
}
