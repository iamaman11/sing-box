//! Single first-use Windows installation: the same protected application,
//! existing stopped SCM service and exactly ONE LocalSystem dispatcher task.
//! No runner shell authority, SSH, extra daemon, network/TUN side effects or
//! separate journal. The existing typed receipt marker is BEGIN before SCM.
use super::*;
use edge_shared_types::host_journal::require_windows_local_administrator_first_use;
use std::path::Path;

pub(super) fn install(install_root: &Path) -> Result<(), String> {
    require_windows_local_administrator_first_use().map_err(str::to_owned)?;
    if install_root != Path::new(r"C:\sing-box") {
        return Err("HOST_WINDOWS_CLEAN_INSTALL_ROOT_INVALID".into());
    }
    require_exact_immutable_activation_console(install_root)?;
    let active = load_verified_activation(install_root).map_err(|e| e.to_string())?;
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32 {
        return Err("HOST_WINDOWS_CLEAN_INSTALL_PROXY_ONLY_REQUIRED".into());
    }
    // The exact native doctor can report a missing SCM while still proving
    // immutable binaries and absence of sing-box processes or managed TUN.
    let output = Command::new(&active.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "HOST_WINDOWS_CLEAN_INSTALL_DOCTOR_UNAVAILABLE")?;
    let doctor = String::from_utf8_lossy(&output.stdout);
    verify_clean_prestate(&doctor, &active.release_set_sha256)?;
    windows_receipt_enrollment::preflight_fresh_identity_slot(install_root)?;
    // Enumerate task scheduler successfully before treating absence as proven.
    // schtasks /Query exit=1 is ambiguous (missing task vs access/transport
    // failure), and would authorize an unsafe first-use BEGIN on uncertainty.
    // We independently enumerate ALL visible tasks before /Create (without /F);
    // an enumeration error is a hard denial, never interpreted as 'not found'.
    let task_absence_proof = r#"
$ErrorActionPreference = 'Stop'
$all = @(Get-ScheduledTask -ErrorAction Stop)
if (@($all | Where-Object { $_.TaskName -ceq 'EdgePlatformPrivilegedDispatch' }).Count -ne 0) {
    throw 'HOST_WINDOWS_CLEAN_INSTALL_TASK_ALREADY_EXISTS'
}
# A pre-existing Windows SCM owner must not become an uncertain create
# *after* the first durable marker. CIM errors deny, not mean "absent".
$controller = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='EdgePlatformController'" -ErrorAction Stop)
if ($controller.Count -ne 0) {
    throw 'HOST_WINDOWS_CLEAN_INSTALL_SCM_ALREADY_EXISTS'
}
"#;
    let task_absence = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            task_absence_proof,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "HOST_WINDOWS_CLEAN_INSTALL_TASK_QUERY_UNAVAILABLE")?;
    if !task_absence.success() {
        return Err("HOST_WINDOWS_CLEAN_INSTALL_TASK_ABSENCE_UNPROVEN".into());
    }
    // First durable effect is the SAME protected typed receipt identity
    // marker, after provisioning its existing ACL-verified native journal.
    converge_native_host_acl(install_root)?;
    windows_receipt_enrollment::prepare_clean_before_scm(install_root)?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|_| "HOST_WINDOWS_CLEAN_INSTALL_SCM_UNAVAILABLE")?;
    let info = ServiceInfo {
        name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(&active.controller_path),
        launch_arguments: vec![
            OsString::from("windows-service"),
            install_root.as_os_str().to_owned(),
            OsString::from(INSTALLED_CONTROLLER_ADDR),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)),
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|_| "HOST_WINDOWS_CLEAN_INSTALL_SCM_CREATE_UNCERTAIN_NO_REPLAY")?;
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .map_err(|_| "HOST_WINDOWS_CLEAN_INSTALL_SERVICE_SID_UNCERTAIN_NO_REPLAY")?;
    converge_application_acl(install_root)?;
    // The new SYSTEM task must never execute a binary under a user-writable
    // installation root, even if native-host/journal themselves are protected.
    converge_windows_system_authority_acl(install_root, Path::new(&active.console_path))?;
    let state = service
        .query_status()
        .map_err(|_| "HOST_WINDOWS_CLEAN_INSTALL_SCM_STATE_UNAVAILABLE")?;
    if state.current_state != ServiceState::Stopped || state.process_id.is_some() {
        return Err("HOST_WINDOWS_CLEAN_INSTALL_SCM_NOT_STOPPED_NO_REPLAY".into());
    }
    let action = format!(
        "\"{}\" privileged-dispatch --install-root \"{}\"",
        active.console_path,
        install_root.display(),
    );
    let task = Command::new("schtasks.exe")
        .args([
            "/Create",
            "/TN",
            PRIVILEGED_TASK_NAME,
            "/TR",
            &action,
            "/SC",
            "MINUTE",
            "/MO",
            "1",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "HOST_WINDOWS_CLEAN_INSTALL_TASK_CREATE_UNCERTAIN_NO_REPLAY")?;
    if !task.success() {
        return Err("HOST_WINDOWS_CLEAN_INSTALL_TASK_CREATE_UNCERTAIN_NO_REPLAY".into());
    }
    // Exact postcondition is stronger than task-registration exit status.
    require_offline_windows_owner(install_root, &active)?;
    verify_offline_bootstrap_dispatcher(&active.console_path, "Ready")?;
    windows_trust_enrollment::prepare_pending(install_root)?;
    println!("windows_clean_install=SYSTEM_OWNER_AND_TYPED_INTENTS_DURABLE");
    println!("controller_service=STOPPED_ONDEMAND");
    println!("system_task=EXACT_EXISTING_OWNER");
    println!("network_mutations=0");
    Ok(())
}

/// Pure read-only pre-BEGIN admission: no nonexistent SCM state is mistaken
/// for proof that the immutable release, process inventory or no-TUN is safe.
fn verify_clean_prestate(doctor: &str, release: &str) -> Result<(), String> {
    for required in [
        format!("release_set_sha256={release}"),
        "exact_release_files=PASS".to_owned(),
        "windows_datapath_mode=ProxyOnly".to_owned(),
        "managed_tun_present=false".to_owned(),
        "managed_singbox_process_count=0".to_owned(),
        "orphan_singbox_process_count=0".to_owned(),
        "conflicting_singbox_process_count=0".to_owned(),
        "unknown_singbox_process_count=0".to_owned(),
    ] {
        if doctor
            .lines()
            .filter(|line| line.trim() == required)
            .count()
            != 1
        {
            return Err("HOST_WINDOWS_CLEAN_INSTALL_NATIVE_PRESTATE_UNPROVEN".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_install_never_treats_unknown_process_or_tun_as_absent() {
        let release = "a".repeat(64);
        let doctor = format!(
            "release_set_sha256={release}\nexact_release_files=PASS\nwindows_datapath_mode=ProxyOnly\nmanaged_tun_present=false\nmanaged_singbox_process_count=0\norphan_singbox_process_count=0\nconflicting_singbox_process_count=0\nunknown_singbox_process_count=0\n"
        );
        assert!(verify_clean_prestate(&doctor, &release).is_ok());
        assert!(verify_clean_prestate(&doctor, &"b".repeat(64)).is_err());
        assert!(
            verify_clean_prestate(
                &doctor.replace("managed_tun_present=false", "managed_tun_present=true"),
                &release
            )
            .is_err()
        );
        assert!(
            verify_clean_prestate(
                &doctor.replace(
                    "unknown_singbox_process_count=0",
                    "unknown_singbox_process_count=1"
                ),
                &release
            )
            .is_err()
        );
        assert!(verify_clean_prestate(&format!("{doctor}{doctor}"), &release).is_err());
    }
}
