#![cfg(windows)]

use std::ffi::OsString;
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_service::service::{
    Service, ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceSidType, ServiceStartType,
    ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "EdgePlatformController";
const SERVICE_ACCOUNT: &str = r"NT SERVICE\EdgePlatformController";

struct ServiceGuard {
    service: Service,
    root: PathBuf,
}

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        if let Ok(status) = self.service.query_status()
            && status.current_state != ServiceState::Stopped
        {
            let _ = self.service.stop();
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(10) {
                if self
                    .service
                    .query_status()
                    .is_ok_and(|status| status.current_state == ServiceState::Stopped)
                {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        let _ = self.service.delete();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback test port");
    let addr = listener.local_addr().expect("resolve loopback test port");
    drop(listener);
    addr
}

fn wait_for_state(service: &Service, expected: ServiceState, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if service
            .query_status()
            .is_ok_and(|status| status.current_state == expected)
        {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_for_listener(addr: SocketAddr, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn grant_service_access(root: &Path) {
    let principal = format!(r"{SERVICE_ACCOUNT}:(OI)(CI)M");
    let status = Command::new("icacls.exe")
        .arg(root)
        .args(["/grant:r", &principal, "/T", "/Q"])
        .status()
        .expect("start icacls for SCM lifecycle test");
    assert!(status.success(), "grant virtual service account access");
}

#[test]
fn scm_owned_controller_survives_start_caller_exit_and_keeps_listener() {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .expect("open SCM");

    assert!(
        manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .is_err(),
        "{SERVICE_NAME} unexpectedly exists on the disposable hosted runner"
    );

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("edge-controller-scm-{unique}"));
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create SCM test root");

    let source = PathBuf::from(env!("CARGO_BIN_EXE_edge-controller"));
    let controller = bin_dir.join("edge-controller.exe");
    fs::copy(&source, &controller).expect("copy exact controller under SCM test root");

    let addr = free_loopback_addr();
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: controller,
        launch_arguments: vec![
            OsString::from("windows-service"),
            root.as_os_str().to_owned(),
            OsString::from(addr.to_string()),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(SERVICE_ACCOUNT)),
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::DELETE;
    let service = manager
        .create_service(&service_info, access)
        .expect("create disposable controller service");
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .expect("enable controller service SID");
    grant_service_access(&root);
    let guard = ServiceGuard { service, root };

    let start = Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .status()
        .expect("start service through disposable caller");
    assert!(start.success(), "sc.exe failed to start {SERVICE_NAME}");
    assert!(
        wait_for_state(
            &guard.service,
            ServiceState::Running,
            Duration::from_secs(15)
        ),
        "service did not report Running: {:?}",
        guard.service.query_status()
    );
    assert!(
        wait_for_listener(addr, Duration::from_secs(15)),
        "service never opened {addr}: {:?}",
        guard.service.query_status()
    );

    let first = guard
        .service
        .query_status()
        .expect("query initial ready service");
    let first_pid = first.process_id.expect("running service process id");

    // sc.exe has already exited. Keep the service isolated from its start caller and
    // prove that readiness is durable rather than a transient TCP observation.
    thread::sleep(Duration::from_secs(12));

    let stable = guard.service.query_status().expect("query stable service");
    assert_eq!(
        stable.current_state,
        ServiceState::Running,
        "service exited after initial readiness: {stable:?}"
    );
    assert_eq!(
        stable.process_id,
        Some(first_pid),
        "SCM replaced the controller process after initial readiness: {stable:?}"
    );
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok(),
        "service lost listener {addr} after initial readiness: {stable:?}"
    );
}
