use std::env;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::{
    BootstrapMode, BootstrapRuntimeRequest, BootstrapRuntimeResponse, ControllerStatus,
    DeployRequest, DeployResponse, DestroyRequest, DestroyResponse, DoctorRequest, DoctorResponse,
    Empty, GetOperationRequest, GetSecretRefRequest, GetSelectorStateRequest, GetTraceRequest,
    ListOperationEventsRequest, ListSecretRefsRequest, LocalRuntimeResponse, OperationStatus,
    RestartLocalRuntimeRequest, SecretRefEntry, SelectorState, SetSecretRefRequest,
    SetSelectorRequest, SetSelectorResponse, StartLocalRuntimeRequest, StopLocalRuntimeRequest,
    TraceObservation, UbuntuProxyState,
};
use tonic::Request;
use tonic::transport::Channel;

const DEFAULT_CONTROLLER_ENDPOINT: &str = "http://127.0.0.1:50051";
const DEFAULT_CONTROLLER_ADDR: &str = "127.0.0.1:50051";
const MAX_CONTROLLER_SERVICE_LOG_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_DNS_RECORD: &str = "edge.alegria.by";
const DEFAULT_CLOUDFLARE_ZONE: &str = "alegria.by";
const DEFAULT_ACME_EMAIL: &str = "admin@alegria.by";
const DEFAULT_VULTR_SNAPSHOT_ID: &str = "61605612-d7a2-47b1-85ef-aef90f5083df";
const DESKTOP_SELECTOR_GROUP: &str = "proxy-selector";
const UBUNTU_SELECTOR_GROUP: &str = "wsl-selector";
const DEPLOY_ENDPOINT_ARG_INDEX: usize = 10;
const DESTROY_ENDPOINT_ARG_INDEX: usize = 6;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = env::args().nth(1).unwrap_or_else(|| "menu".to_owned());

    match command.as_str() {
        "menu" => run_menu(controller_endpoint_from_args(2)).await,
        "status" => {
            let status = fetch_status(controller_endpoint_from_args(2)).await?;
            print_status(&status);
            Ok(())
        }
        "doctor" => {
            let doctor = fetch_doctor(controller_endpoint_from_args(2)).await?;
            print_doctor(&doctor);
            if doctor.ok {
                Ok(())
            } else {
                Err("doctor reported failing checks".into())
            }
        }
        "secrets" => {
            let secrets = list_secret_refs(controller_endpoint_from_args(2)).await?;
            print_secret_refs(&secrets);
            Ok(())
        }
        "get-secret" => {
            let name = env::args()
                .nth(2)
                .ok_or("get-secret requires a secret name")?;
            let entry = get_secret_ref(controller_endpoint_from_args(3), &name).await?;
            print_secret_ref(&entry);
            Ok(())
        }
        "set-secret" => {
            let name = env::args()
                .nth(2)
                .ok_or("set-secret requires a secret name")?;
            let secret_ref = env::args()
                .nth(3)
                .ok_or("set-secret requires a secret reference")?;
            let entry =
                set_secret_ref(controller_endpoint_from_args(4), &name, &secret_ref).await?;
            print_secret_ref(&entry);
            Ok(())
        }
        "start-local" => {
            let response = start_local(controller_endpoint_from_args(2)).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)
        }
        "start-local-visible" => {
            let response = start_local_visible(controller_endpoint_from_args(2)).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)
        }
        "stop-local" => {
            let response = stop_local(controller_endpoint_from_args(2)).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)
        }
        "restart-local" => {
            let response = restart_local(controller_endpoint_from_args(2)).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)
        }
        "restart-local-visible" => {
            let response = restart_local_visible(controller_endpoint_from_args(2)).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)
        }
        "get-selector" => {
            let selector =
                fetch_selector_state(controller_endpoint_from_args(2), DESKTOP_SELECTOR_GROUP)
                    .await?;
            print_selector_state(&selector);
            Ok(())
        }
        "get-ubuntu-selector" => {
            let selector =
                fetch_selector_state(controller_endpoint_from_args(2), UBUNTU_SELECTOR_GROUP)
                    .await?;
            print_selector_state_with_label("Ubuntu selector", &selector);
            Ok(())
        }
        "set-selector" => {
            let name = env::args()
                .nth(2)
                .ok_or("set-selector requires a selector target name")?;
            let response = set_selector(
                controller_endpoint_from_args(3),
                DESKTOP_SELECTOR_GROUP,
                &name,
            )
            .await?;
            print_set_selector_result(&response);
            finish_selector_result(response)
        }
        "set-ubuntu-selector" => {
            let name = env::args()
                .nth(2)
                .ok_or("set-ubuntu-selector requires a selector target name")?;
            let response = set_selector(
                controller_endpoint_from_args(3),
                UBUNTU_SELECTOR_GROUP,
                &name,
            )
            .await?;
            print_set_selector_result(&response);
            finish_selector_result(response)
        }
        "trace" => {
            let trace = fetch_trace(controller_endpoint_from_args(2)).await?;
            print_trace(&trace);
            Ok(())
        }
        "trace-ubuntu" => {
            let status = fetch_status(controller_endpoint_from_args(2)).await?;
            let proxy_url = ubuntu_proxy_url_from_status(&status)
                .ok_or("ubuntu proxy endpoint is not available in controller status")?;
            let trace =
                fetch_trace_with_proxy(controller_endpoint_from_args(2), Some(proxy_url)).await?;
            print_trace_with_label("Ubuntu egress IP", &trace);
            Ok(())
        }
        "bootstrap-base" => {
            let response = bootstrap_runtime(
                controller_endpoint_from_args(2),
                BootstrapMode::BootstrapBase,
            )
            .await?;
            print_bootstrap_result(&response);
            finish_bootstrap_result(response)
        }
        "bootstrap-tunnel" => {
            let response = bootstrap_runtime(
                controller_endpoint_from_args(2),
                BootstrapMode::BootstrapTunnel,
            )
            .await?;
            print_bootstrap_result(&response);
            finish_bootstrap_result(response)
        }
        "deploy" => {
            let request = deploy_request_from_args();
            let response = deploy(
                controller_endpoint_from_args(DEPLOY_ENDPOINT_ARG_INDEX),
                request,
            )
            .await?;
            print_deploy_result(&response);
            finish_deploy_result(response)
        }
        "destroy" => {
            let request = destroy_request_from_args();
            let response = destroy(
                controller_endpoint_from_args(DESTROY_ENDPOINT_ARG_INDEX),
                request,
            )
            .await?;
            print_destroy_result(&response);
            finish_destroy_result(response)
        }
        "get-operation" => {
            let operation_id = env::args()
                .nth(2)
                .ok_or("get-operation requires an operation id")?
                .parse::<i64>()?;
            let status = get_operation(controller_endpoint_from_args(3), operation_id).await?;
            print_operation_status(&status);
            Ok(())
        }
        "watch-operation" => {
            let operation_id = env::args()
                .nth(2)
                .ok_or("watch-operation requires an operation id")?
                .parse::<i64>()?;
            let endpoint = controller_endpoint_from_args(3);
            watch_operation(endpoint, operation_id).await
        }
        other => Err(format!("unsupported command: {other}").into()),
    }
}

async fn run_menu(controller_endpoint: String) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!();
        println!("Edge Console");
        println!("1. Status");
        println!("2. Direct tunnel -> auto");
        println!("3. Direct tunnel -> hysteria2");
        println!("4. Direct tunnel -> vless");
        println!("5. WARP tunnel -> auto");
        println!("6. WARP tunnel -> hysteria2");
        println!("7. WARP tunnel -> vless");
        println!("8. Ubuntu tunnel -> auto direct");
        println!("9. Ubuntu tunnel -> hysteria2 direct");
        println!("10. Ubuntu tunnel -> vless direct");
        println!("11. Ubuntu tunnel -> auto warp");
        println!("12. Ubuntu tunnel -> hysteria2 warp");
        println!("13. Ubuntu tunnel -> vless warp");
        println!("14. Show current Ubuntu tunnel");
        println!("15. Show current Ubuntu egress IP");
        println!("16. Show current desktop IP");
        println!("17. Start sing-box (visible window)");
        println!("18. Stop sing-box");
        println!("19. Restart sing-box (visible window)");
        println!("20. Bootstrap base runtime (internal)");
        println!("21. Bootstrap tunnel runtime (internal)");
        println!("22. Create VM from snapshot");
        println!("23. Delete current VM");
        println!("24. List configured secrets");
        println!("25. Show operation");
        println!("26. Watch operation");
        println!("27. Doctor");
        println!("0. Exit");
        print!("Select: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                let status = fetch_status(controller_endpoint.clone()).await?;
                print_status(&status);
            }
            "2" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    DESKTOP_SELECTOR_GROUP,
                    "auto-direct-tunnel",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "3" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    DESKTOP_SELECTOR_GROUP,
                    "hysteria2-direct",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "4" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    DESKTOP_SELECTOR_GROUP,
                    "vless-reality-direct",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "5" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    DESKTOP_SELECTOR_GROUP,
                    "auto-warp-tunnel",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "6" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    DESKTOP_SELECTOR_GROUP,
                    "hysteria2-warp",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "7" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    DESKTOP_SELECTOR_GROUP,
                    "vless-reality-warp",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "8" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    UBUNTU_SELECTOR_GROUP,
                    "auto-direct-tunnel",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "9" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    UBUNTU_SELECTOR_GROUP,
                    "hysteria2-direct",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "10" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    UBUNTU_SELECTOR_GROUP,
                    "vless-reality-direct",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "11" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    UBUNTU_SELECTOR_GROUP,
                    "auto-warp-tunnel",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "12" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    UBUNTU_SELECTOR_GROUP,
                    "hysteria2-warp",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "13" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    UBUNTU_SELECTOR_GROUP,
                    "vless-reality-warp",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "14" => {
                let selector =
                    fetch_selector_state(controller_endpoint.clone(), UBUNTU_SELECTOR_GROUP)
                        .await?;
                print_selector_state_with_label("Ubuntu selector", &selector);
            }
            "15" => {
                let status = fetch_status(controller_endpoint.clone()).await?;
                let proxy_url = ubuntu_proxy_url_from_status(&status)
                    .ok_or("ubuntu proxy endpoint is not available in controller status")?;
                let trace =
                    fetch_trace_with_proxy(controller_endpoint.clone(), Some(proxy_url)).await?;
                print_trace_with_label("Ubuntu egress IP", &trace);
            }
            "16" => {
                let trace = fetch_trace(controller_endpoint.clone()).await?;
                print_trace(&trace);
            }
            "17" => {
                let response = start_local_visible(controller_endpoint.clone()).await?;
                print_local_runtime_result(&response);
            }
            "18" => {
                let response = stop_local(controller_endpoint.clone()).await?;
                print_local_runtime_result(&response);
            }
            "19" => {
                let response = restart_local_visible(controller_endpoint.clone()).await?;
                print_local_runtime_result(&response);
            }
            "20" => {
                let response =
                    bootstrap_runtime(controller_endpoint.clone(), BootstrapMode::BootstrapBase)
                        .await?;
                print_bootstrap_result(&response);
            }
            "21" => {
                let response =
                    bootstrap_runtime(controller_endpoint.clone(), BootstrapMode::BootstrapTunnel)
                        .await?;
                print_bootstrap_result(&response);
            }
            "22" => {
                let response = deploy(
                    controller_endpoint.clone(),
                    DeployRequest {
                        label_prefix: Some("waw-edge".to_owned()),
                        target_ip: None,
                        instance_id: None,
                        tunnel_domain: Some(DEFAULT_DNS_RECORD.to_owned()),
                        acme_email: Some(DEFAULT_ACME_EMAIL.to_owned()),
                        dns_record_name: Some(DEFAULT_DNS_RECORD.to_owned()),
                        cloudflare_zone_name: Some(DEFAULT_CLOUDFLARE_ZONE.to_owned()),
                        mock_provider: false,
                        skip_dns: false,
                        snapshot_id: Some(DEFAULT_VULTR_SNAPSHOT_ID.to_owned()),
                    },
                )
                .await?;
                print_deploy_result(&response);
            }
            "23" => {
                let response = destroy(
                    controller_endpoint.clone(),
                    DestroyRequest {
                        instance_id: None,
                        target_ip: None,
                        dns_record_name: Some(DEFAULT_DNS_RECORD.to_owned()),
                        cloudflare_zone_name: Some(DEFAULT_CLOUDFLARE_ZONE.to_owned()),
                        mock_provider: false,
                        delete_dns: true,
                        delete_instance: true,
                    },
                )
                .await?;
                print_destroy_result(&response);
            }
            "24" => {
                let secrets = list_secret_refs(controller_endpoint.clone()).await?;
                print_secret_refs(&secrets);
            }
            "25" => {
                let operation_id = prompt("Operation id")?;
                let status =
                    get_operation(controller_endpoint.clone(), operation_id.parse()?).await?;
                print_operation_status(&status);
            }
            "26" => {
                let operation_id = prompt("Operation id")?;
                watch_operation(controller_endpoint.clone(), operation_id.parse()?).await?;
            }
            "27" => {
                let doctor = fetch_doctor(controller_endpoint.clone()).await?;
                print_doctor(&doctor);
            }
            "0" => return Ok(()),
            _ => println!("Unknown option"),
        }
    }
}

fn controller_endpoint_from_args(index: usize) -> String {
    env::args()
        .nth(index)
        .or_else(|| env::var("EDGE_CONTROLLER_ENDPOINT").ok())
        .unwrap_or_else(|| DEFAULT_CONTROLLER_ENDPOINT.to_owned())
}

fn optional_arg(index: usize) -> Option<String> {
    env::args().nth(index).and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn looks_like_repo_root(path: &Path) -> bool {
    path.join("edge-platform").join("Cargo.toml").is_file()
        || (path.join("Cargo.toml").is_file() && path.join("crates").is_dir())
}

fn resolve_repo_root_for_controller() -> Option<PathBuf> {
    if let Ok(value) = env::var("EDGE_PLATFORM_REPO_ROOT") {
        let path = PathBuf::from(value);
        if looks_like_repo_root(&path) {
            return Some(path);
        }
    }

    if let Ok(cwd) = env::current_dir() {
        if looks_like_repo_root(&cwd) {
            return Some(cwd);
        }
        if let Some(parent) = cwd.parent()
            && looks_like_repo_root(parent)
        {
            return Some(parent.to_path_buf());
        }
    }

    if let Ok(user_profile) = env::var("USERPROFILE") {
        for candidate in [
            PathBuf::from(&user_profile).join("temp").join("sing-box"),
            PathBuf::from(&user_profile)
                .join("temp")
                .join("sing-box")
                .join("edge-platform"),
            PathBuf::from(&user_profile)
                .join("projects")
                .join("sing-box"),
            PathBuf::from(&user_profile)
                .join("projects")
                .join("sing-box")
                .join("edge-platform"),
        ] {
            if looks_like_repo_root(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

fn controller_binary_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let current = env::current_exe()?;
    let parent = current
        .parent()
        .ok_or("failed to resolve console binary directory")?;
    Ok(parent.join("edge-controller.exe"))
}

fn parse_loopback_addr(endpoint: &str) -> Option<SocketAddr> {
    let value = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    let addr: SocketAddr = value.parse().ok()?;
    if addr.ip().is_loopback() {
        Some(addr)
    } else {
        None
    }
}

fn wait_for_controller(addr: SocketAddr, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(250));
    }
    false
}

fn ensure_controller_running(endpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    let Some(addr) = parse_loopback_addr(endpoint) else {
        return Ok(());
    };
    if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
        return Ok(());
    }

    let controller_binary = controller_binary_path()?;
    let repo_root = resolve_repo_root_for_controller()
        .ok_or("failed to resolve EDGE_PLATFORM_REPO_ROOT for controller autostart")?;
    let runtime_root = if repo_root.join("edge-platform").is_dir() {
        repo_root.join("edge-platform").join(".runtime")
    } else {
        repo_root.join(".runtime")
    };
    std::fs::create_dir_all(&runtime_root)?;
    rotate_service_log_if_needed(
        &runtime_root.join("controller-service-stdout.log"),
        MAX_CONTROLLER_SERVICE_LOG_BYTES,
    )?;
    rotate_service_log_if_needed(
        &runtime_root.join("controller-service-stderr.log"),
        MAX_CONTROLLER_SERVICE_LOG_BYTES,
    )?;

    let stdout = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(runtime_root.join("controller-service-stdout.log"))?;
    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(runtime_root.join("controller-service-stderr.log"))?;

    Command::new(controller_binary)
        .arg("serve")
        .arg(repo_root)
        .arg(DEFAULT_CONTROLLER_ADDR)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;

    if wait_for_controller(addr, Duration::from_secs(10)) {
        Ok(())
    } else {
        Err("edge-controller did not start listening on 127.0.0.1:50051 in time".into())
    }
}

fn rotate_service_log_if_needed(
    path: &Path,
    max_bytes: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    if metadata.len() <= max_bytes {
        return Ok(());
    }
    std::fs::write(path, b"")?;
    Ok(())
}

async fn connect_controller(
    endpoint: String,
) -> Result<ControllerServiceClient<Channel>, Box<dyn std::error::Error>> {
    match ControllerServiceClient::<Channel>::connect(endpoint.clone()).await {
        Ok(client) => Ok(client),
        Err(first_err) => {
            ensure_controller_running(&endpoint)?;
            let mut last_error = None;
            for _ in 0..20 {
                match ControllerServiceClient::<Channel>::connect(endpoint.clone()).await {
                    Ok(client) => return Ok(client),
                    Err(err) => {
                        last_error = Some(err);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            let second_err = last_error
                .map(|err| err.to_string())
                .unwrap_or_else(|| "unknown error".to_owned());
            Err(format!(
                "failed to connect to controller after autostart: first={first_err}; second={second_err}"
            )
            .into())
        }
    }
}

fn deploy_request_from_args() -> DeployRequest {
    DeployRequest {
        label_prefix: optional_arg(2).or_else(|| Some("waw-edge".to_owned())),
        target_ip: optional_arg(3),
        instance_id: optional_arg(4),
        tunnel_domain: optional_arg(5).or_else(|| Some(DEFAULT_DNS_RECORD.to_owned())),
        acme_email: optional_arg(6).or_else(|| Some(DEFAULT_ACME_EMAIL.to_owned())),
        dns_record_name: optional_arg(7).or_else(|| Some(DEFAULT_DNS_RECORD.to_owned())),
        cloudflare_zone_name: optional_arg(8).or_else(|| Some(DEFAULT_CLOUDFLARE_ZONE.to_owned())),
        mock_provider: env::var("EDGE_MOCK_PROVIDER")
            .ok()
            .is_some_and(|value| value == "1"),
        skip_dns: env::var("EDGE_SKIP_DNS")
            .ok()
            .is_some_and(|value| value == "1"),
        snapshot_id: optional_arg(9).or_else(|| Some(DEFAULT_VULTR_SNAPSHOT_ID.to_owned())),
    }
}

fn destroy_request_from_args() -> DestroyRequest {
    DestroyRequest {
        instance_id: optional_arg(2),
        target_ip: optional_arg(3),
        dns_record_name: optional_arg(4),
        cloudflare_zone_name: optional_arg(5),
        mock_provider: env::var("EDGE_MOCK_PROVIDER")
            .ok()
            .is_some_and(|value| value == "1"),
        delete_dns: env::var("EDGE_DELETE_DNS")
            .ok()
            .is_none_or(|value| value == "1"),
        delete_instance: env::var("EDGE_DELETE_INSTANCE")
            .ok()
            .is_none_or(|value| value == "1"),
    }
}

async fn fetch_status(endpoint: String) -> Result<ControllerStatus, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client.get_status(Request::new(Empty {})).await?;
    Ok(response.into_inner())
}

async fn fetch_doctor(endpoint: String) -> Result<DoctorResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .doctor(Request::new(DoctorRequest {
            require_server_ready: true,
            require_local_runtime: true,
            require_egress_traces: true,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn list_secret_refs(
    endpoint: String,
) -> Result<Vec<SecretRefEntry>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .list_secret_refs(Request::new(ListSecretRefsRequest {}))
        .await?;
    Ok(response.into_inner().secrets)
}

async fn get_secret_ref(
    endpoint: String,
    name: &str,
) -> Result<SecretRefEntry, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_secret_ref(Request::new(GetSecretRefRequest {
            name: name.to_owned(),
        }))
        .await?;
    Ok(response.into_inner())
}

async fn set_secret_ref(
    endpoint: String,
    name: &str,
    secret_ref: &str,
) -> Result<SecretRefEntry, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .set_secret_ref(Request::new(SetSecretRefRequest {
            name: name.to_owned(),
            secret_ref: secret_ref.to_owned(),
        }))
        .await?;
    Ok(response.into_inner())
}

async fn bootstrap_runtime(
    endpoint: String,
    mode: BootstrapMode,
) -> Result<BootstrapRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .bootstrap_runtime(Request::new(BootstrapRuntimeRequest { mode: mode as i32 }))
        .await?;
    Ok(response.into_inner())
}

async fn start_local(endpoint: String) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .start_local_runtime(Request::new(StartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            force_restart: false,
            visible_window: false,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn start_local_visible(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .start_local_runtime(Request::new(StartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            force_restart: false,
            visible_window: true,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn stop_local(endpoint: String) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .stop_local_runtime(Request::new(StopLocalRuntimeRequest {
            config_path: None,
            expected_config_only: true,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn restart_local(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .restart_local_runtime(Request::new(RestartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            visible_window: false,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn restart_local_visible(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .restart_local_runtime(Request::new(RestartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            visible_window: true,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn fetch_selector_state(
    endpoint: String,
    group: &str,
) -> Result<SelectorState, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_selector_state(Request::new(GetSelectorStateRequest {
            group: Some(group.to_owned()),
        }))
        .await?;
    Ok(response.into_inner())
}

async fn set_selector(
    endpoint: String,
    group: &str,
    name: &str,
) -> Result<SetSelectorResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .set_selector(Request::new(SetSelectorRequest {
            group: group.to_owned(),
            name: name.to_owned(),
        }))
        .await?;
    Ok(response.into_inner())
}

async fn fetch_trace(endpoint: String) -> Result<TraceObservation, Box<dyn std::error::Error>> {
    fetch_trace_with_proxy(endpoint, None).await
}

async fn fetch_trace_with_proxy(
    endpoint: String,
    proxy_url: Option<String>,
) -> Result<TraceObservation, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_trace(Request::new(GetTraceRequest { proxy_url }))
        .await?;
    Ok(response.into_inner())
}

async fn deploy(
    endpoint: String,
    request: DeployRequest,
) -> Result<DeployResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client.deploy(Request::new(request)).await?;
    Ok(response.into_inner())
}

async fn destroy(
    endpoint: String,
    request: DestroyRequest,
) -> Result<DestroyResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client.destroy(Request::new(request)).await?;
    Ok(response.into_inner())
}

async fn get_operation(
    endpoint: String,
    operation_id: i64,
) -> Result<OperationStatus, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_operation(Request::new(GetOperationRequest { operation_id }))
        .await?;
    Ok(response.into_inner())
}

async fn list_operation_events(
    endpoint: String,
    operation_id: i64,
) -> Result<Vec<edge_shared_types::OperationEvent>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .list_operation_events(Request::new(ListOperationEventsRequest { operation_id }))
        .await?;
    Ok(response.into_inner().events)
}

async fn watch_operation(
    endpoint: String,
    operation_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_event_id = 0_i64;
    loop {
        let status = get_operation(endpoint.clone(), operation_id).await?;
        print_operation_summary(&status);

        let events = list_operation_events(endpoint.clone(), operation_id).await?;
        for event in events {
            if event.id <= last_event_id {
                continue;
            }
            println!("[{}] {}", event.id, event.message);
            last_event_id = event.id;
        }

        let current = status
            .operation
            .as_ref()
            .map(|operation| operation.status)
            .unwrap_or_default();
        if current == edge_shared_types::OperationLifecycleStatus::Succeeded as i32
            || current == edge_shared_types::OperationLifecycleStatus::Failed as i32
        {
            return Ok(());
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn prompt(label: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_owned())
}

fn print_status(status: &ControllerStatus) {
    println!();
    println!("Current status");

    if let Some(local) = &status.local_singbox {
        println!(
            "Local sing-box         : {}",
            if local.process_running {
                "running"
            } else {
                "stopped"
            }
        );
        println!(
            "Local managed config   : {}",
            if local.managed_config { "yes" } else { "no" }
        );
        println!("Expected config path   : {}", local.expected_config_path);
        if let Some(active) = &local.active_config_path {
            println!("Active config path     : {active}");
        }
        if let Some(port) = local.clash_api_port {
            println!("Clash API port         : {port}");
        }
        for warning in &local.warnings {
            println!("Local warning          : {warning}");
        }
    }

    if let Some(deployment) = &status.deployment {
        println!(
            "Live deployment state  : {}",
            if deployment.live_state_present {
                "present"
            } else {
                "missing"
            }
        );
        if let Some(label) = &deployment.deployment_label {
            println!("Deployment label       : {label}");
        }
        if let Some(instance_id) = &deployment.instance_id {
            println!("Instance id            : {instance_id}");
        }
        if let Some(server_ip) = &deployment.server_ip {
            println!("Server IP              : {server_ip}");
        }
        if let Some(tunnel_domain) = &deployment.tunnel_domain {
            println!("Tunnel domain          : {tunnel_domain}");
        }
    }
    println!(
        "App readiness phase    : {}",
        app_readiness_label(status.app_readiness_phase)
    );

    if let Some(runtime) = &status.runtime {
        println!(
            "Edge agent reachable   : {}",
            if runtime.edge_agent_reachable {
                "yes"
            } else {
                "no"
            }
        );
        println!(
            "Compose file present   : {}",
            if runtime.compose_file_present {
                "yes"
            } else {
                "no"
            }
        );
        println!(
            "Docker reachable       : {}",
            if runtime.docker_reachable {
                "yes"
            } else {
                "no"
            }
        );
        if let Some(path) = &runtime.observed_stack_path {
            println!("Observed stack path    : {path}");
        }
        if !runtime.running_containers.is_empty() {
            println!(
                "Running containers     : {}",
                runtime.running_containers.join(", ")
            );
        }
        if !runtime.missing_containers.is_empty() {
            println!(
                "Missing containers     : {}",
                runtime.missing_containers.join(", ")
            );
        }
        if let Some(version) = &runtime.topology_version {
            println!("Topology version       : {version}");
        }
        if let Some(bundle) = &runtime.active_bundle_id {
            println!("Active bundle id       : {bundle}");
        }
        if !runtime.listening_tcp_ports.is_empty() {
            println!(
                "Listening TCP ports    : {}",
                join_ports(&runtime.listening_tcp_ports)
            );
        }
        if !runtime.listening_udp_ports.is_empty() {
            println!(
                "Listening UDP ports    : {}",
                join_ports(&runtime.listening_udp_ports)
            );
        }
        for warning in &runtime.warnings {
            println!("Runtime warning        : {warning}");
        }
    }

    if let Some(selector) = &status.selector {
        print_selector_state_with_label("Desktop selector", selector);
    }

    if let Some(selector) = &status.ubuntu_selector {
        print_selector_state_with_label("Ubuntu selector", selector);
    }

    if let Some(proxy) = &status.ubuntu_proxy {
        print_ubuntu_proxy_state(proxy);
    }

    for note in &status.status_notes {
        println!("Status note            : {note}");
    }
}

fn print_doctor(doctor: &DoctorResponse) {
    println!();
    println!(
        "Doctor verdict         : {}",
        if doctor.ok { "ok" } else { "failed" }
    );
    for check in &doctor.checks {
        println!(
            "{} : {} ({})",
            check.name,
            if check.ok { "ok" } else { "failed" },
            check.detail
        );
    }
    if let Some(trace) = &doctor.desktop_trace {
        print_trace_with_label("Desktop egress", trace);
    }
    if let Some(trace) = &doctor.ubuntu_trace {
        print_trace_with_label("Ubuntu egress", trace);
    }
}

fn print_selector_state(selector: &SelectorState) {
    print_selector_state_with_label("Selector", selector);
}

fn print_selector_state_with_label(label: &str, selector: &SelectorState) {
    println!();
    println!("{label}");
    if let Some(desired) = &selector.desired_main_route {
        println!("Desired route          : {desired}");
    }
    if let Some(observed) = &selector.observed_main_route {
        println!("Observed route         : {observed}");
    }
    println!(
        "Selector degraded      : {}",
        if selector.degraded { "yes" } else { "no" }
    );
    for group in &selector.proxy_groups {
        if let Some(selected) = &group.selected {
            println!("{:<24}: {}", group.name, selected);
        } else {
            println!("{:<24}: unavailable", group.name);
        }
    }
    for warning in &selector.warnings {
        println!("Selector warning       : {warning}");
    }
}

fn print_ubuntu_proxy_state(proxy: &UbuntuProxyState) {
    println!();
    println!("Ubuntu proxy");
    println!(
        "Ubuntu proxy available : {}",
        if proxy.available { "yes" } else { "no" }
    );
    if let Some(host) = &proxy.host {
        println!("Ubuntu proxy host      : {host}");
    }
    if let Some(port) = proxy.port {
        println!("Ubuntu proxy port      : {port}");
    }
    if let Some(url) = &proxy.url {
        println!("Ubuntu proxy URL       : {url}");
    }
    for warning in &proxy.warnings {
        println!("Ubuntu proxy warning   : {warning}");
    }
}

fn print_trace(trace: &TraceObservation) {
    print_trace_with_label("Current tunnel", trace);
}

fn print_trace_with_label(label: &str, trace: &TraceObservation) {
    println!();
    if trace.available {
        if let Some(ip) = &trace.ip {
            println!("{label} IP      : {ip}");
        }
        if let Some(warp) = &trace.warp {
            println!("{label} WARP    : {warp}");
        }
        if let Some(colo) = &trace.colo {
            println!("{label} colo    : {colo}");
        }
    } else {
        println!(
            "{label} note    : {}",
            trace.note.as_deref().unwrap_or("trace unavailable")
        );
    }
}

fn ubuntu_proxy_url_from_status(status: &ControllerStatus) -> Option<String> {
    status
        .ubuntu_proxy
        .as_ref()
        .and_then(|proxy| proxy.url.clone())
}

fn print_bootstrap_result(response: &BootstrapRuntimeResponse) {
    println!();
    println!(
        "Bootstrap mode         : {}",
        bootstrap_mode_label(response.mode)
    );
    println!(
        "Bootstrap success      : {}",
        if response.success { "yes" } else { "no" }
    );
    println!("Exit code              : {}", response.exit_code);
    if !response.warnings.is_empty() {
        for warning in &response.warnings {
            println!("Bootstrap warning      : {warning}");
        }
    }
}

fn app_readiness_label(value: i32) -> &'static str {
    match edge_shared_types::AppReadinessPhase::try_from(value)
        .unwrap_or(edge_shared_types::AppReadinessPhase::Unspecified)
    {
        edge_shared_types::AppReadinessPhase::DeploymentAbsent => "deployment absent",
        edge_shared_types::AppReadinessPhase::ServerRuntimeReady => "server runtime ready",
        edge_shared_types::AppReadinessPhase::LocalRuntimeReady => "local runtime ready",
        edge_shared_types::AppReadinessPhase::SelectorsReady => "selectors ready",
        edge_shared_types::AppReadinessPhase::AppEgressReady => "app egress ready",
        edge_shared_types::AppReadinessPhase::AppReady => "app ready",
        edge_shared_types::AppReadinessPhase::AppReadinessFailed => "app readiness failed",
        edge_shared_types::AppReadinessPhase::Unspecified => "unspecified",
    }
}

fn print_secret_refs(entries: &[SecretRefEntry]) {
    println!();
    println!("Configured secrets");
    for entry in entries {
        println!("{:<32} {}", entry.name, entry.secret_ref);
    }
}

fn print_secret_ref(entry: &SecretRefEntry) {
    println!();
    println!("Secret name           : {}", entry.name);
    println!("Secret reference      : {}", entry.secret_ref);
}

fn print_local_runtime_result(response: &LocalRuntimeResponse) {
    println!();
    println!(
        "Local runtime success  : {}",
        if response.success { "yes" } else { "no" }
    );
    println!("Local runtime note     : {}", response.note);
    if let Some(pid) = response.pid {
        println!("Local runtime PID      : {pid}");
    }
    if let Some(operation) = &response.operation {
        println!("Operation id           : {}", operation.id);
        println!(
            "Operation status       : {}",
            lifecycle_status_label(operation.status)
        );
    }
    for warning in &response.warnings {
        println!("Local runtime warning  : {warning}");
    }
}

fn print_set_selector_result(response: &SetSelectorResponse) {
    println!();
    println!(
        "Selector update        : {}",
        if response.success { "ok" } else { "failed" }
    );
    if let Some(previous) = &response.previous {
        println!("Previous route         : {previous}");
    }
    if let Some(current) = &response.current {
        println!("Current route          : {current}");
    }
    if let Some(operation) = &response.operation {
        println!("Operation id           : {}", operation.id);
        println!(
            "Operation status       : {}",
            lifecycle_status_label(operation.status)
        );
    }
    for warning in &response.warnings {
        println!("Selector warning       : {warning}");
    }
}

fn print_deploy_result(response: &DeployResponse) {
    println!();
    println!(
        "Deploy success         : {}",
        if response.success { "yes" } else { "no" }
    );
    if let Some(deployment) = &response.deployment {
        if let Some(label) = &deployment.deployment_label {
            println!("Deploy label           : {label}");
        }
        if let Some(instance_id) = &deployment.instance_id {
            println!("Deploy instance id     : {instance_id}");
        }
        if let Some(server_ip) = &deployment.server_ip {
            println!("Deploy server IP       : {server_ip}");
        }
    }
    if let Some(runtime) = &response.runtime {
        println!(
            "Deploy runtime ready   : {}",
            if runtime.edge_agent_reachable && runtime.docker_reachable {
                "yes"
            } else {
                "no"
            }
        );
    }
    if let Some(operation) = &response.operation {
        println!("Operation id           : {}", operation.id);
        println!(
            "Operation status       : {}",
            lifecycle_status_label(operation.status)
        );
    }
    for warning in &response.warnings {
        println!("Deploy warning         : {warning}");
    }
}

fn print_destroy_result(response: &DestroyResponse) {
    println!();
    println!(
        "Destroy success        : {}",
        if response.success { "yes" } else { "no" }
    );
    if let Some(deployment) = &response.deployment {
        if let Some(label) = &deployment.deployment_label {
            println!("Removed label          : {label}");
        }
        if let Some(instance_id) = &deployment.instance_id {
            println!("Removed instance id    : {instance_id}");
        }
    }
    if let Some(operation) = &response.operation {
        println!("Operation id           : {}", operation.id);
        println!(
            "Operation status       : {}",
            lifecycle_status_label(operation.status)
        );
    }
    for warning in &response.warnings {
        println!("Destroy warning        : {warning}");
    }
}

fn print_operation_status(status: &OperationStatus) {
    println!();
    print_operation_summary(status);
    for event in &status.recent_events {
        println!("[{}] {}", event.id, event.message);
    }
}

fn print_operation_summary(status: &OperationStatus) {
    if let Some(operation) = &status.operation {
        println!("Operation id           : {}", operation.id);
        println!("Operation kind         : {}", operation.kind);
        println!(
            "Operation status       : {}",
            lifecycle_status_label(operation.status)
        );
        println!("Created at             : {}", operation.created_at_unix);
    }
}

fn bootstrap_mode_label(mode: i32) -> &'static str {
    match BootstrapMode::try_from(mode) {
        Ok(BootstrapMode::BootstrapBase) => "base",
        Ok(BootstrapMode::BootstrapTunnel) => "tunnel",
        Ok(BootstrapMode::BootstrapFull) => "full",
        _ => "unknown",
    }
}

fn lifecycle_status_label(status: i32) -> &'static str {
    match edge_shared_types::OperationLifecycleStatus::try_from(status) {
        Ok(edge_shared_types::OperationLifecycleStatus::Requested) => "requested",
        Ok(edge_shared_types::OperationLifecycleStatus::Running) => "running",
        Ok(edge_shared_types::OperationLifecycleStatus::Succeeded) => "succeeded",
        Ok(edge_shared_types::OperationLifecycleStatus::Failed) => "failed",
        _ => "unknown",
    }
}

fn format_bootstrap_failure(response: &BootstrapRuntimeResponse) -> String {
    let mut parts = vec![format!(
        "controller bootstrap {} failed with exit code {}",
        bootstrap_mode_label(response.mode),
        response.exit_code
    )];
    if !response.stderr.trim().is_empty() {
        parts.push(response.stderr.trim().to_owned());
    }
    if !response.warnings.is_empty() {
        parts.push(format!("warnings: {}", response.warnings.join("; ")));
    }
    parts.join(": ")
}

fn join_ports(ports: &[u32]) -> String {
    ports
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn finish_bootstrap_result(
    response: BootstrapRuntimeResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    if response.success {
        Ok(())
    } else {
        Err(format_bootstrap_failure(&response).into())
    }
}

fn finish_local_result(response: LocalRuntimeResponse) -> Result<(), Box<dyn std::error::Error>> {
    if response.success {
        Ok(())
    } else {
        Err(response.note.into())
    }
}

fn finish_selector_result(response: SetSelectorResponse) -> Result<(), Box<dyn std::error::Error>> {
    if response.success {
        Ok(())
    } else {
        Err("selector update failed".into())
    }
}

fn finish_deploy_result(response: DeployResponse) -> Result<(), Box<dyn std::error::Error>> {
    if response.success {
        Ok(())
    } else {
        Err("deploy failed".into())
    }
}

fn finish_destroy_result(response: DestroyResponse) -> Result<(), Box<dyn std::error::Error>> {
    if response.success {
        Ok(())
    } else {
        Err("destroy failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_bootstrap_label() {
        assert_eq!(
            bootstrap_mode_label(BootstrapMode::BootstrapTunnel as i32),
            "tunnel"
        );
    }

    #[test]
    fn formats_unknown_bootstrap_label() {
        assert_eq!(bootstrap_mode_label(99), "unknown");
    }

    #[test]
    fn formats_bootstrap_failure_message() {
        let message = format_bootstrap_failure(&BootstrapRuntimeResponse {
            success: false,
            mode: BootstrapMode::BootstrapBase as i32,
            exit_code: 3,
            stdout: String::new(),
            stderr: "docker not reachable".to_owned(),
            post_state: None,
            warnings: vec!["gateway container missing".to_owned()],
        });
        assert!(message.contains("controller bootstrap base failed with exit code 3"));
        assert!(message.contains("docker not reachable"));
        assert!(message.contains("gateway container missing"));
    }

    #[test]
    fn optional_arg_like_normalization_drops_blank_values() {
        let normalize = |value: Option<&str>| {
            value.and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_owned())
                }
            })
        };

        assert_eq!(normalize(Some("")), None);
        assert_eq!(normalize(Some("   ")), None);
        assert_eq!(normalize(Some("  edge  ")), Some("edge".to_owned()));
    }

    #[test]
    fn command_endpoint_indices_match_positional_contracts() {
        assert_eq!(DEPLOY_ENDPOINT_ARG_INDEX, 10);
        assert_eq!(DESTROY_ENDPOINT_ARG_INDEX, 6);
    }

    #[test]
    fn formats_operation_lifecycle_labels() {
        assert_eq!(
            lifecycle_status_label(edge_shared_types::OperationLifecycleStatus::Running as i32),
            "running"
        );
        assert_eq!(lifecycle_status_label(99), "unknown");
    }

    #[test]
    fn rotates_large_controller_service_log() {
        let temp_root = std::env::temp_dir().join(format!(
            "edge-console-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_root).unwrap();
        let path = temp_root.join("controller-service-stderr.log");
        std::fs::write(&path, vec![b'x'; 32]).unwrap();
        rotate_service_log_if_needed(&path, 8).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&temp_root);
    }
}
