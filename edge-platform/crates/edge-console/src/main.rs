mod cli;
mod error;

use clap::Parser;
use edge_observability::init as init_observability;
use error::ConsoleError;
use rusqlite::Connection;
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
    TraceObservation, UbuntuProxyState, WindowsActivationState, decode_windows_activation_state,
    verify_windows_activation_files,
};
use tonic::Request;
use tonic::transport::Channel;

const DEFAULT_CONTROLLER_ENDPOINT: &str = "http://127.0.0.1:50051";
const DEFAULT_CONTROLLER_ADDR: &str = "127.0.0.1:50051";
const MAX_CONTROLLER_SERVICE_LOG_BYTES: u64 = 8 * 1024 * 1024;
const DESKTOP_SELECTOR_GROUP: &str = "proxy-selector";
const UBUNTU_SELECTOR_GROUP: &str = "wsl-selector";

#[tokio::main]
async fn main() -> ExitCode {
    let telemetry = init_observability("edge-console");
    let parsed = match cli::Cli::try_parse() {
        Ok(parsed) => parsed,
        Err(err) => {
            let code = err.exit_code();
            let _ = err.print();
            return ExitCode::from(code as u8);
        }
    };
    let command = parsed.command_name();
    tracing::info!(
        component = "edge-console",
        correlation_id = %telemetry.id(),
        command,
        event = "command.start",
        "command started"
    );

    match run(parsed).await {
        Ok(()) => {
            tracing::info!(
                component = "edge-console",
                correlation_id = %telemetry.id(),
                command,
                event = "command.success",
                "command completed"
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(
                component = "edge-console",
                correlation_id = %telemetry.id(),
                command,
                error_category = err.category(),
                event = "command.failure",
                "command failed"
            );
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

async fn run(parsed: cli::Cli) -> Result<(), ConsoleError> {
    use cli::Command;

    match parsed
        .command
        .unwrap_or_else(|| Command::Menu(cli::EndpointArgs::default()))
    {
        Command::Menu(args) => {
            run_menu(args.resolve()).await?;
            Ok(())
        }
        Command::EnsureController(args) => {
            ensure_controller_running(&args.resolve())?;
            println!("status=PASS");
            println!("controller_start_owner=edge-console");
            println!("activation_authority=current.pb");
            Ok(())
        }
        Command::Reconcile(args) => {
            reconcile_installed_runtime(args.resolve()).await?;
            Ok(())
        }
        Command::Status(args) => {
            let status = fetch_status(args.resolve()).await?;
            print_status(&status);
            Ok(())
        }
        Command::Doctor(args) => {
            let doctor = fetch_doctor(args.resolve()).await?;
            print_doctor(&doctor);
            if doctor.ok {
                Ok(())
            } else {
                Err(ConsoleError::Command(
                    "doctor reported failing checks".to_owned(),
                ))
            }
        }
        Command::Secrets(args) => {
            let secrets = list_secret_refs(args.resolve()).await?;
            print_secret_refs(&secrets);
            Ok(())
        }
        Command::GetSecret(args) => {
            let entry = get_secret_ref(cli::controller_endpoint(args.endpoint), &args.name).await?;
            print_secret_ref(&entry);
            Ok(())
        }
        Command::SetSecret(args) => {
            let entry = set_secret_ref(
                cli::controller_endpoint(args.endpoint),
                &args.name,
                &args.secret_ref,
            )
            .await?;
            print_secret_ref(&entry);
            Ok(())
        }
        Command::StartLocal(args) => {
            let response = start_local(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::StartLocalVisible(args) => {
            let response = start_local_visible(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::StopLocal(args) => {
            let response = stop_local(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::RestartLocal(args) => {
            let response = restart_local(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::RestartLocalVisible(args) => {
            let response = restart_local_visible(args.resolve()).await?;
            print_local_runtime_result(&response);
            finish_local_result(response)?;
            Ok(())
        }
        Command::GetSelector(args) => {
            let selector = fetch_selector_state(args.resolve(), DESKTOP_SELECTOR_GROUP).await?;
            print_selector_state(&selector);
            Ok(())
        }
        Command::GetUbuntuSelector(args) => {
            let selector = fetch_selector_state(args.resolve(), UBUNTU_SELECTOR_GROUP).await?;
            print_selector_state_with_label("Ubuntu selector", &selector);
            Ok(())
        }
        Command::SetSelector(args) => {
            let response = set_selector(
                cli::controller_endpoint(args.endpoint),
                DESKTOP_SELECTOR_GROUP,
                &args.name,
            )
            .await?;
            print_set_selector_result(&response);
            finish_selector_result(response)?;
            Ok(())
        }
        Command::SetUbuntuSelector(args) => {
            let response = set_selector(
                cli::controller_endpoint(args.endpoint),
                UBUNTU_SELECTOR_GROUP,
                &args.name,
            )
            .await?;
            print_set_selector_result(&response);
            finish_selector_result(response)?;
            Ok(())
        }
        Command::Trace(args) => {
            let trace = fetch_trace(args.resolve()).await?;
            print_trace(&trace);
            Ok(())
        }
        Command::TraceUbuntu(args) => {
            let endpoint = args.resolve();
            let status = fetch_status(endpoint.clone()).await?;
            let proxy_url = ubuntu_proxy_url_from_status(&status).ok_or_else(|| {
                ConsoleError::Command(
                    "ubuntu proxy endpoint is not available in controller status".to_owned(),
                )
            })?;
            let trace = fetch_trace_with_proxy(endpoint, Some(proxy_url)).await?;
            print_trace_with_label("Ubuntu egress IP", &trace);
            Ok(())
        }
        Command::GetOperation(args) => {
            let status =
                get_operation(cli::controller_endpoint(args.endpoint), args.operation_id).await?;
            print_operation_status(&status);
            Ok(())
        }
        Command::WatchOperation(args) => {
            watch_operation(cli::controller_endpoint(args.endpoint), args.operation_id).await?;
            Ok(())
        }
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
        println!("20. Doctor");
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
                let doctor = fetch_doctor(controller_endpoint.clone()).await?;
                print_doctor(&doctor);
            }
            "0" => return Ok(()),
            _ => println!("Unknown option"),
        }
    }
}

fn installed_root_from_console() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let executable = env::current_exe()?;
    let bin_dir = executable
        .parent()
        .ok_or("failed to resolve edge-console binary directory")?;
    if bin_dir.file_name().and_then(|value| value.to_str()) != Some("bin") {
        return Err("edge-console installed startup requires <install-root>\\bin\\edge-console.exe".into());
    }
    let root = bin_dir
        .parent()
        .ok_or("failed to resolve edge-platform install root")?
        .to_path_buf();
    Ok(root)
}

fn load_verified_activation(
    install_root: &Path,
) -> Result<WindowsActivationState, Box<dyn std::error::Error>> {
    let state_path = install_root.join("current.pb");
    let bytes = std::fs::read(&state_path)?;
    let state = decode_windows_activation_state(&bytes)?;
    verify_windows_activation_files(&state)?;

    let releases_root = install_root.join("releases").canonicalize()?;
    let release_dir = PathBuf::from(&state.release_dir).canonicalize()?;
    let controller = PathBuf::from(&state.controller_path).canonicalize()?;
    if !release_dir.starts_with(&releases_root) {
        return Err("current.pb release_dir is outside the immutable releases root".into());
    }
    if !controller.starts_with(&release_dir) {
        return Err("current.pb controller_path is outside its immutable release directory".into());
    }
    Ok(state)
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

    let install_root = installed_root_from_console()?;
    let activation = load_verified_activation(&install_root)?;
    let runtime_root = install_root.join("runtime");
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

    Command::new(&activation.controller_path)
        .arg("serve")
        .arg(&install_root)
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

async fn reconcile_installed_runtime(
    endpoint: String,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_controller_running(&endpoint)?;
    let status = fetch_status(endpoint.clone()).await?;
    let Some(local) = status.local_singbox.as_ref() else {
        return Err("controller status has no local sing-box observation".into());
    };
    if !local.managed_config {
        println!("status=PASS");
        println!("reconcile=NOOP");
        println!("reason=no_managed_local_config");
        return Ok(());
    }
    if local.process_running {
        println!("status=PASS");
        println!("reconcile=NOOP");
        println!("reason=local_runtime_already_running");
        return Ok(());
    }

    let response = start_local(endpoint).await?;
    if !response.success {
        return Err(format!("local runtime reconcile failed: {}", response.note).into());
    }
    println!("status=PASS");
    println!("reconcile=STARTED_LOCAL_RUNTIME");
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

fn confirm_exact(label: &str, expected: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(prompt(label)? == expected)
}

fn print_status(status: &ControllerStatus) {
    print_lifecycle_status();
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

fn print_lifecycle_status() {
    let path = installed_root_from_console()
        .map(|root| root.join("state").join("controller-state.sqlite"))
        .or_else(|_| {
            env::var("EDGE_REPO_ROOT")
                .map(|root| PathBuf::from(root).join("edge-platform").join(".runtime").join("controller-state.sqlite"))
                .map_err(|err| err.into())
        });
    let Ok(path) = path else { return };
    let Ok(conn) = Connection::open(path) else {
        return;
    };
    let Ok(mut stmt) = conn.prepare(
        "SELECT
             kind,
             status,
             datetime(created_at_unix, 'unixepoch', 'localtime'),
             datetime(completed_at_unix, 'unixepoch', 'localtime'),
             completed_at_unix - created_at_unix,
             target_label,
             target_instance_id,
             target_ip
         FROM operations
         WHERE kind IN ('destroy','deploy')
         ORDER BY id DESC
         LIMIT 2",
    ) else {
        return;
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    });
    let Ok(rows) = rows else { return };
    let operations: Vec<_> = rows.filter_map(Result::ok).collect();
    if operations.is_empty() {
        return;
    }
    println!("\nLifecycle (SQLite)");
    for (kind, status, started_at, completed_at, duration_seconds, label, instance_id, ip) in
        operations
    {
        match (completed_at, duration_seconds) {
            (Some(completed_at), Some(duration_seconds)) => println!(
                "Last {kind:<7} : {status}; started {started_at} local; finished {completed_at} local; duration {duration_seconds}s"
            ),
            _ => {
                println!("Last {kind:<7} : {status}; started {started_at} local; not finished yet")
            }
        }
        if let (Some(label), Some(instance_id), Some(ip)) = (label, instance_id, ip) {
            println!("  target: {label}; instance {instance_id}; IP {ip}");
        }
    }
    let details = conn
        .prepare(
            "SELECT e.message FROM operation_events e JOIN operations o ON o.id=e.operation_id WHERE o.kind='destroy' AND (e.message LIKE 'lifecycle reason:%' OR e.message LIKE 'destroy target verified:%' OR e.message LIKE 'destroy refused:%') ORDER BY e.id DESC LIMIT 2",
        )
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_default();
    for detail in details.into_iter().rev() {
        println!("  {detail}");
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
