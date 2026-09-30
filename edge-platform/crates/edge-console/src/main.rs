mod cli;
mod credential_access_bootstrap;
mod credential_transition;
mod error;

use clap::Parser;
use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
};
use edge_local_runtime::run_non_tun_loopback_smoke;
use edge_observability::init as init_observability;
use edge_secrets::{ACCESS_IDENTITY_FILE_NAME, CredentialStore, fetch_canonical_credential_bundle};
use edge_singbox::{STAGE2_CLASH_API_PORT, STAGE2_DESKTOP_PROXY_PORT, STAGE2_WSL_PROXY_PORT};
use error::ConsoleError;
use rusqlite::Connection;
use std::env;
#[cfg(windows)]
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::{
    BootstrapMode, BootstrapRuntimeRequest, BootstrapRuntimeResponse, ControllerStatus,
    CredentialTransitionAction, DeployRequest, DeployResponse, DestroyRequest, DestroyResponse,
    DoctorRequest, DoctorResponse, Empty, GetOperationRequest, GetSecretRefRequest,
    GetSelectorStateRequest, GetTraceRequest, ListOperationEventsRequest, ListSecretRefsRequest,
    LocalRuntimeResponse, OperationStatus, RestartLocalRuntimeRequest, SecretRefEntry,
    SelectorState, SetSecretRefRequest, SetSelectorRequest, SetSelectorResponse,
    StartLocalRuntimeRequest, StopLocalRuntimeRequest, TraceObservation, UbuntuProxyState,
    WindowsActivationState, WindowsPrivilegedOperation, WindowsPrivilegedRequest,
    WindowsPrivilegedResult, WindowsRuntimeState, WindowsTunnelBinding,
    decode_windows_activation_state, decode_windows_privileged_request,
    decode_windows_privileged_result, decode_windows_runtime_state,
    encode_windows_privileged_request, encode_windows_privileged_result,
    encode_windows_runtime_state, parse_credential_transition_action,
    verify_windows_activation_files,
};
use tonic::Request;
use tonic::transport::Channel;
#[cfg(windows)]
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceSidType,
    ServiceStartType, ServiceState, ServiceType,
};
#[cfg(windows)]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const DEFAULT_CONTROLLER_ENDPOINT: &str = "http://127.0.0.1:50051";
const DEFAULT_CONTROLLER_ADDR: &str = "127.0.0.1:50051";
#[cfg(windows)]
const INSTALLED_CONTROLLER_ADDR: &str = "127.0.0.1:51051";
#[cfg(windows)]
const WINDOWS_CONTROLLER_SERVICE_NAME: &str = "EdgePlatformController";
#[cfg(windows)]
const WINDOWS_CONTROLLER_SERVICE_ACCOUNT: &str = r"NT SERVICE\EdgePlatformController";
const PRIVILEGED_REQUEST_SCHEMA_VERSION: u32 = 1;
const PRIVILEGED_RESULT_SCHEMA_VERSION: u32 = 1;
const PRIVILEGED_TASK_NAME: &str = "EdgePlatformPrivilegedDispatch";
const PRIVILEGED_WAIT_SECS: u64 = 180;
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
            println!("controller_start_owner=windows_scm");
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
        Command::CredentialState(args) => {
            let state = fetch_credential_state(args.resolve()).await?;
            print_windows_credential_state(state.as_ref());
            Ok(())
        }
        Command::SmokeRuntime => {
            let install_root = installed_root_from_console()?;
            let activation = load_verified_activation(&install_root)?;
            let result = run_non_tun_loopback_smoke(
                Path::new(&activation.sing_box_path),
                &install_root.join("runtime"),
            )?;
            println!("status=PASS");
            println!("mode=NON_TUN_LOOPBACK");
            println!("release_set_sha256={}", activation.release_set_sha256);
            println!("sing_box_path={}", activation.sing_box_path);
            println!("sing_box_pid={}", result.singbox_pid);
            println!("proxy_port={}", result.proxy_port);
            println!("origin_port={}", result.origin_port);
            println!("proxy_round_trip=PASS");
            println!("tun_enabled=false");
            println!("system_proxy_mutated=false");
            println!("dns_mutated=false");
            println!("routes_mutated=false");
            println!("cleanup=PASS");
            Ok(())
        }
        Command::Stage2Preflight => {
            let install_root = installed_root_from_console()?;
            verify_stage2_isolated_prerequisites(&install_root).map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("stage2_proxy_ports=AVAILABLE");
            println!("stage2_desktop_proxy_port={STAGE2_DESKTOP_PROXY_PORT}");
            println!("stage2_wsl_proxy_port={STAGE2_WSL_PROXY_PORT}");
            println!("stage2_clash_api_port={STAGE2_CLASH_API_PORT}");
            println!("tun_enabled=false");
            Ok(())
        }
        Command::ProvisionRuntimeState(args) => {
            provision_windows_runtime_state(Path::new(&args.install_root))?;
            Ok(())
        }
        Command::PrivilegedPing(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::Ping as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedActivate(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::ActivateRelease as i32,
                    accepted_revision: Some(args.accepted_revision),
                    release_set_sha256: Some(args.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedStageCredential(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::StageCredential as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: Some(args.generation),
                    credential_transition_action: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::CredentialTransition(args) => {
            let action = parse_credential_transition_action(&args.action)?;
            run_windows_credential_transition(Path::new(&args.install_root), action)
                .await
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::RestartVerifyRuntime => {
            let endpoint = cli::controller_endpoint(None);
            restart_and_verify_windows_tunnels(&endpoint)
                .await
                .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("runtime_restart_functional=PASS");
            println!("runtime_restart_direct=PASS");
            println!("runtime_restart_warp=PASS");
            Ok(())
        }
        Command::PrivilegedPrepareCredentialAccess(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::PrepareCredentialAccessBootstrap as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedInstallCredentialAccess(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::InstallCredentialAccessBootstrap as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::PrivilegedConvergeControllerService(args) => {
            let install_root = PathBuf::from(args.install_root);
            let activation = load_verified_activation(&install_root)?;
            converge_controller_service(&install_root, Path::new(&activation.controller_path))
                .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("controller_service={WINDOWS_CONTROLLER_SERVICE_NAME}");
            println!("controller_start_owner=windows_scm");
            println!("secret_authority=controller_service");
            println!("runner_secret_access=false");
            Ok(())
        }
        Command::PrivilegedDispatch(args) => {
            let install_root = PathBuf::from(args.install_root);
            dispatch_privileged_request(&install_root).await?;
            Ok(())
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

fn privileged_request_path(install_root: &Path) -> PathBuf {
    install_root
        .join("exchange")
        .join("requests")
        .join("request.pb")
}

fn privileged_result_path(install_root: &Path) -> PathBuf {
    install_root
        .join("exchange")
        .join("results")
        .join("result.pb")
}

fn required_provision_env<F>(get: &F, name: &str) -> Result<String, String>
where
    F: Fn(&str) -> Option<String>,
{
    let value = get(name).ok_or_else(|| format!("{name} is required"))?;
    if value.is_empty() || value.trim() != value {
        return Err(format!("{name} must be a non-empty canonical value"));
    }
    Ok(value)
}

fn optional_provision_env<F>(get: &F, name: &str) -> Result<Option<String>, String>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(value) = get(name) else {
        return Ok(None);
    };
    if value.is_empty() || value.trim() != value {
        return Err(format!(
            "{name} must be a non-empty canonical value when provided"
        ));
    }
    Ok(Some(value))
}

fn required_provision_port<F>(get: &F, name: &str) -> Result<u32, String>
where
    F: Fn(&str) -> Option<String>,
{
    required_provision_env(get, name)?
        .parse::<u32>()
        .map_err(|err| format!("{name} must be an integer port: {err}"))
}

fn windows_runtime_state_from_provision_env<F>(get: F) -> Result<WindowsRuntimeState, String>
where
    F: Fn(&str) -> Option<String>,
{
    let direct = WindowsTunnelBinding {
        domain: required_provision_env(&get, "EDGE_WINDOWS_DIRECT_DOMAIN")?,
        hy2_port: required_provision_port(&get, "EDGE_WINDOWS_DIRECT_HY2_PORT")?,
        hy2_password: required_provision_env(&get, "HY2_PASSWORD")?,
        vless_port: required_provision_port(&get, "EDGE_WINDOWS_DIRECT_VLESS_PORT")?,
        vless_uuid: required_provision_env(&get, "VLESS_UUID")?,
        reality_public_key: required_provision_env(&get, "REALITY_PUBLIC_KEY")?,
        reality_short_id: required_provision_env(&get, "REALITY_SHORT_ID")?,
    };
    let warp = WindowsTunnelBinding {
        domain: required_provision_env(&get, "EDGE_WINDOWS_WARP_DOMAIN")?,
        hy2_port: required_provision_port(&get, "EDGE_WINDOWS_WARP_HY2_PORT")?,
        hy2_password: required_provision_env(&get, "HY2_WARP_PASSWORD")?,
        vless_port: required_provision_port(&get, "EDGE_WINDOWS_WARP_VLESS_PORT")?,
        vless_uuid: required_provision_env(&get, "VLESS_WARP_UUID")?,
        reality_public_key: required_provision_env(&get, "REALITY_WARP_PUBLIC_KEY")?,
        reality_short_id: required_provision_env(&get, "REALITY_WARP_SHORT_ID")?,
    };
    let state = WindowsRuntimeState {
        schema_version: 1,
        deployment_label: optional_provision_env(&get, "EDGE_WINDOWS_DEPLOYMENT_LABEL")?,
        instance_id: required_provision_env(&get, "EDGE_WINDOWS_INSTANCE_ID")?,
        server_ip: required_provision_env(&get, "EDGE_WINDOWS_SERVER_IP")?,
        direct: Some(direct),
        warp: Some(warp),
    };
    encode_windows_runtime_state(&state)?;
    Ok(state)
}

fn provision_windows_runtime_state(install_root: &Path) -> Result<(), ConsoleError> {
    if !install_root.join("current.pb").is_file() || !install_root.join("releases").is_dir() {
        return Err(ConsoleError::Command(
            "runtime-state provisioning requires an installed Windows application root".to_owned(),
        ));
    }

    let secret_dir = install_root.join("state").join("secrets");
    if !secret_dir.is_dir() {
        return Err(ConsoleError::Command(format!(
            "controller-private secret directory is missing: {}",
            secret_dir.display()
        )));
    }

    let target = secret_dir.join("runtime-state.pb");
    if target.exists() {
        return Err(ConsoleError::Command(
            "runtime-state.pb already exists; credential rotation requires a separate explicit operation"
                .to_owned(),
        ));
    }
    let staged = target.with_extension("pb.new");
    if staged.exists() {
        return Err(ConsoleError::Command(format!(
            "staged runtime state already exists: {}",
            staged.display()
        )));
    }

    let state = windows_runtime_state_from_provision_env(|name| env::var(name).ok())
        .map_err(ConsoleError::Command)?;
    let bytes = encode_windows_runtime_state(&state).map_err(ConsoleError::Command)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(|err| {
            ConsoleError::Command(format!(
                "failed to create staged runtime state {}: {err}",
                staged.display()
            ))
        })?;
    if let Err(err) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&staged);
        return Err(ConsoleError::Command(format!(
            "failed to write staged runtime state {}: {err}",
            staged.display()
        )));
    }
    drop(file);

    if let Err(err) = fs::rename(&staged, &target) {
        let _ = fs::remove_file(&staged);
        return Err(ConsoleError::Command(format!(
            "failed to publish runtime state {}: {err}",
            target.display()
        )));
    }

    let observed = fs::read(&target).map_err(|err| {
        let _ = fs::remove_file(&target);
        ConsoleError::Command(format!(
            "failed to verify published runtime state {}: {err}",
            target.display()
        ))
    })?;
    if let Err(err) = decode_windows_runtime_state(&observed) {
        let _ = fs::remove_file(&target);
        return Err(ConsoleError::Command(format!(
            "published runtime state failed canonical verification: {err}"
        )));
    }

    println!("status=PASS");
    println!("runtime_state=PROVISIONED");
    println!("runtime_state_schema=1");
    println!("runtime_secret_store=controller_private");
    println!("runtime_secret_consumer=controller_service");
    println!("runner_secret_access=false");
    Ok(())
}

fn new_privileged_request_id() -> Result<String, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(format!("{}-{}", now.as_millis(), std::process::id()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().ok_or("atomic write path has no parent")?;
    fs::create_dir_all(parent)?;
    let temp = path.with_extension("pb.new");
    fs::write(&temp, bytes)?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn submit_privileged_request(
    install_root: &Path,
    request: WindowsPrivilegedRequest,
) -> Result<WindowsPrivilegedResult, Box<dyn std::error::Error>> {
    let request_path = privileged_request_path(install_root);
    if request_path.exists() {
        return Err("a privileged Windows request is already pending".into());
    }
    let bytes = encode_windows_privileged_request(&request)?;
    write_atomic(&request_path, &bytes)?;

    let result_path = privileged_result_path(install_root);
    let deadline = Instant::now() + Duration::from_secs(PRIVILEGED_WAIT_SECS);
    while Instant::now() < deadline {
        match fs::read(&result_path) {
            Ok(bytes) => {
                let result = decode_windows_privileged_result(&bytes)?;
                if result.request_id == request.request_id {
                    return Ok(result);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "timed out waiting {} seconds for privileged Windows request {}",
        PRIVILEGED_WAIT_SECS, request.request_id
    )
    .into())
}

async fn dispatch_privileged_request(
    install_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_path = privileged_request_path(install_root);
    let bytes = match fs::read(&request_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("status=PASS");
            println!("privileged_dispatch=NOOP");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let request = decode_windows_privileged_request(&bytes)?;
    let result = process_privileged_request(install_root, &request).await;
    let result_bytes = encode_windows_privileged_result(&result)?;
    write_atomic(&privileged_result_path(install_root), &result_bytes)?;
    fs::remove_file(&request_path)?;

    print_privileged_result(&result);
    finish_privileged_result(&result)?;
    Ok(())
}

async fn process_privileged_request(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> WindowsPrivilegedResult {
    let outcome = match WindowsPrivilegedOperation::try_from(request.operation) {
        Ok(WindowsPrivilegedOperation::Ping) => {
            let active = load_verified_activation(install_root)
                .ok()
                .map(|state| state.release_set_sha256);
            Ok((
                "PING_PASS".to_owned(),
                "privileged dispatcher is reachable".to_owned(),
                active,
            ))
        }
        Ok(WindowsPrivilegedOperation::ActivateRelease) => {
            activate_privileged_release(install_root, request)
        }
        Ok(WindowsPrivilegedOperation::StageCredential) => {
            stage_windows_credential_candidate_from_worker(install_root, request).await
        }
        Ok(WindowsPrivilegedOperation::PrepareCredentialAccessBootstrap) => {
            credential_access_bootstrap::prepare(install_root)
        }
        Ok(WindowsPrivilegedOperation::InstallCredentialAccessBootstrap) => {
            credential_access_bootstrap::install(install_root)
        }
        Ok(WindowsPrivilegedOperation::CredentialTransition) => {
            let action = request
                .credential_transition_action
                .and_then(|value| CredentialTransitionAction::try_from(value).ok())
                .ok_or_else(|| "credential transition action is missing or invalid".to_owned())
                .and_then(|action| {
                    let activation =
                        load_verified_activation(install_root).map_err(|err| err.to_string())?;
                    let release = activation.release_set_sha256.clone();
                    let (code, detail) =
                        credential_transition::transition(install_root, &activation, action)?;
                    Ok((code, detail, Some(release)))
                });
            action
        }
        Ok(WindowsPrivilegedOperation::Unspecified) | Err(_) => {
            Err("unsupported privileged Windows operation".to_owned())
        }
    };

    match outcome {
        Ok((code, detail, active)) => WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            success: true,
            code,
            detail,
            active_release_set_sha256: active,
        },
        Err(detail) => WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            success: false,
            code: "PRIVILEGED_OPERATION_FAILED".to_owned(),
            detail,
            active_release_set_sha256: load_verified_activation(install_root)
                .ok()
                .map(|state| state.release_set_sha256),
        },
    }
}

async fn stage_windows_credential_candidate_from_worker(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    let generation = request
        .credential_generation
        .ok_or_else(|| "credential_generation is required".to_owned())?;
    if generation == 0 {
        return Err("credential_generation must be greater than zero".to_owned());
    }
    let identity_path = install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    let bundle = fetch_canonical_credential_bundle(
        edge_shared_types::CredentialProjectionKind::Windows,
        generation,
        &identity_path,
    )
    .await?;
    let store = CredentialStore::new(
        windows_credential_store_path(install_root),
        edge_shared_types::CredentialProjectionKind::Windows,
    )?;
    let state = store.stage_candidate(&bundle)?;
    let candidate = state
        .candidate
        .ok_or_else(|| "credential candidate was not persisted".to_owned())?;
    let active = load_verified_activation(install_root)
        .ok()
        .map(|value| value.release_set_sha256);
    Ok((
        "CREDENTIAL_CANDIDATE_STAGED".to_owned(),
        format!(
            "credential candidate staged generation={} slot={}",
            candidate.generation, candidate.slot
        ),
        active,
    ))
}

fn activate_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    let accepted_revision = request
        .accepted_revision
        .as_deref()
        .ok_or_else(|| "accepted_revision is required".to_owned())?;
    let target_release = request
        .release_set_sha256
        .as_deref()
        .ok_or_else(|| "release_set_sha256 is required".to_owned())?;

    let installer = install_root
        .join("bootstrap")
        .join("install-windows-release.ps1");
    if !installer.is_file() {
        return Err(format!(
            "protected Windows installer is missing: {}",
            installer.display()
        ));
    }
    let root = install_root
        .to_str()
        .ok_or_else(|| "Windows install root is not UTF-8".to_owned())?;
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&installer)
        .args([
            "-AcceptedRevision",
            accepted_revision,
            "-ReleaseSetSha256",
            target_release,
            "-InstallRoot",
            root,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to start protected Windows installer: {err}"))?;
    if !status.success() {
        return Err(format!(
            "protected Windows installer failed with exit code {}",
            status.code().unwrap_or(-1)
        ));
    }

    let activation = load_verified_activation(install_root)
        .map_err(|err| format!("updated Windows activation failed verification: {err}"))?;
    if activation.release_set_sha256 != target_release {
        return Err("updated Windows activation does not match requested ReleaseSet".to_owned());
    }
    #[cfg(windows)]
    converge_controller_service(install_root, Path::new(&activation.controller_path))?;
    retarget_privileged_task(install_root, &activation.console_path)?;
    Ok((
        "RELEASE_CONVERGED".to_owned(),
        "exact accepted ReleaseSet and controller service are active".to_owned(),
        Some(activation.release_set_sha256),
    ))
}

fn retarget_privileged_task(install_root: &Path, console_path: &str) -> Result<(), String> {
    let action = format!(
        "\"{}\" privileged-dispatch --install-root \"{}\"",
        console_path,
        install_root.display()
    );
    let status = Command::new("schtasks.exe")
        .args(["/Change", "/TN", PRIVILEGED_TASK_NAME, "/TR", &action])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to retarget privileged Windows task: {err}"))?;
    if !status.success() {
        return Err(format!(
            "failed to retarget privileged Windows task, exit code {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn print_privileged_result(result: &WindowsPrivilegedResult) {
    println!("status={}", if result.success { "PASS" } else { "FAIL" });
    println!("request_id={}", result.request_id);
    println!("code={}", result.code);
    println!("detail={}", result.detail);
    if let Some(release) = result.active_release_set_sha256.as_deref() {
        println!("active_release_set_sha256={release}");
    }
}

fn submit_windows_credential_transition(
    install_root: &Path,
    action: CredentialTransitionAction,
) -> Result<WindowsPrivilegedResult, String> {
    submit_privileged_request(
        install_root,
        WindowsPrivilegedRequest {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            request_id: new_privileged_request_id().map_err(|err| err.to_string())?,
            operation: WindowsPrivilegedOperation::CredentialTransition as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: Some(action as i32),
        },
    )
    .map_err(|err| err.to_string())
}

async fn verify_windows_tunnel_route(
    endpoint: &str,
    route: &str,
    expected_warp: &str,
) -> Result<(), String> {
    let response = set_selector(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP, route)
        .await
        .map_err(|err| err.to_string())?;
    if !response.success {
        return Err(format!("selector update failed for route {route}"));
    }
    let trace = fetch_trace(endpoint.to_owned())
        .await
        .map_err(|err| err.to_string())?;
    if !trace.available || trace.ip.is_none() {
        return Err(format!("Cloudflare trace is unavailable for route {route}"));
    }
    if trace.warp.as_deref() != Some(expected_warp) {
        return Err(format!(
            "route {route} expected Cloudflare warp={expected_warp}, observed {:?}",
            trace.warp
        ));
    }
    Ok(())
}

async fn restart_and_verify_windows_tunnels(endpoint: &str) -> Result<(), String> {
    let restart = restart_local(endpoint.to_owned())
        .await
        .map_err(|err| err.to_string())?;
    if !restart.success {
        return Err(format!(
            "Windows local runtime restart failed: {}",
            restart.note
        ));
    }

    let selector = fetch_selector_state(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP)
        .await
        .map_err(|err| err.to_string())?;
    let original = selector
        .observed_main_route
        .or(selector.desired_main_route)
        .ok_or_else(|| "Windows selector has no restorable route".to_owned())?;

    let direct = verify_windows_tunnel_route(endpoint, "auto-direct-tunnel", "off").await;
    let warp = if direct.is_ok() {
        verify_windows_tunnel_route(endpoint, "auto-warp-tunnel", "on").await
    } else {
        Ok(())
    };
    let restore = set_selector(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP, &original)
        .await
        .map_err(|err| err.to_string())
        .and_then(|response| {
            if response.success {
                Ok(())
            } else {
                Err("failed to restore original Windows selector".to_owned())
            }
        });

    direct?;
    warp?;
    restore
}

fn verify_stage2_isolated_prerequisites(install_root: &Path) -> Result<(), String> {
    let managed_state = windows_runtime_state_path(install_root);
    if managed_state.exists() {
        return Err(format!(
            "Stage 2 requires no pre-existing managed Windows runtime state at {}",
            managed_state.display()
        ));
    }
    let managed_config = local_singbox_config_path(install_root);
    if managed_config.exists() {
        return Err(format!(
            "Stage 2 requires no pre-existing managed Windows runtime config at {}",
            managed_config.display()
        ));
    }

    let endpoints = [
        (
            "desktop proxy",
            format!("127.0.0.1:{STAGE2_DESKTOP_PROXY_PORT}"),
        ),
        ("WSL proxy", format!("0.0.0.0:{STAGE2_WSL_PROXY_PORT}")),
        ("Clash API", format!("127.0.0.1:{STAGE2_CLASH_API_PORT}")),
    ];
    let mut listeners = Vec::with_capacity(endpoints.len());
    for (name, endpoint) in endpoints {
        let listener = TcpListener::bind(&endpoint)
            .map_err(|err| format!("Stage 2 {name} endpoint {endpoint} is unavailable: {err}"))?;
        listeners.push(listener);
    }
    drop(listeners);
    Ok(())
}

async fn stop_managed_windows_runtime_after_failure(endpoint: &str) -> Result<(), String> {
    let response = stop_local(endpoint.to_owned())
        .await
        .map_err(|err| err.to_string())?;
    if response.success {
        Ok(())
    } else {
        Err(format!(
            "failed to stop managed Windows runtime after functional failure: {}",
            response.note
        ))
    }
}

async fn run_windows_credential_transition(
    install_root: &Path,
    action: CredentialTransitionAction,
) -> Result<(), String> {
    let endpoint = cli::controller_endpoint(None);
    let result = submit_windows_credential_transition(install_root, action)?;
    print_privileged_result(&result);
    finish_privileged_result(&result).map_err(|err| err.to_string())?;

    if !matches!(
        action,
        CredentialTransitionAction::ApplyCandidate | CredentialTransitionAction::ApplyActive
    ) {
        return Ok(());
    }

    if let Err(err) = restart_and_verify_windows_tunnels(&endpoint).await {
        return match stop_managed_windows_runtime_after_failure(&endpoint).await {
            Ok(()) => Err(format!(
                "Windows managed runtime failed functional verification and was stopped without touching external sing-box: {err}"
            )),
            Err(cleanup_err) => Err(format!(
                "Windows managed runtime failed functional verification: {err}; managed-runtime cleanup also failed: {cleanup_err}"
            )),
        };
    }

    println!("credential_transition_functional=PASS");
    println!("credential_transition_direct=PASS");
    println!("credential_transition_warp=PASS");
    Ok(())
}

fn finish_privileged_result(
    result: &WindowsPrivilegedResult,
) -> Result<(), Box<dyn std::error::Error>> {
    if result.success {
        Ok(())
    } else {
        Err(format!("privileged Windows operation failed: {}", result.code).into())
    }
}

fn installed_root_from_console() -> Result<PathBuf, Box<dyn std::error::Error>> {
    installed_root_from_executable(&env::current_exe()?)
}

fn installed_root_from_executable(
    executable: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let bin_dir = executable
        .parent()
        .ok_or("failed to resolve edge-console binary directory")?;
    if bin_dir.file_name().and_then(|value| value.to_str()) != Some("bin") {
        return Err(
            "edge-console installed startup requires <install-root>\\releases\\<release-set>\\bin\\edge-console.exe"
                .into(),
        );
    }
    let release_dir = bin_dir
        .parent()
        .ok_or("failed to resolve immutable release directory")?;
    let releases_dir = release_dir
        .parent()
        .ok_or("failed to resolve immutable releases root")?;
    if releases_dir.file_name().and_then(|value| value.to_str()) != Some("releases") {
        return Err(
            "edge-console installed startup requires <install-root>\\releases\\<release-set>\\bin\\edge-console.exe"
                .into(),
        );
    }
    let root = releases_dir
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
    let _activation = load_verified_activation(&install_root)?;
    if wait_for_controller(addr, Duration::from_secs(10)) {
        Ok(())
    } else {
        Err(format!(
            "SCM-owned EdgePlatformController is not listening on {addr}; edge-console does not own controller startup"
        )
        .into())
    }
}

#[cfg(windows)]
fn wait_for_service_state(
    service: &Service,
    expected: ServiceState,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        let status = service
            .query_status()
            .map_err(|err| format!("failed to query controller service state: {err}"))?;
        if status.current_state == expected {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(format!(
        "controller service did not reach {expected:?} within {} seconds",
        timeout.as_secs()
    ))
}

#[cfg(windows)]
fn run_icacls(path: &Path, arguments: &[&str]) -> Result<(), String> {
    let mut command = Command::new("icacls.exe");
    command.arg(path);
    command.args(arguments);
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to start icacls for {}: {err}", path.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "icacls failed for {} with exit code {}",
            path.display(),
            status.code().unwrap_or(-1)
        ))
    }
}

#[cfg(windows)]
fn protect_controller_owned_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|err| {
        format!(
            "failed to create controller-owned {}: {err}",
            path.display()
        )
    })?;
    run_icacls(
        path,
        &[
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            r"NT SERVICE\EdgePlatformController:(OI)(CI)M",
            "/Q",
        ],
    )?;
    run_icacls(path, &["/remove:g", "*S-1-5-20", "/Q"])?;
    run_icacls(path, &["/inheritance:r", "/Q"])?;
    let descendants = path.join("*");
    run_icacls(&descendants, &["/reset", "/T", "/Q"])?;
    Ok(())
}

#[cfg(windows)]
fn converge_application_acl(install_root: &Path) -> Result<(), String> {
    for path in [
        install_root.join("state"),
        install_root.join("state").join("secrets"),
        install_root.join("runtime"),
        install_root.join("logs"),
        install_root.join("exchange").join("requests"),
        install_root.join("exchange").join("results"),
    ] {
        fs::create_dir_all(&path)
            .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
    }

    run_icacls(
        install_root,
        &[
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-20:(OI)(CI)RX",
            r"NT SERVICE\EdgePlatformController:(OI)(CI)RX",
            "/Q",
        ],
    )?;
    run_icacls(install_root, &["/inheritance:r", "/Q"])?;
    let descendants = install_root.join("*");
    run_icacls(&descendants, &["/reset", "/T", "/Q"])?;

    for path in [
        install_root.join("state"),
        install_root.join("runtime"),
        install_root.join("logs"),
    ] {
        protect_controller_owned_directory(&path)?;
    }

    run_icacls(
        &install_root.join("exchange").join("requests"),
        &["/grant:r", "*S-1-5-20:(OI)(CI)M", "/Q"],
    )?;
    run_icacls(
        &install_root.join("exchange").join("results"),
        &["/grant:r", "*S-1-5-20:(OI)(CI)RX", "/Q"],
    )?;
    Ok(())
}

#[cfg(windows)]
fn converge_controller_service(install_root: &Path, controller_path: &Path) -> Result<(), String> {
    if !controller_path.is_file() {
        return Err(format!(
            "exact controller binary is missing: {}",
            controller_path.display()
        ));
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|err| format!("failed to open Windows Service Control Manager: {err}"))?;

    let service_info = ServiceInfo {
        name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: controller_path.to_path_buf(),
        launch_arguments: vec![
            OsString::from("windows-service"),
            install_root.as_os_str().to_owned(),
            OsString::from(INSTALLED_CONTROLLER_ADDR),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)),
        account_password: None,
    };
    let access = ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP;
    let service = manager
        .create_service(&service_info, access)
        .or_else(|_| manager.open_service(WINDOWS_CONTROLLER_SERVICE_NAME, access))
        .map_err(|err| format!("failed to create or open controller service: {err}"))?;

    let status = service
        .query_status()
        .map_err(|err| format!("failed to query controller service before convergence: {err}"))?;
    if status.current_state != ServiceState::Stopped {
        if status.current_state != ServiceState::StopPending {
            service
                .stop()
                .map_err(|err| format!("failed to stop controller service: {err}"))?;
        }
        wait_for_service_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
    }

    service
        .change_config(&service_info)
        .map_err(|err| format!("failed to retarget controller service: {err}"))?;
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .map_err(|err| format!("failed to enable controller service SID: {err}"))?;
    service
        .set_delayed_auto_start(true)
        .map_err(|err| format!("failed to enable delayed controller auto-start: {err}"))?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(15),
                },
            ]),
        })
        .map_err(|err| format!("failed to configure controller service recovery: {err}"))?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|err| format!("failed to enable controller recovery on failures: {err}"))?;

    converge_application_acl(install_root)?;

    service
        .start::<&str>(&[])
        .map_err(|err| format!("failed to start controller service: {err}"))?;
    wait_for_service_state(&service, ServiceState::Running, Duration::from_secs(15))?;

    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse()
        .map_err(|err| format!("invalid installed controller address: {err}"))?;
    if !wait_for_controller(addr, Duration::from_secs(10)) {
        return Err(format!(
            "controller service is Running but is not listening on {INSTALLED_CONTROLLER_ADDR}"
        ));
    }
    Ok(())
}

async fn reconcile_installed_runtime(endpoint: String) -> Result<(), Box<dyn std::error::Error>> {
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
                "failed to connect to SCM-owned controller: first={first_err}; second={second_err}"
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

async fn fetch_credential_state(
    endpoint: String,
) -> Result<Option<edge_shared_types::LocalCredentialState>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    Ok(client
        .get_credential_state(Request::new(Empty {}))
        .await?
        .into_inner()
        .state)
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

fn print_windows_credential_state(state: Option<&edge_shared_types::LocalCredentialState>) {
    println!("credential_state_present={}", state.is_some());
    let Some(state) = state else {
        return;
    };
    println!("credential_schema_version={}", state.schema_version);
    println!("credential_projection={}", state.projection);
    for (name, value) in [
        ("active", state.active.as_ref()),
        ("candidate", state.candidate.as_ref()),
        ("previous", state.previous.as_ref()),
    ] {
        println!("credential_{name}_present={}", value.is_some());
        if let Some(value) = value {
            println!("credential_{name}_generation={}", value.generation);
            println!("credential_{name}_slot={}", value.slot);
            println!("credential_{name}_sha256={}", value.sha256);
        }
    }
}

fn print_lifecycle_status() {
    let Ok(root) = installed_root_from_console() else {
        return;
    };
    let path = root.join("state").join("controller-state.sqlite");
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
    fn resolves_install_root_from_immutable_release_console_path() {
        let root = PathBuf::from("install-root");
        let executable = root
            .join("releases")
            .join("release-set")
            .join("bin")
            .join("edge-console.exe");

        assert_eq!(installed_root_from_executable(&executable).unwrap(), root);
    }

    #[test]
    fn rejects_obsolete_root_bin_console_layout() {
        let executable = PathBuf::from("install-root")
            .join("bin")
            .join("edge-console.exe");

        let error = installed_root_from_executable(&executable).unwrap_err();
        assert!(error.to_string().contains("releases"));
    }

    #[test]
    fn builds_canonical_windows_runtime_state_from_client_only_env() {
        let values = std::collections::BTreeMap::from([
            ("EDGE_WINDOWS_DEPLOYMENT_LABEL", "production".to_owned()),
            ("EDGE_WINDOWS_INSTANCE_ID", "instance-1".to_owned()),
            ("EDGE_WINDOWS_SERVER_IP", "203.0.113.10".to_owned()),
            ("EDGE_WINDOWS_DIRECT_DOMAIN", "edge.example.com".to_owned()),
            ("EDGE_WINDOWS_DIRECT_HY2_PORT", "8443".to_owned()),
            ("HY2_PASSWORD", "direct-password".to_owned()),
            ("EDGE_WINDOWS_DIRECT_VLESS_PORT", "443".to_owned()),
            (
                "VLESS_UUID",
                "00000000-0000-4000-8000-000000000001".to_owned(),
            ),
            ("REALITY_PUBLIC_KEY", "direct-public-key".to_owned()),
            ("REALITY_SHORT_ID", "a1b2c3d4".to_owned()),
            ("EDGE_WINDOWS_WARP_DOMAIN", "edge.example.com".to_owned()),
            ("EDGE_WINDOWS_WARP_HY2_PORT", "9444".to_owned()),
            ("HY2_WARP_PASSWORD", "warp-password".to_owned()),
            ("EDGE_WINDOWS_WARP_VLESS_PORT", "5443".to_owned()),
            (
                "VLESS_WARP_UUID",
                "00000000-0000-4000-8000-000000000002".to_owned(),
            ),
            ("REALITY_WARP_PUBLIC_KEY", "warp-public-key".to_owned()),
            ("REALITY_WARP_SHORT_ID", "b1c2d3e4".to_owned()),
        ]);
        let state =
            windows_runtime_state_from_provision_env(|name| values.get(name).cloned()).unwrap();
        assert_eq!(state.schema_version, 1);
        assert_eq!(state.instance_id, "instance-1");
        assert_eq!(state.server_ip, "203.0.113.10");
        assert_eq!(state.direct.as_ref().unwrap().hy2_port, 8443);
        assert_eq!(state.warp.as_ref().unwrap().vless_port, 5443);
        assert!(encode_windows_runtime_state(&state).is_ok());
    }

    #[test]
    fn provisioning_requires_every_client_secret_but_no_server_private_key() {
        let values = std::collections::BTreeMap::from([
            ("EDGE_WINDOWS_INSTANCE_ID", "instance-1".to_owned()),
            ("EDGE_WINDOWS_SERVER_IP", "203.0.113.10".to_owned()),
            ("EDGE_WINDOWS_DIRECT_DOMAIN", "edge.example.com".to_owned()),
            ("EDGE_WINDOWS_DIRECT_HY2_PORT", "8443".to_owned()),
            ("HY2_PASSWORD", "direct-password".to_owned()),
            ("EDGE_WINDOWS_DIRECT_VLESS_PORT", "443".to_owned()),
            (
                "VLESS_UUID",
                "00000000-0000-4000-8000-000000000001".to_owned(),
            ),
            ("REALITY_PUBLIC_KEY", "direct-public-key".to_owned()),
            ("REALITY_SHORT_ID", "a1b2c3d4".to_owned()),
            ("EDGE_WINDOWS_WARP_DOMAIN", "edge.example.com".to_owned()),
            ("EDGE_WINDOWS_WARP_HY2_PORT", "9444".to_owned()),
            ("HY2_WARP_PASSWORD", "warp-password".to_owned()),
            ("EDGE_WINDOWS_WARP_VLESS_PORT", "5443".to_owned()),
            (
                "VLESS_WARP_UUID",
                "00000000-0000-4000-8000-000000000002".to_owned(),
            ),
            ("REALITY_WARP_PUBLIC_KEY", "warp-public-key".to_owned()),
        ]);
        let err =
            windows_runtime_state_from_provision_env(|name| values.get(name).cloned()).unwrap_err();
        assert!(err.contains("REALITY_WARP_SHORT_ID"));
        assert!(!err.contains("PRIVATE_KEY"));
        assert!(!err.contains("PROXY_PASSWORD"));
    }
}
