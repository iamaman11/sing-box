mod cli;
mod credential_access_bootstrap;
mod credential_transition;
mod error;

use clap::Parser;
use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
};
use edge_local_runtime::{
    RuntimeProcessClassification, classify_runtime_process, observe_process,
    run_non_tun_loopback_smoke, stop_local_runtime as stop_runtime_process,
};
use edge_observability::init as init_observability;
use edge_secrets::{ACCESS_IDENTITY_FILE_NAME, CredentialStore, fetch_canonical_credential_bundle};
use edge_singbox::{STAGE2_CLASH_API_PORT, STAGE2_DESKTOP_PROXY_PORT, STAGE2_WSL_PROXY_PORT};
use error::ConsoleError;
use rusqlite::Connection;
use std::env;
#[cfg(windows)]
use std::ffi::{OsString, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::{
    ControllerStatus, CredentialTransitionAction, DoctorRequest, DoctorResponse, Empty,
    GetOperationRequest, GetSecretRefRequest, GetSelectorStateRequest, GetTraceRequest,
    ListOperationEventsRequest, ListSecretRefsRequest, LocalRuntimeResponse, OperationStatus,
    RestartLocalRuntimeRequest, SecretRefEntry, SelectorState, SetSecretRefRequest,
    SetSelectorRequest, SetSelectorResponse, StartLocalRuntimeRequest, StopLocalRuntimeRequest,
    TraceObservation, UbuntuProxyState, WINDOWS_CONTROLLER_ADDR, WINDOWS_CONTROLLER_ENDPOINT,
    WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS, WindowsActivationState, WindowsDatapathMode,
    WindowsPrivilegedOperation, WindowsPrivilegedRequest, WindowsPrivilegedResult,
    WindowsRuntimeState, WindowsTunnelBinding, canonical_production_desired_state,
    decode_windows_activation_state, decode_windows_privileged_request,
    decode_windows_privileged_result, decode_windows_runtime_state,
    encode_windows_activation_state, encode_windows_privileged_request,
    encode_windows_privileged_result, encode_windows_runtime_state,
    parse_credential_transition_action, verify_windows_activation_files,
};
use tonic::Request;
use tonic::transport::Channel;
#[cfg(windows)]
use windows::Win32::Foundation::WAIT_IO_COMPLETION;
#[cfg(windows)]
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
#[cfg(windows)]
use windows::Win32::System::Services::{
    NotifyServiceStatusChangeW, SC_HANDLE, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_RUNNING,
    SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_NOTIFY_STOPPED,
};
#[cfg(windows)]
use windows::Win32::System::TaskScheduler::ITaskService;
#[cfg(windows)]
use windows::Win32::System::Threading::SleepEx;
#[cfg(windows)]
use windows::Win32::System::Variant::VARIANT;
#[cfg(windows)]
use windows::core::{BSTR, GUID, IUnknown};
#[cfg(windows)]
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceSidType,
    ServiceStartType, ServiceState, ServiceType,
};
#[cfg(windows)]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const DEFAULT_CONTROLLER_ENDPOINT: &str = "http://127.0.0.1:50051";
#[cfg(windows)]
const INSTALLED_CONTROLLER_ADDR: &str = WINDOWS_CONTROLLER_ADDR;
#[cfg(windows)]
const WINDOWS_CONTROLLER_SERVICE_NAME: &str = "EdgePlatformController";
#[cfg(windows)]
const WINDOWS_CONTROLLER_SERVICE_ACCOUNT: &str = r"NT SERVICE\EdgePlatformController";
const PRIVILEGED_REQUEST_SCHEMA_VERSION: u32 = 1;
const PRIVILEGED_RESULT_SCHEMA_VERSION: u32 = 1;
const PRIVILEGED_TASK_NAME: &str = "EdgePlatformPrivilegedDispatch";
#[cfg(windows)]
const HANDOFF_TASK_NAMES: [&str; 4] = [
    "EdgePlatformController",
    "EdgePlatformReconcile",
    "EdgePlatformShutdown",
    "EdgePlatformPrivilegedDispatch",
];
const PRIVILEGED_SHORT_WAIT_SECS: u64 = 180;
const PRIVILEGED_ACTIVATE_WAIT_SECS: u64 = 12 * 60;
const RUNTIME_EVIDENCE_MAX_BYTES: u64 = 16 * 1024;
const RUNTIME_EVIDENCE_MAX_LINES: usize = 80;
const RUNTIME_EVIDENCE_RESULT_MAX_BYTES: usize = 960;
const PRIVILEGED_CHILD_EVIDENCE_MAX_BYTES: usize = 960;
const WINDOWS_TRACE_REOBSERVE_ATTEMPTS: usize = 3;
const WINDOWS_TRACE_REOBSERVE_DELAY: Duration = Duration::from_secs(1);
const DESKTOP_SELECTOR_GROUP: &str = "proxy-selector";
const UBUNTU_SELECTOR_GROUP: &str = "wsl-selector";

pub(crate) fn default_controller_endpoint() -> &'static str {
    #[cfg(windows)]
    {
        if installed_root_from_console().is_ok() {
            return WINDOWS_CONTROLLER_ENDPOINT;
        }
    }
    DEFAULT_CONTROLLER_ENDPOINT
}

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
        Command::PrivilegedRuntimeEvidence(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::RuntimeEvidence as i32,
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
        Command::PrivilegedRollbackPrevious(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::RollbackPreviousRelease as i32,
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
        Command::PrivilegedReinstallAccepted(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::ReinstallAcceptedRelease as i32,
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
        Command::PrivilegedRestartControllerService(args) => {
            let install_root = PathBuf::from(args.install_root);
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::RestartControllerService as i32,
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
        Command::VerifyRuntime => {
            let endpoint = cli::controller_endpoint(None);
            verify_windows_tunnels(&endpoint)
                .await
                .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("runtime_functional=PASS");
            println!("runtime_direct=PASS");
            println!("runtime_warp=PASS");
            Ok(())
        }
        Command::QualityLine1 => {
            let install_root = installed_root_from_console()?;
            let active = load_verified_activation(&install_root)?;
            let installed_console = Path::new(&active.console_path)
                .canonicalize()
                .map_err(|err| format!("Line1 quality cannot verify active console path: {err}"))?;
            let invoked_console = env::current_exe()
                .and_then(|path| path.canonicalize())
                .map_err(|err| {
                    format!("Line1 quality cannot verify invoked console path: {err}")
                })?;
            if installed_console != invoked_console {
                return Err("Line1 quality requires the exact active installed console".into());
            }
            let desired = canonical_production_desired_state()?;
            if desired.windows_datapath_mode != WindowsDatapathMode::ManagedTun as i32 {
                return Err("Line1 quality requires the accepted ManagedTun mode".into());
            }
            let clash = format!("http://127.0.0.1:{STAGE2_CLASH_API_PORT}");
            let report = edge_clash::measure_line1_quality(&clash).await?;
            let observed_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| format!("Line1 quality cannot timestamp observation: {err}"))?
                .as_secs();
            println!("quality_schema=line1-native-delay/v1");
            println!("vantage=WINDOWS");
            println!("observed_at_unix_seconds={observed_at}");
            println!("release_set_sha256={}", active.release_set_sha256);
            println!("probe=sing-box-native-clash-named-outbound-delay");
            println!("metric=HTTPS_URL_TEST_DELAY_ONLY");
            println!(
                "sample_budget_per_outbound={}",
                edge_clash::LINE1_QUALITY_SAMPLES
            );
            println!("selector_mutations=0");
            println!("tunnel_mutations=0");
            println!("selector_before_after=IDENTICAL");
            let mut failures = 0;
            for row in report.rows {
                failures += row.failures;
                let stats = edge_clash::line1_latency_summary(&row.success_ms);
                let (min, median, max) = stats
                    .map(|(min, median, max)| {
                        (min.to_string(), median.to_string(), max.to_string())
                    })
                    .unwrap_or_else(|| {
                        (
                            "UNAVAILABLE".to_owned(),
                            "UNAVAILABLE".to_owned(),
                            "UNAVAILABLE".to_owned(),
                        )
                    });
                println!(
                    "candidate={} successes={} failures={} min_ms={} median_ms={} max_ms={}",
                    row.tag,
                    row.success_ms.len(),
                    row.failures,
                    min,
                    median,
                    max
                );
            }
            if failures > 0 {
                return Err(format!(
                    "Line1 native delay quality had {failures} failed HTTP probes"
                )
                .into());
            }
            println!("quality_status=PASS");
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

fn privileged_wait_secs(request: &WindowsPrivilegedRequest) -> u64 {
    match WindowsPrivilegedOperation::try_from(request.operation) {
        Ok(
            WindowsPrivilegedOperation::ActivateRelease
            | WindowsPrivilegedOperation::RollbackPreviousRelease
            | WindowsPrivilegedOperation::ReinstallAcceptedRelease,
        ) => PRIVILEGED_ACTIVATE_WAIT_SECS,
        _ => PRIVILEGED_SHORT_WAIT_SECS,
    }
}

fn read_matching_privileged_result(
    result_path: &Path,
    request_id: &str,
) -> Result<Option<WindowsPrivilegedResult>, Box<dyn std::error::Error>> {
    match fs::read(result_path) {
        Ok(bytes) => {
            let result = decode_windows_privileged_result(&bytes)?;
            if result.request_id == request_id {
                Ok(Some(result))
            } else {
                Ok(None)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn activation_matches_request(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Option<WindowsActivationState> {
    if !matches!(
        WindowsPrivilegedOperation::try_from(request.operation).ok(),
        Some(WindowsPrivilegedOperation::ActivateRelease)
    ) {
        return None;
    }
    let target_release = request.release_set_sha256.as_deref()?;
    let activation = load_verified_activation(install_root).ok()?;
    (activation.release_set_sha256 == target_release).then_some(activation)
}

fn reconcile_completed_privileged_exchange(
    install_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_path = privileged_request_path(install_root);
    if !request_path.exists() {
        return Ok(());
    }

    let pending_bytes = fs::read(&request_path)?;
    let pending = decode_windows_privileged_request(&pending_bytes)?;
    let result_path = privileged_result_path(install_root);

    if read_matching_privileged_result(&result_path, &pending.request_id)?.is_some() {
        fs::remove_file(&request_path)?;
        return Ok(());
    }

    let age = fs::metadata(&request_path)?
        .modified()?
        .elapsed()
        .unwrap_or_default();
    if age >= Duration::from_secs(PRIVILEGED_ACTIVATE_WAIT_SECS)
        && activation_matches_request(install_root, &pending).is_some()
    {
        fs::remove_file(&request_path)?;
        return Ok(());
    }

    Err(format!(
        "privileged Windows request is still pending: request_id={} operation={}; do not retry blindly",
        pending.request_id, pending.operation
    )
    .into())
}

fn submit_privileged_request(
    install_root: &Path,
    request: WindowsPrivilegedRequest,
) -> Result<WindowsPrivilegedResult, Box<dyn std::error::Error>> {
    reconcile_completed_privileged_exchange(install_root)?;

    let request_path = privileged_request_path(install_root);
    let bytes = encode_windows_privileged_request(&request)?;
    write_atomic(&request_path, &bytes)?;

    let result_path = privileged_result_path(install_root);
    let wait_secs = privileged_wait_secs(&request);
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    while Instant::now() < deadline {
        if let Some(result) = read_matching_privileged_result(&result_path, &request.request_id)? {
            return Ok(result);
        }
        thread::sleep(Duration::from_millis(500));
    }

    if let Some(result) = read_matching_privileged_result(&result_path, &request.request_id)? {
        return Ok(result);
    }

    if let Some(activation) = activation_matches_request(install_root, &request) {
        reconcile_completed_privileged_exchange(install_root)?;
        return Ok(WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: request.request_id,
            success: true,
            code: "RELEASE_CONVERGED_REOBSERVED".to_owned(),
            detail: "exact target ReleaseSet is active after bounded activation wait".to_owned(),
            active_release_set_sha256: Some(activation.release_set_sha256),
        });
    }

    Err(format!(
        "privileged Windows request outcome is uncertain after {wait_secs} seconds: request_id={} operation={}; do not retry blindly",
        request.request_id, request.operation
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
            activate_privileged_release(install_root, request, false)
        }
        Ok(WindowsPrivilegedOperation::RollbackPreviousRelease) => {
            rollback_privileged_release(install_root)
        }
        Ok(WindowsPrivilegedOperation::ReinstallAcceptedRelease) => {
            activate_privileged_release(install_root, request, true)
        }
        Ok(WindowsPrivilegedOperation::StageCredential) => {
            stage_windows_credential_candidate_from_worker(install_root, request).await
        }
        Ok(WindowsPrivilegedOperation::AdmitCredential) => Err(
            "ADMIT_CREDENTIAL is retired; exact-generation STAGE_CREDENTIAL is the sole credential data-plane gate"
                .to_owned(),
        ),
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
        Ok(WindowsPrivilegedOperation::RuntimeEvidence) => {
            let active = load_verified_activation(install_root)
                .ok()
                .map(|state| state.release_set_sha256);
            read_bounded_windows_runtime_evidence(install_root)
                .map(|detail| ("RUNTIME_EVIDENCE_READ".to_owned(), detail, active))
        }
        Ok(WindowsPrivilegedOperation::RestartControllerService) => {
            #[cfg(windows)]
            {
                restart_controller_service(install_root)
            }
            #[cfg(not(windows))]
            {
                Err("RESTART_CONTROLLER_SERVICE is Windows-only".to_owned())
            }
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

fn bounded_privileged_child_evidence(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout =
        compact_runtime_evidence_line(&redact_runtime_evidence(&String::from_utf8_lossy(stdout)));
    let stderr =
        compact_runtime_evidence_line(&redact_runtime_evidence(&String::from_utf8_lossy(stderr)));
    let detail = format!(
        "installer_evidence=BOUNDED;stderr={};stdout={}",
        if stderr.is_empty() { "EMPTY" } else { &stderr },
        if stdout.is_empty() { "EMPTY" } else { &stdout }
    );
    truncate_runtime_evidence(&detail, PRIVILEGED_CHILD_EVIDENCE_MAX_BYTES)
}

fn read_bounded_windows_runtime_evidence(install_root: &Path) -> Result<String, String> {
    let runtime_root = install_root.join("runtime");
    #[cfg(windows)]
    let controller_error = read_controller_service_error_evidence(install_root)?;
    #[cfg(not(windows))]
    let controller_error = "controller_service_error=WINDOWS_ONLY".to_owned();
    #[cfg(windows)]
    let process_classification = read_runtime_process_classification_evidence(install_root)?;
    #[cfg(not(windows))]
    let process_classification = "process_classification=WINDOWS_ONLY".to_owned();
    #[cfg(windows)]
    let scheduled_tasks = read_handoff_task_evidence()?;
    #[cfg(not(windows))]
    let scheduled_tasks = "scheduled_tasks=WINDOWS_ONLY".to_owned();
    #[cfg(windows)]
    let external_owner = read_external_owner_restore_evidence(install_root)?;
    #[cfg(not(windows))]
    let external_owner = "external_owner_evidence=WINDOWS_ONLY".to_owned();
    let critical = format!(
        "runtime_evidence=BOUNDED_READ_ONLY;{controller_error};{process_classification};{scheduled_tasks};{external_owner}"
    );
    if critical.len() > RUNTIME_EVIDENCE_RESULT_MAX_BYTES {
        return Err(format!(
            "critical runtime evidence exceeds bounded result contract: {} > {}",
            critical.len(),
            RUNTIME_EVIDENCE_RESULT_MAX_BYTES
        ));
    }

    let stderr =
        read_bounded_runtime_log_tail(&runtime_root.join("sing-box.stderr.log"), "stderr")?;
    let stdout =
        read_bounded_runtime_log_tail(&runtime_root.join("sing-box.stdout.log"), "stdout")?;
    let optional = format!(";{stderr};{stdout}");
    let remaining = RUNTIME_EVIDENCE_RESULT_MAX_BYTES - critical.len();
    if optional.len() <= remaining {
        return Ok(format!("{critical}{optional}"));
    }
    if remaining <= 32 {
        return Ok(critical);
    }
    Ok(format!(
        "{critical}{}",
        truncate_runtime_evidence(&optional, remaining)
    ))
}

#[cfg(windows)]
fn read_controller_service_error_evidence(install_root: &Path) -> Result<String, String> {
    let path = install_root
        .join("logs")
        .join("controller-service-error.txt");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok("controller_service_error=ABSENT".to_owned());
        }
        Err(err) => {
            return Err(format!(
                "failed to read controller service error evidence: {err}"
            ));
        }
    };
    if bytes.len() > 512 {
        return Ok("controller_service_error=INVALID_OVERSIZE".to_owned());
    }
    let text = String::from_utf8_lossy(&bytes);
    let compact = compact_runtime_evidence_line(&redact_runtime_evidence(&text));
    Ok(format!(
        "controller_service_error={}",
        evidence_field(&truncate_runtime_evidence(&compact, 192))
    ))
}

#[cfg(windows)]
fn current_controller_service_pid() -> Result<Option<u32>, String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("failed to open Windows SCM for process evidence: {err}"))?;
    let service = manager
        .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(|err| format!("failed to open controller service for process evidence: {err}"))?;
    service
        .query_status()
        .map(|status| status.process_id)
        .map_err(|err| format!("failed to query controller service process evidence: {err}"))
}

#[cfg(windows)]
fn read_runtime_process_classification_evidence(install_root: &Path) -> Result<String, String> {
    let managed_config = local_singbox_config_path(install_root);
    let controller_pid = current_controller_service_pid()?;
    let (classification, complete, count, pid, parent_pid) =
        match classify_runtime_process(&managed_config) {
            RuntimeProcessClassification::Absent => ("ABSENT", true, 0usize, None, None),
            RuntimeProcessClassification::Managed(process) => {
                let is_current_child =
                    controller_pid.is_some() && process.parent_pid == controller_pid;
                let complete = process.executable_path.is_some()
                    && !process.command_line.is_empty()
                    && process.config_path.is_some();
                (
                    if is_current_child {
                        "MANAGED"
                    } else {
                        "ORPHAN"
                    },
                    complete,
                    1,
                    Some(process.pid),
                    process.parent_pid,
                )
            }
            RuntimeProcessClassification::Conflicting(processes) => {
                let complete = processes.iter().all(|process| {
                    process.executable_path.is_some() && !process.command_line.is_empty()
                });
                ("CONFLICTING", complete, processes.len(), None, None)
            }
        };
    Ok(format!(
        "process_classification={classification};process_evidence_complete={complete};process_count={count};managed_pid={};managed_parent_pid={};controller_pid={}",
        pid.map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        parent_pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        controller_pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
    ))
}

#[cfg(windows)]
struct TaskSchedulerComGuard;

#[cfg(windows)]
impl Drop for TaskSchedulerComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

#[cfg(windows)]
fn sha256_evidence(value: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(windows)]
fn read_handoff_task_evidence() -> Result<String, String> {
    let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if hr.is_err() {
        return Err(format!(
            "failed to initialize COM for privileged Task Scheduler evidence: {hr:?}"
        ));
    }
    let _guard = TaskSchedulerComGuard;

    let task_scheduler_clsid = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
    let service: ITaskService = unsafe {
        CoCreateInstance(
            &task_scheduler_clsid,
            None::<&IUnknown>,
            CLSCTX_INPROC_SERVER,
        )
    }
    .map_err(|err| format!("failed to create Task Scheduler service: {err}"))?;

    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|err| format!("failed to connect Task Scheduler service: {err}"))?;
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|err| format!("failed to open Task Scheduler root folder: {err}"))?;

    let mut observed = Vec::with_capacity(HANDOFF_TASK_NAMES.len());
    for name in HANDOFF_TASK_NAMES {
        let task = unsafe { root.GetTask(&BSTR::from(name)) }
            .map_err(|err| format!("failed to query scheduled task {name}: {err}"))?;
        let enabled = unsafe { task.Enabled() }
            .map_err(|err| format!("failed to query scheduled task {name} enabled state: {err}"))?;
        let state = unsafe { task.State() }
            .map_err(|err| format!("failed to query scheduled task {name} state: {err}"))?;
        let xml = unsafe { task.Xml() }
            .map_err(|err| format!("failed to query scheduled task {name} definition: {err}"))?;
        observed.push(format!(
            "{name}|{}|{}|{}",
            if enabled.0 != 0 { "1" } else { "0" },
            state.0,
            sha256_evidence(&xml.to_string())
        ));
    }
    Ok(format!("tasks={}", observed.join(",")))
}

#[cfg(windows)]
fn evidence_path_matches(observed: &str, expected: &Path) -> bool {
    let observed = Path::new(observed);
    if observed == expected {
        return true;
    }
    match (observed.canonicalize(), expected.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(windows)]
fn evidence_field(value: &str) -> String {
    compact_runtime_evidence_line(value).replace(';', "%3B")
}

#[cfg(windows)]
fn external_startup_owner_kind(
    parent: Option<&edge_local_runtime::ProcessObservation>,
) -> &'static str {
    let Some(parent) = parent else {
        return "PARENT_ABSENT";
    };
    let name = parent.name.to_ascii_lowercase();
    let command = parent.command_line.to_ascii_lowercase();
    if name.contains("powershell") || name == "pwsh.exe" || name == "pwsh" {
        if command.contains("singbox-dual-menu.ps1") {
            "POWERSHELL_MENU"
        } else if command.contains("start-vultr-edge-session.ps1") {
            "POWERSHELL_SESSION"
        } else if command.contains("sing-box") {
            "POWERSHELL_DIRECT"
        } else {
            "POWERSHELL_PARENT"
        }
    } else if name == "cmd.exe" || name == "cmd" {
        "CMD_PARENT"
    } else {
        "OTHER_LIVE_PARENT"
    }
}

#[cfg(windows)]
fn read_external_owner_restore_evidence(install_root: &Path) -> Result<String, String> {
    let managed_config = local_singbox_config_path(install_root);
    let observed = match classify_runtime_process(&managed_config) {
        RuntimeProcessClassification::Managed(process) => vec![process],
        RuntimeProcessClassification::Conflicting(processes) => processes,
        RuntimeProcessClassification::Absent => Vec::new(),
    };
    let external = observed
        .into_iter()
        .filter(|process| {
            !process
                .config_path
                .as_deref()
                .is_some_and(|path| evidence_path_matches(path, &managed_config))
        })
        .collect::<Vec<_>>();
    if external.len() != 1 {
        return Ok(format!(
            "external_owner_evidence=INCOMPLETE;external_count={}",
            external.len()
        ));
    }

    let process = &external[0];
    let parent = process.parent_pid.and_then(observe_process);
    let executable = process.executable_path.as_deref().unwrap_or("UNKNOWN");
    let config = process.config_path.as_deref().unwrap_or("UNKNOWN");
    let executable_exists = executable != "UNKNOWN" && Path::new(executable).is_file();
    let config_exists = config != "UNKNOWN" && Path::new(config).is_file();
    let command_shape = process.command_line.to_ascii_lowercase().contains(" run ")
        && process.config_path.is_some();

    let check_pass = if executable_exists && config_exists {
        Command::new(executable)
            .args(["check", "-c", config])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    } else {
        false
    };
    let owner_kind = external_startup_owner_kind(parent.as_ref());
    let parent_alive = parent.is_some();
    let restore_preflight =
        executable_exists && config_exists && command_shape && check_pass && parent_alive;

    Ok(format!(
        "external_owner_evidence=BOUNDED_READ_ONLY;external_pid={};external_exe={};external_config={};external_run_shape={};external_exe_exists={};external_config_exists={};external_check={};parent_pid={};parent_name={};parent_exe={};startup_owner={};restore_preflight={}",
        process.pid,
        evidence_field(executable),
        evidence_field(config),
        command_shape,
        executable_exists,
        config_exists,
        if check_pass { "PASS" } else { "FAIL" },
        process
            .parent_pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        parent
            .as_ref()
            .map(|value| evidence_field(&value.name))
            .unwrap_or_else(|| "ABSENT".to_owned()),
        parent
            .as_ref()
            .and_then(|value| value.executable_path.as_deref())
            .map(evidence_field)
            .unwrap_or_else(|| "ABSENT".to_owned()),
        owner_kind,
        if restore_preflight { "PASS" } else { "FAIL" },
    ))
}

fn read_bounded_runtime_log_tail(path: &Path, label: &str) -> Result<String, String> {
    if !path.is_file() {
        return Ok(format!("{label}=MISSING"));
    }

    let mut file = File::open(path).map_err(|err| {
        format!(
            "failed to open managed runtime log {}: {err}",
            path.display()
        )
    })?;
    let len = file
        .metadata()
        .map_err(|err| {
            format!(
                "failed to stat managed runtime log {}: {err}",
                path.display()
            )
        })?
        .len();
    let start = len.saturating_sub(RUNTIME_EVIDENCE_MAX_BYTES);
    file.seek(SeekFrom::Start(start)).map_err(|err| {
        format!(
            "failed to seek managed runtime log {}: {err}",
            path.display()
        )
    })?;

    let mut bytes = Vec::with_capacity((len - start) as usize);
    file.read_to_end(&mut bytes).map_err(|err| {
        format!(
            "failed to read managed runtime log {}: {err}",
            path.display()
        )
    })?;
    let text = String::from_utf8_lossy(&bytes);
    let lines = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .rev()
        .take(RUNTIME_EVIDENCE_MAX_LINES)
        .collect::<Vec<_>>();

    let prioritized = lines
        .iter()
        .copied()
        .filter(|line| is_runtime_evidence_priority(line))
        .take(6)
        .collect::<Vec<_>>();
    let selected = if prioritized.is_empty() {
        lines.iter().copied().take(4).collect::<Vec<_>>()
    } else {
        prioritized
    };

    let compact = selected
        .into_iter()
        .map(redact_runtime_evidence)
        .map(|line| compact_runtime_evidence_line(&line))
        .collect::<Vec<_>>()
        .join(" | ");
    Ok(format!(
        "{label}=truncated:{} bytes:{} {}",
        start > 0,
        bytes.len(),
        compact
    ))
}

fn is_runtime_evidence_priority(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "error",
        "fail",
        "warn",
        "dial",
        "connect",
        "dns",
        "tls",
        "hysteria",
        "vless",
        "timeout",
        "refused",
        "unreachable",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn compact_runtime_evidence_line(line: &str) -> String {
    line.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate_runtime_evidence(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    const SUFFIX: &str = "...[truncated]";
    let mut truncated = value[..end].to_owned();
    while truncated.len() + SUFFIX.len() > max_bytes {
        truncated.pop();
    }
    truncated.push_str(SUFFIX);
    truncated
}

fn redact_runtime_evidence(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut token = String::new();

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            token.push(ch);
        } else {
            append_redacted_runtime_token(&mut output, &mut token);
            output.push(ch);
        }
    }
    append_redacted_runtime_token(&mut output, &mut token);
    output
}

fn append_redacted_runtime_token(output: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }
    let is_uuid = token.len() == 36
        && token.chars().enumerate().all(|(index, ch)| match index {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit(),
        });
    let is_long_hex = token.len() >= 16 && token.bytes().all(|byte| byte.is_ascii_hexdigit());

    if is_uuid {
        output.push_str("<redacted-uuid>");
    } else if is_long_hex {
        output.push_str("<redacted-hex>");
    } else {
        output.push_str(token);
    }
    token.clear();
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
    let state = store.stage_delivery_candidate(&bundle)?;
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

fn require_supported_reinstall_authority() -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "canonical production Windows datapath mode is invalid".to_owned())?;
    match mode {
        WindowsDatapathMode::ProxyOnly | WindowsDatapathMode::ManagedTun => Ok(()),
        WindowsDatapathMode::Unspecified => Err(
            "accepted-release reinstall requires an explicit supported Windows datapath mode"
                .to_owned(),
        ),
    }
}

fn activate_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
    force_rematerialize: bool,
) -> Result<(String, String, Option<String>), String> {
    let accepted_revision = request
        .accepted_revision
        .as_deref()
        .ok_or_else(|| "accepted_revision is required".to_owned())?;
    let target_release = request
        .release_set_sha256
        .as_deref()
        .ok_or_else(|| "release_set_sha256 is required".to_owned())?;

    let before_activation = load_verified_activation(install_root).ok();
    let mut previous_bytes_before = None;

    let restore_verified_owner = |activation: &WindowsActivationState| -> Result<(), String> {
        sync_stable_windows_release_tools(install_root, activation)?;
        reconcile_activation_owner(install_root, activation)
    };

    if force_rematerialize {
        require_supported_reinstall_authority()?;
        let current = before_activation.as_ref().ok_or_else(|| {
            "accepted-release reinstall requires a verified current activation".to_owned()
        })?;
        if current.release_set_sha256 != target_release {
            return Err(
                "accepted-release reinstall target must equal the exact current ReleaseSet"
                    .to_owned(),
            );
        }
        let (_, previous) = load_previous_release_rollback_pair(install_root)?;
        if previous.release_set_sha256 == target_release {
            return Err(
                "accepted-release reinstall requires a distinct verified previous.pb rollback target"
                    .to_owned(),
            );
        }
        previous_bytes_before =
            Some(fs::read(install_root.join("previous.pb")).map_err(|err| {
                format!("failed to snapshot previous.pb before reinstall: {err}")
            })?);
    } else if let Some(activation) = before_activation.as_ref()
        && activation.release_set_sha256 == target_release
    {
        reconcile_activation_owner(install_root, activation)?;
        return Ok((
            "RELEASE_ALREADY_CONVERGED".to_owned(),
            "exact target ReleaseSet is already locally verified; installer not invoked; exact owner handoff reconciled".to_owned(),
            Some(activation.release_set_sha256.clone()),
        ));
    }

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

    stop_runtime_process(&local_singbox_config_path(install_root), true).map_err(|err| {
        format!("failed to stop exact managed proxy before release transition: {err}")
    })?;

    let mut command = Command::new("powershell.exe");
    command
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
        ]);
    if force_rematerialize {
        command.arg("-ForceRematerialize");
    }
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("failed to start protected Windows installer: {err}"))?;

    if !output.status.success() {
        if force_rematerialize {
            if let Ok(observed) = load_verified_activation(install_root)
                && observed.release_set_sha256 == target_release
                && before_activation
                    .as_ref()
                    .is_some_and(|before| before.release_dir != observed.release_dir)
            {
                if let Some(expected_previous) = previous_bytes_before.as_ref()
                    && fs::read(install_root.join("previous.pb")).ok().as_ref()
                        != Some(expected_previous)
                {
                    let _ = write_atomic(&install_root.join("previous.pb"), expected_previous);
                    reconcile_activation_owner(install_root, &observed)?;
                    return Err(
                        "accepted release rematerialized but previous.pb changed unexpectedly; rollback authority was restored"
                            .to_owned(),
                    );
                }
                reconcile_activation_owner(install_root, &observed)?;
                return Ok((
                    "RELEASE_REINSTALLED_REOBSERVED".to_owned(),
                    "alternate immutable release slot committed despite installer exit failure; exact authority was reobserved and owner handoff reconciled"
                        .to_owned(),
                    Some(observed.release_set_sha256),
                ));
            }

            if let Some(before) = before_activation.as_ref() {
                restore_verified_owner(before)?;
            }
            return Err(format!(
                "protected Windows reinstall failed with exit code {}; {}",
                output.status.code().unwrap_or(-1),
                bounded_privileged_child_evidence(&output.stdout, &output.stderr)
            ));
        }

        if let Ok(activation) = load_verified_activation(install_root)
            && activation.release_set_sha256 == target_release
        {
            reconcile_activation_owner(install_root, &activation)?;
            return Ok((
                "RELEASE_CONVERGED_REOBSERVED".to_owned(),
                "exact target ReleaseSet committed despite installer failure; local owner handoff reconciled"
                    .to_owned(),
                Some(activation.release_set_sha256),
            ));
        }

        if let Some(before) = before_activation.as_ref() {
            restore_verified_owner(before)?;
        }
        return Err(format!(
            "protected Windows installer failed with exit code {}; {}",
            output.status.code().unwrap_or(-1),
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        ));
    }

    let activation = load_verified_activation(install_root)
        .map_err(|err| format!("updated Windows activation failed verification: {err}"))?;
    if activation.release_set_sha256 != target_release {
        return Err("updated Windows activation does not match requested ReleaseSet".to_owned());
    }

    if force_rematerialize {
        let before = before_activation
            .as_ref()
            .ok_or_else(|| "reinstall lost its pre-mutation activation snapshot".to_owned())?;
        if activation.release_dir == before.release_dir {
            reconcile_activation_owner(install_root, &activation)?;
            return Err(
                "accepted-release reinstall did not switch to the alternate immutable release slot"
                    .to_owned(),
            );
        }
        if let Some(expected_previous) = previous_bytes_before.as_ref() {
            let observed_previous = fs::read(install_root.join("previous.pb"))
                .map_err(|err| format!("failed to verify previous.pb after reinstall: {err}"))?;
            if &observed_previous != expected_previous {
                write_atomic(&install_root.join("previous.pb"), expected_previous).map_err(
                    |err| format!("failed to restore previous.pb after reinstall: {err}"),
                )?;
                reconcile_activation_owner(install_root, &activation)?;
                return Err(
                    "accepted-release reinstall changed previous.pb; exact prior rollback authority was restored"
                        .to_owned(),
                );
            }
        }
    }

    reconcile_activation_owner(install_root, &activation)?;
    Ok((
        if force_rematerialize {
            "RELEASE_REINSTALLED".to_owned()
        } else {
            "RELEASE_CONVERGED".to_owned()
        },
        if force_rematerialize {
            "exact accepted ReleaseSet was downloaded again, verified, activated from the alternate immutable slot, and previous.pb was preserved"
                .to_owned()
        } else {
            "exact accepted ReleaseSet and controller service are active".to_owned()
        },
        Some(activation.release_set_sha256),
    ))
}

fn load_previous_release_rollback_pair(
    install_root: &Path,
) -> Result<(WindowsActivationState, WindowsActivationState), String> {
    let current_path = install_root.join("current.pb");
    let previous_path = install_root.join("previous.pb");
    if !previous_path.is_file() {
        return Err(
            "previous.pb is absent; bounded Windows ReleaseSet rollback has no target".to_owned(),
        );
    }

    let current = load_verified_activation_path(install_root, &current_path, "current.pb")
        .map_err(|err| err.to_string())?;
    let previous = load_verified_activation_path(install_root, &previous_path, "previous.pb")
        .map_err(|err| err.to_string())?;
    if current.release_set_sha256 == previous.release_set_sha256 {
        return Err("current.pb and previous.pb identify the same ReleaseSet".to_owned());
    }
    Ok((current, previous))
}

fn sync_stable_windows_release_tools(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    let bin_dir = install_root.join("bin");
    fs::create_dir_all(&bin_dir)
        .map_err(|err| format!("failed to prepare stable Windows binary directory: {err}"))?;

    for (source, target_name, label) in [
        (&activation.console_path, "edge-console.exe", "console"),
        (
            &activation.diagnostic_path,
            "edge-diagnostic.exe",
            "diagnostic",
        ),
    ] {
        let bytes = fs::read(source).map_err(|err| {
            format!("failed to read exact {label} for stable rollback boundary: {err}")
        })?;
        let target = bin_dir.join(target_name);
        write_atomic(&target, &bytes)
            .map_err(|err| format!("failed to refresh stable Windows {label}: {err}"))?;
        let observed = fs::read(&target)
            .map_err(|err| format!("failed to verify stable Windows {label}: {err}"))?;
        if observed != bytes {
            return Err(format!(
                "stable Windows {label} does not match the exact activation after refresh"
            ));
        }
    }
    Ok(())
}

fn rollback_privileged_release(
    install_root: &Path,
) -> Result<(String, String, Option<String>), String> {
    let current_path = install_root.join("current.pb");
    let previous_path = install_root.join("previous.pb");
    let (current, previous) = load_previous_release_rollback_pair(install_root)?;

    let managed_config = local_singbox_config_path(install_root);
    stop_runtime_process(&managed_config, true)
        .map_err(|err| format!("failed to stop exact managed runtime before rollback: {err}"))?;

    let current_bytes = fs::read(&current_path)
        .map_err(|err| format!("failed to snapshot current.pb before rollback: {err}"))?;
    let previous_bytes = fs::read(&previous_path)
        .map_err(|err| format!("failed to snapshot previous.pb before rollback: {err}"))?;

    if let Err(err) = write_atomic(&current_path, &previous_bytes) {
        let _ = write_atomic(&current_path, &current_bytes);
        return Err(format!(
            "failed to activate exact previous Windows authority; original current activation restored: {err}"
        ));
    }

    let handoff = (|| -> Result<(), String> {
        sync_stable_windows_release_tools(install_root, &previous)?;
        reconcile_activation_owner(install_root, &previous)
    })();
    if let Err(err) = handoff {
        let pointer_restore = write_atomic(&current_path, &current_bytes);
        let owner_restore = sync_stable_windows_release_tools(install_root, &current)
            .and_then(|_| reconcile_activation_owner(install_root, &current));
        return Err(format!(
            "previous ReleaseSet activation handoff failed: {err}; pointer_restore={pointer_restore:?}; owner_restore={owner_restore:?}"
        ));
    }

    let verified = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    if verified.release_set_sha256 != previous.release_set_sha256 {
        return Err(
            "post-rollback activation verification did not match exact previous.pb".to_owned(),
        );
    }

    Ok((
        "PREVIOUS_RELEASE_ROLLED_BACK".to_owned(),
        "exact previous ReleaseSet restored locally without swapping rollback authority; repeated rollback is fail-closed because current.pb now equals previous.pb"
            .to_owned(),
        Some(verified.release_set_sha256),
    ))
}

fn reconcile_activation_owner(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    retarget_privileged_task(install_root, &activation.console_path)?;
    #[cfg(windows)]
    converge_controller_service_with_activation_console(install_root, activation)?;
    Ok(())
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

    let mut last_unavailable = "trace unavailable without provider detail".to_owned();
    for attempt in 1..=WINDOWS_TRACE_REOBSERVE_ATTEMPTS {
        match fetch_trace(endpoint.to_owned()).await {
            Ok(trace) if trace.available && trace.ip.is_some() => {
                if trace.warp.as_deref() != Some(expected_warp) {
                    return Err(format!(
                        "route {route} expected Cloudflare warp={expected_warp}, observed {:?}",
                        trace.warp
                    ));
                }
                return Ok(());
            }
            Ok(trace) => {
                last_unavailable = trace
                    .note
                    .unwrap_or_else(|| "trace unavailable without provider detail".to_owned());
            }
            Err(err) => {
                last_unavailable = format!("controller trace RPC failed: {err}");
            }
        }

        if attempt < WINDOWS_TRACE_REOBSERVE_ATTEMPTS {
            tokio::time::sleep(WINDOWS_TRACE_REOBSERVE_DELAY).await;
        }
    }

    Err(format!(
        "Cloudflare trace is unavailable for route {route} after {WINDOWS_TRACE_REOBSERVE_ATTEMPTS} bounded observations: {last_unavailable}"
    ))
}

// Always run the restore after a bounded route check, even if either trace fails.
// This is in-process compensation, not a durable promise across forced termination.
async fn verify_routes_with_restore<F, Fut, R, RestoreFut>(
    original: String,
    mut verify: F,
    restore: R,
) -> Result<(), String>
where
    F: FnMut(&'static str, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
    R: FnOnce(String) -> RestoreFut,
    RestoreFut: std::future::Future<Output = Result<(), String>>,
{
    let result = async {
        verify("auto-direct-tunnel", "off").await?;
        verify("auto-warp-tunnel", "on").await
    }
    .await;
    // Explicitly compensate after either success or failure of the checks.
    let restored = restore(original).await;
    match (result, restored) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(verification_error), Ok(())) => Err(format!(
            "Windows tunnel verification failed; original selector restored: {verification_error}"
        )),
        (Ok(()), Err(restore_error)) => Err(format!(
            "Windows tunnel checks passed but original selector restoration is unverified: {restore_error}"
        )),
        (Err(verification_error), Err(restore_error)) => Err(format!(
            "Windows tunnel verification failed: {verification_error}; original selector restoration is unverified: {restore_error}"
        )),
    }
}

async fn restore_windows_tunnel_selector(endpoint: &str, original: &str) -> Result<(), String> {
    let restore = set_selector(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP, original)
        .await
        .map_err(|err| err.to_string())?;
    if !restore.success {
        return Err(format!("selector restore RPC rejected route {original}"));
    }
    let observed = fetch_selector_state(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP)
        .await
        .map_err(|err| err.to_string())?;
    if observed.observed_main_route.as_deref() != Some(original) {
        return Err(format!(
            "selector restore read-back mismatch: expected {original}, observed {:?}",
            observed.observed_main_route
        ));
    }
    Ok(())
}

fn observed_restore_route(selector: SelectorState) -> Result<String, String> {
    // Policy is NOT a safe fallback if the live current selector is unknown.
    selector.observed_main_route.ok_or_else(|| {
        "Windows selector has no observed restorable route; no mutation made".to_owned()
    })
}

async fn verify_windows_tunnels(endpoint: &str) -> Result<(), String> {
    let selector = fetch_selector_state(endpoint.to_owned(), DESKTOP_SELECTOR_GROUP)
        .await
        .map_err(|err| err.to_string())?;
    let original = observed_restore_route(selector)?;
    verify_routes_with_restore(
        original,
        |route, expected_warp| verify_windows_tunnel_route(endpoint, route, expected_warp),
        |original| async move { restore_windows_tunnel_selector(endpoint, &original).await },
    )
    .await
}

async fn restart_and_verify_windows_tunnels(endpoint: &str) -> Result<(), String> {
    let restart = restart_local(endpoint.to_owned())
        .await
        .map_err(|err| err.to_string())?;
    if !restart.success {
        // A failed restart is already an uncertain runtime state. Do not issue
        // an unrelated stop as "cleanup" on a shared Windows network host.
        return Err(format!(
            "Windows local runtime restart failed; no automatic stop attempted: {}",
            restart.note
        ));
    }
    verify_windows_tunnels(endpoint).await
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

    restart_and_verify_windows_tunnels(&endpoint).await?;

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
    load_verified_activation_path(install_root, &install_root.join("current.pb"), "current.pb")
}

fn load_verified_activation_path(
    install_root: &Path,
    state_path: &Path,
    label: &str,
) -> Result<WindowsActivationState, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(state_path)?;
    let state = decode_windows_activation_state(&bytes)?;
    verify_windows_activation_files(&state)?;

    let releases_root = install_root.join("releases").canonicalize()?;
    let release_dir = PathBuf::from(&state.release_dir).canonicalize()?;
    let controller = PathBuf::from(&state.controller_path).canonicalize()?;
    if !release_dir.starts_with(&releases_root) {
        return Err(format!("{label} release_dir is outside the immutable releases root").into());
    }
    if !controller.starts_with(&release_dir) {
        return Err(
            format!("{label} controller_path is outside its immutable release directory").into(),
        );
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

fn controller_is_listening(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

fn ensure_controller_running(endpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    let Some(addr) = parse_loopback_addr(endpoint) else {
        return Ok(());
    };
    if controller_is_listening(addr) {
        return Ok(());
    }

    let install_root = installed_root_from_console()?;
    let _activation = load_verified_activation(&install_root)?;
    Err(format!(
        "SCM-owned EdgePlatformController is not listening on {addr}; edge-console does not own controller startup"
    )
    .into())
}

#[cfg(windows)]
unsafe extern "system" fn service_status_notification_callback(_parameter: *const c_void) {}

#[cfg(windows)]
fn wait_for_service_state(
    service: &Service,
    expected: ServiceState,
    timeout: Duration,
) -> Result<(), String> {
    wait_for_service_state_any(service, &[expected], timeout).map(|_| ())
}

#[cfg(windows)]
fn wait_for_service_state_any(
    service: &Service,
    expected: &[ServiceState],
    timeout: Duration,
) -> Result<ServiceState, String> {
    let notify_mask = match expected {
        [ServiceState::Running] => SERVICE_NOTIFY_RUNNING,
        [ServiceState::Stopped] => SERVICE_NOTIFY_STOPPED,
        [ServiceState::Running, ServiceState::Stopped]
        | [ServiceState::Stopped, ServiceState::Running] => {
            SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED
        }
        _ => {
            return Err(format!(
                "unsupported controller service notification targets: {expected:?}"
            ));
        }
    };

    let initial = service
        .query_status()
        .map_err(|err| format!("failed to query controller service state: {err}"))?;
    if expected.contains(&initial.current_state) {
        return Ok(initial.current_state);
    }

    let monitor_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|err| format!("failed to open SCM for status notification: {err}"))?;
    let monitor = monitor_manager
        .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(|err| format!("failed to open controller service notification handle: {err}"))?;
    let mut notification = SERVICE_NOTIFY_2W {
        dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
        pfnNotifyCallback: Some(service_status_notification_callback),
        ..Default::default()
    };
    let registration = unsafe {
        NotifyServiceStatusChangeW(
            SC_HANDLE(monitor.raw_handle()),
            notify_mask,
            &mut notification,
        )
    };
    if registration != 0 {
        return Err(format!(
            "failed to register controller service status notification: win32={registration}"
        ));
    }

    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let wait_ms = u32::try_from(remaining.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        let wait_result = unsafe { SleepEx(wait_ms, true) };
        if wait_result == 0 {
            break;
        }
        if wait_result != WAIT_IO_COMPLETION.0 {
            drop(monitor);
            return Err(format!(
                "unexpected alertable SCM wait result: {wait_result}"
            ));
        }
        if notification.dwNotificationTriggered & notify_mask.0 == 0 {
            continue;
        }
        if notification.dwNotificationStatus != 0 {
            drop(monitor);
            return Err(format!(
                "controller service status notification failed: win32={}",
                notification.dwNotificationStatus
            ));
        }

        let observed = monitor
            .query_status()
            .map_err(|err| format!("failed to query notified controller service state: {err}"))?;
        if expected.contains(&observed.current_state) {
            return Ok(observed.current_state);
        }
        drop(monitor);
        return Err(format!(
            "controller service notification targeted {expected:?} but observed {:?}",
            observed.current_state
        ));
    }

    drop(monitor);
    let observed = service.query_status().map_err(|err| {
        format!("failed to query controller service after notification timeout: {err}")
    })?;
    Err(format!(
        "controller service did not reach {expected:?} within {} seconds; observed {:?}",
        timeout.as_secs(),
        observed.current_state
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
fn converge_controller_tun_authority() -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "canonical production Windows datapath mode is invalid".to_owned())?;
    if mode != WindowsDatapathMode::ManagedTun {
        return Ok(());
    }

    let script = r#"
$ErrorActionPreference = 'Stop'
$administrators = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$account = New-Object System.Security.Principal.NTAccount('NT SERVICE', 'EdgePlatformController')
$serviceSid = $account.Translate([System.Security.Principal.SecurityIdentifier])
$members = @(Get-LocalGroupMember -SID $administrators)
if (-not ($members | Where-Object { $_.SID -eq $serviceSid })) {
    Add-LocalGroupMember -SID $administrators -Member $serviceSid.Value
}
$verified = @(Get-LocalGroupMember -SID $administrators | Where-Object { $_.SID -eq $serviceSid })
if ($verified.Count -ne 1) {
    throw 'EdgePlatformController service SID is not a member of the local Administrators group'
}
"#;

    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| {
            format!("failed to start bounded Windows TUN authority convergence: {err}")
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "failed to converge EdgePlatformController administrator-class TUN authority: exit={}",
            status.code().unwrap_or(-1)
        ))
    }
}

#[cfg(windows)]
fn converge_controller_service_with_activation_console(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    let console = Path::new(&activation.console_path);
    if !console.is_file() {
        return Err(format!(
            "exact activation console is missing for controller handoff: {}",
            console.display()
        ));
    }
    let root = install_root
        .to_str()
        .ok_or_else(|| "Windows install root is not UTF-8".to_owned())?;
    let output = Command::new(console)
        .args([
            "privileged-converge-controller-service",
            "--install-root",
            root,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|err| {
            format!("failed to start exact activation console for controller handoff: {err}")
        })?;
    if !output.status.success() {
        return Err(format!(
            "exact activation console controller handoff failed: {}",
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn controller_service_binary_path(command: &Path) -> PathBuf {
    let text = command.to_string_lossy();
    if let Some(rest) = text.strip_prefix('"')
        && let Some(end) = rest.find('"')
    {
        return PathBuf::from(&rest[..end]);
    }
    PathBuf::from(text.split_whitespace().next().unwrap_or_default())
}

#[cfg(windows)]
fn restart_controller_service(
    install_root: &Path,
) -> Result<(String, String, Option<String>), String> {
    let activation = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    let expected_controller = Path::new(&activation.controller_path);
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("failed to open Windows Service Control Manager: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::START
                | ServiceAccess::STOP,
        )
        .map_err(|err| format!("failed to open exact controller service: {err}"))?;
    let config = service
        .query_config()
        .map_err(|err| format!("failed to query exact controller service config: {err}"))?;
    let configured_binary = controller_service_binary_path(&config.executable_path);
    if !evidence_path_matches(&configured_binary.to_string_lossy(), expected_controller) {
        return Err("controller service binary does not match current ReleaseSet".to_owned());
    }
    let account = config
        .account_name
        .as_deref()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "LocalSystem".to_owned());
    if !account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT) {
        return Err(format!("unexpected controller service account: {account}"));
    }
    let expected_command = format!(
        "{} windows-service {} {}",
        activation.controller_path,
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR
    );
    if config.executable_path.to_string_lossy() != expected_command {
        return Err("controller service command does not match exact current authority".to_owned());
    }

    let before = service
        .query_status()
        .map_err(|err| format!("failed to query controller service before restart: {err}"))?;
    if before.current_state != ServiceState::Running {
        return Err(format!(
            "controller restart requires Running pre-state, observed {:?}",
            before.current_state
        ));
    }
    let before_pid = before
        .process_id
        .ok_or_else(|| "Running controller service has no PID".to_owned())?;

    service
        .stop()
        .map_err(|err| format!("failed to stop exact controller service: {err}"))?;
    wait_for_service_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
    service
        .start::<&str>(&[])
        .map_err(|err| format!("failed to start exact controller service: {err}"))?;
    wait_for_service_state(
        &service,
        ServiceState::Running,
        Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
    )?;

    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse()
        .map_err(|err| format!("invalid installed controller address: {err}"))?;
    if !controller_is_listening(addr) {
        return Err(format!(
            "restarted controller service is not listening on {INSTALLED_CONTROLLER_ADDR}"
        ));
    }

    let after = service
        .query_status()
        .map_err(|err| format!("failed to query controller service after restart: {err}"))?;
    let after_pid = after
        .process_id
        .ok_or_else(|| "restarted controller service has no PID".to_owned())?;
    if after_pid == before_pid {
        return Err("controller service restart did not change controller PID".to_owned());
    }

    Ok((
        "CONTROLLER_SERVICE_RESTARTED".to_owned(),
        format!(
            "controller_restart=PASS;before_pid={before_pid};after_pid={after_pid};endpoint={INSTALLED_CONTROLLER_ADDR}"
        ),
        Some(activation.release_set_sha256),
    ))
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

    let current_config = service.query_config().map_err(|err| {
        format!("failed to query controller service config before convergence: {err}")
    })?;
    let current_account = current_config
        .account_name
        .as_deref()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "LocalSystem".to_owned());
    let expected_command = format!(
        "{} windows-service {} {}",
        controller_path.display(),
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR
    );
    let current_status = service
        .query_status()
        .map_err(|err| format!("failed to query controller service before convergence: {err}"))?;
    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse()
        .map_err(|err| format!("invalid installed controller address: {err}"))?;
    if current_config.executable_path.to_string_lossy() == expected_command
        && current_account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)
        && current_config.start_type == ServiceStartType::AutoStart
        && current_status.current_state == ServiceState::Running
        && controller_is_listening(addr)
    {
        return Ok(());
    }

    converge_controller_tun_authority()?;

    let status = service
        .query_status()
        .map_err(|err| format!("failed to query controller service before convergence: {err}"))?;
    let observed = if status.current_state == ServiceState::StartPending {
        wait_for_service_state_any(
            &service,
            &[ServiceState::Running, ServiceState::Stopped],
            Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
        )?
    } else {
        status.current_state
    };
    match observed {
        ServiceState::Stopped => {}
        ServiceState::StopPending => {
            wait_for_service_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
        }
        ServiceState::Running | ServiceState::Paused => {
            service.stop().map_err(|err| {
                format!("failed to stop controller service from {observed:?}: {err:?}")
            })?;
            wait_for_service_state(&service, ServiceState::Stopped, Duration::from_secs(15))?;
        }
        other => {
            return Err(format!(
                "controller service is not safely stoppable for owner handoff: {other:?}"
            ));
        }
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
        .set_failure_actions_on_non_crash_failures(false)
        .map_err(|err| format!("failed to limit controller recovery to crash failures: {err}"))?;

    converge_application_acl(install_root)?;

    service
        .start::<&str>(&[])
        .map_err(|err| format!("failed to start controller service: {err}"))?;
    wait_for_service_state(
        &service,
        ServiceState::Running,
        Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
    )?;

    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse()
        .map_err(|err| format!("invalid installed controller address: {err}"))?;
    if !controller_is_listening(addr) {
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

fn lifecycle_status_label(status: i32) -> &'static str {
    match edge_shared_types::OperationLifecycleStatus::try_from(status) {
        Ok(edge_shared_types::OperationLifecycleStatus::Requested) => "requested",
        Ok(edge_shared_types::OperationLifecycleStatus::Running) => "running",
        Ok(edge_shared_types::OperationLifecycleStatus::Succeeded) => "succeeded",
        Ok(edge_shared_types::OperationLifecycleStatus::Failed) => "failed",
        _ => "unknown",
    }
}

fn join_ports(ports: &[u32]) -> String {
    ports
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_route_restore(
        failed_route: Option<&'static str>,
        failed_restore: bool,
    ) -> (Result<(), String>, Vec<String>) {
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let check_events = Arc::clone(&events);
        let restore_events = Arc::clone(&events);
        let result = verify_routes_with_restore(
            "hysteria2-direct".to_owned(),
            move |route, _warp| {
                let events = Arc::clone(&check_events);
                async move {
                    events.lock().unwrap().push(format!("verify:{route}"));
                    if failed_route == Some(route) {
                        Err(format!("trace failed for {route}"))
                    } else {
                        Ok(())
                    }
                }
            },
            move |original| async move {
                restore_events
                    .lock()
                    .unwrap()
                    .push(format!("restore:{original}"));
                if failed_restore {
                    Err("restore read-back mismatch".to_owned())
                } else {
                    Ok(())
                }
            },
        )
        .await;
        let observations = events.lock().unwrap().clone();
        (result, observations)
    }

    #[tokio::test]
    async fn stage4b3_route_checks_restore_original_after_success() {
        let (result, events) = test_route_restore(None, false).await;
        assert!(result.is_ok());
        assert_eq!(
            events,
            [
                "verify:auto-direct-tunnel",
                "verify:auto-warp-tunnel",
                "restore:hysteria2-direct"
            ]
        );
    }

    #[tokio::test]
    async fn stage4b3_route_checks_restore_after_first_route_error() {
        let (result, events) = test_route_restore(Some("auto-direct-tunnel"), false).await;
        assert!(result.unwrap_err().contains("original selector restored"));
        assert_eq!(
            events,
            ["verify:auto-direct-tunnel", "restore:hysteria2-direct"]
        );
    }

    #[tokio::test]
    async fn stage4b3_route_checks_restore_after_second_route_error() {
        let (result, events) = test_route_restore(Some("auto-warp-tunnel"), false).await;
        assert!(result.unwrap_err().contains("original selector restored"));
        assert_eq!(
            events,
            [
                "verify:auto-direct-tunnel",
                "verify:auto-warp-tunnel",
                "restore:hysteria2-direct"
            ]
        );
    }

    #[tokio::test]
    async fn stage4b3_restore_failure_keeps_error_without_stopping_runtime() {
        let (result, events) = test_route_restore(None, true).await;
        assert!(result.unwrap_err().contains("restoration is unverified"));
        assert_eq!(events.last().unwrap(), "restore:hysteria2-direct");
        let (result, events) = test_route_restore(Some("auto-direct-tunnel"), true).await;
        let error = result.unwrap_err();
        assert!(error.contains("trace failed"));
        assert!(error.contains("restoration is unverified"));
        assert_eq!(events.last().unwrap(), "restore:hysteria2-direct");
    }

    #[test]
    fn stage4b3_unknown_live_selector_never_guesses_git_default() {
        let mut selector = SelectorState::placeholder();
        selector.desired_main_route = Some("auto-direct-tunnel".to_owned());
        assert!(
            observed_restore_route(selector)
                .unwrap_err()
                .contains("no mutation made")
        );
    }

    fn rollback_test_activation(
        install_root: &Path,
        release_name: &str,
        release_set_sha256: &str,
    ) -> WindowsActivationState {
        let release_dir = install_root.join("releases").join(release_name);
        let bin_dir = release_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        let controller = bin_dir.join("edge-controller.exe");
        let console = bin_dir.join("edge-console.exe");
        let sing_box = bin_dir.join("sing-box.exe");
        let diagnostic = bin_dir.join("edge-diagnostic.exe");
        std::fs::write(&controller, b"controller").unwrap();
        std::fs::write(&console, b"console").unwrap();
        std::fs::write(&sing_box, b"singbox").unwrap();
        std::fs::write(&diagnostic, b"diagnostic").unwrap();

        WindowsActivationState {
            schema_version: 1,
            release_set_sha256: release_set_sha256.to_owned(),
            source_revision: "1".repeat(40),
            release_dir: release_dir.to_string_lossy().into_owned(),
            controller_path: controller.to_string_lossy().into_owned(),
            console_path: console.to_string_lossy().into_owned(),
            sing_box_path: sing_box.to_string_lossy().into_owned(),
            diagnostic_path: diagnostic.to_string_lossy().into_owned(),
            controller_sha256: vec![
                193, 71, 33, 53, 177, 76, 119, 200, 190, 249, 142, 115, 247, 2, 8, 50, 95, 160,
                220, 241, 230, 189, 102, 138, 233, 179, 26, 156, 234, 41, 95, 231,
            ],
            console_sha256: vec![
                147, 216, 135, 76, 140, 134, 240, 252, 137, 61, 190, 21, 199, 101, 255, 160, 252,
                211, 66, 247, 152, 219, 246, 105, 224, 143, 140, 190, 9, 93, 35, 12,
            ],
            sing_box_sha256: vec![
                106, 175, 72, 98, 84, 64, 79, 91, 126, 34, 43, 199, 22, 96, 133, 30, 4, 200, 107,
                148, 52, 206, 132, 38, 56, 207, 20, 34, 143, 61, 95, 113,
            ],
            diagnostic_sha256: vec![
                90, 105, 94, 234, 91, 0, 163, 31, 138, 239, 125, 187, 137, 200, 247, 152, 250, 179,
                113, 36, 106, 193, 84, 154, 254, 132, 177, 100, 32, 112, 123, 153,
            ],
        }
    }

    fn rollback_test_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("edge-console-release-rollback-{unique}"));
        std::fs::create_dir_all(root.join("releases")).unwrap();
        root
    }

    #[test]
    fn canonical_reinstall_authority_accepts_managed_tun() {
        require_supported_reinstall_authority().unwrap();
    }

    #[test]
    fn stable_release_tools_follow_exact_activation() {
        let root = rollback_test_root();
        let activation = rollback_test_activation(&root, "previous", &"b".repeat(64));
        let stable_bin = root.join("bin");
        std::fs::create_dir_all(&stable_bin).unwrap();
        std::fs::write(stable_bin.join("edge-console.exe"), b"stale-console").unwrap();
        std::fs::write(stable_bin.join("edge-diagnostic.exe"), b"stale-diagnostic").unwrap();

        sync_stable_windows_release_tools(&root, &activation).unwrap();

        assert_eq!(
            std::fs::read(stable_bin.join("edge-console.exe")).unwrap(),
            std::fs::read(&activation.console_path).unwrap()
        );
        assert_eq!(
            std::fs::read(stable_bin.join("edge-diagnostic.exe")).unwrap(),
            std::fs::read(&activation.diagnostic_path).unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn previous_release_rollback_preflight_accepts_only_verified_previous_pb() {
        let root = rollback_test_root();
        let current = rollback_test_activation(&root, "current", &"a".repeat(64));
        let previous = rollback_test_activation(&root, "previous", &"b".repeat(64));
        std::fs::write(
            root.join("current.pb"),
            encode_windows_activation_state(&current).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("previous.pb"),
            encode_windows_activation_state(&previous).unwrap(),
        )
        .unwrap();

        let (observed_current, observed_previous) =
            load_previous_release_rollback_pair(&root).unwrap();
        assert_eq!(observed_current.release_set_sha256, "a".repeat(64));
        assert_eq!(observed_previous.release_set_sha256, "b".repeat(64));

        std::fs::write(root.join("previous.pb"), b"not-protobuf").unwrap();
        assert!(load_previous_release_rollback_pair(&root).is_err());

        std::fs::remove_file(root.join("previous.pb")).unwrap();
        let error = load_previous_release_rollback_pair(&root).unwrap_err();
        assert!(error.contains("previous.pb is absent"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn previous_release_rollback_preflight_rejects_same_release() {
        let root = rollback_test_root();
        let current = rollback_test_activation(&root, "current", &"c".repeat(64));
        let previous = rollback_test_activation(&root, "previous", &"c".repeat(64));
        std::fs::write(
            root.join("current.pb"),
            encode_windows_activation_state(&current).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("previous.pb"),
            encode_windows_activation_state(&previous).unwrap(),
        )
        .unwrap();

        let error = load_previous_release_rollback_pair(&root).unwrap_err();
        assert!(error.contains("same ReleaseSet"));
        let _ = std::fs::remove_dir_all(root);
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

    #[test]
    fn redacts_sensitive_runtime_evidence_tokens() {
        let redacted = redact_runtime_evidence(
            "uuid=00000000-0000-4000-8000-000000000001 short=0011223344556677 password=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef host=miu.alegria.by",
        );
        assert!(!redacted.contains("00000000-0000-4000-8000-000000000001"));
        assert!(!redacted.contains("0011223344556677"));
        assert!(!redacted.contains("0123456789abcdef0123456789abcdef"));
        assert!(redacted.contains("<redacted-uuid>"));
        assert!(redacted.contains("<redacted-hex>"));
        assert!(redacted.contains("miu.alegria.by"));
    }

    #[test]
    fn privileged_activation_has_operation_specific_wait_budget() {
        let activate = WindowsPrivilegedRequest {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            request_id: "activate".to_owned(),
            operation: WindowsPrivilegedOperation::ActivateRelease as i32,
            accepted_revision: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            release_set_sha256: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
            credential_generation: None,
            credential_transition_action: None,
        };
        let ping = WindowsPrivilegedRequest {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            request_id: "ping".to_owned(),
            operation: WindowsPrivilegedOperation::Ping as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: None,
        };

        assert_eq!(
            privileged_wait_secs(&activate),
            PRIVILEGED_ACTIVATE_WAIT_SECS
        );
        assert_eq!(privileged_wait_secs(&ping), PRIVILEGED_SHORT_WAIT_SECS);
        assert!(PRIVILEGED_ACTIVATE_WAIT_SECS > PRIVILEGED_SHORT_WAIT_SECS);
    }

    #[test]
    fn privileged_child_failure_evidence_is_bounded_and_secret_safe() {
        let stdout = b"source_revision=0123456789abcdef0123456789abcdef01234567\n";
        let stderr = format!(
            "Invoke-WebRequest failed token={} url=https://example.invalid/path\n{}",
            "abcdef0123456789abcdef0123456789",
            "download failed ".repeat(200)
        );
        let detail = bounded_privileged_child_evidence(stdout, stderr.as_bytes());

        assert!(detail.len() <= PRIVILEGED_CHILD_EVIDENCE_MAX_BYTES);
        assert!(!detail.chars().any(|ch| ch.is_control()));
        assert!(!detail.contains("0123456789abcdef0123456789abcdef01234567"));
        assert!(!detail.contains("abcdef0123456789abcdef0123456789"));

        let result = WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: "installer-evidence-test".to_owned(),
            success: false,
            code: "PRIVILEGED_OPERATION_FAILED".to_owned(),
            detail,
            active_release_set_sha256: None,
        };
        assert!(encode_windows_privileged_result(&result).is_ok());
    }

    #[test]
    fn critical_runtime_evidence_fits_without_truncating_owner_or_tasks() {
        let tasks = format!(
            "tasks=EdgePlatformController|1|3|{},EdgePlatformReconcile|1|3|{},EdgePlatformShutdown|1|3|{},EdgePlatformPrivilegedDispatch|1|4|{}",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        let external_owner = "external_owner_evidence=BOUNDED_READ_ONLY;external_pid=7464;external_exe=C:\\Users\\Bose\\AppData\\Local\\sing-box-vultr-dual\\runtime\\sing-box.exe;external_config=C:\\Users\\Bose\\temp\\sing-box\\win\\windows\\edge-dns-clean-vultr-dual.json;external_run_shape=true;external_exe_exists=true;external_config_exists=true;external_check=PASS;parent_pid=3792;parent_name=edge-controller.exe;parent_exe=C:\\Users\\Bose\\AppData\\Local\\edge-platform-win-target\\x86_64-pc-windows-msvc\\debug\\edge-controller.exe;startup_owner=OTHER_LIVE_PARENT;restore_preflight=PASS";
        let detail = format!("runtime_evidence=BOUNDED_READ_ONLY;{tasks};{external_owner}");
        assert!(detail.len() <= RUNTIME_EVIDENCE_RESULT_MAX_BYTES);
        assert!(detail.contains("EdgePlatformPrivilegedDispatch"));
        assert!(detail.contains("restore_preflight=PASS"));
        assert!(!detail.contains("[truncated]"));

        let result = WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: "runtime-evidence-test".to_owned(),
            success: true,
            code: "RUNTIME_EVIDENCE_READ".to_owned(),
            detail,
            active_release_set_sha256: None,
        };
        assert!(encode_windows_privileged_result(&result).is_ok());
    }
}
