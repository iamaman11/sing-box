mod cli;
mod credential_access_bootstrap;
mod credential_transition;
mod error;
mod initial_line1_witness;

use clap::Parser;
use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
};
use edge_local_runtime::{
    RuntimeProcessClassification, classify_runtime_process, observe_process,
    run_non_tun_loopback_smoke, stop_local_runtime as stop_runtime_process,
};
use edge_observability::init as init_observability;
use edge_secrets::{
    ACCESS_IDENTITY_FILE_NAME, CredentialStore, CredentialOriginSelection,
    attest_worker_credential_origin, fetch_canonical_credential_bundle,
    verify_canonical_dummy_ab_slots, verify_initial_selected_dummy_slot,
};
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
// Fixed bounded protobuf evidence, including a persistent first-use credential cursor.
// The former 1024-byte cap rejected valid stopped Windows candidates when the
// exact four scheduled-task hashes and recovered credential proof coexisted.
const RUNTIME_EVIDENCE_RESULT_MAX_BYTES: usize = 2048;
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
        Command::PrivilegedCredentialOrigin(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::CredentialOrigin as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::CredentialInitialProbe(args) => {
            run_windows_initial_credential_probe(Path::new(&args.install_root))
                .await
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::CredentialInitialAttest(args) => {
            let root = Path::new(&args.install_root);
            require_initial_windows_credential_host(root).map_err(ConsoleError::Command)?;
            let activation = load_verified_activation(root).map_err(|err| {
                ConsoleError::Command(format!(
                    "Windows first-use attestation release is unverified: {err}"
                ))
            })?;
            if activation.release_set_sha256 != args.release_set_sha256 {
                return Err(ConsoleError::Command(
                    "Windows first-use attestation refuses a different local ReleaseSet".to_owned(),
                ));
            }
            let slot = match args.slot.as_str() {
                "a" => edge_shared_types::CredentialDeliverySlot::A,
                "b" => edge_shared_types::CredentialDeliverySlot::B,
                _ => {
                    return Err(ConsoleError::Command(
                        "initial slot must be a or b".to_owned(),
                    ));
                }
            };
            let proof = verify_initial_selected_dummy_slot(
                edge_shared_types::CredentialProjectionKind::Windows,
                slot,
                &root
                    .join("state")
                    .join("secrets")
                    .join(ACCESS_IDENTITY_FILE_NAME),
            )
            .await
            .map_err(ConsoleError::Command)?;
            let machine = env::var("COMPUTERNAME").map_err(|_| {
                ConsoleError::Command("Windows machine identity unavailable".to_owned())
            })?;
            let digest = edge_shared_types::first_use_host_attestation_sha256(
                edge_shared_types::CredentialProjectionKind::Windows,
                args.generation,
                slot,
                &args.provider_intent_sha256,
                &args.release_set_sha256,
                &machine,
                args.run_id,
            )
            .map_err(ConsoleError::Command)?;
            println!("operation=CREDENTIAL_INITIAL_ATTEST");
            println!("credential_projection=WINDOWS");
            println!("credential_generation={}", args.generation);
            println!("credential_host_attestation_sha256={digest}");
            println!("credential_slot_A={}", proof.slot_a_observation);
            println!("credential_slot_B={}", proof.slot_b_observation);
            println!("credential_selected_slot_exact_dummy=true");
            println!("credential_github_run_id={}", args.run_id);
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            println!("windows_tun_mutations=0");
            println!("windows_dns_mutations=0");
            Ok(())
        }
        Command::CredentialInitialAcceptanceBootstrap(args) => {
            let root = Path::new(&args.install_root);
            load_verified_activation(root).map_err(|err| {
                ConsoleError::Command(format!("isolated Windows release unverified: {err}"))
            })?;
            initial_line1_witness::bootstrap_access(root).map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::CredentialInitialAcceptanceStage(args) => {
            let root = Path::new(&args.install_root);
            load_verified_activation(root).map_err(|err| {
                ConsoleError::Command(format!("isolated Windows release unverified: {err}"))
            })?;
            initial_line1_witness::stage_from_worker(root, args.generation)
                .await
                .map_err(ConsoleError::Command)?;
            Ok(())
        }
        Command::CredentialInitialLine1Witness(args) => {
            let root = Path::new(&args.install_root);
            let activation = load_verified_activation(root).map_err(|err| {
                ConsoleError::Command(format!("Line1 witness release is unverified: {err}"))
            })?;
            initial_line1_witness::run(
                root,
                Path::new(&activation.sing_box_path),
                args.generation,
                args.target_ipv4,
                &args.target_domain,
            )
            .map_err(ConsoleError::Command)?;
            Ok(())
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
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
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
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedActivate(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
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
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::OfflineBootstrap(args) => {
            let install_root = PathBuf::from(args.install_root);
            let request = WindowsPrivilegedRequest {
                schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                request_id: new_privileged_request_id()?,
                operation: WindowsPrivilegedOperation::OfflineActivateRelease as i32,
                accepted_revision: Some(args.accepted_revision),
                release_set_sha256: Some(args.release_set_sha256),
                credential_generation: None,
                credential_transition_action: None,
                initial_commit_intent_sha256: None,
                initial_commit_slot: None,
                initial_recovery_intent_sha256: None,
                initial_candidate_sha256: None,
            };
            let (code, detail, release) =
                offline_bootstrap_privileged_release(&install_root, &request)
                    .map_err(ConsoleError::Command)?;
            println!("status=PASS");
            println!("code={code}");
            println!("detail={detail}");
            if let Some(release) = release {
                println!("active_release_set_sha256={release}");
            }
            Ok(())
        }
        Command::PrivilegedOfflineActivate(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::OfflineActivateRelease as i32,
                    accepted_revision: Some(args.accepted_revision),
                    release_set_sha256: Some(args.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedOfflineRollbackPrevious(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let (current, previous) = load_previous_release_rollback_pair(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::OfflineRollbackPreviousRelease as i32,
                    accepted_revision: Some(current.source_revision),
                    release_set_sha256: Some(previous.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedRollbackPrevious(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let (current, previous) = load_previous_release_rollback_pair(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::RollbackPreviousRelease as i32,
                    accepted_revision: Some(current.source_revision),
                    release_set_sha256: Some(previous.release_set_sha256),
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedReinstallAccepted(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
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
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
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
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedStartProxyOnlyController(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::StartProxyOnlyController as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedStopProxyOnlyController(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::StopProxyOnlyController as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: None,
                    credential_transition_action: None,
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
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
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedInitialCredentialCommit(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::InitialCredentialCommit as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: Some(args.generation),
                    credential_transition_action: None,
                    initial_commit_intent_sha256: Some(args.intent_sha256),
                    initial_commit_slot: Some(args.slot),
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
                },
            )?;
            print_privileged_result(&result);
            finish_privileged_result(&result)?;
            Ok(())
        }
        Command::PrivilegedInitialCredentialRecover(args) => {
            let install_root = PathBuf::from(args.install_root);
            require_exact_immutable_activation_console(&install_root)
                .map_err(ConsoleError::Command)?;
            let result = submit_privileged_request(
                &install_root,
                WindowsPrivilegedRequest {
                    schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                    request_id: new_privileged_request_id()?,
                    operation: WindowsPrivilegedOperation::InitialCredentialRecover as i32,
                    accepted_revision: None,
                    release_set_sha256: None,
                    credential_generation: Some(args.generation),
                    credential_transition_action: None,
                    initial_commit_intent_sha256: Some(args.original_intent_sha256),
                    initial_commit_slot: Some(args.slot),
                    initial_recovery_intent_sha256: Some(args.recovery_intent_sha256),
                    initial_candidate_sha256: Some(args.candidate_sha256),
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
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
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
                    initial_commit_intent_sha256: None,
                    initial_commit_slot: None,
                    initial_recovery_intent_sha256: None,
                    initial_candidate_sha256: None,
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
            | WindowsPrivilegedOperation::ReinstallAcceptedRelease
            | WindowsPrivilegedOperation::OfflineActivateRelease
            | WindowsPrivilegedOperation::OfflineRollbackPreviousRelease,
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
            rollback_privileged_release(install_root, request)
        }
        Ok(WindowsPrivilegedOperation::OfflineActivateRelease) => {
            offline_activate_privileged_release(install_root, request)
        }
        Ok(WindowsPrivilegedOperation::OfflineRollbackPreviousRelease) => {
            offline_rollback_privileged_release(install_root, request)
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
        Ok(WindowsPrivilegedOperation::InitialCredentialCommit) => {
            #[cfg(windows)]
            {
                (|| -> Result<(String, String, Option<String>), String> {
                    require_stopped_proxy_only_initial_commit_owner(install_root)?;
                let activation = load_verified_activation(install_root)
                    .map_err(|err| err.to_string())?;
                let generation = request.credential_generation
                    .ok_or_else(|| "initial Windows paired commit generation absent".to_owned())?;
                let slot = request.initial_commit_slot
                    .ok_or_else(|| "initial Windows paired commit slot absent".to_owned())?;
                let intent = request.initial_commit_intent_sha256.as_deref()
                    .ok_or_else(|| "initial Windows paired commit intent absent".to_owned())?;
                let (code, detail) = credential_transition::initial_commit(
                    install_root, &activation, generation, slot as i32, intent
                )?;
                    Ok((code, detail, Some(activation.release_set_sha256)))
                })()
            }
            #[cfg(not(windows))]
            {
                Err("initial paired Windows credential commit is Windows-only".to_owned())
            }
        }
        Ok(WindowsPrivilegedOperation::InitialCredentialRecover) => {
            #[cfg(windows)]
            {
                (|| -> Result<(String, String, Option<String>), String> {
                    require_stopped_proxy_only_initial_commit_owner(install_root)?;
                    let activation = load_verified_activation(install_root)
                        .map_err(|err| err.to_string())?;
                    let generation = request.credential_generation
                        .ok_or_else(|| "paired recovery generation absent".to_owned())?;
                    let slot = request.initial_commit_slot
                        .ok_or_else(|| "paired recovery slot absent".to_owned())?;
                    let original = request.initial_commit_intent_sha256.as_deref()
                        .ok_or_else(|| "paired recovery original intent absent".to_owned())?;
                    let recovery = request.initial_recovery_intent_sha256.as_deref()
                        .ok_or_else(|| "paired recovery decision absent".to_owned())?;
                    let candidate = request.initial_candidate_sha256.as_deref()
                        .ok_or_else(|| "paired recovery candidate identity absent".to_owned())?;
                    let (code, detail) = credential_transition::initial_recover(
                        install_root,
                        &activation,
                        generation,
                        slot as i32,
                        original,
                        recovery,
                        candidate,
                    )?;
                    Ok((code, detail, Some(activation.release_set_sha256)))
                })()
            }
            #[cfg(not(windows))]
            {
                Err("initial paired credential recovery requires Windows SYSTEM owner".to_owned())
            }
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
        Ok(WindowsPrivilegedOperation::CredentialOrigin) => {
            #[cfg(windows)]
            {
                if require_stopped_proxy_only_initial_commit_owner(install_root).is_err() {
                    Err("WORKER_ORIGIN_BLOCKED: stopped ProxyOnly owner unproven".to_owned())
                } else {
                    match load_verified_activation(install_root) {
                        Err(_) => Err("WORKER_ORIGIN_BLOCKED: immutable release unproven".to_owned()),
                        Ok(activation) => {
                            let identity = install_root.join("state").join("secrets").join(ACCESS_IDENTITY_FILE_NAME);
                            attest_worker_credential_origin(
                                &windows_credential_store_path(install_root),
                                &identity,
                                edge_shared_types::CredentialProjectionKind::Windows,
                                CredentialOriginSelection::Active,
                            ).await.map(|proof| (
                                "CREDENTIAL_WORKER_ORIGIN_READ_ONLY".to_owned(),
                                format!("credential_origin=WORKER_EXACT_CURRENT_ACTIVE;credential_active_generation={};credential_active_slot={};credential_active_sha256={};credential_pair_committed=false;credential_provider_mutations=0;credential_runtime_mutations=0;windows_tun_mutations=0;windows_dns_mutations=0",
                                    proof.generation,proof.slot,proof.bundle_sha256),
                                Some(activation.release_set_sha256),
                            ))
                        }
                    }
                }
            }
            #[cfg(not(windows))]
            {
                Err("WORKER_ORIGIN_BLOCKED: Windows SYSTEM owner required".to_owned())
            }
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
        Ok(WindowsPrivilegedOperation::StartProxyOnlyController) => {
            #[cfg(windows)]
            { proxy_only_controller_service_lifecycle(install_root, true) }
            #[cfg(not(windows))]
            { Err("ProxyOnly SCM start is Windows-only".to_owned()) }
        }
        Ok(WindowsPrivilegedOperation::StopProxyOnlyController) => {
            #[cfg(windows)]
            { proxy_only_controller_service_lifecycle(install_root, false) }
            #[cfg(not(windows))]
            { Err("ProxyOnly SCM stop is Windows-only".to_owned()) }
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

// SYSTEM-owned, read-only projection of the persistent Windows cursor. A
// partially created store is UNKNOWN, never treated as a fresh first-use slot.
// The GitHub runner cannot read private state or any credential bundle.
fn read_bounded_windows_credential_cursor(install_root: &Path) -> Result<String, String> {
    let root = windows_credential_store_path(install_root);
    let Some(store) =
        CredentialStore::open_existing(root, edge_shared_types::CredentialProjectionKind::Windows)?
    else {
        return Ok("credential_cursor=ABSENT".to_owned());
    };
    let state = store.read_state()?.ok_or_else(|| {
        "persistent Windows credential directory has no durable cursor; first-use is UNKNOWN"
            .to_owned()
    })?;
    let active = state.active.as_ref();
    let candidate = state.candidate.as_ref();
    let previous = state.previous.as_ref();
    let slot = match candidate.map(|value| value.slot) {
        Some(value) if value == edge_shared_types::CredentialDeliverySlot::A as i32 => "A",
        Some(value) if value == edge_shared_types::CredentialDeliverySlot::B as i32 => "B",
        Some(_) => "UNKNOWN",
        None => "NONE",
    };
    let active_slot = match active.map(|value| value.slot) {
        Some(value) if value == edge_shared_types::CredentialDeliverySlot::A as i32 => "A",
        Some(value) if value == edge_shared_types::CredentialDeliverySlot::B as i32 => "B",
        Some(_) => "UNKNOWN",
        None => "NONE",
    };
    let receipt = store.read_initial_pair_receipt()?;
    let recovery = store.read_initial_pair_recovery_receipt()?;
    let recovery_sha = recovery
        .as_deref()
        .and_then(|value| {
            value
                .lines()
                .find_map(|line| line.strip_prefix("recovery_intent_sha256="))
        })
        .unwrap_or("ABSENT");
    let receipt_sha = receipt
        .as_deref()
        .and_then(|value| {
            value
                .lines()
                .find_map(|line| line.strip_prefix("intent_sha256="))
        })
        .unwrap_or("ABSENT");
    Ok(format!(
        "credential_cursor=VALID;credential_active_present={};credential_candidate_present={};credential_candidate_generation={};credential_candidate_slot={slot};credential_previous_present={};credential_active_generation={};credential_active_slot={active_slot};credential_active_sha256={};credential_candidate_sha256={};credential_initial_commit_receipt_present={};credential_initial_commit_intent_sha256={receipt_sha};credential_initial_recovery_receipt_present={};credential_initial_recovery_intent_sha256={recovery_sha}",
        active.is_some(),
        candidate.is_some(),
        candidate.map(|value| value.generation).unwrap_or(0),
        previous.is_some(),
        active.map(|value| value.generation).unwrap_or(0),
        active
            .map(|value| value.sha256.as_str())
            .unwrap_or("ABSENT"),
        candidate
            .map(|value| value.sha256.as_str())
            .unwrap_or("ABSENT"),
        receipt.is_some(),
        recovery.is_some(),
    ))
}

#[cfg(windows)]
fn require_stopped_proxy_only_initial_commit_owner(install_root: &Path) -> Result<(), String> {
    let target = canonical_production_desired_state()?;
    if target.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32
        || !install_root
            .to_string_lossy()
            .eq_ignore_ascii_case(r"C:\sing-box")
    {
        return Err("initial Windows paired commit requires canonical ProxyOnly root".to_owned());
    }
    let activation = load_verified_activation(install_root).map_err(|_| {
        "initial Windows commit requires exact immutable installed release".to_owned()
    })?;
    let doctor = Command::new(&activation.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "initial Windows commit requires installed native doctor".to_owned())?;
    let evidence = String::from_utf8(doctor.stdout)
        .map_err(|_| "initial Windows commit native doctor is not UTF-8".to_owned())?;
    for expected in [
        "exact_release_files=PASS",
        "windows_datapath_mode=ProxyOnly",
        "scm_state=Stopped",
        "scm_start_type=OnDemand",
        "managed_tun_present=false",
        "managed_singbox_process_count=0",
        "orphan_singbox_process_count=0",
        "conflicting_singbox_process_count=0",
        "unknown_singbox_process_count=0",
    ] {
        if !evidence.lines().any(|line| line == expected) {
            return Err(format!(
                "initial Windows paired commit missing native stopped owner evidence: {expected}"
            ));
        }
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "initial Windows commit cannot inspect SCM".to_owned())?;
    let service = manager
        .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(|_| "initial Windows commit cannot inspect owner service".to_owned())?;
    let status = service
        .query_status()
        .map_err(|_| "initial Windows commit SCM status uncertain".to_owned())?;
    if status.current_state != ServiceState::Stopped
        || status.process_id.is_some()
        || !matches!(
            classify_runtime_process(&local_singbox_config_path(install_root)),
            RuntimeProcessClassification::Absent
        )
    {
        return Err(
            "initial Windows paired commit requires exact stopped/zero-process SCM".to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn require_offline_first_use_stage_owner(install_root: &Path) -> Result<(), String> {
    let target = canonical_production_desired_state()?;
    if target.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32
        || !install_root
            .to_string_lossy()
            .eq_ignore_ascii_case(r"C:\sing-box")
    {
        return Err("first-use persistent staging is confined to canonical ProxyOnly intent and C:\\sing-box".to_owned());
    }
    let activation = load_verified_activation(install_root).map_err(|_| {
        "persistent first-use staging requires an exact installed ReleaseSet".to_owned()
    })?;
    let doctor = Command::new(&activation.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "persistent first-use staging requires native read-only doctor".to_owned())?;
    // A stopped old ManagedTun can cause a nonzero doctor exit. Require
    // affirmative OS/file evidence, never treat that exit as permission.
    let observation = String::from_utf8(doctor.stdout)
        .map_err(|_| "persistent first-use doctor evidence is not UTF-8".to_owned())?;
    for evidence in [
        "exact_release_files=PASS",
        "scm_state=Stopped",
        "managed_tun_present=false",
        "managed_singbox_process_count=0",
        "orphan_singbox_process_count=0",
        "conflicting_singbox_process_count=0",
        "unknown_singbox_process_count=0",
    ] {
        if !observation.lines().any(|line| line == evidence) {
            return Err(
                "persistent first-use denies missing stopped/no-TUN native evidence".to_owned(),
            );
        }
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "first-use persistent staging cannot inspect SCM".to_owned())?;
    let service = manager
        .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(|_| "first-use persistent staging cannot inspect owner service".to_owned())?;
    let status = service
        .query_status()
        .map_err(|_| "first-use persistent staging cannot read SCM status".to_owned())?;
    if status.current_state != ServiceState::Stopped
        || status.process_id.is_some()
        || !matches!(
            classify_runtime_process(&local_singbox_config_path(install_root)),
            RuntimeProcessClassification::Absent
        )
    {
        return Err(
            "first-use persistent staging refuses a running or ambiguous Windows owner".to_owned(),
        );
    }
    if windows_runtime_state_path(install_root).exists()
        || local_singbox_config_path(install_root).exists()
        || windows_credential_store_path(install_root).exists()
    {
        return Err("first-use persistent staging refuses pre-existing or incomplete managed credential/runtime state".to_owned());
    }
    Ok(())
}

// Classify the existing local cursor before choosing any mutation path. These
// are ownership observations, never proof that a Worker/VM generation matches.
// No parser of historical log text may grant first-use or active authority.
fn classify_windows_credential_lifecycle(
    cursor: &str,
    runtime: &str,
    config: &str,
    identity: &str,
) -> (&'static str, &'static str) {
    if cursor == "credential_cursor=ABSENT" {
        if runtime != "ABSENT" || config != "ABSENT" {
            return ("PARTIAL", "READ_ONLY_RECONCILE");
        }
        return if identity == "PRESENT_NONEMPTY_UNVERIFIED" {
            ("FRESH_LOCAL_ONLY", "JOURNAL_AUTHORIZATION_REQUIRED")
        } else {
            ("FRESH_NEEDS_IDENTITY", "NATIVE_IDENTITY_BOOTSTRAP_REQUIRED")
        };
    }
    let field = |name: &str| {
        let mut matches = cursor.split(';').filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            (key == name).then_some(value)
        });
        let value = matches.next();
        if matches.next().is_some() {
            None
        } else {
            value
        }
    };
    if field("credential_cursor") != Some("VALID") {
        return ("UNKNOWN", "READ_ONLY_RECONCILE");
    }
    match (
        field("credential_active_present"),
        field("credential_candidate_present"),
    ) {
        (Some("true"), Some("false")) if runtime == "PRESENT" && config == "PRESENT" => {
            ("EXISTING_ACTIVE_UNVERIFIED", "READ_ONLY_ORIGIN_RECONCILE")
        }
        (Some("false"), Some("true")) => (
            "EXISTING_CANDIDATE_UNVERIFIED",
            "READ_ONLY_ORIGIN_RECONCILE",
        ),
        (Some("true"), Some("true")) => (
            "EXISTING_TRANSITION_UNVERIFIED",
            "READ_ONLY_ORIGIN_RECONCILE",
        ),
        _ => ("PARTIAL", "READ_ONLY_RECONCILE"),
    }
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
    let cursor = read_bounded_windows_credential_cursor(install_root)?;
    // SYSTEM-only metadata, not an authentication claim. ENOENT is distinct
    // from an ACL/read failure so GitHub cannot infer an empty first-use root.
    let state_file = windows_runtime_state_path(install_root);
    let config_file = local_singbox_config_path(install_root);
    let identity_file = install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    let known_file = |path: &Path| -> Result<Option<fs::Metadata>, String> {
        match fs::metadata(path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("persistent Windows first-use file status unreadable".to_owned()),
        }
    };
    let runtime = if known_file(&state_file)?.is_none() {
        "ABSENT"
    } else {
        "PRESENT"
    };
    let config = if known_file(&config_file)?.is_none() {
        "ABSENT"
    } else {
        "PRESENT"
    };
    let identity = match known_file(&identity_file)? {
        Some(metadata) if metadata.is_file() && metadata.len() > 0 => "PRESENT_NONEMPTY_UNVERIFIED",
        Some(_) => "INVALID",
        None => "ABSENT",
    };
    let (lifecycle, next_action) =
        classify_windows_credential_lifecycle(&cursor, runtime, config, identity);
    let critical = format!(
        "runtime_evidence=BOUNDED_READ_ONLY;{controller_error};{process_classification};{scheduled_tasks};{external_owner};{cursor};credential_lifecycle_state={lifecycle};credential_next_action={next_action};credential_origin=UNPROVEN;first_use_runtime={runtime};first_use_config={config};first_use_access_identity={identity}"
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

fn require_initial_windows_credential_host(install_root: &Path) -> Result<(), String> {
    // Any existing store directory, even with missing/corrupt cursor, is
    // ambiguous. Never interpret it as an unused first-enrollment slot.
    let store_present = windows_credential_store_path(install_root).exists();
    let runtime_present = windows_runtime_state_path(install_root).exists();
    let config_present = local_singbox_config_path(install_root).exists();
    initial_windows_credential_eligibility(store_present, runtime_present, config_present)?;
    load_verified_activation(install_root).map_err(|err| {
        format!("initial Windows proof requires an exact immutable release: {err}")
    })?;
    Ok(())
}

fn initial_windows_credential_eligibility(
    store_present: bool,
    runtime_present: bool,
    config_present: bool,
) -> Result<(), String> {
    if store_present {
        return Err(
            "initial Windows proof refuses an existing or incomplete v2 credential store"
                .to_owned(),
        );
    }
    if runtime_present {
        return Err("initial Windows proof refuses an existing managed runtime state".to_owned());
    }
    if config_present {
        return Err(
            "initial Windows proof refuses an existing rendered sing-box config".to_owned(),
        );
    }
    Ok(())
}

async fn run_windows_initial_credential_probe(install_root: &Path) -> Result<(), String> {
    require_initial_windows_credential_host(install_root)?;
    let identity_path = install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    verify_canonical_dummy_ab_slots(
        edge_shared_types::CredentialProjectionKind::Windows,
        &identity_path,
    )
    .await?;
    println!("operation=CREDENTIAL_INITIAL_PROBE");
    println!("credential_projection=WINDOWS");
    println!("credential_slot_A=EXACT_DUMMY");
    println!("credential_slot_B=EXACT_DUMMY");
    println!("credential_store_present=false");
    println!("credential_provider_mutations=0");
    println!("credential_runtime_mutations=0");
    println!("windows_tun_mutations=0");
    println!("windows_dns_mutations=0");
    println!("credential_initial_authority=NOT_COMMITTED");
    Ok(())
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
    let store_root = windows_credential_store_path(install_root);
    if !store_root.exists() {
        // Existing rotation is untouched. First enrollment is one-shot and
        // must remain stopped inside SYSTEM, irrespective of GitHub preflight.
        #[cfg(windows)]
        require_offline_first_use_stage_owner(install_root)?;
        #[cfg(not(windows))]
        return Err("persistent first-use staging requires Windows SYSTEM owner".to_owned());
    } else {
        let prior = CredentialStore::open_existing(
            &store_root,
            edge_shared_types::CredentialProjectionKind::Windows,
        )?
        .ok_or_else(|| "Windows v2 store disappeared during staging".to_owned())?;
        if prior
            .read_state()?
            .as_ref()
            .and_then(|state| state.active.as_ref())
            .is_none()
        {
            return Err(
                "persistent first-use candidate already attempted or incomplete: never restage"
                    .to_owned(),
            );
        }
    }
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

// Both the submitting CLI and the privileged dispatcher must execute from
// the verified immutable release directory. Calling from bin/edge-console.exe
// would lock the very stable EXE the installer needs to replace, but only
// AFTER the old sing-box has already been stopped.
fn require_exact_immutable_activation_console(install_root: &Path) -> Result<(), String> {
    let active = load_verified_activation(install_root)
        .map_err(|err| format!("cannot verify active release before activation: {err}"))?;
    let running = env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|err| format!("cannot verify invoking console path before activation: {err}"))?;
    let expected = Path::new(&active.console_path)
        .canonicalize()
        .map_err(|err| format!("cannot resolve exact active immutable console path: {err}"))?;
    if running != expected {
        return Err(format!(
            "activation requires exact immutable console {}; never invoke from the stable bin/edge-console.exe, which cannot be replaced while running",
            expected.display()
        ));
    }
    Ok(())
}

fn activate_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
    force_rematerialize: bool,
) -> Result<(String, String, Option<String>), String> {
    // This runs again inside privileged dispatch, BEFORE touching sing-box.
    // Updating the stable console fails on Windows if the same EXE is loaded.
    require_exact_immutable_activation_console(install_root)?;
    let accepted_revision = request
        .accepted_revision
        .as_deref()
        .ok_or_else(|| "accepted_revision is required".to_owned())?;
    let target_release = request
        .release_set_sha256
        .as_deref()
        .ok_or_else(|| "release_set_sha256 is required".to_owned())?;

    // An accepted ProxyOnly target cannot silently retire the current managed TUN.
    // Do not infer independent foreign WARP DNS/control recovery from a release pointer.
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode == WindowsDatapathMode::ProxyOnly as i32 {
        edge_local_runtime::reject_unproven_windows_tun_teardown("managed-tun-to-proxy-only")?;
    }

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

fn offline_handoff_gate(
    stopped: bool,
    no_runtime_processes: bool,
    no_managed_tun: bool,
    exact_service_owner: bool,
) -> Result<(), String> {
    if stopped && no_runtime_processes && no_managed_tun && exact_service_owner {
        Ok(())
    } else {
        Err("OFFLINE_HANDOFF_BLOCKED: stopped SCM, zero runtime owners, absent TUN and exact executable/account are mandatory".to_owned())
    }
}

#[cfg(windows)]
fn require_offline_windows_owner(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    require_offline_windows_owner_at(install_root, activation, &install_root.join("current.pb"))
}

#[cfg(windows)]
fn require_offline_windows_owner_at(
    install_root: &Path,
    activation: &WindowsActivationState,
    authority_path: &Path,
) -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    if !matches!(
        WindowsDatapathMode::try_from(desired.windows_datapath_mode),
        Ok(WindowsDatapathMode::ProxyOnly | WindowsDatapathMode::ManagedTun)
    ) {
        return Err("OFFLINE_HANDOFF_BLOCKED: canonical mode unsupported".to_owned());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("offline SCM manager unavailable: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|err| format!("offline SCM owner unavailable: {err}"))?;
    let config = service
        .query_config()
        .map_err(|err| format!("offline SCM configuration unavailable: {err}"))?;
    let status = service
        .query_status()
        .map_err(|err| format!("offline SCM state unavailable: {err}"))?;
    let expected_command = format!(
        "{} windows-service {} {}",
        activation.controller_path,
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR
    );
    let account = config
        .account_name
        .as_deref()
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    // A stopped former ManagedTun may be safely retired into ProxyOnly only
    // after this very owner proves zero TUN and processes. The new owner
    // remains manual-start until separate accepted service activation.
    let start_type_allowed = config.start_type == ServiceStartType::OnDemand
        || config.start_type == ServiceStartType::AutoStart;
    let exact = config.executable_path.to_string_lossy() == expected_command
        && account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)
        && start_type_allowed;
    let no_processes = matches!(
        classify_runtime_process(&local_singbox_config_path(install_root)),
        RuntimeProcessClassification::Absent
    );
    let output = Command::new(&activation.diagnostic_path)
        .arg("doctor")
        .arg(authority_path)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("offline exact native diagnostic unavailable: {err}"))?;
    // Doctor can exit non-zero when a deliberately stopped ManagedTun is
    // not in its desired running state. Its exact OS observations remain useful.
    let doctor = String::from_utf8_lossy(&output.stdout);
    let has_field = |field: &str| doctor.lines().any(|line| line.trim() == field);
    let attested_mode = has_field("windows_datapath_mode=ManagedTun")
        || (has_field("windows_datapath_mode=ProxyOnly")
            && desired.windows_datapath_mode == WindowsDatapathMode::ProxyOnly as i32);
    let exact_release = has_field(&format!(
        "release_set_sha256={}",
        activation.release_set_sha256
    ));
    let no_tun = attested_mode
        && exact_release
        && has_field("managed_tun_present=false")
        && has_field("managed_singbox_process_count=0")
        && has_field("orphan_singbox_process_count=0")
        && has_field("conflicting_singbox_process_count=0")
        && has_field("unknown_singbox_process_count=0")
        && has_field("exact_release_files=PASS");
    offline_handoff_gate(
        status.current_state == ServiceState::Stopped && status.process_id.is_none(),
        no_processes,
        no_tun,
        exact,
    )
}

#[cfg(windows)]
fn offline_retarget_controller_service(
    install_root: &Path,
    from: &WindowsActivationState,
    to: &WindowsActivationState,
) -> Result<(), String> {
    offline_retarget_controller_service_checked(install_root, from, to, false)
}

#[cfg(windows)]
fn offline_retarget_controller_service_checked(
    install_root: &Path,
    from: &WindowsActivationState,
    to: &WindowsActivationState,
    _restore_from_verified_snapshot: bool,
) -> Result<(), String> {
    // current.pb already points at the newly installed version. Prove the
    // outgoing owner against its immutable snapshot, not the new pointer.
    require_offline_windows_owner_from_snapshot(install_root, from)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("offline SCM manager unavailable: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|err| format!("offline SCM owner unavailable: {err}"))?;
    let next = ServiceInfo {
        name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(&to.controller_path),
        launch_arguments: vec![
            OsString::from("windows-service"),
            install_root.as_os_str().to_owned(),
            OsString::from(INSTALLED_CONTROLLER_ADDR),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)),
        account_password: None,
    };
    service
        .change_config(&next)
        .map_err(|err| format!("offline SCM retarget failed: {err}"))?;
    let updated = service
        .query_config()
        .map_err(|err| format!("offline SCM config readback failed: {err}"))?;
    let state = service
        .query_status()
        .map_err(|err| format!("offline SCM state readback failed: {err}"))?;
    let expected = format!(
        "{} windows-service {} {}",
        to.controller_path,
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR
    );
    if updated.executable_path.to_string_lossy() != expected
        || updated.start_type != ServiceStartType::OnDemand
        || state.current_state != ServiceState::Stopped
        || state.process_id.is_some()
    {
        return Err(
            "OFFLINE_HANDOFF_BLOCKED: SCM retarget has no exact stopped readback".to_owned(),
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn offline_retarget_controller_service_checked(
    _install_root: &Path,
    _from: &WindowsActivationState,
    _to: &WindowsActivationState,
    _restore_from_verified_snapshot: bool,
) -> Result<(), String> {
    Err("offline SCM recovery handoff is Windows-only".to_owned())
}

#[cfg(not(windows))]
fn require_offline_windows_owner(
    _install_root: &Path,
    _activation: &WindowsActivationState,
) -> Result<(), String> {
    Err("offline Windows ReleaseSet handoff is Windows-only".to_owned())
}

#[cfg(not(windows))]
fn offline_retarget_controller_service(
    _install_root: &Path,
    _from: &WindowsActivationState,
    _to: &WindowsActivationState,
) -> Result<(), String> {
    Err("offline Windows SCM retarget is Windows-only".to_owned())
}

// A saved, previously verified activation is independent of a torn current.pb.
// Use a single exclusive temporary proof in the SAME install root (the native
// diagnostic derives its root from authority_path.parent()). Never overwrite a
// leftover proof after a crash, and never trust a caller-provided executable.
#[cfg(windows)]
fn require_offline_windows_owner_from_snapshot(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    verify_windows_activation_files(activation)?;
    let proof = install_root.join("offline-recovery-proof.pb");
    let bytes = encode_windows_activation_state(activation)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&proof)
        .map_err(|err| format!("exclusive offline recovery proof unavailable: {err}"))?;
    let written = file.write_all(&bytes).and_then(|_| file.sync_all());
    drop(file);
    let result = written
        .map_err(|err| format!("failed to persist bounded offline recovery proof: {err}"))
        .and_then(|_| require_offline_windows_owner_at(install_root, activation, &proof));
    let cleanup = fs::remove_file(&proof)
        .map_err(|err| format!("offline recovery proof cleanup failed: {err}"));
    result?;
    cleanup
}

#[cfg(not(windows))]
fn require_offline_windows_owner_from_snapshot(
    _install_root: &Path,
    _activation: &WindowsActivationState,
) -> Result<(), String> {
    Err("offline recovery proof is Windows-only".to_owned())
}

// Snapshot an existing rollback authority without collapsing read errors into
// absence. Only ENOENT is a legitimate missing previous.pb.
fn snapshot_offline_previous(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "OFFLINE_PREVIOUS_SNAPSHOT_BLOCKED: cannot read existing rollback authority: {err}"
        )),
    }
}

fn restore_offline_previous(
    path: &Path,
    old_current_bytes: &[u8],
    previous: &Option<Vec<u8>>,
) -> Result<(), String> {
    if let Some(bytes) = previous {
        return write_atomic(path, bytes)
            .map_err(|err| format!("offline previous authority restoration failed: {err}"));
    }
    // Only the protected installer is permitted to create previous.pb when
    // none existed. It copies exact old current.pb, so a different new file
    // must not be deleted by compensation.
    match fs::read(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "OFFLINE_PREVIOUS_RESTORE_BLOCKED: previous state unreadable: {err}"
        )),
        Ok(bytes) if bytes == old_current_bytes => fs::remove_file(path)
            .map_err(|err| format!("offline generated previous authority removal failed: {err}")),
        Ok(_) => Err(
            "OFFLINE_PREVIOUS_RESTORE_BLOCKED: new previous.pb is not the exact saved current authority"
                .to_owned(),
        ),
    }
}

// This bounded pointer-only compensation can be fault-injected on any OS.
// It never calls SCM or starts a process. Every failure stops before the
// current authority is rewritten, leaving an inspectable split state.
fn restore_offline_authority_pointers(
    install_root: &Path,
    old_current_bytes: &[u8],
    previous: &Option<Vec<u8>>,
) -> Result<(), String> {
    restore_offline_previous(
        &install_root.join("previous.pb"),
        old_current_bytes,
        previous,
    )?;
    write_atomic(&install_root.join("current.pb"), old_current_bytes)
        .map_err(|err| format!("offline current authority restoration failed: {err}"))
}

// A failed or uncertain offline handoff never starts either controller or
// sing-box. Restore exact previous authority only from locally verified bytes.
fn restore_offline_release(
    install_root: &Path,
    before: &WindowsActivationState,
    current_bytes: &[u8],
    previous_bytes: &Option<Vec<u8>>,
    alternate_scm_owner: Option<&WindowsActivationState>,
) -> Result<(), String> {
    // Never read the possibly torn current.pb to decide whether compensation
    // is safe. Each SCM candidate must be a verified immutable activation:
    // the old snapshot, or the exact new/rollback candidate supplied above.
    // Any third owner must fail closed without writing the release pointers.
    if require_offline_windows_owner_from_snapshot(install_root, before).is_err() {
        let replacement = alternate_scm_owner.ok_or_else(|| {
            "OFFLINE_RESTORE_BLOCKED: current SCM does not match saved old authority and no exact replacement was proved".to_owned()
        })?;
        require_offline_windows_owner_from_snapshot(install_root, replacement)?;
        if replacement.controller_path != before.controller_path {
            offline_retarget_controller_service_checked(install_root, replacement, before, true)?;
        }
    }
    // Restore previous first; a failed prerequisite never overwrites current.
    restore_offline_authority_pointers(install_root, current_bytes, previous_bytes)?;
    sync_stable_windows_release_tools(install_root, before)?;
    retarget_privileged_task(install_root, &before.console_path)?;
    require_offline_windows_owner(install_root, before)?;
    Ok(())
}

#[cfg(windows)]
fn offline_hold_controller_stopped(
    install_root: &Path,
    before: &WindowsActivationState,
) -> Result<(), String> {
    require_offline_windows_owner(install_root, before)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("offline SCM manager unavailable: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|err| format!("offline SCM owner unavailable: {err}"))?;
    let config = service.query_config().map_err(|err| err.to_string())?;
    let account = config
        .account_name
        .as_ref()
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT) {
        return Err("OFFLINE_HANDOFF_BLOCKED: SCM identity changed".to_owned());
    }
    let next = ServiceInfo {
        name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_CONTROLLER_SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(&before.controller_path),
        launch_arguments: vec![
            OsString::from("windows-service"),
            install_root.as_os_str().to_owned(),
            OsString::from(INSTALLED_CONTROLLER_ADDR),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)),
        account_password: None,
    };
    service
        .change_config(&next)
        .map_err(|err| format!("offline SCM hold failed: {err}"))?;
    let observed = service.query_config().map_err(|err| err.to_string())?;
    let status = service.query_status().map_err(|err| err.to_string())?;
    if observed.start_type != ServiceStartType::OnDemand
        || status.current_state != ServiceState::Stopped
        || status.process_id.is_some()
    {
        return Err("OFFLINE_HANDOFF_BLOCKED: stopped manual-start SCM readback failed".to_owned());
    }
    require_offline_windows_owner(install_root, before)
}

#[cfg(not(windows))]
fn offline_hold_controller_stopped(
    _install_root: &Path,
    _before: &WindowsActivationState,
) -> Result<(), String> {
    Err("offline SCM hold is Windows-only".to_owned())
}

fn offline_activate_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    require_exact_immutable_activation_console(install_root)?;
    offline_activate_privileged_release_with_installer(install_root, request, None)
}

fn offline_activate_privileged_release_with_installer(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
    verified_bootstrap_installer: Option<&Path>,
) -> Result<(String, String, Option<String>), String> {
    let before = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    require_offline_windows_owner(install_root, &before)?;
    let revision = request
        .accepted_revision
        .as_deref()
        .ok_or_else(|| "offline activation requires accepted revision".to_owned())?;
    let target = request
        .release_set_sha256
        .as_deref()
        .ok_or_else(|| "offline activation requires exact ReleaseSet SHA256".to_owned())?;
    if target.len() != 64
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(
            "offline activation requires exact lowercase canonical revision and SHA256".to_owned(),
        );
    }
    if before.release_set_sha256 == target {
        return Err(
            "offline activation target already current; use read-only diagnose, do not replay"
                .to_owned(),
        );
    }
    let current_bytes = fs::read(install_root.join("current.pb")).map_err(|err| err.to_string())?;
    let previous_path = install_root.join("previous.pb");
    let previous_bytes = snapshot_offline_previous(&previous_path)?;
    if previous_bytes.is_some() {
        load_verified_activation_path(install_root, &previous_path, "previous.pb")
            .map_err(|err| format!("OFFLINE_PREVIOUS_SNAPSHOT_BLOCKED: {err}"))?;
    }
    // This is the first mutation. Hold SCM on manual start BEFORE modifying
    // release pointers so an unexpected reboot cannot start ManagedTun.
    offline_hold_controller_stopped(install_root, &before)?;
    let installer = verified_bootstrap_installer
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            install_root
                .join("bootstrap")
                .join("install-windows-release.ps1")
        });
    if !installer.is_file() {
        return Err("protected offline installer missing".to_owned());
    }
    // Revalidation after the offline handoff must use the same direct
    // GitHub policy; Windows PowerShell 5.1 lacks -NoProxy.
    let output = Command::new("pwsh.exe")
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
            revision,
            "-ReleaseSetSha256",
            target,
            "-InstallRoot",
        ])
        .arg(install_root)
        .arg("-Offline")
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("offline protected installer invocation failed: {err}"))?;
    let post = match load_verified_activation(install_root) {
        Ok(value) => value,
        Err(err) => {
            let compensation = restore_offline_release(
                install_root,
                &before,
                &current_bytes,
                &previous_bytes,
                None,
            );
            return Err(format!(
                "offline installer outcome uncertain, current.pb unreadable: {err}; compensation={compensation:?}; do not retry blindly"
            ));
        }
    };
    if !output.status.success() || post.release_set_sha256 != target {
        // No blind replay of installer after an unknown result.
        let restore =
            restore_offline_release(install_root, &before, &current_bytes, &previous_bytes, None);
        return Err(format!(
            "offline installer not accepted; exit={}; restore={restore:?}; {}",
            output.status.code().unwrap_or(-1),
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        ));
    }
    let handoff = offline_retarget_controller_service(install_root, &before, &post)
        .and_then(|_| retarget_privileged_task(install_root, &post.console_path))
        .and_then(|_| {
            #[cfg(windows)]
            if verified_bootstrap_installer.is_some() {
                verify_offline_bootstrap_dispatcher(&post.console_path)?;
            }
            Ok(())
        });
    if let Err(err) = handoff {
        let restore = restore_offline_release(
            install_root,
            &before,
            &current_bytes,
            &previous_bytes,
            Some(&post),
        );
        return Err(format!(
            "offline owner handoff failed: {err}; compensation={restore:?}; do not blindly retry"
        ));
    }
    if let Err(err) = require_offline_windows_owner(install_root, &post) {
        let compensation = restore_offline_release(
            install_root,
            &before,
            &current_bytes,
            &previous_bytes,
            Some(&post),
        );
        return Err(format!(
            "offline post-handoff owner not verified: {err}; compensation={compensation:?}; do not retry blindly"
        ));
    }
    Ok((
        "OFFLINE_RELEASE_ACTIVATED".to_owned(),
        "exact ReleaseSet installed; SCM remains Stopped; no TUN/DNS/routes changed and no service started".to_owned(),
        Some(post.release_set_sha256),
    ))
}

#[cfg(windows)]
fn encoded_powershell_command(script: &str) -> String {
    // -EncodedCommand is the native PowerShell contract for programmatic
    // invocation: UTF-16LE base64, with no ambiguity from Windows argv quoting.
    use base64::Engine as _;
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(windows)]
fn require_offline_bootstrap_installer_archive_identity(
    verified_zip: &Path,
    candidate_installer: &Path,
) -> Result<(), String> {
    // No install, SCM, task, or BEGIN mutation. The target ZIP and binaries
    // have already passed verify-windows; prove installer identity separately.
    // Phase-labelled evidence is bounded and never includes installer bytes.
    let verify_script = r#"
$ErrorActionPreference = 'Stop'
$phase = 'LOAD_COMPRESSION'
try {
    # Keep the verified host-specific ZIP assembly loader. The local digest
    # below uses direct .NET streams instead of module-autoloaded Get-FileHash.
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $phase = 'OPEN_ZIP'
    $archive = [IO.Compression.ZipFile]::OpenRead($env:EDGE_BOOTSTRAP_VERIFIED_ZIP)
    try {
        $phase = 'FIND_UNIQUE_ENTRY'
        $entries = @($archive.Entries | Where-Object {
            [string]$_.FullName.Replace('\','/') -ceq 'bootstrap/install-windows-release.ps1'
        })
        if ($entries.Count -ne 1) { throw 'ZIP_ENTRY_COUNT_INVALID' }
        $phase = 'HASH_ZIP_ENTRY'
        $stream = $entries[0].Open()
        try {
            $hasher = [Security.Cryptography.SHA256]::Create()
            try { $expected = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-','') }
            finally { $hasher.Dispose() }
        } finally { $stream.Dispose() }
    } finally { $archive.Dispose() }
    $phase = 'HASH_LOCAL_INSTALLER'
    $fileStream = [IO.File]::OpenRead($env:EDGE_BOOTSTRAP_TARGET_INSTALLER)
    try {
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $actual = ([BitConverter]::ToString($hasher.ComputeHash($fileStream))).Replace('-','') }
        finally { $hasher.Dispose() }
    } finally { $fileStream.Dispose() }
    $phase = 'COMPARE_DIGEST'
    if ($actual -cne $expected) { throw 'candidate installer hash differs from verified ZIP' }
} catch {
    # Do not print paths, ZIP entries, credentials, or complete PowerShell
    # exception messages. The phase and stable error ID suffice for forensics.
    $id = [string]$_.FullyQualifiedErrorId
    if ($id -notmatch '^[a-zA-Z0-9,._-]{1,96}$') { $id = 'UNCLASSIFIED' }
    [Console]::Error.WriteLine("ZIP_PROOF_PHASE=$phase;ERROR_ID=$id")
    exit 82
}
"#;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_powershell_command(verify_script),
        ])
        .env("EDGE_BOOTSTRAP_VERIFIED_ZIP", verified_zip)
        .env("EDGE_BOOTSTRAP_TARGET_INSTALLER", candidate_installer)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: ZIP proof host unavailable: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "OFFLINE_BOOTSTRAP_BLOCKED: ZIP-to-installer verification failed; child_exit={}; {}",
            output.status.code().unwrap_or(-1),
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_offline_bootstrap_dispatcher(exact_console: &str) -> Result<(), String> {
    // Readback after retargeting the ONE existing task is required before
    // committing a successful offline handoff; never trust schtasks exit alone.
    let proof = r#"
$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName 'EdgePlatformPrivilegedDispatch' -ErrorAction Stop
if ($null -eq $task) { throw 'existing SYSTEM dispatcher missing' }
# Localized principal names (e.g. 'СИСТЕМА') are never authority:
# resolve by Windows itself and compare only the immutable LocalSystem SID.
$principalName = [string]$task.Principal.UserId
try {
    $principalSid = if ($principalName -ceq 'S-1-5-18') {
        'S-1-5-18'
    } else {
        ([System.Security.Principal.NTAccount]::new($principalName)).Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    }
} catch {
    throw 'existing SYSTEM dispatcher principal SID cannot be resolved'
}
if ($principalSid -cne 'S-1-5-18' -or
    [string]$task.State -cne 'Ready' -or
    [string]$task.Principal.RunLevel -cne 'Highest' -or
    [string]$task.Principal.LogonType -cne 'ServiceAccount' -or
    @($task.Actions).Count -ne 1) {
    throw 'existing SYSTEM dispatcher principal/state changed'
}
$action = @($task.Actions)[0]
if ([string]$action.Execute.Trim('"') -cne $env:EDGE_BOOTSTRAP_EXPECTED_CONSOLE -or
    [string]$action.Arguments -notmatch '^privileged-dispatch --install-root "?C:\\sing-box"?$') {
    throw 'exact immutable dispatcher action/arguments changed'
}
"#;
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", proof])
        .env("EDGE_BOOTSTRAP_EXPECTED_CONSOLE", exact_console)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: dispatcher proof unavailable: {err}"))?;
    if !status.success() {
        return Err(
            "OFFLINE_BOOTSTRAP_BLOCKED: exact SYSTEM dispatcher readback failed".to_owned(),
        );
    }
    Ok(())
}

fn offline_bootstrap_identifiers_valid(revision: &str, digest: &str) -> bool {
    revision.len() == 40
        && digest.len() == 64
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(windows)]
fn offline_bootstrap_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    // One operator-authorized local admin invocation from the independently
    // verified NEW immutable console. The installed legacy SYSTEM dispatcher
    // never sees a wire operation it does not understand.
    if install_root != Path::new(r"C:\sing-box") {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: unexpected Windows root".to_owned());
    }
    let revision = request
        .accepted_revision
        .as_deref()
        .ok_or_else(|| "OFFLINE_BOOTSTRAP_BLOCKED: accepted revision missing".to_owned())?;
    let target = request
        .release_set_sha256
        .as_deref()
        .ok_or_else(|| "OFFLINE_BOOTSTRAP_BLOCKED: ReleaseSet missing".to_owned())?;
    if !offline_bootstrap_identifiers_valid(revision, target) {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: malformed exact revision or digest".to_owned());
    }
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32 {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: canonical target is not ProxyOnly".to_owned());
    }
    let before = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    if before.release_set_sha256 == target {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: exact distinct legacy release required".to_owned());
    }
    require_offline_windows_owner(install_root, &before)?;
    // Datapath mode belongs to the immutable release's compiled policy,
    // not to WindowsActivationState. Prove the old binary's exact doctor.
    let old_doctor = Command::new(&before.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: old doctor missing: {err}"))?;
    let old_readout = String::from_utf8_lossy(&old_doctor.stdout);
    if !old_readout
        .lines()
        .any(|line| line == "windows_datapath_mode=ManagedTun")
    {
        return Err(
            "OFFLINE_BOOTSTRAP_BLOCKED: exact stopped old ManagedTun source unproven".to_owned(),
        );
    }

    let candidate = install_root.join("releases").join(target);
    let console = candidate.join("bin").join("edge-console.exe");
    let current_exe = env::current_exe().map_err(|err| err.to_string())?;
    if current_exe.canonicalize().map_err(|err| err.to_string())?
        != console.canonicalize().map_err(|err| err.to_string())?
    {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: not exact verified target console".to_owned());
    }
    let stage_installer = candidate
        .join("bootstrap")
        .join("install-windows-release.ps1");
    if !stage_installer.is_file() {
        return Err("OFFLINE_BOOTSTRAP_BLOCKED: target installer missing".to_owned());
    }
    // The native verifier checks manifest, ZIP and ALL exact target binaries.
    // Never accept a caller-provided executable/installer or download command.
    let verification = Command::new(candidate.join("bin").join("edge-release-set.exe"))
        .args(["verify-windows", "--input"])
        .arg(candidate.join("release-set.pb"))
        .arg("--sha256-file")
        .arg(candidate.join("release-set.pb.sha256"))
        .arg("--windows-artifact")
        .arg(candidate.join("edge-platform-windows.zip"))
        .arg("--windows-controller")
        .arg(candidate.join("bin").join("edge-controller.exe"))
        .arg("--windows-console")
        .arg(&console)
        .arg("--windows-diagnostic")
        .arg(candidate.join("bin").join("edge-diagnostic.exe"))
        .arg("--windows-sing-box")
        .arg(candidate.join("bin").join("sing-box.exe"))
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: verifier unavailable: {err}"))?;
    if !verification.status.success() {
        return Err(
            "OFFLINE_BOOTSTRAP_BLOCKED: target ReleaseSet or binary verification failed".to_owned(),
        );
    }
    require_offline_bootstrap_installer_archive_identity(
        &candidate.join("edge-platform-windows.zip"),
        &stage_installer,
    )?;

    // Only an elevated local Windows admin can open CHANGE_CONFIG on this
    // SCM owner. Prove permission before creating the non-replayable intent.
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("OFFLINE_BOOTSTRAP_BLOCKED: SCM unavailable: {err}"))?;
    let _authorized_service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_BLOCKED: local admin authorization absent: {err}")
        })?;

    // The accepted protected main, immutable release tag, merge-parent source
    // tree, and target package are verified by the existing installer BEFORE
    // any SCM, current.pb or dispatcher mutation.
    let root = install_root
        .to_str()
        .ok_or_else(|| "OFFLINE_BOOTSTRAP_BLOCKED: invalid Windows root".to_owned())?;
    // The canonical offline installer requires PowerShell 7 -NoProxy.
    // Reject an unavailable pwsh before its irreversible BEGIN, never fall
    // back to Windows PowerShell 5.1 or the broken ambient proxy path.
    let preflight = Command::new("pwsh.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&stage_installer)
        .args([
            "-AcceptedRevision",
            revision,
            "-ReleaseSetSha256",
            target,
            "-InstallRoot",
            root,
            "-Offline",
            "-StageOnly",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_BLOCKED: release preflight unavailable: {err}")
        })?;
    if !preflight.status.success() {
        return Err(format!(
            "OFFLINE_BOOTSTRAP_BLOCKED: accepted release preflight failed: {}",
            bounded_privileged_child_evidence(&preflight.stdout, &preflight.stderr)
        ));
    }
    require_offline_windows_owner(install_root, &before)?;

    require_offline_bootstrap_installer_archive_identity(
        &candidate.join("edge-platform-windows.zip"),
        &stage_installer,
    )?;

    verify_offline_bootstrap_dispatcher(&before.console_path)?;

    // Create exactly one durable BEGIN before the first SCM mutation.
    // Never replay after a lost result, even if the old release was restored.
    let intent = install_root.join("offline-bootstrap-intent-v1");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&intent)
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_BLOCKED: intent already exists or cannot be created: {err}")
        })?;
    let marker = format!(
        "schema=sing-box.windows-offline-bootstrap/v1\nfrom={}\nto={target}\naccepted_revision={revision}\n",
        before.release_set_sha256,
    );
    file.write_all(marker.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|err| {
            format!("OFFLINE_BOOTSTRAP_UNKNOWN: durable intent failure: {err}; do not replay")
        })?;
    drop(file);
    offline_activate_privileged_release_with_installer(
        install_root,
        request,
        Some(&stage_installer),
    )
}

fn offline_rollback_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    require_exact_immutable_activation_console(install_root)?;
    let (current, previous) = load_previous_release_rollback_pair(install_root)?;
    require_managed_tun_rollback_pair(request, &current, &previous)?;
    require_offline_windows_owner(install_root, &current)?;
    let current_bytes = fs::read(install_root.join("current.pb")).map_err(|err| err.to_string())?;
    let previous_bytes =
        fs::read(install_root.join("previous.pb")).map_err(|err| err.to_string())?;
    offline_retarget_controller_service(install_root, &current, &previous)?;
    if let Err(err) = write_atomic(&install_root.join("current.pb"), &previous_bytes)
        .map_err(|err| err.to_string())
        .and_then(|_| sync_stable_windows_release_tools(install_root, &previous))
        .and_then(|_| retarget_privileged_task(install_root, &previous.console_path))
    {
        let restored = restore_offline_release(
            install_root,
            &current,
            &current_bytes,
            &Some(previous_bytes),
            Some(&previous),
        );
        return Err(format!(
            "offline rollback handoff failed: {err}; compensation={restored:?}; do not retry blindly"
        ));
    }
    require_offline_windows_owner(install_root, &previous)?;
    Ok((
        "OFFLINE_PREVIOUS_RELEASE_RESTORED".to_owned(),
        "exact previous ReleaseSet restored with stopped SCM; no service or TUN started".to_owned(),
        Some(previous.release_set_sha256),
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

// An explicit previous-release rollback is a ManagedTun-to-ManagedTun release
// handoff, never a general permission to remove TUN or use an unknown target.
// The submitted exact authority pair is checked again by the privileged owner
// BEFORE sing-box is stopped; a changed previous.pb fails without mutation.
fn require_managed_tun_rollback_pair(
    request: &WindowsPrivilegedRequest,
    current: &WindowsActivationState,
    previous: &WindowsActivationState,
) -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode != WindowsDatapathMode::ManagedTun as i32 {
        return Err("rollback refuses a non-ManagedTun accepted desired mode".to_owned());
    }
    require_exact_rollback_authority_pair(request, current, previous)
}

fn require_exact_rollback_authority_pair(
    request: &WindowsPrivilegedRequest,
    current: &WindowsActivationState,
    previous: &WindowsActivationState,
) -> Result<(), String> {
    if current.release_set_sha256 == previous.release_set_sha256 {
        return Err("rollback refuses identical current and previous release".to_owned());
    }
    if request.accepted_revision.as_deref() != Some(current.source_revision.as_str())
        || request.release_set_sha256.as_deref() != Some(previous.release_set_sha256.as_str())
    {
        return Err(
            "rollback authority changed since exact submitted current/previous proof".to_owned(),
        );
    }
    Ok(())
}

fn rollback_privileged_release(
    install_root: &Path,
    request: &WindowsPrivilegedRequest,
) -> Result<(String, String, Option<String>), String> {
    require_exact_immutable_activation_console(install_root)?;
    let current_path = install_root.join("current.pb");
    let previous_path = install_root.join("previous.pb");
    let (current, previous) = load_previous_release_rollback_pair(install_root)?;
    require_managed_tun_rollback_pair(request, &current, &previous)?;

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
            initial_commit_intent_sha256: None,
            initial_commit_slot: None,
            initial_recovery_intent_sha256: None,
            initial_candidate_sha256: None,
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
fn proxy_only_controller_service_lifecycle(
    install_root: &Path,
    start: bool,
) -> Result<(String, String, Option<String>), String> {
    // Exactly one SYSTEM dispatcher owns the SCM mutation. A GitHub runner
    // never gets SCM privileges and the normal console cannot start a service.
    let desired = canonical_production_desired_state()?;
    if desired.windows_datapath_mode != WindowsDatapathMode::ProxyOnly as i32 {
        return Err("PROXY_ONLY_SCM_BLOCKED: accepted desired mode is not ProxyOnly".to_owned());
    }
    let active = load_verified_activation(install_root).map_err(|err| err.to_string())?;
    let diagnostic = Command::new(&active.diagnostic_path)
        .arg("doctor")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("PROXY_ONLY_SCM_BLOCKED: exact diagnostic failed: {err}"))?;
    let fields = String::from_utf8_lossy(&diagnostic.stdout);
    let has = |line: &str| fields.lines().any(|value| value.trim() == line);
    if !has("windows_datapath_mode=ProxyOnly")
        || !has("managed_tun_present=false")
        || !has("exact_release_files=PASS")
        || !has(&format!("release_set_sha256={}", active.release_set_sha256))
    {
        return Err("PROXY_ONLY_SCM_BLOCKED: exact release / no-TUN evidence missing".to_owned());
    }
    let observed = classify_runtime_process(&local_singbox_config_path(install_root));
    if matches!(observed, RuntimeProcessClassification::Conflicting(_)) {
        return Err("PROXY_ONLY_SCM_BLOCKED: conflicting sing-box owner".to_owned());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("PROXY_ONLY_SCM_BLOCKED: SCM unavailable: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::START
                | ServiceAccess::STOP,
        )
        .map_err(|err| format!("PROXY_ONLY_SCM_BLOCKED: owner unavailable: {err}"))?;
    let config = service.query_config().map_err(|err| err.to_string())?;
    let exact_command = format!(
        "{} windows-service {} {}",
        active.controller_path,
        install_root.display(),
        INSTALLED_CONTROLLER_ADDR,
    );
    let account = config
        .account_name
        .as_deref()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();
    if config.executable_path.to_string_lossy() != exact_command
        || !account.eq_ignore_ascii_case(WINDOWS_CONTROLLER_SERVICE_ACCOUNT)
        || config.start_type != ServiceStartType::OnDemand
    {
        return Err("PROXY_ONLY_SCM_BLOCKED: exact immutable Manual SCM owner mismatch".to_owned());
    }
    let before = service.query_status().map_err(|err| err.to_string())?;
    let addr: SocketAddr = INSTALLED_CONTROLLER_ADDR
        .parse::<SocketAddr>()
        .map_err(|err| err.to_string())?;
    let code = if start {
        match before.current_state {
            ServiceState::Stopped => {
                if before.process_id.is_some()
                    || !matches!(observed, RuntimeProcessClassification::Absent)
                    || controller_is_listening(addr)
                {
                    return Err(
                        "PROXY_ONLY_SCM_BLOCKED: stopped owner has residual runtime/listener"
                            .to_owned(),
                    );
                }
                service
                    .start::<&str>(&[])
                    .map_err(|err| format!("PROXY_ONLY_SCM_START_UNKNOWN: {err}"))?;
                wait_for_service_state(
                    &service,
                    ServiceState::Running,
                    Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
                )?;
                "PROXY_ONLY_SCM_STARTED"
            }
            ServiceState::Running
                if before.process_id.is_some() && controller_is_listening(addr) =>
            {
                "PROXY_ONLY_SCM_ALREADY_RUNNING"
            }
            other => {
                return Err(format!(
                    "PROXY_ONLY_SCM_BLOCKED: unsafe start state {other:?}"
                ));
            }
        }
    } else {
        match before.current_state {
            ServiceState::Stopped
                if before.process_id.is_none()
                    && matches!(observed, RuntimeProcessClassification::Absent)
                    && !controller_is_listening(addr) =>
            {
                "PROXY_ONLY_SCM_ALREADY_STOPPED"
            }
            ServiceState::Running
                if before.process_id.is_some() && controller_is_listening(addr) =>
            {
                // Stop the exact SCM owner FIRST. While the controller is
                // Running its supervisor may relaunch a child immediately
                // after a direct process stop (physically observed on Windows).
                // SCM shutdown sets STOP_REQUESTED, aborts supervision and
                // terminates only its owned child before reporting Stopped.
                // Never kill a process from this caller or touch TUN, DNS,
                // routes, foreign sing-box or CloudflareWARP.
                service
                    .stop()
                    .map_err(|err| format!("PROXY_ONLY_SCM_STOP_UNKNOWN: {err}"))?;
                wait_for_service_state(
                    &service,
                    ServiceState::Stopped,
                    Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
                )
                .map_err(|err| format!("PROXY_ONLY_SCM_STOP_UNKNOWN: {err}"))?;
                if !matches!(
                    classify_runtime_process(&local_singbox_config_path(install_root)),
                    RuntimeProcessClassification::Absent
                ) {
                    return Err(
                        "PROXY_ONLY_SCM_STOP_UNKNOWN: managed child remains after SCM stop"
                            .to_owned(),
                    );
                }
                "PROXY_ONLY_SCM_STOPPED"
            }
            other => {
                return Err(format!(
                    "PROXY_ONLY_SCM_BLOCKED: unsafe stop state {other:?}"
                ));
            }
        }
    };
    let after = service.query_status().map_err(|err| err.to_string())?;
    let after_config = service.query_config().map_err(|err| err.to_string())?;
    let expected = if start {
        ServiceState::Running
    } else {
        ServiceState::Stopped
    };
    if after.current_state != expected
        || (start && (after.process_id.is_none() || !controller_is_listening(addr)))
        || (!start
            && (after.process_id.is_some()
                || controller_is_listening(addr)
                || !matches!(
                    classify_runtime_process(&local_singbox_config_path(install_root)),
                    RuntimeProcessClassification::Absent
                )))
        || after_config.start_type != ServiceStartType::OnDemand
    {
        return Err("PROXY_ONLY_SCM_UNKNOWN: SCM readback failed; do not replay".to_owned());
    }
    Ok((
        code.to_owned(),
        format!("mode=ProxyOnly;scm={expected:?};startup=OnDemand;tun=ABSENT;network_mutations=0"),
        Some(active.release_set_sha256),
    ))
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

    fn offline_test_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "edge-offline-restore-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    #[cfg(windows)]
    fn create_zip_identity_fixture(root: &Path, include_installer: bool) -> (PathBuf, PathBuf) {
        let package = root.join("package");
        let bootstrap = package.join("bootstrap");
        fs::create_dir_all(&bootstrap).unwrap();
        let expected_installer = bootstrap.join("install-windows-release.ps1");
        fs::write(
            &expected_installer,
            b"Write-Output 'verified-archive-bytes'\r\n",
        )
        .unwrap();
        if !include_installer {
            fs::remove_file(&expected_installer).unwrap();
            fs::write(package.join("different.txt"), b"not an installer").unwrap();
        }
        let zip = root.join("candidate.zip");
        let fixture_script = r#"
$ErrorActionPreference='Stop'
Compress-Archive -Path (Join-Path $env:EDGE_ZIP_TEST_PACKAGE '*') -DestinationPath $env:EDGE_ZIP_TEST_DEST -CompressionLevel Optimal
"#;
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded_powershell_command(fixture_script),
            ])
            .env("EDGE_ZIP_TEST_PACKAGE", &package)
            .env("EDGE_ZIP_TEST_DEST", &zip)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "disposable ZIP fixture build failed: {}",
            bounded_privileged_child_evidence(&output.stdout, &output.stderr)
        );
        (zip, expected_installer)
    }

    #[cfg(windows)]
    #[test]
    fn native_offline_zip_proof_uses_real_rust_child_and_rejects_all_mismatches() {
        // No mocked PowerShell invocation: run this on the native Windows
        // candidate runner, using the exact Rust -> powershell.exe argv/env.
        // The root deliberately contains Unicode to exercise path encoding.
        let root = offline_test_root("zip-unicode-кириллица");
        let (zip, packaged) = create_zip_identity_fixture(&root, true);
        if let Err(err) = require_offline_bootstrap_installer_archive_identity(&zip, &packaged) {
            panic!("positive native ZIP proof failed: {err}");
        }
        fs::write(&packaged, b"tampered packaged script").unwrap();
        let mismatch =
            require_offline_bootstrap_installer_archive_identity(&zip, &packaged).unwrap_err();
        assert!(mismatch.contains("COMPARE_DIGEST"), "{mismatch}");
        fs::remove_file(&packaged).unwrap();
        let missing =
            require_offline_bootstrap_installer_archive_identity(&zip, &packaged).unwrap_err();
        assert!(missing.contains("HASH_LOCAL_INSTALLER"), "{missing}");

        let empty_root = offline_test_root("zip-no-entry");
        let (no_entry, _) = create_zip_identity_fixture(&empty_root, false);
        let absent =
            require_offline_bootstrap_installer_archive_identity(&no_entry, &packaged).unwrap_err();
        assert!(absent.contains("FIND_UNIQUE_ENTRY"), "{absent}");

        let corrupt_zip = root.join("corrupt.zip");
        fs::write(&corrupt_zip, b"not-a-zip").unwrap();
        let corrupt = require_offline_bootstrap_installer_archive_identity(&corrupt_zip, &packaged)
            .unwrap_err();
        assert!(corrupt.contains("OPEN_ZIP"), "{corrupt}");

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(empty_root);
    }

    #[cfg(windows)]
    #[test]
    fn encoded_powershell_command_survives_windows_command_quoting() {
        let probe = r#"
$ErrorActionPreference = 'Stop'
if ('embedded "quotes" and кириллица' -cne 'embedded "quotes" and кириллица') {
    throw 'argv encoding defect'
}
"#;
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded_powershell_command(probe),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn previous_snapshot_only_treats_missing_file_as_absence() {
        let root = offline_test_root("snapshot");
        let previous = root.join("previous.pb");
        assert!(snapshot_offline_previous(&previous).unwrap().is_none());
        fs::write(&previous, b"previous-exact").unwrap();
        assert_eq!(
            snapshot_offline_previous(&previous).unwrap(),
            Some(b"previous-exact".to_vec())
        );
        fs::remove_file(&previous).unwrap();
        fs::create_dir(&previous).unwrap();
        assert!(
            snapshot_offline_previous(&previous)
                .unwrap_err()
                .contains("OFFLINE_PREVIOUS_SNAPSHOT_BLOCKED")
        );
        assert!(previous.is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_pointer_restore_uses_verified_saved_bytes_even_when_current_torn() {
        let root = offline_test_root("torn-pointer");
        let current = root.join("current.pb");
        let previous = root.join("previous.pb");
        fs::write(&current, b"torn-current").unwrap();
        fs::write(&previous, b"new-previous").unwrap();
        restore_offline_authority_pointers(
            &root,
            b"verified-old-current",
            &Some(b"verified-old-previous".to_vec()),
        )
        .unwrap();
        assert_eq!(fs::read(&current).unwrap(), b"verified-old-current");
        assert_eq!(fs::read(&previous).unwrap(), b"verified-old-previous");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_pointer_restore_never_deletes_unknown_previous_or_replays_current() {
        let root = offline_test_root("unknown-previous");
        let current = root.join("current.pb");
        let previous = root.join("previous.pb");
        fs::write(&current, b"new-current").unwrap();
        fs::write(&previous, b"foreign-previous").unwrap();
        let err =
            restore_offline_authority_pointers(&root, b"verified-old-current", &None).unwrap_err();
        assert!(err.contains("OFFLINE_PREVIOUS_RESTORE_BLOCKED"));
        assert_eq!(fs::read(&current).unwrap(), b"new-current");
        assert_eq!(fs::read(&previous).unwrap(), b"foreign-previous");

        fs::write(&previous, b"verified-old-current").unwrap();
        restore_offline_authority_pointers(&root, b"verified-old-current", &None).unwrap();
        assert_eq!(fs::read(&current).unwrap(), b"verified-old-current");
        assert!(!previous.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_pointer_restore_blocks_unreadable_previous_before_current_rewrite() {
        let root = offline_test_root("read-error");
        let current = root.join("current.pb");
        let previous = root.join("previous.pb");
        fs::write(&current, b"torn-current").unwrap();
        fs::create_dir(&previous).unwrap();
        assert!(
            restore_offline_authority_pointers(&root, b"saved-current", &None)
                .unwrap_err()
                .contains("OFFLINE_PREVIOUS_RESTORE_BLOCKED")
        );
        assert_eq!(fs::read(&current).unwrap(), b"torn-current");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_bootstrap_identifiers_require_exact_lowercase_immutable_values() {
        let revision = "a".repeat(40);
        let digest = "b".repeat(64);
        assert!(offline_bootstrap_identifiers_valid(&revision, &digest));
        assert!(!offline_bootstrap_identifiers_valid(
            &revision[..39],
            &digest
        ));
        assert!(!offline_bootstrap_identifiers_valid(
            &revision,
            &digest[..63]
        ));
        assert!(!offline_bootstrap_identifiers_valid(
            &revision.to_uppercase(),
            &digest
        ));
        assert!(!offline_bootstrap_identifiers_valid(
            &revision,
            &format!("{}g", &digest[..63])
        ));
    }

    #[test]
    fn offline_release_handoff_refuses_running_scm_any_child_tun_or_wrong_owner() {
        assert!(offline_handoff_gate(true, true, true, true).is_ok());
        for (stopped, zero_process, no_tun, exact_owner) in [
            (false, true, true, true),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, false),
            (false, false, false, false),
        ] {
            assert!(
                offline_handoff_gate(stopped, zero_process, no_tun, exact_owner)
                    .unwrap_err()
                    .contains("OFFLINE_HANDOFF_BLOCKED")
            );
        }
    }

    #[test]
    fn credential_origin_is_dedicated_read_only_wire_operation() {
        assert_eq!(WindowsPrivilegedOperation::CredentialOrigin as i32, 18);
        let request = WindowsPrivilegedRequest {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            request_id: "worker-origin".to_owned(),
            operation: WindowsPrivilegedOperation::CredentialOrigin as i32,
            accepted_revision: None, release_set_sha256: None,
            credential_generation: None, credential_transition_action: None,
            initial_commit_intent_sha256: None, initial_commit_slot: None,
            initial_recovery_intent_sha256: None, initial_candidate_sha256: None,
        };
        assert_eq!(decode_windows_privileged_request(
            &encode_windows_privileged_request(&request).unwrap()
        ).unwrap().operation, 18);
        assert_eq!(privileged_wait_secs(&request), PRIVILEGED_SHORT_WAIT_SECS);
    }

    #[test]
    fn offline_release_operations_have_dedicated_wire_numbers() {
        assert_eq!(
            WindowsPrivilegedOperation::OfflineActivateRelease as i32,
            12
        );
        assert_eq!(
            WindowsPrivilegedOperation::OfflineRollbackPreviousRelease as i32,
            13
        );
        for operation in [
            WindowsPrivilegedOperation::OfflineActivateRelease,
            WindowsPrivilegedOperation::OfflineRollbackPreviousRelease,
        ] {
            let req = WindowsPrivilegedRequest {
                schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
                request_id: "offline-exact-test".to_owned(),
                operation: operation as i32,
                accepted_revision: Some("a".repeat(40)),
                release_set_sha256: Some("b".repeat(64)),
                credential_generation: None,
                credential_transition_action: None,
                initial_commit_intent_sha256: None,
                initial_commit_slot: None,
                initial_recovery_intent_sha256: None,
                initial_candidate_sha256: None,
            };
            let encoded = encode_windows_privileged_request(&req).unwrap();
            assert_eq!(
                decode_windows_privileged_request(&encoded)
                    .unwrap()
                    .operation,
                operation as i32
            );
            assert_eq!(privileged_wait_secs(&req), PRIVILEGED_ACTIVATE_WAIT_SECS);
            // An offline mutation cannot be re-observed as a successful
            // normal activation without exact stopped SCM and owner proof.
            assert!(activation_matches_request(Path::new("__absent__"), &req).is_none());
        }
    }

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
    fn previous_managed_tun_rollback_requires_exact_unchanged_authority_pair() {
        let root = rollback_test_root();
        let current = rollback_test_activation(&root, "current", &"a".repeat(64));
        let previous = rollback_test_activation(&root, "previous", &"b".repeat(64));
        let mut request = WindowsPrivilegedRequest {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            request_id: "rollback-test".to_owned(),
            operation: WindowsPrivilegedOperation::RollbackPreviousRelease as i32,
            accepted_revision: Some(current.source_revision.clone()),
            release_set_sha256: Some(previous.release_set_sha256.clone()),
            credential_generation: None,
            credential_transition_action: None,
            initial_commit_intent_sha256: None,
            initial_commit_slot: None,
            initial_recovery_intent_sha256: None,
            initial_candidate_sha256: None,
        };
        // The immutable authority pair is checked in both build modes.
        // Actual release rollback remains forbidden on first-install ProxyOnly.
        require_exact_rollback_authority_pair(&request, &current, &previous).unwrap();
        let compiled_mode = canonical_production_desired_state()
            .unwrap()
            .windows_datapath_mode;
        if compiled_mode == WindowsDatapathMode::ManagedTun as i32 {
            require_managed_tun_rollback_pair(&request, &current, &previous).unwrap();
        } else {
            assert_eq!(compiled_mode, WindowsDatapathMode::ProxyOnly as i32);
            assert!(
                require_managed_tun_rollback_pair(&request, &current, &previous)
                    .unwrap_err()
                    .contains("non-ManagedTun")
            );
        }

        request.release_set_sha256 = Some("c".repeat(64));
        assert!(
            require_exact_rollback_authority_pair(&request, &current, &previous)
                .unwrap_err()
                .contains("authority changed")
        );
        request.release_set_sha256 = Some(previous.release_set_sha256.clone());
        request.accepted_revision = Some("f".repeat(40));
        assert!(
            require_exact_rollback_authority_pair(&request, &current, &previous)
                .unwrap_err()
                .contains("authority changed")
        );
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
            initial_commit_intent_sha256: None,
            initial_commit_slot: None,
            initial_recovery_intent_sha256: None,
            initial_candidate_sha256: None,
        };
        let ping = WindowsPrivilegedRequest {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            request_id: "ping".to_owned(),
            operation: WindowsPrivilegedOperation::Ping as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: None,
            initial_commit_intent_sha256: None,
            initial_commit_slot: None,
            initial_recovery_intent_sha256: None,
            initial_candidate_sha256: None,
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
    fn initial_windows_proof_refuses_active_or_incomplete_local_state() {
        assert!(initial_windows_credential_eligibility(false, false, false).is_ok());
        assert!(
            initial_windows_credential_eligibility(true, false, false)
                .unwrap_err()
                .contains("incomplete v2 credential store")
        );
        assert!(
            initial_windows_credential_eligibility(false, true, false)
                .unwrap_err()
                .contains("managed runtime state")
        );
        assert!(initial_windows_credential_eligibility(true, true, true).is_err());
        assert!(
            initial_windows_credential_eligibility(false, false, true)
                .unwrap_err()
                .contains("rendered sing-box config")
        );
    }

    #[test]
    fn persistent_windows_cursor_proof_refuses_torn_store_without_guessing_absence() {
        let root = offline_test_root("first-use-cursor");
        assert_eq!(
            read_bounded_windows_credential_cursor(&root).unwrap(),
            "credential_cursor=ABSENT"
        );
        let store = windows_credential_store_path(&root);
        fs::create_dir_all(&store).unwrap();
        assert!(
            read_bounded_windows_credential_cursor(&root)
                .unwrap_err()
                .contains("no durable cursor")
        );
        fs::write(store.join("state.pb"), b"corrupt").unwrap();
        assert!(read_bounded_windows_credential_cursor(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_credential_status_is_not_a_remote_origin_proof() {
        let active = "credential_cursor=VALID;credential_active_present=true;credential_candidate_present=false;credential_active_generation=7;credential_active_slot=B";
        assert_eq!(
            classify_windows_credential_lifecycle(
                active,
                "PRESENT",
                "PRESENT",
                "PRESENT_NONEMPTY_UNVERIFIED"
            ),
            ("EXISTING_ACTIVE_UNVERIFIED", "READ_ONLY_ORIGIN_RECONCILE")
        );
        assert_eq!(
            classify_windows_credential_lifecycle(
                active,
                "ABSENT",
                "PRESENT",
                "PRESENT_NONEMPTY_UNVERIFIED"
            ),
            ("PARTIAL", "READ_ONLY_RECONCILE")
        );
        assert_eq!(
            classify_windows_credential_lifecycle(
                "credential_cursor=ABSENT",
                "ABSENT",
                "ABSENT",
                "PRESENT_NONEMPTY_UNVERIFIED"
            ),
            ("FRESH_LOCAL_ONLY", "JOURNAL_AUTHORIZATION_REQUIRED")
        );
        assert_eq!(
            classify_windows_credential_lifecycle(
                "credential_cursor=ABSENT",
                "PRESENT",
                "ABSENT",
                "PRESENT_NONEMPTY_UNVERIFIED"
            ),
            ("PARTIAL", "READ_ONLY_RECONCILE")
        );
        assert_eq!(
            classify_windows_credential_lifecycle(
                "credential_cursor=VALID;credential_active_present=false;credential_candidate_present=true",
                "ABSENT",
                "ABSENT",
                "PRESENT_NONEMPTY_UNVERIFIED"
            ),
            (
                "EXISTING_CANDIDATE_UNVERIFIED",
                "READ_ONLY_ORIGIN_RECONCILE"
            )
        );
        assert_eq!(
            classify_windows_credential_lifecycle(
                "credential_cursor=VALID;credential_active_present=true;credential_active_present=false;credential_candidate_present=false",
                "PRESENT",
                "PRESENT",
                "PRESENT_NONEMPTY_UNVERIFIED"
            ),
            ("PARTIAL", "READ_ONLY_RECONCILE")
        );
    }

    #[test]
    fn first_use_recovery_proof_and_full_task_hashes_fit_bounded_result() {
        let tasks = format!(
            "tasks=EdgePlatformController|1|3|{},EdgePlatformReconcile|1|3|{},EdgePlatformShutdown|1|3|{},EdgePlatformPrivilegedDispatch|1|4|{}",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        let cursor = format!(
            "credential_cursor=VALID;credential_active_present=false;credential_candidate_present=true;credential_candidate_generation=38503639351;credential_candidate_slot=B;credential_previous_present=false;credential_active_generation=0;credential_active_slot=NONE;credential_active_sha256=ABSENT;credential_candidate_sha256={};credential_initial_commit_receipt_present=true;credential_initial_commit_intent_sha256={};credential_initial_recovery_receipt_present=false;credential_initial_recovery_intent_sha256=ABSENT",
            "e".repeat(64),
            "f".repeat(64),
        );
        let critical = format!(
            "runtime_evidence=BOUNDED_READ_ONLY;controller_service_error=ABSENT;process_classification=ABSENT;process_evidence_complete=true;process_count=0;managed_pid=ABSENT;managed_parent_pid=ABSENT;controller_pid=ABSENT;{tasks};external_owner_evidence=INCOMPLETE;external_count=0;{cursor};first_use_runtime=PRESENT;first_use_config=PRESENT;first_use_access_identity=PRESENT_NONEMPTY_UNVERIFIED"
        );
        assert!(
            critical.len() > 1024,
            "the original cap made initial recovery unobservable"
        );
        assert!(critical.len() <= RUNTIME_EVIDENCE_RESULT_MAX_BYTES);
        let result = WindowsPrivilegedResult {
            schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
            request_id: "exact-first-use-recovery-evidence".to_owned(),
            success: true,
            code: "RUNTIME_EVIDENCE_READ".to_owned(),
            detail: critical,
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
