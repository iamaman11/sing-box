mod cli;
mod docker_observation;
mod error;
mod host_admin_native;
mod host_bootstrap_access;
mod host_diagnostics;
mod host_enroll;
mod host_native;
mod host_probe;
mod host_snapshot;
mod line2_quality;
mod local_dispatch;
mod mesh_network_diagnostics;
mod network_observation;
mod runtime_environment;
mod runtime_probe;
use runtime_environment::*;
mod mesh_runtime_state;
use mesh_runtime_state::*;
mod runtime_templates;
use runtime_templates::*;
mod legacy_runtime_effects;
use legacy_runtime_effects::*;
mod vm_runtime_observation;

use crate::docker_observation::{
    ContainerRuntimeEvidence, DockerObservation, observe_container_runtime, observe_docker,
};
use crate::host_diagnostics::collect_host_runtime_diagnostics;
use crate::mesh_network_diagnostics::{
    collect_container_network_diagnostics, collect_host_network_diagnostics, extract_route_events,
};
use crate::runtime_probe::{BoundedCommandProbe, bounded_command_probe};
use clap::Parser;
use local_dispatch::run_local;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vm_runtime_observation::*;

use edge_observability::init as init_observability;
use edge_secrets::{
    ACCESS_IDENTITY_FILE_NAME, ApplicationRuntimeSecrets, CredentialOriginSelection,
    CredentialStore, InitialDummySlotProof, attest_worker_credential_origin,
    fetch_canonical_credential_bundle, verify_canonical_dummy_ab_slots,
    verify_initial_selected_dummy_slot,
};
use edge_shared_types::{
    AgentState, AgentVersion, ApplicationBundleReleaseState, ApplyBundleRequest,
    ApplyBundleResponse, BootstrapMode, BootstrapRuntimeRequest, BootstrapRuntimeResponse,
    BundleFile, ContainerRuntimeObservation, CredentialDeliverySlot, CredentialProjectionKind,
    CredentialStateObservation, CredentialTransitionAction, Empty, FileCategory, FilePresence,
    InitialCredentialHostProbeRequest, InitialCredentialHostProbeResponse,
    InitialVmCredentialRuntimeRequest, InitialVmCredentialRuntimeResponse,
    InitialVmLine2EndpointResult, Ipv4NetworkObservation, LocalCredentialState,
    MeshContainerDiagnostics, MeshRuntimeConvergeRequest, MeshRuntimeDiagnostics,
    MeshRuntimeFailureSnapshot, MeshRuntimeState, ReadBundleIdentityRequest,
    ReadBundleIdentityResponse, ReadRenderedArtifactsRequest, ReadRenderedArtifactsResponse,
    RollbackBundleRequest, RollbackBundleResponse, RuntimeProbeEvidence, RuntimeProbeStatus,
    StageCredentialCandidateRequest, VerifyRuntimeRequest, canonical_apply_bundle_digest,
    parse_credential_transition_action,
};
use error::AgentError;
use prost::Message;
use serde::{Deserialize, Serialize};

const DEFAULT_ACCEPTANCE_AGENT_ADDR: &str = "127.0.0.1:50061";
const DEFAULT_STACK_DIR: &str = "/opt/vultr-edge-stack/stack";
const APPLICATION_RELEASE_MARKER: &str = ".application-release.pb";
const PREVIOUS_STACK_DIR: &str = "stack.previous";
const STAGING_STACK_DIR: &str = "stack.next";
const ROLLBACK_STACK_DIR: &str = "stack.rollback";
const RUNTIME_POLICY_FILE: &str = ".env.runtime.policy";
const RUNTIME_ENV_FILE: &str = ".env.runtime";
const RUNTIME_SECRET_DIR: &str = "runtime-secrets";
const RUNTIME_SECRET_FILE: &str = "application-runtime-v1.env";
const MESH_RUNTIME_SECRET_FILE: &str = "mesh-node-v1.env";
const MESH_RUNTIME_FAILURE_FILE: &str = "last-readiness-failure-v1.pb";
const MESH_ACTIVE_REGISTRATION_FILE: &str = "active-registration-v1";
const MESH_STATE_DIR_KEY: &str = "MESH_STATE_DIR";
const MAX_MESH_FAILURE_REASONS: usize = 12;
const MAX_MESH_FAILURE_REASON_CHARS: usize = 512;
const IMAGE_ENV_FILE: &str = ".images.env";
const MESH_NODE_TOKEN_KEY: &str = "MESH_NODE_TOKEN";
const EDGE_GATEWAY_IMAGE_KEY: &str = "EDGE_GATEWAY_IMAGE";
const EDGE_WARP_EGRESS_IMAGE_KEY: &str = "EDGE_WARP_EGRESS_IMAGE";
const EDGE_MESH_IMAGE_KEY: &str = "CLOUDFLARE_MESH_IMAGE";
const WARP_CONTAINER: &str = "vultr-warp-egress";
const LINE1_CONTAINER: &str = "vultr-line1-gateway";
const LINE2_CONTAINER: &str = "vultr-line2-proxy";
const MESH_CONTAINER: &str = "vultr-cloudflare-mesh";
const CLOUDFLARE_TRACE_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";
const POST_BOOTSTRAP_REOBSERVE_ATTEMPTS: usize = 45;
const POST_BOOTSTRAP_REOBSERVE_DELAY: Duration = Duration::from_secs(2);
const MAX_LOCAL_BUNDLE_REQUEST_BYTES: u64 = 8 * 1024 * 1024;

#[tokio::main]
async fn main() -> ExitCode {
    let telemetry = init_observability("edge-agent");
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
        component = "edge-agent",
        correlation_id = %telemetry.id(),
        command,
        event = "command.start",
        "command started"
    );

    match run(parsed).await {
        Ok(()) => {
            tracing::info!(
                component = "edge-agent",
                correlation_id = %telemetry.id(),
                command,
                event = "command.success",
                "command completed"
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(
                component = "edge-agent",
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

async fn run(parsed: cli::Cli) -> Result<(), AgentError> {
    use cli::Command;

    match parsed.command {
        Command::Local { command } => run_local(command).await,
    }
}

/// One compact native VM evidence protobuf. There is no GitHub runner or
/// credential authority here, and this cannot issue a mutation VERIFIED receipt.
async fn run_local_host_observe(stack_dir: &Path) -> Result<(), String> {
    let observed = capture_local_host_observation(stack_dir).await?;
    io::stdout()
        .write_all(&observed.encode_to_vec())
        .map_err(|_| "HOST_OBSERVATION_STDOUT_UNAVAILABLE".to_owned())
}

/// No compiled Docker name list: native readback uses accepted Git selectors.
fn owned_application_container_running(
    names: &[String],
    resources: &[edge_shared_types::FleetVmContainer],
) -> bool {
    resources
        .iter()
        .any(|resource| names.contains(&resource.container_name))
}

fn native_vm_owner_state(
    docker_reachable: bool,
    ownership_proven: bool,
    running_containers: &[String],
    resources: &[edge_shared_types::FleetVmContainer],
) -> edge_shared_types::FleetNativeOwnerState {
    use edge_shared_types::FleetNativeOwnerState;
    if !docker_reachable || !ownership_proven || resources.is_empty() {
        FleetNativeOwnerState::Unproven
    } else if owned_application_container_running(running_containers, resources) {
        FleetNativeOwnerState::Running
    } else {
        FleetNativeOwnerState::Stopped
    }
}

/// One local source of native VM readback, shared with authenticated execution.
async fn capture_local_host_observation(
    stack_dir: &Path,
) -> Result<edge_shared_types::FleetNativeObservation, String> {
    use edge_shared_types::host_lifecycle::build_native_observation;
    use edge_shared_types::{FleetHostKind, FleetNativeOwnerState, FleetNativeReleaseProof};
    let state = inspect_runtime(stack_dir, AgentMode::Runtime).await;
    let release_path = stack_dir.join(APPLICATION_RELEASE_MARKER);
    let mut digest = None;
    match fs::File::open(&release_path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| "VM_HOST_RELEASE_UNREADABLE".to_owned())?;
            if bytes.is_empty() || bytes.len() > 4096 {
                return Err("VM_HOST_RELEASE_INVALID_SIZE".to_owned());
            }
            let release = ApplicationBundleRelease::decode(bytes.as_slice())
                .map_err(|_| "VM_HOST_RELEASE_PROTO_INVALID".to_owned())?;
            if release.encode_to_vec() != bytes || release.schema_version != 1 {
                return Err("VM_HOST_RELEASE_NONCANONICAL".to_owned());
            }
            digest = Some(release.bundle_digest);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("VM_HOST_RELEASE_UNREADABLE".to_owned()),
    }
    // Docker names are untrusted without project/service/ID readback.
    // A running container is also NOT evidence of public TLS/auth/egress.
    let resources = host_native::registered_vm_containers().ok();
    let ownership_proven = state.docker_reachable
        && match resources.as_deref() {
            Some(scope) => docker_observation::verify_owned_application_containers(scope)
                .await
                .is_ok(),
            None => false,
        };
    let owner_state = native_vm_owner_state(
        state.docker_reachable,
        ownership_proven,
        &state.running_containers,
        resources.as_deref().unwrap_or(&[]),
    );
    // Absence must be observed independently: Docker was inspected and no
    // owned application containers or release marker exist. A running
    // container with no marker is an UNKNOWN state, not a fresh installation.
    let proof = if digest.is_some() {
        FleetNativeReleaseProof::ApplicationBundle
    } else if owner_state == FleetNativeOwnerState::Stopped
        && !state.compose_file_present
        && state.missing_containers.is_empty()
        && state.containers.is_empty()
    {
        FleetNativeReleaseProof::VerifiedAbsent
    } else {
        FleetNativeReleaseProof::Unproven
    };
    let mut reasons = Vec::new();
    if digest.is_none() && proof != FleetNativeReleaseProof::VerifiedAbsent {
        reasons.push("VM_BUNDLE_NOT_OBSERVED");
    }
    if !state.docker_reachable {
        reasons.push("VM_DOCKER_UNAVAILABLE");
    } else if !ownership_proven {
        reasons.push("VM_APPLICATION_OWNER_UNPROVEN");
    }
    // Preserve the root-observed *reason*, not only runtime_ready=false.
    // Reason codes are already part of signed FleetNativeObservation/v1;
    // never export raw Docker, WARP or credential errors.
    let reasons = native_runtime_reason_codes(&state, reasons);
    // Runtime readiness is already explicitly encoded as
    // runtime_ready_proven / runtime_ready. Stopped VM resources are not
    // a broken observation; do not flag them as an evidence error merely
    // because the application is intentionally stopped.
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_CLOCK_UNAVAILABLE".to_owned())?
        .as_secs();
    let observed = build_native_observation(
        FleetHostKind::Vm,
        owner_state,
        proof,
        digest.as_deref(),
        ownership_proven.then_some(state.ready),
        observed_at,
        &reasons,
    )
    .map_err(str::to_owned)?;
    Ok(observed)
}

/// Lightweight read-only VM observation. It deliberately does not claim
/// container health, egress success, credential equality or pair completion.
fn run_local_fast(stack_dir: &Path) -> Result<(), String> {
    let started = Instant::now();
    let path = stack_dir.join(APPLICATION_RELEASE_MARKER);
    let mut bytes = Vec::new();
    match std::fs::File::open(&path) {
        Ok(file) => {
            file.take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| "FLEET_FAST_RELEASE_UNREADABLE".to_owned())?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("FLEET_FAST_RELEASE_UNREADABLE".to_owned()),
    }
    if bytes.len() > 4096 {
        return Err("FLEET_FAST_RELEASE_TOO_LARGE".to_owned());
    }
    let digest = if bytes.is_empty() {
        "UNPROVEN".to_owned()
    } else {
        let release = ApplicationBundleRelease::decode(bytes.as_slice())
            .map_err(|_| "FLEET_FAST_RELEASE_INVALID".to_owned())?;
        if release.encode_to_vec() != bytes
            || release.schema_version != 1
            || release.bundle_id.trim().is_empty()
            || validate_lower_hex("bundle_digest", &release.bundle_digest, 64).is_err()
        {
            return Err("FLEET_FAST_RELEASE_INVALID".to_owned());
        }
        release.bundle_digest
    };
    let observed_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "FAST_CLOCK_UNAVAILABLE".to_owned())?
        .as_secs();
    println!("fast_schema=sing-box.fleet-fast/v1");
    println!("fast_observed_unix_seconds={observed_unix_seconds}");
    println!("fast_host_kind=VM");
    println!(
        "fast_native_host_trust={}",
        host_native::local_trust_preflight()
    );
    println!("fast_bundle_digest={digest}");
    println!("fast_runtime=UNPROVEN");
    println!("fast_reason=CONTAINERS_AND_ENDPOINTS_NOT_PROBED");
    println!("fast_next_action=RUN_DEEP_DIAGNOSE");
    println!("fast_credential_pair_terminal=UNPROVEN");
    println!("fast_credential_replay_authorized=false");
    println!("fast_mutations=0");
    println!("fast_elapsed_ms={}", started.elapsed().as_millis());
    Ok(())
}

/// Operator-visible diagnostics are closed and non-secret: never print
/// arbitrary Docker, network or credential error strings into GH logs.
fn native_runtime_reason_code(reason: &str) -> &'static str {
    if reason == "direct egress datapath probe failed" {
        "DIRECT_EGRESS_FAILED"
    } else if reason == "WARP egress datapath probe failed" {
        "WARP_EGRESS_FAILED"
    } else if reason.starts_with("expected containers are not running: ") {
        "CONTAINER_NOT_RUNNING"
    } else if reason.starts_with("expected TCP ports are not listening: ") {
        "TCP_PORTS_MISSING"
    } else if reason.starts_with("expected UDP ports are not listening: ") {
        "UDP_PORTS_MISSING"
    } else if reason.starts_with("container ")
        && reason.contains("does not match exact accepted runtime")
    {
        "EXACT_IMAGE_OR_CONTAINER_UNREADY"
    } else if reason.contains("bundle artifact") {
        "BUNDLE_ARTIFACT_UNREADY"
    } else if reason.starts_with("compose file is not readable") {
        "COMPOSE_UNREADABLE"
    } else if reason.starts_with("compose file is not valid YAML") {
        "COMPOSE_INVALID"
    } else if reason.starts_with("exact ReleaseSet image authority is unavailable") {
        "EXACT_IMAGE_AUTHORITY_UNPROVEN"
    } else if reason.starts_with("no exact ReleaseSet image mapping exists") {
        "EXACT_IMAGE_MAPPING_MISSING"
    } else if reason.starts_with("typed Docker inspection failed") {
        "DOCKER_CONTAINER_INSPECTION_UNPROVEN"
    } else if reason.to_ascii_lowercase().contains("mesh") {
        "MESH_RUNTIME_UNREADY"
    } else if reason.contains("docker runtime") {
        "DOCKER_UNAVAILABLE"
    } else {
        "OTHER_UNPROVEN"
    }
}

/// Reuse the same closed readiness evidence for unsigned local diagnosis and
/// the existing root-signed FleetNativeObservation. No new wire contract, no
/// raw command errors, and no mutation: absence of a proven cause stays UNPROVEN.
fn native_runtime_reason_codes(
    state: &AgentState,
    mut codes: Vec<&'static str>,
) -> Vec<&'static str> {
    for reason in &state.degraded_reasons {
        let code = native_runtime_reason_code(reason);
        if !codes.contains(&code) && codes.len() < 12 {
            codes.push(code);
        }
    }
    if !state.ready && codes.is_empty() {
        codes.push("VM_RUNTIME_NOT_READY_UNPROVEN");
    }
    codes
}

fn print_agent_state_evidence(operation: &str, state: &AgentState) {
    println!("operation={operation}");
    println!("healthy={}", state.healthy);
    println!("ready={}", state.ready);
    println!("docker_reachable={}", state.docker_reachable);
    println!("compose_file_present={}", state.compose_file_present);
    println!("running_container_count={}", state.running_containers.len());
    println!("missing_container_count={}", state.missing_containers.len());
    println!("degraded_reason_count={}", state.degraded_reasons.len());
    // Distinguish unknown from an independently probed false result, without
    // publishing raw curl/warp-cli/network output or a second telemetry store.
    for (name, result) in [
        ("direct_egress", state.direct_egress_ready),
        ("warp_egress", state.warp_egress_ready),
        ("mesh_runtime", state.mesh_runtime_ready),
    ] {
        println!("{name}_proven={}", result.is_some());
        println!("{name}_ready={}", result.unwrap_or(false));
    }
    for (index, reason) in state.degraded_reasons.iter().take(12).enumerate() {
        println!(
            "degraded_reason_{index}_code={}",
            native_runtime_reason_code(reason)
        );
    }
    println!("tcp_listener_count={}", state.listening_tcp_ports.len());
    println!("udp_listener_count={}", state.listening_udp_ports.len());
    for (index, container) in state.containers.iter().enumerate() {
        println!("container_{index}_name={}", container.name);
        println!("container_{index}_present={}", container.present);
        println!("container_{index}_running={}", container.running);
        println!(
            "container_{index}_exact_image_ready={}",
            container.exact_image_ready
        );
        println!(
            "container_{index}_restart_count={}",
            container.restart_count.unwrap_or_default()
        );
        println!(
            "container_{index}_oom_killed={}",
            container.oom_killed.unwrap_or(false)
        );
    }
}

fn print_mesh_state_evidence(state: &MeshRuntimeState) {
    println!("mesh_token_store_present={}", state.token_store_present);
    println!("mesh_container_running={}", state.container_running);
    println!("mesh_exact_image_ready={}", state.exact_image_ready);
    println!("mesh_runtime_ready={}", state.runtime_ready);
    println!("mesh_warning_count={}", state.warnings.len());
    if let Some(registration_id) = state.registration_id.as_deref() {
        println!("mesh_registration_id={registration_id}");
    }
}

fn print_credential_state_evidence(state: Option<&LocalCredentialState>) {
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

fn verify_initial_agent_binary(expected_sha256: &str) -> Result<(), String> {
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "VM first-use proof requires an exact SHA-256 from immutable ReleaseSet".to_owned(),
        );
    }
    // Hash the kernel's live executable handle, not its resolved pathname:
    // the path can be replaced while an old process is still running.
    let observed = edge_shared_types::file_sha256_lower_hex(Path::new("/proc/self/exe"))?;
    if observed != expected_sha256 {
        return Err("VM first-use attestation refuses non-ReleaseSet agent bytes".to_owned());
    }
    Ok(())
}

async fn attest_initial_vm_host(
    stack_dir: &Path,
    generation: u64,
    slot: CredentialDeliverySlot,
    provider_intent_sha256: &str,
    release_set_sha256: &str,
    expected_agent_sha256: &str,
    run_id: u64,
) -> Result<(String, InitialDummySlotProof), String> {
    // The same native owner checks exact binary and selected Worker slot.
    // Unknown contents of the OTHER slot never become overwrite authority.
    verify_initial_agent_binary(expected_agent_sha256)?;
    let proof = verify_initial_vm_selected_dummy_probe(stack_dir, slot).await?;
    let machine = fs::read_to_string("/etc/machine-id")
        .map_err(|err| format!("VM machine identity unreadable: {err}"))?;
    let digest = edge_shared_types::first_use_host_attestation_sha256(
        CredentialProjectionKind::Vm,
        generation,
        slot,
        provider_intent_sha256,
        release_set_sha256,
        &machine,
        run_id,
    )?;
    Ok((digest, proof))
}

fn validate_initial_vm_runtime_request(
    request: &InitialVmCredentialRuntimeRequest,
) -> Result<(), String> {
    if request.generation == 0
        || request.generation == edge_shared_types::CREDENTIAL_DUMMY_PROBE_GENERATION_A
        || request.generation == edge_shared_types::CREDENTIAL_DUMMY_PROBE_GENERATION_B
    {
        return Err("first-use VM runtime refuses zero or dummy generation".to_owned());
    }
    validate_lower_hex("ReleaseSet", &request.release_set_sha256, 64)?;
    verify_initial_agent_binary(&request.expected_agent_sha256)
}

fn initial_vm_runtime_response(
    generation: u64,
    materialized: bool,
    endpoints: Vec<line2_quality::EndpointProof>,
) -> InitialVmCredentialRuntimeResponse {
    InitialVmCredentialRuntimeResponse {
        projection: CredentialProjectionKind::Vm as i32,
        generation,
        candidate_unpromoted: true,
        candidate_materialized: materialized,
        vm_local_line2: endpoints
            .into_iter()
            .map(|p| InitialVmLine2EndpointResult {
                endpoint: p.name.to_owned(),
                protocol: p.protocol.to_owned(),
                port: u32::from(p.port),
                successful_samples: p.successes,
                failed_samples: p.failures,
                negative_auth_rejected: p.negative_auth_rejected,
            })
            .collect(),
        external_line1_proven: false,
        external_line2_proven: false,
        direct_warp_egress_distinct_proven: false,
    }
}

fn parse_first_use_slot(value: &str) -> Result<edge_shared_types::CredentialDeliverySlot, String> {
    match value {
        "a" => Ok(edge_shared_types::CredentialDeliverySlot::A),
        "b" => Ok(edge_shared_types::CredentialDeliverySlot::B),
        _ => Err("first-use attestation requires slot a or b".to_owned()),
    }
}

async fn verify_initial_vm_selected_dummy_probe(
    stack_dir: &Path,
    slot: CredentialDeliverySlot,
) -> Result<InitialDummySlotProof, String> {
    require_empty_vm_initial_credential_host(stack_dir)?;
    let docker = observe_docker().await?;
    require_no_vm_application_containers(&docker)?;
    verify_initial_selected_dummy_slot(
        CredentialProjectionKind::Vm,
        slot,
        &vm_credential_access_identity_path(stack_dir)?,
    )
    .await
}

async fn verify_initial_vm_dummy_probe(stack_dir: &Path) -> Result<(), String> {
    require_empty_vm_initial_credential_host(stack_dir)?;
    let docker = observe_docker().await?;
    require_no_vm_application_containers(&docker)?;
    verify_canonical_dummy_ab_slots(
        CredentialProjectionKind::Vm,
        &vm_credential_access_identity_path(stack_dir)?,
    )
    .await
}

#[derive(Clone, Copy)]
enum AgentMode {
    Health,
    Readiness,
    Runtime,
}

async fn inspect_runtime(stack_dir: &Path, mode: AgentMode) -> AgentState {
    let mut state = AgentState {
        healthy: true,
        ready: false,
        topology_version: "vultr-edge".to_owned(),
        active_bundle_id: stack_dir
            .file_name()
            .map(|name| name.to_string_lossy().to_string()),
        degraded_reasons: Vec::new(),
        docker_reachable: false,
        compose_file_present: false,
        observed_stack_path: Some(stack_dir.display().to_string()),
        running_containers: Vec::new(),
        missing_containers: Vec::new(),
        listening_tcp_ports: Vec::new(),
        listening_udp_ports: Vec::new(),
        direct_egress_ready: None,
        warp_egress_ready: None,
        mesh_runtime_ready: None,
        containers: Vec::new(),
    };

    inspect_bundle_artifacts(stack_dir, &mut state);

    // The host engine is an independent substrate observation. Do not return
    // a false "Docker unavailable" just because the application Compose file
    // has not been installed yet. This is essential on first-use VM hosts.
    let docker = observe_docker()
        .await
        .unwrap_or_else(|_| DockerObservation::unreachable());
    state.docker_reachable = docker.reachable;
    state.running_containers = docker.running_containers.clone();
    state.listening_tcp_ports = docker.listening_tcp_ports.clone();
    state.listening_udp_ports = docker.listening_udp_ports.clone();
    if !docker.reachable {
        state
            .degraded_reasons
            .push("docker runtime is not reachable from edge-agent".to_owned());
    }

    let compose_path = stack_dir.join("docker-compose.yml");
    let enabled_profiles = enabled_application_profiles(stack_dir);
    let line2_enabled = line2_runtime_enabled(stack_dir);
    let Some(compose) =
        inspect_compose(&compose_path, &mut state, &enabled_profiles, line2_enabled)
    else {
        state.healthy = false;
        return state;
    };

    state.missing_containers = compose
        .expected_containers
        .iter()
        .filter(|name| {
            !docker
                .running_containers
                .iter()
                .any(|running| running == *name)
        })
        .cloned()
        .collect();

    if !state.missing_containers.is_empty() {
        state.degraded_reasons.push(format!(
            "expected containers are not running: {}",
            state.missing_containers.join(", ")
        ));
    }

    if docker.reachable {
        collect_exact_container_evidence(stack_dir, &compose.expected_containers, &mut state).await;
    }

    let expected_tcp = compose.expected_tcp_ports;
    let expected_udp = compose.expected_udp_ports;
    let missing_tcp = expected_tcp
        .iter()
        .filter(|port| !state.listening_tcp_ports.iter().any(|value| value == *port))
        .copied()
        .collect::<Vec<_>>();
    let missing_udp = expected_udp
        .iter()
        .filter(|port| !state.listening_udp_ports.iter().any(|value| value == *port))
        .copied()
        .collect::<Vec<_>>();

    if !missing_tcp.is_empty() {
        state.degraded_reasons.push(format!(
            "expected TCP ports are not listening: {}",
            join_ports(&missing_tcp)
        ));
    }
    if !missing_udp.is_empty() {
        state.degraded_reasons.push(format!(
            "expected UDP ports are not listening: {}",
            join_ports(&missing_udp)
        ));
    }

    let datapaths_ready = if matches!(mode, AgentMode::Health) {
        true
    } else {
        inspect_datapath_readiness(&mut state, &docker).await
    };

    state.ready = state.compose_file_present
        && !state
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("bundle artifact"))
        && state.docker_reachable
        && state.missing_containers.is_empty()
        && state
            .containers
            .iter()
            .all(|container| container.exact_image_ready)
        && missing_tcp.is_empty()
        && missing_udp.is_empty()
        && datapaths_ready;

    if matches!(mode, AgentMode::Health) {
        state.ready = false;
    }
    if matches!(mode, AgentMode::Readiness) {
        state.healthy = state.compose_file_present && state.docker_reachable;
    }

    state
}

async fn collect_exact_container_evidence(
    stack_dir: &Path,
    expected_containers: &[String],
    state: &mut AgentState,
) {
    let images = match read_exact_image_environment(stack_dir) {
        Ok(images) => images,
        Err(err) => {
            state.degraded_reasons.push(format!(
                "exact ReleaseSet image authority is unavailable: {err}"
            ));
            return;
        }
    };

    for name in expected_containers {
        let expected_image = match name.as_str() {
            WARP_CONTAINER => images.get(EDGE_WARP_EGRESS_IMAGE_KEY).cloned(),
            LINE1_CONTAINER | LINE2_CONTAINER => images.get(EDGE_GATEWAY_IMAGE_KEY).cloned(),
            MESH_CONTAINER => images.get(EDGE_MESH_IMAGE_KEY).cloned(),
            _ => None,
        };
        let Some(expected_image) = expected_image else {
            state.degraded_reasons.push(format!(
                "no exact ReleaseSet image mapping exists for expected container {name}"
            ));
            continue;
        };

        match observe_container_runtime(name).await {
            Ok(evidence) => {
                let health_ready = !matches!(
                    evidence.health.as_deref(),
                    Some("UNHEALTHY") | Some("STARTING")
                );
                let exact_image_ready = evidence.present
                    && evidence.running
                    && evidence.image.as_deref() == Some(expected_image.as_str())
                    && evidence.oom_killed != Some(true)
                    && health_ready;

                if !exact_image_ready {
                    state.degraded_reasons.push(format!(
                        "container {name} does not match exact accepted runtime: {}",
                        evidence.summary()
                    ));
                }

                state.containers.push(ContainerRuntimeObservation {
                    name: evidence.name,
                    present: evidence.present,
                    running: evidence.running,
                    expected_image: Some(expected_image),
                    observed_image: evidence.image,
                    exact_image_ready,
                    health: evidence.health,
                    exit_code: evidence.exit_code,
                    restart_count: evidence.restart_count,
                    oom_killed: evidence.oom_killed,
                    networks: evidence.networks,
                    published_ports: evidence.published_ports,
                    mounts: evidence.mounts,
                    runtime_error_present: evidence.runtime_error.is_some(),
                    recent_events: evidence.log_tail,
                });
            }
            Err(err) => {
                state.degraded_reasons.push(format!(
                    "typed Docker inspection failed for expected container {name}: {err}"
                ));
                state.containers.push(ContainerRuntimeObservation {
                    name: name.clone(),
                    present: false,
                    running: false,
                    expected_image: Some(expected_image),
                    observed_image: None,
                    exact_image_ready: false,
                    health: None,
                    exit_code: None,
                    restart_count: None,
                    oom_killed: None,
                    networks: Vec::new(),
                    published_ports: Vec::new(),
                    mounts: Vec::new(),
                    runtime_error_present: true,
                    recent_events: Vec::new(),
                });
            }
        }
    }
    state
        .containers
        .sort_by(|left, right| left.name.cmp(&right.name));
}

fn apply_bundle(
    stack_dir: &Path,
    request: ApplyBundleRequest,
) -> Result<ApplyBundleResponse, String> {
    // Historical bundle payload validation remains an offline data guard; there is no VM RPC ingress.
    // In particular a missing digest must NEVER fall back to writing host
    // paths, certificate files or the agent's execution environment.
    validate_digest_bound_bundle_request(&request)?;
    apply_digest_bound_bundle(stack_dir, request, false)
}

fn validate_digest_bound_bundle_request(
    request: &ApplyBundleRequest,
) -> Result<(String, String), String> {
    if !request.prune_existing {
        return Err("digest-bound application bundles require prune_existing=true".to_owned());
    }
    if !request.host_files.is_empty()
        || request.deployment_summary.is_some()
        || request.agent_env_file.is_some()
    {
        return Err(
            "digest-bound application bundles may contain only stack_files; host mutation remains a separate typed operation"
                .to_owned(),
        );
    }

    let bundle_id = request
        .bundle_id
        .clone()
        .ok_or_else(|| "bundle_id is required".to_owned())?;
    let expected_digest = request
        .bundle_digest
        .clone()
        .ok_or_else(|| "bundle_digest is required".to_owned())?;
    validate_lower_hex("bundle_digest", &expected_digest, 64)?;
    let computed_digest = canonical_apply_bundle_digest(request)?;
    if computed_digest != expected_digest {
        return Err(format!(
            "bundle digest mismatch: expected {expected_digest}, computed {computed_digest}"
        ));
    }
    Ok((bundle_id, expected_digest))
}

fn apply_digest_bound_bundle(
    stack_dir: &Path,
    request: ApplyBundleRequest,
    initial_policy_only: bool,
) -> Result<ApplyBundleResponse, String> {
    let (bundle_id, expected_digest) = validate_digest_bound_bundle_request(&request)?;
    if initial_policy_only {
        validate_initial_policy_bundle_request(&request)?;
        require_empty_vm_initial_credential_host(stack_dir)?;
        require_empty_vm_initial_bundle_host(stack_dir)?;
    }

    if let Some(current) = read_application_release(stack_dir)
        && current.bundle_id == bundle_id
        && current.bundle_digest == expected_digest
    {
        let previous = read_application_release(&previous_stack_dir(stack_dir));
        return Ok(bundle_apply_response(
            stack_dir,
            Vec::new(),
            Vec::new(),
            &current,
            previous.as_ref(),
        ));
    }

    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no parent".to_owned())?;
    let staging = parent.join(STAGING_STACK_DIR);
    let previous = parent.join(PREVIOUS_STACK_DIR);
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|err| {
            format!(
                "failed to clear stale staging stack {}: {err}",
                staging.display()
            )
        })?;
    }
    fs::create_dir_all(&staging).map_err(|err| {
        format!(
            "failed to create staging stack {}: {err}",
            staging.display()
        )
    })?;

    let mut written_paths = Vec::new();
    for file in &request.stack_files {
        write_bundle_file(&staging, file, &mut written_paths)?;
    }
    if initial_policy_only {
        // Validate exact images before activating the policy-only stack.
        read_exact_image_environment(&staging)?;
        // Fresh stage contains repository policy and pinned images, never an
        // active credential or generated runtime. Only initial-apply may start.
        if staging.join(RUNTIME_ENV_FILE).exists() {
            return Err("initial bundle must not materialize runtime credentials".to_owned());
        }
    } else {
        materialize_vm_owned_runtime_environment(&staging)?;
    }

    let release = ApplicationBundleRelease {
        schema_version: 1,
        bundle_id,
        bundle_digest: expected_digest,
    };
    write_application_release(&staging, &release)?;

    let old_release = read_application_release(stack_dir);
    if stack_dir.exists() && initial_policy_only {
        // A precreated empty directory is not a previous application release.
        fs::remove_dir(stack_dir)
            .map_err(|err| format!("initial bundle target directory is no longer empty: {err}"))?;
    } else if stack_dir.exists() {
        if previous.exists() {
            fs::remove_dir_all(&previous).map_err(|err| {
                format!(
                    "failed to remove previous application stack {}: {err}",
                    previous.display()
                )
            })?;
        }
        fs::rename(stack_dir, &previous).map_err(|err| {
            format!(
                "failed to rotate active stack {} to {}: {err}",
                stack_dir.display(),
                previous.display()
            )
        })?;
    }

    if let Err(err) = fs::rename(&staging, stack_dir) {
        if previous.exists() && !stack_dir.exists() {
            let _ = fs::rename(&previous, stack_dir);
        }
        return Err(format!(
            "failed to atomically activate staged stack {}: {err}",
            staging.display()
        ));
    }

    Ok(bundle_apply_response(
        stack_dir,
        written_paths,
        Vec::new(),
        &release,
        old_release.as_ref(),
    ))
}

fn rollback_bundle(
    stack_dir: &Path,
    request: RollbackBundleRequest,
) -> Result<RollbackBundleResponse, String> {
    validate_lower_hex(
        "expected_current_bundle_digest",
        &request.expected_current_bundle_digest,
        64,
    )?;
    let current = read_application_release(stack_dir)
        .ok_or_else(|| "active application release marker is missing".to_owned())?;
    if current.bundle_digest != request.expected_current_bundle_digest {
        return Err(
            "current bundle digest changed since rollback authorization; refusing stale rollback"
                .to_owned(),
        );
    }

    let previous = previous_stack_dir(stack_dir);
    let previous_release = read_application_release(&previous)
        .ok_or_else(|| "previous application release is unavailable".to_owned())?;
    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no parent".to_owned())?;
    let rollback = parent.join(ROLLBACK_STACK_DIR);
    if rollback.exists() {
        return Err(format!(
            "rollback scratch path already exists: {}; refusing to guess recovery state",
            rollback.display()
        ));
    }

    fs::rename(stack_dir, &rollback).map_err(|err| {
        format!(
            "failed to stage current stack for rollback {}: {err}",
            stack_dir.display()
        )
    })?;
    if let Err(err) = fs::rename(&previous, stack_dir) {
        let _ = fs::rename(&rollback, stack_dir);
        return Err(format!(
            "failed to activate previous stack {}: {err}",
            previous.display()
        ));
    }
    if let Err(err) = fs::rename(&rollback, &previous) {
        let _ = fs::rename(stack_dir, &previous);
        let _ = fs::rename(&rollback, stack_dir);
        return Err(format!(
            "failed to complete rollback stack swap; attempted restoration: {err}"
        ));
    }

    Ok(RollbackBundleResponse {
        success: true,
        active_bundle_id: Some(previous_release.bundle_id.clone()),
        active_bundle_digest: Some(previous_release.bundle_digest.clone()),
        previous_bundle_id: Some(current.bundle_id),
        previous_bundle_digest: Some(current.bundle_digest),
        warnings: Vec::new(),
    })
}

fn bundle_apply_response(
    stack_dir: &Path,
    written_paths: Vec<String>,
    warnings: Vec<String>,
    active: &ApplicationBundleRelease,
    previous: Option<&ApplicationBundleRelease>,
) -> ApplyBundleResponse {
    ApplyBundleResponse {
        success: true,
        written_paths,
        stack_dir: Some(stack_dir.display().to_string()),
        warnings,
        active_bundle_id: Some(active.bundle_id.clone()),
        active_bundle_digest: Some(active.bundle_digest.clone()),
        previous_bundle_id: previous.map(|release| release.bundle_id.clone()),
        previous_bundle_digest: previous.map(|release| release.bundle_digest.clone()),
    }
}

fn previous_stack_dir(stack_dir: &Path) -> PathBuf {
    stack_dir
        .parent()
        .map(|parent| parent.join(PREVIOUS_STACK_DIR))
        .unwrap_or_else(|| PathBuf::from(PREVIOUS_STACK_DIR))
}

fn read_application_release(stack_dir: &Path) -> Option<ApplicationBundleRelease> {
    let bytes = fs::read(stack_dir.join(APPLICATION_RELEASE_MARKER)).ok()?;
    let release = ApplicationBundleRelease::decode(bytes.as_slice()).ok()?;
    if release.encode_to_vec() != bytes
        || release.schema_version != 1
        || release.bundle_id.trim().is_empty()
        || validate_lower_hex("bundle_digest", &release.bundle_digest, 64).is_err()
    {
        return None;
    }
    Some(release)
}

fn write_application_release(
    stack_dir: &Path,
    release: &ApplicationBundleRelease,
) -> Result<(), String> {
    if release.schema_version != 1
        || release.bundle_id.trim().is_empty()
        || validate_lower_hex("bundle_digest", &release.bundle_digest, 64).is_err()
    {
        return Err("application release marker is invalid".to_owned());
    }
    fs::write(
        stack_dir.join(APPLICATION_RELEASE_MARKER),
        release.encode_to_vec(),
    )
    .map_err(|err| format!("failed to write application release marker: {err}"))
}

fn validate_initial_policy_bundle_request(request: &ApplyBundleRequest) -> Result<(), String> {
    let mut required = BTreeSet::from(["docker-compose.yml", RUNTIME_POLICY_FILE, IMAGE_ENV_FILE]);
    let mut seen = BTreeSet::new();
    for file in &request.stack_files {
        validate_bundle_relative_path(&file.relative_path)?;
        if !seen.insert(file.relative_path.as_str()) {
            return Err("initial bundle contains duplicate file paths".to_owned());
        }
        if file.relative_path == RUNTIME_ENV_FILE
            || file.relative_path.contains("runtime-secrets")
            || file.relative_path.contains(".env.runtime.new")
            || file.sensitive
        {
            return Err("initial policy bundle must not contain credentials".to_owned());
        }
        if file.relative_path == RUNTIME_POLICY_FILE {
            let policy = std::str::from_utf8(&file.content)
                .map_err(|_| "initial runtime policy must be UTF-8".to_owned())?;
            validate_runtime_policy_env(policy)?;
        }
        required.remove(file.relative_path.as_str());
    }
    if !required.is_empty() {
        return Err(
            "initial policy bundle requires exact Compose, image and runtime policy inputs"
                .to_owned(),
        );
    }
    Ok(())
}

fn require_empty_vm_initial_bundle_host(stack_dir: &Path) -> Result<(), String> {
    let parent = stack_dir
        .parent()
        .ok_or_else(|| "initial bundle requires a host-state parent".to_owned())?;
    for name in [STAGING_STACK_DIR, PREVIOUS_STACK_DIR, ROLLBACK_STACK_DIR] {
        if parent.join(name).exists() {
            return Err(format!(
                "initial bundle refuses ambiguous existing stack state {name}"
            ));
        }
    }
    if stack_dir.exists() {
        let mut entries = fs::read_dir(stack_dir)
            .map_err(|err| format!("initial bundle cannot inspect target stack: {err}"))?;
        if entries.next().is_some() {
            return Err("initial bundle refuses existing application stack content".to_owned());
        }
    }
    Ok(())
}

fn materialize_vm_owned_runtime_environment(stack_dir: &Path) -> Result<(), String> {
    if !stack_dir.join(RUNTIME_POLICY_FILE).is_file() {
        return Ok(());
    }
    let bundle = active_vm_credential_bundle(stack_dir)?.ok_or_else(|| {
        "VM runtime activation requires an active Cloudflare Worker v2 credential; independent local credential generation is forbidden".to_owned()
    })?;
    let secrets = ApplicationRuntimeSecrets::from_vm_bundle(&bundle)?;
    write_vm_runtime_environment(stack_dir, &secrets)
}

fn validate_runtime_policy_env(raw: &str) -> Result<(), String> {
    let line2 = ["PROXY_USERNAME", "PROXY_CERT_CN"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let line1 = [
        "REALITY_SERVER_NAME",
        "TUNNEL_DOMAIN",
        "ACME_EMAIL",
        "ACME_PROVIDER",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let full = line1.union(&line2).copied().collect::<BTreeSet<_>>();
    let allowed = full.clone();
    let mut observed = BTreeSet::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "runtime policy line {} must use KEY=VALUE syntax",
                index + 1
            )
        })?;
        if !allowed.contains(key) {
            return Err(format!("unsupported runtime policy key: {key}"));
        }
        if value.is_empty()
            || value.len() > 253
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b':' | b'@' | b'%' | b'+' | b'/' | b'-')
            })
        {
            return Err(format!(
                "runtime policy {key} must be a non-empty shell-safe policy value"
            ));
        }
        if !observed.insert(key) {
            return Err(format!("runtime policy key is duplicated: {key}"));
        }
    }
    if observed != line2 && observed != line1 && observed != full {
        return Err(
            "runtime policy key set must exactly match base, tunnel, or full application policy"
                .to_owned(),
        );
    }
    Ok(())
}

fn vm_credential_store_root(stack_dir: &Path) -> Result<PathBuf, String> {
    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no parent".to_owned())?;
    Ok(parent.join(RUNTIME_SECRET_DIR).join("application-v2"))
}

fn validate_existing_vm_credential_store(stack_dir: &Path) -> Result<(), String> {
    CredentialStore::open_existing(
        vm_credential_store_root(stack_dir)?,
        CredentialProjectionKind::Vm,
    )?;
    Ok(())
}

fn vm_credential_access_identity_path(stack_dir: &Path) -> Result<PathBuf, String> {
    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no parent".to_owned())?;
    Ok(parent
        .join(RUNTIME_SECRET_DIR)
        .join(ACCESS_IDENTITY_FILE_NAME))
}

// Initial enrollment deliberately does not reuse ApplyCandidate/Promote. It may
// start only on an empty, isolated VM. Any interrupted attempt leaves evidence
// behind and refuses a replay rather than generating or applying replacements.
fn require_empty_vm_initial_credential_host(stack_dir: &Path) -> Result<(), String> {
    if observe_vm_credential_state(stack_dir)?.is_some()
        || vm_credential_store_root(stack_dir)?.exists()
    {
        return Err("initial VM enrollment requires absent v2 store and cursor; refusing uncertain or repeated enrollment".to_owned());
    }
    if legacy_vm_runtime_secret_path(stack_dir)?.exists() {
        return Err("initial VM enrollment refuses a legacy runtime credential file".to_owned());
    }
    for relative in [
        RUNTIME_ENV_FILE,
        "rendered/line1-gateway.json",
        "rendered/line2-proxy.json",
    ] {
        if stack_dir.join(relative).exists() {
            return Err(format!(
                "initial VM enrollment refuses existing runtime artifact {relative}"
            ));
        }
    }
    Ok(())
}

fn require_initial_vm_policy_bundle_ready(stack_dir: &Path) -> Result<(), String> {
    if read_application_release(stack_dir).is_none() {
        return Err(
            "initial VM credential apply requires an exact staged application bundle".to_owned(),
        );
    }
    if !stack_dir.join("docker-compose.yml").is_file() {
        return Err("initial VM credential apply requires staged Compose".to_owned());
    }
    let policy = fs::read_to_string(stack_dir.join(RUNTIME_POLICY_FILE))
        .map_err(|_| "initial VM credential apply requires staged policy".to_owned())?;
    validate_runtime_policy_env(&policy)?;
    read_exact_image_environment(stack_dir)?;
    Ok(())
}

fn require_no_vm_application_containers(observation: &DockerObservation) -> Result<(), String> {
    if !observation.reachable {
        return Err("initial VM enrollment refuses unknown Docker daemon state".to_owned());
    }
    for container in [
        "vultr-warp-egress",
        "vultr-line1-gateway",
        "vultr-line2-proxy",
    ] {
        if observation.container_present(container) {
            return Err(format!(
                "initial VM enrollment refuses an existing application container: {container}"
            ));
        }
    }
    Ok(())
}

fn validate_unpromoted_vm_initial_state(
    state: &LocalCredentialState,
    generation: u64,
) -> Result<(), String> {
    if generation == 0 || state.active.is_some() || state.previous.is_some() {
        return Err(
            "initial VM functional proof refuses active/previous or zero generation".to_owned(),
        );
    }
    let candidate = state.candidate.as_ref().ok_or_else(|| {
        "initial VM functional proof requires exactly one staged candidate".to_owned()
    })?;
    if candidate.generation != generation {
        return Err("initial VM functional proof refuses candidate generation mismatch".to_owned());
    }
    Ok(())
}

async fn verify_initial_vm_credential_functional(
    stack_dir: &Path,
    generation: u64,
) -> Result<Vec<line2_quality::EndpointProof>, String> {
    let store = open_vm_credential_store(stack_dir)?;
    let state = store.read_state()?.ok_or_else(|| {
        "initial VM functional proof requires a persisted candidate state".to_owned()
    })?;
    validate_unpromoted_vm_initial_state(&state, generation)?;
    let candidate = state
        .candidate
        .as_ref()
        .ok_or_else(|| "initial VM functional proof candidate disappeared".to_owned())?;
    let bundle = store.read_bundle(candidate)?;
    verify_vm_candidate_runtime_materialized(stack_dir, &bundle)?;
    let docker = observe_docker().await?;
    if !docker.reachable {
        return Err("initial VM functional proof cannot observe Docker".to_owned());
    }
    let images = read_exact_image_environment(stack_dir)?;
    let gateway_image = images
        .get(EDGE_GATEWAY_IMAGE_KEY)
        .ok_or_else(|| "initial VM functional proof requires pinned gateway image".to_owned())?;
    let warp_image = images
        .get(EDGE_WARP_EGRESS_IMAGE_KEY)
        .ok_or_else(|| "initial VM functional proof requires pinned WARP image".to_owned())?;
    for (name, expected_image) in [
        ("vultr-warp-egress", warp_image),
        ("vultr-line1-gateway", gateway_image),
        ("vultr-line2-proxy", gateway_image),
    ] {
        if !docker.container_exact_image_ready(name, expected_image) {
            return Err(format!(
                "initial VM functional proof refuses stopped or non-pinned container {name}"
            ));
        }
    }
    // Real authenticated 204 through each of six direct/WARP HTTP,
    // SOCKS5 and HTTPS endpoints. Reuse the existing native quality owner;
    // no configuration change, pointer promotion, or secret export.
    let endpoints = line2_quality::measure(stack_dir, read_typed_runtime_environment)?;
    // A passing network sample is not sufficient if another owner changed the
    // credential cursor or rendered runtime while the test was in progress.
    let after_state = store
        .read_state()?
        .ok_or_else(|| "initial VM functional proof lost its credential cursor".to_owned())?;
    if after_state != state {
        return Err("initial VM functional proof refuses a changed credential cursor".to_owned());
    }
    verify_vm_candidate_runtime_materialized(stack_dir, &bundle)?;
    Ok(endpoints)
}

async fn fetch_and_stage_vm_credential_candidate(
    stack_dir: &Path,
    generation: u64,
) -> Result<LocalCredentialState, String> {
    let bundle = fetch_canonical_credential_bundle(
        CredentialProjectionKind::Vm,
        generation,
        &vm_credential_access_identity_path(stack_dir)?,
    )
    .await?;
    stage_vm_credential_candidate(stack_dir, bundle)
}

fn stage_vm_credential_candidate(
    stack_dir: &Path,
    bundle: edge_shared_types::CredentialDeliveryBundle,
) -> Result<LocalCredentialState, String> {
    if bundle.projection != CredentialProjectionKind::Vm as i32 {
        return Err("VM credential owner rejects non-VM projection".to_owned());
    }
    let store = CredentialStore::new(
        vm_credential_store_root(stack_dir)?,
        CredentialProjectionKind::Vm,
    )?;
    store.stage_delivery_candidate(&bundle)
}

fn observe_vm_credential_state(stack_dir: &Path) -> Result<Option<LocalCredentialState>, String> {
    let Some(store) = CredentialStore::open_existing(
        vm_credential_store_root(stack_dir)?,
        CredentialProjectionKind::Vm,
    )?
    else {
        return Ok(None);
    };
    store.read_state()
}

fn open_vm_credential_store(stack_dir: &Path) -> Result<CredentialStore, String> {
    CredentialStore::open_existing(
        vm_credential_store_root(stack_dir)?,
        CredentialProjectionKind::Vm,
    )?
    .ok_or_else(|| "VM v2 credential store is absent".to_owned())
}

fn active_vm_credential_bundle(
    stack_dir: &Path,
) -> Result<Option<edge_shared_types::CredentialDeliveryBundle>, String> {
    let Some(store) = CredentialStore::open_existing(
        vm_credential_store_root(stack_dir)?,
        CredentialProjectionKind::Vm,
    )?
    else {
        return Ok(None);
    };
    let Some(state) = store.read_state()? else {
        return Ok(None);
    };
    state
        .active
        .as_ref()
        .map(|reference| store.read_bundle(reference))
        .transpose()
}

fn vm_runtime_environment(
    stack_dir: &Path,
    secrets: &ApplicationRuntimeSecrets,
) -> Result<String, String> {
    let policy_path = stack_dir.join(RUNTIME_POLICY_FILE);
    let policy = fs::read_to_string(&policy_path).map_err(|err| {
        format!(
            "failed to read runtime policy {}: {err}",
            policy_path.display()
        )
    })?;
    validate_runtime_policy_env(&policy)?;
    secrets.validate()?;
    let mut runtime = policy;
    if !runtime.ends_with('\n') {
        runtime.push('\n');
    }
    runtime.push_str(&secrets.render_env());
    Ok(runtime)
}

fn write_vm_runtime_environment(
    stack_dir: &Path,
    secrets: &ApplicationRuntimeSecrets,
) -> Result<(), String> {
    let runtime = vm_runtime_environment(stack_dir, secrets)?;
    let path = stack_dir.join(RUNTIME_ENV_FILE);
    let temporary = path.with_extension("runtime.new");
    fs::write(&temporary, runtime.as_bytes()).map_err(|err| {
        format!(
            "failed to stage VM runtime environment {}: {err}",
            temporary.display()
        )
    })?;
    set_bundle_file_permissions(&temporary, false, true)?;
    fs::rename(&temporary, &path).map_err(|err| {
        let _ = fs::remove_file(&temporary);
        format!(
            "failed to atomically publish VM runtime environment {}: {err}",
            path.display()
        )
    })
}

fn legacy_vm_runtime_secret_path(stack_dir: &Path) -> Result<PathBuf, String> {
    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no parent".to_owned())?;
    Ok(parent.join(RUNTIME_SECRET_DIR).join(RUNTIME_SECRET_FILE))
}

// Observe what the on-disk runtime actually contains, not just whether the
// Worker issued a generation. Candidate-only is a legitimate first-use state,
// *not* evidence of an active/local cutover. No credential bytes, hashes,
// rendered env values, or private file paths may appear in stdout.
#[derive(Debug, PartialEq, Eq)]
enum VmRenderedCredentialSource {
    V2Active {
        delivery_generation: u64,
        tunnel_auth_generation: u64,
        reality_generation: u64,
        line2_generation: u64,
    },
    V2Candidate {
        delivery_generation: u64,
        tunnel_auth_generation: u64,
        reality_generation: u64,
        line2_generation: u64,
    },
    LegacyStorePresent,
    Unproven(&'static str),
}

fn observed_vm_credential_generations(
    bundle: &edge_shared_types::CredentialDeliveryBundle,
) -> Option<(u64, u64, u64, u64)> {
    let edge_shared_types::credential_delivery_bundle::Payload::Vm(vm) = bundle.payload.as_ref()?
    else {
        return None;
    };
    Some((
        bundle.generation,
        vm.tunnel_auth.as_ref()?.generation,
        vm.reality_identity.as_ref()?.generation,
        vm.line2_proxy.as_ref()?.generation,
    ))
}

fn observe_vm_rendered_credential_source(stack_dir: &Path) -> VmRenderedCredentialSource {
    let rendered = match fs::read_to_string(stack_dir.join(RUNTIME_ENV_FILE)) {
        Ok(value) => value,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return VmRenderedCredentialSource::Unproven("RUNTIME_ENV_ABSENT");
        }
        Err(_) => return VmRenderedCredentialSource::Unproven("RUNTIME_ENV_UNREADABLE"),
    };
    let store = match CredentialStore::open_existing(
        match vm_credential_store_root(stack_dir) {
            Ok(root) => root,
            Err(_) => return VmRenderedCredentialSource::Unproven("V2_STATE_INVALID"),
        },
        CredentialProjectionKind::Vm,
    ) {
        Ok(Some(store)) => store,
        Ok(None) => {
            return if legacy_vm_runtime_secret_path(stack_dir).is_ok_and(|path| path.is_file()) {
                VmRenderedCredentialSource::LegacyStorePresent
            } else {
                VmRenderedCredentialSource::Unproven("NO_MATCHING_LOCAL_CREDENTIAL_SOURCE")
            };
        }
        Err(_) => return VmRenderedCredentialSource::Unproven("V2_STATE_INVALID"),
    };
    let state = match store.read_state() {
        Ok(Some(state)) => state,
        Ok(None) => return VmRenderedCredentialSource::Unproven("V2_STATE_ABSENT"),
        Err(_) => return VmRenderedCredentialSource::Unproven("V2_STATE_INVALID"),
    };

    // Active always has priority. A different staged candidate must not be
    // adopted as the current source while the previous active pointer exists.
    if let Some(active) = state.active.as_ref() {
        let bundle = match store.read_bundle(active) {
            Ok(bundle) => bundle,
            Err(_) => return VmRenderedCredentialSource::Unproven("V2_ACTIVE_INVALID"),
        };
        let Ok(secrets) = ApplicationRuntimeSecrets::from_vm_bundle(&bundle) else {
            return VmRenderedCredentialSource::Unproven("V2_ACTIVE_INVALID");
        };
        if vm_runtime_environment(stack_dir, &secrets).is_ok_and(|value| value == rendered) {
            if let Some((
                delivery_generation,
                tunnel_auth_generation,
                reality_generation,
                line2_generation,
            )) = observed_vm_credential_generations(&bundle)
            {
                return VmRenderedCredentialSource::V2Active {
                    delivery_generation,
                    tunnel_auth_generation,
                    reality_generation,
                    line2_generation,
                };
            }
            return VmRenderedCredentialSource::Unproven("V2_ACTIVE_INVALID");
        }
        return VmRenderedCredentialSource::Unproven("V2_ACTIVE_RENDER_MISMATCH");
    }

    // The only permitted candidate-only reconciliation is exactly one
    // generation with neither an active nor previous bundle. It is read-only.
    if state.previous.is_some() {
        return VmRenderedCredentialSource::Unproven("V2_CURSOR_INCONSISTENT");
    }
    if let Some(candidate) = state.candidate.as_ref() {
        let bundle = match store.read_bundle(candidate) {
            Ok(bundle) => bundle,
            Err(_) => return VmRenderedCredentialSource::Unproven("V2_CANDIDATE_INVALID"),
        };
        let Ok(secrets) = ApplicationRuntimeSecrets::from_vm_bundle(&bundle) else {
            return VmRenderedCredentialSource::Unproven("V2_CANDIDATE_INVALID");
        };
        if !vm_runtime_environment(stack_dir, &secrets).is_ok_and(|value| value == rendered) {
            return VmRenderedCredentialSource::Unproven("V2_CANDIDATE_RENDER_MISMATCH");
        }
        if let Some((
            delivery_generation,
            tunnel_auth_generation,
            reality_generation,
            line2_generation,
        )) = observed_vm_credential_generations(&bundle)
        {
            return VmRenderedCredentialSource::V2Candidate {
                delivery_generation,
                tunnel_auth_generation,
                reality_generation,
                line2_generation,
            };
        }
        return VmRenderedCredentialSource::Unproven("V2_CANDIDATE_INVALID");
    }
    if legacy_vm_runtime_secret_path(stack_dir).is_ok_and(|path| path.is_file()) {
        return VmRenderedCredentialSource::LegacyStorePresent;
    }
    VmRenderedCredentialSource::Unproven("NO_MATCHING_LOCAL_CREDENTIAL_SOURCE")
}

fn vm_application_operational_verdict(
    runtime_ready: bool,
    credential_source: &VmRenderedCredentialSource,
) -> &'static str {
    if !runtime_ready {
        return "BLOCKED_RUNTIME_NOT_READY";
    }
    match credential_source {
        VmRenderedCredentialSource::V2Active { .. } => "READY_RUNTIME_CREDENTIAL_SOURCE_UNPROVEN",
        VmRenderedCredentialSource::V2Candidate { .. } => "NETWORK_READY_INITIAL_CUTOVER_PENDING",
        VmRenderedCredentialSource::LegacyStorePresent
        | VmRenderedCredentialSource::Unproven(_) => "BLOCKED_CREDENTIAL_SOURCE_UNPROVEN",
    }
}

fn print_vm_rendered_credential_source(source: &VmRenderedCredentialSource) {
    match source {
        VmRenderedCredentialSource::V2Active {
            delivery_generation,
            tunnel_auth_generation,
            reality_generation,
            line2_generation,
        } => {
            println!("credential_rendered_source=V2_ACTIVE_RENDERED");
            println!("credential_delivery_generation={delivery_generation}");
            println!("credential_tunnel_auth_generation={tunnel_auth_generation}");
            println!("credential_reality_generation={reality_generation}");
            println!("credential_line2_generation={line2_generation}");
            println!("credential_lifecycle_verdict=ACTIVE_RENDERED_RUNNING_UNPROVEN");
            println!("credential_next_safe_action=VERIFY_CONTAINER_RUNTIME_SOURCE");
        }
        VmRenderedCredentialSource::V2Candidate {
            delivery_generation,
            tunnel_auth_generation,
            reality_generation,
            line2_generation,
        } => {
            println!("credential_rendered_source=V2_CANDIDATE_RENDERED");
            println!("credential_delivery_generation={delivery_generation}");
            println!("credential_tunnel_auth_generation={tunnel_auth_generation}");
            println!("credential_reality_generation={reality_generation}");
            println!("credential_line2_generation={line2_generation}");
            println!("credential_lifecycle_verdict=STAGED_FIRST_USE_NOT_CUT_OVER");
            println!("credential_next_safe_action=RECONCILE_PAIRED_FIRST_USE");
        }
        VmRenderedCredentialSource::LegacyStorePresent => {
            println!("credential_rendered_source=UNPROVEN");
            println!("credential_rendered_reason=LEGACY_STORE_PRESENT_NO_V2_MATCH");
            println!("credential_lifecycle_verdict=BLOCKED_LEGACY_SOURCE");
            println!("credential_next_safe_action=READ_ONLY_RECONCILIATION");
        }
        VmRenderedCredentialSource::Unproven(reason) => {
            println!("credential_rendered_source=UNPROVEN");
            println!("credential_rendered_reason={reason}");
            println!("credential_lifecycle_verdict=BLOCKED_UNPROVEN_SOURCE");
            println!("credential_next_safe_action=READ_ONLY_RECONCILIATION");
        }
    }
    // A matching .env.runtime is only disk evidence. Verifying that already
    // running containers loaded it is a distinct runtime/protocol proof.
    println!("credential_running_source=UNPROVEN_WITHOUT_CONTAINER_RELOAD_PROOF");
}

fn verify_vm_candidate_runtime_materialized(
    stack_dir: &Path,
    candidate: &edge_shared_types::CredentialDeliveryBundle,
) -> Result<(), String> {
    let secrets = ApplicationRuntimeSecrets::from_vm_bundle(candidate)?;
    let expected = vm_runtime_environment(stack_dir, &secrets)?;
    let actual = fs::read_to_string(stack_dir.join(RUNTIME_ENV_FILE)).map_err(|_| {
        "VM candidate promotion requires a readable rendered environment".to_owned()
    })?;
    if actual != expected {
        return Err(
            "VM candidate promotion refused: rendered environment differs from candidate Worker-v2 generation"
                .to_owned(),
        );
    }
    Ok(())
}

// This is only a *process-visible file* attestation. It cannot establish
// whether sing-box has parsed those bytes or whether remote Line1 credentials
// are accepted. Those need independent authenticated protocol witnesses.
fn verify_rendered_config_matches_vm_projection(
    stack_dir: &Path,
    runtime: &BTreeMap<String, String>,
) -> Result<(), String> {
    let line1 = expand_runtime_template(
        stack_dir,
        "line1-gateway/config.template.json",
        runtime,
        &LINE1_RUNTIME_TEMPLATE_KEYS,
    )?;
    let mut line2_values = runtime.clone();
    let (certificate, key) = line2_certificate_container_paths(runtime)?;
    line2_values.insert("PROXY_CERT_PATH".to_owned(), certificate);
    line2_values.insert("PROXY_KEY_PATH".to_owned(), key);
    let line2 = expand_runtime_template(
        stack_dir,
        "line2-proxy/config.template.json",
        &line2_values,
        &LINE2_RUNTIME_TEMPLATE_KEYS,
    )?;
    for (name, expected) in [("line1-gateway.json", line1), ("line2-proxy.json", line2)] {
        let observed = fs::read(stack_dir.join("rendered").join(name))
            .map_err(|_| "runtime proof cannot read the rendered config".to_owned())?;
        if observed != expected.as_bytes() {
            return Err(
                "runtime proof refuses a rendered config that differs from Worker-v2 projection"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

async fn attest_vm_running_config_source(stack_dir: &Path) -> Result<(), String> {
    use crate::docker_observation::verify_running_container_config_binding;

    let origin = observe_vm_rendered_credential_source(stack_dir);
    let candidate_only = match origin {
        VmRenderedCredentialSource::V2Candidate { .. } => true,
        VmRenderedCredentialSource::V2Active { .. } => false,
        _ => {
            return Err(
                "running credential source refuses unknown, legacy or mismatched rendered owner"
                    .to_owned(),
            );
        }
    };
    let store = open_vm_credential_store(stack_dir)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "runtime source proof requires durable VM credential state".to_owned())?;
    let reference = if candidate_only {
        if state.active.is_some() || state.previous.is_some() {
            return Err(
                "runtime source proof refuses ambiguous initial candidate state".to_owned(),
            );
        }
        state.candidate.as_ref()
    } else {
        state.active.as_ref()
    }
    .ok_or_else(|| "runtime source proof has no exact selected credential generation".to_owned())?;
    let bundle = store.read_bundle(reference)?;
    let secrets = ApplicationRuntimeSecrets::from_vm_bundle(&bundle)?;
    let expected_env = vm_runtime_environment(stack_dir, &secrets)?;
    if fs::read(stack_dir.join(RUNTIME_ENV_FILE))
        .map_err(|_| "runtime source proof cannot read rendered environment".to_owned())?
        != expected_env.as_bytes()
    {
        return Err("runtime source proof detected a different credential projection".to_owned());
    }
    let runtime = read_typed_runtime_environment(stack_dir)?;
    verify_rendered_config_matches_vm_projection(stack_dir, &runtime)?;
    for (container, path) in [
        (LINE1_CONTAINER, "rendered/line1-gateway.json"),
        (LINE2_CONTAINER, "rendered/line2-proxy.json"),
    ] {
        verify_running_container_config_binding(container, &stack_dir.join(path)).await?;
    }
    // Require an unchanged credential cursor and exactly reproduced rendering
    // after the external Docker observations; never print secret bytes/hashes.
    if store.read_state()?.as_ref() != Some(&state)
        || observe_vm_rendered_credential_source(stack_dir) != origin
    {
        return Err("runtime source proof refuses a concurrent credential transition".to_owned());
    }
    verify_rendered_config_matches_vm_projection(
        stack_dir,
        &read_typed_runtime_environment(stack_dir)?,
    )?;
    println!("credential_runtime_proof=PASS_PROCESS_VISIBLE_FILES");
    println!("credential_selected_generation={}", reference.generation);
    println!(
        "credential_selected_role={}",
        if candidate_only {
            "CANDIDATE"
        } else {
            "ACTIVE"
        }
    );
    println!("line1_config_source=WORKER_V2_PROCESS_BIND_EXACT");
    println!("line2_config_source=WORKER_V2_PROCESS_BIND_EXACT");
    println!("credential_running_source=CONFIG_VISIBLE_LOADED_UNPROVEN");
    println!("line1_authenticated_generation=UNPROVEN_WITHOUT_EXTERNAL_WITNESS");
    println!("credential_state_mutations=0");
    println!("container_mutations=0");
    Ok(())
}

fn require_vm_active_v2_for_promotion(state: &LocalCredentialState) -> Result<(), String> {
    if state.active.is_none() {
        return Err(
            "VM promotion refuses initial enrollment without an explicit paired Worker-v2 cutover"
                .to_owned(),
        );
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("failed to set {} mode 700: {err}", path.display()))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn validate_lower_hex(label: &str, value: &str, expected_len: usize) -> Result<(), String> {
    if value.len() != expected_len
        || !value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must be exactly {expected_len} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

type ApplicationBundleRelease = ApplicationBundleReleaseState;

fn prepare_runtime_directories(stack_dir: &Path) -> Result<(), String> {
    for relative in ["certs", "rendered"] {
        fs::create_dir_all(stack_dir.join(relative)).map_err(|err| {
            format!(
                "failed to create typed runtime directory {}: {err}",
                stack_dir.join(relative).display()
            )
        })?;
    }
    set_private_directory_permissions(&stack_dir.join("certs"))?;
    set_private_directory_permissions(&stack_dir.join("rendered"))?;

    let warp_state = warp_runtime_state_dir(stack_dir)?;
    fs::create_dir_all(&warp_state).map_err(|err| {
        format!(
            "failed to create host-level WARP runtime state {}: {err}",
            warp_state.display()
        )
    })?;
    set_private_directory_permissions(&warp_state)?;

    let parent = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no host-state parent".to_owned())?;
    let certificate_state = parent.join("certificate-state");
    fs::create_dir_all(&certificate_state).map_err(|err| {
        format!(
            "failed to create certificate owner state {}: {err}",
            certificate_state.display()
        )
    })?;
    set_private_directory_permissions(&certificate_state)?;
    Ok(())
}

fn validate_mesh_node_token(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 16 * 1024
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err("Mesh node token must be a non-empty bounded single-line value".to_owned());
    }
    Ok(())
}

fn warp_runtime_state_dir(stack_dir: &Path) -> Result<PathBuf, String> {
    let host_root = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no host-state parent".to_owned())?;
    Ok(host_root.join("warp-state"))
}

fn mesh_runtime_secret_path(stack_dir: &Path) -> Result<PathBuf, String> {
    let host_root = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no host-state parent".to_owned())?;
    Ok(host_root
        .join(RUNTIME_SECRET_DIR)
        .join(MESH_RUNTIME_SECRET_FILE))
}

fn mesh_runtime_state_dir(stack_dir: &Path) -> Result<PathBuf, String> {
    let host_root = stack_dir
        .parent()
        .ok_or_else(|| "application stack path has no host-state parent".to_owned())?;
    Ok(host_root.join("mesh-state"))
}

fn validate_mesh_registration_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(
            "Mesh registration identity must be a non-empty bounded path-safe provider identity"
                .to_owned(),
        );
    }
    Ok(())
}

fn mesh_registration_state_dir(stack_dir: &Path, registration_id: &str) -> Result<PathBuf, String> {
    validate_mesh_registration_id(registration_id)?;
    Ok(mesh_runtime_state_dir(stack_dir)?.join(registration_id))
}

fn mesh_active_registration_path(stack_dir: &Path) -> Result<PathBuf, String> {
    Ok(mesh_runtime_state_dir(stack_dir)?.join(MESH_ACTIVE_REGISTRATION_FILE))
}

fn read_mesh_registration_id(stack_dir: &Path) -> Result<Option<String>, String> {
    let path = mesh_active_registration_path(stack_dir)?;
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read active Mesh registration identity: {err}"
            ));
        }
    };
    let value = raw
        .strip_suffix('\n')
        .ok_or_else(|| "active Mesh registration identity must end with one newline".to_owned())?;
    if value.contains('\n') || value.contains('\r') {
        return Err("active Mesh registration identity must contain exactly one line".to_owned());
    }
    validate_mesh_registration_id(value)?;
    Ok(Some(value.to_owned()))
}

fn persist_mesh_registration_id(stack_dir: &Path, registration_id: &str) -> Result<(), String> {
    validate_mesh_registration_id(registration_id)?;
    prepare_mesh_runtime_state(stack_dir)?;
    let path = mesh_active_registration_path(stack_dir)?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, format!("{registration_id}\n"))
        .map_err(|err| format!("failed to write active Mesh registration identity: {err}"))?;
    set_bundle_file_permissions(&temporary, false, false)?;
    fs::rename(&temporary, &path)
        .map_err(|err| format!("failed to publish active Mesh registration identity: {err}"))?;
    if read_mesh_registration_id(stack_dir)?.as_deref() != Some(registration_id) {
        return Err("active Mesh registration identity failed exact verification".to_owned());
    }
    Ok(())
}

fn read_mesh_node_token(stack_dir: &Path) -> Result<String, String> {
    let path = mesh_runtime_secret_path(stack_dir)?;
    let raw = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read Mesh runtime secret store: {err}"))?;
    let line = raw
        .strip_suffix('\n')
        .ok_or_else(|| "Mesh runtime secret store must end with one newline".to_owned())?;
    if line.contains('\n') || line.contains('\r') {
        return Err("Mesh runtime secret store must contain exactly one line".to_owned());
    }
    let value = line
        .strip_prefix("MESH_NODE_TOKEN=")
        .ok_or_else(|| "Mesh runtime secret store has an invalid schema".to_owned())?;
    validate_mesh_node_token(value)?;
    Ok(value.to_owned())
}

fn persist_mesh_node_token(stack_dir: &Path, value: &str) -> Result<(), String> {
    validate_mesh_node_token(value)?;
    let path = mesh_runtime_secret_path(stack_dir)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Mesh runtime secret store has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create Mesh runtime secret directory: {err}"))?;
    set_private_directory_permissions(parent)?;

    if path.exists() {
        let observed = read_mesh_node_token(stack_dir)?;
        if observed == value {
            set_bundle_file_permissions(&path, false, true)?;
            return Ok(());
        }
    }

    let temporary = path.with_extension("tmp");
    fs::write(&temporary, format!("{MESH_NODE_TOKEN_KEY}={value}\n"))
        .map_err(|err| format!("failed to write temporary Mesh runtime secret store: {err}"))?;
    set_bundle_file_permissions(&temporary, false, true)?;
    fs::rename(&temporary, &path)
        .map_err(|err| format!("failed to atomically publish Mesh runtime secret store: {err}"))?;
    if read_mesh_node_token(stack_dir)? != value {
        return Err("published Mesh runtime secret store failed exact verification".to_owned());
    }
    Ok(())
}

fn prepare_mesh_runtime_state(stack_dir: &Path) -> Result<(), String> {
    let state = mesh_runtime_state_dir(stack_dir)?;
    fs::create_dir_all(&state)
        .map_err(|err| format!("failed to create host-level Mesh runtime state: {err}"))?;
    set_private_directory_permissions(&state)
}

fn line2_certificate_container_paths(
    runtime: &BTreeMap<String, String>,
) -> Result<(String, String), String> {
    if let Some(domain) = runtime.get("TUNNEL_DOMAIN") {
        if !valid_certificate_domain(domain) {
            return Err("TUNNEL_DOMAIN is invalid for Line 2 certificate paths".to_owned());
        }
        let provider = runtime
            .get("ACME_PROVIDER")
            .ok_or_else(|| "ACME_PROVIDER is required for Line 2 certificate paths".to_owned())?;
        let directory = acme_certificate_directory(provider)?;
        let base = format!("/var/lib/sing-box/acme/certificates/{directory}/{domain}");
        return Ok((
            format!("{base}/{domain}.crt"),
            format!("{base}/{domain}.key"),
        ));
    }
    Ok(("/certs/proxy.crt".to_owned(), "/certs/proxy.key".to_owned()))
}

fn prepare_base_proxy_certificate(
    stack_dir: &Path,
    runtime: &BTreeMap<String, String>,
) -> Result<(), String> {
    if runtime.contains_key("TUNNEL_DOMAIN") {
        return Err(
            "base certificate fallback is forbidden when tunnel policy is enabled".to_owned(),
        );
    }
    let cert = stack_dir.join("certs/proxy.crt");
    let key = stack_dir.join("certs/proxy.key");
    match (cert.is_file(), key.is_file()) {
        (true, true) => {
            if certificate_is_valid(&cert, 300) {
                return Ok(());
            }
            return Err("existing base fallback certificate is invalid or expired".to_owned());
        }
        (true, false) | (false, true) => {
            return Err("base fallback certificate state is partial".to_owned());
        }
        (false, false) => {}
    }

    let common_name = runtime
        .get("PROXY_CERT_CN")
        .ok_or_else(|| "base certificate requires PROXY_CERT_CN".to_owned())?;
    let args = vec![
        "req".to_owned(),
        "-x509".to_owned(),
        "-nodes".to_owned(),
        "-newkey".to_owned(),
        "rsa:2048".to_owned(),
        "-keyout".to_owned(),
        key.display().to_string(),
        "-out".to_owned(),
        cert.display().to_string(),
        "-days".to_owned(),
        "3650".to_owned(),
        "-subj".to_owned(),
        format!("/CN={common_name}"),
    ];
    run_fixed_command(
        stack_dir,
        "openssl",
        &args,
        &BTreeMap::new(),
        "generate base certificate",
    )?;
    set_bundle_file_permissions(&key, false, true)?;
    set_bundle_file_permissions(&cert, false, false)?;
    if !certificate_is_valid(&cert, 300) || !key.is_file() {
        return Err("generated base fallback certificate failed validation".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct CertificateReadinessEvidence {
    cert_present: bool,
    key_present: bool,
    key_nonempty: bool,
    cert_valid: bool,
    line1: Option<ContainerRuntimeEvidence>,
    docker_observation_error: Option<String>,
}

impl CertificateReadinessEvidence {
    fn ready(&self) -> bool {
        self.cert_present && self.key_present && self.key_nonempty && self.cert_valid
    }

    fn summary(&self) -> String {
        let line1 = self
            .line1
            .as_ref()
            .map(ContainerRuntimeEvidence::summary)
            .unwrap_or_else(|| "unavailable".to_owned());
        let docker_error = self.docker_observation_error.as_deref().unwrap_or("none");
        format!(
            "certificate={{present:{} key_present:{} key_nonempty:{} valid:{}}} line1={{ {line1} }} docker_observation_error={docker_error}",
            self.cert_present, self.key_present, self.key_nonempty, self.cert_valid
        )
    }
}

async fn observe_certificate_readiness(cert: &Path, key: &Path) -> CertificateReadinessEvidence {
    let cert_present = cert.is_file();
    let key_present = key.is_file();
    let key_nonempty = key_present && fs::metadata(key).is_ok_and(|metadata| metadata.len() > 0);
    let cert_valid = cert_present && certificate_is_valid(cert, 300);

    match observe_container_runtime(LINE1_CONTAINER).await {
        Ok(line1) => CertificateReadinessEvidence {
            cert_present,
            key_present,
            key_nonempty,
            cert_valid,
            line1: Some(line1),
            docker_observation_error: None,
        },
        Err(err) => CertificateReadinessEvidence {
            cert_present,
            key_present,
            key_nonempty,
            cert_valid,
            line1: None,
            docker_observation_error: Some(err),
        },
    }
}

async fn wait_for_owned_certificate(stack_dir: &Path) -> Result<(), String> {
    let [cert, key] = expected_proxy_certificate_paths(stack_dir)?;
    let mut consecutive_not_running = 0u8;
    let mut last = observe_certificate_readiness(&cert, &key).await;

    for _ in 0..90 {
        if last.ready() {
            return Ok(());
        }

        if let Some(line1) = last.line1.as_ref() {
            if !line1.present || !line1.running {
                consecutive_not_running = consecutive_not_running.saturating_add(1);
            } else {
                consecutive_not_running = 0;
            }
        } else {
            consecutive_not_running = 0;
        }

        if consecutive_not_running >= 3 {
            return Err(format!(
                "Line 1 certificate owner is not running after three bounded observations; {}",
                last.summary()
            ));
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
        last = observe_certificate_readiness(&cert, &key).await;
    }

    Err(format!(
        "Line 1 certificate owner did not publish a valid certificate within 180 seconds; {}",
        last.summary()
    ))
}

fn certificate_is_valid(path: &Path, minimum_validity_seconds: u64) -> bool {
    let checkend = minimum_validity_seconds.to_string();
    Command::new("openssl")
        .args(["x509", "-checkend", &checkend, "-noout", "-in"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn verify_bootstrap_post_state(
    stack_dir: &Path,
    mode: BootstrapMode,
    post_state: &AgentState,
) -> BootstrapVerification {
    let mut warnings = Vec::new();

    if !post_state.compose_file_present {
        warnings.push("compose file was not observed after bootstrap".to_owned());
    }
    if !post_state.docker_reachable {
        warnings.push("docker runtime is not reachable after bootstrap".to_owned());
    }

    let tunnel_expected = tunnel_runtime_enabled(stack_dir);
    let line2_expected = line2_runtime_enabled(stack_dir);

    let mut expected = vec!["vultr-warp-egress"];
    if matches!(
        mode,
        BootstrapMode::BootstrapBase | BootstrapMode::BootstrapFull
    ) && line2_expected
    {
        expected.push("vultr-line2-proxy");
    }
    if matches!(
        mode,
        BootstrapMode::BootstrapTunnel | BootstrapMode::BootstrapFull
    ) && tunnel_expected
    {
        expected.push("vultr-line1-gateway");
    }

    for container in expected {
        if !post_state
            .running_containers
            .iter()
            .any(|running| running == container)
        {
            warnings.push(format!(
                "expected container is not running after bootstrap: {container}"
            ));
        }
    }

    if matches!(
        mode,
        BootstrapMode::BootstrapTunnel | BootstrapMode::BootstrapFull
    ) && !tunnel_expected
    {
        warnings.push(
            "tunnel bootstrap requested but TUNNEL_DOMAIN/ACME_EMAIL are not configured".to_owned(),
        );
    }
    if matches!(
        mode,
        BootstrapMode::BootstrapBase | BootstrapMode::BootstrapFull
    ) && !line2_expected
    {
        warnings.push(
            "Line 2 bootstrap requested but PROXY_USERNAME/PROXY_CERT_CN are not configured"
                .to_owned(),
        );
    }
    if post_state.direct_egress_ready != Some(true) {
        warnings.push("direct egress datapath is not ready after bootstrap".to_owned());
    }
    if post_state.warp_egress_ready != Some(true) {
        warnings.push("WARP egress datapath is not ready after bootstrap".to_owned());
    }
    // Line 3 Mesh owns an independent lifecycle. Its disabled or degraded
    // state cannot reject a Line 1/Line 2 bootstrap or credential cutover.
    BootstrapVerification {
        success: warnings.is_empty(),
        warnings,
    }
}

fn parse_compose_port(value: &str) -> Option<PortMapping> {
    let protocol = if value.ends_with("/udp") {
        Protocol::Udp
    } else {
        Protocol::Tcp
    };
    let base = value.split('/').next()?;
    let host_port = base.split(':').next()?.parse().ok()?;
    Some(PortMapping {
        host_port,
        protocol,
    })
}

fn join_ports(ports: &[u32]) -> String {
    ports
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn write_bundle_file(
    root: &Path,
    file: &BundleFile,
    written_paths: &mut Vec<String>,
) -> Result<(), String> {
    validate_bundle_relative_path(&file.relative_path)?;
    let sensitive = file.sensitive || intrinsically_sensitive_bundle_path(&file.relative_path);
    if file.executable && sensitive {
        return Err(format!(
            "bundle file {} cannot be both executable and sensitive",
            file.relative_path
        ));
    }

    let path = root.join(&file.relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(&path, &file.content)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    set_bundle_file_permissions(&path, file.executable, sensitive)?;
    written_paths.push(path.display().to_string());
    Ok(())
}

fn intrinsically_sensitive_bundle_path(value: &str) -> bool {
    value == ".env.runtime"
        || value == "deployment-summary.json"
        || value.ends_with(".key")
        || value.starts_with("tunnel-state/acme/")
}

fn validate_bundle_relative_path(value: &str) -> Result<(), String> {
    if value.is_empty() || value.contains('\\') {
        return Err(format!(
            "bundle path must be a normalized relative path without traversal: {value}"
        ));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "bundle path must be a normalized relative path without traversal: {value}"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_bundle_file_permissions(
    path: &Path,
    executable: bool,
    sensitive: bool,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if sensitive {
        0o600
    } else if executable {
        0o755
    } else {
        0o644
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("failed to set {} mode {mode:o}: {err}", path.display()))
}

#[cfg(not(unix))]
fn set_bundle_file_permissions(
    _path: &Path,
    _executable: bool,
    _sensitive: bool,
) -> Result<(), String> {
    Ok(())
}

fn collect_rendered_artifacts(stack_dir: &Path) -> Vec<FilePresence> {
    let mut required = vec![
        (
            stack_dir.join("docker-compose.yml"),
            FileCategory::RequiredRepoInput,
        ),
        (
            stack_dir.join(RUNTIME_POLICY_FILE),
            FileCategory::RequiredRepoInput,
        ),
        (
            stack_dir.join(RUNTIME_ENV_FILE),
            FileCategory::LocalOnlySensitive,
        ),
    ];
    if line2_runtime_enabled(stack_dir) {
        required.push((
            stack_dir.join("rendered/line2-proxy.json"),
            FileCategory::LocalOnlySensitive,
        ));
    }
    if tunnel_runtime_enabled(stack_dir) {
        required.push((
            stack_dir.join("rendered/line1-gateway.json"),
            FileCategory::LocalOnlySensitive,
        ));
    }
    if let Ok(paths) = expected_proxy_certificate_paths(stack_dir) {
        required.extend(
            paths
                .into_iter()
                .map(|path| (path, FileCategory::LocalOnlySensitive)),
        );
    }

    required
        .into_iter()
        .map(|(path, category)| FilePresence {
            path: rendered_artifact_display_path(stack_dir, &path),
            present: path.is_file(),
            category: category as i32,
        })
        .collect()
}

fn rendered_artifact_display_path(stack_dir: &Path, path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(stack_dir) {
        return relative.to_string_lossy().replace('\\', "/");
    }
    if let Some(parent) = stack_dir.parent()
        && let Ok(relative) = path.strip_prefix(parent)
    {
        return format!("../{}", relative.to_string_lossy().replace('\\', "/"));
    }
    path.display().to_string()
}

fn read_runtime_env(path: &Path) -> Option<std::collections::BTreeMap<String, String>> {
    let raw = fs::read_to_string(path).ok()?;
    let mut values = std::collections::BTreeMap::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            values.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }

    Some(values)
}

fn env_flag_present(values: &std::collections::BTreeMap<String, String>, key: &str) -> bool {
    values
        .get(key)
        .is_some_and(|value| !value.trim().is_empty())
}

fn line2_runtime_enabled(stack_dir: &Path) -> bool {
    read_runtime_env(&stack_dir.join(".env.runtime")).is_some_and(|values| {
        env_flag_present(&values, "PROXY_USERNAME") && env_flag_present(&values, "PROXY_CERT_CN")
    })
}

fn tunnel_runtime_enabled(stack_dir: &Path) -> bool {
    read_runtime_env(&stack_dir.join(".env.runtime")).is_some_and(|values| {
        env_flag_present(&values, "TUNNEL_DOMAIN") && env_flag_present(&values, "ACME_EMAIL")
    })
}

fn validate_acme_provider(value: &str) -> Result<(), String> {
    acme_certificate_directory(value).map(|_| ())
}

fn acme_certificate_directory(value: &str) -> Result<&'static str, String> {
    match value {
        "letsencrypt" => Ok("acme-v02.api.letsencrypt.org-directory"),
        "https://acme-staging-v02.api.letsencrypt.org/directory" => {
            Ok("acme-staging-v02.api.letsencrypt.org-directory")
        }
        _ => Err(
            "ACME_PROVIDER must be letsencrypt or the exact Let’s Encrypt staging directory"
                .to_owned(),
        ),
    }
}

fn valid_certificate_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn expected_proxy_certificate_paths(stack_dir: &Path) -> Result<[PathBuf; 2], String> {
    let runtime = read_runtime_env(&stack_dir.join(".env.runtime")).ok_or_else(|| {
        "runtime environment is unavailable for certificate observation".to_owned()
    })?;
    if env_flag_present(&runtime, "TUNNEL_DOMAIN") {
        let domain = runtime
            .get("TUNNEL_DOMAIN")
            .map(String::as_str)
            .unwrap_or_default();
        if !valid_certificate_domain(domain) {
            return Err("TUNNEL_DOMAIN is invalid for certificate owner state".to_owned());
        }
        let provider = runtime
            .get("ACME_PROVIDER")
            .ok_or_else(|| "ACME_PROVIDER is required for certificate owner state".to_owned())?;
        let directory = acme_certificate_directory(provider)?;
        let owner = stack_dir
            .parent()
            .ok_or_else(|| "application stack path has no certificate-state parent".to_owned())?
            .join("certificate-state")
            .join("acme")
            .join("certificates")
            .join(directory)
            .join(domain);
        return Ok([
            owner.join(format!("{domain}.crt")),
            owner.join(format!("{domain}.key")),
        ]);
    }

    let certs = stack_dir.join("certs");
    Ok([certs.join("proxy.crt"), certs.join("proxy.key")])
}

fn enabled_application_profiles(stack_dir: &Path) -> BTreeSet<String> {
    let mut profiles = BTreeSet::new();
    if tunnel_runtime_enabled(stack_dir) {
        profiles.insert("tunnel".to_owned());
    }
    profiles
}

fn read_bundle_summary(path: &Path) -> Option<BundleSummary> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

#[derive(Debug)]
struct BootstrapVerification {
    success: bool,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct ComposeObservation {
    expected_containers: Vec<String>,
    expected_tcp_ports: Vec<u32>,
    expected_udp_ports: Vec<u32>,
}

#[derive(Debug)]
struct PortMapping {
    host_port: u32,
    protocol: Protocol,
}

#[derive(Debug)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Deserialize)]
struct ComposeFile {
    services: std::collections::BTreeMap<String, ComposeService>,
}

#[derive(Debug, Deserialize)]
struct ComposeService {
    container_name: Option<String>,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BundleSummary {
    label: Option<String>,
    instance_id: Option<String>,
}

#[cfg(test)]
mod native_runtime_diagnostic_code_tests {
    use super::*;

    #[test]
    fn signed_observation_uses_closed_bounded_readiness_codes() {
        let state = AgentState {
            ready: false,
            degraded_reasons: vec![
                "WARP egress datapath probe failed".to_owned(),
                "direct egress datapath probe failed".to_owned(),
                "WARP egress datapath probe failed".to_owned(),
                "unexpected API_TOKEN=secret".to_owned(),
            ],
            ..Default::default()
        };
        assert_eq!(
            native_runtime_reason_codes(&state, vec!["VM_APPLICATION_OWNER_UNPROVEN"]),
            vec![
                "VM_APPLICATION_OWNER_UNPROVEN",
                "WARP_EGRESS_FAILED",
                "DIRECT_EGRESS_FAILED",
                "OTHER_UNPROVEN"
            ]
        );
        let full = native_runtime_reason_codes(&state, vec!["VM_DOCKER_UNAVAILABLE"; 12]);
        assert_eq!(full.len(), 12);
        let unknown = AgentState { ready: false, ..Default::default() };
        assert_eq!(
            native_runtime_reason_codes(&unknown, Vec::new()),
            vec!["VM_RUNTIME_NOT_READY_UNPROVEN"]
        );
        let ready = AgentState { ready: true, ..Default::default() };
        assert!(native_runtime_reason_codes(&ready, Vec::new()).is_empty());
    }

    #[test]
    fn known_readiness_failures_are_distinct_and_do_not_echo_secrets() {
        assert_eq!(
            native_runtime_reason_code("direct egress datapath probe failed"),
            "DIRECT_EGRESS_FAILED"
        );
        assert_eq!(
            native_runtime_reason_code("WARP egress datapath probe failed"),
            "WARP_EGRESS_FAILED"
        );
        assert_eq!(
            native_runtime_reason_code("expected TCP ports are not listening: 443"),
            "TCP_PORTS_MISSING"
        );
        assert_eq!(
            native_runtime_reason_code("expected UDP ports are not listening: 443"),
            "UDP_PORTS_MISSING"
        );
        assert_eq!(
            native_runtime_reason_code(
                "container abc does not match exact accepted runtime: PRIVATE"
            ),
            "EXACT_IMAGE_OR_CONTAINER_UNREADY"
        );
        assert_eq!(
            native_runtime_reason_code("mesh credential private-token=SECRET"),
            "MESH_RUNTIME_UNREADY"
        );
        assert_eq!(
            native_runtime_reason_code("docker runtime is not reachable from edge-agent"),
            "DOCKER_UNAVAILABLE"
        );
        assert_eq!(
            native_runtime_reason_code("unexpected token=SECRET"),
            "OTHER_UNPROVEN"
        );
    }
}

#[cfg(test)]
#[path = "main_native_mutation_ingress_tests.rs"]
mod native_mutation_ingress_tests;
