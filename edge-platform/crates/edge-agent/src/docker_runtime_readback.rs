use super::*;
#[path = "docker_process_readback.rs"]
mod process_readback;
use process_readback::collect_native_process_snapshot;

/// Running is not equivalent to readiness. A missing healthcheck is not
/// an implicit PASS. This only describes local Docker health, not egress.
pub(super) fn native_running_health_reason(
    running: bool,
    health_debug: Option<&str>,
) -> (edge_shared_types::FleetVmObservedReason, &'static str) {
    use edge_shared_types::FleetVmObservedReason as Reason;
    if !running {
        return (Reason::Stopped, "");
    }
    match health_debug.map(str::to_ascii_lowercase) {
        Some(ref state) if state == "healthy" => (Reason::Healthy, "HEALTHY"),
        Some(ref state) if state == "unhealthy" => (Reason::HealthUnhealthy, "UNHEALTHY"),
        Some(ref state) if state == "starting" => (Reason::HealthStarting, "STARTING"),
        None => (Reason::RunningNoHealthcheck, ""),
        _ => (Reason::HealthUnproven, ""),
    }
}

/// Bounded direct DNS configuration observation. /etc/resolv.conf may be a
/// systemd-resolved symlink: it is a source of configuration, never proof that
/// an upstream nameserver responds.
pub(super) fn observe_native_dns_configuration() -> Result<Vec<String>, String> {
    let path = Path::new("/etc/resolv.conf");
    let metadata = fs::metadata(path).map_err(|_| "HOST_VM_DNS_CONFIG_UNAVAILABLE")?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("HOST_VM_DNS_CONFIG_UNTRUSTED".into());
    }
    let bytes = fs::read(path).map_err(|_| "HOST_VM_DNS_CONFIG_UNREADABLE")?;
    if bytes.len() > 4096 {
        return Err("HOST_VM_DNS_CONFIG_TOO_LARGE".into());
    }
    parse_native_dns_configuration(&bytes)
}

pub(super) fn parse_native_dns_configuration(bytes: &[u8]) -> Result<Vec<String>, String> {
    let raw = std::str::from_utf8(bytes).map_err(|_| "HOST_VM_DNS_CONFIG_NOT_UTF8")?;
    let mut nameservers = Vec::new();
    let mut seen = BTreeSet::new();
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let addr = fields.next().ok_or("HOST_VM_DNS_NAMESERVER_INVALID")?;
        let parsed = addr
            .parse::<IpAddr>()
            .map_err(|_| "HOST_VM_DNS_NAMESERVER_INVALID")?;
        let canonical = parsed.to_string();
        if !seen.insert(canonical.clone()) || fields.next().is_some() {
            return Err("HOST_VM_DNS_NAMESERVER_DUPLICATE_OR_INVALID".into());
        }
        nameservers.push(canonical);
        if nameservers.len() > 8 {
            return Err("HOST_VM_DNS_TOO_MANY_NAMESERVERS".into());
        }
    }
    if nameservers.is_empty() {
        return Err("HOST_VM_DNS_NO_NAMESERVERS".into());
    }
    Ok(nameservers)
}

/// Native netfilter ruleset inspection via the installed nft CLI, with no
/// shell, dynamic arguments, mutation or polling. The digest is a fingerprint
/// of observed bytes, NOT evidence that firewall desired rules are correct.
pub(super) async fn observe_native_nft_ruleset() -> Option<(Vec<u8>, u32)> {
    // The installed Linux coreutils timeout bounds the fixed nft command
    // without a Tokio process feature, background agent or polling loop.
    // The root owner provides every argument; no runner-supplied path or shell.
    let output = tokio::task::spawn_blocking(|| {
        std::process::Command::new("/usr/bin/timeout")
            .args(["-s", "KILL", "6s", "/usr/sbin/nft", "-j", "list", "ruleset"])
            .env_clear()
            .output()
    })
    .await
    .ok()?
    .ok()?;
    if !output.status.success() || output.stdout.len() > 262144 {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let rows = parsed.get("nftables")?.as_array()?;
    let count = rows
        .iter()
        .filter(|entry| entry.get("rule").is_some())
        .count();
    let count = u32::try_from(count).ok()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &output.stdout)
        .as_ref()
        .to_vec();
    Some((digest, count))
}

/// Same installed root Agent, same typed readback: netlink, DNS configuration,
/// and nft ruleset are separate observations. Unknown stays UNKNOWN.
pub(super) async fn observe_native_vm_network_readback() -> edge_shared_types::FleetVmNetworkReadback
{
    let ipv4 = super::super::network_observation::observe_ipv4_network()
        .await
        .ok()
        .filter(|value| value.encode_to_vec().len() <= 24_576);
    let dns = observe_native_dns_configuration().ok();
    let nft = observe_native_nft_ruleset().await;
    let (dual_stack, dual_stack_error_code) =
        match super::super::network_observation::observe_dual_stack().await {
            Ok(value) => (Some(value), String::new()),
            Err(code) => (None, code.to_owned()),
        };
    edge_shared_types::FleetVmNetworkReadback {
        dual_stack,
        dual_stack_error_code,
        ipv4,
        dns_nameservers: dns.clone().unwrap_or_default(),
        dns_configuration_observed: dns.is_some(),
        nft_ruleset_sha256: nft
            .as_ref()
            .map(|(hash, _)| hash.clone())
            .unwrap_or_default(),
        nft_rule_count: nft.as_ref().map(|(_, count)| *count).unwrap_or_default(),
        nft_ruleset_observed: nft.is_some(),
    }
}

pub(super) fn set_vm_observed_reason(
    row: &mut edge_shared_types::FleetVmResourceReadback,
    reason: edge_shared_types::FleetVmObservedReason,
) {
    row.observed_reason = reason as i32;
    row.reason_code = reason
        .as_str_name()
        .strip_prefix("FLEET_VM_OBSERVED_REASON_")
        .expect("closed protobuf Docker reason")
        .to_owned();
}

/// One typed root-local credential dependency, observed from the SAME
/// credential store as native INSTALL. No generation is treated as a remote
/// attestation. Partial/legacy stores are explicit blockers.
pub(super) fn observe_native_vm_credential_readback(
    stack_dir: &Path,
) -> edge_shared_types::FleetVmCredentialReadback {
    use edge_shared_types::{
        FleetVmCredentialReadback as Readback, FleetVmCredentialState as State,
    };
    let make = |state: State, active_generation: u64, candidate_generation: u64| Readback {
        state: state as i32,
        active_generation,
        candidate_generation,
    };
    if super::super::legacy_vm_runtime_secret_path(stack_dir).is_ok_and(|path| path.exists()) {
        return make(State::LegacyPresent, 0, 0);
    }
    let state = match super::super::observe_vm_credential_state(stack_dir) {
        Ok(Some(state))
            if state.projection == edge_shared_types::CredentialProjectionKind::Vm as i32 =>
        {
            state
        }
        Ok(None)
            if super::super::vm_credential_store_root(stack_dir)
                .is_ok_and(|path| !path.exists()) =>
        {
            return make(State::StoreAbsent, 0, 0);
        }
        _ => return make(State::Unproven, 0, 0),
    };
    let candidate_generation = state
        .candidate
        .as_ref()
        .map(|reference| reference.generation)
        .unwrap_or(0);
    if let Some(active) = state.active.as_ref() {
        let valid = super::super::active_vm_credential_bundle(stack_dir)
            .ok()
            .flatten()
            .is_some_and(|bundle| {
                bundle.generation == active.generation
                    && pin_active_native_vm_credential(&bundle).is_ok()
            });
        return if valid {
            make(
                State::ActiveLocalValid,
                active.generation,
                candidate_generation,
            )
        } else {
            make(State::Unproven, 0, 0)
        };
    }
    if let Some(candidate) = state.candidate.as_ref() {
        let valid = super::super::open_vm_credential_store(stack_dir)
            .ok()
            .and_then(|store| store.read_bundle(candidate).ok())
            .is_some_and(|bundle| {
                bundle.generation == candidate.generation
                    && pin_active_native_vm_credential(&bundle).is_ok()
            });
        return if valid && state.previous.is_none() {
            make(State::CandidateOnly, 0, candidate.generation)
        } else {
            make(State::Unproven, 0, 0)
        };
    }
    make(State::Unproven, 0, 0)
}

/// Typed bounded Docker State.Error classifier. This input may contain
/// secrets; never persist or print it. UNKNOWN remains UNPROVEN, not healthy.
pub(super) fn native_vm_docker_failure_class(
    reason: &str,
) -> edge_shared_types::FleetVmRuntimeFailureClass {
    use edge_shared_types::FleetVmRuntimeFailureClass as Class;
    let reason = reason
        .chars()
        .take(4096)
        .collect::<String>()
        .to_ascii_lowercase();
    if reason.is_empty() {
        Class::Unproven
    } else if reason.contains("invalid config")
        || reason.contains("failed to parse")
        || reason.contains("config parse")
        || reason.contains("json:")
    {
        Class::ConfigParse
    } else if reason.contains("permission denied") || reason.contains("access denied") {
        Class::Permission
    } else if reason.contains("address already in use") || reason.contains("bind:") {
        Class::PortBind
    } else if reason.contains("no such host") || reason.contains("dns lookup") {
        Class::Dns
    } else if reason.contains("connection refused") {
        Class::UpstreamRefused
    } else if reason.contains("certificate") || reason.contains("tls:") {
        Class::Tls
    } else if reason.contains("panic") || reason.contains("segmentation fault") {
        Class::ProcessCrash
    } else if reason.contains("no such file or directory") {
        Class::FileMissing
    } else {
        Class::StateErrorOther
    }
}

/// Read-only, per-resource Docker evidence. Each entry is inspected once:
/// labels, immutable ID and state come from the SAME inspect response.
/// Never read or emit environment, credentials, mount contents or Docker logs.
pub(crate) async fn observe_vm_resource_report(
    host: &edge_shared_types::FleetHost,
    stack_dir: &Path,
) -> Result<edge_shared_types::FleetVmResourceReport, String> {
    use edge_shared_types::{
        FleetVmConfigProof, FleetVmInstalledPolicyStatus, FleetVmObservedReason as Reason,
        FleetVmResourceReadback, FleetVmResourceReport,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "HOST_VM_RESOURCES_CLOCK_UNAVAILABLE")?
        .as_secs();
    let docker = docker_connection().await.ok();
    let mut resources = Vec::with_capacity(host.vm_containers.len());
    for resource in &host.vm_containers {
        let mut row = FleetVmResourceReadback {
            resource: Some(resource.clone()),
            observed_reason: Reason::DockerUnavailable as i32,
            reason_code: "DOCKER_UNAVAILABLE".to_owned(),
            config_proof: if resource.compose_service == "warp-egress" {
                FleetVmConfigProof::NotApplicable as i32
            } else {
                FleetVmConfigProof::NotRunning as i32
            },
            ..Default::default()
        };
        if let Some(docker) = &docker {
            match docker
                .inspect_container(&resource.container_name, None)
                .await
            {
                Err(BollardError::DockerResponseServerError {
                    status_code: 404, ..
                }) => {
                    set_vm_observed_reason(&mut row, Reason::ContainerAbsent);
                }
                Err(_) => set_vm_observed_reason(&mut row, Reason::InspectUnavailable),
                Ok(inspect) => {
                    row.present = true;
                    set_vm_observed_reason(&mut row, Reason::ForeignOwner);
                    let valid_labels = inspect
                        .config
                        .as_ref()
                        .and_then(|cfg| cfg.labels.as_ref())
                        .is_some_and(|labels| {
                            exact_application_compose_owner(
                                &resource.container_name,
                                labels,
                                &host.vm_containers,
                            )
                            .is_ok()
                        });
                    let id = inspect.id.as_deref().unwrap_or("");
                    let valid_id = id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit());
                    if inspect.name.as_deref()
                        == Some(format!("/{}", resource.container_name).as_str())
                        && valid_labels
                        && valid_id
                    {
                        row.ownership_proven = true;
                        row.container_id = id.to_owned();
                        if let Some(config) = &inspect.config {
                            row.image = config
                                .image
                                .as_deref()
                                .filter(|image| image.len() <= 256)
                                .unwrap_or("")
                                .to_owned();
                        }
                        if let Some(restarts) =
                            inspect.restart_count.and_then(|v| u64::try_from(v).ok())
                        {
                            row.restart_count = restarts;
                            row.restart_count_proven = true;
                        }
                        set_vm_observed_reason(&mut row, Reason::StateUnproven);
                        if let Some(state) = &inspect.state {
                            if let Some(exit_code) = state.exit_code {
                                row.last_exit_code = exit_code;
                                row.last_exit_code_proven = true;
                            }
                            if let Some(oom) = state.oom_killed {
                                row.oom_killed = oom;
                                row.oom_killed_proven = true;
                            }
                            if let Some(error) =
                                state.error.as_deref().filter(|value| !value.is_empty())
                            {
                                row.docker_state_error_present = true;
                                row.runtime_failure_class =
                                    native_vm_docker_failure_class(error) as i32;
                            }
                            if let Ok(running) = require_known_native_container_state(state) {
                                row.running_proven = true;
                                row.running = running;
                                let raw_health = state
                                    .health
                                    .as_ref()
                                    .and_then(|health| health.status.as_ref())
                                    .map(|status| format!("{status:?}"));
                                let (reason, health) =
                                    native_running_health_reason(running, raw_health.as_deref());
                                set_vm_observed_reason(&mut row, reason);
                                row.health = health.to_owned();
                            }
                        }
                    }
                }
            }
        }
        if row.ownership_proven
            && row.running_proven
            && row.running
            && matches!(
                resource.compose_service.as_str(),
                "line1-gateway" | "line2-proxy"
            )
        {
            let name = resource.compose_service.as_str();
            let config = stack_dir.join(format!("rendered/{name}.json"));
            row.config_proof = FleetVmConfigProof::Unproven as i32;
            // Bounded, root-local file read. Any race or missing bind remains
            // UNPROVEN; no secret-bearing config bytes leave the owner.
            if let Ok(metadata) = fs::symlink_metadata(&config)
                && metadata.file_type().is_file()
                && metadata.len() > 0
                && metadata.len() <= 4 * 1024 * 1024
                && let Ok(before) = fs::read(&config)
                && verify_running_container_config_binding(&resource.container_name, &config)
                    .await
                    .is_ok()
                && fs::read(&config).is_ok_and(|after| after == before)
            {
                row.config_proof = FleetVmConfigProof::BoundRunningProcess as i32;
                row.config_sha256 = ring::digest::digest(&ring::digest::SHA256, &before)
                    .as_ref()
                    .to_vec();
            }
        }
        resources.push(row);
    }
    let installed_policy = compile_native_vm_policy_checked(stack_dir, host);
    let (installed_policy_graph, installed_policy_status, installed_policy_error_code) =
        match installed_policy {
            Ok(graph) => (
                Some(graph),
                FleetVmInstalledPolicyStatus::Valid as i32,
                String::new(),
            ),
            Err(error) => (None, error.status as i32, error.code),
        };
    let credential = observe_native_vm_credential_readback(stack_dir);
    let mut bootstrap_phase =
        super::super::host_native::local_vm_bootstrap_phase(host, &credential);
    // Run only for a trust-verified, Git-pinned first use with no local ACTIVE.
    // A failed GET becomes an exact read-only dependency reason, never a
    // failed deep report, a credential write or permission to start Docker.
    if bootstrap_phase == edge_shared_types::FleetVmBootstrapPhase::FirstUseWorkerSourceUnverified {
        bootstrap_phase = observe_native_vm_first_use_source(host, stack_dir).await;
    }
    let report = FleetVmResourceReport {
        schema_version: 2,
        machine_id: host.machine_id.clone(),
        observed_at_unix: now,
        resources,
        remote_attested: false,
        network: Some(observe_native_vm_network_readback().await),
        // Installed bytes may be absent or invalid after a partial failure.
        // Never conceal Docker evidence solely because policy cannot render.
        installed_policy_graph,
        installed_policy_status,
        installed_policy_error_code,
        credential: Some(credential),
        bootstrap_phase: bootstrap_phase as i32,
        processes: Some(collect_native_process_snapshot()),
        managed_docker: collect_native_managed_docker_readback(stack_dir, host, docker.as_ref())
            .await,
        managed_kernel_routes: collect_native_managed_kernel_routes(stack_dir, host).await,
    };
    edge_shared_types::host_resources::validate_vm_resource_report(&report, host)
        .map_err(str::to_owned)?;
    Ok(report)
}

pub(crate) async fn observe_docker() -> Result<DockerObservation, String> {
    let docker = docker_connection().await?;

    let options = ListContainersOptionsBuilder::default().all(true).build();
    let containers = docker
        .list_containers(Some(options))
        .await
        .map_err(|err| format!("failed to list Docker containers: {err}"))?;

    Ok(normalize_containers(containers))
}

pub(crate) async fn observe_container_runtime(
    container_name: &str,
) -> Result<ContainerRuntimeEvidence, String> {
    let docker = docker_connection().await?;
    let inspect = match docker.inspect_container(container_name, None).await {
        Ok(inspect) => inspect,
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            return Ok(ContainerRuntimeEvidence {
                present: false,
                running: false,
                exit_code: None,
                runtime_error: None,
                log_tail: Vec::new(),
                name: container_name.to_owned(),
                image: None,
                restart_count: None,
                oom_killed: None,
                health: None,
                networks: Vec::new(),
                published_ports: Vec::new(),
                mounts: Vec::new(),
            });
        }
        Err(err) => {
            return Err(format!(
                "failed to inspect Docker container {container_name}: {err}"
            ));
        }
    };

    let state = inspect.state.unwrap_or_default();
    let image = inspect
        .config
        .and_then(|config| config.image)
        .or(inspect.image);
    let restart_count = inspect
        .restart_count
        .and_then(|value| u64::try_from(value).ok());
    let oom_killed = state.oom_killed;
    let health = state
        .health
        .as_ref()
        .and_then(|health| health.status.as_ref())
        .map(|status| format!("{status:?}"));

    let network_settings = inspect.network_settings.unwrap_or_default();
    let mut networks = network_settings
        .networks
        .unwrap_or_default()
        .into_keys()
        .collect::<Vec<_>>();
    networks.sort();
    networks.dedup();

    let mut published_ports = network_settings
        .ports
        .unwrap_or_default()
        .into_iter()
        .flat_map(|(container_port, bindings)| {
            bindings
                .unwrap_or_default()
                .into_iter()
                .map(move |binding| match binding.host_port {
                    Some(host_port) => format!("{container_port}->{host_port}"),
                    None => container_port.clone(),
                })
        })
        .collect::<Vec<_>>();
    published_ports.sort();
    published_ports.dedup();

    let mut mounts = inspect
        .mounts
        .unwrap_or_default()
        .into_iter()
        .map(|mount| {
            let kind = mount.typ.unwrap_or_else(|| "UNKNOWN".to_owned());
            let destination = mount.destination.unwrap_or_else(|| "<unknown>".to_owned());
            let rw = mount
                .rw
                .map(|value| value.to_string())
                .unwrap_or_else(|| "UNKNOWN".to_owned());
            format!("{kind}:{destination}:rw={rw}")
        })
        .collect::<Vec<_>>();
    mounts.sort();
    mounts.dedup();

    let options = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .timestamps(false)
        .tail("40")
        .build();
    let log_tail = match docker
        .logs(container_name, Some(options))
        .try_collect::<Vec<_>>()
        .await
    {
        Ok(outputs) => {
            bounded_redacted_log_tail(outputs.into_iter().map(|output| output.to_string()))
        }
        Err(err) => vec![format!("[docker log observation unavailable: {err}]")],
    };

    Ok(ContainerRuntimeEvidence {
        present: true,
        running: state.running.unwrap_or(false),
        exit_code: state.exit_code,
        runtime_error: state.error.filter(|value| !value.is_empty()),
        log_tail,
        name: container_name.to_owned(),
        image,
        restart_count,
        oom_killed,
        health,
        networks,
        published_ports,
        mounts,
    })
}

// Bollard 0.21.1 models Docker inspect MountPoint.Type as Option<String>,
// not MountPointTypeEnum. Debug-formatting it adds quotes (\x22bind\x22) and
// therefore falsely rejects a genuine read-only bind. Check the exact wire
// representation directly, and keep missing/writable evidence fail-closed.
pub(super) fn require_exact_readonly_config_bind(
    container: &str,
    kind: Option<&str>,
    writable: Option<bool>,
) -> Result<(), String> {
    match kind {
        Some("bind") => {}
        Some(_) => {
            return Err(format!(
                "runtime config proof {container} config mount type=NON_BIND"
            ));
        }
        None => {
            return Err(format!(
                "runtime config proof {container} config mount type=UNAVAILABLE"
            ));
        }
    }
    match writable {
        Some(false) => Ok(()),
        Some(true) => Err(format!(
            "runtime config proof {container} config mount writable=TRUE"
        )),
        None => Err(format!(
            "runtime config proof {container} config mount writable=UNAVAILABLE"
        )),
    }
}

/// Read-only proof of the *file visible to the running process*. This does
/// not claim that sing-box reloaded that file into its in-memory configuration.
/// Authentication is an independent network-level proof.
pub(crate) async fn verify_running_container_config_binding(
    name: &str,
    expected_host_file: &Path,
) -> Result<(), String> {
    const CONTAINER_CONFIG: &str = "/etc/sing-box/config.json";
    const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
    if !matches!(name, "vultr-line1-gateway" | "vultr-line2-proxy") {
        return Err("runtime credential proof refuses an unknown container".to_owned());
    }
    let docker = docker_connection().await?;
    let before = docker
        .inspect_container(name, None)
        .await
        .map_err(|_| "runtime config proof cannot inspect the named container".to_owned())?;
    let state = before
        .state
        .as_ref()
        .ok_or("runtime config proof requires observed container state")?;
    if state.running != Some(true) {
        return Err("runtime config proof refuses a non-running container".to_owned());
    }
    let pid = state
        .pid
        .filter(|pid| *pid > 1)
        .ok_or("runtime config proof requires exact running Linux process PID")?;
    let started_at = state
        .started_at
        .clone()
        .ok_or("runtime config proof requires Docker process start identity")?;

    let config_mounts = before
        .mounts
        .as_ref()
        .ok_or("runtime config proof requires Docker bind mount evidence")?
        .iter()
        .filter(|mount| mount.destination.as_deref() == Some(CONTAINER_CONFIG))
        .collect::<Vec<_>>();
    if config_mounts.len() != 1 {
        return Err("runtime config proof requires exactly one config bind mount".to_owned());
    }
    let mount = config_mounts[0];
    require_exact_readonly_config_bind(name, mount.typ.as_deref(), mount.rw)?;
    let expected = fs::canonicalize(expected_host_file)
        .map_err(|_| "runtime config proof cannot resolve expected host file".to_owned())?;
    let bound = mount
        .source
        .as_deref()
        .ok_or("runtime config proof has no Docker source path")?;
    if fs::canonicalize(bound).ok().as_deref() != Some(expected.as_path()) {
        return Err("runtime config proof refuses a different bind source".to_owned());
    }
    let metadata = fs::metadata(&expected)
        .map_err(|_| "runtime config proof cannot stat expected file".to_owned())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
        return Err("runtime config proof refuses a missing or oversized config".to_owned());
    }
    let visible = PathBuf::from(format!("/proc/{pid}/root{CONTAINER_CONFIG}"));
    let in_container = fs::read(&visible)
        .map_err(|_| "runtime config proof cannot read running process mount view".to_owned())?;
    if in_container.len() as u64 != metadata.len()
        || in_container
            != fs::read(&expected)
                .map_err(|_| "runtime config proof cannot re-read expected host file".to_owned())?
    {
        return Err(
            "running process sees different config bytes than the exact host bind".to_owned(),
        );
    }
    let after = docker
        .inspect_container(name, None)
        .await
        .map_err(|_| "runtime config proof cannot re-inspect the named container".to_owned())?;
    let stable = after.state.as_ref().is_some_and(|state| {
        state.running == Some(true)
            && state.pid == Some(pid)
            && state.started_at.as_ref() == Some(&started_at)
    });
    if !stable {
        return Err("running container restarted during config-source attestation".to_owned());
    }
    Ok(())
}

pub(super) fn bounded_redacted_log_tail<I>(lines: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut normalized = lines
        .into_iter()
        .flat_map(|chunk| {
            chunk
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(redact_runtime_log_line)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    if normalized.len() > 40 {
        normalized.drain(..normalized.len() - 40);
    }
    normalized
}

pub(super) fn redact_runtime_log_line(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    if [
        "password",
        "private_key",
        "private key",
        "authorization",
        "credential",
        "mesh_node_token",
        "bearer ",
        "token=",
        "uuid=",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        // An ERROR/FATAL private-key load failure needs a useful diagnosis,
        // without exposing a key, path, original log token or surrounding
        // secret. Emit one fixed safe symbol, not a redacted raw excerpt.
        if (lowered.contains(" fatal[")
            || lowered.starts_with("fatal")
            || lowered.contains(" error[")
            || lowered.starts_with("error"))
            && (lowered.contains("private key") || lowered.contains("private_key"))
            && (lowered.contains("tls") || lowered.contains("certificate"))
            && (lowered.contains("failed")
                || lowered.contains("invalid")
                || lowered.contains("mismatch")
                || lowered.contains("cannot")
                || lowered.contains("unable"))
        {
            return "[SAFE_FATAL_TLS_PRIVATE_KEY_ERROR]".to_owned();
        }
        return "[redacted sensitive runtime log line]".to_owned();
    }
    line.chars().take(320).collect()
}

pub(super) fn normalize_containers(summaries: Vec<ContainerSummary>) -> DockerObservation {
    let mut containers = Vec::new();
    let mut running_containers = BTreeSet::new();
    let mut listening_tcp_ports = BTreeSet::new();
    let mut listening_udp_ports = BTreeSet::new();

    for summary in summaries {
        let running = matches!(summary.state, Some(ContainerSummaryStateEnum::RUNNING));
        let mut names = summary
            .names
            .unwrap_or_default()
            .into_iter()
            .map(|name| name.trim_start_matches('/').to_owned())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();

        if running {
            running_containers.extend(names.iter().cloned());
            for port in summary.ports.unwrap_or_default() {
                let Some(public_port) = port.public_port else {
                    continue;
                };
                match port.typ {
                    Some(PortSummaryTypeEnum::TCP) => {
                        listening_tcp_ports.insert(u32::from(public_port));
                    }
                    Some(PortSummaryTypeEnum::UDP) => {
                        listening_udp_ports.insert(u32::from(public_port));
                    }
                    _ => {}
                }
            }
        }

        let image = summary.image;
        let mut networks = summary
            .network_settings
            .and_then(|settings| settings.networks)
            .map(|networks| networks.into_keys().collect::<Vec<_>>())
            .unwrap_or_default();
        networks.sort();
        networks.dedup();

        for name in names {
            containers.push(DockerContainerObservation {
                name,
                running,
                image: image.clone(),
                networks: networks.clone(),
            });
        }
    }

    containers.sort_by(|left, right| left.name.cmp(&right.name));
    DockerObservation {
        reachable: true,
        running_containers: running_containers.into_iter().collect(),
        listening_tcp_ports: listening_tcp_ports.into_iter().collect(),
        listening_udp_ports: listening_udp_ports.into_iter().collect(),
        containers,
    }
}
