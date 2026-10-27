use super::*;

pub(super) fn inspect_bundle_artifacts(stack_dir: &Path, state: &mut AgentState) {
    let runtime_env = stack_dir.join(".env.runtime");
    if !runtime_env.is_file() {
        state.degraded_reasons.push(format!(
            "bundle artifact missing: {}",
            runtime_env.display()
        ));
    }

    let rendered_dir = stack_dir.join("rendered");
    let mut expected_rendered = Vec::new();
    if line2_runtime_enabled(stack_dir) {
        expected_rendered.push("line2-proxy.json");
    }
    if tunnel_runtime_enabled(stack_dir) {
        expected_rendered.push("line1-gateway.json");
    }
    let missing_rendered = expected_rendered
        .iter()
        .filter(|name| !rendered_dir.join(name).is_file())
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if !missing_rendered.is_empty() {
        state.degraded_reasons.push(format!(
            "bundle artifact missing: rendered/{}",
            missing_rendered.join(", rendered/")
        ));
    }

    match expected_proxy_certificate_paths(stack_dir) {
        Ok(paths) => {
            let missing = paths
                .iter()
                .filter(|path| !path.is_file())
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                state.degraded_reasons.push(format!(
                    "bundle artifact missing: certificate {}",
                    missing.join(", ")
                ));
            }
        }
        Err(reason) => state
            .degraded_reasons
            .push(format!("bundle artifact invalid: {reason}")),
    }

    if let Some(summary_path) = stack_dir
        .parent()
        .map(|parent| parent.join("deployment-summary.json"))
        .filter(|path| path.is_file())
        && let Some(summary) = read_bundle_summary(&summary_path)
    {
        if let Some(label) = summary.label {
            state.active_bundle_id = Some(label);
        }
        if let Some(instance_id) = summary.instance_id {
            state.topology_version = format!("{}:{}", state.topology_version, instance_id);
        }
    }
}

pub(super) fn inspect_compose(
    compose_path: &Path,
    state: &mut AgentState,
    enabled_profiles: &BTreeSet<String>,
    line2_enabled: bool,
) -> Option<ComposeObservation> {
    let raw = match fs::read_to_string(compose_path) {
        Ok(raw) => {
            state.compose_file_present = true;
            raw
        }
        Err(err) => {
            state.degraded_reasons.push(format!(
                "compose file is not readable at {}: {err}",
                compose_path.display()
            ));
            return None;
        }
    };

    let compose: ComposeFile = match serde_yaml::from_str(&raw) {
        Ok(compose) => compose,
        Err(err) => {
            state.degraded_reasons.push(format!(
                "compose file is not valid YAML at {}: {err}",
                compose_path.display()
            ));
            return None;
        }
    };

    let mut expected_containers = Vec::new();
    let mut expected_tcp_ports = BTreeSet::new();
    let mut expected_udp_ports = BTreeSet::new();

    for (service_name, service) in compose.services {
        if service_name == "line2-proxy" && !line2_enabled {
            continue;
        }
        if !service.profiles.is_empty()
            && !service
                .profiles
                .iter()
                .any(|profile| enabled_profiles.contains(profile))
        {
            continue;
        }
        if let Some(name) = service.container_name {
            expected_containers.push(name);
        }
        for port in service.ports {
            if let Some(parsed) = parse_compose_port(&port) {
                match parsed.protocol {
                    Protocol::Tcp => {
                        expected_tcp_ports.insert(parsed.host_port);
                    }
                    Protocol::Udp => {
                        expected_udp_ports.insert(parsed.host_port);
                    }
                }
            }
        }
    }

    Some(ComposeObservation {
        expected_containers,
        expected_tcp_ports: expected_tcp_ports.into_iter().collect(),
        expected_udp_ports: expected_udp_ports.into_iter().collect(),
    })
}

pub(super) async fn inspect_datapath_readiness(
    state: &mut AgentState,
    docker: &DockerObservation,
) -> bool {
    let direct_ready = probe_direct_egress(&state.running_containers);
    state.direct_egress_ready = Some(direct_ready);
    if !direct_ready {
        state
            .degraded_reasons
            .push("direct egress datapath probe failed".to_owned());
    }

    let warp_failure = probe_warp_egress_failure(&state.running_containers);
    state.warp_egress_ready = Some(warp_failure.is_none());
    if let Some(reason) = warp_failure {
        state.degraded_reasons.push(reason.to_owned());
    }

    let mesh_ready = if docker.container_present(MESH_CONTAINER) {
        let diagnostics =
            collect_mesh_runtime_diagnostics(docker, MeshDiagnosticDepth::Basic).await;
        let ready = mesh_runtime_diagnostics_ready(&diagnostics);
        if !ready {
            append_mesh_runtime_diagnostic_warnings(&diagnostics, &mut state.degraded_reasons);
        }
        Some(ready)
    } else {
        None
    };
    state.mesh_runtime_ready = mesh_ready;

    direct_ready && warp_failure.is_none() && mesh_ready != Some(false)
}

pub(super) fn wait_for_warp_datapath() -> Result<(), String> {
    for _ in 0..45 {
        if probe_warp_service_local() {
            return Ok(());
        }
        sleep(Duration::from_secs(2));
    }
    Err("WARP egress datapath did not become ready within 90 seconds".to_owned())
}

pub(super) fn runtime_probe_consumers(running_containers: &[String]) -> Vec<&'static str> {
    [LINE1_CONTAINER, LINE2_CONTAINER]
        .into_iter()
        .filter(|candidate| {
            running_containers
                .iter()
                .any(|running| running == candidate)
        })
        .collect()
}

pub(super) fn probe_direct_egress(running_containers: &[String]) -> bool {
    let consumers = runtime_probe_consumers(running_containers);
    !consumers.is_empty()
        && consumers.into_iter().all(|consumer| {
            bounded_command_output(
                "docker",
                &[
                    "exec",
                    consumer,
                    "curl",
                    "-4",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--connect-timeout",
                    "3",
                    "--max-time",
                    "8",
                    CLOUDFLARE_TRACE_URL,
                ],
                12,
            )
            .is_some_and(|output| cloudflare_trace_has_warp_mode(&output, "off"))
        })
}

pub(super) fn warp_client_connected() -> bool {
    bounded_command_output(
        "docker",
        &["exec", WARP_CONTAINER, "warp-cli", "--accept-tos", "status"],
        8,
    )
    .is_some_and(|output| output.lines().any(|line| line.contains("Connected")))
}

pub(super) fn probe_warp_service_local() -> bool {
    if !warp_client_connected() {
        return false;
    }
    bounded_command_output(
        "docker",
        &[
            "exec",
            WARP_CONTAINER,
            "curl",
            "-4",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            "--socks5-hostname",
            "127.0.0.1:11080",
            CLOUDFLARE_TRACE_URL,
        ],
        12,
    )
    .is_some_and(|output| {
        cloudflare_trace_has_warp_mode(&output, "on")
            || cloudflare_trace_has_warp_mode(&output, "plus")
    })
}

/// Same native WARP probe as before; now report the FIRST failed predicate
/// without duplicating probes or publishing curl/warp-cli stdout.
pub(super) fn probe_warp_egress_failure(
    running_containers: &[String],
) -> Option<&'static str> {
    if !warp_client_connected() {
        return Some("WARP client not connected");
    }
    let consumers = runtime_probe_consumers(running_containers);
    if consumers.is_empty() {
        return Some("WARP consumers absent");
    }
    for consumer in consumers {
        let ok = bounded_command_output(
            "docker",
            &[
                "exec",
                consumer,
                "curl",
                "-4",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "3",
                "--max-time",
                "8",
                "--socks5-hostname",
                "warp-egress:11080",
                CLOUDFLARE_TRACE_URL,
            ],
            12,
        )
        .is_some_and(|output| {
            cloudflare_trace_has_warp_mode(&output, "on")
                || cloudflare_trace_has_warp_mode(&output, "plus")
        });
        if !ok {
            return Some(match consumer {
                LINE1_CONTAINER => "WARP Line1 consumer egress failed",
                LINE2_CONTAINER => "WARP Line2 consumer egress failed",
                _ => "WARP consumer identity unproven",
            });
        }
    }
    None
}

pub(super) fn parse_warp_connection_state(probe: &BoundedCommandProbe) -> Option<String> {
    if !matches!(
        probe.status,
        RuntimeProbeStatus::Ok | RuntimeProbeStatus::NonZero
    ) {
        return None;
    }
    let lowered = probe.stdout.to_ascii_lowercase();
    if lowered
        .lines()
        .any(|line| line.contains("disconnected") || line.contains("not connected"))
    {
        Some("DISCONNECTED".to_owned())
    } else if lowered.lines().any(|line| line.contains("connecting")) {
        Some("CONNECTING".to_owned())
    } else if lowered.lines().any(|line| line.contains("connected")) {
        Some("CONNECTED".to_owned())
    } else if probe.status == RuntimeProbeStatus::Ok {
        Some("UNKNOWN".to_owned())
    } else {
        None
    }
}

pub(super) fn parse_tunnel_protocol(probe: &BoundedCommandProbe) -> Option<String> {
    if !matches!(
        probe.status,
        RuntimeProbeStatus::Ok | RuntimeProbeStatus::NonZero
    ) {
        return None;
    }
    let lowered = probe.stdout.to_ascii_lowercase();
    if lowered.contains("masque") {
        Some("MASQUE".to_owned())
    } else if lowered.contains("wireguard") {
        Some("WIREGUARD".to_owned())
    } else if probe.status == RuntimeProbeStatus::Ok {
        Some("NOT_REPORTED".to_owned())
    } else {
        None
    }
}

pub(super) fn parse_binary_bool_probe(probe: &mut BoundedCommandProbe) -> Option<bool> {
    if probe.status != RuntimeProbeStatus::Ok {
        return None;
    }
    match probe.stdout.trim() {
        "1" | "present" => Some(true),
        "0" | "absent" => Some(false),
        _ => {
            probe.status = RuntimeProbeStatus::ParseError;
            None
        }
    }
}

pub(super) fn mesh_warp_cli_probe_args(command: &'static str) -> [&'static str; 5] {
    ["exec", MESH_CONTAINER, "warp-cli", "--accept-tos", command]
}

pub(super) async fn collect_mesh_runtime_diagnostics(
    docker: &DockerObservation,
    diagnostic_depth: MeshDiagnosticDepth,
) -> MeshRuntimeDiagnostics {
    let warp_status_args = mesh_warp_cli_probe_args("status");
    let warp_status = bounded_command_probe("docker", &warp_status_args, 8, true);
    let warp_connection_state = parse_warp_connection_state(&warp_status);

    let warp_settings_args = mesh_warp_cli_probe_args("settings");
    let warp_settings = bounded_command_probe("docker", &warp_settings_args, 8, true);
    let tunnel_protocol = parse_tunnel_protocol(&warp_settings);

    let mut tun_device = bounded_command_probe(
        "docker",
        &[
            "exec",
            MESH_CONTAINER,
            "sh",
            "-c",
            "if [ -c /dev/net/tun ]; then printf present; else printf absent; fi",
        ],
        6,
        true,
    );
    let tun_device_present = parse_binary_bool_probe(&mut tun_device);

    let mut ipv4_forwarding = bounded_command_probe(
        "docker",
        &[
            "exec",
            MESH_CONTAINER,
            "cat",
            "/proc/sys/net/ipv4/ip_forward",
        ],
        6,
        true,
    );
    let ipv4_forwarding_value = parse_binary_bool_probe(&mut ipv4_forwarding);

    let capability_probe = bounded_command_probe(
        "docker",
        &[
            "inspect",
            "--format",
            "{{json .HostConfig.CapAdd}}",
            MESH_CONTAINER,
        ],
        6,
        true,
    );
    let (net_admin_present, net_raw_present) = if capability_probe.status == RuntimeProbeStatus::Ok
    {
        let upper = capability_probe.stdout.to_ascii_uppercase();
        (
            Some(upper.contains("NET_ADMIN")),
            Some(upper.contains("NET_RAW")),
        )
    } else {
        (None, None)
    };

    let container_evidence = observe_container_runtime(MESH_CONTAINER).await.ok();
    let route_events = container_evidence
        .as_ref()
        .map(|evidence| extract_route_events(&evidence.log_tail))
        .unwrap_or_default();
    let container = container_evidence.map(|evidence| MeshContainerDiagnostics {
        present: evidence.present,
        running: evidence.running,
        exit_code: evidence.exit_code,
        runtime_error_present: evidence.runtime_error.is_some(),
        recent_events: evidence.log_tail,
        name: evidence.name,
        image: evidence.image,
        restart_count: evidence.restart_count,
        oom_killed: evidence.oom_killed,
        networks: evidence.networks,
    });

    let (host_network, container_network, host) = match diagnostic_depth {
        MeshDiagnosticDepth::Basic => (None, None, None),
        MeshDiagnosticDepth::Deep => (
            Some(collect_host_network_diagnostics()),
            Some(collect_container_network_diagnostics(MESH_CONTAINER)),
            Some(collect_host_runtime_diagnostics()),
        ),
    };

    MeshRuntimeDiagnostics {
        warp_status_probe: Some(warp_status.diagnostic_evidence()),
        warp_connection_state,
        warp_settings_probe: Some(warp_settings.diagnostic_evidence()),
        tunnel_protocol,
        tun_device_probe: Some(tun_device.evidence()),
        tun_device_present,
        ipv4_forwarding_probe: Some(ipv4_forwarding.evidence()),
        ipv4_forwarding: ipv4_forwarding_value,
        mesh_network_attached: docker.container_on_mesh_network(MESH_CONTAINER),
        container,
        capability_probe: Some(capability_probe.evidence()),
        net_admin_present,
        net_raw_present,
        host_network,
        container_network,
        route_events,
        host,
    }
}

pub(super) fn mesh_runtime_diagnostics_ready(diagnostics: &MeshRuntimeDiagnostics) -> bool {
    diagnostics.warp_connection_state.as_deref() == Some("CONNECTED")
        && diagnostics.ipv4_forwarding == Some(true)
        && diagnostics.mesh_network_attached
}

pub(super) fn append_mesh_runtime_diagnostic_warnings(
    diagnostics: &MeshRuntimeDiagnostics,
    warnings: &mut Vec<String>,
) {
    match diagnostics.warp_connection_state.as_deref() {
        Some("CONNECTED") => {}
        Some(state) => warnings.push(format!("Mesh runtime connection state is {state}")),
        None => warnings.push("Mesh runtime connection state unavailable".to_owned()),
    }
    if diagnostics.ipv4_forwarding != Some(true) {
        warnings.push("Mesh runtime IPv4 forwarding is not enabled".to_owned());
    }
    if !diagnostics.mesh_network_attached {
        warnings
            .push("Mesh runtime container is not attached to the expected mesh network".to_owned());
    }
    if let Some(probe) = diagnostics.warp_status_probe.as_ref()
        && probe.status != RuntimeProbeStatus::Ok as i32
    {
        warnings.push(format!(
            "Mesh runtime WARP status probe failed: {}",
            runtime_probe_failure_summary(probe)
        ));
    }
    if let Some(probe) = diagnostics.warp_settings_probe.as_ref()
        && probe.status != RuntimeProbeStatus::Ok as i32
    {
        warnings.push(format!(
            "Mesh runtime WARP settings probe failed: {}",
            runtime_probe_failure_summary(probe)
        ));
    }
    if let Some(probe) = diagnostics.ipv4_forwarding_probe.as_ref()
        && probe.status != RuntimeProbeStatus::Ok as i32
    {
        warnings.push(format!(
            "Mesh runtime IPv4 forwarding probe failed: {}",
            runtime_probe_failure_summary(probe)
        ));
    }
}

pub(super) fn runtime_probe_failure_summary(probe: &RuntimeProbeEvidence) -> String {
    let mut details = Vec::new();
    if let Some(exit_code) = probe.exit_code {
        details.push(format!("exit_code={exit_code}"));
    }
    if let Some(stdout) = probe.diagnostic_stdout.as_deref() {
        details.push(format!("stdout={stdout:?}"));
    }
    if let Some(stderr) = probe.diagnostic_stderr.as_deref() {
        details.push(format!("stderr={stderr:?}"));
    }
    let status = runtime_probe_status_label(probe.status);
    if details.is_empty() {
        status.to_owned()
    } else {
        format!("{status} {}", details.join(" "))
    }
}

pub(super) fn runtime_probe_status_label(value: i32) -> &'static str {
    match RuntimeProbeStatus::try_from(value).unwrap_or(RuntimeProbeStatus::Unspecified) {
        RuntimeProbeStatus::Unspecified => "UNSPECIFIED",
        RuntimeProbeStatus::Ok => "OK",
        RuntimeProbeStatus::Timeout => "TIMEOUT",
        RuntimeProbeStatus::CommandNotFound => "COMMAND_NOT_FOUND",
        RuntimeProbeStatus::PermissionDenied => "PERMISSION_DENIED",
        RuntimeProbeStatus::Unsupported => "UNSUPPORTED",
        RuntimeProbeStatus::NonZero => "NON_ZERO",
        RuntimeProbeStatus::Empty => "EMPTY",
        RuntimeProbeStatus::ParseError => "PARSE_ERROR",
        RuntimeProbeStatus::OutputLimit => "OUTPUT_LIMIT",
    }
}

pub(super) fn mesh_tunnel_protocol_evidence_from_diagnostics(
    diagnostics: &MeshRuntimeDiagnostics,
) -> String {
    match diagnostics.tunnel_protocol.as_deref() {
        Some(protocol) => format!("Mesh runtime tunnel protocol evidence: {protocol}"),
        None => format!(
            "Mesh runtime tunnel protocol evidence unavailable: settings_probe={}",
            diagnostics
                .warp_settings_probe
                .as_ref()
                .map(|probe| runtime_probe_status_label(probe.status))
                .unwrap_or("UNSPECIFIED")
        ),
    }
}

pub(super) fn mesh_container_diagnostic_summary(evidence: &MeshContainerDiagnostics) -> String {
    let exit_code = evidence
        .exit_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let start = evidence.recent_events.len().saturating_sub(8);
    let logs = if evidence.recent_events.is_empty() {
        "none".to_owned()
    } else {
        evidence.recent_events[start..].join(" | ")
    };
    format!(
        "name={} present={} running={} exit_code={} restart_count={} oom_killed={} image={} networks={:?} runtime_error_present={} log_tail={}",
        evidence.name,
        evidence.present,
        evidence.running,
        exit_code,
        evidence
            .restart_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        evidence
            .oom_killed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        evidence.image.as_deref().unwrap_or("unknown"),
        evidence.networks,
        evidence.runtime_error_present,
        logs
    )
}

pub(super) fn bounded_container_runtime_summary(evidence: &ContainerRuntimeEvidence) -> String {
    let exit_code = evidence
        .exit_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let runtime_error = evidence.runtime_error.as_deref().unwrap_or("none");
    let start = evidence.log_tail.len().saturating_sub(8);
    let logs = if evidence.log_tail.is_empty() {
        "none".to_owned()
    } else {
        evidence.log_tail[start..].join(" | ")
    };
    format!(
        "present={} running={} exit_code={} runtime_error={} log_tail={}",
        evidence.present, evidence.running, exit_code, runtime_error, logs
    )
}

pub(super) fn bounded_command_output(
    program: &str,
    args: &[&str],
    timeout_seconds: u64,
) -> Option<String> {
    let timeout = format!("{timeout_seconds}s");
    let output = Command::new("timeout")
        .arg(timeout)
        .arg(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 16 * 1024 {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

pub(super) fn cloudflare_trace_has_warp_mode(raw: &str, expected: &str) -> bool {
    let mut warp = None;
    let mut ip_present = false;
    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "warp" if warp.is_none() => warp = Some(value),
            "warp" => return false,
            "ip" if !value.trim().is_empty() => ip_present = true,
            _ => {}
        }
    }
    ip_present && warp == Some(expected)
}
