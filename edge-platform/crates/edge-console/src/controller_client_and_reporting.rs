use super::*;

pub(super) async fn connect_controller(
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

pub(super) async fn fetch_status(
    endpoint: String,
) -> Result<ControllerStatus, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client.get_status(Request::new(Empty {})).await?;
    Ok(response.into_inner())
}

pub(super) async fn fetch_credential_state(
    endpoint: String,
) -> Result<Option<edge_shared_types::LocalCredentialState>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    Ok(client
        .get_credential_state(Request::new(Empty {}))
        .await?
        .into_inner()
        .state)
}

pub(super) async fn fetch_doctor(
    endpoint: String,
) -> Result<DoctorResponse, Box<dyn std::error::Error>> {
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

pub(super) async fn list_secret_refs(
    endpoint: String,
) -> Result<Vec<SecretRefEntry>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .list_secret_refs(Request::new(ListSecretRefsRequest {}))
        .await?;
    Ok(response.into_inner().secrets)
}

pub(super) async fn get_secret_ref(
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

pub(super) async fn set_secret_ref(
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

pub(super) async fn start_local(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
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

pub(super) async fn start_local_visible(
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

pub(super) async fn stop_local(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .stop_local_runtime(Request::new(StopLocalRuntimeRequest {
            config_path: None,
            expected_config_only: true,
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn restart_local(
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

pub(super) async fn restart_local_visible(
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

pub(super) async fn fetch_selector_state(
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

pub(super) async fn set_selector(
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

pub(super) async fn fetch_trace(
    endpoint: String,
) -> Result<TraceObservation, Box<dyn std::error::Error>> {
    fetch_trace_with_proxy(endpoint, None).await
}

pub(super) async fn fetch_trace_with_proxy(
    endpoint: String,
    proxy_url: Option<String>,
) -> Result<TraceObservation, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_trace(Request::new(GetTraceRequest { proxy_url }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn get_operation(
    endpoint: String,
    operation_id: i64,
) -> Result<OperationStatus, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_operation(Request::new(GetOperationRequest { operation_id }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn list_operation_events(
    endpoint: String,
    operation_id: i64,
) -> Result<Vec<edge_shared_types::OperationEvent>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .list_operation_events(Request::new(ListOperationEventsRequest { operation_id }))
        .await?;
    Ok(response.into_inner().events)
}

pub(super) async fn watch_operation(
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

pub(super) fn print_status(status: &ControllerStatus) {
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

pub(super) fn print_windows_credential_state(
    state: Option<&edge_shared_types::LocalCredentialState>,
) {
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

pub(super) fn print_lifecycle_status() {
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

pub(super) fn print_doctor(doctor: &DoctorResponse) {
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

pub(super) fn print_selector_state(selector: &SelectorState) {
    print_selector_state_with_label("Selector", selector);
}

pub(super) fn print_selector_state_with_label(label: &str, selector: &SelectorState) {
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

pub(super) fn print_ubuntu_proxy_state(proxy: &UbuntuProxyState) {
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

pub(super) fn print_trace(trace: &TraceObservation) {
    print_trace_with_label("Current tunnel", trace);
}

pub(super) fn print_trace_with_label(label: &str, trace: &TraceObservation) {
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

pub(super) fn ubuntu_proxy_url_from_status(status: &ControllerStatus) -> Option<String> {
    status
        .ubuntu_proxy
        .as_ref()
        .and_then(|proxy| proxy.url.clone())
}

pub(super) fn app_readiness_label(value: i32) -> &'static str {
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

pub(super) fn print_secret_refs(entries: &[SecretRefEntry]) {
    println!();
    println!("Configured secrets");
    for entry in entries {
        println!("{:<32} {}", entry.name, entry.secret_ref);
    }
}

pub(super) fn print_secret_ref(entry: &SecretRefEntry) {
    println!();
    println!("Secret name           : {}", entry.name);
    println!("Secret reference      : {}", entry.secret_ref);
}

pub(super) fn print_local_runtime_result(response: &LocalRuntimeResponse) {
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

pub(super) fn print_set_selector_result(response: &SetSelectorResponse) {
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

pub(super) fn print_operation_status(status: &OperationStatus) {
    println!();
    print_operation_summary(status);
    for event in &status.recent_events {
        println!("[{}] {}", event.id, event.message);
    }
}

pub(super) fn print_operation_summary(status: &OperationStatus) {
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

pub(super) fn lifecycle_status_label(status: i32) -> &'static str {
    match edge_shared_types::OperationLifecycleStatus::try_from(status) {
        Ok(edge_shared_types::OperationLifecycleStatus::Requested) => "requested",
        Ok(edge_shared_types::OperationLifecycleStatus::Running) => "running",
        Ok(edge_shared_types::OperationLifecycleStatus::Succeeded) => "succeeded",
        Ok(edge_shared_types::OperationLifecycleStatus::Failed) => "failed",
        _ => "unknown",
    }
}

pub(super) fn join_ports(ports: &[u32]) -> String {
    ports
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn finish_local_result(
    response: LocalRuntimeResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    if response.success {
        Ok(())
    } else {
        Err(response.note.into())
    }
}

pub(super) fn finish_selector_result(
    response: SetSelectorResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    if response.success {
        Ok(())
    } else {
        Err("selector update failed".into())
    }
}
