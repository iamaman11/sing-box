use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::{
    BootstrapMode, BootstrapRuntimeRequest, BootstrapRuntimeResponse, ControllerStatus,
    DeployRequest, DeployResponse, DestroyRequest, DestroyResponse, Empty, GetOperationRequest,
    GetSecretRefRequest, GetSelectorStateRequest, GetTraceRequest, ListOperationEventsRequest,
    ListSecretRefsRequest, LocalRuntimeResponse, OperationStatus, RestartLocalRuntimeRequest,
    SecretRefEntry, SelectorState, SetSecretRefRequest, SetSelectorRequest, SetSelectorResponse,
    StartLocalRuntimeRequest, StopLocalRuntimeRequest, TraceObservation,
};
use tonic::Request;
use tonic::transport::Channel;

const DEFAULT_CONTROLLER_ENDPOINT: &str = "http://127.0.0.1:50051";

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
        "get-selector" => {
            let selector = fetch_selector_state(controller_endpoint_from_args(2)).await?;
            print_selector_state(&selector);
            Ok(())
        }
        "set-selector" => {
            let name = env::args()
                .nth(2)
                .ok_or("set-selector requires a selector target name")?;
            let response =
                set_selector(controller_endpoint_from_args(3), "proxy-selector", &name).await?;
            print_set_selector_result(&response);
            finish_selector_result(response)
        }
        "trace" => {
            let trace = fetch_trace(controller_endpoint_from_args(2)).await?;
            print_trace(&trace);
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
            let response = deploy(controller_endpoint_from_args(9), request).await?;
            print_deploy_result(&response);
            finish_deploy_result(response)
        }
        "destroy" => {
            let request = destroy_request_from_args();
            let response = destroy(controller_endpoint_from_args(7), request).await?;
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
        println!("8. Show current IP");
        println!("9. Start local runtime");
        println!("10. Stop local runtime");
        println!("11. Restart local runtime");
        println!("12. Bootstrap base runtime");
        println!("13. Bootstrap tunnel runtime");
        println!("14. Deploy bundle to target");
        println!("15. Destroy deployment state");
        println!("16. List configured secrets");
        println!("17. Show operation");
        println!("18. Watch operation");
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
                    "proxy-selector",
                    "auto-direct-tunnel",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "3" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    "proxy-selector",
                    "hysteria2-direct",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "4" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    "proxy-selector",
                    "vless-reality-direct",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "5" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    "proxy-selector",
                    "auto-warp-tunnel",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "6" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    "proxy-selector",
                    "hysteria2-warp",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "7" => {
                let response = set_selector(
                    controller_endpoint.clone(),
                    "proxy-selector",
                    "vless-reality-warp",
                )
                .await?;
                print_set_selector_result(&response);
            }
            "8" => {
                let trace = fetch_trace(controller_endpoint.clone()).await?;
                print_trace(&trace);
            }
            "9" => {
                let response = start_local(controller_endpoint.clone()).await?;
                print_local_runtime_result(&response);
            }
            "10" => {
                let response = stop_local(controller_endpoint.clone()).await?;
                print_local_runtime_result(&response);
            }
            "11" => {
                let response = restart_local(controller_endpoint.clone()).await?;
                print_local_runtime_result(&response);
            }
            "12" => {
                let response =
                    bootstrap_runtime(controller_endpoint.clone(), BootstrapMode::BootstrapBase)
                        .await?;
                print_bootstrap_result(&response);
            }
            "13" => {
                let response =
                    bootstrap_runtime(controller_endpoint.clone(), BootstrapMode::BootstrapTunnel)
                        .await?;
                print_bootstrap_result(&response);
            }
            "14" => {
                let target_ip = prompt("Target IP")?;
                let tunnel_domain = prompt("Tunnel domain (blank to skip)")?;
                let acme_email = prompt("ACME email (blank to skip)")?;
                let response = deploy(
                    controller_endpoint.clone(),
                    DeployRequest {
                        label_prefix: None,
                        target_ip: if target_ip.trim().is_empty() {
                            None
                        } else {
                            Some(target_ip)
                        },
                        instance_id: None,
                        tunnel_domain: if tunnel_domain.trim().is_empty() {
                            None
                        } else {
                            Some(tunnel_domain)
                        },
                        acme_email: if acme_email.trim().is_empty() {
                            None
                        } else {
                            Some(acme_email)
                        },
                        dns_record_name: None,
                        cloudflare_zone_name: None,
                        mock_provider: false,
                        skip_dns: false,
                    },
                )
                .await?;
                print_deploy_result(&response);
            }
            "15" => {
                let response = destroy(
                    controller_endpoint.clone(),
                    DestroyRequest {
                        instance_id: None,
                        target_ip: None,
                        dns_record_name: None,
                        cloudflare_zone_name: None,
                        mock_provider: false,
                        delete_dns: true,
                        delete_instance: false,
                    },
                )
                .await?;
                print_destroy_result(&response);
            }
            "16" => {
                let secrets = list_secret_refs(controller_endpoint.clone()).await?;
                print_secret_refs(&secrets);
            }
            "17" => {
                let operation_id = prompt("Operation id")?;
                let status =
                    get_operation(controller_endpoint.clone(), operation_id.parse()?).await?;
                print_operation_status(&status);
            }
            "18" => {
                let operation_id = prompt("Operation id")?;
                watch_operation(controller_endpoint.clone(), operation_id.parse()?).await?;
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

fn deploy_request_from_args() -> DeployRequest {
    DeployRequest {
        label_prefix: env::args().nth(2),
        target_ip: env::args().nth(3),
        instance_id: env::args().nth(4),
        tunnel_domain: env::args().nth(5),
        acme_email: env::args().nth(6),
        dns_record_name: env::args().nth(7),
        cloudflare_zone_name: env::args().nth(8),
        mock_provider: env::var("EDGE_MOCK_PROVIDER")
            .ok()
            .is_some_and(|value| value == "1"),
        skip_dns: env::var("EDGE_SKIP_DNS")
            .ok()
            .is_some_and(|value| value == "1"),
    }
}

fn destroy_request_from_args() -> DestroyRequest {
    DestroyRequest {
        instance_id: env::args().nth(2),
        target_ip: env::args().nth(3),
        dns_record_name: env::args().nth(4),
        cloudflare_zone_name: env::args().nth(5),
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
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client.get_status(Request::new(Empty {})).await?;
    Ok(response.into_inner())
}

async fn list_secret_refs(
    endpoint: String,
) -> Result<Vec<SecretRefEntry>, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .list_secret_refs(Request::new(ListSecretRefsRequest {}))
        .await?;
    Ok(response.into_inner().secrets)
}

async fn get_secret_ref(
    endpoint: String,
    name: &str,
) -> Result<SecretRefEntry, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
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
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
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
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .bootstrap_runtime(Request::new(BootstrapRuntimeRequest { mode: mode as i32 }))
        .await?;
    Ok(response.into_inner())
}

async fn start_local(endpoint: String) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .start_local_runtime(Request::new(StartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            force_restart: false,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn stop_local(endpoint: String) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
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
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .restart_local_runtime(Request::new(RestartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
        }))
        .await?;
    Ok(response.into_inner())
}

async fn fetch_selector_state(
    endpoint: String,
) -> Result<SelectorState, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .get_selector_state(Request::new(GetSelectorStateRequest { group: None }))
        .await?;
    Ok(response.into_inner())
}

async fn set_selector(
    endpoint: String,
    group: &str,
    name: &str,
) -> Result<SetSelectorResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .set_selector(Request::new(SetSelectorRequest {
            group: group.to_owned(),
            name: name.to_owned(),
        }))
        .await?;
    Ok(response.into_inner())
}

async fn fetch_trace(endpoint: String) -> Result<TraceObservation, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .get_trace(Request::new(GetTraceRequest { proxy_url: None }))
        .await?;
    Ok(response.into_inner())
}

async fn deploy(
    endpoint: String,
    request: DeployRequest,
) -> Result<DeployResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client.deploy(Request::new(request)).await?;
    Ok(response.into_inner())
}

async fn destroy(
    endpoint: String,
    request: DestroyRequest,
) -> Result<DestroyResponse, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client.destroy(Request::new(request)).await?;
    Ok(response.into_inner())
}

async fn get_operation(
    endpoint: String,
    operation_id: i64,
) -> Result<OperationStatus, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client
        .get_operation(Request::new(GetOperationRequest { operation_id }))
        .await?;
    Ok(response.into_inner())
}

async fn list_operation_events(
    endpoint: String,
    operation_id: i64,
) -> Result<Vec<edge_shared_types::OperationEvent>, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
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
        print_selector_state(selector);
    }

    for note in &status.status_notes {
        println!("Status note            : {note}");
    }
}

fn print_selector_state(selector: &SelectorState) {
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

fn print_trace(trace: &TraceObservation) {
    println!();
    if trace.available {
        if let Some(ip) = &trace.ip {
            println!("Current tunnel IP      : {ip}");
        }
        if let Some(warp) = &trace.warp {
            println!("Current tunnel WARP    : {warp}");
        }
        if let Some(colo) = &trace.colo {
            println!("Current tunnel colo    : {colo}");
        }
    } else {
        println!(
            "Current tunnel note    : {}",
            trace.note.as_deref().unwrap_or("trace unavailable")
        );
    }
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
}
