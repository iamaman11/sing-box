use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::{
    BootstrapMode, BootstrapRuntimeRequest, BootstrapRuntimeResponse, ControllerStatus, Empty,
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
        "bootstrap-base" => {
            let response = bootstrap_runtime(
                controller_endpoint_from_args(2),
                BootstrapMode::BootstrapBase,
            )
            .await?;
            print_bootstrap_result(&response);
            if response.success {
                Ok(())
            } else {
                Err(format_bootstrap_failure(&response).into())
            }
        }
        "bootstrap-tunnel" => {
            let response = bootstrap_runtime(
                controller_endpoint_from_args(2),
                BootstrapMode::BootstrapTunnel,
            )
            .await?;
            print_bootstrap_result(&response);
            if response.success {
                Ok(())
            } else {
                Err(format_bootstrap_failure(&response).into())
            }
        }
        other => Err(format!("unsupported command: {other}").into()),
    }
}

async fn run_menu(controller_endpoint: String) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!();
        println!("Edge Console");
        println!("1. Status");
        println!("2. Bootstrap base runtime");
        println!("3. Bootstrap tunnel runtime");
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
                let response =
                    bootstrap_runtime(controller_endpoint.clone(), BootstrapMode::BootstrapBase)
                        .await?;
                print_bootstrap_result(&response);
            }
            "3" => {
                let response =
                    bootstrap_runtime(controller_endpoint.clone(), BootstrapMode::BootstrapTunnel)
                        .await?;
                print_bootstrap_result(&response);
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

async fn fetch_status(endpoint: String) -> Result<ControllerStatus, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client.get_status(Request::new(Empty {})).await?;
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
        for warning in &selector.warnings {
            println!("Selector warning       : {warning}");
        }
    }

    for note in &status.status_notes {
        println!("Status note            : {note}");
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

fn bootstrap_mode_label(mode: i32) -> &'static str {
    match BootstrapMode::try_from(mode) {
        Ok(BootstrapMode::BootstrapBase) => "base",
        Ok(BootstrapMode::BootstrapTunnel) => "tunnel",
        Ok(BootstrapMode::BootstrapFull) => "full",
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
}
