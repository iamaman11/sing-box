use crate::application_lifecycle_command::resolve_application_authority_from_spec;
use crate::application_lifecycle_service::{
    cleanup_mesh_runtime_remote, converge_mesh_runtime_remote, observe_ipv4_network_remote,
    verify_mesh_runtime_remote,
};
use crate::cloudflare_mesh_lifecycle_service::{
    CloudflareMeshApiProvider, MeshExecutionPolicy, apply_mesh_once, authorize_mesh_apply,
    authorize_mesh_cleanup, cleanup_mesh_once, exact_mesh_node_token, observe_mesh,
    plan_mesh_apply, plan_mesh_cleanup, wait_mesh_provider_healthy,
};
use crate::vultr_vpc_lifecycle_service::{VpcReadyReport, VultrVpcApiProvider, verify_vpc_ready};
use edge_controller_core::cloudflare_mesh_lifecycle::{
    DesiredMeshState, MeshObservation, MeshRouteSpec,
};
use edge_controller_core::vultr_vpc_lifecycle::DesiredVpcState;
use edge_shared_types::Ipv4NetworkObservation;
use serde::Serialize;
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or_else(usage)?;
    match command {
        "inventory" => run_inventory(&args[1..]).await,
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "vpc-plan" => run_vpc_plan(&args[1..]).await,
        "vpc-apply" => run_vpc_apply(&args[1..]).await,
        "cleanup-plan" => run_cleanup_plan(&args[1..]).await,
        "cleanup-apply" => run_cleanup_apply(&args[1..]).await,
        "runtime-apply" => run_runtime_apply(&args[1..]).await,
        "vpc-runtime-apply" => run_vpc_runtime_apply(&args[1..]).await,
        "runtime-verify" => run_runtime_verify(&args[1..]).await,
        "vpc-runtime-verify" => run_vpc_runtime_verify(&args[1..]).await,
        "runtime-cleanup" => run_runtime_cleanup(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_inventory(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-orchestrator line3-mesh inventory <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let observed = observe_mesh(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "desired": desired,
        "observation": observed,
    }))
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-orchestrator line3-mesh plan <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_mesh_apply(&mut provider, &desired).await?;
    let authorized = authorize_mesh_apply(&desired, &observed, plan.clone())?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator line3-mesh apply <spec-path> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let report = apply_mesh_once(
        &mut provider,
        &desired,
        &args[1],
        MeshExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_vpc_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator line3-mesh vpc-plan <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
                .to_owned(),
        );
    }
    let (desired, guest_vpc) = load_desired_with_verified_vpc_route(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )
    .await?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_mesh_apply(&mut provider, &desired).await?;
    let authorized = authorize_mesh_apply(&desired, &observed, plan.clone())?;
    print_json(serde_json::json!({
        "guest_vpc": guest_vpc,
        "observation": observed,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
    }))
}

async fn run_vpc_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err(
            "usage: edge-orchestrator line3-mesh vpc-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let (desired, guest_vpc) = load_desired_with_verified_vpc_route(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )
    .await?;
    let mut provider = provider_from_env(&desired)?;
    let report = apply_mesh_once(
        &mut provider,
        &desired,
        &args[3],
        MeshExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::json!({
        "guest_vpc": guest_vpc,
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_cleanup_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-orchestrator line3-mesh cleanup-plan <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_mesh_cleanup(&mut provider, &desired).await?;
    let authorized = authorize_mesh_cleanup(&desired, &observed, plan.clone())?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
    }))
}

async fn run_cleanup_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator line3-mesh cleanup-apply <spec-path> <destructive-digest> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let report = cleanup_mesh_once(
        &mut provider,
        &desired,
        &args[1],
        &args[2],
        MeshExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_runtime_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator line3-mesh runtime-apply <mesh-spec-path> <application-spec-path>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    run_runtime_apply_with_desired(desired, Path::new(&args[1])).await
}

async fn run_vpc_runtime_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator line3-mesh vpc-runtime-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
                .to_owned(),
        );
    }
    let (desired, _guest_vpc) = load_desired_with_verified_vpc_route(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )
    .await?;
    run_runtime_apply_with_desired(desired, Path::new(&args[2])).await
}

async fn run_runtime_apply_with_desired(
    desired: DesiredMeshState,
    application_spec: &Path,
) -> Result<(), String> {
    let mut provider = provider_from_env(&desired)?;
    let node_token = exact_mesh_node_token(&mut provider, &desired).await?;
    let authority = resolve_application_authority_from_spec(application_spec).await?;
    let state = converge_mesh_runtime_remote(&authority, node_token).await?;
    if !state.runtime_ready {
        let provider_summary = observe_mesh(&mut provider, &desired)
            .await
            .map(|observation| mesh_observation_summary(&observation))
            .unwrap_or_else(|err| {
                format!(
                    "provider_observation_error={}",
                    err.chars().take(512).collect::<String>()
                )
            });
        return Err(format!(
            "Mesh runtime convergence completed without READY: {}; diagnostics={}; {}",
            state.warnings.join("; "),
            mesh_runtime_diagnostic_summary(&state),
            provider_summary
        ));
    }
    let provider_observation =
        wait_mesh_provider_healthy(&mut provider, &desired, MeshExecutionPolicy::default()).await?;
    print_mesh_runtime_result("READY", &state, Some(provider_observation))
}

async fn run_runtime_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator line3-mesh runtime-verify <mesh-spec-path> <application-spec-path>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    run_runtime_verify_with_desired(desired, Path::new(&args[1])).await
}

async fn run_vpc_runtime_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator line3-mesh vpc-runtime-verify <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
                .to_owned(),
        );
    }
    let (desired, _guest_vpc) = load_desired_with_verified_vpc_route(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )
    .await?;
    run_runtime_verify_with_desired(desired, Path::new(&args[2])).await
}

async fn run_runtime_verify_with_desired(
    desired: DesiredMeshState,
    application_spec: &Path,
) -> Result<(), String> {
    let mut provider = provider_from_env(&desired)?;
    let provider_observation =
        wait_mesh_provider_healthy(&mut provider, &desired, MeshExecutionPolicy::default()).await?;
    let authority = resolve_application_authority_from_spec(application_spec).await?;
    let state = verify_mesh_runtime_remote(&authority).await?;
    if !state.runtime_ready {
        return Err(format!(
            "Mesh runtime verify did not observe READY: {}; diagnostics={}; {}",
            state.warnings.join("; "),
            mesh_runtime_diagnostic_summary(&state),
            mesh_observation_summary(&provider_observation)
        ));
    }
    print_mesh_runtime_result("PASS", &state, Some(provider_observation))
}

async fn run_runtime_cleanup(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err(
            "usage: edge-orchestrator line3-mesh runtime-cleanup <application-spec-path>"
                .to_owned(),
        );
    }
    let authority = resolve_application_authority_from_spec(Path::new(&args[0])).await?;
    let state = cleanup_mesh_runtime_remote(&authority).await?;
    if state.token_store_present || state.container_running {
        return Err("Mesh runtime cleanup did not observe exact absence".to_owned());
    }
    print_mesh_runtime_result("ABSENT", &state, None)
}

fn mesh_observation_summary(observation: &MeshObservation) -> String {
    let statuses = if observation.nodes.is_empty() {
        "none".to_owned()
    } else {
        observation
            .nodes
            .iter()
            .map(|node| node.status.as_deref().unwrap_or("unknown"))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "provider_nodes={} provider_routes={} provider_statuses=[{}]",
        observation.nodes.len(),
        observation.routes.len(),
        statuses
    )
}

fn print_mesh_runtime_result(
    status: &str,
    state: &edge_shared_types::MeshRuntimeState,
    provider_observation: Option<edge_controller_core::cloudflare_mesh_lifecycle::MeshObservation>,
) -> Result<(), String> {
    print_json(serde_json::json!({
        "status": status,
        "runtime": {
            "token_store_present": state.token_store_present,
            "container_running": state.container_running,
            "exact_image_ready": state.exact_image_ready,
            "runtime_ready": state.runtime_ready,
            "warnings": state.warnings,
            "diagnostics": mesh_runtime_diagnostics_json(state.diagnostics.as_ref()),
            "last_failure_snapshot": mesh_runtime_failure_snapshot_json(state.last_failure_snapshot.as_ref()),
        },
        "provider_observation": provider_observation,
    }))
}

fn runtime_probe_status_name(value: i32) -> &'static str {
    match value {
        1 => "OK",
        2 => "TIMEOUT",
        3 => "COMMAND_NOT_FOUND",
        4 => "PERMISSION_DENIED",
        5 => "UNSUPPORTED",
        6 => "NON_ZERO",
        7 => "EMPTY",
        8 => "PARSE_ERROR",
        9 => "OUTPUT_LIMIT",
        _ => "UNSPECIFIED",
    }
}

fn runtime_probe_json(
    probe: Option<&edge_shared_types::RuntimeProbeEvidence>,
) -> serde_json::Value {
    match probe {
        Some(probe) => serde_json::json!({
            "status": runtime_probe_status_name(probe.status),
            "exit_code": probe.exit_code,
            "diagnostic_stdout": probe.diagnostic_stdout,
            "diagnostic_stderr": probe.diagnostic_stderr,
        }),
        None => serde_json::json!({
            "status": "UNSPECIFIED",
            "exit_code": null,
        }),
    }
}

fn runtime_network_diagnostics_json(
    diagnostics: Option<&edge_shared_types::RuntimeNetworkDiagnostics>,
) -> serde_json::Value {
    let Some(diagnostics) = diagnostics else {
        return serde_json::Value::Null;
    };
    let dns = diagnostics.dns.as_ref().map(|dns| {
        serde_json::json!({
            "probe": runtime_probe_json(dns.probe.as_ref()),
            "nameservers": dns.nameservers,
            "search_domains": dns.search_domains,
        })
    });
    serde_json::json!({
        "interfaces_probe": runtime_probe_json(diagnostics.interfaces_probe.as_ref()),
        "interfaces": diagnostics.interfaces.iter().map(|interface| {
            serde_json::json!({
                "name": interface.name,
                "mtu": interface.mtu,
                "up": interface.up,
                "addresses": interface.addresses,
            })
        }).collect::<Vec<_>>(),
        "routes_probe": runtime_probe_json(diagnostics.routes_probe.as_ref()),
        "routes": diagnostics.routes.iter().map(|route| {
            serde_json::json!({
                "destination": route.destination,
                "gateway": route.gateway,
                "device": route.device,
                "preferred_source": route.preferred_source,
                "metric": route.metric,
                "table": route.table,
                "protocol": route.protocol,
            })
        }).collect::<Vec<_>>(),
        "rules_probe": runtime_probe_json(diagnostics.rules_probe.as_ref()),
        "rules": diagnostics.rules.iter().map(|rule| {
            serde_json::json!({
                "priority": rule.priority,
                "source": rule.source,
                "destination": rule.destination,
                "table": rule.table,
            })
        }).collect::<Vec<_>>(),
        "dns": dns,
        "sockets_probe": runtime_probe_json(diagnostics.sockets_probe.as_ref()),
        "sockets": diagnostics.sockets.iter().map(|socket| {
            serde_json::json!({
                "protocol": socket.protocol,
                "local_address": socket.local_address,
                "local_port": socket.local_port,
                "remote_address": socket.remote_address,
                "remote_port": socket.remote_port,
                "state": socket.state,
            })
        }).collect::<Vec<_>>(),
        "default_route_present": diagnostics.default_route_present_observed,
    })
}

fn runtime_network_summary_json(
    diagnostics: Option<&edge_shared_types::RuntimeNetworkDiagnostics>,
) -> serde_json::Value {
    let Some(diagnostics) = diagnostics else {
        return serde_json::Value::Null;
    };
    let interfaces = diagnostics
        .interfaces
        .iter()
        .take(16)
        .map(|interface| {
            serde_json::json!({
                "name": interface.name,
                "mtu": interface.mtu,
                "up": interface.up,
                "addresses": interface.addresses,
            })
        })
        .collect::<Vec<_>>();
    let routes = diagnostics
        .routes
        .iter()
        .filter(|route| {
            route.destination == "default"
                || route.destination.starts_with("10.")
                || route.destination.starts_with("172.")
                || route.destination.starts_with("192.168.")
        })
        .take(32)
        .map(|route| {
            serde_json::json!({
                "destination": route.destination,
                "gateway": route.gateway,
                "device": route.device,
                "preferred_source": route.preferred_source,
                "metric": route.metric,
                "table": route.table,
                "protocol": route.protocol,
            })
        })
        .collect::<Vec<_>>();
    let remote_sockets = diagnostics
        .sockets
        .iter()
        .filter(|socket| {
            socket
                .remote_address
                .as_deref()
                .is_some_and(|value| value != "0.0.0.0" && value != "::" && value != "*")
        })
        .take(24)
        .map(|socket| {
            serde_json::json!({
                "protocol": socket.protocol,
                "remote_address": socket.remote_address,
                "remote_port": socket.remote_port,
                "state": socket.state,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "interfaces_probe": runtime_probe_json(diagnostics.interfaces_probe.as_ref()),
        "routes_probe": runtime_probe_json(diagnostics.routes_probe.as_ref()),
        "rules_probe": runtime_probe_json(diagnostics.rules_probe.as_ref()),
        "sockets_probe": runtime_probe_json(diagnostics.sockets_probe.as_ref()),
        "default_route_present": diagnostics.default_route_present_observed,
        "interfaces": interfaces,
        "routes": routes,
        "dns": diagnostics.dns.as_ref().map(|dns| serde_json::json!({
            "probe": runtime_probe_json(dns.probe.as_ref()),
            "nameservers": dns.nameservers,
            "search_domains": dns.search_domains,
        })),
        "remote_sockets": remote_sockets,
    })
}

fn host_runtime_diagnostics_json(
    diagnostics: Option<&edge_shared_types::HostRuntimeDiagnostics>,
) -> serde_json::Value {
    let Some(diagnostics) = diagnostics else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "identity": diagnostics.identity.as_ref().map(|identity| serde_json::json!({
            "probe": runtime_probe_json(identity.probe.as_ref()),
            "hostname": identity.hostname,
            "kernel_release": identity.kernel_release,
            "architecture": identity.architecture,
        })),
        "time": diagnostics.time.as_ref().map(|time| serde_json::json!({
            "probe": runtime_probe_json(time.probe.as_ref()),
            "unix_time_seconds": time.unix_time_seconds,
            "uptime_seconds": time.uptime_seconds,
        })),
        "resources": diagnostics.resources.as_ref().map(|resources| serde_json::json!({
            "probe": runtime_probe_json(resources.probe.as_ref()),
            "logical_cpus": resources.logical_cpus,
            "load_1": resources.load_1,
            "load_5": resources.load_5,
            "load_15": resources.load_15,
            "memory_total_bytes": resources.memory_total_bytes,
            "memory_available_bytes": resources.memory_available_bytes,
        })),
    })
}

fn mesh_runtime_failure_snapshot_json(
    snapshot: Option<&edge_shared_types::MeshRuntimeFailureSnapshot>,
) -> serde_json::Value {
    let Some(snapshot) = snapshot else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "observed_unix_time_seconds": snapshot.observed_unix_time_seconds,
        "reasons": snapshot.reasons,
        "warp_connection_state": snapshot.warp_connection_state,
        "tunnel_protocol": snapshot.tunnel_protocol,
        "warp_status": runtime_probe_status_name(snapshot.warp_status),
        "warp_settings": runtime_probe_status_name(snapshot.warp_settings),
        "tun_device_status": runtime_probe_status_name(snapshot.tun_device_status),
        "ipv4_forwarding_status": runtime_probe_status_name(snapshot.ipv4_forwarding_status),
        "container_present": snapshot.container_present,
        "container_running": snapshot.container_running,
        "container_exit_code": snapshot.container_exit_code,
        "container_restart_count": snapshot.container_restart_count,
        "container_oom_killed": snapshot.container_oom_killed,
        "container_image": snapshot.container_image,
        "container_networks": snapshot.container_networks,
        "exact_image_ready": snapshot.exact_image_ready,
    })
}

fn mesh_runtime_diagnostics_json(
    diagnostics: Option<&edge_shared_types::MeshRuntimeDiagnostics>,
) -> serde_json::Value {
    let Some(diagnostics) = diagnostics else {
        return serde_json::Value::Null;
    };
    let container = diagnostics.container.as_ref().map(|container| {
        serde_json::json!({
            "present": container.present,
            "running": container.running,
            "exit_code": container.exit_code,
            "runtime_error_present": container.runtime_error_present,
            "recent_events": container.recent_events,
            "name": container.name,
            "image": container.image,
            "restart_count": container.restart_count,
            "oom_killed": container.oom_killed,
            "networks": container.networks,
        })
    });
    serde_json::json!({
        "warp_status_probe": runtime_probe_json(diagnostics.warp_status_probe.as_ref()),
        "warp_connection_state": diagnostics.warp_connection_state,
        "warp_settings_probe": runtime_probe_json(diagnostics.warp_settings_probe.as_ref()),
        "tunnel_protocol": diagnostics.tunnel_protocol,
        "tun_device_probe": runtime_probe_json(diagnostics.tun_device_probe.as_ref()),
        "tun_device_present": diagnostics.tun_device_present,
        "ipv4_forwarding_probe": runtime_probe_json(diagnostics.ipv4_forwarding_probe.as_ref()),
        "ipv4_forwarding": diagnostics.ipv4_forwarding,
        "mesh_network_attached": diagnostics.mesh_network_attached,
        "capability_probe": runtime_probe_json(diagnostics.capability_probe.as_ref()),
        "net_admin_present": diagnostics.net_admin_present,
        "net_raw_present": diagnostics.net_raw_present,
        "container": container,
        "host_network": runtime_network_diagnostics_json(diagnostics.host_network.as_ref()),
        "container_network": runtime_network_diagnostics_json(diagnostics.container_network.as_ref()),
        "host": host_runtime_diagnostics_json(diagnostics.host.as_ref()),
        "route_churn_aggregates": diagnostics.route_events.iter().map(|event| serde_json::json!({
            "changed_count": event.changed_count,
            "window": event.window,
            "aggregate_counter_only": event.aggregate_counter_only,
        })).collect::<Vec<_>>(),
    })
}

fn mesh_runtime_diagnostic_summary(state: &edge_shared_types::MeshRuntimeState) -> String {
    let Some(diagnostics) = state.diagnostics.as_ref() else {
        return "absent".to_owned();
    };
    let recent_events = diagnostics
        .container
        .as_ref()
        .map(|container| {
            let start = container.recent_events.len().saturating_sub(8);
            container.recent_events[start..].to_vec()
        })
        .unwrap_or_default();
    serde_json::json!({
        "warp_status_probe": runtime_probe_json(diagnostics.warp_status_probe.as_ref()),
        "warp_connection_state": diagnostics.warp_connection_state,
        "warp_settings_probe": runtime_probe_json(diagnostics.warp_settings_probe.as_ref()),
        "tunnel_protocol": diagnostics.tunnel_protocol,
        "tun_device_probe": runtime_probe_json(diagnostics.tun_device_probe.as_ref()),
        "tun_device_present": diagnostics.tun_device_present,
        "ipv4_forwarding_probe": runtime_probe_json(diagnostics.ipv4_forwarding_probe.as_ref()),
        "ipv4_forwarding": diagnostics.ipv4_forwarding,
        "mesh_network_attached": diagnostics.mesh_network_attached,
        "capability_probe": runtime_probe_json(diagnostics.capability_probe.as_ref()),
        "net_admin_present": diagnostics.net_admin_present,
        "net_raw_present": diagnostics.net_raw_present,
        "recent_events": recent_events,
        "container": diagnostics.container.as_ref().map(|container| serde_json::json!({
            "present": container.present,
            "running": container.running,
            "exit_code": container.exit_code,
            "runtime_error_present": container.runtime_error_present,
            "name": container.name,
            "image": container.image,
            "restart_count": container.restart_count,
            "oom_killed": container.oom_killed,
            "networks": container.networks,
        })),
        "host": host_runtime_diagnostics_json(diagnostics.host.as_ref()),
        "last_failure_snapshot": mesh_runtime_failure_snapshot_json(state.last_failure_snapshot.as_ref()),
        "host_network": runtime_network_summary_json(diagnostics.host_network.as_ref()),
        "container_network": runtime_network_summary_json(diagnostics.container_network.as_ref()),
        "route_churn_aggregates": diagnostics.route_events.iter().map(|event| serde_json::json!({
            "changed_count": event.changed_count,
            "window": event.window,
            "aggregate_counter_only": event.aggregate_counter_only,
        })).collect::<Vec<_>>(),
    })
    .to_string()
}

fn load_desired(path: &Path) -> Result<DesiredMeshState, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Cloudflare Mesh spec {}: {err}",
            path.display()
        )
    })?;
    DesiredMeshState::parse_json(&raw).map_err(|err| err.to_string())
}

fn load_vpc_desired(path: &Path) -> Result<DesiredVpcState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read Vultr VPC spec {}: {err}", path.display()))?;
    DesiredVpcState::parse_json(&raw).map_err(|err| err.to_string())
}

async fn load_desired_with_verified_vpc_route(
    mesh_base_path: &Path,
    vpc_spec_path: &Path,
    application_spec_path: &Path,
) -> Result<(DesiredMeshState, GuestVpcNetworkReport), String> {
    let mesh_base = load_desired(mesh_base_path)?;
    let vpc = load_vpc_desired(vpc_spec_path)?;
    let api_key = env::var("VULTR_API_KEY").map_err(|_| "VULTR_API_KEY is required".to_owned())?;
    let mut provider = VultrVpcApiProvider::new(api_key)?;
    let ready = verify_vpc_ready(&mut provider, &vpc).await?;
    let authority = resolve_application_authority_from_spec(application_spec_path).await?;
    let guest_observation = observe_ipv4_network_remote(&authority).await?;
    let guest_vpc = evaluate_guest_vpc_network(&guest_observation, &ready)?;
    let desired = compose_verified_vpc_route(mesh_base, &vpc, ready)?;
    Ok((desired, guest_vpc))
}

#[derive(Debug, Clone, Serialize)]
struct GuestVpcNetworkReport {
    status: &'static str,
    interface: String,
    cidr: String,
    private_ipv4: String,
}

fn evaluate_guest_vpc_network(
    observation: &Ipv4NetworkObservation,
    ready: &VpcReadyReport,
) -> Result<GuestVpcNetworkReport, String> {
    let prefix = validate_verified_private_network(&ready.cidr, &ready.private_ipv4)?;
    let (subnet, _) = ready
        .cidr
        .split_once('/')
        .ok_or_else(|| "verified Vultr VPC CIDR must use IPv4 prefix notation".to_owned())?;

    let mut matching_interfaces = observation
        .addresses
        .iter()
        .filter(|address| {
            address.global_scope
                && address.address == ready.private_ipv4
                && address.prefix_length == u32::from(prefix)
        })
        .filter_map(|address| {
            observation
                .links
                .iter()
                .find(|link| {
                    link.interface_index == address.interface_index
                        && !link.loopback
                        && link.up
                        && link.lower_up
                })
                .map(|link| (link.interface_index, link.name.clone()))
        })
        .collect::<Vec<_>>();
    matching_interfaces.sort();
    matching_interfaces.dedup();

    let (interface_index, interface) = match matching_interfaces.as_slice() {
        [(interface_index, interface)] => (*interface_index, interface.clone()),
        [] => {
            return Err(
                "guest did not expose the exact provider-observed private IPv4 on an UP VPC interface"
                    .to_owned(),
            );
        }
        _ => {
            return Err(
                "guest private IPv4 observation is ambiguous across multiple interfaces".to_owned(),
            );
        }
    };

    let route_matches = observation
        .routes
        .iter()
        .filter(|route| {
            route.destination == subnet
                && route.prefix_length == u32::from(prefix)
                && route.output_interface_index == interface_index
                && route.kernel_protocol
                && route.link_scope
                && route.preferred_source.as_deref() == Some(ready.private_ipv4.as_str())
        })
        .count();
    if route_matches != 1 {
        return Err(format!(
            "guest did not expose exactly one connected kernel route for the verified VPC CIDR; observed {route_matches}"
        ));
    }

    Ok(GuestVpcNetworkReport {
        status: "PASS",
        interface,
        cidr: ready.cidr.clone(),
        private_ipv4: ready.private_ipv4.clone(),
    })
}

fn compose_verified_vpc_route(
    mut mesh_base: DesiredMeshState,
    vpc: &DesiredVpcState,
    ready: VpcReadyReport,
) -> Result<DesiredMeshState, String> {
    if !mesh_base.routes.is_empty() {
        return Err(
            "VPC-composed Mesh base spec must contain zero routes; run-local route authority comes only from verified Vultr VPC state"
                .to_owned(),
        );
    }
    if mesh_base.environment != vpc.environment {
        return Err(format!(
            "Mesh environment {} does not match Vultr VPC environment {}",
            mesh_base.environment, vpc.environment
        ));
    }
    if ready.status != "PASS" {
        return Err("Vultr VPC is not READY for Mesh route composition".to_owned());
    }
    if ready.target.region != vpc.region {
        return Err(format!(
            "verified Vultr target region {} does not match VPC desired region {}",
            ready.target.region, vpc.region
        ));
    }
    validate_verified_private_network(&ready.cidr, &ready.private_ipv4)?;
    mesh_base.routes.push(MeshRouteSpec {
        network: ready.cidr,
    });
    mesh_base.validate().map_err(|err| err.to_string())?;
    Ok(mesh_base)
}

fn validate_verified_private_network(cidr: &str, private_ipv4: &str) -> Result<u8, String> {
    let (subnet_text, prefix_text) = cidr
        .split_once('/')
        .ok_or_else(|| "verified Vultr VPC CIDR must use IPv4 prefix notation".to_owned())?;
    let subnet = subnet_text
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("verified Vultr VPC CIDR has invalid IPv4 subnet: {err}"))?;
    let prefix = prefix_text
        .parse::<u8>()
        .map_err(|err| format!("verified Vultr VPC CIDR has invalid prefix: {err}"))?;
    if !(1..=32).contains(&prefix) {
        return Err("verified Vultr VPC CIDR prefix must be in 1..=32".to_owned());
    }
    if !subnet.is_private() {
        return Err("verified Vultr VPC CIDR must be RFC1918 IPv4".to_owned());
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    if (u32::from(subnet) & mask) != u32::from(subnet) {
        return Err("verified Vultr VPC CIDR must be canonical".to_owned());
    }

    let private_ip = private_ipv4
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("verified Vultr private IPv4 is invalid: {err}"))?;
    if !private_ip.is_private() {
        return Err("verified Vultr private IPv4 must be RFC1918".to_owned());
    }
    if (u32::from(private_ip) & mask) != u32::from(subnet) {
        return Err("verified Vultr private IPv4 is outside the verified VPC CIDR".to_owned());
    }
    Ok(prefix)
}

fn provider_from_env(desired: &DesiredMeshState) -> Result<CloudflareMeshApiProvider, String> {
    let api_token = env::var("CLOUDFLARE_API_TOKEN")
        .map_err(|_| "CLOUDFLARE_API_TOKEN is required".to_owned())?;
    CloudflareMeshApiProvider::new(api_token, desired.account_id.clone())
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    let output = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize Cloudflare Mesh result: {err}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-orchestrator line3-mesh inventory <spec-path>",
        "  edge-orchestrator line3-mesh plan <spec-path>",
        "  edge-orchestrator line3-mesh apply <spec-path> <authorized-plan-sha256>",
        "  edge-orchestrator line3-mesh vpc-plan <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>",
        "  edge-orchestrator line3-mesh vpc-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path> <authorized-plan-sha256>",
        "  edge-orchestrator line3-mesh cleanup-plan <spec-path>",
        "  edge-orchestrator line3-mesh cleanup-apply <spec-path> <destructive-digest> <authorized-plan-sha256>",
        "  edge-orchestrator line3-mesh runtime-apply <mesh-spec-path> <application-spec-path>",
        "  edge-orchestrator line3-mesh vpc-runtime-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>",
        "  edge-orchestrator line3-mesh runtime-verify <mesh-spec-path> <application-spec-path>",
        "  edge-orchestrator line3-mesh vpc-runtime-verify <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>",
        "  edge-orchestrator line3-mesh runtime-cleanup <application-spec-path>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    #[test]
    fn mesh_observation_summary_is_bounded_to_status_and_counts() {
        let observation = MeshObservation {
            nodes: vec![
                edge_controller_core::cloudflare_mesh_lifecycle::ObservedMeshNode {
                    provider_id: "node-1".to_owned(),
                    name: "singbox-line3-test".to_owned(),
                    status: Some("inactive".to_owned()),
                },
            ],
            routes: vec![],
        };
        assert_eq!(
            mesh_observation_summary(&observation),
            "provider_nodes=1 provider_routes=0 provider_statuses=[inactive]"
        );
    }

    use super::*;
    use crate::vultr_vpc_lifecycle_service::TargetInstance;

    fn mesh_base() -> DesiredMeshState {
        DesiredMeshState {
            schema: 1,
            account_id: "4426df1449e417511bc7697d60b7f62f".to_owned(),
            environment: "application-acceptance".to_owned(),
            node_name: "singbox-line3-application-acceptance".to_owned(),
            routes: Vec::new(),
        }
    }

    fn vpc_desired() -> DesiredVpcState {
        DesiredVpcState {
            schema: 1,
            environment: "application-acceptance".to_owned(),
            region: "waw".to_owned(),
            machine_id: "application-acceptance-1".to_owned(),
        }
    }

    fn ready_report(cidr: &str, private_ipv4: &str) -> VpcReadyReport {
        VpcReadyReport {
            status: "PASS",
            target: TargetInstance {
                provider_id: "instance-1".to_owned(),
                region: "waw".to_owned(),
                main_ip: "203.0.113.10".to_owned(),
            },
            vpc_provider_id: "vpc-1".to_owned(),
            cidr: cidr.to_owned(),
            private_ipv4: private_ipv4.to_owned(),
        }
    }

    fn guest_observation() -> Ipv4NetworkObservation {
        Ipv4NetworkObservation {
            links: vec![edge_shared_types::Ipv4LinkObservation {
                interface_index: 7,
                name: "ens7".to_owned(),
                up: true,
                lower_up: true,
                loopback: false,
            }],
            addresses: vec![edge_shared_types::Ipv4AddressObservation {
                interface_index: 7,
                address: "10.0.4.2".to_owned(),
                prefix_length: 24,
                global_scope: true,
            }],
            routes: vec![edge_shared_types::Ipv4RouteObservation {
                destination: "10.0.4.0".to_owned(),
                prefix_length: 24,
                output_interface_index: 7,
                preferred_source: Some("10.0.4.2".to_owned()),
                kernel_protocol: true,
                link_scope: true,
            }],
        }
    }

    #[test]
    fn guest_vpc_network_accepts_only_exact_provider_backed_observation() {
        let ready = ready_report("10.0.4.0/24", "10.0.4.2");
        let report = evaluate_guest_vpc_network(&guest_observation(), &ready).unwrap();
        assert_eq!(report.status, "PASS");
        assert_eq!(report.interface, "ens7");
    }

    #[test]
    fn guest_vpc_network_rejects_missing_or_ambiguous_private_ip() {
        let ready = ready_report("10.0.4.0/24", "10.0.4.2");

        let mut missing = guest_observation();
        missing.addresses.clear();
        assert!(evaluate_guest_vpc_network(&missing, &ready).is_err());

        let mut ambiguous = guest_observation();
        ambiguous
            .links
            .push(edge_shared_types::Ipv4LinkObservation {
                interface_index: 8,
                name: "ens8".to_owned(),
                up: true,
                lower_up: true,
                loopback: false,
            });
        ambiguous
            .addresses
            .push(edge_shared_types::Ipv4AddressObservation {
                interface_index: 8,
                address: "10.0.4.2".to_owned(),
                prefix_length: 24,
                global_scope: true,
            });
        assert!(evaluate_guest_vpc_network(&ambiguous, &ready).is_err());

        let mut wrong_prefix = guest_observation();
        wrong_prefix.addresses[0].prefix_length = 25;
        assert!(evaluate_guest_vpc_network(&wrong_prefix, &ready).is_err());
    }

    #[test]
    fn guest_vpc_network_requires_admin_up_carrier_and_non_loopback_link() {
        let ready = ready_report("10.0.4.0/24", "10.0.4.2");

        let mut admin_down = guest_observation();
        admin_down.links[0].up = false;
        assert!(evaluate_guest_vpc_network(&admin_down, &ready).is_err());

        let mut carrier_down = guest_observation();
        carrier_down.links[0].lower_up = false;
        assert!(evaluate_guest_vpc_network(&carrier_down, &ready).is_err());

        let mut loopback = guest_observation();
        loopback.links[0].loopback = true;
        assert!(evaluate_guest_vpc_network(&loopback, &ready).is_err());
    }

    #[test]
    fn guest_vpc_network_requires_one_exact_connected_kernel_route() {
        let ready = ready_report("10.0.4.0/24", "10.0.4.2");

        let mut missing = guest_observation();
        missing.routes.clear();
        assert!(evaluate_guest_vpc_network(&missing, &ready).is_err());

        let mut duplicate = guest_observation();
        duplicate.routes.push(duplicate.routes[0].clone());
        assert!(evaluate_guest_vpc_network(&duplicate, &ready).is_err());

        let mut wrong_interface = guest_observation();
        wrong_interface.routes[0].output_interface_index = 8;
        assert!(evaluate_guest_vpc_network(&wrong_interface, &ready).is_err());

        let mut wrong_prefix = guest_observation();
        wrong_prefix.routes[0].prefix_length = 25;
        assert!(evaluate_guest_vpc_network(&wrong_prefix, &ready).is_err());

        let mut wrong_preferred_source = guest_observation();
        wrong_preferred_source.routes[0].preferred_source = Some("10.0.4.3".to_owned());
        assert!(evaluate_guest_vpc_network(&wrong_preferred_source, &ready).is_err());

        let mut wrong_protocol = guest_observation();
        wrong_protocol.routes[0].kernel_protocol = false;
        assert!(evaluate_guest_vpc_network(&wrong_protocol, &ready).is_err());

        let mut wrong_scope = guest_observation();
        wrong_scope.routes[0].link_scope = false;
        assert!(evaluate_guest_vpc_network(&wrong_scope, &ready).is_err());
    }

    #[test]
    fn guest_vpc_network_rejects_invalid_provider_network_authority() {
        let observation = guest_observation();

        assert!(
            evaluate_guest_vpc_network(
                &observation,
                &ready_report("203.0.113.0/24", "203.0.113.2")
            )
            .is_err()
        );
        assert!(
            evaluate_guest_vpc_network(&observation, &ready_report("10.0.4.7/24", "10.0.4.8"))
                .is_err()
        );
        assert!(
            evaluate_guest_vpc_network(&observation, &ready_report("10.0.4.0/24", "10.0.5.2"))
                .is_err()
        );
    }

    #[test]
    fn vpc_route_composition_uses_only_verified_private_network() {
        let effective = compose_verified_vpc_route(
            mesh_base(),
            &vpc_desired(),
            ready_report("10.0.4.0/24", "10.0.4.2"),
        )
        .unwrap();
        assert_eq!(
            effective.routes,
            vec![MeshRouteSpec {
                network: "10.0.4.0/24".to_owned(),
            }]
        );

        assert!(
            compose_verified_vpc_route(
                mesh_base(),
                &vpc_desired(),
                ready_report("203.0.113.0/24", "203.0.113.2")
            )
            .is_err()
        );
        assert!(
            compose_verified_vpc_route(
                mesh_base(),
                &vpc_desired(),
                ready_report("10.0.4.7/24", "10.0.4.8")
            )
            .is_err()
        );
    }

    #[test]
    fn changed_verified_vpc_cidr_changes_effective_mesh_route_without_source_edit() {
        let first = compose_verified_vpc_route(
            mesh_base(),
            &vpc_desired(),
            ready_report("10.0.4.0/24", "10.0.4.2"),
        )
        .unwrap();
        let second = compose_verified_vpc_route(
            mesh_base(),
            &vpc_desired(),
            ready_report("10.0.5.0/24", "10.0.5.2"),
        )
        .unwrap();

        assert_eq!(first.routes[0].network, "10.0.4.0/24");
        assert_eq!(second.routes[0].network, "10.0.5.0/24");
        assert_ne!(first.routes, second.routes);
    }

    #[test]
    fn vpc_route_composition_rejects_git_routes_and_mismatched_authority() {
        let mut predeclared = mesh_base();
        predeclared.routes.push(MeshRouteSpec {
            network: "10.255.0.0/24".to_owned(),
        });
        assert!(
            compose_verified_vpc_route(
                predeclared,
                &vpc_desired(),
                ready_report("10.0.4.0/24", "10.0.4.2")
            )
            .is_err()
        );

        let mut mismatched_vpc = vpc_desired();
        mismatched_vpc.environment = "foreign".to_owned();
        assert!(
            compose_verified_vpc_route(
                mesh_base(),
                &mismatched_vpc,
                ready_report("10.0.4.0/24", "10.0.4.2")
            )
            .is_err()
        );

        let mut not_ready = ready_report("10.0.4.0/24", "10.0.4.2");
        not_ready.status = "NOT_READY";
        assert!(compose_verified_vpc_route(mesh_base(), &vpc_desired(), not_ready).is_err());
    }

    #[test]
    fn mesh_runtime_renderer_preserves_extended_typed_diagnostics() {
        let ok_probe = || edge_shared_types::RuntimeProbeEvidence {
            status: 1,
            ..Default::default()
        };
        let diagnostics = edge_shared_types::MeshRuntimeDiagnostics {
            container: Some(edge_shared_types::MeshContainerDiagnostics {
                present: true,
                running: true,
                exit_code: Some(0),
                runtime_error_present: false,
                recent_events: vec!["bounded-event".to_owned()],
                name: "vultr-cloudflare-mesh".to_owned(),
                image: Some("docker.io/cloudflare/mesh@sha256:abc".to_owned()),
                restart_count: Some(3),
                oom_killed: Some(false),
                networks: vec!["mesh-net".to_owned()],
            }),
            host: Some(edge_shared_types::HostRuntimeDiagnostics {
                identity: Some(edge_shared_types::HostIdentityDiagnostics {
                    probe: Some(ok_probe()),
                    hostname: Some("acceptance-host".to_owned()),
                    kernel_release: Some("6.12.0".to_owned()),
                    architecture: Some("x86_64".to_owned()),
                }),
                time: Some(edge_shared_types::HostTimeDiagnostics {
                    probe: Some(ok_probe()),
                    unix_time_seconds: Some(1_790_000_000),
                    uptime_seconds: Some(12_345),
                }),
                resources: Some(edge_shared_types::HostResourceDiagnostics {
                    probe: Some(ok_probe()),
                    logical_cpus: Some(2),
                    load_1: Some(0.1),
                    load_5: Some(0.2),
                    load_15: Some(0.3),
                    memory_total_bytes: Some(1_000_000),
                    memory_available_bytes: Some(750_000),
                }),
            }),
            ..Default::default()
        };
        let snapshot = edge_shared_types::MeshRuntimeFailureSnapshot {
            observed_unix_time_seconds: 1_790_000_001,
            reasons: vec!["bounded failure reason".to_owned()],
            warp_connection_state: Some("DISCONNECTED".to_owned()),
            tunnel_protocol: Some("MASQUE".to_owned()),
            warp_status: 6,
            warp_settings: 1,
            tun_device_status: 1,
            ipv4_forwarding_status: 1,
            container_present: true,
            container_running: false,
            container_exit_code: Some(1),
            container_restart_count: Some(4),
            container_oom_killed: Some(false),
            container_image: Some("docker.io/cloudflare/mesh@sha256:abc".to_owned()),
            container_networks: vec!["mesh-net".to_owned()],
            exact_image_ready: true,
        };

        let rendered = mesh_runtime_diagnostics_json(Some(&diagnostics));
        assert_eq!(rendered["container"]["name"], "vultr-cloudflare-mesh");
        assert_eq!(rendered["container"]["restart_count"], 3);
        assert_eq!(rendered["container"]["oom_killed"], false);
        assert_eq!(rendered["container"]["networks"][0], "mesh-net");
        assert_eq!(rendered["host"]["identity"]["hostname"], "acceptance-host");
        assert_eq!(rendered["host"]["time"]["uptime_seconds"], 12_345);
        assert_eq!(rendered["host"]["resources"]["logical_cpus"], 2);
        assert_eq!(
            rendered["host"]["resources"]["memory_available_bytes"],
            750_000
        );

        let failure = mesh_runtime_failure_snapshot_json(Some(&snapshot));
        assert_eq!(failure["warp_status"], "NON_ZERO");
        assert_eq!(failure["container_restart_count"], 4);
        assert_eq!(failure["container_networks"][0], "mesh-net");

        let state = edge_shared_types::MeshRuntimeState {
            diagnostics: Some(diagnostics),
            last_failure_snapshot: Some(snapshot),
            ..Default::default()
        };
        let summary = mesh_runtime_diagnostic_summary(&state);
        assert!(summary.contains("\"host\""));
        assert!(summary.contains("\"restart_count\":3"));
        assert!(summary.contains("\"last_failure_snapshot\""));
    }

    #[test]
    fn usage_is_closed_and_has_no_raw_provider_identity_or_token_surface() {
        let text = usage();
        assert!(text.contains("line3-mesh plan"));
        assert!(text.contains(
            "line3-mesh vpc-plan <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
        ));
        assert!(text.contains(
            "line3-mesh vpc-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
        ));
        assert!(text.contains("line3-mesh cleanup-apply"));
        assert!(text.contains("line3-mesh runtime-apply"));
        assert!(text.contains("line3-mesh vpc-runtime-apply"));
        assert!(text.contains("line3-mesh runtime-verify"));
        assert!(text.contains("line3-mesh vpc-runtime-verify"));
        assert!(text.contains("line3-mesh runtime-cleanup"));
        assert!(!text.contains("node-id"));
        assert!(!text.contains("route-id"));
        assert!(!text.contains("token"));
        assert!(!text.contains("account-id"));
        assert!(!text.contains("<cidr>"));
        assert!(!text.contains("vpc-id"));
        assert!(!text.contains("exec"));
        assert!(!text.contains("shell"));
    }
}
