use crate::application_lifecycle_command::resolve_application_authority_from_spec;
use crate::application_lifecycle_service::{
    cleanup_mesh_runtime_remote, converge_mesh_runtime_remote, observe_ipv4_network_remote,
    verify_mesh_runtime_remote,
};
use crate::cloudflare_mesh_lifecycle_service::{
    CloudflareMeshApiProvider, MeshExecutionPolicy, apply_mesh_once, cleanup_mesh_once,
    exact_mesh_node_token, observe_mesh, plan_mesh_apply, plan_mesh_cleanup,
    wait_mesh_provider_healthy,
};
use crate::vultr_vpc_lifecycle_service::{VpcReadyReport, VultrVpcApiProvider, verify_vpc_ready};
use edge_controller_core::cloudflare_mesh_lifecycle::{DesiredMeshState, MeshRouteSpec};
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
        return Err("usage: edge-controller line3-mesh inventory <spec-path>".to_owned());
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
        return Err("usage: edge-controller line3-mesh plan <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_mesh_apply(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller line3-mesh apply <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let report = apply_mesh_once(&mut provider, &desired, MeshExecutionPolicy::default()).await?;
    print_json(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_vpc_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller line3-mesh vpc-plan <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
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
    print_json(serde_json::json!({
        "guest_vpc": guest_vpc,
        "observation": observed,
        "plan": plan,
    }))
}

async fn run_vpc_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller line3-mesh vpc-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
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
    let report = apply_mesh_once(&mut provider, &desired, MeshExecutionPolicy::default()).await?;
    print_json(serde_json::json!({
        "guest_vpc": guest_vpc,
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_cleanup_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller line3-mesh cleanup-plan <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_mesh_cleanup(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
    }))
}

async fn run_cleanup_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller line3-mesh cleanup-apply <spec-path> <destructive-digest>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let report = cleanup_mesh_once(
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

async fn run_runtime_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller line3-mesh runtime-apply <mesh-spec-path> <application-spec-path>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    run_runtime_apply_with_desired(desired, Path::new(&args[1])).await
}

async fn run_vpc_runtime_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller line3-mesh vpc-runtime-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
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
        return Err(format!(
            "Mesh runtime convergence completed without READY: {}",
            state.warnings.join("; ")
        ));
    }
    let provider_observation =
        wait_mesh_provider_healthy(&mut provider, &desired, MeshExecutionPolicy::default()).await?;
    print_mesh_runtime_result("READY", &state, Some(provider_observation))
}

async fn run_runtime_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller line3-mesh runtime-verify <mesh-spec-path> <application-spec-path>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    run_runtime_verify_with_desired(desired, Path::new(&args[1])).await
}

async fn run_vpc_runtime_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller line3-mesh vpc-runtime-verify <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>"
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
            "Mesh runtime verify did not observe READY: {}",
            state.warnings.join("; ")
        ));
    }
    print_mesh_runtime_result("PASS", &state, Some(provider_observation))
}

async fn run_runtime_cleanup(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err(
            "usage: edge-controller line3-mesh runtime-cleanup <application-spec-path>".to_owned(),
        );
    }
    let authority = resolve_application_authority_from_spec(Path::new(&args[0])).await?;
    let state = cleanup_mesh_runtime_remote(&authority).await?;
    if state.token_store_present || state.container_running {
        return Err("Mesh runtime cleanup did not observe exact absence".to_owned());
    }
    print_mesh_runtime_result("ABSENT", &state, None)
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
        },
        "provider_observation": provider_observation,
    }))
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
        "  edge-controller line3-mesh inventory <spec-path>",
        "  edge-controller line3-mesh plan <spec-path>",
        "  edge-controller line3-mesh apply <spec-path>",
        "  edge-controller line3-mesh vpc-plan <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>",
        "  edge-controller line3-mesh vpc-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>",
        "  edge-controller line3-mesh cleanup-plan <spec-path>",
        "  edge-controller line3-mesh cleanup-apply <spec-path> <destructive-digest>",
        "  edge-controller line3-mesh runtime-apply <mesh-spec-path> <application-spec-path>",
        "  edge-controller line3-mesh vpc-runtime-apply <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>",
        "  edge-controller line3-mesh runtime-verify <mesh-spec-path> <application-spec-path>",
        "  edge-controller line3-mesh vpc-runtime-verify <mesh-base-spec-path> <vpc-spec-path> <application-spec-path>",
        "  edge-controller line3-mesh runtime-cleanup <application-spec-path>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
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
            },
            vpc_provider_id: "vpc-1".to_owned(),
            cidr: cidr.to_owned(),
            private_ipv4: private_ipv4.to_owned(),
        }
    }

    fn guest_observation(lower_up: bool, include_route: bool) -> Ipv4NetworkObservation {
        Ipv4NetworkObservation {
            links: vec![edge_shared_types::Ipv4LinkObservation {
                interface_index: 7,
                name: "ens7".to_owned(),
                up: true,
                lower_up,
                loopback: false,
            }],
            addresses: vec![edge_shared_types::Ipv4AddressObservation {
                interface_index: 7,
                address: "10.0.4.2".to_owned(),
                prefix_length: 24,
                global_scope: true,
            }],
            routes: if include_route {
                vec![edge_shared_types::Ipv4RouteObservation {
                    destination: "10.0.4.0".to_owned(),
                    prefix_length: 24,
                    output_interface_index: 7,
                    preferred_source: Some("10.0.4.2".to_owned()),
                    kernel_protocol: true,
                    link_scope: true,
                }]
            } else {
                Vec::new()
            },
        }
    }

    #[test]
    fn guest_vpc_network_requires_exact_up_interface_and_connected_kernel_route() {
        let ready = ready_report("10.0.4.0/24", "10.0.4.2");
        let observation = guest_observation(true, true);

        let report = evaluate_guest_vpc_network(&observation, &ready).unwrap();
        assert_eq!(report.status, "PASS");
        assert_eq!(report.interface, "ens7");

        assert!(evaluate_guest_vpc_network(&guest_observation(true, false), &ready).is_err());
        assert!(evaluate_guest_vpc_network(&guest_observation(false, true), &ready).is_err());
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
