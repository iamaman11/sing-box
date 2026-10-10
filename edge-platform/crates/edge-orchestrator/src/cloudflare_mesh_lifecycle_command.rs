use crate::application_lifecycle_command::resolve_application_authority_from_spec;
use crate::application_lifecycle_service::{
    cleanup_mesh_runtime_remote, converge_mesh_runtime_remote, mesh_provider_failure_evidence,
    observe_ipv4_network_remote, observe_mesh_runtime_remote_once, verify_mesh_runtime_remote,
};
use crate::cloudflare_mesh_lifecycle_service::{
    CloudflareMeshApiProvider, MeshExecutionPolicy, apply_mesh_once, authorize_mesh_apply,
    authorize_mesh_cleanup, cleanup_mesh_once, exact_mesh_node_token, observe_mesh,
    plan_mesh_apply, plan_mesh_cleanup, wait_mesh_provider_healthy,
};
use crate::vultr_vpc_lifecycle_service::{VpcReadyReport, VultrVpcApiProvider, verify_vpc_ready};
use edge_controller_core::cloudflare_mesh_lifecycle::{
    ApplyAction, CleanupAction, DesiredMeshState, MeshRouteSpec,
};
use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_controller_core::vultr_vpc_lifecycle::DesiredVpcState;
use edge_shared_types::Ipv4NetworkObservation;
use serde::Serialize;
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

pub(crate) async fn acceptance_require_clean_room(spec_path: &Path) -> Result<(), String> {
    let desired = load_desired(spec_path)?;
    let mut provider = provider_from_env(&desired)?;
    let (_observation, plan) = plan_mesh_cleanup(&mut provider, &desired).await?;
    if !matches!(plan.action, CleanupAction::Noop) || plan.destructive_digest.is_some() {
        return Err(format!(
            "acceptance Mesh clean room is not empty: action={:?}",
            plan.action
        ));
    }
    Ok(())
}

pub(crate) async fn acceptance_converge_provider(
    mesh_base_spec_path: &Path,
    vpc_spec_path: &Path,
    application_spec_path: &Path,
) -> Result<(), String> {
    let (desired, _guest_vpc) = load_desired_with_verified_vpc_route(
        mesh_base_spec_path,
        vpc_spec_path,
        application_spec_path,
    )
    .await?;
    let mut provider = production_provider_from_env(mesh_base_spec_path, &desired)?;
    for _ in 0..4 {
        let (observed, plan) = plan_mesh_apply(&mut provider, &desired).await?;
        if matches!(plan.action, ApplyAction::Noop) {
            // Provider topology must exist before the guest connector can start. Health is
            // intentionally checked only after acceptance_runtime_apply starts that runtime.
            return Ok(());
        }
        let authorized = authorize_mesh_apply(&desired, &observed, plan)?;
        apply_mesh_once(
            &mut provider,
            &desired,
            &authorized.authority.authority_digest,
            MeshExecutionPolicy::default(),
        )
        .await?;
    }
    Err("Mesh provider convergence exceeded bounded one-mutation steps".to_owned())
}

pub(crate) async fn acceptance_runtime_apply(
    mesh_base_spec_path: &Path,
    vpc_spec_path: &Path,
    application_spec_path: &Path,
) -> Result<(), String> {
    let (desired, _guest_vpc) = load_desired_with_verified_vpc_route(
        mesh_base_spec_path,
        vpc_spec_path,
        application_spec_path,
    )
    .await?;
    let mut provider = production_provider_from_env(mesh_base_spec_path, &desired)?;
    let credential = exact_mesh_node_token(&mut provider, &desired).await?;
    let authority = resolve_application_authority_from_spec(application_spec_path).await?;
    let state = converge_mesh_runtime_remote(
        &authority,
        credential.registration_id.clone(),
        credential.node_token,
    )
    .await?;
    if !state.runtime_ready
        || !state.exact_image_ready
        || state.registration_id.as_deref() != Some(credential.registration_id.as_str())
    {
        return Err(format!(
            "Mesh runtime convergence completed without exact READY identity: runtime_ready={} exact_image_ready={} registration_match={} warnings={}",
            state.runtime_ready,
            state.exact_image_ready,
            state.registration_id.as_deref() == Some(credential.registration_id.as_str()),
            state.warnings.join("; ")
        ));
    }
    println!("mesh_runtime_local_status=READY");
    println!("mesh_runtime_registration_identity=EXACT");
    if let Err(provider_failure) =
        wait_mesh_provider_healthy(&mut provider, &desired, MeshExecutionPolicy::default()).await
    {
        // The guest can be locally READY while Cloudflare still reports inactive.
        // Capture one read-only, typed deep observation before acceptance destroys this VM.
        // Neither failed observation nor a provider timeout authorizes replaying convergence.
        let diagnostic = observe_mesh_runtime_remote_once(&authority).await;
        return Err(mesh_provider_failure_with_diagnostic(
            &provider_failure,
            diagnostic,
            &credential.registration_id,
        ));
    }
    println!("mesh_provider_status=HEALTHY");
    Ok(())
}

fn mesh_provider_failure_with_diagnostic(
    provider_failure: &str,
    diagnostic: Result<edge_shared_types::MeshRuntimeState, String>,
    expected_registration: &str,
) -> String {
    // Never append a raw RPC error: it can contain endpoints or other untrusted data.
    let evidence = match diagnostic {
        Ok(state) => mesh_provider_failure_evidence(&state, expected_registration),
        Err(_) => "local_diagnostic=UNAVAILABLE".to_owned(),
    };
    format!("{provider_failure}; {evidence}")
}

pub(crate) async fn acceptance_runtime_verify(
    mesh_base_spec_path: &Path,
    vpc_spec_path: &Path,
    application_spec_path: &Path,
) -> Result<(), String> {
    let (desired, _guest_vpc) = load_desired_with_verified_vpc_route(
        mesh_base_spec_path,
        vpc_spec_path,
        application_spec_path,
    )
    .await?;
    let mut provider = production_provider_from_env(mesh_base_spec_path, &desired)?;
    let provider_observation =
        wait_mesh_provider_healthy(&mut provider, &desired, MeshExecutionPolicy::default()).await?;
    let [provider_node] = provider_observation.nodes.as_slice() else {
        return Err("Mesh provider verification did not observe exactly one node".to_owned());
    };
    let authority = resolve_application_authority_from_spec(application_spec_path).await?;
    let state = verify_mesh_runtime_remote(&authority).await?;
    if !state.runtime_ready
        || !state.exact_image_ready
        || state.registration_id.as_deref() != Some(provider_node.provider_id.as_str())
    {
        return Err(format!(
            "Mesh runtime verification did not observe exact READY identity: runtime_ready={} exact_image_ready={} registration_match={} warnings={}",
            state.runtime_ready,
            state.exact_image_ready,
            state.registration_id.as_deref() == Some(provider_node.provider_id.as_str()),
            state.warnings.join("; ")
        ));
    }
    Ok(())
}

pub(crate) async fn acceptance_runtime_cleanup(application_spec_path: &Path) -> Result<(), String> {
    let authority = resolve_application_authority_from_spec(application_spec_path).await?;
    let state = cleanup_mesh_runtime_remote(&authority).await?;
    if state.runtime_ready || state.token_store_present || state.container_running {
        return Err("Mesh runtime cleanup did not prove exact absence".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_cleanup_provider_to_absent(spec_path: &Path) -> Result<(), String> {
    let desired = load_desired(spec_path)?;
    let mut provider = provider_from_env(&desired)?;
    for _ in 0..4 {
        let (observed, plan) = plan_mesh_cleanup(&mut provider, &desired).await?;
        if matches!(plan.action, CleanupAction::Noop) {
            if plan.destructive_digest.is_some()
                || !observed.nodes.is_empty()
                || !observed.routes.is_empty()
            {
                return Err("Mesh NOOP cleanup plan contained provider residue".to_owned());
            }
            return Ok(());
        }
        let destructive_digest = plan
            .destructive_digest
            .clone()
            .ok_or_else(|| "Mesh cleanup mutation is missing destructive digest".to_owned())?;
        let authorized = authorize_mesh_cleanup(&desired, &observed, plan)?;
        cleanup_mesh_once(
            &mut provider,
            &desired,
            &destructive_digest,
            &authorized.authority.authority_digest,
            MeshExecutionPolicy::default(),
        )
        .await?;
    }
    Err("Mesh provider cleanup exceeded bounded one-mutation steps".to_owned())
}

fn load_desired(path: &Path) -> Result<DesiredMeshState, String> {
    if path == Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH) {
        return ProductionComposition::canonical()
            .map(|composition| composition.mesh)
            .map_err(|err| err.to_string());
    }

    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Cloudflare Mesh spec {}: {err}",
            path.display()
        )
    })?;
    DesiredMeshState::parse_json(&raw).map_err(|err| err.to_string())
}

fn load_vpc_desired(path: &Path) -> Result<DesiredVpcState, String> {
    if path == Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH) {
        return ProductionComposition::canonical()
            .map(|composition| composition.vpc)
            .map_err(|err| err.to_string());
    }

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

fn production_provider_from_env(
    spec_path: &Path,
    desired: &DesiredMeshState,
) -> Result<CloudflareMeshApiProvider, String> {
    if spec_path != Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH) {
        return provider_from_env(desired);
    }
    let api_token = env::var("CLOUDFLARE_CONTROL_TOKEN").map_err(|_| {
        "CLOUDFLARE_CONTROL_TOKEN is required for canonical production Mesh".to_owned()
    })?;
    CloudflareMeshApiProvider::new(api_token, desired.account_id.clone())
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
    fn inactive_provider_preserves_failure_and_bounded_typed_evidence() {
        let state = edge_shared_types::MeshRuntimeState {
            runtime_ready: true,
            exact_image_ready: true,
            registration_id: Some("node-a".to_owned()),
            ..Default::default()
        };
        let error = mesh_provider_failure_with_diagnostic(
            "Cloudflare Mesh node did not become healthy; last_status=inactive",
            Ok(state),
            "node-a",
        );
        assert!(error.contains("last_status=inactive"));
        assert!(error.contains("local_diagnostic=OBSERVED"));
        assert!(error.contains("registration_match=true"));
        assert!(error.contains("runtime_ready=true"));
        assert!(!error.contains("node-a"));
    }

    #[test]
    fn inactive_provider_diagnostic_rpc_failure_does_not_replace_primary_failure() {
        let error = mesh_provider_failure_with_diagnostic(
            "last_status=inactive",
            Err("Bearer secret-token at 10.0.0.1".to_owned()),
            "node-a",
        );
        assert_eq!(error, "last_status=inactive; local_diagnostic=UNAVAILABLE");
    }

    #[test]
    fn inactive_provider_registration_drift_fails_evidence_match() {
        let state = edge_shared_types::MeshRuntimeState {
            runtime_ready: false,
            registration_id: Some("node-other".to_owned()),
            ..Default::default()
        };
        let error = mesh_provider_failure_with_diagnostic(
            "last_status=inactive",
            Ok(state),
            "node-expected",
        );
        assert!(error.contains("registration_match=false"));
        assert!(error.contains("runtime_ready=false"));
        assert!(!error.contains("node-other"));
        assert!(!error.contains("node-expected"));
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
}
