use crate::cloudflare_target_plane_command;
use edge_controller_core::production::ProductionComposition;
use edge_provider_cloudflare as cloudflare;
use edge_provider_cloudflare::{
    CloudflareDeviceProfile, CloudflareMeshNode, CloudflareMeshRoute, CloudflareWorkerDomain,
    CloudflareWorkerRoute, CloudflareWorkerScript,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::env;

const LEGACY_PRODUCTION_NODE: &str = "singbox-line3-production";
const LEGACY_VULTR_NODE: &str = "vultr";
const LEGACY_PROFILE: &str = "sing-box Mesh nodes";
const LEGACY_ROUTE_NETWORK: &str = "10.27.96.0/20";
const LEGACY_WORKER: &str = "edge-lease-reaper";
const LEGACY_WORKER_ROUTE: &str = "lease.alegria.by/*";
const MAX_MUTATIONS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HistoricalNodeObservation {
    node: CloudflareMeshNode,
    routes: Vec<CloudflareMeshRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HistoricalProfileObservation {
    profile: CloudflareDeviceProfile,
    includes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HistoricalObservation {
    account_id: String,
    production_node: Option<HistoricalNodeObservation>,
    legacy_vultr_node: Option<HistoricalNodeObservation>,
    mesh_profile: Option<HistoricalProfileObservation>,
    worker_route: Option<CloudflareWorkerRoute>,
    worker_script: Option<CloudflareWorkerScript>,
    worker_domains_referencing_legacy_script: Vec<CloudflareWorkerDomain>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum HistoricalAction {
    Noop,
    DeleteProductionMeshRoute { route_id: String },
    DeleteProductionMeshNode { node_id: String },
    DeleteLegacyVultrNode { node_id: String },
    DeleteMeshProfile { profile_id: String },
    DeleteLegacyWorkerRoute { route_id: String },
    DeleteLegacyWorkerScript,
}

struct Inputs {
    production: ProductionComposition,
    historical_token: String,
    dns_token: String,
}

impl Inputs {
    fn load() -> Result<Self, String> {
        let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
        if production.cloudflare.migration_target_account_id.is_some() {
            return Err(
                "historical retirement requires migration_target_account_id to remain absent"
                    .to_owned(),
            );
        }
        if production.cloudflare.active_account_id == production.shared_dns_account_id {
            return Err(
                "historical retirement requires current production account to differ from the historical/shared account"
                    .to_owned(),
            );
        }
        Ok(Self {
            production,
            historical_token: required_env("CLOUDFLARE_API_TOKEN")?,
            dns_token: required_env("CLOUDFLARE_DNS_TOKEN")?,
        })
    }

    fn historical_account_id(&self) -> &str {
        &self.production.shared_dns_account_id
    }

    fn zone_name(&self) -> &str {
        &self.production.dns.zone_name
    }
}

pub(crate) async fn plan() -> Result<(), String> {
    let inputs = Inputs::load()?;
    verify_replacement_plane().await?;
    let observation = observe(&inputs).await?;
    let action = next_action(&observation)?;
    print_state("PLAN", 0, &observation, &action);
    Ok(())
}

pub(crate) async fn apply() -> Result<(), String> {
    let inputs = Inputs::load()?;
    let mut mutations = 0u32;

    for step in 1..=MAX_MUTATIONS {
        verify_replacement_plane().await?;
        let before = observe(&inputs).await?;
        let action = next_action(&before)?;
        println!("retirement_step={step}");
        println!("action={}", action_name(&action));

        if action == HistoricalAction::Noop {
            print_state("PASS", mutations, &before, &action);
            return Ok(());
        }

        let mutation = execute_once(&inputs, &action).await;
        let after = observe(&inputs).await?;
        let next = next_action(&after)?;

        match mutation {
            Ok(()) => {
                mutations = mutations.saturating_add(1);
                if next == action {
                    return Err(format!(
                        "historical retirement action {} made no observable progress; mutation was not replayed",
                        action_name(&action)
                    ));
                }
            }
            Err(error) => {
                if next != action {
                    return Err(format!(
                        "historical retirement action {} returned an error but read-only re-observation changed state; mutation was not replayed: {error}",
                        action_name(&action)
                    ));
                }
                return Err(format!(
                    "historical retirement action {} failed and remains pending; mutation was not replayed: {error}",
                    action_name(&action)
                ));
            }
        }

        println!("next_action={}", action_name(&next));
        print_state("PROGRESS", mutations, &after, &next);
    }

    Err(format!(
        "historical retirement exceeded bounded {MAX_MUTATIONS}-mutation limit"
    ))
}

pub(crate) async fn verify() -> Result<(), String> {
    let inputs = Inputs::load()?;
    verify_replacement_plane().await?;
    let observation = observe(&inputs).await?;
    let action = next_action(&observation)?;
    if action != HistoricalAction::Noop {
        return Err(format!(
            "historical retirement verify requires NOOP; observed {}",
            action_name(&action)
        ));
    }
    print_state("PASS", 0, &observation, &action);
    Ok(())
}

async fn verify_replacement_plane() -> Result<(), String> {
    cloudflare_target_plane_command::verify_active_invariant().await
}

async fn observe(inputs: &Inputs) -> Result<HistoricalObservation, String> {
    let account_id = inputs.historical_account_id();

    let production_nodes =
        cloudflare::list_mesh_nodes(&inputs.historical_token, account_id, Some(LEGACY_PRODUCTION_NODE))
            .await?;
    let production_node = exact_node(
        &inputs.historical_token,
        account_id,
        LEGACY_PRODUCTION_NODE,
        production_nodes,
    )
    .await?;

    let vultr_nodes =
        cloudflare::list_mesh_nodes(&inputs.historical_token, account_id, Some(LEGACY_VULTR_NODE))
            .await?;
    let legacy_vultr_node = exact_node(
        &inputs.historical_token,
        account_id,
        LEGACY_VULTR_NODE,
        vultr_nodes,
    )
    .await?;

    let profiles = cloudflare::list_device_profiles(&inputs.historical_token, account_id).await?;
    let mut profile_matches = profiles
        .into_iter()
        .filter(|profile| profile.name == LEGACY_PROFILE)
        .collect::<Vec<_>>();
    if profile_matches.len() > 1 {
        return Err(format!(
            "historical Mesh profile identity is ambiguous: observed {} exact-name matches",
            profile_matches.len()
        ));
    }
    let mesh_profile = match profile_matches.pop() {
        Some(profile) => {
            validate_historical_profile(inputs, &profile).await?;
            let includes = cloudflare::get_device_profile_includes(
                &inputs.historical_token,
                account_id,
                &profile.id,
            )
            .await?;
            let mut include_addresses = includes
                .into_iter()
                .filter_map(|entry| entry.address)
                .collect::<Vec<_>>();
            include_addresses.sort();
            include_addresses.dedup();
            let expected = vec!["100.64.0.0/12".to_owned(), "100.96.0.0/12".to_owned()];
            if include_addresses != expected {
                return Err(format!(
                    "historical Mesh profile split-tunnel ownership drifted: observed {:?}",
                    include_addresses
                ));
            }
            Some(HistoricalProfileObservation {
                profile,
                includes: include_addresses,
            })
        }
        None => None,
    };

    let routes = cloudflare::list_worker_routes(&inputs.dns_token, inputs.zone_name()).await?;
    let route_matches = routes
        .into_iter()
        .filter(|route| {
            route.pattern == LEGACY_WORKER_ROUTE
                || route.script.as_deref() == Some(LEGACY_WORKER)
        })
        .collect::<Vec<_>>();
    let worker_route = match route_matches.as_slice() {
        [] => None,
        [route]
            if route.pattern == LEGACY_WORKER_ROUTE
                && route.script.as_deref() == Some(LEGACY_WORKER) =>
        {
            Some(route.clone())
        }
        _ => {
            return Err(format!(
                "legacy Worker route ownership is ambiguous or drifted: observed {:?}",
                route_matches
            ));
        }
    };

    let scripts = cloudflare::list_worker_scripts(&inputs.historical_token, account_id).await?;
    let script_matches = scripts
        .into_iter()
        .filter(|script| script.id == LEGACY_WORKER)
        .collect::<Vec<_>>();
    let worker_script = match script_matches.as_slice() {
        [] => None,
        [script] => Some(script.clone()),
        _ => {
            return Err(format!(
                "legacy Worker script identity is ambiguous: observed {} matches",
                script_matches.len()
            ));
        }
    };

    let worker_domains =
        cloudflare::list_worker_domains(&inputs.historical_token, account_id).await?;
    let worker_domains_referencing_legacy_script = worker_domains
        .into_iter()
        .filter(|domain| domain.service == LEGACY_WORKER)
        .collect::<Vec<_>>();

    Ok(HistoricalObservation {
        account_id: account_id.to_owned(),
        production_node,
        legacy_vultr_node,
        mesh_profile,
        worker_route,
        worker_script,
        worker_domains_referencing_legacy_script,
    })
}

async fn exact_node(
    token: &str,
    account_id: &str,
    expected_name: &str,
    mut nodes: Vec<CloudflareMeshNode>,
) -> Result<Option<HistoricalNodeObservation>, String> {
    if nodes.len() > 1 {
        return Err(format!(
            "historical Mesh node {expected_name} is ambiguous: observed {} matches",
            nodes.len()
        ));
    }
    let Some(node) = nodes.pop() else {
        return Ok(None);
    };
    if node.name != expected_name {
        return Err(format!(
            "historical Mesh node name drifted: expected {expected_name}, observed {}",
            node.name
        ));
    }
    let routes = cloudflare::list_mesh_routes(token, account_id, &node.id).await?;
    Ok(Some(HistoricalNodeObservation { node, routes }))
}

async fn validate_historical_profile(
    inputs: &Inputs,
    profile: &CloudflareDeviceProfile,
) -> Result<(), String> {
    let desired = &inputs.production.cloudflare.target_plane;
    if profile.name != desired.mesh_profile_name
        || profile.description.as_deref() != Some(desired.mesh_profile_description.as_str())
        || profile.enabled != Some(true)
        || profile.service_mode.as_deref() != Some(desired.mesh_profile_service_mode.as_str())
        || profile.tunnel_protocol.as_deref()
            != Some(desired.mesh_profile_tunnel_protocol.as_str())
        || profile.auto_connect != Some(desired.mesh_profile_auto_connect)
        || profile.switch_locked != Some(desired.mesh_profile_switch_locked)
    {
        return Err(
            "historical Mesh profile no longer matches the accepted project-owned identity"
                .to_owned(),
        );
    }
    Ok(())
}

fn next_action(observed: &HistoricalObservation) -> Result<HistoricalAction, String> {
    if let Some(node) = &observed.production_node {
        if node.routes.len() > 1 {
            return Err(format!(
                "historical production Mesh node has {} routes; broad cleanup is forbidden",
                node.routes.len()
            ));
        }
        if let Some(route) = node.routes.first() {
            if route.network != LEGACY_ROUTE_NETWORK
                || route.tunnel_type.as_deref() != Some("warp_connector")
            {
                return Err(format!(
                    "historical production Mesh route ownership drifted: {:?}",
                    route
                ));
            }
            return Ok(HistoricalAction::DeleteProductionMeshRoute {
                route_id: route.id.clone(),
            });
        }
        return Ok(HistoricalAction::DeleteProductionMeshNode {
            node_id: node.node.id.clone(),
        });
    }

    if let Some(node) = &observed.legacy_vultr_node {
        if !node.routes.is_empty() {
            return Err(
                "legacy vultr Mesh node unexpectedly owns routes; deletion is blocked".to_owned(),
            );
        }
        if node.node.status.as_deref() == Some("healthy") {
            return Err(
                "legacy vultr Mesh node is healthy/active; deletion is blocked".to_owned(),
            );
        }
        return Ok(HistoricalAction::DeleteLegacyVultrNode {
            node_id: node.node.id.clone(),
        });
    }

    if let Some(profile) = &observed.mesh_profile {
        return Ok(HistoricalAction::DeleteMeshProfile {
            profile_id: profile.profile.id.clone(),
        });
    }

    if let Some(route) = &observed.worker_route {
        return Ok(HistoricalAction::DeleteLegacyWorkerRoute {
            route_id: route.id.clone(),
        });
    }

    if observed.worker_script.is_some() {
        if !observed.worker_domains_referencing_legacy_script.is_empty() {
            return Err(format!(
                "legacy Worker still has {} custom-domain reference(s); deletion is blocked",
                observed.worker_domains_referencing_legacy_script.len()
            ));
        }
        return Ok(HistoricalAction::DeleteLegacyWorkerScript);
    }

    Ok(HistoricalAction::Noop)
}

async fn execute_once(inputs: &Inputs, action: &HistoricalAction) -> Result<(), String> {
    match action {
        HistoricalAction::Noop => Ok(()),
        HistoricalAction::DeleteProductionMeshRoute { route_id } => {
            cloudflare::delete_mesh_cidr_route(
                &inputs.historical_token,
                inputs.historical_account_id(),
                route_id,
            )
            .await
        }
        HistoricalAction::DeleteProductionMeshNode { node_id }
        | HistoricalAction::DeleteLegacyVultrNode { node_id } => {
            cloudflare::delete_mesh_node(
                &inputs.historical_token,
                inputs.historical_account_id(),
                node_id,
            )
            .await
        }
        HistoricalAction::DeleteMeshProfile { profile_id } => {
            cloudflare::delete_device_profile(
                &inputs.historical_token,
                inputs.historical_account_id(),
                profile_id,
            )
            .await
        }
        HistoricalAction::DeleteLegacyWorkerRoute { route_id } => {
            cloudflare::delete_worker_route(&inputs.dns_token, inputs.zone_name(), route_id).await
        }
        HistoricalAction::DeleteLegacyWorkerScript => {
            cloudflare::delete_worker_script(
                &inputs.historical_token,
                inputs.historical_account_id(),
                LEGACY_WORKER,
            )
            .await
        }
    }
}

fn print_state(
    status: &str,
    mutations: u32,
    observation: &HistoricalObservation,
    action: &HistoricalAction,
) {
    println!("historical_retirement_status={status}");
    println!("historical_account_id={}", observation.account_id);
    println!("mutations_performed={mutations}");
    println!("next_action={}", action_name(action));
    println!(
        "production_mesh_node_present={}",
        observation.production_node.is_some()
    );
    println!(
        "legacy_vultr_node_present={}",
        observation.legacy_vultr_node.is_some()
    );
    println!(
        "historical_mesh_profile_present={}",
        observation.mesh_profile.is_some()
    );
    println!(
        "legacy_worker_route_present={}",
        observation.worker_route.is_some()
    );
    println!(
        "legacy_worker_script_present={}",
        observation.worker_script.is_some()
    );
    println!(
        "legacy_worker_domain_references={}",
        observation.worker_domains_referencing_legacy_script.len()
    );
}

fn action_name(action: &HistoricalAction) -> &'static str {
    match action {
        HistoricalAction::Noop => "NOOP",
        HistoricalAction::DeleteProductionMeshRoute { .. } => "DELETE_PRODUCTION_MESH_ROUTE",
        HistoricalAction::DeleteProductionMeshNode { .. } => "DELETE_PRODUCTION_MESH_NODE",
        HistoricalAction::DeleteLegacyVultrNode { .. } => "DELETE_LEGACY_VULTR_NODE",
        HistoricalAction::DeleteMeshProfile { .. } => "DELETE_HISTORICAL_MESH_PROFILE",
        HistoricalAction::DeleteLegacyWorkerRoute { .. } => "DELETE_LEGACY_WORKER_ROUTE",
        HistoricalAction::DeleteLegacyWorkerScript => "DELETE_LEGACY_WORKER_SCRIPT",
    }
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must be non-empty"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, id: &str, status: Option<&str>) -> CloudflareMeshNode {
        CloudflareMeshNode {
            id: id.to_owned(),
            name: name.to_owned(),
            status: status.map(ToOwned::to_owned),
        }
    }

    fn observation() -> HistoricalObservation {
        HistoricalObservation {
            account_id: "historical".to_owned(),
            production_node: Some(HistoricalNodeObservation {
                node: node(LEGACY_PRODUCTION_NODE, "prod-node", Some("healthy")),
                routes: vec![CloudflareMeshRoute {
                    id: "route".to_owned(),
                    network: LEGACY_ROUTE_NETWORK.to_owned(),
                    tunnel_id: "prod-node".to_owned(),
                    tunnel_type: Some("warp_connector".to_owned()),
                    comment: Some("managed-by-sing-box:line3:production".to_owned()),
                }],
            }),
            legacy_vultr_node: Some(HistoricalNodeObservation {
                node: node(LEGACY_VULTR_NODE, "vultr-node", Some("inactive")),
                routes: vec![],
            }),
            mesh_profile: None,
            worker_route: None,
            worker_script: None,
            worker_domains_referencing_legacy_script: vec![],
        }
    }

    #[test]
    fn retirement_order_is_route_before_nodes() {
        let observed = observation();
        let action = next_action(&observed).unwrap();
        assert!(matches!(
            action,
            HistoricalAction::DeleteProductionMeshRoute { .. }
        ));

        let mut observed = observed;
        observed.production_node.as_mut().unwrap().routes.clear();
        let action = next_action(&observed).unwrap();
        assert!(matches!(
            action,
            HistoricalAction::DeleteProductionMeshNode { .. }
        ));

        observed.production_node = None;
        let action = next_action(&observed).unwrap();
        assert!(matches!(
            action,
            HistoricalAction::DeleteLegacyVultrNode { .. }
        ));
    }

    #[test]
    fn healthy_legacy_vultr_node_fails_closed() {
        let mut observed = observation();
        observed.production_node = None;
        observed.legacy_vultr_node.as_mut().unwrap().node.status = Some("healthy".to_owned());
        assert!(next_action(&observed).is_err());
    }

    #[test]
    fn unrelated_worker_domain_blocks_script_delete() {
        let mut observed = observation();
        observed.production_node = None;
        observed.legacy_vultr_node = None;
        observed.worker_script = Some(CloudflareWorkerScript {
            id: LEGACY_WORKER.to_owned(),
        });
        observed
            .worker_domains_referencing_legacy_script
            .push(CloudflareWorkerDomain {
                id: "domain".to_owned(),
                hostname: "legacy.example".to_owned(),
                service: LEGACY_WORKER.to_owned(),
                zone_id: "zone".to_owned(),
                zone_name: "example".to_owned(),
            });
        assert!(next_action(&observed).is_err());
    }

}
