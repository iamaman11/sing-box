use edge_controller_core::cloudflare_mesh_lifecycle::{
    ApplyAction, ApplyPlan, CleanupAction, CleanupPlan, DesiredMeshState, MeshObservation,
    ObservedMeshNode, ObservedMeshRoute, plan_apply, plan_cleanup, verify_cleanup_digest,
};
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_provider_cloudflare::{
    CloudflareMeshNode, CloudflareMeshRoute, create_mesh_cidr_route, create_mesh_node,
    delete_mesh_cidr_route, delete_mesh_node, get_mesh_node_token, list_mesh_nodes,
    list_mesh_routes,
};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, Copy)]
pub struct MeshExecutionPolicy {
    pub reobserve_attempts: usize,
    pub reobserve_delay: Duration,
}

impl Default for MeshExecutionPolicy {
    fn default() -> Self {
        Self {
            reobserve_attempts: 30,
            reobserve_delay: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MeshApplyReport {
    pub performed: ApplyAction,
    pub observation: MeshObservation,
    pub next_plan: ApplyPlan,
}

#[derive(Debug, Clone)]
pub struct MeshCleanupReport {
    pub performed: CleanupAction,
    pub observation: MeshObservation,
    pub next_plan: CleanupPlan,
}

#[allow(async_fn_in_trait)]
pub trait MeshProvider {
    async fn list_nodes(&mut self, exact_name: &str) -> Result<Vec<CloudflareMeshNode>, String>;
    async fn list_routes(&mut self, node_id: &str) -> Result<Vec<CloudflareMeshRoute>, String>;
    async fn create_node(&mut self, name: &str) -> Result<CloudflareMeshNode, String>;
    async fn create_route(
        &mut self,
        node_id: &str,
        network: &str,
        comment: &str,
    ) -> Result<CloudflareMeshRoute, String>;
    async fn delete_route(&mut self, route_id: &str) -> Result<(), String>;
    async fn delete_node(&mut self, node_id: &str) -> Result<(), String>;
    async fn get_node_token(&mut self, node_id: &str) -> Result<String, String>;
}

pub struct CloudflareMeshApiProvider {
    api_token: String,
    account_id: String,
}

impl CloudflareMeshApiProvider {
    pub fn new(api_token: String, account_id: String) -> Result<Self, String> {
        if api_token.trim().is_empty() {
            return Err("CLOUDFLARE_API_TOKEN must be non-empty".to_owned());
        }
        if account_id.trim().is_empty() {
            return Err("CLOUDFLARE_ACCOUNT_ID must be non-empty".to_owned());
        }
        Ok(Self {
            api_token,
            account_id,
        })
    }
}

impl MeshProvider for CloudflareMeshApiProvider {
    async fn list_nodes(&mut self, exact_name: &str) -> Result<Vec<CloudflareMeshNode>, String> {
        list_mesh_nodes(&self.api_token, &self.account_id, Some(exact_name)).await
    }

    async fn list_routes(&mut self, node_id: &str) -> Result<Vec<CloudflareMeshRoute>, String> {
        list_mesh_routes(&self.api_token, &self.account_id, node_id).await
    }

    async fn create_node(&mut self, name: &str) -> Result<CloudflareMeshNode, String> {
        create_mesh_node(&self.api_token, &self.account_id, name).await
    }

    async fn create_route(
        &mut self,
        node_id: &str,
        network: &str,
        comment: &str,
    ) -> Result<CloudflareMeshRoute, String> {
        create_mesh_cidr_route(
            &self.api_token,
            &self.account_id,
            node_id,
            network,
            Some(comment),
        )
        .await
    }

    async fn delete_route(&mut self, route_id: &str) -> Result<(), String> {
        delete_mesh_cidr_route(&self.api_token, &self.account_id, route_id).await
    }

    async fn delete_node(&mut self, node_id: &str) -> Result<(), String> {
        delete_mesh_node(&self.api_token, &self.account_id, node_id).await
    }

    async fn get_node_token(&mut self, node_id: &str) -> Result<String, String> {
        get_mesh_node_token(&self.api_token, &self.account_id, node_id).await
    }
}

pub async fn observe_mesh<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
) -> Result<MeshObservation, String> {
    desired.validate().map_err(|err| err.to_string())?;
    let nodes = provider.list_nodes(&desired.node_name).await?;
    let routes = if nodes.len() == 1 {
        provider.list_routes(&nodes[0].id).await?
    } else {
        Vec::new()
    };
    Ok(MeshObservation {
        nodes: nodes.into_iter().map(observed_node).collect(),
        routes: routes.into_iter().map(observed_route).collect(),
    })
}

pub async fn plan_mesh_apply<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
) -> Result<(MeshObservation, ApplyPlan), String> {
    let observed = observe_mesh(provider, desired).await?;
    let plan = plan_apply(desired, &observed).map_err(|err| err.to_string())?;
    Ok((observed, plan))
}

pub async fn apply_mesh_once<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
    authorized_plan_digest: &str,
    policy: MeshExecutionPolicy,
) -> Result<MeshApplyReport, String> {
    validate_policy(policy)?;
    let (before, plan) = plan_mesh_apply(provider, desired).await?;
    let authorized = authorize_mesh_apply(desired, &before, plan.clone())?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;
    match plan.action.clone() {
        ApplyAction::Noop => Ok(MeshApplyReport {
            performed: ApplyAction::Noop,
            observation: before,
            next_plan: plan,
        }),
        ApplyAction::CreateNode => {
            let mutation = provider.create_node(&desired.node_name).await;
            reobserve_apply_change(
                provider,
                desired,
                policy,
                &plan.action,
                mutation.map(|_| ()),
            )
            .await
        }
        ApplyAction::CreateRoute { ref network } => {
            let node_id = plan
                .node_id
                .as_deref()
                .ok_or_else(|| "CREATE_ROUTE plan is missing node_id".to_owned())?;
            let mutation = provider
                .create_route(node_id, network, &desired.ownership_comment())
                .await;
            reobserve_apply_change(
                provider,
                desired,
                policy,
                &plan.action,
                mutation.map(|_| ()),
            )
            .await
        }
    }
}

pub async fn exact_mesh_node_token<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
) -> Result<String, String> {
    let (observed, plan) = plan_mesh_apply(provider, desired).await?;
    if plan.action != ApplyAction::Noop {
        return Err(format!(
            "Mesh runtime token requires provider desired state NOOP; observed {:?}",
            plan.action
        ));
    }
    let [node] = observed.nodes.as_slice() else {
        return Err("Mesh runtime token requires exactly one observed provider node".to_owned());
    };
    let token = provider.get_node_token(&node.provider_id).await?;
    if token.is_empty()
        || token.len() > 16 * 1024
        || token.trim() != token
        || token
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err("Cloudflare Mesh node token has an invalid bounded shape".to_owned());
    }
    Ok(token)
}

pub async fn wait_mesh_provider_healthy<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
    policy: MeshExecutionPolicy,
) -> Result<MeshObservation, String> {
    validate_policy(policy)?;
    let mut last_status = None;
    for attempt in 0..policy.reobserve_attempts {
        let (observed, plan) = plan_mesh_apply(provider, desired).await?;
        if plan.action != ApplyAction::Noop {
            return Err(format!(
                "Mesh provider desired state drifted while waiting for health: {:?}",
                plan.action
            ));
        }
        let [node] = observed.nodes.as_slice() else {
            return Err("Mesh provider health requires exactly one observed node".to_owned());
        };
        if node.status.as_deref() == Some("healthy") {
            return Ok(observed);
        }
        last_status = node.status.clone();
        if attempt + 1 < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }
    Err(format!(
        "Cloudflare Mesh node did not become healthy after bounded re-observation; last_status={}",
        last_status.as_deref().unwrap_or("missing")
    ))
}

pub async fn plan_mesh_cleanup<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
) -> Result<(MeshObservation, CleanupPlan), String> {
    let observed = observe_mesh(provider, desired).await?;
    let plan = plan_cleanup(desired, &observed).map_err(|err| err.to_string())?;
    Ok((observed, plan))
}

pub fn authorize_mesh_apply(
    desired: &DesiredMeshState,
    observed: &MeshObservation,
    plan: ApplyPlan,
) -> Result<AuthorizedPlan<ApplyPlan>, String> {
    let disposition = if matches!(plan.action, ApplyAction::Noop) {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    authorize_plan(
        "cloudflare_mesh_apply",
        desired,
        observed,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub fn authorize_mesh_cleanup(
    desired: &DesiredMeshState,
    observed: &MeshObservation,
    plan: CleanupPlan,
) -> Result<AuthorizedPlan<CleanupPlan>, String> {
    let disposition = if matches!(plan.action, CleanupAction::Noop) {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    authorize_plan(
        "cloudflare_mesh_cleanup",
        desired,
        observed,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub async fn cleanup_mesh_once<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
    expected_digest: &str,
    authorized_plan_digest: &str,
    policy: MeshExecutionPolicy,
) -> Result<MeshCleanupReport, String> {
    validate_policy(policy)?;
    let observed = observe_mesh(provider, desired).await?;
    let current = plan_cleanup(desired, &observed).map_err(|err| err.to_string())?;
    let authorized = authorize_mesh_cleanup(desired, &observed, current.clone())?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;
    let plan = verify_cleanup_digest(desired, &observed, expected_digest)
        .map_err(|err| err.to_string())?;
    if current != plan {
        return Err("Cloudflare Mesh cleanup authorization changed during planning".to_owned());
    }
    let action = plan.action.clone();

    let mutation = match &action {
        CleanupAction::Noop => {
            return Err("Cloudflare Mesh cleanup target is already absent".to_owned());
        }
        CleanupAction::DeleteRoute { route_id, .. } => provider.delete_route(route_id).await,
        CleanupAction::DeleteNode { node_id } => provider.delete_node(node_id).await,
    };

    reobserve_cleanup_change(provider, desired, policy, &action, mutation).await
}

async fn reobserve_apply_change<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
    policy: MeshExecutionPolicy,
    performed: &ApplyAction,
    mutation: Result<(), String>,
) -> Result<MeshApplyReport, String> {
    let mutation_error = mutation.err();
    let mut last_observation = None;
    let mut last_plan = None;

    for attempt in 0..policy.reobserve_attempts {
        let observed = observe_mesh(provider, desired).await?;
        let next_plan = plan_apply(desired, &observed).map_err(|err| err.to_string())?;
        if apply_action_completed(performed, &next_plan) {
            return Ok(MeshApplyReport {
                performed: performed.clone(),
                observation: observed,
                next_plan,
            });
        }
        last_observation = Some(observed);
        last_plan = Some(next_plan);
        if attempt + 1 < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }

    let detail = mutation_error.unwrap_or_else(|| "mutation returned success".to_owned());
    Err(format!(
        "Cloudflare Mesh {:?} did not become observable after bounded re-observation ({detail}); mutation was not replayed; last_plan={:?}; last_observation={:?}",
        performed, last_plan, last_observation
    ))
}

async fn reobserve_cleanup_change<P: MeshProvider>(
    provider: &mut P,
    desired: &DesiredMeshState,
    policy: MeshExecutionPolicy,
    performed: &CleanupAction,
    mutation: Result<(), String>,
) -> Result<MeshCleanupReport, String> {
    let mutation_error = mutation.err();
    let mut last_observation = None;
    let mut last_plan = None;

    for attempt in 0..policy.reobserve_attempts {
        let observed = observe_mesh(provider, desired).await?;
        let next_plan = plan_cleanup(desired, &observed).map_err(|err| err.to_string())?;
        if cleanup_action_completed(performed, &observed) {
            return Ok(MeshCleanupReport {
                performed: performed.clone(),
                observation: observed,
                next_plan,
            });
        }
        last_observation = Some(observed);
        last_plan = Some(next_plan);
        if attempt + 1 < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }

    let detail = mutation_error.unwrap_or_else(|| "mutation returned success".to_owned());
    Err(format!(
        "Cloudflare Mesh {:?} did not become observable after bounded re-observation ({detail}); mutation was not replayed; last_plan={:?}; last_observation={:?}",
        performed, last_plan, last_observation
    ))
}

fn apply_action_completed(performed: &ApplyAction, next_plan: &ApplyPlan) -> bool {
    match (performed, &next_plan.action) {
        (ApplyAction::CreateNode, ApplyAction::CreateNode) => false,
        (
            ApplyAction::CreateRoute { network: expected },
            ApplyAction::CreateRoute { network: next },
        ) if expected == next => false,
        _ => true,
    }
}

fn cleanup_action_completed(performed: &CleanupAction, observed: &MeshObservation) -> bool {
    match performed {
        CleanupAction::Noop => true,
        CleanupAction::DeleteRoute { route_id, .. } => observed
            .routes
            .iter()
            .all(|route| route.provider_id != *route_id),
        CleanupAction::DeleteNode { node_id } => observed
            .nodes
            .iter()
            .all(|node| node.provider_id != *node_id),
    }
}

fn validate_policy(policy: MeshExecutionPolicy) -> Result<(), String> {
    if policy.reobserve_attempts == 0 {
        return Err("Cloudflare Mesh re-observation attempts must be greater than zero".to_owned());
    }
    Ok(())
}

fn observed_node(node: CloudflareMeshNode) -> ObservedMeshNode {
    ObservedMeshNode {
        provider_id: node.id,
        name: node.name,
        status: node.status,
    }
}

fn observed_route(route: CloudflareMeshRoute) -> ObservedMeshRoute {
    ObservedMeshRoute {
        provider_id: route.id,
        network: route.network,
        tunnel_id: route.tunnel_id,
        tunnel_type: route.tunnel_type,
        comment: route.comment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeProvider {
        nodes: Vec<CloudflareMeshNode>,
        routes: Vec<CloudflareMeshRoute>,
        create_node_calls: usize,
        create_route_calls: usize,
        delete_route_calls: usize,
        delete_node_calls: usize,
        create_node_error: Option<String>,
        create_route_error: Option<String>,
        commit_node_on_error: bool,
        commit_route_on_error: bool,
    }

    impl MeshProvider for FakeProvider {
        async fn list_nodes(
            &mut self,
            exact_name: &str,
        ) -> Result<Vec<CloudflareMeshNode>, String> {
            Ok(self
                .nodes
                .iter()
                .filter(|node| node.name == exact_name)
                .cloned()
                .collect())
        }

        async fn list_routes(&mut self, node_id: &str) -> Result<Vec<CloudflareMeshRoute>, String> {
            Ok(self
                .routes
                .iter()
                .filter(|route| route.tunnel_id == node_id)
                .cloned()
                .collect())
        }

        async fn create_node(&mut self, name: &str) -> Result<CloudflareMeshNode, String> {
            self.create_node_calls += 1;
            let node = CloudflareMeshNode {
                id: "node-1".to_owned(),
                name: name.to_owned(),
                status: Some("healthy".to_owned()),
            };
            if self.create_node_error.is_none() || self.commit_node_on_error {
                self.nodes.push(node.clone());
            }
            match self.create_node_error.clone() {
                Some(error) => Err(error),
                None => Ok(node),
            }
        }

        async fn create_route(
            &mut self,
            node_id: &str,
            network: &str,
            comment: &str,
        ) -> Result<CloudflareMeshRoute, String> {
            self.create_route_calls += 1;
            let route = CloudflareMeshRoute {
                id: format!("route-{}", self.create_route_calls),
                network: network.to_owned(),
                tunnel_id: node_id.to_owned(),
                tunnel_type: Some("warp_connector".to_owned()),
                comment: Some(comment.to_owned()),
            };
            if self.create_route_error.is_none() || self.commit_route_on_error {
                self.routes.push(route.clone());
            }
            match self.create_route_error.clone() {
                Some(error) => Err(error),
                None => Ok(route),
            }
        }

        async fn delete_route(&mut self, route_id: &str) -> Result<(), String> {
            self.delete_route_calls += 1;
            self.routes.retain(|route| route.id != route_id);
            Ok(())
        }

        async fn delete_node(&mut self, node_id: &str) -> Result<(), String> {
            self.delete_node_calls += 1;
            self.nodes.retain(|node| node.id != node_id);
            Ok(())
        }

        async fn get_node_token(&mut self, node_id: &str) -> Result<String, String> {
            if self.nodes.iter().any(|node| node.id == node_id) {
                Ok("opaque-mesh-node-token".to_owned())
            } else {
                Err("node is absent".to_owned())
            }
        }
    }

    fn desired(routes: &[&str]) -> DesiredMeshState {
        DesiredMeshState {
            schema: 1,
            account_id: "0123456789abcdef0123456789abcdef".to_owned(),
            environment: "poc".to_owned(),
            node_name: "singbox-line3-poc".to_owned(),
            routes: routes
                .iter()
                .map(
                    |network| edge_controller_core::cloudflare_mesh_lifecycle::MeshRouteSpec {
                        network: (*network).to_owned(),
                    },
                )
                .collect(),
        }
    }

    fn policy() -> MeshExecutionPolicy {
        MeshExecutionPolicy {
            reobserve_attempts: 2,
            reobserve_delay: Duration::ZERO,
        }
    }

    async fn apply_authority(provider: &mut FakeProvider, desired: &DesiredMeshState) -> String {
        let (observed, plan) = plan_mesh_apply(provider, desired).await.unwrap();
        authorize_mesh_apply(desired, &observed, plan)
            .unwrap()
            .authority
            .authority_digest
    }

    async fn cleanup_authority(
        provider: &mut FakeProvider,
        desired: &DesiredMeshState,
    ) -> (String, String) {
        let (observed, plan) = plan_mesh_cleanup(provider, desired).await.unwrap();
        let destructive = plan.destructive_digest.clone().unwrap();
        let generic = authorize_mesh_cleanup(desired, &observed, plan)
            .unwrap()
            .authority
            .authority_digest;
        (destructive, generic)
    }

    #[tokio::test]
    async fn create_node_is_one_shot_and_observed() {
        let desired = desired(&[]);
        let mut provider = FakeProvider::default();
        let authority = apply_authority(&mut provider, &desired).await;
        let report = apply_mesh_once(&mut provider, &desired, &authority, policy())
            .await
            .unwrap();
        assert_eq!(provider.create_node_calls, 1);
        assert_eq!(report.performed, ApplyAction::CreateNode);
        assert_eq!(report.next_plan.action, ApplyAction::Noop);
    }

    #[tokio::test]
    async fn uncertain_node_create_recovers_by_observation_without_replay() {
        let mut provider = FakeProvider {
            create_node_error: Some("simulated response loss".to_owned()),
            commit_node_on_error: true,
            ..FakeProvider::default()
        };
        let desired = desired(&[]);
        let authority = apply_authority(&mut provider, &desired).await;
        let report = apply_mesh_once(&mut provider, &desired, &authority, policy())
            .await
            .unwrap();
        assert_eq!(provider.create_node_calls, 1);
        assert_eq!(report.next_plan.action, ApplyAction::Noop);
    }

    #[tokio::test]
    async fn route_create_is_one_shot_and_observed() {
        let mut provider = FakeProvider {
            nodes: vec![CloudflareMeshNode {
                id: "node-1".to_owned(),
                name: "singbox-line3-poc".to_owned(),
                status: Some("healthy".to_owned()),
            }],
            ..FakeProvider::default()
        };
        let desired = desired(&["1.1.1.1/32"]);
        let authority = apply_authority(&mut provider, &desired).await;
        let report = apply_mesh_once(&mut provider, &desired, &authority, policy())
            .await
            .unwrap();
        assert_eq!(provider.create_route_calls, 1);
        assert_eq!(
            report.performed,
            ApplyAction::CreateRoute {
                network: "1.1.1.1/32".to_owned()
            }
        );
        assert_eq!(report.next_plan.action, ApplyAction::Noop);
    }

    #[tokio::test]
    async fn stale_apply_authority_rejects_without_mutation() {
        let desired = desired(&[]);
        let mut provider = FakeProvider::default();
        let authority = apply_authority(&mut provider, &desired).await;
        provider.nodes.push(CloudflareMeshNode {
            id: "node-foreign".to_owned(),
            name: desired.node_name.clone(),
            status: Some("healthy".to_owned()),
        });

        let error = apply_mesh_once(&mut provider, &desired, &authority, policy())
            .await
            .unwrap_err();

        assert!(error.contains("stale"));
        assert_eq!(provider.create_node_calls, 0);
        assert_eq!(provider.create_route_calls, 0);
    }

    #[tokio::test]
    async fn token_requires_exact_topology_but_not_pre_runtime_health() {
        let desired = desired(&[]);
        let mut provider = FakeProvider {
            nodes: vec![CloudflareMeshNode {
                id: "node-1".to_owned(),
                name: "singbox-line3-poc".to_owned(),
                status: Some("inactive".to_owned()),
            }],
            ..FakeProvider::default()
        };

        let (_observed, plan) = plan_mesh_apply(&mut provider, &desired).await.unwrap();
        assert_eq!(plan.action, ApplyAction::Noop);
        assert_eq!(
            exact_mesh_node_token(&mut provider, &desired)
                .await
                .unwrap(),
            "opaque-mesh-node-token"
        );
        assert!(
            wait_mesh_provider_healthy(&mut provider, &desired, policy())
                .await
                .is_err()
        );

        let mut missing = FakeProvider::default();
        assert!(exact_mesh_node_token(&mut missing, &desired).await.is_err());
    }

    #[tokio::test]
    async fn provider_health_requires_healthy_status_and_no_drift() {
        let mut provider = FakeProvider {
            nodes: vec![CloudflareMeshNode {
                id: "node-1".to_owned(),
                name: "singbox-line3-poc".to_owned(),
                status: Some("healthy".to_owned()),
            }],
            ..FakeProvider::default()
        };
        wait_mesh_provider_healthy(&mut provider, &desired(&[]), policy())
            .await
            .unwrap();

        provider.nodes[0].status = Some("degraded".to_owned());
        assert!(
            wait_mesh_provider_healthy(&mut provider, &desired(&[]), policy())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stale_cleanup_digest_never_mutates() {
        let desired = desired(&[]);
        let mut provider = FakeProvider {
            nodes: vec![CloudflareMeshNode {
                id: "node-1".to_owned(),
                name: "singbox-line3-poc".to_owned(),
                status: Some("healthy".to_owned()),
            }],
            ..FakeProvider::default()
        };
        let (_, authority) = cleanup_authority(&mut provider, &desired).await;
        let error = cleanup_mesh_once(
            &mut provider,
            &desired,
            &"0".repeat(64),
            &authority,
            policy(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("stale"));
        assert_eq!(provider.delete_node_calls, 0);
        assert_eq!(provider.delete_route_calls, 0);
    }

    #[tokio::test]
    async fn cleanup_deletes_one_resource_per_call() {
        let desired = desired(&["1.1.1.1/32"]);
        let ownership = desired.ownership_comment();
        let mut provider = FakeProvider {
            nodes: vec![CloudflareMeshNode {
                id: "node-1".to_owned(),
                name: "singbox-line3-poc".to_owned(),
                status: Some("healthy".to_owned()),
            }],
            routes: vec![CloudflareMeshRoute {
                id: "route-1".to_owned(),
                network: "1.1.1.1/32".to_owned(),
                tunnel_id: "node-1".to_owned(),
                tunnel_type: Some("warp_connector".to_owned()),
                comment: Some(ownership),
            }],
            ..FakeProvider::default()
        };

        let (digest, authority) = cleanup_authority(&mut provider, &desired).await;
        let report = cleanup_mesh_once(&mut provider, &desired, &digest, &authority, policy())
            .await
            .unwrap();

        assert_eq!(provider.delete_route_calls, 1);
        assert_eq!(provider.delete_node_calls, 0);
        assert!(matches!(
            report.next_plan.action,
            CleanupAction::DeleteNode { .. }
        ));
    }
}
