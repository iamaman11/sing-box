use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const CURRENT_SCHEMA: u32 = 1;
pub const NODE_NAME_PREFIX: &str = "singbox-line3-";
const OWNERSHIP_COMMENT_PREFIX: &str = "managed-by-sing-box:line3:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredMeshState {
    pub schema: u32,
    pub account_id: String,
    pub environment: String,
    pub node_name: String,
    #[serde(default)]
    pub routes: Vec<MeshRouteSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRouteSpec {
    pub network: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedMeshNode {
    pub provider_id: String,
    pub name: String,
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedMeshRoute {
    pub provider_id: String,
    pub network: String,
    pub tunnel_id: String,
    pub tunnel_type: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MeshObservation {
    pub nodes: Vec<ObservedMeshNode>,
    pub routes: Vec<ObservedMeshRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplyAction {
    Noop,
    CreateNode,
    CreateRoute { network: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPlan {
    pub action: ApplyAction,
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CleanupAction {
    Noop,
    DeleteRoute {
        route_id: String,
        network: String,
    },
    DeleteNode {
        node_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupPlan {
    pub action: CleanupAction,
    pub destructive_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshLifecycleError {
    Json(String),
    UnsupportedSchema(u32),
    Validation(String),
    Ambiguous(String),
    Conflict(String),
    Serialization(String),
}

impl fmt::Display for MeshLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message)
            | Self::Validation(message)
            | Self::Ambiguous(message)
            | Self::Conflict(message)
            | Self::Serialization(message) => f.write_str(message),
            Self::UnsupportedSchema(schema) => {
                write!(f, "unsupported Cloudflare Mesh lifecycle schema {schema}")
            }
        }
    }
}

impl std::error::Error for MeshLifecycleError {}

impl DesiredMeshState {
    pub fn parse_json(input: &str) -> Result<Self, MeshLifecycleError> {
        let desired: Self =
            serde_json::from_str(input).map_err(|err| MeshLifecycleError::Json(err.to_string()))?;
        desired.validate()?;
        Ok(desired)
    }

    pub fn validate(&self) -> Result<(), MeshLifecycleError> {
        if self.schema != CURRENT_SCHEMA {
            return Err(MeshLifecycleError::UnsupportedSchema(self.schema));
        }
        validate_account_id(&self.account_id)?;
        validate_identifier("environment", &self.environment, 64)?;
        validate_identifier("node_name", &self.node_name, 128)?;
        if !self.node_name.starts_with(NODE_NAME_PREFIX) {
            return Err(MeshLifecycleError::Validation(format!(
                "Cloudflare Mesh node_name must start with {NODE_NAME_PREFIX}"
            )));
        }

        let comment = self.ownership_comment();
        if comment.len() > 100 {
            return Err(MeshLifecycleError::Validation(
                "derived Cloudflare Mesh ownership comment exceeds 100 characters".to_owned(),
            ));
        }

        let mut networks = BTreeSet::new();
        for route in &self.routes {
            let canonical = canonical_network(&route.network)?;
            if canonical != route.network {
                return Err(MeshLifecycleError::Validation(format!(
                    "Cloudflare Mesh route {} is not canonical; use {canonical}",
                    route.network
                )));
            }
            if !networks.insert(route.network.clone()) {
                return Err(MeshLifecycleError::Validation(format!(
                    "duplicate Cloudflare Mesh route {}",
                    route.network
                )));
            }
        }
        Ok(())
    }

    pub fn ownership_comment(&self) -> String {
        format!("{OWNERSHIP_COMMENT_PREFIX}{}", self.environment)
    }
}

pub fn plan_apply(
    desired: &DesiredMeshState,
    observed: &MeshObservation,
) -> Result<ApplyPlan, MeshLifecycleError> {
    desired.validate()?;
    let node = select_exact_node(desired, observed)?;
    let Some(node) = node else {
        return Ok(ApplyPlan {
            action: ApplyAction::CreateNode,
            node_id: None,
        });
    };

    let routes = exact_node_routes(desired, observed, node)?;
    let ownership = desired.ownership_comment();
    let desired_networks = desired
        .routes
        .iter()
        .map(|route| route.network.as_str())
        .collect::<BTreeSet<_>>();

    for route in &routes {
        if route.comment.as_deref() != Some(ownership.as_str()) {
            return Err(MeshLifecycleError::Conflict(format!(
                "Cloudflare Mesh node {} has foreign route {} ({})",
                desired.node_name, route.provider_id, route.network
            )));
        }
        if !desired_networks.contains(route.network.as_str()) {
            return Err(MeshLifecycleError::Conflict(format!(
                "Cloudflare Mesh node {} has managed route {} not present in desired state; remove it through cleanup before changing the route set",
                desired.node_name, route.network
            )));
        }
    }

    for desired_route in &desired.routes {
        let matches = routes
            .iter()
            .filter(|route| route.network == desired_route.network)
            .collect::<Vec<_>>();
        match matches.len() {
            0 => {
                return Ok(ApplyPlan {
                    action: ApplyAction::CreateRoute {
                        network: desired_route.network.clone(),
                    },
                    node_id: Some(node.provider_id.clone()),
                });
            }
            1 => {}
            count => {
                return Err(MeshLifecycleError::Ambiguous(format!(
                    "Cloudflare Mesh route {} is ambiguous on node {}: observed {count} matches",
                    desired_route.network, desired.node_name
                )));
            }
        }
    }

    Ok(ApplyPlan {
        action: ApplyAction::Noop,
        node_id: Some(node.provider_id.clone()),
    })
}

pub fn plan_cleanup(
    desired: &DesiredMeshState,
    observed: &MeshObservation,
) -> Result<CleanupPlan, MeshLifecycleError> {
    desired.validate()?;
    let node = select_exact_node(desired, observed)?;
    let Some(node) = node else {
        return Ok(CleanupPlan {
            action: CleanupAction::Noop,
            destructive_digest: None,
        });
    };

    let mut routes = exact_node_routes(desired, observed, node)?;
    let ownership = desired.ownership_comment();
    for route in &routes {
        if route.comment.as_deref() != Some(ownership.as_str()) {
            return Err(MeshLifecycleError::Conflict(format!(
                "refusing Cloudflare Mesh cleanup because node {} has foreign route {} ({})",
                desired.node_name, route.provider_id, route.network
            )));
        }
    }
    routes.sort_by(|left, right| {
        left.network
            .cmp(&right.network)
            .then_with(|| left.provider_id.cmp(&right.provider_id))
    });

    let action = match routes.first() {
        Some(route) => CleanupAction::DeleteRoute {
            route_id: route.provider_id.clone(),
            network: route.network.clone(),
        },
        None => CleanupAction::DeleteNode {
            node_id: node.provider_id.clone(),
        },
    };
    let destructive_digest = Some(cleanup_digest(desired, observed, &action)?);
    Ok(CleanupPlan {
        action,
        destructive_digest,
    })
}

pub fn verify_cleanup_digest(
    desired: &DesiredMeshState,
    observed: &MeshObservation,
    expected_digest: &str,
) -> Result<CleanupPlan, MeshLifecycleError> {
    if !is_sha256_hex(expected_digest) {
        return Err(MeshLifecycleError::Validation(
            "Cloudflare Mesh cleanup digest must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    let plan = plan_cleanup(desired, observed)?;
    let Some(actual) = plan.destructive_digest.as_deref() else {
        return Err(MeshLifecycleError::Conflict(
            "Cloudflare Mesh cleanup target is already absent".to_owned(),
        ));
    };
    if actual != expected_digest {
        return Err(MeshLifecycleError::Conflict(
            "Cloudflare Mesh cleanup digest is stale".to_owned(),
        ));
    }
    Ok(plan)
}

fn select_exact_node<'a>(
    desired: &DesiredMeshState,
    observed: &'a MeshObservation,
) -> Result<Option<&'a ObservedMeshNode>, MeshLifecycleError> {
    let matches = observed
        .nodes
        .iter()
        .filter(|node| node.name == desired.node_name)
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches[0])),
        count => Err(MeshLifecycleError::Ambiguous(format!(
            "Cloudflare Mesh node {} is ambiguous: observed {count} exact-name matches",
            desired.node_name
        ))),
    }
}

fn exact_node_routes<'a>(
    desired: &DesiredMeshState,
    observed: &'a MeshObservation,
    node: &ObservedMeshNode,
) -> Result<Vec<&'a ObservedMeshRoute>, MeshLifecycleError> {
    let mut routes = Vec::new();
    for route in &observed.routes {
        if route.tunnel_id != node.provider_id
            || route.tunnel_type.as_deref() != Some("warp_connector")
        {
            continue;
        }
        let canonical = canonical_network(&route.network).map_err(|err| {
            MeshLifecycleError::Conflict(format!(
                "Cloudflare Mesh node {} returned invalid route {}: {err}",
                desired.node_name, route.provider_id
            ))
        })?;
        if canonical != route.network {
            return Err(MeshLifecycleError::Conflict(format!(
                "Cloudflare Mesh node {} returned non-canonical route {}: {}",
                desired.node_name, route.provider_id, route.network
            )));
        }
        routes.push(route);
    }
    Ok(routes)
}

fn cleanup_digest(
    desired: &DesiredMeshState,
    observed: &MeshObservation,
    action: &CleanupAction,
) -> Result<String, MeshLifecycleError> {
    let mut nodes = observed
        .nodes
        .iter()
        .filter(|node| node.name == desired.node_name)
        .cloned()
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));

    let node_ids = nodes
        .iter()
        .map(|node| node.provider_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut routes = observed
        .routes
        .iter()
        .filter(|route| node_ids.contains(route.tunnel_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    routes.sort_by(|left, right| {
        left.network
            .cmp(&right.network)
            .then_with(|| left.provider_id.cmp(&right.provider_id))
    });

    let value = json!({
        "schema": desired.schema,
        "account_id": desired.account_id,
        "environment": desired.environment,
        "node_name": desired.node_name,
        "nodes": nodes,
        "routes": routes,
        "action": action,
    });
    let bytes = serde_json::to_vec(&value)
        .map_err(|err| MeshLifecycleError::Serialization(err.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn canonical_network(value: &str) -> Result<String, MeshLifecycleError> {
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        MeshLifecycleError::Validation(format!(
            "Cloudflare Mesh route {value} must use CIDR notation"
        ))
    })?;
    let address = address.parse::<IpAddr>().map_err(|err| {
        MeshLifecycleError::Validation(format!(
            "invalid Cloudflare Mesh route address {address}: {err}"
        ))
    })?;
    let prefix = prefix.parse::<u8>().map_err(|err| {
        MeshLifecycleError::Validation(format!(
            "invalid Cloudflare Mesh route prefix in {value}: {err}"
        ))
    })?;
    if prefix == 0 {
        return Err(MeshLifecycleError::Validation(format!(
            "default Cloudflare Mesh route {value} is intentionally disabled until the explicit full-Internet PoC gate"
        )));
    }

    match address {
        IpAddr::V4(ip) => {
            if prefix > 32 {
                return Err(MeshLifecycleError::Validation(format!(
                    "IPv4 Cloudflare Mesh route prefix must be <= 32: {value}"
                )));
            }
            let mask = u32::MAX << (32 - prefix);
            let network = Ipv4Addr::from(u32::from(ip) & mask);
            Ok(format!("{network}/{prefix}"))
        }
        IpAddr::V6(ip) => {
            if prefix > 128 {
                return Err(MeshLifecycleError::Validation(format!(
                    "IPv6 Cloudflare Mesh route prefix must be <= 128: {value}"
                )));
            }
            let mask = u128::MAX << (128 - prefix);
            let network = Ipv6Addr::from(u128::from(ip) & mask);
            Ok(format!("{network}/{prefix}"))
        }
    }
}

fn validate_account_id(value: &str) -> Result<(), MeshLifecycleError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MeshLifecycleError::Validation(
            "Cloudflare account_id must be exactly 32 lowercase hexadecimal characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_identifier(
    label: &str,
    value: &str,
    max_len: usize,
) -> Result<(), MeshLifecycleError> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err(MeshLifecycleError::Validation(format!(
            "{label} must be 1..={max_len} ASCII alphanumeric, '-' or '_' characters"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> DesiredMeshState {
        DesiredMeshState::parse_json(
            r#"{
  "schema": 1,
  "account_id": "0123456789abcdef0123456789abcdef",
  "environment": "poc",
  "node_name": "singbox-line3-poc",
  "routes": [
    {"network": "1.1.1.1/32"},
    {"network": "2606:4700:4700::1111/128"}
  ]
}"#,
        )
        .unwrap()
    }

    fn node() -> ObservedMeshNode {
        ObservedMeshNode {
            provider_id: "node-1".to_owned(),
            name: "singbox-line3-poc".to_owned(),
            status: Some("healthy".to_owned()),
        }
    }

    fn route(id: &str, network: &str, comment: Option<&str>) -> ObservedMeshRoute {
        ObservedMeshRoute {
            provider_id: id.to_owned(),
            network: network.to_owned(),
            tunnel_id: "node-1".to_owned(),
            tunnel_type: Some("warp_connector".to_owned()),
            comment: comment.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn strict_schema_rejects_unknown_fields() {
        let error = DesiredMeshState::parse_json(
            r#"{
  "schema": 1,
  "account_id": "0123456789abcdef0123456789abcdef",
  "environment": "poc",
  "node_name": "singbox-line3-poc",
  "routes": [],
  "extra": true
}"#,
        )
        .unwrap_err();
        assert!(matches!(error, MeshLifecycleError::Json(_)));
    }

    #[test]
    fn account_id_is_explicit_git_authority_not_runtime_secret() {
        let mut desired = desired();
        desired.account_id = "not-an-account".to_owned();
        let error = desired.validate().unwrap_err();
        assert!(error.to_string().contains("32 lowercase hexadecimal"));
    }

    #[test]
    fn default_routes_are_explicitly_blocked() {
        for network in ["0.0.0.0/0", "::/0"] {
            let json = format!(
                r#"{{"schema":1,"account_id":"0123456789abcdef0123456789abcdef","environment":"poc","node_name":"singbox-line3-poc","routes":[{{"network":"{network}"}}]}}"#
            );
            let error = DesiredMeshState::parse_json(&json).unwrap_err();
            assert!(error.to_string().contains("explicit full-Internet PoC gate"));
        }
    }

    #[test]
    fn noncanonical_networks_are_rejected() {
        let error = DesiredMeshState::parse_json(
            r#"{"schema":1,"account_id":"0123456789abcdef0123456789abcdef","environment":"poc","node_name":"singbox-line3-poc","routes":[{"network":"203.0.113.7/24"}]}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("use 203.0.113.0/24"));
    }

    #[test]
    fn missing_node_plans_single_create() {
        let plan = plan_apply(&desired(), &MeshObservation::default()).unwrap();
        assert_eq!(plan.action, ApplyAction::CreateNode);
        assert_eq!(plan.node_id, None);
    }

    #[test]
    fn duplicate_exact_node_fails_closed() {
        let observed = MeshObservation {
            nodes: vec![
                node(),
                ObservedMeshNode {
                    provider_id: "node-2".to_owned(),
                    ..node()
                },
            ],
            routes: vec![],
        };
        let error = plan_apply(&desired(), &observed).unwrap_err();
        assert!(matches!(error, MeshLifecycleError::Ambiguous(_)));
    }

    #[test]
    fn missing_route_plans_one_mutation() {
        let observed = MeshObservation {
            nodes: vec![node()],
            routes: vec![],
        };
        let plan = plan_apply(&desired(), &observed).unwrap();
        assert_eq!(
            plan.action,
            ApplyAction::CreateRoute {
                network: "1.1.1.1/32".to_owned()
            }
        );
        assert_eq!(plan.node_id.as_deref(), Some("node-1"));
    }

    #[test]
    fn foreign_route_on_dedicated_node_fails_closed() {
        let observed = MeshObservation {
            nodes: vec![node()],
            routes: vec![route("route-1", "1.1.1.1/32", Some("manual"))],
        };
        let error = plan_apply(&desired(), &observed).unwrap_err();
        assert!(matches!(error, MeshLifecycleError::Conflict(_)));
        assert!(error.to_string().contains("foreign route"));
    }

    #[test]
    fn exact_desired_state_is_noop() {
        let desired = desired();
        let ownership = desired.ownership_comment();
        let observed = MeshObservation {
            nodes: vec![node()],
            routes: vec![
                route("route-1", "1.1.1.1/32", Some(&ownership)),
                route(
                    "route-2",
                    "2606:4700:4700::1111/128",
                    Some(&ownership),
                ),
            ],
        };
        let plan = plan_apply(&desired, &observed).unwrap();
        assert_eq!(plan.action, ApplyAction::Noop);
    }

    #[test]
    fn extra_managed_route_requires_explicit_cleanup() {
        let desired = desired();
        let ownership = desired.ownership_comment();
        let observed = MeshObservation {
            nodes: vec![node()],
            routes: vec![
                route("route-1", "1.1.1.1/32", Some(&ownership)),
                route(
                    "route-2",
                    "2606:4700:4700::1111/128",
                    Some(&ownership),
                ),
                route("route-3", "203.0.113.0/24", Some(&ownership)),
            ],
        };
        let error = plan_apply(&desired, &observed).unwrap_err();
        assert!(error.to_string().contains("cleanup"));
    }

    #[test]
    fn cleanup_is_one_mutation_at_a_time_and_digest_bound() {
        let desired = desired();
        let ownership = desired.ownership_comment();
        let observed = MeshObservation {
            nodes: vec![node()],
            routes: vec![
                route("route-b", "2606:4700:4700::1111/128", Some(&ownership)),
                route("route-a", "1.1.1.1/32", Some(&ownership)),
            ],
        };
        let first = plan_cleanup(&desired, &observed).unwrap();
        assert_eq!(
            first.action,
            CleanupAction::DeleteRoute {
                route_id: "route-a".to_owned(),
                network: "1.1.1.1/32".to_owned()
            }
        );
        let digest = first.destructive_digest.clone().unwrap();
        assert_eq!(verify_cleanup_digest(&desired, &observed, &digest).unwrap(), first);

        let changed = MeshObservation {
            nodes: observed.nodes.clone(),
            routes: vec![observed.routes[0].clone()],
        };
        let stale = verify_cleanup_digest(&desired, &changed, &digest).unwrap_err();
        assert!(stale.to_string().contains("stale"));
    }

    #[test]
    fn cleanup_refuses_foreign_routes_before_node_delete() {
        let desired = desired();
        let observed = MeshObservation {
            nodes: vec![node()],
            routes: vec![route("route-foreign", "1.1.1.1/32", None)],
        };
        let error = plan_cleanup(&desired, &observed).unwrap_err();
        assert!(error.to_string().contains("foreign route"));
    }

    #[test]
    fn cleanup_deletes_node_only_after_owned_routes_are_absent() {
        let desired = desired();
        let observed = MeshObservation {
            nodes: vec![node()],
            routes: vec![],
        };
        let plan = plan_cleanup(&desired, &observed).unwrap();
        assert!(matches!(
            plan.action,
            CleanupAction::DeleteNode { ref node_id } if node_id == "node-1"
        ));
        assert!(plan.destructive_digest.is_some());
    }
}
