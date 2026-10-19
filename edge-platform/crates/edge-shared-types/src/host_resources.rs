//! One typed, bounded VM resource diagnostic. Data from the runner is
//! STRUCTURAL EVIDENCE only, not authenticated native owner attestation.
use crate::{
    FleetHost, FleetHostKind, FleetVmConfigProof, FleetVmDesiredGraph, FleetVmNetworkReadback,
    FleetVmResourceReadback, FleetVmResourceReport,
};
use prost::Message;
use std::net::IpAddr;

pub const MAX_VM_RESOURCE_REPORT_BYTES: usize = 32768;

/// Validate the exact per-resource graph that the existing root Agent
/// derives from installed Compose, image pins and templates. Validation
/// alone is not authorization to mutate any resource.
pub fn validate_vm_desired_graph(
    graph: &FleetVmDesiredGraph,
    host: &FleetHost,
) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || graph.schema_version != 1
        || graph.machine_id != host.machine_id
        || graph.resources.is_empty()
        || graph.resources.len() != host.vm_containers.len()
        || graph.networks.is_empty()
        || graph.networks.len() > 16
        || graph.encode_to_vec().len() > 16384
    {
        return Err("VM_GRAPH_SCOPE_INVALID");
    }
    // All network membership is typed, bounded and tied to exact Compose
    // project ownership. Missing/default networks, foreign Mesh attachments,
    // duplicate names and unused networks cannot silently enter a release.
    let mut network_names = std::collections::BTreeSet::new();
    let mut network_membership = std::collections::BTreeSet::new();
    let project = &host.vm_containers[0].compose_project;
    for network in &graph.networks {
        if network.compose_project != *project
            || network.driver != "bridge"
            || network.network_name.is_empty()
            || network.network_name.len() > 64
            || !network
                .network_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || network.network_name == "mesh_net"
            || !network_names.insert(network.network_name.as_str())
            || network.attached_services.is_empty()
        {
            return Err("VM_GRAPH_NETWORK_SCOPE_INVALID");
        }
        let mut members = std::collections::BTreeSet::new();
        for service in &network.attached_services {
            if !host
                .vm_containers
                .iter()
                .any(|item| &item.compose_service == service)
                || !members.insert(service.as_str())
                || !network_membership.insert(service.as_str())
            {
                // Current native lifecycle deliberately permits one owned
                // network per registered container, never implicit multi-net.
                return Err("VM_GRAPH_NETWORK_MEMBERSHIP_INVALID");
            }
        }
    }
    if network_membership.len() != host.vm_containers.len() {
        return Err("VM_GRAPH_NETWORK_MEMBERSHIP_INCOMPLETE");
    }
    let mut unique = std::collections::BTreeSet::new();
    for (row, selector) in graph.resources.iter().zip(&host.vm_containers) {
        if row.resource.as_ref() != Some(selector)
            || !unique.insert(selector.compose_service.as_str())
            || row.image_ref.len() > 256
            || !row
                .image_ref
                .rsplit_once("@sha256:")
                .is_some_and(|(name, sha)| {
                    !name.is_empty()
                        && sha.len() == 64
                        && sha.bytes().all(|b| b.is_ascii_hexdigit())
                })
            || row.dependencies.len() > graph.resources.len()
        {
            return Err("VM_GRAPH_RESOURCE_INVALID");
        }
        match selector.compose_service.as_str() {
            "line1-gateway" | "line2-proxy"
                if row.config_template_sha256.len() != 32
                    || row.config_template_sha256.iter().all(|b| *b == 0) =>
            {
                return Err("VM_GRAPH_CONFIG_MISSING");
            }
            "warp-egress" if !row.config_template_sha256.is_empty() => {
                return Err("VM_GRAPH_WARP_CONFIG_FOREIGN");
            }
            _ if !row.config_template_sha256.is_empty()
                && (row.config_template_sha256.len() != 32
                    || row.config_template_sha256.iter().all(|b| *b == 0)) =>
            {
                return Err("VM_GRAPH_CONFIG_INVALID");
            }
            _ => {}
        }
        let mut deps = std::collections::BTreeSet::new();
        for dep in &row.dependencies {
            if dep == &selector.compose_service
                || !host
                    .vm_containers
                    .iter()
                    .any(|item| item.compose_service == *dep)
                || !deps.insert(dep)
            {
                return Err("VM_GRAPH_DEPENDENCY_INVALID");
            }
        }
    }
    let mut settled = std::collections::BTreeSet::new();
    while settled.len() < graph.resources.len() {
        let before = settled.len();
        for resource in &graph.resources {
            let name = resource.resource.as_ref().unwrap().compose_service.as_str();
            if !settled.contains(name)
                && resource
                    .dependencies
                    .iter()
                    .all(|dep| settled.contains(dep.as_str()))
            {
                settled.insert(name);
            }
        }
        if settled.len() == before {
            return Err("VM_GRAPH_DEPENDENCY_CYCLE");
        }
    }
    Ok(())
}

/// Stable hierarchical path of a registered VM resource. The identity is
/// derived from the sole FleetHost selector; a runner does not choose it.
pub fn vm_container_resource_id(
    host: &FleetHost,
    selector: &crate::FleetVmContainer,
) -> Result<String, &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || !host.vm_containers.contains(selector)
        || selector.compose_project.is_empty()
        || selector.compose_service.is_empty()
    {
        return Err("VM_RESOURCE_ID_NOT_REGISTERED");
    }
    Ok(format!(
        "container/{}/{}",
        selector.compose_project, selector.compose_service
    ))
}

fn vm_network_resource_id(project: &str, name: &str) -> String {
    format!("network/{project}/{name}")
}

fn vm_config_resource_id(project: &str, service: &str) -> String {
    format!("config/{project}/{service}")
}

fn vm_host_resource_id(host: &FleetHost) -> String {
    format!("host/{}", host.machine_id)
}

/// A PURE hierarchy projection: host -> networks/containers -> config
/// children. Container-to-network and Compose dependency edges remain
/// explicit and typed. A missing/foreign edge blocks the whole projection;
/// only known native owners appear and no mutation authority is conferred.
pub fn derive_vm_resource_hierarchy(
    host: &FleetHost,
    desired: &FleetVmDesiredGraph,
) -> Result<crate::FleetResourceHierarchy, &'static str> {
    use crate::FleetResourceHierarchy;
    validate_vm_desired_graph(desired, host)?;
    let nodes = project_vm_hierarchy_nodes_unchecked(host, desired)?;
    let graph = FleetResourceHierarchy {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        nodes,
        owner_attested: false,
        mutation_authorized: false,
    };
    validate_vm_resource_hierarchy(&graph, host, desired)?;
    Ok(graph)
}

/// Binds every reported node to the precise Git desired projection, not a
/// caller-supplied parent, dependency list, or a forged owner attestation.
pub fn validate_vm_resource_hierarchy(
    observed: &crate::FleetResourceHierarchy,
    host: &FleetHost,
    desired: &FleetVmDesiredGraph,
) -> Result<(), &'static str> {
    validate_vm_desired_graph(desired, host)?;
    if observed.schema_version != 1
        || observed.machine_id != host.machine_id
        || observed.nodes.is_empty()
        || observed.nodes.len() > 128
        || observed.owner_attested
        || observed.mutation_authorized
        || observed.encode_to_vec().len() > 32768
    {
        return Err("VM_HIERARCHY_SCOPE_OR_AUTHORITY_INVALID");
    }
    // Recompute from exact policy without another source of truth. This
    // internal builder does not call this validator, preventing recursion.
    let mut unique = std::collections::BTreeSet::new();
    let mut seen = std::collections::BTreeSet::new();
    let all_ids = observed
        .nodes
        .iter()
        .map(|node| node.resource_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for node in &observed.nodes {
        if !unique.insert(node.resource_id.as_str())
            || node.owner != crate::FleetResourceOwner::VmRootAgent as i32
            || crate::FleetResourceKind::try_from(node.kind).is_err()
            || node.kind == crate::FleetResourceKind::Unspecified as i32
        {
            return Err("VM_HIERARCHY_NODE_IDENTITY_INVALID");
        }
        if node.parent_resource_id.is_empty() {
            if node.resource_id != vm_host_resource_id(host)
                || node.kind != crate::FleetResourceKind::Host as i32
                || !node.dependency_ids.is_empty()
            {
                return Err("VM_HIERARCHY_ROOT_INVALID");
            }
        } else if !seen.contains(node.parent_resource_id.as_str()) {
            return Err("VM_HIERARCHY_PARENT_NOT_FOUND_OR_UNORDERED");
        }
        // Dependencies are graph edges, not serialization order. A gateway
        // may depend on WARP declared later in the inventory. Cycles are
        // already rejected by validate_vm_desired_graph above.
        for dep in &node.dependency_ids {
            if !all_ids.contains(dep.as_str()) || dep == &node.resource_id {
                return Err("VM_HIERARCHY_DEPENDENCY_UNREGISTERED");
            }
        }
        if !node.expected_policy_sha256.is_empty()
            && (node.expected_policy_sha256.len() != 32
                || node.expected_policy_sha256.iter().all(|byte| *byte == 0))
        {
            return Err("VM_HIERARCHY_DIGEST_INVALID");
        }
        seen.insert(node.resource_id.as_str());
    }
    if observed.nodes[0].resource_id != vm_host_resource_id(host)
        || observed.nodes.len()
            != 1 + desired.networks.len()
                + desired.resources.len()
                + desired
                    .resources
                    .iter()
                    .filter(|r| !r.config_template_sha256.is_empty())
                    .count()
    {
        return Err("VM_HIERARCHY_INCOMPLETE");
    }
    // Exact parent, order, owner and dependency enforcement for each
    // independently immutable resource, rather than merely validating form.
    let expected = project_vm_hierarchy_nodes_unchecked(host, desired)?;
    if observed.nodes != expected {
        return Err("VM_HIERARCHY_POLICY_DRIFT");
    }
    Ok(())
}

fn project_vm_hierarchy_nodes_unchecked(
    host: &FleetHost,
    desired: &FleetVmDesiredGraph,
) -> Result<Vec<crate::FleetResourceNode>, &'static str> {
    use crate::{FleetResourceKind as Kind, FleetResourceNode, FleetResourceOwner as Owner};
    let root = vm_host_resource_id(host);
    let mut result = vec![FleetResourceNode {
        resource_id: root.clone(),
        kind: Kind::Host as i32,
        parent_resource_id: String::new(),
        dependency_ids: Vec::new(),
        owner: Owner::VmRootAgent as i32,
        expected_policy_sha256: Vec::new(),
    }];
    let mut networks = std::collections::BTreeMap::<&str, &str>::new();
    for network in &desired.networks {
        for service in &network.attached_services {
            networks.insert(service, &network.network_name);
        }
        result.push(FleetResourceNode {
            resource_id: vm_network_resource_id(&network.compose_project, &network.network_name),
            kind: Kind::DockerNetwork as i32,
            parent_resource_id: root.clone(),
            dependency_ids: Vec::new(),
            owner: Owner::VmRootAgent as i32,
            expected_policy_sha256: ring::digest::digest(
                &ring::digest::SHA256,
                &network.encode_to_vec(),
            )
            .as_ref()
            .to_vec(),
        });
    }
    for resource in &desired.resources {
        let selector = resource
            .resource
            .as_ref()
            .ok_or("VM_HIERARCHY_SELECTOR_MISSING")?;
        let id = vm_container_resource_id(host, selector)?;
        let network = networks
            .get(&selector.compose_service.as_str())
            .ok_or("VM_HIERARCHY_NETWORK_DEPENDENCY_MISSING")?;
        let mut dependencies = vec![vm_network_resource_id(&selector.compose_project, network)];
        for dependency in &resource.dependencies {
            let s = host
                .vm_containers
                .iter()
                .find(|v| v.compose_service == *dependency)
                .ok_or("VM_HIERARCHY_FOREIGN_CONTAINER_DEPENDENCY")?;
            dependencies.push(vm_container_resource_id(host, s)?);
        }
        dependencies.sort();
        dependencies.dedup();
        result.push(FleetResourceNode {
            resource_id: id.clone(),
            kind: Kind::DockerContainer as i32,
            parent_resource_id: root.clone(),
            dependency_ids: dependencies,
            owner: Owner::VmRootAgent as i32,
            expected_policy_sha256: ring::digest::digest(
                &ring::digest::SHA256,
                &resource.encode_to_vec(),
            )
            .as_ref()
            .to_vec(),
        });
        if !resource.config_template_sha256.is_empty() {
            result.push(FleetResourceNode {
                resource_id: vm_config_resource_id(
                    &selector.compose_project,
                    &selector.compose_service,
                ),
                kind: Kind::SingboxConfig as i32,
                parent_resource_id: id.clone(),
                dependency_ids: vec![id],
                owner: Owner::VmRootAgent as i32,
                expected_policy_sha256: resource.config_template_sha256.clone(),
            });
        }
    }
    Ok(result)
}

/// Deterministic resource policy diff. "Installed" is the protected
/// root-local bundle, not Docker physical proof. "Desired" is independently
/// compiled from the immutable, Git-owned ReleaseSet. This function never
/// accepts a runner authority or performs mutations.
pub fn propose_vm_graph_reconcile(
    host: &FleetHost,
    installed: &FleetVmDesiredGraph,
    desired: &FleetVmDesiredGraph,
) -> Result<crate::FleetVmGraphReconcile, &'static str> {
    use crate::{
        FleetResourceKind as Kind, FleetResourceOwner as Owner, FleetVmGraphReconcile,
        FleetVmGraphResourceChange, FleetVmPolicyChange,
    };
    let installed_hierarchy = derive_vm_resource_hierarchy(host, installed)?;
    let desired_hierarchy = derive_vm_resource_hierarchy(host, desired)?;
    // The root and network dependency identities are an invariant across
    // this image/config-only effector. A new network/dependency needs its
    // own native operation rather than falling through to Compose.
    if installed_hierarchy.nodes.len() != desired_hierarchy.nodes.len() {
        return Err("VM_RECONCILE_HIERARCHY_SCOPE_CHANGED");
    }
    if installed.networks != desired.networks {
        return Err("VM_RECONCILE_NETWORK_POLICY_REQUIRES_NATIVE_HANDLER");
    }
    // The source container order is the single canonical fleet order.
    // A dependency delta needs its own typed Docker/network lifecycle and
    // must never sneak through a config-only or image-only effector.
    let mut old_consumers = std::collections::BTreeMap::<&str, Vec<usize>>::new();
    let mut resources = Vec::with_capacity(desired.resources.len());
    for (index, (before, after)) in installed
        .resources
        .iter()
        .zip(&desired.resources)
        .enumerate()
    {
        if before.resource != after.resource || before.dependencies != after.dependencies {
            return Err("VM_RECONCILE_DEPENDENCY_OR_IDENTITY_CHANGED");
        }
        old_consumers
            .entry(&before.image_ref)
            .or_default()
            .push(index);
        let image_changed = before.image_ref != after.image_ref;
        let config_changed = before.config_template_sha256 != after.config_template_sha256;
        if image_changed && config_changed {
            return Err("VM_RECONCILE_COMBINED_IMAGE_AND_CONFIG_UNSUPPORTED");
        }
        let change = if image_changed {
            FleetVmPolicyChange::ImageReplaced
        } else if config_changed {
            FleetVmPolicyChange::ConfigTemplateReplaced
        } else {
            FleetVmPolicyChange::NoChange
        };
        let selector = after.resource.as_ref().ok_or("VM_RECONCILE_RESOURCE_MISSING")?;
        let (resource_id, resource_kind) = if change == FleetVmPolicyChange::ConfigTemplateReplaced {
            (
                vm_config_resource_id(&selector.compose_project, &selector.compose_service),
                Kind::SingboxConfig,
            )
        } else {
            (vm_container_resource_id(host, selector)?, Kind::DockerContainer)
        };
        let exact_node = desired_hierarchy.nodes.iter()
            .find(|node| node.resource_id == resource_id)
            .ok_or("VM_RECONCILE_RESOURCE_NODE_NOT_IN_GRAPH")?;
        if exact_node.kind != resource_kind as i32
            || exact_node.owner != Owner::VmRootAgent as i32
            || (resource_kind == Kind::SingboxConfig
                && exact_node.parent_resource_id != vm_container_resource_id(host, selector)?)
            || (resource_kind == Kind::DockerContainer
                && exact_node.parent_resource_id != vm_host_resource_id(host))
        {
            return Err("VM_RECONCILE_NODE_OWNER_OR_PARENT_INVALID");
        }
        resources.push(FleetVmGraphResourceChange {
            resource: after.resource.clone(),
            change: change as i32,
            expected_image_ref: after.image_ref.clone(),
            expected_config_template_sha256: after.config_template_sha256.clone(),
            resource_id,
            resource_kind: resource_kind as i32,
        });
    }
    // When several services share an old OCI image, replacing a subset
    // could start mixed releases under one logical image resource. All
    // consumers must move to the SAME immutable digest in one transaction.
    for consumers in old_consumers.values() {
        if consumers.len() > 1 {
            let replacements = consumers
                .iter()
                .map(|&index| &desired.resources[index].image_ref)
                .collect::<std::collections::BTreeSet<_>>();
            if replacements.len() != 1 {
                return Err("VM_RECONCILE_SHARED_IMAGE_PARTIAL_REPLACE");
            }
        }
    }
    Ok(FleetVmGraphReconcile {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        resources,
        owner_attested: false,
        mutation_authorized: false,
    })
}

pub fn validate_vm_resource_report(
    report: &FleetVmResourceReport,
    host: &FleetHost,
) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || report.schema_version != 1
        || report.remote_attested
        || report.machine_id != host.machine_id
        || report.observed_at_unix == 0
        || host.vm_containers.is_empty()
        || report.resources.len() != host.vm_containers.len()
        || report.encode_to_vec().len() > MAX_VM_RESOURCE_REPORT_BYTES
    {
        return Err("VM_RESOURCE_REPORT_SCOPE_INVALID");
    }
    if let Some(network) = report.network.as_ref() {
        validate_vm_network_readback(network)?;
    }
    for (row, expected) in report.resources.iter().zip(host.vm_containers.iter()) {
        if row.resource.as_ref() != Some(expected)
            || row.image.len() > 256
            || !row.image.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b':' | b'.' | b'_' | b'-' | b'@')
            })
            || row.health.len() > 32
            || !row
                .health
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || (row.present
                && !row.ownership_proven
                && (!row.container_id.is_empty()
                    || !row.image.is_empty()
                    || !row.health.is_empty()
                    || row.running
                    || row.running_proven
                    || row.restart_count_proven))
            || (!row.present && (row.ownership_proven || row.running_proven || row.running))
            || (row.running && !row.running_proven)
            || (row.ownership_proven && !valid_container_id(&row.container_id))
            || (!row.ownership_proven && !row.container_id.is_empty())
            || (row.restart_count != 0 && !row.restart_count_proven)
            || !config_proof_consistent(row, expected)
            || !reason_consistent(row)
        {
            return Err("VM_RESOURCE_REPORT_EVIDENCE_INVALID");
        }
    }
    Ok(())
}

/// Strict bounds and relationships for runner-copied VM network bytes.
/// Structural validation NEVER authenticates their claimed source or proves
/// Internet/DNS/firewall policy convergence.
pub fn validate_vm_network_readback(network: &FleetVmNetworkReadback) -> Result<(), &'static str> {
    if network.dns_nameservers.len() > 8
        || network
            .dns_nameservers
            .iter()
            .any(|address| address.parse::<IpAddr>().is_err())
        || !network.dns_configuration_observed && !network.dns_nameservers.is_empty()
        || !network.nft_ruleset_observed
            && (!network.nft_ruleset_sha256.is_empty() || network.nft_rule_count != 0)
        || network.nft_ruleset_observed
            && (network.nft_ruleset_sha256.len() != 32
                || network.nft_ruleset_sha256.iter().all(|byte| *byte == 0))
    {
        return Err("VM_NETWORK_EVIDENCE_INVALID");
    }
    let mut nameservers = std::collections::BTreeSet::new();
    if network
        .dns_nameservers
        .iter()
        .any(|address| !nameservers.insert(address))
    {
        return Err("VM_NETWORK_DNS_DUPLICATE");
    }
    if let Some(ipv4) = &network.ipv4 {
        if ipv4.links.len() > 128
            || ipv4.addresses.len() > 256
            || ipv4.routes.len() > 512
            || ipv4.links.iter().any(|link| {
                link.interface_index == 0
                    || link.name.is_empty()
                    || link.name.len() > 64
                    || !link.name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'_' | b'.' | b'-' | b':' | b'@')
                    })
            })
            || ipv4.addresses.iter().any(|address| {
                address.address.parse::<std::net::Ipv4Addr>().is_err()
                    || address.prefix_length > 32
                    || !ipv4
                        .links
                        .iter()
                        .any(|link| link.interface_index == address.interface_index)
            })
            || ipv4.routes.iter().any(|route| {
                route.destination.parse::<std::net::Ipv4Addr>().is_err()
                    || route.prefix_length > 32
                    || route.output_interface_index != 0
                        && !ipv4
                            .links
                            .iter()
                            .any(|link| link.interface_index == route.output_interface_index)
                    || route
                        .preferred_source
                        .as_ref()
                        .is_some_and(|source| source.parse::<std::net::Ipv4Addr>().is_err())
            })
            || ipv4.encode_to_vec().len() > 24_576
        {
            return Err("VM_NETWORK_KERNEL_EVIDENCE_INVALID");
        }
    }
    Ok(())
}

fn valid_container_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn config_proof_consistent(
    row: &FleetVmResourceReadback,
    expected: &crate::FleetVmContainer,
) -> bool {
    let proof = FleetVmConfigProof::try_from(row.config_proof);
    let digest_valid =
        row.config_sha256.len() == 32 && row.config_sha256.iter().any(|byte| *byte != 0);
    match proof {
        Ok(FleetVmConfigProof::Unproven) => row.config_sha256.is_empty(),
        Ok(FleetVmConfigProof::NotApplicable) => {
            expected.compose_service == "warp-egress" && row.config_sha256.is_empty()
        }
        Ok(FleetVmConfigProof::NotRunning) => !row.running && row.config_sha256.is_empty(),
        Ok(FleetVmConfigProof::BoundRunningProcess) => {
            matches!(
                expected.compose_service.as_str(),
                "line1-gateway" | "line2-proxy"
            ) && row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && digest_valid
        }
        Err(_) => false,
    }
}

fn reason_consistent(row: &FleetVmResourceReadback) -> bool {
    match row.reason_code.as_str() {
        "CONTAINER_ABSENT" => !row.present,
        "DOCKER_UNAVAILABLE" | "INSPECT_UNAVAILABLE" => !row.present,
        "FOREIGN_OWNER" => row.present && !row.ownership_proven,
        "STATE_UNPROVEN" => row.present && row.ownership_proven && !row.running_proven,
        "HEALTHY" => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "HEALTHY"
        }
        "HEALTH_STARTING" => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "STARTING"
        }
        "HEALTH_UNHEALTHY" => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "UNHEALTHY"
        }
        "RUNNING_NO_HEALTHCHECK" | "HEALTH_UNPROVEN" => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health.is_empty()
        }
        "STOPPED" => row.present && row.ownership_proven && row.running_proven && !row.running,
        _ => false,
    }
}

pub fn decode_vm_resource_report(
    bytes: &[u8],
    host: &FleetHost,
) -> Result<FleetVmResourceReport, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_VM_RESOURCE_REPORT_BYTES {
        return Err("VM_RESOURCE_REPORT_SIZE_INVALID");
    }
    let report =
        FleetVmResourceReport::decode(bytes).map_err(|_| "VM_RESOURCE_REPORT_PROTO_INVALID")?;
    if report.encode_to_vec() != bytes {
        return Err("VM_RESOURCE_REPORT_NONCANONICAL");
    }
    validate_vm_resource_report(&report, host)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FleetHostKind, FleetVmContainer};
    fn fixture() -> (FleetHost, FleetVmResourceReport) {
        let resource = FleetVmContainer {
            container_name: "my-proxy".into(),
            compose_project: "my-app".into(),
            compose_service: "proxy".into(),
        };
        let host = FleetHost {
            machine_id: "vm-a".into(),
            kind: FleetHostKind::Vm as i32,
            vm_containers: vec![resource.clone()],
            ..Default::default()
        };
        let report = FleetVmResourceReport {
            schema_version: 1,
            machine_id: "vm-a".into(),
            observed_at_unix: 100,
            resources: vec![FleetVmResourceReadback {
                resource: Some(resource),
                present: true,
                ownership_proven: true,
                running: true,
                running_proven: true,
                container_id: "a".repeat(64),
                reason_code: "HEALTHY".into(),
                health: "HEALTHY".into(),
                ..Default::default()
            }],
            remote_attested: false,
            network: None,
        };
        (host, report)
    }
    #[test]
    fn network_report_cannot_forge_dns_or_firewall_proof() {
        use crate::{Ipv4AddressObservation, Ipv4LinkObservation, Ipv4NetworkObservation};
        let network = FleetVmNetworkReadback {
            ipv4: Some(Ipv4NetworkObservation {
                links: vec![Ipv4LinkObservation {
                    interface_index: 2,
                    name: "ens3".into(),
                    up: true,
                    lower_up: true,
                    loopback: false,
                }],
                addresses: vec![Ipv4AddressObservation {
                    interface_index: 2,
                    address: "192.0.2.10".into(),
                    prefix_length: 24,
                    global_scope: true,
                }],
                ..Default::default()
            }),
            dns_nameservers: vec!["1.1.1.1".into()],
            dns_configuration_observed: true,
            nft_rule_count: 2,
            nft_ruleset_observed: true,
            nft_ruleset_sha256: vec![42; 32],
        };
        assert!(validate_vm_network_readback(&network).is_ok());
        let mut forged = network.clone();
        forged.nft_ruleset_observed = false;
        assert!(validate_vm_network_readback(&forged).is_err());
        forged = network.clone();
        forged.dns_configuration_observed = false;
        assert!(validate_vm_network_readback(&forged).is_err());
        forged = network.clone();
        forged.ipv4.as_mut().unwrap().addresses[0].interface_index = 999;
        assert!(validate_vm_network_readback(&forged).is_err());
        forged = network.clone();
        forged.dns_nameservers.push("not-an-ip".into());
        assert!(validate_vm_network_readback(&forged).is_err());
    }

    #[test]
    fn typed_vm_graph_rejects_foreign_resources_and_dependency_cycles() {
        use crate::{FleetVmContainer, FleetVmDesiredResource};
        let selector = |name: &str| FleetVmContainer {
            container_name: format!("test-{name}"),
            compose_project: "test".into(),
            compose_service: name.into(),
        };
        let host = FleetHost {
            machine_id: "vm-test".into(),
            kind: FleetHostKind::Vm as i32,
            vm_containers: vec![selector("line1-gateway"), selector("warp-egress")],
            ..Default::default()
        };
        let image = format!("repo/app@sha256:{}", "a".repeat(64));
        let mut graph = FleetVmDesiredGraph {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resources: vec![
                FleetVmDesiredResource {
                    resource: Some(host.vm_containers[0].clone()),
                    image_ref: image.clone(),
                    dependencies: vec!["warp-egress".into()],
                    config_template_sha256: vec![9; 32],
                },
                FleetVmDesiredResource {
                    resource: Some(host.vm_containers[1].clone()),
                    image_ref: image.clone(),
                    ..Default::default()
                },
            ],
            networks: vec![crate::FleetVmDesiredNetwork {
                compose_project: "test".into(),
                network_name: "edge_net".into(),
                driver: "bridge".into(),
                attached_services: vec!["line1-gateway".into(), "warp-egress".into()],
            }],
        };
        assert!(validate_vm_desired_graph(&graph, &host).is_ok());
        let mut unknown_network = graph.clone();
        unknown_network.networks[0]
            .attached_services
            .push("cloudflare-mesh".into());
        assert_eq!(
            validate_vm_desired_graph(&unknown_network, &host),
            Err("VM_GRAPH_NETWORK_MEMBERSHIP_INVALID")
        );
        unknown_network = graph.clone();
        unknown_network.networks[0].driver = "host".into();
        assert_eq!(
            validate_vm_desired_graph(&unknown_network, &host),
            Err("VM_GRAPH_NETWORK_SCOPE_INVALID")
        );
        graph.resources[1].dependencies.push("line1-gateway".into());
        assert_eq!(
            validate_vm_desired_graph(&graph, &host),
            Err("VM_GRAPH_DEPENDENCY_CYCLE")
        );
        graph.resources[1].dependencies.clear();
        graph.resources[0].image_ref = "repo/app:latest".into();
        assert!(validate_vm_desired_graph(&graph, &host).is_err());
        graph.resources[0].image_ref = image;
        graph.resources[0]
            .resource
            .as_mut()
            .unwrap()
            .compose_service = "foreign".into();
        assert!(validate_vm_desired_graph(&graph, &host).is_err());
    }

    #[test]
    fn resource_report_fails_closed_on_forgery_and_foreign_owner() {
        let (host, mut report) = fixture();
        let bytes = report.encode_to_vec();
        assert_eq!(decode_vm_resource_report(&bytes, &host).unwrap(), report);
        report.remote_attested = true;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.remote_attested = false;
        report.resources[0]
            .resource
            .as_mut()
            .unwrap()
            .compose_project = "foreign".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].resource = host.vm_containers.first().cloned();
        report.resources[0].ownership_proven = false;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].container_id.clear();
        report.resources[0].health.clear();
        report.resources[0].running_proven = false;
        report.resources[0].running = false;
        report.resources[0].reason_code = "FOREIGN_OWNER".into();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].reason_code = "HEALTHY".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report = fixture().1;
        report.resources[0].config_proof = FleetVmConfigProof::BoundRunningProcess as i32;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].config_sha256 = vec![7; 32];
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].config_proof = FleetVmConfigProof::Unproven as i32;
        report.resources[0].config_sha256.clear();
        report.resources[0].reason_code = "HEALTH_STARTING".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].health = "STARTING".into();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].reason_code = "RUNNING_NO_HEALTHCHECK".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].health.clear();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        let mut invalid = bytes;
        invalid.extend_from_slice(&[0x08, 0x01]); // noncanonical duplicate field
        assert!(decode_vm_resource_report(&invalid, &host).is_err());
    }
}

/*
 * One deterministic, strictly non-authorizing proposal per VM container.
 * We deliberately do NOT treat Docker health as proof of matching config,
 * image digest, network, DNS or TLS. All config/release mutations remain
 * blocked until native owner-side bundle/resource comparison is wired.
 */
pub fn propose_vm_resource_transitions(
    host: &FleetHost,
    report: &FleetVmResourceReport,
) -> Result<crate::FleetVmResourceTransitionPlan, &'static str> {
    use crate::{
        FleetHostPlannedStep as Step, FleetHostRunState, FleetVmResourceReason as Reason,
        FleetVmResourceTransition, FleetVmResourceTransitionPlan,
    };
    validate_vm_resource_report(report, host)?;
    let desired = host
        .target
        .as_ref()
        .and_then(|target| FleetHostRunState::try_from(target.run_state).ok());
    let mut resources = Vec::with_capacity(report.resources.len());
    for row in &report.resources {
        let (step, reason) = match desired {
            None | Some(FleetHostRunState::Unspecified) => {
                (Step::Blocked, Reason::TargetUnsetObserveOnly)
            }
            Some(FleetHostRunState::Stopped)
                if !row.present && row.reason_code == "CONTAINER_ABSENT" =>
            {
                (Step::Noop, Reason::AbsentAsDesired)
            }
            Some(FleetHostRunState::Running)
                if !row.present && row.reason_code == "CONTAINER_ABSENT" =>
            {
                (Step::Install, Reason::ContainerAbsentInstallRequired)
            }
            Some(_) if !row.present || !row.ownership_proven || !row.running_proven => {
                (Step::Blocked, Reason::ResourceIdentityOrStateUnproven)
            }
            Some(FleetHostRunState::Stopped) if row.running => {
                (Step::Stop, Reason::ContainerRunningButTargetStopped)
            }
            Some(FleetHostRunState::Stopped) => (Step::Noop, Reason::StoppedAsDesired),
            Some(FleetHostRunState::Running) if !row.running => {
                (Step::Start, Reason::ContainerStoppedButTargetRunning)
            }
            Some(FleetHostRunState::Running)
                if matches!(
                    row.reason_code.as_str(),
                    "HEALTHY" | "RUNNING_NO_HEALTHCHECK"
                ) =>
            {
                // An already-running container requires no START. Docker
                // health is NOT proof of configuration or network readiness.
                (Step::Noop, Reason::RunningRuntimeOnlyConfigUnproven)
            }
            Some(FleetHostRunState::Running) => {
                (Step::Blocked, Reason::RuntimeHealthOrConfigUnproven)
            }
        };
        let selector = row.resource.as_ref().ok_or("VM_RESOURCE_PLAN_SELECTOR_MISSING")?;
        resources.push(FleetVmResourceTransition {
            resource: row.resource.clone(),
            resource_id: vm_container_resource_id(host, selector)?,
            step: step as i32,
            reason_code: reason
                .as_str_name()
                .strip_prefix("FLEET_VM_RESOURCE_REASON_")
                .expect("typed reason uses the stable protobuf prefix")
                .to_owned(),
            reason: reason as i32,
        });
    }
    let proposed = FleetVmResourceTransitionPlan {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        resources,
        owner_attested: false,
        mutation_authorized: false,
    };
    validate_vm_resource_transition_plan(&proposed, host)?;
    Ok(proposed)
}

/// Contract validation is distinct from authorization: even a well-formed
/// runner-copied plan must never claim owner attestation or mutation rights.
/// Validate exact host scope, typed reason/action pairing and the backwards-
/// compatible reason_code projection. No new owner registry is introduced.
pub fn validate_vm_resource_transition_plan(
    plan: &crate::FleetVmResourceTransitionPlan,
    host: &FleetHost,
) -> Result<(), &'static str> {
    use crate::{FleetHostPlannedStep as Step, FleetVmResourceReason as Reason};
    if host.kind != FleetHostKind::Vm as i32
        || plan.schema_version != 1
        || plan.machine_id != host.machine_id
        || plan.resources.len() != host.vm_containers.len()
        || plan.owner_attested
        || plan.mutation_authorized
    {
        return Err("VM_RESOURCE_PLAN_SCOPE_OR_AUTHORITY_INVALID");
    }
    for (entry, selector) in plan.resources.iter().zip(&host.vm_containers) {
        if entry.resource.as_ref() != Some(selector)
            || entry.resource_id != vm_container_resource_id(host, selector)?
        {
            return Err("VM_RESOURCE_PLAN_IDENTITY_INVALID");
        }
        let reason =
            Reason::try_from(entry.reason).map_err(|_| "VM_RESOURCE_PLAN_REASON_UNRECOGNIZED")?;
        if reason == Reason::Unspecified {
            return Err("VM_RESOURCE_PLAN_REASON_UNSPECIFIED");
        }
        let code = reason
            .as_str_name()
            .strip_prefix("FLEET_VM_RESOURCE_REASON_")
            .ok_or("VM_RESOURCE_PLAN_REASON_INVALID")?;
        if entry.reason_code != code {
            return Err("VM_RESOURCE_PLAN_REASON_CODE_MISMATCH");
        }
        let expected_step = match reason {
            Reason::TargetUnsetObserveOnly
            | Reason::ResourceIdentityOrStateUnproven
            | Reason::RuntimeHealthOrConfigUnproven => Step::Blocked,
            Reason::AbsentAsDesired
            | Reason::StoppedAsDesired
            | Reason::RunningRuntimeOnlyConfigUnproven => Step::Noop,
            Reason::ContainerAbsentInstallRequired => Step::Install,
            Reason::ContainerRunningButTargetStopped => Step::Stop,
            Reason::ContainerStoppedButTargetRunning => Step::Start,
            Reason::Unspecified => return Err("VM_RESOURCE_PLAN_REASON_UNSPECIFIED"),
        };
        if entry.step != expected_step as i32 {
            return Err("VM_RESOURCE_PLAN_ACTION_REASON_CONFLICT");
        }
    }
    Ok(())
}

/// A runtime NOOP is not proof of config convergence. Use the *typed* reason
/// from the exact same plan consumed by the native owner, never free text.
pub fn vm_resource_requires_attention(transition: &crate::FleetVmResourceTransition) -> bool {
    transition.step != crate::FleetHostPlannedStep::Noop as i32
        || transition.reason
            == crate::FleetVmResourceReason::RunningRuntimeOnlyConfigUnproven as i32
}

#[cfg(test)]
mod vm_graph_reconcile_tests {
    use super::*;
    use crate::{
        FleetHostKind, FleetVmContainer, FleetVmDesiredGraph, FleetVmDesiredResource,
        FleetVmPolicyChange,
    };

    fn sample() -> (FleetHost, FleetVmDesiredGraph) {
        let selectors = ["line1-gateway", "line2-proxy", "warp-egress"]
            .iter()
            .map(|name| FleetVmContainer {
                container_name: format!("vultr-{name}"),
                compose_project: "vultr-edge".into(),
                compose_service: (*name).into(),
            })
            .collect::<Vec<_>>();
        let host = FleetHost {
            machine_id: "vm-a".into(),
            kind: FleetHostKind::Vm as i32,
            vm_containers: selectors.clone(),
            ..Default::default()
        };
        let image = format!("app/gateway@sha256:{}", "a".repeat(64));
        let warp_image = format!("app/warp@sha256:{}", "b".repeat(64));
        let resources = selectors
            .into_iter()
            .enumerate()
            .map(|(index, resource)| FleetVmDesiredResource {
                resource: Some(resource),
                image_ref: if index == 2 {
                    warp_image.clone()
                } else {
                    image.clone()
                },
                dependencies: if index == 2 {
                    vec![]
                } else {
                    vec!["warp-egress".into()]
                },
                config_template_sha256: if index == 2 { vec![] } else { vec![10; 32] },
            })
            .collect();
        let graph = FleetVmDesiredGraph {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resources,
            networks: vec![crate::FleetVmDesiredNetwork {
                compose_project: "vultr-edge".into(),
                network_name: "edge_net".into(),
                driver: "bridge".into(),
                attached_services: vec![
                    "line1-gateway".into(),
                    "line2-proxy".into(),
                    "warp-egress".into(),
                ],
            }],
        };
        (host, graph)
    }

    #[test]
    fn immutable_vm_resource_hierarchy_is_closed_and_parented() {
        use crate::{FleetResourceKind as Kind, FleetResourceOwner as Owner};
        let (host, desired) = sample();
        let hierarchy = derive_vm_resource_hierarchy(&host, &desired).unwrap();
        assert!(!hierarchy.owner_attested && !hierarchy.mutation_authorized);
        assert_eq!(hierarchy.nodes.len(), 7);
        assert_eq!(hierarchy.nodes[0].resource_id, "host/vm-a");
        assert_eq!(
            hierarchy.nodes[1].resource_id,
            "network/vultr-edge/edge_net"
        );
        assert_eq!(hierarchy.nodes[1].kind, Kind::DockerNetwork as i32);
        assert_eq!(hierarchy.nodes[1].owner, Owner::VmRootAgent as i32);
        let line2 = hierarchy
            .nodes
            .iter()
            .find(|node| node.resource_id == "container/vultr-edge/line2-proxy")
            .unwrap();
        assert_eq!(line2.parent_resource_id, "host/vm-a");
        assert_eq!(line2.kind, Kind::DockerContainer as i32);
        assert_eq!(
            line2.dependency_ids,
            vec![
                "container/vultr-edge/warp-egress".to_owned(),
                "network/vultr-edge/edge_net".to_owned(),
            ]
        );
        let config = hierarchy
            .nodes
            .iter()
            .find(|node| node.resource_id == "config/vultr-edge/line2-proxy")
            .unwrap();
        assert_eq!(config.parent_resource_id, line2.resource_id);
        assert_eq!(config.kind, Kind::SingboxConfig as i32);
        assert_eq!(
            config.expected_policy_sha256,
            desired.resources[1].config_template_sha256
        );
        assert_eq!(
            validate_vm_resource_hierarchy(&hierarchy, &host, &desired),
            Ok(())
        );
        let mut forged = hierarchy.clone();
        forged.nodes[1].owner = Owner::WindowsSystemController as i32;
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.nodes[3].parent_resource_id = "host/foreign".into();
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.nodes[3].dependency_ids.clear();
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.owner_attested = true;
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.nodes.push(forged.nodes[0].clone());
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
    }

    #[test]
    fn docker_network_policy_change_never_sneaks_through_image_or_config_effector() {
        let (host, installed) = sample();
        let mut desired = installed.clone();
        desired.networks[0].network_name = "new_edge_net".into();
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_NETWORK_POLICY_REQUIRES_NATIVE_HANDLER")
        );
        desired = installed.clone();
        desired.networks[0].attached_services.swap(0, 1);
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_NETWORK_POLICY_REQUIRES_NATIVE_HANDLER")
        );
    }

    #[test]
    fn line2_configuration_only_changes_one_registered_resource() {
        let (host, installed) = sample();
        let mut desired = installed.clone();
        desired.resources[1].config_template_sha256 = vec![11; 32];
        let plan = propose_vm_graph_reconcile(&host, &installed, &desired).unwrap();
        assert_eq!(plan.resources.len(), 3);
        assert!(!plan.owner_attested && !plan.mutation_authorized);
        assert_eq!(
            plan.resources[0].change,
            FleetVmPolicyChange::NoChange as i32
        );
        assert_eq!(
            plan.resources[1].change,
            FleetVmPolicyChange::ConfigTemplateReplaced as i32
        );
        assert_eq!(
            plan.resources[2].change,
            FleetVmPolicyChange::NoChange as i32
        );
        assert_eq!(
            plan.resources[1].expected_image_ref,
            installed.resources[1].image_ref
        );
        assert_eq!(plan.resources[1].resource_id, "config/vultr-edge/line2-proxy");
        assert_eq!(
            plan.resources[1].resource_kind,
            crate::FleetResourceKind::SingboxConfig as i32
        );
        assert_eq!(plan.resources[0].resource_id, "container/vultr-edge/line1-gateway");
        assert_eq!(
            plan.resources[0].resource_kind,
            crate::FleetResourceKind::DockerContainer as i32
        );
    }

    #[test]
    fn shared_image_is_one_indivisible_owner_scope() {
        let (host, installed) = sample();
        let mut desired = installed.clone();
        desired.resources[0].image_ref = format!("app/gateway@sha256:{}", "c".repeat(64));
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_SHARED_IMAGE_PARTIAL_REPLACE")
        );
        desired.resources[1].image_ref = desired.resources[0].image_ref.clone();
        let plan = propose_vm_graph_reconcile(&host, &installed, &desired).unwrap();
        assert_eq!(
            plan.resources
                .iter()
                .filter(|item| item.change == FleetVmPolicyChange::ImageReplaced as i32)
                .count(),
            2
        );
        assert_eq!(
            plan.resources[2].change,
            FleetVmPolicyChange::NoChange as i32
        );
        assert_eq!(plan.resources[0].resource_id, "container/vultr-edge/line1-gateway");
        assert_eq!(plan.resources[1].resource_id, "container/vultr-edge/line2-proxy");
        assert!(plan.resources[0].resource_kind
            == crate::FleetResourceKind::DockerContainer as i32);
    }

    #[test]
    fn dependencies_and_combined_image_config_are_not_silent_updates() {
        let (host, installed) = sample();
        let mut desired = installed.clone();
        desired.resources[0].dependencies.clear();
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_DEPENDENCY_OR_IDENTITY_CHANGED")
        );
        desired = installed.clone();
        desired.resources[0].image_ref = format!("app/gateway@sha256:{}", "d".repeat(64));
        desired.resources[0].config_template_sha256 = vec![12; 32];
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_COMBINED_IMAGE_AND_CONFIG_UNSUPPORTED")
        );
        desired = installed.clone();
        desired.resources[0].image_ref = "app/gateway:latest".into();
        assert!(propose_vm_graph_reconcile(&host, &installed, &desired).is_err());
    }
}

#[cfg(test)]
mod resource_planning_tests {
    use super::*;
    use crate::{
        FleetHostMode, FleetHostPlannedStep, FleetHostRunState, FleetHostTarget, FleetVmContainer,
        FleetVmResourceReadback,
    };

    fn fixture() -> (FleetHost, FleetVmResourceReport) {
        let resource = FleetVmContainer {
            container_name: "vultr-line2-proxy".into(),
            compose_project: "vultr-edge".into(),
            compose_service: "line2-proxy".into(),
        };
        let host = FleetHost {
            machine_id: "vm-test".into(),
            kind: FleetHostKind::Vm as i32,
            vm_containers: vec![resource.clone()],
            target: Some(FleetHostTarget {
                run_state: FleetHostRunState::Running as i32,
                windows_mode: FleetHostMode::Unspecified as i32,
            }),
            ..Default::default()
        };
        let report = FleetVmResourceReport {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            observed_at_unix: 100,
            resources: vec![FleetVmResourceReadback {
                resource: Some(resource),
                present: true,
                ownership_proven: true,
                running: true,
                running_proven: true,
                container_id: "a".repeat(64),
                reason_code: "HEALTHY".into(),
                health: "HEALTHY".into(),
                ..Default::default()
            }],
            remote_attested: false,
            network: None,
        };
        (host, report)
    }

    fn step(host: &FleetHost, report: &FleetVmResourceReport) -> FleetHostPlannedStep {
        let result = propose_vm_resource_transitions(host, report).unwrap();
        assert!(!result.owner_attested && !result.mutation_authorized);
        FleetHostPlannedStep::try_from(result.resources[0].step).unwrap()
    }

    #[test]
    fn typed_resource_reason_and_action_are_one_non_authorizing_contract() {
        use crate::FleetVmResourceReason as Reason;
        let (host, report) = fixture();
        let plan = propose_vm_resource_transitions(&host, &report).unwrap();
        assert_eq!(
            plan.resources[0].reason,
            Reason::RunningRuntimeOnlyConfigUnproven as i32
        );
        assert_eq!(
            plan.resources[0].reason_code,
            "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN"
        );
        assert!(validate_vm_resource_transition_plan(&plan, &host).is_ok());
        let mut invalid = plan.clone();
        invalid.resources[0].reason_code = "ARBITRARY_FIX_WITH_SHELL".into();
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_REASON_CODE_MISMATCH")
        );
        invalid = plan.clone();
        invalid.resources[0].step = FleetHostPlannedStep::Stop as i32;
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_ACTION_REASON_CONFLICT")
        );
        invalid = plan.clone();
        invalid.resources[0].reason = Reason::Unspecified as i32;
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_REASON_UNSPECIFIED")
        );
        invalid = plan.clone();
        invalid.resources[0].resource_id = "container/foreign/line2-proxy".into();
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_IDENTITY_INVALID")
        );
        invalid = plan.clone();
        invalid.owner_attested = true;
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_SCOPE_OR_AUTHORITY_INVALID")
        );
        invalid = plan.clone();
        invalid.resources[0]
            .resource
            .as_mut()
            .unwrap()
            .compose_service = "foreign".into();
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_IDENTITY_INVALID")
        );
    }

    #[test]
    fn independent_runtime_states_never_fake_config_or_owner_authority() {
        let (mut host, mut report) = fixture();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        assert_eq!(
            propose_vm_resource_transitions(&host, &report)
                .unwrap()
                .resources[0]
                .reason_code,
            "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN"
        );
        report.resources[0].health.clear();
        report.resources[0].reason_code = "RUNNING_NO_HEALTHCHECK".into();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        assert_eq!(
            propose_vm_resource_transitions(&host, &report)
                .unwrap()
                .resources[0]
                .reason_code,
            "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN"
        );

        report.resources[0].running = false;
        report.resources[0].reason_code = "STOPPED".into();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Start);
        host.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        report.resources[0].running = true;
        report.resources[0].reason_code = "RUNNING_NO_HEALTHCHECK".into();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Stop);

        host.target = None;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Blocked);
        host.target = Some(FleetHostTarget {
            run_state: FleetHostRunState::Running as i32,
            windows_mode: FleetHostMode::Unspecified as i32,
        });
        report.resources[0].ownership_proven = false;
        report.resources[0].container_id.clear();
        report.resources[0].running = false;
        report.resources[0].running_proven = false;
        report.resources[0].reason_code = "FOREIGN_OWNER".into();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Blocked);
    }

    #[test]
    fn running_noop_never_conceals_unproven_config() {
        let (host, report) = fixture();
        let plan = propose_vm_resource_transitions(&host, &report).unwrap();
        assert_eq!(plan.resources[0].step, FleetHostPlannedStep::Noop as i32);
        assert!(vm_resource_requires_attention(&plan.resources[0]));
        let mut stopped = host;
        stopped.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        let mut report = report;
        report.resources[0].running = false;
        report.resources[0].health.clear();
        report.resources[0].reason_code = "STOPPED".into();
        let plan = propose_vm_resource_transitions(&stopped, &report).unwrap();
        assert!(!vm_resource_requires_attention(&plan.resources[0]));
    }

    #[test]
    fn absence_and_untrusted_reports_are_not_recovery_authority() {
        let (mut host, mut report) = fixture();
        report.resources[0] = FleetVmResourceReadback {
            resource: host.vm_containers.first().cloned(),
            reason_code: "CONTAINER_ABSENT".into(),
            ..Default::default()
        };
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Install);
        host.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        report.remote_attested = true;
        assert!(propose_vm_resource_transitions(&host, &report).is_err());
        report.remote_attested = false;
        report.machine_id = "foreign-vm".into();
        assert!(propose_vm_resource_transitions(&host, &report).is_err());
    }
}
