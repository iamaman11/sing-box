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

/// Deterministic resource policy diff. "Installed" is the protected
/// root-local bundle, not Docker physical proof. "Desired" is independently
/// compiled from the immutable, Git-owned ReleaseSet. This function never
/// accepts a runner authority or performs mutations.
pub fn propose_vm_graph_reconcile(
    host: &FleetHost,
    installed: &FleetVmDesiredGraph,
    desired: &FleetVmDesiredGraph,
) -> Result<crate::FleetVmGraphReconcile, &'static str> {
    use crate::{FleetVmGraphReconcile, FleetVmGraphResourceChange, FleetVmPolicyChange};
    validate_vm_desired_graph(installed, host)?;
    validate_vm_desired_graph(desired, host)?;
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
        resources.push(FleetVmGraphResourceChange {
            resource: after.resource.clone(),
            change: change as i32,
            expected_image_ref: after.image_ref.clone(),
            expected_config_template_sha256: after.config_template_sha256.clone(),
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
        FleetHostPlannedStep as Step, FleetHostRunState, FleetVmResourceTransition,
        FleetVmResourceTransitionPlan,
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
                (Step::Blocked, "TARGET_UNSET_OBSERVE_ONLY")
            }
            Some(FleetHostRunState::Stopped)
                if !row.present && row.reason_code == "CONTAINER_ABSENT" =>
            {
                (Step::Noop, "ABSENT_AS_DESIRED")
            }
            Some(FleetHostRunState::Running)
                if !row.present && row.reason_code == "CONTAINER_ABSENT" =>
            {
                (Step::Install, "CONTAINER_ABSENT_INSTALL_REQUIRED")
            }
            Some(_) if !row.present || !row.ownership_proven || !row.running_proven => {
                (Step::Blocked, "RESOURCE_IDENTITY_OR_STATE_UNPROVEN")
            }
            Some(FleetHostRunState::Stopped) if row.running => {
                (Step::Stop, "CONTAINER_RUNNING_BUT_TARGET_STOPPED")
            }
            Some(FleetHostRunState::Stopped) => (Step::Noop, "STOPPED_AS_DESIRED"),
            Some(FleetHostRunState::Running) if !row.running => {
                (Step::Start, "CONTAINER_STOPPED_BUT_TARGET_RUNNING")
            }
            Some(FleetHostRunState::Running)
                if matches!(
                    row.reason_code.as_str(),
                    "HEALTHY" | "RUNNING_NO_HEALTHCHECK"
                ) =>
            {
                // An already-running container requires no START. Docker
                // health is NOT proof of configuration or network readiness.
                (Step::Noop, "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN")
            }
            Some(FleetHostRunState::Running) => {
                (Step::Blocked, "RUNTIME_HEALTH_OR_CONFIG_UNPROVEN")
            }
        };
        resources.push(FleetVmResourceTransition {
            resource: row.resource.clone(),
            step: step as i32,
            reason_code: reason.to_owned(),
        });
    }
    Ok(FleetVmResourceTransitionPlan {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        resources,
        owner_attested: false,
        mutation_authorized: false,
    })
}

/// A runtime NOOP is not evidence of configuration convergence. Keep that
/// distinction visible in the *same* operator diagnostic and typed planner.
pub fn vm_resource_requires_attention(transition: &crate::FleetVmResourceTransition) -> bool {
    transition.step != crate::FleetHostPlannedStep::Noop as i32
        || transition.reason_code == "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN"
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
