//! One native, Git-owned isolated IPv4/IPv6 route transaction.
//! Same Worker-signed HostIntent and protected journal as the existing
//! managed Docker resource; a runner never supplies iproute2 argv.
use super::*;
use edge_shared_types::{
    FleetHost, FleetVmIpFamily as Family, FleetVmKernelRoute, FleetVmManagedKernelRoute,
    FleetVmManagedKernelRouteReadback,
};
use prost::Message;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command as OsCommand;

const TABLE_FIRST: u32 = 20_000;
const TABLE_LAST: u32 = 20_999;

#[derive(Debug)]
pub(super) struct PreparedManagedRoute {
    spec: FleetVmManagedKernelRoute,
    create: bool,
    before: Vec<FleetVmKernelRoute>,
    interface_index: u32,
}

pub(super) fn is_managed_route_manifest(path: &str) -> bool {
    path.starts_with("managed/host-route-") && path.ends_with(".pb")
}

fn canonical_destination(spec: &FleetVmManagedKernelRoute) -> bool {
    let Ok(ip) = spec.destination.parse::<IpAddr>() else {
        return false;
    };
    if spec.destination != ip.to_string() {
        return false;
    }
    match (Family::try_from(spec.family), ip) {
        (Ok(Family::V4), IpAddr::V4(ip)) if (8..=32).contains(&spec.prefix_length) => {
            ip != Ipv4Addr::UNSPECIFIED
                && ip != Ipv4Addr::BROADCAST
                && !ip.is_multicast()
                && !ip.is_loopback()
                && u32::from(ip) & ((1_u32 << (32 - spec.prefix_length)) - 1) == 0
        }
        (Ok(Family::V6), IpAddr::V6(ip)) if (16..=128).contains(&spec.prefix_length) => {
            ip != Ipv6Addr::UNSPECIFIED
                && !ip.is_multicast()
                && !ip.is_loopback()
                && u128::from(ip) & ((1_u128 << (128 - spec.prefix_length)) - 1) == 0
        }
        _ => false,
    }
}

fn canonical_scope(host: &FleetHost, path: &str, spec: &FleetVmManagedKernelRoute) -> bool {
    let Some(suffix) = path
        .strip_prefix("managed/host-route-")
        .and_then(|value| value.strip_suffix(".pb"))
    else {
        return false;
    };
    !suffix.is_empty()
        && suffix.len() <= 24
        && !suffix.starts_with('-')
        && !suffix.ends_with('-')
        && suffix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && spec.schema_version == 1
        && host.kind == edge_shared_types::FleetHostKind::Vm as i32
        && spec.machine_id == host.machine_id
        && spec.resource_name == format!("sb-{}-{suffix}", host.machine_id)
        && spec.resource_name.len() <= 112
        && (TABLE_FIRST..=TABLE_LAST).contains(&spec.table_id)
        && spec.interface_name.starts_with("sb")
        && (3..=15).contains(&spec.interface_name.len())
        && !spec.interface_name.ends_with('-')
        && spec
            .interface_name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && canonical_destination(spec)
}

fn decode_route(
    host: &FleetHost,
    path: &str,
    raw: &[u8],
) -> Result<FleetVmManagedKernelRoute, String> {
    if raw.is_empty() || raw.len() > 2048 {
        return Err("HOST_VM_MANAGED_ROUTE_PROTOBUF_SIZE_INVALID".into());
    }
    let spec = FleetVmManagedKernelRoute::decode(raw)
        .map_err(|_| "HOST_VM_MANAGED_ROUTE_PROTOBUF_INVALID")?;
    if spec.encode_to_vec() != raw || !canonical_scope(host, path, &spec) {
        return Err("HOST_VM_MANAGED_ROUTE_SCOPE_OR_CANONICAL_INVALID".into());
    }
    Ok(spec)
}

// A reserved interface prefix is NOT ownership.  The existing privileged
// root owner must have assigned the exact per-resource Linux ifalias before a
// Git-declared route can use that interface.  The ifindex additionally binds
// the alias to the observed rtnetlink link, preventing name-only adoption.
fn canonical_owned_interface_alias(spec: &FleetVmManagedKernelRoute, alias: &str) -> bool {
    alias == format!("sing-box:{}:{}", spec.machine_id, spec.resource_name)
}

pub(super) fn exact_docker_bridge_owner(
    spec: &FleetVmManagedKernelRoute,
    network: &bollard::models::NetworkInspect,
) -> bool {
    let options = network.options.as_ref();
    let labels = network.labels.as_ref();
    network.name.as_deref() == Some(spec.resource_name.as_str())
        && network.driver.as_deref() == Some("bridge")
        && network.internal == Some(true)
        && network.attachable == Some(false)
        && options.and_then(|value| value.get("com.docker.network.bridge.name"))
            == Some(&spec.interface_name)
        && labels.and_then(|value| value.get("io.github.iamaman11.singbox.machine"))
            == Some(&spec.machine_id)
        && labels.and_then(|value| value.get("io.github.iamaman11.singbox.resource"))
            == Some(&spec.resource_name)
}

async fn prove_managed_interface_owner(
    spec: &FleetVmManagedKernelRoute,
    expected_index: u32,
) -> Result<(), String> {
    let link = Path::new("/sys/class/net").join(&spec.interface_name);
    let index = fs::read_to_string(link.join("ifindex"))
        .map_err(|_| "HOST_VM_MANAGED_ROUTE_LINK_INDEX_UNAVAILABLE")?
        .trim()
        .parse::<u32>()
        .map_err(|_| "HOST_VM_MANAGED_ROUTE_LINK_INDEX_INVALID")?;
    if expected_index != index {
        return Err("HOST_VM_MANAGED_ROUTE_LINK_IDENTITY_CHANGED".into());
    }
    // A root-owned explicitly labelled link remains supported; ordinary
    // "sb" prefixes or a reused interface index never establish ownership.
    let alias = fs::read_to_string(link.join("ifalias")).unwrap_or_default();
    if canonical_owned_interface_alias(spec, alias.trim_end_matches('\n')) {
        return Ok(());
    }
    // The existing Docker owner can alternatively prove a Linux bridge.
    // Require an exact same-name Git-owned Docker resource, matching bridge
    // option, bridge kernel type and full owner labels. This avoids creating
    // a second native link lifecycle engine for Docker-managed interfaces.
    if !link.join("bridge").is_dir() {
        return Err("HOST_VM_MANAGED_ROUTE_LINK_OWNER_UNPROVEN".into());
    }
    let docker = super::super::docker_connection()
        .await
        .map_err(|_| "HOST_VM_MANAGED_ROUTE_DOCKER_OWNER_UNAVAILABLE")?;
    let network = docker
        .inspect_network(&spec.resource_name, None)
        .await
        .map_err(|_| "HOST_VM_MANAGED_ROUTE_DOCKER_NETWORK_UNPROVEN")?;
    if !exact_docker_bridge_owner(spec, &network) {
        return Err("HOST_VM_MANAGED_ROUTE_DOCKER_LINK_FOREIGN".into());
    }
    Ok(())
}

fn route_in_owned_table(
    kernel: &edge_shared_types::FleetVmDualStackNetwork,
    spec: &FleetVmManagedKernelRoute,
) -> Result<(u32, Vec<FleetVmKernelRoute>), String> {
    edge_shared_types::host_resources::validate_vm_dual_stack_network(kernel)
        .map_err(str::to_owned)?;
    let links = kernel
        .links
        .iter()
        .filter(|link| link.name == spec.interface_name && !link.loopback)
        .collect::<Vec<_>>();
    if links.len() != 1 {
        return Err("HOST_VM_MANAGED_ROUTE_INTERFACE_UNPROVEN".into());
    }
    let index = links[0].interface_index;
    // A supposedly isolated table with ANY existing policy rule can already
    // steer foreign traffic. Reserving its numeric ID is insufficient proof
    // of owner isolation. Fail before BEGIN or further native effects.
    if kernel
        .policy_rules
        .iter()
        .any(|rule| rule.table_id == spec.table_id)
    {
        return Err("HOST_VM_MANAGED_ROUTE_TABLE_POLICY_RULE_CONFLICT".into());
    }
    let routes = kernel
        .routes
        .iter()
        .filter(|route| route.table_id == spec.table_id)
        .cloned()
        .collect::<Vec<_>>();
    if routes.len() > 1 {
        return Err("HOST_VM_MANAGED_ROUTE_TABLE_SHARED_OR_FOREIGN".into());
    }
    if let Some(row) = routes.first()
        && (row.family != spec.family
            || row.destination != spec.destination
            || row.prefix_length != spec.prefix_length
            || row.output_interface_index != index
            || !row.gateway.is_empty()
            || !row.preferred_source.is_empty()
            || row.metric != 0
            || row.kernel_protocol)
    {
        return Err("HOST_VM_MANAGED_ROUTE_TABLE_FOREIGN_OR_DRIFT".into());
    }
    Ok((index, routes))
}

pub(super) async fn preflight_managed_route(
    host: &FleetHost,
    path: &str,
    before: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<PreparedManagedRoute, String> {
    if before.is_some() == after.is_some() {
        return Err("HOST_VM_MANAGED_ROUTE_UPDATE_OR_NOOP_UNSUPPORTED".into());
    }
    let spec = decode_route(
        host,
        path,
        before
            .or(after)
            .ok_or("HOST_VM_MANAGED_ROUTE_MISSING_MANIFEST")?,
    )?;
    let create = after.is_some();
    let kernel = crate::network_observation::observe_dual_stack()
        .await
        .map_err(str::to_owned)?;
    let (index, routes) = route_in_owned_table(&kernel, &spec)?;
    prove_managed_interface_owner(&spec, index).await?;
    if (create && !routes.is_empty()) || (!create && routes.len() != 1) {
        return Err("HOST_VM_MANAGED_ROUTE_PRESTATE_DRIFT".into());
    }
    Ok(PreparedManagedRoute {
        spec,
        create,
        before: routes,
        interface_index: index,
    })
}

fn transition_matches(
    old: &[FleetVmKernelRoute],
    new: &[FleetVmKernelRoute],
    create: bool,
) -> bool {
    (create && old.is_empty() && new.len() == 1) || (!create && old.len() == 1 && new.is_empty())
}

pub(super) async fn apply_managed_route_once(plan: &PreparedManagedRoute) -> Result<(), String> {
    let before = crate::network_observation::observe_dual_stack()
        .await
        .map_err(|_| "HOST_VM_MANAGED_ROUTE_PRE_EFFECT_UNPROVEN_NO_REPLAY")?;
    let (index, old) = route_in_owned_table(&before, &plan.spec)?;
    prove_managed_interface_owner(&plan.spec, index).await?;
    if index != plan.interface_index || old != plan.before {
        return Err("HOST_VM_MANAGED_ROUTE_CAS_CHANGED_NO_REPLAY".into());
    }
    let family = if plan.spec.family == Family::V4 as i32 {
        "-4"
    } else {
        "-6"
    };
    let op = if plan.create { "add" } else { "del" };
    let destination = format!("{}/{}", plan.spec.destination, plan.spec.prefix_length);
    let table = plan.spec.table_id.to_string();
    // No shell, user argv, default route, provider write, retry or second
    // service. Only project-reserved isolated table and sb* link are touched.
    // iproute2 is bounded by timeout, but even a bounded synchronous wait
    // must not block the single Tokio runtime that owns native control.
    // Run it on the existing Tokio blocking pool; no new daemon/scheduler.
    let interface_name = plan.spec.interface_name.clone();
    let status = tokio::task::spawn_blocking(move || {
        OsCommand::new("/usr/bin/timeout")
            .args([
                "--kill-after=2s",
                "8s",
                "/usr/sbin/ip",
                family,
                "route",
                op,
                &destination,
                "dev",
                &interface_name,
                "table",
                &table,
            ])
            .status()
    })
    .await
    .map_err(|_| "HOST_VM_MANAGED_ROUTE_EFFECT_TASK_UNKNOWN_NO_REPLAY")?
    .map_err(|_| "HOST_VM_MANAGED_ROUTE_EFFECT_START_UNKNOWN_NO_REPLAY")?;
    if !status.success() {
        return Err("HOST_VM_MANAGED_ROUTE_EFFECT_UNCERTAIN_NO_REPLAY".into());
    }
    let post = crate::network_observation::observe_dual_stack()
        .await
        .map_err(|_| "HOST_VM_MANAGED_ROUTE_POST_EFFECT_UNPROVEN_NO_REPLAY")?;
    let (after_index, new) = route_in_owned_table(&post, &plan.spec)?;
    prove_managed_interface_owner(&plan.spec, after_index).await?;
    if after_index != plan.interface_index || !transition_matches(&plan.before, &new, plan.create) {
        return Err("HOST_VM_MANAGED_ROUTE_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    Ok(())
}

fn failure(reason: &str) -> FleetVmManagedKernelRouteReadback {
    FleetVmManagedKernelRouteReadback {
        reason_code: reason.to_owned(),
        ..Default::default()
    }
}

pub(crate) async fn collect_native_managed_kernel_routes(
    stack_dir: &Path,
    host: &FleetHost,
) -> Vec<FleetVmManagedKernelRouteReadback> {
    let dir = stack_dir.join("managed");
    let entries = match fs::read_dir(&dir) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => return vec![failure("MANAGED_ROUTE_DIRECTORY_UNAVAILABLE")],
    };
    if super::checked_managed_directory(stack_dir, false).is_err() {
        return vec![failure("MANAGED_ROUTE_DIRECTORY_UNTRUSTED")];
    }
    let mut names = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return vec![failure("MANAGED_ROUTE_DIRECTORY_ENTRY_INVALID")];
        };
        let Ok(name) = entry.file_name().into_string() else {
            return vec![failure("MANAGED_ROUTE_FILENAME_INVALID")];
        };
        if is_managed_route_manifest(&format!("managed/{name}")) {
            names.push(name);
            if names.len() > 32 {
                return vec![failure("MANAGED_ROUTE_MANIFEST_COUNT_EXCEEDED")];
            }
        }
    }
    names.sort();
    if names.is_empty() {
        return Vec::new();
    }
    let kernel = crate::network_observation::observe_dual_stack().await;
    let mut results = Vec::new();
    for name in names {
        let mut row = failure("MANAGED_ROUTE_MANIFEST_UNPROVEN");
        let bytes = match super::checked_managed_existing_file(&dir.join(&name), 0) {
            Ok(Some(bytes)) => bytes,
            _ => {
                results.push(row);
                continue;
            }
        };
        let path = format!("managed/{name}");
        let spec = match decode_route(host, &path, &bytes) {
            Ok(value) => value,
            Err(_) => {
                results.push(row);
                continue;
            }
        };
        row.resource_name = spec.resource_name.clone();
        row.family = spec.family;
        row.table_id = spec.table_id;
        row.manifest_sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .to_vec();
        match kernel.as_ref() {
            Ok(snapshot) => match route_in_owned_table(snapshot, &spec) {
                Ok((index, routes)) => match prove_managed_interface_owner(&spec, index).await {
                    Ok(()) => {
                        row.present = routes.len() == 1;
                        row.converged = row.present;
                        row.reason_code = if row.present {
                            "DESIRED_PRESENT"
                        } else {
                            "ROUTE_MISSING"
                        }
                        .into();
                    }
                    Err(reason) => row.reason_code = reason,
                },
                Err(reason) => row.reason_code = reason,
            },
            Err(_) => row.reason_code = "ROUTE_KERNEL_DUMP_UNAVAILABLE".into(),
        }
        results.push(row);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> FleetHost {
        FleetHost {
            machine_id: "vm-test".into(),
            kind: edge_shared_types::FleetHostKind::Vm as i32,
            ..Default::default()
        }
    }

    fn route(family: Family, dst: &str, prefix: u32) -> FleetVmManagedKernelRoute {
        FleetVmManagedKernelRoute {
            schema_version: 1,
            machine_id: "vm-test".into(),
            resource_name: "sb-vm-test-lab".into(),
            family: family as i32,
            destination: dst.into(),
            prefix_length: prefix,
            interface_name: "sblab0".into(),
            table_id: 20_100,
        }
    }

    #[test]
    fn docker_bridge_route_rejects_foreign_owner_name_and_linux_interface() {
        use std::collections::HashMap;
        let spec = route(Family::V4, "10.31.0.0", 16);
        let mut network = bollard::models::NetworkInspect {
            name: Some(spec.resource_name.clone()),
            driver: Some("bridge".into()),
            internal: Some(true),
            attachable: Some(false),
            options: Some(HashMap::from([(
                "com.docker.network.bridge.name".into(),
                spec.interface_name.clone(),
            )])),
            labels: Some(HashMap::from([
                (
                    "io.github.iamaman11.singbox.machine".into(),
                    spec.machine_id.clone(),
                ),
                (
                    "io.github.iamaman11.singbox.resource".into(),
                    spec.resource_name.clone(),
                ),
            ])),
            ..Default::default()
        };
        assert!(exact_docker_bridge_owner(&spec, &network));
        network.labels.as_mut().unwrap().insert(
            "io.github.iamaman11.singbox.machine".into(),
            "other-host".into(),
        );
        assert!(!exact_docker_bridge_owner(&spec, &network));
        network.labels.as_mut().unwrap().insert(
            "io.github.iamaman11.singbox.machine".into(),
            spec.machine_id.clone(),
        );
        network
            .options
            .as_mut()
            .unwrap()
            .insert("com.docker.network.bridge.name".into(), "sbforeign0".into());
        assert!(!exact_docker_bridge_owner(&spec, &network));
        network.options.as_mut().unwrap().insert(
            "com.docker.network.bridge.name".into(),
            spec.interface_name.clone(),
        );
        network.internal = Some(false);
        assert!(!exact_docker_bridge_owner(&spec, &network));
    }

    #[test]
    fn route_requires_exact_resource_owned_ifalias_not_just_sb_prefix() {
        let first = route(Family::V4, "10.31.0.0", 16);
        assert!(canonical_owned_interface_alias(
            &first,
            "sing-box:vm-test:sb-vm-test-lab"
        ));
        for forged in [
            "",
            "sblab0",
            "sing-box:other-vm:sb-vm-test-lab",
            "sing-box:vm-test:sb-vm-test-other",
            "sing-box:vm-test:sb-vm-test-lab-extra",
        ] {
            assert!(!canonical_owned_interface_alias(&first, forged));
        }
    }

    #[test]
    fn managed_routes_reject_default_foreign_main_and_noncanonical_prefixes() {
        let path = "managed/host-route-lab.pb";
        let v4 = route(Family::V4, "10.31.0.0", 16);
        let v6 = route(Family::V6, "fd12:3456::", 48);
        assert!(decode_route(&host(), path, &v4.encode_to_vec()).is_ok());
        assert!(decode_route(&host(), path, &v6.encode_to_vec()).is_ok());
        for (dst, prefix) in [
            ("0.0.0.0", 0),
            ("10.31.8.0", 16),
            ("224.0.0.0", 8),
            ("127.0.0.1", 32),
        ] {
            assert!(!canonical_destination(&route(Family::V4, dst, prefix)));
        }
        for (dst, prefix) in [("::", 0), ("fd12:3456::1", 48), ("ff00::", 16)] {
            assert!(!canonical_destination(&route(Family::V6, dst, prefix)));
        }
        let mut invalid = v4.clone();
        invalid.table_id = 254;
        assert!(!canonical_scope(&host(), path, &invalid));
        invalid = v4.clone();
        invalid.interface_name = "eth0".into();
        assert!(!canonical_scope(&host(), path, &invalid));
        invalid = v4;
        invalid.machine_id = "foreign-vm".into();
        assert!(!canonical_scope(&host(), path, &invalid));
    }

    #[test]
    fn kernel_route_snapshot_rejects_foreign_table_and_cas_drift() {
        let spec = route(Family::V4, "10.31.0.0", 16);
        let mut kernel = edge_shared_types::FleetVmDualStackNetwork {
            links: vec![edge_shared_types::Ipv4LinkObservation {
                interface_index: 11,
                name: "sblab0".into(),
                up: true,
                lower_up: true,
                loopback: false,
            }],
            ipv4_route_dump_complete: true,
            ipv6_route_dump_complete: true,
            ipv4_rule_dump_complete: true,
            ipv6_rule_dump_complete: true,
            ..Default::default()
        };
        assert_eq!(route_in_owned_table(&kernel, &spec).unwrap().0, 11);
        assert!(route_in_owned_table(&kernel, &spec).unwrap().1.is_empty());
        let expected = FleetVmKernelRoute {
            family: Family::V4 as i32,
            destination: spec.destination.clone(),
            prefix_length: spec.prefix_length,
            table_id: spec.table_id,
            output_interface_index: 11,
            ..Default::default()
        };
        kernel.routes.push(expected.clone());
        assert_eq!(
            route_in_owned_table(&kernel, &spec).unwrap().1,
            vec![expected.clone()]
        );
        kernel.routes[0].table_id = 254;
        assert!(route_in_owned_table(&kernel, &spec).unwrap().1.is_empty());
        kernel.routes[0].table_id = spec.table_id;
        kernel.routes[0].output_interface_index = 12;
        assert!(route_in_owned_table(&kernel, &spec).is_err());
        kernel.routes[0].output_interface_index = 11;
        kernel.routes[0].gateway = "10.0.0.1".into();
        assert!(route_in_owned_table(&kernel, &spec).is_err());
        kernel.routes[0].gateway.clear();
        kernel.routes.push(expected);
        assert!(route_in_owned_table(&kernel, &spec).is_err());
        kernel.routes.clear();
        kernel
            .policy_rules
            .push(edge_shared_types::FleetVmKernelPolicyRule {
                family: Family::V4 as i32,
                table_id: spec.table_id,
                priority: 12_345,
                ..Default::default()
            });
        assert!(route_in_owned_table(&kernel, &spec).is_err());
    }

    #[test]
    fn route_effect_is_once_only_and_cannot_call_noop_a_success() {
        let row = FleetVmKernelRoute {
            family: Family::V4 as i32,
            destination: "10.31.0.0".into(),
            prefix_length: 16,
            table_id: 20_100,
            output_interface_index: 11,
            ..Default::default()
        };
        assert!(transition_matches(&[], &[row.clone()], true));
        assert!(transition_matches(&[row.clone()], &[], false));
        assert!(!transition_matches(&[], &[], true));
        assert!(!transition_matches(&[row.clone()], &[row.clone()], true));
        assert!(!transition_matches(&[row], &[], true));
    }
}
