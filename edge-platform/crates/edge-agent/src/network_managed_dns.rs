//! Per-link systemd-resolved DNS on one explicitly owned Docker bridge.
//! No global resolver edits, revert, shell, default-route changes or retries.
//! The existing signed BEGIN / UNKNOWN_NO_REPLAY journal owns the effect.
use super::*;
use edge_shared_types::{
    FleetHost, FleetHostKind, FleetVmManagedKernelRoute, FleetVmManagedSystemDns,
    FleetVmManagedSystemDnsReadback,
};
use prost::Message;
use std::net::IpAddr;
use std::process::{Command as OsCommand, Stdio};

const DNS_LIMIT: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinkDnsState {
    nameservers: Vec<String>,
    domains: Vec<String>,
}

#[derive(Debug)]
pub(super) struct PreparedManagedDns {
    spec: FleetVmManagedSystemDns,
    after: Option<FleetVmManagedSystemDns>,
    previous: LinkDnsState,
    interface_index: u32,
    network_id: String,
}

pub(super) fn is_managed_dns_manifest(path: &str) -> bool {
    path.starts_with("managed/host-dns-") && path.ends_with(".pb")
}

fn decode_scope(
    host: &FleetHost,
    path: &str,
    bytes: &[u8],
) -> Result<FleetVmManagedSystemDns, String> {
    let suffix = path
        .strip_prefix("managed/host-dns-")
        .and_then(|s| s.strip_suffix(".pb"))
        .ok_or("HOST_VM_DNS_MANIFEST_PATH_INVALID")?;
    if suffix.is_empty()
        || suffix.len() > 24
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        || bytes.is_empty()
        || bytes.len() > 2048
    {
        return Err("HOST_VM_DNS_MANIFEST_BOUNDS_INVALID".into());
    }
    let spec =
        FleetVmManagedSystemDns::decode(bytes).map_err(|_| "HOST_VM_DNS_PROTOBUF_INVALID")?;
    if spec.encode_to_vec() != bytes
        || spec.schema_version != 1
        || host.kind != FleetHostKind::Vm as i32
        || host.machine_id.is_empty() || host.machine_id.len() > 64
        || !host.machine_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || spec.machine_id != host.machine_id
        || spec.resource_name != format!("sb-{}-{suffix}", host.machine_id)
        || spec.resource_name.len() > 112
        || !spec.interface_name.starts_with("sb")
        || !(3..=15).contains(&spec.interface_name.len())
        || !spec.interface_name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        // The routing-only domain is an isolated dedicated namespace. An
        // arbitrary "~." / public suffix could capture GitHub/Worker DNS.
        || spec.routing_domain != format!("~{suffix}.singbox.internal")
        || spec.name_servers.is_empty() || spec.name_servers.len() > DNS_LIMIT
    {
        return Err("HOST_VM_DNS_SCOPE_OR_CONTROL_PATH_UNPROVEN".into());
    }
    let mut previous = None;
    for addr in &spec.name_servers {
        let ip = addr
            .parse::<IpAddr>()
            .map_err(|_| "HOST_VM_DNS_SERVER_INVALID")?;
        if ip.to_string() != *addr
            || ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || previous.as_ref().is_some_and(|p| p >= addr)
        {
            return Err("HOST_VM_DNS_SERVER_NONCANONICAL".into());
        }
        previous = Some(addr);
    }
    Ok(spec)
}

fn owner_route(spec: &FleetVmManagedSystemDns) -> FleetVmManagedKernelRoute {
    FleetVmManagedKernelRoute {
        machine_id: spec.machine_id.clone(),
        resource_name: spec.resource_name.clone(),
        interface_name: spec.interface_name.clone(),
        ..Default::default()
    }
}

async fn owned_bridge(spec: &FleetVmManagedSystemDns) -> Result<(u32, String), String> {
    let link = Path::new("/sys/class/net").join(&spec.interface_name);
    if !link.join("bridge").is_dir() {
        return Err("HOST_VM_DNS_BRIDGE_LINK_MISSING_OR_FOREIGN".into());
    }
    let index = fs::read_to_string(link.join("ifindex"))
        .map_err(|_| "HOST_VM_DNS_LINK_INDEX_UNAVAILABLE")?
        .trim()
        .parse::<u32>()
        .map_err(|_| "HOST_VM_DNS_LINK_INDEX_INVALID")?;
    let docker = super::super::docker_connection()
        .await
        .map_err(|_| "HOST_VM_DNS_DOCKER_UNAVAILABLE")?;
    let net = docker
        .inspect_network(&spec.resource_name, None)
        .await
        .map_err(|_| "HOST_VM_DNS_NETWORK_UNAVAILABLE")?;
    if !super::managed_route::exact_docker_bridge_owner(&owner_route(spec), &net) {
        return Err("HOST_VM_DNS_NETWORK_OWNER_UNPROVEN".into());
    }
    let id = net
        .id
        .filter(|v| !v.is_empty())
        .ok_or("HOST_VM_DNS_NETWORK_ID_UNPROVEN")?;
    Ok((index, id))
}

fn parse_link_values(raw: &str, index: u32, interface_name: &str) -> Result<Vec<String>, String> {
    let prefix = format!("Link {index} ({interface_name}):");
    let line = raw.trim_end_matches('\n');
    let remainder = line
        .strip_prefix(&prefix)
        .ok_or("HOST_VM_DNS_LINK_OUTPUT_UNPROVEN")?;
    if remainder.contains('\n') || remainder.contains('\r') {
        return Err("HOST_VM_DNS_LINK_OUTPUT_AMBIGUOUS".into());
    }
    Ok(remainder.split_whitespace().map(str::to_owned).collect())
}

async fn resolvectl(args: Vec<String>) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let result = OsCommand::new("/usr/bin/timeout")
            .args(["--kill-after=2s", "8s", "/usr/bin/resolvectl"])
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| "HOST_VM_DNS_RESOLVECTL_START_UNAVAILABLE".to_owned())?;
        if !result.status.success() {
            return Err("HOST_VM_DNS_RESOLVECTL_FAILED_OR_TIMEOUT".into());
        }
        if result.stdout.len() > 16384 {
            return Err("HOST_VM_DNS_RESOLVECTL_OUTPUT_OVERSIZE".into());
        }
        String::from_utf8(result.stdout)
            .map_err(|_| "HOST_VM_DNS_RESOLVECTL_OUTPUT_UTF8_INVALID".into())
    })
    .await
    .map_err(|_| "HOST_VM_DNS_RESOLVECTL_TASK_UNKNOWN_NO_REPLAY".to_owned())?
}

async fn inspect(spec: &FleetVmManagedSystemDns, index: u32) -> Result<LinkDnsState, String> {
    let dns = resolvectl(vec!["dns".into(), spec.interface_name.clone()]).await?;
    let domains = resolvectl(vec!["domain".into(), spec.interface_name.clone()]).await?;
    Ok(LinkDnsState {
        nameservers: parse_link_values(&dns, index, &spec.interface_name)?,
        domains: parse_link_values(&domains, index, &spec.interface_name)?,
    })
}

fn expected_state(spec: Option<&FleetVmManagedSystemDns>) -> LinkDnsState {
    LinkDnsState {
        nameservers: spec.map(|s| s.name_servers.clone()).unwrap_or_default(),
        domains: spec
            .map(|s| vec![s.routing_domain.clone()])
            .unwrap_or_default(),
    }
}

pub(super) async fn preflight_managed_dns(
    host: &FleetHost,
    path: &str,
    before: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<PreparedManagedDns, String> {
    let old = before.map(|s| decode_scope(host, path, s)).transpose()?;
    let next = after.map(|s| decode_scope(host, path, s)).transpose()?;
    let spec = next
        .as_ref()
        .or(old.as_ref())
        .ok_or("HOST_VM_DNS_TRANSITION_EMPTY")?;
    if old.as_ref().is_some_and(|p| {
        next.as_ref().is_some_and(|n| {
            p.machine_id != n.machine_id
                || p.resource_name != n.resource_name
                || p.interface_name != n.interface_name
                || p == n
        })
    }) {
        return Err("HOST_VM_DNS_IDENTITY_CHANGE_OR_NOOP".into());
    }
    let (index, id) = owned_bridge(spec).await?;
    let current = inspect(spec, index).await?;
    if current != expected_state(old.as_ref()) {
        return Err("HOST_VM_DNS_PRESTATE_FOREIGN_OR_DRIFT".into());
    }
    Ok(PreparedManagedDns {
        spec: spec.clone(),
        after: next,
        previous: current,
        interface_index: index,
        network_id: id,
    })
}

pub(super) async fn apply_managed_dns_once(plan: &PreparedManagedDns) -> Result<(), String> {
    let (index, id) = owned_bridge(&plan.spec).await?;
    if index != plan.interface_index
        || id != plan.network_id
        || inspect(&plan.spec, index)
            .await
            .map_err(|_| "HOST_VM_DNS_CAS_UNPROVEN_NO_REPLAY")?
            != plan.previous
    {
        return Err("HOST_VM_DNS_CAS_CHANGED_NO_REPLAY".into());
    }
    let target = expected_state(plan.after.as_ref());
    // On removal, clear DNS first: an absent resolver cannot leak traffic.
    // On creation, set the isolated routing-only domain before DNS servers.
    // Separate native calls are NOT atomic. Any uncertain result is retained
    // in the existing journal as UNKNOWN_NO_REPLAY, never blindly retried.
    let commands: Vec<(&str, Vec<String>)> = if plan.after.is_some() {
        vec![
            ("domain", target.domains.clone()),
            ("dns", target.nameservers.clone()),
        ]
    } else {
        vec![
            ("dns", vec![String::new()]),
            ("domain", vec![String::new()]),
        ]
    };
    for (command, values) in commands {
        let mut args = vec![command.to_owned(), plan.spec.interface_name.clone()];
        args.extend(values);
        resolvectl(args)
            .await
            .map_err(|_| "HOST_VM_DNS_EFFECT_UNKNOWN_NO_REPLAY")?;
    }
    if inspect(&plan.spec, index)
        .await
        .map_err(|_| "HOST_VM_DNS_POSTSTATE_UNKNOWN_NO_REPLAY")?
        != target
    {
        return Err("HOST_VM_DNS_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    let (after_index, after_id) = owned_bridge(&plan.spec)
        .await
        .map_err(|_| "HOST_VM_DNS_POST_OWNER_UNKNOWN_NO_REPLAY")?;
    if after_index != index || after_id != id {
        return Err("HOST_VM_DNS_POST_OWNER_CHANGED_NO_REPLAY".into());
    }
    Ok(())
}

fn failure(code: &str) -> FleetVmManagedSystemDnsReadback {
    FleetVmManagedSystemDnsReadback {
        reason_code: code.into(),
        ..Default::default()
    }
}

pub(crate) async fn collect_native_managed_system_dns(
    stack_dir: &Path,
    host: &FleetHost,
) -> Vec<FleetVmManagedSystemDnsReadback> {
    let dir = stack_dir.join("managed");
    let entries = match fs::read_dir(&dir) {
        Ok(v) => v,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => return vec![failure("MANAGED_SYSTEM_DNS_DIRECTORY_UNAVAILABLE")],
    };
    if super::checked_managed_directory(stack_dir, false).is_err() {
        return vec![failure("MANAGED_SYSTEM_DNS_DIRECTORY_UNTRUSTED")];
    }
    let mut names = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return vec![failure("MANAGED_SYSTEM_DNS_ENTRY_INVALID")];
        };
        let Ok(name) = entry.file_name().into_string() else {
            return vec![failure("MANAGED_SYSTEM_DNS_NAME_INVALID")];
        };
        if is_managed_dns_manifest(&format!("managed/{name}")) {
            names.push(name);
            if names.len() > 32 {
                return vec![failure("MANAGED_SYSTEM_DNS_COUNT_OVERSIZE")];
            }
        }
    }
    names.sort();
    let mut rows = Vec::new();
    for name in names {
        let Ok(Some(bytes)) = super::checked_managed_existing_file(&dir.join(&name), 0) else {
            rows.push(failure("MANAGED_SYSTEM_DNS_MANIFEST_UNREADABLE"));
            continue;
        };
        let spec = match decode_scope(host, &format!("managed/{name}"), &bytes) {
            Ok(v) => v,
            Err(code) => {
                rows.push(failure(&code));
                continue;
            }
        };
        let mut row = failure("MANAGED_SYSTEM_DNS_STATE_UNPROVEN");
        row.resource_name = spec.resource_name.clone();
        row.manifest_sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .to_vec();
        match owned_bridge(&spec).await {
            Ok((index, _)) => match inspect(&spec, index).await {
                Ok(actual) if actual == expected_state(Some(&spec)) => {
                    row.present = true;
                    row.converged = true;
                    row.reason_code = "DESIRED_PRESENT".into();
                }
                Ok(actual) => {
                    row.present = !actual.nameservers.is_empty() || !actual.domains.is_empty();
                    row.reason_code = "MANAGED_SYSTEM_DNS_DRIFT".into();
                }
                Err(code) => row.reason_code = code,
            },
            Err(code) => row.reason_code = code,
        }
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (FleetHost, FleetVmManagedSystemDns) {
        let host = FleetHost {
            machine_id: "vmtest".into(),
            kind: FleetHostKind::Vm as i32,
            ..Default::default()
        };
        let spec = FleetVmManagedSystemDns {
            schema_version: 1,
            machine_id: "vmtest".into(),
            resource_name: "sb-vmtest-lab".into(),
            interface_name: "sblab0".into(),
            routing_domain: "~lab.singbox.internal".into(),
            name_servers: vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()],
        };
        (host, spec)
    }

    #[test]
    fn scoped_dns_rejects_foreign_host_global_catchall_and_noncanonical() {
        let (host, mut spec) = fixture();
        assert!(decode_scope(&host, "managed/host-dns-lab.pb", &spec.encode_to_vec()).is_ok());
        for domain in [
            "~.",
            "~github.com",
            "~cloudflare.com",
            "~internal",
            "lab.singbox.internal",
        ] {
            spec.routing_domain = domain.into();
            assert!(decode_scope(&host, "managed/host-dns-lab.pb", &spec.encode_to_vec()).is_err());
        }
        let (_, mut spec) = fixture();
        spec.name_servers = vec!["127.0.0.1".into()];
        assert!(decode_scope(&host, "managed/host-dns-lab.pb", &spec.encode_to_vec()).is_err());
        let (_, mut spec) = fixture();
        spec.name_servers.reverse();
        assert!(decode_scope(&host, "managed/host-dns-lab.pb", &spec.encode_to_vec()).is_err());
        let (_, mut spec) = fixture();
        spec.machine_id = "foreign".into();
        assert!(decode_scope(&host, "managed/host-dns-lab.pb", &spec.encode_to_vec()).is_err());
    }

    #[test]
    fn malformed_resolvectl_link_output_is_never_accepted() {
        assert_eq!(
            parse_link_values("Link 17 (sblab0): 1.1.1.1\n", 17, "sblab0").unwrap(),
            vec!["1.1.1.1"]
        );
        assert!(parse_link_values("Global: 1.1.1.1\n", 17, "sblab0").is_err());
        assert!(parse_link_values("Link 18 (sblab0):\n", 17, "sblab0").is_err());
        assert!(parse_link_values("Link 17 (sblab0): 1.1.1.1\nBAD", 17, "sblab0").is_err());
    }

    #[test]
    fn expected_readback_is_exact_and_removal_clears_only_our_lists() {
        let (_, spec) = fixture();
        assert_eq!(
            expected_state(None),
            LinkDnsState {
                nameservers: vec![],
                domains: vec![]
            }
        );
        assert_eq!(
            expected_state(Some(&spec)).domains,
            vec!["~lab.singbox.internal"]
        );
        assert_eq!(expected_state(Some(&spec)).nameservers, spec.name_servers);
    }
}
