use edge_shared_types::{
    RuntimeDnsDiagnostics, RuntimeNetworkDiagnostics, RuntimeNetworkInterface, RuntimeNetworkRoute,
    RuntimeNetworkRule, RuntimeProbeStatus, RuntimeRouteEvent, RuntimeSocketEndpoint,
};
use serde_json::Value;

use crate::runtime_probe::{BoundedCommandProbe, bounded_command_probe};

const MAX_INTERFACES: usize = 64;
const MAX_ADDRESSES_PER_INTERFACE: usize = 16;
const MAX_ROUTES: usize = 128;
const MAX_RULES: usize = 64;
const MAX_SOCKETS: usize = 96;
const MAX_ROUTE_EVENTS: usize = 16;

pub(crate) fn collect_host_network_diagnostics() -> RuntimeNetworkDiagnostics {
    collect_network_diagnostics(None, None)
}

pub(crate) fn collect_container_network_diagnostics(
    container_name: &str,
) -> RuntimeNetworkDiagnostics {
    let mut pid_probe = bounded_command_probe(
        "docker",
        &["inspect", "--format", "{{.State.Pid}}", container_name],
        6,
        true,
    );
    let Some(pid) = parse_container_pid(&mut pid_probe) else {
        return unavailable_network_diagnostics(&pid_probe);
    };
    collect_network_diagnostics(Some(pid), Some(container_name))
}

pub(crate) fn extract_route_events(events: &[String]) -> Vec<RuntimeRouteEvent> {
    let mut parsed = events
        .iter()
        .filter_map(|line| parse_route_event(line))
        .collect::<Vec<_>>();
    if parsed.len() > MAX_ROUTE_EVENTS {
        parsed.drain(..parsed.len() - MAX_ROUTE_EVENTS);
    }
    parsed
}

fn collect_network_diagnostics(
    namespace_pid: Option<u32>,
    container_name: Option<&str>,
) -> RuntimeNetworkDiagnostics {
    let mut interfaces_probe =
        fixed_probe(namespace_pid, &["ip", "-j", "address", "show"], 6, true);
    let interfaces = parse_interfaces(&mut interfaces_probe);

    let mut routes_probe = fixed_probe(
        namespace_pid,
        &["ip", "-j", "route", "show", "table", "all"],
        6,
        true,
    );
    let routes = parse_routes(&mut routes_probe);
    let default_route_present_observed = default_route_observation(&routes_probe, &routes);
    let default_route_present = default_route_present_observed.unwrap_or(false);

    let mut rules_probe =
        fixed_probe(namespace_pid, &["ip", "-j", "rule", "show"], 6, true);
    let rules = parse_rules(&mut rules_probe);

    let dns_probe = fixed_dns_probe(container_name);
    let dns = parse_dns(dns_probe);

    let mut sockets_probe = fixed_probe(
        namespace_pid,
        &["ss", "-H", "-n", "-t", "-u", "-a"],
        6,
        false,
    );
    let sockets = parse_sockets(&mut sockets_probe);

    RuntimeNetworkDiagnostics {
        interfaces_probe: Some(interfaces_probe.evidence()),
        interfaces,
        routes_probe: Some(routes_probe.evidence()),
        routes,
        rules_probe: Some(rules_probe.evidence()),
        rules,
        dns: Some(dns),
        sockets_probe: Some(sockets_probe.evidence()),
        sockets,
        default_route_present,
        default_route_present_observed,
    }
}

fn fixed_probe(
    namespace_pid: Option<u32>,
    command: &[&str],
    timeout_seconds: u64,
    require_output: bool,
) -> BoundedCommandProbe {
    let Some(pid) = namespace_pid else {
        return bounded_command_probe(command[0], &command[1..], timeout_seconds, require_output);
    };
    let (program, args) = container_namespace_command(pid, command);
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    bounded_command_probe(&program, &arg_refs, timeout_seconds, require_output)
}

fn container_namespace_command(pid: u32, command: &[&str]) -> (String, Vec<String>) {
    let mut args = vec![
        "-t".to_owned(),
        pid.to_string(),
        "-n".to_owned(),
        "--".to_owned(),
    ];
    args.extend(command.iter().map(|value| (*value).to_owned()));
    ("nsenter".to_owned(), args)
}

fn fixed_dns_probe(container_name: Option<&str>) -> BoundedCommandProbe {
    let Some(container_name) = container_name else {
        return bounded_command_probe("cat", &["/etc/resolv.conf"], 6, true);
    };

    let path_probe = bounded_command_probe(
        "docker",
        &[
            "inspect",
            "--format",
            "{{.ResolvConfPath}}",
            container_name,
        ],
        6,
        true,
    );
    if path_probe.status != RuntimeProbeStatus::Ok {
        return path_probe;
    }
    let resolv_conf_path = path_probe.stdout.trim().to_owned();
    if resolv_conf_path.is_empty() {
        let mut empty = path_probe;
        empty.status = RuntimeProbeStatus::Empty;
        return empty;
    }
    bounded_command_probe("cat", &[resolv_conf_path.as_str()], 6, true)
}

fn parse_container_pid(probe: &mut BoundedCommandProbe) -> Option<u32> {
    if probe.status != RuntimeProbeStatus::Ok {
        return None;
    }
    match probe.stdout.trim().parse::<u32>().ok().filter(|pid| *pid > 0) {
        Some(pid) => Some(pid),
        None => {
            probe.status = RuntimeProbeStatus::ParseError;
            None
        }
    }
}

fn unavailable_network_diagnostics(probe: &BoundedCommandProbe) -> RuntimeNetworkDiagnostics {
    RuntimeNetworkDiagnostics {
        interfaces_probe: Some(probe.evidence()),
        interfaces: Vec::new(),
        routes_probe: Some(probe.evidence()),
        routes: Vec::new(),
        rules_probe: Some(probe.evidence()),
        rules: Vec::new(),
        dns: Some(RuntimeDnsDiagnostics {
            probe: Some(probe.evidence()),
            nameservers: Vec::new(),
            search_domains: Vec::new(),
        }),
        sockets_probe: Some(probe.evidence()),
        sockets: Vec::new(),
        default_route_present: false,
        default_route_present_observed: None,
    }
}

fn default_route_observation(
    probe: &BoundedCommandProbe,
    routes: &[RuntimeNetworkRoute],
) -> Option<bool> {
    if probe.status == RuntimeProbeStatus::Ok {
        Some(routes.iter().any(|route| route.destination == "default"))
    } else {
        None
    }
}

fn parse_interfaces(probe: &mut BoundedCommandProbe) -> Vec<RuntimeNetworkInterface> {
    if probe.status != RuntimeProbeStatus::Ok {
        return Vec::new();
    }
    let value: Value = match serde_json::from_str(&probe.stdout) {
        Ok(value) => value,
        Err(_) => {
            probe.status = RuntimeProbeStatus::ParseError;
            return Vec::new();
        }
    };
    let Some(items) = value.as_array() else {
        probe.status = RuntimeProbeStatus::ParseError;
        return Vec::new();
    };

    let mut result = items
        .iter()
        .filter_map(|item| {
            let name = bounded_json_string(item.get("ifname")?, 128)?;
            let mtu = item
                .get("mtu")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());
            let up = item
                .get("flags")
                .and_then(Value::as_array)
                .is_some_and(|flags| {
                    flags
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|flag| flag == "UP")
                });
            let mut addresses = item
                .get("addr_info")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|address| {
                    let family = bounded_json_string(address.get("family")?, 16)?;
                    let local = bounded_json_string(address.get("local")?, 128)?;
                    let prefix = address.get("prefixlen")?.as_u64()?;
                    Some(format!("{family}:{local}/{prefix}"))
                })
                .take(MAX_ADDRESSES_PER_INTERFACE)
                .collect::<Vec<_>>();
            addresses.sort();
            addresses.dedup();
            Some(RuntimeNetworkInterface {
                name,
                mtu,
                up,
                addresses,
            })
        })
        .take(MAX_INTERFACES)
        .collect::<Vec<_>>();
    result.sort_by(|left, right| left.name.cmp(&right.name));
    result
}

fn parse_routes(probe: &mut BoundedCommandProbe) -> Vec<RuntimeNetworkRoute> {
    if probe.status != RuntimeProbeStatus::Ok {
        return Vec::new();
    }
    let value: Value = match serde_json::from_str(&probe.stdout) {
        Ok(value) => value,
        Err(_) => {
            probe.status = RuntimeProbeStatus::ParseError;
            return Vec::new();
        }
    };
    let Some(items) = value.as_array() else {
        probe.status = RuntimeProbeStatus::ParseError;
        return Vec::new();
    };

    let mut result = items
        .iter()
        .filter_map(|item| {
            let destination = item
                .get("dst")
                .and_then(Value::as_str)
                .map(|value| value.to_owned())
                .unwrap_or_else(|| "default".to_owned());
            if destination.len() > 160 {
                return None;
            }
            Some(RuntimeNetworkRoute {
                destination,
                gateway: bounded_optional_json_string(item.get("gateway"), 128),
                device: bounded_optional_json_string(item.get("dev"), 128),
                preferred_source: bounded_optional_json_string(item.get("prefsrc"), 128),
                metric: item
                    .get("metric")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
                table: json_scalar_string(item.get("table"), 64),
                protocol: bounded_optional_json_string(item.get("protocol"), 64),
            })
        })
        .take(MAX_ROUTES)
        .collect::<Vec<_>>();
    result.sort_by(|left, right| {
        (
            &left.destination,
            &left.device,
            &left.gateway,
            &left.preferred_source,
            left.metric,
            &left.table,
            &left.protocol,
        )
            .cmp(&(
                &right.destination,
                &right.device,
                &right.gateway,
                &right.preferred_source,
                right.metric,
                &right.table,
                &right.protocol,
            ))
    });
    result
}

fn parse_rules(probe: &mut BoundedCommandProbe) -> Vec<RuntimeNetworkRule> {
    if probe.status != RuntimeProbeStatus::Ok {
        return Vec::new();
    }
    let value: Value = match serde_json::from_str(&probe.stdout) {
        Ok(value) => value,
        Err(_) => {
            probe.status = RuntimeProbeStatus::ParseError;
            return Vec::new();
        }
    };
    let Some(items) = value.as_array() else {
        probe.status = RuntimeProbeStatus::ParseError;
        return Vec::new();
    };

    let mut result = items
        .iter()
        .map(|item| RuntimeNetworkRule {
            priority: item
                .get("priority")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            source: bounded_optional_json_string(item.get("from"), 160),
            destination: bounded_optional_json_string(item.get("to"), 160),
            table: json_scalar_string(item.get("table"), 64),
        })
        .take(MAX_RULES)
        .collect::<Vec<_>>();
    result.sort_by(|left, right| {
        (left.priority, &left.source, &left.destination, &left.table).cmp(&(
            right.priority,
            &right.source,
            &right.destination,
            &right.table,
        ))
    });
    result
}

fn parse_dns(probe: BoundedCommandProbe) -> RuntimeDnsDiagnostics {
    let mut nameservers = Vec::new();
    let mut search_domains = Vec::new();

    if probe.status == RuntimeProbeStatus::Ok {
        for line in probe.stdout.lines() {
            let clean = line.split('#').next().unwrap_or_default().trim();
            if clean.is_empty() {
                continue;
            }
            let mut parts = clean.split_whitespace();
            match parts.next() {
                Some("nameserver") => {
                    if let Some(value) = parts.next()
                        && value.len() <= 128
                    {
                        nameservers.push(value.to_owned());
                    }
                }
                Some("search") => {
                    for value in parts {
                        if value.len() <= 128 {
                            search_domains.push(value.to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    nameservers.sort();
    nameservers.dedup();
    nameservers.truncate(16);
    search_domains.sort();
    search_domains.dedup();
    search_domains.truncate(16);

    RuntimeDnsDiagnostics {
        probe: Some(probe.evidence()),
        nameservers,
        search_domains,
    }
}

fn parse_sockets(probe: &mut BoundedCommandProbe) -> Vec<RuntimeSocketEndpoint> {
    if probe.status != RuntimeProbeStatus::Ok {
        return Vec::new();
    }

    let mut result = probe
        .stdout
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 6 {
                return None;
            }
            let protocol = fields[0].to_ascii_lowercase();
            if protocol != "tcp" && protocol != "udp" {
                return None;
            }
            let state = fields[1];
            let (local_address, local_port) = split_endpoint(fields[4]);
            let (remote_address, remote_port) = split_endpoint(fields[5]);
            Some(RuntimeSocketEndpoint {
                protocol,
                local_address,
                local_port,
                remote_address: if remote_address.is_empty() {
                    None
                } else {
                    Some(remote_address)
                },
                remote_port,
                state: if state.is_empty() {
                    None
                } else {
                    Some(state.chars().take(32).collect())
                },
            })
        })
        .take(MAX_SOCKETS)
        .collect::<Vec<_>>();

    if !probe.stdout.trim().is_empty() && result.is_empty() {
        probe.status = RuntimeProbeStatus::ParseError;
        return Vec::new();
    }

    result.sort_by(|left, right| {
        (
            &left.protocol,
            &left.local_address,
            left.local_port,
            &left.remote_address,
            left.remote_port,
            &left.state,
        )
            .cmp(&(
                &right.protocol,
                &right.local_address,
                right.local_port,
                &right.remote_address,
                right.remote_port,
                &right.state,
            ))
    });
    result.dedup_by(|left, right| {
        left.protocol == right.protocol
            && left.local_address == right.local_address
            && left.local_port == right.local_port
            && left.remote_address == right.remote_address
            && left.remote_port == right.remote_port
            && left.state == right.state
    });
    result
}

fn split_endpoint(value: &str) -> (String, Option<u32>) {
    let bounded = value.chars().take(192).collect::<String>();
    if let Some(stripped) = bounded.strip_prefix('[')
        && let Some((address, port)) = stripped.rsplit_once("]:")
    {
        return (address.to_owned(), parse_port(port));
    }
    if let Some((address, port)) = bounded.rsplit_once(':')
        && !address.contains(':')
    {
        return (address.to_owned(), parse_port(port));
    }
    (bounded, None)
}

fn parse_port(value: &str) -> Option<u32> {
    if value == "*" {
        None
    } else {
        value.parse::<u32>().ok().filter(|port| *port <= 65535)
    }
}

fn parse_route_event(line: &str) -> Option<RuntimeRouteEvent> {
    let marker = "Routes changed:";
    let start = line.find(marker)? + marker.len();
    let rest = line[start..].trim();
    let (count_text, tail) = rest.split_once(' ')?;
    let changed_count = count_text.parse::<u32>().ok()?;
    let window = tail
        .strip_prefix("in the ")
        .unwrap_or(tail)
        .trim()
        .chars()
        .take(64)
        .collect::<String>();
    if window.is_empty() {
        return None;
    }
    Some(RuntimeRouteEvent {
        changed_count,
        window,
        aggregate_counter_only: true,
    })
}

fn bounded_json_string(value: &Value, max_len: usize) -> Option<String> {
    let value = value.as_str()?;
    if value.is_empty() || value.len() > max_len {
        None
    } else {
        Some(value.to_owned())
    }
}

fn bounded_optional_json_string(value: Option<&Value>, max_len: usize) -> Option<String> {
    value.and_then(|value| bounded_json_string(value, max_len))
}

fn json_scalar_string(value: Option<&Value>, max_len: usize) -> Option<String> {
    let value = value?;
    let text = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => return None,
    };
    if text.is_empty() || text.len() > max_len {
        None
    } else {
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_probe(stdout: &str) -> BoundedCommandProbe {
        BoundedCommandProbe {
            status: RuntimeProbeStatus::Ok,
            exit_code: Some(0),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    #[test]
    fn parses_and_normalizes_interfaces_routes_and_rules() {
        let mut interfaces = ok_probe(
            r#"[{"ifname":"eth0","mtu":1500,"flags":["BROADCAST","UP"],"addr_info":[{"family":"inet","local":"10.27.96.3","prefixlen":20},{"family":"inet6","local":"fe80::1","prefixlen":64}]}]"#,
        );
        let parsed_interfaces = parse_interfaces(&mut interfaces);
        assert_eq!(parsed_interfaces.len(), 1);
        assert_eq!(parsed_interfaces[0].name, "eth0");
        assert_eq!(parsed_interfaces[0].mtu, Some(1500));
        assert!(parsed_interfaces[0].up);
        assert_eq!(
            parsed_interfaces[0].addresses,
            vec!["inet6:fe80::1/64", "inet:10.27.96.3/20"]
        );

        let mut routes = ok_probe(
            r#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp"},{"dst":"10.27.96.0/20","dev":"eth1","prefsrc":"10.27.96.3","protocol":"kernel","table":254}]"#,
        );
        let parsed_routes = parse_routes(&mut routes);
        assert_eq!(parsed_routes.len(), 2);
        assert!(
            parsed_routes
                .iter()
                .any(|route| route.destination == "default")
        );
        assert!(parsed_routes.iter().any(|route| {
            route.destination == "10.27.96.0/20"
                && route.preferred_source.as_deref() == Some("10.27.96.3")
        }));

        let mut rules = ok_probe(
            r#"[{"priority":0,"from":"all","table":"local"},{"priority":32766,"from":"all","table":"main"}]"#,
        );
        let parsed_rules = parse_rules(&mut rules);
        assert_eq!(parsed_rules.len(), 2);
        assert_eq!(parsed_rules[0].priority, Some(0));
    }

    #[test]
    fn parses_dns_and_socket_endpoints_without_process_metadata() {
        let dns = parse_dns(ok_probe(
            "nameserver 1.1.1.1\nsearch example.internal corp.internal\noptions edns0\n",
        ));
        assert_eq!(dns.nameservers, vec!["1.1.1.1"]);
        assert_eq!(
            dns.search_domains,
            vec!["corp.internal", "example.internal"]
        );

        let mut sockets = ok_probe(
            "tcp ESTAB 0 0 10.0.0.2:443 203.0.113.10:51234\nudp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n",
        );
        let parsed = parse_sockets(&mut sockets);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().any(|socket| {
            socket.protocol == "tcp"
                && socket.local_port == Some(443)
                && socket.remote_port == Some(51234)
        }));
    }

    #[test]
    fn route_churn_log_becomes_bounded_typed_event() {
        let events = vec![
            "DEBUG actor: Routes changed: 5 in the last 30 seconds".to_owned(),
            "unrelated".to_owned(),
        ];
        let parsed = extract_route_events(&events);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].changed_count, 5);
        assert_eq!(parsed[0].window, "last 30 seconds");
        assert!(parsed[0].aggregate_counter_only);
    }

    #[test]
    fn container_network_probe_uses_host_namespace_tools() {
        let (program, args) =
            container_namespace_command(4242, &["ip", "-j", "route", "show", "table", "all"]);
        assert_eq!(program, "nsenter");
        assert_eq!(
            args,
            vec![
                "-t", "4242", "-n", "--", "ip", "-j", "route", "show", "table", "all"
            ]
        );
        assert!(!args.iter().any(|arg| arg == "docker" || arg == "exec"));
    }

    #[test]
    fn failed_route_observation_keeps_default_route_unknown() {
        let probe = BoundedCommandProbe {
            status: RuntimeProbeStatus::CommandNotFound,
            exit_code: Some(127),
            stdout: String::new(),
            stderr: "ip: command not found".to_owned(),
        };
        assert_eq!(default_route_observation(&probe, &[]), None);
    }

    #[test]
    fn invalid_json_is_classified_as_parse_error() {
        let mut probe = ok_probe("not-json");
        assert!(parse_routes(&mut probe).is_empty());
        assert_eq!(probe.status, RuntimeProbeStatus::ParseError);
    }

    #[test]
    fn network_evidence_is_bounded() {
        let many = (0..200)
            .map(|index| {
                format!(
                    r#"{{"dst":"10.{}.0.0/16","dev":"eth0","protocol":"static"}}"#,
                    index
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut probe = ok_probe(&format!("[{many}]"));
        assert_eq!(parse_routes(&mut probe).len(), MAX_ROUTES);
    }
}
