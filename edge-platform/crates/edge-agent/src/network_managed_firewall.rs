//! One Git-owned nftables inet input table. No shell, generic runner argv,
//! dynamic rule evaluation, default DROP, firewall daemon or blind rollback.
//! The existing Worker-signed native journal contains BEGIN before ONE nft
//! netlink batch. Unknown acknowledgement keeps UNKNOWN_NO_REPLAY.
use super::*;
use edge_shared_types::{
    FleetHost, FleetHostKind, FleetVmFirewallTransport, FleetVmManagedFirewall,
    FleetVmManagedFirewallReadback,
};
use prost::Message;
use serde_json::Value;
use std::io::Write;
use std::process::{Command as OsCommand, Stdio};

const RULES_MAX: usize = 16;

#[derive(Debug)]
pub(super) struct PreparedManagedFirewall {
    before: Option<FleetVmManagedFirewall>,
    after: Option<FleetVmManagedFirewall>,
    before_rules: Option<Vec<(i32, u16)>>,
    script: String,
}

pub(super) fn is_managed_firewall_manifest(path: &str) -> bool {
    path.starts_with("managed/host-firewall-") && path.ends_with(".pb")
}

fn table_name(spec: &FleetVmManagedFirewall) -> &str {
    // The Git suffix is restricted to [a-z0-9]+ in decode_scope.
    spec.resource_name
        .rsplit_once('-')
        .map(|(_, suffix)| suffix)
        .unwrap_or("")
}

fn canonical_rules(spec: &FleetVmManagedFirewall) -> Option<Vec<(i32, u16)>> {
    if spec.denied_ingress.is_empty() || spec.denied_ingress.len() > RULES_MAX {
        return None;
    }
    let mut ordered = Vec::with_capacity(spec.denied_ingress.len());
    for rule in &spec.denied_ingress {
        if !matches!(
            FleetVmFirewallTransport::try_from(rule.transport),
            Ok(FleetVmFirewallTransport::Tcp | FleetVmFirewallTransport::Udp)
        ) || !(1025..=65535).contains(&rule.destination_port)
        {
            return None;
        }
        ordered.push((rule.transport, rule.destination_port as u16));
    }
    if ordered.windows(2).any(|pair| pair[0] >= pair[1]) {
        return None;
    }
    Some(ordered)
}

fn decode_scope(host: &FleetHost, path: &str, raw: &[u8]) -> Result<FleetVmManagedFirewall, String> {
    let suffix = path
        .strip_prefix("managed/host-firewall-")
        .and_then(|rest| rest.strip_suffix(".pb"))
        .ok_or("HOST_VM_FIREWALL_MANIFEST_PATH_INVALID")?;
    if suffix.is_empty()
        || suffix.len() > 24
        || !suffix.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err("HOST_VM_FIREWALL_TABLE_NAME_INVALID".into());
    }
    if raw.is_empty() || raw.len() > 2048 {
        return Err("HOST_VM_FIREWALL_MANIFEST_SIZE_INVALID".into());
    }
    let spec = FleetVmManagedFirewall::decode(raw)
        .map_err(|_| "HOST_VM_FIREWALL_MANIFEST_DECODE_INVALID")?;
    if host.machine_id.is_empty()
        || host.machine_id.len() > 64
        || !host.machine_id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
        })
        || spec.encode_to_vec() != raw
        || spec.schema_version != 1
        || host.kind != FleetHostKind::Vm as i32
        || spec.machine_id != host.machine_id
        || spec.resource_name != format!("sb-{}-{suffix}", host.machine_id)
        || spec.resource_name.len() > 112
        || canonical_rules(&spec).is_none()
    {
        return Err("HOST_VM_FIREWALL_MANIFEST_SCOPE_INVALID".into());
    }
    Ok(spec)
}

fn table_id(spec: &FleetVmManagedFirewall) -> String {
    format!("sb_{}", table_name(spec))
}

fn chain_comment(spec: &FleetVmManagedFirewall) -> String {
    format!("sing-box:{}:{}", spec.machine_id, spec.resource_name)
}

fn render_batch(
    before: Option<&FleetVmManagedFirewall>,
    after: Option<&FleetVmManagedFirewall>,
) -> String {
    let spec = after.or(before).expect("nonempty firewall transition");
    let table = table_id(spec);
    let mut batch = String::new();
    match (before, after) {
        (None, Some(_)) => {
            batch.push_str(&format!("add table inet {table}\n"));
            batch.push_str(&format!(
                "add chain inet {table} ingress {{ type filter hook input priority 10; policy accept; comment \"{}\"; }}\n",
                chain_comment(spec),
            ));
        }
        (Some(_), Some(_)) => {
            batch.push_str(&format!("flush chain inet {table} ingress\n"));
        }
        (Some(_), None) => {
            batch.push_str(&format!("delete table inet {table}\n"));
            return batch;
        }
        (None, None) => unreachable!(),
    }
    for (protocol, port) in canonical_rules(after.expect("present rules")).unwrap() {
        let label = if protocol == FleetVmFirewallTransport::Tcp as i32 {
            "tcp"
        } else {
            "udp"
        };
        batch.push_str(&format!("add rule inet {table} ingress {label} dport {port} drop\n"));
    }
    batch
}

async fn nft(args: Vec<String>, stdin: Option<String>) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let mut command = OsCommand::new("/usr/bin/timeout");
        command.args(["--kill-after=2s", "8s", "/usr/sbin/nft"]);
        command.args(args);
        command.stderr(Stdio::null()).stdout(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|_| "HOST_VM_FIREWALL_EXEC_START_FAILED".to_owned())?;
        if let Some(payload) = stdin {
            child
                .stdin
                .take()
                .ok_or("HOST_VM_FIREWALL_EXEC_STDIN_MISSING")?
                .write_all(payload.as_bytes())
                .map_err(|_| "HOST_VM_FIREWALL_EXEC_STDIN_UNCERTAIN_NO_REPLAY")?;
        }
        let output = child
            .wait_with_output()
            .map_err(|_| "HOST_VM_FIREWALL_EXEC_ACK_UNCERTAIN_NO_REPLAY")?;
        if !output.status.success() {
            return Err("HOST_VM_FIREWALL_EXEC_FAILED_OR_TIMEOUT_NO_REPLAY".into());
        }
        if output.stdout.len() > 65536 {
            return Err("HOST_VM_FIREWALL_OUTPUT_OVERSIZE".into());
        }
        String::from_utf8(output.stdout)
            .map_err(|_| "HOST_VM_FIREWALL_OUTPUT_UTF8_INVALID".into())
    })
    .await
    .map_err(|_| "HOST_VM_FIREWALL_EXEC_TASK_UNCERTAIN_NO_REPLAY")?
}

fn decode_ruleset(
    spec: &FleetVmManagedFirewall,
    root: &Value,
) -> Result<Vec<(i32, u16)>, String> {
    let objects = root["nftables"]
        .as_array()
        .ok_or("HOST_VM_FIREWALL_JSON_SHAPE_INVALID")?;
    let mut found_table = false;
    let mut found_chain = false;
    let mut rules = Vec::new();
    for object in objects {
        if object.get("metainfo").is_some() {
            continue;
        }
        if let Some(table) = object.get("table") {
            if found_table
                || table["family"].as_str() != Some("inet")
                || table["name"].as_str() != Some(table_id(spec).as_str())
            {
                return Err("HOST_VM_FIREWALL_TABLE_FOREIGN".into());
            }
            found_table = true;
        } else if let Some(chain) = object.get("chain") {
            if found_chain
                || chain["family"].as_str() != Some("inet")
                || chain["table"].as_str() != Some(table_id(spec).as_str())
                || chain["name"].as_str() != Some("ingress")
                || chain["type"].as_str() != Some("filter")
                || chain["hook"].as_str() != Some("input")
                || chain["prio"].as_i64() != Some(10)
                || chain["policy"].as_str() != Some("accept")
                || chain["comment"].as_str() != Some(chain_comment(spec).as_str())
            {
                return Err("HOST_VM_FIREWALL_CHAIN_FOREIGN".into());
            }
            found_chain = true;
        } else if let Some(rule) = object.get("rule") {
            if rule["family"].as_str() != Some("inet")
                || rule["table"].as_str() != Some(table_id(spec).as_str())
                || rule["chain"].as_str() != Some("ingress")
            {
                return Err("HOST_VM_FIREWALL_RULE_FOREIGN".into());
            }
            let expressions = rule["expr"].as_array()
                .ok_or("HOST_VM_FIREWALL_RULE_EXPRESSION_UNPROVEN")?;
            if expressions.len() != 2
                || expressions[1].get("drop").is_none()
                || expressions[0]["match"]["op"].as_str() != Some("==")
                || expressions[0]["match"]["left"]["payload"]["field"].as_str() != Some("dport")
            {
                return Err("HOST_VM_FIREWALL_RULE_EXPRESSION_FOREIGN".into());
            }
            let protocol = match expressions[0]["match"]["left"]["payload"]["protocol"].as_str() {
                Some("tcp") => FleetVmFirewallTransport::Tcp as i32,
                Some("udp") => FleetVmFirewallTransport::Udp as i32,
                _ => return Err("HOST_VM_FIREWALL_RULE_PROTOCOL_INVALID".into()),
            };
            let port = expressions[0]["match"]["right"].as_u64()
                .and_then(|number| u16::try_from(number).ok())
                .ok_or("HOST_VM_FIREWALL_RULE_PORT_INVALID")?;
            rules.push((protocol, port));
        } else {
            return Err("HOST_VM_FIREWALL_TABLE_OBJECT_FOREIGN".into());
        }
    }
    if !found_table || !found_chain || rules.len() > RULES_MAX {
        return Err("HOST_VM_FIREWALL_TABLE_SHAPE_UNPROVEN".into());
    }
    Ok(rules)
}

async fn inspect(spec: &FleetVmManagedFirewall) -> Result<Option<Vec<(i32, u16)>>, String> {
    let all = nft(vec!["-j".into(), "list".into(), "tables".into()], None).await?;
    let parsed: Value = serde_json::from_str(&all)
        .map_err(|_| "HOST_VM_FIREWALL_TABLES_JSON_INVALID")?;
    let records = parsed["nftables"]
        .as_array()
        .ok_or("HOST_VM_FIREWALL_TABLES_SHAPE_INVALID")?;
    let mut present = false;
    for record in records {
        if let Some(table) = record.get("table") {
            if table["family"].as_str() == Some("inet")
                && table["name"].as_str() == Some(table_id(spec).as_str())
            {
                if present {
                    return Err("HOST_VM_FIREWALL_TABLE_DUPLICATE".into());
                }
                present = true;
            }
        } else if record.get("metainfo").is_none() {
            return Err("HOST_VM_FIREWALL_TABLES_SHAPE_FOREIGN".into());
        }
    }
    if !present {
        return Ok(None);
    }
    let exact = nft(
        vec!["-j".into(), "list".into(), "table".into(), "inet".into(), table_id(spec)],
        None,
    ).await?;
    let parsed: Value = serde_json::from_str(&exact)
        .map_err(|_| "HOST_VM_FIREWALL_INSPECT_JSON_INVALID")?;
    Ok(Some(decode_ruleset(spec, &parsed)?))
}

pub(super) async fn preflight_managed_firewall(
    host: &FleetHost,
    path: &str,
    before: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<PreparedManagedFirewall, String> {
    let prior = before.map(|bytes| decode_scope(host, path, bytes)).transpose()?;
    let next = after.map(|bytes| decode_scope(host, path, bytes)).transpose()?;
    let spec = next.as_ref().or(prior.as_ref())
        .ok_or("HOST_VM_FIREWALL_TRANSITION_EMPTY")?;
    if let (Some(prior), Some(next)) = (&prior, &next) {
        if prior.machine_id != next.machine_id
            || prior.resource_name != next.resource_name
            || prior.denied_ingress == next.denied_ingress
        {
            return Err("HOST_VM_FIREWALL_NO_EFFECT_OR_IDENTITY_CHANGE".into());
        }
    }
    let current = inspect(spec).await?;
    if let Some(old) = &prior {
        if current.as_ref() != canonical_rules(old).as_ref() {
            return Err("HOST_VM_FIREWALL_PRESTATE_DRIFT".into());
        }
    } else if current.is_some() {
        return Err("HOST_VM_FIREWALL_FOREIGN_TABLE_EXISTS".into());
    }
    let script = render_batch(prior.as_ref(), next.as_ref());
    nft(vec!["-c".into(), "-f".into(), "-".into()], Some(script.clone()))
        .await
        .map_err(|_| "HOST_VM_FIREWALL_PREFLIGHT_SYNTAX_OR_RUNTIME_BLOCKED")?;
    Ok(PreparedManagedFirewall {
        before: prior,
        after: next,
        before_rules: current,
        script,
    })
}

pub(super) async fn apply_managed_firewall_once(plan: &PreparedManagedFirewall) -> Result<(), String> {
    let spec = plan.after.as_ref().or(plan.before.as_ref())
        .ok_or("HOST_VM_FIREWALL_PLAN_EMPTY")?;
    if inspect(spec).await? != plan.before_rules {
        return Err("HOST_VM_FIREWALL_CAS_CHANGED_NO_REPLAY".into());
    }
    nft(vec!["-f".into(), "-".into()], Some(plan.script.clone()))
        .await
        .map_err(|_| "HOST_VM_FIREWALL_EFFECT_UNKNOWN_NO_REPLAY")?;
    let expected = plan.after.as_ref().and_then(canonical_rules);
    if inspect(spec).await
        .map_err(|_| "HOST_VM_FIREWALL_POSTSTATE_UNKNOWN_NO_REPLAY")? != expected
    {
        return Err("HOST_VM_FIREWALL_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    Ok(())
}

fn readback_failure(code: &str) -> FleetVmManagedFirewallReadback {
    FleetVmManagedFirewallReadback {
        reason_code: code.into(),
        ..Default::default()
    }
}

pub(crate) async fn collect_native_managed_firewall(
    stack_dir: &Path,
    host: &FleetHost,
) -> Vec<FleetVmManagedFirewallReadback> {
    let dir = stack_dir.join("managed");
    let entries = match fs::read_dir(&dir) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => return vec![readback_failure("MANAGED_FIREWALL_DIRECTORY_UNAVAILABLE")],
    };
    if super::checked_managed_directory(stack_dir, false).is_err() {
        return vec![readback_failure("MANAGED_FIREWALL_DIRECTORY_UNTRUSTED")];
    }
    let mut names = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return vec![readback_failure("MANAGED_FIREWALL_DIRECTORY_ENTRY_INVALID")];
        };
        let Ok(name) = entry.file_name().into_string() else {
            return vec![readback_failure("MANAGED_FIREWALL_FILENAME_INVALID")];
        };
        if is_managed_firewall_manifest(&format!("managed/{name}")) {
            names.push(name);
            if names.len() > 32 {
                return vec![readback_failure("MANAGED_FIREWALL_MANIFESTS_OVERSIZE")];
            }
        }
    }
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let mut row = readback_failure("MANAGED_FIREWALL_MANIFEST_UNPROVEN");
        let Ok(Some(bytes)) = super::checked_managed_existing_file(&dir.join(&name), 0) else {
            out.push(row);
            continue;
        };
        let spec = match decode_scope(host, &format!("managed/{name}"), &bytes) {
            Ok(value) => value,
            Err(reason) => {
                row.reason_code = reason;
                out.push(row);
                continue;
            }
        };
        row.resource_name = spec.resource_name.clone();
        row.manifest_sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref().to_vec();
        match inspect(&spec).await {
            Ok(Some(live)) if Some(live) == canonical_rules(&spec) => {
                row.present = true;
                row.converged = true;
                row.reason_code = "DESIRED_PRESENT".into();
            }
            Ok(Some(_)) => {
                row.present = true;
                row.reason_code = "MANAGED_FIREWALL_RULESET_DRIFT".into();
            }
            Ok(None) => row.reason_code = "MANAGED_FIREWALL_TABLE_MISSING".into(),
            Err(reason) => row.reason_code = reason,
        }
        out.push(row);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (FleetHost, FleetVmManagedFirewall) {
        let host = FleetHost {
            kind: FleetHostKind::Vm as i32,
            machine_id: "vmtest".into(),
            ..Default::default()
        };
        let spec = FleetVmManagedFirewall {
            schema_version: 1,
            machine_id: "vmtest".into(),
            resource_name: "sb-vmtest-lab".into(),
            denied_ingress: vec![edge_shared_types::FleetVmFirewallDeny {
                transport: FleetVmFirewallTransport::Tcp as i32,
                destination_port: 22555,
            }],
        };
        (host, spec)
    }
    #[test]
    fn firewall_manifest_is_typed_bounded_and_scoped() {
        let (host, mut spec) = fixture();
        assert!(decode_scope(&host, "managed/host-firewall-lab.pb", &spec.encode_to_vec()).is_ok());
        spec.machine_id = "foreign".into();
        assert!(decode_scope(&host, "managed/host-firewall-lab.pb", &spec.encode_to_vec()).is_err());
        let (_, mut spec) = fixture();
        spec.denied_ingress[0].destination_port = 22;
        assert!(decode_scope(&host, "managed/host-firewall-lab.pb", &spec.encode_to_vec()).is_err());
        spec.denied_ingress[0].destination_port = 22555;
        spec.denied_ingress.push(spec.denied_ingress[0].clone());
        assert!(decode_scope(&host, "managed/host-firewall-lab.pb", &spec.encode_to_vec()).is_err());
        assert!(decode_scope(&host, "managed/host-firewall-../x.pb", &spec.encode_to_vec()).is_err());
        let mut injected = host;
        injected.machine_id = "vm\";delete table inet filter;#".into();
        assert!(decode_scope(
            &injected,
            "managed/host-firewall-lab.pb",
            &spec.encode_to_vec()
        ).is_err());
    }

    #[test]
    fn generated_nft_batch_is_atomic_scoped_and_never_defaults_to_drop() {
        let (_, mut spec) = fixture();
        let created = render_batch(None, Some(&spec));
        assert!(created.starts_with("add table inet sb_lab\n"));
        assert!(created.contains("hook input priority 10; policy accept;"));
        assert!(created.contains("tcp dport 22555 drop"));
        assert!(!created.contains("policy drop"));
        assert!(!created.contains("flush ruleset"));
        assert!(!created.contains("delete table inet filter"));
        let deleted = render_batch(Some(&spec), None);
        assert_eq!(deleted, "delete table inet sb_lab\n");
        spec.denied_ingress[0].destination_port = 22556;
        let (_, previous) = fixture();
        let edited = render_batch(Some(&previous), Some(&spec));
        assert!(edited.starts_with("flush chain inet sb_lab ingress\n"));
        assert!(edited.contains("tcp dport 22556 drop"));
        assert!(!edited.contains("add table"));
    }

    #[test]
    fn firewall_native_readback_rejects_foreign_chain_or_extra_rules() {
        let (_, spec) = fixture();
        let good = serde_json::json!({
            "nftables": [
                {"metainfo": {"json_schema_version": 1}},
                {"table": {"family": "inet", "name": "sb_lab"}},
                {"chain": {
                    "family": "inet", "table": "sb_lab", "name": "ingress",
                    "type": "filter", "hook": "input", "prio": 10, "policy": "accept",
                    "comment": "sing-box:vmtest:sb-vmtest-lab"
                }},
                {"rule": {
                    "family": "inet", "table": "sb_lab", "chain": "ingress",
                    "expr": [
                        {"match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                            "right": 22555
                        }},
                        {"drop": null}
                    ]
                }}
            ]
        });
        assert_eq!(
            decode_ruleset(&spec, &good).unwrap(),
            vec![(FleetVmFirewallTransport::Tcp as i32, 22555)]
        );
        let mut foreign = good.clone();
        foreign["nftables"][2]["chain"]["hook"] = Value::String("output".into());
        assert!(decode_ruleset(&spec, &foreign).is_err());
        foreign = good.clone();
        foreign["nftables"].as_array_mut().unwrap().push(
            serde_json::json!({"chain": {"name":"foreign"}})
        );
        assert!(decode_ruleset(&spec, &foreign).is_err());
        foreign = good;
        foreign["nftables"][3]["rule"]["expr"][1] = serde_json::json!({"accept":null});
        assert!(decode_ruleset(&spec, &foreign).is_err());
    }
}
