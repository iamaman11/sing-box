//! Read-only host Line2 public acceptance using existing authoritative owners.
//! The GitHub runner is the independent traffic vantage, not a Docker or VM
//! mutation owner. No operator-supplied IP, TLS name or credential is trusted.
use edge_shared_types::canonical_production_desired_state;
use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

/// Validate the existing Git-pinned sing-box JSON boundary (not an alternate
/// desired registry) before six open TCP listeners can be called our Line2.
/// The WARP SOCKS outbound explicitly declares TCP-only: do not claim UDP.
fn validate_git_line2_template(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err("HOST_VM_LINE2_GIT_TEMPLATE_SIZE_INVALID");
    }
    let root: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "HOST_VM_LINE2_GIT_TEMPLATE_JSON_INVALID")?;
    let inbounds = root["inbounds"]
        .as_array()
        .ok_or("HOST_VM_LINE2_GIT_INBOUNDS_MISSING")?;
    let expected = [
        ("http-proxy-auth", "http", 3128_u64),
        ("socks-proxy-auth", "socks", 1080),
        ("https-proxy-auth", "http", 9443),
        ("http-proxy-direct-auth", "http", 4128),
        ("socks-proxy-direct-auth", "socks", 4080),
        ("https-proxy-direct-auth", "http", 4443),
    ];
    if inbounds.len() != expected.len() {
        return Err("HOST_VM_LINE2_GIT_PUBLIC_INGRESS_SCOPE_DRIFT");
    }
    for (tag, protocol, port) in expected {
        let matching = inbounds
            .iter()
            .filter(|entry| entry["tag"].as_str() == Some(tag))
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err("HOST_VM_LINE2_GIT_PUBLIC_INGRESS_AMBIGUOUS");
        }
        let inbound = matching[0];
        let users = inbound["users"]
            .as_array()
            .ok_or("HOST_VM_LINE2_GIT_USERS_MISSING")?;
        if inbound["type"].as_str() != Some(protocol)
            || inbound["listen"].as_str() != Some("::")
            || inbound["listen_port"].as_u64() != Some(port)
            || users.len() != 1
            || users[0]["username"].as_str() != Some("${PROXY_USERNAME}")
            || users[0]["password"].as_str() != Some("${PROXY_PASSWORD}")
        {
            return Err("HOST_VM_LINE2_GIT_PUBLIC_INGRESS_CONFIG_DRIFT");
        }
        if tag.starts_with("https-") {
            if inbound["tls"]["enabled"].as_bool() != Some(true)
                || inbound["tls"]["certificate_path"].as_str() != Some("${PROXY_CERT_PATH}")
                || inbound["tls"]["key_path"].as_str() != Some("${PROXY_KEY_PATH}")
            {
                return Err("HOST_VM_LINE2_GIT_TLS_INGRESS_DRIFT");
            }
        } else if !inbound["tls"].is_null() {
            return Err("HOST_VM_LINE2_GIT_UNEXPECTED_INGRESS_TLS");
        }
    }
    let outbounds = root["outbounds"]
        .as_array()
        .ok_or("HOST_VM_LINE2_GIT_OUTBOUNDS_MISSING")?;
    if outbounds.len() != 3 {
        return Err("HOST_VM_LINE2_GIT_OUTBOUND_SCOPE_DRIFT");
    }
    let warp = outbounds
        .iter()
        .filter(|item| item["tag"].as_str() == Some("warp-local"))
        .collect::<Vec<_>>();
    if warp.len() != 1
        || warp[0]["type"].as_str() != Some("socks")
        || warp[0]["server"].as_str() != Some("warp-egress")
        || warp[0]["server_port"].as_u64() != Some(11080)
        || warp[0]["network"].as_str() != Some("tcp")
    {
        return Err("HOST_VM_LINE2_GIT_WARP_TCP_ONLY_POLICY_DRIFT");
    }
    for (tag, kind) in [("direct", "direct"), ("block", "block")] {
        if outbounds
            .iter()
            .filter(|item| {
                item["tag"].as_str() == Some(tag) && item["type"].as_str() == Some(kind)
            })
            .count() != 1
        {
            return Err("HOST_VM_LINE2_GIT_DIRECT_BLOCK_OUTBOUND_DRIFT");
        }
    }
    let route = &root["route"];
    let rules = route["rules"]
        .as_array()
        .ok_or("HOST_VM_LINE2_GIT_ROUTE_RULES_MISSING")?;
    if route["final"].as_str() != Some("direct")
        || rules.len() != 2
        || rules[0]["ip_is_private"].as_bool() != Some(true)
        || rules[0]["outbound"].as_str() != Some("block")
        || rules[1]["outbound"].as_str() != Some("warp-local")
    {
        return Err("HOST_VM_LINE2_GIT_ROUTE_POLICY_DRIFT");
    }
    let warp_inbounds = rules[1]["inbound"]
        .as_array()
        .ok_or("HOST_VM_LINE2_GIT_WARP_INGRESS_MISSING")?;
    let names = warp_inbounds
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<BTreeSet<_>>();
    if warp_inbounds.len() != 3
        || names != BTreeSet::from([
            "http-proxy-auth",
            "socks-proxy-auth",
            "https-proxy-auth",
        ])
    {
        return Err("HOST_VM_LINE2_GIT_WARP_INGRESS_SCOPE_DRIFT");
    }
    Ok(())
}

fn check_git_line2_template(bundle_root: &str) -> Result<(), String> {
    let path = Path::new(bundle_root).join("line2-proxy/config.template.json");
    let meta = fs::symlink_metadata(&path).map_err(|_| "HOST_VM_LINE2_GIT_TEMPLATE_MISSING")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 65_536 {
        return Err("HOST_VM_LINE2_GIT_TEMPLATE_UNTRUSTED".into());
    }
    let raw = fs::read(&path).map_err(|_| "HOST_VM_LINE2_GIT_TEMPLATE_READ_FAILED")?;
    validate_git_line2_template(&raw).map_err(str::to_owned)
}

/// Git-owned hostname against the independently provider-observed exact VM IP.
/// DNS configuration observation on the VM is NOT a substitute for public
/// resolution from the GitHub-hosted runner.
fn validate_public_dns(
    addresses: &BTreeSet<IpAddr>,
    expected_ipv4: Ipv4Addr,
    vm_ipv6_enabled: bool,
) -> Result<(), &'static str> {
    if addresses.is_empty()
        || !addresses.contains(&IpAddr::V4(expected_ipv4))
        || addresses.iter().any(|address| match address {
            IpAddr::V4(ip) => *ip != expected_ipv4,
            IpAddr::V6(ip) => !vm_ipv6_enabled || ip.is_loopback() || ip.is_unspecified(),
        })
    {
        return Err("HOST_VM_LINE2_WITNESS_PUBLIC_DNS_IP_MISMATCH");
    }
    // An IPv6-enabled VM still needs a provider-owned public v6 and exact AAAA
    // expectation before claiming dual-stack Internet PASS.
    if vm_ipv6_enabled {
        return Err("HOST_VM_LINE2_WITNESS_IPV6_PROVIDER_PIN_UNPROVEN");
    }
    Ok(())
}

async fn check_public_dns(
    hostname: &str,
    expected_ipv4: &str,
    vm_ipv6_enabled: bool,
) -> Result<(), String> {
    let expected = expected_ipv4
        .parse::<Ipv4Addr>()
        .map_err(|_| "HOST_VM_LINE2_WITNESS_PROVIDER_IPV4_INVALID")?;
    let resolved = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::net::lookup_host((hostname, 443)),
    )
    .await
    .map_err(|_| "HOST_VM_LINE2_WITNESS_DNS_TIMEOUT")?
    .map_err(|_| "HOST_VM_LINE2_WITNESS_DNS_RESOLUTION_UNAVAILABLE")?;
    let answers = resolved.map(|address| address.ip()).collect::<BTreeSet<_>>();
    validate_public_dns(&answers, expected, vm_ipv6_enabled).map_err(str::to_owned)
}

fn validate_witness_scope(
    machine_id: &str,
    active_machine: &str,
    dns_name: &str,
    production_name: &str,
    line1_name: &str,
    line2_name: &str,
    username: &str,
    generation: u64,
) -> Result<(), &'static str> {
    if machine_id.is_empty()
        || machine_id.len() > 64
        || !machine_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || machine_id != active_machine
    {
        return Err("HOST_VM_LINE2_WITNESS_ACTIVE_MACHINE_MISMATCH");
    }
    if dns_name.is_empty()
        || dns_name != production_name
        || line1_name != dns_name
        || line2_name != dns_name
        || username != "acceptance"
        || generation == 0
    {
        return Err("HOST_VM_LINE2_WITNESS_GIT_POLICY_MISMATCH");
    }
    Ok(())
}

pub(crate) async fn run(
    machine_id: &str,
    source_comment_id: Option<u64>,
    release: &edge_orchestrator::OrchestrationContext,
) -> Result<(), String> {
    let comment = source_comment_id
        .filter(|id| *id > 0)
        .ok_or("HOST_VM_LINE2_WITNESS_OPERATOR_COMMENT_REQUIRED")?;
    // Same protected Git and exact release authority used by /host apply.
    // The witness MUST NOT create a VM or accept an operator-supplied IP.
    release.application_release_authority()?;
    let host = release.verified_vm_first_use_host(machine_id)?;
    let generation = host
        .vm_first_use_credential
        .as_ref()
        .ok_or("HOST_VM_LINE2_WITNESS_CREDENTIAL_GIT_PIN_MISSING")?
        .generation;
    let root = canonical_production_desired_state()?;
    let dns = root
        .dns
        .as_ref()
        .ok_or("HOST_VM_LINE2_WITNESS_DNS_DESIRED_MISSING")?;
    let path = format!("infra/hosts/specs/{machine_id}.textproto");
    let (machine, application) = crate::vm_host_desired::load(Path::new(&path))?;
    let line1 = application
        .runtime_policy
        .line1
        .as_ref()
        .ok_or("HOST_VM_LINE2_WITNESS_LINE1_POLICY_MISSING")?;
    let line2 = application
        .runtime_policy
        .line2
        .as_ref()
        .ok_or("HOST_VM_LINE2_WITNESS_LINE2_POLICY_MISSING")?;
    check_git_line2_template(&application.bundle_root)?;
    validate_witness_scope(
        machine_id,
        &dns.active_machine_id,
        &dns.record_name,
        &root.public_hostname,
        &line1.tunnel_domain,
        &line2.proxy_cert_cn,
        &line2.proxy_username,
        generation,
    )
    .map_err(str::to_owned)?;

    // The existing Vultr read-only owner requires exact machine NOOP and
    // verified firewall bindings. Only its observed main_ip is tested.
    let observed =
        crate::vultr_lifecycle_command::exact_existing_machine_observation(&machine, machine_id)
            .await?;
    let ip = observed
        .main_ip
        .ok_or("HOST_VM_LINE2_WITNESS_VULTR_PUBLIC_IP_UNPROVEN")?;
    let vm_ipv6_enabled = machine
        .machines
        .first()
        .ok_or("HOST_VM_LINE2_WITNESS_MACHINE_SPEC_MISSING")?
        .provider
        .enable_ipv6;
    check_public_dns(&dns.record_name, &ip, vm_ipv6_enabled).await?;
    let client_id = std::env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID")
        .map_err(|_| "HOST_VM_LINE2_WITNESS_ACCESS_CLIENT_ID_MISSING")?;
    let client_secret = std::env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET")
        .map_err(|_| "HOST_VM_LINE2_WITNESS_ACCESS_CLIENT_SECRET_MISSING")?;
    // Active Worker signer is proved using a fresh nonce against EXACT Git
    // authority, not inferred from the Access GET or provider metadata.
    if host.worker_authority_public_key.len() != 32 {
        return Err("HOST_VM_LINE2_WITNESS_WORKER_SIGNER_PIN_MISSING".to_owned());
    }
    edge_secrets::prove_canonical_host_signer_with_service_identity(
        &client_id,
        &client_secret,
        &host.worker_authority_public_key,
    )
    .await?;
    // Never print either Access value, retrieved proxy password or raw body.
    crate::line2_external_witness::witness_with_service_identity(
        generation,
        &ip,
        &dns.record_name,
        &line2.proxy_username,
        &client_id,
        &client_secret,
    )
    .await?;
    println!("host_vm_line2_witness_operation=issue1-comment-{comment}");
    println!("host_vm_line2_witness_machine={machine_id}");
    println!("host_vm_line2_witness_source=PROTECTED_GIT_AND_VULTR_READ_ONLY");
    println!(
        "host_vm_line2_witness_release={}",
        release.release().release_set_sha256
    );
    println!("host_vm_line2_witness_worker=VERIFIED_GIT_PINNED_ED25519");
    println!("host_vm_line2_public_dns_a=EXACT_PROVIDER_IP");
    println!("host_vm_line2_public_dns_aaaa=EXACT_DISABLED_VM_POLICY");
    println!("host_vm_line2_warp_udp=GIT_OUTBOUND_TCP_ONLY_NOT_SUPPORTED");
    println!("host_vm_line2_direct_udp=UNPROVEN_PUBLIC_UDP_WITNESS_MISSING");
    println!("host_vm_line2_witness_mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admit(id: &str) -> Result<(), &'static str> {
        validate_witness_scope(
            id,
            "application-acceptance-5",
            "miu.alegria.by",
            "miu.alegria.by",
            "miu.alegria.by",
            "miu.alegria.by",
            "acceptance",
            38503639351,
        )
    }

    #[test]
    fn line2_public_witness_requires_exact_git_selected_machine() {
        assert!(admit("application-acceptance-5").is_ok());
        for bad in [
            "",
            "application-acceptance-4",
            "production-1",
            "application/acceptance-5",
            "application-acceptance-5 ",
        ] {
            assert!(admit(bad).is_err());
        }
    }

    #[test]
    fn line2_exact_git_template_rejects_forged_ports_credentials_and_warp_udp() {
        let canonical =
            include_bytes!("../../../../win/vultr-waw/stack/line2-proxy/config.template.json");
        assert!(validate_git_line2_template(canonical).is_ok());
        let mut bad: serde_json::Value = serde_json::from_slice(canonical).unwrap();
        bad["inbounds"][0]["listen_port"] = serde_json::json!(9999);
        assert!(validate_git_line2_template(&serde_json::to_vec(&bad).unwrap()).is_err());
        bad = serde_json::from_slice(canonical).unwrap();
        bad["inbounds"][0]["users"][0]["password"] = serde_json::json!("foreign");
        assert!(validate_git_line2_template(&serde_json::to_vec(&bad).unwrap()).is_err());
        bad = serde_json::from_slice(canonical).unwrap();
        bad["outbounds"][0]["network"] = serde_json::json!("tcp,udp");
        assert!(validate_git_line2_template(&serde_json::to_vec(&bad).unwrap()).is_err());
        bad = serde_json::from_slice(canonical).unwrap();
        bad["route"]["final"] = serde_json::json!("warp-local");
        assert!(validate_git_line2_template(&serde_json::to_vec(&bad).unwrap()).is_err());
    }

    #[test]
    fn public_dns_uses_provider_ip_and_blocks_unscoped_aaaa() {
        let provider = Ipv4Addr::new(64, 176, 76, 2);
        let a = IpAddr::V4(provider);
        assert!(validate_public_dns(&BTreeSet::from([a]), provider, false).is_ok());
        for answers in [
            BTreeSet::new(),
            BTreeSet::from([IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]),
            BTreeSet::from([a, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]),
            BTreeSet::from([a, IpAddr::V6("2001:4860:4860::8888".parse().unwrap())]),
        ] {
            assert!(validate_public_dns(&answers, provider, false).is_err());
        }
        assert!(validate_public_dns(&BTreeSet::from([a]), provider, true).is_err());
    }

    #[test]
    fn line2_public_witness_denies_hostname_tls_username_and_generation_drift() {
        let args = (
            "application-acceptance-5",
            "application-acceptance-5",
            "miu.alegria.by",
            "miu.alegria.by",
            "miu.alegria.by",
            "miu.alegria.by",
            "acceptance",
            38503639351,
        );
        assert!(
            validate_witness_scope(
                args.0, args.1, args.2, args.3, args.4, args.5, args.6, args.7
            )
            .is_ok()
        );
        for (line1, line2, username, generation) in [
            ("foreign.example", args.5, args.6, args.7),
            (args.4, "foreign.example", args.6, args.7),
            (args.4, args.5, "root", args.7),
            (args.4, args.5, args.6, 0),
        ] {
            assert!(
                validate_witness_scope(
                    args.0, args.1, args.2, args.3, line1, line2, username, generation,
                )
                .is_err()
            );
        }
    }
}
