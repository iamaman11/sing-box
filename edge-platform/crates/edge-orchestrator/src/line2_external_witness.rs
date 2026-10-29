//! Independent GitHub-hosted Line2 public-port witness. Read-only VM
//! projection via canonical Cloudflare Worker; never opens a VM/SSH channel,
//! starts a service or emits a secret. Production control remains elsewhere.
use edge_secrets::{
    fetch_canonical_credential_bundle, fetch_canonical_credential_bundle_with_service_identity,
};
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialProjectionKind, credential_delivery_bundle,
};
use std::collections::BTreeSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

const CURL: &str = "/usr/bin/curl";
const HTTPS_204: &str = "https://www.gstatic.com/generate_204";
const EGRESS: &str = "https://api.ipify.org";
const SECOND_EGRESS: &str = "https://www.cloudflare.com/cdn-cgi/trace";
// The reserved .invalid TLD must not resolve or reach an HTTP origin.
// SOCKS5h, unlike SOCKS5, delegates name resolution to the remote proxy.
const DNS_NEGATIVE: &str = "https://sing-box-never-resolve.invalid/";
const MAX_PUBLIC_REPLY_BYTES: usize = 16_384;
const PROXIES: [(&str, &str, u16); 6] = [
    ("http-direct", "http", 4128),
    ("socks5-direct", "socks5h", 4080),
    ("https-direct", "https", 4443),
    ("http-warp", "http", 3128),
    ("socks5-warp", "socks5h", 1080),
    ("https-warp", "https", 9443),
];

fn quote_curl_config(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return Err("Line2 proxy credential contains noncanonical characters".to_owned());
    }
    Ok(raw.replace('\\', "\\\\").replace('"', "\\\""))
}

fn valid_domain(raw: &str) -> bool {
    raw.len() <= 253
        && raw.len() >= 4
        && raw.contains('.')
        && raw.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 0 || b == 168))
        || (a == 198 && ((b == 18 || b == 19) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}
fn cloudflare_trace_ipv4(body: &str) -> Result<Ipv4Addr, String> {
    let value = body
        .lines()
        .filter_map(|line| line.strip_prefix("ip="))
        .collect::<Vec<_>>();
    if value.len() != 1 {
        return Err("HOST_VM_LINE2_WITNESS_TRACE_IP_MISSING_OR_DUPLICATE".to_owned());
    }
    let ip: Ipv4Addr = value[0]
        .parse()
        .map_err(|_| "HOST_VM_LINE2_WITNESS_TRACE_IP_INVALID")?;
    if !public_ipv4(ip) {
        return Err("HOST_VM_LINE2_WITNESS_TRACE_IP_NONPUBLIC".to_owned());
    }
    Ok(ip)
}

fn cloudflare_trace_warp(body: &str) -> Result<bool, String> {
    let value = body
        .lines()
        .filter_map(|line| line.strip_prefix("warp="))
        .collect::<Vec<_>>();
    if value.len() != 1 {
        return Err("HOST_VM_LINE2_WITNESS_TRACE_WARP_MISSING_OR_DUPLICATE".to_owned());
    }
    match value[0] {
        "on" | "plus" => Ok(true),
        "off" => Ok(false),
        _ => Err("HOST_VM_LINE2_WITNESS_TRACE_WARP_UNPROVEN".to_owned()),
    }
}

fn proxy_address(protocol: &str, ip: Ipv4Addr, domain: &str, port: u16) -> String {
    if protocol == "https" {
        format!("https://{domain}:{port}")
    } else {
        format!("{protocol}://{ip}:{port}")
    }
}
fn query_proxy(
    protocol: &str,
    ip: Ipv4Addr,
    domain: &str,
    port: u16,
    target: &str,
    username: &str,
    password: &str,
) -> Result<(Option<i32>, String, String), String> {
    let proxy = proxy_address(protocol, ip, domain, port);
    // curl -q suppresses .curlrc. No credentials in argv or environment:
    // libcurl takes the full proxy-user field on a private config stdin.
    let mut command = Command::new(CURL);
    command.args([
        "-q",
        "--config",
        "-",
        "--silent",
        "--fail",
        "--proto",
        "=https",
        "--connect-timeout",
        "4",
        "--max-filesize",
        "16384",
        "--proto-redir",
        "=https",
        "--max-time",
        "12",
        "--noproxy",
        "",
        "--output",
        "-",
        "--write-out",
        "\nHTTP:%{http_connect};%{http_code}",
        "--proxy",
        proxy.as_str(),
    ]);
    if protocol == "https" {
        command.args(["--resolve", &format!("{domain}:{port}:{ip}")]);
    }
    command
        .arg(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| "Line2 witness curl unavailable".to_owned())?;
    let secret = quote_curl_config(&format!("{username}:{password}"))?;
    let written = child
        .stdin
        .take()
        .and_then(|mut stdin| {
            stdin
                .write_all(format!("proxy-user = \"{secret}\"\n").as_bytes())
                .ok()
        })
        .is_some();
    let output = child
        .wait_with_output()
        .map_err(|_| "Line2 witness curl process observation failed".to_owned())?;
    if !written {
        return Err("Line2 witness could not feed proxy identity".to_owned());
    }
    if output.stdout.len() > MAX_PUBLIC_REPLY_BYTES {
        return Err("HOST_VM_LINE2_WITNESS_HTTP_REPLY_OVERSIZE".to_owned());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "Line2 witness response is not UTF8".to_owned())?;
    let (body, statuses) = text
        .rsplit_once("\nHTTP:")
        .ok_or("Line2 witness curl did not return statuses")?;
    if statuses.len() != 7
        || statuses.as_bytes()[3] != b';'
        || !statuses
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 3 || b.is_ascii_digit())
    {
        return Err("HOST_VM_LINE2_WITNESS_STATUS_NONCANONICAL".to_owned());
    }
    Ok((output.status.code(), body.to_owned(), statuses.to_owned()))
}

fn require_authenticated_https_status(
    protocol: &str,
    result: &(Option<i32>, String, String),
    expected_status: &str,
) -> Result<(), &'static str> {
    let (connect, origin) = result
        .2
        .split_once(';')
        .ok_or("HOST_VM_LINE2_WITNESS_STATUS_INVALID")?;
    // The HTTPS origin must never be counted after a proxy authentication
    // rejection (407), or after an unintended direct/bypassed connection.
    let expected_connect = match protocol {
        "http" | "https" => "200",
        "socks5h" => "000",
        _ => return Err("HOST_VM_LINE2_WITNESS_PROTOCOL_INVALID"),
    };
    if result.0 != Some(0) || connect != expected_connect || origin != expected_status {
        return Err("HOST_VM_LINE2_WITNESS_PROXY_ORIGIN_PROOF_FAILED");
    }
    Ok(())
}

fn require_204(protocol: &str, result: (Option<i32>, String, String)) -> Result<(), String> {
    require_authenticated_https_status(protocol, &result, "204")
        .map_err(str::to_owned)?;
    if !result.1.is_empty() {
        return Err("HOST_VM_LINE2_WITNESS_204_BODY_UNEXPECTED".into());
    }
    Ok(())
}

fn remote_nxdomain_has_no_successful_origin(
    protocol: &str,
    result: &(Option<i32>, String, String),
) -> bool {
    // Only a positive SOCKS5h request followed by this negative request can
    // attribute the name-resolution failure to a functioning remote proxy.
    // This is a no-origin proof, not an authoritative DNS RCODE proof.
    protocol == "socks5h"
        && matches!(result.0, Some(5 | 6 | 97))
        && result.1.is_empty()
        && result.2 == "000;000"
}
fn negative_rejected(protocol: &str, (exit, _, codes): &(Option<i32>, String, String)) -> bool {
    let (connect, status) = match codes.split_once(';') {
        Some(pair) => pair,
        None => return false,
    };
    if matches!(protocol, "http" | "https") {
        matches!(exit, Some(22 | 56)) && connect == "407" && matches!(status, "000" | "407")
    } else if protocol == "socks5h" {
        matches!(exit, Some(67 | 97)) && connect == "000" && status == "000"
    } else {
        false
    }
}

pub(crate) async fn witness(
    generation: u64,
    vm_ip: &str,
    domain: &str,
    username: &str,
    access_identity_path: &Path,
) -> Result<(), String> {
    if generation == 0 || !valid_domain(domain) || username != "acceptance" {
        return Err(
            "Line2 witness refuses invalid generation, domain or noncanonical identity".to_owned(),
        );
    }
    let ip: Ipv4Addr = vm_ip
        .parse()
        .map_err(|_| "Line2 witness VM address must be a canonical IPv4".to_owned())?;
    if !public_ipv4(ip) || ip.to_string() != vm_ip {
        return Err("Line2 witness VM address must be an owned public IPv4".to_owned());
    }
    if !Path::new(CURL).is_file() {
        return Err("Line2 witness fixed curl executable not installed".to_owned());
    }
    let bundle = fetch_canonical_credential_bundle(
        CredentialProjectionKind::Vm,
        generation,
        access_identity_path,
    )
    .await?;
    // Blocking curl probes are bounded but must never occupy a Tokio worker
    // while the same runtime operates the typed control plane.
    let domain = domain.to_owned();
    let username = username.to_owned();
    tokio::task::spawn_blocking(move || {
        verify_bundle_and_probe(generation, ip, &domain, &username, bundle)
    })
    .await
    .map_err(|_| "HOST_VM_LINE2_WITNESS_TASK_UNKNOWN")?
}

/// The independent GitHub-hosted witness reuses the protected VM Access
/// identity directly, rather than copying a secret to a new credential file.
pub(crate) async fn witness_with_service_identity(
    generation: u64,
    vm_ip: &str,
    domain: &str,
    username: &str,
    access_client_id: &str,
    access_client_secret: &str,
) -> Result<(), String> {
    if generation == 0 || !valid_domain(domain) || username != "acceptance" {
        return Err("HOST_VM_WITNESS_TARGET_INVALID".to_owned());
    }
    let ip: Ipv4Addr = vm_ip.parse().map_err(|_| "HOST_VM_WITNESS_IP_INVALID")?;
    if !public_ipv4(ip) || ip.to_string() != vm_ip {
        return Err("HOST_VM_WITNESS_NOT_PUBLIC_IPV4".to_owned());
    }
    if !Path::new(CURL).is_file() {
        return Err("HOST_VM_WITNESS_CURL_UNAVAILABLE".to_owned());
    }
    let bundle = fetch_canonical_credential_bundle_with_service_identity(
        CredentialProjectionKind::Vm,
        generation,
        access_client_id,
        access_client_secret,
    )
    .await?;
    let domain = domain.to_owned();
    let username = username.to_owned();
    tokio::task::spawn_blocking(move || {
        verify_bundle_and_probe(generation, ip, &domain, &username, bundle)
    })
    .await
    .map_err(|_| "HOST_VM_LINE2_WITNESS_TASK_UNKNOWN")?
}

fn verify_bundle_and_probe(
    generation: u64,
    ip: Ipv4Addr,
    domain: &str,
    username: &str,
    bundle: CredentialDeliveryBundle,
) -> Result<(), String> {
    if bundle.generation != generation || bundle.dummy_non_secret {
        return Err("Line2 witness refuses dummy or stale VM credential generation".to_owned());
    }
    let projection = match bundle.payload {
        Some(credential_delivery_bundle::Payload::Vm(value)) => value,
        _ => return Err("Line2 witness refuses non-VM projection".to_owned()),
    };
    let password = projection
        .line2_proxy
        .ok_or("Line2 witness real VM proxy generation missing")?
        .password;
    if password.is_empty() {
        return Err("Line2 witness refuses empty VM proxy secret".to_owned());
    }
    let mut external_ips = Vec::with_capacity(6);
    let mut secondary_ips = Vec::with_capacity(6);
    let mut names = BTreeSet::new();
    for (name, protocol, port) in PROXIES {
        if !names.insert(name) || port == 0 {
            return Err("Line2 witness duplicated a named proxy".to_owned());
        }
        // Five independent public Internet HTTPS requests through each named
        // public port. A loopback-only service cannot satisfy this check.
        for _ in 0..5 {
            let result = query_proxy(protocol, ip, domain, port, HTTPS_204, username, &password)?;
            require_204(protocol, result)
                .map_err(|_| format!("{name} external HTTPS 204 failed"))?;
        }
        let negative = query_proxy(
            protocol,
            ip,
            domain,
            port,
            HTTPS_204,
            "invalid-acceptance",
            &password,
        )?;
        if !negative_rejected(protocol, &negative) {
            return Err(format!(
                "{name} external incorrect auth not rejected at proxy"
            ));
        }
        let response = query_proxy(protocol, ip, domain, port, EGRESS, username, &password)?;
        require_authenticated_https_status(protocol, &response, "200")
            .map_err(|_| format!("{name} external public egress endpoint failed"))?;
        let observed: Ipv4Addr = response
            .1
            .trim()
            .parse()
            .map_err(|_| format!("{name} egress IPv4 invalid"))?;
        if !public_ipv4(observed) {
            return Err(format!("{name} egress is not a public IPv4"));
        }
        external_ips.push(observed);
        // A second independent public network destination is mandatory: one
        // external IP echo service alone cannot prove the intended route.
        let trace = query_proxy(
            protocol,
            ip,
            domain,
            port,
            SECOND_EGRESS,
            username,
            &password,
        )?;
        require_authenticated_https_status(protocol, &trace, "200")
            .map_err(|_| format!("{name} second independent egress witness failed"))?;
        secondary_ips.push(cloudflare_trace_ipv4(&trace.1)?);
        if cloudflare_trace_warp(&trace.1)? != name.ends_with("-warp") {
            return Err(format!("{name} Cloudflare trace contradicts declared DIRECT/WARP route"));
        }
        if protocol == "socks5h" {
            let nxdomain = query_proxy(
                protocol,
                ip,
                domain,
                port,
                DNS_NEGATIVE,
                username,
                &password,
            )?;
            if !remote_nxdomain_has_no_successful_origin(protocol, &nxdomain) {
                return Err(format!("{name} SOCKS5h negative remote-DNS proof missing"));
            }
        }
        println!(
            "line2_external_endpoint={name} samples=5 HTTPS=PASS TLS=VERIFIED AUTH_NEGATIVE=REJECTED EGRESS_WITNESSES=2"
        );
    }
    if !(0..3)
        .all(|i| external_ips[i] != external_ips[i + 3] && secondary_ips[i] != secondary_ips[i + 3])
    {
        return Err("Line2 direct/WARP public egress identities indistinguishable".to_owned());
    }
    println!("operation=INITIAL_LINE2_EXTERNAL_WITNESS");
    println!("line2_external_6_of_6=PASS");
    // Six public port probes are NOT the entire #538 G5 matrix. Separate
    // DNS positive/NXDOMAIN, IPv6 and UDP policy cases remain independent.
    println!("line2_g5_full_policy_matrix=UNPROVEN");
    println!("line2_direct_warp_egress_distinct=true");
    println!("line2_external_warp_identity=TRACE_CONFIRMED");
    println!("line2_socks_remote_dns_negative_origin=REJECTED");
    println!("line2_dns_authoritative_nxdomain_rcode=UNPROVEN");
    println!("line2_credential_projection=VM_CANONICAL_WORKER_V2");
    println!("line2_witness_vantage=INDEPENDENT_GITHUB_RUNNER");
    println!("provider_mutations=0");
    println!("vm_runtime_mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cloudflare_trace_requires_exact_one_public_ipv4() {
        assert_eq!(
            cloudflare_trace_ipv4("warp=off\nip=8.8.8.8\nloc=DE\n").unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap()
        );
        for bad in [
            "",
            "ip=192.168.0.1\n",
            "ip=8.8.8.8\nip=1.1.1.1\n",
            "ip=::1\n",
            "ip=not-an-ip\n",
        ] {
            assert!(cloudflare_trace_ipv4(bad).is_err());
        }
    }

    #[test]
    fn trace_warp_requires_one_explicit_signed_route_identity() {
        assert_eq!(cloudflare_trace_warp("ip=8.8.8.8\nwarp=off\n"), Ok(false));
        assert_eq!(cloudflare_trace_warp("ip=8.8.8.8\nwarp=on\n"), Ok(true));
        assert_eq!(cloudflare_trace_warp("ip=8.8.8.8\nwarp=plus\n"), Ok(true));
        for bad in [
            "",
            "warp=\n",
            "warp=unknown\n",
            "warp=on\nwarp=off\n",
        ] {
            assert!(cloudflare_trace_warp(bad).is_err());
        }
    }

    #[test]
    fn named_port_set_matches_six_public_line2_endpoints() {
        assert_eq!(PROXIES.len(), 6);
        assert_eq!(
            PROXIES.iter().map(|x| x.2).collect::<BTreeSet<_>>().len(),
            6
        );
    }
    #[test]
    fn rejects_reserved_vantages_and_bad_tls_names() {
        for ip in [
            "127.0.0.1",
            "10.20.30.40",
            "192.168.1.1",
            "100.64.1.2",
            "198.51.100.9",
        ] {
            assert!(!public_ipv4(ip.parse().unwrap()));
        }
        for domain in [
            "",
            ".bad",
            "bad..domain",
            "http://domain.test",
            "-bad.example",
        ] {
            assert!(!valid_domain(domain));
        }
        assert!(valid_domain("stage2-acceptance.alegria.by"));
    }
    #[test]
    fn never_accepts_timeouts_or_http_origin_as_invalid_proxy_auth() {
        for protocol in ["http", "https", "socks5h"] {
            assert!(!negative_rejected(
                protocol,
                &(Some(28), String::new(), "000;000".into())
            ));
        }
        assert!(negative_rejected(
            "http",
            &(Some(22), String::new(), "407;000".into())
        ));
        assert!(negative_rejected(
            "socks5h",
            &(Some(97), String::new(), "000;000".into())
        ));
        assert!(require_204("http", (Some(0), String::new(), "200;204".into())).is_ok());
        assert!(require_204("socks5h", (Some(0), String::new(), "000;204".into())).is_ok());
        assert!(require_204("http", (Some(0), "body".into(), "200;204".into())).is_err());
        assert!(require_204("http", (Some(0), String::new(), "407;204".into())).is_err());
        assert!(require_204("http", (Some(0), String::new(), "000;204".into())).is_err());
        assert!(require_204("socks5h", (Some(0), String::new(), "200;204".into())).is_err());
        assert!(require_204("http", (Some(0), String::new(), "200;407".into())).is_err());
        assert!(require_204("invalid", (Some(0), String::new(), "200;204".into())).is_err());
    }

    #[test]
    fn negative_remote_dns_does_not_infer_nxdomain_from_transport_timeout() {
        assert!(remote_nxdomain_has_no_successful_origin(
            "socks5h",
            &(Some(97), String::new(), "000;000".into())
        ));
        for candidate in [
            (Some(0), String::new(), "200;200".into()),
            (Some(28), String::new(), "000;000".into()),
            (Some(97), "origin response".into(), "000;000".into()),
            (Some(97), String::new(), "200;000".into()),
        ] {
            assert!(!remote_nxdomain_has_no_successful_origin("socks5h", &candidate));
        }
        assert!(!remote_nxdomain_has_no_successful_origin(
            "http",
            &(Some(97), String::new(), "000;000".into())
        ));
    }
}
