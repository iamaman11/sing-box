//! One-shot VM-vantage authenticated Line 2 probe; no new listener, state or credential export.
use std::collections::BTreeMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

const CURL_PATH: &str = "/usr/bin/curl";
const TARGET: &str = "https://www.gstatic.com/generate_204";
const SAMPLES: usize = 5;
const MAX_MS: u64 = 7000;
const PROXY_PORTS: [(&str, &str, u16); 6] = [
    ("http-direct", "http", 4128),
    ("socks5-direct", "socks5h", 4080),
    ("https-direct", "https", 4443),
    ("http-warp", "http", 3128),
    ("socks5-warp", "socks5h", 1080),
    ("https-warp", "https", 9443),
];

fn curl_config_quote(value: &str) -> Result<String, String> {
    if value.is_empty() || value.chars().any(|c| c.is_control()) {
        return Err("Line2 proxy identity contains unsupported characters".to_owned());
    }
    // curl config double-quoted value: backslash and quotes must be escaped.
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn proxy_target(protocol: &str, port: u16, domain: &str) -> String {
    if protocol == "https" {
        format!("https://{domain}:{port}")
    } else {
        format!("{protocol}://127.0.0.1:{port}")
    }
}

fn parse_probe_result(text: &str) -> Option<u64> {
    let raw = text.trim();
    let (code, seconds) = raw.split_once(';')?;
    if code != "204" {
        return None;
    }
    let seconds: f64 = seconds.parse().ok()?;
    if !seconds.is_finite() || seconds <= 0.0 || seconds > (MAX_MS as f64 / 1000.0) {
        return None;
    }
    Some((seconds * 1000.0).ceil() as u64)
}

fn summarize(samples: &[u64]) -> Option<(u64, u64, u64)> {
    if samples.is_empty() {
        return None;
    }
    let mut values = samples.to_vec();
    values.sort_unstable();
    let half = values.len() / 2;
    let median = if values.len() % 2 == 0 {
        (values[half - 1] + values[half]) / 2
    } else {
        values[half]
    };
    Some((values[0], median, values[values.len() - 1]))
}

fn one_sample(
    proxy: &str,
    local_resolution: Option<&str>,
    credentials: &str,
) -> Option<u64> {
    let mut command = Command::new(CURL_PATH);
    command.args([
        "-q",
        "--config", "-",
        "--silent",
        "--fail",
        "--proto", "=https",
        "--connect-timeout", "3",
        "--max-time", "7",
        "--noproxy", "",
        "--output", "/dev/null",
        "--write-out", "%{http_code};%{time_total}",
        "--proxy", proxy,
    ]);
    if let Some(resolve) = local_resolution {
        command.args(["--resolve", resolve]);
    }
    command.arg(TARGET);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let input = format!("proxy-user = \"{credentials}\"\n");
    // Credentials never appear in argv, environment or stdout. curl stderr is suppressed.
    let wrote = child
        .stdin
        .take()
        .and_then(|mut stdin| stdin.write_all(input.as_bytes()).ok());
    let result = child.wait_with_output().ok()?;
    if wrote.is_none() || !result.status.success() {
        return None;
    }
    parse_probe_result(std::str::from_utf8(&result.stdout).ok()?)
}

pub(crate) fn measure(
    stack_dir: &Path,
    read_environment: impl FnOnce(&Path) -> Result<BTreeMap<String, String>, String>,
) -> Result<(), String> {
    let values = read_environment(stack_dir)?;
    let user = values.get("PROXY_USERNAME").ok_or("Line2 VM policy is missing proxy user")?;
    let password = values
        .get("PROXY_PASSWORD")
        .ok_or("Line2 VM credential projection is missing proxy password")?;
    let domain = values
        .get("TUNNEL_DOMAIN")
        .or_else(|| values.get("PROXY_CERT_CN"))
        .ok_or("Line2 VM policy is missing TLS proxy certificate hostname")?;
    // Hostname is validated by the existing runtime policy, not taken from the caller.
    if domain.is_empty()
        || !domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || domain.parse::<Ipv4Addr>().is_ok()
    {
        return Err("Line2 certificate hostname is invalid".to_owned());
    }
    let auth = curl_config_quote(&format!("{user}:{password}"))?;
    if !Path::new(CURL_PATH).is_file() {
        return Err("Line2 fixed system curl executable is unavailable".to_owned());
    }

    println!("quality_schema=line2-vm-auth-delay/v1");
    println!("vantage=VM_LOCALHOST");
    println!("target=HTTPS_204");
    println!("credential_source=VM_RUNTIME_PROJECTION");
    println!("sample_budget_per_proxy={SAMPLES}");
    println!("runtime_mutations=0");
    let mut failures = 0;
    for (tag, protocol, port) in PROXY_PORTS {
        let proxy = proxy_target(protocol, port, domain);
        let resolution = if protocol == "https" {
            Some(format!("{domain}:{port}:127.0.0.1"))
        } else {
            None
        };
        let mut samples = Vec::with_capacity(SAMPLES);
        let mut errors = 0;
        for _ in 0..SAMPLES {
            match one_sample(&proxy, resolution.as_deref(), &auth) {
                Some(delay) => samples.push(delay),
                None => errors += 1,
            }
        }
        failures += errors;
        let (min, median, max) = summarize(&samples)
            .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
            .unwrap_or_else(|| ("UNAVAILABLE".to_owned(), "UNAVAILABLE".to_owned(), "UNAVAILABLE".to_owned()));
        println!(
            "proxy={tag} protocol={protocol} port={port} successes={} failures={errors} min_ms={min} median_ms={median} max_ms={max}",
            samples.len()
        );
    }
    if failures > 0 {
        println!("quality_status=FAIL");
        return Err(format!("Line2 VM authenticated proxy checks failed: {failures} of {}", PROXY_PORTS.len() * SAMPLES));
    }
    println!("quality_status=PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_distinct_fixed_local_proxy_endpoints() {
        let mut ports = std::collections::BTreeSet::new();
        assert_eq!(PROXY_PORTS.len(), 6);
        for (_, _, port) in PROXY_PORTS {
            assert!(ports.insert(port));
        }
        assert_eq!(proxy_target("http", 4128, "edge.example.com"), "http://127.0.0.1:4128");
        assert_eq!(proxy_target("socks5h", 1080, "edge.example.com"), "socks5h://127.0.0.1:1080");
        assert_eq!(proxy_target("https", 9443, "edge.example.com"), "https://edge.example.com:9443");
    }

    #[test]
    fn secret_in_stdin_config_is_quoted_and_never_on_command_line() {
        assert_eq!(curl_config_quote("u:abc\\\"def").unwrap(), "u:abc\\\\\\\"def");
        assert!(curl_config_quote("u:with\nline").is_err());
    }

    #[test]
    fn only_real_successful_204_sample_is_accepted() {
        assert_eq!(parse_probe_result("204;0.055400"), Some(56));
        assert_eq!(parse_probe_result("407;0.055400"), None);
        assert_eq!(parse_probe_result("200;0.055400"), None);
        assert_eq!(parse_probe_result("204;nan"), None);
        assert_eq!(parse_probe_result("204;8.999999"), None);
        assert_eq!(summarize(&[91, 55, 76, 61, 71]), Some((55, 71, 91)));
        assert_eq!(summarize(&[]), None);
    }
}
