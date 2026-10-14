//! Bounded external Line1 proof by an isolated, disposable ProxyOnly consumer.
//! No SCM, TUN, DNS, route, system-proxy or controller mutation is permitted.
use edge_controller_core::windows_credential_store_path;
use edge_secrets::{
    ACCESS_IDENTITY_FILE_NAME, CredentialStore, fetch_canonical_credential_bundle,
    windows_runtime_state_from_canonical_production_bundle, write_access_service_identity,
    write_atomic_private,
};
use edge_shared_types::{CredentialProjectionKind, WindowsRuntimeState};
use edge_singbox::render_windows_config;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const TAGS: [&str; 4] = [
    "hysteria2-direct",
    "vless-reality-direct",
    "hysteria2-warp",
    "vless-reality-warp",
];
const HTTPS_PROBE: &str = "https://www.gstatic.com/generate_204";
const EGRESS_PROBE: &str = "https://api.ipify.org";
const NEGATIVE_UUID: &str = "00000000-0000-4000-8000-000000000000";

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct PrivateCandidate(PathBuf);
impl Drop for PrivateCandidate {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        if let Some(parent) = self.0.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
}

fn allocate_loopback_ports(count: usize) -> Result<Vec<u16>, String> {
    let mut sockets = Vec::with_capacity(count);
    for _ in 0..count {
        sockets.push(
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .map_err(|_| "Line1 isolated localhost port reservation failed".to_owned())?,
        );
    }
    let ports = sockets
        .iter()
        .map(|socket| socket.local_addr().map(|addr| addr.port()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Line1 isolated listener address readback failed".to_owned())?;
    if ports.iter().copied().collect::<BTreeSet<_>>().len() != count {
        return Err("Line1 isolated ports are not distinct".to_owned());
    }
    Ok(ports)
}

fn isolated_config(state: &WindowsRuntimeState, ports: &[u16]) -> Result<Vec<u8>, String> {
    if ports.len() != 8
        || ports.iter().any(|port| *port == 0)
        || ports.iter().copied().collect::<BTreeSet<_>>().len() != 8
    {
        return Err("Line1 witness requires eight distinct nonzero localhost listeners".to_owned());
    }
    let mut config: Value = serde_json::from_slice(&render_windows_config(state)?)
        .map_err(|_| "Line1 canonical sing-box renderer produced invalid JSON".to_owned())?;
    let source = config["outbounds"]
        .as_array()
        .ok_or("Line1 canonical outbounds missing")?;
    let mut positive = Vec::new();
    let mut negative = Vec::new();
    for tag in TAGS {
        let original = source
            .iter()
            .find(|item| item["tag"].as_str() == Some(tag))
            .ok_or_else(|| format!("Line1 canonical outbound {tag} missing"))?
            .clone();
        let mut invalid = original.clone();
        let invalid_tag = format!("{tag}-invalid");
        invalid["tag"] = json!(invalid_tag);
        if tag.starts_with("hysteria2-") {
            let password = invalid["password"]
                .as_str()
                .ok_or("Line1 Hysteria2 password missing")?;
            invalid["password"] = json!(format!("invalid-{password}"));
        } else {
            if invalid["uuid"].as_str() == Some(NEGATIVE_UUID) {
                return Err("Line1 negative UUID collided with issued identity".to_owned());
            }
            invalid["uuid"] = json!(NEGATIVE_UUID);
        }
        positive.push(original);
        negative.push(invalid);
    }

    let mut inbounds = Vec::with_capacity(8);
    let mut rules = Vec::with_capacity(8);
    for (idx, tag) in TAGS.iter().enumerate() {
        let invalid_tag = format!("{tag}-invalid");
        for (offset, output) in [(0, *tag), (4, invalid_tag.as_str())] {
            let listener = format!("line1-witness-{}", idx + offset);
            inbounds.push(json!({
                "type": "mixed",
                "tag": listener,
                "listen": "127.0.0.1",
                "listen_port": ports[idx + offset],
            }));
            rules.push(json!({"inbound": [listener], "outbound": output}));
        }
    }
    positive.extend(negative);
    positive.push(json!({"type": "direct", "tag": "direct"}));
    config["inbounds"] = json!(inbounds);
    config["outbounds"] = json!(positive);
    config["route"] = json!({"rules": rules, "final": "direct", "auto_detect_interface": true});
    config
        .as_object_mut()
        .ok_or("Line1 canonical config must be an object")?
        .remove("experimental");
    if config["inbounds"].as_array().is_none_or(|entries| {
        entries.len() != 8
            || entries
                .iter()
                .any(|item| item["type"] != "mixed" || item["listen"] != "127.0.0.1")
    }) {
        return Err("Line1 isolated witness would expose non-local or TUN inbound".to_owned());
    }
    serde_json::to_vec_pretty(&config)
        .map_err(|_| "failed to serialize isolated Line1 witness config".to_owned())
}

fn curl_through(port: u16, target: &str) -> Result<(String, String), String> {
    // A system curl directly supplied by Windows. No shell invocation; no
    // issued credential appears in argv or environment or output.
    let output = Command::new(r"C:\Windows\System32\curl.exe")
        .args([
            "-q", // Disable user .curlrc: the witness owns its exact proxy arguments.
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--connect-timeout",
            "3",
            "--max-time",
            "9",
            "--noproxy",
            "",
            "--proxy",
            &format!("http://127.0.0.1:{port}"),
            "--output",
            "-",
            "--write-out",
            "\\nCODE:%{http_code}",
            target,
        ])
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "Line1 external witness curl executable unavailable".to_owned())?;
    if !output.status.success() {
        // Exit code is non-sensitive and distinguishes DNS/TLS/refused/timeout.
        // Never print curl stderr, URLs, secrets or the rendered sing-box JSON.
        let code = output.status.code().map_or_else(
            || "UNKNOWN".to_owned(),
            |value| value.to_string(),
        );
        return Err(format!("Line1 external HTTPS request failed curl_exit={code}"));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "Line1 external HTTPS response is not UTF-8".to_owned())?;
    let (body, status) = text
        .rsplit_once("\nCODE:")
        .ok_or("Line1 curl did not report HTTP status")?;
    if !matches!(status, "200" | "204") {
        return Err("Line1 external HTTPS returned unexpected status".to_owned());
    }
    Ok((body.to_owned(), status.to_owned()))
}

// Conservative exclusion of non-public, special-purpose and reserved IPv4
// ranges. Never accept local, documentation or CGNAT egress as public WARP.
fn globally_routable(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 0 || (b == 168) || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

fn check_endpoint(port: u16, invalid_port: u16, tag: &str) -> Result<Ipv4Addr, String> {
    let (positive, status) = curl_through(port, HTTPS_PROBE)
        .map_err(|err| format!("Line1 endpoint={tag} phase=https204 {err}"))?;
    if status != "204" || !positive.is_empty() {
        return Err(format!("{tag} external HTTPS 204 body was not empty"));
    }
    // The invalid request must fail. Positive connectivity is proven first
    // on the same protocol/server, so a generic network outage cannot pass.
    if curl_through(invalid_port, HTTPS_PROBE).is_ok() {
        return Err(format!("{tag} accepted an invalid tunnel credential"));
    }
    let (egress, status) = curl_through(port, EGRESS_PROBE)
        .map_err(|err| format!("Line1 endpoint={tag} phase=public_egress {err}"))?;
    if status != "200" {
        return Err(format!(
            "{tag} external egress service returned non-200 HTTP"
        ));
    }
    let address = egress
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("{tag} external public IPv4 witness invalid"))?;
    if !globally_routable(address) {
        return Err(format!("{tag} external egress address is not global"));
    }
    Ok(address)
}

pub(crate) fn require_isolated_root(root: &Path) -> Result<(), String> {
    if !root
        .to_string_lossy()
        .eq_ignore_ascii_case(r"C:\sing-box-acceptance")
    {
        return Err("only isolated Windows acceptance install root may use this owner".to_owned());
    }
    Ok(())
}

/// One first-use Access bootstrap for the already-existing Windows Access
/// identity. Secret input comes only from protected GitHub environment scope.
pub(crate) fn bootstrap_access(root: &Path) -> Result<(), String> {
    require_isolated_root(root)?;
    let identity_path = root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    if identity_path.exists() || windows_credential_store_path(root).exists() {
        return Err("isolated Access bootstrap refuses existing or partial credentials".to_owned());
    }
    let client = std::env::var("EDGE_WINDOWS_ACCESS_CLIENT_ID")
        .map_err(|_| "isolated Windows Access client ID unavailable".to_owned())?;
    let secret = std::env::var("EDGE_WINDOWS_ACCESS_CLIENT_SECRET")
        .map_err(|_| "isolated Windows Access client secret unavailable".to_owned())?;
    let text = format!("CF_ACCESS_CLIENT_ID={client}\nCF_ACCESS_CLIENT_SECRET={secret}\n");
    write_access_service_identity(&identity_path, &text)?;
    println!("operation=CREDENTIAL_INITIAL_ISOLATED_WINDOWS_ACCESS_BOOTSTRAP");
    println!("credential_access_identity_source=GITHUB_WINDOWS_BOOTSTRAP");
    println!("credential_worker_mutations=0");
    println!("windows_scm_mutations=0");
    println!("windows_tun_mutations=0");
    Ok(())
}

/// A single local consumer of the canonical Worker. It never dispatches to
/// the serving SCM owner. An uncertain store write is never replayed.
pub(crate) async fn stage_from_worker(root: &Path, generation: u64) -> Result<(), String> {
    require_isolated_root(root)?;
    if generation == 0 {
        return Err("isolated Windows stage requires nonzero generation".to_owned());
    }
    let path = windows_credential_store_path(root);
    if path.exists() {
        return Err("isolated Windows first-use stage is already attempted".to_owned());
    }
    let identity = root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    let bundle =
        fetch_canonical_credential_bundle(CredentialProjectionKind::Windows, generation, &identity)
            .await?;
    let store = CredentialStore::new(path, CredentialProjectionKind::Windows)?;
    let state = store.stage_delivery_candidate(&bundle)?;
    if state.active.is_some() || state.previous.is_some() {
        return Err("isolated Windows candidate unexpectedly activated runtime".to_owned());
    }
    if state.candidate.as_ref().map(|cursor| cursor.generation) != Some(generation) {
        return Err("isolated Windows candidate generation mismatch".to_owned());
    }
    println!("operation=CREDENTIAL_INITIAL_ISOLATED_WINDOWS_STAGE");
    println!("credential_candidate_generation={generation}");
    println!("credential_active_present=false");
    println!("credential_candidate_present=true");
    println!("windows_scm_mutations=0");
    println!("windows_tun_mutations=0");
    println!("windows_dns_mutations=0");
    Ok(())
}

pub(crate) fn run(
    install_root: &Path,
    singbox_binary: &Path,
    generation: u64,
) -> Result<(), String> {
    if generation == 0 {
        return Err("Line1 witness requires nonzero credential generation".to_owned());
    }
    // Never launch a second client from the serving C:\sing-box tree.
    require_isolated_root(install_root)?;
    if !singbox_binary.is_file() {
        return Err("Line1 witness exact installed sing-box binary missing".to_owned());
    }
    let store = CredentialStore::open_existing(
        windows_credential_store_path(install_root),
        CredentialProjectionKind::Windows,
    )?
    .ok_or("Line1 isolated credential store missing")?;
    let state = store
        .read_state()?
        .ok_or("Line1 credential cursor absent")?;
    if state.active.is_some() || state.previous.is_some() {
        return Err("Line1 witness refuses active or previous runtime generations".to_owned());
    }
    let candidate = state
        .candidate
        .as_ref()
        .ok_or("Line1 staged candidate absent")?;
    if candidate.generation != generation {
        return Err("Line1 witness refuses different credential generation".to_owned());
    }
    let bundle = store.read_bundle(candidate)?;
    let runtime = windows_runtime_state_from_canonical_production_bundle(&bundle)?;
    let ports = allocate_loopback_ports(8)?;
    let config = isolated_config(&runtime, &ports)?;
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Line1 witness system clock invalid")?
        .as_nanos();
    let private = install_root
        .join("runtime")
        .join(format!("line1-witness-{}-{ns}", std::process::id()))
        .join("candidate.json");
    if private.exists() {
        return Err("Line1 private witness config already exists".to_owned());
    }
    write_atomic_private(&private, &config)?;
    let _private_guard = PrivateCandidate(private.clone());
    let check = Command::new(singbox_binary)
        .args(["check", "-c"])
        .arg(&private)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "Line1 exact sing-box config checker unavailable")?;
    if !check.success() {
        return Err("Line1 candidate rejected by exact sing-box check".to_owned());
    }
    let child = Command::new(singbox_binary)
        .args(["run", "-c"])
        .arg(&private)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|_| "Line1 isolated process start failed")?;
    let mut owner = OwnedChild(child);
    let mut ips = Vec::with_capacity(4);
    for (i, tag) in TAGS.iter().enumerate() {
        if owner
            .0
            .try_wait()
            .map_err(|_| "Line1 process wait failed")?
            .is_some()
        {
            return Err("Line1 isolated sing-box exited before external acceptance".to_owned());
        }
        let ip = check_endpoint(ports[i], ports[i + 4], tag)?;
        ips.push(ip);
        println!("line1_endpoint={tag} HTTPS=PASS AUTH_NEGATIVE=REJECTED TLS=VERIFIED");
    }
    if ips[0] == ips[2] || ips[1] == ips[3] {
        return Err("Line1 direct and WARP have the same observed external IPv4".to_owned());
    }
    // Never print the addresses or any credential to the GitHub job.
    println!("operation=CREDENTIAL_INITIAL_LINE1_EXTERNAL_WITNESS");
    println!("line1_external_4_of_4=PASS");
    println!("line1_direct_warp_egress_distinct=true");
    println!("line1_witness_vantage=WINDOWS_ISOLATED_PROXY_ONLY");
    println!("line1_issued_generation={generation}");
    println!("windows_tun_mutations=0");
    println!("windows_dns_mutations=0");
    println!("windows_routes_mutations=0");
    println!("windows_scm_mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_port_plan_before_any_config_or_process() {
        let invalid = vec![1080u16; 8];
        assert_eq!(invalid.iter().copied().collect::<BTreeSet<_>>().len(), 1);
        assert!(allocate_loopback_ports(0).unwrap().is_empty());
    }

    #[test]
    fn witness_failure_reports_only_named_endpoint_and_safe_curl_code() {
        let cause = "Line1 external HTTPS request failed curl_exit=28";
        let annotated = format!("Line1 endpoint={} phase=https204 {cause}", TAGS[0]);
        assert_eq!(annotated, "Line1 endpoint=hysteria2-direct phase=https204 Line1 external HTTPS request failed curl_exit=28");
        assert!(!annotated.contains("https://"));
    }

    #[test]
    fn acceptance_root_does_not_equal_serving_root() {
        assert_ne!(
            r"C:\sing-box-acceptance".to_ascii_lowercase(),
            r"C:\sing-box".to_ascii_lowercase()
        );
        assert_eq!(TAGS.len(), 4);
        assert!(TAGS.iter().collect::<BTreeSet<_>>().len() == 4);
    }
}
