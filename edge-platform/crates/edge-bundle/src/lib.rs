use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use edge_trust::{
    AgentTlsIdentity, WrittenAgentTlsMaterial, issue_agent_tls_material, write_agent_tls_material,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

const TEMPLATE_STACK_PATH: &str = "win/vultr-waw/stack";
const GENERATED_ROOT_PATH: &str = "edge-platform/.runtime/generated";
const DEFAULT_LABEL_PREFIX: &str = "waw-edge";
const DEFAULT_PLAN: &str = "vc2-1c-1gb";
const DEFAULT_REGION: &str = "waw";
const REALITY_SERVER_NAME: &str = "www.microsoft.com";
const SERVER_TLS_ROOT: &str = "/opt/vultr-edge-stack/tls";

#[derive(Debug, Clone)]
pub struct BundleFilePayload {
    pub relative_path: String,
    pub content: Vec<u8>,
    pub executable: bool,
}

#[derive(Debug, Clone)]
pub struct BuildBundleRequest<'a> {
    pub repo_root: &'a Path,
    pub target_ip: &'a str,
    pub instance_id: &'a str,
    pub tunnel_domain: Option<&'a str>,
    pub acme_email: Option<&'a str>,
    pub cloudflare_zone_name: Option<&'a str>,
    pub dns_record_name: Option<&'a str>,
    pub label_prefix: Option<&'a str>,
    pub deployment_label: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct PreparedDeploymentBundle {
    pub label: String,
    pub generated_dir: PathBuf,
    pub local_stack_dir: PathBuf,
    pub stack_files: Vec<BundleFilePayload>,
    pub host_files: Vec<BundleFilePayload>,
    pub deployment_summary_json: String,
    pub current_state_json: String,
    pub agent_env_content: String,
    pub local_trust_material: WrittenAgentTlsMaterial,
    pub deployment: DeploymentStateDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentStateDocument {
    pub label: String,
    pub instance_id: String,
    pub ip: String,
    pub plan: String,
    pub region: String,
    pub proxy: ProxyDocument,
    pub warp_proxy: ProxyDocument,
    pub direct_proxy: ProxyDocument,
    pub tunnel: TunnelDocument,
    pub tunnel_warp: TunnelDocument,
    pub dns: DnsDocument,
    pub paths: PathsDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDocument {
    pub host: String,
    pub http_port: u32,
    pub socks5_port: u32,
    pub https_port: u32,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelDocument {
    pub enabled: bool,
    pub domain: String,
    pub vless_port: u32,
    pub hy2_port: u32,
    pub vless_uuid: String,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub hy2_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsDocument {
    pub zone: String,
    pub zone_id: String,
    pub record: String,
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsDocument {
    pub local_stack: String,
    pub private_key: String,
    pub scoped_private_key: String,
    pub known_hosts: String,
}

#[derive(Debug, Default, Deserialize)]
struct ExistingStateDocument {
    label: Option<String>,
}

pub fn build_bundle(request: &BuildBundleRequest<'_>) -> Result<PreparedDeploymentBundle, String> {
    let label = request
        .deployment_label
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| generate_deployment_label(request.label_prefix));
    let generated_dir = request
        .repo_root
        .join(GENERATED_ROOT_PATH)
        .join(label.as_str());
    let local_stack_dir = generated_dir.join("stack");
    fs::create_dir_all(&local_stack_dir)
        .map_err(|err| format!("failed to create {}: {err}", local_stack_dir.display()))?;

    let template_stack_dir = request.repo_root.join(TEMPLATE_STACK_PATH);
    if !template_stack_dir.is_dir() {
        return Err(format!(
            "stack template directory is missing: {}",
            template_stack_dir.display()
        ));
    }

    let existing_env = load_existing_runtime_env(request.repo_root)?;
    let proxy_cert_cn = request.tunnel_domain.unwrap_or("proxy.local").to_owned();
    let tunnel_enabled = request
        .tunnel_domain
        .is_some_and(|value| !value.trim().is_empty())
        && request
            .acme_email
            .is_some_and(|value| !value.trim().is_empty());

    let reality_direct =
        read_or_generate_reality_pair(&existing_env, "REALITY_PRIVATE_KEY", "REALITY_PUBLIC_KEY")?;
    let reality_warp = read_or_generate_reality_pair(
        &existing_env,
        "REALITY_WARP_PRIVATE_KEY",
        "REALITY_WARP_PUBLIC_KEY",
    )?;

    let env_values = RuntimeEnvValues {
        proxy_username: "v_user".to_owned(),
        proxy_password: existing_or_random(&existing_env, "PROXY_PASSWORD", 24)?,
        proxy_cert_cn,
        vless_uuid: existing_or_uuid(&existing_env, "VLESS_UUID")?,
        hy2_password: existing_or_random(&existing_env, "HY2_PASSWORD", 24)?,
        reality_private_key: reality_direct.0,
        reality_public_key: reality_direct.1.clone(),
        reality_short_id: existing_or_hex(&existing_env, "REALITY_SHORT_ID", 8)?,
        vless_warp_uuid: existing_or_uuid(&existing_env, "VLESS_WARP_UUID")?,
        hy2_warp_password: existing_or_random(&existing_env, "HY2_WARP_PASSWORD", 24)?,
        reality_warp_private_key: reality_warp.0,
        reality_warp_public_key: reality_warp.1.clone(),
        reality_warp_short_id: existing_or_hex(&existing_env, "REALITY_WARP_SHORT_ID", 8)?,
        reality_server_name: REALITY_SERVER_NAME.to_owned(),
        tunnel_domain: request.tunnel_domain.unwrap_or_default().to_owned(),
        acme_email: request.acme_email.unwrap_or_default().to_owned(),
    };
    let env_runtime_content = render_runtime_env(&env_values);

    let tls_material = issue_agent_tls_material(&AgentTlsIdentity {
        deployment_id: label.clone(),
        instance_id: request.instance_id.to_owned(),
        server_ip: request.target_ip.to_owned(),
        domain_name: "edge-agent".to_owned(),
    })?;
    let local_trust_dir = generated_dir.join("trust");
    let local_trust_material = write_agent_tls_material(&local_trust_dir, &tls_material)?;

    let deployment = DeploymentStateDocument {
        label: label.clone(),
        instance_id: request.instance_id.to_owned(),
        ip: request.target_ip.to_owned(),
        plan: DEFAULT_PLAN.to_owned(),
        region: DEFAULT_REGION.to_owned(),
        proxy: ProxyDocument {
            host: request.target_ip.to_owned(),
            http_port: 3128,
            socks5_port: 1080,
            https_port: 9443,
            username: env_values.proxy_username.clone(),
            password: env_values.proxy_password.clone(),
        },
        warp_proxy: ProxyDocument {
            host: request.target_ip.to_owned(),
            http_port: 3128,
            socks5_port: 1080,
            https_port: 9443,
            username: env_values.proxy_username.clone(),
            password: env_values.proxy_password.clone(),
        },
        direct_proxy: ProxyDocument {
            host: request.target_ip.to_owned(),
            http_port: 4128,
            socks5_port: 4080,
            https_port: 4443,
            username: env_values.proxy_username.clone(),
            password: env_values.proxy_password.clone(),
        },
        tunnel: TunnelDocument {
            enabled: tunnel_enabled,
            domain: request.tunnel_domain.unwrap_or_default().to_owned(),
            vless_port: 443,
            hy2_port: 8443,
            vless_uuid: env_values.vless_uuid.clone(),
            reality_public_key: reality_direct.1,
            reality_short_id: env_values.reality_short_id.clone(),
            hy2_password: env_values.hy2_password.clone(),
        },
        tunnel_warp: TunnelDocument {
            enabled: tunnel_enabled,
            domain: request.tunnel_domain.unwrap_or_default().to_owned(),
            vless_port: 5443,
            hy2_port: 9444,
            vless_uuid: env_values.vless_warp_uuid.clone(),
            reality_public_key: reality_warp.1,
            reality_short_id: env_values.reality_warp_short_id.clone(),
            hy2_password: env_values.hy2_warp_password.clone(),
        },
        dns: DnsDocument {
            zone: request.cloudflare_zone_name.unwrap_or_default().to_owned(),
            zone_id: String::new(),
            record: request.dns_record_name.unwrap_or_default().to_owned(),
            ip: request.target_ip.to_owned(),
        },
        paths: PathsDocument {
            local_stack: local_stack_dir.display().to_string(),
            private_key: String::new(),
            scoped_private_key: String::new(),
            known_hosts: String::new(),
        },
    };

    let deployment_summary_json = serde_json::to_string_pretty(&deployment)
        .map_err(|err| format!("failed to encode deployment summary JSON: {err}"))?;
    let current_state_json = deployment_summary_json.clone();

    let mut stack_files = collect_template_stack_files(&template_stack_dir)?;
    stack_files.push(BundleFilePayload {
        relative_path: ".env.runtime".to_owned(),
        content: env_runtime_content.as_bytes().to_vec(),
        executable: false,
    });
    write_bundle_files(&local_stack_dir, &stack_files)?;

    let host_files = vec![
        BundleFilePayload {
            relative_path: "tls/ca.pem".to_owned(),
            content: tls_material.ca_cert_pem.as_bytes().to_vec(),
            executable: false,
        },
        BundleFilePayload {
            relative_path: "tls/agent-server.pem".to_owned(),
            content: tls_material.server_cert_pem.as_bytes().to_vec(),
            executable: false,
        },
        BundleFilePayload {
            relative_path: "tls/agent-server.key".to_owned(),
            content: tls_material.server_key_pem.as_bytes().to_vec(),
            executable: false,
        },
    ];
    write_host_files(&generated_dir, &host_files)?;

    let summary_path = generated_dir.join("deployment-summary.json");
    fs::write(&summary_path, deployment_summary_json.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", summary_path.display()))?;

    Ok(PreparedDeploymentBundle {
        label,
        generated_dir,
        local_stack_dir,
        stack_files,
        host_files,
        deployment_summary_json,
        current_state_json,
        agent_env_content: render_agent_env(),
        local_trust_material,
        deployment,
    })
}

fn collect_template_stack_files(
    template_stack_dir: &Path,
) -> Result<Vec<BundleFilePayload>, String> {
    let mut files = Vec::new();
    collect_dir_recursive(template_stack_dir, template_stack_dir, &mut files)?;
    Ok(files)
}

fn collect_dir_recursive(
    root: &Path,
    current: &Path,
    files: &mut Vec<BundleFilePayload>,
) -> Result<(), String> {
    for entry in fs::read_dir(current)
        .map_err(|err| format!("failed to read {}: {err}", current.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to iterate directory entry: {err}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("failed to read file type for {}: {err}", path.display()))?;
        if file_type.is_dir() {
            collect_dir_recursive(root, &path, files)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let relative_path = path
            .strip_prefix(root)
            .map_err(|err| format!("failed to strip prefix from {}: {err}", path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let executable = relative_path == "bootstrap.sh";
        let content =
            fs::read(&path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        files.push(BundleFilePayload {
            relative_path,
            content,
            executable,
        });
    }
    Ok(())
}

fn write_bundle_files(root: &Path, files: &[BundleFilePayload]) -> Result<(), String> {
    for file in files {
        let path = root.join(&file.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        fs::write(&path, &file.content)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    }
    Ok(())
}

fn write_host_files(root: &Path, files: &[BundleFilePayload]) -> Result<(), String> {
    for file in files {
        let path = root.join(&file.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        fs::write(&path, &file.content)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    }
    Ok(())
}

fn load_existing_runtime_env(repo_root: &Path) -> Result<BTreeMap<String, String>, String> {
    let state_path = repo_root.join("win/vultr-waw/current-edge.json");
    if !state_path.is_file() {
        return Ok(BTreeMap::new());
    }

    let raw = fs::read_to_string(&state_path)
        .map_err(|err| format!("failed to read {}: {err}", state_path.display()))?;
    let state: ExistingStateDocument = serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {}: {err}", state_path.display()))?;
    let Some(label) = state.label else {
        return Ok(BTreeMap::new());
    };

    let env_path = repo_root
        .join("win/vultr-waw/generated")
        .join(label)
        .join("stack")
        .join(".env.runtime");
    if !env_path.is_file() {
        return Ok(BTreeMap::new());
    }
    let raw_env = fs::read_to_string(&env_path)
        .map_err(|err| format!("failed to read {}: {err}", env_path.display()))?;
    Ok(parse_env(&raw_env))
}

fn parse_env(raw: &str) -> BTreeMap<String, String> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (key, value) = trimmed.split_once('=')?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn render_runtime_env(values: &RuntimeEnvValues) -> String {
    [
        ("PROXY_USERNAME", values.proxy_username.as_str()),
        ("PROXY_PASSWORD", values.proxy_password.as_str()),
        ("PROXY_CERT_CN", values.proxy_cert_cn.as_str()),
        ("VLESS_UUID", values.vless_uuid.as_str()),
        ("HY2_PASSWORD", values.hy2_password.as_str()),
        ("REALITY_PRIVATE_KEY", values.reality_private_key.as_str()),
        ("REALITY_PUBLIC_KEY", values.reality_public_key.as_str()),
        ("REALITY_SHORT_ID", values.reality_short_id.as_str()),
        ("VLESS_WARP_UUID", values.vless_warp_uuid.as_str()),
        ("HY2_WARP_PASSWORD", values.hy2_warp_password.as_str()),
        (
            "REALITY_WARP_PRIVATE_KEY",
            values.reality_warp_private_key.as_str(),
        ),
        (
            "REALITY_WARP_PUBLIC_KEY",
            values.reality_warp_public_key.as_str(),
        ),
        (
            "REALITY_WARP_SHORT_ID",
            values.reality_warp_short_id.as_str(),
        ),
        ("REALITY_SERVER_NAME", values.reality_server_name.as_str()),
        ("TUNNEL_DOMAIN", values.tunnel_domain.as_str()),
        ("ACME_EMAIL", values.acme_email.as_str()),
    ]
    .into_iter()
    .map(|(key, value)| format!("{key}={value}\n"))
    .collect()
}

fn render_agent_env() -> String {
    format!(
        "EDGE_AGENT_TLS_SERVER_CERT_PATH={SERVER_TLS_ROOT}/agent-server.pem\nEDGE_AGENT_TLS_SERVER_KEY_PATH={SERVER_TLS_ROOT}/agent-server.key\nEDGE_AGENT_TLS_CA_CERT_PATH={SERVER_TLS_ROOT}/ca.pem\n"
    )
}

fn existing_or_random(
    env: &BTreeMap<String, String>,
    key: &str,
    bytes: usize,
) -> Result<String, String> {
    if let Some(value) = env.get(key).filter(|value| !value.trim().is_empty()) {
        return Ok(value.clone());
    }
    random_base64url(bytes)
}

fn existing_or_hex(
    env: &BTreeMap<String, String>,
    key: &str,
    bytes: usize,
) -> Result<String, String> {
    if let Some(value) = env.get(key).filter(|value| !value.trim().is_empty()) {
        return Ok(value.clone());
    }
    random_hex(bytes)
}

fn existing_or_uuid(env: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    if let Some(value) = env.get(key).filter(|value| !value.trim().is_empty()) {
        return Ok(value.clone());
    }
    generate_uuid_v4()
}

fn read_or_generate_reality_pair(
    env: &BTreeMap<String, String>,
    private_key: &str,
    public_key: &str,
) -> Result<(String, String), String> {
    if let (Some(private), Some(public)) = (
        env.get(private_key)
            .filter(|value| !value.trim().is_empty()),
        env.get(public_key).filter(|value| !value.trim().is_empty()),
    ) {
        return Ok((private.clone(), public.clone()));
    }

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Ok((
        URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        URL_SAFE_NO_PAD.encode(public.to_bytes()),
    ))
}

fn random_base64url(bytes: usize) -> Result<String, String> {
    let mut buffer = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut buffer = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    Ok(buffer
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn generate_uuid_v4() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}

pub fn generate_deployment_label(prefix: Option<&str>) -> String {
    let prefix = prefix.unwrap_or(DEFAULT_LABEL_PREFIX);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{prefix}-{timestamp}")
}

#[derive(Debug, Clone)]
struct RuntimeEnvValues {
    proxy_username: String,
    proxy_password: String,
    proxy_cert_cn: String,
    vless_uuid: String,
    hy2_password: String,
    reality_private_key: String,
    reality_public_key: String,
    reality_short_id: String,
    vless_warp_uuid: String,
    hy2_warp_password: String,
    reality_warp_private_key: String,
    reality_warp_public_key: String,
    reality_warp_short_id: String,
    reality_server_name: String,
    tunnel_domain: String,
    acme_email: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_bundle_from_template_stack() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let request = BuildBundleRequest {
            repo_root: &repo_root,
            target_ip: "203.0.113.20",
            instance_id: "instance-1",
            tunnel_domain: Some("edge.example.com"),
            acme_email: Some("admin@example.com"),
            cloudflare_zone_name: Some("example.com"),
            dns_record_name: Some("edge.example.com"),
            label_prefix: Some("test-edge"),
            deployment_label: None,
        };

        let bundle = build_bundle(&request).unwrap();
        assert!(
            bundle
                .stack_files
                .iter()
                .any(|file| file.relative_path == "docker-compose.yml")
        );
        assert!(
            bundle
                .stack_files
                .iter()
                .any(|file| file.relative_path == ".env.runtime")
        );
        assert!(
            bundle
                .host_files
                .iter()
                .any(|file| file.relative_path == "tls/agent-server.key")
        );
        assert!(
            bundle
                .deployment_summary_json
                .contains("\"instance_id\": \"instance-1\"")
        );
        assert!(bundle.agent_env_content.contains(SERVER_TLS_ROOT));
        let _ = fs::remove_dir_all(bundle.generated_dir);
    }

    #[test]
    fn generates_uuid_v4_shape() {
        let value = generate_uuid_v4().unwrap();
        assert_eq!(value.len(), 36);
        assert_eq!(value.as_bytes()[14], b'4');
    }

    #[test]
    fn respects_explicit_deployment_label() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let request = BuildBundleRequest {
            repo_root: &repo_root,
            target_ip: "203.0.113.21",
            instance_id: "instance-2",
            tunnel_domain: None,
            acme_email: None,
            cloudflare_zone_name: None,
            dns_record_name: None,
            label_prefix: Some("ignored"),
            deployment_label: Some("edge-fixed-label"),
        };

        let bundle = build_bundle(&request).unwrap();
        assert_eq!(bundle.label, "edge-fixed-label");
        let _ = fs::remove_dir_all(bundle.generated_dir);
    }
}
