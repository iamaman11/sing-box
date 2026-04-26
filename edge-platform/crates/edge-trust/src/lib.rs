use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, SanType};
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

const AGENT_SERVER_CERT_ENV: &str = "EDGE_AGENT_TLS_SERVER_CERT_PATH";
const AGENT_SERVER_KEY_ENV: &str = "EDGE_AGENT_TLS_SERVER_KEY_PATH";
const AGENT_CA_CERT_ENV: &str = "EDGE_AGENT_TLS_CA_CERT_PATH";
const AGENT_CLIENT_CERT_ENV: &str = "EDGE_CONTROLLER_TLS_CLIENT_CERT_PATH";
const AGENT_CLIENT_KEY_ENV: &str = "EDGE_CONTROLLER_TLS_CLIENT_KEY_PATH";
const AGENT_DOMAIN_ENV: &str = "EDGE_AGENT_TLS_DOMAIN";
const DEFAULT_AGENT_DOMAIN: &str = "edge-agent";
const CA_CERT_FILE_NAME: &str = "ca.pem";
const SERVER_CERT_FILE_NAME: &str = "agent-server.pem";
const SERVER_KEY_FILE_NAME: &str = "agent-server.key";
const CLIENT_CERT_FILE_NAME: &str = "controller-client.pem";
const CLIENT_KEY_FILE_NAME: &str = "controller-client.key";

#[derive(Debug, Clone)]
pub struct AgentTlsIdentity {
    pub deployment_id: String,
    pub instance_id: String,
    pub server_ip: String,
    pub domain_name: String,
}

#[derive(Debug, Clone)]
pub struct AgentServerTlsPaths {
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AgentClientTlsPaths {
    pub ca_cert_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub domain_name: String,
}

#[derive(Debug, Clone)]
pub struct IssuedAgentTlsMaterial {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub domain_name: String,
}

#[derive(Debug, Clone)]
pub struct WrittenAgentTlsMaterial {
    pub ca_cert_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub domain_name: String,
}

pub fn optional_agent_server_tls_from_env() -> Result<Option<ServerTlsConfig>, String> {
    let server_cert_path = optional_non_empty_env(AGENT_SERVER_CERT_ENV);
    let server_key_path = optional_non_empty_env(AGENT_SERVER_KEY_ENV);
    let ca_cert_path = optional_non_empty_env(AGENT_CA_CERT_ENV);

    match (server_cert_path, server_key_path, ca_cert_path) {
        (None, None, None) => Ok(None),
        (Some(server_cert_path), Some(server_key_path), Some(ca_cert_path)) => {
            agent_server_tls_from_paths(&AgentServerTlsPaths {
                server_cert_path: PathBuf::from(server_cert_path),
                server_key_path: PathBuf::from(server_key_path),
                ca_cert_path: PathBuf::from(ca_cert_path),
            })
            .map(Some)
        }
        _ => Err(
            "EDGE_AGENT_TLS_SERVER_CERT_PATH, EDGE_AGENT_TLS_SERVER_KEY_PATH, and EDGE_AGENT_TLS_CA_CERT_PATH must be provided together".to_owned(),
        ),
    }
}

pub fn optional_agent_client_tls_from_env() -> Result<Option<ClientTlsConfig>, String> {
    let ca_cert_path = optional_non_empty_env(AGENT_CA_CERT_ENV);
    let client_cert_path = optional_non_empty_env(AGENT_CLIENT_CERT_ENV);
    let client_key_path = optional_non_empty_env(AGENT_CLIENT_KEY_ENV);

    match (ca_cert_path, client_cert_path, client_key_path) {
        (None, None, None) => Ok(None),
        (Some(ca_cert_path), Some(client_cert_path), Some(client_key_path)) => {
            agent_client_tls_from_paths(&AgentClientTlsPaths {
                ca_cert_path: PathBuf::from(ca_cert_path),
                client_cert_path: PathBuf::from(client_cert_path),
                client_key_path: PathBuf::from(client_key_path),
                domain_name: optional_non_empty_env(AGENT_DOMAIN_ENV)
                    .unwrap_or_else(|| DEFAULT_AGENT_DOMAIN.to_owned()),
            })
            .map(Some)
        }
        _ => Err(
            "EDGE_AGENT_TLS_CA_CERT_PATH, EDGE_CONTROLLER_TLS_CLIENT_CERT_PATH, and EDGE_CONTROLLER_TLS_CLIENT_KEY_PATH must be provided together".to_owned(),
        ),
    }
}

pub fn agent_server_tls_from_paths(paths: &AgentServerTlsPaths) -> Result<ServerTlsConfig, String> {
    let server_cert = read_pem(&paths.server_cert_path, "server cert")?;
    let server_key = read_pem(&paths.server_key_path, "server key")?;
    let ca_cert = read_pem(&paths.ca_cert_path, "CA cert")?;

    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(ca_cert)))
}

pub fn agent_client_tls_from_paths(paths: &AgentClientTlsPaths) -> Result<ClientTlsConfig, String> {
    let ca_cert = read_pem(&paths.ca_cert_path, "CA cert")?;
    let client_cert = read_pem(&paths.client_cert_path, "client cert")?;
    let client_key = read_pem(&paths.client_key_path, "client key")?;

    Ok(ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_cert))
        .identity(Identity::from_pem(client_cert, client_key))
        .domain_name(paths.domain_name.clone()))
}

pub fn agent_endpoint_scheme(endpoint: &str, tls_enabled: bool) -> String {
    if !tls_enabled {
        return endpoint.to_owned();
    }

    if endpoint.starts_with("https://") {
        return endpoint.to_owned();
    }
    if let Some(rest) = endpoint.strip_prefix("http://") {
        return format!("https://{rest}");
    }
    format!("https://{endpoint}")
}

pub fn issue_agent_tls_material(
    identity: &AgentTlsIdentity,
) -> Result<IssuedAgentTlsMaterial, String> {
    let ca_key = KeyPair::generate().map_err(|err| format!("failed to generate CA key: {err}"))?;
    let mut ca_params = CertificateParams::new(vec![])
        .map_err(|err| format!("failed to build CA params: {err}"))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(
        DnType::CommonName,
        format!(
            "edge-ca:{}:{}",
            identity.deployment_id, identity.instance_id
        ),
    );
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)
        .map_err(|err| format!("failed to issue CA certificate: {err}"))?;

    let server_key =
        KeyPair::generate().map_err(|err| format!("failed to generate server key: {err}"))?;
    let mut server_params = CertificateParams::new(vec![identity.domain_name.clone()])
        .map_err(|err| format!("failed to build server params: {err}"))?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, identity.domain_name.clone());
    if let Ok(ip) = identity.server_ip.parse::<IpAddr>() {
        server_params.subject_alt_names.push(SanType::IpAddress(ip));
    }
    let server_cert = server_params
        .signed_by(&server_key, &ca)
        .map_err(|err| format!("failed to issue server certificate: {err}"))?;

    let client_key =
        KeyPair::generate().map_err(|err| format!("failed to generate client key: {err}"))?;
    let mut client_params = CertificateParams::new(vec!["edge-controller".to_owned()])
        .map_err(|err| format!("failed to build client params: {err}"))?;
    client_params
        .distinguished_name
        .push(DnType::CommonName, "edge-controller");
    let client_cert = client_params
        .signed_by(&client_key, &ca)
        .map_err(|err| format!("failed to issue client certificate: {err}"))?;

    Ok(IssuedAgentTlsMaterial {
        ca_cert_pem: ca.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
        domain_name: identity.domain_name.clone(),
    })
}

pub fn write_agent_tls_material(
    output_dir: &Path,
    material: &IssuedAgentTlsMaterial,
) -> Result<WrittenAgentTlsMaterial, String> {
    fs::create_dir_all(output_dir).map_err(|err| {
        format!(
            "failed to create TLS output directory {}: {err}",
            output_dir.display()
        )
    })?;

    let ca_cert_path = output_dir.join(CA_CERT_FILE_NAME);
    let server_cert_path = output_dir.join(SERVER_CERT_FILE_NAME);
    let server_key_path = output_dir.join(SERVER_KEY_FILE_NAME);
    let client_cert_path = output_dir.join(CLIENT_CERT_FILE_NAME);
    let client_key_path = output_dir.join(CLIENT_KEY_FILE_NAME);

    fs::write(&ca_cert_path, material.ca_cert_pem.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", ca_cert_path.display()))?;
    fs::write(&server_cert_path, material.server_cert_pem.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", server_cert_path.display()))?;
    fs::write(&server_key_path, material.server_key_pem.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", server_key_path.display()))?;
    fs::write(&client_cert_path, material.client_cert_pem.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", client_cert_path.display()))?;
    fs::write(&client_key_path, material.client_key_pem.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", client_key_path.display()))?;

    Ok(WrittenAgentTlsMaterial {
        ca_cert_path,
        server_cert_path,
        server_key_path,
        client_cert_path,
        client_key_path,
        domain_name: material.domain_name.clone(),
    })
}

pub fn write_agent_server_env_file(
    env_file_path: &Path,
    material: &WrittenAgentTlsMaterial,
) -> Result<(), String> {
    let content = format!(
        "EDGE_AGENT_TLS_SERVER_CERT_PATH={}\nEDGE_AGENT_TLS_SERVER_KEY_PATH={}\nEDGE_AGENT_TLS_CA_CERT_PATH={}\n",
        material.server_cert_path.display(),
        material.server_key_path.display(),
        material.ca_cert_path.display(),
    );
    fs::write(env_file_path, content)
        .map_err(|err| format!("failed to write {}: {err}", env_file_path.display()))
}

impl WrittenAgentTlsMaterial {
    pub fn agent_server_paths(&self) -> AgentServerTlsPaths {
        AgentServerTlsPaths {
            server_cert_path: self.server_cert_path.clone(),
            server_key_path: self.server_key_path.clone(),
            ca_cert_path: self.ca_cert_path.clone(),
        }
    }

    pub fn agent_client_paths(&self) -> AgentClientTlsPaths {
        AgentClientTlsPaths {
            ca_cert_path: self.ca_cert_path.clone(),
            client_cert_path: self.client_cert_path.clone(),
            client_key_path: self.client_key_path.clone(),
            domain_name: self.domain_name.clone(),
        }
    }
}

fn read_pem(path: &PathBuf, label: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|err| format!("failed to read {label} {}: {err}", path.display()))
}

fn optional_non_empty_env(name: &str) -> Option<String> {
    normalize_optional_env(env::var(name).ok())
}

fn normalize_optional_env(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rewrites_http_endpoint_to_https_when_tls_is_enabled() {
        assert_eq!(
            agent_endpoint_scheme("http://127.0.0.1:50061", true),
            "https://127.0.0.1:50061"
        );
        assert_eq!(
            agent_endpoint_scheme("http://127.0.0.1:50061", false),
            "http://127.0.0.1:50061"
        );
    }

    #[test]
    fn ignores_blank_optional_tls_env_values() {
        assert_eq!(normalize_optional_env(Some(String::new())), None);
        assert_eq!(normalize_optional_env(Some("   ".to_owned())), None);
        assert_eq!(
            normalize_optional_env(Some("/tmp/cert.pem".to_owned())),
            Some("/tmp/cert.pem".to_owned())
        );
    }

    #[test]
    fn issues_and_writes_agent_tls_material() {
        let root = temp_dir("edge-trust");
        let env_file = root.join("edge-agent.env");
        let material = issue_agent_tls_material(&AgentTlsIdentity {
            deployment_id: "deploy-1".to_owned(),
            instance_id: "instance-1".to_owned(),
            server_ip: "203.0.113.10".to_owned(),
            domain_name: "edge-agent".to_owned(),
        })
        .unwrap();
        let written = write_agent_tls_material(&root, &material).unwrap();
        write_agent_server_env_file(&env_file, &written).unwrap();

        let server_tls = agent_server_tls_from_paths(&written.agent_server_paths());
        assert!(server_tls.is_ok());

        let client_tls = agent_client_tls_from_paths(&written.agent_client_paths());
        assert!(client_tls.is_ok());

        let env_content = fs::read_to_string(env_file).unwrap();
        assert!(env_content.contains("EDGE_AGENT_TLS_SERVER_CERT_PATH="));
        assert!(env_content.contains("EDGE_AGENT_TLS_SERVER_KEY_PATH="));
        assert!(env_content.contains("EDGE_AGENT_TLS_CA_CERT_PATH="));

        let _ = fs::remove_dir_all(root);
    }

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("{label}-{unique}"));
        fs::create_dir_all(&root).unwrap();
        root
    }
}
