use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::time::{Duration, sleep};

const API_ROOT: &str = "https://api.vultr.com/v2";
const SAFE_REQUEST_ATTEMPTS: usize = 4;
const SAFE_REQUEST_RETRY_DELAYS_SECS: [u64; SAFE_REQUEST_ATTEMPTS - 1] = [2, 4, 8];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrInstance {
    pub id: String,
    pub label: String,
    pub region: String,
    pub plan: String,
    pub status: String,
    pub server_status: String,
    pub main_ip: String,
}

#[derive(Debug, Clone)]
pub struct CreateInstanceRequest<'a> {
    pub region: &'a str,
    pub plan: &'a str,
    pub os_id: Option<u32>,
    pub snapshot_id: Option<&'a str>,
    pub label: &'a str,
    pub ssh_key_id: &'a str,
    pub cloud_init: &'a str,
}

pub async fn create_instance(
    api_key: &str,
    request: &CreateInstanceRequest<'_>,
) -> Result<VultrInstance, String> {
    let client = authorized_client(api_key)?;
    let body = build_create_instance_payload(request)?;
    let response = client
        .post(format!("{API_ROOT}/instances"))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("failed to create Vultr instance: {}", error_chain(&err)))?;
    let payload: InstanceEnvelope = parse_success_json(response).await?;
    Ok(payload.instance.into())
}

pub async fn get_instance(api_key: &str, instance_id: &str) -> Result<VultrInstance, String> {
    let response = send_with_safe_retries("read Vultr instance", || async {
        let client = authorized_client(api_key)?;
        client
            .get(format!("{API_ROOT}/instances/{instance_id}"))
            .send()
            .await
            .map_err(|err| format!("failed to read Vultr instance: {}", error_chain(&err)))
    })
    .await?;
    let payload: InstanceEnvelope = parse_success_json(response).await?;
    Ok(payload.instance.into())
}

pub async fn destroy_instance(api_key: &str, instance_id: &str) -> Result<(), String> {
    let response = send_with_safe_retries("destroy Vultr instance", || async {
        let client = authorized_client(api_key)?;
        client
            .delete(format!("{API_ROOT}/instances/{instance_id}"))
            .send()
            .await
            .map_err(|err| format!("failed to destroy Vultr instance: {}", error_chain(&err)))
    })
    .await?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response
        .text()
        .await
        .map_err(|err| format!("failed to read Vultr destroy response body: {err}"))?;
    Err(format!("Vultr API returned {status}: {body}"))
}

pub async fn list_instances(api_key: &str) -> Result<Vec<VultrInstance>, String> {
    let response = send_with_safe_retries("list Vultr instances", || async {
        let client = authorized_client(api_key)?;
        client
            .get(format!("{API_ROOT}/instances"))
            .send()
            .await
            .map_err(|err| format!("failed to list Vultr instances: {}", error_chain(&err)))
    })
    .await?;
    let payload: ListInstancesEnvelope = parse_success_json(response).await?;
    Ok(payload.instances.into_iter().map(Into::into).collect())
}

fn error_chain(err: &reqwest::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(err) = source {
        parts.push(err.to_string());
        source = err.source();
    }
    parts.join(": ")
}

fn is_retryable_transport_error(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("client error (connect)")
        || normalized.contains("dns error")
        || normalized.contains("tcp connect error")
        || normalized.contains("connection reset")
        || normalized.contains("connection aborted")
        || normalized.contains("broken pipe")
        || normalized.contains("connection refused")
        || normalized.contains("unexpected eof")
        || normalized.contains("timed out")
        || normalized.contains("timeout")
        || normalized.contains("os error 10053")
        || normalized.contains("os error 10054")
        || normalized.contains("os error 10060")
        || normalized.contains("os error 104")
        || normalized.contains("os error 110")
        || normalized.contains("os error 111")
}

async fn send_with_safe_retries<F, Fut>(
    action_name: &str,
    mut action: F,
) -> Result<reqwest::Response, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response, String>>,
{
    let mut last_error = None;
    for attempt in 0..SAFE_REQUEST_ATTEMPTS {
        match action().await {
            Ok(response) => return Ok(response),
            Err(err) if attempt + 1 < SAFE_REQUEST_ATTEMPTS && is_retryable_transport_error(&err) => {
                last_error = Some(err);
                sleep(Duration::from_secs(
                    SAFE_REQUEST_RETRY_DELAYS_SECS[attempt],
                ))
                .await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        format!(
            "{} failed after {} attempts with an unknown transport error",
            action_name, SAFE_REQUEST_ATTEMPTS
        )
    }))
}

pub fn mock_instance(label: &str, region: &str, plan: &str, ip: &str) -> VultrInstance {
    VultrInstance {
        id: format!("mock-{}-{}", region, label.replace('.', "-")),
        label: label.to_owned(),
        region: region.to_owned(),
        plan: plan.to_owned(),
        status: "active".to_owned(),
        server_status: "ok".to_owned(),
        main_ip: ip.to_owned(),
    }
}

fn authorized_client(api_key: &str) -> Result<Client, String> {
    if api_key.trim().is_empty() {
        return Err("Vultr API key is required".to_owned());
    }
    Client::builder()
        .user_agent("edge-platform/0.1")
        .default_headers(
            [(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {api_key}")
                    .parse()
                    .map_err(|err| format!("failed to build Vultr auth header: {err}"))?,
            )]
            .into_iter()
            .collect(),
        )
        .build()
        .map_err(|err| format!("failed to build Vultr HTTP client: {err}"))
}

fn build_create_instance_payload(
    request: &CreateInstanceRequest<'_>,
) -> Result<CreateInstancePayload, String> {
    Ok(CreateInstancePayload {
        region: request.region.to_owned(),
        plan: request.plan.to_owned(),
        os_id: request.os_id,
        snapshot_id: request.snapshot_id.map(ToOwned::to_owned),
        label: request.label.to_owned(),
        hostname: request.label.to_owned(),
        enable_ipv6: true,
        sshkey_id: vec![request.ssh_key_id.to_owned()],
        user_data: STANDARD.encode(request.cloud_init.as_bytes()),
    })
}

async fn parse_success_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("failed to read Vultr response body: {err}"))?;
    if !status.is_success() {
        return Err(format!("Vultr API returned {status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|err| format!("invalid Vultr JSON payload: {err}"))
}

#[derive(Debug, Serialize)]
struct CreateInstancePayload {
    region: String,
    plan: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<String>,
    label: String,
    hostname: String,
    enable_ipv6: bool,
    sshkey_id: Vec<String>,
    user_data: String,
}

#[derive(Debug, Deserialize)]
struct InstanceEnvelope {
    instance: VultrInstancePayload,
}

#[derive(Debug, Deserialize)]
struct ListInstancesEnvelope {
    instances: Vec<VultrInstancePayload>,
}

#[derive(Debug, Deserialize)]
struct VultrInstancePayload {
    id: String,
    label: String,
    region: String,
    plan: String,
    status: String,
    server_status: String,
    #[serde(default)]
    main_ip: String,
}

impl From<VultrInstancePayload> for VultrInstance {
    fn from(value: VultrInstancePayload) -> Self {
        Self {
            id: value.id,
            label: value.label,
            region: value.region,
            plan: value.plan,
            status: value.status,
            server_status: value.server_status,
            main_ip: value.main_ip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_create_instance_payload() {
        let payload = build_create_instance_payload(&CreateInstanceRequest {
            region: "waw",
            plan: "vc2-1c-1gb",
            os_id: Some(2136),
            snapshot_id: None,
            label: "edge-1",
            ssh_key_id: "ssh-key-1",
            cloud_init: "#cloud-config\npackages: []\n",
        })
        .unwrap();
        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json["region"], "waw");
        assert_eq!(json["label"], "edge-1");
        assert_eq!(json["os_id"], 2136);
        assert!(json.get("snapshot_id").is_none());
        assert!(json["user_data"].as_str().unwrap().len() > 8);
    }

    #[test]
    fn serializes_snapshot_based_create_payload() {
        let payload = build_create_instance_payload(&CreateInstanceRequest {
            region: "waw",
            plan: "vc2-1c-1gb",
            os_id: None,
            snapshot_id: Some("61605612-d7a2-47b1-85ef-aef90f5083df"),
            label: "edge-1",
            ssh_key_id: "ssh-key-1",
            cloud_init: "#cloud-config\npackages: []\n",
        })
        .unwrap();
        let json = serde_json::to_value(payload).unwrap();
        assert!(json.get("os_id").is_none());
        assert_eq!(json["snapshot_id"], "61605612-d7a2-47b1-85ef-aef90f5083df");
    }

    #[test]
    fn creates_mock_instance() {
        let instance = mock_instance("edge-1", "waw", "vc2-1c-1gb", "203.0.113.10");
        assert_eq!(instance.status, "active");
        assert_eq!(instance.main_ip, "203.0.113.10");
    }
}
