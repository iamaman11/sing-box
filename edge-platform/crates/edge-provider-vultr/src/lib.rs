use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use tokio::time::{Duration, sleep};

const API_ROOT: &str = "https://api.vultr.com/v2";
const SAFE_OBSERVATION_ATTEMPTS: usize = 4;
const SAFE_OBSERVATION_RETRY_DELAYS_SECS: [u64; SAFE_OBSERVATION_ATTEMPTS - 1] = [2, 4, 8];
const MAX_PROVIDER_ERROR_CHARS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VultrErrorKind {
    Configuration,
    ObservationTransport,
    MutationUncertain,
    Http,
    Decode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VultrError {
    pub operation: &'static str,
    pub kind: VultrErrorKind,
    pub status: Option<u16>,
    pub retry_after_secs: Option<u64>,
    pub detail: String,
}

impl VultrError {
    pub fn is_not_found(&self) -> bool {
        self.status == Some(StatusCode::NOT_FOUND.as_u16())
    }

    pub fn is_mutation_uncertain(&self) -> bool {
        self.kind == VultrErrorKind::MutationUncertain
    }

    pub fn requires_mutation_reobservation(&self) -> bool {
        if self.kind == VultrErrorKind::MutationUncertain {
            return true;
        }
        self.kind == VultrErrorKind::Http
            && self
                .status
                .and_then(|status| StatusCode::from_u16(status).ok())
                .is_some_and(|status| {
                    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
                })
    }

    pub fn is_observation_retryable(&self) -> bool {
        match self.kind {
            VultrErrorKind::ObservationTransport => true,
            VultrErrorKind::Http => self
                .status
                .and_then(|status| StatusCode::from_u16(status).ok())
                .is_some_and(|status| {
                    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
                }),
            VultrErrorKind::Configuration
            | VultrErrorKind::MutationUncertain
            | VultrErrorKind::Decode => false,
        }
    }
}

impl fmt::Display for VultrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(status) => write!(
                f,
                "{} failed with HTTP {}: {}",
                self.operation, status, self.detail
            ),
            None => write!(f, "{} failed: {}", self.operation, self.detail),
        }
    }
}

impl Error for VultrError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrInstance {
    pub id: String,
    pub label: String,
    pub region: String,
    pub plan: String,
    pub status: String,
    pub server_status: String,
    pub power_status: String,
    pub main_ip: String,
    pub firewall_group_id: String,
    pub tags: Vec<String>,
    pub os_id: u32,
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
    pub firewall_group_id: Option<&'a str>,
    pub tags: Vec<&'a str>,
    pub enable_ipv6: bool,
}

pub async fn create_instance_typed(
    api_key: &str,
    request: &CreateInstanceRequest<'_>,
) -> Result<VultrInstance, VultrError> {
    let client = authorized_client(api_key)?;
    let body = build_create_instance_payload(request)?;
    execute_json_once(
        "create Vultr instance",
        client.post(format!("{API_ROOT}/instances")).json(&body),
        true,
    )
    .await
    .map(|payload: InstanceEnvelope| payload.instance.into())
}

pub async fn create_instance(
    api_key: &str,
    request: &CreateInstanceRequest<'_>,
) -> Result<VultrInstance, String> {
    create_instance_typed(api_key, request)
        .await
        .map_err(|err| err.to_string())
}

pub async fn get_instance_typed(
    api_key: &str,
    instance_id: &str,
) -> Result<VultrInstance, VultrError> {
    let client = authorized_client(api_key)?;
    let url = format!("{API_ROOT}/instances/{instance_id}");
    observation_json("read Vultr instance", || client.get(&url))
        .await
        .map(|payload: InstanceEnvelope| payload.instance.into())
}

pub async fn get_instance(api_key: &str, instance_id: &str) -> Result<VultrInstance, String> {
    get_instance_typed(api_key, instance_id)
        .await
        .map_err(|err| err.to_string())
}

pub async fn destroy_instance_typed(api_key: &str, instance_id: &str) -> Result<(), VultrError> {
    let client = authorized_client(api_key)?;
    let response = client
        .delete(format!("{API_ROOT}/instances/{instance_id}"))
        .send()
        .await
        .map_err(|err| mutation_transport_error("destroy Vultr instance", err))?;

    let status = response.status();
    let retry_after_secs = retry_after_seconds(&response);
    if status.is_success() {
        return Ok(());
    }

    let detail = provider_error_detail(
        response
            .bytes()
            .await
            .map_err(|err| mutation_transport_error("read Vultr destroy response", err))?
            .as_ref(),
    );

    Err(VultrError {
        operation: "destroy Vultr instance",
        kind: VultrErrorKind::Http,
        status: Some(status.as_u16()),
        retry_after_secs,
        detail,
    })
}

pub async fn destroy_instance(api_key: &str, instance_id: &str) -> Result<(), String> {
    destroy_instance_typed(api_key, instance_id)
        .await
        .map_err(|err| err.to_string())
}

pub fn is_not_found_error(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("404 not found")
        || normalized.contains("http 404")
        || (normalized.contains("\"status\":404") && normalized.contains("not found"))
}

pub async fn list_instances_typed(api_key: &str) -> Result<Vec<VultrInstance>, VultrError> {
    let client = authorized_client(api_key)?;
    let mut result = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let current_cursor = cursor.clone();
        let page: ListInstancesEnvelope = observation_json("list Vultr instances", || {
            let request = client
                .get(format!("{API_ROOT}/instances"))
                .query(&[("per_page", "500")]);
            match current_cursor.as_deref() {
                Some(cursor) if !cursor.is_empty() => request.query(&[("cursor", cursor)]),
                _ => request,
            }
        })
        .await?;

        result.extend(page.instances.into_iter().map(Into::into));

        cursor = page
            .meta
            .and_then(|meta| meta.links)
            .and_then(|links| links.next)
            .filter(|value| !value.trim().is_empty());

        if cursor.is_none() {
            break;
        }
    }

    Ok(result)
}

pub async fn list_instances(api_key: &str) -> Result<Vec<VultrInstance>, String> {
    list_instances_typed(api_key)
        .await
        .map_err(|err| err.to_string())
}

async fn observation_json<T, F>(
    operation: &'static str,
    mut build_request: F,
) -> Result<T, VultrError>
where
    T: DeserializeOwned,
    F: FnMut() -> RequestBuilder,
{
    let mut last_error = None;

    for attempt in 1..=SAFE_OBSERVATION_ATTEMPTS {
        match execute_json_once(operation, build_request(), false).await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < SAFE_OBSERVATION_ATTEMPTS && err.is_observation_retryable() => {
                let delay = err
                    .retry_after_secs
                    .unwrap_or(SAFE_OBSERVATION_RETRY_DELAYS_SECS[attempt - 1])
                    .min(30);
                last_error = Some(err);
                sleep(Duration::from_secs(delay)).await;
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_error.unwrap_or_else(|| VultrError {
        operation,
        kind: VultrErrorKind::ObservationTransport,
        status: None,
        retry_after_secs: None,
        detail: format!("observation failed after {SAFE_OBSERVATION_ATTEMPTS} attempts"),
    }))
}

async fn execute_json_once<T: DeserializeOwned>(
    operation: &'static str,
    request: RequestBuilder,
    mutation: bool,
) -> Result<T, VultrError> {
    let response = request.send().await.map_err(|err| {
        if mutation {
            mutation_transport_error(operation, err)
        } else {
            observation_transport_error(operation, err)
        }
    })?;

    let status = response.status();
    let retry_after_secs = retry_after_seconds(&response);
    let bytes = response.bytes().await.map_err(|err| {
        if mutation {
            mutation_transport_error(operation, err)
        } else {
            observation_transport_error(operation, err)
        }
    })?;

    if !status.is_success() {
        return Err(VultrError {
            operation,
            kind: VultrErrorKind::Http,
            status: Some(status.as_u16()),
            retry_after_secs,
            detail: provider_error_detail(&bytes),
        });
    }

    serde_json::from_slice(&bytes).map_err(|err| VultrError {
        operation,
        kind: if mutation {
            VultrErrorKind::MutationUncertain
        } else {
            VultrErrorKind::Decode
        },
        status: Some(status.as_u16()),
        retry_after_secs,
        detail: format!("invalid Vultr JSON payload: {err}"),
    })
}

fn observation_transport_error(operation: &'static str, err: reqwest::Error) -> VultrError {
    VultrError {
        operation,
        kind: VultrErrorKind::ObservationTransport,
        status: None,
        retry_after_secs: None,
        detail: transport_detail(&err),
    }
}

fn mutation_transport_error(operation: &'static str, err: reqwest::Error) -> VultrError {
    VultrError {
        operation,
        kind: VultrErrorKind::MutationUncertain,
        status: None,
        retry_after_secs: None,
        detail: transport_detail(&err),
    }
}

fn transport_detail(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        "transport timeout".to_owned()
    } else if err.is_connect() {
        "transport connection failure".to_owned()
    } else if err.is_request() {
        format!("transport request failure: {err}")
    } else {
        format!("transport failure: {err}")
    }
}

fn retry_after_seconds(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn provider_error_detail(body: &[u8]) -> String {
    let text = if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        value
            .get("error")
            .or_else(|| value.get("message"))
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned())
    } else {
        String::from_utf8_lossy(body).into_owned()
    };

    let mut chars = text.chars();
    let bounded: String = chars.by_ref().take(MAX_PROVIDER_ERROR_CHARS).collect();
    if chars.next().is_some() {
        format!("{bounded}…")
    } else if bounded.trim().is_empty() {
        "provider returned no error detail".to_owned()
    } else {
        bounded
    }
}

pub fn mock_instance(label: &str, region: &str, plan: &str, ip: &str) -> VultrInstance {
    VultrInstance {
        id: format!("mock-{}-{}", region, label.replace('.', "-")),
        label: label.to_owned(),
        region: region.to_owned(),
        plan: plan.to_owned(),
        status: "active".to_owned(),
        server_status: "ok".to_owned(),
        power_status: "running".to_owned(),
        main_ip: ip.to_owned(),
        firewall_group_id: String::new(),
        tags: Vec::new(),
        os_id: 0,
    }
}

fn authorized_client(api_key: &str) -> Result<Client, VultrError> {
    if api_key.trim().is_empty() {
        return Err(VultrError {
            operation: "build Vultr API client",
            kind: VultrErrorKind::Configuration,
            status: None,
            retry_after_secs: None,
            detail: "Vultr API key is required".to_owned(),
        });
    }

    Client::builder()
        .user_agent("edge-platform/0.1")
        .default_headers(
            [(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {api_key}")
                    .parse()
                    .map_err(|err| VultrError {
                        operation: "build Vultr API client",
                        kind: VultrErrorKind::Configuration,
                        status: None,
                        retry_after_secs: None,
                        detail: format!("failed to build Vultr auth header: {err}"),
                    })?,
            )]
            .into_iter()
            .collect(),
        )
        .build()
        .map_err(|err| VultrError {
            operation: "build Vultr API client",
            kind: VultrErrorKind::Configuration,
            status: None,
            retry_after_secs: None,
            detail: format!("failed to build Vultr HTTP client: {err}"),
        })
}

fn build_create_instance_payload(
    request: &CreateInstanceRequest<'_>,
) -> Result<CreateInstancePayload, VultrError> {
    if request.os_id.is_none() && request.snapshot_id.is_none() {
        return Err(VultrError {
            operation: "build Vultr create request",
            kind: VultrErrorKind::Configuration,
            status: None,
            retry_after_secs: None,
            detail: "either os_id or snapshot_id is required".to_owned(),
        });
    }

    Ok(CreateInstancePayload {
        region: request.region.to_owned(),
        plan: request.plan.to_owned(),
        os_id: request.os_id,
        snapshot_id: request.snapshot_id.map(ToOwned::to_owned),
        label: request.label.to_owned(),
        hostname: request.label.to_owned(),
        enable_ipv6: request.enable_ipv6,
        sshkey_id: vec![request.ssh_key_id.to_owned()],
        user_data: STANDARD.encode(request.cloud_init.as_bytes()),
        firewall_group_id: request.firewall_group_id.map(ToOwned::to_owned),
        tags: request
            .tags
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    })
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
    #[serde(skip_serializing_if = "Option::is_none")]
    firewall_group_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct InstanceEnvelope {
    instance: VultrInstancePayload,
}

#[derive(Debug, Deserialize)]
struct ListInstancesEnvelope {
    instances: Vec<VultrInstancePayload>,
    #[serde(default)]
    meta: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct ListMeta {
    #[serde(default)]
    links: Option<ListLinks>,
}

#[derive(Debug, Deserialize)]
struct ListLinks {
    #[serde(default)]
    next: Option<String>,
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
    power_status: String,
    #[serde(default)]
    main_ip: String,
    #[serde(default)]
    firewall_group_id: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    os_id: u32,
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
            power_status: value.power_status,
            main_ip: value.main_ip,
            firewall_group_id: value.firewall_group_id,
            tags: value.tags,
            os_id: value.os_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>() -> CreateInstanceRequest<'a> {
        CreateInstanceRequest {
            region: "waw",
            plan: "vc2-1c-1gb",
            os_id: Some(2625),
            snapshot_id: None,
            label: "edge-1",
            ssh_key_id: "ssh-key-1",
            cloud_init: "#cloud-config\npackages: []\n",
            firewall_group_id: Some("firewall-1"),
            tags: vec!["managed-by-sing-box", "logical-edge-1"],
            enable_ipv6: false,
        }
    }

    #[test]
    fn serializes_create_instance_payload() {
        let payload = build_create_instance_payload(&request()).unwrap();
        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json["region"], "waw");
        assert_eq!(json["label"], "edge-1");
        assert_eq!(json["os_id"], 2625);
        assert_eq!(json["firewall_group_id"], "firewall-1");
        assert_eq!(json["enable_ipv6"], false);
        assert_eq!(json["tags"][0], "managed-by-sing-box");
        assert!(json.get("snapshot_id").is_none());
        assert!(json["user_data"].as_str().unwrap().len() > 8);
    }

    #[test]
    fn serializes_snapshot_based_create_payload() {
        let request = CreateInstanceRequest {
            region: "waw",
            plan: "vc2-1c-1gb",
            os_id: None,
            snapshot_id: Some("61605612-d7a2-47b1-85ef-aef90f5083df"),
            label: "edge-1",
            ssh_key_id: "ssh-key-1",
            cloud_init: "#cloud-config\npackages: []\n",
            firewall_group_id: None,
            tags: Vec::new(),
            enable_ipv6: true,
        };
        let payload = build_create_instance_payload(&request).unwrap();
        let json = serde_json::to_value(payload).unwrap();
        assert!(json.get("os_id").is_none());
        assert_eq!(json["snapshot_id"], "61605612-d7a2-47b1-85ef-aef90f5083df");
    }

    #[test]
    fn creates_mock_instance() {
        let instance = mock_instance("edge-1", "waw", "vc2-1c-1gb", "203.0.113.10");
        assert_eq!(instance.status, "active");
        assert_eq!(instance.power_status, "running");
        assert_eq!(instance.main_ip, "203.0.113.10");
    }

    #[test]
    fn classifies_not_found_without_string_parsing() {
        let error = VultrError {
            operation: "read Vultr instance",
            kind: VultrErrorKind::Http,
            status: Some(404),
            retry_after_secs: None,
            detail: "Not found.".to_owned(),
        };
        assert!(error.is_not_found());
    }

    #[test]
    fn classifies_observation_retryable_http_statuses() {
        for status in [429, 500, 502, 503, 504] {
            let error = VultrError {
                operation: "list Vultr instances",
                kind: VultrErrorKind::Http,
                status: Some(status),
                retry_after_secs: None,
                detail: "retryable".to_owned(),
            };
            assert!(error.is_observation_retryable(), "status={status}");
        }

        let error = VultrError {
            operation: "list Vultr instances",
            kind: VultrErrorKind::Http,
            status: Some(404),
            retry_after_secs: None,
            detail: "not found".to_owned(),
        };
        assert!(!error.is_observation_retryable());
    }

    #[test]
    fn marks_mutation_transport_as_uncertain() {
        let error = VultrError {
            operation: "create Vultr instance",
            kind: VultrErrorKind::MutationUncertain,
            status: None,
            retry_after_secs: None,
            detail: "transport lost".to_owned(),
        };
        assert!(error.is_mutation_uncertain());
        assert!(!error.is_observation_retryable());
    }

    #[test]
    fn bounds_provider_error_detail() {
        let body = format!("{{\"error\":\"{}\"}}", "x".repeat(800));
        let detail = provider_error_detail(body.as_bytes());
        assert!(detail.chars().count() <= MAX_PROVIDER_ERROR_CHARS + 1);
        assert!(detail.ends_with('…'));
    }
}
