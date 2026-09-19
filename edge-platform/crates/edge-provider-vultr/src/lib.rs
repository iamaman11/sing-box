use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use tokio::time::{Duration, sleep};

const API_ROOT: &str = "https://api.vultr.com/v2";
const SAFE_OBSERVATION_ATTEMPTS: usize = 4;
const SAFE_OBSERVATION_RETRY_DELAYS_SECS: [u64; SAFE_OBSERVATION_ATTEMPTS - 1] = [2, 4, 8];
const MAX_PROVIDER_ERROR_CHARS: usize = 512;
const MAX_PROVIDER_ERROR_BYTES: usize = 64 * 1024;
const MAX_LIST_PAGES: usize = 1_000;

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
    pub v6_main_ip: String,
    pub firewall_group_id: String,
    pub date_created: String,
    pub tags: Vec<String>,
    pub os_id: u32,
    pub snapshot_id: Option<String>,
    pub enable_ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrSshKey {
    pub id: String,
    pub name: String,
    pub ssh_key: String,
    pub date_created: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrFirewallGroup {
    pub id: String,
    pub description: String,
    pub date_created: String,
    pub date_modified: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrFirewallRule {
    pub id: u64,
    pub ip_type: String,
    pub protocol: String,
    pub subnet: String,
    pub subnet_size: u32,
    pub port: String,
    pub source: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFirewallRuleRequest<'a> {
    pub ip_type: &'a str,
    pub protocol: &'a str,
    pub subnet: &'a str,
    pub subnet_size: u32,
    pub port: &'a str,
    pub source: Option<&'a str>,
    pub notes: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrSnapshot {
    pub id: String,
    pub description: String,
    pub status: String,
    pub os_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrOperatingSystem {
    pub id: u32,
    pub name: String,
    pub arch: String,
    pub family: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrPlan {
    pub id: String,
    pub plan_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VultrRegionAvailability {
    pub available_plans: Vec<String>,
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

    let (body, body_truncated) = read_bounded_error_body(response)
        .await
        .map_err(|err| mutation_transport_error("read Vultr destroy response", err))?;
    let detail = provider_error_detail(&body, body_truncated);

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
    let mut seen_cursors = HashSet::new();
    let mut page_count = 0usize;

    loop {
        page_count += 1;
        if page_count > MAX_LIST_PAGES {
            return Err(VultrError {
                operation: "list Vultr instances",
                kind: VultrErrorKind::Decode,
                status: None,
                retry_after_secs: None,
                detail: format!("pagination exceeded {MAX_LIST_PAGES} pages"),
            });
        }

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

        let next_cursor = page
            .meta
            .and_then(|meta| meta.links)
            .and_then(|links| links.next)
            .filter(|value| !value.trim().is_empty());

        cursor = match next_cursor {
            Some(next) if seen_cursors.insert(next.clone()) => Some(next),
            Some(next) => {
                return Err(VultrError {
                    operation: "list Vultr instances",
                    kind: VultrErrorKind::Decode,
                    status: None,
                    retry_after_secs: None,
                    detail: format!("pagination cursor cycle detected at {next}"),
                });
            }
            None => break,
        };
    }

    Ok(result)
}

pub async fn list_instances(api_key: &str) -> Result<Vec<VultrInstance>, String> {
    list_instances_typed(api_key)
        .await
        .map_err(|err| err.to_string())
}

pub async fn list_ssh_keys_typed(api_key: &str) -> Result<Vec<VultrSshKey>, VultrError> {
    let client = authorized_client(api_key)?;
    let mut result = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();

    for page_count in 1..=MAX_LIST_PAGES {
        let current_cursor = cursor.clone();
        let page: ListSshKeysEnvelope = observation_json("list Vultr SSH keys", || {
            let request = client
                .get(format!("{API_ROOT}/ssh-keys"))
                .query(&[("per_page", "500")]);
            match current_cursor.as_deref() {
                Some(cursor) if !cursor.is_empty() => request.query(&[("cursor", cursor)]),
                _ => request,
            }
        })
        .await?;
        result.extend(page.ssh_keys.into_iter().map(Into::into));
        cursor = next_cursor(
            "list Vultr SSH keys",
            page_count,
            page.meta,
            &mut seen_cursors,
        )?;
        if cursor.is_none() {
            return Ok(result);
        }
    }

    Err(pagination_limit_error("list Vultr SSH keys"))
}

pub async fn get_ssh_key_typed(api_key: &str, ssh_key_id: &str) -> Result<VultrSshKey, VultrError> {
    let client = authorized_client(api_key)?;
    let url = format!("{API_ROOT}/ssh-keys/{ssh_key_id}");
    observation_json("read Vultr SSH key", || client.get(&url))
        .await
        .map(|payload: SshKeyEnvelope| payload.ssh_key.into())
}

pub async fn create_ssh_key_typed(
    api_key: &str,
    name: &str,
    ssh_key: &str,
) -> Result<VultrSshKey, VultrError> {
    if name.trim().is_empty() || ssh_key.trim().is_empty() {
        return Err(configuration_error(
            "create Vultr SSH key",
            "SSH key name and public key material are required",
        ));
    }
    let client = authorized_client(api_key)?;
    execute_json_once(
        "create Vultr SSH key",
        client
            .post(format!("{API_ROOT}/ssh-keys"))
            .json(&CreateSshKeyPayload {
                name: name.to_owned(),
                ssh_key: ssh_key.to_owned(),
            }),
        true,
    )
    .await
    .map(|payload: SshKeyEnvelope| payload.ssh_key.into())
}

pub async fn destroy_ssh_key_typed(api_key: &str, ssh_key_id: &str) -> Result<(), VultrError> {
    let client = authorized_client(api_key)?;
    execute_empty_mutation_once(
        "destroy Vultr SSH key",
        client.delete(format!("{API_ROOT}/ssh-keys/{ssh_key_id}")),
    )
    .await
}

pub async fn list_firewall_groups_typed(
    api_key: &str,
) -> Result<Vec<VultrFirewallGroup>, VultrError> {
    let client = authorized_client(api_key)?;
    let mut result = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();

    for page_count in 1..=MAX_LIST_PAGES {
        let current_cursor = cursor.clone();
        let page: ListFirewallGroupsEnvelope =
            observation_json("list Vultr firewall groups", || {
                let request = client
                    .get(format!("{API_ROOT}/firewalls"))
                    .query(&[("per_page", "500")]);
                match current_cursor.as_deref() {
                    Some(cursor) if !cursor.is_empty() => request.query(&[("cursor", cursor)]),
                    _ => request,
                }
            })
            .await?;
        result.extend(page.firewall_groups.into_iter().map(Into::into));
        cursor = next_cursor(
            "list Vultr firewall groups",
            page_count,
            page.meta,
            &mut seen_cursors,
        )?;
        if cursor.is_none() {
            return Ok(result);
        }
    }

    Err(pagination_limit_error("list Vultr firewall groups"))
}

pub async fn get_firewall_group_typed(
    api_key: &str,
    firewall_group_id: &str,
) -> Result<VultrFirewallGroup, VultrError> {
    let client = authorized_client(api_key)?;
    let url = format!("{API_ROOT}/firewalls/{firewall_group_id}");
    observation_json("read Vultr firewall group", || client.get(&url))
        .await
        .map(|payload: FirewallGroupEnvelope| payload.firewall_group.into())
}

pub async fn create_firewall_group_typed(
    api_key: &str,
    description: &str,
) -> Result<VultrFirewallGroup, VultrError> {
    if description.trim().is_empty() {
        return Err(configuration_error(
            "create Vultr firewall group",
            "firewall description is required",
        ));
    }
    let client = authorized_client(api_key)?;
    execute_json_once(
        "create Vultr firewall group",
        client
            .post(format!("{API_ROOT}/firewalls"))
            .json(&CreateFirewallGroupPayload {
                description: description.to_owned(),
            }),
        true,
    )
    .await
    .map(|payload: FirewallGroupEnvelope| payload.firewall_group.into())
}

pub async fn destroy_firewall_group_typed(
    api_key: &str,
    firewall_group_id: &str,
) -> Result<(), VultrError> {
    let client = authorized_client(api_key)?;
    execute_empty_mutation_once(
        "destroy Vultr firewall group",
        client.delete(format!("{API_ROOT}/firewalls/{firewall_group_id}")),
    )
    .await
}

pub async fn list_firewall_rules_typed(
    api_key: &str,
    firewall_group_id: &str,
) -> Result<Vec<VultrFirewallRule>, VultrError> {
    let client = authorized_client(api_key)?;
    let mut result = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();

    for page_count in 1..=MAX_LIST_PAGES {
        let current_cursor = cursor.clone();
        let page: ListFirewallRulesEnvelope = observation_json("list Vultr firewall rules", || {
            let request = client
                .get(format!("{API_ROOT}/firewalls/{firewall_group_id}/rules"))
                .query(&[("per_page", "500")]);
            match current_cursor.as_deref() {
                Some(cursor) if !cursor.is_empty() => request.query(&[("cursor", cursor)]),
                _ => request,
            }
        })
        .await?;
        result.extend(page.firewall_rules.into_iter().map(Into::into));
        cursor = next_cursor(
            "list Vultr firewall rules",
            page_count,
            page.meta,
            &mut seen_cursors,
        )?;
        if cursor.is_none() {
            return Ok(result);
        }
    }

    Err(pagination_limit_error("list Vultr firewall rules"))
}

pub async fn create_firewall_rule_typed(
    api_key: &str,
    firewall_group_id: &str,
    request: &CreateFirewallRuleRequest<'_>,
) -> Result<VultrFirewallRule, VultrError> {
    if request.ip_type.trim().is_empty()
        || request.protocol.trim().is_empty()
        || request.subnet.trim().is_empty()
    {
        return Err(configuration_error(
            "create Vultr firewall rule",
            "ip_type, protocol, and subnet are required",
        ));
    }
    let client = authorized_client(api_key)?;
    execute_json_once(
        "create Vultr firewall rule",
        client
            .post(format!("{API_ROOT}/firewalls/{firewall_group_id}/rules"))
            .json(&CreateFirewallRulePayload {
                ip_type: request.ip_type.to_owned(),
                protocol: request.protocol.to_owned(),
                subnet: request.subnet.to_owned(),
                subnet_size: request.subnet_size,
                port: request.port.to_owned(),
                source: request.source.map(ToOwned::to_owned),
                notes: request.notes.map(ToOwned::to_owned),
            }),
        true,
    )
    .await
    .map(|payload: FirewallRuleEnvelope| payload.firewall_rule.into())
}

pub async fn destroy_firewall_rule_typed(
    api_key: &str,
    firewall_group_id: &str,
    firewall_rule_id: u64,
) -> Result<(), VultrError> {
    let client = authorized_client(api_key)?;
    execute_empty_mutation_once(
        "destroy Vultr firewall rule",
        client.delete(format!(
            "{API_ROOT}/firewalls/{firewall_group_id}/rules/{firewall_rule_id}"
        )),
    )
    .await
}

pub async fn get_region_availability_typed(
    api_key: &str,
    region: &str,
    plan_type: &str,
) -> Result<VultrRegionAvailability, VultrError> {
    let client = authorized_client(api_key)?;
    let url = format!("{API_ROOT}/regions/{region}/availability");
    observation_json("read Vultr region availability", || {
        client.get(&url).query(&[("type", plan_type)])
    })
    .await
}

pub async fn list_snapshots_typed(api_key: &str) -> Result<Vec<VultrSnapshot>, VultrError> {
    let client = authorized_client(api_key)?;
    let mut result = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();

    for page_count in 1..=MAX_LIST_PAGES {
        let current_cursor = cursor.clone();
        let page: ListSnapshotsEnvelope = observation_json("list Vultr snapshots", || {
            let request = client
                .get(format!("{API_ROOT}/snapshots"))
                .query(&[("per_page", "500")]);
            match current_cursor.as_deref() {
                Some(cursor) if !cursor.is_empty() => request.query(&[("cursor", cursor)]),
                _ => request,
            }
        })
        .await?;
        result.extend(page.snapshots.into_iter().map(Into::into));
        cursor = next_cursor(
            "list Vultr snapshots",
            page_count,
            page.meta,
            &mut seen_cursors,
        )?;
        if cursor.is_none() {
            return Ok(result);
        }
    }

    Err(pagination_limit_error("list Vultr snapshots"))
}

pub async fn list_operating_systems_typed(
    api_key: &str,
) -> Result<Vec<VultrOperatingSystem>, VultrError> {
    let client = authorized_client(api_key)?;
    let mut result = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();

    for page_count in 1..=MAX_LIST_PAGES {
        let current_cursor = cursor.clone();
        let page: ListOperatingSystemsEnvelope =
            observation_json("list Vultr operating systems", || {
                let request = client
                    .get(format!("{API_ROOT}/os"))
                    .query(&[("per_page", "500")]);
                match current_cursor.as_deref() {
                    Some(cursor) if !cursor.is_empty() => request.query(&[("cursor", cursor)]),
                    _ => request,
                }
            })
            .await?;
        result.extend(page.os.into_iter().map(Into::into));
        cursor = next_cursor(
            "list Vultr operating systems",
            page_count,
            page.meta,
            &mut seen_cursors,
        )?;
        if cursor.is_none() {
            return Ok(result);
        }
    }

    Err(pagination_limit_error("list Vultr operating systems"))
}

pub async fn list_plans_typed(
    api_key: &str,
    plan_type: Option<&str>,
) -> Result<Vec<VultrPlan>, VultrError> {
    let client = authorized_client(api_key)?;
    let mut result = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();

    for page_count in 1..=MAX_LIST_PAGES {
        let current_cursor = cursor.clone();
        let page: ListPlansEnvelope = observation_json("list Vultr plans", || {
            let mut request = client
                .get(format!("{API_ROOT}/plans"))
                .query(&[("per_page", "500")]);
            if let Some(plan_type) = plan_type {
                request = request.query(&[("type", plan_type)]);
            }
            if let Some(cursor) = current_cursor.as_deref().filter(|value| !value.is_empty()) {
                request = request.query(&[("cursor", cursor)]);
            }
            request
        })
        .await?;
        result.extend(page.plans.into_iter().map(Into::into));
        cursor = next_cursor("list Vultr plans", page_count, page.meta, &mut seen_cursors)?;
        if cursor.is_none() {
            return Ok(result);
        }
    }

    Err(pagination_limit_error("list Vultr plans"))
}

fn next_cursor(
    operation: &'static str,
    page_count: usize,
    meta: Option<ListMeta>,
    seen_cursors: &mut HashSet<String>,
) -> Result<Option<String>, VultrError> {
    let next = meta
        .and_then(|meta| meta.links)
        .and_then(|links| links.next)
        .filter(|value| !value.trim().is_empty());
    match next {
        Some(next) if seen_cursors.insert(next.clone()) => Ok(Some(next)),
        Some(next) => Err(VultrError {
            operation,
            kind: VultrErrorKind::Decode,
            status: None,
            retry_after_secs: None,
            detail: format!("pagination cursor cycle detected at {next}"),
        }),
        None if page_count <= MAX_LIST_PAGES => Ok(None),
        None => Err(pagination_limit_error(operation)),
    }
}

fn pagination_limit_error(operation: &'static str) -> VultrError {
    VultrError {
        operation,
        kind: VultrErrorKind::Decode,
        status: None,
        retry_after_secs: None,
        detail: format!("pagination exceeded {MAX_LIST_PAGES} pages"),
    }
}

fn configuration_error(operation: &'static str, detail: &str) -> VultrError {
    VultrError {
        operation,
        kind: VultrErrorKind::Configuration,
        status: None,
        retry_after_secs: None,
        detail: detail.to_owned(),
    }
}

async fn execute_empty_mutation_once(
    operation: &'static str,
    request: RequestBuilder,
) -> Result<(), VultrError> {
    let response = request
        .send()
        .await
        .map_err(|err| mutation_transport_error(operation, err))?;
    let status = response.status();
    let retry_after_secs = retry_after_seconds(&response);
    if status.is_success() {
        return Ok(());
    }
    let (body, body_truncated) = read_bounded_error_body(response)
        .await
        .map_err(|err| mutation_transport_error(operation, err))?;
    Err(VultrError {
        operation,
        kind: VultrErrorKind::Http,
        status: Some(status.as_u16()),
        retry_after_secs,
        detail: provider_error_detail(&body, body_truncated),
    })
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

    if !status.is_success() {
        let (body, body_truncated) = read_bounded_error_body(response).await.map_err(|err| {
            if mutation {
                mutation_transport_error(operation, err)
            } else {
                observation_transport_error(operation, err)
            }
        })?;
        return Err(VultrError {
            operation,
            kind: VultrErrorKind::Http,
            status: Some(status.as_u16()),
            retry_after_secs,
            detail: provider_error_detail(&body, body_truncated),
        });
    }

    let bytes = response.bytes().await.map_err(|err| {
        if mutation {
            mutation_transport_error(operation, err)
        } else {
            observation_transport_error(operation, err)
        }
    })?;

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

async fn read_bounded_error_body(
    mut response: reqwest::Response,
) -> Result<(Vec<u8>, bool), reqwest::Error> {
    let mut body = Vec::with_capacity(MAX_PROVIDER_ERROR_BYTES.min(8 * 1024));
    let mut truncated = false;

    while let Some(chunk) = response.chunk().await? {
        let remaining = MAX_PROVIDER_ERROR_BYTES.saturating_sub(body.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    Ok((body, truncated))
}

fn provider_error_detail(body: &[u8], body_truncated: bool) -> String {
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
    if body_truncated || chars.next().is_some() {
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
        v6_main_ip: String::new(),
        firewall_group_id: String::new(),
        date_created: String::new(),
        tags: Vec::new(),
        os_id: 0,
        snapshot_id: None,
        enable_ipv6: false,
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
    if request.os_id.is_some() == request.snapshot_id.is_some() {
        return Err(VultrError {
            operation: "build Vultr create request",
            kind: VultrErrorKind::Configuration,
            status: None,
            retry_after_secs: None,
            detail: "exactly one of os_id or snapshot_id is required".to_owned(),
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

#[derive(Debug, Serialize)]
struct CreateSshKeyPayload {
    name: String,
    ssh_key: String,
}

#[derive(Debug, Serialize)]
struct CreateFirewallGroupPayload {
    description: String,
}

#[derive(Debug, Serialize)]
struct CreateFirewallRulePayload {
    ip_type: String,
    protocol: String,
    subnet: String,
    subnet_size: u32,
    port: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SshKeyEnvelope {
    ssh_key: VultrSshKeyPayload,
}

#[derive(Debug, Deserialize)]
struct ListSshKeysEnvelope {
    ssh_keys: Vec<VultrSshKeyPayload>,
    #[serde(default)]
    meta: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct VultrSshKeyPayload {
    id: String,
    name: String,
    ssh_key: String,
    #[serde(default)]
    date_created: String,
}

impl From<VultrSshKeyPayload> for VultrSshKey {
    fn from(value: VultrSshKeyPayload) -> Self {
        Self {
            id: value.id,
            name: value.name,
            ssh_key: value.ssh_key,
            date_created: value.date_created,
        }
    }
}

#[derive(Debug, Deserialize)]
struct FirewallGroupEnvelope {
    firewall_group: VultrFirewallGroupPayload,
}

#[derive(Debug, Deserialize)]
struct ListFirewallGroupsEnvelope {
    firewall_groups: Vec<VultrFirewallGroupPayload>,
    #[serde(default)]
    meta: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct VultrFirewallGroupPayload {
    id: String,
    description: String,
    #[serde(default)]
    date_created: String,
    #[serde(default)]
    date_modified: String,
}

impl From<VultrFirewallGroupPayload> for VultrFirewallGroup {
    fn from(value: VultrFirewallGroupPayload) -> Self {
        Self {
            id: value.id,
            description: value.description,
            date_created: value.date_created,
            date_modified: value.date_modified,
        }
    }
}

#[derive(Debug, Deserialize)]
struct FirewallRuleEnvelope {
    firewall_rule: VultrFirewallRulePayload,
}

#[derive(Debug, Deserialize)]
struct ListFirewallRulesEnvelope {
    firewall_rules: Vec<VultrFirewallRulePayload>,
    #[serde(default)]
    meta: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct VultrFirewallRulePayload {
    id: u64,
    ip_type: String,
    protocol: String,
    subnet: String,
    subnet_size: u32,
    #[serde(default)]
    port: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    notes: String,
}

impl From<VultrFirewallRulePayload> for VultrFirewallRule {
    fn from(value: VultrFirewallRulePayload) -> Self {
        Self {
            id: value.id,
            ip_type: value.ip_type,
            protocol: value.protocol,
            subnet: value.subnet,
            subnet_size: value.subnet_size,
            port: value.port,
            source: value.source,
            notes: value.notes,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListSnapshotsEnvelope {
    snapshots: Vec<VultrSnapshotPayload>,
    #[serde(default)]
    meta: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct VultrSnapshotPayload {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    os_id: u32,
}

impl From<VultrSnapshotPayload> for VultrSnapshot {
    fn from(value: VultrSnapshotPayload) -> Self {
        Self {
            id: value.id,
            description: value.description,
            status: value.status,
            os_id: value.os_id,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListOperatingSystemsEnvelope {
    os: Vec<VultrOperatingSystemPayload>,
    #[serde(default)]
    meta: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct VultrOperatingSystemPayload {
    id: u32,
    name: String,
    #[serde(default)]
    arch: String,
    #[serde(default)]
    family: String,
}

impl From<VultrOperatingSystemPayload> for VultrOperatingSystem {
    fn from(value: VultrOperatingSystemPayload) -> Self {
        Self {
            id: value.id,
            name: value.name,
            arch: value.arch,
            family: value.family,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListPlansEnvelope {
    plans: Vec<VultrPlanPayload>,
    #[serde(default)]
    meta: Option<ListMeta>,
}

#[derive(Debug, Deserialize)]
struct VultrPlanPayload {
    id: String,
    #[serde(rename = "type", default)]
    plan_type: String,
}

impl From<VultrPlanPayload> for VultrPlan {
    fn from(value: VultrPlanPayload) -> Self {
        Self {
            id: value.id,
            plan_type: value.plan_type,
        }
    }
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
    v6_main_ip: String,
    #[serde(default)]
    firewall_group_id: String,
    #[serde(default)]
    date_created: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    os_id: u32,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    enable_ipv6: bool,
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
            v6_main_ip: value.v6_main_ip,
            firewall_group_id: value.firewall_group_id,
            date_created: value.date_created,
            tags: value.tags,
            os_id: value.os_id,
            snapshot_id: value
                .snapshot_id
                .filter(|snapshot_id| !snapshot_id.trim().is_empty()),
            enable_ipv6: value.enable_ipv6,
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
    fn rejects_create_payload_with_both_image_authorities() {
        let request = CreateInstanceRequest {
            region: "waw",
            plan: "vc2-1c-1gb",
            os_id: Some(2625),
            snapshot_id: Some("snapshot-1"),
            label: "edge-1",
            ssh_key_id: "ssh-key-1",
            cloud_init: "#cloud-config\n",
            firewall_group_id: None,
            tags: Vec::new(),
            enable_ipv6: false,
        };
        let error = build_create_instance_payload(&request).unwrap_err();
        assert_eq!(error.kind, VultrErrorKind::Configuration);
        assert!(error.detail.contains("exactly one"));
    }

    #[test]
    fn decodes_snapshot_and_ipv6_instance_observation() {
        let payload: VultrInstancePayload = serde_json::from_value(serde_json::json!({
            "id": "instance-1",
            "label": "proxy-1",
            "region": "waw",
            "plan": "vc2-1c-1gb",
            "status": "active",
            "server_status": "ok",
            "power_status": "running",
            "main_ip": "203.0.113.10",
            "v6_main_ip": "2001:db8::10",
            "firewall_group_id": "firewall-1",
            "date_created": "2026-09-19T00:00:00+00:00",
            "tags": ["managed-by-sing-box"],
            "os_id": 2625,
            "snapshot_id": "snapshot-1",
            "enable_ipv6": true
        }))
        .unwrap();
        let instance: VultrInstance = payload.into();

        assert_eq!(instance.snapshot_id.as_deref(), Some("snapshot-1"));
        assert!(instance.enable_ipv6);
        assert_eq!(instance.v6_main_ip, "2001:db8::10");
        assert_eq!(instance.date_created, "2026-09-19T00:00:00+00:00");
        assert_eq!(instance.os_id, 2625);
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
    fn detects_repeated_pagination_cursor() {
        let mut seen = HashSet::new();
        assert!(seen.insert("cursor-2".to_owned()));
        assert!(!seen.insert("cursor-2".to_owned()));
    }

    #[test]
    fn marks_byte_truncated_provider_error_detail() {
        let detail = provider_error_detail(b"provider failure", true);
        assert_eq!(detail, "provider failure…");
    }

    #[test]
    fn bounds_provider_error_detail() {
        let body = format!("{{\"error\":\"{}\"}}", "x".repeat(800));
        let detail = provider_error_detail(body.as_bytes(), false);
        assert!(detail.chars().count() <= MAX_PROVIDER_ERROR_CHARS + 1);
        assert!(detail.ends_with('…'));
    }
}
