use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const API_ROOT: &str = "https://api.cloudflare.com/client/v4";
const MAX_API_PAGES: u32 = 1000;
const API_PAGE_SIZE: u32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareDnsRecord {
    pub zone_name: String,
    pub zone_id: String,
    pub record_name: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareDnsObservedRecord {
    pub id: String,
    pub zone_id: String,
    pub record_name: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareMeshNode {
    pub id: String,
    pub name: String,
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareMeshRoute {
    pub id: String,
    pub network: String,
    pub tunnel_id: String,
    pub tunnel_type: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareZeroTrustDeviceSettings {
    pub gateway_proxy_enabled: Option<bool>,
    pub gateway_udp_proxy_enabled: Option<bool>,
    pub use_zt_virtual_ip: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareDeviceProfile {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub precedence: Option<u64>,
    pub match_expression: Option<String>,
    pub service_mode: Option<String>,
    pub tunnel_protocol: Option<String>,
    pub auto_connect: Option<u64>,
    pub switch_locked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareSplitTunnelEntry {
    pub address: Option<String>,
    pub host: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareGatewayRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub action: String,
    pub precedence: Option<u64>,
    pub enabled: Option<bool>,
    pub filters: Vec<String>,
    pub traffic: Option<String>,
    pub identity: Option<String>,
    pub device_posture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareDevicePostureRule {
    pub id: String,
    pub name: String,
    pub rule_type: String,
    pub platforms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareSplitTunnelWrite {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareDeviceProfileWrite {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub precedence: u64,
    #[serde(rename = "match")]
    pub match_expression: String,
    pub service_mode_v2: CloudflareServiceModeWrite,
    pub tunnel_protocol: String,
    pub auto_connect: u64,
    pub switch_locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<CloudflareSplitTunnelWrite>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareServiceModeWrite {
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareGatewayRuleWrite {
    pub name: String,
    pub description: String,
    pub action: String,
    pub enabled: bool,
    pub precedence: u64,
    pub filters: Vec<String>,
    pub traffic: String,
    pub identity: String,
    pub device_posture: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareAccessApplication {
    pub id: String,
    pub name: String,
    pub app_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareAccessPolicy {
    pub id: String,
    pub name: String,
    pub decision: Option<String>,
}

pub async fn upsert_a_record(
    api_token: &str,
    zone_name: &str,
    record_name: &str,
    ip: &str,
) -> Result<CloudflareDnsRecord, String> {
    let client = authorized_client(api_token)?;
    let zone = fetch_zone(&client, zone_name).await?;
    let body = DnsRecordWriteRequest {
        record_type: "A".to_owned(),
        name: record_name.to_owned(),
        content: ip.to_owned(),
        ttl: 120,
        proxied: false,
    };
    let record = fetch_record(&client, &zone.id, record_name).await?;

    if let Some(record) = record {
        let response = client
            .put(format!(
                "{API_ROOT}/zones/{}/dns_records/{}",
                zone.id, record.id
            ))
            .json(&body)
            .send()
            .await
            .map_err(|err| format!("failed to update Cloudflare DNS record: {err}"))?;
        ensure_success(response).await?;
    } else {
        let response = client
            .post(format!("{API_ROOT}/zones/{}/dns_records", zone.id))
            .json(&body)
            .send()
            .await
            .map_err(|err| format!("failed to create Cloudflare DNS record: {err}"))?;
        ensure_success(response).await?;
    }

    Ok(CloudflareDnsRecord {
        zone_name: zone_name.to_owned(),
        zone_id: zone.id,
        record_name: record_name.to_owned(),
        ip: ip.to_owned(),
    })
}

pub async fn delete_a_record(
    api_token: &str,
    zone_name: &str,
    record_name: &str,
) -> Result<(), String> {
    let client = authorized_client(api_token)?;
    let zone = fetch_zone(&client, zone_name).await?;
    let Some(record) = fetch_record(&client, &zone.id, record_name).await? else {
        return Ok(());
    };
    let response = client
        .delete(format!(
            "{API_ROOT}/zones/{}/dns_records/{}",
            zone.id, record.id
        ))
        .send()
        .await
        .map_err(|err| format!("failed to delete Cloudflare DNS record: {err}"))?;
    ensure_success(response).await?;
    Ok(())
}

pub async fn list_a_records(
    api_token: &str,
    zone_name: &str,
    record_name: &str,
) -> Result<Vec<CloudflareDnsObservedRecord>, String> {
    require_non_empty("Cloudflare DNS zone", zone_name)?;
    require_non_empty("Cloudflare DNS record name", record_name)?;
    let client = authorized_client(api_token)?;
    let zone = fetch_zone(&client, zone_name).await?;
    let records = fetch_records(&client, &zone.id, record_name).await?;
    Ok(records
        .into_iter()
        .map(|record| CloudflareDnsObservedRecord {
            id: record.id,
            zone_id: zone.id.clone(),
            record_name: record.name,
            ip: record.content,
        })
        .collect())
}

pub async fn create_a_record(
    api_token: &str,
    zone_name: &str,
    record_name: &str,
    ip: &str,
) -> Result<(), String> {
    let client = authorized_client(api_token)?;
    let zone = fetch_zone(&client, zone_name).await?;
    let body = DnsRecordWriteRequest {
        record_type: "A".to_owned(),
        name: record_name.to_owned(),
        content: ip.to_owned(),
        ttl: 120,
        proxied: false,
    };
    let response = client
        .post(format!("{API_ROOT}/zones/{}/dns_records", zone.id))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("failed to create Cloudflare DNS record: {err}"))?;
    ensure_success(response).await
}

pub async fn update_a_record_by_id(
    api_token: &str,
    zone_name: &str,
    record_id: &str,
    record_name: &str,
    ip: &str,
) -> Result<(), String> {
    require_non_empty("Cloudflare DNS record ID", record_id)?;
    let client = authorized_client(api_token)?;
    let zone = fetch_zone(&client, zone_name).await?;
    let body = DnsRecordWriteRequest {
        record_type: "A".to_owned(),
        name: record_name.to_owned(),
        content: ip.to_owned(),
        ttl: 120,
        proxied: false,
    };
    let response = client
        .put(format!(
            "{API_ROOT}/zones/{}/dns_records/{record_id}",
            zone.id
        ))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("failed to update Cloudflare DNS record: {err}"))?;
    ensure_success(response).await
}

pub async fn delete_a_record_by_id(
    api_token: &str,
    zone_name: &str,
    record_id: &str,
) -> Result<(), String> {
    require_non_empty("Cloudflare DNS record ID", record_id)?;
    let client = authorized_client(api_token)?;
    let zone = fetch_zone(&client, zone_name).await?;
    let response = client
        .delete(format!(
            "{API_ROOT}/zones/{}/dns_records/{record_id}",
            zone.id
        ))
        .send()
        .await
        .map_err(|err| format!("failed to delete Cloudflare DNS record: {err}"))?;
    ensure_success(response).await
}

pub async fn list_mesh_nodes(
    api_token: &str,
    account_id: &str,
    exact_name: Option<&str>,
) -> Result<Vec<CloudflareMeshNode>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    if let Some(name) = exact_name {
        require_non_empty("Cloudflare Mesh node name", name)?;
    }

    let client = authorized_client(api_token)?;
    let mut result = Vec::new();
    for page in 1..=MAX_API_PAGES {
        let mut query = vec![
            ("is_deleted", "false".to_owned()),
            ("page", page.to_string()),
            ("per_page", API_PAGE_SIZE.to_string()),
        ];
        if let Some(name) = exact_name {
            query.push(("name", name.to_owned()));
        }
        let response = client
            .get(format!("{API_ROOT}/accounts/{account_id}/warp_connector"))
            .query(&query)
            .send()
            .await
            .map_err(|err| format!("failed to list Cloudflare Mesh nodes: {err}"))?;
        let payload: ApiEnvelope<Vec<MeshNodeRecord>> = parse_success_json(response).await?;
        let page_count = payload.result.len();
        result.extend(
            payload
                .result
                .into_iter()
                .map(mesh_node_from_record)
                .filter(|node| exact_name.is_none_or(|name| node.name == name)),
        );
        if page_is_complete(page_count) {
            return Ok(result);
        }
    }
    Err(format!(
        "Cloudflare Mesh node pagination exceeded {MAX_API_PAGES} pages"
    ))
}

pub async fn get_mesh_node(
    api_token: &str,
    account_id: &str,
    node_id: &str,
) -> Result<CloudflareMeshNode, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Mesh node ID", node_id)?;
    let client = authorized_client(api_token)?;
    let response = client
        .get(format!(
            "{API_ROOT}/accounts/{account_id}/warp_connector/{node_id}"
        ))
        .send()
        .await
        .map_err(|err| format!("failed to get Cloudflare Mesh node: {err}"))?;
    let payload: ApiEnvelope<MeshNodeRecord> = parse_success_json(response).await?;
    Ok(mesh_node_from_record(payload.result))
}

pub async fn create_mesh_node(
    api_token: &str,
    account_id: &str,
    name: &str,
) -> Result<CloudflareMeshNode, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Mesh node name", name)?;

    let client = authorized_client(api_token)?;
    let response = client
        .post(format!("{API_ROOT}/accounts/{account_id}/warp_connector"))
        .json(&MeshNodeWriteRequest {
            name: name.to_owned(),
        })
        .send()
        .await
        .map_err(|err| format!("failed to create Cloudflare Mesh node: {err}"))?;
    let payload: ApiEnvelope<MeshNodeRecord> = parse_success_json(response).await?;
    Ok(mesh_node_from_record(payload.result))
}

pub async fn get_mesh_node_token(
    api_token: &str,
    account_id: &str,
    node_id: &str,
) -> Result<String, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Mesh node ID", node_id)?;

    let client = authorized_client(api_token)?;
    let response = client
        .get(format!(
            "{API_ROOT}/accounts/{account_id}/warp_connector/{node_id}/token"
        ))
        .send()
        .await
        .map_err(|err| format!("failed to get Cloudflare Mesh node token: {err}"))?;
    let payload: ApiEnvelope<String> = parse_success_json(response).await?;
    require_non_empty("Cloudflare Mesh node token", &payload.result)?;
    Ok(payload.result)
}

pub async fn delete_mesh_node(
    api_token: &str,
    account_id: &str,
    node_id: &str,
) -> Result<(), String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Mesh node ID", node_id)?;

    let client = authorized_client(api_token)?;
    let response = client
        .delete(format!(
            "{API_ROOT}/accounts/{account_id}/warp_connector/{node_id}"
        ))
        .send()
        .await
        .map_err(|err| format!("failed to delete Cloudflare Mesh node: {err}"))?;
    ensure_success(response).await
}

pub async fn list_mesh_routes(
    api_token: &str,
    account_id: &str,
    node_id: &str,
) -> Result<Vec<CloudflareMeshRoute>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Mesh node ID", node_id)?;

    let client = authorized_client(api_token)?;
    let mut result = Vec::new();
    for page in 1..=MAX_API_PAGES {
        let query = mesh_route_list_query(node_id, page);
        let response = client
            .get(format!("{API_ROOT}/accounts/{account_id}/teamnet/routes"))
            .query(&query)
            .send()
            .await
            .map_err(|err| format!("failed to list Cloudflare Mesh routes: {err}"))?;
        let payload: ApiEnvelope<Vec<MeshRouteRecord>> = parse_success_json(response).await?;
        let page_count = payload.result.len();
        result.extend(
            payload
                .result
                .into_iter()
                .map(mesh_route_from_record)
                .filter(|route| {
                    route.tunnel_id == node_id
                        && route.tunnel_type.as_deref() == Some("warp_connector")
                }),
        );
        if page_is_complete(page_count) {
            return Ok(result);
        }
    }
    Err(format!(
        "Cloudflare Mesh route pagination exceeded {MAX_API_PAGES} pages"
    ))
}

pub async fn create_mesh_cidr_route(
    api_token: &str,
    account_id: &str,
    node_id: &str,
    network: &str,
    comment: Option<&str>,
) -> Result<CloudflareMeshRoute, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Mesh node ID", node_id)?;
    require_non_empty("Cloudflare Mesh CIDR route", network)?;
    validate_mesh_route_comment(comment)?;

    let client = authorized_client(api_token)?;
    let response = client
        .post(format!("{API_ROOT}/accounts/{account_id}/teamnet/routes"))
        .json(&MeshRouteWriteRequest {
            network: network.to_owned(),
            tunnel_id: node_id.to_owned(),
            comment: comment.map(ToOwned::to_owned),
        })
        .send()
        .await
        .map_err(|err| format!("failed to create Cloudflare Mesh CIDR route: {err}"))?;
    let payload: ApiEnvelope<MeshRouteRecord> = parse_success_json(response).await?;
    Ok(mesh_route_from_record(payload.result))
}

pub async fn delete_mesh_cidr_route(
    api_token: &str,
    account_id: &str,
    route_id: &str,
) -> Result<(), String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Mesh route ID", route_id)?;

    let client = authorized_client(api_token)?;
    let response = client
        .delete(format!(
            "{API_ROOT}/accounts/{account_id}/teamnet/routes/{route_id}"
        ))
        .send()
        .await
        .map_err(|err| format!("failed to delete Cloudflare Mesh CIDR route: {err}"))?;
    ensure_success(response).await
}

pub async fn get_zero_trust_device_settings(
    api_token: &str,
    account_id: &str,
) -> Result<CloudflareZeroTrustDeviceSettings, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    let client = authorized_client(api_token)?;
    let response = client
        .get(format!("{API_ROOT}/accounts/{account_id}/devices/settings"))
        .send()
        .await
        .map_err(|err| format!("failed to get Cloudflare Zero Trust device settings: {err}"))?;
    let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
    let result = payload
        .result
        .as_object()
        .ok_or_else(|| "Cloudflare device settings result must be an object".to_owned())?;
    Ok(CloudflareZeroTrustDeviceSettings {
        gateway_proxy_enabled: result.get("gateway_proxy_enabled").and_then(Value::as_bool),
        gateway_udp_proxy_enabled: result
            .get("gateway_udp_proxy_enabled")
            .and_then(Value::as_bool),
        use_zt_virtual_ip: result.get("use_zt_virtual_ip").and_then(Value::as_bool),
    })
}

pub async fn list_device_profiles(
    api_token: &str,
    account_id: &str,
) -> Result<Vec<CloudflareDeviceProfile>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    let client = authorized_client(api_token)?;
    let mut profiles = Vec::new();
    let mut default_policy_seen = false;
    for page in 1..=MAX_API_PAGES {
        let response = client
            .get(format!("{API_ROOT}/accounts/{account_id}/devices/policies"))
            .query(&[("page", page.to_string()), ("per_page", "50".to_owned())])
            .send()
            .await
            .map_err(|err| format!("failed to list Cloudflare device profiles: {err}"))?;
        let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
        let values = value_array(payload.result, "Cloudflare device profiles")?;
        let page_count = values.len();
        profiles.extend(device_profiles_from_list_values(
            values,
            &mut default_policy_seen,
        )?);
        if page_count < 50 {
            return Ok(profiles);
        }
    }
    Err(format!(
        "Cloudflare device profile pagination exceeded {MAX_API_PAGES} pages"
    ))
}

pub async fn create_device_profile(
    api_token: &str,
    account_id: &str,
    request: &CloudflareDeviceProfileWrite,
) -> Result<CloudflareDeviceProfile, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    let client = authorized_client(api_token)?;
    let response = client
        .post(format!("{API_ROOT}/accounts/{account_id}/devices/policy"))
        .json(request)
        .send()
        .await
        .map_err(|err| format!("failed to create Cloudflare device profile: {err}"))?;
    let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
    device_profile_from_value(payload.result)
}

pub async fn update_device_profile(
    api_token: &str,
    account_id: &str,
    profile_id: &str,
    request: &CloudflareDeviceProfileWrite,
) -> Result<CloudflareDeviceProfile, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare device profile ID", profile_id)?;
    let client = authorized_client(api_token)?;
    let response = client
        .patch(format!(
            "{API_ROOT}/accounts/{account_id}/devices/policy/{profile_id}"
        ))
        .json(request)
        .send()
        .await
        .map_err(|err| format!("failed to update Cloudflare device profile: {err}"))?;
    let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
    device_profile_from_value(payload.result)
}

pub async fn get_device_profile_includes(
    api_token: &str,
    account_id: &str,
    profile_id: &str,
) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
    get_device_profile_split_tunnels(api_token, account_id, profile_id, "include").await
}

pub async fn get_device_profile_excludes(
    api_token: &str,
    account_id: &str,
    profile_id: &str,
) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
    get_device_profile_split_tunnels(api_token, account_id, profile_id, "exclude").await
}

async fn get_device_profile_split_tunnels(
    api_token: &str,
    account_id: &str,
    profile_id: &str,
    kind: &str,
) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare device profile ID", profile_id)?;
    if !matches!(kind, "include" | "exclude") {
        return Err("Cloudflare split tunnel kind must be include or exclude".to_owned());
    }
    let client = authorized_client(api_token)?;
    let response = client
        .get(format!(
            "{API_ROOT}/accounts/{account_id}/devices/policy/{profile_id}/{kind}"
        ))
        .send()
        .await
        .map_err(|err| format!("failed to get Cloudflare device profile {kind} list: {err}"))?;
    let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
    value_array(payload.result, "Cloudflare split tunnel list")?
        .into_iter()
        .map(split_tunnel_from_value)
        .collect()
}

pub async fn set_device_profile_includes(
    api_token: &str,
    account_id: &str,
    profile_id: &str,
    entries: &[CloudflareSplitTunnelWrite],
) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
    set_device_profile_split_tunnels(api_token, account_id, profile_id, "include", entries).await
}

pub async fn set_device_profile_excludes(
    api_token: &str,
    account_id: &str,
    profile_id: &str,
    entries: &[CloudflareSplitTunnelWrite],
) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
    set_device_profile_split_tunnels(api_token, account_id, profile_id, "exclude", entries).await
}

async fn set_device_profile_split_tunnels(
    api_token: &str,
    account_id: &str,
    profile_id: &str,
    kind: &str,
    entries: &[CloudflareSplitTunnelWrite],
) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare device profile ID", profile_id)?;
    if !matches!(kind, "include" | "exclude") {
        return Err("Cloudflare split tunnel kind must be include or exclude".to_owned());
    }
    for entry in entries {
        if entry.address.is_some() == entry.host.is_some() {
            return Err(
                "Cloudflare split tunnel write requires exactly one of address or host".to_owned(),
            );
        }
        if entry
            .description
            .as_ref()
            .is_some_and(|value| value.len() > 100)
        {
            return Err(
                "Cloudflare split tunnel description must be at most 100 characters".to_owned(),
            );
        }
    }
    let client = authorized_client(api_token)?;
    let response = client
        .put(format!(
            "{API_ROOT}/accounts/{account_id}/devices/policy/{profile_id}/{kind}"
        ))
        .json(entries)
        .send()
        .await
        .map_err(|err| format!("failed to set Cloudflare device profile {kind} list: {err}"))?;
    let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
    value_array(payload.result, "Cloudflare split tunnel list")?
        .into_iter()
        .map(split_tunnel_from_value)
        .collect()
}

pub async fn list_gateway_rules(
    api_token: &str,
    account_id: &str,
) -> Result<Vec<CloudflareGatewayRule>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    let client = authorized_client(api_token)?;
    let mut rules = Vec::new();
    for page in 1..=MAX_API_PAGES {
        let response = client
            .get(format!("{API_ROOT}/accounts/{account_id}/gateway/rules"))
            .query(&[
                ("order_by", "precedence".to_owned()),
                ("direction", "asc".to_owned()),
                ("page", page.to_string()),
                ("per_page", "50".to_owned()),
            ])
            .send()
            .await
            .map_err(|err| format!("failed to list Cloudflare Gateway rules: {err}"))?;
        let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
        let values = value_array(payload.result, "Cloudflare Gateway rules")?;
        let page_count = values.len();
        for value in values {
            rules.push(gateway_rule_from_value(value)?);
        }
        if page_count < 50 {
            rules.sort_by_key(|rule| rule.precedence.unwrap_or(u64::MAX));
            return Ok(rules);
        }
    }
    Err(format!(
        "Cloudflare Gateway rule pagination exceeded {MAX_API_PAGES} pages"
    ))
}

pub async fn list_device_posture_rules(
    api_token: &str,
    account_id: &str,
) -> Result<Vec<CloudflareDevicePostureRule>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    let client = authorized_client(api_token)?;
    let mut rules = Vec::new();
    for page in 1..=MAX_API_PAGES {
        let response = client
            .get(format!("{API_ROOT}/accounts/{account_id}/devices/posture"))
            .query(&[("page", page.to_string()), ("per_page", "50".to_owned())])
            .send()
            .await
            .map_err(|err| format!("failed to list Cloudflare device posture rules: {err}"))?;
        let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
        let values = value_array(payload.result, "Cloudflare device posture rules")?;
        let page_count = values.len();
        for value in values {
            rules.push(device_posture_rule_from_value(value)?);
        }
        if page_count < 50 {
            return Ok(rules);
        }
    }
    Err(format!(
        "Cloudflare device posture pagination exceeded {MAX_API_PAGES} pages"
    ))
}

pub async fn create_gateway_rule(
    api_token: &str,
    account_id: &str,
    request: &CloudflareGatewayRuleWrite,
) -> Result<CloudflareGatewayRule, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    let client = authorized_client(api_token)?;
    let response = client
        .post(format!("{API_ROOT}/accounts/{account_id}/gateway/rules"))
        .json(request)
        .send()
        .await
        .map_err(|err| format!("failed to create Cloudflare Gateway rule: {err}"))?;
    let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
    gateway_rule_from_value(payload.result)
}

pub async fn update_gateway_rule(
    api_token: &str,
    account_id: &str,
    rule_id: &str,
    request: &CloudflareGatewayRuleWrite,
) -> Result<CloudflareGatewayRule, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Gateway rule ID", rule_id)?;
    let client = authorized_client(api_token)?;
    let response = client
        .put(format!(
            "{API_ROOT}/accounts/{account_id}/gateway/rules/{rule_id}"
        ))
        .json(request)
        .send()
        .await
        .map_err(|err| format!("failed to update Cloudflare Gateway rule: {err}"))?;
    let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
    gateway_rule_from_value(payload.result)
}

pub async fn list_access_applications(
    api_token: &str,
    account_id: &str,
) -> Result<Vec<CloudflareAccessApplication>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    let client = authorized_client(api_token)?;
    let mut applications = Vec::new();
    for page in 1..=MAX_API_PAGES {
        let response = client
            .get(format!("{API_ROOT}/accounts/{account_id}/access/apps"))
            .query(&[("page", page.to_string()), ("per_page", "50".to_owned())])
            .send()
            .await
            .map_err(|err| format!("failed to list Cloudflare Access applications: {err}"))?;
        let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
        let values = value_array(payload.result, "Cloudflare Access applications")?;
        let page_count = values.len();
        for value in values {
            applications.push(access_application_from_value(value)?);
        }
        if page_count < 50 {
            return Ok(applications);
        }
    }
    Err(format!(
        "Cloudflare Access application pagination exceeded {MAX_API_PAGES} pages"
    ))
}

pub async fn list_access_application_policies(
    api_token: &str,
    account_id: &str,
    app_id: &str,
) -> Result<Vec<CloudflareAccessPolicy>, String> {
    require_non_empty("Cloudflare account ID", account_id)?;
    require_non_empty("Cloudflare Access application ID", app_id)?;
    let client = authorized_client(api_token)?;
    let response = client
        .get(format!(
            "{API_ROOT}/accounts/{account_id}/access/apps/{app_id}/policies"
        ))
        .send()
        .await
        .map_err(|err| format!("failed to list Cloudflare Access application policies: {err}"))?;
    let payload: ApiEnvelope<Value> = parse_success_json(response).await?;
    value_array(payload.result, "Cloudflare Access application policies")?
        .into_iter()
        .map(access_policy_from_value)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ListedDeviceProfile {
    Default,
    Custom(CloudflareDeviceProfile),
}

fn device_profiles_from_list_values(
    values: Vec<Value>,
    default_policy_seen: &mut bool,
) -> Result<Vec<CloudflareDeviceProfile>, String> {
    let mut profiles = Vec::new();
    for value in values {
        match listed_device_profile_from_value(value)? {
            ListedDeviceProfile::Default => {
                if *default_policy_seen {
                    return Err(
                        "Cloudflare device profile list contained more than one default policy"
                            .to_owned(),
                    );
                }
                *default_policy_seen = true;
            }
            ListedDeviceProfile::Custom(profile) => profiles.push(profile),
        }
    }
    Ok(profiles)
}

fn listed_device_profile_from_value(value: Value) -> Result<ListedDeviceProfile, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Cloudflare device profile must be an object".to_owned())?;

    let is_default = match object.get("default") {
        Some(Value::Bool(value)) => *value,
        Some(_) => {
            return Err(
                "Cloudflare device profile field default must be a boolean when present".to_owned(),
            );
        }
        None => false,
    };

    if is_default {
        optional_value_string(object, "policy_id")
            .or_else(|| optional_value_string(object, "id"))
            .ok_or_else(|| {
                "Cloudflare default device profile field policy_id/id is required".to_owned()
            })?;

        if let Some(name) = object.get("name") {
            name.as_str()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    "Cloudflare default device profile field name must be a non-empty string when present"
                        .to_owned()
                })?;
        }

        return Ok(ListedDeviceProfile::Default);
    }

    device_profile_from_value(value).map(ListedDeviceProfile::Custom)
}

fn device_profile_from_value(value: Value) -> Result<CloudflareDeviceProfile, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Cloudflare device profile must be an object".to_owned())?;
    Ok(CloudflareDeviceProfile {
        id: optional_value_string(object, "policy_id")
            .or_else(|| optional_value_string(object, "id"))
            .ok_or_else(|| "Cloudflare device profile field policy_id/id is required".to_owned())?,
        name: required_value_string(object, "name", "Cloudflare device profile")?,
        description: object
            .get("description")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        enabled: object.get("enabled").and_then(Value::as_bool),
        precedence: object.get("precedence").and_then(Value::as_u64),
        match_expression: object
            .get("match")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        service_mode: object
            .get("service_mode_v2")
            .and_then(Value::as_object)
            .and_then(|mode| mode.get("mode"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        tunnel_protocol: object
            .get("tunnel_protocol")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        auto_connect: object.get("auto_connect").and_then(Value::as_u64),
        switch_locked: object.get("switch_locked").and_then(Value::as_bool),
    })
}

fn split_tunnel_from_value(value: Value) -> Result<CloudflareSplitTunnelEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Cloudflare split tunnel entry must be an object".to_owned())?;
    let address = optional_value_string(object, "address");
    let host = optional_value_string(object, "host");
    if address.is_some() == host.is_some() {
        return Err(
            "Cloudflare split tunnel entry requires exactly one of address or host".to_owned(),
        );
    }
    Ok(CloudflareSplitTunnelEntry {
        address,
        host,
        description: object
            .get("description")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn gateway_rule_from_value(value: Value) -> Result<CloudflareGatewayRule, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Cloudflare Gateway rule must be an object".to_owned())?;
    Ok(CloudflareGatewayRule {
        id: required_value_string(object, "id", "Cloudflare Gateway rule")?,
        name: required_value_string(object, "name", "Cloudflare Gateway rule")?,
        description: object
            .get("description")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        action: required_value_string(object, "action", "Cloudflare Gateway rule")?,
        precedence: object.get("precedence").and_then(Value::as_u64),
        enabled: object.get("enabled").and_then(Value::as_bool),
        filters: object
            .get("filters")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        traffic: object
            .get("traffic")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        identity: object
            .get("identity")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        device_posture: object
            .get("device_posture")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn device_posture_rule_from_value(value: Value) -> Result<CloudflareDevicePostureRule, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Cloudflare device posture rule must be an object".to_owned())?;
    let platforms = object
        .get("match")
        .and_then(Value::as_array)
        .map(|matches| {
            matches
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|entry| entry.get("platform"))
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(CloudflareDevicePostureRule {
        id: required_value_string(object, "id", "Cloudflare device posture rule")?,
        name: required_value_string(object, "name", "Cloudflare device posture rule")?,
        rule_type: required_value_string(object, "type", "Cloudflare device posture rule")?,
        platforms,
    })
}

fn access_application_from_value(value: Value) -> Result<CloudflareAccessApplication, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Cloudflare Access application must be an object".to_owned())?;
    Ok(CloudflareAccessApplication {
        id: required_value_string(object, "id", "Cloudflare Access application")?,
        name: required_value_string(object, "name", "Cloudflare Access application")?,
        app_type: required_value_string(object, "type", "Cloudflare Access application")?,
    })
}

fn access_policy_from_value(value: Value) -> Result<CloudflareAccessPolicy, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Cloudflare Access policy must be an object".to_owned())?;
    Ok(CloudflareAccessPolicy {
        id: required_value_string(object, "id", "Cloudflare Access policy")?,
        name: required_value_string(object, "name", "Cloudflare Access policy")?,
        decision: object
            .get("decision")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn optional_value_string(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn required_value_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{label} field {key} is required"))
}

fn value_array(value: Value, label: &str) -> Result<Vec<Value>, String> {
    value
        .as_array()
        .cloned()
        .ok_or_else(|| format!("{label} result must be an array"))
}

pub fn mock_upsert_a_record(zone_name: &str, record_name: &str, ip: &str) -> CloudflareDnsRecord {
    CloudflareDnsRecord {
        zone_name: zone_name.to_owned(),
        zone_id: format!("mock-zone-{}", zone_name.replace('.', "-")),
        record_name: record_name.to_owned(),
        ip: ip.to_owned(),
    }
}

fn mesh_node_from_record(record: MeshNodeRecord) -> CloudflareMeshNode {
    CloudflareMeshNode {
        id: record.id,
        name: record.name,
        status: record.status,
    }
}

fn mesh_route_from_record(record: MeshRouteRecord) -> CloudflareMeshRoute {
    CloudflareMeshRoute {
        id: record.id,
        network: record.network,
        tunnel_id: record.tunnel_id,
        tunnel_type: record.tun_type,
        comment: record.comment,
    }
}

fn mesh_route_list_query(node_id: &str, page: u32) -> Vec<(&'static str, String)> {
    vec![
        ("is_deleted", "false".to_owned()),
        ("tun_type", "warp_connector".to_owned()),
        ("tunnel_id", node_id.to_owned()),
        ("page", page.to_string()),
        ("per_page", API_PAGE_SIZE.to_string()),
    ]
}

fn page_is_complete(page_count: usize) -> bool {
    page_count < API_PAGE_SIZE as usize
}

fn validate_mesh_route_comment(comment: Option<&str>) -> Result<(), String> {
    if comment.is_some_and(|value| value.len() > 100) {
        return Err("Cloudflare Mesh route comment must be at most 100 characters".to_owned());
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

fn authorized_client(api_token: &str) -> Result<Client, String> {
    if api_token.trim().is_empty() {
        return Err("Cloudflare API token is required".to_owned());
    }
    Client::builder()
        .user_agent("edge-platform/0.1")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .default_headers(
            [(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {api_token}")
                    .parse()
                    .map_err(|err| format!("failed to build Cloudflare auth header: {err}"))?,
            )]
            .into_iter()
            .collect(),
        )
        .build()
        .map_err(|err| format!("failed to build Cloudflare HTTP client: {err}"))
}

async fn fetch_zone(client: &Client, zone_name: &str) -> Result<ZoneRecord, String> {
    let response = client
        .get(format!("{API_ROOT}/zones"))
        .query(&[("name", zone_name)])
        .send()
        .await
        .map_err(|err| format!("failed to query Cloudflare zones: {err}"))?;
    let payload: ApiEnvelope<Vec<ZoneRecord>> = parse_success_json(response).await?;
    payload
        .result
        .into_iter()
        .next()
        .ok_or_else(|| format!("Cloudflare zone not found: {zone_name}"))
}

async fn fetch_record(
    client: &Client,
    zone_id: &str,
    record_name: &str,
) -> Result<Option<DnsRecord>, String> {
    Ok(fetch_records(client, zone_id, record_name)
        .await?
        .into_iter()
        .next())
}

async fn fetch_records(
    client: &Client,
    zone_id: &str,
    record_name: &str,
) -> Result<Vec<DnsRecord>, String> {
    let response = client
        .get(format!("{API_ROOT}/zones/{zone_id}/dns_records"))
        .query(&[("type", "A"), ("name", record_name), ("per_page", "100")])
        .send()
        .await
        .map_err(|err| format!("failed to query Cloudflare DNS records: {err}"))?;
    let payload: ApiEnvelope<Vec<DnsRecord>> = parse_success_json(response).await?;
    Ok(payload.result)
}

async fn ensure_success(response: reqwest::Response) -> Result<(), String> {
    let _: ApiEnvelope<serde_json::Value> = parse_success_json(response).await?;
    Ok(())
}

async fn parse_success_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<ApiEnvelope<T>, String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("failed to read Cloudflare response body: {err}"))?;
    if !status.is_success() {
        return Err(format!("Cloudflare API returned {status}: {body}"));
    }
    let payload: ApiEnvelope<T> = serde_json::from_str(&body)
        .map_err(|err| format!("invalid Cloudflare JSON payload: {err}"))?;
    if !payload.success {
        let errors = payload
            .errors
            .iter()
            .map(|error| {
                error
                    .message
                    .as_deref()
                    .unwrap_or("unspecified Cloudflare API error")
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("Cloudflare API reported success=false: {errors}"));
    }
    Ok(payload)
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    success: bool,
    result: T,
    #[serde(default)]
    errors: Vec<ApiResponseInfo>,
}

#[derive(Debug, Deserialize)]
struct ApiResponseInfo {
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZoneRecord {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct MeshNodeRecord {
    id: String,
    name: String,
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct MeshNodeWriteRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct MeshRouteRecord {
    id: String,
    network: String,
    tunnel_id: String,
    #[serde(default)]
    tun_type: Option<String>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, Serialize)]
struct MeshRouteWriteRequest {
    network: String,
    tunnel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

#[derive(Debug, Serialize)]
struct DnsRecordWriteRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
    proxied: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_mock_cloudflare_record() {
        let record = mock_upsert_a_record("example.com", "edge.example.com", "203.0.113.10");
        assert_eq!(record.zone_id, "mock-zone-example-com");
        assert_eq!(record.record_name, "edge.example.com");
    }

    #[test]
    fn serializes_dns_request_body() {
        let body = serde_json::to_value(DnsRecordWriteRequest {
            record_type: "A".to_owned(),
            name: "edge.example.com".to_owned(),
            content: "203.0.113.10".to_owned(),
            ttl: 120,
            proxied: false,
        })
        .unwrap();
        assert_eq!(body["type"], "A");
        assert_eq!(body["name"], "edge.example.com");
    }

    #[test]
    fn serializes_mesh_node_request_body() {
        let body = serde_json::to_value(MeshNodeWriteRequest {
            name: "vultr-waw-line3".to_owned(),
        })
        .unwrap();
        assert_eq!(body["name"], "vultr-waw-line3");
    }

    #[test]
    fn serializes_current_route_id_api_request_body() {
        let body = serde_json::to_value(MeshRouteWriteRequest {
            network: "203.0.113.0/24".to_owned(),
            tunnel_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            comment: Some("line-3-poc".to_owned()),
        })
        .unwrap();
        assert_eq!(body["network"], "203.0.113.0/24");
        assert_eq!(body["tunnel_id"], "11111111-1111-1111-1111-111111111111");
        assert_eq!(body["comment"], "line-3-poc");
    }

    #[test]
    fn mesh_route_list_query_uses_current_tun_type_contract() {
        let query = mesh_route_list_query("11111111-1111-1111-1111-111111111111", 7);
        assert!(query.contains(&("tun_type", "warp_connector".to_owned())));
        assert!(!query.iter().any(|(key, _)| *key == "tun_types"));
        assert!(query.contains(&(
            "tunnel_id",
            "11111111-1111-1111-1111-111111111111".to_owned()
        )));
        assert!(query.contains(&("page", "7".to_owned())));
        assert!(query.contains(&("per_page", "1000".to_owned())));
    }

    #[test]
    fn pagination_continues_only_for_full_pages() {
        assert!(!page_is_complete(API_PAGE_SIZE as usize));
        assert!(page_is_complete((API_PAGE_SIZE - 1) as usize));
        assert!(page_is_complete(0));
    }

    #[test]
    fn route_comment_is_bounded() {
        let valid = "x".repeat(100);
        let invalid = "x".repeat(101);
        assert!(validate_mesh_route_comment(Some(&valid)).is_ok());
        assert!(validate_mesh_route_comment(None).is_ok());
        assert_eq!(
            validate_mesh_route_comment(Some(&invalid)).unwrap_err(),
            "Cloudflare Mesh route comment must be at most 100 characters"
        );
    }

    #[test]
    fn exact_mesh_observation_filters_provider_overmatch() {
        let exact = ["wanted", "other"]
            .into_iter()
            .map(|name| {
                mesh_node_from_record(MeshNodeRecord {
                    id: format!("id-{name}"),
                    name: name.to_owned(),
                    status: Some("healthy".to_owned()),
                })
            })
            .filter(|node| node.name == "wanted")
            .collect::<Vec<_>>();
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].name, "wanted");

        let routes = [
            MeshRouteRecord {
                id: "route-1".to_owned(),
                network: "203.0.113.0/24".to_owned(),
                tunnel_id: "node-1".to_owned(),
                tun_type: Some("warp_connector".to_owned()),
                comment: None,
            },
            MeshRouteRecord {
                id: "route-2".to_owned(),
                network: "198.51.100.0/24".to_owned(),
                tunnel_id: "node-2".to_owned(),
                tun_type: Some("warp_connector".to_owned()),
                comment: None,
            },
            MeshRouteRecord {
                id: "route-3".to_owned(),
                network: "192.0.2.0/24".to_owned(),
                tunnel_id: "node-1".to_owned(),
                tun_type: Some("cfd_tunnel".to_owned()),
                comment: None,
            },
        ]
        .into_iter()
        .map(mesh_route_from_record)
        .filter(|route| {
            route.tunnel_id == "node-1" && route.tunnel_type.as_deref() == Some("warp_connector")
        })
        .collect::<Vec<_>>();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].id, "route-1");
    }

    #[test]
    fn serializes_zero_trust_device_profile_write_contract() {
        let value = serde_json::to_value(CloudflareDeviceProfileWrite {
            name: "sing-box Mesh nodes".to_owned(),
            description: "Project Mesh nodes".to_owned(),
            enabled: true,
            precedence: 100,
            match_expression: "identity.email == \"warp_connector@example.cloudflareaccess.com\""
                .to_owned(),
            service_mode_v2: CloudflareServiceModeWrite {
                mode: "warp".to_owned(),
            },
            tunnel_protocol: "masque".to_owned(),
            auto_connect: 1,
            switch_locked: true,
            include: Some(vec![CloudflareSplitTunnelWrite {
                address: Some("100.96.0.0/12".to_owned()),
                host: None,
                description: Some("Cloudflare Mesh device IPs".to_owned()),
            }]),
        })
        .unwrap();

        assert_eq!(
            value["match"],
            "identity.email == \"warp_connector@example.cloudflareaccess.com\""
        );
        assert_eq!(value["service_mode_v2"]["mode"], "warp");
        assert_eq!(value["tunnel_protocol"], "masque");
        assert_eq!(value["auto_connect"], 1);
        assert_eq!(value["switch_locked"], true);
        assert_eq!(value["include"][0]["address"], "100.96.0.0/12");
        assert!(value.get("exclude").is_none());
    }

    #[test]
    fn serializes_zero_trust_gateway_write_contract() {
        let value = serde_json::to_value(CloudflareGatewayRuleWrite {
            name: "sing-box Mesh Android allow".to_owned(),
            description: "Project Mesh allow".to_owned(),
            action: "allow".to_owned(),
            enabled: true,
            precedence: 9999,
            filters: vec!["l4".to_owned()],
            traffic: "net.dst.ip in {100.96.0.0/12}".to_owned(),
            identity: "identity.email == \"android@example.com\"".to_owned(),
            device_posture: "any(device_posture.checks.passed[*] in {\"posture-android\"})"
                .to_owned(),
        })
        .unwrap();

        assert_eq!(value["action"], "allow");
        assert_eq!(value["filters"][0], "l4");
        assert_eq!(value["traffic"], "net.dst.ip in {100.96.0.0/12}");
        assert_eq!(
            value["identity"],
            "identity.email == \"android@example.com\""
        );
        assert!(
            value["device_posture"]
                .as_str()
                .unwrap()
                .contains("posture-android")
        );
    }

    #[test]
    fn parses_zero_trust_device_profile_contract() {
        let profile = device_profile_from_value(serde_json::json!({
            "policy_id": "profile-1",
            "name": "Cloudflare Mesh nodes",
            "enabled": true,
            "precedence": 100,
            "match": "identity.email == \"warp_connector@example.cloudflareaccess.com\"",
            "service_mode_v2": {"mode": "warp"},
            "tunnel_protocol": "masque",
            "auto_connect": 1,
            "switch_locked": true
        }))
        .unwrap();

        assert_eq!(profile.id, "profile-1");
        assert_eq!(profile.precedence, Some(100));
        assert_eq!(profile.service_mode.as_deref(), Some("warp"));
        assert_eq!(profile.tunnel_protocol.as_deref(), Some("masque"));
        assert_eq!(profile.auto_connect, Some(1));
        assert_eq!(profile.switch_locked, Some(true));
    }

    #[test]
    fn listed_device_profile_accepts_live_default_shape_without_inventing_name() {
        let mut default_policy_seen = false;
        let profiles = device_profiles_from_list_values(
            vec![serde_json::json!({
                "policy_id": "default-policy",
                "default": true,
                "enabled": true,
                "service_mode_v2": {"mode": "warp"},
                "tunnel_protocol": "masque"
            })],
            &mut default_policy_seen,
        )
        .unwrap();

        assert!(profiles.is_empty());
        assert!(default_policy_seen);
    }

    #[test]
    fn listed_device_profile_keeps_custom_name_strict() {
        let error = listed_device_profile_from_value(serde_json::json!({
            "policy_id": "custom-profile",
            "default": false,
            "enabled": true,
            "precedence": 100,
            "service_mode_v2": {"mode": "warp"},
            "tunnel_protocol": "masque"
        }))
        .unwrap_err();

        assert!(error.contains("field name is required"));
    }

    #[test]
    fn listed_device_profile_rejects_default_without_provider_id() {
        let error = listed_device_profile_from_value(serde_json::json!({
            "default": true,
            "enabled": true,
            "service_mode_v2": {"mode": "warp"},
            "tunnel_protocol": "masque"
        }))
        .unwrap_err();

        assert!(error.contains("policy_id/id is required"));
    }

    #[test]
    fn listed_device_profile_rejects_multiple_defaults() {
        let mut default_policy_seen = false;
        let error = device_profiles_from_list_values(
            vec![
                serde_json::json!({
                    "policy_id": "default-policy-1",
                    "default": true,
                    "enabled": true
                }),
                serde_json::json!({
                    "policy_id": "default-policy-2",
                    "default": true,
                    "enabled": true
                }),
            ],
            &mut default_policy_seen,
        )
        .unwrap_err();

        assert!(error.contains("more than one default policy"));
    }

    #[test]
    fn split_tunnel_write_omits_inactive_union_fields() {
        let value = serde_json::to_value(CloudflareSplitTunnelWrite {
            address: Some("100.96.0.0/12".to_owned()),
            host: None,
            description: None,
        })
        .unwrap();
        assert_eq!(value["address"], "100.96.0.0/12");
        assert!(value.get("host").is_none());
        assert!(value.get("description").is_none());
    }

    #[test]
    fn parses_zero_trust_split_tunnel_contract() {
        let entry = split_tunnel_from_value(serde_json::json!({
            "address": "100.96.0.0/12",
            "description": "Cloudflare Mesh IPs"
        }))
        .unwrap();

        assert_eq!(entry.address.as_deref(), Some("100.96.0.0/12"));
        assert_eq!(entry.description.as_deref(), Some("Cloudflare Mesh IPs"));
    }

    #[test]
    fn parses_gateway_rule_without_identity_leakage_requirement() {
        let rule = gateway_rule_from_value(serde_json::json!({
            "id": "rule-1",
            "name": "Mesh allow",
            "action": "allow",
            "precedence": 100,
            "enabled": true,
            "traffic": "net.dst.ip in {100.96.0.0/12}",
            "identity": "identity.email == \"redacted@example.com\""
        }))
        .unwrap();

        assert_eq!(rule.action, "allow");
        assert_eq!(rule.precedence, Some(100));
        assert_eq!(
            rule.traffic.as_deref(),
            Some("net.dst.ip in {100.96.0.0/12}")
        );
    }

    #[test]
    fn parses_warp_access_application_and_policy() {
        let application = access_application_from_value(serde_json::json!({
            "id": "app-1",
            "name": "Device enrollment",
            "type": "warp"
        }))
        .unwrap();
        let policy = access_policy_from_value(serde_json::json!({
            "id": "policy-1",
            "name": "Allow enrollment",
            "decision": "allow"
        }))
        .unwrap();

        assert_eq!(application.app_type, "warp");
        assert_eq!(policy.decision.as_deref(), Some("allow"));
    }

    #[test]
    fn malformed_zero_trust_objects_fail_closed() {
        assert!(device_profile_from_value(serde_json::json!({"name": "missing id"})).is_err());
        assert!(gateway_rule_from_value(serde_json::json!({"id": "rule-1"})).is_err());
        assert!(access_application_from_value(serde_json::json!({"id": "app-1"})).is_err());
    }
}
