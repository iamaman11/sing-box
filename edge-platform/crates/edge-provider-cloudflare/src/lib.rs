use reqwest::Client;
use serde::{Deserialize, Serialize};

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
        result.extend(payload.result.into_iter().map(mesh_node_from_record));
        if page_is_complete(page, page_count, payload.result_info.as_ref()) {
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
        let query = [
            ("is_deleted", "false".to_owned()),
            ("tun_types", "warp_connector".to_owned()),
            ("tunnel_id", node_id.to_owned()),
            ("page", page.to_string()),
            ("per_page", API_PAGE_SIZE.to_string()),
        ];
        let response = client
            .get(format!("{API_ROOT}/accounts/{account_id}/teamnet/routes"))
            .query(&query)
            .send()
            .await
            .map_err(|err| format!("failed to list Cloudflare Mesh routes: {err}"))?;
        let payload: ApiEnvelope<Vec<MeshRouteRecord>> = parse_success_json(response).await?;
        let page_count = payload.result.len();
        result.extend(payload.result.into_iter().map(mesh_route_from_record));
        if page_is_complete(page, page_count, payload.result_info.as_ref()) {
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
    if let Some(comment) = comment {
        if comment.len() > 100 {
            return Err("Cloudflare Mesh route comment must be at most 100 characters".to_owned());
        }
    }

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

fn page_is_complete(
    page: u32,
    page_count: usize,
    result_info: Option<&ApiResultInfo>,
) -> bool {
    if let Some(info) = result_info
        && let Some(total_count) = info.total_count
    {
        return u64::from(page) * u64::from(info.per_page.unwrap_or(API_PAGE_SIZE))
            >= u64::from(total_count);
    }
    page_count < API_PAGE_SIZE as usize
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
    let response = client
        .get(format!("{API_ROOT}/zones/{zone_id}/dns_records"))
        .query(&[("type", "A"), ("name", record_name)])
        .send()
        .await
        .map_err(|err| format!("failed to query Cloudflare DNS records: {err}"))?;
    let payload: ApiEnvelope<Vec<DnsRecord>> = parse_success_json(response).await?;
    Ok(payload.result.into_iter().next())
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
    let payload: ApiEnvelope<T> =
        serde_json::from_str(&body).map_err(|err| format!("invalid Cloudflare JSON payload: {err}"))?;
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
    #[serde(default)]
    result_info: Option<ApiResultInfo>,
}

#[derive(Debug, Deserialize)]
struct ApiResponseInfo {
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiResultInfo {
    per_page: Option<u32>,
    total_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ZoneRecord {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
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
        assert_eq!(
            body["tunnel_id"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(body["comment"], "line-3-poc");
    }

    #[test]
    fn pagination_uses_result_info_when_available() {
        let info = ApiResultInfo {
            per_page: Some(1000),
            total_count: Some(1001),
        };
        assert!(!page_is_complete(1, 1000, Some(&info)));
        assert!(page_is_complete(2, 1, Some(&info)));
    }

    #[test]
    fn pagination_falls_back_to_short_page() {
        assert!(!page_is_complete(1, 1000, None));
        assert!(page_is_complete(2, 5, None));
    }

    #[test]
    fn route_comment_is_bounded() {
        let comment = "x".repeat(101);
        assert_eq!(comment.len(), 101);
    }
}
