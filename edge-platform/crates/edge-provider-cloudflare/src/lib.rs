use reqwest::Client;
use serde::{Deserialize, Serialize};

const API_ROOT: &str = "https://api.cloudflare.com/client/v4";

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
    Ok(CloudflareMeshNode {
        id: payload.result.id,
        name: payload.result.name,
        status: payload.result.status,
    })
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
    Ok(CloudflareMeshRoute {
        id: payload.result.id,
        network: payload.result.network,
        tunnel_id: payload.result.tunnel_id,
    })
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

fn require_non_empty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

pub fn mock_upsert_a_record(zone_name: &str, record_name: &str, ip: &str) -> CloudflareDnsRecord {
    CloudflareDnsRecord {
        zone_name: zone_name.to_owned(),
        zone_id: format!("mock-zone-{}", zone_name.replace('.', "-")),
        record_name: record_name.to_owned(),
        ip: ip.to_owned(),
    }
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
    let _payload: ApiEnvelope<serde_json::Value> = parse_success_json(response).await?;
    Ok(())
}

async fn parse_success_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("failed to read Cloudflare response body: {err}"))?;
    if !status.is_success() {
        return Err(format!("Cloudflare API returned {status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|err| format!("invalid Cloudflare JSON payload: {err}"))
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    #[serde(rename = "success")]
    _success: bool,
    result: T,
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
    fn serializes_mesh_node_request_body() {
        let body = serde_json::to_value(MeshNodeWriteRequest {
            name: "vultr-waw-exit".to_owned(),
        })
        .unwrap();
        assert_eq!(body["name"], "vultr-waw-exit");
    }

    #[test]
    fn serializes_mesh_route_request_body() {
        let body = serde_json::to_value(MeshRouteWriteRequest {
            network: "203.0.113.10/32".to_owned(),
            tunnel_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            comment: Some("line-3-poc".to_owned()),
        })
        .unwrap();
        assert_eq!(body["network"], "203.0.113.10/32");
        assert_eq!(
            body["tunnel_id"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(body["comment"], "line-3-poc");
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
}
