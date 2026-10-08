use edge_shared_types::{ProxyGroupState, SelectorState};
use reqwest::Client;
use serde::Deserialize;
use std::thread;
use std::time::Duration;

const DEFAULT_AUX_GROUPS: &[&str] = &["auto-direct-tunnel", "auto-warp-tunnel"];

pub async fn get_selector_state(
    controller_url: &str,
    main_group: &str,
    aux_groups: &[&str],
) -> Result<SelectorState, String> {
    let response = clash_control_client()?
        .get(format!("{controller_url}/proxies"))
        .send()
        .await
        .map_err(|err| format!("failed to reach clash API: {err}"))?;
    let response = response
        .error_for_status()
        .map_err(|err| format!("clash API returned an error: {err}"))?;
    let payload: ProxiesResponse = response
        .json()
        .await
        .map_err(|err| format!("invalid clash API JSON: {err}"))?;

    Ok(selector_state_from_payload(payload, main_group, aux_groups))
}

pub async fn set_selector(
    controller_url: &str,
    group: &str,
    name: &str,
    aux_groups: &[&str],
) -> Result<(Option<String>, SelectorState), String> {
    let before = get_selector_state(controller_url, group, aux_groups)
        .await
        .ok();
    let previous = before
        .as_ref()
        .and_then(|selector| selector.observed_main_route.clone());

    let response = clash_control_client()?
        .put(format!("{controller_url}/proxies/{group}"))
        .json(&SelectorMutationBody {
            name: name.to_owned(),
        })
        .send()
        .await
        .map_err(|err| format!("failed to send clash selector update: {err}"))?;
    response
        .error_for_status()
        .map_err(|err| format!("clash selector update failed: {err}"))?;

    for _ in 0..10 {
        let selector = get_selector_state(controller_url, group, aux_groups).await?;
        if selector.observed_main_route.as_deref() == Some(name) {
            return Ok((previous, selector));
        }
        thread::sleep(Duration::from_millis(250));
    }

    let selector = get_selector_state(controller_url, group, aux_groups).await?;
    Err(format!(
        "clash selector did not converge to {name}; observed {}",
        selector.observed_main_route.as_deref().unwrap_or("<none>")
    ))
}

pub fn default_aux_groups() -> &'static [&'static str] {
    DEFAULT_AUX_GROUPS
}

fn clash_control_client() -> Result<Client, String> {
    Client::builder()
        .no_proxy()
        .build()
        .map_err(|err| format!("failed to build clash control HTTP client: {err}"))
}

fn selector_state_from_payload(
    payload: ProxiesResponse,
    main_group: &str,
    aux_groups: &[&str],
) -> SelectorState {
    let mut groups = Vec::new();
    let mut selector = SelectorState {
        desired_main_route: None,
        observed_main_route: None,
        degraded: false,
        warnings: Vec::new(),
        proxy_groups: Vec::new(),
    };

    for group_name in std::iter::once(main_group).chain(aux_groups.iter().copied()) {
        match payload.proxies.get(group_name) {
            Some(group) => {
                let candidates = group.all.clone().unwrap_or_default();
                let selected = group.now.clone();
                if group_name == main_group {
                    selector.observed_main_route = selected.clone();
                    if selected.is_none() {
                        selector.degraded = true;
                        selector
                            .warnings
                            .push(format!("{main_group} did not report an active route"));
                    }
                }
                groups.push(ProxyGroupState {
                    name: group_name.to_owned(),
                    selected,
                    candidates,
                    warnings: Vec::new(),
                });
            }
            None => {
                selector.degraded = true;
                selector
                    .warnings
                    .push(format!("clash API group is missing: {group_name}"));
                groups.push(ProxyGroupState {
                    name: group_name.to_owned(),
                    selected: None,
                    candidates: Vec::new(),
                    warnings: vec![format!(
                        "group not found in clash API response: {group_name}"
                    )],
                });
            }
        }
    }

    selector.proxy_groups = groups;
    selector
}

#[derive(Debug, Deserialize)]
struct ProxiesResponse {
    proxies: std::collections::BTreeMap<String, ProxyGroupResponse>,
}

#[derive(Debug, Deserialize)]
struct ProxyGroupResponse {
    now: Option<String>,
    all: Option<Vec<String>>,
}

#[derive(Debug, serde::Serialize)]
struct SelectorMutationBody {
    name: String,
}

// One-shot native sing-box quality observation. Delay queries update sing-box's
// own URL-test history but never select an outbound or change its routing policy.
const LINE1_QUALITY_TAGS: [&str; 4] = [
    "hysteria2-direct",
    "vless-reality-direct",
    "hysteria2-warp",
    "vless-reality-warp",
];
pub const LINE1_QUALITY_SAMPLES: usize = 5;
const LINE1_DELAY_TIMEOUT_MS: u64 = 3500;
const LINE1_REQUEST_TIMEOUT_MS: u64 = 4500;
const LINE1_PROBE_TARGET: &str = "https://www.gstatic.com/generate_204";

#[derive(Debug)]
pub struct Line1QualityRow {
    pub tag: &'static str,
    pub success_ms: Vec<u64>,
    pub failures: usize,
}

#[derive(Debug)]
pub struct Line1QualityReport {
    pub rows: Vec<Line1QualityRow>,
}

#[derive(Debug, Deserialize)]
struct Line1DelayResponse {
    delay: u64,
}

fn line1_selector_routes(payload: &ProxiesResponse) -> Result<[String; 2], String> {
    for tag in LINE1_QUALITY_TAGS {
        if !payload.proxies.contains_key(tag) {
            return Err(format!(
                "native Clash API is missing canonical outbound {tag}"
            ));
        }
    }
    let mut routes = Vec::with_capacity(2);
    for group in ["proxy-selector", "wsl-selector"] {
        let state = payload
            .proxies
            .get(group)
            .ok_or_else(|| format!("native Clash API is missing selector {group}"))?;
        let members = state
            .all
            .as_ref()
            .ok_or_else(|| format!("native Clash API selector {group} has no members"))?;
        if LINE1_QUALITY_TAGS
            .iter()
            .any(|tag| !members.iter().any(|member| member.as_str() == *tag))
        {
            return Err(format!(
                "native Clash API selector {group} lacks a canonical outbound"
            ));
        }
        let selected = state
            .now
            .as_deref()
            .filter(|value| members.iter().any(|member| member.as_str() == *value))
            .ok_or_else(|| format!("native Clash API selector {group} lacks a valid live route"))?;
        routes.push(selected.to_owned());
    }
    Ok([routes[0].clone(), routes[1].clone()])
}

async fn line1_selector_snapshot(
    client: &Client,
    controller_url: &str,
) -> Result<[String; 2], String> {
    let response = client
        .get(format!("{controller_url}/proxies"))
        .send()
        .await
        .map_err(|_| "native Clash API selector observation unavailable".to_owned())?
        .error_for_status()
        .map_err(|_| "native Clash API selector observation failed".to_owned())?;
    let payload: ProxiesResponse = response
        .json()
        .await
        .map_err(|_| "native Clash API returned invalid selector evidence".to_owned())?;
    line1_selector_routes(&payload)
}

pub async fn measure_line1_quality(controller_url: &str) -> Result<Line1QualityReport, String> {
    // Do not permit user-info, DNS aliases or remote hosts at this boundary.
    if controller_url != "http://127.0.0.1:19091" {
        return Err(
            "Line1 quality requires the exact installed loopback Clash endpoint".to_owned(),
        );
    }
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(LINE1_REQUEST_TIMEOUT_MS))
        .build()
        .map_err(|_| "failed to construct bounded native Clash API client".to_owned())?;
    let before = line1_selector_snapshot(&client, controller_url).await?;
    let mut rows = Vec::with_capacity(LINE1_QUALITY_TAGS.len());
    for tag in LINE1_QUALITY_TAGS {
        let mut row = Line1QualityRow {
            tag,
            success_ms: Vec::with_capacity(LINE1_QUALITY_SAMPLES),
            failures: 0,
        };
        for _ in 0..LINE1_QUALITY_SAMPLES {
            let result = client
                .get(format!("{controller_url}/proxies/{tag}/delay"))
                .query(&[("url", LINE1_PROBE_TARGET), ("timeout", "3500")])
                .send()
                .await;
            let delay = match result {
                Ok(response) if response.status().is_success() => response
                    .json::<Line1DelayResponse>()
                    .await
                    .ok()
                    .map(|data| data.delay),
                _ => None,
            };
            match delay {
                Some(ms) if ms > 0 && ms <= LINE1_DELAY_TIMEOUT_MS => row.success_ms.push(ms),
                _ => row.failures += 1,
            }
        }
        rows.push(row);
    }
    let after = line1_selector_snapshot(&client, controller_url).await?;
    if after != before {
        return Err("Line1 quality observed live desktop/WSL selector drift; no selector mutation attempted".to_owned());
    }
    Ok(Line1QualityReport { rows })
}

pub fn line1_latency_summary(values: &[u64]) -> Option<(u64, u64, u64)> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    let median = if sorted.len() % 2 == 0 {
        (sorted[middle - 1] + sorted[middle]) / 2
    } else {
        sorted[middle]
    };
    Some((sorted[0], median, sorted[sorted.len() - 1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_selector_state_from_payload() {
        let payload = ProxiesResponse {
            proxies: std::collections::BTreeMap::from([
                (
                    "proxy-selector".to_owned(),
                    ProxyGroupResponse {
                        now: Some("auto-direct-tunnel".to_owned()),
                        all: Some(vec![
                            "auto-direct-tunnel".to_owned(),
                            "hysteria2-direct".to_owned(),
                        ]),
                    },
                ),
                (
                    "auto-direct-tunnel".to_owned(),
                    ProxyGroupResponse {
                        now: Some("hysteria2-direct".to_owned()),
                        all: Some(vec![
                            "hysteria2-direct".to_owned(),
                            "vless-reality-direct".to_owned(),
                        ]),
                    },
                ),
                (
                    "auto-warp-tunnel".to_owned(),
                    ProxyGroupResponse {
                        now: Some("hysteria2-warp".to_owned()),
                        all: Some(vec![
                            "hysteria2-warp".to_owned(),
                            "vless-reality-warp".to_owned(),
                        ]),
                    },
                ),
            ]),
        };

        let selector = selector_state_from_payload(payload, "proxy-selector", default_aux_groups());
        assert_eq!(
            selector.observed_main_route.as_deref(),
            Some("auto-direct-tunnel")
        );
        assert_eq!(selector.proxy_groups.len(), 3);
        assert!(!selector.degraded);
    }

    #[test]
    fn builds_proxy_bypassing_local_control_client() {
        assert!(clash_control_client().is_ok());
    }
    #[test]
    fn quality_rejects_missing_outbound_or_selector() {
        let mut payload = ProxiesResponse {
            proxies: std::collections::BTreeMap::new(),
        };
        assert!(line1_selector_routes(&payload).is_err());
        for tag in LINE1_QUALITY_TAGS {
            payload.proxies.insert(
                tag.to_owned(),
                ProxyGroupResponse {
                    now: None,
                    all: None,
                },
            );
        }
        for group in ["proxy-selector", "wsl-selector"] {
            payload.proxies.insert(
                group.to_owned(),
                ProxyGroupResponse {
                    now: Some("auto-direct-tunnel".to_owned()),
                    all: Some(
                        LINE1_QUALITY_TAGS
                            .iter()
                            .map(|tag| (*tag).to_owned())
                            .chain(std::iter::once("auto-direct-tunnel".to_owned()))
                            .collect(),
                    ),
                },
            );
        }
        assert_eq!(
            line1_selector_routes(&payload).unwrap(),
            [
                "auto-direct-tunnel".to_owned(),
                "auto-direct-tunnel".to_owned()
            ]
        );
        payload.proxies.remove("vless-reality-warp");
        assert!(line1_selector_routes(&payload).is_err());
    }

    #[test]
    fn quality_reports_true_median_without_claiming_p95_or_packet_loss() {
        assert_eq!(line1_latency_summary(&[]), None);
        assert_eq!(
            line1_latency_summary(&[90, 20, 40, 30, 50]),
            Some((20, 40, 90))
        );
        assert_eq!(line1_latency_summary(&[20, 30]), Some((20, 25, 30)));
    }
}
