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

// Delay samples are per-named-outbound Clash URL tests and NEVER change the
// desktop/WSL selector. This does NOT measure throughput or HTTP failure rate.
pub const QUALITY_LINE1_TAGS: [&str; 4] = [
    "hysteria2-direct",
    "vless-reality-direct",
    "hysteria2-warp",
    "vless-reality-warp",
];
const QUALITY_DELAY_SAMPLES: u32 = 3;
const QUALITY_DELAY_TIMEOUT_MS: u32 = 3500;

#[derive(Debug, PartialEq, Eq)]
pub struct ReadonlyDelaySamples {
    pub attempts: u32,
    pub readings_ms: Vec<u32>,
}

pub async fn observe_outbound_delays(
    controller_url: &str,
    name: &str,
) -> Result<ReadonlyDelaySamples, String> {
    if !QUALITY_LINE1_TAGS.contains(&name) {
        return Err("quality probe refused unknown outbound tag".to_owned());
    }
    // The quality RPC is for the exact local Clash API only. No arbitrary
    // outbound network URL or proxy-controller address is accepted.
    if controller_url != "http://127.0.0.1:19091" {
        return Err("quality probe requires the canonical local Clash API".to_owned());
    }
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(
            u64::from(QUALITY_DELAY_TIMEOUT_MS) + 500,
        ))
        .build()
        .map_err(|_| "quality probe HTTP client unavailable".to_owned())?;
    let mut readings_ms = Vec::new();
    for _ in 0..QUALITY_DELAY_SAMPLES {
        let response = client
            .get(format!("{controller_url}/proxies/{name}/delay"))
            .query(&[
                ("url", "https://www.gstatic.com/generate_204"),
                ("timeout", "3500"),
            ])
            .send()
            .await;
        if let Ok(response) = response
            && let Ok(response) = response.error_for_status()
            && let Ok(body) = response.json::<QualityDelayPayload>().await
            && body.delay > 0
            && body.delay <= QUALITY_DELAY_TIMEOUT_MS
        {
            readings_ms.push(body.delay);
        }
    }
    Ok(ReadonlyDelaySamples {
        attempts: QUALITY_DELAY_SAMPLES,
        readings_ms,
    })
}

#[derive(Deserialize)]
struct QualityDelayPayload {
    delay: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct QualityLatencyStats {
    pub min_ms: u32,
    pub median_ms: u32,
    pub p95_ms: u32,
    pub jitter_ms: u32,
}

pub fn summarise_delay_samples(readings: &[u32]) -> Option<QualityLatencyStats> {
    if readings.is_empty() {
        return None;
    }
    let mut sorted = readings.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let jitter_sum: u64 = readings
        .windows(2)
        .map(|pair| u64::from(pair[0].abs_diff(pair[1])))
        .sum();
    let jitter_ms = if n == 1 {
        0
    } else {
        (jitter_sum / (n as u64 - 1)) as u32
    };
    Some(QualityLatencyStats {
        min_ms: sorted[0],
        median_ms: sorted[(n - 1) / 2],
        p95_ms: sorted[((95 * n + 99) / 100).saturating_sub(1)],
        jitter_ms,
    })
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
    fn quality_latency_stats_have_exact_nearest_rank_p95_and_ordered_jitter() {
        let s = summarise_delay_samples(&[20, 100, 30]).unwrap();
        assert_eq!(s.min_ms, 20);
        assert_eq!(s.median_ms, 30);
        assert_eq!(s.p95_ms, 100);
        assert_eq!(s.jitter_ms, 75);
        assert_eq!(summarise_delay_samples(&[]), None);
        assert_eq!(summarise_delay_samples(&[23]).unwrap().jitter_ms, 0);
    }

    #[tokio::test]
    async fn quality_refuses_unknown_or_non_loopback_clash_api() {
        assert!(
            observe_outbound_delays("http://127.0.0.1:19091", "proxy-selector")
                .await
                .is_err()
        );
        assert!(
            observe_outbound_delays("https://external.example", "hysteria2-direct")
                .await
                .is_err()
        );
    }

    #[test]
    fn builds_proxy_bypassing_local_control_client() {
        assert!(clash_control_client().is_ok());
    }
}
