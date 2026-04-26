use edge_shared_types::{ProxyGroupState, SelectorState};
use reqwest::Client;
use serde::Deserialize;

const MAIN_GROUP: &str = "proxy-selector";
const AUX_GROUPS: &[&str] = &["auto-direct-tunnel", "auto-warp-tunnel"];

pub async fn get_selector_state(controller_url: &str) -> Result<SelectorState, String> {
    let response = Client::new()
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

    Ok(selector_state_from_payload(payload))
}

pub async fn set_selector(
    controller_url: &str,
    group: &str,
    name: &str,
) -> Result<(Option<String>, SelectorState), String> {
    let before = get_selector_state(controller_url).await.ok();
    let previous = before
        .as_ref()
        .and_then(|selector| selector.observed_main_route.clone());

    let response = Client::new()
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

    let selector = get_selector_state(controller_url).await?;
    Ok((previous, selector))
}

fn selector_state_from_payload(payload: ProxiesResponse) -> SelectorState {
    let mut groups = Vec::new();
    let mut selector = SelectorState {
        desired_main_route: None,
        observed_main_route: None,
        degraded: false,
        warnings: Vec::new(),
        proxy_groups: Vec::new(),
    };

    for group_name in std::iter::once(MAIN_GROUP).chain(AUX_GROUPS.iter().copied()) {
        match payload.proxies.get(group_name) {
            Some(group) => {
                let candidates = group.all.clone().unwrap_or_default();
                let selected = group.now.clone();
                if group_name == MAIN_GROUP {
                    selector.observed_main_route = selected.clone();
                    if selected.is_none() {
                        selector.degraded = true;
                        selector
                            .warnings
                            .push("proxy-selector did not report an active route".to_owned());
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

        let selector = selector_state_from_payload(payload);
        assert_eq!(
            selector.observed_main_route.as_deref(),
            Some("auto-direct-tunnel")
        );
        assert_eq!(selector.proxy_groups.len(), 3);
        assert!(!selector.degraded);
    }
}
