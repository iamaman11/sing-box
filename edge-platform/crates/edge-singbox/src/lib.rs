use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use edge_shared_types::{
    LocalSingboxState, SelectorState, UbuntuProxyState, WindowsDatapathMode, WindowsRuntimeState,
    WindowsTunnelBinding, canonical_production_desired_state, production_windows_route_tag,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

const MANAGED_SELECTOR_TAG: &str = "proxy-selector";
const WSL_SELECTOR_TAG: &str = "wsl-selector";
const WSL_INBOUND_TAG: &str = "wsl-mixed-in";
const DESKTOP_TRACE_INBOUND_TAG: &str = "mixed-in";
pub const STAGE2_DESKTOP_PROXY_PORT: u32 = 17891;
pub const STAGE2_WSL_PROXY_PORT: u32 = 17892;
pub const STAGE2_CLASH_API_PORT: u32 = 19091;
const DEFAULT_WSL_PROXY_PORT: u32 = STAGE2_WSL_PROXY_PORT;
const WSL_INBOUND_BIND_HOST: &str = "0.0.0.0";
const WARP_SERVICE_PROCESS: &str = "warp-svc.exe";
const WARP_CONTROL_ENDPOINTS: &[&str] = &[
    "162.159.197.2/32",
    "162.159.197.3/32",
    "162.159.197.4/32",
    "162.159.137.105/32",
    "162.159.138.105/32",
];
// Foreign Cloudflare One Client owns this Mesh/device route on the shared Windows host.
// MANAGED_TUN must route around it; sing-box never adopts or mutates CloudflareWARP.
const FOREIGN_CLOUDFLARE_MESH_CIDRS: &[&str] = &["100.96.0.0/12"];
const LOOPBACK_CIDRS: &[&str] = &["127.0.0.0/8", "::1/128"];
const EXPECTED_OUTBOUND_TAGS: &[&str] = &[
    "auto-direct-tunnel",
    "auto-warp-tunnel",
    "hysteria2-direct",
    "vless-reality-direct",
    "hysteria2-warp",
    "vless-reality-warp",
];

#[derive(Debug, Clone)]
pub struct LocalConfigObservation {
    pub local_singbox: LocalSingboxState,
    pub selector: SelectorState,
    pub ubuntu_selector: SelectorState,
    pub ubuntu_proxy: UbuntuProxyState,
}

#[derive(Debug, Clone)]
pub struct ExpectedTunnelBindings {
    pub server: String,
    pub direct: TunnelBinding,
    pub warp: TunnelBinding,
}

#[derive(Debug, Clone)]
pub struct TunnelBinding {
    pub domain: String,
    pub hy2_port: u32,
    pub hy2_password: String,
    pub vless_port: u32,
    pub vless_uuid: String,
    pub reality_public_key: String,
    pub reality_short_id: String,
}

#[derive(Debug, Clone)]
pub struct ConfigSyncSummary {
    pub instance_id: Option<String>,
    pub config_path: String,
}

pub fn inspect_local_config(
    config_path: &Path,
    expected_bindings: Option<&ExpectedTunnelBindings>,
) -> LocalConfigObservation {
    let expected_config_path = config_path.display().to_string();
    let mut local_singbox = LocalSingboxState::placeholder(expected_config_path.clone());
    let mut selector = SelectorState::placeholder();
    let mut ubuntu_selector = SelectorState::placeholder();
    let mut ubuntu_proxy = UbuntuProxyState::unavailable("WSL proxy inbound is missing");

    let process = detect_process(config_path);
    local_singbox.process_running = process.is_some();
    local_singbox.active_config_path = process
        .as_ref()
        .and_then(|process| process.config_path.clone())
        .or_else(|| {
            config_path
                .is_file()
                .then_some(expected_config_path.clone())
        });

    if let Some(process) = process {
        if let Some(active_config) = process.config_path {
            if same_path_string(&active_config, config_path) {
                local_singbox.managed_config = true;
            } else {
                local_singbox.warnings.push(format!(
                    "sing-box is running with a different config: {active_config}"
                ));
            }
        } else {
            local_singbox.warnings.push(
                "sing-box process detected but config path was not found in command line"
                    .to_owned(),
            );
        }
    }

    let raw_config = match fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(err) => {
            local_singbox
                .warnings
                .push(format!("unable to read local sing-box config: {err}"));
            selector.warnings.push(
                "selector state unavailable because local config could not be read".to_owned(),
            );
            return LocalConfigObservation {
                local_singbox,
                selector,
                ubuntu_selector,
                ubuntu_proxy,
            };
        }
    };

    let parsed: SingboxConfig = match serde_json::from_str(&raw_config) {
        Ok(parsed) => parsed,
        Err(err) => {
            local_singbox
                .warnings
                .push(format!("local sing-box config is not valid JSON: {err}"));
            selector
                .warnings
                .push("selector state unavailable because local config JSON is invalid".to_owned());
            return LocalConfigObservation {
                local_singbox,
                selector,
                ubuntu_selector,
                ubuntu_proxy,
            };
        }
    };

    local_singbox.clash_api_port = parsed
        .experimental
        .as_ref()
        .and_then(|experimental| experimental.clash_api.as_ref())
        .and_then(|clash_api| clash_api.external_controller.as_deref())
        .and_then(parse_controller_port);

    selector = inspect_selector_group(&parsed, MANAGED_SELECTOR_TAG, &mut local_singbox);
    ubuntu_selector = inspect_selector_group(&parsed, WSL_SELECTOR_TAG, &mut local_singbox);
    if selector.desired_main_route.is_some() || ubuntu_selector.desired_main_route.is_some() {
        local_singbox.managed_config = true;
    }

    ubuntu_proxy = inspect_ubuntu_proxy_inbound(&parsed, &mut local_singbox, &mut ubuntu_selector);

    if !parsed
        .outbounds
        .iter()
        .any(|outbound| EXPECTED_OUTBOUND_TAGS.contains(&outbound.tag.as_str()))
    {
        local_singbox
            .warnings
            .push("local config does not contain expected Vultr dual-tunnel outbounds".to_owned());
        selector.degraded = true;
    }

    if local_singbox.clash_api_port.is_none() {
        local_singbox
            .warnings
            .push("clash API port is not configured in local config".to_owned());
        selector.warnings.push(
            "live selector observation is limited because clash API is not configured".to_owned(),
        );
    }

    if let Some(expected) = expected_bindings {
        compare_tunnel_binding(
            &parsed,
            "hysteria2-direct",
            "vless-reality-direct",
            &expected.server,
            &expected.direct,
            &mut local_singbox,
            &mut selector,
        );
        compare_tunnel_binding(
            &parsed,
            "hysteria2-warp",
            "vless-reality-warp",
            &expected.server,
            &expected.warp,
            &mut local_singbox,
            &mut selector,
        );
    } else {
        local_singbox.warnings.push(
            "live tunnel state is unavailable, config/state parity was not checked".to_owned(),
        );
    }

    LocalConfigObservation {
        local_singbox,
        selector,
        ubuntu_selector,
        ubuntu_proxy,
    }
}

fn inspect_selector_group(
    parsed: &SingboxConfig,
    selector_tag: &str,
    local_singbox: &mut LocalSingboxState,
) -> SelectorState {
    let mut selector = SelectorState::placeholder();
    let selector_outbound = parsed
        .outbounds
        .iter()
        .find(|outbound| outbound.kind == "selector" && outbound.tag == selector_tag);

    if let Some(selector_config) = selector_outbound {
        selector.desired_main_route = selector_config.default.clone();
        selector.observed_main_route = selector_config.default.clone();

        let missing_expected = EXPECTED_OUTBOUND_TAGS
            .iter()
            .filter(|tag| !selector_config.outbounds.iter().any(|entry| entry == **tag))
            .map(|tag| (*tag).to_owned())
            .collect::<Vec<_>>();
        if !missing_expected.is_empty() {
            local_singbox.warnings.push(format!(
                "managed selector {selector_tag} is missing expected tunnel entries: {}",
                missing_expected.join(", ")
            ));
            selector.degraded = true;
        }
    } else {
        local_singbox.warnings.push(format!(
            "managed selector {selector_tag} is missing from local config"
        ));
        selector
            .warnings
            .push(format!("{selector_tag} was not found in local config"));
        selector.degraded = true;
    }

    selector
}

fn inspect_ubuntu_proxy_inbound(
    parsed: &SingboxConfig,
    local_singbox: &mut LocalSingboxState,
    ubuntu_selector: &mut SelectorState,
) -> UbuntuProxyState {
    let Some(inbound) = parsed
        .inbounds
        .iter()
        .find(|inbound| inbound.kind == "mixed" && inbound.tag == WSL_INBOUND_TAG)
    else {
        local_singbox
            .warnings
            .push("WSL inbound wsl-mixed-in is missing from local config".to_owned());
        ubuntu_selector.degraded = true;
        ubuntu_selector
            .warnings
            .push("wsl-mixed-in inbound was not found in local config".to_owned());
        return UbuntuProxyState::unavailable("wsl-mixed-in inbound is missing");
    };

    let endpoint = resolve_wsl_proxy_endpoint();
    let host = endpoint
        .published_host
        .clone()
        .or_else(|| inbound.listen.clone())
        .unwrap_or_else(|| "127.0.0.1".to_owned());
    let port = inbound.listen_port.unwrap_or(DEFAULT_WSL_PROXY_PORT);
    if !endpoint.warnings.is_empty() {
        ubuntu_selector.degraded = true;
        ubuntu_selector.warnings.extend(endpoint.warnings.clone());
    }
    UbuntuProxyState {
        available: true,
        host: Some(host.clone()),
        port: Some(port),
        url: Some(format!("http://{host}:{port}")),
        warnings: endpoint.warnings,
    }
}

pub fn sync_local_config(
    config_path: &Path,
    state_path: &Path,
    runtime_root: &Path,
) -> Result<ConfigSyncSummary, String> {
    let raw_state = fs::read_to_string(state_path)
        .map_err(|err| format!("unable to read legacy state file: {err}"))?;
    let legacy: SyncState = serde_json::from_str(&raw_state)
        .map_err(|err| format!("legacy state file is invalid JSON: {err}"))?;
    sync_local_config_from_bindings(config_path, &legacy, runtime_root)
}

pub fn render_windows_config(state: &WindowsRuntimeState) -> Result<Vec<u8>, String> {
    let desired = canonical_production_desired_state()?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "canonical production Windows datapath mode is invalid".to_owned())?;
    if mode == WindowsDatapathMode::Unspecified {
        return Err("canonical production Windows datapath mode is unspecified".to_owned());
    }
    render_windows_config_for_mode(state, mode)
}

fn render_windows_config_for_mode(
    state: &WindowsRuntimeState,
    mode: WindowsDatapathMode,
) -> Result<Vec<u8>, String> {
    edge_shared_types::encode_windows_runtime_state(state)?;
    let desired = canonical_production_desired_state()?;
    let routes = desired
        .windows_route_policy
        .as_ref()
        .ok_or_else(|| "canonical Windows route policy is missing".to_owned())?;
    let desktop_route = production_windows_route_tag(routes.desktop)?;
    let wsl_route = production_windows_route_tag(routes.wsl)?;
    let reality_server_name = desired
        .application
        .as_ref()
        .and_then(|application| application.line1.as_ref())
        .map(|line1| line1.reality_server_name.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "canonical production Reality server name is missing".to_owned())?;
    let direct = state
        .direct
        .as_ref()
        .ok_or_else(|| "Windows runtime state direct tunnel is missing".to_owned())?;
    let warp = state
        .warp
        .as_ref()
        .ok_or_else(|| "Windows runtime state WARP tunnel is missing".to_owned())?;
    let selector_entries = json!([
        "auto-direct-tunnel",
        "auto-warp-tunnel",
        "hysteria2-direct",
        "vless-reality-direct",
        "hysteria2-warp",
        "vless-reality-warp"
    ]);
    let mut config = json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [
            {
                "type": "mixed",
                "tag": DESKTOP_TRACE_INBOUND_TAG,
                "listen": "127.0.0.1",
                "listen_port": STAGE2_DESKTOP_PROXY_PORT
            },
            {
                "type": "mixed",
                "tag": WSL_INBOUND_TAG,
                "listen": WSL_INBOUND_BIND_HOST,
                "listen_port": STAGE2_WSL_PROXY_PORT
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": MANAGED_SELECTOR_TAG,
                "outbounds": selector_entries.clone(),
                "default": desktop_route
            },
            {
                "type": "selector",
                "tag": WSL_SELECTOR_TAG,
                "outbounds": selector_entries,
                "default": wsl_route
            },
            {
                "type": "urltest",
                "tag": "auto-direct-tunnel",
                "outbounds": ["hysteria2-direct", "vless-reality-direct"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "10m"
            },
            {
                "type": "urltest",
                "tag": "auto-warp-tunnel",
                "outbounds": ["hysteria2-warp", "vless-reality-warp"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "10m"
            },
            {
                "type": "hysteria2",
                "tag": "hysteria2-direct",
                "server": state.server_ip,
                "server_port": direct.hy2_port,
                "password": direct.hy2_password,
                "tls": { "enabled": true, "server_name": direct.domain }
            },
            {
                "type": "vless",
                "tag": "vless-reality-direct",
                "server": state.server_ip,
                "server_port": direct.vless_port,
                "uuid": direct.vless_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": true,
                    "server_name": reality_server_name,
                    "utls": { "enabled": true, "fingerprint": "chrome" },
                    "reality": {
                        "enabled": true,
                        "public_key": direct.reality_public_key,
                        "short_id": direct.reality_short_id
                    }
                }
            },
            {
                "type": "hysteria2",
                "tag": "hysteria2-warp",
                "server": state.server_ip,
                "server_port": warp.hy2_port,
                "password": warp.hy2_password,
                "tls": { "enabled": true, "server_name": warp.domain }
            },
            {
                "type": "vless",
                "tag": "vless-reality-warp",
                "server": state.server_ip,
                "server_port": warp.vless_port,
                "uuid": warp.vless_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": true,
                    "server_name": reality_server_name,
                    "utls": { "enabled": true, "fingerprint": "chrome" },
                    "reality": {
                        "enabled": true,
                        "public_key": warp.reality_public_key,
                        "short_id": warp.reality_short_id
                    }
                }
            },
            { "type": "direct", "tag": "direct" }
        ],
        "route": {
            "rules": [
                { "inbound": [DESKTOP_TRACE_INBOUND_TAG], "outbound": MANAGED_SELECTOR_TAG },
                { "inbound": [WSL_INBOUND_TAG], "outbound": WSL_SELECTOR_TAG }
            ],
            "final": MANAGED_SELECTOR_TAG,
            "auto_detect_interface": true
        },
        "experimental": {
            "clash_api": {
                "external_controller": format!("127.0.0.1:{STAGE2_CLASH_API_PORT}")
            }
        }
    });

    if mode == WindowsDatapathMode::ManagedTun {
        let inbounds = config
            .get_mut("inbounds")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "Windows config inbounds are not an array".to_owned())?;
        inbounds.push(json!({
            "type": "tun",
            "tag": "managed-tun-in",
            "interface_name": "sing-box-tun",
            "address": ["172.19.0.1/30"],
            "auto_route": true,
            "strict_route": true,
            "dns_mode": "hijack"
        }));
        config["dns"] = json!({
            "servers": [
                {
                    "type": "tls",
                    "tag": "managed-dns",
                    "server": "1.1.1.1",
                    "server_port": 853,
                    "tls": {
                        "enabled": true,
                        "server_name": "cloudflare-dns.com"
                    },
                    "detour": MANAGED_SELECTOR_TAG
                }
            ],
            "final": "managed-dns",
            "strategy": "ipv4_only"
        });
        sync_tun_route_excludes(&mut config, Some(state.server_ip.as_str()));
        sync_stable_bypass_rules(&mut config);
    }

    let has_tun = config
        .get("inbounds")
        .and_then(Value::as_array)
        .is_some_and(|inbounds| {
            inbounds
                .iter()
                .any(|inbound| inbound.get("type").and_then(Value::as_str) == Some("tun"))
        });
    match mode {
        WindowsDatapathMode::ProxyOnly if has_tun => {
            return Err(
                "PROXY_ONLY Windows renderer unexpectedly produced a TUN inbound".to_owned(),
            );
        }
        WindowsDatapathMode::ManagedTun if !has_tun => {
            return Err("MANAGED_TUN Windows renderer did not produce a TUN inbound".to_owned());
        }
        WindowsDatapathMode::Unspecified => {
            return Err("Windows runtime datapath mode is unspecified".to_owned());
        }
        _ => {}
    }

    serde_json::to_vec_pretty(&config)
        .map_err(|err| format!("failed to render Windows config: {err}"))
}

pub fn sync_local_config_from_runtime_state(
    config_path: &Path,
    state: &WindowsRuntimeState,
    runtime_root: &Path,
) -> Result<ConfigSyncSummary, String> {
    let direct = state
        .direct
        .as_ref()
        .ok_or_else(|| "Windows runtime state direct tunnel is missing".to_owned())?;
    let warp = state
        .warp
        .as_ref()
        .ok_or_else(|| "Windows runtime state warp tunnel is missing".to_owned())?;
    let typed = SyncState {
        instance_id: Some(state.instance_id.clone()),
        ip: Some(state.server_ip.clone()),
        tunnel: sync_tunnel_state_from_proto(direct),
        tunnel_warp: sync_tunnel_state_from_proto(warp),
    };
    sync_local_config_from_bindings(config_path, &typed, runtime_root)
}

fn sync_tunnel_state_from_proto(value: &WindowsTunnelBinding) -> SyncTunnelState {
    SyncTunnelState {
        domain: value.domain.clone(),
        hy2_port: value.hy2_port,
        hy2_password: value.hy2_password.clone(),
        vless_port: value.vless_port,
        vless_uuid: value.vless_uuid.clone(),
        reality_public_key: value.reality_public_key.clone(),
        reality_short_id: value.reality_short_id.clone(),
    }
}

fn sync_local_config_from_bindings(
    config_path: &Path,
    state: &SyncState,
    runtime_root: &Path,
) -> Result<ConfigSyncSummary, String> {
    let raw_config = fs::read_to_string(config_path)
        .map_err(|err| format!("unable to read local sing-box config: {err}"))?;

    let mut config: Value = serde_json::from_str(&raw_config)
        .map_err(|err| format!("local sing-box config is not valid JSON: {err}"))?;

    let runtime_root = runtime_root.display().to_string();
    if let Some(clash_api) = config
        .pointer_mut("/experimental/clash_api")
        .and_then(Value::as_object_mut)
    {
        clash_api.insert(
            "external_ui".to_owned(),
            Value::String(format!("{runtime_root}/metacubexd-ui")),
        );
    }
    if let Some(cache_file) = config
        .pointer_mut("/experimental/cache_file")
        .and_then(Value::as_object_mut)
    {
        cache_file.insert(
            "path".to_owned(),
            Value::String(format!("{runtime_root}/cache-dns-vultr-dual.db")),
        );
    }

    sync_tunnel_outbound(
        &mut config,
        "hysteria2-direct",
        &state.tunnel,
        TunnelKind::Hysteria2,
    );
    sync_tunnel_outbound(
        &mut config,
        "vless-reality-direct",
        &state.tunnel,
        TunnelKind::VlessReality,
    );
    sync_tunnel_outbound(
        &mut config,
        "hysteria2-warp",
        &state.tunnel_warp,
        TunnelKind::Hysteria2,
    );
    sync_tunnel_outbound(
        &mut config,
        "vless-reality-warp",
        &state.tunnel_warp,
        TunnelKind::VlessReality,
    );
    sync_tun_route_excludes(&mut config, state.ip.as_deref());
    sync_stable_bypass_rules(&mut config);
    sync_wsl_inbound(&mut config);
    sync_wsl_selector(&mut config);
    sync_wsl_route_rule(&mut config);

    let rendered = serde_json::to_vec_pretty(&config)
        .map_err(|err| format!("failed to render updated config: {err}"))?;
    fs::write(config_path, rendered).map_err(|err| format!("failed to write config: {err}"))?;

    Ok(ConfigSyncSummary {
        instance_id: state.instance_id.clone(),
        config_path: config_path.display().to_string(),
    })
}

fn sync_tun_route_excludes(config: &mut Value, server_ip: Option<&str>) {
    let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) else {
        return;
    };

    let mut required = WARP_CONTROL_ENDPOINTS
        .iter()
        .chain(FOREIGN_CLOUDFLARE_MESH_CIDRS.iter())
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if let Some(server_ip) = server_ip.filter(|value| !value.trim().is_empty()) {
        required.push(format!("{server_ip}/32"));
    }
    for inbound in inbounds {
        let Some(object) = inbound.as_object_mut() else {
            continue;
        };
        if object
            .get("type")
            .and_then(Value::as_str)
            .map(|value| value != "tun")
            .unwrap_or(true)
        {
            continue;
        }

        let excludes = object
            .entry("route_exclude_address".to_owned())
            .or_insert_with(|| Value::Array(Vec::new()));
        if !excludes.is_array() {
            *excludes = Value::Array(Vec::new());
        }
        let excludes = excludes.as_array_mut().expect("array inserted above");
        for cidr in &required {
            let exists = excludes
                .iter()
                .any(|value| value.as_str() == Some(cidr.as_str()));
            if !exists {
                excludes.push(Value::String(cidr.clone()));
            }
        }
    }
}

fn sync_stable_bypass_rules(config: &mut Value) {
    let Some(rules) = config
        .get_mut("route")
        .and_then(Value::as_object_mut)
        .and_then(|route| route.get_mut("rules"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    // Order is security- and correctness-relevant: these flows must bypass
    // TUN before sniffing, inbound selectors, or generic process rules can
    // send them back into sing-box.
    rules.retain(|rule| !is_warp_service_bypass(rule) && !is_loopback_bypass(rule));
    rules.insert(0, direct_process_rule(WARP_SERVICE_PROCESS));
    rules.insert(1, direct_cidr_rule(LOOPBACK_CIDRS));
}

fn is_warp_service_bypass(rule: &Value) -> bool {
    rule.get("outbound").and_then(Value::as_str) == Some("direct")
        && rule
            .get("process_name")
            .and_then(Value::as_array)
            .is_some_and(|names| {
                names
                    .iter()
                    .any(|name| name.as_str() == Some(WARP_SERVICE_PROCESS))
            })
}

fn is_loopback_bypass(rule: &Value) -> bool {
    rule.get("outbound").and_then(Value::as_str) == Some("direct")
        && rule
            .get("ip_cidr")
            .and_then(Value::as_array)
            .is_some_and(|cidrs| {
                LOOPBACK_CIDRS
                    .iter()
                    .all(|expected| cidrs.iter().any(|cidr| cidr.as_str() == Some(expected)))
            })
}

fn direct_process_rule(process_name: &str) -> Value {
    Value::Object(Map::from_iter([
        (
            "process_name".to_owned(),
            Value::Array(vec![Value::String(process_name.to_owned())]),
        ),
        ("outbound".to_owned(), Value::String("direct".to_owned())),
    ]))
}

fn direct_cidr_rule(cidrs: &[&str]) -> Value {
    Value::Object(Map::from_iter([
        (
            "ip_cidr".to_owned(),
            Value::Array(
                cidrs
                    .iter()
                    .map(|cidr| Value::String((*cidr).to_owned()))
                    .collect(),
            ),
        ),
        ("outbound".to_owned(), Value::String("direct".to_owned())),
    ]))
}

fn sync_wsl_inbound(config: &mut Value) {
    let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) else {
        return;
    };

    if let Some(inbound) = inbounds.iter_mut().find(|inbound| {
        inbound
            .get("tag")
            .and_then(Value::as_str)
            .map(|value| value == WSL_INBOUND_TAG)
            .unwrap_or(false)
    }) {
        let Some(object) = inbound.as_object_mut() else {
            return;
        };
        object.insert("type".to_owned(), Value::String("mixed".to_owned()));
        object.insert(
            "listen".to_owned(),
            Value::String(WSL_INBOUND_BIND_HOST.to_owned()),
        );
        object.insert(
            "listen_port".to_owned(),
            Value::Number(DEFAULT_WSL_PROXY_PORT.into()),
        );
        return;
    }

    inbounds.push(Value::Object(Map::from_iter([
        ("type".to_owned(), Value::String("mixed".to_owned())),
        ("tag".to_owned(), Value::String(WSL_INBOUND_TAG.to_owned())),
        (
            "listen".to_owned(),
            Value::String(WSL_INBOUND_BIND_HOST.to_owned()),
        ),
        (
            "listen_port".to_owned(),
            Value::Number(DEFAULT_WSL_PROXY_PORT.into()),
        ),
    ])));
}

fn sync_wsl_selector(config: &mut Value) {
    let Some(outbounds) = config.get_mut("outbounds").and_then(Value::as_array_mut) else {
        return;
    };

    let expected = EXPECTED_OUTBOUND_TAGS
        .iter()
        .map(|value| Value::String((*value).to_owned()))
        .collect::<Vec<_>>();

    if let Some(outbound) = outbounds.iter_mut().find(|outbound| {
        outbound
            .get("tag")
            .and_then(Value::as_str)
            .map(|value| value == WSL_SELECTOR_TAG)
            .unwrap_or(false)
    }) {
        let Some(object) = outbound.as_object_mut() else {
            return;
        };
        object.insert("type".to_owned(), Value::String("selector".to_owned()));
        object.insert(
            "default".to_owned(),
            Value::String("auto-direct-tunnel".to_owned()),
        );
        object.insert("outbounds".to_owned(), Value::Array(expected));
        return;
    }

    outbounds.push(Value::Object(Map::from_iter([
        ("type".to_owned(), Value::String("selector".to_owned())),
        ("tag".to_owned(), Value::String(WSL_SELECTOR_TAG.to_owned())),
        (
            "default".to_owned(),
            Value::String("auto-direct-tunnel".to_owned()),
        ),
        ("outbounds".to_owned(), Value::Array(expected)),
    ])));
}

fn sync_wsl_route_rule(config: &mut Value) {
    let Some(rules) = config
        .get_mut("route")
        .and_then(Value::as_object_mut)
        .and_then(|route| route.get_mut("rules"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    for rule in rules.iter_mut() {
        let Some(object) = rule.as_object_mut() else {
            continue;
        };
        let Some(inbound) = object.get("inbound").and_then(Value::as_array) else {
            continue;
        };
        let matches = inbound
            .iter()
            .any(|value| value.as_str() == Some(WSL_INBOUND_TAG));
        if !matches {
            continue;
        }
        object.insert(
            "outbound".to_owned(),
            Value::String(WSL_SELECTOR_TAG.to_owned()),
        );
        object.insert(
            "inbound".to_owned(),
            Value::Array(vec![Value::String(WSL_INBOUND_TAG.to_owned())]),
        );
        return;
    }

    let insert_at = rules
        .iter()
        .position(|rule| {
            rule.get("inbound")
                .and_then(Value::as_array)
                .is_some_and(|inbound| {
                    inbound
                        .iter()
                        .any(|value| value.as_str() == Some("mixed-in"))
                })
        })
        .unwrap_or(rules.len());
    rules.insert(
        insert_at,
        Value::Object(Map::from_iter([
            (
                "inbound".to_owned(),
                Value::Array(vec![Value::String(WSL_INBOUND_TAG.to_owned())]),
            ),
            (
                "outbound".to_owned(),
                Value::String(WSL_SELECTOR_TAG.to_owned()),
            ),
        ])),
    );
}

#[derive(Debug, Clone)]
struct WslProxyEndpoint {
    published_host: Option<String>,
    warnings: Vec<String>,
}

fn resolve_wsl_proxy_endpoint() -> WslProxyEndpoint {
    let mut warnings = Vec::new();

    if let Some(ip) = resolve_ubuntu_gateway_ipv4() {
        return WslProxyEndpoint {
            published_host: Some(ip),
            warnings,
        };
    }

    let adapter_ips = resolve_wsl_adapter_ipv4s();
    match adapter_ips.as_slice() {
        [only] => WslProxyEndpoint {
            published_host: Some(only.clone()),
            warnings: vec![
                "Ubuntu WSL gateway could not be resolved directly; using single detected WSL adapter IPv4"
                    .to_owned(),
            ],
        },
        [] => WslProxyEndpoint {
            published_host: None,
            warnings: vec![
                "Ubuntu WSL gateway could not be resolved; verify WSL is running before using the Ubuntu proxy"
                    .to_owned(),
            ],
        },
        many => {
            warnings.push(format!(
                "multiple WSL adapter IPv4 addresses detected ({}); Ubuntu endpoint may require verification",
                many.join(", ")
            ));
            WslProxyEndpoint {
                published_host: None,
                warnings,
            }
        }
    }
}

fn resolve_ubuntu_gateway_ipv4() -> Option<String> {
    #[cfg(windows)]
    {
        let output = Command::new("wsl.exe")
            .args([
                "-d",
                "Ubuntu",
                "bash",
                "-lc",
                "ip route show default | cut -d' ' -f3",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if value.parse::<Ipv4Addr>().is_err() {
            None
        } else {
            Some(value)
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn resolve_wsl_adapter_ipv4s() -> Vec<String> {
    #[cfg(windows)]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like 'vEthernet (WSL*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress",
            ])
            .output();
        let Ok(output) = output else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| line.parse::<Ipv4Addr>().is_ok())
            .map(ToOwned::to_owned)
            .collect()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

pub fn default_trace_proxy_url(config_path: &Path) -> Result<Option<String>, String> {
    trace_proxy_url_for_inbound(config_path, DESKTOP_TRACE_INBOUND_TAG)
}

pub fn ubuntu_trace_proxy_url(config_path: &Path) -> Result<Option<String>, String> {
    trace_proxy_url_for_inbound(config_path, WSL_INBOUND_TAG)
}

fn trace_proxy_url_for_inbound(
    config_path: &Path,
    inbound_tag: &str,
) -> Result<Option<String>, String> {
    let raw_config = fs::read_to_string(config_path)
        .map_err(|err| format!("unable to read local sing-box config: {err}"))?;
    let parsed: TraceConfig = serde_json::from_str(&raw_config)
        .map_err(|err| format!("invalid local config JSON: {err}"))?;

    Ok(parsed.inbounds.into_iter().find_map(|inbound| {
        if inbound.kind == "mixed" && inbound.tag == inbound_tag {
            let host = inbound.listen.unwrap_or_else(|| "127.0.0.1".to_owned());
            inbound
                .listen_port
                .map(|port| format!("http://{host}:{port}"))
        } else {
            None
        }
    }))
}

fn compare_tunnel_binding(
    parsed: &SingboxConfig,
    hy2_tag: &str,
    vless_tag: &str,
    expected_server: &str,
    expected: &TunnelBinding,
    local_singbox: &mut LocalSingboxState,
    selector: &mut SelectorState,
) {
    let Some(hy2) = parsed
        .outbounds
        .iter()
        .find(|outbound| outbound.tag == hy2_tag)
    else {
        local_singbox
            .warnings
            .push(format!("managed config is missing outbound {hy2_tag}"));
        selector.degraded = true;
        return;
    };

    let Some(vless) = parsed
        .outbounds
        .iter()
        .find(|outbound| outbound.tag == vless_tag)
    else {
        local_singbox
            .warnings
            .push(format!("managed config is missing outbound {vless_tag}"));
        selector.degraded = true;
        return;
    };

    compare_field(
        local_singbox,
        selector,
        hy2_tag,
        "server",
        hy2.server.as_deref(),
        Some(expected_server),
    );
    compare_field(
        local_singbox,
        selector,
        hy2_tag,
        "server_port",
        hy2.server_port,
        Some(expected.hy2_port),
    );
    compare_field(
        local_singbox,
        selector,
        hy2_tag,
        "password",
        hy2.password.as_deref(),
        Some(expected.hy2_password.as_str()),
    );
    compare_field(
        local_singbox,
        selector,
        hy2_tag,
        "tls.server_name",
        hy2.tls.as_ref().and_then(|tls| tls.server_name.as_deref()),
        Some(expected.domain.as_str()),
    );
    compare_field(
        local_singbox,
        selector,
        vless_tag,
        "server",
        vless.server.as_deref(),
        Some(expected_server),
    );
    compare_field(
        local_singbox,
        selector,
        vless_tag,
        "server_port",
        vless.server_port,
        Some(expected.vless_port),
    );
    compare_field(
        local_singbox,
        selector,
        vless_tag,
        "uuid",
        vless.uuid.as_deref(),
        Some(expected.vless_uuid.as_str()),
    );
    compare_field(
        local_singbox,
        selector,
        vless_tag,
        "tls.reality.public_key",
        vless
            .tls
            .as_ref()
            .and_then(|tls| tls.reality.as_ref())
            .and_then(|reality| reality.public_key.as_deref()),
        Some(expected.reality_public_key.as_str()),
    );
    compare_field(
        local_singbox,
        selector,
        vless_tag,
        "tls.reality.short_id",
        vless
            .tls
            .as_ref()
            .and_then(|tls| tls.reality.as_ref())
            .and_then(|reality| reality.short_id.as_deref()),
        Some(expected.reality_short_id.as_str()),
    );
}

fn compare_field<T>(
    local_singbox: &mut LocalSingboxState,
    selector: &mut SelectorState,
    outbound_tag: &str,
    field_name: &str,
    observed: Option<T>,
    expected: Option<T>,
) where
    T: PartialEq + std::fmt::Display,
{
    if observed == expected {
        return;
    }

    let observed = observed
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<missing>".to_owned());
    let expected = expected
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<missing>".to_owned());
    local_singbox.warnings.push(format!(
        "{outbound_tag}.{field_name} does not match live state: config={observed}, state={expected}"
    ));
    selector.degraded = true;
}

#[derive(Debug)]
struct ProcessObservation {
    config_path: Option<String>,
}

fn detect_process(expected_config_path: &Path) -> Option<ProcessObservation> {
    let proc_dir = Path::new("/proc");
    let entries = fs::read_dir(proc_dir).ok()?;

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid = file_name.to_string_lossy();
        if !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }

        let cmdline_path = entry.path().join("cmdline");
        let bytes = match fs::read(cmdline_path) {
            Ok(bytes) if !bytes.is_empty() => bytes,
            _ => continue,
        };

        let parts = bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).to_string())
            .collect::<Vec<_>>();
        if parts.is_empty() || !parts[0].contains("sing-box") {
            continue;
        }

        let config_path = extract_config_path(&parts);
        if let Some(candidate) = config_path.as_deref()
            && same_path_string(candidate, expected_config_path)
        {
            return Some(ProcessObservation { config_path });
        }
    }

    None
}

fn extract_config_path(arguments: &[String]) -> Option<String> {
    arguments.windows(2).find_map(|window| {
        if window[0] == "-c" || window[0] == "--config" {
            Some(window[1].clone())
        } else {
            None
        }
    })
}

fn same_path_string(candidate: &str, expected: &Path) -> bool {
    let candidate = PathBuf::from(candidate);
    if candidate == expected {
        return true;
    }

    match (candidate.canonicalize(), expected.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn parse_controller_port(value: &str) -> Option<u32> {
    value.rsplit(':').next()?.parse().ok()
}

#[derive(Clone, Copy)]
enum TunnelKind {
    Hysteria2,
    VlessReality,
}

fn sync_tunnel_outbound(config: &mut Value, tag: &str, tunnel: &SyncTunnelState, kind: TunnelKind) {
    let Some(outbound) = find_outbound_mut(config, tag) else {
        return;
    };

    let Some(object) = outbound.as_object_mut() else {
        return;
    };

    object.insert("server".to_owned(), Value::String(tunnel.domain.clone()));
    match kind {
        TunnelKind::Hysteria2 => {
            object.insert(
                "server_port".to_owned(),
                Value::Number(tunnel.hy2_port.into()),
            );
            object.insert(
                "password".to_owned(),
                Value::String(tunnel.hy2_password.clone()),
            );
            let tls = ensure_child_object(object, "tls");
            tls.insert(
                "server_name".to_owned(),
                Value::String(tunnel.domain.clone()),
            );
        }
        TunnelKind::VlessReality => {
            object.insert(
                "server_port".to_owned(),
                Value::Number(tunnel.vless_port.into()),
            );
            object.insert("uuid".to_owned(), Value::String(tunnel.vless_uuid.clone()));
            let tls = ensure_child_object(object, "tls");
            let reality = ensure_child_object(tls, "reality");
            reality.insert(
                "public_key".to_owned(),
                Value::String(tunnel.reality_public_key.clone()),
            );
            reality.insert(
                "short_id".to_owned(),
                Value::String(tunnel.reality_short_id.clone()),
            );
        }
    }
}

fn find_outbound_mut<'a>(config: &'a mut Value, tag: &str) -> Option<&'a mut Value> {
    config
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .and_then(|outbounds| {
            outbounds.iter_mut().find(|outbound| {
                outbound
                    .get("tag")
                    .and_then(Value::as_str)
                    .map(|value| value == tag)
                    .unwrap_or(false)
            })
        })
}

fn ensure_child_object<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
) -> &'a mut Map<String, Value> {
    let value = parent
        .entry(key.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !value.is_object() {
        *value = Value::Object(Map::new());
    }
    value.as_object_mut().expect("object inserted above")
}

#[derive(Debug, Deserialize)]
struct SingboxConfig {
    #[serde(default)]
    inbounds: Vec<Inbound>,
    #[serde(default)]
    outbounds: Vec<Outbound>,
    experimental: Option<Experimental>,
}

#[derive(Debug, Deserialize)]
struct Experimental {
    clash_api: Option<ClashApi>,
}

#[derive(Debug, Deserialize)]
struct ClashApi {
    external_controller: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Outbound {
    #[serde(rename = "type")]
    kind: String,
    tag: String,
    #[serde(default)]
    outbounds: Vec<String>,
    default: Option<String>,
    server: Option<String>,
    server_port: Option<u32>,
    password: Option<String>,
    uuid: Option<String>,
    tls: Option<Tls>,
}

#[derive(Debug, Deserialize)]
struct Inbound {
    #[serde(rename = "type")]
    kind: String,
    tag: String,
    listen: Option<String>,
    listen_port: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Tls {
    server_name: Option<String>,
    reality: Option<Reality>,
}

#[derive(Debug, Deserialize)]
struct Reality {
    public_key: Option<String>,
    short_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SyncState {
    instance_id: Option<String>,
    ip: Option<String>,
    tunnel: SyncTunnelState,
    tunnel_warp: SyncTunnelState,
}

#[derive(Debug, Deserialize)]
struct SyncTunnelState {
    domain: String,
    hy2_port: u32,
    hy2_password: String,
    vless_port: u32,
    vless_uuid: String,
    reality_public_key: String,
    reality_short_id: String,
}

#[derive(Debug, Deserialize)]
struct TraceConfig {
    #[serde(default)]
    inbounds: Vec<TraceInbound>,
}

#[derive(Debug, Deserialize)]
struct TraceInbound {
    #[serde(rename = "type")]
    kind: String,
    tag: String,
    listen: Option<String>,
    listen_port: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn inspects_managed_dual_config() {
        let repo_root = unique_test_dir();
        let config_path = repo_root.join("edge-dns-clean-vultr-dual.json");
        fs::create_dir_all(&repo_root).unwrap();
        fs::write(
            &config_path,
            r#"{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090"
    }
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "wsl-mixed-in",
      "listen": "0.0.0.0",
      "listen_port": 17890
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy-selector",
      "outbounds": [
        "auto-direct-tunnel",
        "auto-warp-tunnel",
        "hysteria2-direct",
        "vless-reality-direct",
        "hysteria2-warp",
        "vless-reality-warp"
      ],
      "default": "auto-direct-tunnel"
    },
    {
      "type": "selector",
      "tag": "wsl-selector",
      "outbounds": [
        "auto-direct-tunnel",
        "auto-warp-tunnel",
        "hysteria2-direct",
        "vless-reality-direct",
        "hysteria2-warp",
        "vless-reality-warp"
      ],
      "default": "auto-direct-tunnel"
    },
    { "type": "urltest", "tag": "auto-direct-tunnel" },
    { "type": "urltest", "tag": "auto-warp-tunnel" },
    {
      "type": "hysteria2",
      "tag": "hysteria2-direct",
      "server": "203.0.113.10",
      "server_port": 8443,
      "password": "direct-password",
      "tls": { "server_name": "edge.alegria.by" }
    },
    {
      "type": "vless",
      "tag": "vless-reality-direct",
      "server": "203.0.113.10",
      "server_port": 443,
      "uuid": "direct-uuid",
      "tls": {
        "reality": {
          "public_key": "direct-public-key",
          "short_id": "direct-short-id"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-warp",
      "server": "203.0.113.10",
      "server_port": 9444,
      "password": "warp-password",
      "tls": { "server_name": "edge.alegria.by" }
    },
    {
      "type": "vless",
      "tag": "vless-reality-warp",
      "server": "203.0.113.10",
      "server_port": 5443,
      "uuid": "warp-uuid",
      "tls": {
        "reality": {
          "public_key": "warp-public-key",
          "short_id": "warp-short-id"
        }
      }
    }
  ]
}"#,
        )
        .unwrap();

        let observation = inspect_local_config(
            &config_path,
            Some(&ExpectedTunnelBindings {
                server: "203.0.113.10".to_owned(),
                direct: TunnelBinding {
                    domain: "edge.alegria.by".to_owned(),
                    hy2_port: 8443,
                    hy2_password: "direct-password".to_owned(),
                    vless_port: 443,
                    vless_uuid: "direct-uuid".to_owned(),
                    reality_public_key: "direct-public-key".to_owned(),
                    reality_short_id: "direct-short-id".to_owned(),
                },
                warp: TunnelBinding {
                    domain: "edge.alegria.by".to_owned(),
                    hy2_port: 9444,
                    hy2_password: "warp-password".to_owned(),
                    vless_port: 5443,
                    vless_uuid: "warp-uuid".to_owned(),
                    reality_public_key: "warp-public-key".to_owned(),
                    reality_short_id: "warp-short-id".to_owned(),
                },
            }),
        );
        assert!(observation.local_singbox.managed_config);
        assert_eq!(observation.local_singbox.clash_api_port, Some(9090));
        assert_eq!(
            observation.selector.desired_main_route.as_deref(),
            Some("auto-direct-tunnel")
        );
        assert_eq!(
            observation.ubuntu_selector.desired_main_route.as_deref(),
            Some("auto-direct-tunnel")
        );
        assert_eq!(observation.ubuntu_proxy.port, Some(17890));
        assert!(observation.ubuntu_proxy.url.is_some());
        assert!(!observation.selector.degraded);

        fs::remove_dir_all(repo_root).unwrap();
    }

    #[test]
    fn flags_missing_selector() {
        let repo_root = unique_test_dir();
        let config_path = repo_root.join("edge-dns-clean-vultr-dual.json");
        fs::create_dir_all(&repo_root).unwrap();
        fs::write(
            &config_path,
            r#"{
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}"#,
        )
        .unwrap();

        let observation = inspect_local_config(&config_path, None);
        assert!(!observation.local_singbox.managed_config);
        assert!(observation.selector.degraded);
        assert!(
            observation
                .selector
                .warnings
                .iter()
                .any(|warning| warning.contains("proxy-selector"))
        );
        assert!(observation.ubuntu_selector.degraded);
        assert!(
            observation
                .local_singbox
                .warnings
                .iter()
                .any(|warning| warning.contains("live tunnel state is unavailable"))
        );

        fs::remove_dir_all(repo_root).unwrap();
    }

    #[test]
    fn flags_config_state_mismatch() {
        let repo_root = unique_test_dir();
        let config_path = repo_root.join("edge-dns-clean-vultr-dual.json");
        fs::create_dir_all(&repo_root).unwrap();
        fs::write(
            &config_path,
            r#"{
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy-selector",
      "outbounds": [
        "auto-direct-tunnel",
        "auto-warp-tunnel",
        "hysteria2-direct",
        "vless-reality-direct",
        "hysteria2-warp",
        "vless-reality-warp"
      ],
      "default": "auto-direct-tunnel"
    },
    {
      "type": "selector",
      "tag": "wsl-selector",
      "outbounds": [
        "auto-direct-tunnel",
        "auto-warp-tunnel",
        "hysteria2-direct",
        "vless-reality-direct",
        "hysteria2-warp",
        "vless-reality-warp"
      ],
      "default": "auto-direct-tunnel"
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-direct",
      "server": "198.51.100.9",
      "server_port": 8443,
      "password": "direct-password",
      "tls": { "server_name": "wrong.example.com" }
    },
    {
      "type": "vless",
      "tag": "vless-reality-direct",
      "server": "203.0.113.10",
      "server_port": 443,
      "uuid": "direct-uuid",
      "tls": {
        "reality": {
          "public_key": "wrong-public-key",
          "short_id": "direct-short-id"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-warp",
      "server": "203.0.113.10",
      "server_port": 9444,
      "password": "warp-password",
      "tls": { "server_name": "edge.alegria.by" }
    },
    {
      "type": "vless",
      "tag": "vless-reality-warp",
      "server": "203.0.113.10",
      "server_port": 5443,
      "uuid": "warp-uuid",
      "tls": {
        "reality": {
          "public_key": "warp-public-key",
          "short_id": "warp-short-id"
        }
      }
    }
  ]
}"#,
        )
        .unwrap();

        let observation = inspect_local_config(
            &config_path,
            Some(&ExpectedTunnelBindings {
                server: "203.0.113.10".to_owned(),
                direct: TunnelBinding {
                    domain: "edge.alegria.by".to_owned(),
                    hy2_port: 8443,
                    hy2_password: "direct-password".to_owned(),
                    vless_port: 443,
                    vless_uuid: "direct-uuid".to_owned(),
                    reality_public_key: "direct-public-key".to_owned(),
                    reality_short_id: "direct-short-id".to_owned(),
                },
                warp: TunnelBinding {
                    domain: "edge.alegria.by".to_owned(),
                    hy2_port: 9444,
                    hy2_password: "warp-password".to_owned(),
                    vless_port: 5443,
                    vless_uuid: "warp-uuid".to_owned(),
                    reality_public_key: "warp-public-key".to_owned(),
                    reality_short_id: "warp-short-id".to_owned(),
                },
            }),
        );

        assert!(observation.selector.degraded);
        assert!(
            observation
                .local_singbox
                .warnings
                .iter()
                .any(|warning| warning.contains("does not match live state"))
        );

        fs::remove_dir_all(repo_root).unwrap();
    }

    #[test]
    fn syncs_local_config_from_state() {
        let repo_root = unique_test_dir();
        let config_path = repo_root.join("edge-dns-clean-vultr-dual.json");
        let state_path = repo_root.join("current-edge.json");
        let runtime_root = repo_root.join("runtime");
        fs::create_dir_all(&repo_root).unwrap();
        fs::write(
            &config_path,
            r#"{
  "outbounds": [
    { "type": "hysteria2", "tag": "hysteria2-direct", "tls": {} },
    { "type": "vless", "tag": "vless-reality-direct", "tls": { "reality": {} } },
    { "type": "hysteria2", "tag": "hysteria2-warp", "tls": {} },
    { "type": "vless", "tag": "vless-reality-warp", "tls": { "reality": {} } }
  ],
  "inbounds": [{ "type": "tun", "tag": "tun-in", "route_exclude_address": [] }],
  "route": { "rules": [] },
  "experimental": {
    "cache_file": {},
    "clash_api": {}
  }
}"#,
        )
        .unwrap();
        fs::write(
            &state_path,
            r#"{
  "instance_id":"instance-1",
  "tunnel":{
    "domain":"edge.example.com",
    "hy2_port":8443,
    "hy2_password":"direct-password",
    "vless_port":443,
    "vless_uuid":"direct-uuid",
    "reality_public_key":"direct-public-key",
    "reality_short_id":"direct-short-id"
  },
  "tunnel_warp":{
    "domain":"edge.example.com",
    "hy2_port":9444,
    "hy2_password":"warp-password",
    "vless_port":5443,
    "vless_uuid":"warp-uuid",
    "reality_public_key":"warp-public-key",
    "reality_short_id":"warp-short-id"
  }
}"#,
        )
        .unwrap();

        let summary = sync_local_config(&config_path, &state_path, &runtime_root).unwrap();
        assert_eq!(summary.instance_id.as_deref(), Some("instance-1"));

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(
            updated
                .pointer("/experimental/clash_api/external_ui")
                .and_then(serde_json::Value::as_str),
            Some(format!("{}/metacubexd-ui", runtime_root.display()).as_str())
        );
        assert_eq!(
            updated
                .pointer("/outbounds/0/server")
                .and_then(serde_json::Value::as_str),
            Some("edge.example.com")
        );
        assert_eq!(
            updated
                .pointer("/outbounds/1/tls/reality/public_key")
                .and_then(serde_json::Value::as_str),
            Some("direct-public-key")
        );
        assert_eq!(
            updated
                .pointer("/inbounds/1/tag")
                .and_then(serde_json::Value::as_str),
            Some("wsl-mixed-in")
        );
        assert_eq!(
            updated
                .pointer("/inbounds/1/listen")
                .and_then(serde_json::Value::as_str),
            Some("0.0.0.0")
        );
        assert_eq!(
            updated
                .pointer("/route/rules/0/process_name/0")
                .and_then(serde_json::Value::as_str),
            Some(WARP_SERVICE_PROCESS)
        );
        assert_eq!(
            updated
                .pointer("/route/rules/1/ip_cidr/0")
                .and_then(serde_json::Value::as_str),
            Some("127.0.0.0/8")
        );
        let excludes = updated
            .pointer("/inbounds/0/route_exclude_address")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert!(
            excludes
                .iter()
                .any(|value| { value.as_str() == Some("162.159.197.2/32") })
        );

        fs::remove_dir_all(repo_root).unwrap();
    }

    #[test]
    fn derives_default_trace_proxy_url_from_config() {
        let repo_root = unique_test_dir();
        let config_path = repo_root.join("edge-dns-clean-vultr-dual.json");
        fs::create_dir_all(&repo_root).unwrap();
        fs::write(
            &config_path,
            r#"{
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890 },
    { "type": "mixed", "tag": "wsl-mixed-in", "listen": "172.26.16.1", "listen_port": 17890 }
  ]
}"#,
        )
        .unwrap();

        let proxy = default_trace_proxy_url(&config_path).unwrap();
        assert_eq!(proxy.as_deref(), Some("http://127.0.0.1:7890"));
        let ubuntu_proxy = ubuntu_trace_proxy_url(&config_path).unwrap();
        assert_eq!(ubuntu_proxy.as_deref(), Some("http://172.26.16.1:17890"));

        fs::remove_dir_all(repo_root).unwrap();
    }

    #[test]
    fn falls_back_to_single_adapter_ip_when_gateway_unavailable() {
        let endpoint = WslProxyEndpoint {
            published_host: Some("172.26.16.1".to_owned()),
            warnings: vec![
                "Ubuntu WSL gateway could not be resolved directly; using single detected WSL adapter IPv4"
                    .to_owned(),
            ],
        };
        assert_eq!(endpoint.published_host.as_deref(), Some("172.26.16.1"));
        assert_eq!(endpoint.warnings.len(), 1);
    }

    fn stage2_runtime_state() -> WindowsRuntimeState {
        WindowsRuntimeState {
            schema_version: 1,
            deployment_label: Some("production".to_owned()),
            instance_id: "production-1".to_owned(),
            server_ip: "203.0.113.10".to_owned(),
            direct: Some(WindowsTunnelBinding {
                domain: "edge.example.com".to_owned(),
                hy2_port: 8443,
                hy2_password: "direct-password".to_owned(),
                vless_port: 443,
                vless_uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
                reality_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                reality_short_id: "0011223344556677".to_owned(),
            }),
            warp: Some(WindowsTunnelBinding {
                domain: "edge.example.com".to_owned(),
                hy2_port: 9444,
                hy2_password: "warp-password".to_owned(),
                vless_port: 5443,
                vless_uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
                reality_public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
                reality_short_id: "8899aabbccddeeff".to_owned(),
            }),
        }
    }

    #[test]
    fn git_route_policy_defaults_are_rendered_for_both_selectors() {
        let desired = canonical_production_desired_state().unwrap();
        let routes = desired.windows_route_policy.unwrap();
        let rendered = render_windows_config_for_mode(
            &stage2_runtime_state(),
            WindowsDatapathMode::ManagedTun,
        )
        .unwrap();
        let config: Value = serde_json::from_slice(&rendered).unwrap();
        let outbounds = config.get("outbounds").and_then(Value::as_array).unwrap();
        for (tag, value) in [
            ("proxy-selector", routes.desktop),
            ("wsl-selector", routes.wsl),
        ] {
            let selector = outbounds
                .iter()
                .find(|item| item.get("tag").and_then(Value::as_str) == Some(tag))
                .unwrap();
            assert_eq!(
                selector.get("default").and_then(Value::as_str),
                Some(production_windows_route_tag(value).unwrap())
            );
        }
        assert_eq!(production_windows_route_tag(0).is_err(), true);
        assert_eq!(production_windows_route_tag(12345).is_err(), true);
        assert_eq!(production_windows_route_tag(2).unwrap(), "hysteria2-direct");
        assert_eq!(
            production_windows_route_tag(6).unwrap(),
            "vless-reality-warp"
        );
    }

    #[test]
    fn windows_vless_outbounds_match_canonical_vm_vision_flow() {
        // VM line1-gateway requires users[].flow=xtls-rprx-vision on both
        // Reality inbounds; the outbound must send that exact flow too.
        for mode in [
            WindowsDatapathMode::ProxyOnly,
            WindowsDatapathMode::ManagedTun,
        ] {
            let rendered = render_windows_config_for_mode(&stage2_runtime_state(), mode).unwrap();
            let config: Value = serde_json::from_slice(&rendered).unwrap();
            let outbounds = config.get("outbounds").and_then(Value::as_array).unwrap();
            for tag in ["vless-reality-direct", "vless-reality-warp"] {
                let outbound = outbounds
                    .iter()
                    .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some(tag))
                    .unwrap();
                assert_eq!(
                    outbound.get("flow").and_then(Value::as_str),
                    Some("xtls-rprx-vision"),
                    "{tag} requires the VM inbound's Reality flow"
                );
            }
        }
    }

    #[test]
    fn stage2_renderer_is_proxy_only_and_uses_dedicated_ports() {
        let rendered =
            render_windows_config_for_mode(&stage2_runtime_state(), WindowsDatapathMode::ProxyOnly)
                .unwrap();
        let config: Value = serde_json::from_slice(&rendered).unwrap();
        let inbounds = config.get("inbounds").and_then(Value::as_array).unwrap();

        assert!(
            inbounds
                .iter()
                .all(|inbound| { inbound.get("type").and_then(Value::as_str) != Some("tun") })
        );
        assert_eq!(
            inbounds[0].get("listen_port").and_then(Value::as_u64),
            Some(STAGE2_DESKTOP_PROXY_PORT as u64)
        );
        assert_eq!(
            inbounds[1].get("listen_port").and_then(Value::as_u64),
            Some(STAGE2_WSL_PROXY_PORT as u64)
        );
        assert_eq!(
            config
                .pointer("/experimental/clash_api/external_controller")
                .and_then(Value::as_str),
            Some("127.0.0.1:19091")
        );
        assert!(config.get("dns").is_none());
        assert!(config.pointer("/route/default_domain_resolver").is_none());
        let outbounds = config.get("outbounds").and_then(Value::as_array).unwrap();
        for tag in [
            "hysteria2-direct",
            "vless-reality-direct",
            "hysteria2-warp",
            "vless-reality-warp",
        ] {
            let outbound = outbounds
                .iter()
                .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some(tag))
                .unwrap();
            assert_eq!(
                outbound.get("server").and_then(Value::as_str),
                Some("203.0.113.10")
            );
        }
        let hysteria_direct = outbounds
            .iter()
            .find(|outbound| {
                outbound.get("tag").and_then(Value::as_str) == Some("hysteria2-direct")
            })
            .unwrap();
        assert_eq!(
            hysteria_direct
                .pointer("/tls/server_name")
                .and_then(Value::as_str),
            Some("edge.example.com")
        );
    }

    #[test]
    fn stage4b_renderer_emits_managed_tun_without_changing_proxy_mode_default() {
        let state = stage2_runtime_state();
        let rendered =
            render_windows_config_for_mode(&state, WindowsDatapathMode::ManagedTun).unwrap();
        let config: Value = serde_json::from_slice(&rendered).unwrap();
        let inbounds = config.get("inbounds").and_then(Value::as_array).unwrap();
        assert_eq!(
            inbounds
                .iter()
                .filter(|inbound| inbound.get("type").and_then(Value::as_str) == Some("tun"))
                .count(),
            1
        );
        let tun = inbounds
            .iter()
            .find(|inbound| inbound.get("type").and_then(Value::as_str) == Some("tun"))
            .unwrap();
        assert_eq!(
            tun.get("interface_name").and_then(Value::as_str),
            Some("sing-box-tun")
        );
        assert_eq!(tun.get("auto_route").and_then(Value::as_bool), Some(true));
        assert_eq!(tun.get("strict_route").and_then(Value::as_bool), Some(true));
        assert!(tun.get("auto_redirect").is_none());
        assert_eq!(tun.get("dns_mode").and_then(Value::as_str), Some("hijack"));
        let excludes = tun
            .get("route_exclude_address")
            .and_then(Value::as_array)
            .unwrap();
        for required in [
            "203.0.113.10/32",
            "100.96.0.0/12",
            "162.159.197.2/32",
            "162.159.197.3/32",
            "162.159.197.4/32",
            "162.159.137.105/32",
            "162.159.138.105/32",
        ] {
            assert!(
                excludes
                    .iter()
                    .any(|value| value.as_str() == Some(required)),
                "managed TUN must exclude {required}"
            );
        }
        assert_eq!(
            config.pointer("/dns/final").and_then(Value::as_str),
            Some("managed-dns")
        );
        assert!(
            config
                .pointer("/route/rules")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .any(|rule| {
                    rule.get("process_name")
                        .and_then(Value::as_array)
                        .is_some_and(|names| {
                            names
                                .iter()
                                .any(|name| name.as_str() == Some(WARP_SERVICE_PROCESS))
                        })
                        && rule.get("outbound").and_then(Value::as_str) == Some("direct")
                })
        );
    }

    // Offline Stage 4B.2-C experiment only: production renders hijack and
    // never exposes an unaccepted native DNS knob to the Windows controller.
    fn stage4b_offline_native_dns_candidate() -> (Value, Value) {
        let accepted: Value = serde_json::from_slice(
            &render_windows_config_for_mode(
                &stage2_runtime_state(),
                WindowsDatapathMode::ManagedTun,
            )
            .unwrap(),
        )
        .unwrap();
        let mut candidate = accepted.clone();
        let inbounds = candidate
            .get_mut("inbounds")
            .and_then(Value::as_array_mut)
            .unwrap();
        let tun = inbounds
            .iter_mut()
            .find(|inbound| {
                inbound.get("tag").and_then(Value::as_str) == Some("managed-tun-in")
            })
            .unwrap();
        assert_eq!(tun.get("dns_mode").and_then(Value::as_str), Some("hijack"));
        tun["dns_mode"] = Value::String("native".to_owned());
        (accepted, candidate)
    }

    #[test]
    fn stage4b_native_dns_offline_candidate_changes_exactly_one_field() {
        let (accepted, candidate) = stage4b_offline_native_dns_candidate();
        let tun = candidate["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some("managed-tun-in"))
            .unwrap();
        assert_eq!(tun.get("dns_mode").and_then(Value::as_str), Some("native"));
        assert_eq!(tun.get("strict_route").and_then(Value::as_bool), Some(true));
        assert_eq!(tun.get("auto_route").and_then(Value::as_bool), Some(true));

        let mut reverted = candidate;
        let tun = reverted["inbounds"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some("managed-tun-in"))
            .unwrap();
        tun["dns_mode"] = Value::String("hijack".to_owned());
        assert_eq!(reverted, accepted, "offline experiment changed another field");
        let authoritative: Value =
            serde_json::from_slice(&render_windows_config(&stage2_runtime_state()).unwrap())
                .unwrap();
        assert_eq!(
            authoritative, accepted,
            "offline experiment must not alter canonical production rendering"
        );
    }

    #[test]
    fn stage4b_native_dns_offline_candidate_passes_exact_sing_box_check_when_supplied() {
        let Some(binary) = std::env::var_os("EDGE_TEST_SING_BOX") else {
            return; // Native config validation runs with the locked binary in Windows CI.
        };
        let (_accepted, candidate) = stage4b_offline_native_dns_candidate();
        let repo_root = unique_test_dir();
        fs::create_dir_all(&repo_root).unwrap();
        let config_path = repo_root.join("stage4b-offline-native-dns-candidate.json");
        fs::write(&config_path, serde_json::to_vec(&candidate).unwrap()).unwrap();

        let status = Command::new(binary)
            .args(["check", "-c"])
            .arg(&config_path)
            .status()
            .unwrap();
        let _ = fs::remove_dir_all(repo_root);
        assert!(
            status.success(),
            "exact pinned sing-box rejected offline-only native DNS candidate"
        );
    }

    #[test]
    fn exact_sing_box_accepts_stage4b_managed_tun_config_when_supplied() {
        let Some(binary) = std::env::var_os("EDGE_TEST_SING_BOX") else {
            return;
        };
        let repo_root = unique_test_dir();
        fs::create_dir_all(&repo_root).unwrap();
        let config_path = repo_root.join("stage4b-managed-tun.json");
        let state = stage2_runtime_state();
        fs::write(
            &config_path,
            render_windows_config_for_mode(&state, WindowsDatapathMode::ManagedTun).unwrap(),
        )
        .unwrap();

        let status = Command::new(binary)
            .args(["check", "-c"])
            .arg(&config_path)
            .status()
            .unwrap();
        let _ = fs::remove_dir_all(repo_root);
        assert!(
            status.success(),
            "exact sing-box rejected Stage 4B managed TUN config"
        );
    }

    #[test]
    fn exact_sing_box_accepts_stage2_proxy_only_config_when_supplied() {
        let Some(binary) = std::env::var_os("EDGE_TEST_SING_BOX") else {
            return;
        };
        let repo_root = unique_test_dir();
        fs::create_dir_all(&repo_root).unwrap();
        let config_path = repo_root.join("stage2-proxy-only.json");
        fs::write(
            &config_path,
            render_windows_config(&stage2_runtime_state()).unwrap(),
        )
        .unwrap();

        let status = Command::new(binary)
            .args(["check", "-c"])
            .arg(&config_path)
            .status()
            .unwrap();
        let _ = fs::remove_dir_all(repo_root);
        assert!(
            status.success(),
            "exact sing-box rejected Stage 2 proxy-only config"
        );
    }

    fn unique_test_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-singbox-test-{unique}"))
    }
}
