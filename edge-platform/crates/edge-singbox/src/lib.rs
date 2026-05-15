use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use edge_shared_types::{LocalSingboxState, SelectorState, UbuntuProxyState};
use serde::Deserialize;
use serde_json::{Map, Value};

const MANAGED_SELECTOR_TAG: &str = "proxy-selector";
const WSL_SELECTOR_TAG: &str = "wsl-selector";
const WSL_INBOUND_TAG: &str = "wsl-mixed-in";
const DESKTOP_TRACE_INBOUND_TAG: &str = "mixed-in";
const DEFAULT_WSL_PROXY_PORT: u32 = 17890;
const WSL_INBOUND_BIND_HOST: &str = "0.0.0.0";
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
            &expected.direct,
            &mut local_singbox,
            &mut selector,
        );
        compare_tunnel_binding(
            &parsed,
            "hysteria2-warp",
            "vless-reality-warp",
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
    let raw_config = fs::read_to_string(config_path)
        .map_err(|err| format!("unable to read local sing-box config: {err}"))?;
    let raw_state = fs::read_to_string(state_path)
        .map_err(|err| format!("unable to read state file: {err}"))?;

    let mut config: Value = serde_json::from_str(&raw_config)
        .map_err(|err| format!("local sing-box config is not valid JSON: {err}"))?;
    let state: SyncState = serde_json::from_str(&raw_state)
        .map_err(|err| format!("state file is invalid JSON: {err}"))?;

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
    sync_wsl_inbound(&mut config);
    sync_wsl_selector(&mut config);
    sync_wsl_route_rule(&mut config);

    let rendered = serde_json::to_vec_pretty(&config)
        .map_err(|err| format!("failed to render updated config: {err}"))?;
    fs::write(config_path, rendered).map_err(|err| format!("failed to write config: {err}"))?;

    Ok(ConfigSyncSummary {
        instance_id: state.instance_id,
        config_path: config_path.display().to_string(),
    })
}

fn sync_tun_route_excludes(config: &mut Value, server_ip: Option<&str>) {
    let Some(server_ip) = server_ip else {
        return;
    };
    if server_ip.trim().is_empty() {
        return;
    }
    let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) else {
        return;
    };

    let server_cidr = format!("{server_ip}/32");
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
        let exists = excludes
            .iter()
            .any(|value| value.as_str() == Some(server_cidr.as_str()));
        if !exists {
            excludes.push(Value::String(server_cidr.clone()));
        }
    }
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
        Some(expected.domain.as_str()),
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
        Some(expected.domain.as_str()),
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
        if let Some(candidate) = config_path.as_deref() {
            if same_path_string(candidate, expected_config_path) {
                return Some(ProcessObservation { config_path });
            }
        } else {
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
      "server": "edge.alegria.by",
      "server_port": 8443,
      "password": "direct-password",
      "tls": { "server_name": "edge.alegria.by" }
    },
    {
      "type": "vless",
      "tag": "vless-reality-direct",
      "server": "edge.alegria.by",
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
      "server": "edge.alegria.by",
      "server_port": 9444,
      "password": "warp-password",
      "tls": { "server_name": "edge.alegria.by" }
    },
    {
      "type": "vless",
      "tag": "vless-reality-warp",
      "server": "edge.alegria.by",
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
      "server": "wrong.example.com",
      "server_port": 8443,
      "password": "direct-password",
      "tls": { "server_name": "wrong.example.com" }
    },
    {
      "type": "vless",
      "tag": "vless-reality-direct",
      "server": "edge.alegria.by",
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
      "server": "edge.alegria.by",
      "server_port": 9444,
      "password": "warp-password",
      "tls": { "server_name": "edge.alegria.by" }
    },
    {
      "type": "vless",
      "tag": "vless-reality-warp",
      "server": "edge.alegria.by",
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
  "inbounds": [],
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
                .pointer("/inbounds/0/tag")
                .and_then(serde_json::Value::as_str),
            Some("wsl-mixed-in")
        );
        assert_eq!(
            updated
                .pointer("/inbounds/0/listen")
                .and_then(serde_json::Value::as_str),
            Some("0.0.0.0")
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

    fn unique_test_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-singbox-test-{unique}"))
    }
}
