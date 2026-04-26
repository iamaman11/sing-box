use std::fs;
use std::path::{Path, PathBuf};

use edge_shared_types::{LocalSingboxState, SelectorState};
use serde::Deserialize;

const MANAGED_SELECTOR_TAG: &str = "proxy-selector";
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
}

pub fn inspect_local_config(config_path: &Path) -> LocalConfigObservation {
    let expected_config_path = config_path.display().to_string();
    let mut local_singbox = LocalSingboxState::placeholder(expected_config_path.clone());
    let mut selector = SelectorState::placeholder();

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
            };
        }
    };

    local_singbox.clash_api_port = parsed
        .experimental
        .as_ref()
        .and_then(|experimental| experimental.clash_api.as_ref())
        .and_then(|clash_api| clash_api.external_controller.as_deref())
        .and_then(parse_controller_port);

    let selector_outbound = parsed
        .outbounds
        .iter()
        .find(|outbound| outbound.kind == "selector" && outbound.tag == MANAGED_SELECTOR_TAG);

    if let Some(selector_config) = selector_outbound {
        local_singbox.managed_config = true;
        selector.desired_main_route = selector_config.default.clone();
        selector.observed_main_route = selector_config.default.clone();

        let missing_expected = EXPECTED_OUTBOUND_TAGS
            .iter()
            .filter(|tag| !selector_config.outbounds.iter().any(|entry| entry == **tag))
            .map(|tag| (*tag).to_owned())
            .collect::<Vec<_>>();
        if !missing_expected.is_empty() {
            local_singbox.warnings.push(format!(
                "managed selector is missing expected tunnel entries: {}",
                missing_expected.join(", ")
            ));
            selector.degraded = true;
        }
    } else {
        local_singbox
            .warnings
            .push("managed selector proxy-selector is missing from local config".to_owned());
        selector
            .warnings
            .push("proxy-selector was not found in local config".to_owned());
        selector.degraded = true;
    }

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

    LocalConfigObservation {
        local_singbox,
        selector,
    }
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

#[derive(Debug, Deserialize)]
struct SingboxConfig {
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
    { "type": "urltest", "tag": "auto-direct-tunnel" },
    { "type": "urltest", "tag": "auto-warp-tunnel" },
    { "type": "hysteria2", "tag": "hysteria2-direct" },
    { "type": "vless", "tag": "vless-reality-direct" },
    { "type": "hysteria2", "tag": "hysteria2-warp" },
    { "type": "vless", "tag": "vless-reality-warp" }
  ]
}"#,
        )
        .unwrap();

        let observation = inspect_local_config(&config_path);
        assert!(observation.local_singbox.managed_config);
        assert_eq!(observation.local_singbox.clash_api_port, Some(9090));
        assert_eq!(
            observation.selector.desired_main_route.as_deref(),
            Some("auto-direct-tunnel")
        );
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

        let observation = inspect_local_config(&config_path);
        assert!(!observation.local_singbox.managed_config);
        assert!(observation.selector.degraded);
        assert!(
            observation
                .selector
                .warnings
                .iter()
                .any(|warning| warning.contains("proxy-selector"))
        );

        fs::remove_dir_all(repo_root).unwrap();
    }

    fn unique_test_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-singbox-test-{unique}"))
    }
}
