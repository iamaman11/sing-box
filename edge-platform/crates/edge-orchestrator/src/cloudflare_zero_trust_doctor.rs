use edge_provider_cloudflare::{
    get_device_profile_includes, get_zero_trust_device_settings, list_access_application_policies,
    list_access_applications, list_device_profiles, list_gateway_rules, list_mesh_nodes,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;

const TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";
const REACHABILITY_ATTESTATION_ENV: &str = "CLOUDFLARE_ENROLLED_DEVICE_REACHABILITY_CONFIRMED";

#[derive(Debug, Deserialize)]
struct Guardrails {
    schema: u32,
    account_id: String,
    owned_resource_selectors: OwnedResourceSelectors,
    zero_trust_boundary: ZeroTrustBoundary,
}

#[derive(Debug, Deserialize)]
struct OwnedResourceSelectors {
    mesh_node_name: String,
}

#[derive(Debug, Deserialize)]
struct ZeroTrustBoundary {
    generic_warp_connector_selector: String,
    required_client_contract: RequiredClientContract,
    project_owned_legacy_warp_connector_names: Vec<String>,
    manual_prerequisites: Vec<String>,
    access_enrollment_required: bool,
    gateway_mesh_allow_required: bool,
}

#[derive(Debug, Deserialize)]
struct RequiredClientContract {
    service_mode: String,
    tunnel_protocol: String,
    mesh_cidr: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    status: &'static str,
    token_read_authority: &'static str,
    account_id: String,
    device_settings: DeviceSettingsReport,
    connectors: ConnectorReport,
    mesh_node_profile: MeshProfileReport,
    enrollment: EnrollmentReport,
    gateway: GatewayReport,
    manual_prerequisites: ManualPrerequisiteReport,
}

#[derive(Debug, Serialize)]
struct DeviceSettingsReport {
    gateway_proxy_enabled: Option<bool>,
    gateway_udp_proxy_enabled: Option<bool>,
    use_zt_virtual_ip: Option<bool>,
    ready: bool,
}

#[derive(Debug, Serialize)]
struct ConnectorReport {
    current_names: Vec<String>,
    project_owned_legacy_names: Vec<String>,
    desired_acceptance_name: String,
    unexpected_names: Vec<String>,
    ready: bool,
}

#[derive(Debug, Serialize)]
struct MeshProfileReport {
    exact_selector_matches: usize,
    matching_profile_names: Vec<String>,
    service_mode: Option<String>,
    tunnel_protocol: Option<String>,
    mesh_cidr_included: bool,
    ready: bool,
}

#[derive(Debug, Serialize)]
struct EnrollmentReport {
    warp_application_count: usize,
    warp_applications_with_policy: usize,
    required: bool,
    ready: bool,
}

#[derive(Debug, Serialize)]
struct GatewayReport {
    mesh_block_rule_count: usize,
    earliest_mesh_block_precedence: Option<u64>,
    earlier_mesh_allow_count: usize,
    required: bool,
    ready: bool,
}

#[derive(Debug, Serialize)]
struct ManualPrerequisiteReport {
    enrolled_device_reachability_required: bool,
    enrolled_device_reachability_confirmed: bool,
    ready: bool,
}

pub async fn run(spec_path: &Path) -> Result<(), String> {
    let desired = load_guardrails(spec_path)?;
    validate_guardrails(&desired)?;

    let api_token = env::var(TOKEN_ENV).map_err(|_| format!("{TOKEN_ENV} is required"))?;
    if api_token.trim().is_empty() {
        return Err(format!("{TOKEN_ENV} must be non-empty"));
    }

    let settings = get_zero_trust_device_settings(&api_token, &desired.account_id).await?;
    let settings_ready = settings.gateway_proxy_enabled == Some(true)
        && settings.gateway_udp_proxy_enabled == Some(true)
        && settings.use_zt_virtual_ip == Some(true);

    let nodes = list_mesh_nodes(&api_token, &desired.account_id, None).await?;
    let current_names = nodes
        .iter()
        .map(|node| node.name.clone())
        .collect::<BTreeSet<_>>();
    let mut allowed_names = desired
        .zero_trust_boundary
        .project_owned_legacy_warp_connector_names
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    allowed_names.insert(desired.owned_resource_selectors.mesh_node_name.clone());
    let unexpected_names = current_names
        .difference(&allowed_names)
        .cloned()
        .collect::<Vec<_>>();
    let connectors_ready = unexpected_names.is_empty();

    let profiles = list_device_profiles(&api_token, &desired.account_id).await?;
    let matching_profiles = profiles
        .into_iter()
        .filter(|profile| {
            profile.match_expression.as_deref()
                == Some(
                    desired
                        .zero_trust_boundary
                        .generic_warp_connector_selector
                        .as_str(),
                )
        })
        .collect::<Vec<_>>();

    let mut mesh_cidr_included = false;
    let mut selected_mode = None;
    let mut selected_protocol = None;
    let mut matching_profile_names = Vec::new();
    if matching_profiles.len() == 1 {
        let profile = &matching_profiles[0];
        matching_profile_names.push(profile.name.clone());
        selected_mode = profile.service_mode.clone();
        selected_protocol = profile.tunnel_protocol.clone();
        let includes =
            get_device_profile_includes(&api_token, &desired.account_id, &profile.id).await?;
        mesh_cidr_included = includes.iter().any(|entry| {
            entry.address.as_deref()
                == Some(
                    desired
                        .zero_trust_boundary
                        .required_client_contract
                        .mesh_cidr
                        .as_str(),
                )
        });
    } else {
        matching_profile_names.extend(matching_profiles.iter().map(|profile| profile.name.clone()));
    }
    let mesh_profile_ready = matching_profiles.len() == 1
        && selected_mode.as_deref()
            == Some(
                desired
                    .zero_trust_boundary
                    .required_client_contract
                    .service_mode
                    .as_str(),
            )
        && selected_protocol.as_deref()
            == Some(
                desired
                    .zero_trust_boundary
                    .required_client_contract
                    .tunnel_protocol
                    .as_str(),
            )
        && mesh_cidr_included;

    let apps = list_access_applications(&api_token, &desired.account_id).await?;
    let warp_apps = apps
        .into_iter()
        .filter(|app| app.app_type.eq_ignore_ascii_case("warp"))
        .collect::<Vec<_>>();
    let mut warp_apps_with_policy = 0usize;
    for app in &warp_apps {
        let policies =
            list_access_application_policies(&api_token, &desired.account_id, &app.id).await?;
        if !policies.is_empty() {
            warp_apps_with_policy += 1;
        }
    }
    let enrollment_ready =
        !desired.zero_trust_boundary.access_enrollment_required || warp_apps_with_policy > 0;

    let rules = list_gateway_rules(&api_token, &desired.account_id).await?;
    let mesh_cidr = desired
        .zero_trust_boundary
        .required_client_contract
        .mesh_cidr
        .as_str();
    let mesh_blocks = rules
        .iter()
        .filter(|rule| {
            rule.enabled != Some(false)
                && rule.action.eq_ignore_ascii_case("block")
                && rule
                    .traffic
                    .as_deref()
                    .is_some_and(|traffic| traffic.contains(mesh_cidr))
        })
        .collect::<Vec<_>>();
    let earliest_block = mesh_blocks.iter().filter_map(|rule| rule.precedence).min();
    let earlier_mesh_allows = rules
        .iter()
        .filter(|rule| {
            rule.enabled != Some(false)
                && rule.action.eq_ignore_ascii_case("allow")
                && rule
                    .traffic
                    .as_deref()
                    .is_some_and(|traffic| traffic.contains(mesh_cidr))
                && match (rule.precedence, earliest_block) {
                    (Some(allow), Some(block)) => allow < block,
                    (Some(_), None) => true,
                    _ => false,
                }
        })
        .count();
    let gateway_ready = !desired.zero_trust_boundary.gateway_mesh_allow_required
        || mesh_blocks.is_empty()
        || earlier_mesh_allows > 0;

    let reachability_required = desired
        .zero_trust_boundary
        .manual_prerequisites
        .iter()
        .any(|value| value == "enrolled-device-reachability");
    let reachability_confirmed = env_true(REACHABILITY_ATTESTATION_ENV);
    let manual_ready = !reachability_required || reachability_confirmed;

    let ready = settings_ready
        && connectors_ready
        && mesh_profile_ready
        && enrollment_ready
        && gateway_ready
        && manual_ready;

    let report = DoctorReport {
        status: if ready { "PASS" } else { "BLOCKED" },
        token_read_authority: "PASS",
        account_id: desired.account_id,
        device_settings: DeviceSettingsReport {
            gateway_proxy_enabled: settings.gateway_proxy_enabled,
            gateway_udp_proxy_enabled: settings.gateway_udp_proxy_enabled,
            use_zt_virtual_ip: settings.use_zt_virtual_ip,
            ready: settings_ready,
        },
        connectors: ConnectorReport {
            current_names: current_names.into_iter().collect(),
            project_owned_legacy_names: desired
                .zero_trust_boundary
                .project_owned_legacy_warp_connector_names,
            desired_acceptance_name: desired.owned_resource_selectors.mesh_node_name,
            unexpected_names,
            ready: connectors_ready,
        },
        mesh_node_profile: MeshProfileReport {
            exact_selector_matches: matching_profiles.len(),
            matching_profile_names,
            service_mode: selected_mode,
            tunnel_protocol: selected_protocol,
            mesh_cidr_included,
            ready: mesh_profile_ready,
        },
        enrollment: EnrollmentReport {
            warp_application_count: warp_apps.len(),
            warp_applications_with_policy: warp_apps_with_policy,
            required: desired.zero_trust_boundary.access_enrollment_required,
            ready: enrollment_ready,
        },
        gateway: GatewayReport {
            mesh_block_rule_count: mesh_blocks.len(),
            earliest_mesh_block_precedence: earliest_block,
            earlier_mesh_allow_count: earlier_mesh_allows,
            required: desired.zero_trust_boundary.gateway_mesh_allow_required,
            ready: gateway_ready,
        },
        manual_prerequisites: ManualPrerequisiteReport {
            enrolled_device_reachability_required: reachability_required,
            enrolled_device_reachability_confirmed: reachability_confirmed,
            ready: manual_ready,
        },
    };

    let output = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("failed to serialize Zero Trust doctor report: {err}"))?;
    println!("{output}");
    if ready {
        Ok(())
    } else {
        Err("Cloudflare Zero Trust readiness is BLOCKED".to_owned())
    }
}

fn load_guardrails(path: &Path) -> Result<Guardrails, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Zero Trust guardrails {}: {err}",
            path.display()
        )
    })?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("invalid Zero Trust guardrails {}: {err}", path.display()))
}

fn validate_guardrails(desired: &Guardrails) -> Result<(), String> {
    if desired.schema != 1 {
        return Err(format!(
            "unsupported Zero Trust guardrails schema {}",
            desired.schema
        ));
    }
    if desired.account_id.trim().is_empty() {
        return Err("Cloudflare account ID must be non-empty".to_owned());
    }
    if desired
        .zero_trust_boundary
        .generic_warp_connector_selector
        .trim()
        .is_empty()
    {
        return Err("generic WARP Connector selector must be non-empty".to_owned());
    }
    if desired
        .zero_trust_boundary
        .required_client_contract
        .mesh_cidr
        .trim()
        .is_empty()
    {
        return Err("Mesh CIDR must be non-empty".to_owned());
    }
    Ok(())
}

fn env_true(name: &str) -> bool {
    env::var(name)
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_attestation_is_required() {
        assert!(!env_true("EDGE_TEST_UNSET_ZERO_TRUST_ATTESTATION"));
    }

    #[test]
    fn schema_validation_rejects_empty_account() {
        let desired = Guardrails {
            schema: 1,
            account_id: String::new(),
            owned_resource_selectors: OwnedResourceSelectors {
                mesh_node_name: "singbox-line3-application-acceptance".to_owned(),
            },
            zero_trust_boundary: ZeroTrustBoundary {
                generic_warp_connector_selector:
                    "identity.email == \"warp_connector@example.cloudflareaccess.com\"".to_owned(),
                required_client_contract: RequiredClientContract {
                    service_mode: "warp".to_owned(),
                    tunnel_protocol: "masque".to_owned(),
                    mesh_cidr: "100.96.0.0/12".to_owned(),
                },
                project_owned_legacy_warp_connector_names: vec!["vultr".to_owned()],
                manual_prerequisites: vec!["enrolled-device-reachability".to_owned()],
                access_enrollment_required: true,
                gateway_mesh_allow_required: true,
            },
        };
        assert!(validate_guardrails(&desired).is_err());
    }
}
