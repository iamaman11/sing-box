use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

pub const CURRENT_SCHEMA: u32 = 1;
const REQUIRED_MESH_CIDRS: [&str; 2] = ["100.64.0.0/12", "100.96.0.0/12"];
const PRESERVED_CGNAT_EXCLUSIONS: [&str; 2] = ["100.80.0.0/12", "100.112.0.0/12"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredZeroTrustState {
    pub schema: u32,
    pub project: String,
    pub account_id: String,
    pub allowed_connector_names: Vec<String>,
    pub mesh_profile: MeshProfileDesired,
    pub android_profile: AndroidProfileDesired,
    pub gateway_allow: GatewayAllowDesired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshProfileDesired {
    pub name: String,
    pub description: String,
    pub match_expression: String,
    pub precedence_start: u64,
    pub service_mode: String,
    pub tunnel_protocol: String,
    pub include_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidProfileDesired {
    pub profile_id_env: String,
    pub required_service_mode: String,
    pub required_tunnel_protocol: String,
    pub remove_exclusions: Vec<String>,
    pub add_exclusions: Vec<SplitTunnelEntry>,
    pub required_routed_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAllowDesired {
    pub name: String,
    pub description: String,
    pub identity_email_env: String,
    pub block_rule_name: String,
    pub destination_cidrs: Vec<String>,
    pub posture: PostureSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureSelector {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub platform: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct SplitTunnelEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedDeviceProfile {
    pub provider_id: String,
    pub name: String,
    pub enabled: Option<bool>,
    pub precedence: Option<u64>,
    pub match_expression: Option<String>,
    pub service_mode: Option<String>,
    pub tunnel_protocol: Option<String>,
    #[serde(default)]
    pub includes: Vec<SplitTunnelEntry>,
    #[serde(default)]
    pub excludes: Vec<SplitTunnelEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPostureRule {
    pub provider_id: String,
    pub rule_type: String,
    pub platforms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedGatewayRule {
    pub provider_id: String,
    pub name: String,
    pub action: String,
    pub precedence: Option<u64>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub filters: Vec<String>,
    pub traffic: Option<String>,
    pub identity_sha256: Option<String>,
    pub device_posture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ZeroTrustObservation {
    pub device_settings_ready: bool,
    pub access_enrollment_ready: bool,
    #[serde(default)]
    pub connector_names: Vec<String>,
    #[serde(default)]
    pub mesh_profile_matches: Vec<ObservedDeviceProfile>,
    #[serde(default)]
    pub profile_precedences: Vec<u64>,
    pub android_profile: Option<ObservedDeviceProfile>,
    #[serde(default)]
    pub posture_rules: Vec<ObservedPostureRule>,
    #[serde(default)]
    pub gateway_rules: Vec<ObservedGatewayRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAuthority {
    pub android_profile_id: String,
    pub identity_sha256: String,
    pub enrolled_device_reachability_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ZeroTrustAction {
    Noop,
    CreateMeshProfile {
        precedence: u64,
    },
    UpdateMeshProfile {
        profile_id: String,
        precedence: u64,
    },
    SetMeshIncludes {
        profile_id: String,
        entries: Vec<SplitTunnelEntry>,
    },
    SetAndroidExcludes {
        profile_id: String,
        entries: Vec<SplitTunnelEntry>,
    },
    CreateGatewayAllow {
        precedence: u64,
        posture_rule_id: String,
    },
    UpdateGatewayAllow {
        rule_id: String,
        precedence: u64,
        posture_rule_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroTrustPlan {
    pub action: ZeroTrustAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZeroTrustLifecycleError {
    Json(String),
    UnsupportedSchema(u32),
    Validation(String),
    Ambiguous(String),
    Conflict(String),
}

impl fmt::Display for ZeroTrustLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message)
            | Self::Validation(message)
            | Self::Ambiguous(message)
            | Self::Conflict(message) => f.write_str(message),
            Self::UnsupportedSchema(schema) => {
                write!(
                    f,
                    "unsupported Cloudflare Zero Trust lifecycle schema {schema}"
                )
            }
        }
    }
}

impl std::error::Error for ZeroTrustLifecycleError {}

impl DesiredZeroTrustState {
    pub fn parse_json(input: &str) -> Result<Self, ZeroTrustLifecycleError> {
        let desired: Self = serde_json::from_str(input)
            .map_err(|err| ZeroTrustLifecycleError::Json(err.to_string()))?;
        desired.validate()?;
        Ok(desired)
    }

    pub fn validate(&self) -> Result<(), ZeroTrustLifecycleError> {
        if self.schema != CURRENT_SCHEMA {
            return Err(ZeroTrustLifecycleError::UnsupportedSchema(self.schema));
        }
        if self.project != "sing-box" {
            return Err(ZeroTrustLifecycleError::Validation(
                "Cloudflare Zero Trust project must be sing-box".to_owned(),
            ));
        }
        validate_account_id(&self.account_id)?;
        validate_env_name(&self.android_profile.profile_id_env)?;
        validate_env_name(&self.gateway_allow.identity_email_env)?;

        if self.allowed_connector_names.is_empty() {
            return Err(ZeroTrustLifecycleError::Validation(
                "at least one project-owned/allowed connector name is required".to_owned(),
            ));
        }
        ensure_unique_nonempty("allowed connector name", &self.allowed_connector_names)?;

        for value in [
            &self.mesh_profile.name,
            &self.mesh_profile.description,
            &self.mesh_profile.match_expression,
            &self.gateway_allow.name,
            &self.gateway_allow.description,
            &self.gateway_allow.block_rule_name,
            &self.gateway_allow.posture.rule_type,
            &self.gateway_allow.posture.platform,
        ] {
            if value.trim().is_empty() {
                return Err(ZeroTrustLifecycleError::Validation(
                    "Zero Trust desired strings must be non-empty".to_owned(),
                ));
            }
        }
        if self.mesh_profile.precedence_start == 0 {
            return Err(ZeroTrustLifecycleError::Validation(
                "Mesh profile precedence_start must be greater than zero".to_owned(),
            ));
        }
        if self.mesh_profile.service_mode != "warp"
            || self.mesh_profile.tunnel_protocol != "masque"
            || self.android_profile.required_service_mode != "warp"
            || self.android_profile.required_tunnel_protocol != "masque"
        {
            return Err(ZeroTrustLifecycleError::Validation(
                "Mesh and Android profiles must require warp + masque".to_owned(),
            ));
        }

        let mesh_includes = canonical_cidr_set(&self.mesh_profile.include_cidrs)?;
        let required_mesh = REQUIRED_MESH_CIDRS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
        if !required_mesh.is_subset(&mesh_includes) {
            return Err(ZeroTrustLifecycleError::Validation(
                "Mesh profile must include both 100.64.0.0/12 and 100.96.0.0/12".to_owned(),
            ));
        }

        let remove = canonical_cidr_set(&self.android_profile.remove_exclusions)?;
        if remove != BTreeSet::from(["100.64.0.0/10".to_owned()]) {
            return Err(ZeroTrustLifecycleError::Validation(
                "Android preservation transform must remove exactly 100.64.0.0/10".to_owned(),
            ));
        }
        let required_routed = canonical_cidr_set(&self.android_profile.required_routed_cidrs)?;
        if !required_mesh.is_subset(&required_routed) {
            return Err(ZeroTrustLifecycleError::Validation(
                "Android profile must route both Cloudflare Mesh required /12 ranges".to_owned(),
            ));
        }
        let add_addresses = self
            .android_profile
            .add_exclusions
            .iter()
            .filter_map(|entry| entry.address.as_deref())
            .map(canonical_ipv4_cidr)
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected_preserved = PRESERVED_CGNAT_EXCLUSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
        if !expected_preserved.is_subset(&add_addresses) {
            return Err(ZeroTrustLifecycleError::Validation(
                "Android preservation transform must add 100.80.0.0/12 and 100.112.0.0/12 exclusions"
                    .to_owned(),
            ));
        }

        let gateway_destinations = canonical_cidr_set(&self.gateway_allow.destination_cidrs)?;
        if !gateway_destinations.contains("100.96.0.0/12") {
            return Err(ZeroTrustLifecycleError::Validation(
                "Gateway project allow must include the Mesh device range 100.96.0.0/12".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn plan_apply(
    desired: &DesiredZeroTrustState,
    observed: &ZeroTrustObservation,
    authority: &RuntimeAuthority,
) -> Result<ZeroTrustPlan, ZeroTrustLifecycleError> {
    desired.validate()?;
    if authority.android_profile_id.trim().is_empty() || authority.identity_sha256.len() != 64 {
        return Err(ZeroTrustLifecycleError::Validation(
            "runtime Zero Trust authority is incomplete".to_owned(),
        ));
    }

    if !authority.enrolled_device_reachability_confirmed {
        return Err(ZeroTrustLifecycleError::Conflict(
            "enrolled-device reachability is not confirmed; Zero Trust mutation remains blocked"
                .to_owned(),
        ));
    }
    if !observed.device_settings_ready {
        return Err(ZeroTrustLifecycleError::Conflict(
            "global Zero Trust device settings are not Mesh-ready".to_owned(),
        ));
    }
    if !observed.access_enrollment_ready {
        return Err(ZeroTrustLifecycleError::Conflict(
            "no WARP enrollment Access application with policy was proven".to_owned(),
        ));
    }

    let allowed = desired
        .allowed_connector_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let unexpected = observed
        .connector_names
        .iter()
        .filter(|name| !allowed.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(ZeroTrustLifecycleError::Conflict(format!(
            "unexpected Cloudflare Mesh connectors are present: {}",
            unexpected.join(", ")
        )));
    }

    let mesh_profile = match observed.mesh_profile_matches.as_slice() {
        [] => {
            let precedence = next_free_precedence(
                desired.mesh_profile.precedence_start,
                observed.profile_precedences.iter().copied(),
            )?;
            return Ok(ZeroTrustPlan {
                action: ZeroTrustAction::CreateMeshProfile { precedence },
            });
        }
        [profile] => profile,
        profiles => {
            return Err(ZeroTrustLifecycleError::Ambiguous(format!(
                "Mesh profile selector is ambiguous: observed {} matching profiles",
                profiles.len()
            )));
        }
    };

    if mesh_profile.name != desired.mesh_profile.name
        || mesh_profile.match_expression.as_deref()
            != Some(desired.mesh_profile.match_expression.as_str())
    {
        return Err(ZeroTrustLifecycleError::Conflict(
            "Mesh profile name/selector collision is not project-owned".to_owned(),
        ));
    }
    let mesh_precedence = mesh_profile.precedence.ok_or_else(|| {
        ZeroTrustLifecycleError::Conflict("Mesh profile has no precedence".to_owned())
    })?;
    if mesh_profile.enabled == Some(false)
        || mesh_profile.service_mode.as_deref() != Some(desired.mesh_profile.service_mode.as_str())
        || mesh_profile.tunnel_protocol.as_deref()
            != Some(desired.mesh_profile.tunnel_protocol.as_str())
    {
        return Ok(ZeroTrustPlan {
            action: ZeroTrustAction::UpdateMeshProfile {
                profile_id: mesh_profile.provider_id.clone(),
                precedence: mesh_precedence,
            },
        });
    }

    let desired_includes = desired
        .mesh_profile
        .include_cidrs
        .iter()
        .map(|address| SplitTunnelEntry {
            address: Some(address.clone()),
            host: None,
            description: Some(if address == "100.96.0.0/12" {
                "Cloudflare Mesh device IPs".to_owned()
            } else {
                "Cloudflare source IPs".to_owned()
            }),
        })
        .collect::<Vec<_>>();
    if split_tunnel_keyset(&mesh_profile.includes) != split_tunnel_keyset(&desired_includes) {
        return Ok(ZeroTrustPlan {
            action: ZeroTrustAction::SetMeshIncludes {
                profile_id: mesh_profile.provider_id.clone(),
                entries: sorted_entries(desired_includes),
            },
        });
    }

    let android = observed.android_profile.as_ref().ok_or_else(|| {
        ZeroTrustLifecycleError::Conflict("Android profile target was not observed".to_owned())
    })?;
    if android.provider_id != authority.android_profile_id {
        return Err(ZeroTrustLifecycleError::Conflict(
            "observed Android profile does not match runtime authority".to_owned(),
        ));
    }
    if android.service_mode.as_deref()
        != Some(desired.android_profile.required_service_mode.as_str())
        || android.tunnel_protocol.as_deref()
            != Some(desired.android_profile.required_tunnel_protocol.as_str())
    {
        return Err(ZeroTrustLifecycleError::Conflict(
            "Android profile is not warp + masque; refusing split-tunnel mutation".to_owned(),
        ));
    }

    let desired_android_excludes = desired_android_excludes(desired, &android.excludes)?;
    if split_tunnel_keyset(&android.excludes) != split_tunnel_keyset(&desired_android_excludes) {
        return Ok(ZeroTrustPlan {
            action: ZeroTrustAction::SetAndroidExcludes {
                profile_id: android.provider_id.clone(),
                entries: desired_android_excludes,
            },
        });
    }

    let posture_matches = observed
        .posture_rules
        .iter()
        .filter(|rule| {
            rule.rule_type == desired.gateway_allow.posture.rule_type
                && rule
                    .platforms
                    .iter()
                    .any(|platform| platform == &desired.gateway_allow.posture.platform)
        })
        .collect::<Vec<_>>();
    let posture = match posture_matches.as_slice() {
        [rule] => *rule,
        [] => {
            return Err(ZeroTrustLifecycleError::Conflict(
                "required Android device posture rule is absent".to_owned(),
            ));
        }
        rules => {
            return Err(ZeroTrustLifecycleError::Ambiguous(format!(
                "Android posture selector matched {} rules",
                rules.len()
            )));
        }
    };

    let block_matches = observed
        .gateway_rules
        .iter()
        .filter(|rule| rule.name == desired.gateway_allow.block_rule_name)
        .collect::<Vec<_>>();
    let block = match block_matches.as_slice() {
        [rule] => *rule,
        [] => {
            return Err(ZeroTrustLifecycleError::Conflict(
                "required private-traffic block rule was not observed".to_owned(),
            ));
        }
        rules => {
            return Err(ZeroTrustLifecycleError::Ambiguous(format!(
                "private-traffic block selector matched {} rules",
                rules.len()
            )));
        }
    };
    if !block.action.eq_ignore_ascii_case("block") || block.enabled == Some(false) {
        return Err(ZeroTrustLifecycleError::Conflict(
            "private-traffic baseline rule is not an enabled block".to_owned(),
        ));
    }
    let block_precedence = block.precedence.ok_or_else(|| {
        ZeroTrustLifecycleError::Conflict("private-traffic block rule has no precedence".to_owned())
    })?;

    let project_rules = observed
        .gateway_rules
        .iter()
        .filter(|rule| rule.name == desired.gateway_allow.name)
        .collect::<Vec<_>>();
    let traffic = gateway_traffic_expression(&desired.gateway_allow.destination_cidrs)?;
    match project_rules.as_slice() {
        [] => {
            let precedence = preceding_free_precedence(
                block_precedence,
                observed
                    .gateway_rules
                    .iter()
                    .filter_map(|rule| rule.precedence),
            )?;
            Ok(ZeroTrustPlan {
                action: ZeroTrustAction::CreateGatewayAllow {
                    precedence,
                    posture_rule_id: posture.provider_id.clone(),
                },
            })
        }
        [rule] => {
            let precedence = rule.precedence.unwrap_or(block_precedence);
            let exact = rule.action.eq_ignore_ascii_case("allow")
                && rule.enabled != Some(false)
                && rule.filters.iter().any(|filter| filter == "l4")
                && rule.traffic.as_deref() == Some(traffic.as_str())
                && rule.identity_sha256.as_deref() == Some(authority.identity_sha256.as_str())
                && rule
                    .device_posture
                    .as_deref()
                    .is_some_and(|value| value.contains(&posture.provider_id))
                && precedence < block_precedence;
            if exact {
                Ok(ZeroTrustPlan {
                    action: ZeroTrustAction::Noop,
                })
            } else {
                let desired_precedence = if precedence < block_precedence {
                    precedence
                } else {
                    preceding_free_precedence(
                        block_precedence,
                        observed
                            .gateway_rules
                            .iter()
                            .filter(|candidate| candidate.provider_id != rule.provider_id)
                            .filter_map(|candidate| candidate.precedence),
                    )?
                };
                Ok(ZeroTrustPlan {
                    action: ZeroTrustAction::UpdateGatewayAllow {
                        rule_id: rule.provider_id.clone(),
                        precedence: desired_precedence,
                        posture_rule_id: posture.provider_id.clone(),
                    },
                })
            }
        }
        rules => Err(ZeroTrustLifecycleError::Ambiguous(format!(
            "project Gateway allow name matched {} rules",
            rules.len()
        ))),
    }
}

pub fn gateway_traffic_expression(cidrs: &[String]) -> Result<String, ZeroTrustLifecycleError> {
    let values = canonical_cidr_set(cidrs)?;
    Ok(format!(
        "net.dst.ip in {{{}}}",
        values.into_iter().collect::<Vec<_>>().join(" ")
    ))
}

fn desired_android_excludes(
    desired: &DesiredZeroTrustState,
    observed: &[SplitTunnelEntry],
) -> Result<Vec<SplitTunnelEntry>, ZeroTrustLifecycleError> {
    let remove = canonical_cidr_set(&desired.android_profile.remove_exclusions)?;
    let required = canonical_cidr_set(&desired.android_profile.required_routed_cidrs)?;
    let mut result = Vec::new();
    for entry in observed {
        if let Some(address) = entry.address.as_deref() {
            let canonical = canonical_ipv4_cidr(address)?;
            if remove.contains(&canonical) {
                continue;
            }
            for target in &required {
                if ipv4_cidr_contains(&canonical, target)? {
                    return Err(ZeroTrustLifecycleError::Conflict(format!(
                        "Android exclusion {canonical} still contains required routed range {target}"
                    )));
                }
            }
        }
        result.push(entry.clone());
    }
    for entry in &desired.android_profile.add_exclusions {
        if !split_tunnel_keyset(&result).contains(&split_tunnel_key(entry)) {
            result.push(entry.clone());
        }
    }
    Ok(sorted_entries(result))
}

fn next_free_precedence<I>(start: u64, used: I) -> Result<u64, ZeroTrustLifecycleError>
where
    I: IntoIterator<Item = u64>,
{
    let used = used.into_iter().collect::<BTreeSet<_>>();
    for candidate in start..=start.saturating_add(10_000) {
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(ZeroTrustLifecycleError::Conflict(
        "unable to allocate deterministic Mesh profile precedence".to_owned(),
    ))
}

fn preceding_free_precedence<I>(
    block_precedence: u64,
    used: I,
) -> Result<u64, ZeroTrustLifecycleError>
where
    I: IntoIterator<Item = u64>,
{
    if block_precedence == 0 {
        return Err(ZeroTrustLifecycleError::Conflict(
            "block precedence leaves no earlier slot".to_owned(),
        ));
    }
    let used = used.into_iter().collect::<BTreeSet<_>>();
    for candidate in (0..block_precedence).rev() {
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(ZeroTrustLifecycleError::Conflict(
        "unable to allocate an earlier Gateway precedence".to_owned(),
    ))
}

fn canonical_cidr_set(values: &[String]) -> Result<BTreeSet<String>, ZeroTrustLifecycleError> {
    let mut result = BTreeSet::new();
    for value in values {
        let canonical = canonical_ipv4_cidr(value)?;
        if canonical != *value {
            return Err(ZeroTrustLifecycleError::Validation(format!(
                "CIDR {value} is not canonical; use {canonical}"
            )));
        }
        if !result.insert(canonical) {
            return Err(ZeroTrustLifecycleError::Validation(format!(
                "duplicate CIDR {value}"
            )));
        }
    }
    Ok(result)
}

fn canonical_ipv4_cidr(value: &str) -> Result<String, ZeroTrustLifecycleError> {
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        ZeroTrustLifecycleError::Validation(format!("CIDR {value} must use prefix notation"))
    })?;
    let address = address.parse::<Ipv4Addr>().map_err(|err| {
        ZeroTrustLifecycleError::Validation(format!("invalid IPv4 CIDR {value}: {err}"))
    })?;
    let prefix = prefix.parse::<u8>().map_err(|err| {
        ZeroTrustLifecycleError::Validation(format!("invalid IPv4 prefix {value}: {err}"))
    })?;
    if prefix > 32 {
        return Err(ZeroTrustLifecycleError::Validation(format!(
            "IPv4 prefix must be <= 32: {value}"
        )));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let network = Ipv4Addr::from(u32::from(address) & mask);
    Ok(format!("{network}/{prefix}"))
}

fn ipv4_cidr_contains(parent: &str, child: &str) -> Result<bool, ZeroTrustLifecycleError> {
    let (parent_addr, parent_prefix) = parse_ipv4_cidr(parent)?;
    let (child_addr, child_prefix) = parse_ipv4_cidr(child)?;
    if parent_prefix > child_prefix {
        return Ok(false);
    }
    let mask = if parent_prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(parent_prefix))
    };
    Ok((u32::from(parent_addr) & mask) == (u32::from(child_addr) & mask))
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), ZeroTrustLifecycleError> {
    let canonical = canonical_ipv4_cidr(value)?;
    let (address, prefix) = canonical
        .split_once('/')
        .expect("canonical CIDR contains slash");
    Ok((
        address.parse::<Ipv4Addr>().expect("canonical IPv4 parses"),
        prefix.parse::<u8>().expect("canonical prefix parses"),
    ))
}

fn split_tunnel_key(entry: &SplitTunnelEntry) -> String {
    match (&entry.address, &entry.host) {
        (Some(address), None) => format!("address:{address}"),
        (None, Some(host)) => format!("host:{host}"),
        _ => "invalid".to_owned(),
    }
}

fn split_tunnel_keyset(entries: &[SplitTunnelEntry]) -> BTreeSet<String> {
    entries.iter().map(split_tunnel_key).collect()
}

fn sorted_entries(mut entries: Vec<SplitTunnelEntry>) -> Vec<SplitTunnelEntry> {
    entries.sort();
    entries
}

fn validate_account_id(value: &str) -> Result<(), ZeroTrustLifecycleError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ZeroTrustLifecycleError::Validation(
            "Cloudflare account_id must be exactly 32 lowercase hexadecimal characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_env_name(value: &str) -> Result<(), ZeroTrustLifecycleError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(ZeroTrustLifecycleError::Validation(format!(
            "runtime authority env name {value:?} is invalid"
        )));
    }
    Ok(())
}

fn ensure_unique_nonempty(label: &str, values: &[String]) -> Result<(), ZeroTrustLifecycleError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() || !seen.insert(value) {
            return Err(ZeroTrustLifecycleError::Validation(format!(
                "{label} values must be non-empty and unique"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> DesiredZeroTrustState {
        DesiredZeroTrustState::parse_json(
            r#"{
  "schema":1,
  "project":"sing-box",
  "account_id":"0123456789abcdef0123456789abcdef",
  "allowed_connector_names":["vultr","singbox-line3-application-acceptance"],
  "mesh_profile":{
    "name":"sing-box Mesh nodes",
    "description":"Project Mesh node routing",
    "match_expression":"identity.email == \"warp_connector@example.cloudflareaccess.com\"",
    "precedence_start":100,
    "service_mode":"warp",
    "tunnel_protocol":"masque",
    "include_cidrs":["100.64.0.0/12","100.96.0.0/12"]
  },
  "android_profile":{
    "profile_id_env":"CLOUDFLARE_ANDROID_PROFILE_ID",
    "required_service_mode":"warp",
    "required_tunnel_protocol":"masque",
    "remove_exclusions":["100.64.0.0/10"],
    "add_exclusions":[
      {"address":"100.80.0.0/12","description":"Preserved non-Cloudflare CGNAT bypass"},
      {"address":"100.112.0.0/12","description":"Preserved non-Cloudflare CGNAT bypass"}
    ],
    "required_routed_cidrs":["100.64.0.0/12","100.96.0.0/12"]
  },
  "gateway_allow":{
    "name":"sing-box Mesh Android allow",
    "description":"Allow project Android Mesh traffic before private deny",
    "identity_email_env":"CLOUDFLARE_ANDROID_IDENTITY_EMAIL",
    "block_rule_name":"Default deny for private traffic",
    "destination_cidrs":["100.96.0.0/12"],
    "posture":{"type":"os_version","platform":"android"}
  }
}"#,
        )
        .unwrap()
    }

    fn mesh_profile() -> ObservedDeviceProfile {
        let desired = desired();
        ObservedDeviceProfile {
            provider_id: "profile-mesh".to_owned(),
            name: desired.mesh_profile.name,
            enabled: Some(true),
            precedence: Some(100),
            match_expression: Some(desired.mesh_profile.match_expression),
            service_mode: Some("warp".to_owned()),
            tunnel_protocol: Some("masque".to_owned()),
            includes: desired
                .mesh_profile
                .include_cidrs
                .into_iter()
                .map(|address| SplitTunnelEntry {
                    address: Some(address),
                    host: None,
                    description: None,
                })
                .collect(),
            excludes: vec![],
        }
    }

    fn android_profile() -> ObservedDeviceProfile {
        ObservedDeviceProfile {
            provider_id: "android-profile".to_owned(),
            name: "Android".to_owned(),
            enabled: Some(true),
            precedence: Some(10),
            match_expression: None,
            service_mode: Some("warp".to_owned()),
            tunnel_protocol: Some("masque".to_owned()),
            includes: vec![],
            excludes: vec![SplitTunnelEntry {
                address: Some("100.64.0.0/10".to_owned()),
                host: None,
                description: Some("CGNAT".to_owned()),
            }],
        }
    }

    fn authority() -> RuntimeAuthority {
        RuntimeAuthority {
            android_profile_id: "android-profile".to_owned(),
            identity_sha256: "a".repeat(64),
            enrolled_device_reachability_confirmed: true,
        }
    }

    #[test]
    fn missing_mesh_profile_plans_create() {
        let observed = ZeroTrustObservation {
            device_settings_ready: true,
            access_enrollment_ready: true,
            connector_names: vec!["vultr".to_owned()],
            android_profile: Some(android_profile()),
            ..ZeroTrustObservation::default()
        };
        let plan = plan_apply(&desired(), &observed, &authority()).unwrap();
        assert!(matches!(
            plan.action,
            ZeroTrustAction::CreateMeshProfile { precedence: 100 }
        ));
    }

    #[test]
    fn android_cgnat_parent_is_exactly_carved() {
        let desired = desired();
        let result = desired_android_excludes(&desired, &android_profile().excludes).unwrap();
        let keys = split_tunnel_keyset(&result);
        assert!(!keys.contains("address:100.64.0.0/10"));
        assert!(keys.contains("address:100.80.0.0/12"));
        assert!(keys.contains("address:100.112.0.0/12"));
    }

    #[test]
    fn unexpected_connector_fails_closed() {
        let observed = ZeroTrustObservation {
            device_settings_ready: true,
            access_enrollment_ready: true,
            connector_names: vec!["foreign".to_owned()],
            ..ZeroTrustObservation::default()
        };
        let error = plan_apply(&desired(), &observed, &authority()).unwrap_err();
        assert!(error.to_string().contains("unexpected"));
    }

    #[test]
    fn exact_state_is_noop() {
        let desired = desired();
        let mut android = android_profile();
        android.excludes = desired_android_excludes(&desired, &android.excludes).unwrap();
        let posture_id = "posture-android".to_owned();
        let traffic = gateway_traffic_expression(&desired.gateway_allow.destination_cidrs).unwrap();
        let observed = ZeroTrustObservation {
            device_settings_ready: true,
            access_enrollment_ready: true,
            connector_names: vec!["vultr".to_owned()],
            mesh_profile_matches: vec![mesh_profile()],
            profile_precedences: vec![10, 100],
            android_profile: Some(android),
            posture_rules: vec![ObservedPostureRule {
                provider_id: posture_id.clone(),
                rule_type: "os_version".to_owned(),
                platforms: vec!["android".to_owned()],
            }],
            gateway_rules: vec![
                ObservedGatewayRule {
                    provider_id: "allow-1".to_owned(),
                    name: desired.gateway_allow.name.clone(),
                    action: "allow".to_owned(),
                    precedence: Some(9999),
                    enabled: Some(true),
                    filters: vec!["l4".to_owned()],
                    traffic: Some(traffic),
                    identity_sha256: Some(authority().identity_sha256),
                    device_posture: Some(format!(
                        "any(device_posture.checks.passed[*] in {{\"{posture_id}\"}})"
                    )),
                },
                ObservedGatewayRule {
                    provider_id: "block-1".to_owned(),
                    name: desired.gateway_allow.block_rule_name.clone(),
                    action: "block".to_owned(),
                    precedence: Some(10000),
                    enabled: Some(true),
                    filters: vec!["l4".to_owned()],
                    traffic: Some("net.dst.ip in {10.0.0.0/8 100.96.0.0/12}".to_owned()),
                    identity_sha256: None,
                    device_posture: None,
                },
            ],
        };
        let plan = plan_apply(&desired, &observed, &authority()).unwrap();
        assert_eq!(plan.action, ZeroTrustAction::Noop);
    }

    #[test]
    fn broader_remaining_android_exclusion_is_rejected() {
        let desired = desired();
        let observed = vec![SplitTunnelEntry {
            address: Some("100.0.0.0/8".to_owned()),
            host: None,
            description: None,
        }];
        let error = desired_android_excludes(&desired, &observed).unwrap_err();
        assert!(error.to_string().contains("still contains"));
    }
}
