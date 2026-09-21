use edge_controller_core::cloudflare_zero_trust_lifecycle::{
    DesiredZeroTrustState, ObservedDeviceProfile, ObservedGatewayRule, ObservedPostureRule,
    RuntimeAuthority, SplitTunnelEntry, ZeroTrustAction, ZeroTrustObservation, ZeroTrustPlan,
    gateway_traffic_expression, plan_apply,
};
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_provider_cloudflare::{
    CloudflareDevicePostureRule, CloudflareDeviceProfile, CloudflareDeviceProfileWrite,
    CloudflareGatewayRule, CloudflareGatewayRuleWrite, CloudflareMeshNode,
    CloudflareServiceModeWrite, CloudflareSplitTunnelEntry, CloudflareSplitTunnelWrite,
    create_device_profile, create_gateway_rule, get_device_profile_excludes,
    get_device_profile_includes, list_device_posture_rules, list_device_profiles,
    list_gateway_rules, list_mesh_nodes, set_device_profile_excludes, set_device_profile_includes,
    update_device_profile, update_gateway_rule,
};
use ring::digest::{SHA256, digest};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct ZeroTrustRuntimeInputs {
    pub android_profile_id: String,
    pub identity_email: String,
    pub authority: RuntimeAuthority,
}

impl ZeroTrustRuntimeInputs {
    pub fn new(android_profile_id: String, identity_email: String) -> Result<Self, String> {
        if android_profile_id.trim().is_empty() {
            return Err(
                "Cloudflare Android profile runtime authority must be non-empty".to_owned(),
            );
        }
        validate_identity_email(&identity_email)?;
        let identity = identity_expression(&identity_email);
        let authority = RuntimeAuthority {
            android_profile_id: android_profile_id.clone(),
            identity_sha256: expression_sha256(&identity),
        };
        Ok(Self {
            android_profile_id,
            identity_email,
            authority,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ZeroTrustExecutionPolicy {
    pub reobserve_attempts: usize,
    pub reobserve_delay: Duration,
}

impl Default for ZeroTrustExecutionPolicy {
    fn default() -> Self {
        Self {
            reobserve_attempts: 15,
            reobserve_delay: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZeroTrustApplyReport {
    pub performed: ZeroTrustAction,
    pub observation: ZeroTrustObservation,
    pub next_plan: ZeroTrustPlan,
}

#[allow(async_fn_in_trait)]
pub trait ZeroTrustProvider {
    async fn list_connectors(&mut self) -> Result<Vec<CloudflareMeshNode>, String>;
    async fn list_profiles(&mut self) -> Result<Vec<CloudflareDeviceProfile>, String>;
    async fn get_includes(
        &mut self,
        profile_id: &str,
    ) -> Result<Vec<CloudflareSplitTunnelEntry>, String>;
    async fn get_excludes(
        &mut self,
        profile_id: &str,
    ) -> Result<Vec<CloudflareSplitTunnelEntry>, String>;
    async fn list_posture_rules(&mut self) -> Result<Vec<CloudflareDevicePostureRule>, String>;
    async fn list_gateway_rules(&mut self) -> Result<Vec<CloudflareGatewayRule>, String>;
    async fn create_profile(
        &mut self,
        request: &CloudflareDeviceProfileWrite,
    ) -> Result<(), String>;
    async fn update_profile(
        &mut self,
        profile_id: &str,
        request: &CloudflareDeviceProfileWrite,
    ) -> Result<(), String>;
    async fn set_includes(
        &mut self,
        profile_id: &str,
        entries: &[CloudflareSplitTunnelWrite],
    ) -> Result<(), String>;
    async fn set_excludes(
        &mut self,
        profile_id: &str,
        entries: &[CloudflareSplitTunnelWrite],
    ) -> Result<(), String>;
    async fn create_gateway(&mut self, request: &CloudflareGatewayRuleWrite) -> Result<(), String>;
    async fn update_gateway(
        &mut self,
        rule_id: &str,
        request: &CloudflareGatewayRuleWrite,
    ) -> Result<(), String>;
}

pub struct CloudflareZeroTrustApiProvider {
    api_token: String,
    account_id: String,
}

impl CloudflareZeroTrustApiProvider {
    pub fn new(api_token: String, account_id: String) -> Result<Self, String> {
        if api_token.trim().is_empty() {
            return Err("CLOUDFLARE_API_TOKEN must be non-empty".to_owned());
        }
        if account_id.trim().is_empty() {
            return Err("Cloudflare account ID must be non-empty".to_owned());
        }
        Ok(Self {
            api_token,
            account_id,
        })
    }
}

impl ZeroTrustProvider for CloudflareZeroTrustApiProvider {
    async fn list_connectors(&mut self) -> Result<Vec<CloudflareMeshNode>, String> {
        list_mesh_nodes(&self.api_token, &self.account_id, None).await
    }

    async fn list_profiles(&mut self) -> Result<Vec<CloudflareDeviceProfile>, String> {
        list_device_profiles(&self.api_token, &self.account_id).await
    }

    async fn get_includes(
        &mut self,
        profile_id: &str,
    ) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
        get_device_profile_includes(&self.api_token, &self.account_id, profile_id).await
    }

    async fn get_excludes(
        &mut self,
        profile_id: &str,
    ) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
        get_device_profile_excludes(&self.api_token, &self.account_id, profile_id).await
    }

    async fn list_posture_rules(&mut self) -> Result<Vec<CloudflareDevicePostureRule>, String> {
        list_device_posture_rules(&self.api_token, &self.account_id).await
    }

    async fn list_gateway_rules(&mut self) -> Result<Vec<CloudflareGatewayRule>, String> {
        list_gateway_rules(&self.api_token, &self.account_id).await
    }

    async fn create_profile(
        &mut self,
        request: &CloudflareDeviceProfileWrite,
    ) -> Result<(), String> {
        create_device_profile(&self.api_token, &self.account_id, request)
            .await
            .map(|_| ())
    }

    async fn update_profile(
        &mut self,
        profile_id: &str,
        request: &CloudflareDeviceProfileWrite,
    ) -> Result<(), String> {
        update_device_profile(&self.api_token, &self.account_id, profile_id, request)
            .await
            .map(|_| ())
    }

    async fn set_includes(
        &mut self,
        profile_id: &str,
        entries: &[CloudflareSplitTunnelWrite],
    ) -> Result<(), String> {
        set_device_profile_includes(&self.api_token, &self.account_id, profile_id, entries)
            .await
            .map(|_| ())
    }

    async fn set_excludes(
        &mut self,
        profile_id: &str,
        entries: &[CloudflareSplitTunnelWrite],
    ) -> Result<(), String> {
        set_device_profile_excludes(&self.api_token, &self.account_id, profile_id, entries)
            .await
            .map(|_| ())
    }

    async fn create_gateway(&mut self, request: &CloudflareGatewayRuleWrite) -> Result<(), String> {
        create_gateway_rule(&self.api_token, &self.account_id, request)
            .await
            .map(|_| ())
    }

    async fn update_gateway(
        &mut self,
        rule_id: &str,
        request: &CloudflareGatewayRuleWrite,
    ) -> Result<(), String> {
        update_gateway_rule(&self.api_token, &self.account_id, rule_id, request)
            .await
            .map(|_| ())
    }
}

pub async fn observe_zero_trust<P: ZeroTrustProvider>(
    provider: &mut P,
    desired: &DesiredZeroTrustState,
    runtime: &ZeroTrustRuntimeInputs,
) -> Result<ZeroTrustObservation, String> {
    let connectors = provider.list_connectors().await?;
    let profiles = provider.list_profiles().await?;
    let profile_precedences = profiles
        .iter()
        .filter_map(|profile| profile.precedence)
        .collect();

    let mut mesh_profile_matches = Vec::new();
    let mut android_profile = None;
    for profile in profiles {
        let is_mesh_match = profile.name == desired.mesh_profile.name
            || profile.match_expression.as_deref()
                == Some(desired.mesh_profile.match_expression.as_str());
        let is_android = profile.id == runtime.android_profile_id;
        if !is_mesh_match && !is_android {
            continue;
        }

        let includes = if is_mesh_match {
            provider.get_includes(&profile.id).await?
        } else {
            Vec::new()
        };
        let excludes = if is_android {
            provider.get_excludes(&profile.id).await?
        } else {
            Vec::new()
        };
        let observed = observed_profile(profile, includes, excludes);
        if is_mesh_match {
            mesh_profile_matches.push(observed.clone());
        }
        if is_android {
            if android_profile.is_some() {
                return Err("Android profile runtime authority resolved more than once".to_owned());
            }
            android_profile = Some(observed);
        }
    }

    let posture_rules = provider
        .list_posture_rules()
        .await?
        .into_iter()
        .map(|rule| ObservedPostureRule {
            provider_id: rule.id,
            rule_type: rule.rule_type,
            platforms: rule.platforms,
        })
        .collect();

    let gateway_rules = provider
        .list_gateway_rules()
        .await?
        .into_iter()
        .map(observed_gateway_rule)
        .collect();

    Ok(ZeroTrustObservation {
        connector_names: connectors.into_iter().map(|node| node.name).collect(),
        mesh_profile_matches,
        profile_precedences,
        android_profile,
        posture_rules,
        gateway_rules,
    })
}

pub async fn plan_zero_trust<P: ZeroTrustProvider>(
    provider: &mut P,
    desired: &DesiredZeroTrustState,
    runtime: &ZeroTrustRuntimeInputs,
) -> Result<(ZeroTrustObservation, ZeroTrustPlan), String> {
    let observed = observe_zero_trust(provider, desired, runtime).await?;
    let plan = plan_apply(desired, &observed, &runtime.authority).map_err(|err| err.to_string())?;
    Ok((observed, plan))
}

pub fn authorize_zero_trust_apply(
    desired: &DesiredZeroTrustState,
    runtime: &RuntimeAuthority,
    observed: &ZeroTrustObservation,
    plan: ZeroTrustPlan,
) -> Result<AuthorizedPlan<ZeroTrustPlan>, String> {
    let disposition = if matches!(plan.action, ZeroTrustAction::Noop) {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    let authority_desired = serde_json::json!({
        "desired": desired,
        "runtime_authority": runtime,
    });
    authorize_plan(
        "cloudflare_zero_trust_apply",
        &authority_desired,
        observed,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub async fn apply_zero_trust_once<P: ZeroTrustProvider>(
    provider: &mut P,
    desired: &DesiredZeroTrustState,
    runtime: &ZeroTrustRuntimeInputs,
    authorized_plan_sha256: &str,
    policy: ZeroTrustExecutionPolicy,
) -> Result<ZeroTrustApplyReport, String> {
    validate_policy(policy)?;
    let (before, plan) = plan_zero_trust(provider, desired, runtime).await?;
    let authorized =
        authorize_zero_trust_apply(desired, &runtime.authority, &before, plan.clone())?;
    verify_exact_authority(authorized_plan_sha256, &authorized.authority)
        .map_err(|err| err.to_string())?;

    let action = plan.action.clone();
    let mutation = match &action {
        ZeroTrustAction::Noop => {
            return Ok(ZeroTrustApplyReport {
                performed: ZeroTrustAction::Noop,
                observation: before,
                next_plan: plan,
            });
        }
        ZeroTrustAction::CreateMeshProfile { precedence } => {
            let request = mesh_profile_request(desired, *precedence, true);
            provider.create_profile(&request).await
        }
        ZeroTrustAction::UpdateMeshProfile {
            profile_id,
            precedence,
        } => {
            let request = mesh_profile_request(desired, *precedence, false);
            provider.update_profile(profile_id, &request).await
        }
        ZeroTrustAction::SetMeshIncludes {
            profile_id,
            entries,
        } => {
            let entries = provider_entries(entries);
            provider.set_includes(profile_id, &entries).await
        }
        ZeroTrustAction::SetAndroidExcludes {
            profile_id,
            entries,
        } => {
            let entries = provider_entries(entries);
            provider.set_excludes(profile_id, &entries).await
        }
        ZeroTrustAction::CreateGatewayAllow {
            precedence,
            posture_rule_id,
        } => {
            let request = gateway_request(desired, runtime, *precedence, posture_rule_id)?;
            provider.create_gateway(&request).await
        }
        ZeroTrustAction::UpdateGatewayAllow {
            rule_id,
            precedence,
            posture_rule_id,
        } => {
            let request = gateway_request(desired, runtime, *precedence, posture_rule_id)?;
            provider.update_gateway(rule_id, &request).await
        }
    };

    reobserve_change(provider, desired, runtime, policy, action, mutation).await
}

async fn reobserve_change<P: ZeroTrustProvider>(
    provider: &mut P,
    desired: &DesiredZeroTrustState,
    runtime: &ZeroTrustRuntimeInputs,
    policy: ZeroTrustExecutionPolicy,
    performed: ZeroTrustAction,
    mutation: Result<(), String>,
) -> Result<ZeroTrustApplyReport, String> {
    let mutation_error = mutation.err();
    let mut last_observation = None;
    let mut last_plan = None;
    for attempt in 0..policy.reobserve_attempts {
        let observed = observe_zero_trust(provider, desired, runtime).await?;
        let next_plan =
            plan_apply(desired, &observed, &runtime.authority).map_err(|err| err.to_string())?;
        if action_completed(&performed, &next_plan.action) {
            return Ok(ZeroTrustApplyReport {
                performed,
                observation: observed,
                next_plan,
            });
        }
        last_observation = Some(observed);
        last_plan = Some(next_plan);
        if attempt + 1 < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }

    let detail = mutation_error.unwrap_or_else(|| "mutation returned success".to_owned());
    Err(format!(
        "Cloudflare Zero Trust mutation did not converge after bounded read-only re-observation ({detail}); mutation was not replayed; performed={performed:?}; last_plan={last_plan:?}; last_observation={last_observation:?}"
    ))
}

fn action_completed(performed: &ZeroTrustAction, next: &ZeroTrustAction) -> bool {
    match (performed, next) {
        (ZeroTrustAction::CreateMeshProfile { .. }, ZeroTrustAction::CreateMeshProfile { .. }) => {
            false
        }
        (
            ZeroTrustAction::UpdateMeshProfile {
                profile_id: left, ..
            },
            ZeroTrustAction::UpdateMeshProfile {
                profile_id: right, ..
            },
        ) if left == right => false,
        (
            ZeroTrustAction::SetMeshIncludes {
                profile_id: left, ..
            },
            ZeroTrustAction::SetMeshIncludes {
                profile_id: right, ..
            },
        ) if left == right => false,
        (
            ZeroTrustAction::SetAndroidExcludes {
                profile_id: left, ..
            },
            ZeroTrustAction::SetAndroidExcludes {
                profile_id: right, ..
            },
        ) if left == right => false,
        (
            ZeroTrustAction::CreateGatewayAllow { .. },
            ZeroTrustAction::CreateGatewayAllow { .. },
        ) => false,
        (
            ZeroTrustAction::UpdateGatewayAllow { rule_id: left, .. },
            ZeroTrustAction::UpdateGatewayAllow { rule_id: right, .. },
        ) if left == right => false,
        _ => true,
    }
}

fn mesh_profile_request(
    desired: &DesiredZeroTrustState,
    precedence: u64,
    include_on_create: bool,
) -> CloudflareDeviceProfileWrite {
    CloudflareDeviceProfileWrite {
        name: desired.mesh_profile.name.clone(),
        description: desired.mesh_profile.description.clone(),
        enabled: true,
        precedence,
        match_expression: desired.mesh_profile.match_expression.clone(),
        service_mode_v2: CloudflareServiceModeWrite {
            mode: desired.mesh_profile.service_mode.clone(),
        },
        tunnel_protocol: desired.mesh_profile.tunnel_protocol.clone(),
        include: include_on_create.then(|| {
            desired
                .mesh_profile
                .include_cidrs
                .iter()
                .map(|address| CloudflareSplitTunnelWrite {
                    address: Some(address.clone()),
                    host: None,
                    description: Some(if address == "100.96.0.0/12" {
                        "Cloudflare Mesh device IPs".to_owned()
                    } else {
                        "Cloudflare source IPs".to_owned()
                    }),
                })
                .collect()
        }),
    }
}

fn gateway_request(
    desired: &DesiredZeroTrustState,
    runtime: &ZeroTrustRuntimeInputs,
    precedence: u64,
    posture_rule_id: &str,
) -> Result<CloudflareGatewayRuleWrite, String> {
    if posture_rule_id.trim().is_empty() {
        return Err("Cloudflare Android posture rule ID must be non-empty".to_owned());
    }
    Ok(CloudflareGatewayRuleWrite {
        name: desired.gateway_allow.name.clone(),
        description: desired.gateway_allow.description.clone(),
        action: "allow".to_owned(),
        enabled: true,
        precedence,
        filters: vec!["l4".to_owned()],
        traffic: gateway_traffic_expression(&desired.gateway_allow.destination_cidrs)
            .map_err(|err| err.to_string())?,
        identity: identity_expression(&runtime.identity_email),
        device_posture: format!(
            "any(device_posture.checks.passed[*] in {{\"{posture_rule_id}\"}})"
        ),
    })
}

fn observed_profile(
    profile: CloudflareDeviceProfile,
    includes: Vec<CloudflareSplitTunnelEntry>,
    excludes: Vec<CloudflareSplitTunnelEntry>,
) -> ObservedDeviceProfile {
    ObservedDeviceProfile {
        provider_id: profile.id,
        name: profile.name,
        enabled: profile.enabled,
        precedence: profile.precedence,
        match_expression: profile.match_expression,
        service_mode: profile.service_mode,
        tunnel_protocol: profile.tunnel_protocol,
        includes: core_entries(includes),
        excludes: core_entries(excludes),
    }
}

fn observed_gateway_rule(rule: CloudflareGatewayRule) -> ObservedGatewayRule {
    ObservedGatewayRule {
        provider_id: rule.id,
        name: rule.name,
        action: rule.action,
        precedence: rule.precedence,
        enabled: rule.enabled,
        filters: rule.filters,
        traffic: rule.traffic.map(|value| normalize_expression(&value)),
        identity_sha256: rule.identity.map(|value| expression_sha256(&value)),
        device_posture: rule
            .device_posture
            .map(|value| normalize_expression(&value)),
    }
}

fn core_entries(entries: Vec<CloudflareSplitTunnelEntry>) -> Vec<SplitTunnelEntry> {
    entries
        .into_iter()
        .map(|entry| SplitTunnelEntry {
            address: entry.address,
            host: entry.host,
            description: entry.description,
        })
        .collect()
}

fn provider_entries(entries: &[SplitTunnelEntry]) -> Vec<CloudflareSplitTunnelWrite> {
    entries
        .iter()
        .map(|entry| CloudflareSplitTunnelWrite {
            address: entry.address.clone(),
            host: entry.host.clone(),
            description: entry.description.clone(),
        })
        .collect()
}

fn identity_expression(email: &str) -> String {
    format!("identity.email == \"{email}\"")
}

fn normalize_expression(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn expression_sha256(value: &str) -> String {
    digest(&SHA256, normalize_expression(value).as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_identity_email(value: &str) -> Result<(), String> {
    if value.trim() != value
        || value.is_empty()
        || !value.contains('@')
        || value
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '"' | '\\'))
    {
        return Err("Cloudflare Android identity email has invalid bounded shape".to_owned());
    }
    Ok(())
}

fn validate_policy(policy: ZeroTrustExecutionPolicy) -> Result<(), String> {
    if policy.reobserve_attempts == 0 {
        return Err(
            "Cloudflare Zero Trust re-observation attempts must be greater than zero".to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_controller_core::cloudflare_zero_trust_lifecycle::DesiredZeroTrustState;

    #[derive(Default)]
    struct FakeProvider {
        connectors: Vec<CloudflareMeshNode>,
        profiles: Vec<CloudflareDeviceProfile>,
        includes: Vec<CloudflareSplitTunnelEntry>,
        excludes: Vec<CloudflareSplitTunnelEntry>,
        posture: Vec<CloudflareDevicePostureRule>,
        gateway: Vec<CloudflareGatewayRule>,
        create_profile_calls: usize,
        create_profile_error: Option<String>,
        commit_profile_on_error: bool,
    }

    impl ZeroTrustProvider for FakeProvider {
        async fn list_connectors(&mut self) -> Result<Vec<CloudflareMeshNode>, String> {
            Ok(self.connectors.clone())
        }
        async fn list_profiles(&mut self) -> Result<Vec<CloudflareDeviceProfile>, String> {
            Ok(self.profiles.clone())
        }
        async fn get_includes(
            &mut self,
            _profile_id: &str,
        ) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
            Ok(self.includes.clone())
        }
        async fn get_excludes(
            &mut self,
            _profile_id: &str,
        ) -> Result<Vec<CloudflareSplitTunnelEntry>, String> {
            Ok(self.excludes.clone())
        }
        async fn list_posture_rules(&mut self) -> Result<Vec<CloudflareDevicePostureRule>, String> {
            Ok(self.posture.clone())
        }
        async fn list_gateway_rules(&mut self) -> Result<Vec<CloudflareGatewayRule>, String> {
            Ok(self.gateway.clone())
        }
        async fn create_profile(
            &mut self,
            request: &CloudflareDeviceProfileWrite,
        ) -> Result<(), String> {
            self.create_profile_calls += 1;
            if self.create_profile_error.is_none() || self.commit_profile_on_error {
                self.profiles.push(CloudflareDeviceProfile {
                    id: "mesh-profile".to_owned(),
                    name: request.name.clone(),
                    description: Some(request.description.clone()),
                    enabled: Some(request.enabled),
                    precedence: Some(request.precedence),
                    match_expression: Some(request.match_expression.clone()),
                    service_mode: Some(request.service_mode_v2.mode.clone()),
                    tunnel_protocol: Some(request.tunnel_protocol.clone()),
                });
                self.includes = request
                    .include
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|entry| CloudflareSplitTunnelEntry {
                        address: entry.address,
                        host: entry.host,
                        description: entry.description,
                    })
                    .collect();
            }
            match self.create_profile_error.clone() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
        async fn update_profile(
            &mut self,
            _profile_id: &str,
            _request: &CloudflareDeviceProfileWrite,
        ) -> Result<(), String> {
            Ok(())
        }
        async fn set_includes(
            &mut self,
            _profile_id: &str,
            _entries: &[CloudflareSplitTunnelWrite],
        ) -> Result<(), String> {
            Ok(())
        }
        async fn set_excludes(
            &mut self,
            _profile_id: &str,
            _entries: &[CloudflareSplitTunnelWrite],
        ) -> Result<(), String> {
            Ok(())
        }
        async fn create_gateway(
            &mut self,
            _request: &CloudflareGatewayRuleWrite,
        ) -> Result<(), String> {
            Ok(())
        }
        async fn update_gateway(
            &mut self,
            _rule_id: &str,
            _request: &CloudflareGatewayRuleWrite,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    fn desired() -> DesiredZeroTrustState {
        DesiredZeroTrustState::parse_json(include_str!(
            "../../../../infra/cloudflare/zero-trust-lifecycle.json"
        ))
        .unwrap()
    }

    fn runtime() -> ZeroTrustRuntimeInputs {
        ZeroTrustRuntimeInputs::new(
            "android-profile".to_owned(),
            "android@example.com".to_owned(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn stale_authority_rejects_before_mutation() {
        let desired = desired();
        let runtime = runtime();
        let mut provider = FakeProvider {
            connectors: vec![CloudflareMeshNode {
                id: "node-vultr".to_owned(),
                name: "vultr".to_owned(),
                status: Some("healthy".to_owned()),
            }],
            profiles: vec![CloudflareDeviceProfile {
                id: "android-profile".to_owned(),
                name: "Android".to_owned(),
                description: None,
                enabled: Some(true),
                precedence: Some(10),
                match_expression: None,
                service_mode: Some("warp".to_owned()),
                tunnel_protocol: Some("masque".to_owned()),
            }],
            ..FakeProvider::default()
        };
        let (observed, plan) = plan_zero_trust(&mut provider, &desired, &runtime)
            .await
            .unwrap();
        let authorized =
            authorize_zero_trust_apply(&desired, &runtime.authority, &observed, plan).unwrap();
        provider.connectors.push(CloudflareMeshNode {
            id: "foreign".to_owned(),
            name: "foreign".to_owned(),
            status: None,
        });

        let error = apply_zero_trust_once(
            &mut provider,
            &desired,
            &runtime,
            &authorized.authority.authority_digest,
            ZeroTrustExecutionPolicy {
                reobserve_attempts: 1,
                reobserve_delay: Duration::ZERO,
            },
        )
        .await
        .unwrap_err();
        assert!(error.contains("unexpected") || error.contains("stale"));
        assert_eq!(provider.create_profile_calls, 0);
    }

    #[tokio::test]
    async fn uncertain_create_is_observed_without_replay() {
        let desired = desired();
        let runtime = runtime();
        let mut provider = FakeProvider {
            connectors: vec![CloudflareMeshNode {
                id: "node-vultr".to_owned(),
                name: "vultr".to_owned(),
                status: Some("healthy".to_owned()),
            }],
            profiles: vec![CloudflareDeviceProfile {
                id: "android-profile".to_owned(),
                name: "Android".to_owned(),
                description: None,
                enabled: Some(true),
                precedence: Some(10),
                match_expression: None,
                service_mode: Some("warp".to_owned()),
                tunnel_protocol: Some("masque".to_owned()),
            }],
            create_profile_error: Some("transport lost".to_owned()),
            commit_profile_on_error: true,
            ..FakeProvider::default()
        };
        let (observed, plan) = plan_zero_trust(&mut provider, &desired, &runtime)
            .await
            .unwrap();
        let authorized =
            authorize_zero_trust_apply(&desired, &runtime.authority, &observed, plan).unwrap();

        let report = apply_zero_trust_once(
            &mut provider,
            &desired,
            &runtime,
            &authorized.authority.authority_digest,
            ZeroTrustExecutionPolicy {
                reobserve_attempts: 1,
                reobserve_delay: Duration::ZERO,
            },
        )
        .await
        .unwrap();

        assert_eq!(provider.create_profile_calls, 1);
        assert!(!matches!(
            report.next_plan.action,
            ZeroTrustAction::CreateMeshProfile { .. }
        ));
    }
}
