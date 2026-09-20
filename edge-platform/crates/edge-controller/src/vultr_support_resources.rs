use crate::vultr_lifecycle_service::LifecycleExecutionPolicy;
use edge_controller_core::vultr_lifecycle::{
    DesiredState, MANAGED_BY_IDENTITY, MachineSpec, decode_provider_tags,
};
use edge_provider_vultr::{
    CreateFirewallRuleRequest, VultrError, VultrFirewallGroup, VultrFirewallRule, VultrInstance,
    VultrOperatingSystem, VultrPlan, VultrRegionAvailability, VultrSnapshot, VultrSshKey,
    create_firewall_group_typed, create_firewall_rule_typed, create_ssh_key_typed,
    destroy_firewall_group_typed, destroy_firewall_rule_typed, destroy_ssh_key_typed,
    get_region_availability_typed, list_firewall_groups_typed, list_firewall_rules_typed,
    list_operating_systems_typed, list_plans_typed, list_snapshots_typed, list_ssh_keys_typed,
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use tokio::time::sleep;

const FIREWALL_PROFILE_SCHEMA: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallProfileSet {
    profiles: BTreeMap<String, FirewallProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallProfile {
    pub name: String,
    pub rules: Vec<FirewallRuleSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirewallRuleSpec {
    pub ip_type: String,
    pub protocol: String,
    pub subnet: String,
    pub subnet_size: u32,
    pub port: String,
    pub source: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSshKey {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFirewallProfile {
    pub id: String,
    pub profile_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportCleanupReport {
    pub environment_in_use: bool,
    pub ssh_key_removed: bool,
    pub firewall_groups_removed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerAccessReleaseReport {
    pub firewall_group_id: Option<String>,
    pub removed_rule_ids: Vec<u64>,
    pub verified_absent: bool,
}

#[allow(async_fn_in_trait)]
pub trait SupportResourceProvider {
    async fn list_ssh_keys(&mut self) -> Result<Vec<VultrSshKey>, VultrError>;
    async fn create_ssh_key(
        &mut self,
        name: &str,
        public_key: &str,
    ) -> Result<VultrSshKey, VultrError>;
    async fn destroy_ssh_key(&mut self, ssh_key_id: &str) -> Result<(), VultrError>;
    async fn list_firewall_groups(&mut self) -> Result<Vec<VultrFirewallGroup>, VultrError>;
    async fn create_firewall_group(
        &mut self,
        description: &str,
    ) -> Result<VultrFirewallGroup, VultrError>;
    async fn destroy_firewall_group(&mut self, firewall_group_id: &str) -> Result<(), VultrError>;
    async fn list_firewall_rules(
        &mut self,
        firewall_group_id: &str,
    ) -> Result<Vec<VultrFirewallRule>, VultrError>;
    async fn create_firewall_rule(
        &mut self,
        firewall_group_id: &str,
        rule: &FirewallRuleSpec,
    ) -> Result<VultrFirewallRule, VultrError>;
    async fn destroy_firewall_rule(
        &mut self,
        firewall_group_id: &str,
        firewall_rule_id: u64,
    ) -> Result<(), VultrError>;
    async fn list_plans(&mut self) -> Result<Vec<VultrPlan>, VultrError>;
    async fn region_availability(
        &mut self,
        region: &str,
        plan_type: &str,
    ) -> Result<VultrRegionAvailability, VultrError>;
    async fn list_operating_systems(&mut self) -> Result<Vec<VultrOperatingSystem>, VultrError>;
    async fn list_snapshots(&mut self) -> Result<Vec<VultrSnapshot>, VultrError>;
}

pub struct VultrSupportApiProvider {
    api_key: String,
}

impl VultrSupportApiProvider {
    pub fn new(api_key: String) -> Result<Self, String> {
        if api_key.trim().is_empty() {
            return Err("VULTR_API_KEY must be non-empty".to_owned());
        }
        Ok(Self { api_key })
    }
}

impl SupportResourceProvider for VultrSupportApiProvider {
    async fn list_ssh_keys(&mut self) -> Result<Vec<VultrSshKey>, VultrError> {
        list_ssh_keys_typed(&self.api_key).await
    }

    async fn create_ssh_key(
        &mut self,
        name: &str,
        public_key: &str,
    ) -> Result<VultrSshKey, VultrError> {
        create_ssh_key_typed(&self.api_key, name, public_key).await
    }

    async fn destroy_ssh_key(&mut self, ssh_key_id: &str) -> Result<(), VultrError> {
        destroy_ssh_key_typed(&self.api_key, ssh_key_id).await
    }

    async fn list_firewall_groups(&mut self) -> Result<Vec<VultrFirewallGroup>, VultrError> {
        list_firewall_groups_typed(&self.api_key).await
    }

    async fn create_firewall_group(
        &mut self,
        description: &str,
    ) -> Result<VultrFirewallGroup, VultrError> {
        create_firewall_group_typed(&self.api_key, description).await
    }

    async fn destroy_firewall_group(&mut self, firewall_group_id: &str) -> Result<(), VultrError> {
        destroy_firewall_group_typed(&self.api_key, firewall_group_id).await
    }

    async fn list_firewall_rules(
        &mut self,
        firewall_group_id: &str,
    ) -> Result<Vec<VultrFirewallRule>, VultrError> {
        list_firewall_rules_typed(&self.api_key, firewall_group_id).await
    }

    async fn create_firewall_rule(
        &mut self,
        firewall_group_id: &str,
        rule: &FirewallRuleSpec,
    ) -> Result<VultrFirewallRule, VultrError> {
        create_firewall_rule_typed(
            &self.api_key,
            firewall_group_id,
            &CreateFirewallRuleRequest {
                ip_type: &rule.ip_type,
                protocol: &rule.protocol,
                subnet: &rule.subnet,
                subnet_size: rule.subnet_size,
                port: &rule.port,
                source: (!rule.source.is_empty()).then_some(rule.source.as_str()),
                notes: (!rule.notes.is_empty()).then_some(rule.notes.as_str()),
            },
        )
        .await
    }

    async fn destroy_firewall_rule(
        &mut self,
        firewall_group_id: &str,
        firewall_rule_id: u64,
    ) -> Result<(), VultrError> {
        destroy_firewall_rule_typed(&self.api_key, firewall_group_id, firewall_rule_id).await
    }

    async fn list_plans(&mut self) -> Result<Vec<VultrPlan>, VultrError> {
        list_plans_typed(&self.api_key, None).await
    }

    async fn region_availability(
        &mut self,
        region: &str,
        plan_type: &str,
    ) -> Result<VultrRegionAvailability, VultrError> {
        get_region_availability_typed(&self.api_key, region, plan_type).await
    }

    async fn list_operating_systems(&mut self) -> Result<Vec<VultrOperatingSystem>, VultrError> {
        list_operating_systems_typed(&self.api_key).await
    }

    async fn list_snapshots(&mut self) -> Result<Vec<VultrSnapshot>, VultrError> {
        list_snapshots_typed(&self.api_key).await
    }
}

impl FirewallProfileSet {
    pub fn parse_json(raw: &str) -> Result<Self, String> {
        let value: Value = serde_json::from_str(raw)
            .map_err(|err| format!("invalid firewall profiles JSON: {err}"))?;
        let root = expect_object(&value, "firewall profiles")?;
        reject_unknown_keys(root, &["schema", "profiles"], "firewall profiles")?;
        let schema = root
            .get("schema")
            .and_then(Value::as_u64)
            .ok_or_else(|| "firewall profiles schema must be an integer".to_owned())?;
        if schema != FIREWALL_PROFILE_SCHEMA {
            return Err(format!("unsupported firewall profiles schema {schema}"));
        }
        let profile_values = root
            .get("profiles")
            .and_then(Value::as_array)
            .ok_or_else(|| "firewall profiles must contain a profiles array".to_owned())?;

        let mut profiles = BTreeMap::new();
        for profile_value in profile_values {
            let profile = parse_profile(profile_value)?;
            if profiles.insert(profile.name.clone(), profile).is_some() {
                return Err("firewall profile names must be unique".to_owned());
            }
        }
        Ok(Self { profiles })
    }

    pub fn profile(&self, name: &str) -> Result<&FirewallProfile, String> {
        self.profiles
            .get(name)
            .ok_or_else(|| format!("firewall profile {name} is not defined"))
    }

    pub fn resolve_controller_ipv4_for_profiles(
        &mut self,
        profile_names: &[String],
        controller_ipv4: Option<&str>,
    ) -> Result<(), String> {
        const PLACEHOLDER: &str = "@controller-ipv4";
        let needs_controller_ip = profile_names.iter().any(|name| {
            self.profiles
                .get(name)
                .is_some_and(|profile| profile.rules.iter().any(|rule| rule.subnet == PLACEHOLDER))
        });
        if !needs_controller_ip {
            return Ok(());
        }
        let raw = controller_ipv4.ok_or_else(|| {
            "referenced firewall profiles require EDGE_CONTROLLER_IPV4".to_owned()
        })?;
        let ipv4 = raw
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "EDGE_CONTROLLER_IPV4 must be a valid IPv4 address".to_owned())?
            .to_string();

        for name in profile_names {
            let profile = self
                .profiles
                .get_mut(name)
                .ok_or_else(|| format!("firewall profile {name} is not defined"))?;
            for rule in &mut profile.rules {
                if rule.subnet == PLACEHOLDER {
                    if rule.ip_type != "v4" || rule.subnet_size != 32 {
                        return Err(format!(
                            "firewall profile {} uses {PLACEHOLDER} but is not an exact IPv4 /32",
                            profile.name
                        ));
                    }
                    rule.subnet = ipv4.clone();
                }
            }
            profile.rules.sort();
        }
        Ok(())
    }
}

pub async fn validate_machine_catalog<P: SupportResourceProvider>(
    provider: &mut P,
    machine: &MachineSpec,
) -> Result<(), String> {
    let plans = provider.list_plans().await.map_err(|err| err.to_string())?;
    let matching_plans = plans
        .iter()
        .filter(|plan| plan.id == machine.provider.plan)
        .collect::<Vec<_>>();
    let plan = match matching_plans.as_slice() {
        [] => {
            return Err(format!(
                "Vultr plan {} is absent from the live catalog",
                machine.provider.plan
            ));
        }
        [plan] => *plan,
        _ => {
            return Err(format!(
                "Vultr plan {} is ambiguous in the live catalog",
                machine.provider.plan
            ));
        }
    };
    if plan.plan_type.trim().is_empty() {
        return Err(format!(
            "Vultr plan {} has no provider type",
            machine.provider.plan
        ));
    }

    let availability = provider
        .region_availability(&machine.provider.region, &plan.plan_type)
        .await
        .map_err(|err| err.to_string())?;
    if !availability
        .available_plans
        .iter()
        .any(|plan_id| plan_id == &machine.provider.plan)
    {
        return Err(format!(
            "Vultr plan {} is not currently available in region {}",
            machine.provider.plan, machine.provider.region
        ));
    }

    if let Some(os_id) = machine.provider.os_id {
        let operating_systems = provider
            .list_operating_systems()
            .await
            .map_err(|err| err.to_string())?;
        if !operating_systems.iter().any(|os| os.id == os_id) {
            return Err(format!(
                "Vultr OS id {os_id} is absent from the live OS catalog"
            ));
        }
    }
    if let Some(snapshot_id) = machine.provider.snapshot_id.as_deref() {
        let snapshots = provider
            .list_snapshots()
            .await
            .map_err(|err| err.to_string())?;
        let matches = snapshots
            .iter()
            .filter(|snapshot| snapshot.id == snapshot_id)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => {
                return Err(format!(
                    "Vultr snapshot {snapshot_id} is absent from the live snapshot catalog"
                ));
            }
            [snapshot] if snapshot.status.eq_ignore_ascii_case("complete") => {}
            [snapshot] => {
                return Err(format!(
                    "Vultr snapshot {snapshot_id} is not ready: status={}",
                    snapshot.status
                ));
            }
            _ => {
                return Err(format!(
                    "Vultr snapshot {snapshot_id} is ambiguous in the live snapshot catalog"
                ));
            }
        }
    }
    Ok(())
}

pub async fn resolve_managed_ssh_key<P: SupportResourceProvider>(
    provider: &mut P,
    environment: &str,
    canonical_public_key: &str,
    policy: &LifecycleExecutionPolicy,
) -> Result<ResolvedSshKey, String> {
    let desired_name = format!("singbox-{environment}-ops");
    let desired_material = public_key_material(canonical_public_key)?;

    match observe_managed_ssh_key(provider, &desired_name, &desired_material).await? {
        SshKeyObservation::Exact(key) => return Ok(key),
        SshKeyObservation::Conflict(detail) => return Err(detail),
        SshKeyObservation::Absent => {}
    }

    let mutation = provider
        .create_ssh_key(&desired_name, canonical_public_key.trim())
        .await;
    match &mutation {
        Ok(_) => {}
        Err(err) if err.requires_mutation_reobservation() => {}
        Err(err) => return Err(err.to_string()),
    }

    for attempt in 0..policy.create_reobserve_attempts {
        match observe_managed_ssh_key(provider, &desired_name, &desired_material).await? {
            SshKeyObservation::Exact(key) => return Ok(key),
            SshKeyObservation::Conflict(detail) => return Err(detail),
            SshKeyObservation::Absent => {}
        }
        if attempt + 1 < policy.create_reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }

    match mutation {
        Ok(_) => Err(format!(
            "Vultr SSH key {desired_name} was created but did not become observable"
        )),
        Err(err) => Err(format!(
            "{err}; SSH-key CREATE was not replayed and exact re-observation remained absent"
        )),
    }
}

pub async fn observe_verified_firewall_bindings<P: SupportResourceProvider>(
    provider: &mut P,
    desired: &DesiredState,
    profiles: &FirewallProfileSet,
) -> Result<BTreeMap<String, String>, String> {
    let groups = provider
        .list_firewall_groups()
        .await
        .map_err(|err| err.to_string())?;
    let profile_names = desired
        .machines
        .iter()
        .filter_map(|machine| machine.provider.firewall_profile.as_deref())
        .collect::<BTreeSet<_>>();
    let mut verified = BTreeMap::new();

    for profile_name in profile_names {
        let profile = profiles.profile(profile_name)?;
        let description = firewall_group_description(&desired.environment, profile_name);
        let matching = groups
            .iter()
            .filter(|group| group.description == description)
            .collect::<Vec<_>>();
        let group = match matching.as_slice() {
            [] => continue,
            [group] => *group,
            _ => {
                return Err(format!(
                    "multiple Vultr firewall groups have owned description {description}"
                ));
            }
        };
        let rules = provider
            .list_firewall_rules(&group.id)
            .await
            .map_err(|err| err.to_string())?;
        if firewall_rules_match(profile, &rules)? {
            verified.insert(group.id.clone(), profile_name.to_owned());
        }
    }
    Ok(verified)
}

pub async fn ensure_firewall_profile<P: SupportResourceProvider>(
    provider: &mut P,
    environment: &str,
    profile: &FirewallProfile,
    policy: &LifecycleExecutionPolicy,
) -> Result<ResolvedFirewallProfile, String> {
    let description = firewall_group_description(environment, &profile.name);
    let mut group = observe_firewall_group(provider, &description).await?;
    if group.is_none() {
        let mutation = provider.create_firewall_group(&description).await;
        match &mutation {
            Ok(_) => {}
            Err(err) if err.requires_mutation_reobservation() => {}
            Err(err) => return Err(err.to_string()),
        }

        for attempt in 0..policy.create_reobserve_attempts {
            group = observe_firewall_group(provider, &description).await?;
            if group.is_some() {
                break;
            }
            if attempt + 1 < policy.create_reobserve_attempts {
                sleep(policy.reobserve_delay).await;
            }
        }
        if group.is_none() {
            return match mutation {
                Ok(_) => Err(format!(
                    "Vultr firewall group {description} was created but did not become observable"
                )),
                Err(err) => Err(format!(
                    "{err}; firewall-group CREATE was not replayed and exact re-observation remained absent"
                )),
            };
        }
    }

    let group = group.expect("checked above");
    reconcile_firewall_rules(provider, &group.id, profile, policy).await?;
    Ok(ResolvedFirewallProfile {
        id: group.id,
        profile_name: profile.name.clone(),
    })
}

pub async fn release_controller_ipv4_access<P: SupportResourceProvider>(
    provider: &mut P,
    environment: &str,
    unresolved_profile: &FirewallProfile,
    controller_ipv4: &str,
    policy: &LifecycleExecutionPolicy,
) -> Result<ControllerAccessReleaseReport, String> {
    let target_specs = controller_ipv4_access_specs(unresolved_profile, controller_ipv4)?;
    if target_specs.is_empty() {
        return Err(format!(
            "firewall profile {} has no @controller-ipv4 access rule",
            unresolved_profile.name
        ));
    }

    let description = firewall_group_description(environment, &unresolved_profile.name);
    let Some(group) = observe_firewall_group(provider, &description).await? else {
        return Ok(ControllerAccessReleaseReport {
            firewall_group_id: None,
            removed_rule_ids: Vec::new(),
            verified_absent: true,
        });
    };

    let observed = provider
        .list_firewall_rules(&group.id)
        .await
        .map_err(|err| err.to_string())?;
    let mut removed_rule_ids = Vec::new();

    for rule in observed {
        let spec = firewall_rule_spec(&rule)?;
        if target_specs
            .iter()
            .any(|target| same_firewall_access_semantics(&spec, target))
        {
            delete_firewall_rule_and_observe(provider, &group.id, rule.id, policy).await?;
            removed_rule_ids.push(rule.id);
        }
    }

    let final_rules = provider
        .list_firewall_rules(&group.id)
        .await
        .map_err(|err| err.to_string())?;
    let remaining = final_rules
        .iter()
        .map(firewall_rule_spec)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|spec| {
            target_specs
                .iter()
                .any(|target| same_firewall_access_semantics(spec, target))
        })
        .collect::<Vec<_>>();
    if !remaining.is_empty() {
        return Err(format!(
            "controller SSH access cleanup did not prove exact /32 absence in firewall group {}: {:?}",
            group.id, remaining
        ));
    }

    removed_rule_ids.sort_unstable();
    Ok(ControllerAccessReleaseReport {
        firewall_group_id: Some(group.id),
        removed_rule_ids,
        verified_absent: true,
    })
}

pub(crate) fn same_firewall_access_semantics(
    left: &FirewallRuleSpec,
    right: &FirewallRuleSpec,
) -> bool {
    left.ip_type == right.ip_type
        && left.protocol == right.protocol
        && left.subnet == right.subnet
        && left.subnet_size == right.subnet_size
        && left.port == right.port
        && left.source == right.source
}

pub(crate) fn controller_ipv4_access_specs(
    unresolved_profile: &FirewallProfile,
    controller_ipv4: &str,
) -> Result<BTreeSet<FirewallRuleSpec>, String> {
    const PLACEHOLDER: &str = "@controller-ipv4";
    let ipv4 = controller_ipv4
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "EDGE_CONTROLLER_IPV4 must be a valid IPv4 address".to_owned())?
        .to_string();
    let mut targets = BTreeSet::new();

    for rule in &unresolved_profile.rules {
        if rule.subnet != PLACEHOLDER {
            continue;
        }
        if rule.ip_type != "v4" || rule.subnet_size != 32 {
            return Err(format!(
                "firewall profile {} uses {PLACEHOLDER} but is not an exact IPv4 /32",
                unresolved_profile.name
            ));
        }
        let mut resolved = rule.clone();
        resolved.subnet = ipv4.clone();
        targets.insert(resolved);
    }

    Ok(targets)
}

pub async fn cleanup_environment_support_resources<P: SupportResourceProvider>(
    provider: &mut P,
    desired: &DesiredState,
    remaining_instances: &[VultrInstance],
    canonical_public_key: &str,
    policy: &LifecycleExecutionPolicy,
) -> Result<SupportCleanupReport, String> {
    let mut environment_in_use = false;
    for instance in remaining_instances {
        let decoded = decode_provider_tags(&instance.tags).map_err(|err| {
            format!(
                "cannot prove support-resource cleanup safety because instance {} has invalid lifecycle tags: {err}",
                instance.id
            )
        })?;
        if decoded.ownership.managed_by.as_deref() == Some(MANAGED_BY_IDENTITY)
            && decoded.ownership.environment.as_deref() == Some(desired.environment.as_str())
        {
            environment_in_use = true;
        }
    }
    if environment_in_use {
        return Ok(SupportCleanupReport {
            environment_in_use: true,
            ssh_key_removed: false,
            firewall_groups_removed: Vec::new(),
        });
    }

    let firewall_prefix = format!("singbox-{}-fw-", desired.environment);
    let groups = provider
        .list_firewall_groups()
        .await
        .map_err(|err| err.to_string())?;
    let mut candidates = groups
        .into_iter()
        .filter(|group| group.description.starts_with(&firewall_prefix))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.id.cmp(&right.id));

    let mut seen_descriptions = BTreeSet::new();
    for group in &candidates {
        if !seen_descriptions.insert(group.description.clone()) {
            return Err(format!(
                "support-resource cleanup is ambiguous: duplicate managed firewall description {}",
                group.description
            ));
        }
        if remaining_instances
            .iter()
            .any(|instance| instance.firewall_group_id == group.id)
        {
            return Err(format!(
                "support-resource cleanup refused: firewall group {} is still attached to provider instance",
                group.id
            ));
        }
    }

    let desired_ssh_name = format!("singbox-{}-ops", desired.environment);
    let desired_ssh_material = public_key_material(canonical_public_key)?;
    let ssh_key =
        match observe_managed_ssh_key(provider, &desired_ssh_name, &desired_ssh_material).await? {
            SshKeyObservation::Exact(key) => Some(key),
            SshKeyObservation::Absent => None,
            SshKeyObservation::Conflict(detail) => return Err(detail),
        };

    let mut firewall_groups_removed = Vec::new();
    for group in candidates {
        delete_firewall_group_and_observe(provider, &group, policy).await?;
        firewall_groups_removed.push(group.id);
    }

    let ssh_key_removed = if let Some(key) = ssh_key {
        delete_ssh_key_and_observe(provider, &key, policy).await?;
        true
    } else {
        false
    };

    Ok(SupportCleanupReport {
        environment_in_use: false,
        ssh_key_removed,
        firewall_groups_removed,
    })
}

async fn delete_firewall_group_and_observe<P: SupportResourceProvider>(
    provider: &mut P,
    group: &VultrFirewallGroup,
    policy: &LifecycleExecutionPolicy,
) -> Result<(), String> {
    let mutation = provider.destroy_firewall_group(&group.id).await;
    match &mutation {
        Ok(()) => {}
        Err(err) if err.is_not_found() => return Ok(()),
        Err(err) if err.requires_mutation_reobservation() => {}
        Err(err) => return Err(err.to_string()),
    }
    for attempt in 0..policy.destroy_reobserve_attempts {
        let groups = provider
            .list_firewall_groups()
            .await
            .map_err(|err| err.to_string())?;
        if !groups.iter().any(|candidate| candidate.id == group.id) {
            return Ok(());
        }
        if attempt + 1 < policy.destroy_reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }
    Err(format!(
        "firewall-group DELETE for {} was not proven absent and was not replayed",
        group.id
    ))
}

async fn delete_ssh_key_and_observe<P: SupportResourceProvider>(
    provider: &mut P,
    key: &ResolvedSshKey,
    policy: &LifecycleExecutionPolicy,
) -> Result<(), String> {
    let mutation = provider.destroy_ssh_key(&key.id).await;
    match &mutation {
        Ok(()) => {}
        Err(err) if err.is_not_found() => return Ok(()),
        Err(err) if err.requires_mutation_reobservation() => {}
        Err(err) => return Err(err.to_string()),
    }
    for attempt in 0..policy.destroy_reobserve_attempts {
        let keys = provider
            .list_ssh_keys()
            .await
            .map_err(|err| err.to_string())?;
        if !keys.iter().any(|candidate| candidate.id == key.id) {
            return Ok(());
        }
        if attempt + 1 < policy.destroy_reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }
    Err(format!(
        "SSH-key DELETE for {} was not proven absent and was not replayed",
        key.id
    ))
}

async fn reconcile_firewall_rules<P: SupportResourceProvider>(
    provider: &mut P,
    group_id: &str,
    profile: &FirewallProfile,
    policy: &LifecycleExecutionPolicy,
) -> Result<(), String> {
    let max_mutations = profile.rules.len().saturating_mul(2).saturating_add(32);
    for mutation_index in 0..=max_mutations {
        let current = provider
            .list_firewall_rules(group_id)
            .await
            .map_err(|err| err.to_string())?;
        let current_by_spec = current_rule_map(&current)?;
        let desired = profile.rules.iter().cloned().collect::<BTreeSet<_>>();

        if current_by_spec.keys().cloned().collect::<BTreeSet<_>>() == desired
            && current_by_spec.values().all(|ids| ids.len() == 1)
        {
            return Ok(());
        }
        if mutation_index == max_mutations {
            break;
        }

        if let Some((spec, ids)) = current_by_spec
            .iter()
            .find(|(spec, ids)| !desired.contains(*spec) || ids.len() > 1)
        {
            let rule_id = *ids
                .last()
                .ok_or_else(|| format!("firewall rule map for {spec:?} is unexpectedly empty"))?;
            delete_firewall_rule_and_observe(provider, group_id, rule_id, policy).await?;
            continue;
        }

        if let Some(missing) = desired
            .iter()
            .find(|spec| !current_by_spec.contains_key(*spec))
        {
            create_firewall_rule_and_observe(provider, group_id, missing, policy).await?;
            continue;
        }
    }

    let observed = provider
        .list_firewall_rules(group_id)
        .await
        .map_err(|err| err.to_string())?;
    Err(format!(
        "firewall profile {} did not converge after bounded reconciliation; desired={:?} observed={:?}",
        profile.name, profile.rules, observed
    ))
}

async fn create_firewall_rule_and_observe<P: SupportResourceProvider>(
    provider: &mut P,
    group_id: &str,
    desired: &FirewallRuleSpec,
    policy: &LifecycleExecutionPolicy,
) -> Result<(), String> {
    let mutation = provider.create_firewall_rule(group_id, desired).await;
    let expected_id = match &mutation {
        Ok(rule) => {
            let returned = firewall_rule_spec(rule)?;
            if returned != *desired {
                return Err(format!(
                    "Vultr normalized created firewall rule away from desired state; desired={desired:?} returned={returned:?}"
                ));
            }
            Some(rule.id)
        }
        Err(err) if err.requires_mutation_reobservation() => None,
        Err(err) => return Err(err.to_string()),
    };

    let mut last_observed = Vec::new();
    for attempt in 0..policy.create_reobserve_attempts {
        let observed = provider
            .list_firewall_rules(group_id)
            .await
            .map_err(|err| err.to_string())?;
        let current = current_rule_map(&observed)?;
        let matching = current.get(desired).cloned().unwrap_or_default();

        match expected_id {
            Some(id) if matching.contains(&id) => return Ok(()),
            None if matching.len() == 1 => return Ok(()),
            None if matching.len() > 1 => {
                return Err(format!(
                    "uncertain firewall-rule CREATE became ambiguous for {desired:?}: observed matching ids={matching:?}; mutation was not replayed"
                ));
            }
            _ => {}
        }

        last_observed = observed;
        if attempt + 1 < policy.create_reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }

    match mutation {
        Ok(rule) => Err(format!(
            "firewall-rule CREATE returned id={} but that exact rule did not become observable after bounded re-observation; desired={desired:?} observed={last_observed:?}; mutation was not replayed",
            rule.id
        )),
        Err(err) => Err(format!(
            "{err}; firewall-rule CREATE outcome was not proven by bounded re-observation; desired={desired:?} observed={last_observed:?}; mutation was not replayed"
        )),
    }
}

async fn delete_firewall_rule_and_observe<P: SupportResourceProvider>(
    provider: &mut P,
    group_id: &str,
    rule_id: u64,
    policy: &LifecycleExecutionPolicy,
) -> Result<(), String> {
    let mutation = provider.destroy_firewall_rule(group_id, rule_id).await;
    match &mutation {
        Ok(()) => {}
        Err(err) if err.is_not_found() => return Ok(()),
        Err(err) if err.requires_mutation_reobservation() => {}
        Err(err) => return Err(err.to_string()),
    }

    let mut last_observed = Vec::new();
    for attempt in 0..policy.destroy_reobserve_attempts {
        let observed = provider
            .list_firewall_rules(group_id)
            .await
            .map_err(|err| err.to_string())?;
        if !observed.iter().any(|rule| rule.id == rule_id) {
            return Ok(());
        }
        last_observed = observed;
        if attempt + 1 < policy.destroy_reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }

    Err(format!(
        "firewall-rule DELETE for id={rule_id} was not proven absent after bounded re-observation; observed={last_observed:?}; mutation was not replayed"
    ))
}

enum SshKeyObservation {
    Absent,
    Exact(ResolvedSshKey),
    Conflict(String),
}

async fn observe_managed_ssh_key<P: SupportResourceProvider>(
    provider: &mut P,
    desired_name: &str,
    desired_material: &str,
) -> Result<SshKeyObservation, String> {
    let keys = provider
        .list_ssh_keys()
        .await
        .map_err(|err| err.to_string())?;
    let named = keys
        .iter()
        .filter(|key| key.name == desired_name)
        .collect::<Vec<_>>();
    if named.len() > 1 {
        return Ok(SshKeyObservation::Conflict(format!(
            "multiple Vultr SSH keys use managed name {desired_name}"
        )));
    }
    let Some(key) = named.first().copied() else {
        return Ok(SshKeyObservation::Absent);
    };
    let observed_material = public_key_material(&key.ssh_key)?;
    if observed_material != desired_material {
        return Ok(SshKeyObservation::Conflict(format!(
            "Vultr SSH key {} has managed name {} but different public key material",
            key.id, desired_name
        )));
    }
    Ok(SshKeyObservation::Exact(ResolvedSshKey {
        id: key.id.clone(),
        name: key.name.clone(),
    }))
}

async fn observe_firewall_group<P: SupportResourceProvider>(
    provider: &mut P,
    description: &str,
) -> Result<Option<VultrFirewallGroup>, String> {
    let groups = provider
        .list_firewall_groups()
        .await
        .map_err(|err| err.to_string())?;
    let matching = groups
        .into_iter()
        .filter(|group| group.description == description)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [] => Ok(None),
        [group] => Ok(Some(group.clone())),
        _ => Err(format!(
            "multiple Vultr firewall groups have owned description {description}"
        )),
    }
}

fn firewall_rules_match(
    profile: &FirewallProfile,
    observed: &[VultrFirewallRule],
) -> Result<bool, String> {
    let map = current_rule_map(observed)?;
    let desired = profile.rules.iter().cloned().collect::<BTreeSet<_>>();
    Ok(map.keys().cloned().collect::<BTreeSet<_>>() == desired
        && map.values().all(|ids| ids.len() == 1))
}

fn current_rule_map(
    observed: &[VultrFirewallRule],
) -> Result<BTreeMap<FirewallRuleSpec, Vec<u64>>, String> {
    let mut result: BTreeMap<FirewallRuleSpec, Vec<u64>> = BTreeMap::new();
    for rule in observed {
        let spec = firewall_rule_spec(rule)?;
        result.entry(spec).or_default().push(rule.id);
    }
    for ids in result.values_mut() {
        ids.sort_unstable();
    }
    Ok(result)
}

pub(crate) fn firewall_rule_spec(rule: &VultrFirewallRule) -> Result<FirewallRuleSpec, String> {
    let subnet = rule.subnet.trim().to_owned();
    let raw_source = rule.source.trim();
    let provider_derived_source = format!("{subnet}/{}", rule.subnet_size);
    let source = if raw_source == provider_derived_source {
        String::new()
    } else {
        raw_source.to_owned()
    };
    let spec = FirewallRuleSpec {
        ip_type: rule.ip_type.trim().to_owned(),
        protocol: rule.protocol.trim().to_owned(),
        subnet,
        subnet_size: rule.subnet_size,
        port: rule.port.trim().to_owned(),
        source,
        notes: rule.notes.trim().to_owned(),
    };
    validate_rule(&spec)?;
    Ok(spec)
}

pub(crate) fn firewall_group_description(environment: &str, profile_name: &str) -> String {
    format!("singbox-{environment}-fw-{profile_name}")
}

pub(crate) fn public_key_material(public_key: &str) -> Result<String, String> {
    let fields = public_key.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 2 {
        return Err("SSH public key must contain algorithm and base64 material".to_owned());
    }
    if fields[0] != "ssh-ed25519" {
        return Err(format!(
            "canonical operational key must be ssh-ed25519, got {}",
            fields[0]
        ));
    }
    if fields[1].is_empty()
        || !fields[1]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err("SSH public key base64 material is malformed".to_owned());
    }
    Ok(format!("{} {}", fields[0], fields[1]))
}

fn parse_profile(value: &Value) -> Result<FirewallProfile, String> {
    let object = expect_object(value, "firewall profile")?;
    reject_unknown_keys(object, &["name", "rules"], "firewall profile")?;
    let name = required_identifier(object, "name", "firewall profile")?;
    let rules = object
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("firewall profile {name} must contain a rules array"))?;
    let mut parsed_rules = Vec::new();
    let mut unique = BTreeSet::new();
    for value in rules {
        let rule = parse_rule(value, &name)?;
        if !unique.insert(rule.clone()) {
            return Err(format!("firewall profile {name} contains a duplicate rule"));
        }
        parsed_rules.push(rule);
    }
    parsed_rules.sort();
    Ok(FirewallProfile {
        name,
        rules: parsed_rules,
    })
}

fn parse_rule(value: &Value, profile_name: &str) -> Result<FirewallRuleSpec, String> {
    let object = expect_object(value, "firewall rule")?;
    reject_unknown_keys(
        object,
        &[
            "ip_type",
            "protocol",
            "subnet",
            "subnet_size",
            "port",
            "source",
            "notes",
        ],
        "firewall rule",
    )?;
    let rule = FirewallRuleSpec {
        ip_type: required_identifier(object, "ip_type", "firewall rule")?,
        protocol: required_identifier(object, "protocol", "firewall rule")?,
        subnet: required_string(object, "subnet", "firewall rule")?,
        subnet_size: object
            .get("subnet_size")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                format!("firewall profile {profile_name} rule subnet_size must be an integer")
            })?,
        port: optional_string(object, "port")?,
        source: optional_string(object, "source")?,
        notes: optional_string(object, "notes")?,
    };
    validate_rule(&rule)?;
    Ok(rule)
}

fn validate_rule(rule: &FirewallRuleSpec) -> Result<(), String> {
    match rule.ip_type.as_str() {
        "v4" if rule.subnet_size <= 32 => {}
        "v6" if rule.subnet_size <= 128 => {}
        "v4" => return Err("IPv4 firewall subnet_size must be <= 32".to_owned()),
        "v6" => return Err("IPv6 firewall subnet_size must be <= 128".to_owned()),
        other => return Err(format!("unsupported firewall ip_type {other}")),
    }
    if rule.protocol.is_empty() || rule.subnet.is_empty() {
        return Err("firewall protocol and subnet must be non-empty".to_owned());
    }
    Ok(())
}

fn expect_object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object"))
}

fn reject_unknown_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), String> {
    if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("{label} contains unknown field {unknown}"));
    }
    Ok(())
}

fn required_identifier(
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, String> {
    let value = required_string(object, key, label)?;
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!(
            "{label} field {key} contains unsupported characters"
        ));
    }
    Ok(value)
}

fn required_string(object: &Map<String, Value>, key: &str, label: &str) -> Result<String, String> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} field {key} must be a string"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(format!("{label} field {key} must be non-empty and trimmed"));
    }
    Ok(trimmed.to_owned())
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    match object.get(key) {
        None => Ok(String::new()),
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| format!("firewall rule field {key} must be a string"))?;
            if text.trim() != text {
                return Err(format!("firewall rule field {key} must be trimmed"));
            }
            Ok(text.to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_provider_vultr::VultrErrorKind;

    #[derive(Default)]
    struct FakeSupportProvider {
        ssh_keys: Vec<VultrSshKey>,
        firewall_groups: Vec<VultrFirewallGroup>,
        firewall_rules: BTreeMap<String, Vec<VultrFirewallRule>>,
        plans: Vec<VultrPlan>,
        operating_systems: Vec<VultrOperatingSystem>,
        snapshots: Vec<VultrSnapshot>,
        availability: BTreeMap<(String, String), Vec<String>>,
        ssh_create_error: Option<VultrError>,
        ssh_create_commits: bool,
        ssh_create_calls: usize,
        ssh_delete_error: Option<VultrError>,
        ssh_delete_commits: bool,
        ssh_delete_calls: usize,
        firewall_group_create_calls: usize,
        firewall_group_delete_error: Option<VultrError>,
        firewall_group_delete_commits: bool,
        firewall_group_delete_calls: usize,
        firewall_rule_create_calls: usize,
        firewall_rule_delete_calls: usize,
        next_rule_id: u64,
        firewall_rule_create_visibility_delay: usize,
        firewall_rule_create_visibility_reads: usize,
        pending_firewall_rule: Option<(String, VultrFirewallRule)>,
        firewall_rule_delete_visibility_delay: usize,
        firewall_rule_delete_visibility_reads: usize,
        pending_firewall_rule_delete: Option<(String, u64)>,
    }

    impl SupportResourceProvider for FakeSupportProvider {
        async fn list_ssh_keys(&mut self) -> Result<Vec<VultrSshKey>, VultrError> {
            Ok(self.ssh_keys.clone())
        }

        async fn create_ssh_key(
            &mut self,
            name: &str,
            public_key: &str,
        ) -> Result<VultrSshKey, VultrError> {
            self.ssh_create_calls += 1;
            let key = VultrSshKey {
                id: "ssh-1".to_owned(),
                name: name.to_owned(),
                ssh_key: public_key.to_owned(),
                date_created: String::new(),
            };
            if self.ssh_create_error.is_none() || self.ssh_create_commits {
                self.ssh_keys.push(key.clone());
            }
            match self.ssh_create_error.clone() {
                Some(err) => Err(err),
                None => Ok(key),
            }
        }

        async fn destroy_ssh_key(&mut self, ssh_key_id: &str) -> Result<(), VultrError> {
            self.ssh_delete_calls += 1;
            if self.ssh_delete_error.is_none() || self.ssh_delete_commits {
                self.ssh_keys.retain(|key| key.id != ssh_key_id);
            }
            match self.ssh_delete_error.clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        async fn list_firewall_groups(&mut self) -> Result<Vec<VultrFirewallGroup>, VultrError> {
            Ok(self.firewall_groups.clone())
        }

        async fn create_firewall_group(
            &mut self,
            description: &str,
        ) -> Result<VultrFirewallGroup, VultrError> {
            self.firewall_group_create_calls += 1;
            let group = VultrFirewallGroup {
                id: "fw-1".to_owned(),
                description: description.to_owned(),
                date_created: String::new(),
                date_modified: String::new(),
            };
            self.firewall_groups.push(group.clone());
            Ok(group)
        }

        async fn destroy_firewall_group(
            &mut self,
            firewall_group_id: &str,
        ) -> Result<(), VultrError> {
            self.firewall_group_delete_calls += 1;
            if self.firewall_group_delete_error.is_none() || self.firewall_group_delete_commits {
                self.firewall_groups
                    .retain(|group| group.id != firewall_group_id);
                self.firewall_rules.remove(firewall_group_id);
            }
            match self.firewall_group_delete_error.clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        async fn list_firewall_rules(
            &mut self,
            firewall_group_id: &str,
        ) -> Result<Vec<VultrFirewallRule>, VultrError> {
            if self
                .pending_firewall_rule
                .as_ref()
                .is_some_and(|(group_id, _)| group_id == firewall_group_id)
            {
                if self.firewall_rule_create_visibility_reads
                    >= self.firewall_rule_create_visibility_delay
                {
                    if let Some((group_id, rule)) = self.pending_firewall_rule.take() {
                        self.firewall_rules.entry(group_id).or_default().push(rule);
                    }
                } else {
                    self.firewall_rule_create_visibility_reads += 1;
                }
            }

            if self
                .pending_firewall_rule_delete
                .as_ref()
                .is_some_and(|(group_id, _)| group_id == firewall_group_id)
            {
                if self.firewall_rule_delete_visibility_reads
                    >= self.firewall_rule_delete_visibility_delay
                {
                    if let Some((group_id, rule_id)) = self.pending_firewall_rule_delete.take()
                        && let Some(rules) = self.firewall_rules.get_mut(&group_id)
                    {
                        rules.retain(|rule| rule.id != rule_id);
                    }
                } else {
                    self.firewall_rule_delete_visibility_reads += 1;
                }
            }

            Ok(self
                .firewall_rules
                .get(firewall_group_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn create_firewall_rule(
            &mut self,
            firewall_group_id: &str,
            rule: &FirewallRuleSpec,
        ) -> Result<VultrFirewallRule, VultrError> {
            self.firewall_rule_create_calls += 1;
            self.next_rule_id += 1;
            let observed = VultrFirewallRule {
                id: self.next_rule_id,
                ip_type: rule.ip_type.clone(),
                protocol: rule.protocol.clone(),
                subnet: rule.subnet.clone(),
                subnet_size: rule.subnet_size,
                port: rule.port.clone(),
                source: rule.source.clone(),
                notes: rule.notes.clone(),
            };
            if self.firewall_rule_create_visibility_delay == 0 {
                self.firewall_rules
                    .entry(firewall_group_id.to_owned())
                    .or_default()
                    .push(observed.clone());
            } else {
                self.firewall_rule_create_visibility_reads = 0;
                self.pending_firewall_rule = Some((firewall_group_id.to_owned(), observed.clone()));
            }
            Ok(observed)
        }

        async fn destroy_firewall_rule(
            &mut self,
            firewall_group_id: &str,
            firewall_rule_id: u64,
        ) -> Result<(), VultrError> {
            self.firewall_rule_delete_calls += 1;
            if self.firewall_rule_delete_visibility_delay == 0 {
                if let Some(rules) = self.firewall_rules.get_mut(firewall_group_id) {
                    rules.retain(|rule| rule.id != firewall_rule_id);
                }
            } else {
                self.firewall_rule_delete_visibility_reads = 0;
                self.pending_firewall_rule_delete =
                    Some((firewall_group_id.to_owned(), firewall_rule_id));
            }
            Ok(())
        }

        async fn list_plans(&mut self) -> Result<Vec<VultrPlan>, VultrError> {
            Ok(self.plans.clone())
        }

        async fn region_availability(
            &mut self,
            region: &str,
            plan_type: &str,
        ) -> Result<VultrRegionAvailability, VultrError> {
            Ok(VultrRegionAvailability {
                available_plans: self
                    .availability
                    .get(&(region.to_owned(), plan_type.to_owned()))
                    .cloned()
                    .unwrap_or_default(),
            })
        }

        async fn list_operating_systems(
            &mut self,
        ) -> Result<Vec<VultrOperatingSystem>, VultrError> {
            Ok(self.operating_systems.clone())
        }

        async fn list_snapshots(&mut self) -> Result<Vec<VultrSnapshot>, VultrError> {
            Ok(self.snapshots.clone())
        }
    }

    fn policy() -> LifecycleExecutionPolicy {
        LifecycleExecutionPolicy {
            create_reobserve_attempts: 2,
            destroy_reobserve_attempts: 2,
            reobserve_delay: std::time::Duration::ZERO,
        }
    }

    fn managed_instance(environment: &str, firewall_group_id: &str) -> VultrInstance {
        VultrInstance {
            id: "instance-1".to_owned(),
            label: "edge-1".to_owned(),
            region: "waw".to_owned(),
            plan: "vc2-1c-1gb".to_owned(),
            status: "active".to_owned(),
            server_status: "ok".to_owned(),
            power_status: "running".to_owned(),
            main_ip: "203.0.113.10".to_owned(),
            v6_main_ip: String::new(),
            firewall_group_id: firewall_group_id.to_owned(),
            date_created: String::new(),
            tags: vec![
                "managed-by-sing-box".to_owned(),
                format!("singbox-env-{environment}"),
                "singbox-id-edge-1".to_owned(),
                format!("singbox-spec-{}", "0".repeat(64)),
            ],
            os_id: 2625,
            snapshot_id: None,
            enable_ipv6: false,
        }
    }

    fn uncertain(operation: &'static str) -> VultrError {
        VultrError {
            operation,
            kind: VultrErrorKind::MutationUncertain,
            status: None,
            retry_after_secs: None,
            detail: "simulated response loss".to_owned(),
        }
    }

    fn profiles() -> FirewallProfileSet {
        FirewallProfileSet::parse_json(
            r#"{
  "schema": 1,
  "profiles": [
    {
      "name": "ssh-only",
      "rules": [
        {
          "ip_type": "v4",
          "protocol": "tcp",
          "subnet": "203.0.113.10",
          "subnet_size": 32,
          "port": "22",
          "notes": "managed ssh"
        }
      ]
    }
  ]
}"#,
        )
        .unwrap()
    }

    #[test]
    fn provider_derived_cidr_source_is_not_independent_rule_identity() {
        let rule = VultrFirewallRule {
            id: 1,
            ip_type: "v4".to_owned(),
            protocol: "tcp".to_owned(),
            subnet: "203.0.113.10".to_owned(),
            subnet_size: 32,
            port: "22".to_owned(),
            source: "203.0.113.10/32".to_owned(),
            notes: "managed ssh".to_owned(),
        };
        let normalized = firewall_rule_spec(&rule).unwrap();
        assert_eq!(normalized.source, "");
        assert_eq!(normalized.subnet, "203.0.113.10");
        assert_eq!(normalized.subnet_size, 32);
    }

    #[test]
    fn special_firewall_source_remains_significant_identity() {
        let rule = VultrFirewallRule {
            id: 1,
            ip_type: "v4".to_owned(),
            protocol: "tcp".to_owned(),
            subnet: "0.0.0.0".to_owned(),
            subnet_size: 0,
            port: "443".to_owned(),
            source: "cloudflare".to_owned(),
            notes: String::new(),
        };
        let normalized = firewall_rule_spec(&rule).unwrap();
        assert_eq!(normalized.source, "cloudflare");
    }

    #[test]
    fn firewall_profiles_reject_unknown_fields_and_duplicates() {
        let unknown = r#"{"schema":1,"profiles":[],"extra":true}"#;
        assert!(FirewallProfileSet::parse_json(unknown).is_err());

        let duplicate = r#"{
          "schema":1,
          "profiles":[
            {"name":"same","rules":[]},
            {"name":"same","rules":[]}
          ]
        }"#;
        assert!(FirewallProfileSet::parse_json(duplicate).is_err());
    }

    #[test]
    fn public_key_identity_ignores_comment_but_not_material() {
        let first = public_key_material(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSsamKBL5VmXVJM4R1WXVXl3yvvExG5u9SAlZyItrRr comment-a",
        )
        .unwrap();
        let second = public_key_material(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSsamKBL5VmXVJM4R1WXVXl3yvvExG5u9SAlZyItrRr comment-b",
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn resolves_existing_exact_managed_ssh_key_without_mutation() {
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSsamKBL5VmXVJM4R1WXVXl3yvvExG5u9SAlZyItrRr canonical";
        let mut provider = FakeSupportProvider {
            ssh_keys: vec![VultrSshKey {
                id: "ssh-existing".to_owned(),
                name: "singbox-production-ops".to_owned(),
                ssh_key: public_key.to_owned(),
                date_created: String::new(),
            }],
            ..FakeSupportProvider::default()
        };

        let resolved = resolve_managed_ssh_key(&mut provider, "production", public_key, &policy())
            .await
            .unwrap();

        assert_eq!(resolved.id, "ssh-existing");
        assert_eq!(provider.ssh_create_calls, 0);
    }

    #[tokio::test]
    async fn uncertain_ssh_create_reobserves_without_replay() {
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSsamKBL5VmXVJM4R1WXVXl3yvvExG5u9SAlZyItrRr canonical";
        let mut provider = FakeSupportProvider {
            ssh_create_error: Some(uncertain("create Vultr SSH key")),
            ssh_create_commits: true,
            ..FakeSupportProvider::default()
        };

        let resolved = resolve_managed_ssh_key(&mut provider, "production", public_key, &policy())
            .await
            .unwrap();

        assert_eq!(resolved.id, "ssh-1");
        assert_eq!(provider.ssh_create_calls, 1);
    }

    #[tokio::test]
    async fn managed_ssh_name_with_wrong_material_fails_closed() {
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSsamKBL5VmXVJM4R1WXVXl3yvvExG5u9SAlZyItrRr canonical";
        let mut provider = FakeSupportProvider {
            ssh_keys: vec![VultrSshKey {
                id: "ssh-conflict".to_owned(),
                name: "singbox-production-ops".to_owned(),
                ssh_key: "ssh-ed25519 AAAAwrong conflict".to_owned(),
                date_created: String::new(),
            }],
            ..FakeSupportProvider::default()
        };

        let error = resolve_managed_ssh_key(&mut provider, "production", public_key, &policy())
            .await
            .unwrap_err();
        assert!(error.contains("different public key material"));
        assert_eq!(provider.ssh_create_calls, 0);
    }

    #[tokio::test]
    async fn firewall_profile_create_and_reconcile_converges_exactly() {
        let profile_set = profiles();
        let profile = profile_set.profile("ssh-only").unwrap();
        let mut provider = FakeSupportProvider::default();

        let resolved = ensure_firewall_profile(&mut provider, "production", profile, &policy())
            .await
            .unwrap();

        assert_eq!(resolved.id, "fw-1");
        assert_eq!(provider.firewall_group_create_calls, 1);
        assert_eq!(provider.firewall_rule_create_calls, 1);
        assert!(
            firewall_rules_match(profile, provider.firewall_rules.get("fw-1").unwrap()).unwrap()
        );
    }

    #[tokio::test]
    async fn firewall_create_waits_for_visibility_without_duplicate_mutation() {
        let profile_set = profiles();
        let profile = profile_set.profile("ssh-only").unwrap();
        let mut provider = FakeSupportProvider {
            firewall_rule_create_visibility_delay: 1,
            ..FakeSupportProvider::default()
        };

        ensure_firewall_profile(&mut provider, "production", profile, &policy())
            .await
            .unwrap();

        assert_eq!(provider.firewall_rule_create_calls, 1);
        assert!(
            firewall_rules_match(profile, provider.firewall_rules.get("fw-1").unwrap()).unwrap()
        );
    }

    #[tokio::test]
    async fn firewall_delete_waits_for_absence_before_next_mutation() {
        let profile_set = profiles();
        let profile = profile_set.profile("ssh-only").unwrap();
        let mut provider = FakeSupportProvider {
            firewall_groups: vec![VultrFirewallGroup {
                id: "fw-1".to_owned(),
                description: "singbox-production-fw-ssh-only".to_owned(),
                date_created: String::new(),
                date_modified: String::new(),
            }],
            firewall_rules: BTreeMap::from([(
                "fw-1".to_owned(),
                vec![VultrFirewallRule {
                    id: 1,
                    ip_type: "v4".to_owned(),
                    protocol: "tcp".to_owned(),
                    subnet: "192.0.2.1".to_owned(),
                    subnet_size: 32,
                    port: "22".to_owned(),
                    source: String::new(),
                    notes: "wrong".to_owned(),
                }],
            )]),
            next_rule_id: 1,
            firewall_rule_delete_visibility_delay: 1,
            ..FakeSupportProvider::default()
        };

        ensure_firewall_profile(&mut provider, "production", profile, &policy())
            .await
            .unwrap();

        assert_eq!(provider.firewall_rule_delete_calls, 1);
        assert_eq!(provider.firewall_rule_create_calls, 1);
        assert!(
            firewall_rules_match(profile, provider.firewall_rules.get("fw-1").unwrap()).unwrap()
        );
    }

    #[tokio::test]
    async fn firewall_reconcile_removes_unowned_rule_inside_owned_group() {
        let profile_set = profiles();
        let profile = profile_set.profile("ssh-only").unwrap();
        let mut provider = FakeSupportProvider {
            firewall_groups: vec![VultrFirewallGroup {
                id: "fw-1".to_owned(),
                description: "singbox-production-fw-ssh-only".to_owned(),
                date_created: String::new(),
                date_modified: String::new(),
            }],
            firewall_rules: BTreeMap::from([(
                "fw-1".to_owned(),
                vec![VultrFirewallRule {
                    id: 1,
                    ip_type: "v4".to_owned(),
                    protocol: "tcp".to_owned(),
                    subnet: "192.0.2.1".to_owned(),
                    subnet_size: 32,
                    port: "22".to_owned(),
                    source: String::new(),
                    notes: "wrong".to_owned(),
                }],
            )]),
            next_rule_id: 1,
            ..FakeSupportProvider::default()
        };

        ensure_firewall_profile(&mut provider, "production", profile, &policy())
            .await
            .unwrap();

        assert_eq!(provider.firewall_rule_delete_calls, 1);
        assert_eq!(provider.firewall_rule_create_calls, 1);
        assert!(
            firewall_rules_match(profile, provider.firewall_rules.get("fw-1").unwrap()).unwrap()
        );
    }

    #[tokio::test]
    async fn controller_access_release_removes_only_exact_dynamic_rule() {
        let profile_set = FirewallProfileSet::parse_json(
            r#"{
              "schema":1,
              "profiles":[{
                "name":"edge-access",
                "rules":[
                  {
                    "ip_type":"v4",
                    "protocol":"tcp",
                    "subnet":"@controller-ipv4",
                    "subnet_size":32,
                    "port":"22",
                    "notes":"ephemeral controller SSH"
                  },
                  {
                    "ip_type":"v4",
                    "protocol":"tcp",
                    "subnet":"0.0.0.0",
                    "subnet_size":0,
                    "port":"443",
                    "notes":"public service"
                  }
                ]
              }]
            }"#,
        )
        .unwrap();
        let profile = profile_set.profile("edge-access").unwrap();
        let mut provider = FakeSupportProvider {
            firewall_groups: vec![VultrFirewallGroup {
                id: "fw-1".to_owned(),
                description: "singbox-production-fw-edge-access".to_owned(),
                date_created: String::new(),
                date_modified: String::new(),
            }],
            firewall_rules: BTreeMap::from([(
                "fw-1".to_owned(),
                vec![
                    VultrFirewallRule {
                        id: 11,
                        ip_type: "v4".to_owned(),
                        protocol: "tcp".to_owned(),
                        subnet: "203.0.113.25".to_owned(),
                        subnet_size: 32,
                        port: "22".to_owned(),
                        source: String::new(),
                        notes: "provider-side note drift must not keep SSH open".to_owned(),
                    },
                    VultrFirewallRule {
                        id: 12,
                        ip_type: "v4".to_owned(),
                        protocol: "tcp".to_owned(),
                        subnet: "0.0.0.0".to_owned(),
                        subnet_size: 0,
                        port: "443".to_owned(),
                        source: String::new(),
                        notes: "public service".to_owned(),
                    },
                ],
            )]),
            ..FakeSupportProvider::default()
        };

        let report = release_controller_ipv4_access(
            &mut provider,
            "production",
            profile,
            "203.0.113.25",
            &policy(),
        )
        .await
        .unwrap();

        assert!(report.verified_absent);
        assert_eq!(report.removed_rule_ids, vec![11]);
        let remaining = provider.firewall_rules.get("fw-1").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, 12);
        assert_eq!(provider.firewall_rule_delete_calls, 1);
    }

    #[test]
    fn resolves_controller_ipv4_placeholder_exactly() {
        let mut profile_set = FirewallProfileSet::parse_json(
            r#"{
              "schema":1,
              "profiles":[{
                "name":"acceptance-ssh",
                "rules":[{
                  "ip_type":"v4",
                  "protocol":"tcp",
                  "subnet":"@controller-ipv4",
                  "subnet_size":32,
                  "port":"22"
                }]
              }]
            }"#,
        )
        .unwrap();
        profile_set
            .resolve_controller_ipv4_for_profiles(
                &["acceptance-ssh".to_owned()],
                Some("203.0.113.25"),
            )
            .unwrap();
        assert_eq!(
            profile_set.profile("acceptance-ssh").unwrap().rules[0].subnet,
            "203.0.113.25"
        );
    }

    #[tokio::test]
    async fn cleanup_refuses_shared_resources_while_environment_is_in_use() {
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSsamKBL5VmXVJM4R1WXVXl3yvvExG5u9SAlZyItrRr canonical";
        let desired = DesiredState::parse_json(
            r#"{
              "schema":1,
              "environment":"production",
              "machines":[{
                "id":"edge-1",
                "role":"edge",
                "provider":{"region":"waw","plan":"vc2-1c-1gb","os_id":2625,"enable_ipv6":false},
                "bootstrap_profile":"singbox-host-v1"
              }]
            }"#,
        )
        .unwrap();
        let mut provider = FakeSupportProvider {
            ssh_keys: vec![VultrSshKey {
                id: "ssh-1".to_owned(),
                name: "singbox-production-ops".to_owned(),
                ssh_key: public_key.to_owned(),
                date_created: String::new(),
            }],
            ..FakeSupportProvider::default()
        };

        let report = cleanup_environment_support_resources(
            &mut provider,
            &desired,
            &[managed_instance("production", "")],
            public_key,
            &policy(),
        )
        .await
        .unwrap();

        assert!(report.environment_in_use);
        assert_eq!(provider.ssh_delete_calls, 0);
        assert_eq!(provider.firewall_group_delete_calls, 0);
    }

    #[tokio::test]
    async fn cleanup_removes_owned_resources_once_after_environment_is_absent() {
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSsamKBL5VmXVJM4R1WXVXl3yvvExG5u9SAlZyItrRr canonical";
        let desired = DesiredState::parse_json(
            r#"{
              "schema":1,
              "environment":"acceptance",
              "machines":[{
                "id":"edge-1",
                "role":"edge",
                "provider":{"region":"waw","plan":"vc2-1c-1gb","os_id":2625,"enable_ipv6":false},
                "bootstrap_profile":"singbox-host-v1"
              }]
            }"#,
        )
        .unwrap();
        let mut provider = FakeSupportProvider {
            ssh_keys: vec![VultrSshKey {
                id: "ssh-1".to_owned(),
                name: "singbox-acceptance-ops".to_owned(),
                ssh_key: public_key.to_owned(),
                date_created: String::new(),
            }],
            firewall_groups: vec![VultrFirewallGroup {
                id: "fw-1".to_owned(),
                description: "singbox-acceptance-fw-ssh-only".to_owned(),
                date_created: String::new(),
                date_modified: String::new(),
            }],
            ..FakeSupportProvider::default()
        };

        let report = cleanup_environment_support_resources(
            &mut provider,
            &desired,
            &[],
            public_key,
            &policy(),
        )
        .await
        .unwrap();

        assert!(!report.environment_in_use);
        assert!(report.ssh_key_removed);
        assert_eq!(report.firewall_groups_removed, vec!["fw-1".to_owned()]);
        assert_eq!(provider.ssh_delete_calls, 1);
        assert_eq!(provider.firewall_group_delete_calls, 1);
    }

    #[tokio::test]
    async fn uncertain_cleanup_delete_reobserves_without_replay() {
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSsamKBL5VmXVJM4R1WXVXl3yvvExG5u9SAlZyItrRr canonical";
        let desired = DesiredState::parse_json(
            r#"{
              "schema":1,
              "environment":"acceptance",
              "machines":[{
                "id":"edge-1",
                "role":"edge",
                "provider":{"region":"waw","plan":"vc2-1c-1gb","os_id":2625,"enable_ipv6":false},
                "bootstrap_profile":"singbox-host-v1"
              }]
            }"#,
        )
        .unwrap();
        let mut provider = FakeSupportProvider {
            ssh_keys: vec![VultrSshKey {
                id: "ssh-1".to_owned(),
                name: "singbox-acceptance-ops".to_owned(),
                ssh_key: public_key.to_owned(),
                date_created: String::new(),
            }],
            ssh_delete_error: Some(uncertain("destroy Vultr SSH key")),
            ssh_delete_commits: true,
            ..FakeSupportProvider::default()
        };

        cleanup_environment_support_resources(&mut provider, &desired, &[], public_key, &policy())
            .await
            .unwrap();

        assert_eq!(provider.ssh_delete_calls, 1);
        assert!(provider.ssh_keys.is_empty());
    }

    #[tokio::test]
    async fn catalog_validation_checks_plan_region_and_os() {
        let desired = DesiredState::parse_json(
            r#"{
              "schema":1,
              "environment":"production",
              "machines":[{
                "id":"edge-1",
                "role":"edge",
                "provider":{
                  "region":"waw",
                  "plan":"vc2-1c-1gb",
                  "os_id":2625,
                  "enable_ipv6":false
                },
                "bootstrap_profile":"singbox-host-v1"
              }]
            }"#,
        )
        .unwrap();
        let mut provider = FakeSupportProvider {
            plans: vec![VultrPlan {
                id: "vc2-1c-1gb".to_owned(),
                plan_type: "vc2".to_owned(),
            }],
            availability: BTreeMap::from([(
                ("waw".to_owned(), "vc2".to_owned()),
                vec!["vc2-1c-1gb".to_owned()],
            )]),
            operating_systems: vec![VultrOperatingSystem {
                id: 2625,
                name: "Debian 13 x64".to_owned(),
                arch: "x64".to_owned(),
                family: "debian".to_owned(),
            }],
            ..FakeSupportProvider::default()
        };

        validate_machine_catalog(&mut provider, &desired.machines[0])
            .await
            .unwrap();
    }
}
