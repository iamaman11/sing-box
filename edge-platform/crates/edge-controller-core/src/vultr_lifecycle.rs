use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

pub const SUPPORTED_SCHEMA: u32 = 1;
pub const MANAGED_BY_IDENTITY: &str = "sing-box";
pub const MANAGED_BY_TAG: &str = "managed-by-sing-box";
pub const ENVIRONMENT_TAG_PREFIX: &str = "singbox-env-";
pub const LOGICAL_ID_TAG_PREFIX: &str = "singbox-id-";
pub const SPEC_DIGEST_TAG_PREFIX: &str = "singbox-spec-";
pub const FIREWALL_PROFILE_TAG_PREFIX: &str = "singbox-fw-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredState {
    pub schema: u32,
    pub environment: String,
    pub machines: Vec<MachineSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSpec {
    pub id: String,
    pub role: String,
    pub provider: ProviderSpec,
    pub bootstrap_profile: String,
    #[serde(default)]
    pub application_profiles: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSpec {
    pub region: String,
    pub plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    pub enable_ipv6: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleSpecError {
    Json(String),
    UnsupportedSchema(u32),
    Validation(String),
    Serialization(String),
}

impl fmt::Display for LifecycleSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(detail) => write!(f, "invalid desired-state JSON: {detail}"),
            Self::UnsupportedSchema(schema) => {
                write!(f, "unsupported desired-state schema {schema}")
            }
            Self::Validation(detail) => write!(f, "invalid desired state: {detail}"),
            Self::Serialization(detail) => {
                write!(f, "failed to canonicalize desired state: {detail}")
            }
        }
    }
}

impl Error for LifecycleSpecError {}

impl DesiredState {
    pub fn parse_json(raw: &str) -> Result<Self, LifecycleSpecError> {
        let desired: Self =
            serde_json::from_str(raw).map_err(|err| LifecycleSpecError::Json(err.to_string()))?;
        desired.validate()?;
        Ok(desired)
    }

    pub fn validate(&self) -> Result<(), LifecycleSpecError> {
        if self.schema != SUPPORTED_SCHEMA {
            return Err(LifecycleSpecError::UnsupportedSchema(self.schema));
        }
        validate_identifier("environment", &self.environment)?;

        let mut machine_ids = BTreeSet::new();
        for machine in &self.machines {
            machine.validate()?;
            if !machine_ids.insert(machine.id.as_str()) {
                return Err(LifecycleSpecError::Validation(format!(
                    "duplicate machine id {}",
                    machine.id
                )));
            }
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<String, LifecycleSpecError> {
        self.validate()?;
        let mut normalized = self.clone();
        normalized
            .machines
            .sort_by(|left, right| left.id.cmp(&right.id));
        for machine in &mut normalized.machines {
            machine.tags.sort();
        }
        canonical_json(&normalized)
    }

    pub fn digest(&self) -> Result<String, LifecycleSpecError> {
        Ok(sha256_hex(self.canonical_json()?.as_bytes()))
    }

    pub fn machine_digest(&self, machine: &MachineSpec) -> Result<String, LifecycleSpecError> {
        self.validate()?;
        if !self
            .machines
            .iter()
            .any(|candidate| candidate.id == machine.id)
        {
            return Err(LifecycleSpecError::Validation(format!(
                "machine {} is not part of desired state",
                machine.id
            )));
        }

        let mut normalized = machine.clone();
        normalized.tags.sort();
        let value = serde_json::json!({
            "schema": self.schema,
            "environment": self.environment,
            "machine": normalized,
        });
        Ok(sha256_hex(canonical_json_value(&value).as_bytes()))
    }
}

impl MachineSpec {
    fn validate(&self) -> Result<(), LifecycleSpecError> {
        validate_identifier("machine id", &self.id)?;
        validate_identifier("role", &self.role)?;
        validate_identifier("bootstrap profile", &self.bootstrap_profile)?;
        self.provider.validate(&self.id)?;

        validate_unique_strings(
            &format!("machine {} application_profiles", self.id),
            &self.application_profiles,
            true,
        )?;
        validate_user_tags(&self.id, &self.tags)?;
        Ok(())
    }
}

impl ProviderSpec {
    fn validate(&self, machine_id: &str) -> Result<(), LifecycleSpecError> {
        validate_identifier(&format!("machine {machine_id} region"), &self.region)?;
        validate_identifier(&format!("machine {machine_id} plan"), &self.plan)?;

        match (self.os_id, self.snapshot_id.as_deref()) {
            (Some(0), _) => {
                return Err(LifecycleSpecError::Validation(format!(
                    "machine {machine_id} os_id must be greater than zero"
                )));
            }
            (Some(_), Some(_)) => {
                return Err(LifecycleSpecError::Validation(format!(
                    "machine {machine_id} must select exactly one of os_id or snapshot_id"
                )));
            }
            (None, None) => {
                return Err(LifecycleSpecError::Validation(format!(
                    "machine {machine_id} must select exactly one of os_id or snapshot_id"
                )));
            }
            (None, Some(snapshot_id)) => {
                validate_identifier(&format!("machine {machine_id} snapshot_id"), snapshot_id)?;
            }
            (Some(_), None) => {}
        }

        if let Some(firewall_profile) = self.firewall_profile.as_deref() {
            validate_identifier(
                &format!("machine {machine_id} firewall_profile"),
                firewall_profile,
            )?;
        }
        Ok(())
    }
}

fn validate_identifier(label: &str, value: &str) -> Result<(), LifecycleSpecError> {
    if value.is_empty() || value.trim() != value {
        return Err(LifecycleSpecError::Validation(format!(
            "{label} must be non-empty and must not contain leading/trailing whitespace"
        )));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(LifecycleSpecError::Validation(format!(
            "{label} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_unique_strings(
    label: &str,
    values: &[String],
    identifiers: bool,
) -> Result<(), LifecycleSpecError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if identifiers {
            validate_identifier(label, value)?;
        } else if value.is_empty() || value.trim() != value {
            return Err(LifecycleSpecError::Validation(format!(
                "{label} entries must be non-empty and trimmed"
            )));
        }
        if !seen.insert(value.as_str()) {
            return Err(LifecycleSpecError::Validation(format!(
                "{label} contains duplicate value {value}"
            )));
        }
    }
    Ok(())
}

fn validate_user_tags(machine_id: &str, tags: &[String]) -> Result<(), LifecycleSpecError> {
    validate_unique_strings(&format!("machine {machine_id} tags"), tags, true)?;
    for tag in tags {
        if tag == MANAGED_BY_TAG
            || tag.starts_with(ENVIRONMENT_TAG_PREFIX)
            || tag.starts_with(LOGICAL_ID_TAG_PREFIX)
            || tag.starts_with(SPEC_DIGEST_TAG_PREFIX)
            || tag.starts_with(FIREWALL_PROFILE_TAG_PREFIX)
        {
            return Err(LifecycleSpecError::Validation(format!(
                "machine {machine_id} tag {tag} uses the reserved lifecycle namespace"
            )));
        }
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, LifecycleSpecError> {
    let value = serde_json::to_value(value)
        .map_err(|err| LifecycleSpecError::Serialization(err.to_string()))?;
    Ok(canonical_json_value(&value))
}

fn canonical_json_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => {
            serde_json::to_string(value).expect("serializing a JSON string to a string cannot fail")
        }
        Value::Array(values) => {
            let body = values
                .iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let body = entries
                .into_iter()
                .map(|(key, value)| {
                    let key = serde_json::to_string(key)
                        .expect("serializing a JSON object key cannot fail");
                    format!("{key}:{}", canonical_json_value(value))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hash = digest(&SHA256, bytes);
    let mut output = String::with_capacity(hash.as_ref().len() * 2);
    for byte in hash.as_ref() {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedOwnership {
    pub managed_by: Option<String>,
    pub environment: Option<String>,
    pub logical_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedMachine {
    pub provider_id: String,
    pub label: String,
    pub ownership: ObservedOwnership,
    pub region: String,
    pub plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6_main_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    pub enable_ipv6: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_profile: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleInventory {
    pub resources: Vec<ObservedMachine>,
    pub orphaned_managed_provider_ids: Vec<String>,
}

pub fn build_inventory(
    desired: &DesiredState,
    mut resources: Vec<ObservedMachine>,
) -> LifecycleInventory {
    resources.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    let desired_ids = desired
        .machines
        .iter()
        .map(|machine| machine.id.as_str())
        .collect::<BTreeSet<_>>();

    let orphaned_managed_provider_ids = resources
        .iter()
        .filter(|resource| {
            resource.ownership.managed_by.as_deref() == Some(MANAGED_BY_IDENTITY)
                && resource.ownership.environment.as_deref() == Some(desired.environment.as_str())
                && resource
                    .ownership
                    .logical_id
                    .as_deref()
                    .is_some_and(|logical_id| !desired_ids.contains(logical_id))
        })
        .map(|resource| resource.provider_id.clone())
        .collect();

    LifecycleInventory {
        resources,
        orphaned_managed_provider_ids,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanClass {
    Noop,
    Create,
    UpdateInPlace,
    ReplaceRequired,
    BlockedDrift,
    BlockedAmbiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachinePlan {
    pub machine_id: String,
    pub class: PlanClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    pub desired_spec_digest: String,
    pub reasons: Vec<String>,
}

pub fn plan_all(
    desired: &DesiredState,
    inventory: &LifecycleInventory,
) -> Result<Vec<MachinePlan>, LifecycleSpecError> {
    desired.validate()?;
    let mut machines = desired.machines.iter().collect::<Vec<_>>();
    machines.sort_by(|left, right| left.id.cmp(&right.id));
    machines
        .into_iter()
        .map(|machine| plan_machine(desired, machine, inventory))
        .collect()
}

pub fn plan_machine(
    desired: &DesiredState,
    machine: &MachineSpec,
    inventory: &LifecycleInventory,
) -> Result<MachinePlan, LifecycleSpecError> {
    let desired_digest = desired.machine_digest(machine)?;
    let mut exact_owned = inventory
        .resources
        .iter()
        .filter(|resource| ownership_matches(desired, machine, resource))
        .collect::<Vec<_>>();
    exact_owned.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));

    if exact_owned.len() > 1 {
        return Ok(MachinePlan {
            machine_id: machine.id.clone(),
            class: PlanClass::BlockedAmbiguous,
            provider_id: None,
            desired_spec_digest: desired_digest,
            reasons: vec![format!(
                "multiple exact owned resources match logical id {}: {}",
                machine.id,
                exact_owned
                    .iter()
                    .map(|resource| resource.provider_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )],
        });
    }

    let Some(observed) = exact_owned.first().copied() else {
        let mut conflicts = inventory
            .resources
            .iter()
            .filter(|resource| identity_conflicts(desired, machine, resource))
            .map(|resource| resource.provider_id.as_str())
            .collect::<Vec<_>>();
        conflicts.sort_unstable();
        conflicts.dedup();

        if conflicts.is_empty() {
            return Ok(MachinePlan {
                machine_id: machine.id.clone(),
                class: PlanClass::Create,
                provider_id: None,
                desired_spec_digest: desired_digest,
                reasons: vec!["no exact owned provider resource exists".to_owned()],
            });
        }

        return Ok(MachinePlan {
            machine_id: machine.id.clone(),
            class: PlanClass::BlockedDrift,
            provider_id: None,
            desired_spec_digest: desired_digest,
            reasons: vec![format!(
                "provider resources conflict with logical identity {}: {}",
                machine.id,
                conflicts.join(", ")
            )],
        });
    };

    if observed.provider_id.trim().is_empty() {
        return Ok(MachinePlan {
            machine_id: machine.id.clone(),
            class: PlanClass::BlockedDrift,
            provider_id: None,
            desired_spec_digest: desired_digest,
            reasons: vec!["exact owned resource has an empty provider id".to_owned()],
        });
    }

    if observed.os_id.is_none() && observed.snapshot_id.is_none() {
        return Ok(MachinePlan {
            machine_id: machine.id.clone(),
            class: PlanClass::BlockedDrift,
            provider_id: Some(observed.provider_id.clone()),
            desired_spec_digest: desired_digest,
            reasons: vec!["observed provider image identity is missing".to_owned()],
        });
    }

    let mut replacement_reasons = Vec::new();
    if observed.region != machine.provider.region {
        replacement_reasons.push(format!(
            "region differs: desired={} observed={}",
            machine.provider.region, observed.region
        ));
    }
    if observed.plan != machine.provider.plan {
        replacement_reasons.push(format!(
            "plan differs: desired={} observed={}",
            machine.provider.plan, observed.plan
        ));
    }
    let image_matches = match (
        machine.provider.os_id,
        machine.provider.snapshot_id.as_deref(),
    ) {
        (Some(expected_os_id), None) => {
            observed.snapshot_id.is_none() && observed.os_id == Some(expected_os_id)
        }
        (None, Some(expected_snapshot_id)) => {
            observed.snapshot_id.as_deref() == Some(expected_snapshot_id)
        }
        _ => false,
    };
    if !image_matches {
        replacement_reasons.push("provider image identity differs".to_owned());
    }
    if observed.enable_ipv6 != machine.provider.enable_ipv6 {
        replacement_reasons.push(format!(
            "IPv6 policy differs: desired={} observed={}",
            machine.provider.enable_ipv6, observed.enable_ipv6
        ));
    }

    if !replacement_reasons.is_empty() {
        return Ok(MachinePlan {
            machine_id: machine.id.clone(),
            class: PlanClass::ReplaceRequired,
            provider_id: Some(observed.provider_id.clone()),
            desired_spec_digest: desired_digest,
            reasons: replacement_reasons,
        });
    }

    let mut update_reasons = Vec::new();
    if observed.label != machine.id {
        update_reasons.push(format!(
            "label differs: desired={} observed={}",
            machine.id, observed.label
        ));
    }
    if observed.firewall_profile != machine.provider.firewall_profile {
        update_reasons.push("firewall profile differs".to_owned());
    }

    let mut desired_tags = machine.tags.clone();
    desired_tags.sort();
    let mut observed_tags = observed.tags.clone();
    observed_tags.sort();
    if desired_tags != observed_tags {
        update_reasons.push("managed tags differ".to_owned());
    }
    if observed.spec_digest.as_deref() != Some(desired_digest.as_str()) {
        update_reasons.push("managed spec digest differs".to_owned());
    }

    let class = if update_reasons.is_empty() {
        PlanClass::Noop
    } else {
        PlanClass::UpdateInPlace
    };
    Ok(MachinePlan {
        machine_id: machine.id.clone(),
        class,
        provider_id: Some(observed.provider_id.clone()),
        desired_spec_digest: desired_digest,
        reasons: update_reasons,
    })
}

fn ownership_matches(
    desired: &DesiredState,
    machine: &MachineSpec,
    resource: &ObservedMachine,
) -> bool {
    resource.ownership.managed_by.as_deref() == Some(MANAGED_BY_IDENTITY)
        && resource.ownership.environment.as_deref() == Some(desired.environment.as_str())
        && resource.ownership.logical_id.as_deref() == Some(machine.id.as_str())
}

fn identity_conflicts(
    desired: &DesiredState,
    machine: &MachineSpec,
    resource: &ObservedMachine,
) -> bool {
    if resource.label == machine.id {
        return true;
    }
    if resource.ownership.logical_id.as_deref() == Some(machine.id.as_str()) {
        return true;
    }
    resource.ownership.managed_by.as_deref() == Some(MANAGED_BY_IDENTITY)
        && resource.ownership.environment.as_deref() == Some(desired.environment.as_str())
        && resource.label == machine.id
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderIdentityError {
    DuplicateLifecycleTag(&'static str),
    InvalidLifecycleTag(String),
    IncompleteManagedIdentity,
}

impl fmt::Display for ProviderIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateLifecycleTag(kind) => {
                write!(f, "provider instance has multiple {kind} lifecycle tags")
            }
            Self::InvalidLifecycleTag(tag) => write!(f, "invalid lifecycle tag {tag}"),
            Self::IncompleteManagedIdentity => {
                write!(f, "provider instance has incomplete managed lifecycle identity")
            }
        }
    }
}

impl Error for ProviderIdentityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedProviderTags {
    pub ownership: ObservedOwnership,
    pub spec_digest: Option<String>,
    pub firewall_profile: Option<String>,
    pub user_tags: Vec<String>,
}

pub fn provider_tags_for_machine(
    desired: &DesiredState,
    machine: &MachineSpec,
) -> Result<Vec<String>, LifecycleSpecError> {
    desired.validate()?;
    let spec_digest = desired.machine_digest(machine)?;
    let mut tags = vec![
        MANAGED_BY_TAG.to_owned(),
        format!("{ENVIRONMENT_TAG_PREFIX}{}", desired.environment),
        format!("{LOGICAL_ID_TAG_PREFIX}{}", machine.id),
        format!("{SPEC_DIGEST_TAG_PREFIX}{spec_digest}"),
    ];
    if let Some(profile) = machine.provider.firewall_profile.as_deref() {
        tags.push(format!("{FIREWALL_PROFILE_TAG_PREFIX}{profile}"));
    }
    tags.extend(machine.tags.iter().cloned());
    tags.sort();
    Ok(tags)
}

pub fn decode_provider_tags(tags: &[String]) -> Result<DecodedProviderTags, ProviderIdentityError> {
    let mut managed = false;
    let mut environment = None;
    let mut logical_id = None;
    let mut spec_digest = None;
    let mut firewall_profile = None;
    let mut user_tags = Vec::new();

    for tag in tags {
        if tag == MANAGED_BY_TAG {
            if managed {
                return Err(ProviderIdentityError::DuplicateLifecycleTag("managed-by"));
            }
            managed = true;
            continue;
        }
        if let Some(value) = tag.strip_prefix(ENVIRONMENT_TAG_PREFIX) {
            set_lifecycle_value("environment", tag, value, &mut environment)?;
            continue;
        }
        if let Some(value) = tag.strip_prefix(LOGICAL_ID_TAG_PREFIX) {
            set_lifecycle_value("logical-id", tag, value, &mut logical_id)?;
            continue;
        }
        if let Some(value) = tag.strip_prefix(SPEC_DIGEST_TAG_PREFIX) {
            if spec_digest.is_some() {
                return Err(ProviderIdentityError::DuplicateLifecycleTag("spec-digest"));
            }
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ProviderIdentityError::InvalidLifecycleTag(tag.clone()));
            }
            spec_digest = Some(value.to_owned());
            continue;
        }
        if let Some(value) = tag.strip_prefix(FIREWALL_PROFILE_TAG_PREFIX) {
            set_lifecycle_value("firewall-profile", tag, value, &mut firewall_profile)?;
            continue;
        }
        user_tags.push(tag.clone());
    }

    let any_lifecycle_identity =
        managed || environment.is_some() || logical_id.is_some() || spec_digest.is_some();
    if any_lifecycle_identity && !(managed && environment.is_some() && logical_id.is_some()) {
        return Err(ProviderIdentityError::IncompleteManagedIdentity);
    }

    user_tags.sort();
    Ok(DecodedProviderTags {
        ownership: ObservedOwnership {
            managed_by: managed.then(|| MANAGED_BY_IDENTITY.to_owned()),
            environment,
            logical_id,
        },
        spec_digest,
        firewall_profile,
        user_tags,
    })
}

fn set_lifecycle_value(
    kind: &'static str,
    raw_tag: &str,
    value: &str,
    slot: &mut Option<String>,
) -> Result<(), ProviderIdentityError> {
    if slot.is_some() {
        return Err(ProviderIdentityError::DuplicateLifecycleTag(kind));
    }
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(ProviderIdentityError::InvalidLifecycleTag(
            raw_tag.to_owned(),
        ));
    }
    *slot = Some(value.to_owned());
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestroyPlan {
    pub machine_id: String,
    pub provider_id: String,
    pub label: String,
    pub source_revision: String,
    pub region: String,
    pub plan: String,
    pub os_id: Option<u32>,
    pub snapshot_id: Option<String>,
    pub main_ip: Option<String>,
    pub v6_main_ip: Option<String>,
    pub firewall_group_id: Option<String>,
    pub date_created: Option<String>,
    pub observed_spec_digest: Option<String>,
    pub destroy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestroyAuthorityError {
    Spec(LifecycleSpecError),
    InvalidSourceRevision,
    Absent,
    Ambiguous,
    StaleDigest { expected: String, actual: String },
}

impl fmt::Display for DestroyAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spec(err) => err.fmt(f),
            Self::InvalidSourceRevision => {
                write!(f, "source revision must be a 40 or 64 character lowercase hex digest")
            }
            Self::Absent => write!(f, "exact owned provider resource is absent"),
            Self::Ambiguous => write!(f, "multiple exact owned provider resources exist"),
            Self::StaleDigest { expected, actual } => write!(
                f,
                "destroy digest is stale: authorized={expected} current={actual}"
            ),
        }
    }
}

impl Error for DestroyAuthorityError {}

impl From<LifecycleSpecError> for DestroyAuthorityError {
    fn from(value: LifecycleSpecError) -> Self {
        Self::Spec(value)
    }
}

pub fn destroy_plan(
    desired: &DesiredState,
    machine: &MachineSpec,
    inventory: &LifecycleInventory,
    source_revision: &str,
) -> Result<DestroyPlan, DestroyAuthorityError> {
    desired.validate()?;
    if !is_source_revision(source_revision) {
        return Err(DestroyAuthorityError::InvalidSourceRevision);
    }

    let exact_owned = inventory
        .resources
        .iter()
        .filter(|resource| ownership_matches(desired, machine, resource))
        .collect::<Vec<_>>();
    let observed = match exact_owned.as_slice() {
        [] => return Err(DestroyAuthorityError::Absent),
        [observed] => *observed,
        _ => return Err(DestroyAuthorityError::Ambiguous),
    };

    let destroy_digest = destroy_digest(desired, machine, observed, source_revision)?;
    Ok(DestroyPlan {
        machine_id: machine.id.clone(),
        provider_id: observed.provider_id.clone(),
        label: observed.label.clone(),
        source_revision: source_revision.to_owned(),
        region: observed.region.clone(),
        plan: observed.plan.clone(),
        os_id: observed.os_id,
        snapshot_id: observed.snapshot_id.clone(),
        main_ip: observed.main_ip.clone(),
        v6_main_ip: observed.v6_main_ip.clone(),
        firewall_group_id: observed.firewall_group_id.clone(),
        date_created: observed.date_created.clone(),
        observed_spec_digest: observed.spec_digest.clone(),
        destroy_digest,
    })
}

pub fn authorize_destroy(
    desired: &DesiredState,
    machine: &MachineSpec,
    inventory: &LifecycleInventory,
    source_revision: &str,
    authorized_digest: &str,
) -> Result<String, DestroyAuthorityError> {
    let current = destroy_plan(desired, machine, inventory, source_revision)?;
    if current.destroy_digest != authorized_digest {
        return Err(DestroyAuthorityError::StaleDigest {
            expected: authorized_digest.to_owned(),
            actual: current.destroy_digest,
        });
    }
    Ok(current.provider_id)
}

fn destroy_digest(
    desired: &DesiredState,
    machine: &MachineSpec,
    observed: &ObservedMachine,
    source_revision: &str,
) -> Result<String, LifecycleSpecError> {
    let mut tags = observed.tags.clone();
    tags.sort();
    let value = serde_json::json!({
        "schema": SUPPORTED_SCHEMA,
        "environment": desired.environment,
        "logical_id": machine.id,
        "source_revision": source_revision,
        "provider": {
            "id": observed.provider_id,
            "label": observed.label,
            "ownership": observed.ownership,
            "region": observed.region,
            "plan": observed.plan,
            "os_id": observed.os_id,
            "snapshot_id": observed.snapshot_id,
            "main_ip": observed.main_ip,
            "v6_main_ip": observed.v6_main_ip,
            "firewall_group_id": observed.firewall_group_id,
            "date_created": observed.date_created,
            "enable_ipv6": observed.enable_ipv6,
            "firewall_profile": observed.firewall_profile,
            "tags": tags,
            "spec_digest": observed.spec_digest,
        }
    });
    Ok(sha256_hex(canonical_json_value(&value).as_bytes()))
}

fn is_source_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired_json() -> &'static str {
        r#"{
  "schema": 1,
  "environment": "production",
  "machines": [
    {
      "id": "edge-1",
      "role": "edge",
      "provider": {
        "region": "waw",
        "plan": "vc2-1c-1gb",
        "os_id": 2625,
        "enable_ipv6": false,
        "firewall_profile": "edge"
      },
      "bootstrap_profile": "singbox-host-v1",
      "application_profiles": ["singbox-edge"],
      "tags": ["public-egress", "primary"]
    },
    {
      "id": "proxy-1",
      "role": "remote-proxy",
      "provider": {
        "region": "waw",
        "plan": "vc2-1c-1gb",
        "snapshot_id": "snapshot-1",
        "enable_ipv6": true,
        "firewall_profile": "proxy"
      },
      "bootstrap_profile": "singbox-host-v1",
      "application_profiles": ["remote-proxy"],
      "tags": ["proxy"]
    }
  ]
}"#
    }

    fn desired() -> DesiredState {
        DesiredState::parse_json(desired_json()).unwrap()
    }

    fn observed_for(
        desired: &DesiredState,
        machine: &MachineSpec,
        provider_id: &str,
    ) -> ObservedMachine {
        ObservedMachine {
            provider_id: provider_id.to_owned(),
            label: machine.id.clone(),
            ownership: ObservedOwnership {
                managed_by: Some(MANAGED_BY_IDENTITY.to_owned()),
                environment: Some(desired.environment.clone()),
                logical_id: Some(machine.id.clone()),
            },
            region: machine.provider.region.clone(),
            plan: machine.provider.plan.clone(),
            main_ip: Some("203.0.113.10".to_owned()),
            v6_main_ip: None,
            firewall_group_id: Some("firewall-1".to_owned()),
            date_created: Some("2026-09-19T00:00:00+00:00".to_owned()),
            os_id: machine.provider.os_id,
            snapshot_id: machine.provider.snapshot_id.clone(),
            enable_ipv6: machine.provider.enable_ipv6,
            firewall_profile: machine.provider.firewall_profile.clone(),
            tags: machine.tags.clone(),
            spec_digest: Some(desired.machine_digest(machine).unwrap()),
        }
    }

    #[test]
    fn rejects_unknown_fields_at_multiple_levels() {
        let top = desired_json().replacen(
            r#""environment": "production","#,
            r#""environment": "production", "unexpected": true,"#,
            1,
        );
        assert!(matches!(
            DesiredState::parse_json(&top),
            Err(LifecycleSpecError::Json(_))
        ));

        let nested = desired_json().replacen(
            r#""region": "waw","#,
            r#""region": "waw", "provider_id": "forbidden-authority","#,
            1,
        );
        assert!(matches!(
            DesiredState::parse_json(&nested),
            Err(LifecycleSpecError::Json(_))
        ));
    }

    #[test]
    fn rejects_invalid_image_identity_and_duplicate_machine_ids() {
        let both = desired_json().replacen(
            r#""os_id": 2625,"#,
            r#""os_id": 2625, "snapshot_id": "snapshot-conflict","#,
            1,
        );
        assert!(matches!(
            DesiredState::parse_json(&both),
            Err(LifecycleSpecError::Validation(_))
        ));

        let duplicate = desired_json().replace(r#""id": "proxy-1""#, r#""id": "edge-1""#);
        assert!(matches!(
            DesiredState::parse_json(&duplicate),
            Err(LifecycleSpecError::Validation(_))
        ));
    }

    #[test]
    fn canonical_digest_is_stable_for_machine_and_tag_order() {
        let first = desired();

        let mut second = first.clone();
        second.machines.reverse();
        second
            .machines
            .iter_mut()
            .find(|machine| machine.id == "edge-1")
            .unwrap()
            .tags
            .reverse();

        assert_eq!(
            first.canonical_json().unwrap(),
            second.canonical_json().unwrap()
        );
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn canonical_digest_preserves_application_profile_order() {
        let first = desired();
        let mut second = first.clone();
        let index = second
            .machines
            .iter()
            .position(|machine| machine.id == "edge-1")
            .unwrap();
        second.machines[index].application_profiles = vec!["a".to_owned(), "b".to_owned()];
        let digest_ab = second.machine_digest(&second.machines[index]).unwrap();

        second.machines[index].application_profiles.reverse();
        let digest_ba = second.machine_digest(&second.machines[index]).unwrap();
        assert_ne!(digest_ab, digest_ba);
    }

    #[test]
    fn sha256_implementation_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn inventory_is_deterministic_and_reports_orphans() {
        let desired = desired();
        let edge = &desired.machines[0];
        let mut exact = observed_for(&desired, edge, "instance-z");
        let orphan = ObservedMachine {
            provider_id: "instance-a".to_owned(),
            label: "old-1".to_owned(),
            ownership: ObservedOwnership {
                managed_by: Some(MANAGED_BY_IDENTITY.to_owned()),
                environment: Some("production".to_owned()),
                logical_id: Some("old-1".to_owned()),
            },
            ..exact.clone()
        };
        exact.provider_id = "instance-z".to_owned();

        let inventory = build_inventory(&desired, vec![exact, orphan]);
        assert_eq!(inventory.resources[0].provider_id, "instance-a");
        assert_eq!(
            inventory.orphaned_managed_provider_ids,
            vec!["instance-a".to_owned()]
        );
    }

    #[test]
    fn plan_create_when_exact_identity_is_absent() {
        let desired = desired();
        let machine = &desired.machines[0];
        let inventory = build_inventory(&desired, Vec::new());

        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::Create);
        assert!(plan.provider_id.is_none());
    }

    #[test]
    fn plan_noop_for_exact_matching_resource() {
        let desired = desired();
        let machine = &desired.machines[0];
        let observed = observed_for(&desired, machine, "instance-1");
        let inventory = build_inventory(&desired, vec![observed]);

        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::Noop);
        assert_eq!(plan.provider_id.as_deref(), Some("instance-1"));
        assert!(plan.reasons.is_empty());
    }

    #[test]
    fn plan_update_in_place_for_mutable_drift() {
        let desired = desired();
        let machine = &desired.machines[0];
        let mut observed = observed_for(&desired, machine, "instance-1");
        observed.firewall_profile = Some("wrong".to_owned());

        let inventory = build_inventory(&desired, vec![observed]);
        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::UpdateInPlace);
        assert!(
            plan.reasons
                .iter()
                .any(|reason| reason == "firewall profile differs")
        );
    }

    #[test]
    fn plan_replace_required_for_immutable_drift() {
        let desired = desired();
        let machine = &desired.machines[0];
        let mut observed = observed_for(&desired, machine, "instance-1");
        observed.plan = "vc2-2c-4gb".to_owned();

        let inventory = build_inventory(&desired, vec![observed]);
        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::ReplaceRequired);
    }

    #[test]
    fn plan_blocks_conflicting_unowned_identity() {
        let desired = desired();
        let machine = &desired.machines[0];
        let mut observed = observed_for(&desired, machine, "foreign-instance");
        observed.ownership.managed_by = None;

        let inventory = build_inventory(&desired, vec![observed]);
        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::BlockedDrift);
    }

    #[test]
    fn plan_fails_closed_on_multiple_exact_owned_resources() {
        let desired = desired();
        let machine = &desired.machines[0];
        let first = observed_for(&desired, machine, "instance-1");
        let second = observed_for(&desired, machine, "instance-2");

        let inventory = build_inventory(&desired, vec![first, second]);
        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::BlockedAmbiguous);
        assert!(plan.provider_id.is_none());
    }

    #[test]
    fn plan_snapshot_accepts_observed_os_id_alongside_snapshot_origin() {
        let desired = desired();
        let machine = &desired.machines[1];
        let mut observed = observed_for(&desired, machine, "instance-snapshot");
        observed.os_id = Some(2625);

        let inventory = build_inventory(&desired, vec![observed]);
        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::Noop);
    }

    #[test]
    fn provider_tag_codec_round_trips_lifecycle_and_user_tags() {
        let desired = desired();
        let machine = &desired.machines[0];

        let tags = provider_tags_for_machine(&desired, machine).unwrap();
        let decoded = decode_provider_tags(&tags).unwrap();

        assert_eq!(
            decoded.ownership.managed_by.as_deref(),
            Some(MANAGED_BY_IDENTITY)
        );
        assert_eq!(decoded.ownership.environment.as_deref(), Some("production"));
        assert_eq!(decoded.ownership.logical_id.as_deref(), Some("edge-1"));
        assert_eq!(
            decoded.spec_digest.as_deref(),
            Some(desired.machine_digest(machine).unwrap().as_str())
        );
        assert_eq!(decoded.firewall_profile.as_deref(), Some("edge"));
        assert_eq!(
            decoded.user_tags,
            vec!["primary".to_owned(), "public-egress".to_owned()]
        );
    }

    #[test]
    fn provider_tag_codec_rejects_incomplete_or_duplicate_identity() {
        let incomplete = vec![MANAGED_BY_TAG.to_owned()];
        assert_eq!(
            decode_provider_tags(&incomplete).unwrap_err(),
            ProviderIdentityError::IncompleteManagedIdentity
        );

        let duplicate = vec![
            MANAGED_BY_TAG.to_owned(),
            format!("{ENVIRONMENT_TAG_PREFIX}production"),
            format!("{ENVIRONMENT_TAG_PREFIX}staging"),
            format!("{LOGICAL_ID_TAG_PREFIX}edge-1"),
        ];
        assert_eq!(
            decode_provider_tags(&duplicate).unwrap_err(),
            ProviderIdentityError::DuplicateLifecycleTag("environment")
        );
    }

    #[test]
    fn desired_state_rejects_user_tags_in_reserved_namespace() {
        let raw = desired_json().replace(
            r#""tags": ["proxy"]"#,
            r#""tags": ["singbox-env-production"]"#,
        );
        assert!(matches!(
            DesiredState::parse_json(&raw),
            Err(LifecycleSpecError::Validation(_))
        ));
    }

    #[test]
    fn destroy_authority_is_stable_and_returns_exact_provider_id() {
        let desired = desired();
        let machine = &desired.machines[0];
        let observed = observed_for(&desired, machine, "instance-1");
        let inventory = build_inventory(&desired, vec![observed]);
        let source_revision = "8af5e7e34747208019b0e630dd7962752ac46a95";

        let plan = destroy_plan(&desired, machine, &inventory, source_revision).unwrap();
        let authorized = authorize_destroy(
            &desired,
            machine,
            &inventory,
            source_revision,
            &plan.destroy_digest,
        )
        .unwrap();

        assert_eq!(authorized, "instance-1");
    }

    #[test]
    fn destroy_authority_rejects_stale_digest_after_observed_change() {
        let desired = desired();
        let machine = &desired.machines[0];
        let source_revision = "8af5e7e34747208019b0e630dd7962752ac46a95";
        let observed = observed_for(&desired, machine, "instance-1");
        let initial_inventory = build_inventory(&desired, vec![observed.clone()]);
        let plan =
            destroy_plan(&desired, machine, &initial_inventory, source_revision).unwrap();

        let mut changed = observed;
        changed.plan = "vc2-2c-4gb".to_owned();
        let changed_inventory = build_inventory(&desired, vec![changed]);
        let error = authorize_destroy(
            &desired,
            machine,
            &changed_inventory,
            source_revision,
            &plan.destroy_digest,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DestroyAuthorityError::StaleDigest { .. }
        ));
    }

    #[test]
    fn destroy_authority_fails_closed_on_ambiguity() {
        let desired = desired();
        let machine = &desired.machines[0];
        let inventory = build_inventory(
            &desired,
            vec![
                observed_for(&desired, machine, "instance-1"),
                observed_for(&desired, machine, "instance-2"),
            ],
        );

        assert_eq!(
            destroy_plan(
                &desired,
                machine,
                &inventory,
                "8af5e7e34747208019b0e630dd7962752ac46a95",
            )
            .unwrap_err(),
            DestroyAuthorityError::Ambiguous
        );
    }

    #[test]
    fn plan_all_is_ordered_by_logical_machine_id() {
        let desired = desired();
        let inventory = build_inventory(&desired, Vec::new());
        let plans = plan_all(&desired, &inventory).unwrap();

        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].machine_id, "edge-1");
        assert_eq!(plans[1].machine_id, "proxy-1");
        assert!(plans.iter().all(|plan| plan.class == PlanClass::Create));
    }
}
