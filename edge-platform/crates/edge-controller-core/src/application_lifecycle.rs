use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::path::{Component, Path};

pub const SUPPORTED_APPLICATION_SCHEMA: u32 = 2;
pub const SUPPORTED_ARTIFACT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredApplicationState {
    pub schema: u32,
    pub environment: String,
    pub vultr_spec_path: String,
    pub machine_id: String,
    pub application_profile: String,
    pub bundle_root: String,
    #[serde(default)]
    pub runtime_env_required: bool,
    pub runtime_policy: ApplicationRuntimePolicy,
    pub bootstrap_mode: ApplicationBootstrapMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRuntimePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line1: Option<Line1RuntimePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line2: Option<Line2RuntimePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Line1RuntimePolicy {
    pub tunnel_domain: String,
    pub acme_email: String,
    pub acme_provider: String,
    pub reality_server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Line2RuntimePolicy {
    pub proxy_username: String,
    pub proxy_cert_cn: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationBootstrapMode {
    Base,
    Tunnel,
    Full,
}

impl ApplicationBootstrapMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Tunnel => "tunnel",
            Self::Full => "full",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentArtifactManifest {
    pub schema: u32,
    pub source_revision: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedApplicationRelease {
    pub release_id: String,
    pub source_revision: String,
    pub agent_sha256: String,
    pub bundle_digest: String,
    pub bootstrap_mode: ApplicationBootstrapMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApplicationObservation {
    pub observed_agent_sha256: Option<String>,
    pub observed_bundle_digest: Option<String>,
    pub runtime_ready: bool,
    pub current_release: Option<PublishedApplicationRelease>,
    pub previous_release: Option<PublishedApplicationRelease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationRecoveryObservation {
    pub application: ApplicationObservation,
    pub backup_agent_sha256: Option<String>,
    pub backup_bundle_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationRecoveryPlanClass {
    Noop,
    Recover,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationRecoveryAction {
    RestoreBundle,
    RestoreAgent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplicationRecoveryPlan {
    pub class: ApplicationRecoveryPlanClass,
    pub machine_id: String,
    pub target_release: PublishedApplicationRelease,
    pub actions: Vec<ApplicationRecoveryAction>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationPlanClass {
    Noop,
    Apply,
    Upgrade,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationAction {
    InstallAgent,
    ApplyBundle,
    Bootstrap,
    Verify,
    PublishRelease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplicationPlan {
    pub class: ApplicationPlanClass,
    pub desired_state_digest: String,
    pub desired_release: PublishedApplicationRelease,
    pub actions: Vec<ApplicationAction>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RollbackPlan {
    pub machine_id: String,
    pub current_release: PublishedApplicationRelease,
    pub previous_release: PublishedApplicationRelease,
    pub rollback_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationSpecError {
    Json(String),
    UnsupportedSchema(u32),
    Validation(String),
    Serialization(String),
}

impl fmt::Display for ApplicationSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(detail) => write!(f, "invalid application desired-state JSON: {detail}"),
            Self::UnsupportedSchema(schema) => {
                write!(f, "unsupported application desired-state schema {schema}")
            }
            Self::Validation(detail) => write!(f, "invalid application desired state: {detail}"),
            Self::Serialization(detail) => {
                write!(f, "failed to serialize application desired state: {detail}")
            }
        }
    }
}

impl Error for ApplicationSpecError {}

impl DesiredApplicationState {
    pub fn parse_json(raw: &str) -> Result<Self, ApplicationSpecError> {
        let desired: Self =
            serde_json::from_str(raw).map_err(|err| ApplicationSpecError::Json(err.to_string()))?;
        desired.validate()?;
        Ok(desired)
    }

    pub fn validate(&self) -> Result<(), ApplicationSpecError> {
        if self.schema != SUPPORTED_APPLICATION_SCHEMA {
            return Err(ApplicationSpecError::UnsupportedSchema(self.schema));
        }
        validate_identifier("environment", &self.environment)?;
        validate_identifier("machine_id", &self.machine_id)?;
        validate_identifier("application_profile", &self.application_profile)?;
        validate_repo_path("vultr_spec_path", &self.vultr_spec_path)?;
        validate_repo_path("bundle_root", &self.bundle_root)?;
        if !self.vultr_spec_path.starts_with("infra/vultr/")
            || !self.vultr_spec_path.ends_with(".json")
        {
            return Err(ApplicationSpecError::Validation(
                "vultr_spec_path must be an infra/vultr/*.json path".to_owned(),
            ));
        }
        if !self.runtime_env_required {
            return Err(ApplicationSpecError::Validation(
                "runtime_env_required must be true for the managed edge application".to_owned(),
            ));
        }
        self.runtime_policy.validate(self.bootstrap_mode)
    }

    pub fn canonical_json(&self) -> Result<String, ApplicationSpecError> {
        self.validate()?;
        serde_json::to_string(self)
            .map_err(|err| ApplicationSpecError::Serialization(err.to_string()))
    }

    pub fn digest(&self) -> Result<String, ApplicationSpecError> {
        Ok(sha256_hex(self.canonical_json()?.as_bytes()))
    }
}

impl ApplicationRuntimePolicy {
    fn validate(&self, mode: ApplicationBootstrapMode) -> Result<(), ApplicationSpecError> {
        let line1_required = matches!(
            mode,
            ApplicationBootstrapMode::Tunnel | ApplicationBootstrapMode::Full
        );
        let line2_required = matches!(
            mode,
            ApplicationBootstrapMode::Base | ApplicationBootstrapMode::Full
        );

        if self.line1.is_some() != line1_required {
            return Err(ApplicationSpecError::Validation(format!(
                "runtime_policy.line1 presence must match bootstrap_mode {}",
                mode.as_str()
            )));
        }
        if self.line2.is_some() != line2_required {
            return Err(ApplicationSpecError::Validation(format!(
                "runtime_policy.line2 presence must match bootstrap_mode {}",
                mode.as_str()
            )));
        }

        if let Some(line1) = self.line1.as_ref() {
            validate_runtime_dns_name("runtime_policy.line1.tunnel_domain", &line1.tunnel_domain)?;
            validate_runtime_public_value("runtime_policy.line1.acme_email", &line1.acme_email)?;
            validate_acme_provider(&line1.acme_provider)?;
            validate_runtime_public_value(
                "runtime_policy.line1.reality_server_name",
                &line1.reality_server_name,
            )?;
        }
        if let Some(line2) = self.line2.as_ref() {
            validate_runtime_public_value(
                "runtime_policy.line2.proxy_username",
                &line2.proxy_username,
            )?;
            validate_runtime_public_value(
                "runtime_policy.line2.proxy_cert_cn",
                &line2.proxy_cert_cn,
            )?;
        }
        Ok(())
    }
}

fn validate_acme_provider(value: &str) -> Result<(), ApplicationSpecError> {
    const LETSENCRYPT_PRODUCTION: &str = "letsencrypt";
    const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
    if !matches!(value, LETSENCRYPT_PRODUCTION | LETSENCRYPT_STAGING) {
        return Err(ApplicationSpecError::Validation(
            "runtime_policy.line1.acme_provider must be letsencrypt or the exact Let’s Encrypt staging directory"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_runtime_dns_name(label: &str, value: &str) -> Result<(), ApplicationSpecError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.to_ascii_lowercase()
        || !value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !part.starts_with('-')
                && !part.ends_with('-')
        })
    {
        return Err(ApplicationSpecError::Validation(format!(
            "{label} must be a canonical lowercase DNS name"
        )));
    }
    Ok(())
}

fn validate_runtime_public_value(label: &str, value: &str) -> Result<(), ApplicationSpecError> {
    if value.is_empty()
        || value.len() > 253
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'@' | b'%' | b'+' | b'/' | b'-')
        })
    {
        return Err(ApplicationSpecError::Validation(format!(
            "{label} must be a non-empty single-line runtime policy value"
        )));
    }
    Ok(())
}

impl AgentArtifactManifest {
    pub fn parse_json(raw: &str) -> Result<Self, ApplicationSpecError> {
        let manifest: Self =
            serde_json::from_str(raw).map_err(|err| ApplicationSpecError::Json(err.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ApplicationSpecError> {
        if self.schema != SUPPORTED_ARTIFACT_SCHEMA {
            return Err(ApplicationSpecError::Validation(format!(
                "unsupported edge-agent artifact schema {}",
                self.schema
            )));
        }
        validate_hex("artifact source_revision", &self.source_revision, 40)?;
        validate_hex("artifact sha256", &self.sha256, 64)
    }
}

pub fn desired_bundle_id(
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
) -> Result<String, ApplicationSpecError> {
    desired.validate()?;
    artifact.validate()?;
    let desired_digest = desired.digest()?;
    Ok(format!(
        "{}-{}-{}",
        desired.machine_id,
        &artifact.source_revision[..12],
        &desired_digest[..12]
    ))
}

pub fn desired_release(
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    bundle_digest: &str,
) -> Result<PublishedApplicationRelease, ApplicationSpecError> {
    desired.validate()?;
    artifact.validate()?;
    validate_hex("bundle digest", bundle_digest, 64)?;
    Ok(PublishedApplicationRelease {
        release_id: format!(
            "{}-{}-{}",
            desired_bundle_id(desired, artifact)?,
            &bundle_digest[..12],
            desired.bootstrap_mode.as_str()
        ),
        source_revision: artifact.source_revision.clone(),
        agent_sha256: artifact.sha256.clone(),
        bundle_digest: bundle_digest.to_owned(),
        bootstrap_mode: desired.bootstrap_mode,
    })
}

pub fn plan_application(
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    bundle_digest: &str,
    observation: &ApplicationObservation,
) -> Result<ApplicationPlan, ApplicationSpecError> {
    let release = desired_release(desired, artifact, bundle_digest)?;
    let desired_state_digest = desired.digest()?;

    if let Some(current) = observation.current_release.as_ref() {
        let observed_agent = observation.observed_agent_sha256.as_deref();
        let observed_bundle = observation.observed_bundle_digest.as_deref();
        let agent_is_known = observed_agent == Some(current.agent_sha256.as_str())
            || observed_agent == Some(release.agent_sha256.as_str());
        let bundle_is_known = observed_bundle == Some(current.bundle_digest.as_str())
            || observed_bundle == Some(release.bundle_digest.as_str());
        if !agent_is_known {
            return Ok(blocked_plan(
                desired_state_digest,
                release,
                "observed edge-agent digest is neither published current nor exact desired",
            ));
        }
        if !bundle_is_known {
            return Ok(blocked_plan(
                desired_state_digest,
                release,
                "observed application bundle digest is neither published current nor exact desired",
            ));
        }
    }

    let agent_matches =
        observation.observed_agent_sha256.as_deref() == Some(release.agent_sha256.as_str());
    let bundle_matches =
        observation.observed_bundle_digest.as_deref() == Some(release.bundle_digest.as_str());
    let release_matches = observation.current_release.as_ref() == Some(&release);

    if agent_matches && bundle_matches && release_matches && observation.runtime_ready {
        return Ok(ApplicationPlan {
            class: ApplicationPlanClass::Noop,
            desired_state_digest,
            desired_release: release,
            actions: Vec::new(),
            reasons: vec!["exact application release is already healthy".to_owned()],
        });
    }

    let mut actions = Vec::new();
    if !agent_matches {
        actions.push(ApplicationAction::InstallAgent);
    }
    if !bundle_matches {
        actions.push(ApplicationAction::ApplyBundle);
    }
    if !bundle_matches || !observation.runtime_ready {
        actions.push(ApplicationAction::Bootstrap);
    }
    actions.push(ApplicationAction::Verify);
    if !release_matches {
        actions.push(ApplicationAction::PublishRelease);
    }

    Ok(ApplicationPlan {
        class: if observation.current_release.is_some() {
            ApplicationPlanClass::Upgrade
        } else {
            ApplicationPlanClass::Apply
        },
        desired_state_digest,
        desired_release: release,
        actions,
        reasons: vec!["observed application state differs from exact desired release".to_owned()],
    })
}

pub fn plan_incomplete_upgrade_recovery(
    desired: &DesiredApplicationState,
    observation: &ApplicationRecoveryObservation,
) -> Result<ApplicationRecoveryPlan, ApplicationSpecError> {
    desired.validate()?;
    let current = observation
        .application
        .current_release
        .clone()
        .ok_or_else(|| {
            ApplicationSpecError::Validation(
                "incomplete-upgrade recovery requires a published current release".to_owned(),
            )
        })?;
    validate_release("current", &current)?;

    let active_agent = observation.application.observed_agent_sha256.as_deref();
    let active_bundle = observation.application.observed_bundle_digest.as_deref();
    let agent_matches = active_agent == Some(current.agent_sha256.as_str());
    let bundle_matches = active_bundle == Some(current.bundle_digest.as_str());

    if agent_matches && bundle_matches {
        return Ok(ApplicationRecoveryPlan {
            class: ApplicationRecoveryPlanClass::Noop,
            machine_id: desired.machine_id.clone(),
            target_release: current,
            actions: Vec::new(),
            reasons: vec![
                "active application material already matches published current release".to_owned(),
            ],
        });
    }

    let mut blocked_reasons = Vec::new();
    if !agent_matches {
        if active_agent.is_none() {
            blocked_reasons.push(
                "active edge-agent digest is unavailable; refusing incomplete-upgrade recovery"
                    .to_owned(),
            );
        } else if observation.backup_agent_sha256.as_deref() != Some(current.agent_sha256.as_str())
        {
            blocked_reasons.push(
                "backup edge-agent digest does not match published current release".to_owned(),
            );
        }
    }
    if !bundle_matches {
        if active_bundle.is_none() {
            blocked_reasons.push(
                "active application bundle digest is unavailable; refusing incomplete-upgrade recovery"
                    .to_owned(),
            );
        } else if observation.backup_bundle_digest.as_deref()
            != Some(current.bundle_digest.as_str())
        {
            blocked_reasons.push(
                "backup application bundle digest does not match published current release"
                    .to_owned(),
            );
        }
    }

    if !blocked_reasons.is_empty() {
        return Ok(ApplicationRecoveryPlan {
            class: ApplicationRecoveryPlanClass::Blocked,
            machine_id: desired.machine_id.clone(),
            target_release: current,
            actions: Vec::new(),
            reasons: blocked_reasons,
        });
    }

    let mut actions = Vec::new();
    if !bundle_matches {
        actions.push(ApplicationRecoveryAction::RestoreBundle);
    }
    if !agent_matches {
        actions.push(ApplicationRecoveryAction::RestoreAgent);
    }

    Ok(ApplicationRecoveryPlan {
        class: ApplicationRecoveryPlanClass::Recover,
        machine_id: desired.machine_id.clone(),
        target_release: current,
        actions,
        reasons: vec![
            "active material differs from published current release and exact matching backups are present"
                .to_owned(),
        ],
    })
}

pub fn build_rollback_plan(
    desired: &DesiredApplicationState,
    observation: &ApplicationObservation,
) -> Result<RollbackPlan, ApplicationSpecError> {
    desired.validate()?;
    let current = observation.current_release.clone().ok_or_else(|| {
        ApplicationSpecError::Validation("rollback requires a published current release".to_owned())
    })?;
    let previous = observation.previous_release.clone().ok_or_else(|| {
        ApplicationSpecError::Validation(
            "rollback requires a published previous release".to_owned(),
        )
    })?;

    validate_release("current", &current)?;
    validate_release("previous", &previous)?;

    if observation.observed_agent_sha256.as_deref() != Some(current.agent_sha256.as_str()) {
        return Err(ApplicationSpecError::Validation(
            "rollback is blocked because observed edge-agent digest does not match current release"
                .to_owned(),
        ));
    }
    if observation.observed_bundle_digest.as_deref() != Some(current.bundle_digest.as_str()) {
        return Err(ApplicationSpecError::Validation(
            "rollback is blocked because observed bundle digest does not match current release"
                .to_owned(),
        ));
    }

    let rollback_digest = rollback_digest(desired, &current, &previous)?;
    Ok(RollbackPlan {
        machine_id: desired.machine_id.clone(),
        current_release: current,
        previous_release: previous,
        rollback_digest,
    })
}

pub fn authorize_rollback(
    desired: &DesiredApplicationState,
    observation: &ApplicationObservation,
    authorized_digest: &str,
) -> Result<RollbackPlan, ApplicationSpecError> {
    validate_hex("rollback authorization digest", authorized_digest, 64)?;
    let plan = build_rollback_plan(desired, observation)?;
    if plan.rollback_digest != authorized_digest {
        return Err(ApplicationSpecError::Validation(
            "rollback digest is stale; re-run rollback-plan against current observations"
                .to_owned(),
        ));
    }
    Ok(plan)
}

fn rollback_digest(
    desired: &DesiredApplicationState,
    current: &PublishedApplicationRelease,
    previous: &PublishedApplicationRelease,
) -> Result<String, ApplicationSpecError> {
    let value = serde_json::json!({
        "schema": 1,
        "desired_state_digest": desired.digest()?,
        "machine_id": desired.machine_id,
        "current": current,
        "previous": previous,
    });
    let canonical = serde_json::to_vec(&value)
        .map_err(|err| ApplicationSpecError::Serialization(err.to_string()))?;
    Ok(sha256_hex(&canonical))
}

fn blocked_plan(
    desired_state_digest: String,
    desired_release: PublishedApplicationRelease,
    reason: &str,
) -> ApplicationPlan {
    ApplicationPlan {
        class: ApplicationPlanClass::Blocked,
        desired_state_digest,
        desired_release,
        actions: Vec::new(),
        reasons: vec![reason.to_owned()],
    }
}

fn validate_release(
    label: &str,
    release: &PublishedApplicationRelease,
) -> Result<(), ApplicationSpecError> {
    validate_identifier(&format!("{label} release_id"), &release.release_id)?;
    validate_hex(
        &format!("{label} source_revision"),
        &release.source_revision,
        40,
    )?;
    validate_hex(&format!("{label} agent_sha256"), &release.agent_sha256, 64)?;
    validate_hex(
        &format!("{label} bundle_digest"),
        &release.bundle_digest,
        64,
    )
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ApplicationSpecError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(ApplicationSpecError::Validation(format!(
            "{label} must contain only ASCII letters, digits, '.', '_' or '-'"
        )));
    }
    Ok(())
}

fn validate_repo_path(label: &str, value: &str) -> Result<(), ApplicationSpecError> {
    if value.is_empty() || value.contains('\\') {
        return Err(ApplicationSpecError::Validation(format!(
            "{label} must be a normalized repository-relative path"
        )));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ApplicationSpecError::Validation(format!(
            "{label} must be a normalized repository-relative path without traversal"
        )));
    }
    Ok(())
}

fn validate_hex(label: &str, value: &str, expected_len: usize) -> Result<(), ApplicationSpecError> {
    if value.len() != expected_len
        || !value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(ApplicationSpecError::Validation(format!(
            "{label} must be exactly {expected_len} lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> DesiredApplicationState {
        DesiredApplicationState {
            schema: 2,
            environment: "production".to_owned(),
            vultr_spec_path: "infra/vultr/production.json".to_owned(),
            machine_id: "edge-1".to_owned(),
            application_profile: "edge-stack".to_owned(),
            bundle_root: "win/vultr-waw/stack".to_owned(),
            runtime_env_required: true,
            runtime_policy: ApplicationRuntimePolicy {
                line1: None,
                line2: Some(Line2RuntimePolicy {
                    proxy_username: "acceptance".to_owned(),
                    proxy_cert_cn: "application-acceptance.local".to_owned(),
                }),
            },
            bootstrap_mode: ApplicationBootstrapMode::Base,
        }
    }

    fn artifact() -> AgentArtifactManifest {
        AgentArtifactManifest {
            schema: 1,
            source_revision: "1".repeat(40),
            sha256: "2".repeat(64),
        }
    }

    fn release() -> PublishedApplicationRelease {
        desired_release(&desired(), &artifact(), &"3".repeat(64)).unwrap()
    }

    #[test]
    fn strict_schema_rejects_unknown_fields() {
        let raw = r#"{
            "schema":2,
            "environment":"production",
            "vultr_spec_path":"infra/vultr/production.json",
            "machine_id":"edge-1",
            "application_profile":"edge-stack",
            "bundle_root":"win/vultr-waw/stack",
            "runtime_env_required":true,
            "runtime_policy":{
                "line2":{
                    "proxy_username":"acceptance",
                    "proxy_cert_cn":"application-acceptance.local"
                }
            },
            "bootstrap_mode":"base",
            "surprise":true
        }"#;
        assert!(DesiredApplicationState::parse_json(raw).is_err());
    }

    #[test]
    fn runtime_policy_matches_bootstrap_mode() {
        let mut value = desired();
        value.runtime_policy.line2 = None;
        assert!(value.validate().is_err());

        value.runtime_policy.line2 = Some(Line2RuntimePolicy {
            proxy_username: "acceptance".to_owned(),
            proxy_cert_cn: "application-acceptance.local".to_owned(),
        });
        value.runtime_policy.line1 = Some(Line1RuntimePolicy {
            tunnel_domain: "edge.example.com".to_owned(),
            acme_email: "admin@example.com".to_owned(),
            acme_provider: "letsencrypt".to_owned(),
            reality_server_name: "www.microsoft.com".to_owned(),
        });
        assert!(value.validate().is_err());

        value.bootstrap_mode = ApplicationBootstrapMode::Full;
        assert!(value.validate().is_ok());

        value.runtime_policy.line1.as_mut().unwrap().tunnel_domain = "../escape".to_owned();
        assert!(value.validate().is_err());
        value.runtime_policy.line1.as_mut().unwrap().tunnel_domain = "Edge.Example.com".to_owned();
        assert!(value.validate().is_err());
        value.runtime_policy.line1.as_mut().unwrap().tunnel_domain = "edge.example.com".to_owned();
        assert!(value.validate().is_ok());

        value.runtime_policy.line1.as_mut().unwrap().acme_provider =
            "https://acme-staging-v02.api.letsencrypt.org/directory".to_owned();
        assert!(value.validate().is_ok());
        value.runtime_policy.line1.as_mut().unwrap().acme_provider =
            "https://example.com/acme/directory".to_owned();
        assert!(value.validate().is_err());
    }

    #[test]
    fn paths_reject_traversal_and_backslashes() {
        let mut value = desired();
        value.bundle_root = "../stack".to_owned();
        assert!(value.validate().is_err());
        value.bundle_root = "win\\stack".to_owned();
        assert!(value.validate().is_err());
    }

    #[test]
    fn desired_digest_is_deterministic() {
        assert_eq!(desired().digest().unwrap(), desired().digest().unwrap());
    }

    #[test]
    fn first_release_plans_apply() {
        let plan = plan_application(
            &desired(),
            &artifact(),
            &"3".repeat(64),
            &ApplicationObservation::default(),
        )
        .unwrap();
        assert_eq!(plan.class, ApplicationPlanClass::Apply);
        assert_eq!(
            plan.actions,
            vec![
                ApplicationAction::InstallAgent,
                ApplicationAction::ApplyBundle,
                ApplicationAction::Bootstrap,
                ApplicationAction::Verify,
                ApplicationAction::PublishRelease,
            ]
        );
    }

    #[test]
    fn exact_healthy_release_is_noop() {
        let release = release();
        let observation = ApplicationObservation {
            observed_agent_sha256: Some(release.agent_sha256.clone()),
            observed_bundle_digest: Some(release.bundle_digest.clone()),
            runtime_ready: true,
            current_release: Some(release),
            previous_release: None,
        };
        let plan =
            plan_application(&desired(), &artifact(), &"3".repeat(64), &observation).unwrap();
        assert_eq!(plan.class, ApplicationPlanClass::Noop);
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn published_release_drift_blocks_instead_of_overwriting() {
        let current = release();
        let observation = ApplicationObservation {
            observed_agent_sha256: Some("4".repeat(64)),
            observed_bundle_digest: Some(current.bundle_digest.clone()),
            runtime_ready: true,
            current_release: Some(current),
            previous_release: None,
        };
        let plan =
            plan_application(&desired(), &artifact(), &"3".repeat(64), &observation).unwrap();
        assert_eq!(plan.class, ApplicationPlanClass::Blocked);
    }

    #[test]
    fn incomplete_upgrade_recovery_requires_exact_published_current_backups() {
        let current = release();
        let observation = ApplicationRecoveryObservation {
            application: ApplicationObservation {
                observed_agent_sha256: Some("4".repeat(64)),
                observed_bundle_digest: Some("5".repeat(64)),
                runtime_ready: false,
                current_release: Some(current.clone()),
                previous_release: None,
            },
            backup_agent_sha256: Some(current.agent_sha256.clone()),
            backup_bundle_digest: Some(current.bundle_digest.clone()),
        };
        let plan = plan_incomplete_upgrade_recovery(&desired(), &observation).unwrap();
        assert_eq!(plan.class, ApplicationRecoveryPlanClass::Recover);
        assert_eq!(
            plan.actions,
            vec![
                ApplicationRecoveryAction::RestoreBundle,
                ApplicationRecoveryAction::RestoreAgent,
            ]
        );

        let mut blocked = observation.clone();
        blocked.backup_agent_sha256 = Some("6".repeat(64));
        let plan = plan_incomplete_upgrade_recovery(&desired(), &blocked).unwrap();
        assert_eq!(plan.class, ApplicationRecoveryPlanClass::Blocked);
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn incomplete_upgrade_recovery_is_noop_when_active_matches_published_current() {
        let current = release();
        let observation = ApplicationRecoveryObservation {
            application: ApplicationObservation {
                observed_agent_sha256: Some(current.agent_sha256.clone()),
                observed_bundle_digest: Some(current.bundle_digest.clone()),
                runtime_ready: false,
                current_release: Some(current),
                previous_release: None,
            },
            backup_agent_sha256: None,
            backup_bundle_digest: None,
        };
        let plan = plan_incomplete_upgrade_recovery(&desired(), &observation).unwrap();
        assert_eq!(plan.class, ApplicationRecoveryPlanClass::Noop);
        assert!(plan.actions.is_empty());
    }

    #[test]
    fn incomplete_upgrade_recovery_restores_only_divergent_components() {
        let current = release();

        let agent_only = ApplicationRecoveryObservation {
            application: ApplicationObservation {
                observed_agent_sha256: Some("4".repeat(64)),
                observed_bundle_digest: Some(current.bundle_digest.clone()),
                runtime_ready: false,
                current_release: Some(current.clone()),
                previous_release: None,
            },
            backup_agent_sha256: Some(current.agent_sha256.clone()),
            backup_bundle_digest: None,
        };
        let plan = plan_incomplete_upgrade_recovery(&desired(), &agent_only).unwrap();
        assert_eq!(plan.class, ApplicationRecoveryPlanClass::Recover);
        assert_eq!(plan.actions, vec![ApplicationRecoveryAction::RestoreAgent]);

        let bundle_only = ApplicationRecoveryObservation {
            application: ApplicationObservation {
                observed_agent_sha256: Some(current.agent_sha256.clone()),
                observed_bundle_digest: Some("5".repeat(64)),
                runtime_ready: false,
                current_release: Some(current.clone()),
                previous_release: None,
            },
            backup_agent_sha256: None,
            backup_bundle_digest: Some(current.bundle_digest.clone()),
        };
        let plan = plan_incomplete_upgrade_recovery(&desired(), &bundle_only).unwrap();
        assert_eq!(plan.class, ApplicationRecoveryPlanClass::Recover);
        assert_eq!(plan.actions, vec![ApplicationRecoveryAction::RestoreBundle]);
    }

    #[test]
    fn rollback_digest_is_stale_safe() {
        let current = release();
        let previous = PublishedApplicationRelease {
            release_id: "edge-1-previous".to_owned(),
            source_revision: "4".repeat(40),
            agent_sha256: "5".repeat(64),
            bundle_digest: "6".repeat(64),
            bootstrap_mode: ApplicationBootstrapMode::Base,
        };
        let observation = ApplicationObservation {
            observed_agent_sha256: Some(current.agent_sha256.clone()),
            observed_bundle_digest: Some(current.bundle_digest.clone()),
            runtime_ready: true,
            current_release: Some(current),
            previous_release: Some(previous),
        };
        let plan = build_rollback_plan(&desired(), &observation).unwrap();
        assert!(authorize_rollback(&desired(), &observation, &plan.rollback_digest).is_ok());
        assert!(authorize_rollback(&desired(), &observation, &"0".repeat(64)).is_err());
    }
}
