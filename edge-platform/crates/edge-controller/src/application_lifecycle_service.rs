use crate::vultr_host_bootstrap::{
    StrictSshTunnelGuard, start_strict_agent_tunnel, strict_scp_upload, strict_ssh_capture,
    strict_ssh_run,
};
use edge_controller_core::application_lifecycle::{
    AgentArtifactManifest, ApplicationAction, ApplicationBootstrapMode, ApplicationObservation,
    ApplicationPlan, ApplicationPlanClass, DesiredApplicationState, PublishedApplicationRelease,
    RollbackPlan, authorize_rollback, build_rollback_plan, desired_bundle_id, desired_release,
    plan_application,
};
use edge_shared_types::agent_service_client::AgentServiceClient;
use edge_shared_types::{
    ApplyBundleRequest, BootstrapMode, BootstrapRuntimeRequest, BundleFile,
    ReadBundleIdentityRequest, RollbackBundleRequest, VerifyRuntimeRequest,
    canonical_apply_bundle_digest,
};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tonic::Request;
use tonic::transport::Channel;

const REMOTE_ROOT: &str = "/opt/vultr-edge-stack";
const REMOTE_AGENT: &str = "/opt/vultr-edge-stack/bin/edge-agent";
const REMOTE_PREVIOUS_AGENT: &str = "/opt/vultr-edge-stack/bin/edge-agent.previous";
const REMOTE_STACK_RELEASE: &str = "/opt/vultr-edge-stack/stack/.application-release.json";
const REMOTE_PREVIOUS_STACK_RELEASE: &str =
    "/opt/vultr-edge-stack/stack.previous/.application-release.json";
const REMOTE_CONTROL_RELEASE: &str = "/opt/vultr-edge-stack/application-release.json";
const REMOTE_CONTROL_RELEASE_STAGING: &str = "/tmp/singbox-application-release.json.tmp";
const AGENT_DROPIN_PATH: &str =
    "/etc/systemd/system/edge-agent.service.d/90-application-control.conf";
const AGENT_DROPIN_CONTENT: &str =
    "[Service]\nEnvironment=EDGE_AGENT_ADDR=127.0.0.1:50061\nEnvironmentFile=\n";

#[derive(Debug, Clone)]
pub(crate) struct ApplicationAuthority {
    pub target_ip: String,
    pub logical_hostname: String,
    pub operator_private_key_path: PathBuf,
    pub canonical_operator_public_key: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedApplicationBundle {
    pub request: ApplyBundleRequest,
    pub release: PublishedApplicationRelease,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ApplicationObservationView {
    pub observed_agent_sha256: Option<String>,
    pub observed_bundle_digest: Option<String>,
    pub runtime_ready: bool,
    pub current_release: Option<PublishedApplicationRelease>,
    pub previous_release: Option<PublishedApplicationRelease>,
}

impl From<&ApplicationObservation> for ApplicationObservationView {
    fn from(value: &ApplicationObservation) -> Self {
        Self {
            observed_agent_sha256: value.observed_agent_sha256.clone(),
            observed_bundle_digest: value.observed_bundle_digest.clone(),
            runtime_ready: value.runtime_ready,
            current_release: value.current_release.clone(),
            previous_release: value.previous_release.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ApplicationExecutionReport {
    pub operation: String,
    pub initial_plan: ApplicationPlan,
    pub final_plan: ApplicationPlan,
    pub final_observation: ApplicationObservationView,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ApplicationControlState {
    schema: u32,
    current: PublishedApplicationRelease,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<PublishedApplicationRelease>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleReleaseView {
    schema: u32,
    bundle_id: String,
    bundle_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DesiredMutationMode {
    Apply,
    Upgrade,
}

impl DesiredMutationMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Upgrade => "upgrade",
        }
    }
}

pub(crate) fn runtime_secret_path() -> Option<PathBuf> {
    env::var_os("EDGE_APPLICATION_RUNTIME_SECRET_PATH")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
}

pub(crate) fn verify_exact_agent_artifact(
    artifact: &AgentArtifactManifest,
    artifact_path: &Path,
) -> Result<(), String> {
    artifact.validate().map_err(|err| err.to_string())?;
    if !artifact_path.is_file() {
        return Err(format!(
            "exact edge-agent artifact was not found: {}",
            artifact_path.display()
        ));
    }
    let bytes = fs::read(artifact_path).map_err(|err| {
        format!(
            "failed to read exact edge-agent artifact {}: {err}",
            artifact_path.display()
        )
    })?;
    let observed = sha256_hex(&bytes);
    if observed != artifact.sha256 {
        return Err(format!(
            "edge-agent artifact digest mismatch: manifest={} observed={observed}",
            artifact.sha256
        ));
    }
    Ok(())
}

pub(crate) fn prepare_application_bundle(
    repo_root: &Path,
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    runtime_secret_path: Option<&Path>,
) -> Result<PreparedApplicationBundle, String> {
    desired.validate().map_err(|err| err.to_string())?;
    artifact.validate().map_err(|err| err.to_string())?;

    let bundle_root = repo_root.join(&desired.bundle_root);
    if !bundle_root.is_dir() {
        return Err(format!(
            "application bundle root is missing: {}",
            bundle_root.display()
        ));
    }
    if bundle_root.join(".env.runtime").exists() {
        return Err(
            "committed application bundle must not contain .env.runtime; runtime secrets are injected separately"
                .to_owned(),
        );
    }

    let mut stack_files = Vec::new();
    collect_bundle_files(&bundle_root, &bundle_root, &mut stack_files)?;

    match runtime_secret_path {
        Some(path) => {
            let content = render_runtime_environment(desired, path)?;
            stack_files.push(BundleFile {
                relative_path: ".env.runtime".to_owned(),
                content,
                executable: false,
                sensitive: true,
            });
        }
        None if desired.runtime_env_required => {
            return Err(
                "runtime credential material is required; set EDGE_APPLICATION_RUNTIME_SECRET_PATH to a private file"
                    .to_owned(),
            );
        }
        None => {}
    }

    let bundle_id = desired_bundle_id(desired, artifact).map_err(|err| err.to_string())?;
    let mut request = ApplyBundleRequest {
        stack_files,
        host_files: Vec::new(),
        deployment_summary: None,
        agent_env_file: None,
        prune_existing: true,
        bundle_id: Some(bundle_id),
        bundle_digest: None,
    };
    let bundle_digest = canonical_apply_bundle_digest(&request)?;
    request.bundle_digest = Some(bundle_digest.clone());
    let release =
        desired_release(desired, artifact, &bundle_digest).map_err(|err| err.to_string())?;

    Ok(PreparedApplicationBundle { request, release })
}

fn render_runtime_environment(
    desired: &DesiredApplicationState,
    secret_path: &Path,
) -> Result<Vec<u8>, String> {
    let raw = fs::read_to_string(secret_path).map_err(|err| {
        format!(
            "failed to read runtime credential file {}: {err}",
            secret_path.display()
        )
    })?;
    let secrets = parse_runtime_secrets(&raw)?;
    let expected = expected_runtime_secret_keys(desired.bootstrap_mode);
    let observed = secrets.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed != expected {
        let missing = expected
            .difference(&observed)
            .copied()
            .collect::<Vec<_>>();
        let unexpected = observed
            .difference(&expected)
            .copied()
            .collect::<Vec<_>>();
        return Err(format!(
            "runtime credential keys do not match bootstrap mode {}: missing=[{}] unexpected=[{}]",
            desired.bootstrap_mode.as_str(),
            missing.join(","),
            unexpected.join(",")
        ));
    }

    for (key, value) in &secrets {
        validate_runtime_secret_value(key, value)?;
    }

    let mut values = Vec::new();
    if let Some(line2) = desired.runtime_policy.line2.as_ref() {
        values.push(("PROXY_USERNAME", line2.proxy_username.as_str()));
        values.push((
            "PROXY_PASSWORD",
            required_runtime_secret(&secrets, "PROXY_PASSWORD")?,
        ));
        values.push(("PROXY_CERT_CN", line2.proxy_cert_cn.as_str()));
    }
    if let Some(line1) = desired.runtime_policy.line1.as_ref() {
        values.push((
            "VLESS_UUID",
            required_runtime_secret(&secrets, "VLESS_UUID")?,
        ));
        values.push((
            "HY2_PASSWORD",
            required_runtime_secret(&secrets, "HY2_PASSWORD")?,
        ));
        values.push((
            "REALITY_PRIVATE_KEY",
            required_runtime_secret(&secrets, "REALITY_PRIVATE_KEY")?,
        ));
        values.push((
            "REALITY_SHORT_ID",
            required_runtime_secret(&secrets, "REALITY_SHORT_ID")?,
        ));
        values.push((
            "VLESS_WARP_UUID",
            required_runtime_secret(&secrets, "VLESS_WARP_UUID")?,
        ));
        values.push((
            "HY2_WARP_PASSWORD",
            required_runtime_secret(&secrets, "HY2_WARP_PASSWORD")?,
        ));
        values.push((
            "REALITY_WARP_PRIVATE_KEY",
            required_runtime_secret(&secrets, "REALITY_WARP_PRIVATE_KEY")?,
        ));
        values.push((
            "REALITY_WARP_SHORT_ID",
            required_runtime_secret(&secrets, "REALITY_WARP_SHORT_ID")?,
        ));
        values.push(("REALITY_SERVER_NAME", line1.reality_server_name.as_str()));
        values.push(("TUNNEL_DOMAIN", line1.tunnel_domain.as_str()));
        values.push(("ACME_EMAIL", line1.acme_email.as_str()));
    }

    let rendered = values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect::<String>();
    Ok(rendered.into_bytes())
}

fn parse_runtime_secrets(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        let line_number = index + 1;
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!("runtime credential line {line_number} must use KEY=VALUE syntax")
        })?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!(
                "runtime credential line {line_number} has an invalid key"
            ));
        }
        if value.is_empty() {
            return Err(format!("runtime credential {key} must be non-empty"));
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("runtime credential key {key} is duplicated"));
        }
    }
    if values.is_empty() {
        return Err("runtime credential file must be non-empty".to_owned());
    }
    Ok(values)
}

fn expected_runtime_secret_keys(mode: ApplicationBootstrapMode) -> BTreeSet<&'static str> {
    let mut keys = BTreeSet::new();
    if matches!(
        mode,
        ApplicationBootstrapMode::Base | ApplicationBootstrapMode::Full
    ) {
        keys.insert("PROXY_PASSWORD");
    }
    if matches!(
        mode,
        ApplicationBootstrapMode::Tunnel | ApplicationBootstrapMode::Full
    ) {
        keys.extend([
            "HY2_PASSWORD",
            "HY2_WARP_PASSWORD",
            "REALITY_PRIVATE_KEY",
            "REALITY_SHORT_ID",
            "REALITY_WARP_PRIVATE_KEY",
            "REALITY_WARP_SHORT_ID",
            "VLESS_UUID",
            "VLESS_WARP_UUID",
        ]);
    }
    keys
}

fn required_runtime_secret<'a>(
    secrets: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    secrets
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("required runtime credential {key} is missing"))
}

fn validate_runtime_secret_value(key: &str, value: &str) -> Result<(), String> {
    if value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'~' | b':' | b'@' | b'%' | b'+' | b'/' | b'=' | b'-')
        })
    {
        return Err(format!(
            "runtime credential {key} contains characters unsafe for the canonical env-file format"
        ));
    }

    match key {
        "PROXY_PASSWORD" | "HY2_PASSWORD" | "HY2_WARP_PASSWORD" => {
            if value.len() < 16 {
                return Err(format!(
                    "runtime credential {key} must be at least 16 characters"
                ));
            }
        }
        "VLESS_UUID" | "VLESS_WARP_UUID" => validate_runtime_uuid(key, value)?,
        "REALITY_PRIVATE_KEY" | "REALITY_WARP_PRIVATE_KEY" => {
            if value.len() != 43
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(format!(
                    "runtime credential {key} must be a 43-character base64url X25519 private key"
                ));
            }
        }
        "REALITY_SHORT_ID" | "REALITY_WARP_SHORT_ID" => {
            if value.len() != 16
                || !value
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
            {
                return Err(format!(
                    "runtime credential {key} must be exactly 16 lowercase hexadecimal characters"
                ));
            }
        }
        _ => return Err(format!("unsupported runtime credential key {key}")),
    }
    Ok(())
}

fn validate_runtime_uuid(key: &str, value: &str) -> Result<(), String> {
    if value.len() != 36
        || !value
            .chars()
            .enumerate()
            .all(|(index, ch)| match index {
                8 | 13 | 18 | 23 => ch == '-',
                _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
            })
    {
        return Err(format!(
            "runtime credential {key} must be a lowercase UUID"
        ));
    }
    Ok(())
}

pub(crate) async fn observe_application(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
) -> Result<ApplicationObservation, String> {
    let observed_agent_sha256 = remote_file_sha(authority, REMOTE_AGENT)?;
    let observed_bundle_digest = read_remote_bundle_release(authority, REMOTE_STACK_RELEASE)?
        .map(|value| value.bundle_digest);
    let control = read_control_state(authority)?;
    let runtime_ready = if observed_agent_sha256.is_some() {
        verify_runtime_ready(authority, desired.bootstrap_mode)
            .await
            .unwrap_or(false)
    } else {
        false
    };

    Ok(ApplicationObservation {
        observed_agent_sha256,
        observed_bundle_digest,
        runtime_ready,
        current_release: control.as_ref().map(|value| value.current.clone()),
        previous_release: control.and_then(|value| value.previous),
    })
}

pub(crate) async fn execute_desired(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    artifact_path: &Path,
    prepared: &PreparedApplicationBundle,
    mode: DesiredMutationMode,
) -> Result<ApplicationExecutionReport, String> {
    verify_exact_agent_artifact(artifact, artifact_path)?;
    let initial_observation = observe_application(authority, desired).await?;
    let initial_plan = plan_application(
        desired,
        artifact,
        &prepared.release.bundle_digest,
        true,
        &initial_observation,
    )
    .map_err(|err| err.to_string())?;

    match initial_plan.class {
        ApplicationPlanClass::Blocked => {
            return Err(format!(
                "application mutation is blocked: {}",
                initial_plan.reasons.join("; ")
            ));
        }
        ApplicationPlanClass::Noop => {
            return Ok(ApplicationExecutionReport {
                operation: mode.as_str().to_owned(),
                final_plan: initial_plan.clone(),
                initial_plan,
                final_observation: ApplicationObservationView::from(&initial_observation),
            });
        }
        ApplicationPlanClass::Apply if mode == DesiredMutationMode::Upgrade => {
            return Err(
                "upgrade requires an existing published application release; use apply".to_owned(),
            );
        }
        ApplicationPlanClass::Upgrade if mode == DesiredMutationMode::Apply => {
            return Err("apply refuses to overwrite an existing release; use upgrade".to_owned());
        }
        ApplicationPlanClass::Apply | ApplicationPlanClass::Upgrade => {}
    }

    if initial_plan
        .actions
        .contains(&ApplicationAction::InstallAgent)
    {
        install_exact_agent(authority, artifact, artifact_path)?;
    }
    ensure_private_agent_service(authority)?;

    if initial_plan
        .actions
        .contains(&ApplicationAction::ApplyBundle)
    {
        apply_bundle_once(authority, prepared).await?;
    }

    if initial_plan.actions.contains(&ApplicationAction::Bootstrap) {
        bootstrap_once(authority, desired.bootstrap_mode).await?;
    }

    if !verify_runtime_ready(authority, desired.bootstrap_mode).await? {
        return Err("typed runtime verification did not reach readiness".to_owned());
    }

    if initial_plan
        .actions
        .contains(&ApplicationAction::PublishRelease)
    {
        publish_release_once(authority, &prepared.release)?;
    }

    let final_observation = observe_application(authority, desired).await?;
    let final_plan = plan_application(
        desired,
        artifact,
        &prepared.release.bundle_digest,
        true,
        &final_observation,
    )
    .map_err(|err| err.to_string())?;
    if final_plan.class != ApplicationPlanClass::Noop {
        return Err(format!(
            "application mutation completed operations but did not converge to NOOP: {:?}: {}",
            final_plan.class,
            final_plan.reasons.join("; ")
        ));
    }

    Ok(ApplicationExecutionReport {
        operation: mode.as_str().to_owned(),
        initial_plan,
        final_plan,
        final_observation: ApplicationObservationView::from(&final_observation),
    })
}

pub(crate) async fn verify_desired(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    prepared: &PreparedApplicationBundle,
) -> Result<(ApplicationPlan, ApplicationObservationView), String> {
    let observation = observe_application(authority, desired).await?;
    let plan = plan_application(
        desired,
        artifact,
        &prepared.release.bundle_digest,
        true,
        &observation,
    )
    .map_err(|err| err.to_string())?;
    Ok((plan, ApplicationObservationView::from(&observation)))
}

pub(crate) async fn rollback_plan_remote(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
) -> Result<RollbackPlan, String> {
    let observation = observe_application(authority, desired).await?;
    let plan = build_rollback_plan(desired, &observation).map_err(|err| err.to_string())?;
    verify_previous_release_material(authority, &plan.current_release, &plan.previous_release)?;
    Ok(plan)
}

pub(crate) async fn execute_rollback(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
    authorized_digest: &str,
) -> Result<ApplicationObservationView, String> {
    let observation = observe_application(authority, desired).await?;
    let plan = authorize_rollback(desired, &observation, authorized_digest)
        .map_err(|err| err.to_string())?;
    verify_previous_release_material(authority, &plan.current_release, &plan.previous_release)?;

    rollback_bundle_once(authority, &plan).await?;
    if plan.current_release.agent_sha256 != plan.previous_release.agent_sha256 {
        rollback_agent_once(authority, &plan.current_release, &plan.previous_release)?;
    }
    ensure_private_agent_service(authority)?;
    bootstrap_once(authority, plan.previous_release.bootstrap_mode).await?;
    if !verify_runtime_ready(authority, plan.previous_release.bootstrap_mode).await? {
        return Err("rolled-back runtime did not reach typed readiness".to_owned());
    }

    publish_control_state_once(
        authority,
        &ApplicationControlState {
            schema: 1,
            current: plan.previous_release.clone(),
            previous: Some(plan.current_release.clone()),
        },
    )?;

    let final_observation = observe_application(authority, desired).await?;
    if final_observation.current_release.as_ref() != Some(&plan.previous_release)
        || final_observation.observed_agent_sha256.as_deref()
            != Some(plan.previous_release.agent_sha256.as_str())
        || final_observation.observed_bundle_digest.as_deref()
            != Some(plan.previous_release.bundle_digest.as_str())
        || !final_observation.runtime_ready
    {
        return Err("rollback did not converge to the exact previous release".to_owned());
    }
    Ok(ApplicationObservationView::from(&final_observation))
}

fn collect_bundle_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<BundleFile>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|err| {
            format!(
                "failed to read application bundle {}: {err}",
                current.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("failed to enumerate application bundle: {err}"))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|err| format!("failed to inspect bundle path {}: {err}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "application bundle symlinks are not allowed: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_bundle_files(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!(
                "application bundle contains unsupported filesystem entry: {}",
                path.display()
            ));
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|err| format!("failed to derive bundle-relative path: {err}"))?;
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(format!(
                "application bundle path is not normalized: {}",
                relative.display()
            ));
        }
        let relative_path = relative.to_string_lossy().replace('\\', "/");
        if relative_path == ".env.runtime" {
            return Err("application bundle source must not contain .env.runtime".to_owned());
        }
        files.push(BundleFile {
            executable: relative_path == "bootstrap.sh",
            sensitive: false,
            relative_path,
            content: fs::read(&path)
                .map_err(|err| format!("failed to read bundle file {}: {err}", path.display()))?,
        });
    }
    Ok(())
}

fn remote_file_sha(
    authority: &ApplicationAuthority,
    remote_path: &str,
) -> Result<Option<String>, String> {
    let command = format!(
        "if sudo test -f {remote_path}; then sudo sha256sum {remote_path} | cut -d ' ' -f1; fi"
    );
    let value = strict_ssh_capture(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &command,
    )?;
    if value.is_empty() {
        return Ok(None);
    }
    validate_lower_hex("remote sha256", &value, 64)?;
    Ok(Some(value))
}

fn read_remote_bundle_release(
    authority: &ApplicationAuthority,
    remote_path: &str,
) -> Result<Option<BundleReleaseView>, String> {
    let raw = strict_ssh_capture(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &format!("sudo cat {remote_path} 2>/dev/null || true"),
    )?;
    if raw.is_empty() {
        return Ok(None);
    }
    let value: BundleReleaseView = serde_json::from_str(&raw)
        .map_err(|err| format!("remote bundle release marker is invalid JSON: {err}"))?;
    if value.schema != 1 {
        return Err(format!(
            "unsupported remote bundle release marker schema {}",
            value.schema
        ));
    }
    validate_lower_hex("remote bundle digest", &value.bundle_digest, 64)?;
    if value.bundle_id.trim().is_empty() {
        return Err("remote bundle release marker has empty bundle_id".to_owned());
    }
    Ok(Some(value))
}

fn read_control_state(
    authority: &ApplicationAuthority,
) -> Result<Option<ApplicationControlState>, String> {
    let raw = strict_ssh_capture(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &format!("sudo cat {REMOTE_CONTROL_RELEASE} 2>/dev/null || true"),
    )?;
    if raw.is_empty() {
        return Ok(None);
    }
    let state: ApplicationControlState = serde_json::from_str(&raw)
        .map_err(|err| format!("application release control marker is invalid JSON: {err}"))?;
    if state.schema != 1 {
        return Err(format!(
            "unsupported application release control schema {}",
            state.schema
        ));
    }
    Ok(Some(state))
}

fn install_exact_agent(
    authority: &ApplicationAuthority,
    artifact: &AgentArtifactManifest,
    artifact_path: &Path,
) -> Result<(), String> {
    verify_exact_agent_artifact(artifact, artifact_path)?;
    let current = remote_file_sha(authority, REMOTE_AGENT)?;
    if current.as_deref() == Some(artifact.sha256.as_str()) {
        return Ok(());
    }

    let candidate = format!("/tmp/singbox-edge-agent-{}.tmp", artifact.sha256);
    strict_scp_upload(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        artifact_path,
        &candidate,
    )?;

    let command = format!(
        "set -eu; expected='{digest}'; candidate='{candidate}'; actual=$(sha256sum \"$candidate\" | cut -d ' ' -f1); test \"$actual\" = \"$expected\"; sudo install -d -m 0755 {root}/bin /etc/systemd/system/edge-agent.service.d; if sudo test -f {agent}; then sudo cp -f {agent} {previous}; fi; sudo install -m 0755 \"$candidate\" {agent}.next; actual=$(sudo sha256sum {agent}.next | cut -d ' ' -f1); test \"$actual\" = \"$expected\"; printf '%s\\n' '[Service]' 'Environment=EDGE_AGENT_ADDR=127.0.0.1:50061' 'EnvironmentFile=' | sudo tee {dropin} >/dev/null; sudo mv -f {agent}.next {agent}; rm -f \"$candidate\"; sudo systemctl daemon-reload; sudo systemctl enable edge-agent.service >/dev/null; sudo systemctl restart edge-agent.service; sudo systemctl is-active --quiet edge-agent.service",
        digest = artifact.sha256,
        candidate = candidate,
        root = REMOTE_ROOT,
        agent = REMOTE_AGENT,
        previous = REMOTE_PREVIOUS_AGENT,
        dropin = AGENT_DROPIN_PATH,
    );

    if let Err(err) = strict_ssh_run(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &command,
    ) {
        let observed = remote_file_sha(authority, REMOTE_AGENT)?;
        if observed.as_deref() == Some(artifact.sha256.as_str()) {
            return Ok(());
        }
        return Err(format!(
            "edge-agent install outcome is uncertain; mutation was not replayed: {err}"
        ));
    }

    let observed = remote_file_sha(authority, REMOTE_AGENT)?;
    if observed.as_deref() != Some(artifact.sha256.as_str()) {
        return Err(
            "edge-agent install completed but remote digest did not match exact artifact"
                .to_owned(),
        );
    }
    Ok(())
}

fn ensure_private_agent_service(authority: &ApplicationAuthority) -> Result<(), String> {
    let observed = strict_ssh_capture(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &format!("sudo cat {AGENT_DROPIN_PATH} 2>/dev/null || true"),
    )?;
    if observed.trim() == AGENT_DROPIN_CONTENT.trim() {
        return Ok(());
    }

    let command = format!(
        "set -eu; sudo install -d -m 0755 /etc/systemd/system/edge-agent.service.d; printf '%s\\n' '[Service]' 'Environment=EDGE_AGENT_ADDR=127.0.0.1:50061' 'EnvironmentFile=' | sudo tee {AGENT_DROPIN_PATH} >/dev/null; sudo systemctl daemon-reload; sudo systemctl restart edge-agent.service; sudo systemctl is-active --quiet edge-agent.service"
    );
    if let Err(err) = strict_ssh_run(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &command,
    ) {
        let reobserved = strict_ssh_capture(
            &authority.target_ip,
            &authority.logical_hostname,
            &authority.operator_private_key_path,
            &authority.canonical_operator_public_key,
            &format!("sudo cat {AGENT_DROPIN_PATH} 2>/dev/null || true"),
        )?;
        if reobserved.trim() == AGENT_DROPIN_CONTENT.trim() {
            return Ok(());
        }
        return Err(format!(
            "edge-agent private service normalization outcome is uncertain; mutation was not replayed: {err}"
        ));
    }
    Ok(())
}

async fn apply_bundle_once(
    authority: &ApplicationAuthority,
    prepared: &PreparedApplicationBundle,
) -> Result<(), String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    let result = client
        .apply_bundle(Request::new(prepared.request.clone()))
        .await;
    match result {
        Ok(response)
            if response.get_ref().active_bundle_digest.as_deref()
                == Some(prepared.release.bundle_digest.as_str()) =>
        {
            Ok(())
        }
        Ok(response) => Err(format!(
            "edge-agent ApplyBundle returned unexpected active digest {:?}",
            response.get_ref().active_bundle_digest
        )),
        Err(err) => {
            let observed = read_remote_bundle_release(authority, REMOTE_STACK_RELEASE)?;
            if observed
                .as_ref()
                .is_some_and(|value| value.bundle_digest == prepared.release.bundle_digest)
            {
                return Ok(());
            }
            Err(format!(
                "ApplyBundle outcome is uncertain and desired bundle was not observed; RPC was not replayed: {err}"
            ))
        }
    }
}

async fn rollback_bundle_once(
    authority: &ApplicationAuthority,
    plan: &RollbackPlan,
) -> Result<(), String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    let result = client
        .rollback_bundle(Request::new(RollbackBundleRequest {
            expected_current_bundle_digest: plan.current_release.bundle_digest.clone(),
        }))
        .await;
    match result {
        Ok(response)
            if response.get_ref().active_bundle_digest.as_deref()
                == Some(plan.previous_release.bundle_digest.as_str()) =>
        {
            Ok(())
        }
        Ok(response) => Err(format!(
            "edge-agent RollbackBundle returned unexpected active digest {:?}",
            response.get_ref().active_bundle_digest
        )),
        Err(err) => {
            let observed = read_remote_bundle_release(authority, REMOTE_STACK_RELEASE)?;
            if observed
                .as_ref()
                .is_some_and(|value| value.bundle_digest == plan.previous_release.bundle_digest)
            {
                return Ok(());
            }
            Err(format!(
                "RollbackBundle outcome is uncertain and previous bundle was not observed; RPC was not replayed: {err}"
            ))
        }
    }
}

fn rollback_agent_once(
    authority: &ApplicationAuthority,
    current: &PublishedApplicationRelease,
    previous: &PublishedApplicationRelease,
) -> Result<(), String> {
    let previous_observed = remote_file_sha(authority, REMOTE_PREVIOUS_AGENT)?;
    if previous_observed.as_deref() != Some(previous.agent_sha256.as_str()) {
        return Err(
            "previous edge-agent artifact digest does not match published previous release"
                .to_owned(),
        );
    }
    let command = format!(
        "set -eu; sudo cp -f {agent} {agent}.rollback; sudo mv -f {previous_agent} {agent}; sudo mv -f {agent}.rollback {previous_agent}; sudo systemctl restart edge-agent.service; sudo systemctl is-active --quiet edge-agent.service",
        agent = REMOTE_AGENT,
        previous_agent = REMOTE_PREVIOUS_AGENT,
    );
    if let Err(err) = strict_ssh_run(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &command,
    ) {
        let observed = remote_file_sha(authority, REMOTE_AGENT)?;
        if observed.as_deref() == Some(previous.agent_sha256.as_str()) {
            return Ok(());
        }
        return Err(format!(
            "edge-agent rollback outcome is uncertain; mutation was not replayed: {err}"
        ));
    }
    let observed = remote_file_sha(authority, REMOTE_AGENT)?;
    if observed.as_deref() != Some(previous.agent_sha256.as_str()) {
        return Err(format!(
            "edge-agent rollback did not reach previous digest; current release remains {}",
            current.release_id
        ));
    }
    Ok(())
}

async fn bootstrap_once(
    authority: &ApplicationAuthority,
    mode: ApplicationBootstrapMode,
) -> Result<(), String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    let response = client
        .bootstrap_runtime(Request::new(BootstrapRuntimeRequest {
            mode: proto_bootstrap_mode(mode) as i32,
        }))
        .await
        .map_err(|err| format!("typed BootstrapRuntime RPC failed: {err}"))?
        .into_inner();
    if response.success {
        Ok(())
    } else {
        Err(format!(
            "typed BootstrapRuntime failed with exit_code={} warnings={}",
            response.exit_code,
            response.warnings.join("; ")
        ))
    }
}

async fn verify_runtime_ready(
    authority: &ApplicationAuthority,
    mode: ApplicationBootstrapMode,
) -> Result<bool, String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    let response = client
        .verify_runtime(Request::new(VerifyRuntimeRequest {
            require_readiness: true,
            mode: proto_bootstrap_mode(mode) as i32,
        }))
        .await
        .map_err(|err| format!("typed VerifyRuntime RPC failed: {err}"))?
        .into_inner();
    Ok(response.ready)
}

async fn connect_agent(
    authority: &ApplicationAuthority,
) -> Result<(AgentServiceClient<Channel>, StrictSshTunnelGuard), String> {
    let (port, tunnel) = start_strict_agent_tunnel(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
    )?;
    let endpoint = format!("http://127.0.0.1:{port}");
    let mut last = None;
    for _ in 0..20 {
        match AgentServiceClient::connect(endpoint.clone()).await {
            Ok(client) => return Ok((client, tunnel)),
            Err(err) => last = Some(err.to_string()),
        }
        sleep(Duration::from_millis(250)).await;
    }
    Err(format!(
        "edge-agent did not become reachable through strict SSH tunnel: {}",
        last.unwrap_or_else(|| "no connection attempt completed".to_owned())
    ))
}

fn publish_release_once(
    authority: &ApplicationAuthority,
    release: &PublishedApplicationRelease,
) -> Result<(), String> {
    let existing = read_control_state(authority)?;
    if existing
        .as_ref()
        .is_some_and(|value| value.current == *release)
    {
        return Ok(());
    }
    let state = ApplicationControlState {
        schema: 1,
        current: release.clone(),
        previous: existing.map(|value| value.current),
    };
    publish_control_state_once(authority, &state)
}

fn publish_control_state_once(
    authority: &ApplicationAuthority,
    state: &ApplicationControlState,
) -> Result<(), String> {
    let local = unique_temp_file("singbox-application-release");
    let raw = serde_json::to_vec(state)
        .map_err(|err| format!("failed to serialize application release control state: {err}"))?;
    fs::write(&local, raw)
        .map_err(|err| format!("failed to write temporary release control state: {err}"))?;

    let upload = strict_scp_upload(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &local,
        REMOTE_CONTROL_RELEASE_STAGING,
    );
    let _ = fs::remove_file(&local);
    upload?;

    let command = format!(
        "set -eu; sudo install -d -m 0755 {REMOTE_ROOT}; sudo install -m 0644 {REMOTE_CONTROL_RELEASE_STAGING} {REMOTE_CONTROL_RELEASE}; rm -f {REMOTE_CONTROL_RELEASE_STAGING}"
    );
    if let Err(err) = strict_ssh_run(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &command,
    ) {
        if read_control_state(authority)?.as_ref() == Some(state) {
            return Ok(());
        }
        return Err(format!(
            "release publication outcome is uncertain; publication was not replayed: {err}"
        ));
    }
    if read_control_state(authority)?.as_ref() != Some(state) {
        return Err(
            "release publication completed but exact control state was not observed".to_owned(),
        );
    }
    Ok(())
}

fn verify_previous_release_material(
    authority: &ApplicationAuthority,
    current: &PublishedApplicationRelease,
    previous: &PublishedApplicationRelease,
) -> Result<(), String> {
    if current.agent_sha256 != previous.agent_sha256 {
        let previous_agent = remote_file_sha(authority, REMOTE_PREVIOUS_AGENT)?;
        if previous_agent.as_deref() != Some(previous.agent_sha256.as_str()) {
            return Err(
                "rollback blocked: previous edge-agent artifact does not match published previous release"
                    .to_owned(),
            );
        }
    }
    let previous_bundle = read_remote_bundle_release(authority, REMOTE_PREVIOUS_STACK_RELEASE)?;
    if previous_bundle
        .as_ref()
        .map(|value| value.bundle_digest.as_str())
        != Some(previous.bundle_digest.as_str())
    {
        return Err(
            "rollback blocked: previous application bundle does not match published previous release"
                .to_owned(),
        );
    }
    Ok(())
}

fn proto_bootstrap_mode(mode: ApplicationBootstrapMode) -> BootstrapMode {
    match mode {
        ApplicationBootstrapMode::Base => BootstrapMode::BootstrapBase,
        ApplicationBootstrapMode::Tunnel => BootstrapMode::BootstrapTunnel,
        ApplicationBootstrapMode::Full => BootstrapMode::BootstrapFull,
    }
}

fn validate_lower_hex(label: &str, value: &str, expected_len: usize) -> Result<(), String> {
    if value.len() != expected_len
        || !value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must be exactly {expected_len} lowercase hexadecimal characters"
        ));
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

fn unique_temp_file(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_controller_core::application_lifecycle::{
        ApplicationBootstrapMode, ApplicationRuntimePolicy, Line2RuntimePolicy,
    };

    fn test_desired(bundle_root: &str) -> DesiredApplicationState {
        DesiredApplicationState {
            schema: 2,
            environment: "test".to_owned(),
            vultr_spec_path: "infra/vultr/test.json".to_owned(),
            machine_id: "edge-1".to_owned(),
            application_profile: "edge-stack".to_owned(),
            bundle_root: bundle_root.to_owned(),
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

    fn test_artifact() -> AgentArtifactManifest {
        AgentArtifactManifest {
            schema: 1,
            source_revision: "1".repeat(40),
            sha256: "2".repeat(64),
        }
    }

    #[test]
    fn bundle_requires_runtime_secret_without_committing_it() {
        let root = unique_temp_file("application-bundle-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
        fs::write(stack.join("bootstrap.sh"), "#!/bin/sh\n").unwrap();

        let desired = test_desired("stack");
        let error =
            prepare_application_bundle(&root, &desired, &test_artifact(), None).unwrap_err();
        assert!(error.contains("runtime credential material is required"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bundle_digest_binds_private_runtime_material() {
        let root = unique_temp_file("application-bundle-digest-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
        fs::write(stack.join("bootstrap.sh"), "#!/bin/sh\n").unwrap();
        let env_a = root.join("env-a");
        let env_b = root.join("env-b");
        fs::write(&env_a, "PROXY_PASSWORD=0123456789abcdef\n").unwrap();
        fs::write(&env_b, "PROXY_PASSWORD=fedcba9876543210\n").unwrap();

        let desired = test_desired("stack");
        let a =
            prepare_application_bundle(&root, &desired, &test_artifact(), Some(&env_a)).unwrap();
        let b =
            prepare_application_bundle(&root, &desired, &test_artifact(), Some(&env_b)).unwrap();
        assert_ne!(a.release.bundle_digest, b.release.bundle_digest);
        assert!(
            a.request
                .stack_files
                .iter()
                .find(|file| file.relative_path == ".env.runtime")
                .unwrap()
                .sensitive
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_only_upgrade_gets_distinct_exact_release_identity() {
        let root = unique_temp_file("application-release-identity-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
        fs::write(stack.join("bootstrap.sh"), "#!/bin/sh\n").unwrap();
        let env_a = root.join("env-a");
        let env_b = root.join("env-b");
        fs::write(&env_a, "PROXY_PASSWORD=0123456789abcdef\n").unwrap();
        fs::write(&env_b, "PROXY_PASSWORD=fedcba9876543210\n").unwrap();

        let desired = test_desired("stack");
        let a =
            prepare_application_bundle(&root, &desired, &test_artifact(), Some(&env_a)).unwrap();
        let b =
            prepare_application_bundle(&root, &desired, &test_artifact(), Some(&env_b)).unwrap();

        assert_ne!(a.release.bundle_digest, b.release.bundle_digest);
        assert_ne!(a.release.release_id, b.release.release_id);
        assert_eq!(a.release.agent_sha256, b.release.agent_sha256);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_secret_schema_rejects_unknown_and_duplicate_keys() {
        let root = unique_temp_file("application-runtime-secret-schema-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();

        let unknown = root.join("unknown");
        fs::write(
            &unknown,
            "PROXY_PASSWORD=0123456789abcdef\nMESH_NODE_TOKEN=forbidden\n",
        )
        .unwrap();
        let error = prepare_application_bundle(
            &root,
            &test_desired("stack"),
            &test_artifact(),
            Some(&unknown),
        )
        .unwrap_err();
        assert!(error.contains("unexpected=[MESH_NODE_TOKEN]"));

        let duplicate = root.join("duplicate");
        fs::write(
            &duplicate,
            "PROXY_PASSWORD=0123456789abcdef\nPROXY_PASSWORD=fedcba9876543210\n",
        )
        .unwrap();
        let error = prepare_application_bundle(
            &root,
            &test_desired("stack"),
            &test_artifact(),
            Some(&duplicate),
        )
        .unwrap_err();
        assert!(error.contains("duplicated"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_env_is_composed_from_public_policy_and_private_credentials() {
        let root = unique_temp_file("application-runtime-composition-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
        let secret = root.join("secret");
        fs::write(&secret, "PROXY_PASSWORD=0123456789abcdef\n").unwrap();

        let prepared = prepare_application_bundle(
            &root,
            &test_desired("stack"),
            &test_artifact(),
            Some(&secret),
        )
        .unwrap();
        let runtime = prepared
            .request
            .stack_files
            .iter()
            .find(|file| file.relative_path == ".env.runtime")
            .unwrap();
        let content = String::from_utf8(runtime.content.clone()).unwrap();
        assert_eq!(
            content,
            "PROXY_USERNAME=acceptance\nPROXY_PASSWORD=0123456789abcdef\nPROXY_CERT_CN=application-acceptance.local\n"
        );
        assert!(runtime.sensitive);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committed_runtime_env_is_rejected() {
        let root = unique_temp_file("application-bundle-secret-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join(".env.runtime"), "TOKEN=committed\n").unwrap();
        let env_path = root.join("env");
        fs::write(&env_path, "PROXY_PASSWORD=0123456789abcdef\n").unwrap();

        let error = prepare_application_bundle(
            &root,
            &test_desired("stack"),
            &test_artifact(),
            Some(&env_path),
        )
        .unwrap_err();
        assert!(error.contains("must not contain .env.runtime"));

        fs::remove_dir_all(root).unwrap();
    }
}
