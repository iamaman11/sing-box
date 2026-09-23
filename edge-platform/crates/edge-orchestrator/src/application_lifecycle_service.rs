use crate::vultr_host_bootstrap::{
    StrictSshTunnelGuard, start_strict_agent_tunnel, strict_scp_upload, strict_ssh_capture,
    strict_ssh_run,
};
use edge_controller_core::application_lifecycle::{
    AgentArtifactManifest, ApplicationAction, ApplicationBootstrapMode, ApplicationObservation,
    ApplicationPlan, ApplicationPlanClass, ApplicationRecoveryAction, ApplicationRecoveryObservation,
    ApplicationRecoveryPlan, ApplicationRecoveryPlanClass, DesiredApplicationState,
    PublishedApplicationRelease, RollbackPlan, authorize_rollback, build_rollback_plan,
    desired_bundle_id, desired_release, plan_application, plan_incomplete_upgrade_recovery,
};
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_shared_types::agent_service_client::AgentServiceClient;
use edge_shared_types::{
    ApplyBundleRequest, BootstrapMode, BootstrapRuntimeRequest, BundleFile, Ipv4NetworkObservation,
    MeshRuntimeConvergeRequest, MeshRuntimeState, RollbackBundleRequest, VerifyRuntimeRequest,
    canonical_apply_bundle_digest,
};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
const REMOTE_STAGING_STACK_RELEASE: &str =
    "/opt/vultr-edge-stack/stack.next/.application-release.json";
const REMOTE_CONTROL_RELEASE: &str = "/opt/vultr-edge-stack/application-release.json";
const REMOTE_CONTROL_RELEASE_STAGING: &str = "/tmp/singbox-application-release.json.tmp";
const AGENT_DROPIN_PATH: &str =
    "/etc/systemd/system/edge-agent.service.d/90-application-control.conf";
const AGENT_DROPIN_CONTENT: &str =
    "[Service]\nEnvironment=EDGE_AGENT_ADDR=127.0.0.1:50061\nEnvironmentFile=\n";
const READ_ONLY_RUNTIME_REOBSERVE_ATTEMPTS: usize = 45;
const READ_ONLY_RUNTIME_REOBSERVE_DELAY: Duration = Duration::from_secs(2);
const UNCERTAIN_BUNDLE_REOBSERVE_ATTEMPTS: usize = 45;
const UNCERTAIN_BUNDLE_REOBSERVE_DELAY: Duration = Duration::from_secs(2);

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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ApplicationRecoveryExecutionReport {
    pub initial_plan: ApplicationRecoveryPlan,
    pub final_plan: ApplicationRecoveryPlan,
    pub final_observation: ApplicationRecoveryObservation,
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
            "committed application bundle must not contain .env.runtime; the VM derives it from Git-owned policy and VM-owned credentials"
                .to_owned(),
        );
    }
    if bundle_root.join(".env.runtime.policy").exists() {
        return Err(
            "committed application bundle must not contain .env.runtime.policy; runtime policy is derived only from application desired state"
                .to_owned(),
        );
    }
    validate_materialized_image_environment(&bundle_root.join(".images.env"))?;

    let mut stack_files = Vec::new();
    collect_bundle_files(&bundle_root, &bundle_root, &mut stack_files)?;

    stack_files.push(BundleFile {
        relative_path: ".env.runtime.policy".to_owned(),
        content: render_runtime_policy_environment(desired).into_bytes(),
        executable: false,
        sensitive: false,
    });

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

fn validate_materialized_image_environment(path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "exact application image environment is missing or unreadable at {}: {err}",
            path.display()
        )
    })?;
    let mut values = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "application image environment line {} must use KEY=VALUE syntax",
                index + 1
            )
        })?;
        if key.is_empty() || key.trim() != key || value.is_empty() {
            return Err(format!(
                "application image environment line {} is invalid",
                index + 1
            ));
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!(
                "application image environment contains duplicate key: {key}"
            ));
        }
    }

    let expected = BTreeSet::from([
        "EDGE_GATEWAY_IMAGE",
        "EDGE_WARP_EGRESS_IMAGE",
        "CLOUDFLARE_MESH_IMAGE",
    ]);
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(
            "application image environment must contain exactly EDGE_GATEWAY_IMAGE, EDGE_WARP_EGRESS_IMAGE, and CLOUDFLARE_MESH_IMAGE"
                .to_owned(),
        );
    }
    validate_exact_image_ref(
        "EDGE_GATEWAY_IMAGE",
        values.get("EDGE_GATEWAY_IMAGE").unwrap(),
        "ghcr.io/iamaman11/vultr-edge-gateway",
    )?;
    validate_exact_image_ref(
        "EDGE_WARP_EGRESS_IMAGE",
        values.get("EDGE_WARP_EGRESS_IMAGE").unwrap(),
        "ghcr.io/iamaman11/vultr-warp-egress",
    )?;
    validate_exact_image_ref(
        "CLOUDFLARE_MESH_IMAGE",
        values.get("CLOUDFLARE_MESH_IMAGE").unwrap(),
        "docker.io/cloudflare/mesh",
    )?;
    Ok(())
}

fn validate_exact_image_ref(label: &str, value: &str, repository: &str) -> Result<(), String> {
    let prefix = format!("{repository}@sha256:");
    let digest = value
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("{label} must reference exact repository {repository} by digest"))?;
    validate_lower_hex(label, digest, 64)
}

fn render_runtime_policy_environment(desired: &DesiredApplicationState) -> String {
    let mut values = Vec::new();
    if let Some(line2) = desired.runtime_policy.line2.as_ref() {
        values.push(("PROXY_USERNAME", line2.proxy_username.as_str()));
        values.push(("PROXY_CERT_CN", line2.proxy_cert_cn.as_str()));
    }
    if let Some(line1) = desired.runtime_policy.line1.as_ref() {
        values.push(("REALITY_SERVER_NAME", line1.reality_server_name.as_str()));
        values.push(("TUNNEL_DOMAIN", line1.tunnel_domain.as_str()));
        values.push(("ACME_EMAIL", line1.acme_email.as_str()));
        values.push(("ACME_PROVIDER", line1.acme_provider.as_str()));
    }

    values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect()
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

pub(crate) async fn observe_application_recovery(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
) -> Result<ApplicationRecoveryObservation, String> {
    let application = observe_application(authority, desired).await?;
    let backup_agent_sha256 = remote_file_sha(authority, REMOTE_PREVIOUS_AGENT)?;
    let backup_bundle_digest =
        read_remote_bundle_release(authority, REMOTE_PREVIOUS_STACK_RELEASE)?
            .map(|value| value.bundle_digest);
    Ok(ApplicationRecoveryObservation {
        application,
        backup_agent_sha256,
        backup_bundle_digest,
    })
}

pub(crate) async fn execute_desired(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    artifact_path: &Path,
    prepared: &PreparedApplicationBundle,
    authorized_plan_digest: &str,
    mode: DesiredMutationMode,
) -> Result<ApplicationExecutionReport, String> {
    verify_exact_agent_artifact(artifact, artifact_path)?;
    let initial_observation = observe_application(authority, desired).await?;
    let initial_plan = plan_application(
        desired,
        artifact,
        &prepared.release.bundle_digest,
        &initial_observation,
    )
    .map_err(|err| err.to_string())?;
    let authorized = authorize_application_plan(
        desired,
        artifact,
        &prepared.release.bundle_digest,
        &initial_observation,
        initial_plan.clone(),
    )?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
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

pub(crate) fn authorize_application_plan(
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    bundle_digest: &str,
    observation: &ApplicationObservation,
    plan: ApplicationPlan,
) -> Result<AuthorizedPlan<ApplicationPlan>, String> {
    let disposition = match plan.class {
        ApplicationPlanClass::Noop => PlanDisposition::Noop,
        ApplicationPlanClass::Apply | ApplicationPlanClass::Upgrade => PlanDisposition::Mutate,
        ApplicationPlanClass::Blocked => PlanDisposition::Blocked,
    };
    let desired_material = serde_json::json!({
        "desired": desired,
        "artifact": artifact,
        "bundle_digest": bundle_digest,
    });
    authorize_plan(
        "application",
        &desired_material,
        observation,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub(crate) fn authorize_application_recovery(
    desired: &DesiredApplicationState,
    observation: &ApplicationRecoveryObservation,
    plan: ApplicationRecoveryPlan,
) -> Result<AuthorizedPlan<ApplicationRecoveryPlan>, String> {
    let disposition = match plan.class {
        ApplicationRecoveryPlanClass::Noop => PlanDisposition::Noop,
        ApplicationRecoveryPlanClass::Recover => PlanDisposition::Mutate,
        ApplicationRecoveryPlanClass::Blocked => PlanDisposition::Blocked,
    };
    authorize_plan(
        "application_recovery",
        desired,
        observation,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub(crate) async fn recovery_plan_remote(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
) -> Result<(ApplicationRecoveryObservation, ApplicationRecoveryPlan), String> {
    let observation = observe_application_recovery(authority, desired).await?;
    let plan =
        plan_incomplete_upgrade_recovery(desired, &observation).map_err(|err| err.to_string())?;
    Ok((observation, plan))
}

pub(crate) async fn execute_recovery(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
    authorized_plan_digest: &str,
) -> Result<ApplicationRecoveryExecutionReport, String> {
    let observation = observe_application_recovery(authority, desired).await?;
    let initial_plan =
        plan_incomplete_upgrade_recovery(desired, &observation).map_err(|err| err.to_string())?;
    let authorized =
        authorize_application_recovery(desired, &observation, initial_plan.clone())?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    match initial_plan.class {
        ApplicationRecoveryPlanClass::Blocked => {
            return Err(format!(
                "incomplete-upgrade recovery is blocked: {}",
                initial_plan.reasons.join("; ")
            ));
        }
        ApplicationRecoveryPlanClass::Noop => {
            return Ok(ApplicationRecoveryExecutionReport {
                final_plan: initial_plan.clone(),
                initial_plan,
                final_observation: observation,
            });
        }
        ApplicationRecoveryPlanClass::Recover => {}
    }

    let target = initial_plan.target_release.clone();
    let original_previous_release = observation.application.previous_release.clone();

    if initial_plan
        .actions
        .contains(&ApplicationRecoveryAction::RestoreBundle)
    {
        let expected_active = observation
            .application
            .observed_bundle_digest
            .as_deref()
            .ok_or_else(|| "recovery plan lost exact active bundle digest".to_owned())?;
        restore_bundle_from_backup_once(authority, expected_active, &target.bundle_digest).await?;
    }

    if initial_plan
        .actions
        .contains(&ApplicationRecoveryAction::RestoreAgent)
    {
        let expected_active = observation
            .application
            .observed_agent_sha256
            .as_deref()
            .ok_or_else(|| "recovery plan lost exact active edge-agent digest".to_owned())?;
        restore_agent_from_backup_once(authority, expected_active, &target.agent_sha256)?;
    }

    let final_observation = observe_application_recovery(authority, desired).await?;
    if final_observation.application.current_release.as_ref() != Some(&target)
        || final_observation.application.previous_release != original_previous_release
        || final_observation.application.observed_agent_sha256.as_deref()
            != Some(target.agent_sha256.as_str())
        || final_observation.application.observed_bundle_digest.as_deref()
            != Some(target.bundle_digest.as_str())
    {
        return Err(
            "incomplete-upgrade recovery did not converge exactly to published current release"
                .to_owned(),
        );
    }

    let final_plan = plan_incomplete_upgrade_recovery(desired, &final_observation)
        .map_err(|err| err.to_string())?;
    if final_plan.class != ApplicationRecoveryPlanClass::Noop {
        return Err(
            "incomplete-upgrade recovery completed but recovery plan did not converge to NOOP"
                .to_owned(),
        );
    }

    Ok(ApplicationRecoveryExecutionReport {
        initial_plan,
        final_plan,
        final_observation,
    })
}

pub(crate) fn authorize_application_rollback(
    desired: &DesiredApplicationState,
    observation: &ApplicationObservation,
    plan: RollbackPlan,
) -> Result<AuthorizedPlan<RollbackPlan>, String> {
    authorize_plan(
        "application_rollback",
        desired,
        observation,
        plan,
        PlanDisposition::Mutate,
    )
    .map_err(|err| err.to_string())
}

pub(crate) async fn verify_desired(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    prepared: &PreparedApplicationBundle,
) -> Result<(ApplicationPlan, ApplicationObservationView), String> {
    for attempt in 0..READ_ONLY_RUNTIME_REOBSERVE_ATTEMPTS {
        let observation = observe_application(authority, desired).await?;
        let plan = plan_application(
            desired,
            artifact,
            &prepared.release.bundle_digest,
            &observation,
        )
        .map_err(|err| err.to_string())?;

        if plan.class == ApplicationPlanClass::Noop
            || !exact_release_identity_observed(&observation, &prepared.release)
            || attempt + 1 == READ_ONLY_RUNTIME_REOBSERVE_ATTEMPTS
        {
            return Ok((plan, ApplicationObservationView::from(&observation)));
        }

        sleep(READ_ONLY_RUNTIME_REOBSERVE_DELAY).await;
    }

    unreachable!("bounded application verification loop always returns")
}

fn exact_release_identity_observed(
    observation: &ApplicationObservation,
    release: &PublishedApplicationRelease,
) -> bool {
    observation.observed_agent_sha256.as_deref() == Some(release.agent_sha256.as_str())
        && observation.observed_bundle_digest.as_deref() == Some(release.bundle_digest.as_str())
        && observation.current_release.as_ref() == Some(release)
}

pub(crate) async fn rollback_plan_remote(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
) -> Result<(ApplicationObservation, RollbackPlan), String> {
    let observation = observe_application(authority, desired).await?;
    let plan = build_rollback_plan(desired, &observation).map_err(|err| err.to_string())?;
    verify_previous_release_material(authority, &plan.current_release, &plan.previous_release)?;
    Ok((observation, plan))
}

pub(crate) async fn execute_rollback(
    authority: &ApplicationAuthority,
    desired: &DesiredApplicationState,
    authorized_digest: &str,
    authorized_plan_digest: &str,
) -> Result<ApplicationObservationView, String> {
    let observation = observe_application(authority, desired).await?;
    let current = build_rollback_plan(desired, &observation).map_err(|err| err.to_string())?;
    let generic = authorize_application_rollback(desired, &observation, current.clone())?;
    verify_exact_authority(authorized_plan_digest, &generic.authority)
        .map_err(|err| err.to_string())?;
    let plan = authorize_rollback(desired, &observation, authorized_digest)
        .map_err(|err| err.to_string())?;
    if current != plan {
        return Err("application rollback authorization changed during planning".to_owned());
    }
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
            executable: false,
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

fn exact_bundle_digest_observed(
    observed: Option<&BundleReleaseView>,
    expected_digest: &str,
) -> bool {
    observed.is_some_and(|value| value.bundle_digest == expected_digest)
}

fn bounded_detail(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn application_agent_forensic_summary(authority: &ApplicationAuthority) -> String {
    let command = format!(
        "marker_digest() {{ path=\"$1\"; if sudo test -f \"$path\"; then sudo jq -r '.bundle_digest // \"invalid\"' \"$path\" 2>/dev/null || printf invalid; else printf absent; fi; }}; active=$(marker_digest '{active}'); staging=$(marker_digest '{staging}'); previous=$(marker_digest '{previous}'); unit_active=$(systemctl is-active edge-agent.service 2>/dev/null || true); unit_sub=$(systemctl show edge-agent.service -p SubState --value 2>/dev/null || true); unit_result=$(systemctl show edge-agent.service -p Result --value 2>/dev/null || true); unit_restarts=$(systemctl show edge-agent.service -p NRestarts --value 2>/dev/null || true); unit_status=$(systemctl show edge-agent.service -p ExecMainStatus --value 2>/dev/null || true); listener=$(ss -ltnH 'sport = :50061' 2>/dev/null | wc -l | tr -d ' ' || true); boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true); printf 'active=%s staging=%s previous=%s unit_active=%s unit_sub=%s unit_result=%s unit_restarts=%s unit_status=%s listener=%s boot_id=%s' \"$active\" \"$staging\" \"$previous\" \"$unit_active\" \"$unit_sub\" \"$unit_result\" \"$unit_restarts\" \"$unit_status\" \"$listener\" \"$boot_id\"",
        active = REMOTE_STACK_RELEASE,
        staging = REMOTE_STAGING_STACK_RELEASE,
        previous = REMOTE_PREVIOUS_STACK_RELEASE,
    );
    match strict_ssh_capture(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &command,
    ) {
        Ok(value) => bounded_detail(&value, 1200),
        Err(err) => format!("forensic_unavailable={}", bounded_detail(&err, 512)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BundleObservationResolution {
    observation_attempts: usize,
}

async fn wait_for_exact_bundle_digest_after_uncertain_mutation(
    authority: &ApplicationAuthority,
    expected_digest: &str,
) -> Result<BundleObservationResolution, String> {
    validate_lower_hex("expected uncertain bundle digest", expected_digest, 64)?;
    let mut last_detail = "not-observed".to_owned();

    for attempt in 0..UNCERTAIN_BUNDLE_REOBSERVE_ATTEMPTS {
        match read_remote_bundle_release(authority, REMOTE_STACK_RELEASE) {
            Ok(observed) if exact_bundle_digest_observed(observed.as_ref(), expected_digest) => {
                return Ok(BundleObservationResolution {
                    observation_attempts: attempt + 1,
                });
            }
            Ok(Some(observed)) => {
                last_detail = format!("active_digest={}", observed.bundle_digest);
            }
            Ok(None) => {
                last_detail = "active_digest=absent".to_owned();
            }
            Err(err) => {
                last_detail = format!("observation_error={}", bounded_detail(&err, 512));
            }
        }

        if attempt + 1 < UNCERTAIN_BUNDLE_REOBSERVE_ATTEMPTS {
            sleep(UNCERTAIN_BUNDLE_REOBSERVE_DELAY).await;
        }
    }

    Err(format!(
        "desired bundle digest was not observed after {} bounded read-only observations; last={}; forensic={}",
        UNCERTAIN_BUNDLE_REOBSERVE_ATTEMPTS,
        last_detail,
        application_agent_forensic_summary(authority)
    ))
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

async fn execute_bundle_mutation_once<M, MFut, R, RFut>(
    operation: &'static str,
    expected_digest: &str,
    mutate: M,
    recover_uncertain: R,
) -> Result<(), String>
where
    M: FnOnce() -> MFut,
    MFut: std::future::Future<Output = Result<Option<String>, String>>,
    R: FnOnce(String) -> RFut,
    RFut: std::future::Future<Output = Result<(), String>>,
{
    match mutate().await {
        Ok(active_digest) if active_digest.as_deref() == Some(expected_digest) => Ok(()),
        Ok(active_digest) => Err(format!(
            "edge-agent {operation} returned unexpected active digest {active_digest:?}"
        )),
        Err(err) => recover_uncertain(err).await,
    }
}

fn record_bundle_mutation_resolved_by_observation(
    operation: &'static str,
    expected_digest: &str,
    resolution: BundleObservationResolution,
) {
    tracing::info!(
        component = "edge-controller",
        operation,
        expected_bundle_digest = %expected_digest,
        mutation_attempts = 1_u64,
        observation_attempts = resolution.observation_attempts as u64,
        rpc_replayed = false,
        resolution = "resolved_by_observation",
        event = "application.bundle_mutation.resolved_by_observation",
        "bundle mutation transport uncertainty resolved by exact read-only observation"
    );
}

async fn apply_bundle_once(
    authority: &ApplicationAuthority,
    prepared: &PreparedApplicationBundle,
) -> Result<(), String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    let expected_digest = prepared.release.bundle_digest.clone();
    let recovery_expected_digest = expected_digest.clone();
    execute_bundle_mutation_once(
        "ApplyBundle",
        &expected_digest,
        || async {
            client
                .apply_bundle(Request::new(prepared.request.clone()))
                .await
                .map(|response| response.get_ref().active_bundle_digest.clone())
                .map_err(|err| err.to_string())
        },
        |err| async move {
            match wait_for_exact_bundle_digest_after_uncertain_mutation(
                authority,
                &recovery_expected_digest,
            )
            .await
            {
                Ok(resolution) => {
                    record_bundle_mutation_resolved_by_observation(
                        "ApplyBundle",
                        &recovery_expected_digest,
                        resolution,
                    );
                    Ok(())
                }
                Err(observation) => Err(format!(
                    "ApplyBundle outcome is uncertain; RPC was not replayed: {err}; {observation}"
                )),
            }
        },
    )
    .await
}

async fn restore_bundle_from_backup_once(
    authority: &ApplicationAuthority,
    expected_active_digest: &str,
    target_backup_digest: &str,
) -> Result<(), String> {
    validate_lower_hex(
        "expected active recovery bundle digest",
        expected_active_digest,
        64,
    )?;
    validate_lower_hex(
        "target backup recovery bundle digest",
        target_backup_digest,
        64,
    )?;
    let active = read_remote_bundle_release(authority, REMOTE_STACK_RELEASE)?;
    if active.as_ref().map(|value| value.bundle_digest.as_str())
        != Some(expected_active_digest)
    {
        return Err(
            "active bundle digest changed since incomplete-upgrade recovery planning".to_owned(),
        );
    }
    let backup = read_remote_bundle_release(authority, REMOTE_PREVIOUS_STACK_RELEASE)?;
    if backup.as_ref().map(|value| value.bundle_digest.as_str())
        != Some(target_backup_digest)
    {
        return Err(
            "backup bundle digest changed since incomplete-upgrade recovery planning".to_owned(),
        );
    }

    let (mut client, _tunnel) = connect_agent(authority).await?;
    let expected_active = expected_active_digest.to_owned();
    let expected_target = target_backup_digest.to_owned();
    let recovery_target = expected_target.clone();
    execute_bundle_mutation_once(
        "RecoverPublishedBundle",
        &expected_target,
        || async {
            client
                .rollback_bundle(Request::new(RollbackBundleRequest {
                    expected_current_bundle_digest: expected_active,
                }))
                .await
                .map(|response| response.get_ref().active_bundle_digest.clone())
                .map_err(|err| err.to_string())
        },
        |err| async move {
            match wait_for_exact_bundle_digest_after_uncertain_mutation(
                authority,
                &recovery_target,
            )
            .await
            {
                Ok(resolution) => {
                    record_bundle_mutation_resolved_by_observation(
                        "RecoverPublishedBundle",
                        &recovery_target,
                        resolution,
                    );
                    Ok(())
                }
                Err(observation) => Err(format!(
                    "RecoverPublishedBundle outcome is uncertain; RPC was not replayed: {err}; {observation}"
                )),
            }
        },
    )
    .await
}

fn restore_agent_from_backup_once(
    authority: &ApplicationAuthority,
    expected_active_digest: &str,
    target_backup_digest: &str,
) -> Result<(), String> {
    validate_lower_hex(
        "expected active recovery edge-agent digest",
        expected_active_digest,
        64,
    )?;
    validate_lower_hex(
        "target backup recovery edge-agent digest",
        target_backup_digest,
        64,
    )?;
    if remote_file_sha(authority, REMOTE_AGENT)?.as_deref() != Some(expected_active_digest) {
        return Err(
            "active edge-agent digest changed since incomplete-upgrade recovery planning".to_owned(),
        );
    }
    if remote_file_sha(authority, REMOTE_PREVIOUS_AGENT)?.as_deref() != Some(target_backup_digest) {
        return Err(
            "backup edge-agent digest changed since incomplete-upgrade recovery planning".to_owned(),
        );
    }

    let command = format!(
        "set -eu; test \"$(sudo sha256sum {agent} | cut -d ' ' -f1)\" = '{expected_active}'; test \"$(sudo sha256sum {previous} | cut -d ' ' -f1)\" = '{expected_backup}'; sudo mv -f {agent} {agent}.recovery; if ! sudo mv -f {previous} {agent}; then sudo mv -f {agent}.recovery {agent}; exit 1; fi; sudo mv -f {agent}.recovery {previous}; sudo systemctl restart edge-agent.service; sudo systemctl is-active --quiet edge-agent.service",
        agent = REMOTE_AGENT,
        previous = REMOTE_PREVIOUS_AGENT,
        expected_active = expected_active_digest,
        expected_backup = target_backup_digest,
    );
    if let Err(err) = strict_ssh_run(
        &authority.target_ip,
        &authority.logical_hostname,
        &authority.operator_private_key_path,
        &authority.canonical_operator_public_key,
        &command,
    ) {
        let observed = remote_file_sha(authority, REMOTE_AGENT)?;
        if observed.as_deref() == Some(target_backup_digest) {
            return Ok(());
        }
        return Err(format!(
            "edge-agent incomplete-upgrade recovery outcome is uncertain; mutation was not replayed: {err}"
        ));
    }
    if remote_file_sha(authority, REMOTE_AGENT)?.as_deref() != Some(target_backup_digest) {
        return Err(
            "edge-agent incomplete-upgrade recovery did not reach published current digest"
                .to_owned(),
        );
    }
    Ok(())
}

async fn rollback_bundle_once(
    authority: &ApplicationAuthority,
    plan: &RollbackPlan,
) -> Result<(), String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    let expected_digest = plan.previous_release.bundle_digest.clone();
    let recovery_expected_digest = expected_digest.clone();
    let expected_current_digest = plan.current_release.bundle_digest.clone();
    execute_bundle_mutation_once(
        "RollbackBundle",
        &expected_digest,
        || async {
            client
                .rollback_bundle(Request::new(RollbackBundleRequest {
                    expected_current_bundle_digest: expected_current_digest,
                }))
                .await
                .map(|response| response.get_ref().active_bundle_digest.clone())
                .map_err(|err| err.to_string())
        },
        |err| async move {
            match wait_for_exact_bundle_digest_after_uncertain_mutation(
                authority,
                &recovery_expected_digest,
            )
            .await
            {
                Ok(resolution) => {
                    record_bundle_mutation_resolved_by_observation(
                        "RollbackBundle",
                        &recovery_expected_digest,
                        resolution,
                    );
                    Ok(())
                }
                Err(observation) => Err(format!(
                    "RollbackBundle outcome is uncertain; RPC was not replayed: {err}; {observation}"
                )),
            }
        },
    )
    .await
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
    let result = client
        .bootstrap_runtime(Request::new(BootstrapRuntimeRequest {
            mode: proto_bootstrap_mode(mode) as i32,
        }))
        .await;
    match result {
        Ok(response) => {
            let response = response.into_inner();
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
        Err(err) => match wait_for_runtime_ready_after_uncertain_bootstrap(authority, mode).await {
            Ok(()) => Ok(()),
            Err(observation) => Err(format!(
                "BootstrapRuntime outcome is uncertain; RPC was not replayed: {err}; {observation}"
            )),
        },
    }
}

async fn wait_for_runtime_ready_after_uncertain_bootstrap(
    authority: &ApplicationAuthority,
    mode: ApplicationBootstrapMode,
) -> Result<(), String> {
    let mut last_detail = "not-observed".to_owned();
    for attempt in 0..READ_ONLY_RUNTIME_REOBSERVE_ATTEMPTS {
        match verify_runtime_ready(authority, mode).await {
            Ok(true) => return Ok(()),
            Ok(false) => last_detail = "runtime_ready=false".to_owned(),
            Err(err) => {
                last_detail = format!("observation_error={}", bounded_detail(&err, 512));
            }
        }
        if attempt + 1 < READ_ONLY_RUNTIME_REOBSERVE_ATTEMPTS {
            sleep(READ_ONLY_RUNTIME_REOBSERVE_DELAY).await;
        }
    }
    Err(format!(
        "runtime readiness was not observed after {} bounded read-only observations; last={}; forensic={}",
        READ_ONLY_RUNTIME_REOBSERVE_ATTEMPTS,
        last_detail,
        application_agent_forensic_summary(authority)
    ))
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

pub(crate) async fn observe_ipv4_network_remote(
    authority: &ApplicationAuthority,
) -> Result<Ipv4NetworkObservation, String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    client
        .observe_ipv4_network(Request::new(edge_shared_types::Empty {}))
        .await
        .map_err(|err| format!("typed ObserveIpv4Network RPC failed: {err}"))
        .map(|response| response.into_inner())
}

pub(crate) async fn converge_mesh_runtime_remote(
    authority: &ApplicationAuthority,
    node_token: String,
) -> Result<MeshRuntimeState, String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    match client
        .converge_mesh_runtime(Request::new(MeshRuntimeConvergeRequest { node_token }))
        .await
    {
        Ok(response) => Ok(response.into_inner()),
        Err(err) => {
            let reobserved = verify_mesh_runtime_remote(authority).await.map_err(|observe_err| {
                format!(
                    "ConvergeMeshRuntime outcome is uncertain; RPC was not replayed: {err}; read-only re-observation failed: {observe_err}; forensic={}",
                    application_agent_forensic_summary(authority)
                )
            })?;
            if reobserved.runtime_ready {
                Ok(reobserved)
            } else {
                Err(format!(
                    "ConvergeMeshRuntime outcome is uncertain; RPC was not replayed: {err}; read-only re-observation did not reach READY: {}",
                    reobserved.warnings.join("; ")
                ))
            }
        }
    }
}

pub(crate) async fn verify_mesh_runtime_remote(
    authority: &ApplicationAuthority,
) -> Result<MeshRuntimeState, String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    let mut last_state = None;
    let mut last_error = None;

    for attempt in 0..READ_ONLY_RUNTIME_REOBSERVE_ATTEMPTS {
        match client
            .verify_mesh_runtime(Request::new(edge_shared_types::Empty {}))
            .await
        {
            Ok(response) => {
                let state = response.into_inner();
                if state.runtime_ready {
                    return Ok(state);
                }
                last_state = Some(state);
                last_error = None;
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }

        if attempt + 1 < READ_ONLY_RUNTIME_REOBSERVE_ATTEMPTS {
            sleep(READ_ONLY_RUNTIME_REOBSERVE_DELAY).await;
        }
    }

    if let Some(state) = last_state {
        return Ok(state);
    }

    Err(format!(
        "typed VerifyMeshRuntime RPC did not produce an observation after bounded re-observation: {}",
        last_error.unwrap_or_else(|| "no RPC observation completed".to_owned())
    ))
}

pub(crate) async fn cleanup_mesh_runtime_remote(
    authority: &ApplicationAuthority,
) -> Result<MeshRuntimeState, String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    match client
        .cleanup_mesh_runtime(Request::new(edge_shared_types::Empty {}))
        .await
    {
        Ok(response) => Ok(response.into_inner()),
        Err(err) => {
            let state = observe_mesh_runtime_remote_once(authority).await.map_err(|observe_err| {
                format!(
                    "CleanupMeshRuntime outcome is uncertain; RPC was not replayed: {err}; read-only re-observation failed: {observe_err}; forensic={}",
                    application_agent_forensic_summary(authority)
                )
            })?;
            if !state.token_store_present && !state.container_running {
                Ok(state)
            } else {
                Err(format!(
                    "CleanupMeshRuntime outcome is uncertain; RPC was not replayed: {err}; token_store_present={} container_running={}",
                    state.token_store_present, state.container_running
                ))
            }
        }
    }
}

async fn observe_mesh_runtime_remote_once(
    authority: &ApplicationAuthority,
) -> Result<MeshRuntimeState, String> {
    let (mut client, _tunnel) = connect_agent(authority).await?;
    client
        .verify_mesh_runtime(Request::new(edge_shared_types::Empty {}))
        .await
        .map_err(|err| format!("typed VerifyMeshRuntime RPC failed: {err}"))
        .map(|response| response.into_inner())
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

    #[test]
    fn exact_bundle_digest_observation_matches_only_exact_digest() {
        let observed = BundleReleaseView {
            schema: 1,
            bundle_id: "bundle-a".to_owned(),
            bundle_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        };
        assert!(exact_bundle_digest_observed(
            Some(&observed),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!exact_bundle_digest_observed(
            Some(&observed),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        assert!(!exact_bundle_digest_observed(
            None,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn bounded_detail_never_exceeds_requested_character_count() {
        assert_eq!(bounded_detail("abcdef", 4), "abcd");
        assert_eq!(bounded_detail("abc", 4), "abc");
    }

    #[tokio::test]
    async fn uncertain_bundle_transport_is_mutated_once_and_never_replayed() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mutation_calls = Arc::new(AtomicUsize::new(0));
        let recovery_calls = Arc::new(AtomicUsize::new(0));
        let mutation_counter = Arc::clone(&mutation_calls);
        let recovery_counter = Arc::clone(&recovery_calls);
        let expected_digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        execute_bundle_mutation_once(
            "ApplyBundle",
            expected_digest,
            || async move {
                mutation_counter.fetch_add(1, Ordering::SeqCst);
                Err::<Option<String>, String>("transport reset".to_owned())
            },
            |rpc_error| async move {
                recovery_counter.fetch_add(1, Ordering::SeqCst);
                assert_eq!(rpc_error, "transport reset");
                Ok(())
            },
        )
        .await
        .unwrap();

        assert_eq!(mutation_calls.load(Ordering::SeqCst), 1);
        assert_eq!(recovery_calls.load(Ordering::SeqCst), 1);
    }
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

    fn write_test_image_environment(stack: &Path) {
        fs::write(
            stack.join(".images.env"),
            concat!(
                "EDGE_GATEWAY_IMAGE=ghcr.io/iamaman11/vultr-edge-gateway@sha256:",
                "1111111111111111111111111111111111111111111111111111111111111111\n",
                "EDGE_WARP_EGRESS_IMAGE=ghcr.io/iamaman11/vultr-warp-egress@sha256:",
                "2222222222222222222222222222222222222222222222222222222222222222\n",
                "CLOUDFLARE_MESH_IMAGE=docker.io/cloudflare/mesh@sha256:",
                "3333333333333333333333333333333333333333333333333333333333333333\n",
            ),
        )
        .unwrap();
    }

    #[test]
    fn bundle_contains_public_runtime_policy_but_no_secret_env() {
        let root = unique_temp_file("application-bundle-policy-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
        write_test_image_environment(&stack);

        let prepared =
            prepare_application_bundle(&root, &test_desired("stack"), &test_artifact()).unwrap();
        let policy = prepared
            .request
            .stack_files
            .iter()
            .find(|file| file.relative_path == ".env.runtime.policy")
            .unwrap();
        assert_eq!(
            String::from_utf8(policy.content.clone()).unwrap(),
            "PROXY_USERNAME=acceptance\nPROXY_CERT_CN=application-acceptance.local\n"
        );
        assert!(!policy.sensitive);
        assert!(
            prepared
                .request
                .stack_files
                .iter()
                .all(|file| file.relative_path != ".env.runtime")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_release_identity_can_wait_for_readiness_without_masking_drift() {
        let desired = test_desired("stack");
        let artifact = test_artifact();
        let release = desired_release(&desired, &artifact, &"3".repeat(64)).unwrap();
        let mut observation = ApplicationObservation {
            observed_agent_sha256: Some(release.agent_sha256.clone()),
            observed_bundle_digest: Some(release.bundle_digest.clone()),
            runtime_ready: false,
            current_release: Some(release.clone()),
            previous_release: None,
        };

        assert!(exact_release_identity_observed(&observation, &release));

        observation.observed_bundle_digest = Some("4".repeat(64));
        assert!(!exact_release_identity_observed(&observation, &release));
    }

    #[test]
    fn public_runtime_policy_changes_exact_release_identity() {
        let root = unique_temp_file("application-public-policy-digest-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();
        write_test_image_environment(&stack);

        let a_desired = test_desired("stack");
        let mut b_desired = a_desired.clone();
        b_desired
            .runtime_policy
            .line2
            .as_mut()
            .unwrap()
            .proxy_username = "acceptance-v2".to_owned();

        let a = prepare_application_bundle(&root, &a_desired, &test_artifact()).unwrap();
        let b = prepare_application_bundle(&root, &b_desired, &test_artifact()).unwrap();

        assert_ne!(a.release.bundle_digest, b.release.bundle_digest);
        assert_ne!(a.release.release_id, b.release.release_id);
        assert_eq!(a.release.agent_sha256, b.release.agent_sha256);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_exact_image_environment_is_rejected_before_bundle_application() {
        let root = unique_temp_file("application-image-authority-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join("docker-compose.yml"), "services: {}\n").unwrap();

        let error = prepare_application_bundle(&root, &test_desired("stack"), &test_artifact())
            .unwrap_err();
        assert!(error.contains("image environment is missing or unreadable"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committed_runtime_env_is_rejected() {
        let root = unique_temp_file("application-bundle-secret-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(stack.join(".env.runtime"), "TOKEN=committed\n").unwrap();

        let error = prepare_application_bundle(&root, &test_desired("stack"), &test_artifact())
            .unwrap_err();
        assert!(error.contains("must not contain .env.runtime"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committed_runtime_policy_is_rejected() {
        let root = unique_temp_file("application-bundle-policy-authority-test");
        let stack = root.join("stack");
        fs::create_dir_all(&stack).unwrap();
        fs::write(
            stack.join(".env.runtime.policy"),
            "PROXY_USERNAME=second-authority\n",
        )
        .unwrap();

        let error = prepare_application_bundle(&root, &test_desired("stack"), &test_artifact())
            .unwrap_err();
        assert!(error.contains("runtime policy is derived only from application desired state"));

        fs::remove_dir_all(root).unwrap();
    }
}
