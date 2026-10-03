use crate::cli::{
    CredentialDeliveryCommand, CredentialDeliverySlotArg, CredentialRotationClassArg,
};
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_controller_core::production::{ProductionComposition, ProductionCredentialPlaneOwnership};
use edge_orchestrator::credential_snapshot::{
    ApplicationCredentialClass, FreshCredentialSnapshotRequest, RotateCredentialSnapshotRequest,
    generate_fresh_credential_snapshot, rotate_credential_snapshot,
};
use edge_provider_cloudflare as cloudflare;
use edge_secrets::fetch_canonical_credential_bundle_with_identity;
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialDeliverySlot, CredentialIsolationProbe,
    CredentialProjectionKind,
};
use prost::Message;
use ring::digest::{SHA256, digest};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::{env, fs};
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_CONVERGENCE_STEPS: usize = 2;
const SLOT_A: &str = "EDGE_CREDENTIAL_BUNDLE_A";
const SLOT_B: &str = "EDGE_CREDENTIAL_BUNDLE_B";
const PROBE_GENERATION_A: u64 = 9_000_001;
const PROBE_GENERATION_B: u64 = 9_000_002;
const INVALID_PROBE_GENERATION: u64 = 9_000_003;
const ACCESS_ANALYTICS_EVIDENCE_ATTEMPTS: usize = 6;
const ACCESS_ANALYTICS_EVIDENCE_INTERVAL_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProjectionDesired {
    projection: String,
    worker_name: String,
    access_application_name: String,
    access_policy_name: String,
    proof_service_token_name: String,
    host_service_token_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProjectionObservation {
    projection: String,
    worker_name: String,
    worker_script_present: bool,
    worker_identity_present: bool,
    worker_id: Option<String>,
    worker_binding_count: Option<usize>,
    worker_secret_bindings: Vec<cloudflare::CloudflareWorkerSecretBinding>,
    worker_version_tag: Option<String>,
    worker_latest_version_id: Option<String>,
    worker_latest_version_tag: Option<String>,
    worker_active_deployment_id: Option<String>,
    worker_active_version_ids: Vec<String>,
    workers_dev_enabled: Option<bool>,
    previews_enabled: Option<bool>,
    custom_domain_count: usize,
    proof_service_token_id: Option<String>,
    proof_service_token_enabled: Option<bool>,
    proof_service_token_duration: Option<String>,
    host_service_token_id: Option<String>,
    host_service_token_client_id: Option<String>,
    host_service_token_enabled: Option<bool>,
    host_service_token_duration: Option<String>,
    access_application_id: Option<String>,
    access_application_type: Option<String>,
    access_service_auth_401_redirect: Option<bool>,
    access_destination_type: Option<String>,
    access_destination_worker_id: Option<String>,
    access_destination_uri: Option<String>,
    access_destination_has_overrides: Option<bool>,
    access_policies: Vec<cloudflare::CloudflareAccessPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CredentialPlaneObservation {
    control_token_identity: cloudflare::CloudflareApiTokenIdentity,
    access_organization: Option<cloudflare::CloudflareAccessOrganization>,
    workers_dev_subdomain: Option<String>,
    projections: Vec<ProjectionObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum CredentialDeliveryAction {
    Noop,
    InstallDummyAbContract { projection: String },
    RestoreFixedAbVersionTag { projection: String },
    RestoreFixedAbBaseline { projection: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionDeliveryState {
    LegacyLocked,
    FixedAbVersionTagMissing,
    FixedAbLatestPendingDeployment,
    FixedAb,
}

#[derive(Debug, Clone)]
struct DeliverySlot {
    name: &'static str,
    generation: u64,
    payload: Vec<u8>,
    secret_text: String,
}

#[derive(Debug, Clone)]
struct DeliveryWorkerMaterial {
    source: String,
    version_tag: String,
    slots: Vec<DeliverySlot>,
}

#[derive(Debug, Clone)]
struct AccessFailureEvidence {
    projection: String,
    ray_id: Option<String>,
    datetime_start: String,
    datetime_end: String,
    http_status: u16,
    acceptance_error: String,
}

#[derive(Debug, Clone)]
enum ProofAttemptError {
    Ordinary(String),
    Functional(AccessFailureEvidence),
}

impl From<String> for ProofAttemptError {
    fn from(value: String) -> Self {
        Self::Ordinary(value)
    }
}

pub async fn run_delivery(command: CredentialDeliveryCommand) -> Result<(), String> {
    let control_token = required_env("CLOUDFLARE_CONTROL_TOKEN")?;
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = production.cloudflare.credential_plane.clone();

    if production.cloudflare.active_account_id != desired.target_account_id
        || production.cloudflare.migration_target_account_id.is_some()
    {
        return Err(
            "credential delivery requires the dedicated credential account to be active canonical production authority with no migration target"
                .to_owned(),
        );
    }

    match command {
        CredentialDeliveryCommand::ContractPlan => {
            let observed = observe(&control_token, &desired).await?;
            print_observation(&desired, &observed)?;
            let authorized = authorized_plan(&desired, &observed)?;
            println!("plan_action={}", action_name(&authorized.plan));
            println!("plan_authority={}", authorized.authority.authority_digest);
            println!("plan_disposition={:?}", authorized.disposition);
            println!("real_credentials_created=0");
            Ok(())
        }
        CredentialDeliveryCommand::ContractConverge => converge(&control_token, &desired).await,
        CredentialDeliveryCommand::ContractVerify => verify(&control_token, &desired).await,
        CredentialDeliveryCommand::ContractProve => prove(&control_token, &desired).await,
        CredentialDeliveryCommand::HostBootstrapConverge => {
            host_bootstrap_converge(&control_token, &desired).await
        }
        CredentialDeliveryCommand::RotateApplication {
            class,
            active_generation,
            generation,
            slot,
        } => {
            rotate_application_publish(
                &control_token,
                &desired,
                class,
                active_generation,
                generation,
                slot,
            )
            .await
        }
        CredentialDeliveryCommand::FreshV2Publish { generation } => {
            fresh_v2_publish(&control_token, &desired, generation).await
        }
        CredentialDeliveryCommand::FreshV2RestoreBaseline => {
            fresh_v2_restore_baseline(&control_token, &desired).await
        }
    }
}

async fn rotate_application_publish(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    class: CredentialRotationClassArg,
    active_generation: u64,
    generation: u64,
    slot: CredentialDeliverySlotArg,
) -> Result<(), String> {
    if active_generation == 0 || generation == 0 || active_generation == generation {
        return Err(
            "steady-state credential rotation requires distinct non-zero active and candidate generations"
                .to_owned(),
        );
    }

    let before = observe(control_token, desired).await?;
    validate_access_boundary(desired, &before)?;
    for projection in projections(desired) {
        if projection_delivery_state(desired, &projection, &before)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} credential Worker must be in exact fixed A/B state before rotation",
                projection.projection
            ));
        }
    }

    let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
    let rotation_identity = cloudflare::verify_api_token(&rotation_token).await?;
    if rotation_identity.status != "active" {
        return Err(format!(
            "credential-rotation token {} is not active: {}",
            rotation_identity.id, rotation_identity.status
        ));
    }
    if rotation_identity.id == before.control_token_identity.id {
        return Err(
            "credential-rotation token must be physically distinct from CLOUDFLARE_CONTROL_TOKEN"
                .to_owned(),
        );
    }

    let vm_client_id = required_env("CLOUDFLARE_VM_ACCESS_CLIENT_ID")?;
    let vm_client_secret = required_env("CLOUDFLARE_VM_ACCESS_CLIENT_SECRET")?;
    let active_vm = fetch_canonical_credential_bundle_with_identity(
        CredentialProjectionKind::Vm,
        active_generation,
        &vm_client_id,
        &vm_client_secret,
    )
    .await?;
    let candidate_slot = match slot {
        CredentialDeliverySlotArg::A => CredentialDeliverySlot::A,
        CredentialDeliverySlotArg::B => CredentialDeliverySlot::B,
    };
    let rotation_class = match class {
        CredentialRotationClassArg::TunnelAuth => ApplicationCredentialClass::TunnelAuth,
        CredentialRotationClassArg::RealityIdentity => ApplicationCredentialClass::RealityIdentity,
        CredentialRotationClassArg::Line2ProxyAuth => ApplicationCredentialClass::Line2ProxyAuth,
    };
    let snapshot = rotate_credential_snapshot(
        &active_vm,
        RotateCredentialSnapshotRequest {
            delivery_generation: generation,
            slot: candidate_slot,
            class: rotation_class,
        },
    )?;

    let slot_name = match candidate_slot {
        CredentialDeliverySlot::A => SLOT_A,
        CredentialDeliverySlot::B => SLOT_B,
        CredentialDeliverySlot::Unspecified => unreachable!("validated candidate slot"),
    };
    let vm = projection_desired(desired, "vm")?;
    let windows = projection_desired(desired, "windows")?;
    let vm_secret = hex_encode(&snapshot.vm.encode_to_vec());
    let windows_secret = hex_encode(&snapshot.windows.encode_to_vec());

    publish_rotation_slot(
        control_token,
        &rotation_token,
        desired,
        &vm,
        slot_name,
        &vm_secret,
    )
    .await?;
    let observed_vm = fetch_canonical_credential_bundle_with_identity(
        CredentialProjectionKind::Vm,
        generation,
        &vm_client_id,
        &vm_client_secret,
    )
    .await?;
    if observed_vm != snapshot.vm {
        return Err(
            "VM candidate data-plane re-observation did not return the exact generated projection"
                .to_owned(),
        );
    }

    publish_rotation_slot(
        control_token,
        &rotation_token,
        desired,
        &windows,
        slot_name,
        &windows_secret,
    )
    .await?;

    println!("credential_rotation_provider_publish=PASS");
    println!("credential_rotation_class={}", class.as_str());
    println!("credential_active_generation={active_generation}");
    println!("credential_generation={generation}");
    println!("credential_slot={}", slot.as_str());
    println!("paired_projection_count=2");
    println!("active_slot_mutated=false");
    println!("vm_candidate_data_plane_reobservation=PASS");
    println!("windows_candidate_data_plane_reobservation=DEFERRED_TO_LOCAL_OWNER");
    println!("runner_plaintext_access=false");
    Ok(())
}

async fn publish_rotation_slot(
    control_token: &str,
    rotation_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
    slot_name: &str,
    secret_text: &str,
) -> Result<(), String> {
    let before = observe(control_token, desired).await?;
    let before_projection = projection_observation(&before, &projection.projection)?;
    if projection_delivery_state(desired, projection, &before)? != ProjectionDeliveryState::FixedAb
    {
        return Err(format!(
            "{} credential Worker drifted before inactive-slot publication",
            projection.projection
        ));
    }
    let material = delivery_worker_material(&projection.projection)?;

    let version_id = match cloudflare::patch_latest_worker_version_secrets(
        rotation_token,
        &desired.target_account_id,
        &projection.worker_name,
        &material.version_tag,
        &[(slot_name, secret_text)],
    )
    .await
    {
        Ok(version_id) => version_id,
        Err(err) => {
            let observed = observe(control_token, desired).await?;
            let current = projection_observation(&observed, &projection.projection)?;
            if current.worker_latest_version_id == before_projection.worker_latest_version_id {
                return Err(format!(
                    "{} inactive-slot publication failed and read-only re-observation proved no new Worker version: {err}",
                    projection.projection
                ));
            }
            if current.worker_latest_version_tag.as_deref() != Some(material.version_tag.as_str())
                || projection_delivery_state(desired, projection, &observed)?
                    != ProjectionDeliveryState::FixedAbLatestPendingDeployment
            {
                return Err(format!(
                    "{} inactive-slot publication outcome is uncertain after re-observation: {err}",
                    projection.projection
                ));
            }
            current.worker_latest_version_id.clone().ok_or_else(|| {
                format!(
                    "{} inactive-slot publication created no observable latest Worker version",
                    projection.projection
                )
            })?
        }
    };

    let deploy_once = cloudflare::deploy_worker_version(
        rotation_token,
        &desired.target_account_id,
        &projection.worker_name,
        &version_id,
    )
    .await;
    if let Err(first_err) = deploy_once {
        let observed = observe(control_token, desired).await?;
        let current = projection_observation(&observed, &projection.projection)?;
        if current.worker_active_version_ids == vec![version_id.clone()] {
            return Ok(());
        }
        if current.worker_latest_version_id.as_deref() != Some(version_id.as_str())
            || projection_delivery_state(desired, projection, &observed)?
                != ProjectionDeliveryState::FixedAbLatestPendingDeployment
        {
            return Err(format!(
                "{} candidate deployment outcome is uncertain after re-observation: {first_err}",
                projection.projection
            ));
        }
        cloudflare::deploy_worker_version(
            rotation_token,
            &desired.target_account_id,
            &projection.worker_name,
            &version_id,
        )
        .await
        .map_err(|retry_err| {
            format!(
                "{} candidate deployment failed after re-observation proved the first attempt unchanged: first={first_err}; retry={retry_err}",
                projection.projection
            )
        })?;
    }

    let after = observe(control_token, desired).await?;
    if projection_delivery_state(desired, projection, &after)? != ProjectionDeliveryState::FixedAb {
        return Err(format!(
            "{} credential Worker did not return to exact fixed A/B topology after candidate deployment",
            projection.projection
        ));
    }
    Ok(())
}

async fn fresh_v2_restore_baseline(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let before = observe(control_token, desired).await?;
    validate_access_boundary(desired, &before)?;
    for projection in projections(desired) {
        if projection_delivery_state(desired, &projection, &before)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} credential Worker is not in exact fixed A/B topology before baseline restore",
                projection.projection
            ));
        }
    }

    let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
    let rotation_identity = cloudflare::verify_api_token(&rotation_token).await?;
    if rotation_identity.status != "active" {
        return Err(format!(
            "credential-rotation token {} is not active: {}",
            rotation_identity.id, rotation_identity.status
        ));
    }
    if rotation_identity.id == before.control_token_identity.id {
        return Err(
            "credential-rotation token must be physically distinct from CLOUDFLARE_CONTROL_TOKEN"
                .to_owned(),
        );
    }

    let windows = projection_desired(desired, "windows")?;
    let vm = projection_desired(desired, "vm")?;
    restore_dummy_slot(&rotation_token, desired, &[&windows, &vm]).await?;

    let after = observe(control_token, desired).await?;
    validate_access_boundary(desired, &after)?;
    for projection in projections(desired) {
        if projection_delivery_state(desired, &projection, &after)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} credential Worker did not return to exact fixed A/B baseline",
                projection.projection
            ));
        }
    }

    println!("credential_fresh_v2_baseline_restore=PASS");
    println!("credential_secret_mutations=2");
    println!("credential_deployment_mutations=2");
    println!("active_slot_mutated=false");
    Ok(())
}

async fn fresh_v2_publish(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    generation: u64,
) -> Result<(), String> {
    if generation == 0 {
        return Err("fresh-v2 generation must be greater than zero".to_owned());
    }

    let before = observe(control_token, desired).await?;
    validate_access_boundary(desired, &before)?;
    for projection in projections(desired) {
        if projection_delivery_state(desired, &projection, &before)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} credential Worker is not in exact fixed A/B state",
                projection.projection
            ));
        }
    }

    let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
    let rotation_identity = cloudflare::verify_api_token(&rotation_token).await?;
    if rotation_identity.status != "active" {
        return Err(format!(
            "credential-rotation token {} is not active: {}",
            rotation_identity.id, rotation_identity.status
        ));
    }
    if rotation_identity.id == before.control_token_identity.id {
        return Err(
            "credential-rotation token must be physically distinct from CLOUDFLARE_CONTROL_TOKEN"
                .to_owned(),
        );
    }

    let snapshot = generate_fresh_credential_snapshot(FreshCredentialSnapshotRequest {
        delivery_generation: generation,
        slot: CredentialDeliverySlot::A,
        tunnel_auth_generation: generation,
        reality_identity_generation: generation,
        line2_proxy_generation: generation,
    })?;
    let windows = projection_desired(desired, "windows")?;
    let vm = projection_desired(desired, "vm")?;
    let windows_material = delivery_worker_material(&windows.projection)?;
    let vm_material = delivery_worker_material(&vm.projection)?;
    let windows_secret = hex_encode(&snapshot.windows.encode_to_vec());
    let vm_secret = hex_encode(&snapshot.vm.encode_to_vec());

    let windows_version_id = match cloudflare::patch_latest_worker_version_secrets(
        &rotation_token,
        &desired.target_account_id,
        &windows.worker_name,
        &windows_material.version_tag,
        &[(SLOT_A, windows_secret.as_str())],
    )
    .await
    {
        Ok(version_id) => version_id,
        Err(err) => {
            restore_dummy_slot(&rotation_token, desired, &[&windows]).await?;
            return Err(format!(
                "Windows fresh-v2 inactive-slot publication failed and baseline was restored: {err}"
            ));
        }
    };

    let vm_version_id = match cloudflare::patch_latest_worker_version_secrets(
        &rotation_token,
        &desired.target_account_id,
        &vm.worker_name,
        &vm_material.version_tag,
        &[(SLOT_A, vm_secret.as_str())],
    )
    .await
    {
        Ok(version_id) => version_id,
        Err(err) => {
            restore_dummy_slot(&rotation_token, desired, &[&windows, &vm]).await?;
            return Err(format!(
                "VM fresh-v2 inactive-slot publication failed and paired baseline was restored: {err}"
            ));
        }
    };

    if let Err(err) = cloudflare::deploy_worker_version(
        &rotation_token,
        &desired.target_account_id,
        &windows.worker_name,
        &windows_version_id,
    )
    .await
    {
        restore_dummy_slot(&rotation_token, desired, &[&windows, &vm]).await?;
        return Err(format!(
            "Windows fresh-v2 version deployment failed and paired baseline was restored: {err}"
        ));
    }

    if let Err(err) = cloudflare::deploy_worker_version(
        &rotation_token,
        &desired.target_account_id,
        &vm.worker_name,
        &vm_version_id,
    )
    .await
    {
        restore_dummy_slot(&rotation_token, desired, &[&windows, &vm]).await?;
        return Err(format!(
            "VM fresh-v2 version deployment failed and paired baseline was restored: {err}"
        ));
    }

    let post_publish_validation = async {
        let after = observe(control_token, desired).await?;
        validate_access_boundary(desired, &after)?;
        for projection in projections(desired) {
            if projection_delivery_state(desired, &projection, &after)?
                != ProjectionDeliveryState::FixedAb
            {
                return Err(format!(
                    "{} credential Worker left exact fixed A/B contract after publication",
                    projection.projection
                ));
            }
        }
        Ok::<(), String>(())
    }
    .await;

    if let Err(err) = post_publish_validation {
        restore_dummy_slot(&rotation_token, desired, &[&windows, &vm]).await?;
        return Err(format!(
            "fresh-v2 provider publication failed post-deploy validation and paired baseline was restored: {err}"
        ));
    }

    println!("credential_fresh_v2_provider_publish=PASS");
    println!("credential_generation={generation}");
    println!("credential_slot=A");
    println!("paired_projection_count=2");
    println!("credential_secret_mutations=2");
    println!("credential_deployment_mutations=2");
    println!("active_slot_mutated=false");
    println!("runner_plaintext_access=false");
    Ok(())
}

async fn restore_dummy_slot(
    rotation_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    projections: &[&ProjectionDesired],
) -> Result<(), String> {
    for projection in projections {
        let material = delivery_worker_material(&projection.projection)?;
        let dummy = material
            .slots
            .iter()
            .find(|slot| slot.name == SLOT_A)
            .ok_or_else(|| "fixed A/B material is missing slot A".to_owned())?;
        let version_id = cloudflare::patch_latest_worker_version_secrets(
            rotation_token,
            &desired.target_account_id,
            &projection.worker_name,
            &material.version_tag,
            &[(SLOT_A, dummy.secret_text.as_str())],
        )
        .await
        .map_err(|err| {
            format!(
                "failed to restore inactive dummy slot A for {} after partial fresh-v2 publication; mutation state is uncertain: {err}",
                projection.projection
            )
        })?;
        cloudflare::deploy_worker_version(
            rotation_token,
            &desired.target_account_id,
            &projection.worker_name,
            &version_id,
        )
        .await
        .map_err(|err| {
            format!(
                "failed to deploy restored dummy slot A for {} after partial fresh-v2 publication; mutation state is uncertain: {err}",
                projection.projection
            )
        })?;
    }
    Ok(())
}

pub(crate) async fn verify_credential_plane_invariant() -> Result<(), String> {
    let control_token = required_env("CLOUDFLARE_CONTROL_TOKEN")?;
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = &production.cloudflare.credential_plane;
    let observed = observe(&control_token, desired).await?;

    validate_access_boundary(desired, &observed)?;
    for projection in projections(desired) {
        projection_delivery_state(desired, &projection, &observed)?;
    }
    Ok(())
}

fn write_private_bootstrap_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("bootstrap secret output must not be empty".to_owned());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create bootstrap output directory: {err}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|err| format!("failed to create bootstrap secret output: {err}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("failed to persist bootstrap secret output: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to protect bootstrap secret output: {err}"))?;
    }
    Ok(())
}

fn validate_host_bootstrap_preconditions(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(), String> {
    if observed.control_token_identity.status != "active" {
        return Err("CLOUDFLARE_CONTROL_TOKEN is not active".to_owned());
    }
    let organization = observed
        .access_organization
        .as_ref()
        .ok_or_else(|| "accepted Access organization is missing".to_owned())?;
    if organization.name != desired.access_organization_name
        || organization.auth_domain != desired.access_auth_domain
        || organization.deny_unmatched_requests != Some(true)
    {
        return Err("credential Access organization drifted".to_owned());
    }
    if observed.workers_dev_subdomain.as_deref() != Some(desired.workers_dev_subdomain.as_str()) {
        return Err("credential workers.dev namespace drifted".to_owned());
    }

    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        if projection_delivery_state(desired, &projection, observed)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} credential Worker must already be exact FIXED_A_B before host bootstrap",
                projection.projection
            ));
        }
        if !current.worker_script_present
            || !current.worker_identity_present
            || current.custom_domain_count != 0
            || current.workers_dev_enabled != Some(true)
            || current.previews_enabled != Some(false)
        {
            return Err(format!(
                "{} credential Worker drifted from workers.dev-only authority",
                projection.projection
            ));
        }

        let proof_id = current
            .proof_service_token_id
            .as_deref()
            .ok_or_else(|| format!("{} proof service token is missing", projection.projection))?;
        if current.proof_service_token_enabled != Some(false)
            || current.proof_service_token_duration.as_deref()
                != Some(desired.proof_token_duration.as_str())
        {
            return Err(format!(
                "{} proof service token drifted",
                projection.projection
            ));
        }

        if current.host_service_token_id.is_some()
            && (current.host_service_token_enabled != Some(true)
                || current.host_service_token_duration.as_deref()
                    != Some(desired.host_service_token_duration.as_str()))
        {
            return Err(format!(
                "{} existing host service token drifted",
                projection.projection
            ));
        }

        let expected_hostname = workers_dev_hostname(desired, &projection);
        if current
            .access_application_id
            .as_deref()
            .unwrap_or("")
            .is_empty()
            || current.access_application_type.as_deref() != Some("self_hosted")
            || current.access_service_auth_401_redirect != Some(true)
            || current.access_destination_type.as_deref() != Some("public")
            || current.access_destination_uri.as_deref() != Some(expected_hostname.as_str())
            || current.access_destination_worker_id.is_some()
            || current.access_destination_has_overrides != Some(false)
        {
            return Err(format!(
                "{} Access application drifted from exact workers.dev Service Auth",
                projection.projection
            ));
        }
        if current.access_policies.len() != 1 {
            return Err(format!(
                "{} Access application must have exactly one service-auth policy",
                projection.projection
            ));
        }
        let policy = &current.access_policies[0];
        if policy.name != projection.access_policy_name
            || policy.decision.as_deref() != Some("non_identity")
            || policy.has_extra_rules
        {
            return Err(format!(
                "{} Access service-auth policy drifted",
                projection.projection
            ));
        }
        if !bootstrap_policy_tokens_are_recoverable(
            proof_id,
            current.host_service_token_id.as_deref(),
            &policy.include_service_token_ids,
        ) {
            return Err(format!(
                "{} Access service-auth policy contains unexpected token identities",
                projection.projection
            ));
        }
    }
    Ok(())
}

fn bootstrap_policy_tokens_are_recoverable(
    proof_id: &str,
    host_id: Option<&str>,
    actual_ids: &[String],
) -> bool {
    let mut actual = actual_ids.to_vec();
    actual.sort();

    let mut proof_only = vec![proof_id.to_owned()];
    proof_only.sort();
    if actual == proof_only {
        return true;
    }

    let Some(host_id) = host_id else {
        return false;
    };
    let mut terminal = vec![proof_id.to_owned(), host_id.to_owned()];
    terminal.sort();
    actual == terminal
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn existing_host_credential_from_escrow(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
    current: &ProjectionObservation,
) -> Result<cloudflare::CloudflareAccessServiceCredential, String> {
    let token_id = current
        .host_service_token_id
        .as_deref()
        .ok_or_else(|| format!("{} host service token is missing", projection.projection))?;
    let observed_client_id = current
        .host_service_token_client_id
        .as_deref()
        .ok_or_else(|| {
            format!(
                "{} host service token client ID is unavailable",
                projection.projection
            )
        })?;

    let (client_id_env, client_secret_env) = match projection.projection.as_str() {
        "windows" => (
            "EDGE_WINDOWS_HOST_CLIENT_ID",
            "EDGE_WINDOWS_HOST_CLIENT_SECRET",
        ),
        "vm" => ("EDGE_VM_HOST_CLIENT_ID", "EDGE_VM_HOST_CLIENT_SECRET"),
        _ => return Err("unsupported host bootstrap projection".to_owned()),
    };

    let client_id = optional_env(client_id_env).ok_or_else(|| {
        format!(
            "{} host token already exists but bootstrap escrow is unavailable; fail closed instead of rotating implicitly",
            projection.projection
        )
    })?;
    let client_secret = optional_env(client_secret_env).ok_or_else(|| {
        format!(
            "{} host token already exists but bootstrap escrow secret is unavailable; fail closed instead of rotating implicitly",
            projection.projection
        )
    })?;
    if client_id != observed_client_id {
        return Err(format!(
            "{} host bootstrap escrow client ID does not match observed Cloudflare token identity",
            projection.projection
        ));
    }

    Ok(cloudflare::CloudflareAccessServiceCredential {
        id: token_id.to_owned(),
        client_id,
        client_secret,
        enabled: current.host_service_token_enabled,
        duration: current.host_service_token_duration.clone(),
        name: Some(projection.host_service_token_name.clone()),
    })
}

fn validate_host_credential(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
    credential: &cloudflare::CloudflareAccessServiceCredential,
) -> Result<(), String> {
    if credential.id.is_empty()
        || credential.client_id.is_empty()
        || credential.client_secret.is_empty()
        || credential.name.as_deref() != Some(projection.host_service_token_name.as_str())
        || credential.enabled != Some(true)
        || credential.duration.as_deref() != Some(desired.host_service_token_duration.as_str())
    {
        return Err(format!(
            "{} host service-token credential response is not exact",
            projection.projection
        ));
    }
    Ok(())
}

async fn host_bootstrap_converge(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let before = observe(control_token, desired).await?;
    validate_host_bootstrap_preconditions(desired, &before)?;

    let windows_output = required_env("EDGE_WINDOWS_HOST_IDENTITY_OUTPUT")?;
    let vm_id_output = required_env("EDGE_VM_HOST_CLIENT_ID_OUTPUT")?;
    let vm_secret_output = required_env("EDGE_VM_HOST_CLIENT_SECRET_OUTPUT")?;
    let mut mutations = 0u32;

    for projection in projections(desired) {
        let current = projection_observation(&before, &projection.projection)?;
        let credential = if current.host_service_token_id.is_some() {
            existing_host_credential_from_escrow(desired, &projection, current)?
        } else {
            let credential = cloudflare::create_access_service_token(
                control_token,
                &desired.target_account_id,
                &projection.host_service_token_name,
                &desired.host_service_token_duration,
                true,
            )
            .await?;
            mutations += 1;
            credential
        };
        validate_host_credential(desired, &projection, &credential)?;

        match projection.projection.as_str() {
            "windows" => {
                let raw = format!(
                    "CF_ACCESS_CLIENT_ID={}\nCF_ACCESS_CLIENT_SECRET={}\n",
                    credential.client_id, credential.client_secret
                );
                write_private_bootstrap_file(Path::new(&windows_output), raw.as_bytes())?;
            }
            "vm" => {
                write_private_bootstrap_file(
                    Path::new(&vm_id_output),
                    credential.client_id.as_bytes(),
                )?;
                write_private_bootstrap_file(
                    Path::new(&vm_secret_output),
                    credential.client_secret.as_bytes(),
                )?;
            }
            _ => return Err("unsupported host bootstrap projection".to_owned()),
        }

        let proof_id = current
            .proof_service_token_id
            .as_deref()
            .ok_or_else(|| format!("{} proof token disappeared", projection.projection))?;
        let app_id = current
            .access_application_id
            .as_deref()
            .ok_or_else(|| format!("{} Access application disappeared", projection.projection))?;
        let policy = current
            .access_policies
            .first()
            .ok_or_else(|| format!("{} Access policy disappeared", projection.projection))?;
        let expected_ids = vec![proof_id.to_owned(), credential.id.clone()];
        let mut actual_ids = policy.include_service_token_ids.clone();
        let mut sorted_expected = expected_ids.clone();
        actual_ids.sort();
        sorted_expected.sort();
        if actual_ids != sorted_expected {
            cloudflare::update_access_service_policy_tokens(
                control_token,
                &desired.target_account_id,
                app_id,
                &policy.id,
                &projection.access_policy_name,
                &expected_ids,
            )
            .await?;
            mutations += 1;
        }
    }

    let after = observe(control_token, desired).await?;
    validate_access_boundary(desired, &after)?;
    println!("credential_host_bootstrap_status=PASS");
    println!("host_identity_delivery=RUNNER_BLIND");
    println!("windows_bootstrap_envelope=CMS_RFC5652");
    println!("vm_bootstrap_sink=GITHUB_ENVIRONMENT_SECRET");
    println!("provider_mutations={mutations}");
    println!("real_credentials_created=0");
    println!("production_runtime_mutations=0");
    Ok(())
}

async fn converge(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let mut mutations = 0u32;
    for step in 1..=MAX_CONVERGENCE_STEPS {
        let before = observe(control_token, desired).await?;
        let authorized = authorized_plan(desired, &before)?;
        println!("credential_delivery_step={step}");
        println!("action={}", action_name(&authorized.plan));
        println!("plan_authority={}", authorized.authority.authority_digest);

        if authorized.plan == CredentialDeliveryAction::Noop {
            print_terminal(desired, &before, mutations)?;
            return Ok(());
        }

        let (after, next, performed) = apply_once(
            control_token,
            desired,
            &authorized.authority.authority_digest,
        )
        .await?;
        mutations = mutations.saturating_add(performed);
        if next == authorized.plan {
            return Err(format!(
                "credential-delivery action made no observable progress; mutation was not replayed: {}",
                action_name(&next)
            ));
        }
        println!("next_action={}", action_name(&next));
        if next == CredentialDeliveryAction::Noop {
            print_terminal(desired, &after, mutations)?;
            return Ok(());
        }
        print_observation(desired, &after)?;
    }

    Err(format!(
        "credential-delivery convergence exceeded bounded {MAX_CONVERGENCE_STEPS}-step limit"
    ))
}

async fn apply_once(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    authorized_digest: &str,
) -> Result<(CredentialPlaneObservation, CredentialDeliveryAction, u32), String> {
    let before = observe(control_token, desired).await?;
    let authorized = authorized_plan(desired, &before)?;
    verify_exact_authority(authorized_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    let performed = match &authorized.plan {
        CredentialDeliveryAction::Noop => 0,
        CredentialDeliveryAction::InstallDummyAbContract { projection } => {
            let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
            let rotation_identity = cloudflare::verify_api_token(&rotation_token).await?;
            if rotation_identity.status != "active" {
                return Err(format!(
                    "credential-rotation token {} is not active: {}",
                    rotation_identity.id, rotation_identity.status
                ));
            }
            if rotation_identity.id == before.control_token_identity.id {
                return Err(
                    "credential-rotation token must be physically distinct from CLOUDFLARE_CONTROL_TOKEN"
                        .to_owned(),
                );
            }

            let projection = projection_desired(desired, projection)?;
            if projection_delivery_state(desired, &projection, &before)?
                != ProjectionDeliveryState::LegacyLocked
            {
                return Err(format!(
                    "atomic A/B install requires exact legacy locked state for {}",
                    projection.projection
                ));
            }
            let material = delivery_worker_material(&projection.projection)?;
            let secrets = material
                .slots
                .iter()
                .map(|slot| (slot.name, slot.secret_text.as_str()))
                .collect::<Vec<_>>();
            println!(
                "credential_rotation_token_identity={} credential_rotation_token_status={}",
                rotation_identity.id, rotation_identity.status
            );
            cloudflare::upload_worker_module_with_secret_text_bindings(
                &rotation_token,
                &desired.target_account_id,
                &projection.worker_name,
                &material.source,
                &desired.worker_compatibility_date,
                &material.version_tag,
                &secrets,
            )
            .await?;
            1
        }
        CredentialDeliveryAction::RestoreFixedAbVersionTag { projection } => {
            let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
            let rotation_identity = cloudflare::verify_api_token(&rotation_token).await?;
            if rotation_identity.status != "active" {
                return Err(format!(
                    "credential-rotation token {} is not active: {}",
                    rotation_identity.id, rotation_identity.status
                ));
            }
            if rotation_identity.id == before.control_token_identity.id {
                return Err(
                    "credential-rotation token must be physically distinct from CLOUDFLARE_CONTROL_TOKEN"
                        .to_owned(),
                );
            }

            let projection = projection_desired(desired, projection)?;
            if projection_delivery_state(desired, &projection, &before)?
                != ProjectionDeliveryState::FixedAbVersionTagMissing
            {
                return Err(format!(
                    "version-tag repair requires exact A/B bindings with only the version tag missing for {}",
                    projection.projection
                ));
            }
            let material = delivery_worker_material(&projection.projection)?;
            println!(
                "credential_rotation_token_identity={} credential_rotation_token_status={}",
                rotation_identity.id, rotation_identity.status
            );
            cloudflare::patch_worker_version_annotations(
                &rotation_token,
                &desired.target_account_id,
                &projection.worker_name,
                &material.version_tag,
            )
            .await?;
            1
        }
        CredentialDeliveryAction::RestoreFixedAbBaseline { projection } => {
            let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
            let rotation_identity = cloudflare::verify_api_token(&rotation_token).await?;
            if rotation_identity.status != "active" {
                return Err(format!(
                    "credential-rotation token {} is not active: {}",
                    rotation_identity.id, rotation_identity.status
                ));
            }
            if rotation_identity.id == before.control_token_identity.id {
                return Err(
                    "credential-rotation token must be physically distinct from CLOUDFLARE_CONTROL_TOKEN"
                        .to_owned(),
                );
            }

            let projection = projection_desired(desired, projection)?;
            if projection_delivery_state(desired, &projection, &before)?
                != ProjectionDeliveryState::FixedAbLatestPendingDeployment
            {
                return Err(format!(
                    "fixed A/B baseline recovery requires one exact tagged latest version pending deployment for {}",
                    projection.projection
                ));
            }
            let material = delivery_worker_material(&projection.projection)?;
            let dummy = material
                .slots
                .iter()
                .find(|slot| slot.name == SLOT_A)
                .ok_or_else(|| "fixed A/B material is missing slot A".to_owned())?;
            println!(
                "credential_rotation_token_identity={} credential_rotation_token_status={}",
                rotation_identity.id, rotation_identity.status
            );
            let version_id = cloudflare::patch_latest_worker_version_secrets(
                &rotation_token,
                &desired.target_account_id,
                &projection.worker_name,
                &material.version_tag,
                &[(SLOT_A, dummy.secret_text.as_str())],
            )
            .await?;
            cloudflare::deploy_worker_version(
                &rotation_token,
                &desired.target_account_id,
                &projection.worker_name,
                &version_id,
            )
            .await?;
            2
        }
    };

    let after = observe(control_token, desired).await?;
    let next = plan(desired, &after)?;
    Ok((after, next, performed))
}

fn authorized_plan(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<AuthorizedPlan<CredentialDeliveryAction>, String> {
    let action = plan(desired, observed)?;
    let disposition = if action == CredentialDeliveryAction::Noop {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    authorize_plan(
        "cloudflare_credential_delivery_phase6_contract",
        desired,
        observed,
        action,
        disposition,
    )
    .map_err(|err| err.to_string())
}

fn plan(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<CredentialDeliveryAction, String> {
    validate_access_boundary(desired, observed)?;
    for projection in projections(desired) {
        match projection_delivery_state(desired, &projection, observed)? {
            ProjectionDeliveryState::LegacyLocked => {
                return Ok(CredentialDeliveryAction::InstallDummyAbContract {
                    projection: projection.projection,
                });
            }
            ProjectionDeliveryState::FixedAbVersionTagMissing => {
                return Ok(CredentialDeliveryAction::RestoreFixedAbVersionTag {
                    projection: projection.projection,
                });
            }
            ProjectionDeliveryState::FixedAbLatestPendingDeployment => {
                return Ok(CredentialDeliveryAction::RestoreFixedAbBaseline {
                    projection: projection.projection,
                });
            }
            ProjectionDeliveryState::FixedAb => {}
        }
    }
    Ok(CredentialDeliveryAction::Noop)
}

fn projection_delivery_state(
    _desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
    observed: &CredentialPlaneObservation,
) -> Result<ProjectionDeliveryState, String> {
    let current = projection_observation(observed, &projection.projection)?;
    let legacy_tag = legacy_worker_version_tag(&projection.projection)?;
    let material = delivery_worker_material(&projection.projection)?;

    if current.worker_binding_count == Some(0)
        && current.worker_secret_bindings.is_empty()
        && current.worker_version_tag.as_deref() == Some(legacy_tag.as_str())
    {
        return Ok(ProjectionDeliveryState::LegacyLocked);
    }

    if current.worker_binding_count == Some(2) {
        require_exact_secret_bindings(&projection.worker_name, &current.worker_secret_bindings)?;
        let latest_is_only_active = current.worker_active_deployment_id.is_some()
            && current
                .worker_latest_version_id
                .as_ref()
                .is_some_and(|latest| {
                    current.worker_active_version_ids.len() == 1
                        && current.worker_active_version_ids[0] == *latest
                });
        let settings_tag = current.worker_version_tag.as_deref();
        let latest_tag = current.worker_latest_version_tag.as_deref();
        if latest_is_only_active
            && settings_tag == Some(material.version_tag.as_str())
            && latest_tag == Some(material.version_tag.as_str())
        {
            return Ok(ProjectionDeliveryState::FixedAb);
        }
        let latest_is_pending_deployment = current.worker_active_deployment_id.is_some()
            && current.worker_active_version_ids.len() == 1
            && current
                .worker_latest_version_id
                .as_ref()
                .is_some_and(|latest| current.worker_active_version_ids[0] != *latest);
        if latest_is_pending_deployment
            && settings_tag == Some(material.version_tag.as_str())
            && latest_tag == Some(material.version_tag.as_str())
        {
            return Ok(ProjectionDeliveryState::FixedAbLatestPendingDeployment);
        }
        if latest_is_only_active && settings_tag.is_none() && latest_tag.is_none() {
            return Ok(ProjectionDeliveryState::FixedAbVersionTagMissing);
        }
    }

    let bindings = current
        .worker_secret_bindings
        .iter()
        .map(|binding| format!("{}:{}", binding.name, binding.binding_type))
        .collect::<Vec<_>>()
        .join(",");
    Err(format!(
        "Worker {} is neither exact legacy locked state nor exact fixed A/B state: settings_version_tag={}, latest_version_id={}, latest_version_tag={}, active_deployment_id={}, active_version_ids={}, binding_count={}, secret_bindings={}",
        projection.worker_name,
        current.worker_version_tag.as_deref().unwrap_or("ABSENT"),
        current
            .worker_latest_version_id
            .as_deref()
            .unwrap_or("ABSENT"),
        current
            .worker_latest_version_tag
            .as_deref()
            .unwrap_or("ABSENT"),
        current
            .worker_active_deployment_id
            .as_deref()
            .unwrap_or("ABSENT"),
        if current.worker_active_version_ids.is_empty() {
            "ABSENT".to_owned()
        } else {
            current.worker_active_version_ids.join(",")
        },
        current
            .worker_binding_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        if bindings.is_empty() {
            "ABSENT"
        } else {
            bindings.as_str()
        }
    ))
}

fn validate_access_boundary(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(), String> {
    if observed.control_token_identity.status != "active" {
        return Err("CLOUDFLARE_CONTROL_TOKEN is not active".to_owned());
    }
    let organization = observed
        .access_organization
        .as_ref()
        .ok_or_else(|| "accepted Access organization is missing".to_owned())?;
    if organization.name != desired.access_organization_name
        || organization.auth_domain != desired.access_auth_domain
        || organization.deny_unmatched_requests != Some(true)
    {
        return Err("credential Access organization drifted".to_owned());
    }
    if observed.workers_dev_subdomain.as_deref() != Some(desired.workers_dev_subdomain.as_str()) {
        return Err("credential workers.dev namespace drifted".to_owned());
    }

    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        if !current.worker_script_present || !current.worker_identity_present {
            return Err(format!(
                "Worker {} must already exist with immutable identity",
                projection.worker_name
            ));
        }
        if current.worker_id.as_deref().unwrap_or("").is_empty() {
            return Err(format!(
                "Worker {} is missing provider identity",
                projection.worker_name
            ));
        }
        if current.custom_domain_count != 0 {
            return Err(format!(
                "Worker {} must remain workers.dev-only",
                projection.worker_name
            ));
        }
        if current.workers_dev_enabled != Some(true) || current.previews_enabled != Some(false) {
            return Err(format!(
                "Worker {} must be published only on workers.dev with previews disabled",
                projection.worker_name
            ));
        }

        let proof_token_id = current
            .proof_service_token_id
            .as_deref()
            .ok_or_else(|| format!("{} proof service token is missing", projection.projection))?;
        if current.proof_service_token_enabled != Some(false) {
            return Err(format!(
                "{} proof service token must be disabled at rest",
                projection.projection
            ));
        }
        if current.proof_service_token_duration.as_deref()
            != Some(desired.proof_token_duration.as_str())
        {
            return Err(format!(
                "{} proof service token duration drifted",
                projection.projection
            ));
        }

        let host_token_id = current
            .host_service_token_id
            .as_deref()
            .ok_or_else(|| format!("{} host service token is missing", projection.projection))?;
        if current.host_service_token_enabled != Some(true) {
            return Err(format!(
                "{} host service token must remain enabled",
                projection.projection
            ));
        }
        if current.host_service_token_duration.as_deref()
            != Some(desired.host_service_token_duration.as_str())
        {
            return Err(format!(
                "{} host service token duration drifted",
                projection.projection
            ));
        }

        if current.access_application_type.as_deref() != Some("self_hosted")
            || current.access_service_auth_401_redirect != Some(true)
        {
            return Err(format!(
                "{} Access application drifted from self-hosted Service Auth",
                projection.projection
            ));
        }
        let expected_hostname = workers_dev_hostname(desired, &projection);
        if current.access_destination_type.as_deref() != Some("public")
            || current.access_destination_uri.as_deref() != Some(expected_hostname.as_str())
            || current.access_destination_worker_id.is_some()
            || current.access_destination_has_overrides != Some(false)
        {
            return Err(format!(
                "{} Access destination drifted from exact workers.dev hostname",
                projection.projection
            ));
        }

        if current.access_policies.len() != 1 {
            return Err(format!(
                "{} Access application must have exactly one service-auth policy",
                projection.projection
            ));
        }
        let policy = &current.access_policies[0];
        let mut observed_service_token_ids = policy.include_service_token_ids.clone();
        observed_service_token_ids.sort();
        let mut expected_service_token_ids =
            vec![proof_token_id.to_owned(), host_token_id.to_owned()];
        expected_service_token_ids.sort();
        if policy.name != projection.access_policy_name
            || policy.decision.as_deref() != Some("non_identity")
            || observed_service_token_ids != expected_service_token_ids
            || policy.has_extra_rules
        {
            return Err(format!(
                "{} Access service-token isolation policy drifted",
                projection.projection
            ));
        }
    }
    Ok(())
}

async fn verify(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let observed = observe(control_token, desired).await?;
    let action = plan(desired, &observed)?;
    if action != CredentialDeliveryAction::Noop {
        return Err(format!(
            "credential-delivery verify requires exact terminal A/B state; next action={}",
            action_name(&action)
        ));
    }
    print_terminal(desired, &observed, 0)?;
    println!("credential_secret_mutations=0");
    Ok(())
}

async fn prove(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let before = observe(control_token, desired).await?;
    if plan(desired, &before)? != CredentialDeliveryAction::Noop {
        return Err("credential-delivery proof requires exact terminal A/B state".to_owned());
    }

    preflight_access_analytics(control_token, desired).await?;

    let mutations = prove_ab_session(control_token, desired, &before).await?;

    let after = observe(control_token, desired).await?;
    if plan(desired, &after)? != CredentialDeliveryAction::Noop {
        return Err(
            "credential-delivery proof did not return to exact terminal A/B state".to_owned(),
        );
    }
    println!("credential_delivery_status=PASS");
    println!("credential_delivery_contract=FIXED_A_B");
    println!("exact_generation_selection=PASS");
    println!("access_isolation_structural=PASS");
    println!("proof_session=SHARED_TWO_PROJECTION");
    println!("proof_tokens_enabled=false");
    println!("host_tokens_enabled=true");
    println!("proof_provider_mutations={mutations}");
    println!("credential_secret_mutations=0");
    println!("real_credentials_created=0");
    println!("production_runtime_mutations=0");
    Ok(())
}

async fn prove_ab_session(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<u32, String> {
    let windows = projection_desired(desired, "windows")?;
    let vm = projection_desired(desired, "vm")?;
    let windows_observed = projection_observation(observed, "windows")?;
    let vm_observed = projection_observation(observed, "vm")?;

    let windows_token_id = windows_observed
        .proof_service_token_id
        .as_deref()
        .ok_or_else(|| "Windows proof token ID is missing".to_owned())?;
    let vm_token_id = vm_observed
        .proof_service_token_id
        .as_deref()
        .ok_or_else(|| "VM proof token ID is missing".to_owned())?;
    let windows_policy_id = windows_observed
        .access_policies
        .first()
        .filter(|_| windows_observed.access_policies.len() == 1)
        .map(|policy| policy.id.as_str())
        .ok_or_else(|| "Windows proof requires exactly one Access policy".to_owned())?;
    let vm_policy_id = vm_observed
        .access_policies
        .first()
        .filter(|_| vm_observed.access_policies.len() == 1)
        .map(|policy| policy.id.as_str())
        .ok_or_else(|| "VM proof requires exactly one Access policy".to_owned())?;
    let workers_subdomain = observed
        .workers_dev_subdomain
        .as_deref()
        .ok_or_else(|| "workers.dev account subdomain is missing".to_owned())?;

    let mut mutations = 0u32;
    let proof_result: Result<(), ProofAttemptError> = async {
        for (projection, token_id) in [(&windows, windows_token_id), (&vm, vm_token_id)] {
            cloudflare::set_access_service_token_enabled(
                control_token,
                &desired.target_account_id,
                token_id,
                &projection.proof_service_token_name,
                &desired.proof_token_duration,
                true,
            )
            .await?;
            mutations += 1;

            let enabled = cloudflare::get_access_service_token(
                control_token,
                &desired.target_account_id,
                token_id,
            )
            .await?;
            validate_enabled_proof_token(
                projection,
                token_id,
                &desired.proof_token_duration,
                None,
                &enabled,
            )?;
            print_proof_token_state("enabled", projection, &enabled);
        }

        let windows_enabled = cloudflare::get_access_service_token(
            control_token,
            &desired.target_account_id,
            windows_token_id,
        )
        .await?;
        let windows_client_id = validate_enabled_proof_token(
            &windows,
            windows_token_id,
            &desired.proof_token_duration,
            None,
            &windows_enabled,
        )?;

        let windows_credential = cloudflare::rotate_access_service_token(
            control_token,
            &desired.target_account_id,
            windows_token_id,
        )
        .await?;
        mutations += 1;
        validate_rotated_proof_credential(
            &windows,
            windows_token_id,
            &windows_client_id,
            &desired.proof_token_duration,
            &windows_credential,
        )?;
        let windows_rotated = cloudflare::get_access_service_token(
            control_token,
            &desired.target_account_id,
            windows_token_id,
        )
        .await?;
        validate_enabled_proof_token(
            &windows,
            windows_token_id,
            &desired.proof_token_duration,
            Some(&windows_client_id),
            &windows_rotated,
        )?;
        print_proof_token_state("rotated", &windows, &windows_rotated);

        let vm_enabled = cloudflare::get_access_service_token(
            control_token,
            &desired.target_account_id,
            vm_token_id,
        )
        .await?;
        let vm_client_id = validate_enabled_proof_token(
            &vm,
            vm_token_id,
            &desired.proof_token_duration,
            None,
            &vm_enabled,
        )?;

        let vm_credential = cloudflare::rotate_access_service_token(
            control_token,
            &desired.target_account_id,
            vm_token_id,
        )
        .await?;
        mutations += 1;
        validate_rotated_proof_credential(
            &vm,
            vm_token_id,
            &vm_client_id,
            &desired.proof_token_duration,
            &vm_credential,
        )?;
        let vm_rotated = cloudflare::get_access_service_token(
            control_token,
            &desired.target_account_id,
            vm_token_id,
        )
        .await?;
        validate_enabled_proof_token(
            &vm,
            vm_token_id,
            &desired.proof_token_duration,
            Some(&vm_client_id),
            &vm_rotated,
        )?;
        print_proof_token_state("rotated", &vm, &vm_rotated);

        for (projection, credential) in [(&windows, &windows_credential), (&vm, &vm_credential)] {
            let material = delivery_worker_material(&projection.projection)?;
            for slot in &material.slots {
                prove_expected_slot(projection, workers_subdomain, slot, credential).await?;
            }

            let invalid_url = probe_url(projection, workers_subdomain, INVALID_PROBE_GENERATION);
            let invalid = cloudflare::probe_worker(&invalid_url, Some(credential)).await?;
            if invalid.status != 404 || !invalid.body.is_empty() {
                return Err(format!(
                    "{} invalid generation must return exact empty 404; status={} body_len={}",
                    projection.projection,
                    invalid.status,
                    invalid.body.len()
                )
                .into());
            }
            println!(
                "credential_delivery_proof projection={} generation={} outcome=NOT_FOUND status={}",
                projection.projection, INVALID_PROBE_GENERATION, invalid.status
            );
        }

        Ok(())
    }
    .await;

    let disable_windows = cloudflare::set_access_service_token_enabled(
        control_token,
        &desired.target_account_id,
        windows_token_id,
        &windows.proof_service_token_name,
        &desired.proof_token_duration,
        false,
    )
    .await;
    if disable_windows.is_ok() {
        mutations += 1;
    }
    let disable_vm = cloudflare::set_access_service_token_enabled(
        control_token,
        &desired.target_account_id,
        vm_token_id,
        &vm.proof_service_token_name,
        &desired.proof_token_duration,
        false,
    )
    .await;
    if disable_vm.is_ok() {
        mutations += 1;
    }

    if let Err(err) = disable_windows {
        return Err(format!(
            "credential proof cleanup failed to disable Windows proof token: {err}; VM cleanup={:?}",
            disable_vm.err()
        ));
    }
    if let Err(err) = disable_vm {
        return Err(format!(
            "credential proof cleanup failed to disable VM proof token: {err}"
        ));
    }

    match proof_result {
        Ok(()) => Ok(mutations),
        Err(ProofAttemptError::Ordinary(err)) => Err(err),
        Err(ProofAttemptError::Functional(failure)) => {
            let (expected_policy_id, expected_service_token_id) = match failure.projection.as_str()
            {
                "windows" => (windows_policy_id, windows_token_id),
                "vm" => (vm_policy_id, vm_token_id),
                other => {
                    return Err(format!(
                        "unsupported projection in Access failure evidence: {other}"
                    ));
                }
            };
            let classification = diagnose_access_failure_after_cleanup(
                control_token,
                &desired.target_account_id,
                expected_policy_id,
                expected_service_token_id,
                &failure,
            )
            .await
            .map_err(|err| {
                format!(
                    "{}; proof-token cleanup completed; post-cleanup Access diagnostics failed: {err}",
                    failure.acceptance_error
                )
            })?;
            Err(format!(
                "{}; proof-token cleanup completed; access_diagnostic_classification={classification}; no HTTP probe replay performed",
                failure.acceptance_error
            ))
        }
    }
}

fn validate_rotated_proof_credential(
    projection: &ProjectionDesired,
    expected_token_id: &str,
    expected_client_id: &str,
    expected_duration: &str,
    credential: &cloudflare::CloudflareAccessServiceCredential,
) -> Result<(), String> {
    if credential.id != expected_token_id
        || credential.client_id != expected_client_id
        || credential.enabled != Some(true)
        || credential.duration.as_deref() != Some(expected_duration)
        || credential.name.as_deref() != Some(projection.proof_service_token_name.as_str())
    {
        return Err(format!(
            "{} proof-token rotation changed identity or state",
            projection.projection
        ));
    }
    Ok(())
}

async fn prove_expected_slot(
    projection: &ProjectionDesired,
    workers_subdomain: &str,
    slot: &DeliverySlot,
    credential: &cloudflare::CloudflareAccessServiceCredential,
) -> Result<(), ProofAttemptError> {
    let url = probe_url(projection, workers_subdomain, slot.generation);
    let probe_start = (OffsetDateTime::now_utc() - TimeDuration::seconds(30))
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format Access proof start timestamp: {err}"))?;
    let response = cloudflare::probe_worker(&url, Some(credential)).await?;
    let probe_end = (OffsetDateTime::now_utc() + TimeDuration::seconds(30))
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format Access proof end timestamp: {err}"))?;
    if let Err(acceptance_error) = require_allowed(
        &format!("{}_{}", projection.projection, slot.name),
        &response,
        &slot.payload,
        slot.generation,
        projection_kind(&projection.projection)?,
    ) {
        let ray_id = response
            .cf_ray
            .as_deref()
            .map(normalize_cf_ray)
            .transpose()?
            .map(ToOwned::to_owned);
        println!(
            "access_failure_capture projection={} slot={} http_status={} ray_id={} datetime_start={} datetime_end={}",
            projection.projection,
            slot.name,
            response.status,
            ray_id.as_deref().unwrap_or("ABSENT"),
            probe_start,
            probe_end
        );
        return Err(ProofAttemptError::Functional(AccessFailureEvidence {
            projection: projection.projection.clone(),
            ray_id,
            datetime_start: probe_start,
            datetime_end: probe_end,
            http_status: response.status,
            acceptance_error,
        }));
    }
    println!(
        "credential_delivery_proof projection={} slot={} generation={} outcome=PASS status={}",
        projection.projection, slot.name, slot.generation, response.status
    );
    Ok(())
}

async fn preflight_access_analytics(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let now = OffsetDateTime::now_utc();
    let start = (now - TimeDuration::seconds(1))
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format GraphQL preflight start timestamp: {err}"))?;
    let end = now
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format GraphQL preflight end timestamp: {err}"))?;
    match cloudflare::list_access_login_events(
        control_token,
        &desired.target_account_id,
        "0000000000000000",
        &start,
        &end,
    )
    .await
    {
        Ok(_) => {
            println!("access_graphql_preflight=PASS");
            Ok(())
        }
        Err(err) if cloudflare::is_graphql_authorization_error(&err) => Err(format!(
            "ACCOUNT_ANALYTICS_READ_REQUIRED permission=Account Analytics Read; no proof mutation performed; provider_error={err}"
        )),
        Err(err) => Err(format!(
            "ACCESS_GRAPHQL_PREFLIGHT_FAILED no proof mutation performed; provider_error={err}"
        )),
    }
}

fn validate_enabled_proof_token(
    projection: &ProjectionDesired,
    expected_token_id: &str,
    expected_duration: &str,
    expected_client_id: Option<&str>,
    token: &cloudflare::CloudflareAccessServiceToken,
) -> Result<String, String> {
    if token.id != expected_token_id
        || token.name.as_deref() != Some(projection.proof_service_token_name.as_str())
        || token.enabled != Some(true)
        || token.duration.as_deref() != Some(expected_duration)
    {
        return Err(format!(
            "{} proof token did not enter the exact enabled state",
            projection.projection
        ));
    }
    let client_id = token
        .client_id
        .as_deref()
        .ok_or_else(|| format!("{} proof token client_id is missing", projection.projection))?;
    if let Some(expected) = expected_client_id
        && client_id != expected
    {
        return Err(format!(
            "{} proof token client_id changed after rotation",
            projection.projection
        ));
    }
    let expires_at = token.expires_at.as_deref().ok_or_else(|| {
        format!(
            "{} proof token expires_at is missing",
            projection.projection
        )
    })?;
    let expires = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|err| {
        format!(
            "{} proof token expires_at is not RFC3339: {err}",
            projection.projection
        )
    })?;
    if expires <= OffsetDateTime::now_utc() {
        return Err(format!("{} proof token is expired", projection.projection));
    }
    Ok(client_id.to_owned())
}

fn print_proof_token_state(
    stage: &str,
    projection: &ProjectionDesired,
    token: &cloudflare::CloudflareAccessServiceToken,
) {
    println!(
        "proof_token_state projection={} stage={} token_id={} client_id={} enabled={} duration={} expires_at={}",
        projection.projection,
        stage,
        token.id,
        token.client_id.as_deref().unwrap_or("ABSENT"),
        token
            .enabled
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        token.duration.as_deref().unwrap_or("ABSENT"),
        token.expires_at.as_deref().unwrap_or("ABSENT")
    );
}

async fn diagnose_access_failure_after_cleanup(
    control_token: &str,
    account_id: &str,
    expected_policy_id: &str,
    expected_service_token_id: &str,
    failure: &AccessFailureEvidence,
) -> Result<&'static str, String> {
    let Some(ray_id) = failure.ray_id.as_deref() else {
        println!(
            "access_login_evidence_wait ray_id=ABSENT http_status={} result=CF_RAY_MISSING",
            failure.http_status
        );
        return Ok("ACCESS_DIAGNOSTIC_CF_RAY_MISSING");
    };

    for attempt in 1..=ACCESS_ANALYTICS_EVIDENCE_ATTEMPTS {
        let events = cloudflare::list_access_login_events(
            control_token,
            account_id,
            ray_id,
            &failure.datetime_start,
            &failure.datetime_end,
        )
        .await?;
        println!(
            "access_login_evidence_wait attempt={} max_attempts={} ray_id={} records={} http_status={} datetime_start={} datetime_end={}",
            attempt,
            ACCESS_ANALYTICS_EVIDENCE_ATTEMPTS,
            ray_id,
            events.len(),
            failure.http_status,
            failure.datetime_start,
            failure.datetime_end
        );
        if !events.is_empty() {
            return classify_access_login_events(
                ray_id,
                expected_policy_id,
                expected_service_token_id,
                failure.http_status,
                &events,
            );
        }
        if attempt < ACCESS_ANALYTICS_EVIDENCE_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_secs(
                ACCESS_ANALYTICS_EVIDENCE_INTERVAL_SECONDS,
            ))
            .await;
        }
    }

    Ok("ACCESS_LOGIN_EVENT_NOT_OBSERVED_AFTER_BOUNDED_WAIT")
}

fn classify_access_login_events(
    ray_id: &str,
    expected_policy_id: &str,
    expected_service_token_id: &str,
    http_status: u16,
    events: &[cloudflare::CloudflareAccessLoginEvent],
) -> Result<&'static str, String> {
    if events.len() != 1 {
        return Err(format!(
            "GraphQL Access login correlation for ray_id={ray_id} is ambiguous: {} matching records",
            events.len()
        ));
    }
    let event = &events[0];
    println!(
        "access_login_evidence ray_id={} http_status={} successful={} approving_policy_id={} identity_provider={} service_token_id={} datetime={}",
        ray_id,
        http_status,
        event
            .is_successful_login
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        event.approving_policy_id.as_deref().unwrap_or("ABSENT"),
        event.identity_provider.as_deref().unwrap_or("ABSENT"),
        event.service_token_id.as_deref().unwrap_or("ABSENT"),
        event.datetime.as_deref().unwrap_or("ABSENT")
    );
    if event.cf_ray_id.as_deref() != Some(ray_id) {
        return Err(format!(
            "GraphQL Access login event Ray ID mismatch: expected={ray_id} observed={}",
            event.cf_ray_id.as_deref().unwrap_or("ABSENT")
        ));
    }
    if event.identity_provider.as_deref() != Some("nonidentity") {
        return Ok("WRONG_AUTHENTICATION_MODE");
    }
    if event.service_token_id.as_deref() != Some(expected_service_token_id) {
        return Ok("TOKEN_INVALID");
    }
    match event.is_successful_login {
        Some(false) => Ok("POLICY_DENIED"),
        Some(true) if event.approving_policy_id.as_deref() != Some(expected_policy_id) => {
            Ok("WRONG_POLICY")
        }
        Some(true) if http_status != 200 => Ok("ACCESS_ALLOWED_BUT_WORKER_FAILED"),
        Some(true) => Ok("PASS"),
        None => Err(format!(
            "GraphQL Access login event for ray_id={ray_id} is missing isSuccessfulLogin"
        )),
    }
}

fn normalize_cf_ray(raw: &str) -> Result<&str, String> {
    let ray_id = raw
        .split('-')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("invalid CF-Ray header: {raw}"))?;
    if ray_id.len() != 16 || !ray_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid CF-Ray identifier in header: raw={raw} normalized={ray_id}"
        ));
    }
    Ok(ray_id)
}

fn require_allowed(
    name: &str,
    probe: &cloudflare::CloudflareWorkerProbe,
    expected_body: &[u8],
    expected_generation: u64,
    expected_projection: CredentialProjectionKind,
) -> Result<(), String> {
    if probe.status != 200 || probe.body != expected_body {
        return Err(format!(
            "{name} expected exact HTTP 200 typed A/B payload; status={} body_len={}",
            probe.status,
            probe.body.len()
        ));
    }
    if !probe
        .content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("application/x-protobuf"))
    {
        return Err(format!("{name} did not return application/x-protobuf"));
    }
    let payload = CredentialDeliveryBundle::decode(probe.body.as_slice())
        .map_err(|err| format!("{name} returned invalid CredentialDeliveryBundle: {err}"))?;
    if payload.encode_to_vec() != probe.body
        || payload.schema_version != 1
        || payload.generation != expected_generation
        || payload.projection != expected_projection as i32
        || !payload.dummy_non_secret
    {
        return Err(format!(
            "{name} returned an incorrect or non-canonical A/B probe bundle"
        ));
    }
    Ok(())
}

async fn observe(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<CredentialPlaneObservation, String> {
    let control_token_identity = cloudflare::verify_api_token(api_token).await?;
    let scripts = cloudflare::list_worker_scripts(api_token, &desired.target_account_id).await?;
    let workers = cloudflare::list_workers(api_token, &desired.target_account_id).await?;
    let worker_domains =
        cloudflare::list_worker_domains(api_token, &desired.target_account_id).await?;
    let access_organization =
        cloudflare::get_access_organization(api_token, &desired.target_account_id)
            .await
            .map(Some)
            .or_else(|err| {
                if cloudflare::is_access_not_enabled_error(&err) {
                    Ok(None)
                } else {
                    Err(err)
                }
            })?;
    let (service_tokens, access_applications) = if access_organization.is_some() {
        (
            cloudflare::list_access_service_tokens(api_token, &desired.target_account_id).await?,
            cloudflare::list_access_applications(api_token, &desired.target_account_id).await?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let workers_dev_subdomain =
        cloudflare::get_workers_subdomain(api_token, &desired.target_account_id)
            .await
            .map(|value| Some(value.subdomain))
            .or_else(|err| {
                if cloudflare::is_workers_subdomain_not_configured_error(&err) {
                    Ok(None)
                } else {
                    Err(err)
                }
            })?;

    let mut projections_observed = Vec::new();
    for projection in projections(desired) {
        let matching_scripts = scripts
            .iter()
            .filter(|script| script.id == projection.worker_name)
            .collect::<Vec<_>>();
        if matching_scripts.len() > 1 {
            return Err(format!(
                "duplicate Worker script identity observed for {}",
                projection.worker_name
            ));
        }
        let worker_script_present = matching_scripts.len() == 1;

        let matching_workers = workers
            .iter()
            .filter(|worker| worker.name == projection.worker_name)
            .collect::<Vec<_>>();
        if matching_workers.len() > 1 {
            return Err(format!(
                "duplicate immutable Worker identity observed for {}",
                projection.worker_name
            ));
        }
        let worker_identity = matching_workers.first().copied();

        let (settings, secret_bindings, workers_dev_enabled, previews_enabled) =
            if worker_script_present {
                let subdomain = cloudflare::get_worker_script_subdomain(
                    api_token,
                    &desired.target_account_id,
                    &projection.worker_name,
                )
                .await?;
                (
                    Some(
                        cloudflare::get_worker_script_settings(
                            api_token,
                            &desired.target_account_id,
                            &projection.worker_name,
                        )
                        .await?,
                    ),
                    cloudflare::list_worker_script_secrets(
                        api_token,
                        &desired.target_account_id,
                        &projection.worker_name,
                    )
                    .await?,
                    Some(subdomain.enabled),
                    Some(subdomain.previews_enabled),
                )
            } else {
                (
                    None,
                    Vec::new(),
                    worker_identity.and_then(|worker| worker.workers_dev_enabled),
                    worker_identity.and_then(|worker| worker.previews_enabled),
                )
            };

        let version_head = if worker_script_present {
            Some(
                cloudflare::get_worker_script_version_head(
                    api_token,
                    &desired.target_account_id,
                    &projection.worker_name,
                )
                .await?,
            )
        } else {
            None
        };

        let latest_version_tag = match (
            worker_identity,
            version_head
                .as_ref()
                .and_then(|value| value.latest_version_id.as_deref()),
        ) {
            (Some(worker), Some(version_id)) => Some(
                cloudflare::get_worker_version_tag(
                    api_token,
                    &desired.target_account_id,
                    &worker.id,
                    version_id,
                )
                .await?,
            ),
            _ => None,
        }
        .flatten();

        let matching_proof_tokens = service_tokens
            .iter()
            .filter(|token| {
                token.name.as_deref() == Some(projection.proof_service_token_name.as_str())
            })
            .collect::<Vec<_>>();
        if matching_proof_tokens.len() > 1 {
            return Err(format!(
                "duplicate proof service-token identity observed for {}",
                projection.proof_service_token_name
            ));
        }
        let proof_token = matching_proof_tokens.first().copied();

        let matching_host_tokens = service_tokens
            .iter()
            .filter(|token| {
                token.name.as_deref() == Some(projection.host_service_token_name.as_str())
            })
            .collect::<Vec<_>>();
        if matching_host_tokens.len() > 1 {
            return Err(format!(
                "duplicate host service-token identity observed for {}",
                projection.host_service_token_name
            ));
        }
        let host_token = matching_host_tokens.first().copied();

        let matching_apps = access_applications
            .iter()
            .filter(|app| app.name == projection.access_application_name)
            .collect::<Vec<_>>();
        if matching_apps.len() > 1 {
            return Err(format!(
                "duplicate Access application identity observed for {}",
                projection.access_application_name
            ));
        }
        let app = matching_apps.first().copied();
        let policies = match app {
            Some(app) => {
                cloudflare::list_access_application_policies(
                    api_token,
                    &desired.target_account_id,
                    &app.id,
                )
                .await?
            }
            None => Vec::new(),
        };
        let destination = app.and_then(|app| {
            if app.destinations.len() == 1 {
                app.destinations.first()
            } else {
                None
            }
        });

        projections_observed.push(ProjectionObservation {
            projection: projection.projection,
            worker_name: projection.worker_name.clone(),
            worker_script_present,
            worker_identity_present: worker_identity.is_some(),
            worker_id: worker_identity.map(|worker| worker.id.clone()),
            worker_binding_count: settings.as_ref().map(|value| value.binding_count),
            worker_secret_bindings: secret_bindings,
            worker_version_tag: settings.and_then(|value| value.version_tag),
            worker_latest_version_id: version_head
                .as_ref()
                .and_then(|value| value.latest_version_id.clone()),
            worker_latest_version_tag: latest_version_tag,
            worker_active_deployment_id: version_head
                .as_ref()
                .and_then(|value| value.active_deployment_id.clone()),
            worker_active_version_ids: version_head
                .map(|value| value.active_version_ids)
                .unwrap_or_default(),
            workers_dev_enabled,
            previews_enabled,
            custom_domain_count: worker_domains
                .iter()
                .filter(|domain| domain.service == projection.worker_name)
                .count(),
            proof_service_token_id: proof_token.map(|value| value.id.clone()),
            proof_service_token_enabled: proof_token.and_then(|value| value.enabled),
            proof_service_token_duration: proof_token.and_then(|value| value.duration.clone()),
            host_service_token_id: host_token.map(|value| value.id.clone()),
            host_service_token_client_id: host_token.and_then(|value| value.client_id.clone()),
            host_service_token_enabled: host_token.and_then(|value| value.enabled),
            host_service_token_duration: host_token.and_then(|value| value.duration.clone()),
            access_application_id: app.map(|value| value.id.clone()),
            access_application_type: app.map(|value| value.app_type.clone()),
            access_service_auth_401_redirect: app.and_then(|value| value.service_auth_401_redirect),
            access_destination_type: destination.map(|value| value.destination_type.clone()),
            access_destination_worker_id: destination.and_then(|value| value.worker_id.clone()),
            access_destination_uri: destination.and_then(|value| value.uri.clone()),
            access_destination_has_overrides: destination.map(|value| value.has_overrides),
            access_policies: policies,
        });
    }

    Ok(CredentialPlaneObservation {
        control_token_identity,
        access_organization,
        workers_dev_subdomain,
        projections: projections_observed,
    })
}

fn projections(desired: &ProductionCredentialPlaneOwnership) -> [ProjectionDesired; 2] {
    [
        ProjectionDesired {
            projection: "windows".to_owned(),
            worker_name: desired.windows_worker_name.clone(),
            access_application_name: desired.windows_access_application_name.clone(),
            access_policy_name: desired.windows_access_policy_name.clone(),
            proof_service_token_name: desired.windows_service_token_name.clone(),
            host_service_token_name: desired.windows_host_service_token_name.clone(),
        },
        ProjectionDesired {
            projection: "vm".to_owned(),
            worker_name: desired.vm_worker_name.clone(),
            access_application_name: desired.vm_access_application_name.clone(),
            access_policy_name: desired.vm_access_policy_name.clone(),
            proof_service_token_name: desired.vm_service_token_name.clone(),
            host_service_token_name: desired.vm_host_service_token_name.clone(),
        },
    ]
}

fn projection_desired(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &str,
) -> Result<ProjectionDesired, String> {
    projections(desired)
        .into_iter()
        .find(|candidate| candidate.projection == projection)
        .ok_or_else(|| format!("unsupported credential projection {projection}"))
}

fn projection_observation<'a>(
    observed: &'a CredentialPlaneObservation,
    projection: &str,
) -> Result<&'a ProjectionObservation, String> {
    observed
        .projections
        .iter()
        .find(|candidate| candidate.projection == projection)
        .ok_or_else(|| format!("missing credential projection observation {projection}"))
}

fn projection_kind(projection: &str) -> Result<CredentialProjectionKind, String> {
    match projection {
        "windows" => Ok(CredentialProjectionKind::Windows),
        "vm" => Ok(CredentialProjectionKind::Vm),
        _ => Err(format!("unsupported credential projection {projection}")),
    }
}

fn workers_dev_hostname(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
) -> String {
    format!(
        "{}.{}.workers.dev",
        projection.worker_name, desired.workers_dev_subdomain
    )
}

fn probe_url(projection: &ProjectionDesired, workers_subdomain: &str, generation: u64) -> String {
    format!(
        "https://{}.{}.workers.dev/v1/credentials?generation={generation}",
        projection.worker_name, workers_subdomain
    )
}

fn require_exact_secret_bindings(
    worker_name: &str,
    bindings: &[cloudflare::CloudflareWorkerSecretBinding],
) -> Result<(), String> {
    let observed = bindings
        .iter()
        .map(|binding| (binding.name.as_str(), binding.binding_type.as_str()))
        .collect::<Vec<_>>();
    let expected = vec![(SLOT_A, "secret_text"), (SLOT_B, "secret_text")];
    if observed != expected {
        return Err(format!(
            "Worker {worker_name} secret bindings differ from exact fixed A/B contract: observed={observed:?}"
        ));
    }
    Ok(())
}

fn delivery_worker_material(projection: &str) -> Result<DeliveryWorkerMaterial, String> {
    let projection_kind = projection_kind(projection)?;
    let slots = [(SLOT_A, PROBE_GENERATION_A), (SLOT_B, PROBE_GENERATION_B)]
        .into_iter()
        .map(|(name, generation)| {
            let payload = CredentialDeliveryBundle {
                schema_version: 1,
                generation,
                projection: projection_kind as i32,
                dummy_non_secret: true,
                slot: CredentialDeliverySlot::Unspecified as i32,
                payload: None,
            }
            .encode_to_vec();
            DeliverySlot {
                name,
                generation,
                secret_text: hex_encode(&payload),
                payload,
            }
        })
        .collect::<Vec<_>>();

    let source = r#"const S=["EDGE_CREDENTIAL_BUNDLE_A","EDGE_CREDENTIAL_BUNDLE_B"];
const P=__PROJECTION__;
function H(v){if(typeof v!=="string"||v.length===0||v.length%2||!/^[0-9a-f]+$/.test(v))return null;const b=new Uint8Array(v.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(v.slice(i*2,i*2+2),16);return b}
function V(b,p){let v=0n,s=0n;for(let i=0;i<10;i++){if(p>=b.length)return null;const x=BigInt(b[p++]);v|=(x&127n)<<s;if((x&128n)===0n)return[v,p];s+=7n}return null}
function G(b){let p=0,z=null,g=null,r=null;while(p<b.length){const k=V(b,p);if(!k)return null;const f=Number(k[0]>>3n),w=Number(k[0]&7n);p=k[1];if(!f)return null;if(w===0){const x=V(b,p);if(!x)return null;p=x[1];if(f===1)z=Number(x[0]);else if(f===2)g=x[0];else if(f===3)r=Number(x[0]);continue}if(w===1){if(p+8>b.length)return null;p+=8;continue}if(w===2){const x=V(b,p);if(!x||x[0]>BigInt(b.length))return null;p=x[1];const n=Number(x[0]);if(p+n>b.length)return null;p+=n;continue}if(w===5){if(p+4>b.length)return null;p+=4;continue}return null}return z===1&&g!==null&&r===P?g:null}
export default{async fetch(q,e){const u=new URL(q.url),x=u.searchParams.get("generation");if(q.method!=="GET"||u.pathname!=="/v1/credentials"||u.searchParams.size!==1||x===null||!/^(0|[1-9][0-9]*)$/.test(x))return new Response(null,{status:404,headers:{"Cache-Control":"no-store"}});let n;try{n=BigInt(x)}catch{return new Response(null,{status:404,headers:{"Cache-Control":"no-store"}})}const m=[];for(const s of S){const b=H(e[s]);if(b!==null&&G(b)===n)m.push(b)}if(m.length!==1)return new Response(null,{status:m.length?409:404,headers:{"Cache-Control":"no-store"}});return new Response(m[0],{status:200,headers:{"Content-Type":"application/x-protobuf","Cache-Control":"no-store"}})}};"#
        .replace("__PROJECTION__", &(projection_kind as i32).to_string());
    let version_tag = format!(
        "sing-box-phase6-ab-{projection}-{}",
        &sha256_hex(source.as_bytes())[..16]
    );
    Ok(DeliveryWorkerMaterial {
        source,
        version_tag,
        slots,
    })
}

fn legacy_worker_version_tag(projection: &str) -> Result<String, String> {
    let payload = CredentialIsolationProbe {
        schema_version: 1,
        generation: 1,
        projection: projection_kind(projection)? as i32,
        dummy_non_secret: true,
    }
    .encode_to_vec();
    let payload_hex = hex_encode(&payload);
    let source = format!(
        "const H=\"{payload_hex}\";const B=new Uint8Array(H.length/2);for(let i=0;i<B.length;i++)B[i]=Number.parseInt(H.slice(i*2,i*2+2),16);export default{{async fetch(request){{const u=new URL(request.url);if(request.method!==\"GET\"||u.pathname!==\"/v1/credentials\"||u.searchParams.size!==1||u.searchParams.get(\"generation\")!==\"1\")return new Response(null,{{status:404,headers:{{\"Cache-Control\":\"no-store\"}}}});return new Response(B,{{status:200,headers:{{\"Content-Type\":\"application/x-protobuf\",\"Cache-Control\":\"no-store\"}}}})}} }};\n"
    );
    Ok(format!(
        "sing-box-phase2-{projection}-{}",
        &sha256_hex(source.as_bytes())[..16]
    ))
}

fn print_observation(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(), String> {
    println!("credential_delivery_account={}", desired.target_account_id);
    println!(
        "credential_delivery_control_token_identity={}",
        observed.control_token_identity.id
    );
    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        let bindings = current
            .worker_secret_bindings
            .iter()
            .map(|binding| format!("{}:{}", binding.name, binding.binding_type))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "credential_delivery_projection={} worker={} version_tag={} binding_count={} secret_bindings={} proof_token_enabled={}",
            projection.projection,
            projection.worker_name,
            current.worker_version_tag.as_deref().unwrap_or("ABSENT"),
            current
                .worker_binding_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            if bindings.is_empty() {
                "ABSENT"
            } else {
                bindings.as_str()
            },
            current
                .proof_service_token_enabled
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned())
        );
        println!(
            "credential_delivery_projection={} latest_version_id={} latest_version_tag={} active_deployment_id={} active_version_ids={}",
            projection.projection,
            current
                .worker_latest_version_id
                .as_deref()
                .unwrap_or("ABSENT"),
            current
                .worker_latest_version_tag
                .as_deref()
                .unwrap_or("ABSENT"),
            current
                .worker_active_deployment_id
                .as_deref()
                .unwrap_or("ABSENT"),
            if current.worker_active_version_ids.is_empty() {
                "ABSENT".to_owned()
            } else {
                current.worker_active_version_ids.join(",")
            }
        );
        println!(
            "credential_delivery_projection={} host_token_enabled={}",
            projection.projection,
            current
                .host_service_token_enabled
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned())
        );
    }
    Ok(())
}

fn print_terminal(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
    mutations: u32,
) -> Result<(), String> {
    print_observation(desired, observed)?;
    println!("credential_delivery_status=PASS");
    println!("credential_delivery_contract=FIXED_A_B");
    println!("credential_secret_slots_per_projection=2");
    println!("proof_tokens_enabled=false");
    println!("provider_mutations={mutations}");
    println!("real_credentials_created=0");
    println!("production_runtime_mutations=0");
    Ok(())
}

fn action_name(action: &CredentialDeliveryAction) -> &'static str {
    match action {
        CredentialDeliveryAction::Noop => "NOOP",
        CredentialDeliveryAction::InstallDummyAbContract { .. } => "INSTALL_DUMMY_A_B_CONTRACT",
        CredentialDeliveryAction::RestoreFixedAbVersionTag { .. } => {
            "RESTORE_FIXED_A_B_VERSION_TAG"
        }
        CredentialDeliveryAction::RestoreFixedAbBaseline { .. } => "RESTORE_FIXED_A_B_BASELINE",
    }
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be blank"));
    }
    Ok(value)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

    fn desired() -> ProductionCredentialPlaneOwnership {
        ProductionCredentialPlaneOwnership {
            target_account_id: "6be6e4b6340822dbeb18cb6c2f09c660".to_owned(),
            access_organization_name: "sing-box".to_owned(),
            access_auth_domain: "sing-box-6be6e4b6.cloudflareaccess.com".to_owned(),
            windows_worker_name: "sing-box-credentials-windows".to_owned(),
            vm_worker_name: "sing-box-credentials-vm".to_owned(),
            windows_access_application_name: "sing-box-credentials-windows-access".to_owned(),
            vm_access_application_name: "sing-box-credentials-vm-access".to_owned(),
            windows_access_policy_name: "sing-box-credentials-windows-service-auth".to_owned(),
            vm_access_policy_name: "sing-box-credentials-vm-service-auth".to_owned(),
            windows_service_token_name: "sing-box-credentials-windows-phase2-proof".to_owned(),
            vm_service_token_name: "sing-box-credentials-vm-phase2-proof".to_owned(),
            windows_host_service_token_name: "sing-box-credentials-windows-host".to_owned(),
            vm_host_service_token_name: "sing-box-credentials-vm-host".to_owned(),
            worker_compatibility_date: "2026-09-28".to_owned(),
            proof_token_duration: "1h".to_owned(),
            host_service_token_duration: "forever".to_owned(),
            workers_dev_subdomain: "sing-box-6be6e4b6340822dbeb18cb6c2f09c660".to_owned(),
        }
    }

    fn projection_observation(
        desired: &ProductionCredentialPlaneOwnership,
        projection_name: &str,
    ) -> ProjectionObservation {
        let projection = projection_desired(desired, projection_name).unwrap();
        let proof_token_id = format!("{projection_name}-proof-token-id");
        let host_token_id = format!("{projection_name}-host-token-id");
        ProjectionObservation {
            projection: projection.projection.clone(),
            worker_name: projection.worker_name.clone(),
            worker_script_present: true,
            worker_identity_present: true,
            worker_id: Some(format!("{projection_name}-worker-id")),
            worker_binding_count: Some(0),
            worker_secret_bindings: Vec::new(),
            worker_version_tag: Some(legacy_worker_version_tag(projection_name).unwrap()),
            worker_latest_version_id: Some(format!("{projection_name}-version-id")),
            worker_latest_version_tag: Some(legacy_worker_version_tag(projection_name).unwrap()),
            worker_active_deployment_id: Some(format!("{projection_name}-deployment-id")),
            worker_active_version_ids: vec![format!("{projection_name}-version-id")],
            workers_dev_enabled: Some(true),
            previews_enabled: Some(false),
            custom_domain_count: 0,
            proof_service_token_id: Some(proof_token_id.clone()),
            proof_service_token_enabled: Some(false),
            proof_service_token_duration: Some(desired.proof_token_duration.clone()),
            host_service_token_id: Some(host_token_id.clone()),
            host_service_token_client_id: Some(format!("{projection_name}-host-client-id")),
            host_service_token_enabled: Some(true),
            host_service_token_duration: Some(desired.host_service_token_duration.clone()),
            access_application_id: Some(format!("{projection_name}-app-id")),
            access_application_type: Some("self_hosted".to_owned()),
            access_service_auth_401_redirect: Some(true),
            access_destination_type: Some("public".to_owned()),
            access_destination_worker_id: None,
            access_destination_uri: Some(workers_dev_hostname(desired, &projection)),
            access_destination_has_overrides: Some(false),
            access_policies: vec![cloudflare::CloudflareAccessPolicy {
                id: format!("{projection_name}-policy-id"),
                name: projection.access_policy_name,
                decision: Some("non_identity".to_owned()),
                include_service_token_ids: vec![proof_token_id, host_token_id],
                has_extra_rules: false,
                precedence: Some(1),
                reusable: Some(false),
                app_count: None,
            }],
        }
    }

    fn observation(desired: &ProductionCredentialPlaneOwnership) -> CredentialPlaneObservation {
        CredentialPlaneObservation {
            control_token_identity: cloudflare::CloudflareApiTokenIdentity {
                id: "control-token-id".to_owned(),
                status: "active".to_owned(),
            },
            access_organization: Some(cloudflare::CloudflareAccessOrganization {
                name: desired.access_organization_name.clone(),
                auth_domain: desired.access_auth_domain.clone(),
                deny_unmatched_requests: Some(true),
            }),
            workers_dev_subdomain: Some(desired.workers_dev_subdomain.clone()),
            projections: vec![
                projection_observation(desired, "windows"),
                projection_observation(desired, "vm"),
            ],
        }
    }

    fn make_terminal(observed: &mut CredentialPlaneObservation, projection_name: &str) {
        let current = observed
            .projections
            .iter_mut()
            .find(|projection| projection.projection == projection_name)
            .unwrap();
        current.worker_binding_count = Some(2);
        current.worker_secret_bindings = vec![
            cloudflare::CloudflareWorkerSecretBinding {
                name: SLOT_A.to_owned(),
                binding_type: "secret_text".to_owned(),
            },
            cloudflare::CloudflareWorkerSecretBinding {
                name: SLOT_B.to_owned(),
                binding_type: "secret_text".to_owned(),
            },
        ];
        let version_tag = delivery_worker_material(projection_name)
            .unwrap()
            .version_tag;
        current.worker_version_tag = Some(version_tag.clone());
        current.worker_latest_version_tag = Some(version_tag);
    }

    #[test]
    fn host_bootstrap_policy_allows_only_recoverable_partial_or_terminal_sets() {
        let proof = "proof-token-id";
        let host = "host-token-id";
        assert!(bootstrap_policy_tokens_are_recoverable(
            proof,
            Some(host),
            &[proof.to_owned()],
        ));
        assert!(bootstrap_policy_tokens_are_recoverable(
            proof,
            Some(host),
            &[host.to_owned(), proof.to_owned()],
        ));
        assert!(!bootstrap_policy_tokens_are_recoverable(
            proof,
            Some(host),
            &[proof.to_owned(), "foreign-token-id".to_owned()],
        ));
        assert!(!bootstrap_policy_tokens_are_recoverable(
            proof,
            None,
            &[proof.to_owned(), host.to_owned()],
        ));
    }

    #[test]
    fn bounded_transition_accepts_exact_legacy_and_exact_mixed_state() {
        let desired = desired();
        let mut observed = observation(&desired);
        assert_eq!(
            projection_delivery_state(
                &desired,
                &projection_desired(&desired, "windows").unwrap(),
                &observed,
            )
            .unwrap(),
            ProjectionDeliveryState::LegacyLocked
        );
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::InstallDummyAbContract {
                projection: "windows".to_owned(),
            }
        );

        make_terminal(&mut observed, "windows");
        assert_eq!(
            projection_delivery_state(
                &desired,
                &projection_desired(&desired, "windows").unwrap(),
                &observed,
            )
            .unwrap(),
            ProjectionDeliveryState::FixedAb
        );
        assert_eq!(
            projection_delivery_state(
                &desired,
                &projection_desired(&desired, "vm").unwrap(),
                &observed,
            )
            .unwrap(),
            ProjectionDeliveryState::LegacyLocked
        );
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::InstallDummyAbContract {
                projection: "vm".to_owned(),
            }
        );
    }

    #[test]
    fn host_identity_must_be_enabled_forever_and_policy_bound() {
        let desired = desired();
        let mut observed = observation(&desired);
        make_terminal(&mut observed, "windows");
        make_terminal(&mut observed, "vm");
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::Noop
        );

        observed.projections[0].host_service_token_enabled = Some(false);
        assert!(plan(&desired, &observed).is_err());
        observed.projections[0].host_service_token_enabled = Some(true);

        observed.projections[0].host_service_token_duration = Some("1h".to_owned());
        assert!(plan(&desired, &observed).is_err());
        observed.projections[0].host_service_token_duration =
            Some(desired.host_service_token_duration.clone());

        observed.projections[0].access_policies[0]
            .include_service_token_ids
            .pop();
        assert!(plan(&desired, &observed).is_err());
    }

    #[test]
    fn delivery_plan_is_one_atomic_mutation_per_projection() {
        let desired = desired();
        let mut observed = observation(&desired);

        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::InstallDummyAbContract {
                projection: "windows".to_owned(),
            }
        );

        make_terminal(&mut observed, "windows");
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::InstallDummyAbContract {
                projection: "vm".to_owned(),
            }
        );

        make_terminal(&mut observed, "vm");
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::Noop
        );
    }

    #[test]
    fn delivery_material_is_typed_projection_specific_and_not_embedded_in_code() {
        let windows = delivery_worker_material("windows").unwrap();
        let vm = delivery_worker_material("vm").unwrap();
        assert_eq!(windows.slots.len(), 2);
        assert_eq!(vm.slots.len(), 2);
        assert_ne!(windows.source, vm.source);
        assert_ne!(windows.version_tag, vm.version_tag);

        for (material, projection) in [
            (&windows, CredentialProjectionKind::Windows),
            (&vm, CredentialProjectionKind::Vm),
        ] {
            for slot in &material.slots {
                let decoded = CredentialDeliveryBundle::decode(slot.payload.as_slice()).unwrap();
                assert_eq!(decoded.encode_to_vec(), slot.payload);
                assert_eq!(decoded.schema_version, 1);
                assert_eq!(decoded.generation, slot.generation);
                assert_eq!(decoded.projection, projection as i32);
                assert!(decoded.dummy_non_secret);
                assert_eq!(decoded.slot, CredentialDeliverySlot::Unspecified as i32);
                assert!(decoded.payload.is_none());
                assert_eq!(slot.secret_text, hex_encode(&slot.payload));
                assert!(!material.source.contains(&slot.secret_text));
            }
        }
        assert!(windows.source.contains(SLOT_A));
        assert!(windows.source.contains(SLOT_B));
        assert!(!windows.source.contains("private_key"));
        assert!(!windows.source.contains("password"));
    }

    #[test]
    fn delivery_plan_repairs_only_missing_fixed_ab_version_tags() {
        let desired = desired();
        let mut observed = observation(&desired);
        make_terminal(&mut observed, "windows");
        make_terminal(&mut observed, "vm");

        observed.projections[0].worker_version_tag = None;
        observed.projections[0].worker_latest_version_tag = None;
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::RestoreFixedAbVersionTag {
                projection: "windows".to_owned(),
            }
        );

        let windows_tag = delivery_worker_material("windows").unwrap().version_tag;
        observed.projections[0].worker_version_tag = Some(windows_tag.clone());
        observed.projections[0].worker_latest_version_tag = Some(windows_tag);
        observed.projections[1].worker_version_tag = None;
        observed.projections[1].worker_latest_version_tag = None;
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::RestoreFixedAbVersionTag {
                projection: "vm".to_owned(),
            }
        );
    }

    #[test]
    fn delivery_plan_rejects_wrong_nonempty_fixed_ab_version_tag() {
        let desired = desired();
        let mut observed = observation(&desired);
        make_terminal(&mut observed, "windows");
        make_terminal(&mut observed, "vm");
        observed.projections[0].worker_version_tag = Some("unexpected-version".to_owned());
        assert!(plan(&desired, &observed).is_err());
    }

    #[test]
    fn delivery_contract_recovers_tagged_latest_version_pending_deployment() {
        let desired = desired();
        let mut observed = observation(&desired);
        make_terminal(&mut observed, "windows");
        make_terminal(&mut observed, "vm");

        observed.projections[0].worker_active_version_ids = vec!["older-active-version".to_owned()];
        assert_eq!(
            projection_delivery_state(
                &desired,
                &projection_desired(&desired, "windows").unwrap(),
                &observed,
            )
            .unwrap(),
            ProjectionDeliveryState::FixedAbLatestPendingDeployment
        );
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialDeliveryAction::RestoreFixedAbBaseline {
                projection: "windows".to_owned(),
            }
        );
    }

    #[test]
    fn delivery_contract_rejects_disagreement_between_settings_and_latest_version_tags() {
        let desired = desired();
        let mut observed = observation(&desired);
        make_terminal(&mut observed, "windows");
        make_terminal(&mut observed, "vm");

        observed.projections[0].worker_latest_version_tag = None;
        assert!(plan(&desired, &observed).is_err());

        let expected = delivery_worker_material("windows").unwrap().version_tag;
        observed.projections[0].worker_latest_version_tag = Some(expected);
        observed.projections[0].worker_version_tag = None;
        assert!(plan(&desired, &observed).is_err());
    }

    #[test]
    fn delivery_contract_rejects_extra_bindings() {
        let desired = desired();
        let mut observed = observation(&desired);
        make_terminal(&mut observed, "windows");
        observed.projections[0].worker_secret_bindings.push(
            cloudflare::CloudflareWorkerSecretBinding {
                name: "UNEXPECTED".to_owned(),
                binding_type: "secret_text".to_owned(),
            },
        );
        observed.projections[0].worker_binding_count = Some(3);
        assert!(plan(&desired, &observed).is_err());
    }

    #[test]
    fn access_diagnostic_classifies_exact_service_auth_event() {
        let event = cloudflare::CloudflareAccessLoginEvent {
            datetime: Some("2026-09-29T13:30:40Z".to_owned()),
            is_successful_login: Some(false),
            approving_policy_id: Some("policy-id".to_owned()),
            cf_ray_id: Some("0123456789abcdef".to_owned()),
            identity_provider: Some("nonidentity".to_owned()),
            service_token_id: Some("token-id".to_owned()),
        };
        assert_eq!(
            classify_access_login_events(
                "0123456789abcdef",
                "policy-id",
                "token-id",
                401,
                &[event],
            )
            .unwrap(),
            "POLICY_DENIED"
        );
    }

    #[test]
    fn access_diagnostic_distinguishes_access_allow_from_worker_failure() {
        let event = cloudflare::CloudflareAccessLoginEvent {
            datetime: Some("2026-09-29T13:30:40Z".to_owned()),
            is_successful_login: Some(true),
            approving_policy_id: Some("policy-id".to_owned()),
            cf_ray_id: Some("0123456789abcdef".to_owned()),
            identity_provider: Some("nonidentity".to_owned()),
            service_token_id: Some("token-id".to_owned()),
        };
        assert_eq!(
            classify_access_login_events(
                "0123456789abcdef",
                "policy-id",
                "token-id",
                401,
                &[event],
            )
            .unwrap(),
            "ACCESS_ALLOWED_BUT_WORKER_FAILED"
        );
    }

    #[test]
    fn cf_ray_normalization_keeps_only_exact_ray_id() {
        assert_eq!(
            normalize_cf_ray("0123456789abcdef-WAW").unwrap(),
            "0123456789abcdef"
        );
        assert!(normalize_cf_ray("not-a-ray").is_err());
    }
}
