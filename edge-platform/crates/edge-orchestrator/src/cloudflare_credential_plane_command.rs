use crate::cli::{CloudflareCredentialPlaneCommand, CredentialDeliveryCommand};
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_controller_core::production::{ProductionComposition, ProductionCredentialPlaneOwnership};
use edge_provider_cloudflare as cloudflare;
use edge_shared_types::{CredentialDeliveryBundle, CredentialIsolationProbe, CredentialProjectionKind};
use prost::Message;
use ring::digest::{SHA256, digest};
use serde::Serialize;
use std::env;
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_CONVERGENCE_STEPS: usize = 16;
const DELIVERY_MAX_CONVERGENCE_STEPS: usize = 4;
const DELIVERY_SLOT_A: &str = "EDGE_CREDENTIAL_BUNDLE_A";
const DELIVERY_SLOT_B: &str = "EDGE_CREDENTIAL_BUNDLE_B";
const DELIVERY_PROBE_GENERATION_A: u64 = 9_000_001;
const DELIVERY_PROBE_GENERATION_B: u64 = 9_000_002;
const DELIVERY_INVALID_PROBE_GENERATION: u64 = 9_000_003;
const ACCESS_ANALYTICS_EVIDENCE_ATTEMPTS: usize = 6;
const ACCESS_ANALYTICS_EVIDENCE_INTERVAL_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProjectionDesired {
    projection: String,
    worker_name: String,
    access_application_name: String,
    access_policy_name: String,
    service_token_name: String,
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
    workers_dev_enabled: Option<bool>,
    previews_enabled: Option<bool>,
    custom_domain_count: usize,
    service_token_id: Option<String>,
    service_token_enabled: Option<bool>,
    service_token_duration: Option<String>,
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
enum CredentialPlaneAction {
    Noop,
    CreateAccessOrganization,
    CreateWorkersDevSubdomain,
    CreateWorkerIdentityLocked { projection: String },
    UploadWorkerModuleLocked { projection: String },
    CreateServiceToken { projection: String },
    CreateAccessApplication { projection: String },
    UpdateAccessApplication { projection: String },
    CreateAccessPolicy { projection: String },
    ConfigureWorkersDev { projection: String },
    DisableProofToken { projection: String },
    ProveIsolationAndLock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum CredentialDeliveryAction {
    Noop,
    UploadWorkerContract { projection: String },
    SeedDummySlots { projection: String },
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
struct WorkerMaterial {
    payload: Vec<u8>,
    source: String,
    version_tag: String,
}

#[derive(Debug, Clone)]
struct ProofCase {
    name: &'static str,
    outcome: &'static str,
    status: u16,
}

#[derive(Debug, Clone)]
struct ProofReport {
    cases: Vec<ProofCase>,
}

#[derive(Debug, Clone)]
struct AccessFailureEvidence {
    ray_id: Option<String>,
    datetime_start: String,
    datetime_end: String,
    http_status: u16,
    acceptance_error: String,
}

#[derive(Debug, Clone)]
enum ProofAttemptError {
    Ordinary(String),
    FirstCase(AccessFailureEvidence),
}

impl From<String> for ProofAttemptError {
    fn from(value: String) -> Self {
        Self::Ordinary(value)
    }
}

pub async fn run(command: CloudflareCredentialPlaneCommand) -> Result<(), String> {
    let control_token = env::var("CLOUDFLARE_CONTROL_TOKEN")
        .map_err(|_| "CLOUDFLARE_CONTROL_TOKEN is required".to_owned())?;
    if control_token.trim().is_empty() {
        return Err("CLOUDFLARE_CONTROL_TOKEN must not be blank".to_owned());
    }

    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = production.cloudflare.credential_plane.clone();
    if production.cloudflare.active_account_id == desired.target_account_id {
        return Err(
            "transitional Phase 2 credential commands are disabled after the credential plane becomes active production authority"
                .to_owned(),
        );
    }

    match command {
        CloudflareCredentialPlaneCommand::Inventory => {
            let observed = observe(&control_token, &desired).await?;
            print_observation(&desired, &observed);
            print_access_evaluation_inventory(&control_token, &desired).await?;
            Ok(())
        }
        CloudflareCredentialPlaneCommand::Plan => {
            let observed = observe(&control_token, &desired).await?;
            let authorized = authorized_plan(&desired, &observed)?;
            print_observation(&desired, &observed);
            println!("plan_action={}", action_name(&authorized.plan));
            println!("plan_authority={}", authorized.authority.authority_digest);
            println!("plan_disposition={:?}", authorized.disposition);
            Ok(())
        }
        CloudflareCredentialPlaneCommand::Converge => converge(&control_token, &desired).await,
        CloudflareCredentialPlaneCommand::Verify => verify_locked(&control_token, &desired).await,
        CloudflareCredentialPlaneCommand::Prove => prove_locked(&control_token, &desired).await,
    }
}


pub async fn run_delivery(command: CredentialDeliveryCommand) -> Result<(), String> {
    let control_token = env::var("CLOUDFLARE_CONTROL_TOKEN")
        .map_err(|_| "CLOUDFLARE_CONTROL_TOKEN is required".to_owned())?;
    if control_token.trim().is_empty() {
        return Err("CLOUDFLARE_CONTROL_TOKEN must not be blank".to_owned());
    }

    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = production.cloudflare.credential_plane.clone();
    if production.cloudflare.active_account_id != desired.target_account_id
        || production.cloudflare.migration_target_account_id.is_some()
    {
        return Err(
            "steady-state credential delivery requires the credential plane to be the active canonical Cloudflare authority with no migration target"
                .to_owned(),
        );
    }

    match command {
        CredentialDeliveryCommand::ContractPlan => {
            let observed = observe(&control_token, &desired).await?;
            let authorized = delivery_authorized_plan(&desired, &observed)?;
            print_delivery_observation(&desired, &observed)?;
            println!("plan_action={}", delivery_action_name(&authorized.plan));
            println!("plan_authority={}", authorized.authority.authority_digest);
            println!("plan_disposition={:?}", authorized.disposition);
            println!("real_credentials_created=0");
            Ok(())
        }
        CredentialDeliveryCommand::ContractConverge => {
            delivery_converge(&control_token, &desired).await
        }
        CredentialDeliveryCommand::ContractVerify => {
            delivery_verify(&control_token, &desired).await
        }
        CredentialDeliveryCommand::ContractProve => {
            delivery_prove(&control_token, &desired).await
        }
    }
}

async fn delivery_converge(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let mut mutations = 0u32;
    for step in 1..=DELIVERY_MAX_CONVERGENCE_STEPS {
        let before = observe(control_token, desired).await?;
        let authorized = delivery_authorized_plan(desired, &before)?;
        println!("credential_delivery_step={step}");
        println!("action={}", delivery_action_name(&authorized.plan));
        println!("plan_authority={}", authorized.authority.authority_digest);

        if matches!(authorized.plan, CredentialDeliveryAction::Noop) {
            print_delivery_observation(desired, &before)?;
            println!("credential_delivery_status=PASS");
            println!("credential_delivery_contract=FIXED_A_B");
            println!("credential_secret_slots_per_projection=2");
            println!("provider_mutations={mutations}");
            println!("real_credentials_created=0");
            println!("production_runtime_mutations=0");
            return Ok(());
        }

        let (after, next, performed) = apply_delivery_once(
            control_token,
            desired,
            &authorized.authority.authority_digest,
        )
        .await?;
        mutations = mutations.saturating_add(performed);
        if next == authorized.plan {
            return Err(format!(
                "credential-delivery action made no observable progress; mutation was not replayed: {}",
                delivery_action_name(&next)
            ));
        }
        println!("next_action={}", delivery_action_name(&next));
        print_delivery_observation(desired, &after)?;
    }

    Err(format!(
        "credential-delivery convergence exceeded bounded {DELIVERY_MAX_CONVERGENCE_STEPS}-step limit"
    ))
}

async fn apply_delivery_once(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    authorized_digest: &str,
) -> Result<(CredentialPlaneObservation, CredentialDeliveryAction, u32), String> {
    let before = observe(control_token, desired).await?;
    let authorized = delivery_authorized_plan(desired, &before)?;
    verify_exact_authority(authorized_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    match &authorized.plan {
        CredentialDeliveryAction::Noop => {}
        CredentialDeliveryAction::UploadWorkerContract { projection } => {
            let projection = projection_desired(desired, projection)?;
            let observed = projection_observation(&before, &projection.projection)?;
            if observed.worker_binding_count != Some(0)
                || !observed.worker_secret_bindings.is_empty()
            {
                return Err(format!(
                    "refusing Worker code transition with existing bindings for {}",
                    projection.worker_name
                ));
            }
            let material = delivery_worker_material(&projection.projection)?;
            cloudflare::upload_worker_module(
                control_token,
                &desired.target_account_id,
                &projection.worker_name,
                &material.source,
                &desired.worker_compatibility_date,
                &material.version_tag,
            )
            .await?;
        }
        CredentialDeliveryAction::SeedDummySlots { projection } => {
            let projection = projection_desired(desired, projection)?;
            let rotation_token = env::var("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")
                .map_err(|_| "CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN is required for A/B secret mutation".to_owned())?;
            if rotation_token.trim().is_empty() {
                return Err(
                    "CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN must not be blank for A/B secret mutation"
                        .to_owned(),
                );
            }
            let identity = cloudflare::verify_api_token(&rotation_token).await?;
            if identity.status != "active" {
                return Err(format!(
                    "credential-rotation token {} is not active: {}",
                    identity.id, identity.status
                ));
            }
            if identity.id == before.control_token_identity.id {
                return Err(
                    "credential-rotation token must be physically distinct from CLOUDFLARE_CONTROL_TOKEN"
                        .to_owned(),
                );
            }
            println!(
                "credential_rotation_token_identity={} credential_rotation_token_status={}",
                identity.id, identity.status
            );

            let material = delivery_worker_material(&projection.projection)?;
            let secret_refs = material
                .slots
                .iter()
                .map(|slot| (slot.name, slot.secret_text.as_str()))
                .collect::<Vec<_>>();
            let written = cloudflare::bulk_update_worker_script_secrets(
                &rotation_token,
                &desired.target_account_id,
                &projection.worker_name,
                &secret_refs,
                &material.version_tag,
            )
            .await?;
            require_exact_delivery_secret_bindings(&projection.worker_name, &written)?;
        }
    }

    let after = observe(control_token, desired).await?;
    let next = delivery_plan(desired, &after)?;
    Ok((after, next, 1))
}

fn delivery_authorized_plan(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<AuthorizedPlan<CredentialDeliveryAction>, String> {
    let action = delivery_plan(desired, observed)?;
    let disposition = if matches!(action, CredentialDeliveryAction::Noop) {
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

fn delivery_plan(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<CredentialDeliveryAction, String> {
    validate_delivery_base(desired, observed)?;

    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        let legacy = worker_material(desired, &projection.projection)?;
        let delivery = delivery_worker_material(&projection.projection)?;

        if current.worker_secret_bindings.is_empty() {
            if current.worker_binding_count != Some(0) {
                return Err(format!(
                    "Worker {} has non-secret or unobservable bindings before A/B initialization",
                    projection.worker_name
                ));
            }
            match current.worker_version_tag.as_deref() {
                Some(tag) if tag == legacy.version_tag => {
                    return Ok(CredentialDeliveryAction::UploadWorkerContract {
                        projection: projection.projection,
                    });
                }
                Some(tag) if tag == delivery.version_tag => {
                    return Ok(CredentialDeliveryAction::SeedDummySlots {
                        projection: projection.projection,
                    });
                }
                Some(tag) => {
                    return Err(format!(
                        "Worker {} has unsupported code version before A/B initialization: {}",
                        projection.worker_name, tag
                    ));
                }
                None => {
                    return Err(format!(
                        "Worker {} is missing its exact version tag",
                        projection.worker_name
                    ));
                }
            }
        }

        require_exact_delivery_secret_bindings(
            &projection.worker_name,
            &current.worker_secret_bindings,
        )?;
        if current.worker_binding_count != Some(2) {
            return Err(format!(
                "Worker {} must have exactly the two A/B secret bindings and no other bindings; observed={:?}",
                projection.worker_name, current.worker_binding_count
            ));
        }
        if current.worker_version_tag.as_deref() != Some(delivery.version_tag.as_str()) {
            return Err(format!(
                "Worker {} has A/B secrets but not the exact accepted delivery contract code",
                projection.worker_name
            ));
        }
    }

    Ok(CredentialDeliveryAction::Noop)
}

fn validate_delivery_base(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(), String> {
    let organization = observed
        .access_organization
        .as_ref()
        .ok_or_else(|| "credential delivery requires the accepted Access organization".to_owned())?;
    if organization.name != desired.access_organization_name
        || organization.auth_domain != desired.access_auth_domain
        || organization.deny_unmatched_requests != Some(true)
    {
        return Err("credential delivery Access organization drifted".to_owned());
    }
    if observed.workers_dev_subdomain.as_deref() != Some(desired.workers_dev_subdomain.as_str()) {
        return Err("credential delivery workers.dev namespace drifted".to_owned());
    }

    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        if !current.worker_script_present || !current.worker_identity_present {
            return Err(format!(
                "credential delivery Worker {} must already exist with immutable identity",
                projection.worker_name
            ));
        }
        if current.worker_id.as_deref().is_none_or(str::is_empty) {
            return Err(format!(
                "credential delivery Worker {} is missing provider identity",
                projection.worker_name
            ));
        }
        if current.custom_domain_count != 0 {
            return Err(format!(
                "credential delivery Worker {} must remain workers.dev-only",
                projection.worker_name
            ));
        }
        if current.workers_dev_enabled != Some(true) || current.previews_enabled != Some(false) {
            return Err(format!(
                "credential delivery Worker {} must be published only on workers.dev with previews disabled",
                projection.worker_name
            ));
        }

        let token_id = current
            .service_token_id
            .as_deref()
            .ok_or_else(|| format!("{} service token is missing", projection.projection))?;
        if current.service_token_enabled != Some(false) {
            return Err(format!(
                "{} proof service token must be disabled at rest before credential delivery mutation/proof",
                projection.projection
            ));
        }
        if current.service_token_duration.as_deref() != Some(desired.proof_token_duration.as_str()) {
            return Err(format!(
                "{} proof service token duration drifted",
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
        if policy.name != projection.access_policy_name
            || policy.decision.as_deref() != Some("non_identity")
            || policy.include_service_token_ids != vec![token_id.to_owned()]
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

fn require_exact_delivery_secret_bindings(
    worker_name: &str,
    bindings: &[cloudflare::CloudflareWorkerSecretBinding],
) -> Result<(), String> {
    let observed = bindings
        .iter()
        .map(|binding| (binding.name.as_str(), binding.binding_type.as_str()))
        .collect::<Vec<_>>();
    let expected = vec![
        (DELIVERY_SLOT_A, "secret_text"),
        (DELIVERY_SLOT_B, "secret_text"),
    ];
    if observed != expected {
        return Err(format!(
            "Worker {worker_name} secret bindings differ from exact fixed A/B contract: observed={observed:?}"
        ));
    }
    Ok(())
}

async fn delivery_verify(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let observed = observe(control_token, desired).await?;
    let action = delivery_plan(desired, &observed)?;
    if action != CredentialDeliveryAction::Noop {
        return Err(format!(
            "credential-delivery verify requires exact terminal A/B state; observed next action {}",
            delivery_action_name(&action)
        ));
    }
    print_delivery_observation(desired, &observed)?;
    println!("credential_delivery_status=PASS");
    println!("credential_delivery_contract=FIXED_A_B");
    println!("proof_tokens_enabled=false");
    println!("provider_mutations=0");
    println!("credential_secret_mutations=0");
    println!("production_runtime_mutations=0");
    println!("real_credentials_created=0");
    Ok(())
}

fn delivery_action_name(action: &CredentialDeliveryAction) -> &'static str {
    match action {
        CredentialDeliveryAction::Noop => "NOOP",
        CredentialDeliveryAction::UploadWorkerContract { .. } => "UPLOAD_WORKER_CONTRACT",
        CredentialDeliveryAction::SeedDummySlots { .. } => "SEED_DUMMY_A_B_SLOTS",
    }
}

fn print_delivery_observation(
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
        let names = current
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
            if names.is_empty() { "ABSENT" } else { names.as_str() },
            current
                .service_token_enabled
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned())
        );
    }
    Ok(())
}


async fn converge(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let mut mutations = 0u32;
    let mut terminal_proof = None;

    for step in 1..=MAX_CONVERGENCE_STEPS {
        let before = observe(api_token, desired).await?;
        let authorized = authorized_plan(desired, &before)?;
        println!("convergence_step={step}");
        println!("action={}", action_name(&authorized.plan));
        println!("plan_authority={}", authorized.authority.authority_digest);

        if matches!(authorized.plan, CredentialPlaneAction::Noop) {
            print_terminal(desired, &before, mutations, terminal_proof.as_ref());
            return Ok(());
        }

        let (after, next, proof, performed) =
            apply_once(api_token, desired, &authorized.authority.authority_digest).await?;
        mutations = mutations.saturating_add(performed);
        if proof.is_some() {
            terminal_proof = proof;
        }
        if next == authorized.plan {
            return Err(format!(
                "credential-plane action made no observable progress; mutation was not replayed: {}",
                action_name(&next)
            ));
        }
        println!("next_action={}", action_name(&next));
        print_observation(desired, &after);
    }

    Err(format!(
        "credential-plane convergence exceeded bounded {MAX_CONVERGENCE_STEPS}-step limit"
    ))
}

async fn apply_once(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    authorized_digest: &str,
) -> Result<
    (
        CredentialPlaneObservation,
        CredentialPlaneAction,
        Option<ProofReport>,
        u32,
    ),
    String,
> {
    let before = observe(api_token, desired).await?;
    let authorized = authorized_plan(desired, &before)?;
    verify_exact_authority(authorized_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    let (proof, mutations) = apply_action(api_token, desired, &before, &authorized.plan).await?;
    let after = observe(api_token, desired).await?;
    let next = plan(desired, &after)?;
    Ok((after, next, proof, mutations))
}

pub(crate) async fn verify_credential_plane_invariant() -> Result<(), String> {
    let control_token = env::var("CLOUDFLARE_CONTROL_TOKEN")
        .map_err(|_| "CLOUDFLARE_CONTROL_TOKEN is required".to_owned())?;
    if control_token.trim().is_empty() {
        return Err("CLOUDFLARE_CONTROL_TOKEN must not be blank".to_owned());
    }
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = &production.cloudflare.credential_plane;
    let observed = observe(&control_token, desired).await?;

    // During the Phase 6 transition, normal production verification accepts
    // either the exact terminal Phase 2 locked state or the exact terminal A/B
    // delivery state. A partial mixture is rejected by both validators.
    if let Ok(CredentialPlaneAction::Noop) = plan(desired, &observed) {
        return Ok(());
    }
    match delivery_plan(desired, &observed) {
        Ok(CredentialDeliveryAction::Noop) => Ok(()),
        Ok(action) => Err(format!(
            "credential-plane invariant is mid-transition; observed next delivery action {}",
            delivery_action_name(&action)
        )),
        Err(delivery_err) => Err(format!(
            "credential-plane invariant matches neither exact Phase 2 locked state nor exact Phase 6 A/B state: {delivery_err}"
        )),
    }
}

async fn verify_locked(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let observed = observe(api_token, desired).await?;
    let action = plan(desired, &observed)?;
    if action != CredentialPlaneAction::Noop {
        return Err(format!(
            "credential-plane verify requires exact locked state; observed next action {}",
            action_name(&action)
        ));
    }
    print_observation(desired, &observed);
    println!("credential_plane_status=PASS");
    println!("structural_verification=PASS");
    println!("proof_tokens_enabled=false");
    println!("previews_enabled=false");
    println!("provider_mutations=0");
    println!("production_runtime_mutations=0");
    println!("real_credentials_created=0");
    println!("active_account_unchanged=true");
    Ok(())
}

async fn prove_locked(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let observed = observe(api_token, desired).await?;
    let action = plan(desired, &observed)?;
    if action != CredentialPlaneAction::Noop {
        return Err(format!(
            "explicit proof requires structurally converged locked state; observed next action {}",
            action_name(&action)
        ));
    }
    let preflight_now = OffsetDateTime::now_utc();
    let preflight_start = (preflight_now - TimeDuration::seconds(1))
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format GraphQL preflight start timestamp: {err}"))?;
    let preflight_end = preflight_now
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format GraphQL preflight end timestamp: {err}"))?;
    match cloudflare::list_access_login_events(
        api_token,
        &desired.target_account_id,
        "0000000000000000",
        &preflight_start,
        &preflight_end,
    )
    .await
    {
        Ok(_) => println!("access_graphql_preflight=PASS"),
        Err(err) if cloudflare::is_graphql_authorization_error(&err) => {
            return Err(format!(
                "ACCOUNT_ANALYTICS_READ_REQUIRED permission=Account Analytics Read; no proof mutation performed; provider_error={err}"
            ));
        }
        Err(err) => {
            return Err(format!(
                "ACCESS_GRAPHQL_PREFLIGHT_FAILED no proof mutation performed; provider_error={err}"
            ));
        }
    }
    let forced = CredentialPlaneAction::ProveIsolationAndLock;
    let authorized = authorize_plan(
        "cloudflare_credential_plane_phase2_proof",
        desired,
        &observed,
        forced.clone(),
        PlanDisposition::Mutate,
    )
    .map_err(|err| err.to_string())?;
    verify_exact_authority(
        &authorized.authority.authority_digest,
        &authorized.authority,
    )
    .map_err(|err| err.to_string())?;
    let (proof, mutations) = apply_action(api_token, desired, &observed, &forced).await?;
    let after = observe(api_token, desired).await?;
    if plan(desired, &after)? != CredentialPlaneAction::Noop {
        return Err("credential-plane proof did not return to exact locked state".to_owned());
    }
    print_terminal(desired, &after, mutations, proof.as_ref());
    Ok(())
}

fn authorized_plan(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<AuthorizedPlan<CredentialPlaneAction>, String> {
    let action = plan(desired, observed)?;
    let disposition = if matches!(action, CredentialPlaneAction::Noop) {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    authorize_plan(
        "cloudflare_credential_plane_phase2",
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
) -> Result<CredentialPlaneAction, String> {
    match observed.access_organization.as_ref() {
        None => return Ok(CredentialPlaneAction::CreateAccessOrganization),
        Some(organization) => {
            if organization.name != desired.access_organization_name
                || organization.auth_domain != desired.access_auth_domain
                || organization.deny_unmatched_requests != Some(true)
            {
                return Err(format!(
                    "existing target Access organization differs from Phase 2 desired boundary: {organization:?}"
                ));
            }
        }
    }

    match observed.workers_dev_subdomain.as_deref() {
        None => return Ok(CredentialPlaneAction::CreateWorkersDevSubdomain),
        Some(subdomain) if subdomain != desired.workers_dev_subdomain => {
            return Err(format!(
                "existing workers.dev account subdomain differs from Phase 2 desired boundary: observed={subdomain} desired={}",
                desired.workers_dev_subdomain
            ));
        }
        Some(_) => {}
    }

    for projection in projections(desired) {
        let observed = projection_observation(observed, &projection.projection)?;
        let material = worker_material(desired, &projection.projection)?;

        if !observed.worker_identity_present {
            if observed.worker_script_present {
                return Err(format!(
                    "Worker {} exists as script without immutable Worker identity",
                    projection.worker_name
                ));
            }
            return Ok(CredentialPlaneAction::CreateWorkerIdentityLocked {
                projection: projection.projection,
            });
        }
        let worker_id = observed.worker_id.as_deref().ok_or_else(|| {
            format!(
                "immutable Worker identity {} is missing its provider ID",
                projection.worker_name
            )
        })?;
        if !observed.worker_script_present {
            ensure_projection_locked(&projection, observed)?;
            return Ok(CredentialPlaneAction::UploadWorkerModuleLocked {
                projection: projection.projection,
            });
        }
        if observed.worker_binding_count != Some(0) {
            return Err(format!(
                "Worker {} has bindings; Phase 2 requires physical absence of credential bindings",
                projection.worker_name
            ));
        }
        if observed.worker_version_tag.as_deref() != Some(material.version_tag.as_str()) {
            return Err(format!(
                "Worker {} exists but is not the exact Phase 2 dummy payload version",
                projection.worker_name
            ));
        }
        if observed.custom_domain_count != 0 {
            return Err(format!(
                "Worker {} has custom Worker domains; Phase 2 permits workers.dev only",
                projection.worker_name
            ));
        }

        if observed.service_token_id.is_none() {
            ensure_projection_locked(&projection, observed)?;
            return Ok(CredentialPlaneAction::CreateServiceToken {
                projection: projection.projection,
            });
        }
        if let Some(duration) = observed.service_token_duration.as_deref() {
            if duration != desired.proof_token_duration {
                return Err(format!(
                    "service token {} has unexpected duration {duration}",
                    projection.service_token_name
                ));
            }
        }

        let token_id = observed.service_token_id.as_deref().unwrap();
        let expected_hostname = workers_dev_hostname(desired, &projection);
        match observed.access_application_id.as_deref() {
            None => {
                ensure_projection_locked(&projection, observed)?;
                return Ok(CredentialPlaneAction::CreateAccessApplication {
                    projection: projection.projection,
                });
            }
            Some(_) => {
                if observed.access_application_type.as_deref() != Some("self_hosted")
                    || observed.access_service_auth_401_redirect != Some(true)
                {
                    return Err(format!(
                        "Access application {} differs from the exact self-hosted Service Auth contract",
                        projection.access_application_name
                    ));
                }
                if observed.access_policies.is_empty() {
                    ensure_projection_locked(&projection, observed)?;
                    return Ok(CredentialPlaneAction::CreateAccessPolicy {
                        projection: projection.projection,
                    });
                }
                if observed.access_policies.len() != 1 {
                    return Err(format!(
                        "Access application {} must have exactly one service-auth policy",
                        projection.access_application_name
                    ));
                }
                let policy = &observed.access_policies[0];
                if policy.name != projection.access_policy_name
                    || policy.decision.as_deref() != Some("non_identity")
                    || policy.include_service_token_ids != vec![token_id.to_owned()]
                    || policy.has_extra_rules
                {
                    return Err(format!(
                        "Access policy for {} differs from exact service-token isolation policy",
                        projection.projection
                    ));
                }

                let destination_is_exact_hostname = observed.access_destination_type.as_deref()
                    == Some("public")
                    && observed.access_destination_uri.as_deref()
                        == Some(expected_hostname.as_str())
                    && observed.access_destination_worker_id.is_none()
                    && observed.access_destination_has_overrides == Some(false);
                if destination_is_exact_hostname {
                    continue;
                }

                let destination_is_exact_legacy_worker =
                    observed.access_destination_type.as_deref() == Some("worker")
                        && observed.access_destination_worker_id.as_deref() == Some(worker_id)
                        && observed.access_destination_uri.is_none()
                        && observed.access_destination_has_overrides == Some(false);
                if destination_is_exact_legacy_worker {
                    return Ok(CredentialPlaneAction::UpdateAccessApplication {
                        projection: projection.projection,
                    });
                }

                return Err(format!(
                    "Access application {} has an ambiguous destination; expected exact public hostname {} or the exact migratable Worker destination",
                    projection.access_application_name, expected_hostname
                ));
            }
        }
    }

    for projection in projections(desired) {
        let observed = projection_observation(observed, &projection.projection)?;
        if observed.workers_dev_enabled != Some(true) || observed.previews_enabled != Some(false) {
            return Ok(CredentialPlaneAction::ConfigureWorkersDev {
                projection: projection.projection,
            });
        }
    }

    for projection in projections(desired) {
        let observed = projection_observation(observed, &projection.projection)?;
        match observed.service_token_enabled {
            Some(true) => {
                return Ok(CredentialPlaneAction::DisableProofToken {
                    projection: projection.projection,
                });
            }
            Some(false) => {}
            None => {
                return Err(format!(
                    "service token enabled state is missing for {}",
                    projection.projection
                ));
            }
        }
    }

    Ok(CredentialPlaneAction::Noop)
}

async fn apply_action(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
    action: &CredentialPlaneAction,
) -> Result<(Option<ProofReport>, u32), String> {
    match action {
        CredentialPlaneAction::Noop => Ok((None, 0)),
        CredentialPlaneAction::CreateAccessOrganization => {
            cloudflare::create_access_organization(
                api_token,
                &desired.target_account_id,
                &desired.access_organization_name,
                &desired.access_auth_domain,
            )
            .await?;
            Ok((None, 1))
        }
        CredentialPlaneAction::CreateWorkersDevSubdomain => {
            let created = cloudflare::create_workers_subdomain(
                api_token,
                &desired.target_account_id,
                &desired.workers_dev_subdomain,
            )
            .await?;
            if created.subdomain != desired.workers_dev_subdomain {
                return Err(format!(
                    "Cloudflare created unexpected workers.dev account subdomain: observed={} desired={}",
                    created.subdomain, desired.workers_dev_subdomain
                ));
            }
            Ok((None, 1))
        }
        CredentialPlaneAction::CreateWorkerIdentityLocked { projection } => {
            let projection = projection_desired(desired, projection)?;
            let worker = cloudflare::create_worker_identity_locked(
                api_token,
                &desired.target_account_id,
                &projection.worker_name,
            )
            .await?;
            if worker.name != projection.worker_name
                || worker.workers_dev_enabled != Some(false)
                || worker.previews_enabled != Some(false)
            {
                return Err(format!(
                    "Worker identity {} was not created atomically locked",
                    projection.worker_name
                ));
            }
            Ok((None, 1))
        }
        CredentialPlaneAction::UploadWorkerModuleLocked { projection } => {
            let projection = projection_desired(desired, projection)?;
            let material = worker_material(desired, &projection.projection)?;
            cloudflare::upload_worker_module(
                api_token,
                &desired.target_account_id,
                &projection.worker_name,
                &material.source,
                &desired.worker_compatibility_date,
                &material.version_tag,
            )
            .await?;
            Ok((None, 1))
        }
        CredentialPlaneAction::CreateServiceToken { projection } => {
            let projection = projection_desired(desired, projection)?;
            let credential = cloudflare::create_access_service_token(
                api_token,
                &desired.target_account_id,
                &projection.service_token_name,
                &desired.proof_token_duration,
                false,
            )
            .await?;
            drop(credential);
            Ok((None, 1))
        }
        CredentialPlaneAction::CreateAccessApplication { projection } => {
            let projection = projection_desired(desired, projection)?;
            let hostname = workers_dev_hostname(desired, &projection);
            cloudflare::create_hostname_access_application(
                api_token,
                &desired.target_account_id,
                &projection.access_application_name,
                &hostname,
            )
            .await?;
            Ok((None, 1))
        }
        CredentialPlaneAction::UpdateAccessApplication { projection } => {
            let projection = projection_desired(desired, projection)?;
            let current = projection_observation(observed, &projection.projection)?;
            let application_id = current.access_application_id.as_deref().ok_or_else(|| {
                "Access application ID is required before destination update".to_owned()
            })?;
            let hostname = workers_dev_hostname(desired, &projection);
            cloudflare::update_hostname_access_application(
                api_token,
                &desired.target_account_id,
                application_id,
                &projection.access_application_name,
                &hostname,
            )
            .await?;
            Ok((None, 1))
        }
        CredentialPlaneAction::CreateAccessPolicy { projection } => {
            let projection = projection_desired(desired, projection)?;
            let current = projection_observation(observed, &projection.projection)?;
            let application_id = current.access_application_id.as_deref().ok_or_else(|| {
                "Access application ID is required before policy creation".to_owned()
            })?;
            let token_id = current
                .service_token_id
                .as_deref()
                .ok_or_else(|| "service token ID is required before policy creation".to_owned())?;
            cloudflare::create_access_service_policy(
                api_token,
                &desired.target_account_id,
                application_id,
                &projection.access_policy_name,
                token_id,
            )
            .await?;
            Ok((None, 1))
        }
        CredentialPlaneAction::ConfigureWorkersDev { projection } => {
            let projection = projection_desired(desired, projection)?;
            cloudflare::set_worker_script_subdomain(
                api_token,
                &desired.target_account_id,
                &projection.worker_name,
                true,
                false,
            )
            .await?;
            Ok((None, 1))
        }
        CredentialPlaneAction::DisableProofToken { projection } => {
            let projection = projection_desired(desired, projection)?;
            let current = projection_observation(observed, &projection.projection)?;
            let token_id = current
                .service_token_id
                .as_deref()
                .ok_or_else(|| "service token ID is required before disable".to_owned())?;
            cloudflare::set_access_service_token_enabled(
                api_token,
                &desired.target_account_id,
                token_id,
                &projection.service_token_name,
                &desired.proof_token_duration,
                false,
            )
            .await?;
            Ok((None, 1))
        }
        CredentialPlaneAction::ProveIsolationAndLock => {
            let (report, mutations) = prove_isolation(api_token, desired, observed).await?;
            Ok((Some(report), mutations))
        }
    }
}

async fn prove_isolation(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(ProofReport, u32), String> {
    let windows = projection_desired(desired, "windows")?;
    let vm = projection_desired(desired, "vm")?;
    let windows_observed = projection_observation(observed, "windows")?;
    let vm_observed = projection_observation(observed, "vm")?;

    let windows_token_id = windows_observed
        .service_token_id
        .as_deref()
        .ok_or_else(|| "Windows proof token ID is missing".to_owned())?;
    let vm_token_id = vm_observed
        .service_token_id
        .as_deref()
        .ok_or_else(|| "VM proof token ID is missing".to_owned())?;
    let windows_policy_id = windows_observed
        .access_policies
        .first()
        .filter(|_| windows_observed.access_policies.len() == 1)
        .map(|policy| policy.id.as_str())
        .ok_or_else(|| "Windows Access proof requires exactly one policy".to_owned())?;
    let workers_subdomain = observed
        .workers_dev_subdomain
        .as_deref()
        .ok_or_else(|| "workers.dev account subdomain is missing".to_owned())?;

    let windows_url = format!(
        "https://{}.{}.workers.dev/v1/credentials?generation=1",
        windows.worker_name, workers_subdomain
    );
    let vm_url = format!(
        "https://{}.{}.workers.dev/v1/credentials?generation=1",
        vm.worker_name, workers_subdomain
    );

    let mut mutations = 0u32;
    let mut windows_enabled_by_proof = false;
    let mut vm_enabled_by_proof = false;

    let proof_result: Result<ProofReport, ProofAttemptError> = async {
        if windows_observed.service_token_enabled != Some(true) {
            cloudflare::set_access_service_token_enabled(
                api_token,
                &desired.target_account_id,
                windows_token_id,
                &windows.service_token_name,
                &desired.proof_token_duration,
                true,
            )
            .await?;
            mutations += 1;
            windows_enabled_by_proof = true;
        }
        let windows_enabled_state = cloudflare::get_access_service_token(
            api_token,
            &desired.target_account_id,
            windows_token_id,
        )
        .await?;
        let windows_client_id = validate_proof_token_state(
            &windows,
            windows_token_id,
            &desired.proof_token_duration,
            None,
            &windows_enabled_state,
        )?;
        print_proof_token_state("enabled", &windows, &windows_enabled_state);

        if vm_observed.service_token_enabled != Some(true) {
            cloudflare::set_access_service_token_enabled(
                api_token,
                &desired.target_account_id,
                vm_token_id,
                &vm.service_token_name,
                &desired.proof_token_duration,
                true,
            )
            .await?;
            mutations += 1;
            vm_enabled_by_proof = true;
        }
        let vm_enabled_state = cloudflare::get_access_service_token(
            api_token,
            &desired.target_account_id,
            vm_token_id,
        )
        .await?;
        let vm_client_id = validate_proof_token_state(
            &vm,
            vm_token_id,
            &desired.proof_token_duration,
            None,
            &vm_enabled_state,
        )?;
        print_proof_token_state("enabled", &vm, &vm_enabled_state);

        let windows_credential = cloudflare::rotate_access_service_token(
            api_token,
            &desired.target_account_id,
            windows_token_id,
        )
        .await?;
        mutations += 1;
        validate_rotated_credential(
            &windows,
            windows_token_id,
            &windows_client_id,
            &desired.proof_token_duration,
            &windows_credential,
        )?;
        print_rotated_credential(&windows, &windows_credential);
        let windows_rotated_state = cloudflare::get_access_service_token(
            api_token,
            &desired.target_account_id,
            windows_token_id,
        )
        .await?;
        validate_proof_token_state(
            &windows,
            windows_token_id,
            &desired.proof_token_duration,
            Some(&windows_client_id),
            &windows_rotated_state,
        )?;
        print_proof_token_state("rotated", &windows, &windows_rotated_state);

        let vm_credential = cloudflare::rotate_access_service_token(
            api_token,
            &desired.target_account_id,
            vm_token_id,
        )
        .await?;
        mutations += 1;
        validate_rotated_credential(
            &vm,
            vm_token_id,
            &vm_client_id,
            &desired.proof_token_duration,
            &vm_credential,
        )?;
        print_rotated_credential(&vm, &vm_credential);
        let vm_rotated_state = cloudflare::get_access_service_token(
            api_token,
            &desired.target_account_id,
            vm_token_id,
        )
        .await?;
        validate_proof_token_state(
            &vm,
            vm_token_id,
            &desired.proof_token_duration,
            Some(&vm_client_id),
            &vm_rotated_state,
        )?;
        print_proof_token_state("rotated", &vm, &vm_rotated_state);

        let windows_material = worker_material(desired, "windows")?;
        let vm_material = worker_material(desired, "vm")?;
        let ww_start = (OffsetDateTime::now_utc() - TimeDuration::seconds(30))
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format Access proof start timestamp: {err}"))?;
        let ww = cloudflare::probe_worker(&windows_url, Some(&windows_credential)).await?;
        let ww_end = (OffsetDateTime::now_utc() + TimeDuration::seconds(30))
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format Access proof end timestamp: {err}"))?;

        if let Err(acceptance_error) = require_allowed(
            "windows_to_windows",
            &ww,
            &windows_material.payload,
            CredentialProjectionKind::Windows,
        ) {
            let ray_id = match ww.cf_ray.as_deref() {
                Some(raw) => Some(normalize_cf_ray(raw)?.to_owned()),
                None => None,
            };
            println!(
                "access_failure_capture case=windows_to_windows http_status={} ray_id={} datetime_start={} datetime_end={}",
                ww.status,
                ray_id.as_deref().unwrap_or("ABSENT"),
                ww_start,
                ww_end
            );
            return Err(ProofAttemptError::FirstCase(AccessFailureEvidence {
                ray_id,
                datetime_start: ww_start,
                datetime_end: ww_end,
                http_status: ww.status,
                acceptance_error,
            }));
        }
        println!("access_request_classification case=windows_to_windows class=PASS");

        let wv = cloudflare::probe_worker(&vm_url, Some(&windows_credential)).await?;
        let vv = cloudflare::probe_worker(&vm_url, Some(&vm_credential)).await?;
        let vw = cloudflare::probe_worker(&windows_url, Some(&vm_credential)).await?;
        let aw = cloudflare::probe_worker(&windows_url, None).await?;
        let av = cloudflare::probe_worker(&vm_url, None).await?;

        require_denied("windows_to_vm", &wv)?;
        require_allowed(
            "vm_to_vm",
            &vv,
            &vm_material.payload,
            CredentialProjectionKind::Vm,
        )?;
        require_denied("vm_to_windows", &vw)?;
        require_denied("anonymous_to_windows", &aw)?;
        require_denied("anonymous_to_vm", &av)?;

        Ok(ProofReport {
            cases: vec![
                ProofCase {
                    name: "windows_to_windows",
                    outcome: "PASS",
                    status: ww.status,
                },
                ProofCase {
                    name: "windows_to_vm",
                    outcome: "DENIED",
                    status: wv.status,
                },
                ProofCase {
                    name: "vm_to_vm",
                    outcome: "PASS",
                    status: vv.status,
                },
                ProofCase {
                    name: "vm_to_windows",
                    outcome: "DENIED",
                    status: vw.status,
                },
                ProofCase {
                    name: "anonymous_to_windows",
                    outcome: "DENIED",
                    status: aw.status,
                },
                ProofCase {
                    name: "anonymous_to_vm",
                    outcome: "DENIED",
                    status: av.status,
                },
            ],
        })
    }
    .await;

    let disable_windows = cloudflare::set_access_service_token_enabled(
        api_token,
        &desired.target_account_id,
        windows_token_id,
        &windows.service_token_name,
        &desired.proof_token_duration,
        false,
    )
    .await;
    if disable_windows.is_ok() {
        mutations += 1;
    }
    let disable_vm = cloudflare::set_access_service_token_enabled(
        api_token,
        &desired.target_account_id,
        vm_token_id,
        &vm.service_token_name,
        &desired.proof_token_duration,
        false,
    )
    .await;
    if disable_vm.is_ok() {
        mutations += 1;
    }

    if let Err(err) = disable_windows {
        return Err(format!(
            "credential proof cleanup failed to disable Windows proof token: {err}; VM cleanup={:?}; windows_enabled_by_proof={windows_enabled_by_proof}; vm_enabled_by_proof={vm_enabled_by_proof}",
            disable_vm.err()
        ));
    }
    if let Err(err) = disable_vm {
        return Err(format!(
            "credential proof cleanup failed to disable VM proof token: {err}; windows_enabled_by_proof={windows_enabled_by_proof}; vm_enabled_by_proof={vm_enabled_by_proof}"
        ));
    }

    match proof_result {
        Ok(report) => Ok((report, mutations)),
        Err(ProofAttemptError::Ordinary(err)) => Err(err),
        Err(ProofAttemptError::FirstCase(failure)) => {
            let classification = diagnose_access_failure_after_cleanup(
                api_token,
                &desired.target_account_id,
                windows_policy_id,
                windows_token_id,
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
                "{}; proof-token cleanup completed; access_diagnostic_classification={classification}; no remaining matrix probes executed",
                failure.acceptance_error
            ))
        }
    }
}

async fn diagnose_access_failure_after_cleanup(
    api_token: &str,
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
            api_token,
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

fn validate_proof_token_state(
    projection: &ProjectionDesired,
    expected_token_id: &str,
    expected_duration: &str,
    expected_client_id: Option<&str>,
    token: &cloudflare::CloudflareAccessServiceToken,
) -> Result<String, String> {
    if token.id != expected_token_id {
        return Err(format!(
            "{} proof service token ID changed: expected={} observed={}",
            projection.projection, expected_token_id, token.id
        ));
    }
    if token.name.as_deref() != Some(projection.service_token_name.as_str()) {
        return Err(format!(
            "{} proof service token name mismatch",
            projection.projection
        ));
    }
    if token.enabled != Some(true) {
        return Err(format!(
            "{} proof service token is not enabled after proof-local enable/rotation: {:?}",
            projection.projection, token.enabled
        ));
    }
    if token.duration.as_deref() != Some(expected_duration) {
        return Err(format!(
            "{} proof service token duration mismatch: expected={} observed={}",
            projection.projection,
            expected_duration,
            token.duration.as_deref().unwrap_or("ABSENT")
        ));
    }
    let client_id = token.client_id.as_deref().ok_or_else(|| {
        format!(
            "{} proof service token client_id is missing",
            projection.projection
        )
    })?;
    if let Some(expected) = expected_client_id
        && client_id != expected
    {
        return Err(format!(
            "{} proof service token client_id changed: expected={} observed={}",
            projection.projection, expected, client_id
        ));
    }
    let expires_at = token.expires_at.as_deref().ok_or_else(|| {
        format!(
            "{} proof service token expires_at is missing",
            projection.projection
        )
    })?;
    let expires = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|err| {
        format!(
            "{} proof service token expires_at is not RFC3339: {err}",
            projection.projection
        )
    })?;
    if expires <= OffsetDateTime::now_utc() {
        return Err(format!(
            "{} proof service token is expired: expires_at={expires_at}",
            projection.projection
        ));
    }
    Ok(client_id.to_owned())
}

fn validate_rotated_credential(
    projection: &ProjectionDesired,
    expected_token_id: &str,
    expected_client_id: &str,
    expected_duration: &str,
    credential: &cloudflare::CloudflareAccessServiceCredential,
) -> Result<(), String> {
    if credential.id != expected_token_id {
        return Err(format!(
            "{} rotated proof credential token ID changed: expected={} observed={}",
            projection.projection, expected_token_id, credential.id
        ));
    }
    if credential.client_id != expected_client_id {
        return Err(format!(
            "{} rotated proof credential client_id changed: expected={} observed={}",
            projection.projection, expected_client_id, credential.client_id
        ));
    }
    if credential.enabled != Some(true) {
        return Err(format!(
            "{} rotated proof credential is not enabled: {:?}",
            projection.projection, credential.enabled
        ));
    }
    if credential.duration.as_deref() != Some(expected_duration) {
        return Err(format!(
            "{} rotated proof credential duration mismatch: expected={} observed={}",
            projection.projection,
            expected_duration,
            credential.duration.as_deref().unwrap_or("ABSENT")
        ));
    }
    if credential.name.as_deref() != Some(projection.service_token_name.as_str()) {
        return Err(format!(
            "{} rotated proof credential name mismatch",
            projection.projection
        ));
    }
    Ok(())
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

fn print_rotated_credential(
    projection: &ProjectionDesired,
    credential: &cloudflare::CloudflareAccessServiceCredential,
) {
    println!(
        "proof_token_rotation projection={} token_id={} client_id={} enabled={} duration={} name={}",
        projection.projection,
        credential.id,
        credential.client_id,
        credential
            .enabled
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        credential.duration.as_deref().unwrap_or("ABSENT"),
        credential.name.as_deref().unwrap_or("ABSENT")
    );
}

fn require_allowed(
    name: &str,
    probe: &cloudflare::CloudflareWorkerProbe,
    expected_body: &[u8],
    expected_projection: CredentialProjectionKind,
) -> Result<(), String> {
    if probe.status != 200 || probe.body != expected_body {
        return Err(format!(
            "{name} expected exact HTTP 200 typed dummy payload, observed status={} body_len={}",
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
    let payload = CredentialIsolationProbe::decode(probe.body.as_slice())
        .map_err(|err| format!("{name} returned invalid CredentialIsolationProbe: {err}"))?;
    if payload.encode_to_vec() != probe.body
        || payload.schema_version != 1
        || payload.generation != 1
        || payload.projection != expected_projection as i32
        || !payload.dummy_non_secret
    {
        return Err(format!(
            "{name} returned a non-canonical or incorrect typed dummy payload"
        ));
    }
    Ok(())
}

fn require_denied(name: &str, probe: &cloudflare::CloudflareWorkerProbe) -> Result<(), String> {
    if probe.status != 401 {
        return Err(format!(
            "{name} expected exact HTTP 401 Access denial, observed status={}",
            probe.status
        ));
    }
    Ok(())
}

async fn observe(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<CredentialPlaneObservation, String> {
    let control_token_identity = cloudflare::verify_api_token(api_token).await?;
    if control_token_identity.status != "active" {
        return Err(format!(
            "CLOUDFLARE_CONTROL_TOKEN exact identity {} is not active: {}",
            control_token_identity.id, control_token_identity.status
        ));
    }

    let scripts = cloudflare::list_worker_scripts(api_token, &desired.target_account_id).await?;
    let workers = cloudflare::list_workers(api_token, &desired.target_account_id).await?;
    let worker_domains =
        cloudflare::list_worker_domains(api_token, &desired.target_account_id).await?;

    let access_organization =
        match cloudflare::get_access_organization(api_token, &desired.target_account_id).await {
            Ok(value) => Some(value),
            Err(err) if cloudflare::is_access_not_enabled_error(&err) => None,
            Err(err) => return Err(err),
        };

    let (service_tokens, access_applications) = if access_organization.is_some() {
        (
            cloudflare::list_access_service_tokens(api_token, &desired.target_account_id).await?,
            cloudflare::list_access_applications(api_token, &desired.target_account_id).await?,
        )
    } else {
        (Vec::new(), Vec::new())
    };

    // The account-level workers.dev namespace is a distinct provider resource.
    // Its existence does not publish any Worker; per-Worker routing remains
    // explicitly locked until whole-Worker Access isolation is complete.
    let workers_dev_subdomain =
        match cloudflare::get_workers_subdomain(api_token, &desired.target_account_id).await {
            Ok(value) => Some(value.subdomain),
            Err(err) if cloudflare::is_workers_subdomain_not_configured_error(&err) => None,
            Err(err) => return Err(err),
        };

    // This owner is deliberately name-scoped. Other Workers, Access applications,
    // service tokens and domains may coexist in the dedicated account as later
    // Cloudflare phases converge; they are neither adopted nor rejected here.
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
        let worker_identity_present = worker_identity.is_some();
        let worker_id = worker_identity.map(|worker| worker.id.clone());

        let (settings, worker_secret_bindings, workers_dev_enabled, previews_enabled) = if worker_script_present {
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

        let matching_tokens = service_tokens
            .iter()
            .filter(|token| token.name.as_deref() == Some(projection.service_token_name.as_str()))
            .collect::<Vec<_>>();
        if matching_tokens.len() > 1 {
            return Err(format!(
                "duplicate service-token identity observed for {}",
                projection.service_token_name
            ));
        }
        let token = matching_tokens.first().copied();

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
        let custom_domain_count = worker_domains
            .iter()
            .filter(|domain| domain.service == projection.worker_name)
            .count();

        projections_observed.push(ProjectionObservation {
            projection: projection.projection,
            worker_name: projection.worker_name,
            worker_script_present,
            worker_identity_present,
            worker_id,
            worker_binding_count: settings.as_ref().map(|value| value.binding_count),
            worker_secret_bindings,
            worker_version_tag: settings.and_then(|value| value.version_tag),
            workers_dev_enabled,
            previews_enabled,
            custom_domain_count,
            service_token_id: token.map(|value| value.id.clone()),
            service_token_enabled: token.and_then(|value| value.enabled),
            service_token_duration: token.and_then(|value| value.duration.clone()),
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

fn ensure_projection_locked(
    projection: &ProjectionDesired,
    observed: &ProjectionObservation,
) -> Result<(), String> {
    if observed.workers_dev_enabled != Some(false) || observed.previews_enabled != Some(false) {
        return Err(format!(
            "Worker {} must remain workers.dev=false and previews=false until exact Access isolation is complete",
            projection.worker_name
        ));
    }
    Ok(())
}

fn projections(desired: &ProductionCredentialPlaneOwnership) -> [ProjectionDesired; 2] {
    [
        ProjectionDesired {
            projection: "windows".to_owned(),
            worker_name: desired.windows_worker_name.clone(),
            access_application_name: desired.windows_access_application_name.clone(),
            access_policy_name: desired.windows_access_policy_name.clone(),
            service_token_name: desired.windows_service_token_name.clone(),
        },
        ProjectionDesired {
            projection: "vm".to_owned(),
            worker_name: desired.vm_worker_name.clone(),
            access_application_name: desired.vm_access_application_name.clone(),
            access_policy_name: desired.vm_access_policy_name.clone(),
            service_token_name: desired.vm_service_token_name.clone(),
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

fn workers_dev_hostname(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
) -> String {
    format!(
        "{}.{}.workers.dev",
        projection.worker_name, desired.workers_dev_subdomain
    )
}

fn worker_material(
    _desired: &ProductionCredentialPlaneOwnership,
    projection: &str,
) -> Result<WorkerMaterial, String> {
    let projection_kind = match projection {
        "windows" => CredentialProjectionKind::Windows,
        "vm" => CredentialProjectionKind::Vm,
        _ => return Err(format!("unsupported credential projection {projection}")),
    };
    let payload = CredentialIsolationProbe {
        schema_version: 1,
        generation: 1,
        projection: projection_kind as i32,
        dummy_non_secret: true,
    }
    .encode_to_vec();
    let payload_hex = payload
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let source = format!(
        "const H=\"{payload_hex}\";const B=new Uint8Array(H.length/2);for(let i=0;i<B.length;i++)B[i]=Number.parseInt(H.slice(i*2,i*2+2),16);export default{{async fetch(request){{const u=new URL(request.url);if(request.method!==\"GET\"||u.pathname!==\"/v1/credentials\"||u.searchParams.size!==1||u.searchParams.get(\"generation\")!==\"1\")return new Response(null,{{status:404,headers:{{\"Cache-Control\":\"no-store\"}}}});return new Response(B,{{status:200,headers:{{\"Content-Type\":\"application/x-protobuf\",\"Cache-Control\":\"no-store\"}}}})}} }};\n"
    );
    let source_hash = sha256_hex(source.as_bytes());
    let version_tag = format!("sing-box-phase2-{projection}-{}", &source_hash[..16]);
    Ok(WorkerMaterial {
        payload,
        source,
        version_tag,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn action_name(action: &CredentialPlaneAction) -> &'static str {
    match action {
        CredentialPlaneAction::Noop => "NOOP",
        CredentialPlaneAction::CreateAccessOrganization => "CREATE_ACCESS_ORGANIZATION",
        CredentialPlaneAction::CreateWorkersDevSubdomain => "CREATE_WORKERS_DEV_SUBDOMAIN",
        CredentialPlaneAction::CreateWorkerIdentityLocked { .. } => "CREATE_WORKER_IDENTITY_LOCKED",
        CredentialPlaneAction::UploadWorkerModuleLocked { .. } => "UPLOAD_WORKER_MODULE_LOCKED",
        CredentialPlaneAction::CreateServiceToken { .. } => "CREATE_SERVICE_TOKEN",
        CredentialPlaneAction::CreateAccessApplication { .. } => "CREATE_ACCESS_APPLICATION",
        CredentialPlaneAction::UpdateAccessApplication { .. } => "UPDATE_ACCESS_APPLICATION",
        CredentialPlaneAction::CreateAccessPolicy { .. } => "CREATE_ACCESS_POLICY",
        CredentialPlaneAction::ConfigureWorkersDev { .. } => "CONFIGURE_WORKERS_DEV",
        CredentialPlaneAction::DisableProofToken { .. } => "DISABLE_PROOF_TOKEN",
        CredentialPlaneAction::ProveIsolationAndLock => "PROVE_ISOLATION_AND_LOCK",
    }
}

async fn print_access_evaluation_inventory(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let applications =
        cloudflare::list_access_applications(api_token, &desired.target_account_id).await?;
    let reusable =
        cloudflare::list_access_reusable_policies(api_token, &desired.target_account_id).await?;
    println!("access_application_total={}", applications.len());
    for app in applications {
        let destinations = app
            .destinations
            .iter()
            .map(|destination| {
                format!(
                    "{}:worker_id={}:uri={}:overrides={}",
                    destination.destination_type,
                    destination.worker_id.as_deref().unwrap_or("ABSENT"),
                    destination.uri.as_deref().unwrap_or("ABSENT"),
                    destination.has_overrides
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let policy_refs = if app.policy_ids.is_empty() {
            "NONE".to_owned()
        } else {
            app.policy_ids.join(",")
        };
        let legacy = cloudflare::list_access_application_policies(
            api_token,
            &desired.target_account_id,
            &app.id,
        )
        .await?;
        println!(
            "access_application id={} name={} type={} service_auth_401_redirect={} destinations={} policy_refs={} legacy_policy_count={}",
            app.id,
            app.name,
            app.app_type,
            app.service_auth_401_redirect
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            if destinations.is_empty() {
                "NONE".to_owned()
            } else {
                destinations
            },
            policy_refs,
            legacy.len()
        );
        for policy in legacy {
            println!(
                "access_application_policy app_id={} id={} name={} decision={} precedence={} reusable={} app_count={} service_token_ids={} extra_rules={}",
                app.id,
                policy.id,
                policy.name,
                policy.decision.as_deref().unwrap_or("ABSENT"),
                policy
                    .precedence
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "ABSENT".to_owned()),
                policy
                    .reusable
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "ABSENT".to_owned()),
                policy
                    .app_count
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "ABSENT".to_owned()),
                if policy.include_service_token_ids.is_empty() {
                    "NONE".to_owned()
                } else {
                    policy.include_service_token_ids.join(",")
                },
                policy.has_extra_rules
            );
        }
    }
    println!("access_reusable_policy_total={}", reusable.len());
    for policy in reusable {
        println!(
            "access_reusable_policy id={} name={} decision={} precedence={} reusable={} app_count={} service_token_ids={} extra_rules={}",
            policy.id,
            policy.name,
            policy.decision.as_deref().unwrap_or("ABSENT"),
            policy
                .precedence
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            policy
                .reusable
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            policy
                .app_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            if policy.include_service_token_ids.is_empty() {
                "NONE".to_owned()
            } else {
                policy.include_service_token_ids.join(",")
            },
            policy.has_extra_rules
        );
    }
    Ok(())
}

fn print_observation(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) {
    println!("target_account_id={}", desired.target_account_id);
    println!("control_token_id={}", observed.control_token_identity.id);
    println!(
        "control_token_status={}",
        observed.control_token_identity.status
    );
    println!(
        "access_organization={}",
        observed
            .access_organization
            .as_ref()
            .map(|value| value.name.as_str())
            .unwrap_or("NOT_CONFIGURED")
    );
    println!(
        "workers_dev_subdomain={}",
        observed
            .workers_dev_subdomain
            .as_deref()
            .unwrap_or("NOT_CONFIGURED")
    );
    for projection in &observed.projections {
        println!(
            "projection={} worker={} worker_identity_present={} worker_script_present={} worker_id={} bindings={} workers_dev={} previews={} custom_domains={} service_token_id={} service_token_enabled={} access_application_id={} policies={}",
            projection.projection,
            projection.worker_name,
            projection.worker_identity_present,
            projection.worker_script_present,
            projection.worker_id.as_deref().unwrap_or("ABSENT"),
            projection
                .worker_binding_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            projection
                .workers_dev_enabled
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            projection
                .previews_enabled
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            projection.custom_domain_count,
            projection.service_token_id.as_deref().unwrap_or("ABSENT"),
            projection
                .service_token_enabled
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            projection
                .access_application_id
                .as_deref()
                .unwrap_or("ABSENT"),
            projection.access_policies.len(),
        );
    }
}

fn print_terminal(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
    mutations: u32,
    proof: Option<&ProofReport>,
) {
    print_observation(desired, observed);
    if let Some(proof) = proof {
        for case in &proof.cases {
            println!(
                "auth_matrix={} outcome={} status={}",
                case.name, case.outcome, case.status
            );
        }
        println!("isolation_proof=PASS");
    } else {
        println!("isolation_proof=NOT_RUN_STRUCTURAL_NOOP");
    }
    println!("credential_plane_status=PASS");
    println!("credential_isolation_probe_schema=1");
    println!("dummy_non_secret=true");
    println!("real_credentials_created=0");
    println!("proof_tokens_enabled=false");
    println!("previews_enabled=false");
    println!("provider_mutations={mutations}");
    println!("production_runtime_mutations=0");
    println!("active_account_unchanged=true");
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
            worker_compatibility_date: "2026-09-28".to_owned(),
            proof_token_duration: "1h".to_owned(),
            workers_dev_subdomain: "sing-box-6be6e4b6340822dbeb18cb6c2f09c660".to_owned(),
        }
    }

    fn exact_projection_observation(
        desired: &ProductionCredentialPlaneOwnership,
        projection_name: &str,
        destination_type: &str,
    ) -> ProjectionObservation {
        let projection = projection_desired(desired, projection_name).unwrap();
        let worker_id = format!("{projection_name}-worker-id");
        let token_id = format!("{projection_name}-token-id");
        let hostname = workers_dev_hostname(desired, &projection);
        let (destination_worker_id, destination_uri) = match destination_type {
            "worker" => (Some(worker_id.clone()), None),
            "public" => (None, Some(hostname)),
            other => (None, Some(format!("{other}.invalid"))),
        };
        ProjectionObservation {
            projection: projection.projection.clone(),
            worker_name: projection.worker_name,
            worker_script_present: true,
            worker_identity_present: true,
            worker_id: Some(worker_id),
            worker_binding_count: Some(0),
            worker_version_tag: Some(
                worker_material(desired, &projection.projection)
                    .unwrap()
                    .version_tag,
            ),
            workers_dev_enabled: Some(true),
            previews_enabled: Some(false),
            custom_domain_count: 0,
            service_token_id: Some(token_id.clone()),
            service_token_enabled: Some(false),
            service_token_duration: Some(desired.proof_token_duration.clone()),
            access_application_id: Some(format!("{projection_name}-app-id")),
            access_application_type: Some("self_hosted".to_owned()),
            access_service_auth_401_redirect: Some(true),
            access_destination_type: Some(destination_type.to_owned()),
            access_destination_worker_id: destination_worker_id,
            access_destination_uri: destination_uri,
            access_destination_has_overrides: Some(false),
            access_policies: vec![cloudflare::CloudflareAccessPolicy {
                id: format!("{projection_name}-policy-id"),
                name: projection.access_policy_name,
                decision: Some("non_identity".to_owned()),
                include_service_token_ids: vec![token_id],
                has_extra_rules: false,
                precedence: Some(1),
                reusable: Some(false),
                app_count: None,
            }],
        }
    }

    fn exact_observation(
        desired: &ProductionCredentialPlaneOwnership,
        windows_destination: &str,
        vm_destination: &str,
    ) -> CredentialPlaneObservation {
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
                exact_projection_observation(desired, "windows", windows_destination),
                exact_projection_observation(desired, "vm", vm_destination),
            ],
        }
    }

    #[test]
    fn exact_hostname_access_destination_is_terminal_noop() {
        let desired = desired();
        let observed = exact_observation(&desired, "public", "public");
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialPlaneAction::Noop
        );
    }

    #[test]
    fn exact_legacy_worker_destination_plans_one_in_place_update() {
        let desired = desired();
        let observed = exact_observation(&desired, "worker", "public");
        assert_eq!(
            plan(&desired, &observed).unwrap(),
            CredentialPlaneAction::UpdateAccessApplication {
                projection: "windows".to_owned(),
            }
        );
    }

    #[test]
    fn unrelated_access_destination_fails_closed() {
        let desired = desired();
        let observed = exact_observation(&desired, "unexpected", "public");
        assert!(plan(&desired, &observed).is_err());
    }

    #[test]
    fn workers_dev_hostname_is_exact_and_scheme_free() {
        let desired = desired();
        let projection = projection_desired(&desired, "windows").unwrap();
        assert_eq!(
            workers_dev_hostname(&desired, &projection),
            "sing-box-credentials-windows.sing-box-6be6e4b6340822dbeb18cb6c2f09c660.workers.dev"
        );
    }

    #[test]
    fn dummy_workers_are_physically_projection_specific_and_secret_free() {
        let desired = desired();
        let windows = worker_material(&desired, "windows").unwrap();
        let vm = worker_material(&desired, "vm").unwrap();
        assert_ne!(windows.source, vm.source);
        assert_ne!(windows.version_tag, vm.version_tag);
        let windows_probe = CredentialIsolationProbe::decode(windows.payload.as_slice()).unwrap();
        let vm_probe = CredentialIsolationProbe::decode(vm.payload.as_slice()).unwrap();
        assert_eq!(
            windows_probe.projection,
            CredentialProjectionKind::Windows as i32
        );
        assert_eq!(vm_probe.projection, CredentialProjectionKind::Vm as i32);
        assert!(windows_probe.dummy_non_secret);
        assert!(vm_probe.dummy_non_secret);
        assert!(!windows.source.contains("private_key"));
        assert!(!vm.source.contains("password"));
        assert!(!windows.source.contains("0x08"));
        assert!(!vm.source.contains("0x08"));
    }

    #[test]
    fn proof_token_state_requires_exact_live_identity_and_future_expiry() {
        let projection = projection_desired(&desired(), "windows").unwrap();
        let token = cloudflare::CloudflareAccessServiceToken {
            id: "token-id".to_owned(),
            name: Some(projection.service_token_name.clone()),
            enabled: Some(true),
            expires_at: Some("9999-12-31T23:59:59Z".to_owned()),
            duration: Some("1h".to_owned()),
            client_id: Some("client-id".to_owned()),
        };
        assert_eq!(
            validate_proof_token_state(&projection, "token-id", "1h", None, &token).unwrap(),
            "client-id"
        );
        assert!(
            validate_proof_token_state(
                &projection,
                "token-id",
                "1h",
                Some("different-client"),
                &token
            )
            .is_err()
        );

        let mut expired = token.clone();
        expired.expires_at = Some("2000-01-01T00:00:00Z".to_owned());
        assert!(validate_proof_token_state(&projection, "token-id", "1h", None, &expired).is_err());
    }

    #[test]
    fn rotated_credential_must_preserve_token_and_client_identity() {
        let projection = projection_desired(&desired(), "windows").unwrap();
        let credential = cloudflare::CloudflareAccessServiceCredential {
            id: "token-id".to_owned(),
            client_id: "client-id".to_owned(),
            client_secret: "secret-value".to_owned(),
            enabled: Some(true),
            duration: Some("1h".to_owned()),
            name: Some(projection.service_token_name.clone()),
        };
        assert!(
            validate_rotated_credential(&projection, "token-id", "client-id", "1h", &credential)
                .is_ok()
        );
    }

    #[test]
    fn access_denial_contract_ignores_provider_body() {
        let probe = cloudflare::CloudflareWorkerProbe {
            status: 401,
            content_type: Some("text/html".to_owned()),
            cf_ray: Some("187d944c61940c77-WAW".to_owned()),
            body: vec![0; 8192],
        };
        assert!(require_denied("anonymous_to_windows", &probe).is_ok());
    }

    #[test]
    fn cf_ray_normalization_is_exact_and_bounded() {
        assert_eq!(
            normalize_cf_ray("187d944c61940c77-WAW").unwrap(),
            "187d944c61940c77"
        );
        assert_eq!(
            normalize_cf_ray("187d944c61940c77").unwrap(),
            "187d944c61940c77"
        );
        assert!(normalize_cf_ray("not-a-ray").is_err());
        assert!(normalize_cf_ray("187d944c61940c7").is_err());
    }

    #[test]
    fn access_login_diagnostics_classify_exact_token_policy_and_status() {
        let base = cloudflare::CloudflareAccessLoginEvent {
            datetime: Some("2026-09-28T18:00:00Z".to_owned()),
            is_successful_login: Some(true),
            approving_policy_id: Some("policy-id".to_owned()),
            cf_ray_id: Some("187d944c61940c77".to_owned()),
            identity_provider: Some("nonidentity".to_owned()),
            service_token_id: Some("token-id".to_owned()),
        };
        assert_eq!(
            classify_access_login_events(
                "187d944c61940c77",
                "policy-id",
                "token-id",
                401,
                std::slice::from_ref(&base),
            )
            .unwrap(),
            "ACCESS_ALLOWED_BUT_WORKER_FAILED"
        );

        let mut denied = base.clone();
        denied.is_successful_login = Some(false);
        assert_eq!(
            classify_access_login_events(
                "187d944c61940c77",
                "policy-id",
                "token-id",
                401,
                &[denied],
            )
            .unwrap(),
            "POLICY_DENIED"
        );

        let mut wrong_token = base;
        wrong_token.service_token_id = Some("other-token".to_owned());
        assert_eq!(
            classify_access_login_events(
                "187d944c61940c77",
                "policy-id",
                "token-id",
                401,
                &[wrong_token],
            )
            .unwrap(),
            "TOKEN_INVALID"
        );
    }

    #[test]
    fn action_names_are_bounded_and_explicit() {
        assert_eq!(
            action_name(&CredentialPlaneAction::ProveIsolationAndLock),
            "PROVE_ISOLATION_AND_LOCK"
        );
        assert_eq!(
            action_name(&CredentialPlaneAction::CreateWorkersDevSubdomain),
            "CREATE_WORKERS_DEV_SUBDOMAIN"
        );
        assert_eq!(
            action_name(&CredentialPlaneAction::DisableProofToken {
                projection: "windows".to_owned(),
            }),
            "DISABLE_PROOF_TOKEN"
        );
        assert_eq!(
            action_name(&CredentialPlaneAction::UpdateAccessApplication {
                projection: "windows".to_owned(),
            }),
            "UPDATE_ACCESS_APPLICATION"
        );
        assert_eq!(action_name(&CredentialPlaneAction::Noop), "NOOP");
    }
}
