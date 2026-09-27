use edge_controller_core::cloudflare_credential_plane::{
    CREDENTIAL_ISOLATION_GENERATION, CredentialPlaneAction, CredentialPlaneDesired,
    CredentialPlaneObservation, CredentialPlanePlan, CredentialProjection,
    CredentialProjectionDesired, CredentialProjectionObservation,
    authorize_credential_plane_plan,
};
use edge_controller_core::production::ProductionComposition;
use edge_provider_cloudflare::{
    self as cloudflare, CloudflareAccessApplication, CloudflareAccessPolicy,
    CloudflareAccessServiceToken, CloudflareAccessServiceTokenSecret, CloudflareWorkerScript,
};
use edge_shared_types::{CredentialIsolationProbe, CredentialProjectionKind};
use prost::Message;
use serde::Serialize;

const WORKER_COMPATIBILITY_DATE: &str = "2026-09-28";
const SERVICE_TOKEN_DURATION: &str = "8760h";
const MAX_CONVERGENCE_MUTATIONS: usize = 8;
const WORKER_TEMPLATE: &str =
    include_str!("../../../../infra/cloudflare/credential-worker.mjs");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialPlaneConvergenceStep {
    pub iteration: usize,
    pub authority_digest: String,
    pub performed: CredentialPlaneAction,
    pub next: CredentialPlaneAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialPlaneConvergenceReport {
    pub status: &'static str,
    pub mutations_performed: usize,
    pub steps: Vec<CredentialPlaneConvergenceStep>,
    pub observation: CredentialPlaneObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialPlaneVerificationReport {
    pub status: &'static str,
    pub mutations_performed: usize,
    pub observation: CredentialPlaneObservation,
    pub plan: CredentialPlanePlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialIsolationMatrix {
    pub windows_to_windows: &'static str,
    pub windows_to_vm: &'static str,
    pub vm_to_vm: &'static str,
    pub vm_to_windows: &'static str,
    pub anonymous_to_windows: &'static str,
    pub anonymous_to_vm: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialPlaneAcceptanceReport {
    pub status: &'static str,
    pub provider_mutations_performed: usize,
    pub target_account_id: String,
    pub active_production_account_id: String,
    pub windows_worker_name: String,
    pub windows_worker_tag: String,
    pub vm_worker_name: String,
    pub vm_worker_tag: String,
    pub windows_service_token_id: String,
    pub vm_service_token_id: String,
    pub windows_access_application_id: String,
    pub vm_access_application_id: String,
    pub windows_access_policy_id: String,
    pub vm_access_policy_id: String,
    pub workers_subdomain: String,
    pub previews_enabled: bool,
    pub dummy_non_secret_payload: bool,
    pub real_application_credentials_created: bool,
    pub production_account_changed: bool,
    pub production_runtime_touched: bool,
    pub matrix: CredentialIsolationMatrix,
}

pub fn desired_from_production() -> Result<CredentialPlaneDesired, String> {
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let target_account_id = production
        .cloudflare
        .migration_target_account_id
        .clone()
        .ok_or_else(|| {
            "Phase 2 requires cloudflare.migration_target_account_id before the Phase 5 authority flip"
                .to_owned()
        })?;
    let plane = &production.cloudflare.credential_plane;
    Ok(CredentialPlaneDesired {
        account_id: target_account_id,
        generation: CREDENTIAL_ISOLATION_GENERATION,
        windows: CredentialProjectionDesired {
            worker_name: plane.windows_worker_name.clone(),
            service_token_name: plane.windows_service_token_name.clone(),
        },
        vm: CredentialProjectionDesired {
            worker_name: plane.vm_worker_name.clone(),
            service_token_name: plane.vm_service_token_name.clone(),
        },
    })
}

pub async fn plan(api_token: &str) -> Result<CredentialPlanePlan, String> {
    let desired = desired_from_production()?;
    let observed = observe(api_token, &desired).await?;
    authorize_credential_plane_plan(&desired, &observed)
}

pub async fn verify(api_token: &str) -> Result<CredentialPlaneVerificationReport, String> {
    let desired = desired_from_production()?;
    let observation = observe(api_token, &desired).await?;
    let plan = authorize_credential_plane_plan(&desired, &observation)?;
    if !matches!(plan.plan, CredentialPlaneAction::Noop) {
        return Err(format!(
            "credential-plane verification requires NOOP, observed next action {:?}",
            plan.plan
        ));
    }
    Ok(CredentialPlaneVerificationReport {
        status: "PASS",
        mutations_performed: 0,
        observation,
        plan,
    })
}

pub async fn converge(api_token: &str) -> Result<CredentialPlaneConvergenceReport, String> {
    let desired = desired_from_production()?;
    let mut steps = Vec::new();

    for iteration in 1..=MAX_CONVERGENCE_MUTATIONS {
        let observed = observe(api_token, &desired).await?;
        let authorized = authorize_credential_plane_plan(&desired, &observed)?;
        if matches!(authorized.plan, CredentialPlaneAction::Noop) {
            return Ok(CredentialPlaneConvergenceReport {
                status: "PASS",
                mutations_performed: steps.len(),
                steps,
                observation: observed,
            });
        }

        let performed = authorized.plan.clone();
        apply_once(api_token, &desired, &observed, &performed).await?;

        let reobserved = observe(api_token, &desired).await?;
        let next = authorize_credential_plane_plan(&desired, &reobserved)?;
        if next.plan == performed {
            return Err(format!(
                "credential-plane mutation {:?} was not proven by re-observation; refusing blind replay",
                performed
            ));
        }

        steps.push(CredentialPlaneConvergenceStep {
            iteration,
            authority_digest: authorized.authority.authority_digest,
            performed,
            next: next.plan.clone(),
        });

        if matches!(next.plan, CredentialPlaneAction::Noop) {
            return Ok(CredentialPlaneConvergenceReport {
                status: "PASS",
                mutations_performed: steps.len(),
                steps,
                observation: reobserved,
            });
        }
    }

    Err(format!(
        "credential-plane convergence exceeded the bounded {MAX_CONVERGENCE_MUTATIONS}-mutation limit"
    ))
}

pub async fn acceptance(api_token: &str) -> Result<CredentialPlaneAcceptanceReport, String> {
    let desired = desired_from_production()?;
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let observation = observe(api_token, &desired).await?;
    let structural = authorize_credential_plane_plan(&desired, &observation)?;
    if !matches!(structural.plan, CredentialPlaneAction::Noop) {
        return Err(format!(
            "credential-plane acceptance requires structurally converged state, next action {:?}",
            structural.plan
        ));
    }

    let windows_token_id = required(
        "windows service token ID",
        observation.windows.service_token_id.as_deref(),
    )?;
    let vm_token_id = required(
        "VM service token ID",
        observation.vm.service_token_id.as_deref(),
    )?;
    let windows_secret =
        cloudflare::rotate_access_service_token(api_token, &desired.account_id, windows_token_id)
            .await?;
    validate_rotated_token(
        &windows_secret,
        windows_token_id,
        &desired.windows.service_token_name,
    )?;
    let vm_secret =
        cloudflare::rotate_access_service_token(api_token, &desired.account_id, vm_token_id)
            .await?;
    validate_rotated_token(&vm_secret, vm_token_id, &desired.vm.service_token_name)?;

    let workers_subdomain = required(
        "Workers subdomain",
        observation.workers_subdomain.as_deref(),
    )?
    .to_owned();
    let windows_url = probe_url(&desired.windows.worker_name, &workers_subdomain);
    let vm_url = probe_url(&desired.vm.worker_name, &workers_subdomain);

    let windows_to_windows =
        cloudflare::probe_access_url(
            &windows_url,
            Some(&windows_secret.client_id),
            Some(&windows_secret.client_secret),
        )
        .await?;
    assert_allowed_probe(
        "windows identity -> windows Worker",
        &windows_to_windows,
        CredentialProjectionKind::Windows,
    )?;

    let windows_to_vm =
        cloudflare::probe_access_url(
            &vm_url,
            Some(&windows_secret.client_id),
            Some(&windows_secret.client_secret),
        )
        .await?;
    assert_denied_probe("windows identity -> VM Worker", &windows_to_vm)?;

    let vm_to_vm =
        cloudflare::probe_access_url(
            &vm_url,
            Some(&vm_secret.client_id),
            Some(&vm_secret.client_secret),
        )
        .await?;
    assert_allowed_probe(
        "VM identity -> VM Worker",
        &vm_to_vm,
        CredentialProjectionKind::Vm,
    )?;

    let vm_to_windows =
        cloudflare::probe_access_url(
            &windows_url,
            Some(&vm_secret.client_id),
            Some(&vm_secret.client_secret),
        )
        .await?;
    assert_denied_probe("VM identity -> windows Worker", &vm_to_windows)?;

    let anonymous_to_windows = cloudflare::probe_access_url(&windows_url, None, None).await?;
    assert_denied_probe("anonymous -> windows Worker", &anonymous_to_windows)?;
    let anonymous_to_vm = cloudflare::probe_access_url(&vm_url, None, None).await?;
    assert_denied_probe("anonymous -> VM Worker", &anonymous_to_vm)?;

    Ok(CredentialPlaneAcceptanceReport {
        status: "PASS",
        provider_mutations_performed: 2,
        target_account_id: desired.account_id.clone(),
        active_production_account_id: production.cloudflare.active_account_id.clone(),
        windows_worker_name: desired.windows.worker_name.clone(),
        windows_worker_tag: required(
            "windows Worker immutable tag",
            observation.windows.worker_tag.as_deref(),
        )?
        .to_owned(),
        vm_worker_name: desired.vm.worker_name.clone(),
        vm_worker_tag: required(
            "VM Worker immutable tag",
            observation.vm.worker_tag.as_deref(),
        )?
        .to_owned(),
        windows_service_token_id: windows_token_id.to_owned(),
        vm_service_token_id: vm_token_id.to_owned(),
        windows_access_application_id: required(
            "windows Access application ID",
            observation.windows.access_application_id.as_deref(),
        )?
        .to_owned(),
        vm_access_application_id: required(
            "VM Access application ID",
            observation.vm.access_application_id.as_deref(),
        )?
        .to_owned(),
        windows_access_policy_id: required(
            "windows Access policy ID",
            observation.windows.access_policy_id.as_deref(),
        )?
        .to_owned(),
        vm_access_policy_id: required(
            "VM Access policy ID",
            observation.vm.access_policy_id.as_deref(),
        )?
        .to_owned(),
        workers_subdomain,
        previews_enabled: false,
        dummy_non_secret_payload: true,
        real_application_credentials_created: false,
        production_account_changed: false,
        production_runtime_touched: false,
        matrix: CredentialIsolationMatrix {
            windows_to_windows: "PASS",
            windows_to_vm: "DENIED",
            vm_to_vm: "PASS",
            vm_to_windows: "DENIED",
            anonymous_to_windows: "DENIED",
            anonymous_to_vm: "DENIED",
        },
    })
}

async fn apply_once(
    api_token: &str,
    desired: &CredentialPlaneDesired,
    observed: &CredentialPlaneObservation,
    action: &CredentialPlaneAction,
) -> Result<(), String> {
    match action {
        CredentialPlaneAction::CreateWorker { projection } => {
            let projection_desired = projection_desired(desired, *projection);
            let source = render_worker_source(*projection)?;
            let worker = cloudflare::upload_worker_module(
                api_token,
                &desired.account_id,
                &projection_desired.worker_name,
                WORKER_COMPATIBILITY_DATE,
                &source,
            )
            .await?;
            if worker.id != projection_desired.worker_name || worker.tag.as_deref().is_none_or(str::is_empty) {
                return Err(format!(
                    "Cloudflare Worker create did not return exact name + immutable tag for {}",
                    projection.as_str()
                ));
            }
            Ok(())
        }
        CredentialPlaneAction::ConfigureWorkerSubdomain { projection } => {
            let projection_desired = projection_desired(desired, *projection);
            let configured = cloudflare::configure_worker_script_subdomain(
                api_token,
                &desired.account_id,
                &projection_desired.worker_name,
                true,
                false,
            )
            .await?;
            if !configured.enabled || configured.previews_enabled {
                return Err(format!(
                    "Cloudflare Worker subdomain did not converge to enabled=true previews_enabled=false for {}",
                    projection.as_str()
                ));
            }
            Ok(())
        }
        CredentialPlaneAction::CreateServiceToken { projection } => {
            let projection_desired = projection_desired(desired, *projection);
            let token = cloudflare::create_access_service_token(
                api_token,
                &desired.account_id,
                &projection_desired.service_token_name,
                SERVICE_TOKEN_DURATION,
            )
            .await?;
            if token.name != projection_desired.service_token_name || !token.enabled {
                return Err(format!(
                    "Cloudflare Access service token create returned unexpected identity for {}",
                    projection.as_str()
                ));
            }
            drop(token);
            Ok(())
        }
        CredentialPlaneAction::CreateAccessApplication { projection } => {
            let projection_desired = projection_desired(desired, *projection);
            let actual = projection_observation(observed, *projection);
            let worker_id = required(
                "Worker immutable tag before Access application create",
                actual.worker_tag.as_deref(),
            )?;
            let service_token_id = required(
                "service token ID before Access application create",
                actual.service_token_id.as_deref(),
            )?;
            let app = cloudflare::create_worker_access_application(
                api_token,
                &desired.account_id,
                &projection_desired.access_application_name(),
                worker_id,
                &projection_desired.access_policy_name(),
                service_token_id,
            )
            .await?;
            if app.name != projection_desired.access_application_name()
                || app.app_type != "self_hosted"
            {
                return Err(format!(
                    "Cloudflare Worker Access application create returned unexpected identity for {}",
                    projection.as_str()
                ));
            }
            Ok(())
        }
        CredentialPlaneAction::Noop => Ok(()),
    }
}

pub async fn observe(
    api_token: &str,
    desired: &CredentialPlaneDesired,
) -> Result<CredentialPlaneObservation, String> {
    let scripts = cloudflare::list_worker_scripts(api_token, &desired.account_id).await?;
    let access_apps = access_or_empty(
        cloudflare::list_access_applications(api_token, &desired.account_id).await,
    )?;
    let service_tokens = access_or_empty(
        cloudflare::list_access_service_tokens(api_token, &desired.account_id).await,
    )?;

    let windows =
        observe_projection(api_token, &desired.account_id, &desired.windows, &scripts, &service_tokens, &access_apps)
            .await?;
    let vm =
        observe_projection(api_token, &desired.account_id, &desired.vm, &scripts, &service_tokens, &access_apps)
            .await?;

    let workers_subdomain = if windows.worker_tag.is_some() && vm.worker_tag.is_some() {
        match cloudflare::get_workers_subdomain(api_token, &desired.account_id).await {
            Ok(value) => Some(value.subdomain),
            Err(_) => None,
        }
    } else {
        None
    };

    Ok(CredentialPlaneObservation {
        workers_subdomain,
        windows,
        vm,
    })
}

async fn observe_projection(
    api_token: &str,
    account_id: &str,
    desired: &CredentialProjectionDesired,
    scripts: &[CloudflareWorkerScript],
    service_tokens: &[CloudflareAccessServiceToken],
    access_apps: &[CloudflareAccessApplication],
) -> Result<CredentialProjectionObservation, String> {
    let worker = scripts.iter().find(|script| script.id == desired.worker_name);
    let worker_tag = match worker {
        Some(worker) => Some(
            worker
                .tag
                .clone()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    format!(
                        "Worker {} exists but has no immutable provider tag",
                        desired.worker_name
                    )
                })?,
        ),
        None => None,
    };
    let (worker_subdomain_enabled, worker_previews_enabled) = match worker {
        Some(_) => {
            let subdomain =
                cloudflare::get_worker_script_subdomain(api_token, account_id, &desired.worker_name)
                    .await?;
            (Some(subdomain.enabled), Some(subdomain.previews_enabled))
        }
        None => (None, None),
    };

    let matching_tokens = service_tokens
        .iter()
        .filter(|token| token.name.as_deref() == Some(desired.service_token_name.as_str()))
        .collect::<Vec<_>>();
    if matching_tokens.len() > 1 {
        return Err(format!(
            "multiple Cloudflare Access service tokens match canonical name {}",
            desired.service_token_name
        ));
    }
    let service_token = matching_tokens.first().copied();

    let matching_apps = access_apps
        .iter()
        .filter(|app| app.name == desired.access_application_name())
        .collect::<Vec<_>>();
    if matching_apps.len() > 1 {
        return Err(format!(
            "multiple Cloudflare Access applications match canonical name {}",
            desired.access_application_name()
        ));
    }
    let app = matching_apps.first().copied();

    let mut access_destination_worker_id = None;
    let mut access_application_has_extra_destinations = false;
    let mut access_policy_id = None;
    let mut access_policy_decision = None;
    let mut access_policy_service_token_ids = Vec::new();
    let mut access_policy_has_extra_rules = false;

    if let Some(app) = app {
        access_application_has_extra_destinations = app.app_type != "self_hosted"
            || app.destinations.len() != 1
            || app.destinations[0].destination_type != "worker"
            || app.destinations[0].worker_id.is_none()
            || app.destinations[0].overrides_count != 0;
        access_destination_worker_id = app
            .destinations
            .first()
            .and_then(|destination| destination.worker_id.clone());

        let policies =
            cloudflare::list_access_application_policies(api_token, account_id, &app.id).await?;
        let policy_name = desired.access_policy_name();
        let matching_policies = policies
            .iter()
            .filter(|policy| policy.name == policy_name)
            .collect::<Vec<_>>();
        if matching_policies.len() > 1 {
            return Err(format!(
                "multiple Cloudflare Access policies match canonical name {policy_name}"
            ));
        }
        access_policy_has_extra_rules = policies.len() != 1;
        if let Some(policy) = matching_policies.first() {
            access_policy_id = Some(policy.id.clone());
            access_policy_decision = policy.decision.clone();
            access_policy_service_token_ids = policy.service_token_ids.clone();
            access_policy_has_extra_rules |= policy.has_extra_rules;
        }
    }

    Ok(CredentialProjectionObservation {
        worker_tag,
        worker_subdomain_enabled,
        worker_previews_enabled,
        service_token_id: service_token.map(|token| token.id.clone()),
        service_token_enabled: service_token.and_then(|token| token.enabled),
        access_application_id: app.map(|app| app.id.clone()),
        access_destination_worker_id,
        access_application_has_extra_destinations,
        access_policy_id,
        access_policy_decision,
        access_policy_service_token_ids,
        access_policy_has_extra_rules,
    })
}

fn access_or_empty<T>(value: Result<Vec<T>, String>) -> Result<Vec<T>, String> {
    match value {
        Ok(value) => Ok(value),
        Err(error) if cloudflare::is_access_not_enabled_error(&error) => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn projection_desired(
    desired: &CredentialPlaneDesired,
    projection: CredentialProjection,
) -> &CredentialProjectionDesired {
    match projection {
        CredentialProjection::Windows => &desired.windows,
        CredentialProjection::Vm => &desired.vm,
    }
}

fn projection_observation(
    observed: &CredentialPlaneObservation,
    projection: CredentialProjection,
) -> &CredentialProjectionObservation {
    match projection {
        CredentialProjection::Windows => &observed.windows,
        CredentialProjection::Vm => &observed.vm,
    }
}

fn render_worker_source(projection: CredentialProjection) -> Result<String, String> {
    let projection_kind = match projection {
        CredentialProjection::Windows => CredentialProjectionKind::Windows,
        CredentialProjection::Vm => CredentialProjectionKind::Vm,
    };
    let probe = CredentialIsolationProbe {
        schema_version: 1,
        generation: CREDENTIAL_ISOLATION_GENERATION,
        projection: projection_kind as i32,
        dummy_non_secret: true,
    };
    let bytes = probe.encode_to_vec();
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if WORKER_TEMPLATE.matches("__PROBE_HEX__").count() != 1 {
        return Err("credential Worker template must contain exactly one __PROBE_HEX__ placeholder".to_owned());
    }
    Ok(WORKER_TEMPLATE.replace("__PROBE_HEX__", &hex))
}

fn probe_url(worker_name: &str, workers_subdomain: &str) -> String {
    format!(
        "https://{worker_name}.{workers_subdomain}.workers.dev/v1/credentials?generation={CREDENTIAL_ISOLATION_GENERATION}"
    )
}

fn assert_allowed_probe(
    label: &str,
    response: &cloudflare::CloudflareAccessProbeResponse,
    expected_projection: CredentialProjectionKind,
) -> Result<(), String> {
    if response.status != 200 {
        return Err(format!("{label} expected HTTP 200, got {}", response.status));
    }
    if !response
        .content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("application/x-protobuf"))
    {
        return Err(format!("{label} did not return application/x-protobuf"));
    }
    let probe = CredentialIsolationProbe::decode(response.body.as_slice())
        .map_err(|err| format!("{label} returned invalid protobuf: {err}"))?;
    if probe.encode_to_vec() != response.body {
        return Err(format!("{label} returned non-canonical protobuf bytes"));
    }
    if probe.schema_version != 1
        || probe.generation != CREDENTIAL_ISOLATION_GENERATION
        || probe.projection != expected_projection as i32
        || !probe.dummy_non_secret
    {
        return Err(format!("{label} returned the wrong typed dummy projection"));
    }
    Ok(())
}

fn assert_denied_probe(
    label: &str,
    response: &cloudflare::CloudflareAccessProbeResponse,
) -> Result<(), String> {
    if (200..300).contains(&response.status) {
        return Err(format!(
            "{label} must be denied before Worker execution, got HTTP {}",
            response.status
        ));
    }
    Ok(())
}

fn validate_rotated_token(
    token: &CloudflareAccessServiceTokenSecret,
    expected_id: &str,
    expected_name: &str,
) -> Result<(), String> {
    if token.id != expected_id
        || token.name != expected_name
        || !token.enabled
        || token.client_id.is_empty()
        || token.client_secret.is_empty()
    {
        return Err(format!(
            "rotated Cloudflare Access service token did not preserve exact identity {expected_name}"
        ));
    }
    Ok(())
}

fn required<'a>(label: &str, value: Option<&'a str>) -> Result<&'a str, String> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{label} is required"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_template_has_no_protobuf_field_encoding() {
        assert_eq!(WORKER_TEMPLATE.matches("__PROBE_HEX__").count(), 1);
        assert!(!WORKER_TEMPLATE.contains("0x08"));
        assert!(!WORKER_TEMPLATE.contains("EDGE_PROJECTION"));
    }

    #[test]
    fn worker_source_is_projection_specific_but_schema_owned_by_rust() {
        let windows = render_worker_source(CredentialProjection::Windows).unwrap();
        let vm = render_worker_source(CredentialProjection::Vm).unwrap();
        assert_ne!(windows, vm);
        assert!(!windows.contains("__PROBE_HEX__"));
        assert!(!vm.contains("__PROBE_HEX__"));
    }
}
