use crate::application_lifecycle_service::{
    ApplicationAuthority, ApplicationObservationView, DesiredMutationMode,
    authorize_application_plan, authorize_application_recovery, authorize_application_rollback,
    execute_desired, execute_recovery, execute_rollback, observe_application,
    prepare_application_bundle, recovery_plan_remote, rollback_plan_remote, verify_desired,
    verify_exact_agent_artifact,
};
use crate::vultr_host_bootstrap::{strict_ssh_accept, verify_operator_key_matches};
use crate::vultr_lifecycle_command::{
    host_substrate_versions_from_env, lifecycle_provider_from_env, load_desired_state,
    load_firewall_profiles, operator_private_key_path_from_env, read_canonical_ssh_public_key,
    support_provider_from_env, verified_firewall_bindings,
};
use crate::vultr_lifecycle_service::plan_desired_state_with_firewall_profiles;
use edge_controller_core::application_lifecycle::{
    AgentArtifactManifest, ApplicationPlanClass, DesiredApplicationState, plan_application,
};
use edge_controller_core::lifecycle::{PlanDisposition, authorize_plan};
use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_controller_core::vultr_lifecycle::PlanClass;
use edge_orchestrator::OrchestrationContext;
use edge_provider_vultr::get_instance_typed;
use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) async fn run(args: Vec<String>, context: &OrchestrationContext) -> Result<(), String> {
    context.application_release_authority()?;
    let operation = args.first().map(String::as_str).ok_or_else(usage)?;
    match operation {
        "materialize" => run_materialize(&args[1..], context),
        "plan" => run_plan(&args[1..], context).await,
        "apply" => run_mutation(&args[1..], DesiredMutationMode::Apply, context).await,
        "verify" => run_verify(&args[1..], context).await,
        "upgrade" => run_mutation(&args[1..], DesiredMutationMode::Upgrade, context).await,
        "recover-plan" => run_recovery_plan(&args[1..]).await,
        "recover-apply" => run_recovery_apply(&args[1..]).await,
        "rollback-plan" => run_rollback_plan(&args[1..]).await,
        "rollback-apply" => run_rollback_apply(&args[1..]).await,
        _ => Err(usage()),
    }
}

fn run_materialize(args: &[String], context: &OrchestrationContext) -> Result<(), String> {
    let (spec_path, manifest_path, artifact_path) = desired_args(args, "materialize")?;
    let desired = load_application_desired(&spec_path)?;
    let bundle_root = Path::new(".").join(&desired.bundle_root);
    context.materialize_application_inputs(&bundle_root, &manifest_path, &artifact_path)?;
    let artifact = load_artifact_manifest(&manifest_path)?;
    verify_release_bound_application_inputs(context, &desired, &artifact, &artifact_path)
}

async fn run_plan(args: &[String], context: &OrchestrationContext) -> Result<(), String> {
    let (spec_path, manifest_path, artifact_path) = desired_args(args, "plan")?;
    let desired = load_application_desired(&spec_path)?;
    let artifact = load_artifact_manifest(&manifest_path)?;
    verify_release_bound_application_inputs(context, &desired, &artifact, &artifact_path)?;
    let authority = resolve_application_authority(&desired).await?;
    let prepared = prepare_application_bundle(Path::new("."), &desired, &artifact)?;
    let observation = observe_application(&authority, &desired).await?;
    let plan = plan_application(
        &desired,
        &artifact,
        &prepared.release.bundle_digest,
        &observation,
    )
    .map_err(|err| err.to_string())?;
    let authorized = authorize_application_plan(
        &desired,
        &artifact,
        &prepared.release.bundle_digest,
        &observation,
        plan.clone(),
    )?;

    print_json(json!({
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "observation": ApplicationObservationView::from(&observation),
        "mutations_performed": 0
    }))
}

async fn run_mutation(
    args: &[String],
    mode: DesiredMutationMode,
    context: &OrchestrationContext,
) -> Result<(), String> {
    let operation = match mode {
        DesiredMutationMode::Apply => "apply",
        DesiredMutationMode::Upgrade => "upgrade",
    };
    if args.len() != 4 {
        return Err(format!(
            "usage: edge-orchestrator application-lifecycle {operation} <spec-path> <artifact-manifest-path> <edge-agent-artifact-path> <authorized-plan-sha256>"
        ));
    }
    let spec_path = PathBuf::from(&args[0]);
    let manifest_path = PathBuf::from(&args[1]);
    let artifact_path = PathBuf::from(&args[2]);
    let authorized_plan_digest = &args[3];
    let desired = load_application_desired(&spec_path)?;
    let artifact = load_artifact_manifest(&manifest_path)?;
    verify_release_bound_application_inputs(context, &desired, &artifact, &artifact_path)?;
    let prepared = prepare_application_bundle(Path::new("."), &desired, &artifact)?;
    let authority = resolve_application_authority(&desired).await?;
    let report = execute_desired(
        &authority,
        &desired,
        &artifact,
        &artifact_path,
        &prepared,
        authorized_plan_digest,
        mode,
    )
    .await?;
    print_json(serde_json::to_value(report).map_err(|err| err.to_string())?)
}

async fn run_verify(args: &[String], context: &OrchestrationContext) -> Result<(), String> {
    let (spec_path, manifest_path, artifact_path) = desired_args(args, "verify")?;
    let desired = load_application_desired(&spec_path)?;
    let artifact = load_artifact_manifest(&manifest_path)?;
    verify_release_bound_application_inputs(context, &desired, &artifact, &artifact_path)?;
    let prepared = prepare_application_bundle(Path::new("."), &desired, &artifact)?;
    let authority = resolve_application_authority(&desired).await?;
    let (plan, observation) = verify_desired(&authority, &desired, &artifact, &prepared).await?;
    let healthy = plan.class == ApplicationPlanClass::Noop;
    let disposition = if healthy {
        PlanDisposition::Noop
    } else if plan.class == ApplicationPlanClass::Blocked {
        PlanDisposition::Blocked
    } else {
        PlanDisposition::Mutate
    };
    let desired_material = json!({
        "desired": &desired,
        "artifact": &artifact,
        "bundle_digest": &prepared.release.bundle_digest,
    });
    let authorized = authorize_plan(
        "application",
        &desired_material,
        &observation,
        plan.clone(),
        disposition,
    )
    .map_err(|err| err.to_string())?;
    print_json(json!({
        "status": if healthy { "PASS" } else { "FAIL" },
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "observation": observation,
        "mutations_performed": 0
    }))?;
    if healthy {
        Ok(())
    } else {
        Err("application verify did not observe exact healthy desired release".to_owned())
    }
}

async fn run_recovery_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err(
            "usage: edge-orchestrator application-lifecycle recover-plan <spec-path>".to_owned(),
        );
    }
    let desired = load_application_desired(Path::new(&args[0]))?;
    let authority = resolve_application_authority(&desired).await?;
    let (observation, plan) = recovery_plan_remote(&authority, &desired).await?;
    let authorized = authorize_application_recovery(&desired, &observation, plan.clone())?;
    print_json(json!({
        "recovery": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "observation": observation,
        "mutations_performed": 0
    }))
}

async fn run_recovery_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator application-lifecycle recover-apply <spec-path> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    validate_digest(&args[1])?;
    let desired = load_application_desired(Path::new(&args[0]))?;
    let authority = resolve_application_authority(&desired).await?;
    let report = execute_recovery(&authority, &desired, &args[1]).await?;
    print_json(json!({
        "status": "RECOVERED",
        "report": report
    }))
}

async fn run_rollback_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err(
            "usage: edge-orchestrator application-lifecycle rollback-plan <spec-path>".to_owned(),
        );
    }
    let desired = load_application_desired(Path::new(&args[0]))?;
    let authority = resolve_application_authority(&desired).await?;
    let (observation, plan) = rollback_plan_remote(&authority, &desired).await?;
    let authorized = authorize_application_rollback(&desired, &observation, plan.clone())?;
    print_json(json!({
        "rollback": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0
    }))
}

async fn run_rollback_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator application-lifecycle rollback-apply <spec-path> <rollback-digest> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    validate_digest(&args[1])?;
    validate_digest(&args[2])?;
    let desired = load_application_desired(Path::new(&args[0]))?;
    let authority = resolve_application_authority(&desired).await?;
    let observation = execute_rollback(&authority, &desired, &args[1], &args[2]).await?;
    print_json(json!({
        "status": "ROLLED_BACK",
        "observation": observation
    }))
}

fn desired_args(args: &[String], operation: &str) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    if args.len() != 3 {
        return Err(format!(
            "usage: edge-orchestrator application-lifecycle {operation} <spec-path> <artifact-manifest-path> <edge-agent-artifact-path>"
        ));
    }
    Ok((
        PathBuf::from(&args[0]),
        PathBuf::from(&args[1]),
        PathBuf::from(&args[2]),
    ))
}

pub(crate) async fn production_converge_desired(
    context: &OrchestrationContext,
    desired: &DesiredApplicationState,
    artifact_path: &Path,
) -> Result<(String, String), String> {
    let bundle_root = Path::new(".").join(&desired.bundle_root);
    context.materialize_application_image_environment(&bundle_root, artifact_path)?;
    let artifact = context.expected_application_artifact()?;
    verify_release_bound_application_inputs(context, desired, &artifact, artifact_path)?;
    let prepared = prepare_application_bundle(Path::new("."), desired, &artifact)?;
    let authority = resolve_application_authority(desired).await?;
    let observation = observe_application(&authority, desired).await?;
    let plan = plan_application(
        desired,
        &artifact,
        &prepared.release.bundle_digest,
        &observation,
    )
    .map_err(|err| err.to_string())?;

    match plan.class {
        ApplicationPlanClass::Noop => {
            return Ok((
                plan.desired_release.release_id,
                plan.desired_release.bundle_digest,
            ));
        }
        ApplicationPlanClass::Blocked => {
            return Err(format!(
                "production application convergence is blocked: {}",
                plan.reasons.join("; ")
            ));
        }
        ApplicationPlanClass::Apply | ApplicationPlanClass::Upgrade => {}
    }

    let mode = match plan.class {
        ApplicationPlanClass::Apply => DesiredMutationMode::Apply,
        ApplicationPlanClass::Upgrade => DesiredMutationMode::Upgrade,
        ApplicationPlanClass::Noop | ApplicationPlanClass::Blocked => unreachable!(),
    };
    let authorized = authorize_application_plan(
        desired,
        &artifact,
        &prepared.release.bundle_digest,
        &observation,
        plan,
    )?;
    let report = execute_desired(
        &authority,
        desired,
        &artifact,
        artifact_path,
        &prepared,
        &authorized.authority.authority_digest,
        mode,
    )
    .await?;
    if report.final_plan.class != ApplicationPlanClass::Noop {
        return Err(format!(
            "production application convergence did not reach NOOP: {:?}: {}",
            report.final_plan.class,
            report.final_plan.reasons.join("; ")
        ));
    }
    Ok((
        report.final_plan.desired_release.release_id,
        report.final_plan.desired_release.bundle_digest,
    ))
}

pub(crate) async fn acceptance_apply_desired(
    context: &OrchestrationContext,
    desired: &DesiredApplicationState,
    manifest_path: &Path,
    artifact_path: &Path,
    mode: DesiredMutationMode,
    expected_initial_class: ApplicationPlanClass,
) -> Result<(String, String), String> {
    let artifact = load_artifact_manifest(manifest_path)?;
    verify_release_bound_application_inputs(context, desired, &artifact, artifact_path)?;
    let prepared = prepare_application_bundle(Path::new("."), desired, &artifact)?;
    let authority = resolve_application_authority(desired).await?;
    let observation = observe_application(&authority, desired).await?;
    let plan = plan_application(
        desired,
        &artifact,
        &prepared.release.bundle_digest,
        &observation,
    )
    .map_err(|err| err.to_string())?;
    if plan.class != expected_initial_class {
        return Err(format!(
            "acceptance application expected initial {:?}, got {:?}: {}",
            expected_initial_class,
            plan.class,
            plan.reasons.join("; ")
        ));
    }
    let authorized = authorize_application_plan(
        desired,
        &artifact,
        &prepared.release.bundle_digest,
        &observation,
        plan,
    )?;
    let report = execute_desired(
        &authority,
        desired,
        &artifact,
        artifact_path,
        &prepared,
        &authorized.authority.authority_digest,
        mode,
    )
    .await?;
    if report.final_plan.class != ApplicationPlanClass::Noop {
        return Err(format!(
            "acceptance application mutation did not converge to NOOP: {:?}: {}",
            report.final_plan.class,
            report.final_plan.reasons.join("; ")
        ));
    }
    Ok((
        report.final_plan.desired_release.release_id,
        report.final_plan.desired_release.bundle_digest,
    ))
}

pub(crate) async fn acceptance_verify_desired(
    context: &OrchestrationContext,
    desired: &DesiredApplicationState,
    manifest_path: &Path,
    artifact_path: &Path,
) -> Result<(), String> {
    let artifact = load_artifact_manifest(manifest_path)?;
    verify_release_bound_application_inputs(context, desired, &artifact, artifact_path)?;
    let prepared = prepare_application_bundle(Path::new("."), desired, &artifact)?;
    let authority = resolve_application_authority(desired).await?;
    let (plan, _observation) = verify_desired(&authority, desired, &artifact, &prepared).await?;
    if plan.class != ApplicationPlanClass::Noop {
        return Err(format!(
            "acceptance application verify expected NOOP, got {:?}: {}",
            plan.class,
            plan.reasons.join("; ")
        ));
    }
    Ok(())
}

pub(crate) async fn acceptance_rollback(
    context: &OrchestrationContext,
    desired: &DesiredApplicationState,
    expected_current_release: &str,
    expected_previous_release: &str,
    manifest_path: &Path,
    artifact_path: &Path,
) -> Result<(), String> {
    let authority = resolve_application_authority(desired).await?;
    let (observation, rollback) = rollback_plan_remote(&authority, desired).await?;
    if rollback.current_release.release_id != expected_current_release
        || rollback.previous_release.release_id != expected_previous_release
    {
        return Err(format!(
            "acceptance rollback authority mismatch: current={} previous={}",
            rollback.current_release.release_id, rollback.previous_release.release_id
        ));
    }
    let authorized = authorize_application_rollback(desired, &observation, rollback.clone())?;
    execute_rollback(
        &authority,
        desired,
        &rollback.rollback_digest,
        &authorized.authority.authority_digest,
    )
    .await?;
    acceptance_verify_desired(context, desired, manifest_path, artifact_path).await
}

fn verify_release_bound_application_inputs(
    context: &OrchestrationContext,
    desired: &DesiredApplicationState,
    artifact: &AgentArtifactManifest,
    artifact_path: &Path,
) -> Result<(), String> {
    context.validate_application_artifact(artifact, artifact_path)?;
    let bundle_root = Path::new(".").join(&desired.bundle_root);
    context.validate_application_image_environment(&bundle_root)?;
    verify_exact_agent_artifact(artifact, artifact_path)
}

pub(crate) async fn resolve_application_authority_from_spec(
    path: &Path,
) -> Result<ApplicationAuthority, String> {
    let desired = load_application_desired(path)?;
    resolve_application_authority(&desired).await
}

pub(crate) fn load_application_desired(path: &Path) -> Result<DesiredApplicationState, String> {
    if path == Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH) {
        return ProductionComposition::canonical()
            .map(|composition| composition.application)
            .map_err(|err| err.to_string());
    }

    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read application spec {}: {err}", path.display()))?;
    DesiredApplicationState::parse_json(&raw)
        .map_err(|err| format!("failed to parse application spec {}: {err}", path.display()))
}

pub(crate) fn load_artifact_manifest(path: &Path) -> Result<AgentArtifactManifest, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read artifact manifest {}: {err}", path.display()))?;
    AgentArtifactManifest::parse_json(&raw).map_err(|err| {
        format!(
            "failed to parse artifact manifest {}: {err}",
            path.display()
        )
    })
}

pub(crate) async fn resolve_application_authority(
    desired: &DesiredApplicationState,
) -> Result<ApplicationAuthority, String> {
    let vultr_desired = load_desired_state(Path::new(&desired.vultr_spec_path))?;
    if vultr_desired.environment != desired.environment {
        return Err(format!(
            "application environment {} does not match Vultr desired-state environment {}",
            desired.environment, vultr_desired.environment
        ));
    }
    let machine = vultr_desired
        .machines
        .iter()
        .find(|machine| machine.id == desired.machine_id)
        .ok_or_else(|| {
            format!(
                "application machine {} is not present in {}",
                desired.machine_id, desired.vultr_spec_path
            )
        })?;
    if !machine
        .application_profiles
        .iter()
        .any(|profile| profile == &desired.application_profile)
    {
        return Err(format!(
            "machine {} does not declare required application profile {}",
            desired.machine_id, desired.application_profile
        ));
    }

    let profiles = load_firewall_profiles(&vultr_desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &vultr_desired, profiles.as_ref())
            .await?;
    let lifecycle = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &vultr_desired,
        Some(&desired.machine_id),
        &verified_firewalls,
    )
    .await?;
    let machine_plan = lifecycle
        .plans
        .first()
        .ok_or_else(|| "Vultr lifecycle returned no machine plan".to_owned())?;
    if machine_plan.class != PlanClass::Noop {
        return Err(format!(
            "application lifecycle requires an accepted NOOP Vultr machine; observed {:?}: {}",
            machine_plan.class,
            machine_plan.reasons.join("; ")
        ));
    }
    let provider_id = machine_plan
        .provider_id
        .as_deref()
        .ok_or_else(|| "NOOP Vultr machine plan is missing provider id".to_owned())?;

    let api_key = env::var("VULTR_API_KEY").map_err(|_| "VULTR_API_KEY is required".to_owned())?;
    let instance = get_instance_typed(&api_key, provider_id)
        .await
        .map_err(|err| err.to_string())?;
    if instance.status != "active"
        || instance.power_status != "running"
        || instance.server_status != "ok"
        || instance.main_ip.trim().is_empty()
    {
        return Err(format!(
            "application target is not provider-ready: status={} power_status={} server_status={} main_ip_present={}",
            instance.status,
            instance.power_status,
            instance.server_status,
            !instance.main_ip.trim().is_empty()
        ));
    }

    let operator_private_key_path = operator_private_key_path_from_env()?;
    let canonical_operator_public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_operator_public_key)?;
    let substrate = host_substrate_versions_from_env()?;
    strict_ssh_accept(
        &instance.main_ip,
        &desired.machine_id,
        &operator_private_key_path,
        &canonical_operator_public_key,
        &substrate,
        15,
        Duration::from_secs(2),
    )
    .await?;

    Ok(ApplicationAuthority {
        target_ip: instance.main_ip,
        logical_hostname: desired.machine_id.clone(),
        operator_private_key_path,
        canonical_operator_public_key,
    })
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(
            "rollback digest must be exactly 64 lowercase hexadecimal characters".to_owned(),
        );
    }
    Ok(())
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize application lifecycle result: {err}"))?;
    println!("{rendered}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-orchestrator application-lifecycle materialize <spec-path> <artifact-manifest-path> <edge-agent-artifact-path>",
        "  edge-orchestrator application-lifecycle plan <spec-path> <artifact-manifest-path> <edge-agent-artifact-path>",
        "  edge-orchestrator application-lifecycle apply <spec-path> <artifact-manifest-path> <edge-agent-artifact-path> <authorized-plan-sha256>",
        "  edge-orchestrator application-lifecycle verify <spec-path> <artifact-manifest-path> <edge-agent-artifact-path>",
        "  edge-orchestrator application-lifecycle upgrade <spec-path> <artifact-manifest-path> <edge-agent-artifact-path> <authorized-plan-sha256>",
        "  edge-orchestrator application-lifecycle recover-plan <spec-path>",
        "  edge-orchestrator application-lifecycle recover-apply <spec-path> <authorized-plan-sha256>",
        "  edge-orchestrator application-lifecycle rollback-plan <spec-path>",
        "  edge-orchestrator application-lifecycle rollback-apply <spec-path> <rollback-digest> <authorized-plan-sha256>",
    ]
    .join("\n")
}
