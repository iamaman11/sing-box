use crate::application_lifecycle_service::{
    ApplicationAuthority, DesiredMutationMode, authorize_application_plan,
    authorize_application_rollback, candidate_application_image_environment, exact_file_sha256,
    execute_desired, execute_rollback, observe_application, prepare_application_bundle,
    prepare_application_bundle_with_image_environment, rollback_plan_remote, verify_desired,
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
use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_controller_core::vultr_lifecycle::PlanClass;
use edge_orchestrator::OrchestrationContext;
use edge_provider_vultr::get_instance_typed;
use prost::Message;
use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration;

pub(crate) fn build_candidate_application_bundle(
    spec_path: &Path,
    runtime_source_revision: &str,
    edge_agent_artifact_path: &Path,
    edge_gateway_image: &str,
    edge_warp_egress_image: &str,
    mesh_image: &str,
    output_protobuf_path: &Path,
) -> Result<(), String> {
    let desired = load_application_desired(spec_path)?;
    let artifact = AgentArtifactManifest {
        schema: 1,
        source_revision: runtime_source_revision.to_owned(),
        sha256: exact_file_sha256(edge_agent_artifact_path)?,
    };
    artifact.validate().map_err(|err| err.to_string())?;
    verify_exact_agent_artifact(&artifact, edge_agent_artifact_path)?;
    let image_environment = candidate_application_image_environment(
        edge_gateway_image,
        edge_warp_egress_image,
        mesh_image,
    )?;
    let prepared = prepare_application_bundle_with_image_environment(
        Path::new("."),
        &desired,
        &artifact,
        &image_environment,
    )?;
    let encoded = prepared.request.encode_to_vec();
    fs::write(output_protobuf_path, &encoded).map_err(|err| {
        format!(
            "failed to write candidate application bundle {}: {err}",
            output_protobuf_path.display()
        )
    })?;
    println!(
        "application_bundle_id={}",
        prepared.request.bundle_id.as_deref().unwrap_or("")
    );
    println!(
        "application_bundle_digest={}",
        prepared.request.bundle_digest.as_deref().unwrap_or("")
    );
    println!(
        "application_bundle_sha256={}",
        exact_file_sha256(output_protobuf_path)?
    );
    println!("application_bundle_bytes={}", encoded.len());
    Ok(())
}

pub(crate) fn materialize(
    context: &OrchestrationContext,
    spec_path: &Path,
    manifest_path: &Path,
    artifact_path: &Path,
) -> Result<(), String> {
    context.application_release_authority()?;
    let desired = load_application_desired(spec_path)?;
    let bundle_root = Path::new(".").join(&desired.bundle_root);
    context.materialize_application_inputs(&bundle_root, manifest_path, artifact_path)?;
    let artifact = load_artifact_manifest(manifest_path)?;
    verify_release_bound_application_inputs(context, &desired, &artifact, artifact_path)
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

pub(crate) async fn production_verify_desired(
    context: &OrchestrationContext,
    desired: &DesiredApplicationState,
    artifact_path: &Path,
) -> Result<(), String> {
    let bundle_root = Path::new(".").join(&desired.bundle_root);
    context.materialize_application_image_environment(&bundle_root, artifact_path)?;
    let artifact = context.expected_application_artifact()?;
    verify_release_bound_application_inputs(context, desired, &artifact, artifact_path)?;
    let prepared = prepare_application_bundle(Path::new("."), desired, &artifact)?;
    let authority = resolve_application_authority(desired).await?;
    let (plan, _observation) = verify_desired(&authority, desired, &artifact, &prepared).await?;
    if plan.class != ApplicationPlanClass::Noop {
        return Err(format!(
            "production application verify expected NOOP, got {:?}: {}",
            plan.class,
            plan.reasons.join("; ")
        ));
    }
    Ok(())
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
