use crate::application_lifecycle_service::{
    ApplicationAuthority, ApplicationObservationView, DesiredMutationMode,
    authorize_application_plan, authorize_application_rollback, execute_desired, execute_rollback,
    observe_application, prepare_application_bundle, rollback_plan_remote, verify_desired,
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
use edge_controller_core::vultr_lifecycle::PlanClass;
use edge_provider_vultr::get_instance_typed;
use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) async fn run(args: Vec<String>) -> Result<(), String> {
    let operation = args.first().map(String::as_str).ok_or_else(usage)?;
    match operation {
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_mutation(&args[1..], DesiredMutationMode::Apply).await,
        "verify" => run_verify(&args[1..]).await,
        "upgrade" => run_mutation(&args[1..], DesiredMutationMode::Upgrade).await,
        "rollback-plan" => run_rollback_plan(&args[1..]).await,
        "rollback-apply" => run_rollback_apply(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    let (spec_path, manifest_path, artifact_path) = desired_args(args, "plan")?;
    let desired = load_application_desired(&spec_path)?;
    let artifact = load_artifact_manifest(&manifest_path)?;
    verify_exact_agent_artifact(&artifact, &artifact_path)?;
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

async fn run_mutation(args: &[String], mode: DesiredMutationMode) -> Result<(), String> {
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
    verify_exact_agent_artifact(&artifact, &artifact_path)?;
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

async fn run_verify(args: &[String]) -> Result<(), String> {
    let (spec_path, manifest_path, artifact_path) = desired_args(args, "verify")?;
    let desired = load_application_desired(&spec_path)?;
    let artifact = load_artifact_manifest(&manifest_path)?;
    verify_exact_agent_artifact(&artifact, &artifact_path)?;
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

pub(crate) async fn resolve_application_authority_from_spec(
    path: &Path,
) -> Result<ApplicationAuthority, String> {
    let desired = load_application_desired(path)?;
    resolve_application_authority(&desired).await
}

fn load_application_desired(path: &Path) -> Result<DesiredApplicationState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read application spec {}: {err}", path.display()))?;
    DesiredApplicationState::parse_json(&raw)
        .map_err(|err| format!("failed to parse application spec {}: {err}", path.display()))
}

fn load_artifact_manifest(path: &Path) -> Result<AgentArtifactManifest, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read artifact manifest {}: {err}", path.display()))?;
    AgentArtifactManifest::parse_json(&raw).map_err(|err| {
        format!(
            "failed to parse artifact manifest {}: {err}",
            path.display()
        )
    })
}

async fn resolve_application_authority(
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
        "  edge-orchestrator application-lifecycle plan <spec-path> <artifact-manifest-path> <edge-agent-artifact-path>",
        "  edge-orchestrator application-lifecycle apply <spec-path> <artifact-manifest-path> <edge-agent-artifact-path> <authorized-plan-sha256>",
        "  edge-orchestrator application-lifecycle verify <spec-path> <artifact-manifest-path> <edge-agent-artifact-path>",
        "  edge-orchestrator application-lifecycle upgrade <spec-path> <artifact-manifest-path> <edge-agent-artifact-path> <authorized-plan-sha256>",
        "  edge-orchestrator application-lifecycle rollback-plan <spec-path>",
        "  edge-orchestrator application-lifecycle rollback-apply <spec-path> <rollback-digest> <authorized-plan-sha256>",
    ]
    .join("\n")
}
