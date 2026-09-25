use crate::vultr_host_bootstrap::{
    HostSubstrateVersions, InstanceAction, OperationalProvider, VultrOperationalApiProvider,
    apply_instance_action, prepare_strict_bootstrap,
    prove_restricted_control_negative_capabilities, start_strict_agent_tunnel, strict_scp_upload,
    strict_ssh_accept, strict_ssh_capture, strict_ssh_run, strict_ssh_run_stdin,
    verify_operator_key_matches, wait_provider_ready,
};
use crate::vultr_host_substrate_service::{
    HostSubstrateExecutionPolicy, apply_host_substrate_once, build_host_substrate_authority,
};
use crate::vultr_lifecycle_service::{
    ApplyAction, ApplyReport, CreatePrerequisites, LifecycleExecutionPolicy, LifecycleProvider,
    VultrApiProvider, apply_machine_with_firewall_profiles, authorize_vultr_destroy,
    authorize_vultr_machine, destroy_machine_with_firewall_profiles,
    inventory_desired_state_with_firewall_profiles, plan_desired_state_with_firewall_profiles,
};
use crate::vultr_support_resources::{
    FirewallProfileSet, ResolvedFirewallProfile, SupportResourceProvider, VultrSupportApiProvider,
    cleanup_environment_support_resources, controller_access_cleanup_projection_matches,
    controller_ipv4_access_specs, ensure_firewall_profile, ensure_persistent_firewall_profile,
    firewall_group_description, firewall_rule_spec, observe_verified_firewall_bindings,
    public_key_material, release_controller_ipv4_access, resolve_managed_ssh_key,
    validate_machine_catalog,
};
use edge_controller_core::host_substrate_lifecycle::HostSubstrateAction;
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_controller_core::orchestration::SupportAccessLeaseState;
use edge_controller_core::vultr_lifecycle::{
    DesiredState, MANAGED_BY_IDENTITY, MachineSpec, ObservedMachine, PlanClass,
    decode_provider_tags, destroy_plan,
};
use edge_orchestrator::OrchestrationContext;
use edge_provider_vultr::{VultrFirewallRule, VultrInstance};
use edge_shared_types::Empty;
use edge_shared_types::agent_service_client::AgentServiceClient;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tonic::Request;

const DEFAULT_CLOUD_INIT_PATH: &str = "win/vultr-waw/cloud-init.yaml";
const CANONICAL_SSH_PUBLIC_KEY_PATH: &str = "infra/vultr/singbox-ops.pub";
const FIREWALL_PROFILES_PATH: &str = "infra/vultr/firewall-profiles.json";

pub async fn run(args: Vec<String>, context: &OrchestrationContext) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or_else(usage)?;
    match command {
        "doctor" => run_doctor(&args[1..]).await,
        "inventory" => run_inventory(&args[1..]).await,
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "substrate-plan" => run_substrate_plan(&args[1..]).await,
        "substrate-apply" => run_substrate_apply(&args[1..]).await,
        "substrate-verify" => run_substrate_verify(&args[1..]).await,
        "transport-proof" => run_transport_proof(&args[1..], context).await,
        "runner-bootstrap" => run_runner_bootstrap(&args[1..]).await,
        "acquire-access-plan" => run_acquire_access_plan(&args[1..]).await,
        "acquire-access" => run_acquire_access(&args[1..]).await,
        "lease-acquire" => run_lease_acquire(&args[1..]).await,
        "release-access-plan" => run_release_access_plan(&args[1..]).await,
        "release-access" => run_release_access(&args[1..]).await,
        "lease-release" => run_lease_release(&args[1..]).await,
        "action-plan" => run_action_plan(&args[1..]).await,
        "action" => run_action(&args[1..]).await,
        "destroy-plan" => run_destroy_plan(&args[1..]).await,
        "destroy-apply" => run_destroy_apply(&args[1..]).await,
        "cleanup-plan" => run_cleanup_plan(&args[1..]).await,
        "cleanup" => run_cleanup(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_doctor(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-orchestrator vultr-lifecycle doctor <spec-path>".to_owned());
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let profiles = load_firewall_profiles(&desired)?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;

    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    for machine in &desired.machines {
        validate_machine_catalog(&mut support_provider, machine).await?;
    }
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        None,
        &verified_firewalls,
    )
    .await?;

    print_json_value(serde_json::json!({
        "status": "PASS",
        "environment": desired.environment,
        "desired_state_digest": report.desired_state_digest,
        "machine_count": desired.machines.len(),
        "catalog_validation": "PASS",
        "operator_key_match": "PASS",
        "plans": report.plans,
        "orphaned_managed_provider_ids": report.orphaned_managed_provider_ids,
        "verified_firewall_bindings": verified_firewalls,
        "mutations_performed": 0,
    }))
}

async fn run_inventory(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-orchestrator vultr-lifecycle inventory <spec-path>".to_owned());
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let profiles = load_firewall_profiles(&desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let inventory = inventory_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        &verified_firewalls,
    )
    .await?;
    let inventory = serde_json::to_value(inventory)
        .map_err(|err| format!("failed to serialize lifecycle inventory: {err}"))?;
    print_json_value(serde_json::json!({
        "environment": desired.environment,
        "inventory": inventory,
        "verified_firewall_bindings": verified_firewalls,
    }))
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    if !(args.len() == 1 || args.len() == 2) {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle plan <spec-path> [machine-id]".to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let profiles = load_firewall_profiles(&desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        args.get(1).map(String::as_str),
        &verified_firewalls,
    )
    .await?;
    let authorized_plans = report
        .plans
        .iter()
        .cloned()
        .map(|plan| authorize_vultr_machine(&desired, &report.inventory, plan))
        .collect::<Result<Vec<_>, _>>()?;
    print_json_value(serde_json::json!({
        "environment": report.environment,
        "desired_state_digest": report.desired_state_digest,
        "plans": report.plans,
        "authorized_plans": authorized_plans,
        "orphaned_managed_provider_ids": report.orphaned_managed_provider_ids,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle apply <spec-path> <machine-id> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let value = apply_machine_value(Path::new(&args[0]), &args[1], Some(args[2].as_str())).await?;
    print_json_value(value)
}

async fn apply_machine_value(
    spec_path: &Path,
    machine_id: &str,
    expected_authority: Option<&str>,
) -> Result<serde_json::Value, String> {
    let desired = load_desired_state(spec_path)?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profiles = load_firewall_profiles(&desired)?;
    let substrate = host_substrate_versions_from_env()?;
    let policy = LifecycleExecutionPolicy::default();
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let mut verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;

    let initial = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    let initial_plan = initial
        .plans
        .first()
        .cloned()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    let initial_class = initial_plan.class;
    let authorized = authorize_vultr_machine(&desired, &initial.inventory, initial_plan)?;
    let authority_digest = expected_authority
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| authorized.authority.authority_digest.clone());
    verify_exact_authority(&authority_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    if matches!(
        initial_class,
        PlanClass::BlockedAmbiguous | PlanClass::BlockedDrift | PlanClass::ReplaceRequired
    ) {
        let plan = &initial.plans[0];
        return Err(format!(
            "machine {} is {:?}; apply refuses before support-resource mutation: {}",
            machine.id,
            plan.class,
            plan.reasons.join("; ")
        ));
    }

    let firewall = if matches!(initial_class, PlanClass::Create | PlanClass::UpdateInPlace) {
        if let Some(profile_name) = machine.provider.firewall_profile.as_deref() {
            let profile_set = profiles.as_ref().ok_or_else(|| {
                format!(
                    "machine {} references firewall profile {profile_name}, but no profile registry is loaded",
                    machine.id
                )
            })?;
            let profile = profile_set.profile(profile_name)?;
            let resolved = ensure_persistent_firewall_profile(
                &mut support_provider,
                &desired.environment,
                profile,
                &policy,
            )
            .await?;
            verified_firewalls.insert(resolved.id.clone(), resolved.profile_name.clone());
            Some(resolved)
        } else {
            None
        }
    } else {
        None
    };

    let after_support = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    let after_support_plan = after_support
        .plans
        .first()
        .cloned()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    let after_support_class = after_support_plan.class;

    if initial_class == PlanClass::UpdateInPlace && after_support_class != PlanClass::Noop {
        return Err(format!(
            "machine {} support-resource convergence did not reach NOOP: {:?}: {}",
            machine.id,
            after_support_class,
            after_support_plan.reasons.join("; ")
        ));
    }
    if initial_class != PlanClass::UpdateInPlace {
        let after_support_authorized = authorize_vultr_machine(
            &desired,
            &after_support.inventory,
            after_support_plan.clone(),
        )?;
        verify_exact_authority(&authority_digest, &after_support_authorized.authority)
            .map_err(|err| err.to_string())?;
    }

    let prerequisites = if after_support_class == PlanClass::Create {
        validate_machine_catalog(&mut support_provider, machine).await?;
        let ssh_key = resolve_managed_ssh_key(
            &mut support_provider,
            &desired.environment,
            &canonical_public_key,
            &policy,
        )
        .await?;
        let base_cloud_init = read_base_cloud_init(machine)?;
        let strict_bootstrap = prepare_strict_bootstrap(
            &base_cloud_init,
            &machine.id,
            &operator_private_key_path,
            &canonical_public_key,
            &substrate,
        )?;
        resolve_create_prerequisites(
            machine,
            &ssh_key.id,
            firewall.as_ref(),
            strict_bootstrap.cloud_init,
        )?
    } else {
        empty_create_prerequisites(machine)
    };

    let support_reconciled =
        initial_class == PlanClass::UpdateInPlace && after_support_class == PlanClass::Noop;
    let report = if support_reconciled {
        let provider_id = after_support_plan
            .provider_id
            .clone()
            .ok_or_else(|| "converged UPDATE_IN_PLACE plan is missing provider id".to_owned())?;
        ApplyReport {
            action: ApplyAction::Noop,
            machine_id: machine.id.clone(),
            provider_id,
            final_plan: after_support_plan,
        }
    } else {
        apply_machine_with_firewall_profiles(
            &mut lifecycle_provider,
            &desired,
            machine_id,
            &authority_digest,
            &prerequisites,
            &policy,
            &verified_firewalls,
        )
        .await?
    };

    let mut operational_provider = operational_provider_from_env()?;
    let ready = wait_provider_ready(
        &mut operational_provider,
        &report.provider_id,
        60,
        std::time::Duration::from_secs(5),
    )
    .await?;

    Ok(serde_json::json!({
        "action": report.action.as_str(),
        "machine_id": report.machine_id,
        "provider_id": report.provider_id,
        "main_ip": ready.main_ip,
        "final_plan": report.final_plan,
        "provider_ready": true,
        "host_substrate_required": true,
        "support_reconciled": support_reconciled,
    }))
}

pub(crate) async fn acceptance_create_machine(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let value = apply_machine_value(spec_path, machine_id, None).await?;
    if value.get("action").and_then(serde_json::Value::as_str) != Some("CREATED")
        || value
            .get("provider_ready")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || value
            .get("host_substrate_required")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(format!(
            "fresh acceptance VM create returned unexpected result: {value}"
        ));
    }
    Ok(())
}

pub(crate) async fn exact_existing_machine_observation(
    desired: &DesiredState,
    machine_id: &str,
) -> Result<ObservedMachine, String> {
    let profiles = load_firewall_profiles(desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    if report.plans.len() != 1 {
        return Err(format!(
            "expected exactly one lifecycle plan for {machine_id}, got {}",
            report.plans.len()
        ));
    }
    let plan = &report.plans[0];
    if plan.class != PlanClass::Noop {
        return Err(format!(
            "exact machine observation requires NOOP; machine {machine_id} plan is {:?}: {}",
            plan.class,
            plan.reasons.join("; ")
        ));
    }
    let provider_id = plan
        .provider_id
        .as_deref()
        .ok_or_else(|| format!("NOOP machine plan for {machine_id} is missing provider id"))?;
    let mut matches = report
        .inventory
        .resources
        .iter()
        .filter(|resource| resource.provider_id == provider_id);
    let observed = matches
        .next()
        .ok_or_else(|| format!("NOOP machine {machine_id} is absent from observed inventory"))?;
    if matches.next().is_some() {
        return Err(format!(
            "provider inventory is ambiguous for exact machine {machine_id} ({provider_id})"
        ));
    }
    if observed.ownership.logical_id.as_deref() != Some(machine_id) {
        return Err(format!(
            "observed provider resource {provider_id} is not owned by logical machine {machine_id}"
        ));
    }
    Ok(observed.clone())
}

async fn exact_existing_machine_provider_id(
    desired: &DesiredState,
    machine_id: &str,
) -> Result<String, String> {
    Ok(exact_existing_machine_observation(desired, machine_id)
        .await?
        .provider_id)
}

async fn run_substrate_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle substrate-plan <spec-path> <machine-id>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
    let provider_id = exact_existing_machine_provider_id(&desired, &args[1]).await?;
    let substrate = host_substrate_versions_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let mut provider = operational_provider_from_env()?;
    let (observation, authorized) = build_host_substrate_authority(
        &mut provider,
        &desired,
        machine,
        &provider_id,
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        HostSubstrateExecutionPolicy::default(),
    )
    .await?;

    print_json_value(serde_json::json!({
        "observation": observation,
        "plan": authorized.plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_substrate_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle substrate-apply <spec-path> <machine-id> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
    let provider_id = exact_existing_machine_provider_id(&desired, &args[1]).await?;
    let substrate = host_substrate_versions_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let mut provider = operational_provider_from_env()?;
    let report = apply_host_substrate_once(
        &mut provider,
        &desired,
        machine,
        &provider_id,
        &args[2],
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        HostSubstrateExecutionPolicy::default(),
    )
    .await?;

    print_json_value(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_substrate_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle substrate-verify <spec-path> <machine-id>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
    let provider_id = exact_existing_machine_provider_id(&desired, &args[1]).await?;
    let substrate = host_substrate_versions_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let mut provider = operational_provider_from_env()?;
    let (observation, authorized) = build_host_substrate_authority(
        &mut provider,
        &desired,
        machine,
        &provider_id,
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        HostSubstrateExecutionPolicy::default(),
    )
    .await?;
    if authorized.plan.action != HostSubstrateAction::Noop {
        return Err(format!(
            "host substrate verify is BLOCKED; next action is {:?}: {}",
            authorized.plan.action,
            authorized.plan.reasons.join("; ")
        ));
    }

    print_json_value(serde_json::json!({
        "status": "PASS",
        "observation": observation,
        "plan": authorized.plan,
        "plan_authority": authorized.authority,
    }))
}

async fn run_transport_proof(
    args: &[String],
    context: &OrchestrationContext,
) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle transport-proof <spec-path> <machine-id> <edge-agent-artifact-path>"
                .to_owned(),
        );
    }

    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine_id = &args[1];
    let artifact_path = Path::new(&args[2]);
    let expected_artifact = context.expected_application_artifact()?;
    context.validate_application_artifact(&expected_artifact, artifact_path)?;

    let observed = exact_existing_machine_observation(&desired, machine_id).await?;
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| format!("exact machine {machine_id} has no observed public IPv4"))?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;

    const REMOTE_T0_AGENT: &str = "/tmp/singbox-edge-agent-t0";
    const INSTALLED_AGENT: &str = "/opt/vultr-edge-stack/bin/edge-agent";
    strict_scp_upload(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        artifact_path,
        REMOTE_T0_AGENT,
    )?;
    strict_ssh_run(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        &format!(
            "sudo install -m 0755 {REMOTE_T0_AGENT} {INSTALLED_AGENT} && rm -f {REMOTE_T0_AGENT} && sudo systemctl restart edge-agent.service && sudo systemctl is-active --quiet edge-agent.service"
        ),
    )?;
    let remote_sha = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        &format!("sha256sum {INSTALLED_AGENT} | cut -d' ' -f1"),
    )?;
    if remote_sha != expected_artifact.sha256 {
        return Err(format!(
            "T0 installed edge-agent digest mismatch: expected {}, got {remote_sha}",
            expected_artifact.sha256
        ));
    }

    let (local_port, tunnel) = start_strict_agent_tunnel(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
    )?;
    let endpoint = format!("http://127.0.0.1:{local_port}");
    let mut last_error = None;
    let mut client = None;
    for _ in 0..20 {
        match AgentServiceClient::connect(endpoint.clone()).await {
            Ok(value) => {
                client = Some(value);
                break;
            }
            Err(err) => last_error = Some(err.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let mut client = client.ok_or_else(|| {
        format!(
            "T0 restricted edge-agent tunnel did not become reachable: {}",
            last_error.unwrap_or_else(|| "no connection attempt completed".to_owned())
        )
    })?;

    let version = client
        .get_version(Request::new(Empty {}))
        .await
        .map_err(|err| format!("T0 GetVersion through restricted transport failed: {err}"))?
        .into_inner();
    if version.name != "edge-agent" {
        return Err(format!(
            "T0 restricted transport reached unexpected agent name {}",
            version.name
        ));
    }
    let health = client
        .get_health(Request::new(Empty {}))
        .await
        .map_err(|err| format!("T0 GetHealth through restricted transport failed: {err}"))?
        .into_inner();
    let network = client
        .observe_ipv4_network(Request::new(Empty {}))
        .await
        .map_err(|err| format!("T0 ObserveIpv4Network through restricted transport failed: {err}"))?
        .into_inner();
    if network.links.is_empty() || network.addresses.is_empty() {
        return Err(
            "T0 restricted transport returned empty typed IPv4 link/address observation".to_owned(),
        );
    }

    let negative = prove_restricted_control_negative_capabilities(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
    )?;

    drop(client);
    drop(tunnel);

    print_json_value(serde_json::json!({
        "status": "PASS",
        "machine_id": machine_id,
        "transport_user": "edge-control",
        "transport_target": "127.0.0.1:50061",
        "agent": {
            "name": version.name,
            "version": version.version,
            "sha256": remote_sha,
            "get_version": "PASS",
            "get_health": "PASS",
            "health_value": health.healthy,
            "readiness_value": health.ready,
            "observe_ipv4_network": "PASS",
            "link_count": network.links.len(),
            "address_count": network.addresses.len(),
            "route_count": network.routes.len(),
        },
        "negative_capabilities": {
            "shell_rejected": negative.shell_rejected,
            "exec_rejected": negative.exec_rejected,
            "scp_rejected": negative.scp_rejected,
            "sftp_rejected": negative.sftp_rejected,
            "pty_rejected": negative.pty_rejected,
            "remote_forward_rejected": negative.remote_forward_rejected,
        },
        "legacy_bootstrap_used": true,
        "exclusive_transport_key_capability_proven": false,
        "note": "T0a proves the edge-control account path only; privileged bootstrap deletion and no-/32 proof belong to T0b",
    }))
}

async fn run_runner_bootstrap(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle runner-bootstrap <spec-path> <machine-id> <installer-path>"
                .to_owned(),
        );
    }

    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine_id = &args[1];
    if !desired
        .machines
        .iter()
        .any(|machine| machine.id == *machine_id)
    {
        return Err(format!(
            "machine {machine_id} is not present in desired state"
        ));
    }
    let installer_path = Path::new(&args[2]);
    if !installer_path.is_file() {
        return Err(format!(
            "root runner installer was not found: {}",
            installer_path.display()
        ));
    }

    let registration_token = env::var("EDGE_RUNNER_REGISTRATION_TOKEN")
        .map_err(|_| "EDGE_RUNNER_REGISTRATION_TOKEN is required".to_owned())?;
    validate_runner_registration_token(&registration_token)?;

    let observed = exact_existing_machine_observation(&desired, machine_id).await?;
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| format!("exact machine {machine_id} has no observed public IPv4"))?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;

    const REMOTE_INSTALLER: &str = "/tmp/singbox-root-runner-bootstrap";
    strict_scp_upload(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        installer_path,
        REMOTE_INSTALLER,
    )?;

    let remote_command = format!(
        "sudo bash {REMOTE_INSTALLER} {machine_id}; rc=$?; rm -f {REMOTE_INSTALLER}; exit $rc"
    );
    let token_stdin = format!("{registration_token}\n");
    strict_ssh_run_stdin(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        &remote_command,
        token_stdin.as_bytes(),
    )?;

    let root_uid = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "sudo -u github-runner sudo -n id -u",
    )?;
    if root_uid != "0" {
        return Err(format!(
            "self-hosted runner root authority verification failed: expected uid 0, got {root_uid}"
        ));
    }
    let listener = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "pgrep -u github-runner -f Runner.Listener >/dev/null && echo PASS",
    )?;
    if listener != "PASS" {
        return Err("self-hosted runner listener is not active".to_owned());
    }

    print_json_value(serde_json::json!({
        "status": "PASS",
        "machine_id": machine_id,
        "runner_name": format!("sing-box-{machine_id}"),
        "runner_user": "github-runner",
        "root_authority": true,
        "listener": "PASS",
        "registration_token_persisted": false,
    }))
}

fn validate_runner_registration_token(value: &str) -> Result<(), String> {
    if value.len() < 16
        || value.len() > 512
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err("runner registration token is malformed".to_owned());
    }
    Ok(())
}

async fn run_acquire_access_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle acquire-access-plan <spec-path> <machine-id>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let authorized = build_access_authority(
        &desired,
        &args[1],
        AccessAuthorityMode::Acquire,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    print_json_value(serde_json::json!({
        "plan": authorized.plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_acquire_access(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle acquire-access <spec-path> <machine-id> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let result = acquire_access_with_authority(&desired, &args[1], &args[2]).await?;
    print_json_value(result)
}

async fn acquire_access_with_authority(
    desired: &DesiredState,
    machine_id: &str,
    authorized_plan_digest: &str,
) -> Result<serde_json::Value, String> {
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profile_name = machine.provider.firewall_profile.as_deref().ok_or_else(|| {
        format!(
            "machine {} has no firewall_profile; acquire-access requires provider-owned SSH ingress",
            machine.id
        )
    })?;

    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let authorized = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Acquire,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    match authorized.disposition {
        PlanDisposition::Noop => {
            return Ok(serde_json::json!({
                "action": "NOOP",
                "machine_id": machine.id,
                "firewall_profile": profile_name,
                "next_plan": authorized.plan,
                "mutations_performed": 0,
            }));
        }
        PlanDisposition::Blocked => {
            return Err(format!(
                "acquire-access is blocked for machine {} by exact authorized plan",
                machine.id
            ));
        }
        PlanDisposition::Mutate => {}
    }

    let (_, resolved_profiles, _, _) = load_access_authority_profiles(desired)?;
    let profile = resolved_profiles.profile(profile_name)?;
    let policy = LifecycleExecutionPolicy::default();
    let resolved = ensure_firewall_profile(
        &mut support_provider,
        &desired.environment,
        profile,
        &policy,
    )
    .await?;

    let next = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Acquire,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if next.disposition != PlanDisposition::Noop {
        return Err(format!(
            "firewall access reconciliation completed but machine {} did not converge to NOOP",
            machine.id
        ));
    }

    Ok(serde_json::json!({
        "action": "ACQUIRED",
        "machine_id": machine.id,
        "firewall_group_id": resolved.id,
        "firewall_profile": resolved.profile_name,
        "next_plan": next.plan,
        "mutations_performed": 1,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpReadinessPolicy {
    max_attempts: usize,
    max_elapsed: Duration,
    connect_timeout: Duration,
    backoff: Duration,
}

impl TcpReadinessPolicy {
    const fn support_access() -> Self {
        Self {
            max_attempts: 90,
            max_elapsed: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(3),
            backoff: Duration::from_secs(2),
        }
    }

    fn validate(self) -> Result<Self, String> {
        if self.max_attempts == 0 {
            return Err("TCP readiness max_attempts must be greater than zero".to_owned());
        }
        if self.max_elapsed.is_zero() {
            return Err("TCP readiness max_elapsed must be greater than zero".to_owned());
        }
        if self.connect_timeout.is_zero() {
            return Err("TCP readiness connect_timeout must be greater than zero".to_owned());
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TcpReadinessState {
    Ready,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TcpReadinessFailureClass {
    ConnectTimeout,
    ConnectionRefused,
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct TcpReadinessObservation {
    attempts: usize,
    elapsed_ms: u64,
    final_state: TcpReadinessState,
    last_error_class: Option<TcpReadinessFailureClass>,
}

impl TcpReadinessObservation {
    fn evidence(&self) -> String {
        format!(
            "attempts={}; elapsed_ms={}; final_state={:?}; last_error_class={:?}",
            self.attempts, self.elapsed_ms, self.final_state, self.last_error_class
        )
    }
}

fn bounded_elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn classify_tcp_connect_error(error: &std::io::Error) -> TcpReadinessFailureClass {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => TcpReadinessFailureClass::ConnectionRefused,
        std::io::ErrorKind::TimedOut => TcpReadinessFailureClass::ConnectTimeout,
        _ => TcpReadinessFailureClass::Io,
    }
}

async fn observe_tcp_readiness_with_probe<F, Fut>(
    policy: TcpReadinessPolicy,
    mut probe: F,
) -> Result<TcpReadinessObservation, String>
where
    F: FnMut(Duration) -> Fut,
    Fut: std::future::Future<Output = Result<(), TcpReadinessFailureClass>>,
{
    let policy = policy.validate()?;
    let started = Instant::now();
    let mut attempts = 0usize;
    let mut last_error_class = None;

    while attempts < policy.max_attempts && started.elapsed() < policy.max_elapsed {
        let remaining = policy.max_elapsed.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }

        attempts += 1;
        let attempt_timeout = std::cmp::min(policy.connect_timeout, remaining);
        match probe(attempt_timeout).await {
            Ok(()) => {
                return Ok(TcpReadinessObservation {
                    attempts,
                    elapsed_ms: bounded_elapsed_ms(started),
                    final_state: TcpReadinessState::Ready,
                    last_error_class,
                });
            }
            Err(class) => last_error_class = Some(class),
        }

        if attempts >= policy.max_attempts || started.elapsed() >= policy.max_elapsed {
            break;
        }

        let remaining = policy.max_elapsed.saturating_sub(started.elapsed());
        let delay = std::cmp::min(policy.backoff, remaining);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    Ok(TcpReadinessObservation {
        attempts,
        elapsed_ms: bounded_elapsed_ms(started),
        final_state: TcpReadinessState::Timeout,
        last_error_class,
    })
}

async fn observe_tcp_readiness(
    target_ip: &str,
    policy: TcpReadinessPolicy,
) -> Result<TcpReadinessObservation, String> {
    let target_ip = target_ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|err| format!("observed machine public IPv4 {target_ip:?} is invalid: {err}"))?;
    let target = std::net::SocketAddr::from((target_ip, 22));

    observe_tcp_readiness_with_probe(policy, |attempt_timeout| async move {
        match tokio::time::timeout(attempt_timeout, tokio::net::TcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                drop(stream);
                Ok(())
            }
            Ok(Err(error)) => Err(classify_tcp_connect_error(&error)),
            Err(_) => Err(TcpReadinessFailureClass::ConnectTimeout),
        }
    })
    .await
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct SupportAccessProviderEvidence {
    controller_ipv4: String,
    firewall_group_id: Option<String>,
    matching_rule_ids: Vec<u64>,
    exact_controller_rules_present_once: bool,
    machine_firewall_group_id: Option<String>,
    firewall_group_attached_to_machine: bool,
    acquire_plan_disposition: String,
}

fn classify_support_access_provider_evidence(
    controller_ipv4: String,
    firewall_group_id: Option<String>,
    observed_rules: &[VultrFirewallRule],
    target_rules: &std::collections::BTreeSet<crate::vultr_support_resources::FirewallRuleSpec>,
    machine_firewall_group_id: Option<String>,
    acquire_disposition: PlanDisposition,
) -> Result<SupportAccessProviderEvidence, String> {
    let mut matching_rule_ids = Vec::new();
    let mut matching_counts = BTreeMap::new();
    for rule in observed_rules {
        let spec = firewall_rule_spec(rule)?;
        if target_rules.contains(&spec) {
            matching_rule_ids.push(rule.id);
            *matching_counts.entry(spec).or_insert(0usize) += 1;
        }
    }
    matching_rule_ids.sort_unstable();

    let exact_controller_rules_present_once = !target_rules.is_empty()
        && target_rules
            .iter()
            .all(|target| matching_counts.get(target) == Some(&1usize));
    let firewall_group_attached_to_machine = firewall_group_id
        .as_ref()
        .is_some_and(|group_id| machine_firewall_group_id.as_ref() == Some(group_id));
    let acquire_plan_disposition = match acquire_disposition {
        PlanDisposition::Noop => "NOOP",
        PlanDisposition::Mutate => "MUTATE",
        PlanDisposition::Blocked => "BLOCKED",
    }
    .to_owned();

    Ok(SupportAccessProviderEvidence {
        controller_ipv4,
        firewall_group_id,
        matching_rule_ids,
        exact_controller_rules_present_once,
        machine_firewall_group_id,
        firewall_group_attached_to_machine,
        acquire_plan_disposition,
    })
}

async fn capture_support_access_provider_evidence(
    desired: &DesiredState,
    machine_id: &str,
    lifecycle_provider: &mut VultrApiProvider,
    support_provider: &mut VultrSupportApiProvider,
) -> Result<SupportAccessProviderEvidence, String> {
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profile_name = machine
        .provider
        .firewall_profile
        .as_deref()
        .ok_or_else(|| {
            format!(
                "machine {} has no firewall_profile; timeout evidence requires support access",
                machine.id
            )
        })?;

    let (raw_profiles, _, _, controller_ipv4) = load_access_authority_profiles(desired)?;
    let raw_profile = raw_profiles.profile(profile_name)?;
    let target_rules = controller_ipv4_access_specs(raw_profile, &controller_ipv4)?;
    let (support_observation, observed_rules) =
        observe_firewall_access_authority(support_provider, &desired.environment, profile_name)
            .await?;
    let firewall_group_id = support_observation
        .get("group")
        .and_then(serde_json::Value::as_object)
        .and_then(|group| group.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    let fresh_machine = exact_existing_machine_observation(desired, machine_id).await?;
    let fresh_authority = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Acquire,
        lifecycle_provider,
        support_provider,
    )
    .await?;

    classify_support_access_provider_evidence(
        controller_ipv4,
        firewall_group_id,
        &observed_rules,
        &target_rules,
        fresh_machine.firewall_group_id,
        fresh_authority.disposition,
    )
}

fn support_access_timeout_error(
    target_ip: &str,
    tcp_readiness: &TcpReadinessObservation,
    provider_evidence: Result<SupportAccessProviderEvidence, String>,
) -> String {
    let evidence_json = match provider_evidence {
        Ok(evidence) => serde_json::to_string(&evidence).unwrap_or_else(|err| {
            format!(r#"{{"status":"SERIALIZATION_ERROR","detail":"{err}"}}"#)
        }),
        Err(error) => serde_json::to_string(&serde_json::json!({
            "status": "OBSERVATION_ERROR",
            "detail": error,
        }))
        .unwrap_or_else(|err| format!(r#"{{"status":"SERIALIZATION_ERROR","detail":"{err}"}}"#)),
    };
    format!(
        "support-access TCP readiness failed for {target_ip}:22: {}; provider_evidence={evidence_json}",
        tcp_readiness.evidence()
    )
}

fn strict_ssh_error_after_tcp_ready(
    tcp_readiness: &TcpReadinessObservation,
    ssh_error: String,
) -> String {
    format!(
        "support-access TCP readiness passed ({}); {ssh_error}",
        tcp_readiness.evidence()
    )
}

async fn run_lease_acquire(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle lease-acquire <spec-path> <machine-id>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let planned = build_access_authority(
        &desired,
        &args[1],
        AccessAuthorityMode::Acquire,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if planned.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "lease-acquire is blocked for machine {} by exact plan",
            args[1]
        ));
    }
    let authority_digest = planned.authority.authority_digest.clone();
    let access = acquire_access_with_authority(&desired, &args[1], &authority_digest).await?;

    let mut lease = SupportAccessLeaseState::default();
    lease.acquired()?;
    let observed = exact_existing_machine_observation(&desired, &args[1]).await?;
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| format!("exact machine {} has no observed public IPv4", args[1]))?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let substrate = host_substrate_versions_from_env()?;
    let tcp_readiness =
        observe_tcp_readiness(target_ip, TcpReadinessPolicy::support_access()).await?;
    if tcp_readiness.final_state == TcpReadinessState::Timeout {
        let provider_evidence = capture_support_access_provider_evidence(
            &desired,
            &args[1],
            &mut lifecycle_provider,
            &mut support_provider,
        )
        .await;
        return Err(support_access_timeout_error(
            target_ip,
            &tcp_readiness,
            provider_evidence,
        ));
    }
    strict_ssh_accept(
        target_ip,
        &args[1],
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        15,
        Duration::from_secs(2),
    )
    .await
    .map_err(|error| strict_ssh_error_after_tcp_ready(&tcp_readiness, error))?;
    lease.ready()?;
    let mutations_performed = access
        .get("mutations_performed")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    print_json_value(serde_json::json!({
        "status": "READY",
        "machine_id": args[1],
        "lease_phase": lease.phase(),
        "access": access,
        "provider_id": observed.provider_id,
        "tcp_readiness": tcp_readiness,
        "mutations_performed": mutations_performed,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessReconcileClass {
    Noop,
    FirewallOnly,
    Blocked,
}

fn access_reconcile_class(
    plan: &edge_controller_core::vultr_lifecycle::MachinePlan,
) -> AccessReconcileClass {
    match plan.class {
        PlanClass::Noop => AccessReconcileClass::Noop,
        PlanClass::UpdateInPlace
            if !plan.reasons.is_empty()
                && plan.reasons.iter().all(|reason| {
                    reason == "firewall profile differs or is not provider-verified"
                }) =>
        {
            AccessReconcileClass::FirewallOnly
        }
        _ => AccessReconcileClass::Blocked,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessAuthorityMode {
    Acquire,
    Release,
}

impl AccessAuthorityMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Acquire => "ACQUIRE",
            Self::Release => "RELEASE",
        }
    }
}

fn load_access_authority_profiles(
    desired: &DesiredState,
) -> Result<
    (
        FirewallProfileSet,
        FirewallProfileSet,
        serde_json::Value,
        String,
    ),
    String,
> {
    let path = Path::new(FIREWALL_PROFILES_PATH);
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read firewall profiles {}: {err}", path.display()))?;
    let raw_profiles = FirewallProfileSet::parse_json(&raw)?;
    let mut resolved_profiles = raw_profiles.clone();
    let profile_names = desired
        .machines
        .iter()
        .filter_map(|machine| machine.provider.firewall_profile.clone())
        .collect::<Vec<_>>();
    let controller_ipv4 = env::var("EDGE_CONTROLLER_IPV4")
        .map_err(|_| "EDGE_CONTROLLER_IPV4 is required for access authority".to_owned())?;
    resolved_profiles
        .resolve_controller_ipv4_for_profiles(&profile_names, Some(controller_ipv4.as_str()))?;
    for profile_name in &profile_names {
        resolved_profiles.profile(profile_name)?;
    }
    let value = serde_json::from_str(&raw)
        .map_err(|err| format!("invalid firewall profiles JSON: {err}"))?;
    Ok((raw_profiles, resolved_profiles, value, controller_ipv4))
}

async fn observe_firewall_access_authority<P: SupportResourceProvider>(
    provider: &mut P,
    environment: &str,
    profile_name: &str,
) -> Result<(serde_json::Value, Vec<VultrFirewallRule>), String> {
    let description = firewall_group_description(environment, profile_name);
    let mut groups = provider
        .list_firewall_groups()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|group| group.description == description)
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    if groups.len() > 1 {
        return Err(format!(
            "multiple Vultr firewall groups have owned description {description}"
        ));
    }

    let mut rules = if let Some(group) = groups.first() {
        provider
            .list_firewall_rules(&group.id)
            .await
            .map_err(|err| err.to_string())?
    } else {
        Vec::new()
    };
    rules.sort_by_key(|rule| rule.id);
    let group = groups.first().map(|group| {
        serde_json::json!({
            "id": group.id,
            "description": group.description,
        })
    });
    let observation = serde_json::json!({
        "description": description,
        "group": group,
        "rules": rules,
    });
    Ok((observation, rules))
}

async fn build_access_authority(
    desired: &DesiredState,
    machine_id: &str,
    mode: AccessAuthorityMode,
    lifecycle_provider: &mut VultrApiProvider,
    support_provider: &mut VultrSupportApiProvider,
) -> Result<AuthorizedPlan<serde_json::Value>, String> {
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profile_name = machine.provider.firewall_profile.as_deref().ok_or_else(|| {
        format!(
            "machine {} has no firewall_profile; access authority requires provider-owned SSH ingress",
            machine.id
        )
    })?;
    let (raw_profiles, resolved_profiles, profile_material, controller_ipv4) =
        load_access_authority_profiles(desired)?;
    let raw_profile = raw_profiles.profile(profile_name)?;
    if !raw_profile
        .rules
        .iter()
        .any(|rule| rule.subnet == "@controller-ipv4")
    {
        return Err(format!(
            "firewall profile {profile_name} has no @controller-ipv4 rule"
        ));
    }

    let (support_observation, observed_rules) =
        observe_firewall_access_authority(support_provider, &desired.environment, profile_name)
            .await?;
    let desired_material = serde_json::json!({
        "desired": desired,
        "machine_id": machine_id,
        "operation": mode.as_str(),
        "controller_ipv4": controller_ipv4,
        "firewall_profiles": profile_material,
    });

    match mode {
        AccessAuthorityMode::Acquire => {
            let verified_firewalls =
                observe_verified_firewall_bindings(support_provider, desired, &resolved_profiles)
                    .await?;
            let report = plan_desired_state_with_firewall_profiles(
                lifecycle_provider,
                desired,
                Some(machine_id),
                &verified_firewalls,
            )
            .await?;
            let machine_plan = report
                .plans
                .first()
                .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?
                .clone();
            let (action, disposition) = match access_reconcile_class(&machine_plan) {
                AccessReconcileClass::Noop => ("NOOP", PlanDisposition::Noop),
                AccessReconcileClass::FirewallOnly => ("ACQUIRE", PlanDisposition::Mutate),
                AccessReconcileClass::Blocked => ("BLOCKED", PlanDisposition::Blocked),
            };
            let observed = serde_json::json!({
                "machine_inventory": report.inventory,
                "support": support_observation,
            });
            let plan = serde_json::json!({
                "action": action,
                "machine_id": machine_id,
                "firewall_profile": profile_name,
                "machine_plan": machine_plan,
            });
            authorize_plan(
                "vultr_support_access",
                &desired_material,
                &observed,
                plan,
                disposition,
            )
            .map_err(|err| err.to_string())
        }
        AccessAuthorityMode::Release => {
            let targets = controller_ipv4_access_specs(raw_profile, &controller_ipv4)?;
            if targets.is_empty() {
                return Err(format!(
                    "firewall profile {profile_name} has no @controller-ipv4 access rule"
                ));
            }
            let mut matching_rule_ids = Vec::new();
            for rule in &observed_rules {
                let spec = firewall_rule_spec(rule)?;
                if controller_access_cleanup_projection_matches(raw_profile, &spec)? {
                    matching_rule_ids.push(rule.id);
                }
            }
            matching_rule_ids.sort_unstable();
            let disposition = if matching_rule_ids.is_empty() {
                PlanDisposition::Noop
            } else {
                PlanDisposition::Mutate
            };
            let plan = serde_json::json!({
                "action": if disposition == PlanDisposition::Noop { "NOOP" } else { "RELEASE" },
                "machine_id": machine_id,
                "firewall_profile": profile_name,
                "matching_rule_ids": matching_rule_ids,
            });
            authorize_plan(
                "vultr_support_access",
                &desired_material,
                &support_observation,
                plan,
                disposition,
            )
            .map_err(|err| err.to_string())
        }
    }
}

async fn run_release_access_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle release-access-plan <spec-path> <machine-id>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let authorized = build_access_authority(
        &desired,
        &args[1],
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    print_json_value(serde_json::json!({
        "plan": authorized.plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_release_access(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle release-access <spec-path> <machine-id> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let result = release_access_with_authority(&desired, &args[1], &args[2]).await?;
    print_json_value(result)
}

async fn release_access_with_authority(
    desired: &DesiredState,
    machine_id: &str,
    authorized_plan_digest: &str,
) -> Result<serde_json::Value, String> {
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profile_name = machine.provider.firewall_profile.as_deref().ok_or_else(|| {
        format!(
            "machine {} has no firewall_profile; release-access requires provider-owned SSH ingress",
            machine.id
        )
    })?;
    let (raw_profiles, _, _, controller_ipv4) = load_access_authority_profiles(desired)?;
    let profile = raw_profiles.profile(profile_name)?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let authorized = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    if authorized.disposition == PlanDisposition::Noop {
        return Ok(serde_json::json!({
            "action": "NOOP",
            "machine_id": machine.id,
            "firewall_profile": profile_name,
            "next_plan": authorized.plan,
            "mutations_performed": 0,
        }));
    }
    if authorized.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "release-access is blocked for machine {} by exact authorized plan",
            machine.id
        ));
    }

    let report = release_controller_ipv4_access(
        &mut support_provider,
        &desired.environment,
        profile,
        &controller_ipv4,
        &policy,
    )
    .await?;
    if !report.verified_absent {
        return Err("controller SSH access cleanup did not verify absence".to_owned());
    }

    let next = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if next.disposition != PlanDisposition::Noop {
        return Err("controller SSH access cleanup did not converge to NOOP".to_owned());
    }

    Ok(serde_json::json!({
        "action": "RELEASED",
        "machine_id": machine.id,
        "firewall_profile": profile_name,
        "firewall_group_id": report.firewall_group_id,
        "verified_absent": report.verified_absent,
        "next_plan": next.plan,
        "mutations_performed": 1,
    }))
}

async fn run_lease_release(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle lease-release <spec-path> <machine-id>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let planned = build_access_authority(
        &desired,
        &args[1],
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if planned.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "lease-release is blocked for machine {} by exact plan",
            args[1]
        ));
    }
    let authority_digest = planned.authority.authority_digest.clone();
    let access = release_access_with_authority(&desired, &args[1], &authority_digest).await?;
    let verified_absent = access
        .get("verified_absent")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| {
            access
                .get("action")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|action| action == "NOOP")
        });
    if !verified_absent {
        return Err("lease-release did not prove transient SSH access absent".to_owned());
    }
    print_json_value(serde_json::json!({
        "status": "RELEASED",
        "machine_id": args[1],
        "access": access,
    }))
}

fn instance_action_disposition(
    action: InstanceAction,
    observed: &VultrInstance,
) -> (PlanDisposition, &'static str) {
    match action {
        InstanceAction::Start => match observed.power_status.as_str() {
            "running" => (PlanDisposition::Noop, "NOOP"),
            "stopped" => (PlanDisposition::Mutate, "START"),
            _ => (PlanDisposition::Blocked, "BLOCKED"),
        },
        InstanceAction::Halt => match observed.power_status.as_str() {
            "stopped" => (PlanDisposition::Noop, "NOOP"),
            "running" => (PlanDisposition::Mutate, "HALT"),
            _ => (PlanDisposition::Blocked, "BLOCKED"),
        },
        InstanceAction::Reboot => {
            if observed.power_status == "running"
                && observed.status == "active"
                && observed.server_status == "ok"
            {
                (PlanDisposition::Mutate, "REBOOT")
            } else {
                (PlanDisposition::Blocked, "BLOCKED")
            }
        }
    }
}

async fn build_instance_action_authority(
    desired: &DesiredState,
    machine_id: &str,
    action: InstanceAction,
    lifecycle_provider: &mut VultrApiProvider,
    support_provider: &mut VultrSupportApiProvider,
    operational_provider: &mut VultrOperationalApiProvider,
) -> Result<(AuthorizedPlan<serde_json::Value>, VultrInstance), String> {
    let profiles = load_firewall_profiles(desired)?;
    let verified_firewalls =
        verified_firewall_bindings(support_provider, desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        lifecycle_provider,
        desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    let target = report
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    if target.class != PlanClass::Noop {
        return Err(format!(
            "instance action requires exact NOOP provider identity; machine {} is {:?}: {}",
            machine_id,
            target.class,
            target.reasons.join("; ")
        ));
    }
    let provider_id = target
        .provider_id
        .as_deref()
        .ok_or_else(|| "NOOP plan is missing provider id".to_owned())?;
    let operational = operational_provider
        .get_instance(provider_id)
        .await
        .map_err(|err| err.to_string())?;
    if operational.id != provider_id {
        return Err(format!(
            "instance action observation returned unexpected provider id {} for {}",
            operational.id, provider_id
        ));
    }

    let (disposition, planned_action) = instance_action_disposition(action, &operational);
    let desired_material = serde_json::json!({
        "desired": desired,
        "machine_id": machine_id,
        "requested_action": action.as_str(),
    });
    let observed_material = serde_json::json!({
        "lifecycle_inventory": report.inventory,
        "operational": {
            "provider_id": operational.id,
            "power_status": operational.power_status,
            "status": operational.status,
            "server_status": operational.server_status,
        }
    });
    let action_plan = serde_json::json!({
        "machine_id": machine_id,
        "provider_id": provider_id,
        "requested_action": action.as_str(),
        "action": planned_action,
    });
    let authorized = authorize_plan(
        "vultr_instance_action",
        &desired_material,
        &observed_material,
        action_plan,
        disposition,
    )
    .map_err(|err| err.to_string())?;
    Ok((authorized, operational))
}

async fn run_action_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle action-plan <spec-path> <machine-id> <start|halt|reboot>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let action = InstanceAction::parse(&args[2])?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let mut operational_provider = operational_provider_from_env()?;
    let (authorized, operational) = build_instance_action_authority(
        &desired,
        &args[1],
        action,
        &mut lifecycle_provider,
        &mut support_provider,
        &mut operational_provider,
    )
    .await?;
    print_json_value(serde_json::json!({
        "plan": authorized.plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "observation": {
            "power_status": operational.power_status,
            "status": operational.status,
            "server_status": operational.server_status,
        },
        "mutations_performed": 0,
    }))
}

pub(crate) fn validate_linux_boot_id(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || !bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
    {
        return Err("guest boot_id is not a canonical Linux UUID".to_owned());
    }
    Ok(())
}

pub(crate) fn observe_guest_boot_id(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
) -> Result<String, String> {
    let boot_id = strict_ssh_capture(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        canonical_operator_public_key,
        "cat /proc/sys/kernel/random/boot_id",
    )?;
    validate_linux_boot_id(&boot_id)?;
    Ok(boot_id)
}

pub(crate) async fn wait_for_guest_boot_id_change(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    previous_boot_id: &str,
    attempts: usize,
    delay: std::time::Duration,
) -> Result<String, String> {
    if attempts == 0 {
        return Err("guest reboot observation attempts must be greater than zero".to_owned());
    }
    validate_linux_boot_id(previous_boot_id)?;

    let mut last_state = "not-observed";
    for attempt in 0..attempts {
        match strict_ssh_capture(
            target_ip,
            logical_hostname,
            operator_private_key_path,
            canonical_operator_public_key,
            "cat /proc/sys/kernel/random/boot_id",
        ) {
            Ok(current) => {
                if validate_linux_boot_id(&current).is_err() {
                    last_state = "invalid-boot-id";
                } else if current != previous_boot_id {
                    return Ok(current);
                } else {
                    last_state = "same-boot-id";
                }
            }
            Err(_) => {
                last_state = "ssh-unavailable";
            }
        }

        if attempt + 1 < attempts {
            tokio::time::sleep(delay).await;
        }
    }

    Err(format!(
        "guest reboot was not proven for {logical_hostname} at {target_ip}: boot_id did not change after {attempts} observations; last_state={last_state}"
    ))
}

async fn run_action(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle action <spec-path> <machine-id> <start|halt|reboot> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let action = InstanceAction::parse(&args[2])?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let mut operational_provider = operational_provider_from_env()?;
    let (authorized, operational) = build_instance_action_authority(
        &desired,
        &args[1],
        action,
        &mut lifecycle_provider,
        &mut support_provider,
        &mut operational_provider,
    )
    .await?;
    verify_exact_authority(&args[3], &authorized.authority).map_err(|err| err.to_string())?;

    match authorized.disposition {
        PlanDisposition::Noop => {
            return print_json_value(serde_json::json!({
                "machine_id": args[1],
                "provider_id": operational.id,
                "action": "NOOP",
                "power_status": operational.power_status,
                "status": operational.status,
                "server_status": operational.server_status,
                "mutations_performed": 0,
            }));
        }
        PlanDisposition::Blocked => {
            return Err(format!(
                "instance {} action {} is blocked by current operational state: power_status={} status={} server_status={}",
                args[1],
                action.as_str(),
                operational.power_status,
                operational.status,
                operational.server_status
            ));
        }
        PlanDisposition::Mutate => {}
    }

    let reboot_probe = if action == InstanceAction::Reboot {
        let canonical_public_key = read_canonical_ssh_public_key()?;
        let operator_private_key_path = operator_private_key_path_from_env()?;
        verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
        let boot_id_before = observe_guest_boot_id(
            &operational.main_ip,
            &args[1],
            &operator_private_key_path,
            &canonical_public_key,
        )?;
        Some((
            canonical_public_key,
            operator_private_key_path,
            boot_id_before,
        ))
    } else {
        None
    };

    let observed = apply_instance_action(
        &mut operational_provider,
        &operational.id,
        action,
        60,
        std::time::Duration::from_secs(2),
    )
    .await?;

    let reboot_observation =
        if let Some((canonical_public_key, operator_private_key_path, boot_id_before)) =
            reboot_probe
        {
            let boot_id_after = wait_for_guest_boot_id_change(
                &operational.main_ip,
                &args[1],
                &operator_private_key_path,
                &canonical_public_key,
                &boot_id_before,
                60,
                std::time::Duration::from_secs(2),
            )
            .await?;
            Some(serde_json::json!({
                "boot_id_before": boot_id_before,
                "boot_id_after": boot_id_after,
                "boot_id_changed": true,
            }))
        } else {
            None
        };

    let next_plan = if matches!(action, InstanceAction::Start | InstanceAction::Halt) {
        let (next, _) = build_instance_action_authority(
            &desired,
            &args[1],
            action,
            &mut lifecycle_provider,
            &mut support_provider,
            &mut operational_provider,
        )
        .await?;
        if next.disposition != PlanDisposition::Noop {
            return Err(format!(
                "instance action {} completed but did not converge to NOOP",
                action.as_str()
            ));
        }
        Some(next.plan)
    } else {
        None
    };

    print_json_value(serde_json::json!({
        "machine_id": args[1],
        "provider_id": operational.id,
        "action": action.as_str(),
        "power_status": observed.power_status,
        "status": observed.status,
        "server_status": observed.server_status,
        "next_plan": next_plan,
        "reboot_observation": reboot_observation,
        "mutations_performed": 1,
    }))
}

async fn run_destroy_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle destroy-plan <spec-path> <machine-id> <source-revision>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let profiles = load_firewall_profiles(&desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let inventory = inventory_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        &verified_firewalls,
    )
    .await?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
    let plan =
        destroy_plan(&desired, machine, &inventory, &args[2]).map_err(|err| err.to_string())?;
    let authorized =
        authorize_vultr_destroy(&desired, &args[1], &args[2], &inventory, plan.clone())?;
    let mut value = serde_json::to_value(&plan)
        .map_err(|err| format!("failed to serialize destroy plan: {err}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "destroy plan serialization must be a JSON object".to_owned())?;
    object.insert(
        "plan_authority".to_owned(),
        serde_json::to_value(&authorized.authority)
            .map_err(|err| format!("failed to serialize plan authority: {err}"))?,
    );
    object.insert(
        "plan_disposition".to_owned(),
        serde_json::to_value(authorized.disposition)
            .map_err(|err| format!("failed to serialize plan disposition: {err}"))?,
    );
    print_json_value(value)
}

async fn run_destroy_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle destroy-apply <spec-path> <machine-id> <source-revision> <destroy-digest> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let profiles = load_firewall_profiles(&desired)?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let report = destroy_machine_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        &args[1],
        &args[2],
        &args[3],
        &args[4],
        &policy,
        &verified_firewalls,
    )
    .await?;

    print_json_value(serde_json::json!({
        "machine_id": report.machine_id,
        "provider_id": report.provider_id,
        "delete_requested": report.delete_requested,
        "absence_verified": report.absence_verified,
        "support_cleanup_required": true,
    }))
}

struct SupportCleanupAuthorityContext {
    authorized: AuthorizedPlan<serde_json::Value>,
    remaining_instances: Vec<VultrInstance>,
}

async fn build_support_cleanup_authority(
    desired: &DesiredState,
    lifecycle_provider: &mut VultrApiProvider,
    support_provider: &mut VultrSupportApiProvider,
    canonical_public_key: &str,
) -> Result<SupportCleanupAuthorityContext, String> {
    let mut remaining_instances = lifecycle_provider
        .list_instances()
        .await
        .map_err(|err| err.to_string())?;
    remaining_instances.sort_by(|left, right| left.id.cmp(&right.id));

    let mut environment_in_use = false;
    let mut instance_observation = Vec::new();
    for instance in &remaining_instances {
        let decoded = decode_provider_tags(&instance.tags).map_err(|err| {
            format!(
                "cannot prove support-resource cleanup safety because instance {} has invalid lifecycle tags: {err}",
                instance.id
            )
        })?;
        if decoded.ownership.managed_by.as_deref() == Some(MANAGED_BY_IDENTITY)
            && decoded.ownership.environment.as_deref() == Some(desired.environment.as_str())
        {
            environment_in_use = true;
        }
        let mut tags = instance.tags.clone();
        tags.sort();
        instance_observation.push(serde_json::json!({
            "id": instance.id,
            "firewall_group_id": instance.firewall_group_id,
            "tags": tags,
        }));
    }

    let canonical_material = public_key_material(canonical_public_key)?;
    let desired_material = serde_json::json!({
        "desired": desired,
        "canonical_ssh_public_key": canonical_material,
    });

    if environment_in_use {
        let observed = serde_json::json!({
            "instances": instance_observation,
        });
        let plan = serde_json::json!({
            "action": "NOOP",
            "environment_in_use": true,
            "firewall_group_ids": [],
            "ssh_key_id": null,
        });
        let authorized = authorize_plan(
            "vultr_support_cleanup",
            &desired_material,
            &observed,
            plan,
            PlanDisposition::Noop,
        )
        .map_err(|err| err.to_string())?;
        return Ok(SupportCleanupAuthorityContext {
            authorized,
            remaining_instances,
        });
    }

    let firewall_prefix = format!("singbox-{}-fw-", desired.environment);
    let mut groups = support_provider
        .list_firewall_groups()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|group| group.description.starts_with(&firewall_prefix))
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| left.id.cmp(&right.id));

    let mut seen_descriptions = std::collections::BTreeSet::new();
    for group in &groups {
        if !seen_descriptions.insert(group.description.clone()) {
            return Err(format!(
                "support-resource cleanup is ambiguous: duplicate managed firewall description {}",
                group.description
            ));
        }
        if remaining_instances
            .iter()
            .any(|instance| instance.firewall_group_id == group.id)
        {
            return Err(format!(
                "support-resource cleanup refused: firewall group {} is still attached to provider instance",
                group.id
            ));
        }
    }

    let desired_ssh_name = format!("singbox-{}-ops", desired.environment);
    let mut named_keys = support_provider
        .list_ssh_keys()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|key| key.name == desired_ssh_name)
        .collect::<Vec<_>>();
    named_keys.sort_by(|left, right| left.id.cmp(&right.id));
    if named_keys.len() > 1 {
        return Err(format!(
            "multiple Vultr SSH keys use managed name {desired_ssh_name}"
        ));
    }
    let ssh_key = if let Some(key) = named_keys.first() {
        let observed_material = public_key_material(&key.ssh_key)?;
        if observed_material != canonical_material {
            return Err(format!(
                "Vultr SSH key {} has managed name {} but different public key material",
                key.id, desired_ssh_name
            ));
        }
        Some(serde_json::json!({
            "id": key.id,
            "name": key.name,
            "public_key": observed_material,
        }))
    } else {
        None
    };

    let group_observation = groups
        .iter()
        .map(|group| {
            serde_json::json!({
                "id": group.id,
                "description": group.description,
            })
        })
        .collect::<Vec<_>>();
    let firewall_group_ids = groups
        .iter()
        .map(|group| group.id.clone())
        .collect::<Vec<_>>();
    let ssh_key_id = named_keys.first().map(|key| key.id.clone());
    let disposition = if firewall_group_ids.is_empty() && ssh_key_id.is_none() {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    let observed = serde_json::json!({
        "instances": instance_observation,
        "firewall_groups": group_observation,
        "ssh_key": ssh_key,
    });
    let plan = serde_json::json!({
        "action": if disposition == PlanDisposition::Noop { "NOOP" } else { "CLEANUP" },
        "environment_in_use": false,
        "firewall_group_ids": firewall_group_ids,
        "ssh_key_id": ssh_key_id,
    });
    let authorized = authorize_plan(
        "vultr_support_cleanup",
        &desired_material,
        &observed,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())?;

    Ok(SupportCleanupAuthorityContext {
        authorized,
        remaining_instances,
    })
}

async fn run_cleanup_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-orchestrator vultr-lifecycle cleanup-plan <spec-path>".to_owned());
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let context = build_support_cleanup_authority(
        &desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    print_json_value(serde_json::json!({
        "plan": context.authorized.plan,
        "plan_authority": context.authorized.authority,
        "plan_disposition": context.authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_cleanup(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle cleanup <spec-path> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let context = build_support_cleanup_authority(
        &desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    verify_exact_authority(&args[1], &context.authorized.authority)
        .map_err(|err| err.to_string())?;

    if context.authorized.disposition == PlanDisposition::Noop {
        let environment_in_use = context
            .authorized
            .plan
            .get("environment_in_use")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        return print_json_value(serde_json::json!({
            "environment": desired.environment,
            "action": "NOOP",
            "environment_in_use": environment_in_use,
            "ssh_key_removed": false,
            "firewall_groups_removed": [],
            "plan": context.authorized.plan,
            "mutations_performed": 0,
        }));
    }
    if context.authorized.disposition == PlanDisposition::Blocked {
        return Err("support-resource cleanup is blocked by exact authorized plan".to_owned());
    }

    let cleanup = cleanup_environment_support_resources(
        &mut support_provider,
        &desired,
        &context.remaining_instances,
        &canonical_public_key,
        &policy,
    )
    .await?;
    let next = build_support_cleanup_authority(
        &desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    if next.authorized.disposition != PlanDisposition::Noop {
        return Err("support-resource cleanup did not converge to NOOP".to_owned());
    }

    print_json_value(serde_json::json!({
        "environment": desired.environment,
        "action": "CLEANED",
        "environment_in_use": cleanup.environment_in_use,
        "ssh_key_removed": cleanup.ssh_key_removed,
        "firewall_groups_removed": cleanup.firewall_groups_removed,
        "next_plan": next.authorized.plan,
    }))
}

pub(crate) async fn acceptance_require_clean_room(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let support = build_support_cleanup_authority(
        &desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    let environment_in_use = support
        .authorized
        .plan
        .get("environment_in_use")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let firewall_count = support
        .authorized
        .plan
        .get("firewall_group_ids")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(usize::MAX);
    let ssh_key_absent = support
        .authorized
        .plan
        .get("ssh_key_id")
        .is_some_and(serde_json::Value::is_null);
    if support.authorized.disposition != PlanDisposition::Noop
        || environment_in_use
        || firewall_count != 0
        || !ssh_key_absent
    {
        return Err("acceptance Vultr support clean room is not empty".to_owned());
    }

    let profiles = load_firewall_profiles(&desired)?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    if !report.orphaned_managed_provider_ids.is_empty() {
        return Err(format!(
            "acceptance Vultr clean room has orphaned managed provider resources: {:?}",
            report.orphaned_managed_provider_ids
        ));
    }
    let plan = report
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    if plan.class != PlanClass::Create {
        return Err(format!(
            "fresh acceptance VM must plan CREATE, got {:?}: {}",
            plan.class,
            plan.reasons.join("; ")
        ));
    }
    Ok(())
}

pub(crate) async fn acceptance_lease_acquire(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let planned = build_access_authority(
        &desired,
        machine_id,
        AccessAuthorityMode::Acquire,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if planned.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "acceptance lease-acquire is blocked for machine {machine_id}"
        ));
    }
    let access =
        acquire_access_with_authority(&desired, machine_id, &planned.authority.authority_digest)
            .await?;

    let observed = exact_existing_machine_observation(&desired, machine_id).await?;
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| format!("exact machine {machine_id} has no observed public IPv4"))?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let substrate = host_substrate_versions_from_env()?;
    let tcp_readiness =
        observe_tcp_readiness(target_ip, TcpReadinessPolicy::support_access()).await?;
    if tcp_readiness.final_state == TcpReadinessState::Timeout {
        let provider_evidence = capture_support_access_provider_evidence(
            &desired,
            machine_id,
            &mut lifecycle_provider,
            &mut support_provider,
        )
        .await;
        return Err(support_access_timeout_error(
            target_ip,
            &tcp_readiness,
            provider_evidence,
        ));
    }
    strict_ssh_accept(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        15,
        Duration::from_secs(2),
    )
    .await
    .map_err(|error| strict_ssh_error_after_tcp_ready(&tcp_readiness, error))?;

    if access
        .get("next_plan")
        .and_then(|plan| plan.get("action"))
        .and_then(serde_json::Value::as_str)
        != Some("NOOP")
    {
        return Err("acceptance lease-acquire did not converge to NOOP".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_lease_release(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let planned = build_access_authority(
        &desired,
        machine_id,
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if planned.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "acceptance lease-release is blocked for machine {machine_id}"
        ));
    }
    let access =
        release_access_with_authority(&desired, machine_id, &planned.authority.authority_digest)
            .await?;
    let verified_absent = access
        .get("verified_absent")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| {
            access
                .get("action")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|action| action == "NOOP")
        });
    let no_matching_rules = access
        .get("next_plan")
        .and_then(|plan| plan.get("matching_rule_ids"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(Vec::is_empty);
    if !verified_absent || !no_matching_rules {
        return Err("acceptance lease-release did not prove transient SSH absence".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_converge_substrate(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let provider_id = exact_existing_machine_provider_id(&desired, machine_id).await?;
    let substrate = host_substrate_versions_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let mut provider = operational_provider_from_env()?;

    for _ in 0..4 {
        let (_observation, authorized) = build_host_substrate_authority(
            &mut provider,
            &desired,
            machine,
            &provider_id,
            &operator_private_key_path,
            &canonical_public_key,
            &substrate,
            HostSubstrateExecutionPolicy::default(),
        )
        .await?;
        match authorized.plan.action {
            HostSubstrateAction::Noop => return Ok(()),
            HostSubstrateAction::ScrubUserData | HostSubstrateAction::RotateHostCertificate => {
                apply_host_substrate_once(
                    &mut provider,
                    &desired,
                    machine,
                    &provider_id,
                    &authorized.authority.authority_digest,
                    &operator_private_key_path,
                    &canonical_public_key,
                    &substrate,
                    HostSubstrateExecutionPolicy::default(),
                )
                .await?;
            }
            action => {
                return Err(format!(
                    "acceptance host substrate convergence is blocked: {action:?}: {}",
                    authorized.plan.reasons.join("; ")
                ));
            }
        }
    }
    Err("host substrate convergence exceeded bounded mutation steps".to_owned())
}

pub(crate) async fn acceptance_verify_substrate(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let provider_id = exact_existing_machine_provider_id(&desired, machine_id).await?;
    let substrate = host_substrate_versions_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let mut provider = operational_provider_from_env()?;
    let (_observation, authorized) = build_host_substrate_authority(
        &mut provider,
        &desired,
        machine,
        &provider_id,
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        HostSubstrateExecutionPolicy::default(),
    )
    .await?;
    if authorized.plan.action != HostSubstrateAction::Noop {
        return Err(format!(
            "acceptance host substrate verify expected NOOP, got {:?}: {}",
            authorized.plan.action,
            authorized.plan.reasons.join("; ")
        ));
    }
    Ok(())
}

pub(crate) async fn acceptance_reboot(spec_path: &Path, machine_id: &str) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let mut operational_provider = operational_provider_from_env()?;
    let (authorized, operational) = build_instance_action_authority(
        &desired,
        machine_id,
        InstanceAction::Reboot,
        &mut lifecycle_provider,
        &mut support_provider,
        &mut operational_provider,
    )
    .await?;
    if authorized.disposition != PlanDisposition::Mutate {
        return Err("fresh acceptance reboot was not authorized as one mutation".to_owned());
    }
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let boot_id_before = observe_guest_boot_id(
        &operational.main_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
    )?;
    let authority_digest = authorized.authority.authority_digest.clone();
    let (fresh_authorized, fresh_operational) = build_instance_action_authority(
        &desired,
        machine_id,
        InstanceAction::Reboot,
        &mut lifecycle_provider,
        &mut support_provider,
        &mut operational_provider,
    )
    .await?;
    verify_exact_authority(&authority_digest, &fresh_authorized.authority)
        .map_err(|err| err.to_string())?;
    if fresh_authorized.disposition != PlanDisposition::Mutate
        || fresh_operational.id != operational.id
    {
        return Err("acceptance reboot authority changed before mutation".to_owned());
    }
    apply_instance_action(
        &mut operational_provider,
        &operational.id,
        InstanceAction::Reboot,
        60,
        Duration::from_secs(2),
    )
    .await?;
    let boot_id_after = wait_for_guest_boot_id_change(
        &operational.main_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        &boot_id_before,
        60,
        Duration::from_secs(2),
    )
    .await?;
    if boot_id_before == boot_id_after {
        return Err("acceptance reboot did not change guest boot identity".to_owned());
    }
    Ok(())
}

async fn acceptance_cleanup_support(desired: &DesiredState) -> Result<(), String> {
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let context = build_support_cleanup_authority(
        desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    if context.authorized.disposition == PlanDisposition::Blocked {
        return Err("acceptance support cleanup is blocked by exact plan".to_owned());
    }
    if context.authorized.disposition == PlanDisposition::Mutate {
        cleanup_environment_support_resources(
            &mut support_provider,
            desired,
            &context.remaining_instances,
            &canonical_public_key,
            &policy,
        )
        .await?;
    }
    let next = build_support_cleanup_authority(
        desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    let environment_in_use = next
        .authorized
        .plan
        .get("environment_in_use")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let firewall_count = next
        .authorized
        .plan
        .get("firewall_group_ids")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(usize::MAX);
    let ssh_key_absent = next
        .authorized
        .plan
        .get("ssh_key_id")
        .is_some_and(serde_json::Value::is_null);
    if next.authorized.disposition != PlanDisposition::Noop
        || environment_in_use
        || firewall_count != 0
        || !ssh_key_absent
    {
        return Err("acceptance support cleanup did not converge to exact absence".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_destroy_and_cleanup(
    spec_path: &Path,
    machine_id: &str,
    source_revision: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let profiles = load_firewall_profiles(&desired)?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let inventory = inventory_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        &verified_firewalls,
    )
    .await?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let lifecycle = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    let machine_plan = lifecycle
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    if machine_plan.class != PlanClass::Create {
        let plan = destroy_plan(&desired, machine, &inventory, source_revision)
            .map_err(|err| err.to_string())?;
        let authorized = authorize_vultr_destroy(
            &desired,
            machine_id,
            source_revision,
            &inventory,
            plan.clone(),
        )?;
        let report = destroy_machine_with_firewall_profiles(
            &mut lifecycle_provider,
            &desired,
            machine_id,
            source_revision,
            &plan.destroy_digest,
            &authorized.authority.authority_digest,
            &policy,
            &verified_firewalls,
        )
        .await?;
        if !report.absence_verified {
            return Err("acceptance VM destroy did not prove exact provider absence".to_owned());
        }
    }
    acceptance_cleanup_support(&desired).await?;
    acceptance_require_clean_room(spec_path, machine_id).await
}

pub(crate) fn load_desired_state(path: &Path) -> Result<DesiredState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read lifecycle spec {}: {err}", path.display()))?;
    DesiredState::parse_json(&raw)
        .map_err(|err| format!("failed to parse lifecycle spec {}: {err}", path.display()))
}

pub(crate) fn load_firewall_profiles(
    desired: &DesiredState,
) -> Result<Option<FirewallProfileSet>, String> {
    let Some(profiles) = load_firewall_profiles_raw(desired)? else {
        return Ok(None);
    };
    let profile_names = desired
        .machines
        .iter()
        .filter_map(|machine| machine.provider.firewall_profile.clone())
        .collect::<Vec<_>>();
    for profile_name in &profile_names {
        profiles.profile(profile_name)?;
    }
    Ok(Some(profiles))
}

fn load_firewall_profiles_raw(
    desired: &DesiredState,
) -> Result<Option<FirewallProfileSet>, String> {
    if desired
        .machines
        .iter()
        .all(|machine| machine.provider.firewall_profile.is_none())
    {
        return Ok(None);
    }
    let path = Path::new(FIREWALL_PROFILES_PATH);
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read firewall profiles {}: {err}", path.display()))?;
    FirewallProfileSet::parse_json(&raw).map(Some)
}

pub(crate) async fn verified_firewall_bindings(
    provider: &mut VultrSupportApiProvider,
    desired: &DesiredState,
    profiles: Option<&FirewallProfileSet>,
) -> Result<BTreeMap<String, String>, String> {
    match profiles {
        Some(profiles) => observe_verified_firewall_bindings(provider, desired, profiles).await,
        None => Ok(BTreeMap::new()),
    }
}

pub(crate) fn lifecycle_provider_from_env() -> Result<VultrApiProvider, String> {
    VultrApiProvider::new(vultr_api_key_from_env()?)
}

pub(crate) fn support_provider_from_env() -> Result<VultrSupportApiProvider, String> {
    VultrSupportApiProvider::new(vultr_api_key_from_env()?)
}

fn operational_provider_from_env() -> Result<VultrOperationalApiProvider, String> {
    VultrOperationalApiProvider::new(vultr_api_key_from_env()?)
}

pub(crate) fn operator_private_key_path_from_env() -> Result<PathBuf, String> {
    let path = env::var_os("EDGE_SSH_PRIVATE_KEY_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| {
            "EDGE_SSH_PRIVATE_KEY_PATH is required for strict SSH lifecycle apply".to_owned()
        })?;
    if !path.is_file() {
        return Err(format!(
            "EDGE_SSH_PRIVATE_KEY_PATH does not point to a readable file: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn vultr_api_key_from_env() -> Result<String, String> {
    env::var("VULTR_API_KEY").map_err(|_| "VULTR_API_KEY is required".to_owned())
}

pub(crate) fn host_substrate_versions_from_env() -> Result<HostSubstrateVersions, String> {
    HostSubstrateVersions::new(
        env::var("EDGE_DOCKER_ENGINE_VERSION").map_err(|_| {
            "EDGE_DOCKER_ENGINE_VERSION is required for vultr-lifecycle apply".to_owned()
        })?,
        env::var("EDGE_CONTAINERD_VERSION").map_err(|_| {
            "EDGE_CONTAINERD_VERSION is required for vultr-lifecycle apply".to_owned()
        })?,
        env::var("EDGE_COMPOSE_VERSION")
            .map_err(|_| "EDGE_COMPOSE_VERSION is required for vultr-lifecycle apply".to_owned())?,
    )
}

pub(crate) fn read_canonical_ssh_public_key() -> Result<String, String> {
    let path = Path::new(CANONICAL_SSH_PUBLIC_KEY_PATH);
    let public_key = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read canonical SSH public key {}: {err}",
            path.display()
        )
    })?;
    if public_key.trim().is_empty() {
        return Err(format!(
            "canonical SSH public key {} is empty",
            path.display()
        ));
    }
    Ok(public_key)
}

fn resolve_create_prerequisites(
    machine: &MachineSpec,
    ssh_key_id: &str,
    firewall: Option<&ResolvedFirewallProfile>,
    cloud_init: String,
) -> Result<CreatePrerequisites, String> {
    if machine.bootstrap_profile != "singbox-host-v2" {
        return Err(format!(
            "bootstrap profile {} is not implemented by the current application layer",
            machine.bootstrap_profile
        ));
    }
    if ssh_key_id.trim().is_empty() {
        return Err("resolved Vultr SSH key id is empty".to_owned());
    }

    let (firewall_group_id, firewall_profile) =
        match (machine.provider.firewall_profile.as_deref(), firewall) {
            (None, None) => (None, None),
            (Some(expected), Some(resolved)) if resolved.profile_name == expected => (
                Some(resolved.id.clone()),
                Some(resolved.profile_name.clone()),
            ),
            (Some(expected), Some(resolved)) => {
                return Err(format!(
                    "resolved firewall profile {} does not match desired profile {expected}",
                    resolved.profile_name
                ));
            }
            (Some(expected), None) => {
                return Err(format!(
                    "machine {} requires resolved firewall profile {expected}",
                    machine.id
                ));
            }
            (None, Some(resolved)) => {
                return Err(format!(
                    "machine {} has no firewall profile but resolver supplied {}",
                    machine.id, resolved.profile_name
                ));
            }
        };

    Ok(CreatePrerequisites {
        bootstrap_profile: machine.bootstrap_profile.clone(),
        ssh_key_id: ssh_key_id.to_owned(),
        cloud_init,
        firewall_group_id,
        firewall_profile,
    })
}

fn read_base_cloud_init(machine: &MachineSpec) -> Result<String, String> {
    if machine.bootstrap_profile != "singbox-host-v2" {
        return Err(format!(
            "bootstrap profile {} is not implemented by the current application layer",
            machine.bootstrap_profile
        ));
    }
    let cloud_init_path = PathBuf::from(DEFAULT_CLOUD_INIT_PATH);
    fs::read_to_string(&cloud_init_path).map_err(|err| {
        format!(
            "failed to read bootstrap profile {} from {}: {err}",
            machine.bootstrap_profile,
            cloud_init_path.display()
        )
    })
}

fn empty_create_prerequisites(machine: &MachineSpec) -> CreatePrerequisites {
    CreatePrerequisites {
        bootstrap_profile: machine.bootstrap_profile.clone(),
        ssh_key_id: String::new(),
        cloud_init: String::new(),
        firewall_group_id: None,
        firewall_profile: None,
    }
}

fn print_json_value(value: serde_json::Value) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize lifecycle result: {err}"))?;
    println!("{json}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-orchestrator vultr-lifecycle doctor <spec-path>",
        "  edge-orchestrator vultr-lifecycle inventory <spec-path>",
        "  edge-orchestrator vultr-lifecycle plan <spec-path> [machine-id]",
        "  edge-orchestrator vultr-lifecycle apply <spec-path> <machine-id> <authorized-plan-sha256>",
        "  edge-orchestrator vultr-lifecycle substrate-plan <spec-path> <machine-id>",
        "  edge-orchestrator vultr-lifecycle substrate-apply <spec-path> <machine-id> <authorized-plan-sha256>",
        "  edge-orchestrator vultr-lifecycle substrate-verify <spec-path> <machine-id>",
        "  edge-orchestrator vultr-lifecycle transport-proof <spec-path> <machine-id> <edge-agent-artifact-path>",
        "  edge-orchestrator vultr-lifecycle runner-bootstrap <spec-path> <machine-id> <installer-path>",
        "  edge-orchestrator vultr-lifecycle acquire-access-plan <spec-path> <machine-id>",
        "  edge-orchestrator vultr-lifecycle acquire-access <spec-path> <machine-id> <authorized-plan-sha256>",
        "  edge-orchestrator vultr-lifecycle lease-acquire <spec-path> <machine-id>",
        "  edge-orchestrator vultr-lifecycle release-access-plan <spec-path> <machine-id>",
        "  edge-orchestrator vultr-lifecycle release-access <spec-path> <machine-id> <authorized-plan-sha256>",
        "  edge-orchestrator vultr-lifecycle lease-release <spec-path> <machine-id>",
        "  edge-orchestrator vultr-lifecycle action-plan <spec-path> <machine-id> <start|halt|reboot>",
        "  edge-orchestrator vultr-lifecycle action <spec-path> <machine-id> <start|halt|reboot> <authorized-plan-sha256>",
        "  edge-orchestrator vultr-lifecycle destroy-plan <spec-path> <machine-id> <source-revision>",
        "  edge-orchestrator vultr-lifecycle destroy-apply <spec-path> <machine-id> <source-revision> <destroy-digest> <authorized-plan-sha256>",
        "  edge-orchestrator vultr-lifecycle cleanup-plan <spec-path>",
        "  edge-orchestrator vultr-lifecycle cleanup <spec-path> <authorized-plan-sha256>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_boot_id_validation_is_strict() {
        assert!(validate_linux_boot_id("930df168-8e6b-4dff-ba80-3c24ed12fd86").is_ok());
        assert!(validate_linux_boot_id("").is_err());
        assert!(validate_linux_boot_id("same-boot").is_err());
        assert!(validate_linux_boot_id("930df168-8e6b-4dff-ba80-3c24ed12fd8z").is_err());
    }

    #[test]
    fn firewall_binding_must_match_desired_profile() {
        let desired = DesiredState::parse_json(
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
      "bootstrap_profile": "singbox-host-v2"
    }
  ]
}"#,
        )
        .unwrap();
        let resolved = ResolvedFirewallProfile {
            id: "fw-1".to_owned(),
            profile_name: "other".to_owned(),
        };

        let error = resolve_create_prerequisites(
            &desired.machines[0],
            "ssh-1",
            Some(&resolved),
            "#cloud-config\n".to_owned(),
        )
        .unwrap_err();
        assert!(error.contains("does not match desired profile"));
    }

    #[test]
    fn stale_support_access_authority_is_rejected_before_mutation() {
        let desired = serde_json::json!({
            "environment": "production",
            "machine_id": "edge-1",
            "operation": "ACQUIRE",
            "controller_ipv4": "203.0.113.50"
        });
        let plan = serde_json::json!({
            "action": "ACQUIRE",
            "machine_id": "edge-1",
            "firewall_profile": "edge"
        });
        let before = authorize_plan(
            "vultr_support_access",
            &desired,
            &serde_json::json!({"rules": []}),
            plan.clone(),
            PlanDisposition::Mutate,
        )
        .unwrap();
        let changed = authorize_plan(
            "vultr_support_access",
            &desired,
            &serde_json::json!({"rules": [{"id": 42, "subnet": "203.0.113.50/32"}]}),
            plan,
            PlanDisposition::Mutate,
        )
        .unwrap();

        let error = verify_exact_authority(&before.authority.authority_digest, &changed.authority)
            .unwrap_err();
        assert!(error.to_string().contains("stale"));
    }

    #[test]
    fn access_reconcile_allows_only_firewall_only_update() {
        use edge_controller_core::vultr_lifecycle::MachinePlan;

        let firewall_only = MachinePlan {
            machine_id: "edge-1".to_owned(),
            class: PlanClass::UpdateInPlace,
            provider_id: Some("provider-1".to_owned()),
            desired_spec_digest: "0".repeat(64),
            reasons: vec!["firewall profile differs or is not provider-verified".to_owned()],
        };
        assert_eq!(
            access_reconcile_class(&firewall_only),
            AccessReconcileClass::FirewallOnly
        );

        let mut mixed = firewall_only.clone();
        mixed.reasons.push("managed tags differ".to_owned());
        assert_eq!(
            access_reconcile_class(&mixed),
            AccessReconcileClass::Blocked
        );

        let mut create = firewall_only;
        create.class = PlanClass::Create;
        create.reasons = vec!["no exact owned provider resource exists".to_owned()];
        assert_eq!(
            access_reconcile_class(&create),
            AccessReconcileClass::Blocked
        );
    }

    fn operational_instance(
        power_status: &str,
        status: &str,
        server_status: &str,
    ) -> VultrInstance {
        VultrInstance {
            id: "instance-1".to_owned(),
            label: "edge-1".to_owned(),
            region: "waw".to_owned(),
            plan: "vc2-1c-1gb".to_owned(),
            status: status.to_owned(),
            server_status: server_status.to_owned(),
            power_status: power_status.to_owned(),
            main_ip: "203.0.113.10".to_owned(),
            v6_main_ip: String::new(),
            firewall_group_id: "fw-1".to_owned(),
            date_created: "2026-09-20T00:00:00Z".to_owned(),
            tags: Vec::new(),
            os_id: 2625,
            snapshot_id: None,
            enable_ipv6: false,
        }
    }

    #[test]
    fn instance_action_disposition_uses_operational_state() {
        let running = operational_instance("running", "active", "ok");
        assert_eq!(
            instance_action_disposition(InstanceAction::Start, &running),
            (PlanDisposition::Noop, "NOOP")
        );
        assert_eq!(
            instance_action_disposition(InstanceAction::Halt, &running),
            (PlanDisposition::Mutate, "HALT")
        );
        assert_eq!(
            instance_action_disposition(InstanceAction::Reboot, &running),
            (PlanDisposition::Mutate, "REBOOT")
        );

        let stopped = operational_instance("stopped", "active", "ok");
        assert_eq!(
            instance_action_disposition(InstanceAction::Start, &stopped),
            (PlanDisposition::Mutate, "START")
        );
        assert_eq!(
            instance_action_disposition(InstanceAction::Halt, &stopped),
            (PlanDisposition::Noop, "NOOP")
        );
        assert_eq!(
            instance_action_disposition(InstanceAction::Reboot, &stopped),
            (PlanDisposition::Blocked, "BLOCKED")
        );
    }

    #[test]
    fn timeout_provider_evidence_requires_exact_rule_and_attachment() {
        let target = crate::vultr_support_resources::FirewallRuleSpec {
            ip_type: "v4".to_owned(),
            protocol: "tcp".to_owned(),
            subnet: "203.0.113.25".to_owned(),
            subnet_size: 32,
            port: "22".to_owned(),
            source: String::new(),
            notes: "application acceptance controller SSH".to_owned(),
        };
        let targets = std::collections::BTreeSet::from([target.clone()]);
        let observed = VultrFirewallRule {
            id: 41,
            ip_type: target.ip_type.clone(),
            protocol: target.protocol.clone(),
            subnet: target.subnet.clone(),
            subnet_size: target.subnet_size,
            port: target.port.clone(),
            source: target.source.clone(),
            notes: target.notes.clone(),
        };

        let evidence = classify_support_access_provider_evidence(
            "203.0.113.25".to_owned(),
            Some("fw-1".to_owned()),
            &[observed],
            &targets,
            Some("fw-1".to_owned()),
            PlanDisposition::Noop,
        )
        .unwrap();

        assert_eq!(evidence.matching_rule_ids, vec![41]);
        assert!(evidence.exact_controller_rules_present_once);
        assert!(evidence.firewall_group_attached_to_machine);
        assert_eq!(evidence.acquire_plan_disposition, "NOOP");
    }

    #[test]
    fn timeout_provider_evidence_exposes_missing_rule_and_detached_group() {
        let target = crate::vultr_support_resources::FirewallRuleSpec {
            ip_type: "v4".to_owned(),
            protocol: "tcp".to_owned(),
            subnet: "203.0.113.25".to_owned(),
            subnet_size: 32,
            port: "22".to_owned(),
            source: String::new(),
            notes: "application acceptance controller SSH".to_owned(),
        };
        let targets = std::collections::BTreeSet::from([target]);

        let evidence = classify_support_access_provider_evidence(
            "203.0.113.25".to_owned(),
            Some("fw-1".to_owned()),
            &[],
            &targets,
            Some("fw-other".to_owned()),
            PlanDisposition::Mutate,
        )
        .unwrap();

        assert!(evidence.matching_rule_ids.is_empty());
        assert!(!evidence.exact_controller_rules_present_once);
        assert!(!evidence.firewall_group_attached_to_machine);
        assert_eq!(evidence.acquire_plan_disposition, "MUTATE");
    }

    #[tokio::test]
    async fn tcp_readiness_retries_probe_only_until_bounded_timeout() {
        let policy = TcpReadinessPolicy {
            max_attempts: 3,
            max_elapsed: Duration::from_secs(1),
            connect_timeout: Duration::from_millis(1),
            backoff: Duration::ZERO,
        };
        let mut calls = 0usize;
        let observation = observe_tcp_readiness_with_probe(policy, |_| {
            calls += 1;
            std::future::ready(Err(TcpReadinessFailureClass::ConnectionRefused))
        })
        .await
        .unwrap();

        assert_eq!(calls, 3);
        assert_eq!(observation.attempts, 3);
        assert_eq!(observation.final_state, TcpReadinessState::Timeout);
        assert_eq!(
            observation.last_error_class,
            Some(TcpReadinessFailureClass::ConnectionRefused)
        );
    }

    #[tokio::test]
    async fn tcp_readiness_accepts_late_network_path_before_strict_ssh() {
        let policy = TcpReadinessPolicy {
            max_attempts: 4,
            max_elapsed: Duration::from_secs(1),
            connect_timeout: Duration::from_millis(1),
            backoff: Duration::ZERO,
        };
        let mut calls = 0usize;
        let observation = observe_tcp_readiness_with_probe(policy, |_| {
            calls += 1;
            std::future::ready(if calls < 3 {
                Err(TcpReadinessFailureClass::ConnectTimeout)
            } else {
                Ok(())
            })
        })
        .await
        .unwrap();

        assert_eq!(calls, 3);
        assert_eq!(observation.attempts, 3);
        assert_eq!(observation.final_state, TcpReadinessState::Ready);
        assert_eq!(
            observation.last_error_class,
            Some(TcpReadinessFailureClass::ConnectTimeout)
        );
    }

    #[test]
    fn strict_ssh_failure_after_tcp_ready_keeps_protocol_failure_distinct() {
        let tcp = TcpReadinessObservation {
            attempts: 7,
            elapsed_ms: 1234,
            final_state: TcpReadinessState::Ready,
            last_error_class: Some(TcpReadinessFailureClass::ConnectTimeout),
        };
        let error =
            strict_ssh_error_after_tcp_ready(&tcp, "HOST_TRUST: certificate mismatch".to_owned());

        assert!(error.contains("TCP readiness passed"));
        assert!(error.contains("final_state=Ready"));
        assert!(error.contains("HOST_TRUST: certificate mismatch"));
        assert!(!error.contains("TCP readiness failed"));
    }

    #[test]
    fn runner_registration_token_validation_is_secret_safe_and_bounded() {
        assert!(validate_runner_registration_token("A".repeat(32).as_str()).is_ok());
        assert!(validate_runner_registration_token("short").is_err());
        assert!(validate_runner_registration_token("token with space").is_err());
        assert!(validate_runner_registration_token(&"x".repeat(513)).is_err());
    }

    #[test]
    fn usage_is_closed_grammar() {
        let text = usage();
        assert!(text.contains("vultr-lifecycle plan"));
        assert!(text.contains("vultr-lifecycle destroy-apply"));
        assert!(text.contains("vultr-lifecycle transport-proof"));
        assert!(text.contains("vultr-lifecycle runner-bootstrap"));
        assert!(text.contains("vultr-lifecycle acquire-access"));
        assert!(text.contains("vultr-lifecycle release-access"));
        assert!(!text.contains("exec"));
        assert!(!text.contains("shell"));
    }
}
