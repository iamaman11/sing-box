#[path = "vultr_access_readiness.rs"]
mod access_readiness;
use access_readiness::*;

use crate::application_lifecycle_command::{
    acceptance_stage_initial_policy, load_application_desired,
};
use crate::cloudflare_dns_lifecycle_command::acceptance_create_or_reuse as converge_initial_disposable_dns;
use crate::credential_initial_journal::verify_initial_vm_runtime_gate;
use crate::vultr_host_bootstrap::{
    HostSubstrateVersions, InstanceAction, OperationalProvider, VultrOperationalApiProvider,
    apply_instance_action, capture_ssh_transport_stage_once, prepare_strict_bootstrap,
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
    FirewallProfile, FirewallProfileSet, FirewallRuleSpec, ResolvedFirewallProfile,
    SupportResourceProvider, VultrSupportApiProvider, cleanup_environment_support_resources,
    controller_access_cleanup_projection_matches, controller_ipv4_access_specs,
    ensure_firewall_profile, ensure_persistent_firewall_profile, firewall_group_description,
    firewall_rule_spec, observe_verified_firewall_bindings, public_key_material,
    release_controller_ipv4_access, resolve_managed_ssh_key, validate_machine_catalog,
};
use edge_controller_core::application_lifecycle::{
    ApplicationBootstrapMode, DesiredApplicationState,
};
use edge_controller_core::host_substrate_lifecycle::HostSubstrateAction;
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_controller_core::orchestration::SupportAccessLeaseState;
use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_controller_core::vultr_lifecycle::{
    DesiredState, MANAGED_BY_IDENTITY, MachineSpec, ObservedMachine, PlanClass,
    decode_provider_tags, destroy_plan,
};
use edge_orchestrator::OrchestrationContext;
use edge_provider_vultr::{VultrFirewallRule, VultrInstance};
use edge_shared_types::agent_service_client::AgentServiceClient;
use edge_shared_types::{
    CANONICAL_PRODUCTION_DESIRED_STATE_BYTES, CredentialDeliverySlot, CredentialProjectionKind,
    Empty, InitialCredentialHostProbeRequest, InitialVmCredentialRuntimeRequest,
    InitialVmCredentialRuntimeResponse,
};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tonic::Request;

#[path = "vm_owner_compatibility.rs"]
mod vm_owner_compatibility;
#[path = "vm_owner_upgrade.rs"]
mod vm_owner_upgrade;

// Historical acceptance-v1 preflight still guards internal, unreachable
// old helpers. It is NOT a new CLI or VM first-use mutation authority.
fn validate_disposable_acceptance(desired: &DesiredApplicationState) -> Result<(), String> {
    if desired.environment != "application-acceptance" {
        return Err(format!(
            "application acceptance requires environment application-acceptance, got {}",
            desired.environment
        ));
    }
    if desired.machine_id != "application-acceptance-1" {
        return Err(format!(
            "application acceptance requires machine application-acceptance-1, got {}",
            desired.machine_id
        ));
    }
    if desired.bootstrap_mode != ApplicationBootstrapMode::Full {
        return Err("application acceptance requires full bootstrap mode".to_owned());
    }
    let line1 = desired
        .runtime_policy
        .line1
        .as_ref()
        .ok_or_else(|| "application acceptance requires line1 runtime policy".to_owned())?;
    if line1.acme_provider != "letsencrypt" {
        return Err(
            "disposable network acceptance requires publicly trusted Let's Encrypt ACME authority"
                .to_owned(),
        );
    }
    desired
        .runtime_policy
        .line2
        .as_ref()
        .ok_or_else(|| "application acceptance requires line2 runtime policy".to_owned())?;
    Ok(())
}

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
        "endpoint-observe" => run_endpoint_observe(&args[1..]).await,
        "transport-proof" => run_transport_proof(&args[1..], context).await,
        "initial-host-probe" => run_initial_host_probe(&args[1..], context).await,
        "initial-dns-converge" => run_initial_dns_converge(&args[1..], context).await,
        "initial-policy-stage" => run_initial_policy_stage(&args[1..], context).await,
        "initial-runtime-apply" => run_initial_vm_runtime(&args[1..], context, true).await,
        "initial-runtime-verify" => run_initial_vm_runtime(&args[1..], context, false).await,
        "runner-bootstrap" => run_runner_bootstrap(&args[1..], context).await,
        "owner-upgrade" => vm_owner_upgrade::run(&args[1..], context).await,
        "owner-rollback" => vm_owner_upgrade::rollback(&args[1..], context).await,
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

pub(crate) async fn production_converge_machine(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let value = apply_machine_value(spec_path, machine_id, None).await?;
    let action = value
        .get("action")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "production machine convergence returned no typed action".to_owned())?;
    if !matches!(action, "CREATED" | "NOOP")
        || value
            .get("provider_ready")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(format!(
            "production machine convergence returned unexpected result: {value}"
        ));
    }
    Ok(())
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

/// Reuses the existing provider ownership/NOOP resolver. A DNS response,
/// arbitrary runner IP, or operator-provided address is NOT machine identity.
async fn run_endpoint_observe(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle endpoint-observe <spec-path> <machine-id>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let actual = exact_existing_machine_observation(&desired, &args[1]).await?;
    let address = actual
        .main_ip
        .as_deref()
        .ok_or_else(|| "provider-owned machine has no observed IPv4".to_owned())?;
    let ip: std::net::Ipv4Addr = address
        .parse()
        .map_err(|_| "provider-owned machine IPv4 is malformed".to_owned())?;
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
    {
        return Err("provider-owned machine address is not a public unicast IPv4".to_owned());
    }
    print_json_value(serde_json::json!({
        "schema": "sing-box.vultr-exact-endpoint/v1",
        "machine_id": args[1],
        "public_ipv4": ip.to_string(),
        "provider_owner": "EXACT_GIT_DESIRED_NOOP"
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
    let result = build_host_substrate_authority(
        &mut provider,
        &desired,
        machine,
        &provider_id,
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        HostSubstrateExecutionPolicy::default(),
    )
    .await;
    let (observation, authorized) = match result {
        Ok(value) => value,
        Err(err) => {
            // Preserve the failure, but capture one existing native, typed,
            // read-only forensic observation before disposable cleanup.
            // Never diagnose unrelated production machines through this path.
            if is_disposable_ssh_forensic_target(&desired.environment, &args[1]) {
                let forensic =
                    acceptance_ssh_failure_forensics(Path::new(&args[0]), &args[1]).await;
                println!("disposable_ssh_failure_forensics={forensic}");
            }
            return Err(err);
        }
    };
    if authorized.plan.action != HostSubstrateAction::Noop {
        if is_disposable_ssh_forensic_target(&desired.environment, &args[1]) {
            let forensic = acceptance_ssh_failure_forensics(Path::new(&args[0]), &args[1]).await;
            println!("disposable_ssh_failure_forensics={forensic}");
        }
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

fn require_disposable_initial_probe_target(spec: &str, machine: &str) -> Result<(), String> {
    if spec != "infra/vultr/application-acceptance.json" || machine != "application-acceptance-1" {
        return Err(
            "initial host proof can only target the fixed disposable application-acceptance VM"
                .to_owned(),
        );
    }
    Ok(())
}

/// Install the existing dedicated VM Access identity into the freshly staged
/// disposable host. Host identity is not an application credential and cannot
/// authorize local secret generation; the only issuer remains Worker-v2.
/// GitHub-hosted owner sends it once over the existing strict bootstrap SSH
/// stdin. Never place the token in command arguments, logs or stack policy.
fn initial_vm_access_identity_payload(
    client_id: &str,
    client_secret: &str,
) -> Result<String, String> {
    validate_bootstrap_secret("initial VM Access client ID", client_id)?;
    validate_bootstrap_secret("initial VM Access client secret", client_secret)?;
    Ok(format!(
        "CF_ACCESS_CLIENT_ID={client_id}\nCF_ACCESS_CLIENT_SECRET={client_secret}\n"
    ))
}

/// Accept existing VM Access material only with exact bytes, root ownership,
/// root-confined directory and no link. No mutation or secret disclosure.
fn validate_initial_vm_existing_identity(
    directory_owner: &str,
    file_owner: &str,
    observed_sha256: &str,
    expected_payload: &[u8],
) -> Result<(), String> {
    if directory_owner != "0:0:700" || file_owner != "0:0:600" {
        return Err("existing VM Access identity owner/mode mismatch; no replay".to_owned());
    }
    let expected = ring::digest::digest(&ring::digest::SHA256, expected_payload);
    let expected_hex: String = expected
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    if observed_sha256 != expected_hex {
        return Err(
            "existing VM Access identity differs from authorized escrow; no replay".to_owned(),
        );
    }
    Ok(())
}

async fn install_disposable_initial_vm_access_identity(
    vultr_spec_path: &str,
    machine_id: &str,
    expected_agent_sha256: &str,
    payload: &str,
) -> Result<&'static str, String> {
    require_disposable_initial_probe_target(vultr_spec_path, machine_id)?;
    let desired = load_desired_state(Path::new(vultr_spec_path))?;
    let observed = exact_existing_machine_observation(&desired, machine_id).await?;
    let target_ip = observed.main_ip.as_deref().ok_or_else(|| {
        "initial VM Access installation requires observed disposable IPv4".to_owned()
    })?;
    let key = operator_private_key_path_from_env()?;
    let public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&key, &public_key)?;

    let agent_sha = strict_ssh_capture(
        target_ip,
        machine_id,
        &key,
        &public_key,
        "sha256sum /opt/vultr-edge-stack/bin/edge-agent | cut -d' ' -f1",
    )?;
    if agent_sha != expected_agent_sha256 {
        return Err("initial VM Access installation refuses a non-ReleaseSet agent".to_owned());
    }

    // Exact fixed file, not a caller-supplied path. An interrupted write leaves
    // evidence, so a rerun fails closed instead of replacing an unknown token.
    let presence = strict_ssh_capture(
        target_ip,
        machine_id,
        &key,
        &public_key,
        "if sudo test -e /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env || sudo test -L /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env; then echo PRESENT; else echo ABSENT; fi",
    )?;
    // Existing exact owned VM is a valid NOOP only if the stored secret bytes,
    // root ownership and directory confinement equal the host identity already
    // supplied by the authorized GitHub environment. A stale, unreadable,
    // symlinked or differently provisioned identity must NEVER be overwritten.
    let directory = strict_ssh_capture(
        target_ip,
        machine_id,
        &key,
        &public_key,
        "if sudo test -L /opt/vultr-edge-stack/runtime-secrets; then echo LINK; elif sudo test -d /opt/vultr-edge-stack/runtime-secrets; then echo PRESENT; elif sudo test -e /opt/vultr-edge-stack/runtime-secrets; then echo FOREIGN; else echo ABSENT; fi",
    )?;
    if presence == "PRESENT" {
        if directory != "PRESENT" {
            return Err("initial VM Access existing secret has unknown directory owner".to_owned());
        }
        let directory_owner = strict_ssh_capture(
            target_ip,
            machine_id,
            &key,
            &public_key,
            "sudo stat -c '%u:%g:%a' /opt/vultr-edge-stack/runtime-secrets",
        )?;
        let file_owner = strict_ssh_capture(
            target_ip,
            machine_id,
            &key,
            &public_key,
            "if sudo test -L /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env; then echo LINK; elif sudo test -f /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env; then sudo stat -c '%u:%g:%a' /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env; else echo FOREIGN; fi",
        )?;
        let observed_hash = strict_ssh_capture(
            target_ip,
            machine_id,
            &key,
            &public_key,
            "sudo sha256sum /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env | cut -d' ' -f1",
        )?;
        validate_initial_vm_existing_identity(
            &directory_owner,
            &file_owner,
            &observed_hash,
            payload.as_bytes(),
        )?;
        return Ok("REUSED_EXACT");
    }
    if presence != "ABSENT" || directory != "ABSENT" {
        return Err(
            "initial VM Access identity scope is unknown; do not replay or overwrite".to_owned(),
        );
    }
    const INSTALL: &str = "set -eu; sudo -n install -d -o root -g root -m 0700 /opt/vultr-edge-stack/runtime-secrets; sudo -n install -o root -g root -m 0600 /dev/stdin /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env";
    strict_ssh_run_stdin(
        target_ip,
        machine_id,
        &key,
        &public_key,
        INSTALL,
        payload.as_bytes(),
    )
    .map_err(|err| format!("initial VM Access write outcome uncertain; do not repeat: {err}"))?;
    let owner = strict_ssh_capture(
        target_ip,
        machine_id,
        &key,
        &public_key,
        "sudo stat -c '%u:%g:%a' /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env",
    )?;
    if owner != "0:0:600" {
        return Err("initial VM Access identity ownership is not root:root mode 0600".to_owned());
    }
    Ok("CREATED_ONCE")
}

/// Exact first-install boundary for the disposable N1 VM only. Called after
/// native Vultr creation/substrate, before initial provider publication.
async fn run_initial_policy_stage(
    args: &[String],
    context: &OrchestrationContext,
) -> Result<(), String> {
    if args.len() != 5 {
        return Err("usage: edge-orchestrator vultr-lifecycle initial-policy-stage <disposable-vultr-spec> <machine-id> <application-spec> <agent-manifest> <agent-artifact>".to_owned());
    }
    require_disposable_initial_probe_target(&args[0], &args[1])?;
    let desired = load_application_desired(Path::new(&args[2]))?;
    validate_disposable_acceptance(&desired)?;
    if desired.machine_id != args[1] || desired.vultr_spec_path != args[0] {
        return Err(
            "initial policy stage refuses mismatched provider/application target".to_owned(),
        );
    }
    let expected_agent = context.expected_application_artifact()?;
    context.validate_application_artifact(&expected_agent, Path::new(&args[4]))?;
    // Require both existing Cloudflare host identities before ANY VM write.
    // The immutable provider-approved values are injected only into this
    // GitHub-hosted lifecycle job, never into a self-hosted runner.
    let vm_client_id = env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID")
        .map_err(|_| "initial VM requires existing Cloudflare VM Access client ID".to_owned())?;
    let vm_client_secret = env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET").map_err(|_| {
        "initial VM requires existing Cloudflare VM Access client secret".to_owned()
    })?;
    let access_payload = initial_vm_access_identity_payload(&vm_client_id, &vm_client_secret)?;

    let (bundle_id, digest) = acceptance_stage_initial_policy(
        context,
        &desired,
        Path::new(&args[3]),
        Path::new(&args[4]),
    )
    .await?;
    let access_state = install_disposable_initial_vm_access_identity(
        &args[0],
        &args[1],
        &expected_agent.sha256,
        &access_payload,
    )
    .await?;
    print_json_value(serde_json::json!({
        "operation": "INITIAL_VM_POLICY_STAGE",
        "status": "PASS",
        "machine_id": args[1],
        "release_set_sha256": context.release().release_set_sha256,
        "agent_sha256": expected_agent.sha256,
        "bundle_id": bundle_id,
        "bundle_digest": digest,
        "credential_generation": "UNISSUED",
        "application_containers": "NOT_STARTED",
        "runtime_credentials": "ABSENT",
        "vm_access_identity_installed": true,
        "vm_access_identity_owner": "ROOT_0600",
        "vm_access_identity_state": access_state,
        "provider_credential_mutations": 0,
        "external_line1": "UNPROVEN",
        "external_line2": "UNPROVEN",
    }))
}

// The first install reuses the existing disposable DNS owner rather than
// adding an alternate record writer. Once the VM exists, one exact DNS
// CREATE enables ACME name validation and external TLS client probes.
// On unknown provider ACK, STOP; the canonical cleanup is a separate
// authorized action after read-only reconciliation, never mutation replay.
/// Exact native first-use DNS state: one owned CREATE, or read-only NOOP.
/// An existing nonmatching/foreign DNS record is never updated or adopted.
async fn run_initial_dns_converge(
    args: &[String],
    context: &OrchestrationContext,
) -> Result<(), String> {
    if args.len() != 2
        || args[0] != "infra/cloudflare/application-acceptance-dns.json"
        || args[1] != "infra/application/disposable-acceptance.json"
    {
        return Err("initial DNS requires exact owned disposable specs".to_owned());
    }
    context.application_release_authority()?;
    let application = load_application_desired(Path::new(&args[1]))?;
    validate_disposable_acceptance(&application)?;
    let outcome = converge_initial_disposable_dns(Path::new(&args[0]), Path::new(&args[1])).await?;
    print_json_value(serde_json::json!({
        "operation": "INITIAL_VM_DNS_CONVERGE",
        "status": "PASS",
        "outcome": outcome,
        "record": "stage2-acceptance.alegria.by",
        "environment": "application-acceptance",
        "external_tls": "UNPROVEN",
        "provider_mutations": if outcome == "CREATED" { 1 } else { 0 },
        "provider_mutation_replay_allowed": false,
    }))
}

async fn run_initial_host_probe(
    args: &[String],
    context: &OrchestrationContext,
) -> Result<(), String> {
    if args.len() != 8 {
        return Err("usage: edge-orchestrator vultr-lifecycle initial-host-probe <disposable-vultr-spec> <machine-id> <generation> <slot:a|b> <provider-intent-sha256> <release-set-sha256> <github-run-id> <agent-artifact-path>".to_owned());
    }
    require_disposable_initial_probe_target(&args[0], &args[1])?;
    let desired = load_desired_state(Path::new(&args[0]))?;
    let generation: u64 = args[2]
        .parse()
        .map_err(|_| "initial host proof needs numeric generation".to_owned())?;
    let slot = match args[3].as_str() {
        "a" => CredentialDeliverySlot::A,
        "b" => CredentialDeliverySlot::B,
        _ => return Err("initial host proof requires slot a or b".to_owned()),
    };
    let provider_intent = &args[4];
    let release_set = &args[5];
    let github_run_id: u64 = args[6]
        .parse()
        .map_err(|_| "initial host proof needs GitHub run ID".to_owned())?;
    let expected_agent = context.expected_application_artifact()?;
    context.validate_application_artifact(&expected_agent, Path::new(&args[7]))?;
    if release_set != &context.release().release_set_sha256 {
        return Err("initial host proof requires exact immutable ReleaseSet".to_owned());
    }
    if generation == 0 || github_run_id == 0 {
        return Err("initial host proof requires positive generation and run ID".to_owned());
    }
    if env::var("GITHUB_SHA").ok().as_deref() != Some(context.release().accepted_revision.as_str())
    {
        return Err("initial host proof refuses GitHub source revision drift".to_owned());
    }
    if env::var("GITHUB_RUN_ID").ok().as_deref() != Some(args[6].as_str()) {
        return Err("initial host proof refuses caller-supplied foreign GitHub run ID".to_owned());
    }
    let observed = exact_existing_machine_observation(&desired, &args[1]).await?;
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| "exact disposable VM has no observed IPv4".to_owned())?;
    let key_path = operator_private_key_path_from_env()?;
    let public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&key_path, &public_key)?;
    let remote_sha = strict_ssh_capture(
        target_ip,
        &args[1],
        &key_path,
        &public_key,
        "sha256sum /opt/vultr-edge-stack/bin/edge-agent | cut -d' ' -f1",
    )?;
    if remote_sha != expected_agent.sha256 {
        return Err("initial host proof rejects unpinned installed agent binary".to_owned());
    }
    let (port, tunnel) = start_strict_agent_tunnel(target_ip, &args[1], &key_path, &public_key)?;
    let endpoint = format!("http://127.0.0.1:{port}");
    let mut client = AgentServiceClient::connect(endpoint)
        .await
        .map_err(|err| format!("initial VM restricted AgentService connection failed: {err}"))?;
    let result = client
        .verify_initial_credential_host(Request::new(InitialCredentialHostProbeRequest {
            generation,
            slot: slot as i32,
            provider_intent_sha256: provider_intent.clone(),
            release_set_sha256: release_set.clone(),
            github_run_id,
            expected_agent_sha256: expected_agent.sha256.clone(),
        }))
        .await
        .map_err(|err| format!("initial VM native host attestation refused: {err}"))?
        .into_inner();
    drop(client);
    drop(tunnel);
    if result.projection != CredentialProjectionKind::Vm as i32
        || result.generation != generation
        || result.slot != slot as i32
        || result.github_run_id != github_run_id
        || result.agent_sha256 != expected_agent.sha256
        || !result.selected_slot_exact_dummy
        || !result.empty_host
        || !matches!(
            result.slot_a_observation.as_str(),
            "EXACT_CANONICAL_DUMMY" | "NOT_FOUND_OR_OTHER_GENERATION" | "NONCANONICAL_PAYLOAD"
        )
        || !matches!(
            result.slot_b_observation.as_str(),
            "EXACT_CANONICAL_DUMMY" | "NOT_FOUND_OR_OTHER_GENERATION" | "NONCANONICAL_PAYLOAD"
        )
        || result.exact_dummy_ab
            != (result.slot_a_observation == "EXACT_CANONICAL_DUMMY"
                && result.slot_b_observation == "EXACT_CANONICAL_DUMMY")
        || (slot == CredentialDeliverySlot::A
            && result.slot_a_observation != "EXACT_CANONICAL_DUMMY")
        || (slot == CredentialDeliverySlot::B
            && result.slot_b_observation != "EXACT_CANONICAL_DUMMY")
        || result.attestation_sha256.len() != 64
        || !result
            .attestation_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(
            "initial VM proof returned mismatched or incomplete typed guest identity".to_owned(),
        );
    }
    print_json_value(serde_json::json!({
        "operation": "CREDENTIAL_INITIAL_HOST_PROBE",
        "status": "PASS",
        "machine_id": args[1],
        "guest_ipv4": target_ip,
        "agent_sha256": result.agent_sha256,
        "release_set_sha256": release_set,
        "provider_intent_sha256": provider_intent,
        "github_run_id": github_run_id,
        "credential_generation": generation,
        "credential_slot": args[3],
        "credential_projection": "VM",
        "credential_host_attestation_sha256": result.attestation_sha256,
        "credential_slot_A": result.slot_a_observation,
        "credential_slot_B": result.slot_b_observation,
        "credential_selected_slot_exact_dummy": result.selected_slot_exact_dummy,
        "credential_peer_slot_overwrite_authorized": false,
        "credential_store_present": false,
        "credential_runtime_mutations": 0,
        "credential_provider_mutations": 0,
    }))
}

fn require_six_exact_vm_local_line2(
    response: &InitialVmCredentialRuntimeResponse,
) -> Result<(), String> {
    let expected = [
        ("http-direct", "http", 4128),
        ("socks5-direct", "socks5h", 4080),
        ("https-direct", "https", 4443),
        ("http-warp", "http", 3128),
        ("socks5-warp", "socks5h", 1080),
        ("https-warp", "https", 9443),
    ];
    if response.vm_local_line2.len() != expected.len() {
        return Err("initial VM result is missing authenticated Line2 endpoints".to_owned());
    }
    for (observed, (name, protocol, port)) in response.vm_local_line2.iter().zip(expected) {
        if observed.endpoint != name
            || observed.protocol != protocol
            || observed.port != port
            || observed.successful_samples != 5
            || observed.failed_samples != 0
            || !observed.negative_auth_rejected
        {
            return Err(format!(
                "initial VM result refuses incomplete Line2 sample for {name}"
            ));
        }
    }
    Ok(())
}

// Only the original VM runtime job can apply first-use credentials. A distinct
// post-reboot job may re-observe the same candidate, but never replay apply.
fn authorize_initial_runtime_job(job: &str, apply: bool) -> Result<(), String> {
    if (apply && job == "initial_vm_runtime")
        || (!apply && matches!(job, "initial_vm_runtime" | "initial_reboot"))
    {
        Ok(())
    } else {
        Err(
            "initial VM runtime refuses an unauthorized GitHub mutation or observation job"
                .to_owned(),
        )
    }
}

async fn run_initial_vm_runtime(
    args: &[String],
    context: &OrchestrationContext,
    apply: bool,
) -> Result<(), String> {
    if args.len() != 8 {
        return Err("usage: edge-orchestrator vultr-lifecycle initial-runtime-apply|initial-runtime-verify <disposable-spec> <machine-id> <generation> <release-set-sha256> <github-run-id> <journal-history-path> <exact-BEGIN-path> <agent-artifact-path>".to_owned());
    }
    require_disposable_initial_probe_target(&args[0], &args[1])?;
    for (key, expected) in [
        ("GITHUB_REPOSITORY", "iamaman11/sing-box"),
        ("GITHUB_REPOSITORY_ID", "1221750822"),
        ("GITHUB_ACTOR_ID", "44100369"),
        ("GITHUB_EVENT_NAME", "issue_comment"),
        ("GITHUB_RUN_ATTEMPT", "1"),
    ] {
        if env::var(key).ok().as_deref() != Some(expected) {
            return Err(format!("initial VM runtime refuses untrusted {key}"));
        }
    }
    authorize_initial_runtime_job(
        &env::var("GITHUB_JOB")
            .map_err(|_| "initial VM runtime requires GitHub job identity".to_owned())?,
        apply,
    )?;
    let generation: u64 = args[2]
        .parse()
        .map_err(|_| "initial VM runtime requires numeric generation".to_owned())?;
    let run_id: u64 = args[4]
        .parse()
        .map_err(|_| "initial VM runtime requires GitHub run ID".to_owned())?;
    if env::var("GITHUB_RUN_ID").ok().as_deref() != Some(args[4].as_str())
        || env::var("GITHUB_SHA").ok().as_deref()
            != Some(context.release().accepted_revision.as_str())
        || args[3] != context.release().release_set_sha256
    {
        return Err("initial VM runtime refuses foreign GitHub run or ReleaseSet".to_owned());
    }
    let history = fs::read_to_string(&args[5])
        .map_err(|err| format!("VM first-use BEGIN journal unreadable: {err}"))?;
    let exact_begin = fs::read_to_string(&args[6])
        .map_err(|err| format!("VM first-use exact BEGIN unreadable: {err}"))?;
    verify_initial_vm_runtime_gate(
        &history,
        &exact_begin,
        generation,
        &context.release().source_revision,
        &context.release().release_set_sha256,
        run_id,
    )?;
    let expected_agent = context.expected_application_artifact()?;
    context.validate_application_artifact(&expected_agent, Path::new(&args[7]))?;
    let desired = load_desired_state(Path::new(&args[0]))?;
    let observed = exact_existing_machine_observation(&desired, &args[1]).await?;
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| "initial VM runtime has no observed public IPv4".to_owned())?;
    let key = operator_private_key_path_from_env()?;
    let public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&key, &public_key)?;
    let remote_sha = strict_ssh_capture(
        target_ip,
        &args[1],
        &key,
        &public_key,
        "sha256sum /opt/vultr-edge-stack/bin/edge-agent | cut -d' ' -f1",
    )?;
    if remote_sha != expected_agent.sha256 {
        return Err("initial VM runtime refuses unexpected installed agent binary".to_owned());
    }
    let (port, tunnel) = start_strict_agent_tunnel(target_ip, &args[1], &key, &public_key)?;
    let mut client = AgentServiceClient::connect(format!("http://127.0.0.1:{port}"))
        .await
        .map_err(|err| format!("initial VM runtime restricted RPC unreachable: {err}"))?;
    let request = Request::new(InitialVmCredentialRuntimeRequest {
        generation,
        expected_agent_sha256: expected_agent.sha256.clone(),
        release_set_sha256: args[3].clone(),
    });
    // Never replay the mutation, even if acknowledgement disappears.
    let response = if apply {
        client.apply_initial_vm_credential(request).await
    } else {
        client.verify_initial_vm_credential(request).await
    }
    .map_err(|err| {
        format!(
            "initial VM runtime {} unresolved; do not replay: {err}",
            if apply { "apply" } else { "verify" },
        )
    })?
    .into_inner();
    drop(client);
    drop(tunnel);
    if response.projection != CredentialProjectionKind::Vm as i32
        || response.generation != generation
        || !response.candidate_unpromoted
        || !response.candidate_materialized
        || response.external_line1_proven
        || response.external_line2_proven
        || response.direct_warp_egress_distinct_proven
    {
        return Err("initial VM runtime returned invalid candidate or external proof".to_owned());
    }
    if apply && !response.vm_local_line2.is_empty() {
        return Err("initial VM apply falsely claims authenticated network samples".to_owned());
    }
    if !apply {
        require_six_exact_vm_local_line2(&response)?;
    }
    print_json_value(serde_json::json!({
        "operation": if apply { "INITIAL_VM_RUNTIME_APPLY" } else { "INITIAL_VM_RUNTIME_VERIFY" },
        "status": "PASS",
        "machine_id": args[1],
        "release_set_sha256": args[3],
        "github_run_id": run_id,
        "generation": generation,
        "candidate_unpromoted": true,
        "candidate_materialized": true,
        "vm_local_line2": response.vm_local_line2.iter().map(|endpoint| serde_json::json!({
            "name": endpoint.endpoint.as_str(),
            "protocol": endpoint.protocol.as_str(),
            "port": endpoint.port,
            "successful_samples": endpoint.successful_samples,
            "failed_samples": endpoint.failed_samples,
            "negative_auth_rejected": endpoint.negative_auth_rejected,
        })).collect::<Vec<_>>(),
        "external_line1_4_of_4": "UNPROVEN",
        "external_line2_6_of_6": "UNPROVEN",
        "distinct_direct_warp_egress": "UNPROVEN",
        "provider_mutations": 0,
        "windows_tun_mutations": 0,
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

/// The only authorized bridge after a receipt-key-only protected Git merge:
/// the EXISTING Vultr lease opens bounded SSH to the EXISTING root Agent.
/// NO provider CREATE, Docker privileges for runner or journal replay.
/// First prove and, if necessary, upgrade the exact existing native owner
/// through its bounded durable transition before enrollment and receipt proof.
pub(crate) async fn host_receipt_refresh(
    machine_id: &str,
    agent_path: &Path,
    context: &OrchestrationContext,
) -> Result<(), String> {
    if env::var("GITHUB_RUN_ATTEMPT").as_deref() != Ok("1") {
        return Err("HOST_RECEIPT_REFRESH_NO_AUTOMATIC_REPLAY".to_owned());
    }
    let git_host = context.verified_vm_first_use_host(machine_id)?;
    edge_shared_types::host_lifecycle::verify_vm_first_use_git_prerequisites(&git_host)
        .map_err(str::to_owned)?;
    edge_shared_types::host_lifecycle::verify_vm_signed_git_prerequisites(&git_host)
        .map_err(str::to_owned)?;
    let expected_key = git_host
        .native_receipt_public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let spec = Path::new(&git_host.vm_provider_spec_path);
    let desired = load_desired_state(spec)?;
    // All immutable ReleaseSet prerequisites are checked BEFORE any provider
    // support-access mutation. A later SSH failure is not an input error.
    let substrate = pinned_host_substrate_versions(context)?;
    let key_path = operator_private_key_path_from_env()?;
    let expected_ssh_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&key_path, &expected_ssh_key)?;
    // Existing means EXACT owned NOOP, not an unowned machine to adopt.
    exact_existing_machine_observation(&desired, machine_id).await?;
    acceptance_lease_acquire_with_substrate(spec, machine_id, &substrate).await?;
    let outcome = async {
        let observed = exact_existing_machine_observation(&desired, machine_id).await?;
        let ip = observed.main_ip.as_deref()
            .ok_or("HOST_RECEIPT_REFRESH_MACHINE_IPV4_UNPROVEN")?;
        let key_path = operator_private_key_path_from_env()?;
        let expected_ssh_key = read_canonical_ssh_public_key()?;
        verify_operator_key_matches(&key_path, &expected_ssh_key)?;
        let release_sha = context.release().release_set_sha256.as_str();
        if release_sha.len() != 64
            || !release_sha.bytes().all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
        {
            return Err("HOST_RECEIPT_REFRESH_RELEASE_SHA_INVALID".to_owned());
        }
        // Installed owner compatibility is a typed dependency of trust refresh.
        // The older agent MUST NOT decode a release newer than its schema.
        let owner_transition = vm_owner_compatibility::reconcile_before_enrollment(
            machine_id, context, agent_path, ip, &key_path, &expected_ssh_key,
        ).await?;
        let command = format!(
            "sudo -n /usr/local/libexec/sing-box/edge-agent local host-enroll {machine_id} {release_sha}"
        );
        let evidence = strict_ssh_capture(
            ip, machine_id, &key_path, &expected_ssh_key, &command,
        )?;
        let (public_key, registration) =
            verified_native_enrollment_result(&evidence, machine_id, release_sha)?;
        if public_key != expected_key || registration != "PINNED_GIT_MATCH" {
            return Err("HOST_RECEIPT_REFRESH_GIT_PRIVATE_IDENTITY_MISMATCH".to_owned());
        }
        println!("host_receipt_refresh=ROOT_PROTECTED_GIT_PINNED");
        println!("host_machine_id={machine_id}");
        println!("host_owner_transition={}", match owner_transition {
            vm_owner_compatibility::OwnerDecision::Upgrade => "UPGRADED_ONCE",
            vm_owner_compatibility::OwnerDecision::Current => "NOOP_EXACT_OWNER",
        });
        println!("host_mutations={}", u8::from(owner_transition == vm_owner_compatibility::OwnerDecision::Upgrade));
        Ok(())
    }.await;
    let cleanup = acceptance_lease_release(spec, machine_id).await;
    match (outcome, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(format!(
            "HOST_RECEIPT_REFRESH_ACCESS_CLEANUP_UNPROVEN: {error}"
        )),
        (Err(error), Err(cleanup)) => Err(format!(
            "{error}; HOST_RECEIPT_REFRESH_ACCESS_CLEANUP_UNPROVEN: {cleanup}"
        )),
    }
}

/// Fail-closed VM create admission: no ambiguous plan or existing owner
/// can be downgraded to a fresh CREATE by the first-use workflow.
fn admit_vm_first_use_provider_plan(
    selected: Option<&PlanClass>,
    plan_count: usize,
    prior_owned: bool,
) -> Result<(), &'static str> {
    if plan_count != 1 || !matches!(selected, Some(PlanClass::Create)) {
        return Err("HOST_FIRST_USE_PROVIDER_NOT_EXACT_CREATE_NO_REPLAY");
    }
    if prior_owned {
        return Err("HOST_FIRST_USE_PROVIDER_OWNED_VM_ALREADY_PRESENT");
    }
    Ok(())
}

/// Read-only admission before the Git receipt reservation. A previously
/// created/uncertain VM is not a fresh first-use candidate and must not
/// acquire a misleading new registration PR. Uses the existing Vultr
/// lifecycle planner and exact canonical protected Git provider spec.
pub(crate) async fn host_first_use_provider_preflight(
    machine_id: &str,
    context: &OrchestrationContext,
) -> Result<(), String> {
    let host = context.verified_vm_first_use_host(machine_id)?;
    edge_shared_types::host_lifecycle::verify_vm_first_use_git_prerequisites(&host)
        .map_err(str::to_owned)?;
    if !host.native_receipt_public_key.is_empty() {
        return Err("HOST_FIRST_USE_RECEIPT_ALREADY_REGISTERED".to_owned());
    }
    if host.vm_first_use_credential.is_none() {
        return Err("HOST_VM_FIRST_USE_CREDENTIAL_GIT_REQUIRED".to_owned());
    }
    // Preflight the same Cloudflare Access credentials used by root
    // enrollment. Missing environment secrets must not strand a draft PR
    // after the registry branch is already reserved.
    for (label, name) in [
        (
            "credential Access client id",
            "EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID",
        ),
        (
            "credential Access client secret",
            "EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET",
        ),
    ] {
        let value = env::var(name).map_err(|_| "HOST_FIRST_USE_ACCESS_IDENTITY_REQUIRED")?;
        validate_bootstrap_secret(label, &value)?;
    }
    crate::cloudflare_credential_plane_command::verify_current_vm_first_use_worker_source(&host)
        .await?;
    let provider_spec = Path::new(&host.vm_provider_spec_path);
    let desired = load_desired_state(provider_spec)?;
    if desired.machines.len() != 1 || desired.machines[0].id != machine_id {
        return Err("HOST_FIRST_USE_PROVIDER_SCOPE_NOT_SINGLE_VM".to_owned());
    }
    let profiles = load_firewall_profiles(&desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    validate_machine_catalog(&mut support_provider, &desired.machines[0]).await?;
    let bindings =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &bindings,
    )
    .await?;
    let prior_owned = report
        .inventory
        .resources
        .iter()
        .any(|resource| resource.ownership.logical_id.as_deref() == Some(machine_id));
    admit_vm_first_use_provider_plan(
        report.plans.as_slice().first().map(|plan| &plan.class),
        report.plans.len(),
        prior_owned,
    )
    .map_err(str::to_owned)?;
    println!("host_machine_id={machine_id}");
    println!("host_first_use_provider_plan=EXACT_CREATE_ONLY");
    println!("host_receipt_registration=NOT_YET_RESERVED");
    println!("host_mutations=0");
    Ok(())
}

/// One protected /host apply first-use operation using the pre-existing
/// Vultr provider, strict host substrate and Git-attested root enrollment.
/// On unknown CREATE/SSH outcome nothing is retried or adopted.
pub(crate) async fn host_first_use(
    machine_id: &str,
    installer: &Path,
    agent: &Path,
    context: &OrchestrationContext,
) -> Result<(), String> {
    if env::var("GITHUB_RUN_ATTEMPT").as_deref() != Ok("1") {
        return Err("HOST_FIRST_USE_NO_AUTOMATIC_REPLAY".to_owned());
    }
    let git_host = context.verified_vm_first_use_host(machine_id)?;
    edge_shared_types::host_lifecycle::verify_vm_first_use_git_prerequisites(&git_host)
        .map_err(str::to_owned)?;
    if !git_host.native_receipt_public_key.is_empty() {
        return Err("HOST_FIRST_USE_ALREADY_ENROLLED_USE_SIGNED_APPLY".to_owned());
    }
    if git_host.vm_first_use_credential.is_none() {
        return Err("HOST_VM_FIRST_USE_CREDENTIAL_GIT_REQUIRED".to_owned());
    }
    let provider_spec = Path::new(&git_host.vm_provider_spec_path);
    if !installer.is_file() {
        return Err("HOST_FIRST_USE_INSTALLER_MISSING".to_owned());
    }
    context.validate_application_artifact(&context.expected_application_artifact()?, agent)?;
    validate_runner_registration_token(
        &env::var("EDGE_RUNNER_REGISTRATION_TOKEN")
            .map_err(|_| "HOST_FIRST_USE_RUNNER_TOKEN_REQUIRED".to_owned())?,
    )?;
    validate_bootstrap_secret(
        "credential Access client id",
        &env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID")
            .map_err(|_| "HOST_FIRST_USE_ACCESS_CLIENT_ID_REQUIRED".to_owned())?,
    )?;
    validate_bootstrap_secret(
        "credential Access client secret",
        &env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET")
            .map_err(|_| "HOST_FIRST_USE_ACCESS_CLIENT_SECRET_REQUIRED".to_owned())?,
    )?;
    // CREATE and the support-access lease are both mutations: reject missing
    // or malformed release-pinned substrate versions before either starts.
    let substrate = pinned_host_substrate_versions(context)?;
    // The same real Cloudflare Access GET is rechecked immediately before
    // CREATE, not inferred from the earlier preflight or a Git hash alone.
    crate::cloudflare_credential_plane_command::verify_current_vm_first_use_worker_source(
        &git_host,
    )
    .await?;
    // Provider CREATE must be the exact first transition. NOOP means an
    // existing VM or an uncertain earlier response: never automatic adoption.
    acceptance_create_machine(provider_spec, machine_id).await?;
    acceptance_lease_acquire_with_substrate(provider_spec, machine_id, &substrate).await?;
    let outcome = async {
        acceptance_converge_substrate(provider_spec, machine_id).await?;
        bootstrap_production_runner(
            &load_desired_state(provider_spec)?,
            provider_spec,
            machine_id,
            installer,
            agent,
            context,
        )
        .await
    }
    .await;
    let access_release = acceptance_lease_release(provider_spec, machine_id).await;
    match (outcome, access_release) {
        (Ok(()), Ok(())) => {
            println!("host_first_use_state=AWAITING_PROTECTED_GIT_RECEIPT_REGISTRATION");
            println!("host_signed_install=NOT_YET_AUTHORIZED");
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(format!("HOST_FIRST_USE_ACCESS_CLEANUP_UNPROVEN: {error}")),
        (Err(error), Err(release_error)) => Err(format!(
            "{error}; HOST_FIRST_USE_ACCESS_CLEANUP_UNPROVEN: {release_error}"
        )),
    }
}

async fn run_runner_bootstrap(
    args: &[String],
    context: &OrchestrationContext,
) -> Result<(), String> {
    if args.len() != 4 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle runner-bootstrap <spec-path> <machine-id> <installer-path> <local-owner-artifact-path>"
                .to_owned(),
        );
    }

    let desired = load_desired_state(Path::new(&args[0]))?;
    bootstrap_production_runner(
        &desired,
        Path::new(&args[0]),
        &args[1],
        Path::new(&args[2]),
        Path::new(&args[3]),
        context,
    )
    .await
}

pub(crate) async fn bootstrap_production_runner(
    desired: &DesiredState,
    provider_spec_path: &Path,
    machine_id: &str,
    installer_path: &Path,
    local_owner_artifact: &Path,
    context: &OrchestrationContext,
) -> Result<(), String> {
    if !desired
        .machines
        .iter()
        .any(|machine| machine.id == machine_id)
    {
        return Err(format!(
            "machine {machine_id} is not present in desired state"
        ));
    }
    // Provider desired describes the VM substrate, not a second application
    // host registry. Only this exact accepted Git FleetHost can authorize
    // the fixed first-use native owner installation and root enrollment.
    let canonical_host = context.verified_vm_first_use_host(machine_id)?;
    edge_shared_types::host_lifecycle::verify_vm_first_use_provider_spec(
        &canonical_host,
        provider_spec_path
            .to_str()
            .ok_or("HOST_BOOTSTRAP_PROVIDER_SPEC_NOT_UTF8")?,
    )
    .map_err(str::to_owned)?;
    if !canonical_host.desired_spec_path.starts_with("infra/")
        || !canonical_host.desired_spec_path.ends_with(".json")
            && !canonical_host.desired_spec_path.ends_with(".textproto")
    {
        return Err("HOST_BOOTSTRAP_GIT_DESIRED_SPEC_PATH_INVALID".to_owned());
    }
    if !installer_path.is_file() {
        return Err(format!(
            "production runner installer was not found: {}",
            installer_path.display()
        ));
    }
    let expected_artifact = context.expected_application_artifact()?;
    context.validate_application_artifact(&expected_artifact, local_owner_artifact)?;

    let registration_token = env::var("EDGE_RUNNER_REGISTRATION_TOKEN")
        .map_err(|_| "EDGE_RUNNER_REGISTRATION_TOKEN is required".to_owned())?;
    validate_runner_registration_token(&registration_token)?;
    let credential_access_client_id = env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID")
        .map_err(|_| "EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID is required".to_owned())?;
    let credential_access_client_secret = env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET")
        .map_err(|_| "EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET is required".to_owned())?;
    validate_bootstrap_secret("credential Access client id", &credential_access_client_id)?;
    validate_bootstrap_secret(
        "credential Access client secret",
        &credential_access_client_secret,
    )?;

    let observed = exact_existing_machine_observation(&desired, machine_id).await?;
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| format!("exact machine {machine_id} has no observed public IPv4"))?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;

    const REMOTE_INSTALLER: &str = "/tmp/singbox-production-runner-bootstrap";
    const REMOTE_OWNER_STAGED: &str = "/tmp/singbox-production-runtime-owner";
    const LOCAL_OWNER: &str = "/usr/local/libexec/sing-box/edge-agent";
    strict_scp_upload(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        installer_path,
        REMOTE_INSTALLER,
    )?;
    strict_scp_upload(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        local_owner_artifact,
        REMOTE_OWNER_STAGED,
    )?;

    // Trusted bootstrap operator installs the one exact native owner first.
    // The GitHub runner is NOT enrolled or allowed to run host-enroll.
    // No untrusted command body, hostname or arbitrary shell is accepted here.
    // First-use bootstrap is not a backdoor upgrade path. Never replace an
    // already-installed root Agent if its digest differs: use the signed
    // lifecycle instead. A symlink, foreign owner or untrusted parent blocks.
    let observed_owner = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "if test -L /usr/local/libexec/sing-box || test -L /usr/local/libexec/sing-box/edge-agent; then echo UNPROVEN; elif test ! -e /usr/local/libexec/sing-box/edge-agent; then echo ABSENT; elif test -f /usr/local/libexec/sing-box/edge-agent && test \"$(stat -c '%u:%g:%a' /usr/local/libexec/sing-box/edge-agent)\" = 0:0:755; then sha256sum /usr/local/libexec/sing-box/edge-agent | awk '{print $1}'; else echo UNPROVEN; fi",
    )?;
    let install_required =
        admit_native_first_use_owner(&observed_owner, &expected_artifact.sha256)?;
    if install_required {
        let install_owner = format!(
            "sudo install -d -o root -g root -m 0755 /usr/local/libexec/sing-box && sudo install -o root -g root -m 0755 {REMOTE_OWNER_STAGED} {LOCAL_OWNER}"
        );
        strict_ssh_run(
            target_ip,
            machine_id,
            &operator_private_key_path,
            &canonical_public_key,
            &install_owner,
        )?;
    }
    let installed_sha = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "sha256sum /usr/local/libexec/sing-box/edge-agent | awk '{print $1}'",
    )?;
    if installed_sha != expected_artifact.sha256 {
        return Err(
            "installed local runtime owner digest does not match exact ReleaseSet".to_owned(),
        );
    }

    // Root-only first-use: the native agent independently fetches the
    // accepted immutable main ReleaseSet and its Git-pinned Worker signer,
    // generates one private receipt identity under root, then reports ONLY
    // the public key. No runner credential, sudo elevation or second owner.
    // An uncertain SSH/ACK result must not cause an automatic replay.
    let release_sha = context.release().release_set_sha256.as_str();
    if !release_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) || release_sha.len() != 64 {
        return Err("HOST_BOOTSTRAP_RELEASE_DIGEST_INVALID".to_owned());
    }
    if machine_id.is_empty()
        || machine_id.len() > 64
        || !machine_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("HOST_BOOTSTRAP_MACHINE_ID_INVALID".to_owned());
    }
    let enrollment_command =
        format!("sudo -n {LOCAL_OWNER} local host-enroll {machine_id} {release_sha}");
    let enrollment_output = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        &enrollment_command,
    )?;
    let (receipt_public_key, receipt_registration) =
        verified_native_enrollment_result(&enrollment_output, machine_id, release_sha)?;

    // Only after a root receipt identity exists may the low-privilege
    // transport runner be installed. It never receives the receipt private
    // key, Worker signer, root enrollment verb or Docker socket.
    let remote_command = format!(
        "sudo bash {REMOTE_INSTALLER} {machine_id}; rc=$?; rm -f {REMOTE_INSTALLER} {REMOTE_OWNER_STAGED}; exit $rc"
    );
    let token_stdin = format!(
        "{registration_token}\n{credential_access_client_id}\n{credential_access_client_secret}\n"
    );
    strict_ssh_run_stdin(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        &remote_command,
        token_stdin.as_bytes(),
    )?;

    let generic_root_denied = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "if sudo -u github-runner sudo -n id -u >/dev/null 2>&1; then exit 1; else echo PASS; fi",
    )?;
    if generic_root_denied != "PASS" {
        return Err("production runner generic-root denial was not proven".to_owned());
    }
    let docker_socket_denied = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "if sudo -u github-runner test -r /var/run/docker.sock 2>/dev/null; then exit 1; else echo PASS; fi",
    )?;
    if docker_socket_denied != "PASS" {
        return Err("production runner Docker-socket denial was not proven".to_owned());
    }
    let bounded_dispatch = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "sudo -u github-runner sudo -n /usr/local/libexec/sing-box/edge-agent local status >/dev/null && echo PASS",
    )?;
    if bounded_dispatch != "PASS" {
        return Err("production runner bounded local-runtime dispatch failed".to_owned());
    }
    let acceptance_rpc_disabled = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "if systemctl is-enabled edge-agent.service >/dev/null 2>&1; then exit 1; else echo PASS; fi",
    )?;
    if acceptance_rpc_disabled != "PASS" {
        return Err("production enrollment left the acceptance RPC service enabled".to_owned());
    }
    let rpc_listener_absent = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "if ss -ltnH 'sport = :50061' 2>/dev/null | grep -q .; then exit 1; else echo PASS; fi",
    )?;
    if rpc_listener_absent != "PASS" {
        return Err(
            "production enrollment left an edge-agent RPC listener on port 50061".to_owned(),
        );
    }
    let listener = strict_ssh_capture(
        target_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        "pgrep -u github-runner -f Runner.Listener >/dev/null && echo PASS",
    )?;
    if listener != "PASS" {
        return Err("self-hosted production runner listener is not active".to_owned());
    }

    // Export only the public key after ALL root enrollment, runner ACL and
    // owner-boundary checks succeeded. This is never a signed INSTALL receipt.
    let output_path =
        env::var_os("GITHUB_OUTPUT").ok_or("HOST_FIRST_USE_GITHUB_OUTPUT_REQUIRED")?;
    let output_meta = std::fs::symlink_metadata(&output_path)
        .map_err(|_| "HOST_FIRST_USE_GITHUB_OUTPUT_UNAVAILABLE")?;
    if !output_meta.file_type().is_file()
        || receipt_public_key.len() != 64
        || !receipt_public_key
            .bytes()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err("HOST_FIRST_USE_PUBLIC_RECEIPT_OUTPUT_INVALID".to_owned());
    }
    {
        let mut output = OpenOptions::new()
            .append(true)
            .open(&output_path)
            .map_err(|_| "HOST_FIRST_USE_PUBLIC_RECEIPT_OUTPUT_UNWRITABLE")?;
        writeln!(output, "receipt_public_key_hex={receipt_public_key}")
            .map_err(|_| "HOST_FIRST_USE_PUBLIC_RECEIPT_OUTPUT_WRITE_FAILED")?;
        output
            .sync_all()
            .map_err(|_| "HOST_FIRST_USE_PUBLIC_RECEIPT_OUTPUT_SYNC_FAILED")?;
    }
    println!("host_first_use_receipt_public_key_hex={receipt_public_key}");
    print_json_value(serde_json::json!({
        "status": "PASS",
        "machine_id": canonical_host.machine_id,
        "runner_name": format!("sing-box-production-{machine_id}"),
        "runner_user": "github-runner",
        "generic_root_authority": false,
        "bounded_runtime_dispatch": true,
        "docker_socket_authority": false,
        "acceptance_rpc_service_enabled": false,
        "tcp_50061_listener": false,
        "local_owner_sha256": installed_sha,
        "native_receipt_public_key_hex": receipt_public_key,
        "native_receipt_registration": receipt_registration,
        "root_enrollment": "GIT_RELEASE_ATTESTED",
        "native_application_mutations": 0,
        "listener": "PASS",
        "registration_token_persisted": false,
        "credential_access_identity_installed": true,
        "runner_credential_access": false,
    }))
}

/// Read-only admission for first-use owner installation. An installed
/// mismatching binary is never replaced over strict SSH; only the signed
/// native lifecycle may change it. Uncertain readback is a hard stop.
fn admit_native_first_use_owner(observed: &str, expected_sha: &str) -> Result<bool, String> {
    if expected_sha.len() != 64
        || !expected_sha
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("HOST_BOOTSTRAP_NATIVE_OWNER_EXPECTED_DIGEST_INVALID".to_owned());
    }
    if observed == "ABSENT" {
        return Ok(true);
    }
    if observed == expected_sha {
        return Ok(false);
    }
    Err("HOST_BOOTSTRAP_NATIVE_OWNER_DRIFT_NO_SSH_REPLACE".to_owned())
}

/// Validate ONLY the bounded public result from our already-installed root
/// Agent. Transport text never becomes enrollment authority, and uncertainty
/// never triggers another first-use mutation.
fn verified_native_enrollment_result(
    output: &str,
    machine_id: &str,
    release_sha: &str,
) -> Result<(String, String), String> {
    if output.is_empty() || output.len() > 1024 || !output.is_ascii() {
        return Err("HOST_BOOTSTRAP_ENROLLMENT_EVIDENCE_INVALID".to_owned());
    }
    let mut properties = BTreeMap::new();
    for line in output.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or("HOST_BOOTSTRAP_ENROLLMENT_EVIDENCE_INVALID")?;
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
            || !matches!(
                name,
                "host_enroll"
                    | "host_machine_id"
                    | "host_release_set_sha256"
                    | "host_native_receipt_public_key_hex"
                    | "host_native_receipt_registration"
                    | "host_worker_public_key_sha256"
                    | "host_mutations"
            )
            || properties.insert(name, value).is_some()
        {
            return Err("HOST_BOOTSTRAP_ENROLLMENT_EVIDENCE_INVALID".to_owned());
        }
    }
    if !matches!(
        properties.get("host_enroll"),
        Some(&"PROTECTED_TRUST_STAGED" | &"PROTECTED_TRUST_REFRESHED" | &"PROTECTED_TRUST_CURRENT")
    ) || properties.get("host_machine_id") != Some(&machine_id)
        || properties.get("host_release_set_sha256") != Some(&release_sha)
        || properties.get("host_mutations") != Some(&"0")
    {
        return Err("HOST_BOOTSTRAP_ENROLLMENT_IDENTITY_MISMATCH".to_owned());
    }
    let key = properties
        .get("host_native_receipt_public_key_hex")
        .ok_or("HOST_BOOTSTRAP_RECEIPT_PUBLIC_KEY_MISSING")?;
    if key.len() != 64
        || key
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        || key.bytes().all(|byte| byte == b'0')
    {
        return Err("HOST_BOOTSTRAP_RECEIPT_PUBLIC_KEY_INVALID".to_owned());
    }
    let registration = properties
        .get("host_native_receipt_registration")
        .ok_or("HOST_BOOTSTRAP_RECEIPT_REGISTRATION_MISSING")?;
    if !matches!(*registration, "AWAITING_PROTECTED_GIT" | "PINNED_GIT_MATCH") {
        return Err("HOST_BOOTSTRAP_RECEIPT_REGISTRATION_INVALID".to_owned());
    }
    Ok(((*key).to_owned(), (*registration).to_owned()))
}

fn validate_bootstrap_secret(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(format!("{label} is malformed"));
    }
    Ok(())
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

async fn run_lease_acquire(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator vultr-lifecycle lease-acquire <spec-path> <machine-id>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let substrate = host_substrate_versions_from_env()?;
    let (lease, access, observed, tcp_readiness) =
        acquire_transient_access_ready_exact(&desired, &args[1], &substrate).await?;

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

fn canonical_production_desired_state_sha256() -> String {
    ring::digest::digest(
        &ring::digest::SHA256,
        CANONICAL_PRODUCTION_DESIRED_STATE_BYTES,
    )
    .as_ref()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

fn load_access_authority_profile_source(
    desired: &DesiredState,
) -> Result<(FirewallProfileSet, serde_json::Value), String> {
    if desired.environment == "production" {
        let profiles = load_firewall_profiles_raw(desired)?.ok_or_else(|| {
            "production support-access requires the canonical protobuf-derived firewall profile"
                .to_owned()
        })?;
        return Ok((
            profiles,
            serde_json::Value::String(format!(
                "production-desired-state-sha256:{}",
                canonical_production_desired_state_sha256()
            )),
        ));
    }

    let path = Path::new(FIREWALL_PROFILES_PATH);
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read firewall profiles {}: {err}", path.display()))?;
    let profiles = FirewallProfileSet::parse_json(&raw)?;
    let material = serde_json::from_str(&raw)
        .map_err(|err| format!("invalid firewall profiles JSON: {err}"))?;
    Ok((profiles, material))
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
    let (raw_profiles, profile_material) = load_access_authority_profile_source(desired)?;
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
    Ok((
        raw_profiles,
        resolved_profiles,
        profile_material,
        controller_ipv4,
    ))
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
    let access = release_transient_access_exact(&desired, &args[1]).await?;
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
        // This is the read-only gate *before* reboot. A failed SSH
        // observation must not cause a reboot or a mutation retry.
        let boot_id_before = match observe_guest_boot_id(
            &operational.main_ip,
            &args[1],
            &operator_private_key_path,
            &canonical_public_key,
        ) {
            Ok(boot_id) => boot_id,
            Err(err) => {
                if is_disposable_ssh_forensic_target(&desired.environment, &args[1]) {
                    let forensic =
                        acceptance_ssh_failure_forensics(Path::new(&args[0]), &args[1]).await;
                    println!("disposable_reboot_preflight_forensics={forensic}");
                }
                return Err(format!(
                    "reboot rejected before provider mutation: guest boot_id SSH observation failed; {err}"
                ));
            }
        };
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

    let reboot_observation = if let Some((
        canonical_public_key,
        operator_private_key_path,
        boot_id_before,
    )) = reboot_probe
    {
        let boot_id_after = match wait_for_guest_boot_id_change(
            &operational.main_ip,
            &args[1],
            &operator_private_key_path,
            &canonical_public_key,
            &boot_id_before,
            60,
            std::time::Duration::from_secs(2),
        )
        .await
        {
            Ok(boot_id) => boot_id,
            Err(err) => {
                if is_disposable_ssh_forensic_target(&desired.environment, &args[1]) {
                    let forensic =
                        acceptance_ssh_failure_forensics(Path::new(&args[0]), &args[1]).await;
                    println!("disposable_reboot_post_observation_forensics={forensic}");
                }
                return Err(format!(
                    "reboot completion not proven after one provider mutation; no reboot replay: {err}"
                ));
            }
        };
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

fn is_disposable_ssh_forensic_target(environment: &str, machine_id: &str) -> bool {
    matches!(
        (environment, machine_id),
        ("application-acceptance", "application-acceptance-1")
            | ("lifecycle-acceptance", "lifecycle-acceptance-1")
    )
}

/// Capture read-only provider/firewall/TCP/SSH phases before the disposable
/// acceptance coordinator compensates the VM. This function never mutates or
/// retries an installation. Every diagnostic field is fixed-shape and bounded.
pub(crate) async fn acceptance_ssh_failure_forensics(
    spec_path: &Path,
    machine_id: &str,
) -> serde_json::Value {
    let unavailable = || {
        serde_json::json!({
            "schema": "acceptance-ssh-forensics/v1",
            "status": "UNAVAILABLE",
            "mutations_performed": 0,
        })
    };
    let Ok(desired) = load_desired_state(spec_path) else {
        return unavailable();
    };
    // This forensic path must never observe an unrelated production machine.
    if !is_disposable_ssh_forensic_target(&desired.environment, machine_id) {
        return unavailable();
    }
    let Ok(machine) = exact_existing_machine_observation(&desired, machine_id).await else {
        return unavailable();
    };
    let Some(target_ip) = machine.main_ip.as_deref() else {
        return unavailable();
    };

    let provider_ready = match operational_provider_from_env() {
        Ok(mut provider) => match provider.get_instance(&machine.provider_id).await {
            Ok(instance) => {
                if instance.status == "active"
                    && instance.power_status == "running"
                    && instance.server_status == "ok"
                    && instance.main_ip == target_ip
                {
                    "PASS"
                } else {
                    "FAIL"
                }
            }
            Err(_) => "UNAVAILABLE",
        },
        Err(_) => "UNAVAILABLE",
    };
    let tcp = observe_tcp_readiness(
        target_ip,
        TcpReadinessPolicy {
            max_attempts: 1,
            max_elapsed: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(3),
            backoff: Duration::ZERO,
        },
    )
    .await
    .ok();
    let (tcp_state, tcp_error) = match tcp.as_ref() {
        Some(result) => (
            match result.final_state {
                TcpReadinessState::Ready => "CONNECTED",
                TcpReadinessState::Timeout => "FAILED",
            },
            result.last_error_class.map(|kind| format!("{kind:?}")),
        ),
        None => ("UNAVAILABLE", None),
    };

    let provider_evidence = match (lifecycle_provider_from_env(), support_provider_from_env()) {
        (Ok(mut lifecycle), Ok(mut support)) => capture_support_access_provider_evidence(
            &desired,
            machine_id,
            &mut lifecycle,
            &mut support,
        )
        .await
        .ok(),
        _ => None,
    };
    let (controller_rule_once, firewall_attached, acquire_noop, runner_egress_matches) =
        match provider_evidence {
            Some(ref evidence) => (
                Some(evidence.exact_controller_rules_present_once),
                Some(evidence.firewall_group_attached_to_machine),
                Some(evidence.acquire_plan_disposition == "NOOP"),
                env::var("EDGE_CONTROLLER_IPV4")
                    .ok()
                    .map(|expected| expected == evidence.controller_ipv4),
            ),
            None => (None, None, None, None),
        };
    let ssh_phase = match (
        operator_private_key_path_from_env(),
        read_canonical_ssh_public_key(),
    ) {
        (Ok(private_key), Ok(public_key)) => {
            if verify_operator_key_matches(&private_key, &public_key).is_ok() {
                capture_ssh_transport_stage_once(target_ip, machine_id, &private_key, &public_key)
                    .unwrap_or_else(|_| "UNAVAILABLE".to_owned())
            } else {
                "UNAVAILABLE".to_owned()
            }
        }
        _ => "UNAVAILABLE".to_owned(),
    };
    serde_json::json!({
        "schema": "acceptance-ssh-forensics/v1",
        "status": "OBSERVED",
        "provider_ready": provider_ready,
        "tcp_22": tcp_state,
        "tcp_error_class": tcp_error,
        "controller_rule_once": controller_rule_once,
        "firewall_attached": firewall_attached,
        "access_plan_noop": acquire_noop,
        "runner_egress_matches": runner_egress_matches,
        "ssh_phase": ssh_phase,
        "mutations_performed": 0,
    })
}

pub(crate) async fn acceptance_lease_acquire(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let substrate = host_substrate_versions_from_env()?;
    acceptance_lease_acquire_with_substrate(spec_path, machine_id, &substrate).await
}

/// No process-global re-read: this is one already-validated substrate version
/// set passed through the whole support-access transaction.
async fn acceptance_lease_acquire_with_substrate(
    spec_path: &Path,
    machine_id: &str,
    substrate: &HostSubstrateVersions,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let (_lease, access, _observed, _tcp_readiness) =
        acquire_transient_access_ready_exact(&desired, machine_id, substrate).await?;

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
    if path == Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH) {
        return ProductionComposition::canonical()
            .map(|composition| composition.machines)
            .map_err(|err| err.to_string());
    }

    if path.starts_with("infra/hosts/specs") {
        return crate::vm_host_desired::load(path).map(|(machine, _)| machine);
    }
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

    if desired.environment == "production" {
        let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
        if desired != &production.machines {
            return Err(
                "production Vultr desired state does not match canonical ProductionDesiredState"
                    .to_owned(),
            );
        }
        let mut rules = production
            .firewall_rules
            .into_iter()
            .map(|rule| FirewallRuleSpec {
                ip_type: "v4".to_owned(),
                protocol: rule.protocol.to_owned(),
                subnet: "0.0.0.0".to_owned(),
                subnet_size: 0,
                port: rule.port.to_string(),
                source: String::new(),
                notes: rule.purpose,
            })
            .collect::<Vec<_>>();
        if production.support_controller_ssh {
            rules.push(FirewallRuleSpec {
                ip_type: "v4".to_owned(),
                protocol: "tcp".to_owned(),
                subnet: "@controller-ipv4".to_owned(),
                subnet_size: 32,
                port: "22".to_owned(),
                source: String::new(),
                notes: "transient production controller SSH lease".to_owned(),
            });
        }
        return FirewallProfileSet::single(FirewallProfile {
            name: "production".to_owned(),
            rules,
        })
        .map(Some);
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

/// Project the already-verified immutable ReleaseSet into the existing native
/// substrate type. Never accept a second runner-owned desired or env override
/// on signed Host first-use/trust paths.
fn pinned_host_substrate_versions(
    context: &OrchestrationContext,
) -> Result<HostSubstrateVersions, String> {
    let release = context.release();
    HostSubstrateVersions::new(
        release.docker_engine_version.clone(),
        release.containerd_version.clone(),
        release.compose_version.clone(),
    )
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
        "  edge-orchestrator vultr-lifecycle initial-host-probe <disposable-vultr-spec> <machine-id> <generation> <slot:a|b> <provider-intent-sha256> <release-set-sha256> <github-run-id> <edge-agent-artifact-path>",
        "  edge-orchestrator vultr-lifecycle initial-policy-stage <disposable-vultr-spec> <machine-id> <application-spec> <agent-manifest> <agent-artifact>",
        "  edge-orchestrator vultr-lifecycle initial-runtime-apply|initial-runtime-verify <disposable-vultr-spec> <machine-id> <generation> <release-set-sha256> <github-run-id> <history-path> <exact-BEGIN-path> <edge-agent-artifact-path>",
        "  edge-orchestrator vultr-lifecycle runner-bootstrap <spec-path> <machine-id> <installer-path> <local-owner-artifact-path>",
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
#[path = "vultr_lifecycle_command_tests.rs"]
mod tests;
