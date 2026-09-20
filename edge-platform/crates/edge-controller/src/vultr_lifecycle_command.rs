use crate::vultr_host_bootstrap::{
    HostSubstrateVersions, InstanceAction, VultrOperationalApiProvider, apply_instance_action,
    ensure_host_certificate_rotated, prepare_strict_bootstrap, scrub_user_data, strict_ssh_accept,
    verify_host_certificate_rotated, verify_operator_key_matches, verify_user_data_scrubbed,
    wait_provider_ready,
};
use crate::vultr_lifecycle_service::{
    ApplyAction, ApplyReport, CreatePrerequisites, LifecycleExecutionPolicy, LifecycleProvider,
    VultrApiProvider, apply_machine_with_firewall_profiles, authorize_vultr_destroy,
    authorize_vultr_machine, destroy_machine_with_firewall_profiles,
    inventory_desired_state_with_firewall_profiles, plan_desired_state_with_firewall_profiles,
};
use crate::vultr_support_resources::{
    FirewallProfileSet, ResolvedFirewallProfile, VultrSupportApiProvider,
    cleanup_environment_support_resources, ensure_firewall_profile,
    observe_verified_firewall_bindings, release_controller_ipv4_access, resolve_managed_ssh_key,
    validate_machine_catalog,
};
use edge_controller_core::lifecycle::{PlanDisposition, authorize_plan, verify_exact_authority};
use edge_controller_core::vultr_lifecycle::{
    DesiredState, MANAGED_BY_IDENTITY, MachineSpec, PlanClass, decode_provider_tags, destroy_plan,
};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_CLOUD_INIT_PATH: &str = "win/vultr-waw/cloud-init.yaml";
const CANONICAL_SSH_PUBLIC_KEY_PATH: &str = "infra/vultr/singbox-ops.pub";
const FIREWALL_PROFILES_PATH: &str = "infra/vultr/firewall-profiles.json";

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or_else(usage)?;
    match command {
        "doctor" => run_doctor(&args[1..]).await,
        "inventory" => run_inventory(&args[1..]).await,
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "acquire-access" => run_acquire_access(&args[1..]).await,
        "release-access" => run_release_access(&args[1..]).await,
        "action-plan" => run_action_plan(&args[1..]).await,
        "action" => run_action(&args[1..]).await,
        "destroy-plan" => run_destroy_plan(&args[1..]).await,
        "destroy-apply" => run_destroy_apply(&args[1..]).await,
        "cleanup" => run_cleanup(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_doctor(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller vultr-lifecycle doctor <spec-path>".to_owned());
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
        return Err("usage: edge-controller vultr-lifecycle inventory <spec-path>".to_owned());
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
            "usage: edge-controller vultr-lifecycle plan <spec-path> [machine-id]".to_owned(),
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
            "usage: edge-controller vultr-lifecycle apply <spec-path> <machine-id> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
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
        Some(&args[1]),
        &verified_firewalls,
    )
    .await?;
    let initial_plan = initial
        .plans
        .first()
        .cloned()
        .ok_or_else(|| format!("no lifecycle plan was produced for {}", args[1]))?;
    let initial_class = initial_plan.class;
    let authorized = authorize_vultr_machine(&desired, &initial.inventory, initial_plan)?;
    verify_exact_authority(&args[2], &authorized.authority).map_err(|err| err.to_string())?;

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
            let resolved = ensure_firewall_profile(
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
        Some(&args[1]),
        &verified_firewalls,
    )
    .await?;
    let after_support_plan = after_support
        .plans
        .first()
        .cloned()
        .ok_or_else(|| format!("no lifecycle plan was produced for {}", args[1]))?;
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
        verify_exact_authority(&args[2], &after_support_authorized.authority)
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
            &args[1],
            &args[2],
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

    strict_ssh_accept(
        &ready.main_ip,
        &machine.id,
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        60,
        std::time::Duration::from_secs(5),
    )
    .await?;

    let (scrub_changed, rotated) = match report.action {
        ApplyAction::Created => {
            let scrub_changed = scrub_user_data(
                &mut operational_provider,
                &report.provider_id,
                30,
                std::time::Duration::from_secs(2),
            )
            .await?;
            let rotated = ensure_host_certificate_rotated(
                &ready.main_ip,
                &machine.id,
                &operator_private_key_path,
                &canonical_public_key,
                2,
            )?;
            (scrub_changed, rotated)
        }
        ApplyAction::Noop => {
            verify_user_data_scrubbed(&mut operational_provider, &report.provider_id).await?;
            verify_host_certificate_rotated(
                &ready.main_ip,
                &machine.id,
                &operator_private_key_path,
                &canonical_public_key,
                2,
            )?;
            (false, false)
        }
    };

    print_json_value(serde_json::json!({
        "action": report.action.as_str(),
        "machine_id": report.machine_id,
        "provider_id": report.provider_id,
        "main_ip": ready.main_ip,
        "final_plan": report.final_plan,
        "strict_ssh_acceptance": "PASS",
        "user_data_scrubbed": true,
        "user_data_scrub_changed": scrub_changed,
        "host_certificate_rotated": rotated,
        "support_reconciled": support_reconciled,
    }))
}

async fn run_acquire_access(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller vultr-lifecycle acquire-access <spec-path> <machine-id>"
                .to_owned(),
        );
    }

    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
    let profile_name = machine.provider.firewall_profile.as_deref().ok_or_else(|| {
        format!(
            "machine {} has no firewall_profile; reconcile-access requires provider-owned SSH ingress",
            machine.id
        )
    })?;
    let raw_profiles = load_firewall_profiles_raw(&desired)?
        .ok_or_else(|| format!("firewall profile registry is required for {profile_name}"))?;
    let raw_profile = raw_profiles.profile(profile_name)?;
    if !raw_profile
        .rules
        .iter()
        .any(|rule| rule.subnet == "@controller-ipv4")
    {
        return Err(format!(
            "firewall profile {profile_name} has no @controller-ipv4 rule; acquire-access cannot establish an ephemeral runner lease"
        ));
    }

    let profiles = load_firewall_profiles(&desired)?
        .ok_or_else(|| format!("firewall profile registry is required for {profile_name}"))?;
    let profile = profiles.profile(profile_name)?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let mut verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, Some(&profiles)).await?;

    let initial = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(&args[1]),
        &verified_firewalls,
    )
    .await?;
    let initial_plan = initial
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {}", machine.id))?
        .clone();

    match access_reconcile_class(&initial_plan) {
        AccessReconcileClass::Noop => {
            return print_json_value(serde_json::json!({
                "action": "NOOP",
                "machine_id": machine.id,
                "provider_id": initial_plan.provider_id,
                "final_plan": initial_plan,
                "verified_firewall_bindings": verified_firewalls,
                "authority": "vultr-support-resource",
            }));
        }
        AccessReconcileClass::FirewallOnly => {}
        AccessReconcileClass::Blocked => {
            return Err(format!(
                "acquire-access refuses non-firewall lifecycle drift for machine {}: {:?}: {}",
                machine.id,
                initial_plan.class,
                initial_plan.reasons.join("; ")
            ));
        }
    }

    let resolved = ensure_firewall_profile(
        &mut support_provider,
        &desired.environment,
        profile,
        &policy,
    )
    .await?;
    verified_firewalls.insert(resolved.id.clone(), resolved.profile_name.clone());

    let final_report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(&args[1]),
        &verified_firewalls,
    )
    .await?;
    let final_plan = final_report
        .plans
        .first()
        .ok_or_else(|| {
            format!(
                "no post-access lifecycle plan was produced for {}",
                machine.id
            )
        })?
        .clone();

    if final_plan.class != PlanClass::Noop {
        return Err(format!(
            "firewall access reconciliation completed but machine {} did not converge to NOOP: {:?}: {}",
            machine.id,
            final_plan.class,
            final_plan.reasons.join("; ")
        ));
    }

    print_json_value(serde_json::json!({
        "action": "ACQUIRED",
        "machine_id": machine.id,
        "provider_id": final_plan.provider_id,
        "firewall_group_id": resolved.id,
        "firewall_profile": resolved.profile_name,
        "final_plan": final_plan,
        "authority": "vultr-support-resource",
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

async fn run_release_access(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller vultr-lifecycle release-access <spec-path> <machine-id>"
                .to_owned(),
        );
    }

    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
    let profile_name = machine.provider.firewall_profile.as_deref().ok_or_else(|| {
        format!(
            "machine {} has no firewall_profile; release-access requires provider-owned SSH ingress",
            machine.id
        )
    })?;
    let profiles = load_firewall_profiles_raw(&desired)?
        .ok_or_else(|| format!("firewall profile registry is required for {profile_name}"))?;
    let profile = profiles.profile(profile_name)?;
    let controller_ipv4 = env::var("EDGE_CONTROLLER_IPV4")
        .map_err(|_| "EDGE_CONTROLLER_IPV4 is required for release-access".to_owned())?;
    let policy = LifecycleExecutionPolicy::default();
    let mut support_provider = support_provider_from_env()?;
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

    print_json_value(serde_json::json!({
        "action": "RELEASED",
        "machine_id": machine.id,
        "firewall_profile": profile_name,
        "firewall_group_id": report.firewall_group_id,
        "removed_rule_ids": report.removed_rule_ids,
        "verified_absent": report.verified_absent,
        "authority": "vultr-support-resource",
    }))
}

async fn run_action_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller vultr-lifecycle action-plan <spec-path> <machine-id> <start|halt|reboot>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let action = InstanceAction::parse(&args[2])?;
    let profiles = load_firewall_profiles(&desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(&args[1]),
        &verified_firewalls,
    )
    .await?;
    let target = report
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {}", args[1]))?;
    if target.class != PlanClass::Noop {
        return Err(format!(
            "instance action requires exact NOOP provider identity; machine {} is {:?}: {}",
            args[1],
            target.class,
            target.reasons.join("; ")
        ));
    }
    let provider_id = target
        .provider_id
        .as_deref()
        .ok_or_else(|| "NOOP plan is missing provider id".to_owned())?;
    let desired_material = serde_json::json!({
        "desired": &desired,
        "machine_id": &args[1],
        "action": action.as_str(),
    });
    let action_plan = serde_json::json!({
        "machine_id": &args[1],
        "provider_id": provider_id,
        "action": action.as_str(),
    });
    let authorized = authorize_plan(
        "vultr_instance_action",
        &desired_material,
        &report.inventory,
        action_plan.clone(),
        PlanDisposition::Mutate,
    )
    .map_err(|err| err.to_string())?;
    print_json_value(serde_json::json!({
        "plan": action_plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_action(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err(
            "usage: edge-controller vultr-lifecycle action <spec-path> <machine-id> <start|halt|reboot> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let action = InstanceAction::parse(&args[2])?;
    let profiles = load_firewall_profiles(&desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let plan = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(&args[1]),
        &verified_firewalls,
    )
    .await?;
    let target = plan
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {}", args[1]))?;
    if target.class != PlanClass::Noop {
        return Err(format!(
            "instance action requires exact NOOP provider identity; machine {} is {:?}: {}",
            args[1],
            target.class,
            target.reasons.join("; ")
        ));
    }
    let provider_id = target
        .provider_id
        .as_deref()
        .ok_or_else(|| "NOOP plan is missing provider id".to_owned())?;
    let desired_material = serde_json::json!({
        "desired": &desired,
        "machine_id": &args[1],
        "action": action.as_str(),
    });
    let action_plan = serde_json::json!({
        "machine_id": &args[1],
        "provider_id": provider_id,
        "action": action.as_str(),
    });
    let authorized = authorize_plan(
        "vultr_instance_action",
        &desired_material,
        &plan.inventory,
        action_plan,
        PlanDisposition::Mutate,
    )
    .map_err(|err| err.to_string())?;
    verify_exact_authority(&args[3], &authorized.authority).map_err(|err| err.to_string())?;
    let mut operational_provider = operational_provider_from_env()?;
    let observed = apply_instance_action(
        &mut operational_provider,
        provider_id,
        action,
        60,
        std::time::Duration::from_secs(2),
    )
    .await?;

    print_json_value(serde_json::json!({
        "machine_id": args[1],
        "provider_id": provider_id,
        "action": action.as_str(),
        "power_status": observed.power_status,
        "status": observed.status,
        "server_status": observed.server_status,
    }))
}

async fn run_destroy_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller vultr-lifecycle destroy-plan <spec-path> <machine-id> <source-revision>"
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
            "usage: edge-controller vultr-lifecycle destroy-apply <spec-path> <machine-id> <source-revision> <destroy-digest> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let profiles = load_firewall_profiles(&desired)?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
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

    let remaining_instances =
        wait_after_destroy_inventory(&mut lifecycle_provider, &desired, &args[1], &policy).await?;
    let cleanup = cleanup_environment_support_resources(
        &mut support_provider,
        &desired,
        &remaining_instances,
        &canonical_public_key,
        &policy,
    )
    .await?;

    print_json_value(serde_json::json!({
        "machine_id": report.machine_id,
        "provider_id": report.provider_id,
        "delete_requested": report.delete_requested,
        "absence_verified": report.absence_verified,
        "support_cleanup": {
            "environment_in_use": cleanup.environment_in_use,
            "ssh_key_removed": cleanup.ssh_key_removed,
            "firewall_groups_removed": cleanup.firewall_groups_removed,
        }
    }))
}

async fn run_cleanup(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller vultr-lifecycle cleanup <spec-path>".to_owned());
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let remaining_instances = lifecycle_provider
        .list_instances()
        .await
        .map_err(|err| err.to_string())?;
    let cleanup = cleanup_environment_support_resources(
        &mut support_provider,
        &desired,
        &remaining_instances,
        &canonical_public_key,
        &policy,
    )
    .await?;
    print_json_value(serde_json::json!({
        "environment": desired.environment,
        "environment_in_use": cleanup.environment_in_use,
        "ssh_key_removed": cleanup.ssh_key_removed,
        "firewall_groups_removed": cleanup.firewall_groups_removed,
    }))
}

async fn wait_after_destroy_inventory(
    provider: &mut VultrApiProvider,
    desired: &DesiredState,
    destroyed_machine_id: &str,
    policy: &LifecycleExecutionPolicy,
) -> Result<Vec<edge_provider_vultr::VultrInstance>, String> {
    for attempt in 0..policy.destroy_reobserve_attempts {
        let instances = provider
            .list_instances()
            .await
            .map_err(|err| err.to_string())?;
        let mut stale_destroyed_target_present = false;
        let mut other_environment_instance_present = false;

        for instance in &instances {
            let decoded = decode_provider_tags(&instance.tags).map_err(|err| {
                format!(
                    "cannot reconcile post-destroy inventory because instance {} has invalid lifecycle tags: {err}",
                    instance.id
                )
            })?;
            if decoded.ownership.managed_by.as_deref() != Some(MANAGED_BY_IDENTITY)
                || decoded.ownership.environment.as_deref() != Some(desired.environment.as_str())
            {
                continue;
            }
            if decoded.ownership.logical_id.as_deref() == Some(destroyed_machine_id) {
                stale_destroyed_target_present = true;
            } else {
                other_environment_instance_present = true;
            }
        }

        if other_environment_instance_present || !stale_destroyed_target_present {
            return Ok(instances);
        }
        if attempt + 1 < policy.destroy_reobserve_attempts {
            tokio::time::sleep(policy.reobserve_delay).await;
        }
    }

    Err(format!(
        "destroyed machine {destroyed_machine_id} remained visible in provider list inventory after exact UUID absence"
    ))
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
    let Some(mut profiles) = load_firewall_profiles_raw(desired)? else {
        return Ok(None);
    };
    let profile_names = desired
        .machines
        .iter()
        .filter_map(|machine| machine.provider.firewall_profile.clone())
        .collect::<Vec<_>>();
    let controller_ipv4 = env::var("EDGE_CONTROLLER_IPV4").ok();
    profiles.resolve_controller_ipv4_for_profiles(&profile_names, controller_ipv4.as_deref())?;
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
        "  edge-controller vultr-lifecycle doctor <spec-path>",
        "  edge-controller vultr-lifecycle inventory <spec-path>",
        "  edge-controller vultr-lifecycle plan <spec-path> [machine-id]",
        "  edge-controller vultr-lifecycle apply <spec-path> <machine-id> <authorized-plan-sha256>",
        "  edge-controller vultr-lifecycle acquire-access <spec-path> <machine-id>",
        "  edge-controller vultr-lifecycle release-access <spec-path> <machine-id>",
        "  edge-controller vultr-lifecycle action-plan <spec-path> <machine-id> <start|halt|reboot>",
        "  edge-controller vultr-lifecycle action <spec-path> <machine-id> <start|halt|reboot> <authorized-plan-sha256>",
        "  edge-controller vultr-lifecycle destroy-plan <spec-path> <machine-id> <source-revision>",
        "  edge-controller vultr-lifecycle destroy-apply <spec-path> <machine-id> <source-revision> <destroy-digest> <authorized-plan-sha256>",
        "  edge-controller vultr-lifecycle cleanup <spec-path>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn usage_is_closed_grammar() {
        let text = usage();
        assert!(text.contains("vultr-lifecycle plan"));
        assert!(text.contains("vultr-lifecycle destroy-apply"));
        assert!(text.contains("vultr-lifecycle acquire-access"));
        assert!(text.contains("vultr-lifecycle release-access"));
        assert!(!text.contains("exec"));
        assert!(!text.contains("shell"));
    }
}
