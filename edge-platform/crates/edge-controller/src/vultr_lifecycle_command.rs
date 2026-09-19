use crate::vultr_host_bootstrap::{
    InstanceAction, VultrOperationalApiProvider, apply_instance_action, prepare_strict_bootstrap,
    rotate_host_certificate, scrub_user_data, strict_ssh_accept, wait_provider_ready,
};
use crate::vultr_lifecycle_service::{
    CreatePrerequisites, LifecycleExecutionPolicy, VultrApiProvider,
    apply_machine_with_firewall_profiles, build_destroy_plan_with_firewall_profiles,
    destroy_machine_with_firewall_profiles, plan_desired_state_with_firewall_profiles,
};
use crate::vultr_support_resources::{
    FirewallProfileSet, ResolvedFirewallProfile, VultrSupportApiProvider, ensure_firewall_profile,
    observe_verified_firewall_bindings, resolve_managed_ssh_key, validate_machine_catalog,
};
use edge_controller_core::vultr_lifecycle::{DesiredState, MachineSpec, PlanClass};
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
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "action" => run_action(&args[1..]).await,
        "destroy-plan" => run_destroy_plan(&args[1..]).await,
        "destroy-apply" => run_destroy_apply(&args[1..]).await,
        _ => Err(usage()),
    }
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
    print_json_value(serde_json::json!({
        "environment": report.environment,
        "desired_state_digest": report.desired_state_digest,
        "plans": report.plans,
        "orphaned_managed_provider_ids": report.orphaned_managed_provider_ids,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller vultr-lifecycle apply <spec-path> <machine-id>".to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
    let profiles = load_firewall_profiles(&desired)?;
    let policy = LifecycleExecutionPolicy::default();
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let mut verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;

    let preflight = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(&args[1]),
        &verified_firewalls,
    )
    .await?;

    let prerequisites = if preflight
        .plans
        .first()
        .is_some_and(|plan| plan.class == PlanClass::Create)
    {
        validate_machine_catalog(&mut support_provider, machine).await?;
        let ssh_key = resolve_managed_ssh_key(
            &mut support_provider,
            &desired.environment,
            &canonical_public_key,
            &policy,
        )
        .await?;

        let firewall = if let Some(profile_name) = machine.provider.firewall_profile.as_deref() {
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
        };

        let base_cloud_init = read_base_cloud_init(machine)?;
        let strict_bootstrap = prepare_strict_bootstrap(
            &base_cloud_init,
            &machine.id,
            &operator_private_key_path,
            &canonical_public_key,
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

    let report = apply_machine_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        &args[1],
        &prerequisites,
        &policy,
        &verified_firewalls,
    )
    .await?;

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
        60,
        std::time::Duration::from_secs(5),
    )
    .await?;

    let scrub_changed = scrub_user_data(
        &mut operational_provider,
        &report.provider_id,
        30,
        std::time::Duration::from_secs(2),
    )
    .await?;

    let rotated = report.action.as_str() == "CREATED";
    if rotated {
        rotate_host_certificate(
            &ready.main_ip,
            &machine.id,
            &operator_private_key_path,
            &canonical_public_key,
            2,
        )?;
    }

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
    }))
}

async fn run_action(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller vultr-lifecycle action <spec-path> <machine-id> <start|halt|reboot>"
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
    let plan = build_destroy_plan_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        &args[1],
        &args[2],
        &verified_firewalls,
    )
    .await?;
    let value = serde_json::to_value(&plan)
        .map_err(|err| format!("failed to serialize destroy plan: {err}"))?;
    print_json_value(value)
}

async fn run_destroy_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err(
            "usage: edge-controller vultr-lifecycle destroy-apply <spec-path> <machine-id> <source-revision> <destroy-digest>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let profiles = load_firewall_profiles(&desired)?;
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
        &LifecycleExecutionPolicy::default(),
        &verified_firewalls,
    )
    .await?;
    print_json_value(serde_json::json!({
        "machine_id": report.machine_id,
        "provider_id": report.provider_id,
        "delete_requested": report.delete_requested,
        "absence_verified": report.absence_verified,
    }))
}

fn load_desired_state(path: &Path) -> Result<DesiredState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read lifecycle spec {}: {err}", path.display()))?;
    DesiredState::parse_json(&raw)
        .map_err(|err| format!("failed to parse lifecycle spec {}: {err}", path.display()))
}

fn load_firewall_profiles(desired: &DesiredState) -> Result<Option<FirewallProfileSet>, String> {
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
    let profiles = FirewallProfileSet::parse_json(&raw)?;
    for profile_name in desired
        .machines
        .iter()
        .filter_map(|machine| machine.provider.firewall_profile.as_deref())
    {
        profiles.profile(profile_name)?;
    }
    Ok(Some(profiles))
}

async fn verified_firewall_bindings(
    provider: &mut VultrSupportApiProvider,
    desired: &DesiredState,
    profiles: Option<&FirewallProfileSet>,
) -> Result<BTreeMap<String, String>, String> {
    match profiles {
        Some(profiles) => observe_verified_firewall_bindings(provider, desired, profiles).await,
        None => Ok(BTreeMap::new()),
    }
}

fn lifecycle_provider_from_env() -> Result<VultrApiProvider, String> {
    VultrApiProvider::new(vultr_api_key_from_env()?)
}

fn support_provider_from_env() -> Result<VultrSupportApiProvider, String> {
    VultrSupportApiProvider::new(vultr_api_key_from_env()?)
}

fn operational_provider_from_env() -> Result<VultrOperationalApiProvider, String> {
    VultrOperationalApiProvider::new(vultr_api_key_from_env()?)
}

fn operator_private_key_path_from_env() -> Result<PathBuf, String> {
    let path = env::var_os("EDGE_SSH_PRIVATE_KEY_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| "EDGE_SSH_PRIVATE_KEY_PATH is required for strict SSH lifecycle apply".to_owned())?;
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

fn read_canonical_ssh_public_key() -> Result<String, String> {
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
    if machine.bootstrap_profile != "singbox-host-v1" {
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
    if machine.bootstrap_profile != "singbox-host-v1" {
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
        "  edge-controller vultr-lifecycle plan <spec-path> [machine-id]",
        "  edge-controller vultr-lifecycle apply <spec-path> <machine-id>",
        "  edge-controller vultr-lifecycle action <spec-path> <machine-id> <start|halt|reboot>",
        "  edge-controller vultr-lifecycle destroy-plan <spec-path> <machine-id> <source-revision>",
        "  edge-controller vultr-lifecycle destroy-apply <spec-path> <machine-id> <source-revision> <destroy-digest>",
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
      "bootstrap_profile": "singbox-host-v1"
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
    fn usage_is_closed_grammar() {
        let text = usage();
        assert!(text.contains("vultr-lifecycle plan"));
        assert!(text.contains("vultr-lifecycle destroy-apply"));
        assert!(!text.contains("exec"));
        assert!(!text.contains("shell"));
    }
}
