use crate::vultr_lifecycle_service::{
    ApplyReport, CreatePrerequisites, LifecycleExecutionPolicy, LifecyclePlanReport,
    VultrApiProvider, apply_machine, build_destroy_plan, destroy_machine, plan_desired_state,
};
use edge_controller_core::vultr_lifecycle::{DesiredState, MachineSpec};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_CLOUD_INIT_PATH: &str = "win/vultr-waw/cloud-init.yaml";

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or_else(usage)?;
    match command {
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "destroy-plan" => run_destroy_plan(&args[1..]).await,
        "destroy-apply" => run_destroy_apply(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    if !(args.len() == 1 || args.len() == 2) {
        return Err("usage: edge-controller vultr-lifecycle plan <spec-path> [machine-id]".to_owned());
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let report = plan_desired_state(
        &mut provider,
        &desired,
        args.get(1).map(String::as_str),
    )
    .await?;
    print_json(&report)
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("usage: edge-controller vultr-lifecycle apply <spec-path> <machine-id>".to_owned());
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == args[1])
        .ok_or_else(|| format!("machine {} is not present in desired state", args[1]))?;
    let prerequisites = resolve_create_prerequisites(machine)?;
    let mut provider = provider_from_env()?;
    let report = apply_machine(
        &mut provider,
        &desired,
        &args[1],
        &prerequisites,
        &LifecycleExecutionPolicy::default(),
    )
    .await?;
    print_json(&report)
}

async fn run_destroy_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller vultr-lifecycle destroy-plan <spec-path> <machine-id> <source-revision>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let plan = build_destroy_plan(&mut provider, &desired, &args[1], &args[2]).await?;
    print_json(&plan)
}

async fn run_destroy_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err(
            "usage: edge-controller vultr-lifecycle destroy-apply <spec-path> <machine-id> <source-revision> <destroy-digest>"
                .to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let report = destroy_machine(
        &mut provider,
        &desired,
        &args[1],
        &args[2],
        &args[3],
        &LifecycleExecutionPolicy::default(),
    )
    .await?;
    print_json(&report)
}

fn load_desired_state(path: &Path) -> Result<DesiredState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read lifecycle spec {}: {err}", path.display()))?;
    DesiredState::parse_json(&raw)
        .map_err(|err| format!("failed to parse lifecycle spec {}: {err}", path.display()))
}

fn provider_from_env() -> Result<VultrApiProvider, String> {
    let api_key =
        env::var("VULTR_API_KEY").map_err(|_| "VULTR_API_KEY is required".to_owned())?;
    VultrApiProvider::new(api_key)
}

fn resolve_create_prerequisites(machine: &MachineSpec) -> Result<CreatePrerequisites, String> {
    if let Some(profile) = machine.provider.firewall_profile.as_deref() {
        return Err(format!(
            "CREATE for machine {} declares firewall profile {}; provider-verified firewall resolution is not wired yet, so apply refuses before mutation",
            machine.id, profile
        ));
    }

    if machine.bootstrap_profile != "singbox-host-v1" {
        return Err(format!(
            "bootstrap profile {} is not implemented by the current application layer",
            machine.bootstrap_profile
        ));
    }

    let ssh_key_id = env::var("EDGE_VULTR_SSH_KEY_ID").map_err(|_| {
        "EDGE_VULTR_SSH_KEY_ID is required temporarily for CREATE until owned SSH-key discovery is wired"
            .to_owned()
    })?;
    if ssh_key_id.trim().is_empty() {
        return Err("EDGE_VULTR_SSH_KEY_ID must be non-empty".to_owned());
    }

    let cloud_init_path = env::var_os("EDGE_VULTR_CLOUD_INIT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CLOUD_INIT_PATH));
    let cloud_init = fs::read_to_string(&cloud_init_path).map_err(|err| {
        format!(
            "failed to read bootstrap profile {} from {}: {err}",
            machine.bootstrap_profile,
            cloud_init_path.display()
        )
    })?;

    Ok(CreatePrerequisites {
        bootstrap_profile: machine.bootstrap_profile.clone(),
        ssh_key_id,
        cloud_init,
        firewall_group_id: None,
        firewall_profile: None,
    })
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|err| format!("failed to serialize lifecycle result: {err}"))?;
    println!("{json}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-controller vultr-lifecycle plan <spec-path> [machine-id]",
        "  edge-controller vultr-lifecycle apply <spec-path> <machine-id>",
        "  edge-controller vultr-lifecycle destroy-plan <spec-path> <machine-id> <source-revision>",
        "  edge-controller vultr-lifecycle destroy-apply <spec-path> <machine-id> <source-revision> <destroy-digest>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_firewall_backed_create_until_provider_binding_is_verified() {
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

        let error = resolve_create_prerequisites(&desired.machines[0]).unwrap_err();
        assert!(error.contains("provider-verified firewall resolution is not wired yet"));
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
