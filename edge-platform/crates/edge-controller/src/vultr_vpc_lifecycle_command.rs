use crate::vultr_vpc_lifecycle_service::{
    VpcExecutionPolicy, VultrVpcApiProvider, apply_vpc_attachment_once, apply_vpc_once,
    cleanup_vpc_once, observe_vpc, plan_vpc, plan_vpc_attachment, plan_vpc_cleanup,
    verify_vpc_ready,
};
use edge_controller_core::vultr_vpc_lifecycle::DesiredVpcState;
use std::env;
use std::fs;
use std::path::Path;

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or_else(usage)?;
    match command {
        "inventory" => run_inventory(&args[1..]).await,
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "attachment-plan" => run_attachment_plan(&args[1..]).await,
        "attachment-apply" => run_attachment_apply(&args[1..]).await,
        "verify" => run_verify(&args[1..]).await,
        "cleanup-plan" => run_cleanup_plan(&args[1..]).await,
        "cleanup-apply" => run_cleanup_apply(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_inventory(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "inventory")?;
    let mut provider = provider_from_env()?;
    let observation = observe_vpc(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "desired": desired,
        "observation": observation,
        "mutations_performed": 0,
    }))
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "plan")?;
    let mut provider = provider_from_env()?;
    let (observation, plan) = plan_vpc(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "observation": observation,
        "plan": plan,
        "mutations_performed": 0,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "apply")?;
    let mut provider = provider_from_env()?;
    let report = apply_vpc_once(&mut provider, &desired, VpcExecutionPolicy::default()).await?;
    print_json(serde_json::to_value(report).map_err(|err| err.to_string())?)
}

async fn run_attachment_plan(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "attachment-plan")?;
    let mut provider = provider_from_env()?;
    let (target, observation, attachments, plan) =
        plan_vpc_attachment(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "target": target,
        "observation": observation,
        "attachments": attachments,
        "plan": plan,
        "mutations_performed": 0,
    }))
}

async fn run_attachment_apply(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "attachment-apply")?;
    let mut provider = provider_from_env()?;
    let report =
        apply_vpc_attachment_once(&mut provider, &desired, VpcExecutionPolicy::default()).await?;
    print_json(serde_json::to_value(report).map_err(|err| err.to_string())?)
}

async fn run_verify(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "verify")?;
    let mut provider = provider_from_env()?;
    let report = verify_vpc_ready(&mut provider, &desired).await?;
    print_json(serde_json::to_value(report).map_err(|err| err.to_string())?)
}

async fn run_cleanup_plan(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "cleanup-plan")?;
    let mut provider = provider_from_env()?;
    let (observation, attachments, plan) = plan_vpc_cleanup(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "observation": observation,
        "attachments": attachments,
        "plan": plan,
        "mutations_performed": 0,
    }))
}

async fn run_cleanup_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller vultr-vpc cleanup-apply <spec-path> <destructive-digest>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let report = cleanup_vpc_once(
        &mut provider,
        &desired,
        &args[1],
        VpcExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::to_value(report).map_err(|err| err.to_string())?)
}

fn one_spec_arg(args: &[String], command: &str) -> Result<DesiredVpcState, String> {
    if args.len() != 1 {
        return Err(format!(
            "usage: edge-controller vultr-vpc {command} <spec-path>"
        ));
    }
    load_desired(Path::new(&args[0]))
}

fn load_desired(path: &Path) -> Result<DesiredVpcState, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Vultr VPC desired state {}: {err}",
            path.display()
        )
    })?;
    DesiredVpcState::parse_json(&raw).map_err(|err| err.to_string())
}

fn provider_from_env() -> Result<VultrVpcApiProvider, String> {
    let api_key =
        env::var("VULTR_API_KEY").map_err(|_| "VULTR_API_KEY is required".to_owned())?;
    VultrVpcApiProvider::new(api_key)
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    let output = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize Vultr VPC result: {err}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-controller vultr-vpc inventory <spec-path>",
        "  edge-controller vultr-vpc plan <spec-path>",
        "  edge-controller vultr-vpc apply <spec-path>",
        "  edge-controller vultr-vpc attachment-plan <spec-path>",
        "  edge-controller vultr-vpc attachment-apply <spec-path>",
        "  edge-controller vultr-vpc verify <spec-path>",
        "  edge-controller vultr-vpc cleanup-plan <spec-path>",
        "  edge-controller vultr-vpc cleanup-apply <spec-path> <destructive-digest>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_is_closed_and_has_no_raw_provider_identity_surface() {
        let text = usage();
        assert!(text.contains("vultr-vpc attachment-apply"));
        assert!(text.contains("vultr-vpc cleanup-apply"));
        assert!(!text.contains("vpc-id"));
        assert!(!text.contains("instance-id"));
        assert!(!text.contains("subnet"));
        assert!(!text.contains("curl"));
        assert!(!text.contains("shell"));
    }
}
