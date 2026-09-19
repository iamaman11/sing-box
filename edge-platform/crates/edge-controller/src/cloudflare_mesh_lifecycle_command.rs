use crate::cloudflare_mesh_lifecycle_service::{
    CloudflareMeshApiProvider, MeshExecutionPolicy, apply_mesh_once, cleanup_mesh_once,
    observe_mesh, plan_mesh_apply, plan_mesh_cleanup,
};
use edge_controller_core::cloudflare_mesh_lifecycle::DesiredMeshState;
use std::env;
use std::fs;
use std::path::Path;

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or_else(usage)?;
    match command {
        "inventory" => run_inventory(&args[1..]).await,
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "cleanup-plan" => run_cleanup_plan(&args[1..]).await,
        "cleanup-apply" => run_cleanup_apply(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_inventory(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller line3-mesh inventory <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let observed = observe_mesh(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "desired": desired,
        "observation": observed,
    }))
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller line3-mesh plan <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_mesh_apply(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller line3-mesh apply <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let report = apply_mesh_once(&mut provider, &desired, MeshExecutionPolicy::default()).await?;
    print_json(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_cleanup_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller line3-mesh cleanup-plan <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_mesh_cleanup(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
    }))
}

async fn run_cleanup_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller line3-mesh cleanup-apply <spec-path> <destructive-digest>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env(&desired)?;
    let report = cleanup_mesh_once(
        &mut provider,
        &desired,
        &args[1],
        MeshExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

fn load_desired(path: &Path) -> Result<DesiredMeshState, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Cloudflare Mesh spec {}: {err}",
            path.display()
        )
    })?;
    DesiredMeshState::parse_json(&raw).map_err(|err| err.to_string())
}

fn provider_from_env(desired: &DesiredMeshState) -> Result<CloudflareMeshApiProvider, String> {
    let api_token = env::var("CLOUDFLARE_API_TOKEN")
        .map_err(|_| "CLOUDFLARE_API_TOKEN is required".to_owned())?;
    CloudflareMeshApiProvider::new(api_token, desired.account_id.clone())
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    let output = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize Cloudflare Mesh result: {err}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-controller line3-mesh inventory <spec-path>",
        "  edge-controller line3-mesh plan <spec-path>",
        "  edge-controller line3-mesh apply <spec-path>",
        "  edge-controller line3-mesh cleanup-plan <spec-path>",
        "  edge-controller line3-mesh cleanup-apply <spec-path> <destructive-digest>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_is_closed_and_has_no_raw_provider_identity_or_token_surface() {
        let text = usage();
        assert!(text.contains("line3-mesh plan"));
        assert!(text.contains("line3-mesh cleanup-apply"));
        assert!(!text.contains("node-id"));
        assert!(!text.contains("route-id"));
        assert!(!text.contains("token"));
        assert!(!text.contains("account-id"));
        assert!(!text.contains("exec"));
        assert!(!text.contains("shell"));
    }
}
