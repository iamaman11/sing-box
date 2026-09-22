use crate::cloudflare_dns_lifecycle_service::{
    CloudflareDnsApiProvider, DnsExecutionPolicy, apply_dns_once, authorize_dns_apply,
    authorize_dns_cleanup, cleanup_dns_once, observe_dns, plan_dns_apply, plan_dns_cleanup,
};
use edge_controller_core::cloudflare_dns_lifecycle::DesiredDnsState;
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
        return Err("usage: edge-orchestrator cloudflare-dns inventory <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let observed = observe_dns(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "desired": desired,
        "observation": observed,
        "mutations_performed": 0,
    }))
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-orchestrator cloudflare-dns plan <spec-path> <target-ipv4>".to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let (observed, plan) = plan_dns_apply(&mut provider, &desired, &args[1]).await?;
    let authorized = authorize_dns_apply(&desired, &args[1], &observed, plan.clone())?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator cloudflare-dns apply <spec-path> <target-ipv4> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let report = apply_dns_once(
        &mut provider,
        &desired,
        &args[1],
        &args[2],
        DnsExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_cleanup_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-orchestrator cloudflare-dns cleanup-plan <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let (observed, plan) = plan_dns_cleanup(&mut provider, &desired).await?;
    let authorized = authorize_dns_cleanup(&desired, &observed, plan.clone())?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_cleanup_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-orchestrator cloudflare-dns cleanup-apply <spec-path> <destructive-digest> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let report = cleanup_dns_once(
        &mut provider,
        &desired,
        &args[1],
        &args[2],
        DnsExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

fn load_desired(path: &Path) -> Result<DesiredDnsState, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Cloudflare DNS spec {}: {err}",
            path.display()
        )
    })?;
    DesiredDnsState::parse_json(&raw).map_err(|err| err.to_string())
}

fn provider_from_env() -> Result<CloudflareDnsApiProvider, String> {
    let api_token = env::var("CLOUDFLARE_API_TOKEN")
        .map_err(|_| "CLOUDFLARE_API_TOKEN is required".to_owned())?;
    CloudflareDnsApiProvider::new(api_token)
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    let output = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize Cloudflare DNS result: {err}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-orchestrator cloudflare-dns inventory <spec-path>",
        "  edge-orchestrator cloudflare-dns plan <spec-path> <target-ipv4>",
        "  edge-orchestrator cloudflare-dns apply <spec-path> <target-ipv4> <authorized-plan-sha256>",
        "  edge-orchestrator cloudflare-dns cleanup-plan <spec-path>",
        "  edge-orchestrator cloudflare-dns cleanup-apply <spec-path> <destructive-digest> <authorized-plan-sha256>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_is_closed_and_does_not_expose_provider_ids_or_tokens() {
        let text = usage();
        assert!(text.contains("cloudflare-dns plan"));
        assert!(text.contains("cloudflare-dns cleanup-apply"));
        assert!(!text.contains("record-id"));
        assert!(!text.contains("zone-id"));
        assert!(!text.contains("token"));
        assert!(!text.contains("exec"));
        assert!(!text.contains("shell"));
    }
}
