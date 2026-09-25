use crate::cloudflare_dns_lifecycle_service::{
    CloudflareDnsApiProvider, DnsExecutionPolicy, apply_dns_once, authorize_dns_apply,
    authorize_dns_cleanup, cleanup_dns_once, observe_dns, plan_dns_apply, plan_dns_cleanup,
};
use crate::vultr_lifecycle_command::{
    exact_existing_machine_observation, load_desired_state as load_vultr_desired_state,
};
use edge_controller_core::application_lifecycle::DesiredApplicationState;
use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_controller_core::cloudflare_dns_lifecycle::{ApplyAction, CleanupAction, DesiredDnsState};
use edge_controller_core::orchestration::{MachineObservation, derive_dns_target};
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
            "usage: edge-orchestrator cloudflare-dns plan <spec-path> <application-spec-path>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let derived = derive_target_from_application(Path::new(&args[1])).await?;
    let mut provider = provider_from_env()?;
    let (observed, plan) = plan_dns_apply(&mut provider, &desired, &derived.target_ipv4).await?;
    let authorized = authorize_dns_apply(&desired, &derived.target_ipv4, &observed, plan.clone())?;
    print_json(serde_json::json!({
        "derived_target": derived,
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
            "usage: edge-orchestrator cloudflare-dns apply <spec-path> <application-spec-path> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let derived = derive_target_from_application(Path::new(&args[1])).await?;
    let mut provider = provider_from_env()?;
    let report = apply_dns_once(
        &mut provider,
        &desired,
        &derived.target_ipv4,
        &args[2],
        DnsExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::json!({
        "derived_target": derived,
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

pub(crate) async fn acceptance_require_clean_room(spec_path: &Path) -> Result<(), String> {
    let desired = load_desired(spec_path)?;
    let mut provider = provider_from_env()?;
    let (_observation, plan) = plan_dns_cleanup(&mut provider, &desired).await?;
    if !matches!(plan.action, CleanupAction::Noop) || plan.destructive_digest.is_some() {
        return Err(format!(
            "acceptance DNS clean room is not empty: action={:?}",
            plan.action
        ));
    }
    Ok(())
}

pub(crate) async fn production_converge(
    spec_path: &Path,
    application_spec_path: &Path,
) -> Result<(), String> {
    let desired = load_desired(spec_path)?;
    let derived = derive_target_from_application(application_spec_path).await?;
    let mut provider = provider_from_env()?;
    let (observed, plan) = plan_dns_apply(&mut provider, &desired, &derived.target_ipv4).await?;
    if matches!(plan.action, ApplyAction::Noop) {
        return Ok(());
    }
    let authorized = authorize_dns_apply(&desired, &derived.target_ipv4, &observed, plan)?;
    let report = apply_dns_once(
        &mut provider,
        &desired,
        &derived.target_ipv4,
        &authorized.authority.authority_digest,
        DnsExecutionPolicy::default(),
    )
    .await?;
    if !matches!(report.next_plan.action, ApplyAction::Noop) {
        return Err("production DNS convergence did not reach NOOP".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_create(
    spec_path: &Path,
    application_spec_path: &Path,
) -> Result<(), String> {
    let desired = load_desired(spec_path)?;
    let derived = derive_target_from_application(application_spec_path).await?;
    let mut provider = provider_from_env()?;
    let (observed, plan) = plan_dns_apply(&mut provider, &desired, &derived.target_ipv4).await?;
    if !matches!(plan.action, ApplyAction::Create { .. }) {
        return Err(format!(
            "fresh acceptance DNS must plan CREATE, got {:?}",
            plan.action
        ));
    }
    let authorized = authorize_dns_apply(&desired, &derived.target_ipv4, &observed, plan)?;
    let report = apply_dns_once(
        &mut provider,
        &desired,
        &derived.target_ipv4,
        &authorized.authority.authority_digest,
        DnsExecutionPolicy::default(),
    )
    .await?;
    if !matches!(report.next_plan.action, ApplyAction::Noop) {
        return Err("acceptance DNS create did not converge to NOOP".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_verify_noop(
    spec_path: &Path,
    application_spec_path: &Path,
) -> Result<(), String> {
    let desired = load_desired(spec_path)?;
    let derived = derive_target_from_application(application_spec_path).await?;
    let mut provider = provider_from_env()?;
    let (_observed, plan) = plan_dns_apply(&mut provider, &desired, &derived.target_ipv4).await?;
    if !matches!(plan.action, ApplyAction::Noop) {
        return Err(format!(
            "acceptance DNS expected NOOP, got {:?}",
            plan.action
        ));
    }
    Ok(())
}

pub(crate) async fn acceptance_cleanup_to_absent(spec_path: &Path) -> Result<(), String> {
    let desired = load_desired(spec_path)?;
    let mut provider = provider_from_env()?;
    let (observed, plan) = plan_dns_cleanup(&mut provider, &desired).await?;
    if matches!(plan.action, CleanupAction::Noop) {
        if plan.destructive_digest.is_some() {
            return Err("DNS NOOP cleanup plan contained destructive digest".to_owned());
        }
        return Ok(());
    }
    let destructive_digest = plan
        .destructive_digest
        .clone()
        .ok_or_else(|| "DNS cleanup mutation is missing destructive digest".to_owned())?;
    let authorized = authorize_dns_cleanup(&desired, &observed, plan)?;
    let report = cleanup_dns_once(
        &mut provider,
        &desired,
        &destructive_digest,
        &authorized.authority.authority_digest,
        DnsExecutionPolicy::default(),
    )
    .await?;
    if !matches!(report.next_plan.action, CleanupAction::Noop)
        || report.next_plan.destructive_digest.is_some()
    {
        return Err("acceptance DNS cleanup did not converge to NOOP".to_owned());
    }
    Ok(())
}

fn load_desired(path: &Path) -> Result<DesiredDnsState, String> {
    if path == Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH) {
        return ProductionComposition::canonical()
            .map(|composition| composition.dns)
            .map_err(|err| err.to_string());
    }

    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Cloudflare DNS spec {}: {err}",
            path.display()
        )
    })?;
    DesiredDnsState::parse_json(&raw).map_err(|err| err.to_string())
}

async fn derive_target_from_application(
    application_spec_path: &Path,
) -> Result<edge_controller_core::orchestration::DerivedDnsTarget, String> {
    let application =
        crate::application_lifecycle_command::load_application_desired(application_spec_path)?;
    let vultr_desired = load_vultr_desired_state(Path::new(&application.vultr_spec_path))?;
    if vultr_desired.environment != application.environment {
        return Err(format!(
            "application/Vultr environment mismatch during DNS derivation: {} != {}",
            application.environment, vultr_desired.environment
        ));
    }
    let observed =
        exact_existing_machine_observation(&vultr_desired, &application.machine_id).await?;
    let main_ipv4 = observed.main_ip.ok_or_else(|| {
        format!(
            "exact machine {} has no observed public IPv4",
            application.machine_id
        )
    })?;
    derive_dns_target(&MachineObservation {
        provider_id: observed.provider_id,
        main_ipv4,
    })
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
        "  edge-orchestrator cloudflare-dns plan <spec-path> <application-spec-path>",
        "  edge-orchestrator cloudflare-dns apply <spec-path> <application-spec-path> <authorized-plan-sha256>",
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
