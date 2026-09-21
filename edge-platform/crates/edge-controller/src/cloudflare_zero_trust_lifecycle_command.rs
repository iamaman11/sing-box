use crate::cloudflare_zero_trust_doctor;
use crate::cloudflare_zero_trust_lifecycle_service::{
    CloudflareZeroTrustApiProvider, ZeroTrustExecutionPolicy, ZeroTrustRuntimeInputs,
    apply_zero_trust_once, authorize_zero_trust_apply, observe_zero_trust, plan_zero_trust,
};
use edge_controller_core::cloudflare_zero_trust_lifecycle::{
    DesiredZeroTrustState, ZeroTrustAction,
};
use std::env;
use std::fs;
use std::path::Path;

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or_else(usage)?;
    match command {
        "doctor" => run_doctor(&args[1..]).await,
        "inventory" => run_inventory(&args[1..]).await,
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "verify" => run_verify(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_doctor(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err(
            "usage: edge-controller cloudflare-zero-trust doctor <guardrails-path>".to_owned(),
        );
    }
    cloudflare_zero_trust_doctor::run(Path::new(&args[0])).await
}

async fn run_inventory(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err(
            "usage: edge-controller cloudflare-zero-trust inventory <spec-path>".to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let runtime = runtime_inputs(&desired)?;
    let mut provider = provider_from_env(&desired)?;
    let observed = observe_zero_trust(&mut provider, &desired, &runtime).await?;
    print_json(serde_json::json!({
        "desired": desired,
        "runtime_authority": runtime.authority,
        "observation": observed,
    }))
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller cloudflare-zero-trust plan <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let runtime = runtime_inputs(&desired)?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_zero_trust(&mut provider, &desired, &runtime).await?;
    let authorized =
        authorize_zero_trust_apply(&desired, &runtime.authority, &observed, plan.clone())?;
    print_json(serde_json::json!({
        "observation": observed,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller cloudflare-zero-trust apply <spec-path> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let runtime = runtime_inputs(&desired)?;
    let mut provider = provider_from_env(&desired)?;
    let report = apply_zero_trust_once(
        &mut provider,
        &desired,
        &runtime,
        &args[1],
        ZeroTrustExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::json!({
        "performed": report.performed,
        "observation": report.observation,
        "next_plan": report.next_plan,
    }))
}

async fn run_verify(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: edge-controller cloudflare-zero-trust verify <spec-path>".to_owned());
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let runtime = runtime_inputs(&desired)?;
    let mut provider = provider_from_env(&desired)?;
    let (observed, plan) = plan_zero_trust(&mut provider, &desired, &runtime).await?;
    if !matches!(plan.action, ZeroTrustAction::Noop) {
        return Err(format!(
            "Cloudflare Zero Trust verify is BLOCKED; next action is {:?}",
            plan.action
        ));
    }
    print_json(serde_json::json!({
        "status": "PASS",
        "observation": observed,
        "plan": plan,
        "runtime_authority": runtime.authority,
    }))
}

fn load_desired(path: &Path) -> Result<DesiredZeroTrustState, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Cloudflare Zero Trust lifecycle spec {}: {err}",
            path.display()
        )
    })?;
    DesiredZeroTrustState::parse_json(&raw).map_err(|err| err.to_string())
}

fn runtime_inputs(desired: &DesiredZeroTrustState) -> Result<ZeroTrustRuntimeInputs, String> {
    let android_profile_id = env::var(&desired.android_profile.profile_id_env).map_err(|_| {
        format!(
            "{} is required as the external Android profile authority",
            desired.android_profile.profile_id_env
        )
    })?;
    let identity_email = env::var(&desired.gateway_allow.identity_email_env).map_err(|_| {
        format!(
            "{} is required as the external Android identity authority",
            desired.gateway_allow.identity_email_env
        )
    })?;
    let reachability_confirmed = env::var("CLOUDFLARE_ENROLLED_DEVICE_REACHABILITY_CONFIRMED")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"));
    ZeroTrustRuntimeInputs::new(android_profile_id, identity_email, reachability_confirmed)
}

fn provider_from_env(
    desired: &DesiredZeroTrustState,
) -> Result<CloudflareZeroTrustApiProvider, String> {
    let api_token = env::var("CLOUDFLARE_API_TOKEN")
        .map_err(|_| "CLOUDFLARE_API_TOKEN is required".to_owned())?;
    CloudflareZeroTrustApiProvider::new(api_token, desired.account_id.clone())
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    let output = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize Cloudflare Zero Trust result: {err}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-controller cloudflare-zero-trust doctor <guardrails-path>",
        "  edge-controller cloudflare-zero-trust inventory <spec-path>",
        "  edge-controller cloudflare-zero-trust plan <spec-path>",
        "  edge-controller cloudflare-zero-trust apply <spec-path> <authorized-plan-sha256>",
        "  edge-controller cloudflare-zero-trust verify <spec-path>",
    ]
    .join("\n")
}
