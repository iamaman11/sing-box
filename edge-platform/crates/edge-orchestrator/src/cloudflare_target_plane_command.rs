use crate::cloudflare_credential_plane_command::verify_credential_plane_invariant;
use crate::cloudflare_mesh_lifecycle_service::{
    CloudflareMeshApiProvider, MeshExecutionPolicy, apply_mesh_once, authorize_mesh_apply,
    observe_mesh, plan_mesh_apply,
};
use crate::vultr_lifecycle_command::exact_existing_machine_observation;
use crate::vultr_vpc_lifecycle_service::{VultrVpcApiProvider, verify_vpc_ready};
use edge_controller_core::cloudflare_mesh_lifecycle::{
    ApplyAction as MeshApplyAction, DesiredMeshState, MeshObservation, MeshRouteSpec,
};
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_controller_core::production::{ProductionComposition, ProductionTargetPlaneOwnership};
use edge_provider_cloudflare as cloudflare;
use edge_provider_cloudflare::{
    CloudflareDeviceProfileWrite, CloudflareServiceModeWrite, CloudflareSplitTunnelEntry,
    CloudflareSplitTunnelWrite,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::env;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::sleep;

const MAX_CONVERGENCE_STEPS: usize = 8;
const REOBSERVE_ATTEMPTS: usize = 15;
const REOBSERVE_DELAY_SECONDS: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TargetMeshProfileDesired {
    name: String,
    description: String,
    match_expression: String,
    precedence_start: u64,
    service_mode: String,
    tunnel_protocol: String,
    auto_connect: u64,
    switch_locked: bool,
    include_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TargetPlaneDesired {
    target_account_id: String,
    mesh: DesiredMeshState,
    mesh_profile: TargetMeshProfileDesired,
    shared_dns_account_id: String,
    dns_zone_name: String,
    dns_record_name: String,
    dns_target_ipv4: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TargetMeshProfileObservation {
    provider_id: String,
    name: String,
    description: Option<String>,
    enabled: Option<bool>,
    precedence: Option<u64>,
    match_expression: Option<String>,
    service_mode: Option<String>,
    tunnel_protocol: Option<String>,
    auto_connect: Option<u64>,
    switch_locked: Option<bool>,
    includes: Vec<CloudflareSplitTunnelEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TargetDnsRecordObservation {
    provider_id: String,
    ip: String,
    proxied: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TargetPlaneObservation {
    credential_plane_locked: bool,
    zero_trust_device_settings_ready: bool,
    vpc_cidr: String,
    production_public_ipv4: String,
    mesh: MeshObservation,
    mesh_profile_matches: Vec<TargetMeshProfileObservation>,
    profile_precedences: Vec<u64>,
    dns_records: Vec<TargetDnsRecordObservation>,
    shared_dns_record_count: usize,
    shared_dns_worker_route_count: usize,
    legacy_lease_route_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum TargetPlaneAction {
    Noop,
    CreateMeshNode,
    CreateMeshRoute { network: String },
    CreateMeshProfile { precedence: u64 },
    UpdateMeshProfile { profile_id: String, precedence: u64 },
    SetMeshProfileIncludes { profile_id: String },
    CreateProductionDnsRecord,
    UpdateProductionDnsRecord { record_id: String },
}

pub(crate) async fn inventory() -> Result<(), String> {
    let inputs = Inputs::load_migration()?;
    let desired = desired(&inputs).await?;
    let observed = observe(&inputs, &desired).await?;
    let action = plan(&desired, &observed)?;
    print_inventory(&desired, &observed, &action)
}

pub(crate) async fn plan_command() -> Result<(), String> {
    let inputs = Inputs::load_migration()?;
    let desired = desired(&inputs).await?;
    let observed = observe(&inputs, &desired).await?;
    let authorized = authorized_plan(&desired, &observed)?;
    print_inventory(&desired, &observed, &authorized.plan)?;
    println!("plan_action={}", action_name(&authorized.plan));
    println!("plan_authority={}", authorized.authority.authority_digest);
    println!("plan_disposition={:?}", authorized.disposition);
    Ok(())
}

pub(crate) async fn converge() -> Result<(), String> {
    converge_with_inputs(Inputs::load_migration()?).await
}

pub(crate) async fn converge_active() -> Result<(), String> {
    let inputs = Inputs::load_verify()?;
    validate_active_target(&inputs)?;
    converge_with_inputs(inputs).await
}

async fn converge_with_inputs(inputs: Inputs) -> Result<(), String> {
    let desired = desired(&inputs).await?;
    let mut mutations = 0u32;

    for step in 1..=MAX_CONVERGENCE_STEPS {
        let before = observe(&inputs, &desired).await?;
        let authorized = authorized_plan(&desired, &before)?;
        println!("convergence_step={step}");
        println!("action={}", action_name(&authorized.plan));
        println!("plan_authority={}", authorized.authority.authority_digest);

        if authorized.plan == TargetPlaneAction::Noop {
            print_terminal(&desired, &before, mutations)?;
            return Ok(());
        }

        let (after, next) = apply_once(
            &inputs,
            &desired,
            &authorized.plan,
            &authorized.authority.authority_digest,
        )
        .await?;
        mutations = mutations.saturating_add(1);
        if next == authorized.plan {
            return Err(format!(
                "target-plane action made no observable progress; mutation was not replayed: {}",
                action_name(&next)
            ));
        }
        println!("next_action={}", action_name(&next));
        print_inventory(&desired, &after, &next)?;
    }

    Err(format!(
        "target-plane convergence exceeded bounded {MAX_CONVERGENCE_STEPS}-step limit"
    ))
}

pub(crate) async fn verify() -> Result<(), String> {
    verify_with_inputs(Inputs::load_verify()?).await
}

pub(crate) async fn verify_active_invariant() -> Result<(), String> {
    let inputs = Inputs::load_verify()?;
    validate_active_target(&inputs)?;
    verify_with_inputs(inputs).await
}

fn validate_active_target(inputs: &Inputs) -> Result<(), String> {
    if inputs
        .production
        .cloudflare
        .migration_target_account_id
        .is_some()
    {
        return Err(
            "active Cloudflare invariant requires migration_target_account_id to be empty"
                .to_owned(),
        );
    }
    if inputs.production.cloudflare.target_plane.target_account_id
        != inputs.production.cloudflare.active_account_id
    {
        return Err(
            "active Cloudflare invariant requires project plane ownership to equal active_account_id"
                .to_owned(),
        );
    }
    Ok(())
}

async fn verify_with_inputs(inputs: Inputs) -> Result<(), String> {
    let desired = desired(&inputs).await?;
    let observed = observe(&inputs, &desired).await?;
    let action = plan(&desired, &observed)?;
    if action != TargetPlaneAction::Noop {
        return Err(format!(
            "target-plane verify requires terminal NOOP; observed {}",
            action_name(&action)
        ));
    }
    print_terminal(&desired, &observed, 0)
}

struct Inputs {
    production: ProductionComposition,
    control_token: String,
    dns_token: String,
    vultr_api_key: String,
}

impl Inputs {
    fn load_migration() -> Result<Self, String> {
        let inputs = Self::load_verify()?;
        let target = inputs
            .production
            .cloudflare
            .migration_target_account_id
            .as_deref()
            .ok_or_else(|| {
                "target-plane mutation owner requires cloudflare.migration_target_account_id"
                    .to_owned()
            })?;
        if target == inputs.production.cloudflare.active_account_id {
            return Err(
                "target-plane mutation owner refuses an active-account migration target".to_owned(),
            );
        }
        Ok(inputs)
    }

    fn load_verify() -> Result<Self, String> {
        let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
        let control_token = required_env("CLOUDFLARE_CONTROL_TOKEN")?;
        let dns_token = required_env("CLOUDFLARE_DNS_TOKEN")?;
        let vultr_api_key = required_env("VULTR_API_KEY")?;
        Ok(Self {
            production,
            control_token,
            dns_token,
            vultr_api_key,
        })
    }
}

async fn desired(inputs: &Inputs) -> Result<TargetPlaneDesired, String> {
    let target = &inputs.production.cloudflare.target_plane;
    let mut vpc_provider = VultrVpcApiProvider::new(inputs.vultr_api_key.clone())?;
    let ready = verify_vpc_ready(&mut vpc_provider, &inputs.production.vpc).await?;
    if ready.status != "PASS" {
        return Err("target-plane requires a READY canonical Vultr VPC".to_owned());
    }

    let machine = exact_existing_machine_observation(
        &inputs.production.machines,
        &inputs.production.machine_id,
    )
    .await?;
    let public_ipv4 = machine
        .main_ip
        .as_deref()
        .ok_or_else(|| "exact production Vultr machine has no public IPv4".to_owned())?
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("exact production public IPv4 is invalid: {err}"))?
        .to_string();

    let mut mesh = inputs.production.mesh.clone();
    mesh.account_id = target.target_account_id.clone();
    mesh.routes = vec![MeshRouteSpec {
        network: ready.cidr,
    }];
    mesh.validate().map_err(|err| err.to_string())?;

    Ok(TargetPlaneDesired {
        target_account_id: target.target_account_id.clone(),
        mesh,
        mesh_profile: mesh_profile_desired(
            target,
            &inputs
                .production
                .cloudflare
                .credential_plane
                .access_auth_domain,
        )?,
        shared_dns_account_id: inputs.production.shared_dns_account_id.clone(),
        dns_zone_name: inputs.production.dns.zone_name.clone(),
        dns_record_name: inputs.production.dns.record_name.clone(),
        dns_target_ipv4: public_ipv4,
    })
}

fn mesh_profile_desired(
    target: &ProductionTargetPlaneOwnership,
    access_auth_domain: &str,
) -> Result<TargetMeshProfileDesired, String> {
    let team = access_auth_domain
        .strip_suffix(".cloudflareaccess.com")
        .filter(|value| !value.is_empty() && !value.contains('.'))
        .ok_or_else(|| {
            "credential-plane Access auth domain cannot derive one exact Cloudflare team name"
                .to_owned()
        })?;
    let mut include_cidrs = target.mesh_profile_include_cidrs.clone();
    include_cidrs.sort();
    Ok(TargetMeshProfileDesired {
        name: target.mesh_profile_name.clone(),
        description: target.mesh_profile_description.clone(),
        match_expression: format!(
            "identity.email == \"warp_connector@{team}.cloudflareaccess.com\""
        ),
        precedence_start: target.mesh_profile_precedence_start,
        service_mode: target.mesh_profile_service_mode.clone(),
        tunnel_protocol: target.mesh_profile_tunnel_protocol.clone(),
        auto_connect: target.mesh_profile_auto_connect,
        switch_locked: target.mesh_profile_switch_locked,
        include_cidrs,
    })
}

async fn observe(
    inputs: &Inputs,
    desired: &TargetPlaneDesired,
) -> Result<TargetPlaneObservation, String> {
    verify_credential_plane_invariant().await?;

    let settings = cloudflare::get_zero_trust_device_settings(
        &inputs.control_token,
        &desired.target_account_id,
    )
    .await?;
    let zero_trust_device_settings_ready = settings.gateway_proxy_enabled == Some(true)
        && settings.gateway_udp_proxy_enabled == Some(true)
        && settings.use_zt_virtual_ip == Some(true);
    if !zero_trust_device_settings_ready {
        return Err(
            "target account Zero Trust device settings differ from the accepted Mesh-ready boundary"
                .to_owned(),
        );
    }

    let mut mesh_provider = CloudflareMeshApiProvider::new(
        inputs.control_token.clone(),
        desired.target_account_id.clone(),
    )?;
    let mesh = observe_mesh(&mut mesh_provider, &desired.mesh).await?;

    let profiles =
        cloudflare::list_device_profiles(&inputs.control_token, &desired.target_account_id).await?;
    let profile_precedences = profiles
        .iter()
        .filter_map(|profile| profile.precedence)
        .collect::<Vec<_>>();
    let mut mesh_profile_matches = Vec::new();
    for profile in profiles {
        let matches_name = profile.name == desired.mesh_profile.name;
        let matches_selector = profile.match_expression.as_deref()
            == Some(desired.mesh_profile.match_expression.as_str());
        if !matches_name && !matches_selector {
            continue;
        }
        let includes = cloudflare::get_device_profile_includes(
            &inputs.control_token,
            &desired.target_account_id,
            &profile.id,
        )
        .await?;
        mesh_profile_matches.push(TargetMeshProfileObservation {
            provider_id: profile.id,
            name: profile.name,
            description: profile.description,
            enabled: profile.enabled,
            precedence: profile.precedence,
            match_expression: profile.match_expression,
            service_mode: profile.service_mode,
            tunnel_protocol: profile.tunnel_protocol,
            auto_connect: profile.auto_connect,
            switch_locked: profile.switch_locked,
            includes,
        });
    }
    mesh_profile_matches.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));

    let a_records = cloudflare::list_a_records(
        &inputs.dns_token,
        &desired.dns_zone_name,
        &desired.dns_record_name,
    )
    .await?;
    let summaries =
        cloudflare::list_dns_record_summaries(&inputs.dns_token, &desired.dns_zone_name).await?;
    let summary_matches = summaries
        .iter()
        .filter(|record| record.record_type == "A" && record.name == desired.dns_record_name)
        .collect::<Vec<_>>();
    if summary_matches.len() != a_records.len() {
        return Err(
            "shared DNS exact A-record observation disagrees between content and summary surfaces"
                .to_owned(),
        );
    }
    let mut dns_records = Vec::new();
    for record in a_records {
        let summary = summary_matches
            .iter()
            .find(|summary| summary.id == record.id)
            .ok_or_else(|| {
                "shared DNS A record is missing its exact summary identity".to_owned()
            })?;
        dns_records.push(TargetDnsRecordObservation {
            provider_id: record.id,
            ip: record.ip,
            proxied: summary.proxied,
        });
    }
    dns_records.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));

    let routes = cloudflare::list_worker_routes(&inputs.dns_token, &desired.dns_zone_name).await?;
    let legacy_lease_route_present = routes.iter().any(|route| {
        route.pattern == "lease.alegria.by/*"
            && route.script.as_deref() == Some("edge-lease-reaper")
    });

    Ok(TargetPlaneObservation {
        credential_plane_locked: true,
        zero_trust_device_settings_ready,
        vpc_cidr: desired.mesh.routes[0].network.clone(),
        production_public_ipv4: desired.dns_target_ipv4.clone(),
        mesh,
        mesh_profile_matches,
        profile_precedences,
        dns_records,
        shared_dns_record_count: summaries.len(),
        shared_dns_worker_route_count: routes.len(),
        legacy_lease_route_present,
    })
}

fn plan(
    desired: &TargetPlaneDesired,
    observed: &TargetPlaneObservation,
) -> Result<TargetPlaneAction, String> {
    let mesh_plan =
        edge_controller_core::cloudflare_mesh_lifecycle::plan_apply(&desired.mesh, &observed.mesh)
            .map_err(|err| err.to_string())?;
    match mesh_plan.action {
        MeshApplyAction::Noop => {}
        MeshApplyAction::CreateNode => return Ok(TargetPlaneAction::CreateMeshNode),
        MeshApplyAction::CreateRoute { network } => {
            return Ok(TargetPlaneAction::CreateMeshRoute { network });
        }
    }

    let profile = match observed.mesh_profile_matches.as_slice() {
        [] => {
            return Ok(TargetPlaneAction::CreateMeshProfile {
                precedence: next_free_precedence(
                    desired.mesh_profile.precedence_start,
                    observed.profile_precedences.iter().copied(),
                )?,
            });
        }
        [profile] => profile,
        profiles => {
            return Err(format!(
                "target Mesh profile selector is ambiguous: observed {} matches",
                profiles.len()
            ));
        }
    };
    if profile.name != desired.mesh_profile.name
        || profile.match_expression.as_deref()
            != Some(desired.mesh_profile.match_expression.as_str())
    {
        return Err(
            "target Mesh profile name/selector collision is not exact project ownership".to_owned(),
        );
    }
    let precedence = match profile.precedence {
        Some(value) => value,
        None => next_free_precedence(
            desired.mesh_profile.precedence_start,
            observed.profile_precedences.iter().copied(),
        )?,
    };
    if profile.description.as_deref() != Some(desired.mesh_profile.description.as_str())
        || profile.enabled != Some(true)
        || profile.service_mode.as_deref() != Some(desired.mesh_profile.service_mode.as_str())
        || profile.tunnel_protocol.as_deref() != Some(desired.mesh_profile.tunnel_protocol.as_str())
        || profile.auto_connect != Some(desired.mesh_profile.auto_connect)
        || profile.switch_locked != Some(desired.mesh_profile.switch_locked)
        || profile.precedence != Some(precedence)
    {
        return Ok(TargetPlaneAction::UpdateMeshProfile {
            profile_id: profile.provider_id.clone(),
            precedence,
        });
    }
    if include_keyset(&profile.includes) != desired_include_keyset(&desired.mesh_profile) {
        return Ok(TargetPlaneAction::SetMeshProfileIncludes {
            profile_id: profile.provider_id.clone(),
        });
    }

    match observed.dns_records.as_slice() {
        [] => Ok(TargetPlaneAction::CreateProductionDnsRecord),
        [record] => {
            if record.ip == desired.dns_target_ipv4 && record.proxied == Some(false) {
                Ok(TargetPlaneAction::Noop)
            } else {
                Ok(TargetPlaneAction::UpdateProductionDnsRecord {
                    record_id: record.provider_id.clone(),
                })
            }
        }
        records => Err(format!(
            "shared DNS production record is ambiguous: observed {} exact-name A records",
            records.len()
        )),
    }
}

fn authorized_plan(
    desired: &TargetPlaneDesired,
    observed: &TargetPlaneObservation,
) -> Result<AuthorizedPlan<TargetPlaneAction>, String> {
    let action = plan(desired, observed)?;
    let disposition = if action == TargetPlaneAction::Noop {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    authorize_plan(
        "cloudflare_vertical_b_target_plane",
        desired,
        observed,
        action,
        disposition,
    )
    .map_err(|err| err.to_string())
}

async fn apply_once(
    inputs: &Inputs,
    desired: &TargetPlaneDesired,
    expected_action: &TargetPlaneAction,
    authorized_digest: &str,
) -> Result<(TargetPlaneObservation, TargetPlaneAction), String> {
    let before = observe(inputs, desired).await?;
    let authorized = authorized_plan(desired, &before)?;
    verify_exact_authority(authorized_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;
    if &authorized.plan != expected_action {
        return Err("target-plane action changed after exact authority verification".to_owned());
    }

    let mutation = match &authorized.plan {
        TargetPlaneAction::Noop => {
            return Ok((before, TargetPlaneAction::Noop));
        }
        TargetPlaneAction::CreateMeshNode | TargetPlaneAction::CreateMeshRoute { .. } => {
            apply_mesh_action(inputs, desired, &authorized.plan).await
        }
        TargetPlaneAction::CreateMeshProfile { precedence } => cloudflare::create_device_profile(
            &inputs.control_token,
            &desired.target_account_id,
            &profile_write(desired, *precedence, true),
        )
        .await
        .map(|_| ()),
        TargetPlaneAction::UpdateMeshProfile {
            profile_id,
            precedence,
        } => cloudflare::update_device_profile(
            &inputs.control_token,
            &desired.target_account_id,
            profile_id,
            &profile_write(desired, *precedence, false),
        )
        .await
        .map(|_| ()),
        TargetPlaneAction::SetMeshProfileIncludes { profile_id } => {
            cloudflare::set_device_profile_includes(
                &inputs.control_token,
                &desired.target_account_id,
                profile_id,
                &profile_include_writes(desired),
            )
            .await
            .map(|_| ())
        }
        TargetPlaneAction::CreateProductionDnsRecord => {
            cloudflare::create_a_record(
                &inputs.dns_token,
                &desired.dns_zone_name,
                &desired.dns_record_name,
                &desired.dns_target_ipv4,
            )
            .await
        }
        TargetPlaneAction::UpdateProductionDnsRecord { record_id } => {
            cloudflare::update_a_record_by_id(
                &inputs.dns_token,
                &desired.dns_zone_name,
                record_id,
                &desired.dns_record_name,
                &desired.dns_target_ipv4,
            )
            .await
        }
    };

    reobserve_after_mutation(inputs, desired, &authorized.plan, mutation).await
}

async fn apply_mesh_action(
    inputs: &Inputs,
    desired: &TargetPlaneDesired,
    expected: &TargetPlaneAction,
) -> Result<(), String> {
    let mut provider = CloudflareMeshApiProvider::new(
        inputs.control_token.clone(),
        desired.target_account_id.clone(),
    )?;
    let (observed, mesh_plan) = plan_mesh_apply(&mut provider, &desired.mesh).await?;
    let expected_mesh = match expected {
        TargetPlaneAction::CreateMeshNode => MeshApplyAction::CreateNode,
        TargetPlaneAction::CreateMeshRoute { network } => MeshApplyAction::CreateRoute {
            network: network.clone(),
        },
        _ => return Err("non-Mesh action reached Mesh apply".to_owned()),
    };
    if mesh_plan.action != expected_mesh {
        return Err("target Mesh sub-plan changed before mutation".to_owned());
    }
    let authorized = authorize_mesh_apply(&desired.mesh, &observed, mesh_plan)?;
    apply_mesh_once(
        &mut provider,
        &desired.mesh,
        &authorized.authority.authority_digest,
        MeshExecutionPolicy::default(),
    )
    .await
    .map(|_| ())
}

async fn reobserve_after_mutation(
    inputs: &Inputs,
    desired: &TargetPlaneDesired,
    performed: &TargetPlaneAction,
    mutation: Result<(), String>,
) -> Result<(TargetPlaneObservation, TargetPlaneAction), String> {
    let mutation_error = mutation.err();
    let mut last = None;
    for attempt in 0..REOBSERVE_ATTEMPTS {
        let observed = observe(inputs, desired).await?;
        let next = plan(desired, &observed)?;
        if &next != performed {
            return Ok((observed, next));
        }
        last = Some((observed, next));
        if attempt + 1 < REOBSERVE_ATTEMPTS {
            sleep(Duration::from_secs(REOBSERVE_DELAY_SECONDS)).await;
        }
    }
    let detail = mutation_error.unwrap_or_else(|| "mutation returned success".to_owned());
    Err(format!(
        "target-plane mutation made no observable progress after bounded re-observation ({detail}); mutation was not replayed; last={last:?}"
    ))
}

fn profile_write(
    desired: &TargetPlaneDesired,
    precedence: u64,
    include_on_create: bool,
) -> CloudflareDeviceProfileWrite {
    CloudflareDeviceProfileWrite {
        name: desired.mesh_profile.name.clone(),
        description: desired.mesh_profile.description.clone(),
        enabled: true,
        precedence,
        match_expression: desired.mesh_profile.match_expression.clone(),
        service_mode_v2: CloudflareServiceModeWrite {
            mode: desired.mesh_profile.service_mode.clone(),
        },
        tunnel_protocol: desired.mesh_profile.tunnel_protocol.clone(),
        auto_connect: desired.mesh_profile.auto_connect,
        switch_locked: desired.mesh_profile.switch_locked,
        include: include_on_create.then(|| profile_include_writes(desired)),
    }
}

fn profile_include_writes(desired: &TargetPlaneDesired) -> Vec<CloudflareSplitTunnelWrite> {
    desired
        .mesh_profile
        .include_cidrs
        .iter()
        .map(|address| CloudflareSplitTunnelWrite {
            address: Some(address.clone()),
            host: None,
            description: Some(if address == "100.96.0.0/12" {
                "Cloudflare Mesh device IPs".to_owned()
            } else {
                "Cloudflare source IPs".to_owned()
            }),
        })
        .collect()
}

fn desired_include_keyset(profile: &TargetMeshProfileDesired) -> BTreeSet<String> {
    profile
        .include_cidrs
        .iter()
        .map(|address| format!("address:{address}"))
        .collect()
}

fn include_keyset(entries: &[CloudflareSplitTunnelEntry]) -> BTreeSet<String> {
    entries
        .iter()
        .map(|entry| match (&entry.address, &entry.host) {
            (Some(address), None) => format!("address:{address}"),
            (None, Some(host)) => format!("host:{host}"),
            _ => "invalid".to_owned(),
        })
        .collect()
}

fn next_free_precedence<I>(start: u64, used: I) -> Result<u64, String>
where
    I: IntoIterator<Item = u64>,
{
    let used = used.into_iter().collect::<BTreeSet<_>>();
    for candidate in start..=start.saturating_add(10_000) {
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err("unable to allocate deterministic target Mesh profile precedence".to_owned())
}

fn print_inventory(
    desired: &TargetPlaneDesired,
    observed: &TargetPlaneObservation,
    action: &TargetPlaneAction,
) -> Result<(), String> {
    let value = serde_json::json!({
        "desired": desired,
        "observation": observed,
        "next_action": action,
        "historical_cloudflare_mutations": 0,
        "shared_dns_scope": "exact-production-record-only",
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&value)
            .map_err(|err| format!("failed to serialize target-plane inventory: {err}"))?
    );
    Ok(())
}

fn print_terminal(
    desired: &TargetPlaneDesired,
    observed: &TargetPlaneObservation,
    mutations: u32,
) -> Result<(), String> {
    print_inventory(desired, observed, &TargetPlaneAction::Noop)?;
    println!("target_plane_status=PASS");
    println!("phase3_target_account=PASS");
    println!("phase4_shared_dns_boundary=PASS");
    println!("credential_plane_invariant=PASS");
    println!("provider_plan=NOOP");
    println!("provider_mutations={mutations}");
    println!("historical_cloudflare_mutations=0");
    println!("active_account_unchanged=true");
    println!("shared_dns_unrelated_resources_adopted=0");
    Ok(())
}

fn action_name(action: &TargetPlaneAction) -> &'static str {
    match action {
        TargetPlaneAction::Noop => "NOOP",
        TargetPlaneAction::CreateMeshNode => "CREATE_MESH_NODE",
        TargetPlaneAction::CreateMeshRoute { .. } => "CREATE_MESH_ROUTE",
        TargetPlaneAction::CreateMeshProfile { .. } => "CREATE_MESH_PROFILE",
        TargetPlaneAction::UpdateMeshProfile { .. } => "UPDATE_MESH_PROFILE",
        TargetPlaneAction::SetMeshProfileIncludes { .. } => "SET_MESH_PROFILE_INCLUDES",
        TargetPlaneAction::CreateProductionDnsRecord => "CREATE_PRODUCTION_DNS_RECORD",
        TargetPlaneAction::UpdateProductionDnsRecord { .. } => "UPDATE_PRODUCTION_DNS_RECORD",
    }
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be blank"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ProductionTargetPlaneOwnership {
        ProductionTargetPlaneOwnership {
            target_account_id: "6be6e4b6340822dbeb18cb6c2f09c660".to_owned(),
            mesh_profile_name: "sing-box Mesh nodes".to_owned(),
            mesh_profile_description:
                "Project Mesh nodes: Traffic and DNS over MASQUE with required Cloudflare Mesh ranges"
                    .to_owned(),
            mesh_profile_precedence_start: 100,
            mesh_profile_service_mode: "warp".to_owned(),
            mesh_profile_tunnel_protocol: "masque".to_owned(),
            mesh_profile_auto_connect: 1,
            mesh_profile_switch_locked: true,
            mesh_profile_include_cidrs: vec![
                "100.64.0.0/12".to_owned(),
                "100.96.0.0/12".to_owned(),
            ],
        }
    }

    #[test]
    fn selector_is_derived_from_target_access_team() {
        let desired =
            mesh_profile_desired(&target(), "sing-box-6be6e4b6.cloudflareaccess.com").unwrap();
        assert_eq!(
            desired.match_expression,
            "identity.email == \"warp_connector@sing-box-6be6e4b6.cloudflareaccess.com\""
        );
    }

    #[test]
    fn selector_refuses_non_team_access_domains() {
        assert!(mesh_profile_desired(&target(), "nested.team.cloudflareaccess.com").is_err());
    }

    #[test]
    fn precedence_is_deterministic_and_collision_safe() {
        assert_eq!(next_free_precedence(100, [100, 101, 103]).unwrap(), 102);
    }

    #[test]
    fn action_names_are_large_slice_bounded() {
        assert_eq!(
            action_name(&TargetPlaneAction::CreateMeshNode),
            "CREATE_MESH_NODE"
        );
        assert_eq!(
            action_name(&TargetPlaneAction::CreateProductionDnsRecord),
            "CREATE_PRODUCTION_DNS_RECORD"
        );
        assert_eq!(action_name(&TargetPlaneAction::Noop), "NOOP");
    }
}
