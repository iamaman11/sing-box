use edge_controller_core::production::ProductionComposition;
use edge_provider_cloudflare::{
    self as cloudflare, CloudflareAccessApplication, CloudflareAccessPolicy,
    CloudflareAccessServiceToken, CloudflareAccount, CloudflareApiTokenMetadata,
    CloudflareDevicePostureRule, CloudflareDeviceProfile, CloudflareDnsObservedRecord,
    CloudflareDnsRecordSummary, CloudflareGatewayRule, CloudflareMeshNode, CloudflareMeshRoute,
    CloudflareSplitTunnelEntry, CloudflareWorkerDomain, CloudflareWorkerRoute,
    CloudflareWorkerScript, CloudflareZeroTrustDeviceSettings,
};
use std::env;

const TARGET_ACCOUNT_NAME: &str = "sing-box";

#[derive(Debug)]
enum ReadObservation<T> {
    Pass(T),
    Blocked { error: String },
}

impl<T> ReadObservation<T> {
    fn is_pass(&self) -> bool {
        matches!(self, Self::Pass(_))
    }
}

impl<T> From<Result<T, String>> for ReadObservation<T> {
    fn from(value: Result<T, String>) -> Self {
        match value {
            Ok(value) => Self::Pass(value),
            Err(error) => Self::Blocked { error },
        }
    }
}

#[derive(Debug)]
struct MeshNodeSnapshot {
    id: String,
    name: String,
    status: Option<String>,
    routes: ReadObservation<Vec<CloudflareMeshRoute>>,
}

#[derive(Debug)]
struct DeviceProfileSnapshot {
    id: String,
    name: String,
    description: Option<String>,
    enabled: Option<bool>,
    precedence: Option<u64>,
    match_expression_present: bool,
    service_mode: Option<String>,
    tunnel_protocol: Option<String>,
    auto_connect: Option<u64>,
    switch_locked: Option<bool>,
    includes: ReadObservation<Vec<CloudflareSplitTunnelEntry>>,
    excludes: ReadObservation<Vec<CloudflareSplitTunnelEntry>>,
}

#[derive(Debug)]
struct GatewayRuleSnapshot {
    id: String,
    name: String,
    description: Option<String>,
    action: String,
    precedence: Option<u64>,
    enabled: Option<bool>,
    filters: Vec<String>,
    traffic: Option<String>,
    identity_present: bool,
    device_posture_present: bool,
}

#[derive(Debug)]
struct AccessApplicationSnapshot {
    id: String,
    name: String,
    app_type: String,
    policies: ReadObservation<Vec<CloudflareAccessPolicy>>,
}

#[derive(Debug)]
struct AccountSnapshot {
    account_id: String,
    device_settings: ReadObservation<CloudflareZeroTrustDeviceSettings>,
    mesh_nodes: ReadObservation<Vec<MeshNodeSnapshot>>,
    device_profiles: ReadObservation<Vec<DeviceProfileSnapshot>>,
    gateway_rules: ReadObservation<Vec<GatewayRuleSnapshot>>,
    posture_rules: ReadObservation<Vec<CloudflareDevicePostureRule>>,
    access_applications: ReadObservation<Vec<AccessApplicationSnapshot>>,
    service_tokens: ReadObservation<Vec<CloudflareAccessServiceToken>>,
    worker_scripts: ReadObservation<Vec<CloudflareWorkerScript>>,
    worker_domains: ReadObservation<Vec<CloudflareWorkerDomain>>,
}

impl AccountSnapshot {
    fn complete(&self) -> bool {
        self.device_settings.is_pass()
            && self.mesh_nodes.is_pass()
            && self.device_profiles.is_pass()
            && self.gateway_rules.is_pass()
            && self.posture_rules.is_pass()
            && self.access_applications.is_pass()
            && self.service_tokens.is_pass()
            && self.worker_scripts.is_pass()
            && self.worker_domains.is_pass()
    }
}

#[derive(Debug)]
struct SharedDnsSnapshot {
    zone_name: String,
    production_record_name: String,
    record_summaries: ReadObservation<Vec<CloudflareDnsRecordSummary>>,
    production_a_records: ReadObservation<Vec<CloudflareDnsObservedRecord>>,
    worker_routes: ReadObservation<Vec<CloudflareWorkerRoute>>,
}

impl SharedDnsSnapshot {
    fn complete(&self) -> bool {
        self.record_summaries.is_pass()
            && self.production_a_records.is_pass()
            && self.worker_routes.is_pass()
    }
}

#[derive(Debug)]
struct AccountDiscovery {
    memberships_api: ReadObservation<Vec<CloudflareAccount>>,
    discovered_accounts: Vec<CloudflareAccount>,
}

#[derive(Debug)]
struct Phase0Inventory {
    schema_version: u32,
    mutations_performed: u32,
    observation_status: &'static str,
    blockers: Vec<String>,
    historical_account_id: String,
    target_account_name: &'static str,
    current_api_token: ReadObservation<CloudflareApiTokenMetadata>,
    account_discovery: AccountDiscovery,
    historical_account: AccountSnapshot,
    target_account: ReadObservation<AccountSnapshot>,
    shared_dns: SharedDnsSnapshot,
}

pub(crate) async fn run() -> Result<(), String> {
    let composition = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let api_token = env::var("CLOUDFLARE_API_TOKEN")
        .map_err(|_| "CLOUDFLARE_API_TOKEN is required for Cloudflare inventory".to_owned())?;
    if api_token.trim().is_empty() {
        return Err("CLOUDFLARE_API_TOKEN must be non-empty".to_owned());
    }

    let historical_account_id = composition.mesh.account_id.clone();

    let token_metadata =
        ReadObservation::from(cloudflare::current_api_token_metadata(&api_token).await);

    // Cloudflare's account list endpoint is not an API-token discovery authority.
    // Memberships is the typed user-scoped discovery surface when Memberships Read is granted.
    let memberships_result = cloudflare::list_membership_accounts(&api_token).await;
    let discovered_accounts = memberships_result.as_ref().cloned().unwrap_or_default();
    let account_discovery = AccountDiscovery {
        memberships_api: ReadObservation::from(memberships_result),
        discovered_accounts: discovered_accounts.clone(),
    };

    let historical_account = observe_account(&api_token, &historical_account_id).await;

    let target_matches = discovered_accounts
        .iter()
        .filter(|account| account.name == TARGET_ACCOUNT_NAME)
        .cloned()
        .collect::<Vec<_>>();
    let target_account = match target_matches.as_slice() {
        [target] if target.id != historical_account_id => {
            ReadObservation::Pass(observe_account(&api_token, &target.id).await)
        }
        [target] => ReadObservation::Blocked {
            error: format!(
                "target account {TARGET_ACCOUNT_NAME} resolves to historical account {}",
                target.id
            ),
        },
        [] => ReadObservation::Blocked {
            error: format!(
                "target account {TARGET_ACCOUNT_NAME} was not visible through account discovery"
            ),
        },
        _ => ReadObservation::Blocked {
            error: format!(
                "target account {TARGET_ACCOUNT_NAME} is ambiguous: {} matches",
                target_matches.len()
            ),
        },
    };

    let shared_dns = SharedDnsSnapshot {
        zone_name: composition.dns.zone_name.clone(),
        production_record_name: composition.dns.record_name.clone(),
        record_summaries: ReadObservation::from(
            cloudflare::list_dns_record_summaries(&api_token, &composition.dns.zone_name).await,
        ),
        production_a_records: ReadObservation::from(
            cloudflare::list_a_records(
                &api_token,
                &composition.dns.zone_name,
                &composition.dns.record_name,
            )
            .await,
        ),
        worker_routes: ReadObservation::from(
            cloudflare::list_worker_routes(&api_token, &composition.dns.zone_name).await,
        ),
    };

    let mut blockers = Vec::new();
    if !historical_account.complete() {
        blockers.push("historical account inventory has blocked read surfaces".to_owned());
    }
    match &target_account {
        ReadObservation::Pass(snapshot) if snapshot.complete() => {}
        ReadObservation::Pass(_) => {
            blockers.push("target account inventory has blocked read surfaces".to_owned())
        }
        ReadObservation::Blocked { error } => blockers.push(error.clone()),
    }
    if !shared_dns.complete() {
        blockers.push("shared DNS inventory has blocked read surfaces".to_owned());
    }

    let observation_status = if blockers.is_empty() {
        "COMPLETE"
    } else {
        "BLOCKED"
    };
    let inventory = Phase0Inventory {
        schema_version: 1,
        mutations_performed: 0,
        observation_status,
        blockers,
        historical_account_id,
        target_account_name: TARGET_ACCOUNT_NAME,
        current_api_token: token_metadata,
        account_discovery,
        historical_account,
        target_account,
        shared_dns,
    };

    println!("Cloudflare Phase 0 read-only inventory");
    println!("observation_status={}", inventory.observation_status);
    println!("mutations_performed={}", inventory.mutations_performed);
    println!("historical_account_id={}", inventory.historical_account_id);
    println!("target_account_name={}", inventory.target_account_name);
    println!();
    println!("{inventory:#?}");

    if inventory.blockers.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Cloudflare Phase 0 inventory BLOCKED by {} read/ownership condition(s)",
            inventory.blockers.len()
        ))
    }
}

async fn observe_account(api_token: &str, account_id: &str) -> AccountSnapshot {
    let device_settings = ReadObservation::from(
        cloudflare::get_zero_trust_device_settings(api_token, account_id).await,
    );
    let mesh_nodes = ReadObservation::from(observe_mesh_nodes(api_token, account_id).await);
    let device_profiles =
        ReadObservation::from(observe_device_profiles(api_token, account_id).await);
    let gateway_rules = ReadObservation::from(
        cloudflare::list_gateway_rules(api_token, account_id)
            .await
            .map(|rules| rules.into_iter().map(gateway_rule_snapshot).collect()),
    );
    let posture_rules =
        ReadObservation::from(cloudflare::list_device_posture_rules(api_token, account_id).await);
    let access_applications =
        ReadObservation::from(observe_access_applications(api_token, account_id).await);
    let service_tokens =
        ReadObservation::from(cloudflare::list_access_service_tokens(api_token, account_id).await);
    let worker_scripts =
        ReadObservation::from(cloudflare::list_worker_scripts(api_token, account_id).await);
    let worker_domains =
        ReadObservation::from(cloudflare::list_worker_domains(api_token, account_id).await);

    AccountSnapshot {
        account_id: account_id.to_owned(),
        device_settings,
        mesh_nodes,
        device_profiles,
        gateway_rules,
        posture_rules,
        access_applications,
        service_tokens,
        worker_scripts,
        worker_domains,
    }
}

async fn observe_mesh_nodes(
    api_token: &str,
    account_id: &str,
) -> Result<Vec<MeshNodeSnapshot>, String> {
    let mut nodes = cloudflare::list_mesh_nodes(api_token, account_id, None).await?;
    nodes.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    let mut snapshots = Vec::with_capacity(nodes.len());
    for CloudflareMeshNode { id, name, status } in nodes {
        let routes =
            ReadObservation::from(cloudflare::list_mesh_routes(api_token, account_id, &id).await);
        snapshots.push(MeshNodeSnapshot {
            id,
            name,
            status,
            routes,
        });
    }
    Ok(snapshots)
}

async fn observe_device_profiles(
    api_token: &str,
    account_id: &str,
) -> Result<Vec<DeviceProfileSnapshot>, String> {
    let mut profiles = cloudflare::list_device_profiles(api_token, account_id).await?;
    profiles.sort_by(|left, right| {
        left.precedence
            .unwrap_or(u64::MAX)
            .cmp(&right.precedence.unwrap_or(u64::MAX))
            .then(left.name.cmp(&right.name))
            .then(left.id.cmp(&right.id))
    });
    let mut snapshots = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let includes = ReadObservation::from(
            cloudflare::get_device_profile_includes(api_token, account_id, &profile.id).await,
        );
        let excludes = ReadObservation::from(
            cloudflare::get_device_profile_excludes(api_token, account_id, &profile.id).await,
        );
        snapshots.push(device_profile_snapshot(profile, includes, excludes));
    }
    Ok(snapshots)
}

fn device_profile_snapshot(
    profile: CloudflareDeviceProfile,
    includes: ReadObservation<Vec<CloudflareSplitTunnelEntry>>,
    excludes: ReadObservation<Vec<CloudflareSplitTunnelEntry>>,
) -> DeviceProfileSnapshot {
    DeviceProfileSnapshot {
        id: profile.id,
        name: profile.name,
        description: profile.description,
        enabled: profile.enabled,
        precedence: profile.precedence,
        match_expression_present: profile.match_expression.is_some(),
        service_mode: profile.service_mode,
        tunnel_protocol: profile.tunnel_protocol,
        auto_connect: profile.auto_connect,
        switch_locked: profile.switch_locked,
        includes,
        excludes,
    }
}

fn gateway_rule_snapshot(rule: CloudflareGatewayRule) -> GatewayRuleSnapshot {
    GatewayRuleSnapshot {
        id: rule.id,
        name: rule.name,
        description: rule.description,
        action: rule.action,
        precedence: rule.precedence,
        enabled: rule.enabled,
        filters: rule.filters,
        traffic: rule.traffic,
        identity_present: rule.identity.is_some(),
        device_posture_present: rule.device_posture.is_some(),
    }
}

async fn observe_access_applications(
    api_token: &str,
    account_id: &str,
) -> Result<Vec<AccessApplicationSnapshot>, String> {
    let mut applications = cloudflare::list_access_applications(api_token, account_id).await?;
    applications.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    let mut snapshots = Vec::with_capacity(applications.len());
    for CloudflareAccessApplication { id, name, app_type } in applications {
        let policies = ReadObservation::from(
            cloudflare::list_access_application_policies(api_token, account_id, &id).await,
        );
        snapshots.push(AccessApplicationSnapshot {
            id,
            name,
            app_type,
            policies,
        });
    }
    Ok(snapshots)
}
