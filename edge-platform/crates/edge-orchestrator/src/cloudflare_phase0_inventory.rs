use edge_controller_core::production::ProductionComposition;
use edge_provider_cloudflare::{
    self as cloudflare, CloudflareAccessApplication, CloudflareAccessPolicy,
    CloudflareAccessServiceToken, CloudflareApiTokenIdentity, CloudflareDevicePostureRule,
    CloudflareDeviceProfile, CloudflareDnsObservedRecord, CloudflareDnsRecordSummary,
    CloudflareGatewayRule, CloudflareMeshNode, CloudflareMeshRoute, CloudflareSplitTunnelEntry,
    CloudflareWorkerDomain, CloudflareWorkerRoute, CloudflareWorkerScript,
    CloudflareZeroTrustDeviceSettings,
};
use std::env;

const TARGET_ACCOUNT_NAME: &str = "sing-box";

#[derive(Debug)]
enum ReadObservation<T> {
    Pass(T),
    NotConfigured { reason: String },
    Blocked { error: String },
}

impl<T> ReadObservation<T> {
    fn is_pass(&self) -> bool {
        matches!(self, Self::Pass(_))
    }

    fn is_observed(&self) -> bool {
        matches!(self, Self::Pass(_) | Self::NotConfigured { .. })
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
            && self.posture_rules.is_observed()
            && self.access_applications.is_observed()
            && self.service_tokens.is_observed()
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
struct Phase0Inventory {
    schema_version: u32,
    mutations_performed: u32,
    observation_status: &'static str,
    blockers: Vec<String>,
    historical_account_id: String,
    target_account_name: &'static str,
    target_account_id: Option<String>,
    historical_token_identity: ReadObservation<CloudflareApiTokenIdentity>,
    historical_account: AccountSnapshot,
    target_account: ReadObservation<AccountSnapshot>,
    shared_dns: SharedDnsSnapshot,
}

pub(crate) async fn run() -> Result<(), String> {
    let composition = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let historical_token = env::var("CLOUDFLARE_API_TOKEN").map_err(|_| {
        "CLOUDFLARE_API_TOKEN is required for historical-account inventory".to_owned()
    })?;
    if historical_token.trim().is_empty() {
        return Err("CLOUDFLARE_API_TOKEN must be non-empty".to_owned());
    }

    let historical_account_id = composition.mesh.account_id.clone();
    let target_account_id = nonempty_env("CLOUDFLARE_TARGET_ACCOUNT_ID");
    let control_token = nonempty_env("CLOUDFLARE_CONTROL_TOKEN");
    let dns_token = nonempty_env("CLOUDFLARE_DNS_TOKEN");
    let historical_token_identity =
        ReadObservation::from(cloudflare::verify_api_token(&historical_token).await);

    let historical_account = observe_account(&historical_token, &historical_account_id).await;

    let target_account = match target_account_id.as_deref() {
        None => ReadObservation::Blocked {
            error: "CLOUDFLARE_TARGET_ACCOUNT_ID is required for dedicated sing-box account observation"
                .to_owned(),
        },
        Some(account_id) if !is_cloudflare_id(account_id) => ReadObservation::Blocked {
            error: "CLOUDFLARE_TARGET_ACCOUNT_ID must be exactly 32 hexadecimal characters"
                .to_owned(),
        },
        Some(account_id) if account_id == historical_account_id => ReadObservation::Blocked {
            error: format!(
                "target account {TARGET_ACCOUNT_NAME} must differ from historical account {historical_account_id}"
            ),
        },
        Some(account_id) => match control_token.as_deref() {
            Some(token) => ReadObservation::Pass(observe_account(token, account_id).await),
            None => ReadObservation::Blocked {
                error: "CLOUDFLARE_CONTROL_TOKEN is required for dedicated sing-box account read-only observation"
                    .to_owned(),
            },
        },
    };

    let shared_dns = match dns_token.as_deref() {
        Some(token) => {
            observe_shared_dns(
                token,
                &composition.dns.zone_name,
                &composition.dns.record_name,
            )
            .await
        }
        None => blocked_shared_dns(
            &composition.dns.zone_name,
            &composition.dns.record_name,
            "CLOUDFLARE_DNS_TOKEN is required for shared alegria.by read-only observation",
        ),
    };

    let mut blockers = Vec::new();
    if !historical_token_identity.is_pass() {
        blockers.push("historical automation token identity has blocked read surface".to_owned());
    }
    if !historical_account.complete() {
        blockers.push("historical account inventory has blocked read surfaces".to_owned());
    }
    match &target_account {
        ReadObservation::Pass(snapshot) if snapshot.complete() => {}
        ReadObservation::Pass(_) => {
            blockers.push("target account inventory has blocked read surfaces".to_owned())
        }
        ReadObservation::NotConfigured { reason } => blockers.push(reason.clone()),
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
        target_account_id,
        historical_token_identity,
        historical_account,
        target_account,
        shared_dns,
    };

    println!("Cloudflare Phase 0 read-only inventory");
    println!("observation_status={}", inventory.observation_status);
    println!("mutations_performed={}", inventory.mutations_performed);
    println!("historical_account_id={}", inventory.historical_account_id);
    println!("target_account_name={}", inventory.target_account_name);
    println!(
        "target_account_id={}",
        inventory
            .target_account_id
            .as_deref()
            .unwrap_or("<missing>")
    );
    match &inventory.historical_token_identity {
        ReadObservation::Pass(identity) => {
            println!("historical_token_id={}", identity.id);
            println!("historical_token_status={}", identity.status);
        }
        ReadObservation::NotConfigured { reason } => {
            println!("historical_token_id=<not-configured>");
            println!("historical_token_status={reason}");
        }
        ReadObservation::Blocked { .. } => {
            println!("historical_token_id=<blocked>");
            println!("historical_token_status=<blocked>");
        }
    }
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

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn is_cloudflare_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn access_read_observation<T>(value: Result<T, String>) -> ReadObservation<T> {
    match value {
        Ok(value) => ReadObservation::Pass(value),
        Err(error) if cloudflare::is_access_not_enabled_error(&error) => {
            ReadObservation::NotConfigured {
                reason: "Cloudflare Access is not enabled".to_owned(),
            }
        }
        Err(error) => ReadObservation::Blocked { error },
    }
}

async fn observe_shared_dns(
    api_token: &str,
    zone_name: &str,
    production_record_name: &str,
) -> SharedDnsSnapshot {
    SharedDnsSnapshot {
        zone_name: zone_name.to_owned(),
        production_record_name: production_record_name.to_owned(),
        record_summaries: ReadObservation::from(
            cloudflare::list_dns_record_summaries(api_token, zone_name).await,
        ),
        production_a_records: ReadObservation::from(
            cloudflare::list_a_records(api_token, zone_name, production_record_name).await,
        ),
        worker_routes: ReadObservation::from(
            cloudflare::list_worker_routes(api_token, zone_name).await,
        ),
    }
}

fn blocked_shared_dns(
    zone_name: &str,
    production_record_name: &str,
    error: &str,
) -> SharedDnsSnapshot {
    SharedDnsSnapshot {
        zone_name: zone_name.to_owned(),
        production_record_name: production_record_name.to_owned(),
        record_summaries: ReadObservation::Blocked {
            error: error.to_owned(),
        },
        production_a_records: ReadObservation::Blocked {
            error: error.to_owned(),
        },
        worker_routes: ReadObservation::Blocked {
            error: error.to_owned(),
        },
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
        access_read_observation(cloudflare::list_device_posture_rules(api_token, account_id).await);
    let access_applications =
        access_read_observation(observe_access_applications(api_token, account_id).await);
    let service_tokens = access_read_observation(
        cloudflare::list_access_service_tokens(api_token, account_id).await,
    );
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

#[cfg(test)]
mod tests {
    use super::{ReadObservation, access_read_observation};

    #[test]
    fn access_not_enabled_is_observed_but_not_passed() {
        let observation: ReadObservation<()> = access_read_observation(Err(
            "access.api.error.not_enabled: Access is not enabled".to_owned(),
        ));

        assert!(matches!(observation, ReadObservation::NotConfigured { .. }));
        assert!(observation.is_observed());
        assert!(!observation.is_pass());
    }

    #[test]
    fn unrelated_access_error_remains_blocked() {
        let observation: ReadObservation<()> =
            access_read_observation(Err("403 Forbidden: Authentication error".to_owned()));

        assert!(matches!(observation, ReadObservation::Blocked { .. }));
        assert!(!observation.is_observed());
    }
}
