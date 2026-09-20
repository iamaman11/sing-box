use edge_controller_core::cloudflare_dns_lifecycle::{
    ApplyAction, ApplyPlan, CleanupAction, CleanupPlan, DesiredDnsState, DnsObservation,
    ObservedDnsRecord, plan_apply, plan_cleanup, verify_cleanup_digest,
};
use edge_provider_cloudflare::{
    CloudflareDnsObservedRecord, create_a_record, delete_a_record_by_id, list_a_records,
    update_a_record_by_id,
};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, Copy)]
pub struct DnsExecutionPolicy {
    pub reobserve_attempts: usize,
    pub reobserve_delay: Duration,
}

impl Default for DnsExecutionPolicy {
    fn default() -> Self {
        Self {
            reobserve_attempts: 30,
            reobserve_delay: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsApplyReport {
    pub performed: ApplyAction,
    pub observation: DnsObservation,
    pub next_plan: ApplyPlan,
}

#[derive(Debug, Clone)]
pub struct DnsCleanupReport {
    pub performed: CleanupAction,
    pub observation: DnsObservation,
    pub next_plan: CleanupPlan,
}

#[allow(async_fn_in_trait)]
pub trait DnsProvider {
    async fn list_records(
        &mut self,
        zone_name: &str,
        record_name: &str,
    ) -> Result<Vec<CloudflareDnsObservedRecord>, String>;
    async fn create_record(
        &mut self,
        zone_name: &str,
        record_name: &str,
        ip: &str,
    ) -> Result<(), String>;
    async fn update_record(
        &mut self,
        zone_name: &str,
        record_id: &str,
        record_name: &str,
        ip: &str,
    ) -> Result<(), String>;
    async fn delete_record(&mut self, zone_name: &str, record_id: &str) -> Result<(), String>;
}

pub struct CloudflareDnsApiProvider {
    api_token: String,
}

impl CloudflareDnsApiProvider {
    pub fn new(api_token: String) -> Result<Self, String> {
        if api_token.trim().is_empty() {
            return Err("CLOUDFLARE_API_TOKEN must be non-empty".to_owned());
        }
        Ok(Self { api_token })
    }
}

impl DnsProvider for CloudflareDnsApiProvider {
    async fn list_records(
        &mut self,
        zone_name: &str,
        record_name: &str,
    ) -> Result<Vec<CloudflareDnsObservedRecord>, String> {
        list_a_records(&self.api_token, zone_name, record_name).await
    }

    async fn create_record(
        &mut self,
        zone_name: &str,
        record_name: &str,
        ip: &str,
    ) -> Result<(), String> {
        create_a_record(&self.api_token, zone_name, record_name, ip).await
    }

    async fn update_record(
        &mut self,
        zone_name: &str,
        record_id: &str,
        record_name: &str,
        ip: &str,
    ) -> Result<(), String> {
        update_a_record_by_id(&self.api_token, zone_name, record_id, record_name, ip).await
    }

    async fn delete_record(&mut self, zone_name: &str, record_id: &str) -> Result<(), String> {
        delete_a_record_by_id(&self.api_token, zone_name, record_id).await
    }
}

pub async fn observe_dns<P: DnsProvider>(
    provider: &mut P,
    desired: &DesiredDnsState,
) -> Result<DnsObservation, String> {
    desired.validate().map_err(|err| err.to_string())?;
    let records = provider
        .list_records(&desired.zone_name, &desired.record_name)
        .await?;
    Ok(DnsObservation {
        records: records.into_iter().map(observed_record).collect(),
    })
}

pub async fn plan_dns_apply<P: DnsProvider>(
    provider: &mut P,
    desired: &DesiredDnsState,
    target_ip: &str,
) -> Result<(DnsObservation, ApplyPlan), String> {
    let observed = observe_dns(provider, desired).await?;
    let plan = plan_apply(desired, target_ip, &observed).map_err(|err| err.to_string())?;
    Ok((observed, plan))
}

pub async fn apply_dns_once<P: DnsProvider>(
    provider: &mut P,
    desired: &DesiredDnsState,
    target_ip: &str,
    policy: DnsExecutionPolicy,
) -> Result<DnsApplyReport, String> {
    validate_policy(policy)?;
    let (before, plan) = plan_dns_apply(provider, desired, target_ip).await?;
    match plan.action.clone() {
        ApplyAction::Noop => Ok(DnsApplyReport {
            performed: ApplyAction::Noop,
            observation: before,
            next_plan: plan,
        }),
        ApplyAction::Create { ref ip } => {
            let mutation = provider
                .create_record(&desired.zone_name, &desired.record_name, ip)
                .await;
            reobserve_apply_change(provider, desired, target_ip, policy, &plan.action, mutation)
                .await
        }
        ApplyAction::Update {
            ref record_id,
            ref to_ip,
            ..
        } => {
            let mutation = provider
                .update_record(&desired.zone_name, record_id, &desired.record_name, to_ip)
                .await;
            reobserve_apply_change(provider, desired, target_ip, policy, &plan.action, mutation)
                .await
        }
    }
}

pub async fn plan_dns_cleanup<P: DnsProvider>(
    provider: &mut P,
    desired: &DesiredDnsState,
) -> Result<(DnsObservation, CleanupPlan), String> {
    let observed = observe_dns(provider, desired).await?;
    let plan = plan_cleanup(desired, &observed).map_err(|err| err.to_string())?;
    Ok((observed, plan))
}

pub async fn cleanup_dns_once<P: DnsProvider>(
    provider: &mut P,
    desired: &DesiredDnsState,
    expected_digest: &str,
    policy: DnsExecutionPolicy,
) -> Result<DnsCleanupReport, String> {
    validate_policy(policy)?;
    let observed = observe_dns(provider, desired).await?;
    let plan = verify_cleanup_digest(desired, &observed, expected_digest)
        .map_err(|err| err.to_string())?;
    let action = plan.action.clone();
    let mutation = match &action {
        CleanupAction::Noop => {
            return Err("Cloudflare DNS cleanup target is already absent".to_owned());
        }
        CleanupAction::Delete { record_id, .. } => {
            provider.delete_record(&desired.zone_name, record_id).await
        }
    };
    reobserve_cleanup_change(provider, desired, policy, &action, mutation).await
}

async fn reobserve_apply_change<P: DnsProvider>(
    provider: &mut P,
    desired: &DesiredDnsState,
    target_ip: &str,
    policy: DnsExecutionPolicy,
    performed: &ApplyAction,
    mutation: Result<(), String>,
) -> Result<DnsApplyReport, String> {
    let mutation_error = mutation.err();
    let mut last_observation = None;
    let mut last_plan = None;

    for attempt in 0..policy.reobserve_attempts {
        let observed = observe_dns(provider, desired).await?;
        let next_plan = plan_apply(desired, target_ip, &observed).map_err(|err| err.to_string())?;
        if matches!(next_plan.action, ApplyAction::Noop) {
            return Ok(DnsApplyReport {
                performed: performed.clone(),
                observation: observed,
                next_plan,
            });
        }
        last_observation = Some(observed);
        last_plan = Some(next_plan);
        if attempt + 1 < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }

    let detail = mutation_error.unwrap_or_else(|| "mutation returned success".to_owned());
    Err(format!(
        "Cloudflare DNS {:?} did not converge after bounded re-observation ({detail}); mutation was not replayed; last_plan={:?}; last_observation={:?}",
        performed, last_plan, last_observation
    ))
}

async fn reobserve_cleanup_change<P: DnsProvider>(
    provider: &mut P,
    desired: &DesiredDnsState,
    policy: DnsExecutionPolicy,
    performed: &CleanupAction,
    mutation: Result<(), String>,
) -> Result<DnsCleanupReport, String> {
    let mutation_error = mutation.err();
    let mut last_observation = None;
    let mut last_plan = None;

    for attempt in 0..policy.reobserve_attempts {
        let observed = observe_dns(provider, desired).await?;
        let next_plan = plan_cleanup(desired, &observed).map_err(|err| err.to_string())?;
        if matches!(next_plan.action, CleanupAction::Noop) {
            return Ok(DnsCleanupReport {
                performed: performed.clone(),
                observation: observed,
                next_plan,
            });
        }
        last_observation = Some(observed);
        last_plan = Some(next_plan);
        if attempt + 1 < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }

    let detail = mutation_error.unwrap_or_else(|| "mutation returned success".to_owned());
    Err(format!(
        "Cloudflare DNS {:?} did not become absent after bounded re-observation ({detail}); mutation was not replayed; last_plan={:?}; last_observation={:?}",
        performed, last_plan, last_observation
    ))
}

fn validate_policy(policy: DnsExecutionPolicy) -> Result<(), String> {
    if policy.reobserve_attempts == 0 {
        return Err("Cloudflare DNS re-observation attempts must be greater than zero".to_owned());
    }
    Ok(())
}

fn observed_record(record: CloudflareDnsObservedRecord) -> ObservedDnsRecord {
    ObservedDnsRecord {
        provider_id: record.id,
        record_name: record.record_name,
        ip: record.ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeProvider {
        records: Vec<CloudflareDnsObservedRecord>,
        create_calls: usize,
        update_calls: usize,
        delete_calls: usize,
        mutation_error: Option<String>,
        commit_on_error: bool,
    }

    impl DnsProvider for FakeProvider {
        async fn list_records(
            &mut self,
            _zone_name: &str,
            record_name: &str,
        ) -> Result<Vec<CloudflareDnsObservedRecord>, String> {
            Ok(self
                .records
                .iter()
                .filter(|record| record.record_name == record_name)
                .cloned()
                .collect())
        }

        async fn create_record(
            &mut self,
            _zone_name: &str,
            record_name: &str,
            ip: &str,
        ) -> Result<(), String> {
            self.create_calls += 1;
            if self.mutation_error.is_none() || self.commit_on_error {
                self.records.push(CloudflareDnsObservedRecord {
                    id: "dns-1".to_owned(),
                    zone_id: "zone-1".to_owned(),
                    record_name: record_name.to_owned(),
                    ip: ip.to_owned(),
                });
            }
            match self.mutation_error.clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        async fn update_record(
            &mut self,
            _zone_name: &str,
            record_id: &str,
            _record_name: &str,
            ip: &str,
        ) -> Result<(), String> {
            self.update_calls += 1;
            if self.mutation_error.is_none() || self.commit_on_error {
                if let Some(record) = self
                    .records
                    .iter_mut()
                    .find(|record| record.id == record_id)
                {
                    record.ip = ip.to_owned();
                }
            }
            match self.mutation_error.clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        async fn delete_record(&mut self, _zone_name: &str, record_id: &str) -> Result<(), String> {
            self.delete_calls += 1;
            if self.mutation_error.is_none() || self.commit_on_error {
                self.records.retain(|record| record.id != record_id);
            }
            match self.mutation_error.clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }
    }

    fn desired() -> DesiredDnsState {
        DesiredDnsState {
            schema: 1,
            environment: "lifecycle-acceptance".to_owned(),
            zone_name: "alegria.by".to_owned(),
            record_name: "stage2-acceptance.alegria.by".to_owned(),
        }
    }

    fn record(ip: &str) -> CloudflareDnsObservedRecord {
        CloudflareDnsObservedRecord {
            id: "dns-1".to_owned(),
            zone_id: "zone-1".to_owned(),
            record_name: "stage2-acceptance.alegria.by".to_owned(),
            ip: ip.to_owned(),
        }
    }

    fn policy() -> DnsExecutionPolicy {
        DnsExecutionPolicy {
            reobserve_attempts: 2,
            reobserve_delay: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn create_is_observed_once_and_converges_to_noop() {
        let mut provider = FakeProvider::default();
        let report = apply_dns_once(&mut provider, &desired(), "203.0.113.10", policy())
            .await
            .unwrap();
        assert_eq!(provider.create_calls, 1);
        assert!(matches!(report.performed, ApplyAction::Create { .. }));
        assert_eq!(report.next_plan.action, ApplyAction::Noop);
    }

    #[tokio::test]
    async fn mutation_error_is_accepted_only_when_reobservation_proves_commit() {
        let mut provider = FakeProvider {
            mutation_error: Some("transport lost".to_owned()),
            commit_on_error: true,
            ..FakeProvider::default()
        };
        let report = apply_dns_once(&mut provider, &desired(), "203.0.113.10", policy())
            .await
            .unwrap();
        assert_eq!(provider.create_calls, 1);
        assert_eq!(report.next_plan.action, ApplyAction::Noop);
    }

    #[tokio::test]
    async fn uncertain_mutation_is_not_replayed() {
        let mut provider = FakeProvider {
            mutation_error: Some("transport lost".to_owned()),
            commit_on_error: false,
            ..FakeProvider::default()
        };
        assert!(
            apply_dns_once(&mut provider, &desired(), "203.0.113.10", policy())
                .await
                .is_err()
        );
        assert_eq!(provider.create_calls, 1);
    }

    #[tokio::test]
    async fn update_uses_observed_record_identity() {
        let mut provider = FakeProvider {
            records: vec![record("203.0.113.9")],
            ..FakeProvider::default()
        };
        let report = apply_dns_once(&mut provider, &desired(), "203.0.113.10", policy())
            .await
            .unwrap();
        assert_eq!(provider.update_calls, 1);
        assert!(matches!(report.performed, ApplyAction::Update { .. }));
        assert_eq!(report.next_plan.action, ApplyAction::Noop);
    }

    #[tokio::test]
    async fn cleanup_is_digest_bound_and_reobserved() {
        let mut provider = FakeProvider {
            records: vec![record("203.0.113.10")],
            ..FakeProvider::default()
        };
        let (_, plan) = plan_dns_cleanup(&mut provider, &desired()).await.unwrap();
        let digest = plan.destructive_digest.unwrap();
        let report = cleanup_dns_once(&mut provider, &desired(), &digest, policy())
            .await
            .unwrap();
        assert_eq!(provider.delete_calls, 1);
        assert!(matches!(report.performed, CleanupAction::Delete { .. }));
        assert!(matches!(report.next_plan.action, CleanupAction::Noop));
    }
}
