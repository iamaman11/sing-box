use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TcpReadinessPolicy {
    pub(super) max_attempts: usize,
    max_elapsed: Duration,
    connect_timeout: Duration,
    backoff: Duration,
}

impl TcpReadinessPolicy {
    const fn support_access() -> Self {
        Self {
            max_attempts: 90,
            max_elapsed: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(3),
            backoff: Duration::from_secs(2),
        }
    }

    pub(super) fn validate(self) -> Result<Self, String> {
        if self.max_attempts == 0 {
            return Err("TCP readiness max_attempts must be greater than zero".to_owned());
        }
        if self.max_elapsed.is_zero() {
            return Err("TCP readiness max_elapsed must be greater than zero".to_owned());
        }
        if self.connect_timeout.is_zero() {
            return Err("TCP readiness connect_timeout must be greater than zero".to_owned());
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum TcpReadinessState {
    Ready,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum TcpReadinessFailureClass {
    ConnectTimeout,
    ConnectionRefused,
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(super) struct TcpReadinessObservation {
    pub(super) attempts: usize,
    pub(super) elapsed_ms: u64,
    final_state: TcpReadinessState,
    last_error_class: Option<TcpReadinessFailureClass>,
}

impl TcpReadinessObservation {
    pub(super) fn evidence(&self) -> String {
        format!(
            "attempts={}; elapsed_ms={}; final_state={:?}; last_error_class={:?}",
            self.attempts, self.elapsed_ms, self.final_state, self.last_error_class
        )
    }
}

pub(super) fn bounded_elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

pub(super) fn classify_tcp_connect_error(error: &std::io::Error) -> TcpReadinessFailureClass {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => TcpReadinessFailureClass::ConnectionRefused,
        std::io::ErrorKind::TimedOut => TcpReadinessFailureClass::ConnectTimeout,
        _ => TcpReadinessFailureClass::Io,
    }
}

pub(super) async fn observe_tcp_readiness_with_probe<F, Fut>(
    policy: TcpReadinessPolicy,
    mut probe: F,
) -> Result<TcpReadinessObservation, String>
where
    F: FnMut(Duration) -> Fut,
    Fut: std::future::Future<Output = Result<(), TcpReadinessFailureClass>>,
{
    let policy = policy.validate()?;
    let started = Instant::now();
    let mut attempts = 0usize;
    let mut last_error_class = None;

    while attempts < policy.max_attempts && started.elapsed() < policy.max_elapsed {
        let remaining = policy.max_elapsed.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }

        attempts += 1;
        let attempt_timeout = std::cmp::min(policy.connect_timeout, remaining);
        match probe(attempt_timeout).await {
            Ok(()) => {
                return Ok(TcpReadinessObservation {
                    attempts,
                    elapsed_ms: bounded_elapsed_ms(started),
                    final_state: TcpReadinessState::Ready,
                    last_error_class,
                });
            }
            Err(class) => last_error_class = Some(class),
        }

        if attempts >= policy.max_attempts || started.elapsed() >= policy.max_elapsed {
            break;
        }

        let remaining = policy.max_elapsed.saturating_sub(started.elapsed());
        let delay = std::cmp::min(policy.backoff, remaining);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    Ok(TcpReadinessObservation {
        attempts,
        elapsed_ms: bounded_elapsed_ms(started),
        final_state: TcpReadinessState::Timeout,
        last_error_class,
    })
}

pub(super) async fn observe_tcp_readiness(
    target_ip: &str,
    policy: TcpReadinessPolicy,
) -> Result<TcpReadinessObservation, String> {
    let target_ip = target_ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|err| format!("observed machine public IPv4 {target_ip:?} is invalid: {err}"))?;
    let target = std::net::SocketAddr::from((target_ip, 22));

    observe_tcp_readiness_with_probe(policy, |attempt_timeout| async move {
        match tokio::time::timeout(attempt_timeout, tokio::net::TcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                drop(stream);
                Ok(())
            }
            Ok(Err(error)) => Err(classify_tcp_connect_error(&error)),
            Err(_) => Err(TcpReadinessFailureClass::ConnectTimeout),
        }
    })
    .await
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(super) struct SupportAccessProviderEvidence {
    controller_ipv4: String,
    pub(super) firewall_group_id: Option<String>,
    matching_rule_ids: Vec<u64>,
    exact_controller_rules_present_once: bool,
    machine_firewall_group_id: Option<String>,
    pub(super) firewall_group_attached_to_machine: bool,
    acquire_plan_disposition: String,
}

pub(super) fn classify_support_access_provider_evidence(
    controller_ipv4: String,
    pub(super) firewall_group_id: Option<String>,
    observed_rules: &[VultrFirewallRule],
    target_rules: &std::collections::BTreeSet<crate::vultr_support_resources::FirewallRuleSpec>,
    machine_firewall_group_id: Option<String>,
    acquire_disposition: PlanDisposition,
) -> Result<SupportAccessProviderEvidence, String> {
    let mut matching_rule_ids = Vec::new();
    let mut matching_counts = BTreeMap::new();
    for rule in observed_rules {
        let spec = firewall_rule_spec(rule)?;
        if target_rules.contains(&spec) {
            matching_rule_ids.push(rule.id);
            *matching_counts.entry(spec).or_insert(0usize) += 1;
        }
    }
    matching_rule_ids.sort_unstable();

    let exact_controller_rules_present_once = !target_rules.is_empty()
        && target_rules
            .iter()
            .all(|target| matching_counts.get(target) == Some(&1usize));
    let firewall_group_attached_to_machine = firewall_group_id
        .as_ref()
        .is_some_and(|group_id| machine_firewall_group_id.as_ref() == Some(group_id));
    let acquire_plan_disposition = match acquire_disposition {
        PlanDisposition::Noop => "NOOP",
        PlanDisposition::Mutate => "MUTATE",
        PlanDisposition::Blocked => "BLOCKED",
    }
    .to_owned();

    Ok(SupportAccessProviderEvidence {
        controller_ipv4,
        firewall_group_id,
        matching_rule_ids,
        exact_controller_rules_present_once,
        machine_firewall_group_id,
        firewall_group_attached_to_machine,
        acquire_plan_disposition,
    })
}

pub(super) async fn capture_support_access_provider_evidence(
    desired: &DesiredState,
    machine_id: &str,
    lifecycle_provider: &mut VultrApiProvider,
    support_provider: &mut VultrSupportApiProvider,
) -> Result<SupportAccessProviderEvidence, String> {
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profile_name = machine
        .provider
        .firewall_profile
        .as_deref()
        .ok_or_else(|| {
            format!(
                "machine {} has no firewall_profile; timeout evidence requires support access",
                machine.id
            )
        })?;

    let (raw_profiles, _, _, controller_ipv4) = load_access_authority_profiles(desired)?;
    let raw_profile = raw_profiles.profile(profile_name)?;
    let target_rules = controller_ipv4_access_specs(raw_profile, &controller_ipv4)?;
    let (support_observation, observed_rules) =
        observe_firewall_access_authority(support_provider, &desired.environment, profile_name)
            .await?;
    let firewall_group_id = support_observation
        .get("group")
        .and_then(serde_json::Value::as_object)
        .and_then(|group| group.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    let fresh_machine = exact_existing_machine_observation(desired, machine_id).await?;
    let fresh_authority = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Acquire,
        lifecycle_provider,
        support_provider,
    )
    .await?;

    classify_support_access_provider_evidence(
        controller_ipv4,
        firewall_group_id,
        &observed_rules,
        &target_rules,
        fresh_machine.firewall_group_id,
        fresh_authority.disposition,
    )
}

pub(super) fn support_access_timeout_error(
    target_ip: &str,
    tcp_readiness: &TcpReadinessObservation,
    pub(super) provider_evidence: Result<SupportAccessProviderEvidence, String>,
) -> String {
    let evidence_json = match provider_evidence {
        Ok(evidence) => serde_json::to_string(&evidence).unwrap_or_else(|err| {
            format!(r#"{{"status":"SERIALIZATION_ERROR","detail":"{err}"}}"#)
        }),
        Err(error) => serde_json::to_string(&serde_json::json!({
            "status": "OBSERVATION_ERROR",
            "detail": error,
        }))
        .unwrap_or_else(|err| format!(r#"{{"status":"SERIALIZATION_ERROR","detail":"{err}"}}"#)),
    };
    format!(
        "support-access TCP readiness failed for {target_ip}:22: {}; provider_evidence={evidence_json}",
        tcp_readiness.evidence()
    )
}

pub(super) fn strict_ssh_error_after_tcp_ready(
    tcp_readiness: &TcpReadinessObservation,
    ssh_error: String,
) -> String {
    format!(
        "support-access TCP readiness passed ({}); {ssh_error}",
        tcp_readiness.evidence()
    )
}

pub(super) async fn release_transient_access_exact(
    desired: &DesiredState,
    machine_id: &str,
) -> Result<serde_json::Value, String> {
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let planned = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if planned.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "lease-release is blocked for machine {machine_id} by exact plan"
        ));
    }
    let authority_digest = planned.authority.authority_digest.clone();
    let access = release_access_with_authority(desired, machine_id, &authority_digest).await?;
    let verified_absent = access
        .get("verified_absent")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| {
            access
                .get("action")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|action| action == "NOOP")
        });
    if !verified_absent {
        return Err("lease-release did not prove transient SSH access absent".to_owned());
    }
    Ok(access)
}

pub(super) async fn acquire_transient_access_ready_exact(
    desired: &DesiredState,
    machine_id: &str,
    substrate: &HostSubstrateVersions,
) -> Result<
    (
        SupportAccessLeaseState,
        serde_json::Value,
        ObservedMachine,
        TcpReadinessObservation,
    ),
    String,
> {
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let planned = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Acquire,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if planned.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "lease-acquire is blocked for machine {machine_id} by exact plan"
        ));
    }
    let authority_digest = planned.authority.authority_digest.clone();

    let attempt = async {
        let access = acquire_access_with_authority(desired, machine_id, &authority_digest).await?;
        let mut lease = SupportAccessLeaseState::default();
        lease.acquired()?;
        let observed = exact_existing_machine_observation(desired, machine_id).await?;
        let target_ip = observed
            .main_ip
            .clone()
            .ok_or_else(|| format!("exact machine {machine_id} has no observed public IPv4"))?;
        let operator_private_key_path = operator_private_key_path_from_env()?;
        let canonical_public_key = read_canonical_ssh_public_key()?;
        verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
        let tcp_readiness =
            observe_tcp_readiness(&target_ip, TcpReadinessPolicy::support_access()).await?;
        if tcp_readiness.final_state == TcpReadinessState::Timeout {
            let provider_evidence = capture_support_access_provider_evidence(
                desired,
                machine_id,
                &mut lifecycle_provider,
                &mut support_provider,
            )
            .await;
            return Err(support_access_timeout_error(
                &target_ip,
                &tcp_readiness,
                provider_evidence,
            ));
        }
        strict_ssh_accept(
            &target_ip,
            machine_id,
            &operator_private_key_path,
            &canonical_public_key,
            substrate,
            15,
            Duration::from_secs(2),
        )
        .await
        .map_err(|error| strict_ssh_error_after_tcp_ready(&tcp_readiness, error))?;
        lease.ready()?;
        Ok::<_, String>((lease, access, observed, tcp_readiness))
    }
    .await;

    match attempt {
        Ok(result) => Ok(result),
        Err(primary_error) => match release_transient_access_exact(desired, machine_id).await {
            Ok(_) => Err(format!(
                "{primary_error}; transient support access compensated"
            )),
            Err(compensation_error) => Err(format!(
                "{primary_error}; transient support access compensation failed: {compensation_error}"
            )),
        },
    }
}
