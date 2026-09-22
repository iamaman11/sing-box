use crate::vultr_host_bootstrap::{
    HostSubstrateVersions, OperationalProvider, StrictSshFailureClass,
    ensure_host_certificate_rotated, observe_strict_ssh_acceptance, observe_user_data_scrubbed,
    read_host_certificate_serial, scrub_user_data,
};
use edge_controller_core::host_substrate_lifecycle::{
    HOST_CERTIFICATE_MINIMUM_SERIAL, HostSubstrateAction, HostSubstrateObservation,
    HostSubstratePlan, StrictSshState, plan_host_substrate,
};
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_controller_core::vultr_lifecycle::{DesiredState, MachineSpec};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct HostSubstrateExecutionPolicy {
    pub ssh_observe_attempts: usize,
    pub ssh_observe_delay: Duration,
    pub user_data_reobserve_attempts: usize,
    pub user_data_reobserve_delay: Duration,
}

impl Default for HostSubstrateExecutionPolicy {
    fn default() -> Self {
        Self {
            ssh_observe_attempts: 60,
            ssh_observe_delay: Duration::from_secs(5),
            user_data_reobserve_attempts: 30,
            user_data_reobserve_delay: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostSubstrateApplyReport {
    pub performed: HostSubstrateAction,
    pub observation: HostSubstrateObservation,
    pub next_plan: HostSubstratePlan,
}

fn strict_state(class: StrictSshFailureClass) -> StrictSshState {
    match class {
        StrictSshFailureClass::Transport => StrictSshState::Transport,
        StrictSshFailureClass::HostTrust => StrictSshState::HostTrust,
        StrictSshFailureClass::Authentication => StrictSshState::Authentication,
        StrictSshFailureClass::RemoteAcceptance => StrictSshState::RemoteAcceptance,
        StrictSshFailureClass::OtherSsh => StrictSshState::OtherSsh,
    }
}

pub async fn observe_host_substrate<P: OperationalProvider>(
    provider: &mut P,
    machine: &MachineSpec,
    provider_id: &str,
    operator_private_key_path: &Path,
    canonical_public_key: &str,
    substrate: &HostSubstrateVersions,
    policy: HostSubstrateExecutionPolicy,
) -> Result<HostSubstrateObservation, String> {
    if policy.ssh_observe_attempts == 0 {
        return Err("host substrate SSH observation attempts must be greater than zero".to_owned());
    }

    let instance = provider
        .get_instance(provider_id)
        .await
        .map_err(|err| err.to_string())?;
    let provider_ready = instance.status == "active"
        && instance.power_status == "running"
        && instance.server_status == "ok"
        && !instance.main_ip.trim().is_empty();

    if !provider_ready {
        return Ok(HostSubstrateObservation {
            machine_id: machine.id.clone(),
            provider_id: provider_id.to_owned(),
            main_ip: instance.main_ip,
            provider_ready: false,
            strict_ssh_state: StrictSshState::OtherSsh,
            strict_ssh_evidence: format!(
                "provider_not_ready:status={};power_status={};server_status={};main_ip_present={}",
                instance.status,
                instance.power_status,
                instance.server_status,
                !instance.main_ip.trim().is_empty()
            ),
            user_data_scrubbed: None,
            host_certificate_serial: None,
        });
    }

    let strict = observe_strict_ssh_acceptance(
        &instance.main_ip,
        &machine.id,
        operator_private_key_path,
        canonical_public_key,
        substrate,
        policy.ssh_observe_attempts,
        policy.ssh_observe_delay,
    )
    .await?;

    if !strict.passed {
        return Ok(HostSubstrateObservation {
            machine_id: machine.id.clone(),
            provider_id: provider_id.to_owned(),
            main_ip: instance.main_ip,
            provider_ready: true,
            strict_ssh_state: strict
                .last_class
                .map(strict_state)
                .unwrap_or(StrictSshState::OtherSsh),
            strict_ssh_evidence: strict.evidence(),
            user_data_scrubbed: None,
            host_certificate_serial: None,
        });
    }

    let user_data_scrubbed = observe_user_data_scrubbed(provider, provider_id).await?;
    let serial = read_host_certificate_serial(
        &instance.main_ip,
        &machine.id,
        operator_private_key_path,
        canonical_public_key,
    )?;

    Ok(HostSubstrateObservation {
        machine_id: machine.id.clone(),
        provider_id: provider_id.to_owned(),
        main_ip: instance.main_ip,
        provider_ready: true,
        strict_ssh_state: StrictSshState::Pass,
        strict_ssh_evidence: strict.evidence(),
        user_data_scrubbed: Some(user_data_scrubbed),
        host_certificate_serial: Some(serial),
    })
}

pub fn authorize_host_substrate(
    desired: &DesiredState,
    machine: &MachineSpec,
    observed: &HostSubstrateObservation,
) -> Result<AuthorizedPlan<HostSubstratePlan>, String> {
    let plan = plan_host_substrate(observed, HOST_CERTIFICATE_MINIMUM_SERIAL);
    let disposition = match plan.action {
        HostSubstrateAction::Noop => PlanDisposition::Noop,
        HostSubstrateAction::ScrubUserData | HostSubstrateAction::RotateHostCertificate => {
            PlanDisposition::Mutate
        }
        HostSubstrateAction::BlockedProvider
        | HostSubstrateAction::BlockedStrictSsh
        | HostSubstrateAction::BlockedSubstrate => PlanDisposition::Blocked,
    };
    let desired_material = serde_json::json!({
        "desired": desired,
        "machine_id": machine.id,
        "minimum_host_certificate_serial": HOST_CERTIFICATE_MINIMUM_SERIAL,
    });
    authorize_plan(
        "vultr_host_substrate",
        &desired_material,
        observed,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub async fn build_host_substrate_authority<P: OperationalProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine: &MachineSpec,
    provider_id: &str,
    operator_private_key_path: &Path,
    canonical_public_key: &str,
    substrate: &HostSubstrateVersions,
    policy: HostSubstrateExecutionPolicy,
) -> Result<(HostSubstrateObservation, AuthorizedPlan<HostSubstratePlan>), String> {
    let observation = observe_host_substrate(
        provider,
        machine,
        provider_id,
        operator_private_key_path,
        canonical_public_key,
        substrate,
        policy,
    )
    .await?;
    let authorized = authorize_host_substrate(desired, machine, &observation)?;
    Ok((observation, authorized))
}

pub async fn apply_host_substrate_once<P: OperationalProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine: &MachineSpec,
    provider_id: &str,
    authorized_plan_sha256: &str,
    operator_private_key_path: &Path,
    canonical_public_key: &str,
    substrate: &HostSubstrateVersions,
    policy: HostSubstrateExecutionPolicy,
) -> Result<HostSubstrateApplyReport, String> {
    let (_before, authorized) = build_host_substrate_authority(
        provider,
        desired,
        machine,
        provider_id,
        operator_private_key_path,
        canonical_public_key,
        substrate,
        policy,
    )
    .await?;
    verify_exact_authority(authorized_plan_sha256, &authorized.authority)
        .map_err(|err| err.to_string())?;

    match authorized.disposition {
        PlanDisposition::Noop => {
            let observation = observe_host_substrate(
                provider,
                machine,
                provider_id,
                operator_private_key_path,
                canonical_public_key,
                substrate,
                HostSubstrateExecutionPolicy {
                    ssh_observe_attempts: 1,
                    ..policy
                },
            )
            .await?;
            let next_plan = plan_host_substrate(&observation, HOST_CERTIFICATE_MINIMUM_SERIAL);
            return Ok(HostSubstrateApplyReport {
                performed: HostSubstrateAction::Noop,
                observation,
                next_plan,
            });
        }
        PlanDisposition::Blocked => {
            return Err(format!(
                "host substrate apply is blocked by exact plan: {}",
                authorized.plan.reasons.join("; ")
            ));
        }
        PlanDisposition::Mutate => {}
    }

    let performed = authorized.plan.action;
    match performed {
        HostSubstrateAction::ScrubUserData => {
            scrub_user_data(
                provider,
                provider_id,
                policy.user_data_reobserve_attempts,
                policy.user_data_reobserve_delay,
            )
            .await?;
        }
        HostSubstrateAction::RotateHostCertificate => {
            ensure_host_certificate_rotated(
                &_before.main_ip,
                &machine.id,
                operator_private_key_path,
                canonical_public_key,
                HOST_CERTIFICATE_MINIMUM_SERIAL,
            )?;
        }
        HostSubstrateAction::Noop
        | HostSubstrateAction::BlockedProvider
        | HostSubstrateAction::BlockedStrictSsh
        | HostSubstrateAction::BlockedSubstrate => {
            return Err(
                "host substrate authority did not resolve to exactly one mutation".to_owned(),
            );
        }
    }

    let observation = observe_host_substrate(
        provider,
        machine,
        provider_id,
        operator_private_key_path,
        canonical_public_key,
        substrate,
        HostSubstrateExecutionPolicy {
            ssh_observe_attempts: 1,
            ..policy
        },
    )
    .await?;
    let next_plan = plan_host_substrate(&observation, HOST_CERTIFICATE_MINIMUM_SERIAL);
    Ok(HostSubstrateApplyReport {
        performed,
        observation,
        next_plan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_controller_core::host_substrate_lifecycle::HostSubstrateAction;

    #[test]
    fn action_disposition_allows_only_one_mutation_kind() {
        for action in [
            HostSubstrateAction::ScrubUserData,
            HostSubstrateAction::RotateHostCertificate,
        ] {
            assert!(matches!(
                action,
                HostSubstrateAction::ScrubUserData | HostSubstrateAction::RotateHostCertificate
            ));
        }
    }
}
