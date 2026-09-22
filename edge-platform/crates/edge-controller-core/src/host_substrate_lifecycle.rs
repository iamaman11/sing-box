use serde::{Deserialize, Serialize};

pub const HOST_CERTIFICATE_MINIMUM_SERIAL: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StrictSshState {
    Pass,
    Transport,
    HostTrust,
    Authentication,
    RemoteAcceptance,
    OtherSsh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSubstrateObservation {
    pub machine_id: String,
    pub provider_id: String,
    pub main_ip: String,
    pub provider_ready: bool,
    pub strict_ssh_state: StrictSshState,
    pub strict_ssh_evidence: String,
    pub user_data_scrubbed: Option<bool>,
    pub host_certificate_serial: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostSubstrateAction {
    BlockedProvider,
    BlockedStrictSsh,
    BlockedSubstrate,
    ScrubUserData,
    RotateHostCertificate,
    Noop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSubstratePlan {
    pub action: HostSubstrateAction,
    pub reasons: Vec<String>,
}

pub fn plan_host_substrate(
    observed: &HostSubstrateObservation,
    minimum_certificate_serial: u64,
) -> HostSubstratePlan {
    if !observed.provider_ready {
        return HostSubstratePlan {
            action: HostSubstrateAction::BlockedProvider,
            reasons: vec!["provider instance is not ready".to_owned()],
        };
    }

    match observed.strict_ssh_state {
        StrictSshState::Pass => {}
        StrictSshState::RemoteAcceptance => {
            return HostSubstratePlan {
                action: HostSubstrateAction::BlockedSubstrate,
                reasons: vec![format!(
                    "strict SSH reached remote substrate acceptance but it is not ready: {}",
                    observed.strict_ssh_evidence
                )],
            };
        }
        StrictSshState::Transport
        | StrictSshState::HostTrust
        | StrictSshState::Authentication
        | StrictSshState::OtherSsh => {
            return HostSubstratePlan {
                action: HostSubstrateAction::BlockedStrictSsh,
                reasons: vec![format!(
                    "strict SSH is not accepted: {}",
                    observed.strict_ssh_evidence
                )],
            };
        }
    }

    match observed.user_data_scrubbed {
        Some(false) => {
            return HostSubstratePlan {
                action: HostSubstrateAction::ScrubUserData,
                reasons: vec!["provider user-data is not in canonical scrubbed state".to_owned()],
            };
        }
        None => {
            return HostSubstratePlan {
                action: HostSubstrateAction::BlockedProvider,
                reasons: vec!["provider user-data state is unavailable".to_owned()],
            };
        }
        Some(true) => {}
    }

    match observed.host_certificate_serial {
        Some(serial) if serial >= minimum_certificate_serial => HostSubstratePlan {
            action: HostSubstrateAction::Noop,
            reasons: Vec::new(),
        },
        Some(serial) => HostSubstratePlan {
            action: HostSubstrateAction::RotateHostCertificate,
            reasons: vec![format!(
                "host certificate serial {serial} is below required minimum {minimum_certificate_serial}"
            )],
        },
        None => HostSubstratePlan {
            action: HostSubstrateAction::BlockedStrictSsh,
            reasons: vec!["host certificate serial could not be observed".to_owned()],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> HostSubstrateObservation {
        HostSubstrateObservation {
            machine_id: "edge-1".to_owned(),
            provider_id: "instance-1".to_owned(),
            main_ip: "203.0.113.10".to_owned(),
            provider_ready: true,
            strict_ssh_state: StrictSshState::Pass,
            strict_ssh_evidence: "PASS".to_owned(),
            user_data_scrubbed: Some(true),
            host_certificate_serial: Some(HOST_CERTIFICATE_MINIMUM_SERIAL),
        }
    }

    #[test]
    fn provider_block_precedes_guest_observation() {
        let mut observed = observation();
        observed.provider_ready = false;
        observed.user_data_scrubbed = None;
        observed.host_certificate_serial = None;
        assert_eq!(
            plan_host_substrate(&observed, HOST_CERTIFICATE_MINIMUM_SERIAL).action,
            HostSubstrateAction::BlockedProvider
        );
    }

    #[test]
    fn strict_ssh_failure_is_read_only_blocker() {
        let mut observed = observation();
        observed.strict_ssh_state = StrictSshState::Transport;
        observed.strict_ssh_evidence = "connection_closed".to_owned();
        observed.user_data_scrubbed = None;
        observed.host_certificate_serial = None;
        assert_eq!(
            plan_host_substrate(&observed, HOST_CERTIFICATE_MINIMUM_SERIAL).action,
            HostSubstrateAction::BlockedStrictSsh
        );
    }

    #[test]
    fn remote_acceptance_failure_is_substrate_blocker() {
        let mut observed = observation();
        observed.strict_ssh_state = StrictSshState::RemoteAcceptance;
        observed.strict_ssh_evidence = "EDGE_SUBSTRATE_FAIL:host-bootstrap-marker".to_owned();
        observed.user_data_scrubbed = None;
        observed.host_certificate_serial = None;
        assert_eq!(
            plan_host_substrate(&observed, HOST_CERTIFICATE_MINIMUM_SERIAL).action,
            HostSubstrateAction::BlockedSubstrate
        );
    }

    #[test]
    fn scrub_is_the_only_first_mutation() {
        let mut observed = observation();
        observed.user_data_scrubbed = Some(false);
        observed.host_certificate_serial = Some(1);
        assert_eq!(
            plan_host_substrate(&observed, HOST_CERTIFICATE_MINIMUM_SERIAL).action,
            HostSubstrateAction::ScrubUserData
        );
    }

    #[test]
    fn rotation_follows_successful_scrub() {
        let mut observed = observation();
        observed.host_certificate_serial = Some(1);
        assert_eq!(
            plan_host_substrate(&observed, HOST_CERTIFICATE_MINIMUM_SERIAL).action,
            HostSubstrateAction::RotateHostCertificate
        );
    }

    #[test]
    fn noop_requires_all_acceptance_state() {
        assert_eq!(
            plan_host_substrate(&observation(), HOST_CERTIFICATE_MINIMUM_SERIAL).action,
            HostSubstrateAction::Noop
        );
    }
}
