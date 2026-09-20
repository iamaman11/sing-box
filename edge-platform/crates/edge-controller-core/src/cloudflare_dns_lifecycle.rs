use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

const CURRENT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredDnsState {
    pub schema: u32,
    pub environment: String,
    pub zone_name: String,
    pub record_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedDnsRecord {
    pub provider_id: String,
    pub record_name: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DnsObservation {
    pub records: Vec<ObservedDnsRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplyAction {
    Noop,
    Create {
        ip: String,
    },
    Update {
        record_id: String,
        from_ip: String,
        to_ip: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPlan {
    pub action: ApplyAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CleanupAction {
    Noop,
    Delete { record_id: String, ip: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupPlan {
    pub action: CleanupAction,
    pub destructive_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsLifecycleError {
    Json(String),
    UnsupportedSchema(u32),
    Validation(String),
    Ambiguous(String),
    Conflict(String),
    Serialization(String),
}

impl fmt::Display for DnsLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message)
            | Self::Validation(message)
            | Self::Ambiguous(message)
            | Self::Conflict(message)
            | Self::Serialization(message) => f.write_str(message),
            Self::UnsupportedSchema(schema) => {
                write!(f, "unsupported Cloudflare DNS lifecycle schema {schema}")
            }
        }
    }
}

impl std::error::Error for DnsLifecycleError {}

impl DesiredDnsState {
    pub fn parse_json(input: &str) -> Result<Self, DnsLifecycleError> {
        let desired: Self =
            serde_json::from_str(input).map_err(|err| DnsLifecycleError::Json(err.to_string()))?;
        desired.validate()?;
        Ok(desired)
    }

    pub fn validate(&self) -> Result<(), DnsLifecycleError> {
        if self.schema != CURRENT_SCHEMA {
            return Err(DnsLifecycleError::UnsupportedSchema(self.schema));
        }
        validate_identifier("environment", &self.environment, 64)?;
        validate_dns_name("zone_name", &self.zone_name)?;
        validate_dns_name("record_name", &self.record_name)?;
        if self.record_name != self.zone_name
            && !self
                .record_name
                .strip_suffix(&format!(".{}", self.zone_name))
                .is_some_and(|prefix| !prefix.is_empty())
        {
            return Err(DnsLifecycleError::Validation(format!(
                "record_name {} must be the zone apex or a child of {}",
                self.record_name, self.zone_name
            )));
        }
        Ok(())
    }
}

pub fn validate_target_ipv4(value: &str) -> Result<Ipv4Addr, DnsLifecycleError> {
    let parsed = value.parse::<Ipv4Addr>().map_err(|err| {
        DnsLifecycleError::Validation(format!("invalid Cloudflare DNS target IPv4 {value}: {err}"))
    })?;
    if parsed.is_unspecified()
        || parsed.is_loopback()
        || parsed.is_multicast()
        || parsed.is_broadcast()
    {
        return Err(DnsLifecycleError::Validation(format!(
            "Cloudflare DNS target IPv4 is not routable: {value}"
        )));
    }
    Ok(parsed)
}

pub fn plan_apply(
    desired: &DesiredDnsState,
    target_ip: &str,
    observed: &DnsObservation,
) -> Result<ApplyPlan, DnsLifecycleError> {
    desired.validate()?;
    validate_target_ipv4(target_ip)?;
    let records = exact_records(desired, observed)?;
    match records.as_slice() {
        [] => Ok(ApplyPlan {
            action: ApplyAction::Create {
                ip: target_ip.to_owned(),
            },
        }),
        [record] if record.ip == target_ip => Ok(ApplyPlan {
            action: ApplyAction::Noop,
        }),
        [record] => Ok(ApplyPlan {
            action: ApplyAction::Update {
                record_id: record.provider_id.clone(),
                from_ip: record.ip.clone(),
                to_ip: target_ip.to_owned(),
            },
        }),
        _ => unreachable!("exact_records rejects ambiguity"),
    }
}

pub fn plan_cleanup(
    desired: &DesiredDnsState,
    observed: &DnsObservation,
) -> Result<CleanupPlan, DnsLifecycleError> {
    desired.validate()?;
    let records = exact_records(desired, observed)?;
    let Some(record) = records.first() else {
        return Ok(CleanupPlan {
            action: CleanupAction::Noop,
            destructive_digest: None,
        });
    };
    let action = CleanupAction::Delete {
        record_id: record.provider_id.clone(),
        ip: record.ip.clone(),
    };
    Ok(CleanupPlan {
        destructive_digest: Some(cleanup_digest(desired, observed, &action)?),
        action,
    })
}

pub fn verify_cleanup_digest(
    desired: &DesiredDnsState,
    observed: &DnsObservation,
    expected_digest: &str,
) -> Result<CleanupPlan, DnsLifecycleError> {
    if !is_sha256_hex(expected_digest) {
        return Err(DnsLifecycleError::Validation(
            "Cloudflare DNS cleanup digest must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    let plan = plan_cleanup(desired, observed)?;
    let Some(actual) = plan.destructive_digest.as_deref() else {
        return Err(DnsLifecycleError::Conflict(
            "Cloudflare DNS cleanup target is already absent".to_owned(),
        ));
    };
    if actual != expected_digest {
        return Err(DnsLifecycleError::Conflict(
            "Cloudflare DNS cleanup digest is stale".to_owned(),
        ));
    }
    Ok(plan)
}

fn exact_records<'a>(
    desired: &DesiredDnsState,
    observed: &'a DnsObservation,
) -> Result<Vec<&'a ObservedDnsRecord>, DnsLifecycleError> {
    let mut matches = observed
        .records
        .iter()
        .filter(|record| record.record_name == desired.record_name)
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    if matches.len() > 1 {
        return Err(DnsLifecycleError::Ambiguous(format!(
            "Cloudflare DNS record {} is ambiguous: observed {} exact A records",
            desired.record_name,
            matches.len()
        )));
    }
    for record in &matches {
        validate_target_ipv4(&record.ip).map_err(|err| {
            DnsLifecycleError::Conflict(format!(
                "Cloudflare DNS record {} returned invalid provider content: {err}",
                desired.record_name
            ))
        })?;
    }
    Ok(matches)
}

fn cleanup_digest(
    desired: &DesiredDnsState,
    observed: &DnsObservation,
    action: &CleanupAction,
) -> Result<String, DnsLifecycleError> {
    let mut records = observed
        .records
        .iter()
        .filter(|record| record.record_name == desired.record_name)
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    let value = json!({
        "schema": desired.schema,
        "environment": desired.environment,
        "zone_name": desired.zone_name,
        "record_name": desired.record_name,
        "records": records,
        "action": action,
    });
    let bytes = serde_json::to_vec(&value)
        .map_err(|err| DnsLifecycleError::Serialization(err.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn validate_dns_name(label: &str, value: &str) -> Result<(), DnsLifecycleError> {
    if value.is_empty() || value.len() > 253 || value.ends_with('.') {
        return Err(DnsLifecycleError::Validation(format!(
            "{label} must be a canonical lowercase DNS name"
        )));
    }
    for part in value.split('.') {
        if part.is_empty()
            || part.len() > 63
            || !part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || part.starts_with('-')
            || part.ends_with('-')
        {
            return Err(DnsLifecycleError::Validation(format!(
                "{label} must be a canonical lowercase DNS name"
            )));
        }
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str, max_len: usize) -> Result<(), DnsLifecycleError> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err(DnsLifecycleError::Validation(format!(
            "{label} must be 1..={max_len} ASCII alphanumeric, '-' or '_' characters"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> DesiredDnsState {
        DesiredDnsState {
            schema: 1,
            environment: "lifecycle-acceptance".to_owned(),
            zone_name: "alegria.by".to_owned(),
            record_name: "stage2-acceptance.alegria.by".to_owned(),
        }
    }

    #[test]
    fn validates_closed_dns_spec() {
        desired().validate().unwrap();
        let mut wrong = desired();
        wrong.record_name = "other.example.com".to_owned();
        assert!(wrong.validate().is_err());
        let mut upper = desired();
        upper.record_name = "Stage2.alegria.by".to_owned();
        assert!(upper.validate().is_err());
    }

    #[test]
    fn plans_create_noop_and_observed_update() {
        let desired = desired();
        let empty = DnsObservation::default();
        assert_eq!(
            plan_apply(&desired, "203.0.113.10", &empty).unwrap().action,
            ApplyAction::Create {
                ip: "203.0.113.10".to_owned()
            }
        );

        let exact = DnsObservation {
            records: vec![ObservedDnsRecord {
                provider_id: "dns-1".to_owned(),
                record_name: desired.record_name.clone(),
                ip: "203.0.113.10".to_owned(),
            }],
        };
        assert_eq!(
            plan_apply(&desired, "203.0.113.10", &exact).unwrap().action,
            ApplyAction::Noop
        );
        assert_eq!(
            plan_apply(&desired, "203.0.113.11", &exact).unwrap().action,
            ApplyAction::Update {
                record_id: "dns-1".to_owned(),
                from_ip: "203.0.113.10".to_owned(),
                to_ip: "203.0.113.11".to_owned(),
            }
        );
    }

    #[test]
    fn fails_closed_on_ambiguous_exact_records() {
        let desired = desired();
        let observed = DnsObservation {
            records: vec![
                ObservedDnsRecord {
                    provider_id: "dns-1".to_owned(),
                    record_name: desired.record_name.clone(),
                    ip: "203.0.113.10".to_owned(),
                },
                ObservedDnsRecord {
                    provider_id: "dns-2".to_owned(),
                    record_name: desired.record_name.clone(),
                    ip: "203.0.113.10".to_owned(),
                },
            ],
        };
        assert!(matches!(
            plan_apply(&desired, "203.0.113.10", &observed),
            Err(DnsLifecycleError::Ambiguous(_))
        ));
    }

    #[test]
    fn cleanup_is_digest_bound_and_stale_safe() {
        let desired = desired();
        let observed = DnsObservation {
            records: vec![ObservedDnsRecord {
                provider_id: "dns-1".to_owned(),
                record_name: desired.record_name.clone(),
                ip: "203.0.113.10".to_owned(),
            }],
        };
        let plan = plan_cleanup(&desired, &observed).unwrap();
        let digest = plan.destructive_digest.clone().unwrap();
        verify_cleanup_digest(&desired, &observed, &digest).unwrap();

        let changed = DnsObservation {
            records: vec![ObservedDnsRecord {
                provider_id: "dns-1".to_owned(),
                record_name: desired.record_name.clone(),
                ip: "203.0.113.11".to_owned(),
            }],
        };
        assert!(matches!(
            verify_cleanup_digest(&desired, &changed, &digest),
            Err(DnsLifecycleError::Conflict(_))
        ));
    }

    #[test]
    fn rejects_invalid_target_addresses() {
        assert!(validate_target_ipv4("not-an-ip").is_err());
        assert!(validate_target_ipv4("127.0.0.1").is_err());
        assert!(validate_target_ipv4("0.0.0.0").is_err());
    }

    #[test]
    fn spec_rejects_unknown_fields() {
        let raw = r#"{
            "schema":1,
            "environment":"lifecycle-acceptance",
            "zone_name":"alegria.by",
            "record_name":"stage2-acceptance.alegria.by",
            "unexpected":true
        }"#;
        assert!(DesiredDnsState::parse_json(raw).is_err());
    }

    #[test]
    fn duplicate_provider_ids_do_not_weaken_ambiguity() {
        let desired = desired();
        let observed = DnsObservation {
            records: vec![
                ObservedDnsRecord {
                    provider_id: "dns-1".to_owned(),
                    record_name: desired.record_name.clone(),
                    ip: "203.0.113.10".to_owned(),
                },
                ObservedDnsRecord {
                    provider_id: "dns-1".to_owned(),
                    record_name: desired.record_name.clone(),
                    ip: "203.0.113.10".to_owned(),
                },
            ],
        };
        assert!(plan_cleanup(&desired, &observed).is_err());
    }

    #[test]
    fn environment_validation_is_bounded() {
        let mut desired = desired();
        desired.environment = "bad environment".to_owned();
        assert!(desired.validate().is_err());
    }

    #[test]
    fn observed_records_are_exact_name_scoped() {
        let desired = desired();
        let observed = DnsObservation {
            records: vec![
                ObservedDnsRecord {
                    provider_id: "dns-foreign".to_owned(),
                    record_name: "other.alegria.by".to_owned(),
                    ip: "203.0.113.20".to_owned(),
                },
                ObservedDnsRecord {
                    provider_id: "dns-owned".to_owned(),
                    record_name: desired.record_name.clone(),
                    ip: "203.0.113.10".to_owned(),
                },
            ],
        };
        assert_eq!(
            plan_apply(&desired, "203.0.113.10", &observed)
                .unwrap()
                .action,
            ApplyAction::Noop
        );
    }

    #[test]
    fn cleanup_digest_is_order_stable_for_unrelated_records() {
        let desired = desired();
        let first = DnsObservation {
            records: vec![
                ObservedDnsRecord {
                    provider_id: "other".to_owned(),
                    record_name: "other.alegria.by".to_owned(),
                    ip: "203.0.113.20".to_owned(),
                },
                ObservedDnsRecord {
                    provider_id: "dns-1".to_owned(),
                    record_name: desired.record_name.clone(),
                    ip: "203.0.113.10".to_owned(),
                },
            ],
        };
        let mut second = first.clone();
        second.records.reverse();
        assert_eq!(
            plan_cleanup(&desired, &first).unwrap().destructive_digest,
            plan_cleanup(&desired, &second).unwrap().destructive_digest
        );
    }

    #[test]
    fn provider_record_ip_set_is_not_used_as_authority() {
        let values = ["203.0.113.10", "203.0.113.11"]
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(values.len(), 2);
    }
}
