use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

pub const PLAN_AUTHORITY_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanDisposition {
    Noop,
    Mutate,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationState {
    Converged,
    MutationRequired,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAuthority {
    pub schema_version: u32,
    pub domain: String,
    pub desired_digest: String,
    pub observed_digest: String,
    pub plan_digest: String,
    pub authority_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedPlan<P> {
    pub disposition: PlanDisposition,
    pub authority: PlanAuthority,
    pub plan: P,
}

impl<P> AuthorizedPlan<P> {
    pub const fn verification_state(&self) -> VerificationState {
        match self.disposition {
            PlanDisposition::Noop => VerificationState::Converged,
            PlanDisposition::Mutate => VerificationState::MutationRequired,
            PlanDisposition::Blocked => VerificationState::Blocked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanAuthorityError {
    InvalidDomain,
    Serialization(String),
    InvalidDigest,
    Stale {
        authorized: String,
        current: String,
    },
}

impl fmt::Display for PlanAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomain => write!(
                f,
                "plan authority domain must be a bounded lowercase ASCII identifier"
            ),
            Self::Serialization(detail) => {
                write!(f, "failed to canonicalize plan authority material: {detail}")
            }
            Self::InvalidDigest => {
                write!(f, "plan authority digest must be 64 lowercase hexadecimal characters")
            }
            Self::Stale {
                authorized,
                current,
            } => write!(
                f,
                "plan authority is stale: authorized={authorized} current={current}"
            ),
        }
    }
}

impl std::error::Error for PlanAuthorityError {}

#[derive(Serialize)]
struct AuthorityMaterial<'a> {
    schema_version: u32,
    domain: &'a str,
    disposition: PlanDisposition,
    desired_digest: &'a str,
    observed_digest: &'a str,
    plan_digest: &'a str,
}

pub fn authorize_plan<D, O, P>(
    domain: &str,
    desired: &D,
    observed: &O,
    plan: P,
    disposition: PlanDisposition,
) -> Result<AuthorizedPlan<P>, PlanAuthorityError>
where
    D: Serialize + ?Sized,
    O: Serialize + ?Sized,
    P: Serialize,
{
    validate_domain(domain)?;
    let desired_digest = canonical_digest(desired)?;
    let observed_digest = canonical_digest(observed)?;
    let plan_digest = canonical_digest(&plan)?;
    let material = AuthorityMaterial {
        schema_version: PLAN_AUTHORITY_SCHEMA,
        domain,
        disposition,
        desired_digest: &desired_digest,
        observed_digest: &observed_digest,
        plan_digest: &plan_digest,
    };
    let authority_digest = canonical_digest(&material)?;

    Ok(AuthorizedPlan {
        disposition,
        authority: PlanAuthority {
            schema_version: PLAN_AUTHORITY_SCHEMA,
            domain: domain.to_owned(),
            desired_digest,
            observed_digest,
            plan_digest,
            authority_digest,
        },
        plan,
    })
}

pub fn verify_exact_authority(
    authorized_digest: &str,
    current: &PlanAuthority,
) -> Result<(), PlanAuthorityError> {
    if !is_sha256_hex(authorized_digest) {
        return Err(PlanAuthorityError::InvalidDigest);
    }
    if current.authority_digest != authorized_digest {
        return Err(PlanAuthorityError::Stale {
            authorized: authorized_digest.to_owned(),
            current: current.authority_digest.clone(),
        });
    }
    Ok(())
}

pub fn canonical_digest<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, PlanAuthorityError> {
    let value = serde_json::to_value(value)
        .map_err(|err| PlanAuthorityError::Serialization(err.to_string()))?;
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|err| PlanAuthorityError::Serialization(err.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut entries = values.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key, canonicalize(value));
            }
            Value::Object(canonical)
        }
        scalar => scalar,
    }
}

fn validate_domain(domain: &str) -> Result<(), PlanAuthorityError> {
    if domain.is_empty()
        || domain.len() > 96
        || domain.trim() != domain
        || !domain.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(PlanAuthorityError::InvalidDomain);
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn plan_authority_binds_desired_observed_and_plan() {
        let first = authorize_plan(
            "cloudflare_dns",
            &json!({"record": "edge.example.com"}),
            &json!({"records": []}),
            json!({"action": "CREATE", "ip": "203.0.113.10"}),
            PlanDisposition::Mutate,
        )
        .unwrap();
        let changed = authorize_plan(
            "cloudflare_dns",
            &json!({"record": "edge.example.com"}),
            &json!({"records": [{"id": "r1", "ip": "203.0.113.9"}]}),
            json!({"action": "UPDATE", "ip": "203.0.113.10"}),
            PlanDisposition::Mutate,
        )
        .unwrap();

        assert_ne!(
            first.authority.authority_digest,
            changed.authority.authority_digest
        );
        assert!(verify_exact_authority(
            &first.authority.authority_digest,
            &first.authority
        )
        .is_ok());
        assert!(matches!(
            verify_exact_authority(
                &first.authority.authority_digest,
                &changed.authority
            ),
            Err(PlanAuthorityError::Stale { .. })
        ));
    }

    #[test]
    fn canonical_digest_ignores_json_object_insertion_order() {
        let left = json!({"a": 1, "b": {"x": 2, "y": 3}});
        let right: Value =
            serde_json::from_str(r#"{"b":{"y":3,"x":2},"a":1}"#).unwrap();
        assert_eq!(
            canonical_digest(&left).unwrap(),
            canonical_digest(&right).unwrap()
        );
    }

    #[test]
    fn noop_is_the_only_converged_disposition() {
        let plan = authorize_plan(
            "application",
            &json!({"desired": 1}),
            &json!({"observed": 1}),
            json!({"action": "NOOP"}),
            PlanDisposition::Noop,
        )
        .unwrap();
        assert_eq!(plan.verification_state(), VerificationState::Converged);
    }

    proptest! {
        #[test]
        fn authority_is_deterministic_for_identical_material(
            desired in "[a-z0-9-]{1,32}",
            observed in 0u64..1_000_000,
            plan in 0u64..1_000_000,
        ) {
            let first = authorize_plan(
                "vultr_machine",
                &desired,
                &observed,
                plan,
                PlanDisposition::Mutate,
            ).unwrap();
            let second = authorize_plan(
                "vultr_machine",
                &desired,
                &observed,
                plan,
                PlanDisposition::Mutate,
            ).unwrap();
            prop_assert_eq!(first.authority, second.authority);
        }
    }
}
