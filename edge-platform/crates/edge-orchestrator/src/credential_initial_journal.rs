//! Pure non-secret admission policy for exactly one first-use credential
//! transaction. GitHub issue #26's durable comments are an audit journal,
//! never a second desired-state or secret authority. No provider mutation or
//! history write is performed in this module.
use edge_shared_types::{CREDENTIAL_DUMMY_PROBE_GENERATION_A, CREDENTIAL_DUMMY_PROBE_GENERATION_B};
use serde::{Deserialize, Serialize};

const MARKER_FAMILY: &str = "<!-- sing-box-credential-initial-attempt/";
const MARKER: &str = "<!-- sing-box-credential-initial-attempt/v1 -->";
const SCHEMA: &str = "sing-box.credential-initial-attempt/v1";

#[derive(Debug, Clone)]
pub(crate) struct InitialPairJournalPlan {
    pub(crate) generation: u64,
    pub(crate) slot: String,
    pub(crate) provider_intent_sha256: String,
    pub(crate) vm_attestation_sha256: String,
    pub(crate) windows_attestation_sha256: String,
    pub(crate) release_source_revision: String,
    pub(crate) release_set_sha256: String,
    pub(crate) github_run_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptRecord {
    schema: String,
    phase: String,
    generation: u64,
    slot: String,
    provider_intent_sha256: String,
    vm_attestation_sha256: String,
    windows_attestation_sha256: String,
    release_source_revision: String,
    release_set_sha256: String,
    github_run_id: u64,
}

#[derive(Deserialize)]
struct IssueComment {
    body: Option<String>,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_request(request: &InitialPairJournalPlan) -> Result<(), String> {
    if request.generation == 0
        || request.generation == CREDENTIAL_DUMMY_PROBE_GENERATION_A
        || request.generation == CREDENTIAL_DUMMY_PROBE_GENERATION_B
        || request.github_run_id == 0
        || (request.slot != "A" && request.slot != "B")
    {
        return Err(
            "initial journal requires one real generation, fixed slot and run ID".to_owned(),
        );
    }
    for (name, value) in [
        ("provider intent", &request.provider_intent_sha256),
        ("VM attestation", &request.vm_attestation_sha256),
        ("Windows attestation", &request.windows_attestation_sha256),
        ("source revision", &request.release_source_revision),
        ("release set", &request.release_set_sha256),
    ] {
        if !valid_sha256(value) {
            return Err(format!(
                "initial journal requires exact lowercase SHA-256 for {name}"
            ));
        }
    }
    if request.vm_attestation_sha256 == request.windows_attestation_sha256 {
        return Err("initial journal rejects identical VM and Windows attestations".to_owned());
    }
    Ok(())
}

pub(crate) fn require_empty_initial_history(history: &str) -> Result<(), String> {
    validate_journal_history(history)
}

fn validate_journal_history(history: &str) -> Result<(), String> {
    // GitHub pagination is materialized by the trusted caller as a single
    // array. A malformed/partial read is a hard stop, never an empty ledger.
    let comments: Vec<IssueComment> = serde_json::from_str(history)
        .map_err(|_| "initial journal history must be complete JSON comment array".to_owned())?;
    for comment in comments {
        let Some(body) = comment.body else {
            continue;
        };
        if body.contains(MARKER_FAMILY) {
            // No source may regenerate the first-use pair, even if an earlier
            // attempt was interrupted before PATCH. A missing/invalid record
            // is unknown, NOT permission to replay a mutation.
            let content = body.strip_prefix(MARKER).ok_or_else(|| {
                "initial journal contains displaced attempt marker; refusing issuance".to_owned()
            })?;
            let record: AttemptRecord = serde_json::from_str(content.trim()).map_err(|_| {
                "initial journal contains malformed attempt; refusing issuance".to_owned()
            })?;
            if record.schema != SCHEMA || record.phase != "BEGIN" {
                return Err(
                    "initial journal contains unknown attempt phase; refusing issuance".to_owned(),
                );
            }
            return Err(format!(
                "initial journal already has durable BEGIN in run {}; no replay or new initial issuance",
                record.github_run_id
            ));
        }
    }
    Ok(())
}

/// Return a non-secret GitHub issue comment body for a caller that has already
/// independently established BOTH owner-origin host attestations. Merely
/// passing hex digests here must never be treated as host authentication.
pub(crate) fn plan_initial_pair_reservation(
    request: &InitialPairJournalPlan,
    history: &str,
) -> Result<String, String> {
    validate_request(request)?;
    validate_journal_history(history)?;
    let record = AttemptRecord {
        schema: SCHEMA.to_owned(),
        phase: "BEGIN".to_owned(),
        generation: request.generation,
        slot: request.slot.clone(),
        provider_intent_sha256: request.provider_intent_sha256.clone(),
        vm_attestation_sha256: request.vm_attestation_sha256.clone(),
        windows_attestation_sha256: request.windows_attestation_sha256.clone(),
        release_source_revision: request.release_source_revision.clone(),
        release_set_sha256: request.release_set_sha256.clone(),
        github_run_id: request.github_run_id,
    };
    let encoded = serde_json::to_string(&record)
        .map_err(|err| format!("initial journal cannot encode reservation: {err}"))?;
    Ok(format!("{MARKER}\n{encoded}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> InitialPairJournalPlan {
        InitialPairJournalPlan {
            generation: 101,
            slot: "A".to_owned(),
            provider_intent_sha256: "a".repeat(64),
            vm_attestation_sha256: "b".repeat(64),
            windows_attestation_sha256: "c".repeat(64),
            release_source_revision: "d".repeat(64),
            release_set_sha256: "e".repeat(64),
            github_run_id: 1011,
        }
    }

    #[test]
    fn initial_reservation_is_exact_nonsecret_single_use() {
        let record = plan_initial_pair_reservation(&request(), "[]").unwrap();
        assert!(record.starts_with(MARKER));
        assert!(!record.contains("secret_text"));
        assert!(!record.contains("password"));
        let history = serde_json::json!([{"body": record}]).to_string();
        assert!(
            plan_initial_pair_reservation(&request(), &history)
                .unwrap_err()
                .contains("no replay")
        );
        let different = InitialPairJournalPlan {
            generation: 102,
            ..request()
        };
        assert!(plan_initial_pair_reservation(&different, &history).is_err());
    }

    #[test]
    fn corrupted_or_ambiguous_history_is_never_an_empty_journal() {
        for body in [
            "not json",
            "[",
            r#"[{"body":"<!-- sing-box-credential-initial-attempt/v1 --> broken"}]"#,
            r#"[{"body":"ignored <!-- sing-box-credential-initial-attempt/v1 --> {}"}]"#,
            r#"[{"body":"<!-- sing-box-credential-initial-attempt/v2 --> {}"}]"#,
            r#"[{"body":"<!-- sing-box-credential-initial-attempt/v1 --> {\"schema\":\"unknown\"}"}]"#,
        ] {
            assert!(plan_initial_pair_reservation(&request(), body).is_err());
        }
        assert!(
            plan_initial_pair_reservation(&request(), r#"[{"body":"normal issue comment"}]"#)
                .is_ok()
        );
    }

    #[test]
    fn rejects_dummy_generations_missing_attestation_and_bad_digests() {
        for generation in [
            0,
            CREDENTIAL_DUMMY_PROBE_GENERATION_A,
            CREDENTIAL_DUMMY_PROBE_GENERATION_B,
        ] {
            assert!(
                plan_initial_pair_reservation(
                    &InitialPairJournalPlan {
                        generation,
                        ..request()
                    },
                    "[]"
                )
                .is_err()
            );
        }
        for bad in ["", "a", "A".repeat(64).as_str(), "g".repeat(64).as_str()] {
            assert!(
                plan_initial_pair_reservation(
                    &InitialPairJournalPlan {
                        vm_attestation_sha256: bad.to_owned(),
                        ..request()
                    },
                    "[]"
                )
                .is_err()
            );
        }
        assert!(
            plan_initial_pair_reservation(
                &InitialPairJournalPlan {
                    windows_attestation_sha256: "b".repeat(64),
                    ..request()
                },
                "[]"
            )
            .is_err()
        );
        assert!(
            plan_initial_pair_reservation(
                &InitialPairJournalPlan {
                    github_run_id: 0,
                    ..request()
                },
                "[]"
            )
            .is_err()
        );
    }
}
