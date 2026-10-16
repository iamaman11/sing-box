//! Pure non-secret admissibility for one existing Windows ACTIVE A -> VM B join.
//! GitHub is the single remote coordinator, and the authenticated SYSTEM/root
//! owners must collect these witnesses. A JSON flag is NEVER host authentication
//! or mutation authority. This module cannot contact Worker or mutate hosts.
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;

const MARKER: &str = "<!-- sing-box-credential-existing-join/v1 -->";
const FAMILY: &str = "<!-- sing-box-credential-existing-join/";
const SCHEMA: &str = "sing-box.credential-existing-join/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Witness {
    pub generation: u64,
    pub slot: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExistingJoinIntent {
    pub schema: String,
    pub run_id: u64,
    pub accepted_revision: String,
    pub release_set_sha256: String,
    pub windows_active: Witness,
    pub windows_candidate: Witness,
    pub vm_candidate: Witness,
    // Each check must be performed by the protected workflow using actual
    // owner-origin readback. Self-declared true is NOT authorization.
    pub windows_worker_both_exact: bool,
    pub windows_stopped_proxy_only: bool,
    pub windows_line1_four_authenticated: bool,
    pub vm_worker_candidate_exact: bool,
    pub vm_line2_six_authenticated: bool,
}

fn lower_hex(text: &str, size: usize) -> bool {
    text.len() == size
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn validate(spec: &ExistingJoinIntent, revision: &str, release: &str) -> Result<(), String> {
    let a = &spec.windows_active;
    let b = &spec.windows_candidate;
    let vm = &spec.vm_candidate;
    if spec.schema != SCHEMA
        || spec.run_id == 0
        || !lower_hex(&spec.accepted_revision, 40)
        || !lower_hex(&spec.release_set_sha256, 64)
        || spec.accepted_revision != revision
        || spec.release_set_sha256 != release
        || a.generation == 0
        || b.generation == 0
        || a.generation == b.generation
        || b.generation != vm.generation
        || a.slot != "A"
        || b.slot != "B"
        || vm.slot != "B"
        || !lower_hex(&a.sha256, 64)
        || !lower_hex(&b.sha256, 64)
        || !lower_hex(&vm.sha256, 64)
        || a.sha256 == b.sha256
        || a.sha256 == vm.sha256
        || b.sha256 == vm.sha256
        || !spec.windows_worker_both_exact
        || !spec.windows_stopped_proxy_only
        || !spec.windows_line1_four_authenticated
        || !spec.vm_worker_candidate_exact
        || !spec.vm_line2_six_authenticated
    {
        return Err("existing-active join blocked: exact A/B release, origin or functional witnesses missing".to_owned());
    }
    Ok(())
}

fn records(history: &str) -> Result<Vec<String>, String> {
    let array: Vec<serde_json::Value> = serde_json::from_str(history)
        .map_err(|_| "join journal must be a complete JSON comment array".to_owned())?;
    let mut found = Vec::new();
    for value in array {
        let body = value
            .get("body")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "join journal has a missing comment body".to_owned())?;
        if body.trim().is_empty() {
            return Err("join journal has an empty comment body".to_owned());
        }
        if body.contains(FAMILY) {
            if !body.starts_with(&format!("{MARKER}\n")) {
                return Err("join journal has displaced or unsupported marker".to_owned());
            }
            found.push(body.to_owned());
        }
        if body.starts_with("<!-- sing-box-credential-paired-commit/") {
            return Err("join journal refuses a concurrent first-use paired commit".to_owned());
        }
    }
    Ok(found)
}

pub(crate) fn plan(
    spec: &ExistingJoinIntent,
    history: &str,
    revision: &str,
    release: &str,
) -> Result<String, String> {
    validate(spec, revision, release)?;
    if !records(history)?.is_empty() {
        return Err("existing-active join was already requested: no replay".to_owned());
    }
    let body = serde_json::to_string(spec)
        .map_err(|_| "existing-active join record encoding failed".to_owned())?;
    Ok(format!("{MARKER}\n{body}"))
}

pub(crate) fn readback(
    spec: &ExistingJoinIntent,
    history: &str,
    exact: &str,
    revision: &str,
    release: &str,
) -> Result<(), String> {
    validate(spec, revision, release)?;
    let raw = exact
        .strip_prefix(&format!("{MARKER}\n"))
        .ok_or_else(|| "existing-active join readback marker missing".to_owned())?;
    let actual: ExistingJoinIntent = serde_json::from_str(raw)
        .map_err(|_| "existing-active join readback record malformed".to_owned())?;
    if actual != *spec || serde_json::to_string(&actual).ok().as_deref() != Some(raw) {
        return Err(
            "existing-active join record differs from exact immutable witnesses".to_owned(),
        );
    }
    let history_records = records(history)?;
    if history_records.len() != 1 || history_records[0] != exact {
        return Err("existing-active join requires exactly one durable matching intent".to_owned());
    }
    Ok(())
}

/// Independently collected NON-SECRET post-state. The trusted GitHub owner
/// must reconstruct this from the actual SYSTEM/root process; this JSON is
/// untrusted when supplied by an operator. This classifier NEVER mutates.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExistingJoinSnapshot {
    pub(crate) windows_active: Witness,
    pub(crate) windows_candidate: Option<Witness>,
    pub(crate) windows_previous: Option<Witness>,
    pub(crate) vm_active: Option<Witness>,
    pub(crate) vm_candidate: Option<Witness>,
    pub(crate) vm_join_receipt_intent_sha256: Option<String>,
    pub(crate) windows_worker_origin_verified: bool,
    pub(crate) vm_worker_origin_verified: bool,
    pub(crate) windows_stopped_proxy_only: bool,
    pub(crate) line1_authenticated_endpoints: u8,
    pub(crate) line2_authenticated_endpoints: u8,
}

/// A single, bounded status/recovery decision, never an instruction to replay.
/// Full paired ACTIVE still requires independent network acceptance after the
/// cursor readback; a lost ACK is not a new mutation authorization.
pub(crate) fn reconcile(
    spec: &ExistingJoinIntent,
    history: &str,
    exact: &str,
    revision: &str,
    release: &str,
    snapshot: &ExistingJoinSnapshot,
) -> Result<&'static str, String> {
    readback(spec, history, exact, revision, release)?;
    let expected_digest = {
        use ring::digest::{SHA256, digest};
        digest(&SHA256, exact.as_bytes())
            .as_ref()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>()
    };
    if !snapshot.windows_worker_origin_verified
        || !snapshot.vm_worker_origin_verified
        || !snapshot.windows_stopped_proxy_only
        || snapshot.line1_authenticated_endpoints != 4
        || snapshot.line2_authenticated_endpoints != 6
    {
        return Ok("SAFE_BLOCKED_UNPROVEN_OWNER_OR_NETWORK");
    }
    let a = &spec.windows_active;
    let b = &spec.windows_candidate;
    let vm = &spec.vm_candidate;
    let win_is_a = &snapshot.windows_active == a;
    let win_is_b = &snapshot.windows_active == b;
    let vm_is_b = snapshot.vm_active.as_ref() == Some(vm);
    let vm_candidate_b = snapshot.vm_candidate.as_ref() == Some(vm);
    let receipt_correct =
        snapshot.vm_join_receipt_intent_sha256.as_deref() == Some(expected_digest.as_str());
    let receipt_absent = snapshot.vm_join_receipt_intent_sha256.is_none();
    if win_is_a
        && snapshot.windows_candidate.as_ref() == Some(b)
        && snapshot.windows_previous.is_none()
        && snapshot.vm_active.is_none()
        && vm_candidate_b
        && receipt_absent
    {
        return Ok("INTENT_DURABLE_PREPARED_NO_AUTO_APPLY");
    }
    if win_is_b
        && snapshot.windows_candidate.is_none()
        && snapshot.windows_previous.as_ref() == Some(a)
        && vm_is_b
        && snapshot.vm_candidate.is_none()
        && receipt_correct
    {
        return Ok("POINTERS_COMPLETE_REQUIRES_INDEPENDENT_ACCEPTANCE");
    }
    if (win_is_a || win_is_b)
        && (vm_is_b || vm_candidate_b)
        && (snapshot.vm_join_receipt_intent_sha256.is_none() || receipt_correct)
    {
        return Ok("PARTIAL_SAFE_BLOCKED_NO_REPLAY");
    }
    Ok("UNKNOWN_SAFE_BLOCKED_NO_REPLAY")
}

pub(crate) fn dispatch(
    command: &crate::cli::CredentialDeliveryCommand,
    revision: &str,
    release: &str,
) -> Result<(), String> {
    use crate::cli::CredentialDeliveryCommand;
    match command {
        CredentialDeliveryCommand::ExistingJoinPlan {
            spec_path,
            journal_history_path,
            record_output_path,
        } => {
            let spec: ExistingJoinIntent = serde_json::from_slice(
                &fs::read(spec_path).map_err(|_| "existing join spec unavailable")?,
            )
            .map_err(|_| "existing join spec invalid")?;
            let history = fs::read_to_string(journal_history_path)
                .map_err(|_| "existing join history unavailable")?;
            let text = plan(&spec, &history, revision, release)?;
            // Create-new local non-secret intent; the coordinator separately
            // appends ONE GitHub comment and reads it back before host writes.
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(record_output_path)
                .map_err(|_| "existing join local record already exists or UNKNOWN")?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| "existing join local record write UNKNOWN")?;
            println!("existing_join_policy=INTENT_PLANNED_LOCAL_ONLY");
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::ExistingJoinReadback {
            spec_path,
            journal_history_path,
            exact_record_path,
        } => {
            let spec: ExistingJoinIntent = serde_json::from_slice(
                &fs::read(spec_path).map_err(|_| "existing join spec unavailable")?,
            )
            .map_err(|_| "existing join spec invalid")?;
            let history = fs::read_to_string(journal_history_path)
                .map_err(|_| "existing join history unavailable")?;
            let exact = fs::read_to_string(exact_record_path)
                .map_err(|_| "existing join exact record unavailable")?;
            readback(&spec, &history, &exact, revision, release)?;
            println!("existing_join_intent=EXACT_DURABLE_ONCE");
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::ExistingJoinReconcile {
            spec_path,
            journal_history_path,
            exact_record_path,
            snapshot_path,
        } => {
            let spec: ExistingJoinIntent = serde_json::from_slice(
                &fs::read(spec_path).map_err(|_| "existing join spec unavailable")?,
            )
            .map_err(|_| "existing join spec invalid")?;
            let snapshot: ExistingJoinSnapshot = serde_json::from_slice(
                &fs::read(snapshot_path).map_err(|_| "existing join owner snapshot unavailable")?,
            )
            .map_err(|_| "existing join owner snapshot invalid")?;
            let history = fs::read_to_string(journal_history_path)
                .map_err(|_| "existing join history unavailable")?;
            let exact = fs::read_to_string(exact_record_path)
                .map_err(|_| "existing join exact intent unavailable")?;
            let decision = reconcile(&spec, &history, &exact, revision, release, &snapshot)?;
            println!("existing_join_state={decision}");
            println!("credential_mutation_allowed=false");
            println!("credential_mutation_replayed=false");
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            Ok(())
        }
        _ => Err("existing join policy received unrelated command".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> ExistingJoinIntent {
        ExistingJoinIntent {
            schema: SCHEMA.to_owned(),
            run_id: 345,
            accepted_revision: "a".repeat(40),
            release_set_sha256: "b".repeat(64),
            windows_active: Witness {
                generation: 101,
                slot: "A".to_owned(),
                sha256: "c".repeat(64),
            },
            windows_candidate: Witness {
                generation: 202,
                slot: "B".to_owned(),
                sha256: "d".repeat(64),
            },
            vm_candidate: Witness {
                generation: 202,
                slot: "B".to_owned(),
                sha256: "e".repeat(64),
            },
            windows_worker_both_exact: true,
            windows_stopped_proxy_only: true,
            windows_line1_four_authenticated: true,
            vm_worker_candidate_exact: true,
            vm_line2_six_authenticated: true,
        }
    }
    #[test]
    fn positive_plan_and_exact_history_readback() {
        let g = good();
        let record = plan(&g, "[]", &g.accepted_revision, &g.release_set_sha256).unwrap();
        let history = serde_json::json!([{"body":record}]).to_string();
        let expected = format!("{MARKER}\n{}", serde_json::to_string(&g).unwrap());
        readback(
            &g,
            &history,
            &expected,
            &g.accepted_revision,
            &g.release_set_sha256,
        )
        .unwrap();
        assert!(plan(&g, &history, &g.accepted_revision, &g.release_set_sha256).is_err());
    }
    #[test]
    fn false_origin_mismatch_slot_or_release_blocks() {
        let g = good();
        for changed in [
            ExistingJoinIntent {
                vm_worker_candidate_exact: false,
                ..g.clone()
            },
            ExistingJoinIntent {
                windows_line1_four_authenticated: false,
                ..g.clone()
            },
            ExistingJoinIntent {
                windows_candidate: g.windows_active.clone(),
                ..g.clone()
            },
            ExistingJoinIntent {
                release_set_sha256: "f".repeat(64),
                ..g.clone()
            },
        ] {
            assert!(plan(&changed, "[]", &g.accepted_revision, &g.release_set_sha256).is_err());
        }
    }
    #[test]
    fn torn_or_duplicate_intent_blocks_and_no_implicit_retry() {
        let g = good();
        let record = plan(&g, "[]", &g.accepted_revision, &g.release_set_sha256).unwrap();
        let duplicate = serde_json::json!([{"body":record},{"body":record}]).to_string();
        assert!(
            readback(
                &g,
                &duplicate,
                &record,
                &g.accepted_revision,
                &g.release_set_sha256
            )
            .is_err()
        );
        assert!(plan(&g, &duplicate, &g.accepted_revision, &g.release_set_sha256).is_err());
        let partial = serde_json::json!([{"body":"<!-- sing-box-credential-existing-join/v2 -->"}])
            .to_string();
        assert!(plan(&g, &partial, &g.accepted_revision, &g.release_set_sha256).is_err());
    }

    fn snapshot(spec: &ExistingJoinIntent) -> ExistingJoinSnapshot {
        ExistingJoinSnapshot {
            windows_active: spec.windows_active.clone(),
            windows_candidate: Some(spec.windows_candidate.clone()),
            windows_previous: None,
            vm_active: None,
            vm_candidate: Some(spec.vm_candidate.clone()),
            vm_join_receipt_intent_sha256: None,
            windows_worker_origin_verified: true,
            vm_worker_origin_verified: true,
            windows_stopped_proxy_only: true,
            line1_authenticated_endpoints: 4,
            line2_authenticated_endpoints: 6,
        }
    }

    fn classify(spec: &ExistingJoinIntent, state: &ExistingJoinSnapshot) -> &'static str {
        let record = plan(spec, "[]", &spec.accepted_revision, &spec.release_set_sha256).unwrap();
        let history = serde_json::json!([{"body":record}]).to_string();
        reconcile(
            spec, &history, &record, &spec.accepted_revision,
            &spec.release_set_sha256, state,
        ).unwrap()
    }

    #[test]
    fn exact_durable_prepared_state_does_not_automatically_apply() {
        let g = good();
        assert_eq!(
            classify(&g, &snapshot(&g)),
            "INTENT_DURABLE_PREPARED_NO_AUTO_APPLY"
        );
    }

    #[test]
    fn half_committed_vm_join_refuses_automatic_replay() {
        let g = good();
        let intent = plan(&g, "[]", &g.accepted_revision, &g.release_set_sha256).unwrap();
        let digest = {
            use ring::digest::{SHA256, digest};
            digest(&SHA256, intent.as_bytes())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let mut s = snapshot(&g);
        s.vm_candidate = None;
        s.vm_active = Some(g.vm_candidate.clone());
        s.vm_join_receipt_intent_sha256 = Some(digest);
        assert_eq!(classify(&g, &s), "PARTIAL_SAFE_BLOCKED_NO_REPLAY");
    }

    #[test]
    fn completed_pointers_still_require_independent_acceptance() {
        let g = good();
        let record = plan(&g, "[]", &g.accepted_revision, &g.release_set_sha256).unwrap();
        let digest = {
            use ring::digest::{SHA256, digest};
            digest(&SHA256, record.as_bytes())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let mut s = snapshot(&g);
        s.windows_active = g.windows_candidate.clone();
        s.windows_candidate = None;
        s.windows_previous = Some(g.windows_active.clone());
        s.vm_active = Some(g.vm_candidate.clone());
        s.vm_candidate = None;
        s.vm_join_receipt_intent_sha256 = Some(digest);
        assert_eq!(classify(&g, &s), "POINTERS_COMPLETE_REQUIRES_INDEPENDENT_ACCEPTANCE");
        s.vm_join_receipt_intent_sha256 = Some("e".repeat(64));
        assert_eq!(classify(&g, &s), "UNKNOWN_SAFE_BLOCKED_NO_REPLAY");
    }

    #[test]
    fn incomplete_or_unproven_snapshot_is_blocked() {
        let g = good();
        let mut s = snapshot(&g);
        s.windows_worker_origin_verified = false;
        assert_eq!(classify(&g, &s), "SAFE_BLOCKED_UNPROVEN_OWNER_OR_NETWORK");
        s.windows_worker_origin_verified = true;
        s.line2_authenticated_endpoints = 5;
        assert_eq!(classify(&g, &s), "SAFE_BLOCKED_UNPROVEN_OWNER_OR_NETWORK");
    }

}
