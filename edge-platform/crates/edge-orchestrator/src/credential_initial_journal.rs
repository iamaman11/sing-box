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
    body: String,
}

fn valid_git_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        ("release set", &request.release_set_sha256),
    ] {
        if !valid_sha256(value) {
            return Err(format!(
                "initial journal requires exact lowercase SHA-256 for {name}"
            ));
        }
    }
    if !valid_git_revision(&request.release_source_revision) {
        return Err(
            "initial journal requires exact lowercase 40-character Git source revision".to_owned(),
        );
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
        let body = comment.body;
        if body.trim().is_empty() {
            return Err("initial journal refuses an empty issue comment body".to_owned());
        }
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

/// Verify exactly one **already persisted** GitHub BEGIN with the entire
/// original record unchanged. This is read-only and is not permission to PATCH:
/// only an independently authorized, single-run host+provider owner may
/// pass through the subsequent mutation gate.
pub(crate) fn verify_recorded_initial_attempt(
    history: &str,
    exact_record: &str,
) -> Result<(), String> {
    let (marker, content) = exact_record
        .split_once('\n')
        .ok_or_else(|| "initial journal readback requires canonical record marker".to_owned())?;
    if marker != MARKER || content.trim().is_empty() {
        return Err("initial journal readback refuses malformed record marker".to_owned());
    }
    let record: AttemptRecord = serde_json::from_str(content)
        .map_err(|_| "initial journal readback refuses invalid JSON record".to_owned())?;
    if record.schema != SCHEMA || record.phase != "BEGIN" {
        return Err("initial journal readback requires exact BEGIN schema".to_owned());
    }
    validate_request(&InitialPairJournalPlan {
        generation: record.generation,
        slot: record.slot,
        provider_intent_sha256: record.provider_intent_sha256,
        vm_attestation_sha256: record.vm_attestation_sha256,
        windows_attestation_sha256: record.windows_attestation_sha256,
        release_source_revision: record.release_source_revision,
        release_set_sha256: record.release_set_sha256,
        github_run_id: record.github_run_id,
    })?;
    let comments: Vec<IssueComment> = serde_json::from_str(history).map_err(|_| {
        "initial journal readback requires complete GitHub comment array".to_owned()
    })?;
    let mut seen = 0;
    for comment in comments {
        if comment.body.trim().is_empty() {
            return Err("initial journal readback refuses empty or incomplete comment".to_owned());
        }
        if comment.body.contains(MARKER_FAMILY) {
            if comment.body != exact_record {
                return Err(
                    "initial journal readback detected different or malformed BEGIN".to_owned(),
                );
            }
            seen += 1;
        }
    }
    if seen != 1 {
        return Err("initial journal readback requires one and only one durable BEGIN".to_owned());
    }
    Ok(())
}

/// Exact one-shot reservation identity, checked against immutable ReleaseSet
/// and BOTH independently trusted host attestations. A verified GitHub comment
/// is a necessary durable barrier but is *not* proof of host job provenance.
pub(crate) fn verify_expected_initial_attempt(
    history: &str,
    exact_record: &str,
    expected: &InitialPairJournalPlan,
) -> Result<(), String> {
    validate_request(expected)?;
    verify_recorded_initial_attempt(history, exact_record)?;
    let (_, body) = exact_record
        .split_once('\n')
        .ok_or_else(|| "expected initial attempt has no record body".to_owned())?;
    let record: AttemptRecord = serde_json::from_str(body)
        .map_err(|_| "expected initial attempt has malformed body".to_owned())?;
    if record.generation != expected.generation
        || record.slot != expected.slot
        || record.provider_intent_sha256 != expected.provider_intent_sha256
        || record.vm_attestation_sha256 != expected.vm_attestation_sha256
        || record.windows_attestation_sha256 != expected.windows_attestation_sha256
        || record.release_source_revision != expected.release_source_revision
        || record.release_set_sha256 != expected.release_set_sha256
        || record.github_run_id != expected.github_run_id
    {
        return Err(
            "durable initial BEGIN does not equal current host/provider/release intent".to_owned(),
        );
    }
    Ok(())
}

/// Verify the original durable GitHub BEGIN once again before the exact
/// disposable VM runtime applies a candidate. Reconciliation never issues,
/// regenerates or repairs credentials.
pub(crate) fn verify_initial_vm_runtime_gate(
    history: &str,
    exact_record: &str,
    generation: u64,
    source_revision: &str,
    release_set_sha256: &str,
    github_run_id: u64,
) -> Result<(), String> {
    verify_recorded_initial_attempt(history, exact_record)?;
    let (_, body) = exact_record
        .split_once('\n')
        .ok_or_else(|| "VM runtime requires exact initial BEGIN marker".to_owned())?;
    let record: AttemptRecord = serde_json::from_str(body)
        .map_err(|_| "VM runtime requires canonical initial BEGIN".to_owned())?;
    if record.generation != generation
        || record.release_source_revision != source_revision
        || record.release_set_sha256 != release_set_sha256
        || record.github_run_id != github_run_id
    {
        return Err("VM runtime differs from persisted first-use BEGIN".to_owned());
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

// One non-secret paired-commit DECISION, not a second secret writer or an
// automatic permission to transition either host. The durable record is
// immutable GitHub Issue #26 history; the authenticated GitHub workflow must
// independently prove which VM and Windows owner produced each input.
const PAIRED_COMMIT_MARKER_FAMILY: &str = "<!-- sing-box-credential-paired-commit/";
const PAIRED_COMMIT_MARKER: &str = "<!-- sing-box-credential-paired-commit/v1 -->";
const PAIRED_COMMIT_SCHEMA: &str = "sing-box.credential-paired-commit/v1";

#[derive(Debug, Clone)]
pub(crate) struct PairedCommitPlan {
    pub(crate) original_run_id: u64,
    pub(crate) commit_run_id: u64,
    pub(crate) generation: u64,
    pub(crate) slot: String,
    pub(crate) accepted_revision: String,
    pub(crate) release_set_sha256: String,
    pub(crate) vm_prepared_sha256: String,
    pub(crate) windows_prepared_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedCommitRecord {
    schema: String,
    phase: String,
    original_run_id: u64,
    commit_run_id: u64,
    generation: u64,
    slot: String,
    accepted_revision: String,
    release_set_sha256: String,
    original_begin_sha256: String,
    vm_prepared_sha256: String,
    windows_prepared_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PairedHostCursor {
    Candidate,
    Active,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairedHostReadback {
    pub(crate) generation: u64,
    pub(crate) slot: String,
    pub(crate) cursor: PairedHostCursor,
    pub(crate) runtime_verified: bool,
    pub(crate) owner_origin_verified: bool,
}

fn validate_commit_request(request: &PairedCommitPlan) -> Result<(), String> {
    if request.original_run_id == 0
        || request.commit_run_id == 0
        || request.original_run_id == request.commit_run_id
        || request.generation == 0
        || (request.slot != "A" && request.slot != "B")
        || !valid_git_revision(&request.accepted_revision)
        || !valid_sha256(&request.release_set_sha256)
        || !valid_sha256(&request.vm_prepared_sha256)
        || !valid_sha256(&request.windows_prepared_sha256)
        || request.vm_prepared_sha256 == request.windows_prepared_sha256
    {
        return Err("paired commit requires distinct run IDs, exact release, slot, and two distinct prepared owner hashes".to_owned());
    }
    Ok(())
}

fn original_begin_for_commit(history: &str, exact_original: &str) -> Result<AttemptRecord, String> {
    verify_recorded_initial_attempt(history, exact_original)?;
    let (_, body) = exact_original
        .split_once('\n')
        .ok_or_else(|| "paired commit requires canonical original BEGIN".to_owned())?;
    serde_json::from_str(body)
        .map_err(|_| "paired commit requires validated original BEGIN".to_owned())
}

fn matching_original_begin(
    original: &AttemptRecord,
    request: &PairedCommitPlan,
) -> Result<(), String> {
    if original.generation != request.generation
        || original.slot != request.slot
        || original.github_run_id != request.original_run_id
    {
        return Err("paired commit rejects generation/slot/original run mismatch".to_owned());
    }
    Ok(())
}

fn commit_records(history: &str) -> Result<Vec<String>, String> {
    let comments: Vec<IssueComment> = serde_json::from_str(history)
        .map_err(|_| "paired commit requires complete JSON issue history".to_owned())?;
    let mut records = Vec::new();
    for comment in comments {
        if comment.body.trim().is_empty() {
            return Err("paired commit refuses incomplete/empty issue comment".to_owned());
        }
        if comment.body.contains(PAIRED_COMMIT_MARKER_FAMILY) {
            if !comment.body.starts_with(PAIRED_COMMIT_MARKER)
                || !comment
                    .body
                    .starts_with(&format!("{PAIRED_COMMIT_MARKER}\n"))
            {
                return Err("paired commit refuses displaced or unknown-version marker".to_owned());
            }
            records.push(comment.body);
        }
    }
    Ok(records)
}

fn paired_commit_record(request: &PairedCommitPlan, original_begin: &str) -> PairedCommitRecord {
    use ring::digest::{SHA256, digest};
    let original_sha = digest(&SHA256, original_begin.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    PairedCommitRecord {
        schema: PAIRED_COMMIT_SCHEMA.to_owned(),
        phase: "COMMIT_INTENT".to_owned(),
        original_run_id: request.original_run_id,
        commit_run_id: request.commit_run_id,
        generation: request.generation,
        slot: request.slot.clone(),
        accepted_revision: request.accepted_revision.clone(),
        release_set_sha256: request.release_set_sha256.clone(),
        original_begin_sha256: original_sha,
        vm_prepared_sha256: request.vm_prepared_sha256.clone(),
        windows_prepared_sha256: request.windows_prepared_sha256.clone(),
    }
}

/// Produce a non-secret INTENT file only after an existing exact first-use
/// BEGIN, two separately authenticated prepared host witnesses, and a fresh
/// fully paginated history were supplied by the caller. This pure policy
/// cannot authenticate a hash or actually write GitHub history.
pub(crate) fn plan_paired_commit(
    request: &PairedCommitPlan,
    history: &str,
    original_begin: &str,
) -> Result<String, String> {
    validate_commit_request(request)?;
    let original = original_begin_for_commit(history, original_begin)?;
    matching_original_begin(&original, request)?;
    if !commit_records(history)?.is_empty() {
        return Err(
            "paired commit already has an intent; no replay after uncertain result".to_owned(),
        );
    }
    let record = paired_commit_record(request, original_begin);
    Ok(format!(
        "{PAIRED_COMMIT_MARKER}\n{}",
        serde_json::to_string(&record)
            .map_err(|err| format!("paired intent encoding failed: {err}"))?
    ))
}

/// Verify the exact and ONLY durable COMMIT_INTENT, including the immutable
/// original BEGIN. Unknown/duplicate/different records fail closed.
pub(crate) fn verify_paired_commit_intent(
    request: &PairedCommitPlan,
    history: &str,
    original_begin: &str,
    exact_intent: &str,
) -> Result<(), String> {
    validate_commit_request(request)?;
    let original = original_begin_for_commit(history, original_begin)?;
    matching_original_begin(&original, request)?;
    let expected = paired_commit_record(request, original_begin);
    let (marker, body) = exact_intent
        .split_once('\n')
        .ok_or_else(|| "paired intent readback requires marker and record".to_owned())?;
    if marker != PAIRED_COMMIT_MARKER {
        return Err("paired intent readback refuses different marker".to_owned());
    }
    let actual: PairedCommitRecord = serde_json::from_str(body)
        .map_err(|_| "paired intent readback rejects malformed record".to_owned())?;
    if actual.schema != PAIRED_COMMIT_SCHEMA
        || actual.phase != "COMMIT_INTENT"
        || actual.original_run_id != expected.original_run_id
        || actual.commit_run_id != expected.commit_run_id
        || actual.generation != expected.generation
        || actual.slot != expected.slot
        || actual.accepted_revision != expected.accepted_revision
        || actual.release_set_sha256 != expected.release_set_sha256
        || actual.original_begin_sha256 != expected.original_begin_sha256
        || actual.vm_prepared_sha256 != expected.vm_prepared_sha256
        || actual.windows_prepared_sha256 != expected.windows_prepared_sha256
    {
        return Err(
            "paired commit readback differs from exact original and both prepared owners"
                .to_owned(),
        );
    }
    let records = commit_records(history)?;
    if records.len() != 1 || records[0] != exact_intent {
        return Err(
            "paired commit readback requires exactly one matching durable intent".to_owned(),
        );
    }
    Ok(())
}

/// Read-only status classification: deliberately NEVER returns an instruction
/// to replay or promote either half. A partial/unknown state is terminal
/// BLOCKED until a separately authenticated operator reconciliation.
pub(crate) fn reconcile_paired_commit(
    request: &PairedCommitPlan,
    history: &str,
    original_begin: &str,
    exact_intent: &str,
    vm: &PairedHostReadback,
    windows: &PairedHostReadback,
) -> Result<&'static str, String> {
    verify_paired_commit_intent(request, history, original_begin, exact_intent)?;
    for (role, host) in [("VM", vm), ("WINDOWS", windows)] {
        if host.generation != request.generation
            || host.slot != request.slot
            || !host.owner_origin_verified
        {
            return Err(format!(
                "paired commit {role} origin/generation/slot is unproven"
            ));
        }
    }
    use PairedHostCursor::{Active, Candidate};
    match (vm.cursor, windows.cursor) {
        (Active, Active) if vm.runtime_verified && windows.runtime_verified => {
            Ok("PAIR_ACTIVE_VERIFIED")
        }
        (Candidate, Candidate) => Ok("PAIR_INTENT_RECORDED_NO_MUTATION"),
        (Active, Candidate) | (Candidate, Active) => Ok("PAIR_PARTIAL_BLOCKED_NO_REPLAY"),
        (Active, Active) => Ok("PAIR_POINTERS_ACTIVE_RUNTIME_UNPROVEN"),
        _ => Ok("PAIR_UNKNOWN_BLOCKED_NO_REPLAY"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared_commit() -> PairedCommitPlan {
        PairedCommitPlan {
            original_run_id: 1011,
            commit_run_id: 2022,
            generation: 101,
            slot: "A".to_owned(),
            accepted_revision: "1".repeat(40),
            release_set_sha256: "2".repeat(64),
            vm_prepared_sha256: "3".repeat(64),
            windows_prepared_sha256: "4".repeat(64),
        }
    }

    fn persisted_original() -> (String, String) {
        let original = plan_initial_pair_reservation(&request(), "[]").unwrap();
        let history = serde_json::json!([{"body": original}]).to_string();
        (original, history)
    }

    #[test]
    fn paired_commit_requires_original_and_exact_distinct_prepared_hosts() {
        let (original, history) = persisted_original();
        let req = prepared_commit();
        let planned = plan_paired_commit(&req, &history, &original).unwrap();
        assert!(planned.starts_with(PAIRED_COMMIT_MARKER));
        assert!(!planned.contains("secret_text"));
        assert!(!planned.contains("password"));
        let committed = serde_json::json!([{"body": original},{"body": planned}]).to_string();
        verify_paired_commit_intent(&req, &committed, &original, &planned).unwrap();
        assert!(
            plan_paired_commit(&req, &committed, &original)
                .unwrap_err()
                .contains("no replay")
        );
        assert!(plan_paired_commit(&req, "[]", &original).is_err());
        assert!(
            plan_paired_commit(
                &PairedCommitPlan {
                    windows_prepared_sha256: "3".repeat(64),
                    ..req.clone()
                },
                &history,
                &original
            )
            .is_err()
        );
        assert!(
            plan_paired_commit(
                &PairedCommitPlan {
                    generation: 102,
                    ..req.clone()
                },
                &history,
                &original
            )
            .is_err()
        );
        assert!(
            plan_paired_commit(
                &PairedCommitPlan {
                    original_run_id: req.commit_run_id,
                    ..req.clone()
                },
                &history,
                &original
            )
            .is_err()
        );
    }

    #[test]
    fn paired_commit_rejects_all_corrupted_replayed_or_displaced_records() {
        let (original, history) = persisted_original();
        let req = prepared_commit();
        let planned = plan_paired_commit(&req, &history, &original).unwrap();
        for corrupt in [
            serde_json::json!([{"body": original},{"body": planned},{"body": planned}]).to_string(),
            serde_json::json!([{"body": original},{"body": planned},{"body": "<!-- sing-box-credential-paired-commit/v2 -->"}]).to_string(),
            serde_json::json!([{"body": original},{"body": format!("comment {planned}")}]).to_string(),
            serde_json::json!([{"body": original},{"body": format!("{planned}extra")}]).to_string(),
            serde_json::json!([{"body": original},{"body": null}]).to_string(),
            "[]".to_owned(),
        ] {
            assert!(verify_paired_commit_intent(&req, &corrupt, &original, &planned).is_err());
        }
        for different in [
            PairedCommitPlan {
                commit_run_id: req.commit_run_id + 1,
                ..req.clone()
            },
            PairedCommitPlan {
                vm_prepared_sha256: "5".repeat(64),
                ..req.clone()
            },
            PairedCommitPlan {
                windows_prepared_sha256: "5".repeat(64),
                ..req.clone()
            },
            PairedCommitPlan {
                release_set_sha256: "5".repeat(64),
                ..req.clone()
            },
            PairedCommitPlan {
                accepted_revision: "5".repeat(40),
                ..req.clone()
            },
            PairedCommitPlan {
                slot: "B".to_owned(),
                ..req.clone()
            },
        ] {
            let committed = serde_json::json!([{"body": original},{"body": planned}]).to_string();
            assert!(
                verify_paired_commit_intent(&different, &committed, &original, &planned).is_err()
            );
        }
    }

    #[test]
    fn paired_commit_reconciliation_never_replays_partial_or_unknown() {
        let (original, history) = persisted_original();
        let req = prepared_commit();
        let planned = plan_paired_commit(&req, &history, &original).unwrap();
        let committed = serde_json::json!([{"body": original},{"body": planned}]).to_string();
        let valid = PairedHostReadback {
            generation: req.generation,
            slot: req.slot.clone(),
            cursor: PairedHostCursor::Candidate,
            runtime_verified: true,
            owner_origin_verified: true,
        };
        let mut vm = valid.clone();
        let mut windows = valid.clone();
        let classify = |vm: &PairedHostReadback, windows: &PairedHostReadback| {
            reconcile_paired_commit(&req, &committed, &original, &planned, vm, windows)
        };
        assert_eq!(
            classify(&vm, &windows).unwrap(),
            "PAIR_INTENT_RECORDED_NO_MUTATION"
        );
        vm.cursor = PairedHostCursor::Active;
        assert_eq!(
            classify(&vm, &windows).unwrap(),
            "PAIR_PARTIAL_BLOCKED_NO_REPLAY"
        );
        windows.cursor = PairedHostCursor::Active;
        assert_eq!(classify(&vm, &windows).unwrap(), "PAIR_ACTIVE_VERIFIED");
        vm.runtime_verified = false;
        assert_eq!(
            classify(&vm, &windows).unwrap(),
            "PAIR_POINTERS_ACTIVE_RUNTIME_UNPROVEN"
        );
        vm.cursor = PairedHostCursor::Unknown;
        assert_eq!(
            classify(&vm, &windows).unwrap(),
            "PAIR_UNKNOWN_BLOCKED_NO_REPLAY"
        );
        vm.owner_origin_verified = false;
        assert!(classify(&vm, &windows).is_err());
        vm.owner_origin_verified = true;
        vm.generation += 1;
        assert!(classify(&vm, &windows).is_err());
        windows.slot = "B".to_owned();
        assert!(classify(&vm, &windows).is_err());
    }

    #[test]
    fn vm_runtime_requires_exact_durable_begin_for_run_and_release() {
        let req = request();
        let record = plan_initial_pair_reservation(&req, "[]").unwrap();
        let history = serde_json::json!([{ "body": record }]).to_string();
        assert!(
            verify_initial_vm_runtime_gate(
                &history,
                &record,
                req.generation,
                &req.release_source_revision,
                &req.release_set_sha256,
                req.github_run_id,
            )
            .is_ok()
        );
        assert!(
            verify_initial_vm_runtime_gate(
                &history,
                &record,
                req.generation + 1,
                &req.release_source_revision,
                &req.release_set_sha256,
                req.github_run_id,
            )
            .is_err()
        );
        assert!(
            verify_initial_vm_runtime_gate(
                &history,
                &record,
                req.generation,
                &req.release_source_revision,
                &req.release_set_sha256,
                req.github_run_id + 1,
            )
            .is_err()
        );
        assert!(
            verify_initial_vm_runtime_gate(
                "[]",
                &record,
                req.generation,
                &req.release_source_revision,
                &req.release_set_sha256,
                req.github_run_id,
            )
            .is_err()
        );
    }

    fn request() -> InitialPairJournalPlan {
        InitialPairJournalPlan {
            generation: 101,
            slot: "A".to_owned(),
            provider_intent_sha256: "a".repeat(64),
            vm_attestation_sha256: "b".repeat(64),
            windows_attestation_sha256: "c".repeat(64),
            release_source_revision: "d".repeat(40),
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
            r#"[{"id":1}]"#,
            r#"[{"body":null}]"#,
            r#"[{"body":""}]"#,
            r#"[{"body":"   "}]"#,
            r#"[{"body":"<!-- sing-box-credential-initial-attempt/v1 --> {\"schema\":\"unknown\"}"}]"#,
        ] {
            assert!(plan_initial_pair_reservation(&request(), body).is_err());
        }
        assert!(
            plan_initial_pair_reservation(&request(), r#"[{"body":"normal issue comment"}]"#)
                .is_ok()
        );
        assert!(plan_initial_pair_reservation(&request(), "[]").is_ok());
    }

    #[test]
    fn readback_requires_exact_single_persisted_begin() {
        let record = plan_initial_pair_reservation(&request(), "[]").unwrap();
        let once = serde_json::json!([{"body":"ordinary"}, {"body":record}]).to_string();
        assert!(verify_recorded_initial_attempt(&once, &record).is_ok());
        for history in [
            "[]".to_owned(),
            serde_json::json!([{"body":record}, {"body":record}]).to_string(),
            serde_json::json!([{"body":record}, {"body":null}]).to_string(),
            serde_json::json!([{"body":format!("{record}x")}]).to_string(),
            serde_json::json!([{"body":record}, {"body":"<!-- sing-box-credential-initial-attempt/v2 -->"}]).to_string(),
        ] {
            assert!(verify_recorded_initial_attempt(&history, &record).is_err());
        }
        let changed = record.replace("\"generation\":101", "\"generation\":102");
        assert!(verify_recorded_initial_attempt(&once, &changed).is_err());
        assert!(verify_recorded_initial_attempt(&once, "BEGIN").is_err());
    }

    #[test]
    fn readback_is_fenced_to_exact_run_release_provider_and_both_host_evidences() {
        let intended = request();
        let record = plan_initial_pair_reservation(&intended, "[]").unwrap();
        let history = serde_json::json!([{"body": record}]).to_string();
        verify_expected_initial_attempt(&history, &record, &intended).unwrap();
        let changed = [
            InitialPairJournalPlan {
                generation: 102,
                ..request()
            },
            InitialPairJournalPlan {
                slot: "B".to_owned(),
                ..request()
            },
            InitialPairJournalPlan {
                provider_intent_sha256: "f".repeat(64),
                ..request()
            },
            InitialPairJournalPlan {
                vm_attestation_sha256: "f".repeat(64),
                ..request()
            },
            InitialPairJournalPlan {
                windows_attestation_sha256: "f".repeat(64),
                ..request()
            },
            InitialPairJournalPlan {
                release_source_revision: "f".repeat(64),
                ..request()
            },
            InitialPairJournalPlan {
                release_set_sha256: "f".repeat(64),
                ..request()
            },
            InitialPairJournalPlan {
                github_run_id: 1012,
                ..request()
            },
        ];
        for mismatch in changed {
            assert!(verify_expected_initial_attempt(&history, &record, &mismatch).is_err());
        }
        assert!(verify_expected_initial_attempt("[]", &record, &request()).is_err());
    }

    #[test]
    fn initial_journal_accepts_git_revision_not_sha256_and_rejects_malformed() {
        let valid = request();
        assert!(plan_initial_pair_reservation(&valid, "[]").is_ok());
        assert_eq!(valid.release_source_revision.len(), 40);
        for bad in [
            "d".repeat(64),
            "g".repeat(40),
            "D".repeat(40),
            "".to_owned(),
        ] {
            assert!(
                plan_initial_pair_reservation(
                    &InitialPairJournalPlan {
                        release_source_revision: bad,
                        ..request()
                    },
                    "[]"
                )
                .is_err()
            );
        }
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
