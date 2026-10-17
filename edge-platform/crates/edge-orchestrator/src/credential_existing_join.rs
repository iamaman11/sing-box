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

const BEGIN_MARKER: &str = "<!-- sing-box-credential-existing-join-begin/v1 -->";
const BEGIN_FAMILY: &str = "<!-- sing-box-credential-existing-join-begin/";
const BEGIN_SCHEMA: &str = "sing-box.credential-existing-join-begin/v1";

/// Immutable original A and VM B, captured before Windows candidate staging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExistingJoinBegin {
    pub schema: String,
    pub run_id: u64,
    pub accepted_revision: String,
    pub release_set_sha256: String,
    pub windows_active: Witness,
    pub vm_candidate: Witness,
    pub windows_worker_origin_exact: bool,
    pub vm_worker_origin_exact: bool,
    pub vm_line2_six_authenticated: bool,
    pub windows_stopped_proxy_only: bool,
}

fn validate_begin(value: &ExistingJoinBegin, revision: &str, release: &str) -> Result<(), String> {
    if value.schema != BEGIN_SCHEMA
        || value.run_id == 0
        || value.accepted_revision != revision
        || !lower_hex(revision, 40)
        || value.release_set_sha256 != release
        || !lower_hex(release, 64)
        || value.windows_active.generation == 0
        || value.vm_candidate.generation == 0
        || value.windows_active.generation == value.vm_candidate.generation
        || value.windows_active.slot != "A"
        || value.vm_candidate.slot != "B"
        || !lower_hex(&value.windows_active.sha256, 64)
        || !lower_hex(&value.vm_candidate.sha256, 64)
        || value.windows_active.sha256 == value.vm_candidate.sha256
        || !value.windows_worker_origin_exact
        || !value.vm_worker_origin_exact
        || !value.vm_line2_six_authenticated
        || !value.windows_stopped_proxy_only
    {
        return Err("existing join BEGIN original A/VM B owner proof absent".to_owned());
    }
    Ok(())
}

fn begin_records(history: &str) -> Result<Vec<String>, String> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(history)
        .map_err(|_| "existing join BEGIN GitHub history malformed".to_owned())?;
    let mut found = Vec::new();
    for row in rows {
        let body = row
            .get("body")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "existing join BEGIN GitHub history unreadable".to_owned())?;
        if body.contains(BEGIN_FAMILY) {
            if !body.starts_with(&format!("{BEGIN_MARKER}\n")) {
                return Err("existing join BEGIN unsupported/ambiguous marker".to_owned());
            }
            found.push(body.to_owned());
        }
    }
    Ok(found)
}

pub(crate) fn plan_begin(
    value: &ExistingJoinBegin,
    history: &str,
    revision: &str,
    release: &str,
) -> Result<String, String> {
    validate_begin(value, revision, release)?;
    if !begin_records(history)?.is_empty() || !records(history)?.is_empty() {
        return Err("existing join BEGIN has already been attempted; no replay".to_owned());
    }
    let body = serde_json::to_string(value)
        .map_err(|_| "existing join BEGIN serialization failed".to_owned())?;
    Ok(format!("{BEGIN_MARKER}\n{body}"))
}

pub(crate) fn readback_begin(
    value: &ExistingJoinBegin,
    history: &str,
    exact: &str,
    revision: &str,
    release: &str,
) -> Result<(), String> {
    validate_begin(value, revision, release)?;
    let body = exact
        .strip_prefix(&format!("{BEGIN_MARKER}\n"))
        .ok_or_else(|| "existing join BEGIN exact marker missing".to_owned())?;
    let decoded: ExistingJoinBegin = serde_json::from_str(body)
        .map_err(|_| "existing join BEGIN content malformed".to_owned())?;
    if &decoded != value || serde_json::to_string(&decoded).ok().as_deref() != Some(body) {
        return Err(
            "existing join BEGIN differs from original authenticated owner proof".to_owned(),
        );
    }
    let stored = begin_records(history)?;
    if stored.len() != 1 || stored[0] != exact || !records(history)?.is_empty() {
        return Err("existing join BEGIN not durably unique before COMMIT".to_owned());
    }
    Ok(())
}

fn require_matching_begin(
    spec: &ExistingJoinIntent,
    history: &str,
    revision: &str,
    release: &str,
) -> Result<(), String> {
    let stored = begin_records(history)?;
    if stored.len() != 1 {
        return Err("existing join COMMIT requires exactly one original BEGIN".to_owned());
    }
    let body = stored[0]
        .strip_prefix(&format!("{BEGIN_MARKER}\n"))
        .ok_or_else(|| "existing join BEGIN marker malformed".to_owned())?;
    let original: ExistingJoinBegin = serde_json::from_str(body)
        .map_err(|_| "existing join BEGIN original data malformed".to_owned())?;
    validate_begin(&original, revision, release)?;
    if serde_json::to_string(&original).ok().as_deref() != Some(body)
        || original.run_id != spec.run_id
        || original.accepted_revision != spec.accepted_revision
        || original.release_set_sha256 != spec.release_set_sha256
        || original.windows_active != spec.windows_active
        || original.vm_candidate != spec.vm_candidate
    {
        return Err("existing join COMMIT differs from immutable BEGIN".to_owned());
    }
    Ok(())
}

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

/// Rust-owned, read-only journal classification. Does not infer missing host
/// receipts from a comment: even a complete COMMIT is NOT runtime acceptance.
pub(crate) fn inspect_journal(
    history: &str,
    revision: &str,
    release: &str,
) -> Result<&'static str, String> {
    let begins = begin_records(history)?;
    let commits = records(history)?;
    if begins.is_empty() && commits.is_empty() {
        return Ok("NO_BEGIN_NO_MUTATION_AUTHORITY");
    }
    if begins.len() != 1 || commits.len() > 1 {
        return Err("existing join journal duplicate/orphan or unsupported; UNKNOWN".to_owned());
    }
    let original = begins[0]
        .strip_prefix(&format!("{BEGIN_MARKER}\n"))
        .ok_or_else(|| "existing join original BEGIN displaced".to_owned())?;
    let begin: ExistingJoinBegin = serde_json::from_str(original)
        .map_err(|_| "existing join original BEGIN malformed".to_owned())?;
    validate_begin(&begin, revision, release)?;
    if serde_json::to_string(&begin).ok().as_deref() != Some(original) {
        return Err("existing join original BEGIN is noncanonical".to_owned());
    }
    if commits.is_empty() {
        readback_begin(&begin, history, &begins[0], revision, release)?;
        return Ok("BEGIN_DURABLE_NO_AUTOMATIC_REPLAY");
    }
    let body = commits[0]
        .strip_prefix(&format!("{MARKER}\n"))
        .ok_or_else(|| "existing join COMMIT marker displaced".to_owned())?;
    let commit: ExistingJoinIntent =
        serde_json::from_str(body).map_err(|_| "existing join COMMIT malformed".to_owned())?;
    readback(&commit, history, &commits[0], revision, release)?;
    Ok("COMMIT_DURABLE_OWNER_RECEIPTS_UNPROVEN")
}

/// The Host lifecycle and credential recovery must use ONE journal parser.
/// The revision and ReleaseSet are extracted only to validate the historical
/// immutable record against itself, never to authorize a new mutation. In
/// particular, a durable COMMIT_INTENT is not a proven physical COMMIT.
pub(crate) fn host_admission_status(history: &[u8]) -> Result<&'static str, String> {
    let data = std::str::from_utf8(history)
        .map_err(|_| "HOST_JOURNAL_INVALID_UTF8".to_owned())?;
    let rows: Vec<serde_json::Value> = serde_json::from_str(data)
        .map_err(|_| "HOST_JOURNAL_MALFORMED".to_owned())?;
    if rows.is_empty() {
        return Err("HOST_JOURNAL_EMPTY".to_owned());
    }
    let begins = begin_records(data)?;
    if begins.is_empty() {
        // inspect_journal also rejects orphan, displaced or unknown join
        // intent records and concurrent paired first-use commits.
        return inspect_journal(data, "", "");
    }
    if begins.len() != 1 {
        return Err("HOST_JOURNAL_ORIGINAL_AB_DUPLICATE".to_owned());
    }
    let raw = begins[0]
        .strip_prefix(&format!("{BEGIN_MARKER}\n"))
        .ok_or_else(|| "HOST_JOURNAL_BEGIN_AMBIGUOUS".to_owned())?;
    let begin: ExistingJoinBegin = serde_json::from_str(raw)
        .map_err(|_| "HOST_JOURNAL_BEGIN_INVALID".to_owned())?;
    inspect_journal(data, &begin.accepted_revision, &begin.release_set_sha256)
}

pub(crate) fn plan(
    spec: &ExistingJoinIntent,
    history: &str,
    revision: &str,
    release: &str,
) -> Result<String, String> {
    validate(spec, revision, release)?;
    require_matching_begin(spec, history, revision, release)?;
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
    require_matching_begin(spec, history, revision, release)?;
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
    pub(crate) windows_join_receipt_intent_sha256: Option<String>,
    pub(crate) windows_prepare_begin_sha256: Option<String>,
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
    let begin = begin_records(history)?;
    if begin.len() != 1 {
        return Ok("UNKNOWN_SAFE_BLOCKED_NO_REPLAY");
    }
    let begin_digest = {
        use ring::digest::{SHA256, digest};
        digest(&SHA256, begin[0].as_bytes())
            .as_ref()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>()
    };
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
    {
        return Ok("SAFE_BLOCKED_UNPROVEN_OWNER_OR_NETWORK");
    }
    // Recovery may identify a physically durable partial/complete pointer
    // state even when the original Line1/Line2 network witnesses have expired.
    // Such observations NEVER authorize another mutation or acceptance.
    let network_verified =
        snapshot.line1_authenticated_endpoints == 4 && snapshot.line2_authenticated_endpoints == 6;
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
    let windows_receipt_correct =
        snapshot.windows_join_receipt_intent_sha256.as_deref() == Some(expected_digest.as_str());
    let windows_receipt_absent = snapshot.windows_join_receipt_intent_sha256.is_none();
    let prepare_correct =
        snapshot.windows_prepare_begin_sha256.as_deref() == Some(begin_digest.as_str());
    let prepare_absent = snapshot.windows_prepare_begin_sha256.is_none();
    if (!windows_receipt_absent && !windows_receipt_correct)
        || (!receipt_absent && !receipt_correct)
        || (!prepare_absent && !prepare_correct)
    {
        return Ok("UNKNOWN_SAFE_BLOCKED_NO_REPLAY");
    }
    if win_is_a
        && snapshot.windows_candidate.as_ref() == Some(b)
        && snapshot.windows_previous.is_none()
        && snapshot.vm_active.is_none()
        && vm_candidate_b
        && receipt_absent
        && windows_receipt_absent
        && prepare_correct
    {
        // BEGIN-bound prepare receipt is necessary; an unstaged or
        // interrupted candidate store is not a prepared managed runtime.
        // Even with a receipt, only the independent Line1 witness above
        // can confirm that applying the candidate actually completed.
        return if network_verified {
            Ok("INTENT_DURABLE_PREPARED_NO_AUTO_APPLY")
        } else {
            Ok("PREPARED_NETWORK_UNPROVEN_NO_REPLAY")
        };
    }
    if win_is_b
        && snapshot.windows_candidate.is_none()
        && snapshot.windows_previous.as_ref() == Some(a)
        && vm_is_b
        && snapshot.vm_candidate.is_none()
        && receipt_correct
        && windows_receipt_correct
        && prepare_correct
    {
        return if network_verified {
            Ok("POINTERS_COMPLETE_REQUIRES_INDEPENDENT_ACCEPTANCE")
        } else {
            Ok("POINTERS_COMPLETE_NETWORK_UNPROVEN_NO_REPLAY")
        };
    }
    if (win_is_a || win_is_b)
        && (vm_is_b || vm_candidate_b)
        && (receipt_absent || receipt_correct)
        && (windows_receipt_absent || windows_receipt_correct)
        && (prepare_absent || prepare_correct)
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
        CredentialDeliveryCommand::ExistingJoinJournalInspect {
            journal_history_path,
        } => {
            let history = fs::read_to_string(journal_history_path)
                .map_err(|_| "existing join GitHub history unavailable")?;
            let status = inspect_journal(&history, revision, release)?;
            println!("existing_join_journal_state={status}");
            println!("credential_mutation_allowed=false");
            println!("credential_mutation_replayed=false");
            Ok(())
        }
        CredentialDeliveryCommand::ExistingJoinBeginPlan {
            spec_path,
            journal_history_path,
            record_output_path,
        } => {
            let spec: ExistingJoinBegin = serde_json::from_slice(
                &fs::read(spec_path).map_err(|_| "existing join BEGIN spec unreadable")?,
            )
            .map_err(|_| "existing join BEGIN spec malformed")?;
            let history = fs::read_to_string(journal_history_path)
                .map_err(|_| "existing join BEGIN GitHub history unavailable")?;
            let record = plan_begin(&spec, &history, revision, release)?;
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(record_output_path)
                .map_err(|_| "existing join BEGIN local record exists or UNKNOWN")?;
            file.write_all(record.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| "existing join BEGIN local write UNKNOWN")?;
            println!("existing_join_begin=PLANNED_LOCAL_ONLY");
            println!("credential_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::ExistingJoinBeginReadback {
            spec_path,
            journal_history_path,
            exact_record_path,
        } => {
            let spec: ExistingJoinBegin = serde_json::from_slice(
                &fs::read(spec_path).map_err(|_| "existing join BEGIN spec unreadable")?,
            )
            .map_err(|_| "existing join BEGIN spec malformed")?;
            let history = fs::read_to_string(journal_history_path)
                .map_err(|_| "existing join BEGIN GitHub history unavailable")?;
            let exact = fs::read_to_string(exact_record_path)
                .map_err(|_| "existing join BEGIN exact record missing")?;
            readback_begin(&spec, &history, &exact, revision, release)?;
            println!("existing_join_begin=EXACT_DURABLE_ONCE");
            println!("credential_mutations=0");
            Ok(())
        }
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
    fn source_begin(spec: &ExistingJoinIntent) -> ExistingJoinBegin {
        ExistingJoinBegin {
            schema: BEGIN_SCHEMA.to_owned(),
            run_id: spec.run_id,
            accepted_revision: spec.accepted_revision.clone(),
            release_set_sha256: spec.release_set_sha256.clone(),
            windows_active: spec.windows_active.clone(),
            vm_candidate: spec.vm_candidate.clone(),
            windows_worker_origin_exact: true,
            vm_worker_origin_exact: true,
            vm_line2_six_authenticated: true,
            windows_stopped_proxy_only: true,
        }
    }
    fn history_begin(spec: &ExistingJoinIntent) -> String {
        let begin = source_begin(spec);
        let exact = plan_begin(
            &begin,
            "[]",
            &spec.accepted_revision,
            &spec.release_set_sha256,
        )
        .unwrap();
        serde_json::json!([{"body":exact}]).to_string()
    }
    fn history_commit(spec: &ExistingJoinIntent, exact: &str) -> String {
        let initial: Vec<serde_json::Value> = serde_json::from_str(&history_begin(spec)).unwrap();
        serde_json::json!([initial[0], {"body":exact}]).to_string()
    }
    #[test]
    fn original_begin_is_durable_before_staged_windows_b_and_commit() {
        let g = good();
        let begin = source_begin(&g);
        let recorded =
            plan_begin(&begin, "[]", &g.accepted_revision, &g.release_set_sha256).unwrap();
        let history = history_begin(&g);
        readback_begin(
            &begin,
            &history,
            &recorded,
            &g.accepted_revision,
            &g.release_set_sha256,
        )
        .unwrap();
        assert!(
            plan_begin(
                &begin,
                &history,
                &g.accepted_revision,
                &g.release_set_sha256
            )
            .is_err()
        );
        let commit = plan(&g, &history, &g.accepted_revision, &g.release_set_sha256).unwrap();
        readback(
            &g,
            &history_commit(&g, &commit),
            &commit,
            &g.accepted_revision,
            &g.release_set_sha256,
        )
        .unwrap();
    }
    #[test]
    fn missing_duplicate_or_drifted_begin_never_authorizes_commit() {
        let g = good();
        assert!(plan(&g, "[]", &g.accepted_revision, &g.release_set_sha256).is_err());
        let begin = source_begin(&g);
        let orig = plan_begin(&begin, "[]", &g.accepted_revision, &g.release_set_sha256).unwrap();
        let duplicated = serde_json::json!([{"body":orig},{"body":orig}]).to_string();
        assert!(plan(&g, &duplicated, &g.accepted_revision, &g.release_set_sha256).is_err());
        let mut drift = g.clone();
        drift.windows_active.generation += 1;
        assert!(
            plan(
                &drift,
                &history_begin(&g),
                &g.accepted_revision,
                &g.release_set_sha256
            )
            .is_err()
        );
        let unsupported =
            serde_json::json!([{"body":"<!-- sing-box-credential-existing-join-begin/v2 -->"}])
                .to_string();
        assert!(
            plan_begin(
                &begin,
                &unsupported,
                &g.accepted_revision,
                &g.release_set_sha256
            )
            .is_err()
        );
    }

    #[test]
    fn positive_plan_and_exact_history_readback() {
        let g = good();
        let record = plan(
            &g,
            &history_begin(&g),
            &g.accepted_revision,
            &g.release_set_sha256,
        )
        .unwrap();
        let history = history_commit(&g, &record);
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
            assert!(
                plan(
                    &changed,
                    &history_begin(&g),
                    &g.accepted_revision,
                    &g.release_set_sha256
                )
                .is_err()
            );
        }
    }
    #[test]
    fn torn_or_duplicate_intent_blocks_and_no_implicit_retry() {
        let g = good();
        let record = plan(
            &g,
            &history_begin(&g),
            &g.accepted_revision,
            &g.release_set_sha256,
        )
        .unwrap();
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
            windows_join_receipt_intent_sha256: None,
            windows_prepare_begin_sha256: None,
            windows_worker_origin_verified: true,
            vm_worker_origin_verified: true,
            windows_stopped_proxy_only: true,
            line1_authenticated_endpoints: 4,
            line2_authenticated_endpoints: 6,
        }
    }

    fn classify(spec: &ExistingJoinIntent, state: &ExistingJoinSnapshot) -> &'static str {
        let record = plan(
            spec,
            &history_begin(spec),
            &spec.accepted_revision,
            &spec.release_set_sha256,
        )
        .unwrap();
        let history = history_commit(spec, &record);
        reconcile(
            spec,
            &history,
            &record,
            &spec.accepted_revision,
            &spec.release_set_sha256,
            state,
        )
        .unwrap()
    }

    fn beginning_digest_for_test(spec: &ExistingJoinIntent) -> String {
        use ring::digest::{SHA256, digest};
        let history: Vec<serde_json::Value> = serde_json::from_str(&history_begin(spec)).unwrap();
        let body = history[0]["body"].as_str().unwrap();
        digest(&SHA256, body.as_bytes())
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }

    #[test]
    fn exact_durable_prepared_state_does_not_automatically_apply() {
        let g = good();
        // Merely seeing B in the local candidate store is not proof that
        // SYSTEM durably prepared and applied the managed runtime.
        assert_eq!(
            classify(&g, &snapshot(&g)),
            "PARTIAL_SAFE_BLOCKED_NO_REPLAY"
        );
        let mut s = snapshot(&g);
        s.windows_prepare_begin_sha256 = Some(beginning_digest_for_test(&g));
        assert_eq!(classify(&g, &s), "INTENT_DURABLE_PREPARED_NO_AUTO_APPLY");
    }

    #[test]
    fn half_committed_vm_join_refuses_automatic_replay() {
        let g = good();
        let intent = plan(
            &g,
            &history_begin(&g),
            &g.accepted_revision,
            &g.release_set_sha256,
        )
        .unwrap();
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
        let record = plan(
            &g,
            &history_begin(&g),
            &g.accepted_revision,
            &g.release_set_sha256,
        )
        .unwrap();
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
        s.vm_join_receipt_intent_sha256 = Some(digest.clone());
        s.windows_join_receipt_intent_sha256 = Some(digest);
        let begin = beginning_digest_for_test(&g);
        s.windows_prepare_begin_sha256 = Some(begin);
        assert_eq!(
            classify(&g, &s),
            "POINTERS_COMPLETE_REQUIRES_INDEPENDENT_ACCEPTANCE"
        );
        s.vm_join_receipt_intent_sha256 = Some("e".repeat(64));
        assert_eq!(classify(&g, &s), "UNKNOWN_SAFE_BLOCKED_NO_REPLAY");
    }

    #[test]
    fn completed_pointers_with_expired_network_are_read_only_and_not_accepted() {
        let g = good();
        let commit = plan(
            &g,
            &history_begin(&g),
            &g.accepted_revision,
            &g.release_set_sha256,
        )
        .unwrap();
        let sha = {
            use ring::digest::{SHA256, digest};
            digest(&SHA256, commit.as_bytes())
                .as_ref()
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        };
        let mut s = snapshot(&g);
        s.windows_active = g.windows_candidate.clone();
        s.windows_candidate = None;
        s.windows_previous = Some(g.windows_active.clone());
        s.vm_active = Some(g.vm_candidate.clone());
        s.vm_candidate = None;
        s.vm_join_receipt_intent_sha256 = Some(sha.clone());
        s.windows_join_receipt_intent_sha256 = Some(sha);
        s.windows_prepare_begin_sha256 = Some(beginning_digest_for_test(&g));
        s.line1_authenticated_endpoints = 0;
        s.line2_authenticated_endpoints = 0;
        assert_eq!(
            classify(&g, &s),
            "POINTERS_COMPLETE_NETWORK_UNPROVEN_NO_REPLAY"
        );
    }

    #[test]
    fn vm_and_windows_receipts_must_match_the_exact_same_begin_and_commit() {
        let g = good();
        let mut s = snapshot(&g);
        s.windows_prepare_begin_sha256 = Some("d".repeat(64));
        assert_eq!(classify(&g, &s), "UNKNOWN_SAFE_BLOCKED_NO_REPLAY");
        s.windows_prepare_begin_sha256 = Some(beginning_digest_for_test(&g));
        assert_eq!(classify(&g, &s), "INTENT_DURABLE_PREPARED_NO_AUTO_APPLY");
        s.windows_join_receipt_intent_sha256 = Some("e".repeat(64));
        assert_eq!(classify(&g, &s), "UNKNOWN_SAFE_BLOCKED_NO_REPLAY");
    }

    #[test]
    fn rust_inspection_distinguishes_absent_begin_and_exact_commit_without_granting_apply() {
        let g = good();
        assert_eq!(
            inspect_journal("[]", &g.accepted_revision, &g.release_set_sha256).unwrap(),
            "NO_BEGIN_NO_MUTATION_AUTHORITY"
        );
        let begin = history_begin(&g);
        assert_eq!(
            inspect_journal(&begin, &g.accepted_revision, &g.release_set_sha256).unwrap(),
            "BEGIN_DURABLE_NO_AUTOMATIC_REPLAY"
        );
        let record = plan(&g, &begin, &g.accepted_revision, &g.release_set_sha256).unwrap();
        assert_eq!(
            inspect_journal(
                &history_commit(&g, &record),
                &g.accepted_revision,
                &g.release_set_sha256
            )
            .unwrap(),
            "COMMIT_DURABLE_OWNER_RECEIPTS_UNPROVEN"
        );
        let orphan = serde_json::json!([{"body":record}]).to_string();
        assert!(inspect_journal(&orphan, &g.accepted_revision, &g.release_set_sha256).is_err());
    }
    #[test]
    fn host_and_credentials_share_exact_original_join_journal_semantics() {
        let g = good();
        let ordinary = serde_json::json!([{"body":"read-only evidence"}]).to_string();
        assert_eq!(
            host_admission_status(ordinary.as_bytes()).unwrap(),
            "NO_BEGIN_NO_MUTATION_AUTHORITY"
        );
        assert_eq!(host_admission_status(b"[]").unwrap_err(), "HOST_JOURNAL_EMPTY");
        let begin = history_begin(&g);
        assert_eq!(
            host_admission_status(begin.as_bytes()).unwrap(),
            "BEGIN_DURABLE_NO_AUTOMATIC_REPLAY"
        );
        let commit = plan(&g, &begin, &g.accepted_revision, &g.release_set_sha256).unwrap();
        let history = history_commit(&g, &commit);
        assert_eq!(
            host_admission_status(history.as_bytes()).unwrap(),
            "COMMIT_DURABLE_OWNER_RECEIPTS_UNPROVEN"
        );
        let mut duplicates: Vec<serde_json::Value> =
            serde_json::from_str(&begin).unwrap();
        duplicates.push(duplicates[0].clone());
        assert_eq!(
            host_admission_status(serde_json::to_string(&duplicates).unwrap().as_bytes())
                .unwrap_err(),
            "HOST_JOURNAL_ORIGINAL_AB_DUPLICATE"
        );
        let orphan = serde_json::json!([{"body":commit}]).to_string();
        assert!(host_admission_status(orphan.as_bytes()).is_err());
        let unsupported = serde_json::json!([
            {"body":"<!-- sing-box-credential-existing-join-begin/v2 -->\n{}"}
        ]).to_string();
        assert!(host_admission_status(unsupported.as_bytes()).is_err());
    }

    #[test]
    fn incomplete_or_unproven_snapshot_is_blocked() {
        let g = good();
        let mut s = snapshot(&g);
        s.windows_worker_origin_verified = false;
        assert_eq!(classify(&g, &s), "SAFE_BLOCKED_UNPROVEN_OWNER_OR_NETWORK");
        s.windows_worker_origin_verified = true;
        s.windows_prepare_begin_sha256 = Some(beginning_digest_for_test(&g));
        s.line2_authenticated_endpoints = 5;
        assert_eq!(classify(&g, &s), "PREPARED_NETWORK_UNPROVEN_NO_REPLAY");
    }
}
