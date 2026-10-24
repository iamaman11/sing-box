//! Rust-owned reconciliation for prior VM Worker code-only BEGIN reservations.
//!
//! GitHub issue history is untrusted input. A historical BEGIN can be
//! superseded only if the exact operator comment, protected Actions run and
//! Worker-owner job all have independently verified terminal SUCCESS.
//! The caller must separately prove active Cloudflare bytes equal the exact
//! immutable ReleaseSet predecessor. Failed/unknown prior runs forbid replay.
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::Value;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration;

const API: &str = "https://api.github.com/repos/iamaman11/sing-box";
const BEGIN_PREFIX: &str = "<!-- sing-box-vm-worker-authorizer-begin/v1 machine=";
const BEGIN_FAMILY: &str = "<!-- sing-box-vm-worker-authorizer-begin/";
const ISSUE26: &str = "https://api.github.com/repos/iamaman11/sing-box/issues/26";
const ISSUE1: &str = "https://api.github.com/repos/iamaman11/sing-box/issues/1";
const ACTOR_ID: u64 = 44100369;
const BOT_ID: u64 = 41898282;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PriorBegin {
    operator_comment_id: u64,
    source_revision: String,
    github_run_id: u64,
}

fn id_after(part: &str, prefix: &str) -> Result<u64, &'static str> {
    let digits = part
        .strip_prefix(prefix)
        .ok_or("HOST_VM_WORKER_PRIOR_BEGIN_MALFORMED_NO_REPLAY")?;
    if digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("HOST_VM_WORKER_PRIOR_BEGIN_MALFORMED_NO_REPLAY");
    }
    digits
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or("HOST_VM_WORKER_PRIOR_BEGIN_MALFORMED_NO_REPLAY")
}

fn prior_begins(history: &str, machine_id: &str) -> Result<Vec<PriorBegin>, String> {
    let records: Vec<Value> = serde_json::from_str(history)
        .map_err(|_| "HOST_VM_WORKER_HISTORY_MALFORMED_NO_REPLAY")?;
    if records.len() > 3000 {
        return Err("HOST_VM_WORKER_HISTORY_UNBOUNDED_NO_REPLAY".into());
    }
    let prefix = format!("{BEGIN_PREFIX}{machine_id} ");
    let scope = format!(" machine={machine_id} ");
    let mut seen_comments = BTreeSet::new();
    let mut seen_runs = BTreeSet::new();
    let mut found = Vec::new();
    for entry in records {
        let body = entry.get("body").and_then(Value::as_str).unwrap_or("");
        // A future or malformed marker for this machine cannot be silently
        // ignored as historical prose.
        if body.starts_with(BEGIN_FAMILY) && body.contains(&scope) && !body.starts_with(&prefix) {
            return Err("HOST_VM_WORKER_PRIOR_BEGIN_VERSION_UNPROVEN_NO_REPLAY".into());
        }
        let Some(fields) = body.strip_prefix(&prefix) else {
            continue;
        };
        let fields = fields
            .strip_suffix(" -->")
            .ok_or("HOST_VM_WORKER_PRIOR_BEGIN_MALFORMED_NO_REPLAY")?;
        let pieces = fields.split(' ').collect::<Vec<_>>();
        if pieces.len() != 3 {
            return Err("HOST_VM_WORKER_PRIOR_BEGIN_MALFORMED_NO_REPLAY".into());
        }
        let operator_comment_id = id_after(pieces[0], "comment=")?;
        let source_revision = pieces[1]
            .strip_prefix("revision=")
            .ok_or("HOST_VM_WORKER_PRIOR_BEGIN_MALFORMED_NO_REPLAY")?;
        if source_revision.len() != 40
            || !source_revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("HOST_VM_WORKER_PRIOR_BEGIN_MALFORMED_NO_REPLAY".into());
        }
        let github_run_id = id_after(pieces[2], "run=")?;
        if entry.pointer("/user/id").and_then(Value::as_u64) != Some(BOT_ID)
            || entry.get("issue_url").and_then(Value::as_str) != Some(ISSUE26)
            || entry.get("created_at").and_then(Value::as_str).is_none()
            || entry.get("created_at") != entry.get("updated_at")
            || !seen_comments.insert(operator_comment_id)
            || !seen_runs.insert(github_run_id)
        {
            return Err("HOST_VM_WORKER_PRIOR_BEGIN_UNTRUSTED_NO_REPLAY".into());
        }
        found.push(PriorBegin {
            operator_comment_id,
            source_revision: source_revision.to_owned(),
            github_run_id,
        });
    }
    Ok(found)
}

fn prior_run_is_terminal(
    prior: &PriorBegin,
    machine_id: &str,
    operator: &Value,
    run: &Value,
    jobs: &Value,
) -> bool {
    let exact_command = format!("/host apply {machine_id}");
    operator.get("id").and_then(Value::as_u64) == Some(prior.operator_comment_id)
        && operator.pointer("/user/id").and_then(Value::as_u64) == Some(ACTOR_ID)
        && operator.get("issue_url").and_then(Value::as_str) == Some(ISSUE1)
        && operator.get("body").and_then(Value::as_str) == Some(exact_command.as_str())
        && operator.get("created_at") == operator.get("updated_at")
        && run.get("id").and_then(Value::as_u64) == Some(prior.github_run_id)
        && run.get("head_sha").and_then(Value::as_str)
            == Some(prior.source_revision.as_str())
        && run.get("status").and_then(Value::as_str) == Some("completed")
        && run.get("conclusion").and_then(Value::as_str) == Some("success")
        && run.get("event").and_then(Value::as_str) == Some("issue_comment")
        && run.get("run_attempt").and_then(Value::as_u64) == Some(1)
        && run.pointer("/actor/id").and_then(Value::as_u64) == Some(ACTOR_ID)
        && run.pointer("/triggering_actor/id").and_then(Value::as_u64) == Some(ACTOR_ID)
        && run.get("path").and_then(Value::as_str)
            == Some(".github/workflows/edge-control-plane.yml")
        && run.get("name").and_then(Value::as_str) == Some(exact_command.as_str())
        && jobs.get("total_count").and_then(Value::as_u64).is_some_and(|n| n <= 100)
        && jobs.get("jobs").and_then(Value::as_array).is_some_and(|items| {
            items.iter().filter(|job| {
                job.get("name").and_then(Value::as_str) == Some("host_worker_authorizer")
                    && job.get("status").and_then(Value::as_str) == Some("completed")
                    && job.get("conclusion").and_then(Value::as_str) == Some("success")
                    && job.get("run_id").and_then(Value::as_u64) == Some(prior.github_run_id)
            }).count() == 1
        })
}

async fn github_get_json(client: &Client, token: &str, path: &str) -> Result<Value, String> {
    let response = client
        .get(format!("{API}/{path}"))
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "HOST_VM_WORKER_PRIOR_GITHUB_READ_UNPROVEN_NO_REPLAY")?;
    if response.status() != StatusCode::OK
        || response.content_length().is_some_and(|n| n == 0 || n > 2_097_152)
    {
        return Err("HOST_VM_WORKER_PRIOR_GITHUB_READ_UNPROVEN_NO_REPLAY".into());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "HOST_VM_WORKER_PRIOR_GITHUB_READ_UNPROVEN_NO_REPLAY")?;
    if bytes.is_empty() || bytes.len() > 2_097_152 {
        return Err("HOST_VM_WORKER_PRIOR_GITHUB_READ_UNPROVEN_NO_REPLAY".into());
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "HOST_VM_WORKER_PRIOR_GITHUB_JSON_UNPROVEN_NO_REPLAY".into())
}

/// Called ONLY by the immutable Rust Worker plan after Cloudflare has proven
/// the exact predecessor digest and that there is no pending/split version.
/// Must finish before the GitHub workflow may append a new durable BEGIN.
pub(crate) async fn verify_prior_vm_worker_begins(machine_id: &str) -> Result<(), String> {
    let history_path = env::var_os("HOST_VM_WORKER_BEGIN_HISTORY_PATH")
        .ok_or("HOST_VM_WORKER_HISTORY_PATH_REQUIRED")?;
    let path = Path::new(&history_path);
    let meta = fs::symlink_metadata(path)
        .map_err(|_| "HOST_VM_WORKER_HISTORY_UNAVAILABLE_NO_REPLAY")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 10 * 1024 * 1024 {
        return Err("HOST_VM_WORKER_HISTORY_UNTRUSTED_NO_REPLAY".into());
    }
    let history = fs::read_to_string(path)
        .map_err(|_| "HOST_VM_WORKER_HISTORY_UNREADABLE_NO_REPLAY")?;
    let beginnings = prior_begins(&history, machine_id)?;
    if beginnings.is_empty() {
        println!("host_vm_worker_prior_begin=NONE");
        return Ok(());
    }
    let token = env::var("GH_TOKEN")
        .map_err(|_| "HOST_VM_WORKER_PRIOR_GITHUB_TOKEN_REQUIRED")?;
    if token.is_empty() || token.len() > 1024 {
        return Err("HOST_VM_WORKER_PRIOR_GITHUB_TOKEN_INVALID".into());
    }
    let client = Client::builder()
        .user_agent("sing-box-rust-native-worker-reconciliation/1")
        .redirect(Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| "HOST_VM_WORKER_PRIOR_GITHUB_CLIENT_UNAVAILABLE")?;
    for prior in &beginnings {
        let operator = github_get_json(
            &client,
            &token,
            &format!("issues/comments/{}", prior.operator_comment_id),
        )
        .await?;
        let run = github_get_json(
            &client,
            &token,
            &format!("actions/runs/{}", prior.github_run_id),
        )
        .await?;
        let jobs = github_get_json(
            &client,
            &token,
            &format!("actions/runs/{}/jobs?per_page=100", prior.github_run_id),
        )
        .await?;
        if !prior_run_is_terminal(prior, machine_id, &operator, &run, &jobs) {
            return Err("HOST_VM_WORKER_PRIOR_BEGIN_UNRECONCILED_NO_REPLAY".into());
        }
    }
    println!("host_vm_worker_prior_begin=TERMINAL_OWNER_RUN_RECONCILED");
    println!("host_vm_worker_prior_begin_count={}", beginnings.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn revision() -> String {
        "eae7bd8f89bf37bbe4eb61683d6bf59bad4a261b".into()
    }
    fn begin(machine: &str, operator: u64, run: u64) -> Value {
        serde_json::json!({
            "body": format!("{BEGIN_PREFIX}{machine} comment={operator} revision={} run={run} -->", revision()),
            "user": {"id": BOT_ID},
            "issue_url": ISSUE26,
            "created_at": "2026-10-23T23:33:49Z",
            "updated_at": "2026-10-23T23:33:49Z"
        })
    }
    #[test]
    fn only_exact_machine_marker_is_parsed() {
        let records = serde_json::json!([
            {"body": "historical free text"},
            begin("another-machine", 12, 23),
            begin("application-acceptance-3", 6376840359_u64, 40040305662_u64)
        ]);
        let found = prior_begins(&records.to_string(), "application-acceptance-3").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].github_run_id, 40040305662);
        assert_eq!(found[0].source_revision, revision());
    }
    #[test]
    fn forged_edited_duplicate_or_malformed_begin_is_blocking() {
        let item = begin("application-acceptance-3", 12, 23);
        assert!(prior_begins(&serde_json::json!([item, begin("application-acceptance-3", 12, 24)]).to_string(), "application-acceptance-3").is_err());
        let mut changed = begin("application-acceptance-3", 12, 23);
        changed["updated_at"] = Value::String("2026-10-23T23:33:50Z".into());
        assert!(prior_begins(&serde_json::json!([changed]).to_string(), "application-acceptance-3").is_err());
        let mut malformed = begin("application-acceptance-3", 12, 23);
        malformed["body"] = Value::String("<!-- sing-box-vm-worker-authorizer-begin/v1 machine=application-acceptance-3 comment=12 revision=garbage run=23 -->".into());
        assert!(prior_begins(&serde_json::json!([malformed]).to_string(), "application-acceptance-3").is_err());
        let mut forged = begin("application-acceptance-3", 12, 23);
        forged["user"]["id"] = Value::from(ACTOR_ID);
        assert!(prior_begins(&serde_json::json!([forged]).to_string(), "application-acceptance-3").is_err());
    }
    #[test]
    fn run_must_be_exact_terminal_worker_owner_and_operator() {
        let prior = prior_begins(&serde_json::json!([begin("application-acceptance-3", 12, 23)]).to_string(), "application-acceptance-3").unwrap().remove(0);
        let operator = serde_json::json!({"id":12,"user":{"id":ACTOR_ID},"issue_url":ISSUE1,
            "body":"/host apply application-acceptance-3","created_at":"today","updated_at":"today"});
        let run = serde_json::json!({"id":23,"head_sha":revision(),"status":"completed",
            "conclusion":"success","event":"issue_comment","run_attempt":1,
            "actor":{"id":ACTOR_ID},"triggering_actor":{"id":ACTOR_ID},
            "path":".github/workflows/edge-control-plane.yml",
            "name":"/host apply application-acceptance-3"});
        let jobs = serde_json::json!({"total_count":1,"jobs":[{"name":"host_worker_authorizer",
            "run_id":23,"status":"completed","conclusion":"success"}]});
        assert!(prior_run_is_terminal(&prior, "application-acceptance-3", &operator, &run, &jobs));
        let mut failed = run.clone();
        failed["conclusion"] = Value::String("failure".into());
        assert!(!prior_run_is_terminal(&prior, "application-acceptance-3", &operator, &failed, &jobs));
        let mut wrong = jobs.clone();
        wrong["jobs"][0]["conclusion"] = Value::String("skipped".into());
        assert!(!prior_run_is_terminal(&prior, "application-acceptance-3", &operator, &run, &wrong));
        let mut wrong_actor = operator.clone();
        wrong_actor["user"]["id"] = Value::from(BOT_ID);
        assert!(!prior_run_is_terminal(&prior, "application-acceptance-3", &wrong_actor, &run, &jobs));
    }
}
