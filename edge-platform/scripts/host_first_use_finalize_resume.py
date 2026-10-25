#!/usr/bin/env python3
"""Recover EXACT existing first-use native proof; NEVER issue VM CREATE.

Protected GitHub /host recover already serializes this under the native Vultr
control lock. Fail-closed on any ambiguous BEGIN, run, artifact or receipt.
This module performs only GitHub GET; mutation is left to authenticated Rust.
"""
import os
import re
import sys
from pathlib import Path
from host_first_use_abort import (
    ACTOR, REPO, Blocked, exact_branch, github, pages, read_job_log, require,
    verify_reservation as _unused_abort_only,
)

RE_HEX = re.compile(r"^[0-9a-f]{40}$")
RE_COMMENT = re.compile(r"^[1-9][0-9]{0,19}$")


def exactly_step(j, name, state):
    return sum(s.get("name") == name and s.get("conclusion") == state
               for s in j.get("steps", [])) == 1


def verify():
    machine = os.environ.get("TARGET_MACHINE", "")
    current = os.environ.get("GITHUB_SHA", "")
    source = os.environ.get("SOURCE_COMMENT_ID", "")
    actor = os.environ.get("GITHUB_ACTOR_ID", "")
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and
            os.environ.get("GITHUB_EVENT_NAME") == "issue_comment" and
            os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and
            actor == ACTOR and RE_HEX.fullmatch(current) and
            RE_COMMENT.fullmatch(source) and
            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", machine),
            "HOST_RESUME_UNAUTHORIZED_CONTEXT")
    require(github(f"repos/{REPO}/git/ref/heads/main").get("object", {}).get("sha") == current,
            "HOST_RESUME_MAIN_MOVED")
    branch, origin, reserved_sha = exact_branch(machine)
    require(origin != source and RE_COMMENT.fullmatch(origin),
            "HOST_RESUME_ORIGIN_COMMENT_INVALID")
    original = github(f"repos/{REPO}/issues/comments/{origin}")
    require(original.get("body", "").strip() == f"/host apply {machine}" and
            original.get("user", {}).get("id") == int(ACTOR) and
            original.get("issue_url") == f"https://api.github.com/repos/{REPO}/issues/1",
            "HOST_RESUME_ORIGINAL_COMMAND_UNPROVEN")
    begin_pattern = re.compile(
        r"HOST_NATIVE_FIRST_USE_BEGIN_V1 machine=" + re.escape(machine) +
        r" issue1_comment=" + re.escape(origin) +
        r" revision=([0-9a-f]{40}) run=([1-9][0-9]*) attempt=1 no_replay=true")
    begins = []
    entries = pages(f"repos/{REPO}/issues/26/comments?per_page=100")
    for comment in entries:
        match = begin_pattern.fullmatch(comment.get("body", "").strip())
        if match:
            begins.append((comment.get("id"), match.group(1), match.group(2)))
    require(len(begins) == 1, "HOST_RESUME_DURABLE_BEGIN_NOT_UNIQUE")
    _, original_sha, run_id = begins[0]
    require(original_sha != current and RE_HEX.fullmatch(original_sha),
            "HOST_RESUME_RELEASE_BINDING_UNPROVEN")
    aborts = [c for c in entries if c.get("body", "").startswith(
        f"HOST_NATIVE_FIRST_USE_ABORT_V1 machine={machine} origin_comment={origin} ")]
    require(not aborts, "HOST_RESUME_ORIGIN_ALREADY_ABORTED")
    run = github(f"repos/{REPO}/actions/runs/{run_id}")
    require(run.get("head_sha") == original_sha and
            run.get("event") == "issue_comment" and
            run.get("conclusion") == "failure" and run.get("run_attempt") == 1,
            "HOST_RESUME_ORIGINAL_RUN_UNPROVEN")
    jobs_response = github(f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100")
    require(isinstance(jobs_response, dict) and
            jobs_response.get("total_count", 101) <= 100,
            "HOST_RESUME_ORIGINAL_JOBS_NOT_EXHAUSTIVE")
    jobs = jobs_response.get("jobs", [])
    def one_job(name, result):
        matched = [j for j in jobs if j.get("name") == name]
        require(len(matched) == 1 and matched[0].get("conclusion") == result,
                "HOST_RESUME_ORIGINAL_JOB_STATE_INVALID")
        return matched[0]
    created = one_job("host_first_use", "success")
    proof = one_job("host_first_use_native_proof", "success")
    failed = one_job("host_first_use_finalize", "failure")
    require(exactly_step(created, "Execute exactly one no-SSH native Vultr CREATE", "success") and
            exactly_step(proof, "Collect exact installed Root Agent public proof", "success"),
            "HOST_RESUME_NATIVE_FIRST_USE_NOT_PROVEN")
    require(exactly_step(failed, "Verify signed root proof and scrub provider user-data with GET",
                         "failure") and
            exactly_step(failed, "Complete ONLY the reserved protected public receipt PR",
                         "skipped"), "HOST_RESUME_FAILURE_STAGE_MISMATCH")
    log = read_job_log(failed.get("id"))
    require(log.count("EDGE_RELEASE_CONTEXT_PATH is required for edge-orchestrator") == 1,
            "HOST_RESUME_ORIGINAL_FAILURE_NOT_CTX")
    prs = github(f"repos/{REPO}/pulls?state=open&head=iamaman11:{branch}&per_page=100")
    require(isinstance(prs, list) and len(prs) == 1,
            "HOST_RESUME_RECEIPT_PR_NOT_UNIQUE")
    pr = prs[0]
    require(pr.get("draft") is True and pr.get("state") == "open" and
            not pr.get("merged_at") and pr.get("head", {}).get("sha") == reserved_sha and
            pr.get("head", {}).get("ref") == branch and
            pr.get("base", {}).get("ref") == "main" and
            pr.get("title") == f"host: register native receipt for {machine}",
            "HOST_RESUME_RESERVED_PR_DRIFT")
    artifact_list = github(f"repos/{REPO}/actions/runs/{run_id}/artifacts?per_page=100")
    require(isinstance(artifact_list, dict) and
            artifact_list.get("total_count", 101) <= 100,
            "HOST_RESUME_ARTIFACTS_NOT_EXHAUSTIVE")
    expected_name = f"native-first-use-proof-{run_id}"
    artifacts = [x for x in artifact_list.get("artifacts", [])
                 if x.get("name") == expected_name]
    require(len(artifacts) == 1 and not artifacts[0].get("expired") and
            artifacts[0].get("size_in_bytes", 1_000_000) <= 4096 and
            artifacts[0].get("workflow_run", {}).get("id") == int(run_id),
            "HOST_RESUME_NATIVE_PROOF_ARTIFACT_UNPROVEN")
    output = os.environ.get("GITHUB_OUTPUT", "")
    require(output and Path(output).is_file(), "HOST_RESUME_OUTPUT_REQUIRED")
    with open(output, "a", encoding="utf-8") as out:
        out.write(f"original_sha={original_sha}\noriginal_run={run_id}\n"
                  f"original_comment={origin}\noriginal_branch={branch}\n")
    print("host_first_use_resume=EXACT_CREATED_ROOT_PROOF_SOURCE_VERIFIED_GET_ONLY")
    print("host_provider_mutations=0")
    print("host_replay_allowed=false")


if __name__ == "__main__":
    try:
        verify()
    except (Blocked, OSError, TypeError, KeyError, ValueError) as error:
        reason = str(error) if isinstance(error, Blocked) else "HOST_RESUME_EVIDENCE_UNAVAILABLE"
        print(reason if re.fullmatch(r"HOST_RESUME_[A-Z0-9_]+|HOST_ABORT_[A-Z0-9_]+", reason)
              else "HOST_RESUME_EVIDENCE_UNAVAILABLE", file=sys.stderr)
        raise SystemExit(1)
