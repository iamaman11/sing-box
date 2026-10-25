#!/usr/bin/env python3
"""Reconcile ONE proven pre-CREATE abort; never replay an unknown VM mutation.

Executes ONLY within the existing protected GitHub environment/owner and
serial production-vultr concurrency group. Git keeps BEGIN/terminal history.
"""
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

REPO = "iamaman11/sing-box"
ACTOR = "44100369"
SOURCE_COMMENT = re.compile(r"^[1-9][0-9]{0,19}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
NO_REPLAY = "HOST_NATIVE_FIRST_USE_ABORT_V1"


class Blocked(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def github(path, method="GET", form=None, paginate=False):
    command = ["gh", "api"]
    if paginate:
        command.extend(["--paginate", "--slurp"])
    if method != "GET":
        command.extend(["-X", method])
    command.append(path)
    if form is not None:
        command.extend(["-f", "body=" + form])
    try:
        output = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=35
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("HOST_ABORT_GITHUB_TRANSPORT_UNAVAILABLE") from None
    require(output.returncode == 0, "HOST_ABORT_GITHUB_API_UNPROVEN")
    if method == "DELETE":
        return None
    require(len(output.stdout) < 3_000_000, "HOST_ABORT_GITHUB_RESPONSE_TOO_LARGE")
    try:
        return json.loads(output.stdout)
    except ValueError:
        raise Blocked("HOST_ABORT_GITHUB_SCHEMA_INVALID") from None


def pages(path):
    response = github(path, paginate=True)
    require(isinstance(response, list) and response, "HOST_ABORT_PAGINATION_UNPROVEN")
    require(all(isinstance(page, list) for page in response),
            "HOST_ABORT_PAGINATION_SCHEMA_INVALID")
    return [entry for page in response for entry in page]


def exact_branch(machine):
    prefix = f"host-receipt-{machine}-"
    candidates = github(f"repos/{REPO}/git/matching-refs/heads/{prefix}")
    require(isinstance(candidates, list) and len(candidates) == 1,
            "HOST_ABORT_RESERVATION_NOT_UNIQUE")
    item = candidates[0]
    ref = item.get("ref", "")
    require(re.fullmatch(r"refs/heads/" + re.escape(prefix) + r"([1-9][0-9]*)", ref)
            is not None, "HOST_ABORT_RESERVATION_SCOPE_INVALID")
    sha = item.get("object", {}).get("sha", "")
    require(bool(REVISION.fullmatch(sha)), "HOST_ABORT_REF_SHA_UNPROVEN")
    return ref.removeprefix("refs/heads/"), ref.removeprefix("refs/heads/" + prefix), sha


class DenyLogRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def read_job_log(job_id):
    """Fetch GitHub's official 302 signed log URL without forwarding API token.

    No raw log, JWT, registration token or download URL enters output.
    """
    require(isinstance(job_id, int) and job_id > 0, "HOST_ABORT_JOB_ID_INVALID")
    secret = os.environ.get("GH_TOKEN", "")
    require(bool(secret), "HOST_ABORT_GITHUB_IDENTITY_MISSING")
    url = f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs"
    req = Request(url, headers={
        "Authorization": "Bearer " + secret,
        "Accept": "application/vnd.github+json",
        "User-Agent": "sing-box-read-only-diagnostic",
    }, method="GET")
    response = None
    try:
        response = build_opener(DenyLogRedirect()).open(req, timeout=35)
        require(response.geturl() == url, "HOST_ABORT_JOB_LOG_ORIGIN_INVALID")
        raw = response.read(2_000_001)
    except HTTPError as error:
        require(error.code == 302, "HOST_ABORT_JOB_LOG_REDIRECT_INVALID")
        location = error.headers.get("Location", "")
        parsed = urlsplit(location)
        host = parsed.hostname or ""
        require(parsed.scheme == "https" and parsed.username is None and
                parsed.password is None and parsed.port in (None, 443) and
                (host.endswith(".actions.githubusercontent.com") or
                 host.endswith(".blob.core.windows.net")),
                "HOST_ABORT_JOB_LOG_SIGNED_LOCATION_INVALID")
        # Deliberately NO authorization headers on the redirected request.
        with urlopen(Request(location, headers={
                "User-Agent": "sing-box-read-only-diagnostic",
            }, method="GET"), timeout=45) as downloaded:
            raw = downloaded.read(2_000_001)
    except (URLError, OSError, TimeoutError, ValueError):
        raise Blocked("HOST_ABORT_ORIGINAL_JOB_LOG_UNAVAILABLE") from None
    finally:
        if response is not None:
            response.close()
    require(0 < len(raw) <= 2_000_000 and not raw.startswith(b"PK\x03\x04"),
            "HOST_ABORT_ORIGINAL_JOB_LOG_UNPROVEN")
    return raw.decode("utf-8", "replace")


def verify_original_run(machine, comment, revision, run_id):
    source = github(f"repos/{REPO}/issues/comments/{comment}")
    require(source.get("body", "").strip() == f"/host apply {machine}" and
            source.get("user", {}).get("id") == int(ACTOR),
            "HOST_ABORT_ORIGINAL_OPERATOR_COMMAND_UNPROVEN")
    run = github(f"repos/{REPO}/actions/runs/{run_id}")
    require(run.get("head_sha") == revision and
            run.get("event") == "issue_comment" and
            run.get("conclusion") == "failure" and
            run.get("run_attempt") == 1,
            "HOST_ABORT_ORIGINAL_RUN_NOT_TERMINAL")
    jobs = github(f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100")
    require(isinstance(jobs, dict) and jobs.get("total_count", 101) <= 100,
            "HOST_ABORT_ORIGINAL_JOBS_NOT_EXHAUSTIVE")
    matches = [j for j in jobs.get("jobs", []) if j.get("name") == "host_first_use"]
    require(len(matches) == 1 and matches[0].get("conclusion") == "failure",
            "HOST_ABORT_ORIGINAL_FIRST_USE_UNPROVEN")
    steps = matches[0].get("steps", [])
    def concluded(name, state):
        return sum(s.get("name") == name and s.get("conclusion") == state
                   for s in steps) == 1
    if (concluded("Execute exactly one no-SSH native Vultr CREATE", "skipped")
            and concluded("Get one short-lived GitHub runner registration capability", "failure")):
        return "PROVEN_SKIPPED"
    # One exact historical source-bound defect: the firewall binding lookup
    # occurs before the first provider POST in this accepted Rust revision.
    # Require BOTH matching step disposition and its actual unredacted job
    # error code from the immutable original GitHub Actions job log.
    require(revision == "43892f4c527b94b2d0cc07ff5bd95eaa56711115" and
            concluded("Get one short-lived GitHub runner registration capability", "success") and
            concluded("Execute exactly one no-SSH native Vultr CREATE", "failure"),
            "HOST_ABORT_CREATE_FAILURE_NOT_PROVEN_PREPOST")
    job_id = matches[0].get("id")
    text = re.sub(r"\x1b\[[0-9;]*m", "", read_job_log(job_id))
    require(sum(line.rstrip().endswith("HOST_FIRST_USE_FIREWALL_BINDING_UNPROVEN")
                for line in text.splitlines()) == 1 and
            "host_first_use_provider_plan=EXACT_CREATE_ONLY" in text and
            "host_first_use_preflight=PROVIDER_AND_WORKER_GET_PROVEN" in text and
            "host_first_use_provider_create=EXACT_NATIVE_CLOUD_INIT_ACCEPTED" not in text,
            "HOST_ABORT_FIREWALL_PREPOST_ERROR_NOT_PROVEN")
    return "PROVEN_NOT_ENTERED_PREPOST_FIREWALL"


def verify_reservation(machine, comment, sha, revision):
    prs = github(f"repos/{REPO}/pulls?state=all&head=iamaman11:host-receipt-{machine}-{comment}&per_page=100")
    require(isinstance(prs, list) and len(prs) == 1,
            "HOST_ABORT_RECEIPT_PR_NOT_UNIQUE")
    pr = prs[0]
    require(pr.get("state") == "closed" and not pr.get("merged_at") and
            pr.get("head", {}).get("sha") == sha and
            pr.get("head", {}).get("ref") == f"host-receipt-{machine}-{comment}" and
            pr.get("base", {}).get("ref") == "main" and
            pr.get("title") == f"ABORTED PRE-CREATE (NO ROOT RECEIPT): {machine}" and
            "TERMINAL: ABORTED BEFORE VM CREATE" in pr.get("body", ""),
            "HOST_ABORT_RECEIPT_PR_NOT_EXPLICITLY_ABORTED")
    # Reserved branch must contain *only* the old Git registry and its
    # original pending marker, NOT a native root key or fresh operator edits.
    def registry_at(ref):
        value = github(f"repos/{REPO}/contents/infra/hosts/hosts.textproto?ref={ref}")
        require(isinstance(value, dict) and value.get("encoding") == "base64" and
                value.get("type") == "file", "HOST_ABORT_REGISTRY_UNPROVEN")
        try:
            return base64.b64decode(value["content"], validate=False)
        except (ValueError, KeyError):
            raise Blocked("HOST_ABORT_REGISTRY_ENCODING_INVALID") from None
    old = registry_at(revision)
    reserved = registry_at(f"host-receipt-{machine}-{comment}")
    expected = old + f"\n# native-receipt-registration-pending {machine} issue1-comment-{comment}\n".encode()
    require(reserved == expected, "HOST_ABORT_RESERVED_REF_CONTENT_DRIFT")


def verify_runner_absent(machine):
    # Pagination is mandatory; absence in one GitHub page is not proof.
    data = github(f"repos/{REPO}/actions/runners?per_page=100", paginate=True)
    require(isinstance(data, list) and data and all(isinstance(x, dict) for x in data),
            "HOST_ABORT_RUNNER_INVENTORY_UNPROVEN")
    totals = {x.get("total_count") for x in data}
    runners = [r for page in data for r in page.get("runners", [])]
    require(len(totals) == 1 and totals.pop() == len(runners),
            "HOST_ABORT_RUNNER_INVENTORY_INCOMPLETE")
    require(not any(x.get("name") == f"sing-box-production-{machine}" for x in runners),
            "HOST_ABORT_RUNNER_ALREADY_REGISTERED")


def reconcile():
    machine = os.environ.get("TARGET_MACHINE", "")
    revision = os.environ.get("GITHUB_SHA", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    actor = os.environ.get("GITHUB_ACTOR_ID", "")
    comment = os.environ.get("SOURCE_COMMENT_ID", "")
    require(repo == REPO and actor == ACTOR and
            os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and
            os.environ.get("GITHUB_EVENT_NAME") == "issue_comment" and
            bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", machine)) and
            bool(REVISION.fullmatch(revision)) and bool(SOURCE_COMMENT.fullmatch(comment)),
            "HOST_ABORT_UNAUTHORIZED_CONTEXT")
    before = Path(os.environ["PROVIDER_PREFLIGHT_PROOF"]).read_text(encoding="utf-8")
    require("host_first_use_provider_plan=EXACT_CREATE_ONLY\n" in before + "\n" and
            "host_first_use_preflight=PROVIDER_AND_WORKER_GET_PROVEN\n" in before + "\n",
            "HOST_ABORT_FULL_PROVIDER_ABSENCE_NOT_PROVEN")
    require(github(f"repos/{REPO}/git/ref/heads/main").get("object", {}).get("sha") == revision,
            "HOST_ABORT_MAIN_MOVED")
    branch, origin, sha = exact_branch(machine)
    require(origin != comment, "HOST_ABORT_ORIGIN_MUST_BE_OLDER")
    entries = pages(f"repos/{REPO}/issues/26/comments?per_page=100")
    begins = []
    for entry in entries:
        raw = entry.get("body", "")
        expression = (r"HOST_NATIVE_FIRST_USE_BEGIN_V1 machine=" + re.escape(machine) +
                      r" issue1_comment=" + re.escape(origin) +
                      r" revision=([0-9a-f]{40}) run=([1-9][0-9]*) attempt=1 no_replay=true")
        match = re.fullmatch(expression, raw.strip())
        if match:
            begins.append((entry["id"], match.group(1), match.group(2)))
    require(len(begins) == 1, "HOST_ABORT_DURABLE_BEGIN_NOT_UNIQUE")
    begin_id, old_revision, run_id = begins[0]
    require(old_revision != revision, "HOST_ABORT_NOT_A_NEW_RELEASE")
    create_phase = verify_original_run(machine, origin, old_revision, run_id)
    verify_reservation(machine, origin, sha, old_revision)
    verify_runner_absent(machine)
    # Full provider inventory+exact CREATE plan was checked by the accepted
    # Rust owner using cursor pagination immediately before entering here.
    marker = (f"{NO_REPLAY} machine={machine} origin_comment={origin} "
              f"origin_run={run_id} begin={begin_id} branch={branch} "
              f"ref_sha={sha} revision={revision} "
              f"create={create_phase} provider=ABSENT_FULL_TYPED_PREFLIGHT "
              f"runner=ABSENT_FULL_INVENTORY no_replay=true")
    matches = [x for x in entries if x.get("body", "").strip() == marker]
    require(len(matches) <= 1, "HOST_ABORT_TERMINAL_EVIDENCE_AMBIGUOUS")
    if not matches:
        github(f"repos/{REPO}/issues/26/comments", method="POST", form=marker)
    # Re-check exact original ref after writing the durable terminal record.
    check_branch, check_origin, check_sha = exact_branch(machine)
    require((check_branch, check_origin, check_sha) == (branch, origin, sha),
            "HOST_ABORT_REF_CHANGED_AFTER_TERMINAL")
    github(f"repos/{REPO}/git/refs/heads/{branch}", method="DELETE")
    require(github(f"repos/{REPO}/git/matching-refs/heads/host-receipt-{machine}-") == [],
            "HOST_ABORT_RESERVATION_NOT_RETIRED")
    print("host_first_use_abort=TERMINAL_PRECREATE_RECONCILED")
    print(f"host_machine_id={machine}")
    print(f"host_previous_operation_id=issue1-comment-{origin}")
    print("host_provider_mutations=0")
    print("host_vm_create=NOT_EXECUTED")
    print("host_replay_allowed=false")


if __name__ == "__main__":
    try:
        reconcile()
    except (Blocked, OSError, KeyError, TypeError, ValueError) as e:
        reason = str(e) if isinstance(e, Blocked) else "HOST_ABORT_EVIDENCE_UNAVAILABLE"
        print(reason if re.fullmatch(r"HOST_ABORT_[A-Z0-9_]+", reason)
              else "HOST_ABORT_EVIDENCE_UNAVAILABLE", file=sys.stderr)
        raise SystemExit(1)
