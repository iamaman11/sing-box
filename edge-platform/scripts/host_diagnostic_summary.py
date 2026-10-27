#!/usr/bin/env python3
"""One read-only /host --deep diagnosis from EXISTING Git and provider evidence.

The Rust host status owns Git facts; host_capability_preflight owns bounded
Cloudflare/Vultr/GitHub GETs. This module initially joins them without native authority. A subsequent report
merge accepts only fields that the hosted pinned Rust verifier already proved;
Python does not authenticate signatures or authorize mutations.
JSON is the existing GitHub Actions output boundary, not a desired-state store.
"""
from dataclasses import asdict, dataclass
import json
import os
import re
import sys

TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{1,119}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MACHINE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
OP = re.compile(r"^issue1-comment-[1-9][0-9]{0,19}$")
GIT_PHASES = {"BLOCKED", "PREPARED_GIT_ONLY", "ENROLLED_GIT_ONLY"}


@dataclass(frozen=True)
class Diagnostic:
    schema: str
    machine_id: str
    phase: str
    status: str
    owner: str
    reason: str
    last_proven_step: str
    next_action: str
    operation_id: str
    source_digest: str
    release_set_sha256: str
    replay_allowed: bool
    mutation_authorized: bool
    physical_accepted: bool
    sources: dict
    provider_mutations: int
    worker_mutations: int
    github_mutations: int


def token(value):
    """No untrusted API response bodies or arbitrary header strings escape."""
    return value if isinstance(value, str) and TOKEN.fullmatch(value) else "UNPROVEN_INVALID_SOURCE_CODE"


def fuse(observation, git, *, machine_id, operation_id, source_digest,
         release_set_sha256, worker_bundle_status="UNPROVEN_GIT_PIN_ONLY"):
    if not (MACHINE.fullmatch(machine_id) and OP.fullmatch(operation_id)
            and SHA.fullmatch(source_digest) and DIGEST.fullmatch(release_set_sha256)):
        raise ValueError("HOST_DIAGNOSTIC_CORRELATION_INVALID")
    if not isinstance(observation, dict) or observation.get("machine_id") != machine_id:
        raise ValueError("HOST_DIAGNOSTIC_OBSERVATION_SCOPE_MISMATCH")
    if (observation.get("scope") != "READ_ONLY_PROTECTED_ENVIRONMENT"
            or any(observation.get(field) != 0 for field in
                   ("provider_mutations", "worker_mutations", "github_mutations"))):
        raise ValueError("HOST_DIAGNOSTIC_MUTATION_EVIDENCE_INVALID")
    phase = git.get("phase")
    if phase not in GIT_PHASES or any(
            token(git.get(key)) == "UNPROVEN_INVALID_SOURCE_CODE"
            for key in ("owner", "reason", "last_proven_step", "next_action")):
        raise ValueError("HOST_DIAGNOSTIC_GIT_OWNER_INVALID")
    # Every entry is an already observed closed enum. Do not invent a live
    # native result from a public Git receipt, runner status or Docker desired.
    names = {
        "git": git["reason"],
        "vultr": observation.get("vultr_machine"),
        "worker_access": observation.get("worker_host_route_get"),
        "worker_bundle": worker_bundle_status,
        "worker_source": observation.get("worker_active_deployment"),
        "worker_signer": observation.get("worker_host_signing_bindings"),
        "runner": observation.get("github_runner_state"),
    }
    sources = {key: token(value) for key, value in names.items()}
    sources["cloud_init"] = "UNPROVEN_NO_NATIVE_OR_PROVIDER_BOOT_JOURNAL"
    sources["root_agent"] = "UNPROVEN_NO_SIGNED_NATIVE_OBSERVATION"
    sources["signed_receipt"] = "UNPROVEN_GIT_PIN_IS_NOT_PHYSICAL_RECEIPT"

    status, owner, reason, last, next_action, current_phase = (
        "UNPROVEN", "ROOT_AGENT", "HOST_PHYSICAL_OBSERVATION_REQUIRED",
        git["last_proven_step"], "VERIFY_SIGNED_NATIVE_OBSERVATION",
        "NATIVE_OBSERVATION",
    )
    if phase == "BLOCKED":
        status, owner, reason, last, next_action, current_phase = (
            "BLOCKED", git["owner"], git["reason"], git["last_proven_step"],
            git["next_action"], "GIT_READINESS",
        )
    elif sources["worker_access"] != "GET_204_WORKER_JWT_VERIFIED_NOT_SIGNING_PROOF":
        status, owner, reason, last, next_action, current_phase = (
            "BLOCKED", "CLOUDFLARE_ACCESS",
            sources["worker_access"], "GIT_FIRST_USE_REFERENCE_ONLY",
            "VERIFY_ACCESS_POLICY_AND_WORKER_ROUTE", "WORKER_ACCESS",
        )
    elif sources["worker_bundle"] != "GIT_PIN_EXACT_ACCESS_GET_PROVEN":
        status, owner, reason, last, next_action, current_phase = (
            "BLOCKED", "CLOUDFLARE_WORKER_SOURCE",
            sources["worker_bundle"], "WORKER_ACCESS_GET_ONLY",
            "VERIFY_EXACT_GIT_PINNED_WORKER_BUNDLE", "WORKER_SOURCE",
        )
    elif sources["vultr"] not in (
            "LABEL_ABSENT_SINGLE_PAGE_NOT_CREATE_AUTHORITY",
            "EXACT_LABEL_PRESENT_NO_CREATE"):
        status, owner, reason, last, next_action, current_phase = (
            "BLOCKED", "VULTR_PROVIDER", sources["vultr"],
            "WORKER_ACCESS_GET_ONLY", "VERIFY_EXACT_VULTR_INVENTORY",
            "VULTR_INVENTORY",
        )
    elif sources["vultr"] == "LABEL_ABSENT_SINGLE_PAGE_NOT_CREATE_AUTHORITY":
        status, owner, reason, last, next_action, current_phase = (
            "UNPROVEN", "VULTR_FIRST_USE",
            "HOST_VM_ABSENT_FIRST_USE_NOT_EXECUTED",
            "VULTR_LABEL_ABSENT_BOUNDED_GET",
            "VERIFY_FIRST_USE_ADMISSION_BEFORE_ANY_CREATE",
            "BEFORE_VM_CREATE",
        )
    elif sources["runner"] != "RUNNER_ONLINE_IDLE_NOT_NATIVE_PROOF":
        status, owner, reason, last, next_action, current_phase = (
            "UNPROVEN", "GITHUB_RUNNER", sources["runner"],
            "VULTR_LABEL_PRESENT_NOT_NATIVE_PROOF",
            "CHECK_RUNNER_AND_PROVIDER_CONSOLE_JOURNAL",
            "BOOTSTRAP_OR_RUNNER",
        )
    return asdict(Diagnostic(
        schema="sing-box.host-diagnostic/v1", machine_id=machine_id,
        phase=current_phase, status=status, owner=owner, reason=reason,
        last_proven_step=last, next_action=next_action, operation_id=operation_id,
        source_digest=source_digest, release_set_sha256=release_set_sha256,
        replay_allowed=False, mutation_authorized=False, physical_accepted=False,
        sources=sources, provider_mutations=0, worker_mutations=0,
        github_mutations=0,
    ))


def merge_rust_verified_native(original, native_readback, comment_id, expected_source):
    """Update ONE pre-existing JSON only after hosted Rust proved Ed25519.

    Caller MUST check typed.outputs.native_snapshot_proof, which only the
    Git-pinned Rust verifier writes. Text here supplies bounded presentation,
    NEVER signature authority or mutation admission.
    """
    marker = "### Unified deep diagnosis — read only\n\n" + "```json\n"
    if original.count(marker) != 1:
        raise ValueError("HOST_DIAG_REPORT_MARKER_INVALID")
    before, remaining = original.split(marker, 1)
    if "\n```" not in remaining:
        raise ValueError("HOST_DIAG_REPORT_FENCE_MISSING")
    json_text, suffix = remaining.split("\n```", 1)
    if len(json_text) > 8192:
        raise ValueError("HOST_DIAG_REPORT_JSON_TOO_LARGE")
    report = json.loads(json_text)
    op = "issue1-comment-" + comment_id
    if (not OP.fullmatch(op) or not SHA.fullmatch(expected_source)
            or report.get("schema") != "sing-box.host-diagnostic/v1"
            or report.get("operation_id") != op
            or report.get("source_digest") != expected_source
            or not DIGEST.fullmatch(report.get("release_set_sha256", ""))
            or any(report.get(k) is not False for k in
                   ("replay_allowed", "mutation_authorized", "physical_accepted"))
            or any(report.get(k) != 0 for k in
                   ("provider_mutations", "worker_mutations", "github_mutations"))
            or not isinstance(report.get("sources"), dict)):
        raise ValueError("HOST_DIAG_SIGNED_SCOPE_MISMATCH")

    evidence = {}
    for line in native_readback.splitlines():
        if not line.startswith("host_native_snapshot_"):
            continue
        if "=" not in line:
            raise ValueError("HOST_DIAG_SIGNED_FIELD_INVALID")
        key, value = line.split("=", 1)
        key = key.removeprefix("host_native_snapshot_")
        if key in evidence or len(value) > 128:
            raise ValueError("HOST_DIAG_SIGNED_FIELD_DUPLICATE_OR_LARGE")
        evidence[key] = value
    proof = evidence.get("proof")
    stale = proof == "VERIFIED_ROOT_SIGNED_STALE_RELEASE_READ_ONLY"
    if (proof not in ("VERIFIED_ROOT_SIGNED_READ_ONLY",
                      "VERIFIED_ROOT_SIGNED_STALE_RELEASE_READ_ONLY")
            or evidence.get("operation_id") != op
            or evidence.get("replay_allowed") != "false"
            or evidence.get("mutations") != "0"):
        raise ValueError("HOST_DIAG_SIGNED_VERDICT_UNPROVEN")
    # All fields originate from the hosted Rust verifier, which checked the
    # pinned Ed25519 key. A historical installed SHA is NOT authenticated
    # current Git parity nor an independently fetched ReleaseSet artifact.
    if stale:
        if (evidence.get("release_parity") != "INSTALLED_RELEASE_DRIFT"
                or evidence.get("release_provenance") != "ROOT_SIGNED_INSTALLED_CLAIM_ONLY"
                or evidence.get("verdict") != "INSTALLED_RELEASE_DRIFT_CURRENT_STATE_UNPROVEN"
                or not DIGEST.fullmatch(evidence.get("installed_release_sha256", ""))
                or evidence.get("desired_release_sha256") != report["release_set_sha256"]
                or evidence["installed_release_sha256"] == report["release_set_sha256"]):
            raise ValueError("HOST_DIAG_SIGNED_STALE_RELEASE_CONTRADICTION")
    try:
        pending = int(evidence["pending_count"])
        restarts = int(evidence["line2_restarts"])
        last_exit = int(evidence["line2_exit"])
    except (KeyError, ValueError) as exc:
        raise ValueError("HOST_DIAG_SIGNED_METRIC_INVALID") from exc
    if not (0 <= pending <= 64 and 0 <= restarts < 1_000_000_000
            and -1 <= last_exit <= 255
            and TOKEN.fullmatch(evidence.get("line2_failure_code", ""))
            and (not evidence.get("line2_log_sha256") or
                 DIGEST.fullmatch(evidence["line2_log_sha256"]))):
        raise ValueError("HOST_DIAG_SIGNED_METRIC_SCOPE_INVALID")
    pending_op = evidence.get("pending_operation", "")
    pending_resource = evidence.get("pending_resource", "")
    pending_digest = evidence.get("pending_request_sha256", "")
    if pending:
        if (not OP.fullmatch(pending_op) or
                not re.fullmatch(r"[a-zA-Z0-9._/-]{1,128}", pending_resource) or
                not DIGEST.fullmatch(pending_digest)):
            raise ValueError("HOST_DIAG_SIGNED_PENDING_INVALID")
    elif pending_op or pending_resource or pending_digest:
        raise ValueError("HOST_DIAG_SIGNED_PENDING_UNEXPECTED")

    # Only accept bounded fields that the existing Git-pinned Rust verifier
    # extracted from the Ed25519-verified native snapshot. No Python signing,
    # source-of-truth override, or new diagnostic state machine.
    verdict = evidence.get("verdict", "UNPROVEN")
    if not TOKEN.fullmatch(verdict):
        raise ValueError("HOST_DIAG_SIGNED_VERDICT_INVALID")
    ready_proven = evidence.get("runtime_ready_proven")
    ready = evidence.get("runtime_ready")
    reason_count_text = evidence.get("reason_count")
    runtime = None
    if any(value is not None for value in (ready_proven, ready, reason_count_text)):
        if (ready_proven not in ("true", "false") or ready not in ("true", "false")
                or reason_count_text is None or not reason_count_text.isascii()
                or not reason_count_text.isdecimal()
                or int(reason_count_text) > 12
                or (ready == "true" and ready_proven != "true")):
            raise ValueError("HOST_DIAG_SIGNED_RUNTIME_INVALID")
        reason_count = int(reason_count_text)
        codes = []
        for index in range(reason_count):
            code = evidence.get(f"reason_{index}_code")
            if not isinstance(code, str) or len(code) > 96 or not TOKEN.fullmatch(code):
                raise ValueError("HOST_DIAG_SIGNED_REASON_INVALID")
            codes.append(code)
        actual_keys = {key for key in evidence
                       if re.fullmatch(r"reason_[0-9]{1,2}_code", key)}
        expected_keys = {f"reason_{index}_code" for index in range(reason_count)}
        if actual_keys != expected_keys:
            raise ValueError("HOST_DIAG_SIGNED_REASON_MISMATCH")
        runtime = {
            "ready_proven": ready_proven == "true",
            "ready": ready == "true",
            "reason_codes": codes,
        }
    elif any(re.fullmatch(r"reason_[0-9]{1,2}_code", key) for key in evidence):
        raise ValueError("HOST_DIAG_SIGNED_REASON_WITHOUT_COUNT")

    report["sources"]["root_agent"] = proof
    report["sources"]["native_snapshot"] = proof
    report["sources"]["signed_receipt"] = "UNPROVEN_NO_MUTATION_RECEIPT"
    report["sources"]["native_job"] = "VERIFIED_READ_ONLY_RUNNER_DELIVERY"
    # Preserve the early GitHub runner API status in sources for provenance.
    # A busy runner at initial GET is NOT proof that its later job failed.
    report["native"] = {
        "scope": "ROOT_SIGNED_READ_ONLY",
        "pending_count": pending,
        "pending_operation_id": pending_op,
        "pending_resource": pending_resource,
        "pending_request_sha256": pending_digest,
        "line2_failure_code": evidence["line2_failure_code"],
        "line2_restarts": restarts,
        "line2_last_exit": last_exit,
        "line2_log_sha256": evidence.get("line2_log_sha256", ""),
        "replay_allowed": False,
        "mutation_authorized": False,
        "snapshot_verdict": verdict,
    }
    if stale:
        report["native"]["installed_release_sha256"] = evidence["installed_release_sha256"]
        report["native"]["release_parity"] = "INSTALLED_RELEASE_DRIFT"
        report["native"]["release_provenance"] = "ROOT_SIGNED_INSTALLED_CLAIM_ONLY"
    if runtime is not None:
        report["native"]["runtime"] = runtime
    # Source drift is independent of runtime failure and of the historical
    # pending BEGIN. Never treat a current logical bundle mismatch as evidence
    # that the older signed Docker effect was not executed.
    bundle_fields = ("bundle_expected_sha256", "bundle_observed_sha256", "bundle_matches")
    if any(key in evidence for key in bundle_fields):
        if (not all(key in evidence for key in bundle_fields)
                or not DIGEST.fullmatch(evidence["bundle_expected_sha256"])
                or (evidence["bundle_observed_sha256"]
                    and not DIGEST.fullmatch(evidence["bundle_observed_sha256"]))
                or evidence["bundle_matches"] not in ("true", "false")):
            raise ValueError("HOST_DIAG_SIGNED_BUNDLE_INVALID")
        matches = evidence["bundle_matches"] == "true"
        if matches != (evidence["bundle_expected_sha256"]
                       == evidence["bundle_observed_sha256"]):
            raise ValueError("HOST_DIAG_SIGNED_BUNDLE_CONTRADICTION")
        report["native"]["bundle"] = {
            "matches_current_release": matches,
            "expected_sha256": evidence["bundle_expected_sha256"],
            "observed_sha256": evidence["bundle_observed_sha256"],
        }
    # A provider or Git BLOCKED reason is still binding. Replace the early
    # runner-busy placeholder only after hosted Rust verified this very
    # operation's root signature. Never mark current release physically GO.
    if report["phase"] in ("BOOTSTRAP_OR_RUNNER", "NATIVE_OBSERVATION"):
        if pending:
            report.update(
                phase="NATIVE_SIGNED_OBSERVATION",
                status="BLOCKED",
                owner="ROOT_AGENT",
                reason="HOST_RESOURCE_PENDING_NO_REPLAY",
                last_proven_step="ROOT_SIGNED_PENDING_OBSERVATION",
                next_action="READ_ONLY_RECONCILE_ORIGINAL_BEGIN_AND_FAILED_PREDICATE",
            )
        elif stale:
            report.update(
                phase="INSTALLED_RELEASE_READ_ONLY",
                status="UNPROVEN",
                owner="ROOT_AGENT",
                reason="INSTALLED_RELEASE_DRIFT",
                last_proven_step="ROOT_SIGNED_INSTALLED_SNAPSHOT",
                next_action="VERIFY_CURRENT_RELEASE_AND_PLAN_SIGNED_OWNER_REFRESH",
            )
    return (before + marker +
            json.dumps(report, sort_keys=True, separators=(",", ":")) +
            "\n```" + suffix)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--merge-signed"]:
        if len(sys.argv) != 6:
            raise SystemExit("HOST_DIAG_SIGNED_ARGS_INVALID")
        _, _, original_path, readback_path, comment_id, expected_source = sys.argv
        try:
            with open(original_path, encoding="utf-8") as fp:
                original = fp.read(20001)
            with open(readback_path, encoding="utf-8") as fp:
                native = fp.read(65537)
            if len(original) > 20000 or len(native) > 65536:
                raise ValueError("HOST_DIAG_SIGNED_INPUT_TOO_LARGE")
            print(merge_rust_verified_native(original, native, comment_id, expected_source))
        except (ValueError, KeyError, TypeError, UnicodeError, OSError) as error:
            raise SystemExit("HOST_DIAG_SIGNED_MERGE_REJECTED") from error
        sys.exit(0)
    raw = sys.stdin.read(8193)
    if len(raw) > 8192:
        raise SystemExit("HOST_DIAGNOSTIC_INPUT_TOO_LARGE")
    try:
        source = json.loads(raw)
        result = fuse(
            source,
            {
                "phase": os.environ["GIT_PHASE"],
                "owner": os.environ["GIT_OWNER"],
                "reason": os.environ["GIT_REASON"],
                "last_proven_step": os.environ["GIT_LAST_PROVEN_STEP"],
                "next_action": os.environ["GIT_NEXT_ACTION"],
            },
            machine_id=os.environ["TARGET_MACHINE"],
            operation_id=os.environ["OPERATION_ID"],
            source_digest=os.environ["GITHUB_SHA"],
            release_set_sha256=os.environ["RELEASE_SET_SHA256"],
            worker_bundle_status=os.environ["VM_BUNDLE_STATUS"],
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise SystemExit("HOST_DIAGNOSTIC_INPUT_REJECTED") from error
