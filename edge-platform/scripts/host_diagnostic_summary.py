#!/usr/bin/env python3
"""One read-only /host --deep diagnosis from EXISTING Git and provider evidence.

The Rust host status owns Git facts; host_capability_preflight owns bounded
Cloudflare/Vultr/GitHub GETs. This module only joins them, never performs I/O,
accesses secrets or promotes a runner/API result to signed native proof.
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
            sources["worker_access"], "WORKER_BUNDLE_EXACT_GET_PROVEN" if sources["worker_bundle"] == "GIT_PIN_EXACT_ACCESS_GET_PROVEN" else "GIT_FIRST_USE_REFERENCE_ONLY",
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


def attach_verified_native(original, comment_id):
    """Only Rust-verified native evidence may upgrade the existing issue JSON."""
    marker = "### Unified deep diagnosis — read only\n\n" + chr(96) * 3 + "json\n"
    if original.count(marker) != 1:
        raise ValueError("HOST_DIAGNOSTIC_REPORT_MISSING")
    before, remaining = original.split(marker, 1)
    raw, suffix = remaining.split("\n" + chr(96) * 3, 1)
    data = json.loads(raw)
    if (data.get("schema") != "sing-box.host-diagnostic/v1"
            or data.get("operation_id") != "issue1-comment-" + comment_id
            or data.get("physical_accepted") is not False
            or data.get("replay_allowed") is not False
            or data.get("mutation_authorized") is not False
            or not isinstance(data.get("sources"), dict)):
        raise ValueError("HOST_DIAGNOSTIC_NATIVE_CORRELATION_INVALID")
    data["sources"]["root_agent"] = "VERIFIED_ROOT_SIGNED_READ_ONLY"
    data["sources"]["native_snapshot"] = "VERIFIED_ROOT_SIGNED_READ_ONLY"
    data["sources"]["signed_receipt"] = "UNPROVEN_NO_MUTATION_RECEIPT"
    data["native_observation_authenticated"] = True
    data["last_proven_step"] = "ROOT_SIGNED_READ_ONLY_SNAPSHOT"
    return before + marker + json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n" + chr(96) * 3 + suffix


if __name__ == "__main__" and sys.argv[1:] == ["--attach-native"]:
    try:
        if os.environ["NATIVE_SNAPSHOT_PROOF"] != "VERIFIED_ROOT_SIGNED_READ_ONLY":
            raise ValueError("HOST_DIAGNOSTIC_NATIVE_PROOF_NOT_VERIFIED")
        comment = os.environ["SOURCE_COMMENT_ID"]
        if not comment.isdigit() or int(comment) == 0:
            raise ValueError("HOST_DIAGNOSTIC_COMMENT_INVALID")
        original = sys.stdin.read(25001)
        if len(original) > 25000:
            raise ValueError("HOST_DIAGNOSTIC_REPORT_OVERSIZED")
        print(attach_verified_native(original, comment), end="")
    except (ValueError, KeyError, json.JSONDecodeError):
        raise SystemExit("HOST_DIAGNOSTIC_NATIVE_REPORT_REJECTED")
elif __name__ == "__main__":
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
