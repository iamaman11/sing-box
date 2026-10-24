#!/usr/bin/env python3
"""Derive canonical VM Worker code and its accepted-main predecessor.

Only the authenticated protected-main baseline and its first-parent ancestry
are eligible as predecessors. Never select intermediate feature-branch commits:
those bytes may have passed CI but were never promoted or installed.
Generated source bytes are compared by full SHA-256, never by a version tag.
No network, cloud operations, credentials, or alternate mutation authority.
"""
import argparse
import hashlib
import subprocess
from pathlib import Path

WORKER_PATH="edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs"

def varint(value: int) -> bytes:
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)

def dummy(generation: int) -> bytes:
    return b"\x08\x01\x10" + varint(generation) + b"\x18\x02\x20\x01"

def generated_source(body: str) -> bytes:
    start = 'let source = r#"'
    end = '"#\n        .replace("__PROJECTION__"'
    if body.count(start) != 1 or body.count(end) != 1:
        raise ValueError("Worker source template not unique")
    code = body.split(start, 1)[1].split(end, 1)[0]
    substitutions = {
        "__PROJECTION__": "2",
        "__HOST_SIGNER_PROJECTION__": "2",
        "__DUMMY_A_DIGEST__": hashlib.sha256(dummy(9_000_001)).hexdigest(),
        "__DUMMY_B_DIGEST__": hashlib.sha256(dummy(9_000_002)).hexdigest(),
        "__DUMMY_A_GENERATION__": "9000001",
        "__DUMMY_B_GENERATION__": "9000002",
    }
    for key, value in substitutions.items():
        code = code.replace(key, value)
    if "__" in code:
        raise ValueError("unknown generated Worker placeholder")
    return code.encode("utf-8")

def digest(body: str) -> str:
    return hashlib.sha256(generated_source(body)).hexdigest()

def run_git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, timeout=30).strip()

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--accepted-baseline", required=True,
                        help="protected main at PR creation, or the main merge first parent")
    args = parser.parse_args()
    baseline = args.accepted_baseline
    if len(baseline) != 40 or not all(c in "0123456789abcdef" for c in baseline):
        raise SystemExit("accepted protected-main baseline must be a full lowercase Git SHA")
    # GitHub Actions supplies baseline from the PR base or protected merge
    # parent, never from a user-controlled issue, config file or environment.
    try:
        run_git("cat-file", "-e", baseline + "^{commit}")
        run_git("merge-base", "--is-ancestor", baseline, "HEAD")
    except subprocess.CalledProcessError:
        raise SystemExit("accepted protected-main baseline is not an ancestor of candidate") from None
    current = digest(args.source.read_text(encoding="utf-8"))
    # Explicitly inspect baseline even if the Worker file did not change in
    # that main commit (path-filtered git log would otherwise omit it).
    revisions = [baseline] + run_git(
        "log", "--first-parent", "--format=%H", baseline, "--", WORKER_PATH
    ).splitlines()
    if not revisions:
        raise SystemExit("no protected first-parent Worker source history")
    previous = None
    for revision in dict.fromkeys(revisions):
        try:
            body = run_git("show", revision + ":" + WORKER_PATH)
            candidate = digest(body)
        except (subprocess.CalledProcessError, ValueError):
            continue
        if candidate != current:
            previous = (revision, candidate)
            break
    if previous is None:
        raise SystemExit("no distinct accepted Worker predecessor in Git ancestry")
    print("vm_worker_source_sha256=" + current)
    print("vm_worker_predecessor_sha256=" + previous[1])
    print("vm_worker_predecessor_revision=" + previous[0])

if __name__ == "__main__":
    main()
