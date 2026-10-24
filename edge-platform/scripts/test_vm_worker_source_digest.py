#!/usr/bin/env python3
"""No-network regression: a feature branch's intermediate Worker never becomes accepted predecessor."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from vm_worker_source_digest import WORKER_PATH, digest, generated_source


SCRIPT = Path(__file__).resolve().with_name("vm_worker_source_digest.py")


def git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def write_worker(root: Path, marker: str) -> str:
    target = root / WORKER_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    body = 'let source = r#"const MARKER="' + marker + '";\n"#\n        .replace("__PROJECTION__", "2");\n'
    target.write_text(body, encoding="utf-8")
    return digest(body)


def commit(root: Path, message: str) -> str:
    git(root, "add", "--", WORKER_PATH)
    git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


def evidence(root: Path, baseline: str):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--source", WORKER_PATH,
         "--accepted-baseline", baseline],
        cwd=root, text=True, capture_output=True, timeout=30
    )


def values(result):
    assert result.returncode == 0, result.stderr
    return dict(line.split("=", 1) for line in result.stdout.strip().splitlines())


with tempfile.TemporaryDirectory(prefix="vm-worker-history-") as tmp:
    root = Path(tmp)
    git(root, "init", "-b", "main")
    git(root, "config", "user.email", "ci@example.invalid")
    git(root, "config", "user.name", "Source Test")

    initial = write_worker(root, "initial")
    commit(root, "protected initial")
    accepted = write_worker(root, "accepted-production")
    accepted_rev = commit(root, "protected accepted Worker")
    git(root, "branch", "feature")

    # Main is advanced to an accepted source that is the target for this PR.
    target = write_worker(root, "next-uninstalled")
    new_main_rev = commit(root, "protected main has new target but Worker not installed")
    git(root, "checkout", "feature")
    # Feature branch based on the OLDER accepted main, then two intermediate
    # source commits. Neither may enter the predecessor chain.
    intermediate = write_worker(root, "unreleased-intermediate")
    commit(root, "feature revision 1 never installed")
    final = write_worker(root, "final-worker")
    commit(root, "feature revision 2 never installed")
    selected = values(evidence(root, accepted_rev))
    assert selected["vm_worker_source_sha256"] == final
    assert selected["vm_worker_predecessor_sha256"] == accepted
    assert selected["vm_worker_predecessor_revision"] == accepted_rev
    assert selected["vm_worker_predecessor_sha256"] != intermediate

    # Now make a fresh branch off latest accepted main with unchanged Worker
    # source. The baseline itself equals target and must be skipped; history
    # yields the nearest distinct protected-main version, never a PR commit.
    git(root, "checkout", "main")
    git(root, "checkout", "-b", "no-source-change")
    latest = values(evidence(root, new_main_rev))
    assert latest["vm_worker_source_sha256"] == target
    assert latest["vm_worker_predecessor_sha256"] == accepted
    assert latest["vm_worker_predecessor_revision"] == accepted_rev

    # Abort rather than silently guess if source is not based on accepted main.
    git(root, "checkout", "feature")
    not_ancestor = evidence(root, new_main_rev)
    assert not_ancestor.returncode != 0
    assert "not an ancestor" in not_ancestor.stderr
    bad_sha = evidence(root, "a" * 40)
    assert bad_sha.returncode != 0
    assert "not an ancestor" in bad_sha.stderr

    # No baseline must be rejected; never infer it from a branch's HEAD.
    no_baseline = subprocess.run(
        [sys.executable, str(SCRIPT), "--source", WORKER_PATH],
        cwd=root, capture_output=True, text=True, timeout=30,
    )
    assert no_baseline.returncode != 0
    assert "accepted-baseline" in no_baseline.stderr

print("vm_worker_accepted_main_provenance=PASS")
