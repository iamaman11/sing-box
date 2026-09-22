#!/usr/bin/env python3

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT = Path(__file__).with_name("runtime_input_digest.py")


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def digest(root: Path, *inputs: str) -> str:
    result = run(
        "digest",
        "--component",
        "gateway",
        "--root",
        str(root),
        *sum((["--input", value] for value in inputs), []),
    )
    value = result.stdout.strip()
    assert len(value) == 64
    return value


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "context"
        root.mkdir()
        (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        nested = root / "files"
        nested.mkdir()
        payload = nested / "payload"
        payload.write_text("alpha\n", encoding="utf-8")

        first = digest(root, "BASE_IMAGE=repo@sha256:" + "1" * 64, "VERSION=1")
        reordered = digest(root, "VERSION=1", "BASE_IMAGE=repo@sha256:" + "1" * 64)
        assert first == reordered, "input ordering must not change identity"

        payload.write_text("beta\n", encoding="utf-8")
        changed_file = digest(root, "BASE_IMAGE=repo@sha256:" + "1" * 64, "VERSION=1")
        assert changed_file != first, "runtime context content must change identity"

        payload.write_text("alpha\n", encoding="utf-8")
        changed_input = digest(root, "BASE_IMAGE=repo@sha256:" + "2" * 64, "VERSION=1")
        assert changed_input != first, "resolved immutable build input must change identity"

        os.chmod(payload, 0o755)
        changed_mode = digest(root, "BASE_IMAGE=repo@sha256:" + "1" * 64, "VERSION=1")
        assert changed_mode != first, "executable mode must change identity"
        os.chmod(payload, 0o644)

        labels = (
            '{"io.alegria.runtime-input.schema":"1",'
            '"io.alegria.runtime-input.component":"gateway",'
            f'"io.alegria.runtime-input.digest":"{first}",'
            '"org.opencontainers.image.source":"https://github.com/iamaman11/sing-box"}'
        )
        exact = run(
            "verify-labels",
            "--component",
            "gateway",
            "--digest",
            first,
            "--labels-json",
            labels,
        )
        assert exact.stdout.strip() == "REUSE"

        wrong_digest = run(
            "verify-labels",
            "--component",
            "gateway",
            "--digest",
            "f" * 64,
            "--labels-json",
            labels,
            check=False,
        )
        assert wrong_digest.returncode == 1
        assert wrong_digest.stdout.strip() == "BUILD"

        wrong_schema = run(
            "verify-labels",
            "--component",
            "gateway",
            "--digest",
            first,
            "--labels-json",
            labels.replace('"1"', '"2"', 1),
            check=False,
        )
        assert wrong_schema.returncode == 1

        link = root / "forbidden-link"
        link.symlink_to(payload)
        rejected = run(
            "digest",
            "--component",
            "gateway",
            "--root",
            str(root),
            "--input",
            "VERSION=1",
            check=False,
        )
        assert rejected.returncode == 2
        assert "symlink is forbidden" in rejected.stderr

    duplicate = run(
        "digest",
        "--component",
        "gateway",
        "--root",
        str(Path(__file__).parent),
        "--input",
        "VERSION=1",
        "--input",
        "VERSION=2",
        check=False,
    )
    assert duplicate.returncode == 2
    assert "duplicate runtime input" in duplicate.stderr


if __name__ == "__main__":
    main()
