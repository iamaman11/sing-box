#!/usr/bin/env python3
"""Canonical runtime input identity for reusable OCI image artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SCHEMA = 1
CONTRACT = "docker-build-v1"
SUPPORTED_COMPONENTS = {"gateway", "warp"}
LABEL_SCHEMA = "io.alegria.runtime-input.schema"
LABEL_COMPONENT = "io.alegria.runtime-input.component"
LABEL_DIGEST = "io.alegria.runtime-input.digest"


class ContractError(ValueError):
    pass


def _validate_component(value: str) -> str:
    if value not in SUPPORTED_COMPONENTS:
        raise ContractError(f"unsupported component: {value}")
    return value


def _validate_digest(value: str) -> str:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ContractError("digest must be exactly 64 lowercase hexadecimal characters")
    return value


def _parse_inputs(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            raise ContractError("runtime input must use NAME=VALUE syntax")
        name, value = raw.split("=", 1)
        if (
            not name
            or not value
            or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for ch in name)
        ):
            raise ContractError("runtime input name/value is invalid")
        if name in parsed:
            raise ContractError(f"duplicate runtime input: {name}")
        parsed[name] = value
    return parsed


def _collect_files(root: Path) -> list[dict[str, object]]:
    if not root.is_dir():
        raise ContractError(f"runtime context is not a directory: {root}")

    files: list[dict[str, object]] = []
    for current, dir_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dir_names.sort()
        file_names.sort()

        for name in list(dir_names):
            path = current_path / name
            if path.is_symlink():
                raise ContractError(f"runtime context symlink is forbidden: {path}")

        for name in file_names:
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ContractError(f"runtime context symlink is forbidden: {path}")
            if not stat.S_ISREG(metadata.st_mode):
                raise ContractError(f"unsupported runtime context entry: {path}")
            relative = path.relative_to(root).as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            files.append(
                {
                    "path": relative,
                    "sha256": digest,
                    "executable": bool(metadata.st_mode & 0o111),
                }
            )

    if not files:
        raise ContractError("runtime context must contain at least one file")
    return files


def runtime_input_digest(component: str, root: Path, inputs: dict[str, str]) -> str:
    component = _validate_component(component)
    payload = {
        "schema": SCHEMA,
        "contract": CONTRACT,
        "component": component,
        "files": _collect_files(root),
        "inputs": dict(sorted(inputs.items())),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def labels_match(component: str, digest: str, labels: object) -> bool:
    component = _validate_component(component)
    digest = _validate_digest(digest)
    if not isinstance(labels, dict):
        return False
    return (
        labels.get(LABEL_SCHEMA) == str(SCHEMA)
        and labels.get(LABEL_COMPONENT) == component
        and labels.get(LABEL_DIGEST) == digest
    )


def _digest_command(args: argparse.Namespace) -> int:
    digest = runtime_input_digest(
        args.component,
        Path(args.root),
        _parse_inputs(args.input),
    )
    print(digest)
    return 0


def _verify_labels_command(args: argparse.Namespace) -> int:
    try:
        labels = json.loads(args.labels_json)
    except json.JSONDecodeError as error:
        raise ContractError(f"labels JSON is invalid: {error.msg}") from error
    if labels_match(args.component, args.digest, labels):
        print("REUSE")
        return 0
    print("BUILD")
    return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    digest = subparsers.add_parser("digest")
    digest.add_argument("--component", required=True)
    digest.add_argument("--root", required=True)
    digest.add_argument("--input", action="append", default=[])
    digest.set_defaults(handler=_digest_command)

    verify = subparsers.add_parser("verify-labels")
    verify.add_argument("--component", required=True)
    verify.add_argument("--digest", required=True)
    verify.add_argument("--labels-json", required=True)
    verify.set_defaults(handler=_verify_labels_command)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except ContractError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
