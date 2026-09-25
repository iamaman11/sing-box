#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path

WINDOWS_INPUT_SCHEMA = 1
WINDOWS_BUILD_CONTRACT_PATH = ".github/workflows/edge-platform-ci.yml"
WINDOWS_BUILD_CONTRACT_BEGIN = "# WINDOWS_CANDIDATE_BUILD_CONTRACT_BEGIN"
WINDOWS_BUILD_CONTRACT_END = "# WINDOWS_CANDIDATE_BUILD_CONTRACT_END"
ROOT_PACKAGES = ("edge-controller", "edge-console", "edge-diagnostic")
REQUIRED_INPUT_KEYS = {
    "rust_toolchain",
    "windows_runner",
    "sing_box_version",
    "sing_box_windows_sha256",
}
LOWER_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def _feed_field(context: "hashlib._Hash", value: bytes) -> None:
    context.update(len(value).to_bytes(8, "big"))
    context.update(value)


def _dependency_tables(manifest: dict) -> list[dict]:
    tables: list[dict] = []
    for key in ("dependencies", "build-dependencies", "dev-dependencies"):
        value = manifest.get(key)
        if isinstance(value, dict):
            tables.append(value)
    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for key in ("dependencies", "build-dependencies", "dev-dependencies"):
                value = target.get(key)
                if isinstance(value, dict):
                    tables.append(value)
    return tables


def _package_dir(workspace: Path, package: str) -> Path:
    path = workspace / "crates" / package
    if not (path / "Cargo.toml").is_file():
        raise ValueError(f"required Windows package is missing: {package}")
    return path


def _reachable_package_dirs(repo_root: Path) -> list[Path]:
    workspace = repo_root / "edge-platform"
    pending = [_package_dir(workspace, package) for package in ROOT_PACKAGES]
    visited: set[Path] = set()
    while pending:
        package_dir = pending.pop()
        package_dir = package_dir.resolve()
        if package_dir in visited:
            continue
        try:
            package_dir.relative_to(workspace.resolve())
        except ValueError as error:
            raise ValueError(f"local dependency escapes edge-platform: {package_dir}") from error
        visited.add(package_dir)

        manifest_path = package_dir / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        for table in _dependency_tables(manifest):
            for spec in table.values():
                if not isinstance(spec, dict) or "path" not in spec:
                    continue
                raw = spec["path"]
                if not isinstance(raw, str) or not raw:
                    raise ValueError(f"invalid local dependency path in {manifest_path}")
                dependency_dir = (package_dir / raw).resolve()
                try:
                    dependency_dir.relative_to(workspace.resolve())
                except ValueError as error:
                    raise ValueError(
                        f"local dependency escapes edge-platform: {dependency_dir}"
                    ) from error
                if not (dependency_dir / "Cargo.toml").is_file():
                    raise ValueError(f"local dependency manifest is missing: {dependency_dir}")
                pending.append(dependency_dir)
    return sorted(visited, key=lambda path: path.relative_to(repo_root).as_posix())


def _tracked_files(repo_root: Path) -> list[Path]:
    required = [
        repo_root / "edge-platform" / "Cargo.toml",
        repo_root / "edge-platform" / "Cargo.lock",
        repo_root / "edge-platform" / "proto",
        repo_root / "edge-platform" / "scripts" / "windows_input_digest.py",
    ]
    required.extend(_reachable_package_dirs(repo_root))

    files: set[Path] = set()
    for path in required:
        if not path.exists():
            raise ValueError(
                f"required Windows input path is missing: {path.relative_to(repo_root).as_posix()}"
            )
        if path.is_symlink():
            raise ValueError(
                f"Windows input symlink is forbidden: {path.relative_to(repo_root).as_posix()}"
            )
        if path.is_file():
            files.add(path)
            continue
        if not path.is_dir():
            raise ValueError(f"unsupported Windows input path type: {path}")
        package_sources = (path / "Cargo.toml").is_file()
        for child in path.rglob("*"):
            child_relative = child.relative_to(path)
            if package_sources and child_relative.parts[:2] == ("src", "bin"):
                continue
            if child.is_symlink():
                raise ValueError(
                    f"Windows input symlink is forbidden: {child.relative_to(repo_root).as_posix()}"
                )
            if child.is_file():
                files.add(child)
    return sorted(files, key=lambda path: path.relative_to(repo_root).as_posix())


def _windows_build_contract(repo_root: Path) -> bytes:
    path = repo_root / WINDOWS_BUILD_CONTRACT_PATH
    raw = path.read_text(encoding="utf-8")
    if raw.count(WINDOWS_BUILD_CONTRACT_BEGIN) != 1 or raw.count(WINDOWS_BUILD_CONTRACT_END) != 1:
        raise ValueError("Windows candidate build contract markers must occur exactly once")
    start = raw.index(WINDOWS_BUILD_CONTRACT_BEGIN)
    end = raw.index(WINDOWS_BUILD_CONTRACT_END, start)
    if end <= start:
        raise ValueError("Windows candidate build contract markers are out of order")
    return raw[start : end + len(WINDOWS_BUILD_CONTRACT_END)].encode()


def _validated_inputs(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("resolved Windows inputs must be a JSON object")
    if set(value) != REQUIRED_INPUT_KEYS:
        missing = sorted(REQUIRED_INPUT_KEYS - set(value))
        extra = sorted(set(value) - REQUIRED_INPUT_KEYS)
        raise ValueError(f"resolved Windows input keys mismatch: missing={missing} extra={extra}")
    result: dict[str, str] = {}
    for key in sorted(REQUIRED_INPUT_KEYS):
        item = value[key]
        if not isinstance(item, str) or not item or item.strip() != item or "\n" in item or "\r" in item:
            raise ValueError(f"resolved Windows input {key} must be a non-empty canonical string")
        result[key] = item
    if not LOWER_HEX_64.fullmatch(result["sing_box_windows_sha256"]):
        raise ValueError("sing_box_windows_sha256 must be a lowercase SHA-256")
    return result


def compute_digest(repo_root: Path, resolved_inputs: object) -> str:
    repo_root = repo_root.resolve()
    inputs = _validated_inputs(resolved_inputs)
    context = hashlib.sha256()
    context.update(b"sing-box-windows-candidate-input\0")
    context.update(WINDOWS_INPUT_SCHEMA.to_bytes(4, "big"))
    context.update(b"build-contract\0")
    _feed_field(context, _windows_build_contract(repo_root))
    for path in _tracked_files(repo_root):
        relative = path.relative_to(repo_root).as_posix().encode()
        content = path.read_bytes()
        context.update(b"file\0")
        _feed_field(context, relative)
        _feed_field(context, content)
    for key, value in inputs.items():
        context.update(b"input\0")
        _feed_field(context, key.encode())
        _feed_field(context, value.encode())
    return context.hexdigest()


def decide_reuse(
    candidate_digest: str,
    base_schema: str,
    base_digest: str,
    base_source_revision: str,
    base_artifact_sha256: str,
    base_controller_sha256: str,
    base_console_sha256: str,
    base_sing_box_sha256: str,
    base_diagnostic_sha256: str,
) -> bool:
    if not LOWER_HEX_64.fullmatch(candidate_digest):
        raise ValueError("candidate Windows input digest must be a lowercase SHA-256")
    if base_schema != "6":
        return False
    return (
        LOWER_HEX_64.fullmatch(base_digest) is not None
        and candidate_digest == base_digest
        and LOWER_HEX_40.fullmatch(base_source_revision) is not None
        and LOWER_HEX_64.fullmatch(base_artifact_sha256) is not None
        and LOWER_HEX_64.fullmatch(base_controller_sha256) is not None
        and LOWER_HEX_64.fullmatch(base_console_sha256) is not None
        and LOWER_HEX_64.fullmatch(base_sing_box_sha256) is not None
        and LOWER_HEX_64.fullmatch(base_diagnostic_sha256) is not None
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    compute = sub.add_parser("compute")
    compute.add_argument("--repo-root", required=True)
    compute.add_argument("--inputs-json", required=True)

    decide = sub.add_parser("decide")
    decide.add_argument("--candidate-digest", required=True)
    decide.add_argument("--base-schema", required=True)
    decide.add_argument("--base-digest", default="")
    decide.add_argument("--base-source-revision", default="")
    decide.add_argument("--base-artifact-sha256", default="")
    decide.add_argument("--base-controller-sha256", default="")
    decide.add_argument("--base-console-sha256", default="")
    decide.add_argument("--base-sing-box-sha256", default="")
    decide.add_argument("--base-diagnostic-sha256", default="")

    args = parser.parse_args()
    if args.command == "compute":
        payload = json.loads(Path(args.inputs_json).read_text(encoding="utf-8"))
        print(compute_digest(Path(args.repo_root), payload))
        return

    print(
        "REUSE"
        if decide_reuse(
            args.candidate_digest,
            args.base_schema,
            args.base_digest,
            args.base_source_revision,
            args.base_artifact_sha256,
            args.base_controller_sha256,
            args.base_console_sha256,
            args.base_sing_box_sha256,
            args.base_diagnostic_sha256,
        )
        else "BUILD"
    )


if __name__ == "__main__":
    main()
