#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from pathlib import Path

RUNTIME_INPUT_SCHEMA = 1
REQUIRED_INPUT_KEYS = {
    "rust_toolchain",
    "sing_box_version",
    "sing_box_linux_url",
    "sing_box_linux_sha256",
    "warp_version",
    "warp_url",
    "warp_sha256",
    "debian_base_image",
    "ubuntu_base_image",
    "mesh_image",
    "docker_engine_version",
    "containerd_version",
    "compose_version",
}
TRACKED_PATHS = (
    "edge-platform/Cargo.toml",
    "edge-platform/Cargo.lock",
    "edge-platform/crates/edge-agent",
    "edge-platform/crates/edge-observability",
    "edge-platform/crates/edge-secrets",
    "edge-platform/crates/edge-shared-types",
    "edge-platform/crates/edge-trust",
    "edge-platform/proto",
    "edge-platform/scripts/runtime_input_digest.py",
    "win/vultr-waw/stack/edge-gateway",
    "win/vultr-waw/stack/warp-egress",
)

LOWER_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
GATEWAY_REF = re.compile(r"^ghcr\.io/iamaman11/vultr-edge-gateway@sha256:[0-9a-f]{64}$")
WARP_REF = re.compile(r"^ghcr\.io/iamaman11/vultr-warp-egress@sha256:[0-9a-f]{64}$")


def _feed_field(context: "hashlib._Hash", value: bytes) -> None:
    context.update(len(value).to_bytes(8, "big"))
    context.update(value)


def _tracked_files(repo_root: Path) -> list[Path]:
    files: set[Path] = set()
    for raw in TRACKED_PATHS:
        path = repo_root / raw
        if not path.exists():
            raise ValueError(f"required runtime input path is missing: {raw}")
        if path.is_symlink():
            raise ValueError(f"runtime input symlink is forbidden: {raw}")
        if path.is_file():
            files.add(path)
            continue
        if not path.is_dir():
            raise ValueError(f"unsupported runtime input path type: {raw}")
        for child in path.rglob("*"):
            if child.is_symlink():
                raise ValueError(
                    f"runtime input symlink is forbidden: {child.relative_to(repo_root).as_posix()}"
                )
            if child.is_file():
                files.add(child)
    return sorted(files, key=lambda path: path.relative_to(repo_root).as_posix())


def _validated_inputs(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("resolved runtime inputs must be a JSON object")
    if set(value) != REQUIRED_INPUT_KEYS:
        missing = sorted(REQUIRED_INPUT_KEYS - set(value))
        extra = sorted(set(value) - REQUIRED_INPUT_KEYS)
        raise ValueError(f"resolved runtime input keys mismatch: missing={missing} extra={extra}")
    result: dict[str, str] = {}
    for key in sorted(REQUIRED_INPUT_KEYS):
        item = value[key]
        if not isinstance(item, str) or not item or item.strip() != item or "\n" in item or "\r" in item:
            raise ValueError(f"resolved runtime input {key} must be a non-empty canonical string")
        result[key] = item
    for key in ("sing_box_linux_sha256", "warp_sha256"):
        if not LOWER_HEX_64.fullmatch(result[key]):
            raise ValueError(f"{key} must be a lowercase SHA-256")
    for key in ("debian_base_image", "ubuntu_base_image", "mesh_image"):
        if "@sha256:" not in result[key] or not LOWER_HEX_64.fullmatch(result[key].rsplit("@sha256:", 1)[1]):
            raise ValueError(f"{key} must be an immutable digest reference")
    return result


def compute_digest(repo_root: Path, resolved_inputs: object) -> str:
    repo_root = repo_root.resolve()
    inputs = _validated_inputs(resolved_inputs)
    context = hashlib.sha256()
    context.update(b"sing-box-vm-runtime-input\0")
    context.update(RUNTIME_INPUT_SCHEMA.to_bytes(4, "big"))
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
    base_runtime_source_revision: str,
    base_agent_sha256: str,
    gateway_ref: str,
    warp_ref: str,
) -> bool:
    if base_schema != "4":
        return False
    if not LOWER_HEX_64.fullmatch(candidate_digest):
        raise ValueError("candidate runtime input digest must be a lowercase SHA-256")
    return (
        LOWER_HEX_64.fullmatch(base_digest) is not None
        and candidate_digest == base_digest
        and LOWER_HEX_40.fullmatch(base_runtime_source_revision) is not None
        and LOWER_HEX_64.fullmatch(base_agent_sha256) is not None
        and GATEWAY_REF.fullmatch(gateway_ref) is not None
        and WARP_REF.fullmatch(warp_ref) is not None
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
    decide.add_argument("--base-runtime-source-revision", default="")
    decide.add_argument("--base-agent-sha256", default="")
    decide.add_argument("--gateway-ref", default="")
    decide.add_argument("--warp-ref", default="")

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
            args.base_runtime_source_revision,
            args.base_agent_sha256,
            args.gateway_ref,
            args.warp_ref,
        )
        else "BUILD"
    )


if __name__ == "__main__":
    main()
