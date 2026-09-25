#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

LOCK_SCHEMA_VERSION = 1
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
NUMERIC_VERSION = re.compile(r"^(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*)){2,5}$")
DEBIAN_VERSION = re.compile(r"^[0-9A-Za-z.+:~_-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

TOP_LEVEL_KEYS = {"schema_version", "sing_box", "cloudflare_warp", "docker", "oci"}
SING_BOX_KEYS = {"version", "windows", "linux"}
ASSET_KEYS = {"url", "sha256"}
WARP_KEYS = {"version", "url", "sha256"}
DOCKER_KEYS = {"engine_version", "containerd_version", "compose_version"}
OCI_KEYS = {"debian_base_image", "ubuntu_base_image", "mesh_image"}


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{name} keys mismatch: missing={missing} extra={extra}")


def _string(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or "\n" in value
        or "\r" in value
    ):
        raise ValueError(f"{name} must be a non-empty canonical string")
    return value


def _sha256(value: Any, name: str) -> str:
    value = _string(value, name)
    if not SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256")
    return value


def _sing_box_version(value: Any) -> str:
    value = _string(value, "sing_box.version")
    if not SEMVER.fullmatch(value):
        raise ValueError("sing_box.version must be normalized x.y.z")
    return value


def _numeric_version(value: Any, name: str) -> str:
    value = _string(value, name)
    if not NUMERIC_VERSION.fullmatch(value):
        raise ValueError(f"{name} must be a normalized numeric dotted version")
    return value


def _debian_version(value: Any, name: str) -> str:
    value = _string(value, name)
    if not DEBIAN_VERSION.fullmatch(value):
        raise ValueError(f"{name} contains an invalid Debian version token")
    if "~debian.13~trixie" not in value:
        raise ValueError(f"{name} is incompatible with the canonical Debian 13/trixie host")
    return value


def _sing_box_asset(value: Any, platform: str, version: str) -> dict[str, str]:
    item = _object(value, f"sing_box.{platform}")
    _exact_keys(item, ASSET_KEYS, f"sing_box.{platform}")
    suffix = (
        f"sing-box-{version}-windows-amd64.zip"
        if platform == "windows"
        else f"sing-box-{version}-linux-amd64-glibc.tar.gz"
    )
    expected_url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{suffix}"
    url = _string(item["url"], f"sing_box.{platform}.url")
    if url != expected_url:
        raise ValueError(
            f"sing_box.{platform}.url must identify the exact pinned v{version} asset"
        )
    return {
        "url": url,
        "sha256": _sha256(item["sha256"], f"sing_box.{platform}.sha256"),
    }


def _warp(value: Any) -> dict[str, str]:
    item = _object(value, "cloudflare_warp")
    _exact_keys(item, WARP_KEYS, "cloudflare_warp")
    version = _numeric_version(item["version"], "cloudflare_warp.version")
    url = _string(item["url"], "cloudflare_warp.url")
    parsed = urlparse(url)
    expected_name = f"cloudflare-warp_{version}_amd64.deb"
    path = PurePosixPath(parsed.path)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "pkg.cloudflareclient.com"
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/pool/")
        or path.name != expected_name
        or ".." in path.parts
    ):
        raise ValueError(
            "cloudflare_warp.url must identify the exact pinned amd64 package under pkg.cloudflareclient.com/pool"
        )
    return {
        "version": version,
        "url": url,
        "sha256": _sha256(item["sha256"], "cloudflare_warp.sha256"),
    }


def _docker(value: Any) -> dict[str, str]:
    item = _object(value, "docker")
    _exact_keys(item, DOCKER_KEYS, "docker")
    return {
        "engine_version": _debian_version(item["engine_version"], "docker.engine_version"),
        "containerd_version": _debian_version(
            item["containerd_version"], "docker.containerd_version"
        ),
        "compose_version": _debian_version(item["compose_version"], "docker.compose_version"),
    }


def _oci_ref(value: Any, name: str, repository: str) -> str:
    value = _string(value, name)
    prefix = f"{repository}@sha256:"
    if not value.startswith(prefix):
        raise ValueError(f"{name} must use exact immutable {repository}@sha256 identity")
    digest = value.removeprefix(prefix)
    if not SHA256.fullmatch(digest):
        raise ValueError(f"{name} must contain a lowercase OCI SHA-256 digest")
    return value


def _oci(value: Any) -> dict[str, str]:
    item = _object(value, "oci")
    _exact_keys(item, OCI_KEYS, "oci")
    return {
        "debian_base_image": _oci_ref(
            item["debian_base_image"],
            "oci.debian_base_image",
            "docker.io/library/debian",
        ),
        "ubuntu_base_image": _oci_ref(
            item["ubuntu_base_image"],
            "oci.ubuntu_base_image",
            "docker.io/library/ubuntu",
        ),
        "mesh_image": _oci_ref(
            item["mesh_image"],
            "oci.mesh_image",
            "docker.io/cloudflare/mesh",
        ),
    }


def normalize_release_inputs(value: Any) -> dict[str, str | int]:
    root = _object(value, "release input lock")
    _exact_keys(root, TOP_LEVEL_KEYS, "release input lock")
    schema_version = root["schema_version"]
    if type(schema_version) is not int or schema_version != LOCK_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported release input lock schema: {schema_version!r}"
        )

    sing_box = _object(root["sing_box"], "sing_box")
    _exact_keys(sing_box, SING_BOX_KEYS, "sing_box")
    version = _sing_box_version(sing_box["version"])
    windows = _sing_box_asset(sing_box["windows"], "windows", version)
    linux = _sing_box_asset(sing_box["linux"], "linux", version)
    warp = _warp(root["cloudflare_warp"])
    docker = _docker(root["docker"])
    oci = _oci(root["oci"])

    selected: dict[str, str | int] = {
        "schema_version": LOCK_SCHEMA_VERSION,
        "sing_box_version": version,
        "sing_box_windows_url": windows["url"],
        "sing_box_windows_sha256": windows["sha256"],
        "sing_box_linux_url": linux["url"],
        "sing_box_linux_sha256": linux["sha256"],
        "warp_version": warp["version"],
        "warp_url": warp["url"],
        "warp_sha256": warp["sha256"],
        "docker_engine_version": docker["engine_version"],
        "containerd_version": docker["containerd_version"],
        "compose_version": docker["compose_version"],
        "debian_base_image": oci["debian_base_image"],
        "ubuntu_base_image": oci["ubuntu_base_image"],
        "mesh_image": oci["mesh_image"],
    }
    authority_payload = json.dumps(
        selected, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    selected["authority_sha256"] = hashlib.sha256(
        b"sing-box-release-inputs-v1\0" + authority_payload
    ).hexdigest()
    return selected


def load_release_inputs(path: Path) -> dict[str, str | int]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ValueError(f"release input lock is missing: {path}") from error
    except OSError as error:
        raise ValueError(f"cannot read release input lock {path}: {error}") from error
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"release input lock is malformed JSON: {error}") from error
    return normalize_release_inputs(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    lock = subparsers.add_parser("lock")
    lock.add_argument("lock_file", type=Path)
    args = parser.parse_args()

    try:
        result = load_release_inputs(args.lock_file)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
