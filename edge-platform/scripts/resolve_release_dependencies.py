#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

STABLE_SEMVER = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
NUMERIC_VERSION = re.compile(r"^(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*)){2,5}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _stable_semver(tag: str) -> tuple[int, int, int] | None:
    match = STABLE_SEMVER.fullmatch(tag)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _numeric_version(value: str) -> tuple[int, ...] | None:
    if not NUMERIC_VERSION.fullmatch(value):
        return None
    return tuple(int(part) for part in value.split("."))


def _asset(release: dict[str, Any], expected_name: str, version: str) -> dict[str, str]:
    matches = [asset for asset in release.get("assets", []) if asset.get("name") == expected_name]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one release asset named {expected_name}")
    asset = matches[0]
    digest = str(asset.get("digest") or "")
    if not digest.startswith("sha256:") or not SHA256.fullmatch(digest.removeprefix("sha256:")):
        raise ValueError(f"{expected_name} is missing an exact GitHub SHA-256 digest")
    expected_prefix = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/"
    url = str(asset.get("browser_download_url") or "")
    if url != expected_prefix + expected_name:
        raise ValueError(f"{expected_name} has unexpected download URL")
    return {
        "name": expected_name,
        "url": url,
        "sha256": digest.removeprefix("sha256:"),
    }


def resolve_sing_box(releases: list[dict[str, Any]]) -> dict[str, Any]:
    candidates: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = str(release.get("tag_name") or "")
        version_tuple = _stable_semver(tag)
        if version_tuple is not None:
            candidates.append((version_tuple, release))
    if not candidates:
        raise ValueError("no stable sing-box x.y.z release found")

    version_tuple, release = max(candidates, key=lambda item: item[0])
    version = ".".join(str(part) for part in version_tuple)
    if release.get("tag_name") != f"v{version}":
        raise ValueError("resolved sing-box tag is not normalized")

    return {
        "version": version,
        "tag": f"v{version}",
        "windows": _asset(
            release,
            f"sing-box-{version}-windows-amd64.zip",
            version,
        ),
        "linux": _asset(
            release,
            f"sing-box-{version}-linux-amd64-glibc.tar.gz",
            version,
        ),
    }


def _parse_debian_packages(raw: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    for stanza in re.split(r"\n\s*\n", raw.strip()):
        fields: dict[str, str] = {}
        current: str | None = None
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")) and current is not None:
                fields[current] += "\n" + line.strip()
                continue
            key, sep, value = line.partition(":")
            if not sep:
                raise ValueError(f"invalid Debian Packages line: {line!r}")
            current = key
            fields[key] = value.strip()
        if fields:
            packages.append(fields)
    return packages


def resolve_warp_packages(raw: str) -> dict[str, str]:
    candidates: list[tuple[tuple[int, ...], dict[str, str]]] = []
    for package in _parse_debian_packages(raw):
        if package.get("Package") != "cloudflare-warp" or package.get("Architecture") != "amd64":
            continue
        version = package.get("Version", "")
        parsed = _numeric_version(version)
        if parsed is not None:
            candidates.append((parsed, package))
    if not candidates:
        raise ValueError("no stable numeric amd64 cloudflare-warp package found")

    _, package = max(candidates, key=lambda item: item[0])
    version = package["Version"]
    sha256 = package.get("SHA256", "")
    if not SHA256.fullmatch(sha256):
        raise ValueError("cloudflare-warp package SHA256 is missing or invalid")

    filename = package.get("Filename", "")
    path = PurePosixPath(filename)
    if not filename.startswith("pool/") or path.is_absolute() or ".." in path.parts:
        raise ValueError("cloudflare-warp package filename is not a safe repository-relative path")

    return {
        "version": version,
        "filename": filename,
        "url": f"https://pkg.cloudflareclient.com/{filename}",
        "sha256": sha256,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    sing_box = subparsers.add_parser("sing-box")
    sing_box.add_argument("releases_json", type=Path)

    warp = subparsers.add_parser("warp")
    warp.add_argument("packages_file", type=Path)

    args = parser.parse_args()
    if args.command == "sing-box":
        releases = json.loads(args.releases_json.read_text(encoding="utf-8"))
        if not isinstance(releases, list):
            raise SystemExit("sing-box releases input must be a JSON array")
        result = resolve_sing_box(releases)
    else:
        result = resolve_warp_packages(args.packages_file.read_text(encoding="utf-8"))

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
