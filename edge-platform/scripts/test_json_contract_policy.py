#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# JSON is permitted only when an external runtime physically requires JSON.
# These are sing-box configuration templates consumed by sing-box itself.
PHYSICALLY_REQUIRED_JSON = {
    "win/vultr-waw/stack/line1-gateway/config.template.json",
    "win/vultr-waw/stack/line2-proxy/config.template.json",
}

# Frozen first-party debt. New entries are forbidden. This set may only shrink
# as the corresponding contracts move to protobuf/textproto.
LEGACY_FIRST_PARTY_JSON_DEBT = {
    "infra/application/disposable-acceptance-v2.json",
    "infra/application/disposable-acceptance.json",
    "infra/cloudflare/application-acceptance-dns.json",
    "infra/cloudflare/application-acceptance-mesh.json",
    "infra/cloudflare/disposable-dns.json",
    "infra/cloudflare/zero-trust-guardrails.json",
    "infra/cloudflare/zero-trust-lifecycle.json",
    "infra/release/release-inputs.lock.json",
    "infra/vultr/application-acceptance-vpc.json",
    "infra/vultr/application-acceptance.json",
    "infra/vultr/disposable-acceptance.json",
    "infra/vultr/firewall-profiles.json",
    "infra/vultr/root-runner-dev.json",
}


def tracked_json_files() -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "*.json"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def main() -> None:
    observed = tracked_json_files()
    allowed = PHYSICALLY_REQUIRED_JSON | LEGACY_FIRST_PARTY_JSON_DEBT
    unexpected = sorted(observed - allowed)
    if unexpected:
        raise SystemExit(
            "new first-party JSON files are forbidden; use protobuf binary or "
            "protobuf text format instead. Unexpected JSON files: "
            + ", ".join(unexpected)
        )

    missing_required = sorted(PHYSICALLY_REQUIRED_JSON - observed)
    if missing_required:
        raise SystemExit(
            "physically-required external JSON allowlist is stale; review the "
            "architecture rule before changing it. Missing: "
            + ", ".join(missing_required)
        )

    if "infra/production/production.json" in observed:
        raise SystemExit(
            "production desired state must be protobuf/textproto, never production.json"
        )

    required_protobuf_authority = {
        "edge-platform/proto/edge/platform/v1/production.proto",
        "infra/production/production.textproto",
    }
    tracked = {
        line.strip()
        for line in subprocess.run(
            ["git", "ls-files"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        if line.strip()
    }
    missing_authority = sorted(required_protobuf_authority - tracked)
    if missing_authority:
        raise SystemExit(
            "canonical production protobuf authority is incomplete: "
            + ", ".join(missing_authority)
        )

    legacy_remaining = sorted(observed & LEGACY_FIRST_PARTY_JSON_DEBT)
    print(
        "JSON policy PASS: "
        f"{len(PHYSICALLY_REQUIRED_JSON)} physically-required JSON files; "
        f"{len(legacy_remaining)} frozen legacy first-party JSON files remain"
    )
    for path in legacy_remaining:
        print(f"legacy-json-debt={path}")


if __name__ == "__main__":
    main()
