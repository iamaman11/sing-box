#!/usr/bin/env python3
"""Ensure protected Git receipt and workflow changes cannot bypass CI promotion."""

import fnmatch
import re
from pathlib import Path


def main() -> None:
    ci = Path(".github/workflows/edge-platform-ci.yml").read_text(encoding="utf-8")
    header = ci.split("\npermissions:\n", 1)[0]
    assert header.startswith("name: Edge Platform CI\n\non:\n")
    expected = ["edge-platform/**", "infra/**", "win/**", ".github/workflows/**"]
    for event in ("pull_request", "push"):
        matched = re.search(
            rf"(?ms)^  {event}:\n(.*?)(?=^  (?:pull_request|push):|\Z)",
            header,
        )
        assert matched is not None, f"{event} event missing"
        paths = re.findall(r'^      - "([^"]+)"$', matched.group(1), re.M)
        assert paths == expected, f"{event} event excludes canonical inputs: {paths}"
        for filename in (
            "infra/hosts/hosts.textproto",
            "infra/release/release-inputs.lock.json",
            "infra/production/production.textproto",
            ".github/workflows/host-native-observe.yml",
            ".github/workflows/vultr-vpc-lifecycle.yml",
            "edge-platform/proto/edge/platform/v1/fleet.proto",
        ):
            assert any(fnmatch.fnmatchcase(filename, p) for p in paths), (
                f"{event} fails to check {filename}"
            )

    # A source change must compile the pinned canonical Git registry, and
    # protected main must publish that exact registry via candidate promotion.
    assert 'infra/hosts/hosts.textproto#format=txtpb' in ci
    assert "fleet-registry.pb" in ci
    assert "  candidate_complete:\n" in ci
    assert "  promote:\n" in ci
    assert "accepted_tree" in ci and "candidate_tree" in ci
    print("canonical_ci_trigger_scope=PASS")


if __name__ == "__main__":
    main()
