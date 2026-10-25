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
    # No second Linux/Windows compilation after promotion: accepted binaries
    # are EXACT candidate artifacts already checked on the PR, not cache seeds.
    assert "  warm_linux_cache:\n" not in ci
    assert "  warm_windows_cache:\n" not in ci
    # Cheap format failure MUST happen before restoring 1+ GiB Cargo objects.
    source = ci.split("  verify:\n", 1)[1].split("\n  dependencies:", 1)[0]
    fmt_step = source.index("      - name: Check formatting\n")
    cache_step = source.index("      - name: Restore disposable Cargo source cache\n")
    test_step = source.index("      - name: Test workspace\n")
    assert fmt_step < cache_step < test_step
    # The candidate builds may use disposable read caches; none are an
    # authority for promotion, which only verifies and publishes exact bytes.
    assert "cargo-linux-${{ runner.os }}" in ci
    assert "cargo-windows-${{ runner.os }}" in ci
    assert "needs: [verify, dependencies, windows, linux_candidate, release_authority]" in ci
    # Candidate merge remains guarded by five mandatory success assertions;
    # protected-main promotion does not rebuild a second release.
    for key in (
        "SOURCE_RESULT", "DEPENDENCIES_RESULT", "WINDOWS_RESULT",
        "LINUX_RESULT", "RELEASE_AUTHORITY_RESULT",
    ):
        assert f'test "${{{key}}}" = "success"' in ci

    print("canonical_ci_trigger_scope=PASS")


if __name__ == "__main__":
    main()
