#!/usr/bin/env python3
"""Verify native-only GitHub ingress after the hard cut (no legacy dispatch)."""
from pathlib import Path
import re

root=Path(".github/workflows")
required={"edge-control-plane.yml","edge-platform-ci.yml","host-native-observe.yml"}
legacy={"credential-lifecycle.yml","vultr-lifecycle.yml","vultr-acceptance-resume.yml","vm-application-lifecycle.yml","vultr-vpc-lifecycle.yml","windows-physical.yml"}
actual={p.name for p in root.glob("*.yml")}
assert required <= actual, f"native workflow missing: {required-actual}"
assert not (legacy & actual), f"legacy mutation workflow present: {legacy&actual}"
router=(root/"edge-control-plane.yml").read_text(encoding="utf-8")
native=(root/"host-native-observe.yml").read_text(encoding="utf-8")
ci=(root/"edge-platform-ci.yml").read_text(encoding="utf-8")
assert "  issue_comment:" in router and "  workflow_run:" in router
assert "github.event.issue.number == 1" in router
assert "github.actor_id == '44100369'" in router
assert router.count("uses: ./.github/workflows/host-native-observe.yml")==2
assert "host_refresh_trust:" not in router and "needs.host_refresh_trust" not in router
assert "refresh-receipt" not in router.split("  host_resume_receipt:",1)[0]
assert "refresh-receipt" in router.split("  host_resume_receipt:",1)[1], "bootstrap Git receipt enrollment is kept"
assert "host_first_use:" in router and "host_resume_receipt:" in router
assert "  workflow_call:" in native and "  workflow_call:" not in router
assert "  pull_request:" in ci and "  push:" in ci
assert all(name not in router for name in legacy)
for p in root.glob("*.yml"):
    src=p.read_text(encoding="utf-8")
    assert "\t" not in src
print("native_only_workflow_topology=PASS")
