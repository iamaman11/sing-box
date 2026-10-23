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
assert "refresh-receipt" not in router, "routine and receipt-resume SSH refresh prohibited"
assert "local host-refresh" in native, "native root must own trust and binary upgrades"
assert "Refresh protected Git main release" in native
capability = router.split("  host_capabilities:", 1)[1].split("  host_first_use:", 1)[0]
assert "issues/26/comments" not in capability, "historical journal must not gate read-only status"
assert "sing-box-credential-existing-join-begin" not in capability
assert "vm-credential-proof" not in capability
assert "host_first_use:" in router and "host_resume_receipt:" in router
assert "  workflow_call:" in native and "  workflow_call:" not in router
assert "  pull_request:" in ci and "  push:" in ci
assert all(name not in router for name in legacy)
for p in root.glob("*.yml"):
    src=p.read_text(encoding="utf-8")
    assert "\t" not in src

# A retired hosted SSH refresh must never be revived as a hidden Rust command.
orchestrator_cli=Path("edge-platform/crates/edge-orchestrator/src/cli.rs").read_text(encoding="utf-8")
orchestrator_main=Path("edge-platform/crates/edge-orchestrator/src/main.rs").read_text(encoding="utf-8")
agent_cli=Path("edge-platform/crates/edge-agent/src/cli.rs").read_text(encoding="utf-8")
agent_main=Path("edge-platform/crates/edge-agent/src/main.rs").read_text(encoding="utf-8")
agent_dispatch=Path("edge-platform/crates/edge-agent/src/local_dispatch.rs").read_text(encoding="utf-8")
vm_installer=Path("edge-platform/scripts/install-vultr-production-runner.sh").read_text(encoding="utf-8")
assert "RefreshReceipt" not in orchestrator_cli and "RefreshReceipt" not in orchestrator_main
assert "local host-refresh" in native
assert 'HostRefresh,' in agent_cli
assert "LocalCommand::HostRefresh => host_enroll::refresh_current()" in agent_dispatch
assert "mod local_dispatch;" in agent_main
assert 'SING_BOX_NATIVE_HOST_TRUST = ${LOCAL_OWNER} local host-refresh' in vm_installer
assert "host-enroll machine release" in vm_installer
assert "SING_BOX_NATIVE_HOST_TRUST" in vm_installer
assert 'local host-refresh *' not in vm_installer

# Signer enrollment is a continuation of the SAME Worker update operation.
# Every step checks the live Worker source through the Rust protected owner.
# A failed/unknown update skips all signing steps (Actions success gate).
worker = router.split("  host_worker_authorizer:",1)[1].split("  host_capabilities:",1)[0]
assert worker.count("if: fromJSON(needs.host.outputs.host_action_json).operation == 'WORKER_AUTHORIZER_PREFLIGHT'") == 4
assert "if: steps.plan.outputs.required == 'false' && fromJSON(needs.host.outputs.host_action_json).operation == 'WORKER_AUTHORIZER_PREFLIGHT'" not in worker
assert "vm-worker-signer-prepare" in worker and "vm-worker-signer-commit" in worker
assert worker.index("Apply exact VM Worker code once") < worker.index("Prepare one ephemeral VM signer")

# Physical CREATE must never depend on a Git-only credential reference.
# The same bounded native Worker GET checks the typed non-dummy payload at
# preflight and again immediately before provider mutation.
provider=Path("edge-platform/crates/edge-orchestrator/src/vultr_lifecycle_command.rs").read_text(encoding="utf-8")
worker_src=Path("edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs").read_text(encoding="utf-8")
gate="verify_current_vm_first_use_worker_source("
assert provider.count(gate)==2, "missing actual Worker GET before first-use / CREATE"
assert provider.index(gate) < provider.index('host_first_use_provider_plan=EXACT_CREATE_ONLY')
assert provider.rindex(gate) < provider.index("acceptance_create_machine(provider_spec, machine_id).await?")
assert "get_vm_credential_bundle_with_access(" in worker_src
assert "attest_vm_first_use_credential_bytes(&bytes, generation, expected_sha256)?" in worker_src

# GitHub receives ONLY the validated Rust closed enum decision as JSON.
# The old operation output may exist for humans but cannot steer execution.
assert "host_action_json: ${{ steps.observe.outputs.host_action_json }}" in router
assert "needs.host.outputs.operation" not in router
assert "fromJSON(needs.host.outputs.host_action_json).operation" in router
assert "credential_pair_windows" not in orchestrator_cli
for marker in ("mod controller_rpc;", "mod command_dispatch;", "mod local_dispatch;"):
    owner = ("edge-controller" if "controller" in marker else "edge-console" if "command" in marker else "edge-agent")
    assert marker in Path(f"edge-platform/crates/{owner}/src/main.rs").read_text(encoding="utf-8")

print("native_only_workflow_topology=PASS")
