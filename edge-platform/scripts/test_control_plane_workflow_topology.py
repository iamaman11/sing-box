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
assert "native_local_entrypoint_allowed" not in agent_main
assert "native_local_entrypoint_allowed" not in agent_dispatch
assert 'SING_BOX_NATIVE_HOST_TRUST = ${LOCAL_OWNER} local host-refresh' in vm_installer
assert "host-enroll machine release" in vm_installer
assert "SING_BOX_NATIVE_HOST_TRUST" in vm_installer
assert 'local host-refresh *' not in vm_installer

# Signer enrollment is a continuation of the SAME Worker update operation.
# Every step checks the live Worker source through the Rust protected owner.
# A failed/unknown update skips all signing steps (Actions success gate).
worker = router.split("  host_worker_authorizer:",1)[1].split("  host_capabilities:",1)[0]
assert worker.count("if: needs.host.outputs.operation == 'WORKER_AUTHORIZER_PREFLIGHT'") == 4
assert "if: steps.plan.outputs.required == 'false' && needs.host.outputs.operation == 'WORKER_AUTHORIZER_PREFLIGHT'" not in worker
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

# GitHub needs only a scalar for job/step routing.
# All structured desired/intent/result/receipt stays Protobuf.
assert "operation: ${{ steps.observe.outputs.operation }}" in router
assert "host_action_json" not in router
assert "needs.host.outputs.operation" in router
assert "fromJSON(needs.host.outputs.host_matrix)" in router  # GitHub matrix API
host_source=Path("edge-platform/crates/edge-orchestrator/src/host_command.rs").read_text(encoding="utf-8")
assert "enum HostWorkflowOperation" in host_source
assert 'writeln!(file, "operation={}", action.as_str())' in host_source
assert "HostWorkflowDecision" not in host_source
assert "credential_pair_windows" not in orchestrator_cli
for marker in ("mod controller_rpc;", "mod command_dispatch;", "mod local_dispatch;"):
    owner = ("edge-controller" if "controller" in marker else "edge-console" if "command" in marker else "edge-agent")
    assert marker in Path(f"edge-platform/crates/{owner}/src/main.rs").read_text(encoding="utf-8")

# Receipt merge continuation uses the same closed Rust enum projection
# as ordinary /host apply. GitHub's compulsory scalar job output is transport,
# not a free-form command parser or a new source of mutation authority.
assert "operation: ${{ steps.prepare.outputs.operation }}" in router
assert "needs.host_resume_receipt.outputs.operation == 'APPLY_PREFLIGHT'" in router
assert "if: steps.prepare.outputs.operation == 'APPLY_PREFLIGHT'" in router
assert "host_action_json" not in router
host_source = Path("edge-platform/crates/edge-orchestrator/src/host_command.rs").read_text(encoding="utf-8")
assert "enum HostWorkflowOperation" in host_source
assert "HostWorkflowDecision" not in host_source
# The retired VM gRPC listener must not reappear beside signed native owner.
agent_main = Path("edge-platform/crates/edge-agent/src/main.rs").read_text(encoding="utf-8")
assert "AgentServerImpl" not in agent_main and "serve_acceptance_rpc(" not in agent_main
assert "async fn run_local_bundle_converge(" not in agent_main
assert "async fn run_local_bootstrap(" not in agent_main
assert 'mod native_mutation_ingress_tests;' in agent_main

# A single canonical /host dispatch: retired Mesh direct mutation modules
# cannot be reintroduced through a hidden Rust binary or a stray workflow.
for name in ("cloudflare_mesh_lifecycle_command", "cloudflare_mesh_profile_command"):
    assert not Path(f"edge-platform/crates/edge-orchestrator/src/{name}.rs").exists()
    assert f"mod {name};" not in orchestrator_main
assert "MeshProfileCommand" not in orchestrator_cli

# After the typed CLI hard-cut, no parallel VM credential/Bootstrap/Mesh
# mutation handlers may stay compiled inside the local root process.
agent_main = Path("edge-platform/crates/edge-agent/src/main.rs").read_text(encoding="utf-8")
observation = Path("edge-platform/crates/edge-agent/src/vm_runtime_observation.rs").read_text(encoding="utf-8")
assert "mod vm_runtime_observation;" in agent_main
assert "use vm_runtime_observation::*;" in agent_main
assert "pub(super) async fn inspect_datapath_readiness(" in observation
assert "pub(super) fn probe_direct_egress(" in observation
for retired_handler in (
    "initial_commit_vm_credential", "initial_apply_vm_credential",
    "transition_vm_credential", "converge_mesh_runtime", "cleanup_mesh_runtime",
    "run_bootstrap", "execute_typed_bootstrap", "wait_for_bootstrap_post_state",
    "should_reobserve_bootstrap_post_state", "run_mesh_compose",
    "apply_vm_credential_runtime",
):
    assert retired_handler not in agent_main
    assert retired_handler not in observation
assert "mod host_native;" in agent_main
assert Path("edge-platform/crates/edge-agent/src/host_native.rs").exists()

print("native_only_workflow_topology=PASS")
