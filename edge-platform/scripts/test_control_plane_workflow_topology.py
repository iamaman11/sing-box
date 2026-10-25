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
# A deleted/offline VM can keep its self-hosted job queued forever.
# VM-native serialization must be PER MACHINE, never the shared fleet lock
# that also protects the hosted Worker authorizer and Vultr first-use owner.
native_observe = native.split("  observe:\n", 1)[1].split("\n  report:", 1)[0]
assert "format('host-native-vm-{0}', inputs.machine_id)" in native_observe
assert "vultr-control-plane-production" not in native_observe
assert "cancel-in-progress: false" in native_observe
assert "format('host-readonly-{0}', inputs.source_comment_id)" in native_observe
for job in ("host_worker_authorizer", "host_first_use", "host_resume_receipt"):
    # Nested YAML field indentation differs from top-level job indentation.
    following = router.split(f"  {job}:\n", 1)[1]
    stop = re.search(r"(?m)^  [a-z][a-z_]*:\s*$", following)
    section = following[:stop.start()] if stop else following
    assert "group: vultr-control-plane-production" in section
    assert "cancel-in-progress: false" in section
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
# The same /host apply must never upgrade Worker bytes and trigger native INSTALL.
# The closed, Rust-owned plan decision gates the dependent native job.
native_dispatch = router.split("  host_observe:\n", 1)[1].split("  host_report:\n", 1)[0]
assert "needs.host_worker_authorizer.result == 'success' &&" in native_dispatch
assert "needs.host_worker_authorizer.outputs.source_upgrade_required == 'false'" in native_dispatch
assert "source_upgrade_required: ${{ steps.plan.outputs.required }}" in worker
assert worker.index("source_upgrade_required: ${{ steps.plan.outputs.required }}") < worker.index("Plan exact VM Worker release with GET only")
assert 'case "${RUST_WORKER_PLAN_REQUIRED}" in' in worker
assert "true|false)" in worker
assert "if: steps.plan.outputs.required == 'true'" in worker


# Physical CREATE must never depend on a Git-only credential reference.
# The same bounded native Worker GET checks the typed non-dummy payload at
# preflight and again immediately before provider mutation.
provider=Path("edge-platform/crates/edge-orchestrator/src/vultr_lifecycle_command.rs").read_text(encoding="utf-8")
worker_src=Path("edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs").read_text(encoding="utf-8")
vm_proof=Path("edge-platform/crates/edge-orchestrator/src/vm_credential_proof.rs").read_text(encoding="utf-8")
gate="verify_current_vm_first_use_worker_source("
assert provider.count(gate)==2, "missing actual Worker GET before first-use / CREATE"
# Do not restore the retired SSH receipt refresh and old-owner compatibility
# migration. The installed Root Agent already owns the signed in-place
# host-refresh path; first-use SSH remains separately BLOCKED by #484.
assert "host_receipt_refresh(" not in provider
assert "vm_owner_compatibility" not in provider and "vm_owner_upgrade" not in provider
assert not Path("edge-platform/crates/edge-orchestrator/src/vm_owner_compatibility.rs").exists()
assert not Path("edge-platform/crates/edge-orchestrator/src/vm_owner_upgrade.rs").exists()
assert provider.index(gate) < provider.index('host_first_use_provider_plan=EXACT_CREATE_ONLY')
assert provider.rindex(gate) < provider.index("acceptance_create_machine(provider_spec, machine_id).await?")
assert '#[path = "vm_credential_proof.rs"]' in worker_src
assert "get_vm_credential_bundle_with_access(" in vm_proof
# A GET-only capability probe must not request an SSH private key.
# The old first-use implementation cannot reach provider CREATE until the
# signed cloud-init enrollment plus root-only Access delivery is implemented.
capability_job=router.split("  host_capabilities:", 1)[1].split("  host_first_use:", 1)[0]
assert "VULTR_SSH_PRIVATE_KEY" not in capability_job
capability_probe=Path("edge-platform/scripts/host_capability_preflight.py").read_text(encoding="utf-8")
assert "operator_ssh_private_key" not in capability_probe
assert '"bootstrap_transport": "SSH_RETIRED_CLOUD_INIT_REQUIRED"' in capability_probe
assert 'admit_first_use_bootstrap_transport().map_err(str::to_owned)?;' in provider
assert provider.count("admit_first_use_bootstrap_transport().map_err(str::to_owned)?;") == 2
assert 'HOST_FIRST_USE_CLOUD_INIT_ENROLLMENT_NOT_IMPLEMENTED_NO_CREATE' in provider

# The SSH-free native bootstrap is a verified, secret-free component of the
# existing Rust Vultr owner. It must not be used to bypass the first-use gate
# until the one-shot Worker Access/runner handoff is implemented.
bootstrap=Path("edge-platform/crates/edge-orchestrator/src/vultr_host_bootstrap.rs").read_text(encoding="utf-8")
native_init=Path("edge-platform/crates/edge-orchestrator/src/vultr_native_cloud_init.rs").read_text(encoding="utf-8")
assert '#[path = "vultr_native_cloud_init.rs"]' in bootstrap
assert "render_native_first_use_cloud_init" in bootstrap
assert "sha256sum --check --status" in native_init
assert "local host-enroll" in native_init
assert "HOST_CLOUD_INIT_NATIVE_OWNER_ALREADY_PRESENT_NO_REPLAY" in native_init
assert "NATIVE_ROOT_ENROLLED_AWAITING_ONE_TIME_CREDENTIAL_HANDOFF" in native_init
assert "EDGE_RUNNER_REGISTRATION_TOKEN" not in native_init.split("const NATIVE_FIRST_USE:",1)[1].split('";',1)[0]
assert "ssh_authorized_keys:" not in native_init.split("const NATIVE_FIRST_USE:",1)[1].split('";',1)[0]
assert "admit_first_use_bootstrap_transport().map_err(str::to_owned)?;" in provider
assert "attest_vm_first_use_credential_bytes(&bytes, generation, expected_sha256)?" in vm_proof
assert "verify_vm_first_use_git_prerequisites(host)" in vm_proof
assert "host_vm_create=NOT_AUTHORIZED" in vm_proof
assert "deploy_worker_version(" not in vm_proof and "patch_worker" not in vm_proof

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

# A closed Rust enum, not the human command text, is the sole mutation
# dispatcher across the reusable VM workflow and native effect/report gates.
assert "operation: ${{ needs.host.outputs.operation }}" in router
assert "operation: ${{ needs.host_resume_receipt.outputs.operation }}" in router
assert "operation:\n        required: true" in native
assert native.count("HOST_OPERATION: ${{ inputs.operation }}") == 2
assert "case \"${COMMAND_BODY}\" in" not in native
assert "startsWith(env.COMMAND_BODY, '/host apply ')" not in native
assert "startsWith(env.COMMAND_BODY, '/host recover ')" not in native
assert native.count("env.HOST_OPERATION == 'APPLY_PREFLIGHT'") >= 3
assert 'test "${HOST_OPERATION}" = APPLY_PREFLIGHT' in native
assert '"${HOST_OPERATION}" = APPLY_PREFLIGHT ]]; then' in native
assert "grep -Fxq false" not in router, "GitHub API bool must be decoded as JSON"
assert "jq -e '(.errors == null)" in router
assert "needs.host.outputs.operation == 'STATUS'" in router

# Compile-time native modules are part of the same agent, not extra owners.
for name in ("runtime_environment", "runtime_templates", "mesh_runtime_state", "legacy_runtime_effects"):
    assert f"mod {name};" in agent_main
    assert f"use {name}::*;" in agent_main
    assert Path(f"edge-platform/crates/edge-agent/src/{name}.rs").is_file()
assert agent_main.endswith("mod native_mutation_ingress_tests;\n")

# The old direct Vultr CLI action/destroy/cleanup dispatchers are deleted as
# compiled source, not masked by an alternate shell or a hidden CLI variant.
assert "pub async fn run(args: Vec<String>" not in provider
for retired in ("run_destroy_apply", "run_cleanup", "run_action", "run_substrate_apply",
                "run_initial_vm_runtime", "run_runner_bootstrap", "run_apply"):
    assert not re.search(rf"(?:async )?fn {retired}\(", provider), retired
assert "VultrLifecycle" not in orchestrator_cli

print("native_only_workflow_topology=PASS")
