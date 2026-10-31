#!/usr/bin/env python3
"""Verify native-only GitHub ingress after the hard cut (no legacy dispatch)."""
from pathlib import Path
import ast
import re

root=Path(".github/workflows")
required={"edge-control-plane.yml","edge-platform-ci.yml","host-native-observe.yml"}
legacy={"credential-lifecycle.yml","vultr-lifecycle.yml","vultr-acceptance-resume.yml","vm-application-lifecycle.yml","vultr-vpc-lifecycle.yml","windows-physical.yml"}
actual={p.name for p in root.glob("*.yml")}
assert required <= actual, f"native workflow missing: {required-actual}"
assert not (legacy & actual), f"legacy mutation workflow present: {legacy&actual}"
router=(root/"edge-control-plane.yml").read_text(encoding="utf-8")
native=(root/"host-native-observe.yml").read_text(encoding="utf-8")
# The single /host namespace also owns a strictly read-only external Line2
# witness; it can use protected credentials only on the GitHub-hosted vantage.
# This job MUST NOT acquire native root, a new transport, or a provider write.
line2 = router.split("  host_line2_external_witness:\n",1)[1].split("\n  host_project_dns:",1)[0]
for admission in (
    "github.event.issue.number == 1",
    "github.actor_id == '44100369'",
    "github.run_attempt == 1",
    "startsWith(github.event.comment.body, '/host witness-line2 ')",
    "name: production-vultr",
    "contents: read",
    "bash edge-platform/scripts/resolve_durable_release.sh",
    'test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"',
    "EDGE_RELEASE_CONTEXT_PATH=",
    "compile_vm_host_desired.sh",
    "--source-comment-id",
    'witness-line2 "${machine}"',
    "line2_g5_full_policy_matrix=UNPROVEN",
    "line2_authenticated_doh_a_and_nxdomain=VERIFIED_ALL_SIX_PROXY_PATHS",
    "line2_local_dns_leak_absence=UNPROVEN_NEEDS_EXTERNAL_CAPTURE",
):
    assert admission in line2, f"Line2 protected witness is missing {admission}"
assert "issues: write" in line2, "single correlated report cannot be posted"
assert "gh api -X POST" in line2 and "issues/1/comments" in line2
assert "SOURCE_COMMENT_ID" in line2 and "G5_FULL_NETWORK_MATRIX=UNPROVEN" in line2
assert "PROXIED_DOH_A_AND_NXDOMAIN=${report}" in line2
assert "NATIVE_SIGNED_VM_READBACK=NOT_SUBSTITUTED" in line2
assert "id: witness" in line2 and "if: ${{ always() }}" in line2
assert "group: sing-box-line2-independent-readonly-${{ github.event.comment.id }}" in line2
assert "sudo " not in line2 and "docker " not in line2
assert "CLOUDFLARE_CONTROL_TOKEN:" not in line2
assert "IAMAMAN11_SING_BOX_CONTROL_PLANE_TOKEN:" not in line2
assert "uses: ./.github/workflows/host-native-observe.yml" not in line2
ci=(root/"edge-platform-ci.yml").read_text(encoding="utf-8")
# Release publication authenticates GitHub's exact two-parent merge and
# merged PR identity, not the human commit message. This must support
# ordinary GitHub merge titles and authorized custom titles equally.
assert "HOST_RELEASE_MERGE_SUBJECT_NOT_CANONICAL" not in ci
assert 'repos/${REPOSITORY}/pulls?state=closed&sort=updated&direction=desc&per_page=100' in ci
assert '.merge_commit_sha == $accepted' in ci
assert '.head.sha == $candidate' in ci
assert 'HOST_RELEASE_MERGED_PR_NOT_UNIQUE' in ci
assert 'HOST_RELEASE_MERGED_PR_ID_UNPROVEN' in ci
assert "  issue_comment:" in router and "  workflow_run:" in router
# GitHub run titles are public, short navigation labels, never raw commands.
# /host admin requests carry opaque encoded argv and must stay in signed intents.
run_name = next(line for line in router.splitlines() if line.startswith("run-name:"))
assert "github.event.comment.body" not in run_name, "raw admin argv leaked into run title"
assert "github.event.comment.id" in run_name, "operator correlation removed"
assert "release continuation" in run_name, "post-merge action title missing"
# VM5 first-use continuation must give the existing, read-scoped Github
# token to the shared ReleaseSet resolver. A missing GH_TOKEN previously
# stopped the protected seal job *after* the native root key was registered,
# leaving no safe way to finish bootstrap from that workflow attempt.
seal = router.split("  host_resume_seal:\n", 1)[1].split("\n  host_resume_native_access:", 1)[0]
assert "GH_TOKEN: ${{ github.token }}" in seal, "VM bootstrap seal resolver has no GitHub token"
assert "contents: read" in seal and "actions: read" in seal
assert "bash edge-platform/scripts/resolve_durable_release.sh" in seal
assert "IAMAMAN11_SING_BOX_CONTROL_PLANE_TOKEN" not in seal, "No broad PAT for release GET"
# A fresh authenticated /host recover --bootstrap-access must continue ONLY
# the existing signed root credential handoff, never the original CREATE/INSTALL.
# Both the old merge continuation and new explicit recovery share the same
# native owner/proof/signer; the latter cannot enter host_resume_native APPLY.
bootstrap = router.split("  host_resume_native_bootstrap:\n", 1)[1].split("\n  host_resume_seal:", 1)[0]
access = router.split("  host_resume_native_access:\n", 1)[1].split("\n  host_resume_native:", 1)[0]
install = router.split("  host_resume_native:\n", 1)[1]
assert 'command=(recover "${BASH_REMATCH[1]}" --bootstrap-access)' in router
assert "BOOTSTRAP_ACCESS_PREFLIGHT" in bootstrap and "BOOTSTRAP_ACCESS_PREFLIGHT" in seal
assert "BOOTSTRAP_ACCESS_PREFLIGHT" in access
assert "github.event_name == 'issue_comment'" in bootstrap
assert "github.run_attempt == 1" in bootstrap
assert "local host-refresh" in bootstrap and "local host-bootstrap-proof" in bootstrap
assert "local host-bootstrap-access" in access
assert "HOST_RESUME_MODE" in seal
assert "git/ref/heads/main" in seal and 'test "$(git rev-parse HEAD)"' in seal
assert "needs.host_resume_receipt.outputs.operation == 'APPLY_PREFLIGHT'" in install
assert "needs.host.outputs.operation == 'BOOTSTRAP_ACCESS_PREFLIGHT'" not in install
assert "host_resume_native_bootstrap" in router and "host_resume_native_access" in router
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
assert 'vm-credential-proof "${TARGET_MACHINE}"' in capability
assert "host_vm_worker_live_source=GIT_PIN_EXACT_ACCESS_GET_PROVEN" in capability
assert "host_vm_worker_live_source=BLOCKED" in capability
assert "host_worker_mutations=0" in capability
# GitHub job-level concurrency retains only ONE running and ONE pending
# participant per group; a third simultaneous publisher cancels the older
# pending report even with cancel-in-progress=false. Host Access and hosted
# VM capability GET may run concurrently, but native signed reconciliation
# must wait for the hosted capability JSON to be written or explicitly fail.
host_access = router.split("  host_access_boundary:\n", 1)[1].split("\n  host_capabilities:\n", 1)[0]
native_dispatch = router.split("  host_observe:\n", 1)[1].split("\n  host_report:\n", 1)[0]
def require_ordered_native_report(dispatch):
    assert "needs: [host, host_report, host_worker_authorizer, host_capabilities]" in dispatch
    assert "always() && !cancelled()" in dispatch
    assert "needs.host.result == 'success'" in dispatch
    assert "needs.host_report.result == 'success'" in dispatch
    assert "uses: ./.github/workflows/host-native-observe.yml" in dispatch
require_ordered_native_report(native_dispatch)
for missing in (
    native_dispatch.replace(
        "host_worker_authorizer, host_capabilities]", "host_worker_authorizer]", 1),
    native_dispatch.replace("always() && !cancelled()", "true", 1),
    native_dispatch.replace("needs.host_report.result == 'success'", "true", 1),
):
    try:
        require_ordered_native_report(missing)
    except AssertionError:
        pass
    else:
        raise AssertionError("UNSERIALIZED_HOST_DEEP_NATIVE_REPORT_NOT_REJECTED")
assert "group: host-deep-report-${{ github.event.comment.id }}" in host_access
assert "group: host-deep-report-${{ github.event.comment.id }}" in capability
assert "group: host-deep-report-${{ inputs.source_comment_id }}" in native
assert "cancel-in-progress: false" in host_access
assert "cancel-in-progress: false" in capability
assert "cancel-in-progress: false" in native
assert "host_provider_mutations=0" in capability
assert "host_diagnostic_summary.py" in capability
assert "report_comment_id: ${{ needs.host_report.outputs.comment_id }}" in router
assert "report_comment_id:" in native
assert "Native observation — same operation, independent runner" in native
assert "group: host-deep-report-${{ github.event.comment.id }}" in capability
assert "group: host-deep-report-${{ inputs.source_comment_id }}" in native
assert "cancel-in-progress: false" in capability
assert "cancel-in-progress: false" in native
assert "issues/comments/${REPORT_COMMENT_ID}" in native
assert "HOST_DIAGNOSTIC=CORRELATED_ONE_REPORT_NO_MUTATION" in capability
assert "RELEASE_SET_SHA256:" in capability
assert "REPORT_COMMENT_ID:" in capability
assert "issues/comments/${REPORT_COMMENT_ID}" in capability
assert "native-sealed-access" not in capability
assert "  host_capabilities:" in router
assert "host_first_use:" in router and "host_resume_receipt:" in router
assert "  workflow_call:" in native and "  workflow_call:" not in router
# One shared Git readback is passed to existing protected hosted capability
# checks; neither a second runner nor a second desired source is added.
assert "diagnostic_git_phase:" in router
assert "diagnostic_git_reason:" in router
assert "host_first_use_last_proven_step=" not in router
assert 'host_first_use_${field}=' in router
assert "diagnostic_release_set_sha256" in router
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
# A historical BEGIN must be root-journal verified, never inferred from
# Docker's running state or erased by an operator status request.
native_pending=Path("edge-platform/crates/edge-agent/src/host_snapshot.rs").read_text(encoding="utf-8")
typed_proto=Path("edge-platform/proto/edge/platform/v1/fleet.proto").read_text(encoding="utf-8")
assert "HOST_SNAPSHOT_ORIGINAL_BEGIN_MISMATCH" in native_pending
assert "decode_host_result(&begin_bytes)" in native_pending
assert "begin.operation_id != intent.operation_id" in native_pending
assert "original_release_sha256: intent.release_set_sha256" in native_pending
assert "original_desired_sha256: intent.desired_sha256" in native_pending
assert "pending_begin_record_sha256:" in native_pending
assert "pending_original_release_sha256 = 17" in typed_proto
assert "pending_original_desired_sha256 = 18" in typed_proto
assert "pending_begin_record_sha256 = 19" in typed_proto
assert "pending_original_release_sha256|pending_original_desired_sha256|pending_begin_record_sha256" in native
assert "protected_journal_has_pending(journal)?" in Path("edge-platform/crates/edge-agent/src/host_native.rs").read_text(encoding="utf-8")

# A fresh Windows install must have exactly one owner of SCM/SYSTEM task.
# The runner bootstrap is transport-only; it must not duplicate registration.
windows_installer = Path("edge-platform/scripts/install-windows-release.ps1").read_text()
windows_runner_bootstrap = Path("edge-platform/scripts/bootstrap-windows-runner.ps1").read_text()
assert "function Assert-RootExecutionChain {" in windows_installer
assert "Assert-RootExecutionChain -ApproveRepair:$ApproveAclRepair" in windows_installer
assert "Assert-RootExecutionChain -CreateFresh" in windows_installer
assert "WINDOWS_INSTALL_PRELAUNCH_DESCENDANT_REPARSE_BLOCKED" in windows_installer
assert "WINDOWS_INSTALL_ACL_REPAIR_REQUIRES_EXACT_DISABLED_SYSTEM_TASK" in windows_installer
assert "WINDOWS_INSTALL_ACL_REPAIR_OLD_CONSOLE_RUNNING" in windows_installer
assert "WINDOWS_INSTALL_ACL_REPAIR_CONTROLLER_NOT_STOPPED" in windows_installer
preflight = windows_installer.split("function Assert-RootExecutionChain {", 1)[1].split(
    "function Protect-ReleaseStageBeforeExecution {", 1
)[0]
assert preflight.index("WINDOWS_INSTALL_ACL_REPAIR_REQUIRES_EXACT_DISABLED_SYSTEM_TASK") < preflight.index(
    "& icacls.exe $path /grant:r"
)
assert "Disable-ScheduledTask" not in windows_installer
assert "Enable-ScheduledTask" not in windows_installer

prelaunch = windows_installer.split("function Assert-RootExecutionChain {", 1)[1].split(
    "function Protect-ReleaseStageBeforeExecution {", 1
)[0]
assert prelaunch.index("WINDOWS_INSTALL_PRELAUNCH_DESCENDANT_REPARSE_BLOCKED") < prelaunch.index(
    "& icacls.exe (Join-Path $path '*') /reset /T /Q"
)
assert "Get-ProtectedAppAclReadback -Path $entry.FullName" in prelaunch

assert "function Assert-ExistingNativeReleaseFromProtectedGit {" in windows_installer
assert "Assert-ExistingNativeReleaseFromProtectedGit\n    $installed" in windows_installer
assert "WINDOWS_INSTALL_OLD_EXECUTABLE_NOT_PUBLISHED_NO_EXECUTION" in windows_installer
assert "WINDOWS_INSTALL_OLD_RELEASE_NOT_PROTECTED_MAIN_ANCESTOR" in windows_installer

assert "WINDOWS_INSTALL_PRELAUNCH_UNPRIVILEGED_WRITER_BLOCKED" in windows_installer
assert 'Join-Path $InstallRoot (".release-stage-"' in windows_installer
assert "function Connect-CanonicalWindowsApplication {" in windows_runner_bootstrap
assert "& $installer -ConnectWindows -InstallRoot $ApplicationRoot" in windows_runner_bootstrap
assert "function Register-PrivilegedDispatcher {" not in windows_runner_bootstrap
assert "function Converge-ControllerService {" not in windows_runner_bootstrap
assert "Register-ScheduledTask" not in windows_runner_bootstrap
assert "Install-InitialApplicationAuthority" not in windows_runner_bootstrap

# A signed explicit recovery for an old BEGIN uses the existing native
# transport, NEVER a second service or an unsigned root journal reset.
journal = Path("edge-platform/crates/edge-shared-types/src/host_journal.rs").read_text(encoding="utf-8")
native_admission = Path("edge-platform/crates/edge-agent/src/host_native.rs").read_text(encoding="utf-8")
assert "--adjudicate" in router
assert "command=(recover" in router
assert "adjudicate: bool" in orchestrator_cli
adjudication_source = Path("edge-platform/crates/edge-orchestrator/src/host_command.rs").read_text(encoding="utf-8")
assert "HostLifecycleOperation::Adjudicate" in adjudication_source
assert "HostLifecycleOperation::Adjudicate => HostWorkflowOperation::ApplyPreflight" in adjudication_source
assert "intent.action != edge_shared_types::FleetHostAction::Recover as i32" in native_admission
assert "HOST_NATIVE_HISTORICAL_BASELINE_UNPROVEN_NO_REPLAY" in journal
assert "HOST_NATIVE_RECOVERY_CONFLICTING_TERMINAL" in journal
assert 'let terminal_name = if partial { "incomplete" } else { "verified" };' in journal
assert "FleetHostResultState::UnknownNoReplay as i32" in journal
assert '("incomplete", Ok(FleetHostResultState::UnknownNoReplay))' in journal
assert "HistoricalPartialRequiresFreshApply" in journal
assert "FLEET_HOST_RESULT_REASON_HISTORICAL_PARTIAL_REQUIRES_FRESH_APPLY = 7" in typed_proto
assert "Refresh exact root owner for code-only recover, without resource replay" in native
assert "HOST_OPERATION == 'RECOVER_PREFLIGHT'" in native
assert "HOST_OPERATION == 'APPLY_PREFLIGHT'" in native

# Operator drift evidence must come from the Ed25519-verified root snapshot,
# and can never be substituted by the runner's unauthenticated observation.
host_readback=Path("edge-platform/crates/edge-orchestrator/src/host_command.rs").read_text(encoding="utf-8")
signed_start=host_readback.index("edge_shared_types::host_diagnostic_snapshot::verify_installed_read_only(")
signed_proof=host_readback.index("let snapshot_proof = if matches_current_release {", signed_start)
assert '"VERIFIED_ROOT_SIGNED_READ_ONLY"' in host_readback[signed_proof:]
assert '"VERIFIED_ROOT_SIGNED_STALE_RELEASE_READ_ONLY"' in host_readback[signed_proof:]
assert "host_native_snapshot_proof={snapshot_proof}" in host_readback[signed_proof:]
assert "INSTALLED_RELEASE_DRIFT_CURRENT_STATE_UNPROVEN" in host_readback[signed_proof:]
assert "ROOT_SIGNED_INSTALLED_CLAIM_ONLY" in host_readback[signed_proof:]
assert "native_snapshot_proof" in host_readback[signed_proof:]
expected=host_readback.index("host_native_snapshot_bundle_expected_sha256=", signed_proof)
observed=host_readback.index("host_native_snapshot_bundle_observed_sha256=", expected)
match=host_readback.index("host_native_snapshot_bundle_matches=", observed)
assert signed_start < signed_proof < expected < observed < match
assert "hex(&native_bundle_sha)" in host_readback[expected:observed]
assert "hex(&verified_observation.observed_release_sha256)" in host_readback[observed:match+180]
assert "host_native_snapshot_replay_allowed=false" in host_readback[match:]
assert "bundle_expected_sha256|bundle_observed_sha256|bundle_matches" in native
assert "host_native_snapshot_proof=VERIFIED_ROOT_SIGNED_READ_ONLY" in native

# The same /host apply must never upgrade Worker bytes and trigger native INSTALL.
# The closed, Rust-owned plan decision gates the dependent native job.
native_dispatch = router.split("  host_observe:\n", 1)[1].split("  host_report:\n", 1)[0]
assert "needs.host_worker_authorizer.result == 'success' &&" in native_dispatch
assert "needs.host_worker_authorizer.outputs.source_upgrade_required == 'false'" in native_dispatch
# Explicit historical RECOVER is a signed FleetHostAction::Recover carried by
# the existing VM root host-apply dispatch; unlike a fresh APPLY, it cannot
# request a source-upgrade action. The signed Root Agent verifies Worker auth.
# Without this narrow admission the green workflow silently skips the VM job.
assert "github.event.comment.body == format('/host recover {0} --adjudicate', needs.host.outputs.machine_id)" in native_dispatch
assert "needs.host_worker_authorizer.result == 'success'" in native_dispatch
assert "github.event.comment.body == format('/host apply {0}', needs.host.outputs.machine_id)" in worker
assert "needs.host.outputs.operation == 'APPLY_PREFLIGHT'" in native_dispatch
assert "source_upgrade_required: ${{ steps.plan.outputs.required }}" in worker
assert worker.index("source_upgrade_required: ${{ steps.plan.outputs.required }}") < worker.index("Plan exact VM Worker release with GET only")
assert 'case "${RUST_WORKER_PLAN_REQUIRED}" in' in worker
assert "true|false)" in worker
assert "if: steps.plan.outputs.required == 'true'" in worker


# Physical CREATE must never depend on a Git-only credential reference.
# Native preflight performs a bounded Worker GET; all first-use mutations
# remain disabled until the native encrypted handoff is implemented.
provider=Path("edge-platform/crates/edge-orchestrator/src/vultr_lifecycle_command.rs").read_text(encoding="utf-8")
worker_src=Path("edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs").read_text(encoding="utf-8")
vm_proof=Path("edge-platform/crates/edge-orchestrator/src/vm_credential_proof.rs").read_text(encoding="utf-8")
gate="verify_current_vm_first_use_worker_source("
assert provider.count(gate)==1, "one read-only Worker GET must precede first-use admission"
# Do not restore the retired SSH receipt refresh and old-owner compatibility
# migration. The installed Root Agent already owns the signed in-place
# host-refresh path; first-use SSH remains separately BLOCKED by #484.
assert "host_receipt_refresh(" not in provider
assert "vm_owner_compatibility" not in provider and "vm_owner_upgrade" not in provider
assert not Path("edge-platform/crates/edge-orchestrator/src/vm_owner_compatibility.rs").exists()
assert not Path("edge-platform/crates/edge-orchestrator/src/vm_owner_upgrade.rs").exists()
assert provider.index(gate) < provider.index('host_first_use_provider_plan=EXACT_CREATE_ONLY')
assert "acceptance_create_machine(provider_spec, machine_id).await?" not in provider
assert "bootstrap_production_runner(" not in provider
assert "HOST_VM_CREATE_REQUIRES_NATIVE_ONE_TIME_ENROLLMENT_NO_SSH" in provider
assert '#[path = "vm_credential_proof.rs"]' in worker_src
assert "get_vm_credential_bundle_with_access(" in vm_proof
# A GET-only capability probe must not request an SSH private key.
# The published first-use workflow remains fail-closed. The typed Rust
# CREATE is reachable only through its protected GitHub admission and must
# never be activated by a generic provider lifecycle or SSH fallback.
capability_job=router.split("  host_capabilities:", 1)[1].split("  host_first_use:", 1)[0]
assert "VULTR_SSH_PRIVATE_KEY" not in capability_job
capability_probe=Path("edge-platform/scripts/host_capability_preflight.py").read_text(encoding="utf-8")
assert "operator_ssh_private_key" not in capability_probe
assert '"bootstrap_transport": "SSH_RETIRED_CLOUD_INIT_REQUIRED"' in capability_probe
assert 'admit_first_use_bootstrap_transport().map_err(str::to_owned)' not in provider
assert 'HOST_FIRST_USE_PROTECTED_GITHUB_DURABLE_BEGIN_REQUIRED' in provider
assert 'singbox-native-first-use-v1' in provider
assert 'render_native_first_use_with_runner(' in provider
assert 'host_first_use_scrub(' in provider
assert provider.count("HOST_FIRST_USE_PROTECTED_GITHUB_DURABLE_BEGIN_REQUIRED") == 1
assert 'host_first_use_provider_preflight(machine_id, context).await?' in provider
assert 'HOST_FIRST_USE_PROVIDER_NOT_EXACT_CREATE_NO_REPLAY' in provider
# The existing hosted job is now the only first-use CREATE owner. Durable
# Git BEGIN + absence/runner checks MUST precede issuing a short-lived token
# and the one permitted provider CREATE. Signed native proof must precede
# provider user-data scrub GET and public receipt PR finalization.
firstuse_job=router.split("  host_first_use:",1)[1].split("  host_resume_receipt:",1)[0]
assert "VULTR_SSH_PRIVATE_KEY" not in firstuse_job
assert "EDGE_SSH_PRIVATE_KEY_PATH" not in firstuse_job
assert "first-use-preflight" in firstuse_job
assert firstuse_job.index("Reserve unique Git receipt PR and durable BEGIN BEFORE VM CREATE") < firstuse_job.index("/actions/runners/registration-token")
assert firstuse_job.index("/actions/runners/registration-token") < firstuse_job.index("Execute exactly one no-SSH native Vultr CREATE")
assert '{40,512}' not in firstuse_job, "GitHub opaque runner tokens may be 29 chars"
assert 'HOST_FIRST_USE_RUNNER_TOKEN_UNSAFE_SYNTAX_NO_CREATE' in firstuse_job
assert 'HOST_FIRST_USE_RUNNER_REGISTRATION_API_DENIED_NO_CREATE' in firstuse_job
assert firstuse_job.index("Execute exactly one no-SSH native Vultr CREATE") < firstuse_job.index("Collect signed public-only proof")
assert firstuse_job.index("bootstrap-proof-check") < firstuse_job.index('first-use-scrub')
assert firstuse_job.index('first-use-scrub') < firstuse_job.index("Complete ONLY the reserved protected public receipt PR")
assert "host-receipt-${TARGET_MACHINE}-${SOURCE_COMMENT_ID}" in firstuse_job
assert "HOST_FIRST_USE_DURABLE_BEGIN_RECORDED" in firstuse_job
assert "HOST_FIRST_USE_CREATE_ONCE_NO_AUTOMATIC_REPLAY" in firstuse_job
assert "FIRST_USE_ABORT_PREFLIGHT" in router
assert "host_first_use_abort:" in router
assert "edge-platform/scripts/host_first_use_abort.py" in router
assert "HOST_FIRST_USE_NATIVE_HANDOFF_NOT_ACCEPTED_NO_CREATE" not in firstuse_job
assert "edge-agent.service" not in Path("win/vultr-waw/cloud-init.yaml").read_text(encoding="utf-8")
# One selected Git pointer (never shell-copied generation/digest) is
# verified by the existing hidden Rust Worker Access GET during deep status.
# No user-specified bundle identity or worker mutation is admitted.
capabilities=router.split("  host_capabilities:",1)[1].split("\n  host_",1)[0]
assert 'vm-credential-proof "${TARGET_MACHINE}"' in capabilities
assert 'host_vm_worker_live_source=GIT_PIN_EXACT_ACCESS_GET_PROVEN' in capabilities
assert 'host_vm_worker_live_source=BLOCKED' in capabilities
assert 'host_worker_mutations=0' in capabilities
assert 'HOST_ORIGINAL_COMMAND:' in capabilities
assert 'EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET:' in capabilities
assert 'first-use "' not in capabilities

# GitHub runs each step in a fresh shell. A prior step's export cannot provide
# the exact release context to the signer proof invocation.
signer_step = capabilities.split('      - name: Verify fresh active Worker Ed25519 challenge', 1)[1].split('      - name: Publish one correlated deep diagnosis', 1)[0]
assert 'export EDGE_RELEASE_CONTEXT_PATH="${OUTPUT_DIR}/resolved.env"' in signer_step
assert signer_step.index('export EDGE_RELEASE_CONTEXT_PATH=') < signer_step.index('vm-worker-signer-proof "${TARGET_MACHINE}"')
assert 'HOST_SIGNER_PROOF_RELEASE_CONTEXT_UNAVAILABLE' in signer_step
assert 'host_vm_worker_signed_identity=UNPROVEN' in signer_step



# Rust native cloud-init is the only accepted CREATE renderer; the hosted
# flow must prove the independent one-use receipt and user-data scrub.
bootstrap=Path("edge-platform/crates/edge-orchestrator/src/vultr_host_bootstrap.rs").read_text(encoding="utf-8")
native_init=Path("edge-platform/crates/edge-orchestrator/src/vultr_native_cloud_init.rs").read_text(encoding="utf-8")
assert '#[path = "vultr_native_cloud_init.rs"]' in bootstrap
assert "render_native_first_use_cloud_init" in bootstrap
assert "sha256sum --check --status" in native_init
assert "local host-enroll" in native_init
assert "HOST_CLOUD_INIT_NATIVE_OWNER_ALREADY_PRESENT_NO_REPLAY" in native_init
assert "NATIVE_ROOT_ENROLLED_AWAITING_ONE_TIME_CREDENTIAL_HANDOFF" in native_init
assert "EDGE_RUNNER_REGISTRATION_TOKEN" not in native_init.split("const NATIVE_FIRST_USE:",1)[1].split('"#;',1)[0]
assert "ssh_authorized_keys:" not in native_init.split("const NATIVE_FIRST_USE:",1)[1].split('"#;',1)[0]
assert "render_native_first_use_with_runner(" in provider
assert "host_first_use_scrub(" in provider
assert "HOST_FIRST_USE_PROTECTED_GITHUB_DURABLE_BEGIN_REQUIRED" in provider

# Provider payload omits sshkey_id entirely for the native bootstrap profile.
native_provider=Path("edge-platform/crates/edge-provider-vultr/src/lib.rs").read_text(encoding="utf-8")
lifecycle_service=Path("edge-platform/crates/edge-orchestrator/src/vultr_lifecycle_service.rs").read_text(encoding="utf-8")
assert 'ssh_key_id: Option<&' in native_provider
assert '#[serde(skip_serializing_if = "Vec::is_empty")]\n    sshkey_id:' in native_provider
assert "singbox-native-first-use-v1" in lifecycle_service
assert "HOST_NATIVE_CREATE_MUST_HAVE_NO_SSH_AND_PINNED_CLOUD_INIT" in lifecycle_service
assert "--runner-only" in vm_installer
assert "runner first-use already registered; no replay" in vm_installer
assert "runner bootstrap must use --runner-only" in vm_installer
assert 'CF_ACCESS_CLIENT_ID=%s' not in vm_installer
assert 'CF_ACCESS_CLIENT_SECRET=%s' not in vm_installer
assert "SING_BOX_NATIVE_BOOTSTRAP" in vm_installer
native_bootstrap = Path("edge-platform/crates/edge-agent/src/host_bootstrap_access.rs").read_text(encoding="utf-8")
native_enroll = Path("edge-platform/crates/edge-agent/src/host_enroll.rs").read_text(encoding="utf-8")
assert 'bootstrap-x25519.secret' in native_bootstrap and 'bootstrap-x25519.secret' in native_enroll
assert 'local host-bootstrap-access' in vm_installer
assert 'diagnose_canonical_host_access(&staged)' in native_bootstrap
assert 'BOOTSTRAP_ACCESS_ALREADY_BEGUN_NO_REPLAY' in native_bootstrap
assert 'FleetVmBootstrapAccessEnvelope' in Path("edge-platform/proto/edge/platform/v1/fleet.proto").read_text(encoding="utf-8")

assert "RUNNER_REGISTERED_AWAITING_ROOT_ONLY_ACCESS_HANDOFF" in native_init
assert "fn render_native_first_use_with_runner(" in native_init

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
assert ('"${HOST_OPERATION}" = APPLY_PREFLIGHT ]]; then' in native
        or '"${TARGET_KIND}" = WINDOWS && "${HOST_OPERATION}" = APPLY_PREFLIGHT' in native)
# Windows cannot be dispatched by runner unless current Git public trust
# was pinned at PREPARE, and only one existing SYSTEM task may mutate SCM.
assert "verify_windows_signed_git_prerequisites(selected)" in host_source
assert "HOST_WINDOWS_GIT_RECEIPT_REGISTRATION_REQUIRED" in Path(
    "edge-platform/crates/edge-shared-types/src/host_lifecycle.rs"
).read_text(encoding="utf-8")
assert "Start-ScheduledTask -TaskName" not in native
assert "host-native-windows-" in native
assert "HOST_WINDOWS_SYSTEM_RECEIPT_UNKNOWN_NO_REPLAY" in native
assert "SHA256]::HashData($candidate)" in native
assert "EdgePlatformPrivilegedDispatch" in Path(
    "edge-platform/scripts/bootstrap-windows-runner.ps1"
).read_text(encoding="utf-8")
assert "WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-20'" in native
assert "[IO.FileMode]::CreateNew" in native
assert "native-windows-receipt-" in native
assert 'native-result "${TARGET_MACHINE}"' in native
assert "host-native-windows-" in native
# NetworkService can receive a false ABSENT from the SYSTEM Task Scheduler.
# STATUS must use installed native doctor / optional typed observation only.
# Even signed-intent DELIVERY cannot rely on NetworkService's task enumeration:
# existing LocalSystem exclusively owns native journal ACL, Worker authorization,
# exact SCM effect and signed receipt. Administrator first-use still checks task.
assert "release_set_sha256: ${{ needs.host.outputs.diagnostic_release_set_sha256 }}" in router
assert "release_set_sha256:\n        required: false" in native
assert "host_windows_system_task_visibility=UNPROVEN_NETWORKSERVICE" in native
assert "host_windows_first_use_preflight=NOT_RUN_ADMIN_OR_SYSTEM_REQUIRED" in native
assert "host_typed_readback=UNPROVEN_INSTALLED_VERSION_OR_EVIDENCE" in native
assert "windows-first-use-offline-handoff.ps1" not in native
assert "-Preflight -ExistingActive" not in native
assert "Get-ScheduledTask" not in native
assert "actions/checkout@v4" not in native
assert "Start-ScheduledTask" not in native
assert "HOST_WINDOWS_RUNNER_MUST_REMAIN_NETWORKSERVICE" in native
win_system = Path(
    "edge-platform/crates/edge-console/src/windows_signed_host.rs"
).read_text(encoding="utf-8")
assert "require_exact_immutable_activation_console(install_root)?;" in win_system
assert "verify_native_journal_protection(&journal).map_err(str::to_owned)?;" in win_system
assert "verify_system_trust(" in win_system
assert "edge_secrets::request_canonical_host_authorization(&intent_bytes, &identity)" in win_system
# Git authority and installed physical runtime are distinct, but the
# same protected SYSTEM journal and Worker signature must guard both.
assert "execute_native_windows_host_once(" in win_system
assert "windows_trust_enrollment::fetch_exact_protected_git(&installed).await?" in win_system
assert "HOST_WINDOWS_SYSTEM_SIGNER_ROTATION_UNPROVEN" in win_system
assert "&installed_runtime_sha256," in win_system
journal_source = Path(
    "edge-platform/crates/edge-shared-types/src/host_journal.rs"
).read_text(encoding="utf-8")
assert "expected_windows_installed_release: Option<WindowsExecutionBinding<'_>>" in journal_source
assert "expected_config_sha256" in journal_source
assert "HOST_WINDOWS_RECOVERY_CONFIGURATION_NOT_CONVERGED_NO_REPLAY" in journal_source
admin_system = Path("edge-platform/crates/edge-console/src/windows_admin.rs").read_text(encoding="utf-8")
assert "request_canonical_native_admin_authorization" in admin_system
assert "host_admin::verify_authorization" in admin_system
assert "TransportRequest::open" in admin_system
assert "host_admin::sign_receipt" in admin_system
# Generic ADMIN is an arbitrary executable and must not bypass UNKNOWN
# lifecycle network effects. Only a signed native RECOVER can inspect the
# historical resource journal; /host status remains independently read-only.
assert 'name.starts_with("resource-") && recovery' in admin_system
assert 'name.starts_with("resource-") && (admin || recovery)' not in admin_system
assert "signed_admin_cannot_bypass_historical_resource_pending" in admin_system
assert "if admin && recovery {" in admin_system
assert "HOST_WINDOWS_ADMIN_RECOVERY_SCOPE_INVALID" in admin_system
assert "HOST_WINDOWS_PENDING_GATE_NO_REPLAY" in admin_system
assert "HOST_WINDOWS_OPERATION_EXISTS_NO_REPLAY" in admin_system
assert "check_journal_entry(&name, &id, admin, recovery)?" in admin_system
admin_dispatch = admin_system.split("pub(super) async fn dispatch_if_present", 1)[1].split(
    "pub(super) fn preflight_expired_transport_handoff", 1
)[0]
assert admin_dispatch.count("request_available(&journal, &operation, true, false)?;") == 2
assert admin_dispatch.index(
    "host_admin::verify_authorization"
) < admin_dispatch.rindex(
    "request_available(&journal, &operation, true, false)?;"
) < admin_dispatch.index("create(&pending, &raw)?;")
assert admin_dispatch.index("request_available(&journal") < admin_dispatch.index("request_canonical_native_admin_authorization")
denial = admin_system.split("fn deny_before_begin", 1)[1].split("#[cfg(test)]", 1)[0]
assert denial.index("request_available(&journal") < denial.index("host_admin::prebegin_rejection")
assert "receipt.rejected_before_begin" in denial
assert "transport.consume()?" in denial
assert "windows_native_runtime::execute" in Path("edge-platform/crates/edge-controller/src/controller_rpc.rs").read_text(encoding="utf-8")
effect_contract=Path("edge-platform/crates/edge-shared-types/src/windows_runtime_effect.rs").read_text(encoding="utf-8")
assert "verify_host_authorization" in effect_contract
assert "HOST_WINDOWS_EFFECT_ALREADY_CONSUMED_NO_REPLAY" in effect_contract
assert "effect.challenge.as_ref() != Some(challenge)" in effect_contract
assert "host_admin_native_result=SYSTEM_SIGNED_PROOF_PENDING_INDEPENDENT_VERIFICATION" in native
assert "HOST_WINDOWS_ADMIN_RECEIPT_UNKNOWN_NO_REPLAY" in native
assert 'if [[ "${HOST_OPERATION}" = ADMIN ]]; then' in native
assert "HOST_WINDOWS_INSTALLED_RUNTIME_READBACK_MISMATCH" in journal_source
assert "verify_native_journal_protection(protected_journal_dir)?;" in journal_source
assert "SYSTEM task or immutable action mismatched" in Path(
    "edge-platform/scripts/windows-first-use-offline-handoff.ps1"
).read_text(encoding="utf-8")
assert "grep -Fxq false" not in router, "GitHub API bool must be decoded as JSON"
assert "jq -e '(.errors == null)" in router
assert "needs.host.outputs.operation == 'STATUS'" in router

# Native Windows first-use is a single local Administrator transaction.
# It must never reactivate the old NetworkService-writable unsigned mutation
# inlet while replacing the EXACT existing LocalSystem task.
win_installer = Path("edge-platform/scripts/install-windows-release.ps1").read_text(encoding="utf-8")
win_console = Path("edge-platform/crates/edge-console/src/main.rs").read_text(encoding="utf-8")
assert "[string]$old['windows_datapath_mode'] -notin @('ManagedTun', 'ProxyOnly')" in win_installer
assert "[string]$old['scm_start_type'] -cne 'OnDemand'" in win_installer
assert "require_offline_bootstrap_exact_doctor(" in win_console
assert "require_offline_bootstrap_quiescent(install_root)?;" in win_console
assert "change_offline_bootstrap_task_enabled(false)?;" in win_console
assert 'verify_offline_bootstrap_dispatcher(&before.console_path, "Disabled")?;' in win_console
assert "require_no_running_legacy_dispatcher(&before.console_path)?;" in win_console
assert "require_offline_bootstrap_request_queue_empty(install_root)?;" in win_console
assert 'verify_offline_bootstrap_dispatcher(&post.console_path, "Disabled")?;' in win_console
assert "change_offline_bootstrap_task_enabled(true)?;" in win_console
# Exact LocalSystem failure evidence is advisory, create-only, and recorded in
# the EXISTING native journal, never a new executor or authorization source.
assert "verify_native_journal_protection(&journal)?;" in win_console
assert 'format!("system-dispatch-failure-{release}.pb")' in win_console
assert 'system_dispatch_failure_record(&installed.release_set_sha256, message, when)?' in win_console
assert 'create_new(true)' in win_console
assert '"system_dispatch_failure": system_failure' in Path(
    "edge-platform/crates/edge-console/src/command_dispatch.rs"
).read_text(encoding="utf-8")
assert 'message WindowsSystemDispatchFailure' in Path(
    "edge-platform/proto/edge/platform/v1/diagnostics.proto"
).read_text(encoding="utf-8")
assert 'verify_offline_bootstrap_dispatcher(&console.to_string_lossy(), "Ready")?;' in win_console

# The existing native first-use must actually be reachable from the
# installed console CLI. Source-only helper functions do not satisfy W6.
win_cli = Path("edge-platform/crates/edge-console/src/cli.rs").read_text(encoding="utf-8")
win_dispatch = Path("edge-platform/crates/edge-console/src/command_dispatch.rs").read_text(encoding="utf-8")
assert "OfflineBootstrap(PrivilegedActivateArgs)" in win_cli
assert 'Self::OfflineBootstrap(_) => "offline-bootstrap"' in win_cli
# A narrow W4 locally elevated first-use identity reservation and public
# readback are permitted, but no unsigned SCM/Worker/remote mutation.
assert "Command::OfflineBootstrap(_)" in win_console
assert "Command::OfflineBootstrapPreflight(_)" in win_console
assert "Command::OfflineReceiptIdentityPrepare(_)" in win_console
assert "Command::OfflineReceiptIdentityObserve(_)" in win_console
assert "windows_receipt_enrollment::dispatch_if_present(install_root)" in win_console
assert '.map_err(|reason| format!("SYSTEM_RECEIPT: {reason}"))?' in win_console
# W4 clean physical bootstrap must work with STOPPED / ProxyOnly and
# missing native-host from the old W6 install. The one authorized offline
# transaction itself prepares the protected SYSTEM journal before re-enabling
# the existing scheduled task; service START or a runner script is forbidden.
offline_handoff = win_console.split(
    "fn offline_activate_privileged_release_with_installer(", 1
)[1].split("fn encoded_powershell_command(", 1)[0]
assert "converge_native_host_acl(install_root)?;" in offline_handoff
assert offline_handoff.index("converge_native_host_acl(install_root)") < offline_handoff.index("retarget_privileged_task(")
assert "fn converge_native_host_acl(install_root: &Path)" in win_console
assert "HOST_WINDOWS_SYSTEM_NATIVE_ROOT_REPARSE_OR_NOT_DIR" in win_console
assert "run_icacls(&path, &[\"/remove:g\", \"*S-1-5-20\", \"/Q\"])" in win_console
assert "converge_native_host_acl(install_root)?;" in win_console
identity_owner = Path("edge-platform/crates/edge-console/src/windows_receipt_enrollment.rs").read_text(encoding="utf-8")
assert "verify_native_journal_protection(&root.join(\"journal\"))" in identity_owner
assert "require_windows_local_administrator_first_use()" in identity_owner
assert "Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())" in identity_owner
assert "create_only(&root.join(PRIVATE), secret.as_ref())" in identity_owner
assert "complete_marker(&root)?" in identity_owner
assert "seal_system_private(&root)?" in identity_owner
assert '"/remove:g", "*S-1-5-32-544"' in identity_owner
assert '"/setowner", "*S-1-5-18"' in identity_owner
assert "HOST_WINDOWS_RECEIPT_ENROLL_COMPETING_REQUEST" in identity_owner
# Fresh first-use still denies keys/trust; ONLY an explicitly approved
# retained-BEGIN supersession may transfer two exact unconsumed requests.
assert "preflight_fresh_identity_slot(install_root)" in win_console
assert "HOST_WINDOWS_FIRST_USE_REBIND_EXPLICIT_BEGIN_APPROVAL_REQUIRED" in win_console
assert "preflight_pending_rebind(" in win_console
assert "rebind_pending_after_offline_handoff(" in win_console
assert "verify_offline_bootstrap_dispatcher(&current.console_path, \"Disabled\")" in identity_owner
assert "pending_rebind_snapshot(&root, predecessor)?" in identity_owner
assert "HOST_WINDOWS_FIRST_USE_REBIND_SLOT_ALREADY_USED_NO_REKEY" in identity_owner
assert "fs::hard_link(root.join(name), &saved)" in identity_owner
assert "create_only(&root.join(MARKER), &new_receipt.encode_to_vec())?" in identity_owner
assert '        &root.join("trust-enrollment.pb"),' in identity_owner
assert "        &new_trust.encode_to_vec()," in identity_owner
assert "HOST_WINDOWS_FIRST_USE_REBIND_TRUST_READBACK_UNAVAILABLE" in identity_owner
assert 'windows_trust_enrollment::prepare_disabled_handoff(install_root, true)' in win_console
assert 'windows_trust_enrollment::prepare_pending(root)' in Path("edge-platform/crates/edge-console/src/command_dispatch.rs").read_text(encoding="utf-8")
assert 'Command::OfflineFirstUseStatus(args)' in Path("edge-platform/crates/edge-console/src/command_dispatch.rs").read_text(encoding="utf-8")
assert 'OfflineFirstUseStatus(InstallRootArgs)' in Path("edge-platform/crates/edge-console/src/cli.rs").read_text(encoding="utf-8")
assert "TRUST_RECORDED_UNVERIFIED" in Path("edge-platform/crates/edge-console/src/windows_trust_enrollment.rs").read_text(encoding="utf-8")
assert "require_identity_request_for_trust(" in identity_owner

assert "windows_receipt_enrollment::prepare_disabled_handoff(" in win_console
assert "fresh_machine.as_deref().ok_or(" in win_console
assert "resolve_local_windows_machine(&before).await?" in win_console
assert "OFFLINE_BOOTSTRAP_IDENTITY_STEP_UNCERTAIN_NO_REPLAY" in win_console
assert "HOST_WINDOWS_RECEIPT_ENROLL_SLOT_NOT_EMPTY_NO_REKEY" in identity_owner
install_script = Path("edge-platform/scripts/install-windows-release.ps1").read_text(encoding="utf-8")
assert "WINDOWS_CONNECT_FIRST_USE_STATE_UNPROVEN" in install_script
assert "WINDOWS_CONNECT_FIRST_USE_UNKNOWN_STAGE_NO_REPLAY" in install_script
assert "WINDOWS_CONNECT_INITIAL_SCM_OR_TASK_UNKNOWN_NO_REPLAY" in install_script
assert "WINDOWS_CONNECT_PARTIAL_INITIAL_INSTALL_NO_REPLAY" in install_script
assert "OfflineCleanInstall(InstallRootArgs)" in Path("edge-platform/crates/edge-console/src/cli.rs").read_text(encoding="utf-8")
clean_install = Path("edge-platform/crates/edge-console/src/windows_clean_install.rs").read_text(encoding="utf-8")
assert "prepare_clean_before_scm(install_root, &machine_id)?" in clean_install
assert "resolve_local_windows_machine(&active).await?" in clean_install
assert "HOST_WINDOWS_FIRST_USE_GIT_HOST_ABSENT_OR_AMBIGUOUS" in Path(
    "edge-platform/crates/edge-console/src/windows_trust_enrollment.rs"
).read_text()
assert "async fn install(install_root: &Path)" in clean_install
assert "fn valid_machine_id(machine: &str)" in identity_owner
assert "fn bound_machine_id(install_root: &Path)" in identity_owner
# The first-use Administrator must NEVER run the SYSTEM-only journal
# primary-token gate; the dispatcher performs that check after enrolment.
identity_clean_prepare = identity_owner.split(
    "pub(super) fn prepare_clean_before_scm(", 1
)[1].split("pub(super) fn prepare(", 1)[0]
assert "require_windows_local_administrator_first_use()" in identity_clean_prepare
assert "verify_native_journal_protection(&" not in identity_clean_prepare
assert "start_type: ServiceStartType::OnDemand" in clean_install
assert '"/RU",\n            "SYSTEM",' in clean_install
assert '"/SC",\n            "MINUTE",' in clean_install
assert "verify_offline_bootstrap_dispatcher(&active.console_path, \"Ready\")?" in clean_install
assert "Get-ScheduledTask -ErrorAction Stop" in clean_install
assert 'Get-CimInstance -ClassName Win32_Service -Filter "Name=\'EdgePlatformController\'"' in clean_install
assert "HOST_WINDOWS_CLEAN_INSTALL_SCM_ALREADY_EXISTS" in clean_install
assert "HOST_WINDOWS_CLEAN_INSTALL_TASK_ABSENCE_UNPROVEN" in clean_install
assert '"/Create",' in clean_install and '"/RU",' in clean_install
assert '"/F",' not in clean_install
assert "windows_trust_enrollment::prepare_pending(install_root)?" in clean_install
assert "OFFLINE_BOOTSTRAP_ENROLL_BLOCKED" in install_script
assert '--enroll-receipt' in install_script
# No handwritten SHA / no duplicate downloader for the public Windows entry.
assert '[switch]$ConnectWindows' in install_script
assert 'WINDOWS_CONNECT_AWAITING_EXACT_PROTECTED_MAIN_RELEASE' in install_script
assert 'WINDOWS_CONNECT_RETAINED_BEGIN_REQUIRES_EXPLICIT_APPROVAL' in install_script
assert 'WINDOWS_CONNECT_IDENTITY_RESULT_UNKNOWN_NO_REPLAY' in install_script
assert "Assert-AcceptedReleaseAuthority -AcceptedRevision ([string]$branch.commit.sha) -Tag $tagName" in install_script
assert "BootstrapNow = $true" in install_script
assert "EnrollReceipt = $true" in install_script
assert "Offline = $true" in install_script
assert "$argsInitial = @{" in install_script
assert "$argsExact = @{" in install_script
assert "$argsExact['RetainedIntentSha256'] = $oldDigest" in install_script
assert "$argsExact['ExpectedCurrentReleaseSetSha256'] = [string]$installed['release_set_sha256']" in install_script
assert "$argsExact += @(" not in install_script
assert "if ($ApproveRetainedBegin)" in install_script
assert "HOST_WINDOWS_RECEIPT_ENROLL_TRUST_ALREADY_PRESENT" in identity_owner
# Operator supplies no manually copied Git/candidate hash: the exact signed
# installation itself owns both values, and immutable marker remains typed.
assert "OfflineReceiptIdentityPrepare(InstallRootArgs)" in Path("edge-platform/crates/edge-console/src/cli.rs").read_text(encoding="utf-8")
assert "OfflineHostTrustPrepare(InstallRootArgs)" in Path("edge-platform/crates/edge-console/src/cli.rs").read_text(encoding="utf-8")
assert "active.source_revision.clone()" in identity_owner
assert "active.release_set_sha256.clone()" in identity_owner
trust_owner = Path("edge-platform/crates/edge-console/src/windows_trust_enrollment.rs").read_text(encoding="utf-8")
assert "windows_trust_enrollment::dispatch_if_needed(install_root)" in win_console
assert '.map_err(|reason| format!("SYSTEM_TRUST: {reason}"))?' in win_console
assert "verify_native_journal_protection(&root.join(\"journal\"))" in trust_owner
assert 'pub(super) async fn dispatch_if_needed(install_root: &Path)' in trust_owner
assert 'verify_windows_signed_git_prerequisites(host)' in trust_owner
assert 'windows_signed_host::verify_system_trust(' in trust_owner
assert 'HOST_WINDOWS_TRUST_GITHUB_MAIN_RELEASE_TAG_NOT_EXACT' in trust_owner
assert 'create_new(true)' in trust_owner
assert '"/remove:g", "*S-1-5-32-544"' in trust_owner
assert 'HOST_WINDOWS_TRUST_RELEASE_ASSET_DIGEST_MISMATCH' in trust_owner
assert 'Command::OfflineHostTrustPrepare(_)' in win_console
assert 'verify_enrollment_marker(&marker_bytes, &active)' in trust_owner
assert 'complete_trust_marker(&root)?' in trust_owner
assert 'HOST_WINDOWS_TRUST_EXISTING_MISMATCH_NO_REPLAY' in trust_owner
assert 'HOST_WINDOWS_TRUST_ENROLL_COMPETING_REQUEST' in trust_owner
assert 'HOST_WINDOWS_TRUST_ENROLL_ALREADY_COMPLETED' in trust_owner
assert 'FleetWindowsTrustEnrollment::decode(bytes)' in trust_owner
assert "active.source_revision.clone()" in trust_owner
assert "active.release_set_sha256.clone()" in trust_owner
assert 'let protected_main = head["object"]["sha"].as_str();' in trust_owner
assert 'release["target_commitish"].as_str() != protected_main' in trust_owner

assert "worker_trust=NOT_ENROLLED" in identity_owner
assert "require_explicit_local_administrator_first_use()?;" in win_console
assert "require_windows_local_administrator_first_use()" in win_console
native_journal = Path("edge-platform/crates/edge-shared-types/src/host_journal.rs").read_text(encoding="utf-8")
# Historical P4 failure: a local elevated Administrator passed the explicit
# offline-bootstrap gate but two READ-ONLY pre-BEGIN observations accidentally
# demanded the SYSTEM token. The caller is not SYSTEM; prove the immutable
# journal path/ancestor ACL instead. This must NEVER weaken the SYSTEM-only
# journal executor, signed host owner, or protected identity files.
identity_pre_begin = identity_owner.split(
    "pub(super) fn verify_existing_receipt_identity_slot(", 1
)[1].split("// An explicit retained-BEGIN", 1)[0]
trust_pre_begin = trust_owner.split(
    "pub(super) fn preflight_pending_trust_handoff(", 1
)[1].split("/// Archive exact predecessor", 1)[0]
for pre_begin in (identity_pre_begin, trust_pre_begin):
    assert "require_windows_local_administrator_first_use()" in pre_begin
    assert re.search(
        r'verify_windows_protected_path_acl\(\s*&root\.join\("journal"\),\s*false,?\s*\)',
        pre_begin,
    )
    assert 'verify_native_journal_protection(' not in pre_begin
    assert 'fs::read(root.join(PRIVATE))' not in pre_begin
assert 'if install_root != Path::new(r"C:\\sing-box")' in trust_pre_begin
# The host's exact Win32 probe proved receipt-key.pk8 returns ACCESS_DENIED
# (5) for elevated Administrator, while public/COMPLETED/journal ACL GETs
# succeed. Only LocalSystem can attest PKCS8 and its DACL. Both P4 pre-BEGIN
# and post-activation call the SAME public-only verifier.
assert 'verify_existing_receipt_identity_public_files(&root, |path|' in identity_pre_begin
assert 'verify_sealed_private_metadata(&root.join(PRIVATE))?' in identity_pre_begin
assert 'for (name, max) in [(PUBLIC, 32), (COMPLETED, 512)]' in identity_pre_begin
assert 'verify_public_acl(&path)?;' in identity_pre_begin
assert 'fs::read(root.join(PUBLIC))' in identity_pre_begin
assert 'verify_windows_protected_path_acl(path, true)' in identity_pre_begin
assert 'verify_windows_protected_path_acl(&path, true)' not in identity_pre_begin
assert 'for name in [PRIVATE, PUBLIC, COMPLETED]' not in identity_pre_begin
assert 'fs::read(root.join(PRIVATE))' not in identity_pre_begin
assert 'GetNamedSecurityInfoW' not in identity_pre_begin
assert 'windows_p4_administrator_public_identity_never_reads_sealed_private_acl' in identity_owner
assert 'windows_p4_sealed_private_denies_acl_query_but_allows_public_preflight' in identity_owner
assert 'verify_native_journal_protection(&root.join("journal"))' in identity_owner
assert 'seal_system_private(&root)?' in identity_owner
assert 'existing_private_public(&root)?' in identity_owner
assert 'read_only_first_use_stage_for_offline_bootstrap(' in win_console
assert 'verify_existing_receipt_identity_slot(' in win_console
assert 'preflight_pending_trust_handoff(' in win_console
assert 'preflight_pending_trust_handoff(install_root, predecessor)?' in trust_owner
assert 'verify_native_journal_protection(&root.join("journal"))' in identity_owner
assert 'verify_native_journal_protection(&root.join("journal"))' in trust_owner
assert 'verify_native_journal_protection(&journal)' in win_system
assert 'HOST_WINDOWS_LOCALSYSTEM_REQUIRED' in native_journal
assert "pub fn require_windows_local_administrator_first_use()" in native_journal
# Win32 CheckTokenMembership requires an impersonation token, NOT the
# primary token returned by OpenProcessToken. Keep the exact process-user
# identity and UAC enabled-group gate: never substitute a NULL thread token.
assert "OpenProcessToken(" in native_journal
assert "TOKEN_QUERY | TOKEN_DUPLICATE" in native_journal
assert "DuplicateToken(primary, SecurityImpersonation, &mut impersonation)" in native_journal
assert "CheckTokenMembership(impersonation, admin_sid.as_mut_ptr().cast(), &mut enabled)" in native_journal
assert "CheckTokenMembership(token, admin_sid.as_mut_ptr().cast(), &mut enabled)" not in native_journal
assert "windows_process_primary_admin_member(token)?" in native_journal
assert "HOST_WINDOWS_FIRST_USE_ELEVATED_ADMIN_REQUIRED" in native_journal
assert "WinLocalSystemSid" in native_journal
assert "WinLocalServiceSid" in native_journal
assert "WinNetworkServiceSid" in native_journal
assert "Command::OfflineBootstrap(args) =>" in win_dispatch
assert "offline_bootstrap_privileged_release(" in win_dispatch
assert "supersession.as_ref()," in win_dispatch
assert "WindowsPrivilegedOperation::OfflineActivateRelease as i32" in win_dispatch
assert '"privileged-offline-activate",' in win_cli
assert "fn legacy_console_mutation_ingress_is_unparseable()" in win_cli
assert "HOST_WINDOWS_LEGACY_PRIVILEGED_MUTATION_DISABLED" in win_console
assert "require_offline_bootstrap_quiescent(install_root)?;" in win_console

# The previously deployed P4 executed the EXACT candidate console, but its
# read-only existing-identity classification still required the INSTALLED
# console. Preserve strict active binding for every ordinary command and
# every mutating trust/enrollment path; create one candidate-bound read-only
# pre-BEGIN exception, NOT an unrestricted relaxed identity checker.
assert "read_only_first_use_stage_for_offline_bootstrap(" in win_console
identity_read_start = identity_owner.index("pub(super) fn read_only_first_use_stage(")
identity_read_end = identity_owner.index("pub(super) fn checked_regular_exists(", identity_read_start)
identity_readers = identity_owner[identity_read_start:identity_read_end]
assert "require_exact_immutable_activation_console(install_root)?;" in identity_readers
assert "pub(super) fn read_only_first_use_stage_for_offline_bootstrap(" in identity_readers
assert "if &active != predecessor" in identity_readers
assert "require_offline_windows_owner(install_root, &active)?;" in identity_readers
assert "verify_windows_protected_path_acl(" in identity_readers
assert "require_exact_offline_bootstrap_reader_identity(" in identity_readers
assert "read_only_first_use_stage_from_installed(install_root, &active)" in identity_readers
assert "read_only_first_use_stage_from_installed(install_root, &active)" in identity_readers
assert "require_exact_immutable_activation_console(install_root)?;" in trust_owner
assert "require_exact_immutable_activation_console(install_root)?;" in identity_owner
# Only installed-to-candidate read observation, never command execution,
# pointer promotion, private-key read, task reenable or credential commit.
candidate_start = identity_owner.index("pub(super) fn read_only_first_use_stage_for_offline_bootstrap(")
candidate_end = identity_owner.index("fn read_only_first_use_stage_from_installed(", candidate_start)
candidate_reader = identity_owner[candidate_start:candidate_end]
for forbidden in ("change_offline_bootstrap_task_enabled(", "rebind_pending_trust_after_offline_handoff(",
                  "fs::remove_file(", ".create_new(", "promote_candidate(", "discard_candidate("):
    assert forbidden not in candidate_reader, forbidden

# The real W4 failure occurred BEFORE native owner handoff: the offline
# PowerShell StageOnly gate still required Ready, while Rust admitted exact
# Disabled+retained-BEGIN recovery. Both StageOnly and BootstrapNow must
# receive the same exact pinned old BEGIN and current-release pair; do not
# broaden task-state admission for ordinary or unpinned installations.
installer = Path("edge-platform/scripts/install-windows-release.ps1").read_text(encoding="utf-8")
assert '(-not $BootstrapNow -and -not $StageOnly)' in installer
assert "$disabledSuccessorProven = $false" in installer
assert "$hasRetained -and [string]$dispatch.State -ceq 'Disabled'" in installer
assert "(Get-FileHash -LiteralPath $retainedPath -Algorithm SHA256)" in installer
# A historical BEGIN is from -> to; installed can equal either endpoint
# after a compensated UNKNOWN, but a distinct new target must be neither.
assert "function Assert-DisabledOfflineSuccessorIdentity {" in installer
assert "($RetainedFrom -cne $InstalledRelease -and" in installer
assert "$RetainedTo -cne $InstalledRelease)" in installer
assert "$NextRelease -ceq $RetainedFrom" in installer
assert "$NextRelease -ceq $RetainedTo" in installer
assert "$NextRevision -ceq $RetainedRevision" in installer
assert "Assert-DisabledOfflineSuccessorIdentity `" in installer
assert "-RetainedFrom $retainedMatch.Groups['from'].Value" in installer
assert "-RetainedTo $retainedMatch.Groups['to'].Value" in installer
assert "-InstalledRelease ([string]$old['release_set_sha256'])" in installer
assert "-NextRelease $ReleaseSetSha256" in installer
assert "-NextRevision $AcceptedRevision" in installer
assert "(retained.from != installed_release && retained.to != installed_release)" in win_console
assert "|| retained.from == next_target" in win_console
assert "|| retained.to == next_target" in win_console
assert "([string]$dispatch.State -cne 'Ready' -and -not $disabledSuccessorProven)" in installer
assert 'if let Some(approval) = supersession {' in win_console
assert '.arg("-RetainedIntentSha256")' in win_console
assert '.arg(&approval.expected_intent_sha256)' in win_console
assert '.arg("-ExpectedCurrentReleaseSetSha256")' in win_console
assert '.arg(&approval.expected_current_release_set_sha256)' in win_console

# The elevated read-only diagnostic must use the SAME verified
# current owner, native doctor, task and no-replay gates as mutation pre-BEGIN.
# No staged installer, filesystem write, SCM operation or task state changes
# may appear in this exact helper. Output is local JSON boundary only.
assert "OfflineBootstrapPreflight(InstallRootArgs)" in win_cli
assert 'Self::OfflineBootstrapPreflight(_) => "offline-bootstrap-preflight"' in win_cli
assert "Command::OfflineBootstrapPreflight(args) =>" in win_dispatch
assert 'read_only_windows_first_use_source(&root, None, "", "")' in win_dispatch
assert '"w4_signer_and_receipt_enrollment": "NOT_PROVEN"' in win_dispatch
start = win_console.index("fn read_only_windows_first_use_source(")
end = win_console.index("fn offline_bootstrap_privileged_release(", start)
helper = win_console[start:end]
for gate in (
    "require_explicit_local_administrator_first_use()?;",
    "load_verified_activation(install_root)",
    "require_offline_windows_owner(install_root, &before)?;",
    "require_offline_bootstrap_exact_doctor(",
    'verify_offline_bootstrap_dispatcher(&before.console_path, "Ready")?;',
    "require_offline_bootstrap_quiescent(install_root)?;",
    "require_no_running_legacy_dispatcher(&before.console_path)?;",
):
    assert gate in helper, gate
for mutation in ("write_atomic(", "create_new(", "offline_activate_privileged_release_with_installer(",
                 "change_offline_bootstrap_task_enabled(", "retarget_privileged_task(",
                 "change_config(", "remove_file("):
    assert mutation not in helper, mutation
assert "let (before, previously_disabled) =" in win_console
assert "read_only_windows_first_use_source(install_root, supersession, revision, target)?;" in win_console
assert "require_distinct_offline_bootstrap_successor(" in helper
assert 'task.validate(&before.console_path, false)?;' in helper
assert "archive_retained_offline_bootstrap_intent(" in win_console
assert "retained_intent_sha256: Option<String>" in win_cli
assert "expected_current_release_set_sha256: Option<String>" in win_cli
assert '"offline-bootstrap-intent-v1.historical-{}"' in win_console
assert "require_offline_bootstrap_other_pending_absent(install_root)?;" in win_console
assert "fs::hard_link(&original, &archive)" in win_console
assert "fs::remove_file(&original)" in win_console
assert "require_no_historical_bootstrap_supersession(install_root)?;" in win_console
assert "historical supersession record exists; no replay" in win_console
assert "fs::rename(install_root.join(\"offline-bootstrap-intent-v1\"), &archive)" not in win_console
assert "OFFLINE_BOOTSTRAP_SUPERSESSION_INSTALLED_RELEASE_DRIFT" in win_console
assert "OFFLINE_BOOTSTRAP_SUPERSESSION_LEGACY_INTENT_SHA_MISMATCH" in win_console
assert "OFFLINE_BOOTSTRAP_SUPERSESSION_ARCHIVE_ALREADY_EXISTS_NO_REPLAY" in win_console

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


# Reconciliation runs within the existing protected ingress and has no root
# executor, separate transport, or speculative CREATE/replay capability.
abort = Path("edge-platform/scripts/host_first_use_abort.py").read_text(encoding="utf-8")
ast.parse(abort, filename="host_first_use_abort.py")
abort_job = router.split("  host_first_use_abort:\n", 1)[1].split("\n  host_resume_receipt:", 1)[0]
assert "needs.host.outputs.operation == 'FIRST_USE_ABORT_PREFLIGHT'" in abort_job
assert "group: vultr-control-plane-production" in abort_job
assert "first-use-preflight" in abort_job
assert 'host-abort-preflight.txt' in abort_job
assert "host_first_use_abort.py" in abort_job
assert abort_job.index("Classify pre-CREATE abort or existing VM, without mutation") < abort_job.index("Retire only exact aborted GitHub first-use reservation")
assert 'return "PROVEN_SKIPPED"' in abort
assert "HOST_ABORT_CREATE_FAILURE_NOT_PROVEN_PREPOST" in abort
assert 'return "PROVEN_NOT_ENTERED_PREPOST_FIREWALL"' in abort
assert "HOST_ABORT_RESERVED_REF_CONTENT_DRIFT" in abort
assert "HOST_ABORT_TERMINAL_EVIDENCE_AMBIGUOUS" in abort
assert abort.index("verify_original_run(machine, origin, old_revision, run_id)") < abort.index('method="POST", form=marker')
assert abort.index('method="POST", form=marker') < abort.index('method="DELETE"')
assert "HOST_ABORT_RUNNER_INVENTORY_INCOMPLETE" in abort
assert "host_first_use_finalize_resume.py" in router
assert "host_first_use_receipt_register.sh" in router
assert "host_first_use_receipt_register.sh" in router
assert "bootstrap-proof-check" in router
assert "HOST_FIRST_USE_RECOVERY=SIGNED_ROOT_PROOF_AND_SCRUB_PROVEN" in router
assert 'export REPOSITORY="${GITHUB_REPOSITORY}"' in router
assert 'export EDGE_RELEASE_CONTEXT_PATH="${OUTPUT_DIR}/resolved.env"' in router
assert "HOST_ABORT_FIREWALL_PREPOST_ERROR_NOT_PROVEN" in abort
# The initial Root proof is bound to the ORIGINAL release, but the receipt
# modifies current protected Git and must use CURRENT release provenance.
assert 'host-current-receipt-release' in router
assert router.count('GITHUB_SHA="${ORIGINAL_SHA}" "${bin}" host --hosts-pb "${fleet}"') >= 2
assert 'export ACCEPTED_REVISION="${GITHUB_SHA}"' in router
assert 'export HOST_RECEIPT_RELEASE_DIR="${OUTPUT_DIR}"' in router
assert 'export EDGE_RELEASE_CONTEXT_PATH="${OUTPUT_DIR}/resolved.env"' in router
assert "DenyLogRedirect" in abort
assert "read_job_log(job_id)" in abort
assert '"Authorization": "Bearer " + secret' in abort
assert "HOST_ABORT_JOB_LOG_SIGNED_LOCATION_INVALID" in abort
assert '43892f4c527b94b2d0cc07ff5bd95eaa56711115' in abort
assert 'create={create_phase}' in abort
first_use_source = provider.split("pub(crate) async fn host_first_use(", 1)[1].split("pub(crate) async fn host_first_use_scrub(", 1)[0]
assert "HOST_FIRST_USE_FIREWALL_BINDING_UNPROVEN" not in first_use_source
assert first_use_source.index("ensure_persistent_firewall_profile(") < first_use_source.index("apply_machine_with_firewall_profiles(")
assert 'host_replay_allowed=false' in abort

print("native_only_workflow_topology=PASS")
