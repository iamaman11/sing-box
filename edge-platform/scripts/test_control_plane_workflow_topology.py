#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
ROUTER = WORKFLOWS / "edge-control-plane.yml"
APPLICATION = WORKFLOWS / "vm-application-lifecycle.yml"
VULTR = WORKFLOWS / "vultr-lifecycle.yml"
WINDOWS_PHYSICAL = WORKFLOWS / "windows-physical.yml"
ZERO_TRUST = WORKFLOWS / "zero-trust-lifecycle.yml"
ZERO_TRUST_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/cloudflare_zero_trust_lifecycle_command.rs")
ZERO_TRUST_SERVICE = Path("edge-platform/crates/edge-orchestrator/src/cloudflare_zero_trust_lifecycle_service.rs")
ZERO_TRUST_CORE = Path("edge-platform/crates/edge-controller-core/src/cloudflare_zero_trust_lifecycle.rs")
CREDENTIALS = WORKFLOWS / "credential-lifecycle.yml"
VPC = WORKFLOWS / "vultr-vpc-lifecycle.yml"
DNS = WORKFLOWS / "cloudflare-dns-lifecycle.yml"
EDGE_PLATFORM_CI = WORKFLOWS / "edge-platform-ci.yml"
RUNTIME_INPUT = Path("edge-platform/scripts/runtime_input_digest.py")
WINDOWS_INPUT = Path("edge-platform/scripts/windows_input_digest.py")
WINDOWS_INSTALLER = Path("edge-platform/scripts/install-windows-release.ps1")
WINDOWS_RUNNER_BOOTSTRAP = Path("edge-platform/scripts/bootstrap-windows-runner.ps1")
WINDOWS_CONSOLE = Path("edge-platform/crates/edge-console/src/main.rs")
WINDOWS_CONSOLE_CLI = Path("edge-platform/crates/edge-console/src/cli.rs")
WINDOWS_CONTROLLER = Path("edge-platform/crates/edge-controller/src/main.rs")
WINDOWS_CONTROLLER_CLI = Path("edge-platform/crates/edge-controller/src/cli.rs")
WINDOWS_CONTROLLER_CORE = Path("edge-platform/crates/edge-controller-core/src/lib.rs")
EDGE_LOCAL_RUNTIME = Path("edge-platform/crates/edge-local-runtime/src/lib.rs")
VM_AGENT = Path("edge-platform/crates/edge-agent/src/main.rs")
VM_AGENT_CLI = Path("edge-platform/crates/edge-agent/src/cli.rs")
SHARED_TYPES = Path("edge-platform/crates/edge-shared-types/src/lib.rs")
PRODUCTION_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/production_command.rs")
CREDENTIAL_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs")
CREDENTIAL_CLI = Path("edge-platform/crates/edge-orchestrator/src/cli.rs")
CREDENTIAL_PROVIDER = Path("edge-platform/crates/edge-provider-cloudflare/src/lib.rs")
CREDENTIAL_SNAPSHOT = Path("edge-platform/crates/edge-orchestrator/src/credential_snapshot.rs")
CREDENTIAL_STORE = Path("edge-platform/crates/edge-secrets/src/credential_store.rs")
CREDENTIAL_PROTO = Path("edge-platform/proto/edge/platform/v1/credential_plane.proto")
RUNTIME_PROTO = Path("edge-platform/proto/edge/platform/v1/runtime.proto")
RELEASE_PROTO = Path("edge-platform/proto/edge/release/v1/release_set.proto")
WINDOWS_SINGBOX = Path("edge-platform/crates/edge-singbox/src/lib.rs")
WINDOWS_DIAGNOSTIC = Path("edge-platform/crates/edge-diagnostic/src/main.rs")
AGENT_PROTO = Path("edge-platform/proto/edge/platform/v1/agent.proto")
CONTROLLER_PROTO = Path("edge-platform/proto/edge/platform/v1/controller.proto")
PRODUCTION_INVENTORY = Path("edge-platform/crates/edge-orchestrator/src/cloudflare_production_inventory.rs")
ACCEPTANCE_COORDINATOR = Path("edge-platform/crates/edge-orchestrator/src/application_acceptance_command.rs")
VULTR_LIFECYCLE_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/vultr_lifecycle_command.rs")
PRODUCTION_VM_RUNNER_INSTALLER = Path("edge-platform/scripts/install-vultr-production-runner.sh")
ARCHITECTURE = Path("edge-platform/ARCHITECTURE.md")
README = Path("edge-platform/README.md")
RUNBOOK = Path("win/docs/RUNBOOK.md")
LOCAL_ARCHITECTURE = Path("win/docs/LOCAL-ARCHITECTURE.md")
SERVER_ARCHITECTURE = Path("win/docs/SERVER-ARCHITECTURE.md")
ROOT_README = Path("README.md")
LOCAL_AGENT_CONTRACT = Path("infra/LOCAL_AGENT_EXECUTION_CONTRACT.md")
APPLICATION_README = Path("infra/application/README.md")
VULTR_STACK_README = Path("win/vultr-waw/README.md")
PRODUCTION_DESIRED = Path("infra/production/production.textproto")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    router = ROUTER.read_text(encoding="utf-8")
    application = APPLICATION.read_text(encoding="utf-8")
    vultr = VULTR.read_text(encoding="utf-8")
    windows_physical = WINDOWS_PHYSICAL.read_text(encoding="utf-8")
    credentials = CREDENTIALS.read_text(encoding="utf-8")
    vpc = VPC.read_text(encoding="utf-8")
    edge_platform_ci = EDGE_PLATFORM_CI.read_text(encoding="utf-8")
    runtime_input = RUNTIME_INPUT.read_text(encoding="utf-8")
    windows_input = WINDOWS_INPUT.read_text(encoding="utf-8")
    windows_installer = WINDOWS_INSTALLER.read_text(encoding="utf-8")
    windows_runner_bootstrap = WINDOWS_RUNNER_BOOTSTRAP.read_text(encoding="utf-8")
    windows_console = WINDOWS_CONSOLE.read_text(encoding="utf-8")
    windows_console_cli = WINDOWS_CONSOLE_CLI.read_text(encoding="utf-8")
    windows_controller = WINDOWS_CONTROLLER.read_text(encoding="utf-8")
    windows_controller_runtime = windows_controller.split("#[cfg(test)]", 1)[0]
    windows_controller_cli = WINDOWS_CONTROLLER_CLI.read_text(encoding="utf-8")
    windows_controller_core = WINDOWS_CONTROLLER_CORE.read_text(encoding="utf-8")
    edge_local_runtime = EDGE_LOCAL_RUNTIME.read_text(encoding="utf-8")
    require(
        "Set-DnsClientServerAddress" not in edge_local_runtime
        and "restore_windows_dns_if_owned" not in windows_controller
        and "Clear-DnsClientCache" not in edge_local_runtime
        and "restore_windows_dns_if_owned" not in edge_local_runtime
        and "WINDOWS_OWNED_DNS_IPV4" not in edge_local_runtime,
        "local runtime must never reset foreign Cloudflare One Client DNS by resolver IP",
    )
    require(
        windows_console.count("require_exact_immutable_activation_console(&install_root)") == 5
        and windows_console.count("require_exact_immutable_activation_console(install_root)?;") == 4
        and "fn require_exact_immutable_activation_console(install_root: &Path)" in windows_console
        and "let expected = Path::new(&active.console_path)" in windows_console
        and "if running != expected {" in windows_console
        and "never invoke from the stable bin/edge-console.exe" in windows_console
        and windows_console.split("fn activate_privileged_release(", 1)[1].index(
            "require_exact_immutable_activation_console(install_root)?;"
        ) < windows_console.split("fn activate_privileged_release(", 1)[1].index(
            "stop_runtime_process(&local_singbox_config_path"
        ),
        "immutable console preflight must reject loaded stable EXE at CLI and dispatcher before stopping ManagedTun",
    )
    require(
        "fn supervise_windows_managed_child(repo_root: PathBuf)" in windows_controller
        and "fn reconcile_windows_child_exit(" in windows_controller
        and "WaitForSingleObject(handle, u32::MAX)" in windows_controller
        and 'std::thread::Builder::new()' in windows_controller
        and 'tokio::sync::oneshot::channel()' in windows_controller
        and "spawn_blocking(move || wait_for_windows_child_exit" not in windows_controller
        and "WINDOWS_RUNTIME_REPLACEMENT_GENERATION.fetch_add(1, Ordering::AcqRel)" in windows_controller
        and "exchange/requests/request.pb" in windows_controller
        and "destructive_windows_handoff_pending(repo_root)?" in windows_controller
        and "WindowsPrivilegedOperation::ActivateRelease" in windows_controller
        and "WindowsPrivilegedOperation::RestartControllerService" in windows_controller
        and "completed_result.as_deref() != prior_privileged_result" in windows_controller
        and "decode_windows_privileged_result(bytes)?" in windows_controller
        and "decode_windows_activation_state(&activation_bytes)?" in windows_controller
        and "if executable != expected {" in windows_controller
        and "WINDOWS_RUNTIME_OWNER_GATE" in windows_controller
        and "one-shot native child recovery budget exhausted" in windows_controller
        and "write_controller_service_error(&supervisor_root, \"child_exit\", &err)" in windows_controller
        and "WINDOWS_SERVICE_STOP_REQUESTED.store(true, Ordering::Release)" in windows_controller,
        "SCM child exit response must use kernel event, exact single owner, durable handoff and bounded one-shot recovery without polling",
    )
    # Native SCM safety cannot depend on the GitHub workflow barrier:
    # Windows AutoStart and kernel-event child recovery invoke Rust directly.
    native_gate = "require_native_windows_runtime_launch_safety"
    require(
        native_gate in windows_controller
        and "NATIVE_MANAGED_TUN_PREAUTH_BLOCKED" in windows_controller
        and "WindowsStartupDecision::BlockedUnprovenLine1" in windows_controller
        and "native_managed_tun_requires_real_pre_tun_authentication_on_every_start"
            in windows_controller
        and "require_native_windows_route_capture_safety(mode)?;" in windows_controller
        and "WindowsDatapathMode::ManagedTun => Err(" in windows_controller
        and "require_native_windows_runtime_launch_safety(repo_root)?;" in windows_controller
        and "require_native_windows_runtime_launch_safety(&self.repo_root)" in windows_controller
        and windows_controller.count("require_native_windows_runtime_launch_safety(&self.repo_root)") == 2
        and windows_controller.index(
            "require_native_windows_runtime_launch_safety(repo_root)?;"
        ) < windows_controller.index(
            'map_err(|err| format!("one-shot native child recovery failed: {err}"))?'
        )
        and windows_controller.index(
            "require_native_windows_runtime_launch_safety(&self.repo_root)"
        ) < windows_controller.index(
            "WINDOWS_RUNTIME_REPLACEMENT_GENERATION.fetch_add(1, Ordering::AcqRel);",
            windows_controller.index("async fn restart_local_runtime("),
        ),
        "SCM boot, orphan restarts, child-event recovery and both RPC launch paths must fail closed before ManagedTun route capture",
    )

    # The service-entry failure handler must not undo the fail-closed
    # preflight by cleaning up a process inherited from an older owner.
    require(
        "fn failed_windows_scm_start_owns_child(" in windows_controller
        and "fn stop_only_owned_child_after_failed_scm_start(" in windows_controller
        and "failed_scm_start_cleanup_is_exact_single_child_of_current_owner_only"
            in windows_controller
        and "exact_children.len() == 1" in windows_controller
        and "exact_children[0].parent_pid == Some(scm_pid)" in windows_controller
        and windows_controller.count(
            "stop_only_owned_child_after_failed_scm_start(&config.repo_root);"
        ) == 3
        and "let _ = stop_runtime_process(&default_local_config_path(&config.repo_root), true);"
            not in windows_controller,
        "SCM failure cleanup must only stop a unique child owned by the current service",
    )

    # P0 interrupted offline handoff: no dropping a failed previous.pb read,
    # no decoding a possibly torn current.pb before restoring verified bytes.
    offline_restore_start = windows_console.index("fn restore_offline_release(")
    offline_restore_end = windows_console.index(
        "fn offline_activate_privileged_release(", offline_restore_start
    )
    offline_restore = windows_console[offline_restore_start:offline_restore_end]
    require(
        "fn snapshot_offline_previous(" in windows_console
        and "Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None)"
            in windows_console
        and "OFFLINE_PREVIOUS_SNAPSHOT_BLOCKED" in windows_console
        and "let previous_bytes = snapshot_offline_previous(&previous_path)?;"
            in windows_console
        and "load_verified_activation_path(install_root, &previous_path, \"previous.pb\")"
            in windows_console
        and "fs::read(install_root.join(\"previous.pb\")).ok()"
            not in windows_console.split("fn offline_activate_privileged_release(", 1)[1].split(
                "fn offline_rollback_privileged_release(", 1
            )[0]
        and "fn restore_offline_authority_pointers(" in windows_console
        and "restore_offline_authority_pointers(install_root, current_bytes, previous_bytes)?;"
            in offline_restore
        and "load_verified_activation(install_root)" not in offline_restore
        and "require_offline_windows_owner_from_snapshot(install_root, before)" in offline_restore
        and "offline_retarget_controller_service_checked(" in offline_restore
        and "fn require_offline_windows_owner_from_snapshot(" in windows_console
        and "create_new(true)" in windows_console
        and "offline-recovery-proof.pb" in windows_console
        and "OFFLINE_PREVIOUS_RESTORE_BLOCKED" in windows_console
        and "offline_pointer_restore_uses_verified_saved_bytes_even_when_current_torn"
            in windows_console
        and "offline_pointer_restore_never_deletes_unknown_previous_or_replays_current"
            in windows_console
        and "offline_pointer_restore_blocks_unreadable_previous_before_current_rewrite"
            in windows_console,
        "offline restore must remain fail-closed against torn current authority, unreadable prior rollback, and mismatched SCM owner",
    )

    # Offline mutation is a NEW wire contract, not a reinterpretation of the
    # existing ActuateRelease opcode supported by the installed dispatcher.
    require(
        "WINDOWS_PRIVILEGED_OPERATION_OFFLINE_ACTIVATE_RELEASE = 12;"
            in RUNTIME_PROTO.read_text(encoding="utf-8")
        and "WINDOWS_PRIVILEGED_OPERATION_OFFLINE_ROLLBACK_PREVIOUS_RELEASE = 13;"
            in RUNTIME_PROTO.read_text(encoding="utf-8")
        and "PrivilegedOfflineActivate" in windows_console_cli
        and "PrivilegedOfflineRollbackPrevious" in windows_console_cli
        and "WindowsPrivilegedOperation::OfflineActivateRelease" in windows_console
        and "WindowsPrivilegedOperation::OfflineRollbackPreviousRelease" in windows_console
        and "fn offline_activate_privileged_release(" in windows_console
        and "fn offline_rollback_privileged_release(" in windows_console
        and "fn require_offline_windows_owner(" in windows_console
        and "fn offline_retarget_controller_service(" in windows_console
        and "OFFLINE_HANDOFF_BLOCKED" in windows_console
        and "offline_handoff_gate(" in windows_console
        and "require_offline_windows_owner(install_root, &before)?;" in windows_console
        and "require_offline_windows_owner(install_root, &current)?;" in windows_console
        and "fn restore_offline_release(" in windows_console
        and "offline_release_handoff_refuses_running_scm_any_child_tun_or_wrong_owner"
            in windows_console
        and "offline_release_operations_have_dedicated_wire_numbers"
            in windows_console
        and "if require_offline_windows_owner_from_snapshot(install_root, before).is_err()"
            in windows_console
        and "offline_retarget_controller_service(install_root, &before, &post)" in windows_console
        and "retarget_privileged_task(install_root, &post.console_path)" in windows_console
        and "-Offline" in windows_console
        and "[switch]$Offline" in windows_installer
        and windows_installer.count("Assert-OfflineWindow") == 3
        and "Get-CimInstance -ClassName Win32_Service" not in windows_installer
        and "Get-CimInstance -ClassName Win32_Process" in windows_installer
        and "Get-NetAdapter -Name 'sing-box-tun'" in windows_installer
        and "Stop-Service" not in windows_installer
        and "Start-Service" not in windows_installer
        and "Set-DnsClientServerAddress" not in windows_installer
        and "privileged-offline-activate" not in router
        and "privileged-offline-rollback-previous" not in router
        and "offline mutation is not routed until the installed SYSTEM bootstrap can dispatch it"
            not in router,
        "offline install and rollback must be bounded typed SYSTEM operations and not bypass the existing protected issue router",
    )

    # The protected issue operator has a separate exact-command allowlist.
    require(
        "github.event.comment.body == '/windows offline-preflight'" in router
        and "github.event.comment.body == '/windows diagnose'" in router
        and "uses: ./.github/workflows/windows-physical.yml" in router,
        "new offline preflight must be reachable through the sole protected GitHub issue control",
    )

    # Offline handoff preflight uses only already installed native privilege
    # evidence; it cannot pretend that old dispatch supports new operations.
    require(
        '"/windows offline-preflight") operation="diagnose"; readonly_purpose="offline-preflight" ;;'
            in windows_physical
        and "readonly_purpose: ${{ steps.auth.outputs.readonly_purpose }}" in windows_physical
        and "EDGE_READONLY_PURPOSE: ${{ needs.resolve.outputs.readonly_purpose }}" in windows_physical
        and "if ($env:EDGE_READONLY_PURPOSE -ceq 'offline-preflight')" in windows_physical
        and "offline_preflight_observation=PASS" in windows_physical
        and "offline_privileged_task_readonly=PASS" in windows_physical
        and "offline_zero_runtime_owners=PASS" in windows_physical
        and "privileged-runtime-evidence --install-root $root" in windows_physical
        and "process_classification=ABSENT;process_evidence_complete=true;process_count=0;"
            in windows_physical
        and "Get-CimInstance -ClassName Win32_Service" in windows_physical
        and "offline_native_activation=NOT_EXECUTED_READ_ONLY_PREFLIGHT"
            in windows_physical
        and "offline_command_advertised=$offlineCommandAdvertised" in windows_physical
        and "installedCommands = @(& $console --help)" in windows_physical
        and "offline_mutations_performed=0" in windows_physical
        and windows_physical.count("      - name: Execute typed lifecycle mutation") == 1,
        "offline preflight must observe exact stopped owner and old privileged task without installation or TUN capture",
    )

    # A human-stopped Windows controller is an observable degraded state,
    # not a reason for read-only diagnosis to run ManagedTun lifecycle checks.
    read_only_step = "      - name: Observe safe Windows state (read-only)"
    prestate_step = "      - name: Assert isolated root and observe pre-state"
    require(
        windows_physical.count(read_only_step) == 1
        and windows_physical.count(prestate_step) == 1,
        "stopped-owner diagnosis must remain a single native read-only observation",
    )
    read_only = windows_physical.split(read_only_step, 1)[1].split(prestate_step, 1)[0]
    require(
        "if: ${{ needs.resolve.outputs.operation == 'diagnose' }}" in read_only
        and "Assert-Doctor $a" in read_only
        and "Assert-Doctor $b" in read_only
        and "observation_status=PASS" in read_only
        and "desired_state_status=$desired" in read_only
        and "DEGRADED_STOPPED" in read_only
        and "BLOCKED_STOPPED_OWNER_AUTOSTART" in read_only
        and "independent_no_tun_dns_control_recovery=UNPROVEN" in read_only
        and "Get-NetRoute -AddressFamily IPv4" in read_only
        and "Resolve-DnsName www.gstatic.com" in read_only
        and "curl.exe --noproxy '*'" in read_only
        and "GetFileSystemEntries" in read_only
        and not any(
            action in read_only
            for action in (
                "Set-Service", "Start-Service", "Stop-Service",
                "privileged-activate", "privileged-rollback-previous",
                "start-local", "stop-local", "Set-DnsClientServerAddress",
                "Set-NetRoute", "New-NetRoute", "sc.exe", "taskkill.exe",
            )
        ),
        "diagnose must check actual stopped owner and direct network without mutation",
    )
    for name in (
        prestate_step,
        "      - name: Verify exact authority and SCM handoff",
        "      - name: Final diagnostics and transport-only boundary",
    ):
        prefix = windows_physical.split(name, 1)[1].split("\n        shell:", 1)[0]
        require(
            "if: ${{ needs.resolve.outputs.operation != 'diagnose' }}" in prefix,
            f"{name} must not apply ManagedTun lifecycle assertions to read-only diagnose",
        )
    require(
        "if: ${{ always() && needs.resolve.outputs.operation != 'diagnose' }}" in windows_physical
        and "if: ${{ needs.resolve.outputs.operation != 'diagnose' && needs.resolve.outputs.operation != 'quality-line1' }}" in windows_physical,
        "diagnose must bypass privileged post-mutation assertions and any lifecycle mutation",
    )

    # A previous successful TUN cutover on the deleted VM never authorizes
    # an unauthenticated restart on the rebuilt server. This pre-mutation
    # policy has to be upstream of every native activation, not a warning.
    pre_mutation = windows_physical.split(
        "      - name: Assert isolated root and observe pre-state", 1
    )[1].split("      - name: Execute typed lifecycle mutation", 1)[0]
    require(
        "PRE_MUTATION_MANAGED_TUN_PREAUTH_BLOCKED" in pre_mutation
        and "[string]$values['scm_state'] -cne 'Running'" in pre_mutation
        and "[int]$values['managed_singbox_process_count'] -ne 1" in pre_mutation
        and "$currentTun -cne 'true'" in pre_mutation
        and "independent no-TUN DNS/control restoration are UNPROVEN" in pre_mutation
        and "Write-Warning 'Recovering a partial ManagedTun activation" not in windows_physical
        and "EDGE_BEFORE_PARTIAL_MANAGED_TUN" not in windows_physical
        and "privileged-activate" not in pre_mutation
        and "      - name: Execute typed lifecycle mutation" in windows_physical,
        "stopped or partial ManagedTun must fail closed before any route-capturing lifecycle mutation",
    )

    # Cloudflare One observation is allowed only inside existing read-only diagnose.
    foreign_marker = "      - name: Observe Cloudflare One effective client state (read-only)"
    require(windows_physical.count(foreign_marker) == 1, "foreign observation must not create duplicate owners")
    foreign_observation = windows_physical.split(foreign_marker, 1)[1].split(
        "      - name: Publish bounded lifecycle evidence", 1
    )[0]
    require(
        "if: ${{ needs.resolve.outputs.operation == 'diagnose' }}" in foreign_observation
        and "Read-CloudflareClient 'status'" in foreign_observation
        and "Read-CloudflareClient 'settings'" in foreign_observation
        and "cloudflare_one_effective_mode=$mode" in foreign_observation
        and "cloudflare_one_split_tunnel_mode=$split" in foreign_observation
        and "cloudflare_one_profile_id_sha256=$profileHash" in foreign_observation
        and "cloudflare_one_dns_writer=UNKNOWN" in foreign_observation
        and "cloudflare_one_no_tun_recovery=UNPROVEN" in foreign_observation
        and "Write-Host $settings.value" not in foreign_observation
        and "Write-Host $status.value" not in foreign_observation
        and "Set-DnsClientServerAddress" not in foreign_observation
        and "Clear-DnsClientCache" not in foreign_observation
        and "warp-diag" not in foreign_observation
        and "warp-cli connect" not in foreign_observation
        and "warp-cli disconnect" not in foreign_observation
        and "Set-NetRoute" not in foreign_observation,
        "foreign Cloudflare One diagnostic must be nonsecret and read-only",
    )
    vm_agent = VM_AGENT.read_text(encoding="utf-8")
    vm_agent_cli = VM_AGENT_CLI.read_text(encoding="utf-8")
    shared_types = SHARED_TYPES.read_text(encoding="utf-8")
    vm_agent_runtime = vm_agent.split("#[cfg(test)]", 1)[0]
    initial_bundle = vm_agent_runtime.split("async fn run_local_bundle_stage_initial(", 1)[1].split(
        "async fn run_local_bundle_converge(", 1
    )[0]
    require(
        "BundleStageInitial" in vm_agent_cli
        and "run_local_bundle_stage_initial(&stack_dir).await" in vm_agent_runtime
        and "validate_digest_bound_bundle_request(&request)" in initial_bundle
        and "stage_initial_vm_policy_bundle(stack_dir, request)" in initial_bundle
        and "validate_initial_policy_bundle_request(&request)" in vm_agent_runtime
        and "require_empty_vm_initial_credential_host(stack_dir)" in vm_agent_runtime
        and "require_empty_vm_initial_bundle_host(stack_dir)" in vm_agent_runtime
        and "require_no_vm_application_containers(&docker)" in vm_agent_runtime
        and "apply_digest_bound_bundle(stack_dir, request, true)" in vm_agent_runtime
        and "application_runtime_started=false" in initial_bundle
        and "credential_authentication=UNPROVEN" in initial_bundle
        and "initial_policy_only: bool" in vm_agent_runtime
        and "materialize_vm_owned_runtime_environment(&staging)?" in vm_agent_runtime,
        "fresh policy-only bundle staging must be exact, single-owner, and never start runtime",
    )
    cloudflare_native_provider = Path(
        "edge-platform/crates/edge-provider-cloudflare/src/lib.rs"
    ).read_text(encoding="utf-8")
    credential_delivery_client = Path(
        "edge-platform/crates/edge-secrets/src/credential_delivery.rs"
    ).read_text(encoding="utf-8")
    credential_provider = Path(
        "edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs"
    ).read_text(encoding="utf-8")
    require(
        "CredentialInitialProbe" in vm_agent_cli
        and "verify_canonical_dummy_ab_slots(" in vm_agent_runtime
        and "credential_slot_A=EXACT_DUMMY" in vm_agent_runtime
        and "credential_slot_B=EXACT_DUMMY" in vm_agent_runtime
        and "credential_provider_mutations=0" in vm_agent_runtime
        and "credential_runtime_mutations=0" in vm_agent_runtime
        and "CREDENTIAL_DUMMY_PROBE_GENERATION_A" in credential_provider
        and "CREDENTIAL_DUMMY_PROBE_GENERATION_B" in credential_provider
        and "observe_fixed_dummy_binding(" in credential_delivery_client
        and "/v1/proof-slot?generation=" in credential_delivery_client
        and "StatusCode::NO_CONTENT" in credential_delivery_client
        and "StatusCode::CONFLICT" in credential_delivery_client
        and "crypto.subtle.digest" in credential_provider
        and "bindings_inherit=strict" in cloudflare_native_provider
        and "upload_worker_slot_proof_version(" in cloudflare_native_provider
        and '"type": "inherit"' in cloudflare_native_provider
        and '"/v1/proof-slot"' in credential_provider
        and 'sha256_hex(&slots[0].payload)' in credential_provider
        and "previous_fixed_ab_version_tag(" in credential_provider
        and "ProjectionDeliveryState::FixedAbProofUpgradeRequired" in credential_provider
        and "slot_A={}; slot_B={}" in credential_delivery_client
        and "publication_authorized=false" in credential_delivery_client
        and "DummySlotObservation::MissingOrOtherGeneration" in credential_delivery_client
        and "DummySlotObservation::Noncanonical" in credential_delivery_client
        and "if bundle.dummy_non_secret && !allow_dummy_probe" in credential_delivery_client,
        "fresh credential A/B proof must be authenticated, projection-bound, exact dummy only and read-only",
    )
    require(
        "CredentialInitialProbe(InstallRootArgs)" in windows_console_cli
        and "run_windows_initial_credential_probe(Path::new(&args.install_root))" in windows_console
        and "verify_canonical_dummy_ab_slots(" in windows_console
        and "CredentialProjectionKind::Windows" in windows_console
        and "initial_windows_credential_eligibility(" in windows_console
        and "credential_provider_mutations=0" in windows_console
        and "windows_dns_mutations=0" in windows_console
        and "windows_tun_mutations=0" in windows_console,
        "Windows initial proof must use its own exact Access projection without touching TUN or DNS",
    )
    require(
        "initial-pair-preflight" in credentials
        and 'needs.authorize.outputs.operation == \'initial-pair-preflight\'' in credentials
        and "INITIAL_GENERATION" in credentials
        and "INITIAL_SLOT" in credentials
        and "credentials initial-pair-preflight" in credentials
        and "initial_pair_provider_intent_sha256=" in credentials
        and "grep -Eq '^initial_pair_provider_intent_sha256=[0-9a-f]{64}$'" in credentials
        and "[0-9a-f]{64}[$]" not in credentials
        and "test" in credentials
        and "grep -Fxq 'credential_provider_mutations=0'" in credentials
        and "credentials initial-pair-publish" not in credentials
        and "initial_pair_provider_intent_sha256={provider_intent_sha256}" in credential_provider
        and "release_context.release().source_revision.clone()" in credential_provider
        and "release_context.release().release_set_sha256.clone()" in credential_provider
        and 'required_env("EDGE_RELEASE_SET_SHA256")' not in credential_provider
        and "run_delivery(command, release_context)"
        in Path("edge-platform/crates/edge-orchestrator/src/main.rs").read_text(encoding="utf-8")
        and "initial_pair_provider_intent_sha256(" in credential_provider
        and 'credential-initial-pair-provider-intent/v1' in credential_provider
        and "credentials initial-pair-journal-observe" in credentials
        and "gh api --paginate" in credentials
        and "issues: read" not in credentials
        and "credential_initial_journal_empty=true" in credentials
        and "credential_journal_mutations=0" in credentials
        and "require_empty_initial_history(&history)?" in credential_provider
        and "return run_readonly_journal(command);" in credential_provider
        and credential_provider.index("return run_readonly_journal(command);")
            < credential_provider.index('required_env("CLOUDFLARE_CONTROL_TOKEN")?')
        and "verify_recorded_initial_attempt(&history, &exact)?" in credential_provider
        and "initial_publication_authorized=false" in credential_provider
        and "initial_publication_authorized=false" in credential_provider
        and "initial_pair_preflight(&control_token" in credential_provider
        and "validate_initial_pair_provider_observation(" in credential_provider,
        "hosted initial provider gate must stay read-only and fail closed until both host attestations",
    )
    # Execute the actual GNU grep matcher, not just a substring assertion.
    # A previous passing CI hid a literal-dollar suffix regression.
    exact_digest_regex = re.search(
        r"grep -Eq '(\^initial_pair_provider_intent_sha256=\[0-9a-f\]\{64\}\$)'",
        credentials,
    )
    require(
        exact_digest_regex is not None,
        "initial pair preflight must use an exact-line 64-digit digest matcher",
    )
    valid_digest = "initial_pair_provider_intent_sha256=" + ("a" * 64)
    invalid_digests = (
        "initial_pair_provider_intent_sha256=" + ("a" * 63),
        "initial_pair_provider_intent_sha256=" + ("a" * 65),
        "initial_pair_provider_intent_sha256=" + ("A" * 64),
        valid_digest + "$",
        valid_digest + "tail",
        "other_initial_pair_provider_intent_sha256=" + ("a" * 64),
    )
    for line, expected in ((valid_digest, True), *((item, False) for item in invalid_digests)):
        outcome = subprocess.run(
            ["grep", "-Eq", exact_digest_regex.group(1)],
            input=line + "\n",
            text=True,
            capture_output=True,
            check=False,
        )
        require(
            (outcome.returncode == 0) == expected,
            "initial pair digest shell validator accepted malformed evidence or rejected valid evidence",
        )
    require(
        'if operation in {"rotate-application", "host-bootstrap-converge"}:' in credentials
        and 'os.environ.get("GITHUB_RUN_ATTEMPT") != "1"' in credentials
        and "credential mutation replay forbidden: read-only reconciliation required" in credentials,
        "GitHub credential mutation must fail closed before host preparation on a run re-attempt",
    )
    publish_slot = credential_provider.split(
        "async fn publish_rotation_slot(", 1
    )[1].split("pub(crate) async fn verify_credential_plane_invariant(", 1)[0]
    require(
        publish_slot.count("cloudflare::patch_latest_worker_version_secrets(") == 1
        and publish_slot.count("cloudflare::deploy_worker_version(") == 1
        and "LATEST_VERSION_CHANGED_CONTENT_UNPROVEN" in publish_slot
        and "stop without replay or deploy" in publish_slot
        and "stop without replay;" in publish_slot,
        "ambiguous Cloudflare PATCH/deploy may only reconcile read-only, never retry a mutation",
    )
    vm_initial_functional = vm_agent_runtime.split(
        "async fn verify_initial_vm_credential_functional(", 1
    )[1].split("async fn initial_apply_vm_credential(", 1)[0]
    require(
        re.search(r"CredentialInitialVerify\s*\{\s*generation:\s*u64,?\s*\}", vm_agent_cli) is not None
        and "verify_initial_vm_credential_functional(&stack_dir, generation)" in vm_agent_runtime
        and "validate_unpromoted_vm_initial_state(&state, generation)?" in vm_initial_functional
        and "verify_vm_candidate_runtime_materialized(stack_dir, &bundle)?" in vm_initial_functional
        and "read_exact_image_environment(stack_dir)?" in vm_initial_functional
        and "docker.container_exact_image_ready(name, expected_image)"
        in vm_initial_functional
        and "line2_quality::measure(stack_dir, read_typed_runtime_environment)?"
        in vm_initial_functional
        and "if after_state != state {" in vm_initial_functional
        and vm_initial_functional.count("verify_vm_candidate_runtime_materialized(stack_dir, &bundle)?") == 2
        and "promote_candidate" not in vm_initial_functional
        and "line2_authenticated_endpoints=6" in vm_agent_runtime
        and "line2_egress_identity=UNPROVEN" in vm_agent_runtime
        and "external_tls_chain=UNPROVEN" in vm_agent_runtime
        and "line1_authenticated_endpoints=UNPROVEN" in vm_agent_runtime
        and "CredentialInitialAttest" in vm_agent_cli
        and "attest_initial_vm_host(" in vm_agent_runtime
        and "verify_initial_vm_selected_dummy_probe(stack_dir, slot).await?" in vm_agent_runtime
        and "selected_slot_exact_dummy: true" in vm_agent_runtime
        and "slot_a_observation: proof.slot_a_observation.to_owned()" in vm_agent_runtime
        and "slot_b_observation: proof.slot_b_observation.to_owned()" in vm_agent_runtime
        and "first_use_host_attestation_sha256(" in vm_agent_runtime
        and "expected_agent_sha256" in vm_agent_cli
        and "verify_initial_agent_binary(expected_agent_sha256)?" in vm_agent_runtime
        and "async fn verify_initial_credential_host(" in vm_agent_runtime
        and "request: Request<InitialCredentialHostProbeRequest>" in vm_agent_runtime
        and "credential_exact_agent_binary=true" in vm_agent_runtime
        and "file_sha256_lower_hex(" in vm_agent_runtime
        and 'Path::new("/proc/self/exe")' in vm_agent_runtime
        and "CredentialInitialAttest" in windows_console_cli
        and "require_initial_windows_credential_host(root)" in windows_console
        and "verify_initial_selected_dummy_slot(" in windows_console
        and "credential_selected_slot_exact_dummy=true" in windows_console
        and "first_use_host_attestation_sha256(" in windows_console
        and "windows_tun_mutations=0" in windows_console
        and "windows_dns_mutations=0" in windows_console
        and "credential_pair_committed=false" in vm_agent_runtime,
        "initial VM functional proof must bind exact unpromoted candidate and six real Line2 probes without claiming Line1",
    )
    # The canonical GitHub operation must reach the native disposable
    # policy owner rather than leaving another unused Rust CLI capability.
    require(
        "INITIAL_VM_INSTALL_BLOCKED_PRE_MUTATION" not in vultr
        and 'operation = "initial-vm-install"' in vultr
        and 'initial_acceptance_final:' in vultr
        and 'N1_N2_PHYSICAL_ACCEPTANCE=PASS' in vultr
        and 'if tokens == ["/vultr", "initial-vm-install"]:' in vultr
        and 'spec_path = "infra/vultr/application-acceptance.json"' in vultr
        and 'machine_id = "application-acceptance-1"' in vultr
        and 'run_lifecycle initial-policy-stage' in vultr
        and 'run_lifecycle apply "${spec}" "${machine}" "${authority}"' in vultr
        and 'converge_host_substrate "${spec}" "${machine}" "initial-vm-install"' in vultr
        and '(. [0].class == "CREATE"' not in vultr
        and '(.[0].class == "CREATE" or .[0].class == "NOOP")' in vultr
        and 'machine_class="$(jq -er' in vultr
        and 'existing_owned_count=' in vultr
        and 'REUSED_OWNED' in vultr
        and "echo 'first_use_create_confirmed=false'" in vultr
        and '.ownership.logical_id == "application-acceptance-1"' in vultr
        and 'initial-dns-converge' in vultr
        and "needs: authorize" in vultr
        and '"${bin}" application-lifecycle materialize' in vultr
        and 'runtime_credentials == "ABSENT"' in vultr
        and 'application_containers == "NOT_STARTED"' in vultr,
        "one GitHub initial VM install must CREATE or reuse exact owned NOOP and invoke immutable policy owner",
    )
    # A clean VM must receive only the existing dedicated Cloudflare host
    # identity (never an application credential) through the same exact owner.
    # The SSH lease, root-only file, and first-attempt guard are one operation.
    vultr_lifecycle_command = VULTR_LIFECYCLE_COMMAND.read_text(encoding="utf-8")
    require(
        'if operation in {"initial-vm-install", "initial-acceptance-resume"} and os.environ.get("GITHUB_RUN_ATTEMPT") != "1":' in vultr
        and 'acquire_host_access "${spec}" "${machine}" "initial-vm-install"' in vultr
        and 'release_host_access "${spec}" "${machine}" "initial-vm-install"' in vultr
        and "vm_access_identity_installed == true" in vultr
        and "vm_access_identity_owner == \"ROOT_0600\"" in vultr
        and 'operation: "INITIAL_VM_INSTALL"' in vultr
        and 'status: "STAGED_NOT_ACCEPTED"' in vultr
        and 'external_line1: "UNPROVEN"' in vultr
        and 'external_line2: "UNPROVEN"' in vultr
        and "secrets.CLOUDFLARE_VM_ACCESS_CLIENT_ID" in vultr
        and "secrets.CLOUDFLARE_VM_ACCESS_CLIENT_SECRET" in vultr
        and "fn initial_vm_access_identity_payload(" in vultr_lifecycle_command
        and "strict_ssh_run_stdin(" in vultr_lifecycle_command
        and "initial VM Access write outcome uncertain; do not repeat" in vultr_lifecycle_command
        and "validate_initial_vm_existing_identity(" in vultr_lifecycle_command
        and "initial VM Access identity scope is unknown; do not replay or overwrite" in vultr_lifecycle_command
        and "existing VM Access identity differs from authorized escrow; no replay" in vultr_lifecycle_command
        and "vm_access_identity_state" in vultr_lifecycle_command
        and "needs: [authorize, initial_windows_isolate]" in vultr
        and "needs.initial_windows_isolate.result == 'success'" in vultr
        and "vm_access_identity_owner" in vultr_lifecycle_command
        and "CREDENTIAL_INITIAL_HOST_PROBE" in vultr_lifecycle_command,
        "first-use must either stage exact root-only VM Access identity once or re-attest existing bytes without replay",
    )
    require(
        "group: credential-transaction-${{ github.repository_id }}" in vultr
        and "group: credential-transaction-${{ github.repository_id }}" in credentials
        and "group: credential-transaction-${{ github.repository_id }}" in application
        and "cancel-in-progress: false" in vultr,
        "Vultr and credential workflows must share one non-cancelling initial-pair transaction lock",
    )
    # CI must validate the *actual public network* reachability contract.
    # Docker port publication is not enough if Vultr blocks the packet.
    acceptance_firewalls = json.loads(
        Path("infra/vultr/firewall-profiles.json").read_text(encoding="utf-8")
    )
    profile = next(
        item for item in acceptance_firewalls["profiles"]
        if item["name"] == "application-acceptance"
    )
    external = {
        (item["protocol"], int(item["port"]))
        for item in profile["rules"]
        if item["subnet"] == "0.0.0.0" and item["subnet_size"] == 0
    }
    required = {
        ("tcp", 80), ("tcp", 443), ("tcp", 5443),
        ("udp", 8443), ("udp", 9444),
        ("tcp", 4128), ("tcp", 4080), ("tcp", 4443),
        ("tcp", 3128), ("tcp", 1080), ("tcp", 9443),
    }
    require(
        external == required
        and all(item["ip_type"] == "v4" for item in profile["rules"]),
        "disposable VM firewall must expose exact 4 Line1 + 6 Line2 remote ports and ACME HTTP",
    )

    # A substring-only test missed a real YAML defect: a consumer at column
    # zero is NOT a GitHub workflow job. Keep first-use owners under jobs:.
    require(
        all(
            re.search(r"(?m)^  " + re.escape(name) + r":\s*$", vultr)
            for name in (
                "initial_preflight", "initial_vm_attest",
                "initial_windows_attest", "initial_pair_publish",
                "initial_vm_runtime", "initial_windows_consume",
                "initial_acceptance_verdict", "initial_cleanup", "initial_reboot",
            )
        )
        and not re.search(r"(?m)^initial_(?:preflight|vm_attest|windows_attest|pair_publish|vm_runtime|windows_consume):", vultr),
        "all first-use jobs must be children of the reusable workflow jobs mapping",
    )

    # Full first-use cleanup is owned by the existing disposable application
    # cleanup orchestrator, not a second VM-only destroy or fallback executor.
    # It runs even when external acceptance fails after VM creation and its
    # outcome must be an independent zero-leak certificate, never inferred.
    first_use_cleanup = vultr.split("\n  initial_cleanup:\n", 1)
    require(
        len(first_use_cleanup) == 2
        and 'needs: [authorize, execute, initial_acceptance_verdict]' in first_use_cleanup[1]
        and 'always() &&' in first_use_cleanup[1]
        and "needs.execute.result != 'skipped'" in first_use_cleanup[1]
        and "needs.execute.outputs.first_use_create_confirmed == 'true'"
            in first_use_cleanup[1]
        and "first_use_provider_mutation_attempted: ${{ steps.execute_lifecycle.outputs.first_use_provider_mutation_attempted }}" in vultr
        and "first_use_create_confirmed: ${{ steps.execute_lifecycle.outputs.first_use_create_confirmed }}" in vultr
        and 'echo \'first_use_create_confirmed=true\' >> "${GITHUB_OUTPUT}"' in vultr
        and 'echo \'first_use_provider_mutation_attempted=true\' >> "${GITHUB_OUTPUT}"' in vultr
        and "id: execute_lifecycle" in vultr
        and 'group: vultr-control-plane-production' in first_use_cleanup[1]
        and 'application-cleanup \\' in first_use_cleanup[1]
        and '.zero_leaked_resources == "PASS"' in first_use_cleanup[1]
        and '.terminal_stage == "complete"' in first_use_cleanup[1]
        and "N1_N2_DISPOSABLE_ZERO_LEAK_CLEANUP=PASS" in first_use_cleanup[1]
        and 'infra/cloudflare/application-acceptance-dns.json' in first_use_cleanup[1]
        and 'infra/vultr/application-acceptance-vpc.json' in first_use_cleanup[1]
        and 'miu.alegria.by' in first_use_cleanup[1]
        and '"${EDGE_APPLICATION_ORCHESTRATOR}" application-cleanup' in first_use_cleanup[1]
        and 'destroy-apply' not in first_use_cleanup[1]
        and 'vultr-lifecycle cleanup' not in first_use_cleanup[1],
        "first-use MUST run one exact existing native disposable cleanup after terminal verdict and require zero-leak certificate",
    )

    # Reboot must be a SINGLE native provider action and its recovery proof
    # must be a READ-ONLY candidate observation with the same durable BEGIN.
    reboot_job_parts = vultr.split("\n  initial_reboot:\n", 1)
    require(
        len(reboot_job_parts) == 2
        and 'needs: [authorize, initial_preflight, initial_vm_runtime, initial_windows_consume, initial_line2_external]'
            in reboot_job_parts[1]
        and 'vultr-lifecycle action-plan infra/vultr/application-acceptance.json application-acceptance-1 reboot'
            in reboot_job_parts[1]
        and 'vultr-lifecycle action infra/vultr/application-acceptance.json application-acceptance-1 reboot'
            in reboot_job_parts[1]
        and '.reboot_observation.boot_id_changed == true' in reboot_job_parts[1]
        and 'vultr-lifecycle substrate-verify infra/vultr/application-acceptance.json application-acceptance-1'
            in reboot_job_parts[1]
        and 'vultr-lifecycle initial-runtime-verify' in reboot_job_parts[1]
        and 'vultr-lifecycle initial-runtime-apply' not in reboot_job_parts[1]
        and 'N1_N2_POST_REBOOT_VM_LOCAL_LINE2=PASS' in reboot_job_parts[1]
        and "initial_reboot" in vultr.split("  initial_acceptance_verdict:", 1)[1].split("  initial_cleanup:", 1)[0]
        and 'authorize_initial_runtime_job(' in vultr_lifecycle_command
        and '(!apply && matches!(job, "initial_vm_runtime" | "initial_reboot"))'
            in vultr_lifecycle_command
        and 'initial_reboot_can_only_reobserve_not_reapply_credentials' in vultr_lifecycle_command,
        "one-shot disposable reboot must prove real boot-ID change and same-candidate read-only recovery",
    )

    # A staging CA certificate cannot pass independent public TLS trust.
    # Disposable real network acceptance uses a separate hostname and DNS,
    # never the permanent production hostname, but needs a trusted ACME issuer.
    disposable_policy = json.loads(
        Path("infra/application/disposable-acceptance.json").read_text(encoding="utf-8")
    )
    require(
        disposable_policy["runtime_policy"]["line1"]["acme_provider"] == "letsencrypt"
        and disposable_policy["runtime_policy"]["line1"]["tunnel_domain"]
            == "stage2-acceptance.alegria.by",
        "disposable real external TLS acceptance must use public-trust ACME on isolated DNS",
    )

    # The installed SCM endpoint differs from the CLI's development fallback.
    # Never hardcode either port in the first-use workflow: the *verified*
    # immutable console resolves its own installed controller identity.
    console_source = WINDOWS_CONSOLE.read_text(encoding="utf-8")
    shared_types = Path(
        "edge-platform/crates/edge-shared-types/src/lib.rs"
    ).read_text(encoding="utf-8")
    require(
        'WINDOWS_CONTROLLER_ENDPOINT' in shared_types
        and 'return WINDOWS_CONTROLLER_ENDPOINT;' in console_source
        and vultr.count('& $console credential-state') == 0
        and 'credential-initial-acceptance-stage' in vultr
        and 'credential-initial-line1-witness' in vultr
        and 'credential-state http://' not in vultr
        and 'credential-state https://' not in vultr,
        "first-use Windows acceptance must not depend on the serving SCM endpoint or a hardcoded port",
    )

    # VM diagnostics must distinguish exactly rendered first-use candidate from
    # active generation, while never declaring container credential provenance
    # based on .env.runtime equality or green Docker readiness alone.
    vm_owner = Path("edge-platform/crates/edge-agent/src/main.rs").read_text(encoding="utf-8")
    require(
        'VmRenderedCredentialSource::V2Candidate' in vm_owner
        and 'credential_rendered_source=V2_CANDIDATE_RENDERED' in vm_owner
        and 'credential_lifecycle_verdict=STAGED_FIRST_USE_NOT_CUT_OVER' in vm_owner
        and 'credential_running_source=UNPROVEN_WITHOUT_CONTAINER_RELOAD_PROOF' in vm_owner
        and 'application_operational_verdict=' in vm_owner
        and 'fn first_use_candidate_rendered_is_proven_on_disk_but_not_active_or_running()' in vm_owner
        and 'fn rotated_candidate_does_not_override_active_render_authority()' in vm_owner,
        "VM diagnosis must make first-use cursor/rendered/loaded credential boundaries explicit",
    )

    # First-use Line1 must distinguish UDP from TCP on the same physical run,
    # not stop after the first QUIC timeout and misreport remaining endpoints.
    line1_witness = Path(
        "edge-platform/crates/edge-console/src/initial_line1_witness.rs"
    ).read_text(encoding="utf-8")
    require(
        'let ips = probe_all_endpoints(|i, tag|' in line1_witness
        and 'line1_probe_failure={reason}' in line1_witness
        and 'Line1 external NOT_ACCEPTED: {failures}/4 endpoints failed' in line1_witness
        and 'proxy_connect={connect}' in line1_witness
        and 'proxy_connect=000' in line1_witness
        and 'connect == "200"' in line1_witness
        and 'fn bounded_witness_checks_all_four_even_if_first_times_out()' in line1_witness,
        "Line1 witness must test all four external endpoints and classify safe CONNECT/timeout evidence",
    )

    # Locale-independent Windows ACLs, and an authenticated failed
    # materialization step before any recovery of an empty unmarked root.
    windows_first_use_reconcile = Path(
        "edge-platform/scripts/reconcile-windows-first-use.ps1"
    ).read_text(encoding="utf-8")
    require(
        "'*S-1-5-18:(OI)(CI)F'" in vultr
        and "'*S-1-5-32-544:(OI)(CI)F'" in vultr
        and "'Administrators:(OI)(CI)F'" not in vultr
        and "'SYSTEM:(OI)(CI)F'" not in vultr
        and "initial_windows_cleanup:" in vultr
        and " -RemoveOwned -RecoverEmptyPreMarker" in vultr
        and "premarker_authorized:" in windows_physical
        and "id: source" in windows_physical
        and 'Materialize isolated release from accepted immutable ReleaseSet' in windows_physical
        and "PREMARKER_AUTHORIZED" in windows_physical
        and " -RecoverEmptyPreMarker" in windows_physical
        and "RecoverEmptyPreMarker" in windows_first_use_reconcile
        and "FIRST_USE_PREMARKER_UNKNOWN: unmarked directory is not empty" in windows_first_use_reconcile
        and "FIRST_USE_PREMARKER_UNKNOWN: unmarked directory owner is foreign" in windows_first_use_reconcile
        and "[IO.Directory]::Delete($root, $false)" in windows_first_use_reconcile
        and "FIRST_USE_SERVING_OWNER_CHANGED" in windows_first_use_reconcile
        and "FIRST_USE_RUNTIME_BUSY" in windows_first_use_reconcile,
        "Windows acceptance requires locale-free ACL SIDs and fail-closed empty premarker recovery",
    )

    # Every independent VM first-use job which acquires a support-access
    # lease must export Docker/containerd/Compose versions from the already
    # authenticated ReleaseSet. Otherwise the first one may pass, then later
    # runtime/reboot jobs fail with the same missing Rust environment input.
    for step, following in [
        ("initial_vm_attest", "initial_windows_access_issue"),
        ("initial_vm_runtime", "initial_line2_external"),
        ("initial_reboot", "initial_acceptance_final"),
    ]:
        scoped_owner = vultr.split(f"  {step}:\n", 1)[1].split(
            f"\n  {following}:", 1
        )[0]
        require(
            'source "${OUTPUT_DIR}/resolved.env"' in scoped_owner
            and 'test -n "${EDGE_DOCKER_ENGINE_VERSION}"' in scoped_owner
            and 'test -n "${EDGE_CONTAINERD_VERSION}"' in scoped_owner
            and 'test -n "${EDGE_COMPOSE_VERSION}"' in scoped_owner
            and "export EDGE_DOCKER_ENGINE_VERSION EDGE_CONTAINERD_VERSION EDGE_COMPOSE_VERSION" in scoped_owner
            and '"${owner}" vultr-lifecycle lease-acquire' in scoped_owner,
            f"{step} must pass all three immutable ReleaseSet substrate versions before typed support-access lease",
        )

    # Read-only Windows observation is independent of the current release
    # resolver. Mutation and offline handoff still require ReleaseSet authority.
    require(
        "if: (steps.auth.outputs.operation != 'diagnose' && steps.auth.outputs.operation != 'quality-line1') || steps.auth.outputs.readonly_purpose == 'offline-preflight'"
        in windows_physical
        and "if ($env:EDGE_OPERATION -in @('converge','repair') -and" in windows_physical
        and "line1_quality_source=INSTALLED_VERIFIED_RELEASE" in windows_physical
        and "Line1 quality requires the exact accepted installed ReleaseSet" not in windows_physical
        and '".github/workflows/vultr-acceptance-resume.yml"' in edge_platform_ci,
        "read-only diagnostics must use installed verified binaries without a new release",
    )

    resume = (WORKFLOWS / "vultr-acceptance-resume.yml").read_text(encoding="utf-8")

    # PowerShell 7 must preserve all four bounded stdout observations even if
    # the immutable native witness returns nonzero. Never replay on failure.
    require(
        resume.count('$PSNativeCommandUseErrorActionPreference = $false') == 2
        and resume.count('try {\n            $raw=@(& $console credential-initial-line1-witness') == 2
        and resume.count('$witnessExit=$LASTEXITCODE') == 2
        and resume.count('line1_(endpoint|probe_failure)') == 2
        and resume.count('if ($witnessExit -ne 0) { throw') == 2
        and resume.count('$PSNativeCommandUseErrorActionPreference = $true') == 3,
        "Line1 witness failure must print bounded four-endpoint evidence before failing",
    )

    # The acceptance VM has its own independently attested address and TLS
    # hostname. Never use production DNS to target that VM's credentials.
    witness_cli = Path(
        "edge-platform/crates/edge-console/src/cli.rs"
    ).read_text(encoding="utf-8")
    witness_impl = Path(
        "edge-platform/crates/edge-console/src/initial_line1_witness.rs"
    ).read_text(encoding="utf-8")
    witness_secrets = Path(
        "edge-platform/crates/edge-secrets/src/runtime.rs"
    ).read_text(encoding="utf-8")
    require(
        "CredentialInitialLine1Witness(AttestedLine1WitnessArgs)" in witness_cli
        and "pub target_ipv4: std::net::Ipv4Addr" in witness_cli
        and "windows_runtime_state_from_attested_vm_bundle" in witness_impl
        and "windows_runtime_state_from_canonical_production_bundle(&bundle)" not in witness_impl
        and "windows_runtime_state_from_target_bundle(bundle, Some((target_ip, target_domain)))" in witness_secrets
        and "needs: [source, access, vm]" in resume
        and "needs: [source, vm, windows, reboot]" in resume
        and resume.count("--target-ipv4 $env:TARGET_IPV4 --target-domain $env:TARGET_DOMAIN") == 2
        and "needs.vm.outputs.ip" in resume
        and "needs.vm.outputs.domain" in resume
        and "initial_line2_external.outputs.vm_ipv4" in vultr
        and "initial_line2_external.outputs.tls_domain" in vultr
        and "--target-ipv4 $env:TARGET_IPV4 --target-domain $env:TARGET_DOMAIN" in vultr,
        "isolated Line1 must use the exact VM attested IP and hostname, never production DNS",
    )

    # The only legal continuation after one irreversible paired Worker BEGIN
    # is a source-run-bound read-only acceptance. A distinct resume command
    # must never fall through to generic VM execute, republish credentials,
    # or create a second Windows privileged task / SCM owner.
    require(
        '"/vultr", "initial-acceptance-resume"' in vultr
        and "initial-acceptance-resume'" in vultr
        and "resume_source_run_id:" in vultr
        and "uses: ./.github/workflows/vultr-acceptance-resume.yml" in vultr
        and "needs.authorize.outputs.operation != 'initial-acceptance-resume'" in vultr
        and 'source_run_id:' in resume
        and 'sing-box-credential-initial-attempt/v1' in resume
        and 'sing-box-initial-resume-reboot/v1' in resume
        and "resolve_durable_release.sh" in resume
        # The original issued generation stays immutable, while current binary
        # authority is independently resolved from the protected main commit.
        and "control_accepted: ${{ steps.proof.outputs.control_accepted }}" in resume
        and "control_release: ${{ steps.proof.outputs.control_release }}" in resume
        and 'git fetch -q --no-tags --depth=1 origin "$GITHUB_SHA"' in resume
        and 'unset EXPECTED_RELEASE_TAG\n          # The original BEGIN is only evidence, never the current resolver input.\n          export ACCEPTED_REVISION="$GITHUB_SHA"\n          export OUTPUT_DIR=' in resume
        and resume.count('export ACCEPTED_REVISION="$GITHUB_SHA"') == 1
        and 'test "$EDGE_ACCEPTED_REVISION" = "$GITHUB_SHA"' in resume
        and resume.count("ACCEPTED_REVISION: ${{ needs.source.outputs.control_accepted }}") == 2
        and resume.count("SOURCE_RELEASE: ${{ needs.source.outputs.control_release }}") == 3
        and resume.count('export EXPECTED_RELEASE_TAG="edge-release-$CONTROL_RELEASE"') == 2
        and resume.count('test "$EDGE_RELEASE_SET_SHA256" = "$CONTROL_RELEASE"') == 2
        and "-ArchivedAcceptanceSourceRunId ([UInt64]$env:GENERATION)" not in resume
        and 'N1_N2_ORIGINAL_PAIRED_CREDENTIALS_REUSED_NO_REPLAY=PASS' in resume
        and "initial-pair-publish" not in resume
        and "initial-runtime-apply" not in resume
        and "credential-transition validate-candidate" not in resume
        and "privileged-dispatch" not in resume
        and "credential-initial-line1-witness" in resume
        and "credential-initial-acceptance-stage" in resume
        and "initial-line2-external-witness" in resume
        and "line1_external_4_of_4=PASS" in resume
        and "line2_external_6_of_6=PASS" in resume
        and "reboot_observation.boot_id_changed==true" in resume
        and "initial-windows-acceptance-cleanup" in resume
        and "reconcile-windows-first-use.ps1" in resume
        and "N1_N2_ACCEPTANCE=PASS" in resume
        and "ARCHIVED_ACCEPTANCE_BLOCKED" in windows_installer
        and "ArchivedAcceptanceSourceRunId" in windows_installer
        and "if ($ArchivedAcceptanceSourceRunId -lt 10000000)" in windows_installer
        and "C:\\sing-box-acceptance" in windows_installer,
        "initial resume must reuse exact first-use publication, prove external 10/10 and one reboot, and reject serving privilege",
    )

    # Single first-use request: new VM, two independent host owners, one
    # durable BEGIN, paired Workers and the native VM runtime, no replay.
    initial_flow = vultr.split("  initial_preflight:", 1)[1]
    require(
        'if tokens == ["/vultr", "initial-vm-install"]:' in vultr
        and 'initial_vm_attest:' in initial_flow
        and 'initial_windows_attest:' in initial_flow
        and 'initial_windows_isolate:' in vultr
        and 'initial_windows_cleanup:' in initial_flow
        and 'C:\\sing-box-acceptance' in vultr
        and 'WINDOWS_SERVING_INSTALL_ROOT=UNTOUCHED' in vultr
        and 'initial_pair_publish:' in initial_flow
        and 'initial_vm_runtime:' in initial_flow
        and 'initial_windows_consume:' in initial_flow
        and 'needs: [authorize, initial_preflight, initial_windows_attest, initial_pair_publish, initial_line2_external]' in initial_flow
        and 'credential-initial-acceptance-stage' in initial_flow
        and 'credential-initial-line1-witness' in initial_flow
        and 'credential-transition validate-candidate' not in initial_flow
        and 'The isolated Windows root deliberately has NO privileged SCM/task' in initial_flow
        and 'The native isolated witness below performs exact candidate readback' in initial_flow
        and 'credential-initial-line1-witness' in initial_flow
        and 'First-use isolated Windows credential cursor already exists' in initial_flow
        and 'FIRST_USE_WINDOWS_ISOLATION_BLOCKED:' in initial_flow
        and 'FIRST_USE_WINDOWS_ISOLATION_CHANGED:' in initial_flow
        and initial_flow.count("['windows_datapath_mode'] -cne 'ProxyOnly'") == 2
        and 'N2_EXTERNAL_LINE1_4_OF_4=PASS' in initial_flow
        and 'WINDOWS_ACTIVE_CREDENTIAL_PROMOTION=NOT_PERFORMED' in initial_flow
        and 'needs: [authorize, execute, initial_preflight]' in initial_flow
        and 'needs: [authorize, initial_windows_attest]' not in vultr
        and "needs.initial_windows_attest.result == 'success'" not in vultr
        and 'needs: [authorize, initial_windows_isolate]' in vultr
        and 'needs: [authorize, initial_preflight, initial_vm_attest, initial_windows_attest, initial_windows_access_issue]' in initial_flow
        and "always() &&" in vultr
        and 'needs: [authorize, initial_preflight, initial_vm_attest, initial_windows_attest, initial_windows_access_issue]' in initial_flow
        and 'needs: [authorize, initial_preflight, initial_pair_publish]' in initial_flow
        and 'credential-initial-attest' in initial_flow
        and 'name: Bind first-use Cloudflare version intent\n    needs: [authorize, initial_worker_proof_upgrade]' in vultr
        and 'initial_worker_proof_upgrade:' in vultr
        and 'credentials initial-worker-proof-plan' in vultr
        and 'credentials initial-worker-proof-upgrade' in vultr
        and 'worker_proof_durable_begin=EXACT_READBACK' in vultr
        and 'worker_secret_patch_mutations=0' in vultr
        and 'credential_selected_slot_exact_dummy == true' in initial_flow
        and '.credential_slot_B == "EXACT_CANONICAL_DUMMY"' in initial_flow
        and 'name: Attest isolated Windows host without TUN or DNS mutation\n    needs: [authorize, initial_preflight, initial_windows_isolate]' in vultr
        and 'vultr-lifecycle initial-host-probe' in initial_flow
        and 'credentials initial-pair-journal-plan' in initial_flow
        and 'credentials initial-pair-journal-readback' in initial_flow
        and 'credentials initial-pair-publish' in initial_flow
        and 'gh api --method POST "repos/${REPOSITORY}/issues/26/comments"' in initial_flow
        and vultr.count('issues: write') == 3
        and 'resume_acceptance:' in vultr
        and 'uses: ./.github/workflows/vultr-acceptance-resume.yml' in vultr
        and 'actions: read' in vultr
        and "needs: [authorize, initial_worker_proof_upgrade]" in vultr
        and 'GITHUB_RUN_ATTEMPT' in initial_flow
        and 'vultr-lifecycle initial-runtime-apply' in initial_flow
        and 'vultr-lifecycle initial-runtime-verify' in initial_flow
        and 'all(.vm_local_line2[]; .successful_samples == 5 and .failed_samples == 0 and .negative_auth_rejected == true)' in initial_flow
        and 'vultr-lifecycle initial-dns-converge' not in initial_flow
        and 'run_lifecycle initial-dns-converge' in vultr
        and 'INITIAL_VM_DNS_CONVERGE' in vultr
        and 'REUSED_OWNED' in vultr
        and 'machine_class=' in vultr
        and 'REUSED_OWNED' in vultr
        and 'first_use_create_confirmed=true' in vultr
        and 'first_use_create_confirmed=true' not in vultr.split('NOOP)')[1].split('CREATE)')[0]
        and 'infra/cloudflare/application-acceptance-dns.json' in vultr
        and 'INITIAL_VM_DNS_CONVERGE' in vultr
        and 'provider_mutation_replay_allowed == false' in vultr
        and 'N2_EXTERNAL_TEN_ENDPOINTS=UNPROVEN' in initial_flow
        and 'initial_acceptance_verdict:' in initial_flow
        and 'N1_N2_PRE_CLEANUP_TRAFFIC=PASS' in initial_flow
        and 'N1_N2_PHYSICAL_ACCEPTANCE=PASS' in initial_flow
        and 'initial_line2_external:' in initial_flow
        and 'initial_windows_post_reboot:' in initial_flow
        and 'initial_acceptance_final:' in initial_flow
        and "needs: [authorize, execute, initial_acceptance_verdict, initial_windows_cleanup, initial_windows_access_cleanup, initial_cleanup]" in initial_flow
        and 'initial_windows_access_issue:' in initial_flow
        and 'initial_windows_access_cleanup:' in initial_flow
        and 'credentials initial-windows-acceptance-issue' in initial_flow
        and 'credentials initial-windows-acceptance-cleanup' in initial_flow
        and 'WINDOWS_ACCESS_CLEANUP' in initial_flow
        and 'CLOUDFLARE_WINDOWS_ACCEPTANCE_CLIENT_SECRET' in initial_flow
        and 'EDGE_INITIAL_WINDOWS_ACCEPTANCE_TOKEN_ID' in initial_flow
        and 'WINDOWS_ACCEPTANCE_ACCESS_REVOKE=PASS' in initial_flow
        and 'line2_external_6_of_6=PASS' in initial_flow
        and 'N2_POST_REBOOT_EXTERNAL_LINE2_6_OF_6=PASS' in initial_flow
        and 'N2_POST_REBOOT_EXTERNAL_LINE1_4_OF_4=PASS' in initial_flow
        and 'WINDOWS_SERVING_INSTALL_ROOT=UNTOUCHED' in initial_flow
        and 'FIRST_USE_CREATE_CONFIRMED' in initial_flow
        and 'N1_N2_REUSED_OWNED_VM=PRESERVED_NOT_DISPOSED' in initial_flow
        and 'initial_publication_authorized=false' in initial_flow
        and 'windows_tun_mutations' in initial_flow
        and 'windows_dns_mutations' in initial_flow,
        "single initial install must bind release and both host attestations to durable BEGIN before paired publication",
    )

    require(
        'acceptance_create_or_reuse as converge_initial_disposable_dns' in vultr_lifecycle_command
        and 'converge_initial_disposable_dns(Path::new(&args[0]), Path::new(&args[1])).await?' in vultr_lifecycle_command
        and '"initial-dns-converge" => run_initial_dns_converge' in vultr_lifecycle_command
        and '"provider_mutations": if outcome == "CREATED" { 1 } else { 0 }' in vultr_lifecycle_command
        and 'INITIAL_VM_DNS_CONVERGE' in vultr
        and '.outcome == "REUSED_OWNED" and .provider_mutations == 0' in vultr,
        "initial VM DNS must use one exact CREATE-or-NOOP native owner with no foreign update or replay",
    )

    # RPC and local bundle paths must reject the retired unbound / host-file
    # write path rather than silently writing to arbitrary host roots.
    bundle_entrypoint = vm_agent_runtime.rsplit("fn apply_bundle(", 1)[1].split(
        "fn validate_digest_bound_bundle_request(", 1
    )[0]
    require(
        "validate_digest_bound_bundle_request(&request)?" in bundle_entrypoint
        and "apply_digest_bound_bundle(stack_dir, request, false)" in bundle_entrypoint
        and "apply_legacy_bundle" not in vm_agent_runtime
        and "fn application_rpc_refuses_legacy_bundle_and_host_file_writes()" in vm_agent,
        "all application bundle transports must reject legacy unbound host writes",
    )
    # First-use policy stage is the only pre-credential installation path.
    agent_proto = AGENT_PROTO.read_text(encoding="utf-8")
    vultr_lifecycle_command = VULTR_LIFECYCLE_COMMAND.read_text(encoding="utf-8")
    application_policy_service = Path(
        "edge-platform/crates/edge-orchestrator/src/application_lifecycle_service.rs"
    ).read_text(encoding="utf-8")
    application_policy_command = Path(
        "edge-platform/crates/edge-orchestrator/src/application_lifecycle_command.rs"
    ).read_text(encoding="utf-8")
    require(
        "rpc StageInitialPolicyBundle(ApplyBundleRequest)" in agent_proto
        and "async fn stage_initial_policy_bundle(" in vm_agent_runtime
        and "stage_initial_vm_policy_bundle(&self.stack_dir, request.into_inner())" in vm_agent_runtime
        and "async fn stage_initial_vm_policy_bundle(" in vm_agent_runtime
        and "require_no_vm_application_containers(&docker)?" in vm_agent_runtime
        and "stage_initial_application_policy(" in application_policy_service
        and "stage_initial_policy_bundle(Request::new(prepared.request.clone()))"
            in application_policy_service
        and "initial policy stage RPC has uncertain outcome; no mutation replay"
            in application_policy_service
        and "acceptance_stage_initial_policy(" in application_policy_command
        and '"initial-policy-stage" => run_initial_policy_stage' in vultr_lifecycle_command
        and "validate_disposable_acceptance(&desired)?" in vultr_lifecycle_command
        and "application_containers" in vultr_lifecycle_command
        and "runtime_credentials" in vultr_lifecycle_command,
        "initial disposable VM stage must install exact policy only through one restricted native owner",
    )
    # Docker substrate state must be independently observed, even when the
    # application bundle has never been staged onto a new VM.
    vm_inspect = vm_agent_runtime.split(
        "async fn inspect_runtime(", 1
    )[1].split("fn inspect_bundle_artifacts(", 1)[0]
    require(
        vm_inspect.index("let docker = observe_docker()")
        < vm_inspect.index("let Some(compose) =")
        and vm_inspect.index("state.docker_reachable = docker.reachable")
        < vm_inspect.index("let Some(compose) ="),
        "VM diagnostics must observe Docker substrate before any Compose-missing early return",
    )
    # Public Clap command is a separate authorization boundary from the
    # Rust dispatch. A missing Clap variant passed CI in PR #366 but failed
    # the real /vultr owner-upgrade before host mutation.
    vultr_cli = Path("edge-platform/crates/edge-orchestrator/src/cli.rs").read_text(
        encoding="utf-8"
    )
    require(
        "OwnerUpgrade(VultrOwnerUpgradeArgs)" in vultr_cli
        and "OwnerRollback(VultrOwnerRollbackArgs)" in vultr_cli
        and 'Self::OwnerUpgrade(args) => vec![' in vultr_cli
        and 'Self::OwnerRollback(args) => vec![' in vultr_cli
        and "fn owner_transition_workflow_commands_reach_exact_public_clap_dispatch()" in vultr_cli
        and vultr.index('"${bin}" vultr-lifecycle owner-upgrade --help >/dev/null') < vultr.index('acquire_host_access "${spec}" "${machine}" "owner-upgrade"')
        and vultr.index('"${bin}" vultr-lifecycle owner-rollback --help >/dev/null') < vultr.index('acquire_host_access "${spec}" "${machine}" "owner-rollback"'),
        "VM owner transitions must parse through actual orchestrator Clap CLI before access lease",
    )

    # First trusted VM owner upgrade must never bootstrap/re-register the runner,
    # republish credentials, mutate Docker, or accept a blind replay after an
    # uncertain SSH acknowledgement. All target IDs come from Git inventory.
    vm_owner_upgrade = Path(
        "edge-platform/crates/edge-orchestrator/src/vm_owner_upgrade.rs"
    ).read_text(encoding="utf-8")
    require(
        '"owner-upgrade" => vm_owner_upgrade::run(&args[1..], context).await'
            in vultr_lifecycle_command
        and 'mod vm_owner_upgrade;' in vultr_lifecycle_command
        and '"owner-rollback" => vm_owner_upgrade::rollback(&args[1..], context).await' in vultr_lifecycle_command
        and 'elif verb == "owner-rollback" and len(tokens) == 6:' in vultr
        and 'run_lifecycle owner-rollback "${spec}" "${machine}" "${OWNER_CURRENT_SHA}" "${OWNER_PREVIOUS_SHA}"' in vultr
        and 'bound_rollback_preflight(&current, &args[2], &previous, &args[3], &journal)?;' in vm_owner_upgrade
        and 'sudo -n ln {OWNER} {FAILED}' in vm_owner_upgrade
        and 'sudo -n mv -T {PREVIOUS} {OWNER}' in vm_owner_upgrade
        and 'elif verb == "owner-upgrade" and len(tokens) == 5:' in vultr
        and 'OWNER_PREVIOUS_SHA: ${{ needs.authorize.outputs.owner_previous_sha }}' in vultr
        and 'run_lifecycle owner-upgrade "${spec}" "${machine}" "${EDGE_LIFECYCLE_AGENT}" "${OWNER_PREVIOUS_SHA}"'
            in vultr
        and 'test "${GITHUB_RUN_ATTEMPT}" = "1"' in vultr
        and 'acquire_host_access "${spec}" "${machine}" "owner-upgrade"' in vultr
        and 'release_host_access "${spec}" "${machine}" "owner-upgrade"' in vultr
        and 'context.validate_application_artifact(&expected, Path::new(&args[2]))?;'
            in vm_owner_upgrade
        and 'exact_existing_machine_observation(&desired, &args[1]).await?'
            in vm_owner_upgrade
        and 'bound_upgrade_preflight(&current, &args[3], &expected.sha256)?'
            in vm_owner_upgrade
        and 'durable_nonreplay_begin' in vm_owner_upgrade
        and 'sudo -n ln {OWNER} {PREVIOUS}' in vm_owner_upgrade
        and 'sudo -n mv -T {NEXT} {OWNER}' in vm_owner_upgrade
        and 'let boot_before = capture("cat /proc/sys/kernel/random/boot_id")?;' in vm_owner_upgrade
        and 'runner_mutations": 0' in vm_owner_upgrade
        and 'container_mutations": 0' in vm_owner_upgrade
        and 'credential_mutations": 0' in vm_owner_upgrade
        and 'bootstrap_production_runner(' not in vm_owner_upgrade
        and 'apply_vm_credential_runtime(' not in vm_owner_upgrade
        and 'systemctl restart' not in vm_owner_upgrade,
        "VM owner update must preserve bounded exact-release identity and no-replay/runtime isolation",
    )

    # One native owner serves first-use VM apply/verify over the existing
    # restricted AgentService. Local Line2 results must stay per endpoint;
    # aggregate VM-local success must never be called external acceptance.
    # Load these alongside the first-use assertion; later all-workspace
    # checks also load the same canonical proto and owner files.
    agent_proto = AGENT_PROTO.read_text(encoding="utf-8")
    credential_proto = CREDENTIAL_PROTO.read_text(encoding="utf-8")
    vultr_lifecycle_command = VULTR_LIFECYCLE_COMMAND.read_text(encoding="utf-8")
    first_use_journal = Path(
        "edge-platform/crates/edge-orchestrator/src/credential_initial_journal.rs"
    ).read_text(encoding="utf-8")
    line2_quality = Path(
        "edge-platform/crates/edge-agent/src/line2_quality.rs"
    ).read_text(encoding="utf-8")
    require(
        "rpc ApplyInitialVmCredential(InitialVmCredentialRuntimeRequest)" in agent_proto
        and "rpc VerifyInitialVmCredential(InitialVmCredentialRuntimeRequest)" in agent_proto
        and "message InitialVmLine2EndpointResult" in credential_proto
        and "repeated InitialVmLine2EndpointResult vm_local_line2 = 5;" in credential_proto
        and "async fn apply_initial_vm_credential(" in vm_agent_runtime
        and "async fn verify_initial_vm_credential(" in vm_agent_runtime
        and "validate_initial_vm_runtime_request(&request)" in vm_agent_runtime
        and "initial_apply_vm_credential(&self.stack_dir, request.generation)" in vm_agent_runtime
        and "verify_initial_vm_credential_functional(" in vm_agent_runtime
        and "external_line1_proven: false" in vm_agent_runtime
        and "external_line2_proven: false" in vm_agent_runtime
        and "direct_warp_egress_distinct_proven: false" in vm_agent_runtime
        and "pub(crate) struct EndpointProof" in line2_quality
        and "endpoint_proofs.push(EndpointProof {" in line2_quality
        and "fn verify_initial_vm_runtime_gate(" in first_use_journal
        and "verify_recorded_initial_attempt(history, exact_record)?" in first_use_journal
        and '"initial-runtime-apply" => run_initial_vm_runtime' in vultr_lifecycle_command
        and '"initial-runtime-verify" => run_initial_vm_runtime' in vultr_lifecycle_command
        and "verify_initial_vm_runtime_gate(" in vultr_lifecycle_command
        and "require_six_exact_vm_local_line2(&response)?" in vultr_lifecycle_command
        and "do not replay" in vultr_lifecycle_command
        and "require_disposable_initial_probe_target(&args[0], &args[1])?" in vultr_lifecycle_command,
        "VM first-use must use typed restricted owner and exact BEGIN with six "
        "individual local Line2 results, never an external acceptance shortcut",
    )
    initial_vm_apply = vm_agent_runtime.split("async fn initial_apply_vm_credential(", 1)[1].split(
        "async fn fetch_and_stage_vm_credential_candidate(", 1
    )[0]
    require(
        re.search(r"CredentialInitialApply\s*\{\s*generation:\s*u64,?\s*\}", vm_agent_cli) is not None
        and "initial_apply_vm_credential(&stack_dir, generation)" in vm_agent_runtime
        and "require_initial_vm_policy_bundle_ready(stack_dir)?" in initial_vm_apply
        and "require_empty_vm_initial_credential_host(stack_dir)?" in initial_vm_apply
        and "let docker = observe_docker().await?;" in initial_vm_apply
        and "require_no_vm_application_containers(&docker)?" in initial_vm_apply
        and "Command::new(\"docker\")" not in initial_vm_apply
        and initial_vm_apply.index("require_no_vm_application_containers(&docker)?")
        < initial_vm_apply.index("fetch_and_stage_vm_credential_candidate(")
        and "apply_vm_credential_runtime(stack_dir, &secrets).await?" in initial_vm_apply
        and "verify_vm_candidate_runtime_materialized(stack_dir, &bundle)?" in initial_vm_apply
        and "promote_candidate" not in initial_vm_apply
        and "legacy_vm_runtime_secret_path(stack_dir)?.exists()" in vm_agent_runtime
        and "VM candidate application requires an established active Worker v2 generation" in vm_agent_runtime,
        "initial VM Worker-v2 application must be isolated, non-replayed and never auto-promoted",
    )
    production_command = PRODUCTION_COMMAND.read_text(encoding="utf-8")
    application_command = Path(
        "edge-platform/crates/edge-orchestrator/src/application_lifecycle_command.rs"
    ).read_text(encoding="utf-8")
    hosted_production_main = Path("edge-platform/crates/edge-orchestrator/src/main.rs").read_text(
        encoding="utf-8"
    )
    credential_command = CREDENTIAL_COMMAND.read_text(encoding="utf-8")
    credential_cli = CREDENTIAL_CLI.read_text(encoding="utf-8")
    credential_provider = CREDENTIAL_PROVIDER.read_text(encoding="utf-8")
    credential_snapshot = CREDENTIAL_SNAPSHOT.read_text(encoding="utf-8")
    credential_store = CREDENTIAL_STORE.read_text(encoding="utf-8")
    credential_proto = CREDENTIAL_PROTO.read_text(encoding="utf-8")
    runtime_proto = RUNTIME_PROTO.read_text(encoding="utf-8")
    release_proto = RELEASE_PROTO.read_text(encoding="utf-8")
    windows_singbox = WINDOWS_SINGBOX.read_text(encoding="utf-8")
    windows_diagnostic = WINDOWS_DIAGNOSTIC.read_text(encoding="utf-8")
    agent_proto = AGENT_PROTO.read_text(encoding="utf-8")
    controller_proto = CONTROLLER_PROTO.read_text(encoding="utf-8")
    production_inventory = PRODUCTION_INVENTORY.read_text(encoding="utf-8")
    acceptance_coordinator = ACCEPTANCE_COORDINATOR.read_text(encoding="utf-8")
    vultr_lifecycle_command = VULTR_LIFECYCLE_COMMAND.read_text(encoding="utf-8")
    production_vm_runner_installer = PRODUCTION_VM_RUNNER_INSTALLER.read_text(encoding="utf-8")
    architecture = ARCHITECTURE.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")
    local_architecture = LOCAL_ARCHITECTURE.read_text(encoding="utf-8")
    server_architecture = SERVER_ARCHITECTURE.read_text(encoding="utf-8")
    root_readme = ROOT_README.read_text(encoding="utf-8")
    local_agent_contract = LOCAL_AGENT_CONTRACT.read_text(encoding="utf-8")
    application_readme = APPLICATION_README.read_text(encoding="utf-8")
    vultr_stack_readme = VULTR_STACK_README.read_text(encoding="utf-8")
    production_desired = PRODUCTION_DESIRED.read_text(encoding="utf-8")

    listeners = sorted(
        path.name
        for path in WORKFLOWS.glob("*.yml")
        if "issue_comment:" in path.read_text(encoding="utf-8")
    )
    require(
        "Stage 3 and Stage 4A remain closed" in architecture
        and "Stage 4A exit decision — CLOSED" in architecture
        and "Managed TUN is now permitted only inside the explicit Stage 4B cutover" in architecture
        and "Stage 4B entry contract — managed Windows TUN" in architecture
        and "Add one typed Windows datapath mode" in architecture
        and "copied into `WindowsRuntimeState`, `WindowsRuntime`, or `WindowsActivationState`" in architecture
        and "Do not widen the SCM service identity merely by assumption" in architecture
        and "typed Windows process observation distinguishes managed / conflicting external / absent ownership" in architecture
        and "`infra/production/production.textproto` in Windows candidate input identity" in architecture
        and "exact locally verified `previous.pb`" in architecture
        and "Windows bidirectional mode changes remain N3" in architecture
        and "Stage 4B datapath convergence" in local_architecture
        and "Generated `runtime\\\\sing-box.json` never chooses the mode" in local_architecture
        and "## 10. Current N1/N2 → N3 native Windows modes (2026-10-12)" in runbook
        and "`PROXY_ONLY` ReleaseSet must never be treated as authority for the TUN cutover" in architecture
        and "Shared-host foreign-project isolation" in architecture
        and "Sing-box configuration, protocol selection and quality authority" in architecture
        and "No Windows start, converge, repair, rollback, unattended reboot or TUN switch" in runbook
        and "Production release rollback is not yet a supported public operation" not in runbook
        and "**ACTIVE N1/N2 → N3 → N4 (2026-10-12).**" in readme
        and "the sole execution cursor" in readme
        and "same existing normal VM lifecycle" in readme
        and "The former production VM" not in readme
        and "The old production VM was deleted" in readme
        and "EdgePlatformController` is **Stopped / AutoStart**" in readme
        and "do not start or mutate Windows WARP/MISH/OKX" in readme
        and "The accepted proxy-only runtime is the starting point" not in readme
        and "currently working external Windows sing-box" not in readme
        and "bounded local owner" in readme
        and "Independent authenticated 10/10 direct/WARP" in readme
        and "/production rollback" in runbook
        and "/credentials rotate tunnel-auth" in runbook
        and "canonical permanent" in runbook
        and "custom X25519/HKDF/AEAD handoff" in runbook
        and "Routine production converge/verify/diagnose/rollback does not acquire a support lease" in server_architecture
        and "> **N1/N2 physical network 10/10 + reboot: ACCEPTED." in root_readme
        and "Original Worker credentials generation `38503639351`" in root_readme
        and "The already-owned acceptance VM was retained" in root_readme
        and "**One delivery order:** N1/N2" in root_readme
        and "Never start/restart/converge/repair/rollback TUN merely to retest" in root_readme
        and "An acceptance VM is disposable" not in root_readme
        and "First-use credentials require a durable journal" in root_readme
        and "The currently working external Windows sing-box/TUN" not in root_readme
        and "bounded Stage-3 historical deletion slice is closed" in local_agent_contract
        and "`/production rollback` uses the same" in application_readme
        and "Routine production does not acquire a temporary support lease" in vultr_stack_readme
        and "strict SSH local-forward" not in vultr_stack_readme
        and "currently #169" not in runbook,
        "operator docs must reflect sole Issue #26 N1/N2→N3→N4 and enforce stopped TUN/no-TUN recovery safety",
    )
    image_build_section = edge_platform_ci.split("# VM_RUNTIME_BUILD_CONTRACT_BEGIN", 1)[1].split("# VM_RUNTIME_BUILD_CONTRACT_END", 1)[0]
    require(
        image_build_section.count("docker buildx build --platform linux/amd64 --provenance=false --sbom=false --push") == 2
        and "docker push" not in image_build_section
        and 'evidence_image="${gateway_ref}"' in edge_platform_ci
        and 'docker pull "${evidence_image}" >/dev/null' in edge_platform_ci
        and 'docker buildx imagetools inspect "${gateway_ref}"' in edge_platform_ci,
        "OCI candidate must publish once via Buildx and re-read immutable GHCR digests before attestations",
    )
    require(
        "PRE_MUTATION_TUN_TEARDOWN_BLOCKED" in windows_physical
        and "PRE_MUTATION_TUN_TEARDOWN_BLOCKED" in windows_physical.split("      - name: Execute typed lifecycle mutation", 1)[0]
        and "managed_tun_automatic_rollback=BLOCKED_NO_INDEPENDENT_DNS_RESTORE" in windows_physical
        and "privileged-rollback-previous" not in windows_physical.split("      - name: Refuse unproven automatic rollback after MANAGED_TUN verification failure", 1)[1].split("      - name: Final diagnostics and transport-only boundary", 1)[0]
        and "$env:EDGE_OPERATION -eq 'stop'" in windows_physical
        and "$env:EDGE_OPERATION -eq 'rollback'" in windows_physical
        and "managed_tun_previous_rollback_dns_owner_preflight=PASS" in windows_physical
        and "previous_release_native_desired_managed_tun=PASS" in windows_physical
        and "$previousDiagnostic doctor $previous" in windows_physical
        and "Invoke-WebRequest" not in windows_physical
        and "PRE_MUTATION_ROLLBACK_BLOCKED" in windows_physical.split("      - name: Execute typed lifecycle mutation", 1)[0]
        and "$currentMode -ceq 'ManagedTun'" in windows_physical
        and "$env:EDGE_EXPECTED_MODE -ceq 'ProxyOnly'" in windows_physical
        and 'reject_unproven_windows_tun_teardown("stop-local")' in windows_controller_runtime
        and 'fn require_managed_tun_rollback_pair(' in windows_console
        and 'require_exact_immutable_activation_console(install_root)?;' in windows_console.split('fn rollback_privileged_release(', 1)[1].split('fn reconcile_activation_owner(', 1)[0]
        and 'require_managed_tun_rollback_pair(request, &current, &previous)?;' in windows_console
        and '"managed-tun-to-proxy-only"' in windows_console
        and "failed to stop exact managed proxy before release transition" in windows_console,
        "Only explicit exact ManagedTun previous-release rollback may pass the existing owner; stop/ProxyOnly teardown stays blocked",
    )
    require(
        "PRE_MUTATION_LEGACY_DNS_WRITER_BLOCKED" not in windows_physical
        and "legacy_managed_tun_exact_remote_upgrade" not in windows_physical
        and "1ebe355143ac3d59a11d4c40755e1f8aa2aa9060c957822d831f18d4ace667b5" not in windows_physical
        and "PRE_MUTATION_TUN_TEARDOWN_BLOCKED" in windows_physical
        and "PRE_MUTATION_ROLLBACK_BLOCKED" in windows_physical,
        "completed one-shot migration exception must be deleted without enabling unguarded TUN teardown",
    )
    require(
        "/windows cutover" not in router
        and "/windows cutover" not in windows_physical
        and "github.event.comment.body == '/windows diagnose'" in router
        and "github.event.comment.body == '/windows converge'" in router
        and "github.event.comment.body == '/windows start'" in router
        and "github.event.comment.body == '/windows stop'" in router
        and "github.event.comment.body == '/windows restart-controller'" in router
        and "github.event.comment.body == '/windows repair'" in router
        and "github.event.comment.body == '/windows rollback'" in router
        and 'operation="diagnose"' in windows_physical
        and 'operation="converge"' in windows_physical
        and 'operation="start"' in windows_physical
        and 'operation="stop"' in windows_physical
        and 'operation="restart-controller"' in windows_physical
        and 'operation="repair"' in windows_physical
        and 'operation="rollback"' in windows_physical
        and "privileged-reinstall-accepted" in windows_physical
        and "verify-runtime" in windows_physical
        and "restart-verify-runtime" not in windows_physical
        and "Verify exact authority and SCM handoff" in windows_physical
        and "Read-only privileged runtime evidence after restart" in windows_physical
        and windows_physical.count("privileged-runtime-evidence") == 4
        and windows_physical.rindex("verify-runtime") < windows_physical.rindex("privileged-runtime-evidence")
        and "runtime\\sing-box.stderr.log" not in windows_physical
        and "runtime_evidence=BOUNDED_READ_ONLY" in windows_physical
        and "Managed sing-box stderr evidence is missing after lifecycle verification" in windows_physical
        and "Managed sing-box stderr evidence was omitted from the bounded privileged result" in windows_physical
        and windows_physical.count("External sing-box owner changed") == 1
        and "EDGE_EXTERNAL_PIDS_BEFORE" in windows_physical
        and "Stage 4B.2-C requires zero external sing-box owners" in windows_physical
        and "Resolve expected Windows datapath mode" in windows_physical
        and "Prove MANAGED_TUN ordinary Windows traffic DNS and foreign Mesh coexistence" in windows_physical
        and "Refuse unproven automatic rollback after MANAGED_TUN verification failure" in windows_physical
        and "PRE_MUTATION_MANAGED_TUN_PREAUTH_BLOCKED" in windows_physical
        and "Exact immutable rollback console is unavailable" not in windows_physical
        and "Stable rollback console is missing" not in windows_physical
        and "runtime_server_ip" not in windows_diagnostic
        and "server_bypass" not in windows_diagnostic
        and "state\\secrets\\runtime-state.pb" not in windows_diagnostic
        and "Typed controller status failed" in windows_physical
        and "^Server IP\\s+:\\s+" in windows_physical
        and "Repair target must equal the exact current ReleaseSet before runtime stop" in windows_physical
        and "Invoke-WebRequest" not in windows_physical
        and "edge-platform-windows.zip" not in windows_physical
        and "Failed to stop exact managed proxy before release converge" not in windows_physical
        and "failed to stop exact managed proxy before release transition" in windows_console
        and "id: lifecycle_mutation" in windows_physical
        and "steps.lifecycle_mutation.outcome == 'success'" in windows_physical
        and "managed_tun_server_bypass=PASS" in windows_physical
        and "Find-NetRoute -RemoteIPAddress $serverIp" in windows_physical
        and "managed_tun_process_search_access_denied=ABSENT" in windows_physical
        and "foreign_cloudflarewarp_tun_dns_cleanup=PASS" in windows_physical
        and "Set-DnsClientServerAddress -InterfaceAlias 'CloudflareWARP'" not in windows_physical
        and "stop-local $env:EDGE_CONTROLLER_ENDPOINT" in windows_physical
        and "EDGE_CURRENT_EXACT_DIAGNOSTIC" in windows_physical
        and "Exact immutable post-state diagnostic path is unavailable" in windows_physical
        and "unknown_singbox_process_count" in windows_diagnostic
        and "identity_unknown" in windows_diagnostic
        and "process_inspection_complete=" in windows_diagnostic
        and "prestate_managed_owner=PRIVILEGED_EXACT_PROOF" in windows_physical
        and "managed_process_identity=PRIVILEGED_EXACT_PROOF" in windows_physical
        and "Final process identity is UNKNOWN without exact matching privileged evidence" in windows_physical
        and "Fail-closed rollback requires independently proven exact active owner before mutation" not in windows_physical
        and "Rolled back process cannot be independently confirmed as exact managed owner" not in windows_physical
        and "$env:EDGE_OPERATION -in @('converge','repair')" in windows_physical
        and "managed_tun_present" in windows_physical
        and "start-local $env:EDGE_CONTROLLER_ENDPOINT" in windows_physical
        and "runtime_start=NOOP_ALREADY_RUNNING" in windows_physical
        and windows_physical.count("privileged-runtime-evidence") == 4
        and "EDGE_STOPPED_OWNER_RECOVERY=YES" in windows_physical
        and "Bounded recovery still observes privileged external sing-box ownership" in windows_physical
        and "stopped_owner_recovery_diagnostic_exit=NORMALIZED_AFTER_PROVEN_CONFLICT" in windows_physical
        and "Recovering stopped SCM owner only after privileged evidence proved zero external sing-box owners" in windows_physical
        and "RESTARTED_ORPHAN_MANAGED" in windows_controller_runtime
        and "failed to stop exact managed runtime on controller exit" in windows_controller_runtime
        and "managed_parent_is_current_controller" in windows_controller_runtime
        and "if: ${{ always() }}" in windows_physical
        and "bin\\edge-console.exe" in windows_physical
        and "Privileged conflict evidence failed read-only" in windows_physical
        and "Transient runtime control changed ReleaseSet authority" in windows_physical
        and "Expected zero managed proxy processes after stop" in windows_physical
        and "Final explicit runtime stop left managed TUN present" in windows_physical
        and "Read-only managed proxy trace" not in windows_physical
        and "$env:EDGE_OPERATION -in @('converge','repair')" in windows_physical
        and "needs.resolve.outputs.operation != 'diagnose'" in windows_physical,
        "Stage 4B Windows lifecycle must stay one fixed typed boundary across ProxyOnly/ManagedTun with no second cutover command",
    )
    require(
        "127.0.0.1:45151" in windows_physical
        and "127.0.0.1:51051" not in windows_physical
        and "WINDOWS_PRIVILEGED_OPERATION_RESTART_CONTROLLER_SERVICE = 11" in runtime_proto
        and "RestartControllerService" in shared_types
        and "privileged-restart-controller-service" in windows_console_cli
        and "CONTROLLER_SERVICE_RESTARTED" in windows_console
        and "controller_service_error=ABSENT" in windows_console
        and "process_classification=" in windows_console
        and "ServiceState::StartPending" in windows_controller_runtime
        and "TcpListener::bind(config.addr)" in windows_controller_runtime
        and "serve_with_incoming_shutdown" in windows_controller_runtime
        and "WINDOWS_CONTROLLER_INIT_TIMEOUT" in windows_controller_runtime
        and windows_controller_runtime.index("ServiceState::StartPending")
            < windows_controller_runtime.index("controller_server(config.repo_root.clone())")
        and windows_controller_runtime.index("controller_server(config.repo_root.clone())")
            < windows_controller_runtime.index("TcpListener::bind(config.addr)")
        and windows_controller_runtime.index("TcpListener::bind(config.addr)")
            < windows_controller_runtime.index("converge_windows_runtime_on_service_start")
        and windows_controller_runtime.index("converge_windows_runtime_on_service_start")
            < windows_controller_runtime.index("ServiceState::Running")
        and "windows_boot_time_unix_seconds" in windows_diagnostic
        and "controller_listener_present" in windows_diagnostic
        and "controller_process_start_unix_seconds" in windows_diagnostic
        and "orphan_singbox_process_count" in windows_diagnostic
        and "clean_stopped_bootstrap_diagnostic_exit=NORMALIZED_AFTER_PROVEN_CLEAN_STATE" in windows_physical
        and "EDGE_CLEAN_STOPPED_BOOTSTRAP=YES" in windows_physical
        and "runtime_start_noop_identity=PASS" in windows_physical,
        "Release A must make SCM readiness deterministic, use the fixed non-dynamic controller endpoint and expose only bounded GitHub-visible lifecycle evidence",
    )
    require(
        '".repair"' in windows_installer
        and "PreservePrevious" in windows_installer
        and "ForceRematerialize" in windows_installer
        and "reinstall-old" not in windows_installer
        and "refuses to overwrite the active immutable release directory" in windows_installer
        and "privileged-reinstall-accepted" in windows_console_cli
        and "ReinstallAcceptedRelease" in windows_console
        and "require_supported_reinstall_authority" in windows_console
        and "require_proxy_only_reinstall_authority" not in windows_console
        and "sync_stable_windows_release_tools" in windows_console
        and "current.pb and previous.pb identify the same ReleaseSet" in windows_console
        and "repeated rollback is fail-closed because current.pb now equals previous.pb" in windows_console
        and "failed to swap exact current/previous Windows activation authority" not in windows_console
        and "spawn_with_temporary_debug_privilege" in edge_local_runtime
        and "SeDebugPrivilege" in edge_local_runtime
        and "ProxyOnlySmoke" not in runtime_proto
        and "run_proxy_only_egress_smoke" not in edge_local_runtime,
        "Windows repair/rollback must use bounded immutable slots, preserve previous.pb, support both accepted datapath modes and keep stable operator tools aligned with exact activation",
    )
    require(
        "schema_version: 6" in production_desired
        and "windows_datapath_mode: WINDOWS_DATAPATH_MODE_PROXY_ONLY" in production_desired
        and "windows_datapath_mode: WINDOWS_DATAPATH_MODE_MANAGED_TUN" not in production_desired,
        "First Windows installation must embed canonical ProxyOnly mode and never seize host TUN, routes or DNS",
    )
    require(
        'repo_root / "infra" / "production" / "production.textproto"' in windows_input,
        "Windows candidate identity must include canonical production desired state while it is compiled into Windows binaries",
    )
    require(
        "WindowsDatapathMode datapath_mode" not in runtime_proto
        and "WindowsDatapathMode datapath_mode" not in release_proto
        and "RELEASE_SET_SCHEMA_VERSION: u32 = 7" in shared_types
        and "desired.windows_datapath_mode" in windows_singbox
        and "state.datapath_mode" not in windows_singbox,
        "Stage 4B datapath authority must remain Git-owned and embedded, never duplicated into runtime/ReleaseSet state",
    )
    require(
        "canonical_production_desired_state" in windows_diagnostic
        and "QueryServiceStatusEx" in windows_diagnostic
        and "SC_STATUS_PROCESS_INFO" in windows_diagnostic
        and "SERVICE_STATUS_PROCESS" in windows_diagnostic
        and "scm_native_process_id(&service)" in windows_diagnostic
        and "scm_process_id_valid_for_state" in windows_diagnostic
        and "SERVICE_PAUSE_PENDING" in windows_diagnostic
        and "SERVICE_CONTINUE_PENDING" in windows_diagnostic
        and "status.process_id" not in windows_diagnostic
        and "process.parent()" in windows_diagnostic
        and "scm_process_id" in windows_diagnostic
        and "service_binary_path" in windows_diagnostic
        and "powershell.exe" not in windows_diagnostic.lower()
        and "get-ciminstance" not in windows_diagnostic.lower()
        and "win32_service" not in windows_diagnostic.lower(),
        "Stage 4B diagnostics must derive mode from embedded desired state and use native typed Windows APIs without PowerShell/WMI parsing",
    )
    require(
        "MANAGED_TUN" not in credential_command
        and "datapath_mode" not in credential_command,
        "credential Workers/control plane must remain credential delivery only and gain no Stage 4B datapath role",
    )
    require(
        "AcceptanceServe" in vm_agent_cli
        and 'Cli::try_parse_from(["edge-agent", "acceptance-serve"]).is_ok()' in vm_agent_cli
        and 'Cli::try_parse_from(["edge-agent"]).is_err()' in vm_agent_cli
        and 'Cli::try_parse_from(["edge-agent", "serve"]).is_err()' in vm_agent_cli
        and "LocalCommand" in vm_agent_cli
        and "BootstrapBase" in vm_agent_cli
        and "BootstrapTunnel" in vm_agent_cli
        and "BootstrapFull" in vm_agent_cli
        and "MeshVerify" in vm_agent_cli
        and "MeshCleanup" in vm_agent_cli
        and "CredentialState" in vm_agent_cli
        and "CredentialTransition" in vm_agent_cli
        and "CredentialApplyCandidate" not in vm_agent_cli
        and "CredentialPromote" not in vm_agent_cli
        and "CredentialRollback" not in vm_agent_cli
        and 'Cli::try_parse_from(["edge-agent", "local", "exec"]).is_err()' in vm_agent_cli
        and 'Cli::try_parse_from(["edge-agent", "exec", "whoami"]).is_err()' in vm_agent_cli,
        "Linux runtime owner must expose only the closed local operation grammar and explicitly reject exec",
    )
    require(
        listeners == [ROUTER.name],
        f"exactly one issue_comment listener is required, observed: {listeners}",
    )
    require("workflow_call:" in application, "application lifecycle must be reusable")
    require("workflow_call:" in vultr, "Vultr lifecycle must be reusable")
    require("workflow_call:" in windows_physical, "Windows physical cycle must be reusable")
    require("workflow_call:" in credentials, "credential lifecycle must be reusable")
    tunnel_auth = credential_proto.split("message TunnelAuthentication {", 1)[1].split("}", 1)[0]
    reality_public = credential_proto.split("message RealityPublicIdentity {", 1)[1].split("}", 1)[0]
    reality_private = credential_proto.split("message RealityPrivateIdentity {", 1)[1].split("}", 1)[0]
    windows_projection = credential_proto.split("message WindowsCredentialProjection {", 1)[1].split("}", 1)[0]
    vm_projection = credential_proto.split("message VmCredentialProjection {", 1)[1].split("}", 1)[0]
    require(
        "map<" not in credential_proto
        and not any(line.strip().startswith("bytes ") for line in credential_proto.splitlines())
        and "oneof payload" in credential_proto
        and "enum CredentialDeliverySlot" in credential_proto
        and "CredentialDeliverySlot slot = 5;" in credential_proto,
        "credential v2 must remain an explicit typed protobuf contract with fixed A/B slot identity and without maps or arbitrary byte bags",
    )
    require(
        "vless_uuid" in tunnel_auth
        and "hysteria2_password" in tunnel_auth
        and "reality_short_id" in tunnel_auth
        and "public_key" not in tunnel_auth
        and "private_key" not in tunnel_auth,
        "tunnel authentication must remain independent from Reality server identity",
    )
    require(
        "public_key" in reality_public
        and "private_key" not in reality_public
        and "private_key" in reality_private
        and "public_key" not in reality_private,
        "credential schema must keep Reality public material Windows-side and private material VM-side",
    )
    require(
        "TunnelAuthenticationGeneration tunnel_auth" in windows_projection
        and "RealityPublicIdentityGeneration reality_identity" in windows_projection
        and "line2_proxy" not in windows_projection
        and "RealityPrivateIdentityGeneration" not in windows_projection
        and "TunnelAuthenticationGeneration tunnel_auth" in vm_projection
        and "RealityPrivateIdentityGeneration reality_identity" in vm_projection
        and "ProxyCredentialGeneration line2_proxy" in vm_projection
        and "RealityPublicIdentityGeneration" not in vm_projection,
        "credential schema must keep independent tunnel-auth/Reality/proxy lifecycles and least-privilege projections",
    )
    require(
        "generate_fresh_credential_snapshot" in credential_snapshot
        and "FreshCredentialSnapshotRequest" in credential_snapshot
        and "validate_credential_delivery_bundle" in credential_snapshot
        and "ApplicationRuntimeSecrets" not in credential_snapshot,
        "fresh snapshot builder must own typed generation assembly without reusing the legacy monolithic secret model",
    )
    require(
        all(
            token not in credential_snapshot
            for token in (
                "edge_provider_",
                "reqwest",
                "tokio",
                "std::fs",
                "std::env",
                "upload_worker",
                "CLOUDFLARE_",
                "VULTR_",
            )
        ),
        "fresh snapshot builder must remain pure/in-memory and provider/runtime side-effect free",
    )
    require(
        "struct CredentialStore" in credential_store
        and "stage_candidate" in credential_store
        and "promote_candidate" in credential_store
        and "rollback_previous" in credential_store
        and "decode_local_credential_state" in credential_store
        and "verify_local_credential_bundle_reference" in credential_store
        and "atomic_replace" in credential_store,
        "local credential store must remain typed, digest-bound and crash-safe",
    )
    require(
        all(
            token not in credential_store
            for token in (
                "serde_json",
                "rusqlite",
                "ApplicationRuntimeSecrets",
                "OsRng",
                "edge_provider_",
                "reqwest",
                "CLOUDFLARE_",
                "VULTR_",
            )
        ),
        "local credential store must not own generation, provider access, JSON or SQLite state",
    )
    require(
        'state/secrets/application-v2' in windows_controller_core
        and 'runtime-secrets/application-v2' in vm_agent,
        "Windows and VM v2 credentials must stay inside the existing private secret roots",
    )
    # A Worker-only credential authority is meaningful only when VM activation
    # cannot silently create or adopt an independent local secret at runtime.
    materialize = vm_agent_runtime.split(
        "fn materialize_vm_owned_runtime_environment", 1
    )[1].split("fn validate_runtime_policy_env", 1)[0]
    require(
        'active_vm_credential_bundle(stack_dir)?.ok_or_else' in materialize
        and 'ApplicationRuntimeSecrets::from_vm_bundle(&bundle)?' in materialize
        and 'ensure_vm_runtime_secret_store' not in vm_agent_runtime
        and 'read_legacy_vm_runtime_secrets' not in vm_agent_runtime
        and 'legacy VM credential apply is retired' in vm_agent_runtime
        and 'credential_rendered_source=V2_ACTIVE_RENDERED' in vm_agent_runtime
        and 'credential_running_source=UNPROVEN_WITHOUT_CONTAINER_RELOAD_PROOF'
        in vm_agent_runtime
        and 'vm_runtime_materialization_refuses_legacy_and_requires_explicit_active_v2'
        in vm_agent,
        "VM runtime credentials must be Worker-v2-only and fail closed, without local generator or legacy rollback",
    )

    # A new generation cannot be declared active merely because a local
    # candidate pointer exists. Both owners prove exact applied artifacts;
    # VM also requires a verified READY runtime before moving the cursor.
    vm_promote = vm_agent_runtime.split(
        "CredentialTransitionAction::Promote => {", 1
    )[1].split("CredentialTransitionAction::ApplyLegacy =>", 1)[0]
    # Credential transitions are implemented in their isolated source module.
    windows_transition = Path("edge-platform/crates/edge-console/src/credential_transition.rs").read_text(encoding="utf-8")
    windows_promote = windows_transition.split(
        "CredentialTransitionAction::Promote => {", 1
    )[1].split("CredentialTransitionAction::ApplyActive =>", 1)[0]
    require(
        "require_vm_active_v2_for_promotion(&state)?" in vm_promote
        and "verify_vm_candidate_runtime_materialized(stack_dir, &bundle)?" in vm_promote
        and "verify_bootstrap_post_state(stack_dir, BootstrapMode::BootstrapFull, &runtime)" in vm_promote
        and "store.promote_candidate()?" in vm_promote
        and "require_active_v2_for_rotation(&state)?" in windows_promote
        and "verify_exact_candidate_runtime(install_root, activation, &store, candidate)?" in windows_promote
        and "store.promote_candidate()?" in windows_promote
        and "require_active_v2_for_rotation(&state)?"
        in windows_transition.split("CredentialTransitionAction::ApplyCandidate => {", 1)[1].split("CredentialTransitionAction::Promote =>", 1)[0]
        and "vm_candidate_promotion_cannot_commit_an_unapplied_worker_generation" in vm_agent,
        "rotation entrypoints must refuse initial enrollment and verify candidate artifacts before promotion",
    )

    require(
        "message StageCredentialCandidateRequest" in credential_proto
        and "CredentialDeliveryBundle bundle = 1;" in credential_proto
        and "message CredentialStateObservation" in credential_proto
        and "LocalCredentialState state = 1;" in credential_proto,
        "candidate staging transport must remain typed and return only non-secret local state refs",
    )
    for owner_proto in (agent_proto, controller_proto):
        require(
            'import "edge/platform/v1/credential_plane.proto";' in owner_proto
            and "rpc StageCredentialCandidate(StageCredentialCandidateRequest) returns (CredentialStateObservation);" in owner_proto
            and "rpc GetCredentialState(Empty) returns (CredentialStateObservation);" in owner_proto,
            "both runtime owners must expose the same bounded candidate staging/observation contract",
        )
    vm_stage_start = vm_agent_runtime.index("fn stage_vm_credential_candidate")
    vm_stage_end = vm_agent_runtime.index("fn observe_vm_credential_state", vm_stage_start)
    vm_stage = vm_agent_runtime[vm_stage_start:vm_stage_end]
    windows_stage_start = windows_controller_runtime.index("fn stage_windows_credential_candidate")
    windows_stage_end = windows_controller_runtime.index(
        "fn observe_windows_credential_state", windows_stage_start
    )
    windows_stage = windows_controller_runtime[windows_stage_start:windows_stage_end]
    require(
        "store.stage_delivery_candidate(&bundle)" in vm_stage
        and "local_credential_bundle_ref(&bundle)" not in vm_stage
        and "promote_candidate(" not in vm_stage
        and "rollback_previous(" not in vm_stage
        and "require_installed_windows_credential_owner" in windows_stage
        and "store.stage_delivery_candidate(&bundle)" in windows_stage
        and "local_credential_bundle_ref(&bundle)" not in windows_stage
        and "promote_candidate(" not in windows_stage
        and "rollback_previous(" not in windows_stage
        and "materialize_credential_delivery_candidate" in credential_store
        and "self.stage_candidate(&candidate)" in credential_store,
        "candidate ingress must materialize typed rotation deltas inside the local secret store and remain stage-only; transition authority stays in the bounded local-owner command",
    )
    require(
        "StageCredentialCandidateRequest" not in windows_console
        and "PrivilegedStageCredential" in windows_console_cli
        and "WindowsPrivilegedOperation::StageCredential" in windows_console
        and "fetch_canonical_credential_bundle" in windows_console,
        "Windows runner may carry only typed generation intent while SYSTEM fetches and stages the canonical bundle",
    )
    require(
        "RELEASE_ALREADY_CONVERGED" in windows_console
        and "installer not invoked; exact owner handoff reconciled" in windows_console
        and "RELEASE_CONVERGED_REOBSERVED" in windows_console
        and "local owner handoff reconciled" in windows_console
        and "fn reconcile_activation_owner(" in windows_console
        and windows_console.index(
            "retarget_privileged_task(install_root, &activation.console_path)?;"
        )
        < windows_console.index(
            "converge_controller_service_with_activation_console(install_root, activation)?;"
        )
        and windows_console.count(
            "reconcile_activation_owner(install_root, &previous)"
        ) == 1
        and windows_console.count(
            "reconcile_activation_owner(install_root, &current)"
        ) == 1
        and "current_config.executable_path.to_string_lossy() == expected_command"
            in windows_console
        and "current_status.current_state == ServiceState::Running" in windows_console
        and "controller_is_listening(addr)" in windows_console
        and "fn wait_for_controller(" not in windows_console,
        "Windows release activation and rollback must share one recoverable owner handoff while healthy same-target convergence remains idempotent",
    )
    service_wait_start = windows_console.index("fn wait_for_service_state(")
    service_wait_end = windows_console.index(
        "fn run_icacls(", service_wait_start
    )
    service_wait = windows_console[service_wait_start:service_wait_end]
    service_runtime_start = windows_controller_runtime.index(
        "fn run_edge_controller_service()"
    )
    service_runtime_end = windows_controller_runtime.index(
        "enum WindowsStartupDecision", service_runtime_start
    )
    service_runtime = windows_controller_runtime[service_runtime_start:service_runtime_end]
    require(
        "runtime.block_on(async {" in service_runtime
        and "timeout(" in service_runtime
        and "runtime.block_on(timeout(" not in service_runtime
        and "tokio::net::TcpListener::bind(config.addr).await" in service_runtime,
        "Windows service Tokio timers and sockets must be constructed inside the entered runtime context",
    )

    service_start = windows_controller_runtime.index(
        "fn run_edge_controller_service()"
    )
    service_end = windows_controller_runtime.index(
        "enum WindowsStartupDecision", service_start
    )
    registered_service = windows_controller_runtime[service_start:service_end]
    require(
        registered_service.index("service_control_handler::register(")
        < registered_service.index("let service_result = catch_unwind(")
        and 'write_controller_service_error(&config.repo_root, "panic", &message)' in registered_service
        and registered_service.index(
            'write_controller_service_error(&config.repo_root, "panic", &message)'
        )
        < registered_service.rindex("set_stopped(true).map_err(")
        and "set_stopped(result.is_err())?;" in registered_service
        and "let _ = status_handle.set_service_status" not in registered_service
        and registered_service.count("current_state: ServiceState::Stopped") == 1,
        "The registered Windows service must persist caught panic evidence before exactly one SCM Stopped transition; startup errors must not silently discard status failures",
    )

    service_entry_start = windows_controller_runtime.index(
        "fn edge_controller_service_main("
    )
    service_entry_end = windows_controller_runtime.index(
        "fn run_edge_controller_service()", service_entry_start
    )
    service_entry = windows_controller_runtime[service_entry_start:service_entry_end]
    runtime_start_start = windows_controller_runtime.index(
        "fn converge_windows_runtime_on_service_start("
    )
    runtime_start_end = windows_controller_runtime.index(
        "fn normalize_runtime_secret_refs(", runtime_start_start
    )
    runtime_start = windows_controller_runtime[runtime_start_start:runtime_start_end]
    require(
        "catch_unwind(AssertUnwindSafe(run_edge_controller_service))" in service_entry
        and 'write_controller_service_boundary_error("panic"' in service_entry
        and 'write_controller_service_boundary_error("service_entry"' in service_entry
        and "unreachable!(" not in runtime_start,
        "Windows service entry must contain Rust panics before the extern-system boundary and startup ownership conflicts must remain fail-closed without panicking",
    )

    require(
        "WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS" in shared_types
        and "Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS)"
            in windows_controller_runtime
        and windows_console.count(
            "Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS)"
        ) >= 2
        and "wait_for_service_state(&service, ServiceState::Running, Duration::from_secs(15))?;"
            not in windows_console
        and "wait_for_service_state(&service, ServiceState::Running, Duration::from_secs(45))?;"
            not in windows_console
        and "NotifyServiceStatusChangeW" in service_wait
        and "SleepEx" in service_wait
        and "SERVICE_NOTIFY_RUNNING" in service_wait
        and "SERVICE_NOTIFY_STOPPED" in service_wait
        and "thread::sleep" not in service_wait
        and "query_status()" in service_wait,
        "Windows SCM readiness must use native status notifications with one bounded safety deadline and no polling sleep",
    )
    controller_handoff_start = windows_console.index("fn converge_controller_service(")
    controller_handoff_end = windows_console.index(
        "async fn reconcile_installed_runtime(", controller_handoff_start
    )
    controller_handoff = windows_console[
        controller_handoff_start:controller_handoff_end
    ]
    require(
        "fn wait_for_service_state_any(" in service_wait
        and "SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED" in service_wait
        and "thread::sleep" not in service_wait
        and "status.current_state == ServiceState::StartPending" in controller_handoff
        and "wait_for_service_state_any(" in controller_handoff
        and "ServiceState::Running | ServiceState::Paused =>" in controller_handoff
        and "ServiceState::Stopped => {}" in controller_handoff
        and "ServiceState::StopPending =>" in controller_handoff
        and 'controller service is not safely stoppable for owner handoff' in controller_handoff
        and "if status.current_state != ServiceState::StopPending" not in controller_handoff,
        "Windows owner handoff must settle SCM StartPending natively before issuing STOP; unknown states fail closed",
    )
    require(
        "CredentialAdmit" not in vm_agent_cli
        and "local-credential-admit" not in vm_agent_cli
        and "PrivilegedAdmitCredential" not in windows_console_cli
        and "admit_vm_credential_generation" not in vm_agent_runtime
        and "admit_windows_credential_generation" not in windows_console
        and windows_console.count("WindowsPrivilegedOperation::AdmitCredential") == 1
        and 'ADMIT_CREDENTIAL is retired; exact-generation STAGE_CREDENTIAL is the sole credential data-plane gate' in windows_console
        and 'WINDOWS_PRIVILEGED_OPERATION_ADMIT_CREDENTIAL = 8 [deprecated = true];' in runtime_proto
        and 'ADMIT_CREDENTIAL is retired; exact-generation STAGE_CREDENTIAL is the sole credential data-plane gate' in shared_types,
        "retired Stage-2 read-only credential admission must stay non-executable; exact-generation staging is the sole steady-state data-plane gate while the old Windows wire identity remains a deprecated fail-closed tombstone",
    )
    require("workflow_call:" in vpc, "VPC lifecycle must be reusable")
    require("issue_comment:" not in application, "application backend must not listen to comments")
    require("issue_comment:" not in vultr, "Vultr backend must not listen to comments")
    require("issue_comment:" not in windows_physical, "Windows physical cycle must not listen to comments")
    require("issue_comment:" not in credentials, "credential backend must not listen to comments")
    require("issue_comment:" not in vpc, "VPC backend must not listen to comments")
    require(not ZERO_TRUST.exists() and not DNS.exists(), "retired standalone Cloudflare operator workflows must stay absent")
    require(
        not ZERO_TRUST_COMMAND.exists()
        and not ZERO_TRUST_SERVICE.exists()
        and not ZERO_TRUST_CORE.exists()
        and ("pub(crate) enum CloudflareZeroTrustCommand {\n    Doctor(ZeroTrustDoctorArgs),\n}" in credential_cli
        and "pub(crate) enum ZeroTrustReadinessScope {" in credential_cli
        and "pub scope: ZeroTrustReadinessScope" in credential_cli),
        "retired Zero Trust mutation lifecycle must stay physically absent; only the read-only doctor CLI may remain",
    )

    require(
        "uses: ./.github/workflows/vm-application-lifecycle.yml" in router,
        "router must call the application backend",
    )
    require(
        "startsWith(github.event.comment.body, '/production ')" in router
        and router.count("uses: ./.github/workflows/vm-application-lifecycle.yml") == 2,
        "router must expose production only through the existing owner-gated application lifecycle backend",
    )
    require(
        "uses: ./.github/workflows/credential-lifecycle.yml" in router
        and "startsWith(github.event.comment.body, '/credentials ')" in router,
        "router must expose credential delivery only through the dedicated owner-gated /credentials backend",
    )
    require(
        "uses: ./.github/workflows/vultr-lifecycle.yml" in router,
        "router must call the Vultr backend",
    )
    require(
        "uses: ./.github/workflows/windows-physical.yml" in router
        and "github.event.comment.body == '/windows smoke'" in router
        and "github.actor_id == '44100369'" in router,
        "router must expose the physical Windows cycle only as the exact owner-only /windows smoke command",
    )
    require(
        "vultr-root-ops.yml" not in router
        and "startsWith(github.event.comment.body, '/root ')" not in router
        and not (WORKFLOWS / "vultr-root-ops.yml").exists()
        and not Path("edge-platform/scripts/install-vultr-root-runner.sh").exists(),
        "retired generic root-runner routing/workflow/installer must be absent",
    )
    require(
        "startsWith(github.event.comment.body, '/zero-trust ')" not in router
        and "zero-trust-lifecycle.yml" not in router
        and not ZERO_TRUST.exists(),
        "duplicate production-facing /zero-trust operator workflow must be retired",
    )
    require(
        "/credential-plane " not in router
        and "cloudflare-credential-plane.yml" not in router,
        "router must not introduce a second credential-plane authority namespace",
    )
    require(
        "uses: ./.github/workflows/vultr-vpc-lifecycle.yml" in router,
        "router must call the VPC backend",
    )
    require(
        "startsWith(github.event.comment.body, '/dns ')" not in router
        and "cloudflare-dns-lifecycle.yml" not in router
        and not DNS.exists(),
        "duplicate production-facing /dns operator workflow must be retired",
    )
    require(
        "startsWith(github.event.comment.body, '/mesh ')" not in router
        and "cloudflare-mesh-lifecycle.yml" not in router
        and not (WORKFLOWS / "cloudflare-mesh-lifecycle.yml").exists(),
        "parallel /mesh operator transport must be retired; provider Mesh belongs to canonical /production composition and VM runtime Mesh belongs to the local owner",
    )
    require(
        "CloudflareDns" not in credential_cli
        and "cloudflare-dns" not in credential_cli
        and "Line3Mesh" not in credential_cli
        and "line3-mesh" not in credential_cli,
        "retired standalone DNS/Mesh operator CLI namespaces must stay absent; acceptance/production call typed internal functions directly",
    )
    require(
        "vultr-control-plane-production" not in router,
        "router and skipped comments must never occupy production concurrency",
    )

    require(
        "issues: read" not in vultr
        and vultr.count("issues: write") == 3
        and "issues: read" not in credentials
        and "issues: write" not in credentials
        and "  vultr:" in router
        and "    permissions:\n      contents: read\n      actions: read\n      issues: write" in router
        and "    uses: ./.github/workflows/vultr-acceptance-resume.yml" in vultr
        and "      actions: read" in vultr,
        "Issue #26 BEGIN and reboot may be written only by scoped authorized Vultr initial/resume owners",
    )
    require(
        "startsWith(github.event.comment.body, '/vm ')" in router
        and "issues: write" not in router.split("  application:\n", 1)[1].split("\n  production:", 1)[0],
        "universal Git VM route must preserve caller, comment and least-privilege gates",
    )
    require(
        "permissions:\n  contents: read\n" in router,
        "router must grant only read-only contents permission required by reusable backends",
    )
    require(
        "contents: write" not in router and "actions: write" not in router,
        "router must not gain write permissions",
    )

    for name, backend in [
        ("application", application),
        ("vultr", vultr),
        ("vpc", vpc),
    ]:
        require(
            "edge-orchestrator-linux-amd64" in backend
            and "EDGE_ORCHESTRATOR_SHA256" in backend,
            f"{name} backend must execute the exact immutable edge-orchestrator",
        )
        require(
            "edge-controller-linux-amd64" not in backend,
            f"{name} backend must not execute Linux edge-controller as provider owner",
        )
        require(
            "EDGE_RELEASE_CONTEXT_PATH" in backend,
            f"{name} backend must pass one exact resolved ReleaseSet context into edge-orchestrator",
        )
        require(
            "COMMENT_BODY: ${{ inputs.command_body }}" in backend,
            f"{name} backend must parse only the router-provided command body",
        )
        require(
            "github.event.comment.body" not in backend,
            f"{name} backend must not depend on issue_comment event payloads",
        )
        require(
            "group: vultr-control-plane-production" in backend,
            f"{name} mutation backend must retain shared production concurrency",
        )
        require(
            "\n  verify:\n" not in backend,
            f"{name} backend must resolve its immutable ReleaseSet only in the actual command job",
        )

    require(
        '"credential-inventory"' not in application
        and '"credential-plan"' not in application
        and '"credential-converge"' not in application
        and '"credential-verify"' not in application
        and '"credential-prove"' not in application
        and 'command_family = "production_credentials"' not in application
        and "  production_credentials:\n" not in application,
        "transitional Phase 2 credential commands must be retired after production authority cutover",
    )
    require(
        '("/credentials", "verify"): "verify"' in credentials
        and '("/credentials", "host-bootstrap-converge"): "host-bootstrap-converge"' in credentials
        and 'tokens[0:2] == ["/credentials", "rotate"]' in credentials
        and '"tunnel-auth", "reality-identity", "line2-proxy-auth"' in credentials
        and 'operation = "rotate-application"' in credentials
        and '"contract-plan"' not in credentials
        and '"contract-converge"' not in credentials
        and '"contract-prove"' not in credentials
        and "ContractPlan" not in credential_cli
        and "ContractConverge" not in credential_cli
        and "ContractProve" not in credential_cli
        and "FreshV2Publish" not in credential_cli
        and "FreshV2RestoreBaseline" not in credential_cli
        and "async fn converge(" not in credential_command
        and "async fn prove(" not in credential_command
        and "fresh_v2_publish" not in credential_command
        and "fresh_v2_restore_baseline" not in credential_command
        and '"fresh-v2-cutover"' not in credentials
        and '"fresh-v2-publication-prove"' not in credentials
        and '"fresh-v2-cleanup"' not in credentials
        and '"${EDGE_CREDENTIAL_ORCHESTRATOR}" credentials contract-verify' in credentials
        and '"retire-proof-tokens"' not in credentials
        and "RetireProofTokens" not in credential_cli
        and "initial_windows_acceptance_cleanup" in credential_command
        and 'cloudflare::delete_access_service_token(' in credential_command
        and "RetireProofTokens" not in credential_command
        and "credentials rotate-application" in credentials
        and "credential-transition drop-previous" in credentials
        and "credential-transition apply-candidate" in credentials
        and "credential-transition apply-active" in credentials
        and "credential-transition promote" in credentials
        and "credential-transition rollback-previous" in credentials
        and "group: vultr-control-plane-production" in credentials
        and "group: credential-transaction-${{ github.repository_id }}" in credentials
        and "cancel-in-progress: false" in credentials
        and "CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN" in credentials
        and "credential_rotation_delivery=CLASS_SCOPED_DELTA" in credentials
        and "active_credential_plaintext_readback=false" in credentials
        and "candidate_data_plane_reobservation=LOCAL_OWNERS" in credentials
        and "VULTR_API_KEY" not in credentials
        and "VULTR_SSH_PRIVATE_KEY" not in credentials
        and "CLOUDFLARE_API_TOKEN" not in credentials
        and "CLOUDFLARE_DNS_TOKEN" not in credentials
        and "api.ipify.org" not in credentials
        and "lease-acquire" not in credentials
        and "lease-release" not in credentials
        and "actions/upload-artifact" not in credentials
        and "actions/cache" not in credentials,
        "credential operator must retain no Stage-3 proof-token retirement; only run-scoped first-use acceptance revoke is allowed",
    )

    rotation_workflow = credentials.split("  rotate_release:\n", 1)[1].split(
        "  host_bootstrap_release:\n", 1
    )[0]
    require(
        "CLOUDFLARE_VM_ACCESS_CLIENT_ID" not in rotation_workflow
        and "CLOUDFLARE_VM_ACCESS_CLIENT_SECRET" not in rotation_workflow
        and "fetch_active_vm_bundle_with_bounded_proof" not in credential_command
        and "fetch_canonical_credential_bundle_with_identity" not in credential_command
        and "credential_rotation_delivery=CLASS_SCOPED_DELTA" in rotation_workflow
        and "active_credential_plaintext_readback=false" in rotation_workflow,
        "application rotation must publish only the selected typed class delta and must never read back the active credential plaintext",
    )

    require(
        "ROTATION_VM_UNCOMMITTED_RECOVERY=ACTIVE_RESTORED" in rotation_workflow
        and "ROTATION_WINDOWS_UNCOMMITTED_RECOVERY=ACTIVE_RESTORED" in rotation_workflow
        and "half-promoted recovery requires explicit diagnosis" in rotation_workflow
        and "credential-transition apply-active" in rotation_workflow
        and "credential-transition discard-candidate" in rotation_workflow,
        "application rotation must recover only observed uncommitted candidates and fail closed on half-promoted cross-host state",
    )

    require(
        "proven_unchanged: ${{ steps.promote.outputs.proven_unchanged }}" in rotation_workflow
        and "VM_ROTATION_PROMOTE=PROVEN_UNCHANGED_AFTER_BOUNDED_RETRY" in rotation_workflow
        and "needs.rotate_vm_promote.outputs.proven_unchanged == 'true'" in rotation_workflow
        and "no automatic cross-host compensation is authorized" in rotation_workflow,
        "cross-host credential promotion compensation must run only after the VM owner proves the promotion remained unchanged; uncertain outcomes must fail closed",
    )

    rotation_jobs = re.findall(r"^  rotate_[a-z0-9_]+:$", rotation_workflow, re.MULTILINE)
    require(
        len(rotation_jobs) <= 12
        and "  rotate_vm_admit:\n" not in rotation_workflow
        and "  rotate_windows_admit:\n" not in rotation_workflow
        and "  rotate_vm_recover_uncommitted:\n" not in rotation_workflow
        and "  rotate_windows_recover_uncommitted:\n" not in rotation_workflow
        and "  rotate_vm_retire_previous:\n" not in rotation_workflow
        and "  rotate_windows_retire_previous:\n" not in rotation_workflow
        and "  rotate_windows_prepare:\n" in rotation_workflow
        and "  rotate_vm_prepare:\n" in rotation_workflow
        and "  rotate_windows_stage:\n" in rotation_workflow
        and "  rotate_vm_candidate:\n" in rotation_workflow,
        "steady-state credential rotation must keep cross-host barriers explicit without expanding into redundant admission/recovery micro-jobs",
    )

    host_bootstrap_workflow = credentials.split("  host_bootstrap_release:\n", 1)[1]
    host_bootstrap_start = credential_command.index("async fn host_bootstrap_converge(")
    host_bootstrap_end = credential_command.index("fn plan(", host_bootstrap_start)
    host_bootstrap = credential_command[host_bootstrap_start:host_bootstrap_end]
    require(
        '"host-bootstrap-converge"' in credentials
        and host_bootstrap_workflow.count("sing-box-windows-lab") == 2
        and "CMS/RFC5652 ciphertext only" in credentials
        and "CLOUDFLARE_WINDOWS_ACCESS_CLIENT_ID" in credentials
        and "CLOUDFLARE_WINDOWS_ACCESS_CLIENT_SECRET" in credentials
        and "CLOUDFLARE_VM_ACCESS_CLIENT_ID" in credentials
        and "CLOUDFLARE_VM_ACCESS_CLIENT_SECRET" in credentials
        and "WINDOWS_BOOTSTRAP_ESCROW=DELETED" in credentials
        and "EDGE_RELEASE_CONTEXT_PATH" in credentials
        and "rotate_access_service_token(" not in host_bootstrap
        and "actions/upload-artifact" not in credentials
        and "actions/download-artifact" not in credentials,
        "host identity bootstrap must remain create-once, retry-safe, runner-blind, ciphertext-only on Windows and artifact-free",
    )
    require(
        "  cutover_release:\n" not in credentials
        and "cutover_publish:" not in credentials
        and "cutover_final_verify:" not in credentials
        and "STAGE2_FRESH_V2_CUTOVER=PASS" not in credentials,
        "terminal Stage-2 cutover/proof workflow branches must be deleted after accepted cutover",
    )

    require(
        '"target-plane-inventory"' not in application
        and '"target-plane-plan"' not in application
        and '"target-plane-converge"' not in application
        and '"target-plane-verify"' not in application
        and 'command_family = "production_target_plane"' not in application
        and "  production_target_plane:\n" not in application,
        "provider target-plane logic may remain internal, but its public transitional operator surface must be retired",
    )
    require(
        application.count("group: vultr-control-plane-production") == 6
        and "  mesh_profile:\n" in application
        and "needs.authorize.outputs.command_family == 'mesh_profile'" in application
        and 'cloudflare-target-plane acceptance-profile plan' in application
        and 'cloudflare-target-plane acceptance-profile verify' in application
        and 'cloudflare-target-plane acceptance-profile apply' in application
        and '[[ "${EDGE_PLAN_AUTHORITY}" =~ ^[0-9a-f]{64}$ ]]' in application,
        "existing application owner must serialize exact scoped Mesh-profile lifecycle with all provider, production, cleanup and disposable jobs",
    )
    production_observe = application.split("  production_observe:\n", 1)[1].split(
        "\n  production_runtime:", 1
    )[0]
    require(
        '"${EDGE_APPLICATION_ORCHESTRATOR}" production diagnose' in production_observe
        and "cloudflare-production-inventory.txt" in production_observe
        and "~~~text" in production_observe
        and "CLOUDFLARE_API_TOKEN" not in production_observe
        and "CLOUDFLARE_CONTROL_TOKEN: ${{ secrets.CLOUDFLARE_CONTROL_TOKEN }}" in production_observe
        and "CLOUDFLARE_DNS_TOKEN: ${{ secrets.CLOUDFLARE_DNS_TOKEN }}" in production_observe
        and "CLOUDFLARE_TARGET_ACCOUNT_ID" not in production_observe
        and "jq " not in production_observe
        and ".mutations_performed" not in production_observe
        and ".observation_status" not in production_observe
        and "cloudflare-phase0-inventory.json" not in production_observe
        and "VULTR_API_KEY" not in production_observe
        and "VULTR_SSH_PRIVATE_KEY" not in production_observe
        and "EDGE_SSH_PRIVATE_KEY_PATH" not in production_observe
        and "api.ipify.org" not in production_observe
        and "lease-acquire" not in production_observe
        and "lease-release" not in production_observe,
        "production diagnose workflow must remain a thin GET-only wrapper: no jq/JSON lifecycle semantics and no Vultr/SSH authority",
    )
    require(
        "retire-historical-" not in application
        and "production_historical_retirement" not in application
        and "CLOUDFLARE_HISTORICAL_RETIRE_TOKEN" not in application,
        "terminal historical retirement operator surface and temporary write authority must stay deleted",
    )
    require(
        "serde_json::to_string" not in production_inventory
        and "serde::Serialize" not in production_inventory
        and "list_membership_accounts" not in production_inventory
        and "CLOUDFLARE_API_TOKEN" not in production_inventory
        and "CLOUDFLARE_TARGET_ACCOUNT_ID" not in production_inventory
        and "CLOUDFLARE_CONTROL_TOKEN" in production_inventory
        and "CLOUDFLARE_DNS_TOKEN" in production_inventory
        and "current_account_id" in production_inventory
        and "shared_dns_account_id" in production_inventory
        and "migration_target_present" in production_inventory
        and "Cloudflare production inventory BLOCKED by" in production_inventory
        and 'println!("{inventory:#?}")' in production_inventory,
        "steady-state production inventory owner must observe current account + shared DNS without historical migration authority or a first-party JSON contract",
    )

    require(
        vultr.count("group: vultr-control-plane-production") == 2
        and "initial_cleanup:" in vultr
        and "needs: [authorize, execute, initial_acceptance_verdict]" in vultr,
        "Vultr execute and first-use disposable cleanup must share the exact single-owner lock",
    )
    require(
        "runs-on:" in windows_physical
        and "- self-hosted" in windows_physical
        and "- Windows" in windows_physical
        and "- X64" in windows_physical
        and "- sing-box-windows-lab" in windows_physical,
        "Windows physical cycle must target only the dedicated repository runner",
    )
    require(
        "PRIVILEGED_SHORT_WAIT_SECS" in windows_console
        and "PRIVILEGED_ACTIVATE_WAIT_SECS" in windows_console
        and "RELEASE_CONVERGED_REOBSERVED" in windows_console
        and "do not retry blindly" in windows_console
        and "1790862397323-17868" not in windows_physical
        and "STALE_RUNTIME_EVIDENCE_REQUEST" not in windows_physical,
        "Windows privileged activation must use operation-specific completion reconciliation without incident-specific stale-request cleanup",
    )
    require(
        "sync_local_config_from_runtime_state" not in edge_local_runtime
        and "decode_windows_runtime_state" in edge_local_runtime
        and "is_typed_runtime_state" in edge_local_runtime,
        "typed Windows runtime config must be validated/launched as already rendered; legacy semantic sync must not regain typed-config ownership",
    )
    require(
        'test "$CONTROL_PROTECTED" = "true"' in windows_physical
        and "github.ref_protected" in windows_physical
        and "edge-platform/scripts/resolve_durable_release.sh" in windows_physical
        and "C:\\sing-box" in windows_physical
        and "privileged-activate" in windows_physical
        and "privileged-reinstall-accepted" in windows_physical
        and "privileged-rollback-previous" in windows_physical
        and "EDGE_CURRENT_CONSOLE" in windows_physical
        and "edge-diagnostic.exe" in windows_physical
        and "EDGE_RELEASE_TAG" not in windows_physical
        and "EDGE_WINDOWS_ARTIFACT_SHA256" not in windows_physical
        and "EDGE_WINDOWS_DIAGNOSTIC_SHA256" not in windows_physical
        and "EDGE_REPOSITORY" not in windows_physical
        and "edge-target-diagnostic-" not in windows_physical
        and "Target Windows artifact digest mismatch" not in windows_physical
        and "Target Windows diagnostic digest mismatch" not in windows_physical
        and "EdgePlatformController" in windows_physical
        and "NT SERVICE\\EdgePlatformController" in windows_physical
        and "Get-CimInstance Win32_Service" not in windows_physical
        and "scm_executable_path" in windows_physical
        and "scm_executable_matches_release" in windows_physical
        and "$bootstrapDoctor | Write-Host" in windows_physical
        and "$doctor | Write-Host" in windows_physical
        and "controller_path" in windows_physical
        and "controller_running=true" not in windows_physical
        and "Runner unexpectedly has direct private-state access" in windows_physical
        and "smoke-runtime" not in windows_physical
        and "http://127.0.0.1:45151" in windows_physical
        and "install-windows-release.ps1" not in windows_physical
        and "-ReleaseOnly" not in windows_physical
        and "External sing-box owner changed" in windows_physical
        and "managed_tun_present" in windows_physical,
        "Windows lifecycle must preserve protected-main ReleaseSet authority, privileged SYSTEM mutation, exact SCM ownership and transport-only runner isolation",
    )
    require(
        "workflow_dispatch:" not in windows_physical
        and "pull_request:" not in windows_physical
        and "pull_request_target:" not in windows_physical
        and "cargo build" not in windows_physical
        and "cargo run" not in windows_physical
        and "rustc " not in windows_physical
        and "VULTR_API_KEY" not in windows_physical
        and "CLOUDFLARE_API_TOKEN" not in windows_physical
        and "LegacyRuntimeStatePath" not in windows_physical
        and "LegacySingBoxConfigPath" not in windows_physical,
        "Windows runner must have no untrusted trigger, local build, provider credential, or legacy-state migration path",
    )
    require(
        'RunnerRoot = "C:\\sing-box-runner"' in windows_runner_bootstrap
        and 'ApplicationRoot = "C:\\sing-box"' in windows_runner_bootstrap
        and '[string]$AcceptedRevision' in windows_runner_bootstrap
        and '[string]$ReleaseSetSha256' in windows_runner_bootstrap
        and 'Assert-MainProtected' in windows_runner_bootstrap
        and 'if (-not [bool]$branch.protected)' in windows_runner_bootstrap
        and 'Install-InitialApplicationAuthority' in windows_runner_bootstrap
        and 'Converge-ControllerService' in windows_runner_bootstrap
        and 'privileged-converge-controller-service' in windows_runner_bootstrap
        and 'Configure-ApplicationAcl' not in windows_runner_bootstrap
        and 'icacls.exe' not in windows_runner_bootstrap
        and 'Register-PrivilegedDispatcher' in windows_runner_bootstrap
        and 'EdgePlatformPrivilegedDispatch' in windows_runner_bootstrap
        and 'New-ScheduledTaskPrincipal' in windows_runner_bootstrap
        and '$SystemSid = "S-1-5-18"' in windows_runner_bootstrap
        and '$NetworkServiceSid = "S-1-5-20"' in windows_runner_bootstrap
        and 'Resolve-IdentitySid' in windows_runner_bootstrap
        and '-UserId $SystemSid' in windows_runner_bootstrap
        and 'runner_application_access=TRANSPORT_ONLY' in windows_runner_bootstrap
        and 'controller_service=EdgePlatformController' in windows_runner_bootstrap
        and 'controller_start_owner=windows_scm' in windows_runner_bootstrap
        and 'secret_authority=controller_service' in windows_runner_bootstrap
        and 'RunnerVersion = "2.337.0"' in windows_runner_bootstrap
        and '1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc' in windows_runner_bootstrap
        and '--labels $RunnerLabel' in windows_runner_bootstrap
        and '--runasservice' in windows_runner_bootstrap
        and '--windowslogonaccount $RunnerServiceAccount' in windows_runner_bootstrap
        and 'Translate([Security.Principal.NTAccount])' in windows_runner_bootstrap
        and 'runner_identity_sid=$NetworkServiceSid' in windows_runner_bootstrap
        and '--disableupdate' not in windows_runner_bootstrap
        and 'runner_update_policy=github_auto' in windows_runner_bootstrap
        and "-ReleaseOnly" not in windows_runner_bootstrap,
        "Windows bootstrap must delegate application ACL/service ownership to one native controller convergence path while keeping the runner transport-only",
    )
    require(
        "cargo " not in windows_runner_bootstrap
        and "rustup" not in windows_runner_bootstrap
        and "winget" not in windows_runner_bootstrap
        and "gh.exe" not in windows_runner_bootstrap
        and "VULTR_API_KEY" not in windows_runner_bootstrap
        and "CLOUDFLARE_API_TOKEN" not in windows_runner_bootstrap,
        "physical Windows runner bootstrap must not install build toolchains or provider authority",
    )
    runner_cli_args = credential_cli.split(
        "pub(crate) struct VultrRunnerBootstrapArgs {", 1
    )[1].split("}", 1)[0]
    runner_cli_transport = credential_cli.split(
        "Self::RunnerBootstrap(args) => vec![", 1
    )[1].split("],", 1)[0]
    runner_native_handler = vultr_lifecycle_command.split(
        "async fn run_runner_bootstrap(", 1
    )[1].split("pub(crate) async fn bootstrap_production_runner(", 1)[0]
    require(
        "pub local_owner_artifact_path: PathBuf" in runner_cli_args
        and "path(args.local_owner_artifact_path)" in runner_cli_transport
        and "if args.len() != 4" in runner_native_handler
        and "Path::new(&args[3])" in runner_native_handler
        and 'run_lifecycle runner-bootstrap "${spec}" "${machine}"' in vultr
        and '"${RUNNER_TEMP}/edge-platform-release/edge-agent-linux-amd64"' in vultr
        and "needs.authorize.outputs.operation == 'runner-bootstrap') && secrets.CLOUDFLARE_VM_ACCESS_CLIENT_ID" in vultr
        and "needs.authorize.outputs.operation == 'runner-bootstrap') && secrets.CLOUDFLARE_VM_ACCESS_CLIENT_SECRET" in vultr,
        "runner bootstrap must match the 4-argument typed owner and deliver VM Access identity only during bounded native enrollment",
    )
    require(
        'verb == "runner-bootstrap" and len(tokens) == 4' in vultr
        and '"runner-bootstrap"' in vultr
        and "IAMAMAN11_SING_BOX_CONTROL_PLANE_TOKEN" in vultr
        and "/actions/runners/registration-token" in vultr
        and 'run_lifecycle runner-bootstrap "${spec}" "${machine}"' in vultr
        and "install-vultr-production-runner.sh" in vultr
        and "edge-agent-linux-amd64" in vultr,
        "Vultr lifecycle must bootstrap the bounded production VM runner with the exact ReleaseSet local owner using a short-lived registration token",
    )


    require(
        'verb == "action-plan" and len(tokens) == 5' in vultr
        and '"action-plan"' in vultr
        and '"apply"' in vultr
        and '"action"' in vultr
        and 'action-plan)' in vultr
        and 'run_lifecycle action-plan "${spec}" "${machine}" "${INSTANCE_ACTION}" | tee "${RUNNER_TEMP}/result.json"' in vultr,
        "Vultr backend must expose the existing typed read-only instance action plan through the sole router",
    )
    require(
        vultr.count('cat "${RUNNER_TEMP}/post-start-substrate.json" >&2') == 1
        and vultr.count('cat "${RUNNER_TEMP}/post-reboot-substrate.json" >&2') == 1
        and vultr.count('cat "${RUNNER_TEMP}/apply-noop-substrate.json" >&2') == 1
        and vultr.count('cat "${verify_output}" >&2') == 1
        and "if ! run_lifecycle substrate-verify" in vultr,
        "native disposable substrate failure evidence must reach GH Actions before cleanup without retry",
    )
    reboot_observation = vultr_lifecycle_command.split(
        "let reboot_probe = if action == InstanceAction::Reboot {", 1
    )[1].split("let next_plan = if matches!", 1)[0]
    require(
        "disposable_reboot_preflight_forensics=" in reboot_observation
        and "disposable_reboot_post_observation_forensics=" in reboot_observation
        and reboot_observation.count("acceptance_ssh_failure_forensics(") == 2
        and "reboot rejected before provider mutation" in reboot_observation
        and "no reboot replay" in reboot_observation
        and vultr.count('cat "${RUNNER_TEMP}/reboot.json" >&2') == 1,
        "disposable reboot must surface native pre/post SSH evidence and never replay ambiguous mutation",
    )
    substrate_verify = vultr_lifecycle_command.split(
        "async fn run_substrate_verify(", 1
    )[1].split("async fn run_transport_proof(", 1)[0]
    require(
        "is_disposable_ssh_forensic_target(&desired.environment, &args[1])"
        in substrate_verify
        and "acceptance_ssh_failure_forensics(Path::new(&args[0]), &args[1])"
        in substrate_verify
        and substrate_verify.count("disposable_ssh_failure_forensics=") == 2
        and "is_disposable_ssh_forensic_target(environment: &str, machine_id: &str)"
        in vultr_lifecycle_command
        and '("lifecycle-acceptance", "lifecycle-acceptance-1")'
        in vultr_lifecycle_command
        and "mutations_performed" in vultr_lifecycle_command
        and "capture_ssh_transport_stage_once(" in vultr_lifecycle_command,
        "disposable lifecycle SSH failure must expose native typed read-only phase evidence before cleanup",
    )
    require(
        vpc.count("group: vultr-control-plane-production") == 1,
        "VPC backend must serialize its execute mutation job",
    )
    require(
        "edge-platform/scripts/resolve_durable_release.sh" in vpc,
        "staged VPC substrate backend must consume the durable accepted ReleaseSet",
    )
    require(
        '"attachment-apply"' in vpc
        and "vultr-vpc attachment-plan" in vpc
        and "vultr-vpc attachment-apply" in vpc
        and "vultr-vpc verify" in vpc,
        "VPC backend must retain staged attachment authority and verification",
    )
    require(
        "vultr-lifecycle lease-acquire" in vpc
        and "vultr-lifecycle lease-release" in vpc
        and "ACCESS_CLEANUP_ARMED=1" in vpc,
        "VPC guest mutation must use the typed transient SSH lease with armed cleanup",
    )
    require(
        "acquire-access-plan" not in vpc and "release-access-plan" not in vpc,
        "VPC workflow must not own transient-access PlanAuthority plumbing",
    )
    require(
        'run_lifecycle lease-acquire "${spec}" "${machine}"' in vultr
        and 'run_lifecycle lease-release "${spec}" "${machine}"' in vultr,
        "Vultr workflow host operations must use the typed transient SSH lease",
    )
    require(
        "release_transient_access_exact" in vultr_lifecycle_command
        and vultr_lifecycle_command.count("acquire_transient_access_ready_exact") >= 3
        and "transient support access compensated" in vultr_lifecycle_command
        and "transient support access compensation failed" in vultr_lifecycle_command,
        "all typed support-access lease acquisition paths must share compensated readiness semantics",
    )
    require(
        'if [[ "${INSTANCE_ACTION}" == "reboot" ]]' not in vultr
        and '"action-reboot"' not in vultr
        and 'run_lifecycle action "${spec}" "${machine}" "${INSTANCE_ACTION}" "${authority}" | tee "${RUNNER_TEMP}/result.json"' in vultr,
        "provider instance actions, including recovery reboot, must not depend on guest SSH",
    )
    require(
        "NOPASSWD:ALL" not in production_vm_runner_installer
        and "usermod -aG docker" not in production_vm_runner_installer
        and "sing-box-production-vm" in production_vm_runner_installer
        and "SING_BOX_RUNTIME_READ" in production_vm_runner_installer
        and "SING_BOX_RUNTIME_MUTATE" in production_vm_runner_installer
        and "${LOCAL_OWNER} local status" in production_vm_runner_installer
        and "${LOCAL_OWNER} local credential-admit *" not in production_vm_runner_installer
        and "${LOCAL_OWNER} local credential-stage *" in production_vm_runner_installer
        and "${LOCAL_OWNER} local bundle-verify" in production_vm_runner_installer
        and "${LOCAL_OWNER} local bundle-converge" in production_vm_runner_installer
        and "${LOCAL_OWNER} local bundle-rollback" in production_vm_runner_installer
        and "${LOCAL_OWNER} local bundle-verify" in production_vm_runner_installer.split("Cmnd_Alias SING_BOX_RUNTIME_READ =", 1)[1].split("\n", 1)[0]
        and "${LOCAL_OWNER} local credential-stage *" in production_vm_runner_installer.split("Cmnd_Alias SING_BOX_RUNTIME_MUTATE =", 1)[1].split("\n", 1)[0]
        and "${LOCAL_OWNER} local bundle-converge" in production_vm_runner_installer.split("Cmnd_Alias SING_BOX_RUNTIME_MUTATE =", 1)[1].split("\n", 1)[0]
        and "${LOCAL_OWNER} local bundle-rollback" in production_vm_runner_installer.split("Cmnd_Alias SING_BOX_RUNTIME_MUTATE =", 1)[1].split("\n", 1)[0]
        and "${LOCAL_OWNER} local bundle-rollback" not in production_vm_runner_installer.split("Cmnd_Alias SING_BOX_RUNTIME_READ =", 1)[1].split("\n", 1)[0]
        and "runner must not have direct Docker socket authority" in production_vm_runner_installer
        and "production enrollment must leave no edge-agent RPC listener on :50061" in production_vm_runner_installer
        and "acceptance_rpc_service_enabled" in vultr
        and "tcp_50061_listener" in vultr
        and "Verify self-hosted runner online" in vultr
        and '.status == "online"' in vultr
        and 'index("sing-box-production-vm")' in vultr
        and 'index("vultr-root")) == null' in vultr
        and 'index($machine)' in vultr,
        "production VM runner bootstrap must be bounded, Docker-socket blind, and verified through the GitHub runner API",
    )
    vm_stage2_owner_commands = set(
        re.findall(r'sudo -n "\$\{owner\}" local ([a-z0-9-]+)', credentials)
    )
    vm_sudoers_owner_commands = set(
        re.findall(
            r'\$\{LOCAL_OWNER\} local ([a-z0-9-]+)',
            production_vm_runner_installer,
        )
    )
    require(
        vm_stage2_owner_commands <= vm_sudoers_owner_commands,
        "every Stage 2 VM sudo local-owner command must be installed in the production runner sudoers allowlist",
    )
    require(
        'verb == "access-release" and len(tokens) == 4' in vultr
        and 'operation, spec_path, machine_id = "access-release", tokens[2], tokens[3]' in vultr
        and "access-release)" in vultr
        and 'release_host_access "${spec}" "${machine}" "explicit"' in vultr
        and '.status == "RELEASED"' in vultr
        and '.access.next_plan.action == "NOOP"' in vultr
        and '(.access.next_plan.matching_rule_ids | length) == 0' in vultr
        and '.access.verified_absent == true' not in vultr,
        "Vultr backend must accept the typed lease-release NOOP absence proof without depending on an internal verified_absent field",
    )
    require(
        'production_destroy = (' in vultr
        and 'spec_path == "infra/production/production.textproto"' in vultr
        and 'machine_id == "production-1"' in vultr
        and 'operation in {"destroy-plan", "destroy-apply"}' in vultr
        and 'if not production_destroy and (' in vultr
        and 'if spec_path == "infra/production/production.textproto" and not production_destroy:' in vultr,
        "production VM destroy must use only the exact canonical proto, exact machine and plan/apply pair",
    )
    require(
        '"cleanup-plan"' in vultr
        and "cleanup-plan)" in vultr
        and 'run_lifecycle cleanup-plan "${spec}" | tee "${RUNNER_TEMP}/result.json"' in vultr
        and '.plan.environment_in_use | type == "boolean"' in vultr,
        "Vultr backend must expose the existing typed read-only support cleanup plan",
    )
    require(
        "acquire-access-plan" not in vultr and "release-access-plan" not in vultr,
        "Vultr workflow must not own transient-access PlanAuthority plumbing",
    )
    production_enroll = application.split("\n  production_enroll:\n", 1)[1].split(
        "\n  production_provider:", 1
    )[0]
    production_provider = application.split("\n  production_provider:\n", 1)[1].split(
        "\n  production_observe:", 1
    )[0]
    production_runtime = application.split("\n  production_runtime:\n", 1)[1].split(
        "\n  cleanup:", 1
    )[0]
    require(
        'tokens[0] == "/production"' in application
        and '"enroll-runtime",' in application
        and '"converge",' in application
        and '"verify",' in application
        and '"diagnose",' in application
        and '"rollback",' in application
        and 'spec_path = "infra/production/production.textproto"' in application,
        "production grammar must expose only the accepted steady-state surface plus explicit enrollment",
    )
    require(
        "\n  execute:\n" not in application
        and "\n  production:\n" not in application
        and '"plan", "apply", "verify", "upgrade"' not in application,
        "retired hosted SSH application/production jobs and manual application mutation grammar must be absent",
    )
    require(
        "runs-on: ubuntu-24.04" in production_enroll
        and "production enroll-runtime" in production_enroll
        and "VULTR_SSH_PRIVATE_KEY: ${{ secrets.VULTR_SSH_PRIVATE_KEY }}" in production_enroll
        and "IAMAMAN11_SING_BOX_CONTROL_PLANE_TOKEN: ${{ secrets.IAMAMAN11_SING_BOX_CONTROL_PLANE_TOKEN }}" in production_enroll
        and "VULTR_API_KEY: ${{ secrets.VULTR_API_KEY }}" in production_enroll
        and "api.ipify.org" in production_enroll
        and "EDGE_RUNNER_REGISTRATION_TOKEN" in production_enroll
        and "install-vultr-production-runner.sh" in production_enroll
        and "EDGE_DOCKER_ENGINE_VERSION" in production_enroll
        and "EDGE_CONTAINERD_VERSION" in production_enroll
        and "EDGE_COMPOSE_VERSION" in production_enroll
        and "steady_state_transport=GITHUB_SELF_HOSTED_RUNNER" in production_enroll
        and "CLOUDFLARE_CONTROL_TOKEN" not in production_enroll
        and "CLOUDFLARE_DNS_TOKEN" not in production_enroll,
        "production enrollment must be the sole bounded SSH bootstrap into the permanent self-hosted runtime transport",
    )
    require(
        "runs-on: ubuntu-24.04" in production_provider
        and production_provider.count("edge-platform/scripts/resolve_durable_release.sh") == 1
        and 'Read-only production DNS ownership gate' in production_provider
        and 'converge|verify|rollback)' in production_provider
        and '"${EDGE_PROVIDER_ORCHESTRATOR}" production dns-noop' in production_provider
        and "cloudflare-target-plane" not in production_provider
        and "active-converge" not in production_provider
        and "verify-active" not in production_provider
        and "grep -Fxq 'operation=PRODUCTION_DNS_NOOP'" in production_provider
        and "grep -Fxq 'provider_mutations=0'" in production_provider
        and "grep -Fxq 'production_runtime_mutations=0'" in production_provider
        and "CLOUDFLARE_CONTROL_TOKEN" not in production_provider
        and "CLOUDFLARE_DNS_TOKEN: ${{ secrets.CLOUDFLARE_DNS_TOKEN }}" in production_provider
        and "VULTR_API_KEY: ${{ secrets.VULTR_API_KEY }}" in production_provider
        and "VULTR_SSH_PRIVATE_KEY" not in production_provider
        and "api.ipify.org" not in production_provider
        and "lease-acquire" not in production_provider
        and "application_bundle_sha256" in production_provider
        and "application_bundle_asset_id" in production_provider
        and 'releases/tags/${EDGE_RELEASE_TAG}' in production_provider
        and 'select(.name == "application-bundle.pb")' in production_provider
        and "actions/upload-artifact" not in production_provider,
        "production provider plane must remain GitHub-hosted, verify the promoted ReleaseSet and export only exact immutable bundle identity",
    )
    # Run the actual Github authorization parser read-only against the
    # canonical manifest, plus rejects for missing specs and unsafe grammar.
    authorizer = application.split(
        "      - name: Parse and authorize typed request\n", 1
    )[1].split("          python3 <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
    authorizer = "\n".join(
        line[10:] if line.startswith("          ") else line
        for line in authorizer.splitlines()
    )
    for command, should_pass in [
        ("/vm diagnose infra/application/disposable-acceptance.json", True),
        ("/vm quality-line2 infra/application/disposable-acceptance.json", True),
        ("/vm credential-initial-probe infra/application/disposable-acceptance.json", True),
        ("/vm diagnose infra/application/unknown.json", False),
        ("/vm diagnose infra/application/../vultr/application-acceptance.json", False),
        ("/vm converge infra/application/disposable-acceptance.json", False),
    ]:
        with tempfile.NamedTemporaryFile() as output:
            env = dict(
                os.environ,
                COMMENT_BODY=command,
                GITHUB_OUTPUT=output.name,
            )
            result = subprocess.run(
                [sys.executable, "-c", authorizer],
                env=env, text=True, capture_output=True, timeout=10, check=False,
            )
            require(
                (result.returncode == 0) == should_pass,
                f"Git VM authorization unexpected result for {command}: {result.stderr}",
            )
            if should_pass:
                source = Path(output.name).read_text(encoding="utf-8")
                require(
                    "command_family=vm\n" in source
                    and "runtime_machine=application-acceptance-1\n" in source,
                    "canonical application spec must select exactly its Git-owned machine",
                )
    require(
        'len(tokens) == 3 and tokens[0] == "/vm"' in application
        and 'command_family = "vm"' in application
        and 'desired.get("machine_id", "")' in application
        and 'desired.get("vultr_spec_path", "")' in application
        and 'desired.get("application_profile") not in machine.get("application_profiles", [])' in application
        and 'len([m for m in machines if isinstance(m, dict) and m.get("id") == runtime_machine]) != 1' in application
        and 'git checkout --detach FETCH_HEAD' in application
        and '"credential-initial-probe",' in application
        and "needs.authorize.outputs.operation == 'credential-initial-probe'" in production_runtime
        and 'local_operation="credential-initial-probe"' in production_runtime
        and 'local credential-initial-probe' in PRODUCTION_VM_RUNNER_INSTALLER.read_text(encoding="utf-8")
        and "needs.authorize.outputs.command_family == 'vm'" in production_runtime
        and 'VM_RUNTIME_MACHINE: ${{ needs.authorize.outputs.runtime_machine }}' in production_runtime
        and 'vm_runtime_target=BLOCKED_INVALID_GIT_IDENTITY' in production_runtime
        and 'vm_runtime_target=BLOCKED_RUNNER_IDENTITY_MISMATCH' in production_runtime
        and 'RUNNER_NAME' in production_runtime
        and "production-1|application-acceptance-1)" not in production_runtime
        and 'command_family = "acceptance_vm"' not in application
        and 'runtime_machine = "application-acceptance-1"' not in application,
        "VM diagnostics must resolve any exact typed Git-owned resource and reject runner/provider identity drift",
    )
    require(
        "- self-hosted" in production_runtime
        and "- Linux" in production_runtime
        and "- X64" in production_runtime
        and "- sing-box-production-vm" in production_runtime
        and "- ${{ needs.authorize.outputs.runtime_machine }}" in production_runtime
        and 'owner="/usr/local/libexec/sing-box/edge-agent"' in production_runtime
        and "PROVIDER_APPLICATION_BUNDLE_SHA256" in production_runtime
        and "PROVIDER_APPLICATION_BUNDLE_ASSET_ID" in production_runtime
        and '/releases/assets/${PROVIDER_APPLICATION_BUNDLE_ASSET_ID}' in production_runtime
        and "--proto '=https'" in production_runtime
        and "--proto-redir '=https'" in production_runtime
        and "--connect-timeout 10" in production_runtime
        and "--max-time 60" in production_runtime
        and 'sha256sum "${bundle}"' in production_runtime
        and 'sudo -n "${owner}" local "${local_operation}" < "${EDGE_LOCAL_APPLICATION_BUNDLE}"' in production_runtime
        and 'local_operation="bundle-converge"' in production_runtime
        and 'local_operation="bundle-verify"' in production_runtime
        and 'local_operation="bundle-rollback"' in production_runtime
        and 'local_operation="diagnose"' in production_runtime
        and "retire-historical-" not in production_runtime
        and 'local_operation="bootstrap-full"' not in production_runtime
        and "edge-platform/scripts/resolve_durable_release.sh" not in production_runtime
        and "EDGE_LOCAL_ORCHESTRATOR" not in production_runtime
        and "application-lifecycle materialize" not in production_runtime
        and "actions/upload-artifact" not in production_runtime
        and "actions/download-artifact" not in production_runtime
        and "git init ." not in production_runtime
        and "git fetch " not in production_runtime
        and "git checkout " not in production_runtime
        and "/tarball/" not in production_runtime
        and "VULTR_API_KEY" not in production_runtime
        and "CLOUDFLARE_CONTROL_TOKEN" not in production_runtime
        and "CLOUDFLARE_DNS_TOKEN" not in production_runtime
        and "VULTR_SSH_PRIVATE_KEY" not in production_runtime
        and "api.ipify.org" not in production_runtime
        and "lease-acquire" not in production_runtime
        and "/var/run/docker.sock" in production_runtime
        and "sudo -n id -u" in production_runtime,
        "production runtime plane must remain transport-only: immutable ReleaseSet-bound bundle -> SHA verify -> fixed sudo local owner, with no source/render/provider/generic-root authority",
    )
    owner_preflight = production_runtime.split(
        "      - name: Verify bounded local runtime authority", 1
    )[1].split("      - name: Verify exact transported application bundle", 1)[0]
    require(
        "      - production_observe" not in production_runtime.split("    if:", 1)[0]
        and "needs.production_observe.result" not in production_runtime
        and "OBSERVE_AGENT_SHA256" not in production_runtime
        and "OBSERVE_RELEASE_SET_SHA256" not in production_runtime
        and "needs.authorize.outputs.operation == 'diagnose' ||" in production_runtime
        and "needs.authorize.outputs.operation == 'quality-line2' ||" in production_runtime,
        "native VM read-only observation must run in parallel with provider inventory",
    )
    require(
        "vm_owner_identity=PASS_NATIVE_INSTALLED_READONLY" in owner_preflight
        and "vm_owner_identity=BLOCKED_INSTALLED_OWNER_PATH" in owner_preflight
        and "vm_owner_identity=BLOCKED_INSTALLED_OWNER_FILESYSTEM_TRUST" in owner_preflight
        and "vm_owner_identity=BLOCKED_OWNER_DIGEST_UNAVAILABLE" in owner_preflight
        and "vm_owner_identity=BLOCKED_INSTALLED_OWNER_MISMATCH" in owner_preflight
        and "vm_owner_identity=PASS_EXACT_ACCEPTED_OWNER" in owner_preflight
        and 'echo "vm_owner_observed_sha256=${observed}"' in owner_preflight
        and "for path in /usr /usr/local /usr/local/libexec" in owner_preflight
        and 'if [[ ! -x "${owner}" || -L "${owner}" ]]; then' in owner_preflight
        and "diagnose|quality-line2|credential-initial-probe)" in owner_preflight
        and "converge|verify|rollback)" in owner_preflight
        and owner_preflight.index("vm_owner_identity=PASS_NATIVE_INSTALLED_READONLY")
        < owner_preflight.index("converge|verify|rollback)")
        and owner_preflight.index('if [[ "${observed}" != "${expected_owner}" ]]; then')
        < owner_preflight.index('sudo -n "${owner}" local status >/dev/null')
        and "curl " not in owner_preflight
        and "python3" not in owner_preflight
        and "ssh " not in owner_preflight,
        "VM native read-only observation must be version-independent; mutations remain exact accepted release",
    )
    require(
        "vm_credential_observation=PASS" in production_runtime
        and "vm_credential_observation=UNAVAILABLE" in production_runtime
        and "'^credential_(state_present|active_present|active_generation|active_slot|candidate_present|previous_present)='" in production_runtime
        and 'sudo -n "${owner}" local credential-state' in production_runtime,
        "production diagnose must expose only bounded VM credential generation state via the existing root owner",
    )
    require(
        "production_rollback_desired" not in production_command
        and "pub(crate) async fn rollback(" not in production_command,
        "steady-state production rollback must have no legacy orchestrator lease/SSH implementation",
    )
    # The actual operator path is GitHub provider preflight -> local VM owner.
    # The old hosted Rust mutation/verify path is duplicate ownership.
    require(
        "pub(crate) async fn converge(" not in production_command
        and "pub(crate) async fn verify(" not in production_command
        and "async fn verify_with_lease(" not in production_command
        and "pub(crate) async fn verify_dns_noop(" in production_command
        and "pub(crate) async fn enroll_runtime(" in production_command
        and "dns_verify_noop(spec, spec).await" in production_command
        and "production_command::converge" not in hosted_production_main
        and "production_command::verify(" not in hosted_production_main
        and "Converge(ProductionRuntimeArgs)" not in credential_cli
        and "Verify(ProductionRuntimeArgs)" not in credential_cli
        and "ProductionRuntimeArgs" not in credential_cli
        and "pub(crate) async fn production_converge_desired(" not in application_command
        and "pub(crate) async fn production_verify_desired(" not in application_command,
        "hosted production converge/verify and dead application helpers must stay retired; only GitHub native DNS gate + VM runtime owner may mutate",
    )

    acceptance_job = application.split("\n  acceptance:\n", 1)[1]
    cleanup_job = application.split("\n  cleanup:\n", 1)[1].split("\n  acceptance:\n", 1)[0]
    application_before_acceptance = application.split("\n  acceptance:\n", 1)[0]
    require(
        "  cleanup:\n    needs: authorize" in application
        and "  acceptance:\n    needs: authorize" in application
        and "  production_runtime:\n    needs:" in application,
        "steady-state production and disposable application commands must dispatch through explicit owners",
    )
    require(
        acceptance_job.count("edge-platform/scripts/resolve_durable_release.sh") == 1
        and "needs.verify.outputs.release_tag" not in acceptance_job,
        "acceptance job must perform exactly one durable ReleaseSet resolution",
    )
    require(
        acceptance_job.count('"${EDGE_APPLICATION_ORCHESTRATOR}" application-acceptance') == 1,
        "normal acceptance must invoke exactly one typed lifecycle coordinator",
    )
    require(
        "VULTR_SSH_PRIVATE_KEY: ${{ secrets.VULTR_SSH_PRIVATE_KEY }}" in acceptance_job
        and "api.ipify.org" in acceptance_job
        and "application-acceptance" in acceptance_job,
        "acceptance retains its disposable SSH bootstrap; persistent production SSH is isolated to explicit production enrollment",
    )
    require(
        cleanup_job.count("edge-platform/scripts/resolve_durable_release.sh") == 1
        and "needs.verify.outputs.release_tag" not in cleanup_job
        and cleanup_job.count('"${EDGE_APPLICATION_ORCHESTRATOR}" application-cleanup') == 1,
        "disposable cleanup must resolve one exact ReleaseSet and invoke exactly one typed cleanup coordinator",
    )
    require(
        "VULTR_SSH_PRIVATE_KEY" not in cleanup_job
        and "EDGE_SSH_PRIVATE_KEY_PATH" not in cleanup_job
        and "api.ipify.org" not in cleanup_job,
        "disposable cleanup recovery must not depend on guest SSH authority or controller egress discovery",
    )
    for forbidden in [
        "vultr-lifecycle apply ",
        "vultr-lifecycle substrate-plan ",
        "vultr-lifecycle substrate-apply ",
        "vultr-lifecycle lease-acquire ",
        "vultr-lifecycle action-plan ",
        "vultr-lifecycle action ",
        "vultr-lifecycle destroy-plan ",
        "vultr-lifecycle destroy-apply ",
        "vultr-lifecycle cleanup-plan ",
        "vultr-lifecycle cleanup ",
        "vultr-vpc ",
        "cloudflare-dns ",
        "line3-mesh ",
    ]:
        require(
            forbidden not in acceptance_job,
            f"acceptance workflow must not bypass the typed coordinator with direct domain lifecycle commands: {forbidden}",
        )
    require(
        acceptance_job.count('"${orchestrator}" application-lifecycle materialize') == 1,
        "acceptance may invoke exactly one local typed release-input materialization before the coordinator",
    )
    require(
        'operation_rc="${PIPESTATUS[0]}"' in acceptance_job
        and "application-acceptance-result.json" in acceptance_job,
        "acceptance workflow must preserve coordinator exit status and terminal certificate",
    )
    require(
        "acceptance_lease_acquire" in acceptance_coordinator
        and "acceptance_lease_release" in acceptance_coordinator
        and "acceptance_destroy_and_cleanup" in acceptance_coordinator
        and "FAIL_CLEANED" in acceptance_coordinator
        and "DIAGNOSTIC_REQUIRED" in acceptance_coordinator
        and 'zero_leaked_resources: "PASS"' in acceptance_coordinator,
        "typed acceptance coordinator must own lease-finally, compensation and terminal zero-leak classification",
    )
    require(
        "std::process::Command" not in acceptance_coordinator
        and "Command::new" not in acceptance_coordinator
        and "sh -c" not in acceptance_coordinator,
        "typed acceptance coordinator must compose owners in-process, never via shell/process replay",
    )
    require(
        application.count('"${orchestrator}" application-lifecycle materialize') == 1,
        "only disposable acceptance may materialize release inputs through the legacy remote application coordinator",
    )
    require(
        "EDGE_DOCKER_ENGINE_VERSION" in vpc
        and "EDGE_CONTAINERD_VERSION" in vpc
        and "EDGE_COMPOSE_VERSION" in vpc,
        "VPC host-substrate verification must bind exact ReleaseSet substrate versions",
    )
    require(
        "dns_create(&args.dns_spec_path, &args.spec_path)" in acceptance_coordinator
        and "dns_verify_noop(&args.dns_spec_path, &args.spec_path)" in acceptance_coordinator,
        "typed acceptance must keep DNS target derivation inside the existing internal DNS owner",
    )
    require(
        "vm_ip=" not in application and "vm_ip" not in acceptance_coordinator,
        "application acceptance must not own derived VM public-IP plumbing",
    )
    require(
        "vultr-vpc cleanup-plan" in vpc
        and vpc.count("vultr-vpc cleanup-apply") == 1
        and '"cleanup-plan", "cleanup-apply"' in vpc
        and '(.plan.action.kind == "DETACH_INSTANCE" or .plan.action.kind == "DELETE_VPC")' in vpc
        and 'destructive_digest="$(jq -er' in vpc
        and 'authority="$(plan_authority' in vpc
        and '.[1].performed.kind == .[0].plan.action.kind' in vpc,
        "VPC backend must expose one-at-a-time typed cleanup with fresh destructive digest and PlanAuthority",
    )
    require(
        "VPC_ID" not in vpc
        and "INSTANCE_ID" not in vpc,
        "VPC cleanup workflow must not accept raw provider identifiers as command authority",
    )

    acquire_pos = vpc.index("vpc-access-acquire.json")
    ready_pos = vpc.index("vpc-access-ready.json")
    attachment_plan_pos = vpc.index("vpc-attachment-plan.json")
    require(
        acquire_pos < ready_pos < attachment_plan_pos,
        "VPC backend must prove host substrate readiness after access acquisition and before attachment planning",
    )
    require(
        "vultr-lifecycle substrate-verify" in vpc
        and '.status == "PASS" and .plan.action == "NOOP"' in vpc,
        "VPC access readiness must use canonical read-only substrate verification",
    )

    require(
        "vpc_attach_and_verify" in acceptance_coordinator
        and "acceptance_verify_substrate" in acceptance_coordinator,
        "typed acceptance must retain VPC guest-readiness and host-substrate verification",
    )
    require(
        acceptance_coordinator.count("acceptance_reboot(vultr_spec, machine_id)") == 1,
        "typed acceptance must retain exactly one explicit reboot for persistence verification",
    )
    require(
        "context.release().accepted_revision.as_str()" in acceptance_coordinator
        and "GITHUB_SHA" not in acceptance_coordinator,
        "typed acceptance destroy authority must come from validated ReleaseSet accepted revision",
    )
    require(
        '"${EDGE_PROVIDER_ORCHESTRATOR}" production dns-noop' in production_provider
        and "MeshVerify" in vm_agent_cli
        and "MeshCleanup" in vm_agent_cli
        and 'local_operation="bundle-converge"' in production_runtime
        and edge_platform_ci.count("application-bundle-build") == 2
        and "export-bundle" not in application
        and "VULTR_SSH_PRIVATE_KEY" not in production_runtime,
        "Optional Mesh must be independent: GitHub provider DNS NOOP, candidate-only application bundle, and local VM runtime owner",
    )

    orchestrator_manifest = Path("edge-platform/crates/edge-orchestrator/Cargo.toml").read_text(
        encoding="utf-8"
    )
    require(
        "runtime_input_sha256" in edge_platform_ci
        and "runtime_input_digest.py compute" in edge_platform_ci
        and "runtime_input_digest.py decide" in edge_platform_ci
        and "python3 edge-platform/scripts/test_runtime_input_digest.py" in edge_platform_ci,
        "candidate CI must derive, test, and consume one conservative VM runtime input identity",
    )
    require(
        edge_platform_ci.count("bash edge-platform/scripts/resolve_durable_release.sh") == 1
        and "Store exact accepted VM runtime reuse bytes" in edge_platform_ci
        and "Materialize exact accepted VM runtime reuse bytes" in edge_platform_ci
        and "Resolve exact accepted VM runtime reuse" not in edge_platform_ci,
        "candidate CI must resolve the accepted base once and transport only exact verified reuse bytes to the Linux job",
    )
    require(
        'base_release_revision="${BASE_REVISION}"' in edge_platform_ci
        and 'current_release_count="$(gh api "repos/${REPOSITORY}/releases?per_page=100"' in edge_platform_ci
        and 'test "$(jq -er \'.parents | length\' <<<"${base_commit}")" = "2"' in edge_platform_ci
        and 'base_release_revision="$(jq -er \'.parents[0].sha\' <<<"${base_commit}")"' in edge_platform_ci
        and 'ACCEPTED_REVISION="${base_release_revision}" OUTPUT_DIR="${base_dir}"' in edge_platform_ci
        and 'candidate_base_release=VERIFIED_IMMEDIATE_MERGE_PARENT' in edge_platform_ci,
        "candidate input reuse may recover only through a verified published immediate main merge-parent",
    )
    require(
        'runtime_source_revision="${EDGE_RUNTIME_SOURCE_REVISION}"' in edge_platform_ci
        and 'EXPECTED_AGENT_SHA256: ${{ needs.dependencies.outputs.base_runtime_agent_sha256 }}' in edge_platform_ci
        and 'test "$(sha256sum "${base_dir}/edge-agent-linux-amd64" | awk \'{print $1}\')" = "${EXPECTED_AGENT_SHA256}"' in edge_platform_ci
        and 'if [[ "${RUNTIME_REUSE}" != "true" ]]; then' in edge_platform_ci,
        "runtime reuse must preserve accepted provenance, verify transported bytes, and skip edge-agent rebuild only after the typed reuse decision",
    )
    require(
        '    ".github/workflows/edge-platform-ci.yml",' not in runtime_input
        and 'RUNTIME_BUILD_CONTRACT_PATH = ".github/workflows/edge-platform-ci.yml"' in runtime_input
        and "_runtime_build_contract(repo_root)" in runtime_input,
        "runtime identity must hash only the marked VM build contract, not the whole CI workflow",
    )
    require(
        '"edge-platform/crates/edge-agent"' in runtime_input
        and '"win/vultr-waw/stack/edge-gateway"' in runtime_input
        and '"win/vultr-waw/stack/warp-egress"' in runtime_input,
        "runtime identity must cover the VM runtime source/build surface; schema reuse semantics belong to the runtime input owner tests",
    )
    require(
        "edge-release-$ReleaseSetSha256" in windows_installer
        and "https://api.github.com/repos/$Repository/releases/tags/$Tag" in windows_installer
        and "application/octet-stream" in windows_installer
        and "release-set.pb" in windows_installer
        and "current.pb" in windows_installer
        and "previous.pb" in windows_installer
        and "edge-diagnostic.exe" in windows_installer
        and "verify-windows" in windows_installer
        and "write-windows-activation" in windows_installer
        and '$null = & $Tool @activationArgs' in windows_installer
        and '$activation["current_state"]' in windows_installer
        and '$activation["console"]' in windows_installer
        and '$activation["diagnostic"]' in windows_installer,
        "Windows activation must keep helper stdout out of the PowerShell function result and return one typed activation boundary",
    )
    require(
        "current.json" not in windows_installer
        and "manifest.json" not in windows_installer
        and "gh.exe" not in windows_installer.lower()
        and "gh run download" not in windows_installer
        and "workflow run" not in windows_installer,
        "Windows activation must never regress to JSON pointers, gh.exe, or workflow-run artifact authority",
    )
    metadata_read = windows_installer.split("function Invoke-GitHubJsonGet {", 1)[1].split(
        "function Invoke-GitHubAssetGet {", 1
    )[0]
    asset_read = windows_installer.split("function Invoke-GitHubAssetGet {", 1)[1].split(
        "function Assert-LowerHexRevision {", 1
    )[0]
    require(
        windows_installer.count("Invoke-RestMethod") == 1
        and windows_installer.count("Invoke-WebRequest") == 1
        and "$GitHubReadAttempts = 3" in windows_installer
        and "$GitHubReadTimeoutSec = 15" in windows_installer
        and "$GitHubAssetTimeoutSec = 120" in windows_installer
        and "Test-TransientGitHubReadFailure" in metadata_read
        and "Test-TransientGitHubReadFailure" in asset_read
        and "Start-Sleep -Seconds $GitHubRetryDelaySec" in metadata_read
        and "Start-Sleep -Seconds $GitHubRetryDelaySec" in asset_read
        and "@(408, 425, 429, 500, 502, 503, 504)" in windows_installer
        and "Activate-ReleaseAuthority" not in metadata_read
        and "Activate-ReleaseAuthority" not in asset_read,
        "Windows GitHub retry must remain bounded and scoped only to read-only metadata/asset transport",
    )
    require(
        'repo_root / "edge-platform" / "scripts" / "install-windows-release.ps1"' in windows_input
        and '$packageBootstrap = Join-Path $packageRoot "bootstrap"' in edge_platform_ci
        and 'Copy-Item "edge-platform\\scripts\\install-windows-release.ps1"' in edge_platform_ci
        and 'bootstrap\\install-windows-release.ps1' in windows_installer
        and "Refresh-StableBootstrapInstaller" in windows_installer
        and '$releaseInstaller = Join-Path $releaseDir "bootstrap\\install-windows-release.ps1"' in windows_installer
        and "Bootstrap installer refresh failed SHA-256 verification" in windows_installer,
        "Windows installer changes must force a Windows candidate and self-update only from the verified immutable release",
    )
    require(
        "migrate-windows-runtime-state" not in windows_installer
        and "LegacyRuntimeStatePath" not in windows_installer
        and "LegacySingBoxConfigPath" not in windows_installer
        and "sing-box.json" not in windows_installer,
        "Windows release activation must not import legacy runtime/config state",
    )
    require(
        "[switch]$ReleaseOnly" not in windows_installer
        and "[switch]$Rollback" not in windows_installer
        and "runtime_state=NOT_CONFIGURED" in windows_installer
        and "runtime_config=NOT_CONFIGURED" in windows_installer
        and "automation_registered=false" in windows_installer
        and "Activate-ReleaseAuthority" in windows_installer,
        "Windows installer must have exactly one release-authority-only execution mode",
    )
    require(
        "AcceptedRevision" in windows_installer
        and "Assert-AcceptedReleaseAuthority" in windows_installer
        and "branches/main" in windows_installer
        and "git/ref/tags/$Tag" in windows_installer
        and 'if (-not [bool]$branch.protected)' in windows_installer
        and "Durable release tag does not resolve to AcceptedRevision" in windows_installer
        and "Assert-AcceptedCandidateSource" in windows_installer
        and "ReleaseSet.source_revision is not the accepted PR-head parent of AcceptedRevision" in windows_installer
        and "ReleaseSet source tree does not match AcceptedRevision tree" in windows_installer
        and '$parents.Count -ne 2' in windows_installer
        and '$parents[1].sha -ne $sourceRevision' in windows_installer
        and 'activation=NOOP' in windows_installer,
        "protected installer must mirror merge promotion authority and own idempotent NOOP without rotating activation pointers",
    )
    require(
        "Register-InstalledAutomation" not in windows_installer
        and "EdgePlatformController" not in windows_installer
        and "EdgePlatformReconcile" not in windows_installer
        and "EdgePlatformShutdown" not in windows_installer
        and "schtasks /Create" not in windows_installer
        and "RepoRoot" not in windows_installer,
        "Windows installer must not own controller/runtime scheduled automation",
    )
    require(
        all(
            not Path(path).exists()
            for path in (
                "edge-platform/scripts/ensure-edge-controller.ps1",
                "edge-platform/scripts/register-edge-controller-task.ps1",
                "edge-platform/scripts/register-edge-platform-automation.ps1",
                "edge-platform/scripts/start-edge-platform.ps1",
                "edge-platform/scripts/reconcile-edge-platform.ps1",
                "edge-platform/scripts/shutdown-edge-platform.ps1",
                "edge-platform/scripts/start-edge-controller.cmd",
                "edge-platform/scripts/start-edge-platform.cmd",
                "edge-platform/scripts/shutdown-edge-platform.cmd",
            )
        ),
        "legacy Windows startup/reconcile/shutdown wrappers must stay deleted",
    )

    require(
        "current.pb" in windows_console
        and "decode_windows_activation_state" in windows_console
        and "verify_windows_activation_files" in windows_console
        and "WINDOWS_CONTROLLER_SERVICE_NAME" in windows_console
        and "WINDOWS_CONTROLLER_SERVICE_ACCOUNT" in windows_console
        and "converge_controller_tun_authority" in windows_console
        and "S-1-5-32-544" in windows_console
        and "Add-LocalGroupMember" in windows_console
        and "set_failure_actions_on_non_crash_failures(false)" in windows_console
        and "converge_controller_service" in windows_console
        and "windows_scm" in windows_console
        and "edge-console does not own controller startup" in windows_console
        and '.arg("serve")' not in windows_console
        and ".spawn()?" not in windows_console
        and "EDGE_REPO_ROOT" not in windows_console
        and "resolve_repo_root_for_controller" not in windows_console
        and 'parent.join("edge-controller.exe")' not in windows_console,
        "edge-console must resolve current.pb and converge exactly one SCM-owned controller without a child-process startup fallback",
    )
    require(
        "SmokeRuntime" in WINDOWS_CONSOLE.with_name("cli.rs").read_text(encoding="utf-8")
        and "run_non_tun_loopback_smoke" in windows_console
        and "mode=NON_TUN_LOOPBACK" in windows_console
        and "tun_enabled=false" in windows_console,
        "installed console may retain the bounded non-TUN artifact smoke, but it must not own controller startup",
    )
    require(
        "PrivilegedPing" in WINDOWS_CONSOLE.with_name("cli.rs").read_text(encoding="utf-8")
        and "PrivilegedActivate" in WINDOWS_CONSOLE.with_name("cli.rs").read_text(encoding="utf-8")
        and "PrivilegedDispatch" in WINDOWS_CONSOLE.with_name("cli.rs").read_text(encoding="utf-8")
        and "decode_windows_privileged_request" in windows_console
        and "encode_windows_privileged_result" in windows_console
        and "EdgePlatformPrivilegedDispatch" in windows_console
        and "install-windows-release.ps1" in windows_console
        and "-ReleaseOnly" not in windows_console
        and "RELEASE_ALREADY_ACTIVE" not in windows_console
        and "updated Windows activation source revision does not match accepted revision" not in windows_console
        and "schtasks.exe" in windows_console,
        "edge-console must delegate merge/candidate provenance to the protected installer, then retarget the immutable SYSTEM dispatcher after exact activation",
    )
    require(
        '"state/runtime-state.pb"' in windows_controller
        or "windows_runtime_state_path" in windows_controller,
        "installed controller must consume typed Windows runtime state",
    )
    require(
        '"state/secrets/runtime-state.pb"' in windows_controller_core
        and '"state/runtime-state.pb"' not in windows_controller_core,
        "credential-bearing WindowsRuntimeState must remain under controller-only secret state",
    )

    require(
        "migrate_windows_runtime_state" not in windows_controller
        and '"migrate-windows-runtime-state"' in windows_controller_cli
        and "is_err()" in windows_controller_cli,
        "installed Windows controller must reject the retired legacy JSON migration command",
    )

    require(
        "windows_input_sha256" in edge_platform_ci
        and "windows_input_digest.py compute" in edge_platform_ci
        and "windows_input_digest.py decide" in edge_platform_ci
        and "WINDOWS_CANDIDATE_BUILD_CONTRACT_BEGIN" in edge_platform_ci
        and "WINDOWS_CANDIDATE_BUILD_CONTRACT_END" in edge_platform_ci
        and "needs.dependencies.outputs.windows_reuse != 'true'" in edge_platform_ci
        and "gh release download $env:BASE_RELEASE_TAG" in edge_platform_ci,
        "candidate CI must derive durable Windows identity and reuse only the exact accepted artifact",
    )
    require(
        edge_platform_ci.count("if: needs.dependencies.outputs.windows_reuse != 'true'") == 3
        and "Validate Stage 4B.1 Windows code proof with exact sing-box" in edge_platform_ci
        and "cargo test --locked -p edge-singbox stage2_" in edge_platform_ci
        and "cargo test --locked -p edge-singbox stage4b_" in edge_platform_ci
        and "EDGE_TEST_SING_BOX" in edge_platform_ci
        and "write-windows-manifest" in edge_platform_ci
        and "write-linux-manifest" in edge_platform_ci
        and "windows-build-manifest.pb" in edge_platform_ci
        and "linux-build-manifest.pb" in edge_platform_ci
        and "ConvertTo-Json" not in edge_platform_ci
        and "--windows-manifest" in edge_platform_ci
        and "--linux-manifest" in edge_platform_ci
        and edge_platform_ci.count("verify-candidate") == 2,
        "candidate and promotion paths must converge through the typed platform build-manifest contract",
    )
    require(
        "base_mesh_image: ${{ steps.resolve.outputs.base_mesh_image }}" in edge_platform_ci
        and "base_mesh_image=%s" in edge_platform_ci
        and "BASE_MESH_IMAGE: ${{ needs.dependencies.outputs.base_mesh_image }}" in edge_platform_ci
        and 'if [[ "${mesh_ref}" != "${BASE_MESH_IMAGE}" ]]; then' in edge_platform_ci
        and edge_platform_ci.count('docker buildx imagetools inspect "${mesh_ref}"') == 1,
        "CI must live-check a changed pinned Mesh digest once, reuse identical accepted base digest, and never re-check Docker Hub at promotion",
    )

    require(
        "needs.windows.outputs.artifact_sha256" not in edge_platform_ci
        and "needs.windows.outputs.controller_sha256" not in edge_platform_ci
        and "needs.windows.outputs.console_sha256" not in edge_platform_ci
        and "needs.linux_candidate.outputs.edge_agent_sha256" not in edge_platform_ci
        and "needs.linux_candidate.outputs.edge_controller_sha256" not in edge_platform_ci
        and "needs.linux_candidate.outputs.edge_orchestrator_sha256" not in edge_platform_ci,
        "ReleaseSet assembly must consume typed build manifests instead of scattered build hash outputs",
    )
    require(
        "steps.authority.outputs.release_set_sha256" not in edge_platform_ci
        and "needs.release_authority.outputs.release_set_sha256" not in edge_platform_ci
        and '[[ "${EDGE_GATEWAY_IMAGE}" =~' not in edge_platform_ci
        and '[[ "${EDGE_WARP_EGRESS_IMAGE}" =~' not in edge_platform_ci,
        "typed release ownership must not regress to redundant GitHub outputs or shell-owned manifest validation",
    )
    require(
        "types: [opened, synchronize, reopened]" in edge_platform_ci
        and "types: [opened, synchronize, reopened, closed]" not in edge_platform_ci
        and "  push:\n    branches: [main]" in edge_platform_ci
        and "group: ${{ github.event_name == 'push' && 'edge-platform-promotion-main'" in edge_platform_ci
        and "cancel-in-progress: ${{ github.event_name != 'push' }}" in edge_platform_ci
        and "if: github.event_name == 'push' && github.ref == 'refs/heads/main'" in edge_platform_ci
        and "ACCEPTED_REVISION: ${{ github.sha }}" in edge_platform_ci
        and "test \"$(jq -er '.parents | length'" in edge_platform_ci
        and "candidate_revision=\"$(jq -er '.parents[1].sha'" in edge_platform_ci
        and 'test "${accepted_tree}" = "${candidate_tree}"' in edge_platform_ci
        and 'associated_prs="$(gh api "repos/${REPOSITORY}/commits/${ACCEPTED_REVISION}/pulls?per_page=10")"' in edge_platform_ci
        and 'select(.merge_commit_sha == $accepted)' in edge_platform_ci
        and 'select(.head.sha == $candidate)' in edge_platform_ci
        and 'select(.base.ref == "main")' in edge_platform_ci
        and 'if length == 1 then .[0] else error("accepted merge has no unique matching merged PR") end' in edge_platform_ci
        and "pull-requests: read" in edge_platform_ci
        and 'select(.status == "completed")' in edge_platform_ci
        and 'select(.conclusion == "success")' in edge_platform_ci,
        "CI promotion must execute on actual protected main merge and bind exact merged PR, tested tree, and completed successful candidate without rebuild",
    )
    require(
        "Publish accepted Windows artifact without rebuild" in edge_platform_ci
        and "name: edge-platform-windows-${{ steps.locate.outputs.accepted_revision }}" in edge_platform_ci
        and "Publish accepted Linux artifact without rebuild" not in edge_platform_ci
        and "name: edge-platform-release-${{ steps.locate.outputs.accepted_revision }}" not in edge_platform_ci
        and "Publish accepted ReleaseSet without rebuild" not in edge_platform_ci
        and "name: edge-platform-release-set-${{ steps.locate.outputs.accepted_revision }}" not in edge_platform_ci,
        "promotion must retain the Windows artifact consumed by the installer without re-uploading redundant Linux or ReleaseSet Actions artifacts",
    )
    require(
        edge_platform_ci.count(
            "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
        )
        == 3
        and edge_platform_ci.count("continue-on-error: true") == 3
        and "Restore disposable Cargo source cache" in edge_platform_ci
        and "Restore disposable Cargo Windows cache" in edge_platform_ci
        and "Restore disposable Cargo Linux cache" in edge_platform_ci
        and "cargo-source-${{ runner.os }}-${{ runner.arch }}-rust-1.95.0-${{ hashFiles('edge-platform/Cargo.lock') }}-" in edge_platform_ci
        and "cargo-windows-${{ runner.os }}-${{ runner.arch }}-rust-1.95.0-${{ hashFiles('edge-platform/Cargo.lock') }}-" in edge_platform_ci
        and "cargo-linux-${{ runner.os }}-${{ runner.arch }}-rust-1.95.0-${{ hashFiles('edge-platform/Cargo.lock') }}-" in edge_platform_ci
        and "cache-hit" not in edge_platform_ci,
        "Cargo caches must remain pinned, job-scoped disposable acceleration without semantic ownership",
    )
    require(
        "ROOT_PACKAGES = (\"edge-controller\", \"edge-console\", \"edge-diagnostic\")"
        in windows_input
        and "_reachable_package_dirs(repo_root)" in windows_input
        and "WINDOWS_BUILD_CONTRACT_PATH" in windows_input
        and 'base_schema not in {"6", "7"}' in windows_input
        and "base_diagnostic_sha256" in windows_input,
        "Windows identity must cover controller/console/diagnostic transitive local dependencies, marked build contract and allow exact reuse only from ReleaseSet v6/v7",
    )

    require(
        "edge-state" not in orchestrator_manifest,
        "GitHub-only edge-orchestrator must not introduce a second persistent desired-state store",
    )
    orchestrator_main = Path("edge-platform/crates/edge-orchestrator/src/main.rs").read_text(
        encoding="utf-8"
    )
    require(
        "OrchestrationContext::from_process_env()" in orchestrator_main,
        "edge-orchestrator must validate exact ReleaseSet context before lifecycle dispatch",
    )


if __name__ == "__main__":
    main()
