#!/usr/bin/env python3
import re
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
        and "Clear-DnsClientCache" not in edge_local_runtime
        and "restore_windows_dns_if_owned" not in edge_local_runtime
        and "WINDOWS_OWNED_DNS_IPV4" not in edge_local_runtime,
        "local runtime must never reset foreign Cloudflare One Client DNS by resolver IP",
    )
    vm_agent = VM_AGENT.read_text(encoding="utf-8")
    vm_agent_cli = VM_AGENT_CLI.read_text(encoding="utf-8")
    shared_types = SHARED_TYPES.read_text(encoding="utf-8")
    vm_agent_runtime = vm_agent.split("#[cfg(test)]", 1)[0]
    production_command = PRODUCTION_COMMAND.read_text(encoding="utf-8")
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
        "Stage 3 and Stage 4A are closed" in architecture
        and "Stage 4A exit decision — CLOSED" in architecture
        and "Managed TUN is now permitted only inside the explicit Stage 4B cutover" in architecture
        and "Stage 4B entry contract — managed Windows TUN" in architecture
        and "Add one typed Windows datapath mode" in architecture
        and "copied into `WindowsRuntimeState`, `WindowsRuntime`, or `WindowsActivationState`" in architecture
        and "Do not widen the SCM service identity merely by assumption" in architecture
        and "typed Windows process observation distinguishes managed / conflicting external / absent ownership" in architecture
        and "`infra/production/production.textproto` in Windows candidate input identity" in architecture
        and "exact locally verified `previous.pb`" in architecture
        and "one explicit legacy-to-managed handoff" in architecture
        and "Stage 4B datapath convergence" in local_architecture
        and "Generated `runtime\\\\sing-box.json` never chooses the mode" in local_architecture
        and "Stage 4B managed Windows TUN cutover" in runbook
        and "`PROXY_ONLY` ReleaseSet must never be treated as authority for the TUN cutover" in architecture
        and "Shared-host foreign-project isolation" in architecture
        and "Sing-box configuration, protocol selection and quality authority" in architecture
        and "Do not mutate Windows from an unaccepted mode-flip revision" in runbook
        and "Production release rollback is not yet a supported public operation" not in runbook
        and "Stage 3 and Stage 4A are closed" in readme
        and "The project is now in Stage 4B" in readme
        and "currently working external Windows sing-box" in readme
        and "The routine production surface is `/production converge|verify|diagnose|rollback`" in readme
        and "class-scoped application rotation" in readme
        and "/production rollback" in runbook
        and "/credentials rotate tunnel-auth" in runbook
        and "canonical permanent" in runbook
        and "custom X25519/HKDF/AEAD handoff" in runbook
        and "Routine production converge/verify/diagnose/rollback does not acquire a support lease" in server_architecture
        and "Current execution is Stage 4B" in root_readme
        and "Stage-transition rule: Stage 4A is closed" in root_readme
        and "bounded Stage-3 historical deletion slice is closed" in local_agent_contract
        and "`/production rollback` uses the same" in application_readme
        and "Routine production does not acquire a temporary support lease" in vultr_stack_readme
        and "strict SSH local-forward" not in vultr_stack_readme
        and "currently #169" not in runbook,
        "operator documentation must match closed Stage 3/4A and the active bounded Stage 4B managed-TUN cutover without advertising historical authority",
    )
    require(
        "PRE_MUTATION_TUN_TEARDOWN_BLOCKED" in windows_physical
        and "PRE_MUTATION_TUN_TEARDOWN_BLOCKED" in windows_physical.split("      - name: Execute typed lifecycle mutation", 1)[0]
        and "managed_tun_automatic_rollback=BLOCKED_NO_INDEPENDENT_DNS_RESTORE" in windows_physical
        and "privileged-rollback-previous" not in windows_physical.split("      - name: Refuse unproven automatic rollback after MANAGED_TUN verification failure", 1)[1].split("      - name: Final diagnostics and transport-only boundary", 1)[0]
        and "$env:EDGE_OPERATION -in @('stop','rollback')" in windows_physical
        and "$currentMode -ceq 'ManagedTun'" in windows_physical
        and "$env:EDGE_EXPECTED_MODE -ceq 'ProxyOnly'" in windows_physical
        and 'reject_unproven_windows_tun_teardown("stop-local")' in windows_controller_runtime
        and 'reject_unproven_windows_tun_teardown("rollback-previous")' in windows_console
        and '"managed-tun-to-proxy-only"' in windows_console
        and "failed to stop exact managed proxy before release transition" in windows_console,
        "Windows TUN teardown must be rejected before the operator or native owner mutates runtime, without affecting ManagedTun-to-ManagedTun activation",
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
        and windows_physical.count("privileged-runtime-evidence") == 3
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
        and "Recovering a partial ManagedTun activation with no managed TUN present" in windows_physical
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
        and windows_physical.count("privileged-runtime-evidence") == 3
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
        and "windows_datapath_mode: WINDOWS_DATAPATH_MODE_MANAGED_TUN" in production_desired
        and "windows_datapath_mode: WINDOWS_DATAPATH_MODE_PROXY_ONLY" not in production_desired,
        "Stage 4B.2-C operator acceptance must keep canonical production Windows datapath explicitly MANAGED_TUN",
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
        and "pub(crate) enum CloudflareZeroTrustCommand {\n    Doctor(SpecArgs),\n}" in credential_cli,
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
        and "delete_access_service_token" not in credential_command
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
        "credential operator workflow must expose only steady-state rotation/verify/bootstrap after Stage-3 proof-token retirement plumbing is physically deleted",
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
        application.count("group: vultr-control-plane-production") == 5,
        "application backend must serialize enrollment, provider, observation, cleanup and disposable acceptance jobs",
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
        vultr.count("group: vultr-control-plane-production") == 1,
        "Vultr backend must serialize its execute mutation job",
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
        and 'provider_operation="active-converge"' in production_provider
        and 'provider_operation="verify-active"' in production_provider
        and 'verify|rollback)' in production_provider
        and '"${EDGE_PROVIDER_ORCHESTRATOR}" cloudflare-target-plane "${provider_operation}"' in production_provider
        and "CLOUDFLARE_CONTROL_TOKEN: ${{ secrets.CLOUDFLARE_CONTROL_TOKEN }}" in production_provider
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
    require(
        "- self-hosted" in production_runtime
        and "- Linux" in production_runtime
        and "- X64" in production_runtime
        and "- sing-box-production-vm" in production_runtime
        and "- production-1" in production_runtime
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
    require(
        "production_rollback_desired" not in production_command
        and "pub(crate) async fn rollback(" not in production_command,
        "steady-state production rollback must have no legacy orchestrator lease/SSH implementation",
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
        'provider_operation="active-converge"' in production_provider
        and 'provider_operation="verify-active"' in production_provider
        and "MeshVerify" in vm_agent_cli
        and "MeshCleanup" in vm_agent_cli
        and 'local_operation="bundle-converge"' in production_runtime
        and edge_platform_ci.count("application-bundle-build") == 2
        and "export-bundle" not in application
        and "VULTR_SSH_PRIVATE_KEY" not in production_runtime,
        "Mesh ownership must remain split: hosted provider authority, candidate-only semantic bundle build, and self-hosted local runtime owner",
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
