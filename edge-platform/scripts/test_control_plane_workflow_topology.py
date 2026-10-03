#!/usr/bin/env python3
import re
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
ROUTER = WORKFLOWS / "edge-control-plane.yml"
APPLICATION = WORKFLOWS / "vm-application-lifecycle.yml"
VULTR = WORKFLOWS / "vultr-lifecycle.yml"
WINDOWS_PHYSICAL = WORKFLOWS / "windows-physical.yml"
ZERO_TRUST = WORKFLOWS / "zero-trust-lifecycle.yml"
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
PRODUCTION_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/production_command.rs")
CREDENTIAL_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs")
CREDENTIAL_PROVIDER = Path("edge-platform/crates/edge-provider-cloudflare/src/lib.rs")
CREDENTIAL_SNAPSHOT = Path("edge-platform/crates/edge-orchestrator/src/credential_snapshot.rs")
CREDENTIAL_STORE = Path("edge-platform/crates/edge-secrets/src/credential_store.rs")
CREDENTIAL_PROTO = Path("edge-platform/proto/edge/platform/v1/credential_plane.proto")
RUNTIME_PROTO = Path("edge-platform/proto/edge/platform/v1/runtime.proto")
AGENT_PROTO = Path("edge-platform/proto/edge/platform/v1/agent.proto")
CONTROLLER_PROTO = Path("edge-platform/proto/edge/platform/v1/controller.proto")
PRODUCTION_INVENTORY = Path("edge-platform/crates/edge-orchestrator/src/cloudflare_production_inventory.rs")
ACCEPTANCE_COORDINATOR = Path("edge-platform/crates/edge-orchestrator/src/application_acceptance_command.rs")
VULTR_LIFECYCLE_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/vultr_lifecycle_command.rs")
PRODUCTION_VM_RUNNER_INSTALLER = Path("edge-platform/scripts/install-vultr-production-runner.sh")
ARCHITECTURE = Path("edge-platform/ARCHITECTURE.md")
README = Path("edge-platform/README.md")
RUNBOOK = Path("win/docs/RUNBOOK.md")
SERVER_ARCHITECTURE = Path("win/docs/SERVER-ARCHITECTURE.md")
ROOT_README = Path("README.md")
LOCAL_AGENT_CONTRACT = Path("infra/LOCAL_AGENT_EXECUTION_CONTRACT.md")
APPLICATION_README = Path("infra/application/README.md")
VULTR_STACK_README = Path("win/vultr-waw/README.md")


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
    vm_agent = VM_AGENT.read_text(encoding="utf-8")
    vm_agent_cli = VM_AGENT_CLI.read_text(encoding="utf-8")
    vm_agent_runtime = vm_agent.split("#[cfg(test)]", 1)[0]
    production_command = PRODUCTION_COMMAND.read_text(encoding="utf-8")
    credential_command = CREDENTIAL_COMMAND.read_text(encoding="utf-8")
    credential_provider = CREDENTIAL_PROVIDER.read_text(encoding="utf-8")
    credential_snapshot = CREDENTIAL_SNAPSHOT.read_text(encoding="utf-8")
    credential_store = CREDENTIAL_STORE.read_text(encoding="utf-8")
    credential_proto = CREDENTIAL_PROTO.read_text(encoding="utf-8")
    runtime_proto = RUNTIME_PROTO.read_text(encoding="utf-8")
    agent_proto = AGENT_PROTO.read_text(encoding="utf-8")
    controller_proto = CONTROLLER_PROTO.read_text(encoding="utf-8")
    production_inventory = PRODUCTION_INVENTORY.read_text(encoding="utf-8")
    acceptance_coordinator = ACCEPTANCE_COORDINATOR.read_text(encoding="utf-8")
    vultr_lifecycle_command = VULTR_LIFECYCLE_COMMAND.read_text(encoding="utf-8")
    production_vm_runner_installer = PRODUCTION_VM_RUNNER_INSTALLER.read_text(encoding="utf-8")
    architecture = ARCHITECTURE.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")
    server_architecture = SERVER_ARCHITECTURE.read_text(encoding="utf-8")
    root_readme = ROOT_README.read_text(encoding="utf-8")
    local_agent_contract = LOCAL_AGENT_CONTRACT.read_text(encoding="utf-8")
    application_readme = APPLICATION_README.read_text(encoding="utf-8")
    vultr_stack_readme = VULTR_STACK_README.read_text(encoding="utf-8")

    listeners = sorted(
        path.name
        for path in WORKFLOWS.glob("*.yml")
        if "issue_comment:" in path.read_text(encoding="utf-8")
    )
    require(
        "Stage-3 historical application-exclusive Cloudflare retirement are closed" in architecture
        and "remaining Stage-3 steady-state lifecycle closure" in architecture
        and "The project is in late Stage 3" in readme
        and "The routine production surface is `/production converge|verify|diagnose|rollback`" in readme
        and "class-scoped application rotation" in readme
        and "/production rollback" in runbook
        and "/credentials rotate tunnel-auth" in runbook
        and "host-identity rotation remains a Stage-3 boundary" in runbook
        and "Routine production converge/verify/diagnose/rollback does not acquire a support lease" in server_architecture
        and "Current execution is late Stage 3" in root_readme
        and "bounded Stage-3 historical deletion slice is closed" in local_agent_contract
        and "`/production rollback` uses the same" in application_readme
        and "Routine production does not acquire a temporary support lease" in vultr_stack_readme
        and "strict SSH local-forward" not in vultr_stack_readme
        and "currently #169" not in runbook,
        "operator documentation must match the current Stage-3 local rollback/application-rotation surface and must not advertise historical #169 or Stage-2 proof commands as current authority",
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
        and "installer not invoked" in windows_console
        and "RELEASE_CONVERGED_REOBSERVED" in windows_console
        and "local owner handoff reconciled" in windows_console,
        "Windows release activation must reconcile exact local authority before replay and after uncertain child failure",
    )
    require(
        "CredentialAdmit" not in vm_agent_cli
        and "local-credential-admit" not in vm_agent_cli
        and "PrivilegedAdmitCredential" not in windows_console_cli
        and "WindowsPrivilegedOperation::AdmitCredential" not in windows_console
        and "admit_vm_credential_generation" not in vm_agent_runtime
        and "admit_windows_credential_generation" not in windows_console
        and 'reserved 8;' in runtime_proto
        and 'reserved "WINDOWS_PRIVILEGED_OPERATION_ADMIT_CREDENTIAL";' in runtime_proto,
        "retired Stage-2 read-only credential admission must stay deleted; exact-generation staging is the sole steady-state data-plane gate and the old Windows wire identity remains reserved",
    )
    require("workflow_call:" in vpc, "VPC lifecycle must be reusable")
    require("issue_comment:" not in application, "application backend must not listen to comments")
    require("issue_comment:" not in vultr, "Vultr backend must not listen to comments")
    require("issue_comment:" not in windows_physical, "Windows physical cycle must not listen to comments")
    require("issue_comment:" not in credentials, "credential backend must not listen to comments")
    require("issue_comment:" not in vpc, "VPC backend must not listen to comments")
    require(not ZERO_TRUST.exists() and not DNS.exists(), "retired standalone Cloudflare operator workflows must stay absent")

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
        and '"fresh-v2-cutover"' not in credentials
        and '"fresh-v2-publication-prove"' not in credentials
        and '"fresh-v2-cleanup"' not in credentials
        and '"${EDGE_CREDENTIAL_ORCHESTRATOR}" credentials contract-verify' in credentials
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
        "credential operator workflow must expose class-scoped application rotation plus verify and explicit host bootstrap without reviving Stage-2 proof/cutover surfaces",
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
    host_bootstrap_end = credential_command.index("async fn converge(", host_bootstrap_start)
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
        'test "$COMMAND_BODY" = "/windows smoke"' in windows_physical
        and 'test "$CONTROL_PROTECTED" = "true"' in windows_physical
        and "github.ref_protected" in windows_physical
        and "edge-platform/scripts/resolve_durable_release.sh" in windows_physical
        and "C:\\sing-box" in windows_physical
        and windows_physical.count("privileged-activate") == 2
        and "EDGE_ACTIVATION_REQUEST_CONSOLE" in windows_physical
        and "Complete exact release-owner handoff" in windows_physical
        and "ACTIVATION_HANDOFF=PASS" in windows_physical
        and "privileged-ping" in windows_physical
        and "EDGE_CURRENT_CONSOLE" in windows_physical
        and "edge-diagnostic.exe" in windows_physical
        and "EdgePlatformController" in windows_physical
        and "NT SERVICE\\EdgePlatformController" in windows_physical
        and "service.PathName" in windows_physical
        and "controller_path" in windows_physical
        and "controller_running=true" not in windows_physical
        and "NetworkService runner unexpectedly has direct access" in windows_physical
        and "smoke-runtime" not in windows_physical
        and "http://127.0.0.1:51051" in windows_physical
        and "install-windows-release.ps1" not in windows_physical
        and "-ReleaseOnly" not in windows_physical,
        "Windows physical cycle must prove exact SYSTEM activation, SCM controller ownership and transport-only runner isolation",
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
        and "application-lifecycle export-bundle" not in production_runtime
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
        "application-lifecycle plan ",
        "application-lifecycle apply ",
        "application-lifecycle verify ",
        "application-lifecycle upgrade ",
        "application-lifecycle recover-plan ",
        "application-lifecycle recover-apply ",
        "application-lifecycle rollback-plan ",
        "application-lifecycle rollback-apply ",
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
        and "Validate Stage 2 proxy-only config with exact sing-box" in edge_platform_ci
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
