#!/usr/bin/env python3
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
ROUTER = WORKFLOWS / "edge-control-plane.yml"
APPLICATION = WORKFLOWS / "vm-application-lifecycle.yml"
VULTR = WORKFLOWS / "vultr-lifecycle.yml"
ROOT_OPS = WORKFLOWS / "vultr-root-ops.yml"
ZERO_TRUST = WORKFLOWS / "zero-trust-lifecycle.yml"
VPC = WORKFLOWS / "vultr-vpc-lifecycle.yml"
DNS = WORKFLOWS / "cloudflare-dns-lifecycle.yml"
MESH = WORKFLOWS / "cloudflare-mesh-lifecycle.yml"
EDGE_PLATFORM_CI = WORKFLOWS / "edge-platform-ci.yml"
RUNTIME_INPUT = Path("edge-platform/scripts/runtime_input_digest.py")
WINDOWS_INPUT = Path("edge-platform/scripts/windows_input_digest.py")
WINDOWS_INSTALLER = Path("edge-platform/scripts/install-windows-release.ps1")
WINDOWS_ENSURE = Path("edge-platform/scripts/ensure-edge-controller.ps1")
WINDOWS_AUTOMATION = Path("edge-platform/scripts/register-edge-platform-automation.ps1")
WINDOWS_CONSOLE = Path("edge-platform/crates/edge-console/src/main.rs")
WINDOWS_CONTROLLER = Path("edge-platform/crates/edge-controller/src/main.rs")
WINDOWS_CONTROLLER_CLI = Path("edge-platform/crates/edge-controller/src/cli.rs")
PRODUCTION_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/production_command.rs")
ACCEPTANCE_COORDINATOR = Path("edge-platform/crates/edge-orchestrator/src/application_acceptance_command.rs")
VULTR_LIFECYCLE_COMMAND = Path("edge-platform/crates/edge-orchestrator/src/vultr_lifecycle_command.rs")
ROOT_RUNNER_INSTALLER = Path("edge-platform/scripts/install-vultr-root-runner.sh")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    router = ROUTER.read_text(encoding="utf-8")
    application = APPLICATION.read_text(encoding="utf-8")
    vultr = VULTR.read_text(encoding="utf-8")
    root_ops = ROOT_OPS.read_text(encoding="utf-8")
    zero_trust = ZERO_TRUST.read_text(encoding="utf-8")
    vpc = VPC.read_text(encoding="utf-8")
    dns = DNS.read_text(encoding="utf-8")
    mesh = MESH.read_text(encoding="utf-8")
    edge_platform_ci = EDGE_PLATFORM_CI.read_text(encoding="utf-8")
    runtime_input = RUNTIME_INPUT.read_text(encoding="utf-8")
    windows_input = WINDOWS_INPUT.read_text(encoding="utf-8")
    windows_installer = WINDOWS_INSTALLER.read_text(encoding="utf-8")
    windows_ensure = WINDOWS_ENSURE.read_text(encoding="utf-8")
    windows_automation = WINDOWS_AUTOMATION.read_text(encoding="utf-8")
    windows_console = WINDOWS_CONSOLE.read_text(encoding="utf-8")
    windows_controller = WINDOWS_CONTROLLER.read_text(encoding="utf-8")
    windows_controller_cli = WINDOWS_CONTROLLER_CLI.read_text(encoding="utf-8")
    production_command = PRODUCTION_COMMAND.read_text(encoding="utf-8")
    acceptance_coordinator = ACCEPTANCE_COORDINATOR.read_text(encoding="utf-8")
    vultr_lifecycle_command = VULTR_LIFECYCLE_COMMAND.read_text(encoding="utf-8")
    root_runner_installer = ROOT_RUNNER_INSTALLER.read_text(encoding="utf-8")

    listeners = sorted(
        path.name
        for path in WORKFLOWS.glob("*.yml")
        if "issue_comment:" in path.read_text(encoding="utf-8")
    )
    require(
        listeners == [ROUTER.name],
        f"exactly one issue_comment listener is required, observed: {listeners}",
    )

    require("workflow_call:" in application, "application lifecycle must be reusable")
    require("workflow_call:" in vultr, "Vultr lifecycle must be reusable")
    require("workflow_call:" in root_ops, "Vultr root ops must be reusable")
    require("workflow_call:" in zero_trust, "Zero Trust lifecycle must be reusable")
    require("workflow_call:" in vpc, "VPC lifecycle must be reusable")
    require("workflow_call:" in dns, "DNS lifecycle must be reusable")
    require("workflow_call:" in mesh, "Mesh lifecycle must be reusable")
    require("issue_comment:" not in application, "application backend must not listen to comments")
    require("issue_comment:" not in vultr, "Vultr backend must not listen to comments")
    require("issue_comment:" not in root_ops, "Vultr root ops must not listen to comments")
    require("issue_comment:" not in zero_trust, "Zero Trust backend must not listen to comments")
    require("issue_comment:" not in vpc, "VPC backend must not listen to comments")
    require("issue_comment:" not in dns, "DNS backend must not listen to comments")
    require("issue_comment:" not in mesh, "Mesh backend must not listen to comments")

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
        "uses: ./.github/workflows/vultr-lifecycle.yml" in router,
        "router must call the Vultr backend",
    )
    require(
        "uses: ./.github/workflows/vultr-root-ops.yml" in router
        and "startsWith(github.event.comment.body, '/root ')" in router,
        "router must expose root ops only through the sole owner-gated Issue #1 listener",
    )
    require(
        "uses: ./.github/workflows/zero-trust-lifecycle.yml" in router,
        "router must call the Zero Trust backend",
    )
    require(
        "uses: ./.github/workflows/vultr-vpc-lifecycle.yml" in router,
        "router must call the VPC backend",
    )
    require(
        "uses: ./.github/workflows/cloudflare-dns-lifecycle.yml" in router,
        "router must call the DNS backend",
    )
    require(
        "uses: ./.github/workflows/cloudflare-mesh-lifecycle.yml" in router,
        "router must call the Mesh backend",
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
        ("zero-trust", zero_trust),
        ("vpc", vpc),
        ("dns", dns),
        ("mesh", mesh),
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
        application.count("group: vultr-control-plane-production") == 4,
        "application backend must serialize execute, production, cleanup and acceptance mutation jobs",
    )
    require(
        vultr.count("group: vultr-control-plane-production") == 1,
        "Vultr backend must serialize its execute mutation job",
    )
    require(
        "runs-on:" in root_ops
        and "- self-hosted" in root_ops
        and "- vultr-root" in root_ops
        and "- test-vm" in root_ops
        and '${{ needs.authorize.outputs.machine_id }}' in root_ops,
        "root ops must target only the machine-labelled self-hosted Vultr root runner",
    )
    require(
        "permissions: {}" in root_ops
        and 'sudo -n bash "${command_file}"' in root_ops
        and "base64.urlsafe_b64decode" in root_ops,
        "root ops must carry no GitHub token permission and execute only the explicitly owner-routed command as root",
    )
    require(
        'verb == "runner-bootstrap" and len(tokens) == 4' in vultr
        and '"runner-bootstrap"' in vultr
        and "IAMAMAN11_SING_BOX_CONTROL_PLANE_TOKEN" in vultr
        and "/actions/runners/registration-token" in vultr
        and 'run_lifecycle runner-bootstrap "${spec}" "${machine}"' in vultr
        and "install-vultr-root-runner.sh" in vultr,
        "Vultr lifecycle must bootstrap the repository root runner through the typed host owner using a short-lived registration token",
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
        zero_trust.count("group: vultr-control-plane-production") == 1,
        "Zero Trust backend must serialize its execute mutation job",
    )
    require(
        vpc.count("group: vultr-control-plane-production") == 1,
        "VPC backend must serialize its execute mutation job",
    )
    require(
        dns.count("group: vultr-control-plane-production") == 1,
        "DNS backend must serialize its execute mutation job",
    )
    require(
        mesh.count("group: vultr-control-plane-production") == 2,
        "Mesh backend must serialize both provider observation and execute jobs",
    )
    require(
        "edge-platform/scripts/resolve_durable_release.sh" in zero_trust,
        "Zero Trust backend must consume the durable accepted ReleaseSet",
    )
    require(
        "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}" in zero_trust,
        "Zero Trust backend must use the production Cloudflare token secret",
    )
    require(
        "CLOUDFLARE_ANDROID_PROFILE_ID: ${{ secrets.CLOUDFLARE_ANDROID_PROFILE_ID }}"
        in zero_trust,
        "Android profile authority must stay outside Git",
    )
    require(
        "CLOUDFLARE_ANDROID_IDENTITY_EMAIL: ${{ secrets.CLOUDFLARE_ANDROID_IDENTITY_EMAIL }}"
        in zero_trust,
        "Android identity authority must stay outside Git",
    )
    require(
        "CLOUDFLARE_ENROLLED_DEVICE_REACHABILITY_CONFIRMED: ${{ vars.CLOUDFLARE_ENROLLED_DEVICE_REACHABILITY_CONFIRMED }}"
        in zero_trust,
        "dashboard reachability must remain an explicit production attestation",
    )
    require(
        'case "${operation}" in' in zero_trust
        and "preflight)" in zero_trust
        and "converge)" in zero_trust
        and "verify)" in zero_trust,
        "Zero Trust backend must retain typed preflight/converge/verify operations",
    )
    require(
        'for iteration in $(seq 1 8)' in zero_trust,
        "Zero Trust convergence must stay bounded",
    )
    require(
        "cloudflare-zero-trust apply" in zero_trust
        and "plan_authority.authority_digest" in zero_trust,
        "Zero Trust mutations must consume exact PlanAuthority",
    )

    require(
        'echo "Operation: `${operation}`"' not in zero_trust
        and "printf 'Operation: `%s`\\n' \"${operation}\"" in zero_trust,
        "Zero Trust workflow summary must not execute the operation through shell command substitution",
    )

    require(
        "edge-platform/scripts/resolve_durable_release.sh" in vpc
        and "edge-platform/scripts/resolve_durable_release.sh" in dns,
        "staged substrate backends must consume the durable accepted ReleaseSet",
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
        "root runner bootstrap failed: stage=%s exit=%s" in root_runner_installer
        and "tail -c 4096" in root_runner_installer
        and "[REDACTED]" in root_runner_installer
        and "run_logged install-runner-dependencies ./bin/installdependencies.sh" in root_runner_installer
        and root_runner_installer.index("run_logged install-runner-dependencies ./bin/installdependencies.sh")
        < root_runner_installer.index("run_logged configure-runner")
        and "run_logged configure-runner" in root_runner_installer
        and "pgrep -u" not in root_runner_installer
        and "Verify self-hosted runner online" in vultr
        and '.status == "online"' in vultr
        and 'index("vultr-root")' in vultr
        and 'index($machine)' in vultr,
        "root-runner bootstrap must install pinned dependencies, avoid process-name readiness races, and defer online identity to the GitHub runner API",
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
    production_job = application.split("\n  production:\n", 1)[1].split("\n  cleanup:\n", 1)[0]
    require(
        'tokens == ["/production", "converge"]' in application
        and 'tokens == ["/production", "verify"]' in application
        and 'tokens == ["/production", "rollback"]' in application
        and 'spec_path = "infra/production/production.textproto"' in application,
        "production command grammar must be fixed to converge/verify/rollback and the sole canonical textproto",
    )
    require(
        "needs.authorize.outputs.command_family == 'production'" in production_job
        and production_job.count("edge-platform/scripts/resolve_durable_release.sh") == 1
        and '"${bin}" production "${REQUESTED_OPERATION}" "${EDGE_APPLICATION_ARTIFACT}"' in production_job
        and '"${bin}" production rollback' in production_job,
        "production backend must resolve one exact durable ReleaseSet and invoke only the typed production coordinator",
    )
    require(
        "VULTR_API_KEY: ${{ secrets.VULTR_API_KEY }}" in production_job
        and "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}" in production_job
        and "VULTR_SSH_PRIVATE_KEY: ${{ secrets.VULTR_SSH_PRIVATE_KEY }}" in production_job,
        "production backend must receive only the bounded provider and strict-SSH authorities required by the typed coordinator",
    )
    for forbidden in [
        "INSTANCE_ID",
        "VPC_ID",
        "PROVIDER_ID",
        "TARGET_IPV4",
        "MESH_CIDR",
        "current.json",
        "manifest.json",
    ]:
        require(
            forbidden not in production_job,
            f"production workflow must not transport raw provider/runtime authority: {forbidden}",
        )
    require(
        "std::process::Command" not in production_command
        and "Command::new" not in production_command
        and "sh -c" not in production_command
        and "production_converge_machine" in production_command
        and "production_converge_desired" in production_command
        and "production_verify_desired" in production_command
        and "production_rollback_desired" in production_command,
        "typed production coordinator must compose existing owners in-process without shell replay",
    )

    acceptance_job = application.split("\n  acceptance:\n", 1)[1]
    cleanup_job = application.split("\n  cleanup:\n", 1)[1].split("\n  acceptance:\n", 1)[0]
    application_before_acceptance = application.split("\n  acceptance:\n", 1)[0]
    execute_job = application.split("\n  execute:\n", 1)[1].split("\n  production:\n", 1)[0]
    require(
        "  cleanup:\n    needs: authorize" in application
        and "  acceptance:\n    needs: authorize" in application
        and "  execute:\n    needs: authorize" in application,
        "application commands must dispatch directly from authorization to exactly one command job",
    )
    require(
        execute_job.count("edge-platform/scripts/resolve_durable_release.sh") == 1
        and "needs.verify" not in execute_job,
        "normal application execute must perform exactly one durable ReleaseSet resolution",
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
        application.count('"${orchestrator}" application-lifecycle materialize') == 2,
        "both application materialization paths must delegate exact release inputs to the typed Rust owner",
    )
    require(
        "EDGE_DOCKER_ENGINE_VERSION" in vpc
        and "EDGE_CONTAINERD_VERSION" in vpc
        and "EDGE_COMPOSE_VERSION" in vpc,
        "VPC host-substrate verification must bind exact ReleaseSet substrate versions",
    )
    require(
        '"apply"' in dns
        and "cloudflare-dns plan" in dns
        and "cloudflare-dns apply" in dns
        and "plan_authority.authority_digest" in dns,
        "DNS backend mutations must consume fresh exact PlanAuthority",
    )
    require(
        "TARGET_IPV4" not in dns and "target_ipv4" not in dns,
        "DNS workflow must not accept or transport a manually derived target IPv4",
    )
    require(
        "APPLICATION_SPEC_PATH" in dns,
        "DNS workflow must delegate target derivation to the typed orchestrator from application/Vultr observation",
    )
    require(
        "VULTR_API_KEY: ${{ secrets.VULTR_API_KEY }}" in dns,
        "DNS composition must have bounded Vultr read authority for current VM observation",
    )
    require(
        "dns_create(&args.dns_spec_path, &args.spec_path)" in acceptance_coordinator
        and "dns_verify_noop(&args.dns_spec_path, &args.spec_path)" in acceptance_coordinator,
        "typed acceptance must keep DNS target derivation inside the existing DNS owner",
    )
    require(
        "vm_ip=" not in application and "vm_ip" not in acceptance_coordinator,
        "application acceptance must not own derived VM public-IP plumbing",
    )
    require(
        "cloudflare-dns cleanup-plan" in dns
        and dns.count("cloudflare-dns cleanup-apply") == 1
        and 'tokens[1] in {"inventory", "cleanup-plan", "cleanup-apply"}' in dns
        and '.plan.action.kind == "DELETE"' in dns
        and 'destructive_digest="$(jq -er' in dns
        and 'authority="$(plan_authority' in dns
        and '.[1].performed.kind == .[0].plan.action.kind' in dns,
        "DNS backend must expose only typed exact-authority cleanup with one delete per invocation",
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
        "RECORD_ID" not in dns
        and "ZONE_ID" not in dns
        and "VPC_ID" not in vpc
        and "INSTANCE_ID" not in vpc,
        "cleanup workflows must not accept raw provider identifiers as command authority",
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
        "edge-platform/scripts/resolve_durable_release.sh" in mesh,
        "Mesh backend must consume the exact durable accepted ReleaseSet",
    )
    require(
        "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}" in mesh
        and "VULTR_API_KEY: ${{ secrets.VULTR_API_KEY }}" in mesh
        and "VULTR_SSH_PRIVATE_KEY: ${{ secrets.VULTR_SSH_PRIVATE_KEY }}" in mesh,
        "Mesh backend must receive only the provider and strict-SSH authorities required by verified VPC composition",
    )
    require(
        "line3-mesh vpc-plan" in mesh
        and "line3-mesh vpc-apply" in mesh
        and "plan_authority.authority_digest" in mesh,
        "Mesh provider mutations must reuse typed VPC-derived planning and exact PlanAuthority",
    )
    require(
        "vultr-lifecycle lease-acquire" in mesh
        and "vultr-lifecycle lease-release" in mesh
        and "ACCESS_CLEANUP_ARMED=1" in mesh,
        "Mesh VPC proof must use the typed transient SSH lease with armed cleanup",
    )
    require(
        "acquire-access-plan" not in mesh and "release-access-plan" not in mesh,
        "Mesh workflow must not own transient-access PlanAuthority plumbing",
    )
    require(
        'tokens[0] == "/mesh"' in mesh
        and 'tokens[1] in {"provider-cleanup-plan", "provider-cleanup-verify"}' in mesh
        and 'len(tokens) == 3' in mesh
        and 'tokens[1] in {"plan", "apply", "cleanup-plan", "cleanup-apply", "runtime-apply", "runtime-verify", "runtime-observe", "runtime-cleanup"}' in mesh,
        "Mesh backend must expose only the bounded provider/runtime grammar plus one provider-only CP16 observation",
    )
    require(
        "line3-mesh vpc-runtime-apply" in mesh
        and "line3-mesh vpc-runtime-verify" in mesh
        and mesh.count("line3-mesh runtime-observe") == 3
        and mesh.count("line3-mesh runtime-cleanup") == 1
        and mesh.count("line3-mesh cleanup-plan") == 3
        and mesh.count("line3-mesh cleanup-apply") == 1
        and "MESH_NODE_TOKEN" not in mesh,
        "Mesh backend must expose bounded runtime operations plus one-at-a-time typed provider cleanup without raw token authority",
    )
    require(
        '.plan.action.kind == "NOOP" and .plan_disposition == "NOOP"' in mesh,
        "Mesh runtime operations must fail closed unless provider state is already NOOP",
    )
    require(
        "MESH_CIDR" not in mesh
        and "PRIVATE_IPV4" not in mesh
        and "PROVIDER_ID" not in mesh,
        "Mesh workflow must not transport raw provider IDs, CIDR, or private-IP authority",
    )
    require(
        '"${bin}" line3-mesh vpc-plan' in mesh
        and '"${MESH_SPEC_PATH}" "${VPC_SPEC_PATH}" "${APPLICATION_SPEC_PATH}"' in mesh,
        "Mesh plan must derive effective route only through the typed VPC-composed command",
    )
    require(
        mesh.count("line3-mesh vpc-apply") == 1,
        "one Mesh workflow invocation must contain at most one provider apply call",
    )
    require(
        mesh.count("line3-mesh vpc-runtime-apply") == 1
        and mesh.count("line3-mesh vpc-runtime-verify") == 1,
        "one Mesh workflow invocation must contain at most one typed runtime converge and one typed runtime verify call",
    )
    require(
        "mesh-runtime-observe-provider-plan.json" in mesh
        and "mesh-runtime-observe.json" in mesh
        and '(.status == "READY" and .runtime.runtime_ready == true)' in mesh
        and '(.status == "ABSENT" and .runtime.runtime_ready == false and .runtime.token_store_present == false and .runtime.container_running == false)' in mesh
        and '(.status == "DEGRADED" and .runtime.runtime_ready == false and (.runtime.token_store_present == true or .runtime.container_running == true))' in mesh,
        "Mesh runtime observation must stay read-only, provider-NOOP-gated, and classify READY/ABSENT/DEGRADED deterministically",
    )
    require(
        "mesh-runtime-cleanup-provider-before.json" in mesh
        and "mesh-runtime-cleanup-provider-after.json" in mesh
        and '.status == "ABSENT" and .runtime.token_store_present == false and .runtime.container_running == false and .runtime.runtime_ready == false' in mesh
        and "provider_before:.[0],runtime:.[1],provider_after:.[2]" in mesh,
        "Mesh runtime cleanup must prove provider NOOP before and after one typed cleanup and require exact runtime absence",
    )
    require(
        "mesh-provider-cleanup-runtime.json" in mesh
        and "mesh-provider-cleanup-plan.json" in mesh
        and "mesh-provider-cleanup-apply.json" in mesh
        and 'destructive_digest="$(jq -er' in mesh
        and 'authority="$(plan_authority' in mesh
        and '(.plan.action.kind == "DELETE_ROUTE" or .plan.action.kind == "DELETE_NODE")' in mesh
        and '.[1].performed.kind == .[0].plan.action.kind' in mesh,
        "Mesh provider cleanup must require runtime ABSENT, fresh destructive digest + PlanAuthority, and exactly one matching delete per invocation",
    )

    provider_observe = mesh.split("  provider_observe:\n", 1)[1].split("\n  execute:", 1)[0]
    require(
        "line3-mesh cleanup-plan" in provider_observe
        and ".mutations_performed == 0" in provider_observe
        and '"provider-cleanup-verify"' in provider_observe
        and '(.plan.action.kind == "DELETE_ROUTE" or .plan.action.kind == "DELETE_NODE")' in provider_observe
        and '.plan.action.kind == "NOOP"' in provider_observe,
        "Mesh provider plan must be read-only for MUTATE/NOOP, while explicit verify requires exact zero-state",
    )
    require(
        "EDGE_RELEASE_CONTEXT_PATH" in provider_observe
        and "VULTR_API_KEY" not in provider_observe
        and "VULTR_SSH_PRIVATE_KEY" not in provider_observe
        and "EDGE_SSH_PRIVATE_KEY_PATH" not in provider_observe
        and "vultr-lifecycle lease-acquire" not in provider_observe
        and "vultr-lifecycle lease-release" not in provider_observe
        and "api.ipify.org" not in provider_observe
        and "cleanup-apply" not in provider_observe,
        "CP16 Mesh provider observation must not materialize SSH/Vultr authority, discover egress, acquire access, or expose mutation",
    )

    orchestrator_manifest = Path("edge-platform/crates/edge-orchestrator/Cargo.toml").read_text(
        encoding="utf-8"
    )
    require(
        "runtime_input_sha256" in edge_platform_ci
        and "runtime_input_digest.py compute" in edge_platform_ci
        and "runtime_input_digest.py decide" in edge_platform_ci
        and "Resolve exact accepted VM runtime reuse" in edge_platform_ci,
        "candidate CI must derive and consume one conservative VM runtime input identity",
    )
    require(
        'test "${candidate_agent_sha}" = "${EDGE_AGENT_SHA256}"' in edge_platform_ci
        and 'runtime_source_revision="${EDGE_RUNTIME_SOURCE_REVISION}"' in edge_platform_ci,
        "runtime reuse must prove deterministic edge-agent bytes and preserve original runtime provenance",
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
        and '"win/vultr-waw/stack/warp-egress"' in runtime_input
        and 'base_schema not in {"4", "5"}' in runtime_input,
        "runtime identity must cover runtime sources and fail closed for pre-v4 ReleaseSets",
    )
    require(
        "edge-release-$ReleaseSetSha256" in windows_installer
        and "https://api.github.com/repos/$Repository/releases/tags/$Tag" in windows_installer
        and "application/octet-stream" in windows_installer
        and "release-set.pb" in windows_installer
        and "current.pb" in windows_installer
        and "previous.pb" in windows_installer
        and '$runtimeStatePath = Join-Path $stateDir "runtime-state.pb"' in windows_installer
        and '$runtimeConfigPath = Join-Path $runtimeDir "sing-box.json"' in windows_installer
        and "edge-diagnostic.exe" in windows_installer
        and "verify-windows" in windows_installer
        and "write-windows-activation" in windows_installer,
        "Windows activation must be one durable ReleaseSet plus one install-root protobuf/local-runtime boundary",
    )
    require(
        "current.json" not in windows_installer
        and "manifest.json" not in windows_installer
        and "gh.exe" not in windows_installer.lower()
        and "gh run download" not in windows_installer
        and "workflow run" not in windows_installer,
        "Windows activation must never regress to JSON pointers, gh.exe, or workflow-run artifact authority",
    )
    require(
        "migrate-windows-runtime-state" in windows_installer
        and "LegacyRuntimeStatePath" in windows_installer
        and "LegacySingBoxConfigPath" in windows_installer,
        "legacy Windows files may enter the installed model only through one explicit first-install migration",
    )
    require(
        '$quotedConsole ensure-controller' in windows_installer
        and '$quotedConsole reconcile' in windows_installer
        and '$quotedConsole stop-local' in windows_installer
        and "RepoRoot" not in windows_installer,
        "installed scheduled tasks must target only stable edge-console commands and carry no RepoRoot",
    )

    require(
        "edge-console.exe" in windows_ensure
        and "ensure-controller" in windows_ensure
        and "RepoRoot" not in windows_ensure
        and "current.json" not in windows_ensure,
        "legacy ensure wrapper must delegate only to the installed console owner",
    )
    require(
        "current.pb" in windows_console
        and "decode_windows_activation_state" in windows_console
        and "verify_windows_activation_files" in windows_console
        and '"serve"' in windows_console
        and '.arg(&install_root)' in windows_console
        and "resolve_repo_root_for_controller" not in windows_console
        and 'parent.join("edge-controller.exe")' not in windows_console,
        "edge-console must be the sole current.pb resolver and exact controller startup owner",
    )
    require(
        '"state/runtime-state.pb"' in windows_controller
        or "windows_runtime_state_path" in windows_controller,
        "installed controller must consume typed Windows runtime state",
    )
    require(
        "migrate_windows_runtime_state" in windows_controller
        and "MigrateWindowsRuntimeState" in windows_controller_cli
        and '"migrate-windows-runtime-state"' in windows_controller_cli,
        "controller must expose only the bounded one-time legacy JSON to protobuf migration",
    )
    require(
        '$quotedConsole ensure-controller' in windows_automation
        and '$quotedConsole reconcile' in windows_automation
        and '$quotedConsole stop-local' in windows_automation
        and "RepoRoot" not in windows_automation,
        "manual automation registration must match installer-owned stable console tasks",
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
        edge_platform_ci.count("if: needs.dependencies.outputs.windows_reuse != 'true'") == 2
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
        and 'base_schema != "6"' in windows_input
        and "base_diagnostic_sha256" in windows_input,
        "Windows identity must cover controller/console/diagnostic transitive local dependencies, marked build contract and fail closed before ReleaseSet v6",
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
