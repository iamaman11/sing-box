#!/usr/bin/env python3
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
ROUTER = WORKFLOWS / "edge-control-plane.yml"
APPLICATION = WORKFLOWS / "vm-application-lifecycle.yml"
VULTR = WORKFLOWS / "vultr-lifecycle.yml"
ZERO_TRUST = WORKFLOWS / "zero-trust-lifecycle.yml"
VPC = WORKFLOWS / "vultr-vpc-lifecycle.yml"
DNS = WORKFLOWS / "cloudflare-dns-lifecycle.yml"
MESH = WORKFLOWS / "cloudflare-mesh-lifecycle.yml"
EDGE_PLATFORM_CI = WORKFLOWS / "edge-platform-ci.yml"
RUNTIME_INPUT = Path("edge-platform/scripts/runtime_input_digest.py")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    router = ROUTER.read_text(encoding="utf-8")
    application = APPLICATION.read_text(encoding="utf-8")
    vultr = VULTR.read_text(encoding="utf-8")
    zero_trust = ZERO_TRUST.read_text(encoding="utf-8")
    vpc = VPC.read_text(encoding="utf-8")
    dns = DNS.read_text(encoding="utf-8")
    mesh = MESH.read_text(encoding="utf-8")
    edge_platform_ci = EDGE_PLATFORM_CI.read_text(encoding="utf-8")
    runtime_input = RUNTIME_INPUT.read_text(encoding="utf-8")

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
    require("workflow_call:" in zero_trust, "Zero Trust lifecycle must be reusable")
    require("workflow_call:" in vpc, "VPC lifecycle must be reusable")
    require("workflow_call:" in dns, "DNS lifecycle must be reusable")
    require("workflow_call:" in mesh, "Mesh lifecycle must be reusable")
    require("issue_comment:" not in application, "application backend must not listen to comments")
    require("issue_comment:" not in vultr, "Vultr backend must not listen to comments")
    require("issue_comment:" not in zero_trust, "Zero Trust backend must not listen to comments")
    require("issue_comment:" not in vpc, "VPC backend must not listen to comments")
    require("issue_comment:" not in dns, "DNS backend must not listen to comments")
    require("issue_comment:" not in mesh, "Mesh backend must not listen to comments")

    require(
        "uses: ./.github/workflows/vm-application-lifecycle.yml" in router,
        "router must call the application backend",
    )
    require(
        "uses: ./.github/workflows/vultr-lifecycle.yml" in router,
        "router must call the Vultr backend",
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
        application.count("group: vultr-control-plane-production") == 2,
        "application backend must serialize execute and acceptance mutation jobs",
    )
    require(
        vultr.count("group: vultr-control-plane-production") == 1,
        "Vultr backend must serialize its execute mutation job",
    )
    require(
        'verb == "action-plan" and len(tokens) == 5' in vultr
        and '"action-plan", "apply", "action"' in vultr
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
        mesh.count("group: vultr-control-plane-production") == 1,
        "Mesh backend must serialize its execute mutation job",
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
        "acquire-access-plan" not in vultr and "release-access-plan" not in vultr,
        "Vultr workflow must not own transient-access PlanAuthority plumbing",
    )
    require(
        "vultr-lifecycle lease-acquire" in application
        and "vultr-lifecycle lease-release" in application,
        "application workflow must use the typed transient SSH lease",
    )
    require(
        "acquire-access-plan" not in application and "release-access-plan" not in application,
        "application workflow must not own transient-access PlanAuthority plumbing",
    )
    require(
        application.count('test "${EDGE_RELEASE_SCHEMA_VERSION}" = "4"') == 2
        and application.count('[[ "${EDGE_RUNTIME_SOURCE_REVISION}" =~ ^[0-9a-f]{40}$ ]]') == 2
        and application.count('[[ "${EDGE_RUNTIME_INPUT_SHA256}" =~ ^[0-9a-f]{64}$ ]]') == 2,
        "application lifecycle must require exact ReleaseSet v4 runtime identity in both materialization paths",
    )
    require(
        application.count('--arg source_revision "${EDGE_RUNTIME_SOURCE_REVISION}"') == 2
        and '--arg source_revision "${GITHUB_SHA}"' not in application,
        "application release provenance must come from VM runtime authority, not control-plane main SHA",
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
        '"${bin}" cloudflare-dns plan "${dns_spec}" "${app_spec}"' in application
        and '"${bin}" cloudflare-dns apply "${dns_spec}" "${app_spec}"' in application,
        "application acceptance must not manually copy VM public IPv4 into DNS commands",
    )
    require(
        "vm_ip=" not in application,
        "application acceptance must not own derived VM public-IP plumbing",
    )
    require(
        "cleanup-apply" not in vpc and "cleanup-apply" not in dns,
        "staged Checkpoint 1 backends must not expose destructive cleanup",
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
        "cleanup_acceptance" not in application
        and "acceptance-emergency-" not in application
        and "if [[ $rc -ne 0 ]]; then cleanup" not in application,
        "acceptance failure must preserve provider/guest state for diagnosis, never auto-clean",
    )
    require(
        "require_vpc_clean_room()" in application,
        "acceptance must require a read-only VPC clean-room proof",
    )
    preflight_marker = "# Fail closed on any acceptance-owned residue."
    support_marker = 'acceptance-support-before.json'
    vm_marker = 'acceptance-plan-before.json'
    require(preflight_marker in application, "acceptance must fail closed on residue")
    preflight_pos = application.index(preflight_marker)
    support_pos = application.index(support_marker, preflight_pos)
    vm_pos = application.index(vm_marker, support_pos)
    require(
        preflight_pos < support_pos < vm_pos,
        "strict read-only clean-room proof must precede fresh VM planning",
    )
    require(
        '.plan.action == "NOOP" and .plan.environment_in_use == false' in application,
        "acceptance must prove support resources absent before fresh creation",
    )

    require(
        ".guest_transition.network_ready == true" in application,
        "VPC attachment acceptance must require exact guest VPC network readiness",
    )
    require(
        ".guest_transition.boot_id_changed == true" not in application,
        "VPC attachment success must not depend on undocumented provider reboot behavior",
    )
    require(
        "acceptance-vpc-reboot" not in application,
        "VPC attachment must not be followed by a second explicit reboot",
    )
    reboot_action = 'vultr-lifecycle action-plan "${vultr_spec}" "${machine}" reboot'
    require(
        application.count(reboot_action) == 1,
        "application acceptance must retain exactly one explicit reboot for final persistence verification",
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
        'tokens[0] != "/mesh"' in mesh
        and 'tokens[1] not in {"plan", "apply", "runtime-apply", "runtime-verify", "runtime-cleanup"}' in mesh,
        "Mesh backend must expose only the bounded provider/runtime grammar",
    )
    require(
        "line3-mesh vpc-runtime-apply" in mesh
        and "line3-mesh vpc-runtime-verify" in mesh
        and mesh.count("line3-mesh runtime-cleanup") == 1
        and "line3-mesh cleanup-" not in mesh
        and "MESH_NODE_TOKEN" not in mesh,
        "Mesh backend must expose only VPC-composed runtime operations plus one typed runtime cleanup, without raw token or provider cleanup surfaces",
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
        "mesh-runtime-cleanup-provider-before.json" in mesh
        and "mesh-runtime-cleanup-provider-after.json" in mesh
        and '.status == "ABSENT" and .runtime.token_store_present == false and .runtime.container_running == false and .runtime.runtime_ready == false' in mesh
        and "provider_before:.[0],runtime:.[1],provider_after:.[2]" in mesh,
        "Mesh runtime cleanup must prove provider NOOP before and after one typed cleanup and require exact runtime absence",
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
        and "base_schema != \"4\"" in runtime_input,
        "runtime identity must cover runtime sources and fail closed for legacy ReleaseSets",
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
