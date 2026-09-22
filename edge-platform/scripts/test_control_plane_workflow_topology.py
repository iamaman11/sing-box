#!/usr/bin/env python3
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
ROUTER = WORKFLOWS / "edge-control-plane.yml"
APPLICATION = WORKFLOWS / "vm-application-lifecycle.yml"
VULTR = WORKFLOWS / "vultr-lifecycle.yml"
ZERO_TRUST = WORKFLOWS / "zero-trust-lifecycle.yml"
VPC = WORKFLOWS / "vultr-vpc-lifecycle.yml"
DNS = WORKFLOWS / "cloudflare-dns-lifecycle.yml"


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
    require("issue_comment:" not in application, "application backend must not listen to comments")
    require("issue_comment:" not in vultr, "Vultr backend must not listen to comments")
    require("issue_comment:" not in zero_trust, "Zero Trust backend must not listen to comments")
    require("issue_comment:" not in vpc, "VPC backend must not listen to comments")
    require("issue_comment:" not in dns, "DNS backend must not listen to comments")

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
    ]:
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
        "acquire-access-plan" in vpc
        and "release-access-plan" in vpc
        and "ACCESS_CLEANUP_ARMED=1" in vpc,
        "VPC guest mutation must use transient SSH access with armed cleanup",
    )
    require(
        '"apply"' in dns
        and "cloudflare-dns plan" in dns
        and "cloudflare-dns apply" in dns
        and "plan_authority.authority_digest" in dns,
        "DNS backend mutations must consume fresh exact PlanAuthority",
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
        "cleanup_acceptance() (" in application,
        "acceptance cleanup must run in an isolated subshell",
    )
    preflight_marker = (
        "# Recover any exact acceptance-owned residue from a previous failed run."
    )
    support_marker = 'acceptance-support-before.json'
    vm_marker = 'acceptance-plan-before.json'
    require(preflight_marker in application, "acceptance must retain residue-recovery preflight")
    preflight_pos = application.index(preflight_marker)
    support_pos = application.index(support_marker, preflight_pos)
    vm_pos = application.index(vm_marker, support_pos)
    require(
        preflight_pos < support_pos < vm_pos,
        "strict support clean-room proof must precede fresh VM planning",
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


if __name__ == "__main__":
    main()
