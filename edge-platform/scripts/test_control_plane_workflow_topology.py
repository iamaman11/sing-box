#!/usr/bin/env python3
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
ROUTER = WORKFLOWS / "edge-control-plane.yml"
APPLICATION = WORKFLOWS / "vm-application-lifecycle.yml"
VULTR = WORKFLOWS / "vultr-lifecycle.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    router = ROUTER.read_text(encoding="utf-8")
    application = APPLICATION.read_text(encoding="utf-8")
    vultr = VULTR.read_text(encoding="utf-8")

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
    require("issue_comment:" not in application, "application backend must not listen to comments")
    require("issue_comment:" not in vultr, "Vultr backend must not listen to comments")

    require(
        "uses: ./.github/workflows/vm-application-lifecycle.yml" in router,
        "router must call the application backend",
    )
    require(
        "uses: ./.github/workflows/vultr-lifecycle.yml" in router,
        "router must call the Vultr backend",
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

    for name, backend in [("application", application), ("vultr", vultr)]:
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
        ".guest_transition.boot_id_changed == true" in application,
        "VPC attachment acceptance must require a proven guest boot transition",
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
