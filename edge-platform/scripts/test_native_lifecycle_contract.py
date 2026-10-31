#!/usr/bin/env python3
"""Source-level lifecycle guard for issue #595; production Rust tests are separate.

This gate checks that future edits do not silently reintroduce the exact
full-fleet-decode upgrade deadlock, bypass protected authority, or separate
first-use CREATE from the canonical operator chain. It is NOT an N-1 binary
execution or physical acceptance proof.
"""
from pathlib import Path


def require(condition: bool, code: str) -> None:
    if not condition:
        raise AssertionError(code)


def check_refresh(source: str) -> None:
    require(
        "fn previous_vm_for_code_only_refresh(" in source,
        "L03_NARROW_PREVIOUS_VM_ADAPTER_MISSING",
    )
    narrow = source.split("fn previous_vm_for_code_only_refresh(", 1)[1].split(
        "/// Refresh the CURRENT", 1
    )[0]
    for token in (
        "HostRegistry::decode(bytes)",
        "registry.schema_version != 1",
        "BTreeSet::new()",
        "host.machine_id == machine_id",
        "vm.kind != FleetHostKind::Vm as i32",
        "managed_host::Owner::VmMachineId(owner)",
        "owner == machine_id",
        "vm.worker_authority_public_key.len() != 32",
        "vm.native_receipt_public_key.len() != 32",
    ):
        require(token in narrow, "L03_PREVIOUS_IDENTITY_CHECK_MISSING: " + token)
    for forbidden in ("decode_host_registry(", "validate_host_registry("):
        require(forbidden not in narrow, "L03_PREVIOUS_FULL_FLEET_VALIDATION_REINTRODUCED")
    refresh = source.split("pub(crate) async fn refresh_current()", 1)[1].split(
        "fn current_published_release_digest(", 1
    )[0]
    for token in (
        "let _guard = super::host_native::owner_operation_lock()?;",
        "read_existing_receipt_identity(trusted)?",
        "previous_vm_for_code_only_refresh(&previous.registry_pb, &previous.machine_id)?",
        "previous.pinned_worker_public_key != host.worker_authority_public_key",
        "current_published_release_digest(&head, &latest)?",
        "accepted_release_asset(",
        "enroll_locked(&previous.machine_id, &release_digest).await?",
        "fs::rename(&stage, binary)",
        "host_resource_mutations=0",
    ):
        require(token in refresh, "L04_NATIVE_REFRESH_BOUNDARY_MISSING: " + token)
    current_enroll = source.split("async fn enroll_locked(", 1)[1].split(
        "/// A root owner refresh reads only", 1
    )[0]
    require(
        "let host = if refreshing {" in current_enroll
        and "previous_vm_for_code_only_refresh(&registry_pb, machine_id)?" in current_enroll
        and "edge_shared_types::decode_host_registry(&registry_pb)" in current_enroll,
        "L03_CURRENT_NEW_FLEET_DECODE_BEFORE_REFRESH",
    )
    require("previous_registry_for_code_only_refresh" not in source, "L03_OLD_FULL_FLEET_ADAPTER_RETURNS")
    # These exact production Rust tests execute via cargo test --workspace --locked.
    for test in (
        "previous_release_refresh_only_requires_exact_vm_identity_not_new_windows_semantics",
        "refreshed_owner_still_requires_private_root_owned_journal_directory",
        "native_refresh_accepts_only_exact_latest_main_release",
        "receipt_identity_is_root_local_and_requires_exact_git_registration",
    ):
        require("fn " + test in source, "L03_L04_RUNTIME_TEST_MISSING: " + test)


def check_bootstrap(cloud: str, access: str, lifecycle: str, router: str) -> None:
    for token in (
        "render_native_first_use_cloud_init(",
        "render_native_first_use_with_runner(",
        "sha256sum --check --status",
        "HOST_CLOUD_INIT_NATIVE_OWNER_ALREADY_PRESENT_NO_REPLAY",
        "ssh_pwauth: false",
        "NATIVE_ROOT_ENROLLED_AWAITING_ONE_TIME_CREDENTIAL_HANDOFF",
        "FIRST_USE_BEGIN_NO_REPLAY",
    ):
        require(token in cloud, "L05_PINNED_FIRST_USE_MISSING: " + token)
    for forbidden in ("ssh_authorized_keys:", "NOPASSWD:ALL"):
        require("rendered.contains(\"" + forbidden + "\")" in cloud, "L05_SSH_SAFETY_GUARD_MISSING: " + forbidden)
    for token in (
        "vm_bootstrap::open_for_native_root(",
        "BOOTSTRAP_PROTECTED_GIT_RECEIPT_NOT_REGISTERED",
        "BOOTSTRAP_ACCESS_ALREADY_BEGUN_NO_REPLAY",
        "diagnose_canonical_host_access(",
    ):
        require(token in access, "L05_ROOT_ONLY_ACCESS_BOUNDARY_MISSING: " + token)
    require(
        "HOST_VM_CREATE_REQUIRES_NATIVE_ONE_TIME_ENROLLMENT_NO_SSH" in lifecycle,
        "L01_GENERAL_PROVIDER_CREATE_REENABLED",
    )
    for token in (
        "Reserve unique Git receipt PR and durable BEGIN BEFORE VM CREATE",
        "Execute exactly one no-SSH native Vultr CREATE",
    ):
        require(token in router, "L05_CANONICAL_FIRST_USE_MISSING: " + token)
    require(
        router.index("Reserve unique Git receipt PR and durable BEGIN BEFORE VM CREATE")
        < router.index("Execute exactly one no-SSH native Vultr CREATE"),
        "L05_CREATE_PRECEDES_DURABLE_BEGIN",
    )


def check_ci(ci: str) -> None:
    source = ci.split("  verify:\n", 1)[1].split("\n  dependencies:", 1)[0]
    require(
        "Enforce native lifecycle invariants and negative regressions" in source
        and "python3 edge-platform/scripts/test_native_lifecycle_contract.py" in source,
        "L07_SOURCE_GATE_NOT_REQUIRED",
    )
    require("cargo test --workspace --locked" in source, "L07_RUST_TESTS_NOT_REQUIRED")
    require(
        "needs: [verify, dependencies, windows, linux_candidate, release_authority]" in ci,
        "L07_CANDIDATE_COMPLETION_DOES_NOT_NEED_SOURCE",
    )
    promote = ci.split("  promote:\n", 1)[1]
    require(
        'test "$(jq -er \'.conclusion\' <<<"${latest_run}")" = "success"' in promote,
        "L07_PROMOTION_CANDIDATE_SUCCESS_NOT_REQUIRED",
    )


def main() -> None:
    root = Path("edge-platform")
    rust = (root / "crates/edge-agent/src/host_enroll.rs").read_text(encoding="utf-8")
    cloud = (root / "crates/edge-orchestrator/src/vultr_native_cloud_init.rs").read_text(encoding="utf-8")
    access = (root / "crates/edge-agent/src/host_bootstrap_access.rs").read_text(encoding="utf-8")
    lifecycle = (root / "crates/edge-orchestrator/src/vultr_lifecycle_command.rs").read_text(encoding="utf-8")
    router = Path(".github/workflows/edge-control-plane.yml").read_text(encoding="utf-8")
    ci = Path(".github/workflows/edge-platform-ci.yml").read_text(encoding="utf-8")
    check_refresh(rust)
    check_bootstrap(cloud, access, lifecycle, router)
    check_ci(ci)

    # Negative fixtures ensure the source gate itself fails on representative
    # security/compatibility regressions, rather than checking only presence.
    for broken in (
        rust.replace("HostRegistry::decode(bytes)", "decode_host_registry(bytes)", 1),
        rust.replace("vm.kind != FleetHostKind::Vm as i32", "false", 1),
        rust.replace(
            "let _guard = super::host_native::owner_operation_lock()?;",
            "let _guard = disabled_lock()?;",
            1,
        ),
        rust.replace("previous_vm_for_code_only_refresh(&registry_pb, machine_id)?", "edge_shared_types::decode_host_registry(&registry_pb)?", 1),
        rust.replace(
            "previous_vm_for_code_only_refresh(&previous.registry_pb, &previous.machine_id)?",
            "edge_shared_types::decode_host_registry(&previous.registry_pb)?",
            1,
        ),
    ):
        try:
            check_refresh(broken)
        except AssertionError:
            pass
        else:
            raise AssertionError("L03_L04_NEGATIVE_FIXTURE_NOT_REJECTED")
    for modified_lifecycle, modified_router in (
        (
            lifecycle,
            router.replace(
                "Reserve unique Git receipt PR and durable BEGIN BEFORE VM CREATE",
                "BEGIN_DISABLED",
                1,
            ),
        ),
        (
            lifecycle.replace(
                "HOST_VM_CREATE_REQUIRES_NATIVE_ONE_TIME_ENROLLMENT_NO_SSH",
                "ALLOW_CREATE",
                1,
            ),
            router,
        ),
    ):
        try:
            check_bootstrap(cloud, access, modified_lifecycle, modified_router)
        except AssertionError:
            pass
        else:
            raise AssertionError("L05_NEGATIVE_FIXTURE_NOT_REJECTED")
    for broken in (
        ci.replace("python3 edge-platform/scripts/test_native_lifecycle_contract.py", "echo disabled", 1),
        ci.replace("cargo test --workspace --locked", "echo skipped", 1),
        ci.replace("needs: [verify, dependencies, windows, linux_candidate, release_authority]", "needs: [dependencies, windows, linux_candidate, release_authority]", 1),
    ):
        try:
            check_ci(broken)
        except AssertionError:
            pass
        else:
            raise AssertionError("L07_NEGATIVE_FIXTURE_NOT_REJECTED")
    print("HOST_LIFECYCLE_SOURCE_CONTRACT=PASS")
    print("HOST_LIFECYCLE_NEGATIVE_FIXTURES=PASS")
    print("HOST_LIFECYCLE_PHYSICAL_N_MINUS_ONE_TO_N=UNPROVEN_SEPARATE_ACCEPTANCE_REQUIRED")


if __name__ == "__main__":
    main()
