#!/usr/bin/env python3
import tempfile
from pathlib import Path

import windows_input_digest as subject


def inputs() -> dict[str, str]:
    return {
        "rust_toolchain": "1.95.0",
        "windows_runner": "windows-2025",
        "sing_box_version": "1.13.9",
        "sing_box_windows_sha256": "1" * 64,
    }


def materialize(root: Path) -> None:
    workflow = root / subject.WINDOWS_BUILD_CONTRACT_PATH
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "before\n"
        + subject.WINDOWS_BUILD_CONTRACT_BEGIN
        + "\ncompile exact-windows\npackage exact-windows\n"
        + subject.WINDOWS_BUILD_CONTRACT_END
        + "\nafter\n",
        encoding="utf-8",
    )

    scripts = root / "edge-platform/scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "windows_input_digest.py").write_text("algorithm-v1\n", encoding="utf-8")

    platform = root / "edge-platform"
    (platform / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    (platform / "Cargo.lock").write_text("lock-v1\n", encoding="utf-8")
    proto = platform / "proto"
    proto.mkdir(exist_ok=True)
    (proto / "contract.proto").write_text("syntax = \"proto3\";\n", encoding="utf-8")

    crates = platform / "crates"
    controller = crates / "edge-controller"
    console = crates / "edge-console"
    diagnostic = crates / "edge-diagnostic"
    shared = crates / "edge-shared-types"
    for path in (controller, console, diagnostic, shared):
        (path / "src").mkdir(parents=True, exist_ok=True)

    (controller / "Cargo.toml").write_text(
        '[package]\nname="edge-controller"\nversion="0.1.0"\n'
        '[dependencies]\nedge-shared-types={path="../edge-shared-types"}\n',
        encoding="utf-8",
    )
    (controller / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (console / "Cargo.toml").write_text(
        '[package]\nname="edge-console"\nversion="0.1.0"\n'
        '[dependencies]\nedge-shared-types={path="../edge-shared-types"}\n',
        encoding="utf-8",
    )
    (console / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (diagnostic / "Cargo.toml").write_text(
        '[package]\nname="edge-diagnostic"\nversion="0.1.0"\n'
        '[dependencies]\nedge-shared-types={path="../edge-shared-types"}\n',
        encoding="utf-8",
    )
    (diagnostic / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (shared / "Cargo.toml").write_text(
        '[package]\nname="edge-shared-types"\nversion="0.1.0"\n',
        encoding="utf-8",
    )
    (shared / "src/lib.rs").write_text("pub struct Shared;\n", encoding="utf-8")


def test_digest_scope() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        materialize(root)
        first = subject.compute_digest(root, inputs())

        unrelated = root / "edge-platform/crates/edge-orchestrator"
        (unrelated / "src").mkdir(parents=True)
        (unrelated / "Cargo.toml").write_text(
            '[package]\nname="edge-orchestrator"\nversion="0.1.0"\n',
            encoding="utf-8",
        )
        (unrelated / "src/main.rs").write_text("fn main() { println!(\"changed\"); }\n", encoding="utf-8")
        assert subject.compute_digest(root, inputs()) == first

        release_tool = root / "edge-platform/crates/edge-shared-types/src/bin/release_set.rs"
        release_tool.parent.mkdir(parents=True)
        release_tool.write_text("fn main() { println!(\"release-only\"); }\n", encoding="utf-8")
        assert subject.compute_digest(root, inputs()) == first

        shared = root / "edge-platform/crates/edge-shared-types/src/lib.rs"
        shared.write_text("pub struct SharedChanged;\n", encoding="utf-8")
        assert subject.compute_digest(root, inputs()) != first


def test_contract_and_dependency_change_identity() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        materialize(root)
        first = subject.compute_digest(root, inputs())

        workflow = root / subject.WINDOWS_BUILD_CONTRACT_PATH
        workflow.write_text(
            "before\n"
            + subject.WINDOWS_BUILD_CONTRACT_BEGIN
            + "\ncompile changed-windows\npackage exact-windows\n"
            + subject.WINDOWS_BUILD_CONTRACT_END
            + "\nafter\n",
            encoding="utf-8",
        )
        assert subject.compute_digest(root, inputs()) != first

        materialize(root)
        changed = inputs()
        changed["sing_box_windows_sha256"] = "2" * 64
        assert subject.compute_digest(root, changed) != first


def test_reuse_requires_schema_six_and_exact_identity() -> None:
    digest = "a" * 64
    kwargs = dict(
        candidate_digest=digest,
        base_schema="6",
        base_digest=digest,
        base_source_revision="b" * 40,
        base_artifact_sha256="c" * 64,
        base_controller_sha256="d" * 64,
        base_console_sha256="e" * 64,
        base_sing_box_sha256="f" * 64,
        base_diagnostic_sha256="1" * 64,
    )
    assert subject.decide_reuse(**kwargs)
    assert not subject.decide_reuse(**{**kwargs, "base_schema": "5"})
    assert not subject.decide_reuse(**{**kwargs, "base_digest": "0" * 64})


def main() -> None:
    test_digest_scope()
    test_contract_and_dependency_change_identity()
    test_reuse_requires_schema_six_and_exact_identity()
    print("windows input digest tests: PASS")


if __name__ == "__main__":
    main()
