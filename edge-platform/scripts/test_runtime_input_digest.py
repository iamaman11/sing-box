#!/usr/bin/env python3
import json
import tempfile
from pathlib import Path

import runtime_input_digest as subject


def inputs() -> dict[str, str]:
    return {
        "rust_toolchain": "1.95.0",
        "sing_box_version": "1.13.9",
        "sing_box_linux_url": "https://example.invalid/sing-box.tar.gz",
        "sing_box_linux_sha256": "1" * 64,
        "warp_version": "2026.9.1",
        "warp_url": "https://example.invalid/warp.deb",
        "warp_sha256": "2" * 64,
        "debian_base_image": "docker.io/library/debian@sha256:" + "3" * 64,
        "ubuntu_base_image": "docker.io/library/ubuntu@sha256:" + "4" * 64,
        "mesh_image": "docker.io/cloudflare/mesh@sha256:" + "5" * 64,
        "docker_engine_version": "5:29.8.1-1~debian.13~trixie",
        "containerd_version": "2.3.5-1~debian.13~trixie",
        "compose_version": "5.5.1-1~debian.13~trixie",
    }


def materialize(root: Path) -> None:
    for raw in subject.TRACKED_PATHS:
        path = root / raw
        if Path(raw).suffix:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{raw}\n", encoding="utf-8")
        else:
            path.mkdir(parents=True, exist_ok=True)
            (path / "input.txt").write_text(f"{raw}\n", encoding="utf-8")
    workflow = root / subject.RUNTIME_BUILD_CONTRACT_PATH
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "control-plane-before\n"
        + subject.RUNTIME_BUILD_CONTRACT_BEGIN
        + "\ndocker build exact-runtime\n"
        + subject.RUNTIME_BUILD_CONTRACT_END
        + "\ncontrol-plane-after\n",
        encoding="utf-8",
    )


def test_digest_scope() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        materialize(root)
        original = subject.compute_digest(root, inputs())

        unrelated = root / "docs/unrelated.md"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("control-plane docs only\n", encoding="utf-8")
        assert subject.compute_digest(root, inputs()) == original

        workflow = root / subject.RUNTIME_BUILD_CONTRACT_PATH
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace("control-plane-before", "control-plane-changed"),
            encoding="utf-8",
        )
        assert subject.compute_digest(root, inputs()) == original

        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace("docker build exact-runtime", "docker build changed-runtime"),
            encoding="utf-8",
        )
        assert subject.compute_digest(root, inputs()) != original

        materialize(root)
        tracked = root / "edge-platform/crates/edge-agent/input.txt"
        tracked.write_text("runtime changed\n", encoding="utf-8")
        assert subject.compute_digest(root, inputs()) != original


def test_dependency_change_invalidates_digest() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        materialize(root)
        first = subject.compute_digest(root, inputs())
        changed = inputs()
        changed["warp_sha256"] = "9" * 64
        assert subject.compute_digest(root, changed) != first


def test_reuse_is_fail_closed() -> None:
    digest = "a" * 64
    source = "b" * 40
    agent = "c" * 64
    gateway = "ghcr.io/iamaman11/vultr-edge-gateway@sha256:" + "d" * 64
    warp = "ghcr.io/iamaman11/vultr-warp-egress@sha256:" + "e" * 64

    assert subject.decide_reuse(digest, "4", digest, source, agent, gateway, warp)
    assert subject.decide_reuse(digest, "5", digest, source, agent, gateway, warp)
    assert not subject.decide_reuse(digest, "3", digest, source, agent, gateway, warp)
    assert not subject.decide_reuse(digest, "4", "f" * 64, source, agent, gateway, warp)
    assert not subject.decide_reuse(digest, "4", "", source, agent, gateway, warp)
    assert not subject.decide_reuse(digest, "4", digest, "", agent, gateway, warp)
    assert not subject.decide_reuse(digest, "4", digest, source, agent, "latest", warp)


if __name__ == "__main__":
    test_digest_scope()
    test_dependency_change_invalidates_digest()
    test_reuse_is_fail_closed()
    print("runtime input digest tests: PASS")
