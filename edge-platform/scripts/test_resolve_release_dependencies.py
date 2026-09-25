#!/usr/bin/env python3
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from resolve_release_dependencies import load_release_inputs, normalize_release_inputs


def valid_lock() -> dict:
    version = "1.14.2"
    return {
        "schema_version": 1,
        "sing_box": {
            "version": version,
            "windows": {
                "url": (
                    "https://github.com/SagerNet/sing-box/releases/download/"
                    f"v{version}/sing-box-{version}-windows-amd64.zip"
                ),
                "sha256": "1" * 64,
            },
            "linux": {
                "url": (
                    "https://github.com/SagerNet/sing-box/releases/download/"
                    f"v{version}/sing-box-{version}-linux-amd64-glibc.tar.gz"
                ),
                "sha256": "2" * 64,
            },
        },
        "cloudflare_warp": {
            "version": "2026.7.1377.0",
            "url": (
                "https://pkg.cloudflareclient.com/pool/noble/main/c/cloudflare-warp/"
                "cloudflare-warp_2026.7.1377.0_amd64.deb"
            ),
            "sha256": "3" * 64,
        },
        "docker": {
            "engine_version": "5:29.8.1-1~debian.13~trixie",
            "containerd_version": "2.3.5-1~debian.13~trixie",
            "compose_version": "5.5.1-1~debian.13~trixie",
        },
        "oci": {
            "debian_base_image": "docker.io/library/debian@sha256:" + "4" * 64,
            "ubuntu_base_image": "docker.io/library/ubuntu@sha256:" + "5" * 64,
            "mesh_image": "docker.io/cloudflare/mesh@sha256:" + "6" * 64,
        },
    }


class ReleaseInputLockTests(unittest.TestCase):
    def test_same_lock_selects_same_identities(self) -> None:
        first = normalize_release_inputs(valid_lock())
        second = normalize_release_inputs(copy.deepcopy(valid_lock()))
        self.assertEqual(first, second)
        self.assertRegex(first["authority_sha256"], r"^[0-9a-f]{64}$")

    def test_semantic_lock_change_changes_authority(self) -> None:
        first = normalize_release_inputs(valid_lock())
        changed = valid_lock()
        changed["cloudflare_warp"]["sha256"] = "9" * 64
        second = normalize_release_inputs(changed)
        self.assertNotEqual(first["authority_sha256"], second["authority_sha256"])
        self.assertNotEqual(first["warp_sha256"], second["warp_sha256"])

    def test_rejects_unsupported_schema(self) -> None:
        value = valid_lock()
        value["schema_version"] = 2
        with self.assertRaisesRegex(ValueError, "unsupported release input lock schema"):
            normalize_release_inputs(value)

    def test_rejects_missing_required_input(self) -> None:
        value = valid_lock()
        del value["docker"]["containerd_version"]
        with self.assertRaisesRegex(ValueError, "docker keys mismatch"):
            normalize_release_inputs(value)

    def test_rejects_unknown_input(self) -> None:
        value = valid_lock()
        value["docker"]["unexpected"] = "value"
        with self.assertRaisesRegex(ValueError, "docker keys mismatch"):
            normalize_release_inputs(value)

    def test_rejects_malformed_hash(self) -> None:
        value = valid_lock()
        value["sing_box"]["windows"]["sha256"] = "ABC"
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            normalize_release_inputs(value)

    def test_rejects_mutable_oci_identity(self) -> None:
        value = valid_lock()
        value["oci"]["mesh_image"] = "docker.io/cloudflare/mesh:latest"
        with self.assertRaisesRegex(ValueError, "exact immutable"):
            normalize_release_inputs(value)

    def test_rejects_sing_box_url_version_mismatch(self) -> None:
        value = valid_lock()
        value["sing_box"]["linux"]["url"] = (
            "https://github.com/SagerNet/sing-box/releases/latest/download/"
            "sing-box-linux-amd64.tar.gz"
        )
        with self.assertRaisesRegex(ValueError, "exact pinned"):
            normalize_release_inputs(value)

    def test_rejects_unpinned_warp_url(self) -> None:
        value = valid_lock()
        value["cloudflare_warp"]["url"] = (
            "https://pkg.cloudflareclient.com/dists/noble/main/binary-amd64/Packages"
        )
        with self.assertRaisesRegex(ValueError, "exact pinned amd64 package"):
            normalize_release_inputs(value)

    def test_rejects_incompatible_docker_suite(self) -> None:
        value = valid_lock()
        value["docker"]["engine_version"] = "5:29.8.1-1~debian.12~bookworm"
        with self.assertRaisesRegex(ValueError, "canonical Debian 13/trixie"):
            normalize_release_inputs(value)

    def test_missing_lock_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.json"
            with self.assertRaisesRegex(ValueError, "release input lock is missing"):
                load_release_inputs(path)

    def test_checked_in_lock_is_valid(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        selected = load_release_inputs(
            repo_root / "infra/release/release-inputs.lock.json"
        )
        self.assertEqual(selected["schema_version"], 1)
        self.assertEqual(selected["sing_box_version"], "1.14.2")
        self.assertEqual(selected["warp_version"], "2026.7.1377.0")
        self.assertTrue(selected["mesh_image"].startswith("docker.io/cloudflare/mesh@sha256:"))


if __name__ == "__main__":
    unittest.main()
