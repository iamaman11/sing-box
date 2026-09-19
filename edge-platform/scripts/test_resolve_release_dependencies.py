#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from resolve_release_dependencies import resolve_sing_box, resolve_warp_packages


def asset(name: str, version: str, digest: str = "1" * 64) -> dict:
    return {
        "name": name,
        "browser_download_url": (
            f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{name}"
        ),
        "digest": f"sha256:{digest}",
    }


def release(version: str, *, prerelease: bool = False, draft: bool = False) -> dict:
    return {
        "tag_name": f"v{version}",
        "prerelease": prerelease,
        "draft": draft,
        "assets": [
            asset(f"sing-box-{version}-windows-amd64.zip", version, "2" * 64),
            asset(f"sing-box-{version}-linux-amd64-glibc.tar.gz", version, "3" * 64),
        ],
    }


class ResolverTests(unittest.TestCase):
    def test_selects_highest_stable_sing_box_release(self) -> None:
        result = resolve_sing_box(
            [
                release("1.13.21"),
                release("1.15.0", prerelease=True),
                release("1.14.1"),
            ]
        )
        self.assertEqual(result["version"], "1.14.1")
        self.assertEqual(result["windows"]["sha256"], "2" * 64)
        self.assertEqual(result["linux"]["sha256"], "3" * 64)

    def test_rejects_missing_sing_box_asset_digest(self) -> None:
        value = release("1.14.1")
        value["assets"][0]["digest"] = None
        with self.assertRaises(ValueError):
            resolve_sing_box([value])

    def test_ignores_non_normalized_or_prerelease_tags(self) -> None:
        invalid = release("1.14.1")
        invalid["tag_name"] = "v1.14.1-rc.1"
        result = resolve_sing_box([invalid, release("1.13.21")])
        self.assertEqual(result["version"], "1.13.21")

    def test_selects_highest_numeric_warp_version(self) -> None:
        raw = """Package: cloudflare-warp
Version: 2026.6.100.0
Architecture: amd64
Filename: pool/noble/main/c/cloudflare-warp/old.deb
SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Package: cloudflare-warp
Version: 2026.7.1377.0
Architecture: amd64
Filename: pool/noble/main/c/cloudflare-warp/new.deb
SHA256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"""
        result = resolve_warp_packages(raw)
        self.assertEqual(result["version"], "2026.7.1377.0")
        self.assertEqual(
            result["url"],
            "https://pkg.cloudflareclient.com/pool/noble/main/c/cloudflare-warp/new.deb",
        )

    def test_rejects_unsafe_warp_filename(self) -> None:
        raw = """Package: cloudflare-warp
Version: 2026.7.1377.0
Architecture: amd64
Filename: pool/../../secret.deb
SHA256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"""
        with self.assertRaises(ValueError):
            resolve_warp_packages(raw)


if __name__ == "__main__":
    unittest.main()
