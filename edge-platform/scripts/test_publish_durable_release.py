#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "scripts" / "publish_durable_release.sh"


FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["FAKE_GITHUB_STATE"])


def load():
    return json.loads(state_path.read_text())


def save(state):
    state_path.write_text(json.dumps(state, sort_keys=True))


args = sys.argv[1:]
if not args or args[0] != "api":
    raise SystemExit(f"unsupported gh invocation: {args!r}")

method = "GET"
endpoint = None
fields = {}
i = 1
while i < len(args):
    arg = args[i]
    if arg == "--method":
        method = args[i + 1]
        i += 2
    elif arg in ("-f", "-F"):
        key, value = args[i + 1].split("=", 1)
        fields[key] = value
        i += 2
    elif arg.startswith("-"):
        raise SystemExit(f"unsupported gh flag: {arg}")
    else:
        if endpoint is not None:
            raise SystemExit(f"multiple gh endpoints: {endpoint!r}, {arg!r}")
        endpoint = arg
        i += 1

if endpoint is None:
    raise SystemExit("missing gh endpoint")

state = load()
tag = state["tag_name"]
release = state.get("release")

if endpoint == f"repos/iamaman11/sing-box/git/ref/tags/{tag}" and method == "GET":
    if state.get("tag_sha") is None:
        print("gh: Not Found (HTTP 404)", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps({
        "ref": f"refs/tags/{tag}",
        "object": {"type": "commit", "sha": state["tag_sha"]},
    }))
elif endpoint == "repos/iamaman11/sing-box/git/refs" and method == "POST":
    assert fields["ref"] == f"refs/tags/{tag}"
    state["tag_sha"] = fields["sha"]
    save(state)
    print(json.dumps({"ref": fields["ref"], "object": {"type": "commit", "sha": fields["sha"]}}))
elif endpoint.startswith("repos/iamaman11/sing-box/releases?") and method == "GET":
    page = 1
    for part in endpoint.split("?", 1)[1].split("&"):
        key, value = part.split("=", 1)
        if key == "page":
            page = int(value)
    if page == 1 and release is not None:
        print(json.dumps([release]))
    else:
        print("[]")
elif endpoint == "repos/iamaman11/sing-box/releases" and method == "POST":
    assert release is None
    release = {
        "id": state["next_release_id"],
        "tag_name": fields["tag_name"],
        "name": fields["name"],
        "draft": fields["draft"] == "true",
        "prerelease": fields["prerelease"] == "true",
        "assets": [],
    }
    state["release"] = release
    save(state)
    print(json.dumps(release))
elif release is not None and endpoint == f"repos/iamaman11/sing-box/releases/{release['id']}" and method == "GET":
    print(json.dumps(release))
elif release is not None and endpoint == f"repos/iamaman11/sing-box/releases/{release['id']}" and method == "PATCH":
    release["draft"] = fields.get("draft", str(release["draft"])).lower() == "true"
    release["prerelease"] = fields.get("prerelease", str(release["prerelease"])).lower() == "true"
    state["release"] = release
    save(state)
    print(json.dumps(release))
elif endpoint == f"repos/iamaman11/sing-box/releases/tags/{tag}" and method == "GET":
    if release is None or release["draft"]:
        print("gh: Not Found (HTTP 404)", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(release))
else:
    raise SystemExit(f"unsupported gh API call: method={method} endpoint={endpoint} fields={fields}")
'''


FAKE_CURL = r'''#!/usr/bin/env python3
import base64
import json
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

state_path = Path(os.environ["FAKE_GITHUB_STATE"])


def load():
    return json.loads(state_path.read_text())


def save(state):
    state_path.write_text(json.dumps(state, sort_keys=True))


args = sys.argv[1:]
method = "GET"
data_file = None
output = None
url = None
i = 0
while i < len(args):
    arg = args[i]
    if arg == "--request":
        method = args[i + 1]
        i += 2
    elif arg == "--data-binary":
        value = args[i + 1]
        assert value.startswith("@")
        data_file = Path(value[1:])
        i += 2
    elif arg == "--output":
        output = Path(args[i + 1])
        i += 2
    elif arg in ("--header",):
        i += 2
    elif arg in ("--fail", "--silent", "--show-error", "--location"):
        i += 1
    elif arg.startswith("-"):
        raise SystemExit(f"unsupported curl flag: {arg}")
    else:
        url = arg
        i += 1

if url is None:
    raise SystemExit("missing curl URL")

state = load()
release = state["release"]

upload = re.fullmatch(
    r"https://uploads\.github\.com/repos/iamaman11/sing-box/releases/(\d+)/assets\?name=([^&]+)",
    url,
)
download = re.fullmatch(
    r"https://api\.github\.com/repos/iamaman11/sing-box/releases/assets/(\d+)",
    url,
)

if method == "POST" and upload:
    assert int(upload.group(1)) == release["id"]
    assert data_file is not None
    name = parse_qs(urlparse(url).query)["name"][0]
    assert all(asset["name"] != name for asset in release["assets"])
    asset_id = state["next_asset_id"]
    state["next_asset_id"] += 1
    content = data_file.read_bytes()
    release["assets"].append({
        "id": asset_id,
        "name": name,
        "size": len(content),
        "content": base64.b64encode(content).decode(),
    })
    state["release"] = release
    save(state)
elif method == "GET" and download:
    assert output is not None
    asset_id = int(download.group(1))
    matches = [asset for asset in release["assets"] if asset["id"] == asset_id]
    assert len(matches) == 1
    output.write_bytes(base64.b64decode(matches[0]["content"]))
else:
    raise SystemExit(f"unsupported curl call: method={method} url={url}")
'''


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def prepare_inputs(root: Path, accepted: str, candidate: str, run_id: str) -> dict[str, str]:
    windows = root / "windows"
    linux = root / "linux"
    authority = root / "release-set"
    output = root / "output"
    windows.mkdir()
    linux.mkdir()
    authority.mkdir()

    (windows / "edge-platform-windows.zip").write_bytes(b"windows-runtime")
    (linux / "edge-agent").write_bytes(b"edge-agent")
    (linux / "edge-controller").write_bytes(b"edge-controller")
    (linux / "edge-release-set").write_bytes(b"release-set-verifier")

    release_bytes = b"canonical-release-set"
    (authority / "release-set.pb").write_bytes(release_bytes)
    digest = hashlib.sha256(release_bytes).hexdigest()
    (authority / "release-set.pb.sha256").write_text(f"{digest}  release-set.pb\n")
    (authority / "acceptance.json").write_text(json.dumps({
        "schema": 1,
        "accepted_revision": accepted,
        "candidate_revision": candidate,
        "source_tree": "c" * 40,
        "candidate_run_id": int(run_id),
    }))

    return {
        "GH_TOKEN": "test-token",
        "REPOSITORY": "iamaman11/sing-box",
        "ACCEPTED_REVISION": accepted,
        "CANDIDATE_REVISION": candidate,
        "CANDIDATE_RUN_ID": run_id,
        "WINDOWS_DIR": str(windows),
        "LINUX_DIR": str(linux),
        "RELEASE_SET_DIR": str(authority),
        "OUTPUT_DIR": str(output),
        "release_set_sha": digest,
    }


def run_publisher(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(PUBLISHER)],
        check=True,
        text=True,
        capture_output=True,
        env=env,
    )


def scenario(existing_draft: bool) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        write_executable(fake_bin / "gh", FAKE_GH)
        write_executable(fake_bin / "curl", FAKE_CURL)

        accepted = "a" * 40
        candidate = "b" * 40
        run_id = "12345"
        values = prepare_inputs(root, accepted, candidate, run_id)
        tag = f"edge-release-{values['release_set_sha']}"

        release = None
        if existing_draft:
            release = {
                "id": 392256134,
                "tag_name": tag,
                "name": "Edge Platform release test",
                "draft": True,
                "prerelease": False,
                "assets": [],
            }

        state_path = root / "github-state.json"
        state_path.write_text(json.dumps({
            "tag_name": tag,
            "tag_sha": accepted,
            "release": release,
            "next_release_id": 500000001,
            "next_asset_id": 700000001,
        }))

        env = os.environ.copy()
        env.update({key: value for key, value in values.items() if key != "release_set_sha"})
        env["FAKE_GITHUB_STATE"] = str(state_path)
        env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"

        first = run_publisher(env)
        state = json.loads(state_path.read_text())
        assert state["release"]["draft"] is False
        assert state["release"]["prerelease"] is False
        assert len(state["release"]["assets"]) == 11
        assert f"release_id={state['release']['id']}" in first.stdout
        assert "durable_assets=11" in first.stdout

        asset_ids = {asset["name"]: asset["id"] for asset in state["release"]["assets"]}
        second = run_publisher(env)
        state_again = json.loads(state_path.read_text())
        assert state_again["release"]["draft"] is False
        assert len(state_again["release"]["assets"]) == 11
        assert {asset["name"]: asset["id"] for asset in state_again["release"]["assets"]} == asset_ids
        assert "durable_assets=11" in second.stdout


def main() -> None:
    scenario(existing_draft=True)
    scenario(existing_draft=False)
    print("durable release publisher tests: OK")


if __name__ == "__main__":
    main()
