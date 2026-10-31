#!/usr/bin/env python3
"""One-shot OLD-root-Admin code-only handoff. No trust or journal mutation."""
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import urllib.request

API = "https://api.github.com/repos/iamaman11/sing-box"
AGENT = "/usr/local/libexec/sing-box/edge-agent"
TRUST = "/opt/vultr-edge-stack/native-host/trust.pb"
LIMIT = 32 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")

def reject(reason):
    raise SystemExit("HOST_VM_LEGACY_BRIDGE_" + reason)

def fetch(url, limit):
    if not url.startswith("https://"):
        reject("URL_INVALID")
    req = urllib.request.Request(url, headers={"User-Agent": "sing-box-host-bridge/1"})
    with urllib.request.urlopen(req, timeout=25) as r:
        if not r.geturl().startswith("https://"):
            reject("REDIRECT_INVALID")
        result = r.read(limit + 1)
    if not result or len(result) > limit:
        reject("SIZE_INVALID")
    return result

def fetch_json(url):
    try:
        result = json.loads(fetch(url, 262144))
    except (ValueError, UnicodeError):
        reject("JSON_INVALID")
    if not isinstance(result, dict):
        reject("JSON_OBJECT_REQUIRED")
    return result

def published_release(digest):
    r = fetch_json(API + "/releases/tags/edge-release-" + digest)
    if (r.get("tag_name") != "edge-release-" + digest
            or r.get("draft") is not False or r.get("prerelease") is not False):
        reject("RELEASE_NOT_ACCEPTED")
    return r

def asset(release, name, tag):
    found = [x for x in release.get("assets", []) if x.get("name") == name]
    if len(found) != 1:
        reject("ASSET_NOT_UNIQUE")
    x = found[0]
    sha = x.get("digest", "").removeprefix("sha256:")
    expected = "https://github.com/iamaman11/sing-box/releases/download/edge-release-" + tag + "/" + name
    if not SHA.fullmatch(sha) or x.get("browser_download_url") != expected:
        reject("ASSET_DIGEST_OR_URL_INVALID")
    return sha, expected, x.get("size", -1)

def checked(path, file, mode):
    try:
        m = os.lstat(path)
    except OSError:
        reject("PATH_MISSING")
    if (m.st_uid != 0 or stat.S_IMODE(m.st_mode) != mode
            or not (stat.S_ISREG(m.st_mode) if file else stat.S_ISDIR(m.st_mode))):
        reject("PATH_UNTRUSTED")

def read_small(path, limit):
    with open(path, "rb") as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        reject("FILE_TOO_LARGE")
    return data

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    if (len(sys.argv) != 3 or os.geteuid() != 0
            or any(not SHA.fullmatch(d) for d in sys.argv[1:])
            or sys.argv[1] == sys.argv[2]):
        reject("REQUEST_INVALID")
    old, new = sys.argv[1:]
    for folder in ("/usr", "/usr/local", "/usr/local/libexec",
                   "/usr/local/libexec/sing-box", "/opt", "/opt/vultr-edge-stack"):
        checked(folder, False, 0o755)
    checked("/opt/vultr-edge-stack/native-host", False, 0o700)
    checked(TRUST, True, 0o600)
    checked(AGENT, True, 0o755)
    trust_sha = sha(read_small(TRUST, 9 * 1024 * 1024))
    old_sha, _, old_size = asset(published_release(old), "edge-agent-linux-amd64", old)
    if not (0 < old_size <= LIMIT):
        reject("OLD_ASSET_SIZE_INVALID")
    installed = read_small(AGENT, LIMIT)
    if len(installed) != old_size or sha(installed) != old_sha:
        reject("OLD_BINARY_MISMATCH")

    head = fetch_json(API + "/git/ref/heads/main")
    latest = fetch_json(API + "/releases/latest")
    revision = head.get("object", {}).get("sha", "")
    if (head.get("object", {}).get("type") != "commit"
            or not re.fullmatch(r"[0-9a-f]{40}", revision)
            or latest.get("target_commitish") != revision
            or latest.get("tag_name") != "edge-release-" + new
            or latest.get("draft") is not False or latest.get("prerelease") is not False):
        reject("CURRENT_MAIN_MISMATCH")
    target = published_release(new)
    if target.get("target_commitish") != revision:
        reject("TARGET_MAIN_MISMATCH")
    release_sha, _, release_size = asset(target, "release-set.pb", new)
    if release_sha != new or not (0 < release_size <= 65536):
        reject("RELEASE_SET_MISMATCH")
    expected, url, size = asset(target, "edge-agent-linux-amd64", new)
    if not (0 < size <= LIMIT):
        reject("NEW_ASSET_SIZE_INVALID")
    binary = fetch(url, LIMIT)
    if len(binary) != size or sha(binary) != expected:
        reject("NEW_BINARY_DIGEST_INVALID")

    if sha(read_small(TRUST, 9 * 1024 * 1024)) != trust_sha:
        reject("TRUST_CHANGED")
    folder = os.path.dirname(AGENT)
    fd, temporary = tempfile.mkstemp(prefix=".edge-agent-bridge-", dir=folder)
    published = False
    try:
        os.fchmod(fd, 0o755)
        with os.fdopen(fd, "wb") as f:
            f.write(binary)
            f.flush()
            os.fsync(f.fileno())
        checked(AGENT, True, 0o755)
        if (sha(read_small(AGENT, LIMIT)) != old_sha
                or sha(read_small(TRUST, 9 * 1024 * 1024)) != trust_sha):
            reject("PRE_REPLACE_DRIFT")
        os.replace(temporary, AGENT)
        published = True
        d = os.open(folder, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if not published and os.path.exists(temporary):
            os.unlink(temporary)
    if (sha(read_small(AGENT, LIMIT)) != expected
            or sha(read_small(TRUST, 9 * 1024 * 1024)) != trust_sha):
        reject("POSTSTATE_UNPROVEN")
    print("HOST_VM_LEGACY_BINARY_REPLACED_TRUST_UNCHANGED")
    print("NEXT=VERIFY_SIGNED_ADMIN_TERMINAL_THEN_SEPARATE_HOST_RECOVER")

if __name__ == "__main__":
    main()
