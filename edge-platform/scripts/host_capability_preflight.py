#!/usr/bin/env python3
"""Read-only protected-Environment capability observation for /host status --deep.

Never a mutation admission authority: no secret values, keys, IDs, raw API
responses or API error bodies are emitted. Only bounded GET requests to three
fixed provider domains. No replay, fallback credentials or credential issuance.
"""
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

TIMEOUT = 12
WORKER_BINDINGS = frozenset({
    "EDGE_HOST_SIGNING_PKCS8_BASE64",
    "EDGE_HOST_SIGNING_KEY_ID",
    "EDGE_HOST_ACCESS_ISSUER",
    "EDGE_HOST_ACCESS_AUD",
    "EDGE_HOST_GITHUB_ACTOR_ID",
})


class DenyRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def observe_json(url, token, host, auth_prefix="Bearer", failure=None):
    """Only GET, exact HTTPS authority, no redirects or response body logging."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != host:
        return None
    request = Request(url, headers={
        "Authorization": f"{auth_prefix} {token}",
        "Accept": "application/json",
    }, method="GET")
    try:
        with build_opener(DenyRedirect()).open(request, timeout=TIMEOUT) as response:
            if response.geturl() != url or response.status != 200:
                return None
            raw = response.read(512 * 1024 + 1)
            if len(raw) > 512 * 1024:
                return None
            return json.loads(raw)
    except HTTPError as error:
        if failure is not None:
            failure.append("HTTP_" + str(error.code) if error.code in (401, 403, 404)
                           else "HTTP_OTHER")
        return None
    except (URLError, TimeoutError, ValueError, OSError):
        if failure is not None:
            failure.append("TRANSPORT_OR_SCHEMA_UNPROVEN")
        return None


def exact_production_worker():
    text = Path("infra/production/production.textproto").read_text(encoding="utf-8")
    ids = re.findall(r'^  active_account_id: "([0-9a-f]{32})"$', text, re.M)
    workers = re.findall(r'^    vm_worker_name: "([a-z0-9-]+)"$', text, re.M)
    if len(ids) != 1 or len(workers) != 1:
        return None
    return ids[0], workers[0]


def target_machine(application_spec_path, machine_id):
    """Derive the ONE provider target from Rust-selected protected Git desired.

    The provider's input is never a caller-supplied URL or VM identity.
    Other Git host kinds remain unavailable rather than defaulting to a
    hard-coded acceptance instance.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", machine_id):
        return False
    # New Git per-host authority is Rust-selected and independently compiled
    # with pinned Buf before this read-only probe. Do NOT duplicate its schema
    # with a custom Python textproto parser.
    expected_typed = f"infra/hosts/specs/{machine_id}.textproto"
    if application_spec_path == expected_typed:
        path = Path(expected_typed)
        return (path.is_file() and not path.is_symlink()
                and 0 < path.stat().st_size <= 131_072)
    if not re.fullmatch(r"infra/application/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json",
                        application_spec_path):
        return False
    try:
        app = json.loads(Path(application_spec_path).read_text(encoding="utf-8"))
        if app.get("schema") != 2 or app.get("machine_id") != machine_id:
            return False
        provider = app.get("vultr_spec_path")
        if (not isinstance(provider, str)
                or not re.fullmatch(r"infra/vultr/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json", provider)):
            return False
        desired = json.loads(Path(provider).read_text(encoding="utf-8"))
        machines = desired.get("machines")
        return (desired.get("schema") == 1
                and isinstance(machines, list) and len(machines) == 1
                and isinstance(machines[0], dict)
                and machines[0].get("id") == machine_id)
    except (ValueError, KeyError, TypeError, OSError):
        return False


def provider_inventory(doc, machine_id):
    if not isinstance(doc, dict) or not isinstance(doc.get("instances"), list):
        return "UNPROVEN_PROVIDER_INVENTORY"
    instances = doc["instances"]
    if not all(isinstance(item, dict) for item in instances):
        return "UNPROVEN_PROVIDER_INVENTORY"
    count = sum(item.get("label") == machine_id for item in instances)
    if count > 1:
        return "BLOCKED_DUPLICATE_MACHINE_LABEL"
    if count == 1:
        return "EXACT_LABEL_PRESENT_NO_CREATE"
    links = doc.get("meta", {}).get("links") if isinstance(doc.get("meta"), dict) else None
    if not isinstance(links, dict) or links.get("next"):
        return "UNPROVEN_PAGINATED_OR_MISSING_META"
    return "LABEL_ABSENT_SINGLE_PAGE_NOT_CREATE_AUTHORITY"


def worker_bindings(doc):
    if not isinstance(doc, dict) or doc.get("success") is not True:
        return "UNPROVEN_WORKER_SECRETS_API"
    bindings = doc.get("result")
    if not isinstance(bindings, list):
        return "UNPROVEN_WORKER_SECRETS_SCHEMA"
    if not all(isinstance(b, dict) and b.get("type") == "secret_text"
               and isinstance(b.get("name"), str) for b in bindings):
        return "UNPROVEN_WORKER_SECRETS_SCHEMA"
    names = {b["name"] for b in bindings}
    return ("PRESENT_NAMES_ONLY_NOT_SIGNING_PROOF" if WORKER_BINDINGS <= names
            else "INCOMPLETE_HOST_SIGNER_BINDINGS")


def observe(machine_id, desired_spec_path):
    result = {
        "schema": "sing-box.host-capability-observation/v1",
        "machine_id": machine_id,
        "scope": "READ_ONLY_PROTECTED_ENVIRONMENT",
        "git_spec": "UNPROVEN",
        "vultr_api": "UNPROVEN",
        "vultr_machine": "UNPROVEN",
        "github_control_token": "UNPROVEN",
        "github_runner_visibility": "UNPROVEN",
        "cloudflare_api": "UNPROVEN",
        "worker_host_signing_bindings": "UNPROVEN",
        "worker_signing_public_key": "UNPROVEN_NO_NATIVE_ATTESTATION",
        "vm_access_service_identity": "UNPROVEN",
        "operator_ssh_private_key": "UNPROVEN",
        "provider_mutations": 0,
        "worker_mutations": 0,
        "github_mutations": 0,
        "next_action": "GIT_PINNED_TRUST_AND_TYPED_FIRST_USE_REQUIRED",
    }
    if not target_machine(desired_spec_path, machine_id):
        result["git_spec"] = "BLOCKED_MACHINE_SPEC_MISMATCH"
        return result
    result["git_spec"] = "EXACT_GIT_SELECTED_APPLICATION_MACHINE"

    key = os.environ.get("VULTR_API_KEY", "")
    if key:
        inventory = observe_json("https://api.vultr.com/v2/instances?per_page=100",
                                 key, "api.vultr.com")
        if isinstance(inventory, dict):
            result["vultr_api"] = "READABLE"
            result["vultr_machine"] = provider_inventory(inventory, machine_id)

    gh = os.environ.get("IAMAMAN11_SING_BOX_CONTROL_PLANE_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if gh and repository == "iamaman11/sing-box":
        repo = observe_json(f"https://api.github.com/repos/{repository}",
                            gh, "api.github.com")
        if isinstance(repo, dict) and repo.get("full_name") == repository:
            permissions = repo.get("permissions")
            result["github_control_token"] = (
                "REPOSITORY_PUSH_VISIBLE" if isinstance(permissions, dict)
                and permissions.get("push") is True else "READABLE_WRITE_UNPROVEN")
        runners = observe_json(f"https://api.github.com/repos/{repository}/actions/runners?per_page=1",
                               gh, "api.github.com")
        if isinstance(runners, dict) and isinstance(runners.get("runners"), list):
            result["github_runner_visibility"] = "READABLE"

    # The existing accepted VM Worker owner uses this scoped read principal.
    # The historical generic CLOUDFLARE_API_TOKEN is scoped to another account
    # and returned 403 on the canonical VM Worker; never fall back to it.
    api = os.environ.get("CLOUDFLARE_CONTROL_TOKEN", "")
    identity = exact_production_worker()
    if api and identity:
        verification = observe_json("https://api.cloudflare.com/client/v4/user/tokens/verify",
                                    api, "api.cloudflare.com")
        if isinstance(verification, dict) and verification.get("success") is True:
            result["cloudflare_api"] = "TOKEN_VALID_API_READABLE"
            account, worker = identity
            failure = []
            secrets = observe_json(
                f"https://api.cloudflare.com/client/v4/accounts/{account}/workers/scripts/{worker}/secrets",
                api, "api.cloudflare.com", failure=failure)
            result["worker_host_signing_bindings"] = (
                worker_bindings(secrets) if secrets is not None else
                "UNPROVEN_WORKER_SECRETS_" + (failure[0] if failure else "UNKNOWN"))

    if (os.environ.get("CLOUDFLARE_VM_ACCESS_CLIENT_ID")
            and os.environ.get("CLOUDFLARE_VM_ACCESS_CLIENT_SECRET")):
        result["vm_access_service_identity"] = "PRESENT_UNVERIFIED"

    if os.environ.get("VULTR_SSH_PRIVATE_KEY"):
        result["operator_ssh_private_key"] = "PRESENT_UNVERIFIED"
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("HOST_CAPABILITY_MACHINE_SCOPE_INVALID")
    # Output contains only fixed enums, no tokens, credentials, network
    # addresses, private keys, account identifiers or provider payloads.
    print(json.dumps(observe(sys.argv[1], sys.argv[2]), sort_keys=True))
