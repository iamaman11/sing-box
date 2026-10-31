#!/usr/bin/env python3
"""Read-only Access isolation readback for the existing /host --deep workflow.

VM and Windows credentials remain separate. The optional third application
covers only VM Worker's /v1/host subtree; neither token ID nor secret leaves
this process. Cloudflare management GET is not signer/receipt proof.
"""
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MAX_BYTES = 524288
ROOT = "https://api.cloudflare.com/client/v4/accounts"


def exact_production(text):
    def one(name):
        values = re.findall(r'^\s*' + re.escape(name) + r': "([A-Za-z0-9.-]+)"\s*$', text, re.M)
        if len(values) != 1:
            raise ValueError("CONFIG_MISSING_OR_DUPLICATE")
        return values[0]
    return {name: one(name) for name in (
        "active_account_id", "windows_worker_name", "vm_worker_name",
        "workers_dev_subdomain", "windows_access_application_name",
        "vm_access_application_name", "windows_access_policy_name",
        "vm_access_policy_name", "windows_host_service_token_name",
        "vm_host_service_token_name")}


def unique(items, name):
    found = [item for item in items if isinstance(item, dict) and item.get("name") == name]
    return found[0] if len(found) == 1 else None


def policy_tokens(policy):
    if policy.get("decision") != "non_identity" or policy.get("exclude") or policy.get("require"):
        return None
    includes = policy.get("include")
    if not isinstance(includes, list):
        return None
    ids = []
    for item in includes:
        if not isinstance(item, dict) or set(item) != {"service_token"}:
            return None
        token = item["service_token"]
        if not isinstance(token, dict) or not isinstance(token.get("token_id"), str):
            return None
        ids.append(token["token_id"])
    return ids if len(ids) == len(set(ids)) else None


def exact_app(app, policies, name, hostname, ids, policy_name):
    if not app or app.get("type") != "self_hosted" or app.get("name") != name:
        return False
    if app.get("service_auth_401_redirect") is not True:
        return False
    destinations = app.get("destinations")
    if (not isinstance(destinations, list) or len(destinations) != 1
            or not isinstance(destinations[0], dict)):
        return False
    destination = destinations[0]
    if (destination.get("type") != "public"
            or destination.get("uri") != hostname
            or destination.get("worker_id")
            or destination.get("overrides")):
        return False
    if not isinstance(policies, list) or len(policies) != 1:
        return False
    policy = policies[0]
    if not isinstance(policy, dict) or policy.get("name") != policy_name:
        return False
    return policy_tokens(policy) is not None and sorted(policy_tokens(policy)) == sorted(ids)


def evaluate(cfg, tokens, apps, policy_by_id):
    vm = unique(tokens, cfg["vm_host_service_token_name"])
    win = unique(tokens, cfg["windows_host_service_token_name"])
    if not vm or not win or vm.get("enabled") is not True or win.get("enabled") is not True:
        return {"host_route": "UNPROVEN_TOKENS", "vm_credentials": "UNPROVEN",
                "windows_credentials": "UNPROVEN", "mutations": 0}
    vmid, winid = vm.get("id"), win.get("id")
    if not isinstance(vmid, str) or not isinstance(winid, str) or vmid == winid:
        return {"host_route": "UNPROVEN_TOKENS", "vm_credentials": "UNPROVEN",
                "windows_credentials": "UNPROVEN", "mutations": 0}
    domain = cfg["workers_dev_subdomain"]
    vmhost = cfg["vm_worker_name"] + "." + domain + ".workers.dev"
    winhost = cfg["windows_worker_name"] + "." + domain + ".workers.dev"

    def check(name, address, ids, policy_name):
        app = unique(apps, name)
        return exact_app(app, policy_by_id.get(app.get("id"), []) if app else [],
                         name, address, ids, policy_name)

    result = {
        "vm_credentials": "EXACT_VM_ONLY" if check(
            cfg["vm_access_application_name"], vmhost, [vmid],
            cfg["vm_access_policy_name"]) else "DRIFT",
        "windows_credentials": "EXACT_WINDOWS_ONLY" if check(
            cfg["windows_access_application_name"], winhost, [winid],
            cfg["windows_access_policy_name"]) else "DRIFT",
        "mutations": 0,
    }
    # Deterministic identity derives from the ONE typed Git VM Worker name.
    name = cfg["vm_worker_name"] + "-host-access"
    matches = [a for a in apps if isinstance(a, dict) and a.get("name") == name]
    if not matches:
        result["host_route"] = "NOT_PROVISIONED_LEGACY_VM_PRESERVED"
    elif len(matches) != 1:
        result["host_route"] = "DUPLICATE_APP_BLOCKED"
    else:
        result["host_route"] = ("EXACT_BOTH_TOKENS_PATH_ONLY" if check(
            name, vmhost + "/v1/host", [vmid, winid],
            cfg["vm_worker_name"] + "-host-service-auth") else "DRIFT_BLOCKED")
    # Never treat provider metadata as a signer proof or signed native receipt.
    result["signer_proof"] = "NOT_IN_THIS_READ_ONLY_PROVIDER_PROBE"
    return result


def main():
    cfg = exact_production(Path("infra/production/production.textproto").read_text())
    token = os.environ.get("CLOUDFLARE_CONTROL_TOKEN", "")
    if not token:
        raise ValueError("CONTROL_TOKEN_UNAVAILABLE")

    def get(path):
        req = Request(f"{ROOT}/{cfg['active_account_id']}/{path}",
                      headers={"Authorization": "Bearer " + token,
                               "User-Agent": "sing-box-host-access-boundary-readonly",
                               "Accept": "application/json"})
        with urlopen(req, timeout=15) as response:
            if response.status != 200:
                raise ValueError("PROVIDER_RESPONSE_INVALID")
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("PROVIDER_RESULT_OVERSIZE")
        data = json.loads(raw)
        if data.get("success") is not True or not isinstance(data.get("result"), list):
            raise ValueError("PROVIDER_RESULT_UNPROVEN")
        if len(data["result"]) >= 50:
            raise ValueError("PROVIDER_PAGINATION_UNPROVEN")
        return data["result"]

    tokens = get("access/service_tokens?per_page=50")
    apps = get("access/apps?per_page=50")
    names = {cfg["vm_access_application_name"],
             cfg["windows_access_application_name"],
             cfg["vm_worker_name"] + "-host-access"}
    policies = {app.get("id"): get("access/apps/" + app["id"] + "/policies")
                for app in apps if isinstance(app, dict)
                and app.get("name") in names and isinstance(app.get("id"), str)
                and re.fullmatch(r"[0-9a-fA-F-]{1,64}", app["id"])}
    out = evaluate(cfg, tokens, apps, policies)
    out["schema"] = "sing-box.host-access-boundary/v1"
    print(json.dumps(out, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except HTTPError as error:
        print(json.dumps({"schema": "sing-box.host-access-boundary/v1",
                          "host_route": "CLOUDFLARE_HTTP_" + str(error.code)
                          if error.code in (401, 403, 404, 429, 503)
                          else "CLOUDFLARE_HTTP_UNPROVEN", "mutations": 0}))
    except (URLError, ValueError, KeyError, OSError, json.JSONDecodeError):
        print(json.dumps({"schema": "sing-box.host-access-boundary/v1",
                          "host_route": "PROVIDER_READ_UNPROVEN", "mutations": 0}))
