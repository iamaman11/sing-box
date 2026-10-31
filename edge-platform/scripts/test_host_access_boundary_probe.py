#!/usr/bin/env python3
"""No network: verify exact VM/Windows separation and optional Host Access."""
from host_access_boundary_probe import evaluate

cfg = dict(active_account_id="a", windows_worker_name="windows",
           vm_worker_name="vm", workers_dev_subdomain="subdomain",
           windows_access_application_name="windows-app",
           vm_access_application_name="vm-app",
           windows_access_policy_name="windows-policy",
           vm_access_policy_name="vm-policy",
           windows_host_service_token_name="windows-token",
           vm_host_service_token_name="vm-token")
tokens = [dict(name="vm-token", id="vm-id", enabled=True),
          dict(name="windows-token", id="win-id", enabled=True)]
def app(name, uri):
    return dict(id=name, name=name, type="self_hosted",
                service_auth_401_redirect=True,
                destinations=[dict(type="public", uri=uri)])
def policy(name, ids):
    return dict(name=name, decision="non_identity", require=[], exclude=[],
                include=[dict(service_token=dict(token_id=i)) for i in ids])
vmhost="vm.subdomain.workers.dev"
winhost="windows.subdomain.workers.dev"
base_apps=[app("vm-app", vmhost),app("windows-app",winhost)]
base_policies={"vm-app":[policy("vm-policy",["vm-id"])],
               "windows-app":[policy("windows-policy",["win-id"])]}
before=evaluate(cfg,tokens,base_apps,base_policies)
assert before["host_route"]=="NOT_PROVISIONED_LEGACY_VM_PRESERVED", before
assert before["vm_credentials"]=="EXACT_VM_ONLY", before
assert before["windows_credentials"]=="EXACT_WINDOWS_ONLY", before
host=app("vm-host-access",vmhost+"/v1/host")
host["id"]="host-app-id"
host_policies={**base_policies,"host-app-id":[policy("vm-host-service-auth",["vm-id","win-id"])]}
ready=evaluate(cfg,tokens,base_apps+[host],host_policies)
assert ready["host_route"]=="EXACT_BOTH_TOKENS_PATH_ONLY",ready
# Broader VM credential access is a BLOCK even if Host Access is exact.
overbroad={**base_policies,"vm-app":[policy("vm-policy",["vm-id","win-id"])]}
assert evaluate(cfg,tokens,base_apps+[host],{**host_policies,**overbroad})["vm_credentials"]=="DRIFT"
# Misrouted Host app, missing Windows token or unexpected extra token fail.
foreign=host.copy()
foreign["destinations"]=[dict(type="public",uri=vmhost)]
assert evaluate(cfg,tokens,base_apps+[foreign],host_policies)["host_route"]=="DRIFT_BLOCKED"
bad={**host_policies,"host-app-id":[policy("vm-host-service-auth",["vm-id"])]}
assert evaluate(cfg,tokens,base_apps+[host],bad)["host_route"]=="DRIFT_BLOCKED"
bad={**host_policies,"host-app-id":[policy("vm-host-service-auth",["vm-id","win-id","foreign"])]}
assert evaluate(cfg,tokens,base_apps+[host],bad)["host_route"]=="DRIFT_BLOCKED"
dup=base_apps+[host,dict(host)]
assert evaluate(cfg,tokens,dup,host_policies)["host_route"]=="DUPLICATE_APP_BLOCKED"
assert evaluate(cfg,tokens,base_apps,base_policies)["mutations"]==0
print("Host Access isolation read-only contract PASS")
