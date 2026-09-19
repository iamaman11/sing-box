#!/usr/bin/env bash
set -Eeuo pipefail

: "${VULTR_API_KEY:?VULTR_API_KEY is required}"
: "${VULTR_SSH_PRIVATE_KEY:?VULTR_SSH_PRIVATE_KEY is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

API_BASE="https://api.vultr.com"
REGION="waw"
PLAN="vc2-1c-1gb"
OS_ID="2625"
OPS_USER="singbox-ops"
RUN_TAG="research-run-${GITHUB_RUN_ID}"
LABEL="singbox-research-${GITHUB_RUN_ID}"
HOSTNAME="${LABEL}"
SSH_NAME="${LABEL}-ops"
FW_DESC="${LABEL}-fw"

tmp="$(mktemp -d)"
operator_key="${tmp}/operator-ed25519"
known_hosts="${tmp}/known_hosts"
instance_id=""
ssh_key_id=""
firewall_id=""
firewall_rule_id=""
main_ip=""
cleanup_started=0

log() {
  printf '%s\n' "$*"
}

api_request() {
  local method="$1"
  local path="$2"
  local body_file="${3:-}"
  local out
  out="$(mktemp "${tmp}/response.XXXXXX")"
  local -a args=(
    --silent
    --show-error
    --connect-timeout 10
    --max-time 30
    --output "$out"
    --write-out '%{http_code}'
    --request "$method"
    --header "Authorization: Bearer ${VULTR_API_KEY}"
    --header "Accept: application/json"
  )
  if [[ -n "$body_file" ]]; then
    args+=(--header "Content-Type: application/json" --data-binary "@${body_file}")
  fi

  set +e
  HTTP_CODE="$(curl "${args[@]}" "${API_BASE}${path}")"
  HTTP_RC=$?
  set -e
  HTTP_BODY="$out"
}

expect_http() {
  local expected="$1"
  local context="$2"
  if [[ "$HTTP_RC" -ne 0 ]]; then
    log "${context}=TRANSPORT_ERROR rc=${HTTP_RC}"
    return 1
  fi
  if [[ "$HTTP_CODE" != "$expected" ]]; then
    log "${context}=HTTP_${HTTP_CODE}"
    if [[ -s "$HTTP_BODY" ]]; then
      jq -c '{error:(.error // .message // "provider_error")}' "$HTTP_BODY" 2>/dev/null || true
    fi
    return 1
  fi
}

safe_delete() {
  local path="$1"
  local context="$2"
  api_request DELETE "$path"
  case "$HTTP_CODE" in
    204|404) log "${context}=cleanup_ok status=${HTTP_CODE}" ;;
    *) log "${context}=cleanup_status_${HTTP_CODE}" ;;
  esac
}

discover_owned_instances() {
  api_request GET "/v2/instances?label=${LABEL}&per_page=500"
  [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]] || return 0
  jq -r --arg label "$LABEL" --arg tag "$RUN_TAG" '
    .instances[]
    | select(.label == $label)
    | select((.tags // []) | index($tag))
    | .id
  ' "$HTTP_BODY"
}

discover_owned_firewalls() {
  api_request GET "/v2/firewalls?per_page=500"
  [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]] || return 0
  jq -r --arg description "$FW_DESC" '
    .firewall_groups[]
    | select(.description == $description)
    | .id
  ' "$HTTP_BODY"
}

discover_owned_ssh_keys() {
  api_request GET "/v2/ssh-keys?per_page=500"
  [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]] || return 0
  jq -r --arg name "$SSH_NAME" '
    .ssh_keys[]
    | select(.name == $name)
    | .id
  ' "$HTTP_BODY"
}

wait_instance_absent() {
  local id="$1"
  for _ in $(seq 1 60); do
    api_request GET "/v2/instances/${id}"
    if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "404" ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

cleanup() {
  if [[ "$cleanup_started" -eq 1 ]]; then
    return
  fi
  cleanup_started=1
  set +e
  log "cleanup=begin"

  mapfile -t instance_ids < <(discover_owned_instances | sort -u)
  if [[ -n "$instance_id" ]] && ! printf '%s\n' "${instance_ids[@]:-}" | grep -Fxq "$instance_id"; then
    instance_ids+=("$instance_id")
  fi

  for id in "${instance_ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    safe_delete "/v2/instances/${id}" "instance:${id}"
  done

  for id in "${instance_ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    wait_instance_absent "$id" || log "instance:${id}=cleanup_absence_unconfirmed"
  done

  mapfile -t firewall_ids < <(discover_owned_firewalls | sort -u)
  if [[ -n "$firewall_id" ]] && ! printf '%s\n' "${firewall_ids[@]:-}" | grep -Fxq "$firewall_id"; then
    firewall_ids+=("$firewall_id")
  fi
  for id in "${firewall_ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    safe_delete "/v2/firewalls/${id}" "firewall:${id}"
  done

  mapfile -t ssh_ids < <(discover_owned_ssh_keys | sort -u)
  if [[ -n "$ssh_key_id" ]] && ! printf '%s\n' "${ssh_ids[@]:-}" | grep -Fxq "$ssh_key_id"; then
    ssh_ids+=("$ssh_key_id")
  fi
  for id in "${ssh_ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    safe_delete "/v2/ssh-keys/${id}" "ssh_key:${id}"
  done

  rm -rf "$tmp"
  log "cleanup=end"
}

trap cleanup EXIT

log "research_run_id=${GITHUB_RUN_ID}"
log "candidate region=${REGION} plan=${PLAN} os_id=${OS_ID}"

# Exact canonical operator identity.
canonical_pub="$(curl --fail --silent --show-error --max-time 20   "https://raw.githubusercontent.com/iamaman11/sing-box/${GITHUB_SHA}/infra/vultr/singbox-ops.pub")"
printf '%s\n' "$VULTR_SSH_PRIVATE_KEY" > "$operator_key"
chmod 600 "$operator_key"
derived_pub="$(ssh-keygen -y -f "$operator_key")"

canonical_material="$(awk '{print $1" "$2}' <<<"$canonical_pub")"
derived_material="$(awk '{print $1" "$2}' <<<"$derived_pub")"
if [[ "$canonical_material" != "$derived_material" ]]; then
  log "operator_key_identity=FAIL"
  exit 1
fi
operator_fingerprint="$(ssh-keygen -lf <(printf '%s\n' "$canonical_pub") -E sha256 | awk '{print $2}')"
log "operator_key_identity=PASS fingerprint=${operator_fingerprint}"

# Live catalog guards.
api_request GET "/v2/regions/${REGION}/availability?type=vc2"
expect_http 200 "region_availability" || exit 1
if ! jq -e --arg plan "$PLAN" '.available_plans | index($plan) != null' "$HTTP_BODY" >/dev/null; then
  log "plan_availability=FAIL"
  exit 1
fi
log "plan_availability=PASS"

api_request GET "/v2/os?per_page=500"
expect_http 200 "os_catalog" || exit 1
os_name="$(jq -r --argjson id "$OS_ID" '.os[] | select(.id == $id) | .name' "$HTTP_BODY")"
if [[ -z "$os_name" || "$os_name" == "null" ]]; then
  log "os_catalog_guard=FAIL"
  exit 1
fi
log "os_catalog_guard=PASS name=${os_name}"

# GitHub-hosted runner exact IPv4 for temporary SSH admission.
runner_ip="$(curl -4 --fail --silent --show-error --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
python3 - "$runner_ip" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
if ip.version != 4 or not ip.is_global:
    raise SystemExit("runner IPv4 is not a global address")
PY
log "runner_ipv4_detected=PASS"

# Prepare strict SSH host certificate. For the research trust domain the
# existing operator key acts as the CA; the per-instance host private key is
# ephemeral and exists only in this disposable VM's user-data.
ssh-keygen -q -t ed25519 -N "" -f "${tmp}/host-ed25519"
ssh-keygen -q -s "$operator_key" -I "$LABEL" -h -n "$HOSTNAME" -V "-5m:+2h" "${tmp}/host-ed25519.pub"
host_key_b64="$(base64 -w0 < "${tmp}/host-ed25519")"
host_pub_b64="$(base64 -w0 < "${tmp}/host-ed25519.pub")"
host_cert_b64="$(base64 -w0 < "${tmp}/host-ed25519-cert.pub")"

cat > "${tmp}/cloud-init.yaml" <<EOF
#cloud-config
users:
  - name: ${OPS_USER}
    groups: [sudo]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${canonical_pub}
ssh_pwauth: false
disable_root: true
ssh_deletekeys: false
ssh_genkeytypes: []
write_files:
  - path: /etc/ssh/ssh_host_ed25519_key
    owner: root:root
    permissions: '0600'
    encoding: b64
    content: ${host_key_b64}
  - path: /etc/ssh/ssh_host_ed25519_key.pub
    owner: root:root
    permissions: '0644'
    encoding: b64
    content: ${host_pub_b64}
  - path: /etc/ssh/ssh_host_ed25519_key-cert.pub
    owner: root:root
    permissions: '0644'
    encoding: b64
    content: ${host_cert_b64}
  - path: /etc/ssh/sshd_config.d/99-singbox-research.conf
    owner: root:root
    permissions: '0644'
    content: |
      HostKey /etc/ssh/ssh_host_ed25519_key
      HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
      PasswordAuthentication no
      PermitRootLogin no
runcmd:
  - [mkdir, -p, /var/lib/singbox-lifecycle]
  - [sh, -c, "printf '%s\\n' research-ready > /var/lib/singbox-lifecycle/research-ready"]
  - [systemctl, restart, ssh]
final_message: "singbox research bootstrap complete"
EOF

user_data_b64="$(base64 -w0 < "${tmp}/cloud-init.yaml")"
printf '@cert-authority %s %s\n' "$HOSTNAME" "$canonical_material" > "$known_hosts"

# Create a run-scoped Vultr SSH key object.
jq -n --arg name "$SSH_NAME" --arg key "$canonical_pub"   '{name:$name, ssh_key:$key}' > "${tmp}/ssh-key.json"
api_request POST "/v2/ssh-keys" "${tmp}/ssh-key.json"
expect_http 201 "ssh_key_create" || exit 1
ssh_key_id="$(jq -r '.ssh_key.id' "$HTTP_BODY")"
[[ -n "$ssh_key_id" && "$ssh_key_id" != "null" ]] || exit 1
log "ssh_key_create=PASS id=${ssh_key_id}"

# Create a closed firewall group and admit only the current runner /32 to SSH.
jq -n --arg description "$FW_DESC" '{description:$description}' > "${tmp}/firewall.json"
api_request POST "/v2/firewalls" "${tmp}/firewall.json"
expect_http 201 "firewall_create" || exit 1
firewall_id="$(jq -r '.firewall_group.id' "$HTTP_BODY")"
[[ -n "$firewall_id" && "$firewall_id" != "null" ]] || exit 1
log "firewall_create=PASS id=${firewall_id}"

jq -n --arg subnet "$runner_ip" --arg notes "$LABEL ssh"   '{ip_type:"v4", protocol:"tcp", subnet:$subnet, subnet_size:32, port:"22", notes:$notes}'   > "${tmp}/firewall-rule.json"
api_request POST "/v2/firewalls/${firewall_id}/rules" "${tmp}/firewall-rule.json"
expect_http 201 "firewall_rule_create" || exit 1
firewall_rule_id="$(jq -r '.firewall_rule.id' "$HTTP_BODY")"
[[ -n "$firewall_rule_id" && "$firewall_rule_id" != "null" ]] || exit 1
log "firewall_rule_create=PASS id=${firewall_rule_id}"

# Create disposable instance. No backups, no activation mail, no IPv6.
jq -n   --arg region "$REGION"   --arg plan "$PLAN"   --arg label "$LABEL"   --arg hostname "$HOSTNAME"   --arg fw "$firewall_id"   --arg ssh "$ssh_key_id"   --arg run_tag "$RUN_TAG"   --arg user_data "$user_data_b64"   --argjson os_id "$OS_ID"   '{
    region:$region,
    plan:$plan,
    os_id:$os_id,
    label:$label,
    hostname:$hostname,
    firewall_group_id:$fw,
    sshkey_id:[$ssh],
    tags:["managed-by-sing-box","research-disposable",$run_tag],
    user_data:$user_data,
    enable_ipv6:false,
    activation_email:false,
    backups:"disabled"
  }' > "${tmp}/instance.json"

api_request POST "/v2/instances" "${tmp}/instance.json"
expect_http 202 "instance_create" || exit 1
instance_id="$(jq -r '.instance.id' "$HTTP_BODY")"
[[ -n "$instance_id" && "$instance_id" != "null" ]] || exit 1
log "instance_create=PASS id=${instance_id}"

# Provider readiness.
ready=0
for _ in $(seq 1 120); do
  api_request GET "/v2/instances/${instance_id}"
  if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]; then
    status="$(jq -r '.instance.status' "$HTTP_BODY")"
    power="$(jq -r '.instance.power_status' "$HTTP_BODY")"
    server="$(jq -r '.instance.server_status' "$HTTP_BODY")"
    ip="$(jq -r '.instance.main_ip' "$HTTP_BODY")"
    if [[ "$status" == "active" && "$power" == "running" && -n "$ip" && "$ip" != "0.0.0.0" ]]; then
      main_ip="$ip"
      ready=1
      log "provider_ready=PASS status=${status} power=${power} server=${server}"
      break
    fi
  fi
  sleep 5
done
if [[ "$ready" -ne 1 ]]; then
  log "provider_ready=FAIL"
  exit 1
fi

ssh_base=(
  ssh
  -i "$operator_key"
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$known_hosts"
  -o HostKeyAlias="$HOSTNAME"
  "${OPS_USER}@${main_ip}"
)

# Separate network reachability from SSH/authentication readiness.
tcp_ready=0
for _ in $(seq 1 30); do
  if timeout 3 bash -c "</dev/tcp/${main_ip}/22" 2>/dev/null; then
    tcp_ready=1
    break
  fi
  sleep 2
done
if [[ "$tcp_ready" -ne 1 ]]; then
  log "tcp_22_reachable=FAIL"
  for source in aws ipify; do
    case "$source" in
      aws) observed="$(curl -4 --fail --silent --show-error --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')" ;;
      ipify) observed="$(curl -4 --fail --silent --show-error --max-time 10 https://api.ipify.org | tr -d '[:space:]')" ;;
    esac
    if [[ "$observed" == "$runner_ip" ]]; then
      log "runner_ipv4_crosscheck_${source}=MATCH"
    else
      log "runner_ipv4_crosscheck_${source}=MISMATCH"
    fi
  done
  exit 1
fi
log "tcp_22_reachable=PASS"

# Strict SSH acceptance via host certificate.
ssh_ready=0
for _ in $(seq 1 5); do
  if "${ssh_base[@]}" 'test -f /var/lib/singbox-lifecycle/research-ready' >/dev/null 2>&1; then
    ssh_ready=1
    break
  fi
  sleep 4
done
if [[ "$ssh_ready" -ne 1 ]]; then
  log "strict_ssh_acceptance=FAIL"

  set +e
  "${ssh_base[@]}" 'true' >/dev/null 2>"${tmp}/strict-ssh.err"
  strict_diag_rc=$?
  set -e
  log "strict_ssh_diagnostic_rc=${strict_diag_rc}"
  grep -Ei 'host certificate|certificate|principal|cert-authority|known.host|host key|verification failed|no matching|permission denied|connection' "${tmp}/strict-ssh.err" | tail -n 40 || true

  # Research-only control: bypass host verification once to distinguish
  # host-certificate failure from guest-user/client-auth failure.
  diagnostic_ssh=(
    ssh
    -i "$operator_key"
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o ConnectionAttempts=1
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    "${OPS_USER}@${main_ip}"
  )

  set +e
  "${diagnostic_ssh[@]}" 'test -f /var/lib/singbox-lifecycle/research-ready' >/dev/null 2>"${tmp}/diagnostic-ssh.err"
  diagnostic_rc=$?
  set -e

  if [[ "$diagnostic_rc" -eq 0 ]]; then
    log "diagnostic_non_strict_ssh=PASS research_only=true"
    "${diagnostic_ssh[@]}" "sudo test -s /etc/ssh/ssh_host_ed25519_key-cert.pub && echo host_cert_file=present || echo host_cert_file=missing"
    "${diagnostic_ssh[@]}" "sudo awk 'NR==1 {print \"host_cert_algorithm=\" \$1}' /etc/ssh/ssh_host_ed25519_key-cert.pub 2>/dev/null || true"
    "${diagnostic_ssh[@]}" "sudo ssh-keygen -L -f /etc/ssh/ssh_host_ed25519_key-cert.pub 2>&1 | head -n 30 || true"
    "${diagnostic_ssh[@]}" "sudo sshd -T 2>/dev/null | grep -E '^(hostkey|hostcertificate|passwordauthentication|permitrootlogin) ' || true"
    "${diagnostic_ssh[@]}" "sudo journalctl -u ssh --no-pager -n 100 2>/dev/null | grep -Ei 'certificate|host key|error|fail' | tail -n 30 || true"
    "${diagnostic_ssh[@]}" "sudo cloud-init status --long 2>/dev/null | grep -E '^(status|extended_status|boot_status_code|detail):' || true"
  else
    log "diagnostic_non_strict_ssh=FAIL rc=${diagnostic_rc}"
    grep -Ei 'Permission denied|Connection refused|Connection timed out|No route to host|Connection closed|Host key verification failed|certificate|principal|REMOTE HOST IDENTIFICATION' "${tmp}/diagnostic-ssh.err" | tail -n 20 || true
  fi
  exit 1
fi
log "strict_ssh_acceptance=PASS host_ca=operator-ed25519"

remote_user="$("${ssh_base[@]}" 'id -un')"
ssh_service="$("${ssh_base[@]}" 'sudo systemctl is-active ssh')"
if [[ "$remote_user" != "$OPS_USER" || "$ssh_service" != "active" ]]; then
  log "host_bootstrap=FAIL"
  exit 1
fi
log "host_bootstrap=PASS user=${remote_user} ssh=${ssh_service}"

# Prove API user-data is retrievable without printing it.
api_request GET "/v2/instances/${instance_id}/user-data"
expect_http 200 "user_data_get" || exit 1
observed_user_data="$(jq -r '.user_data.data' "$HTTP_BODY")"
if [[ "$observed_user_data" != "$user_data_b64" ]]; then
  log "user_data_retrievable=FAIL"
  exit 1
fi
log "user_data_retrievable=PASS content_redacted=true"

# Immediately replace API-visible user-data after strict bootstrap. The current
# value contains the per-instance host private key needed only for first boot.
# This is defense-in-depth: it narrows the API-visible exposure window but does
# not claim that the provider has no internal historical copies.
scrub_plain='#cloud-config
# sing-box bootstrap material scrubbed after strict SSH acceptance
'
scrub_b64="$(printf '%s' "$scrub_plain" | base64 -w0)"
jq -n --arg user_data "$scrub_b64" '{user_data:$user_data}' > "$tmp/user-data-scrub.json"
api_request PATCH "/v2/instances/$instance_id" "$tmp/user-data-scrub.json"
case "$HTTP_CODE" in
  200|202)
    log "user_data_scrub_request=PASS status=$HTTP_CODE"
    ;;
  *)
    expect_http 200 "user_data_scrub_request" || exit 1
    ;;
esac

scrubbed=0
for _ in $(seq 1 30); do
  api_request GET "/v2/instances/$instance_id/user-data"
  if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]; then
    current_user_data="$(jq -r '.user_data.data // empty' "$HTTP_BODY")"
    if [[ "$current_user_data" == "$scrub_b64" ]]; then
      scrubbed=1
      break
    fi
  fi
  sleep 2
done
if [[ "$scrubbed" -ne 1 ]]; then
  log "user_data_scrub_visibility=FAIL"
  exit 1
fi
log "user_data_scrub_visibility=PASS"

# Firewall propagation experiment. A previous run showed that deleting the only
# allow rule did not close new TCP/22 connections within 40 seconds. Avoid an
# ambiguous empty-group state here: replace it with an explicit non-matching
# TCP/22 rule, confirm the provider rule-set, then observe propagation.
api_request DELETE "/v2/firewalls/$firewall_id/rules/$firewall_rule_id"
expect_http 204 "firewall_rule_delete" || exit 1
firewall_rule_id=""

jq -n --arg subnet "192.0.2.1" --arg notes "$LABEL nonmatching-probe" \
  '{ip_type:"v4", protocol:"tcp", subnet:$subnet, subnet_size:32, port:"22", notes:$notes}' \
  > "$tmp/firewall-rule-nonmatching.json"
api_request POST "/v2/firewalls/$firewall_id/rules" "$tmp/firewall-rule-nonmatching.json"
expect_http 201 "firewall_nonmatching_rule_create" || exit 1
firewall_rule_id="$(jq -r '.firewall_rule.id' "$HTTP_BODY")"
[[ -n "$firewall_rule_id" && "$firewall_rule_id" != "null" ]] || exit 1

rules_converged=0
for _ in $(seq 1 30); do
  api_request GET "/v2/firewalls/$firewall_id/rules?per_page=500"
  if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]; then
    runner_rules="$(jq --arg ip "$runner_ip" '[.firewall_rules[] | select(.protocol=="tcp" and .port=="22" and .subnet==$ip)] | length' "$HTTP_BODY")"
    probe_rules="$(jq '[.firewall_rules[] | select(.protocol=="tcp" and .port=="22" and .subnet=="192.0.2.1" and .subnet_size==32)] | length' "$HTTP_BODY")"
    if [[ "$runner_rules" == "0" && "$probe_rules" == "1" ]]; then
      rules_converged=1
      break
    fi
  fi
  sleep 2
done
if [[ "$rules_converged" -ne 1 ]]; then
  log "firewall_rule_api_convergence=FAIL"
  exit 1
fi
log "firewall_rule_api_convergence=PASS mode=nonmatching"

closed=0
started_at="$(date +%s)"
for _ in $(seq 1 60); do
  if ! timeout 2 bash -c "</dev/tcp/$main_ip/22" 2>/dev/null; then
    closed=1
    break
  fi
  sleep 1
done
elapsed="$(( $(date +%s) - started_at ))"
if [[ "$closed" -ne 1 ]]; then
  log "firewall_nonmatching_block=FAIL elapsed_s=$elapsed"
  api_request GET "/v2/instances/$instance_id"
  if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]; then
    attached="$(jq -r '.instance.firewall_group_id // ""' "$HTTP_BODY")"
    log "firewall_debug_attached_group=$attached expected=$firewall_id"
  fi
  api_request GET "/v2/firewalls/$firewall_id/rules?per_page=500"
  if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]; then
    jq -c '[.firewall_rules[] | {id,ip_type,protocol,port,subnet,subnet_size,source,notes}]' "$HTTP_BODY" || true
  fi
  exit 1
fi
log "firewall_nonmatching_block=PASS elapsed_s=$elapsed"

api_request DELETE "/v2/firewalls/$firewall_id/rules/$firewall_rule_id"
expect_http 204 "firewall_nonmatching_rule_delete" || exit 1
firewall_rule_id=""

api_request POST "/v2/firewalls/$firewall_id/rules" "$tmp/firewall-rule.json"
expect_http 201 "firewall_rule_recreate" || exit 1
firewall_rule_id="$(jq -r '.firewall_rule.id' "$HTTP_BODY")"
[[ -n "$firewall_rule_id" && "$firewall_rule_id" != "null" ]] || exit 1

ssh_reopened=0
for _ in $(seq 1 60); do
  if "${ssh_base[@]}" 'true' >/dev/null 2>&1; then
    ssh_reopened=1
    break
  fi
  sleep 2
done
if [[ "$ssh_reopened" -ne 1 ]]; then
  log "firewall_reopen_propagation=FAIL"
  exit 1
fi
log "firewall_reopen_propagation=PASS"
# Reboot must preserve strict host identity and change boot_id.
boot_before="$("${ssh_base[@]}" 'cat /proc/sys/kernel/random/boot_id')"
api_request POST "/v2/instances/${instance_id}/reboot"
expect_http 204 "instance_reboot" || exit 1
boot_after=""
for _ in $(seq 1 60); do
  set +e
  candidate="$("${ssh_base[@]}" 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 && -n "$candidate" && "$candidate" != "$boot_before" ]]; then
    boot_after="$candidate"
    break
  fi
  sleep 3
done
if [[ -z "$boot_after" ]]; then
  log "reboot_acceptance=FAIL"
  exit 1
fi
log "reboot_acceptance=PASS"

# Stop/start lifecycle.
api_request POST "/v2/instances/${instance_id}/halt"
expect_http 204 "instance_halt" || exit 1
stopped=0
for _ in $(seq 1 40); do
  api_request GET "/v2/instances/${instance_id}"
  if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]] && [[ "$(jq -r '.instance.power_status' "$HTTP_BODY")" == "stopped" ]]; then
    stopped=1
    break
  fi
  sleep 3
done
if [[ "$stopped" -ne 1 ]]; then
  log "halt_acceptance=FAIL"
  exit 1
fi
log "halt_acceptance=PASS"

api_request POST "/v2/instances/${instance_id}/start"
expect_http 204 "instance_start" || exit 1
started=0
for _ in $(seq 1 60); do
  if "${ssh_base[@]}" 'test -f /var/lib/singbox-lifecycle/research-ready' >/dev/null 2>&1; then
    started=1
    break
  fi
  sleep 3
done
if [[ "$started" -ne 1 ]]; then
  log "start_acceptance=FAIL"
  exit 1
fi
log "start_acceptance=PASS"

# Exact normal destroy; the trap still acts as a second cleanup line of defense.
api_request DELETE "/v2/instances/${instance_id}"
expect_http 204 "instance_delete" || exit 1
if ! wait_instance_absent "$instance_id"; then
  log "instance_delete_absence=FAIL"
  exit 1
fi
log "instance_delete_absence=PASS"
instance_id=""

api_request DELETE "/v2/firewalls/${firewall_id}"
expect_http 204 "firewall_delete" || exit 1
firewall_id=""
firewall_rule_id=""

api_request DELETE "/v2/ssh-keys/${ssh_key_id}"
expect_http 204 "ssh_key_delete" || exit 1
ssh_key_id=""

# Final leak check by exact run-owned identity.
instance_leaks="$(discover_owned_instances | wc -l | tr -d ' ')"
firewall_leaks="$(discover_owned_firewalls | wc -l | tr -d ' ')"
ssh_leaks="$(discover_owned_ssh_keys | wc -l | tr -d ' ')"
if [[ "$instance_leaks" != "0" || "$firewall_leaks" != "0" || "$ssh_leaks" != "0" ]]; then
  log "final_leak_check=FAIL instances=${instance_leaks} firewalls=${firewall_leaks} ssh_keys=${ssh_leaks}"
  exit 1
fi

log "final_leak_check=PASS"
log "disposable_lifecycle=PASS"
