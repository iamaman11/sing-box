#!/usr/bin/env bash
set -Eeuo pipefail

: "${VULTR_API_KEY:?VULTR_API_KEY is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"

API_BASE="https://api.vultr.com"
REGION="waw"
PLAN="vc2-1c-1gb"
OS_ID=2625
LABEL="singbox-uncertain-${GITHUB_RUN_ID}"
RUN_TAG="uncertain-run-${GITHUB_RUN_ID}"
FW_DESC="${LABEL}-fw"

tmp="$(mktemp -d)"
response="${tmp}/response.json"
body="${tmp}/body.json"
instance_id=""
firewall_id=""
cleanup_started=0
HTTP_CODE=""
HTTP_RC=""

log() { printf '%s\n' "$*"; }

api_request() {
  local method="$1"
  local path="$2"
  local body_file="${3:-}"
  local -a args=(
    --silent --show-error
    --connect-timeout 10 --max-time 30
    --retry 0
    --output "$response"
    --write-out '%{http_code}'
    --request "$method"
    --header "Authorization: Bearer ${VULTR_API_KEY}"
    --header "Accept: application/json"
  )
  if [[ -n "$body_file" ]]; then
    args+=(--header "Content-Type: application/json" --data-binary "@$body_file")
  fi
  : > "$response"
  set +e
  HTTP_CODE="$(curl "${args[@]}" "${API_BASE}${path}")"
  HTTP_RC=$?
  set -e
}

expect_http() {
  local expected="$1"
  local context="$2"
  if [[ "$HTTP_RC" -ne 0 || "$HTTP_CODE" != "$expected" ]]; then
    log "${context}=FAIL transport_rc=${HTTP_RC} status=${HTTP_CODE}"
    return 1
  fi
}

discover_exact_ids() {
  api_request GET "/v2/instances?label=${LABEL}&per_page=500"
  [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]] || return 1
  jq -r --arg label "$LABEL" --arg tag "$RUN_TAG" '
    .instances[]
    | select(.label == $label)
    | select(((.tags // []) | index($tag)) != null)
    | .id
  ' "$response" | sort -u
}

exact_count() {
  local -a ids
  mapfile -t ids < <(discover_exact_ids)
  printf '%s\n' "${#ids[@]}"
}

wait_exact_count() {
  local expected="$1"
  local attempts="$2"
  for _ in $(seq 1 "$attempts"); do
    local count
    count="$(exact_count)"
    if [[ "$count" == "$expected" ]]; then
      return 0
    fi
    if [[ "$count" -gt 1 ]]; then
      log "rediscovery=AMBIGUOUS count=$count"
      return 2
    fi
    sleep 2
  done
  return 1
}

raw_https_send_and_drop() {
  local method="$1"
  local path="$2"
  local body_file="${3:-}"
  python3 - "$method" "$path" "$body_file" <<'PY'
import http.client, os, sys, time
method, path, body_path = sys.argv[1:4]
body = b""
if body_path:
    with open(body_path, "rb") as f:
        body = f.read()
headers = {
    "Authorization": "Bearer " + os.environ["VULTR_API_KEY"],
    "Accept": "application/json",
    "Connection": "close",
}
if body:
    headers["Content-Type"] = "application/json"
    headers["Content-Length"] = str(len(body))

conn = http.client.HTTPSConnection("api.vultr.com", timeout=15)
conn.connect()
conn.putrequest(method, path, skip_accept_encoding=True)
for key, value in headers.items():
    conn.putheader(key, value)
conn.endheaders()
if body:
    conn.send(body)

# Fault injection: the full mutation request has been written to the TLS
# connection, but the client never calls getresponse(). We intentionally lose
# all HTTP status/body information and must recover through observation.
time.sleep(0.20)
conn.close()
PY
}

raw_https_send_partial_and_drop() {
  local path="$1"
  local body_file="$2"
  python3 - "$path" "$body_file" <<'PY'
import os, socket, ssl, sys, time
path, body_path = sys.argv[1:3]
with open(body_path, "rb") as f:
    body = f.read()

host = "api.vultr.com"
ctx = ssl.create_default_context()
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)

headers = (
    f"POST {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    f"Authorization: Bearer {os.environ['VULTR_API_KEY']}\r\n"
    f"Accept: application/json\r\n"
    f"Content-Type: application/json\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"Connection: close\r\n\r\n"
).encode()

ssock.sendall(headers)
# Declared Content-Length is intentionally not fulfilled.
ssock.sendall(body[:max(1, len(body)//3)])
time.sleep(0.05)
ssock.close()
PY
}

wait_absent_id() {
  local id="$1"
  # Real-provider research showed that deletion visibility can lag well beyond
  # the happy-path case. Bound the observation window at ~6 minutes without
  # replaying DELETE.
  for _ in $(seq 1 180); do
    api_request GET "/v2/instances/$id"
    if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "404" ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

cleanup() {
  if [[ "$cleanup_started" -eq 1 ]]; then return; fi
  cleanup_started=1
  set +e
  log "cleanup=begin"

  mapfile -t ids < <(discover_exact_ids 2>/dev/null | sort -u)
  if [[ -n "$instance_id" ]] && ! printf '%s\n' "${ids[@]:-}" | grep -Fxq "$instance_id"; then
    ids+=("$instance_id")
  fi
  for id in "${ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    api_request DELETE "/v2/instances/$id"
    log "cleanup_instance id=$id status=$HTTP_CODE rc=$HTTP_RC"
    wait_absent_id "$id" || true
  done

  if [[ -n "$firewall_id" ]]; then
    for _ in $(seq 1 30); do
      api_request GET "/v2/firewalls/$firewall_id"
      if [[ "$HTTP_CODE" == "404" ]]; then
        break
      fi
      if [[ "$HTTP_CODE" == "200" ]] && [[ "$(jq -r '.firewall_group.instance_count // 0' "$response" 2>/dev/null)" == "0" ]]; then
        api_request DELETE "/v2/firewalls/$firewall_id"
        log "cleanup_firewall id=$firewall_id status=$HTTP_CODE rc=$HTTP_RC"
        break
      fi
      sleep 2
    done
  fi

  rm -rf "$tmp"
  log "cleanup=end"
}
trap cleanup EXIT

log "uncertain_research_run_id=${GITHUB_RUN_ID}"

count="$(exact_count)"
if [[ "$count" != "0" ]]; then
  log "precondition_exact_absence=FAIL count=$count"
  exit 1
fi
log "precondition_exact_absence=PASS"

# One closed firewall. This experiment needs no guest/SSH access.
jq -n --arg description "$FW_DESC" '{description:$description}' > "$body"
api_request POST "/v2/firewalls" "$body"
expect_http 201 "firewall_create" || exit 1
firewall_id="$(jq -r '.firewall_group.id // empty' "$response")"
[[ -n "$firewall_id" ]] || exit 1
log "firewall_create=PASS id=$firewall_id"

jq -n \
  --arg region "$REGION" \
  --arg plan "$PLAN" \
  --arg label "$LABEL" \
  --arg hostname "$LABEL" \
  --arg fw "$firewall_id" \
  --arg tag "$RUN_TAG" \
  --argjson os_id "$OS_ID" \
  '{
    region:$region,
    plan:$plan,
    os_id:$os_id,
    label:$label,
    hostname:$hostname,
    firewall_group_id:$fw,
    tags:["managed-by-sing-box","research-uncertain",$tag],
    activation_email:false,
    enable_ipv6:false,
    backups:"disabled"
  }' > "$body"

# Case A: transport drops before the declared request body is fully delivered.
raw_https_send_partial_and_drop "/v2/instances" "$body"
sleep 3
count="$(exact_count)"
if [[ "$count" != "0" ]]; then
  log "create_not_accepted_response_loss=FAIL count=$count"
  exit 1
fi
log "create_not_accepted_response_loss=PASS rediscovered=0"

# Case B: full create request is sent, but the client intentionally never reads
# any response. No blind replay is allowed.
raw_https_send_and_drop POST "/v2/instances" "$body"
if ! wait_exact_count 1 60; then
  rc=$?
  log "create_accepted_response_loss=FAIL rc=$rc"
  exit 1
fi
mapfile -t ids < <(discover_exact_ids)
if [[ "${#ids[@]}" -ne 1 ]]; then
  log "create_accepted_response_loss=FAIL exact_count=${#ids[@]}"
  exit 1
fi
instance_id="${ids[0]}"
log "create_accepted_response_loss=PASS rediscovered=1 id=$instance_id"

ready=0
for _ in $(seq 1 90); do
  api_request GET "/v2/instances/$instance_id"
  if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]; then
    status="$(jq -r '.instance.status // empty' "$response")"
    power="$(jq -r '.instance.power_status // empty' "$response")"
    if [[ "$status" == "active" && "$power" == "running" ]]; then
      ready=1
      break
    fi
  fi
  sleep 2
done
[[ "$ready" == "1" ]] || { log "provider_ready=FAIL"; exit 1; }
log "provider_ready=PASS"

# Case C: full DELETE is sent, response is intentionally never read. Recovery
# is based only on observation of the exact UUID.
raw_https_send_and_drop DELETE "/v2/instances/$instance_id"
if ! wait_absent_id "$instance_id"; then
  log "delete_accepted_response_loss=FAIL"
  exit 1
fi
log "delete_accepted_response_loss=PASS exact_uuid_absent=true"
instance_id=""

for _ in $(seq 1 30); do
  api_request GET "/v2/firewalls/$firewall_id"
  expect_http 200 "firewall_observe" || exit 1
  if [[ "$(jq -r '.firewall_group.instance_count // 0' "$response")" == "0" ]]; then
    break
  fi
  sleep 2
done

api_request DELETE "/v2/firewalls/$firewall_id"
expect_http 204 "firewall_delete" || exit 1
firewall_id=""
log "firewall_delete=PASS"

count="$(exact_count)"
[[ "$count" == "0" ]] || { log "final_exact_absence=FAIL count=$count"; exit 1; }
log "final_exact_absence=PASS"
log "uncertain_mutation_research=PASS"
