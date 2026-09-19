#!/usr/bin/env bash
set -Eeuo pipefail

: "\${VULTR_API_KEY:?VULTR_API_KEY is required}"
: "\${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"

API_BASE="https://api.vultr.com"
REGION="waw"
PLAN="vc2-1c-1gb"
OS_ID=2625
LABEL="singbox-ambiguous-\${GITHUB_RUN_ID}"
RUN_TAG="ambiguous-run-\${GITHUB_RUN_ID}"
FW_DESC="\${LABEL}-fw"

tmp="$(mktemp -d)"
response="\${tmp}/response.json"
body="\${tmp}/body.json"
firewall_id=""
declare -a created_ids=()
cleanup_started=0
HTTP_CODE=""
HTTP_RC=""

log() { printf '%s\n' "$*"; }

api_request() {
  local method="$1" path="$2" body_file="\${3:-}"
  local -a args=(
    --silent --show-error
    --connect-timeout 10 --max-time 30
    --retry 0
    --output "$response"
    --write-out '%{http_code}'
    --request "$method"
    --header "Authorization: Bearer \${VULTR_API_KEY}"
    --header "Accept: application/json"
  )
  if [[ -n "$body_file" ]]; then
    args+=(--header "Content-Type: application/json" --data-binary "@\${body_file}")
  fi
  : > "$response"
  set +e
  HTTP_CODE="$(curl "\${args[@]}" "\${API_BASE}\${path}")"
  HTTP_RC=$?
  set -e
}

discover_ids() {
  api_request GET "/v2/instances?label=\${LABEL}&per_page=500"
  [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]] || return 1
  jq -r --arg label "$LABEL" --arg tag "$RUN_TAG" '
    .instances[]
    | select(.label == $label)
    | select(((.tags // []) | index($tag)) != null)
    | .id
  ' "$response" | sort -u
}

wait_absent() {
  local id="$1"
  for _ in $(seq 1 60); do
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

  mapfile -t discovered < <(discover_ids 2>/dev/null | sort -u)
  ids=("\${created_ids[@]:-}" "\${discovered[@]:-}")
  mapfile -t ids < <(printf '%s\n' "\${ids[@]}" | sed '/^$/d' | sort -u)

  for id in "\${ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    api_request DELETE "/v2/instances/$id"
    log "cleanup.instance id=$id status=$HTTP_CODE rc=$HTTP_RC"
  done
  for id in "\${ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    wait_absent "$id" || log "cleanup.instance_absence_unconfirmed id=$id"
  done

  if [[ -n "$firewall_id" ]]; then
    for _ in $(seq 1 30); do
      api_request GET "/v2/firewalls/$firewall_id"
      if [[ "$HTTP_CODE" == "404" ]]; then break; fi
      if [[ "$HTTP_CODE" == "200" ]] && [[ "$(jq -r '.firewall_group.instance_count // 0' "$response" 2>/dev/null)" == "0" ]]; then
        api_request DELETE "/v2/firewalls/$firewall_id"
        log "cleanup.firewall status=$HTTP_CODE rc=$HTTP_RC"
        break
      fi
      sleep 2
    done
  fi

  rm -rf "$tmp"
  log "cleanup=end"
}
trap cleanup EXIT

log "ambiguity_research_run_id=\${GITHUB_RUN_ID}"

mapfile -t before < <(discover_ids)
[[ "\${#before[@]}" -eq 0 ]]
log "precondition_exact_absence=PASS"

jq -n --arg description "$FW_DESC" '{description:$description}' > "$body"
api_request POST /v2/firewalls "$body"
[[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "201" ]]
firewall_id="$(jq -r '.firewall_group.id // empty' "$response")"
[[ -n "$firewall_id" ]]
log "firewall_create=PASS"

jq -n \
  --arg region "$REGION" --arg plan "$PLAN" --arg label "$LABEL" \
  --arg fw "$firewall_id" --arg tag "$RUN_TAG" --argjson os "$OS_ID" \
  '{region:$region,plan:$plan,os_id:$os,label:$label,hostname:$label,
    firewall_group_id:$fw,activation_email:false,enable_ipv6:false,backups:"disabled",
    tags:["managed-by-sing-box","research-disposable","ambiguity-probe",$tag]}' > "$body"

for n in 1 2; do
  api_request POST /v2/instances "$body"
  if [[ "$HTTP_RC" -ne 0 || "$HTTP_CODE" != "202" ]]; then
    log "instance_create_\${n}=FAIL status=$HTTP_CODE rc=$HTTP_RC"
    exit 1
  fi
  id="$(jq -r '.instance.id // empty' "$response")"
  [[ -n "$id" ]]
  created_ids+=("$id")
  log "instance_create_\${n}=PASS id=$id"
done

for _ in $(seq 1 60); do
  mapfile -t exact < <(discover_ids)
  if [[ "\${#exact[@]}" -eq 2 ]]; then
    break
  fi
  if [[ "\${#exact[@]}" -gt 2 ]]; then
    log "exact_discovery_unexpected_count=\${#exact[@]}"
    exit 1
  fi
  sleep 2
done

mapfile -t exact < <(discover_ids)
if [[ "\${#exact[@]}" -ne 2 ]]; then
  log "ambiguous_identity_detection=FAIL count=\${#exact[@]}"
  exit 1
fi
log "ambiguous_identity_detection=PASS count=2"

selected_id=""
if [[ "\${#exact[@]}" -eq 1 ]]; then
  selected_id="\${exact[0]}"
fi
if [[ -n "$selected_id" ]]; then
  log "ambiguous_fail_closed=FAIL selected=$selected_id"
  exit 1
fi
log "ambiguous_fail_closed=PASS action=STOP"

for id in "\${exact[@]}"; do
  api_request DELETE "/v2/instances/$id"
  [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "204" ]]
done

for id in "\${exact[@]}"; do
  wait_absent "$id"
done
created_ids=()
log "ambiguous_instances_cleanup=PASS"

for _ in $(seq 1 30); do
  api_request GET "/v2/firewalls/$firewall_id"
  [[ "$HTTP_RC" -eq 0 ]]
  if [[ "$HTTP_CODE" == "200" ]] && [[ "$(jq -r '.firewall_group.instance_count // 0' "$response")" == "0" ]]; then
    break
  fi
  sleep 2
done

api_request DELETE "/v2/firewalls/$firewall_id"
[[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "204" ]]
firewall_id=""
log "firewall_delete=PASS"

mapfile -t final < <(discover_ids)
[[ "\${#final[@]}" -eq 0 ]]
log "final_exact_absence=PASS"
log "ambiguity_research=PASS"
