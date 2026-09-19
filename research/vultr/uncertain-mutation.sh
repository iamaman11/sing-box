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
firewall_id=""
cleanup_started=0

log() { printf '%s\n' "$*"; }

api_request() {
  local method="$1"
  local path="$2"
  local body_file="${3:-}"
  local out
  out="$(mktemp "${tmp}/response.XXXXXX")"
  local -a args=(
    --silent --show-error --connect-timeout 10 --max-time 40
    --output "$out" --write-out '%{http_code}'
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

blind_mutation() {
  local method="$1"
  local path="$2"
  local body_file="${3:-}"
  local -a args=(
    --silent --show-error --connect-timeout 10 --max-time 40
    --output /dev/null
    --request "$method"
    --header "Authorization: Bearer ${VULTR_API_KEY}"
    --header "Accept: application/json"
  )
  if [[ -n "$body_file" ]]; then
    args+=(--header "Content-Type: application/json" --data-binary "@${body_file}")
  fi

  # Fault injection: send exactly one mutation request, then discard all HTTP
  # response metadata. The controller is not allowed to infer success from this.
  set +e
  curl "${args[@]}" "${API_BASE}${path}"
  BLIND_TRANSPORT_RC=$?
  set -e
  log "blind_mutation_sent method=${method} response_intentionally_discarded=true transport_rc=${BLIND_TRANSPORT_RC}"
}

discover_ids() {
  api_request GET "/v2/instances?label=${LABEL}&per_page=500"
  [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]] || return 1
  jq -r --arg label "$LABEL" --arg tag "$RUN_TAG" '
    .instances[]
    | select(.label == $label)
    | select((.tags // []) | index($tag))
    | .id
  ' "$HTTP_BODY" | sort -u
}

wait_count() {
  local expected="$1"
  for _ in $(seq 1 90); do
    mapfile -t ids < <(discover_ids)
    if [[ "${#ids[@]}" -eq "$expected" ]]; then
      printf '%s\n' "${ids[@]}"
      return 0
    fi
    sleep 2
  done
  return 1
}

wait_absent_id() {
  local id="$1"
  for _ in $(seq 1 90); do
    api_request GET "/v2/instances/${id}"
    if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "404" ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

safe_delete_id() {
  local id="$1"
  api_request DELETE "/v2/instances/${id}"
  case "$HTTP_CODE" in
    204|404) ;;
    *) return 1 ;;
  esac
  wait_absent_id "$id"
}

cleanup() {
  if [[ "$cleanup_started" -eq 1 ]]; then return; fi
  cleanup_started=1
  set +e
  log "cleanup=begin"

  mapfile -t ids < <(discover_ids)
  for id in "${ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    safe_delete_id "$id" || log "cleanup.instance_failed id=$id"
  done

  if [[ -n "$firewall_id" ]]; then
    api_request DELETE "/v2/firewalls/${firewall_id}"
    log "cleanup.firewall_status=${HTTP_CODE}"
  fi

  # Recover firewall if the local ID was lost.
  api_request GET "/v2/firewalls?per_page=500"
  if [[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]; then
    mapfile -t fws < <(jq -r --arg d "$FW_DESC" '.firewall_groups[] | select(.description==$d) | .id' "$HTTP_BODY")
    for id in "${fws[@]:-}"; do
      [[ -n "$id" ]] || continue
      api_request DELETE "/v2/firewalls/${id}"
    done
  fi
  rm -rf "$tmp"
  log "cleanup=end"
}
trap cleanup EXIT

log "uncertainty_research_run_id=${GITHUB_RUN_ID}"

# One run-scoped closed firewall; no guest access is needed for this test.
jq -n --arg d "$FW_DESC" '{description:$d}' > "$tmp/fw.json"
api_request POST /v2/firewalls "$tmp/fw.json"
[[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "201" ]]
firewall_id="$(jq -r '.firewall_group.id // empty' "$HTTP_BODY")"
[[ -n "$firewall_id" ]]
log "support_firewall_create=PASS"

jq -n \
  --arg region "$REGION" --arg plan "$PLAN" --arg label "$LABEL" \
  --arg fw "$firewall_id" --arg tag "$RUN_TAG" --argjson os "$OS_ID" \
  '{region:$region,plan:$plan,os_id:$os,label:$label,hostname:$label,
    firewall_group_id:$fw,backups:"disabled",activation_email:false,
    enable_ipv6:false,tags:["managed-by-sing-box","research-disposable","uncertain-mutation",$tag]}' \
  > "$tmp/instance.json"

# CREATE response-loss injection: one POST only; discard status/body.
blind_mutation POST /v2/instances "$tmp/instance.json"

mapfile -t first_ids < <(wait_count 1)
[[ "${#first_ids[@]}" -eq 1 ]]
first_id="${first_ids[0]}"
log "uncertain_create_rediscovery=PASS matches=1"

api_request GET "/v2/instances/${first_id}"
[[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]
jq -e --arg l "$LABEL" --arg t "$RUN_TAG" --arg f "$firewall_id" --arg r "$REGION" --arg p "$PLAN" --argjson o "$OS_ID" '
  .instance
  | .label==$l
  and .region==$r
  and .plan==$p
  and .os_id==$o
  and .firewall_group_id==$f
  and ((.tags // []) | index($t) != null)
' "$HTTP_BODY" >/dev/null
log "uncertain_create_identity=PASS"

# Intentionally create the exact duplicate identity. The resolver must refuse
# to pick either one.
blind_mutation POST /v2/instances "$tmp/instance.json"
mapfile -t duplicate_ids < <(wait_count 2)
[[ "${#duplicate_ids[@]}" -eq 2 ]]
log "ambiguous_identity_detection=PASS matches=2 action=STOP"

# Prove a unique resolver cannot return a target while two exact matches exist.
if [[ "${#duplicate_ids[@]}" -eq 1 ]]; then
  log "ambiguous_fail_closed=FAIL"
  exit 1
fi
log "ambiguous_fail_closed=PASS"

# DELETE response-loss injection on the first exact UUID.
blind_mutation DELETE "/v2/instances/${first_id}"
if ! wait_absent_id "$first_id"; then
  log "uncertain_delete_reobservation=FAIL"
  exit 1
fi
log "uncertain_delete_reobservation=PASS state=ABSENT"

# One duplicate remains; discovery is unique again and it is removed normally.
mapfile -t remaining < <(wait_count 1)
[[ "${#remaining[@]}" -eq 1 ]]
[[ "${remaining[0]}" != "$first_id" ]]
log "post_ambiguity_unique_recovery=PASS"

safe_delete_id "${remaining[0]}"
log "remaining_duplicate_delete=PASS"

mapfile -t final_ids < <(discover_ids)
[[ "${#final_ids[@]}" -eq 0 ]]
log "instance_leak_check=PASS"

api_request DELETE "/v2/firewalls/${firewall_id}"
[[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "204" ]]
firewall_id=""

api_request GET "/v2/firewalls?per_page=500"
[[ "$HTTP_RC" -eq 0 && "$HTTP_CODE" == "200" ]]
fw_leaks="$(jq --arg d "$FW_DESC" '[.firewall_groups[] | select(.description==$d)] | length' "$HTTP_BODY")"
[[ "$fw_leaks" == "0" ]]
log "firewall_leak_check=PASS"

log "uncertain_mutation_research=PASS"
