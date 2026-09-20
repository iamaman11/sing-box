#!/usr/bin/env bash
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$STACK_DIR"
MODE="${1:-full}"

if [[ ! -f .images.env ]]; then
  echo ".images.env not found" >&2
  exit 1
fi
if [[ ! -f .env.runtime ]]; then
  echo ".env.runtime not found" >&2
  exit 1
fi

set -a
source ./.env.runtime
source ./.images.env
set +a

mkdir -p certs rendered warp-state mesh-state tunnel-state

acme_certificate_dir() {
  printf 'tunnel-state/acme/certificates/acme-v02.api.letsencrypt.org-directory/%s' "${TUNNEL_DOMAIN}"
}

wait_for_owned_certificate() {
  local cert_dir
  local cert
  local key
  cert_dir="$(acme_certificate_dir)"
  cert="${cert_dir}/${TUNNEL_DOMAIN}.crt"
  key="${cert_dir}/${TUNNEL_DOMAIN}.key"

  for _ in $(seq 1 90); do
    if [[ -s "$cert" && -s "$key" ]] && openssl x509 -checkend 300 -noout -in "$cert" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done

  docker compose --profile tunnel logs --tail=80 line1-gateway >&2 || true
  echo "line1-gateway did not publish a valid owned certificate for ${TUNNEL_DOMAIN} within 180s" >&2
  return 1
}

prepare_proxy_certificate() {
  if [[ -n "${TUNNEL_DOMAIN:-}" ]]; then
    local cert_dir
    local cert
    local key
    cert_dir="$(acme_certificate_dir)"
    cert="${cert_dir}/${TUNNEL_DOMAIN}.crt"
    key="${cert_dir}/${TUNNEL_DOMAIN}.key"
    if [[ ! -s "$cert" || ! -s "$key" ]]; then
      echo "line1 certificate owner has not published ${TUNNEL_DOMAIN}" >&2
      return 1
    fi

    export PROXY_CERT_PATH="/var/lib/sing-box/acme/certificates/acme-v02.api.letsencrypt.org-directory/${TUNNEL_DOMAIN}/${TUNNEL_DOMAIN}.crt"
    export PROXY_KEY_PATH="/var/lib/sing-box/acme/certificates/acme-v02.api.letsencrypt.org-directory/${TUNNEL_DOMAIN}/${TUNNEL_DOMAIN}.key"
    return 0
  fi

  if [[ ! -f certs/proxy.crt || ! -f certs/proxy.key ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout certs/proxy.key \
      -out certs/proxy.crt \
      -days 3650 \
      -subj "/CN=${PROXY_CERT_CN}"
  fi
  export PROXY_CERT_PATH="/certs/proxy.crt"
  export PROXY_KEY_PATH="/certs/proxy.key"
}

require_digest_ref() {
  local name="$1"
  local value="${!name:-}"
  if [[ ! "$value" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "$name must be an immutable image digest reference" >&2
    exit 1
  fi
}

compose_up() {
  local profile_args=()
  if [[ $# -gt 0 && "$1" == "--profile" ]]; then
    profile_args=("$1" "$2")
    shift 2
  fi

  docker compose "${profile_args[@]}" pull "$@"
  docker compose "${profile_args[@]}" up -d --force-recreate "$@"
}

start_warp_egress() {
  require_digest_ref EDGE_WARP_EGRESS_IMAGE
  compose_up warp-egress
}

start_line2() {
  require_digest_ref EDGE_GATEWAY_IMAGE
  prepare_proxy_certificate
  envsubst < line2-proxy/config.template.json > rendered/line2-proxy.json
  docker compose pull line2-proxy
  docker compose up -d --force-recreate --no-deps line2-proxy
}

start_mesh() {
  require_digest_ref CLOUDFLARE_MESH_IMAGE
  if [[ -z "${MESH_NODE_TOKEN:-}" ]]; then
    echo "MESH_NODE_TOKEN is required for mesh mode" >&2
    exit 1
  fi

  compose_up --profile mesh cloudflare-mesh

  local mesh_ready=0
  for _ in $(seq 1 60); do
    if docker exec vultr-cloudflare-mesh warp-cli status 2>/dev/null | grep -qi "Connected"; then
      mesh_ready=1
      break
    fi
    sleep 2
  done

  if [[ "$mesh_ready" != "1" ]]; then
    docker compose --profile mesh logs --tail=80 cloudflare-mesh >&2 || true
    echo "cloudflare-mesh did not reach Connected state within 120s" >&2
    exit 1
  fi
}

start_tunnels() {
  require_digest_ref EDGE_GATEWAY_IMAGE
  if [[ -z "${TUNNEL_DOMAIN:-}" || -z "${ACME_EMAIL:-}" ]]; then
    echo "TUNNEL_DOMAIN and ACME_EMAIL are required for tunnel mode" >&2
    return 1
  fi

  envsubst < line1-gateway/config.template.json > rendered/line1-gateway.json
  docker compose --profile tunnel pull line1-gateway
  docker compose --profile tunnel up -d --force-recreate --no-deps line1-gateway

  local tunnel_ready=0
  for _ in $(seq 1 60); do
    if docker compose --profile tunnel ps --status running --services | grep -Fxq "line1-gateway"; then
      tunnel_ready=1
      break
    fi
    sleep 2
  done
  if [[ "$tunnel_ready" != "1" ]]; then
    docker compose --profile tunnel logs --tail=80 line1-gateway >&2 || true
    echo "line1-gateway did not reach running state within 120s" >&2
    exit 1
  fi

  wait_for_owned_certificate
}

case "$MODE" in
  base)
    start_warp_egress
    start_line2
    ;;
  tunnel)
    start_warp_egress
    start_tunnels
    ;;
  mesh)
    start_mesh
    ;;
  full)
    start_warp_egress
    start_tunnels
    start_line2
    ;;
  *)
    echo "Unknown bootstrap mode: $MODE" >&2
    exit 1
    ;;
esac

docker ps
