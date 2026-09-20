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

prepare_proxy_certificate() {
  # HTTPS proxy endpoints must present the same publicly trusted certificate
  # as edge.alegria.by.  A self-signed fallback is retained only for stacks
  # without a configured tunnel domain (local/dev use).
  if [[ -n "${TUNNEL_DOMAIN:-}" ]]; then
    local acme_cert_dir="tunnel-state/acme/certificates/acme-v02.api.letsencrypt.org-directory/${TUNNEL_DOMAIN}"
    local acme_cert="${acme_cert_dir}/${TUNNEL_DOMAIN}.crt"
    local acme_key="${acme_cert_dir}/${TUNNEL_DOMAIN}.key"
    if [[ ! -s "$acme_cert" || ! -s "$acme_key" ]]; then
      echo "Trusted proxy certificate is missing for ${TUNNEL_DOMAIN}" >&2
      exit 1
    fi
    install -m 0644 "$acme_cert" certs/proxy.crt
    install -m 0600 "$acme_key" certs/proxy.key
    return
  fi

  if [[ ! -f certs/proxy.crt || ! -f certs/proxy.key ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout certs/proxy.key \
    -out certs/proxy.crt \
    -days 3650 \
    -subj "/CN=${PROXY_CERT_CN}"
  fi
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

start_base() {
  require_digest_ref EDGE_GATEWAY_IMAGE
  require_digest_ref EDGE_WARP_EGRESS_IMAGE
  prepare_proxy_certificate
  envsubst < line2-proxy/config.template.json > rendered/line2-proxy.json
  compose_up warp-egress line2-proxy
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
    return 0
  fi

  local acme_cert_dir="tunnel-state/acme/certificates/acme-v02.api.letsencrypt.org-directory/${TUNNEL_DOMAIN}"
  local acme_cert="${acme_cert_dir}/${TUNNEL_DOMAIN}.crt"
  local acme_key="${acme_cert_dir}/${TUNNEL_DOMAIN}.key"
  if [[ ! -s "$acme_cert" || ! -s "$acme_key" ]]; then
    echo "ACME certificate cache is missing for ${TUNNEL_DOMAIN}: expected ${acme_cert} and ${acme_key}" >&2
    echo "Seed edge-platform/.runtime/cert-cache/acme before deploying tunnels." >&2
    exit 1
  fi

  envsubst < line1-gateway/config.template.json > rendered/line1-gateway.json
  compose_up --profile tunnel line1-gateway
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
}

case "$MODE" in
  base)
    start_base
    ;;
  tunnel)
    start_tunnels
    ;;
  mesh)
    start_mesh
    ;;
  full)
    start_base
    start_tunnels
    ;;
  *)
    echo "Unknown bootstrap mode: $MODE" >&2
    exit 1
    ;;
esac

docker ps
