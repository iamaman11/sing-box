#!/usr/bin/env bash
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$STACK_DIR"
MODE="${1:-full}"
PUBLIC_CERT_ROOT="tunnel-state/acme/certificates"

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

prepare_local_proxy_certificate() {
  if [[ -n "${TUNNEL_DOMAIN:-}" ]]; then
    echo "Public proxy certificate must come from the Line 1 certificate owner" >&2
    exit 1
  fi

  if [[ ! -f certs/proxy.crt || ! -f certs/proxy.key ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout certs/proxy.key \
      -out certs/proxy.crt \
      -days 3650 \
      -subj "/CN=${PROXY_CERT_CN}"
  fi
}

sync_proxy_certificate_from_owner() {
  if [[ -z "${TUNNEL_DOMAIN:-}" ]]; then
    echo "TUNNEL_DOMAIN is required to consume the public certificate" >&2
    exit 1
  fi

  local cert=""
  local key=""
  for _ in $(seq 1 90); do
    mapfile -t matches < <(
      find "$PUBLIC_CERT_ROOT" -type f -name "${TUNNEL_DOMAIN}.crt" -print 2>/dev/null | sort
    )
    if [[ "${#matches[@]}" -gt 1 ]]; then
      printf 'Multiple public certificates found for %s; refusing ambiguous ownership\n' "$TUNNEL_DOMAIN" >&2
      printf '%s\n' "${matches[@]}" >&2
      exit 1
    fi
    if [[ "${#matches[@]}" -eq 1 ]]; then
      cert="${matches[0]}"
      key="${cert%.crt}.key"
      if [[ -s "$cert" && -s "$key" ]]; then
        install -m 0644 "$cert" certs/proxy.crt
        install -m 0600 "$key" certs/proxy.key
        return 0
      fi
    fi
    sleep 2
  done

  docker compose --profile tunnel logs --tail=80 line1-gateway >&2 || true
  echo "Line 1 certificate owner did not publish the required certificate within 180s" >&2
  exit 1
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

start_warp() {
  require_digest_ref EDGE_WARP_EGRESS_IMAGE
  compose_up warp-egress
}

start_base() {
  require_digest_ref EDGE_GATEWAY_IMAGE
  if [[ -n "${TUNNEL_DOMAIN:-}" ]]; then
    sync_proxy_certificate_from_owner
  else
    prepare_local_proxy_certificate
  fi
  envsubst < line2-proxy/config.template.json > rendered/line2-proxy.json
  compose_up line2-proxy
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
    exit 1
  fi

  envsubst < line1-gateway/config.template.json > rendered/line1-gateway.json
  compose_up --profile tunnel line1-gateway

  sync_proxy_certificate_from_owner

  if ! docker compose --profile tunnel ps --status running --services | grep -Fxq "line1-gateway"; then
    docker compose --profile tunnel logs --tail=80 line1-gateway >&2 || true
    echo "line1-gateway is not running after certificate convergence" >&2
    exit 1
  fi
}

case "$MODE" in
  base)
    start_warp
    start_base
    ;;
  tunnel)
    start_warp
    start_tunnels
    ;;
  mesh)
    start_mesh
    ;;
  full)
    start_warp
    start_tunnels
    start_base
    ;;
  *)
    echo "Unknown bootstrap mode: $MODE" >&2
    exit 1
    ;;
esac

docker ps
