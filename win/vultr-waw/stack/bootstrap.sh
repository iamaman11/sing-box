#!/usr/bin/env bash
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$STACK_DIR"
MODE="${1:-full}"

if [[ ! -f .env.runtime ]]; then
  echo ".env.runtime not found" >&2
  exit 1
fi

set -a
source ./.env.runtime
set +a

USE_PREBUILT_IMAGES="${EDGE_USE_PREBUILT_IMAGES:-0}"

mkdir -p certs rendered warp-state tunnel-state

if [[ ! -f certs/proxy.crt || ! -f certs/proxy.key ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout certs/proxy.key \
    -out certs/proxy.crt \
    -days 3650 \
    -subj "/CN=${PROXY_CERT_CN}"
fi

envsubst < edge-gateway/config.template.json > rendered/edge-gateway.json
envsubst < edge-gateway/config.direct.template.json > rendered/edge-gateway-direct.json

compose_up() {
  local profile_args=()
  if [[ $# -gt 0 && "$1" == "--profile" ]]; then
    profile_args=("$1" "$2")
    shift 2
  fi

  if [[ "$USE_PREBUILT_IMAGES" == "1" ]]; then
    docker compose "${profile_args[@]}" pull "$@" || true
    docker compose "${profile_args[@]}" up -d "$@"
  else
    docker compose "${profile_args[@]}" up -d --build "$@"
  fi
}

start_base() {
  compose_up warp-egress edge-gateway edge-gateway-direct
}

start_tunnels() {
  if [[ -z "${TUNNEL_DOMAIN:-}" || -z "${ACME_EMAIL:-}" ]]; then
    return 0
  fi

  envsubst < tunnel-edge/config.template.json > rendered/tunnel-edge.json
  envsubst < tunnel-edge/config.warp.template.json > rendered/tunnel-edge-warp.json
  compose_up --profile tunnel tunnel-edge
  for _ in $(seq 1 60); do
    if docker compose ps tunnel-edge | grep -q "running"; then
      break
    fi
    sleep 2
  done
  compose_up --profile tunnel tunnel-edge-warp
}

case "$MODE" in
  base)
    start_base
    ;;
  tunnel)
    start_tunnels
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
