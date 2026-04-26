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

start_base() {
  docker compose up -d --build warp-egress edge-gateway edge-gateway-direct
}

start_tunnels() {
  if [[ -z "${TUNNEL_DOMAIN:-}" || -z "${ACME_EMAIL:-}" ]]; then
    return 0
  fi

  envsubst < tunnel-edge/config.template.json > rendered/tunnel-edge.json
  envsubst < tunnel-edge/config.warp.template.json > rendered/tunnel-edge-warp.json
  docker compose --profile tunnel up -d --build tunnel-edge
  for _ in $(seq 1 60); do
    if docker compose ps tunnel-edge | grep -q "running"; then
      break
    fi
    sleep 2
  done
  docker compose --profile tunnel up -d tunnel-edge-warp
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
