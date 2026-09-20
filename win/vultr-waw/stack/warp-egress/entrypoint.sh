#!/bin/bash
set -euo pipefail

mkdir -p /run/dbus /var/log/warp
rm -f /run/dbus/pid
dbus-daemon --system --fork 2>/dev/null || true
sleep 1

warp-svc > /var/log/warp/warp-svc.log 2>&1 &

for i in $(seq 1 30); do
    if warp-cli --accept-tos status >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if [ ! -s /var/lib/cloudflare-warp/reg.json ]; then
    warp-cli --accept-tos registration new >/var/log/warp/warp-registration.log 2>&1 || true
else
    echo "existing WARP registration found, reusing it" >/var/log/warp/warp-registration.log
fi
warp-cli --accept-tos mode proxy >/var/log/warp/warp-mode.log 2>&1 || true
warp-cli --accept-tos proxy port 1080 >/var/log/warp/warp-proxy-port.log 2>&1 || true
warp-cli --accept-tos connect >/var/log/warp/warp-connect.log 2>&1 || true

socat TCP-LISTEN:11080,fork,bind=0.0.0.0,reuseaddr TCP:127.0.0.1:1080 \
    >/var/log/warp/warp-socat.log 2>&1 &

warp_ready=0
for i in $(seq 1 45); do
    if warp-cli --accept-tos status 2>/dev/null | grep -q "Connected"; then
        warp_ready=1
        break
    fi
    sleep 1
done

if [ "$warp_ready" != "1" ]; then
    echo "warp-egress failed to reach Connected state within 45s" >&2
    exit 1
fi

echo "warp-egress ready"
exec tail -f /var/log/warp/warp-svc.log /var/log/warp/warp-connect.log /var/log/warp/warp-proxy-port.log /var/log/warp/warp-socat.log
