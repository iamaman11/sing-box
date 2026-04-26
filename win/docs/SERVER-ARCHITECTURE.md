# Server Architecture

## Scope

This document describes the current server-side architecture deployed by the
`vultr-waw` stack. It reflects the current implementation in:

- `vultr-waw/deploy-waw.ps1`
- `vultr-waw/stack/bootstrap.sh`
- `vultr-waw/stack/docker-compose.yml`
- generated runtime files under `%LOCALAPPDATA%\sing-box-vultr-dual\state\generated\...`

## Provider and Instance Model

The current server target is a Vultr Shared CPU instance in `waw` (Warsaw).

The deployment model is:

1. A server is created or reused through `deploy-waw.ps1`.
2. A deployment bundle is generated locally in `vultr-waw/generated/<label>/stack`.
3. The bundle is copied to `/opt/vultr-edge-stack/stack` on the server.
4. `bootstrap.sh` renders configs and starts containers.
5. Health is checked over SSH before the deployment is considered successful.
6. State is persisted in `%LOCALAPPDATA%\sing-box-vultr-dual\state\current-edge.json`.

## Container Topology

The server currently runs 5 containers:

1. `vultr-warp-egress`
2. `vultr-edge-gateway`
3. `vultr-edge-gateway-direct`
4. `vultr-tunnel-edge`
5. `vultr-tunnel-edge-warp`

### 1. `vultr-warp-egress`

Purpose:

- provides local WARP-based egress only
- does not expose a public client-facing port

Characteristics:

- container image from `stack/warp-egress`
- `NET_ADMIN`
- `/dev/net/tun`
- persistent state volume: `./warp-state:/var/lib/cloudflare-warp`
- internal network address: `172.22.10.2`

Role boundary:

- this container is only an egress module
- it should not accept public client traffic directly

### 2. `vultr-edge-gateway`

Purpose:

- public authenticated proxy gateway with WARP egress

Ports:

- `3128/tcp` HTTP proxy
- `1080/tcp` SOCKS5 proxy
- `9443/tcp` HTTPS proxy

Config source:

- rendered file: `rendered/edge-gateway.json`

Dependencies:

- depends on `vultr-warp-egress`
- attached to `edge_net`
- internal address `172.22.10.3`

Traffic path:

- client -> `edge-gateway` -> internal WARP egress -> internet

### 3. `vultr-edge-gateway-direct`

Purpose:

- public authenticated proxy gateway with direct Vultr egress

Ports:

- `4128/tcp` HTTP proxy
- `4080/tcp` SOCKS5 proxy
- `4443/tcp` HTTPS proxy

Config source:

- rendered file: `rendered/edge-gateway-direct.json`

Traffic path:

- client -> `edge-gateway-direct` -> direct internet via Vultr IP

### 4. `vultr-tunnel-edge`

Purpose:

- direct tunnel entrypoint for Windows sing-box clients

Ports:

- `80/tcp` ACME HTTP challenge
- `443/tcp` VLESS Reality
- `8443/udp` Hysteria2

Config source:

- rendered file: `rendered/tunnel-edge.json`

Storage:

- `./tunnel-state:/var/lib/sing-box`

Traffic path:

- Windows sing-box client -> tunnel-edge -> direct internet via Vultr IP

### 5. `vultr-tunnel-edge-warp`

Purpose:

- WARP-backed tunnel entrypoint for Windows sing-box clients

Ports:

- `5443/tcp` VLESS Reality
- `9444/udp` Hysteria2

Config source:

- rendered file: `rendered/tunnel-edge-warp.json`

Dependencies:

- depends on `vultr-warp-egress`
- attached to `edge_net`
- internal address `172.22.10.4`

Traffic path:

- Windows sing-box client -> tunnel-edge-warp -> internal WARP egress -> internet

## Network Layout

Private docker bridge:

- network name: `edge_net`
- subnet: `172.22.10.0/24`

Assigned addresses:

- `warp-egress`: `172.22.10.2`
- `edge-gateway`: `172.22.10.3`
- `tunnel-edge-warp`: `172.22.10.4`

The direct proxy and direct tunnel containers do not require WARP network
attachment.

## Runtime Files and State

Locally generated:

- `%LOCALAPPDATA%\sing-box-vultr-dual\state\current-edge.json`
- `%LOCALAPPDATA%\sing-box-vultr-dual\state\generated\<label>\deployment-summary.json`
- `%LOCALAPPDATA%\sing-box-vultr-dual\state\generated\<label>\stack\.env.runtime`
- `%LOCALAPPDATA%\sing-box-vultr-dual\state\generated\<label>\id_rsa`
- `%LOCALAPPDATA%\sing-box-vultr-dual\state\generated\<label>\known_hosts`

Server-side persistent paths:

- `/opt/vultr-edge-stack/stack/warp-state`
- `/opt/vultr-edge-stack/stack/tunnel-state`
- `/opt/vultr-edge-stack/stack/certs`
- `/opt/vultr-edge-stack/stack/rendered`

## Deploy Flow

The current deploy sequence is two-phase:

1. create or select instance
2. wait for SSH and Docker readiness
3. initialize strict SSH host verification into deployment-local `known_hosts`
4. copy stack
5. run `./bootstrap.sh base`
6. verify base containers:
   - `vultr-warp-egress`
   - `vultr-edge-gateway`
   - `vultr-edge-gateway-direct`
7. update Cloudflare DNS
8. run `./bootstrap.sh tunnel`
9. verify tunnel containers:
   - `vultr-tunnel-edge`
   - `vultr-tunnel-edge-warp`
10. write final state and summary

This is stronger than the earlier model where DNS was updated before any
meaningful verification.

## Server-Side Strengths

- clear separation between WARP egress and sing-box gateways
- separate direct and WARP datapaths
- separate proxy layer and tunnel layer
- two-phase bootstrap
- backend container verification before final success
- deployment-local strict `known_hosts`
- generated runtime bundle kept per deployment

## Server-Side Weaknesses

- default plan remains `vc2-1c-1gb`, which is too tight for this full stack
- no centralized metrics, alerting, or log shipping
- no blue/green cutover or rollback-to-previous-edge flow
- proxy ports remain public and therefore remain abuse-sensitive
- control plane still depends on one Windows operator host and local state file
- firewall posture is not managed as code in the stack itself

## Exact Public Surface

Proxy surface:

- `3128` HTTP via WARP
- `1080` SOCKS5 via WARP
- `9443` HTTPS via WARP
- `4128` HTTP direct
- `4080` SOCKS5 direct
- `4443` HTTPS direct

Tunnel surface:

- `443/tcp` VLESS Reality direct
- `8443/udp` Hysteria2 direct
- `5443/tcp` VLESS Reality via WARP
- `9444/udp` Hysteria2 via WARP

Support:

- `80/tcp` ACME HTTP challenge
