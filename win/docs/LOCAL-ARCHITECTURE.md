# Local Architecture

## Scope

This document describes the current Windows-side architecture used to control
and consume the Vultr edge stack.

It reflects the current implementation in:

- `windows/edge-dns-clean-vultr-dual.json`
- `windows/singbox-dual-menu.ps1`
- `windows/start-vultr-edge-session.ps1`
- `windows/sync-vultr-dual-config.ps1`
- `windows/local-secrets.ps1`
- `windows/initialize-local-secrets-store.ps1`

## Core Components

### 1. Windows sing-box client

Binary:

- `V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe`

Primary dual config:

- `windows/edge-dns-clean-vultr-dual.json`

This client provides:

- local mixed proxy on `127.0.0.1:7890`
- second mixed inbound on `127.0.0.1:7891`
- optional authenticated public mixed inbounds on `9223` and `9224`
- TUN interface `utun0`
- Clash API on `127.0.0.1:9090`
- web UI served from `external_ui`

### 2. Control menu

Script:

- `windows/singbox-dual-menu.ps1`

Functions:

- local sing-box status
- Vultr server status via API
- backend health via SSH
- selector changes
- current IP check
- start dual sing-box
- stop dual sing-box
- create or redeploy Vultr server
- delete Vultr server
- open web UI

Safety model:

- it no longer kills arbitrary `sing-box` processes
- if a different sing-box config is active, it refuses to stop or replace it

### 3. Session launcher

Script:

- `windows/start-vultr-edge-session.ps1`

Purpose:

- one-command operational startup

Flow:

1. verify current Vultr state
2. create server if needed
3. verify backend readiness
4. sync local config from current state
5. start local dual sing-box
6. optionally open UI/menu

Safety model:

- blocks startup if backend is not ready
- refuses to replace a different currently running sing-box config

### 4. Config sync

Script:

- `windows/sync-vultr-dual-config.ps1`

Purpose:

- apply current server-side credentials from the current state file into the
  local dual config

Updates:

- `hysteria2-direct`
- `vless-reality-direct`
- `hysteria2-warp`
- `vless-reality-warp`
- `experimental.clash_api.external_ui`

Encoding:

- writes UTF-8 without BOM to avoid sing-box JSON decode failures

### 5. Local secret store

Files:

- loader: `windows/local-secrets.ps1`
- encrypted store: `%LOCALAPPDATA%\sing-box-vultr-dual\secrets\local-secrets.clixml`
- initializer: `windows/initialize-local-secrets-store.ps1`

Current model:

- secrets are no longer stored as plaintext in the PowerShell loader
- the loader reads DPAPI-protected secrets from the local secret root

Scope limitation:

- this is still tied to the Windows user profile that created the store
- it is not a multi-host or shared secret-management solution

## Local sing-box Data Plane

### Inbounds

1. `mixed-in`
- `127.0.0.1:7890`

2. `mixed-tun`
- `127.0.0.1:7891`

3. `2captcha-public`
- `0.0.0.0:9223`
- authenticated mixed inbound

4. `nodriver-public`
- `0.0.0.0:9224`
- authenticated mixed inbound

5. `tun-in`
- interface: `utun0`
- address: `172.31.255.1/30`
- `auto_route: true`
- `strict_route: true`
- `stack: gvisor`

### Outbounds

Direct branch:

- `hysteria2-direct`
- `vless-reality-direct`
- `auto-direct-tunnel` (`urltest`)

WARP branch:

- `hysteria2-warp`
- `vless-reality-warp`
- `auto-warp-tunnel` (`urltest`)

Top selector:

- `proxy-selector`

Default:

- `auto-direct-tunnel`

### Routing Model

Rules:

1. sniff
2. hijack DNS
3. all local explicit inbounds (`7890`, `7891`, `9223`, `9224`) -> `proxy-selector`
4. selected process list -> `proxy-selector`
5. private IPs -> `direct`
6. final -> `direct`

This means:

- selected apps go through the dual tunnel selector
- everything else remains direct

## DNS Model

Servers:

- Cloudflare DoH
- Google DoH
- bootstrap UDP resolvers

Current behavior:

- DNS is hijacked for TUN traffic
- final DNS goes to DoH
- bootstrap resolver remains direct for initial resolution

Tradeoff:

- good control for tunneled traffic
- not a perfect “all direct apps use only ISP DNS” model

## UI Model

Clash API:

- `127.0.0.1:9090`

UI:

- `metacubexd`
- `external_ui` now resolves relative to the config directory

Windows-local runtime root:

- `%LOCALAPPDATA%\sing-box-vultr-dual\runtime`

Windows-local state root:

- `%LOCALAPPDATA%\sing-box-vultr-dual\state`

Windows-local secret root:

- `%LOCALAPPDATA%\sing-box-vultr-dual\secrets`

Main operational view:

- `http://127.0.0.1:9090/ui/#/proxies`

Operationally meaningful selector:

- `proxy-selector`

The nested items are mostly structural:

- `auto-direct-tunnel`
- `auto-warp-tunnel`
- leaf outbounds

## Local Strengths

- explicit separation between direct and WARP tunnel branches
- `urltest` on both branches
- menu and launcher now enforce backend readiness
- menu no longer kills unrelated sing-box sessions
- project-relative paths allow running from copied project roots
- UI path is now portable
- config sync keeps tunnel credentials consistent with current server state

## Local Weaknesses

- still dependent on one Windows host as the control plane
- still dependent on one local sing-box binary path outside the project tree
- TUN plus per-process routing is operationally useful but not fully
  deterministic for long-lived browser connections
- DPAPI local secret store is safer than plaintext, but still not an
  enterprise secret-management system

## Practical Start Modes

### Menu only

```powershell
& ".\windows\singbox-dual-menu.ps1"
```

### Launcher

```powershell
& ".\windows\start-vultr-edge-session.ps1"
```

### Direct dual sing-box start

```powershell
& "V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe" run -c ".\windows\edge-dns-clean-vultr-dual.json"
```
