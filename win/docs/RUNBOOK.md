# RUNBOOK

## Scope

This runbook describes the practical day-to-day operation of the current
Windows + Vultr stack.

It assumes:

- project copy is available under `\\wsl$\Ubuntu\home\bose\projects\sing-box\win`
- Windows sing-box binary is available at:
  - `V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe`

## Main Entry Points

Menu:

```powershell
powershell -ExecutionPolicy Bypass -File "\\wsl$\Ubuntu\home\bose\projects\sing-box\win\windows\singbox-dual-menu.ps1"
```

Launcher:

```powershell
powershell -ExecutionPolicy Bypass -File "\\wsl$\Ubuntu\home\bose\projects\sing-box\win\windows\start-vultr-edge-session.ps1"
```

Direct dual sing-box start:

```powershell
& "V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe" run -c "\\wsl$\Ubuntu\home\bose\projects\sing-box\win\windows\edge-dns-clean-vultr-dual.json"
```

## Menu Options

`1. Status`

- local sing-box status
- current Vultr instance status
- backend readiness
- active selector state

`2. Direct tunnel -> auto`

- sets `proxy-selector = auto-direct-tunnel`

`3. Direct tunnel -> hysteria2`

- sets `proxy-selector = hysteria2-direct`

`4. Direct tunnel -> vless`

- sets `proxy-selector = vless-reality-direct`

`5. WARP tunnel -> auto`

- sets `proxy-selector = auto-warp-tunnel`

`6. WARP tunnel -> hysteria2`

- sets `proxy-selector = hysteria2-warp`

`7. WARP tunnel -> vless`

- sets `proxy-selector = vless-reality-warp`

`8. Show current IP`

- checks current tunnel egress through local proxy `127.0.0.1:7890`

`9. Start sing-box (new window)`

- starts the dual Windows client
- refuses to start if:
  - Vultr backend is not ready
  - another non-dual sing-box config is already running

`10. Stop sing-box`

- stops only the dual client
- refuses to stop unrelated sing-box processes

`11. Create/redeploy Vultr server`

- creates a server if none exists
- redeploys the current server if one exists
- syncs local dual config from state

`12. Delete current Vultr server`

- deletes the current instance from state

`13. Open UI`

- opens:
  - `http://127.0.0.1:9090/ui/#/proxies`

## Recommended Flows

### 1. Normal startup

1. Open the menu.
2. Press `1` and confirm:
   - `Vultr server exists = True`
   - `Vultr backend ready = True`
3. Press `9`.
4. Press `13`.
5. In the UI or menu, choose:
   - direct branch
   - or WARP branch

### 2. Full startup from scratch

1. Open the menu.
2. Press `11`.
3. Wait for deploy to finish.
4. Press `1` and confirm backend is ready.
5. Press `9`.
6. Press `13`.

### 3. Switch to WARP

In menu:

- `5` for auto WARP
- `6` for forced Hysteria2 WARP
- `7` for forced VLESS WARP

Expected validation:

```powershell
curl.exe --proxy "http://127.0.0.1:7890" https://cloudflare.com/cdn-cgi/trace
```

Expected result:

- `warp=on`

### 4. Switch to direct Vultr egress

In menu:

- `2` for auto direct
- `3` for forced Hysteria2 direct
- `4` for forced VLESS direct

Expected validation:

```powershell
curl.exe --proxy "http://127.0.0.1:7890" https://cloudflare.com/cdn-cgi/trace
```

Expected result:

- `warp=off`
- IP should be the Vultr public IP

### 5. Delete server

1. Open the menu.
2. Press `12`.
3. Confirm deletion.

If server is already missing, the menu should report that instead of failing.

## Direct Proxy Validation

WARP HTTP proxy:

```powershell
curl.exe --proxy "http://v_user:<PASSWORD>@64.176.69.113:3128" https://cloudflare.com/cdn-cgi/trace
```

WARP SOCKS5 proxy:

```powershell
curl.exe --socks5-hostname "64.176.69.113:1080" --proxy-user "v_user:<PASSWORD>" https://cloudflare.com/cdn-cgi/trace
```

WARP HTTPS proxy:

```powershell
curl.exe --proxy-insecure --proxy "https://v_user:<PASSWORD>@64.176.69.113:9443" https://cloudflare.com/cdn-cgi/trace
```

Direct HTTP proxy:

```powershell
curl.exe --proxy "http://v_user:<PASSWORD>@64.176.69.113:4128" https://cloudflare.com/cdn-cgi/trace
```

Direct SOCKS5 proxy:

```powershell
curl.exe --socks5-hostname "64.176.69.113:4080" --proxy-user "v_user:<PASSWORD>" https://cloudflare.com/cdn-cgi/trace
```

Direct HTTPS proxy:

```powershell
curl.exe --proxy-insecure --proxy "https://v_user:<PASSWORD>@64.176.69.113:4443" https://cloudflare.com/cdn-cgi/trace
```

Note:

- actual password is stored in the current state file:
  - `%LOCALAPPDATA%\sing-box-vultr-dual\state\current-edge.json`

## State, Runtime, Secrets

State:

- `%LOCALAPPDATA%\sing-box-vultr-dual\state`

Runtime:

- `%LOCALAPPDATA%\sing-box-vultr-dual\runtime`

Secrets:

- `%LOCALAPPDATA%\sing-box-vultr-dual\secrets`

## Recovery

### If menu says backend not ready

1. Press `1`
2. Check `Vultr backend note`
3. Press `11`
4. Re-check `1`

### If menu says another sing-box config is running

That means a different config is already active, for example:

- `edge-dns-clean-vm-alegria.json`

Stop that process manually first, then start the dual client.

### If UI opens but switching seems ineffective

- old browser connections may still be alive
- close the browser completely and reopen it
- use menu option `8` to verify current tunnel IP directly

## One-Command Startup

If you want a simple start path:

```powershell
powershell -ExecutionPolicy Bypass -File "\\wsl$\Ubuntu\home\bose\projects\sing-box\win\windows\start-vultr-edge-session.ps1"
```

This will:

1. verify current Vultr state
2. create a server if needed
3. verify backend health
4. sync local config
5. start the dual Windows sing-box client
