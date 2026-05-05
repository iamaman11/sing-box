# RUNBOOK

## Primary entrypoint

The normal operator workflow is Rust-first and production-first.

Open the console:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe"
```

The console autostarts `edge-controller.exe` on `127.0.0.1:50051` if needed.

You can also use command mode:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" status
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" trace
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" deploy
```

## Main console actions

- `status`
  - local runtime state
  - deployment summary
  - agent/runtime reachability
  - selector state

- `start-local`
- `stop-local`
- `restart-local`

- `get-selector`
- `set-selector <name>`
- `get-ubuntu-selector`
- `set-ubuntu-selector <name>`

- `trace`
- `trace-ubuntu`

- `deploy`
- `destroy`

- `secrets`
- `get-secret <name>`
- `set-secret <name> <secret-ref>`

- `get-operation <id>`
- `watch-operation <id>`

## Secret names

The controller persists secret references in SQLite.

Supported names:

- `provider.vultr.api_key`
- `provider.cloudflare.api_token`
- `bootstrap.vultr.ssh_key_id`
- `bootstrap.ssh.private_key_path`

Supported secret reference formats:

- `env:NAME`
- `file:/abs/path`
- `path:/abs/path`
- `literal:value`

Example:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-secret provider.vultr.api_key env:VULTR_API_KEY
```

## Recommended flows

### 1. Inspect current state

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" status
```

### 2. Start the local client

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" start-local
```

### 3. Switch desktop route

Direct:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-selector auto-direct-tunnel
```

WARP:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-selector auto-warp-tunnel
```

### 4. Switch Ubuntu WSL route

Direct:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-ubuntu-selector auto-direct-tunnel
```

WARP:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-ubuntu-selector auto-warp-tunnel
```

Show Ubuntu route and egress:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" get-ubuntu-selector
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" trace-ubuntu
```

### 5. Ubuntu-side usage

The supported Ubuntu path is now Windows-side proxying, not Linux-side `tun`.

Current endpoint from Ubuntu:

```bash
http://$(ip route show default | cut -d' ' -f3):17890
```

Ad-hoc command:

```bash
curl -4 --proxy http://$(ip route show default | cut -d' ' -f3):17890 https://api.ipify.org
```

The user shell helper installed in Ubuntu exports proxy env vars automatically for new shells:

- `http_proxy`
- `https_proxy`
- `all_proxy`

### 6. Deploy or redeploy

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" deploy
```

If the deploy output returns an operation id, follow it with:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" watch-operation <id>
```

### 7. Destroy

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" destroy
```

## Current WSL proxy behavior

- Windows `sing-box` exposes:
  - `wsl-mixed-in`
  - port `17890`
- the inbound is routed to:
  - `wsl-selector`
- `wsl-selector` is independent from:
  - `proxy-selector`

That means:

- desktop selector changes do not change Ubuntu selector
- Ubuntu selector changes do not change desktop selector

## Historical note

PowerShell scripts under `win/windows` and `win/vultr-waw`, and the old Linux-side WSL `tun` setup, are retained only as historical reference. They are not the primary supported control path anymore.
