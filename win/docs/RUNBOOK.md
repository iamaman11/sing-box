# RUNBOOK

## Primary entrypoint

The normal operator workflow is now Rust-first.

Start the controller daemon:

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-controller.exe" serve
```

Open the operator console:

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" menu
```

You can also use command mode:

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" status
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" trace
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" deploy
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

- `trace`

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
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" set-secret provider.vultr.api_key env:VULTR_API_KEY
```

## Recommended flows

### 1. Inspect current state

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" status
```

### 2. Start the local client

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" start-local
```

### 3. Switch route

Direct:

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" set-selector auto-direct-tunnel
```

WARP:

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" set-selector auto-warp-tunnel
```

### 4. Deploy or redeploy

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" deploy
```

If the deploy output returns an operation id, follow it with:

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" watch-operation <id>
```

### 5. Destroy

```powershell
& "\\wsl$\Ubuntu\home\bose\projects\sing-box\edge-platform\target\debug\edge-console.exe" destroy
```

## Legacy reference

PowerShell scripts under `win/windows` and `win/vultr-waw` are retained only as
historical reference during migration review. They are not the primary control
path anymore.
