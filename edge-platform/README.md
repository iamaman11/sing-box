# edge-platform

Rust control plane for:

- Windows-side local `sing-box`
- Vultr edge runtime lifecycle
- Ubuntu WSL egress through the Windows `sing-box`

## Production entrypoint

The normal operator entrypoint is:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe"
```

The console now autostarts `edge-controller.exe` on `127.0.0.1:50051` if it is not already running, and reuses the existing controller if it is already up.

## Current architecture

- local control plane:
  - `edge-console -> edge-controller`
- server control plane:
  - `edge-controller -> edge-agent`
- local Windows dataplane:
  - one managed `sing-box`
  - desktop/global selector:
    - `proxy-selector`
  - Ubuntu/WSL selector:
    - `wsl-selector`
- server dataplane:
  - existing 5-container topology on the Vultr VM

## Current source of truth

Do not treat the AppData runtime JSON as authoritative.

Authoritative layers are:

- runtime config shape:
  - `win/windows/edge-dns-clean-vultr-dual.json`
- Windows-side sync and mutation:
  - `edge-platform/crates/edge-singbox/src/lib.rs`
- controller/runtime observation and selector control:
  - `edge-platform/crates/edge-controller/src/main.rs`
  - `edge-platform/crates/edge-console/src/main.rs`

Derived/runtime copies include:

- `C:\Users\Bose\AppData\Local\sing-box-vultr-dual\runtime\edge-dns-clean-vultr-dual.json`

## What works

- local `sing-box` start/stop/restart
- visible-window `sing-box` launch from the console
- desktop selector read/write
- Ubuntu/WSL selector read/write
- desktop trace/IP observation
- Ubuntu trace/IP observation through the Windows WSL inbound
- deploy/destroy through the Rust state machine
- VM creation from Vultr snapshot:
  - `61605612-d7a2-47b1-85ef-aef90f5083df`
- Cloudflare DNS update for:
  - `edge.alegria.by`
- persisted operations, secret refs, and controller state in SQLite

## Current Windows selector model

Desktop/global path:

- selector tag:
  - `proxy-selector`
- menu items:
  - `Direct tunnel -> ...`
  - `WARP tunnel -> ...`

Ubuntu/WSL path:

- inbound tag:
  - `wsl-mixed-in`
- selector tag:
  - `wsl-selector`
- menu items:
  - `Ubuntu tunnel -> auto direct`
  - `Ubuntu tunnel -> hysteria2 direct`
  - `Ubuntu tunnel -> vless direct`
  - `Ubuntu tunnel -> auto warp`
  - `Ubuntu tunnel -> hysteria2 warp`
  - `Ubuntu tunnel -> vless warp`
  - `Show current Ubuntu tunnel`
  - `Show current Ubuntu egress IP`

The two selector surfaces are independent:

- changing `proxy-selector` does not change `wsl-selector`
- changing `wsl-selector` does not change `proxy-selector`

## Ubuntu WSL model

Ubuntu no longer relies on a Linux-side `sing-box` tunnel in the main supported path.

Instead:

- Windows `sing-box` exposes a dedicated WSL inbound on:
  - `0.0.0.0:17890`
- Ubuntu reaches it through the current WSL gateway, typically:
  - `172.26.16.1:17890`

Effective Ubuntu proxy endpoint:

```bash
http://$(ip route show default | cut -d' ' -f3):17890
```

This is the endpoint that should be used by Ubuntu applications or shell proxy environment variables.

## Ubuntu shell setup

The supported Ubuntu-side convenience setup now uses proxy environment variables, not a Linux-side `tun`.

Installed user-side helper:

- `~/.edge-platform-wsl-proxy.sh`

Sourced from:

- `~/.profile`
- `~/.bashrc`

This exports:

- `http_proxy`
- `https_proxy`
- `HTTP_PROXY`
- `HTTPS_PROXY`
- `all_proxy`
- `ALL_PROXY`
- `no_proxy`
- `NO_PROXY`

Current policy:

- `http_proxy` / `https_proxy` point to:
  - `http://<wsl-gateway>:17890`
- `all_proxy` points to:
  - `socks5h://<wsl-gateway>:17890`

System package manager support:

- `/usr/local/bin/edge-wsl-proxy-autodetect`
- `/etc/apt/apt.conf.d/99edge-platform-proxy`

That allows `apt` to auto-detect the current WSL gateway dynamically.

Git policy:

- do not pin `git config --global http.proxy` or `https.proxy` to a static WSL gateway IP
- `git` should inherit the same dynamic proxy environment as the shell
- that keeps `git`, `curl`, and other proxy-aware CLI tools aligned when the WSL gateway changes

## Useful commands

Status:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" status
```

Desktop selector:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" get-selector
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-selector auto-direct-tunnel
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-selector auto-warp-tunnel
```

Ubuntu selector:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" get-ubuntu-selector
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-ubuntu-selector auto-direct-tunnel
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" set-ubuntu-selector auto-warp-tunnel
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" trace-ubuntu
```

Local runtime:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" start-local
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" restart-local
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" stop-local
```

Deploy/destroy:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" deploy
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" destroy
```

## Secret names

Persisted in controller SQLite:

- `provider.vultr.api_key`
- `provider.cloudflare.api_token`
- `bootstrap.vultr.ssh_key_id`
- `bootstrap.ssh.private_key_path`

Supported secret reference formats:

- `env:NAME`
- `file:/abs/path`
- `path:/abs/path`
- `literal:value`

## Notes

- `edge-console` is the only intended operator entrypoint.
- The old Linux-side WSL `tun` setup is retained only as historical reference and is not the primary supported Ubuntu path anymore.
- `untracked` recovery artifacts such as `RECOVERY-NOTES.md` and `recovered/` are intentionally not part of the normal project state.
