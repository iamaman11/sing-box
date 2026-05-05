# WSL historical reference

This directory is retained as historical material from the older Ubuntu-side `sing-box` model.

## Current supported model

The primary supported Ubuntu WSL integration is no longer:

- Linux-side `sing-box`
- Linux-side `tun`
- Linux-side `systemd` tunnel routing

The supported model is now:

- Windows-side `sing-box`
- dedicated WSL inbound:
  - `wsl-mixed-in`
- dedicated WSL selector:
  - `wsl-selector`
- Ubuntu uses the Windows proxy endpoint:

```bash
http://$(ip route show default | cut -d' ' -f3):17890
```

## What remains useful here

Only historical reference files:

- previous Ubuntu-side configs
- notes from the older transparent-routing setup
- migration context

These files should not be treated as the current production architecture.

## Current Ubuntu setup

Current Ubuntu shells are configured by:

- `~/.edge-platform-wsl-proxy.sh`
- `~/.profile`
- `~/.bashrc`

Current apt proxy autodetect:

- `/usr/local/bin/edge-wsl-proxy-autodetect`
- `/etc/apt/apt.conf.d/99edge-platform-proxy`

## Current verification commands

Check the current Ubuntu route selected in Windows:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" get-ubuntu-selector
```

Check the current Ubuntu egress IP through the Windows-side WSL path:

```powershell
& "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" trace-ubuntu
```

Check from inside Ubuntu:

```bash
curl -4 https://api.ipify.org
```

For new shell sessions this should already use the exported proxy environment.

Explicit proxy check:

```bash
curl -4 --proxy http://$(ip route show default | cut -d' ' -f3):17890 https://api.ipify.org
```
