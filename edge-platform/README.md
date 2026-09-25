# edge-platform

Rust control plane for the project.

## Authority boundaries

The remote repository `https://github.com/iamaman11/sing-box` is the canonical
source of truth.

Server lifecycle is GitHub-owned:

- `.github/workflows/vultr-lifecycle.yml`
  - VM create/observe/start/halt/reboot;
  - destroy-plan / digest-gated destroy-apply;
  - lifecycle-owned support-resource cleanup.
- `.github/workflows/vm-application-lifecycle.yml`
  - exact edge-agent/application apply;
  - verify;
  - upgrade;
  - rollback.

Windows is local-only:

- `edge-controller.exe` serves Windows-local status/runtime/selector APIs on
  `127.0.0.1:50051`;
- `edge-console.exe` is the operator CLI for the Windows-local runtime;
- Windows automation may start/stop/restart the local sing-box and change local
  selectors;
- Windows does not create, deploy, bootstrap, or delete Vultr VMs and does not
  own Vultr/Cloudflare provider credentials.

Do not reintroduce a Windows Vultr API path, direct Windows SSH/SCP deployment,
TOFU host enrollment, external VM reaper, or server lifecycle commands in the
Windows console.

## Build and release model

Accepted `main` is built once in GitHub Actions.

Linux/server release set:

- `edge-controller`;
- `edge-agent`;
- `vultr-edge-gateway@sha256:...`;
- `vultr-warp-egress@sha256:...`.

Windows control release set:

- `edge-controller.exe`;
- `edge-console.exe`;
- manifest bound to the exact accepted `main` SHA and SHA-256 of both files.

Production deployment never runs `cargo build` or `docker build` on the VM.
Windows operation does not require a local Rust build.

## Install/update Windows control binaries

Prerequisites:

- GitHub CLI `gh` installed and authenticated;
- this repository available locally so the installer script can be invoked.

Run:

```powershell
& "C:\Users\Bose\temp\sing-box\edge-platform\scripts\install-windows-release.ps1"
```

The installer:

1. resolves the canonical remote `main` SHA;
2. selects the first successful `Edge Platform CI` run for that exact SHA;
3. downloads `edge-platform-windows-<SHA>`;
4. verifies manifest schema, exact revision and both SHA-256 digests;
5. stores the immutable release under:
   `%LOCALAPPDATA%\edge-platform\releases\<SHA>`;
6. currently updates the legacy local activation pointer
   `%LOCALAPPDATA%\edge-platform\current.json`;
7. installs the stable console path:
   `%LOCALAPPDATA%\edge-platform\bin\edge-console.exe`.

`current.json` is frozen first-party JSON migration debt, not an approved
pattern for new state. Slice 2 must move the Windows activation/LKG state to the
protobuf-owned release state while preserving atomic activation and digest
verification. Until that migration lands, the controller is executed from the
versioned release path recorded in the legacy pointer. `ensure-edge-controller.ps1`
verifies its SHA-256 before starting it. If port 50051 is occupied by an
unmanaged process, it fails closed instead of terminating that process.

## Normal Windows entrypoint

```powershell
& "$env:LOCALAPPDATA\edge-platform\bin\edge-console.exe" status
```

Interactive menu:

```powershell
& "$env:LOCALAPPDATA\edge-platform\bin\edge-console.exe"
```

The repository helper `edge-platform/scripts/start-edge-console.cmd` ensures
the matching accepted controller is running before launching the console.

## Windows-local capabilities

Supported operator surface includes:

- status / doctor;
- start/stop/restart local sing-box;
- desktop selector read/write;
- WSL selector read/write;
- desktop and Ubuntu/WSL egress trace.

Server create/destroy/bootstrap is intentionally absent from the Windows
operator surface.

## Application/runtime composition

Canonical stack inputs live under:

- `win/vultr-waw/stack/`.

Accepted-main CI builds custom application images. The application lifecycle
injects immutable image digest references as non-secret `.images.env`.
Runtime secrets/configuration are separate in `.env.runtime`.

The VM only pulls and runs exact image digests.

## Serialization rule

First-party durable contracts and desired state are protobuf-owned. Human-edited
Git desired state uses protobuf text format. JSON is allowed only at physically
required external boundaries; existing internal JSON is frozen migration debt
and must only shrink. See `ARCHITECTURE.md`.

## Safety invariants

- exact accepted `main` revision is always recorded;
- artifacts are verified by SHA-256 before use;
- custom production images use immutable digest references;
- no runtime build on the VM;
- no mutable `:latest` for project-owned production images;
- destructive VM operations require a fresh typed destroy digest;
- strict SSH trust is owned by the canonical GitHub lifecycle;
- Windows contains no provider mutation authority.
