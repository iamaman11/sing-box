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
- `edge-diagnostic.exe`;
- `sing-box.exe`;
- `edge-release-set.exe`;
- canonical `release-set.pb` with exact SHA-256 identities.

Production deployment never runs `cargo build` or `docker build` on the VM.
Windows operation does not require a local Rust build.

## Install/update Windows control binaries

The canonical new Windows application root is `C:\sing-box`. It is intentionally
separate from historical checkout/runtime paths. All project-owned persistent files
for the new Windows application live under `C:\sing-box`; anything outside that
root must have a concrete external Windows/GitHub reason. The GitHub runner is
transport only and lives separately (target `C:\sing-box-runner`).

Prerequisites:

- an exact accepted durable ReleaseSet SHA-256;
- an exact copy of `install-windows-release.ps1` from the accepted Git
  revision when bootstrapping a machine.

`gh.exe`, Cargo and a mutable repository checkout are not installed-runtime
dependencies. The installer uses the GitHub Releases REST API directly. For a
public repository no GitHub token is required; a private-repository bootstrap
may provide `EDGE_GITHUB_TOKEN` / `-GitHubToken` with read access.

Isolated first-stage activation:

```powershell
& .\install-windows-release.ps1 `
  -ReleaseSetSha256 "<accepted-release-set-sha256>" `
  -InstallRoot "C:\sing-box" `
  -ReleaseOnly
```

`-ReleaseOnly` establishes exact release/activation authority without
importing legacy runtime JSON/configuration and without registering scheduled
automation. The controller may then run honestly as `NOT_CONFIGURED`; normal
local runtime start remains fail-closed until typed runtime state/config is
provisioned.

The installer:

1. addresses one immutable durable GitHub Release:
   `edge-release-<ReleaseSetSha256>`;
2. downloads `release-set.pb`, its SHA-256 sidecar, and the exact Windows
   package;
3. verifies the ReleaseSet digest and every Windows binary identity through
   `edge-release-set.exe verify-windows`;
4. stores the immutable release under
   `C:\sing-box\releases\<ReleaseSetSha256>`;
5. writes canonical protobuf activation state to `C:\sing-box\current.pb`;
6. moves the previous activation pointer to `previous.pb` for LKG rollback;
7. installs only stable bootstrap entrypoints in `C:\sing-box\bin`.

`ensure-edge-controller.ps1` resolves the controller only from `current.pb`
through the independent `edge-diagnostic.exe doctor` verification path. It
refuses a controller path outside the immutable release root. There is no
`current.json`, build-manifest, workflow-run, or mutable-latest authority in
the accepted Windows activation path.

Rollback swaps the verified `current.pb` / `previous.pb` activation state
through the installer `-Rollback` path and re-runs independent exact-file
diagnostics.

## Normal Windows entrypoint

```powershell
& "C:\sing-box\bin\edge-console.exe" status
```

Interactive menu:

```powershell
& "C:\sing-box\bin\edge-console.exe"
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
