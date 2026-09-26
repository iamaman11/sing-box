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

Release activation has one mode only:

```powershell
& .\install-windows-release.ps1 `
  -AcceptedRevision "<protected-main-merge-sha>" `
  -ReleaseSetSha256 "<accepted-release-set-sha256>" `
  -InstallRoot "C:\sing-box"
```

The installer establishes exact release/activation authority only. It never
imports legacy runtime JSON, copies a prebuilt `sing-box.json`, registers
controller/reconcile/shutdown tasks, or owns runtime policy. The controller may
therefore run honestly as `NOT_CONFIGURED`; runtime state and generated config
arrive later through typed application-owned boundaries.

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

Installed startup resolves the controller only from `current.pb` through
`edge-console.exe`, while `edge-diagnostic.exe doctor` independently verifies
exact release files. There is no `current.json`, build-manifest, workflow-run,
mutable-latest authority, or repository startup wrapper in the accepted Windows
path.

`previous.pb` is retained as LKG release evidence. Rollback will be exposed only
through the typed privileged boundary; the installer itself has no second
runtime/startup or rollback mode.

## Physical Windows trust bootstrap

The one-time elevated bootstrap establishes **both** the application trust anchor and
the low-privilege GitHub transport:

```text
C:\sing-box
  immutable releases/current.pb/bin/bootstrap   SYSTEM/Admin write only
  exchange\requests                             runner write
  exchange\results                              runner read
  runtime/logs/state                             bounded W1 runner write
  state\secrets                                  SYSTEM/Admin only; runner has no ACL
  EdgePlatformPrivilegedDispatch                 Task Scheduler / SYSTEM

C:\sing-box-runner
  official GitHub Actions Runner / NetworkService
```

The bootstrap requires the exact protected-main revision and exact durable
ReleaseSet digest. It activates that ReleaseSet first, stores a protected copy
of the accepted installer, creates the SYSTEM privileged dispatcher task, applies
ACLs, and only then registers the repository-scoped runner.

The runner never receives administrator authority. Release updates are requested
as canonical protobuf through `privileged-activate`; the SYSTEM dispatcher
accepts only an exact 40-character accepted revision plus exact 64-character
ReleaseSet digest. The protected installer independently verifies that:
- the requested revision is the current protected `main`;
- the durable release tag resolves directly to that revision;
- the ReleaseSet `source_revision` is the accepted PR-head parent of that merge commit;
- that candidate parent has the same Git tree as the accepted merge commit;
- ReleaseSet and Windows artifact hashes match exact bytes.

The dispatcher then activates the release and retargets its scheduled task to
the new immutable release console. The bootstrap also reserves
`C:\sing-box\state\secrets` with inheritance disabled and no NetworkService
ACE, so later W2 credentials can remain local without changing the trust anchor.
This means normal future release updates and later privileged application
operations do not require another local administrator session.

The GitHub runner lives outside the application root. It installs no Git/Rust/
Java/provider toolchain and uses GitHub's native runner self-update mechanism.
The only interactive secret during the one-time bootstrap is GitHub's short-lived
runner registration token; it is read as a SecureString and not persisted.

After trust bootstrap, physical work is driven through owner-only typed commands.
The first `/windows smoke` remains deliberately non-TUN and does not modify DNS,
routes, system proxy, Wintun, firewall/WFP, or the legacy Windows runtime.

## Normal Windows entrypoint

```powershell
& "C:\sing-box\bin\edge-console.exe" status
```

Interactive menu:

```powershell
& "C:\sing-box\bin\edge-console.exe"
```

The optional repository helper `edge-platform/scripts/start-edge-console.cmd` only opens
the installed console UI; it does not own controller lifecycle or release authority.

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
