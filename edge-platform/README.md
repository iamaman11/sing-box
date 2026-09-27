# edge-platform

Rust control-plane workspace for `iamaman11/sing-box`.

For execution order read GitHub Issue #26 first. For stable ownership/invariants read
`ARCHITECTURE.md`.

## Runtime owners

```text
edge-orchestrator
  GitHub-only production/provider composition owner
  -> Vultr
  -> Cloudflare
  -> strict SSH local-forward -> edge-agent

edge-agent
  loopback-only bounded VM executor/observer
  -> Docker Compose / Docker Engine / host observations

EdgePlatformController (edge-controller.exe)
  Windows SCM service
  -> Windows-local credential/config/runtime owner
  -> sing-box.exe

edge-console.exe
  local Windows operator/client surface

edge-diagnostic.exe
  independent read-only Windows diagnostics
```

The installed Windows controller is not a Vultr/Cloudflare orchestrator.

## Canonical production authority

- desired state: `infra/production/production.textproto`;
- exact release identity: immutable `ReleaseSet.pb` / durable release publication;
- provider reality: fresh Vultr/Cloudflare observations;
- Windows activation: `C:\sing-box\current.pb` plus exact immutable release directory;
- VM application activation: exact accepted application release/bundle + immutable image digests.

GitHub Actions is an authorization/execution transport. It does not own lifecycle semantics.

## Windows trust/runtime boundary

Canonical application root:

```text
C:\sing-box
  current.pb
  previous.pb
  releases\<release-set-sha256>\
  bin\
  state\
    secrets\
  runtime\
  logs\
  exchange\
```

Transport root is separate:

```text
C:\sing-box-runner
```

Accepted ownership:
- SCM service: `EdgePlatformController`;
- service identity: `NT SERVICE\EdgePlatformController`;
- GitHub runner: NetworkService transport only;
- SYSTEM privileged bridge: `EdgePlatformPrivilegedDispatch`;
- runner has no plaintext/decrypted application-secret authority.

The console is not a fallback startup owner. Do not restore child-process controller autostart.

## Credential transition

Current accepted direction is tracked in Issue #169.

Do not import legacy Windows credentials into the new application.

Target:
- fresh credential generations;
- isolated VM/Windows Cloudflare credential projections;
- fixed A/B encrypted Worker slots for bounded rollback;
- typed active/candidate local credential state;
- generated sing-box JSON / runtime env as consumer artifacts only.

The existing `provision-runtime-state` command is transitional capability, not the final normal
production credential lifecycle while #169 is open.

## VM transport

Canonical production reaches `edge-agent` through strict OpenSSH local forwarding to a loopback
listener. No public agent management port is required.

The accepted simplification target is to remove historical custom Agent mTLS/`edge-trust` after
all live consumers are proven gone.

## Build/release model

```text
exact source
 -> exact-head CI
 -> build once
 -> candidate acceptance
 -> protected merge
 -> promotion of exact accepted bytes (no rebuild)
 -> durable immutable ReleaseSet
```

Production never builds Rust or project OCI images on the target VM/Windows machine.

## Full lifecycle target

Typed owners must eventually cover:

- bootstrap/enrollment;
- provision;
- deploy;
- converge;
- verify;
- diagnose;
- upgrade;
- release rollback;
- credential rotation/rollback;
- reboot/recovery;
- cleanup/destroy;
- zero-leak verification.

Normal operation must not require manual secret copying or a legacy checkout.

## First-party serialization

- `.textproto` — human-authored Git desired state;
- `.pb` — canonical machine/durable state;
- JSON — only where an external consumer/protocol requires it.

Existing internal JSON is frozen migration debt and may only shrink.

## Safety

Never reintroduce:
- Windows provider mutation authority;
- arbitrary remote PowerShell/SSH production surfaces;
- TOFU SSH success paths;
- mutable release authority;
- plaintext credentials in Git/Issues/Actions/Release assets;
- a second desired-state store;
- a second Windows startup owner.
