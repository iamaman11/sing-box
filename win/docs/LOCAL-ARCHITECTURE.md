# Windows local architecture

Execution order: GitHub Issue #26.
Historical Cloudflare/credential convergence evidence for Stage 3 classification: Issue #169.
Windows implementation/evidence history: Issue #154.
Diagnostics specification: Issue #60.

## Accepted current ownership

```text
accepted Git main + durable ReleaseSet
        |
        v
GitHub self-hosted runner
NetworkService / transport only
        |
        | bounded protobuf request
        v
EdgePlatformPrivilegedDispatch
SYSTEM / allowlisted privileged bridge
        |
        v
C:\sing-box exact activation

Windows SCM
EdgePlatformController
NT SERVICE\EdgePlatformController
        |
        v
edge-controller.exe
Windows-local runtime/config owner
        |
        v
sing-box.exe
```

There is exactly one Windows application startup/runtime owner: SCM
`EdgePlatformController`.

`edge-console.exe` is a local operator/client surface. It must not restore a child-process or
fallback controller owner.

## Application root

All new project-owned Windows application state lives under:

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

Runner transport lives separately:

```text
C:\sing-box-runner
```

Files outside the application root require a concrete external Windows/GitHub reason.

## Trust / ACL model

- immutable release/activation authority: SYSTEM/Admin controlled;
- runner: NetworkService;
- runner write access is bounded to approved exchange/runtime evidence surfaces;
- `state\secrets` is controller-private and excludes runner plaintext access;
- privileged activation crosses only the typed SYSTEM dispatcher;
- no arbitrary remote PowerShell/cmd surface.

## Release model

`current.pb` identifies the exact active immutable ReleaseSet.
`previous.pb` retains the previous accepted release for bounded release rollback once one exists.

Release rollback and credential-generation rollback are separate concerns.

The installed runtime does not depend on:
- mutable repository checkout;
- Cargo;
- `gh.exe`;
- local builds;
- legacy JSON activation pointers.

## Credential model

Do not migrate legacy Windows credentials into the new application.

Accepted target from #169:
- fresh credential generations;
- Windows receives only the client projection;
- Cloudflare Access machine identity is controller-private;
- local typed active/candidate credential state;
- generated sing-box JSON is a consumer artifact;
- active runtime continues when Cloudflare is unavailable;
- failed candidate never replaces active state.

The current repository contains transitional provisioning capability, but #26/#169 determine when it
may be used. Do not revive DPAPI/Vault/SecretRef/current-edge as production authority.

## Local runtime

The controller owns:
- typed Windows policy;
- typed credential/runtime state;
- generation of external sing-box JSON;
- `sing-box check`;
- atomic activation;
- local process/runtime ownership;
- selectors;
- local functional verification;
- bounded rollback/recovery.

Provider lifecycle is intentionally absent.

## Diagnostics

`edge-diagnostic.exe` is independent and read-only.

It should be able to observe:
- release/activation identity;
- SCM service path/identity/state;
- controller/sing-box process identity;
- listeners;
- adapters/routes/DNS;
- TUN/WFP state when later accepted;
- bounded Event Log/application failures;
- functional local/direct/WARP probes;
- active/candidate credential generation metadata without values.

A resident Windows observer is deferred unless live evidence proves one-shot diagnostics
insufficient.

## Legacy boundary

Historical checkout/runtime paths remain no-touch until controlled final cutover.

Do not:
- copy old config/state into `C:\sing-box`;
- reuse old startup owners;
- stop/mutate legacy runtime merely to make new W2 tests pass;
- use legacy secrets as new credential authority.

After cutover, delete legacy paths and compatibility plumbing once no live consumer remains.
