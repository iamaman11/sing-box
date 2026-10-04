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

Accepted target from `edge-platform/ARCHITECTURE.md` (#169 is retained only as historical evidence):
- fresh credential generations;
- Windows receives only the client projection;
- Cloudflare Access machine identity is controller-private;
- local typed active/candidate credential state;
- generated sing-box JSON is a consumer artifact;
- active runtime continues when Cloudflare is unavailable;
- failed candidate never replaces active state.

The current repository contains transitional provisioning capability, but only #26 determines when it
may be used; #169 does not authorize current execution. Do not revive DPAPI/Vault/SecretRef/current-edge
as production authority.

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

### Stage 4B datapath convergence

The accepted Stage-2 runtime is still proxy-only. Stage 4B changes datapath ownership, not the owner
process: SCM `EdgePlatformController` remains the only Windows runtime owner.

The cutover must be represented by one typed datapath mode in the existing protobuf desired-state
boundary. Generated `runtime\\sing-box.json` is never allowed to choose the mode, and an environment
variable must not become a hidden TUN switch. Credential apply/rollback and initial materialization must
all call the same canonical renderer so credential rotation cannot silently change datapath ownership.

The managed-TUN target uses the pinned sing-box Windows implementation for TUN routing and DNS. The
project supplies exact typed policy, endpoint exclusions and loop-prevention rules; it does not add a
second DNS manager, route daemon, WFP mutator or startup scheduler.

The existing guarded restart sequence remains the activation primitive:

```text
render exact candidate
 -> sing-box check
 -> preserve managed last-known-good
 -> activate
 -> observe startup
 -> functional verify
 -> restore managed last-known-good on failed transition
```

SCM startup must additionally converge the installed managed runtime after reboot. If an external or
unexpected sing-box is observed, startup is fail-closed and does not stop or adopt it.

## Diagnostics

`edge-diagnostic.exe` is independent and read-only.

Today it proves release/activation identity and exact controller process identity. Stage 4B must extend
this same binary before live cutover so one-shot native diagnostics can also observe:
- SCM service path/identity/state;
- controller and managed sing-box process identity;
- managed TUN adapter/index/address;
- relevant IPv4/IPv6 routes and endpoint exclusions;
- per-interface DNS state;
- bounded runtime/Event Log failure evidence where useful;
- functional local/DIRECT/WARP results;
- active/candidate credential generation metadata without values.

Prefer native Windows APIs (IP Helper/SCM and equivalent typed Win32 boundaries). Do not add WMI or
PowerShell text parsing merely to satisfy acceptance. Raw WFP enumeration is required only if route/DNS
observation plus a bounded functional DNS-leak test cannot prove the `strict_route` contract.

A resident Windows observer remains deferred unless live evidence proves one-shot diagnostics
insufficient.

## Legacy boundary

Historical checkout/runtime paths remain no-touch until controlled final cutover.

Before the first Stage-4B mutation, read-only diagnostics must identify the exact currently running
external sing-box/startup owner and a bounded restore procedure. That evidence exists only to make the
cutover reversible; the project must not import its config, secrets or startup model into `C:\\sing-box`.

Do not:
- copy old config/state into `C:\sing-box`;
- reuse old startup owners;
- stop/mutate legacy runtime merely to make new W2 tests pass;
- use legacy secrets as new credential authority.

After cutover, delete legacy paths and compatibility plumbing once no live consumer remains.
