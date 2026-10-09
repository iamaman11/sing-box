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

The cutover is represented by one typed datapath mode in the Git-owned protobuf
`ProductionDesiredState`. The mode is embedded into the exact accepted Windows binary and is **not**
copied into `WindowsRuntimeState`, ReleaseSet Windows runtime fields, activation state, a local marker or
an environment variable. `WindowsRuntimeState` remains only the endpoint/credential runtime projection.
Generated `runtime\\sing-box.json` never chooses the mode. Credential apply/rollback, initial
materialization and SCM reboot convergence all call the same canonical renderer, so datapath ownership
cannot drift between lifecycle paths.

Current Windows binaries embed canonical production desired-state bytes at build time. Therefore the
Windows candidate input digest must include `infra/production/production.textproto` for as long as that
compile-time dependency exists; otherwise a mode flip can incorrectly reuse a binary compiled with the
previous mode.

Stage 4B adds one narrow local rollback through the existing privileged bridge: exact verified
`previous.pb` only, no arbitrary digest and no Git/provider/network dependency. The rollback restores the
previous exact activation/binary; the previous SCM controller then re-renders the managed config from the
existing typed runtime projection using that binary's own embedded desired state before starting sing-box.
No local datapath-mode copy is required.

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

SCM startup converges the installed managed runtime after reboot. Process ownership is exact-config
scoped: ordinary mutation can stop/restart only the exact managed process and never the external one.
In PROXY_ONLY mode the managed mixed-proxy runtime may coexist with an external sing-box because it owns
no TUN/routes/DNS; duplicate managed owners remain fail-closed. In MANAGED_TUN mode any external sing-box
remains fail-closed until the later explicit cutover authorizes that exact observed owner.

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

## Stage 4B.2-C — DNS coexistence physical acceptance protocol (NOT authorized to run)

This section is the **execution gate**, not a new runtime or control interface. The sole
canonical execution cursor remains issue #26. The existing source-accepted `ManagedTun`
renderer still emits `dns_mode=hijack` and `strict_route=true`. PR #309 proved that
changing only `dns_mode` to `native` yields an offline config accepted by the exact
locked sing-box v1.14.2 binary. **No physical DNS policy or lifecycle change is accepted.**

### Security objective and boundaries

1. Windows sing-box owns **only** its managed TUN `sing-box-tun`, DNS `172.19.0.2`,
   encrypted managed DNS outbound (`1.1.1.1:853` DoT via the chosen sing-box selector),
   and its existing endpoint/route exclusions. It never edits the foreign
   `CloudflareWARP` DNS, Cloudflare One Client, WARP service, or Ethernet DNS.
2. Cloudflare One Client operates in its observed `TunnelOnly` mode with Mesh
   `100.96.0.0/12` via its own adapter. It owns its foreign service, routes
   and adapter writes; its recorded DNS list `172.19.0.2,192.168.100.1` is
   **not yet independent of the sing-box TUN**. That dependency must not be
   hidden by a successful normal-case Mesh route.
3. Ethernet gets `192.168.100.1` as DNS/gateway **from DHCP**. Native Ethernet
   DNS to `192.168.100.1:53` may be permitted for explicitly approved
   *local/bootstrap resolver* queries; public lookups sent in plaintext to
   Ethernet or a foreign adapter **without explicit permission are DNS leaks**.
   An intentional one-off `Resolve-DnsName -Server 192.168.100.1` probe is
   an authorized test flow, not evidence of safe normal system resolver behavior.
4. Host-level public DNS must continue to use the accepted managed DNS path,
   not silently spread across all Windows interfaces. Windows multihomed DNS
   can query multiple interfaces. `native` removes the *specific* port-53 WFP
   block from the pinned sing-tun `hijack` implementation; **it does not
   implement per-domain DNS access controls or prove absence of leaks**.
   If OS DNS selection cannot enforce this policy, reject this candidate
   rather than add a service, firewall exception, DNS-reset, scheduler,
   alternative controller or ad-hoc WFP priority rules.
5. IPv6 needs an explicit observation and policy, not an assumption that
   current IPv4-only TUN prevents foreign IPv6 DNS or packet egress.
   Keep any unknown DNS writer, IPv6 path or resolver policy **UNPROVEN**.

### Before physical authorization (strict fail-closed preflight)

- Record exact protected `main`, accepted immutable ReleaseSet, current/previous
  activation identity, pinned sing-box SHA, SCM/controller/sing-box identity, and
  the runtime's *actual* TUN DNS mode. A release published in GitHub is **not**
  evidence that the Windows host installed it.
- Confirm local administrator can recover this specific Windows machine from
  its physical console **with no internet** (user has answered YES); prepare
  and review the offline exact *currently working* `hijack` recovery authority
  and required files. Merely having `previous.pb` does not prove a safe return:
  it may itself be `ManagedTun`. No fallback installation or stop may occur
  during this preflight.
- Read-only baseline: `Get-DnsClientServerAddress`, effective NRPT,
  interface metrics, IPv4/IPv6 best routes, exact foreign adapter DNS,
  Mesh interface ownership, current GitHub broker/token **resolved** routes,
  WFP `sing-tun` sublayer and exact process ID, controller/runner state.
  Redact usernames, tokens, private domains, profile IDs and credentials.
  Local agent's prior WFP filter IDs are ephemeral; never hardcode them.
- Check that the bounded verification method can **observe destination and
  egress interface** for plaintext UDP/TCP 53, native IPv6 resolver traffic,
  encrypted managed DoT and the GitHub control transport. `Resolve-DnsName`,
  `Find-NetRoute`, a successful `Test-NetConnection`, and the absence of a
  port-53 listener **alone cannot prove no DNS leaks**. Before the canary,
  agree on an independently observable negative test (e.g. bounded, redacted
  router-side DNS request records or separately authorized limited packet
  observation). If evidence is unavailable, classify `NO_LEAK=UNPROVEN`
  and **do not activate the candidate**.
- Explicitly name permitted Ethernet DNS scopes (only local/bootstrap), expected
  managed DoT/public scopes, expected Cloudflare Mesh services and the
  control-channel target domains; verify both IPv4 and IPv6 behavior.
  Private resolver/data exposure must not appear in GitHub Action logs.
- Require a **separate user authorization** for a one-time, supervised,
  time-bounded test window after presenting recovery steps. Prior YES to
  physical-console access is **not** approval to stop or replace the TUN.

### Supervised candidate sequence (PROPOSAL, not a command)

- Candidate must be supplied by **one exact accepted GitHub release** through
  the existing typed controller/SCM owner and exact-head CI. Do not run a
  patched local JSON, sidecar sing-box, new workflow, second TUN or direct
  service mutation. Preserve the exact working `hijack` release and validate
  deterministic recovery before touching the active TUN. Do not use the
  currently blocked `/windows stop` or `/windows rollback` as a workaround.
- Once all prior gates are satisfied and explicitly authorized, a **single
  bounded** activation performs before/after identity and WFP snapshots,
  then one functional matrix: managed DoT/public resolution, deliberately
  scoped Ethernet DNS via the DHCP resolver, negative DNS egress/leak
  observation, Cloudflare Mesh data and DNS, noncapturing VM endpoints,
  GitHub broker/token route and actual control-plane continuity. Observe
  network behavior, not only config syntax or service `Running`.
- Abort on **any** forbidden public plaintext DNS on Ethernet/CloudflareWARP,
  unsupported IPv6 leak, route or DNS ownership conflict, loss of foreign
  Mesh functionality, unexpected external sing-box owner, stale release
  provenance, unavailable control path, missing negative-test evidence or
  an inability to restore the exact working `hijack` state. Record UNKNOWN
  as a failed acceptance gate, not PASS.
- After the working-TUN canary, **separate** failure-recovery acceptance is
  needed for termination/SCM startup failure: actual dynamic WFP filter
  disappearance, Ethernet DHCP DNS/server usability, no stale route/DNS
  selection, CloudflareWARP independence and restored GitHub runner/broker
  transport *without* sing-box. Dynamic WFP session source proof does not
  establish these host properties. A controlled failure experiment requires
  its own explicit physical approval and return procedure.

### Evidence and stop/go decision

| Gate | PASS requires | Current status |
| --- | --- | --- |
| Offline native candidate | Exact pinned Windows `sing-box check`; only `dns_mode` differs | PASS, PR #309 |
| Native DNS negative leak policy | Observable scoped plaintext DNS/IPv6 negative tests, positive managed DoT | UNPROVEN |
| Cloudflare independence | Foreign Mesh/DNS works with policy and separately without TUN | UNPROVEN |
| Independent GitHub control | Management DNS, transport and recovery proven without sing-box | UNPROVEN |
| Recoverability | Exact known-good restore and user-supervised failed-start recovery tested | UNPROVEN |

**GO for physical activation: NO.** The implementation remains `hijack +
strict_route=true`, and Stage 4B.2-C stays OPEN. Release publication,
console access, source-level dynamic WFP cleanup or offline `sing-box check`
must never be promoted into a claim of physical safe teardown/rollback.

Source contracts: [sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/),
[Cloudflare One with legacy VPNs](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/vpn/),
[Windows WFP dynamic objects](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management).

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


### PROXY_ONLY ChatGPT/operator lifecycle gate

Before Stage 4B.2, the real Windows host must prove the complete managed proxy lifecycle through the one
GitHub control boundary: read-only diagnose, exact accepted converge/install, live DIRECT+WARP verification,
same-release repair from durable assets into the alternate immutable release slot, exact `previous.pb`
rollback, reconverge, and final diagnose. Repair uses only two bounded same-ReleaseSet slots
(`releases/<sha>` and `releases/<sha>.repair`); it never overwrites the active executable directory and
must preserve `previous.pb` byte-for-byte.

The external sing-box is observation-only during this gate. Its process identity must remain unchanged
before/after every operation. TUN/routes/DNS/system-proxy mutation is forbidden.
