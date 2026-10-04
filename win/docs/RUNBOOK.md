# Operator runbook

This runbook intentionally contains only stable supported boundaries.
For the exact current step always read GitHub Issue #26 first.

## 1. Authority check

Before any mutation:

1. read protected `main`;
2. read #26 current cursor;
3. read only the bounded issue explicitly selected by the latest #26 cursor; #169 is historical evidence and is not the current execution owner;
4. inspect open PR/CI state;
5. resolve the durable ReleaseSet only when release authority is required.

Never operate from a saved SHA in old chat/documentation.

## 2. Production control

The normal production owner is the GitHub-only typed orchestrator.

Current routine owner-gated production commands on `main` are:

```text
/production verify
/production converge
/production diagnose
/production rollback
```

`/production enroll-runtime` is an exceptional bootstrap/re-enrollment operation, not normal steady-state
control. Production rollback is ReleaseSet-bound: the workflow transports the exact currently authorized
application bundle to the production self-hosted runner, and the root-owned local owner refuses rollback
if its active bundle no longer matches that authorization. Rollback never opens routine support access,
SSH forwarding or TCP/gRPC agent control.

Use only commands currently authorized by #26. Historical provider-specific operator surfaces are not
normal production API and must not be revived merely because lower-level typed implementation remains.

Do not use direct Windows Vultr/Cloudflare deployment.

## 3. Windows local status

Installed application root:

```text
C:\sing-box
```

Local console:

```powershell
& "C:\sing-box\bin\edge-console.exe" status
```

The controller is owned by Windows SCM. Do not start a second controller manually merely because a
console/status command fails.

Independent release/runtime diagnostics use the installed exact diagnostic binary and canonical
activation state, for example the accepted doctor path:

```powershell
& "C:\sing-box\bin\edge-diagnostic.exe" doctor "C:\sing-box\current.pb"
```

If the installed stable `bin` layout differs in a later accepted release, use the exact path
reported by that release/diagnostic authority rather than a legacy checkout.

## 4. Windows physical GitHub operations

The repository self-hosted runner is transport only.

`/windows smoke` is an acceptance operation that has already passed for W1; do not replay it for
confidence. Use a Windows command only when #26 explicitly returns the cursor to that slice.

No arbitrary issue-comment PowerShell/exec command exists.

## 5. Secrets

Never paste or publish application/provider secrets into:
- Git;
- Issues;
- Actions logs/artifacts;
- Release assets;
- chat instructions.

Do not copy legacy VLESS/Hysteria/Reality/Line2 credentials into the new runtime.

The canonical architecture defines fresh credential generations and host-local Cloudflare Access delivery. Follow #26 for the active gate; do not improvise another SSH/DPAPI/Vault/GitHub-secret transport.

## 6. VM operations

Normal VM operation is:

```text
GitHub -> production VM self-hosted runner -> root-owned local runtime owner
       -> fixed Docker Compose mutation / Bollard observation
```

The runner is low privilege. It must not have generic root, Docker socket access, provider credentials or application credential plaintext authority.

Use hosted-runner SSH only for bootstrap/migration/break-glass. Do not reopen routine /32 support access or TCP/gRPC local forwarding for ordinary status, verify, diagnostics or cleanup. Production release rollback is the existing owner-gated `/production rollback` operation and must stay ReleaseSet-bound on the same persistent local-runner owner boundary; do not revive the internal legacy lease/remote path.

## 7. Diagnosis before repair

Default order:

```text
observe
 -> diagnose
 -> exact plan
 -> one bounded mutation
 -> re-observe
 -> functional verify
```

An unknown mutation outcome is never solved by replaying the same mutation blindly.

Diagnostics are read-only. Repair/converge is a separate explicit operation.

## 8. Release update

Normal release update:

```text
PR exact-head CI
 -> candidate acceptance
 -> protected merge
 -> promotion without rebuild
 -> durable ReleaseSet
 -> converge
 -> verify
```

No local Rust/OCI build occurs on production Windows/VM.

Keep the previous accepted release long enough for bounded rollback.

## 9. Credential rotation

Credential rotation is not part of every release.

The steady-state target is defined by `edge-platform/ARCHITECTURE.md`, not by #169. Rotation is
class-scoped (`tunnel-auth`, `reality-identity`, `line2-proxy-auth`, with host identities separate),
publishes one new candidate into the inactive fixed A/B slot, preserves unrelated credential-class
generations, verifies both least-privilege projections and host-local runtime behavior, then promotes
through the typed active/candidate/previous state transition with bounded rollback/grace.

The public credential workflow supports:
```text
/credentials verify
/credentials rotate tunnel-auth
/credentials rotate reality-identity
/credentials rotate line2-proxy-auth
/credentials host-bootstrap-converge
```

Application rotation first proves the paired active cursor, recovers only an observed uncommitted
candidate, retires an older previous buffer, and publishes only the slot opposite active. Each local
owner then fetches the exact generation during staging, materializes the class-scoped delta inside its
protected store and validates it; both hosts are staged before the first runtime activation. Functional
verification precedes promotion, and promotion is re-observed before any bounded retry. A failed
uncommitted candidate is compensated back to the observed active generation. Do not reuse Stage-2
`fresh-v2-*` proof/cutover commands.

Windows/VM Access host identities remain a separate lifecycle. They are canonical permanent
(`forever`) create-once identities. `host-bootstrap-converge` is the accepted explicit
bootstrap/recovery boundary and never implicitly rotates an installed host identity. Do not add a
second steady-state host-token rotation transport or custom X25519/HKDF/AEAD handoff.

## 10. Stage 4B managed Windows TUN cutover

Stage 4B is split into code proof and one physical cutover. Do not combine the first TUN mutation with
unfinished renderer/diagnostic/reboot work.

### Code-proof gate — no live TUN mutation

Before the external Windows sing-box is touched, protected code must already prove:

- one typed `PROXY_ONLY` / `MANAGED_TUN` datapath mode in existing protobuf desired state;
- one canonical renderer used by initial materialization and credential apply/rollback;
- Windows candidate identity changes when canonical `infra/production/production.textproto` changes,
  while the Windows binary still embeds that desired-state file;
- one bounded local Windows ReleaseSet rollback targets only exact verified `previous.pb`, needs no
  Git/provider/network access, and restores both activation authority and previous-mode runtime/config;
- exact pinned sing-box `check` of the managed-TUN candidate in CI;
- native read-only adapter/route/DNS/TUN diagnostics in the existing diagnostic binary;
- typed `managed / conflicting external / absent` sing-box process observation before any startup
  convergence or cutover mutation;
- SCM `EdgePlatformController` startup convergence so reboot can restore the managed runtime without a
  Scheduled Task, watchdog or second controller;
- the existing Windows workflow/router contains only one fixed owner-authorized cutover path rather than
  a new generic execution namespace;
- exact-head CI + no-rebuild promotion PASS.

The old PowerShell DNS reset is recovery-only legacy behavior. Do not extend it into the new datapath.
Managed-TUN DNS belongs to sing-box; if failed-runtime cleanup later proves an explicit reset is still
needed, keep the mutation inside the existing local-runtime owner and implement it with an exact native
Windows boundary.

### Physical cutover gate

Before any stop/start mutation:

1. resolve the exact accepted ReleaseSet;
2. run read-only managed diagnostics;
3. verify the installed managed side has an exact locally verified `PROXY_ONLY` previous activation and
   that the bounded local ReleaseSet rollback has already passed without touching the external TUN;
4. identify the currently working external sing-box process/startup owner without reading or copying its
   secrets;
5. prove a bounded restore procedure for that exact external owner;
6. STOP if either rollback path is unproven, if the external owner is ambiguous, or if managed-TUN
   authority is not exact.

The `PROXY_ONLY` -> `MANAGED_TUN` desired-state flip must first be committed through the normal
protected Git path, pass exact-head CI and no-rebuild promotion, and produce an exact accepted ReleaseSet.
Do not mutate Windows from an unaccepted mode-flip revision.

Then one authorized cutover using that exact accepted `MANAGED_TUN` ReleaseSet may stop only the
pre-observed external owner and start the managed TUN. Acceptance must prove routes,
endpoint/control-plane bypass, loop prevention, DNS/no-leak behavior,
DIRECT and WARP egress, managed restart, failed-transition rollback, SCM restart and a real Windows
reboot/recovery cycle. A failed acceptance restores connectivity through the bounded pre-observed
cutover rollback path; it must not improvise a new legacy owner.

Only after all checks PASS may the managed runtime be declared the sole Windows datapath owner. Legacy
Windows startup/config/secret glue is deleted later in Stage 4C from fresh last-consumer proof.

## 11. Recovery

Target recovery must not need the legacy checkout.

VM recovery:
```text
Git desired state + exact ReleaseSet + provider APIs + credential plane
```

Windows recovery:
```text
exact ReleaseSet + one-time machine enrollment + active credential generation
```

Generated env/JSON may be recreated. Loss of Cloudflare availability must not stop an already
healthy runtime.

## 12. Stop conditions

Stop before mutation when:
- ownership is ambiguous;
- current main/ReleaseSet authority cannot be proven;
- secret boundary would be widened;
- a mutation outcome is uncertain and has not been re-observed;
- the requested operation would touch legacy runtime before its cutover gate;
- the operation is not authorized by the current #26 cursor.
