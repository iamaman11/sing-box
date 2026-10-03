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

Use hosted-runner SSH only for bootstrap/migration/break-glass. Do not reopen routine /32 support access or TCP/gRPC local forwarding for ordinary status, verify, diagnostics or cleanup. Production release rollback is not yet a supported public operation on current `main`; its replacement must use the same persistent local-runner owner boundary rather than the internal legacy lease/remote path.

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

Application rotation first proves paired active cursors, explicitly retires an older previous buffer
when beginning the next requested rotation, publishes only the slot opposite active, performs read-only
data-plane admission on both hosts, stages and functionally verifies both projections, and promotes with
re-observation before any bounded retry. A failed uncommitted candidate is compensated back to the
observed active generation. Do not reuse Stage-2 `fresh-v2-*` proof/cutover commands.

Windows/VM Access host identities remain a separate lifecycle. `host-bootstrap-converge` is create-once
bootstrap/recovery and never implicitly rotates an installed host identity; explicit steady-state
host-identity rotation remains a Stage-3 boundary until its replacement contract is accepted.

## 10. Recovery

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

## 11. Stop conditions

Stop before mutation when:
- ownership is ambiguous;
- current main/ReleaseSet authority cannot be proven;
- secret boundary would be widened;
- a mutation outcome is uncertain and has not been re-observed;
- the requested operation would touch legacy runtime before its cutover gate;
- the operation is not authorized by the current #26 cursor.
