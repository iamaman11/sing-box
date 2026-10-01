# Operator runbook

This runbook intentionally contains only stable supported boundaries.
For the exact current step always read GitHub Issue #26 first.

## 1. Authority check

Before any mutation:

1. read protected `main`;
2. read #26 current cursor;
3. read the bounded issue selected by #26 (currently #169 for Cloudflare/credential convergence);
4. inspect open PR/CI state;
5. resolve the durable ReleaseSet only when release authority is required.

Never operate from a saved SHA in old chat/documentation.

## 2. Production control

The normal production owner is the GitHub-only typed orchestrator.

Accepted owner-gated production commands include:

```text
/production verify
/production converge
/production rollback
```

Use only commands currently authorized by #26.

Separate historical `/dns`, `/mesh` and `/zero-trust` surfaces are migration debt and are
removed only through #26 Stage 3 after exact consumer/replacement proof.

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

Use hosted-runner SSH only for bootstrap/migration/break-glass. Do not reopen routine /32 support access or TCP/gRPC local forwarding for ordinary status, verify, bootstrap, diagnostics, rollback or cleanup once the local runner path owns that operation.

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

The target flow from #169 is:

```text
write candidate into inactive A/B slots
 -> verify isolated Workers/Access
 -> Git declares candidate generation
 -> server accepts active + candidate
 -> Windows proves candidate direct/WARP traffic
 -> promote candidate to active
 -> keep previous generation for bounded rollback/grace
```

This flow is not authorized for real values until #26 reaches that checkpoint.

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
