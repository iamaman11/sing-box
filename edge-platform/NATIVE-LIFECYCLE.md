# sing-box: one native lifecycle — hard cut 2026-10-23

Canonical desired/code is protected GitHub main. This source change is **not** proof of a new VM installation.

`/host status|apply|recover → immutable Git ReleaseSet → typed Rust planner → Worker-signed HostIntent → Actions delivery → native root Agent or Windows SYSTEM Controller → durable journal → readback → signed receipt`.

Six historical reusable workflows were removed. There is no legacy mutation ingress. GitHub runner is a transport, not root.

SSH exists only for Vultr initial CREATE/bootstrap and completion of initial receipt enrollment after protected Git merge (`host_resume_receipt`). The everyday hosted SSH `host_refresh_trust` and SSH receipt-resume update are removed. VM runner has only `sudo edge-agent local host-refresh` (zero arguments): existing root Agent independently selects the latest protected Git main release, checks its published assets and immutable identities, updates protected trust and its exact binary under one native kernel lock. No arbitrary shell, path, desired, credential or Docker rights are granted. Signing of application effects remains on the separate Worker HostIntent channel.

Fresh host `application-acceptance-3` replaces the deleted `application-acceptance-2`. The **existing shared VM Worker** retains its public Git-accepted signer and exact nonsecret first-use CredentialRef (generation + SHA-256), both validated by an authenticated Worker GET before provider CREATE. No secret or old VM native receipt identity is copied; a new root Agent generates its own native receipt key. The previous VM's historical provider state is not adopted as authority.

Only one security check **per actual trust boundary**: exact Git desired/release, Worker caller Access JWT and scoped signature, local native machine/owner/lock and durable BEGIN, physical readback plus authenticated receipt. UNKNOWN_NO_REPLAY is never retried. For external egress check real DIRECT/WARP + TLS/auth. No reserve tokens, A/B admissions, generic SSH mutation, additional scheduler or service.

Acceptance for freshly created VM: 3/3 containers, Line1 4/4, Line2 6/6, exact running artifact, signed receipt, independent network proof. Keep Windows STOPPED/PROXY_ONLY and do not touch independent Cloudflare One/Mesh.

Rust ingress is closed by typed Clap variants: no historical Vultr/Cloudflare mutator subcommands and no VM local bootstrap/credential direct mutation commands. Native `host-refresh` and signed `host-apply` share the existing protected Root Agent; `operation` is a closed Rust enum mapped to GitHub's required scalar output. This code change is not a physical VM readiness or Windows-TUN acceptance proof.

The dead pre-native direct mutation routines (`initial_commit_vm_credential`, `initial_apply_vm_credential`, `transition_vm_credential`, `run_bootstrap`, `converge_mesh_runtime`, `cleanup_mesh_runtime`, and their internal helpers) are removed from the VM executable source. Read-only runtime probes are isolated in `vm_runtime_observation.rs`. The accepted Worker source proof and signed root `host_native` owner remain unchanged. No additional installation command is authorized.
