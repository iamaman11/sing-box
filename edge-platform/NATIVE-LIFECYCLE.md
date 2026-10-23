# sing-box: one native lifecycle — hard cut 2026-10-23

Canonical desired/code is protected GitHub main. This source change is **not** proof of a new VM installation.

`/host status|apply|recover → immutable Git ReleaseSet → typed Rust planner → Worker-signed HostIntent → Actions delivery → native root Agent or Windows SYSTEM Controller → durable journal → readback → signed receipt`.

Six historical reusable workflows were removed. There is no legacy mutation ingress. GitHub runner is a transport, not root.

SSH exists only for Vultr initial CREATE/bootstrap and completion of initial receipt enrollment after protected Git merge (`host_resume_receipt`). The everyday hosted SSH `host_refresh_trust` is removed. Stale root trust must fail closed until a **native signed** trust-upgrade contract is implemented and accepted. Never invent a second SSH recovery path.

Fresh host `application-acceptance-3` replaces the deleted `application-acceptance-2`: no old receipt key, first-use credential generation or worker signer identity is copied. The previous host's audit evidence remains in historical Git, not as current admission authority.

Only one security check **per actual trust boundary**: exact Git desired/release, Worker caller Access JWT and scoped signature, local native machine/owner/lock and durable BEGIN, physical readback plus authenticated receipt. UNKNOWN_NO_REPLAY is never retried. For external egress check real DIRECT/WARP + TLS/auth. No reserve tokens, A/B admissions, generic SSH mutation, additional scheduler or service.

Acceptance for freshly created VM: 3/3 containers, Line1 4/4, Line2 6/6, exact running artifact, signed receipt, independent network proof. Keep Windows STOPPED/PROXY_ONLY and do not touch independent Cloudflare One/Mesh.
