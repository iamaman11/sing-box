# Local agent — read-only Cloudflare Access diagnostic

Task: establish the exact reason the current VM Worker rejected `POST /v1/host/authorize` with `HOST_WORKER_ACCESS_JWT_REJECTED` (HTTP 403). Do **not** repeat the mutation, invoke `/host apply`, create VMs, rotate secrets, or publish private values.

1. Read protected Git main/release identity, active Worker version, Access application and policy identifiers. Verify the actual Worker name rather than guessing.
2. Compare safely: `EDGE_HOST_ACCESS_ISSUER`, `EDGE_HOST_ACCESS_AUD`, Cloudflare Access application AUD/issuer and JWKS endpoint; report only match/mismatch.
3. Determine which layer returned 403 (Cloudflare Access edge or Worker handler). Check whether the Worker received `Cf-Access-Jwt-Assertion`; report PRESENT/MISSING, never bytes.
4. Classify validation as MISSING, MALFORMED, EXPIRED, NOT_YET_VALID, ISSUER_MISMATCH, AUDIENCE_MISMATCH, SIGNATURE_REJECTED, JWKS_UNAVAILABLE, CONFIG_UNPROVEN or PASS.
5. Verify service-token configuration and GitHub environment secrets **by existence and intended scope only**, no export, mutation or guesses.

Typed report:
```
source_git_sha=
worker_active_version=
access_app_id=
source_run_id=
edge_access=PASS|REJECTED|UNKNOWN
jwt_delivery=PRESENT|MISSING|UNKNOWN
jwt_validation=PASS|MISSING|MALFORMED|EXPIRED|NOT_YET_VALID|ISSUER_MISMATCH|AUDIENCE_MISMATCH|SIGNATURE_REJECTED|JWKS_UNAVAILABLE|CONFIG_UNPROVEN|UNKNOWN
root_cause=evidence_or_UNPROVEN
proposed_minimal_fix=
mutations=0
secrets_disclosed=0
```
