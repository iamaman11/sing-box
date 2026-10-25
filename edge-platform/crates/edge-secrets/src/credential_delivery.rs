use crate::credential_store::write_atomic_private;
use edge_shared_types::{
    CREDENTIAL_DUMMY_PROBE_GENERATION_A, CREDENTIAL_DUMMY_PROBE_GENERATION_B,
    CredentialDeliveryBundle, CredentialDeliverySlot, CredentialProjectionKind,
    canonical_production_desired_state, decode_credential_delivery_bundle,
};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, StatusCode, redirect::Policy};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub const ACCESS_IDENTITY_FILE_NAME: &str = "credential-access-v1.env";
const MAX_ACCESS_IDENTITY_BYTES: u64 = 16 * 1024;
const MAX_CREDENTIAL_BUNDLE_BYTES: u64 = 1024 * 1024;
const CREDENTIAL_WORKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CREDENTIAL_WORKER_TRANSPORT_ATTEMPTS: usize = 3;
const CREDENTIAL_WORKER_TRANSPORT_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Clone, PartialEq, Eq)]
pub struct AccessServiceIdentity {
    client_id: String,
    client_secret: String,
}

impl std::fmt::Debug for AccessServiceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessServiceIdentity")
            .field("client_id", &"<redacted>")
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

impl AccessServiceIdentity {
    pub fn parse_env(raw: &str) -> Result<Self, String> {
        let mut client_id = None;
        let mut client_secret = None;
        for line in raw.lines() {
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| "credential Access identity contains a malformed line".to_owned())?;
            if value.is_empty() || value.trim() != value || value.chars().any(|ch| ch.is_control())
            {
                return Err(format!("{key} must be a non-empty canonical value"));
            }
            match key {
                "CF_ACCESS_CLIENT_ID" if client_id.is_none() => client_id = Some(value.to_owned()),
                "CF_ACCESS_CLIENT_SECRET" if client_secret.is_none() => {
                    client_secret = Some(value.to_owned())
                }
                "CF_ACCESS_CLIENT_ID" | "CF_ACCESS_CLIENT_SECRET" => {
                    return Err(format!("credential Access identity repeats {key}"));
                }
                _ => {
                    return Err("credential Access identity contains an unsupported key".to_owned());
                }
            }
        }
        Ok(Self {
            client_id: client_id
                .ok_or_else(|| "credential Access identity is missing client id".to_owned())?,
            client_secret: client_secret
                .ok_or_else(|| "credential Access identity is missing client secret".to_owned())?,
        })
    }
}

pub fn write_access_service_identity(path: &Path, raw: &str) -> Result<(), String> {
    AccessServiceIdentity::parse_env(raw)?;
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() as u64 > MAX_ACCESS_IDENTITY_BYTES {
        return Err("credential Access identity file size is invalid".to_owned());
    }
    write_atomic_private(path, bytes)
}

pub fn read_access_service_identity(path: &Path) -> Result<AccessServiceIdentity, String> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("credential Access identity is unavailable: {err}"))?;
    if metadata.len() == 0 || metadata.len() > MAX_ACCESS_IDENTITY_BYTES {
        return Err("credential Access identity file size is invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "credential Access identity must be root-owned and inaccessible to group/other"
                    .to_owned(),
            );
        }
    }
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read credential Access identity: {err}"))?;
    AccessServiceIdentity::parse_env(&raw)
}

pub fn canonical_credential_worker_url(
    projection: CredentialProjectionKind,
    generation: u64,
) -> Result<String, String> {
    if generation == 0 {
        return Err("credential generation must be greater than zero".to_owned());
    }
    let desired = canonical_production_desired_state()?;
    let cloudflare = desired
        .cloudflare
        .as_ref()
        .ok_or_else(|| "canonical production Cloudflare authority is missing".to_owned())?;
    let plane = cloudflare
        .credential_plane
        .as_ref()
        .ok_or_else(|| "canonical production credential plane is missing".to_owned())?;
    let worker = match projection {
        CredentialProjectionKind::Windows => &plane.windows_worker_name,
        CredentialProjectionKind::Vm => &plane.vm_worker_name,
        CredentialProjectionKind::Unspecified => {
            return Err("credential projection must be Windows or VM".to_owned());
        }
    };
    if worker.is_empty() || plane.workers_dev_subdomain.is_empty() {
        return Err("canonical credential Worker identity is incomplete".to_owned());
    }
    Ok(format!(
        "https://{}.{}.workers.dev/v1/credentials?generation={generation}",
        worker, plane.workers_dev_subdomain
    ))
}

fn credential_worker_transport_retry_allowed(attempt: usize) -> bool {
    attempt >= 1 && attempt < CREDENTIAL_WORKER_TRANSPORT_ATTEMPTS
}

fn credential_worker_transport_error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_request() {
        "request"
    } else if error.is_body() {
        "body"
    } else {
        "other"
    }
}

async fn send_credential_worker_get(
    client: &Client,
    url: &str,
) -> Result<reqwest::Response, String> {
    for attempt in 1..=CREDENTIAL_WORKER_TRANSPORT_ATTEMPTS {
        match client.get(url).send().await {
            Ok(response) => return Ok(response),
            Err(_) if credential_worker_transport_retry_allowed(attempt) => {
                // This is an exact-generation, read-only GET. Re-observation cannot replay
                // provider or local state mutation, so bounded transport retry is safe.
                tokio::time::sleep(CREDENTIAL_WORKER_TRANSPORT_RETRY_DELAY).await;
            }
            Err(error) => {
                return Err(format!(
                    "credential Worker request failed after {CREDENTIAL_WORKER_TRANSPORT_ATTEMPTS} bounded read-only attempts: kind={}",
                    credential_worker_transport_error_kind(&error)
                ));
            }
        }
    }
    unreachable!("bounded credential Worker transport loop always returns")
}

pub async fn observe_canonical_credential_bundle(
    projection: CredentialProjectionKind,
    generation: u64,
    identity_path: &Path,
) -> Result<Option<CredentialDeliveryBundle>, String> {
    let identity = read_access_service_identity(identity_path)?;
    observe_canonical_credential_bundle_with_identity(projection, generation, &identity, false)
        .await
}

fn credential_worker_client(identity: &AccessServiceIdentity) -> Result<Client, String> {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("cf-access-client-id"),
        HeaderValue::from_str(&identity.client_id)
            .map_err(|_| "credential Access client id is not a valid HTTP header".to_owned())?,
    );
    headers.insert(
        HeaderName::from_static("cf-access-client-secret"),
        HeaderValue::from_str(&identity.client_secret)
            .map_err(|_| "credential Access client secret is not a valid HTTP header".to_owned())?,
    );
    Client::builder()
        .redirect(Policy::none())
        .default_headers(headers)
        .timeout(CREDENTIAL_WORKER_REQUEST_TIMEOUT)
        .build()
        .map_err(|err| format!("failed to construct credential Worker client: {err}"))
}

async fn observe_canonical_credential_bundle_with_identity(
    projection: CredentialProjectionKind,
    generation: u64,
    identity: &AccessServiceIdentity,
    allow_dummy_probe: bool,
) -> Result<Option<CredentialDeliveryBundle>, String> {
    let url = canonical_credential_worker_url(projection, generation)?;
    let client = credential_worker_client(identity)?;
    let response = send_credential_worker_get(&client, &url).await?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if response.status() != StatusCode::OK {
        return Err(format!(
            "credential Worker returned unexpected HTTP status {}",
            response.status().as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_CREDENTIAL_BUNDLE_BYTES)
    {
        return Err("credential Worker response exceeds the bounded payload size".to_owned());
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/x-protobuf") {
        return Err("credential Worker returned an unexpected content type".to_owned());
    }
    let body = response
        .bytes()
        .await
        .map_err(|err| format!("failed to read credential Worker response: {err}"))?;
    if body.is_empty() || body.len() as u64 > MAX_CREDENTIAL_BUNDLE_BYTES {
        return Err("credential Worker response size is invalid".to_owned());
    }
    let bundle = decode_credential_delivery_bundle(&body)?;
    if bundle.dummy_non_secret && !allow_dummy_probe {
        return Err("runtime credential staging rejects dummy proof bundles".to_owned());
    }
    if bundle.projection != projection as i32 || bundle.generation != generation {
        return Err("credential Worker returned the wrong projection or generation".to_owned());
    }
    Ok(Some(bundle))
}

/// Read-only, bounded diagnostics: never expose the returned protobuf bytes,
/// credential values, or the contents of an occupied slot. HTTP 404 from a
/// generation-specific Worker endpoint proves neither an empty binding nor
/// that it is safe to overwrite the binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DummySlotObservation {
    ExactCanonical,
    MissingOrOtherGeneration,
    Noncanonical,
}

impl DummySlotObservation {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExactCanonical => "EXACT_CANONICAL_DUMMY",
            Self::MissingOrOtherGeneration => "NOT_FOUND_OR_OTHER_GENERATION",
            Self::Noncanonical => "NONCANONICAL_PAYLOAD",
        }
    }
}

fn classify_dummy_slot(
    observed: Option<&CredentialDeliveryBundle>,
    projection: CredentialProjectionKind,
    generation: u64,
) -> DummySlotObservation {
    match observed {
        None => DummySlotObservation::MissingOrOtherGeneration,
        Some(bundle) if verify_canonical_dummy_ab_probe(bundle, projection, generation).is_ok() => {
            DummySlotObservation::ExactCanonical
        }
        Some(_) => DummySlotObservation::Noncanonical,
    }
}

/// An exact fixed-binding attestation; generation-only GET cannot identify
/// which Worker A/B binding contained the bytes. This type is only returned
/// after the Worker proves the selected binding against its canonical dummy
/// bytes without returning either the binding value or live credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialDummySlotProof {
    pub slot_a_observation: &'static str,
    pub slot_b_observation: &'static str,
    pub exact_dummy_ab: bool,
}

fn require_selected_dummy(
    slot: CredentialDeliverySlot,
    a: DummySlotObservation,
    b: DummySlotObservation,
) -> Result<InitialDummySlotProof, String> {
    let selected = match slot {
        CredentialDeliverySlot::A => a,
        CredentialDeliverySlot::B => b,
        CredentialDeliverySlot::Unspecified => {
            return Err("initial slot witness refuses unspecified slot".to_owned());
        }
    };
    if selected != DummySlotObservation::ExactCanonical {
        return Err(format!(
            "initial selected Worker slot BLOCKED: selected={}; slot_A={}; slot_B={}; \
             publication_authorized=false; other_slot_overwrite_authorized=false",
            match slot {
                CredentialDeliverySlot::A => "A",
                CredentialDeliverySlot::B => "B",
                CredentialDeliverySlot::Unspecified => unreachable!(),
            },
            a.as_str(),
            b.as_str()
        ));
    }
    Ok(InitialDummySlotProof {
        slot_a_observation: a.as_str(),
        slot_b_observation: b.as_str(),
        exact_dummy_ab: a == DummySlotObservation::ExactCanonical
            && b == DummySlotObservation::ExactCanonical,
    })
}

/// Cloudflare Access-authenticated, bounded GET for a SPECIFIC Worker binding.
/// HTTP 204 is only valid with the Worker script's exact A/B binding comparison.
/// The legacy generation-search endpoint cannot supply such a witness: it
/// searches both slots and may return a B generation stored in A.
/// HTTP 404 also covers a not-yet-upgraded Worker: fail closed, never assume
/// that a binding is empty or try a different generation.
async fn observe_fixed_dummy_binding(
    projection: CredentialProjectionKind,
    slot: CredentialDeliverySlot,
    identity: &AccessServiceIdentity,
) -> Result<DummySlotObservation, String> {
    let (generation, slot_param) = match slot {
        CredentialDeliverySlot::A => (CREDENTIAL_DUMMY_PROBE_GENERATION_A, "a"),
        CredentialDeliverySlot::B => (CREDENTIAL_DUMMY_PROBE_GENERATION_B, "b"),
        CredentialDeliverySlot::Unspecified => {
            return Err("fixed Worker proof requires slot A or B".to_owned());
        }
    };
    let runtime_url = canonical_credential_worker_url(projection, generation)?;
    let proof_url = runtime_url
        .replace("/v1/credentials?generation=", "/v1/proof-slot?generation=")
        + "&slot="
        + slot_param;
    let client = credential_worker_client(identity)?;
    let response = send_credential_worker_get(&client, &proof_url).await?;
    match response.status() {
        StatusCode::NO_CONTENT => Ok(DummySlotObservation::ExactCanonical),
        StatusCode::CONFLICT => Ok(DummySlotObservation::Noncanonical),
        StatusCode::NOT_FOUND => Err(format!(
            "fixed Worker binding proof unavailable for slot {slot_param}: \
             deployed Worker lacks exact-slot attestation or rejected the generation; \
             publication_authorized=false"
        )),
        _ => Err(format!(
            "fixed Worker binding proof returned unexpected HTTP status {}; \
             publication_authorized=false",
            response.status().as_u16()
        )),
    }
}

/// First-use attestation permits only the *selected* exact canonical dummy.
/// The peer may be unknown, but is NEVER read as overwrite authority.
/// An old Worker script or metadata-only proof is explicitly insufficient.
pub async fn verify_initial_selected_dummy_slot(
    projection: CredentialProjectionKind,
    slot: CredentialDeliverySlot,
    identity_path: &Path,
) -> Result<InitialDummySlotProof, String> {
    if !matches!(slot, CredentialDeliverySlot::A | CredentialDeliverySlot::B) {
        return Err("initial Worker witness requires slot A or B".to_owned());
    }
    let identity = read_access_service_identity(identity_path)?;
    let a = observe_fixed_dummy_binding(projection, CredentialDeliverySlot::A, &identity).await?;
    let b = observe_fixed_dummy_binding(projection, CredentialDeliverySlot::B, &identity).await?;
    require_selected_dummy(slot, a, b)
}

/// Strict first-use A/B proof. Unlike generation-only GET, this proves that
/// each exact binding contains its own canonical dummy, under the host's
/// Cloudflare Access identity. Both observations remain secret-safe.
pub async fn verify_canonical_dummy_ab_slots(
    projection: CredentialProjectionKind,
    identity_path: &Path,
) -> Result<(), String> {
    let identity = read_access_service_identity(identity_path)?;
    let a = observe_fixed_dummy_binding(projection, CredentialDeliverySlot::A, &identity).await?;
    let b = observe_fixed_dummy_binding(projection, CredentialDeliverySlot::B, &identity).await?;
    if a == DummySlotObservation::ExactCanonical && b == DummySlotObservation::ExactCanonical {
        return Ok(());
    }
    Err(format!(
        "initial Worker-v2 fixed A/B dummy proof BLOCKED: slot_A={}; slot_B={}; \
         publication_authorized=false; provider_secret_contents=UNREADABLE; \
         no conclusion about occupied slot generations or safe overwrite",
        a.as_str(),
        b.as_str()
    ))
}

fn verify_canonical_dummy_ab_probe(
    observed: &CredentialDeliveryBundle,
    projection: CredentialProjectionKind,
    generation: u64,
) -> Result<(), String> {
    let expected = CredentialDeliveryBundle {
        schema_version: 1,
        generation,
        projection: projection as i32,
        dummy_non_secret: true,
        slot: CredentialDeliverySlot::Unspecified as i32,
        payload: None,
    };
    if !matches!(
        projection,
        CredentialProjectionKind::Vm | CredentialProjectionKind::Windows
    ) || !matches!(
        generation,
        CREDENTIAL_DUMMY_PROBE_GENERATION_A | CREDENTIAL_DUMMY_PROBE_GENERATION_B
    ) || observed != &expected
    {
        return Err(
            "initial Worker-v2 proof refused: endpoint is not the exact canonical dummy slot"
                .to_owned(),
        );
    }
    Ok(())
}

/// A bounded diagnostic code for Worker Host authorization. A rejected HTTP
/// response never grants permission for native mutation or an authorization replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostWorkerAuthorizationRejection {
    JwtMissing,
    JwtMalformed,
    JwtExpired,
    JwtNotYetValid,
    JwtIssuerMismatch,
    JwtAudienceMismatch,
    JwtSignatureRejected,
    JwtKeyUnavailable,
    JwtJwksFetchFailed,
    JwtJwksFetchSameZoneBlocked,
    JwtJwksFetchCloudflareIpBlocked,
    JwtJwksFetchHostBlocked,
    JwtJwksFetchRedirectBlocked,
    JwtJwksFetchTimeout,
    JwtJwksFetchDnsFailed,
    JwtJwksFetchTlsFailed,
    JwtJwksFetchIllegalInvocation,
    JwtJwksFetchTypeError,
    JwtJwksHttpUnavailable,
    JwtJwksInvalid,
    JwtKidNotFound,
    JwtKeyImportFailed,
    JwtSignatureMalformed,
    JwtSignatureVerifyFailed,
    WorkerConfigUnproven,
    GithubApprovalDenied,
    GithubDependencyUnavailable,
    HostSignerKeyInvalid,
    HostSignerCryptoFailed,
    HostSignerImportFailed,
    HostSignerSignFailed,
    HostSignerKeyMismatch,
    HostSignerSignatureInvalid,
    ForbiddenWithoutWorkerReason,
    UnclassifiedPolicyDenied,
    UnclassifiedAuthorizationFailure,
}

impl HostWorkerAuthorizationRejection {
    fn from_response(status: StatusCode, reason: Option<&str>) -> Self {
        match (status, reason) {
            (StatusCode::FORBIDDEN, Some("JWT_MISSING")) => Self::JwtMissing,
            (StatusCode::FORBIDDEN, Some("JWT_MALFORMED")) => Self::JwtMalformed,
            (StatusCode::FORBIDDEN, Some("JWT_EXPIRED")) => Self::JwtExpired,
            (StatusCode::FORBIDDEN, Some("JWT_NOT_YET_VALID")) => Self::JwtNotYetValid,
            (StatusCode::FORBIDDEN, Some("JWT_ISSUER_MISMATCH")) => Self::JwtIssuerMismatch,
            (StatusCode::FORBIDDEN, Some("JWT_AUDIENCE_MISMATCH")) => Self::JwtAudienceMismatch,
            (StatusCode::FORBIDDEN, Some("JWT_SIGNATURE_REJECTED")) => Self::JwtSignatureRejected,
            (StatusCode::FORBIDDEN, Some("JWT_KEY_UNAVAILABLE")) => Self::JwtKeyUnavailable,
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_FAILED")) => Self::JwtJwksFetchFailed,
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_SAME_ZONE_BLOCKED")) => {
                Self::JwtJwksFetchSameZoneBlocked
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_CLOUDFLARE_IP_BLOCKED")) => {
                Self::JwtJwksFetchCloudflareIpBlocked
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_HOST_BLOCKED")) => {
                Self::JwtJwksFetchHostBlocked
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_REDIRECT_BLOCKED")) => {
                Self::JwtJwksFetchRedirectBlocked
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_TIMEOUT")) => Self::JwtJwksFetchTimeout,
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_DNS_FAILED")) => {
                Self::JwtJwksFetchDnsFailed
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_TLS_FAILED")) => {
                Self::JwtJwksFetchTlsFailed
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_ILLEGAL_INVOCATION")) => {
                Self::JwtJwksFetchIllegalInvocation
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_FETCH_TYPE_ERROR")) => {
                Self::JwtJwksFetchTypeError
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_HTTP_UNAVAILABLE")) => {
                Self::JwtJwksHttpUnavailable
            }
            (StatusCode::FORBIDDEN, Some("JWT_JWKS_INVALID")) => Self::JwtJwksInvalid,
            (StatusCode::FORBIDDEN, Some("JWT_KID_NOT_FOUND")) => Self::JwtKidNotFound,
            (StatusCode::FORBIDDEN, Some("JWT_KEY_IMPORT_FAILED")) => Self::JwtKeyImportFailed,
            (StatusCode::FORBIDDEN, Some("JWT_SIGNATURE_MALFORMED")) => Self::JwtSignatureMalformed,
            (StatusCode::FORBIDDEN, Some("JWT_SIGNATURE_VERIFY_FAILED")) => {
                Self::JwtSignatureVerifyFailed
            }
            (StatusCode::FORBIDDEN, Some("WORKER_CONFIG_UNPROVEN")) => Self::WorkerConfigUnproven,
            (StatusCode::FORBIDDEN, Some("GITHUB_APPROVAL_DENIED")) => Self::GithubApprovalDenied,
            (StatusCode::SERVICE_UNAVAILABLE, Some("GITHUB_DEPENDENCY_UNAVAILABLE")) => {
                Self::GithubDependencyUnavailable
            }
            (StatusCode::SERVICE_UNAVAILABLE, Some("HOST_SIGNER_KEY_INVALID")) => {
                Self::HostSignerKeyInvalid
            }
            (StatusCode::SERVICE_UNAVAILABLE, Some("HOST_SIGNER_CRYPTO_FAILED")) => {
                Self::HostSignerCryptoFailed
            }
            (StatusCode::SERVICE_UNAVAILABLE, Some("HOST_SIGNER_IMPORT_FAILED")) => {
                Self::HostSignerImportFailed
            }
            (StatusCode::SERVICE_UNAVAILABLE, Some("HOST_SIGNER_SIGN_FAILED")) => {
                Self::HostSignerSignFailed
            }
            (StatusCode::SERVICE_UNAVAILABLE, Some("HOST_SIGNER_KEY_MISMATCH")) => {
                Self::HostSignerKeyMismatch
            }
            (StatusCode::SERVICE_UNAVAILABLE, Some("HOST_SIGNER_SIGNATURE_INVALID")) => {
                Self::HostSignerSignatureInvalid
            }
            (StatusCode::FORBIDDEN, None) => Self::ForbiddenWithoutWorkerReason,
            (StatusCode::FORBIDDEN, _) => Self::UnclassifiedPolicyDenied,
            _ => Self::UnclassifiedAuthorizationFailure,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::JwtMissing => "HOST_WORKER_JWT_MISSING",
            Self::JwtMalformed => "HOST_WORKER_JWT_MALFORMED",
            Self::JwtExpired => "HOST_WORKER_JWT_EXPIRED",
            Self::JwtNotYetValid => "HOST_WORKER_JWT_NOT_YET_VALID",
            Self::JwtIssuerMismatch => "HOST_WORKER_JWT_ISSUER_MISMATCH",
            Self::JwtAudienceMismatch => "HOST_WORKER_JWT_AUDIENCE_MISMATCH",
            Self::JwtSignatureRejected => "HOST_WORKER_JWT_SIGNATURE_REJECTED",
            Self::JwtKeyUnavailable => "HOST_WORKER_JWT_KEY_UNAVAILABLE",
            Self::JwtJwksFetchFailed => "HOST_WORKER_JWT_JWKS_FETCH_FAILED",
            Self::JwtJwksFetchSameZoneBlocked => "HOST_WORKER_JWT_JWKS_FETCH_SAME_ZONE_BLOCKED",
            Self::JwtJwksFetchCloudflareIpBlocked => {
                "HOST_WORKER_JWT_JWKS_FETCH_CLOUDFLARE_IP_BLOCKED"
            }
            Self::JwtJwksFetchHostBlocked => "HOST_WORKER_JWT_JWKS_FETCH_HOST_BLOCKED",
            Self::JwtJwksFetchRedirectBlocked => "HOST_WORKER_JWT_JWKS_FETCH_REDIRECT_BLOCKED",
            Self::JwtJwksFetchTimeout => "HOST_WORKER_JWT_JWKS_FETCH_TIMEOUT",
            Self::JwtJwksFetchDnsFailed => "HOST_WORKER_JWT_JWKS_FETCH_DNS_FAILED",
            Self::JwtJwksFetchTlsFailed => "HOST_WORKER_JWT_JWKS_FETCH_TLS_FAILED",
            Self::JwtJwksFetchIllegalInvocation => "HOST_WORKER_JWT_JWKS_FETCH_ILLEGAL_INVOCATION",
            Self::JwtJwksFetchTypeError => "HOST_WORKER_JWT_JWKS_FETCH_TYPE_ERROR",
            Self::JwtJwksHttpUnavailable => "HOST_WORKER_JWT_JWKS_HTTP_UNAVAILABLE",
            Self::JwtJwksInvalid => "HOST_WORKER_JWT_JWKS_INVALID",
            Self::JwtKidNotFound => "HOST_WORKER_JWT_KID_NOT_FOUND",
            Self::JwtKeyImportFailed => "HOST_WORKER_JWT_KEY_IMPORT_FAILED",
            Self::JwtSignatureMalformed => "HOST_WORKER_JWT_SIGNATURE_MALFORMED",
            Self::JwtSignatureVerifyFailed => "HOST_WORKER_JWT_SIGNATURE_VERIFY_FAILED",
            Self::WorkerConfigUnproven => "HOST_WORKER_CONFIG_UNPROVEN",
            Self::GithubApprovalDenied => "HOST_WORKER_GITHUB_APPROVAL_DENIED",
            Self::GithubDependencyUnavailable => {
                "HOST_WORKER_GITHUB_DEPENDENCY_UNAVAILABLE_NO_REPLAY"
            }
            Self::HostSignerKeyInvalid => "HOST_WORKER_SIGNER_KEY_INVALID_NO_REPLAY",
            Self::HostSignerCryptoFailed => "HOST_WORKER_SIGNER_CRYPTO_FAILED_NO_REPLAY",
            Self::HostSignerImportFailed => "HOST_WORKER_SIGNER_IMPORT_FAILED_NO_REPLAY",
            Self::HostSignerSignFailed => "HOST_WORKER_SIGNER_SIGN_FAILED_NO_REPLAY",
            Self::HostSignerKeyMismatch => "HOST_WORKER_SIGNER_KEY_MISMATCH_NO_REPLAY",
            Self::HostSignerSignatureInvalid => "HOST_WORKER_SIGNER_SIGNATURE_INVALID_NO_REPLAY",
            Self::ForbiddenWithoutWorkerReason => "HOST_WORKER_FORBIDDEN_WITHOUT_WORKER_REASON",
            Self::UnclassifiedPolicyDenied => "HOST_WORKER_POLICY_DENIED",
            Self::UnclassifiedAuthorizationFailure => "HOST_WORKER_AUTHORIZATION_NOT_ACCEPTED",
        }
    }
}

/// A bounded GET-only proof of the same Access JWT that protects POST.
/// No HostIntent, GitHub approval, signature, replay or native resource mutation.
/// Return codes are safe to print from existing native read-only diagnostics.
pub async fn diagnose_canonical_host_access(identity_path: &Path) -> Result<(), &'static str> {
    let identity = match read_access_service_identity(identity_path) {
        Ok(identity) => identity,
        Err(_) => return Err("HOST_WORKER_ACCESS_IDENTITY_UNAVAILABLE"),
    };
    let mut url = match canonical_credential_worker_url(CredentialProjectionKind::Vm, 1)
        .ok()
        .and_then(|url| reqwest::Url::parse(&url).ok())
    {
        Some(url) => url,
        None => return Err("HOST_WORKER_CANONICAL_URL_INVALID"),
    };
    url.set_path("/v1/host/authorize");
    url.set_query(None);
    let client = match credential_worker_client(&identity) {
        Ok(client) => client,
        Err(_) => return Err("HOST_WORKER_ACCESS_CLIENT_UNAVAILABLE"),
    };
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(_) => return Err("HOST_WORKER_ACCESS_DIAGNOSTIC_GET_UNAVAILABLE"),
    };
    let scope = response
        .headers()
        .get("X-Host-Authorization-Scope")
        .and_then(|header| header.to_str().ok());
    if scope != Some("READ_ONLY_NO_MUTATION") {
        return Err("HOST_WORKER_ACCESS_DIAGNOSTIC_UNTRUSTED_RESPONSE");
    }
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(());
    }
    let reason = response
        .headers()
        .get("X-Host-Authorization-Reason")
        .and_then(|header| header.to_str().ok());
    Err(HostWorkerAuthorizationRejection::from_response(response.status(), reason).code())
}

// Diagnostic metadata is NEVER admission authority. Only a closed set of
// enum tokens and digit-only bounded values may leave the native owner.
// A mismatched operation ID or malformed header suppresses this witness.
fn github_worker_failure_detail(headers: &HeaderMap, operation_id: &str) -> Option<String> {
    let read = |key: &str| headers.get(key).and_then(|value| value.to_str().ok());
    if read("X-Host-Github-Operation-Id") != Some(operation_id) {
        return None;
    }
    let stage = match read("X-Host-Github-Stage")? {
        "GITHUB_COMMENT" => "GITHUB_COMMENT",
        "GITHUB_RELEASE" => "GITHUB_RELEASE",
        "GITHUB_MAIN" => "GITHUB_MAIN",
        "GITHUB_PULLS" => "GITHUB_PULLS",
        "GITHUB_APP_JWT" => "GITHUB_APP_JWT",
        "GITHUB_INSTALLATION_TOKEN" => "GITHUB_INSTALLATION_TOKEN",
        _ => return None,
    };
    let kind = match read("X-Host-Github-Kind")? {
        "HTTP" => "HTTP",
        "REDIRECT" => "REDIRECT",
        "FETCH_EXCEPTION" => "FETCH_EXCEPTION",
        "RESPONSE_DECODE" => "RESPONSE_DECODE",
        "CONFIG_MISSING" => "CONFIG_MISSING",
        "SIGN_EXCEPTION" => "SIGN_EXCEPTION",
        "RESPONSE_INVALID" => "RESPONSE_INVALID",
        _ => return None,
    };
    let mut result = format!("stage={stage};kind={kind}");
    for (header, name, max_len) in [
        ("X-Host-Github-Http-Status", "http_status", 3_usize),
        (
            "X-Host-Github-Rate-Limit-Remaining",
            "rate_limit_remaining",
            10,
        ),
        ("X-Host-Github-Rate-Limit-Reset", "rate_limit_reset", 12),
        ("X-Host-Github-Retry-After", "retry_after", 8),
    ] {
        if let Some(value) = read(header) {
            if !value.is_empty()
                && value.len() <= max_len
                && value.bytes().all(|byte| byte.is_ascii_digit())
                && (name != "http_status"
                    || value
                        .parse::<u16>()
                        .is_ok_and(|status| (100..=599).contains(&status)))
            {
                result.push_str(&format!(";{name}={value}"));
            }
        }
    }
    if let Some(exception) = read("X-Host-Github-Exception-Class") {
        let safe = match exception {
            "TypeError" | "TimeoutError" | "SyntaxError" | "RangeError" | "Error" | "OTHER" => {
                Some(exception)
            }
            _ => None,
        };
        if let Some(safe) = safe {
            result.push_str(&format!(";exception_class={safe}"));
        }
    }
    if let Some(request_id) = read("X-Host-Github-Request-Id") {
        if !request_id.is_empty()
            && request_id.len() <= 64
            && request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            result.push_str(&format!(";github_request_id={request_id}"));
        }
    }
    Some(result)
}

/// Render a bounded refusal witness for EVERY non-200 Worker response.
/// This is observability, not admission. No response body, unknown header or
/// authorization credential is ever copied to a diagnostic or journal.
fn host_worker_rejection_witness(
    status: StatusCode,
    headers: &HeaderMap,
    operation_id: &str,
) -> String {
    let reason = headers
        .get("X-Host-Authorization-Reason")
        .and_then(|value| value.to_str().ok());
    let rejection = HostWorkerAuthorizationRejection::from_response(status, reason);
    let code = if status == StatusCode::NOT_FOUND {
        "HOST_WORKER_SIGNER_NOT_PROVISIONED"
    } else {
        rejection.code()
    };
    // Worker HTTP status and any GitHub upstream HTTP status are distinct.
    let mut witness = format!("{code}:worker_http_status={}", status.as_u16());
    // Only the existing closed enum mapping may authorize a reason to leave
    // the owner. All unclassified/free-form reason headers are suppressed.
    if !matches!(
        rejection,
        HostWorkerAuthorizationRejection::ForbiddenWithoutWorkerReason
            | HostWorkerAuthorizationRejection::UnclassifiedPolicyDenied
            | HostWorkerAuthorizationRejection::UnclassifiedAuthorizationFailure
    ) {
        if let Some(reason) = reason {
            witness.push_str(";authorization_reason=");
            witness.push_str(reason);
        }
    }
    // The existing stage/kind allowlist requires an exact matching operation
    // ID; never trust unrelated headers or turn GitHub diagnostics into replay.
    if status == StatusCode::SERVICE_UNAVAILABLE
        && rejection == HostWorkerAuthorizationRejection::GithubDependencyUnavailable
    {
        if let Some(detail) = github_worker_failure_detail(headers, operation_id) {
            witness.push(';');
            witness.push_str(&detail);
        }
    }
    if let Some(number) = operation_id.strip_prefix("issue1-comment-") {
        if !number.is_empty()
            && number.len() <= 20
            && number.bytes().all(|byte| byte.is_ascii_digit())
        {
            witness.push_str(";operation_id=");
            witness.push_str(operation_id);
        }
    }
    witness
}

/// Ask the ONE existing VM credential Worker to issue its independent
/// Ed25519 authorization for an exact already approved protobuf HostIntent.
/// Never retry a POST whose result is uncertain. This function only acquires
/// detached bytes: root/SYSTEM ownership, local pinned key validation,
/// canonical Git desired and the durable no-replay journal remain mandatory.
pub async fn request_canonical_host_authorization(
    intent_bytes: &[u8],
    identity_path: &Path,
) -> Result<edge_shared_types::FleetHostAuthorization, String> {
    use edge_shared_types::host_lifecycle::{
        MAX_HOST_AUTHORIZATION_BYTES, decode_host_authorization, decode_host_intent,
    };
    let intent = decode_host_intent(intent_bytes).map_err(str::to_owned)?;
    if intent.operation_id.is_empty() {
        return Err("HOST_AUTHORIZATION_EMPTY_OPERATION".to_owned());
    }
    let identity = read_access_service_identity(identity_path)?;
    let mut url = reqwest::Url::parse(&canonical_credential_worker_url(
        CredentialProjectionKind::Vm,
        1,
    )?)
    .map_err(|_| "HOST_WORKER_CANONICAL_URL_INVALID".to_owned())?;
    url.set_path("/v1/host/authorize");
    url.set_query(None);
    let client = credential_worker_client(&identity)?;
    let response = client
        .post(url)
        .header(CONTENT_TYPE, "application/x-protobuf")
        .body(intent_bytes.to_vec())
        .send()
        .await
        .map_err(|err| {
            format!(
                "HOST_WORKER_POST_OUTCOME_UNCERTAIN_NO_REPLAY:{}",
                credential_worker_transport_error_kind(&err)
            )
        })?;
    if response.status() != StatusCode::OK {
        return Err(host_worker_rejection_witness(
            response.status(),
            response.headers(),
            &intent.operation_id,
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length == 0 || length > MAX_HOST_AUTHORIZATION_BYTES as u64)
    {
        return Err("HOST_WORKER_AUTHORIZATION_RESPONSE_SIZE_INVALID".to_owned());
    }
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/x-protobuf")
    {
        return Err("HOST_WORKER_AUTHORIZATION_RESPONSE_TYPE_INVALID".to_owned());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "HOST_WORKER_RESPONSE_UNCERTAIN_NO_REPLAY".to_owned())?;
    let authorization = decode_host_authorization(&bytes).map_err(str::to_owned)?;
    if authorization.operation_id != intent.operation_id {
        return Err("HOST_WORKER_AUTHORIZATION_OPERATION_MISMATCH".to_owned());
    }
    // Signature is deliberately NOT considered verified here: the trusted
    // owner, not an unprivileged caller or a dynamic HTTP response, must pin
    // its own Worker public key and call verify_host_authorization.
    Ok(authorization)
}

/// Signed administrative authority is always minted by the existing Worker,
/// NEVER by the self-hosted runner or the local caller. One POST, no retry.
pub async fn request_canonical_admin_authorization(
    request_bytes: &[u8],
    identity_path: &Path,
) -> Result<edge_shared_types::FleetHostAdministrativeAuthorization, String> {
    use edge_shared_types::host_admin;
    use edge_shared_types::FleetHostAdministrativeAuthorization;
    use prost::Message;

    let request = host_admin::decode(request_bytes).map_err(str::to_owned)?;
    let identity = read_access_service_identity(identity_path)?;
    let mut url = reqwest::Url::parse(&canonical_credential_worker_url(
        CredentialProjectionKind::Vm, 1,
    )?)
    .map_err(|_| "HOST_ADMIN_WORKER_URL_INVALID".to_owned())?;
    url.set_path("/v1/host/admin/authorize");
    url.set_query(None);
    let response = credential_worker_client(&identity)?
        .post(url)
        .header(CONTENT_TYPE, "application/x-protobuf")
        .body(request_bytes.to_vec())
        .send().await
        .map_err(|_| "HOST_ADMIN_AUTHORIZATION_POST_UNKNOWN_NO_REPLAY".to_owned())?;
    if response.status() != StatusCode::OK {
        return Err(format!("HOST_ADMIN_WORKER_REJECTED_HTTP_{}", response.status().as_u16()));
    }
    if response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok())
        != Some("application/x-protobuf")
        || response.content_length().is_some_and(|n| n == 0 || n > 1024)
    {
        return Err("HOST_ADMIN_WORKER_AUTHORIZATION_INVALID_RESPONSE".to_owned());
    }
    let bytes = response.bytes().await
        .map_err(|_| "HOST_ADMIN_AUTHORIZATION_ACK_UNKNOWN_NO_REPLAY")?;
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err("HOST_ADMIN_AUTHORIZATION_SIZE_INVALID".to_owned());
    }
    let authorization = FleetHostAdministrativeAuthorization::decode(bytes.as_ref())
        .map_err(|_| "HOST_ADMIN_AUTHORIZATION_PROTOBUF_INVALID")?;
    if authorization.encode_to_vec().as_slice() != bytes.as_ref()
        || authorization.operation_id != host_admin::operation_id(&request)
    {
        return Err("HOST_ADMIN_AUTHORIZATION_MISMATCH".to_owned());
    }
    // Native root still needs to authenticate the Ed25519 signature against
    // its independent immutable Git-pinned Worker public key.
    Ok(authorization)
}

pub async fn fetch_canonical_credential_bundle(
    projection: CredentialProjectionKind,
    generation: u64,
    identity_path: &Path,
) -> Result<CredentialDeliveryBundle, String> {
    observe_canonical_credential_bundle(projection, generation, identity_path)
        .await?
        .ok_or_else(|| "credential Worker returned unexpected HTTP status 404".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn github_worker_diagnostics_are_bounded_and_operation_pinned() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Host-Github-Operation-Id",
            HeaderValue::from_static("issue1-comment-17"),
        );
        headers.insert(
            "X-Host-Github-Stage",
            HeaderValue::from_static("GITHUB_RELEASE"),
        );
        headers.insert("X-Host-Github-Kind", HeaderValue::from_static("HTTP"));
        headers.insert("X-Host-Github-Http-Status", HeaderValue::from_static("429"));
        headers.insert(
            "X-Host-Github-Rate-Limit-Remaining",
            HeaderValue::from_static("0"),
        );
        headers.insert(
            "X-Host-Github-Request-Id",
            HeaderValue::from_static("A1-B2"),
        );
        assert_eq!(
            github_worker_failure_detail(&headers, "issue1-comment-17"),
            Some("stage=GITHUB_RELEASE;kind=HTTP;http_status=429;rate_limit_remaining=0;github_request_id=A1-B2".to_owned()),
        );
        assert!(github_worker_failure_detail(&headers, "issue1-comment-18").is_none());
        headers.insert(
            "X-Host-Github-Stage",
            HeaderValue::from_static("GITHUB_FOREIGN"),
        );
        assert!(github_worker_failure_detail(&headers, "issue1-comment-17").is_none());
        headers.insert(
            "X-Host-Github-Stage",
            HeaderValue::from_static("GITHUB_RELEASE"),
        );
        headers.insert("X-Host-Github-Http-Status", HeaderValue::from_static("999"));
        headers.insert(
            "X-Host-Github-Request-Id",
            HeaderValue::from_static("invalid!"),
        );
        let safe = github_worker_failure_detail(&headers, "issue1-comment-17").unwrap();
        assert_eq!(
            safe,
            "stage=GITHUB_RELEASE;kind=HTTP;rate_limit_remaining=0"
        );
    }

    #[test]
    fn host_worker_auth_rejections_are_closed_and_bounded() {
        let cases = [
            (
                StatusCode::FORBIDDEN,
                Some("JWT_MISSING"),
                "HOST_WORKER_JWT_MISSING",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("JWT_MALFORMED"),
                "HOST_WORKER_JWT_MALFORMED",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("JWT_EXPIRED"),
                "HOST_WORKER_JWT_EXPIRED",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("JWT_NOT_YET_VALID"),
                "HOST_WORKER_JWT_NOT_YET_VALID",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("JWT_ISSUER_MISMATCH"),
                "HOST_WORKER_JWT_ISSUER_MISMATCH",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("JWT_AUDIENCE_MISMATCH"),
                "HOST_WORKER_JWT_AUDIENCE_MISMATCH",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("JWT_SIGNATURE_REJECTED"),
                "HOST_WORKER_JWT_SIGNATURE_REJECTED",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("JWT_KEY_UNAVAILABLE"),
                "HOST_WORKER_JWT_KEY_UNAVAILABLE",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("WORKER_CONFIG_UNPROVEN"),
                "HOST_WORKER_CONFIG_UNPROVEN",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("GITHUB_APPROVAL_DENIED"),
                "HOST_WORKER_GITHUB_APPROVAL_DENIED",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("GITHUB_DEPENDENCY_UNAVAILABLE"),
                "HOST_WORKER_GITHUB_DEPENDENCY_UNAVAILABLE_NO_REPLAY",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("HOST_SIGNER_KEY_INVALID"),
                "HOST_WORKER_SIGNER_KEY_INVALID_NO_REPLAY",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("HOST_SIGNER_CRYPTO_FAILED"),
                "HOST_WORKER_SIGNER_CRYPTO_FAILED_NO_REPLAY",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("HOST_SIGNER_IMPORT_FAILED"),
                "HOST_WORKER_SIGNER_IMPORT_FAILED_NO_REPLAY",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("HOST_SIGNER_SIGN_FAILED"),
                "HOST_WORKER_SIGNER_SIGN_FAILED_NO_REPLAY",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("HOST_SIGNER_KEY_MISMATCH"),
                "HOST_WORKER_SIGNER_KEY_MISMATCH_NO_REPLAY",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("HOST_SIGNER_SIGNATURE_INVALID"),
                "HOST_WORKER_SIGNER_SIGNATURE_INVALID_NO_REPLAY",
            ),
            (
                StatusCode::FORBIDDEN,
                None,
                "HOST_WORKER_FORBIDDEN_WITHOUT_WORKER_REASON",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("UNTRUSTED_REASON"),
                "HOST_WORKER_POLICY_DENIED",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("ACCESS_JWT_REJECTED"),
                "HOST_WORKER_AUTHORIZATION_NOT_ACCEPTED",
            ),
        ];
        for (status, reason, expected) in cases {
            assert_eq!(
                HostWorkerAuthorizationRejection::from_response(status, reason).code(),
                expected
            );
        }
    }

    #[test]
    fn host_worker_rejection_witness_preserves_status_with_strict_allowlists() {
        let id = "issue1-comment-6388202614";
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Host-Authorization-Reason",
            HeaderValue::from_static("JWT_AUDIENCE_MISMATCH"),
        );
        assert_eq!(
            host_worker_rejection_witness(StatusCode::FORBIDDEN, &headers, id),
            "HOST_WORKER_JWT_AUDIENCE_MISMATCH:worker_http_status=403;authorization_reason=JWT_AUDIENCE_MISMATCH;operation_id=issue1-comment-6388202614"
        );

        // Untrusted free-form reason, even if it names a secret, is never emitted.
        headers.insert(
            "X-Host-Authorization-Reason",
            HeaderValue::from_static("UNTRUSTED_private_key_value"),
        );
        let unclassified = host_worker_rejection_witness(StatusCode::FORBIDDEN, &headers, id);
        assert_eq!(
            unclassified,
            "HOST_WORKER_POLICY_DENIED:worker_http_status=403;operation_id=issue1-comment-6388202614"
        );
        assert!(!unclassified.contains("private_key_value"));
        assert_eq!(
            host_worker_rejection_witness(StatusCode::BAD_REQUEST, &headers, id),
            "HOST_WORKER_AUTHORIZATION_NOT_ACCEPTED:worker_http_status=400;operation_id=issue1-comment-6388202614"
        );
        assert_eq!(
            host_worker_rejection_witness(StatusCode::NOT_FOUND, &headers, id),
            "HOST_WORKER_SIGNER_NOT_PROVISIONED:worker_http_status=404;operation_id=issue1-comment-6388202614"
        );
        assert_eq!(
            host_worker_rejection_witness(StatusCode::BAD_GATEWAY, &headers, "secret-unsafe-id"),
            "HOST_WORKER_AUTHORIZATION_NOT_ACCEPTED:worker_http_status=502"
        );
    }

    #[test]
    fn github_witness_preserves_both_http_statuses_only_for_matching_operation() {
        let id = "issue1-comment-6388202614";
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Host-Authorization-Reason",
            HeaderValue::from_static("GITHUB_DEPENDENCY_UNAVAILABLE"),
        );
        headers.insert("X-Host-Github-Operation-Id", HeaderValue::from_static(id));
        headers.insert(
            "X-Host-Github-Stage",
            HeaderValue::from_static("GITHUB_INSTALLATION_TOKEN"),
        );
        headers.insert(
            "X-Host-Github-Kind",
            HeaderValue::from_static("RESPONSE_INVALID"),
        );
        headers.insert("X-Host-Github-Http-Status", HeaderValue::from_static("201"));
        let accepted = host_worker_rejection_witness(StatusCode::SERVICE_UNAVAILABLE, &headers, id);
        assert_eq!(
            accepted,
            "HOST_WORKER_GITHUB_DEPENDENCY_UNAVAILABLE_NO_REPLAY:worker_http_status=503;authorization_reason=GITHUB_DEPENDENCY_UNAVAILABLE;stage=GITHUB_INSTALLATION_TOKEN;kind=RESPONSE_INVALID;http_status=201;operation_id=issue1-comment-6388202614"
        );

        headers.insert(
            "X-Host-Github-Operation-Id",
            HeaderValue::from_static("issue1-comment-999"),
        );
        let mismatched =
            host_worker_rejection_witness(StatusCode::SERVICE_UNAVAILABLE, &headers, id);
        assert!(!mismatched.contains("stage="));
        assert!(!mismatched.contains("kind="));
        assert!(!mismatched.contains("http_status=201"));
        assert!(mismatched.contains("worker_http_status=503"));

        // A malicious stage or an unclassified HTTP response cannot forge
        // an approval, leak a header, or enable automatic replay.
        headers.insert("X-Host-Github-Operation-Id", HeaderValue::from_static(id));
        headers.insert(
            "X-Host-Github-Stage",
            HeaderValue::from_static("GITHUB_SECRET_LEAK"),
        );
        let spoofed = host_worker_rejection_witness(StatusCode::SERVICE_UNAVAILABLE, &headers, id);
        assert!(!spoofed.contains("GITHUB_SECRET_LEAK"));
        assert!(!spoofed.contains("stage="));
        headers.insert(
            "X-Host-Github-Stage",
            HeaderValue::from_static("GITHUB_COMMENT"),
        );
        assert!(
            !host_worker_rejection_witness(StatusCode::TOO_MANY_REQUESTS, &headers, id)
                .contains("stage=")
        );
    }

    #[test]
    fn signer_503_witness_never_accepts_spoofed_reason() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Host-Authorization-Reason",
            HeaderValue::from_static("HOST_SIGNER_CRYPTO_FAILED"),
        );
        let witness = host_worker_rejection_witness(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers,
            "issue1-comment-6388725669",
        );
        assert_eq!(
            witness,
            "HOST_WORKER_SIGNER_CRYPTO_FAILED_NO_REPLAY:worker_http_status=503;authorization_reason=HOST_SIGNER_CRYPTO_FAILED;operation_id=issue1-comment-6388725669"
        );
        let untrusted = host_worker_rejection_witness(
            StatusCode::FORBIDDEN,
            &headers,
            "issue1-comment-6388725669",
        );
        assert_eq!(
            untrusted,
            "HOST_WORKER_POLICY_DENIED:worker_http_status=403;operation_id=issue1-comment-6388725669"
        );
        headers.insert(
            "X-Host-Authorization-Reason",
            HeaderValue::from_static("HOST_SIGNER_PRIVATE_KEY_SECRET"),
        );
        assert!(
            !host_worker_rejection_witness(
                StatusCode::SERVICE_UNAVAILABLE,
                &headers,
                "issue1-comment-6388725669"
            )
            .contains("PRIVATE_KEY_SECRET")
        );
    }

    #[test]
    fn initial_worker_dummy_probe_requires_exact_full_slot_not_just_generation() {
        let dummy = CredentialDeliveryBundle {
            schema_version: 1,
            generation: CREDENTIAL_DUMMY_PROBE_GENERATION_A,
            projection: CredentialProjectionKind::Vm as i32,
            dummy_non_secret: true,
            slot: CredentialDeliverySlot::Unspecified as i32,
            payload: None,
        };
        let valid = verify_canonical_dummy_ab_probe(
            &dummy,
            CredentialProjectionKind::Vm,
            CREDENTIAL_DUMMY_PROBE_GENERATION_A,
        );
        assert!(valid.is_ok());

        let wrong_projection = verify_canonical_dummy_ab_probe(
            &dummy,
            CredentialProjectionKind::Windows,
            CREDENTIAL_DUMMY_PROBE_GENERATION_A,
        );
        assert!(wrong_projection.is_err());
        let wrong_generation = verify_canonical_dummy_ab_probe(
            &dummy,
            CredentialProjectionKind::Vm,
            CREDENTIAL_DUMMY_PROBE_GENERATION_B,
        );
        assert!(wrong_generation.is_err());

        let mut not_dummy = dummy.clone();
        not_dummy.dummy_non_secret = false;
        let wrong_payload = verify_canonical_dummy_ab_probe(
            &not_dummy,
            CredentialProjectionKind::Vm,
            CREDENTIAL_DUMMY_PROBE_GENERATION_A,
        );
        assert!(wrong_payload.is_err());

        let mut wrong_slot = dummy.clone();
        wrong_slot.slot = CredentialDeliverySlot::A as i32;
        let wrong_slot_result = verify_canonical_dummy_ab_probe(
            &wrong_slot,
            CredentialProjectionKind::Vm,
            CREDENTIAL_DUMMY_PROBE_GENERATION_A,
        );
        assert!(wrong_slot_result.is_err());

        let mut wrong_schema = dummy;
        wrong_schema.schema_version = 2;
        let wrong_schema_result = verify_canonical_dummy_ab_probe(
            &wrong_schema,
            CredentialProjectionKind::Vm,
            CREDENTIAL_DUMMY_PROBE_GENERATION_A,
        );
        assert!(wrong_schema_result.is_err());
    }

    #[test]
    fn first_use_b_witness_preserves_unknown_a_and_rejects_unproven_target() {
        use DummySlotObservation::{ExactCanonical, MissingOrOtherGeneration, Noncanonical};
        let proof = require_selected_dummy(
            CredentialDeliverySlot::B,
            MissingOrOtherGeneration,
            ExactCanonical,
        )
        .unwrap();
        assert_eq!(proof.slot_a_observation, "NOT_FOUND_OR_OTHER_GENERATION");
        assert_eq!(proof.slot_b_observation, "EXACT_CANONICAL_DUMMY");
        assert!(!proof.exact_dummy_ab);
        assert!(
            require_selected_dummy(
                CredentialDeliverySlot::A,
                MissingOrOtherGeneration,
                ExactCanonical,
            )
            .is_err()
        );
        assert!(
            require_selected_dummy(CredentialDeliverySlot::B, ExactCanonical, Noncanonical,)
                .is_err()
        );
        assert!(
            require_selected_dummy(
                CredentialDeliverySlot::Unspecified,
                ExactCanonical,
                ExactCanonical,
            )
            .is_err()
        );
        assert!(
            require_selected_dummy(CredentialDeliverySlot::B, Noncanonical, ExactCanonical,)
                .is_ok()
        );
        assert!(
            require_selected_dummy(CredentialDeliverySlot::B, ExactCanonical, ExactCanonical,)
                .unwrap()
                .exact_dummy_ab
        );
    }

    #[test]
    fn worker_dummy_slot_diagnostics_distinguish_both_without_secret_disclosure() {
        let exact = CredentialDeliveryBundle {
            schema_version: 1,
            generation: CREDENTIAL_DUMMY_PROBE_GENERATION_A,
            projection: CredentialProjectionKind::Vm as i32,
            dummy_non_secret: true,
            slot: CredentialDeliverySlot::Unspecified as i32,
            payload: None,
        };
        assert_eq!(
            classify_dummy_slot(
                Some(&exact),
                CredentialProjectionKind::Vm,
                CREDENTIAL_DUMMY_PROBE_GENERATION_A,
            ),
            DummySlotObservation::ExactCanonical,
        );
        assert_eq!(
            classify_dummy_slot(
                None,
                CredentialProjectionKind::Vm,
                CREDENTIAL_DUMMY_PROBE_GENERATION_B,
            ),
            DummySlotObservation::MissingOrOtherGeneration,
        );
        let mut noncanonical = exact;
        noncanonical.dummy_non_secret = false;
        assert_eq!(
            classify_dummy_slot(
                Some(&noncanonical),
                CredentialProjectionKind::Vm,
                CREDENTIAL_DUMMY_PROBE_GENERATION_A,
            ),
            DummySlotObservation::Noncanonical,
        );
        for value in [
            DummySlotObservation::ExactCanonical,
            DummySlotObservation::MissingOrOtherGeneration,
            DummySlotObservation::Noncanonical,
        ] {
            let result = value.as_str();
            assert!(!result.contains("secret"));
            assert!(!result.contains("client"));
            assert!(!result.contains("9_000_"));
        }
    }

    #[test]
    fn identity_parser_is_closed_and_secret_safe_in_debug() {
        let identity = AccessServiceIdentity::parse_env(
            "CF_ACCESS_CLIENT_ID=client-id\nCF_ACCESS_CLIENT_SECRET=client-secret\n",
        )
        .unwrap();
        let debug = format!("{identity:?}");
        assert!(!debug.contains("client-id"));
        assert!(!debug.contains("client-secret"));
        assert!(AccessServiceIdentity::parse_env("CF_ACCESS_CLIENT_ID=id\nEXTRA=value\n").is_err());
    }

    #[test]
    fn credential_worker_transport_retry_policy_is_bounded() {
        assert_eq!(CREDENTIAL_WORKER_TRANSPORT_ATTEMPTS, 3);
        assert!(!credential_worker_transport_retry_allowed(0));
        assert!(credential_worker_transport_retry_allowed(1));
        assert!(credential_worker_transport_retry_allowed(2));
        assert!(!credential_worker_transport_retry_allowed(3));
        assert!(!credential_worker_transport_retry_allowed(4));
    }

    #[test]
    fn canonical_worker_url_is_projection_specific_and_generation_bound() {
        let windows =
            canonical_credential_worker_url(CredentialProjectionKind::Windows, 101).unwrap();
        let vm = canonical_credential_worker_url(CredentialProjectionKind::Vm, 101).unwrap();
        assert_ne!(windows, vm);
        assert!(windows.ends_with("/v1/credentials?generation=101"));
        assert!(canonical_credential_worker_url(CredentialProjectionKind::Vm, 0).is_err());
    }
}
