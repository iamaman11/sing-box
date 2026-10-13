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

async fn observe_canonical_credential_bundle_with_identity(
    projection: CredentialProjectionKind,
    generation: u64,
    identity: &AccessServiceIdentity,
    allow_dummy_probe: bool,
) -> Result<Option<CredentialDeliveryBundle>, String> {
    let url = canonical_credential_worker_url(projection, generation)?;
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
    let client = Client::builder()
        .redirect(Policy::none())
        .default_headers(headers)
        .timeout(CREDENTIAL_WORKER_REQUEST_TIMEOUT)
        .build()
        .map_err(|err| format!("failed to construct credential Worker client: {err}"))?;
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

/// A non-sensitive host witness for a selected first-use slot. In particular,
/// an unrecognized generation in the other slot is *not* treated as empty or
/// safe to overwrite. Only the selected slot can become write-eligible after
/// the separate host, provider, release, and GitHub BEGIN barriers.
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
            "initial selected Worker slot BLOCKED: selected={}; slot_A={}; slot_B={};              publication_authorized=false; other_slot_overwrite_authorized=false",
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

/// Authenticate the EXACT intended fixed slot for initial enrollment. Both
/// generation-specific GETs are read-only; the other slot is observed but not
/// required to contain dummy bytes, and is never selected for overwrite.
/// This proof alone must never authorize publication or a fresh issuance.
pub async fn verify_initial_selected_dummy_slot(
    projection: CredentialProjectionKind,
    slot: CredentialDeliverySlot,
    identity_path: &Path,
) -> Result<InitialDummySlotProof, String> {
    if !matches!(slot, CredentialDeliverySlot::A | CredentialDeliverySlot::B) {
        return Err("initial Worker witness requires slot A or B".to_owned());
    }
    let identity = read_access_service_identity(identity_path)?;
    let mut findings = Vec::with_capacity(2);
    for generation in [
        CREDENTIAL_DUMMY_PROBE_GENERATION_A,
        CREDENTIAL_DUMMY_PROBE_GENERATION_B,
    ] {
        let observed = observe_canonical_credential_bundle_with_identity(
            projection, generation, &identity, true,
        )
        .await?;
        findings.push(classify_dummy_slot(
            observed.as_ref(),
            projection,
            generation,
        ));
    }
    require_selected_dummy(slot, findings[0], findings[1])
}

/// Read-only proof that BOTH fixed A/B Worker slots still carry the canonical
/// non-secret probe. A Worker binding name, version tag, or 404 cannot prove
/// emptiness. Inspect both known dummy generations before deciding. Never
/// returns payload bytes, actual unknown generations, or Access credentials.
pub async fn verify_canonical_dummy_ab_slots(
    projection: CredentialProjectionKind,
    identity_path: &Path,
) -> Result<(), String> {
    let identity = read_access_service_identity(identity_path)?;
    let mut findings = Vec::with_capacity(2);
    for (slot, generation) in [
        ("A", CREDENTIAL_DUMMY_PROBE_GENERATION_A),
        ("B", CREDENTIAL_DUMMY_PROBE_GENERATION_B),
    ] {
        let observed = observe_canonical_credential_bundle_with_identity(
            projection, generation, &identity, true,
        )
        .await?;
        findings.push((
            slot,
            classify_dummy_slot(observed.as_ref(), projection, generation),
        ));
    }
    if findings
        .iter()
        .all(|(_, status)| *status == DummySlotObservation::ExactCanonical)
    {
        return Ok(());
    }
    Err(format!(
        "initial Worker-v2 fixed A/B dummy proof BLOCKED: slot_A={}; slot_B={}; \
         publication_authorized=false; provider_secret_contents=UNREADABLE; \
         no conclusion about occupied slot generations or safe overwrite",
        findings[0].1.as_str(),
        findings[1].1.as_str()
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
        ).unwrap();
        assert_eq!(proof.slot_a_observation, "NOT_FOUND_OR_OTHER_GENERATION");
        assert_eq!(proof.slot_b_observation, "EXACT_CANONICAL_DUMMY");
        assert!(!proof.exact_dummy_ab);
        assert!(require_selected_dummy(
            CredentialDeliverySlot::A,
            MissingOrOtherGeneration,
            ExactCanonical,
        ).is_err());
        assert!(require_selected_dummy(
            CredentialDeliverySlot::B,
            ExactCanonical,
            Noncanonical,
        ).is_err());
        assert!(require_selected_dummy(
            CredentialDeliverySlot::Unspecified,
            ExactCanonical,
            ExactCanonical,
        ).is_err());
        assert!(require_selected_dummy(
            CredentialDeliverySlot::B,
            Noncanonical,
            ExactCanonical,
        ).is_ok());
        assert!(require_selected_dummy(
            CredentialDeliverySlot::B,
            ExactCanonical,
            ExactCanonical,
        ).unwrap().exact_dummy_ab);
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
