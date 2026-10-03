use crate::credential_store::write_atomic_private;
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialProjectionKind, canonical_production_desired_state,
    decode_credential_delivery_bundle,
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
    observe_canonical_credential_bundle_with_identity(projection, generation, &identity).await
}

async fn observe_canonical_credential_bundle_with_identity(
    projection: CredentialProjectionKind,
    generation: u64,
    identity: &AccessServiceIdentity,
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
    if bundle.dummy_non_secret {
        return Err("runtime credential staging rejects dummy proof bundles".to_owned());
    }
    if bundle.projection != projection as i32 || bundle.generation != generation {
        return Err("credential Worker returned the wrong projection or generation".to_owned());
    }
    Ok(Some(bundle))
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
