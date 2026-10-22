//! Accepted historical provenance for the one existing VM root owner.
//! Old Agent cannot decode a new ReleaseSet. Prove its predecessor through
//! its root-protected original trust and the immutable published Git release,
//! never through a caller-supplied "expected previous SHA".
use super::*;
use base64::Engine as _;
use prost::Message as _;

pub(super) async fn previous_owner_sha(
    capture: &impl Fn(&str) -> Result<String, String>,
    machine_id: &str,
    expected_worker_key: &[u8],
) -> Result<String, String> {
    const FILE: &str = "/opt/vultr-edge-stack/native-host/trust.pb";
    let encoded = capture(&format!(
        "set -eu; test -f {FILE}; test ! -L {FILE}; \
         test \"$(stat -c '%u:%g:%a' {FILE})\" = '0:0:600'; \
         sudo -n base64 -w0 {FILE}"
    ))?;
    // This is the *public-only* trust snapshot, NOT the receipt private key.
    // Never echo these bytes to workflow output or make them a second authority.
    if encoded.is_empty() || encoded.len() > 12 * 1024 * 1024 {
        return Err("HOST_OWNER_TRUST_SIZE_UNPROVEN".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| "HOST_OWNER_TRUST_BASE64_INVALID")?;
    let trust = edge_shared_types::FleetNativeTrustSnapshot::decode(bytes.as_slice())
        .map_err(|_| "HOST_OWNER_TRUST_PROTO_INVALID")?;
    if trust.schema_version != 1
        || trust.encode_to_vec() != bytes
        || trust.machine_id != machine_id
        || trust.pinned_worker_public_key != expected_worker_key
        || trust.release_set_pb.is_empty()
        || trust.release_set_pb.len() > 65536
    {
        return Err("HOST_OWNER_TRUST_IDENTITY_UNPROVEN".into());
    }
    let previous = edge_shared_types::decode_release_set(&trust.release_set_pb)
        .map_err(|_| "HOST_OWNER_TRUST_RELEASE_INVALID")?;
    let sha = ring::digest::digest(&ring::digest::SHA256, &trust.release_set_pb)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let tag = format!("edge-release-{sha}");
    let api = format!("https://api.github.com/repos/iamaman11/sing-box/releases/tags/{tag}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|_| "HOST_OWNER_RELEASE_CLIENT_INVALID")?;
    let response = client
        .get(&api)
        .header("User-Agent", "sing-box-owner-provenance")
        .send()
        .await
        .map_err(|_| "HOST_OWNER_PREVIOUS_RELEASE_UNREACHABLE")?
        .error_for_status()
        .map_err(|_| "HOST_OWNER_PREVIOUS_RELEASE_NOT_PUBLISHED")?;
    let metadata: serde_json::Value = response
        .json()
        .await
        .map_err(|_| "HOST_OWNER_PREVIOUS_RELEASE_METADATA_INVALID")?;
    if metadata["tag_name"].as_str() != Some(tag.as_str())
        || metadata["draft"].as_bool() != Some(false)
        || metadata["prerelease"].as_bool() != Some(false)
    {
        return Err("HOST_OWNER_PREVIOUS_RELEASE_NOT_ACCEPTED".into());
    }
    let url = format!("https://github.com/iamaman11/sing-box/releases/download/{tag}/release-set.pb");
    let assets = metadata["assets"]
        .as_array()
        .ok_or("HOST_OWNER_RELEASE_ASSETS_INVALID")?;
    let mut hits = assets
        .iter()
        .filter(|v| v["name"].as_str() == Some("release-set.pb"));
    let asset = hits.next().ok_or("HOST_OWNER_RELEASE_ASSET_MISSING")?;
    if hits.next().is_some()
        || asset["browser_download_url"].as_str() != Some(url.as_str())
        || asset["digest"].as_str() != Some(format!("sha256:{sha}").as_str())
    {
        return Err("HOST_OWNER_RELEASE_ASSET_UNTRUSTED".into());
    }
    let published = client
        .get(&url)
        .header("User-Agent", "sing-box-owner-provenance")
        .send()
        .await
        .map_err(|_| "HOST_OWNER_RELEASE_DOWNLOAD_UNAVAILABLE")?
        .error_for_status()
        .map_err(|_| "HOST_OWNER_RELEASE_DOWNLOAD_REJECTED")?
        .bytes()
        .await
        .map_err(|_| "HOST_OWNER_RELEASE_DOWNLOAD_UNREADABLE")?;
    if published.len() > 65536 || published.as_ref() != trust.release_set_pb.as_slice() {
        return Err("HOST_OWNER_PREDECESSOR_GIT_BYTES_MISMATCH".into());
    }
    let old = previous
        .vm_runtime
        .as_ref()
        .map(|v| v.edge_agent_sha256.as_slice())
        .ok_or("HOST_OWNER_PREDECESSOR_RUNTIME_MISSING")?;
    if old.len() != 32 {
        return Err("HOST_OWNER_PREDECESSOR_DIGEST_INVALID".into());
    }
    Ok(old.iter().map(|b| format!("{b:02x}")).collect())
}

/// Run again immediately before BEGIN, not merely in an earlier CI stage.
/// An unresolved native application operation precludes replacing its owner.
pub(super) fn application_journal_clear(
    capture: &impl Fn(&str) -> Result<String, String>,
) -> Result<(), String> {
    const ROOT: &str = "/opt/vultr-edge-stack/native-host";
    let result = capture(&format!(
        "set -eu; test -d {ROOT}; test ! -L {ROOT}; \
         test \"$(stat -c '%u:%g:%a' {ROOT})\" = '0:0:700'; \
         test -d {ROOT}/journal; test ! -L {ROOT}/journal; \
         test \"$(stat -c '%u:%g:%a' {ROOT}/journal)\" = '0:0:700'; \
         sudo -n find {ROOT}/journal -maxdepth 1 -name '*.pending.pb' -print -quit"
    ))?;
    if !result.is_empty() {
        return Err("HOST_OWNER_APP_JOURNAL_UNKNOWN_NO_REPLAY".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn application_pending_and_unknown_are_not_healthy() {
        assert!(application_journal_clear(&|_| Ok(String::new())).is_ok());
        assert_eq!(
            application_journal_clear(&|_| Ok("pending.pb".into())).unwrap_err(),
            "HOST_OWNER_APP_JOURNAL_UNKNOWN_NO_REPLAY"
        );
        assert!(application_journal_clear(&|_| Err("SSH_UNAVAILABLE".into())).is_err());
    }
}
