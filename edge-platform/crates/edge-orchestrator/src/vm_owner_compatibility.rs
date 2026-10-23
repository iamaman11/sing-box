//! Immutable predecessor attestation for a VM owner handoff.
//! Never authorizes an upgrade based on runner status or a supplied SHA.
//! The old root trust pins an exact previously published ReleaseSet.
use base64::Engine as _;
use edge_shared_types::{FleetNativeTrustSnapshot, ReleaseSet};
use prost::Message;
use ring::digest::{SHA256, digest};
use std::time::Duration;

fn sha256_hex(value: &[u8]) -> String {
    digest(&SHA256, value).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) struct PreviousOwner {
    pub(super) agent_sha256: String,
    pub(super) release_bytes: Vec<u8>,
    pub(super) release_sha256: String,
}

pub(super) fn decode_root_trust(
    encoded: &str,
    machine_id: &str,
    worker_public_key: &[u8],
) -> Result<PreviousOwner, String> {
    if encoded.is_empty() || encoded.len() > 12_600_000 {
        return Err("HOST_OWNER_TRUST_SIZE_UNPROVEN".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| "HOST_OWNER_TRUST_ENCODING_INVALID")?;
    let trust = FleetNativeTrustSnapshot::decode(bytes.as_slice())
        .map_err(|_| "HOST_OWNER_TRUST_PROTO_INVALID")?;
    if trust.schema_version != 1
        || trust.encode_to_vec() != bytes
        || trust.machine_id != machine_id
        || trust.pinned_worker_public_key != worker_public_key
        || trust.registry_pb.is_empty()
        || trust.application_bundle_pb.is_empty()
        || trust.selected_spec_bytes.is_empty()
        || trust.release_set_pb.is_empty()
        || trust.release_set_pb.len() > 65536
    {
        return Err("HOST_OWNER_TRUST_IDENTITY_UNPROVEN".into());
    }
    let release = ReleaseSet::decode(trust.release_set_pb.as_slice())
        .map_err(|_| "HOST_OWNER_PREVIOUS_RELEASE_PROTO_INVALID")?;
    if release.encode_to_vec() != trust.release_set_pb {
        return Err("HOST_OWNER_PREVIOUS_RELEASE_NONCANONICAL".into());
    }
    let agent = release.vm_runtime
        .as_ref()
        .ok_or("HOST_OWNER_PREVIOUS_AGENT_MISSING")?
        .edge_agent_sha256.as_slice();
    if agent.len() != 32 {
        return Err("HOST_OWNER_PREVIOUS_AGENT_DIGEST_INVALID".into());
    }
    Ok(PreviousOwner {
        agent_sha256: agent.iter().map(|b| format!("{b:02x}")).collect(),
        release_sha256: sha256_hex(&trust.release_set_pb),
        release_bytes: trust.release_set_pb,
    })
}

/// Published GitHub assets must match the protected root bytes exactly;
/// old local bytes are not a second desired source.
pub(super) async fn verify_accepted_predecessor(previous: &PreviousOwner) -> Result<(), String> {
    let tag = format!("edge-release-{}", previous.release_sha256);
    let metadata_url = format!(
        "https://api.github.com/repos/iamaman11/sing-box/releases/tags/{tag}"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|_| "HOST_OWNER_GITHUB_CLIENT_INVALID")?;
    let meta = client.get(metadata_url)
        .header("User-Agent", "sing-box-native-owner-compat")
        .send().await.map_err(|_| "HOST_OWNER_PREVIOUS_GITHUB_UNAVAILABLE")?
        .error_for_status().map_err(|_| "HOST_OWNER_PREVIOUS_RELEASE_NOT_PUBLISHED")?
        .bytes().await.map_err(|_| "HOST_OWNER_PREVIOUS_METADATA_UNREADABLE")?;
    if meta.len() > 262144 {
        return Err("HOST_OWNER_PREVIOUS_METADATA_TOO_LARGE".into());
    }
    let release: serde_json::Value = serde_json::from_slice(&meta)
        .map_err(|_| "HOST_OWNER_PREVIOUS_METADATA_INVALID")?;
    if release["tag_name"].as_str() != Some(tag.as_str())
        || release["draft"].as_bool() != Some(false)
        || release["prerelease"].as_bool() != Some(false)
    {
        return Err("HOST_OWNER_PREVIOUS_RELEASE_NOT_ACCEPTED".into());
    }
    let url = format!(
        "https://github.com/iamaman11/sing-box/releases/download/{tag}/release-set.pb"
    );
    let assets = release["assets"].as_array()
        .ok_or("HOST_OWNER_PREVIOUS_ASSETS_MISSING")?;
    let mut matches = assets.iter()
        .filter(|asset| asset["name"].as_str() == Some("release-set.pb"));
    let asset = matches.next().ok_or("HOST_OWNER_PREVIOUS_ASSET_MISSING")?;
    if matches.next().is_some()
        || asset["browser_download_url"].as_str() != Some(url.as_str())
        || asset["digest"].as_str()
            != Some(format!("sha256:{}", previous.release_sha256).as_str())
    {
        return Err("HOST_OWNER_PREVIOUS_ASSET_UNTRUSTED".into());
    }
    let downloaded = client.get(url)
        .header("User-Agent", "sing-box-native-owner-compat")
        .send().await.map_err(|_| "HOST_OWNER_PREVIOUS_ASSET_UNAVAILABLE")?
        .error_for_status().map_err(|_| "HOST_OWNER_PREVIOUS_ASSET_REJECTED")?
        .bytes().await.map_err(|_| "HOST_OWNER_PREVIOUS_ASSET_UNREADABLE")?;
    if downloaded.len() != previous.release_bytes.len()
        || downloaded.as_ref() != previous.release_bytes.as_slice()
    {
        return Err("HOST_OWNER_PREVIOUS_GIT_BYTES_MISMATCH".into());
    }
    Ok(())
}

pub(super) enum OwnerDecision {
    Upgrade,
    Current,
}

pub(super) fn decide(
    actual: &str,
    previous: &str,
    desired: &str,
    proven_upgrade_chain: bool,
) -> Result<OwnerDecision, String> {
    let valid = |v: &str| v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !valid(actual) || !valid(previous) || !valid(desired) {
        return Err("HOST_OWNER_FINGERPRINT_INVALID".into());
    }
    if actual == desired {
        if actual != previous && !proven_upgrade_chain {
            return Err("HOST_OWNER_UPGRADE_OUTCOME_UNPROVEN_NO_REPLAY".into());
        }
        return Ok(OwnerDecision::Current);
    }
    if actual != previous {
        return Err("HOST_OWNER_UNRECOGNIZED_BINARY_NO_REPLAY".into());
    }
    Ok(OwnerDecision::Upgrade)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drift_and_lost_ack_are_not_replayed() {
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        assert!(matches!(decide(&old, &old, &new, false).unwrap(), OwnerDecision::Upgrade));
        assert!(decide(&new, &old, &new, false).is_err());
        assert!(matches!(decide(&new, &old, &new, true).unwrap(), OwnerDecision::Current));
        assert!(decide(&"c".repeat(64), &old, &new, true).is_err());
        assert!(matches!(decide(&old, &old, &old, false).unwrap(), OwnerDecision::Current));
    }
    #[test]
    fn empty_or_unpinned_trust_is_not_predecessor() {
        assert!(decode_root_trust("", "vm", &[1; 32]).is_err());
        assert!(decode_root_trust("YWJj", "vm", &[1; 32]).is_err());
    }
}
