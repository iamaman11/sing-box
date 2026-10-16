//! Existing-cursor Worker-v2 equality proof, not issuance, activation,
//! paired commit, loaded-process attribution or mutation authorization.
use crate::{CredentialStore, fetch_canonical_credential_bundle};
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialProjectionKind, CredentialDeliverySlot,
    LocalCredentialBundleRef, local_credential_bundle_ref,
};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOriginSelection { Active, Candidate }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialOriginObservation {
    pub generation: u64,
    pub slot: &'static str,
    pub bundle_sha256: String,
}

fn verify_remote_identity(
    projection: CredentialProjectionKind,
    local: &LocalCredentialBundleRef,
    local_bundle: &CredentialDeliveryBundle,
    remote: &CredentialDeliveryBundle,
) -> Result<(), &'static str> {
    if remote.dummy_non_secret || remote.projection != projection as i32
        || remote.generation != local.generation || remote.slot != local.slot
        || !matches!(CredentialDeliverySlot::try_from(remote.slot),
            Ok(CredentialDeliverySlot::A | CredentialDeliverySlot::B))
    {
        return Err("WORKER_ORIGIN_BLOCKED: projection, generation or fixed slot mismatch");
    }
    let observed = local_credential_bundle_ref(remote)
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: remote bundle invalid")?;
    if observed != *local || remote != local_bundle {
        return Err("WORKER_ORIGIN_BLOCKED: Worker bytes differ from local bundle");
    }
    Ok(())
}

/// The caller must be the existing native root/SYSTEM owner. Only exact,
/// authenticated Worker generation GET is used. No secret or raw Worker body
/// ever escapes this function, including on error.
pub async fn attest_worker_credential_origin(
    store_root: &Path,
    identity_path: &Path,
    projection: CredentialProjectionKind,
    selection: CredentialOriginSelection,
) -> Result<CredentialOriginObservation, String> {
    if !matches!(projection, CredentialProjectionKind::Windows | CredentialProjectionKind::Vm) {
        return Err("WORKER_ORIGIN_BLOCKED: invalid projection".to_owned());
    }
    let store = CredentialStore::open_existing(store_root, projection)
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: local store invalid")?
        .ok_or("WORKER_ORIGIN_BLOCKED: local store missing")?;
    let before = store.read_state()
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: local cursor invalid")?
        .ok_or("WORKER_ORIGIN_BLOCKED: local cursor missing")?;
    if before.previous.is_some() || before.active.is_some() == before.candidate.is_some() {
        return Err("WORKER_ORIGIN_BLOCKED: ambiguous cursor; reconcile read-only".to_owned());
    }
    let reference = match selection {
        CredentialOriginSelection::Active => before.active.as_ref(),
        CredentialOriginSelection::Candidate => before.candidate.as_ref(),
    }.ok_or("WORKER_ORIGIN_BLOCKED: selected role absent")?;
    let local = store.read_bundle(reference)
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: local bundle invalid")?;
    let remote = fetch_canonical_credential_bundle(projection, reference.generation, identity_path)
        .await.map_err(|_| "WORKER_ORIGIN_BLOCKED: Worker lookup unproven")?;
    verify_remote_identity(projection, reference, &local, &remote)
        .map_err(str::to_owned)?;
    if store.read_state().map_err(|_| "WORKER_ORIGIN_BLOCKED: cursor re-read failed")?
        .as_ref() != Some(&before)
    {
        return Err("WORKER_ORIGIN_BLOCKED: cursor changed during Worker observation".to_owned());
    }
    let slot = match CredentialDeliverySlot::try_from(reference.slot) {
        Ok(CredentialDeliverySlot::A) => "A",
        Ok(CredentialDeliverySlot::B) => "B",
        _ => return Err("WORKER_ORIGIN_BLOCKED: invalid cursor slot".to_owned()),
    };
    Ok(CredentialOriginObservation {
        generation: reference.generation,
        slot,
        bundle_sha256: reference.sha256.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fake(generation: u64, projection: CredentialProjectionKind, slot: CredentialDeliverySlot) -> CredentialDeliveryBundle {
        CredentialDeliveryBundle { schema_version: 1, generation, projection: projection as i32,
            slot: slot as i32, dummy_non_secret: true, payload: None }
    }
    #[test]
    fn dummy_or_wrong_projection_generation_slot_never_proves_origin() {
        let local = LocalCredentialBundleRef { generation: 123,
            slot: CredentialDeliverySlot::A as i32, sha256: "a".repeat(64) };
        let current = fake(123,CredentialProjectionKind::Windows,CredentialDeliverySlot::A);
        assert!(verify_remote_identity(CredentialProjectionKind::Windows,&local,&current,&current).is_err());
        for (projection,generation,slot) in [
            (CredentialProjectionKind::Vm,123,CredentialDeliverySlot::A),
            (CredentialProjectionKind::Windows,124,CredentialDeliverySlot::A),
            (CredentialProjectionKind::Windows,123,CredentialDeliverySlot::B),
        ] {
            let mut observed=fake(generation,projection,slot);
            observed.dummy_non_secret=false;
            assert!(verify_remote_identity(CredentialProjectionKind::Windows,&local,&current,&observed).is_err());
        }
    }
    #[test]
    fn active_is_never_an_implicit_candidate() {
        assert_ne!(CredentialOriginSelection::Active, CredentialOriginSelection::Candidate);
    }
}
