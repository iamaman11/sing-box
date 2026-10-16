//! Existing-cursor Worker-v2 equality proof, not issuance, activation,
//! paired commit, loaded-process attribution or mutation authorization.
use crate::{CredentialStore, fetch_canonical_credential_bundle};
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialDeliverySlot, CredentialProjectionKind,
    LocalCredentialBundleRef, local_credential_bundle_ref,
};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOriginSelection {
    Active,
    Candidate,
}

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
    if remote.dummy_non_secret
        || remote.projection != projection as i32
        || remote.generation != local.generation
        || remote.slot != local.slot
        || !matches!(
            CredentialDeliverySlot::try_from(remote.slot),
            Ok(CredentialDeliverySlot::A | CredentialDeliverySlot::B)
        )
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
    attest_worker_credential_origin_with(store_root, projection, selection, |kind, generation| {
        fetch_canonical_credential_bundle(kind, generation, identity_path)
    })
    .await
}

// This private seam allows deterministic races to be tested without a live
// Worker. The production path always performs an authenticated canonical GET.
async fn attest_worker_credential_origin_with<F, Fut>(
    store_root: &Path,
    projection: CredentialProjectionKind,
    selection: CredentialOriginSelection,
    fetch: F,
) -> Result<CredentialOriginObservation, String>
where
    F: FnOnce(CredentialProjectionKind, u64) -> Fut,
    Fut: std::future::Future<Output = Result<CredentialDeliveryBundle, String>>,
{
    if !matches!(
        projection,
        CredentialProjectionKind::Windows | CredentialProjectionKind::Vm
    ) {
        return Err("WORKER_ORIGIN_BLOCKED: invalid projection".to_owned());
    }
    let store = CredentialStore::open_existing(store_root, projection)
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: local store invalid")?
        .ok_or("WORKER_ORIGIN_BLOCKED: local store missing")?;
    let before = store
        .read_state()
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: local cursor invalid")?
        .ok_or("WORKER_ORIGIN_BLOCKED: local cursor missing")?;
    if before.previous.is_some() || before.active.is_some() == before.candidate.is_some() {
        return Err("WORKER_ORIGIN_BLOCKED: ambiguous cursor; reconcile read-only".to_owned());
    }
    let reference = match selection {
        CredentialOriginSelection::Active => before.active.as_ref(),
        CredentialOriginSelection::Candidate => before.candidate.as_ref(),
    }
    .ok_or("WORKER_ORIGIN_BLOCKED: selected role absent")?;
    let local = store
        .read_bundle(reference)
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: local bundle invalid")?;
    let remote = fetch(projection, reference.generation)
        .await
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: Worker lookup unproven")?;
    verify_remote_identity(projection, reference, &local, &remote).map_err(str::to_owned)?;
    if store
        .read_state()
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: cursor re-read failed")?
        .as_ref()
        != Some(&before)
    {
        return Err("WORKER_ORIGIN_BLOCKED: cursor changed during Worker observation".to_owned());
    }
    // An unchanged pointer is not sufficient if a bundle file was replaced
    // while the authenticated Worker request was in flight.
    if store
        .read_bundle(reference)
        .map_err(|_| "WORKER_ORIGIN_BLOCKED: bundle re-read failed")?
        != local
    {
        return Err("WORKER_ORIGIN_BLOCKED: bundle changed during Worker observation".to_owned());
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
    fn fake(
        generation: u64,
        projection: CredentialProjectionKind,
        slot: CredentialDeliverySlot,
    ) -> CredentialDeliveryBundle {
        CredentialDeliveryBundle {
            schema_version: 1,
            generation,
            projection: projection as i32,
            slot: slot as i32,
            dummy_non_secret: true,
            payload: None,
        }
    }
    #[test]
    fn dummy_or_wrong_projection_generation_slot_never_proves_origin() {
        let local = LocalCredentialBundleRef {
            generation: 123,
            slot: CredentialDeliverySlot::A as i32,
            sha256: "a".repeat(64),
        };
        let current = fake(
            123,
            CredentialProjectionKind::Windows,
            CredentialDeliverySlot::A,
        );
        assert!(
            verify_remote_identity(
                CredentialProjectionKind::Windows,
                &local,
                &current,
                &current
            )
            .is_err()
        );
        for (projection, generation, slot) in [
            (CredentialProjectionKind::Vm, 123, CredentialDeliverySlot::A),
            (
                CredentialProjectionKind::Windows,
                124,
                CredentialDeliverySlot::A,
            ),
            (
                CredentialProjectionKind::Windows,
                123,
                CredentialDeliverySlot::B,
            ),
        ] {
            let mut observed = fake(generation, projection, slot);
            observed.dummy_non_secret = false;
            assert!(
                verify_remote_identity(
                    CredentialProjectionKind::Windows,
                    &local,
                    &current,
                    &observed
                )
                .is_err()
            );
        }
    }
    #[test]
    fn active_is_never_an_implicit_candidate() {
        assert_ne!(
            CredentialOriginSelection::Active,
            CredentialOriginSelection::Candidate
        );
    }

    fn valid_bundle(generation: u64, slot: CredentialDeliverySlot) -> CredentialDeliveryBundle {
        use edge_shared_types::{
            RealityPublicIdentity, RealityPublicIdentityGeneration, TunnelAuthentication,
            TunnelAuthenticationGeneration, WindowsCredentialProjection,
            credential_delivery_bundle,
        };
        CredentialDeliveryBundle {
            schema_version: 1,
            generation,
            projection: CredentialProjectionKind::Windows as i32,
            slot: slot as i32,
            dummy_non_secret: false,
            payload: Some(credential_delivery_bundle::Payload::Windows(
                WindowsCredentialProjection {
                    tunnel_auth: Some(TunnelAuthenticationGeneration {
                        generation,
                        direct: Some(TunnelAuthentication {
                            vless_uuid: "00000000-0000-4000-8000-000000000001".to_owned(),
                            hysteria2_password: "a".repeat(64),
                            reality_short_id: "b".repeat(16),
                        }),
                        warp: Some(TunnelAuthentication {
                            vless_uuid: "00000000-0000-4000-8000-000000000002".to_owned(),
                            hysteria2_password: "c".repeat(64),
                            reality_short_id: "d".repeat(16),
                        }),
                    }),
                    reality_identity: Some(RealityPublicIdentityGeneration {
                        generation,
                        direct: Some(RealityPublicIdentity {
                            public_key: "A".repeat(43),
                        }),
                        warp: Some(RealityPublicIdentity {
                            public_key: "B".repeat(43),
                        }),
                    }),
                },
            )),
        }
    }

    fn active_store(label: &str, bundle: &CredentialDeliveryBundle) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "edge-origin-{label}-{}-{stamp}",
            std::process::id()
        ));
        let store = CredentialStore::new(&root, CredentialProjectionKind::Windows).unwrap();
        store.stage_candidate(bundle).unwrap();
        store.promote_candidate().unwrap();
        root
    }

    // No additional async runtime dependency: injected lookup is always ready.
    fn ready<F: std::future::Future>(future: F) -> F::Output {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match Future::poll(future.as_mut(), &mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("test Worker future must not suspend"),
        }
    }

    #[test]
    fn valid_worker_bundle_proves_existing_active_origin() {
        let bundle = valid_bundle(123, CredentialDeliverySlot::A);
        let expected = local_credential_bundle_ref(&bundle).unwrap();
        let root = active_store("positive", &bundle);
        let observed = ready(attest_worker_credential_origin_with(
            &root,
            CredentialProjectionKind::Windows,
            CredentialOriginSelection::Active,
            |projection, generation| async {
                assert_eq!(projection, CredentialProjectionKind::Windows);
                assert_eq!(generation, 123);
                Ok(bundle)
            },
        ))
        .unwrap();
        assert_eq!(observed.generation, expected.generation);
        assert_eq!(observed.slot, "A");
        assert_eq!(observed.bundle_sha256, expected.sha256);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn changed_worker_production_bundle_is_rejected() {
        let bundle = valid_bundle(123, CredentialDeliverySlot::A);
        let root = active_store("mismatch", &bundle);
        let mut modified = bundle.clone();
        if let Some(edge_shared_types::credential_delivery_bundle::Payload::Windows(w)) =
            modified.payload.as_mut()
        {
            w.reality_identity
                .as_mut()
                .unwrap()
                .direct
                .as_mut()
                .unwrap()
                .public_key = "Z".repeat(43);
        }
        let result = ready(attest_worker_credential_origin_with(
            &root,
            CredentialProjectionKind::Windows,
            CredentialOriginSelection::Active,
            |_, _| async { Ok(modified) },
        ));
        assert!(result.unwrap_err().starts_with("WORKER_ORIGIN_BLOCKED:"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cursor_mutation_during_worker_request_is_rejected() {
        let bundle = valid_bundle(123, CredentialDeliverySlot::A);
        let root = active_store("cursor-race", &bundle);
        let store = CredentialStore::new(&root, CredentialProjectionKind::Windows).unwrap();
        let next = valid_bundle(124, CredentialDeliverySlot::B);
        let result = ready(attest_worker_credential_origin_with(
            &root,
            CredentialProjectionKind::Windows,
            CredentialOriginSelection::Active,
            |_, _| async {
                store.stage_candidate(&next).unwrap();
                Ok(bundle)
            },
        ));
        assert_eq!(
            result.unwrap_err(),
            "WORKER_ORIGIN_BLOCKED: cursor changed during Worker observation"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
