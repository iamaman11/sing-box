use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialDeliverySlot, CredentialProjectionKind,
    ProxyCredentialGeneration, RealityPrivateIdentity, RealityPrivateIdentityGeneration,
    RealityPublicIdentity, RealityPublicIdentityGeneration, TunnelAuthentication,
    TunnelAuthenticationGeneration, VmCredentialProjection, WindowsCredentialProjection,
    credential_delivery_bundle, validate_credential_delivery_bundle,
};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshCredentialSnapshotRequest {
    pub delivery_generation: u64,
    pub slot: CredentialDeliverySlot,
    pub tunnel_auth_generation: u64,
    pub reality_identity_generation: u64,
    pub line2_proxy_generation: u64,
}

impl FreshCredentialSnapshotRequest {
    fn validate(self) -> Result<(), String> {
        if self.delivery_generation == 0 {
            return Err("delivery_generation must be greater than zero".to_owned());
        }
        if !matches!(
            self.slot,
            CredentialDeliverySlot::A | CredentialDeliverySlot::B
        ) {
            return Err("slot must be fixed credential slot A or B".to_owned());
        }
        if self.tunnel_auth_generation == 0 {
            return Err("tunnel_auth_generation must be greater than zero".to_owned());
        }
        if self.reality_identity_generation == 0 {
            return Err("reality_identity_generation must be greater than zero".to_owned());
        }
        if self.line2_proxy_generation == 0 {
            return Err("line2_proxy_generation must be greater than zero".to_owned());
        }
        Ok(())
    }
}

// Intentionally does not derive Debug: both bundles contain live secret material.
pub struct FreshCredentialSnapshot {
    pub windows: CredentialDeliveryBundle,
    pub vm: CredentialDeliveryBundle,
}

pub fn generate_fresh_credential_snapshot(
    request: FreshCredentialSnapshotRequest,
) -> Result<FreshCredentialSnapshot, String> {
    request.validate()?;

    let tunnel_auth = TunnelAuthenticationGeneration {
        generation: request.tunnel_auth_generation,
        direct: Some(generate_tunnel_authentication()),
        warp: Some(generate_tunnel_authentication()),
    };

    let (direct_private, direct_public) = generate_reality_pair();
    let (warp_private, warp_public) = generate_reality_pair();

    let windows = CredentialDeliveryBundle {
        schema_version: 1,
        generation: request.delivery_generation,
        projection: CredentialProjectionKind::Windows as i32,
        dummy_non_secret: false,
        slot: request.slot as i32,
        payload: Some(credential_delivery_bundle::Payload::Windows(
            WindowsCredentialProjection {
                tunnel_auth: Some(tunnel_auth.clone()),
                reality_identity: Some(RealityPublicIdentityGeneration {
                    generation: request.reality_identity_generation,
                    direct: Some(RealityPublicIdentity {
                        public_key: direct_public,
                    }),
                    warp: Some(RealityPublicIdentity {
                        public_key: warp_public,
                    }),
                }),
            },
        )),
    };

    let vm = CredentialDeliveryBundle {
        schema_version: 1,
        generation: request.delivery_generation,
        projection: CredentialProjectionKind::Vm as i32,
        dummy_non_secret: false,
        slot: request.slot as i32,
        payload: Some(credential_delivery_bundle::Payload::Vm(
            VmCredentialProjection {
                tunnel_auth: Some(tunnel_auth),
                reality_identity: Some(RealityPrivateIdentityGeneration {
                    generation: request.reality_identity_generation,
                    direct: Some(RealityPrivateIdentity {
                        private_key: direct_private,
                    }),
                    warp: Some(RealityPrivateIdentity {
                        private_key: warp_private,
                    }),
                }),
                line2_proxy: Some(ProxyCredentialGeneration {
                    generation: request.line2_proxy_generation,
                    password: random_hex(32),
                }),
            },
        )),
    };

    validate_credential_delivery_bundle(&windows)?;
    validate_credential_delivery_bundle(&vm)?;

    Ok(FreshCredentialSnapshot { windows, vm })
}

fn generate_tunnel_authentication() -> TunnelAuthentication {
    TunnelAuthentication {
        vless_uuid: generate_uuid_v4(),
        hysteria2_password: random_hex(32),
        reality_short_id: random_hex(8),
    }
}

fn generate_reality_pair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (
        URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        URL_SAFE_NO_PAD.encode(public.to_bytes()),
    )
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    buffer
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn generate_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::{decode_credential_delivery_bundle, encode_credential_delivery_bundle};

    fn request() -> FreshCredentialSnapshotRequest {
        FreshCredentialSnapshotRequest {
            delivery_generation: 101,
            slot: CredentialDeliverySlot::B,
            tunnel_auth_generation: 7,
            reality_identity_generation: 3,
            line2_proxy_generation: 2,
        }
    }

    fn windows_projection(snapshot: &FreshCredentialSnapshot) -> &WindowsCredentialProjection {
        match snapshot.windows.payload.as_ref().unwrap() {
            credential_delivery_bundle::Payload::Windows(value) => value,
            credential_delivery_bundle::Payload::Vm(_) => panic!("unexpected VM payload"),
        }
    }

    fn vm_projection(snapshot: &FreshCredentialSnapshot) -> &VmCredentialProjection {
        match snapshot.vm.payload.as_ref().unwrap() {
            credential_delivery_bundle::Payload::Vm(value) => value,
            credential_delivery_bundle::Payload::Windows(_) => {
                panic!("unexpected Windows payload")
            }
        }
    }

    #[test]
    fn snapshot_pairs_one_delivery_generation_and_slot() {
        let snapshot = generate_fresh_credential_snapshot(request()).unwrap();

        assert_eq!(snapshot.windows.generation, 101);
        assert_eq!(snapshot.vm.generation, 101);
        assert_eq!(snapshot.windows.slot, CredentialDeliverySlot::B as i32);
        assert_eq!(snapshot.vm.slot, CredentialDeliverySlot::B as i32);
        assert_eq!(
            snapshot.windows.projection,
            CredentialProjectionKind::Windows as i32
        );
        assert_eq!(snapshot.vm.projection, CredentialProjectionKind::Vm as i32);
    }

    #[test]
    fn snapshot_projects_identical_tunnel_auth_to_both_consumers() {
        let snapshot = generate_fresh_credential_snapshot(request()).unwrap();
        let windows = windows_projection(&snapshot);
        let vm = vm_projection(&snapshot);

        assert_eq!(windows.tunnel_auth, vm.tunnel_auth);
        assert_eq!(windows.tunnel_auth.as_ref().unwrap().generation, 7);
    }

    #[test]
    fn reality_private_and_public_projections_are_corresponding() {
        let snapshot = generate_fresh_credential_snapshot(request()).unwrap();
        let windows = windows_projection(&snapshot);
        let vm = vm_projection(&snapshot);
        let public = windows.reality_identity.as_ref().unwrap();
        let private = vm.reality_identity.as_ref().unwrap();

        assert_eq!(public.generation, 3);
        assert_eq!(private.generation, 3);
        assert_reality_pair(
            &private.direct.as_ref().unwrap().private_key,
            &public.direct.as_ref().unwrap().public_key,
        );
        assert_reality_pair(
            &private.warp.as_ref().unwrap().private_key,
            &public.warp.as_ref().unwrap().public_key,
        );
    }

    #[test]
    fn nested_lifecycle_generations_remain_independent() {
        let snapshot = generate_fresh_credential_snapshot(request()).unwrap();
        let windows = windows_projection(&snapshot);
        let vm = vm_projection(&snapshot);

        assert_eq!(windows.tunnel_auth.as_ref().unwrap().generation, 7);
        assert_eq!(windows.reality_identity.as_ref().unwrap().generation, 3);
        assert_eq!(vm.line2_proxy.as_ref().unwrap().generation, 2);
    }

    #[test]
    fn generated_bundles_are_canonical_and_validate() {
        let snapshot = generate_fresh_credential_snapshot(request()).unwrap();

        for bundle in [&snapshot.windows, &snapshot.vm] {
            let bytes = encode_credential_delivery_bundle(bundle).unwrap();
            assert_eq!(
                decode_credential_delivery_bundle(&bytes).unwrap(),
                bundle.clone()
            );
        }
    }

    #[test]
    fn invalid_generation_or_slot_is_rejected_before_generation() {
        let mut value = request();
        value.delivery_generation = 0;
        assert!(generate_fresh_credential_snapshot(value).is_err());

        let mut value = request();
        value.slot = CredentialDeliverySlot::Unspecified;
        assert!(generate_fresh_credential_snapshot(value).is_err());

        let mut value = request();
        value.tunnel_auth_generation = 0;
        assert!(generate_fresh_credential_snapshot(value).is_err());

        let mut value = request();
        value.reality_identity_generation = 0;
        assert!(generate_fresh_credential_snapshot(value).is_err());

        let mut value = request();
        value.line2_proxy_generation = 0;
        assert!(generate_fresh_credential_snapshot(value).is_err());
    }

    fn assert_reality_pair(private_key: &str, public_key: &str) {
        let private_bytes = URL_SAFE_NO_PAD.decode(private_key).unwrap();
        let private_bytes: [u8; 32] = private_bytes.try_into().unwrap();
        let secret = StaticSecret::from(private_bytes);
        let public = PublicKey::from(&secret);
        assert_eq!(URL_SAFE_NO_PAD.encode(public.to_bytes()), public_key);
    }
}
