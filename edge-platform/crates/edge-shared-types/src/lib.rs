pub mod edge {
    pub mod platform {
        pub mod v1 {
            tonic::include_proto!("edge.platform.v1");
        }
    }
}

pub mod release {
    pub mod v1 {
        tonic::include_proto!("edge.release.v1");
    }
}

pub use edge::platform::v1::*;
use prost::Message;
pub use release::v1::{
    CloudflareRuntime, OciImage, ReleaseSet, SchemaVersions, SingBoxRelease, VmRuntime,
    WindowsActivationState, WindowsRuntime,
};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const MIN_RELEASE_SET_SCHEMA_VERSION: u32 = 1;
pub const RELEASE_SET_SCHEMA_VERSION: u32 = 7;
pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const DB_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_CONTROLLER_ADDR: &str = "127.0.0.1:45151";
pub const WINDOWS_CONTROLLER_ENDPOINT: &str = "http://127.0.0.1:45151";

pub const CANONICAL_PRODUCTION_DESIRED_STATE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/production-desired-state.pb"));

pub fn decode_production_desired_state(bytes: &[u8]) -> Result<ProductionDesiredState, String> {
    let desired = ProductionDesiredState::decode(bytes)
        .map_err(|err| format!("production desired-state protobuf decode failed: {err}"))?;
    let canonical = desired.encode_to_vec();
    if canonical != bytes {
        return Err(
            "production desired-state bytes are not canonical protobuf encoding; refusing ambiguous authority"
                .to_owned(),
        );
    }
    Ok(desired)
}

pub fn canonical_production_desired_state() -> Result<ProductionDesiredState, String> {
    decode_production_desired_state(CANONICAL_PRODUCTION_DESIRED_STATE_BYTES)
}

pub fn encode_credential_delivery_bundle(
    bundle: &CredentialDeliveryBundle,
) -> Result<Vec<u8>, String> {
    validate_credential_delivery_bundle(bundle)?;
    Ok(bundle.encode_to_vec())
}

pub fn decode_credential_delivery_bundle(bytes: &[u8]) -> Result<CredentialDeliveryBundle, String> {
    let bundle = CredentialDeliveryBundle::decode(bytes)
        .map_err(|err| format!("credential-delivery protobuf decode failed: {err}"))?;
    validate_credential_delivery_bundle(&bundle)?;
    if bundle.encode_to_vec() != bytes {
        return Err("credential-delivery bundle is not canonical protobuf encoding".to_owned());
    }
    Ok(bundle)
}

pub fn validate_credential_delivery_bundle(
    bundle: &CredentialDeliveryBundle,
) -> Result<(), String> {
    if bundle.schema_version != 1 {
        return Err(format!(
            "unsupported credential-delivery schema_version {}",
            bundle.schema_version
        ));
    }
    if bundle.generation == 0 {
        return Err("credential-delivery generation must be greater than zero".to_owned());
    }

    let projection = CredentialProjectionKind::try_from(bundle.projection)
        .map_err(|_| "credential-delivery projection is unknown".to_owned())?;
    if projection == CredentialProjectionKind::Unspecified {
        return Err("credential-delivery projection is required".to_owned());
    }
    let slot = CredentialDeliverySlot::try_from(bundle.slot)
        .map_err(|_| "credential-delivery slot is unknown".to_owned())?;

    if bundle.dummy_non_secret {
        if slot != CredentialDeliverySlot::Unspecified {
            return Err(
                "dummy credential-delivery bundle must not claim a real A/B slot".to_owned(),
            );
        }
        if bundle.payload.is_some() {
            return Err(
                "dummy credential-delivery bundle must not carry a real payload".to_owned(),
            );
        }
        return Ok(());
    }
    if slot == CredentialDeliverySlot::Unspecified {
        return Err("real credential-delivery bundle requires fixed slot A or B".to_owned());
    }

    let payload = bundle
        .payload
        .as_ref()
        .ok_or_else(|| "real credential-delivery bundle requires a typed payload".to_owned())?;
    match (projection, payload) {
        (
            CredentialProjectionKind::Windows,
            credential_delivery_bundle::Payload::Windows(value),
        ) => validate_windows_credential_projection(value),
        (CredentialProjectionKind::Vm, credential_delivery_bundle::Payload::Vm(value)) => {
            validate_vm_credential_projection(value)
        }
        (
            CredentialProjectionKind::Windows,
            credential_delivery_bundle::Payload::WindowsRotation(value),
        ) => validate_windows_credential_rotation_delta(bundle.generation, value),
        (CredentialProjectionKind::Vm, credential_delivery_bundle::Payload::VmRotation(value)) => {
            validate_vm_credential_rotation_delta(bundle.generation, value)
        }
        (
            CredentialProjectionKind::Windows,
            credential_delivery_bundle::Payload::Vm(_)
            | credential_delivery_bundle::Payload::VmRotation(_),
        ) => Err("Windows credential-delivery bundle cannot carry a VM payload".to_owned()),
        (
            CredentialProjectionKind::Vm,
            credential_delivery_bundle::Payload::Windows(_)
            | credential_delivery_bundle::Payload::WindowsRotation(_),
        ) => Err("VM credential-delivery bundle cannot carry a Windows payload".to_owned()),
        (CredentialProjectionKind::Unspecified, _) => unreachable!("validated above"),
    }
}

fn validate_windows_credential_projection(
    value: &WindowsCredentialProjection,
) -> Result<(), String> {
    let tunnel_auth = value
        .tunnel_auth
        .as_ref()
        .ok_or_else(|| "Windows credential projection requires tunnel authentication".to_owned())?;
    validate_tunnel_auth_generation("WindowsCredentialProjection.tunnel_auth", tunnel_auth)?;

    let reality_identity = value
        .reality_identity
        .as_ref()
        .ok_or_else(|| "Windows credential projection requires Reality identity".to_owned())?;
    validate_reality_public_generation(
        "WindowsCredentialProjection.reality_identity",
        reality_identity,
    )
}

fn validate_vm_credential_projection(value: &VmCredentialProjection) -> Result<(), String> {
    let tunnel_auth = value
        .tunnel_auth
        .as_ref()
        .ok_or_else(|| "VM credential projection requires tunnel authentication".to_owned())?;
    validate_tunnel_auth_generation("VmCredentialProjection.tunnel_auth", tunnel_auth)?;

    let reality_identity = value
        .reality_identity
        .as_ref()
        .ok_or_else(|| "VM credential projection requires Reality identity".to_owned())?;
    validate_reality_private_generation(
        "VmCredentialProjection.reality_identity",
        reality_identity,
    )?;

    let line2 = value
        .line2_proxy
        .as_ref()
        .ok_or_else(|| "VM credential projection requires Line 2 proxy credentials".to_owned())?;
    validate_proxy_credential_generation("VmCredentialProjection.line2_proxy", line2)
}

fn validate_proxy_credential_generation(
    label: &str,
    value: &ProxyCredentialGeneration,
) -> Result<(), String> {
    if value.generation == 0 {
        return Err(format!("{label}.generation must be greater than zero"));
    }
    validate_lower_hex(&format!("{label}.password"), &value.password, 64)
}

fn validate_rotation_class(value: i32) -> Result<CredentialRotationClass, String> {
    let class = CredentialRotationClass::try_from(value)
        .map_err(|_| "credential rotation class is unknown".to_owned())?;
    if class == CredentialRotationClass::Unspecified {
        return Err("credential rotation class is required".to_owned());
    }
    Ok(class)
}

fn validate_windows_credential_rotation_delta(
    delivery_generation: u64,
    value: &WindowsCredentialRotationDelta,
) -> Result<(), String> {
    let class = validate_rotation_class(value.credential_class)?;
    match class {
        CredentialRotationClass::TunnelAuth => {
            let tunnel = value
                .tunnel_auth
                .as_ref()
                .ok_or_else(|| "Windows tunnel-auth rotation requires tunnel_auth".to_owned())?;
            if value.reality_identity.is_some() {
                return Err(
                    "Windows tunnel-auth rotation must not carry Reality identity".to_owned(),
                );
            }
            validate_tunnel_auth_generation("WindowsCredentialRotationDelta.tunnel_auth", tunnel)?;
            if tunnel.generation != delivery_generation {
                return Err(
                    "Windows tunnel-auth rotation generation must equal delivery generation"
                        .to_owned(),
                );
            }
            Ok(())
        }
        CredentialRotationClass::RealityIdentity => {
            if value.tunnel_auth.is_some() {
                return Err(
                    "Windows Reality rotation must not carry tunnel authentication".to_owned(),
                );
            }
            let reality = value
                .reality_identity
                .as_ref()
                .ok_or_else(|| "Windows Reality rotation requires reality_identity".to_owned())?;
            validate_reality_public_generation(
                "WindowsCredentialRotationDelta.reality_identity",
                reality,
            )?;
            if reality.generation != delivery_generation {
                return Err(
                    "Windows Reality rotation generation must equal delivery generation".to_owned(),
                );
            }
            Ok(())
        }
        CredentialRotationClass::Line2ProxyAuth => {
            if value.tunnel_auth.is_some() || value.reality_identity.is_some() {
                return Err("Windows Line 2 rotation carries no Windows secret material".to_owned());
            }
            Ok(())
        }
        CredentialRotationClass::Unspecified => unreachable!("validated above"),
    }
}

fn validate_vm_credential_rotation_delta(
    delivery_generation: u64,
    value: &VmCredentialRotationDelta,
) -> Result<(), String> {
    let class = validate_rotation_class(value.credential_class)?;
    match class {
        CredentialRotationClass::TunnelAuth => {
            let tunnel = value
                .tunnel_auth
                .as_ref()
                .ok_or_else(|| "VM tunnel-auth rotation requires tunnel_auth".to_owned())?;
            if value.reality_identity.is_some() || value.line2_proxy.is_some() {
                return Err(
                    "VM tunnel-auth rotation must carry only tunnel authentication".to_owned(),
                );
            }
            validate_tunnel_auth_generation("VmCredentialRotationDelta.tunnel_auth", tunnel)?;
            if tunnel.generation != delivery_generation {
                return Err(
                    "VM tunnel-auth rotation generation must equal delivery generation".to_owned(),
                );
            }
            Ok(())
        }
        CredentialRotationClass::RealityIdentity => {
            if value.tunnel_auth.is_some() || value.line2_proxy.is_some() {
                return Err("VM Reality rotation must carry only Reality identity".to_owned());
            }
            let reality = value
                .reality_identity
                .as_ref()
                .ok_or_else(|| "VM Reality rotation requires reality_identity".to_owned())?;
            validate_reality_private_generation(
                "VmCredentialRotationDelta.reality_identity",
                reality,
            )?;
            if reality.generation != delivery_generation {
                return Err(
                    "VM Reality rotation generation must equal delivery generation".to_owned(),
                );
            }
            Ok(())
        }
        CredentialRotationClass::Line2ProxyAuth => {
            if value.tunnel_auth.is_some() || value.reality_identity.is_some() {
                return Err("VM Line 2 rotation must carry only line2_proxy".to_owned());
            }
            let line2 = value
                .line2_proxy
                .as_ref()
                .ok_or_else(|| "VM Line 2 rotation requires line2_proxy".to_owned())?;
            validate_proxy_credential_generation("VmCredentialRotationDelta.line2_proxy", line2)?;
            if line2.generation != delivery_generation {
                return Err(
                    "VM Line 2 rotation generation must equal delivery generation".to_owned(),
                );
            }
            Ok(())
        }
        CredentialRotationClass::Unspecified => unreachable!("validated above"),
    }
}

fn validate_tunnel_auth_generation(
    label: &str,
    value: &TunnelAuthenticationGeneration,
) -> Result<(), String> {
    if value.generation == 0 {
        return Err(format!("{label}.generation must be greater than zero"));
    }
    validate_tunnel_authentication(
        &format!("{label}.direct"),
        value
            .direct
            .as_ref()
            .ok_or_else(|| format!("{label}.direct is required"))?,
    )?;
    validate_tunnel_authentication(
        &format!("{label}.warp"),
        value
            .warp
            .as_ref()
            .ok_or_else(|| format!("{label}.warp is required"))?,
    )
}

fn validate_tunnel_authentication(label: &str, value: &TunnelAuthentication) -> Result<(), String> {
    validate_lower_uuid(&format!("{label}.vless_uuid"), &value.vless_uuid)?;
    validate_lower_hex(
        &format!("{label}.hysteria2_password"),
        &value.hysteria2_password,
        64,
    )?;
    validate_lower_hex(
        &format!("{label}.reality_short_id"),
        &value.reality_short_id,
        16,
    )
}

fn validate_reality_public_generation(
    label: &str,
    value: &RealityPublicIdentityGeneration,
) -> Result<(), String> {
    if value.generation == 0 {
        return Err(format!("{label}.generation must be greater than zero"));
    }
    validate_reality_public_identity(
        &format!("{label}.direct"),
        value
            .direct
            .as_ref()
            .ok_or_else(|| format!("{label}.direct is required"))?,
    )?;
    validate_reality_public_identity(
        &format!("{label}.warp"),
        value
            .warp
            .as_ref()
            .ok_or_else(|| format!("{label}.warp is required"))?,
    )
}

fn validate_reality_private_generation(
    label: &str,
    value: &RealityPrivateIdentityGeneration,
) -> Result<(), String> {
    if value.generation == 0 {
        return Err(format!("{label}.generation must be greater than zero"));
    }
    validate_reality_private_identity(
        &format!("{label}.direct"),
        value
            .direct
            .as_ref()
            .ok_or_else(|| format!("{label}.direct is required"))?,
    )?;
    validate_reality_private_identity(
        &format!("{label}.warp"),
        value
            .warp
            .as_ref()
            .ok_or_else(|| format!("{label}.warp is required"))?,
    )
}

fn validate_reality_public_identity(
    label: &str,
    value: &RealityPublicIdentity,
) -> Result<(), String> {
    validate_reality_key(&format!("{label}.public_key"), &value.public_key)
}

fn validate_reality_private_identity(
    label: &str,
    value: &RealityPrivateIdentity,
) -> Result<(), String> {
    validate_reality_key(&format!("{label}.private_key"), &value.private_key)
}

fn validate_lower_uuid(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 36
        || !value.chars().enumerate().all(|(index, ch)| match index {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
    {
        return Err(format!("{label} must be a lowercase UUID"));
    }
    Ok(())
}

fn validate_reality_key(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(format!(
            "{label} must be a 43-character unpadded base64url X25519 key"
        ));
    }
    Ok(())
}

pub fn credential_delivery_bundle_sha256(
    bundle: &CredentialDeliveryBundle,
) -> Result<String, String> {
    let bytes = encode_credential_delivery_bundle(bundle)?;
    Ok(ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn credential_delivery_is_rotation_delta(bundle: &CredentialDeliveryBundle) -> bool {
    matches!(
        bundle.payload.as_ref(),
        Some(credential_delivery_bundle::Payload::WindowsRotation(_))
            | Some(credential_delivery_bundle::Payload::VmRotation(_))
    )
}

pub fn local_credential_bundle_ref(
    bundle: &CredentialDeliveryBundle,
) -> Result<LocalCredentialBundleRef, String> {
    validate_credential_delivery_bundle(bundle)?;
    if bundle.dummy_non_secret {
        return Err("local credential state cannot reference a dummy delivery bundle".to_owned());
    }
    if credential_delivery_is_rotation_delta(bundle) {
        return Err(
            "local credential state cannot reference an unmaterialized rotation delta".to_owned(),
        );
    }
    Ok(LocalCredentialBundleRef {
        generation: bundle.generation,
        slot: bundle.slot,
        sha256: credential_delivery_bundle_sha256(bundle)?,
    })
}

pub fn materialize_credential_delivery_candidate(
    active: Option<&CredentialDeliveryBundle>,
    delivery: &CredentialDeliveryBundle,
) -> Result<CredentialDeliveryBundle, String> {
    validate_credential_delivery_bundle(delivery)?;
    if delivery.dummy_non_secret {
        return Err("credential candidate materialization refuses dummy bundles".to_owned());
    }
    if !credential_delivery_is_rotation_delta(delivery) {
        local_credential_bundle_ref(delivery)?;
        return Ok(delivery.clone());
    }

    let active = active.ok_or_else(|| {
        "credential rotation delta requires one validated active local projection".to_owned()
    })?;
    validate_credential_delivery_bundle(active)?;
    local_credential_bundle_ref(active)?;
    if active.projection != delivery.projection {
        return Err(
            "credential rotation delta projection differs from active projection".to_owned(),
        );
    }
    if active.generation == delivery.generation {
        return Err("credential rotation delivery generation must differ from active".to_owned());
    }
    if active.slot == delivery.slot {
        return Err("credential rotation delta must use the slot opposite active".to_owned());
    }

    let payload = match (active.payload.as_ref(), delivery.payload.as_ref()) {
        (
            Some(credential_delivery_bundle::Payload::Windows(active)),
            Some(credential_delivery_bundle::Payload::WindowsRotation(delta)),
        ) => {
            let mut next = active.clone();
            match validate_rotation_class(delta.credential_class)? {
                CredentialRotationClass::TunnelAuth => {
                    next.tunnel_auth = delta.tunnel_auth.clone();
                }
                CredentialRotationClass::RealityIdentity => {
                    next.reality_identity = delta.reality_identity.clone();
                }
                CredentialRotationClass::Line2ProxyAuth => {}
                CredentialRotationClass::Unspecified => unreachable!("validated above"),
            }
            credential_delivery_bundle::Payload::Windows(next)
        }
        (
            Some(credential_delivery_bundle::Payload::Vm(active)),
            Some(credential_delivery_bundle::Payload::VmRotation(delta)),
        ) => {
            let mut next = active.clone();
            match validate_rotation_class(delta.credential_class)? {
                CredentialRotationClass::TunnelAuth => {
                    next.tunnel_auth = delta.tunnel_auth.clone();
                }
                CredentialRotationClass::RealityIdentity => {
                    next.reality_identity = delta.reality_identity.clone();
                }
                CredentialRotationClass::Line2ProxyAuth => {
                    next.line2_proxy = delta.line2_proxy.clone();
                }
                CredentialRotationClass::Unspecified => unreachable!("validated above"),
            }
            credential_delivery_bundle::Payload::Vm(next)
        }
        _ => {
            return Err(
                "credential rotation delta and active projection payloads do not match".to_owned(),
            );
        }
    };

    let materialized = CredentialDeliveryBundle {
        schema_version: delivery.schema_version,
        generation: delivery.generation,
        projection: delivery.projection,
        dummy_non_secret: false,
        slot: delivery.slot,
        payload: Some(payload),
    };
    validate_credential_delivery_bundle(&materialized)?;
    local_credential_bundle_ref(&materialized)?;
    Ok(materialized)
}

pub fn encode_local_credential_state(state: &LocalCredentialState) -> Result<Vec<u8>, String> {
    validate_local_credential_state(state)?;
    Ok(state.encode_to_vec())
}

pub fn decode_local_credential_state(bytes: &[u8]) -> Result<LocalCredentialState, String> {
    let state = LocalCredentialState::decode(bytes)
        .map_err(|err| format!("local credential state protobuf decode failed: {err}"))?;
    validate_local_credential_state(&state)?;
    if state.encode_to_vec() != bytes {
        return Err("local credential state is not canonical protobuf encoding".to_owned());
    }
    Ok(state)
}

pub fn validate_local_credential_state(state: &LocalCredentialState) -> Result<(), String> {
    if state.schema_version != 1 {
        return Err(format!(
            "unsupported local credential state schema_version {}",
            state.schema_version
        ));
    }
    let projection = CredentialProjectionKind::try_from(state.projection)
        .map_err(|_| "local credential state projection is unknown".to_owned())?;
    if projection == CredentialProjectionKind::Unspecified {
        return Err("local credential state projection is required".to_owned());
    }

    let active = state.active.as_ref();
    let candidate = state.candidate.as_ref();
    let previous = state.previous.as_ref();
    if active.is_none() && candidate.is_none() && previous.is_none() {
        return Err("local credential state must reference at least one bundle".to_owned());
    }
    if previous.is_some() && active.is_none() {
        return Err("local credential previous state requires an active bundle".to_owned());
    }
    if candidate.is_some() && previous.is_some() {
        return Err(
            "local credential candidate and previous cannot coexist with fixed A/B transport"
                .to_owned(),
        );
    }

    for (label, reference) in [
        ("active", active),
        ("candidate", candidate),
        ("previous", previous),
    ] {
        if let Some(reference) = reference {
            validate_local_credential_bundle_ref(label, reference)?;
        }
    }

    if let (Some(left), Some(right)) = (active, candidate) {
        validate_local_credential_refs_are_opposite("active", left, "candidate", right)?;
    }
    if let (Some(left), Some(right)) = (active, previous) {
        validate_local_credential_refs_are_opposite("active", left, "previous", right)?;
    }
    Ok(())
}

pub fn verify_local_credential_bundle_reference(
    projection: CredentialProjectionKind,
    reference: &LocalCredentialBundleRef,
    bundle: &CredentialDeliveryBundle,
) -> Result<(), String> {
    validate_local_credential_bundle_ref("bundle reference", reference)?;
    validate_credential_delivery_bundle(bundle)?;
    if bundle.dummy_non_secret {
        return Err("local credential state cannot reference a dummy delivery bundle".to_owned());
    }
    if credential_delivery_is_rotation_delta(bundle) {
        return Err(
            "local credential state cannot reference an unmaterialized rotation delta".to_owned(),
        );
    }
    if bundle.projection != projection as i32 {
        return Err(
            "local credential bundle projection does not match state projection".to_owned(),
        );
    }
    if bundle.generation != reference.generation {
        return Err("local credential bundle generation does not match state reference".to_owned());
    }
    if bundle.slot != reference.slot {
        return Err("local credential bundle slot does not match state reference".to_owned());
    }
    if credential_delivery_bundle_sha256(bundle)? != reference.sha256 {
        return Err("local credential bundle digest does not match state reference".to_owned());
    }
    Ok(())
}

fn validate_local_credential_bundle_ref(
    label: &str,
    reference: &LocalCredentialBundleRef,
) -> Result<(), String> {
    if reference.generation == 0 {
        return Err(format!("{label}.generation must be greater than zero"));
    }
    let slot = CredentialDeliverySlot::try_from(reference.slot)
        .map_err(|_| format!("{label}.slot is unknown"))?;
    if !matches!(slot, CredentialDeliverySlot::A | CredentialDeliverySlot::B) {
        return Err(format!("{label}.slot must be A or B"));
    }
    validate_lower_hex(&format!("{label}.sha256"), &reference.sha256, 64)
}

fn validate_local_credential_refs_are_opposite(
    left_label: &str,
    left: &LocalCredentialBundleRef,
    right_label: &str,
    right: &LocalCredentialBundleRef,
) -> Result<(), String> {
    if left.generation == right.generation {
        return Err(format!(
            "{left_label} and {right_label} must use different delivery generations"
        ));
    }
    if left.sha256 == right.sha256 {
        return Err(format!(
            "{left_label} and {right_label} must reference different bundle digests"
        ));
    }
    if left.slot == right.slot {
        return Err(format!(
            "{left_label} and {right_label} must use opposite fixed A/B slots"
        ));
    }
    Ok(())
}

pub fn timestamp_from_unix_seconds(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

pub fn encode_release_set(release: &ReleaseSet) -> Result<Vec<u8>, String> {
    validate_release_set(release)?;
    Ok(release.encode_to_vec())
}

pub fn decode_release_set(bytes: &[u8]) -> Result<ReleaseSet, String> {
    let release = ReleaseSet::decode(bytes)
        .map_err(|err| format!("release-set protobuf decode failed: {err}"))?;
    validate_release_set(&release)?;
    let canonical = release.encode_to_vec();
    if canonical != bytes {
        return Err(
            "release-set bytes are not canonical protobuf encoding; refusing ambiguous authority"
                .to_owned(),
        );
    }
    Ok(release)
}

pub fn release_set_sha256(bytes: &[u8]) -> Result<String, String> {
    decode_release_set(bytes)?;
    Ok(ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn validate_release_set(release: &ReleaseSet) -> Result<(), String> {
    if release.schema_version < MIN_RELEASE_SET_SCHEMA_VERSION
        || release.schema_version > RELEASE_SET_SCHEMA_VERSION
    {
        return Err(format!(
            "unsupported release-set schema_version {}; supported range is {}..={}",
            release.schema_version, MIN_RELEASE_SET_SCHEMA_VERSION, RELEASE_SET_SCHEMA_VERSION
        ));
    }
    validate_lower_hex("source_revision", &release.source_revision, 40)?;

    let sing_box = release
        .sing_box
        .as_ref()
        .ok_or_else(|| "release-set sing_box is required".to_owned())?;
    validate_stable_semver("sing_box.version", &sing_box.version)?;
    validate_sha256_bytes(
        "sing_box.windows_amd64_sha256",
        &sing_box.windows_amd64_sha256,
    )?;
    validate_sha256_bytes("sing_box.linux_amd64_sha256", &sing_box.linux_amd64_sha256)?;

    let windows = release
        .windows_runtime
        .as_ref()
        .ok_or_else(|| "release-set windows_runtime is required".to_owned())?;
    validate_sha256_bytes("windows_runtime.artifact_sha256", &windows.artifact_sha256)?;
    validate_sha256_bytes(
        "windows_runtime.controller_sha256",
        &windows.controller_sha256,
    )?;
    validate_sha256_bytes("windows_runtime.console_sha256", &windows.console_sha256)?;
    validate_sha256_bytes("windows_runtime.sing_box_sha256", &windows.sing_box_sha256)?;
    if windows.sing_box_sha256 != sing_box.windows_amd64_sha256 {
        return Err(
            "windows_runtime.sing_box_sha256 must equal sing_box.windows_amd64_sha256".to_owned(),
        );
    }
    if release.schema_version < 5 {
        if !windows.input_sha256.is_empty() || !windows.source_revision.is_empty() {
            return Err(
                "ReleaseSet schemas before v5 must not contain Windows reuse identity".to_owned(),
            );
        }
    } else {
        validate_sha256_bytes("windows_runtime.input_sha256", &windows.input_sha256)?;
        validate_lower_hex(
            "windows_runtime.source_revision",
            &windows.source_revision,
            40,
        )?;
    }
    if release.schema_version < 6 {
        if !windows.diagnostic_sha256.is_empty() {
            return Err(
                "ReleaseSet schemas before v6 must not contain Windows diagnostic identity"
                    .to_owned(),
            );
        }
    } else {
        validate_sha256_bytes(
            "windows_runtime.diagnostic_sha256",
            &windows.diagnostic_sha256,
        )?;
    }

    let vm = release
        .vm_runtime
        .as_ref()
        .ok_or_else(|| "release-set vm_runtime is required".to_owned())?;
    validate_sha256_bytes("vm_runtime.edge_agent_sha256", &vm.edge_agent_sha256)?;
    match release.schema_version {
        1 => {
            if !vm.edge_controller_sha256.is_empty() {
                return Err(
                    "schema v1 must not contain vm_runtime.edge_controller_sha256".to_owned(),
                );
            }
            if !vm.edge_orchestrator_sha256.is_empty() {
                return Err(
                    "schema v1 must not contain vm_runtime.edge_orchestrator_sha256".to_owned(),
                );
            }
            if !vm.runtime_input_sha256.is_empty() || !vm.runtime_source_revision.is_empty() {
                return Err("schema v1 must not contain VM runtime reuse identity".to_owned());
            }
        }
        2 => {
            validate_sha256_bytes(
                "vm_runtime.edge_controller_sha256",
                &vm.edge_controller_sha256,
            )?;
            if !vm.edge_orchestrator_sha256.is_empty() {
                return Err(
                    "schema v2 must not contain vm_runtime.edge_orchestrator_sha256".to_owned(),
                );
            }
            if !vm.runtime_input_sha256.is_empty() || !vm.runtime_source_revision.is_empty() {
                return Err("schema v2 must not contain VM runtime reuse identity".to_owned());
            }
        }
        3 => {
            validate_sha256_bytes(
                "vm_runtime.edge_controller_sha256",
                &vm.edge_controller_sha256,
            )?;
            validate_sha256_bytes(
                "vm_runtime.edge_orchestrator_sha256",
                &vm.edge_orchestrator_sha256,
            )?;
            if !vm.runtime_input_sha256.is_empty() || !vm.runtime_source_revision.is_empty() {
                return Err("schema v3 must not contain VM runtime reuse identity".to_owned());
            }
        }
        4 | 5 | 6 | 7 => {
            validate_sha256_bytes(
                "vm_runtime.edge_controller_sha256",
                &vm.edge_controller_sha256,
            )?;
            validate_sha256_bytes(
                "vm_runtime.edge_orchestrator_sha256",
                &vm.edge_orchestrator_sha256,
            )?;
            validate_sha256_bytes("vm_runtime.runtime_input_sha256", &vm.runtime_input_sha256)?;
            validate_lower_hex(
                "vm_runtime.runtime_source_revision",
                &vm.runtime_source_revision,
                40,
            )?;
        }
        _ => unreachable!("release-set schema range was validated above"),
    }
    if release.schema_version < 7 {
        if !vm.application_bundle_sha256.is_empty() {
            return Err(
                "ReleaseSet schemas before v7 must not contain VM application bundle identity"
                    .to_owned(),
            );
        }
    } else {
        validate_sha256_bytes(
            "vm_runtime.application_bundle_sha256",
            &vm.application_bundle_sha256,
        )?;
    }

    validate_oci_image(
        "vm_runtime.sing_box_image",
        vm.sing_box_image
            .as_ref()
            .ok_or_else(|| "vm_runtime.sing_box_image is required".to_owned())?,
    )?;
    validate_oci_image(
        "vm_runtime.warp_egress_image",
        vm.warp_egress_image
            .as_ref()
            .ok_or_else(|| "vm_runtime.warp_egress_image is required".to_owned())?,
    )?;
    validate_version_token(
        "vm_runtime.docker_engine_version",
        &vm.docker_engine_version,
    )?;
    validate_version_token("vm_runtime.containerd_version", &vm.containerd_version)?;
    validate_version_token("vm_runtime.compose_version", &vm.compose_version)?;

    let cloudflare = release
        .cloudflare
        .as_ref()
        .ok_or_else(|| "release-set cloudflare is required".to_owned())?;
    validate_version_token("cloudflare.warp_version", &cloudflare.warp_version)?;
    validate_oci_image(
        "cloudflare.mesh_image",
        cloudflare
            .mesh_image
            .as_ref()
            .ok_or_else(|| "cloudflare.mesh_image is required".to_owned())?,
    )?;

    let schemas = release
        .schemas
        .as_ref()
        .ok_or_else(|| "release-set schemas is required".to_owned())?;
    if schemas.config_schema == 0 || schemas.db_schema == 0 {
        return Err("config_schema and db_schema must be non-zero".to_owned());
    }

    Ok(())
}

pub fn encode_windows_privileged_request(
    request: &WindowsPrivilegedRequest,
) -> Result<Vec<u8>, String> {
    validate_windows_privileged_request(request)?;
    Ok(request.encode_to_vec())
}

pub fn decode_windows_privileged_request(bytes: &[u8]) -> Result<WindowsPrivilegedRequest, String> {
    let request = WindowsPrivilegedRequest::decode(bytes)
        .map_err(|err| format!("Windows privileged request protobuf decode failed: {err}"))?;
    validate_windows_privileged_request(&request)?;
    if request.encode_to_vec() != bytes {
        return Err("Windows privileged request is not canonical protobuf encoding".to_owned());
    }
    Ok(request)
}

pub fn validate_windows_privileged_request(
    request: &WindowsPrivilegedRequest,
) -> Result<(), String> {
    if request.schema_version != 1 {
        return Err(format!(
            "unsupported Windows privileged request schema_version {}",
            request.schema_version
        ));
    }
    validate_safe_runtime_token(
        "WindowsPrivilegedRequest.request_id",
        &request.request_id,
        160,
    )?;
    let operation = WindowsPrivilegedOperation::try_from(request.operation)
        .map_err(|_| "WindowsPrivilegedRequest.operation is invalid".to_owned())?;
    match operation {
        WindowsPrivilegedOperation::Unspecified => {
            return Err("WindowsPrivilegedRequest.operation is required".to_owned());
        }
        WindowsPrivilegedOperation::Ping => {
            if request.accepted_revision.is_some()
                || request.release_set_sha256.is_some()
                || request.credential_generation.is_some()
                || request.credential_transition_action.is_some()
            {
                return Err(
                    "PING request must not carry release or credential authority".to_owned(),
                );
            }
        }
        WindowsPrivilegedOperation::RuntimeEvidence => {
            if request.accepted_revision.is_some()
                || request.release_set_sha256.is_some()
                || request.credential_generation.is_some()
                || request.credential_transition_action.is_some()
            {
                return Err("RUNTIME_EVIDENCE request must carry no mutation authority".to_owned());
            }
        }
        WindowsPrivilegedOperation::RestartControllerService => {
            if request.accepted_revision.is_some()
                || request.release_set_sha256.is_some()
                || request.credential_generation.is_some()
                || request.credential_transition_action.is_some()
            {
                return Err(
                    "RESTART_CONTROLLER_SERVICE request must carry no caller-selected authority"
                        .to_owned(),
                );
            }
        }
        WindowsPrivilegedOperation::RollbackPreviousRelease => {
            if request.accepted_revision.is_some()
                || request.release_set_sha256.is_some()
                || request.credential_generation.is_some()
                || request.credential_transition_action.is_some()
            {
                return Err(
                    "ROLLBACK_PREVIOUS_RELEASE carries no caller-selected release authority"
                        .to_owned(),
                );
            }
        }
        WindowsPrivilegedOperation::ActivateRelease
        | WindowsPrivilegedOperation::ReinstallAcceptedRelease => {
            let revision = request
                .accepted_revision
                .as_deref()
                .ok_or_else(|| "release operation requires accepted_revision".to_owned())?;
            let release = request
                .release_set_sha256
                .as_deref()
                .ok_or_else(|| "release operation requires release_set_sha256".to_owned())?;
            if request.credential_generation.is_some()
                || request.credential_transition_action.is_some()
            {
                return Err("release operation must not carry credential authority".to_owned());
            }
            validate_lower_hex("WindowsPrivilegedRequest.accepted_revision", revision, 40)?;
            validate_lower_hex("WindowsPrivilegedRequest.release_set_sha256", release, 64)?;
        }
        WindowsPrivilegedOperation::AdmitCredential => {
            return Err(
                "ADMIT_CREDENTIAL is retired; exact-generation STAGE_CREDENTIAL is the sole credential data-plane gate"
                    .to_owned(),
            );
        }
        WindowsPrivilegedOperation::StageCredential => {
            if request.accepted_revision.is_some()
                || request.release_set_sha256.is_some()
                || request.credential_transition_action.is_some()
            {
                return Err(
                    "credential stage request must carry generation authority only".to_owned(),
                );
            }
            let generation = request
                .credential_generation
                .ok_or_else(|| "credential stage requires credential_generation".to_owned())?;
            if generation == 0 {
                return Err("credential stage generation must be greater than zero".to_owned());
            }
        }
        WindowsPrivilegedOperation::PrepareCredentialAccessBootstrap
        | WindowsPrivilegedOperation::InstallCredentialAccessBootstrap => {
            if request.accepted_revision.is_some()
                || request.release_set_sha256.is_some()
                || request.credential_generation.is_some()
                || request.credential_transition_action.is_some()
            {
                return Err(
                    "credential Access bootstrap request must carry no release or application credential authority"
                        .to_owned(),
                );
            }
        }
        WindowsPrivilegedOperation::CredentialTransition => {
            if request.accepted_revision.is_some()
                || request.release_set_sha256.is_some()
                || request.credential_generation.is_some()
            {
                return Err("CREDENTIAL_TRANSITION must carry action authority only".to_owned());
            }
            let action = request
                .credential_transition_action
                .ok_or_else(|| {
                    "CREDENTIAL_TRANSITION requires credential_transition_action".to_owned()
                })
                .and_then(|value| {
                    CredentialTransitionAction::try_from(value)
                        .map_err(|_| "credential_transition_action is invalid".to_owned())
                })?;
            if action == CredentialTransitionAction::Unspecified {
                return Err("credential_transition_action is required".to_owned());
            }
        }
    }
    Ok(())
}

pub fn parse_credential_transition_action(
    value: &str,
) -> Result<CredentialTransitionAction, String> {
    match value {
        "validate-candidate" => Ok(CredentialTransitionAction::ValidateCandidate),
        "apply-candidate" => Ok(CredentialTransitionAction::ApplyCandidate),
        "promote" => Ok(CredentialTransitionAction::Promote),
        "apply-legacy" => Ok(CredentialTransitionAction::ApplyLegacy),
        "apply-active" => Ok(CredentialTransitionAction::ApplyActive),
        "retire-legacy" => Ok(CredentialTransitionAction::RetireLegacy),
        "discard-candidate" => Ok(CredentialTransitionAction::DiscardCandidate),
        "rollback-previous" => Ok(CredentialTransitionAction::RollbackPrevious),
        "drop-previous" => Ok(CredentialTransitionAction::DropPrevious),
        _ => Err(format!("unsupported credential transition action: {value}")),
    }
}

pub fn encode_windows_privileged_result(
    result: &WindowsPrivilegedResult,
) -> Result<Vec<u8>, String> {
    validate_windows_privileged_result(result)?;
    Ok(result.encode_to_vec())
}

pub fn decode_windows_privileged_result(bytes: &[u8]) -> Result<WindowsPrivilegedResult, String> {
    let result = WindowsPrivilegedResult::decode(bytes)
        .map_err(|err| format!("Windows privileged result protobuf decode failed: {err}"))?;
    validate_windows_privileged_result(&result)?;
    if result.encode_to_vec() != bytes {
        return Err("Windows privileged result is not canonical protobuf encoding".to_owned());
    }
    Ok(result)
}

pub fn validate_windows_privileged_result(result: &WindowsPrivilegedResult) -> Result<(), String> {
    if result.schema_version != 1 {
        return Err(format!(
            "unsupported Windows privileged result schema_version {}",
            result.schema_version
        ));
    }
    validate_safe_runtime_token(
        "WindowsPrivilegedResult.request_id",
        &result.request_id,
        160,
    )?;
    validate_safe_runtime_token("WindowsPrivilegedResult.code", &result.code, 96)?;
    if result.detail.len() > 1024 || result.detail.chars().any(|ch| ch.is_control()) {
        return Err("WindowsPrivilegedResult.detail is invalid".to_owned());
    }
    if let Some(release) = result.active_release_set_sha256.as_deref() {
        validate_lower_hex(
            "WindowsPrivilegedResult.active_release_set_sha256",
            release,
            64,
        )?;
    }
    Ok(())
}

pub fn encode_windows_runtime_state(state: &WindowsRuntimeState) -> Result<Vec<u8>, String> {
    validate_windows_runtime_state(state)?;
    Ok(state.encode_to_vec())
}

pub fn decode_windows_runtime_state(bytes: &[u8]) -> Result<WindowsRuntimeState, String> {
    let state = WindowsRuntimeState::decode(bytes)
        .map_err(|err| format!("Windows runtime-state protobuf decode failed: {err}"))?;
    validate_windows_runtime_state(&state)?;
    if state.encode_to_vec() != bytes {
        return Err("Windows runtime state is not canonical protobuf encoding".to_owned());
    }
    Ok(state)
}

pub fn validate_windows_runtime_state(state: &WindowsRuntimeState) -> Result<(), String> {
    if state.schema_version != 1 {
        return Err(format!(
            "unsupported Windows runtime-state schema_version {}",
            state.schema_version
        ));
    }
    if let Some(label) = state.deployment_label.as_deref() {
        validate_safe_runtime_token("WindowsRuntimeState.deployment_label", label, 160)?;
    }
    validate_safe_runtime_token("WindowsRuntimeState.instance_id", &state.instance_id, 160)?;
    validate_ipv4_literal("WindowsRuntimeState.server_ip", &state.server_ip)?;
    validate_windows_tunnel_binding(
        "WindowsRuntimeState.direct",
        state
            .direct
            .as_ref()
            .ok_or_else(|| "WindowsRuntimeState.direct is required".to_owned())?,
    )?;
    validate_windows_tunnel_binding(
        "WindowsRuntimeState.warp",
        state
            .warp
            .as_ref()
            .ok_or_else(|| "WindowsRuntimeState.warp is required".to_owned())?,
    )?;
    Ok(())
}

fn validate_windows_tunnel_binding(
    label: &str,
    value: &WindowsTunnelBinding,
) -> Result<(), String> {
    validate_runtime_dns_name(&format!("{label}.domain"), &value.domain)?;
    if value.hy2_port == 0 || value.hy2_port > 65535 {
        return Err(format!("{label}.hy2_port must be in 1..=65535"));
    }
    if value.vless_port == 0 || value.vless_port > 65535 {
        return Err(format!("{label}.vless_port must be in 1..=65535"));
    }
    for (field, token, max_len) in [
        ("hy2_password", value.hy2_password.as_str(), 256usize),
        ("vless_uuid", value.vless_uuid.as_str(), 128usize),
        (
            "reality_public_key",
            value.reality_public_key.as_str(),
            256usize,
        ),
        ("reality_short_id", value.reality_short_id.as_str(), 64usize),
    ] {
        validate_safe_runtime_token(&format!("{label}.{field}"), token, max_len)?;
    }
    Ok(())
}

fn validate_safe_runtime_token(label: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max_len || value.chars().any(|ch| ch.is_control()) {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_runtime_dns_name(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 253
        || value != value.to_ascii_lowercase()
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || part.starts_with('-')
                || part.ends_with('-')
                || !part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
    {
        return Err(format!("{label} must be a normalized lowercase DNS name"));
    }
    Ok(())
}

fn validate_ipv4_literal(label: &str, value: &str) -> Result<(), String> {
    let parsed = value
        .parse::<std::net::IpAddr>()
        .map_err(|_| format!("{label} must be an IPv4 literal"))?;
    if !parsed.is_ipv4() {
        return Err(format!("{label} must be an IPv4 literal"));
    }
    Ok(())
}

pub fn encode_windows_activation_state(state: &WindowsActivationState) -> Result<Vec<u8>, String> {
    validate_windows_activation_state(state)?;
    Ok(state.encode_to_vec())
}

pub fn decode_windows_activation_state(bytes: &[u8]) -> Result<WindowsActivationState, String> {
    let state = WindowsActivationState::decode(bytes)
        .map_err(|err| format!("Windows activation protobuf decode failed: {err}"))?;
    validate_windows_activation_state(&state)?;
    if state.encode_to_vec() != bytes {
        return Err("Windows activation state is not canonical protobuf encoding".to_owned());
    }
    Ok(state)
}

pub fn validate_windows_activation_state(state: &WindowsActivationState) -> Result<(), String> {
    if state.schema_version != 1 {
        return Err(format!(
            "unsupported Windows activation schema_version {}",
            state.schema_version
        ));
    }
    validate_lower_hex(
        "WindowsActivationState.release_set_sha256",
        &state.release_set_sha256,
        64,
    )?;
    validate_lower_hex(
        "WindowsActivationState.source_revision",
        &state.source_revision,
        40,
    )?;
    for (label, value) in [
        ("release_dir", state.release_dir.as_str()),
        ("controller_path", state.controller_path.as_str()),
        ("console_path", state.console_path.as_str()),
        ("sing_box_path", state.sing_box_path.as_str()),
        ("diagnostic_path", state.diagnostic_path.as_str()),
    ] {
        if value.is_empty() || value.len() > 1024 || value.contains('\0') {
            return Err(format!("WindowsActivationState.{label} is invalid"));
        }
    }
    for (label, value) in [
        ("controller_sha256", state.controller_sha256.as_slice()),
        ("console_sha256", state.console_sha256.as_slice()),
        ("sing_box_sha256", state.sing_box_sha256.as_slice()),
        ("diagnostic_sha256", state.diagnostic_sha256.as_slice()),
    ] {
        validate_sha256_bytes(&format!("WindowsActivationState.{label}"), value)?;
    }
    Ok(())
}

pub fn verify_windows_activation_files(state: &WindowsActivationState) -> Result<(), String> {
    validate_windows_activation_state(state)?;
    for (label, path, expected) in [
        (
            "controller",
            state.controller_path.as_str(),
            state.controller_sha256.as_slice(),
        ),
        (
            "console",
            state.console_path.as_str(),
            state.console_sha256.as_slice(),
        ),
        (
            "sing-box",
            state.sing_box_path.as_str(),
            state.sing_box_sha256.as_slice(),
        ),
        (
            "diagnostic",
            state.diagnostic_path.as_str(),
            state.diagnostic_sha256.as_slice(),
        ),
    ] {
        let actual = sha256_file(Path::new(path))?;
        if actual.as_slice() != expected {
            return Err(format!(
                "{label} SHA-256 mismatch: expected {}, got {}",
                digest_to_lower_hex(expected),
                digest_to_lower_hex(&actual)
            ));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context.finish().as_ref().to_vec())
}

pub fn digest_to_lower_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_sha256_bytes(label: &str, value: &[u8]) -> Result<(), String> {
    if value.len() != 32 {
        return Err(format!("{label} must contain exactly 32 SHA-256 bytes"));
    }
    Ok(())
}

fn validate_lower_hex(label: &str, value: &str, expected_len: usize) -> Result<(), String> {
    if value.len() != expected_len
        || !value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must be exactly {expected_len} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_stable_semver(label: &str, value: &str) -> Result<(), String> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.chars().all(|ch| ch.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return Err(format!(
            "{label} must be a stable normalized x.y.z version without prerelease/build metadata"
        ));
    }
    Ok(())
}

fn validate_version_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || value.eq_ignore_ascii_case("latest")
        || value.chars().any(|ch| ch.is_ascii_whitespace())
    {
        return Err(format!(
            "{label} must be an exact non-empty version token and must not be latest"
        ));
    }
    Ok(())
}

fn validate_oci_image(label: &str, image: &OciImage) -> Result<(), String> {
    let repository = image.repository.as_str();
    if repository.is_empty()
        || repository.len() > 255
        || repository.contains('@')
        || repository.contains("//")
        || repository.ends_with('/')
        || repository.chars().any(|ch| ch.is_ascii_whitespace())
        || repository != repository.to_ascii_lowercase()
    {
        return Err(format!(
            "{label}.repository must be a normalized lowercase OCI repository without digest"
        ));
    }
    if repository
        .rsplit('/')
        .next()
        .is_some_and(|leaf| leaf.contains(':'))
    {
        return Err(format!(
            "{label}.repository must not contain a mutable image tag"
        ));
    }
    validate_sha256_bytes(&format!("{label}.sha256"), &image.sha256)
}

impl PlatformError {
    pub fn new(
        code: impl Into<String>,
        stage: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
        subsystem: ErrorSubsystem,
    ) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            message: message.into(),
            retryable,
            subsystem: subsystem as i32,
        }
    }

    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl AgentState {
    pub fn bootstrap_placeholder() -> Self {
        Self {
            healthy: true,
            ready: false,
            topology_version: "unknown".to_owned(),
            active_bundle_id: None,
            degraded_reasons: vec!["runtime inspection not implemented in phase 0".to_owned()],
            docker_reachable: false,
            compose_file_present: false,
            observed_stack_path: None,
            running_containers: Vec::new(),
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            direct_egress_ready: None,
            warp_egress_ready: None,
            mesh_runtime_ready: None,
            containers: Vec::new(),
        }
    }

    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl BootstrapRuntimeResponse {
    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl LocalRuntimeResponse {
    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl LocalSingboxState {
    pub fn placeholder(expected_config_path: impl Into<String>) -> Self {
        Self {
            process_running: false,
            managed_config: false,
            expected_config_path: expected_config_path.into(),
            active_config_path: None,
            clash_api_port: Some(9090),
            warnings: Vec::new(),
        }
    }
}

impl DeploymentSummary {
    pub fn missing() -> Self {
        Self {
            live_state_present: false,
            source_state_path: None,
            deployment_label: None,
            instance_id: None,
            server_ip: None,
            tunnel_domain: None,
        }
    }
}

impl ProviderObservation {
    pub fn placeholder() -> Self {
        Self {
            configured: false,
            compute_provider: "vultr".to_owned(),
            dns_provider: "cloudflare".to_owned(),
            warnings: vec!["provider probing not implemented in phase A".to_owned()],
        }
    }
}

impl RuntimeObservation {
    pub fn placeholder() -> Self {
        Self {
            edge_agent_reachable: false,
            runtime_kind: "docker-compose".to_owned(),
            warnings: vec!["edge-agent gRPC probing not implemented in phase A".to_owned()],
            docker_reachable: false,
            observed_stack_path: None,
            running_containers: Vec::new(),
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            topology_version: None,
            active_bundle_id: None,
            compose_file_present: false,
        }
    }

    pub fn from_agent_state(agent_state: &AgentState) -> Self {
        Self {
            edge_agent_reachable: true,
            runtime_kind: "docker-compose".to_owned(),
            warnings: agent_state.degraded_reasons.clone(),
            docker_reachable: agent_state.docker_reachable,
            observed_stack_path: agent_state.observed_stack_path.clone(),
            running_containers: agent_state.running_containers.clone(),
            missing_containers: agent_state.missing_containers.clone(),
            listening_tcp_ports: agent_state.listening_tcp_ports.clone(),
            listening_udp_ports: agent_state.listening_udp_ports.clone(),
            topology_version: Some(agent_state.topology_version.clone()),
            active_bundle_id: agent_state.active_bundle_id.clone(),
            compose_file_present: agent_state.compose_file_present,
        }
    }

    pub fn agent_unreachable(reason: impl Into<String>) -> Self {
        Self {
            edge_agent_reachable: false,
            runtime_kind: "docker-compose".to_owned(),
            warnings: vec![reason.into()],
            docker_reachable: false,
            observed_stack_path: None,
            running_containers: Vec::new(),
            missing_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            topology_version: None,
            active_bundle_id: None,
            compose_file_present: false,
        }
    }
}

impl SelectorState {
    pub fn placeholder() -> Self {
        Self {
            desired_main_route: None,
            observed_main_route: None,
            degraded: false,
            warnings: Vec::new(),
            proxy_groups: Vec::new(),
        }
    }
}

impl UbuntuProxyState {
    pub fn unavailable(note: impl Into<String>) -> Self {
        Self {
            available: false,
            host: None,
            port: None,
            url: None,
            warnings: vec![note.into()],
        }
    }
}

impl ControllerStatus {
    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl DoctorResponse {
    pub fn encode_proto(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl TraceObservation {
    pub fn unavailable(note: impl Into<String>) -> Self {
        Self {
            available: false,
            ip: None,
            warp: None,
            colo: None,
            note: Some(note.into()),
        }
    }
}

pub fn canonical_apply_bundle_digest(request: &ApplyBundleRequest) -> Result<String, String> {
    use ring::digest::{Context, SHA256};

    let bundle_id = request
        .bundle_id
        .as_deref()
        .ok_or_else(|| "digest-bound bundle requires bundle_id".to_owned())?;
    if bundle_id.is_empty()
        || bundle_id.len() > 160
        || !bundle_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err("bundle_id contains unsupported characters".to_owned());
    }

    struct Entry<'a> {
        scope: u8,
        file: &'a BundleFile,
    }

    let mut entries = Vec::new();
    entries.extend(
        request
            .stack_files
            .iter()
            .map(|file| Entry { scope: 1, file }),
    );
    entries.extend(
        request
            .host_files
            .iter()
            .map(|file| Entry { scope: 2, file }),
    );
    if let Some(file) = request.deployment_summary.as_ref() {
        entries.push(Entry { scope: 3, file });
    }
    if let Some(file) = request.agent_env_file.as_ref() {
        entries.push(Entry { scope: 4, file });
    }

    entries.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then_with(|| left.file.relative_path.cmp(&right.file.relative_path))
    });

    for pair in entries.windows(2) {
        if pair[0].scope == pair[1].scope
            && pair[0].file.relative_path == pair[1].file.relative_path
        {
            return Err(format!(
                "duplicate bundle path in scope {}: {}",
                pair[0].scope, pair[0].file.relative_path
            ));
        }
    }

    fn feed_field(context: &mut Context, bytes: &[u8]) {
        context.update(&(bytes.len() as u64).to_be_bytes());
        context.update(bytes);
    }

    let mut context = Context::new(&SHA256);
    context.update(b"sing-box-application-bundle-v1\0");
    feed_field(&mut context, bundle_id.as_bytes());
    context.update(&[u8::from(request.prune_existing)]);

    for entry in entries {
        context.update(&[entry.scope]);
        feed_field(&mut context, entry.file.relative_path.as_bytes());
        context.update(&[
            u8::from(entry.file.executable),
            u8::from(entry.file.sensitive),
        ]);
        feed_field(&mut context, &entry.file.content);
    }

    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod credential_delivery_tests {
    use super::*;

    fn uuid(value: u8) -> String {
        format!("00000000-0000-4000-8000-{value:012x}")
    }

    fn hex(ch: char, len: usize) -> String {
        std::iter::repeat_n(ch, len).collect()
    }

    fn key(ch: char) -> String {
        std::iter::repeat_n(ch, 43).collect()
    }

    fn tunnel_auth(seed: u8) -> TunnelAuthentication {
        TunnelAuthentication {
            vless_uuid: uuid(seed),
            hysteria2_password: hex(if seed % 2 == 0 { 'a' } else { 'b' }, 64),
            reality_short_id: hex(if seed % 2 == 0 { 'c' } else { 'd' }, 16),
        }
    }

    fn public_identity(seed: u8) -> RealityPublicIdentity {
        RealityPublicIdentity {
            public_key: key(if seed % 2 == 0 { 'A' } else { 'B' }),
        }
    }

    fn private_identity(seed: u8) -> RealityPrivateIdentity {
        RealityPrivateIdentity {
            private_key: key(if seed % 2 == 0 { 'C' } else { 'D' }),
        }
    }

    fn windows_projection() -> WindowsCredentialProjection {
        WindowsCredentialProjection {
            tunnel_auth: Some(TunnelAuthenticationGeneration {
                generation: 5,
                direct: Some(tunnel_auth(1)),
                warp: Some(tunnel_auth(2)),
            }),
            reality_identity: Some(RealityPublicIdentityGeneration {
                generation: 3,
                direct: Some(public_identity(1)),
                warp: Some(public_identity(2)),
            }),
        }
    }

    fn vm_projection() -> VmCredentialProjection {
        VmCredentialProjection {
            tunnel_auth: Some(TunnelAuthenticationGeneration {
                generation: 6,
                direct: Some(tunnel_auth(1)),
                warp: Some(tunnel_auth(2)),
            }),
            reality_identity: Some(RealityPrivateIdentityGeneration {
                generation: 4,
                direct: Some(private_identity(1)),
                warp: Some(private_identity(2)),
            }),
            line2_proxy: Some(ProxyCredentialGeneration {
                generation: 2,
                password: hex('e', 64),
            }),
        }
    }

    fn full_bundle(
        projection: CredentialProjectionKind,
        generation: u64,
        slot: CredentialDeliverySlot,
    ) -> CredentialDeliveryBundle {
        let payload = match projection {
            CredentialProjectionKind::Windows => {
                credential_delivery_bundle::Payload::Windows(windows_projection())
            }
            CredentialProjectionKind::Vm => {
                credential_delivery_bundle::Payload::Vm(vm_projection())
            }
            CredentialProjectionKind::Unspecified => panic!("test projection must be concrete"),
        };
        CredentialDeliveryBundle {
            schema_version: 1,
            generation,
            projection: projection as i32,
            dummy_non_secret: false,
            slot: slot as i32,
            payload: Some(payload),
        }
    }

    #[test]
    fn rotation_delta_materialization_preserves_unselected_windows_classes() {
        let active = full_bundle(
            CredentialProjectionKind::Windows,
            100,
            CredentialDeliverySlot::A,
        );
        let active_projection = match active.payload.as_ref().unwrap() {
            credential_delivery_bundle::Payload::Windows(value) => value.clone(),
            _ => unreachable!(),
        };

        for class in [
            CredentialRotationClass::TunnelAuth,
            CredentialRotationClass::RealityIdentity,
            CredentialRotationClass::Line2ProxyAuth,
        ] {
            let delta = WindowsCredentialRotationDelta {
                credential_class: class as i32,
                tunnel_auth: (class == CredentialRotationClass::TunnelAuth).then(|| {
                    TunnelAuthenticationGeneration {
                        generation: 101,
                        direct: Some(tunnel_auth(7)),
                        warp: Some(tunnel_auth(8)),
                    }
                }),
                reality_identity: (class == CredentialRotationClass::RealityIdentity).then(|| {
                    RealityPublicIdentityGeneration {
                        generation: 101,
                        direct: Some(public_identity(7)),
                        warp: Some(public_identity(8)),
                    }
                }),
            };
            let delivery = CredentialDeliveryBundle {
                schema_version: 1,
                generation: 101,
                projection: CredentialProjectionKind::Windows as i32,
                dummy_non_secret: false,
                slot: CredentialDeliverySlot::B as i32,
                payload: Some(credential_delivery_bundle::Payload::WindowsRotation(delta)),
            };
            let materialized =
                materialize_credential_delivery_candidate(Some(&active), &delivery).unwrap();
            let next = match materialized.payload.as_ref().unwrap() {
                credential_delivery_bundle::Payload::Windows(value) => value,
                _ => panic!("rotation must materialize a full Windows projection"),
            };

            match class {
                CredentialRotationClass::TunnelAuth => {
                    assert_eq!(next.tunnel_auth.as_ref().unwrap().generation, 101);
                    assert_eq!(next.reality_identity, active_projection.reality_identity);
                }
                CredentialRotationClass::RealityIdentity => {
                    assert_eq!(next.reality_identity.as_ref().unwrap().generation, 101);
                    assert_eq!(next.tunnel_auth, active_projection.tunnel_auth);
                }
                CredentialRotationClass::Line2ProxyAuth => {
                    assert_eq!(next.tunnel_auth, active_projection.tunnel_auth);
                    assert_eq!(next.reality_identity, active_projection.reality_identity);
                }
                CredentialRotationClass::Unspecified => unreachable!(),
            }
            assert_eq!(materialized.generation, 101);
            assert_eq!(materialized.slot, CredentialDeliverySlot::B as i32);
            assert!(!credential_delivery_is_rotation_delta(&materialized));
        }
    }

    #[test]
    fn rotation_delta_materialization_preserves_unselected_vm_classes() {
        let active = full_bundle(CredentialProjectionKind::Vm, 100, CredentialDeliverySlot::A);
        let active_projection = match active.payload.as_ref().unwrap() {
            credential_delivery_bundle::Payload::Vm(value) => value.clone(),
            _ => unreachable!(),
        };

        for class in [
            CredentialRotationClass::TunnelAuth,
            CredentialRotationClass::RealityIdentity,
            CredentialRotationClass::Line2ProxyAuth,
        ] {
            let delta = VmCredentialRotationDelta {
                credential_class: class as i32,
                tunnel_auth: (class == CredentialRotationClass::TunnelAuth).then(|| {
                    TunnelAuthenticationGeneration {
                        generation: 101,
                        direct: Some(tunnel_auth(9)),
                        warp: Some(tunnel_auth(10)),
                    }
                }),
                reality_identity: (class == CredentialRotationClass::RealityIdentity).then(|| {
                    RealityPrivateIdentityGeneration {
                        generation: 101,
                        direct: Some(private_identity(9)),
                        warp: Some(private_identity(10)),
                    }
                }),
                line2_proxy: (class == CredentialRotationClass::Line2ProxyAuth).then(|| {
                    ProxyCredentialGeneration {
                        generation: 101,
                        password: hex('f', 64),
                    }
                }),
            };
            let delivery = CredentialDeliveryBundle {
                schema_version: 1,
                generation: 101,
                projection: CredentialProjectionKind::Vm as i32,
                dummy_non_secret: false,
                slot: CredentialDeliverySlot::B as i32,
                payload: Some(credential_delivery_bundle::Payload::VmRotation(delta)),
            };
            let materialized =
                materialize_credential_delivery_candidate(Some(&active), &delivery).unwrap();
            let next = match materialized.payload.as_ref().unwrap() {
                credential_delivery_bundle::Payload::Vm(value) => value,
                _ => panic!("rotation must materialize a full VM projection"),
            };

            match class {
                CredentialRotationClass::TunnelAuth => {
                    assert_eq!(next.tunnel_auth.as_ref().unwrap().generation, 101);
                    assert_eq!(next.reality_identity, active_projection.reality_identity);
                    assert_eq!(next.line2_proxy, active_projection.line2_proxy);
                }
                CredentialRotationClass::RealityIdentity => {
                    assert_eq!(next.reality_identity.as_ref().unwrap().generation, 101);
                    assert_eq!(next.tunnel_auth, active_projection.tunnel_auth);
                    assert_eq!(next.line2_proxy, active_projection.line2_proxy);
                }
                CredentialRotationClass::Line2ProxyAuth => {
                    assert_eq!(next.line2_proxy.as_ref().unwrap().generation, 101);
                    assert_eq!(next.tunnel_auth, active_projection.tunnel_auth);
                    assert_eq!(next.reality_identity, active_projection.reality_identity);
                }
                CredentialRotationClass::Unspecified => unreachable!(),
            }
            assert_eq!(materialized.generation, 101);
            assert_eq!(materialized.slot, CredentialDeliverySlot::B as i32);
            assert!(!credential_delivery_is_rotation_delta(&materialized));
        }
    }

    #[test]
    fn rotation_delta_never_becomes_local_state_before_materialization() {
        let delivery = CredentialDeliveryBundle {
            schema_version: 1,
            generation: 101,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: false,
            slot: CredentialDeliverySlot::B as i32,
            payload: Some(credential_delivery_bundle::Payload::WindowsRotation(
                WindowsCredentialRotationDelta {
                    credential_class: CredentialRotationClass::Line2ProxyAuth as i32,
                    tunnel_auth: None,
                    reality_identity: None,
                },
            )),
        };
        validate_credential_delivery_bundle(&delivery).unwrap();
        assert!(credential_delivery_is_rotation_delta(&delivery));
        assert!(local_credential_bundle_ref(&delivery).is_err());
        assert!(materialize_credential_delivery_candidate(None, &delivery).is_err());
    }

    #[test]
    fn dummy_ab_bundle_remains_payload_free_and_canonical() {
        let bundle = CredentialDeliveryBundle {
            schema_version: 1,
            generation: 9_000_001,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: true,
            slot: CredentialDeliverySlot::Unspecified as i32,
            payload: None,
        };
        let bytes = encode_credential_delivery_bundle(&bundle).unwrap();
        assert_eq!(decode_credential_delivery_bundle(&bytes).unwrap(), bundle);
    }

    #[test]
    fn windows_projection_is_client_only_and_canonical() {
        let bundle = CredentialDeliveryBundle {
            schema_version: 1,
            generation: 10,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: false,
            slot: CredentialDeliverySlot::A as i32,
            payload: Some(credential_delivery_bundle::Payload::Windows(
                windows_projection(),
            )),
        };
        let bytes = encode_credential_delivery_bundle(&bundle).unwrap();
        assert_eq!(decode_credential_delivery_bundle(&bytes).unwrap(), bundle);
    }

    #[test]
    fn vm_projection_keeps_three_lifecycles_independent() {
        let projection = vm_projection();
        assert_ne!(
            projection.tunnel_auth.as_ref().unwrap().generation,
            projection.reality_identity.as_ref().unwrap().generation
        );
        assert_ne!(
            projection.reality_identity.as_ref().unwrap().generation,
            projection.line2_proxy.as_ref().unwrap().generation
        );

        let bundle = CredentialDeliveryBundle {
            schema_version: 1,
            generation: 11,
            projection: CredentialProjectionKind::Vm as i32,
            dummy_non_secret: false,
            slot: CredentialDeliverySlot::B as i32,
            payload: Some(credential_delivery_bundle::Payload::Vm(projection)),
        };
        validate_credential_delivery_bundle(&bundle).unwrap();
    }

    #[test]
    fn projection_identity_must_match_typed_payload() {
        let bundle = CredentialDeliveryBundle {
            schema_version: 1,
            generation: 12,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: false,
            slot: CredentialDeliverySlot::A as i32,
            payload: Some(credential_delivery_bundle::Payload::Vm(vm_projection())),
        };
        let error = validate_credential_delivery_bundle(&bundle).unwrap_err();
        assert!(error.contains("Windows credential-delivery bundle cannot carry a VM payload"));
    }

    #[test]
    fn real_bundle_requires_explicit_fixed_slot() {
        let bundle = CredentialDeliveryBundle {
            schema_version: 1,
            generation: 14,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: false,
            slot: CredentialDeliverySlot::Unspecified as i32,
            payload: Some(credential_delivery_bundle::Payload::Windows(
                windows_projection(),
            )),
        };
        let error = validate_credential_delivery_bundle(&bundle).unwrap_err();
        assert!(error.contains("requires fixed slot A or B"));
    }

    #[test]
    fn windows_projection_requires_reality_identity() {
        let mut projection = windows_projection();
        projection.reality_identity = None;
        let error = validate_windows_credential_projection(&projection).unwrap_err();
        assert!(error.contains("requires Reality identity"));
    }

    #[test]
    fn dummy_bundle_rejects_real_payload() {
        let bundle = CredentialDeliveryBundle {
            schema_version: 1,
            generation: 13,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: true,
            slot: CredentialDeliverySlot::Unspecified as i32,
            payload: Some(credential_delivery_bundle::Payload::Windows(
                windows_projection(),
            )),
        };
        assert!(validate_credential_delivery_bundle(&bundle).is_err());
    }
}

#[cfg(test)]
mod local_credential_state_tests {
    use super::*;

    fn bundle(
        projection: CredentialProjectionKind,
        generation: u64,
        slot: CredentialDeliverySlot,
    ) -> CredentialDeliveryBundle {
        let tunnel_auth = TunnelAuthenticationGeneration {
            generation: 7,
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
        };
        let payload = match projection {
            CredentialProjectionKind::Windows => {
                credential_delivery_bundle::Payload::Windows(WindowsCredentialProjection {
                    tunnel_auth: Some(tunnel_auth),
                    reality_identity: Some(RealityPublicIdentityGeneration {
                        generation: 3,
                        direct: Some(RealityPublicIdentity {
                            public_key: "A".repeat(43),
                        }),
                        warp: Some(RealityPublicIdentity {
                            public_key: "B".repeat(43),
                        }),
                    }),
                })
            }
            CredentialProjectionKind::Vm => {
                credential_delivery_bundle::Payload::Vm(VmCredentialProjection {
                    tunnel_auth: Some(tunnel_auth),
                    reality_identity: Some(RealityPrivateIdentityGeneration {
                        generation: 3,
                        direct: Some(RealityPrivateIdentity {
                            private_key: "C".repeat(43),
                        }),
                        warp: Some(RealityPrivateIdentity {
                            private_key: "D".repeat(43),
                        }),
                    }),
                    line2_proxy: Some(ProxyCredentialGeneration {
                        generation: 2,
                        password: "e".repeat(64),
                    }),
                })
            }
            CredentialProjectionKind::Unspecified => panic!("test projection must be concrete"),
        };
        CredentialDeliveryBundle {
            schema_version: 1,
            generation,
            projection: projection as i32,
            dummy_non_secret: false,
            slot: slot as i32,
            payload: Some(payload),
        }
    }

    #[test]
    fn candidate_only_state_is_valid_for_first_v2_staging() {
        let candidate = bundle(
            CredentialProjectionKind::Windows,
            101,
            CredentialDeliverySlot::B,
        );
        let state = LocalCredentialState {
            schema_version: 1,
            projection: CredentialProjectionKind::Windows as i32,
            active: None,
            candidate: Some(local_credential_bundle_ref(&candidate).unwrap()),
            previous: None,
        };
        let bytes = encode_local_credential_state(&state).unwrap();
        assert_eq!(decode_local_credential_state(&bytes).unwrap(), state);
    }

    #[test]
    fn active_and_candidate_must_use_opposite_slots() {
        let active = bundle(CredentialProjectionKind::Vm, 100, CredentialDeliverySlot::A);
        let candidate = bundle(CredentialProjectionKind::Vm, 101, CredentialDeliverySlot::A);
        let state = LocalCredentialState {
            schema_version: 1,
            projection: CredentialProjectionKind::Vm as i32,
            active: Some(local_credential_bundle_ref(&active).unwrap()),
            candidate: Some(local_credential_bundle_ref(&candidate).unwrap()),
            previous: None,
        };
        assert!(validate_local_credential_state(&state).is_err());
    }

    #[test]
    fn candidate_and_previous_cannot_coexist() {
        let active = bundle(
            CredentialProjectionKind::Windows,
            101,
            CredentialDeliverySlot::B,
        );
        let other = bundle(
            CredentialProjectionKind::Windows,
            100,
            CredentialDeliverySlot::A,
        );
        let reference = local_credential_bundle_ref(&other).unwrap();
        let state = LocalCredentialState {
            schema_version: 1,
            projection: CredentialProjectionKind::Windows as i32,
            active: Some(local_credential_bundle_ref(&active).unwrap()),
            candidate: Some(reference.clone()),
            previous: Some(reference),
        };
        assert!(validate_local_credential_state(&state).is_err());
    }

    #[test]
    fn reference_verification_binds_projection_generation_slot_and_digest() {
        let bundle = bundle(CredentialProjectionKind::Vm, 101, CredentialDeliverySlot::B);
        let reference = local_credential_bundle_ref(&bundle).unwrap();
        verify_local_credential_bundle_reference(CredentialProjectionKind::Vm, &reference, &bundle)
            .unwrap();

        let mut wrong = reference.clone();
        wrong.generation += 1;
        assert!(
            verify_local_credential_bundle_reference(
                CredentialProjectionKind::Vm,
                &wrong,
                &bundle,
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod release_set_tests {
    use super::*;

    fn digest(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn image(repository: &str, byte: u8) -> OciImage {
        OciImage {
            repository: repository.to_owned(),
            sha256: digest(byte),
        }
    }

    fn clear_windows_reuse_identity(release: &mut ReleaseSet) {
        let windows = release.windows_runtime.as_mut().unwrap();
        windows.input_sha256.clear();
        windows.source_revision.clear();
        windows.diagnostic_sha256.clear();
    }

    fn clear_application_bundle_identity(release: &mut ReleaseSet) {
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .application_bundle_sha256
            .clear();
    }

    fn valid_release() -> ReleaseSet {
        ReleaseSet {
            schema_version: RELEASE_SET_SCHEMA_VERSION,
            source_revision: "1".repeat(40),
            sing_box: Some(SingBoxRelease {
                version: "1.13.0".to_owned(),
                windows_amd64_sha256: digest(2),
                linux_amd64_sha256: digest(3),
            }),
            windows_runtime: Some(WindowsRuntime {
                artifact_sha256: digest(4),
                controller_sha256: digest(5),
                console_sha256: digest(6),
                sing_box_sha256: digest(2),
                input_sha256: digest(14),
                source_revision: "f".repeat(40),
                diagnostic_sha256: digest(15),
            }),
            vm_runtime: Some(VmRuntime {
                edge_agent_sha256: digest(7),
                edge_controller_sha256: digest(11),
                edge_orchestrator_sha256: digest(12),
                runtime_input_sha256: digest(13),
                runtime_source_revision: "a".repeat(40),
                sing_box_image: Some(image("ghcr.io/iamaman11/sing-box-runtime", 8)),
                warp_egress_image: Some(image("ghcr.io/iamaman11/warp-egress", 9)),
                docker_engine_version: "29.0.1".to_owned(),
                containerd_version: "2.1.4".to_owned(),
                compose_version: "2.39.2".to_owned(),
                application_bundle_sha256: digest(16),
            }),
            cloudflare: Some(CloudflareRuntime {
                warp_version: "2026.9.1".to_owned(),
                mesh_image: Some(image("docker.io/cloudflare/mesh", 10)),
            }),
            schemas: Some(SchemaVersions {
                config_schema: 1,
                db_schema: 1,
            }),
        }
    }

    #[test]
    fn release_set_round_trip_is_canonical_and_identity_is_stable() {
        let release = valid_release();
        let bytes = encode_release_set(&release).unwrap();
        assert_eq!(decode_release_set(&bytes).unwrap(), release);
        let first = release_set_sha256(&bytes).unwrap();
        let second = release_set_sha256(&bytes).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn release_set_rejects_prerelease_sing_box_version() {
        let mut release = valid_release();
        release.sing_box.as_mut().unwrap().version = "1.14.0-rc.1".to_owned();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_wrong_digest_length() {
        let mut release = valid_release();
        release.vm_runtime.as_mut().unwrap().edge_agent_sha256 = vec![0; 31];
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_accepts_legacy_v1_without_controller_hash() {
        let mut release = valid_release();
        release.schema_version = 1;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .edge_controller_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .edge_orchestrator_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_input_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_source_revision
            .clear();
        let bytes = encode_release_set(&release).unwrap();
        assert_eq!(decode_release_set(&bytes).unwrap(), release);
    }

    #[test]
    fn release_set_rejects_v1_with_v2_controller_hash() {
        let mut release = valid_release();
        release.schema_version = 1;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_missing_v2_controller_hash() {
        let mut release = valid_release();
        release.schema_version = 2;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .edge_orchestrator_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .edge_controller_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_input_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_source_revision
            .clear();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_accepts_legacy_v2_without_orchestrator_hash() {
        let mut release = valid_release();
        release.schema_version = 2;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .edge_orchestrator_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_input_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_source_revision
            .clear();
        let bytes = encode_release_set(&release).unwrap();
        assert_eq!(decode_release_set(&bytes).unwrap(), release);
    }

    #[test]
    fn release_set_rejects_v2_with_v3_orchestrator_hash() {
        let mut release = valid_release();
        release.schema_version = 2;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_accepts_legacy_v3_without_runtime_reuse_identity() {
        let mut release = valid_release();
        release.schema_version = 3;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_input_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_source_revision
            .clear();
        let bytes = encode_release_set(&release).unwrap();
        assert_eq!(decode_release_set(&bytes).unwrap(), release);
    }

    #[test]
    fn release_set_rejects_v3_with_v4_runtime_reuse_identity() {
        let mut release = valid_release();
        release.schema_version = 3;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_missing_v4_runtime_reuse_identity() {
        let mut release = valid_release();
        release.schema_version = 4;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_input_sha256
            .clear();
        assert!(validate_release_set(&release).is_err());
        let mut release = valid_release();
        release.schema_version = 4;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_source_revision
            .clear();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_accepts_legacy_v4_without_windows_reuse_identity() {
        let mut release = valid_release();
        release.schema_version = 4;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        let bytes = encode_release_set(&release).unwrap();
        assert_eq!(decode_release_set(&bytes).unwrap(), release);
    }

    #[test]
    fn release_set_accepts_legacy_v5_without_windows_diagnostic_identity() {
        let mut release = valid_release();
        release.schema_version = 5;
        clear_application_bundle_identity(&mut release);
        release
            .windows_runtime
            .as_mut()
            .unwrap()
            .diagnostic_sha256
            .clear();
        let bytes = encode_release_set(&release).unwrap();
        assert_eq!(decode_release_set(&bytes).unwrap(), release);
    }

    #[test]
    fn release_set_rejects_missing_v5_windows_reuse_identity() {
        let mut release = valid_release();
        release.schema_version = 5;
        clear_application_bundle_identity(&mut release);
        release
            .windows_runtime
            .as_mut()
            .unwrap()
            .diagnostic_sha256
            .clear();
        release
            .windows_runtime
            .as_mut()
            .unwrap()
            .input_sha256
            .clear();
        assert!(validate_release_set(&release).is_err());

        let mut release = valid_release();
        release.schema_version = 5;
        clear_application_bundle_identity(&mut release);
        release
            .windows_runtime
            .as_mut()
            .unwrap()
            .diagnostic_sha256
            .clear();
        release
            .windows_runtime
            .as_mut()
            .unwrap()
            .source_revision
            .clear();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_missing_v6_windows_diagnostic_identity() {
        let mut release = valid_release();
        release
            .windows_runtime
            .as_mut()
            .unwrap()
            .diagnostic_sha256
            .clear();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_accepts_legacy_v6_without_application_bundle_identity() {
        let mut release = valid_release();
        release.schema_version = 6;
        clear_application_bundle_identity(&mut release);
        let bytes = encode_release_set(&release).unwrap();
        assert_eq!(decode_release_set(&bytes).unwrap(), release);
    }

    #[test]
    fn release_set_rejects_v6_with_application_bundle_identity() {
        let mut release = valid_release();
        release.schema_version = 6;
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_v7_without_application_bundle_identity() {
        let mut release = valid_release();
        clear_application_bundle_identity(&mut release);
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_missing_v3_orchestrator_hash() {
        let mut release = valid_release();
        release.schema_version = 3;
        clear_application_bundle_identity(&mut release);
        clear_windows_reuse_identity(&mut release);
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_input_sha256
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .runtime_source_revision
            .clear();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .edge_orchestrator_sha256
            .clear();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_missing_v4_orchestrator_hash() {
        let mut release = valid_release();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .edge_orchestrator_sha256
            .clear();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_windows_sing_box_hash_drift() {
        let mut release = valid_release();
        release.windows_runtime.as_mut().unwrap().sing_box_sha256 = digest(11);
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_mutable_oci_tag() {
        let mut release = valid_release();
        release
            .vm_runtime
            .as_mut()
            .unwrap()
            .sing_box_image
            .as_mut()
            .unwrap()
            .repository = "ghcr.io/iamaman11/sing-box-runtime:latest".to_owned();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_noncanonical_or_unknown_wire_fields() {
        let release = valid_release();
        let mut bytes = encode_release_set(&release).unwrap();
        bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
        assert!(decode_release_set(&bytes).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn canonical_production_desired_state_is_protobuf_and_canonical() {
        let desired = canonical_production_desired_state().unwrap();
        assert_eq!(desired.schema_version, 6);
        assert_eq!(desired.environment, "production");
        assert_eq!(desired.machine_id, "production-1");
        assert_eq!(desired.public_hostname, "miu.alegria.by");
        assert_eq!(
            WindowsDatapathMode::try_from(desired.windows_datapath_mode).unwrap(),
            WindowsDatapathMode::ManagedTun
        );
        let cloudflare = desired.cloudflare.as_ref().unwrap();
        assert_eq!(
            cloudflare.active_account_id,
            "6be6e4b6340822dbeb18cb6c2f09c660"
        );
        assert!(cloudflare.migration_target_account_id.is_empty());
        let target_plane = cloudflare.target_plane.as_ref().unwrap();
        assert_eq!(target_plane.mesh_profile_name, "sing-box Mesh nodes");
        assert_eq!(target_plane.mesh_profile_service_mode, "warp");
        assert_eq!(target_plane.mesh_profile_tunnel_protocol, "masque");
        assert_eq!(
            target_plane.mesh_profile_include_cidrs,
            vec!["100.64.0.0/12".to_owned(), "100.96.0.0/12".to_owned()]
        );
        assert_eq!(
            desired.dns.as_ref().unwrap().account_id,
            "4426df1449e417511bc7697d60b7f62f"
        );
        assert!(desired.mesh.as_ref().unwrap().account_id.is_empty());
        assert_eq!(
            desired.encode_to_vec(),
            CANONICAL_PRODUCTION_DESIRED_STATE_BYTES
        );
    }

    #[test]
    fn windows_privileged_request_is_canonical_and_bounded() {
        let request = WindowsPrivilegedRequest {
            schema_version: 1,
            request_id: "request-1".to_owned(),
            operation: WindowsPrivilegedOperation::ActivateRelease as i32,
            accepted_revision: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            release_set_sha256: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
            credential_generation: None,
            credential_transition_action: None,
        };
        let bytes = encode_windows_privileged_request(&request).unwrap();
        assert_eq!(decode_windows_privileged_request(&bytes).unwrap(), request);

        let mut invalid = request.clone();
        invalid.release_set_sha256 = Some("latest".to_owned());
        assert!(encode_windows_privileged_request(&invalid).is_err());
    }

    #[test]
    fn windows_privileged_ping_carries_no_release_authority() {
        let request = WindowsPrivilegedRequest {
            schema_version: 1,
            request_id: "request-ping".to_owned(),
            operation: WindowsPrivilegedOperation::Ping as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: None,
        };
        assert!(encode_windows_privileged_request(&request).is_ok());

        let mut invalid = request;
        invalid.accepted_revision = Some("0123456789abcdef0123456789abcdef01234567".to_owned());
        assert!(encode_windows_privileged_request(&invalid).is_err());
    }

    #[test]
    fn windows_privileged_previous_release_rollback_carries_no_selected_digest() {
        let request = WindowsPrivilegedRequest {
            schema_version: 1,
            request_id: "request-release-rollback".to_owned(),
            operation: WindowsPrivilegedOperation::RollbackPreviousRelease as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: None,
        };
        assert!(encode_windows_privileged_request(&request).is_ok());

        let mut invalid = request;
        invalid.release_set_sha256 = Some("1".repeat(64));
        assert!(encode_windows_privileged_request(&invalid).is_err());
    }

    #[test]
    fn windows_privileged_reinstall_is_accepted_release_only() {
        let request = WindowsPrivilegedRequest {
            schema_version: 1,
            request_id: "request-release-reinstall".to_owned(),
            operation: WindowsPrivilegedOperation::ReinstallAcceptedRelease as i32,
            accepted_revision: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            release_set_sha256: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
            credential_generation: None,
            credential_transition_action: None,
        };
        assert!(encode_windows_privileged_request(&request).is_ok());

        let mut invalid = request;
        invalid.release_set_sha256 = None;
        assert!(encode_windows_privileged_request(&invalid).is_err());
    }

    #[test]
    fn windows_privileged_runtime_evidence_carries_no_mutation_authority() {
        let request = WindowsPrivilegedRequest {
            schema_version: 1,
            request_id: "request-runtime-evidence".to_owned(),
            operation: WindowsPrivilegedOperation::RuntimeEvidence as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: None,
        };
        assert!(encode_windows_privileged_request(&request).is_ok());

        let mut invalid = request;
        invalid.credential_generation = Some(101);
        assert!(encode_windows_privileged_request(&invalid).is_err());
    }

    #[test]
    fn windows_privileged_restart_controller_carries_no_caller_authority() {
        let request = WindowsPrivilegedRequest {
            schema_version: 1,
            request_id: "request-restart-controller".to_owned(),
            operation: WindowsPrivilegedOperation::RestartControllerService as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: None,
        };
        assert!(encode_windows_privileged_request(&request).is_ok());

        let mut invalid = request.clone();
        invalid.accepted_revision = Some("0123456789abcdef0123456789abcdef01234567".to_owned());
        assert!(encode_windows_privileged_request(&invalid).is_err());

        let mut invalid = request.clone();
        invalid.release_set_sha256 = Some("1".repeat(64));
        assert!(encode_windows_privileged_request(&invalid).is_err());

        let mut invalid = request.clone();
        invalid.credential_generation = Some(1);
        assert!(encode_windows_privileged_request(&invalid).is_err());

        let mut invalid = request;
        invalid.credential_transition_action = Some(CredentialTransitionAction::Promote as i32);
        assert!(encode_windows_privileged_request(&invalid).is_err());
    }

    #[test]
    fn windows_privileged_credential_stage_is_generation_only() {
        let request = WindowsPrivilegedRequest {
            schema_version: 1,
            request_id: "request-credential-stage".to_owned(),
            operation: WindowsPrivilegedOperation::StageCredential as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: Some(101),
            credential_transition_action: None,
        };
        assert!(encode_windows_privileged_request(&request).is_ok());

        let mut invalid = request.clone();
        invalid.credential_generation = Some(0);
        assert!(encode_windows_privileged_request(&invalid).is_err());

        let mut invalid = request;
        invalid.accepted_revision = Some("0123456789abcdef0123456789abcdef01234567".to_owned());
        assert!(encode_windows_privileged_request(&invalid).is_err());
    }

    #[test]
    fn credential_transition_parser_and_windows_request_share_one_closed_action_set() {
        for (name, action) in [
            (
                "validate-candidate",
                CredentialTransitionAction::ValidateCandidate,
            ),
            (
                "apply-candidate",
                CredentialTransitionAction::ApplyCandidate,
            ),
            ("promote", CredentialTransitionAction::Promote),
            ("apply-legacy", CredentialTransitionAction::ApplyLegacy),
            ("apply-active", CredentialTransitionAction::ApplyActive),
            ("retire-legacy", CredentialTransitionAction::RetireLegacy),
            (
                "discard-candidate",
                CredentialTransitionAction::DiscardCandidate,
            ),
            (
                "rollback-previous",
                CredentialTransitionAction::RollbackPrevious,
            ),
            ("drop-previous", CredentialTransitionAction::DropPrevious),
        ] {
            assert_eq!(parse_credential_transition_action(name).unwrap(), action);
            let request = WindowsPrivilegedRequest {
                schema_version: 1,
                request_id: format!("request-transition-{}", action as i32),
                operation: WindowsPrivilegedOperation::CredentialTransition as i32,
                accepted_revision: None,
                release_set_sha256: None,
                credential_generation: None,
                credential_transition_action: Some(action as i32),
            };
            assert!(encode_windows_privileged_request(&request).is_ok());
        }

        assert!(parse_credential_transition_action("rotate").is_err());
        let invalid = WindowsPrivilegedRequest {
            schema_version: 1,
            request_id: "request-transition-invalid".to_owned(),
            operation: WindowsPrivilegedOperation::CredentialTransition as i32,
            accepted_revision: None,
            release_set_sha256: None,
            credential_generation: None,
            credential_transition_action: None,
        };
        assert!(encode_windows_privileged_request(&invalid).is_err());
    }

    #[test]
    fn windows_privileged_access_bootstrap_carries_no_release_or_application_credential_authority()
    {
        for operation in [
            WindowsPrivilegedOperation::PrepareCredentialAccessBootstrap,
            WindowsPrivilegedOperation::InstallCredentialAccessBootstrap,
        ] {
            let request = WindowsPrivilegedRequest {
                schema_version: 1,
                request_id: format!("request-access-bootstrap-{}", operation as i32),
                operation: operation as i32,
                accepted_revision: None,
                release_set_sha256: None,
                credential_generation: None,
                credential_transition_action: None,
            };
            assert!(encode_windows_privileged_request(&request).is_ok());

            let mut invalid = request.clone();
            invalid.credential_generation = Some(101);
            assert!(encode_windows_privileged_request(&invalid).is_err());

            let mut invalid = request;
            invalid.accepted_revision = Some("0123456789abcdef0123456789abcdef01234567".to_owned());
            assert!(encode_windows_privileged_request(&invalid).is_err());
        }
    }

    #[test]
    fn encodes_agent_state_with_prost() {
        let bytes = AgentState::bootstrap_placeholder().encode_to_vec();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn encodes_controller_status_with_prost() {
        let status = ControllerStatus {
            inventory: Some(InventoryReport {
                repo_root: "/tmp/repo".to_owned(),
                rust_workspace_present: true,
                required_repo_files: Vec::new(),
                local_only_files: Vec::new(),
                blockers: Vec::new(),
                warnings: Vec::new(),
            }),
            agent_state: Some(AgentState::bootstrap_placeholder()),
            local_singbox: Some(LocalSingboxState::placeholder("config.json")),
            deployment: Some(DeploymentSummary::missing()),
            provider: Some(ProviderObservation::placeholder()),
            runtime: Some(RuntimeObservation::placeholder()),
            selector: Some(SelectorState::placeholder()),
            ubuntu_selector: Some(SelectorState::placeholder()),
            ubuntu_proxy: Some(UbuntuProxyState::unavailable("unavailable")),
            status_notes: vec!["ok".to_owned()],
            app_readiness_phase: AppReadinessPhase::DeploymentAbsent as i32,
        };
        assert!(!status.encode_to_vec().is_empty());
    }
}
