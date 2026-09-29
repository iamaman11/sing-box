use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialDeliverySlot, CredentialIngressPublicKey,
    CredentialProjectionKind, SealedCredentialCandidate, decode_credential_delivery_bundle,
    encode_credential_delivery_bundle,
};
use rand_core::{OsRng, RngCore};
use ring::{aead, digest, hkdf};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

const INGRESS_KEY_FILE: &str = "credential-ingress-x25519.key";
const SEAL_CONTEXT: &[u8] = b"edge-credential-seal-v1";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

pub struct CredentialIngressKey {
    root: PathBuf,
    projection: CredentialProjectionKind,
    secret: StaticSecret,
}

impl CredentialIngressKey {
    pub fn load_or_create(
        root: impl Into<PathBuf>,
        projection: CredentialProjectionKind,
    ) -> Result<Self, String> {
        require_projection(projection)?;
        let root = root.into();
        fs::create_dir_all(&root).map_err(|err| {
            format!(
                "failed to create credential ingress root {}: {err}",
                root.display()
            )
        })?;
        set_private_directory_permissions(&root)?;
        let path = root.join(INGRESS_KEY_FILE);
        let secret = if path.exists() {
            read_private_key(&path)?
        } else {
            let generated = StaticSecret::random_from_rng(OsRng);
            write_private_key_once(&path, generated.to_bytes())?;
            read_private_key(&path)?
        };
        Ok(Self {
            root,
            projection,
            secret,
        })
    }

    pub fn open_existing(
        root: impl Into<PathBuf>,
        projection: CredentialProjectionKind,
    ) -> Result<Option<Self>, String> {
        require_projection(projection)?;
        let root = root.into();
        let path = root.join(INGRESS_KEY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let secret = read_private_key(&path)?;
        Ok(Some(Self {
            root,
            projection,
            secret,
        }))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn public_key(&self) -> CredentialIngressPublicKey {
        let public = PublicKey::from(&self.secret).to_bytes();
        CredentialIngressPublicKey {
            schema_version: 1,
            projection: self.projection as i32,
            public_key: URL_SAFE_NO_PAD.encode(public),
            sha256: sha256_hex(&public),
        }
    }

    pub fn open_candidate(
        &self,
        sealed: &SealedCredentialCandidate,
    ) -> Result<CredentialDeliveryBundle, String> {
        validate_sealed_metadata(sealed)?;
        if sealed.projection != self.projection as i32 {
            return Err("sealed credential projection does not match local owner".to_owned());
        }

        let local_public = self.public_key();
        if sealed.recipient_key_sha256 != local_public.sha256 {
            return Err("sealed credential recipient does not match local ingress key".to_owned());
        }

        let ephemeral_bytes = decode_fixed_base64url::<KEY_BYTES>(
            "sealed credential ephemeral_public_key",
            &sealed.ephemeral_public_key,
        )?;
        let nonce_bytes =
            decode_fixed_base64url::<NONCE_BYTES>("sealed credential nonce", &sealed.nonce)?;
        let mut ciphertext = decode_base64url("sealed credential ciphertext", &sealed.ciphertext)?;
        if ciphertext.len() < aead::CHACHA20_POLY1305.tag_len() {
            return Err("sealed credential ciphertext is shorter than its authentication tag".to_owned());
        }

        let ephemeral = PublicKey::from(ephemeral_bytes);
        let shared = self.secret.diffie_hellman(&ephemeral);
        let aad = envelope_aad(
            sealed.projection,
            sealed.generation,
            sealed.slot,
            &sealed.recipient_key_sha256,
        );
        let key_bytes = derive_aead_key(shared.as_bytes(), &aad)?;
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
                .map_err(|_| "failed to construct credential sealing key".to_owned())?,
        );
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let plaintext = key
            .open_in_place(nonce, aead::Aad::from(aad.as_slice()), &mut ciphertext)
            .map_err(|_| "sealed credential authentication failed".to_owned())?;
        let bundle = decode_credential_delivery_bundle(plaintext)?;
        if bundle.dummy_non_secret {
            return Err("sealed credential candidate cannot contain a dummy bundle".to_owned());
        }
        if bundle.projection != sealed.projection
            || bundle.generation != sealed.generation
            || bundle.slot != sealed.slot
        {
            return Err(
                "sealed credential metadata does not match the decrypted credential bundle"
                    .to_owned(),
            );
        }
        Ok(bundle)
    }
}

pub fn seal_credential_candidate(
    recipient: &CredentialIngressPublicKey,
    bundle: &CredentialDeliveryBundle,
) -> Result<SealedCredentialCandidate, String> {
    validate_ingress_public_key(recipient)?;
    let bytes = encode_credential_delivery_bundle(bundle)?;
    if bundle.dummy_non_secret {
        return Err("real credential sealing refuses dummy bundles".to_owned());
    }
    if bundle.projection != recipient.projection {
        return Err("credential bundle projection does not match ingress recipient".to_owned());
    }

    let recipient_bytes =
        decode_fixed_base64url::<KEY_BYTES>("credential ingress public_key", &recipient.public_key)?;
    let recipient_public = PublicKey::from(recipient_bytes);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);

    let aad = envelope_aad(
        bundle.projection,
        bundle.generation,
        bundle.slot,
        &recipient.sha256,
    );
    let key_bytes = derive_aead_key(shared.as_bytes(), &aad)?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| "failed to construct credential sealing key".to_owned())?,
    );
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = bytes;
    key.seal_in_place_append_tag(nonce, aead::Aad::from(aad.as_slice()), &mut ciphertext)
        .map_err(|_| "failed to seal credential candidate".to_owned())?;

    Ok(SealedCredentialCandidate {
        schema_version: 1,
        projection: bundle.projection,
        generation: bundle.generation,
        slot: bundle.slot,
        recipient_key_sha256: recipient.sha256.clone(),
        ephemeral_public_key: URL_SAFE_NO_PAD.encode(ephemeral_public),
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn validate_ingress_public_key(value: &CredentialIngressPublicKey) -> Result<(), String> {
    if value.schema_version != 1 {
        return Err(format!(
            "unsupported credential ingress public-key schema_version {}",
            value.schema_version
        ));
    }
    let projection = CredentialProjectionKind::try_from(value.projection)
        .map_err(|_| "credential ingress projection is unknown".to_owned())?;
    require_projection(projection)?;
    let public =
        decode_fixed_base64url::<KEY_BYTES>("credential ingress public_key", &value.public_key)?;
    if value.sha256 != sha256_hex(&public) {
        return Err("credential ingress public-key digest mismatch".to_owned());
    }
    Ok(())
}

pub fn validate_sealed_metadata(value: &SealedCredentialCandidate) -> Result<(), String> {
    if value.schema_version != 1 {
        return Err(format!(
            "unsupported sealed credential schema_version {}",
            value.schema_version
        ));
    }
    let projection = CredentialProjectionKind::try_from(value.projection)
        .map_err(|_| "sealed credential projection is unknown".to_owned())?;
    require_projection(projection)?;
    if value.generation == 0 {
        return Err("sealed credential generation must be greater than zero".to_owned());
    }
    let slot = CredentialDeliverySlot::try_from(value.slot)
        .map_err(|_| "sealed credential slot is unknown".to_owned())?;
    if !matches!(slot, CredentialDeliverySlot::A | CredentialDeliverySlot::B) {
        return Err("sealed credential slot must be A or B".to_owned());
    }
    validate_lower_hex("sealed credential recipient_key_sha256", &value.recipient_key_sha256, 64)?;
    decode_fixed_base64url::<KEY_BYTES>(
        "sealed credential ephemeral_public_key",
        &value.ephemeral_public_key,
    )?;
    decode_fixed_base64url::<NONCE_BYTES>("sealed credential nonce", &value.nonce)?;
    let ciphertext = decode_base64url("sealed credential ciphertext", &value.ciphertext)?;
    if ciphertext.len() < aead::CHACHA20_POLY1305.tag_len() {
        return Err("sealed credential ciphertext is shorter than its authentication tag".to_owned());
    }
    Ok(())
}

fn envelope_aad(
    projection: i32,
    generation: u64,
    slot: i32,
    recipient_key_sha256: &str,
) -> Vec<u8> {
    format!(
        "edge-credential-seal-v1|projection={projection}|generation={generation}|slot={slot}|recipient={recipient_key_sha256}"
    )
    .into_bytes()
}

struct AeadKeyLen;

impl hkdf::KeyType for AeadKeyLen {
    fn len(&self) -> usize {
        aead::CHACHA20_POLY1305.key_len()
    }
}

fn derive_aead_key(shared: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, SEAL_CONTEXT);
    let prk = salt.extract(shared);
    let info = [aad];
    let okm = prk
        .expand(&info, AeadKeyLen)
        .map_err(|_| "failed to derive credential sealing key".to_owned())?;
    let mut key = vec![0u8; aead::CHACHA20_POLY1305.key_len()];
    okm.fill(&mut key)
        .map_err(|_| "failed to fill credential sealing key".to_owned())?;
    Ok(key)
}

fn decode_base64url(label: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.contains('=') {
        return Err(format!("{label} must be non-empty unpadded base64url"));
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("{label} is not valid base64url"))
}

fn decode_fixed_base64url<const N: usize>(label: &str, value: &str) -> Result<[u8; N], String> {
    let bytes = decode_base64url(label, value)?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must decode to exactly {N} bytes"))
}

fn require_projection(projection: CredentialProjectionKind) -> Result<(), String> {
    if matches!(
        projection,
        CredentialProjectionKind::Windows | CredentialProjectionKind::Vm
    ) {
        Ok(())
    } else {
        Err("credential projection must be Windows or VM".to_owned())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

fn read_private_key(path: &Path) -> Result<StaticSecret, String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("failed to read credential ingress key {}: {err}", path.display()))?;
    let bytes: [u8; KEY_BYTES] = bytes.try_into().map_err(|_| {
        format!(
            "credential ingress key {} must contain exactly {KEY_BYTES} bytes",
            path.display()
        )
    })?;
    set_private_file_permissions(path)?;
    Ok(StaticSecret::from(bytes))
}

fn write_private_key_once(path: &Path, bytes: [u8; KEY_BYTES]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "credential ingress key path has no parent".to_owned())?;
    let temp = parent.join(format!(
        ".{INGRESS_KEY_FILE}.new-{}",
        std::process::id()
    ));
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to clear stale credential ingress temp key {}: {err}",
                temp.display()
            ));
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|err| {
            format!(
                "failed to create credential ingress temp key {}: {err}",
                temp.display()
            )
        })?;
    file.write_all(&bytes).map_err(|err| {
        format!(
            "failed to write credential ingress temp key {}: {err}",
            temp.display()
        )
    })?;
    file.sync_all().map_err(|err| {
        format!(
            "failed to sync credential ingress temp key {}: {err}",
            temp.display()
        )
    })?;
    drop(file);
    set_private_file_permissions(&temp)?;
    if path.exists() {
        fs::remove_file(&temp).map_err(|err| {
            format!(
                "failed to remove redundant credential ingress temp key {}: {err}",
                temp.display()
            )
        })?;
        return Ok(());
    }
    fs::rename(&temp, path).map_err(|err| {
        format!(
            "failed to publish credential ingress key {}: {err}",
            path.display()
        )
    })?;
    set_private_file_permissions(path)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("failed to set {} mode 700: {err}", path.display()))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("failed to set {} mode 600: {err}", path.display()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::{
        CredentialDeliverySlot, RealityPublicIdentity, RealityPublicIdentityGeneration,
        TunnelAuthentication, TunnelAuthenticationGeneration, WindowsCredentialProjection,
        credential_delivery_bundle,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_root(label: &str) -> PathBuf {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-credential-ingress-{label}-{value}"))
    }

    fn windows_bundle(generation: u64, slot: CredentialDeliverySlot) -> CredentialDeliveryBundle {
        CredentialDeliveryBundle {
            schema_version: 1,
            generation,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: false,
            slot: slot as i32,
            payload: Some(credential_delivery_bundle::Payload::Windows(
                WindowsCredentialProjection {
                    tunnel_auth: Some(TunnelAuthenticationGeneration {
                        generation: 1,
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
                        generation: 1,
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

    #[test]
    fn local_ingress_key_is_stable_and_private() {
        let root = unique_root("stable");
        let first = CredentialIngressKey::load_or_create(
            &root,
            CredentialProjectionKind::Windows,
        )
        .unwrap()
        .public_key();
        let second = CredentialIngressKey::load_or_create(
            &root,
            CredentialProjectionKind::Windows,
        )
        .unwrap()
        .public_key();
        assert_eq!(first, second);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(
                fs::metadata(root.join(INGRESS_KEY_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sealed_candidate_round_trip_binds_recipient_and_metadata() {
        let root = unique_root("roundtrip");
        let ingress = CredentialIngressKey::load_or_create(
            &root,
            CredentialProjectionKind::Windows,
        )
        .unwrap();
        let bundle = windows_bundle(1, CredentialDeliverySlot::A);
        let sealed = seal_credential_candidate(&ingress.public_key(), &bundle).unwrap();

        assert_eq!(sealed.generation, 1);
        assert_eq!(sealed.slot, CredentialDeliverySlot::A as i32);
        assert_eq!(ingress.open_candidate(&sealed).unwrap(), bundle);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_recipient_and_tampering_fail_closed() {
        let left_root = unique_root("left");
        let right_root = unique_root("right");
        let left = CredentialIngressKey::load_or_create(
            &left_root,
            CredentialProjectionKind::Windows,
        )
        .unwrap();
        let right = CredentialIngressKey::load_or_create(
            &right_root,
            CredentialProjectionKind::Windows,
        )
        .unwrap();
        let bundle = windows_bundle(1, CredentialDeliverySlot::A);
        let sealed = seal_credential_candidate(&left.public_key(), &bundle).unwrap();

        assert!(right.open_candidate(&sealed).is_err());

        let mut tampered = sealed;
        tampered.generation = 2;
        assert!(left.open_candidate(&tampered).is_err());

        fs::remove_dir_all(left_root).unwrap();
        fs::remove_dir_all(right_root).unwrap();
    }
}
