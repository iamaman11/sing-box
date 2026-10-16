use edge_shared_types::{
    CredentialDeliveryBundle, CredentialProjectionKind, LocalCredentialBundleRef,
    LocalCredentialState, credential_delivery_bundle_sha256, decode_credential_delivery_bundle,
    decode_local_credential_state, encode_credential_delivery_bundle,
    encode_local_credential_state, local_credential_bundle_ref,
    materialize_credential_delivery_candidate, validate_local_credential_state,
    verify_local_credential_bundle_reference,
};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const STATE_FILE: &str = "state.pb";
const BUNDLES_DIR: &str = "bundles";
const INITIAL_PAIR_COMMIT_RECEIPT: &str = "initial-paired-commit-receipt-v1";

#[derive(Debug, Clone)]
pub struct CredentialStore {
    root: PathBuf,
    projection: CredentialProjectionKind,
}

impl CredentialStore {
    pub fn new(
        root: impl Into<PathBuf>,
        projection: CredentialProjectionKind,
    ) -> Result<Self, String> {
        require_projection(projection)?;
        Ok(Self {
            root: root.into(),
            projection,
        })
    }

    pub fn open_existing(
        root: impl Into<PathBuf>,
        projection: CredentialProjectionKind,
    ) -> Result<Option<Self>, String> {
        require_projection(projection)?;
        let root = root.into();
        if !root.exists() {
            return Ok(None);
        }
        if !root.is_dir() {
            return Err(format!(
                "credential store root is not a directory: {}",
                root.display()
            ));
        }
        let store = Self { root, projection };
        if store.bundles_dir().exists() && !store.bundles_dir().is_dir() {
            return Err(format!(
                "credential bundle store is not a directory: {}",
                store.bundles_dir().display()
            ));
        }
        let _ = store.read_state()?;
        Ok(Some(store))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn read_state(&self) -> Result<Option<LocalCredentialState>, String> {
        let path = self.state_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(format!(
                    "failed to read local credential state {}: {err}",
                    path.display()
                ));
            }
        };
        let state = decode_local_credential_state(&bytes)?;
        self.require_state_projection(&state)?;
        self.verify_state_references(&state)?;
        Ok(Some(state))
    }

    pub fn stage_delivery_candidate(
        &self,
        delivery: &CredentialDeliveryBundle,
    ) -> Result<LocalCredentialState, String> {
        let active_bundle = match self.read_state()?.and_then(|state| state.active) {
            Some(reference) => Some(self.read_bundle(&reference)?),
            None => None,
        };
        let candidate =
            materialize_credential_delivery_candidate(active_bundle.as_ref(), delivery)?;
        self.stage_candidate(&candidate)
    }

    pub fn stage_candidate(
        &self,
        bundle: &CredentialDeliveryBundle,
    ) -> Result<LocalCredentialState, String> {
        self.require_bundle_projection(bundle)?;
        if bundle.dummy_non_secret {
            return Err("local credential store refuses dummy delivery bundles".to_owned());
        }
        let candidate = local_credential_bundle_ref(bundle)?;
        let current = self.read_state()?;

        let mut next = current.unwrap_or(LocalCredentialState {
            schema_version: 1,
            projection: self.projection as i32,
            active: None,
            candidate: None,
            previous: None,
        });
        if let Some(previous) = next.previous.as_ref() {
            return Err(format!(
                "previous credential generation {} must be dropped before staging a new candidate",
                previous.generation
            ));
        }
        if let Some(existing) = next.candidate.as_ref() {
            if existing == &candidate {
                return Ok(next);
            }
            return Err(format!(
                "different credential candidate generation {} is already staged",
                existing.generation
            ));
        }
        if let Some(active) = next.active.as_ref() {
            if active == &candidate {
                return Err("credential candidate is already active".to_owned());
            }
            if active.slot == candidate.slot {
                return Err(
                    "credential candidate must use the fixed slot opposite the active bundle"
                        .to_owned(),
                );
            }
        }

        next.candidate = Some(candidate.clone());
        validate_local_credential_state(&next)?;

        // Candidate validation/materialization must be side-effect free. Create the
        // protected store only after the complete next state is known valid.
        self.prepare_directories()?;
        self.persist_bundle(bundle, &candidate)?;
        self.write_state(&next)?;
        self.gc_unreferenced_bundles(&next)?;
        Ok(next)
    }

    /// One-shot first-use ONLY. The protected coordinator must already have
    /// persisted and independently read back the exact two-host COMMIT_INTENT.
    /// Caller authenticates that provider, release and BOTH prepared host
    /// witnesses match the intent. This store records a private non-secret
    /// receipt BEFORE changing the candidate pointer. An interrupted commit
    /// is UNKNOWN and may NEVER be repeated by this same mutation method.
    pub fn promote_initial_paired_candidate(
        &self,
        generation: u64,
        slot: i32,
        commit_intent_sha256: &str,
    ) -> Result<LocalCredentialState, String> {
        if generation == 0
            || !matches!(slot, 1 | 2)
            || commit_intent_sha256.len() != 64
            || !commit_intent_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(
                "initial pair commit requires exact generation/slot/intent digest".to_owned(),
            );
        }
        let current = self.read_state()?.ok_or_else(|| {
            "initial pair commit requires existing validated candidate cursor".to_owned()
        })?;
        if current.active.is_some() || current.previous.is_some() {
            return Err(
                "initial pair commit refuses pre-existing active/previous credential".to_owned(),
            );
        }
        let candidate = current
            .candidate
            .as_ref()
            .ok_or_else(|| "initial pair commit requires one local candidate".to_owned())?;
        if candidate.generation != generation || candidate.slot != slot {
            return Err(
                "initial pair commit rejects candidate generation/slot mismatch".to_owned(),
            );
        }
        let _bundle = self.read_bundle(candidate)?;
        let receipt = self.root.join(INITIAL_PAIR_COMMIT_RECEIPT);
        // Validate and never replace an existing (even incomplete) receipt.
        // An IO failure here can be unknown: reconciliation is read-only.
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut handle = options.open(&receipt).map_err(|err| {
            format!("initial pair commit receipt already attempted or uncertain: {err}")
        })?;
        let data = format!(
            "sing-box.initial-paired-commit/v1\nprojection={}\ngeneration={generation}\nslot={slot}\nintent_sha256={commit_intent_sha256}\n",
            self.projection as i32,
        );
        handle
            .write_all(data.as_bytes())
            .and_then(|_| handle.sync_all())
            .map_err(|err| format!("initial pair receipt write uncertain, do not replay: {err}"))?;
        set_private_file_permissions(&receipt)?;
        // Atomic pointer write only after durable receipt, no legacy fallback.
        // The final ACTIVE label requires independent paired readback, not this return.
        self.promote_candidate()
    }

    /// Non-secret local readback for an authenticated owner. Never treats an
    /// incomplete or malformed receipt as absence, and never repairs it.
    pub fn read_initial_pair_receipt(&self) -> Result<Option<String>, String> {
        let path = self.root.join(INITIAL_PAIR_COMMIT_RECEIPT);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(format!("initial pair receipt readback failed: {err}")),
        };
        let parts = text.lines().collect::<Vec<_>>();
        if parts.len() != 5
            || parts[0] != "sing-box.initial-paired-commit/v1"
            || parts[1] != format!("projection={}", self.projection as i32)
            || !parts[2].starts_with("generation=")
            || !parts[3].starts_with("slot=")
            || !parts[4].starts_with("intent_sha256=")
            || parts[2]["generation=".len()..].parse::<u64>().unwrap_or(0) == 0
            || !matches!(parts[3]["slot=".len()..].parse::<i32>(), Ok(1 | 2))
            || {
                let hex = &parts[4]["intent_sha256=".len()..];
                hex.len() != 64
                    || !hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
        {
            return Err(
                "initial pair receipt is incomplete or malformed; outcome UNKNOWN".to_owned(),
            );
        }
        Ok(Some(text))
    }

    pub fn promote_candidate(&self) -> Result<LocalCredentialState, String> {
        let current = self
            .read_state()?
            .ok_or_else(|| "local credential state is absent".to_owned())?;
        let candidate = current
            .candidate
            .clone()
            .ok_or_else(|| "local credential candidate is absent".to_owned())?;

        let next = LocalCredentialState {
            schema_version: 1,
            projection: self.projection as i32,
            active: Some(candidate),
            candidate: None,
            previous: current.active,
        };
        validate_local_credential_state(&next)?;
        self.write_state(&next)?;
        self.gc_unreferenced_bundles(&next)?;
        Ok(next)
    }

    pub fn rollback_previous(&self) -> Result<LocalCredentialState, String> {
        let current = self
            .read_state()?
            .ok_or_else(|| "local credential state is absent".to_owned())?;
        if current.candidate.is_some() {
            return Err("discard the staged candidate before credential rollback".to_owned());
        }
        let active = current
            .active
            .clone()
            .ok_or_else(|| "local credential active bundle is absent".to_owned())?;
        let previous = current
            .previous
            .clone()
            .ok_or_else(|| "local credential previous bundle is absent".to_owned())?;

        let next = LocalCredentialState {
            schema_version: 1,
            projection: self.projection as i32,
            active: Some(previous),
            candidate: None,
            previous: Some(active),
        };
        validate_local_credential_state(&next)?;
        self.write_state(&next)?;
        Ok(next)
    }

    pub fn discard_candidate(&self) -> Result<Option<LocalCredentialState>, String> {
        let Some(mut current) = self.read_state()? else {
            return Ok(None);
        };
        if current.candidate.is_none() {
            return Ok(Some(current));
        }
        current.candidate = None;
        if current.active.is_none() && current.previous.is_none() {
            self.remove_state_file()?;
            self.gc_all_bundles()?;
            return Ok(None);
        }
        validate_local_credential_state(&current)?;
        self.write_state(&current)?;
        self.gc_unreferenced_bundles(&current)?;
        Ok(Some(current))
    }

    pub fn drop_previous(&self) -> Result<Option<LocalCredentialState>, String> {
        let Some(mut current) = self.read_state()? else {
            return Ok(None);
        };
        if current.previous.is_none() {
            return Ok(Some(current));
        }
        current.previous = None;
        validate_local_credential_state(&current)?;
        self.write_state(&current)?;
        self.gc_unreferenced_bundles(&current)?;
        Ok(Some(current))
    }

    pub fn read_bundle(
        &self,
        reference: &LocalCredentialBundleRef,
    ) -> Result<CredentialDeliveryBundle, String> {
        let path = self.bundle_path(reference);
        let bytes = fs::read(&path).map_err(|err| {
            format!(
                "failed to read local credential bundle {}: {err}",
                path.display()
            )
        })?;
        let bundle = decode_credential_delivery_bundle(&bytes)?;
        verify_local_credential_bundle_reference(self.projection, reference, &bundle)?;
        Ok(bundle)
    }

    fn require_bundle_projection(&self, bundle: &CredentialDeliveryBundle) -> Result<(), String> {
        if bundle.projection != self.projection as i32 {
            return Err("credential bundle projection does not match local store owner".to_owned());
        }
        Ok(())
    }

    fn require_state_projection(&self, state: &LocalCredentialState) -> Result<(), String> {
        if state.projection != self.projection as i32 {
            return Err("local credential state projection does not match store owner".to_owned());
        }
        Ok(())
    }

    fn prepare_directories(&self) -> Result<(), String> {
        fs::create_dir_all(&self.root).map_err(|err| {
            format!(
                "failed to create credential store root {}: {err}",
                self.root.display()
            )
        })?;
        set_private_directory_permissions(&self.root)?;
        let bundles = self.bundles_dir();
        fs::create_dir_all(&bundles).map_err(|err| {
            format!(
                "failed to create credential bundle directory {}: {err}",
                bundles.display()
            )
        })?;
        set_private_directory_permissions(&bundles)?;
        Ok(())
    }

    fn persist_bundle(
        &self,
        bundle: &CredentialDeliveryBundle,
        reference: &LocalCredentialBundleRef,
    ) -> Result<(), String> {
        let bytes = encode_credential_delivery_bundle(bundle)?;
        if credential_delivery_bundle_sha256(bundle)? != reference.sha256 {
            return Err("credential bundle digest changed during persistence".to_owned());
        }
        let path = self.bundle_path(reference);
        if path.exists() {
            let observed = fs::read(&path).map_err(|err| {
                format!(
                    "failed to read existing credential bundle {}: {err}",
                    path.display()
                )
            })?;
            if observed != bytes {
                return Err(format!(
                    "immutable credential bundle digest path contains different bytes: {}",
                    path.display()
                ));
            }
            let decoded = decode_credential_delivery_bundle(&observed)?;
            verify_local_credential_bundle_reference(self.projection, reference, &decoded)?;
            return Ok(());
        }
        write_atomic_private(&path, &bytes)?;
        let observed = fs::read(&path).map_err(|err| {
            format!(
                "failed to re-read persisted credential bundle {}: {err}",
                path.display()
            )
        })?;
        if observed != bytes {
            return Err("persisted credential bundle failed exact byte verification".to_owned());
        }
        Ok(())
    }

    fn write_state(&self, state: &LocalCredentialState) -> Result<(), String> {
        self.require_state_projection(state)?;
        validate_local_credential_state(state)?;
        self.verify_state_references(state)?;
        let bytes = encode_local_credential_state(state)?;
        write_atomic_private(&self.state_path(), &bytes)?;
        let observed = fs::read(self.state_path())
            .map_err(|err| format!("failed to re-read persisted local credential state: {err}"))?;
        if observed != bytes {
            return Err(
                "persisted local credential state failed exact byte verification".to_owned(),
            );
        }
        Ok(())
    }

    fn verify_state_references(&self, state: &LocalCredentialState) -> Result<(), String> {
        for reference in [
            state.active.as_ref(),
            state.candidate.as_ref(),
            state.previous.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            self.read_bundle(reference)?;
        }
        Ok(())
    }

    fn gc_unreferenced_bundles(&self, state: &LocalCredentialState) -> Result<(), String> {
        let keep = [
            state.active.as_ref(),
            state.candidate.as_ref(),
            state.previous.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|reference| reference.sha256.as_str())
        .collect::<BTreeSet<_>>();

        let dir = self.bundles_dir();
        for entry in fs::read_dir(&dir).map_err(|err| {
            format!(
                "failed to enumerate credential bundle directory {}: {err}",
                dir.display()
            )
        })? {
            let entry =
                entry.map_err(|err| format!("failed to enumerate credential bundle: {err}"))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                return Err("credential bundle filename is not valid UTF-8".to_owned());
            };
            let Some(digest) = name.strip_suffix(".pb") else {
                continue;
            };
            if !keep.contains(digest) {
                fs::remove_file(&path).map_err(|err| {
                    format!(
                        "failed to remove unreferenced credential bundle {}: {err}",
                        path.display()
                    )
                })?;
            }
        }
        sync_directory(&dir)
    }

    fn gc_all_bundles(&self) -> Result<(), String> {
        let dir = self.bundles_dir();
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&dir).map_err(|err| {
            format!(
                "failed to enumerate credential bundle directory {}: {err}",
                dir.display()
            )
        })? {
            let path = entry
                .map_err(|err| format!("failed to enumerate credential bundle: {err}"))?
                .path();
            if path.is_file() {
                fs::remove_file(&path).map_err(|err| {
                    format!(
                        "failed to remove unreferenced credential bundle {}: {err}",
                        path.display()
                    )
                })?;
            }
        }
        sync_directory(&dir)
    }

    fn remove_state_file(&self) -> Result<(), String> {
        let path = self.state_path();
        match fs::remove_file(&path) {
            Ok(()) => sync_directory(&self.root),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!(
                "failed to remove local credential state {}: {err}",
                path.display()
            )),
        }
    }

    fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }

    fn bundles_dir(&self) -> PathBuf {
        self.root.join(BUNDLES_DIR)
    }

    fn bundle_path(&self, reference: &LocalCredentialBundleRef) -> PathBuf {
        self.bundles_dir().join(format!("{}.pb", reference.sha256))
    }
}

fn require_projection(projection: CredentialProjectionKind) -> Result<(), String> {
    if matches!(
        projection,
        CredentialProjectionKind::Windows | CredentialProjectionKind::Vm
    ) {
        Ok(())
    } else {
        Err("credential store projection must be Windows or VM".to_owned())
    }
}

pub fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "credential store path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "failed to create credential store directory {}: {err}",
            parent.display()
        )
    })?;
    set_private_directory_permissions(parent)?;

    let temporary = path.with_extension(
        path.extension()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}.new"))
            .unwrap_or_else(|| "new".to_owned()),
    );
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to clear stale credential temp file {}: {err}",
                temporary.display()
            ));
        }
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|err| {
            format!(
                "failed to create credential temp file {}: {err}",
                temporary.display()
            )
        })?;
    file.write_all(bytes).map_err(|err| {
        format!(
            "failed to write credential temp file {}: {err}",
            temporary.display()
        )
    })?;
    file.sync_all().map_err(|err| {
        format!(
            "failed to sync credential temp file {}: {err}",
            temporary.display()
        )
    })?;
    drop(file);
    set_private_file_permissions(&temporary)?;
    atomic_replace(&temporary, path)?;
    sync_directory(parent)
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

#[cfg(windows)]
fn atomic_replace(source: &Path, target: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let ok = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(format!(
            "failed to atomically replace credential state on Windows: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, target: &Path) -> Result<(), String> {
    fs::rename(source, target).map_err(|err| {
        format!(
            "failed to atomically replace {} with {}: {err}",
            target.display(),
            source.display()
        )
    })
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|err| format!("failed to sync directory {}: {err}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::{
        CredentialDeliverySlot, ProxyCredentialGeneration, RealityPrivateIdentity,
        RealityPrivateIdentityGeneration, RealityPublicIdentity, RealityPublicIdentityGeneration,
        TunnelAuthentication, TunnelAuthenticationGeneration, VmCredentialProjection,
        WindowsCredentialProjection, credential_delivery_bundle,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_root(label: &str) -> PathBuf {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("edge-credential-store-{label}-{value}"))
    }

    fn tunnel_auth(generation: u64) -> TunnelAuthenticationGeneration {
        TunnelAuthenticationGeneration {
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
        }
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
                    tunnel_auth: Some(tunnel_auth(generation)),
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

    fn vm_bundle(generation: u64, slot: CredentialDeliverySlot) -> CredentialDeliveryBundle {
        CredentialDeliveryBundle {
            schema_version: 1,
            generation,
            projection: CredentialProjectionKind::Vm as i32,
            dummy_non_secret: false,
            slot: slot as i32,
            payload: Some(credential_delivery_bundle::Payload::Vm(
                VmCredentialProjection {
                    tunnel_auth: Some(tunnel_auth(generation)),
                    reality_identity: Some(RealityPrivateIdentityGeneration {
                        generation,
                        direct: Some(RealityPrivateIdentity {
                            private_key: "C".repeat(43),
                        }),
                        warp: Some(RealityPrivateIdentity {
                            private_key: "D".repeat(43),
                        }),
                    }),
                    line2_proxy: Some(ProxyCredentialGeneration {
                        generation,
                        password: "e".repeat(64),
                    }),
                },
            )),
        }
    }

    #[test]
    fn invalid_candidate_validation_has_no_filesystem_side_effect() {
        let root = unique_root("invalid-side-effect");
        let store = CredentialStore::new(&root, CredentialProjectionKind::Vm).unwrap();
        assert!(!root.exists());

        let mut invalid = vm_bundle(101, CredentialDeliverySlot::B);
        invalid.dummy_non_secret = true;
        assert!(store.stage_delivery_candidate(&invalid).is_err());
        assert!(!root.exists());
    }

    #[test]
    fn paired_initial_commit_is_single_use_with_durable_receipt_and_no_replay() {
        for projection in [
            CredentialProjectionKind::Windows,
            CredentialProjectionKind::Vm,
        ] {
            let root = unique_root("first-pair");
            let store = CredentialStore::new(&root, projection).unwrap();
            let candidate = if projection == CredentialProjectionKind::Windows {
                windows_bundle(101, CredentialDeliverySlot::B)
            } else {
                vm_bundle(101, CredentialDeliverySlot::B)
            };
            store.stage_candidate(&candidate).unwrap();
            assert!(
                store
                    .promote_initial_paired_candidate(102, 2, &"a".repeat(64))
                    .is_err()
            );
            assert!(
                store
                    .promote_initial_paired_candidate(101, 1, &"a".repeat(64))
                    .is_err()
            );
            assert!(
                store
                    .promote_initial_paired_candidate(101, 2, "BAD")
                    .is_err()
            );
            assert!(store.read_initial_pair_receipt().unwrap().is_none());
            let result = store
                .promote_initial_paired_candidate(101, 2, &"a".repeat(64))
                .unwrap();
            assert_eq!(result.active.as_ref().unwrap().generation, 101);
            assert!(result.candidate.is_none());
            assert!(result.previous.is_none());
            let reopened = CredentialStore::open_existing(&root, projection)
                .unwrap()
                .unwrap();
            assert!(
                reopened
                    .read_initial_pair_receipt()
                    .unwrap()
                    .unwrap()
                    .contains("intent_sha256=")
            );
            assert!(
                reopened
                    .promote_initial_paired_candidate(101, 2, &"a".repeat(64))
                    .is_err()
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn paired_initial_commit_interrupted_receipt_never_auto_replays_pointer() {
        let root = unique_root("first-pair-unknown");
        let store = CredentialStore::new(&root, CredentialProjectionKind::Vm).unwrap();
        store
            .stage_candidate(&vm_bundle(101, CredentialDeliverySlot::B))
            .unwrap();
        store.prepare_directories().unwrap();
        fs::write(root.join(INITIAL_PAIR_COMMIT_RECEIPT), "incomplete").unwrap();
        assert!(store.read_initial_pair_receipt().is_err());
        assert!(
            store
                .promote_initial_paired_candidate(101, 2, &"a".repeat(64))
                .is_err()
        );
        let state = store.read_state().unwrap().unwrap();
        assert!(state.active.is_none());
        assert_eq!(state.candidate.as_ref().unwrap().generation, 101);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn candidate_stage_does_not_change_active_bundle() {
        let root = unique_root("stage");
        let store = CredentialStore::new(&root, CredentialProjectionKind::Windows).unwrap();
        let active = windows_bundle(100, CredentialDeliverySlot::A);
        store.stage_candidate(&active).unwrap();
        store.promote_candidate().unwrap();

        let active_ref = store.read_state().unwrap().unwrap().active.unwrap();
        let before = fs::read(store.bundle_path(&active_ref)).unwrap();

        let candidate = windows_bundle(101, CredentialDeliverySlot::B);
        let state = store.stage_candidate(&candidate).unwrap();
        let after = fs::read(store.bundle_path(state.active.as_ref().unwrap())).unwrap();

        assert_eq!(before, after);
        assert_eq!(state.active.unwrap().generation, 100);
        assert_eq!(state.candidate.unwrap().generation, 101);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn promotion_is_atomic_pointer_transition_with_bounded_previous() {
        let root = unique_root("promote");
        let store = CredentialStore::new(&root, CredentialProjectionKind::Vm).unwrap();
        store
            .stage_candidate(&vm_bundle(100, CredentialDeliverySlot::A))
            .unwrap();
        store.promote_candidate().unwrap();
        store
            .stage_candidate(&vm_bundle(101, CredentialDeliverySlot::B))
            .unwrap();
        let state = store.promote_candidate().unwrap();

        assert_eq!(state.active.as_ref().unwrap().generation, 101);
        assert_eq!(state.previous.as_ref().unwrap().generation, 100);
        assert!(state.candidate.is_none());
        assert_eq!(fs::read_dir(root.join(BUNDLES_DIR)).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn previous_must_expire_before_next_candidate() {
        let root = unique_root("bounded");
        let store = CredentialStore::new(&root, CredentialProjectionKind::Windows).unwrap();
        store
            .stage_candidate(&windows_bundle(100, CredentialDeliverySlot::A))
            .unwrap();
        store.promote_candidate().unwrap();
        store
            .stage_candidate(&windows_bundle(101, CredentialDeliverySlot::B))
            .unwrap();
        store.promote_candidate().unwrap();

        assert!(
            store
                .stage_candidate(&windows_bundle(102, CredentialDeliverySlot::A))
                .is_err()
        );
        store.drop_previous().unwrap();
        let state = store
            .stage_candidate(&windows_bundle(102, CredentialDeliverySlot::A))
            .unwrap();
        assert_eq!(state.candidate.unwrap().generation, 102);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rollback_swaps_active_and_previous_exactly() {
        let root = unique_root("rollback");
        let store = CredentialStore::new(&root, CredentialProjectionKind::Vm).unwrap();
        store
            .stage_candidate(&vm_bundle(100, CredentialDeliverySlot::A))
            .unwrap();
        store.promote_candidate().unwrap();
        store
            .stage_candidate(&vm_bundle(101, CredentialDeliverySlot::B))
            .unwrap();
        store.promote_candidate().unwrap();

        let state = store.rollback_previous().unwrap();
        assert_eq!(state.active.as_ref().unwrap().generation, 100);
        assert_eq!(state.previous.as_ref().unwrap().generation, 101);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restart_reopens_and_verifies_exact_bundle_bytes() {
        let root = unique_root("restart");
        {
            let store = CredentialStore::new(&root, CredentialProjectionKind::Windows).unwrap();
            store
                .stage_candidate(&windows_bundle(100, CredentialDeliverySlot::A))
                .unwrap();
            store.promote_candidate().unwrap();
        }

        let reopened = CredentialStore::open_existing(&root, CredentialProjectionKind::Windows)
            .unwrap()
            .unwrap();
        assert_eq!(
            reopened
                .read_state()
                .unwrap()
                .unwrap()
                .active
                .unwrap()
                .generation,
            100
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_bundle_fails_closed() {
        let root = unique_root("tamper");
        let store = CredentialStore::new(&root, CredentialProjectionKind::Vm).unwrap();
        store
            .stage_candidate(&vm_bundle(100, CredentialDeliverySlot::A))
            .unwrap();
        let state = store.read_state().unwrap().unwrap();
        let candidate = state.candidate.unwrap();
        fs::write(store.bundle_path(&candidate), b"tampered").unwrap();

        assert!(store.read_state().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_store_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_root("permissions");
        let store = CredentialStore::new(&root, CredentialProjectionKind::Windows).unwrap();
        store
            .stage_candidate(&windows_bundle(100, CredentialDeliverySlot::A))
            .unwrap();
        let state = store.read_state().unwrap().unwrap();
        let candidate = state.candidate.unwrap();

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join(BUNDLES_DIR))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join(STATE_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(store.bundle_path(&candidate))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }
}
