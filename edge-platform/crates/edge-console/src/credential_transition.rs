use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
};
use edge_secrets::{CredentialStore, write_atomic_private};
use edge_shared_types::{
    CredentialDeliveryBundle, CredentialProjectionKind, LocalCredentialState,
    WindowsActivationState, WindowsRuntimeState, WindowsTunnelBinding, credential_delivery_bundle,
    decode_windows_runtime_state, encode_windows_runtime_state, verify_windows_activation_files,
};
use edge_singbox::sync_local_config_from_runtime_state;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const LEGACY_RUNTIME_STATE_FILE: &str = "runtime-state.legacy-v1.pb";

#[derive(Clone, Copy)]
enum BundleRole {
    Active,
    Candidate,
}

pub(crate) fn apply_candidate(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(String, String), String> {
    let store = open_store(install_root)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows v2 credential state is absent".to_owned())?;
    if state.active.is_some() || state.previous.is_some() {
        return Err(
            "initial fresh-v2 candidate apply requires empty active/previous state".to_owned(),
        );
    }
    let bundle = read_bundle_for_role(&store, &state, BundleRole::Candidate)?;
    let base = read_runtime_state(install_root)?;
    let next = runtime_state_from_bundle(&base, &bundle)?;
    ensure_legacy_backup(install_root)?;
    apply_runtime_state_transaction(install_root, activation, &next)?;
    Ok((
        "CREDENTIAL_CANDIDATE_APPLIED".to_owned(),
        format!(
            "candidate generation {} applied without promotion",
            bundle.generation
        ),
    ))
}

pub(crate) fn promote(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(String, String), String> {
    let store = open_store(install_root)?;
    let before = store
        .read_state()?
        .ok_or_else(|| "Windows v2 credential state is absent".to_owned())?;
    if before.active.is_some() || before.previous.is_some() {
        return Err(
            "initial fresh-v2 promotion requires no existing v2 active/previous state".to_owned(),
        );
    }
    let state = store.promote_candidate()?;
    let bundle = read_bundle_for_role(&store, &state, BundleRole::Active)?;
    let base = read_runtime_state(install_root)?;
    let next = runtime_state_from_bundle(&base, &bundle)?;
    apply_runtime_state_transaction(install_root, activation, &next)?;
    Ok((
        "CREDENTIAL_PROMOTED".to_owned(),
        format!("active v2 generation {} applied", bundle.generation),
    ))
}

pub(crate) fn apply_active(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(String, String), String> {
    let store = open_store(install_root)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows v2 credential state is absent".to_owned())?;
    if state.candidate.is_some() {
        return Err("Windows active credential apply refuses a staged candidate".to_owned());
    }
    let bundle = read_bundle_for_role(&store, &state, BundleRole::Active)?;
    let base = read_runtime_state(install_root)?;
    let next = runtime_state_from_bundle(&base, &bundle)?;
    apply_runtime_state_transaction(install_root, activation, &next)?;
    Ok((
        "CREDENTIAL_ACTIVE_APPLIED".to_owned(),
        format!("active v2 generation {} reapplied", bundle.generation),
    ))
}

pub(crate) fn apply_legacy(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(String, String), String> {
    verify_windows_activation_files(activation)?;
    let backup = legacy_runtime_state_path(install_root);
    if !backup.is_file() {
        let current = read_runtime_state(install_root)?;
        check_runtime_config(install_root, activation)?;
        let _ = current;
        return Ok((
            "CREDENTIAL_LEGACY_ALREADY_ACTIVE".to_owned(),
            "legacy-v1 runtime remained active; no backup restoration was required".to_owned(),
        ));
    }
    let bytes = fs::read(&backup).map_err(|err| {
        format!(
            "legacy Windows runtime-state backup is unavailable at {}: {err}",
            backup.display()
        )
    })?;
    let state = decode_windows_runtime_state(&bytes)?;
    apply_runtime_state_transaction(install_root, activation, &state)?;
    Ok((
        "CREDENTIAL_LEGACY_APPLIED".to_owned(),
        "legacy-v1 runtime state restored without changing the v2 pointer".to_owned(),
    ))
}

pub(crate) fn discard_candidate(install_root: &Path) -> Result<(String, String), String> {
    let store = open_store(install_root)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows v2 credential state is absent".to_owned())?;
    if state.active.is_some() {
        return Err("initial fresh-v2 candidate discard refuses state after promotion".to_owned());
    }
    store.discard_candidate()?;
    Ok((
        "CREDENTIAL_CANDIDATE_DISCARDED".to_owned(),
        "staged Windows v2 candidate discarded".to_owned(),
    ))
}

pub(crate) fn retire_legacy(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(String, String), String> {
    let store = open_store(install_root)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows v2 credential state is absent".to_owned())?;
    if state.active.is_none() || state.candidate.is_some() {
        return Err(
            "legacy retirement requires one active v2 credential and no candidate".to_owned(),
        );
    }
    let bundle = read_bundle_for_role(&store, &state, BundleRole::Active)?;
    let current = read_runtime_state(install_root)?;
    let expected = runtime_state_from_bundle(&current, &bundle)?;
    if current != expected {
        return Err(
            "legacy retirement refused because runtime-state is not exact active v2".to_owned(),
        );
    }
    check_runtime_config(install_root, activation)?;

    let backup = legacy_runtime_state_path(install_root);
    if backup.exists() {
        fs::remove_file(&backup).map_err(|err| {
            format!(
                "failed to retire legacy Windows runtime-state backup {}: {err}",
                backup.display()
            )
        })?;
    }
    Ok((
        "CREDENTIAL_LEGACY_RETIRED".to_owned(),
        "legacy-v1 Windows runtime-state backup deleted after active-v2 verification".to_owned(),
    ))
}

fn open_store(install_root: &Path) -> Result<CredentialStore, String> {
    CredentialStore::open_existing(
        windows_credential_store_path(install_root),
        CredentialProjectionKind::Windows,
    )?
    .ok_or_else(|| "Windows v2 credential store is absent".to_owned())
}

fn read_bundle_for_role(
    store: &CredentialStore,
    state: &LocalCredentialState,
    role: BundleRole,
) -> Result<CredentialDeliveryBundle, String> {
    let reference = match role {
        BundleRole::Active => state.active.as_ref(),
        BundleRole::Candidate => state.candidate.as_ref(),
    }
    .ok_or_else(|| match role {
        BundleRole::Active => "Windows v2 active credential is absent".to_owned(),
        BundleRole::Candidate => "Windows v2 credential candidate is absent".to_owned(),
    })?;
    store.read_bundle(reference)
}

fn runtime_state_from_bundle(
    base: &WindowsRuntimeState,
    bundle: &CredentialDeliveryBundle,
) -> Result<WindowsRuntimeState, String> {
    edge_shared_types::validate_credential_delivery_bundle(bundle)?;
    if bundle.projection != CredentialProjectionKind::Windows as i32 || bundle.dummy_non_secret {
        return Err("Windows runtime projection requires a real Windows v2 bundle".to_owned());
    }
    let projection = match bundle.payload.as_ref() {
        Some(credential_delivery_bundle::Payload::Windows(value)) => value,
        _ => return Err("Windows v2 bundle payload is not Windows projection".to_owned()),
    };
    let tunnel = projection
        .tunnel_auth
        .as_ref()
        .ok_or_else(|| "Windows v2 bundle is missing tunnel authentication".to_owned())?;
    let reality = projection
        .reality_identity
        .as_ref()
        .ok_or_else(|| "Windows v2 bundle is missing Reality public identity".to_owned())?;
    let direct_auth = tunnel
        .direct
        .as_ref()
        .ok_or_else(|| "Windows v2 bundle is missing direct tunnel authentication".to_owned())?;
    let warp_auth = tunnel
        .warp
        .as_ref()
        .ok_or_else(|| "Windows v2 bundle is missing WARP tunnel authentication".to_owned())?;
    let direct_reality = reality
        .direct
        .as_ref()
        .ok_or_else(|| "Windows v2 bundle is missing direct Reality public identity".to_owned())?;
    let warp_reality = reality
        .warp
        .as_ref()
        .ok_or_else(|| "Windows v2 bundle is missing WARP Reality public identity".to_owned())?;
    let base_direct = base
        .direct
        .as_ref()
        .ok_or_else(|| "Windows runtime state direct binding is absent".to_owned())?;
    let base_warp = base
        .warp
        .as_ref()
        .ok_or_else(|| "Windows runtime state WARP binding is absent".to_owned())?;

    let state = WindowsRuntimeState {
        schema_version: 1,
        deployment_label: base.deployment_label.clone(),
        instance_id: base.instance_id.clone(),
        server_ip: base.server_ip.clone(),
        direct: Some(WindowsTunnelBinding {
            domain: base_direct.domain.clone(),
            hy2_port: base_direct.hy2_port,
            hy2_password: direct_auth.hysteria2_password.clone(),
            vless_port: base_direct.vless_port,
            vless_uuid: direct_auth.vless_uuid.clone(),
            reality_public_key: direct_reality.public_key.clone(),
            reality_short_id: direct_auth.reality_short_id.clone(),
        }),
        warp: Some(WindowsTunnelBinding {
            domain: base_warp.domain.clone(),
            hy2_port: base_warp.hy2_port,
            hy2_password: warp_auth.hysteria2_password.clone(),
            vless_port: base_warp.vless_port,
            vless_uuid: warp_auth.vless_uuid.clone(),
            reality_public_key: warp_reality.public_key.clone(),
            reality_short_id: warp_auth.reality_short_id.clone(),
        }),
    };
    edge_shared_types::encode_windows_runtime_state(&state)?;
    Ok(state)
}

fn read_runtime_state(install_root: &Path) -> Result<WindowsRuntimeState, String> {
    let path = windows_runtime_state_path(install_root);
    let bytes = fs::read(&path).map_err(|err| {
        format!(
            "failed to read Windows runtime state {}: {err}",
            path.display()
        )
    })?;
    decode_windows_runtime_state(&bytes)
}

fn legacy_runtime_state_path(install_root: &Path) -> PathBuf {
    install_root
        .join("state")
        .join("secrets")
        .join(LEGACY_RUNTIME_STATE_FILE)
}

fn ensure_legacy_backup(install_root: &Path) -> Result<(), String> {
    let backup = legacy_runtime_state_path(install_root);
    if backup.exists() {
        let bytes = fs::read(&backup)
            .map_err(|err| format!("failed to read existing legacy Windows backup: {err}"))?;
        decode_windows_runtime_state(&bytes)?;
        return Ok(());
    }
    let current_path = windows_runtime_state_path(install_root);
    let bytes = fs::read(&current_path).map_err(|err| {
        format!("failed to read current Windows runtime state for legacy backup: {err}")
    })?;
    decode_windows_runtime_state(&bytes)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup)
        .map_err(|err| format!("failed to create legacy Windows runtime-state backup: {err}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("failed to persist legacy Windows runtime-state backup: {err}"))
}

fn apply_runtime_state_transaction(
    install_root: &Path,
    activation: &WindowsActivationState,
    state: &WindowsRuntimeState,
) -> Result<(), String> {
    verify_windows_activation_files(activation)?;
    let state_path = windows_runtime_state_path(install_root);
    let config_path = local_singbox_config_path(install_root);
    let old_state = fs::read(&state_path).map_err(|err| {
        format!("failed to snapshot Windows runtime state before transition: {err}")
    })?;
    let old_config = fs::read(&config_path).map_err(|err| {
        format!("failed to snapshot Windows sing-box config before transition: {err}")
    })?;
    let next_state = encode_windows_runtime_state(state)?;

    let apply_result = (|| -> Result<(), String> {
        write_atomic_private(&state_path, &next_state)?;
        sync_local_config_from_runtime_state(&config_path, state, &install_root.join("runtime"))?;
        check_runtime_config(install_root, activation)
    })();

    if let Err(err) = apply_result {
        let state_restore = write_atomic_private(&state_path, &old_state);
        let config_restore = write_atomic_private(&config_path, &old_config);
        if let Err(restore_err) = state_restore.and(config_restore) {
            return Err(format!(
                "{err}; rollback of Windows credential transition also failed: {restore_err}"
            ));
        }
        return Err(err);
    }
    Ok(())
}

fn check_runtime_config(
    install_root: &Path,
    activation: &WindowsActivationState,
) -> Result<(), String> {
    verify_windows_activation_files(activation)?;
    let config = local_singbox_config_path(install_root);
    let status = Command::new(&activation.sing_box_path)
        .args(["check", "-c"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to execute exact sing-box check: {err}"))?;
    if !status.success() {
        return Err(format!(
            "exact sing-box check rejected Stage 2 runtime config with exit code {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::{
        CredentialDeliverySlot, RealityPublicIdentity, RealityPublicIdentityGeneration,
        TunnelAuthentication, TunnelAuthenticationGeneration, WindowsCredentialProjection,
    };

    #[test]
    fn windows_projection_preserves_endpoint_policy_and_replaces_only_secrets() {
        let base = WindowsRuntimeState {
            schema_version: 1,
            deployment_label: Some("production".to_owned()),
            instance_id: "instance-1".to_owned(),
            server_ip: "203.0.113.10".to_owned(),
            direct: Some(binding("edge.example.com", 8443, 443, "old")),
            warp: Some(binding("edge.example.com", 9444, 5443, "old-warp")),
        };
        let bundle = CredentialDeliveryBundle {
            schema_version: 1,
            generation: 55,
            projection: CredentialProjectionKind::Windows as i32,
            dummy_non_secret: false,
            slot: CredentialDeliverySlot::A as i32,
            payload: Some(credential_delivery_bundle::Payload::Windows(
                WindowsCredentialProjection {
                    tunnel_auth: Some(TunnelAuthenticationGeneration {
                        generation: 55,
                        direct: Some(auth(
                            "11111111-1111-4111-8111-111111111111",
                            'a',
                            "1111111111111111",
                        )),
                        warp: Some(auth(
                            "22222222-2222-4222-8222-222222222222",
                            'b',
                            "2222222222222222",
                        )),
                    }),
                    reality_identity: Some(RealityPublicIdentityGeneration {
                        generation: 55,
                        direct: Some(RealityPublicIdentity {
                            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                        }),
                        warp: Some(RealityPublicIdentity {
                            public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
                        }),
                    }),
                },
            )),
        };

        let next = runtime_state_from_bundle(&base, &bundle).unwrap();
        let direct = next.direct.unwrap();
        let warp = next.warp.unwrap();
        assert_eq!(direct.domain, "edge.example.com");
        assert_eq!(direct.hy2_port, 8443);
        assert_eq!(direct.vless_port, 443);
        assert_eq!(direct.vless_uuid, "11111111-1111-4111-8111-111111111111");
        assert_eq!(warp.hy2_port, 9444);
        assert_eq!(warp.vless_port, 5443);
        assert_eq!(warp.vless_uuid, "22222222-2222-4222-8222-222222222222");
    }

    fn binding(domain: &str, hy2_port: u32, vless_port: u32, suffix: &str) -> WindowsTunnelBinding {
        WindowsTunnelBinding {
            domain: domain.to_owned(),
            hy2_port,
            hy2_password: format!("{suffix}-password"),
            vless_port,
            vless_uuid: "00000000-0000-4000-8000-000000000000".to_owned(),
            reality_public_key: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_owned(),
            reality_short_id: "0000000000000000".to_owned(),
        }
    }

    fn auth(uuid: &str, fill: char, short_id: &str) -> TunnelAuthentication {
        TunnelAuthentication {
            vless_uuid: uuid.to_owned(),
            hysteria2_password: std::iter::repeat_n(fill, 64).collect(),
            reality_short_id: short_id.to_owned(),
        }
    }
}
