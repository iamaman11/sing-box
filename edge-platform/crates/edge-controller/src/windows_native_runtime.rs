//! Existing Controller is a supervised child effector, never a second
//! administrative owner. Only SYSTEM can sign its per-process delegation.
use super::*;
use edge_shared_types::{FleetWindowsRuntimeChallenge, windows_runtime_effect};
use prost::Message;
use ring::rand::SecureRandom;
use std::collections::BTreeMap;
static NONCE: OnceLock<[u8; 32]> = OnceLock::new();
static USED: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
fn active(root: &Path) -> Result<edge_shared_types::WindowsActivationState, &'static str> {
    if !is_installed_windows_root(root) {
        return Err("HOST_WINDOWS_EFFECT_INSTALLED_ROOT_REQUIRED");
    }
    let bytes = fs::read(root.join("current.pb"))
        .map_err(|_| "HOST_WINDOWS_EFFECT_ACTIVATION_UNAVAILABLE")?;
    let state = edge_shared_types::decode_windows_activation_state(&bytes)
        .map_err(|_| "HOST_WINDOWS_EFFECT_ACTIVATION_INVALID")?;
    edge_shared_types::verify_windows_activation_files(&state)
        .map_err(|_| "HOST_WINDOWS_EFFECT_RELEASE_FILES_INVALID")?;
    let this = env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|_| "HOST_WINDOWS_EFFECT_EXECUTABLE_UNPROVEN")?;
    if Path::new(&state.controller_path)
        .canonicalize()
        .map_err(|_| "HOST_WINDOWS_EFFECT_EXECUTABLE_UNPROVEN")?
        != this
    {
        return Err("HOST_WINDOWS_EFFECT_EXECUTABLE_MISMATCH");
    }
    Ok(state)
}
pub(super) fn challenge(root: &Path) -> Result<FleetWindowsRuntimeChallenge, &'static str> {
    let state = active(root)?;
    let mut bytes = [0; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "HOST_WINDOWS_EFFECT_RANDOM_UNAVAILABLE")?;
    let nonce = *NONCE.get_or_init(|| bytes);
    let release = state
        .release_set_sha256
        .as_bytes()
        .chunks_exact(2)
        .map(|p| {
            u8::from_str_radix(
                std::str::from_utf8(p).map_err(|_| "HOST_WINDOWS_EFFECT_RELEASE_INVALID")?,
                16,
            )
            .map_err(|_| "HOST_WINDOWS_EFFECT_RELEASE_INVALID")
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FleetWindowsRuntimeChallenge {
        nonce: nonce.to_vec(),
        process_id: std::process::id() as u64,
        installed_release_sha256: release,
    })
}
pub(super) async fn execute(
    root: &Path,
    request: StartLocalRuntimeRequest,
) -> Result<LocalRuntimeResponse, String> {
    if request.singbox_binary_path.is_some()
        || request.config_path.is_some()
        || request.state_path.is_some()
        || request.force_restart
        || request.visible_window
    {
        return Err("HOST_WINDOWS_EFFECT_PATH_OR_MODE_OVERRIDE_FORBIDDEN".into());
    }
    let effect = windows_runtime_effect::decode(&request.native_system_effect)?;
    let intent = effect
        .intent
        .as_ref()
        .ok_or("HOST_WINDOWS_EFFECT_INTENT_MISSING")?;
    // The single SYSTEM owner has already authenticated protected Git. Trust
    // its signed public context, NOT arbitrary caller keys or another HTTP
    // authorizer. The kernel protects this enrolled public identity from write.
    let public_path = root.join("native-host/receipt-public-key.bin");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&public_path, true)?;
    let public =
        fs::read(&public_path).map_err(|_| "HOST_WINDOWS_EFFECT_LOCAL_IDENTITY_UNAVAILABLE")?;
    windows_runtime_effect::verify_system_signature(&effect, &public)?;
    let registry = edge_shared_types::decode_host_registry(&effect.registry_pb)
        .map_err(|_| "HOST_WINDOWS_EFFECT_REGISTRY_INVALID")?;
    let registry_sha = ring::digest::digest(&ring::digest::SHA256, &registry.encode_to_vec())
        .as_ref()
        .to_vec();
    let spec = &effect.selected_spec_bytes;
    let host = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == intent.machine_id)
        .ok_or("HOST_WINDOWS_EFFECT_MACHINE_UNREGISTERED")?;
    let computer = env::var("COMPUTERNAME").map_err(|_| "HOST_WINDOWS_EFFECT_MACHINE_UNPROVEN")?;
    if host.native_receipt_public_key != public {
        return Err("HOST_WINDOWS_EFFECT_LOCAL_IDENTITY_PIN_MISMATCH".into());
    }
    if !matches!(host.owner.as_ref(),Some(edge_shared_types::managed_host::Owner::WindowsRunnerName(n)) if n.eq_ignore_ascii_case(&computer))
    {
        return Err("HOST_WINDOWS_EFFECT_MACHINE_MISMATCH".into());
    }
    let expected = challenge(root)?;
    let path = default_local_config_path(root);
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&path, true)?;
    let bytes = fs::read(&path).map_err(|_| "HOST_WINDOWS_EFFECT_CONFIG_UNAVAILABLE")?;
    if bytes.len() > 1024 * 1024 {
        return Err("HOST_WINDOWS_EFFECT_CONFIG_TOO_LARGE".into());
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "HOST_WINDOWS_EFFECT_CLOCK_INVALID")?
        .as_secs();
    windows_runtime_effect::verify(
        &effect,
        &expected,
        &registry,
        &registry_sha,
        spec,
        digest.as_ref(),
        now,
    )?;
    let state = active(root)?;
    let paths = LocalRuntimePaths {
        singbox_binary_path: PathBuf::from(&state.sing_box_path),
        config_path: path,
        state_path: windows_runtime_state_path(root),
        runtime_root: default_runtime_root(root),
    };
    let started = tokio::task::block_in_place(|| {
        let _gate = WINDOWS_RUNTIME_OWNER_GATE
            .lock()
            .map_err(|_| "HOST_WINDOWS_EFFECT_OWNER_LOCK_POISONED")?;
        windows_runtime_effect::consume(
            &mut *USED
                .lock()
                .map_err(|_| "HOST_WINDOWS_EFFECT_REPLAY_LOCK_POISONED")?,
            &intent.operation_id,
            effect.expires_at_unix,
            now,
        )?;
        edge_local_runtime::start_native_verified_proxy(&paths)
    })?;
    let supervisor_root = root.to_path_buf();
    tokio::spawn(async move {
        if let Err(e) = supervise_windows_managed_child(supervisor_root.clone()).await {
            let _ = write_controller_service_error(&supervisor_root, "native_child_exit", &e);
        }
    });
    Ok(LocalRuntimeResponse {
        success: true,
        pid: started.pid,
        note: started.note,
        warnings: started.warnings,
        operation: None,
        local_singbox: Some(started.local_singbox),
    })
}
