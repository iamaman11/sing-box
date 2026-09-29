use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use edge_controller_core::{
    local_singbox_config_path, windows_credential_store_path, windows_runtime_state_path,
};
use edge_local_runtime::{LocalRuntimePaths, restart_local_runtime};
use edge_secrets::{CredentialStore, write_private_atomic_file};
use edge_shared_types::{
    CredentialCandidateAcceptance, CredentialDeliveryBundle, CredentialProjectionKind,
    LocalCredentialState, TraceObservation, WindowsCredentialProjection, WindowsRuntimeState,
    credential_delivery_bundle, decode_windows_runtime_state, encode_windows_runtime_state,
    validate_windows_runtime_state,
};
use edge_trace::trace_via_proxy;

const LEGACY_RUNTIME_BACKUP: &str = "legacy-runtime-state-v1.pb";

pub async fn probe_candidate(
    repo_root: &Path,
) -> Result<CredentialCandidateAcceptance, String> {
    let store = open_store(repo_root)?;
    let state = store
        .read_state()?
        .ok_or_else(|| "Windows credential state is absent".to_owned())?;
    let candidate_ref = state
        .candidate
        .as_ref()
        .ok_or_else(|| "Windows credential candidate is absent".to_owned())?
        .clone();
    if state.candidate_acceptance_enabled {
        return Err(
            "Windows candidate probe must remain one-shot and cannot persist candidate acceptance"
                .to_owned(),
        );
    }

    let bundle = store.read_bundle(&candidate_ref)?;
    let projection = windows_projection(&bundle)?;
    let tunnel = projection
        .tunnel_auth
        .as_ref()
        .ok_or_else(|| "Windows candidate tunnel authentication is missing".to_owned())?;
    let runtime = read_runtime_state(repo_root)?;
    let direct_binding = runtime
        .direct
        .as_ref()
        .ok_or_else(|| "Windows runtime direct binding is missing".to_owned())?;
    let warp_binding = runtime
        .warp
        .as_ref()
        .ok_or_else(|| "Windows runtime WARP binding is missing".to_owned())?;
    let direct_auth = tunnel
        .direct
        .as_ref()
        .ok_or_else(|| "Windows candidate direct authentication is missing".to_owned())?;
    let warp_auth = tunnel
        .warp
        .as_ref()
        .ok_or_else(|| "Windows candidate WARP authentication is missing".to_owned())?;

    let direct = run_hy2_trace(
        repo_root,
        "direct",
        &direct_binding.domain,
        direct_binding.hy2_port,
        &direct_auth.hysteria2_password,
    )
    .await?;
    let warp = run_hy2_trace(
        repo_root,
        "warp",
        &warp_binding.domain,
        warp_binding.hy2_port,
        &warp_auth.hysteria2_password,
    )
    .await?;

    Ok(CredentialCandidateAcceptance {
        direct_pass: direct.available && direct.warp.as_deref() == Some("off"),
        warp_pass: warp.available && matches!(warp.warp.as_deref(), Some("on") | Some("plus")),
        candidate: Some(candidate_ref),
        direct_colo: direct.colo.unwrap_or_default(),
        warp_colo: warp.colo.unwrap_or_default(),
    })
}

pub fn promote_candidate(repo_root: &Path) -> Result<LocalCredentialState, String> {
    let store = open_store(repo_root)?;
    let before = store
        .read_state()?
        .ok_or_else(|| "Windows credential state is absent".to_owned())?;
    let candidate = before
        .candidate
        .as_ref()
        .ok_or_else(|| "Windows credential candidate is absent".to_owned())?;
    let candidate_bundle = store.read_bundle(candidate)?;
    let current_bytes = fs::read(windows_runtime_state_path(repo_root))
        .map_err(|err| format!("failed to read active Windows runtime state: {err}"))?;
    let current = decode_windows_runtime_state(&current_bytes)?;
    let next = runtime_state_with_bundle(&current, &candidate_bundle)?;
    let next_bytes = encode_windows_runtime_state(&next)?;

    if before.active.is_none() && before.previous.is_none() {
        ensure_legacy_backup(repo_root, &current_bytes)?;
    }

    let promoted = store.promote_candidate()?;
    if let Err(err) = write_private_atomic_file(&windows_runtime_state_path(repo_root), &next_bytes) {
        let _ = reverse_promotion(&store, &promoted);
        return Err(format!("failed to publish promoted Windows runtime state: {err}"));
    }

    if let Err(err) = restart_runtime(repo_root) {
        let _ = write_private_atomic_file(&windows_runtime_state_path(repo_root), &current_bytes);
        let _ = reverse_promotion(&store, &promoted);
        let _ = restart_runtime(repo_root);
        return Err(format!(
            "Windows credential promotion restart failed; automatic rollback attempted: {err}"
        ));
    }
    Ok(promoted)
}

pub fn rollback(repo_root: &Path) -> Result<LocalCredentialState, String> {
    let store = open_store(repo_root)?;
    let before = store
        .read_state()?
        .ok_or_else(|| "Windows credential state is absent".to_owned())?;
    let current_bytes = fs::read(windows_runtime_state_path(repo_root))
        .map_err(|err| format!("failed to read active Windows runtime state: {err}"))?;
    let current = decode_windows_runtime_state(&current_bytes)?;

    let (rolled, target_bytes, initial) = if let Some(previous) = before.previous.as_ref() {
        let bundle = store.read_bundle(previous)?;
        let target = runtime_state_with_bundle(&current, &bundle)?;
        (
            store.rollback_previous()?,
            encode_windows_runtime_state(&target)?,
            false,
        )
    } else {
        let backup = fs::read(legacy_backup_path(repo_root)).map_err(|err| {
            format!("initial Windows v2 rollback requires the legacy runtime backup: {err}")
        })?;
        decode_windows_runtime_state(&backup)?;
        (store.demote_initial_active_to_candidate()?, backup, true)
    };

    if let Err(err) = write_private_atomic_file(&windows_runtime_state_path(repo_root), &target_bytes)
    {
        let _ = reverse_rollback(&store, initial);
        return Err(format!("failed to publish rolled-back Windows runtime state: {err}"));
    }

    if let Err(err) = restart_runtime(repo_root) {
        let _ = write_private_atomic_file(&windows_runtime_state_path(repo_root), &current_bytes);
        let _ = reverse_rollback(&store, initial);
        let _ = restart_runtime(repo_root);
        return Err(format!(
            "Windows credential rollback restart failed; active state restoration attempted: {err}"
        ));
    }
    Ok(rolled)
}

pub fn expire_previous(repo_root: &Path) -> Result<Option<LocalCredentialState>, String> {
    let store = open_store(repo_root)?;
    let state = store.drop_previous()?;
    if state.as_ref().is_some_and(|value| {
        value.active.is_some()
            && value.candidate.is_none()
            && value.previous.is_none()
            && !value.candidate_acceptance_enabled
    }) {
        match fs::remove_file(legacy_backup_path(repo_root)) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!("failed to expire legacy Windows runtime backup: {err}"));
            }
        }
    }
    Ok(state)
}

fn open_store(repo_root: &Path) -> Result<CredentialStore, String> {
    CredentialStore::open_existing(
        windows_credential_store_path(repo_root),
        CredentialProjectionKind::Windows,
    )?
    .ok_or_else(|| "Windows credential store is absent".to_owned())
}

fn read_runtime_state(repo_root: &Path) -> Result<WindowsRuntimeState, String> {
    let bytes = fs::read(windows_runtime_state_path(repo_root))
        .map_err(|err| format!("failed to read Windows runtime state: {err}"))?;
    decode_windows_runtime_state(&bytes)
}

fn runtime_state_with_bundle(
    base: &WindowsRuntimeState,
    bundle: &CredentialDeliveryBundle,
) -> Result<WindowsRuntimeState, String> {
    let projection = windows_projection(bundle)?;
    let tunnel = projection
        .tunnel_auth
        .as_ref()
        .ok_or_else(|| "Windows tunnel authentication is missing".to_owned())?;
    let reality = projection
        .reality_identity
        .as_ref()
        .ok_or_else(|| "Windows Reality identity is missing".to_owned())?;
    let direct_auth = tunnel
        .direct
        .as_ref()
        .ok_or_else(|| "Windows direct tunnel authentication is missing".to_owned())?;
    let warp_auth = tunnel
        .warp
        .as_ref()
        .ok_or_else(|| "Windows WARP tunnel authentication is missing".to_owned())?;
    let direct_reality = reality
        .direct
        .as_ref()
        .ok_or_else(|| "Windows direct Reality identity is missing".to_owned())?;
    let warp_reality = reality
        .warp
        .as_ref()
        .ok_or_else(|| "Windows WARP Reality identity is missing".to_owned())?;

    let mut next = base.clone();
    let direct = next
        .direct
        .as_mut()
        .ok_or_else(|| "Windows runtime direct binding is missing".to_owned())?;
    direct.hy2_password = direct_auth.hysteria2_password.clone();
    direct.vless_uuid = direct_auth.vless_uuid.clone();
    direct.reality_public_key = direct_reality.public_key.clone();
    direct.reality_short_id = direct_auth.reality_short_id.clone();

    let warp = next
        .warp
        .as_mut()
        .ok_or_else(|| "Windows runtime WARP binding is missing".to_owned())?;
    warp.hy2_password = warp_auth.hysteria2_password.clone();
    warp.vless_uuid = warp_auth.vless_uuid.clone();
    warp.reality_public_key = warp_reality.public_key.clone();
    warp.reality_short_id = warp_auth.reality_short_id.clone();

    validate_windows_runtime_state(&next)?;
    Ok(next)
}

fn windows_projection(
    bundle: &CredentialDeliveryBundle,
) -> Result<&WindowsCredentialProjection, String> {
    match bundle.payload.as_ref() {
        Some(credential_delivery_bundle::Payload::Windows(value))
            if bundle.projection == CredentialProjectionKind::Windows as i32
                && !bundle.dummy_non_secret =>
        {
            Ok(value)
        }
        _ => Err("credential bundle is not a real Windows projection".to_owned()),
    }
}

fn ensure_legacy_backup(repo_root: &Path, current_bytes: &[u8]) -> Result<(), String> {
    let path = legacy_backup_path(repo_root);
    if path.exists() {
        let existing = fs::read(&path)
            .map_err(|err| format!("failed to read legacy Windows runtime backup: {err}"))?;
        decode_windows_runtime_state(&existing)?;
        return Ok(());
    }
    write_private_atomic_file(&path, current_bytes)
}

fn legacy_backup_path(repo_root: &Path) -> PathBuf {
    windows_credential_store_path(repo_root).join(LEGACY_RUNTIME_BACKUP)
}

fn reverse_promotion(
    store: &CredentialStore,
    promoted: &LocalCredentialState,
) -> Result<LocalCredentialState, String> {
    if promoted.previous.is_some() {
        store.rollback_previous()
    } else {
        store.demote_initial_active_to_candidate()
    }
}

fn reverse_rollback(
    store: &CredentialStore,
    initial: bool,
) -> Result<LocalCredentialState, String> {
    if initial {
        store.promote_candidate()
    } else {
        store.rollback_previous()
    }
}

fn restart_runtime(repo_root: &Path) -> Result<(), String> {
    let paths = LocalRuntimePaths {
        singbox_binary_path: singbox_binary_path()?,
        config_path: local_singbox_config_path(repo_root),
        state_path: windows_runtime_state_path(repo_root),
        runtime_root: repo_root.join("runtime"),
    };
    restart_local_runtime(&paths).map(|_| ())
}

fn singbox_binary_path() -> Result<PathBuf, String> {
    let current = std::env::current_exe()
        .map_err(|err| format!("failed to locate installed controller executable: {err}"))?;
    let parent = current
        .parent()
        .ok_or_else(|| "installed controller executable has no parent directory".to_owned())?;
    let binary = parent.join("sing-box.exe");
    if !binary.is_file() {
        return Err(format!("installed sing-box binary is missing: {}", binary.display()));
    }
    Ok(binary)
}

async fn run_hy2_trace(
    repo_root: &Path,
    label: &str,
    server: &str,
    server_port: u32,
    password: &str,
) -> Result<TraceObservation, String> {
    let binary = singbox_binary_path()?;
    let root = repo_root.join("runtime").join("credential-candidate-probe");
    fs::create_dir_all(&root)
        .map_err(|err| format!("failed to prepare candidate probe directory: {err}"))?;
    let proxy_port = reserve_local_port()?;
    let config_path = root.join(format!("{label}.json"));
    let config = serde_json::json!({
        "log": {"level": "warn", "timestamp": true},
        "inbounds": [{
            "type": "mixed",
            "tag": "candidate-in",
            "listen": "127.0.0.1",
            "listen_port": proxy_port
        }],
        "outbounds": [{
            "type": "hysteria2",
            "tag": "candidate-out",
            "server": server,
            "server_port": server_port,
            "password": password,
            "tls": {"enabled": true, "server_name": server}
        }],
        "route": {"final": "candidate-out"}
    });
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|err| format!("failed to encode candidate probe config: {err}"))?;
    write_private_atomic_file(&config_path, &bytes)?;

    let check = Command::new(&binary)
        .args(["check", "-c"])
        .arg(&config_path)
        .output()
        .map_err(|err| format!("failed to run candidate sing-box preflight: {err}"))?;
    if !check.status.success() {
        let detail = String::from_utf8_lossy(&check.stderr).trim().to_owned();
        let _ = fs::remove_file(&config_path);
        return Err(if detail.is_empty() {
            format!("candidate sing-box config was rejected with status {}", check.status)
        } else {
            format!("candidate sing-box config was rejected: {detail}")
        });
    }

    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("failed to start candidate proxy runtime: {err}"))?;
    let address = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to observe candidate proxy runtime: {err}"))?
        {
            let _ = fs::remove_file(&config_path);
            return Err(format!("candidate proxy runtime exited before readiness: {status}"));
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&config_path);
            return Err("candidate proxy listener did not become ready within 10 seconds".to_owned());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let trace = trace_via_proxy(&format!("http://127.0.0.1:{proxy_port}")).await;
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&config_path);
    if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok() {
        return Err("candidate proxy listener leaked after cleanup".to_owned());
    }
    Ok(trace)
}

fn reserve_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|err| format!("failed to reserve candidate proxy port: {err}"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|err| format!("failed to observe candidate proxy port: {err}"))
}
