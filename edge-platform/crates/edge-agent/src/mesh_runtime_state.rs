// Cohesive native Rust module; no new runtime owner or workflow.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MeshDiagnosticDepth {
    Basic,
    Deep,
}

pub(super) fn mesh_runtime_failure_snapshot_path(stack_dir: &Path) -> Result<PathBuf, String> {
    Ok(mesh_runtime_state_dir(stack_dir)?.join(MESH_RUNTIME_FAILURE_FILE))
}

pub(super) fn read_mesh_runtime_failure_snapshot(
    stack_dir: &Path,
) -> Result<Option<MeshRuntimeFailureSnapshot>, String> {
    let path = mesh_runtime_failure_snapshot_path(stack_dir)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read persisted Mesh readiness failure snapshot: {err}"
            ));
        }
    };
    let snapshot = MeshRuntimeFailureSnapshot::decode(bytes.as_slice())
        .map_err(|err| format!("failed to decode Mesh readiness failure protobuf: {err}"))?;
    if snapshot.encode_to_vec() != bytes {
        return Err(
            "persisted Mesh readiness failure snapshot is not canonical protobuf".to_owned(),
        );
    }
    Ok(Some(snapshot))
}

pub(super) fn build_mesh_runtime_failure_snapshot(
    diagnostics: Option<&MeshRuntimeDiagnostics>,
    warnings: &[String],
    exact_image_ready: bool,
) -> MeshRuntimeFailureSnapshot {
    let container = diagnostics.and_then(|value| value.container.as_ref());
    MeshRuntimeFailureSnapshot {
        observed_unix_time_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        reasons: warnings
            .iter()
            .take(MAX_MESH_FAILURE_REASONS)
            .map(|value| bounded_secret_safe_failure_reason(value))
            .collect(),
        warp_connection_state: diagnostics.and_then(|value| value.warp_connection_state.clone()),
        tunnel_protocol: diagnostics.and_then(|value| value.tunnel_protocol.clone()),
        warp_status: diagnostics
            .and_then(|value| value.warp_status_probe.as_ref())
            .map(|value| value.status)
            .unwrap_or(RuntimeProbeStatus::Unspecified as i32),
        warp_settings: diagnostics
            .and_then(|value| value.warp_settings_probe.as_ref())
            .map(|value| value.status)
            .unwrap_or(RuntimeProbeStatus::Unspecified as i32),
        tun_device_status: diagnostics
            .and_then(|value| value.tun_device_probe.as_ref())
            .map(|value| value.status)
            .unwrap_or(RuntimeProbeStatus::Unspecified as i32),
        ipv4_forwarding_status: diagnostics
            .and_then(|value| value.ipv4_forwarding_probe.as_ref())
            .map(|value| value.status)
            .unwrap_or(RuntimeProbeStatus::Unspecified as i32),
        container_present: container.is_some_and(|value| value.present),
        container_running: container.is_some_and(|value| value.running),
        container_exit_code: container.and_then(|value| value.exit_code),
        container_restart_count: container.and_then(|value| value.restart_count),
        container_oom_killed: container.and_then(|value| value.oom_killed),
        container_image: container.and_then(|value| value.image.clone()),
        container_networks: container
            .map(|value| value.networks.clone())
            .unwrap_or_default(),
        exact_image_ready,
    }
}

pub(super) fn persist_mesh_runtime_failure_snapshot(
    stack_dir: &Path,
    snapshot: &MeshRuntimeFailureSnapshot,
) -> Result<(), String> {
    prepare_mesh_runtime_state(stack_dir)?;
    let bytes = snapshot.encode_to_vec();
    let path = mesh_runtime_failure_snapshot_path(stack_dir)?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|err| format!("failed to write Mesh readiness failure snapshot: {err}"))?;
    set_bundle_file_permissions(&temporary, false, true)?;
    fs::rename(&temporary, &path)
        .map_err(|err| format!("failed to publish Mesh readiness failure snapshot: {err}"))?;
    Ok(())
}

pub(super) fn bounded_secret_safe_failure_reason(value: &str) -> String {
    let lowered = value.to_ascii_lowercase();
    if [
        "authorization",
        "bearer ",
        "password",
        "private_key",
        "private key",
        "credential",
        "mesh_node_token",
        "token=",
        "secret=",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        return "[REDACTED_SENSITIVE_REASON]".to_owned();
    }
    value.chars().take(MAX_MESH_FAILURE_REASON_CHARS).collect()
}

pub(super) async fn inspect_mesh_runtime(
    stack_dir: &Path,
    diagnostic_depth: MeshDiagnosticDepth,
) -> MeshRuntimeState {
    let token_store_path = mesh_runtime_secret_path(stack_dir).ok();
    let token_store_present = token_store_path.as_ref().is_some_and(|path| path.is_file());
    let token_valid = read_mesh_node_token(stack_dir).is_ok();
    let (docker, docker_error) = match observe_docker().await {
        Ok(observation) => (observation, None),
        Err(err) => (DockerObservation::unreachable(), Some(err)),
    };
    let container_running = docker.container_running(MESH_CONTAINER);
    let expected_image = read_exact_image_environment(stack_dir)
        .ok()
        .and_then(|images| images.get(EDGE_MESH_IMAGE_KEY).cloned());
    let exact_image_ready = expected_image
        .as_deref()
        .is_some_and(|expected| docker.container_exact_image_ready(MESH_CONTAINER, expected));
    let diagnostics = match diagnostic_depth {
        MeshDiagnosticDepth::Basic if container_running && exact_image_ready => {
            Some(collect_mesh_runtime_diagnostics(&docker, diagnostic_depth).await)
        }
        MeshDiagnosticDepth::Deep => {
            Some(collect_mesh_runtime_diagnostics(&docker, diagnostic_depth).await)
        }
        MeshDiagnosticDepth::Basic => None,
    };
    let runtime_ready = token_valid
        && container_running
        && exact_image_ready
        && diagnostics
            .as_ref()
            .is_some_and(mesh_runtime_diagnostics_ready);

    let mut warnings = Vec::new();
    if let Some(err) = docker_error {
        warnings.push(format!("Docker runtime observation failed: {err}"));
    }
    if !token_store_present {
        warnings.push("Mesh runtime token store is absent".to_owned());
    } else if !token_valid {
        warnings.push("Mesh runtime token store is invalid".to_owned());
    }
    if !container_running {
        warnings.push("Mesh runtime container is not running".to_owned());
    }
    if container_running && !exact_image_ready {
        warnings.push("Mesh runtime container does not use the exact accepted image".to_owned());
    }
    if let Some(diagnostics) = diagnostics.as_ref()
        && !mesh_runtime_diagnostics_ready(diagnostics)
    {
        append_mesh_runtime_diagnostic_warnings(diagnostics, &mut warnings);
        if let Some(container) = diagnostics.container.as_ref() {
            warnings.push(format!(
                "Mesh runtime container evidence: {}",
                mesh_container_diagnostic_summary(container)
            ));
        }
        warnings.push(mesh_tunnel_protocol_evidence_from_diagnostics(diagnostics));
    }

    let mut last_failure_snapshot = read_mesh_runtime_failure_snapshot(stack_dir).unwrap_or(None);
    if !runtime_ready && diagnostic_depth == MeshDiagnosticDepth::Deep {
        let snapshot =
            build_mesh_runtime_failure_snapshot(diagnostics.as_ref(), &warnings, exact_image_ready);
        if let Err(err) = persist_mesh_runtime_failure_snapshot(stack_dir, &snapshot) {
            warnings.push(format!(
                "Mesh readiness failure snapshot persistence failed: {}",
                bounded_secret_safe_failure_reason(&err)
            ));
        }
        last_failure_snapshot = Some(snapshot);
    }

    MeshRuntimeState {
        token_store_present,
        container_running,
        exact_image_ready,
        runtime_ready,
        warnings,
        diagnostics,
        last_failure_snapshot,
        registration_id: read_mesh_registration_id(stack_dir).unwrap_or(None),
    }
}
