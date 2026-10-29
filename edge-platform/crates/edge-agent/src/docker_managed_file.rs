//! Immutable Git bundle -> single scoped root-owned managed file mutation.
//! Executed only after Worker-signed HostIntent, owner lock and durable BEGIN.
//! Never accepts a runner path or payload; no Docker exec, shell or SSH.
use super::*;
#[path = "docker_managed_object.rs"]
mod managed_object;
use managed_object::*;
#[path = "network_managed_route.rs"]
mod managed_route;
use managed_route::*;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[derive(Debug)]
pub(crate) struct NativeVmManagedFilePlan {
    path: String,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
    unchanged_sha256: Vec<(String, Vec<u8>)>,
    installed_graph: edge_shared_types::FleetVmDesiredGraph,
    pub(super) target_graph: edge_shared_types::FleetVmDesiredGraph,
    docker: Option<PreparedManagedDocker>,
    route: Option<PreparedManagedRoute>,
    release: edge_shared_types::ApplicationBundleReleaseState,
}

fn managed_file_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("managed/") else {
        return false;
    };
    name.len() <= 64
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !name.contains("..")
        && !name.ends_with('.')
}

/// The only mutable managed file subtree. Never follow symlinks or accept
/// writable-by-non-root parents, even if a Git source path looks valid.
fn checked_managed_directory(
    stack_dir: &Path,
    create: bool,
) -> Result<std::path::PathBuf, &'static str> {
    let root = fs::symlink_metadata(stack_dir).map_err(|_| "HOST_VM_MANAGED_STACK_MISSING")?;
    if !root.file_type().is_dir() || root.uid() != 0 || root.mode() & 0o022 != 0 {
        return Err("HOST_VM_MANAGED_STACK_OWNER_UNTRUSTED");
    }
    let dir = stack_dir.join("managed");
    if create {
        match fs::create_dir(&dir) {
            Ok(()) => {
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                    .map_err(|_| "HOST_VM_MANAGED_DIR_CREATE_PERMISSIONS_UNCERTAIN_NO_REPLAY")?;
                fs::File::open(stack_dir)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| "HOST_VM_MANAGED_DIR_CREATE_SYNC_UNCERTAIN_NO_REPLAY")?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("HOST_VM_MANAGED_DIR_CREATE_UNCERTAIN_NO_REPLAY"),
        }
    }
    let meta = fs::symlink_metadata(&dir).map_err(|_| "HOST_VM_MANAGED_DIR_MISSING")?;
    if !meta.file_type().is_dir() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err("HOST_VM_MANAGED_DIR_OWNER_UNTRUSTED");
    }
    Ok(dir)
}

fn checked_managed_existing_file(
    path: &Path,
    expected_uid: u32,
) -> Result<Option<Vec<u8>>, &'static str> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("HOST_VM_MANAGED_FILE_METADATA_UNAVAILABLE"),
        Ok(meta) => {
            if !meta.file_type().is_file()
                || meta.uid() != expected_uid
                || meta.nlink() != 1
                || meta.mode() & 0o022 != 0
                || meta.len() > 65_536
            {
                return Err("HOST_VM_MANAGED_FILE_OWNER_UNTRUSTED");
            }
            let bytes = fs::read(path).map_err(|_| "HOST_VM_MANAGED_FILE_READ_UNAVAILABLE")?;
            if bytes.len() as u64 != meta.len() {
                return Err("HOST_VM_MANAGED_FILE_RACE");
            }
            Ok(Some(bytes))
        }
    }
}

pub(crate) async fn preflight_native_vm_managed_file(
    stack_dir: &Path,
    host: &FleetHost,
    request: &ApplyBundleRequest,
    installed_graph: &edge_shared_types::FleetVmDesiredGraph,
    target_graph: &edge_shared_types::FleetVmDesiredGraph,
) -> Result<NativeVmManagedFilePlan, String> {
    if installed_graph != target_graph {
        return Err("HOST_VM_MANAGED_FILE_GRAPH_DRIFT".into());
    }
    let (bundle_id, bundle_digest) = crate::validate_digest_bound_bundle_request(request)?;
    let old_release = crate::read_application_release(stack_dir)
        .ok_or("HOST_VM_MANAGED_FILE_INSTALLED_RELEASE_MISSING")?;
    if old_release.bundle_digest == bundle_digest {
        return Err("HOST_VM_MANAGED_FILE_RELEASE_UNCHANGED".into());
    }
    if request.stack_files.is_empty() || request.stack_files.len() > 128 {
        return Err("HOST_VM_MANAGED_FILE_MANIFEST_INVALID".into());
    }
    let installed = super::installed_scoped_static_files(stack_dir)?;
    let mut desired = std::collections::BTreeMap::new();
    for file in &request.stack_files {
        crate::validate_bundle_relative_path(&file.relative_path)
            .map_err(|_| "HOST_VM_MANAGED_FILE_TARGET_PATH_INVALID")?;
        if desired.insert(file.relative_path.as_str(), file).is_some() {
            return Err("HOST_VM_MANAGED_FILE_MANIFEST_DUPLICATE".into());
        }
    }
    // A single manifest change; all non-managed resources must be bit-exact.
    let all = installed
        .iter()
        .map(String::as_str)
        .chain(desired.keys().copied())
        .collect::<std::collections::BTreeSet<_>>();
    let mut changed: Option<(String, Option<Vec<u8>>, Option<Vec<u8>>)> = None;
    let mut unchanged_sha256 = Vec::new();
    for name in all {
        let current = if installed.contains(name) {
            Some(super::exact_vm_policy_file(stack_dir, name)?)
        } else {
            None
        };
        let target = desired.get(name).map(|item| item.content.clone());
        if current == target {
            if let Some(content) = current {
                unchanged_sha256.push((
                    name.to_owned(),
                    ring::digest::digest(&ring::digest::SHA256, &content)
                        .as_ref()
                        .to_vec(),
                ));
            }
            continue;
        }
        if changed.is_some() || !managed_file_path(name) {
            return Err("HOST_VM_MANAGED_FILE_MULTI_OR_FOREIGN_CHANGE".into());
        }
        if let Some(item) = desired.get(name) {
            if item.sensitive
                || item.executable
                || item.content.is_empty()
                || item.content.len() > 65_536
            {
                return Err("HOST_VM_MANAGED_FILE_PAYLOAD_FORBIDDEN".into());
            }
        }
        if current.as_ref().is_some_and(|bytes| bytes.len() > 65_536) {
            return Err("HOST_VM_MANAGED_FILE_OLD_TOO_LARGE".into());
        }
        changed = Some((name.to_owned(), current, target));
    }
    let (path, before, after) = changed.ok_or("HOST_VM_MANAGED_FILE_NO_EXACT_CHANGE")?;
    let directory = stack_dir.join("managed");
    if directory.exists() {
        checked_managed_directory(stack_dir, false)?;
        let existing = checked_managed_existing_file(&stack_dir.join(&path), 0)?;
        if existing != before {
            return Err("HOST_VM_MANAGED_FILE_PRESTATE_UNPROVEN".into());
        }
    } else if before.is_some() {
        return Err("HOST_VM_MANAGED_FILE_OLD_PARENT_MISSING".into());
    }
    // All identity and content are immutable Git/ReleaseSet input;
    // the next stage still requires signed Worker admission and BEGIN.
    if host.kind != edge_shared_types::FleetHostKind::Vm as i32 {
        return Err("HOST_VM_MANAGED_FILE_HOST_KIND_INVALID".into());
    }
    let docker = if is_managed_docker_manifest(&path) {
        Some(
            preflight_managed_docker_object(host, &path, before.as_deref(), after.as_deref())
                .await?,
        )
    } else {
        None
    };
    let route = if is_managed_route_manifest(&path) {
        Some(
            preflight_managed_route(host, &path, before.as_deref(), after.as_deref()).await?,
        )
    } else {
        None
    };
    Ok(NativeVmManagedFilePlan {
        docker,
        route,
        path,
        before,
        after,
        unchanged_sha256,
        installed_graph: installed_graph.clone(),
        target_graph: target_graph.clone(),
        release: edge_shared_types::ApplicationBundleReleaseState {
            schema_version: 1,
            bundle_id,
            bundle_digest,
        },
    })
}

fn atomic_managed_file_change(
    path: &Path,
    before: Option<&[u8]>,
    after: Option<&[u8]>,
    expected_uid: u32,
) -> Result<(), &'static str> {
    if checked_managed_existing_file(path, expected_uid)?.as_deref() != before {
        return Err("HOST_VM_MANAGED_FILE_CAS_CHANGED_NO_REPLAY");
    }
    match after {
        None => {
            fs::remove_file(path).map_err(|_| "HOST_VM_MANAGED_DELETE_ACK_UNCERTAIN_NO_REPLAY")?;
        }
        Some(bytes) => {
            if bytes.is_empty() || bytes.len() > 65_536 {
                return Err("HOST_VM_MANAGED_FILE_CONTENT_INVALID");
            }
            let staging = path.with_extension("native-next");
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut out = options
                .open(&staging)
                .map_err(|_| "HOST_VM_MANAGED_FILE_STAGING_EXISTS_OR_UNAVAILABLE_NO_REPLAY")?;
            out.write_all(bytes)
                .and_then(|_| out.sync_all())
                .map_err(|_| "HOST_VM_MANAGED_FILE_WRITE_UNCERTAIN_NO_REPLAY")?;
            drop(out);
            fs::rename(&staging, path)
                .map_err(|_| "HOST_VM_MANAGED_FILE_ACTIVATION_UNCERTAIN_NO_REPLAY")?;
        }
    }
    let parent = path.parent().ok_or("HOST_VM_MANAGED_FILE_PARENT_INVALID")?;
    fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| "HOST_VM_MANAGED_FILE_SYNC_UNCERTAIN_NO_REPLAY")?;
    if checked_managed_existing_file(path, expected_uid)?.as_deref() != after {
        return Err("HOST_VM_MANAGED_FILE_POSTSTATE_UNPROVEN_NO_REPLAY");
    }
    Ok(())
}

/// Called only under signed one-shot native transaction, after durable BEGIN.
pub(crate) async fn apply_native_vm_managed_file_once(
    stack_dir: &Path,
    host: &FleetHost,
    plan: NativeVmManagedFilePlan,
) -> Result<(), String> {
    if super::compile_native_vm_desired_graph(stack_dir, host)? != plan.installed_graph {
        return Err("HOST_VM_MANAGED_GRAPH_CHANGED_NO_REPLAY".into());
    }
    for (name, hash) in &plan.unchanged_sha256 {
        let current = super::exact_vm_policy_file(stack_dir, name)?;
        if ring::digest::digest(&ring::digest::SHA256, &current).as_ref() != hash.as_slice() {
            return Err("HOST_VM_MANAGED_NEIGHBOUR_DRIFT_NO_REPLAY".into());
        }
    }
    // Re-check the exact target manifest before any native side effect.
    // The neighbor digests alone do not prove that this resource has retained
    // the pre-BEGIN state under the privileged owner lock.
    let target_path = stack_dir.join(&plan.path);
    if fs::symlink_metadata(stack_dir.join("managed")).is_ok() {
        checked_managed_directory(stack_dir, false).map_err(str::to_owned)?;
    }
    if checked_managed_existing_file(&target_path, 0)
        .map_err(str::to_owned)?
        .as_deref() != plan.before.as_deref()
    {
        return Err("HOST_VM_MANAGED_TARGET_CAS_CHANGED_NO_REPLAY".into());
    }
    // Creating the private managed directory is itself an effect and occurs
    // only after journal BEGIN; failure leaves UNKNOWN_NO_REPLAY.
    // The Docker effect is independently CAS-checked under the existing signed BEGIN.
    // Any ambiguous Docker acknowledgement preserves UNKNOWN_NO_REPLAY.
    if let Some(prepared) = plan.docker.as_ref() {
        apply_managed_docker_object_once(prepared).await?;
    }
    if let Some(prepared) = plan.route.as_ref() {
        apply_managed_route_once(prepared).await?;
    }
    checked_managed_directory(stack_dir, plan.before.is_none() && plan.after.is_some())?;
    let path = stack_dir.join(&plan.path);
    atomic_managed_file_change(&path, plan.before.as_deref(), plan.after.as_deref(), 0)
        .map_err(str::to_owned)?;
    if super::compile_native_vm_desired_graph(stack_dir, host)? != plan.target_graph {
        return Err("HOST_VM_MANAGED_GRAPH_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    crate::write_application_release(stack_dir, &plan.release)
        .map_err(|_| "HOST_VM_MANAGED_RELEASE_UNCERTAIN_NO_REPLAY")?;
    Ok(())
}

/// A bounded, non-secret diagnostic of every declared managed Docker manifest.
/// Even malformed/foreign entries yield an explicit failure, never silence.
fn managed_readback_failure(reason: &str) -> edge_shared_types::FleetVmManagedDockerReadback {
    edge_shared_types::FleetVmManagedDockerReadback {
        reason_code: reason.to_owned(),
        ..Default::default()
    }
}

fn managed_docker_state_reason(
    kind: i32,
    desired: i32,
    fingerprint: Option<&str>,
) -> (&'static str, bool) {
    use edge_shared_types::{
        FleetVmManagedDockerDesiredState as State, FleetVmManagedDockerKind as Kind,
    };
    if desired == State::Absent as i32 {
        return if fingerprint.is_none() {
            ("DESIRED_ABSENT", true)
        } else {
            ("UNEXPECTED_PRESENT", false)
        };
    }
    let Some(fingerprint) = fingerprint else {
        return ("MISSING_MANAGED_OBJECT", false);
    };
    if kind == Kind::Container as i32 {
        let running = fingerprint.split('|').nth(1);
        return match (desired, running) {
            (state, Some("R")) if state == State::Present as i32 => ("DESIRED_RUNNING", true),
            (state, Some("S")) if state == State::Stopped as i32 => ("DESIRED_STOPPED", true),
            _ => ("MANAGED_CONTAINER_STATE_MISMATCH", false),
        };
    }
    ("DESIRED_PRESENT", true)
}

pub(crate) async fn collect_native_managed_docker_readback(
    stack_dir: &Path,
    host: &FleetHost,
    docker: Option<&bollard::Docker>,
) -> Vec<edge_shared_types::FleetVmManagedDockerReadback> {
    let dir = stack_dir.join("managed");
    match fs::symlink_metadata(&dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => return vec![managed_readback_failure("MANAGED_DIRECTORY_UNREADABLE")],
        Ok(_) => {}
    }
    if checked_managed_directory(stack_dir, false).is_err() {
        return vec![managed_readback_failure("MANAGED_DIRECTORY_UNTRUSTED")];
    }
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return vec![managed_readback_failure("MANAGED_DIRECTORY_LIST_FAILED")],
    };
    let mut names = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return vec![managed_readback_failure(
                "MANAGED_DIRECTORY_ENTRY_UNREADABLE",
            )];
        };
        let Ok(name) = entry.file_name().into_string() else {
            return vec![managed_readback_failure("MANAGED_DIRECTORY_NAME_INVALID")];
        };
        if is_managed_docker_manifest(&format!("managed/{name}")) {
            names.push(name);
            if names.len() > 64 {
                return vec![managed_readback_failure("MANAGED_OBJECT_COUNT_EXCEEDED")];
            }
        }
    }
    names.sort();
    let mut rows = Vec::with_capacity(names.len());
    for name in names {
        let file = dir.join(&name);
        let mut row = managed_readback_failure("MANAGED_MANIFEST_UNPROVEN");
        let bytes = match checked_managed_existing_file(&file, 0) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                row.reason_code = "MANAGED_MANIFEST_DISAPPEARED".into();
                rows.push(row);
                continue;
            }
            Err(reason) => {
                row.reason_code = reason.into();
                rows.push(row);
                continue;
            }
        };
        let full_name = format!("managed/{name}");
        let spec = match managed_object::decode_exact_spec(host, &full_name, &bytes) {
            Ok(spec) => spec,
            Err(reason) => {
                row.reason_code = reason;
                rows.push(row);
                continue;
            }
        };
        row.resource_name = spec.resource_name.clone();
        row.kind = spec.kind;
        row.desired_state = spec.desired_state;
        row.manifest_sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .to_vec();
        if let Some(docker) = docker {
            match managed_object::observe_managed_docker_object(docker, &spec, false).await {
                Ok(fingerprint) => {
                    row.present = fingerprint.is_some();
                    row.ownership_proven = fingerprint.is_some();
                    if let Some(ref raw) = fingerprint {
                        row.fingerprint_sha256 =
                            ring::digest::digest(&ring::digest::SHA256, raw.as_bytes())
                                .as_ref()
                                .to_vec();
                    }
                    let (reason, converged) = managed_docker_state_reason(
                        spec.kind,
                        spec.desired_state,
                        fingerprint.as_deref(),
                    );
                    row.reason_code = reason.into();
                    row.converged = converged;
                }
                Err(reason) => row.reason_code = reason,
            }
        } else {
            row.reason_code = "DOCKER_ENGINE_UNAVAILABLE".into();
        }
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn docker_readback_absent_running_and_drift_are_distinct() {
        use edge_shared_types::{
            FleetVmManagedDockerDesiredState as Desired, FleetVmManagedDockerKind as Kind,
        };
        assert_eq!(
            managed_docker_state_reason(Kind::LocalVolume as i32, Desired::Absent as i32, None),
            ("DESIRED_ABSENT", true)
        );
        assert_eq!(
            managed_docker_state_reason(
                Kind::Container as i32,
                Desired::Present as i32,
                Some("opaque|R|timestamp")
            ),
            ("DESIRED_RUNNING", true)
        );
        assert_eq!(
            managed_docker_state_reason(
                Kind::Container as i32,
                Desired::Present as i32,
                Some("opaque|S|timestamp")
            ),
            ("MANAGED_CONTAINER_STATE_MISMATCH", false)
        );
        assert_eq!(
            managed_docker_state_reason(
                Kind::BridgeNetwork as i32,
                Desired::Absent as i32,
                Some("opaque")
            ),
            ("UNEXPECTED_PRESENT", false)
        );
        assert_eq!(
            managed_docker_state_reason(
                Kind::Container as i32,
                Desired::Stopped as i32,
                Some("opaque|S|timestamp")
            ),
            ("DESIRED_STOPPED", true)
        );
    }

    #[test]
    fn managed_file_scope_rejects_foreign_and_path_traversal() {
        for invalid in [
            "/etc/resolv.conf",
            "docker-compose.yml",
            "managed/../root",
            "managed/.hidden",
            "managed/a/b",
            "managed/a..b",
            "managed/",
        ] {
            assert!(!managed_file_path(invalid), "{invalid}");
        }
        assert!(managed_file_path("managed/policy.conf"));
        assert!(managed_file_path("managed/line2_rules-v2.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn managed_file_create_update_delete_is_atomic_and_private() {
        let dir = std::env::temp_dir().join(format!(
            "sing-box-managed-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir(&dir).unwrap();
        let target = dir.join("policy");
        let owner_uid = fs::metadata(&dir).unwrap().uid();
        atomic_managed_file_change(&target, None, Some(b"first"), owner_uid).unwrap();
        let meta = fs::metadata(&target).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&target).unwrap(), b"first");
        assert_eq!(
            atomic_managed_file_change(&target, Some(b"stale"), Some(b"overwrite"), owner_uid),
            Err("HOST_VM_MANAGED_FILE_CAS_CHANGED_NO_REPLAY")
        );
        atomic_managed_file_change(&target, Some(b"first"), Some(b"second"), owner_uid).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        atomic_managed_file_change(&target, Some(b"second"), None, owner_uid).unwrap();
        assert!(!target.exists());
        fs::remove_dir(dir).unwrap();
    }
}
