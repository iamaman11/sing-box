//! One Windows LocalSystem execution path for the already-installed
//! EdgePlatformPrivilegedDispatch task. GitHub is transport, never SCM owner.
//! The protected trust + journal must be enrolled separately by SYSTEM;
//! their absence is a hard denial, not permission for a runner fallback.

use super::*;
use edge_shared_types::{
    FleetHostAction, FleetHostAuthorization, FleetHostIntent, FleetHostKind, FleetHostPlannedStep,
    FleetNativeObservation, FleetNativeTrustSnapshot,
    host_journal::verify_native_journal_protection,
    host_lifecycle::{bind_native_host_artifacts, decode_host_intent},
    host_receipt::{check_native_receipt_key, sign_native_receipt},
};
use prost::Message;
use ring::digest::{SHA256, digest};

const INTENT_FILE: &str = "host-intent.pb";
const RECEIPT_FILE: &str = "host-receipt.pb";
const RECEIPT_KEY_FILE: &str = "receipt-key.pk8";

/// Keep the exact exchange object non-writable and non-replaceable while
/// authorizing/executing. Consume by handle, never unlink a swapped pathname.
pub(super) struct TransportRequest {
    file: File,
    pub(super) bytes: Vec<u8>,
}
impl TransportRequest {
    pub(super) fn open(path: &Path, max: u64) -> Result<Self, &'static str> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let mut file = OpenOptions::new()
            .read(true)
            .access_mode(0x80000000 | 0x00010000)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(path)
            .map_err(|_| "HOST_WINDOWS_TRANSPORT_REQUEST_LOCK_UNAVAILABLE")?;
        let meta = file
            .metadata()
            .map_err(|_| "HOST_WINDOWS_TRANSPORT_REQUEST_METADATA_UNAVAILABLE")?;
        if !meta.is_file()
            || meta.file_attributes() & 0x400 != 0
            || meta.len() == 0
            || meta.len() > max
        {
            return Err("HOST_WINDOWS_TRANSPORT_REQUEST_NOT_BOUNDED_REGULAR");
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "HOST_WINDOWS_TRANSPORT_REQUEST_READ_UNAVAILABLE")?;
        if bytes.len() as u64 != meta.len() {
            return Err("HOST_WINDOWS_TRANSPORT_REQUEST_CHANGED");
        }
        Ok(Self { file, bytes })
    }
    pub(super) fn consume(self) -> Result<(), &'static str> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };
        let delete = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                FileDispositionInfo,
                (&delete as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&delete) as u32,
            )
        } == 0
        {
            return Err("HOST_WINDOWS_REQUEST_CONSUMPTION_UNKNOWN_NO_REPLAY");
        }
        Ok(())
    }
}

pub(super) fn bounded_regular_file(path: &Path, max: u64) -> Result<Vec<u8>, &'static str> {
    let meta = fs::symlink_metadata(path).map_err(|_| "HOST_WINDOWS_NATIVE_FILE_MISSING")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > max {
        return Err("HOST_WINDOWS_NATIVE_FILE_NOT_BOUNDED_REGULAR");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "HOST_WINDOWS_NATIVE_FILE_UNREADABLE")?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "HOST_WINDOWS_NATIVE_FILE_UNREADABLE")?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err("HOST_WINDOWS_NATIVE_FILE_NOT_BOUNDED_REGULAR");
    }
    Ok(bytes)
}

/// The installed ReleaseSet and the immutable SYSTEM trust are two
/// independently verified authorities after an approved offline upgrade.
/// The installed bytes are fetched from the exact protected Git release;
/// historical trust is bound to previous.pb or verified published Git ancestry.
/// Never require the new release to equal the old preserved trust bytes.
fn verify_installed_trust_release_binding(
    installed_pb: &[u8],
    installed_sha256: &str,
    trusted_pb: &[u8],
    verified_trust_origin_sha256: Option<&str>,
) -> Result<(), &'static str> {
    let installed_digest = lowercase_sha(digest(&SHA256, installed_pb).as_ref());
    if installed_digest != installed_sha256 {
        return Err("HOST_WINDOWS_SYSTEM_INSTALLED_GIT_RELEASE_CHANGED");
    }
    let trusted_digest = lowercase_sha(digest(&SHA256, trusted_pb).as_ref());
    if trusted_digest == installed_sha256 {
        if installed_pb != trusted_pb {
            return Err("HOST_WINDOWS_SYSTEM_INSTALLED_TRUST_BYTES_CHANGED");
        }
    } else if verified_trust_origin_sha256 != Some(trusted_digest.as_str()) {
        return Err("HOST_WINDOWS_TRUST_PREDECESSOR_RELEASE_MISMATCH");
    }
    Ok(())
}

/// Common authority loader for lifecycle and universal admin. The local
/// bootstrap anchors the installed runtime; independently fetched protected
/// Git anchors current authority. The binding intent is NEVER executed.
pub(super) async fn current_authority(
    install_root: &Path,
    machine_id: &str,
    operation_id: &str,
    requested_at: u64,
    private: &[u8],
) -> Result<
    (
        FleetNativeTrustSnapshot,
        edge_shared_types::FleetHost,
        Vec<u8>,
    ),
    String,
> {
    let installed = load_verified_activation(install_root)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_ACTIVATION_UNPROVEN")?;
    let trust_path = install_root.join("native-host/trust.pb");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&trust_path, true)?;
    let bytes = bounded_regular_file(&trust_path, 9 * 1024 * 1024)?;
    let boot = FleetNativeTrustSnapshot::decode(bytes.as_slice())
        .map_err(|_| "HOST_WINDOWS_SYSTEM_TRUST_PROTO_INVALID")?;
    fn binding(
        machine: &str,
        op: &str,
        when: u64,
        registry: &[u8],
        spec: &[u8],
        release: &[u8],
        historical_windows_trust: bool,
    ) -> Result<FleetHostIntent, String> {
        let hosts = if historical_windows_trust {
            edge_shared_types::host_lifecycle::decode_historical_windows_trust_registry(
                registry, spec, machine,
            )
            .map_err(str::to_owned)?
        } else {
            edge_shared_types::decode_host_registry(registry)?
        };
        let host = hosts
            .hosts
            .iter()
            .find(|h| h.machine_id == machine && h.kind == FleetHostKind::Windows as i32)
            .ok_or("HOST_WINDOWS_SYSTEM_HOST_NOT_REGISTERED")?;
        Ok(FleetHostIntent {
            schema_version: 1,
            machine_id: machine.into(),
            kind: FleetHostKind::Windows as i32,
            resource_id: "sing-box".into(),
            operation_id: op.into(),
            action: FleetHostAction::Stop as i32,
            registry_sha256: digest(&SHA256, registry).as_ref().to_vec(),
            desired_sha256: edge_shared_types::host_lifecycle::digest_host_desired(host, spec)?,
            release_set_sha256: digest(&SHA256, release).as_ref().to_vec(),
            requested_at_unix: when,
            ..Default::default()
        })
    }
    let historical = binding(
        machine_id,
        operation_id,
        requested_at,
        &boot.registry_pb,
        &boot.selected_spec_bytes,
        &boot.release_set_pb,
        true,
    )?;
    let trust_release: String = digest(&SHA256, &boot.release_set_pb)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let predecessor = if trust_release != installed.release_set_sha256 {
        // Old trust is allowed only when the exact prior activation independently
        // verifies. No replacement key, re-enrollment or unsigned runner input.
        Some(
            load_verified_activation_path(
                install_root,
                &install_root.join("previous.pb"),
                "previous.pb",
            )
            .map_err(|_| "HOST_WINDOWS_TRUST_PREDECESSOR_NOT_VERIFIED")?,
        )
    } else {
        None
    };
    let boot = verify_system_trust(&bytes, &historical, &trust_release, private)?;
    let (installed_pb, current_pb, registry_pb, spec) =
        windows_trust_enrollment::fetch_exact_protected_git(&installed).await?;
    // previous.pb proves the last physical local-Administrator handoff.
    // A second or later upgrade must also prove the ORIGINAL immutable
    // trust ReleaseSet through its historical Git tag, asset and ancestry.
    let verified_origin_sha = if let Some(ref previous) = predecessor {
        if previous.release_set_sha256 == trust_release {
            Some(trust_release.clone())
        } else {
            Some(
                windows_trust_enrollment::verify_historical_windows_trust_ancestor(
                    install_root,
                    &boot.release_set_pb,
                    &installed,
                )
                .await?,
            )
        }
    } else {
        None
    };
    verify_installed_trust_release_binding(
        &installed_pb,
        &installed.release_set_sha256,
        &boot.release_set_pb,
        verified_origin_sha.as_deref(),
    )
    .map_err(str::to_owned)?;
    let binding = binding(
        machine_id,
        operation_id,
        requested_at,
        &registry_pb,
        &spec,
        &current_pb,
        false,
    )?;
    let (registry, _) =
        bind_native_host_artifacts(&binding, &registry_pb, &spec, &current_pb, None)?;
    let selected = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == machine_id && h.kind == FleetHostKind::Windows as i32)
        .ok_or("HOST_WINDOWS_SYSTEM_HOST_NOT_REGISTERED")?
        .clone();
    edge_shared_types::host_lifecycle::verify_windows_signed_git_prerequisites(&selected)?;
    if selected.worker_authority_public_key != boot.pinned_worker_public_key {
        return Err("HOST_WINDOWS_SYSTEM_SIGNER_ROTATION_UNPROVEN".into());
    }
    check_native_receipt_key(&selected, private)?;
    Ok((
        FleetNativeTrustSnapshot {
            registry_pb,
            selected_spec_bytes: spec,
            release_set_pb: current_pb,
            ..boot
        },
        selected,
        digest(&SHA256, &installed_pb).as_ref().to_vec(),
    ))
}

fn lowercase_sha(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

/// One actual network baseline per signed operation, kept in the EXISTING
/// SYSTEM journal. An old ManagedTun is never inferred from desired ProxyOnly.
struct WindowsNetworkPreflight {
    baseline: edge_shared_types::windows_native_network::NativeNetworkIdentity,
    prior_tun_luid: Option<u64>,
    original_start_operation: Option<String>,
}

impl WindowsNetworkPreflight {
    fn require_current(&self, stop_effect_completed: bool) -> Result<(), &'static str> {
        use edge_shared_types::windows_native_network;
        if let Some(luid) = self.prior_tun_luid
            && !stop_effect_completed
        {
            let (_, live) = windows_native_network::observe_native_managed_tun()?;
            live.require_foreign_network_preserved(&self.baseline)?;
            if live.owned_tun.interface_luid != luid {
                return Err("HOST_WINDOWS_ACTIVE_TUN_LUID_CHANGED");
            }
            return Ok(());
        }
        let (_, now) = windows_native_network::observe_native_network_identity()?;
        self.baseline.require_restored(&now)
    }
}

/// An OFF transition may stop ONLY an exact running SCM-owned TUN that has
/// an immutable original prestate in the protected SYSTEM journal. Missing
/// snapshot, changed LUID or an unknown owner BLOCKS without a network edit.
fn preflight_existing_windows_route_capture(
    install_root: &Path,
    mode: WindowsDatapathMode,
    action: FleetHostAction,
    desired_run: edge_shared_types::FleetHostRunState,
    observed_owner: edge_shared_types::FleetNativeOwnerState,
) -> Result<WindowsNetworkPreflight, &'static str> {
    use edge_shared_types::windows_native_network::{self, NativeNetworkIdentity};
    let active = install_root.join("native-host/journal/network-baseline.active.pb");
    match fs::symlink_metadata(&active) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err("HOST_WINDOWS_ACTIVE_NETWORK_BASELINE_UNTRUSTED");
            }
            edge_shared_types::host_journal::verify_windows_protected_path_acl(&active, true)?;
            let bytes = bounded_regular_file(
                &active,
                windows_native_network::MAX_NATIVE_NETWORK_BASELINE_BYTES as u64,
            )?;
            let (operation, baseline) = NativeNetworkIdentity::decode_active_baseline(&bytes)?;
            if mode != WindowsDatapathMode::ProxyOnly
                || desired_run != edge_shared_types::FleetHostRunState::Stopped
            {
                return Err("HOST_WINDOWS_ACTIVE_NETWORK_BASELINE_REQUIRES_SIGNED_STOP");
            }
            // The old STOP may have physically restored everything but
            // crashed before archiving this record. RECOVER is read-only:
            // the same protected journal and signed authorization decide
            // whether the prior pending scope may be reconciled.
            if action == FleetHostAction::Recover
                && observed_owner == edge_shared_types::FleetNativeOwnerState::Stopped
            {
                let (_, current) = windows_native_network::observe_native_network_identity()?;
                baseline.require_restored(&current)?;
                return Ok(WindowsNetworkPreflight {
                    baseline,
                    prior_tun_luid: None,
                    original_start_operation: Some(operation),
                });
            }
            if action != FleetHostAction::Stop
                || observed_owner != edge_shared_types::FleetNativeOwnerState::Running
            {
                return Err("HOST_WINDOWS_ACTIVE_NETWORK_BASELINE_REQUIRES_SIGNED_STOP");
            }
            let config = local_singbox_config_path(install_root);
            edge_shared_types::host_journal::verify_windows_protected_path_acl(&config, true)?;
            let config = bounded_regular_file(&config, 1024 * 1024)?;
            edge_singbox::require_managed_tun_config(&config)?;
            let (_, tun) = windows_native_network::observe_native_managed_tun()?;
            tun.require_native_dual_stack_route_capture()?;
            Ok(WindowsNetworkPreflight {
                baseline,
                prior_tun_luid: Some(tun.owned_tun.interface_luid),
                original_start_operation: Some(operation),
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (_, baseline) = windows_native_network::observe_native_network_identity()?;
            if mode == WindowsDatapathMode::ManagedTun {
                baseline.require_foreign_warp_up()?;
            }
            if observed_owner != edge_shared_types::FleetNativeOwnerState::Stopped {
                let config = local_singbox_config_path(install_root);
                edge_shared_types::host_journal::verify_windows_protected_path_acl(&config, true)?;
                let bytes = bounded_regular_file(&config, 1024 * 1024)?;
                edge_singbox::require_no_windows_route_capture_config(&bytes)
                    .map_err(|_| "HOST_WINDOWS_RUNNING_TUN_NETWORK_RESTORATION_REQUIRED")?;
            }
            Ok(WindowsNetworkPreflight {
                baseline,
                prior_tun_luid: None,
                original_start_operation: None,
            })
        }
        Err(_) => Err("HOST_WINDOWS_ACTIVE_NETWORK_BASELINE_UNAVAILABLE"),
    }
}

/// The old baseline stays immutable until the physical network is
/// restored AND the native STOP terminal is durable. Archive in the SAME
/// protected journal; never delete a pending operation or touch foreign NICs.
fn archive_verified_network_baseline(
    root: &Path,
    original_operation: &str,
) -> Result<(), &'static str> {
    use edge_shared_types::windows_native_network::{self, NativeNetworkIdentity};
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    let journal = root.join("native-host/journal");
    let active = journal.join("network-baseline.active.pb");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&active, true)?;
    let bytes = bounded_regular_file(
        &active,
        windows_native_network::MAX_NATIVE_NETWORK_BASELINE_BYTES as u64,
    )?;
    let (operation, baseline) = NativeNetworkIdentity::decode_active_baseline(&bytes)?;
    if operation != original_operation {
        return Err("HOST_WINDOWS_NETWORK_BASELINE_ORIGINAL_OPERATION_MISMATCH");
    }
    let (_, actual) = windows_native_network::observe_native_network_identity()?;
    baseline.require_restored(&actual)?;
    let id = lowercase_sha(&windows_admin::process::sha(original_operation.as_bytes()));
    let archive = journal.join(format!("network-baseline-{id}.restored.pb"));
    match fs::symlink_metadata(&archive) {
        Ok(_) => return Err("HOST_WINDOWS_NETWORK_BASELINE_ARCHIVE_EXISTS"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("HOST_WINDOWS_NETWORK_BASELINE_ARCHIVE_UNAVAILABLE"),
    }
    let from: Vec<u16> = active.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = archive.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err("HOST_WINDOWS_NETWORK_BASELINE_ARCHIVE_UNKNOWN_NO_REPLAY");
    }
    Ok(())
}

/// Only the installed SYSTEM trust supplies the Git registry, exact spec,
/// release and public signer. No runner-provided trust fields are accepted.
/// A Windows trust snapshot uses the existing FleetNativeTrustSnapshot without
/// VM bundle bytes; VM first-use retains its own stricter VM-only decoder.
pub(super) fn verify_system_trust(
    bytes: &[u8],
    intent: &FleetHostIntent,
    installed_release_sha256: &str,
    private_key: &[u8],
) -> Result<FleetNativeTrustSnapshot, &'static str> {
    if bytes.is_empty() || bytes.len() > 9 * 1024 * 1024 {
        return Err("HOST_WINDOWS_SYSTEM_TRUST_SIZE_INVALID");
    }
    let trust = FleetNativeTrustSnapshot::decode(bytes)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_TRUST_PROTO_INVALID")?;
    if trust.encode_to_vec() != bytes
        || trust.schema_version != 1
        || trust.machine_id != intent.machine_id
        || intent.kind != FleetHostKind::Windows as i32
        || !trust.application_bundle_pb.is_empty()
        || trust.pinned_worker_public_key.len() != 32
        || trust.pinned_worker_public_key.iter().all(|key| *key == 0)
    {
        return Err("HOST_WINDOWS_SYSTEM_TRUST_IDENTITY_INVALID");
    }
    let (registry, bound) =
        edge_shared_types::host_lifecycle::bind_historical_windows_trust_artifacts(
            intent,
            &trust.registry_pb,
            &trust.selected_spec_bytes,
            &trust.release_set_pb,
        )?;
    let host = registry
        .hosts
        .iter()
        .find(|host| host.machine_id == intent.machine_id && host.kind == intent.kind)
        .ok_or("HOST_WINDOWS_SYSTEM_HOST_NOT_REGISTERED")?;
    edge_shared_types::host_lifecycle::verify_git_host_worker_signer_pin(
        host,
        &trust.pinned_worker_public_key,
    )?;
    check_native_receipt_key(host, private_key)?;
    if lowercase_sha(&bound.release_set_sha256) != installed_release_sha256 {
        return Err("HOST_WINDOWS_INSTALLED_SOURCE_RELEASE_DRIFT");
    }
    Ok(trust)
}

fn system_native_observation(install_root: &Path) -> Result<FleetNativeObservation, &'static str> {
    let active = load_verified_activation(install_root)
        .map_err(|_| "HOST_WINDOWS_NATIVE_ACTIVATION_UNPROVEN")?;
    // The exact native binary's typed host-observe is required. An older
    // doctor stdout cannot be interpreted as an authenticated protobuf.
    let child = Command::new(&active.diagnostic_path)
        .arg("host-observe")
        .arg(install_root.join("current.pb"))
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "HOST_WINDOWS_NATIVE_READBACK_EXEC_FAILED")?;
    if !child.status.success() || child.stdout.is_empty() || child.stdout.len() > 4096 {
        return Err("HOST_WINDOWS_NATIVE_READBACK_UNPROVEN");
    }
    let mut readback = FleetNativeObservation::decode(child.stdout.as_slice())
        .map_err(|_| "HOST_WINDOWS_NATIVE_READBACK_PROTO_INVALID")?;
    if readback.encode_to_vec() != child.stdout {
        return Err("HOST_WINDOWS_NATIVE_READBACK_NONCANONICAL");
    }
    readback.windows_config_sha256 = windows_config::observed_digest(install_root)?;
    edge_shared_types::host_lifecycle::validate_native_observation(&readback)?;
    if readback.host_kind != FleetHostKind::Windows as i32 {
        return Err("HOST_WINDOWS_NATIVE_READBACK_KIND_MISMATCH");
    }
    if readback.owner_state == edge_shared_types::FleetNativeOwnerState::Running as i32 {
        let config = local_singbox_config_path(install_root);
        let processes = edge_local_runtime::exact_managed_runtime_processes(&config);
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|_| "HOST_WINDOWS_SCM_READBACK_UNAVAILABLE")?;
        let service = manager
            .open_service(WINDOWS_CONTROLLER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .map_err(|_| "HOST_WINDOWS_SCM_READBACK_UNAVAILABLE")?;
        let pid = service
            .query_status()
            .map_err(|_| "HOST_WINDOWS_SCM_READBACK_UNAVAILABLE")?
            .process_id;
        let owned = processes.len() == 1
            && pid.is_some()
            && processes[0].parent_pid == pid
            && processes[0].executable_path.as_ref().is_some_and(|p| {
                Path::new(p).canonicalize().ok()
                    == Path::new(&active.sing_box_path).canonicalize().ok()
            });
        if owned {
            // Only an exact native SCM child/config can prove that this
            // adapter belongs to the running signed ManagedTun operation.
            let owned_tun = bounded_regular_file(&config, 1024 * 1024)
                .is_ok_and(|bytes| edge_singbox::require_managed_tun_config(&bytes).is_ok())
                && edge_shared_types::windows_native_network::observe_native_managed_tun()
                    .is_ok_and(|(_, tun)| tun.require_native_dual_stack_route_capture().is_ok());
            if owned_tun {
                readback.reason_codes.retain(|reason| {
                    reason != "HOST_WINDOWS_NETWORK_MANAGED_TUN_INTERFACE_STILL_PRESENT"
                });
            }
            let ready = tokio::runtime::Handle::current().block_on(proxy_traffic_ready());
            readback.runtime_ready_proven = ready;
            readback.runtime_ready = ready;
        } else {
            readback
                .reason_codes
                .push("WINDOWS_NATIVE_CHILD_OWNERSHIP_UNPROVEN".into());
        }
    }
    Ok(readback)
}

/// Independent, bounded pre-TUN control and DNS witness. This uses the
/// machine's native resolver and DIRECT HTTPS without a proxy; a local
/// sing-box listener is not proof that an unproxied Git/Cloudflare control
/// path survives route capture. Output is only domain-separated evidence
/// derived from real resolver answers and TLS-validated HTTP responses.
async fn probe_pre_tun_native_control_dns() -> Result<([u8; 32], [u8; 32]), &'static str> {
    use std::net::SocketAddr;
    let hosts: Vec<SocketAddr> = tokio::net::lookup_host(("api.github.com", 443))
        .await
        .map_err(|_| "HOST_WINDOWS_NETWORK_DNS_POSITIVE_UNPROVEN")?
        .take(64)
        .collect();
    if hosts.is_empty() {
        return Err("HOST_WINDOWS_NETWORK_DNS_POSITIVE_UNPROVEN");
    }
    if tokio::net::lookup_host(("sing-box-pre-tun-witness.invalid", 443))
        .await
        .is_ok()
    {
        return Err("HOST_WINDOWS_NETWORK_DNS_NXDOMAIN_UNPROVEN");
    }
    let mut hosts = hosts;
    hosts.sort_unstable();
    hosts.dedup();
    let mut dns_evidence = b"sing-box/windows-native-dns-witness/v1:".to_vec();
    for host in hosts {
        let encoded = host.to_string();
        dns_evidence.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        dns_evidence.extend_from_slice(encoded.as_bytes());
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .user_agent("sing-box-native-control-witness/1")
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|_| "HOST_WINDOWS_NETWORK_CONTROL_CLIENT_UNAVAILABLE")?;
    let mut control_evidence = b"sing-box/windows-native-control-witness/v1:".to_vec();
    for (url, status) in [
        ("https://api.github.com", reqwest::StatusCode::OK),
        (
            "https://cp.cloudflare.com/generate_204",
            reqwest::StatusCode::NO_CONTENT,
        ),
    ] {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| "HOST_WINDOWS_NETWORK_CONTROL_TLS_UNREACHABLE")?;
        if response.status() != status {
            return Err("HOST_WINDOWS_NETWORK_CONTROL_RESPONSE_UNPROVEN");
        }
        control_evidence.extend_from_slice(&(url.len() as u32).to_be_bytes());
        control_evidence.extend_from_slice(url.as_bytes());
        control_evidence.extend_from_slice(&status.as_u16().to_be_bytes());
    }
    let mut dns = [0u8; 32];
    dns.copy_from_slice(ring::digest::digest(&SHA256, &dns_evidence).as_ref());
    let mut control = [0u8; 32];
    control.copy_from_slice(ring::digest::digest(&SHA256, &control_evidence).as_ref());
    Ok((dns, control))
}

/// Only a native Windows best-route lookup, rather than a successful HTTP
/// request that might itself use the TUN, can prove control reachability is
/// independent of this owned interface after route capture.
async fn verify_control_egress_outside_native_tun(tun_luid: u64)
    -> Result<(), &'static str>
{
    let mut answers = Vec::new();
    for name in ["api.github.com", "cp.cloudflare.com"] {
        let addresses = tokio::net::lookup_host((name, 443))
            .await
            .map_err(|_| "HOST_WINDOWS_CONTROL_ROUTE_DNS_UNAVAILABLE")?
            .take(32)
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err("HOST_WINDOWS_CONTROL_ROUTE_DNS_UNAVAILABLE");
        }
        answers.extend(addresses);
    }
    answers.sort_unstable();
    answers.dedup();
    edge_shared_types::windows_native_network::require_control_destinations_outside_tun(
        &answers,
        tun_luid,
    )
}

/// TLS+HTTPS through the actual local proxy, never a direct fallback. This is
/// runtime connectivity proof only, not full Line1/Line2/IPv6/WARP acceptance.
async fn proxy_traffic_ready() -> bool {
    let proxy = match reqwest::Proxy::all(format!("http://127.0.0.1:{STAGE2_DESKTOP_PROXY_PORT}")) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let client = match reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    for url in [
        "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com/generate_204",
    ] {
        match client.get(url).send().await {
            Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {}
            _ => return false,
        }
    }
    true
}

#[cfg(windows)]
fn apply_exact_proxyonly_scm_step(
    step: FleetHostPlannedStep,
    root: &Path,
    intent: &FleetHostIntent,
    authorization: &FleetHostAuthorization,
    private: &[u8],
    installed_sha: &[u8],
    config: Option<&windows_config::Configuration>,
    trust: &FleetNativeTrustSnapshot,
    network_baseline: &edge_shared_types::windows_native_network::NativeNetworkIdentity,
) -> Result<(), &'static str> {
    let scm = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_SCM_UNAVAILABLE")?;
    let service = scm
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
        )
        .map_err(|_| "HOST_WINDOWS_SYSTEM_CONTROLLER_UNAVAILABLE")?;
    match step {
        FleetHostPlannedStep::Start => {
            let config = config.ok_or("HOST_WINDOWS_RUNTIME_CONFIGURATION_REQUIRED")?;
            let desired =
                edge_shared_types::parse_production_desired_text(&trust.selected_spec_bytes)?;
            let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
                .map_err(|_| "HOST_WINDOWS_DATAPATH_MODE_INVALID")?;
            if mode == WindowsDatapathMode::ManagedTun {
                // Only one active baseline, in the existing LocalSystem
                // journal. BEGIN has already been synced. Create BEFORE any
                // route-capturing effect so crash recovery never guesses the
                // original foreign routes, DNS or WARP interface.
                network_baseline.require_foreign_warp_up()?;
                edge_shared_types::windows_native_network::require_owned_tun_absent()?;
                let bytes = network_baseline.encode_baseline(&intent.operation_id)?;
                windows_admin::create(
                    &root.join("native-host/journal/network-baseline.active.pb"),
                    &bytes,
                )
                .map_err(|_| "HOST_WINDOWS_NETWORK_BASELINE_UNKNOWN_NO_REPLAY")?;
            }
            windows_config::apply(root, config, &intent.operation_id)?;
            windows_config::prepare_runtime_logs(root)?;
            service
                .start::<&str>(&[])
                .map_err(|_| "HOST_WINDOWS_SYSTEM_START_FAILED")?;
            wait_for_service_state(
                &service,
                ServiceState::Running,
                Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
            )
            .map_err(|_| "HOST_WINDOWS_SYSTEM_START_POSTSTATE_UNPROVEN")?;
            // SCM owns the persistent Controller; the scheduled task must not
            // leave an unsupervised sing-box child behind when it exits.
            let pid = service
                .query_status()
                .map_err(|_| "HOST_WINDOWS_CONTROLLER_PID_UNPROVEN")?
                .process_id
                .ok_or("HOST_WINDOWS_CONTROLLER_PID_UNPROVEN")?;
            tokio::runtime::Handle::current().block_on(async {
                let channel = tonic::transport::Endpoint::from_static(WINDOWS_CONTROLLER_ENDPOINT)
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(45))
                    .connect()
                    .await
                    .map_err(|_| "HOST_WINDOWS_CONTROLLER_CHANNEL_UNAVAILABLE")?;
                let mut client = ControllerServiceClient::new(channel);
                let challenge = client
                    .get_native_runtime_challenge(Empty {})
                    .await
                    .map_err(|_| "HOST_WINDOWS_CONTROLLER_CHALLENGE_UNAVAILABLE")?
                    .into_inner();
                if challenge.process_id != pid as u64
                    || challenge.installed_release_sha256 != installed_sha
                    || challenge.nonce.len() != 32
                {
                    return Err("HOST_WINDOWS_CONTROLLER_CHALLENGE_IDENTITY_MISMATCH");
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "HOST_WINDOWS_EFFECT_CLOCK_INVALID")?
                    .as_secs();
                let mut effect = edge_shared_types::FleetWindowsRuntimeEffect {
                    schema_version: 1,
                    intent: Some(intent.clone()),
                    authorization: Some(authorization.clone()),
                    challenge: Some(challenge),
                    config_sha256: config.digest.clone(),
                    before_network_sha256: network_baseline.signed_prebegin_digest().to_vec(),
                    expires_at_unix: now.saturating_add(60).min(authorization.expires_at_unix),
                    registry_pb: trust.registry_pb.clone(),
                    selected_spec_bytes: trust.selected_spec_bytes.clone(),
                    ..Default::default()
                };
                edge_shared_types::windows_runtime_effect::sign(&mut effect, private)?;
                let response = client
                    .start_local_runtime(StartLocalRuntimeRequest {
                        native_system_effect: effect.encode_to_vec(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|_| "HOST_WINDOWS_CONTROLLER_NATIVE_EFFECT_UNPROVEN")?
                    .into_inner();
                if !response.success || response.pid.is_none() {
                    return Err("HOST_WINDOWS_CONTROLLER_NATIVE_CHILD_UNPROVEN");
                }
                Ok(())
            })?;
        }
        FleetHostPlannedStep::Stop => {
            service
                .stop()
                .map_err(|_| "HOST_WINDOWS_SYSTEM_STOP_FAILED")?;
            wait_for_service_state(
                &service,
                ServiceState::Stopped,
                Duration::from_secs(WINDOWS_CONTROLLER_SERVICE_START_TIMEOUT_SECS),
            )
            .map_err(|_| "HOST_WINDOWS_SYSTEM_STOP_POSTSTATE_UNPROVEN")?;
        }
        _ => return Err("HOST_WINDOWS_SYSTEM_UNSUPPORTED_STEP"),
    }
    Ok(())
}

/// Returns false when the existing task should process the legacy, read-only
/// Ping/RuntimeEvidence. A signed request cannot coexist with the old format.
pub(super) async fn dispatch_if_present(install_root: &Path) -> Result<bool, String> {
    let request = install_root
        .join("exchange")
        .join("requests")
        .join(INTENT_FILE);
    match fs::symlink_metadata(&request) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("HOST_WINDOWS_SYSTEM_REQUEST_METADATA_UNAVAILABLE".into()),
        Ok(meta) if !meta.file_type().is_file() => {
            return Err("HOST_WINDOWS_SYSTEM_REQUEST_NOT_REGULAR".into());
        }
        Ok(_) => {}
    }
    windows_admin::reject_competing_request(&privileged_request_path(install_root))?;
    windows_admin::reject_competing_request(
        &install_root.join("exchange/requests/admin-request.pb"),
    )?;
    // Already-retargeted immutable console, not mutable bin/edge-console.exe.
    require_exact_immutable_activation_console(install_root)?;
    let protected = install_root.join("native-host");
    let journal = protected.join("journal");
    verify_native_journal_protection(&journal).map_err(str::to_owned)?;
    let transport = TransportRequest::open(
        &request,
        edge_shared_types::host_lifecycle::MAX_HOST_INTENT_BYTES as u64,
    )
    .map_err(str::to_owned)?;
    // The runner supplies ONLY the base intent. SYSTEM owns the admission
    // witness and, once native checks succeed, includes it in the exact bytes
    // subsequently authorized by the existing Worker. No second command.
    let mut intent_bytes = transport.bytes.clone();
    let mut intent = decode_host_intent(&intent_bytes).map_err(str::to_owned)?;
    if intent.network_admission.is_some() {
        return Err("HOST_WINDOWS_RUNNER_NETWORK_ADMISSION_FORBIDDEN".into());
    }
    if intent.kind != FleetHostKind::Windows as i32
        || intent.resource_id != "sing-box"
        || !matches!(
            FleetHostAction::try_from(intent.action),
            Ok(FleetHostAction::Start
                | FleetHostAction::Stop
                | FleetHostAction::Apply
                | FleetHostAction::Recover)
        )
    {
        return Err("HOST_WINDOWS_SYSTEM_ACTION_NOT_ACCEPTED".into());
    }
    windows_admin::request_available(
        &journal,
        &intent.operation_id,
        false,
        intent.action == FleetHostAction::Recover as i32,
    )?;
    edge_shared_types::host_journal::verify_windows_protected_path_acl(
        &protected.join(RECEIPT_KEY_FILE),
        true,
    )?;
    let receipt_private =
        bounded_regular_file(&protected.join(RECEIPT_KEY_FILE), 4096).map_err(str::to_owned)?;
    let (trust, selected, installed_runtime_sha256) = current_authority(
        install_root,
        &intent.machine_id,
        &intent.operation_id,
        intent.requested_at_unix,
        &receipt_private,
    )
    .await?;
    bind_native_host_artifacts(
        &intent,
        &trust.registry_pb,
        &trust.selected_spec_bytes,
        &trust.release_set_pb,
        None,
    )?;
    // Independently re-check the exact Git host target against the exact
    // signed desired spec. The runner's preflight is never trusted here.
    let desired = edge_shared_types::parse_production_desired_text(&trust.selected_spec_bytes)?;
    let mode = edge_shared_types::host_lifecycle::validate_windows_mode_target_and_spec(
        &selected, &desired,
    )?;
    // The native readback is a pre-BEGIN proof, not runner-supplied state.
    // ManagedTun may be STAGED while stopped, but no TUN activation or
    // running-owner reconfiguration is authorized by this operation.
    let observed = tokio::task::block_in_place(|| system_native_observation(install_root))
        .map_err(str::to_owned)?;
    let action = FleetHostAction::try_from(intent.action)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_ACTION_NOT_ACCEPTED")?;
    let run = selected
        .target
        .as_ref()
        .ok_or("HOST_TARGET_UNSET_OBSERVE_ONLY")
        .and_then(|target| {
            edge_shared_types::FleetHostRunState::try_from(target.run_state)
                .map_err(|_| "HOST_TARGET_RUN_STATE_INVALID")
        })?;
    let owner = edge_shared_types::FleetNativeOwnerState::try_from(observed.owner_state)
        .map_err(|_| "HOST_WINDOWS_NATIVE_OWNER_STATE_INVALID")?;
    // Critical OFF transition: desired ProxyOnly does NOT prove the existing
    // live runtime is ProxyOnly. Deny before Worker POST and journal BEGIN if
    // any running/unknown owner still has TUN or an exotic/corrupt config.
    let network_preflight =
        preflight_existing_windows_route_capture(install_root, mode, action, run, owner)?;
    let network_baseline = &network_preflight.baseline;
    // Prepare the exact signed ManagedTun candidate READ-ONLY before native
    // BEGIN. A forged runner proof never becomes a reason to skip the
    // separate SYSTEM signature, current physical network or config check.
    // This is still not permission to capture a route: the shared gate below
    // remains CLOSED until real native Line1/control/DNS witness generation.
    let tun_config = if mode == WindowsDatapathMode::ManagedTun && action == FleetHostAction::Start
    {
        let candidate = windows_config::prepare(install_root, &trust.selected_spec_bytes)?
            .ok_or("HOST_WINDOWS_TUN_CONFIG_NOT_PREPARED")?;
        // The native SYSTEM owner will mint the exact bound witness only
        // after all actual read-only probes complete. The Worker never
        // authorizes a runner-supplied pre-TUN readiness boolean.
        // Independently prove the exact Line1 credentials over a disposable
        // ProxyOnly client and the direct DNS/HTTPS control path. Runner-held
        // hashes or a past successful report cannot substitute these probes.
        let active = load_verified_activation(install_root)
            .map_err(|_| "HOST_WINDOWS_NETWORK_ADMISSION_RELEASE_UNPROVEN")?;
        let state_file = windows_runtime_state_path(install_root);
        edge_shared_types::host_journal::verify_windows_protected_path_acl(&state_file, true)?;
        let runtime = decode_windows_runtime_state(&bounded_regular_file(&state_file, 65536)?)?;
        let line1 = initial_line1_witness::prove_serving_line1_before_tun(
            install_root,
            Path::new(&active.sing_box_path),
            &runtime,
        )
        .map_err(|_| "HOST_WINDOWS_NETWORK_ADMISSION_LINE1_UNPROVEN")?;
        let (dns, control) = probe_pre_tun_native_control_dns().await?;
        let (_, after_witness) =
            edge_shared_types::windows_native_network::observe_native_network_identity()?;
        network_baseline.require_restored(&after_witness)?;
        // Expiry starts AFTER all real probes and native restoration, not at
        // the start of potentially long external network acceptance.
        let admission_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "HOST_WINDOWS_SYSTEM_CLOCK_UNAVAILABLE")?
            .as_secs();
        let admission = edge_shared_types::host_lifecycle::sign_windows_network_admission(
            &intent,
            &receipt_private,
            &installed_runtime_sha256,
            &candidate.digest,
            &network_baseline.signed_prebegin_digest(),
            &line1,
            &control,
            &dns,
            admission_now,
        )?;
        intent.network_admission = Some(admission);
        edge_shared_types::host_lifecycle::verify_windows_network_admission(
            &intent,
            &selected.native_receipt_public_key,
            &installed_runtime_sha256,
            &candidate.digest,
            &network_baseline.signed_prebegin_digest(),
            admission_now,
        )?;
        // The Worker must authenticate the same exact enriched Protobuf
        // bytes, and local journal + Controller must recheck both signatures.
        intent_bytes = intent.encode_to_vec();
        Some(candidate)
    } else {
        if intent.network_admission.is_some() {
            return Err("HOST_WINDOWS_NETWORK_ADMISSION_UNEXPECTED_MODE".into());
        }
        None
    };
    edge_shared_types::host_lifecycle::validate_windows_datapath_prebegin_with_admission(
        mode,
        action,
        run,
        owner,
        mode == WindowsDatapathMode::ManagedTun
            && action == FleetHostAction::Start
            && intent.network_admission.is_some(),
    )?;
    let update = if intent.action == FleetHostAction::Apply as i32
        && digest(&SHA256, &trust.release_set_pb).as_ref() != installed_runtime_sha256
    {
        windows_update::preflight(install_root)?;
        Some(windows_update::prepare(&trust.release_set_pb).await?)
    } else {
        None
    };
    let config = if tun_config.is_some() {
        tun_config
    } else if matches!(
        FleetHostAction::try_from(intent.action),
        Ok(FleetHostAction::Apply | FleetHostAction::Recover | FleetHostAction::Start)
    ) && update.is_none()
    {
        windows_config::prepare(install_root, &trust.selected_spec_bytes)?
    } else {
        None
    };
    let identity = install_root
        .join("state")
        .join("secrets")
        .join(ACCESS_IDENTITY_FILE_NAME);
    edge_secrets::diagnose_canonical_host_access(&identity)
        .await
        .map_err(str::to_owned)?;
    // Worker POST is one-shot; no fallback to a runner-supplied signature.
    let auth: FleetHostAuthorization =
        edge_secrets::request_canonical_host_authorization(&intent_bytes, &identity).await?;
    let mut now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_WINDOWS_SYSTEM_CLOCK_UNAVAILABLE")?
        .as_secs();
    edge_shared_types::host_lifecycle::verify_host_authorization(
        &intent,
        &auth,
        &trust.pinned_worker_public_key,
        now,
    )?;
    if let Some(config) = &config
        && matches!(
            FleetHostAction::try_from(intent.action),
            Ok(FleetHostAction::Apply | FleetHostAction::Start)
        )
    {
        windows_config::validate(install_root, config, &intent.operation_id)?;
        now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "HOST_WINDOWS_SYSTEM_CLOCK_UNAVAILABLE")?
            .as_secs();
    }
    if mode == WindowsDatapathMode::ManagedTun && action == FleetHostAction::Start {
        let config = config
            .as_ref()
            .ok_or("HOST_WINDOWS_TUN_CONFIG_NOT_PREPARED")?;
        let (_, fresh) =
            edge_shared_types::windows_native_network::observe_native_network_identity()?;
        network_baseline.require_restored(&fresh)?;
        // Worker signature and native config validation may consume time.
        // Re-verify the entire original SYSTEM-signed proof against current
        // clock, exact binary config and kernel prestate BEFORE BEGIN.
        edge_shared_types::host_lifecycle::verify_windows_network_admission(
            &intent,
            &selected.native_receipt_public_key,
            &installed_runtime_sha256,
            &config.digest,
            &fresh.signed_prebegin_digest(),
            now,
        )?;
    }
    let effect_completed = std::cell::Cell::new(false);
    let result = tokio::task::block_in_place(|| {
        edge_shared_types::host_journal::execute_native_windows_host_once(
            &intent,
            &auth,
            &trust.registry_pb,
            &trust.selected_spec_bytes,
            &trust.release_set_pb,
            None,
            &trust.pinned_worker_public_key,
            &trust.machine_id,
            FleetHostKind::Windows as i32,
            &installed_runtime_sha256,
            config.as_ref().map(|c| c.digest.as_slice()),
            now,
            &journal,
            || {
                let observed = system_native_observation(install_root)?;
                if mode == WindowsDatapathMode::ManagedTun
                    && effect_completed.get()
                    && observed.owner_state
                        == edge_shared_types::FleetNativeOwnerState::Running as i32
                {
                    let (_, live) =
                        edge_shared_types::windows_native_network::observe_native_managed_tun()?;
                    live.require_foreign_network_preserved(network_baseline)?;
                    // A kernel TUN and a listening localhost socket are not
                    // Internet readiness. After route capture independently
                    // prove native resolver + DIRECT GitHub/Cloudflare TLS.
                    // Never report VERIFIED on a broken control path.
                    let proof = tokio::runtime::Handle::current().block_on(async {
                        // Success without an independent native route is NOT
                        // a control-plane PASS: it may be tunnelling through
                        // the very process that is about to crash.
                        verify_control_egress_outside_native_tun(live.owned_tun.interface_luid)
                            .await?;
                        probe_pre_tun_native_control_dns().await?;
                        Ok::<(), &'static str>(())
                    });
                    let (_, after_probes) =
                        edge_shared_types::windows_native_network::observe_native_managed_tun()?;
                    after_probes.require_foreign_network_preserved(network_baseline)?;
                    if proof.is_err() {
                        // The START intent also authorizes immediate safety
                        // cleanup of this exact newly owned child, NOT a
                        // second START or arbitrary foreign route rewrite.
                        let _ = apply_exact_proxyonly_scm_step(
                            FleetHostPlannedStep::Stop,
                            install_root,
                            &intent,
                            &auth,
                            &receipt_private,
                            &installed_runtime_sha256,
                            None,
                            &trust,
                            network_baseline,
                        );
                        return Err("HOST_WINDOWS_TUN_CONTROL_POSTSTATE_UNKNOWN_NO_REPLAY");
                    }
                } else {
                    network_preflight.require_current(effect_completed.get())?;
                }
                Ok(observed)
            },
            |step| match step {
                FleetHostPlannedStep::Start if config.is_some() => {
                    windows_update::preflight(install_root).map(|_| ())
                }
                FleetHostPlannedStep::Stop => Ok(()),
                FleetHostPlannedStep::ReplaceRelease if update.is_some() => {
                    windows_update::preflight(install_root).map(|_| ())
                }
                FleetHostPlannedStep::Configure if config.is_some() => {
                    windows_update::preflight(install_root).map(|_| ())
                }
                _ => Err("HOST_WINDOWS_SYSTEM_NATIVE_STEP_NOT_ACCEPTED"),
            },
            |step| {
                // A previous independent readback cannot authorize stopping
                // whatever interface is present later. Under the SAME SYSTEM
                // journal effect, recheck exact LUID and foreign ownership
                // immediately before the single native SCM STOP.
                if step == FleetHostPlannedStep::Stop && network_preflight.prior_tun_luid.is_some()
                {
                    network_preflight.require_current(false)?;
                }
                let outcome = match step {
                    FleetHostPlannedStep::ReplaceRelease => windows_update::apply(
                        install_root,
                        update.as_ref().ok_or("HOST_WINDOWS_UPDATE_NOT_PREPARED")?,
                        &trust,
                        &intent.operation_id,
                    ),
                    FleetHostPlannedStep::Configure => windows_config::apply(
                        install_root,
                        config.as_ref().ok_or("HOST_WINDOWS_CONFIG_NOT_PREPARED")?,
                        &intent.operation_id,
                    ),
                    _ => apply_exact_proxyonly_scm_step(
                        step,
                        install_root,
                        &intent,
                        &auth,
                        &receipt_private,
                        &installed_runtime_sha256,
                        config.as_ref(),
                        &trust,
                        network_baseline,
                    ),
                };
                if outcome.is_ok() {
                    effect_completed.set(true);
                }
                outcome
            },
        )
    })
    .map_err(str::to_owned)?;
    // Only a VERIFIED signed STOP may retire the active TUN before-state;
    // interrupted effects keep it for a new independent recovery decision.
    if matches!(action, FleetHostAction::Stop | FleetHostAction::Recover)
        && result.state == edge_shared_types::FleetHostResultState::Verified as i32
        && result.physical_readback
        && let Some(original) = network_preflight.original_start_operation.as_deref()
    {
        archive_verified_network_baseline(install_root, original)?;
    }
    // Native journal has already fsynced terminal before SYSTEM signs.
    let signed = sign_native_receipt(&intent, &result, &selected, &receipt_private)
        .map_err(str::to_owned)?;
    let receipt_path = install_root
        .join("exchange")
        .join("results")
        .join(RECEIPT_FILE);
    write_atomic(&receipt_path, &signed.encode_to_vec())
        .map_err(|_| "HOST_WINDOWS_SYSTEM_RECEIPT_PUBLISH_UNCERTAIN")?;
    transport.consume()?;
    println!("status=PASS");
    println!("native_system_receipt=SIGNED_TERMINAL");
    println!("native_system_operation_id={}", intent.operation_id);
    println!("native_system_replay_allowed=false");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_offline_upgrade_keeps_immutable_predecessor_trust() {
        let old_trust = b"previous immutable ReleaseSet";
        let installed = b"new protected Git ReleaseSet";
        let sha = |bytes: &[u8]| lowercase_sha(digest(&SHA256, bytes).as_ref());
        let old_sha = sha(old_trust);
        let installed_sha = sha(installed);

        // Same-release behavior still requires the identical trust bytes.
        assert_eq!(
            verify_installed_trust_release_binding(old_trust, &old_sha, old_trust, None,),
            Ok(())
        );
        // Canonical positive path: exact new release, old trust pinned to
        // previously verified activation; no trust regeneration or overwrite.
        assert_eq!(
            verify_installed_trust_release_binding(
                installed,
                &installed_sha,
                old_trust,
                Some(&old_sha),
            ),
            Ok(())
        );
        // No previous.pb evidence or a foreign predecessor is NOT an upgrade.
        assert_eq!(
            verify_installed_trust_release_binding(installed, &installed_sha, old_trust, None,),
            Err("HOST_WINDOWS_TRUST_PREDECESSOR_RELEASE_MISMATCH")
        );
        assert_eq!(
            verify_installed_trust_release_binding(
                installed,
                &installed_sha,
                old_trust,
                Some(&installed_sha),
            ),
            Err("HOST_WINDOWS_TRUST_PREDECESSOR_RELEASE_MISMATCH")
        );
        // A substituted installed ReleaseSet is denied even with valid old trust.
        assert_eq!(
            verify_installed_trust_release_binding(
                b"tampered installed release",
                &installed_sha,
                old_trust,
                Some(&old_sha),
            ),
            Err("HOST_WINDOWS_SYSTEM_INSTALLED_GIT_RELEASE_CHANGED")
        );
        assert_eq!(
            verify_installed_trust_release_binding(
                installed,
                &installed_sha,
                b"foreign trust",
                Some(&old_sha),
            ),
            Err("HOST_WINDOWS_TRUST_PREDECESSOR_RELEASE_MISMATCH")
        );
    }

    #[test]
    fn transport_request_cannot_be_swapped_during_execution() {
        let dir =
            std::env::temp_dir().join(format!("edge-transport-request-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("request.pb");
        fs::write(&path, b"exact").unwrap();
        let request = TransportRequest::open(&path, 32).unwrap();
        assert_eq!(request.bytes, b"exact");
        assert!(fs::write(&path, b"changed").is_err());
        assert!(fs::rename(&path, dir.join("swapped")).is_err());
        request.consume().unwrap();
        assert!(!path.exists());
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn no_system_trust_can_be_synthesized_from_a_runner_intent() {
        let intent = FleetHostIntent {
            schema_version: 1,
            kind: FleetHostKind::Windows as i32,
            machine_id: "sing-box-windows-lab".into(),
            ..Default::default()
        };
        assert_eq!(
            verify_system_trust(&[], &intent, &"a".repeat(64), &[]),
            Err("HOST_WINDOWS_SYSTEM_TRUST_SIZE_INVALID"),
        );
        let wrong_kind = FleetHostIntent {
            kind: FleetHostKind::Vm as i32,
            ..intent.clone()
        };
        let snapshot = FleetNativeTrustSnapshot {
            schema_version: 1,
            machine_id: intent.machine_id.clone(),
            pinned_worker_public_key: vec![4; 32],
            ..Default::default()
        };
        assert_eq!(
            verify_system_trust(&snapshot.encode_to_vec(), &wrong_kind, &"a".repeat(64), &[]),
            Err("HOST_WINDOWS_SYSTEM_TRUST_IDENTITY_INVALID"),
        );
        let no_pin = FleetNativeTrustSnapshot {
            pinned_worker_public_key: vec![],
            ..snapshot.clone()
        };
        assert_eq!(
            verify_system_trust(&no_pin.encode_to_vec(), &intent, &"a".repeat(64), &[]),
            Err("HOST_WINDOWS_SYSTEM_TRUST_IDENTITY_INVALID"),
        );
    }
}
