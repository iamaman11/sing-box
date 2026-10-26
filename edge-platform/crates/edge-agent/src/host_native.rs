//! One root-owned VM host command. Runner stdin carries ONLY the canonical
//! operation identifier; native release and desired bytes are never accepted
//! from a workflow artifact or the caller's path arguments.
use super::*;
use edge_shared_types::host_journal::execute_native_host_once;
use edge_shared_types::host_lifecycle::decode_host_intent;
use edge_shared_types::{
    FleetHostKind, FleetHostPlannedStep, FleetNativeTrustSnapshot, ReleaseSet,
};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

pub(super) const HOST_PARENT: &str = "/opt/vultr-edge-stack";
pub(super) const TRUSTED_ROOT: &str = "/opt/vultr-edge-stack/native-host";
const JOURNAL_ROOT: &str = "/opt/vultr-edge-stack/native-host/journal";

/// A single kernel-owned exclusion guard for root enrollment AND host apply.
/// The permanent journal is never swapped or copied across ReleaseSets.
/// The lock file is the only new disk resource; it is not an operation ledger.
unsafe extern "C" {
    fn geteuid() -> u32;
    fn flock(fd: i32, operation: i32) -> i32;
}

pub(super) fn owner_operation_lock() -> Result<std::fs::File, String> {
    if unsafe { geteuid() } != 0 {
        return Err("HOST_NATIVE_OWNER_ROOT_REQUIRED".into());
    }
    let parent = Path::new(HOST_PARENT);
    let metadata = fs::symlink_metadata(parent).map_err(|_| "HOST_NATIVE_PARENT_UNAVAILABLE")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("HOST_NATIVE_PARENT_UNTRUSTED".into());
    }
    let lock_path = parent.join(".native-host.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|_| "HOST_NATIVE_OWNER_LOCK_UNAVAILABLE")?;
    let identity = file
        .metadata()
        .map_err(|_| "HOST_NATIVE_OWNER_LOCK_UNAVAILABLE")?;
    let pathname =
        fs::symlink_metadata(&lock_path).map_err(|_| "HOST_NATIVE_OWNER_LOCK_UNAVAILABLE")?;
    if !identity.is_file()
        || !pathname.file_type().is_file()
        || identity.uid() != 0
        || identity.permissions().mode() & 0o077 != 0
        || pathname.ino() != identity.ino()
        || pathname.dev() != identity.dev()
    {
        return Err("HOST_NATIVE_OWNER_LOCK_UNTRUSTED".into());
    }
    // Linux LOCK_EX | LOCK_NB. Never poll or wait for an uncertain owner.
    if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 {
        return Err("HOST_NATIVE_OWNER_BUSY".into());
    }
    Ok(file)
}

/// Metadata only: scanner results never authorize a native mutation or
/// release a durable pending scope. Any malformed entry is preserved intact.
#[derive(Debug, Clone)]
struct NativeJournalEntryMetadata {
    name: String,
    kind: &'static str,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    modified_unix: i64,
    pending: bool,
    failure: &'static str,
}

#[derive(Debug, Default)]
struct NativeJournalScan {
    entries: usize,
    pending: usize,
    sample: Vec<NativeJournalEntryMetadata>,
    first_invalid: Option<NativeJournalEntryMetadata>,
}

fn safe_journal_entry_name(name: &std::ffi::OsStr) -> String {
    if let Some(value) = name.to_str()
        && value.len() <= 128
        && !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return value.to_owned();
    }
    // Never print attacker-supplied names, embedded newlines or path-like data.
    use std::os::unix::ffi::OsStrExt;
    let digest = ring::digest::digest(&ring::digest::SHA256, name.as_bytes());
    let short = digest.as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!("UNSAFE_NAME_SHA256_{short}")
}

fn scan_native_journal_metadata(
    journal: &Path,
    expected_uid: u32,
) -> Result<NativeJournalScan, String> {
    let mut scan = NativeJournalScan::default();
    for entry in fs::read_dir(journal).map_err(|_| "HOST_NATIVE_JOURNAL_UNAVAILABLE")? {
        let entry = entry.map_err(|_| "HOST_NATIVE_JOURNAL_UNAVAILABLE")?;
        let meta =
            fs::symlink_metadata(entry.path()).map_err(|_| "HOST_NATIVE_JOURNAL_UNAVAILABLE")?;
        let kind = if meta.file_type().is_file() {
            "REGULAR"
        } else if meta.file_type().is_symlink() {
            "SYMLINK"
        } else if meta.file_type().is_dir() {
            "DIRECTORY"
        } else {
            "OTHER"
        };
        let mode = meta.permissions().mode() & 0o7777;
        let failure = if !meta.file_type().is_file() {
            "NONREGULAR"
        } else if meta.uid() != expected_uid {
            "OWNER_NOT_ROOT"
        } else if mode & 0o077 != 0 {
            "GROUP_OTHER_BITS_PRESENT"
        } else {
            "NONE"
        };
        let raw_name = entry.file_name();
        let pending = raw_name
            .to_str()
            .is_some_and(|name| name.ends_with(".pending.pb"));
        scan.entries += 1;
        if pending {
            scan.pending += 1;
        }
        let record = NativeJournalEntryMetadata {
            name: safe_journal_entry_name(&raw_name),
            kind,
            uid: meta.uid(),
            gid: meta.gid(),
            mode,
            size: meta.size(),
            modified_unix: meta.mtime(),
            pending,
            failure,
        };
        if failure != "NONE" && scan.first_invalid.is_none() {
            scan.first_invalid = Some(record.clone());
        }
        if scan.sample.len() < 24 {
            scan.sample.push(record);
        }
        // Never return on the first pending scope: a later forged entry
        // must still reject the entire protected journal.
    }
    Ok(scan)
}

/// Full scan, including entries after pending. No permission normalization,
/// journal clean-up, pending removal or unknown-operation replay.
pub(super) fn protected_journal_has_pending(journal: &Path) -> Result<bool, String> {
    let scan = scan_native_journal_metadata(journal, 0)?;
    if scan.first_invalid.is_some() {
        return Err("HOST_NATIVE_JOURNAL_FILE_UNTRUSTED".into());
    }
    Ok(scan.pending != 0)
}

/// Existing root-owned 'local diagnose' entrypoint. Output is deliberately
/// tagged as runner-copied and has no authority for apply/recover.
pub(super) fn print_native_journal_diagnostic() {
    if unsafe { geteuid() } != 0 {
        println!("host_native_journal_diagnostic=UNAVAILABLE_NONROOT");
        return;
    }
    let journal = Path::new(JOURNAL_ROOT);
    let meta = match fs::symlink_metadata(journal) {
        Ok(m) if m.file_type().is_dir() && m.uid() == 0 && m.permissions().mode() & 0o077 == 0 => m,
        _ => {
            println!("host_native_journal_diagnostic=ROOT_UNPROVEN");
            return;
        }
    };
    let _ = meta;
    let scan = match scan_native_journal_metadata(journal, 0) {
        Ok(scan) => scan,
        Err(_) => {
            println!("host_native_journal_diagnostic=READ_ONLY_SCAN_UNAVAILABLE");
            return;
        }
    };
    println!("host_native_journal_origin=ROOT_LOCAL_METADATA_RUNNER_COPIED_UNAUTHENTICATED");
    println!("host_native_journal_mutations=0");
    println!("host_native_journal_entries={}", scan.entries);
    println!("host_native_journal_pending_entries={}", scan.pending);
    println!("host_native_journal_display_limit=24");
    for item in &scan.sample {
        print_native_journal_entry("host_native_journal_entry", item);
    }
    if let Some(invalid) = &scan.first_invalid {
        print_native_journal_entry("host_native_journal_first_invalid", invalid);
        println!("host_native_journal_diagnostic=BLOCKED_UNTRUSTED_ENTRY");
    } else if scan.pending != 0 {
        println!("host_native_journal_diagnostic=UNKNOWN_NO_REPLAY");
    } else {
        println!("host_native_journal_diagnostic=METADATA_ONLY_NO_PENDING");
    }
}

fn print_native_journal_entry(label: &str, entry: &NativeJournalEntryMetadata) {
    println!(
        "{label}=name:{} kind:{} uid:{} gid:{} mode:{:04o} size:{} mtime:{} pending:{} failure:{}",
        entry.name,
        entry.kind,
        entry.uid,
        entry.gid,
        entry.mode,
        entry.size,
        entry.modified_unix,
        entry.pending,
        entry.failure
    );
}

/// Canonical, typed local snapshot. This validates format and bounds only;
/// the root executor must separately attest the published Git source.
/// Native readback resolves the same Git-owned identity scope as signed
/// apply. An absent trust snapshot is UNPROVEN, never an implicit default.
pub(super) fn registered_vm_host() -> Result<edge_shared_types::FleetHost, String> {
    let bytes = root_file(&Path::new(TRUSTED_ROOT).join("trust.pb"), 9 * 1024 * 1024)?;
    let trust = decode_native_trust_snapshot(&bytes)?;
    let registry = edge_shared_types::decode_host_registry(&trust.registry_pb)
        .map_err(|_| "HOST_NATIVE_REGISTRY_INVALID")?;
    let host = registry
        .hosts
        .iter()
        .find(|host| host.machine_id == trust.machine_id && host.kind == FleetHostKind::Vm as i32)
        .ok_or("HOST_NATIVE_VM_UNREGISTERED")?;
    if host.vm_containers.is_empty() {
        return Err("HOST_NATIVE_VM_RESOURCE_SCOPE_MISSING".into());
    }
    Ok(host.clone())
}

/// Legacy local observer shares exactly the same accepted identity scope.
pub(super) fn registered_vm_containers() -> Result<Vec<edge_shared_types::FleetVmContainer>, String>
{
    Ok(registered_vm_host()?.vm_containers)
}

pub(super) fn decode_native_trust_snapshot(
    bytes: &[u8],
) -> Result<FleetNativeTrustSnapshot, String> {
    if bytes.is_empty() || bytes.len() > 9 * 1024 * 1024 {
        return Err("HOST_NATIVE_TRUST_SNAPSHOT_SIZE_INVALID".into());
    }
    let trust = FleetNativeTrustSnapshot::decode(bytes)
        .map_err(|_| "HOST_NATIVE_TRUST_SNAPSHOT_PROTO_INVALID")?;
    if trust.schema_version != 1
        || trust.encode_to_vec() != bytes
        || trust.machine_id.is_empty()
        || trust.machine_id.len() > 64
        || !trust
            .machine_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || trust.registry_pb.is_empty()
        || trust.registry_pb.len() > 65536
        || trust.release_set_pb.is_empty()
        || trust.release_set_pb.len() > 65536
        || trust.application_bundle_pb.is_empty()
        || trust.application_bundle_pb.len() > 8 * 1024 * 1024
        || trust.selected_spec_bytes.is_empty()
        || trust.selected_spec_bytes.len() > 65536
        || trust.pinned_worker_public_key.len() != 32
        || trust.pinned_worker_public_key.iter().all(|b| *b == 0)
    {
        return Err("HOST_NATIVE_TRUST_SNAPSHOT_NONCANONICAL".into());
    }
    Ok(trust)
}

/// Read-only admission prerequisite for fleet fast/deep diagnostics. This
/// proves protected *local file metadata* only, NOT accepted remote provenance
/// or the Worker signer being provisioned. No private credentials are read.
pub(super) fn local_trust_preflight() -> &'static str {
    let root = Path::new(TRUSTED_ROOT);
    let meta = match fs::symlink_metadata(root) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return "UNENROLLED",
        Err(_) => return "UNPROVEN",
    };
    if !meta.file_type().is_dir() || meta.uid() != 0 || meta.permissions().mode() & 0o077 != 0 {
        return "UNPROVEN";
    }
    let bytes = match root_file(&root.join("trust.pb"), 9 * 1024 * 1024) {
        Ok(value) => value,
        Err(_) => return "UNPROVEN",
    };
    if decode_native_trust_snapshot(&bytes).is_err() {
        return "UNPROVEN";
    }
    let journal = match fs::symlink_metadata(root.join("journal")) {
        Ok(value) => value,
        Err(_) => return "UNPROVEN",
    };
    if !journal.file_type().is_dir()
        || journal.uid() != 0
        || journal.permissions().mode() & 0o077 != 0
    {
        return "UNPROVEN";
    }
    match protected_journal_has_pending(&root.join("journal")) {
        Ok(true) => "UNKNOWN_NO_REPLAY",
        Ok(false) => "PROTECTED_LOCAL_ONLY",
        Err(_) => "UNPROVEN",
    }
}

/// One root-local first-use prerequisite readback, never a remote authority
/// or a signed physical receipt. It uses the SAME protected root and the SAME
/// Worker ACTIVE readback as INSTALL, without changing either.
pub(super) fn local_vm_bootstrap_phase(
    host: &edge_shared_types::FleetHost,
    credential: &edge_shared_types::FleetVmCredentialReadback,
) -> edge_shared_types::FleetVmBootstrapPhase {
    use edge_shared_types::{FleetVmBootstrapPhase as Phase, FleetVmCredentialState as Credential};
    match local_trust_preflight() {
        "UNKNOWN_NO_REPLAY" => return Phase::JournalUnknownNoReplay,
        "PROTECTED_LOCAL_ONLY" => {}
        _ => return Phase::TrustUnproven,
    }
    // Local trust may be structurally valid but pinned to a different
    // signer than Git. Return typed UNPROVEN, never claim first-use READY.
    let exact_worker_signer = root_file(&Path::new(TRUSTED_ROOT).join("trust.pb"), 9 * 1024 * 1024)
        .ok()
        .and_then(|bytes| decode_native_trust_snapshot(&bytes).ok())
        .is_some_and(|trust| {
            edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(
                host,
                &trust.pinned_worker_public_key,
            )
            .is_ok()
        });
    if !exact_worker_signer {
        return Phase::TrustUnproven;
    }
    if host.native_receipt_public_key.is_empty() {
        return Phase::ReceiptKeyGitRegistrationRequired;
    }
    let receipt_key = root_file(&Path::new(TRUSTED_ROOT).join("receipt-key.pk8"), 4096);
    if !receipt_key.is_ok_and(|key| {
        edge_shared_types::host_receipt::check_native_receipt_key(host, &key).is_ok()
    }) {
        return Phase::ReceiptKeyMismatchOrUnproven;
    }
    if credential.state == Credential::ActiveLocalValid as i32 && credential.active_generation > 0 {
        Phase::LocalPrerequisitesOnly
    } else if credential.state == Credential::StoreAbsent as i32 {
        if host.vm_first_use_credential.is_some() {
            Phase::FirstUseWorkerSourceUnverified
        } else {
            Phase::FirstUseGitSourceRequired
        }
    } else {
        Phase::WorkerActiveCredentialRequired
    }
}

/// Exactly one accepted path policy for enrollment and subsequent apply.
pub(super) fn git_owned_host_spec_path(path: &str) -> bool {
    path.len() > "infra/".len()
        && path.starts_with("infra/")
        && !path.ends_with('/')
        && !path.contains("..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'))
}

pub(super) fn root_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if !path.starts_with(TRUSTED_ROOT) {
        return Err("HOST_NATIVE_PATH_OUTSIDE_OWNER_ROOT".into());
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "HOST_NATIVE_OWNER_FILE_MISSING")?;
    if !meta.file_type().is_file()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o077 != 0
        || meta.len() == 0
        || meta.len() > limit
    {
        return Err("HOST_NATIVE_OWNER_FILE_NOT_PROTECTED".into());
    }
    fs::read(path).map_err(|_| "HOST_NATIVE_OWNER_FILE_UNREADABLE".into())
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One canonical GitHub release is the source of owner artifacts. The owner
/// independently checks published tag -> accepted Git commit, exact asset
/// digests and the selected source-revision Git desired. The runner does NOT
/// get to supply a replacement registry, release URL or arbitrary Git ref.
pub(super) async fn attest_published_github_source(
    intent: &edge_shared_types::FleetHostIntent,
    registry_pb: &[u8],
    release_pb: &[u8],
    bundle_pb: &[u8],
    exact_spec: &[u8],
    spec_path: &str,
) -> Result<(), String> {
    let release_digest = sha256_hex(release_pb);
    if intent.release_set_sha256.as_slice()
        != ring::digest::digest(&ring::digest::SHA256, release_pb).as_ref()
    {
        return Err("HOST_NATIVE_RELEASE_INTENT_SHA_MISMATCH".into());
    }
    let release = edge_shared_types::ReleaseSet::decode(release_pb)
        .map_err(|_| "HOST_NATIVE_RELEASE_INVALID")?;
    let revision = release.source_revision.as_str();
    if revision.len() != 40
        || !revision.bytes().all(|c| c.is_ascii_hexdigit())
        || !git_owned_host_spec_path(spec_path)
    {
        return Err("HOST_NATIVE_CANONICAL_SOURCE_INVALID".into());
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "HOST_NATIVE_GITHUB_CLIENT_INVALID")?;
    let base = "https://api.github.com/repos/iamaman11/sing-box";
    let tag = format!("edge-release-{release_digest}");
    let uri = format!("{base}/releases/tags/{tag}");
    let response = client
        .get(&uri)
        .header("User-Agent", "sing-box-native-owner")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "HOST_NATIVE_RELEASE_LOOKUP_UNAVAILABLE")?;
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 262144) {
        return Err("HOST_NATIVE_PUBLISHED_RELEASE_NOT_VERIFIED".into());
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| "HOST_NATIVE_RELEASE_RESPONSE_UNAVAILABLE")?;
    if body.len() > 262144 {
        return Err("HOST_NATIVE_RELEASE_RESPONSE_TOO_LARGE".into());
    }
    let published: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| "HOST_NATIVE_RELEASE_METADATA_INVALID")?;
    let accepted = published["target_commitish"]
        .as_str()
        .ok_or("HOST_NATIVE_ACCEPTED_REVISION_MISSING")?;
    if accepted.len() != 40
        || !accepted.bytes().all(|c| c.is_ascii_hexdigit())
        || published["tag_name"].as_str() != Some(tag.as_str())
        || published["draft"].as_bool() != Some(false)
        || published["prerelease"].as_bool() != Some(false)
    {
        return Err("HOST_NATIVE_RELEASE_METADATA_NOT_ACCEPTED".into());
    }
    let ref_response = client
        .get(format!("{base}/git/ref/tags/{tag}"))
        .header("User-Agent", "sing-box-native-owner")
        .send()
        .await
        .map_err(|_| "HOST_NATIVE_RELEASE_REF_UNAVAILABLE")?;
    if !ref_response.status().is_success() {
        return Err("HOST_NATIVE_RELEASE_REF_NOT_ACCEPTED".into());
    }
    let ref_bytes = ref_response
        .bytes()
        .await
        .map_err(|_| "HOST_NATIVE_RELEASE_REF_UNAVAILABLE")?;
    if ref_bytes.len() > 32768 {
        return Err("HOST_NATIVE_RELEASE_REF_TOO_LARGE".into());
    }
    let git_ref: serde_json::Value =
        serde_json::from_slice(&ref_bytes).map_err(|_| "HOST_NATIVE_RELEASE_REF_INVALID")?;
    if git_ref["object"]["type"].as_str() != Some("commit")
        || git_ref["object"]["sha"].as_str() != Some(accepted)
    {
        return Err("HOST_NATIVE_RELEASE_GIT_REF_MISMATCH".into());
    }
    // A release's target_commitish is the accepted main commit, while
    // ReleaseSet.source_revision names the exact candidate that passed CI.
    // They may have different SHA-1 commit identities after a protected
    // merge, but must have the SAME Git tree. A published tag and matching
    // artifact digests without this check could authorize a foreign desired.
    let mut accepted_tree = String::new();
    let mut candidate_tree = String::new();
    for (sha, destination) in [
        (accepted, &mut accepted_tree),
        (revision, &mut candidate_tree),
    ] {
        let response = client
            .get(format!("{base}/git/commits/{sha}"))
            .header("User-Agent", "sing-box-native-owner")
            .send()
            .await
            .map_err(|_| "HOST_NATIVE_GIT_COMMIT_UNAVAILABLE")?;
        if !response.status().is_success() || response.content_length().is_some_and(|n| n > 65536) {
            return Err("HOST_NATIVE_GIT_COMMIT_UNVERIFIED".into());
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| "HOST_NATIVE_GIT_COMMIT_UNAVAILABLE")?;
        if bytes.len() > 65536 {
            return Err("HOST_NATIVE_GIT_COMMIT_TOO_LARGE".into());
        }
        let commit: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "HOST_NATIVE_GIT_COMMIT_INVALID")?;
        if commit["sha"].as_str() != Some(sha) {
            return Err("HOST_NATIVE_GIT_COMMIT_SHA_MISMATCH".into());
        }
        let tree = commit["tree"]["sha"]
            .as_str()
            .ok_or("HOST_NATIVE_GIT_TREE_ABSENT")?;
        if tree.len() != 40 || !tree.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("HOST_NATIVE_GIT_TREE_INVALID".into());
        }
        *destination = tree.to_owned();
    }
    if accepted_tree != candidate_tree {
        return Err("HOST_NATIVE_ACCEPTED_SOURCE_TREE_MISMATCH".into());
    }

    let assets = published["assets"]
        .as_array()
        .ok_or("HOST_NATIVE_RELEASE_ASSETS_INVALID")?;
    for (name, bytes) in [
        ("release-set.pb", release_pb),
        ("application-bundle.pb", bundle_pb),
        ("fleet-registry.pb", registry_pb),
    ] {
        let mut matches = assets
            .iter()
            .filter(|asset| asset["name"].as_str() == Some(name));
        let asset = matches.next().ok_or("HOST_NATIVE_RELEASE_ASSET_MISSING")?;
        if matches.next().is_some()
            || asset["digest"].as_str() != Some(format!("sha256:{}", sha256_hex(bytes)).as_str())
        {
            return Err("HOST_NATIVE_RELEASE_ASSET_DIGEST_MISMATCH".into());
        }
    }
    // Exactly the accepted candidate source tree supplies host desired.
    // The fetched contents are compared with the protected local snapshot,
    // which also binds into the signed intent's desired digest.
    let raw_url =
        format!("https://raw.githubusercontent.com/iamaman11/sing-box/{revision}/{spec_path}");
    let source = client
        .get(raw_url)
        .header("User-Agent", "sing-box-native-owner")
        .send()
        .await
        .map_err(|_| "HOST_NATIVE_GIT_DESIRED_UNAVAILABLE")?;
    if !source.status().is_success() || source.content_length().is_some_and(|n| n > 65536) {
        return Err("HOST_NATIVE_GIT_DESIRED_NOT_ACCEPTED".into());
    }
    let desired = source
        .bytes()
        .await
        .map_err(|_| "HOST_NATIVE_GIT_DESIRED_UNAVAILABLE")?;
    if desired.as_ref() != exact_spec || desired.len() > 65536 {
        return Err("HOST_NATIVE_GIT_DESIRED_MISMATCH".into());
    }
    Ok(())
}

/// Bind the policy files actually used for START to the exact immutable
/// GitHub application bundle already authenticated by the native owner.
/// A release marker alone cannot prove that Compose or image pins on disk
/// still contain the bytes published with that release.
fn verify_installed_native_vm_policy(stack_dir: &Path, bundle_pb: &[u8]) -> Result<(), String> {
    let request = ApplyBundleRequest::decode(bundle_pb)
        .map_err(|_| "HOST_NATIVE_BUNDLE_POLICY_UNDECODABLE")?;
    super::validate_digest_bound_bundle_request(&request)
        .map_err(|_| "HOST_NATIVE_BUNDLE_POLICY_DIGEST_INVALID")?;
    super::docker_observation::verify_exact_installed_vm_bundle_static(stack_dir, &request)
        .map_err(|_| "HOST_NATIVE_VM_STATIC_POLICY_DRIFT")?;
    for name in ["docker-compose.yml", ".images.env"] {
        let mut candidates = request
            .stack_files
            .iter()
            .filter(|file| file.relative_path == name);
        let expected = candidates
            .next()
            .ok_or("HOST_NATIVE_BUNDLE_POLICY_FILE_MISSING")?;
        if candidates.next().is_some()
            || expected.content.is_empty()
            || expected.content.len() > 65536
        {
            return Err("HOST_NATIVE_BUNDLE_POLICY_FILE_INVALID".into());
        }
        verify_installed_native_vm_file(stack_dir, name, &expected.content)?;
    }
    Ok(())
}

fn verify_installed_native_vm_file(
    stack_dir: &Path,
    name: &str,
    expected: &[u8],
) -> Result<(), String> {
    let file = stack_dir.join(name);
    let metadata =
        fs::symlink_metadata(&file).map_err(|_| "HOST_NATIVE_BUNDLE_POLICY_NOT_INSTALLED")?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > 65536
        || metadata.len() as usize != expected.len()
    {
        return Err("HOST_NATIVE_BUNDLE_POLICY_FILE_UNSAFE".into());
    }
    let actual = fs::read(&file).map_err(|_| "HOST_NATIVE_BUNDLE_POLICY_READ_FAILED")?;
    if actual != expected {
        return Err("HOST_NATIVE_BUNDLE_POLICY_DRIFT".into());
    }
    Ok(())
}

/// One closed diagnostic contract for native INSTALL. Only known,
/// non-secret owner error classes may cross the native RPC/CLI boundary.
/// Arbitrary Docker/credential-store errors cannot become operator commands.
#[derive(Debug, Clone, Copy)]
enum NativeVmInstallFailurePhase {
    Preadmission,
    PostBegin,
}

fn native_vm_install_error_class(source: &str, phase: NativeVmInstallFailurePhase) -> &'static str {
    use NativeVmInstallFailurePhase::{PostBegin, Preadmission};
    match (phase, source) {
        (
            Preadmission,
            "HOST_VM_INSTALL_ACTIVE_V2_REQUIRED"
            | "HOST_VM_INSTALL_GIT_FIRST_USE_IDENTITY_REQUIRED",
        ) => "HOST_VM_INSTALL_GIT_FIRST_USE_CREDENTIAL_REQUIRED",
        (
            Preadmission,
            "HOST_VM_INSTALL_WORKER_STORE_UNPROVEN"
            | "HOST_VM_INSTALL_WORKER_ACCESS_UNPROVEN"
            | "HOST_VM_INSTALL_WORKER_ORIGIN_UNPROVEN"
            | "HOST_VM_INSTALL_WORKER_ACTIVE_ORIGIN_MISMATCH"
            | "HOST_VM_INSTALL_GIT_FIRST_USE_GENERATION_MISMATCH"
            | "HOST_VM_INSTALL_GIT_FIRST_USE_DIGEST_MISMATCH"
            | "HOST_VM_INSTALL_WORKER_FIRST_USE_BUNDLE_INVALID"
            | "HOST_VM_INSTALL_WORKER_FIRST_USE_PAYLOAD_INVALID"
            | "HOST_VM_INSTALL_FIRST_USE_STORE_NOT_EMPTY",
        ) => "HOST_VM_INSTALL_WORKER_ACTIVE_ORIGIN_UNPROVEN",
        (
            Preadmission,
            "HOST_VM_INSTALL_CREDENTIAL_UNPROVEN"
            | "HOST_VM_INSTALL_CREDENTIAL_INVALID"
            | "HOST_VM_INSTALL_V2_ACTIVE_IDENTITY_INVALID"
            | "HOST_VM_INSTALL_V2_ACTIVE_PAYLOAD_INVALID",
        ) => "HOST_VM_INSTALL_WORKER_CREDENTIAL_UNPROVEN",
        (
            Preadmission,
            "HOST_VM_INSTALL_EXISTING_STACK"
            | "HOST_VM_INSTALL_CONTAINER_ALREADY_PRESENT"
            | "HOST_VM_INSTALL_EXISTING_NETWORK",
        ) => "HOST_VM_INSTALL_OWNER_PRESTATE_NOT_EMPTY",
        (Preadmission, _) => "HOST_NATIVE_VM_INSTALL_PREADMISSION_BLOCKED",
        (
            PostBegin,
            "HOST_VM_INSTALL_CREDENTIAL_DRIFT_NO_REPLAY"
            | "HOST_VM_INSTALL_ACTIVE_CREDENTIAL_DISAPPEARED_NO_REPLAY"
            | "HOST_VM_INSTALL_CREDENTIAL_CURSOR_UNPROVEN_NO_REPLAY"
            | "HOST_VM_INSTALL_CREDENTIAL_CHANGED_NO_REPLAY"
            | "HOST_VM_INSTALL_CREDENTIAL_PROJECTION_INVALID_NO_REPLAY",
        ) => "HOST_VM_INSTALL_WORKER_CREDENTIAL_DRIFT_NO_REPLAY",
        (PostBegin, _) => "HOST_NATIVE_VM_INSTALL_UNCERTAIN_NO_REPLAY",
    }
}

/// Pre-BEGIN errors are safe to retry with a NEW signed operation because
/// no resource effects have run. Preserve useful closed diagnostics without
/// serializing untrusted Docker daemon text or private paths.
fn native_vm_replace_preadmission_class(code: &str) -> &'static str {
    match code {
        "HOST_VM_STATIC_BUNDLE_DRIFT" => "HOST_VM_STATIC_BUNDLE_DRIFT",
        "HOST_VM_IMAGE_PREVIOUS_IDENTITY_DRIFT" => "HOST_VM_IMAGE_PREVIOUS_IDENTITY_DRIFT",
        "HOST_VM_IMAGE_ALL_REGISTERED_MUST_RUN" => "HOST_VM_IMAGE_ALL_REGISTERED_MUST_RUN",
        "HOST_VM_IMAGE_RUNTIME_INCOMPLETE_NO_REPLAY" => {
            "HOST_VM_IMAGE_RUNTIME_INCOMPLETE_NO_REPLAY"
        }
        "HOST_VM_RECONCILE_EFFECTOR_NOT_IMPLEMENTED" => {
            "HOST_VM_RECONCILE_EFFECTOR_NOT_IMPLEMENTED"
        }
        "HOST_VM_RECONCILE_IMAGE_SCOPE_CONFLICT" => "HOST_VM_RECONCILE_IMAGE_SCOPE_CONFLICT",
        "HOST_VM_IMAGE_FOREIGN_IMAGE_OR_ENV_CHANGED" => {
            "HOST_VM_IMAGE_FOREIGN_IMAGE_OR_ENV_CHANGED"
        }
        "HOST_VM_IMAGE_PREVIOUS_RELEASE_UNPROVEN" => "HOST_VM_IMAGE_PREVIOUS_RELEASE_UNPROVEN",
        "HOST_VM_IMAGE_ENV_SCOPE_INVALID" => "HOST_VM_IMAGE_ENV_SCOPE_INVALID",
        "HOST_VM_RELEASE_TARGET_GRAPH_MISMATCH" => "HOST_VM_RELEASE_TARGET_GRAPH_MISMATCH",
        "HOST_VM_STATIC_BUNDLE_MANIFEST_DRIFT" => "HOST_VM_STATIC_BUNDLE_MANIFEST_DRIFT",
        _ => "HOST_NATIVE_VM_REPLACE_NOT_RESOURCE_SCOPED",
    }
}

/// Root-owned post-BEGIN stage identity. Only closed, non-sensitive native
/// error constants may become signed journal reasons or operator diagnostics.
/// Never include arbitrary Docker daemon errors, command output or secrets.
fn native_vm_replace_error_class(code: &str) -> &'static str {
    match code {
        "HOST_VM_NATIVE_RECREATE_STOP_UNCERTAIN_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_STOP_UNCERTAIN_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_STOP_RUNNING_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_STOP_RUNNING_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_STOP_RESTARTING_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_STOP_RESTARTING_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_STOP_PAUSED_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_STOP_PAUSED_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_STOP_DEAD_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_STOP_DEAD_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_STOP_INSPECT_UNAVAILABLE_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_STOP_INSPECT_UNAVAILABLE_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_STOP_STATE_UNKNOWN_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_STOP_STATE_UNKNOWN_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_STOP_IDENTITY_CHANGED_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_STOP_IDENTITY_CHANGED_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_DELETE_UNCERTAIN_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_DELETE_UNCERTAIN_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_CREATE_UNCERTAIN_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_CREATE_UNCERTAIN_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_START_UNCERTAIN_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_START_UNCERTAIN_NO_REPLAY"
        }
        "HOST_VM_NATIVE_RECREATE_NEW_ID_UNPROVEN_NO_REPLAY" => {
            "HOST_VM_NATIVE_RECREATE_NEW_ID_UNPROVEN_NO_REPLAY"
        }
        "HOST_VM_INSTALL_PULL_TIMEOUT_NO_REPLAY" => "HOST_VM_INSTALL_PULL_TIMEOUT_NO_REPLAY",
        "HOST_VM_INSTALL_PULL_ACK_UNCERTAIN_NO_REPLAY" => {
            "HOST_VM_INSTALL_PULL_ACK_UNCERTAIN_NO_REPLAY"
        }
        "HOST_VM_IMAGE_STAGE_UNCERTAIN_NO_REPLAY" => "HOST_VM_IMAGE_STAGE_UNCERTAIN_NO_REPLAY",
        "HOST_VM_IMAGE_STAGE_PERMISSIONS_UNCERTAIN_NO_REPLAY" => {
            "HOST_VM_IMAGE_STAGE_PERMISSIONS_UNCERTAIN_NO_REPLAY"
        }
        "HOST_VM_IMAGE_ACTIVATE_UNCERTAIN_NO_REPLAY" => {
            "HOST_VM_IMAGE_ACTIVATE_UNCERTAIN_NO_REPLAY"
        }
        "HOST_VM_IMAGE_SYNC_UNCERTAIN_NO_REPLAY" => "HOST_VM_IMAGE_SYNC_UNCERTAIN_NO_REPLAY",
        "HOST_VM_IMAGE_CONFIG_POSTSTATE_UNPROVEN_NO_REPLAY" => {
            "HOST_VM_IMAGE_CONFIG_POSTSTATE_UNPROVEN_NO_REPLAY"
        }
        "HOST_VM_IMAGE_GRAPH_POSTSTATE_UNPROVEN_NO_REPLAY" => {
            "HOST_VM_IMAGE_GRAPH_POSTSTATE_UNPROVEN_NO_REPLAY"
        }
        "HOST_VM_IMAGE_GATEWAY_NOT_RECREATED_NO_REPLAY" => {
            "HOST_VM_IMAGE_GATEWAY_NOT_RECREATED_NO_REPLAY"
        }
        "HOST_VM_IMAGE_WARP_NOT_RECREATED_NO_REPLAY" => {
            "HOST_VM_IMAGE_WARP_NOT_RECREATED_NO_REPLAY"
        }
        "HOST_VM_IMAGE_RELEASE_UNCERTAIN_NO_REPLAY" => "HOST_VM_IMAGE_RELEASE_UNCERTAIN_NO_REPLAY",
        _ => "HOST_NATIVE_VM_REPLACE_UNCERTAIN_NO_REPLAY",
    }
}

/// The existing installed root agent is the *only* mutation authority.
/// Fail closed while the native root has not received the exact immutable
/// release and pinned signer material; no implicit provision or fetch.
pub async fn apply(stack_dir: &Path) -> Result<(), String> {
    let mut intent_pb = Vec::new();
    io::stdin()
        .take(4097)
        .read_to_end(&mut intent_pb)
        .map_err(|_| "HOST_NATIVE_INTENT_STDIN_UNAVAILABLE")?;
    let intent = decode_host_intent(&intent_pb).map_err(str::to_owned)?;
    if intent.kind != FleetHostKind::Vm as i32 {
        return Err("HOST_NATIVE_VM_KIND_REQUIRED".into());
    }
    // Held through Worker authorization, BEGIN, native operation and readback.
    let _resource_lock = owner_operation_lock()?;
    // Resource admission is independent of the signed code-only refresh.
    // A journal with ANY invalid entry or prior unfinished BEGIN must block
    // mutation before credential access, Worker POST and native Docker effects.
    // Only root's read-only diagnostic may inspect such entries.
    let journal = Path::new(JOURNAL_ROOT);
    // A pending mutation still blocks every fresh APPLY. Only an explicitly
    // Worker-signed RECOVER may enter the journal's read-only historical
    // adjudication state machine; it can NEVER invoke Docker effectors.
    if protected_journal_has_pending(journal)?
        && intent.action != edge_shared_types::FleetHostAction::Recover as i32
    {
        return Err("HOST_NATIVE_RESOURCE_PENDING_UNKNOWN_NO_REPLAY".into());
    }
    let trust_root = Path::new(TRUSTED_ROOT);
    let trust_meta =
        fs::symlink_metadata(trust_root).map_err(|_| "HOST_NATIVE_OWNER_ROOT_NOT_PROVISIONED")?;
    if !trust_meta.file_type().is_dir()
        || trust_meta.uid() != 0
        || trust_meta.permissions().mode() & 0o077 != 0
    {
        return Err("HOST_NATIVE_OWNER_ROOT_NOT_PROTECTED".into());
    }
    let trust_bytes = root_file(&trust_root.join("trust.pb"), 9 * 1024 * 1024)?;
    let trust = decode_native_trust_snapshot(&trust_bytes)?;
    let machine_id = trust.machine_id.as_str();
    if machine_id != intent.machine_id {
        return Err("HOST_NATIVE_MACHINE_ID_MISMATCH".into());
    }
    let registry_pb = trust.registry_pb;
    let release_pb = trust.release_set_pb;
    // A trust refresh can complete before binary publication if power is
    // lost. Never BEGIN with an executable that differs from the EXACT
    // accepted ReleaseSet, even if its Ed25519 trust and registry match.
    let accepted_release = ReleaseSet::decode(release_pb.as_slice())
        .map_err(|_| "HOST_NATIVE_VM_RELEASE_DECODE_FAILED")?;
    let expected_owner_sha = accepted_release
        .vm_runtime
        .as_ref()
        .ok_or("HOST_NATIVE_VM_RELEASE_OWNER_ABSENT")?
        .edge_agent_sha256
        .as_slice();
    if expected_owner_sha.len() != 32 || expected_owner_sha.iter().all(|b| *b == 0) {
        return Err("HOST_NATIVE_VM_RELEASE_OWNER_DIGEST_INVALID".into());
    }
    let owner_binary = Path::new("/usr/local/libexec/sing-box/edge-agent");
    let owner_meta = fs::symlink_metadata(owner_binary)
        .map_err(|_| "HOST_NATIVE_VM_OWNER_BINARY_UNAVAILABLE")?;
    if !owner_meta.file_type().is_file()
        || owner_meta.uid() != 0
        || owner_meta.permissions().mode() & 0o777 != 0o755
        || owner_meta.len() == 0
        || owner_meta.len() > 32 * 1024 * 1024
    {
        return Err("HOST_NATIVE_VM_OWNER_BINARY_UNPROTECTED".into());
    }
    let installed_owner =
        fs::read(owner_binary).map_err(|_| "HOST_NATIVE_VM_OWNER_BINARY_UNREADABLE")?;
    if ring::digest::digest(&ring::digest::SHA256, &installed_owner).as_ref() != expected_owner_sha
    {
        return Err("HOST_NATIVE_VM_OWNER_RELEASE_DRIFT".into());
    }
    let bundle_pb = trust.application_bundle_pb;
    let signer_key = trust.pinned_worker_public_key;
    let spec = trust.selected_spec_bytes;
    // No unprivileged desired override: the native root first confirms the
    // spec path is the registered Git-owned one, staged with the accepted
    // release by the owner installation procedure.
    let registry = edge_shared_types::decode_host_registry(&registry_pb)
        .map_err(|_| "HOST_NATIVE_REGISTRY_INVALID")?;
    let host = registry
        .hosts
        .iter()
        .find(|h| h.machine_id == intent.machine_id && h.kind == intent.kind)
        .ok_or("HOST_NATIVE_MACHINE_UNREGISTERED")?;
    if !git_owned_host_spec_path(&host.desired_spec_path) {
        return Err("HOST_NATIVE_SPEC_PATH_INVALID".into());
    }
    // The trusted Worker verification key must match the canonical Git host.
    // Without this equality an enrollment argument could create an alternate
    // signing authority despite valid native journal/receipt machinery.
    edge_shared_types::host_lifecycle::verify_git_worker_signer_pin(host, &signer_key)
        .map_err(str::to_owned)?;
    // The native owner has a separately pinned Git public identity. Without
    // a root-only signing key, no mutation may begin: runner-copied results
    // must never be upgraded to authenticated physical evidence.
    let receipt_pkcs8 = root_file(&trust_root.join("receipt-key.pk8"), 4096)?;
    edge_shared_types::host_receipt::check_native_receipt_key(host, &receipt_pkcs8)
        .map_err(str::to_owned)?;
    // A missing or invalid run target is not executable. The native
    // STOP effector only touches verified application-owned Docker IDs.
    // All unsupported transitions are rejected BEFORE signed BEGIN.
    let vm_target = host
        .target
        .as_ref()
        .ok_or("HOST_TARGET_UNSET_OBSERVE_ONLY")?;
    if !matches!(
        edge_shared_types::FleetHostRunState::try_from(vm_target.run_state),
        Ok(edge_shared_types::FleetHostRunState::Running
            | edge_shared_types::FleetHostRunState::Stopped)
    ) {
        return Err("HOST_NATIVE_VM_TARGET_NOT_EXECUTABLE".into());
    }
    // Only identities from the immutable, typed, Git-owned host registry.
    if host.vm_containers.is_empty() {
        return Err("HOST_NATIVE_VM_RESOURCE_SCOPE_MISSING".into());
    }
    super::docker_observation::verify_owned_application_containers(&host.vm_containers).await?;
    attest_published_github_source(
        &intent,
        &registry_pb,
        &release_pb,
        &bundle_pb,
        &spec,
        &host.desired_spec_path,
    )
    .await?;
    let identity = super::vm_credential_access_identity_path(stack_dir)?;
    // Same Service Auth identity, same Worker and same strict JWT/JWKS
    // verifier as the subsequent POST. A failed GET proof blocks before
    // sending HostIntent; it cannot authorize a native effect by itself.
    edge_secrets::diagnose_canonical_host_access(&identity)
        .await
        .map_err(str::to_owned)?;
    // POST is never retried after an ambiguous result.
    let authorization =
        edge_secrets::request_canonical_host_authorization(&intent_pb, &identity).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_CLOCK_UNAVAILABLE")?
        .as_secs();
    let handle = tokio::runtime::Handle::current();
    // One in-memory plan snapshot shared between pre-BEGIN admission and
    // the single native effector. No second durable state or retry loop.
    let prepared = std::cell::RefCell::new(None);
    let prepared_replace = std::cell::RefCell::new(None);
    let prepared_install = std::cell::RefCell::new(None);
    let result = tokio::task::block_in_place(|| {
        execute_native_host_once(
            &intent,
            &authorization,
            &registry_pb,
            &spec,
            &release_pb,
            Some(&bundle_pb),
            &signer_key,
            machine_id,
            FleetHostKind::Vm as i32,
            now,
            journal,
            || {
                handle
                    .block_on(super::capture_local_host_observation(stack_dir))
                    .map_err(|_| "HOST_NATIVE_READBACK_FAILED")
            },
            |step| match step {
                FleetHostPlannedStep::Start | FleetHostPlannedStep::Stop => {
                    if intent.resource_id != "sing-box" {
                        return Err("HOST_NATIVE_SCOPED_RUN_NOT_ALLOWED");
                    }
                    // STOP remains possible with a missing/old bundle; START
                    // must never execute on a modified Compose or image policy.
                    if step == FleetHostPlannedStep::Start {
                        verify_installed_native_vm_policy(stack_dir, &bundle_pb)
                            .map_err(|_| "HOST_NATIVE_VM_POLICY_DRIFT")?;
                    }
                    let proposal = handle
                        .block_on(super::docker_observation::preflight_native_vm_run(
                            stack_dir, host, step,
                        ))
                        .map_err(|_| "HOST_NATIVE_VM_RUN_PREADMISSION_BLOCKED")?;
                    *prepared.borrow_mut() = Some(proposal);
                    Ok(())
                }
                FleetHostPlannedStep::Install => {
                    if intent.resource_id != "sing-box" {
                        return Err("HOST_NATIVE_VM_INSTALL_HOST_SCOPE_REQUIRED");
                    }
                    let request = ApplyBundleRequest::decode(bundle_pb.as_slice())
                        .map_err(|_| "HOST_NATIVE_VM_INSTALL_BUNDLE_INVALID")?;
                    let plan = handle
                        .block_on(super::docker_observation::preflight_native_vm_install(
                            stack_dir, host, &request,
                        ))
                        .map_err(|error| {
                            native_vm_install_error_class(
                                &error,
                                NativeVmInstallFailurePhase::Preadmission,
                            )
                        })?;
                    // Never reach durable BEGIN on a locally valid but
                    // unverified Worker-v2 ACTIVE cursor. The existing
                    // authenticated origin verifier performs read-only GET.
                    handle
                        .block_on(
                            super::docker_observation::attest_native_vm_install_worker_origin(
                                stack_dir, &plan,
                            ),
                        )
                        .map_err(|error| {
                            native_vm_install_error_class(
                                error,
                                NativeVmInstallFailurePhase::Preadmission,
                            )
                        })?;
                    *prepared_install.borrow_mut() = Some(plan);
                    Ok(())
                }
                FleetHostPlannedStep::ReplaceRelease => {
                    let request = ApplyBundleRequest::decode(bundle_pb.as_slice())
                        .map_err(|_| "HOST_NATIVE_VM_SCOPED_BUNDLE_INVALID")?;
                    let proposal = handle
                        .block_on(super::docker_observation::preflight_native_vm_replace(
                            stack_dir, host, &request,
                        ))
                        .map_err(|error| {
                            let reason = native_vm_replace_preadmission_class(&error);
                            eprintln!("host_native_replace_preadmission={reason}");
                            reason
                        })?;
                    if intent.resource_id != "sing-box" {
                        let scope = proposal
                            .single_config_resource_id(host)
                            .map_err(|_| "HOST_NATIVE_SIGNED_SCOPE_UNSUPPORTED")?;
                        if scope != intent.resource_id {
                            return Err("HOST_NATIVE_SIGNED_SCOPE_DIFFERS_FROM_PLAN");
                        }
                    }
                    *prepared_replace.borrow_mut() = Some(proposal);
                    Ok(())
                }
                _ => Err("HOST_NATIVE_VM_STEP_NOT_IMPLEMENTED"),
            },
            |step| match step {
                FleetHostPlannedStep::Start | FleetHostPlannedStep::Stop => {
                    let proposal = prepared
                        .borrow_mut()
                        .take()
                        .ok_or("HOST_NATIVE_VM_PREPARED_PLAN_MISSING")?;
                    handle
                        .block_on(super::docker_observation::apply_native_vm_run_once(
                            stack_dir, host, proposal,
                        ))
                        .map_err(|_| "HOST_NATIVE_VM_RUN_UNCERTAIN_NO_REPLAY")
                }
                FleetHostPlannedStep::ReplaceRelease => {
                    let proposal = prepared_replace
                        .borrow_mut()
                        .take()
                        .ok_or("HOST_NATIVE_VM_REPLACE_PREPARED_PLAN_MISSING")?;
                    handle
                        .block_on(super::docker_observation::apply_native_vm_replace_once(
                            stack_dir, host, proposal,
                        ))
                        .map_err(|error| {
                            let reason = native_vm_replace_error_class(&error);
                            eprintln!("host_native_replace_failure={reason}");
                            reason
                        })
                }
                FleetHostPlannedStep::Install => {
                    let plan = prepared_install
                        .borrow_mut()
                        .take()
                        .ok_or("HOST_NATIVE_VM_INSTALL_PLAN_MISSING")?;
                    handle
                        .block_on(super::docker_observation::apply_native_vm_install_once(
                            stack_dir, host, plan,
                        ))
                        .map_err(|error| {
                            native_vm_install_error_class(
                                &error,
                                NativeVmInstallFailurePhase::PostBegin,
                            )
                        })
                }
                _ => Err("HOST_NATIVE_STEP_UNSUPPORTED_NO_REPLAY"),
            },
        )
    })
    .map_err(str::to_owned)?;
    let receipt = edge_shared_types::host_receipt::sign_native_receipt(
        &intent,
        &result,
        host,
        &receipt_pkcs8,
    )
    .map_err(str::to_owned)?;
    io::stdout()
        .write_all(&receipt.encode_to_vec())
        .map_err(|_| "HOST_NATIVE_RESULT_STDOUT_UNCERTAIN_NO_REPLAY".into())
}

#[cfg(test)]
mod native_host_path_tests {
    use super::*;

    #[test]
    fn native_journal_scans_past_pending_for_a_later_untrusted_file() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir =
            std::env::temp_dir().join(format!("sing-box-journal-scan-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let pending = dir.join("resource-correct.pending.pb");
        let invalid = dir.join("journal-bad.pb");
        fs::write(&pending, b"pending").unwrap();
        fs::write(&invalid, b"bad").unwrap();
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&invalid, fs::Permissions::from_mode(0o644)).unwrap();
        let uid = fs::metadata(&pending).unwrap().uid();
        let scan = scan_native_journal_metadata(&dir, uid).unwrap();
        assert_eq!(scan.entries, 2);
        assert_eq!(scan.pending, 1);
        let bad = scan.first_invalid.unwrap();
        assert_eq!(bad.name, "journal-bad.pb");
        assert_eq!(bad.failure, "GROUP_OTHER_BITS_PRESENT");
        assert_eq!(bad.mode & 0o777, 0o644);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn native_install_diagnostics_preserve_only_known_typed_failure_classes() {
        use NativeVmInstallFailurePhase::{PostBegin, Preadmission};
        assert_eq!(
            native_vm_install_error_class("HOST_VM_INSTALL_ACTIVE_V2_REQUIRED", Preadmission,),
            "HOST_VM_INSTALL_GIT_FIRST_USE_CREDENTIAL_REQUIRED",
        );
        assert_eq!(
            native_vm_install_error_class("HOST_VM_INSTALL_CREDENTIAL_DRIFT_NO_REPLAY", PostBegin,),
            "HOST_VM_INSTALL_WORKER_CREDENTIAL_DRIFT_NO_REPLAY",
        );
        assert_eq!(
            native_vm_install_error_class("HOST_VM_INSTALL_WORKER_ORIGIN_UNPROVEN", Preadmission,),
            "HOST_VM_INSTALL_WORKER_ACTIVE_ORIGIN_UNPROVEN",
        );
        assert_eq!(
            native_vm_install_error_class(
                "HOST_VM_INSTALL_WORKER_ACTIVE_ORIGIN_MISMATCH",
                Preadmission,
            ),
            "HOST_VM_INSTALL_WORKER_ACTIVE_ORIGIN_UNPROVEN",
        );
        assert_eq!(
            native_vm_install_error_class("some private credential bytes", Preadmission),
            "HOST_NATIVE_VM_INSTALL_PREADMISSION_BLOCKED",
        );
        assert_eq!(
            native_vm_install_error_class("unexpected Docker daemon message", PostBegin),
            "HOST_NATIVE_VM_INSTALL_UNCERTAIN_NO_REPLAY",
        );
    }

    #[test]
    fn native_start_policy_rejects_mutated_files_and_symlinks() {
        let root = std::env::temp_dir().join(format!(
            "sing-box-native-policy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let exact = b"name: vultr-edge\n";
        fs::write(root.join("docker-compose.yml"), exact).unwrap();
        assert!(verify_installed_native_vm_file(&root, "docker-compose.yml", exact).is_ok());
        fs::write(root.join("docker-compose.yml"), b"name: foreign\n").unwrap();
        assert!(verify_installed_native_vm_file(&root, "docker-compose.yml", exact).is_err());
        fs::remove_file(root.join("docker-compose.yml")).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", root.join("docker-compose.yml")).unwrap();
        assert!(verify_installed_native_vm_file(&root, "docker-compose.yml", exact).is_err());
        fs::remove_file(root.join("docker-compose.yml")).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn native_vm_replace_preadmission_reason_explains_static_drift_safely() {
        assert_eq!(
            native_vm_replace_preadmission_class("HOST_VM_STATIC_BUNDLE_DRIFT"),
            "HOST_VM_STATIC_BUNDLE_DRIFT"
        );
        assert_eq!(
            native_vm_replace_preadmission_class("HOST_VM_IMAGE_PREVIOUS_IDENTITY_DRIFT"),
            "HOST_VM_IMAGE_PREVIOUS_IDENTITY_DRIFT"
        );
        assert_eq!(
            native_vm_replace_preadmission_class("API_TOKEN=secret"),
            "HOST_NATIVE_VM_REPLACE_NOT_RESOURCE_SCOPED"
        );
    }

    #[test]
    fn native_vm_replace_error_reason_is_stage_specific_and_closed() {
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_NATIVE_RECREATE_STOP_UNCERTAIN_NO_REPLAY"),
            "HOST_VM_NATIVE_RECREATE_STOP_UNCERTAIN_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_NATIVE_RECREATE_STOP_RUNNING_NO_REPLAY"),
            "HOST_VM_NATIVE_RECREATE_STOP_RUNNING_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_NATIVE_RECREATE_STOP_RESTARTING_NO_REPLAY"),
            "HOST_VM_NATIVE_RECREATE_STOP_RESTARTING_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_NATIVE_RECREATE_STOP_PAUSED_NO_REPLAY"),
            "HOST_VM_NATIVE_RECREATE_STOP_PAUSED_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_NATIVE_RECREATE_STOP_DEAD_NO_REPLAY"),
            "HOST_VM_NATIVE_RECREATE_STOP_DEAD_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_NATIVE_RECREATE_STOP_INSPECT_UNAVAILABLE_NO_REPLAY"),
            "HOST_VM_NATIVE_RECREATE_STOP_INSPECT_UNAVAILABLE_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_NATIVE_RECREATE_STOP_STATE_UNKNOWN_NO_REPLAY"),
            "HOST_VM_NATIVE_RECREATE_STOP_STATE_UNKNOWN_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_NATIVE_RECREATE_STOP_IDENTITY_CHANGED_NO_REPLAY"),
            "HOST_VM_NATIVE_RECREATE_STOP_IDENTITY_CHANGED_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("HOST_VM_IMAGE_ACTIVATE_UNCERTAIN_NO_REPLAY"),
            "HOST_VM_IMAGE_ACTIVATE_UNCERTAIN_NO_REPLAY"
        );
        assert_eq!(
            native_vm_replace_error_class("password=secret"),
            "HOST_NATIVE_VM_REPLACE_UNCERTAIN_NO_REPLAY"
        );
    }

    #[test]
    fn trust_snapshot_is_one_bounded_canonical_protobuf() {
        let mut snapshot = FleetNativeTrustSnapshot {
            schema_version: 1,
            machine_id: "vm-1".to_owned(),
            registry_pb: vec![1],
            release_set_pb: vec![2],
            application_bundle_pb: vec![3],
            selected_spec_bytes: vec![4],
            pinned_worker_public_key: vec![5; 32],
        };
        let bytes = snapshot.encode_to_vec();
        assert_eq!(
            decode_native_trust_snapshot(&bytes).unwrap().machine_id,
            "vm-1"
        );
        snapshot.pinned_worker_public_key = vec![0; 32];
        assert!(decode_native_trust_snapshot(&snapshot.encode_to_vec()).is_err());
        snapshot.pinned_worker_public_key = vec![5; 32];
        snapshot.machine_id = "../other-machine".to_owned();
        assert!(decode_native_trust_snapshot(&snapshot.encode_to_vec()).is_err());
        assert!(decode_native_trust_snapshot(&vec![0; 9 * 1024 * 1024 + 1]).is_err());
    }

    #[test]
    fn actual_vm_specs_are_accepted_but_traversal_is_not() {
        assert!(git_owned_host_spec_path(
            "infra/production/production.textproto"
        ));
        assert!(git_owned_host_spec_path(
            "infra/application/disposable-acceptance.json"
        ));
        assert!(!git_owned_host_spec_path("infra/../secrets.env"));
        assert!(!git_owned_host_spec_path("/etc/sudoers"));
        assert!(!git_owned_host_spec_path("infra/prod\\secret"));
        assert!(!git_owned_host_spec_path("infra/"));
    }
}
