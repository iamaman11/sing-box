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
    WindowsRuntime,
};

pub const MIN_RELEASE_SET_SCHEMA_VERSION: u32 = 1;
pub const RELEASE_SET_SCHEMA_VERSION: u32 = 5;
pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const DB_SCHEMA_VERSION: u32 = 1;

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
        4 | 5 => {
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
        clear_windows_reuse_identity(&mut release);
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_missing_v2_controller_hash() {
        let mut release = valid_release();
        release.schema_version = 2;
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
        clear_windows_reuse_identity(&mut release);
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_accepts_legacy_v3_without_runtime_reuse_identity() {
        let mut release = valid_release();
        release.schema_version = 3;
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
        clear_windows_reuse_identity(&mut release);
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_missing_v4_runtime_reuse_identity() {
        let mut release = valid_release();
        release.schema_version = 4;
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
        clear_windows_reuse_identity(&mut release);
        let bytes = encode_release_set(&release).unwrap();
        assert_eq!(decode_release_set(&bytes).unwrap(), release);
    }

    #[test]
    fn release_set_rejects_missing_v5_windows_reuse_identity() {
        let mut release = valid_release();
        release.windows_runtime.as_mut().unwrap().input_sha256.clear();
        assert!(validate_release_set(&release).is_err());

        let mut release = valid_release();
        release
            .windows_runtime
            .as_mut()
            .unwrap()
            .source_revision
            .clear();
        assert!(validate_release_set(&release).is_err());
    }

    #[test]
    fn release_set_rejects_missing_v3_orchestrator_hash() {
        let mut release = valid_release();
        release.schema_version = 3;
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
