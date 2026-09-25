pub mod application_lifecycle;
pub mod cloudflare_dns_lifecycle;
pub mod cloudflare_mesh_lifecycle;
pub mod cloudflare_zero_trust_lifecycle;
pub mod host_substrate_lifecycle;
pub mod lifecycle;
pub mod orchestration;
pub mod production;
pub mod vultr_lifecycle;
pub mod vultr_vpc_lifecycle;

use edge_state::EdgeState;
use std::fs;
use std::path::{Path, PathBuf};

use edge_shared_types::{
    AgentState, AppReadinessPhase, ControllerStatus, DeployPhase, DeploymentSummary,
    ErrorSubsystem, FileCategory, FilePresence, InventoryReport, PlatformError,
    ProviderObservation, RuntimeObservation,
};
use edge_singbox::{
    ExpectedTunnelBindings, LocalConfigObservation, TunnelBinding, inspect_local_config,
};
use serde::Deserialize;

pub fn validate_deploy_transition(from: DeployPhase, to: DeployPhase) -> Result<(), PlatformError> {
    if is_allowed_deploy_transition(from, to) {
        return Ok(());
    }

    Err(PlatformError::new(
        "invalid_deploy_phase_transition",
        from.as_str_name(),
        format!(
            "cannot transition deploy phase from {} to {}",
            from.as_str_name(),
            to.as_str_name()
        ),
        false,
        ErrorSubsystem::State,
    ))
}

pub const fn is_allowed_deploy_transition(from: DeployPhase, to: DeployPhase) -> bool {
    matches!(
        (from, to),
        (DeployPhase::Requested, DeployPhase::InstanceCreateRequested)
            | (
                DeployPhase::InstanceCreateRequested,
                DeployPhase::InstanceProvisioning
            )
            | (
                DeployPhase::InstanceProvisioning,
                DeployPhase::InstanceAddressAssigned
            )
            | (
                DeployPhase::InstanceAddressAssigned,
                DeployPhase::InstanceRuntimeReady
            )
            | (
                DeployPhase::InstanceRuntimeReady,
                DeployPhase::HostTrustInitialized
            )
            | (
                DeployPhase::HostTrustInitialized,
                DeployPhase::BundleRendered
            )
            | (DeployPhase::BundleRendered, DeployPhase::BundleUploaded)
            | (
                DeployPhase::BundleUploaded,
                DeployPhase::BaseBootstrapStarted
            )
            | (
                DeployPhase::BaseBootstrapStarted,
                DeployPhase::BaseReadyVerified
            )
            | (
                DeployPhase::BaseReadyVerified,
                DeployPhase::DnsCutoverStarted
            )
            | (
                DeployPhase::DnsCutoverStarted,
                DeployPhase::DnsCutoverVerified
            )
            | (
                DeployPhase::DnsCutoverVerified,
                DeployPhase::TunnelBootstrapStarted
            )
            | (
                DeployPhase::TunnelBootstrapStarted,
                DeployPhase::TunnelReadyVerified
            )
            | (
                DeployPhase::TunnelReadyVerified,
                DeployPhase::DeploymentPublished
            )
            | (
                DeployPhase::DeploymentPublished,
                DeployPhase::LocalConfigSynced
            )
            | (
                DeployPhase::LocalConfigSynced,
                DeployPhase::LocalRuntimeStartStarted
            )
            | (
                DeployPhase::LocalRuntimeStartStarted,
                DeployPhase::LocalRuntimeReadyVerified
            )
            | (
                DeployPhase::LocalRuntimeReadyVerified,
                DeployPhase::SelectorIntentsReconciling
            )
            | (
                DeployPhase::SelectorIntentsReconciling,
                DeployPhase::SelectorsVerified
            )
            | (
                DeployPhase::SelectorsVerified,
                DeployPhase::AppEgressVerified
            )
            | (
                DeployPhase::AppEgressVerified,
                DeployPhase::AppReadyCompleted
            )
            | (DeployPhase::LocalConfigSynced, DeployPhase::Completed)
            | (
                DeployPhase::LocalRuntimeReadyVerified,
                DeployPhase::Completed
            )
            | (DeployPhase::SelectorsVerified, DeployPhase::Completed)
            | (DeployPhase::AppEgressVerified, DeployPhase::Completed)
            | (DeployPhase::Requested, DeployPhase::Failed)
            | (DeployPhase::InstanceCreateRequested, DeployPhase::Failed)
            | (DeployPhase::InstanceProvisioning, DeployPhase::Failed)
            | (DeployPhase::InstanceAddressAssigned, DeployPhase::Failed)
            | (DeployPhase::InstanceRuntimeReady, DeployPhase::Failed)
            | (DeployPhase::HostTrustInitialized, DeployPhase::Failed)
            | (DeployPhase::BundleRendered, DeployPhase::Failed)
            | (DeployPhase::BundleUploaded, DeployPhase::Failed)
            | (DeployPhase::BaseBootstrapStarted, DeployPhase::Failed)
            | (DeployPhase::BaseReadyVerified, DeployPhase::Failed)
            | (DeployPhase::DnsCutoverStarted, DeployPhase::Failed)
            | (DeployPhase::DnsCutoverVerified, DeployPhase::Failed)
            | (DeployPhase::TunnelBootstrapStarted, DeployPhase::Failed)
            | (DeployPhase::TunnelReadyVerified, DeployPhase::Failed)
            | (DeployPhase::DeploymentPublished, DeployPhase::Failed)
            | (DeployPhase::LocalConfigSynced, DeployPhase::Failed)
            | (DeployPhase::LocalRuntimeStartStarted, DeployPhase::Failed)
            | (DeployPhase::LocalRuntimeReadyVerified, DeployPhase::Failed)
            | (DeployPhase::SelectorIntentsReconciling, DeployPhase::Failed)
            | (DeployPhase::SelectorsVerified, DeployPhase::Failed)
            | (DeployPhase::AppEgressVerified, DeployPhase::Failed)
            | (DeployPhase::Failed, DeployPhase::RollbackStarted)
            | (DeployPhase::RollbackStarted, DeployPhase::RollbackCompleted)
    )
}

const REQUIRED_REPO_FILES: &[&str] = &[
    "edge-platform/Cargo.toml",
    "edge-platform/README.md",
    "edge-platform/proto/edge_platform.proto",
    "edge-platform/crates/edge-agent/src/main.rs",
    "edge-platform/crates/edge-controller/src/main.rs",
    "edge-platform/crates/edge-console/src/main.rs",
    "edge-platform/FINALIZATION-PLAN.md",
    "win/vultr-waw/cloud-init.yaml",
    "win/vultr-waw/stack/docker-compose.yml",
    "win/vultr-waw/stack/line1-gateway/config.template.json",
    "win/vultr-waw/stack/line2-proxy/config.template.json",
    "win/windows/edge-dns-clean-vultr-dual.json",
];

const LOCAL_ONLY_FILES: &[&str] = &[
    "sing-box-wsl-setup/config.current.json",
    "win/edge-gateway/config.live.json",
    "win/edge-gateway/config.test.json",
    "win/tunnel-edge/config.live.json",
    "win/vultr-waw/current-edge.json",
    "win/windows/local-secrets.ps1",
    "win/windows/local-secrets.clixml",
    "win/windows/cache-dns-vultr-dual.db",
    "win/windows/edge-dns-clean-vm-alegria.json",
    "win/windows/edge-dns-clean-vm-alegria-explicit-proxy.json",
    "win/windows/edge-dns-clean-vm-alegria-split-dns.json",
    "win/windows/edge-dns-clean-vm-alegria-split-dns-v2.json",
    "win/windows/edge-dns-clean-vultr-dual.json",
];

const CURRENT_STATE_PATH: &str = "win/vultr-waw/current-edge.json";
const EXPECTED_LOCAL_CONFIG_PATH: &str = "win/windows/edge-dns-clean-vultr-dual.json";
const DEFAULT_STATE_DB_PATH: &str = "edge-platform/.runtime/controller-state.sqlite";
const DESKTOP_SELECTOR_GROUP: &str = "proxy-selector";
const UBUNTU_SELECTOR_GROUP: &str = "wsl-selector";

pub fn collect_repo_inventory(repo_root: &Path) -> Result<InventoryReport, PlatformError> {
    let repo_root = canonical_repo_root(repo_root)?;

    let required_repo_files = REQUIRED_REPO_FILES
        .iter()
        .map(|path| file_presence(&repo_root, path, FileCategory::RequiredRepoInput))
        .collect::<Vec<_>>();
    let local_only_files = LOCAL_ONLY_FILES
        .iter()
        .map(|path| file_presence(&repo_root, path, FileCategory::LocalOnlySensitive))
        .collect::<Vec<_>>();

    let rust_workspace_present = repo_root.join("edge-platform/Cargo.toml").is_file();

    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    let missing_required = required_repo_files
        .iter()
        .filter(|file| !file.present)
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if !missing_required.is_empty() {
        blockers.push(format!(
            "required repository inputs are missing: {}",
            missing_required.join(", ")
        ));
    }

    let live_files = local_only_files
        .iter()
        .filter(|file| file.present)
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if !live_files.is_empty() {
        warnings.push(format!(
            "live local-only state is present: {}",
            live_files.join(", ")
        ));
    }

    if !rust_workspace_present {
        warnings.push("rust workspace is not present under edge-platform/".to_owned());
    }

    if live_files.is_empty() {
        warnings.push("no local live-state files detected; inventory may be incomplete".to_owned());
    }

    Ok(InventoryReport {
        repo_root: repo_root.display().to_string(),
        rust_workspace_present,
        required_repo_files,
        local_only_files,
        blockers,
        warnings,
    })
}

pub fn collect_controller_status(repo_root: &Path) -> Result<ControllerStatus, PlatformError> {
    let repo_root = canonical_repo_root(repo_root)?;
    let inventory = collect_repo_inventory(&repo_root)?;
    let agent_state = AgentState::bootstrap_placeholder();
    let controller_state = read_controller_state(&repo_root)?;
    let mut singbox = collect_local_singbox_state(&repo_root, controller_state.as_ref());
    let deployment = collect_deployment_summary(&repo_root, controller_state.as_ref())?;
    let provider = ProviderObservation::placeholder();
    let runtime = RuntimeObservation::placeholder();
    apply_selector_intents(&repo_root, &mut singbox);

    let mut status_notes = Vec::new();
    if !inventory.blockers.is_empty() {
        status_notes.push("required repository inputs are incomplete".to_owned());
    }
    if !deployment.live_state_present {
        status_notes
            .push("active deployment is absent in authoritative controller state".to_owned());
    }
    if singbox.selector.degraded {
        status_notes.push("local selector config requires review".to_owned());
    }
    if singbox.ubuntu_selector.degraded || !singbox.ubuntu_proxy.available {
        status_notes.push("ubuntu WSL proxy path requires review".to_owned());
    }

    Ok(ControllerStatus {
        inventory: Some(inventory),
        agent_state: Some(agent_state),
        local_singbox: Some(singbox.local_singbox),
        deployment: Some(deployment),
        provider: Some(provider),
        runtime: Some(runtime),
        selector: Some(singbox.selector),
        ubuntu_selector: Some(singbox.ubuntu_selector),
        ubuntu_proxy: Some(singbox.ubuntu_proxy),
        status_notes,
        app_readiness_phase: controller_state
            .as_ref()
            .map(|state| state.app_readiness_phase as i32)
            .unwrap_or(AppReadinessPhase::DeploymentAbsent as i32),
    })
}

fn canonical_repo_root(repo_root: &Path) -> Result<PathBuf, PlatformError> {
    repo_root.canonicalize().map_err(|err| {
        PlatformError::new(
            "repo_root_unavailable",
            "inventory.repo_root",
            format!(
                "failed to canonicalize repo root {}: {err}",
                repo_root.display()
            ),
            false,
            ErrorSubsystem::State,
        )
    })
}

fn collect_local_singbox_state(
    repo_root: &Path,
    controller_state: Option<&edge_state::StoredControllerState>,
) -> LocalConfigObservation {
    let expected_config_path = repo_root.join(EXPECTED_LOCAL_CONFIG_PATH);
    let expected_bindings = read_expected_tunnel_bindings(repo_root, controller_state);
    inspect_local_config(&expected_config_path, expected_bindings.as_ref())
}

fn collect_deployment_summary(
    repo_root: &Path,
    controller_state: Option<&edge_state::StoredControllerState>,
) -> Result<DeploymentSummary, PlatformError> {
    if let Some(state) = controller_state {
        let parsed = state
            .active_deployment_state_json
            .as_deref()
            .map(|raw| {
                parse_current_edge_state(raw, "controller_state.active_deployment_state_json")
            })
            .transpose()?;
        let live_state_present = state.active_instance_id.is_some()
            || state.active_server_ip.is_some()
            || state.active_deployment_label.is_some()
            || parsed.is_some();
        if live_state_present {
            return Ok(DeploymentSummary {
                live_state_present: true,
                source_state_path: Some(
                    repo_root.join(DEFAULT_STATE_DB_PATH).display().to_string(),
                ),
                deployment_label: state
                    .active_deployment_label
                    .clone()
                    .or_else(|| parsed.as_ref().and_then(|value| value.label.clone())),
                instance_id: state
                    .active_instance_id
                    .clone()
                    .or_else(|| parsed.as_ref().and_then(|value| value.instance_id.clone())),
                server_ip: state
                    .active_server_ip
                    .clone()
                    .or_else(|| parsed.as_ref().and_then(|value| value.ip.clone())),
                tunnel_domain: state.active_tunnel_domain.clone().or_else(|| {
                    parsed
                        .as_ref()
                        .and_then(|value| value.tunnel.as_ref())
                        .and_then(|tunnel| tunnel.domain.clone())
                        .filter(|value| !value.is_empty())
                }),
            });
        }
        return Ok(DeploymentSummary::missing());
    }

    let state_path = repo_root.join(CURRENT_STATE_PATH);
    if !state_path.exists() {
        return Ok(DeploymentSummary::missing());
    }

    let raw = fs::read_to_string(&state_path).map_err(|err| {
        PlatformError::new(
            "current_state_read_failed",
            "controller.status",
            format!("failed to read {}: {err}", state_path.display()),
            true,
            ErrorSubsystem::State,
        )
    })?;

    let parsed = parse_current_edge_state(&raw, &state_path.display().to_string())?;

    Ok(DeploymentSummary {
        live_state_present: true,
        source_state_path: Some(state_path.display().to_string()),
        deployment_label: parsed.label,
        instance_id: parsed.instance_id,
        server_ip: parsed.ip,
        tunnel_domain: parsed
            .tunnel
            .and_then(|tunnel| tunnel.domain)
            .filter(|value| !value.is_empty()),
    })
}

fn read_controller_state(
    repo_root: &Path,
) -> Result<Option<edge_state::StoredControllerState>, PlatformError> {
    let db_path = repo_root.join(DEFAULT_STATE_DB_PATH);
    if !db_path.is_file() {
        return Ok(None);
    }
    let state = EdgeState::open_or_create(&db_path).map_err(|err| {
        PlatformError::new(
            "controller_state_open_failed",
            "controller.status",
            format!("failed to open {}: {err}", db_path.display()),
            true,
            ErrorSubsystem::State,
        )
    })?;
    state.get_controller_state().map_err(|err| {
        PlatformError::new(
            "controller_state_read_failed",
            "controller.status",
            format!("failed to read controller state: {err}"),
            true,
            ErrorSubsystem::State,
        )
    })
}

fn apply_selector_intents(repo_root: &Path, singbox: &mut LocalConfigObservation) {
    let db_path = repo_root.join(DEFAULT_STATE_DB_PATH);
    let Ok(state) = EdgeState::open_or_create(&db_path) else {
        return;
    };
    if let Ok(Some(intent)) = state.get_selector_intent(DESKTOP_SELECTOR_GROUP) {
        singbox.selector.desired_main_route = Some(intent.desired_route);
    }
    if let Ok(Some(intent)) = state.get_selector_intent(UBUNTU_SELECTOR_GROUP) {
        singbox.ubuntu_selector.desired_main_route = Some(intent.desired_route);
    }
}

fn parse_current_edge_state(raw: &str, source: &str) -> Result<CurrentEdgeState, PlatformError> {
    serde_json::from_str(raw).map_err(|err| {
        PlatformError::new(
            "current_state_parse_failed",
            "controller.status",
            format!("failed to parse {source}: {err}"),
            false,
            ErrorSubsystem::State,
        )
    })
}

fn file_presence(repo_root: &Path, path: &str, category: FileCategory) -> FilePresence {
    FilePresence {
        path: path.to_owned(),
        present: repo_root.join(path).exists(),
        category: category as i32,
    }
}

#[derive(Debug, Deserialize)]
struct CurrentEdgeState {
    label: Option<String>,
    instance_id: Option<String>,
    ip: Option<String>,
    tunnel: Option<CurrentTunnelState>,
    tunnel_warp: Option<CurrentWarpTunnelState>,
}

#[derive(Debug, Deserialize)]
struct CurrentTunnelState {
    domain: Option<String>,
    hy2_port: Option<u32>,
    hy2_password: Option<String>,
    vless_port: Option<u32>,
    vless_uuid: Option<String>,
    reality_public_key: Option<String>,
    reality_short_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CurrentWarpTunnelState {
    domain: Option<String>,
    hy2_port: Option<u32>,
    hy2_password: Option<String>,
    vless_port: Option<u32>,
    vless_uuid: Option<String>,
    reality_public_key: Option<String>,
    reality_short_id: Option<String>,
}

fn read_expected_tunnel_bindings(
    repo_root: &Path,
    controller_state: Option<&edge_state::StoredControllerState>,
) -> Option<ExpectedTunnelBindings> {
    let parsed = match controller_state {
        Some(value) => value
            .active_deployment_state_json
            .as_deref()
            .and_then(|raw| {
                parse_current_edge_state(raw, "controller_state.active_deployment_state_json").ok()
            }),
        None => {
            let state_path = repo_root.join(CURRENT_STATE_PATH);
            let raw = fs::read_to_string(state_path).ok()?;
            parse_current_edge_state(&raw, CURRENT_STATE_PATH).ok()
        }
    }?;

    let direct = parsed.tunnel.and_then(tunnel_binding_from_state)?;
    let warp = parsed
        .tunnel_warp
        .and_then(warp_tunnel_binding_from_state)?;
    Some(ExpectedTunnelBindings { direct, warp })
}

fn tunnel_binding_from_state(tunnel: CurrentTunnelState) -> Option<TunnelBinding> {
    Some(TunnelBinding {
        domain: tunnel.domain?,
        hy2_port: tunnel.hy2_port?,
        hy2_password: tunnel.hy2_password?,
        vless_port: tunnel.vless_port?,
        vless_uuid: tunnel.vless_uuid?,
        reality_public_key: tunnel.reality_public_key?,
        reality_short_id: tunnel.reality_short_id?,
    })
}

fn warp_tunnel_binding_from_state(tunnel: CurrentWarpTunnelState) -> Option<TunnelBinding> {
    Some(TunnelBinding {
        domain: tunnel.domain?,
        hy2_port: tunnel.hy2_port?,
        hy2_password: tunnel.hy2_password?,
        vless_port: tunnel.vless_port?,
        vless_uuid: tunnel.vless_uuid?,
        reality_public_key: tunnel.reality_public_key?,
        reality_short_id: tunnel.reality_short_id?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::FileCategory as ProtoFileCategory;
    use proptest::prelude::*;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn accepts_linear_deploy_path() {
        let path = [
            DeployPhase::Requested,
            DeployPhase::InstanceCreateRequested,
            DeployPhase::InstanceProvisioning,
            DeployPhase::InstanceAddressAssigned,
            DeployPhase::InstanceRuntimeReady,
            DeployPhase::HostTrustInitialized,
            DeployPhase::BundleRendered,
            DeployPhase::BundleUploaded,
            DeployPhase::BaseBootstrapStarted,
            DeployPhase::BaseReadyVerified,
            DeployPhase::DnsCutoverStarted,
            DeployPhase::DnsCutoverVerified,
            DeployPhase::TunnelBootstrapStarted,
            DeployPhase::TunnelReadyVerified,
            DeployPhase::DeploymentPublished,
            DeployPhase::LocalConfigSynced,
            DeployPhase::LocalRuntimeStartStarted,
            DeployPhase::LocalRuntimeReadyVerified,
            DeployPhase::SelectorIntentsReconciling,
            DeployPhase::SelectorsVerified,
            DeployPhase::AppEgressVerified,
            DeployPhase::AppReadyCompleted,
        ];

        for window in path.windows(2) {
            validate_deploy_transition(window[0], window[1]).unwrap();
        }
    }

    #[test]
    fn accepts_degraded_runtime_completion_paths() {
        validate_deploy_transition(
            DeployPhase::LocalRuntimeReadyVerified,
            DeployPhase::Completed,
        )
        .unwrap();
        validate_deploy_transition(DeployPhase::SelectorsVerified, DeployPhase::Completed).unwrap();
        validate_deploy_transition(DeployPhase::AppEgressVerified, DeployPhase::Completed).unwrap();
    }

    #[test]
    fn rejects_skipped_phase() {
        let err =
            validate_deploy_transition(DeployPhase::Requested, DeployPhase::InstanceProvisioning)
                .unwrap_err();
        assert_eq!(err.code, "invalid_deploy_phase_transition");
        assert!(!err.retryable);
    }

    #[test]
    fn accepts_failure_and_rollback_path() {
        validate_deploy_transition(DeployPhase::BundleUploaded, DeployPhase::Failed).unwrap();
        validate_deploy_transition(DeployPhase::Failed, DeployPhase::RollbackStarted).unwrap();
        validate_deploy_transition(DeployPhase::RollbackStarted, DeployPhase::RollbackCompleted)
            .unwrap();
    }

    #[test]
    fn rejects_transition_after_completed() {
        assert!(validate_deploy_transition(DeployPhase::Completed, DeployPhase::Failed).is_err());
    }

    proptest! {
        #[test]
        fn transition_validator_matches_allowlist(from in 0i32..=26, to in 0i32..=26) {
            let Ok(from) = DeployPhase::try_from(from) else {
                return Ok(());
            };
            let Ok(to) = DeployPhase::try_from(to) else {
                return Ok(());
            };
            prop_assert_eq!(
                validate_deploy_transition(from, to).is_ok(),
                is_allowed_deploy_transition(from, to)
            );
        }
    }

    #[test]
    fn collects_inventory_and_flags_live_state() {
        let repo_root = temp_repo_root("inventory_with_live_state");
        create_required_repo_files(&repo_root);
        create_file(&repo_root.join(CURRENT_STATE_PATH), "{}");

        let report = collect_repo_inventory(&repo_root).unwrap();
        assert!(report.rust_workspace_present);
        assert!(
            report
                .warnings
                .iter()
                .any(|line| line.contains("live local-only state is present"))
        );
    }

    #[test]
    fn collects_inventory_and_flags_missing_repo_files() {
        let repo_root = temp_repo_root("inventory_missing_required");
        create_file(&repo_root.join("edge-platform/Cargo.toml"), "");

        let report = collect_repo_inventory(&repo_root).unwrap();
        assert!(
            report
                .blockers
                .iter()
                .any(|line| line.contains("required repository inputs are missing"))
        );
    }

    #[test]
    fn collects_controller_status() {
        let repo_root = temp_repo_root("controller_status");
        create_required_repo_files(&repo_root);
        create_file(
            &repo_root.join(CURRENT_STATE_PATH),
            r#"{"label":"edge-a","instance_id":"id-1","ip":"1.2.3.4","tunnel":{"domain":"edge.example.com"}}"#,
        );

        let status = collect_controller_status(&repo_root).unwrap();
        assert!(!status.status_notes.is_empty());
        assert!(!status.agent_state.as_ref().unwrap().ready);
        assert!(status.local_singbox.as_ref().unwrap().managed_config);
        assert_eq!(
            status.local_singbox.as_ref().unwrap().clash_api_port,
            Some(9090)
        );
        assert_eq!(
            status
                .deployment
                .as_ref()
                .unwrap()
                .deployment_label
                .as_deref(),
            Some("edge-a")
        );
        assert_eq!(
            status
                .selector
                .as_ref()
                .unwrap()
                .desired_main_route
                .as_deref(),
            Some("auto-direct-tunnel")
        );
    }

    #[test]
    fn collects_controller_status_from_authoritative_controller_snapshot() {
        let repo_root = temp_repo_root("controller_status_controller_snapshot");
        create_required_repo_files(&repo_root);
        let db_path = repo_root.join(DEFAULT_STATE_DB_PATH);
        let state = edge_state::EdgeState::open_or_create(&db_path).unwrap();
        state
            .upsert_controller_state(edge_state::NewControllerState {
                active_deployment_label: Some("edge-authoritative"),
                active_instance_id: Some("instance-auth"),
                active_server_ip: Some("203.0.113.10"),
                active_tunnel_domain: Some("edge.example.com"),
                active_deployment_state_json: Some(
                    r#"{
  "label":"edge-authoritative",
  "instance_id":"instance-auth",
  "ip":"203.0.113.10",
  "tunnel":{
    "domain":"edge.example.com",
    "hy2_port":8443,
    "hy2_password":"direct-password",
    "vless_port":443,
    "vless_uuid":"direct-uuid",
    "reality_public_key":"direct-public-key",
    "reality_short_id":"direct-short-id"
  },
  "tunnel_warp":{
    "domain":"edge.example.com",
    "hy2_port":9444,
    "hy2_password":"warp-password",
    "vless_port":5443,
    "vless_uuid":"warp-uuid",
    "reality_public_key":"warp-public-key",
    "reality_short_id":"warp-short-id"
  }
}"#,
                ),
                deploy_phase: DeployPhase::DeploymentPublished,
                app_readiness_phase: AppReadinessPhase::AppReady,
                last_error_code: None,
                last_error_message: None,
            })
            .unwrap();

        let status = collect_controller_status(&repo_root).unwrap();
        assert_eq!(
            status
                .deployment
                .as_ref()
                .unwrap()
                .deployment_label
                .as_deref(),
            Some("edge-authoritative")
        );
        assert!(
            !status
                .local_singbox
                .as_ref()
                .unwrap()
                .warnings
                .iter()
                .any(|warning| {
                    warning.contains("does not match expected direct tunnel parameters")
                })
        );
    }

    #[test]
    fn file_presence_uses_proto_enum_values() {
        let root = temp_repo_root("file_presence");
        let entry = file_presence(&root, "foo", FileCategory::RequiredRepoInput);
        assert_eq!(entry.category, ProtoFileCategory::RequiredRepoInput as i32);
    }

    fn create_required_repo_files(repo_root: &Path) {
        create_file(&repo_root.join("edge-platform/README.md"), "");
        create_file(
            &repo_root.join("edge-platform/proto/edge_platform.proto"),
            "",
        );
        create_file(
            &repo_root.join("edge-platform/crates/edge-agent/src/main.rs"),
            "",
        );
        create_file(
            &repo_root.join("edge-platform/crates/edge-controller/src/main.rs"),
            "",
        );
        create_file(
            &repo_root.join("edge-platform/crates/edge-console/src/main.rs"),
            "",
        );
        create_file(&repo_root.join("edge-platform/FINALIZATION-PLAN.md"), "");
        create_file(
            &repo_root.join("win/vultr-waw/stack/docker-compose.yml"),
            "",
        );
        create_file(&repo_root.join("win/vultr-waw/cloud-init.yaml"), "");
        create_file(
            &repo_root.join("win/vultr-waw/stack/line1-gateway/config.template.json"),
            "",
        );
        create_file(
            &repo_root.join("win/vultr-waw/stack/line2-proxy/config.template.json"),
            "",
        );
        create_file(&repo_root.join("edge-platform/Cargo.toml"), "");
        create_file(
            &repo_root.join(EXPECTED_LOCAL_CONFIG_PATH),
            r#"{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090"
    }
  },
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy-selector",
      "outbounds": [
        "auto-direct-tunnel",
        "auto-warp-tunnel",
        "hysteria2-direct",
        "vless-reality-direct",
        "hysteria2-warp",
        "vless-reality-warp"
      ],
      "default": "auto-direct-tunnel"
    },
    { "type": "urltest", "tag": "auto-direct-tunnel" },
    { "type": "urltest", "tag": "auto-warp-tunnel" },
    { "type": "hysteria2", "tag": "hysteria2-direct" },
    { "type": "vless", "tag": "vless-reality-direct" },
    { "type": "hysteria2", "tag": "hysteria2-warp" },
    { "type": "vless", "tag": "vless-reality-warp" }
  ]
}"#,
        );
    }

    fn temp_repo_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("edge-platform-{label}-{unique}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn create_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }
}
