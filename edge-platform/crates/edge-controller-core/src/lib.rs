use std::fs;
use std::path::{Path, PathBuf};

use edge_shared_types::{
    AgentState, ControllerStatus, DeployPhase, DeploymentSummary, ErrorSubsystem, FileCategory,
    FilePresence, InventoryReport, LocalSingboxState, PlatformError, ProviderObservation,
    RuntimeObservation, SelectorState,
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
            | (DeployPhase::LocalConfigSynced, DeployPhase::Completed)
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
            | (DeployPhase::Failed, DeployPhase::RollbackStarted)
            | (DeployPhase::RollbackStarted, DeployPhase::RollbackCompleted)
    )
}

const REQUIRED_REPO_FILES: &[&str] = &[
    "RUST-ULTIMATE-PLATFORM-PLAN.md",
    "win/vultr-waw/deploy-waw.ps1",
    "win/vultr-waw/verify-edge.ps1",
    "win/windows/singbox-dual-menu.ps1",
    "win/windows/sync-vultr-dual-config.ps1",
    "win/vultr-waw/stack/docker-compose.yml",
    "win/vultr-waw/stack/tunnel-edge/config.template.json",
    "edge-platform/Cargo.toml",
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
        blockers.push(format!(
            "live local-only state exists and must not be migrated blindly: {}",
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
    let local_singbox = collect_local_singbox_state(&repo_root);
    let deployment = collect_deployment_summary(&repo_root)?;
    let provider = ProviderObservation::placeholder();
    let runtime = RuntimeObservation::placeholder();
    let selector = SelectorState::placeholder();

    let mut status_notes = Vec::new();
    if !inventory.blockers.is_empty() {
        status_notes.push("migration is blocked on local-only live state review".to_owned());
    }
    if !agent_state.ready {
        status_notes.push("agent is still in bootstrap placeholder mode".to_owned());
    }
    if !local_singbox.process_running {
        status_notes.push("local sing-box process is not running in this environment".to_owned());
    }
    if !deployment.live_state_present {
        status_notes.push("live deployment state file is absent".to_owned());
    }

    Ok(ControllerStatus {
        inventory: Some(inventory),
        agent_state: Some(agent_state),
        local_singbox: Some(local_singbox),
        deployment: Some(deployment),
        provider: Some(provider),
        runtime: Some(runtime),
        selector: Some(selector),
        status_notes,
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

fn collect_local_singbox_state(repo_root: &Path) -> LocalSingboxState {
    let expected_config_path = repo_root.join(EXPECTED_LOCAL_CONFIG_PATH);
    let mut state = LocalSingboxState::placeholder(expected_config_path.display().to_string());
    if !expected_config_path.exists() {
        state
            .warnings
            .push("expected local sing-box config is missing".to_owned());
    }
    state
}

fn collect_deployment_summary(repo_root: &Path) -> Result<DeploymentSummary, PlatformError> {
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

    let parsed: CurrentEdgeState = serde_json::from_str(&raw).map_err(|err| {
        PlatformError::new(
            "current_state_parse_failed",
            "controller.status",
            format!("failed to parse {}: {err}", state_path.display()),
            false,
            ErrorSubsystem::State,
        )
    })?;

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
}

#[derive(Debug, Deserialize)]
struct CurrentTunnelState {
    domain: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::FileCategory as ProtoFileCategory;
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
            DeployPhase::Completed,
        ];

        for window in path.windows(2) {
            validate_deploy_transition(window[0], window[1]).unwrap();
        }
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

    #[test]
    fn collects_inventory_and_flags_live_state() {
        let repo_root = temp_repo_root("inventory_with_live_state");
        create_required_repo_files(&repo_root);
        create_file(&repo_root.join(CURRENT_STATE_PATH), "{}");

        let report = collect_repo_inventory(&repo_root).unwrap();
        assert!(report.rust_workspace_present);
        assert!(
            report
                .blockers
                .iter()
                .any(|line| line.contains("live local-only state exists"))
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
        assert_eq!(
            status
                .deployment
                .as_ref()
                .unwrap()
                .deployment_label
                .as_deref(),
            Some("edge-a")
        );
    }

    #[test]
    fn file_presence_uses_proto_enum_values() {
        let root = temp_repo_root("file_presence");
        let entry = file_presence(&root, "foo", FileCategory::RequiredRepoInput);
        assert_eq!(entry.category, ProtoFileCategory::RequiredRepoInput as i32);
    }

    fn create_required_repo_files(repo_root: &Path) {
        create_file(&repo_root.join("RUST-ULTIMATE-PLATFORM-PLAN.md"), "");
        create_file(&repo_root.join("win/vultr-waw/deploy-waw.ps1"), "");
        create_file(&repo_root.join("win/vultr-waw/verify-edge.ps1"), "");
        create_file(&repo_root.join("win/windows/singbox-dual-menu.ps1"), "");
        create_file(
            &repo_root.join("win/windows/sync-vultr-dual-config.ps1"),
            "",
        );
        create_file(
            &repo_root.join("win/vultr-waw/stack/docker-compose.yml"),
            "",
        );
        create_file(
            &repo_root.join("win/vultr-waw/stack/tunnel-edge/config.template.json"),
            "",
        );
        create_file(&repo_root.join("edge-platform/Cargo.toml"), "");
        create_file(&repo_root.join(EXPECTED_LOCAL_CONFIG_PATH), "");
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
