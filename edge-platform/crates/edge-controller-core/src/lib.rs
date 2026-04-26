use std::path::Path;

use edge_shared_types::{
    AgentState, ControllerStatus, DeployPhase, ErrorSubsystem, FileCategory, FilePresence,
    InventoryReport, PlatformError,
};

pub fn validate_deploy_transition(from: DeployPhase, to: DeployPhase) -> Result<(), PlatformError> {
    if is_allowed_deploy_transition(from, to) {
        return Ok(());
    }

    Err(PlatformError::new(
        "invalid_deploy_phase_transition",
        from.as_str(),
        format!("cannot transition deploy phase from {from} to {to}"),
        false,
        ErrorSubsystem::State,
    ))
}

pub const fn is_allowed_deploy_transition(from: DeployPhase, to: DeployPhase) -> bool {
    use DeployPhase::*;

    matches!(
        (from, to),
        (Requested, InstanceCreateRequested)
            | (InstanceCreateRequested, InstanceProvisioning)
            | (InstanceProvisioning, InstanceAddressAssigned)
            | (InstanceAddressAssigned, InstanceRuntimeReady)
            | (InstanceRuntimeReady, HostTrustInitialized)
            | (HostTrustInitialized, BundleRendered)
            | (BundleRendered, BundleUploaded)
            | (BundleUploaded, BaseBootstrapStarted)
            | (BaseBootstrapStarted, BaseReadyVerified)
            | (BaseReadyVerified, DnsCutoverStarted)
            | (DnsCutoverStarted, DnsCutoverVerified)
            | (DnsCutoverVerified, TunnelBootstrapStarted)
            | (TunnelBootstrapStarted, TunnelReadyVerified)
            | (TunnelReadyVerified, DeploymentPublished)
            | (DeploymentPublished, LocalConfigSynced)
            | (LocalConfigSynced, Completed)
            | (Requested, Failed)
            | (InstanceCreateRequested, Failed)
            | (InstanceProvisioning, Failed)
            | (InstanceAddressAssigned, Failed)
            | (InstanceRuntimeReady, Failed)
            | (HostTrustInitialized, Failed)
            | (BundleRendered, Failed)
            | (BundleUploaded, Failed)
            | (BaseBootstrapStarted, Failed)
            | (BaseReadyVerified, Failed)
            | (DnsCutoverStarted, Failed)
            | (DnsCutoverVerified, Failed)
            | (TunnelBootstrapStarted, Failed)
            | (TunnelReadyVerified, Failed)
            | (DeploymentPublished, Failed)
            | (LocalConfigSynced, Failed)
            | (Failed, RollbackStarted)
            | (RollbackStarted, RollbackCompleted)
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

pub fn collect_repo_inventory(repo_root: &Path) -> Result<InventoryReport, PlatformError> {
    let repo_root = repo_root.canonicalize().map_err(|err| {
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
    })?;

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
    let inventory = collect_repo_inventory(repo_root)?;
    let agent_state = AgentState::bootstrap_placeholder();
    let mut status_notes = Vec::new();

    if !inventory.blockers.is_empty() {
        status_notes.push("migration is blocked on local-only live state review".to_owned());
    }

    if !agent_state.ready {
        status_notes.push("agent is still in bootstrap placeholder mode".to_owned());
    }

    Ok(ControllerStatus {
        inventory,
        agent_state,
        status_notes,
    })
}

fn file_presence(repo_root: &Path, path: &str, category: FileCategory) -> FilePresence {
    FilePresence {
        path: path.to_owned(),
        present: repo_root.join(path).exists(),
        category,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use DeployPhase::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn accepts_linear_deploy_path() {
        let path = [
            Requested,
            InstanceCreateRequested,
            InstanceProvisioning,
            InstanceAddressAssigned,
            InstanceRuntimeReady,
            HostTrustInitialized,
            BundleRendered,
            BundleUploaded,
            BaseBootstrapStarted,
            BaseReadyVerified,
            DnsCutoverStarted,
            DnsCutoverVerified,
            TunnelBootstrapStarted,
            TunnelReadyVerified,
            DeploymentPublished,
            LocalConfigSynced,
            Completed,
        ];

        for window in path.windows(2) {
            validate_deploy_transition(window[0], window[1]).unwrap();
        }
    }

    #[test]
    fn rejects_skipped_phase() {
        let err = validate_deploy_transition(Requested, InstanceProvisioning).unwrap_err();
        assert_eq!(err.code, "invalid_deploy_phase_transition");
        assert!(!err.retryable);
    }

    #[test]
    fn accepts_failure_and_rollback_path() {
        validate_deploy_transition(BundleUploaded, Failed).unwrap();
        validate_deploy_transition(Failed, RollbackStarted).unwrap();
        validate_deploy_transition(RollbackStarted, RollbackCompleted).unwrap();
    }

    #[test]
    fn rejects_transition_after_completed() {
        assert!(validate_deploy_transition(Completed, Failed).is_err());
    }

    #[test]
    fn collects_inventory_and_flags_live_state() {
        let repo_root = temp_repo_root("inventory_with_live_state");
        create_file(&repo_root.join("RUST-ULTIMATE-PLATFORM-PLAN.md"));
        create_file(&repo_root.join("win/vultr-waw/deploy-waw.ps1"));
        create_file(&repo_root.join("win/vultr-waw/verify-edge.ps1"));
        create_file(&repo_root.join("win/windows/singbox-dual-menu.ps1"));
        create_file(&repo_root.join("win/windows/sync-vultr-dual-config.ps1"));
        create_file(&repo_root.join("win/vultr-waw/stack/docker-compose.yml"));
        create_file(&repo_root.join("win/vultr-waw/stack/tunnel-edge/config.template.json"));
        create_file(&repo_root.join("edge-platform/Cargo.toml"));
        create_file(&repo_root.join("win/vultr-waw/current-edge.json"));

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
        create_file(&repo_root.join("edge-platform/Cargo.toml"));

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
        create_file(&repo_root.join("RUST-ULTIMATE-PLATFORM-PLAN.md"));
        create_file(&repo_root.join("win/vultr-waw/deploy-waw.ps1"));
        create_file(&repo_root.join("win/vultr-waw/verify-edge.ps1"));
        create_file(&repo_root.join("win/windows/singbox-dual-menu.ps1"));
        create_file(&repo_root.join("win/windows/sync-vultr-dual-config.ps1"));
        create_file(&repo_root.join("win/vultr-waw/stack/docker-compose.yml"));
        create_file(&repo_root.join("win/vultr-waw/stack/tunnel-edge/config.template.json"));
        create_file(&repo_root.join("edge-platform/Cargo.toml"));

        let status = collect_controller_status(&repo_root).unwrap();
        assert!(!status.status_notes.is_empty());
        assert!(!status.agent_state.ready);
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

    fn create_file(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, []).unwrap();
    }
}
