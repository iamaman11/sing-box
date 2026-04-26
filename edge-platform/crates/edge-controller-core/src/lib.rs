use edge_shared_types::{DeployPhase, ErrorSubsystem, PlatformError};

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

#[cfg(test)]
mod tests {
    use super::*;
    use DeployPhase::*;

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
}
