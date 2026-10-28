use clap::{Args, Parser, Subcommand};
use std::env;

#[derive(Debug, Parser)]
#[command(
    name = "edge-console",
    version,
    about = "Typed local edge operator console"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    pub fn command_name(&self) -> &'static str {
        self.command.as_ref().map(Command::name).unwrap_or("none")
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Status(EndpointArgs),
    Doctor(EndpointArgs),
    CredentialState(EndpointArgs),
    CredentialInitialProbe(InstallRootArgs),
    PrivilegedPing(InstallRootArgs),
    PrivilegedRuntimeEvidence(InstallRootArgs),
    PrivilegedDispatch(InstallRootArgs),
    // Local elevated Administrator one-shot FIRST-USE only: never a runner or
    // untrusted exchange command. The Rust owner verifies exact Git release,
    // immutable candidate, SCM privileges and durable no-replay marker.
    #[cfg(windows)]
    OfflineBootstrap(PrivilegedActivateArgs),
    // Exact same stopped-source / pending / task proof used by first-use,
    // but read-only, without a ReleaseSet install or any SCM/task mutation.
    #[cfg(windows)]
    OfflineBootstrapPreflight(InstallRootArgs),
    VerifyRuntime,
    QualityLine1,
    Secrets(EndpointArgs),
    GetSelector(EndpointArgs),
    GetUbuntuSelector(EndpointArgs),
    Trace(EndpointArgs),
    TraceUbuntu(EndpointArgs),
    GetOperation(OperationEndpointArgs),
    WatchOperation(OperationEndpointArgs),
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Status(_) => "status",
            Self::Doctor(_) => "doctor",
            Self::CredentialState(_) => "credential-state",
            Self::CredentialInitialProbe(_) => "credential-initial-probe",
            Self::PrivilegedPing(_) => "privileged-ping",
            Self::PrivilegedRuntimeEvidence(_) => "privileged-runtime-evidence",
            Self::PrivilegedDispatch(_) => "privileged-dispatch",
            #[cfg(windows)]
            Self::OfflineBootstrap(_) => "offline-bootstrap",
            #[cfg(windows)]
            Self::OfflineBootstrapPreflight(_) => "offline-bootstrap-preflight",
            Self::VerifyRuntime => "verify-runtime",
            Self::QualityLine1 => "quality-line1",
            Self::Secrets(_) => "secrets",
            Self::GetSelector(_) => "get-selector",
            Self::GetUbuntuSelector(_) => "get-ubuntu-selector",
            Self::Trace(_) => "trace",
            Self::TraceUbuntu(_) => "trace-ubuntu",
            Self::GetOperation(_) => "get-operation",
            Self::WatchOperation(_) => "watch-operation",
        }
    }
}

#[derive(Debug, Args, Default)]
pub(crate) struct EndpointArgs {
    pub endpoint: Option<String>,
}

impl EndpointArgs {
    pub fn resolve(self) -> String {
        controller_endpoint(self.endpoint)
    }
}

#[derive(Debug, Args)]
pub(crate) struct InstallRootArgs {
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct InitialCredentialAttestArgs {
    pub generation: u64,
    pub slot: String,
    pub provider_intent_sha256: String,
    pub release_set_sha256: String,
    pub run_id: u64,
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct IsolatedAcceptanceRootArgs {
    #[arg(long, default_value = r"C:\sing-box-acceptance")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct InitialLine1WitnessArgs {
    pub generation: u64,
    #[arg(long, default_value = r"C:\sing-box-acceptance")]
    pub install_root: String,
}

// The witness may only connect to the VM already independently attested by
// the GitHub VM job; it must not resolve a production hostname by default.
#[derive(Debug, Args)]
pub(crate) struct AttestedLine1WitnessArgs {
    pub generation: u64,
    #[arg(long, default_value = r"C:\sing-box-acceptance")]
    pub install_root: String,
    #[arg(long)]
    pub target_ipv4: std::net::Ipv4Addr,
    #[arg(long)]
    pub target_domain: String,
}

#[derive(Debug, Args)]
pub(crate) struct ExistingLine1WitnessArgs {
    pub generation: u64,
    /// Exact Windows B candidate digest observed by protected SYSTEM owner.
    pub windows_candidate_sha256: String,
    /// Independent Git-owned VM endpoint location, never operator default.
    #[arg(long)]
    pub target_ipv4: std::net::Ipv4Addr,
    #[arg(long)]
    pub target_domain: String,
    #[arg(long, default_value = r"C:\sing-box-acceptance")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct PrivilegedActivateArgs {
    pub accepted_revision: String,
    pub release_set_sha256: String,
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
    // An old fsynced BEGIN may remain after successful physical upgrades.
    // Superseding it is a separate explicit operator decision, never inferred
    // from its age or the presence of an unrelated newer binary.
    #[arg(long, requires = "expected_current_release_set_sha256")]
    pub retained_intent_sha256: Option<String>,
    #[arg(long, requires = "retained_intent_sha256")]
    pub expected_current_release_set_sha256: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct PrivilegedCredentialStageArgs {
    pub generation: u64,
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct PrivilegedInitialCredentialCommitArgs {
    pub generation: u64,
    pub slot: u32,
    pub intent_sha256: String,
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct PrivilegedInitialCredentialRecoverArgs {
    pub generation: u64,
    pub slot: u32,
    pub original_intent_sha256: String,
    pub recovery_intent_sha256: String,
    pub candidate_sha256: String,
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
}

/// The original GitHub BEGIN is not a COMMIT. Distinct typed arguments
/// prevent accidentally passing the commit hash to SYSTEM preparation.
#[derive(Debug, Args)]
pub(crate) struct PrivilegedExistingPrepareArgs {
    pub generation: u64,
    pub slot: u32,
    pub begin_sha256: String,
    pub windows_active_sha256: String,
    pub windows_candidate_sha256: String,
    pub vm_candidate_sha256: String,
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct PrivilegedExistingJoinArgs {
    pub generation: u64,
    pub slot: u32,
    pub intent_sha256: String,
    pub windows_active_sha256: String,
    pub windows_candidate_sha256: String,
    pub vm_candidate_sha256: String,
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialTransitionArgs {
    pub action: String,
    #[arg(long, default_value = r"C:\sing-box")]
    pub install_root: String,
}

#[derive(Debug, Args)]
pub(crate) struct NameEndpointArgs {
    pub name: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SetSecretArgs {
    pub name: String,
    pub secret_ref: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct OperationEndpointArgs {
    pub operation_id: i64,
    pub endpoint: Option<String>,
}

pub(crate) fn controller_endpoint(value: Option<String>) -> String {
    value
        .and_then(non_blank)
        .or_else(|| {
            env::var("EDGE_CONTROLLER_ENDPOINT")
                .ok()
                .and_then(non_blank)
        })
        .unwrap_or_else(|| crate::default_controller_endpoint().to_owned())
}

fn non_blank(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn readonly_console_commands_remain_parseable() {
        for command in [
            "status",
            "doctor",
            "credential-state",
            "credential-initial-probe",
            "privileged-ping",
            "privileged-runtime-evidence",
            "privileged-dispatch",
            "verify-runtime",
            "quality-line1",
            "secrets",
            "get-selector",
            "get-ubuntu-selector",
            "trace",
            "trace-ubuntu",
        ] {
            assert!(
                Cli::try_parse_from(["edge-console", command]).is_ok(),
                "{command}"
            );
        }
        assert!(Cli::try_parse_from(["edge-console", "get-operation", "42"]).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn only_exact_explicit_local_first_use_command_is_parseable() {
        assert!(matches!(
            Cli::try_parse_from([
                "edge-console",
                "offline-bootstrap-preflight",
                "--install-root",
                r"C:\sing-box",
            ])
            .unwrap()
            .command,
            Some(Command::OfflineBootstrapPreflight(_))
        ));
        let command = Cli::try_parse_from([
            "edge-console",
            "offline-bootstrap",
            "a82d4b6049c63b329d153626f0a143ae5b7e5618",
            "c16c1eec3f29c8d5e00a9969952d12c4807c798a37edcd8f79fd5fc13ef8a680",
            "--install-root",
            r"C:\sing-box",
        ])
        .unwrap();
        assert!(matches!(
            command.command,
            Some(Command::OfflineBootstrap(_))
        ));
        assert!(Cli::try_parse_from(["edge-console", "offline-bootstrap"]).is_err());
        assert!(Cli::try_parse_from([
            "edge-console", "offline-bootstrap", "a", "b", "--retained-intent-sha256", "c",
        ]).is_err());
        let recovered = Cli::try_parse_from([
            "edge-console",
            "offline-bootstrap",
            "a82d4b6049c63b329d153626f0a143ae5b7e5618",
            "c16c1eec3f29c8d5e00a9969952d12c4807c798a37edcd8f79fd5fc13ef8a680",
            "--retained-intent-sha256",
            "bf7a091a4c3b0a61ead3d3cf1388f599baeed8803c5f1edfcd0289029e53327b",
            "--expected-current-release-set-sha256",
            "08f86d8fb3619f47f2a3b2434f66bbf54b6f5358fed5eb6d99b6a5f913d93730",
        ])
        .unwrap();
        assert!(matches!(
            recovered.command,
            Some(Command::OfflineBootstrap(PrivilegedActivateArgs {
                retained_intent_sha256: Some(_),
                expected_current_release_set_sha256: Some(_),
                ..
            }))
        ));
        assert!(Cli::try_parse_from(["edge-console", "privileged-offline-activate"]).is_err());
    }

    #[test]
    fn legacy_console_mutation_ingress_is_unparseable() {
        for command in [
            "menu",
            "ensure-controller",
            "reconcile",
            "credential-initial-attest",
            "credential-initial-acceptance-bootstrap",
            "credential-initial-acceptance-stage",
            "credential-initial-line1-witness",
            "credential-existing-line1-witness",
            "smoke-runtime",
            "stage2-preflight",
            "provision-runtime-state",
            "privileged-activate",
            "privileged-reinstall-accepted",
            "privileged-rollback-previous",
            "privileged-offline-activate",
            "privileged-stage-credential",
            "credential-transition",
            "privileged-initial-credential-commit",
            "privileged-existing-join",
            "privileged-restart-controller-service",
            "privileged-start-proxy-only-controller",
            "privileged-stop-proxy-only-controller",
            "set-secret",
            "get-secret",
            "start-local",
            "start-local-visible",
            "stop-local",
            "restart-local",
            "set-selector",
            "set-ubuntu-selector",
            "powershell",
        ] {
            assert!(
                Cli::try_parse_from(["edge-console", command]).is_err(),
                "{command}"
            );
        }
    }
}
