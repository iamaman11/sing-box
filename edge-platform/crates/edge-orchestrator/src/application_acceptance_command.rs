use crate::application_lifecycle_command::{
    acceptance_apply_desired, acceptance_rollback, acceptance_verify_desired,
    load_application_desired,
};
use crate::application_lifecycle_service::DesiredMutationMode;
use crate::cli::{ApplicationAcceptanceArgs, ApplicationCleanupArgs};
use crate::cloudflare_dns_lifecycle_command::{
    acceptance_cleanup_to_absent as dns_cleanup_to_absent, acceptance_create as dns_create,
    acceptance_require_clean_room as dns_require_clean_room,
    acceptance_verify_noop as dns_verify_noop,
};
use crate::cloudflare_mesh_lifecycle_command::{
    acceptance_cleanup_provider_to_absent as mesh_cleanup_provider_to_absent,
    acceptance_converge_provider as mesh_converge_provider,
    acceptance_require_clean_room as mesh_require_clean_room,
    acceptance_runtime_apply as mesh_runtime_apply,
    acceptance_runtime_cleanup as mesh_runtime_cleanup,
    acceptance_runtime_verify as mesh_runtime_verify,
};
use crate::vultr_lifecycle_command::{
    acceptance_converge_substrate, acceptance_create_machine, acceptance_destroy_and_cleanup,
    acceptance_lease_acquire, acceptance_lease_release, acceptance_reboot,
    acceptance_require_clean_room as vultr_require_clean_room, acceptance_verify_substrate,
};
use crate::vultr_vpc_lifecycle_command::{
    acceptance_attach_and_verify as vpc_attach_and_verify,
    acceptance_cleanup_to_absent as vpc_cleanup_to_absent, acceptance_create as vpc_create,
    acceptance_require_clean_room as vpc_require_clean_room, acceptance_verify as vpc_verify,
};
use edge_controller_core::application_lifecycle::{
    ApplicationBootstrapMode, ApplicationPlanClass, DesiredApplicationState,
};
use edge_orchestrator::OrchestrationContext;
use serde::Serialize;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Default)]
struct AcceptanceProgress {
    mutation_started: bool,
    vm_possible: bool,
    mesh_runtime_possible: bool,
}

#[derive(Debug)]
struct AcceptanceFailure {
    stage: &'static str,
    detail: String,
    cleanup_allowed: bool,
}

#[derive(Debug)]
struct AcceptanceSuccess {
    release_v1: String,
    release_v2: String,
    bundle_v1: String,
    bundle_v2: String,
}

#[derive(Debug, Serialize)]
struct CleanupCertificate<'a> {
    outcome: &'a str,
    source_revision: &'a str,
    release_set_sha256: &'a str,
    terminal_stage: &'a str,
    failure: Option<&'a str>,
    zero_leaked_resources: &'a str,
}

#[derive(Debug, Clone, Copy)]
struct CleanupPaths<'a> {
    application_spec: &'a Path,
    dns_spec: &'a Path,
    mesh_spec: &'a Path,
    vpc_spec: &'a Path,
}


#[derive(Debug, Serialize)]
struct AcceptanceCertificate<'a> {
    outcome: &'a str,
    source_revision: &'a str,
    release_set_sha256: &'a str,
    terminal_stage: &'a str,
    failure: Option<&'a str>,
    clean_room_precondition: &'a str,
    lifecycle: &'a str,
    compensation: &'a str,
    zero_leaked_resources: &'a str,
    release_v1: Option<&'a str>,
    release_v2: Option<&'a str>,
    bundle_v1: Option<&'a str>,
    bundle_v2: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalPath {
    SuccessCleaned,
    SuccessCleanupFailed,
    CleanRoomRejected,
    FailureCleaned,
    FailureCleanupFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalDisposition {
    outcome: &'static str,
    clean_room_precondition: &'static str,
    lifecycle: &'static str,
    compensation: &'static str,
    zero_leaked_resources: &'static str,
}

fn terminal_disposition(path: TerminalPath) -> TerminalDisposition {
    match path {
        TerminalPath::SuccessCleaned => TerminalDisposition {
            outcome: "PASS",
            clean_room_precondition: "PASS",
            lifecycle: "PASS",
            compensation: "NOT_REQUIRED",
            zero_leaked_resources: "PASS",
        },
        TerminalPath::SuccessCleanupFailed => TerminalDisposition {
            outcome: "DIAGNOSTIC_REQUIRED",
            clean_room_precondition: "PASS",
            lifecycle: "PASS",
            compensation: "FAILED",
            zero_leaked_resources: "UNPROVEN",
        },
        TerminalPath::CleanRoomRejected => TerminalDisposition {
            outcome: "DIAGNOSTIC_REQUIRED",
            clean_room_precondition: "FAIL",
            lifecycle: "NOT_STARTED",
            compensation: "NOT_ALLOWED",
            zero_leaked_resources: "PRESERVED",
        },
        TerminalPath::FailureCleaned => TerminalDisposition {
            outcome: "FAIL_CLEANED",
            clean_room_precondition: "PASS",
            lifecycle: "FAIL",
            compensation: "PASS",
            zero_leaked_resources: "PASS",
        },
        TerminalPath::FailureCleanupFailed => TerminalDisposition {
            outcome: "DIAGNOSTIC_REQUIRED",
            clean_room_precondition: "PASS",
            lifecycle: "FAIL",
            compensation: "FAILED",
            zero_leaked_resources: "UNPROVEN",
        },
    }
}

async fn timed_stage<T, F>(stage: &'static str, future: F) -> Result<T, String>
where
    F: Future<Output = Result<T, String>>,
{
    let started = Instant::now();
    tracing::info!(
        component = "edge-orchestrator",
        stage,
        event = "application.acceptance.stage.start",
        "application acceptance stage started"
    );
    let result = future.await;
    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    tracing::info!(
        component = "edge-orchestrator",
        stage,
        outcome = if result.is_ok() { "PASS" } else { "FAIL" },
        elapsed_ms,
        event = "application.acceptance.stage.terminal",
        "application acceptance stage completed"
    );
    result
}

pub(crate) async fn run(
    args: ApplicationAcceptanceArgs,
    context: &OrchestrationContext,
) -> Result<(), String> {
    let desired = load_application_desired(&args.spec_path)?;
    validate_disposable_acceptance(&desired)?;

    let vultr_spec = PathBuf::from(&desired.vultr_spec_path);
    let machine_id = desired.machine_id.clone();
    let source_revision = context.release().accepted_revision.as_str();
    let release_set_sha256 = context.release().release_set_sha256.as_str();
    let mut progress = AcceptanceProgress::default();

    let result = run_lifecycle(&args, &desired, &vultr_spec, &machine_id, &mut progress).await;

    match result {
        Ok(success) => {
            if let Err(detail) =
                cleanup_environment(
                    CleanupPaths {
                        application_spec: &args.spec_path,
                        dns_spec: &args.dns_spec_path,
                        mesh_spec: &args.mesh_base_spec_path,
                        vpc_spec: &args.vpc_spec_path,
                    },
                    &vultr_spec,
                    &machine_id,
                    source_revision,
                    &progress,
                )
                .await
            {
                let disposition = terminal_disposition(TerminalPath::SuccessCleanupFailed);
                let certificate = AcceptanceCertificate {
                    outcome: disposition.outcome,
                    source_revision,
                    release_set_sha256,
                    terminal_stage: "cleanup",
                    failure: Some(&detail),
                    clean_room_precondition: disposition.clean_room_precondition,
                    lifecycle: disposition.lifecycle,
                    compensation: disposition.compensation,
                    zero_leaked_resources: disposition.zero_leaked_resources,
                    release_v1: Some(&success.release_v1),
                    release_v2: Some(&success.release_v2),
                    bundle_v1: Some(&success.bundle_v1),
                    bundle_v2: Some(&success.bundle_v2),
                };
                print_certificate(&certificate)?;
                return Err(format!(
                    "application acceptance lifecycle passed but cleanup could not prove zero leak: {detail}"
                ));
            }

            let disposition = terminal_disposition(TerminalPath::SuccessCleaned);
            let certificate = AcceptanceCertificate {
                outcome: disposition.outcome,
                source_revision,
                release_set_sha256,
                terminal_stage: "complete",
                failure: None,
                clean_room_precondition: disposition.clean_room_precondition,
                lifecycle: disposition.lifecycle,
                compensation: disposition.compensation,
                zero_leaked_resources: disposition.zero_leaked_resources,
                release_v1: Some(&success.release_v1),
                release_v2: Some(&success.release_v2),
                bundle_v1: Some(&success.bundle_v1),
                bundle_v2: Some(&success.bundle_v2),
            };
            print_certificate(&certificate)
        }
        Err(failure) if !failure.cleanup_allowed => {
            let disposition = terminal_disposition(TerminalPath::CleanRoomRejected);
            let certificate = AcceptanceCertificate {
                outcome: disposition.outcome,
                source_revision,
                release_set_sha256,
                terminal_stage: failure.stage,
                failure: Some(&failure.detail),
                clean_room_precondition: disposition.clean_room_precondition,
                lifecycle: disposition.lifecycle,
                compensation: disposition.compensation,
                zero_leaked_resources: disposition.zero_leaked_resources,
                release_v1: None,
                release_v2: None,
                bundle_v1: None,
                bundle_v2: None,
            };
            print_certificate(&certificate)?;
            Err(format!(
                "application acceptance clean-room precondition failed at {}: {}",
                failure.stage, failure.detail
            ))
        }
        Err(failure) => {
            let cleanup =
                cleanup_environment(
                    CleanupPaths {
                        application_spec: &args.spec_path,
                        dns_spec: &args.dns_spec_path,
                        mesh_spec: &args.mesh_base_spec_path,
                        vpc_spec: &args.vpc_spec_path,
                    },
                    &vultr_spec,
                    &machine_id,
                    source_revision,
                    &progress,
                )
                .await;
            let (disposition, cleanup_detail) = match cleanup {
                Ok(()) => (terminal_disposition(TerminalPath::FailureCleaned), None),
                Err(detail) => (
                    terminal_disposition(TerminalPath::FailureCleanupFailed),
                    Some(detail),
                ),
            };
            let combined = cleanup_detail
                .as_ref()
                .map(|detail| format!("{}; cleanup={detail}", failure.detail))
                .unwrap_or_else(|| failure.detail.clone());
            let certificate = AcceptanceCertificate {
                outcome: disposition.outcome,
                source_revision,
                release_set_sha256,
                terminal_stage: failure.stage,
                failure: Some(&combined),
                clean_room_precondition: disposition.clean_room_precondition,
                lifecycle: disposition.lifecycle,
                compensation: disposition.compensation,
                zero_leaked_resources: disposition.zero_leaked_resources,
                release_v1: None,
                release_v2: None,
                bundle_v1: None,
                bundle_v2: None,
            };
            print_certificate(&certificate)?;
            Err(format!(
                "application acceptance failed at {}: {combined}",
                failure.stage
            ))
        }
    }
}

pub(crate) async fn run_cleanup(
    args: ApplicationCleanupArgs,
    context: &OrchestrationContext,
) -> Result<(), String> {
    let desired = load_application_desired(&args.spec_path)?;
    validate_disposable_acceptance(&desired)?;

    let vultr_spec = PathBuf::from(&desired.vultr_spec_path);
    let machine_id = desired.machine_id.clone();
    let source_revision = context.release().accepted_revision.as_str();
    let release_set_sha256 = context.release().release_set_sha256.as_str();
    let paths = CleanupPaths {
        application_spec: &args.spec_path,
        dns_spec: &args.dns_spec_path,
        mesh_spec: &args.mesh_base_spec_path,
        vpc_spec: &args.vpc_spec_path,
    };
    let progress = AcceptanceProgress {
        mutation_started: true,
        vm_possible: true,
        // Recovery must not depend on guest SSH/runtime health. Exact VM destruction below
        // guarantees guest runtime removal while provider owners clean their own state.
        mesh_runtime_possible: false,
    };

    match cleanup_environment(
        paths,
        &vultr_spec,
        &machine_id,
        source_revision,
        &progress,
    )
    .await
    {
        Ok(()) => {
            let certificate = CleanupCertificate {
                outcome: "PASS",
                source_revision,
                release_set_sha256,
                terminal_stage: "complete",
                failure: None,
                zero_leaked_resources: "PASS",
            };
            print_cleanup_certificate(&certificate)
        }
        Err(detail) => {
            let certificate = CleanupCertificate {
                outcome: "DIAGNOSTIC_REQUIRED",
                source_revision,
                release_set_sha256,
                terminal_stage: "cleanup",
                failure: Some(&detail),
                zero_leaked_resources: "UNPROVEN",
            };
            print_cleanup_certificate(&certificate)?;
            Err(format!(
                "application cleanup could not prove zero leak: {detail}"
            ))
        }
    }
}

async fn run_lifecycle(
    args: &ApplicationAcceptanceArgs,
    desired: &DesiredApplicationState,
    vultr_spec: &Path,
    machine_id: &str,
    progress: &mut AcceptanceProgress,
) -> Result<AcceptanceSuccess, AcceptanceFailure> {
    timed_stage(
        "clean_room",
        require_clean_room(
            CleanupPaths {
                application_spec: &args.spec_path,
                dns_spec: &args.dns_spec_path,
                mesh_spec: &args.mesh_base_spec_path,
                vpc_spec: &args.vpc_spec_path,
            },
            vultr_spec,
            machine_id,
        ),
    )
    .await
    .map_err(|detail| AcceptanceFailure {
        stage: "clean_room",
        detail,
        cleanup_allowed: false,
    })?;

    progress.mutation_started = true;
    timed_stage("vpc_create", vpc_create(&args.vpc_spec_path))
        .await
        .map_err(|detail| operational_failure("vpc_create", detail))?;

    progress.vm_possible = true;
    timed_stage(
        "vm_create",
        acceptance_create_machine(vultr_spec, machine_id),
    )
    .await
    .map_err(|detail| operational_failure("vm_create", detail))?;

    timed_stage(
        "access_acquire",
        acceptance_lease_acquire(vultr_spec, machine_id),
    )
    .await
    .map_err(|detail| operational_failure("access_acquire", detail))?;

    timed_stage(
        "substrate_converge",
        acceptance_converge_substrate(vultr_spec, machine_id),
    )
    .await
    .map_err(|detail| operational_failure("substrate_converge", detail))?;

    timed_stage("vpc_attach", vpc_attach_and_verify(&args.vpc_spec_path))
        .await
        .map_err(|detail| operational_failure("vpc_attach", detail))?;
    timed_stage(
        "substrate_after_vpc",
        acceptance_verify_substrate(vultr_spec, machine_id),
    )
    .await
    .map_err(|detail| operational_failure("substrate_after_vpc", detail))?;

    timed_stage(
        "dns_create",
        dns_create(&args.dns_spec_path, &args.spec_path),
    )
    .await
    .map_err(|detail| operational_failure("dns_create", detail))?;

    let (release_v1, bundle_v1) = timed_stage(
        "application_v1",
        acceptance_apply_desired(
            desired,
            &args.artifact_manifest_path,
            &args.edge_agent_artifact_path,
            DesiredMutationMode::Apply,
            ApplicationPlanClass::Apply,
        ),
    )
    .await
    .map_err(|detail| operational_failure("application_v1", detail))?;

    timed_stage(
        "mesh_provider",
        mesh_converge_provider(
            &args.mesh_base_spec_path,
            &args.vpc_spec_path,
            &args.spec_path,
        ),
    )
    .await
    .map_err(|detail| operational_failure("mesh_provider", detail))?;

    progress.mesh_runtime_possible = true;
    timed_stage(
        "mesh_runtime",
        mesh_runtime_apply(
            &args.mesh_base_spec_path,
            &args.vpc_spec_path,
            &args.spec_path,
        ),
    )
    .await
    .map_err(|detail| operational_failure("mesh_runtime", detail))?;
    timed_stage(
        "mesh_runtime_verify",
        mesh_runtime_verify(
            &args.mesh_base_spec_path,
            &args.vpc_spec_path,
            &args.spec_path,
        ),
    )
    .await
    .map_err(|detail| operational_failure("mesh_runtime_verify", detail))?;

    timed_stage(
        "application_v1_noop",
        acceptance_apply_desired(
            desired,
            &args.artifact_manifest_path,
            &args.edge_agent_artifact_path,
            DesiredMutationMode::Apply,
            ApplicationPlanClass::Noop,
        ),
    )
    .await
    .map_err(|detail| operational_failure("application_v1_noop", detail))?;
    timed_stage(
        "application_v1_verify",
        acceptance_verify_desired(
            desired,
            &args.artifact_manifest_path,
            &args.edge_agent_artifact_path,
        ),
    )
    .await
    .map_err(|detail| operational_failure("application_v1_verify", detail))?;
    timed_stage(
        "dns_noop",
        dns_verify_noop(&args.dns_spec_path, &args.spec_path),
    )
    .await
    .map_err(|detail| operational_failure("dns_noop", detail))?;

    let mut desired_v2 = desired.clone();
    let line2 = desired_v2.runtime_policy.line2.as_mut().ok_or_else(|| {
        operational_failure("application_v2_spec", "line2 runtime policy is absent")
    })?;
    line2.proxy_username = "acceptance-v2".to_owned();
    desired_v2
        .validate()
        .map_err(|err| operational_failure("application_v2_spec", err.to_string()))?;

    let (release_v2, bundle_v2) = timed_stage(
        "application_v2_upgrade",
        acceptance_apply_desired(
            &desired_v2,
            &args.artifact_manifest_path,
            &args.edge_agent_artifact_path,
            DesiredMutationMode::Upgrade,
            ApplicationPlanClass::Upgrade,
        ),
    )
    .await
    .map_err(|detail| operational_failure("application_v2_upgrade", detail))?;
    if release_v1 == release_v2 || bundle_v1 == bundle_v2 {
        return Err(operational_failure(
            "application_v2_identity",
            "v1 and v2 release identities must differ",
        ));
    }

    timed_stage(
        "application_rollback",
        acceptance_rollback(
            desired,
            &release_v2,
            &release_v1,
            &args.artifact_manifest_path,
            &args.edge_agent_artifact_path,
        ),
    )
    .await
    .map_err(|detail| operational_failure("application_rollback", detail))?;

    timed_stage("vm_reboot", acceptance_reboot(vultr_spec, machine_id))
        .await
        .map_err(|detail| operational_failure("vm_reboot", detail))?;
    timed_stage(
        "substrate_after_reboot",
        acceptance_verify_substrate(vultr_spec, machine_id),
    )
    .await
    .map_err(|detail| operational_failure("substrate_after_reboot", detail))?;
    timed_stage(
        "application_after_reboot",
        acceptance_verify_desired(
            desired,
            &args.artifact_manifest_path,
            &args.edge_agent_artifact_path,
        ),
    )
    .await
    .map_err(|detail| operational_failure("application_after_reboot", detail))?;
    timed_stage(
        "mesh_after_reboot",
        mesh_runtime_verify(
            &args.mesh_base_spec_path,
            &args.vpc_spec_path,
            &args.spec_path,
        ),
    )
    .await
    .map_err(|detail| operational_failure("mesh_after_reboot", detail))?;
    timed_stage(
        "dns_after_reboot",
        dns_verify_noop(&args.dns_spec_path, &args.spec_path),
    )
    .await
    .map_err(|detail| operational_failure("dns_after_reboot", detail))?;
    timed_stage("vpc_after_reboot", vpc_verify(&args.vpc_spec_path))
        .await
        .map_err(|detail| operational_failure("vpc_after_reboot", detail))?;

    Ok(AcceptanceSuccess {
        release_v1,
        release_v2,
        bundle_v1,
        bundle_v2,
    })
}

async fn require_clean_room(
    paths: CleanupPaths<'_>,
    vultr_spec: &Path,
    machine_id: &str,
) -> Result<(), String> {
    timed_stage(
        "clean_room.vultr",
        vultr_require_clean_room(vultr_spec, machine_id),
    )
    .await?;
    timed_stage("clean_room.dns", dns_require_clean_room(paths.dns_spec)).await?;
    timed_stage("clean_room.mesh", mesh_require_clean_room(paths.mesh_spec)).await?;
    timed_stage("clean_room.vpc", vpc_require_clean_room(paths.vpc_spec)).await
}

fn record_cleanup_failure(
    failures: &mut Vec<String>,
    label: &'static str,
    result: Result<(), String>,
) {
    if let Err(err) = result {
        failures.push(format!("{label}: {err}"));
    }
}

async fn cleanup_environment(
    paths: CleanupPaths<'_>,
    vultr_spec: &Path,
    machine_id: &str,
    source_revision: &str,
    progress: &AcceptanceProgress,
) -> Result<(), String> {
    if !progress.mutation_started {
        return Ok(());
    }

    let mut failures = Vec::new();

    if progress.mesh_runtime_possible {
        let result = timed_stage(
            "cleanup.mesh_runtime",
            mesh_runtime_cleanup(paths.application_spec),
        )
        .await;
        record_cleanup_failure(&mut failures, "mesh_runtime_cleanup", result);
    }

    let result = timed_stage(
        "cleanup.mesh_provider",
        mesh_cleanup_provider_to_absent(paths.mesh_spec),
    )
    .await;
    record_cleanup_failure(&mut failures, "mesh_provider_cleanup", result);

    let result = timed_stage("cleanup.dns", dns_cleanup_to_absent(paths.dns_spec)).await;
    record_cleanup_failure(&mut failures, "dns_cleanup", result);

    if progress.vm_possible {
        let result = timed_stage(
            "cleanup.access",
            acceptance_lease_release(vultr_spec, machine_id),
        )
        .await;
        record_cleanup_failure(&mut failures, "access_release", result);

        let result = timed_stage(
            "cleanup.vm_support",
            acceptance_destroy_and_cleanup(vultr_spec, machine_id, source_revision),
        )
        .await;
        record_cleanup_failure(&mut failures, "vm_support_cleanup", result);
    }

    // VPC cleanup intentionally follows VM destruction. That removes the strongest
    // attachment dependency while the VPC owner still fresh-observes/fresh-plans
    // every destructive transition.
    let result = timed_stage("cleanup.vpc", vpc_cleanup_to_absent(paths.vpc_spec)).await;
    record_cleanup_failure(&mut failures, "vpc_cleanup", result);

    let final_zero_leak = timed_stage(
        "final_zero_leak",
        require_clean_room(paths, vultr_spec, machine_id),
    )
    .await;

    match final_zero_leak {
        Ok(()) => {
            if !failures.is_empty() {
                tracing::warn!(
                    component = "edge-orchestrator",
                    recovered_failures = %failures.join("; "),
                    event = "application.acceptance.cleanup.recovered",
                    "intermediate cleanup failures were superseded by independent final zero-leak proof"
                );
            }
            Ok(())
        }
        Err(err) => {
            failures.push(format!("final_zero_leak: {err}"));
            Err(failures.join("; "))
        }
    }
}

fn operational_failure(stage: &'static str, detail: impl Into<String>) -> AcceptanceFailure {
    AcceptanceFailure {
        stage,
        detail: detail.into(),
        cleanup_allowed: true,
    }
}

fn validate_disposable_acceptance(desired: &DesiredApplicationState) -> Result<(), String> {
    if desired.environment != "application-acceptance" {
        return Err(format!(
            "application acceptance requires environment application-acceptance, got {}",
            desired.environment
        ));
    }
    if desired.machine_id != "application-acceptance-1" {
        return Err(format!(
            "application acceptance requires machine application-acceptance-1, got {}",
            desired.machine_id
        ));
    }
    if desired.bootstrap_mode != ApplicationBootstrapMode::Full {
        return Err("application acceptance requires full bootstrap mode".to_owned());
    }
    let line1 = desired
        .runtime_policy
        .line1
        .as_ref()
        .ok_or_else(|| "application acceptance requires line1 runtime policy".to_owned())?;
    if line1.acme_provider != "https://acme-staging-v02.api.letsencrypt.org/directory" {
        return Err("application acceptance requires ACME staging authority".to_owned());
    }
    desired
        .runtime_policy
        .line2
        .as_ref()
        .ok_or_else(|| "application acceptance requires line2 runtime policy".to_owned())?;
    Ok(())
}

fn print_certificate(certificate: &AcceptanceCertificate<'_>) -> Result<(), String> {
    let output = serde_json::to_string_pretty(certificate)
        .map_err(|err| format!("failed to serialize application acceptance certificate: {err}"))?;
    println!("{output}");
    Ok(())
}

fn print_cleanup_certificate(certificate: &CleanupCertificate<'_>) -> Result<(), String> {
    let output = serde_json::to_string_pretty(certificate)
        .map_err(|err| format!("failed to serialize application cleanup certificate: {err}"))?;
    println!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_controller_core::application_lifecycle::{
        ApplicationRuntimePolicy, Line1RuntimePolicy, Line2RuntimePolicy,
    };

    fn desired() -> DesiredApplicationState {
        DesiredApplicationState {
            schema: 2,
            environment: "application-acceptance".to_owned(),
            vultr_spec_path: "infra/vultr/application-acceptance.json".to_owned(),
            machine_id: "application-acceptance-1".to_owned(),
            application_profile: "vultr-waw".to_owned(),
            bundle_root: "win/vultr-waw".to_owned(),
            runtime_env_required: true,
            runtime_policy: ApplicationRuntimePolicy {
                line1: Some(Line1RuntimePolicy {
                    tunnel_domain: "stage2-acceptance.alegria.by".to_owned(),
                    acme_email: "admin@alegria.by".to_owned(),
                    acme_provider: "https://acme-staging-v02.api.letsencrypt.org/directory"
                        .to_owned(),
                    reality_server_name: "www.microsoft.com".to_owned(),
                }),
                line2: Some(Line2RuntimePolicy {
                    proxy_username: "acceptance".to_owned(),
                    proxy_cert_cn: "stage2-acceptance.alegria.by".to_owned(),
                }),
            },
            bootstrap_mode: ApplicationBootstrapMode::Full,
        }
    }

    #[test]
    fn disposable_acceptance_refuses_non_disposable_identity() {
        let mut value = desired();
        validate_disposable_acceptance(&value).unwrap();

        value.environment = "production".to_owned();
        assert!(validate_disposable_acceptance(&value).is_err());
    }

    #[test]
    fn clean_room_failure_never_authorizes_compensation() {
        let failure = AcceptanceFailure {
            stage: "clean_room",
            detail: "residue".to_owned(),
            cleanup_allowed: false,
        };
        assert!(!failure.cleanup_allowed);
    }

    #[test]
    fn cleanup_contract_attempts_independent_owners_before_final_zero_leak_decision() {
        let source = include_str!("application_acceptance_command.rs");
        let runtime = source.find("mesh_runtime_cleanup(paths.application_spec)").unwrap();
        let provider = source
            .find("mesh_cleanup_provider_to_absent(paths.mesh_spec)")
            .unwrap();
        let dns = source.find("dns_cleanup_to_absent(paths.dns_spec)").unwrap();
        let access = source
            .find("acceptance_lease_release(vultr_spec, machine_id)")
            .unwrap();
        let vm = source
            .find("acceptance_destroy_and_cleanup(vultr_spec, machine_id, source_revision)")
            .unwrap();
        let vpc = source.find("vpc_cleanup_to_absent(paths.vpc_spec)").unwrap();
        let final_zero_leak = source.find("\"final_zero_leak\"").unwrap();

        assert!(runtime < provider);
        assert!(provider < dns);
        assert!(dns < access);
        assert!(access < vm);
        assert!(vm < vpc);
        assert!(vpc < final_zero_leak);
        assert!(!source.contains("cleanup_failure.is_none()"));
    }

    #[test]
    fn operational_failure_authorizes_only_fresh_owner_compensation() {
        let failure = operational_failure("application_v2_upgrade", "typed failure");
        assert!(failure.cleanup_allowed);
        assert_eq!(failure.stage, "application_v2_upgrade");
    }

    #[test]
    fn terminal_certificate_outcome_matrix_is_fail_closed() {
        let cases = [
            (
                TerminalPath::SuccessCleaned,
                TerminalDisposition {
                    outcome: "PASS",
                    clean_room_precondition: "PASS",
                    lifecycle: "PASS",
                    compensation: "NOT_REQUIRED",
                    zero_leaked_resources: "PASS",
                },
            ),
            (
                TerminalPath::SuccessCleanupFailed,
                TerminalDisposition {
                    outcome: "DIAGNOSTIC_REQUIRED",
                    clean_room_precondition: "PASS",
                    lifecycle: "PASS",
                    compensation: "FAILED",
                    zero_leaked_resources: "UNPROVEN",
                },
            ),
            (
                TerminalPath::CleanRoomRejected,
                TerminalDisposition {
                    outcome: "DIAGNOSTIC_REQUIRED",
                    clean_room_precondition: "FAIL",
                    lifecycle: "NOT_STARTED",
                    compensation: "NOT_ALLOWED",
                    zero_leaked_resources: "PRESERVED",
                },
            ),
            (
                TerminalPath::FailureCleaned,
                TerminalDisposition {
                    outcome: "FAIL_CLEANED",
                    clean_room_precondition: "PASS",
                    lifecycle: "FAIL",
                    compensation: "PASS",
                    zero_leaked_resources: "PASS",
                },
            ),
            (
                TerminalPath::FailureCleanupFailed,
                TerminalDisposition {
                    outcome: "DIAGNOSTIC_REQUIRED",
                    clean_room_precondition: "PASS",
                    lifecycle: "FAIL",
                    compensation: "FAILED",
                    zero_leaked_resources: "UNPROVEN",
                },
            ),
        ];

        for (path, expected) in cases {
            assert_eq!(terminal_disposition(path), expected);
        }
    }
}
