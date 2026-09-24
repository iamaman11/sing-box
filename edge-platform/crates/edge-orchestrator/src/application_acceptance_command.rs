use crate::application_lifecycle_command::{
    acceptance_apply_desired, acceptance_rollback, acceptance_verify_desired,
    load_application_desired,
};
use crate::application_lifecycle_service::DesiredMutationMode;
use crate::cli::ApplicationAcceptanceArgs;
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
use std::path::{Path, PathBuf};

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
                cleanup_environment(&args, &vultr_spec, &machine_id, source_revision, &progress)
                    .await
            {
                let certificate = AcceptanceCertificate {
                    outcome: "DIAGNOSTIC_REQUIRED",
                    source_revision,
                    release_set_sha256,
                    terminal_stage: "cleanup",
                    failure: Some(&detail),
                    clean_room_precondition: "PASS",
                    lifecycle: "PASS",
                    compensation: "FAILED",
                    zero_leaked_resources: "UNPROVEN",
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

            let certificate = AcceptanceCertificate {
                outcome: "PASS",
                source_revision,
                release_set_sha256,
                terminal_stage: "complete",
                failure: None,
                clean_room_precondition: "PASS",
                lifecycle: "PASS",
                compensation: "NOT_REQUIRED",
                zero_leaked_resources: "PASS",
                release_v1: Some(&success.release_v1),
                release_v2: Some(&success.release_v2),
                bundle_v1: Some(&success.bundle_v1),
                bundle_v2: Some(&success.bundle_v2),
            };
            print_certificate(&certificate)
        }
        Err(failure) if !failure.cleanup_allowed => {
            let certificate = AcceptanceCertificate {
                outcome: "DIAGNOSTIC_REQUIRED",
                source_revision,
                release_set_sha256,
                terminal_stage: failure.stage,
                failure: Some(&failure.detail),
                clean_room_precondition: "FAIL",
                lifecycle: "NOT_STARTED",
                compensation: "NOT_ALLOWED",
                zero_leaked_resources: "PRESERVED",
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
                cleanup_environment(&args, &vultr_spec, &machine_id, source_revision, &progress)
                    .await;
            let (outcome, compensation, zero_leak, cleanup_detail) = match cleanup {
                Ok(()) => ("FAIL_CLEANED", "PASS", "PASS", None),
                Err(detail) => ("DIAGNOSTIC_REQUIRED", "FAILED", "UNPROVEN", Some(detail)),
            };
            let combined = cleanup_detail
                .as_ref()
                .map(|detail| format!("{}; cleanup={detail}", failure.detail))
                .unwrap_or_else(|| failure.detail.clone());
            let certificate = AcceptanceCertificate {
                outcome,
                source_revision,
                release_set_sha256,
                terminal_stage: failure.stage,
                failure: Some(&combined),
                clean_room_precondition: "PASS",
                lifecycle: "FAIL",
                compensation,
                zero_leaked_resources: zero_leak,
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

async fn run_lifecycle(
    args: &ApplicationAcceptanceArgs,
    desired: &DesiredApplicationState,
    vultr_spec: &Path,
    machine_id: &str,
    progress: &mut AcceptanceProgress,
) -> Result<AcceptanceSuccess, AcceptanceFailure> {
    require_clean_room(args, vultr_spec, machine_id)
        .await
        .map_err(|detail| AcceptanceFailure {
            stage: "clean_room",
            detail,
            cleanup_allowed: false,
        })?;

    progress.mutation_started = true;
    vpc_create(&args.vpc_spec_path)
        .await
        .map_err(|detail| operational_failure("vpc_create", detail))?;

    progress.vm_possible = true;
    acceptance_create_machine(vultr_spec, machine_id)
        .await
        .map_err(|detail| operational_failure("vm_create", detail))?;

    acceptance_lease_acquire(vultr_spec, machine_id)
        .await
        .map_err(|detail| operational_failure("access_acquire", detail))?;

    acceptance_converge_substrate(vultr_spec, machine_id)
        .await
        .map_err(|detail| operational_failure("substrate_converge", detail))?;

    vpc_attach_and_verify(&args.vpc_spec_path)
        .await
        .map_err(|detail| operational_failure("vpc_attach", detail))?;
    acceptance_verify_substrate(vultr_spec, machine_id)
        .await
        .map_err(|detail| operational_failure("substrate_after_vpc", detail))?;

    dns_create(&args.dns_spec_path, &args.spec_path)
        .await
        .map_err(|detail| operational_failure("dns_create", detail))?;

    let (release_v1, bundle_v1) = acceptance_apply_desired(
        desired,
        &args.artifact_manifest_path,
        &args.edge_agent_artifact_path,
        DesiredMutationMode::Apply,
        ApplicationPlanClass::Apply,
    )
    .await
    .map_err(|detail| operational_failure("application_v1", detail))?;

    mesh_converge_provider(
        &args.mesh_base_spec_path,
        &args.vpc_spec_path,
        &args.spec_path,
    )
    .await
    .map_err(|detail| operational_failure("mesh_provider", detail))?;

    progress.mesh_runtime_possible = true;
    mesh_runtime_apply(
        &args.mesh_base_spec_path,
        &args.vpc_spec_path,
        &args.spec_path,
    )
    .await
    .map_err(|detail| operational_failure("mesh_runtime", detail))?;
    mesh_runtime_verify(
        &args.mesh_base_spec_path,
        &args.vpc_spec_path,
        &args.spec_path,
    )
    .await
    .map_err(|detail| operational_failure("mesh_runtime_verify", detail))?;

    acceptance_apply_desired(
        desired,
        &args.artifact_manifest_path,
        &args.edge_agent_artifact_path,
        DesiredMutationMode::Apply,
        ApplicationPlanClass::Noop,
    )
    .await
    .map_err(|detail| operational_failure("application_v1_noop", detail))?;
    acceptance_verify_desired(
        desired,
        &args.artifact_manifest_path,
        &args.edge_agent_artifact_path,
    )
    .await
    .map_err(|detail| operational_failure("application_v1_verify", detail))?;
    dns_verify_noop(&args.dns_spec_path, &args.spec_path)
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

    let (release_v2, bundle_v2) = acceptance_apply_desired(
        &desired_v2,
        &args.artifact_manifest_path,
        &args.edge_agent_artifact_path,
        DesiredMutationMode::Upgrade,
        ApplicationPlanClass::Upgrade,
    )
    .await
    .map_err(|detail| operational_failure("application_v2_upgrade", detail))?;
    if release_v1 == release_v2 || bundle_v1 == bundle_v2 {
        return Err(operational_failure(
            "application_v2_identity",
            "v1 and v2 release identities must differ",
        ));
    }

    acceptance_rollback(
        desired,
        &release_v2,
        &release_v1,
        &args.artifact_manifest_path,
        &args.edge_agent_artifact_path,
    )
    .await
    .map_err(|detail| operational_failure("application_rollback", detail))?;

    acceptance_reboot(vultr_spec, machine_id)
        .await
        .map_err(|detail| operational_failure("vm_reboot", detail))?;
    acceptance_verify_substrate(vultr_spec, machine_id)
        .await
        .map_err(|detail| operational_failure("substrate_after_reboot", detail))?;
    acceptance_verify_desired(
        desired,
        &args.artifact_manifest_path,
        &args.edge_agent_artifact_path,
    )
    .await
    .map_err(|detail| operational_failure("application_after_reboot", detail))?;
    mesh_runtime_verify(
        &args.mesh_base_spec_path,
        &args.vpc_spec_path,
        &args.spec_path,
    )
    .await
    .map_err(|detail| operational_failure("mesh_after_reboot", detail))?;
    dns_verify_noop(&args.dns_spec_path, &args.spec_path)
        .await
        .map_err(|detail| operational_failure("dns_after_reboot", detail))?;
    vpc_verify(&args.vpc_spec_path)
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
    args: &ApplicationAcceptanceArgs,
    vultr_spec: &Path,
    machine_id: &str,
) -> Result<(), String> {
    vultr_require_clean_room(vultr_spec, machine_id).await?;
    dns_require_clean_room(&args.dns_spec_path).await?;
    mesh_require_clean_room(&args.mesh_base_spec_path).await?;
    vpc_require_clean_room(&args.vpc_spec_path).await
}

async fn cleanup_environment(
    args: &ApplicationAcceptanceArgs,
    vultr_spec: &Path,
    machine_id: &str,
    source_revision: &str,
    progress: &AcceptanceProgress,
) -> Result<(), String> {
    if !progress.mutation_started {
        return Ok(());
    }

    let mut cleanup_failure = None;
    if progress.mesh_runtime_possible
        && let Err(err) = mesh_runtime_cleanup(&args.spec_path).await
    {
        cleanup_failure = Some(format!("mesh_runtime_cleanup: {err}"));
    }
    if cleanup_failure.is_none()
        && let Err(err) = mesh_cleanup_provider_to_absent(&args.mesh_base_spec_path).await
    {
        cleanup_failure = Some(format!("mesh_provider_cleanup: {err}"));
    }
    if cleanup_failure.is_none()
        && let Err(err) = dns_cleanup_to_absent(&args.dns_spec_path).await
    {
        cleanup_failure = Some(format!("dns_cleanup: {err}"));
    }
    if cleanup_failure.is_none()
        && let Err(err) = vpc_cleanup_to_absent(&args.vpc_spec_path).await
    {
        cleanup_failure = Some(format!("vpc_cleanup: {err}"));
    }

    if progress.vm_possible
        && let Err(err) = acceptance_lease_release(vultr_spec, machine_id).await
    {
        let access_failure = format!("access_release: {err}");
        cleanup_failure = Some(match cleanup_failure {
            Some(previous) => format!("{previous}; {access_failure}"),
            None => access_failure,
        });
    }

    if let Some(failure) = cleanup_failure {
        return Err(failure);
    }

    if progress.vm_possible {
        acceptance_destroy_and_cleanup(vultr_spec, machine_id, source_revision)
            .await
            .map_err(|err| format!("vm_support_cleanup: {err}"))?;
    }

    require_clean_room(args, vultr_spec, machine_id)
        .await
        .map_err(|err| format!("final_zero_leak: {err}"))
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
    fn cleanup_contract_keeps_access_release_outside_feature_success_path() {
        let source = include_str!("application_acceptance_command.rs");
        let runtime = source
            .find("mesh_runtime_cleanup(&args.spec_path)")
            .unwrap();
        let provider = source
            .find("mesh_cleanup_provider_to_absent(&args.mesh_base_spec_path)")
            .unwrap();
        let dns = source
            .find("dns_cleanup_to_absent(&args.dns_spec_path)")
            .unwrap();
        let vpc = source
            .find("vpc_cleanup_to_absent(&args.vpc_spec_path)")
            .unwrap();
        let access = source
            .find("acceptance_lease_release(vultr_spec, machine_id)")
            .unwrap();
        let failure_return = source
            .find("if let Some(failure) = cleanup_failure")
            .unwrap();

        assert!(runtime < provider && provider < dns && dns < vpc && vpc < access);
        assert!(access < failure_return);
    }

    #[test]
    fn operational_failure_authorizes_only_fresh_owner_compensation() {
        let failure = operational_failure("application_v2_upgrade", "typed failure");
        assert!(failure.cleanup_allowed);
        assert_eq!(failure.stage, "application_v2_upgrade");
    }
}
