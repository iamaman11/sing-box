use crate::application_lifecycle_command::{
    production_converge_desired, production_rollback_desired, production_verify_desired,
};
use crate::cloudflare_dns_lifecycle_command::{
    acceptance_verify_noop as dns_verify_noop, production_converge as dns_converge,
};
use crate::cloudflare_mesh_lifecycle_command::{
    acceptance_converge_provider as mesh_converge_provider,
    acceptance_runtime_apply as mesh_runtime_apply,
    acceptance_runtime_verify as mesh_runtime_verify,
};
use crate::vultr_lifecycle_command::{
    acceptance_converge_substrate as substrate_converge,
    acceptance_lease_acquire as lease_acquire,
    acceptance_lease_release as lease_release,
    acceptance_verify_substrate as substrate_verify, exact_existing_machine_observation,
    production_converge_machine,
};
use crate::vultr_vpc_lifecycle_command::{
    acceptance_verify as vpc_verify, production_converge as vpc_converge,
};
use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_orchestrator::OrchestrationContext;
use edge_shared_types::canonical_production_desired_state;
use std::path::{Path, PathBuf};

pub(crate) fn validate(release_context: &OrchestrationContext) -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    let composition = ProductionComposition::from_proto(&desired).map_err(|err| err.to_string())?;
    print_identity(release_context, &composition, "PASS");
    Ok(())
}

pub(crate) async fn converge(
    release_context: &OrchestrationContext,
    edge_agent_artifact_path: &Path,
) -> Result<(), String> {
    release_context.application_release_authority()?;
    let composition = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let spec = Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH);

    production_converge_machine(spec, &composition.machine_id).await?;
    lease_acquire(spec, &composition.machine_id).await?;

    let operation = async {
        substrate_converge(spec, &composition.machine_id).await?;
        vpc_converge(spec).await?;
        let (release_id, bundle_digest) = production_converge_desired(
            release_context,
            &composition.application,
            edge_agent_artifact_path,
        )
        .await?;
        dns_converge(spec, spec).await?;
        mesh_converge_provider(spec, spec, spec).await?;
        mesh_runtime_apply(spec, spec, spec).await?;
        verify_with_lease(release_context, &composition, edge_agent_artifact_path).await?;
        Ok::<_, String>((release_id, bundle_digest))
    }
    .await;

    let release_result = lease_release(spec, &composition.machine_id).await;
    match (operation, release_result) {
        (Ok((release_id, bundle_digest)), Ok(())) => {
            print_identity(release_context, &composition, "PASS");
            println!("operation=CONVERGE");
            println!("application_release_id={release_id}");
            println!("application_bundle_digest={bundle_digest}");
            println!("transient_support_access=ABSENT");
            Ok(())
        }
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(release_err)) => Err(format!(
            "production convergence passed but transient support-access cleanup failed: {release_err}"
        )),
        (Err(err), Err(release_err)) => Err(format!(
            "{err}; transient support-access cleanup also failed: {release_err}"
        )),
    }
}

pub(crate) async fn verify(
    release_context: &OrchestrationContext,
    edge_agent_artifact_path: &Path,
) -> Result<(), String> {
    release_context.application_release_authority()?;
    let composition = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let spec = Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH);

    exact_existing_machine_observation(&composition.machines, &composition.machine_id).await?;
    lease_acquire(spec, &composition.machine_id).await?;
    let operation =
        verify_with_lease(release_context, &composition, edge_agent_artifact_path).await;
    let release_result = lease_release(spec, &composition.machine_id).await;

    match (operation, release_result) {
        (Ok(()), Ok(())) => {
            print_identity(release_context, &composition, "PASS");
            println!("operation=VERIFY");
            println!("provider_plan=NOOP");
            println!("transient_support_access=ABSENT");
            Ok(())
        }
        (Err(err), Ok(())) => Err(err),
        (Ok(()), Err(release_err)) => Err(format!(
            "production verification passed but transient support-access cleanup failed: {release_err}"
        )),
        (Err(err), Err(release_err)) => Err(format!(
            "{err}; transient support-access cleanup also failed: {release_err}"
        )),
    }
}

pub(crate) async fn rollback(release_context: &OrchestrationContext) -> Result<(), String> {
    release_context.application_release_authority()?;
    let composition = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let spec = Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH);

    exact_existing_machine_observation(&composition.machines, &composition.machine_id).await?;
    lease_acquire(spec, &composition.machine_id).await?;
    let operation = async {
        let (rolled_back_from, rolled_back_to) =
            production_rollback_desired(&composition.application).await?;
        mesh_runtime_apply(spec, spec, spec).await?;
        mesh_runtime_verify(spec, spec, spec).await?;
        dns_verify_noop(spec, spec).await?;
        vpc_verify(spec).await?;
        substrate_verify(spec, &composition.machine_id).await?;
        Ok::<_, String>((rolled_back_from, rolled_back_to))
    }
    .await;
    let release_result = lease_release(spec, &composition.machine_id).await;

    match (operation, release_result) {
        (Ok((rolled_back_from, rolled_back_to)), Ok(())) => {
            println!("status=PASS");
            println!("operation=ROLLBACK");
            println!("production_authority={CANONICAL_PRODUCTION_AUTHORITY_PATH}");
            println!("rolled_back_from={rolled_back_from}");
            println!("rolled_back_to={rolled_back_to}");
            println!("transient_support_access=ABSENT");
            Ok(())
        }
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(release_err)) => Err(format!(
            "production rollback passed but transient support-access cleanup failed: {release_err}"
        )),
        (Err(err), Err(release_err)) => Err(format!(
            "{err}; transient support-access cleanup also failed: {release_err}"
        )),
    }
}

async fn verify_with_lease(
    release_context: &OrchestrationContext,
    composition: &ProductionComposition,
    edge_agent_artifact_path: &Path,
) -> Result<(), String> {
    let spec = Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH);
    exact_existing_machine_observation(&composition.machines, &composition.machine_id).await?;
    substrate_verify(spec, &composition.machine_id).await?;
    vpc_verify(spec).await?;
    production_verify_desired(
        release_context,
        &composition.application,
        edge_agent_artifact_path,
    )
    .await?;
    dns_verify_noop(spec, spec).await?;
    mesh_runtime_verify(spec, spec, spec).await?;
    Ok(())
}

fn print_identity(
    release_context: &OrchestrationContext,
    composition: &ProductionComposition,
    status: &str,
) {
    let release = release_context.release();
    println!("status={status}");
    println!("production_authority={CANONICAL_PRODUCTION_AUTHORITY_PATH}");
    println!("environment={}", composition.environment);
    println!("machine_id={}", composition.machine_id);
    println!("public_hostname={}", composition.public_hostname);
    println!("one_production_vm=true");
    println!("production_acme=true");
    println!("mesh_routes_derived_from_vpc_observation=true");
    println!("firewall_rule_count={}", composition.firewall_rules.len());
    println!("release_set_sha256={}", release.release_set_sha256);
    println!("source_revision={}", release.source_revision);
    println!("gateway_image={}", release.gateway_image);
    println!("warp_egress_image={}", release.warp_egress_image);
    println!("mesh_image={}", release.mesh_image);
    println!("immutable_oci_release_identity=true");
}

#[allow(dead_code)]
fn _path_owned(path: &Path) -> PathBuf {
    path.to_path_buf()
}
