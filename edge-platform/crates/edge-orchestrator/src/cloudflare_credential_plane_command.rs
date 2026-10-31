use crate::cli::{
    CredentialDeliveryCommand, CredentialDeliverySlotArg, CredentialRotationClassArg,
};
use crate::credential_initial_journal::{
    InitialPairJournalPlan, PairedCommitPlan, PairedHostReadback, PairedRecoveryPlan,
    plan_initial_pair_reservation, plan_paired_commit, plan_paired_recovery,
    reconcile_paired_commit, require_empty_initial_history, verify_expected_initial_attempt,
    verify_paired_commit_intent, verify_paired_recovery, verify_recorded_initial_attempt,
};
use edge_controller_core::production::{ProductionComposition, ProductionCredentialPlaneOwnership};
use edge_orchestrator::credential_snapshot::{
    FreshCredentialSnapshotRequest, RotateCredentialSnapshotRequest,
    generate_fresh_credential_snapshot, generate_rotation_credential_snapshot,
};
use edge_provider_cloudflare as cloudflare;
use edge_shared_types::{
    CREDENTIAL_DUMMY_PROBE_GENERATION_A, CREDENTIAL_DUMMY_PROBE_GENERATION_B,
    CredentialDeliveryBundle, CredentialDeliverySlot, CredentialIsolationProbe,
    CredentialProjectionKind, CredentialRotationClass,
};
use prost::Message;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::{env, fs};

const SLOT_A: &str = "EDGE_CREDENTIAL_BUNDLE_A";
const SLOT_B: &str = "EDGE_CREDENTIAL_BUNDLE_B";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProjectionDesired {
    projection: String,
    worker_name: String,
    access_application_name: String,
    access_policy_name: String,
    host_service_token_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProjectionObservation {
    projection: String,
    worker_name: String,
    worker_script_present: bool,
    worker_identity_present: bool,
    worker_id: Option<String>,
    worker_binding_count: Option<usize>,
    worker_secret_bindings: Vec<cloudflare::CloudflareWorkerSecretBinding>,
    worker_version_tag: Option<String>,
    worker_latest_version_id: Option<String>,
    worker_latest_version_tag: Option<String>,
    worker_active_deployment_id: Option<String>,
    worker_active_version_ids: Vec<String>,
    workers_dev_enabled: Option<bool>,
    previews_enabled: Option<bool>,
    custom_domain_count: usize,
    host_service_token_id: Option<String>,
    host_service_token_client_id: Option<String>,
    host_service_token_enabled: Option<bool>,
    host_service_token_duration: Option<String>,
    access_application_id: Option<String>,
    access_application_type: Option<String>,
    access_service_auth_401_redirect: Option<bool>,
    access_destination_type: Option<String>,
    access_destination_worker_id: Option<String>,
    access_destination_uri: Option<String>,
    access_destination_has_overrides: Option<bool>,
    access_policies: Vec<cloudflare::CloudflareAccessPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CredentialPlaneObservation {
    control_token_identity: cloudflare::CloudflareApiTokenIdentity,
    host_access: Option<HostAccessObservation>,
    access_organization: Option<cloudflare::CloudflareAccessOrganization>,
    workers_dev_subdomain: Option<String>,
    projections: Vec<ProjectionObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum CredentialDeliveryAction {
    Noop,
    InstallDummyAbContract { projection: String },
    RestoreFixedAbVersionTag { projection: String },
    RestoreFixedAbBaseline { projection: String },
    UpgradeSlotProofCode { projection: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionDeliveryState {
    LegacyLocked,
    FixedAbVersionTagMissing,
    FixedAbLatestPendingDeployment,
    FixedAbProofUpgradeRequired,
    FixedAb,
}

#[derive(Debug, Clone)]
struct DeliverySlot {
    name: &'static str,
    generation: u64,
    payload: Vec<u8>,
    secret_text: String,
}

#[derive(Debug, Clone)]
struct DeliveryWorkerMaterial {
    source: String,
    version_tag: String,
    slots: Vec<DeliverySlot>,
}

pub async fn run_delivery(
    command: CredentialDeliveryCommand,
    release_context: &edge_orchestrator::OrchestrationContext,
) -> Result<(), String> {
    // The GitHub attempt journal is independent from Cloudflare provider
    // credentials. An unchanged read-only history check must work before the
    // workflow injects ANY Cloudflare control token.
    if matches!(
        &command,
        CredentialDeliveryCommand::InitialPairJournalObserve { .. }
            | CredentialDeliveryCommand::InitialPairJournalReadback { .. }
    ) {
        return run_readonly_journal(command);
    }
    if matches!(
        &command,
        CredentialDeliveryCommand::InitialPairCommitPlan { .. }
            | CredentialDeliveryCommand::InitialPairCommitReadback { .. }
            | CredentialDeliveryCommand::InitialPairCommitReconcile { .. }
            | CredentialDeliveryCommand::InitialPairRecoveryPlan { .. }
            | CredentialDeliveryCommand::InitialPairRecoveryReadback { .. }
    ) {
        // These calls neither open a Cloudflare write token nor POST to GitHub.
        return run_readonly_paired_commit(command, release_context);
    }
    if matches!(
        &command,
        CredentialDeliveryCommand::ExistingJoinBeginPlan { .. }
            | CredentialDeliveryCommand::ExistingJoinBeginReadback { .. }
            | CredentialDeliveryCommand::ExistingJoinPlan { .. }
            | CredentialDeliveryCommand::ExistingJoinReadback { .. }
            | CredentialDeliveryCommand::ExistingJoinReconcile { .. }
            | CredentialDeliveryCommand::ExistingJoinJournalInspect { .. }
    ) {
        let release = release_context.release();
        return crate::credential_existing_join::dispatch(
            &command,
            &release.accepted_revision,
            &release.release_set_sha256,
        );
    }
    // Independent Github-runner network probe. It has Worker VM read
    // identity only, never a Cloudflare provider mutation token.
    if let CredentialDeliveryCommand::InitialLine2ExternalWitness {
        generation,
        vm_ipv4,
        tls_domain,
        username,
        vm_access_identity_path,
    } = &command
    {
        return crate::line2_external_witness::witness(
            *generation,
            vm_ipv4,
            tls_domain,
            username,
            vm_access_identity_path,
        )
        .await;
    }
    let control_token = required_env("CLOUDFLARE_CONTROL_TOKEN")?;
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = production.cloudflare.credential_plane.clone();

    if production.cloudflare.active_account_id != desired.target_account_id
        || production.cloudflare.migration_target_account_id.is_some()
    {
        return Err(
            "credential delivery requires the dedicated credential account to be active canonical production authority with no migration target"
                .to_owned(),
        );
    }

    match command {
        CredentialDeliveryCommand::ContractVerify => verify(&control_token, &desired).await,
        CredentialDeliveryCommand::HostAccessObserve => {
            let observed = observe(&control_token, &desired).await?;
            let phase = host_access_readback(&desired, &observed)?;
            println!("host_access_schema=sing-box.host-access-boundary/v1");
            println!("host_access_credentials_vm=EXACT_VM_ONLY");
            println!("host_access_credentials_windows=EXACT_WINDOWS_ONLY");
            println!("host_access_route={}", phase.as_str());
            println!("host_access_provider_mutations=0");
            println!("host_access_native_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::ExistingJoinBeginPlan { .. }
        | CredentialDeliveryCommand::ExistingJoinBeginReadback { .. }
        | CredentialDeliveryCommand::ExistingJoinPlan { .. }
        | CredentialDeliveryCommand::ExistingJoinReadback { .. }
        | CredentialDeliveryCommand::ExistingJoinReconcile { .. }
        | CredentialDeliveryCommand::ExistingJoinJournalInspect { .. } => {
            unreachable!("existing join runs before provider authority")
        }
        CredentialDeliveryCommand::InitialLine2ExternalWitness { .. } => {
            unreachable!("independent witness is dispatched before provider authority")
        }
        CredentialDeliveryCommand::InitialWorkerProofPlan {
            run_id,
            journal_history_path,
            record_output_path,
        } => {
            initial_worker_proof_plan(
                &control_token,
                &desired,
                release_context,
                run_id,
                &journal_history_path,
                &record_output_path,
            )
            .await
        }
        CredentialDeliveryCommand::InitialWorkerProofUpgrade {
            run_id,
            journal_history_path,
            exact_record_path,
        } => {
            initial_worker_proof_upgrade(
                &control_token,
                &desired,
                release_context,
                run_id,
                &journal_history_path,
                &exact_record_path,
            )
            .await
        }
        CredentialDeliveryCommand::InitialPairPreflight { generation, slot } => {
            initial_pair_preflight(&control_token, &desired, generation, slot).await
        }
        CredentialDeliveryCommand::InitialPairJournalObserve { .. }
        | CredentialDeliveryCommand::InitialPairJournalReadback { .. }
        | CredentialDeliveryCommand::InitialPairCommitPlan { .. }
        | CredentialDeliveryCommand::InitialPairCommitReadback { .. }
        | CredentialDeliveryCommand::InitialPairCommitReconcile { .. }
        | CredentialDeliveryCommand::InitialPairRecoveryPlan { .. }
        | CredentialDeliveryCommand::InitialPairRecoveryReadback { .. } => {
            unreachable!(
                "read-only journal and paired-commit policy dispatch before provider authority"
            )
        }
        CredentialDeliveryCommand::InitialPairJournalPlan {
            generation,
            slot,
            provider_intent_sha256,
            vm_attestation_sha256,
            windows_attestation_sha256,
            run_id,
            journal_history_path,
            record_output_path,
        } => {
            let observed = observe(&control_token, &desired).await?;
            let expected =
                initial_pair_provider_intent_sha256(&desired, &observed, generation, slot)?;
            if expected != provider_intent_sha256 {
                return Err("initial journal refuses stale or forged provider intent".to_owned());
            }
            let history = fs::read_to_string(&journal_history_path)
                .map_err(|err| format!("initial journal history cannot be read: {err}"))?;
            let request = InitialPairJournalPlan {
                generation,
                slot: slot.as_str().to_owned(),
                provider_intent_sha256,
                vm_attestation_sha256,
                windows_attestation_sha256,
                release_source_revision: release_context.release().source_revision.clone(),
                release_set_sha256: release_context.release().release_set_sha256.clone(),
                github_run_id: run_id,
            };
            let result = plan_initial_pair_reservation(&request, &history)?;
            // Atomic create-new, no replacement: a retry cannot silently
            // alter the exact record later read back from GitHub.
            write_new_initial_record(&record_output_path, &result)?;
            // This is only a local non-secret file. GitHub ISSUE #26 BEGIN
            // is not durable until the authorized workflow POSTs once and
            // independently verifies the full comment history.
            println!("operation=CREDENTIAL_INITIAL_PAIR_JOURNAL_PLAN");
            println!(
                "credential_attempt_record_sha256={}",
                sha256_hex(result.as_bytes())
            );
            println!("credential_record_file_created=true");
            println!("credential_provider_mutations=0");
            println!("credential_journal_mutations=0");
            println!("initial_publication_authorized=false");
            Ok(())
        }
        CredentialDeliveryCommand::InitialPairPublish {
            generation,
            slot,
            provider_intent_sha256,
            vm_attestation_sha256,
            windows_attestation_sha256,
            run_id,
            journal_history_path,
            exact_record_path,
        } => {
            initial_pair_publish(
                &control_token,
                &desired,
                release_context,
                InitialPairJournalPlan {
                    generation,
                    slot: slot.as_str().to_owned(),
                    provider_intent_sha256,
                    vm_attestation_sha256,
                    windows_attestation_sha256,
                    release_source_revision: release_context.release().source_revision.clone(),
                    release_set_sha256: release_context.release().release_set_sha256.clone(),
                    github_run_id: run_id,
                },
                slot,
                &journal_history_path,
                &exact_record_path,
            )
            .await
        }
        CredentialDeliveryCommand::InitialWindowsAcceptanceIssue {
            run_id,
            private_output_path,
            token_id_output_path,
        } => {
            initial_windows_acceptance_issue(
                &control_token,
                &desired,
                run_id,
                &private_output_path,
                &token_id_output_path,
            )
            .await
        }
        CredentialDeliveryCommand::InitialWindowsAcceptanceCleanup { run_id } => {
            initial_windows_acceptance_cleanup(&control_token, &desired, run_id).await
        }
        CredentialDeliveryCommand::HostBootstrapConverge => {
            host_bootstrap_converge(&control_token, &desired).await
        }
        CredentialDeliveryCommand::RotateApplication {
            class,
            active_generation,
            generation,
            slot,
        } => {
            rotate_application_publish(
                &control_token,
                &desired,
                class,
                active_generation,
                generation,
                slot,
            )
            .await
        }
    }
}

// A second, run-scoped Access principal is issued only for isolated Windows
// acceptance. The permanent Windows service token is never exported, read,
// rotated or reused. The only Access policy mutation is a fenced temporary
// addition; after the experiment it must be restored before revoking the token.
fn initial_acceptance_token_name(run_id: u64) -> Result<String, String> {
    if run_id < 10_000_000 {
        return Err("acceptance run ID is not a real GitHub Actions run".to_owned());
    }
    Ok(format!("sing-box-first-use-windows-{run_id}"))
}

fn check_initial_acceptance_github_owner(run_id: u64, phase: &str) -> Result<(), String> {
    let actual_run = required_env("GITHUB_RUN_ID")?;
    let attempt = required_env("GITHUB_RUN_ATTEMPT")?;
    let repository = required_env("GITHUB_REPOSITORY")?;
    let event = required_env("GITHUB_EVENT_NAME")?;
    if actual_run != run_id.to_string()
        || attempt != "1"
        || repository != "iamaman11/sing-box"
        || event != "issue_comment"
        || !matches!(phase, "ISSUE" | "CLEANUP")
    {
        return Err("Windows acceptance Access owner/run mismatch, refusing mutation".to_owned());
    }
    initial_acceptance_token_name(run_id)?;
    Ok(())
}

fn exact_service_auth_ids(
    actual: &cloudflare::CloudflareAccessPolicy,
    expected: &[String],
) -> Result<(), String> {
    if actual.decision.as_deref() != Some("non_identity")
        || actual.has_extra_rules
        || actual.include_service_token_ids.len() != expected.len()
    {
        return Err("Windows acceptance Access service-auth policy drifted".to_owned());
    }
    let mut actual_ids = actual.include_service_token_ids.clone();
    actual_ids.sort();
    let mut expected_ids = expected.to_vec();
    expected_ids.sort();
    if actual_ids != expected_ids || actual_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("Windows acceptance Access token IDs differ from exact policy".to_owned());
    }
    Ok(())
}

fn acceptance_window_policy(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(String, String, String, String), String> {
    let window = projection_observation(observed, "windows")?;
    let production = projections(desired)
        .into_iter()
        .find(|p| p.projection == "windows")
        .ok_or("Windows acceptance projection not canonical")?;
    if window.host_service_token_enabled != Some(true)
        || window.host_service_token_duration.as_deref()
            != Some(desired.host_service_token_duration.as_str())
        || window.access_application_type.as_deref() != Some("self_hosted")
        || window.access_service_auth_401_redirect != Some(true)
        || window.access_destination_type.as_deref() != Some("public")
        || window.access_destination_uri.as_deref()
            != Some(workers_dev_hostname(desired, &production).as_str())
        || window.access_destination_worker_id.is_some()
        || window.access_destination_has_overrides != Some(false)
    {
        return Err("Windows acceptance refuses drifted permanent Access application".to_owned());
    }
    let host = window
        .host_service_token_id
        .clone()
        .ok_or("Windows acceptance missing permanent host service token ID")?;
    let app = window
        .access_application_id
        .clone()
        .ok_or("Windows acceptance missing exact Access application ID")?;
    if window.access_policies.len() != 1 {
        return Err("Windows acceptance requires exactly one existing Access policy".to_owned());
    }
    let policy = &window.access_policies[0];
    if policy.name != production.access_policy_name || policy.id.is_empty() {
        return Err("Windows acceptance refuses unknown policy identity".to_owned());
    }
    Ok((host, app, policy.id.clone(), policy.name.clone()))
}

async fn initial_windows_acceptance_issue(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    run_id: u64,
    private_output: &Path,
    public_output: &Path,
) -> Result<(), String> {
    check_initial_acceptance_github_owner(run_id, "ISSUE")?;
    let before = observe(control_token, desired).await?;
    validate_access_boundary(desired, &before)?;
    let name = initial_acceptance_token_name(run_id)?;
    let tokens =
        cloudflare::list_access_service_tokens(control_token, &desired.target_account_id).await?;
    if tokens
        .iter()
        .any(|t| t.name.as_deref() == Some(name.as_str()))
    {
        return Err("run-scoped Windows acceptance token exists; do not reissue".to_owned());
    }
    let (host, app, policy_id, policy_name) = acceptance_window_policy(desired, &before)?;
    let window = projection_observation(&before, "windows")?;
    exact_service_auth_ids(&window.access_policies[0], &[host.clone()])?;
    if private_output.exists() || public_output.exists() {
        return Err("Windows acceptance escrow file already exists, no overwrite".to_owned());
    }
    let token = cloudflare::create_access_service_token(
        control_token,
        &desired.target_account_id,
        &name,
        "4h",
        true,
    )
    .await
    .map_err(|e| format!("Windows acceptance issuance ACK unknown; no replay: {e}"))?;
    if token.name.as_deref() != Some(name.as_str())
        || token.enabled != Some(true)
        || token.client_id.is_empty()
        || token.client_secret.is_empty()
        || token.id.is_empty()
    {
        return Err("Windows acceptance issued token response is not exact; no retry".to_owned());
    }
    // Immediately persist a private delivery file before the policy mutation.
    // This file remains only on GitHub-hosted trusted acceptance owner and
    // is sent to the Windows runner via protected GH environment secret.
    let private = format!(
        "CF_ACCESS_CLIENT_ID={}\nCF_ACCESS_CLIENT_SECRET={}\n",
        token.client_id, token.client_secret,
    );
    write_private_bootstrap_file(private_output, private.as_bytes())?;
    write_private_bootstrap_file(public_output, token.id.as_bytes())?;

    cloudflare::update_access_service_policy_tokens(
        control_token,
        &desired.target_account_id,
        &app,
        &policy_id,
        &policy_name,
        &[host.clone(), token.id.clone()],
    )
    .await
    .map_err(|e| {
        format!("Windows acceptance policy mutation ACK unknown; reconcile, never replay: {e}")
    })?;
    let after = observe(control_token, desired).await?;
    let window_after = projection_observation(&after, "windows")?;
    if window_after.access_policies.len() != 1 {
        return Err("Windows acceptance policy readback cardinality drifted".to_owned());
    }
    exact_service_auth_ids(&window_after.access_policies[0], &[host, token.id.clone()])?;
    println!("operation=INITIAL_WINDOWS_ACCEPTANCE_ACCESS_ISSUE");
    println!("acceptance_access_run_id={run_id}");
    println!("acceptance_access_token_id={}", token.id);
    println!("acceptance_access_secret_delivery=GITHUB_ENVIRONMENT_ESCROW_ONLY");
    println!("acceptance_access_policy=HOST_PLUS_EXACT_ONE_RUN_SCOPED");
    println!("permanent_host_identity_mutated=false");
    Ok(())
}

async fn initial_windows_acceptance_cleanup(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    run_id: u64,
) -> Result<(), String> {
    check_initial_acceptance_github_owner(run_id, "CLEANUP")?;
    let name = initial_acceptance_token_name(run_id)?;
    let before = observe(control_token, desired).await?;
    let (host, app, policy_id, policy_name) = acceptance_window_policy(desired, &before)?;
    let tokens =
        cloudflare::list_access_service_tokens(control_token, &desired.target_account_id).await?;
    let exact: Vec<_> = tokens
        .iter()
        .filter(|token| token.name.as_deref() == Some(name.as_str()))
        .collect();
    if exact.len() > 1 {
        return Err("duplicate Windows acceptance tokens; refusing ambiguous cleanup".to_owned());
    }
    let policy = &projection_observation(&before, "windows")?.access_policies[0];
    let expected_with_temp = exact.first().map(|t| vec![host.clone(), t.id.clone()]);
    if let Some(expected) = expected_with_temp {
        if exact_service_auth_ids(policy, &expected).is_ok() {
            cloudflare::update_access_service_policy_tokens(
                control_token,
                &desired.target_account_id,
                &app,
                &policy_id,
                &policy_name,
                &[host.clone()],
            )
            .await
            .map_err(|e| {
                format!("Windows Access rollback ACK uncertain; observe before any retry: {e}")
            })?;
            let proof = observe(control_token, desired).await?;
            let window = projection_observation(&proof, "windows")?;
            if window.access_policies.len() != 1 {
                return Err("Windows Access rollback did not prove exactly one policy".to_owned());
            }
            exact_service_auth_ids(&window.access_policies[0], &[host.clone()])?;
        } else {
            exact_service_auth_ids(policy, &[host.clone()])?;
        }
        let token_id = &exact[0].id;
        cloudflare::delete_access_service_token(
            control_token,
            &desired.target_account_id,
            token_id,
        )
        .await
        .map_err(|e| {
            format!("Windows Access revoke ACK uncertain; observe before any retry: {e}")
        })?;
        let remaining =
            cloudflare::list_access_service_tokens(control_token, &desired.target_account_id)
                .await?;
        if remaining
            .iter()
            .any(|t| t.name.as_deref() == Some(name.as_str()) || t.id == *token_id)
        {
            return Err("Windows acceptance Access token revocation unproven".to_owned());
        }
    } else {
        exact_service_auth_ids(policy, &[host.clone()])?;
    }
    let after = observe(control_token, desired).await?;
    validate_access_boundary(desired, &after)?;
    println!("operation=INITIAL_WINDOWS_ACCEPTANCE_ACCESS_CLEANUP");
    println!("acceptance_access_status=REVOKED_OR_ABSENT");
    println!("windows_access_policy=EXACT_HOST_ONLY");
    println!("permanent_host_identity_mutated=false");
    Ok(())
}

fn write_new_initial_record(path: &Path, record: &str) -> Result<(), String> {
    // A BEGIN reservation is a non-secret exact payload for ONE authorized
    // GitHub comment, not a second credential authority.
    if record.len() > 4096
        || !record.starts_with("<!-- sing-box-credential-initial-attempt/v1 -->\n")
    {
        return Err("initial BEGIN local record is malformed or too large".to_owned());
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("cannot create one-shot initial BEGIN file: {err}"))?;
    file.write_all(record.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("initial BEGIN record was not durably written: {err}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedHostObservations {
    vm: PairedHostReadback,
    windows: PairedHostReadback,
}

fn commit_request_from_cli(
    original_run_id: u64,
    commit_run_id: u64,
    generation: u64,
    slot: CredentialDeliverySlotArg,
    vm_prepared_sha256: String,
    windows_prepared_sha256: String,
    release: &edge_orchestrator::OrchestrationContext,
) -> PairedCommitPlan {
    PairedCommitPlan {
        original_run_id,
        commit_run_id,
        generation,
        slot: slot.as_str().to_owned(),
        accepted_revision: release.release().accepted_revision.clone(),
        release_set_sha256: release.release().release_set_sha256.clone(),
        vm_prepared_sha256,
        windows_prepared_sha256,
    }
}

fn read_exact_file(path: &Path, label: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|err| format!("{label}: {err}"))
}

/// Read-only policy and exact local output creation. Not a GitHub POST and
/// never a credential writer. Host origin boolean values in an input file
/// are NOT cryptographic authentication: the independent owner provenance
/// must be proven by the workflow before any separate commit executor exists.
fn run_readonly_paired_commit(
    command: CredentialDeliveryCommand,
    release: &edge_orchestrator::OrchestrationContext,
) -> Result<(), String> {
    match command {
        CredentialDeliveryCommand::InitialPairCommitPlan {
            original_run_id,
            commit_run_id,
            generation,
            slot,
            vm_prepared_sha256,
            windows_prepared_sha256,
            journal_history_path,
            original_begin_path,
            record_output_path,
        } => {
            let request = commit_request_from_cli(
                original_run_id,
                commit_run_id,
                generation,
                slot,
                vm_prepared_sha256,
                windows_prepared_sha256,
                release,
            );
            let history = read_exact_file(
                &journal_history_path,
                "paired commit plan history unavailable",
            )?;
            let original = read_exact_file(
                &original_begin_path,
                "paired commit original BEGIN unavailable",
            )?;
            let intended = plan_paired_commit(&request, &history, &original)?;
            if intended.len() > 4096
                || !intended.starts_with("<!-- sing-box-credential-paired-commit/v1 -->\n")
            {
                return Err("paired commit planned record is malformed or too large".to_owned());
            }
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&record_output_path)
                .map_err(|err| format!("paired commit intent file must be create-new: {err}"))?;
            file.write_all(intended.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|err| format!("paired intent file write uncertain: {err}"))?;
            println!("credential_paired_commit_policy=INTENT_PLANNED_LOCAL_ONLY");
            println!(
                "credential_paired_commit_sha256={}",
                sha256_hex(intended.as_bytes())
            );
            println!("credential_pair_committed=false");
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            println!("credential_journal_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::InitialPairCommitReadback {
            original_run_id,
            commit_run_id,
            generation,
            slot,
            vm_prepared_sha256,
            windows_prepared_sha256,
            journal_history_path,
            original_begin_path,
            exact_intent_path,
        } => {
            let request = commit_request_from_cli(
                original_run_id,
                commit_run_id,
                generation,
                slot,
                vm_prepared_sha256,
                windows_prepared_sha256,
                release,
            );
            let history = read_exact_file(
                &journal_history_path,
                "paired commit readback history unavailable",
            )?;
            let original = read_exact_file(
                &original_begin_path,
                "paired commit original BEGIN unavailable",
            )?;
            let intent = read_exact_file(
                &exact_intent_path,
                "paired commit intended record unavailable",
            )?;
            verify_paired_commit_intent(&request, &history, &original, &intent)?;
            println!("credential_paired_commit_intent=EXACT_DURABLE_ONCE");
            println!("credential_pair_committed=false");
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::InitialPairCommitReconcile {
            original_run_id,
            commit_run_id,
            generation,
            slot,
            vm_prepared_sha256,
            windows_prepared_sha256,
            journal_history_path,
            original_begin_path,
            exact_intent_path,
            host_readback_path,
        } => {
            let request = commit_request_from_cli(
                original_run_id,
                commit_run_id,
                generation,
                slot,
                vm_prepared_sha256,
                windows_prepared_sha256,
                release,
            );
            let history = read_exact_file(
                &journal_history_path,
                "paired commit reconcile history unavailable",
            )?;
            let original = read_exact_file(
                &original_begin_path,
                "paired commit original BEGIN unavailable",
            )?;
            let intent = read_exact_file(
                &exact_intent_path,
                "paired commit intended record unavailable",
            )?;
            let observation = read_exact_file(
                &host_readback_path,
                "paired commit read-only host cursors unavailable",
            )?;
            let reports: PairedHostObservations = serde_json::from_str(&observation)
                .map_err(|_| "paired commit host report is malformed or incomplete".to_owned())?;
            let verdict = reconcile_paired_commit(
                &request,
                &history,
                &original,
                &intent,
                &reports.vm,
                &reports.windows,
            )?;
            println!("credential_paired_commit_reconcile={verdict}");
            println!("credential_replay_authorized=false");
            println!("credential_provider_mutations=0");
            println!("credential_runtime_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::InitialPairRecoveryPlan {
            original_run_id,
            commit_run_id,
            recovery_run_id,
            generation,
            slot,
            vm_prepared_sha256,
            windows_prepared_sha256,
            vm_active_sha256,
            windows_candidate_sha256,
            journal_history_path,
            original_begin_path,
            original_intent_path,
            host_readback_path,
            recovery_output_path,
        } => {
            let pair = commit_request_from_cli(
                original_run_id,
                commit_run_id,
                generation,
                slot,
                vm_prepared_sha256,
                windows_prepared_sha256,
                release,
            );
            let history = read_exact_file(&journal_history_path, "recovery history unavailable")?;
            let original =
                read_exact_file(&original_begin_path, "recovery original BEGIN unavailable")?;
            let intent = read_exact_file(
                &original_intent_path,
                "recovery original COMMIT_INTENT unavailable",
            )?;
            let observation =
                read_exact_file(&host_readback_path, "recovery host proofs unavailable")?;
            let reports: PairedHostObservations = serde_json::from_str(&observation)
                .map_err(|_| "paired recovery host report invalid".to_owned())?;
            let plan = PairedRecoveryPlan {
                original_intent_sha256: sha256_hex(intent.as_bytes()),
                pair,
                recovery_run_id,
                vm_active_sha256,
                windows_candidate_sha256,
                vm: reports.vm,
                windows: reports.windows,
            };
            let output = plan_paired_recovery(&plan, &history, &original, &intent)?;
            if output.len() > 4096
                || !output.starts_with("<!-- sing-box-credential-paired-recovery/v1 -->\n")
            {
                return Err("paired recovery intent must be exact nonsecret record".to_owned());
            }
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&recovery_output_path)
                .map_err(|err| format!("recovery intent file already exists or unknown: {err}"))?;
            file.write_all(output.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|err| format!("paired recovery output write uncertain: {err}"))?;
            println!("paired_recovery_policy=LOCAL_INTENT_ONLY");
            println!(
                "paired_recovery_intent_sha256={}",
                sha256_hex(output.as_bytes())
            );
            println!("paired_recovery_provider_mutations=0");
            println!("paired_recovery_host_mutations=0");
            println!("paired_recovery_journal_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::InitialPairRecoveryReadback {
            original_run_id,
            commit_run_id,
            recovery_run_id,
            generation,
            slot,
            vm_prepared_sha256,
            windows_prepared_sha256,
            vm_active_sha256,
            windows_candidate_sha256,
            journal_history_path,
            original_begin_path,
            original_intent_path,
            host_readback_path,
            recovery_output_path,
        } => {
            let pair = commit_request_from_cli(
                original_run_id,
                commit_run_id,
                generation,
                slot,
                vm_prepared_sha256,
                windows_prepared_sha256,
                release,
            );
            let history = read_exact_file(&journal_history_path, "recovery history unavailable")?;
            let original =
                read_exact_file(&original_begin_path, "recovery original BEGIN unavailable")?;
            let intent = read_exact_file(
                &original_intent_path,
                "recovery original COMMIT_INTENT unavailable",
            )?;
            let observation =
                read_exact_file(&host_readback_path, "recovery host proofs unavailable")?;
            let reports: PairedHostObservations = serde_json::from_str(&observation)
                .map_err(|_| "paired recovery host report invalid".to_owned())?;
            let plan = PairedRecoveryPlan {
                original_intent_sha256: sha256_hex(intent.as_bytes()),
                pair,
                recovery_run_id,
                vm_active_sha256,
                windows_candidate_sha256,
                vm: reports.vm,
                windows: reports.windows,
            };
            let exact = read_exact_file(
                &recovery_output_path,
                "recovery intent readback unavailable",
            )?;
            verify_paired_recovery(&plan, &history, &original, &intent, &exact)?;
            println!("paired_recovery_intent=EXACT_DURABLE_ONCE");
            println!("paired_recovery_provider_mutations=0");
            println!("paired_recovery_host_mutations=0");
            Ok(())
        }
        _ => Err("read-only paired commit policy refuses unrelated command".to_owned()),
    }
}

fn run_readonly_journal(command: CredentialDeliveryCommand) -> Result<(), String> {
    match command {
        CredentialDeliveryCommand::InitialPairJournalObserve {
            journal_history_path,
        } => {
            let history = fs::read_to_string(&journal_history_path)
                .map_err(|err| format!("cannot read initial attempt journal history: {err}"))?;
            require_empty_initial_history(&history)?;
            println!("credential_initial_journal_empty=true");
            println!("credential_journal_mutations=0");
            println!("credential_provider_mutations=0");
            Ok(())
        }
        CredentialDeliveryCommand::InitialPairJournalReadback {
            journal_history_path,
            exact_record_path,
        } => {
            let history = fs::read_to_string(journal_history_path)
                .map_err(|err| format!("initial journal readback cannot open history: {err}"))?;
            let exact = fs::read_to_string(exact_record_path).map_err(|err| {
                format!("initial journal readback cannot open intended record: {err}")
            })?;
            verify_recorded_initial_attempt(&history, &exact)?;
            println!("credential_initial_journal_exact_begin=true");
            println!("credential_provider_mutations=0");
            println!("initial_publication_authorized=false");
            Ok(())
        }
        _ => Err("read-only GitHub journal handler refuses provider command".to_owned()),
    }
}

// Provider-side non-mutating half of the single N1/N2 initial transaction.
// This does not consume a host attestation and may never authorize a POST.
fn validate_initial_pair_provider_observation(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
    generation: u64,
    _slot: CredentialDeliverySlotArg,
) -> Result<(), String> {
    if generation == 0
        || generation == CREDENTIAL_DUMMY_PROBE_GENERATION_A
        || generation == CREDENTIAL_DUMMY_PROBE_GENERATION_B
    {
        return Err(
            "fresh credential generation must be nonzero and distinct from canonical dummy probes"
                .to_owned(),
        );
    }
    validate_access_boundary(desired, observed)?;
    let vm = projection_observation(observed, "vm")?;
    let windows = projection_observation(observed, "windows")?;
    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        if projection_delivery_state(desired, &projection, observed)?
            != ProjectionDeliveryState::FixedAb
            || current
                .worker_latest_version_id
                .as_deref()
                .unwrap_or("")
                .is_empty()
            || current.worker_active_version_ids.len() != 1
        {
            return Err(format!(
                "initial paired provider preflight refuses drifted {} Worker version or A/B topology",
                projection.projection
            ));
        }
    }
    for (label, left, right) in [
        (
            "Worker identity",
            vm.worker_id.as_deref(),
            windows.worker_id.as_deref(),
        ),
        (
            "Access service token",
            vm.host_service_token_id.as_deref(),
            windows.host_service_token_id.as_deref(),
        ),
        (
            "Access client identity",
            vm.host_service_token_client_id.as_deref(),
            windows.host_service_token_client_id.as_deref(),
        ),
        (
            "Access application",
            vm.access_application_id.as_deref(),
            windows.access_application_id.as_deref(),
        ),
    ] {
        if left.is_none() || right.is_none() || left == right {
            return Err(format!(
                "initial paired provider preflight requires distinct nonempty VM and Windows {label}"
            ));
        }
    }
    Ok(())
}

// A stable, non-secret journal key for the *observed* baseline of BOTH
// Workers. Every eventual host attestation and append-only attempt record
// must bind to this exact digest. Provider metadata alone cannot authorize
// publication, regardless of this digest matching.
fn initial_pair_provider_intent_sha256(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
    generation: u64,
    slot: CredentialDeliverySlotArg,
) -> Result<String, String> {
    validate_initial_pair_provider_observation(desired, observed, generation, slot)?;
    let vm = projection_observation(observed, "vm")?;
    let windows = projection_observation(observed, "windows")?;
    let version_id = |projection: &ProjectionObservation| -> Result<String, String> {
        let latest = projection
            .worker_latest_version_id
            .as_deref()
            .ok_or_else(|| {
                format!(
                    "{} initial intent has no latest Worker version",
                    projection.projection
                )
            })?;
        if projection.worker_active_version_ids.as_slice() != [latest] {
            return Err(format!(
                "{} initial intent refuses Worker version race",
                projection.projection
            ));
        }
        Ok(latest.to_owned())
    };
    let identity = serde_json::json!({
        "schema": "credential-initial-pair-provider-intent/v1",
        "account_id": desired.target_account_id,
        "generation": generation,
        "slot": slot.as_str(),
        "vm": {
            "worker_id": vm.worker_id,
            "latest_active_version_id": version_id(vm)?,
            "access_application_id": vm.access_application_id,
            "access_service_token_id": vm.host_service_token_id,
            "access_client_id": vm.host_service_token_client_id,
        },
        "windows": {
            "worker_id": windows.worker_id,
            "latest_active_version_id": version_id(windows)?,
            "access_application_id": windows.access_application_id,
            "access_service_token_id": windows.host_service_token_id,
            "access_client_id": windows.host_service_token_client_id,
        },
    });
    let bytes = serde_json::to_vec(&identity)
        .map_err(|err| format!("failed to encode initial provider intent: {err}"))?;
    Ok(sha256_hex(&bytes))
}

const WORKER_PROOF_MARKER: &str = "<!-- sing-box-worker-proof-upgrade/v1 -->";
const WORKER_PROOF_MARKER_FAMILY: &str = "<!-- sing-box-worker-proof-upgrade/";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerProofAttempt {
    schema: String,
    phase: String,
    github_run_id: u64,
    source_revision: String,
    release_set_sha256: String,
    baseline_sha256: String,
}

fn worker_proof_comments(history: &str) -> Result<Vec<String>, String> {
    let comments: Vec<serde_json::Value> = serde_json::from_str(history)
        .map_err(|_| "Worker proof journal requires complete GitHub JSON history".to_owned())?;
    comments
        .iter()
        .map(|v| {
            v.get("body")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| "Worker proof journal refuses malformed or empty comment".to_owned())
        })
        .collect()
}

fn worker_proof_record(
    history: &str,
    expected: Option<&str>,
) -> Result<Option<WorkerProofAttempt>, String> {
    let comments = worker_proof_comments(history)?;
    let marked = comments
        .iter()
        .filter(|body| body.contains(WORKER_PROOF_MARKER_FAMILY))
        .collect::<Vec<_>>();
    if let Some(exact) = expected {
        if marked.len() != 1 || marked[0].as_str() != exact {
            return Err(
                "Worker proof migration requires one exact durable GitHub BEGIN".to_owned(),
            );
        }
        let body = exact
            .strip_prefix(WORKER_PROOF_MARKER)
            .ok_or_else(|| "Worker proof BEGIN marker is displaced".to_owned())?;
        let parsed: WorkerProofAttempt = serde_json::from_str(body.trim())
            .map_err(|_| "Worker proof BEGIN has malformed JSON".to_owned())?;
        if parsed.schema != "sing-box.worker-proof-upgrade/v1"
            || parsed.phase != "BEGIN"
            || parsed.github_run_id == 0
            || parsed.source_revision.len() != 40
            || parsed.release_set_sha256.len() != 64
            || parsed.baseline_sha256.len() != 64
            || ![
                parsed.source_revision.as_str(),
                parsed.release_set_sha256.as_str(),
                parsed.baseline_sha256.as_str(),
            ]
            .iter()
            .all(|v| {
                v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err("Worker proof BEGIN is not a canonical non-secret record".to_owned());
        }
        return Ok(Some(parsed));
    }
    if !marked.is_empty() {
        return Err(
            "Worker proof migration already has a durable BEGIN; no second initial attempt"
                .to_owned(),
        );
    }
    Ok(None)
}

fn worker_proof_baseline_sha256(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
    context: &edge_orchestrator::OrchestrationContext,
    run_id: u64,
) -> Result<String, String> {
    if run_id == 0 {
        return Err("Worker proof baseline requires valid GitHub run ID".to_owned());
    }
    validate_access_boundary(desired, observed)?;
    let mut workers = Vec::new();
    for projection in projections(desired) {
        if projection_delivery_state(desired, &projection, observed)?
            != ProjectionDeliveryState::FixedAbProofUpgradeRequired
        {
            return Err(format!(
                "{} Worker must have an exact old active code baseline before BEGIN",
                projection.projection
            ));
        }
        let current = projection_observation(observed, &projection.projection)?;
        let latest = current
            .worker_latest_version_id
            .as_deref()
            .ok_or_else(|| "Worker proof baseline requires latest version ID".to_owned())?;
        if current.worker_active_version_ids.as_slice() != [latest] {
            return Err(format!(
                "{} Worker proof baseline requires exact active latest version",
                projection.projection
            ));
        }
        workers.push(serde_json::json!({
            "projection": projection.projection,
            "worker_id": current.worker_id,
            "version_id": latest,
            "version_tag": current.worker_latest_version_tag,
            "access_app_id": current.access_application_id,
        }));
    }
    let identity = serde_json::json!({
        "schema": "sing-box.worker-proof-baseline/v1",
        "github_run_id": run_id,
        "source_revision": context.release().source_revision,
        "release_set_sha256": context.release().release_set_sha256,
        "account_id": desired.target_account_id,
        "workers": workers,
    });
    let bytes = serde_json::to_vec(&identity)
        .map_err(|_| "Worker proof baseline cannot serialize typed intent".to_owned())?;
    Ok(sha256_hex(&bytes))
}

async fn initial_worker_proof_plan(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    context: &edge_orchestrator::OrchestrationContext,
    run_id: u64,
    journal_history_path: &Path,
    record_output_path: &Path,
) -> Result<(), String> {
    if env::var("GITHUB_RUN_ID").ok().as_deref() != Some(run_id.to_string().as_str()) {
        return Err("Worker proof plan refuses foreign GitHub run".to_owned());
    }
    let history = fs::read_to_string(journal_history_path)
        .map_err(|_| "Worker proof plan cannot read complete issue history".to_owned())?;
    // Initial credentials must not have been attempted. An uncertain earlier
    // BEGIN prevents migration from covertly enabling another issuance.
    require_empty_initial_history(&history)?;
    let before = observe(control_token, desired).await?;
    validate_access_boundary(desired, &before)?;
    let states = projections(desired)
        .iter()
        .map(|projection| projection_delivery_state(desired, projection, &before))
        .collect::<Result<Vec<_>, _>>()?;
    if states
        .iter()
        .all(|state| *state == ProjectionDeliveryState::FixedAb)
    {
        // Repeat installation may reuse already deployed *code* without a
        // second Cloudflare mutation or BEGIN. But require the earlier exact
        // journal record: never silently trust a foreign code migration.
        let marked = worker_proof_comments(&history)?
            .into_iter()
            .filter(|body| body.contains(WORKER_PROOF_MARKER_FAMILY))
            .collect::<Vec<_>>();
        if marked.len() != 1 {
            return Err("already-upgraded Workers require one prior exact GitHub BEGIN".to_owned());
        }
        worker_proof_record(&history, Some(&marked[0]))?;
        println!("operation=CREDENTIAL_INITIAL_WORKER_PROOF_PLAN");
        println!("worker_proof_upgrade_required=false");
        println!("worker_proof_code_verified=EXACT_TWO_ACTIVE");
        println!("worker_provider_mutations=0");
        return Ok(());
    }
    worker_proof_record(&history, None)?;
    let digest = worker_proof_baseline_sha256(desired, &before, context, run_id)?;
    let confirmed = observe(control_token, desired).await?;
    if digest != worker_proof_baseline_sha256(desired, &confirmed, context, run_id)? {
        return Err("Worker proof baseline drifted between read-only observations".to_owned());
    }
    let attempt = WorkerProofAttempt {
        schema: "sing-box.worker-proof-upgrade/v1".to_owned(),
        phase: "BEGIN".to_owned(),
        github_run_id: run_id,
        source_revision: context.release().source_revision.clone(),
        release_set_sha256: context.release().release_set_sha256.clone(),
        baseline_sha256: digest,
    };
    let body = format!(
        "{WORKER_PROOF_MARKER}\n{}",
        serde_json::to_string(&attempt)
            .map_err(|_| "cannot encode Worker proof BEGIN".to_owned())?
    );
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(record_output_path)
        .map_err(|_| "Worker proof plan refuses to replace existing BEGIN file".to_owned())?;
    file.write_all(body.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| "Worker proof BEGIN local fsync failed".to_owned())?;
    println!("operation=CREDENTIAL_INITIAL_WORKER_PROOF_PLAN");
    println!("worker_proof_baseline_sha256={}", attempt.baseline_sha256);
    println!("worker_proof_begin_prepared=true");
    println!("worker_proof_upgrade_required=true");
    println!("worker_provider_mutations=0");
    Ok(())
}

/// Source identities are bound to the same immutable ReleaseSet as the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptedVmWorkerSource {
    desired: String,
    predecessor: String,
}

fn accepted_vm_worker_source(
    release: &edge_orchestrator::OrchestrationContext,
) -> Result<AcceptedVmWorkerSource, String> {
    let context =
        env::var_os("EDGE_RELEASE_CONTEXT_PATH").ok_or("HOST_VM_WORKER_RELEASE_CONTEXT_ABSENT")?;
    let parent = Path::new(&context)
        .parent()
        .ok_or("HOST_VM_WORKER_RELEASE_CONTEXT_PARENT_ABSENT")?;
    let path = parent.join("release-set.pb");
    let meta = fs::symlink_metadata(&path).map_err(|_| "HOST_VM_WORKER_RELEASESET_ABSENT")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 65536 {
        return Err("HOST_VM_WORKER_RELEASESET_UNSAFE".to_owned());
    }
    let bytes = fs::read(&path).map_err(|_| "HOST_VM_WORKER_RELEASESET_UNREADABLE")?;
    if sha256_hex(&bytes) != release.release().release_set_sha256 {
        return Err("HOST_VM_WORKER_RELEASESET_DIGEST_MISMATCH".to_owned());
    }
    let accepted = edge_shared_types::decode_release_set(&bytes)?;
    if accepted.schema_version < 8 || accepted.source_revision != release.release().source_revision
    {
        return Err("HOST_VM_WORKER_RELEASESET_V8_REQUIRED".to_owned());
    }
    let cf = accepted
        .cloudflare
        .ok_or("HOST_VM_WORKER_RELEASE_SOURCE_ABSENT")?;
    if cf.vm_worker_source_sha256.len() != 32 || cf.vm_worker_predecessor_source_sha256.len() != 32
    {
        return Err("HOST_VM_WORKER_RELEASE_SOURCE_INVALID".to_owned());
    }
    Ok(AcceptedVmWorkerSource {
        desired: hex_encode(&cf.vm_worker_source_sha256),
        predecessor: hex_encode(&cf.vm_worker_predecessor_source_sha256),
    })
}

/// Worker is observed state, not a Git predecessor. A clean reconcile only
/// requires the exact selected Cloudflare account/Worker, sole active==latest
/// deployment and preserved opaque bindings. Desired bytes come from the
/// protected immutable ReleaseSet; version labels are never authorities.
fn verify_vm_worker_reconcilable_current(
    desired: &ProjectionDesired,
    current: &ProjectionObservation,
) -> Result<(), String> {
    if desired.projection != "vm"
        || desired.worker_name != "sing-box-credentials-vm"
        || current.worker_name != desired.worker_name
        || current.worker_id.is_none()
        || current.worker_latest_version_id.is_none()
        || current.worker_active_version_ids.as_slice()
            != [current.worker_latest_version_id.as_deref().unwrap_or("")]
        || current.worker_active_deployment_id.is_none()
        || !matches!(current.worker_binding_count, Some(8 | 9))
        || current.worker_secret_bindings.len() != current.worker_binding_count.unwrap_or_default()
    {
        return Err("HOST_VM_WORKER_CURRENT_OWNER_OR_DEPLOYMENT_UNPROVEN".to_owned());
    }
    require_exact_secret_bindings(
        &desired.worker_name,
        &desired.projection,
        &current.worker_secret_bindings,
    )
}

/// The exact active Version API is the ONLY observed code, not content/v2
/// (which may return latest pending code instead of 100% traffic).
fn verified_vm_worker_active_code(
    desired: &ProjectionDesired,
    current: &ProjectionObservation,
    active: &cloudflare::CloudflareWorkerExactModule,
) -> Result<Vec<u8>, String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    verify_vm_worker_reconcilable_current(desired, current)?;
    if current.worker_active_version_ids.first() != Some(&active.id)
        || active.secret_bindings != current.worker_secret_bindings
    {
        return Err("HOST_VM_WORKER_ACTIVE_VERSION_OR_BINDINGS_UNPROVEN".into());
    }
    let bytes = STANDARD
        .decode(active.content_base64.as_bytes())
        .map_err(|_| "HOST_VM_WORKER_ACTIVE_CODE_NOT_BASE64")?;
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err("HOST_VM_WORKER_ACTIVE_CODE_BOUNDS_INVALID".into());
    }
    Ok(bytes)
}

/// The only admitted outcomes after exact Worker source and identity verification.
/// Other lifecycle states are blocked before publishing any GitHub decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmWorkerUpgradeDecision {
    AlreadyAccepted,
    UpgradeRequired,
}

impl VmWorkerUpgradeDecision {
    fn from_verified_state(state: ProjectionDeliveryState) -> Result<Self, &'static str> {
        match state {
            ProjectionDeliveryState::FixedAb => Ok(Self::AlreadyAccepted),
            ProjectionDeliveryState::FixedAbProofUpgradeRequired => Ok(Self::UpgradeRequired),
            _ => Err("HOST_VM_WORKER_PLAN_STATE_NOT_ADMITTED"),
        }
    }

    fn workflow_required(self) -> &'static str {
        match self {
            Self::AlreadyAccepted => "false",
            Self::UpgradeRequired => "true",
        }
    }
}

/// Publish only the closed Rust decision scalar to GitHub Actions.
/// Any invalid source or missing output channel fails closed.
fn emit_vm_worker_plan_required(decision: VmWorkerUpgradeDecision) -> Result<(), String> {
    let path = env::var_os("GITHUB_OUTPUT").ok_or("HOST_WORKFLOW_OUTPUT_REQUIRED")?;
    let mut output = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|_| "HOST_WORKFLOW_OUTPUT_NOT_WRITABLE")?;
    writeln!(output, "required={}", decision.workflow_required())
        .map_err(|_| "HOST_WORKFLOW_OUTPUT_WRITE_FAILED")?;
    output
        .sync_all()
        .map_err(|_| "HOST_WORKFLOW_OUTPUT_SYNC_FAILED".to_owned())
}

/// Strict version-bound proof. /scripts/.../content/v2 may serve latest
/// bytes while a different version still receives 100% of production traffic.
fn verify_pending_vm_worker_exact_modules(
    vm: &ProjectionDesired,
    before: &ProjectionObservation,
    accepted: &AcceptedVmWorkerSource,
    material: &DeliveryWorkerMaterial,
    active: &cloudflare::CloudflareWorkerExactModule,
    pending: &cloudflare::CloudflareWorkerExactModule,
) -> Result<(), String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let denied = "HOST_VM_WORKER_PENDING_EXACT_PROOF_REJECTED_NO_REPLAY";
    let Some(active_id) = before.worker_active_version_ids.first() else {
        return Err(denied.into());
    };
    let Some(latest_id) = before.worker_latest_version_id.as_deref() else {
        return Err(denied.into());
    };
    if before.worker_name != vm.worker_name
        || vm.projection != "vm"
        || before.worker_active_version_ids.len() != 1
        || active_id == latest_id
        || before.worker_active_deployment_id.is_none()
        || !matches!(before.worker_binding_count, Some(8 | 9))
        || active.id != *active_id
        || pending.id != latest_id
        || pending.version_tag != material.version_tag
        || before.worker_latest_version_tag.as_deref() != Some(material.version_tag.as_str())
        || active.secret_bindings != pending.secret_bindings
        || active.secret_bindings != before.worker_secret_bindings
    {
        return Err(denied.into());
    }
    require_exact_secret_bindings(&vm.worker_name, "vm", &active.secret_bindings)?;
    let actual_active = STANDARD
        .decode(active.content_base64.as_bytes())
        .map_err(|_| denied)?;
    let actual_pending = STANDARD
        .decode(pending.content_base64.as_bytes())
        .map_err(|_| denied)?;
    if actual_active.is_empty()
        || actual_active.len() > 1_048_576
        || sha256_hex(&actual_pending) != accepted.desired
        || actual_pending != material.source.as_bytes()
    {
        return Err("HOST_VM_WORKER_PENDING_SOURCE_MISMATCH_NO_REPLAY".into());
    }
    Ok(())
}

/// VM-only Host authorizer code promotion. The one public /host apply
/// selects the Git-owned VM; the protected workflow reserves a durable BEGIN
/// before dispatch and supplies the existing distinct Cloudflare read/write
/// identities. No secret values are transported by this Rust operation.
/// Missing signer/receipt pins remain an absolute first-use CREATE gate.
pub(crate) async fn host_vm_worker_authorizer_upgrade(
    machine_id: &str,
    release: &edge_orchestrator::OrchestrationContext,
    plan_only: bool,
) -> Result<(), String> {
    for (key, expected) in [
        ("GITHUB_REPOSITORY", "iamaman11/sing-box"),
        ("GITHUB_REPOSITORY_ID", "1221750822"),
        ("GITHUB_EVENT_NAME", "issue_comment"),
        ("GITHUB_ACTOR_ID", "44100369"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("GITHUB_JOB", "host_worker_authorizer"),
    ] {
        if env::var(key).ok().as_deref() != Some(expected) {
            return Err(format!("HOST_VM_WORKER_MUTATION_UNTRUSTED_{key}"));
        }
    }
    if env::var("GITHUB_SHA").ok().as_deref() != Some(release.release().accepted_revision.as_str())
    {
        return Err("HOST_VM_WORKER_RELEASE_GIT_REVISION_MISMATCH".to_owned());
    }
    if env::var("HOST_ORIGINAL_COMMAND").ok().as_deref()
        != Some(format!("/host apply {machine_id}").as_str())
    {
        return Err("HOST_VM_WORKER_EXACT_APPLY_REQUIRED".to_owned());
    }
    let host = release.verified_vm_worker_code_upgrade_host(machine_id)?;
    if host.machine_id != machine_id {
        return Err("HOST_VM_WORKER_GIT_SELECTION_MISMATCH".to_owned());
    }
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = &production.cloudflare.credential_plane;
    if production.cloudflare.active_account_id != desired.target_account_id
        || production.cloudflare.migration_target_account_id.is_some()
    {
        return Err("HOST_VM_WORKER_PRODUCTION_AUTHORITY_MISMATCH".to_owned());
    }
    let read_token = required_env("CLOUDFLARE_CONTROL_TOKEN")?;
    let write_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
    let before = observe(&read_token, desired).await?;
    validate_access_boundary(desired, &before)?;
    let write_identity = cloudflare::verify_api_token(&write_token).await?;
    if write_identity.status != "active" || write_identity.id == before.control_token_identity.id {
        return Err("HOST_VM_WORKER_DISTINCT_ACTIVE_WRITE_IDENTITY_REQUIRED".to_owned());
    }
    // The Windows Worker is a read-only neighbour here, NOT the target
    // projection. Its tag identifies independently deployed Windows code,
    // so VM-only publication must not require the Windows tag to equal a
    // particular version of the VM credential delivery template.
    // Preserve the entire Windows snapshot across both provider mutations.
    verify_vm_only_windows_neighbour(desired, &before)?;
    let vm = projection_desired(desired, "vm")?;
    let original = projection_observation(&before, "vm")?;
    let accepted_source = accepted_vm_worker_source(release)?;
    let material = delivery_worker_material("vm")?;
    if sha256_hex(material.source.as_bytes()) != accepted_source.desired {
        return Err("HOST_VM_WORKER_DESIRED_RELEASE_SOURCE_MISMATCH".to_owned());
    }
    // Recover a *verified existing pending version*, not the failed HostIntent.
    // Both version-specific modules, including the *active predecessor*, must
    // be read with include=modules. Never infer active source from content/v2.
    if let (Some(latest), [active]) = (
        original.worker_latest_version_id.as_deref(),
        original.worker_active_version_ids.as_slice(),
    ) {
        if latest != active {
            let worker_id = original
                .worker_id
                .as_deref()
                .ok_or("HOST_VM_WORKER_PENDING_IDENTITY_MISSING_NO_REPLAY")?;
            let active_module = cloudflare::get_worker_exact_version_module(
                &read_token,
                &desired.target_account_id,
                worker_id,
                active,
            )
            .await?;
            let pending_module = cloudflare::get_worker_exact_version_module(
                &read_token,
                &desired.target_account_id,
                worker_id,
                latest,
            )
            .await?;
            verify_pending_vm_worker_exact_modules(
                &vm,
                original,
                &accepted_source,
                &material,
                &active_module,
                &pending_module,
            )?;
            let observed_again = observe(&read_token, desired).await?;
            validate_access_boundary(desired, &observed_again)?;
            if observed_again.projections != before.projections {
                return Err("HOST_VM_WORKER_PENDING_PRESTATE_DRIFT_NO_REPLAY".into());
            }
            println!("host_vm_worker_pending_source=EXACT_VERSION_BOUND_SHA256_PROVEN");
            if plan_only {
                crate::vm_worker_begin_reconciliation::verify_pending_vm_worker_begins(
                    machine_id,
                    &pending_module.created_on,
                )
                .await?;
                emit_vm_worker_plan_required(VmWorkerUpgradeDecision::UpgradeRequired)?;
                println!("host_vm_worker_authorizer=EXACT_EXISTING_PENDING_DEPLOY_PLAN");
                println!("worker_mutations=0");
                println!("host_signed_install=NOT_AUTHORIZED");
                return Ok(());
            }
            // The workflow reserved a new BEGIN after plan-only had proven
            // exactly one earlier failed upload. Verify fresh authorization;
            // no repetition of that earlier GitHub comment/HostIntent.
            crate::vm_worker_begin_reconciliation::verify_current_vm_worker_begin(machine_id)
                .await?;
            let before_write = observe(&read_token, desired).await?;
            validate_access_boundary(desired, &before_write)?;
            if before_write.projections != before.projections {
                return Err("HOST_VM_WORKER_PENDING_BEFORE_DEPLOY_DRIFT_NO_REPLAY".into());
            }
            // Deployment is the ONE write in the new separately authorized
            // transaction. A failed ACK never authorizes a second POST.
            let ack = cloudflare::deploy_worker_version(
                &write_token,
                &desired.target_account_id,
                &vm.worker_name,
                latest,
            )
            .await;
            let after = observe(&read_token, desired).await?;
            validate_access_boundary(desired, &after)?;
            if projection_observation(&before, "windows")?
                != projection_observation(&after, "windows")?
                || verify_exact_active_worker_version(projection_observation(&after, "vm")?, latest)
                    .is_err()
                || projection_delivery_state(desired, &vm, &after)?
                    != ProjectionDeliveryState::FixedAb
                || !matches!(
                    projection_observation(&after, "vm")?.worker_binding_count,
                    Some(8 | 9)
                )
            {
                return Err("HOST_VM_WORKER_PENDING_DEPLOY_POSTSTATE_UNPROVEN_NO_REPLAY".into());
            }
            let verified_active = cloudflare::get_worker_exact_version_module(
                &read_token,
                &desired.target_account_id,
                worker_id,
                latest,
            )
            .await?;
            if verified_active != pending_module {
                return Err("HOST_VM_WORKER_PENDING_DEPLOY_ACTIVE_SOURCE_DRIFT_NO_REPLAY".into());
            }
            let final_observation = observe(&read_token, desired).await?;
            if final_observation.projections != after.projections {
                return Err("HOST_VM_WORKER_PENDING_DEPLOY_SECOND_READBACK_DRIFT_NO_REPLAY".into());
            }
            if ack.is_err() {
                return Err("HOST_VM_WORKER_PENDING_DEPLOY_ACK_UNCERTAIN_NO_REPLAY".into());
            }
            println!("host_vm_worker_source_readback=EXACT_ACCEPTED_VERSION_MODULE_BYTES");
            println!("host_vm_worker_authorizer=CANONICAL_VM_CODE_ACTIVE");
            println!("host_vm_worker_active_version_id={latest}");
            println!("worker_mutations=1");
            println!("worker_upload_mutations=0");
            println!("worker_secret_mutations=0");
            println!("windows_worker_mutations=0");
            println!("host_signed_install=NOT_AUTHORIZED");
            return Ok(());
        }
    } else if original.worker_latest_version_id.is_some()
        && !original.worker_active_version_ids.is_empty()
    {
        return Err("HOST_VM_WORKER_SPLIT_DEPLOYMENT_UNPROVEN_NO_REPLAY".into());
    }
    verify_vm_worker_reconcilable_current(&vm, original)?;
    let exact_active = cloudflare::get_worker_exact_version_module(
        &read_token,
        &desired.target_account_id,
        original
            .worker_id
            .as_deref()
            .ok_or("HOST_VM_WORKER_ID_UNPROVEN")?,
        original
            .worker_active_version_ids
            .first()
            .ok_or("HOST_VM_WORKER_ACTIVE_VERSION_UNPROVEN")?,
    )
    .await?;
    let raw = verified_vm_worker_active_code(&vm, original, &exact_active)?;
    let actual_sha256 = sha256_hex(&raw);
    // Git desired owns the target bytes; Cloudflare's exact active version
    // is simply measured runtime state. Any authenticated drift converges
    // via one fenced upload+deploy, never through predecessor-tag guessing.
    let state = if actual_sha256 == accepted_source.desired {
        ProjectionDeliveryState::FixedAb
    } else {
        ProjectionDeliveryState::FixedAbProofUpgradeRequired
    };
    let after_source = observe(&read_token, desired).await?;
    validate_access_boundary(desired, &after_source)?;
    if after_source.projections != before.projections {
        return Err("HOST_VM_WORKER_PREDECESSOR_READBACK_DRIFT".to_owned());
    }
    println!("host_vm_worker_source_provenance=ACCEPTED_RELEASESET_FULL_SHA256");
    if original.worker_latest_version_id.is_none()
        || original.worker_active_version_ids.as_slice()
            != [original.worker_latest_version_id.as_deref().unwrap_or("")]
    {
        return Err("HOST_VM_WORKER_PENDING_OR_SPLIT_DEPLOYMENT_FORBIDDEN".to_owned());
    }
    let decision = VmWorkerUpgradeDecision::from_verified_state(state).map_err(str::to_owned)?;
    if state == ProjectionDeliveryState::FixedAb {
        if plan_only {
            emit_vm_worker_plan_required(decision)?;
        }
        println!("host_vm_worker_authorizer=SOURCE_ALREADY_ACCEPTED");
        println!("worker_mutations=0");
        println!("host_signed_install=NOT_AUTHORIZED");
        return Ok(());
    }
    if state != ProjectionDeliveryState::FixedAbProofUpgradeRequired {
        return Err("HOST_VM_WORKER_BASELINE_NOT_PROVEN_FOR_CODE_UPGRADE".to_owned());
    }
    if plan_only {
        // Reconcile any previous durable BEGIN against the original protected
        // issue command and a terminal successful Worker owner run. The
        // Cloudflare predecessor source and exact active/latest version were
        // independently proven above; an unknown ACK remains NO_REPLAY.
        crate::vm_worker_begin_reconciliation::verify_prior_vm_worker_begins(machine_id).await?;
        emit_vm_worker_plan_required(decision)?;
        println!("host_vm_worker_authorizer=EXACT_VM_CODE_ONLY_PLAN");
        println!("worker_mutations=0");
        println!("host_signed_install=NOT_AUTHORIZED");
        return Ok(());
    }
    // All eight existing opaque bindings are inherited strictly. An
    // incompletely enrolled Worker is not silently repaired or rekeyed.
    let code_baseline = before.clone();
    // Code upload STRICTLY inherits all eight verified Worker secret names
    // from the current latest version (including the pending secret patch).
    let code_original = projection_observation(&code_baseline, "vm")?;
    require_exact_secret_bindings(&vm.worker_name, "vm", &code_original.worker_secret_bindings)?;
    if !matches!(code_original.worker_binding_count, Some(8 | 9)) {
        return Err("HOST_VM_GITHUB_APP_BINDINGS_NOT_READY".to_owned());
    }
    let source = material;
    let version_id = cloudflare::upload_worker_slot_proof_version(
        &write_token,
        &desired.target_account_id,
        &vm.worker_name,
        &source.version_tag,
        &source.source,
        cloudflare::WorkerCodeBindingScope::VmHostSignerGitHubApp,
        &code_original.worker_secret_bindings,
    )
    .await
    .map_err(|_| "HOST_VM_WORKER_UPLOAD_UNCERTAIN_STOP_NO_REPLAY".to_owned())?;
    let pending_observation = observe(&read_token, desired).await?;
    validate_access_boundary(desired, &pending_observation)?;
    if projection_observation(&before, "windows")?
        != projection_observation(&pending_observation, "windows")?
    {
        return Err("HOST_VM_WORKER_WINDOWS_CHANGED_AFTER_UPLOAD_STOP".to_owned());
    }
    let pending = projection_observation(&pending_observation, "vm")?;
    verify_exact_pending_worker_version(code_original, pending, &version_id)?;
    if pending.worker_latest_version_tag.as_deref() != Some(source.version_tag.as_str()) {
        return Err("HOST_VM_WORKER_PENDING_VERSION_TAG_MISMATCH".to_owned());
    }
    let ack = cloudflare::deploy_worker_version(
        &write_token,
        &desired.target_account_id,
        &vm.worker_name,
        &version_id,
    )
    .await;
    let after = observe(&read_token, desired).await?;
    validate_access_boundary(desired, &after)?;
    if projection_observation(&before, "windows")? != projection_observation(&after, "windows")?
        || verify_exact_active_worker_version(projection_observation(&after, "vm")?, &version_id)
            .is_err()
        || projection_delivery_state(desired, &vm, &after)? != ProjectionDeliveryState::FixedAb
        || !matches!(
            projection_observation(&after, "vm")?.worker_binding_count,
            Some(8 | 9)
        )
    {
        return Err("HOST_VM_WORKER_DEPLOYMENT_NOT_PROVEN_STOP_NO_REPLAY".to_owned());
    }
    // The live bytes, not Cloudflare's version label, prove the deployment.
    let final_vm = projection_observation(&after, "vm")?;
    let exact_deployed = cloudflare::get_worker_exact_version_module(
        &read_token,
        &desired.target_account_id,
        final_vm
            .worker_id
            .as_deref()
            .ok_or("HOST_VM_WORKER_FINAL_ID_UNPROVEN")?,
        &version_id,
    )
    .await?;
    let deployed = verified_vm_worker_active_code(&vm, final_vm, &exact_deployed)?;
    if sha256_hex(&deployed) != accepted_source.desired {
        return Err("HOST_VM_WORKER_ACTIVE_BYTES_MISMATCH_NO_REPLAY".to_owned());
    }
    let after_bytes = observe(&read_token, desired).await?;
    validate_access_boundary(desired, &after_bytes)?;
    if after_bytes.projections != after.projections {
        return Err("HOST_VM_WORKER_SOURCE_READBACK_DRIFT_NO_REPLAY".to_owned());
    }
    if ack.is_err() {
        return Err("HOST_VM_WORKER_DEPLOY_ACK_UNCERTAIN_STOP_FOR_RECONCILIATION".to_owned());
    }
    println!("host_vm_worker_source_readback=EXACT_ACCEPTED_BYTES");
    println!("host_vm_worker_authorizer=CANONICAL_VM_CODE_ACTIVE");
    println!("host_vm_worker_active_version_id={version_id}");
    println!("worker_mutations=2");
    println!("worker_secret_mutations=0");
    println!("windows_worker_mutations=0");
    println!("host_signed_install=NOT_AUTHORIZED");
    Ok(())
}

/// A historical journal is a candidate selector, NEVER proof of active
/// credentials. This read-only native owner must independently retrieve the
/// precise generation through the existing Cloudflare VM Access identity,
/// decode canonical protobuf, and verify non-dummy VM payload + exact digest.
// The first-use credential proof is GET-only. Keep it independent from
// Worker code deployment and signer secret rotation, with the same
// public lifecycle entry points and immutable provenance checks.
#[path = "vm_credential_proof.rs"]
mod vm_credential_proof;
#[cfg(test)]
use vm_credential_proof::{
    attest_vm_first_use_credential_bytes, vm_worker_readonly_proof_git_state,
};
pub(crate) use vm_credential_proof::{
    host_vm_credential_proof, verify_current_vm_first_use_worker_source,
};

/// One existing protected VM Worker authority, with no second signer service.
/// The private Ed25519 key is generated once in the GitHub-hosted protected
/// job and never enters Git, artifacts, stdout or a VM runner. Before COMMIT
/// the workflow reserves a public-key-only draft PR; uncertain provider ACKs
/// terminate the one-shot job and cannot be replayed as a new key.
fn verify_host_signer_job(
    machine_id: &str,
    release: &edge_orchestrator::OrchestrationContext,
) -> Result<(), String> {
    for (key, expected) in [
        ("GITHUB_REPOSITORY", "iamaman11/sing-box"),
        ("GITHUB_REPOSITORY_ID", "1221750822"),
        ("GITHUB_EVENT_NAME", "issue_comment"),
        ("GITHUB_ACTOR_ID", "44100369"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("GITHUB_JOB", "host_worker_authorizer"),
    ] {
        if env::var(key).ok().as_deref() != Some(expected) {
            return Err(format!("HOST_VM_SIGNER_UNTRUSTED_{key}"));
        }
    }
    if env::var("GITHUB_SHA").ok().as_deref() != Some(release.release().accepted_revision.as_str())
        || env::var("HOST_ORIGINAL_COMMAND").ok().as_deref()
            != Some(format!("/host apply {machine_id}").as_str())
    {
        return Err("HOST_VM_SIGNER_GIT_SOURCE_UNTRUSTED".to_owned());
    }
    let host = release.verified_vm_worker_authorizer_host(machine_id)?;
    if host.machine_id != machine_id || !host.worker_authority_public_key.is_empty() {
        return Err("HOST_VM_SIGNER_GIT_KEY_ALREADY_PINNED".to_owned());
    }
    Ok(())
}

fn protected_signer_path(path: &Path) -> Result<(), String> {
    let temp = env::var("RUNNER_TEMP").map_err(|_| "HOST_SIGNER_RUNNER_TEMP_MISSING")?;
    if !path.starts_with(&temp)
        || path.parent() != Some(Path::new(&temp))
        || path.file_name().and_then(|v| v.to_str()).is_none_or(|v| {
            !v.starts_with("host-vm-signer-")
                || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("HOST_SIGNER_PRIVATE_PATH_UNTRUSTED".to_owned());
    }
    Ok(())
}

/// The VM Worker code upgrade already requires eight bindings: two fixed
/// A/B slots, five Host signer settings, and one GitHub App installer key.
/// Never regress to the legacy two-only guard after the exact upgrade.
/// Protect all eight names AND the active accepted module bytes before any
/// new signer key is generated or any secret rotation is attempted.
fn verify_exact_vm_signer_source(
    desired: &ProductionCredentialPlaneOwnership,
    before: &CredentialPlaneObservation,
    release_module_sha256: &str,
    active_module_bytes: &[u8],
) -> Result<(), String> {
    let vm = projection_desired(desired, "vm")?;
    let source = projection_observation(before, "vm")?;
    if projection_delivery_state(desired, &vm, before)? != ProjectionDeliveryState::FixedAb
        || !matches!(source.worker_binding_count, Some(8 | 9))
        || source.worker_secret_bindings.len() != source.worker_binding_count.unwrap_or_default()
        || source.worker_latest_version_id.as_deref()
            != source.worker_active_version_ids.first().map(String::as_str)
        || source.worker_active_version_ids.len() != 1
    {
        return Err("HOST_SIGNER_VM_WORKER_NOT_EXACT_EIGHT_ACTIVE".to_owned());
    }
    require_exact_secret_bindings(&vm.worker_name, "vm", &source.worker_secret_bindings)?;
    if sha256_hex(active_module_bytes) != release_module_sha256 {
        return Err("HOST_SIGNER_VM_WORKER_SOURCE_NOT_ACCEPTED_RELEASE".to_owned());
    }
    Ok(())
}

async fn checked_host_signer_vm(
    machine_id: &str,
    release: &edge_orchestrator::OrchestrationContext,
) -> Result<
    (
        edge_controller_core::production::ProductionComposition,
        CredentialPlaneObservation,
    ),
    String,
> {
    verify_host_signer_job(machine_id, release)?;
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = &production.cloudflare.credential_plane;
    if production.cloudflare.active_account_id != desired.target_account_id
        || production.cloudflare.migration_target_account_id.is_some()
    {
        return Err("HOST_SIGNER_PRODUCTION_ACCOUNT_MISMATCH".to_owned());
    }
    let read = required_env("CLOUDFLARE_CONTROL_TOKEN")?;
    let before = observe(&read, desired).await?;
    validate_access_boundary(desired, &before)?;
    let accepted = accepted_vm_worker_source(release)?;
    let module = cloudflare::get_worker_active_module_bytes(
        &read,
        &desired.target_account_id,
        &desired.vm_worker_name,
    )
    .await?;
    verify_exact_vm_signer_source(desired, &before, &accepted.desired, &module)?;
    Ok((production, before))
}

pub(crate) async fn host_vm_signer_prepare(
    machine_id: &str,
    release: &edge_orchestrator::OrchestrationContext,
    key_path: &Path,
    public_path: &Path,
) -> Result<(), String> {
    protected_signer_path(key_path)?;
    protected_signer_path(public_path)?;
    if key_path == public_path {
        return Err("HOST_SIGNER_OUTPUT_COLLISION".to_owned());
    }
    // All live read-only preflight must pass before generating anything
    // secret. The key is ephemeral until the exact protected Git draft exists.
    let _ = checked_host_signer_vm(machine_id, release).await?;
    let random = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&random)
        .map_err(|_| "HOST_SIGNER_ED25519_GENERATE_FAILED")?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "HOST_SIGNER_ED25519_SELF_VERIFY_FAILED")?;
    use ring::signature::KeyPair;
    let public = pair
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut secret = options
        .open(key_path)
        .map_err(|_| "HOST_SIGNER_EPHEMERAL_KEY_EXISTS_OR_UNWRITABLE")?;
    use std::io::Write;
    secret
        .write_all(pkcs8.as_ref())
        .and_then(|_| secret.sync_all())
        .map_err(|_| "HOST_SIGNER_EPHEMERAL_KEY_WRITE_FAILED")?;
    fs::write(public_path, format!("{public}\n"))
        .map_err(|_| "HOST_SIGNER_PUBLIC_KEY_WRITE_FAILED")?;
    println!("host_vm_signer=EPHEMERAL_PRIVATE_PROTECTED_PUBLIC_DRAFT_REQUIRED");
    println!("host_vm_signer_public_key_hex={public}");
    println!("worker_mutations=0");
    Ok(())
}

pub(crate) async fn host_vm_signer_commit(
    machine_id: &str,
    release: &edge_orchestrator::OrchestrationContext,
    key_path: &Path,
    public_path: &Path,
) -> Result<(), String> {
    protected_signer_path(key_path)?;
    protected_signer_path(public_path)?;
    let reservation = env::var("HOST_SIGNER_RESERVATION_SHA")
        .map_err(|_| "HOST_SIGNER_GIT_RESERVATION_REQUIRED")?;
    if reservation.len() != 40
        || !reservation
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("HOST_SIGNER_GIT_RESERVATION_INVALID".to_owned());
    }
    let (production, before) = checked_host_signer_vm(machine_id, release).await?;
    let desired = &production.cloudflare.credential_plane;
    let vm = projection_observation(&before, "vm")?;
    let id = vm
        .access_application_id
        .as_deref()
        .ok_or("HOST_SIGNER_ACCESS_APP_REQUIRED")?;
    let read = required_env("CLOUDFLARE_CONTROL_TOKEN")?;
    let write = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
    let authority = cloudflare::verify_api_token(&write).await?;
    if authority.status != "active" || authority.id == before.control_token_identity.id {
        return Err("HOST_SIGNER_DISTINCT_CLOUDFLARE_WRITE_OWNER_REQUIRED".to_owned());
    }
    let aud =
        cloudflare::get_access_application_audience(&read, &desired.target_account_id, id).await?;
    let auth = before
        .access_organization
        .as_ref()
        .ok_or("HOST_SIGNER_ACCESS_ORGANIZATION_MISSING")?;
    let issuer = format!("https://{}", auth.auth_domain);
    if !issuer.ends_with(".cloudflareaccess.com") || !issuer.starts_with("https://") {
        return Err("HOST_SIGNER_ACCESS_ISSUER_INVALID".to_owned());
    }
    let metadata =
        fs::symlink_metadata(key_path).map_err(|_| "HOST_SIGNER_EPHEMERAL_KEY_MISSING")?;
    if !metadata.file_type().is_file() || metadata.len() > 256 || metadata.len() < 40 {
        return Err("HOST_SIGNER_EPHEMERAL_KEY_INVALID".to_owned());
    }
    let bytes = fs::read(key_path).map_err(|_| "HOST_SIGNER_EPHEMERAL_KEY_UNREADABLE")?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&bytes)
        .map_err(|_| "HOST_SIGNER_EPHEMERAL_KEY_NOT_ED25519")?;
    use ring::signature::KeyPair;
    let pub_hex = pair
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let stored_public =
        fs::read_to_string(public_path).map_err(|_| "HOST_SIGNER_PUBLIC_KEY_UNREADABLE")?;
    if stored_public != format!("{pub_hex}\n") {
        return Err("HOST_SIGNER_EPHEMERAL_PUBLIC_MISMATCH".to_owned());
    }
    let public_hash = sha256_hex(pair.public_key().as_ref());
    let key_id = format!("vm-host-{}", &public_hash[..16]);
    use base64::Engine as _;
    // The existing Worker B64() intentionally accepts ONLY the URL-safe
    // alphabet [A-Za-z0-9_-], not standard Base64 '+' or '/'. Encode PKCS8
    // exactly once with that contract; otherwise most randomly generated
    // signer keys are accepted by Cloudflare as secrets but rejected at
    // signing time (HTTP 503).
    let private_b64 = encode_worker_host_signer_pkcs8(&bytes);
    let actor = "44100369";
    // Five fixed secret names. Cloudflare merge-patches the currently
    // accepted EIGHT-binding version: preserve opaque A/B and GitHub App,
    // replacing only this VM's five Host signer keys. Never POST credentials.
    let bindings = [
        ("EDGE_HOST_SIGNING_PKCS8_BASE64", private_b64.as_str()),
        ("EDGE_HOST_SIGNING_KEY_ID", key_id.as_str()),
        ("EDGE_HOST_GITHUB_ACTOR_ID", actor),
        ("EDGE_HOST_ACCESS_ISSUER", issuer.as_str()),
        ("EDGE_HOST_ACCESS_AUD", aud.as_str()),
    ];
    let material = delivery_worker_material("vm")?;
    let version = cloudflare::patch_latest_worker_version_secrets(
        &write,
        &desired.target_account_id,
        &desired.vm_worker_name,
        &material.version_tag,
        &bindings,
    )
    .await
    .map_err(|_| "HOST_SIGNER_SECRET_WRITE_UNCERTAIN_NO_REPLAY".to_owned())?;
    let after_patch = observe(&read, desired)
        .await
        .map_err(|_| "HOST_SIGNER_WRITE_ACK_READBACK_UNCERTAIN_NO_REPLAY".to_owned())?;
    let vm_after = projection_observation(&after_patch, "vm")?;
    if projection_observation(&before, "windows")?
        != projection_observation(&after_patch, "windows")?
        || vm_after.worker_latest_version_id.as_deref() != Some(version.as_str())
        || !matches!(vm_after.worker_binding_count, Some(8 | 9))
        || vm_after.worker_secret_bindings.len()
            != vm_after.worker_binding_count.unwrap_or_default()
    {
        return Err("HOST_SIGNER_POST_WRITE_DRIFT_NO_REPLAY".to_owned());
    }
    require_exact_secret_bindings(
        &desired.vm_worker_name,
        "vm",
        &vm_after.worker_secret_bindings,
    )?;
    if vm_after.worker_active_version_ids != vec![version.clone()] {
        cloudflare::deploy_worker_version(
            &write,
            &desired.target_account_id,
            &desired.vm_worker_name,
            &version,
        )
        .await
        .map_err(|_| "HOST_SIGNER_DEPLOY_ACK_UNCERTAIN_NO_REPLAY".to_owned())?;
    }
    let final_read = observe(&read, desired)
        .await
        .map_err(|_| "HOST_SIGNER_FINAL_READ_UNCERTAIN_NO_REPLAY".to_owned())?;
    let final_vm = projection_observation(&final_read, "vm")?;
    if projection_observation(&before, "windows")?
        != projection_observation(&final_read, "windows")?
        || final_vm.worker_latest_version_id.as_deref() != Some(version.as_str())
        || final_vm.worker_active_version_ids != vec![version.clone()]
        || !matches!(final_vm.worker_binding_count, Some(8 | 9))
        || projection_delivery_state(desired, &projection_desired(desired, "vm")?, &final_read)?
            != ProjectionDeliveryState::FixedAb
    {
        return Err("HOST_SIGNER_ACTIVE_READBACK_UNCERTAIN_NO_REPLAY".to_owned());
    }
    println!("host_vm_signer=FIVE_BINDINGS_ACTIVE_PUBLIC_GIT_DRAFT");
    println!("host_vm_signer_public_key_hex={pub_hex}");
    println!("host_vm_signer_version_id={version}");
    println!("host_signed_install=NOT_AUTHORIZED");
    println!("windows_worker_mutations=0");
    println!("host_vm_create=NOT_AUTHORIZED");
    Ok(())
}

/// A code-only compatibility update *within the same* canonical initial VM
/// operation, before the first-use credential BEGIN. Neither secret values nor
/// new credential material are generated by this operation. Unknown Cloudflare
/// upload/deploy ACKs always end the run without replay.
async fn initial_worker_proof_upgrade(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    release_context: &edge_orchestrator::OrchestrationContext,
    run_id: u64,
    journal_history_path: &Path,
    exact_record_path: &Path,
) -> Result<(), String> {
    if env::var("GITHUB_RUN_ID").ok().as_deref() != Some(run_id.to_string().as_str()) {
        return Err("Worker proof mutation refuses foreign GitHub run".to_owned());
    }
    let history = fs::read_to_string(journal_history_path)
        .map_err(|_| "Worker proof mutation cannot read complete issue history".to_owned())?;
    let exact = fs::read_to_string(exact_record_path)
        .map_err(|_| "Worker proof mutation cannot read exact BEGIN".to_owned())?;
    let record = worker_proof_record(&history, Some(&exact))?
        .ok_or_else(|| "Worker proof mutation has no durable BEGIN".to_owned())?;
    if record.github_run_id != run_id
        || record.source_revision != release_context.release().source_revision
        || record.release_set_sha256 != release_context.release().release_set_sha256
    {
        return Err("Worker proof BEGIN differs from run or ReleaseSet".to_owned());
    }
    for (key, expected) in [
        ("GITHUB_REPOSITORY", "iamaman11/sing-box"),
        ("GITHUB_REPOSITORY_ID", "1221750822"),
        ("GITHUB_EVENT_NAME", "issue_comment"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("GITHUB_JOB", "initial_worker_proof_upgrade"),
    ] {
        if env::var(key).ok().as_deref() != Some(expected) {
            return Err(format!("Worker proof migration refuses untrusted {key}"));
        }
    }
    if env::var("GITHUB_SHA").ok().as_deref()
        != Some(release_context.release().accepted_revision.as_str())
    {
        return Err("Worker proof migration requires exact accepted GitHub release".to_owned());
    }
    let first = observe(control_token, desired).await?;
    validate_access_boundary(desired, &first)?;
    let intended = worker_proof_baseline_sha256(desired, &first, release_context, run_id)?;
    if intended != record.baseline_sha256 {
        return Err("Worker proof baseline differs from durable GitHub BEGIN".to_owned());
    }
    // Full read-only preflight before the FIRST provider mutation. An
    // unexpected pending version or a foreign tag in EITHER Worker blocks both.
    for projection in projections(desired) {
        let state = projection_delivery_state(desired, &projection, &first)?;
        if !matches!(
            state,
            ProjectionDeliveryState::FixedAbProofUpgradeRequired | ProjectionDeliveryState::FixedAb
        ) {
            return Err(format!(
                "{} Worker proof migration rejects nonterminal baseline",
                projection.projection
            ));
        }
        let obs = projection_observation(&first, &projection.projection)?;
        if obs.worker_latest_version_id.is_none()
            || obs.worker_active_version_ids.as_slice()
                != [obs.worker_latest_version_id.as_deref().unwrap_or("")]
        {
            return Err(format!(
                "{} Worker proof migration requires exactly one active latest version",
                projection.projection
            ));
        }
    }
    let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
    let mutation_identity = cloudflare::verify_api_token(&rotation_token).await?;
    if mutation_identity.status != "active"
        || mutation_identity.id == first.control_token_identity.id
    {
        return Err(
            "Worker code migration requires distinct active least-privilege write identity"
                .to_owned(),
        );
    }
    let mut changed = 0u32;
    let mut exact_uploaded_versions: BTreeMap<String, String> = BTreeMap::new();
    for projection in projections(desired) {
        let current = observe(control_token, desired).await?;
        // Re-check BOTH Workers before every write, never trust the initial
        // observation if another owner modified version or bindings.
        validate_access_boundary(desired, &current)?;
        for p in projections(desired) {
            let state = projection_delivery_state(desired, &p, &current)?;
            if !matches!(
                state,
                ProjectionDeliveryState::FixedAbProofUpgradeRequired
                    | ProjectionDeliveryState::FixedAb
            ) {
                return Err(format!(
                    "{} unexpected Worker state before code-only upgrade",
                    p.projection
                ));
            }
            let observed = projection_observation(&current, &p.projection)?;
            if let Some(expected) = exact_uploaded_versions.get(&p.projection) {
                verify_exact_active_worker_version(observed, expected)?;
                if state != ProjectionDeliveryState::FixedAb {
                    return Err(format!("{} Worker lost upgraded proof code", p.projection));
                }
            } else if observed != projection_observation(&first, &p.projection)? {
                return Err(format!(
                    "{} Worker version, bindings or Access identity drifted from durable BEGIN; STOP",
                    p.projection
                ));
            }
        }
        let state = projection_delivery_state(desired, &projection, &current)?;
        if state == ProjectionDeliveryState::FixedAb {
            continue;
        }
        if state != ProjectionDeliveryState::FixedAbProofUpgradeRequired {
            return Err("Worker code-only migration has an ambiguous baseline".to_owned());
        }
        let old = projection_observation(&current, &projection.projection)?;
        let material = delivery_worker_material(&projection.projection)?;
        // Match the full live secret set before code upload. VM is the ONLY
        // projection allowed to inherit Host signing bindings. A stale caller
        // must not silently replace a seven-binding Worker with just A/B.
        let binding_scope = match (
            projection.projection.as_str(),
            old.worker_secret_bindings.len(),
        ) {
            ("vm", 7) => cloudflare::WorkerCodeBindingScope::VmHostSigner,
            ("vm", 8) => cloudflare::WorkerCodeBindingScope::VmHostSignerGitHubApp,
            ("vm", 9) => cloudflare::WorkerCodeBindingScope::VmHostSignerRouteAccess,
            ("vm" | "windows", 2) => cloudflare::WorkerCodeBindingScope::FixedAb,
            _ => return Err("WORKER_CODE_BINDINGS_NOT_EXACT_PROJECTION_SCOPE".to_owned()),
        };
        let version_id = cloudflare::upload_worker_slot_proof_version(
            &rotation_token,
            &desired.target_account_id,
            &projection.worker_name,
            &material.version_tag,
            &material.source,
            binding_scope,
            &old.worker_secret_bindings,
        )
        .await
        .map_err(|_| format!(
            "{} code-only upload result uncertain: STOP without retry,              inspect exact latest Worker version and A/B metadata",
            projection.projection
        ))?;
        changed += 1;
        let pending_observation = observe(control_token, desired).await?;
        let pending = projection_observation(&pending_observation, &projection.projection)?;
        verify_exact_pending_worker_version(old, pending, &version_id)?;
        if pending.worker_latest_version_tag.as_deref() != Some(&material.version_tag) {
            return Err(format!(
                "{} new proof version tag is not exact; do not deploy",
                projection.projection
            ));
        }
        let deployment = cloudflare::deploy_worker_version(
            &rotation_token,
            &desired.target_account_id,
            &projection.worker_name,
            &version_id,
        )
        .await;
        let deployed = observe(control_token, desired).await?;
        let active = projection_observation(&deployed, &projection.projection)?;
        if verify_exact_active_worker_version(active, &version_id).is_err()
            || projection_delivery_state(desired, &projection, &deployed)?
                != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} code-only deployment not exactly confirmed;                  STOP without replay; uncertain_ack={}",
                projection.projection,
                deployment.is_err()
            ));
        }
        if deployment.is_err() {
            return Err(format!(
                "{} Worker code-only deployment ACK uncertain but exact active version observed;                  stop for read-only reconciliation before any further provider mutation",
                projection.projection
            ));
        }
        exact_uploaded_versions.insert(projection.projection.clone(), version_id);
    }
    let after = observe(control_token, desired).await?;
    for projection in projections(desired) {
        if projection_delivery_state(desired, &projection, &after)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} Worker proof migration did not converge to exact A/B contract",
                projection.projection
            ));
        }
    }
    println!("operation=CREDENTIAL_INITIAL_WORKER_PROOF_UPGRADE");
    println!("worker_proof_durable_begin=EXACT_READBACK");
    println!("worker_code_only_mutations={changed}");
    println!("worker_secret_bindings_inherited_strict=true");
    println!("worker_secret_patch_mutations=0");
    println!("worker_actual_binding_dummy=UNPROVEN_BY_PROVIDER_METADATA");
    println!("host_exact_binding_attestations=REQUIRED");
    println!("first_use_credential_publication_authorized=false");
    Ok(())
}

async fn initial_pair_preflight(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    generation: u64,
    slot: CredentialDeliverySlotArg,
) -> Result<(), String> {
    let observed = observe(control_token, desired).await?;
    let provider_intent_sha256 =
        initial_pair_provider_intent_sha256(desired, &observed, generation, slot)?;
    // The provider-side plan is read-only. Re-observe once and fail if either
    // Worker version or Access identity changed in the meantime. No polling
    // and, in particular, no mutation authority is implied.
    let reobserved = observe(control_token, desired).await?;
    let confirmed_sha256 =
        initial_pair_provider_intent_sha256(desired, &reobserved, generation, slot)?;
    if provider_intent_sha256 != confirmed_sha256 {
        return Err(
            "initial paired provider intent drifted during read-only re-observation".to_owned(),
        );
    }
    println!("operation=CREDENTIAL_INITIAL_PAIR_PREFLIGHT");
    println!("credential_generation={generation}");
    println!("credential_slot={}", slot.as_str());
    println!("worker_projection_count=2");
    println!("provider_topology=EXACT_FIXED_AB");
    println!("vm_access_identity_distinct=true");
    println!("windows_access_identity_distinct=true");
    println!("initial_pair_provider_intent_sha256={provider_intent_sha256}");
    println!("initial_pair_provider_version_barrier=READ_ONLY_REOBSERVED");
    println!("host_dummy_slot_attestations=REQUIRED");
    println!("worker_version_bound_publish=GATED_BY_TWO_HOSTS_AND_DURABLE_BEGIN");
    println!("provider_attempt_journal=NOT_RECORDED");
    println!("initial_publication_authorized=false");
    println!("credential_provider_mutations=0");
    println!("credential_runtime_mutations=0");
    Ok(())
}

/// This is the provider half of ONE first-use attempt, reachable only
/// through the verified same-run disposable VM, Windows and GitHub BEGIN
/// owners in the canonical Vultr lifecycle workflow.
async fn initial_pair_publish(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    release_context: &edge_orchestrator::OrchestrationContext,
    request: InitialPairJournalPlan,
    slot: CredentialDeliverySlotArg,
    journal_history_path: &Path,
    exact_record_path: &Path,
) -> Result<(), String> {
    // Never allow a local shell, a re-run, or a different repository/actor
    // to turn this source capability into an independent issuer.
    for (key, expected) in [
        ("GITHUB_REPOSITORY", "iamaman11/sing-box"),
        ("GITHUB_REPOSITORY_ID", "1221750822"),
        ("GITHUB_ACTOR_ID", "44100369"),
        ("GITHUB_EVENT_NAME", "issue_comment"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("GITHUB_JOB", "initial_pair_publish"),
    ] {
        if env::var(key).ok().as_deref() != Some(expected) {
            return Err(format!("initial pair publisher refuses untrusted {key}"));
        }
    }
    if env::var("GITHUB_RUN_ID").ok().as_deref() != Some(request.github_run_id.to_string().as_str())
        || env::var("GITHUB_SHA").ok().as_deref()
            != Some(release_context.release().accepted_revision.as_str())
    {
        return Err(
            "initial pair publisher refuses a mismatched GitHub run or source revision".to_owned(),
        );
    }

    // A complete GitHub BEGIN must be durably persisted and independently
    // read back before either Worker is patched. A supplied digest is never
    // a substitute for this exact readback.
    let history = fs::read_to_string(journal_history_path)
        .map_err(|err| format!("initial publish cannot read GitHub history: {err}"))?;
    let exact_record = fs::read_to_string(exact_record_path)
        .map_err(|err| format!("initial publish cannot read persisted BEGIN: {err}"))?;
    verify_expected_initial_attempt(&history, &exact_record, &request)?;
    if request.release_source_revision != release_context.release().source_revision
        || request.release_set_sha256 != release_context.release().release_set_sha256
    {
        return Err("initial publish refuses non-exact immutable ReleaseSet authority".to_owned());
    }

    let before = observe(control_token, desired).await?;
    let current_intent =
        initial_pair_provider_intent_sha256(desired, &before, request.generation, slot)?;
    if current_intent != request.provider_intent_sha256 {
        return Err("initial publish refuses changed Worker version/Access baseline".to_owned());
    }
    let previous_version = |projection: &str| -> Result<String, String> {
        let observed = projection_observation(&before, projection)?;
        observed
            .worker_latest_version_id
            .clone()
            .ok_or_else(|| format!("{projection} has no expected initial version"))
    };
    let vm_previous = previous_version("vm")?;
    let windows_previous = previous_version("windows")?;

    // Only this separate Cloudflare token can mutate Worker versions.
    let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
    let rotation_identity = cloudflare::verify_api_token(&rotation_token).await?;
    if rotation_identity.status != "active"
        || rotation_identity.id == before.control_token_identity.id
    {
        return Err(
            "initial publish requires distinct active least-privilege mutation token".to_owned(),
        );
    }
    let delivery_slot = match slot {
        CredentialDeliverySlotArg::A => CredentialDeliverySlot::A,
        CredentialDeliverySlotArg::B => CredentialDeliverySlot::B,
    };
    let snapshot = generate_fresh_credential_snapshot(FreshCredentialSnapshotRequest {
        delivery_generation: request.generation,
        slot: delivery_slot,
        tunnel_auth_generation: request.generation,
        reality_identity_generation: request.generation,
        line2_proxy_generation: request.generation,
    })?;
    let slot_name = match delivery_slot {
        CredentialDeliverySlot::A => SLOT_A,
        CredentialDeliverySlot::B => SLOT_B,
        CredentialDeliverySlot::Unspecified => unreachable!("validated first-use slot"),
    };
    let vm = projection_desired(desired, "vm")?;
    let windows = projection_desired(desired, "windows")?;
    let vm_secret = hex_encode(&snapshot.vm.encode_to_vec());
    let windows_secret = hex_encode(&snapshot.windows.encode_to_vec());

    // Deliberately sequential: cross-Worker atomicity does not exist.
    // A failed/unknown first PATCH or deployment aborts the transaction.
    // New secrets are generated exactly once and never regenerated on retry.
    let vm_published_version = publish_rotation_slot(
        control_token,
        &rotation_token,
        desired,
        &vm,
        slot_name,
        &vm_secret,
        Some(&vm_previous),
    )
    .await?;
    let after_vm = observe(control_token, desired).await?;
    if projection_observation(&after_vm, "windows")?
        .worker_latest_version_id
        .as_deref()
        != Some(windows_previous.as_str())
        || verify_exact_active_worker_version(
            projection_observation(&after_vm, "vm")?,
            &vm_published_version,
        )
        .is_err()
    {
        return Err(
            "initial paired publish observed an unexpected intermediate Worker version".to_owned(),
        );
    }
    let windows_published_version = publish_rotation_slot(
        control_token,
        &rotation_token,
        desired,
        &windows,
        slot_name,
        &windows_secret,
        Some(&windows_previous),
    )
    .await?;
    let after = observe(control_token, desired).await?;
    for (projection, expected_version) in [
        (&vm, vm_published_version.as_str()),
        (&windows, windows_published_version.as_str()),
    ] {
        if projection_delivery_state(desired, projection, &after)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} initial publish lost the exact fixed A/B topology",
                projection.projection
            ));
        }
        verify_exact_active_worker_version(
            projection_observation(&after, &projection.projection)?,
            expected_version,
        )?;
    }
    println!("credential_initial_pair_provider_publish=PASS");
    println!("credential_generation={}", request.generation);
    println!("credential_slot={}", slot.as_str());
    println!("paired_projection_count=2");
    println!("credential_initial_begin_record=EXACT_READBACK");
    println!("credential_initial_consumer_authentication=UNPROVEN");
    println!("credential_initial_external_line1_4_of_4=UNPROVEN");
    println!("credential_initial_external_line2_6_of_6=UNPROVEN");
    Ok(())
}

async fn rotate_application_publish(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    class: CredentialRotationClassArg,
    active_generation: u64,
    generation: u64,
    slot: CredentialDeliverySlotArg,
) -> Result<(), String> {
    if active_generation == 0 || generation == 0 || active_generation == generation {
        return Err(
            "steady-state credential rotation requires distinct non-zero active and candidate generations"
                .to_owned(),
        );
    }

    let before = observe(control_token, desired).await?;
    validate_access_boundary(desired, &before)?;
    for projection in projections(desired) {
        if projection_delivery_state(desired, &projection, &before)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} credential Worker must be in exact fixed A/B state before rotation",
                projection.projection
            ));
        }
    }

    let rotation_token = required_env("CLOUDFLARE_CREDENTIAL_ROTATION_TOKEN")?;
    let rotation_identity = cloudflare::verify_api_token(&rotation_token).await?;
    if rotation_identity.status != "active" {
        return Err(format!(
            "credential-rotation token {} is not active: {}",
            rotation_identity.id, rotation_identity.status
        ));
    }
    if rotation_identity.id == before.control_token_identity.id {
        return Err(
            "credential-rotation token must be physically distinct from CLOUDFLARE_CONTROL_TOKEN"
                .to_owned(),
        );
    }

    let candidate_slot = match slot {
        CredentialDeliverySlotArg::A => CredentialDeliverySlot::A,
        CredentialDeliverySlotArg::B => CredentialDeliverySlot::B,
    };
    let rotation_class = match class {
        CredentialRotationClassArg::TunnelAuth => CredentialRotationClass::TunnelAuth,
        CredentialRotationClassArg::RealityIdentity => CredentialRotationClass::RealityIdentity,
        CredentialRotationClassArg::Line2ProxyAuth => CredentialRotationClass::Line2ProxyAuth,
    };
    let snapshot = generate_rotation_credential_snapshot(RotateCredentialSnapshotRequest {
        delivery_generation: generation,
        slot: candidate_slot,
        class: rotation_class,
    })?;

    let slot_name = match candidate_slot {
        CredentialDeliverySlot::A => SLOT_A,
        CredentialDeliverySlot::B => SLOT_B,
        CredentialDeliverySlot::Unspecified => unreachable!("validated candidate slot"),
    };
    let vm = projection_desired(desired, "vm")?;
    let windows = projection_desired(desired, "windows")?;
    let vm_secret = hex_encode(&snapshot.vm.encode_to_vec());
    let windows_secret = hex_encode(&snapshot.windows.encode_to_vec());

    publish_rotation_slot(
        control_token,
        &rotation_token,
        desired,
        &vm,
        slot_name,
        &vm_secret,
        None,
    )
    .await?;
    publish_rotation_slot(
        control_token,
        &rotation_token,
        desired,
        &windows,
        slot_name,
        &windows_secret,
        None,
    )
    .await?;

    println!("credential_rotation_provider_publish=PASS");
    println!("credential_rotation_class={}", class.as_str());
    println!("credential_active_generation={active_generation}");
    println!("credential_generation={generation}");
    println!("credential_slot={}", slot.as_str());
    println!("paired_projection_count=2");
    println!("active_slot_mutated=false");
    println!("credential_rotation_delivery=CLASS_SCOPED_DELTA");
    println!("active_credential_plaintext_readback=false");
    println!("candidate_data_plane_reobservation=LOCAL_OWNERS");
    println!("self_hosted_runtime_runner_plaintext_access=false");
    Ok(())
}

async fn publish_rotation_slot(
    control_token: &str,
    rotation_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
    slot_name: &str,
    secret_text: &str,
    expected_latest_version: Option<&str>,
) -> Result<String, String> {
    let before = observe(control_token, desired).await?;
    let before_projection = projection_observation(&before, &projection.projection)?;
    if projection_delivery_state(desired, projection, &before)? != ProjectionDeliveryState::FixedAb
    {
        return Err(format!(
            "{} credential Worker drifted before inactive-slot publication",
            projection.projection
        ));
    }
    if expected_latest_version.is_some_and(|version| {
        before_projection.worker_latest_version_id.as_deref() != Some(version)
            || before_projection.worker_active_version_ids.as_slice() != [version]
    }) {
        return Err(format!(
            "{} initial publication refuses stale Worker baseline before PATCH",
            projection.projection
        ));
    }
    let material = delivery_worker_material(&projection.projection)?;

    let version_id = match cloudflare::patch_latest_worker_version_secrets(
        rotation_token,
        &desired.target_account_id,
        &projection.worker_name,
        &material.version_tag,
        &[(slot_name, secret_text)],
    )
    .await
    {
        Ok(version_id) => version_id,
        Err(err) => {
            // Cloudflare hides secret values from GET. A new version is not
            // proof that *our* exact opaque bytes landed. Neither retry the
            // PATCH nor deploy an unverified candidate after a lost ACK.
            let readback = observe(control_token, desired).await;
            let evidence = match readback {
                Ok(observed) => {
                    let current = projection_observation(&observed, &projection.projection)?;
                    if current.worker_latest_version_id
                        == before_projection.worker_latest_version_id
                    {
                        "LATEST_VERSION_UNCHANGED"
                    } else {
                        "LATEST_VERSION_CHANGED_CONTENT_UNPROVEN"
                    }
                }
                Err(_) => "READBACK_UNAVAILABLE",
            };
            return Err(format!(
                "{} inactive-slot PATCH result is not confirmed; evidence={evidence}; stop without replay or deploy; source={err}",
                projection.projection
            ));
        }
    };

    if before_projection.worker_latest_version_id.as_deref() == Some(version_id.as_str()) {
        return Err(format!(
            "{} provider returned unchanged version after secret PATCH",
            projection.projection
        ));
    }
    // A successful PATCH ACK alone does not authorize POST deployment:
    // Cloudflare's mutable /versions/latest has no demonstrated atomic
    // compare-and-swap against our original Worker version. Observe the
    // returned new version and unchanged old deployment exactly once.
    let before_deploy = observe(control_token, desired).await?;
    let pending = projection_observation(&before_deploy, &projection.projection)?;
    verify_exact_pending_worker_version(before_projection, pending, &version_id)?;

    let deploy_once = cloudflare::deploy_worker_version(
        rotation_token,
        &desired.target_account_id,
        &projection.worker_name,
        &version_id,
    )
    .await;
    if let Err(first_err) = deploy_once {
        let observed = observe(control_token, desired).await?;
        let current = projection_observation(&observed, &projection.projection)?;
        if verify_exact_active_worker_version(current, &version_id).is_ok() {
            return Ok(version_id);
        }
        // Re-observation may confirm deployment succeeded, but it cannot
        // authorize a second mutation when the first ACK was uncertain.
        return Err(format!(
            "{} candidate deployment not confirmed for exact version {}; stop without replay; source={first_err}",
            projection.projection, version_id
        ));
    }

    let after = observe(control_token, desired).await?;
    if projection_delivery_state(desired, projection, &after)? != ProjectionDeliveryState::FixedAb {
        return Err(format!(
            "{} credential Worker did not return to exact fixed A/B topology after candidate deployment",
            projection.projection
        ));
    }
    verify_exact_active_worker_version(
        projection_observation(&after, &projection.projection)?,
        &version_id,
    )?;
    Ok(version_id)
}

/// Read-only compare of the exact PATCH result immediately before deploying it.
/// This limits undetected races, but Cloudflare /versions/latest is not a CAS:
/// provider changes between this GET and our POST still require host readback.
fn verify_exact_pending_worker_version(
    before: &ProjectionObservation,
    pending: &ProjectionObservation,
    returned_version: &str,
) -> Result<(), String> {
    if returned_version.trim().is_empty()
        || before.worker_latest_version_id.as_deref() == Some(returned_version)
        || pending.worker_latest_version_id.as_deref() != Some(returned_version)
        || pending.worker_active_version_ids != before.worker_active_version_ids
        || pending.worker_active_deployment_id != before.worker_active_deployment_id
        || pending.worker_id != before.worker_id
        || pending.worker_name != before.worker_name
        || pending.worker_secret_bindings != before.worker_secret_bindings
        || pending.worker_binding_count != before.worker_binding_count
    {
        return Err(format!(
            "{} Worker PATCH readback is ambiguous or drifted; do not deploy or replay",
            before.projection
        ));
    }
    Ok(())
}

fn verify_exact_active_worker_version(
    current: &ProjectionObservation,
    expected_version: &str,
) -> Result<(), String> {
    if expected_version.trim().is_empty()
        || current.worker_latest_version_id.as_deref() != Some(expected_version)
        || current.worker_active_version_ids.as_slice() != [expected_version]
        || current.worker_active_deployment_id.is_none()
    {
        return Err(format!(
            "{} Worker deployment lacks exact active/latest version; do not replay",
            current.projection
        ));
    }
    Ok(())
}

pub(crate) async fn verify_credential_plane_invariant() -> Result<(), String> {
    let control_token = required_env("CLOUDFLARE_CONTROL_TOKEN")?;
    let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let desired = &production.cloudflare.credential_plane;
    let observed = observe(&control_token, desired).await?;

    validate_access_boundary(desired, &observed)?;
    for projection in projections(desired) {
        projection_delivery_state(desired, &projection, &observed)?;
    }
    Ok(())
}

fn write_private_bootstrap_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("bootstrap secret output must not be empty".to_owned());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create bootstrap output directory: {err}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|err| format!("failed to create bootstrap secret output: {err}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("failed to persist bootstrap secret output: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to protect bootstrap secret output: {err}"))?;
    }
    Ok(())
}

fn validate_host_bootstrap_preconditions(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(), String> {
    if observed.control_token_identity.status != "active" {
        return Err("CLOUDFLARE_CONTROL_TOKEN is not active".to_owned());
    }
    let organization = observed
        .access_organization
        .as_ref()
        .ok_or_else(|| "accepted Access organization is missing".to_owned())?;
    if organization.name != desired.access_organization_name
        || organization.auth_domain != desired.access_auth_domain
        || organization.deny_unmatched_requests != Some(true)
    {
        return Err("credential Access organization drifted".to_owned());
    }
    if observed.workers_dev_subdomain.as_deref() != Some(desired.workers_dev_subdomain.as_str()) {
        return Err("credential workers.dev namespace drifted".to_owned());
    }

    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        if projection_delivery_state(desired, &projection, observed)?
            != ProjectionDeliveryState::FixedAb
        {
            return Err(format!(
                "{} credential Worker must already be exact FIXED_A_B before host bootstrap",
                projection.projection
            ));
        }
        if !current.worker_script_present
            || !current.worker_identity_present
            || current.custom_domain_count != 0
            || current.workers_dev_enabled != Some(true)
            || current.previews_enabled != Some(false)
        {
            return Err(format!(
                "{} credential Worker drifted from workers.dev-only authority",
                projection.projection
            ));
        }

        if current.host_service_token_id.is_some()
            && (current.host_service_token_enabled != Some(true)
                || current.host_service_token_duration.as_deref()
                    != Some(desired.host_service_token_duration.as_str()))
        {
            return Err(format!(
                "{} existing host service token drifted",
                projection.projection
            ));
        }

        let expected_hostname = workers_dev_hostname(desired, &projection);
        if current
            .access_application_id
            .as_deref()
            .unwrap_or("")
            .is_empty()
            || current.access_application_type.as_deref() != Some("self_hosted")
            || current.access_service_auth_401_redirect != Some(true)
            || current.access_destination_type.as_deref() != Some("public")
            || current.access_destination_uri.as_deref() != Some(expected_hostname.as_str())
            || current.access_destination_worker_id.is_some()
            || current.access_destination_has_overrides != Some(false)
        {
            return Err(format!(
                "{} Access application drifted from exact workers.dev Service Auth",
                projection.projection
            ));
        }
        if current.access_policies.len() != 1 {
            return Err(format!(
                "{} Access application must have exactly one service-auth policy",
                projection.projection
            ));
        }
        let policy = &current.access_policies[0];
        if policy.name != projection.access_policy_name
            || policy.decision.as_deref() != Some("non_identity")
            || policy.has_extra_rules
        {
            return Err(format!(
                "{} Access service-auth policy drifted",
                projection.projection
            ));
        }
        if !bootstrap_policy_is_safe(
            current.host_service_token_id.as_deref(),
            &policy.include_service_token_ids,
        ) {
            return Err(format!(
                "{} Access service-auth policy contains unexpected token identities",
                projection.projection
            ));
        }
    }
    Ok(())
}

fn bootstrap_policy_is_safe(host_id: Option<&str>, actual_ids: &[String]) -> bool {
    let mut actual = actual_ids.to_vec();
    actual.sort();

    match host_id {
        Some(host_id) => {
            let mut expected = vec![host_id.to_owned()];
            expected.sort();
            actual == expected
        }
        None => actual.is_empty(),
    }
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn existing_host_credential_from_escrow(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
    current: &ProjectionObservation,
) -> Result<cloudflare::CloudflareAccessServiceCredential, String> {
    let token_id = current
        .host_service_token_id
        .as_deref()
        .ok_or_else(|| format!("{} host service token is missing", projection.projection))?;
    let observed_client_id = current
        .host_service_token_client_id
        .as_deref()
        .ok_or_else(|| {
            format!(
                "{} host service token client ID is unavailable",
                projection.projection
            )
        })?;

    let (client_id_env, client_secret_env) = match projection.projection.as_str() {
        "windows" => (
            "EDGE_WINDOWS_HOST_CLIENT_ID",
            "EDGE_WINDOWS_HOST_CLIENT_SECRET",
        ),
        "vm" => ("EDGE_VM_HOST_CLIENT_ID", "EDGE_VM_HOST_CLIENT_SECRET"),
        _ => return Err("unsupported host bootstrap projection".to_owned()),
    };

    let client_id = optional_env(client_id_env).ok_or_else(|| {
        format!(
            "{} host token already exists but bootstrap escrow is unavailable; fail closed instead of rotating implicitly",
            projection.projection
        )
    })?;
    let client_secret = optional_env(client_secret_env).ok_or_else(|| {
        format!(
            "{} host token already exists but bootstrap escrow secret is unavailable; fail closed instead of rotating implicitly",
            projection.projection
        )
    })?;
    if client_id != observed_client_id {
        return Err(format!(
            "{} host bootstrap escrow client ID does not match observed Cloudflare token identity",
            projection.projection
        ));
    }

    Ok(cloudflare::CloudflareAccessServiceCredential {
        id: token_id.to_owned(),
        client_id,
        client_secret,
        enabled: current.host_service_token_enabled,
        duration: current.host_service_token_duration.clone(),
        name: Some(projection.host_service_token_name.clone()),
    })
}

fn validate_host_credential(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
    credential: &cloudflare::CloudflareAccessServiceCredential,
) -> Result<(), String> {
    if credential.id.is_empty()
        || credential.client_id.is_empty()
        || credential.client_secret.is_empty()
        || credential.name.as_deref() != Some(projection.host_service_token_name.as_str())
        || credential.enabled != Some(true)
        || credential.duration.as_deref() != Some(desired.host_service_token_duration.as_str())
    {
        return Err(format!(
            "{} host service-token credential response is not exact",
            projection.projection
        ));
    }
    Ok(())
}

async fn host_bootstrap_converge(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let before = observe(control_token, desired).await?;
    validate_host_bootstrap_preconditions(desired, &before)?;

    let windows_output = required_env("EDGE_WINDOWS_HOST_IDENTITY_OUTPUT")?;
    let vm_id_output = required_env("EDGE_VM_HOST_CLIENT_ID_OUTPUT")?;
    let vm_secret_output = required_env("EDGE_VM_HOST_CLIENT_SECRET_OUTPUT")?;
    let mut mutations = 0u32;

    for projection in projections(desired) {
        let current = projection_observation(&before, &projection.projection)?;
        let credential = if current.host_service_token_id.is_some() {
            existing_host_credential_from_escrow(desired, &projection, current)?
        } else {
            let credential = cloudflare::create_access_service_token(
                control_token,
                &desired.target_account_id,
                &projection.host_service_token_name,
                &desired.host_service_token_duration,
                true,
            )
            .await?;
            mutations += 1;
            credential
        };
        validate_host_credential(desired, &projection, &credential)?;

        match projection.projection.as_str() {
            "windows" => {
                let raw = format!(
                    "CF_ACCESS_CLIENT_ID={}\nCF_ACCESS_CLIENT_SECRET={}\n",
                    credential.client_id, credential.client_secret
                );
                write_private_bootstrap_file(Path::new(&windows_output), raw.as_bytes())?;
            }
            "vm" => {
                write_private_bootstrap_file(
                    Path::new(&vm_id_output),
                    credential.client_id.as_bytes(),
                )?;
                write_private_bootstrap_file(
                    Path::new(&vm_secret_output),
                    credential.client_secret.as_bytes(),
                )?;
            }
            _ => return Err("unsupported host bootstrap projection".to_owned()),
        }

        let app_id = current
            .access_application_id
            .as_deref()
            .ok_or_else(|| format!("{} Access application disappeared", projection.projection))?;
        let policy = current
            .access_policies
            .first()
            .ok_or_else(|| format!("{} Access policy disappeared", projection.projection))?;
        let expected_ids = vec![credential.id.clone()];
        let mut actual_ids = policy.include_service_token_ids.clone();
        let mut sorted_expected = expected_ids.clone();
        actual_ids.sort();
        sorted_expected.sort();
        if actual_ids != sorted_expected {
            cloudflare::update_access_service_policy_tokens(
                control_token,
                &desired.target_account_id,
                app_id,
                &policy.id,
                &projection.access_policy_name,
                &expected_ids,
            )
            .await?;
            mutations += 1;
        }
    }

    let after = observe(control_token, desired).await?;
    validate_access_boundary(desired, &after)?;
    println!("credential_host_bootstrap_status=PASS");
    println!("host_identity_delivery=RUNNER_BLIND");
    println!("windows_bootstrap_envelope=CMS_RFC5652");
    println!("vm_bootstrap_sink=GITHUB_ENVIRONMENT_SECRET");
    println!("provider_mutations={mutations}");
    println!("real_credentials_created=0");
    println!("production_runtime_mutations=0");
    Ok(())
}

fn plan(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<CredentialDeliveryAction, String> {
    validate_access_boundary(desired, observed)?;
    for projection in projections(desired) {
        match projection_delivery_state(desired, &projection, observed)? {
            ProjectionDeliveryState::LegacyLocked => {
                return Ok(CredentialDeliveryAction::InstallDummyAbContract {
                    projection: projection.projection,
                });
            }
            ProjectionDeliveryState::FixedAbVersionTagMissing => {
                return Ok(CredentialDeliveryAction::RestoreFixedAbVersionTag {
                    projection: projection.projection,
                });
            }
            ProjectionDeliveryState::FixedAbLatestPendingDeployment => {
                return Ok(CredentialDeliveryAction::RestoreFixedAbBaseline {
                    projection: projection.projection,
                });
            }
            ProjectionDeliveryState::FixedAbProofUpgradeRequired => {
                return Ok(CredentialDeliveryAction::UpgradeSlotProofCode {
                    projection: projection.projection,
                });
            }
            ProjectionDeliveryState::FixedAb => {}
        }
    }
    Ok(CredentialDeliveryAction::Noop)
}

// Immutable source-proven tags from the last accepted generation-search-only
// Worker scripts, observed through the live provider before this source change.
// They are NOT proof of the physical A/B secret binding values.
fn previous_fixed_ab_version_tag(projection: &str) -> Result<&'static str, String> {
    match projection {
        "windows" => Ok("sing-box-phase6-ab-windows-6924f2f0655f58f9"),
        "vm" => Ok("sing-box-phase6-ab-vm-371edd1d8616c67b"),
        _ => Err("unknown previous Worker projection".to_owned()),
    }
}

/// Validate the independent Windows Worker as a read-only neighbour of a
/// VM-only code upgrade. This verifies resource ownership/Access separately
/// via validate_access_boundary, then fences the exact A/B bindings and
/// single active latest deployment without interpreting Windows code tags
/// using the VM code-upgrade state machine.
fn verify_vm_only_windows_neighbour(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(), String> {
    let windows = projection_desired(desired, "windows")?;
    let current = projection_observation(observed, "windows")?;
    if current.worker_binding_count != Some(2) {
        return Err("HOST_VM_WORKER_WINDOWS_AB_BINDING_COUNT_INVALID".to_owned());
    }
    require_exact_secret_bindings(
        &windows.worker_name,
        &windows.projection,
        &current.worker_secret_bindings,
    )?;
    let latest = current
        .worker_latest_version_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or("HOST_VM_WORKER_WINDOWS_LATEST_UNPROVEN")?;
    if current
        .worker_active_deployment_id
        .as_deref()
        .unwrap_or("")
        .is_empty()
        || current.worker_active_version_ids.as_slice() != [latest]
    {
        return Err("HOST_VM_WORKER_WINDOWS_DEPLOYMENT_AMBIGUOUS".to_owned());
    }
    if !matches!(
        (
            current.worker_version_tag.as_deref(),
            current.worker_latest_version_tag.as_deref(),
        ),
        (Some(settings), Some(latest_tag))
            if !settings.is_empty() && settings == latest_tag
    ) {
        return Err("HOST_VM_WORKER_WINDOWS_TAG_READBACK_INCONSISTENT".to_owned());
    }
    Ok(())
}

fn projection_delivery_state(
    _desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
    observed: &CredentialPlaneObservation,
) -> Result<ProjectionDeliveryState, String> {
    let current = projection_observation(observed, &projection.projection)?;
    let legacy_tag = legacy_worker_version_tag(&projection.projection)?;
    let material = delivery_worker_material(&projection.projection)?;

    if current.worker_binding_count == Some(0)
        && current.worker_secret_bindings.is_empty()
        && current.worker_version_tag.as_deref() == Some(legacy_tag.as_str())
    {
        return Ok(ProjectionDeliveryState::LegacyLocked);
    }

    // Credential data plane remains exactly two A/B slots. The ONE VM Worker
    // may additionally carry five independent Host signer guard secrets, with
    // no second worker or duplicate issuer. Windows never permits signer keys.
    let guarded_host_signer =
        projection.projection == "vm" && matches!(current.worker_binding_count, Some(7 | 8 | 9));
    if current.worker_binding_count == Some(2) || guarded_host_signer {
        require_exact_secret_bindings(
            &projection.worker_name,
            &projection.projection,
            &current.worker_secret_bindings,
        )?;
        let latest_is_only_active = current.worker_active_deployment_id.is_some()
            && current
                .worker_latest_version_id
                .as_ref()
                .is_some_and(|latest| {
                    current.worker_active_version_ids.len() == 1
                        && current.worker_active_version_ids[0] == *latest
                });
        let settings_tag = current.worker_version_tag.as_deref();
        let latest_tag = current.worker_latest_version_tag.as_deref();
        let previous_tag = previous_fixed_ab_version_tag(&projection.projection)?;
        if latest_is_only_active
            && settings_tag == Some(previous_tag)
            && latest_tag == Some(previous_tag)
        {
            // No script or secret change is authorized here. Exact binding
            // inheritance and version fencing are still required to upgrade
            // the code so hosts can prove which slot physically holds dummy.
            return Ok(ProjectionDeliveryState::FixedAbProofUpgradeRequired);
        }
        if latest_is_only_active
            && settings_tag == Some(material.version_tag.as_str())
            && latest_tag == Some(material.version_tag.as_str())
        {
            return Ok(ProjectionDeliveryState::FixedAb);
        }
        let latest_is_pending_deployment = current.worker_active_deployment_id.is_some()
            && current.worker_active_version_ids.len() == 1
            && current
                .worker_latest_version_id
                .as_ref()
                .is_some_and(|latest| current.worker_active_version_ids[0] != *latest);
        if latest_is_pending_deployment
            && settings_tag == Some(material.version_tag.as_str())
            && latest_tag == Some(material.version_tag.as_str())
        {
            return Ok(ProjectionDeliveryState::FixedAbLatestPendingDeployment);
        }
        if latest_is_only_active && settings_tag.is_none() && latest_tag.is_none() {
            return Ok(ProjectionDeliveryState::FixedAbVersionTagMissing);
        }
    }

    let bindings = current
        .worker_secret_bindings
        .iter()
        .map(|binding| format!("{}:{}", binding.name, binding.binding_type))
        .collect::<Vec<_>>()
        .join(",");
    Err(format!(
        "Worker {} is neither exact legacy locked state nor exact fixed A/B state: settings_version_tag={}, latest_version_id={}, latest_version_tag={}, active_deployment_id={}, active_version_ids={}, binding_count={}, secret_bindings={}",
        projection.worker_name,
        current.worker_version_tag.as_deref().unwrap_or("ABSENT"),
        current
            .worker_latest_version_id
            .as_deref()
            .unwrap_or("ABSENT"),
        current
            .worker_latest_version_tag
            .as_deref()
            .unwrap_or("ABSENT"),
        current
            .worker_active_deployment_id
            .as_deref()
            .unwrap_or("ABSENT"),
        if current.worker_active_version_ids.is_empty() {
            "ABSENT".to_owned()
        } else {
            current.worker_active_version_ids.join(",")
        },
        current
            .worker_binding_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned()),
        if bindings.is_empty() {
            "ABSENT"
        } else {
            bindings.as_str()
        }
    ))
}

fn validate_access_boundary(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(), String> {
    if observed.control_token_identity.status != "active" {
        return Err("CLOUDFLARE_CONTROL_TOKEN is not active".to_owned());
    }
    let organization = observed
        .access_organization
        .as_ref()
        .ok_or_else(|| "accepted Access organization is missing".to_owned())?;
    if organization.name != desired.access_organization_name
        || organization.auth_domain != desired.access_auth_domain
        || organization.deny_unmatched_requests != Some(true)
    {
        return Err("credential Access organization drifted".to_owned());
    }
    if observed.workers_dev_subdomain.as_deref() != Some(desired.workers_dev_subdomain.as_str()) {
        return Err("credential workers.dev namespace drifted".to_owned());
    }

    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        if !current.worker_script_present || !current.worker_identity_present {
            return Err(format!(
                "Worker {} must already exist with immutable identity",
                projection.worker_name
            ));
        }
        if current.worker_id.as_deref().unwrap_or("").is_empty() {
            return Err(format!(
                "Worker {} is missing provider identity",
                projection.worker_name
            ));
        }
        if current.custom_domain_count != 0 {
            return Err(format!(
                "Worker {} must remain workers.dev-only",
                projection.worker_name
            ));
        }
        if current.workers_dev_enabled != Some(true) || current.previews_enabled != Some(false) {
            return Err(format!(
                "Worker {} must be published only on workers.dev with previews disabled",
                projection.worker_name
            ));
        }

        let host_token_id = current
            .host_service_token_id
            .as_deref()
            .ok_or_else(|| format!("{} host service token is missing", projection.projection))?;
        if current.host_service_token_enabled != Some(true) {
            return Err(format!(
                "{} host service token must remain enabled",
                projection.projection
            ));
        }
        if current.host_service_token_duration.as_deref()
            != Some(desired.host_service_token_duration.as_str())
        {
            return Err(format!(
                "{} host service token duration drifted",
                projection.projection
            ));
        }

        if current.access_application_type.as_deref() != Some("self_hosted")
            || current.access_service_auth_401_redirect != Some(true)
        {
            return Err(format!(
                "{} Access application drifted from self-hosted Service Auth",
                projection.projection
            ));
        }
        let expected_hostname = workers_dev_hostname(desired, &projection);
        if current.access_destination_type.as_deref() != Some("public")
            || current.access_destination_uri.as_deref() != Some(expected_hostname.as_str())
            || current.access_destination_worker_id.is_some()
            || current.access_destination_has_overrides != Some(false)
        {
            return Err(format!(
                "{} Access destination drifted from exact workers.dev hostname",
                projection.projection
            ));
        }

        if current.access_policies.len() != 1 {
            return Err(format!(
                "{} Access application must have exactly one service-auth policy",
                projection.projection
            ));
        }
        let policy = &current.access_policies[0];
        if policy.name != projection.access_policy_name
            || policy.decision.as_deref() != Some("non_identity")
            || policy.has_extra_rules
        {
            return Err(format!(
                "{} Access service-token isolation policy drifted",
                projection.projection
            ));
        }

        let mut observed_service_token_ids = policy.include_service_token_ids.clone();
        observed_service_token_ids.sort();
        let mut expected_host_only = vec![host_token_id.to_owned()];
        // This narrow exception exists only during a single authorized
        // initial publication while the Windows acceptance token is live.
        // All ordinary production diagnostics still require host-only.
        if projection.projection == "windows" {
            if let Ok(temp_id) = env::var("EDGE_INITIAL_WINDOWS_ACCEPTANCE_TOKEN_ID") {
                let run_id = required_env("EDGE_INITIAL_WINDOWS_ACCEPTANCE_RUN_ID")?
                    .parse::<u64>()
                    .map_err(|_| "invalid acceptance run ID".to_owned())?;
                check_initial_acceptance_github_owner(run_id, "ISSUE")?;
                if temp_id.is_empty() || temp_id == host_token_id {
                    return Err("invalid independent Windows acceptance token ID".to_owned());
                }
                expected_host_only.push(temp_id);
            }
        }
        expected_host_only.sort();
        if observed_service_token_ids != expected_host_only {
            return Err(format!(
                "{} Access service-token isolation policy is not exact host-only Service Auth",
                projection.projection
            ));
        }
    }
    Ok(())
}

async fn verify(
    control_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<(), String> {
    let observed = observe(control_token, desired).await?;
    let action = plan(desired, &observed)?;
    if action != CredentialDeliveryAction::Noop {
        return Err(format!(
            "credential-delivery verify requires exact terminal A/B state; next action={}",
            action_name(&action)
        ));
    }
    print_terminal(desired, &observed, 0)?;
    println!("credential_secret_mutations=0");
    Ok(())
}

async fn observe(
    api_token: &str,
    desired: &ProductionCredentialPlaneOwnership,
) -> Result<CredentialPlaneObservation, String> {
    let control_token_identity = cloudflare::verify_api_token(api_token).await?;
    let scripts = cloudflare::list_worker_scripts(api_token, &desired.target_account_id).await?;
    let workers = cloudflare::list_workers(api_token, &desired.target_account_id).await?;
    let worker_domains =
        cloudflare::list_worker_domains(api_token, &desired.target_account_id).await?;
    let access_organization =
        cloudflare::get_access_organization(api_token, &desired.target_account_id)
            .await
            .map(Some)
            .or_else(|err| {
                if cloudflare::is_access_not_enabled_error(&err) {
                    Ok(None)
                } else {
                    Err(err)
                }
            })?;
    let (service_tokens, access_applications) = if access_organization.is_some() {
        (
            cloudflare::list_access_service_tokens(api_token, &desired.target_account_id).await?,
            cloudflare::list_access_applications(api_token, &desired.target_account_id).await?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let workers_dev_subdomain =
        cloudflare::get_workers_subdomain(api_token, &desired.target_account_id)
            .await
            .map(|value| Some(value.subdomain))
            .or_else(|err| {
                if cloudflare::is_workers_subdomain_not_configured_error(&err) {
                    Ok(None)
                } else {
                    Err(err)
                }
            })?;

    let mut projections_observed = Vec::new();
    for projection in projections(desired) {
        let matching_scripts = scripts
            .iter()
            .filter(|script| script.id == projection.worker_name)
            .collect::<Vec<_>>();
        if matching_scripts.len() > 1 {
            return Err(format!(
                "duplicate Worker script identity observed for {}",
                projection.worker_name
            ));
        }
        let worker_script_present = matching_scripts.len() == 1;

        let matching_workers = workers
            .iter()
            .filter(|worker| worker.name == projection.worker_name)
            .collect::<Vec<_>>();
        if matching_workers.len() > 1 {
            return Err(format!(
                "duplicate immutable Worker identity observed for {}",
                projection.worker_name
            ));
        }
        let worker_identity = matching_workers.first().copied();

        let (settings, secret_bindings, workers_dev_enabled, previews_enabled) =
            if worker_script_present {
                let subdomain = cloudflare::get_worker_script_subdomain(
                    api_token,
                    &desired.target_account_id,
                    &projection.worker_name,
                )
                .await?;
                (
                    Some(
                        cloudflare::get_worker_script_settings(
                            api_token,
                            &desired.target_account_id,
                            &projection.worker_name,
                        )
                        .await?,
                    ),
                    cloudflare::list_worker_script_secrets(
                        api_token,
                        &desired.target_account_id,
                        &projection.worker_name,
                    )
                    .await?,
                    Some(subdomain.enabled),
                    Some(subdomain.previews_enabled),
                )
            } else {
                (
                    None,
                    Vec::new(),
                    worker_identity.and_then(|worker| worker.workers_dev_enabled),
                    worker_identity.and_then(|worker| worker.previews_enabled),
                )
            };

        let version_head = if worker_script_present {
            Some(
                cloudflare::get_worker_script_version_head(
                    api_token,
                    &desired.target_account_id,
                    &projection.worker_name,
                )
                .await?,
            )
        } else {
            None
        };

        let latest_version_tag = match (
            worker_identity,
            version_head
                .as_ref()
                .and_then(|value| value.latest_version_id.as_deref()),
        ) {
            (Some(worker), Some(version_id)) => Some(
                cloudflare::get_worker_version_tag(
                    api_token,
                    &desired.target_account_id,
                    &worker.id,
                    version_id,
                )
                .await?,
            ),
            _ => None,
        }
        .flatten();

        let matching_host_tokens = service_tokens
            .iter()
            .filter(|token| {
                token.name.as_deref() == Some(projection.host_service_token_name.as_str())
            })
            .collect::<Vec<_>>();
        if matching_host_tokens.len() > 1 {
            return Err(format!(
                "duplicate host service-token identity observed for {}",
                projection.host_service_token_name
            ));
        }
        let host_token = matching_host_tokens.first().copied();

        let matching_apps = access_applications
            .iter()
            .filter(|app| app.name == projection.access_application_name)
            .collect::<Vec<_>>();
        if matching_apps.len() > 1 {
            return Err(format!(
                "duplicate Access application identity observed for {}",
                projection.access_application_name
            ));
        }
        let app = matching_apps.first().copied();
        let policies = match app {
            Some(app) => {
                cloudflare::list_access_application_policies(
                    api_token,
                    &desired.target_account_id,
                    &app.id,
                )
                .await?
            }
            None => Vec::new(),
        };
        let destination = app.and_then(|app| {
            if app.destinations.len() == 1 {
                app.destinations.first()
            } else {
                None
            }
        });

        projections_observed.push(ProjectionObservation {
            projection: projection.projection,
            worker_name: projection.worker_name.clone(),
            worker_script_present,
            worker_identity_present: worker_identity.is_some(),
            worker_id: worker_identity.map(|worker| worker.id.clone()),
            worker_binding_count: settings.as_ref().map(|value| value.binding_count),
            worker_secret_bindings: secret_bindings,
            worker_version_tag: settings.and_then(|value| value.version_tag),
            worker_latest_version_id: version_head
                .as_ref()
                .and_then(|value| value.latest_version_id.clone()),
            worker_latest_version_tag: latest_version_tag,
            worker_active_deployment_id: version_head
                .as_ref()
                .and_then(|value| value.active_deployment_id.clone()),
            worker_active_version_ids: version_head
                .map(|value| value.active_version_ids)
                .unwrap_or_default(),
            workers_dev_enabled,
            previews_enabled,
            custom_domain_count: worker_domains
                .iter()
                .filter(|domain| domain.service == projection.worker_name)
                .count(),
            host_service_token_id: host_token.map(|value| value.id.clone()),
            host_service_token_client_id: host_token.and_then(|value| value.client_id.clone()),
            host_service_token_enabled: host_token.and_then(|value| value.enabled),
            host_service_token_duration: host_token.and_then(|value| value.duration.clone()),
            access_application_id: app.map(|value| value.id.clone()),
            access_application_type: app.map(|value| value.app_type.clone()),
            access_service_auth_401_redirect: app.and_then(|value| value.service_auth_401_redirect),
            access_destination_type: destination.map(|value| value.destination_type.clone()),
            access_destination_worker_id: destination.and_then(|value| value.worker_id.clone()),
            access_destination_uri: destination.and_then(|value| value.uri.clone()),
            access_destination_has_overrides: destination.map(|value| value.has_overrides),
            access_policies: policies,
        });
    }

    // Only one exact Host Access app may exist. GET-only audience and policy
    // readback never infer signer trust or permission to mutate Cloudflare.
    let host_access_matches = access_applications
        .iter()
        .filter(|app| app.name == desired.host_access_application_name)
        .collect::<Vec<_>>();
    if host_access_matches.len() > 1 {
        return Err("HOST_ACCESS_APP_DUPLICATED_BLOCKED".into());
    }
    let host_access = if let Some(app) = host_access_matches.first() {
        Some(HostAccessObservation {
            app: (**app).clone(),
            policies: cloudflare::list_access_application_policies(
                api_token,
                &desired.target_account_id,
                &app.id,
            )
            .await?,
            audience: cloudflare::get_access_application_audience(
                api_token,
                &desired.target_account_id,
                &app.id,
            )
            .await?,
        })
    } else {
        None
    };

    Ok(CredentialPlaneObservation {
        control_token_identity,
        host_access,
        access_organization,
        workers_dev_subdomain,
        projections: projections_observed,
    })
}

// Shared Host Authorization is independent of either credential projection.
// The signer remains in the ONE existing VM Worker; no new Worker/key/agent.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostAccessObservation {
    app: cloudflare::CloudflareAccessApplication,
    policies: Vec<cloudflare::CloudflareAccessPolicy>,
    audience: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostAccessReadback {
    NotProvisionedLegacyVmPreserved,
    StagedAwaitWorkerAudience,
    StagedAwaitSignerProof,
    ActiveAwaitSignedHostProof,
}

impl HostAccessReadback {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotProvisionedLegacyVmPreserved => "NOT_PROVISIONED_LEGACY_VM_PRESERVED",
            Self::StagedAwaitWorkerAudience => "STAGED_AWAIT_WORKER_AUDIENCE",
            Self::StagedAwaitSignerProof => "STAGED_AWAIT_SIGNER_PROOF",
            Self::ActiveAwaitSignedHostProof => "ACTIVE_AWAIT_SIGNED_HOST_PROOF",
        }
    }
}

// Staging cannot intercept VM's production Host Authorization. The wildcard
// matters: /v1/host by itself does not cover /v1/host/identity or /admin.
const HOST_ACCESS_STAGE_PATTERN: &str = "/__singbox_host_access_stage__/*";
const HOST_ACCESS_LIVE_PATTERN: &str = "/v1/host/*";

fn host_access_readback(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<HostAccessReadback, String> {
    // Preserve original VM/Windows exclusive credential policy first.
    validate_access_boundary(desired, observed)?;
    if desired.host_access_application_name.is_empty()
        || desired.host_access_policy_name.is_empty()
        || desired.host_access_application_name == desired.vm_access_application_name
        || desired.host_access_application_name == desired.windows_access_application_name
        || desired.host_access_route_pattern != HOST_ACCESS_LIVE_PATTERN
    {
        return Err("HOST_ACCESS_TYPED_GIT_CONTRACT_INVALID".into());
    }
    let vm = projection_observation(observed, "vm")?;
    let win = projection_observation(observed, "windows")?;
    let vm_id = vm
        .host_service_token_id
        .as_deref()
        .ok_or("HOST_ACCESS_VM_TOKEN_UNPROVEN")?;
    let win_id = win
        .host_service_token_id
        .as_deref()
        .ok_or("HOST_ACCESS_WINDOWS_TOKEN_UNPROVEN")?;
    if vm_id == win_id {
        return Err("HOST_ACCESS_TOKEN_NOT_ISOLATED".into());
    }
    let Some(route) = observed.host_access.as_ref() else {
        if vm.worker_binding_count == Some(9) {
            return Err("HOST_ACCESS_AUDIENCE_WITHOUT_APPLICATION".into());
        }
        return Ok(HostAccessReadback::NotProvisionedLegacyVmPreserved);
    };
    let host = format!(
        "{}.{}.workers.dev",
        desired.vm_worker_name, desired.workers_dev_subdomain
    );
    let staged = format!("{host}{HOST_ACCESS_STAGE_PATTERN}");
    let active = format!("{host}{HOST_ACCESS_LIVE_PATTERN}");
    let destinations = route.app.destinations.as_slice();
    if route.app.name != desired.host_access_application_name
        || route.app.app_type != "self_hosted"
        || route.app.service_auth_401_redirect != Some(true)
        || destinations.len() != 1
        || destinations[0].destination_type != "public"
        || destinations[0].worker_id.is_some()
        || destinations[0].has_overrides
        || route.policies.len() != 1
        || route.policies[0].name != desired.host_access_policy_name
        || route.policies[0].decision.as_deref() != Some("non_identity")
        || route.policies[0].has_extra_rules
        || route.policies[0].id.is_empty()
        || (!route.app.policy_ids.is_empty()
            && route.app.policy_ids != vec![route.policies[0].id.clone()])
        || !(8..=64).contains(&route.audience.len())
        || !route
            .audience
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("HOST_ACCESS_APP_OR_POLICY_DRIFT_BLOCKED".into());
    }
    let mut actual = route.policies[0].include_service_token_ids.clone();
    actual.sort_unstable();
    let mut expected = vec![vm_id.to_owned(), win_id.to_owned()];
    expected.sort_unstable();
    if actual.len() != 2 || actual != expected {
        return Err("HOST_ACCESS_TOKEN_SCOPE_DRIFT_BLOCKED".into());
    }
    match destinations[0].uri.as_deref() {
        Some(uri) if uri == staged => match vm.worker_binding_count {
            Some(8) => Ok(HostAccessReadback::StagedAwaitWorkerAudience),
            Some(9) => Ok(HostAccessReadback::StagedAwaitSignerProof),
            _ => Err("HOST_ACCESS_VM_SIGNER_BINDINGS_UNPROVEN".into()),
        },
        Some(uri) if uri == active => {
            if vm.worker_binding_count != Some(9) {
                return Err("HOST_ACCESS_LIVE_BEFORE_SIGNER_READY".into());
            }
            Ok(HostAccessReadback::ActiveAwaitSignedHostProof)
        }
        _ => Err("HOST_ACCESS_PATH_DRIFT_BLOCKED".into()),
    }
}

fn projections(desired: &ProductionCredentialPlaneOwnership) -> [ProjectionDesired; 2] {
    [
        ProjectionDesired {
            projection: "windows".to_owned(),
            worker_name: desired.windows_worker_name.clone(),
            access_application_name: desired.windows_access_application_name.clone(),
            access_policy_name: desired.windows_access_policy_name.clone(),
            host_service_token_name: desired.windows_host_service_token_name.clone(),
        },
        ProjectionDesired {
            projection: "vm".to_owned(),
            worker_name: desired.vm_worker_name.clone(),
            access_application_name: desired.vm_access_application_name.clone(),
            access_policy_name: desired.vm_access_policy_name.clone(),
            host_service_token_name: desired.vm_host_service_token_name.clone(),
        },
    ]
}

fn projection_desired(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &str,
) -> Result<ProjectionDesired, String> {
    projections(desired)
        .into_iter()
        .find(|candidate| candidate.projection == projection)
        .ok_or_else(|| format!("unsupported credential projection {projection}"))
}

fn projection_observation<'a>(
    observed: &'a CredentialPlaneObservation,
    projection: &str,
) -> Result<&'a ProjectionObservation, String> {
    observed
        .projections
        .iter()
        .find(|candidate| candidate.projection == projection)
        .ok_or_else(|| format!("missing credential projection observation {projection}"))
}

fn projection_kind(projection: &str) -> Result<CredentialProjectionKind, String> {
    match projection {
        "windows" => Ok(CredentialProjectionKind::Windows),
        "vm" => Ok(CredentialProjectionKind::Vm),
        _ => Err(format!("unsupported credential projection {projection}")),
    }
}

fn workers_dev_hostname(
    desired: &ProductionCredentialPlaneOwnership,
    projection: &ProjectionDesired,
) -> String {
    format!(
        "{}.{}.workers.dev",
        projection.worker_name, desired.workers_dev_subdomain
    )
}

// Never accept malformed or inadvertently overbroad key material as a
// Cloudflare Worker secret. No key bytes or crypto errors leave this owner.
fn validate_host_github_app_private_key(value: &str) -> Result<(), String> {
    use base64::Engine as _;
    if value.len() < 1000
        || value.len() > 8192
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
    {
        return Err("HOST_VM_GITHUB_APP_KEY_ENCODING_INVALID".to_owned());
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "HOST_VM_GITHUB_APP_KEY_ENCODING_INVALID".to_owned())?;
    if decoded.len() < 800
        || decoded.len() > 4096
        || ring::signature::RsaKeyPair::from_pkcs8(&decoded).is_err()
    {
        return Err("HOST_VM_GITHUB_APP_PKCS8_RSA_INVALID".to_owned());
    }
    Ok(())
}

fn require_exact_secret_bindings(
    worker_name: &str,
    projection: &str,
    bindings: &[cloudflare::CloudflareWorkerSecretBinding],
) -> Result<(), String> {
    let mut observed = bindings
        .iter()
        .map(|binding| (binding.name.as_str(), binding.binding_type.as_str()))
        .collect::<Vec<_>>();
    observed.sort_unstable();
    let mut expected = vec![(SLOT_A, "secret_text"), (SLOT_B, "secret_text")];
    if projection == "vm" && matches!(observed.len(), 7 | 8 | 9) {
        // Exactly one Worker may carry the host signing secret. No extra
        // implicit credentials, fallback secrets or caller-provided key.
        expected.extend_from_slice(&[
            ("EDGE_HOST_SIGNING_PKCS8_BASE64", "secret_text"),
            ("EDGE_HOST_SIGNING_KEY_ID", "secret_text"),
            ("EDGE_HOST_GITHUB_ACTOR_ID", "secret_text"),
            ("EDGE_HOST_ACCESS_ISSUER", "secret_text"),
            ("EDGE_HOST_ACCESS_AUD", "secret_text"),
        ]);
    }
    if projection == "vm" && matches!(observed.len(), 8 | 9) {
        expected.push(("EDGE_HOST_GITHUB_APP_PKCS8_BASE64", "secret_text"));
    }
    if projection == "vm" && observed.len() == 9 {
        expected.push(("EDGE_HOST_ROUTE_ACCESS_AUD", "secret_text"));
    }
    expected.sort_unstable();
    if observed != expected {
        return Err(format!(
            "Worker {worker_name} bindings differ from exact A/B and optional ONE VM Host signer: observed={observed:?}"
        ));
    }
    Ok(())
}

fn delivery_worker_material(projection: &str) -> Result<DeliveryWorkerMaterial, String> {
    let projection_kind = projection_kind(projection)?;
    let slots = [
        (SLOT_A, CREDENTIAL_DUMMY_PROBE_GENERATION_A),
        (SLOT_B, CREDENTIAL_DUMMY_PROBE_GENERATION_B),
    ]
    .into_iter()
    .map(|(name, generation)| {
        let payload = CredentialDeliveryBundle {
            schema_version: 1,
            generation,
            projection: projection_kind as i32,
            dummy_non_secret: true,
            slot: CredentialDeliverySlot::Unspecified as i32,
            payload: None,
        }
        .encode_to_vec();
        DeliverySlot {
            name,
            generation,
            secret_text: hex_encode(&payload),
            payload,
        }
    })
    .collect::<Vec<_>>();

    let source = r#"const S=["EDGE_CREDENTIAL_BUNDLE_A","EDGE_CREDENTIAL_BUNDLE_B"];
const P=__PROJECTION__;
const D=["__DUMMY_A_DIGEST__","__DUMMY_B_DIGEST__"];
const Q=["__DUMMY_A_GENERATION__","__DUMMY_B_GENERATION__"];
function H(v){if(typeof v!=="string"||v.length===0||v.length%2||!/^[0-9a-f]+$/.test(v))return null;const b=new Uint8Array(v.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(v.slice(i*2,i*2+2),16);return b}
function V(b,p){let v=0n,s=0n;for(let i=0;i<10;i++){if(p>=b.length)return null;const x=BigInt(b[p++]);v|=(x&127n)<<s;if((x&128n)===0n)return[v,p];s+=7n}return null}
function G(b){let p=0,z=null,g=null,r=null;while(p<b.length){const k=V(b,p);if(!k)return null;const f=Number(k[0]>>3n),w=Number(k[0]&7n);p=k[1];if(!f)return null;if(w===0){const x=V(b,p);if(!x)return null;p=x[1];if(f===1)z=Number(x[0]);else if(f===2)g=x[0];else if(f===3)r=Number(x[0]);continue}if(w===1){if(p+8>b.length)return null;p+=8;continue}if(w===2){const x=V(b,p);if(!x||x[0]>BigInt(b.length))return null;p=x[1];const n=Number(x[0]);if(p+n>b.length)return null;p+=n;continue}if(w===5){if(p+4>b.length)return null;p+=4;continue}return null}return z===1&&g!==null&&r===P?g:null}

// This endpoint shares the existing Cloudflare secret owner, NEVER a runner
// private key. Inert until the Worker operator provisions all four guards:
// PKCS8 Ed25519 secret, key ID, approved exact intent SHA, and Access issuer/aud.
// Reuses Cloudflare Access JWT identity rather than trusting a caller header.
const TE=new TextEncoder(),TD=new TextDecoder("utf-8",{fatal:true}),NO={"Cache-Control":"no-store"};
function B64(v){if(typeof v!=="string"||v.length>16384||!/^[A-Za-z0-9_-]+={0,2}$/.test(v))return null;try{const s=v.replace(/-/g,"+").replace(/_/g,"/");return Uint8Array.from(atob(s+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))}catch{return null}}
// Strict DER for the sole RFC 8410 Ed25519 PKCS#8 key boundary. Only
// version 0 or 1, OID 1.3.101.112, 32-byte seed, and for version 1 a
// 32-byte embedded public key are accepted. No trailing or alternate fields.
function HOST_DER_TLV(b,pos,end){
 if(pos+2>end)return null;
 const tag=b[pos++];let n=b[pos++];
 if(n>=128){
  const bytes=n&127;if(bytes===0||bytes>2||pos+bytes>end||b[pos]===0)return null;
  n=0;for(let i=0;i<bytes;i++)n=n*256+b[pos++];
  if(n<128)return null;
 }
 if(pos+n>end)return null;
 return{tag,start:pos,end:pos+n,next:pos+n};
}
function HOST_SIGNER_PKCS8(b){
 if(!(b instanceof Uint8Array))return null;
 const root=HOST_DER_TLV(b,0,b.length);
 if(!root||root.tag!==0x30||root.next!==b.length)return null;
 let v=HOST_DER_TLV(b,root.start,root.end);
 if(!v||v.tag!==0x02||v.end-v.start!==1||(b[v.start]!==0&&b[v.start]!==1))return null;
 const version=b[v.start];
 const algorithm=HOST_DER_TLV(b,v.next,root.end);
 if(!algorithm||algorithm.tag!==0x30)return null;
 const oid=HOST_DER_TLV(b,algorithm.start,algorithm.end);
 if(!oid||oid.tag!==0x06||oid.end-oid.start!==3||oid.next!==algorithm.end||
  b[oid.start]!==0x2b||b[oid.start+1]!==0x65||b[oid.start+2]!==0x70)return null;
 const wrapped=HOST_DER_TLV(b,algorithm.next,root.end);
 if(!wrapped||wrapped.tag!==0x04)return null;
 const seed=HOST_DER_TLV(b,wrapped.start,wrapped.end);
 if(!seed||seed.tag!==0x04||seed.end-seed.start!==32||seed.next!==wrapped.end)return null;
 let publicKey=null;
 if(version===1){
  const field=HOST_DER_TLV(b,wrapped.next,root.end);
  if(!field)return null;
  let bits;
  if(field.tag===0x81){bits=field}
  else if(field.tag===0xa1){
   bits=HOST_DER_TLV(b,field.start,field.end);
   if(!bits||bits.tag!==0x03||bits.next!==field.end)return null;
  }else return null;
  if(bits.end-bits.start!==33||b[bits.start]!==0||field.next!==root.end)return null;
  publicKey=b.slice(bits.start+1,bits.end);
 }else if(wrapped.next!==root.end)return null;
 // Canonical RFC8410 v1 (version INTEGER 0); same seed / mathematical key.
 const v1=CAT(Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,
  0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]),
  b.slice(seed.start,seed.end));
 return{v1,publicKey};
}
// Shared native-signature boundary used by AUTHORIZE and the offline workerd
// contract test. Never emit secret bytes or exception details.
async function HOST_SIGNER_SIGN(encoded,payload){
 const pk=B64(encoded);
 const signer=pk===null?null:HOST_SIGNER_PKCS8(pk);
 if(!signer)return{reason:"HOST_SIGNER_KEY_INVALID"};
 let key;try{key=await crypto.subtle.importKey("pkcs8",signer.v1,{name:"Ed25519"},false,["sign"])}
 catch{return{reason:"HOST_SIGNER_IMPORT_FAILED"}}
 let signature;try{signature=new Uint8Array(await crypto.subtle.sign("Ed25519",key,payload))}
 catch{return{reason:"HOST_SIGNER_SIGN_FAILED"}}
 if(signature.length!==64)return{reason:"HOST_SIGNER_SIGNATURE_INVALID"};
 if(signer.publicKey!==null){
  let matches=false;
  try{
   const verifyKey=await crypto.subtle.importKey("raw",signer.publicKey,{name:"Ed25519"},false,["verify"]);
   matches=await crypto.subtle.verify("Ed25519",verifyKey,signature,payload);
  }catch{}
  if(!matches)return{reason:"HOST_SIGNER_KEY_MISMATCH"};
 }
 return{signature};
}
function U32(x){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,x);return b}
function U64(x){const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,BigInt(x));return b}
function CAT(...xs){const n=xs.reduce((a,b)=>a+b.length,0),b=new Uint8Array(n);let p=0;for(const x of xs){b.set(x,p);p+=x.length}return b}
function VI(n){let x=BigInt(n),b=[];do{let v=Number(x&127n);x>>=7n;if(x)v|=128;b.push(v)}while(x);return Uint8Array.from(b)}
function FLD(n,bytes){return CAT(VI((BigInt(n)<<3n)|2n),VI(bytes.length),bytes)}
function FNUM(n,value){return CAT(VI(BigInt(n)<<3n),VI(value))}
// The Worker is still the SAME signer: it validates only the shape and
// exact outer-Intent binding of the already SYSTEM-signed native witness.
// SYSTEM/Controller independently verify the Ed25519 signature against
// the enrolled machine identity and re-observe the real kernel/Line1/DNS.
// Do not let a runner-provided boolean grant any permission.
function NETADMIT(b,m,id,release){
 if(!(b instanceof Uint8Array)||b.length<220||b.length>1024)return false;
 let p=0,last=0,observed=0,expires=0,vm=null,op=null,desired=null;
 const seen=new Set();
 while(p<b.length){
  const key=V(b,p);if(!key)return false;
  const f=Number(key[0]>>3n),w=Number(key[0]&7n);p=key[1];
  if(f<=last||f>13)return false;last=f;seen.add(f);
  if(f===1||f===8||f===9){
   if(w!==0)return false;const n=V(b,p);if(!n)return false;p=n[1];
   if(n[0]>BigInt(Number.MAX_SAFE_INTEGER))return false;
   const num=Number(n[0]);
   if(f===1&&num!==1)return false;
   if(f===8)observed=num;
   if(f===9)expires=num;
   continue;
  }
  if(w!==2)return false;
  const size=V(b,p);if(!size||size[0]>BigInt(b.length))return false;
  p=size[1];const n=Number(size[0]);if(n>b.length-p)return false;
  const value=b.slice(p,p+n);p+=n;
  if(f===2||f===3){
   if(n===0||n>128)return false;
   try{const val=TD.decode(value);if(f===2)vm=val;else op=val;}catch{return false}
  }else if(f===13){
   if(n!==64||!value.some(x=>x!==0))return false;
  }else if(n!==32||!value.some(x=>x!==0)){
   return false;
  }else if(f===5){
   desired=Array.from(value,x=>x.toString(16).padStart(2,"0")).join("");
  }
 }
 if(seen.size!==13||vm!==m||op!==id||desired!==release)return false;
 const now=Math.floor(Date.now()/1000);
 return Number.isSafeInteger(observed)&&Number.isSafeInteger(expires)&&
   observed>0&&expires>observed&&expires-observed<=60&&
   observed<=now&&now<=expires;
}
// Reject duplicate fields, unknown wire types and ambiguous field order.
// The native prost decoder accepts only its canonical protobuf encoding;
// the issuer must not sign a different representation of the same request.
function INFO(b){
 let p=0,last=0,id=null,m=null,action=null,kind=null,schema=null,when=null,resource=null,release=null,admission=null;
 const seen=new Set();
 while(p<b.length){
  const k=V(b,p);if(!k)return null;
  const f=Number(k[0]>>3n),w=Number(k[0]&7n);p=k[1];
  if(f<=last||f>12)return null;last=f;seen.add(f);
  const numberField=f===1||f===3||f===6||f===10||f===11;
  if(numberField){
   if(w!==0)return null;
   const z=V(b,p);if(!z)return null;p=z[1];
   if(f===1)schema=Number(z[0]);
   if(f===3)kind=Number(z[0]);
   if(f===6)action=Number(z[0]);
   if(f===10)return null; // zero-valued requested_mode is omitted by prost
   if(f===11)when=Number(z[0]);
  }else{
   if(w!==2)return null;
   const z=V(b,p);if(!z||z[0]>BigInt(b.length))return null;p=z[1];
   const n=Number(z[0]);if(n>b.length-p)return null;
   const value=b.slice(p,p+n);p+=n;
   if(f===2||f===4||f===5){
    if(n===0||n>128)return null;
    let t;try{t=TD.decode(value)}catch{return null}
    if(f===2)m=t;if(f===4)resource=t;if(f===5)id=t;
   }else if(f>=7&&f<=9){
    if(n!==32||!value.some(x=>x!==0))return null;
    if(f===9)release=Array.from(value,x=>x.toString(16).padStart(2,"0")).join("");
   }else if(f===12){
    admission=value;
   }else return null;
  }
 }
 if([1,2,3,4,5,6,7,8,9,11].some(f=>!seen.has(f)))return null;
 // A resource-specific approval authorizes only one gateway config change.
 const scoped=typeof resource==="string"&&
    /^config\/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/(line1-gateway|line2-proxy)$/.test(resource);
 if(schema!==1||(kind!==1&&kind!==2)||
    !(resource==="sing-box"||(kind===2&&action===2&&scoped))||
    !(action===2||action===3||(kind===1&&(action===7||action===8)))||
    typeof id!=="string"||!/^issue1-comment-[1-9][0-9]{0,19}$/.test(id)||
    typeof m!=="string"||!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(m)||
    !Number.isSafeInteger(when)||when<=0)return null;
 // Network admission is a STRICTLY Windows-only START extension, never a
 // generic VM/Admin/Apply/Stop grant. The approved comment is still checked.
 if(admission!==null&&
    !(kind===1&&action===7&&resource==="sing-box"&&NETADMIT(admission,m,id,release)))
   return null;
 return{id,m,kind,action,when,release,resource};
}
// Only fixed enums and bounded numeric GitHub metadata cross this boundary.
// No URL, response body, exception message, JWT, Location or token is emitted.
function GHFAIL(stage,kind,r,e){
 const status=r?.status;
 const decision=kind!=="HTTP"||[401,403,429].includes(status)||status>=500?"UNAVAILABLE":"DENIED";
 const out={decision,stage,kind};
 if(Number.isInteger(status)&&status>=100&&status<=599)out.http_status=status;
 const h=r?.headers;
 if(h&&typeof h.get==="function"){
  for(const [source,target,max] of [["X-RateLimit-Remaining","rate_limit_remaining",10],
    ["X-RateLimit-Reset","rate_limit_reset",12],["Retry-After","retry_after",8]]){
   const value=h.get(source);
   if(typeof value==="string"&&value.length>0&&value.length<=max&&/^[0-9]+$/.test(value))
    out[target]=value;
  }
  const requestId=h.get("X-GitHub-Request-Id");
  if(typeof requestId==="string"&&/^[A-Za-z0-9-]{1,64}$/.test(requestId))
   out.github_request_id=requestId;
 }
 if(e){
  out.exception_class=["TypeError","TimeoutError","SyntaxError","RangeError","Error"].includes(e?.name)?
    e.name:"OTHER";
 }
 return out;
}
// Installation-scoped GitHub App, not OAuth or an operator PAT. One fresh,
// short-lived token per authorization; no cache, log, body, or token exposure.
// The immutable App/installation IDs are non-secret, pinned to this repository.
const GITHUB_APP_ID="5456373",GITHUB_INSTALLATION_ID="174880562";
function GITHUB_APP_ERROR(stage,kind,r,e){
 return GHFAIL(stage,kind,r,e);
}
async function GITHUB_INSTALLATION_AUTH(e,now){
 const raw=e.EDGE_HOST_GITHUB_APP_PKCS8_BASE64;
 if(typeof raw!=="string"||!raw||raw.length>8192)
  return{error:GITHUB_APP_ERROR("GITHUB_APP_JWT","CONFIG_MISSING",null)};
 let key,jwt;
 try{
  const bytes=B64(raw);
  if(!bytes||bytes.length<800||bytes.length>4096)throw new Error("invalid key size");
  key=await crypto.subtle.importKey("pkcs8",bytes,
   {name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["sign"]);
  const enc=ob=>{
   const data=TE.encode(JSON.stringify(ob));
   let binary="";for(const c of data)binary+=String.fromCharCode(c);
   return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  };
  const header=enc({alg:"RS256",typ:"JWT"});
  const body=enc({iat:now-60,exp:now+540,iss:GITHUB_APP_ID});
  const signing=header+"."+body;
  const sig=new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5",key,TE.encode(signing)));
  let binary="";for(const c of sig)binary+=String.fromCharCode(c);
  jwt=signing+"."+btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
 }catch(err){return{error:GITHUB_APP_ERROR("GITHUB_APP_JWT","SIGN_EXCEPTION",null,err)}}
 const url="https://api.github.com/app/installations/"+GITHUB_INSTALLATION_ID+"/access_tokens";
 let r;
 try{
  r=await fetch(url,{method:"POST",redirect:"manual",headers:{
   "Accept":"application/vnd.github+json","Content-Type":"application/json",
   "Authorization":"Bearer "+jwt,"User-Agent":"sing-box-host-authorizer"
  },body:JSON.stringify({repositories:["sing-box"],
   permissions:{contents:"read",issues:"read",pull_requests:"read"}})});
 }catch(err){return{error:GITHUB_APP_ERROR("GITHUB_INSTALLATION_TOKEN","FETCH_EXCEPTION",null,err)}}
 if(r.status>=300&&r.status<400)
  return{error:GITHUB_APP_ERROR("GITHUB_INSTALLATION_TOKEN","REDIRECT",r)};
 if(!r.ok)return{error:GITHUB_APP_ERROR("GITHUB_INSTALLATION_TOKEN","HTTP",r)};
 let issued;
 try{issued=await r.json()}
 catch(err){return{error:GITHUB_APP_ERROR("GITHUB_INSTALLATION_TOKEN","RESPONSE_DECODE",r,err)}}
 const permissions=issued?.permissions;
 const expiry=Date.parse(issued?.expires_at)/1000;
 const matching=Array.isArray(issued?.repositories)&&issued.repositories.length===1&&
  issued.repositories[0]?.full_name==="iamaman11/sing-box"&&
  issued.repositories[0]?.id===1221750822&&issued.repository_selection==="selected";
 const allowed=permissions&&typeof permissions==="object"&&
  ["contents","issues","pull_requests"].every(x=>permissions[x]==="read")&&
  Object.entries(permissions).every(([k,v])=>
   ["contents","issues","pull_requests","metadata"].includes(k)&&v==="read");
 // GitHub installation tokens are opaque (stateless ghs_APPID_JWT since Oct 2026).
 // Do not parse or constrain token internals; only require a bounded,
 // header-safe ghs_ value. Repo, permissions and expiry remain independent.
 const token=issued?.token;
 const tokenSafe=typeof token==="string"&&token.startsWith("ghs_")&&
  token.length>=16&&token.length<=4096&&!/[\x00-\x20\x7f]/.test(token);
 if(!tokenSafe||
    !Number.isFinite(expiry)||expiry<=now+60||expiry>now+3660||
    !matching||!allowed)
  return{error:GITHUB_APP_ERROR("GITHUB_INSTALLATION_TOKEN","RESPONSE_INVALID",r)};
 return{token:issued.token};
}
async function GITHUB(info,e,now){
 const actor=String(e.EDGE_HOST_GITHUB_ACTOR_ID||"");
 if(!/^[1-9][0-9]{0,19}$/.test(actor)||Math.abs(now-info.when)>300||
    !/^[0-9a-f]{64}$/.test(info.release))return "DENIED";
 const id=info.id.slice("issue1-comment-".length);
 const base="https://api.github.com/repos/iamaman11/sing-box";
 const installation=await GITHUB_INSTALLATION_AUTH(e,now);
 if(installation.error)return installation.error;
 const headers={"Accept":"application/vnd.github+json","User-Agent":"sing-box-host-authorizer",
  "Authorization":"Bearer "+installation.token};
 // Cloudflare Workers supports manual redirect; ALL GitHub 3xx are rejected.
 // Separate fetch, HTTP, and JSON decoding so an incident has one exact stage.
 async function GITHUB_GET(path,stage){
  let r;
  try{r=await fetch(base+path,{redirect:"manual",headers})}
  catch(e){return{error:GHFAIL(stage,"FETCH_EXCEPTION",null,e)}}
  if(r.status>=300&&r.status<400)return{error:GHFAIL(stage,"REDIRECT",r)};
  if(!r.ok)return{error:GHFAIL(stage,"HTTP",r)};
  try{return{value:await r.json()}}
  catch(e){return{error:GHFAIL(stage,"RESPONSE_DECODE",r,e)}}
 }
 const commentResult=await GITHUB_GET("/issues/comments/"+id,"GITHUB_COMMENT");
 if(commentResult.error)return commentResult.error;
 const c=commentResult.value,stamp=Date.parse(c?.created_at)/1000;
 // Rust encodes explicit native historical adjudication as action=RECOVER,
 // but its GitHub command has an exact --adjudicate suffix. Authorize only
 // that VM whole-resource form; no generic fallback or unsigned journal reset.
 const expectedCommand=info.kind===2&&info.action===3&&info.resource==="sing-box"
   ? "/host recover "+info.m+" --adjudicate"
   : "/host "+(info.action===2?"apply":info.action===3?"recover":info.action===7?"start":"stop")+" "+info.m+
     (info.resource==="sing-box"?"":" "+info.resource);
 if(!c||String(c.user?.id)!==actor||c.issue_url!==base+"/issues/1"||
    c.updated_at!==c.created_at||!Number.isFinite(stamp)||
    stamp>now+30||info.when<stamp-30||
    c.body!==expectedCommand)return "DENIED";
 const tag="edge-release-"+info.release;
 const releaseResult=await GITHUB_GET("/releases/tags/"+tag,"GITHUB_RELEASE");
 if(releaseResult.error)return releaseResult.error;
 const value=releaseResult.value;
 if(!value||value.tag_name!==tag||value.draft!==false||value.prerelease!==false||
    !/^[0-9a-f]{40}$/.test(value.target_commitish))return "DENIED";
 if(stamp>=now-300)return "APPROVED";
 // A stale comment is allowed ONLY after an exact accepted first-use
 // receipt merge, with the original machine and operation still pinned.
 if(info.kind!==2||info.action!==2||info.resource!=="sing-box")return "DENIED";
 const accepted=value.target_commitish;
 const mainResult=await GITHUB_GET("/git/ref/heads/main","GITHUB_MAIN");
 if(mainResult.error)return mainResult.error;
 const branch=mainResult.value;
 if(branch?.object?.type!=="commit"||branch.object.sha!==accepted)return "DENIED";
 const pullsResult=await GITHUB_GET("/commits/"+accepted+"/pulls?per_page=20","GITHUB_PULLS");
 if(pullsResult.error)return pullsResult.error;
 const prs=pullsResult.value;
 if(!Array.isArray(prs))return "DENIED";
 const matched=prs.filter(pr=>pr.merged_at!=null&&pr.draft===false&&
    pr.base?.ref==="main"&&pr.head?.repo?.full_name==="iamaman11/sing-box"&&
    pr.merge_commit_sha===accepted&&
    pr.head?.ref==="host-receipt-"+info.m+"-"+id&&
    pr.title==="host: register native receipt for "+info.m);
 if(matched.length!==1)return "DENIED";
 const merged=Date.parse(matched[0].merged_at)/1000;
 return Number.isFinite(merged)&&merged>=stamp&&merged<=now+30&&
    now-merged<=86400?"APPROVED":"DENIED";
}
async function ACCESS_REASON(q,e){
const iss=e.EDGE_HOST_ACCESS_ISSUER,aud=e.EDGE_HOST_ACCESS_AUD;
// Optional second Access app audience: only /v1/host/* has this scope.
// With the installed eight-binding VM Worker it is absent: no behavior drift.
const routeAud=e.EDGE_HOST_ROUTE_ACCESS_AUD;
// Production requests have an absolute URL. The pure ACCESS() contract
// fixture also calls this helper with headers only; that is never a Host
// route and must preserve the original VM JWT admission semantics.
let hostRoute=false;
if(typeof q.url==="string"){
 try{hostRoute=new URL(q.url).pathname.startsWith("/v1/host/")}
 catch{return "WORKER_CONFIG_UNPROVEN"}
}
if(routeAud!==undefined&&(typeof routeAud!=="string"||
    routeAud.length<8||routeAud.length>256||routeAud===aud))return "WORKER_CONFIG_UNPROVEN";
if(typeof iss!=="string"||!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(iss)||typeof aud!=="string"||aud.length<8||aud.length>256)return "WORKER_CONFIG_UNPROVEN";
const t=q.headers.get("Cf-Access-Jwt-Assertion");
if(!t)return "JWT_MISSING";
if(t.length>8192)return "JWT_MALFORMED";
const parts=t.split(".");if(parts.length!==3)return "JWT_MALFORMED";
let h,c;try{h=JSON.parse(TD.decode(B64(parts[0])));c=JSON.parse(TD.decode(B64(parts[1])))}catch{return "JWT_MALFORMED"}
if(!h||h.alg!=="RS256"||typeof h.kid!=="string"||!c)return "JWT_MALFORMED";
if(c.iss!==iss)return "JWT_ISSUER_MISMATCH";
const allowed=hostRoute&&routeAud!==undefined?[aud,routeAud]:[aud];
if(!(typeof c.aud==="string"?allowed.includes(c.aud):Array.isArray(c.aud)&&
     c.aud.length>0&&c.aud.every(x=>typeof x==="string")&&
     c.aud.some(x=>allowed.includes(x))))return "JWT_AUDIENCE_MISMATCH";
const now=Math.floor(Date.now()/1000);
if(!Number.isInteger(c.exp))return "JWT_MALFORMED";
if(c.exp<=now)return "JWT_EXPIRED";
if(c.nbf!==undefined&&(!Number.isInteger(c.nbf)||c.nbf>now+60))return "JWT_NOT_YET_VALID";
// Do not expose exception strings, URLs, JWTs or key material. The bounded
// reason separates denied Worker subrequests from transport failures and
// redirect violations, without weakening the single pinned JWKS origin.
function JWKS_FETCH_FAILURE(e){
 const m=typeof e?.message==="string"?e.message:"";
 if(/(?:^|[^0-9])1042(?:[^0-9]|$)|same.zone|another Worker on the same zone/i.test(m))return "JWT_JWKS_FETCH_SAME_ZONE_BLOCKED";
 if(/(?:^|[^0-9])1024(?:[^0-9]|$)|Cloudflare.owned IP/i.test(m))return "JWT_JWKS_FETCH_CLOUDFLARE_IP_BLOCKED";
 if(/(?:^|[^0-9])1021(?:[^0-9]|$)|host it cannot access/i.test(m))return "JWT_JWKS_FETCH_HOST_BLOCKED";
 if(/redirect/i.test(m))return "JWT_JWKS_FETCH_REDIRECT_BLOCKED";
 if(/timeout|timed out/i.test(m)||e?.name==="TimeoutError")return "JWT_JWKS_FETCH_TIMEOUT";
 if(/dns|resolve|ENOTFOUND/i.test(m))return "JWT_JWKS_FETCH_DNS_FAILED";
 if(/tls|certificate|ssl/i.test(m))return "JWT_JWKS_FETCH_TLS_FAILED";
 if(/Illegal invocation/i.test(m))return "JWT_JWKS_FETCH_ILLEGAL_INVOCATION";
 if(e?.name==="TypeError")return "JWT_JWKS_FETCH_TYPE_ERROR";
 return "JWT_JWKS_FETCH_FAILED";
}
// Workers do not implement Fetch redirect:"error": it throws before any
// JWKS subrequest. Use supported manual mode and reject ALL 3xx without
// following Location, preserving the exact pinned issuer and key origin.
let res;try{res=await fetch(iss+"/cdn-cgi/access/certs",{redirect:"manual"})}catch(e){return JWKS_FETCH_FAILURE(e)}
if(res.status>=300&&res.status<400)return "JWT_JWKS_FETCH_REDIRECT_BLOCKED";
if(!res.ok)return "JWT_JWKS_HTTP_UNAVAILABLE";
let certs;try{certs=await res.json()}catch{return "JWT_JWKS_INVALID"}
if(!certs||!Array.isArray(certs.keys))return "JWT_JWKS_INVALID";
const jwk=certs.keys.find(k=>k&&k.kid===h.kid&&k.kty==="RSA");
if(!jwk)return "JWT_KID_NOT_FOUND";
let key;try{key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"])}catch{return "JWT_KEY_IMPORT_FAILED"}
const sig=B64(parts[2]);if(!sig||sig.length===0)return "JWT_SIGNATURE_MALFORMED";
try{return await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,sig,TE.encode(parts[0]+"."+parts[1]))?"OK":"JWT_SIGNATURE_REJECTED"}catch{return "JWT_SIGNATURE_VERIFY_FAILED"}}
async function ACCESS(q,e){return await ACCESS_REASON(q,e)==="OK"}
// GET is a strictly read-only proof of this same authenticated Access JWT.
// It never parses HostIntent, calls GitHub approval or mints a signature.
async function HOST_AUTH_DIAGNOSTIC(q,e,u){if(P!==__HOST_SIGNER_PROJECTION__||q.method!=="GET"||u.search)return new Response(null,{status:404,headers:NO});
const reason=await ACCESS_REASON(q,e);
return new Response(null,{status:reason==="OK"?204:403,headers:{...NO,"X-Host-Authorization-Reason":reason,"X-Host-Authorization-Scope":"READ_ONLY_NO_MUTATION"}})}
// Administrative programs are not allowlisted. Approval is byte-exact,
// GitHub actor-scoped and cryptographically separate from normal HostIntent.
function ADMIN_INFO(b){
 let p=0,last=0,schema=0,m=null,cid=0,argv=[],release=null,when=0,comment=null,cwd="",env=[],input=null,timeout=0,publish=false;
 let seen=new Set();
 while(p<b.length){
  const k=V(b,p);if(!k)return null;
  const f=Number(k[0]>>3n),w=Number(k[0]&7n);p=k[1];
  if(f<last||(f===last&&f!==4&&f!==9)||f<1||f>12)return null;
  last=f;seen.add(f);
  if(f===1||f===3||f===6||f===11||f===12){
   if(w!==0)return null;
   const n=V(b,p);if(!n||n[0]>BigInt(Number.MAX_SAFE_INTEGER))return null;
   p=n[1];const v=Number(n[0]);
   if(f===1)schema=v;if(f===3)cid=v;if(f===6)when=v;if(f===11)timeout=v;
   if(f===12){if(v!==1)return null;publish=true}
  }else{
   if(w!==2)return null;
   const n=V(b,p);if(!n||n[0]>BigInt(b.length))return null;
   p=n[1];const size=Number(n[0]);if(size>b.length-p)return null;
   const data=b.slice(p,p+size);p+=size;
   if(f===5||f===7){if(size!==32)return null;
    const hex=Array.from(data,x=>x.toString(16).padStart(2,"0")).join("");
    if(f===5)release=hex;else comment=hex;continue}
   if(f===10){input=data;continue}
   let txt;try{txt=TD.decode(data)}catch{return null}
   if(f===2)m=txt;if(f===4)argv.push(txt);if(f===8)cwd=txt;
   if(f===9)env.push(txt);
  }
 }
 if(schema!==1||!Number.isSafeInteger(cid)||cid<=0||!Number.isSafeInteger(when)||when<=0||
    typeof m!=="string"||!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(m)||
    argv.length<1||argv.length>128||argv.some(x=>!x||x.length>8192||x.includes(String.fromCharCode(0)))||
    !/^[0-9a-f]{64}$/.test(release||"")||!/^[0-9a-f]{64}$/.test(comment||"")||
    cwd.length>2048||cwd.includes(String.fromCharCode(0))||
    (cwd&&!cwd.startsWith("/")&&!/^[A-Za-z]:\\/.test(cwd))||
    env.length>128||env.some(x=>x.length>8192||!x.match(/^[A-Za-z0-9_]+=/))||
    !Number.isInteger(timeout)||timeout<1||timeout>3600||
    b.length>32768||[1,2,3,4,5,6,7,11].some(n=>!seen.has(n)))
  return null;
 return {m,cid,argv,release,when,comment,cwd,env,input,timeout,publish,id:"issue1-comment-"+cid};
}
function ADMIN_ARGS_B64(payload){
 const bytes=TE.encode(JSON.stringify(payload));let s="";
 for(const c of bytes)s+=String.fromCharCode(c);
 return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function ADMIN_GITHUB(info,e,now){
 const actor=String(e.EDGE_HOST_GITHUB_ACTOR_ID||"");
 if(!/^[1-9][0-9]{0,19}$/.test(actor)||Math.abs(info.when-now)>300)return "DENIED";
 const installation=await GITHUB_INSTALLATION_AUTH(e,now);
 if(installation.error)return installation.error;
 const base="https://api.github.com/repos/iamaman11/sing-box";
 const headers={"Accept":"application/vnd.github+json","User-Agent":"sing-box-host-authorizer",
    "Authorization":"Bearer "+installation.token};
 async function get(path,stage){
  let r;try{r=await fetch(base+path,{redirect:"manual",headers})}
  catch(err){return {error:GHFAIL(stage,"FETCH_EXCEPTION",null,err)}}
  if(r.status>=300&&r.status<400)return {error:GHFAIL(stage,"REDIRECT",r)};
  if(!r.ok)return {error:GHFAIL(stage,"HTTP",r)};
  try{return {value:await r.json()}}
  catch(err){return {error:GHFAIL(stage,"RESPONSE_DECODE",r,err)}}
 }
 const res=await get("/issues/comments/"+info.cid,"ADMIN_COMMENT");
 if(res.error)return res.error;
 const c=res.value,stamp=Date.parse(c?.created_at)/1000;
 const stdin=info.input===null?"":btoa(Array.from(info.input,x=>String.fromCharCode(x)).join(""))
    .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
 const payload={argv:info.argv,cwd:info.cwd,environment:info.env,stdin_base64:stdin,
    timeout_seconds:info.timeout,publish_output:info.publish};
 const body="/host admin "+info.m+" "+ADMIN_ARGS_B64(payload);
 if(!c||String(c.user?.id)!==actor||c.issue_url!==base+"/issues/1"||
   c.body!==body||c.updated_at!==c.created_at||!Number.isFinite(stamp)||
   stamp>now+30||now-stamp>300||info.when<stamp-30||
   false)return "DENIED";
 const sha=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",TE.encode(body))),
   x=>x.toString(16).padStart(2,"0")).join("");
 if(sha!==info.comment)return "DENIED";
 const rel=await get("/releases/tags/edge-release-"+info.release,"ADMIN_RELEASE");
 if(rel.error)return rel.error;
 const v=rel.value;
 if(!v||v.tag_name!=="edge-release-"+info.release||v.draft!==false||
   v.prerelease!==false||!/^[0-9a-f]{40}$/.test(v.target_commitish||""))return "DENIED";
 const main=await get("/git/ref/heads/main","ADMIN_MAIN");
 if(main.error)return main.error;
 if(main.value?.object?.type!=="commit"||main.value.object.sha!==v.target_commitish)return "DENIED";
 return "APPROVED";
}
async function ADMIN_AUTHORIZE(q,e,u){
 if(P!==__HOST_SIGNER_PROJECTION__||q.method!=="POST"||u.search||
    q.headers.get("Content-Type")!=="application/x-protobuf")return new Response(null,{status:404,headers:NO});
 const k=e.EDGE_HOST_SIGNING_PKCS8_BASE64,id=e.EDGE_HOST_SIGNING_KEY_ID;
 if(typeof k!=="string"||typeof id!=="string"||
   !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id))
  return new Response(null,{status:404,headers:NO});
 const access=await ACCESS_REASON(q,e);
 if(access!=="OK")return new Response(null,{status:403,headers:{...NO,"X-Host-Authorization-Reason":access}});
 if(Number(q.headers.get("Content-Length"))>32768)return new Response(null,{status:413,headers:NO});
 let raw;try{raw=new Uint8Array(await q.arrayBuffer())}
 catch{return new Response(null,{status:400,headers:NO})}
 if(!raw.length||raw.length>32768)return new Response(null,{status:413,headers:NO});
 const info=ADMIN_INFO(raw);if(!info)return new Response(null,{status:400,headers:NO});
 const now=Math.floor(Date.now()/1000);
 const approval=await ADMIN_GITHUB(info,e,now);
 const decision=typeof approval==="string"?approval:approval.decision;
 if(decision!=="APPROVED"){
  return new Response(null,{status:decision==="UNAVAILABLE"?503:403,
   headers:{...NO,"X-Host-Authorization-Reason":decision==="UNAVAILABLE"?
    "GITHUB_DEPENDENCY_UNAVAILABLE":"GITHUB_APPROVAL_DENIED"}});
 }
 const issued=now,expires=now+120,kid=TE.encode(id),oid=TE.encode(info.id);
 const payload=CAT(TE.encode("sing-box/native-admin-authorization/v1:"),
   U32(raw.length),raw,U32(kid.length),kid,U32(oid.length),oid,U64(issued),U64(expires));
 const signed=await HOST_SIGNER_SIGN(k,payload);
 if(signed.reason)return new Response(null,{status:503,headers:{...NO,"X-Host-Authorization-Reason":signed.reason}});
 const output=CAT(FNUM(1,1),FLD(2,kid),FLD(3,oid),FNUM(4,issued),FNUM(5,expires),FLD(6,signed.signature));
 return new Response(output,{status:200,headers:{"Content-Type":"application/x-protobuf",
  "Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
}
// Read-only cryptographic identity of this ACTIVE Worker process. A random
// caller challenge is bound to the actual loaded signing secret. It is not a
// HostAuthorization, never contacts GitHub and cannot execute host actions.
async function HOST_SIGNER_IDENTITY(q,e,u){
 if(P!==__HOST_SIGNER_PROJECTION__||q.method!=="GET"||
    u.searchParams.size!==1)return new Response(null,{status:404,headers:NO});
 const challengeHex=u.searchParams.get("challenge");
 if(!/^[0-9a-f]{64}$/.test(challengeHex||""))return new Response(null,{status:404,headers:NO});
 const access=await ACCESS_REASON(q,e);
 if(access!=="OK")return new Response(null,{status:403,headers:{...NO,"X-Host-Authorization-Reason":access}});
 const encoded=e.EDGE_HOST_SIGNING_PKCS8_BASE64,id=e.EDGE_HOST_SIGNING_KEY_ID;
 if(typeof id!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id))
  return new Response(null,{status:503,headers:{...NO,"X-Host-Authorization-Reason":"HOST_SIGNER_KEY_INVALID"}});
 const raw=B64(encoded),parsed=raw===null?null:HOST_SIGNER_PKCS8(raw);
 if(!parsed)return new Response(null,{status:503,headers:{...NO,"X-Host-Authorization-Reason":"HOST_SIGNER_KEY_INVALID"}});
 // Export only inside the Worker to derive the Ed25519 PUBLIC key from the
 // exact PKCS8 secret. Never emit, store or log the JWK private component d.
 let publicKey;
 try{
  const privateKey=await crypto.subtle.importKey("pkcs8",parsed.v1,{name:"Ed25519"},true,["sign"]);
  const jwk=await crypto.subtle.exportKey("jwk",privateKey);
  if(jwk.kty!=="OKP"||jwk.crv!=="Ed25519"||typeof jwk.x!=="string")throw Error("not Ed25519");
  publicKey=B64(jwk.x);
  if(publicKey===null||publicKey.length!==32||
     (parsed.publicKey!==null&&!publicKey.every((v,i)=>v===parsed.publicKey[i])))
    throw Error("signer public identity mismatch");
 }catch{
  return new Response(null,{status:503,headers:{...NO,"X-Host-Authorization-Reason":"HOST_SIGNER_IDENTITY_UNAVAILABLE"}});
 }
 const challenge=Uint8Array.from(challengeHex.match(/../g),part=>parseInt(part,16));
 const idBytes=TE.encode(id),issued=Math.floor(Date.now()/1000);
 const message=CAT(TE.encode("sing-box/host-signer-identity/v1:"),challenge,
   publicKey,U32(idBytes.length),idBytes,U64(issued));
 const proof=await HOST_SIGNER_SIGN(encoded,message);
 if(proof.reason)return new Response(null,{status:503,headers:{...NO,"X-Host-Authorization-Reason":proof.reason}});
 const body=CAT(FNUM(1,1),FLD(2,challenge),FLD(3,publicKey),FLD(4,idBytes),
   FNUM(5,issued),FLD(6,proof.signature));
 return new Response(body,{status:200,headers:{"Content-Type":"application/x-protobuf",
   "Cache-Control":"no-store","X-Host-Authorization-Scope":"SIGNED_IDENTITY_NO_MUTATION",
   "X-Content-Type-Options":"nosniff"}});
}
async function AUTHORIZE(q,e,u){if(P!==__HOST_SIGNER_PROJECTION__)return new Response(null,{status:404,headers:NO});if(q.method!=="POST"||u.search||q.headers.get("Content-Type")!=="application/x-protobuf")return new Response(null,{status:404,headers:NO});
const k=e.EDGE_HOST_SIGNING_PKCS8_BASE64,id=e.EDGE_HOST_SIGNING_KEY_ID,actor=String(e.EDGE_HOST_GITHUB_ACTOR_ID||"");
if(typeof k!=="string"||typeof id!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id)||!/^[1-9][0-9]{0,19}$/.test(actor))return new Response(null,{status:404,headers:NO});
const reason=await ACCESS_REASON(q,e);if(reason!=="OK")return new Response(null,{status:403,headers:{...NO,"X-Host-Authorization-Reason":reason}});
if(Number(q.headers.get("Content-Length"))>8192)return new Response(null,{status:413,headers:NO});
let raw;try{raw=new Uint8Array(await q.arrayBuffer())}catch{return new Response(null,{status:400,headers:NO})}
if(!raw.length||raw.length>8192)return new Response(null,{status:413,headers:NO});
// GitHub issue #1 is the ONLY operator command source. A valid Cloudflare
// service-token by itself cannot authorize a machine, action or an old comment.
const info=INFO(raw);if(!info)return new Response(null,{status:400,headers:NO});
const approval=await GITHUB(info,e,Math.floor(Date.now()/1000));
const decision=typeof approval==="string"?approval:approval.decision;
if(decision!=="APPROVED"){
 const h={...NO,"X-Host-Authorization-Reason":decision==="UNAVAILABLE"?
   "GITHUB_DEPENDENCY_UNAVAILABLE":"GITHUB_APPROVAL_DENIED"};
 if(typeof approval==="object"&&approval!==null){
  h["X-Host-Github-Stage"]=approval.stage;
  h["X-Host-Github-Kind"]=approval.kind;
  h["X-Host-Github-Operation-Id"]=info.id;
  for(const [field,name] of [["http_status","Http-Status"],
   ["exception_class","Exception-Class"],["rate_limit_remaining","Rate-Limit-Remaining"],
   ["rate_limit_reset","Rate-Limit-Reset"],["retry_after","Retry-After"],
   ["github_request_id","Request-Id"]]){
   if(approval[field]!==undefined)h["X-Host-Github-"+name]=String(approval[field]);
  }
 }
 return new Response(null,{status:decision==="UNAVAILABLE"?503:403,headers:h});
}
const op=info.id;
const issued=Math.floor(Date.now()/1000),expires=issued+120,kid=TE.encode(id),oid=TE.encode(op);
const payload=CAT(TE.encode("sing-box/native-host-authorization/v1:"),U32(raw.length),raw,U32(kid.length),kid,U32(oid.length),oid,U64(issued),U64(expires));
const signed=await HOST_SIGNER_SIGN(k,payload);
if(signed.reason)return new Response(null,{status:503,headers:{...NO,"X-Host-Authorization-Reason":signed.reason}});
const signature=signed.signature;
const out=CAT(FNUM(1,1),FLD(2,kid),FLD(3,oid),FNUM(4,issued),FNUM(5,expires),FLD(6,signature));
return new Response(out,{status:200,headers:{"Content-Type":"application/x-protobuf","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}})}
export default{async fetch(q,e){const u=new URL(q.url);if(u.pathname==="/v1/host/admin/authorize")return ADMIN_AUTHORIZE(q,e,u);if(u.pathname==="/v1/host/identity")return HOST_SIGNER_IDENTITY(q,e,u);if(u.pathname==="/v1/host/authorize")return q.method==="GET"?HOST_AUTH_DIAGNOSTIC(q,e,u):AUTHORIZE(q,e,u);// When a second Host Access audience is configured, defend VM credential
// isolation at the signed Worker boundary too. The original 8-binding VM
// Worker remains byte-for-byte equivalent on credential requests.
if(q.method==="GET"&&u.pathname==="/v1/credentials"&&
   e.EDGE_HOST_ROUTE_ACCESS_AUD!==undefined){
 const reason=await ACCESS_REASON(q,e);
 if(reason!=="OK")return new Response(null,{status:403,headers:{...NO,
   "X-Host-Authorization-Reason":reason}});
}
const x=u.searchParams.get("generation");
if(q.method==="GET"&&u.pathname==="/v1/proof-slot"){const k=u.searchParams.get("slot"),i=k==="a"?0:k==="b"?1:-1;if(u.searchParams.size!==2||i<0||x!==Q[i])return new Response(null,{status:404,headers:{"Cache-Control":"no-store"}});const b=H(e[S[i]]);if(b===null)return new Response(null,{status:409,headers:{"Cache-Control":"no-store"}});const h=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",b))).map(x=>x.toString(16).padStart(2,"0")).join("");return new Response(null,{status:h===D[i]?204:409,headers:{"Cache-Control":"no-store"}})}
if(q.method!=="GET"||u.pathname!=="/v1/credentials"||u.searchParams.size!==1||x===null||!/^(0|[1-9][0-9]*)$/.test(x))return new Response(null,{status:404,headers:{"Cache-Control":"no-store"}});let n;try{n=BigInt(x)}catch{return new Response(null,{status:404,headers:{"Cache-Control":"no-store"}})}const m=[];for(const s of S){const b=H(e[s]);if(b!==null&&G(b)===n)m.push(b)}if(m.length!==1)return new Response(null,{status:m.length?409:404,headers:{"Cache-Control":"no-store"}});return new Response(m[0],{status:200,headers:{"Content-Type":"application/x-protobuf","Cache-Control":"no-store"}})}};"#
        .replace("__PROJECTION__", &(projection_kind as i32).to_string())
        .replace("__HOST_SIGNER_PROJECTION__", &(CredentialProjectionKind::Vm as i32).to_string())
        .replace("__DUMMY_A_DIGEST__", &sha256_hex(&slots[0].payload))
        .replace("__DUMMY_B_DIGEST__", &sha256_hex(&slots[1].payload))
        .replace(
            "__DUMMY_A_GENERATION__",
            &CREDENTIAL_DUMMY_PROBE_GENERATION_A.to_string(),
        )
        .replace(
            "__DUMMY_B_GENERATION__",
            &CREDENTIAL_DUMMY_PROBE_GENERATION_B.to_string(),
        );
    let version_tag = format!(
        "sing-box-phase6-ab-{projection}-{}",
        &sha256_hex(source.as_bytes())[..16]
    );
    Ok(DeliveryWorkerMaterial {
        source,
        version_tag,
        slots,
    })
}

fn legacy_worker_version_tag(projection: &str) -> Result<String, String> {
    let payload = CredentialIsolationProbe {
        schema_version: 1,
        generation: 1,
        projection: projection_kind(projection)? as i32,
        dummy_non_secret: true,
    }
    .encode_to_vec();
    let payload_hex = hex_encode(&payload);
    let source = format!(
        "const H=\"{payload_hex}\";const B=new Uint8Array(H.length/2);for(let i=0;i<B.length;i++)B[i]=Number.parseInt(H.slice(i*2,i*2+2),16);export default{{async fetch(request){{const u=new URL(request.url);if(request.method!==\"GET\"||u.pathname!==\"/v1/credentials\"||u.searchParams.size!==1||u.searchParams.get(\"generation\")!==\"1\")return new Response(null,{{status:404,headers:{{\"Cache-Control\":\"no-store\"}}}});return new Response(B,{{status:200,headers:{{\"Content-Type\":\"application/x-protobuf\",\"Cache-Control\":\"no-store\"}}}})}} }};\n"
    );
    Ok(format!(
        "sing-box-phase2-{projection}-{}",
        &sha256_hex(source.as_bytes())[..16]
    ))
}

fn print_observation(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
) -> Result<(), String> {
    println!("credential_delivery_account={}", desired.target_account_id);
    println!(
        "credential_delivery_control_token_identity={}",
        observed.control_token_identity.id
    );
    for projection in projections(desired) {
        let current = projection_observation(observed, &projection.projection)?;
        let bindings = current
            .worker_secret_bindings
            .iter()
            .map(|binding| format!("{}:{}", binding.name, binding.binding_type))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "credential_delivery_projection={} worker={} version_tag={} binding_count={} secret_bindings={}",
            projection.projection,
            projection.worker_name,
            current.worker_version_tag.as_deref().unwrap_or("ABSENT"),
            current
                .worker_binding_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned()),
            if bindings.is_empty() {
                "ABSENT"
            } else {
                bindings.as_str()
            }
        );
        println!(
            "credential_delivery_projection={} latest_version_id={} latest_version_tag={} active_deployment_id={} active_version_ids={}",
            projection.projection,
            current
                .worker_latest_version_id
                .as_deref()
                .unwrap_or("ABSENT"),
            current
                .worker_latest_version_tag
                .as_deref()
                .unwrap_or("ABSENT"),
            current
                .worker_active_deployment_id
                .as_deref()
                .unwrap_or("ABSENT"),
            if current.worker_active_version_ids.is_empty() {
                "ABSENT".to_owned()
            } else {
                current.worker_active_version_ids.join(",")
            }
        );
        println!(
            "credential_delivery_projection={} host_token_enabled={}",
            projection.projection,
            current
                .host_service_token_enabled
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ABSENT".to_owned())
        );
    }
    Ok(())
}

fn print_terminal(
    desired: &ProductionCredentialPlaneOwnership,
    observed: &CredentialPlaneObservation,
    mutations: u32,
) -> Result<(), String> {
    print_observation(desired, observed)?;
    println!("credential_delivery_status=PASS");
    println!("credential_delivery_contract=FIXED_A_B");
    println!("credential_secret_slots_per_projection=2");
    println!("provider_mutations={mutations}");
    println!("real_credentials_created=0");
    println!("production_runtime_mutations=0");
    Ok(())
}

fn action_name(action: &CredentialDeliveryAction) -> &'static str {
    match action {
        CredentialDeliveryAction::Noop => "NOOP",
        CredentialDeliveryAction::InstallDummyAbContract { .. } => "INSTALL_DUMMY_A_B_CONTRACT",
        CredentialDeliveryAction::RestoreFixedAbVersionTag { .. } => {
            "RESTORE_FIXED_A_B_VERSION_TAG"
        }
        CredentialDeliveryAction::RestoreFixedAbBaseline { .. } => "RESTORE_FIXED_A_B_BASELINE",
        CredentialDeliveryAction::UpgradeSlotProofCode { .. } => "UPGRADE_SLOT_PROOF_CODE",
    }
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be blank"));
    }
    Ok(value)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode_worker_host_signer_pkcs8(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "cloudflare_credential_plane_command_tests.rs"]
mod tests;
