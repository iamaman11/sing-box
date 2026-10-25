#[path = "vultr_access_readiness.rs"]
mod access_readiness;
use access_readiness::*;

use crate::application_lifecycle_command::{
    acceptance_stage_initial_policy, load_application_desired,
};
use crate::cloudflare_dns_lifecycle_command::acceptance_create_or_reuse as converge_initial_disposable_dns;
use crate::credential_initial_journal::verify_initial_vm_runtime_gate;
use crate::vultr_host_bootstrap::{
    HostSubstrateVersions, InstanceAction, OperationalProvider, VultrOperationalApiProvider,
    apply_instance_action, capture_ssh_transport_stage_once, prepare_strict_bootstrap,
    prove_restricted_control_negative_capabilities, start_strict_agent_tunnel, strict_scp_upload,
    strict_ssh_accept, strict_ssh_capture, strict_ssh_run, strict_ssh_run_stdin,
    verify_operator_key_matches, wait_provider_ready,
};
use crate::vultr_host_substrate_service::{
    HostSubstrateExecutionPolicy, apply_host_substrate_once, build_host_substrate_authority,
};
use crate::vultr_lifecycle_service::{
    ApplyAction, ApplyReport, CreatePrerequisites, LifecycleExecutionPolicy, LifecycleProvider,
    VultrApiProvider, apply_machine_with_firewall_profiles, authorize_vultr_destroy,
    authorize_vultr_machine, destroy_machine_with_firewall_profiles,
    inventory_desired_state_with_firewall_profiles, plan_desired_state_with_firewall_profiles,
};
use crate::vultr_support_resources::{
    FirewallProfile, FirewallProfileSet, FirewallRuleSpec, ResolvedFirewallProfile,
    SupportResourceProvider, VultrSupportApiProvider, cleanup_environment_support_resources,
    controller_access_cleanup_projection_matches, controller_ipv4_access_specs,
    ensure_firewall_profile, ensure_persistent_firewall_profile, firewall_group_description,
    firewall_rule_spec, observe_verified_firewall_bindings, public_key_material,
    release_controller_ipv4_access, resolve_managed_ssh_key, validate_machine_catalog,
};
use edge_controller_core::application_lifecycle::{
    ApplicationBootstrapMode, DesiredApplicationState,
};
use edge_controller_core::host_substrate_lifecycle::HostSubstrateAction;
use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_controller_core::orchestration::SupportAccessLeaseState;
use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_controller_core::vultr_lifecycle::{
    DesiredState, MANAGED_BY_IDENTITY, MachineSpec, ObservedMachine, PlanClass,
    decode_provider_tags, destroy_plan,
};
use edge_orchestrator::OrchestrationContext;
use edge_provider_vultr::{VultrFirewallRule, VultrInstance};
use edge_shared_types::agent_service_client::AgentServiceClient;
use edge_shared_types::{
    CANONICAL_PRODUCTION_DESIRED_STATE_BYTES, CredentialDeliverySlot, CredentialProjectionKind,
    Empty, InitialCredentialHostProbeRequest, InitialVmCredentialRuntimeRequest,
    InitialVmCredentialRuntimeResponse,
};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tonic::Request;

// Historical acceptance-v1 preflight still guards internal, unreachable
// old helpers. It is NOT a new CLI or VM first-use mutation authority.
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
    if line1.acme_provider != "letsencrypt" {
        return Err(
            "disposable network acceptance requires publicly trusted Let's Encrypt ACME authority"
                .to_owned(),
        );
    }
    desired
        .runtime_policy
        .line2
        .as_ref()
        .ok_or_else(|| "application acceptance requires line2 runtime policy".to_owned())?;
    Ok(())
}

const CANONICAL_SSH_PUBLIC_KEY_PATH: &str = "infra/vultr/singbox-ops.pub";
const FIREWALL_PROFILES_PATH: &str = "infra/vultr/firewall-profiles.json";

/// General lifecycle may observe or reconcile an already owned VM, but it
/// is never the VM first-use owner. No SSH fallback may CREATE a new VM.
fn deny_unregistered_native_vm_create(class: &PlanClass) -> Result<(), &'static str> {
    if *class == PlanClass::Create {
        Err("HOST_VM_CREATE_REQUIRES_NATIVE_ONE_TIME_ENROLLMENT_NO_SSH")
    } else {
        Ok(())
    }
}

async fn apply_machine_value(
    spec_path: &Path,
    machine_id: &str,
    expected_authority: Option<&str>,
) -> Result<serde_json::Value, String> {
    let desired = load_desired_state(spec_path)?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profiles = load_firewall_profiles(&desired)?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let mut verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;

    let initial = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    let initial_plan = initial
        .plans
        .first()
        .cloned()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    let initial_class = initial_plan.class;
    // No general lifecycle path may silently provision the retired SSH
    // host, even if the dedicated /host first-use preflight is bypassed.
    // Observing/updating existing instances remains a separate operation.
    deny_unregistered_native_vm_create(&initial_class).map_err(str::to_owned)?;
    let authorized = authorize_vultr_machine(&desired, &initial.inventory, initial_plan)?;
    let authority_digest = expected_authority
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| authorized.authority.authority_digest.clone());
    verify_exact_authority(&authority_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    if matches!(
        initial_class,
        PlanClass::BlockedAmbiguous | PlanClass::BlockedDrift | PlanClass::ReplaceRequired
    ) {
        let plan = &initial.plans[0];
        return Err(format!(
            "machine {} is {:?}; apply refuses before support-resource mutation: {}",
            machine.id,
            plan.class,
            plan.reasons.join("; ")
        ));
    }

    let firewall = if matches!(initial_class, PlanClass::Create | PlanClass::UpdateInPlace) {
        if let Some(profile_name) = machine.provider.firewall_profile.as_deref() {
            let profile_set = profiles.as_ref().ok_or_else(|| {
                format!(
                    "machine {} references firewall profile {profile_name}, but no profile registry is loaded",
                    machine.id
                )
            })?;
            let profile = profile_set.profile(profile_name)?;
            let resolved = ensure_persistent_firewall_profile(
                &mut support_provider,
                &desired.environment,
                profile,
                &policy,
            )
            .await?;
            verified_firewalls.insert(resolved.id.clone(), resolved.profile_name.clone());
            Some(resolved)
        } else {
            None
        }
    } else {
        None
    };

    let after_support = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    let after_support_plan = after_support
        .plans
        .first()
        .cloned()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    let after_support_class = after_support_plan.class;

    if initial_class == PlanClass::UpdateInPlace && after_support_class != PlanClass::Noop {
        return Err(format!(
            "machine {} support-resource convergence did not reach NOOP: {:?}: {}",
            machine.id,
            after_support_class,
            after_support_plan.reasons.join("; ")
        ));
    }
    if initial_class != PlanClass::UpdateInPlace {
        let after_support_authorized = authorize_vultr_machine(
            &desired,
            &after_support.inventory,
            after_support_plan.clone(),
        )?;
        verify_exact_authority(&authority_digest, &after_support_authorized.authority)
            .map_err(|err| err.to_string())?;
    }

    // Native first-use is the only future CREATE owner; the old generic
    // lifecycle is limited to already-proven existing machines.
    let prerequisites = empty_create_prerequisites(machine);

    let support_reconciled =
        initial_class == PlanClass::UpdateInPlace && after_support_class == PlanClass::Noop;
    let report = if support_reconciled {
        let provider_id = after_support_plan
            .provider_id
            .clone()
            .ok_or_else(|| "converged UPDATE_IN_PLACE plan is missing provider id".to_owned())?;
        ApplyReport {
            action: ApplyAction::Noop,
            machine_id: machine.id.clone(),
            provider_id,
            final_plan: after_support_plan,
        }
    } else {
        apply_machine_with_firewall_profiles(
            &mut lifecycle_provider,
            &desired,
            machine_id,
            &authority_digest,
            &prerequisites,
            &policy,
            &verified_firewalls,
        )
        .await?
    };

    let mut operational_provider = operational_provider_from_env()?;
    let ready = wait_provider_ready(
        &mut operational_provider,
        &report.provider_id,
        60,
        std::time::Duration::from_secs(5),
    )
    .await?;

    Ok(serde_json::json!({
        "action": report.action.as_str(),
        "machine_id": report.machine_id,
        "provider_id": report.provider_id,
        "main_ip": ready.main_ip,
        "final_plan": report.final_plan,
        "provider_ready": true,
        "host_substrate_required": true,
        "support_reconciled": support_reconciled,
    }))
}

pub(crate) async fn production_converge_machine(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let value = apply_machine_value(spec_path, machine_id, None).await?;
    let action = value
        .get("action")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "production machine convergence returned no typed action".to_owned())?;
    if !matches!(action, "CREATED" | "NOOP")
        || value
            .get("provider_ready")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(format!(
            "production machine convergence returned unexpected result: {value}"
        ));
    }
    Ok(())
}

pub(crate) async fn acceptance_create_machine(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let value = apply_machine_value(spec_path, machine_id, None).await?;
    if value.get("action").and_then(serde_json::Value::as_str) != Some("CREATED")
        || value
            .get("provider_ready")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || value
            .get("host_substrate_required")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(format!(
            "fresh acceptance VM create returned unexpected result: {value}"
        ));
    }
    Ok(())
}

pub(crate) async fn exact_existing_machine_observation(
    desired: &DesiredState,
    machine_id: &str,
) -> Result<ObservedMachine, String> {
    let profiles = load_firewall_profiles(desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    if report.plans.len() != 1 {
        return Err(format!(
            "expected exactly one lifecycle plan for {machine_id}, got {}",
            report.plans.len()
        ));
    }
    let plan = &report.plans[0];
    if plan.class != PlanClass::Noop {
        return Err(format!(
            "exact machine observation requires NOOP; machine {machine_id} plan is {:?}: {}",
            plan.class,
            plan.reasons.join("; ")
        ));
    }
    let provider_id = plan
        .provider_id
        .as_deref()
        .ok_or_else(|| format!("NOOP machine plan for {machine_id} is missing provider id"))?;
    let mut matches = report
        .inventory
        .resources
        .iter()
        .filter(|resource| resource.provider_id == provider_id);
    let observed = matches
        .next()
        .ok_or_else(|| format!("NOOP machine {machine_id} is absent from observed inventory"))?;
    if matches.next().is_some() {
        return Err(format!(
            "provider inventory is ambiguous for exact machine {machine_id} ({provider_id})"
        ));
    }
    if observed.ownership.logical_id.as_deref() != Some(machine_id) {
        return Err(format!(
            "observed provider resource {provider_id} is not owned by logical machine {machine_id}"
        ));
    }
    Ok(observed.clone())
}

async fn exact_existing_machine_provider_id(
    desired: &DesiredState,
    machine_id: &str,
) -> Result<String, String> {
    Ok(exact_existing_machine_observation(desired, machine_id)
        .await?
        .provider_id)
}

fn require_disposable_initial_probe_target(spec: &str, machine: &str) -> Result<(), String> {
    if spec != "infra/vultr/application-acceptance.json" || machine != "application-acceptance-1" {
        return Err(
            "initial host proof can only target the fixed disposable application-acceptance VM"
                .to_owned(),
        );
    }
    Ok(())
}

/// Install the existing dedicated VM Access identity into the freshly staged
/// disposable host. Host identity is not an application credential and cannot
/// authorize local secret generation; the only issuer remains Worker-v2.
/// GitHub-hosted owner sends it once over the existing strict bootstrap SSH
/// stdin. Never place the token in command arguments, logs or stack policy.
fn initial_vm_access_identity_payload(
    client_id: &str,
    client_secret: &str,
) -> Result<String, String> {
    validate_bootstrap_secret("initial VM Access client ID", client_id)?;
    validate_bootstrap_secret("initial VM Access client secret", client_secret)?;
    Ok(format!(
        "CF_ACCESS_CLIENT_ID={client_id}\nCF_ACCESS_CLIENT_SECRET={client_secret}\n"
    ))
}

/// Accept existing VM Access material only with exact bytes, root ownership,
/// root-confined directory and no link. No mutation or secret disclosure.
fn validate_initial_vm_existing_identity(
    directory_owner: &str,
    file_owner: &str,
    observed_sha256: &str,
    expected_payload: &[u8],
) -> Result<(), String> {
    if directory_owner != "0:0:700" || file_owner != "0:0:600" {
        return Err("existing VM Access identity owner/mode mismatch; no replay".to_owned());
    }
    let expected = ring::digest::digest(&ring::digest::SHA256, expected_payload);
    let expected_hex: String = expected
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    if observed_sha256 != expected_hex {
        return Err(
            "existing VM Access identity differs from authorized escrow; no replay".to_owned(),
        );
    }
    Ok(())
}

async fn install_disposable_initial_vm_access_identity(
    vultr_spec_path: &str,
    machine_id: &str,
    expected_agent_sha256: &str,
    payload: &str,
) -> Result<&'static str, String> {
    require_disposable_initial_probe_target(vultr_spec_path, machine_id)?;
    let desired = load_desired_state(Path::new(vultr_spec_path))?;
    let observed = exact_existing_machine_observation(&desired, machine_id).await?;
    let target_ip = observed.main_ip.as_deref().ok_or_else(|| {
        "initial VM Access installation requires observed disposable IPv4".to_owned()
    })?;
    let key = operator_private_key_path_from_env()?;
    let public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&key, &public_key)?;

    let agent_sha = strict_ssh_capture(
        target_ip,
        machine_id,
        &key,
        &public_key,
        "sha256sum /opt/vultr-edge-stack/bin/edge-agent | cut -d' ' -f1",
    )?;
    if agent_sha != expected_agent_sha256 {
        return Err("initial VM Access installation refuses a non-ReleaseSet agent".to_owned());
    }

    // Exact fixed file, not a caller-supplied path. An interrupted write leaves
    // evidence, so a rerun fails closed instead of replacing an unknown token.
    let presence = strict_ssh_capture(
        target_ip,
        machine_id,
        &key,
        &public_key,
        "if sudo test -e /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env || sudo test -L /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env; then echo PRESENT; else echo ABSENT; fi",
    )?;
    // Existing exact owned VM is a valid NOOP only if the stored secret bytes,
    // root ownership and directory confinement equal the host identity already
    // supplied by the authorized GitHub environment. A stale, unreadable,
    // symlinked or differently provisioned identity must NEVER be overwritten.
    let directory = strict_ssh_capture(
        target_ip,
        machine_id,
        &key,
        &public_key,
        "if sudo test -L /opt/vultr-edge-stack/runtime-secrets; then echo LINK; elif sudo test -d /opt/vultr-edge-stack/runtime-secrets; then echo PRESENT; elif sudo test -e /opt/vultr-edge-stack/runtime-secrets; then echo FOREIGN; else echo ABSENT; fi",
    )?;
    if presence == "PRESENT" {
        if directory != "PRESENT" {
            return Err("initial VM Access existing secret has unknown directory owner".to_owned());
        }
        let directory_owner = strict_ssh_capture(
            target_ip,
            machine_id,
            &key,
            &public_key,
            "sudo stat -c '%u:%g:%a' /opt/vultr-edge-stack/runtime-secrets",
        )?;
        let file_owner = strict_ssh_capture(
            target_ip,
            machine_id,
            &key,
            &public_key,
            "if sudo test -L /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env; then echo LINK; elif sudo test -f /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env; then sudo stat -c '%u:%g:%a' /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env; else echo FOREIGN; fi",
        )?;
        let observed_hash = strict_ssh_capture(
            target_ip,
            machine_id,
            &key,
            &public_key,
            "sudo sha256sum /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env | cut -d' ' -f1",
        )?;
        validate_initial_vm_existing_identity(
            &directory_owner,
            &file_owner,
            &observed_hash,
            payload.as_bytes(),
        )?;
        return Ok("REUSED_EXACT");
    }
    if presence != "ABSENT" || directory != "ABSENT" {
        return Err(
            "initial VM Access identity scope is unknown; do not replay or overwrite".to_owned(),
        );
    }
    const INSTALL: &str = "set -eu; sudo -n install -d -o root -g root -m 0700 /opt/vultr-edge-stack/runtime-secrets; sudo -n install -o root -g root -m 0600 /dev/stdin /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env";
    strict_ssh_run_stdin(
        target_ip,
        machine_id,
        &key,
        &public_key,
        INSTALL,
        payload.as_bytes(),
    )
    .map_err(|err| format!("initial VM Access write outcome uncertain; do not repeat: {err}"))?;
    let owner = strict_ssh_capture(
        target_ip,
        machine_id,
        &key,
        &public_key,
        "sudo stat -c '%u:%g:%a' /opt/vultr-edge-stack/runtime-secrets/credential-access-v1.env",
    )?;
    if owner != "0:0:600" {
        return Err("initial VM Access identity ownership is not root:root mode 0600".to_owned());
    }
    Ok("CREATED_ONCE")
}

fn require_six_exact_vm_local_line2(
    response: &InitialVmCredentialRuntimeResponse,
) -> Result<(), String> {
    let expected = [
        ("http-direct", "http", 4128),
        ("socks5-direct", "socks5h", 4080),
        ("https-direct", "https", 4443),
        ("http-warp", "http", 3128),
        ("socks5-warp", "socks5h", 1080),
        ("https-warp", "https", 9443),
    ];
    if response.vm_local_line2.len() != expected.len() {
        return Err("initial VM result is missing authenticated Line2 endpoints".to_owned());
    }
    for (observed, (name, protocol, port)) in response.vm_local_line2.iter().zip(expected) {
        if observed.endpoint != name
            || observed.protocol != protocol
            || observed.port != port
            || observed.successful_samples != 5
            || observed.failed_samples != 0
            || !observed.negative_auth_rejected
        {
            return Err(format!(
                "initial VM result refuses incomplete Line2 sample for {name}"
            ));
        }
    }
    Ok(())
}

// Only the original VM runtime job can apply first-use credentials. A distinct
// post-reboot job may re-observe the same candidate, but never replay apply.
fn authorize_initial_runtime_job(job: &str, apply: bool) -> Result<(), String> {
    if (apply && job == "initial_vm_runtime")
        || (!apply && matches!(job, "initial_vm_runtime" | "initial_reboot"))
    {
        Ok(())
    } else {
        Err(
            "initial VM runtime refuses an unauthorized GitHub mutation or observation job"
                .to_owned(),
        )
    }
}

/// A fresh VM is accepted only when the protected Git/Worker/Vultr
/// evidence selects exactly one CREATE and there is no prior owned VM.
// The irreversible operation additionally requires one issue-scoped,
// durable GitHub BEGIN, a short-lived runner identity and native cloud-init.
fn admit_vm_first_use_provider_plan(
    selected: Option<&PlanClass>,
    plan_count: usize,
    prior_owned: bool,
) -> Result<(), &'static str> {
    if plan_count != 1 || !matches!(selected, Some(PlanClass::Create)) {
        return Err("HOST_FIRST_USE_PROVIDER_NOT_EXACT_CREATE_NO_REPLAY");
    }
    if prior_owned {
        return Err("HOST_FIRST_USE_PROVIDER_OWNED_VM_ALREADY_PRESENT");
    }
    Ok(())
}

/// Read-only admission before the Git receipt reservation. A previously
/// created/uncertain VM is not a fresh first-use candidate and must not
/// acquire a misleading new registration PR. Uses the existing Vultr
/// lifecycle planner and exact canonical protected Git provider spec.
pub(crate) async fn host_first_use_provider_preflight(
    machine_id: &str,
    context: &OrchestrationContext,
) -> Result<(), String> {
    let host = context.verified_vm_first_use_host(machine_id)?;
    edge_shared_types::host_lifecycle::verify_vm_first_use_git_prerequisites(&host)
        .map_err(str::to_owned)?;
    if !host.native_receipt_public_key.is_empty() {
        return Err("HOST_FIRST_USE_RECEIPT_ALREADY_REGISTERED".to_owned());
    }
    if host.vm_first_use_credential.is_none() {
        return Err("HOST_VM_FIRST_USE_CREDENTIAL_GIT_REQUIRED".to_owned());
    }
    // Preflight the same Cloudflare Access credentials used by root
    // enrollment. Missing environment secrets must not strand a draft PR
    // after the registry branch is already reserved.
    for (label, name) in [
        (
            "credential Access client id",
            "EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID",
        ),
        (
            "credential Access client secret",
            "EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET",
        ),
    ] {
        let value = env::var(name).map_err(|_| "HOST_FIRST_USE_ACCESS_IDENTITY_REQUIRED")?;
        validate_bootstrap_secret(label, &value)?;
    }
    crate::cloudflare_credential_plane_command::verify_current_vm_first_use_worker_source(&host)
        .await?;
    let provider_spec = Path::new(&host.vm_provider_spec_path);
    let desired = load_desired_state(provider_spec)?;
    if desired.machines.len() != 1 || desired.machines[0].id != machine_id {
        return Err("HOST_FIRST_USE_PROVIDER_SCOPE_NOT_SINGLE_VM".to_owned());
    }
    let profiles = load_firewall_profiles(&desired)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    validate_machine_catalog(&mut support_provider, &desired.machines[0]).await?;
    let bindings =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &bindings,
    )
    .await?;
    let prior_owned = report
        .inventory
        .resources
        .iter()
        .any(|resource| resource.ownership.logical_id.as_deref() == Some(machine_id));
    admit_vm_first_use_provider_plan(
        report.plans.as_slice().first().map(|plan| &plan.class),
        report.plans.len(),
        prior_owned,
    )
    .map_err(str::to_owned)?;
    println!("host_machine_id={machine_id}");
    println!("host_first_use_provider_plan=EXACT_CREATE_ONLY");
    println!("host_receipt_registration=NOT_YET_RESERVED");
    println!("host_mutations=0");
    println!("host_first_use_preflight=PROVIDER_AND_WORKER_GET_PROVEN");
    Ok(())
}

/// The single new-VM CREATE owner. All Git, Worker and Vultr preconditions
/// are GET-only before this signed/authorized GitHub-hosted invocation.
/// The GitHub job must persist an exact one-time BEGIN before it supplies
/// the ephemeral runner token. An unknown CREATE outcome is NEVER replayed.
pub(crate) async fn host_first_use(
    machine_id: &str,
    _installer: &Path,
    _agent: &Path,
    context: &OrchestrationContext,
) -> Result<(), String> {
    if env::var("GITHUB_RUN_ATTEMPT").as_deref() != Ok("1")
        || env::var("GITHUB_REPOSITORY").as_deref() != Ok("iamaman11/sing-box")
        || env::var("GITHUB_EVENT_NAME").as_deref() != Ok("issue_comment")
        || env::var("EDGE_HOST_BEGIN_COMMENT_ID")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_none_or(|value| value == 0)
    {
        return Err("HOST_FIRST_USE_PROTECTED_GITHUB_DURABLE_BEGIN_REQUIRED".into());
    }
    host_first_use_provider_preflight(machine_id, context).await?;
    let host = context.verified_vm_first_use_host(machine_id)?;
    let provider_spec = Path::new(&host.vm_provider_spec_path);
    let desired = load_desired_state(provider_spec)?;
    let machine = desired
        .machines
        .first()
        .ok_or("HOST_FIRST_USE_MACHINE_MISSING")?;
    if desired.machines.len() != 1
        || machine.id != machine_id
        || machine.bootstrap_profile != "singbox-native-first-use-v1"
    {
        return Err("HOST_FIRST_USE_ONLY_NATIVE_SSH_FREE_PROFILE".into());
    }
    let token = env::var("EDGE_HOST_RUNNER_REGISTRATION_TOKEN")
        .map_err(|_| "HOST_FIRST_USE_EPHEMERAL_GITHUB_TOKEN_MISSING")?;
    let deadline = env::var("EDGE_HOST_RUNNER_TOKEN_EXPIRY_UNIX")
        .map_err(|_| "HOST_FIRST_USE_GITHUB_TOKEN_EXPIRY_MISSING")?
        .parse::<u64>()
        .map_err(|_| "HOST_FIRST_USE_GITHUB_TOKEN_EXPIRY_INVALID")?;
    let release = context.release();
    let agent_sha = release.agent_sha256.as_str();
    if agent_sha.len() != 64
        || !agent_sha.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("HOST_FIRST_USE_AGENT_DIGEST_INVALID".into());
    }
    let substrate = pinned_host_substrate_versions(context)?;
    let cloud_init = crate::vultr_host_bootstrap::render_native_first_use_with_runner(
        include_str!("../../../../win/vultr-waw/cloud-init.yaml"),
        machine_id,
        &release.release_set_sha256,
        agent_sha,
        &substrate,
        &token,
        deadline,
    )?;
    // Old SSH key/certificate must not enter the provider CREATE payload.
    if cloud_init.contains("ssh_authorized_keys:") || cloud_init.contains("ssh_host_ed25519_key") {
        return Err("HOST_FIRST_USE_CLOUD_INIT_SSH_REGRESSION".into());
    }
    let profiles = load_firewall_profiles(&desired)?;
    let mut provider = lifecycle_provider_from_env()?;
    let mut support = support_provider_from_env()?;
    validate_machine_catalog(&mut support, machine).await?;
    let bindings = verified_firewall_bindings(&mut support, &desired, profiles.as_ref()).await?;
    let binding = match machine.provider.firewall_profile.as_deref() {
        None => None,
        Some(name) => Some(
            bindings
                .iter()
                .find(|(_, observed)| observed.as_str() == name)
                .map(|(id, _)| id.clone())
                .ok_or("HOST_FIRST_USE_FIREWALL_BINDING_UNPROVEN")?,
        ),
    };
    let prerequisites = CreatePrerequisites {
        bootstrap_profile: machine.bootstrap_profile.clone(),
        ssh_key_id: String::new(),
        cloud_init,
        firewall_group_id: binding,
        firewall_profile: machine.provider.firewall_profile.clone(),
    };
    let observation = plan_desired_state_with_firewall_profiles(
        &mut provider,
        &desired,
        Some(machine_id),
        &bindings,
    )
    .await?;
    admit_vm_first_use_provider_plan(
        observation.plans.first().map(|plan| &plan.class),
        observation.plans.len(),
        observation
            .inventory
            .resources
            .iter()
            .any(|resource| resource.ownership.logical_id.as_deref() == Some(machine_id)),
    )
    .map_err(str::to_owned)?;
    let plan = observation
        .plans
        .first()
        .ok_or("HOST_FIRST_USE_CREATE_PLAN_MISSING")?
        .clone();
    let authorized = authorize_vultr_machine(&desired, &observation.inventory, plan)?;
    // This is the FIRST irreversible step: the GitHub issue BEGIN and
    // external concurrency owner must already have committed to no-replay.
    let report = apply_machine_with_firewall_profiles(
        &mut provider,
        &desired,
        machine_id,
        &authorized.authority.authority_digest,
        &prerequisites,
        &LifecycleExecutionPolicy::default(),
        &bindings,
    )
    .await?;
    if report.action != ApplyAction::Created {
        return Err("HOST_FIRST_USE_PROVIDER_CREATE_NOT_PROVEN_NO_REPLAY".into());
    }
    println!("host_machine_id={machine_id}");
    println!("host_provider_id={}", report.provider_id);
    println!("host_first_use_provider_create=EXACT_NATIVE_CLOUD_INIT_ACCEPTED");
    println!("host_first_use_bootstrap_transport=GITHUB_EPHEMERAL_RUNNER_NO_SSH");
    println!("host_first_use_signed_native_receipt=AWAITING_PROTECTED_GIT");
    println!("host_first_use_user_data_scrub=REQUIRED_AFTER_RUNNER_PROOF");
    Ok(())
}

/// Complete the provider-side first-use secret scrub only after the caller
/// proved the exact fresh runner is registered and returned native proof.
/// Instance ID comes from canonical Vultr readback, NEVER caller input.
pub(crate) async fn host_first_use_scrub(
    machine_id: &str,
    context: &OrchestrationContext,
) -> Result<(), String> {
    let host = context.verified_vm_first_use_host(machine_id)?;
    let desired = load_desired_state(Path::new(&host.vm_provider_spec_path))?;
    if desired.machines.len() != 1
        || desired.machines[0].id != machine_id
        || desired.machines[0].bootstrap_profile != "singbox-native-first-use-v1"
    {
        return Err("HOST_FIRST_USE_SCRUB_WRONG_MACHINE_OR_PROFILE".into());
    }
    let profiles = load_firewall_profiles(&desired)?;
    let mut provider = lifecycle_provider_from_env()?;
    let mut support = support_provider_from_env()?;
    let bindings = verified_firewall_bindings(&mut support, &desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut provider,
        &desired,
        Some(machine_id),
        &bindings,
    )
    .await?;
    if report.plans.len() != 1 || report.plans[0].class != PlanClass::Noop {
        return Err("HOST_FIRST_USE_SCRUB_PROVIDER_OWNERSHIP_OR_STATE_UNPROVEN".into());
    }
    let instance_id = report.plans[0]
        .provider_id
        .as_deref()
        .ok_or("HOST_FIRST_USE_SCRUB_PROVIDER_ID_MISSING")?;
    let mut operational = operational_provider_from_env()?;
    crate::vultr_host_bootstrap::scrub_user_data(
        &mut operational,
        instance_id,
        2,
        Duration::from_secs(3),
    )
    .await?;
    crate::vultr_host_bootstrap::verify_user_data_scrubbed(&mut operational, instance_id).await?;
    println!("host_first_use_user_data=PROVIDER_GET_PROVED_SCRUBBED");
    println!("host_first_use_token_present_in_provider=false");
    Ok(())
}

fn validate_bootstrap_secret(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(format!("{label} is malformed"));
    }
    Ok(())
}

fn validate_runner_registration_token(value: &str) -> Result<(), String> {
    if value.len() < 16
        || value.len() > 512
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err("runner registration token is malformed".to_owned());
    }
    Ok(())
}

async fn acquire_access_with_authority(
    desired: &DesiredState,
    machine_id: &str,
    authorized_plan_digest: &str,
) -> Result<serde_json::Value, String> {
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profile_name = machine.provider.firewall_profile.as_deref().ok_or_else(|| {
        format!(
            "machine {} has no firewall_profile; acquire-access requires provider-owned SSH ingress",
            machine.id
        )
    })?;

    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let authorized = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Acquire,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    match authorized.disposition {
        PlanDisposition::Noop => {
            return Ok(serde_json::json!({
                "action": "NOOP",
                "machine_id": machine.id,
                "firewall_profile": profile_name,
                "next_plan": authorized.plan,
                "mutations_performed": 0,
            }));
        }
        PlanDisposition::Blocked => {
            return Err(format!(
                "acquire-access is blocked for machine {} by exact authorized plan",
                machine.id
            ));
        }
        PlanDisposition::Mutate => {}
    }

    let (_, resolved_profiles, _, _) = load_access_authority_profiles(desired)?;
    let profile = resolved_profiles.profile(profile_name)?;
    let policy = LifecycleExecutionPolicy::default();
    let resolved = ensure_firewall_profile(
        &mut support_provider,
        &desired.environment,
        profile,
        &policy,
    )
    .await?;

    let next = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Acquire,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if next.disposition != PlanDisposition::Noop {
        return Err(format!(
            "firewall access reconciliation completed but machine {} did not converge to NOOP",
            machine.id
        ));
    }

    Ok(serde_json::json!({
        "action": "ACQUIRED",
        "machine_id": machine.id,
        "firewall_group_id": resolved.id,
        "firewall_profile": resolved.profile_name,
        "next_plan": next.plan,
        "mutations_performed": 1,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessReconcileClass {
    Noop,
    FirewallOnly,
    Blocked,
}

fn access_reconcile_class(
    plan: &edge_controller_core::vultr_lifecycle::MachinePlan,
) -> AccessReconcileClass {
    match plan.class {
        PlanClass::Noop => AccessReconcileClass::Noop,
        PlanClass::UpdateInPlace
            if !plan.reasons.is_empty()
                && plan.reasons.iter().all(|reason| {
                    reason == "firewall profile differs or is not provider-verified"
                }) =>
        {
            AccessReconcileClass::FirewallOnly
        }
        _ => AccessReconcileClass::Blocked,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessAuthorityMode {
    Acquire,
    Release,
}

impl AccessAuthorityMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Acquire => "ACQUIRE",
            Self::Release => "RELEASE",
        }
    }
}

fn canonical_production_desired_state_sha256() -> String {
    ring::digest::digest(
        &ring::digest::SHA256,
        CANONICAL_PRODUCTION_DESIRED_STATE_BYTES,
    )
    .as_ref()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

fn load_access_authority_profile_source(
    desired: &DesiredState,
) -> Result<(FirewallProfileSet, serde_json::Value), String> {
    if desired.environment == "production" {
        let profiles = load_firewall_profiles_raw(desired)?.ok_or_else(|| {
            "production support-access requires the canonical protobuf-derived firewall profile"
                .to_owned()
        })?;
        return Ok((
            profiles,
            serde_json::Value::String(format!(
                "production-desired-state-sha256:{}",
                canonical_production_desired_state_sha256()
            )),
        ));
    }

    let path = Path::new(FIREWALL_PROFILES_PATH);
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read firewall profiles {}: {err}", path.display()))?;
    let profiles = FirewallProfileSet::parse_json(&raw)?;
    let material = serde_json::from_str(&raw)
        .map_err(|err| format!("invalid firewall profiles JSON: {err}"))?;
    Ok((profiles, material))
}

fn load_access_authority_profiles(
    desired: &DesiredState,
) -> Result<
    (
        FirewallProfileSet,
        FirewallProfileSet,
        serde_json::Value,
        String,
    ),
    String,
> {
    let (raw_profiles, profile_material) = load_access_authority_profile_source(desired)?;
    let mut resolved_profiles = raw_profiles.clone();
    let profile_names = desired
        .machines
        .iter()
        .filter_map(|machine| machine.provider.firewall_profile.clone())
        .collect::<Vec<_>>();
    let controller_ipv4 = env::var("EDGE_CONTROLLER_IPV4")
        .map_err(|_| "EDGE_CONTROLLER_IPV4 is required for access authority".to_owned())?;
    resolved_profiles
        .resolve_controller_ipv4_for_profiles(&profile_names, Some(controller_ipv4.as_str()))?;
    for profile_name in &profile_names {
        resolved_profiles.profile(profile_name)?;
    }
    Ok((
        raw_profiles,
        resolved_profiles,
        profile_material,
        controller_ipv4,
    ))
}

async fn observe_firewall_access_authority<P: SupportResourceProvider>(
    provider: &mut P,
    environment: &str,
    profile_name: &str,
) -> Result<(serde_json::Value, Vec<VultrFirewallRule>), String> {
    let description = firewall_group_description(environment, profile_name);
    let mut groups = provider
        .list_firewall_groups()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|group| group.description == description)
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    if groups.len() > 1 {
        return Err(format!(
            "multiple Vultr firewall groups have owned description {description}"
        ));
    }

    let mut rules = if let Some(group) = groups.first() {
        provider
            .list_firewall_rules(&group.id)
            .await
            .map_err(|err| err.to_string())?
    } else {
        Vec::new()
    };
    rules.sort_by_key(|rule| rule.id);
    let group = groups.first().map(|group| {
        serde_json::json!({
            "id": group.id,
            "description": group.description,
        })
    });
    let observation = serde_json::json!({
        "description": description,
        "group": group,
        "rules": rules,
    });
    Ok((observation, rules))
}

async fn build_access_authority(
    desired: &DesiredState,
    machine_id: &str,
    mode: AccessAuthorityMode,
    lifecycle_provider: &mut VultrApiProvider,
    support_provider: &mut VultrSupportApiProvider,
) -> Result<AuthorizedPlan<serde_json::Value>, String> {
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profile_name = machine.provider.firewall_profile.as_deref().ok_or_else(|| {
        format!(
            "machine {} has no firewall_profile; access authority requires provider-owned SSH ingress",
            machine.id
        )
    })?;
    let (raw_profiles, resolved_profiles, profile_material, controller_ipv4) =
        load_access_authority_profiles(desired)?;
    let raw_profile = raw_profiles.profile(profile_name)?;
    if !raw_profile
        .rules
        .iter()
        .any(|rule| rule.subnet == "@controller-ipv4")
    {
        return Err(format!(
            "firewall profile {profile_name} has no @controller-ipv4 rule"
        ));
    }

    let (support_observation, observed_rules) =
        observe_firewall_access_authority(support_provider, &desired.environment, profile_name)
            .await?;
    let desired_material = serde_json::json!({
        "desired": desired,
        "machine_id": machine_id,
        "operation": mode.as_str(),
        "controller_ipv4": controller_ipv4,
        "firewall_profiles": profile_material,
    });

    match mode {
        AccessAuthorityMode::Acquire => {
            let verified_firewalls =
                observe_verified_firewall_bindings(support_provider, desired, &resolved_profiles)
                    .await?;
            let report = plan_desired_state_with_firewall_profiles(
                lifecycle_provider,
                desired,
                Some(machine_id),
                &verified_firewalls,
            )
            .await?;
            let machine_plan = report
                .plans
                .first()
                .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?
                .clone();
            let (action, disposition) = match access_reconcile_class(&machine_plan) {
                AccessReconcileClass::Noop => ("NOOP", PlanDisposition::Noop),
                AccessReconcileClass::FirewallOnly => ("ACQUIRE", PlanDisposition::Mutate),
                AccessReconcileClass::Blocked => ("BLOCKED", PlanDisposition::Blocked),
            };
            let observed = serde_json::json!({
                "machine_inventory": report.inventory,
                "support": support_observation,
            });
            let plan = serde_json::json!({
                "action": action,
                "machine_id": machine_id,
                "firewall_profile": profile_name,
                "machine_plan": machine_plan,
            });
            authorize_plan(
                "vultr_support_access",
                &desired_material,
                &observed,
                plan,
                disposition,
            )
            .map_err(|err| err.to_string())
        }
        AccessAuthorityMode::Release => {
            let targets = controller_ipv4_access_specs(raw_profile, &controller_ipv4)?;
            if targets.is_empty() {
                return Err(format!(
                    "firewall profile {profile_name} has no @controller-ipv4 access rule"
                ));
            }
            let mut matching_rule_ids = Vec::new();
            for rule in &observed_rules {
                let spec = firewall_rule_spec(rule)?;
                if controller_access_cleanup_projection_matches(raw_profile, &spec)? {
                    matching_rule_ids.push(rule.id);
                }
            }
            matching_rule_ids.sort_unstable();
            let disposition = if matching_rule_ids.is_empty() {
                PlanDisposition::Noop
            } else {
                PlanDisposition::Mutate
            };
            let plan = serde_json::json!({
                "action": if disposition == PlanDisposition::Noop { "NOOP" } else { "RELEASE" },
                "machine_id": machine_id,
                "firewall_profile": profile_name,
                "matching_rule_ids": matching_rule_ids,
            });
            authorize_plan(
                "vultr_support_access",
                &desired_material,
                &support_observation,
                plan,
                disposition,
            )
            .map_err(|err| err.to_string())
        }
    }
}

async fn release_access_with_authority(
    desired: &DesiredState,
    machine_id: &str,
    authorized_plan_digest: &str,
) -> Result<serde_json::Value, String> {
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let profile_name = machine.provider.firewall_profile.as_deref().ok_or_else(|| {
        format!(
            "machine {} has no firewall_profile; release-access requires provider-owned SSH ingress",
            machine.id
        )
    })?;
    let (raw_profiles, _, _, controller_ipv4) = load_access_authority_profiles(desired)?;
    let profile = raw_profiles.profile(profile_name)?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let authorized = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    if authorized.disposition == PlanDisposition::Noop {
        return Ok(serde_json::json!({
            "action": "NOOP",
            "machine_id": machine.id,
            "firewall_profile": profile_name,
            "next_plan": authorized.plan,
            "mutations_performed": 0,
        }));
    }
    if authorized.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "release-access is blocked for machine {} by exact authorized plan",
            machine.id
        ));
    }

    let report = release_controller_ipv4_access(
        &mut support_provider,
        &desired.environment,
        profile,
        &controller_ipv4,
        &policy,
    )
    .await?;
    if !report.verified_absent {
        return Err("controller SSH access cleanup did not verify absence".to_owned());
    }

    let next = build_access_authority(
        desired,
        machine_id,
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if next.disposition != PlanDisposition::Noop {
        return Err("controller SSH access cleanup did not converge to NOOP".to_owned());
    }

    Ok(serde_json::json!({
        "action": "RELEASED",
        "machine_id": machine.id,
        "firewall_profile": profile_name,
        "firewall_group_id": report.firewall_group_id,
        "verified_absent": report.verified_absent,
        "next_plan": next.plan,
        "mutations_performed": 1,
    }))
}

fn instance_action_disposition(
    action: InstanceAction,
    observed: &VultrInstance,
) -> (PlanDisposition, &'static str) {
    match action {
        InstanceAction::Start => match observed.power_status.as_str() {
            "running" => (PlanDisposition::Noop, "NOOP"),
            "stopped" => (PlanDisposition::Mutate, "START"),
            _ => (PlanDisposition::Blocked, "BLOCKED"),
        },
        InstanceAction::Halt => match observed.power_status.as_str() {
            "stopped" => (PlanDisposition::Noop, "NOOP"),
            "running" => (PlanDisposition::Mutate, "HALT"),
            _ => (PlanDisposition::Blocked, "BLOCKED"),
        },
        InstanceAction::Reboot => {
            if observed.power_status == "running"
                && observed.status == "active"
                && observed.server_status == "ok"
            {
                (PlanDisposition::Mutate, "REBOOT")
            } else {
                (PlanDisposition::Blocked, "BLOCKED")
            }
        }
    }
}

async fn build_instance_action_authority(
    desired: &DesiredState,
    machine_id: &str,
    action: InstanceAction,
    lifecycle_provider: &mut VultrApiProvider,
    support_provider: &mut VultrSupportApiProvider,
    operational_provider: &mut VultrOperationalApiProvider,
) -> Result<(AuthorizedPlan<serde_json::Value>, VultrInstance), String> {
    let profiles = load_firewall_profiles(desired)?;
    let verified_firewalls =
        verified_firewall_bindings(support_provider, desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        lifecycle_provider,
        desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    let target = report
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    if target.class != PlanClass::Noop {
        return Err(format!(
            "instance action requires exact NOOP provider identity; machine {} is {:?}: {}",
            machine_id,
            target.class,
            target.reasons.join("; ")
        ));
    }
    let provider_id = target
        .provider_id
        .as_deref()
        .ok_or_else(|| "NOOP plan is missing provider id".to_owned())?;
    let operational = operational_provider
        .get_instance(provider_id)
        .await
        .map_err(|err| err.to_string())?;
    if operational.id != provider_id {
        return Err(format!(
            "instance action observation returned unexpected provider id {} for {}",
            operational.id, provider_id
        ));
    }

    let (disposition, planned_action) = instance_action_disposition(action, &operational);
    let desired_material = serde_json::json!({
        "desired": desired,
        "machine_id": machine_id,
        "requested_action": action.as_str(),
    });
    let observed_material = serde_json::json!({
        "lifecycle_inventory": report.inventory,
        "operational": {
            "provider_id": operational.id,
            "power_status": operational.power_status,
            "status": operational.status,
            "server_status": operational.server_status,
        }
    });
    let action_plan = serde_json::json!({
        "machine_id": machine_id,
        "provider_id": provider_id,
        "requested_action": action.as_str(),
        "action": planned_action,
    });
    let authorized = authorize_plan(
        "vultr_instance_action",
        &desired_material,
        &observed_material,
        action_plan,
        disposition,
    )
    .map_err(|err| err.to_string())?;
    Ok((authorized, operational))
}

pub(crate) fn validate_linux_boot_id(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || !bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
    {
        return Err("guest boot_id is not a canonical Linux UUID".to_owned());
    }
    Ok(())
}

pub(crate) fn observe_guest_boot_id(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
) -> Result<String, String> {
    let boot_id = strict_ssh_capture(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        canonical_operator_public_key,
        "cat /proc/sys/kernel/random/boot_id",
    )?;
    validate_linux_boot_id(&boot_id)?;
    Ok(boot_id)
}

pub(crate) async fn wait_for_guest_boot_id_change(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    previous_boot_id: &str,
    attempts: usize,
    delay: std::time::Duration,
) -> Result<String, String> {
    if attempts == 0 {
        return Err("guest reboot observation attempts must be greater than zero".to_owned());
    }
    validate_linux_boot_id(previous_boot_id)?;

    let mut last_state = "not-observed";
    for attempt in 0..attempts {
        match strict_ssh_capture(
            target_ip,
            logical_hostname,
            operator_private_key_path,
            canonical_operator_public_key,
            "cat /proc/sys/kernel/random/boot_id",
        ) {
            Ok(current) => {
                if validate_linux_boot_id(&current).is_err() {
                    last_state = "invalid-boot-id";
                } else if current != previous_boot_id {
                    return Ok(current);
                } else {
                    last_state = "same-boot-id";
                }
            }
            Err(_) => {
                last_state = "ssh-unavailable";
            }
        }

        if attempt + 1 < attempts {
            tokio::time::sleep(delay).await;
        }
    }

    Err(format!(
        "guest reboot was not proven for {logical_hostname} at {target_ip}: boot_id did not change after {attempts} observations; last_state={last_state}"
    ))
}

struct SupportCleanupAuthorityContext {
    authorized: AuthorizedPlan<serde_json::Value>,
    remaining_instances: Vec<VultrInstance>,
}

async fn build_support_cleanup_authority(
    desired: &DesiredState,
    lifecycle_provider: &mut VultrApiProvider,
    support_provider: &mut VultrSupportApiProvider,
    canonical_public_key: &str,
) -> Result<SupportCleanupAuthorityContext, String> {
    let mut remaining_instances = lifecycle_provider
        .list_instances()
        .await
        .map_err(|err| err.to_string())?;
    remaining_instances.sort_by(|left, right| left.id.cmp(&right.id));

    let mut environment_in_use = false;
    let mut instance_observation = Vec::new();
    for instance in &remaining_instances {
        let decoded = decode_provider_tags(&instance.tags).map_err(|err| {
            format!(
                "cannot prove support-resource cleanup safety because instance {} has invalid lifecycle tags: {err}",
                instance.id
            )
        })?;
        if decoded.ownership.managed_by.as_deref() == Some(MANAGED_BY_IDENTITY)
            && decoded.ownership.environment.as_deref() == Some(desired.environment.as_str())
        {
            environment_in_use = true;
        }
        let mut tags = instance.tags.clone();
        tags.sort();
        instance_observation.push(serde_json::json!({
            "id": instance.id,
            "firewall_group_id": instance.firewall_group_id,
            "tags": tags,
        }));
    }

    let canonical_material = public_key_material(canonical_public_key)?;
    let desired_material = serde_json::json!({
        "desired": desired,
        "canonical_ssh_public_key": canonical_material,
    });

    if environment_in_use {
        let observed = serde_json::json!({
            "instances": instance_observation,
        });
        let plan = serde_json::json!({
            "action": "NOOP",
            "environment_in_use": true,
            "firewall_group_ids": [],
            "ssh_key_id": null,
        });
        let authorized = authorize_plan(
            "vultr_support_cleanup",
            &desired_material,
            &observed,
            plan,
            PlanDisposition::Noop,
        )
        .map_err(|err| err.to_string())?;
        return Ok(SupportCleanupAuthorityContext {
            authorized,
            remaining_instances,
        });
    }

    let firewall_prefix = format!("singbox-{}-fw-", desired.environment);
    let mut groups = support_provider
        .list_firewall_groups()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|group| group.description.starts_with(&firewall_prefix))
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| left.id.cmp(&right.id));

    let mut seen_descriptions = std::collections::BTreeSet::new();
    for group in &groups {
        if !seen_descriptions.insert(group.description.clone()) {
            return Err(format!(
                "support-resource cleanup is ambiguous: duplicate managed firewall description {}",
                group.description
            ));
        }
        if remaining_instances
            .iter()
            .any(|instance| instance.firewall_group_id == group.id)
        {
            return Err(format!(
                "support-resource cleanup refused: firewall group {} is still attached to provider instance",
                group.id
            ));
        }
    }

    let desired_ssh_name = format!("singbox-{}-ops", desired.environment);
    let mut named_keys = support_provider
        .list_ssh_keys()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|key| key.name == desired_ssh_name)
        .collect::<Vec<_>>();
    named_keys.sort_by(|left, right| left.id.cmp(&right.id));
    if named_keys.len() > 1 {
        return Err(format!(
            "multiple Vultr SSH keys use managed name {desired_ssh_name}"
        ));
    }
    let ssh_key = if let Some(key) = named_keys.first() {
        let observed_material = public_key_material(&key.ssh_key)?;
        if observed_material != canonical_material {
            return Err(format!(
                "Vultr SSH key {} has managed name {} but different public key material",
                key.id, desired_ssh_name
            ));
        }
        Some(serde_json::json!({
            "id": key.id,
            "name": key.name,
            "public_key": observed_material,
        }))
    } else {
        None
    };

    let group_observation = groups
        .iter()
        .map(|group| {
            serde_json::json!({
                "id": group.id,
                "description": group.description,
            })
        })
        .collect::<Vec<_>>();
    let firewall_group_ids = groups
        .iter()
        .map(|group| group.id.clone())
        .collect::<Vec<_>>();
    let ssh_key_id = named_keys.first().map(|key| key.id.clone());
    let disposition = if firewall_group_ids.is_empty() && ssh_key_id.is_none() {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    let observed = serde_json::json!({
        "instances": instance_observation,
        "firewall_groups": group_observation,
        "ssh_key": ssh_key,
    });
    let plan = serde_json::json!({
        "action": if disposition == PlanDisposition::Noop { "NOOP" } else { "CLEANUP" },
        "environment_in_use": false,
        "firewall_group_ids": firewall_group_ids,
        "ssh_key_id": ssh_key_id,
    });
    let authorized = authorize_plan(
        "vultr_support_cleanup",
        &desired_material,
        &observed,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())?;

    Ok(SupportCleanupAuthorityContext {
        authorized,
        remaining_instances,
    })
}

pub(crate) async fn acceptance_require_clean_room(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let support = build_support_cleanup_authority(
        &desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    let environment_in_use = support
        .authorized
        .plan
        .get("environment_in_use")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let firewall_count = support
        .authorized
        .plan
        .get("firewall_group_ids")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(usize::MAX);
    let ssh_key_absent = support
        .authorized
        .plan
        .get("ssh_key_id")
        .is_some_and(serde_json::Value::is_null);
    if support.authorized.disposition != PlanDisposition::Noop
        || environment_in_use
        || firewall_count != 0
        || !ssh_key_absent
    {
        return Err("acceptance Vultr support clean room is not empty".to_owned());
    }

    let profiles = load_firewall_profiles(&desired)?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let report = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    if !report.orphaned_managed_provider_ids.is_empty() {
        return Err(format!(
            "acceptance Vultr clean room has orphaned managed provider resources: {:?}",
            report.orphaned_managed_provider_ids
        ));
    }
    let plan = report
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    if plan.class != PlanClass::Create {
        return Err(format!(
            "fresh acceptance VM must plan CREATE, got {:?}: {}",
            plan.class,
            plan.reasons.join("; ")
        ));
    }
    Ok(())
}

fn is_disposable_ssh_forensic_target(environment: &str, machine_id: &str) -> bool {
    matches!(
        (environment, machine_id),
        ("application-acceptance", "application-acceptance-1")
            | ("lifecycle-acceptance", "lifecycle-acceptance-1")
    )
}

/// Capture read-only provider/firewall/TCP/SSH phases before the disposable
/// acceptance coordinator compensates the VM. This function never mutates or
/// retries an installation. Every diagnostic field is fixed-shape and bounded.
pub(crate) async fn acceptance_ssh_failure_forensics(
    spec_path: &Path,
    machine_id: &str,
) -> serde_json::Value {
    let unavailable = || {
        serde_json::json!({
            "schema": "acceptance-ssh-forensics/v1",
            "status": "UNAVAILABLE",
            "mutations_performed": 0,
        })
    };
    let Ok(desired) = load_desired_state(spec_path) else {
        return unavailable();
    };
    // This forensic path must never observe an unrelated production machine.
    if !is_disposable_ssh_forensic_target(&desired.environment, machine_id) {
        return unavailable();
    }
    let Ok(machine) = exact_existing_machine_observation(&desired, machine_id).await else {
        return unavailable();
    };
    let Some(target_ip) = machine.main_ip.as_deref() else {
        return unavailable();
    };

    let provider_ready = match operational_provider_from_env() {
        Ok(mut provider) => match provider.get_instance(&machine.provider_id).await {
            Ok(instance) => {
                if instance.status == "active"
                    && instance.power_status == "running"
                    && instance.server_status == "ok"
                    && instance.main_ip == target_ip
                {
                    "PASS"
                } else {
                    "FAIL"
                }
            }
            Err(_) => "UNAVAILABLE",
        },
        Err(_) => "UNAVAILABLE",
    };
    let tcp = observe_tcp_readiness(
        target_ip,
        TcpReadinessPolicy {
            max_attempts: 1,
            max_elapsed: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(3),
            backoff: Duration::ZERO,
        },
    )
    .await
    .ok();
    let (tcp_state, tcp_error) = match tcp.as_ref() {
        Some(result) => (
            match result.final_state {
                TcpReadinessState::Ready => "CONNECTED",
                TcpReadinessState::Timeout => "FAILED",
            },
            result.last_error_class.map(|kind| format!("{kind:?}")),
        ),
        None => ("UNAVAILABLE", None),
    };

    let provider_evidence = match (lifecycle_provider_from_env(), support_provider_from_env()) {
        (Ok(mut lifecycle), Ok(mut support)) => capture_support_access_provider_evidence(
            &desired,
            machine_id,
            &mut lifecycle,
            &mut support,
        )
        .await
        .ok(),
        _ => None,
    };
    let (controller_rule_once, firewall_attached, acquire_noop, runner_egress_matches) =
        match provider_evidence {
            Some(ref evidence) => (
                Some(evidence.exact_controller_rules_present_once),
                Some(evidence.firewall_group_attached_to_machine),
                Some(evidence.acquire_plan_disposition == "NOOP"),
                env::var("EDGE_CONTROLLER_IPV4")
                    .ok()
                    .map(|expected| expected == evidence.controller_ipv4),
            ),
            None => (None, None, None, None),
        };
    let ssh_phase = match (
        operator_private_key_path_from_env(),
        read_canonical_ssh_public_key(),
    ) {
        (Ok(private_key), Ok(public_key)) => {
            if verify_operator_key_matches(&private_key, &public_key).is_ok() {
                capture_ssh_transport_stage_once(target_ip, machine_id, &private_key, &public_key)
                    .unwrap_or_else(|_| "UNAVAILABLE".to_owned())
            } else {
                "UNAVAILABLE".to_owned()
            }
        }
        _ => "UNAVAILABLE".to_owned(),
    };
    serde_json::json!({
        "schema": "acceptance-ssh-forensics/v1",
        "status": "OBSERVED",
        "provider_ready": provider_ready,
        "tcp_22": tcp_state,
        "tcp_error_class": tcp_error,
        "controller_rule_once": controller_rule_once,
        "firewall_attached": firewall_attached,
        "access_plan_noop": acquire_noop,
        "runner_egress_matches": runner_egress_matches,
        "ssh_phase": ssh_phase,
        "mutations_performed": 0,
    })
}

pub(crate) async fn acceptance_lease_acquire(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let substrate = host_substrate_versions_from_env()?;
    acceptance_lease_acquire_with_substrate(spec_path, machine_id, &substrate).await
}

/// No process-global re-read: this is one already-validated substrate version
/// set passed through the whole support-access transaction.
async fn acceptance_lease_acquire_with_substrate(
    spec_path: &Path,
    machine_id: &str,
    substrate: &HostSubstrateVersions,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let (_lease, access, _observed, _tcp_readiness) =
        acquire_transient_access_ready_exact(&desired, machine_id, substrate).await?;

    if access
        .get("next_plan")
        .and_then(|plan| plan.get("action"))
        .and_then(serde_json::Value::as_str)
        != Some("NOOP")
    {
        return Err("acceptance lease-acquire did not converge to NOOP".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_lease_release(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let planned = build_access_authority(
        &desired,
        machine_id,
        AccessAuthorityMode::Release,
        &mut lifecycle_provider,
        &mut support_provider,
    )
    .await?;
    if planned.disposition == PlanDisposition::Blocked {
        return Err(format!(
            "acceptance lease-release is blocked for machine {machine_id}"
        ));
    }
    let access =
        release_access_with_authority(&desired, machine_id, &planned.authority.authority_digest)
            .await?;
    let verified_absent = access
        .get("verified_absent")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| {
            access
                .get("action")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|action| action == "NOOP")
        });
    let no_matching_rules = access
        .get("next_plan")
        .and_then(|plan| plan.get("matching_rule_ids"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(Vec::is_empty);
    if !verified_absent || !no_matching_rules {
        return Err("acceptance lease-release did not prove transient SSH absence".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_converge_substrate(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let provider_id = exact_existing_machine_provider_id(&desired, machine_id).await?;
    let substrate = host_substrate_versions_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let mut provider = operational_provider_from_env()?;

    for _ in 0..4 {
        let (_observation, authorized) = build_host_substrate_authority(
            &mut provider,
            &desired,
            machine,
            &provider_id,
            &operator_private_key_path,
            &canonical_public_key,
            &substrate,
            HostSubstrateExecutionPolicy::default(),
        )
        .await?;
        match authorized.plan.action {
            HostSubstrateAction::Noop => return Ok(()),
            HostSubstrateAction::ScrubUserData | HostSubstrateAction::RotateHostCertificate => {
                apply_host_substrate_once(
                    &mut provider,
                    &desired,
                    machine,
                    &provider_id,
                    &authorized.authority.authority_digest,
                    &operator_private_key_path,
                    &canonical_public_key,
                    &substrate,
                    HostSubstrateExecutionPolicy::default(),
                )
                .await?;
            }
            action => {
                return Err(format!(
                    "acceptance host substrate convergence is blocked: {action:?}: {}",
                    authorized.plan.reasons.join("; ")
                ));
            }
        }
    }
    Err("host substrate convergence exceeded bounded mutation steps".to_owned())
}

pub(crate) async fn acceptance_verify_substrate(
    spec_path: &Path,
    machine_id: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let provider_id = exact_existing_machine_provider_id(&desired, machine_id).await?;
    let substrate = host_substrate_versions_from_env()?;
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let mut provider = operational_provider_from_env()?;
    let (_observation, authorized) = build_host_substrate_authority(
        &mut provider,
        &desired,
        machine,
        &provider_id,
        &operator_private_key_path,
        &canonical_public_key,
        &substrate,
        HostSubstrateExecutionPolicy::default(),
    )
    .await?;
    if authorized.plan.action != HostSubstrateAction::Noop {
        return Err(format!(
            "acceptance host substrate verify expected NOOP, got {:?}: {}",
            authorized.plan.action,
            authorized.plan.reasons.join("; ")
        ));
    }
    Ok(())
}

pub(crate) async fn acceptance_reboot(spec_path: &Path, machine_id: &str) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let mut operational_provider = operational_provider_from_env()?;
    let (authorized, operational) = build_instance_action_authority(
        &desired,
        machine_id,
        InstanceAction::Reboot,
        &mut lifecycle_provider,
        &mut support_provider,
        &mut operational_provider,
    )
    .await?;
    if authorized.disposition != PlanDisposition::Mutate {
        return Err("fresh acceptance reboot was not authorized as one mutation".to_owned());
    }
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let operator_private_key_path = operator_private_key_path_from_env()?;
    verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
    let boot_id_before = observe_guest_boot_id(
        &operational.main_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
    )?;
    let authority_digest = authorized.authority.authority_digest.clone();
    let (fresh_authorized, fresh_operational) = build_instance_action_authority(
        &desired,
        machine_id,
        InstanceAction::Reboot,
        &mut lifecycle_provider,
        &mut support_provider,
        &mut operational_provider,
    )
    .await?;
    verify_exact_authority(&authority_digest, &fresh_authorized.authority)
        .map_err(|err| err.to_string())?;
    if fresh_authorized.disposition != PlanDisposition::Mutate
        || fresh_operational.id != operational.id
    {
        return Err("acceptance reboot authority changed before mutation".to_owned());
    }
    apply_instance_action(
        &mut operational_provider,
        &operational.id,
        InstanceAction::Reboot,
        60,
        Duration::from_secs(2),
    )
    .await?;
    let boot_id_after = wait_for_guest_boot_id_change(
        &operational.main_ip,
        machine_id,
        &operator_private_key_path,
        &canonical_public_key,
        &boot_id_before,
        60,
        Duration::from_secs(2),
    )
    .await?;
    if boot_id_before == boot_id_after {
        return Err("acceptance reboot did not change guest boot identity".to_owned());
    }
    Ok(())
}

async fn acceptance_cleanup_support(desired: &DesiredState) -> Result<(), String> {
    let canonical_public_key = read_canonical_ssh_public_key()?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let context = build_support_cleanup_authority(
        desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    if context.authorized.disposition == PlanDisposition::Blocked {
        return Err("acceptance support cleanup is blocked by exact plan".to_owned());
    }
    if context.authorized.disposition == PlanDisposition::Mutate {
        cleanup_environment_support_resources(
            &mut support_provider,
            desired,
            &context.remaining_instances,
            &canonical_public_key,
            &policy,
        )
        .await?;
    }
    let next = build_support_cleanup_authority(
        desired,
        &mut lifecycle_provider,
        &mut support_provider,
        &canonical_public_key,
    )
    .await?;
    let environment_in_use = next
        .authorized
        .plan
        .get("environment_in_use")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let firewall_count = next
        .authorized
        .plan
        .get("firewall_group_ids")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(usize::MAX);
    let ssh_key_absent = next
        .authorized
        .plan
        .get("ssh_key_id")
        .is_some_and(serde_json::Value::is_null);
    if next.authorized.disposition != PlanDisposition::Noop
        || environment_in_use
        || firewall_count != 0
        || !ssh_key_absent
    {
        return Err("acceptance support cleanup did not converge to exact absence".to_owned());
    }
    Ok(())
}

pub(crate) async fn acceptance_destroy_and_cleanup(
    spec_path: &Path,
    machine_id: &str,
    source_revision: &str,
) -> Result<(), String> {
    let desired = load_desired_state(spec_path)?;
    let profiles = load_firewall_profiles(&desired)?;
    let policy = LifecycleExecutionPolicy::default();
    let mut lifecycle_provider = lifecycle_provider_from_env()?;
    let mut support_provider = support_provider_from_env()?;
    let verified_firewalls =
        verified_firewall_bindings(&mut support_provider, &desired, profiles.as_ref()).await?;
    let inventory = inventory_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        &verified_firewalls,
    )
    .await?;
    let machine = desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))?;
    let lifecycle = plan_desired_state_with_firewall_profiles(
        &mut lifecycle_provider,
        &desired,
        Some(machine_id),
        &verified_firewalls,
    )
    .await?;
    let machine_plan = lifecycle
        .plans
        .first()
        .ok_or_else(|| format!("no lifecycle plan was produced for {machine_id}"))?;
    if machine_plan.class != PlanClass::Create {
        let plan = destroy_plan(&desired, machine, &inventory, source_revision)
            .map_err(|err| err.to_string())?;
        let authorized = authorize_vultr_destroy(
            &desired,
            machine_id,
            source_revision,
            &inventory,
            plan.clone(),
        )?;
        let report = destroy_machine_with_firewall_profiles(
            &mut lifecycle_provider,
            &desired,
            machine_id,
            source_revision,
            &plan.destroy_digest,
            &authorized.authority.authority_digest,
            &policy,
            &verified_firewalls,
        )
        .await?;
        if !report.absence_verified {
            return Err("acceptance VM destroy did not prove exact provider absence".to_owned());
        }
    }
    acceptance_cleanup_support(&desired).await?;
    acceptance_require_clean_room(spec_path, machine_id).await
}

pub(crate) fn load_desired_state(path: &Path) -> Result<DesiredState, String> {
    if path == Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH) {
        return ProductionComposition::canonical()
            .map(|composition| composition.machines)
            .map_err(|err| err.to_string());
    }

    if path.starts_with("infra/hosts/specs") {
        return crate::vm_host_desired::load(path).map(|(machine, _)| machine);
    }
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read lifecycle spec {}: {err}", path.display()))?;
    DesiredState::parse_json(&raw)
        .map_err(|err| format!("failed to parse lifecycle spec {}: {err}", path.display()))
}

pub(crate) fn load_firewall_profiles(
    desired: &DesiredState,
) -> Result<Option<FirewallProfileSet>, String> {
    let Some(profiles) = load_firewall_profiles_raw(desired)? else {
        return Ok(None);
    };
    let profile_names = desired
        .machines
        .iter()
        .filter_map(|machine| machine.provider.firewall_profile.clone())
        .collect::<Vec<_>>();
    for profile_name in &profile_names {
        profiles.profile(profile_name)?;
    }
    Ok(Some(profiles))
}

fn load_firewall_profiles_raw(
    desired: &DesiredState,
) -> Result<Option<FirewallProfileSet>, String> {
    if desired
        .machines
        .iter()
        .all(|machine| machine.provider.firewall_profile.is_none())
    {
        return Ok(None);
    }

    if desired.environment == "production" {
        let production = ProductionComposition::canonical().map_err(|err| err.to_string())?;
        if desired != &production.machines {
            return Err(
                "production Vultr desired state does not match canonical ProductionDesiredState"
                    .to_owned(),
            );
        }
        let mut rules = production
            .firewall_rules
            .into_iter()
            .map(|rule| FirewallRuleSpec {
                ip_type: "v4".to_owned(),
                protocol: rule.protocol.to_owned(),
                subnet: "0.0.0.0".to_owned(),
                subnet_size: 0,
                port: rule.port.to_string(),
                source: String::new(),
                notes: rule.purpose,
            })
            .collect::<Vec<_>>();
        if production.support_controller_ssh {
            rules.push(FirewallRuleSpec {
                ip_type: "v4".to_owned(),
                protocol: "tcp".to_owned(),
                subnet: "@controller-ipv4".to_owned(),
                subnet_size: 32,
                port: "22".to_owned(),
                source: String::new(),
                notes: "transient production controller SSH lease".to_owned(),
            });
        }
        return FirewallProfileSet::single(FirewallProfile {
            name: "production".to_owned(),
            rules,
        })
        .map(Some);
    }

    let path = Path::new(FIREWALL_PROFILES_PATH);
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read firewall profiles {}: {err}", path.display()))?;
    FirewallProfileSet::parse_json(&raw).map(Some)
}

pub(crate) async fn verified_firewall_bindings(
    provider: &mut VultrSupportApiProvider,
    desired: &DesiredState,
    profiles: Option<&FirewallProfileSet>,
) -> Result<BTreeMap<String, String>, String> {
    match profiles {
        Some(profiles) => observe_verified_firewall_bindings(provider, desired, profiles).await,
        None => Ok(BTreeMap::new()),
    }
}

pub(crate) fn lifecycle_provider_from_env() -> Result<VultrApiProvider, String> {
    VultrApiProvider::new(vultr_api_key_from_env()?)
}

pub(crate) fn support_provider_from_env() -> Result<VultrSupportApiProvider, String> {
    VultrSupportApiProvider::new(vultr_api_key_from_env()?)
}

fn operational_provider_from_env() -> Result<VultrOperationalApiProvider, String> {
    VultrOperationalApiProvider::new(vultr_api_key_from_env()?)
}

pub(crate) fn operator_private_key_path_from_env() -> Result<PathBuf, String> {
    let path = env::var_os("EDGE_SSH_PRIVATE_KEY_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| {
            "EDGE_SSH_PRIVATE_KEY_PATH is required for strict SSH lifecycle apply".to_owned()
        })?;
    if !path.is_file() {
        return Err(format!(
            "EDGE_SSH_PRIVATE_KEY_PATH does not point to a readable file: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn vultr_api_key_from_env() -> Result<String, String> {
    env::var("VULTR_API_KEY").map_err(|_| "VULTR_API_KEY is required".to_owned())
}

/// Project the already-verified immutable ReleaseSet into the existing native
/// substrate type. Never accept a second runner-owned desired or env override
/// on signed Host first-use/trust paths.
fn pinned_host_substrate_versions(
    context: &OrchestrationContext,
) -> Result<HostSubstrateVersions, String> {
    let release = context.release();
    HostSubstrateVersions::new(
        release.docker_engine_version.clone(),
        release.containerd_version.clone(),
        release.compose_version.clone(),
    )
}

pub(crate) fn host_substrate_versions_from_env() -> Result<HostSubstrateVersions, String> {
    HostSubstrateVersions::new(
        env::var("EDGE_DOCKER_ENGINE_VERSION").map_err(|_| {
            "EDGE_DOCKER_ENGINE_VERSION is required for vultr-lifecycle apply".to_owned()
        })?,
        env::var("EDGE_CONTAINERD_VERSION").map_err(|_| {
            "EDGE_CONTAINERD_VERSION is required for vultr-lifecycle apply".to_owned()
        })?,
        env::var("EDGE_COMPOSE_VERSION")
            .map_err(|_| "EDGE_COMPOSE_VERSION is required for vultr-lifecycle apply".to_owned())?,
    )
}

pub(crate) fn read_canonical_ssh_public_key() -> Result<String, String> {
    let path = Path::new(CANONICAL_SSH_PUBLIC_KEY_PATH);
    let public_key = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read canonical SSH public key {}: {err}",
            path.display()
        )
    })?;
    if public_key.trim().is_empty() {
        return Err(format!(
            "canonical SSH public key {} is empty",
            path.display()
        ));
    }
    Ok(public_key)
}

fn empty_create_prerequisites(machine: &MachineSpec) -> CreatePrerequisites {
    CreatePrerequisites {
        bootstrap_profile: machine.bootstrap_profile.clone(),
        ssh_key_id: String::new(),
        cloud_init: String::new(),
        firewall_group_id: None,
        firewall_profile: None,
    }
}

fn print_json_value(value: serde_json::Value) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize lifecycle result: {err}"))?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
#[path = "vultr_lifecycle_command_tests.rs"]
mod tests;
