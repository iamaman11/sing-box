use crate::vultr_lifecycle_adapter::{
    managed_provider_tags, normalize_vultr_inventory,
    normalize_vultr_inventory_with_firewall_profiles,
};
use edge_controller_core::vultr_lifecycle::{
    DesiredState, DestroyPlan, LifecycleInventory, MachinePlan, MachineSpec, PlanClass,
    authorize_destroy, destroy_plan, plan_all, plan_machine,
};
use edge_provider_vultr::{
    CreateInstanceRequest, VultrError, VultrErrorKind, VultrInstance, create_instance_typed,
    destroy_instance_typed, get_instance_typed, list_instances_typed,
};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct LifecycleExecutionPolicy {
    pub create_reobserve_attempts: usize,
    pub destroy_reobserve_attempts: usize,
    pub reobserve_delay: Duration,
}

impl Default for LifecycleExecutionPolicy {
    fn default() -> Self {
        Self {
            create_reobserve_attempts: 30,
            destroy_reobserve_attempts: 180,
            reobserve_delay: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePrerequisites {
    pub bootstrap_profile: String,
    pub ssh_key_id: String,
    pub cloud_init: String,
    pub firewall_group_id: Option<String>,
    pub firewall_profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedCreateRequest {
    pub region: String,
    pub plan: String,
    pub os_id: Option<u32>,
    pub snapshot_id: Option<String>,
    pub label: String,
    pub ssh_key_id: String,
    pub cloud_init: String,
    pub firewall_group_id: Option<String>,
    pub tags: Vec<String>,
    pub enable_ipv6: bool,
}

#[allow(async_fn_in_trait)]
pub trait LifecycleProvider {
    async fn list_instances(&mut self) -> Result<Vec<VultrInstance>, VultrError>;
    async fn create_instance(
        &mut self,
        request: &OwnedCreateRequest,
    ) -> Result<VultrInstance, VultrError>;
    async fn get_instance(&mut self, instance_id: &str) -> Result<VultrInstance, VultrError>;
    async fn destroy_instance(&mut self, instance_id: &str) -> Result<(), VultrError>;
}

pub struct VultrApiProvider {
    api_key: String,
}

impl VultrApiProvider {
    pub fn new(api_key: String) -> Result<Self, String> {
        if api_key.trim().is_empty() {
            return Err("VULTR_API_KEY must be non-empty".to_owned());
        }
        Ok(Self { api_key })
    }
}

impl LifecycleProvider for VultrApiProvider {
    async fn list_instances(&mut self) -> Result<Vec<VultrInstance>, VultrError> {
        list_instances_typed(&self.api_key).await
    }

    async fn create_instance(
        &mut self,
        request: &OwnedCreateRequest,
    ) -> Result<VultrInstance, VultrError> {
        let tag_refs = request.tags.iter().map(String::as_str).collect::<Vec<_>>();
        create_instance_typed(
            &self.api_key,
            &CreateInstanceRequest {
                region: &request.region,
                plan: &request.plan,
                os_id: request.os_id,
                snapshot_id: request.snapshot_id.as_deref(),
                label: &request.label,
                ssh_key_id: &request.ssh_key_id,
                cloud_init: &request.cloud_init,
                firewall_group_id: request.firewall_group_id.as_deref(),
                tags: tag_refs,
                enable_ipv6: request.enable_ipv6,
            },
        )
        .await
    }

    async fn get_instance(&mut self, instance_id: &str) -> Result<VultrInstance, VultrError> {
        get_instance_typed(&self.api_key, instance_id).await
    }

    async fn destroy_instance(&mut self, instance_id: &str) -> Result<(), VultrError> {
        destroy_instance_typed(&self.api_key, instance_id).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecyclePlanReport {
    pub environment: String,
    pub desired_state_digest: String,
    pub plans: Vec<MachinePlan>,
    pub orphaned_managed_provider_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyAction {
    Noop,
    Created,
}

impl ApplyAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Noop => "NOOP",
            Self::Created => "CREATED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub action: ApplyAction,
    pub machine_id: String,
    pub provider_id: String,
    pub final_plan: MachinePlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestroyApplyReport {
    pub machine_id: String,
    pub provider_id: String,
    pub delete_requested: bool,
    pub absence_verified: bool,
}

pub async fn plan_desired_state<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine_id: Option<&str>,
) -> Result<LifecyclePlanReport, String> {
    let verified_firewall_profiles = BTreeMap::new();
    plan_desired_state_with_firewall_profiles(
        provider,
        desired,
        machine_id,
        &verified_firewall_profiles,
    )
    .await
}

pub async fn plan_desired_state_with_firewall_profiles<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine_id: Option<&str>,
    verified_firewall_profiles: &BTreeMap<String, String>,
) -> Result<LifecyclePlanReport, String> {
    let inventory = observe_inventory(provider, desired, verified_firewall_profiles).await?;
    let plans = match machine_id {
        Some(machine_id) => {
            let machine = machine_by_id(desired, machine_id)?;
            vec![plan_machine(desired, machine, &inventory).map_err(|err| err.to_string())?]
        }
        None => plan_all(desired, &inventory).map_err(|err| err.to_string())?,
    };
    Ok(LifecyclePlanReport {
        environment: desired.environment.clone(),
        desired_state_digest: desired.digest().map_err(|err| err.to_string())?,
        plans,
        orphaned_managed_provider_ids: inventory.orphaned_managed_provider_ids,
    })
}

pub async fn apply_machine<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine_id: &str,
    prerequisites: &CreatePrerequisites,
    policy: &LifecycleExecutionPolicy,
) -> Result<ApplyReport, String> {
    let verified_firewall_profiles = BTreeMap::new();
    apply_machine_with_firewall_profiles(
        provider,
        desired,
        machine_id,
        prerequisites,
        policy,
        &verified_firewall_profiles,
    )
    .await
}

pub async fn apply_machine_with_firewall_profiles<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine_id: &str,
    prerequisites: &CreatePrerequisites,
    policy: &LifecycleExecutionPolicy,
    verified_firewall_profiles: &BTreeMap<String, String>,
) -> Result<ApplyReport, String> {
    validate_policy(policy)?;
    let machine = machine_by_id(desired, machine_id)?;
    let inventory = observe_inventory(provider, desired, verified_firewall_profiles).await?;
    let initial_plan = plan_machine(desired, machine, &inventory).map_err(|err| err.to_string())?;

    match initial_plan.class {
        PlanClass::Noop => {
            let provider_id = initial_plan
                .provider_id
                .clone()
                .ok_or_else(|| "NOOP plan is missing provider id".to_owned())?;
            Ok(ApplyReport {
                action: ApplyAction::Noop,
                machine_id: machine.id.clone(),
                provider_id,
                final_plan: initial_plan,
            })
        }
        PlanClass::Create => {
            validate_create_prerequisites(machine, prerequisites)?;
            let create_request = create_request(desired, machine, prerequisites)?;

            let mutation_result = provider.create_instance(&create_request).await;
            match &mutation_result {
                Ok(_) => {}
                Err(err) if err.requires_mutation_reobservation() => {}
                Err(err) => return Err(err.to_string()),
            }

            let final_plan =
                reobserve_created_machine(
                    provider,
                    desired,
                    machine,
                    policy,
                    verified_firewall_profiles,
                )
                .await
                .map_err(
                    |detail| match mutation_result {
                        Ok(_) => format!(
                            "CREATE was accepted but machine {} did not converge: {detail}",
                            machine.id
                        ),
                        Err(ref err) => format!(
                            "{}; CREATE was not replayed and re-observation did not prove convergence: {detail}",
                            err
                        ),
                    },
                )?;

            if final_plan.class != PlanClass::Noop {
                return Err(format!(
                    "machine {} was created/recovered but did not converge to NOOP: {:?}: {}",
                    machine.id,
                    final_plan.class,
                    final_plan.reasons.join("; ")
                ));
            }
            let provider_id = final_plan
                .provider_id
                .clone()
                .ok_or_else(|| "converged CREATE plan is missing provider id".to_owned())?;
            Ok(ApplyReport {
                action: ApplyAction::Created,
                machine_id: machine.id.clone(),
                provider_id,
                final_plan,
            })
        }
        PlanClass::UpdateInPlace => Err(format!(
            "machine {} requires UPDATE_IN_PLACE; this slice does not mutate existing instances: {}",
            machine.id,
            initial_plan.reasons.join("; ")
        )),
        PlanClass::ReplaceRequired => Err(format!(
            "machine {} requires replacement; replacement is never implicit: {}",
            machine.id,
            initial_plan.reasons.join("; ")
        )),
        PlanClass::BlockedDrift | PlanClass::BlockedAmbiguous => Err(format!(
            "machine {} is blocked with {:?}: {}",
            machine.id,
            initial_plan.class,
            initial_plan.reasons.join("; ")
        )),
    }
}

pub async fn build_destroy_plan<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine_id: &str,
    source_revision: &str,
) -> Result<DestroyPlan, String> {
    let verified_firewall_profiles = BTreeMap::new();
    build_destroy_plan_with_firewall_profiles(
        provider,
        desired,
        machine_id,
        source_revision,
        &verified_firewall_profiles,
    )
    .await
}

pub async fn build_destroy_plan_with_firewall_profiles<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine_id: &str,
    source_revision: &str,
    verified_firewall_profiles: &BTreeMap<String, String>,
) -> Result<DestroyPlan, String> {
    let machine = machine_by_id(desired, machine_id)?;
    let inventory = observe_inventory(provider, desired, verified_firewall_profiles).await?;
    destroy_plan(desired, machine, &inventory, source_revision).map_err(|err| err.to_string())
}

pub async fn destroy_machine<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine_id: &str,
    source_revision: &str,
    authorized_digest: &str,
    policy: &LifecycleExecutionPolicy,
) -> Result<DestroyApplyReport, String> {
    let verified_firewall_profiles = BTreeMap::new();
    destroy_machine_with_firewall_profiles(
        provider,
        desired,
        machine_id,
        source_revision,
        authorized_digest,
        policy,
        &verified_firewall_profiles,
    )
    .await
}

pub async fn destroy_machine_with_firewall_profiles<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine_id: &str,
    source_revision: &str,
    authorized_digest: &str,
    policy: &LifecycleExecutionPolicy,
    verified_firewall_profiles: &BTreeMap<String, String>,
) -> Result<DestroyApplyReport, String> {
    validate_policy(policy)?;
    let machine = machine_by_id(desired, machine_id)?;
    let inventory = observe_inventory(provider, desired, verified_firewall_profiles).await?;
    let provider_id = authorize_destroy(
        desired,
        machine,
        &inventory,
        source_revision,
        authorized_digest,
    )
    .map_err(|err| err.to_string())?;

    let mutation_result = provider.destroy_instance(&provider_id).await;
    match &mutation_result {
        Ok(()) => {}
        Err(err) if err.is_not_found() => {
            return Ok(DestroyApplyReport {
                machine_id: machine.id.clone(),
                provider_id,
                delete_requested: true,
                absence_verified: true,
            });
        }
        Err(err) if err.requires_mutation_reobservation() => {}
        Err(err) => return Err(err.to_string()),
    }

    if wait_for_absence(provider, &provider_id, policy).await? {
        return Ok(DestroyApplyReport {
            machine_id: machine.id.clone(),
            provider_id,
            delete_requested: true,
            absence_verified: true,
        });
    }

    match mutation_result {
        Ok(()) => Err(format!(
            "DELETE for {} was accepted but exact provider id remained present after bounded re-observation; DELETE was not replayed",
            provider_id
        )),
        Err(err) => Err(format!(
            "{}; exact provider id {} remained present after bounded re-observation and DELETE was not replayed",
            err, provider_id
        )),
    }
}

async fn observe_inventory<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    verified_firewall_profiles: &BTreeMap<String, String>,
) -> Result<LifecycleInventory, String> {
    let instances = provider
        .list_instances()
        .await
        .map_err(|err| err.to_string())?;
    if verified_firewall_profiles.is_empty() {
        normalize_vultr_inventory(desired, &instances)
    } else {
        normalize_vultr_inventory_with_firewall_profiles(
            desired,
            &instances,
            verified_firewall_profiles,
        )
    }
}

async fn reobserve_created_machine<P: LifecycleProvider>(
    provider: &mut P,
    desired: &DesiredState,
    machine: &MachineSpec,
    policy: &LifecycleExecutionPolicy,
    verified_firewall_profiles: &BTreeMap<String, String>,
) -> Result<MachinePlan, String> {
    for attempt in 0..policy.create_reobserve_attempts {
        let inventory = observe_inventory(provider, desired, verified_firewall_profiles).await?;
        let plan = plan_machine(desired, machine, &inventory).map_err(|err| err.to_string())?;
        match plan.class {
            PlanClass::Noop
            | PlanClass::UpdateInPlace
            | PlanClass::ReplaceRequired
            | PlanClass::BlockedDrift
            | PlanClass::BlockedAmbiguous => return Ok(plan),
            PlanClass::Create => {}
        }
        if attempt + 1 < policy.create_reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }
    Err(format!(
        "machine {} remained absent after {} re-observations",
        machine.id, policy.create_reobserve_attempts
    ))
}

async fn wait_for_absence<P: LifecycleProvider>(
    provider: &mut P,
    provider_id: &str,
    policy: &LifecycleExecutionPolicy,
) -> Result<bool, String> {
    for attempt in 0..policy.destroy_reobserve_attempts {
        match provider.get_instance(provider_id).await {
            Ok(_) => {}
            Err(err) if err.is_not_found() => return Ok(true),
            Err(err) => return Err(err.to_string()),
        }
        if attempt + 1 < policy.destroy_reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }
    Ok(false)
}

fn validate_policy(policy: &LifecycleExecutionPolicy) -> Result<(), String> {
    if policy.create_reobserve_attempts == 0 {
        return Err("create re-observation attempts must be greater than zero".to_owned());
    }
    if policy.destroy_reobserve_attempts == 0 {
        return Err("destroy re-observation attempts must be greater than zero".to_owned());
    }
    Ok(())
}

fn machine_by_id<'a>(
    desired: &'a DesiredState,
    machine_id: &str,
) -> Result<&'a MachineSpec, String> {
    desired.validate().map_err(|err| err.to_string())?;
    desired
        .machines
        .iter()
        .find(|machine| machine.id == machine_id)
        .ok_or_else(|| format!("machine {machine_id} is not present in desired state"))
}

fn validate_create_prerequisites(
    machine: &MachineSpec,
    prerequisites: &CreatePrerequisites,
) -> Result<(), String> {
    if prerequisites.bootstrap_profile != machine.bootstrap_profile {
        return Err(format!(
            "bootstrap prerequisite profile {} does not match desired profile {}",
            prerequisites.bootstrap_profile, machine.bootstrap_profile
        ));
    }
    if prerequisites.ssh_key_id.trim().is_empty() {
        return Err("CREATE requires a resolved Vultr SSH key object id".to_owned());
    }
    if prerequisites.cloud_init.trim().is_empty() {
        return Err("CREATE requires non-empty bootstrap user-data".to_owned());
    }

    match machine.provider.firewall_profile.as_deref() {
        Some(expected_profile) => {
            if prerequisites.firewall_profile.as_deref() != Some(expected_profile)
                || prerequisites
                    .firewall_group_id
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
            {
                return Err(format!(
                    "CREATE for machine {} requires a provider-verified firewall binding for profile {}",
                    machine.id, expected_profile
                ));
            }
        }
        None => {
            if prerequisites.firewall_profile.is_some() || prerequisites.firewall_group_id.is_some()
            {
                return Err(format!(
                    "machine {} does not declare a firewall profile but CREATE prerequisites contain a firewall binding",
                    machine.id
                ));
            }
        }
    }
    Ok(())
}

fn create_request(
    desired: &DesiredState,
    machine: &MachineSpec,
    prerequisites: &CreatePrerequisites,
) -> Result<OwnedCreateRequest, String> {
    let tags = managed_provider_tags(desired, machine)?;
    Ok(OwnedCreateRequest {
        region: machine.provider.region.clone(),
        plan: machine.provider.plan.clone(),
        os_id: machine.provider.os_id,
        snapshot_id: machine.provider.snapshot_id.clone(),
        label: machine.id.clone(),
        ssh_key_id: prerequisites.ssh_key_id.clone(),
        cloud_init: prerequisites.cloud_init.clone(),
        firewall_group_id: prerequisites.firewall_group_id.clone(),
        tags,
        enable_ipv6: machine.provider.enable_ipv6,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_controller_core::vultr_lifecycle::provider_tags_for_machine;

    #[derive(Default)]
    struct FakeProvider {
        instances: Vec<VultrInstance>,
        create_error: Option<VultrError>,
        create_commits: bool,
        delete_error: Option<VultrError>,
        delete_commits: bool,
        create_calls: usize,
        delete_calls: usize,
    }

    impl LifecycleProvider for FakeProvider {
        async fn list_instances(&mut self) -> Result<Vec<VultrInstance>, VultrError> {
            Ok(self.instances.clone())
        }

        async fn create_instance(
            &mut self,
            request: &OwnedCreateRequest,
        ) -> Result<VultrInstance, VultrError> {
            self.create_calls += 1;
            let instance = instance_from_request(request);
            if self.create_error.is_none() || self.create_commits {
                self.instances.push(instance.clone());
            }
            match self.create_error.clone() {
                Some(err) => Err(err),
                None => Ok(instance),
            }
        }

        async fn get_instance(&mut self, instance_id: &str) -> Result<VultrInstance, VultrError> {
            self.instances
                .iter()
                .find(|instance| instance.id == instance_id)
                .cloned()
                .ok_or_else(not_found_error)
        }

        async fn destroy_instance(&mut self, instance_id: &str) -> Result<(), VultrError> {
            self.delete_calls += 1;
            if self.delete_error.is_none() || self.delete_commits {
                self.instances.retain(|instance| instance.id != instance_id);
            }
            match self.delete_error.clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }
    }

    fn desired() -> DesiredState {
        DesiredState::parse_json(
            r#"{
  "schema": 1,
  "environment": "production",
  "machines": [
    {
      "id": "edge-1",
      "role": "edge",
      "provider": {
        "region": "waw",
        "plan": "vc2-1c-1gb",
        "os_id": 2625,
        "enable_ipv6": false
      },
      "bootstrap_profile": "singbox-host-v1",
      "application_profiles": ["singbox-edge"],
      "tags": ["primary"]
    },
    {
      "id": "proxy-1",
      "role": "remote-proxy",
      "provider": {
        "region": "fra",
        "plan": "vc2-2c-4gb",
        "snapshot_id": "snapshot-1",
        "enable_ipv6": true
      },
      "bootstrap_profile": "singbox-host-v1",
      "application_profiles": ["remote-proxy"],
      "tags": ["proxy"]
    }
  ]
}"#,
        )
        .unwrap()
    }

    fn prerequisites() -> CreatePrerequisites {
        CreatePrerequisites {
            bootstrap_profile: "singbox-host-v1".to_owned(),
            ssh_key_id: "ssh-key-1".to_owned(),
            cloud_init: "#cloud-config\npackages: []\n".to_owned(),
            firewall_group_id: None,
            firewall_profile: None,
        }
    }

    fn test_policy() -> LifecycleExecutionPolicy {
        LifecycleExecutionPolicy {
            create_reobserve_attempts: 2,
            destroy_reobserve_attempts: 2,
            reobserve_delay: Duration::ZERO,
        }
    }

    fn instance_for_machine(
        desired: &DesiredState,
        machine: &MachineSpec,
        provider_id: &str,
    ) -> VultrInstance {
        VultrInstance {
            id: provider_id.to_owned(),
            label: machine.id.clone(),
            region: machine.provider.region.clone(),
            plan: machine.provider.plan.clone(),
            status: "active".to_owned(),
            server_status: "ok".to_owned(),
            power_status: "running".to_owned(),
            main_ip: "203.0.113.10".to_owned(),
            v6_main_ip: if machine.provider.enable_ipv6 {
                "2001:db8::10".to_owned()
            } else {
                String::new()
            },
            firewall_group_id: String::new(),
            date_created: "2026-09-19T00:00:00+00:00".to_owned(),
            tags: provider_tags_for_machine(desired, machine).unwrap(),
            os_id: machine.provider.os_id.unwrap_or(2625),
            snapshot_id: machine.provider.snapshot_id.clone(),
            enable_ipv6: machine.provider.enable_ipv6,
        }
    }

    fn instance_from_request(request: &OwnedCreateRequest) -> VultrInstance {
        VultrInstance {
            id: format!("instance-{}", request.label),
            label: request.label.clone(),
            region: request.region.clone(),
            plan: request.plan.clone(),
            status: "active".to_owned(),
            server_status: "ok".to_owned(),
            power_status: "running".to_owned(),
            main_ip: "203.0.113.20".to_owned(),
            v6_main_ip: if request.enable_ipv6 {
                "2001:db8::20".to_owned()
            } else {
                String::new()
            },
            firewall_group_id: request.firewall_group_id.clone().unwrap_or_default(),
            date_created: "2026-09-19T00:01:00+00:00".to_owned(),
            tags: request.tags.clone(),
            os_id: request.os_id.unwrap_or(2625),
            snapshot_id: request.snapshot_id.clone(),
            enable_ipv6: request.enable_ipv6,
        }
    }

    fn uncertain_error(operation: &'static str) -> VultrError {
        VultrError {
            operation,
            kind: VultrErrorKind::MutationUncertain,
            status: None,
            retry_after_secs: None,
            detail: "simulated response loss".to_owned(),
        }
    }

    fn not_found_error() -> VultrError {
        VultrError {
            operation: "read Vultr instance",
            kind: VultrErrorKind::Http,
            status: Some(404),
            retry_after_secs: None,
            detail: "not found".to_owned(),
        }
    }

    #[tokio::test]
    async fn plan_reports_two_machine_create_in_stable_order() {
        let desired = desired();
        let mut provider = FakeProvider::default();

        let report = plan_desired_state(&mut provider, &desired, None)
            .await
            .unwrap();

        assert_eq!(report.plans.len(), 2);
        assert_eq!(report.plans[0].machine_id, "edge-1");
        assert_eq!(report.plans[1].machine_id, "proxy-1");
        assert!(
            report
                .plans
                .iter()
                .all(|plan| plan.class == PlanClass::Create)
        );
    }

    #[tokio::test]
    async fn apply_create_then_repeat_apply_is_noop() {
        let desired = desired();
        let mut provider = FakeProvider::default();

        let first = apply_machine(
            &mut provider,
            &desired,
            "edge-1",
            &prerequisites(),
            &test_policy(),
        )
        .await
        .unwrap();
        assert_eq!(first.action, ApplyAction::Created);
        assert_eq!(provider.create_calls, 1);

        let second = apply_machine(
            &mut provider,
            &desired,
            "edge-1",
            &prerequisites(),
            &test_policy(),
        )
        .await
        .unwrap();
        assert_eq!(second.action, ApplyAction::Noop);
        assert_eq!(provider.create_calls, 1);
    }

    #[tokio::test]
    async fn uncertain_create_reobserves_without_replay() {
        let desired = desired();
        let mut provider = FakeProvider {
            create_error: Some(uncertain_error("create Vultr instance")),
            create_commits: true,
            ..FakeProvider::default()
        };

        let report = apply_machine(
            &mut provider,
            &desired,
            "edge-1",
            &prerequisites(),
            &test_policy(),
        )
        .await
        .unwrap();

        assert_eq!(report.action, ApplyAction::Created);
        assert_eq!(provider.create_calls, 1);
    }

    #[tokio::test]
    async fn unresolved_create_uncertainty_never_replays_mutation() {
        let desired = desired();
        let mut provider = FakeProvider {
            create_error: Some(uncertain_error("create Vultr instance")),
            create_commits: false,
            ..FakeProvider::default()
        };

        let error = apply_machine(
            &mut provider,
            &desired,
            "edge-1",
            &prerequisites(),
            &test_policy(),
        )
        .await
        .unwrap_err();

        assert!(error.contains("CREATE was not replayed"));
        assert_eq!(provider.create_calls, 1);
    }

    #[tokio::test]
    async fn replace_required_never_mutates() {
        let desired = desired();
        let machine = &desired.machines[0];
        let mut observed = instance_for_machine(&desired, machine, "instance-1");
        observed.plan = "vc2-2c-4gb".to_owned();
        let mut provider = FakeProvider {
            instances: vec![observed],
            ..FakeProvider::default()
        };

        let error = apply_machine(
            &mut provider,
            &desired,
            "edge-1",
            &prerequisites(),
            &test_policy(),
        )
        .await
        .unwrap_err();

        assert!(error.contains("requires replacement"));
        assert_eq!(provider.create_calls, 0);
    }

    #[tokio::test]
    async fn stale_destroy_digest_refuses_before_delete() {
        let desired = desired();
        let machine = &desired.machines[0];
        let mut provider = FakeProvider {
            instances: vec![instance_for_machine(&desired, machine, "instance-1")],
            ..FakeProvider::default()
        };
        let revision = "350aca23473b71e4fab83f7c55abde90a6f5d307";
        let plan = build_destroy_plan(&mut provider, &desired, "edge-1", revision)
            .await
            .unwrap();

        provider.instances[0].plan = "vc2-2c-4gb".to_owned();
        let error = destroy_machine(
            &mut provider,
            &desired,
            "edge-1",
            revision,
            &plan.destroy_digest,
            &test_policy(),
        )
        .await
        .unwrap_err();

        assert!(error.contains("destroy digest is stale"));
        assert_eq!(provider.delete_calls, 0);
    }

    #[tokio::test]
    async fn authorized_destroy_deletes_exact_uuid_once_and_proves_absence() {
        let desired = desired();
        let machine = &desired.machines[0];
        let mut provider = FakeProvider {
            instances: vec![instance_for_machine(&desired, machine, "instance-1")],
            delete_commits: true,
            ..FakeProvider::default()
        };
        let revision = "350aca23473b71e4fab83f7c55abde90a6f5d307";
        let plan = build_destroy_plan(&mut provider, &desired, "edge-1", revision)
            .await
            .unwrap();

        let report = destroy_machine(
            &mut provider,
            &desired,
            "edge-1",
            revision,
            &plan.destroy_digest,
            &test_policy(),
        )
        .await
        .unwrap();

        assert_eq!(report.provider_id, "instance-1");
        assert!(report.absence_verified);
        assert_eq!(provider.delete_calls, 1);
    }

    #[tokio::test]
    async fn uncertain_delete_accepted_is_reobserved_without_replay() {
        let desired = desired();
        let machine = &desired.machines[0];
        let mut provider = FakeProvider {
            instances: vec![instance_for_machine(&desired, machine, "instance-1")],
            delete_error: Some(uncertain_error("destroy Vultr instance")),
            delete_commits: true,
            ..FakeProvider::default()
        };
        let revision = "350aca23473b71e4fab83f7c55abde90a6f5d307";
        let plan = build_destroy_plan(&mut provider, &desired, "edge-1", revision)
            .await
            .unwrap();

        let report = destroy_machine(
            &mut provider,
            &desired,
            "edge-1",
            revision,
            &plan.destroy_digest,
            &test_policy(),
        )
        .await
        .unwrap();

        assert!(report.absence_verified);
        assert_eq!(provider.delete_calls, 1);
    }
}
