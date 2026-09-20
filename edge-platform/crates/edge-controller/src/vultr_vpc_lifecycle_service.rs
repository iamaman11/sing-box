use edge_controller_core::lifecycle::{
    AuthorizedPlan, PlanDisposition, authorize_plan, verify_exact_authority,
};
use edge_controller_core::vultr_lifecycle::{MANAGED_BY_IDENTITY, decode_provider_tags};
use edge_controller_core::vultr_vpc_lifecycle::{
    AttachmentAction, AttachmentPlan, CleanupAction, CleanupPlan, DesiredVpcState, ObservedVpc,
    ObservedVpcAttachment, VpcApplyAction, VpcApplyPlan, VpcAttachmentObservation, VpcObservation,
    plan_attachment, plan_cleanup, plan_vpc_apply, verify_cleanup_digest,
};
use edge_provider_vultr::{
    VultrError, VultrInstance, VultrVpc, VultrVpcAttachment, attach_vpc_to_instance_typed,
    create_vpc_typed, destroy_vpc_typed, detach_vpc_from_instance_typed, list_instances_typed,
    list_vpc_attachments_typed, list_vpcs_typed,
};
use serde::Serialize;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct VpcExecutionPolicy {
    pub reobserve_attempts: usize,
    pub reobserve_delay: Duration,
}

impl Default for VpcExecutionPolicy {
    fn default() -> Self {
        Self {
            reobserve_attempts: 30,
            reobserve_delay: Duration::from_secs(2),
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait VpcProvider {
    async fn list_vpcs(&mut self) -> Result<Vec<VultrVpc>, VultrError>;
    async fn create_vpc(&mut self, region: &str, description: &str)
    -> Result<VultrVpc, VultrError>;
    async fn destroy_vpc(&mut self, vpc_id: &str) -> Result<(), VultrError>;
    async fn list_vpc_attachments(
        &mut self,
        vpc_id: &str,
    ) -> Result<Vec<VultrVpcAttachment>, VultrError>;
    async fn attach_vpc_to_instance(
        &mut self,
        instance_id: &str,
        vpc_id: &str,
    ) -> Result<(), VultrError>;
    async fn detach_vpc_from_instance(
        &mut self,
        instance_id: &str,
        vpc_id: &str,
    ) -> Result<(), VultrError>;
    async fn list_instances(&mut self) -> Result<Vec<VultrInstance>, VultrError>;
}

pub struct VultrVpcApiProvider {
    api_key: String,
}

impl VultrVpcApiProvider {
    pub fn new(api_key: String) -> Result<Self, String> {
        if api_key.trim().is_empty() {
            return Err("VULTR_API_KEY must be non-empty".to_owned());
        }
        Ok(Self { api_key })
    }
}

impl VpcProvider for VultrVpcApiProvider {
    async fn list_vpcs(&mut self) -> Result<Vec<VultrVpc>, VultrError> {
        list_vpcs_typed(&self.api_key).await
    }

    async fn create_vpc(
        &mut self,
        region: &str,
        description: &str,
    ) -> Result<VultrVpc, VultrError> {
        create_vpc_typed(&self.api_key, region, description).await
    }

    async fn destroy_vpc(&mut self, vpc_id: &str) -> Result<(), VultrError> {
        destroy_vpc_typed(&self.api_key, vpc_id).await
    }

    async fn list_vpc_attachments(
        &mut self,
        vpc_id: &str,
    ) -> Result<Vec<VultrVpcAttachment>, VultrError> {
        list_vpc_attachments_typed(&self.api_key, vpc_id).await
    }

    async fn attach_vpc_to_instance(
        &mut self,
        instance_id: &str,
        vpc_id: &str,
    ) -> Result<(), VultrError> {
        attach_vpc_to_instance_typed(&self.api_key, instance_id, vpc_id).await
    }

    async fn detach_vpc_from_instance(
        &mut self,
        instance_id: &str,
        vpc_id: &str,
    ) -> Result<(), VultrError> {
        detach_vpc_from_instance_typed(&self.api_key, instance_id, vpc_id).await
    }

    async fn list_instances(&mut self) -> Result<Vec<VultrInstance>, VultrError> {
        list_instances_typed(&self.api_key).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetInstance {
    pub provider_id: String,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VpcApplyReport {
    pub performed: VpcApplyAction,
    pub observation: VpcObservation,
    pub next_plan: VpcApplyPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttachmentApplyReport {
    pub performed: AttachmentAction,
    pub target: TargetInstance,
    pub observation: VpcObservation,
    pub attachments: VpcAttachmentObservation,
    pub next_plan: AttachmentPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VpcReadyReport {
    pub status: &'static str,
    pub target: TargetInstance,
    pub vpc_provider_id: String,
    pub cidr: String,
    pub private_ipv4: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanupApplyReport {
    pub performed: CleanupAction,
    pub observation: VpcObservation,
    pub attachments: VpcAttachmentObservation,
    pub next_plan: CleanupPlan,
}

pub async fn observe_vpc<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
) -> Result<VpcObservation, String> {
    desired.validate().map_err(|err| err.to_string())?;
    let description = desired.ownership_description();
    let mut vpcs = provider
        .list_vpcs()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|vpc| vpc.description == description)
        .map(normalize_vpc)
        .collect::<Vec<_>>();
    vpcs.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    Ok(VpcObservation { vpcs })
}

pub async fn plan_vpc<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
) -> Result<(VpcObservation, VpcApplyPlan), String> {
    let observed = observe_vpc(provider, desired).await?;
    let plan = plan_vpc_apply(desired, &observed).map_err(|err| err.to_string())?;
    Ok((observed, plan))
}

pub async fn apply_vpc_once<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
    authorized_plan_digest: &str,
    policy: VpcExecutionPolicy,
) -> Result<VpcApplyReport, String> {
    validate_policy(&policy)?;
    let (observation, plan) = plan_vpc(provider, desired).await?;
    let authorized = authorize_vpc_apply(desired, &observation, plan.clone())?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;
    match &plan.action {
        VpcApplyAction::Noop => Ok(VpcApplyReport {
            performed: VpcApplyAction::Noop,
            observation,
            next_plan: plan,
        }),
        VpcApplyAction::CreateVpc => {
            let mutation = provider
                .create_vpc(&desired.region, &desired.ownership_description())
                .await;
            if let Err(err) = &mutation
                && !err.requires_mutation_reobservation()
            {
                return Err(err.to_string());
            }

            let (observation, next_plan) = wait_for_vpc_noop(provider, desired, &policy).await?;
            Ok(VpcApplyReport {
                performed: VpcApplyAction::CreateVpc,
                observation,
                next_plan,
            })
        }
    }
}

pub async fn plan_vpc_attachment<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
) -> Result<
    (
        TargetInstance,
        VpcObservation,
        VpcAttachmentObservation,
        AttachmentPlan,
    ),
    String,
> {
    let target = resolve_exact_target_instance(provider, desired)
        .await?
        .ok_or_else(|| {
            format!(
                "exact lifecycle-owned Vultr instance {} is absent",
                desired.machine_id
            )
        })?;
    let observation = observe_vpc(provider, desired).await?;
    let vpc_id = exact_vpc_id(desired, &observation)?;
    let attachments = observe_attachments(provider, &vpc_id).await?;
    let plan = plan_attachment(desired, &observation, &attachments, &target.provider_id)
        .map_err(|err| err.to_string())?;
    Ok((target, observation, attachments, plan))
}

pub async fn apply_vpc_attachment_once<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
    authorized_plan_digest: &str,
    policy: VpcExecutionPolicy,
) -> Result<AttachmentApplyReport, String> {
    validate_policy(&policy)?;
    let (target, observation, attachments, plan) = plan_vpc_attachment(provider, desired).await?;
    let authorized = authorize_vpc_attachment(
        desired,
        &target,
        &observation,
        &attachments,
        plan.clone(),
    )?;
    verify_exact_authority(authorized_plan_digest, &authorized.authority)
        .map_err(|err| err.to_string())?;

    match &plan.action {
        AttachmentAction::Noop => Ok(AttachmentApplyReport {
            performed: AttachmentAction::Noop,
            target,
            observation,
            attachments,
            next_plan: plan,
        }),
        AttachmentAction::AttachInstance { vpc_id } => {
            let performed = plan.action.clone();
            let mutation = provider
                .attach_vpc_to_instance(&target.provider_id, vpc_id)
                .await;
            if let Err(err) = &mutation
                && !err.requires_mutation_reobservation()
            {
                return Err(err.to_string());
            }

            let (observation, attachments, next_plan) =
                wait_for_attachment_noop(provider, desired, &target, &policy).await?;
            Ok(AttachmentApplyReport {
                performed,
                target,
                observation,
                attachments,
                next_plan,
            })
        }
    }
}

pub async fn verify_vpc_ready<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
) -> Result<VpcReadyReport, String> {
    let (target, _observation, _attachments, plan) = plan_vpc_attachment(provider, desired).await?;
    if plan.action != AttachmentAction::Noop {
        return Err(format!(
            "Vultr VPC is not READY for machine {}: attachment plan is {:?}",
            desired.machine_id, plan.action
        ));
    }
    let vpc_provider_id = match plan_vpc(provider, desired).await?.1 {
        VpcApplyPlan {
            action: VpcApplyAction::Noop,
            provider_id: Some(provider_id),
            ..
        } => provider_id,
        other => {
            return Err(format!(
                "Vultr VPC is not READY for machine {}: VPC plan is {:?}",
                desired.machine_id, other.action
            ));
        }
    };
    let private_ipv4 = plan.private_ipv4.ok_or_else(|| {
        "Vultr VPC attachment is NOOP but provider private IPv4 is absent".to_owned()
    })?;
    Ok(VpcReadyReport {
        status: "PASS",
        target,
        vpc_provider_id,
        cidr: plan.cidr,
        private_ipv4,
    })
}


pub fn authorize_vpc_apply(
    desired: &DesiredVpcState,
    observation: &VpcObservation,
    plan: VpcApplyPlan,
) -> Result<AuthorizedPlan<VpcApplyPlan>, String> {
    let disposition = if matches!(plan.action, VpcApplyAction::Noop) {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    authorize_plan(
        "vultr_vpc_apply",
        desired,
        observation,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub fn authorize_vpc_attachment(
    desired: &DesiredVpcState,
    target: &TargetInstance,
    observation: &VpcObservation,
    attachments: &VpcAttachmentObservation,
    plan: AttachmentPlan,
) -> Result<AuthorizedPlan<AttachmentPlan>, String> {
    let disposition = if matches!(plan.action, AttachmentAction::Noop) {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    let desired_material = serde_json::json!({
        "desired": desired,
        "target_provider_id": &target.provider_id,
    });
    let observed_material = serde_json::json!({
        "vpc": observation,
        "attachments": attachments,
    });
    authorize_plan(
        "vultr_vpc_attachment",
        &desired_material,
        &observed_material,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub fn authorize_vpc_cleanup(
    desired: &DesiredVpcState,
    observation: &VpcObservation,
    attachments: &VpcAttachmentObservation,
    plan: CleanupPlan,
) -> Result<AuthorizedPlan<CleanupPlan>, String> {
    let disposition = if matches!(plan.action, CleanupAction::Noop) {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    let observed_material = serde_json::json!({
        "vpc": observation,
        "attachments": attachments,
    });
    authorize_plan(
        "vultr_vpc_cleanup",
        desired,
        &observed_material,
        plan,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub async fn plan_vpc_cleanup<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
) -> Result<(VpcObservation, VpcAttachmentObservation, CleanupPlan), String> {
    let observation = observe_vpc(provider, desired).await?;
    let vpc_plan = plan_vpc_apply(desired, &observation).map_err(|err| err.to_string())?;
    let Some(vpc_id) = vpc_plan.provider_id else {
        let attachments = VpcAttachmentObservation::default();
        let plan = plan_cleanup(desired, &observation, &attachments, None)
            .map_err(|err| err.to_string())?;
        return Ok((observation, attachments, plan));
    };

    let attachments = observe_attachments(provider, &vpc_id).await?;
    let target = if attachments.attachments.is_empty() {
        None
    } else {
        Some(
            resolve_exact_target_instance(provider, desired)
                .await?
                .ok_or_else(|| {
                    format!(
                        "refusing Vultr VPC cleanup: attachments exist but exact lifecycle-owned instance {} is absent",
                        desired.machine_id
                    )
                })?,
        )
    };
    let plan = plan_cleanup(
        desired,
        &observation,
        &attachments,
        target.as_ref().map(|target| target.provider_id.as_str()),
    )
    .map_err(|err| err.to_string())?;
    Ok((observation, attachments, plan))
}

pub async fn cleanup_vpc_once<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
    expected_digest: &str,
    authorized_plan_digest: &str,
    policy: VpcExecutionPolicy,
) -> Result<CleanupApplyReport, String> {
    validate_policy(&policy)?;
    let (observation, attachments, current) = plan_vpc_cleanup(provider, desired).await?;
    let target = if attachments.attachments.is_empty() {
        None
    } else {
        Some(
            resolve_exact_target_instance(provider, desired)
                .await?
                .ok_or_else(|| {
                    "refusing Vultr VPC cleanup because exact target instance is absent".to_owned()
                })?,
        )
    };
    let generic = authorize_vpc_cleanup(desired, &observation, &attachments, current.clone())?;
    verify_exact_authority(authorized_plan_digest, &generic.authority)
        .map_err(|err| err.to_string())?;
    let destructive = verify_cleanup_digest(
        desired,
        &observation,
        &attachments,
        target.as_ref().map(|target| target.provider_id.as_str()),
        expected_digest,
    )
    .map_err(|err| err.to_string())?;

    if current != destructive {
        return Err("Vultr VPC cleanup authorization changed during planning".to_owned());
    }

    match &destructive.action {
        CleanupAction::Noop => Err("Vultr VPC cleanup target is already absent".to_owned()),
        CleanupAction::DetachInstance {
            vpc_id,
            instance_id,
        } => {
            let performed = destructive.action.clone();
            let mutation = provider.detach_vpc_from_instance(instance_id, vpc_id).await;
            if let Err(err) = &mutation
                && !err.requires_mutation_reobservation()
            {
                return Err(err.to_string());
            }
            let (observation, attachments, next_plan) =
                wait_for_cleanup_progress(provider, desired, &policy, true).await?;
            Ok(CleanupApplyReport {
                performed,
                observation,
                attachments,
                next_plan,
            })
        }
        CleanupAction::DeleteVpc { vpc_id } => {
            let performed = destructive.action.clone();
            let mutation = provider.destroy_vpc(vpc_id).await;
            if let Err(err) = &mutation
                && !err.requires_mutation_reobservation()
            {
                return Err(err.to_string());
            }
            let (observation, attachments, next_plan) =
                wait_for_cleanup_progress(provider, desired, &policy, false).await?;
            Ok(CleanupApplyReport {
                performed,
                observation,
                attachments,
                next_plan,
            })
        }
    }
}

async fn wait_for_vpc_noop<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
    policy: &VpcExecutionPolicy,
) -> Result<(VpcObservation, VpcApplyPlan), String> {
    for attempt in 1..=policy.reobserve_attempts {
        let (observation, plan) = plan_vpc(provider, desired).await?;
        if plan.action == VpcApplyAction::Noop {
            return Ok((observation, plan));
        }
        if attempt < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }
    Err("Vultr VPC create did not converge to NOOP after bounded re-observation".to_owned())
}

async fn wait_for_attachment_noop<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
    target: &TargetInstance,
    policy: &VpcExecutionPolicy,
) -> Result<(VpcObservation, VpcAttachmentObservation, AttachmentPlan), String> {
    for attempt in 1..=policy.reobserve_attempts {
        let observation = observe_vpc(provider, desired).await?;
        let vpc_id = exact_vpc_id(desired, &observation)?;
        let attachments = observe_attachments(provider, &vpc_id).await?;
        let plan = plan_attachment(desired, &observation, &attachments, &target.provider_id)
            .map_err(|err| err.to_string())?;
        if plan.action == AttachmentAction::Noop {
            return Ok((observation, attachments, plan));
        }
        if attempt < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }
    Err("Vultr VPC attachment did not converge to NOOP after bounded re-observation".to_owned())
}

async fn wait_for_cleanup_progress<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
    policy: &VpcExecutionPolicy,
    expect_delete_vpc: bool,
) -> Result<(VpcObservation, VpcAttachmentObservation, CleanupPlan), String> {
    for attempt in 1..=policy.reobserve_attempts {
        let (observation, attachments, plan) = plan_vpc_cleanup(provider, desired).await?;
        let converged = if expect_delete_vpc {
            matches!(plan.action, CleanupAction::DeleteVpc { .. })
        } else {
            plan.action == CleanupAction::Noop
        };
        if converged {
            return Ok((observation, attachments, plan));
        }
        if attempt < policy.reobserve_attempts {
            sleep(policy.reobserve_delay).await;
        }
    }
    Err(if expect_delete_vpc {
        "Vultr VPC detach did not converge to DELETE_VPC after bounded re-observation".to_owned()
    } else {
        "Vultr VPC delete did not converge to NOOP after bounded re-observation".to_owned()
    })
}

async fn resolve_exact_target_instance<P: VpcProvider>(
    provider: &mut P,
    desired: &DesiredVpcState,
) -> Result<Option<TargetInstance>, String> {
    let instances = provider
        .list_instances()
        .await
        .map_err(|err| err.to_string())?;
    let mut matches = Vec::new();

    for instance in instances {
        let decoded = decode_provider_tags(&instance.tags).map_err(|err| {
            format!(
                "invalid lifecycle identity on Vultr instance {} while resolving VPC target: {err}",
                instance.id
            )
        })?;
        let exact = decoded.ownership.managed_by.as_deref() == Some(MANAGED_BY_IDENTITY)
            && decoded.ownership.environment.as_deref() == Some(desired.environment.as_str())
            && decoded.ownership.logical_id.as_deref() == Some(desired.machine_id.as_str());
        if exact {
            if instance.region != desired.region {
                return Err(format!(
                    "exact lifecycle-owned Vultr instance {} is in region {}, expected {}",
                    instance.id, instance.region, desired.region
                ));
            }
            matches.push(TargetInstance {
                provider_id: instance.id,
                region: instance.region,
            });
        }
    }

    matches.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    match matches.as_slice() {
        [] => Ok(None),
        [target] => Ok(Some(target.clone())),
        _ => Err(format!(
            "Vultr VPC target {} is ambiguous: observed {} exact lifecycle-owned instances",
            desired.machine_id,
            matches.len()
        )),
    }
}

fn exact_vpc_id(desired: &DesiredVpcState, observation: &VpcObservation) -> Result<String, String> {
    let plan = plan_vpc_apply(desired, observation).map_err(|err| err.to_string())?;
    match plan {
        VpcApplyPlan {
            action: VpcApplyAction::Noop,
            provider_id: Some(provider_id),
            ..
        } => Ok(provider_id),
        _ => Err("owned Vultr VPC is absent; create it before attachment".to_owned()),
    }
}

async fn observe_attachments<P: VpcProvider>(
    provider: &mut P,
    vpc_id: &str,
) -> Result<VpcAttachmentObservation, String> {
    let mut attachments = provider
        .list_vpc_attachments(vpc_id)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(normalize_attachment)
        .collect::<Vec<_>>();
    attachments.sort_by(|left, right| {
        left.subscription_id
            .cmp(&right.subscription_id)
            .then_with(|| left.attachment_id.cmp(&right.attachment_id))
    });
    Ok(VpcAttachmentObservation { attachments })
}

fn normalize_vpc(value: VultrVpc) -> ObservedVpc {
    ObservedVpc {
        provider_id: value.id,
        region: value.region,
        description: value.description,
        v4_subnet: value.v4_subnet,
        v4_subnet_mask: value.v4_subnet_mask,
    }
}

fn normalize_attachment(value: VultrVpcAttachment) -> ObservedVpcAttachment {
    ObservedVpcAttachment {
        attachment_id: value.id,
        subscription_id: value.subscription_id,
        private_ipv4: value.private_ipv4,
    }
}

fn validate_policy(policy: &VpcExecutionPolicy) -> Result<(), String> {
    if policy.reobserve_attempts == 0 {
        return Err("Vultr VPC reobserve_attempts must be greater than zero".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_controller_core::vultr_lifecycle::{
        ENVIRONMENT_TAG_PREFIX, LOGICAL_ID_TAG_PREFIX, MANAGED_BY_TAG,
    };
    use edge_provider_vultr::mock_instance;

    #[derive(Default)]
    struct FakeProvider {
        vpcs: Vec<VultrVpc>,
        attachments: Vec<VultrVpcAttachment>,
        instances: Vec<VultrInstance>,
        create_vpc_calls: usize,
        attach_calls: usize,
        detach_calls: usize,
        delete_vpc_calls: usize,
        create_error: Option<VultrError>,
        attach_error: Option<VultrError>,
        commit_create_on_error: bool,
        commit_attach_on_error: bool,
    }

    impl VpcProvider for FakeProvider {
        async fn list_vpcs(&mut self) -> Result<Vec<VultrVpc>, VultrError> {
            Ok(self.vpcs.clone())
        }

        async fn create_vpc(
            &mut self,
            region: &str,
            description: &str,
        ) -> Result<VultrVpc, VultrError> {
            self.create_vpc_calls += 1;
            let vpc = fake_vpc(region, description);
            if self.create_error.is_none() || self.commit_create_on_error {
                self.vpcs.push(vpc.clone());
            }
            match self.create_error.clone() {
                Some(error) => Err(error),
                None => Ok(vpc),
            }
        }

        async fn destroy_vpc(&mut self, vpc_id: &str) -> Result<(), VultrError> {
            self.delete_vpc_calls += 1;
            self.vpcs.retain(|vpc| vpc.id != vpc_id);
            Ok(())
        }

        async fn list_vpc_attachments(
            &mut self,
            _vpc_id: &str,
        ) -> Result<Vec<VultrVpcAttachment>, VultrError> {
            Ok(self.attachments.clone())
        }

        async fn attach_vpc_to_instance(
            &mut self,
            instance_id: &str,
            _vpc_id: &str,
        ) -> Result<(), VultrError> {
            self.attach_calls += 1;
            let attachment = fake_attachment(instance_id);
            if self.attach_error.is_none() || self.commit_attach_on_error {
                self.attachments.push(attachment);
            }
            match self.attach_error.clone() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        async fn detach_vpc_from_instance(
            &mut self,
            instance_id: &str,
            _vpc_id: &str,
        ) -> Result<(), VultrError> {
            self.detach_calls += 1;
            self.attachments
                .retain(|attachment| attachment.subscription_id != instance_id);
            Ok(())
        }

        async fn list_instances(&mut self) -> Result<Vec<VultrInstance>, VultrError> {
            Ok(self.instances.clone())
        }
    }

    fn desired() -> DesiredVpcState {
        DesiredVpcState {
            schema: 1,
            environment: "application-acceptance".to_owned(),
            region: "waw".to_owned(),
            machine_id: "application-acceptance-1".to_owned(),
        }
    }

    fn fake_vpc(region: &str, description: &str) -> VultrVpc {
        VultrVpc {
            id: "vpc-1".to_owned(),
            region: region.to_owned(),
            description: description.to_owned(),
            v4_subnet: "10.0.4.0".to_owned(),
            v4_subnet_mask: 24,
            date_created: "2026-09-20T00:00:00+00:00".to_owned(),
        }
    }

    fn fake_attachment(instance_id: &str) -> VultrVpcAttachment {
        VultrVpcAttachment {
            id: "attachment-1".to_owned(),
            private_ipv4: "10.0.4.2".to_owned(),
            subscription_id: instance_id.to_owned(),
        }
    }

    fn fake_instance() -> VultrInstance {
        let mut instance = mock_instance(
            "application-acceptance-1",
            "waw",
            "vc2-1c-1gb",
            "203.0.113.10",
        );
        instance.tags = vec![
            MANAGED_BY_TAG.to_owned(),
            format!("{ENVIRONMENT_TAG_PREFIX}application-acceptance"),
            format!("{LOGICAL_ID_TAG_PREFIX}application-acceptance-1"),
        ];
        instance
    }

    fn uncertain(operation: &'static str) -> VultrError {
        VultrError {
            operation,
            kind: edge_provider_vultr::VultrErrorKind::MutationUncertain,
            status: None,
            retry_after_secs: None,
            detail: "simulated response loss".to_owned(),
        }
    }

    fn policy() -> VpcExecutionPolicy {
        VpcExecutionPolicy {
            reobserve_attempts: 2,
            reobserve_delay: Duration::ZERO,
        }
    }

    async fn vpc_authority(provider: &mut FakeProvider, desired: &DesiredVpcState) -> String {
        let (observation, plan) = plan_vpc(provider, desired).await.unwrap();
        authorize_vpc_apply(desired, &observation, plan)
            .unwrap()
            .authority
            .authority_digest
    }

    async fn attachment_authority(
        provider: &mut FakeProvider,
        desired: &DesiredVpcState,
    ) -> String {
        let (target, observation, attachments, plan) =
            plan_vpc_attachment(provider, desired).await.unwrap();
        authorize_vpc_attachment(desired, &target, &observation, &attachments, plan)
            .unwrap()
            .authority
            .authority_digest
    }

    async fn cleanup_authority(
        provider: &mut FakeProvider,
        desired: &DesiredVpcState,
    ) -> (String, String) {
        let (observation, attachments, plan) =
            plan_vpc_cleanup(provider, desired).await.unwrap();
        let destructive = plan.destructive_digest.clone().unwrap();
        let generic = authorize_vpc_cleanup(desired, &observation, &attachments, plan)
            .unwrap()
            .authority
            .authority_digest;
        (destructive, generic)
    }

    #[tokio::test]
    async fn create_is_one_shot_and_reobserved() {
        let desired = desired();
        let mut provider = FakeProvider::default();
        let authority = vpc_authority(&mut provider, &desired).await;
        let report = apply_vpc_once(&mut provider, &desired, &authority, policy())
            .await
            .unwrap();
        assert_eq!(provider.create_vpc_calls, 1);
        assert_eq!(report.performed, VpcApplyAction::CreateVpc);
        assert_eq!(report.next_plan.action, VpcApplyAction::Noop);
        assert_eq!(report.next_plan.cidr.as_deref(), Some("10.0.4.0/24"));
    }

    #[tokio::test]
    async fn uncertain_create_is_never_replayed() {
        let mut provider = FakeProvider {
            create_error: Some(uncertain("create Vultr VPC")),
            commit_create_on_error: true,
            ..FakeProvider::default()
        };
        let desired = desired();
        let authority = vpc_authority(&mut provider, &desired).await;
        let report = apply_vpc_once(&mut provider, &desired, &authority, policy())
            .await
            .unwrap();
        assert_eq!(provider.create_vpc_calls, 1);
        assert_eq!(report.next_plan.action, VpcApplyAction::Noop);
    }

    #[tokio::test]
    async fn stale_vpc_authority_rejects_without_mutation() {
        let desired = desired();
        let mut provider = FakeProvider::default();
        let authority = vpc_authority(&mut provider, &desired).await;
        provider.vpcs.push(fake_vpc("waw", &desired.ownership_description()));

        let error = apply_vpc_once(&mut provider, &desired, &authority, policy())
            .await
            .unwrap_err();

        assert!(error.contains("stale"));
        assert_eq!(provider.create_vpc_calls, 0);
    }

    #[tokio::test]
    async fn attach_is_one_shot_and_returns_provider_private_ip() {
        let desired = desired();
        let mut provider = FakeProvider {
            vpcs: vec![fake_vpc("waw", &desired.ownership_description())],
            instances: vec![fake_instance()],
            ..FakeProvider::default()
        };
        let authority = attachment_authority(&mut provider, &desired).await;
        let report = apply_vpc_attachment_once(&mut provider, &desired, &authority, policy())
            .await
            .unwrap();
        assert_eq!(provider.attach_calls, 1);
        assert_eq!(report.next_plan.action, AttachmentAction::Noop);
        assert_eq!(report.next_plan.private_ipv4.as_deref(), Some("10.0.4.2"));
    }

    #[tokio::test]
    async fn uncertain_attach_is_never_replayed() {
        let desired = desired();
        let mut provider = FakeProvider {
            vpcs: vec![fake_vpc("waw", &desired.ownership_description())],
            instances: vec![fake_instance()],
            attach_error: Some(uncertain("attach Vultr VPC to instance")),
            commit_attach_on_error: true,
            ..FakeProvider::default()
        };
        let report = apply_vpc_attachment_once(&mut provider, &desired, policy())
            .await
            .unwrap();
        assert_eq!(provider.attach_calls, 1);
        assert_eq!(report.next_plan.action, AttachmentAction::Noop);
    }

    #[tokio::test]
    async fn foreign_attachment_blocks_apply_and_cleanup() {
        let desired = desired();
        let mut provider = FakeProvider {
            vpcs: vec![fake_vpc("waw", &desired.ownership_description())],
            instances: vec![fake_instance()],
            attachments: vec![fake_attachment("foreign-instance")],
            ..FakeProvider::default()
        };
        assert!(plan_vpc_attachment(&mut provider, &desired).await.is_err());
        assert!(plan_vpc_cleanup(&mut provider, &desired).await.is_err());
        assert_eq!(provider.detach_calls, 0);
        assert_eq!(provider.delete_vpc_calls, 0);
    }

    #[tokio::test]
    async fn cleanup_detaches_then_deletes_with_fresh_digest_each_step() {
        let desired = desired();
        let mut provider = FakeProvider {
            vpcs: vec![fake_vpc("waw", &desired.ownership_description())],
            instances: vec![fake_instance()],
            attachments: vec![fake_attachment("mock-waw-application-acceptance-1")],
            ..FakeProvider::default()
        };

        let (detach_digest, detach_authority) = cleanup_authority(&mut provider, &desired).await;
        let detach = cleanup_vpc_once(
            &mut provider,
            &desired,
            &detach_digest,
            &detach_authority,
            policy(),
        )
        .await
        .unwrap();
        assert_eq!(provider.detach_calls, 1);
        assert!(matches!(
            detach.next_plan.action,
            CleanupAction::DeleteVpc { .. }
        ));

        let (delete_digest, delete_authority) = cleanup_authority(&mut provider, &desired).await;
        assert_ne!(detach_digest, delete_digest);
        let delete = cleanup_vpc_once(
            &mut provider,
            &desired,
            &delete_digest,
            &delete_authority,
            policy(),
        )
        .await
        .unwrap();
        assert_eq!(provider.delete_vpc_calls, 1);
        assert_eq!(delete.next_plan.action, CleanupAction::Noop);
    }

    #[tokio::test]
    async fn duplicate_exact_target_instances_fail_closed() {
        let desired = desired();
        let instance = fake_instance();
        let mut second = instance.clone();
        second.id = "instance-2".to_owned();
        let mut provider = FakeProvider {
            vpcs: vec![fake_vpc("waw", &desired.ownership_description())],
            instances: vec![instance, second],
            ..FakeProvider::default()
        };
        assert!(plan_vpc_attachment(&mut provider, &desired).await.is_err());
        assert_eq!(provider.attach_calls, 0);
    }
}
