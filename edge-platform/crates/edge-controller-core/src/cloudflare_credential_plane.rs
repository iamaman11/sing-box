use crate::lifecycle::{AuthorizedPlan, PlanDisposition, authorize_plan};
use serde::{Deserialize, Serialize};

pub const CREDENTIAL_PLANE_AUTHORITY_DOMAIN: &str = "cloudflare_credential_plane";
pub const CREDENTIAL_ISOLATION_GENERATION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialProjection {
    Windows,
    Vm,
}

impl CredentialProjection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Vm => "vm",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialProjectionDesired {
    pub worker_name: String,
    pub service_token_name: String,
}

impl CredentialProjectionDesired {
    pub fn access_application_name(&self) -> String {
        self.worker_name.clone()
    }

    pub fn access_policy_name(&self) -> String {
        format!("{}-service-auth", self.worker_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPlaneDesired {
    pub account_id: String,
    pub generation: u64,
    pub windows: CredentialProjectionDesired,
    pub vm: CredentialProjectionDesired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CredentialProjectionObservation {
    pub worker_tag: Option<String>,
    pub worker_subdomain_enabled: Option<bool>,
    pub worker_previews_enabled: Option<bool>,
    pub service_token_id: Option<String>,
    pub service_token_enabled: Option<bool>,
    pub access_application_id: Option<String>,
    pub access_destination_worker_id: Option<String>,
    pub access_policy_id: Option<String>,
    pub access_policy_decision: Option<String>,
    pub access_policy_service_token_ids: Vec<String>,
    pub access_policy_has_extra_rules: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CredentialPlaneObservation {
    pub workers_subdomain: Option<String>,
    pub windows: CredentialProjectionObservation,
    pub vm: CredentialProjectionObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialPlaneAction {
    CreateWorker {
        projection: CredentialProjection,
    },
    ConfigureWorkerSubdomain {
        projection: CredentialProjection,
    },
    CreateServiceToken {
        projection: CredentialProjection,
    },
    CreateAccessApplication {
        projection: CredentialProjection,
    },
    Noop,
}

pub type CredentialPlanePlan = AuthorizedPlan<CredentialPlaneAction>;

pub fn authorize_credential_plane_plan(
    desired: &CredentialPlaneDesired,
    observed: &CredentialPlaneObservation,
) -> Result<CredentialPlanePlan, String> {
    validate_desired(desired)?;
    let action = plan_apply(desired, observed)?;
    let disposition = if matches!(action, CredentialPlaneAction::Noop) {
        PlanDisposition::Noop
    } else {
        PlanDisposition::Mutate
    };
    authorize_plan(
        CREDENTIAL_PLANE_AUTHORITY_DOMAIN,
        desired,
        observed,
        action,
        disposition,
    )
    .map_err(|err| err.to_string())
}

pub fn plan_apply(
    desired: &CredentialPlaneDesired,
    observed: &CredentialPlaneObservation,
) -> Result<CredentialPlaneAction, String> {
    validate_desired(desired)?;

    for (projection, expected, actual) in [
        (CredentialProjection::Windows, &desired.windows, &observed.windows),
        (CredentialProjection::Vm, &desired.vm, &observed.vm),
    ] {
        if actual.worker_tag.is_none() {
            reject_orphaned_projection_state(projection, actual)?;
            return Ok(CredentialPlaneAction::CreateWorker { projection });
        }

        if actual.worker_subdomain_enabled != Some(true)
            || actual.worker_previews_enabled != Some(false)
        {
            return Ok(CredentialPlaneAction::ConfigureWorkerSubdomain { projection });
        }

        if actual.service_token_id.is_none() {
            if actual.access_application_id.is_some() {
                return Err(format!(
                    "{} projection Access application exists without the canonical service-token identity",
                    projection.as_str()
                ));
            }
            return Ok(CredentialPlaneAction::CreateServiceToken { projection });
        }

        if actual.service_token_enabled != Some(true) {
            return Err(format!(
                "{} projection service token exists but is not enabled",
                projection.as_str()
            ));
        }

        if actual.access_application_id.is_none() {
            return Ok(CredentialPlaneAction::CreateAccessApplication { projection });
        }

        validate_exact_access_binding(projection, actual)?;
        let worker_tag = actual.worker_tag.as_deref().expect("checked above");
        if actual.access_destination_worker_id.as_deref() != Some(worker_tag) {
            return Err(format!(
                "{} projection Access destination does not bind the exact immutable Worker tag",
                projection.as_str()
            ));
        }
        let service_token_id = actual.service_token_id.as_deref().expect("checked above");
        if actual.access_policy_service_token_ids.as_slice() != [service_token_id] {
            return Err(format!(
                "{} projection Access policy is not bound to exactly its own service token",
                projection.as_str()
            ));
        }

        let _ = expected;
    }

    if observed.workers_subdomain.as_deref().is_none_or(str::is_empty) {
        return Err("Cloudflare Workers account subdomain is unavailable".to_owned());
    }

    Ok(CredentialPlaneAction::Noop)
}

fn validate_exact_access_binding(
    projection: CredentialProjection,
    actual: &CredentialProjectionObservation,
) -> Result<(), String> {
    if actual.access_policy_id.is_none() {
        return Err(format!(
            "{} projection Access application has no exact service-auth policy",
            projection.as_str()
        ));
    }
    if actual.access_policy_decision.as_deref() != Some("non_identity") {
        return Err(format!(
            "{} projection Access policy decision must be non_identity",
            projection.as_str()
        ));
    }
    if actual.access_policy_has_extra_rules {
        return Err(format!(
            "{} projection Access policy contains non-canonical include/require/exclude rules",
            projection.as_str()
        ));
    }
    Ok(())
}

fn reject_orphaned_projection_state(
    projection: CredentialProjection,
    actual: &CredentialProjectionObservation,
) -> Result<(), String> {
    if actual.worker_subdomain_enabled.is_some()
        || actual.worker_previews_enabled.is_some()
        || actual.service_token_id.is_some()
        || actual.access_application_id.is_some()
    {
        return Err(format!(
            "{} projection has credential-plane resources without the canonical Worker",
            projection.as_str()
        ));
    }
    Ok(())
}

fn validate_desired(desired: &CredentialPlaneDesired) -> Result<(), String> {
    if desired.generation != CREDENTIAL_ISOLATION_GENERATION {
        return Err(format!(
            "credential isolation generation must equal {}",
            CREDENTIAL_ISOLATION_GENERATION
        ));
    }
    if desired.account_id.len() != 32
        || !desired
            .account_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("credential-plane account ID must be 32 lowercase hexadecimal characters".to_owned());
    }
    if desired.windows.worker_name == desired.vm.worker_name {
        return Err("credential-plane Worker identities must be distinct".to_owned());
    }
    if desired.windows.service_token_name == desired.vm.service_token_name {
        return Err("credential-plane service-token identities must be distinct".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> CredentialPlaneDesired {
        CredentialPlaneDesired {
            account_id: "6be6e4b6340822dbeb18cb6c2f09c660".to_owned(),
            generation: CREDENTIAL_ISOLATION_GENERATION,
            windows: CredentialProjectionDesired {
                worker_name: "sing-box-credentials-windows".to_owned(),
                service_token_name: "sing-box-windows".to_owned(),
            },
            vm: CredentialProjectionDesired {
                worker_name: "sing-box-credentials-vm".to_owned(),
                service_token_name: "sing-box-vm-production-1".to_owned(),
            },
        }
    }

    fn complete(token: &str, worker_tag: &str) -> CredentialProjectionObservation {
        CredentialProjectionObservation {
            worker_tag: Some(worker_tag.to_owned()),
            worker_subdomain_enabled: Some(true),
            worker_previews_enabled: Some(false),
            service_token_id: Some(token.to_owned()),
            service_token_enabled: Some(true),
            access_application_id: Some(format!("app-{worker_tag}")),
            access_destination_worker_id: Some(worker_tag.to_owned()),
            access_policy_id: Some(format!("policy-{worker_tag}")),
            access_policy_decision: Some("non_identity".to_owned()),
            access_policy_service_token_ids: vec![token.to_owned()],
            access_policy_has_extra_rules: false,
        }
    }

    #[test]
    fn empty_target_starts_with_windows_worker_only() {
        let plan = authorize_credential_plane_plan(
            &desired(),
            &CredentialPlaneObservation::default(),
        )
        .unwrap();
        assert_eq!(
            plan.plan,
            CredentialPlaneAction::CreateWorker {
                projection: CredentialProjection::Windows
            }
        );
    }

    #[test]
    fn exact_isolation_state_is_noop() {
        let observed = CredentialPlaneObservation {
            workers_subdomain: Some("sing-box".to_owned()),
            windows: complete("windows-token", "windows-tag"),
            vm: complete("vm-token", "vm-tag"),
        };
        let plan = authorize_credential_plane_plan(&desired(), &observed).unwrap();
        assert!(matches!(plan.plan, CredentialPlaneAction::Noop));
        assert_eq!(plan.disposition, PlanDisposition::Noop);
    }

    #[test]
    fn cross_projection_service_token_alias_is_rejected() {
        let mut observed = CredentialPlaneObservation {
            workers_subdomain: Some("sing-box".to_owned()),
            windows: complete("windows-token", "windows-tag"),
            vm: complete("vm-token", "vm-tag"),
        };
        observed.windows.access_policy_service_token_ids = vec!["vm-token".to_owned()];
        assert!(
            plan_apply(&desired(), &observed)
                .unwrap_err()
                .contains("exactly its own service token")
        );
    }

    #[test]
    fn preview_path_must_be_disabled() {
        let mut observed = CredentialPlaneObservation::default();
        observed.windows.worker_tag = Some("windows-tag".to_owned());
        observed.windows.worker_subdomain_enabled = Some(true);
        observed.windows.worker_previews_enabled = Some(true);
        assert_eq!(
            plan_apply(&desired(), &observed).unwrap(),
            CredentialPlaneAction::ConfigureWorkerSubdomain {
                projection: CredentialProjection::Windows
            }
        );
    }
}
