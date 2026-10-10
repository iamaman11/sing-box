//! Scoped, single-object Cloudflare Mesh NODE profile owner for the disposable
//! application-acceptance account. No migration, global settings, Android, or DNS writes.
use crate::cli::MeshProfileCommand;
use crate::cloudflare_target_plane_command::next_free_precedence;
use edge_controller_core::lifecycle::{PlanDisposition, authorize_plan, verify_exact_authority};
use edge_controller_core::production::ProductionComposition;
use edge_provider_cloudflare::{
    CloudflareDeviceProfile, CloudflareDeviceProfileWrite, CloudflareServiceModeWrite,
    CloudflareSplitTunnelEntry, CloudflareSplitTunnelWrite, create_device_profile,
    get_device_profile_includes, list_device_profiles,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;

const PROFILE_SPEC: &str = "infra/cloudflare/zero-trust-lifecycle.json";
const GUARDRAILS_SPEC: &str = "infra/cloudflare/zero-trust-guardrails.json";
const ACCEPTANCE_MESH_SPEC: &str = "infra/cloudflare/application-acceptance-mesh.json";
const TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DesiredProfile {
    name: String,
    description: String,
    match_expression: String,
    precedence_start: u64,
    service_mode: String,
    tunnel_protocol: String,
    auto_connect: u64,
    switch_locked: bool,
    include_cidrs: Vec<String>,
}
#[derive(Deserialize)]
struct ProfileSpec {
    schema: u32,
    project: String,
    account_id: String,
    mesh_profile: DesiredProfile,
}
#[derive(Deserialize)]
struct Guardrails {
    schema: u32,
    account_id: String,
    zero_trust_boundary: GuardrailsBoundary,
}
#[derive(Deserialize)]
struct GuardrailsBoundary {
    mutate_existing_objects: bool,
    project_profile_creation_allowed: bool,
    generic_warp_connector_selector_allowed: bool,
    generic_warp_connector_selector: String,
}
#[derive(Deserialize)]
struct AcceptanceMesh {
    account_id: String,
}
#[derive(Clone, Debug, Serialize)]
struct Observation {
    profiles: Vec<CloudflareDeviceProfile>,
    selected_includes: Vec<CloudflareSplitTunnelEntry>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Action {
    Noop,
    Create { precedence: u64 },
}

fn parse_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let raw = fs::read_to_string(Path::new(path))
        .map_err(|_| format!("canonical Mesh authority file is unavailable: {path}"))?;
    serde_json::from_str(&raw)
        .map_err(|_| format!("invalid canonical Mesh authority schema: {path}"))
}

fn load_spec() -> Result<ProfileSpec, String> {
    let spec: ProfileSpec = parse_json(PROFILE_SPEC)?;
    let guardrails: Guardrails = parse_json(GUARDRAILS_SPEC)?;
    let acceptance: AcceptanceMesh = parse_json(ACCEPTANCE_MESH_SPEC)?;
    let active = ProductionComposition::canonical()
        .map_err(|_| "unable to read canonical production Cloudflare account".to_owned())?
        .cloudflare
        .active_account_id;
    validate_spec(&spec, &guardrails, &acceptance.account_id, &active)?;
    Ok(spec)
}

fn validate_spec(
    spec: &ProfileSpec,
    guardrails: &Guardrails,
    acceptance_account: &str,
    active_account: &str,
) -> Result<(), String> {
    let profile = &spec.mesh_profile;
    let cidrs = profile
        .include_cidrs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if spec.schema != 1
        || guardrails.schema != 1
        || spec.project != "sing-box"
        || spec.account_id.is_empty()
        || spec.account_id != guardrails.account_id
        || spec.account_id != acceptance_account
        || spec.account_id == active_account
    {
        return Err(
            "Mesh profile creation must target only the canonical disposable acceptance account"
                .to_owned(),
        );
    }
    if guardrails.zero_trust_boundary.mutate_existing_objects
        || !guardrails
            .zero_trust_boundary
            .project_profile_creation_allowed
        || !guardrails
            .zero_trust_boundary
            .generic_warp_connector_selector_allowed
        || profile.name != "sing-box Mesh nodes"
        || profile.description
            != "Project Mesh nodes: Traffic and DNS over MASQUE with required Cloudflare Mesh ranges"
        || profile.match_expression
            != guardrails
                .zero_trust_boundary
                .generic_warp_connector_selector
        || !profile
            .match_expression
            .starts_with("identity.email == \"warp_connector@")
        || !profile
            .match_expression
            .ends_with(".cloudflareaccess.com\"")
        || profile.precedence_start != 100
        || profile.service_mode != "warp"
        || profile.tunnel_protocol != "masque"
        || profile.auto_connect != 1
        || !profile.switch_locked
        || cidrs != BTreeSet::from(["100.64.0.0/12".to_owned(), "100.96.0.0/12".to_owned()])
        || profile.include_cidrs.len() != cidrs.len()
    {
        return Err(
            "Mesh NODE profile differs from the exact project-owned acceptance contract".to_owned(),
        );
    }
    Ok(())
}

async fn observe(token: &str, spec: &ProfileSpec) -> Result<Observation, String> {
    let mut profiles = list_device_profiles(token, &spec.account_id).await?;
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let matches = profiles
        .iter()
        .filter(|profile| {
            profile.name == spec.mesh_profile.name
                || profile.match_expression.as_deref() == Some(&spec.mesh_profile.match_expression)
        })
        .collect::<Vec<_>>();
    let selected_includes = match matches.as_slice() {
        [profile]
            if profile.name == spec.mesh_profile.name
                && profile.match_expression.as_deref()
                    == Some(&spec.mesh_profile.match_expression) =>
        {
            get_device_profile_includes(token, &spec.account_id, &profile.id).await?
        }
        _ => Vec::new(),
    };
    Ok(Observation {
        profiles,
        selected_includes,
    })
}

fn plan(spec: &ProfileSpec, observation: &Observation) -> Result<Action, String> {
    let matches = observation
        .profiles
        .iter()
        .filter(|profile| {
            profile.name == spec.mesh_profile.name
                || profile.match_expression.as_deref() == Some(&spec.mesh_profile.match_expression)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => {
            let precedence = next_free_precedence(
                spec.mesh_profile.precedence_start,
                observation
                    .profiles
                    .iter()
                    .filter_map(|profile| profile.precedence),
            )?;
            Ok(Action::Create { precedence })
        }
        [profile] => {
            let expected = &spec.mesh_profile;
            let includes = observation
                .selected_includes
                .iter()
                .map(|entry| match (&entry.address, &entry.host) {
                    (Some(address), None) => format!("address:{address}"),
                    _ => "invalid".to_owned(),
                })
                .collect::<BTreeSet<_>>();
            let expected_includes = expected
                .include_cidrs
                .iter()
                .map(|value| format!("address:{value}"))
                .collect::<BTreeSet<_>>();
            if profile.name != expected.name
                || profile.match_expression.as_deref() != Some(&expected.match_expression)
                || profile.description.as_deref() != Some(&expected.description)
                || profile.enabled != Some(true)
                || profile.service_mode.as_deref() != Some(&expected.service_mode)
                || profile.tunnel_protocol.as_deref() != Some(&expected.tunnel_protocol)
                || profile.auto_connect != Some(expected.auto_connect)
                || profile.switch_locked != Some(expected.switch_locked)
                || !profile
                    .precedence
                    .is_some_and(|value| value >= expected.precedence_start)
                || includes != expected_includes
                || observation.selected_includes.len() != expected.include_cidrs.len()
            {
                return Err("project Mesh NODE profile exists but differs: protected existing profile is not modified".to_owned());
            }
            Ok(Action::Noop)
        }
        _ => {
            Err("Mesh NODE profile name or selector is ambiguous: no mutation permitted".to_owned())
        }
    }
}

fn make_write(spec: &ProfileSpec, precedence: u64) -> CloudflareDeviceProfileWrite {
    CloudflareDeviceProfileWrite {
        name: spec.mesh_profile.name.clone(),
        description: spec.mesh_profile.description.clone(),
        enabled: true,
        precedence,
        match_expression: spec.mesh_profile.match_expression.clone(),
        service_mode_v2: CloudflareServiceModeWrite {
            mode: spec.mesh_profile.service_mode.clone(),
        },
        tunnel_protocol: spec.mesh_profile.tunnel_protocol.clone(),
        auto_connect: spec.mesh_profile.auto_connect,
        switch_locked: spec.mesh_profile.switch_locked,
        include: Some(
            spec.mesh_profile
                .include_cidrs
                .iter()
                .map(|address| CloudflareSplitTunnelWrite {
                    address: Some(address.clone()),
                    host: None,
                    description: Some(if address == "100.96.0.0/12" {
                        "Cloudflare Mesh device IPs".to_owned()
                    } else {
                        "Cloudflare source IPs".to_owned()
                    }),
                })
                .collect(),
        ),
    }
}

pub(crate) async fn run(command: MeshProfileCommand) -> Result<(), String> {
    let spec = load_spec()?;
    let token = env::var(TOKEN_ENV).map_err(|_| format!("{TOKEN_ENV} is required"))?;
    if token.is_empty() {
        return Err(format!("{TOKEN_ENV} must not be empty"));
    }
    let before = observe(&token, &spec).await?;
    let planned = plan(&spec, &before)?;
    let authorized = authorize_plan(
        "acceptance_mesh_node_profile",
        &spec.mesh_profile,
        &before,
        planned,
        if planned == Action::Noop {
            PlanDisposition::Noop
        } else {
            PlanDisposition::Mutate
        },
    )
    .map_err(|err| err.to_string())?;
    match command {
        MeshProfileCommand::Plan => {
            println!(
                "mesh_profile_action={}",
                if planned == Action::Noop {
                    "NOOP"
                } else {
                    "CREATE"
                }
            );
            println!("plan_authority={}", authorized.authority.authority_digest);
            println!("existing_profile_count={}", before.profiles.len());
            println!("mutations_performed=0");
            Ok(())
        }
        MeshProfileCommand::Verify => {
            if planned != Action::Noop {
                return Err("Mesh NODE profile not converged; exact CREATE required".to_owned());
            }
            println!("mesh_profile_status=PASS");
            println!("mutations_performed=0");
            Ok(())
        }
        MeshProfileCommand::Apply {
            authorized_plan_sha256,
        } => {
            verify_exact_authority(&authorized_plan_sha256, &authorized.authority)
                .map_err(|err| err.to_string())?;
            let Action::Create { precedence } = planned else {
                return Err(
                    "Mesh profile apply cannot mutate when exact terminal NOOP is observed"
                        .to_owned(),
                );
            };
            // Exactly one POST, with no retry and no UPDATE/DELETE. A transport error
            // has uncertain outcome: only observe; never replay the POST.
            let mutation =
                create_device_profile(&token, &spec.account_id, &make_write(&spec, precedence))
                    .await;
            let after = observe(&token, &spec).await
                .map_err(|_| "Mesh profile mutation outcome uncertain; provider reobservation unavailable; no replay".to_owned())?;
            if plan(&spec, &after)? != Action::Noop {
                return Err("Mesh profile create not verified after one bounded reobservation; no mutation replay".to_owned());
            }
            if mutation.is_err() {
                println!("mesh_profile_create_result=UNCERTAIN_BUT_REOBSERVED_EXACT");
            } else {
                println!("mesh_profile_create_result=CREATED_AND_VERIFIED");
            }
            println!("mesh_profile_status=PASS");
            println!("mutations_performed=1");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (ProfileSpec, Guardrails) {
        let spec: ProfileSpec = serde_json::from_str(include_str!(
            "../../../../infra/cloudflare/zero-trust-lifecycle.json"
        ))
        .unwrap();
        let guardrails: Guardrails = serde_json::from_str(include_str!(
            "../../../../infra/cloudflare/zero-trust-guardrails.json"
        ))
        .unwrap();
        (spec, guardrails)
    }
    fn existing(spec: &ProfileSpec) -> CloudflareDeviceProfile {
        CloudflareDeviceProfile {
            id: "owned-node-profile".to_owned(),
            name: spec.mesh_profile.name.clone(),
            description: Some(spec.mesh_profile.description.clone()),
            enabled: Some(true),
            precedence: Some(100),
            match_expression: Some(spec.mesh_profile.match_expression.clone()),
            service_mode: Some("warp".to_owned()),
            tunnel_protocol: Some("masque".to_owned()),
            auto_connect: Some(1),
            switch_locked: Some(true),
        }
    }
    fn empty() -> Observation {
        Observation {
            profiles: vec![],
            selected_includes: vec![],
        }
    }
    fn includes(spec: &ProfileSpec) -> Vec<CloudflareSplitTunnelEntry> {
        spec.mesh_profile
            .include_cidrs
            .iter()
            .map(|address| CloudflareSplitTunnelEntry {
                address: Some(address.clone()),
                host: None,
                description: None,
            })
            .collect()
    }
    #[test]
    fn acceptance_contract_is_distinct_from_active_production() {
        let (spec, guardrails) = fixture();
        assert!(validate_spec(&spec, &guardrails, &spec.account_id, "production-account").is_ok());
        assert!(validate_spec(&spec, &guardrails, &spec.account_id, &spec.account_id).is_err());
        let mut wrong = spec;
        wrong.mesh_profile.match_expression =
            "identity.email == \"warp_connector@foreign.cloudflareaccess.com\"".to_owned();
        assert!(
            validate_spec(&wrong, &guardrails, &wrong.account_id, "production-account").is_err()
        );
    }
    #[test]
    fn refuses_existing_mutations_and_unapproved_account() {
        let (spec, mut g) = fixture();
        g.zero_trust_boundary.mutate_existing_objects = true;
        assert!(validate_spec(&spec, &g, &spec.account_id, "production").is_err());
        g.zero_trust_boundary.mutate_existing_objects = false;
        g.zero_trust_boundary.project_profile_creation_allowed = false;
        assert!(validate_spec(&spec, &g, &spec.account_id, "production").is_err());
        g.zero_trust_boundary.project_profile_creation_allowed = true;
        assert!(validate_spec(&spec, &g, "foreign-account", "production").is_err());
    }
    #[test]
    fn single_missing_profile_authorizes_exact_one_create() {
        let (spec, _) = fixture();
        assert_eq!(
            plan(&spec, &empty()).unwrap(),
            Action::Create { precedence: 100 }
        );
        let write = make_write(&spec, 100);
        assert_eq!(write.service_mode_v2.mode, "warp");
        assert_eq!(write.include.as_ref().unwrap().len(), 2);
        let consumed = Observation {
            profiles: vec![CloudflareDeviceProfile {
                id: "foreign".to_owned(),
                name: "foreign".to_owned(),
                description: None,
                enabled: Some(true),
                precedence: Some(100),
                match_expression: None,
                service_mode: None,
                tunnel_protocol: None,
                auto_connect: None,
                switch_locked: None,
            }],
            selected_includes: vec![],
        };
        assert_eq!(
            plan(&spec, &consumed).unwrap(),
            Action::Create { precedence: 101 }
        );
    }
    #[test]
    fn terminal_noop_is_exact_and_drift_fails_closed() {
        let (spec, _) = fixture();
        let good = Observation {
            profiles: vec![existing(&spec)],
            selected_includes: includes(&spec),
        };
        assert_eq!(plan(&spec, &good).unwrap(), Action::Noop);
        let mut drift = good.clone();
        drift.profiles[0].switch_locked = Some(false);
        assert!(plan(&spec, &drift).is_err());
        let mut drift = good.clone();
        drift.selected_includes.push(CloudflareSplitTunnelEntry {
            address: Some("10.0.0.0/8".to_owned()),
            host: None,
            description: None,
        });
        assert!(plan(&spec, &drift).is_err());
        let mut drift = good.clone();
        drift.profiles[0].name = "preexisting foreign profile".to_owned();
        assert!(plan(&spec, &drift).is_err());
        let mut collision = good.clone();
        collision.profiles.push(existing(&spec));
        assert!(plan(&spec, &collision).is_err());
    }
    #[test]
    fn exact_plan_authority_rejects_stale_observation() {
        let (spec, _) = fixture();
        let before = empty();
        let old = authorize_plan(
            "acceptance_mesh_node_profile",
            &spec.mesh_profile,
            &before,
            Action::Create { precedence: 100 },
            PlanDisposition::Mutate,
        )
        .unwrap();
        let mut changed = empty();
        changed.profiles.push(CloudflareDeviceProfile {
            id: "foreign".to_owned(),
            name: "foreign".to_owned(),
            description: None,
            enabled: Some(true),
            precedence: Some(100),
            match_expression: None,
            service_mode: None,
            tunnel_protocol: None,
            auto_connect: None,
            switch_locked: None,
        });
        let current = authorize_plan(
            "acceptance_mesh_node_profile",
            &spec.mesh_profile,
            &changed,
            plan(&spec, &changed).unwrap(),
            PlanDisposition::Mutate,
        )
        .unwrap();
        assert!(
            verify_exact_authority(&old.authority.authority_digest, &current.authority).is_err()
        );
    }
}
