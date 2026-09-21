#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

EXPECTED_ACCOUNT = "4426df1449e417511bc7697d60b7f62f"
EXPECTED_PROTECTED = {
    "default-device-profile",
    "preexisting-custom-device-profiles",
    "preexisting-physical-devices",
    "preexisting-registrations",
    "preexisting-warp-connectors",
}
EXPECTED_DIGEST_EXCLUDES = {
    "status",
    "last_seen_at",
    "updated_at",
    "conns_active_at",
    "conns_inactive_at",
}
UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)


def _expect(errors, condition, message):
    if not condition:
        errors.append(message)


def _walk_strings(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_strings(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_strings(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def validate_document(doc):
    errors = []
    _expect(errors, isinstance(doc, dict), "manifest must be a JSON object")
    if not isinstance(doc, dict):
        return errors

    _expect(
        errors,
        set(doc) == {
            "schema",
            "project",
            "account_id",
            "canonical_specs",
            "owned_resource_selectors",
            "zero_trust_boundary",
            "evidence",
        },
        "top-level keys must match schema 1 exactly",
    )
    _expect(errors, doc.get("schema") == 1, "schema must be 1")
    _expect(errors, doc.get("project") == "sing-box", "project must be sing-box")
    _expect(errors, doc.get("account_id") == EXPECTED_ACCOUNT, "unexpected Cloudflare account")

    specs = doc.get("canonical_specs", {})
    _expect(
        errors,
        specs == {
            "dns": "infra/cloudflare/application-acceptance-dns.json",
            "mesh": "infra/cloudflare/application-acceptance-mesh.json",
            "zero_trust_lifecycle": "infra/cloudflare/zero-trust-lifecycle.json",
        },
        "canonical Cloudflare spec paths changed",
    )

    selectors = doc.get("owned_resource_selectors", {})
    _expect(
        errors,
        selectors == {
            "dns_record_name": "stage2-acceptance.alegria.by",
            "mesh_node_name": "singbox-line3-application-acceptance",
            "mesh_route_authority": "verified-vultr-vpc-only",
        },
        "owned resource selectors must remain exact and contain no provider IDs",
    )

    boundary = doc.get("zero_trust_boundary", {})
    _expect(
        errors,
        boundary.get("mode") == "controlled-project-prerequisite-lifecycle",
        "Zero Trust boundary must remain controlled-project-prerequisite-lifecycle",
    )
    _expect(
        errors,
        boundary.get("mutate_existing_objects") is False,
        "existing Zero Trust objects must remain non-mutable",
    )
    _expect(
        errors,
        boundary.get("project_profile_creation_allowed") is True,
        "project Zero Trust profile creation must remain explicitly allowed",
    )
    _expect(
        errors,
        boundary.get("generic_warp_connector_selector_allowed") is True,
        "project-owned WARP Connector selector must remain explicitly allowed",
    )
    _expect(
        errors,
        boundary.get("generic_warp_connector_selector")
        == 'identity.email == "warp_connector@wispy-fire-124a.cloudflareaccess.com"',
        "generic WARP Connector selector identity changed",
    )
    _expect(
        errors,
        set(boundary.get("protected_categories", [])) == EXPECTED_PROTECTED,
        "protected Zero Trust categories are incomplete",
    )
    _expect(
        errors,
        boundary.get("required_client_contract")
        == {
            "service_mode": "warp",
            "tunnel_protocol": "masque",
            "mesh_cidr": "100.96.0.0/12",
            "cloudflare_source_cidr": "100.64.0.0/12",
        },
        "required Mesh client contract changed",
    )

    _expect(
        errors,
        boundary.get("controlled_existing_mutations")
        == ["runtime-authorized-android-profile-split-tunnel-only"],
        "controlled existing-object mutation exception changed",
    )
    _expect(
        errors,
        boundary.get("gateway_project_rule_creation_allowed") is True,
        "project Gateway allow creation must remain explicitly allowed",
    )
    _expect(
        errors,
        boundary.get("project_owned_legacy_warp_connector_names") == ["vultr"],
        "legacy project-owned WARP Connector ownership changed",
    )
    _expect(
        errors,
        boundary.get("manual_prerequisites") == ["enrolled-device-reachability"],
        "manual Mesh prerequisites changed",
    )
    _expect(
        errors,
        boundary.get("access_enrollment_required") is True,
        "WARP device enrollment must remain a required prerequisite",
    )
    _expect(
        errors,
        boundary.get("gateway_mesh_allow_required") is True,
        "project Mesh Gateway allow must remain a required prerequisite",
    )

    evidence = doc.get("evidence", {})
    _expect(
        errors,
        evidence.get("must_be_outside_repository_worktree") is True,
        "evidence must remain outside the repository worktree",
    )
    _expect(
        errors,
        set(evidence.get("configuration_digest_excludes", []))
        == EXPECTED_DIGEST_EXCLUDES,
        "configuration digest volatile-field exclusions changed",
    )

    for path, value in _walk_strings(doc):
        if UUID_RE.search(value):
            errors.append(
                f"{path} contains a live/provider UUID; canonical ownership uses selectors, not live IDs"
            )

    return errors


def validate_repository(doc, repo_root):
    errors = validate_document(doc)
    if errors:
        return errors

    specs = doc["canonical_specs"]
    selectors = doc["owned_resource_selectors"]
    boundary = doc["zero_trust_boundary"]
    boundary = doc["zero_trust_boundary"]

    try:
        dns = json.loads((repo_root / specs["dns"]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"failed to load canonical DNS spec: {error}")
        return errors

    try:
        mesh = json.loads((repo_root / specs["mesh"]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"failed to load canonical Mesh spec: {error}")
        return errors

    try:
        lifecycle = json.loads(
            (repo_root / specs["zero_trust_lifecycle"]).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"failed to load canonical Zero Trust lifecycle spec: {error}")
        return errors

    _expect(
        errors,
        dns.get("record_name") == selectors["dns_record_name"],
        "ownership DNS selector differs from canonical DNS spec",
    )
    _expect(
        errors,
        mesh.get("node_name") == selectors["mesh_node_name"],
        "ownership Mesh node selector differs from canonical Mesh spec",
    )
    _expect(
        errors,
        mesh.get("account_id") == doc["account_id"],
        "ownership account differs from canonical Mesh spec",
    )
    _expect(
        errors,
        mesh.get("routes") == [],
        "canonical Mesh base spec must remain route-free; route authority is derived from verified VPC state",
    )
    _expect(
        errors,
        dns.get("environment") == mesh.get("environment") == "application-acceptance",
        "canonical DNS and Mesh specs must share application-acceptance ownership",
    )
    _expect(
        errors,
        lifecycle.get("account_id") == doc["account_id"],
        "Zero Trust lifecycle account differs from ownership guardrails",
    )
    _expect(
        errors,
        lifecycle.get("allowed_connector_names")
        == ["vultr", selectors["mesh_node_name"]],
        "Zero Trust lifecycle connector allowlist differs from ownership selectors",
    )
    _expect(
        errors,
        lifecycle.get("mesh_profile", {}).get("match_expression")
        == boundary.get("generic_warp_connector_selector"),
        "Zero Trust lifecycle Mesh selector differs from ownership guardrails",
    )
    _expect(
        errors,
        lifecycle.get("mesh_profile", {}).get("include_cidrs")
        == ["100.64.0.0/12", "100.96.0.0/12"],
        "Zero Trust lifecycle Mesh include contract changed",
    )
    _expect(
        errors,
        lifecycle.get("android_profile", {}).get("remove_exclusions")
        == ["100.64.0.0/10"],
        "Android CGNAT removal contract changed",
    )
    _expect(
        errors,
        [entry.get("address") for entry in lifecycle.get("android_profile", {}).get("add_exclusions", [])]
        == ["100.80.0.0/12", "100.112.0.0/12"],
        "Android CGNAT preservation contract changed",
    )

    for path, value in _walk_strings(lifecycle):
        if UUID_RE.search(value):
            errors.append(
                f"Zero Trust lifecycle {path} contains a live/provider UUID; runtime IDs must stay outside Git"
            )

    return errors


def main(argv):
    if len(argv) != 2:
        raise SystemExit(
            "usage: validate_zero_trust_guardrails.py <guardrails-json>"
        )
    path = Path(argv[1])
    doc = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_repository(doc, Path("."))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("zero_trust_guardrails=PASS")


if __name__ == "__main__":
    main(sys.argv)
