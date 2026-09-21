#!/usr/bin/env python3
import copy
import json
from pathlib import Path

from validate_zero_trust_guardrails import validate_document, validate_repository


def assert_invalid(doc, needle):
    errors = validate_document(doc)
    assert any(needle in error for error in errors), errors


base = json.loads(
    Path("infra/cloudflare/zero-trust-guardrails.json").read_text(encoding="utf-8")
)
assert validate_document(base) == []
assert validate_repository(base, Path(".")) == []

case = copy.deepcopy(base)
case["zero_trust_boundary"]["generic_warp_connector_selector_allowed"] = False
assert_invalid(case, "WARP Connector selector")

case = copy.deepcopy(base)
case["zero_trust_boundary"]["project_profile_creation_allowed"] = False
assert_invalid(case, "profile creation")

case = copy.deepcopy(base)
case["zero_trust_boundary"]["protected_categories"].remove(
    "preexisting-registrations"
)
assert_invalid(case, "protected Zero Trust categories are incomplete")

case = copy.deepcopy(base)
case["evidence"]["must_be_outside_repository_worktree"] = False
assert_invalid(case, "evidence must remain outside")

case = copy.deepcopy(base)
case["zero_trust_boundary"]["controlled_existing_mutations"] = []
assert_invalid(case, "controlled existing-object mutation exception")

case = copy.deepcopy(base)
case["zero_trust_boundary"]["gateway_project_rule_creation_allowed"] = False
assert_invalid(case, "Gateway allow creation")

case = copy.deepcopy(base)
case["zero_trust_boundary"]["project_owned_legacy_warp_connector_names"] = []
assert_invalid(case, "legacy project-owned WARP Connector ownership changed")

case = copy.deepcopy(base)
case["zero_trust_boundary"]["manual_prerequisites"] = []
assert_invalid(case, "manual Mesh prerequisites changed")

case = copy.deepcopy(base)
case["owned_resource_selectors"]["legacy_connector_id"] = (
    "fbb6086e-8f54-493f-ae7e-c3fcf9bf3a64"
)
assert_invalid(case, "owned resource selectors must remain exact")
assert_invalid(case, "live/provider UUID")

print("test_validate_zero_trust_guardrails=PASS")
