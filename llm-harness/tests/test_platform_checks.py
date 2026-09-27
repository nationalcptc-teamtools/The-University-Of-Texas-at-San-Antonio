"""Strict, synthetic tests for the finite platform posture catalog."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cptc_harness.contracts import PolicyError, validate_schema
from cptc_harness.platform_checks import (CATALOG, CATALOG_VERSION, PLATFORM_RULES,
                                          PlatformDecision, PlatformRule, evaluate,
                                          fact_schema, validate_facts)


CASES = json.loads((Path(__file__).parent / "fixtures" / "platform_cases.json").read_text())
EXPECTED = {
    "network_tls_certificate_protocol_posture", "linux_sudo_privilege_boundary",
    "domain_account_policy", "delegation_relationships", "gpo_permissions",
    "adcs_configuration_relationships", "route_account_role_authorization",
    "session_lifecycle", "database_versions_transport_roles_grants",
}
VARIANTS = {"vulnerable", "hardened", "false_positive", "ambiguous", "partial", "access_denied", "untrusted"}


def _case_decision(check_id, variant):
    case = CASES[check_id][variant]
    return evaluate(check_id, case["facts"], collection_state=case["collection_state"],
                    provenance=case["provenance"], prerequisites_verified=case["prerequisites_verified"],
                    source_trusted=case["source_trusted"])


def test_catalog_is_finite_immutable_and_fixture_complete():
    assert CATALOG_VERSION == 1
    assert isinstance(CATALOG, tuple) and CATALOG == PLATFORM_RULES
    assert all(isinstance(rule, PlatformRule) for rule in CATALOG)
    assert {rule.check_id for rule in CATALOG} == EXPECTED
    with pytest.raises((AttributeError, TypeError)):
        CATALOG[0].required_fields += ("runtime",)
    assert set(CASES) == EXPECTED
    for check_id, variants in CASES.items():
        assert set(variants) == VARIANTS
        assert len({json.dumps(case, sort_keys=True) for case in variants.values()}) == len(VARIANTS)


@pytest.mark.parametrize("check_id", sorted(EXPECTED))
def test_each_rule_accepts_every_explicit_fixture_and_schema(check_id):
    schema = fact_schema(check_id)
    for case in CASES[check_id].values():
        facts = validate_facts(check_id, case["facts"])
        validate_schema(case["facts"], schema)
        assert set(facts) == set(schema["required"])


@pytest.mark.parametrize("check_id", sorted(EXPECTED))
def test_explicit_variants_match_exact_dispositions_limitations_and_are_deterministic(check_id):
    for variant, case in CASES[check_id].items():
        decision = _case_decision(check_id, variant)
        assert isinstance(decision, PlatformDecision)
        assert decision.disposition == case["expected_disposition"]
        assert list(decision.limitations) == case["expected_limitations"]
        assert decision == _case_decision(check_id, variant)
    assert _case_decision(check_id, "vulnerable").disposition == "candidate"
    assert _case_decision(check_id, "hardened").disposition == "not_observed"
    assert _case_decision(check_id, "false_positive").disposition == "not_observed"
    assert _case_decision(check_id, "ambiguous").disposition == "unknown"
    assert _case_decision(check_id, "partial").disposition == "incomplete"
    assert _case_decision(check_id, "access_denied").disposition == "blocked"
    assert _case_decision(check_id, "untrusted").disposition == "incomplete"


@pytest.mark.parametrize("check_id", sorted(EXPECTED))
def test_absent_and_unsupported_are_visible(check_id):
    facts = CASES[check_id]["vulnerable"]["facts"]
    assert evaluate(check_id, facts, collection_state="absent", provenance="unknown",
                    prerequisites_verified=False, source_trusted=False).disposition == "not_tested"
    assert evaluate(check_id, facts, collection_state="unsupported", provenance="unknown",
                    prerequisites_verified=False, source_trusted=False).disposition == "unsupported"


def test_exact_booleans_unknown_fields_and_schema_rejection():
    facts = CASES["gpo_permissions"]["hardened"]["facts"]
    with pytest.raises(ValueError):
        validate_facts("gpo_permissions", {**facts, "unexpected": False})
    with pytest.raises(ValueError):
        validate_facts("gpo_permissions", {**facts, "acl_complete": 1})
    with pytest.raises(ValueError):
        validate_facts("gpo_permissions", {key: value for key, value in facts.items() if key != "gpo_id"})
    with pytest.raises(ValueError):
        validate_facts("gpo_permissions", {**facts, "gpo_id": "bad id"})
    with pytest.raises(ValueError):
        evaluate("gpo_permissions", facts, collection_state="complete", provenance="operator_reviewed",
                 prerequisites_verified=1, source_trusted=True)
    with pytest.raises(ValueError):
        evaluate("gpo_permissions", facts, collection_state="complete", provenance="operator_reviewed",
                 prerequisites_verified=True, source_trusted=1)
    with pytest.raises(PolicyError):
        validate_schema({**facts, "unexpected": False}, fact_schema("gpo_permissions"))
    with pytest.raises(ValueError):
        evaluate("missing_check", {}, collection_state="complete", provenance="unknown",
                 prerequisites_verified=True, source_trusted=True)
