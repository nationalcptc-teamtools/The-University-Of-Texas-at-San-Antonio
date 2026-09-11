from dataclasses import FrozenInstanceError, fields, replace

import pytest

from cptc11_readonly_wave_v1.contracts import (
    ActionResult,
    HttpGetOperation,
    KeycloakFacts,
    MeilisearchFacts,
    RedisFacts,
    TraefikFacts,
    WireBudget,
    WireCounters,
)


def test_budget_and_counters_are_strict_frozen_values():
    budget = WireBudget(1, 1, 14, 128, 128, 5000)
    assert WireCounters(1, 1, 14, 7, 7).validate(budget) == WireCounters(
        1, 1, 14, 7, 7
    )
    with pytest.raises(FrozenInstanceError):
        budget.max_requests = 2
    for values in (
        (True, 1, 14, 7, 7),
        (1, 2, 14, 7, 7),
        (1, 1, 15, 7, 7),
        (1, 1, 14, 129, 7),
        (1, 1, 14, 7, 129),
    ):
        with pytest.raises((TypeError, ValueError)):
            WireCounters(*values).validate(budget)


def test_action_result_is_closed_metadata_only():
    from cptc11_readonly_wave_v1.catalog import plan_actions

    action = plan_actions("cptc11-readonly-wave-v1")[1]
    result = ActionResult.for_action(
        action,
        outcome="complete",
        limitation="none",
        counters=WireCounters(1, 1, 14, 7, 7),
        evidence_sha256="a" * 64,
        facts=RedisFacts("pong"),
    )
    assert result.facts == RedisFacts("pong")
    assert {field.name for field in fields(result)} == {
        "plan_id",
        "action_id",
        "profile_id",
        "target_id",
        "outcome",
        "limitation",
        "counters",
        "evidence_sha256",
        "facts",
    }
    with pytest.raises((TypeError, ValueError)):
        ActionResult.for_action(
            action,
            outcome="complete",
            limitation="none",
            counters=result.counters,
            evidence_sha256=True,
            facts=result.facts,
        )


def test_action_result_requires_a_sealed_action_and_exact_identity():
    from cptc11_readonly_wave_v1.catalog import plan_actions

    action = plan_actions("cptc11-readonly-wave-v1")[1]
    result = ActionResult.for_action(
        action, "complete", "none", WireCounters(1, 1, 14, 7, 7),
        "a" * 64, RedisFacts("pong"),
    )
    assert (result.plan_id, result.action_id, result.profile_id, result.target_id) == (
        action.plan_id, action.action_id, action.profile_id, action.target_id,
    )
    with pytest.raises(ValueError, match="sealed action"):
        ActionResult(
            action.plan_id, action.action_id, action.profile_id, action.target_id,
            "complete", "none", result.counters, result.evidence_sha256, result.facts,
        )
    with pytest.raises(ValueError, match="sealed action"):
        replace(result, action_id="forged")


def test_action_result_enforces_budget_parser_and_state_coherence():
    from cptc11_readonly_wave_v1.catalog import plan_actions

    redis = plan_actions("cptc11-readonly-wave-v1")[1]
    with pytest.raises(ValueError, match="budget"):
        ActionResult.for_action(
            redis, "complete", "none", WireCounters(1, 1, 14, 129, 129),
            "a" * 64, RedisFacts("pong"),
        )
    with pytest.raises(TypeError, match="parser"):
        ActionResult.for_action(
            redis, "complete", "none", WireCounters(1, 1, 14, 7, 7),
            "a" * 64, TraefikFacts(200, "3.1.2", True),
        )
    incoherent = (
        ("complete", "transport-uncertain", RedisFacts("pong")),
        ("complete", "none", None),
        ("uncertain", "none", None),
        ("uncertain", "transport-uncertain", RedisFacts("pong")),
        ("failed", "cancelled-before-contact", None),
    )
    for outcome, limitation, facts in incoherent:
        with pytest.raises(ValueError, match="coherent"):
            ActionResult.for_action(
                redis, outcome, limitation, WireCounters(1, 1, 14, 7, 7),
                "a" * 64, facts,
            )


def test_complete_action_result_requires_a_captured_complete_response():
    from cptc11_readonly_wave_v1.catalog import plan_actions

    redis = plan_actions("cptc11-readonly-wave-v1")[1]
    with pytest.raises(ValueError, match="coherent"):
        ActionResult.for_action(
            redis, "complete", "none", WireCounters(1, 1, 14, 0, 0),
            "a" * 64, RedisFacts("pong"),
        )
    with pytest.raises(ValueError, match="coherent"):
        ActionResult.for_action(
            redis, "complete", "none", WireCounters(1, 1, 14, 4, 4),
            "a" * 64, RedisFacts("incomplete"),
        )


def test_complete_action_result_preserves_valid_negative_facts():
    from cptc11_readonly_wave_v1.catalog import plan_actions

    actions = plan_actions("cptc11-readonly-wave-v1")
    cases = (
        (actions[0], WireCounters(1, 1, 123, 45, 45), TraefikFacts(404, None, False)),
        (actions[1], WireCounters(1, 1, 14, 34, 34), RedisFacts("authentication_required")),
        (actions[1], WireCounters(1, 1, 14, 11, 11), RedisFacts("unexpected")),
        (actions[3], WireCounters(1, 1, 118, 48, 48), MeilisearchFacts(503, "unavailable")),
    )
    for action, counters, facts in cases:
        result = ActionResult.for_action(
            action, "complete", "none", counters, "a" * 64, facts,
        )
        assert result.facts == facts


def test_action_result_cancelled_before_contact_requires_zero_counters():
    from cptc11_readonly_wave_v1.catalog import plan_actions

    redis = plan_actions("cptc11-readonly-wave-v1")[1]
    result = ActionResult.for_action(
        redis, "cancelled", "cancelled-before-contact", WireCounters(0, 0, 0, 0, 0),
        "a" * 64, None,
    )
    assert result.outcome == "cancelled"
    with pytest.raises(ValueError, match="coherent"):
        ActionResult.for_action(
            redis, "cancelled", "cancelled-before-contact", WireCounters(1, 0, 0, 0, 0),
            "a" * 64, None,
        )


def test_action_result_non_cancelled_counters_require_real_request_progress():
    from cptc11_readonly_wave_v1.catalog import plan_actions

    redis = plan_actions("cptc11-readonly-wave-v1")[1]
    invalid = (
        ("uncertain", "deadline", WireCounters(0, 0, 0, 0, 0)),
        ("uncertain", "transport-uncertain", WireCounters(1, 0, 0, 0, 0)),
        ("uncertain", "transport-uncertain", WireCounters(1, 1, 2, 1, 1)),
        ("failed", "protocol-rejected", WireCounters(0, 0, 0, 0, 0)),
        ("failed", "malformed-response", WireCounters(1, 0, 0, 0, 0)),
        ("failed", "malformed-response", WireCounters(1, 1, 0, 0, 0)),
    )
    for outcome, limitation, counters in invalid:
        with pytest.raises(ValueError, match="coherent"):
            ActionResult.for_action(
                redis, outcome, limitation, counters, "a" * 64, None,
            )

    partial = ActionResult.for_action(
        redis, "uncertain", "transport-uncertain", WireCounters(1, 1, 2, 0, 0),
        "a" * 64, None,
    )
    failed = ActionResult.for_action(
        redis, "failed", "protocol-rejected", WireCounters(1, 1, 14, 1, 1),
        "a" * 64, None,
    )
    assert partial.counters.tx_bytes == 2
    assert failed.counters.tx_bytes == 14


@pytest.mark.parametrize(
    "version",
    ("v3.1.2", "3.01.2", "3.1.2+", "3.1.2-" + "x" * 123),
)
def test_traefik_facts_require_normalized_bounded_semver(version):
    with pytest.raises((TypeError, ValueError), match="version"):
        TraefikFacts(200, version, True)


def test_http_fact_status_rejects_values_below_100():
    with pytest.raises((TypeError, ValueError), match="status_code"):
        TraefikFacts(99, None, False)


def test_operation_digest_must_match_exact_request():
    with pytest.raises(ValueError, match="request_sha256"):
        HttpGetOperation(
            request=b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
            request_sha256="0" * 64,
        )


def test_keycloak_facts_reject_unknown_or_out_of_order_enums():
    common = dict(
        status_code=200,
        realm_path_match=True,
        issuer_scheme="http",
        grant_types_present=True,
        signing_algorithms_present=True,
        unknown_grant_type=False,
        unknown_signing_algorithm=False,
    )
    with pytest.raises((TypeError, ValueError)):
        KeycloakFacts(
            grant_types=("unknown",),
            signing_algorithms=("RS256",),
            **common,
        )
    with pytest.raises(ValueError, match="catalog order"):
        KeycloakFacts(
            grant_types=("implicit", "authorization_code"),
            signing_algorithms=("RS256",),
            **common,
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"grant_types": ("authorization_code",)},
        {"unknown_grant_type": True},
        {"signing_algorithms": ("RS256",)},
        {"unknown_signing_algorithm": True},
        {"realm_path_match": True},
    ),
)
def test_keycloak_facts_reject_every_absent_metadata_contradiction(changes):
    values = {
        "status_code": 200,
        "realm_path_match": False,
        "issuer_scheme": "missing",
        "grant_types_present": False,
        "grant_types": (),
        "unknown_grant_type": False,
        "signing_algorithms_present": False,
        "signing_algorithms": (),
        "unknown_signing_algorithm": False,
    }
    values.update(changes)
    with pytest.raises(ValueError, match="coherent"):
        KeycloakFacts(**values)


def test_keycloak_facts_allow_present_empty_and_unknown_only_arrays():
    facts = KeycloakFacts(
        status_code=404,
        realm_path_match=False,
        issuer_scheme="missing",
        grant_types_present=True,
        grant_types=(),
        unknown_grant_type=True,
        signing_algorithms_present=True,
        signing_algorithms=(),
        unknown_signing_algorithm=True,
    )
    assert facts.grant_types == facts.signing_algorithms == ()
