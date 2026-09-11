from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path

import pytest

from cptc_harness.contracts import PolicyError, canonical_json
from cptc_harness.host_profile_catalog import (
    EXPECTED_HOST_CATALOG_SHA256,
    HOST_PROFILE_ID,
    get_host_profile,
    load_host_profile_catalog,
    validate_host_profile_result,
)


FIXTURES = Path(__file__).parent / "fixtures" / "windows_defender"
RESULT_FIELDS = (
    "realtime_protection_enabled",
    "on_access_protection_enabled",
    "ioav_protection_enabled",
    "behavior_monitoring_enabled",
)


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text())


def _rehash(value: dict[str, object]) -> None:
    value["catalog_sha256"] = hashlib.sha256(canonical_json({
        "version": value["version"],
        "profiles": value["profiles"],
    })).hexdigest()


def test_catalog_exposes_one_exact_immutable_blocked_profile():
    catalog = load_host_profile_catalog()
    assert catalog.version == 1
    assert catalog.catalog_sha256 == EXPECTED_HOST_CATALOG_SHA256
    assert len(catalog.profiles) == 1

    profile = catalog.profiles[0]
    assert profile.profile_id == HOST_PROFILE_ID == "windows_ad.defender_protection"
    assert profile.platform == "windows_ad"
    assert profile.mode == "blocked"
    assert profile.required_role == "admin"
    assert profile.result_fields == RESULT_FIELDS
    assert profile.result_contract == tuple((field, "boolean") for field in RESULT_FIELDS)
    assert profile.runtime_options == ()
    assert profile.effects == ("credentialed_read_only_observation",)
    assert profile.blocked_reason == (
        "Credential-bound parent-owned WinRM HTTPS transport and certificate pin are required."
    )
    assert profile.budget.tcp_connects == 1
    assert profile.budget.udp_datagrams == 0
    assert profile.budget.protocol_requests == 1
    assert profile.budget.tx_bytes == 32768
    assert profile.budget.rx_bytes == 65536
    assert profile.budget.timeout_s == 30.0
    assert profile.budget.cpu_s == 10.0
    assert profile.budget.output_bytes == 16384
    assert profile.budget.process_limit == 1
    assert profile.budget.auth_attempts == 1
    with pytest.raises(FrozenInstanceError):
        profile.mode = "live_admitted"


def test_source_runner_and_query_contracts_are_exact_hash_anchored_identifiers():
    profile = get_host_profile(HOST_PROFILE_ID)
    assert (profile.source_contract.contract_id, profile.source_contract.sha256) == (
        "microsoft.defender.preference-fields.v1",
        "9ccafb2e6ee89af2632f184d06ffe831d8314bee546d42f6fc9a6b5b9a760e0b",
    )
    assert (profile.runner_contract.contract_id, profile.runner_contract.sha256) == (
        "blocked.parent-owned-winrm-https.v1",
        "60862bea8e09410b6bd0a0ef5935bddc3e938b0abf549604f4ab64a2ef271256",
    )
    assert (profile.query_contract.contract_id, profile.query_contract.sha256) == (
        "typed.defender.protection-fields.v1",
        "477dec8abbc3fd6beaca1c953f096e640b2e6b52d13df9aaa7d4d6f4f32bacae",
    )
    for contract in (profile.source_contract, profile.runner_contract, profile.query_contract):
        assert hashlib.sha256(contract.contract_id.encode("ascii")).hexdigest() == contract.sha256


@pytest.mark.parametrize("name", ["disabled.json", "enabled.json", "mixed.json"])
def test_complete_synthetic_results_validate_as_exact_typed_records(name):
    source = _load(name)
    result = validate_host_profile_result(source)
    assert result.as_dict() == source
    assert all(type(value) is bool for value in result.as_dict().values())


def test_result_object_field_order_does_not_change_the_typed_contract():
    source = _load("mixed.json")
    reordered = dict(reversed(tuple(source.items())))
    assert validate_host_profile_result(reordered).as_dict() == source


@pytest.mark.parametrize("name", ["missing.json", "invalid.json"])
def test_incomplete_or_invalid_synthetic_results_are_rejected(name):
    with pytest.raises(PolicyError, match="result"):
        validate_host_profile_result(_load(name))


@pytest.mark.parametrize("bad", [
    {**_load("enabled.json"), "extra": False},
    {**_load("enabled.json"), "realtime_protection_enabled": 1},
    {**_load("enabled.json"), "realtime_protection_enabled": "true"},
    [True, True, True, True],
    None,
])
def test_result_contract_rejects_unknown_fields_and_non_boolean_values(bad):
    with pytest.raises(PolicyError, match="result"):
        validate_host_profile_result(bad)


def test_catalog_rejects_mutation_even_when_attacker_recomputes_inner_hash(tmp_path):
    original = json.loads(load_host_profile_catalog().path.read_text())
    attacks = (
        ("mode", "live_admitted"),
        ("required_role", "user"),
        ("runtime_options", ["command"]),
        ("blocked_reason", "ready"),
    )
    for number, (field, replacement) in enumerate(attacks):
        mutated = json.loads(json.dumps(original))
        mutated["profiles"][0][field] = replacement
        _rehash(mutated)
        path = tmp_path / f"mutated-{number}.json"
        path.write_text(json.dumps(mutated))
        with pytest.raises(PolicyError, match="anchor"):
            load_host_profile_catalog(path)


def test_catalog_rejects_contract_hash_drift_and_unknown_schema_fields(tmp_path):
    original = json.loads(load_host_profile_catalog().path.read_text())
    for number, mutate in enumerate((
        lambda row: row["profiles"][0]["query_contract"].update({"sha256": "0" * 64}),
        lambda row: row["profiles"][0].update({"command": "Get-MpPreference"}),
        lambda row: row["profiles"][0]["budget"].update({"tcp_connects": 2}),
        lambda row: row.update({"runtime": {}}),
    )):
        mutated = json.loads(json.dumps(original))
        mutate(mutated)
        _rehash(mutated)
        path = tmp_path / f"schema-{number}.json"
        path.write_text(json.dumps(mutated))
        with pytest.raises(PolicyError):
            load_host_profile_catalog(path)


def test_catalog_rejects_aliases_wildcards_and_replaced_profiles():
    for profile_id in ("*", "windows_ad.*", "../defender", "windows_ad.defender"):
        with pytest.raises(PolicyError, match="unknown"):
            get_host_profile(profile_id)
    profile = get_host_profile(HOST_PROFILE_ID)
    with pytest.raises(PolicyError, match="profile"):
        validate_host_profile_result(_load("enabled.json"), replace(profile, mode="lab_candidate"))
