from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json

import pytest

from cptc_harness.scanner_catalog import (
    EXPECTED_CATALOG_SHA256,
    PROFILE_IDS,
    catalog_path,
    load_catalog,
    profile_for,
    plan_for,
    validate_plan,
)
from cptc_harness.scanner_contracts import NetworkEndpoint, ScannerContractError, ScannerGrant, ScannerObservation, contract_hash


FIXTURES = Path(__file__).parent / "fixtures" / "scanner"


def test_catalog_is_finite_and_contains_only_design_or_synthetic_profiles():
    profiles = load_catalog()
    assert tuple(profile.profile_id for profile in profiles) == PROFILE_IDS
    assert PROFILE_IDS == (
        "network.nse_smb2_security_mode",
        "network.nse_smb2_time",
        "network.msf_http_version",
    )
    assert {profile.mode for profile in profiles} <= {"design_only", "synthetic_only"}
    assert profiles[0].mode == profiles[1].mode == "synthetic_only"
    assert profiles[2].mode == "design_only"
    for profile in profiles[:2]:
        assert profile.port == 445
        assert profile.budget.tcp_connects == 2
        assert profile.budget.udp_datagrams == 1
        assert profile.budget.protocol_requests == 2
        assert profile.budget.tx_bytes == 4096
        assert profile.budget.rx_bytes == 16384
        assert profile.budget.timeout_s == 15.0
        assert profile.budget.cpu_s == 10.0
        assert profile.budget.output_bytes == 16384
        assert profile.budget.process_limit == 1
    assert profiles[2].budget.tcp_connects == 1
    assert profiles[2].budget.udp_datagrams == 0
    assert profiles[2].budget.protocol_requests == 1
    assert profiles[2].budget.tx_bytes == 4096
    assert profiles[2].budget.rx_bytes == 16384
    assert profiles[2].budget.timeout_s == 10.0
    assert profiles[2].budget.cpu_s == 10.0
    assert profiles[2].budget.output_bytes == 16384
    assert profiles[2].budget.process_limit == 1
    assert all(not profile.allowed_options for profile in profiles)
    assert all(profile.budget.auth_attempts == 0 for profile in profiles)
    assert all(profile.source.sha256 and len(profile.source.sha256) == 64 for profile in profiles)


def test_catalog_hash_drift_and_bad_profile_ids_block():
    with pytest.raises(ScannerContractError, match="hash"):
        load_catalog(FIXTURES / "catalog-drift.json")
    for value in ("*", "network.nse_*", "network.nse_smb2_time.nse", "../../msfconsole"):
        with pytest.raises(ScannerContractError):
            profile_for(value)


def _leaf_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _leaf_paths(item, (*prefix, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _leaf_paths(item, (*prefix, index))
    else:
        yield prefix


def _changed(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 0.5
    return value + "x"


def test_catalog_anchor_rejects_every_profile_leaf_change_even_with_a_recomputed_hash(tmp_path):
    value = json.loads(catalog_path().read_text())
    assert value["catalog_sha256"] == EXPECTED_CATALOG_SHA256
    for number, path_parts in enumerate(_leaf_paths(value["profiles"])):
        mutated = json.loads(json.dumps(value))
        parent = mutated["profiles"]
        for part in path_parts[:-1]:
            parent = parent[part]
        parent[path_parts[-1]] = _changed(parent[path_parts[-1]])
        unsigned = {key: item for key, item in mutated.items() if key != "catalog_sha256"}
        mutated["catalog_sha256"] = contract_hash(unsigned)
        path = tmp_path / f"drift-{number}.json"
        path.write_text(json.dumps(mutated))
        with pytest.raises(ScannerContractError, match="catalog anchor"):
            load_catalog(path)


def test_plan_is_canonical_and_has_no_runtime_arguments():
    observation = ScannerObservation.from_dict({
        "target_id": "web-synth",
        "address": "192.0.2.15",
        "port": 80,
        "service": "http",
        "scheme": "http",
        "cves": [],
    })
    grant = ScannerGrant.from_dict({
        "profile_id": "network.msf_http_version",
        "target_id": "web-synth",
        "endpoints": [{"protocol": "tcp", "address": "192.0.2.15", "port": 80}],
    })
    plan = plan_for("network.msf_http_version", observation, grant=grant)
    assert plan.profile_id == "network.msf_http_version"
    assert plan.mode == "design_only"
    assert plan.approval_required is True
    profile = profile_for(plan.profile_id)
    assert plan.catalog_sha256 == EXPECTED_CATALOG_SHA256
    assert plan.profile_sha256 == contract_hash(profile)
    assert plan.runner_id == profile.runner_id
    assert plan.budget == profile.budget
    assert plan.source == profile.source
    assert plan.effects == profile.effects
    assert validate_plan(plan) is plan
    with pytest.raises(ScannerContractError, match="frozen plan"):
        validate_plan(replace(plan, catalog_sha256="0" * 64))
    with pytest.raises(ScannerContractError, match="arguments"):
        plan_for("network.msf_http_version", observation, grant=grant, arguments={"ForceExploit": True})


@pytest.mark.parametrize("target_id", ["*", "../../scope", "space target", "bad\x00target", "bad\ntarget"])
def test_direct_or_replaced_target_identity_cannot_bypass_canonical_validation(target_id):
    observation = ScannerObservation("web-synth", "192.0.2.15", 80, "http", "http", ())
    grant = ScannerGrant(
        "network.msf_http_version", "web-synth",
        (NetworkEndpoint("tcp", "192.0.2.15", 80),),
    )
    with pytest.raises(ScannerContractError):
        plan_for("network.msf_http_version", replace(observation, target_id=target_id), grant=replace(grant, target_id=target_id))
    plan = plan_for("network.msf_http_version", observation, grant=grant)
    with pytest.raises(ScannerContractError):
        validate_plan(replace(plan, target_id=target_id))


@pytest.mark.parametrize("endpoint", [
    NetworkEndpoint("tcp", "192.0.2.16", 80),
    NetworkEndpoint("udp", "192.0.2.15", 80),
    NetworkEndpoint("tcp", "not-an-ip", 80),
    NetworkEndpoint("tcp", "192.0.2.15", 0),
])
def test_replaced_frozen_endpoint_is_reparsed_before_plan_acceptance(endpoint):
    observation = ScannerObservation("web-synth", "192.0.2.15", 80, "http", "http", ())
    grant = ScannerGrant("network.msf_http_version", "web-synth", (NetworkEndpoint("tcp", "192.0.2.15", 80),))
    plan = plan_for("network.msf_http_version", observation, grant=grant)
    with pytest.raises(ScannerContractError):
        validate_plan(replace(plan, endpoints=(endpoint,)))


def test_nse_plan_requires_both_reviewed_network_endpoints():
    observation = ScannerObservation.from_dict({
        "target_id": "dell-synth-smb", "address": "192.0.2.20", "port": 445,
        "service": "microsoft-ds", "scheme": None, "cves": [],
    })
    incomplete = ScannerGrant.from_dict({
        "profile_id": "network.nse_smb2_time", "target_id": "dell-synth-smb",
        "endpoints": [{"protocol": "tcp", "address": "192.0.2.20", "port": 445}],
    })
    with pytest.raises(ScannerContractError, match="compound"):
        plan_for("network.nse_smb2_time", observation, grant=incomplete)


def test_initial_nse_profiles_reject_ipv6_targets():
    observation = ScannerObservation.from_dict({
        "target_id": "dell-synth-v6", "address": "2001:db8::20", "port": 445,
        "service": "microsoft-ds", "scheme": None, "cves": [],
    })
    grant = ScannerGrant.from_dict({
        "profile_id": "network.nse_smb2_time", "target_id": "dell-synth-v6",
        "endpoints": [
            {"protocol": "tcp", "address": "2001:db8::20", "port": 445},
            {"protocol": "udp", "address": "2001:db8::20", "port": 137},
        ],
    })
    with pytest.raises(ScannerContractError, match="IPv4"):
        plan_for("network.nse_smb2_time", observation, grant=grant)


def test_catalog_source_is_the_single_checked_in_resource():
    assert catalog_path().name == "scanner-profiles-v1.json"
