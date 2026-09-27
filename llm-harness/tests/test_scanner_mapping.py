from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json

import pytest

from cptc_harness.scanner_catalog import validate_plan
from cptc_harness.scanner_contracts import ScannerContractError, ScannerGrant, ScannerObservation
from cptc_harness.scanner_mapping import (
    MANUAL_MS17_010,
    MANUAL_UNMAPPED_CVE,
    ProfileSelection,
    map_observations,
)


FIXTURES = Path(__file__).parent / "fixtures" / "scanner"


def _observations(name: str):
    rows = json.loads((FIXTURES / name).read_text())
    return tuple(ScannerObservation.from_dict(row) for row in rows)


def _grants():
    rows = json.loads((FIXTURES / "grants.json").read_text())
    return tuple(ScannerGrant.from_dict(row) for row in rows)


def _selections():
    return (ProfileSelection.from_dict({
        "profile_id": "network.msf_http_version",
        "target_id": "web-synth",
    }),)


def test_mapping_is_deterministic_and_maps_only_exact_profiles():
    first = map_observations(_observations("observations.json"), _grants(), selections=_selections())
    second = map_observations(
        tuple(reversed(_observations("observations.json"))),
        tuple(reversed(_grants())),
        selections=tuple(reversed(_selections())),
    )
    assert first == second
    assert [item.profile_id for item in first] == [
        "network.nse_smb2_security_mode",
        "network.nse_smb2_time",
        "network.msf_http_version",
    ]
    assert [item.status for item in first] == [
        "synthetic_only", "synthetic_only", "design_only",
    ]
    assert all(item.plan is not None and item.plan.mode == item.status for item in first)
    assert all(validate_plan(item.plan) is item.plan for item in first if item.plan is not None)


def test_metasploit_design_candidate_requires_exact_operator_selection():
    decisions = map_observations(_observations("observations.json"), _grants())
    assert "network.msf_http_version" not in {item.profile_id for item in decisions}
    with pytest.raises(ScannerContractError, match="selection"):
        map_observations(
            _observations("observations.json"), _grants(),
            selections=(ProfileSelection("network.msf_http_version", "missing-target"),),
        )
    for row in (
        {"profile_id": "network.nse_smb2_time", "target_id": "dell-synth-smb"},
        {"profile_id": "network.msf_*", "target_id": "web-synth"},
        {"profile_id": "network.msf_http_version", "target_id": "../web"},
    ):
        with pytest.raises(ScannerContractError):
            ProfileSelection.from_dict(row)


def test_ms17_010_is_a_manual_candidate_without_an_execution_plan():
    decisions = map_observations(_observations("observation_ms17_candidate.json"), _grants())
    assert [item.profile_id for item in decisions] == [
        "network.nse_smb2_security_mode", "network.nse_smb2_time", MANUAL_MS17_010,
    ]
    item = decisions[-1]
    assert item.profile_id == MANUAL_MS17_010
    assert item.status == "manual_only"
    assert item.plan is None
    assert "auxiliary/scanner/smb/smb_ms17_010" in item.reason
    assert item.manual_card is not None
    assert item.manual_card.card_id == MANUAL_MS17_010
    assert item.manual_card.prerequisites
    assert item.manual_card.evidence_requirements
    assert "incomplete" in item.manual_card.result_states
    assert item.manual_card.retest_requirements


def test_unknown_cve_and_unrecognized_services_are_not_silently_mapped():
    decisions = map_observations(_observations("observation_unknown_cve.json"), _grants())
    assert decisions[-1].profile_id == MANUAL_UNMAPPED_CVE
    assert decisions[-1].status == "manual_only"
    assert decisions[-1].plan is None
    assert decisions[-1].manual_card is not None
    assert decisions[-1].manual_card.card_id == MANUAL_UNMAPPED_CVE
    assert map_observations((ScannerObservation.from_dict({
        "target_id": "other",
        "address": "192.0.2.30",
        "port": 22,
        "service": "ssh",
        "scheme": None,
        "cves": [],
    }),), _grants()) == ()


def test_multiple_services_for_one_target_are_deterministic_and_address_conflicts_fail():
    smb = ScannerObservation.from_dict({
        "target_id": "shared", "address": "192.0.2.20", "port": 445,
        "service": "smb", "scheme": None, "cves": [],
    })
    http = ScannerObservation.from_dict({
        "target_id": "shared", "address": "192.0.2.20", "port": 80,
        "service": "http", "scheme": "http", "cves": [],
    })
    assert map_observations((smb, http)) == map_observations((http, smb))
    conflicting = ScannerObservation.from_dict({
        "target_id": "shared", "address": "192.0.2.21", "port": 22,
        "service": "ssh", "scheme": None, "cves": [],
    })
    with pytest.raises(ScannerContractError, match="conflicting target address"):
        map_observations((smb, conflicting))


def test_port_139_ms17_marker_remains_manual_only():
    observation = ScannerObservation.from_dict({
        "target_id": "legacy-smb", "address": "192.0.2.25", "port": 139,
        "service": "netbios-ssn", "scheme": None, "cves": ["CVE-2017-0144"],
    })
    decisions = map_observations((observation,))
    assert len(decisions) == 1
    assert decisions[0].profile_id == MANUAL_MS17_010
    assert decisions[0].status == "manual_only"


def test_unknown_grant_profile_is_rejected_before_mapping():
    with pytest.raises(ScannerContractError, match="profile"):
        map_observations(_observations("observations.json"), _grants() + (ScannerGrant.from_dict({
            "profile_id": "network.nse_*", "target_id": "dell-synth-smb",
            "endpoints": [{"protocol": "tcp", "address": "192.0.2.20", "port": 445}],
        }),))


def test_mapping_revalidates_directly_constructed_observations_and_grants():
    observation = _observations("observations.json")[0]
    grant = _grants()[0]
    for unsafe in (
        replace(observation, target_id="../target"),
        replace(observation, service="SMB"),
        replace(observation, address="192.0.2.020"),
    ):
        with pytest.raises(ScannerContractError, match="canonical|invalid|numeric"):
            map_observations((unsafe,), (grant,))
    with pytest.raises(ScannerContractError, match="canonical|invalid"):
        map_observations((observation,), (replace(grant, target_id="../target"),))


def test_mapper_rejects_noncanonical_ipv6_before_emitting_a_plan():
    observation = ScannerObservation("web-v6", "2001:0db8::1", 80, "http", "http", ())
    grant = ScannerGrant.from_dict({
        "profile_id": "network.msf_http_version",
        "target_id": "web-v6",
        "endpoints": [{"protocol": "tcp", "address": "2001:db8::1", "port": 80}],
    })
    selection = ProfileSelection.from_dict({
        "profile_id": "network.msf_http_version", "target_id": "web-v6",
    })
    with pytest.raises(ScannerContractError, match="canonical"):
        map_observations((observation,), (grant,), selections=(selection,))
