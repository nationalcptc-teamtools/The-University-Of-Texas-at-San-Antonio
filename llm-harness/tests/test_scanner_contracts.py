from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
import json

import pytest

from cptc_harness.scanner_contracts import (
    ScannerContractError,
    ScannerObservation,
    TrafficBudget,
    canonical_json,
)


FIXTURES = Path(__file__).parent / "fixtures" / "scanner"


def _profile_row() -> dict:
    return json.loads((FIXTURES / "profile-row.json").read_text())


def test_profile_contracts_are_immutable_and_reject_extra_fields():
    from cptc_harness.scanner_contracts import ScannerProfile

    profile = ScannerProfile.from_dict(_profile_row())
    with pytest.raises(FrozenInstanceError):
        profile.profile_id = "network.nse_*"
    invalid = {**_profile_row(), "runtime": "msfconsole"}
    with pytest.raises(ScannerContractError, match="unknown or missing"):
        ScannerProfile.from_dict(invalid)
    for bad in (
        {**_profile_row(), "upstream_id": "msfconsole"},
        {**_profile_row(), "effects": ["payload"]},
        {**_profile_row(), "mode": "synthetic_only"},
    ):
        with pytest.raises(ScannerContractError, match=r"runtime|forbidden|profile"):
            ScannerProfile.from_dict(bad)


def test_budget_contract_rejects_negative_values_and_unknown_fields():
    with pytest.raises(ScannerContractError):
        TrafficBudget.from_dict({
            "tcp_connects": -1,
            "udp_datagrams": 0,
            "protocol_requests": 1,
            "tx_bytes": 1,
            "rx_bytes": 1,
            "timeout_s": 1.0,
            "cpu_s": 1.0,
            "output_bytes": 1,
            "process_limit": 1,
            "auth_attempts": 0,
        })
    with pytest.raises(ScannerContractError, match="unknown or missing"):
        TrafficBudget.from_dict({
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "protocol_requests": 1,
            "tx_bytes": 1,
            "rx_bytes": 1,
            "timeout_s": 1.0,
            "cpu_s": 1.0,
            "output_bytes": 1,
            "process_limit": 1,
            "auth_attempts": 0,
            "retries": 0,
        })


def test_observation_rejects_paths_wildcards_malformed_cves_and_compound_grants():
    raw = json.loads((FIXTURES / "observation_smb.json").read_text())
    observation = ScannerObservation.from_dict(raw)
    assert observation.target_id == "dell-synth-smb"
    assert canonical_json(observation) == canonical_json(ScannerObservation.from_dict(raw))
    for key, value in (("target_id", "*"), ("address", "127.0.0.1/24"), ("service", "smb2-security-mode.nse")):
        with pytest.raises(ScannerContractError):
            ScannerObservation.from_dict({**raw, key: value})
    assert ScannerObservation.from_dict({**raw, "cves": ["CVE-2099-9999"]}).cves == ("CVE-2099-9999",)
    for cves in (["not-a-cve"], ["cve-2026-1234"], ["CVE-2026-1234", "CVE-2026-1234"]):
        with pytest.raises(ScannerContractError, match="CVE"):
            ScannerObservation.from_dict({**raw, "cves": cves})
    with pytest.raises(ScannerContractError, match="compound"):
        ScannerObservation.from_dict({**raw, "grant": [{"target_id": raw["target_id"]}]})


def test_observation_and_endpoint_reject_noncanonical_ip_text():
    from cptc_harness.scanner_contracts import NetworkEndpoint

    raw = json.loads((FIXTURES / "observation_smb.json").read_text())
    with pytest.raises(ScannerContractError, match="canonical"):
        ScannerObservation.from_dict({**raw, "address": "2001:0db8::1"})
    with pytest.raises(ScannerContractError, match="canonical"):
        NetworkEndpoint.from_dict({"protocol": "tcp", "address": "2001:0db8::1", "port": 445})
