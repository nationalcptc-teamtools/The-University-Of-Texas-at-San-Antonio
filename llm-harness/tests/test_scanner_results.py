from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from cptc_harness.contracts import PolicyError
from cptc_harness.scanner_catalog_v2 import get_profile_v2
from cptc_harness.scanner_results import (
    Smb2XmlFacts,
    parse_smb2_security_mode_result,
    parse_smb2_xml_facts,
)


FIXTURES = Path(__file__).parent / "fixtures" / "scanner" / "v2"


def _receipt(**changes):
    value = {
        "status": "complete",
        "reason": "complete",
        "tcp_connects": 2,
        "udp_datagrams": 1,
        "protocol_requests": 2,
        "tx_bytes": 256,
        "rx_bytes": 512,
    }
    value.update(changes)
    return value


def _parse(name: str = "signing-required.xml", **changes):
    values = {
        "profile": get_profile_v2("network.nse_smb2_security_mode"),
        "target_ipv4": "192.0.2.20",
        "exit_code": 0,
        "stderr": b"",
        "relay_receipt": _receipt(),
    }
    values.update(changes)
    return parse_smb2_security_mode_result((FIXTURES / name).read_bytes(), **values)


def test_required_signing_is_typed_immutable_and_not_a_candidate():
    result = _parse()
    assert result.profile_id == "network.nse_smb2_security_mode"
    assert result.target_ipv4 == "192.0.2.20"
    assert result.dialect == "3.1.1"
    assert result.signing_enabled is True
    assert result.signing_required is True
    assert result.disposition == "not_observed"
    with pytest.raises(FrozenInstanceError):
        result.signing_required = False


def test_signing_not_required_is_an_observed_candidate_only():
    result = _parse("signing-not-required.xml")
    assert (result.signing_enabled, result.signing_required) == (True, False)
    assert result.disposition == "observed_candidate"
    assert result.confirmed_vulnerability is False


def test_xml_fact_parser_returns_only_observed_protocol_facts():
    facts = parse_smb2_xml_facts(
        (FIXTURES / "signing-not-required.xml").read_bytes(),
        target_ipv4="192.0.2.20",
    )

    assert isinstance(facts, Smb2XmlFacts)
    assert facts.target_ipv4 == "192.0.2.20"
    assert facts.dialect == "3.1.1"
    assert facts.signing_enabled is True
    assert facts.signing_required is False
    assert not hasattr(facts, "confirmed_vulnerability")
    assert not hasattr(facts, "collection_state")


def test_parser_accepts_only_the_exact_inert_nmap_798_preamble():
    fixture = (FIXTURES / "signing-required.xml").read_bytes()
    _declaration, body = fixture.split(b"\n", 1)
    raw = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE nmaprun>\n'
        b'<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>\n'
        b'<!-- Nmap 7.98 scan initiated at a bounded synthetic fixture -->\n'
        + body
    )
    values = {
        "profile": get_profile_v2("network.nse_smb2_security_mode"),
        "target_ipv4": "192.0.2.20",
        "exit_code": 0,
        "stderr": b"",
        "relay_receipt": _receipt(),
    }

    result = parse_smb2_security_mode_result(raw, **values)

    assert result.signing_required is True


@pytest.mark.parametrize("target", ["192.000.2.20", "192.0.2.020", "2001:db8::20", "host.example", "192.0.2.0/24"])
def test_parser_requires_the_exact_canonical_ipv4_target(target):
    with pytest.raises(PolicyError, match="IPv4"):
        _parse(target_ipv4=target)


@pytest.mark.parametrize("name", [
    "contradictory-output.xml",
    "duplicate-dialect.xml",
    "extra-host.xml",
    "extra-port.xml",
    "extra-script.xml",
    "free-text-only.xml",
])
def test_parser_rejects_contradictory_duplicate_or_extra_nmap_content(name):
    with pytest.raises(PolicyError):
        _parse(name)


@pytest.mark.parametrize("name", ["doctype.xml", "entity.xml", "processing-instruction.xml"])
def test_parser_rejects_dtd_entities_and_processing_instructions(name):
    with pytest.raises(PolicyError):
        _parse(name)


def test_parser_rejects_output_stderr_exit_and_receipt_failures():
    profile = get_profile_v2("network.nse_smb2_security_mode")
    with pytest.raises(PolicyError, match="output"):
        parse_smb2_security_mode_result(
            b" " * (profile.output_bytes + 1), profile=profile,
            target_ipv4="192.0.2.20", exit_code=0, stderr=b"", relay_receipt=_receipt(),
        )
    for changes in (
        {"stderr": b"warning"},
        {"exit_code": 1},
        {"relay_receipt": _receipt(status="uncertain")},
        {"relay_receipt": _receipt(rx_bytes=profile.rx_bytes + 1)},
        {"relay_receipt": {**_receipt(), "extra": 1}},
    ):
        with pytest.raises(PolicyError):
            _parse(**changes)
