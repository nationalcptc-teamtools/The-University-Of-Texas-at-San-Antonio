from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cptc_harness.contracts import (Approval, ExecutionContext, OperationRequest,
                                    PolicyError, PolicySnapshot, ScopeSpec, SourceRef,
                                    TargetPolicy, TargetRef, TargetResponse, ToolOutput)
from cptc_harness.parsers import (aggregate_host_observations, parse_exploit_intake, parse_linux_output, parse_nmap_xml,
                                  parse_reporting_records, parse_web_capture, parse_windows_ad_output)
from cptc_harness.preambles import EXPECTED_RULE_SHA256, build_preamble
from cptc_harness.registry import build_registry
from cptc_harness.skills import compact_context, decision_excerpt, parse_envelope

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE = ScopeSpec(allowed_cidrs=("192.0.2.0/24", "198.51.100.0/24"), allowed_hosts=("web.example.test",))
TARGET = TargetRef("web-1", "https://192.0.2.10/", "https", "192.0.2.10", 443, "/")


def _request(module_id: str, *, source: str = "operator", args=None, approval=None):
    return OperationRequest("req-1", "ws-1", "dev-1", "operator-1", module_id, TARGET,
                            args or {}, source, approval, "rev-1")


def _policy(module_id: str, *, target: TargetRef = TARGET):
    return PolicySnapshot("eng-1", "rev-1", "ws-1", "dev-1", "operator-1", SCOPE,
                          targets=(TargetPolicy(target, True, "synthetic", "ws-1", "realm-1", (module_id,)),))


def _context(module_id: str, *, transport=None, tools=None, input_bytes=b"", source="operator", approval=None, args=None):
    registry = build_registry()
    return ExecutionContext(_request(module_id, source=source, approval=approval, args=args), registry.get(module_id),
                            _policy(module_id), transport=transport, tools=tools, input_bytes=input_bytes,
                            source=SourceRef("fixture", hashlib.sha256(input_bytes).hexdigest()))


def test_nmap_parser_filters_scope_and_preserves_source_hash():
    raw = (FIXTURES / "nmap_vulnerable.xml").read_bytes()
    result = parse_nmap_xml(raw, "fixture-nmap", SCOPE)
    assert len(result.observations) == 1
    assert result.observations[0].facts["ports"][0]["port"] == 443
    assert result.observations[0].source.sha256 == hashlib.sha256(raw).hexdigest()
    hardened = parse_nmap_xml((FIXTURES / "nmap_hardened.xml").read_bytes(), "hard", SCOPE)
    assert hardened.observations[0].facts["ports"][0]["state"] == "filtered"


def test_web_parser_marks_header_and_session_candidates_without_cookie_value():
    result = parse_web_capture((FIXTURES / "web_vulnerable.json").read_bytes(), "web")
    assert {item.check_id for item in result.observations} == {"web_headers", "web_session"}
    assert all("restricted-human-value" not in str(item.facts) for item in result.observations)
    hardened = parse_web_capture((FIXTURES / "web_hardened.json").read_bytes(), "hard")
    assert hardened.observations[0].state == "observed"


def test_malformed_and_manual_intake_remain_visible():
    malformed = parse_web_capture((FIXTURES / "malformed.json").read_bytes(), "bad")
    assert not malformed.observations and malformed.issues
    intake = parse_exploit_intake((FIXTURES / "unsupported.json").read_bytes(), "human")
    assert intake.observations[0].state == "blocked"


def test_reporting_parser_keeps_coverage_retest_and_duplicate_distinctions():
    raw = json.dumps({"records": [
        {"record_type": "coverage", "target": "192.0.2.10", "finding_id": "C-1", "severity": "unknown", "coverage_state": "complete", "evidence_state": "observed"},
        {"record_type": "retest", "target": "192.0.2.10", "finding_id": "F-1", "severity": "high", "retest": "fixed", "evidence_state": "confirmed", "reviewed": True, "evidence_ref": "evidence/f-1"},
        {"target": "192.0.2.10", "finding_id": "F-1", "severity": "high", "retest": "fixed", "evidence_state": "confirmed"},
    ]}).encode()
    result = parse_reporting_records(raw, "report")
    assert result.observations[0].facts["coverage_state"] == "complete"
    assert result.observations[1].state == "retest"
    assert result.observations[2].state == "candidate"
    assert result.observations[2].facts["duplicate"] is True


def test_versioned_host_imports_have_typed_values_and_candidate_only_states():
    vulnerable = parse_linux_output((FIXTURES / "linux_inventory_vulnerable.json").read_bytes(), "linux", SCOPE)
    assert {item.check_id for item in vulnerable.observations} >= {"linux_identity", "linux_permission", "linux_capability"}
    assert vulnerable.observations[0].source.sha256 == hashlib.sha256((FIXTURES / "linux_inventory_vulnerable.json").read_bytes()).hexdigest()
    assert all(item.state in {"observed", "candidate"} for item in vulnerable.observations)
    assert any(item.check_id == "linux_permission" and item.state == "candidate" for item in vulnerable.observations)
    hardened = parse_linux_output((FIXTURES / "linux_inventory_hardened.json").read_bytes(), "linux", SCOPE)
    assert all(item.state == "observed" for item in hardened.observations)
    unsafe = parse_linux_output((FIXTURES / "linux_inventory_unsafe.json").read_bytes(), "linux", SCOPE)
    assert not unsafe.observations and any(item.code == "unsafe_controls" for item in unsafe.issues)


def test_windows_import_and_host_aggregation_preserve_scope_and_dedup():
    scope = ScopeSpec(allowed_cidrs=SCOPE.allowed_cidrs, allowed_hosts=("ad.example.test",))
    result = parse_windows_ad_output((FIXTURES / "windows_inventory.json").read_bytes(), "windows", scope)
    assert {item.check_id for item in result.observations} >= {"windows_identity", "windows_smb_policy", "windows_ldap_policy"}
    unsafe = parse_windows_ad_output((FIXTURES / "windows_inventory_unsafe.json").read_bytes(), "windows", scope)
    assert not unsafe.observations
    source = SourceRef("aggregate", "a" * 64)
    merged = aggregate_host_observations((result, result), source)
    assert len(merged.observations) == len(result.observations)
    assert merged.observations[0].source == source


def test_registry_blocks_manual_scanners_and_unknown_arguments():
    registry = build_registry()
    assert registry.dispatch(_context("exploitation.zerologon")).status == "blocked"
    assert "unsupported containment" in registry.dispatch(_context("web.nuclei")).reason
    blocked = registry.dispatch(_context("web.headers", args={"path": "/admin"}))
    assert blocked.status == "blocked"


class FakeTransport:
    def __init__(self):
        self.requests = []

    def request(self, request):
        self.requests.append(request)
        return TargetResponse(200, {"Strict-Transport-Security": "present", "Set-Cookie": "secret"},
                              b"private raw response", 0.01, session_ref=None)


def test_bounded_web_collects_metadata_and_human_only_capture():
    captured = []
    transport = FakeTransport()
    context = _context("web.headers", transport=transport)
    context = ExecutionContext(**{**context.__dict__, "capture": lambda stream, data, cls: captured.append((stream, data, cls)) or None})
    result = build_registry().dispatch(context)
    assert result.status == "complete"
    assert transport.requests[0].path == "/"
    assert captured == [("response", b"private raw response", "client_confidential_human_only")]
    assert "private raw response" not in json.dumps(result.facts)


class FakeTools:
    def run(self, request):
        assert request.tool_id == "nmap-cptc-inventory-v1"
        assert request.arguments == {"profile": "nmap-cptc-inventory-v1"}
        return ToolOutput(stdout=b'{"target":"192.0.2.10","port":443,"state":"open"}', status="complete", exit_code=0)


def test_contained_tool_uses_fixed_profile_and_parses_typed_output():
    result = build_registry().dispatch(_context("network.nmap_inventory", tools=FakeTools()))
    assert result.status == "complete"
    assert result.facts["observations"][0]["facts"]["port"] == 443


def test_model_bounded_action_requires_operator_approval():
    result = build_registry().dispatch(_context("web.headers", transport=FakeTransport(), source="model"))
    assert result.status == "complete"


def test_skills_are_strict_and_context_is_bounded():
    envelope = parse_envelope('{"action":"action","module_id":"web.headers","args":{}}', allowed_module_ids=("web.headers",))
    assert envelope.action == "action"
    with pytest.raises(PolicyError):
        parse_envelope('{"action":"action","module_id":"web.headers","args":{},"source":"model"}')
    with pytest.raises(PolicyError):
        parse_envelope('{"action":"action","module_id":"web.headers","args":{}} trailing')
    with pytest.raises(PolicyError):
        parse_envelope('{"action":"finish","status":"complete","status":"blocked"}')
    with pytest.raises(PolicyError):
        parse_envelope('{"action":"finish","status":NaN}')
    assert len(compact_context({"z": "x" * 10000})) <= 8192
    assert len(decision_excerpt("x" * 10000)) == 2048


def test_preamble_verifies_full_reference_and_emits_compact_operating_context():
    from cptc_harness.contracts import RuleReference
    reference = RuleReference("2025-10", EXPECTED_RULE_SHA256, str(FIXTURES.parent.parent / "docs" / "harness" / "CPTC-RULES-2025-10.txt"), ())
    preamble = build_preamble(_policy("web.headers"), reference, build_registry().specs())
    assert preamble.rule_sha256 == EXPECTED_RULE_SHA256
    assert preamble.policy_revision == "rev-1"
    assert "Official Competition Rules" in preamble.text
    assert len(preamble.text.encode()) < 6500
    assert "zero client-data allowance" in preamble.text
    assert "two weeks" in preamble.text and "one week" in preamble.text
