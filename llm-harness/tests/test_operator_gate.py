"""Operator-only capabilities cannot be reached through model aliases."""
import pytest

from cptc_harness.audit import AuditWriter
from cptc_harness.broker import Broker
from cptc_harness.contracts import Bounds, ClockState, ModuleSpec, OperationRequest, ScopeSpec, TargetPolicy, TargetRef
from cptc_harness.ledger import Ledger
from cptc_harness.network import NetworkBroker
from cptc_harness.registry import build_registry
from test_enforcement_core import policy


@pytest.mark.parametrize("name", ["web.response_capture", "renamed-safe-capture"])
def test_operator_effect_denies_model_before_reservation_or_dispatch(tmp_path, name):
    spec = ModuleSpec(name, "1", "web", "bounded", ("operator_only",), Bounds(request_limit=1),
                      {"type": "object"}, {"type": "object"})
    class Registry:
        def get(self, _): return spec
        def handler(self, _): pytest.fail("must not select a handler")
        def dispatch(self, _): pytest.fail("must not dispatch")
    p = policy()
    ledger = Ledger(tmp_path / "ledger", "eng", "dev")
    audit = AuditWriter(tmp_path / "audit", p)
    try:
        result = Broker(p, Registry(), ledger, audit, clock=ClockState(True, 0)).execute(
            OperationRequest("request", "ws", "dev", "op", name, None, {}, "model", None, "rev"), actor="model")
        assert result.status == "blocked" and "operator request" in result.reason
        assert ledger.usage()["request_limit"] == 0
        assert ledger.usage()["actions"] == 1
        assert audit.verify().valid
    finally:
        audit.close()


def test_model_capture_with_approved_hostname_performs_no_dns_or_grant(tmp_path):
    target = TargetRef("approved", "http://approved.example.test/", "http", "approved.example.test", 80)
    p = policy((TargetPolicy(target, True, "synthetic-profile", "ws", "", ("web.response_capture",)),),
               scope=ScopeSpec(("192.0.2.0/24",), (), ("approved.example.test",)))
    calls = []
    audit = AuditWriter(tmp_path / "audit", p)
    network = NetworkBroker(p, audit=audit, resolver=lambda *a, **kw: calls.append(a) or [])
    try:
        result = Broker(p, build_registry(), Ledger(tmp_path / "ledger", "eng", "dev"), audit,
                        network=network, clock=ClockState(True, 0)).execute(
            OperationRequest("request", "ws", "dev", "op", "web.response_capture", target, {}, "model", None, "rev"), actor="model")
        assert result.status == "blocked" and "operator request" in result.reason
        assert calls == [] and "network_grant" not in audit.path.read_text()
    finally:
        audit.close()
