import hashlib
import http.server
import tempfile
import threading
from datetime import datetime, timedelta, timezone

import pytest

from cptc_harness.audit import AuditWriter
from cptc_harness.broker import Broker
from cptc_harness.contracts import *
from cptc_harness.isolation import IsolatedRunner
from cptc_harness.ledger import Ledger
from cptc_harness.network import NetworkBroker


def policy(targets=(), **extra):
    values = dict(engagement_id="eng", revision="rev", workspace_id="ws", device_id="dev", operator_id="op",
                  scope=ScopeSpec(allowed_cidrs=("127.0.0.0/8", "::1/128"), allowed_hosts=("localhost",)), targets=targets,
                  window_start="2025-01-01T00:00:00Z", window_end="2030-01-01T00:00:00Z",
                  sow_reference="synthetic-sow", roe_reference="synthetic-roe")
    values.update(extra); return PolicySnapshot(**values)


def test_manual_alias_and_untrusted_handler_are_denied():
    spec = ModuleSpec("safe-alias", "1", "web", "manual_only", (), Bounds(), {"type":"object"}, {"type":"object"})
    class R:
        def get(self, _): return spec
        def handler(self, _): return object()
        def dispatch(self, _): raise AssertionError("must not dispatch")
    with tempfile.TemporaryDirectory() as d:
        p = policy(); result = Broker(p, R(), Ledger(d,"eng","dev"), AuditWriter(d,p), clock=ClockState(True,0)).execute(
            OperationRequest("r","ws","dev","op","safe-alias",None,{},"model",None,"rev"), actor="model", handler=lambda _: None)
    assert result.status == "blocked" and "manual" in result.reason


def test_ledger_persists_reservation_and_rejects_conflicts():
    with tempfile.TemporaryDirectory() as d:
        a = Ledger(d,"eng","one",limits={"actions":2}); a.reserve("one",Bounds(actions=1),workspace_id="a",target_id="t",auth_realm="realm")
        a.finish("one")
        b = Ledger(d,"eng","one",limits={"actions":2})
        with pytest.raises(PolicyError): b.reserve("one",Bounds(actions=1),workspace_id="a")
        with pytest.raises(PolicyError): b.assign("other","other-target","realm")
        assert b.usage()["actions"] == 1


def test_reported_request_allowance_includes_other_workflows():
    with tempfile.TemporaryDirectory() as root:
        ledger = Ledger(root, "eng", "dev")
        ledger.reserve("first", Bounds(request_limit=1), workspace_id="ws", target_id="origin", workflow_id="a", limits={"request_limit": 2})
        ledger.finish("first")
        reservation = ledger.reserve("second", Bounds(request_limit=1), workspace_id="ws", target_id="origin", workflow_id="b", limits={"request_limit": 2})
        assert reservation.remaining["request_limit"] == 0
        ledger.finish("second")
        with pytest.raises(PolicyError):
            ledger.reserve("third", Bounds(request_limit=1), workspace_id="ws", target_id="origin", workflow_id="c", limits={"request_limit": 2})


def test_audit_tamper_is_detected_and_sensitive_needs_protection():
    with tempfile.TemporaryDirectory() as d:
        p = policy(); audit = AuditWriter(d,p,clock=ClockState(True,0)); audit.emit(AuditEvent("intent")); assert audit.verify().valid
        with pytest.raises(PolicyError): audit.capture("r","stdout",b"secret","client_confidential")
        (audit.path).write_bytes(audit.path.read_bytes().replace(b"intent",b"other")); assert not audit.verify().valid


def test_dns_scope_and_real_isolated_loopback_http():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *_): pass
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler); threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        port=server.server_port; target=TargetRef("loop",f"http://127.0.0.1:{port}/","http","127.0.0.1",port)
        p=policy((TargetPolicy(target,True,"","ws","",("m",)),)); response=NetworkBroker(p).target_transport(target).request(TargetRequest())
        assert response.body == b"ok"
        with pytest.raises(PolicyError): NetworkBroker(policy((TargetPolicy(target,True,"","ws","",("m",)),),scope=ScopeSpec())).target_transport(target)
    finally: server.shutdown()


def test_bwrap_blocks_workspace_read_and_worker_hash_drift():
    executable="/usr/bin/true"; digest=hashlib.sha256(open(executable,"rb").read()).hexdigest(); spec=WorkerSpec(executable,(),Bounds(timeout_s=3),digest)
    assert IsolatedRunner([spec]).run(spec,b"").status == "complete"
    assert IsolatedRunner([spec]).run(WorkerSpec(executable,(),Bounds(),"0"*64),b"").status == "blocked"


def test_capture_cap_is_explicit_and_clock_unknown_blocks_bounded_work():
    with tempfile.TemporaryDirectory() as d:
        p=policy(); a=AuditWriter(d,p,evidence_cap=3)
        with pytest.raises(PolicyError):
            a.capture("r","stdout",b"abcdef","synthetic")
        assert not a.ready() and any("incomplete_capture" in line for line in a.path.read_text().splitlines())
    target=TargetRef("t","http://localhost:80/","http","localhost",80)
    spec=ModuleSpec("m","1","web","bounded",(),Bounds(),{"type":"object"},{"type":"object"})
    class R:
        def get(self,_): return spec
        def handler(self,_): return self
        def dispatch(self,_): return OperationResult("complete",{})
    with tempfile.TemporaryDirectory() as d:
        p=policy((TargetPolicy(target,True,"reviewed-fixture","ws","",("m",)),)); a=AuditWriter(d,p)
        result=Broker(p,R(),Ledger(d,"eng","dev"),a,clock=ClockState(False,None)).execute(OperationRequest("r","ws","dev","op","m",target,{},"operator",None,"rev"),actor="operator")
        assert result.status == "blocked" and "clock" in result.reason


@pytest.mark.parametrize("missing", ["profile", "sow_reference", "roe_reference"])
def test_eligible_flag_does_not_replace_profile_and_authorization_review(missing):
    from dataclasses import replace
    target = TargetRef("t", "http://localhost:80/", "http", "localhost", 80)
    eligibility = TargetPolicy(target, True, "reviewed-fixture", "ws", "", ("web.headers",))
    p = policy((eligibility,))
    if missing == "profile":
        p = replace(p, targets=(replace(eligibility, profile="unknown"),))
    else:
        p = replace(p, **{missing: "unverified"})
    from cptc_harness.registry import build_registry
    with tempfile.TemporaryDirectory() as root:
        ledger, audit = Ledger(root, "eng", "dev"), AuditWriter(root, p)
        request = OperationRequest("r", "ws", "dev", "op", "web.headers", target, {}, "operator", None, "rev")
        result = Broker(p, build_registry(), ledger, audit, clock=ClockState(True, 0)).execute(request, actor="operator")
        assert result.status == "blocked" and "SOW/ROE" in result.reason
        assert ledger.usage()["request_limit"] == 0
        audit.close()


def test_network_rejects_controls_and_persists_rate_gate():
    target=TargetRef("t","http://localhost:80/","http","localhost",80)
    with tempfile.TemporaryDirectory() as d:
        p=policy((TargetPolicy(target,True,"","ws","",("m",)),)); ledger=Ledger(d,"eng","dev"); net=NetworkBroker(p,ledger=ledger)
        tr=net.target_transport(target)
        with pytest.raises(PolicyError): tr.request(TargetRequest(path="/%2e%2e/x"))
        with pytest.raises(PolicyError): tr.request(TargetRequest(headers={"X":"one\r\ntwo"}))
        ledger.rate_gate("t", 100, 1.0)
        with pytest.raises(PolicyError): Ledger(d,"eng","dev").rate_gate("t",100,2.0)
