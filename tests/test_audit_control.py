from pathlib import Path
import json

import pytest

from cptc_harness.audit_control import reconcile_stop_intents, _request_stop as request_stop, required_emit, required_release
from cptc_harness.contracts import AuditEvent, PolicyError, PolicySnapshot, ScopeSpec

POLICY = PolicySnapshot("engagement", "v1", "workspace", "device", "operator", ScopeSpec())
from cptc_harness.ledger import Ledger


class Audit:
    def __init__(self, fail=False): self.events, self.fail = [], fail
    def emit(self, event):
        if self.fail: raise OSError("synthetic audit failure")
        self.events.append(event); return {"seq": len(self.events)}
    def release_output(self, _):
        if self.fail: raise OSError("synthetic audit failure")
    def control_receipts(self):
        return {event.action_id: event.data for event in self.events if event.kind == "operator_stop"}


def _ledger(tmp_path):
    tmp_path.mkdir(exist_ok=True)
    tmp_path.chmod(0o700)
    return Ledger(tmp_path, "engagement", "device", policy_revision="v1")


def test_stop_sentinel_precedes_sqlite_and_reconciles_once(tmp_path):
    ledger = _ledger(tmp_path)
    receipt = request_stop(tmp_path, "engagement", "device", "operator", interface="cli")
    assert receipt["status"] == "uncertain" and ledger.stopped()
    pending = next((tmp_path / "control").glob("*.json"))
    saved = json.loads(pending.read_text())
    assert saved["reason"] == "operator_request" and saved["interface"] == "cli"
    audit = Audit()
    reconciled = reconcile_stop_intents(ledger, audit, policy=POLICY)
    assert reconciled[0]["correlation_id"] == receipt["correlation_id"] and len(audit.events) == 1
    ledger._db.close()  # simulate a clean central-writer restart
    reopened = Ledger(tmp_path, "engagement", "device", policy_revision="v1")
    assert reconcile_stop_intents(reopened, audit, policy=POLICY) == () and len(audit.events) == 1


def test_stop_survives_dead_sqlite_writer_and_audit_failure(tmp_path):
    ledger = _ledger(tmp_path)
    class DeadLedger:
        def stop(self, _): raise OSError("writer unavailable")
    result = request_stop(tmp_path, "engagement", "device", "operator", interface="human", ledger=DeadLedger())
    assert result["status"] == "uncertain" and ledger.stopped()
    with pytest.raises(PolicyError, match="reconciliation"):
        reconcile_stop_intents(ledger, Audit(fail=True), policy=POLICY)
    assert list((tmp_path / "control").glob("*.json"))


def test_full_or_unavailable_queue_does_not_block_stop_sentinel(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    control = tmp_path / "control"; control.mkdir(mode=0o700)
    for index in range(128):
        (control / (f"q{index}.json")).write_text("{}")
        (control / (f"q{index}.json")).chmod(0o600)
    result = request_stop(tmp_path, "engagement", "device", "operator", interface="cli", ledger=ledger)
    assert result["status"] == "uncertain" and ledger.stopped() and (tmp_path / "operator-stop.json").exists()
    other = tmp_path / "disk-failure"; other.mkdir(); other.chmod(0o700)
    import cptc_harness.audit_control as control_module
    monkeypatch.setattr(control_module, "_control_dirs", lambda _root: (_ for _ in ()).throw(OSError("synthetic disk failure")))
    result = request_stop(other, "engagement", "device", "operator", interface="cli")
    assert result["status"] == "uncertain" and (other / "operator-stop.json").exists()


def test_required_audit_helpers_latch_stop_on_failure(tmp_path):
    ledger = _ledger(tmp_path)
    with pytest.raises(PolicyError): required_emit(Audit(fail=True), ledger, AuditEvent("synthetic"))
    assert ledger.stopped()
    ledger = _ledger(tmp_path / "second")
    with pytest.raises(PolicyError): required_release(Audit(fail=True), ledger, "request")
    assert ledger.stopped()


def test_reason_codes_and_source_semantics_are_strict(tmp_path):
    ledger = _ledger(tmp_path)
    with pytest.raises(PolicyError):
        request_stop(tmp_path, "engagement", "device", "operator", interface="cli", reason="free form")
    with pytest.raises(PolicyError):
        request_stop(tmp_path, "engagement", "device", "operator", interface="cli", source="model")
    receipt = request_stop(tmp_path, "engagement", "device", "operator", interface="human", reason="suspected_lockout", ledger=ledger)
    assert receipt["reason"] == "suspected_lockout"
    saved = json.loads(next((tmp_path / "control").glob("*.json")).read_text())
    assert saved["reason"] == "suspected_lockout" and saved["source"] == "operator"
    with pytest.raises(PolicyError):
        request_stop(tmp_path, "engagement", "device", "operator", interface="human", reason="operator_request", correlation_id=receipt["correlation_id"])


@pytest.mark.parametrize("changed", [
    {"actor": "another-operator"}, {"source": "operator", "interface": "mcp"},
    {"source": "system", "actor": "system", "interface": "human"},
    {"received_at": "future"}, {"received_at": "2026-01-01T00:00:00.000000+00:00"},
    {"received_at": "2026-02-30T00:00:00.000000Z"},
    {"received_at": "2099-01-01T00:00:00.000000Z"}, {"version": True},
])
def test_restart_rejects_spoofed_control_metadata(tmp_path, changed):
    ledger = _ledger(tmp_path)
    request_stop(tmp_path, "engagement", "device", "operator", interface="human")
    sentinel = tmp_path / "operator-stop.json"
    value = json.loads(sentinel.read_text()); value.update(changed)
    sentinel.write_text(json.dumps(value))
    audit = Audit()
    with pytest.raises(PolicyError): reconcile_stop_intents(ledger, audit, policy=POLICY)
    assert ledger.stopped() and not audit.events


def test_sentinel_only_stop_event_reconciles_after_full_queue(tmp_path, monkeypatch):
    import cptc_harness.audit_control as control_module
    ledger = _ledger(tmp_path)
    monkeypatch.setattr(control_module, "_MAX_PENDING", 0)
    request_stop(tmp_path, "engagement", "device", "operator", interface="cli")
    assert not list((tmp_path / "control").glob("*.json"))
    audit = Audit()
    assert len(reconcile_stop_intents(ledger, audit, policy=POLICY)) == 1
    assert reconcile_stop_intents(ledger, audit, policy=POLICY) == ()
    assert len(audit.events) == 1 and ledger.stopped()


def test_internal_audit_failure_has_distinct_source_and_reconciles(tmp_path):
    ledger = _ledger(tmp_path)
    with pytest.raises(PolicyError): required_emit(Audit(fail=True), ledger, AuditEvent("fixture"))
    audit = Audit()
    reconcile_stop_intents(ledger, audit, policy=POLICY)
    assert audit.events[0].data["source"] == "system"
    assert audit.events[0].data["interface"] == "internal"


def test_internal_audit_failure_survives_dead_sqlite(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    monkeypatch.setattr(ledger, "stop", lambda _: (_ for _ in ()).throw(OSError("unavailable")))
    with pytest.raises(PolicyError, match="durable audit"):
        required_emit(Audit(fail=True), ledger, AuditEvent("fixture"))
    assert ledger.stopped()
    audit = Audit()
    assert len(reconcile_stop_intents(ledger, audit, policy=POLICY)) == 1
    assert audit.events[0].data["source"] == "system"


@pytest.mark.parametrize("acknowledgement", ["file", "sqlite"])
def test_acknowledgement_cannot_replace_verified_audit_event(tmp_path, acknowledgement):
    ledger = _ledger(tmp_path)
    request_stop(tmp_path, "engagement", "device", "operator", interface="human")
    sentinel = tmp_path / "operator-stop.json"
    value = json.loads(sentinel.read_text())
    if acknowledgement == "file":
        marker = tmp_path / "control/reconciled/operator-stop.json"
        marker.write_bytes(sentinel.read_bytes()); marker.chmod(0o600)
    else:
        ledger.record_control_reconciled(value["correlation_id"], value["received_at"], value["received_monotonic_ns"])
    audit = Audit()
    with pytest.raises(PolicyError, match="no verified audit receipt"):
        reconcile_stop_intents(ledger, audit, policy=POLICY)
    assert sentinel.exists() and ledger.stopped() and not audit.events
    assert list((tmp_path / "control").glob("*.json"))
