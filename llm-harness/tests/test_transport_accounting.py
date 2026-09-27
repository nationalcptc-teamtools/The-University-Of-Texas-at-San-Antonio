"""Transport use is durable, distinct, and cannot be erased by retries."""
from __future__ import annotations

from dataclasses import asdict
import time

import pytest

from cptc_harness.contracts import Bounds, PolicyError, RESOURCE_COUNTERS
from cptc_harness.ledger import Ledger
from test_integration import age_identity, private
from test_reporting import reporting_runtime


TRANSPORT_COUNTERS = (
    "tcp_connects",
    "udp_datagrams",
    "protocol_requests",
    "tx_bytes",
    "rx_bytes",
)


def ledger(tmp_path) -> Ledger:
    tmp_path.chmod(0o700)
    return Ledger(tmp_path, "eng", "device", policy_revision="policy-v1")


def transport_bounds(**changes) -> Bounds:
    values = {
        "timeout_s": 15.0,
        "request_limit": 1,
        "output_bytes": 32768,
        "process_limit": 1,
        "tcp_connects": 2,
        "udp_datagrams": 1,
        "protocol_requests": 3,
        "tx_bytes": 4096,
        "rx_bytes": 16384,
    }
    values.update(changes)
    return Bounds(**values)


def reserve(store: Ledger, request_id: str = "action") -> None:
    store.reserve(
        request_id,
        transport_bounds(),
        workspace_id="workspace",
        target_id="tcp://192.0.2.10:445",
        workflow_id="wave",
    )


def test_transport_counters_are_first_class_resources():
    assert set(TRANSPORT_COUNTERS) <= set(RESOURCE_COUNTERS)
    encoded = asdict(transport_bounds())
    assert {key: encoded[key] for key in TRANSPORT_COUNTERS} == {
        "tcp_connects": 2,
        "udp_datagrams": 1,
        "protocol_requests": 3,
        "tx_bytes": 4096,
        "rx_bytes": 16384,
    }


def test_bounds_preserve_the_legacy_positional_constructor_order():
    bounds = Bounds(30.0, 1, 32768, 2, 3, 4, 5)
    assert bounds.timeout_s == 30.0
    assert bounds.request_limit == 1
    assert bounds.output_bytes == 32768
    assert bounds.process_limit == 2
    assert bounds.model_calls == 3
    assert bounds.actions == 4
    assert bounds.auth_posts == 5
    assert all(getattr(bounds, key) == 0 for key in TRANSPORT_COUNTERS)


def test_attempt_events_produce_one_durable_terminal_receipt(tmp_path):
    store = ledger(tmp_path)
    reserve(store)
    store.begin_attempt("action", "attempt-1", started_ns=1_000_000_000, deadline_ns=16_000_000_000)
    assert store.record_attempt_event(
        "action",
        "attempt-1",
        "connect-1",
        tcp_connects=1,
    )
    assert store.record_attempt_event(
        "action",
        "attempt-1",
        "smb-negotiate",
        protocol_requests=1,
        tx_bytes=96,
        rx_bytes=160,
    )
    receipt = store.finish_attempt("action", "attempt-1", state="complete", ended_ns=1_125_000_000)
    assert receipt["state"] == "complete"
    assert receipt["elapsed_ms"] == 125
    assert receipt["deadline_exceeded"] is False
    assert receipt["usage"] == {
        "tcp_connects": 1,
        "udp_datagrams": 0,
        "protocol_requests": 1,
        "tx_bytes": 96,
        "rx_bytes": 160,
    }

    store._db.close()
    reopened = ledger(tmp_path)
    assert reopened.attempt_receipt("action") == {
        "request_id": "action",
        "usage": receipt["usage"],
        "attempts": [receipt],
    }


def test_optional_attempt_receipt_distinguishes_reserved_from_dispatched(tmp_path):
    store = ledger(tmp_path)
    reserve(store)

    assert store.optional_attempt_receipt("action") is None

    store.begin_attempt(
        "action", "attempt-1", started_ns=1_000_000_000, deadline_ns=2_000_000_000
    )
    assert store.optional_attempt_receipt("action") == {
        "request_id": "action",
        "usage": {
            "tcp_connects": 0,
            "udp_datagrams": 0,
            "protocol_requests": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
        },
        "attempts": [
            {
                "attempt_id": "attempt-1",
                "state": "running",
                "started_ns": 1_000_000_000,
                "deadline_ns": 2_000_000_000,
                "elapsed_ms": 0,
                "deadline_exceeded": False,
                "usage": {
                    "tcp_connects": 0,
                    "udp_datagrams": 0,
                    "protocol_requests": 0,
                    "tx_bytes": 0,
                    "rx_bytes": 0,
                },
            }
        ],
    }


def test_exact_duplicate_event_is_idempotent_but_conflict_latches_stop(tmp_path):
    store = ledger(tmp_path)
    reserve(store)
    store.begin_attempt("action", "attempt-1", started_ns=10, deadline_ns=1000)
    values = dict(tcp_connects=1, protocol_requests=0, tx_bytes=0, rx_bytes=0, udp_datagrams=0)
    assert store.record_attempt_event("action", "attempt-1", "event", **values)
    assert store.record_attempt_event("action", "attempt-1", "event", **values) is False
    with pytest.raises(PolicyError, match="event receipt conflict"):
        store.record_attempt_event("action", "attempt-1", "event", **{**values, "tx_bytes": 1})
    assert store.stopped()
    assert store.attempt_receipt("action")["usage"]["tcp_connects"] == 1


@pytest.mark.parametrize("counter", TRANSPORT_COUNTERS)
def test_overrun_is_preserved_and_stops_before_more_work(tmp_path, counter):
    store = ledger(tmp_path)
    bounds = transport_bounds(**{counter: 0})
    store.reserve("action", bounds, workspace_id="workspace", target_id="tcp://192.0.2.10:445")
    store.begin_attempt("action", "attempt-1", started_ns=10, deadline_ns=1000)
    values = {key: 0 for key in TRANSPORT_COUNTERS}
    values[counter] = 1
    with pytest.raises(PolicyError, match="transport allowance exceeded"):
        store.record_attempt_event("action", "attempt-1", "overrun", **values)
    receipt = store.attempt_receipt("action")
    assert receipt["usage"][counter] == 1
    assert receipt["attempts"][0]["state"] == "uncertain"
    assert store.stopped()


def test_attempt_intent_requires_active_exact_reservation(tmp_path):
    store = ledger(tmp_path)
    with pytest.raises(PolicyError, match="active reservation"):
        store.begin_attempt("missing", "attempt", started_ns=1, deadline_ns=2)
    reserve(store)
    store.finish("action", state="blocked")
    with pytest.raises(PolicyError, match="active reservation"):
        store.begin_attempt("action", "attempt", started_ns=1, deadline_ns=2)


def test_recovery_marks_open_attempt_uncertain_and_stops_automatic_work(tmp_path):
    store = ledger(tmp_path)
    reserve(store)
    store.begin_attempt("action", "attempt-1", started_ns=10, deadline_ns=1000)
    store.record_attempt_event("action", "attempt-1", "connect", tcp_connects=1)
    store._db.close()

    reopened = ledger(tmp_path)
    recovered = reopened.recover_attempts()
    assert len(recovered) == 1
    assert recovered[0]["request_id"] == "action"
    assert recovered[0]["attempt_id"] == "attempt-1"
    assert recovered[0]["state"] == "uncertain"
    assert reopened.stopped()
    assert reopened.record_attempt_event(
        "action", "attempt-1", "connect", tcp_connects=1,
    ) is False
    with pytest.raises(PolicyError, match="stopped"):
        reopened.reserve("second", transport_bounds(), workspace_id="workspace")


def test_recovery_reconciles_parent_after_allowance_overrun(tmp_path):
    store = ledger(tmp_path)
    store.reserve(
        "action", transport_bounds(tcp_connects=0), workspace_id="workspace",
        target_id="tcp://192.0.2.10:445",
    )
    store.begin_attempt("action", "attempt-1", started_ns=10, deadline_ns=1000)
    with pytest.raises(PolicyError, match="allowance exceeded"):
        store.record_attempt_event("action", "attempt-1", "connect", tcp_connects=1)
    store._db.close()

    reopened = ledger(tmp_path)
    recovered = reopened.recover_attempts()
    assert recovered and reopened._db.execute(
        "SELECT state FROM reservations WHERE request_id='action'"
    ).fetchone() == ("uncertain",)
    assert reopened.attempt_receipt("action")["usage"]["tcp_connects"] == 1


def test_recovery_marks_parent_uncertain_after_terminal_attempt_checkpoint(tmp_path):
    store = ledger(tmp_path)
    reserve(store)
    store.begin_attempt("action", "attempt-1", started_ns=10, deadline_ns=1000)
    store.record_attempt_event("action", "attempt-1", "connect", tcp_connects=1)
    store.finish_attempt("action", "attempt-1", state="complete", ended_ns=20)
    store._db.close()

    reopened = ledger(tmp_path)
    recovered = reopened.recover_attempts()
    assert recovered and recovered[0]["request_id"] == "action"
    assert reopened._db.execute(
        "SELECT state FROM reservations WHERE request_id='action'"
    ).fetchone() == ("uncertain",)
    assert reopened.attempt_receipt("action")["attempts"][0]["state"] == "complete"
    assert reopened.stopped()


def test_recovery_marks_active_reservation_without_attempt_uncertain(tmp_path):
    store = ledger(tmp_path)
    reserve(store)
    store._db.close()

    reopened = ledger(tmp_path)
    recovered = reopened.recover_attempts()
    assert recovered == ({"request_id": "action", "attempt_id": None, "state": "uncertain"},)
    assert reopened._db.execute(
        "SELECT state FROM reservations WHERE request_id='action'"
    ).fetchone() == ("uncertain",)
    assert reopened.stopped()


def test_deadline_overrun_cannot_be_reported_complete(tmp_path):
    store = ledger(tmp_path)
    reserve(store)
    store.begin_attempt("action", "attempt-1", started_ns=100, deadline_ns=200)
    receipt = store.finish_attempt("action", "attempt-1", state="complete", ended_ns=201)
    assert receipt["state"] == "uncertain"
    assert receipt["deadline_exceeded"] is True
    assert store.stopped()


def test_terminal_attempt_event_replay_is_idempotent_but_conflict_stops(tmp_path):
    store = ledger(tmp_path)
    reserve(store)
    store.begin_attempt("action", "attempt-1", started_ns=10, deadline_ns=1000)
    assert store.record_attempt_event("action", "attempt-1", "connect", tcp_connects=1)
    store.finish_attempt("action", "attempt-1", state="complete", ended_ns=20)
    assert store.record_attempt_event("action", "attempt-1", "connect", tcp_connects=1) is False
    with pytest.raises(PolicyError, match="event receipt conflict"):
        store.record_attempt_event("action", "attempt-1", "connect", tcp_connects=2)
    assert store.stopped()


def test_runtime_reconciles_interrupted_attempt_before_new_work(reporting_runtime):
    from cptc_harness.runtime import Runtime

    runtime = reporting_runtime
    runtime.ledger.reserve(
        "interrupted-transport",
        transport_bounds(),
        workspace_id=runtime.policy.workspace_id,
        workflow_id="interrupted-wave",
    )
    runtime.ledger.begin_attempt(
        "interrupted-transport",
        "attempt-1",
        started_ns=10,
        deadline_ns=1000,
    )
    runtime.audit.close()

    reopened = Runtime(runtime.root, ledger_root=runtime.ledger_root.parent)
    try:
        receipt = reopened.ledger.attempt_receipt("interrupted-transport")
        assert receipt["attempts"][0]["state"] == "uncertain"
        assert reopened.ledger.stopped()
        events = reopened.audit.path.read_text().splitlines()
        assert any('"kind":"transport_attempt_recovery"' in line for line in events)
    finally:
        reopened.audit.close()


class RecordingLedger:
    def __init__(self):
        self.calls = []
        self.is_stopped = False

    def stopped(self):
        return self.is_stopped

    def rate_gate(self, *args):
        self.calls.append(("rate", args))

    def begin_attempt(self, request_id, attempt_id, **timing):
        self.calls.append(("begin", request_id, attempt_id, timing))

    def record_attempt_event(self, request_id, attempt_id, event_id, **usage):
        self.calls.append(("event", request_id, attempt_id, event_id, usage))
        return True

    def finish_attempt(self, request_id, attempt_id, **receipt):
        self.calls.append(("finish", request_id, attempt_id, receipt))
        return receipt

    def stop(self, reason):
        self.is_stopped = True
        self.calls.append(("stop", reason))


def network_policy():
    from cptc_harness.contracts import PolicySnapshot, ScopeSpec, TargetPolicy, TargetRef

    target = TargetRef("web", "http://192.0.2.10/", "http", "192.0.2.10", 80, "/")
    policy = PolicySnapshot(
        "eng",
        "revision",
        "workspace",
        "device",
        "operator",
        ScopeSpec(("192.0.2.0/24",)),
        targets=(TargetPolicy(target, True, "synthetic", "workspace", "", ("web.headers",)),),
    )
    return policy, target


def test_http_transport_records_intent_bytes_response_and_completion(monkeypatch):
    from cptc_harness.contracts import TargetRequest, TargetResponse
    from cptc_harness.network import NetworkBroker

    policy, target = network_policy()
    ledger = RecordingLedger()
    broker = NetworkBroker(policy, ledger=ledger, resolver=lambda *args, **kwargs: [(None, None, None, None, (target.host, 80))])
    broker.action_id = "action"
    monkeypatch.setattr(
        broker,
        "_isolated_http",
        lambda *args, **kwargs: TargetResponse(200, {}, b"synthetic-body", 0.01, target.host, False),
    )

    response = broker.target_transport(target, request_limit=1).request(TargetRequest(max_bytes=1024))
    assert response.body == b"synthetic-body"
    begin = next(call for call in ledger.calls if call[0] == "begin")
    events = [call for call in ledger.calls if call[0] == "event"]
    finish = next(call for call in ledger.calls if call[0] == "finish")
    assert begin[1] == "action" and begin[3]["deadline_ns"] > begin[3]["started_ns"]
    assert events[0][4]["tcp_connects"] == 1
    assert events[0][4]["protocol_requests"] == 1
    assert events[0][4]["tx_bytes"] > 0
    assert events[1][4] == {"rx_bytes": len(b"synthetic-body")}
    assert finish[1:3] == begin[1:3] and finish[3]["state"] == "complete"


def test_http_transport_failure_finishes_uncertain_without_retry(monkeypatch):
    from cptc_harness.contracts import TargetRequest
    from cptc_harness.network import NetworkBroker

    policy, target = network_policy()
    ledger = RecordingLedger()
    broker = NetworkBroker(policy, ledger=ledger, resolver=lambda *args, **kwargs: [(None, None, None, None, (target.host, 80))])
    broker.action_id = "action"
    calls = []
    def fail(*args, **kwargs):
        calls.append(1)
        raise OSError("synthetic failure")
    monkeypatch.setattr(broker, "_isolated_http", fail)

    with pytest.raises(PolicyError, match="target transport failed"):
        broker.target_transport(target, request_limit=1).request(TargetRequest(max_bytes=1024))
    assert len(calls) == 1
    assert not [call for call in ledger.calls if call[0] == "event"]
    assert next(call for call in ledger.calls if call[0] == "finish")[3]["state"] == "uncertain"
    assert ledger.is_stopped


def test_accounting_delay_cannot_start_network_work_after_deadline(monkeypatch):
    from cptc_harness.contracts import TargetRequest
    from cptc_harness.network import NetworkBroker

    policy, target = network_policy()

    class SlowLedger(RecordingLedger):
        def begin_attempt(self, request_id, attempt_id, **timing):
            super().begin_attempt(request_id, attempt_id, **timing)
            time.sleep(0.01)

    ledger = SlowLedger()
    broker = NetworkBroker(
        policy,
        ledger=ledger,
        resolver=lambda *args, **kwargs: [(None, None, None, None, (target.host, 80))],
    )
    broker.action_id = "action"
    calls = []
    monkeypatch.setattr(broker, "_isolated_http", lambda *args, **kwargs: calls.append(1))

    with pytest.raises(PolicyError):
        broker.target_transport(target, timeout_s=0.001, request_limit=1).request(TargetRequest(max_bytes=1024))
    assert calls == []
    assert not [call for call in ledger.calls if call[0] == "event"]
