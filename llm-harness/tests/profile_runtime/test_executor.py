from __future__ import annotations

from collections import deque
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import hashlib
import os
import time

import pytest

import cptc_harness.contracts as contracts
from cptc_harness.contracts import Bounds, EvidenceRef, PolicyError
from cptc_harness.audit import AuditWriter
from cptc_harness.contracts import PolicySnapshot, ScopeSpec
from cptc_harness.ledger import Ledger
from cptc_harness.profile_runtime.catalog import load_profile
from cptc_harness.memfd import MFD_ALLOW_SEALING, MFD_CLOEXEC, memfd_create, seal_readonly, write_all
from cptc_harness.profile_runtime.broker_ipc import BrokerWireResult, DispatchNonce
from cptc_harness.profile_runtime.contracts import WireCounters
from cptc_harness.profile_runtime.worker import WireExecutionError, capture_cleartext_http11


PROFILE_ID = "web.http_jellyfin_public_identity"
RUNTIME_SHA256 = load_profile(PROFILE_ID).runtime_pinset_sha256
WORKER_SHA256 = "4" * 64
BODY = b'{"ProductName":"Jellyfin Server","Version":"10.10.7"}'
RAW_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Encoding: identity\r\n"
    + f"Content-Length: {len(BODY)}\r\n".encode("ascii")
    + b"Connection: close\r\n\r\n"
    + BODY
)


def bounds() -> Bounds:
    return Bounds(
        timeout_s=10.0,
        request_limit=1,
        output_bytes=16384,
        process_limit=1,
        tcp_connects=1,
        udp_datagrams=0,
        protocol_requests=1,
        tx_bytes=256,
        rx_bytes=8192,
    )


def ledger(tmp_path) -> Ledger:
    root = tmp_path / "ledger"
    root.mkdir(parents=True)
    root.chmod(0o700)
    return Ledger(root, "engagement", "device", policy_revision="revision")


def action(action_id: str = "portcast-action") -> contracts.ProfileAction:
    return contracts._issue_profile_action(
        action_id=action_id,
        wave_id="wave-one",
        workspace_id="workspace",
        target_id="cptc11-prod-portcast",
        profile_id=PROFILE_ID,
        runtime_pinset_sha256=RUNTIME_SHA256,
        bounds=bounds(),
        limits=(("request_limit", 1),),
        budget_limits=(),
    )


class Channel:
    def __init__(self, responses, *, send_limit=11, send_failure=False):
        self.responses = deque(responses)
        self.send_limit = send_limit
        self.send_failure = send_failure
        self.sent = bytearray()
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def send(self, value):
        if self.send_failure:
            raise OSError("synthetic send failure")
        count = min(len(value), self.send_limit)
        self.sent.extend(value[:count])
        return count

    def recv(self, maximum):
        if not self.responses:
            return b""
        value = self.responses.popleft()
        if len(value) <= maximum:
            return value
        self.responses.appendleft(value[maximum:])
        return value[:maximum]

    def close(self):
        self.closed = True


def capture_ref(raw: bytes, evidence_id: str = "artifact-one") -> EvidenceRef:
    return EvidenceRef(
        evidence_id,
        None,
        "raw",
        "client_confidential_human_only",
        f"evidence/{evidence_id}.age",
        hashlib.sha256(raw).hexdigest(),
        len(raw),
    )


class Provider:
    runtime_pinset_sha256 = RUNTIME_SHA256

    def __init__(self, channel):
        self.channel = channel
        self.opens = 0

    def open_portcast_channel(self):
        self.opens += 1
        return self.channel


class _Metered:
    def __init__(self, channel, record):
        self.channel = channel
        self.record = record
        self.send_index = 0
        self.recv_index = 0
        self.requested = False
        self.first_byte_at = None

    def settimeout(self, value):
        self.channel.settimeout(value)

    def send(self, value):
        count = self.channel.send(value)
        self.send_index += 1
        fields = {"tx_bytes": count}
        if not self.requested:
            fields["protocol_requests"] = 1
            self.requested = True
        from cptc_harness.profile_runtime.broker_ipc import BrokerWireEvent
        self.record(BrokerWireEvent(f"send-{self.send_index:06d}", 0, 0, fields.get("protocol_requests", 0), count, 0, None))
        return count

    def recv(self, maximum):
        value = self.channel.recv(maximum)
        if value:
            self.recv_index += 1
            if self.first_byte_at is None:
                self.first_byte_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            from cptc_harness.profile_runtime.broker_ipc import BrokerWireEvent
            self.record(BrokerWireEvent(f"recv-{self.recv_index:06d}", 0, 0, 0, 0, len(value), self.first_byte_at))
        return value

    def close(self):
        self.channel.close()


class SyntheticBroker:
    expected_worker_sha256 = WORKER_SHA256

    def __init__(self, provider):
        self.provider = provider

    def bind_reserved_attempt(self, _binding):
        return DispatchNonce(b"n" * 32, 2**63 - 1)

    def execute_once(self, _nonce, record, stopped):
        channel = _Metered(self.provider.open_portcast_channel(), record)
        from cptc_harness.profile_runtime.broker_ipc import BrokerWireEvent
        record(BrokerWireEvent("connect-000000", 1, 0, 0, 0, 0, None))
        raw = b""
        limitation = None
        outcome = "complete"
        try:
            wire = capture_cleartext_http11(load_profile(PROFILE_ID), channel, stopped=stopped)
            raw = wire.raw_response
            counters = wire.counters
        except WireExecutionError as error:
            raw = error.raw_response
            counters = error.counters
            outcome = error.outcome
            limitation = error.limitation
        descriptor = memfd_create("executor-test", MFD_CLOEXEC | MFD_ALLOW_SEALING)
        write_all(descriptor, raw)
        os.lseek(descriptor, 0, os.SEEK_SET)
        seal_readonly(descriptor)
        return BrokerWireResult(
            outcome,
            limitation,
            counters,
            descriptor,
            len(raw),
            hashlib.sha256(raw).hexdigest(),
            channel.first_byte_at,
            WORKER_SHA256,
        )


class StagedFailureBroker:
    expected_worker_sha256 = WORKER_SHA256

    def bind_reserved_attempt(self, _binding):
        return DispatchNonce(b"f" * 32, 2**63 - 1)

    def execute_once(self, _nonce, _record, _stopped):
        descriptor = memfd_create(
            "executor-staged-failure", MFD_CLOEXEC | MFD_ALLOW_SEALING
        )
        seal_readonly(descriptor)
        return BrokerWireResult(
            "uncertain",
            "transport_interrupted",
            WireCounters(0, 0, 0, 0, 0, 0, 0),
            descriptor,
            0,
            hashlib.sha256(b"").hexdigest(),
            None,
            WORKER_SHA256,
            "target_open",
        )


def capability(provider: Provider):
    return SyntheticBroker(provider)


def dispatch_profile(*args):
    from cptc_harness.profile_runtime.executor import dispatch_profile as dispatch

    action_value, provider, store, capture, stopped = args
    return dispatch(
        action_value,
        provider,
        store,
        capture,
        lambda _receipt: None,
        stopped,
    )


def test_frozen_profile_action_contract_is_present_before_wire_dispatch():
    assert hasattr(contracts, "ProfileAction")
    assert hasattr(contracts, "_issue_profile_action")


def test_dispatch_records_each_actual_fragment_and_captures_raw_before_return(tmp_path):
    store = ledger(tmp_path)
    channel = Channel([RAW_RESPONSE[:17], RAW_RESPONSE[17:73], RAW_RESPONSE[73:], b""])
    provider = Provider(channel)
    captured = []

    def capture(raw):
        captured.append(raw)
        return capture_ref(raw)

    receipt = dispatch_profile(action(), capability(provider), store, capture, lambda: False)

    assert provider.opens == 1
    assert channel.closed is True
    assert bytes(channel.sent) == (
        b"GET /System/Info/Public HTTP/1.1\r\n"
        b"Accept: application/json\r\n"
        b"Connection: close\r\n"
        b"Host: 10.0.1.30:8096\r\n\r\n"
    )
    assert captured == [RAW_RESPONSE]
    assert receipt.outcome == "complete"
    assert receipt.evidence_bytes == len(RAW_RESPONSE)
    assert receipt.encrypted_artifact_id == "artifact-one"
    assert receipt.counters.tx_bytes == len(channel.sent)
    assert receipt.counters.rx_bytes == len(RAW_RESPONSE)
    attempt = store.attempt_receipt("portcast-action")
    assert attempt["attempts"][0]["state"] == "complete"
    assert attempt["usage"] == {
        "tcp_connects": 1,
        "udp_datagrams": 0,
        "protocol_requests": 1,
        "tx_bytes": len(channel.sent),
        "rx_bytes": len(RAW_RESPONSE),
    }
    event_rows = store._db.execute(
        "SELECT event_id,request_bytes,response_bytes FROM reservation_attempt_events "
        "WHERE request_id=? ORDER BY rowid",
        ("portcast-action",),
    ).fetchall()
    assert event_rows[0] == ("connect-000000", 0, 0)
    assert sum(row[1] for row in event_rows) == len(channel.sent)
    assert sum(row[2] for row in event_rows) == len(RAW_RESPONSE)


def test_stop_after_durable_reservation_never_opens_channel(tmp_path):
    store = ledger(tmp_path)
    provider = Provider(Channel([RAW_RESPONSE, b""]))
    receipt = dispatch_profile(action(), capability(provider), store, capture_ref, lambda: True)
    assert receipt.outcome == "cancelled"
    assert receipt.limitations == ("stop_latched",)
    assert provider.opens == 0
    assert store.attempt_receipt("portcast-action")["attempts"][0]["state"] == "stopped"
    assert store._db.execute(
        "SELECT state FROM reservations WHERE request_id=?", ("portcast-action",)
    ).fetchone() == ("stopped",)


def test_fixed_worker_failure_stage_is_audited_after_the_wire_receipt(tmp_path):
    from cptc_harness.profile_runtime.executor import dispatch_profile as dispatch

    store = ledger(tmp_path)
    calls = []
    receipt = dispatch(
        action(),
        StagedFailureBroker(),
        store,
        capture_ref,
        lambda value: calls.append(("receipt", value.schema_version)),
        lambda: False,
        failure_stage_sink=lambda stage: calls.append(("stage", stage)),
    )

    assert receipt.schema_version == 1
    assert receipt.outcome == "uncertain"
    assert receipt.limitations == ("transport_interrupted",)
    assert calls == [("receipt", 1), ("stage", "target_open")]
    assert store.attempt_receipt("portcast-action")["attempts"][0]["state"] == "uncertain"


def test_failure_stage_audit_error_latches_stop_and_exposes_no_worker_text(tmp_path):
    from cptc_harness.profile_runtime.executor import dispatch_profile as dispatch

    store = ledger(tmp_path)

    def fail_stage(_stage):
        raise OSError("attacker supplied token=secret")

    with pytest.raises(PolicyError, match="failure stage") as raised:
        dispatch(
            action(),
            StagedFailureBroker(),
            store,
            capture_ref,
            lambda _receipt: None,
            lambda: False,
            failure_stage_sink=fail_stage,
        )
    assert "token" not in str(raised.value)
    assert store.stopped() is True


def test_empty_response_is_uncertain_and_never_claimed_parseable(tmp_path):
    store = ledger(tmp_path)
    provider = Provider(Channel([b""]))
    receipt = dispatch_profile(
        action(), capability(provider), store, capture_ref, lambda: False
    )
    assert receipt.outcome == "uncertain"
    assert receipt.limitations == ("unexpected_response",)
    assert receipt.first_byte_at is None
    assert receipt.is_parseable is False
    assert store.stopped() is True


@pytest.mark.parametrize(
    ("channel", "capture"),
    (
        (Channel([], send_failure=True), capture_ref),
        (Channel([RAW_RESPONSE, b""]), lambda _raw: (_ for _ in ()).throw(OSError("capture failed"))),
    ),
)
def test_any_post_attempt_transport_or_capture_uncertainty_finishes_and_latches_stop(
    tmp_path, channel, capture
):
    store = ledger(tmp_path)
    receipt = dispatch_profile(
        action(), capability(Provider(channel)), store, capture, lambda: False
    )
    assert receipt.outcome == "uncertain"
    assert receipt.limitations[0] in {"transport_interrupted", "audit_failure"}
    assert store.stopped() is True
    assert store.attempt_receipt("portcast-action")["attempts"][0]["state"] == "uncertain"
    assert store._db.execute(
        "SELECT state FROM reservations WHERE request_id=?", ("portcast-action",)
    ).fetchone() == ("uncertain",)


def test_accounting_conflict_closes_channel_and_reconciles_after_stop(tmp_path):
    store = ledger(tmp_path)
    channel = Channel([RAW_RESPONSE, b""])
    original = store.record_attempt_event
    tripped = False

    def conflicting(request_id, attempt_id, event_id, **values):
        nonlocal tripped
        if event_id.startswith("send-") and not tripped:
            tripped = True
            created = original(request_id, attempt_id, event_id, **values)
            changed = dict(values)
            changed["tx_bytes"] += 1
            original(request_id, attempt_id, event_id, **changed)
            return created
        return original(request_id, attempt_id, event_id, **values)

    store.record_attempt_event = conflicting
    receipt = dispatch_profile(
        action(), capability(Provider(channel)), store, capture_ref, lambda: False
    )

    assert receipt.outcome == "uncertain"
    assert receipt.limitations == ("transport_interrupted",)
    assert receipt.counters.tcp_connects == 1
    assert receipt.counters.tx_bytes == len(channel.sent)
    assert receipt.counters.capture_bytes == 0
    assert channel.closed is True
    assert store.stopped() is True
    assert store.attempt_receipt("portcast-action")["attempts"][0]["state"] == "uncertain"
    assert store._db.execute(
        "SELECT state FROM reservations WHERE request_id='portcast-action'"
    ).fetchone() == ("uncertain",)


def test_unsealed_or_modified_profile_action_cannot_reach_channel_or_reservation(tmp_path):
    store = ledger(tmp_path)
    provider = Provider(Channel([RAW_RESPONSE, b""]))
    forged = contracts.ProfileAction(
        "forged", "wave-one", "workspace", "cptc11-prod-portcast", PROFILE_ID,
        RUNTIME_SHA256, bounds(), (("request_limit", 1),), (),
    )
    with pytest.raises(PolicyError, match="sealed"):
        dispatch_profile(forged, capability(provider), store, capture_ref, lambda: False)
    assert provider.opens == 0
    assert store._db.execute("SELECT COUNT(*) FROM reservations").fetchone() == (0,)

    sealed = action("modified")
    equal_forgery = contracts.ProfileAction(
        sealed.action_id,
        sealed.wave_id,
        sealed.workspace_id,
        sealed.target_id,
        sealed.profile_id,
        sealed.runtime_pinset_sha256,
        sealed.bounds,
        sealed.limits,
        sealed.budget_limits,
    )
    with pytest.raises(PolicyError, match="sealed"):
        dispatch_profile(
            equal_forgery, capability(provider), store, capture_ref, lambda: False
        )
    with pytest.raises(FrozenInstanceError):
        sealed.profile_id = "other"


def test_unsealed_provider_is_rejected_before_reservation_or_channel(tmp_path):
    store = ledger(tmp_path)
    provider = Provider(Channel([RAW_RESPONSE, b""]))
    with pytest.raises(PolicyError, match="broker"):
        dispatch_profile(action(), provider, store, capture_ref, lambda: False)

    assert provider.opens == 0
    assert store._db.execute("SELECT COUNT(*) FROM reservations").fetchone() == (0,)


def test_receipt_sink_failure_after_wire_contact_is_uncertain_and_stops(tmp_path):
    from cptc_harness.profile_runtime.executor import dispatch_profile as dispatch

    store = ledger(tmp_path)
    provider = Provider(Channel([RAW_RESPONSE, b""]))

    def fail_receipt(_receipt):
        raise OSError("synthetic audit failure")

    receipt = dispatch(
        action(),
        capability(provider),
        store,
        capture_ref,
        fail_receipt,
        lambda: False,
    )

    assert receipt.outcome == "uncertain"
    assert receipt.limitations == ("audit_failure",)
    assert provider.opens == 1
    assert store.stopped() is True
    assert store.attempt_receipt("portcast-action")["attempts"][0]["state"] == "complete"
    assert store.reservation_state("portcast-action") == "uncertain"


def test_final_monotonic_read_at_deadline_persists_only_uncertain_receipt(
    tmp_path, monkeypatch
):
    from cptc_harness.profile_runtime import executor

    moments = iter((1_000_000_000, 2_000_000_000, 11_000_000_000))
    monkeypatch.setattr(executor.time, "monotonic_ns", lambda: next(moments))
    store = ledger(tmp_path)
    provider = Provider(Channel([RAW_RESPONSE, b""]))
    persisted = []

    receipt = executor.dispatch_profile(
        action(),
        capability(provider),
        store,
        capture_ref,
        persisted.append,
        lambda: False,
    )

    assert receipt.outcome == "uncertain"
    assert receipt.limitations == ("timeout",)
    assert [value.outcome for value in persisted] == ["uncertain"]
    assert store.attempt_receipt("portcast-action")["attempts"][0]["state"] == "uncertain"


def test_profile_wire_receipt_is_durable_and_reopens_from_audit(
    tmp_path, monkeypatch
):
    from cptc_harness.profile_runtime.executor import dispatch_profile as dispatch

    audit_root = tmp_path / "audit"
    audit_root.mkdir(mode=0o700)
    policy = PolicySnapshot(
        "engagement",
        "revision",
        "workspace",
        "device",
        "operator",
        ScopeSpec(),
        encrypted_storage=True,
    )
    trusted_worker = ("x" + WORKER_SHA256)[1:]
    writer = AuditWriter(
        audit_root,
        policy,
        encrypted_volume_verified=True,
        profile_worker_sha256=WORKER_SHA256,
        compatible_profile_workers=(trusted_worker,),
    )
    store = ledger(tmp_path / "durable")
    provider = Provider(Channel([RAW_RESPONSE, b""]))
    writer.reserve_output("durable-action", 16384)
    receipt = dispatch(
        action("durable-action"),
        capability(provider),
        store,
        lambda raw: writer.capture(
            "durable-action", "raw", raw, "client_confidential_human_only"
        ),
        writer.record_profile_wire_receipt,
        lambda: False,
    )
    writer.release_output("durable-action")
    import cptc_harness.profile_runtime.receipts as receipt_contracts

    original_validate = receipt_contracts.validate_persisted_profile_wire_receipt
    trusted_expectations = []

    def validate_from_release(value, *, expected_worker_sha256):
        trusted_expectations.append(expected_worker_sha256 is trusted_worker)
        return original_validate(
            value, expected_worker_sha256=expected_worker_sha256
        )

    monkeypatch.setattr(
        receipt_contracts,
        "validate_persisted_profile_wire_receipt",
        validate_from_release,
    )
    assert writer.profile_wire_receipts() == {
        "durable-action": receipt.as_dict()
    }
    assert trusted_expectations == [True]
    writer.close()

    reopened = AuditWriter(
        audit_root,
        policy,
        encrypted_volume_verified=True,
        profile_worker_sha256=WORKER_SHA256,
        compatible_profile_workers=(WORKER_SHA256,),
    )
    assert reopened.profile_wire_receipts() == {
        "durable-action": receipt.as_dict()
    }
    assert reopened.profile_cleanup_receipts() == {}
    reopened.record_profile_cleanup_receipt("durable-action", "passed")
    assert reopened.profile_cleanup_receipts() == {
        "durable-action": {
            "all_resources_closed": True,
            "automatic_retry": False,
            "status": "passed",
        }
    }
    with pytest.raises(PolicyError, match="already recorded"):
        reopened.record_profile_cleanup_receipt("durable-action", "passed")
    reopened.close()

    final = AuditWriter(
        audit_root,
        policy,
        encrypted_volume_verified=True,
        profile_worker_sha256=WORKER_SHA256,
        compatible_profile_workers=(WORKER_SHA256,),
    )
    assert final.profile_cleanup_receipts()["durable-action"]["status"] == "passed"
    final.close()


def test_fixed_failure_stage_is_integrity_verified_and_survives_reopen(tmp_path):
    from cptc_harness.profile_runtime.executor import dispatch_profile as dispatch

    audit_root = tmp_path / "stage-audit"
    audit_root.mkdir(mode=0o700)
    policy = PolicySnapshot(
        "engagement",
        "revision",
        "workspace",
        "device",
        "operator",
        ScopeSpec(),
        encrypted_storage=True,
    )
    writer = AuditWriter(
        audit_root,
        policy,
        encrypted_volume_verified=True,
        profile_worker_sha256=WORKER_SHA256,
        compatible_profile_workers=(WORKER_SHA256,),
    )
    store = ledger(tmp_path / "stage-durable")
    writer.reserve_output("durable-stage-action", 16384)
    dispatch(
        action("durable-stage-action"),
        StagedFailureBroker(),
        store,
        capture_ref,
        writer.record_profile_wire_receipt,
        lambda: False,
        failure_stage_sink=lambda stage: writer.emit(
            contracts.AuditEvent(
                "profile_wire_failure_stage",
                "durable-stage-action",
                {"stage": stage, "automatic_retry": False},
            )
        ),
    )
    writer.release_output("durable-stage-action")

    assert writer.profile_inspection_snapshot("durable-stage-action")[
        "wire_failure_stage"
    ] == "target_open"
    writer.close()

    reopened = AuditWriter(
        audit_root,
        policy,
        encrypted_volume_verified=True,
        profile_worker_sha256=WORKER_SHA256,
        compatible_profile_workers=(WORKER_SHA256,),
    )
    assert reopened.profile_inspection_snapshot("durable-stage-action")[
        "wire_failure_stage"
    ] == "target_open"
    reopened.emit(
        contracts.AuditEvent(
            "profile_wire_failure_stage",
            "durable-stage-action",
            {"stage": "target_open", "automatic_retry": False},
        )
    )
    with pytest.raises(PolicyError, match="invalid or duplicate"):
        reopened.profile_inspection_snapshot("durable-stage-action")
    reopened.close()


def test_failure_stage_without_a_durable_wire_receipt_is_rejected(tmp_path):
    audit_root = tmp_path / "orphan-stage-audit"
    audit_root.mkdir(mode=0o700)
    policy = PolicySnapshot(
        "engagement",
        "revision",
        "workspace",
        "device",
        "operator",
        ScopeSpec(),
        encrypted_storage=True,
    )
    writer = AuditWriter(
        audit_root,
        policy,
        encrypted_volume_verified=True,
        profile_worker_sha256=WORKER_SHA256,
        compatible_profile_workers=(WORKER_SHA256,),
    )
    writer.emit(
        contracts.AuditEvent(
            "profile_wire_failure_stage",
            "orphan-stage-action",
            {"stage": "target_open", "automatic_retry": False},
        )
    )

    with pytest.raises(PolicyError, match="invalid or duplicate"):
        writer.profile_inspection_snapshot("orphan-stage-action")
    writer.close()


def test_cleanup_receipt_requires_existing_wire_receipt(tmp_path):
    audit_root = tmp_path / "audit-without-wire"
    audit_root.mkdir(mode=0o700)
    policy = PolicySnapshot(
        "engagement",
        "revision",
        "workspace",
        "device",
        "operator",
        ScopeSpec(),
        encrypted_storage=True,
    )
    writer = AuditWriter(
        audit_root,
        policy,
        encrypted_volume_verified=True,
        profile_worker_sha256=WORKER_SHA256,
        compatible_profile_workers=(WORKER_SHA256,),
    )

    with pytest.raises(PolicyError, match="wire receipt"):
        writer.record_profile_cleanup_receipt("missing-action", "passed")

    writer.close()
