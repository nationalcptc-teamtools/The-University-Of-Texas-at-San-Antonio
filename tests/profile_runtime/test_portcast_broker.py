from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from cptc_harness.broker import Broker
from cptc_harness.contracts import (
    ClockState, EvidenceRef, OperationRequest, PolicyError, PolicySnapshot,
    ScopeSpec, TargetPolicy, TargetRef,
)
from cptc_harness.integrity import VerifiedRelease
from cptc_harness.ledger import Ledger
from cptc_harness.memfd import MFD_ALLOW_SEALING, MFD_CLOEXEC, memfd_create, seal_readonly, write_all
from cptc_harness.profile_runtime.broker_ipc import (
    BrokerWireEvent, BrokerWireResult, DispatchNonce, PortcastBrokerClient,
)
from cptc_harness.profile_runtime.catalog import load_profile
from cptc_harness.profile_runtime.contracts import WireCounters
from cptc_harness.profile_runtime.worker import build_http11_request
from cptc_harness.registry import build_registry


PROFILE_ID = "web.http_jellyfin_public_identity"
BODY = b'{"ProductName":"Jellyfin Server","Version":"10.10.7"}'
RAW_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
    b"Content-Encoding: identity\r\n"
    + f"Content-Length: {len(BODY)}\r\n".encode("ascii")
    + b"Connection: close\r\n\r\n" + BODY
)
TARGET = TargetRef(
    "cptc11-prod-portcast", "http://10.0.1.30:8096/System/Info/Public",
    "http", "10.0.1.30", 8096, "/System/Info/Public",
)


class Audit:
    def __init__(self, events):
        self.events, self.evidence, self.active_reservations = events, [], set()

    def verify(self):
        return SimpleNamespace(valid=True)

    def ready(self):
        return True

    def encryption_ready(self):
        return True

    def reserve_output(self, request_id, maximum):
        self.events.append(("reserve_output", request_id, maximum))
        self.active_reservations.add(request_id)

    def release_output(self, request_id):
        self.events.append(("release_output", request_id))
        self.active_reservations.discard(request_id)

    def record_profile_wire_receipt(self, receipt):
        self.events.append(("profile_wire_receipt", receipt.action_id))

    def emit(self, event):
        self.events.append((event.kind, event.action_id, event.data))

    def capture(self, request_id, stream, raw, classification):
        self.events.append(("capture", request_id, stream))
        reference = EvidenceRef(
            "encrypted-artifact", TARGET.target_id, stream, classification,
            "evidence/encrypted-artifact.age", hashlib.sha256(raw).hexdigest(), len(raw),
        )
        self.evidence.append((raw, reference))
        return reference


class SyntheticWireBroker(PortcastBrokerClient):
    def __init__(self, ledger, raw, events):
        worker = Path(__file__).parents[2] / "cptc_harness/profile_runtime/worker.py"
        worker_sha256 = hashlib.sha256(worker.read_bytes()).hexdigest()
        self._initialize_for_test(
            ledger,
            VerifiedRelease(
                "portcast-live-v1", "3" * 64, {},
                {PROFILE_ID: worker_sha256}, {PROFILE_ID: (worker_sha256,)},
            ),
        )
        self.raw, self.events, self.opens = raw, events, 0

    def bind_reserved_attempt(self, binding):
        self._verify_reservation(binding)
        self.events.append(("bind",))
        return DispatchNonce(b"p" * 32, 2**63 - 1)

    def execute_once(self, _nonce, record_event, _stopped):
        self.events.append(("open",))
        self.opens += 1
        request = build_http11_request(load_profile(PROFILE_ID).operation)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        record_event(BrokerWireEvent("connect-000000", 1, 0, 0, 0, 0, None))
        record_event(BrokerWireEvent("send-000001", 0, 0, 1, len(request), 0, None))
        record_event(BrokerWireEvent("recv-000001", 0, 0, 0, 0, len(self.raw), now))
        descriptor = memfd_create("broker-test", MFD_CLOEXEC | MFD_ALLOW_SEALING)
        write_all(descriptor, self.raw)
        os.lseek(descriptor, 0, os.SEEK_SET)
        seal_readonly(descriptor)
        return BrokerWireResult(
            "complete", None,
            WireCounters(1, 0, 0, 1, len(request), len(self.raw), len(self.raw)),
            descriptor, len(self.raw), hashlib.sha256(self.raw).hexdigest(), now,
            self.expected_worker_sha256,
        )

    def close(self):
        return None


class StagedFailureWireBroker(SyntheticWireBroker):
    """Return a sealed, zero-traffic failure at the fixed target-open stage."""

    def execute_once(self, _nonce, _record_event, _stopped):
        self.events.append(("open",))
        self.opens += 1
        descriptor = memfd_create("broker-staged-failure", MFD_CLOEXEC | MFD_ALLOW_SEALING)
        seal_readonly(descriptor)
        return BrokerWireResult(
            "uncertain",
            "transport_interrupted",
            WireCounters(0, 0, 0, 0, 0, 0, 0),
            descriptor,
            0,
            hashlib.sha256(b"").hexdigest(),
            None,
            self.expected_worker_sha256,
            "target_open",
        )


def setup(tmp_path, raw=RAW_RESPONSE, *, with_broker=True):
    events, registry = [], build_registry()
    spec = registry.get("web.portcast_identity")
    now = datetime.now(timezone.utc)
    policy = PolicySnapshot(
        "engagement", "revision", "workspace", "device", "operator",
        ScopeSpec(allowed_cidrs=("10.0.1.30/32",)),
        targets=(TargetPolicy(
            TARGET, True, "reviewed-portcast-profile", "workspace", "",
            (spec.module_id,), request_limit=1,
        ),),
        window_start=(now - timedelta(minutes=1)).isoformat(),
        window_end=(now + timedelta(minutes=5)).isoformat(),
        sow_reference="synthetic-sow", roe_reference="synthetic-roe",
    )
    root = tmp_path / "ledger"
    root.mkdir(parents=True)
    root.chmod(0o700)
    ledger = Ledger(root, policy.engagement_id, policy.device_id, policy_revision=policy.revision)
    original_reserve = ledger.reserve_attempt

    def reserve_attempt(*args, **kwargs):
        events.append(("reserve_attempt", args[0]))
        return original_reserve(*args, **kwargs)

    ledger.reserve_attempt = reserve_attempt
    audit = Audit(events)
    wire_broker = SyntheticWireBroker(ledger, raw, events) if with_broker else None
    broker = Broker(
        policy, registry, ledger, audit, clock=ClockState(True, 0),
        profile_wire_broker=wire_broker,
    )
    request = OperationRequest(
        "portcast-action", "workspace", "device", "operator", spec.module_id,
        TARGET, {"profile_id": PROFILE_ID}, "operator", None, "revision",
        workflow_id="wave-one",
    )
    return broker, request, ledger, audit, wire_broker, events


def test_broker_reserves_before_one_worker_result(tmp_path):
    broker, request, ledger, audit, wire_broker, events = setup(tmp_path)
    result = broker.execute(request, actor="operator")
    assert result.status == "complete"
    assert result.facts["observations"][0]["state"] == "candidate"
    assert result.facts["observations"][0]["source_sha256"] == hashlib.sha256(RAW_RESPONSE).hexdigest()
    assert wire_broker.opens == 1 and audit.evidence[0][0] == RAW_RESPONSE
    kinds = [event[0] for event in events]
    assert kinds.index("reserve_output") < kinds.index("operation_intent")
    assert kinds.index("operation_intent") < kinds.index("reserve_attempt")
    assert kinds.index("reserve_attempt") < kinds.index("bind") < kinds.index("open")
    assert kinds.index("capture") < kinds.index("profile_wire_receipt") < kinds.index("operation_result")
    assert ledger.attempt_receipt(request.request_id)["attempts"][0]["state"] == "complete"


def test_typed_parse_failure_does_not_retry(tmp_path):
    broker, request, ledger, _audit, wire_broker, _events = setup(
        tmp_path, RAW_RESPONSE.replace(b"10.10.7", b"10.10.8")
    )
    result = broker.execute(request, actor="operator")
    assert result.status == "failed"
    assert result.reason == "PortCast identity response did not match the reviewed parser"
    assert wire_broker.opens == 1
    assert ledger.attempt_receipt(request.request_id)["attempts"][0]["state"] == "complete"
    assert ledger.stopped() is False


def test_missing_wire_broker_or_extra_input_never_reserves(tmp_path):
    broker, request, ledger, _audit, _wire, _events = setup(tmp_path, with_broker=False)
    result = broker.execute(request, actor="operator")
    assert result.status == "blocked" and "wire broker" in result.reason
    assert ledger._db.execute("SELECT COUNT(*) FROM reservations").fetchone() == (0,)

    broker, request, ledger, _audit, wire_broker, _events = setup(tmp_path / "extra")
    changed = OperationRequest(
        request.request_id + "host", request.workspace_id, request.device_id,
        request.operator_id, request.module_id, request.target,
        {**request.args, "host": "10.0.1.31"}, request.source,
        request.approval_id, request.policy_revision, request.workflow_id,
    )
    assert broker.execute(changed, actor="operator").status == "blocked"
    assert wire_broker.opens == 0
    assert ledger._db.execute("SELECT COUNT(*) FROM reservations").fetchone() == (0,)


def test_old_channel_keyword_fails_closed(tmp_path):
    broker, _request, ledger, audit, _wire, _events = setup(tmp_path)
    with pytest.raises(PolicyError, match="profile_channel_provider was removed"):
        Broker(
            broker.policy, broker.registry, ledger, audit, clock=ClockState(True, 0),
            profile_channel_provider=None,
        )


def test_duplicate_action_is_prewire_denial(tmp_path):
    broker, request, ledger, audit, wire_broker, _events = setup(tmp_path)
    assert broker.execute(request, actor="operator").status == "complete"
    assert broker.execute(request, actor="operator").status == "blocked"
    assert wire_broker.opens == 1 and ledger.stopped() is False
    assert audit.active_reservations == set()


def test_fixed_failure_stage_is_audited_after_wire_receipt(tmp_path):
    broker, request, ledger, audit, _wire_broker, events = setup(tmp_path)
    staged = StagedFailureWireBroker(ledger, b"", events)
    broker._profile_wire_broker = staged

    result = broker.execute(request, actor="operator")

    assert result.status == "uncertain"
    assert staged.opens == 1
    assert ledger.stopped() is True
    assert ledger.attempt_receipt(request.request_id)["usage"] == {
        "protocol_requests": 0,
        "rx_bytes": 0,
        "tcp_connects": 0,
        "tx_bytes": 0,
        "udp_datagrams": 0,
    }
    kinds = [event[0] for event in events]
    receipt_index = kinds.index("profile_wire_receipt")
    stage_index = kinds.index("profile_wire_failure_stage")
    assert receipt_index < stage_index < kinds.index("operation_result")
    assert events[stage_index] == (
        "profile_wire_failure_stage",
        request.request_id,
        {"stage": "target_open", "automatic_retry": False},
    )
    assert audit.evidence == []
