from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
import subprocess
import time
from datetime import datetime, timedelta, timezone

import pytest

import testing.cptc11_lab.portcast_live as live
from cptc_harness.contracts import AuditEvent, PolicyError
import cptc_harness.integrity as integrity
from cptc_harness.integrity import VerifiedRelease
from cptc_harness.memfd import MFD_ALLOW_SEALING, MFD_CLOEXEC, memfd_create, seal_readonly, write_all
from cptc_harness.profile_runtime.broker_ipc import (
    BrokerWireEvent,
    BrokerWireResult,
    DispatchNonce,
    PortcastBrokerClient,
)
from cptc_harness.profile_runtime.catalog import load_profile
from cptc_harness.profile_runtime.contracts import WireCounters
from cptc_harness.profile_runtime.worker import build_http11_request
from cptc_harness.runtime import Runtime


def _response() -> bytes:
    body = (
        b'{"ProductName":"Jellyfin Server","Version":"10.10.7",'
        b'"ServerName":"synthetic-portcast","Id":"synthetic-id",'
        b'"OperatingSystem":"Linux","StartupWizardCompleted":true}'
    )
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Encoding: identity\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )


def _age_identity(tmp_path: Path) -> tuple[Path, str]:
    root = Path(__file__).parents[1]
    age = root / ".tools" / "age"
    keygen = root / ".tools" / "age-keygen"
    identity = tmp_path / "identity.agekey"
    subprocess.run([str(keygen), "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.run(
        [str(keygen), "-y", str(identity)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return age, recipient


def _release(plan) -> VerifiedRelease:
    return VerifiedRelease(
        plan.release_id,
        "3" * 64,
        {},
        {plan.profile_id: plan.worker_sha256},
        {plan.profile_id: (plan.worker_sha256,)},
    )


class SyntheticClient(PortcastBrokerClient):
    instances = []

    def __init__(self, ledger, verified_release):
        self._initialize_for_test(ledger, verified_release)
        self.executions = 0
        self.closed = False
        self.__class__.instances.append(self)

    def bind_reserved_attempt(self, binding):
        self._verify_reservation(binding)
        self._binding = binding
        return DispatchNonce(b"n" * 32, time.monotonic_ns() + 1_000_000_000)

    def execute_once(self, _nonce, record_event, _stopped):
        self.executions += 1
        profile = load_profile("web.http_jellyfin_public_identity")
        request = build_http11_request(profile.operation)
        raw = _response()
        record_event(BrokerWireEvent("connect-000000", 1, 0, 0, 0, 0, None))
        record_event(BrokerWireEvent("send-000001", 0, 0, 1, len(request), 0, None))
        first = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        record_event(BrokerWireEvent("recv-000001", 0, 0, 0, 0, len(raw), first))
        descriptor = memfd_create("portcast-live-test", MFD_CLOEXEC | MFD_ALLOW_SEALING)
        write_all(descriptor, raw)
        os.lseek(descriptor, 0, os.SEEK_SET)
        seal_readonly(descriptor)
        return BrokerWireResult(
            "complete",
            None,
            WireCounters(1, 0, 0, 1, len(request), len(raw), len(raw)),
            descriptor,
            len(raw),
            hashlib.sha256(raw).hexdigest(),
            first,
            self.expected_worker_sha256,
        )

    def close(self):
        self.closed = True


class CloseFailClient(SyntheticClient):
    def close(self):
        self.closed = True
        raise PolicyError("synthetic broker cleanup failed")


def _synthetic_open_window_plan():
    now = datetime.now(timezone.utc)
    return replace(
        live.load_frozen_portcast_plan(),
        reviewed_by="approved:synthetic-reviewer",
        window_start=(now - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        window_end=(now + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    )


def _use_synthetic_open_window(monkeypatch):
    plan = _synthetic_open_window_plan()
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    return plan


def test_frozen_plan_binds_one_exact_admitted_action_and_release(
    tmp_path, monkeypatch
):
    plan = live.load_frozen_portcast_plan()
    anchor = tmp_path / "portcast-live-v1.sha256"
    anchor.write_text(hashlib.sha256(integrity._RELEASE_MANIFEST.read_bytes()).hexdigest() + "\n")
    verified_release = integrity._verify_portcast_release(
        release_root=integrity._RELEASE_ROOT,
        manifest_path=integrity._RELEASE_MANIFEST,
        anchor_path=anchor,
        owner_uid=os.getuid(),
    )
    monkeypatch.setattr(live, "verify_portcast_release", lambda: verified_release)
    verified = live.validate_current_release(plan)
    profile = load_profile(plan.profile_id)

    assert verified.release_id == plan.release_id == "portcast-live-v1"
    assert plan.profile_sha256 == profile.profile_sha256
    assert plan.operation_sha256 == profile.operation.sha256
    assert plan.runtime_pinset_sha256 == profile.runtime_pinset_sha256
    assert plan.request_count == 1
    assert plan.automatic_retries == 0
    assert plan.authentication_attempts == 0
    assert not any(
        hasattr(plan, name)
        for name in ("url", "host", "port", "path", "headers", "body", "proxy", "retry")
    )


def test_checked_in_pending_plan_is_refused_before_its_expired_window():
    plan = live.load_frozen_portcast_plan()
    assert datetime.fromisoformat(
        plan.window_end.replace("Z", "+00:00")
    ) < datetime.now(timezone.utc)
    with pytest.raises(PolicyError, match="not independently approved"):
        live._require_open_window(plan)

    approved = replace(plan, reviewed_by="approved:synthetic-reviewer")
    with pytest.raises(PolicyError, match="operating window is closed"):
        live._require_open_window(approved)


def test_rehashed_pending_plan_is_refused_during_an_open_window():
    now = datetime.now(timezone.utc)
    pending = replace(
        live.load_frozen_portcast_plan(),
        reviewed_by="pending-independent-runtime-rereview",
        window_start=(now - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        window_end=(now + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    )

    with pytest.raises(PolicyError, match="not independently approved"):
        live._require_open_window(pending)


def test_frozen_plan_rejects_rehashed_operator_change(tmp_path, monkeypatch):
    value = json.loads(live._PLAN_PATH.read_text())
    value["request_count"] = 2
    unsigned = dict(value)
    unsigned.pop("plan_sha256")
    value["plan_sha256"] = hashlib.sha256(live._canonical(unsigned)).hexdigest()
    changed = tmp_path / "changed-plan.json"
    changed.write_text(json.dumps(value))
    monkeypatch.setattr(live, "_PLAN_PATH", changed)

    with pytest.raises(PolicyError, match="allowance"):
        live.load_frozen_portcast_plan()


def test_release_failure_blocks_before_runtime_or_broker(tmp_path, monkeypatch):
    monkeypatch.setattr(
        live,
        "validate_current_release",
        lambda _plan: (_ for _ in ()).throw(PolicyError("release drift")),
    )
    monkeypatch.setattr(
        live,
        "_prepare_runtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("runtime")),
    )
    with pytest.raises(PolicyError, match="release drift"):
        live._run_frozen_portcast_action_at_root(
            state_root=tmp_path / "state",
            age_binary=tmp_path / "age",
            age_recipient="age1unused",
            wire_broker_factory=SyntheticClient,
        )


def test_synthetic_broker_executes_once_and_replay_starts_no_second_broker(
    tmp_path, monkeypatch
):
    SyntheticClient.instances.clear()
    plan = _use_synthetic_open_window(monkeypatch)
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "state"

    first = live._run_frozen_portcast_action_at_root(
        state_root=state, age_binary=age, age_recipient=recipient,
        wire_broker_factory=SyntheticClient,
    )
    duplicate = live._run_frozen_portcast_action_at_root(
        state_root=state, age_binary=age, age_recipient=recipient,
        wire_broker_factory=SyntheticClient,
    )

    assert first["status"] == "complete"
    assert first["cleanup_status"] == "passed"
    assert duplicate["status"] == "blocked"
    assert duplicate["automatic_retry"] is False
    assert len(SyntheticClient.instances) == 1
    assert SyntheticClient.instances[0].executions == 1
    assert SyntheticClient.instances[0].closed is True


@pytest.mark.parametrize(
    "kind", ("profile_release_verified", "output_reserved", "operation_intent")
)
def test_audit_only_admission_history_blocks_before_a_second_broker(
    tmp_path, monkeypatch, kind
):
    SyntheticClient.instances.clear()
    plan = _use_synthetic_open_window(monkeypatch)
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / kind
    runtime_root, ledger_root = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    runtime = Runtime(runtime_root, ledger_root=ledger_root, verified_release=release)
    if kind == "output_reserved":
        runtime.audit.reserve_output(plan.action_id, 16384)
        runtime.audit.release_output(plan.action_id)
    else:
        runtime.audit.emit(AuditEvent(kind, plan.action_id, {}))
    runtime.close()

    result = live._run_frozen_portcast_action_at_root(
        state_root=state,
        age_binary=age,
        age_recipient=recipient,
        wire_broker_factory=SyntheticClient,
    )

    assert result["status"] == "blocked"
    assert result["automatic_retry"] is False
    assert SyntheticClient.instances == []


def test_broker_cleanup_failure_records_failed_receipt_and_uncertainty(
    tmp_path, monkeypatch
):
    plan = _use_synthetic_open_window(monkeypatch)
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "cleanup-failure"

    result = live._run_frozen_portcast_action_at_root(
        state_root=state,
        age_binary=age,
        age_recipient=recipient,
        wire_broker_factory=CloseFailClient,
    )

    assert result["status"] == "uncertain"
    assert result["cleanup_status"] == "failed"
    runtime_root, ledger_root = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    runtime = Runtime(runtime_root, ledger_root=ledger_root, verified_release=release)
    assert runtime.audit.profile_cleanup_receipts()[plan.action_id]["status"] == "failed"
    assert runtime.ledger.reservation_state(plan.action_id) == "uncertain"
    assert runtime.ledger.stopped() is True
    runtime.close()
