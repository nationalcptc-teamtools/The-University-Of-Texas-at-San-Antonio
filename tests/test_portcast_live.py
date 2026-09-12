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
from cptc_harness.contracts import (
    AuditEvent,
    OperationRequest,
    OperationResult,
    PolicyError,
)
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
from cptc_harness.registry import build_registry
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
        {
            "cptc_harness/portcast_identity.py": plan.parser_sha256,
            "testing/cptc11_lab/portcast_broker_worker.py": plan.broker_worker_sha256,
        },
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
        live.load_frozen_portcast_plan_v2(),
        # Synthetic unit runtimes deliberately use the legacy schema marker.
        schema_version=1,
        reviewed_by="approved:synthetic-reviewer",
        window_start=(now - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        window_end=(now + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    )


def _seed_blocked_clock_predecessor(runtime: Runtime, plan) -> None:
    request = OperationRequest(
        plan.predecessor_action_id,
        plan.workspace_id,
        plan.device_id,
        plan.operator_id,
        plan.module_id,
        live._target(),
        {"profile_id": plan.profile_id},
        "operator",
        None,
        plan.policy_revision,
        plan.predecessor_plan_id,
    )
    runtime.audit.emit(
        AuditEvent(
            "profile_release_verified",
            plan.predecessor_action_id,
            {"release_id": plan.release_id, "manifest_sha256": "3" * 64},
        )
    )
    runtime.audit.emit(
        AuditEvent(
            "operation_denied",
            plan.predecessor_action_id,
            {"reason": "clock is not safe for active work"},
        )
    )
    runtime._record_result(
        request,
        OperationResult(
            "blocked", reason="clock is not safe for active work"
        ),
    )


def _use_synthetic_open_window(monkeypatch):
    plan = _synthetic_open_window_plan()
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    return plan


def test_legacy_v2_plan_uses_an_explicit_immutable_loader():
    current = live.load_frozen_portcast_plan()
    historical_v5 = live.load_frozen_portcast_plan_v5()
    historical_v3 = live.load_frozen_portcast_plan_v3()
    legacy = live.load_frozen_portcast_plan_v2()

    assert current.schema_version == 6
    assert current.action_id == "cptc11-portcast-public-identity-action-v6"
    assert historical_v5.schema_version == 5
    assert historical_v5.action_id == "cptc11-portcast-public-identity-action-v5"
    assert historical_v3.schema_version == 3
    assert historical_v3.action_id == "cptc11-portcast-public-identity-action-v3"
    assert legacy.schema_version == 2
    assert legacy.action_id == "cptc11-portcast-public-identity-action-v2"
    assert legacy.plan_sha256 == (
        "a6aada496c238513080798ad8012bb4e9688847e2cd49330e2c7f081ce0012c4"
    )
    assert live._read_predecessor_plan(legacy)["schema_version"] == 1


def test_frozen_plan_binds_one_exact_admitted_action_and_release(
    tmp_path, monkeypatch
):
    plan = live.load_frozen_portcast_plan()
    verified_release = _release(plan)
    monkeypatch.setattr(live, "verify_portcast_release", lambda: verified_release)
    verified = live.validate_current_release(plan)
    profile = load_profile(plan.profile_id)

    assert verified.release_id == plan.release_id == "portcast-live-v1"
    assert plan.profile_sha256 == profile.profile_sha256
    assert plan.operation_sha256 == profile.operation.sha256
    assert plan.runtime_pinset_sha256 == profile.runtime_pinset_sha256
    assert plan.request_count == 1
    assert plan.schema_version == 6
    assert plan.action_id == "cptc11-portcast-public-identity-action-v6"
    assert plan.predecessor_action_id == "cptc11-portcast-public-identity-action-v2"
    assert plan.predecessor_v4_action_id == "cptc11-portcast-public-identity-action-v4"
    assert plan.predecessor_v4_plan_sha256 == live._V4_PLAN_SHA256
    assert plan.predecessor_v5_action_id == "cptc11-portcast-public-identity-action-v5"
    assert plan.predecessor_v5_plan_sha256 == live._V5_PLAN_SHA256
    assert plan.automatic_retries == 0
    assert plan.authentication_attempts == 0
    assert not any(
        hasattr(plan, name)
        for name in ("url", "host", "port", "path", "headers", "body", "proxy", "retry")
    )


def test_v2_predecessor_reconciliation_requires_exact_zero_attempt_history(
    tmp_path, monkeypatch
):
    plan = replace(
        live.load_frozen_portcast_plan_v2(),
        reviewed_by="approved:synthetic-reviewer",
    )
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "v2-reconcile"
    runtime_root, ledger_root = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    runtime = Runtime(
        runtime_root, ledger_root=ledger_root, verified_release=release
    )
    _seed_blocked_clock_predecessor(runtime, plan)

    record = live._reconcile_predecessor(runtime, plan, runtime_root)

    assert record["created"] is True
    assert record["predecessor_action_id"] == plan.predecessor_action_id
    assert record["successor_action_id"] == plan.action_id
    assert record["reconciliation_sha256"] == (
        plan.predecessor_reconciliation_sha256
    )
    assert runtime.ledger.reservation_state(plan.predecessor_action_id) is None
    assert runtime.ledger.optional_attempt_receipt(plan.predecessor_action_id) is None
    assert live._reconcile_predecessor(runtime, plan, runtime_root)["created"] is False
    runtime.close()


@pytest.mark.parametrize(
    "mutation",
    ("missing", "history", "reservation", "result", "stopped"),
)
def test_v2_predecessor_reconciliation_fails_closed(
    tmp_path, monkeypatch, mutation
):
    plan = replace(
        live.load_frozen_portcast_plan_v2(),
        reviewed_by="approved:synthetic-reviewer",
    )
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / ("v2-reconcile-" + mutation)
    runtime_root, ledger_root = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    runtime = Runtime(
        runtime_root, ledger_root=ledger_root, verified_release=release
    )
    if mutation != "missing":
        _seed_blocked_clock_predecessor(runtime, plan)
    if mutation == "history":
        runtime.audit.emit(
            AuditEvent("operation_intent", plan.predecessor_action_id, {})
        )
    elif mutation == "reservation":
        runtime.ledger.reserve(
            plan.predecessor_action_id,
            live.build_registry().get(plan.module_id).bounds,
            workspace_id=plan.workspace_id,
            target_id=live._target().canonical_url,
            workflow_id=plan.predecessor_plan_id,
        )
    elif mutation == "result":
        result_path = runtime_root / "results" / (
            plan.predecessor_action_id + ".json"
        )
        result_path.write_bytes(result_path.read_bytes().replace(b"blocked", b"failed"))
    elif mutation == "stopped":
        runtime.ledger.stop("operator stop")

    with pytest.raises(PolicyError, match="predecessor|audit|stopped"):
        live._reconcile_predecessor(runtime, plan, runtime_root)
    assert runtime.ledger.profile_reconciliation(plan.predecessor_action_id) is None
    runtime.close()


def test_direct_prepared_v2_action_cannot_bypass_predecessor_gate(
    tmp_path, monkeypatch
):
    SyntheticClient.instances.clear()
    plan = replace(
        live.load_frozen_portcast_plan_v2(),
        reviewed_by="approved:synthetic-reviewer",
    )
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "direct-prepared-bypass"
    runtime_root, ledger_root = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    runtime = Runtime(
        runtime_root, ledger_root=ledger_root, verified_release=release
    )

    with pytest.raises(PolicyError, match="frozen plan"):
        live.run_prepared_portcast_action(
            runtime, plan, state, release, SyntheticClient
        )

    assert SyntheticClient.instances == []
    assert runtime.ledger.reservation_state(plan.action_id) is None
    assert runtime.ledger.optional_attempt_receipt(plan.action_id) is None
    runtime.close()


@pytest.mark.parametrize(
    "change",
    (
        {"action_id": "cptc11-portcast-forged-action"},
        {"plan_sha256": "f" * 64},
    ),
)
def test_public_runtime_open_rejects_forged_v2_plan_before_state(
    tmp_path, monkeypatch, change
):
    age, recipient = _age_identity(tmp_path)
    exact = replace(
        _synthetic_open_window_plan(),
        schema_version=2,
        evidence_recipient=recipient,
    )
    forged = replace(exact, **change)
    release = replace(
        _release(exact),
        native_file_sha256={
            "bin/age": hashlib.sha256(age.read_bytes()).hexdigest()
        },
    )
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: exact)
    state = tmp_path / "forged-public-open"

    with pytest.raises(PolicyError, match="frozen plan"):
        live.open_frozen_portcast_runtime_at_root(
            state_root=state,
            plan=forged,
            verified_release=release,
            age_binary=age,
            age_recipient=recipient,
        )

    assert not state.exists()


@pytest.mark.parametrize(
    "change",
    (
        {"action_id": "cptc11-portcast-forged-action"},
        {"plan_sha256": "f" * 64},
    ),
)
def test_public_prepared_inspect_rejects_forged_v2_without_reconciliation(
    tmp_path, monkeypatch, change
):
    age, recipient = _age_identity(tmp_path)
    exact = replace(
        _synthetic_open_window_plan(),
        schema_version=2,
        evidence_recipient=recipient,
    )
    legacy = replace(exact, schema_version=1)
    release = replace(
        _release(exact),
        native_file_sha256={
            "bin/age": hashlib.sha256(age.read_bytes()).hexdigest()
        },
    )
    state = tmp_path / "forged-public-inspect"
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    runtime = live._open_frozen_portcast_runtime_at_root_core(
        state_root=state,
        plan=legacy,
        verified_release=release,
        age_binary=age,
        age_recipient=recipient,
    )
    before = runtime.audit.path.read_bytes()
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: exact)
    try:
        with pytest.raises(PolicyError, match="frozen plan"):
            live.inspect_prepared_portcast_state(
                runtime,
                replace(exact, **change),
                state,
            )
        assert runtime.ledger.profile_reconciliation(
            exact.predecessor_action_id
        ) is None
        assert runtime.audit.path.read_bytes() == before
    finally:
        runtime.close()


def test_reconciled_predecessor_tombstone_blocks_even_with_empty_audit(
    tmp_path, monkeypatch
):
    plan = _synthetic_open_window_plan()
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "predecessor-tombstone"
    runtime_root, ledger_root = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    runtime = Runtime(
        runtime_root, ledger_root=ledger_root, verified_release=release
    )
    runtime.ledger.reconcile_profile_predecessor(
        predecessor_action_id=plan.action_id,
        predecessor_plan_id=plan.plan_id,
        predecessor_plan_sha256="1" * 64,
        successor_action_id="synthetic-successor",
        successor_plan_id="synthetic-successor-plan",
        successor_plan_sha256="2" * 64,
        reconciliation_sha256="3" * 64,
        reason_code="clock-source-unavailable",
    )

    result = live._replay_metadata(runtime, plan, runtime_root)

    assert result["status"] == "blocked"
    assert result["reason"] == (
        "reconciled predecessor action is permanently spent"
    )
    assert result["execution"]["attempt_count"] == 0
    assert runtime.ledger.stopped() is True
    runtime.close()


def test_checked_in_plan_binds_current_registry_source():
    plan = live.load_frozen_portcast_plan()

    assert plan.module_source_sha256 == build_registry().get(
        plan.module_id
    ).source_hash


def test_synthetic_pending_and_expired_plans_are_refused():
    plan = live.load_frozen_portcast_plan()
    now = datetime.now(timezone.utc)
    pending = replace(
        plan,
        reviewed_by="pending-independent-runtime-rereview",
        window_start=(now - timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        window_end=(now - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    )
    with pytest.raises(PolicyError, match="not independently approved"):
        live._require_open_window(pending)

    approved = replace(pending, reviewed_by="approved:synthetic-reviewer")
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
    monkeypatch.setattr(live, "_V6_PLAN_PATH", changed)

    with pytest.raises(PolicyError, match="allowance"):
        live.load_frozen_portcast_plan()


def test_frozen_plan_binds_a_valid_evidence_recipient(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan()
    assert live._AGE_RECIPIENT.fullmatch(plan.evidence_recipient)

    value = json.loads(live._PLAN_PATH.read_text())
    value["evidence_recipient"] = "age1invalid"
    unsigned = dict(value)
    unsigned.pop("plan_sha256")
    value["plan_sha256"] = hashlib.sha256(live._canonical(unsigned)).hexdigest()
    changed = tmp_path / "changed-recipient-plan.json"
    changed.write_text(json.dumps(value))
    monkeypatch.setattr(live, "_V6_PLAN_PATH", changed)

    with pytest.raises(PolicyError, match="evidence recipient"):
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
    assert first["execution"] == {
        "reservation_state": "complete",
        "attempt_count": 1,
        "attempt_state": "complete",
        "transport_counters": {
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "protocol_requests": 1,
            "tx_bytes": 103,
            "rx_bytes": 282,
        },
        "wire_counters_verified": True,
        "result_receipt_present": True,
        "failure_stage": None,
    }
    assert duplicate["status"] == "blocked"
    assert duplicate["automatic_retry"] is False
    assert duplicate["execution"] == first["execution"]
    assert len(SyntheticClient.instances) == 1
    assert SyntheticClient.instances[0].executions == 1
    assert SyntheticClient.instances[0].closed is True


def test_pre_dispatch_policy_reason_is_preserved_in_metadata(
    tmp_path, monkeypatch
):
    SyntheticClient.instances.clear()
    plan = _use_synthetic_open_window(monkeypatch)
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = _age_identity(tmp_path)

    result = live._run_frozen_portcast_action_at_root(
        state_root=tmp_path / "unsafe-clock",
        age_binary=age,
        age_recipient=recipient,
        clock_override=live.ClockState(False, None, "synthetic-unsafe"),
        wire_broker_factory=SyntheticClient,
    )

    assert result["status"] == "blocked"
    assert result["reason"] == "clock is not safe for active work"
    assert result["execution"]["attempt_count"] == 0
    assert SyntheticClient.instances[0].executions == 0


def test_initialized_runtime_rejects_a_different_evidence_recipient(
    tmp_path, monkeypatch
):
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "recipient-bound-state"
    live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )

    replacement_identity = tmp_path / "replacement.agekey"
    keygen = Path(__file__).parents[1] / ".tools" / "age-keygen"
    subprocess.run(
        [str(keygen), "-o", str(replacement_identity)],
        check=True,
        capture_output=True,
    )
    replacement = subprocess.run(
        [str(keygen), "-y", str(replacement_identity)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    with pytest.raises(PolicyError, match="evidence recipient"):
        live._prepare_runtime(
            state, plan, age_binary=age, age_recipient=replacement
        )


def test_atomic_runtime_first_start_is_complete_and_restart_is_inode_stable(
    tmp_path, monkeypatch
):
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "atomic-state"

    runtime, ledger = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    inode = runtime.stat().st_ino
    assert {item.name for item in runtime.iterdir()} == (
        live._RUNTIME_DIRECTORIES | live._RUNTIME_FILES
    )
    assert ledger.is_dir()

    monkeypatch.setattr(
        live,
        "initialize",
        lambda *_args, **_kwargs: pytest.fail("existing runtime was reinitialized"),
    )
    reopened, reopened_ledger = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    assert reopened.stat().st_ino == inode
    assert reopened_ledger == ledger


def test_stale_provision_stage_is_never_consumed(tmp_path, monkeypatch):
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "stale-stage-state"
    state.mkdir(mode=0o700)
    stale = state / ".runtime.provision-deadbeef"
    stale.mkdir(mode=0o700)
    (stale / "partial").write_text("not authority")
    (stale / "partial").chmod(0o600)

    runtime, _ledger = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )

    assert runtime.name == "runtime"
    assert stale.is_dir()
    assert (stale / "partial").read_text() == "not authority"


def test_post_rename_sync_failure_blocks_listener_but_restart_reuses_complete_runtime(
    tmp_path, monkeypatch
):
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "post-rename-state"
    original_sync = live._fsync_directory
    failed = False

    def fail_once_after_publish(path):
        nonlocal failed
        if path == state and (state / "runtime").is_dir() and not failed:
            failed = True
            raise OSError("synthetic parent sync failure")
        return original_sync(path)

    monkeypatch.setattr(live, "_fsync_directory", fail_once_after_publish)
    with pytest.raises(OSError, match="parent sync failure"):
        live._prepare_runtime(
            state, plan, age_binary=age, age_recipient=recipient
        )
    assert (state / "runtime" / "runtime.json").is_file()

    monkeypatch.setattr(live, "_fsync_directory", original_sync)
    monkeypatch.setattr(
        live,
        "initialize",
        lambda *_args, **_kwargs: pytest.fail("published runtime was reinitialized"),
    )
    runtime, _ledger = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    assert runtime == state / "runtime"


def test_runtime_publication_collision_preserves_the_appeared_final_directory(
    tmp_path, monkeypatch
):
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "publication-collision"

    def collide(_stage, destination):
        destination.mkdir(mode=0o700)
        marker = destination / "foreign"
        marker.write_text("preserve")
        marker.chmod(0o600)
        raise PolicyError("runtime appeared during provisioning")

    monkeypatch.setattr(live, "_rename_noreplace", collide)
    with pytest.raises(PolicyError, match="appeared during provisioning"):
        live._prepare_runtime(
            state, plan, age_binary=age, age_recipient=recipient
        )

    assert (state / "runtime" / "foreign").read_text() == "preserve"
    assert not any(
        item.name.startswith(".runtime.provision-") for item in state.iterdir()
    )


def test_unprovisioned_dispatch_is_nonmutating(tmp_path, monkeypatch):
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "unprovisioned-state"
    state.mkdir(mode=0o700)

    with pytest.raises(PolicyError, match="policy source is not provisioned"):
        live._prepare_runtime(
            state,
            plan,
            age_binary=age,
            age_recipient=recipient,
            provision=False,
        )

    assert list(state.iterdir()) == []


def test_partial_final_runtime_blocks_without_repair(tmp_path, monkeypatch):
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / "partial-final-state"
    state.mkdir(mode=0o700)
    partial = state / "runtime"
    partial.mkdir(mode=0o700)
    marker = partial / "partial"
    marker.write_text("preserve for review")
    marker.chmod(0o600)

    with pytest.raises(PolicyError, match="runtime layout"):
        live._prepare_runtime(
            state, plan, age_binary=age, age_recipient=recipient
        )

    assert marker.read_text() == "preserve for review"


@pytest.mark.parametrize(
    "relative",
    (".", "runtime.json", "audit"),
    ids=("root", "file", "directory"),
)
def test_runtime_group_drift_blocks_without_repair(
    tmp_path, monkeypatch, relative
):
    alternate_gid = next(
        (gid for gid in os.getgroups() if gid != os.getegid()), None
    )
    if alternate_gid is None:
        pytest.skip("test user has no alternate supplementary group")
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / ("gid-drift-" + relative.replace(".", "root"))
    runtime, _ledger = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    changed = runtime if relative == "." else runtime / relative
    os.chown(changed, -1, alternate_gid)

    with pytest.raises(PolicyError, match="runtime metadata"):
        live._prepare_runtime(
            state, plan, age_binary=age, age_recipient=recipient
        )

    assert changed.stat().st_gid == alternate_gid


@pytest.mark.parametrize("relative", ("ledger", "engagement"))
def test_ledger_root_group_drift_blocks_without_repair(
    tmp_path, monkeypatch, relative
):
    alternate_gid = next(
        (gid for gid in os.getgroups() if gid != os.getegid()), None
    )
    if alternate_gid is None:
        pytest.skip("test user has no alternate supplementary group")
    plan = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    state = tmp_path / ("ledger-gid-drift-" + relative)
    _runtime, ledger_root = live._prepare_runtime(
        state, plan, age_binary=age, age_recipient=recipient
    )
    changed = ledger_root
    if relative == "engagement":
        changed = ledger_root / plan.engagement_id
        changed.mkdir(mode=0o700)
    os.chown(changed, -1, alternate_gid)

    with pytest.raises(PolicyError, match="ledger metadata"):
        live._validate_existing_ledger(ledger_root, plan)

    assert changed.stat().st_gid == alternate_gid


def test_startup_preparation_binds_release_recipient_and_native_age_hash(
    tmp_path, monkeypatch
):
    base = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    plan = replace(base, evidence_recipient=recipient)
    age_sha256 = hashlib.sha256(age.read_bytes()).hexdigest()
    release = replace(
        _release(plan), native_file_sha256={"bin/age": age_sha256}
    )
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)

    runtime, ledger = live.prepare_frozen_portcast_runtime_at_root(
        state_root=tmp_path / "production-state",
        plan=plan,
        verified_release=release,
        age_binary=age,
        age_recipient=recipient,
    )

    assert runtime.is_dir()
    assert ledger.is_dir()

    wrong = replace(release, manifest_sha256="4" * 64)
    with pytest.raises(PolicyError, match="startup binding"):
        live.prepare_frozen_portcast_runtime_at_root(
            state_root=tmp_path / "other-state",
            plan=plan,
            verified_release=wrong,
            age_binary=age,
            age_recipient=recipient,
        )


def test_open_runtime_completes_operational_state_before_read_only_inspect(
    tmp_path, monkeypatch
):
    base = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    plan = replace(base, evidence_recipient=recipient)
    release = replace(
        _release(plan),
        native_file_sha256={
            "bin/age": hashlib.sha256(age.read_bytes()).hexdigest()
        },
    )
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    state = tmp_path / "operational-state"
    runtime = live._open_frozen_portcast_runtime_at_root_core(
        state_root=state,
        plan=plan,
        verified_release=release,
        age_binary=age,
        age_recipient=recipient,
    )

    def snapshot(root):
        result = {}
        for path in sorted(root.rglob("*")):
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            result[relative] = (
                info.st_mode,
                info.st_uid,
                info.st_gid,
                info.st_mtime_ns,
                info.st_ctime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest()
                if path.is_file()
                else None,
            )
        return result

    try:
        before = snapshot(state)
        runtime.audit.ready = lambda: pytest.fail(
            "read-only inspect probed audit write access"
        )
        assert live._inspect_prepared_portcast_state_core(runtime, plan, state) is None
        assert snapshot(state) == before
    finally:
        live._close_runtime(runtime)


def test_prepared_runtime_executes_once_and_blocks_second_broker(
    tmp_path, monkeypatch
):
    SyntheticClient.instances.clear()
    base = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    plan = replace(base, evidence_recipient=recipient)
    release = replace(
        _release(plan),
        native_file_sha256={
            "bin/age": hashlib.sha256(age.read_bytes()).hexdigest()
        },
    )
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    state = tmp_path / "prepared-execute-state"
    runtime = live._open_frozen_portcast_runtime_at_root_core(
        state_root=state,
        plan=plan,
        verified_release=release,
        age_binary=age,
        age_recipient=recipient,
    )
    try:
        first = live._run_prepared_portcast_action_core(
            runtime, plan, state / "runtime", release, SyntheticClient
        )
        second = live._run_prepared_portcast_action_core(
            runtime, plan, state / "runtime", release, SyntheticClient
        )
    finally:
        live._close_runtime(runtime)

    assert first["status"] == "complete"
    assert first["cleanup_status"] == "passed"
    assert second["status"] == "blocked"
    assert second["automatic_retry"] is False
    assert len(SyntheticClient.instances) == 1
    assert SyntheticClient.instances[0].executions == 1
    assert SyntheticClient.instances[0].closed is True


def test_corrupt_ledger_blocks_operational_open_before_service_listener(
    tmp_path, monkeypatch
):
    base = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    plan = replace(base, evidence_recipient=recipient)
    release = replace(
        _release(plan),
        native_file_sha256={
            "bin/age": hashlib.sha256(age.read_bytes()).hexdigest()
        },
    )
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    state = tmp_path / "corrupt-ledger-state"
    runtime = live._open_frozen_portcast_runtime_at_root_core(
        state_root=state,
        plan=plan,
        verified_release=release,
        age_binary=age,
        age_recipient=recipient,
    )
    live._close_runtime(runtime)
    ledger = next((state / "ledger").rglob("ledger.sqlite3"))
    ledger.write_bytes(b"not a sqlite database")

    with pytest.raises(PolicyError, match="ledger"):
        live._open_frozen_portcast_runtime_at_root_core(
            state_root=state,
            plan=plan,
            verified_release=release,
            age_binary=age,
            age_recipient=recipient,
        )
    assert ledger.read_bytes() == b"not a sqlite database"


def test_corrupt_audit_state_blocks_operational_open_without_repair(
    tmp_path, monkeypatch
):
    base = _use_synthetic_open_window(monkeypatch)
    age, recipient = _age_identity(tmp_path)
    plan = replace(base, evidence_recipient=recipient)
    release = replace(
        _release(plan),
        native_file_sha256={
            "bin/age": hashlib.sha256(age.read_bytes()).hexdigest()
        },
    )
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    state = tmp_path / "corrupt-audit-state"
    runtime = live._open_frozen_portcast_runtime_at_root_core(
        state_root=state,
        plan=plan,
        verified_release=release,
        age_binary=age,
        age_recipient=recipient,
    )
    live._close_runtime(runtime)
    audit_state = state / "runtime/audit/.audit-state.json"
    audit_state.write_bytes(b'{"invalid":true}\n')

    with pytest.raises(PolicyError, match="operational state"):
        live._open_frozen_portcast_runtime_at_root_core(
            state_root=state,
            plan=plan,
            verified_release=release,
            age_binary=age,
            age_recipient=recipient,
        )

    assert audit_state.read_bytes() == b'{"invalid":true}\n'


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
    assert result["execution"] == {
        "reservation_state": None,
        "attempt_count": 0,
        "attempt_state": None,
        "transport_counters": None,
        "wire_counters_verified": False,
        "result_receipt_present": False,
        "failure_stage": None,
    }
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
