from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cptc_harness.contracts import OperationRequest, PolicyError, canonical_json, to_json
from cptc_harness.integrity import VerifiedRelease
from cptc_harness.ledger import Ledger
from cptc_harness.profile_runtime.service_client import validate_portcast_result_v5
from cptc_harness.storage import write_json
from cptc_harness.policy import policy_document
from testing.cptc11_lab import portcast_live as live


def _v5_document() -> dict[str, object]:
    value = json.loads(live._V4_PLAN_PATH.read_bytes())
    value.update(
        {
            "schema_version": 5,
            "engagement_id": live._V5_SUCCESSOR_ENGAGEMENT_ID,
            "action_id": live._V5_SUCCESSOR_ACTION_ID,
            "plan_id": live._V5_SUCCESSOR_PLAN_ID,
            "reviewed_by": live._V5_REVIEWED_BY,
            "window_start": live._V5_WINDOW_START,
            "window_end": live._V5_WINDOW_END,
            "predecessor_v4_plan_file_sha256": live._V4_PLAN_FILE_SHA256,
            "predecessor_v4_plan_sha256": live._V4_PLAN_SHA256,
            "predecessor_v4_action_id": live._SUCCESSOR_ACTION_ID,
            "predecessor_v4_engagement_id": live._SUCCESSOR_ENGAGEMENT_ID,
            "predecessor_v4_release_manifest_sha256": live._V4_RELEASE_MANIFEST_SHA256,
            "predecessor_v4_worker_sha256": value["worker_sha256"],
            "predecessor_v4_broker_worker_sha256": value["broker_worker_sha256"],
            "predecessor_v4_profile_worker_sha256": value["profile_worker_sha256"],
            "predecessor_v4_target_sha256": value["target_sha256"],
            "predecessor_v4_request_sha256": value["request_sha256"],
            "predecessor_v4_output_bytes": 16384,
            "predecessor_v4_state_sha256": "c" * 64,
            "predecessor_v4_continuation_row_sha256": "d" * 64,
            "predecessor_v4_failure_stage": live._V4_FAILURE_STAGE,
            "predecessor_v4_stop_reason": live._V4_STOP_REASON,
            "predecessor_v4_broker_socket_opened": False,
            "predecessor_v4_credentials_loaded": False,
            "predecessor_v4_target_traffic": False,
            "predecessor_v4_first_byte_observed": False,
            "predecessor_v4_result_present": False,
            "predecessor_v4_possible_tcp_connects": 0,
            "predecessor_v4_charged_tcp_connects": 0,
        }
    )
    request = OperationRequest(
        value["action_id"], value["workspace_id"], value["device_id"],
        value["operator_id"], value["module_id"], live._target(),
        {"profile_id": value["profile_id"]}, "operator", None,
        value["policy_revision"], value["workflow_id"],
    )
    value["request_sha256"] = hashlib.sha256(
        canonical_json(to_json(request))
    ).hexdigest()
    unsigned = dict(value)
    unsigned.pop("plan_sha256")
    value["plan_sha256"] = hashlib.sha256(live._canonical(unsigned)).hexdigest()
    return value


def _synthetic_v5_release(plan):
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


def test_v5_loader_accepts_a_synthetic_copied_document(tmp_path, monkeypatch):
    path = tmp_path / "portcast-live-plan-v5.json"
    path.write_bytes(live._canonical(_v5_document()))
    monkeypatch.setattr(live, "_V5_PLAN_PATH", path)
    monkeypatch.setattr(live, "_PLAN_PATH", path)

    plan = live.load_frozen_portcast_plan_v5()

    assert plan.schema_version == 5
    assert plan.action_id == live._V5_SUCCESSOR_ACTION_ID
    assert {
        limit.ceiling
        for limit in live.policy_for_plan(plan).budget_limits
        if limit.counter == "tcp_connects"
    } == {2}
    assert len(plan.plan_sha256) == 64


def test_v5_runtime_uses_a_fresh_current_engagement_ledger(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan_v5()
    root = tmp_path / "v5"
    root.mkdir(mode=0o700)
    (root / "runtime").mkdir(mode=0o700)
    write_json(root / "policy-source.json", policy_document(live.policy_for_plan(plan)))
    monkeypatch.setattr(live, "_validate_runtime_tree", lambda *args, **kwargs: None)

    runtime_root, ledger_root = live._prepare_runtime_unlocked(
        root, plan, age_binary=None, age_recipient=None
    )

    assert runtime_root == root / "runtime"
    assert ledger_root == root / "ledger"
    assert ledger_root != root.parent / "ledger" / plan.predecessor_engagement_id
    assert not (ledger_root / plan.engagement_id / "ledger.sqlite3").exists()


def test_v5_predecessor_proof_precedes_runtime_creation(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan_v5()
    release = VerifiedRelease(
        plan.release_id,
        "3" * 64,
        {
            "cptc_harness/portcast_identity.py": plan.parser_sha256,
            "testing/cptc11_lab/portcast_broker_worker.py": plan.broker_worker_sha256,
        },
        {plan.profile_id: plan.worker_sha256},
        {plan.profile_id: (plan.worker_sha256,)},
        native_file_sha256={"bin/age": "a" * 64},
    )
    events = []
    monkeypatch.setattr(live, "_age_configuration", lambda *args: {"age_sha256": "a" * 64})
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: (events.append("release"), release)[1])
    monkeypatch.setattr(live, "_verify_v5_predecessors", lambda *args, **kwargs: events.append("predecessors"))
    monkeypatch.setattr(live, "_prepare_runtime", lambda *args, **kwargs: (events.append("runtime"), (tmp_path / "runtime", tmp_path / "ledger"))[1])

    live.prepare_frozen_portcast_runtime_at_root(
        state_root=tmp_path,
        plan=plan,
        verified_release=release,
        age_binary=tmp_path / "age",
        age_recipient=plan.evidence_recipient,
    )

    assert events == ["release", "predecessors", "runtime"]


def test_v5_success_then_replay_never_creates_a_second_broker(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan_v5()
    release = _synthetic_v5_release(plan)
    events = []

    class Audit:
        def emit(self, event):
            events.append(f"audit:{event.kind}")

    class RuntimeView:
        audit = Audit()
        ledger = object()

        def __init__(self):
            self._portcast_verified_release = release

        def attach_profile_wire_broker(self, _broker):
            events.append("attach")

    runtime = RuntimeView()
    replay = iter((None, {"status": "complete", "automatic_retry": False}))
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    monkeypatch.setattr(live, "_replay_metadata", lambda *args: next(replay))
    monkeypatch.setattr(live, "read_private", lambda *args: b'{"age_binary":"/tmp/age"}')
    monkeypatch.setattr(live, "_verify_aborted_v3_state", lambda *args, **kwargs: events.append("v3") or {"state": "v3"})
    monkeypatch.setattr(live, "_v4_predecessor_state_snapshot", lambda *args, **kwargs: events.append("v4") or {"state": "v4"})
    monkeypatch.setattr(live, "_execute_action", lambda *args: events.append("execute") or {"status": "complete"})

    def factory(_ledger, _release):
        events.append("factory")
        return object()

    first = live._run_prepared_portcast_action_core(
        runtime, plan, tmp_path / "v5" / "runtime", release, factory
    )
    reopened = RuntimeView()
    second = live._run_prepared_portcast_action_core(
        reopened, plan, tmp_path / "v5" / "runtime", release, factory
    )

    assert first["status"] == second["status"] == "complete"
    assert events == [
        "v3", "v4", "audit:profile_predecessor_snapshot_bound",
        "factory", "attach", "audit:profile_release_verified", "execute",
    ]


def test_v5_stale_release_is_rejected_before_broker_factory(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan_v5()
    release = _synthetic_v5_release(plan)
    stale = replace(release, manifest_sha256="4" * 64)
    called = []
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    monkeypatch.setattr(live, "_require_open_window", lambda _plan: None)

    with pytest.raises(PolicyError, match="release binding"):
        live._run_prepared_portcast_action_core(
            SimpleNamespace(_portcast_verified_release=release),
            plan, tmp_path / "v5" / "runtime", stale,
            lambda *_args: called.append(True),
        )

    with pytest.raises(PolicyError, match="frozen plan"):
        live.run_prepared_portcast_action(
            SimpleNamespace(_portcast_verified_release=release),
            plan,
            tmp_path,
            stale,
            lambda *_args: called.append(True),
        )

    assert called == []


def test_v5_uncertain_replay_cannot_retry_the_worker(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan_v5()
    release = _synthetic_v5_release(plan)
    called = []
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    monkeypatch.setattr(
        live,
        "_replay_metadata",
        lambda *args: {"status": "uncertain", "automatic_retry": False},
    )

    result = live._run_prepared_portcast_action_core(
        SimpleNamespace(_portcast_verified_release=release),
        plan, tmp_path / "v5" / "runtime", release,
        lambda *_args: called.append(True),
    )

    assert result == {"status": "uncertain", "automatic_retry": False}
    assert called == []


def test_v5_unbound_runtime_is_rejected_before_broker_factory(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan_v5()
    release = _synthetic_v5_release(plan)
    called = []
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)

    with pytest.raises(PolicyError, match="release binding"):
        live._run_prepared_portcast_action_core(
            SimpleNamespace(), plan, tmp_path / "v5" / "runtime", release,
            lambda *_args: called.append(True),
        )

    assert called == []


def test_v5_open_does_not_record_a_continuation(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan_v5()
    release = VerifiedRelease(
        plan.release_id,
        "3" * 64,
        {
            "cptc_harness/portcast_identity.py": plan.parser_sha256,
            "testing/cptc11_lab/portcast_broker_worker.py": plan.broker_worker_sha256,
        },
        {plan.profile_id: plan.worker_sha256},
        {plan.profile_id: (plan.worker_sha256,)},
    )
    class DB:
        def execute(self, query):
            return self
        def fetchall(self):
            return [("ok",)]
    class Audit:
        def ready(self): return True
        def verify(self): return type("V", (), {"valid": True})()
        def profile_inspection_snapshot(self, _action): return None
    class LedgerView:
        _db = DB()
        def reservation_state(self, _action): return None
    class FakeRuntime:
        def __init__(self, root, **kwargs):
            self.root = Path(root).absolute()
            self.ledger_root = Path(kwargs.get("ledger_root", kwargs.get("ledger_directory"))).absolute()
            self.ledger = LedgerView()
            self.audit = Audit()
    called = []
    monkeypatch.setattr(live, "_require_open_window", lambda _plan: None)
    monkeypatch.setattr(live, "prepare_frozen_portcast_runtime_at_root", lambda **kwargs: (tmp_path / "runtime", tmp_path / "ledger"))
    monkeypatch.setattr(live, "_validate_existing_ledger", lambda *args: None)
    monkeypatch.setattr(live, "_record_profile_continuation", lambda *args: called.append(True))
    monkeypatch.setattr(live, "Runtime", FakeRuntime)

    runtime = live._open_frozen_portcast_runtime_at_root_core(
        state_root=tmp_path,
        plan=plan,
        verified_release=release,
        age_binary=tmp_path / "age",
        age_recipient=plan.evidence_recipient,
    )

    assert called == []
    assert runtime.ledger_root == (tmp_path / "ledger").absolute()


@pytest.mark.parametrize("mutation, expected", (("layout", "layout"), ("lock", "provision lock"), ("policy", "policy|unknown")))
def test_v5_rejects_outer_v4_state_mutation(tmp_path, monkeypatch, mutation, expected):
    plan = live.load_frozen_portcast_plan_v5()
    v4 = live.load_frozen_portcast_plan_v4()
    root = tmp_path / "v4"
    root.mkdir(mode=0o700)
    (root / ".provision.lock").touch(mode=0o600)
    write_json(root / "policy-source.json", policy_document(live.policy_for_plan(v4)))
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    for name in ("audit", "results", "reports"):
        (runtime / name).mkdir(mode=0o700)
    monkeypatch.setattr(live, "_validate_runtime_tree", lambda *args, **kwargs: None)
    monkeypatch.setattr(live, "_ledger_action_counts", lambda *args, **kwargs: {})
    if mutation == "layout":
        (root / "runtime").rename(root / "unexpected")
    elif mutation == "lock":
        (root / ".provision.lock").write_bytes(b"x")
    else:
        write_json(root / "policy-source.json", {})

    with pytest.raises(PolicyError, match=expected):
        live._v4_predecessor_state_snapshot(
            tmp_path,
            tmp_path / "ledger",
            plan,
            age_binary=tmp_path / "age",
            age_recipient=plan.evidence_recipient,
        )


def test_v5_historical_ledger_row_is_read_only_and_unchanged(tmp_path):
    ledger_dir = tmp_path / "ledger"
    ledger = Ledger(ledger_dir, "cptc11-dell-validation", "device", policy_revision="p")
    values = {key: "x" for key in live._CONTINUATION_ROW_FIELDS}
    values.update({
        "predecessor_engagement": "old-engagement",
        "predecessor_action_id": "old-action",
        "predecessor_plan_id": "old-plan",
        "predecessor_raw_failure_stage": None,
        "predecessor_stage": "legacy_target_open_unacknowledged",
        "predecessor_attempt_count": 1,
        "predecessor_observed_tcp_connects": 0,
        "predecessor_possible_tcp_connects": 1,
        "predecessor_charged_tcp_connects": 1,
        "predecessor_observed_udp_datagrams": 0,
        "predecessor_charged_udp_datagrams": 0,
        "predecessor_observed_protocol_requests": 0,
        "predecessor_charged_protocol_requests": 0,
        "predecessor_observed_tx_bytes": 0,
        "predecessor_charged_tx_bytes": 0,
        "predecessor_observed_rx_bytes": 0,
        "predecessor_charged_rx_bytes": 0,
        "predecessor_evidence_bytes": 0,
        "predecessor_first_byte_at": None,
        "predecessor_wire_event_count": 0,
        "predecessor_outcome": "uncertain",
        "predecessor_cleanup_status": "passed",
        "predecessor_stop_reason": "transport outcome uncertain",
        "predecessor_reconciliation_reason": "clock-source-unavailable",
        "predecessor_plan_sha256": "a" * 64,
        "predecessor_release_manifest_sha256": "b" * 64,
        "predecessor_profile_worker_sha256": "c" * 64,
        "predecessor_broker_worker_sha256": "d" * 64,
        "predecessor_audit_chain_tail_sha256": "e" * 64,
        "predecessor_audit_snapshot_sha256": "f" * 64,
        "predecessor_reconciliation_sha256": "0" * 64,
        "predecessor_proof_sha256": "1" * 64,
        "successor_engagement": "cptc11-dell-validation-portcast-v4",
        "successor_action_id": "cptc11-portcast-public-identity-action-v4",
        "created_at": "2026-09-12T06:00:00.000000Z",
    })
    columns = ",".join(live._CONTINUATION_ROW_FIELDS)
    ledger._db.execute(
        f"INSERT INTO profile_continuations ({columns}) VALUES ({','.join('?' for _ in values)})",
        tuple(values[key] for key in live._CONTINUATION_ROW_FIELDS),
    )
    ledger._db.commit()
    ledger._db.close()
    database = ledger_dir / "ledger.sqlite3"
    before = database.read_bytes()
    row = live._read_continuation_row(
        ledger_dir,
        successor_engagement=values["successor_engagement"],
        successor_action_id=values["successor_action_id"],
    )
    assert row == values
    ro = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("UPDATE profile_continuations SET successor_device='tampered'")
    ro.close()
    assert database.read_bytes() == before


def test_v5_loader_rejects_fixed_v4_startup_fact_drift(tmp_path, monkeypatch):
    value = _v5_document()
    value["predecessor_v4_failure_stage"] = "changed"
    unsigned = dict(value)
    unsigned.pop("plan_sha256")
    value["plan_sha256"] = hashlib.sha256(live._canonical(unsigned)).hexdigest()
    path = tmp_path / "changed-v5.json"
    path.write_bytes(live._canonical(value))
    monkeypatch.setattr(live, "_V5_PLAN_PATH", path)
    monkeypatch.setattr(live, "_PLAN_PATH", path)

    with pytest.raises(PolicyError, match="failure stage"):
        live.load_frozen_portcast_plan_v5()


def test_v5_client_accepts_only_the_v5_action():
    metadata = {
        "action_id": live._V5_SUCCESSOR_ACTION_ID,
        "audit_verified": True,
        "automatic_retry": False,
        "cleanup_status": "passed",
        "execution": {
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
        },
        "profile_id": "web.http_jellyfin_public_identity",
        "receipt_outcome": "complete",
        "status": "complete",
        "workspace": "cptc11-portcast-workspace",
    }
    assert validate_portcast_result_v5(metadata) == metadata
    with pytest.raises(PolicyError):
        validate_portcast_result_v5({**metadata, "action_id": "v4"})


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("created_at", "2026-09-12T06:00:01.000000Z"),
        ("predecessor_plan_sha256", "b" * 64),
        ("successor_action_id", "tampered-action"),
    ),
)
def test_v4_continuation_digest_binds_every_row_field(field, value):
    row = {key: None for key in live._CONTINUATION_ROW_FIELDS}
    row["created_at"] = "2026-09-12T06:00:00.000000Z"
    first = live._continuation_row_digest(row)
    row[field] = value
    assert live._continuation_row_digest(row) != first
