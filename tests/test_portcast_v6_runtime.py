from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cptc_harness.contracts import PolicyError, canonical_json
from cptc_harness.integrity import VerifiedRelease
from testing.cptc11_lab import portcast_live as live


def _release(plan):
    return VerifiedRelease(
        plan.release_id,
        "3" * 64,
        {
            "cptc_harness/portcast_identity.py": plan.parser_sha256,
            "testing/cptc11_lab/portcast_broker_worker.py": (
                plan.broker_worker_sha256
            ),
        },
        {plan.profile_id: plan.worker_sha256},
        {plan.profile_id: (plan.worker_sha256,)},
        native_file_sha256={"bin/age": "a" * 64},
    )


def _write_receipt(state_root: Path, plan, value=None) -> Path:
    root = state_root.parent / "predecessors" / "v5"
    root.mkdir(parents=True, mode=0o700)
    path = root / "receipt.json"
    path.write_bytes(
        canonical_json(
            live._expected_v5_predecessor_receipt(plan)
            if value is None
            else value
        )
    )
    path.chmod(0o600)
    return path


def test_v7_is_current_and_v6_remains_historical():
    current = live.load_frozen_portcast_plan()
    historical = live.load_frozen_portcast_plan_v6()

    assert current.schema_version == 7
    assert current.action_id == live._V7_SUCCESSOR_ACTION_ID
    assert current.superseded_v6_action_id == historical.action_id
    assert current.superseded_v6_plan_sha256 == historical.plan_sha256
    assert {
        limit.ceiling
        for limit in live.policy_for_plan(current).budget_limits
        if limit.counter == "tcp_connects"
    } == {2}


def test_v6_binds_exact_canonical_v5_receipt():
    plan = live.load_frozen_portcast_plan()
    raw = canonical_json(live._expected_v5_predecessor_receipt(plan))

    assert len(raw) == 1628
    assert not raw.endswith(b"\n")
    assert hashlib.sha256(raw).hexdigest() == live._V5_STATE_SHA256


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("predecessor_v5_projection_marker_present", True),
        ("predecessor_v5_exec_start_pre_exit_status", 125),
        ("predecessor_v5_charged_tcp_connects", 1),
        ("predecessor_v5_failure_stage", "changed"),
    ),
)
def test_v6_loader_rejects_rehashed_v5_failure_fact_drift(
    tmp_path, monkeypatch, field, value
):
    document = json.loads(live._V6_PLAN_PATH.read_bytes())
    document[field] = value
    unsigned = dict(document)
    unsigned.pop("plan_sha256")
    document["plan_sha256"] = hashlib.sha256(
        live._canonical(unsigned)
    ).hexdigest()
    changed = tmp_path / "changed-v6.json"
    changed.write_bytes(live._canonical(document))
    monkeypatch.setattr(live, "_V6_PLAN_PATH", changed)

    with pytest.raises(PolicyError, match="v5 predecessor binding"):
        live.load_frozen_portcast_plan_v6()


def test_v6_accepts_root_manager_receipt_in_synthetic_storage(tmp_path):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "runtime"
    _write_receipt(state_root, plan)

    snapshot = live._verify_v5_predecessor_receipt(state_root, plan)

    assert snapshot == live._expected_v5_predecessor_receipt(plan)
    assert snapshot["runtime_tree"] == [
        {"kind": "directory", "mode": 0o700, "path": "."}
    ]


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("projection_marker_present", True),
        ("admission_marker_present", False),
        ("exec_start_pre_exit_status", 125),
        (
            "runtime_tree",
            [
                {"kind": "directory", "mode": 0o700, "path": "."},
                {"kind": "file", "mode": 0o600, "path": "result.json"},
            ],
        ),
    ),
)
def test_v6_rejects_mutated_v5_receipt(tmp_path, mutation, value):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "runtime"
    receipt = live._expected_v5_predecessor_receipt(plan)
    receipt[mutation] = value
    _write_receipt(state_root, plan, receipt)

    with pytest.raises(PolicyError, match="state digest"):
        live._verify_v5_predecessor_receipt(state_root, plan)


def test_v6_rejects_receipt_with_a_trailing_newline(tmp_path):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "runtime"
    path = _write_receipt(state_root, plan)
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(PolicyError, match="state digest"):
        live._verify_v5_predecessor_receipt(state_root, plan)


def test_v6_rejects_a_symlinked_predecessor_receipt_path(tmp_path):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "runtime"
    real = tmp_path / "real" / "v5"
    real.mkdir(parents=True, mode=0o700)
    (real / "receipt.json").write_bytes(
        canonical_json(live._expected_v5_predecessor_receipt(plan))
    )
    (tmp_path / "predecessors").symlink_to(real.parent, target_is_directory=True)

    with pytest.raises(PolicyError, match="symlink"):
        live._verify_v5_predecessor_receipt(state_root, plan)


def test_v6_receipt_precedes_runtime_creation(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan()
    release = _release(plan)
    events = []
    monkeypatch.setattr(
        live, "_age_configuration", lambda *args: {"age_sha256": "a" * 64}
    )
    monkeypatch.setattr(
        live,
        "validate_current_release",
        lambda _plan: (events.append("release"), release)[1],
    )
    monkeypatch.setattr(
        live,
        "_verify_v7_predecessor_receipts",
        lambda *args: events.append("predecessor"),
    )
    monkeypatch.setattr(
        live,
        "_prepare_runtime",
        lambda *args, **kwargs: (
            events.append("runtime"),
            (tmp_path / "runtime", tmp_path / "ledger"),
        )[1],
    )

    live.prepare_frozen_portcast_runtime_at_root(
        state_root=tmp_path,
        plan=plan,
        verified_release=release,
        age_binary=tmp_path / "age",
        age_recipient=plan.evidence_recipient,
    )

    assert events == ["release", "predecessor", "runtime"]


def test_v6_mutated_receipt_blocks_before_broker(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan()
    release = _release(plan)
    state_root = tmp_path / "runtime"
    path = _write_receipt(state_root, plan)
    path.write_bytes(path.read_bytes() + b"\n")
    called = []
    runtime = SimpleNamespace(
        _portcast_verified_release=release,
        audit=SimpleNamespace(),
        ledger=object(),
    )
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    monkeypatch.setattr(live, "_replay_metadata", lambda *args: None)

    with pytest.raises(PolicyError, match="state digest"):
        live._run_prepared_portcast_action_core(
            runtime,
            plan,
            state_root / "v6" / "runtime",
            release,
            lambda *_args: called.append("factory"),
        )

    assert called == []


def test_v6_success_then_replay_creates_only_one_broker(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan()
    release = _release(plan)
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

    replay = iter((None, {"status": "complete", "automatic_retry": False}))
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    monkeypatch.setattr(live, "_replay_metadata", lambda *args: next(replay))
    monkeypatch.setattr(
        live,
        "_verify_v7_predecessor_receipts",
        lambda *args: events.append("predecessor") or {},
    )
    monkeypatch.setattr(
        live,
        "_execute_action",
        lambda *args: events.append("execute") or {"status": "complete"},
    )

    def factory(_ledger, _release):
        events.append("factory")
        return object()

    first = live._run_prepared_portcast_action_core(
        RuntimeView(), plan, tmp_path / "v6" / "runtime", release, factory
    )
    second = live._run_prepared_portcast_action_core(
        RuntimeView(), plan, tmp_path / "v6" / "runtime", release, factory
    )

    assert first["status"] == second["status"] == "complete"
    assert events == [
        "predecessor",
        "audit:profile_predecessor_snapshot_bound",
        "factory",
        "attach",
        "audit:profile_release_verified",
        "execute",
    ]


def test_v6_unbound_release_blocks_before_receipt_and_broker(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan()
    release = _release(plan)
    called = []
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    monkeypatch.setattr(
        live,
        "_verify_v7_predecessor_receipts",
        lambda *args: called.append("predecessor"),
    )

    with pytest.raises(PolicyError, match="release binding"):
        live._run_prepared_portcast_action_core(
            SimpleNamespace(),
            plan,
            tmp_path / "v6" / "runtime",
            replace(release, manifest_sha256="4" * 64),
            lambda *_args: called.append("factory"),
        )

    assert called == []
