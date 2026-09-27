from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from cptc_harness.contracts import PolicyError
from testing.cptc11_lab import portcast_live as live


def _rehash(value: dict[str, object]) -> dict[str, object]:
    value = dict(value)
    value.pop("plan_sha256", None)
    value["plan_sha256"] = hashlib.sha256(live._canonical(value)).hexdigest()
    return value


def _write_v6_unused_receipt(state_root: Path, plan, value=None) -> Path:
    root = state_root.parent / "predecessors" / "v6-unused"
    root.mkdir(parents=True, mode=0o700)
    path = root / "receipt.json"
    document = (
        live._expected_v6_unused_receipt(plan) if value is None else value
    )
    path.write_bytes(live.canonical_json(document))
    path.chmod(0o600)
    return path


def test_v7_is_current_and_v6_is_immutable_superseded_history():
    current = live.load_frozen_portcast_plan()
    historical = live.load_frozen_portcast_plan_v6()

    assert current.schema_version == 7
    assert current.action_id == live._V7_SUCCESSOR_ACTION_ID
    assert historical.schema_version == 6
    assert historical.action_id == live._V6_SUCCESSOR_ACTION_ID
    assert current.superseded_v6_plan_sha256 == historical.plan_sha256
    assert current.superseded_v6_plan_file_sha256 == hashlib.sha256(
        live._V6_PLAN_PATH.read_bytes()
    ).hexdigest()
    assert current.superseded_v6_deployed is False
    assert current.superseded_v6_service_started is False
    assert current.superseded_v6_target_capability_created is False
    assert current.superseded_v6_target_traffic is False
    assert current.superseded_v6_first_byte_observed is False


def test_v7_uses_a_new_action_and_request_but_the_same_reviewed_target():
    current = live.load_frozen_portcast_plan()
    historical = live.load_frozen_portcast_plan_v6()

    assert current.action_id != historical.action_id
    assert current.engagement_id != historical.engagement_id
    assert current.plan_id != historical.plan_id
    assert current.request_sha256 != historical.request_sha256
    assert current.target_sha256 == historical.target_sha256
    assert current.profile_id == historical.profile_id
    assert current.tcp_connection_limit == 1
    assert current.automatic_retries == 0
    assert current.authentication_attempts == 0


def test_v7_window_starts_after_the_unused_v6_window_closed():
    plan = live.load_frozen_portcast_plan()
    start = datetime.fromisoformat(plan.window_start.replace("Z", "+00:00"))
    superseded_end = datetime.fromisoformat(
        plan.superseded_v6_window_end.replace("Z", "+00:00")
    )

    assert start > superseded_end
    assert start.tzinfo == timezone.utc


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("superseded_v6_deployed", True),
        ("superseded_v6_service_started", True),
        ("superseded_v6_target_capability_created", True),
        ("superseded_v6_target_traffic", True),
        ("superseded_v6_reason", "changed"),
        ("superseded_v6_plan_sha256", "0" * 64),
    ),
)
def test_v7_rejects_rehashed_v6_supersession_drift(
    tmp_path, monkeypatch, field, value
):
    document = json.loads(live._V7_PLAN_PATH.read_bytes())
    document[field] = value
    changed = tmp_path / "changed-v7.json"
    changed.write_bytes(live._canonical(_rehash(document)))
    monkeypatch.setattr(live, "_V7_PLAN_PATH", changed)

    with pytest.raises(PolicyError, match="v6 supersession"):
        live.load_frozen_portcast_plan_v7()


def test_v7_rejects_rehashed_v6_scope_drift(tmp_path, monkeypatch):
    document = json.loads(live._V7_PLAN_PATH.read_bytes())
    document["target_sha256"] = "0" * 64
    changed = tmp_path / "changed-scope-v7.json"
    changed.write_bytes(live._canonical(_rehash(document)))
    monkeypatch.setattr(live, "_V7_PLAN_PATH", changed)

    with pytest.raises(PolicyError, match="successor request binding|superseded scope"):
        live.load_frozen_portcast_plan_v7()


def test_v7_cumulative_tcp_allowance_does_not_charge_unused_v6():
    plan = live.load_frozen_portcast_plan()
    ceilings = {
        item.ceiling
        for item in live.policy_for_plan(plan).budget_limits
        if item.counter == "tcp_connects"
    }

    assert ceilings == {2}
    assert plan.predecessor_charged_tcp_connects == 1
    assert plan.predecessor_v5_charged_tcp_connects == 0


def test_v7_receipt_gate_accepts_only_schema_v6_or_v7(tmp_path):
    plan = live.load_frozen_portcast_plan()

    with pytest.raises(PolicyError, match="requires schema v6 or v7"):
        live._verify_v5_predecessor_receipt(
            tmp_path / "runtime", replace(plan, schema_version=5)
        )


def test_v7_accepts_exact_root_manager_unused_v6_receipt(tmp_path):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "runtime"
    path = _write_v6_unused_receipt(state_root, plan)

    snapshot = live._verify_v6_unused_receipt(state_root, plan)

    assert snapshot == live._expected_v6_unused_receipt(plan)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        plan.superseded_v6_state_receipt_sha256
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("deployment_status", "deployed"),
        ("execution_status", "started"),
        ("target_traffic", True),
        ("first_byte_observed", True),
        ("possible_tcp_connects", 1),
    ),
)
def test_v7_rejects_mutated_unused_v6_receipt(
    tmp_path, field, value
):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "runtime"
    receipt = live._expected_v6_unused_receipt(plan)
    receipt[field] = value
    _write_v6_unused_receipt(state_root, plan, receipt)

    with pytest.raises(PolicyError, match="unused state digest"):
        live._verify_v6_unused_receipt(state_root, plan)


def test_v7_rejects_unused_v6_receipt_with_trailing_newline(tmp_path):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "runtime"
    path = _write_v6_unused_receipt(state_root, plan)
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(PolicyError, match="unused state digest"):
        live._verify_v6_unused_receipt(state_root, plan)


def test_v7_rejects_symlinked_unused_v6_receipt_path(tmp_path):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "runtime"
    real = tmp_path / "real" / "v6-unused"
    real.mkdir(parents=True, mode=0o700)
    (real / "receipt.json").write_bytes(
        live.canonical_json(live._expected_v6_unused_receipt(plan))
    )
    (tmp_path / "predecessors").symlink_to(
        real.parent, target_is_directory=True
    )

    with pytest.raises(PolicyError, match="symlink"):
        live._verify_v6_unused_receipt(state_root, plan)
