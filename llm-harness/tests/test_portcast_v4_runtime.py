from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from cptc_harness.contracts import PolicyError, canonical_json
from cptc_harness.ledger import Ledger
from cptc_harness.policy import policy_document
from cptc_harness.runtime import initialize
from cptc_harness.storage import write_json
from testing.cptc11_lab import portcast_live as live
from testing.cptc11_lab import portcast_service as service


V3_FILE_SHA256 = "bea58da1b695dc6e3d4ff681b2f784ee5d31a8466ba4a858df49afc308e3f64c"
V3_PLAN_SHA256 = "cb057ddfe09076b781fecb84f3172294ff3aa7409ee2544e52f30043a0dbe936"


def _fake_age(tmp_path: Path) -> Path:
    age = tmp_path / "age"
    age.write_bytes(b"synthetic pinned age fixture\n")
    age.chmod(0o700)
    return age


def _seed_aborted_v3(tmp_path: Path):
    plan = live.load_frozen_portcast_plan_v4()
    v3 = live.load_frozen_portcast_plan_v3()
    age = _fake_age(tmp_path)
    predecessor = tmp_path / live._V3_PREDECESSOR_DIRECTORY
    predecessor.mkdir(mode=0o700)
    lock = predecessor / ".provision.lock"
    lock.touch(mode=0o600)
    policy_source = predecessor / "policy-source.json"
    write_json(policy_source, policy_document(live.policy_for_plan(v3)))
    initialize(
        predecessor / "runtime",
        policy_source,
        recipient=v3.evidence_recipient,
        age_binary=age,
    )
    ledger_directory = tmp_path / "ledger" / plan.predecessor_engagement_id
    ledger = Ledger(
        ledger_directory,
        plan.engagement_id,
        plan.device_id,
        policy_revision=plan.policy_revision,
    )
    ledger._db.close()
    socket_path = tmp_path / "missing.sock"
    snapshot = live._aborted_v3_state_snapshot(
        predecessor,
        ledger_directory,
        age_binary=age,
        age_recipient=v3.evidence_recipient,
        socket_path=socket_path,
    )
    bound = replace(
        plan,
        predecessor_v3_state_sha256=hashlib.sha256(
            canonical_json(snapshot)
        ).hexdigest(),
    )
    return bound, age, ledger_directory, predecessor, socket_path


def test_v4_plan_binds_all_prior_plans_and_exact_single_request():
    before = {
        path: path.read_bytes()
        for path in (live._V1_PLAN_PATH, live._V2_PLAN_PATH, live._V3_PLAN_PATH)
    }
    plan = live.load_frozen_portcast_plan_v4()
    v3 = live.load_frozen_portcast_plan_v3()

    assert plan.schema_version == 4
    assert plan.engagement_id == "cptc11-dell-validation-portcast-v4"
    assert plan.action_id == "cptc11-portcast-public-identity-action-v4"
    assert plan.plan_id == "cptc11-portcast-public-identity-wave-v4"
    assert plan.request_count == plan.tcp_connection_limit == 1
    assert plan.authentication_attempts == plan.automatic_retries == 0
    assert plan.predecessor_v3_plan_file_sha256 == V3_FILE_SHA256
    assert plan.predecessor_v3_plan_sha256 == V3_PLAN_SHA256
    assert plan.predecessor_v3_action_id == v3.action_id
    assert hashlib.sha256(before[live._V3_PLAN_PATH]).hexdigest() == V3_FILE_SHA256
    assert {path: path.read_bytes() for path in before} == before


def test_v4_plan_carries_zero_v3_traffic_and_two_total_tcp_connections():
    plan = live.load_frozen_portcast_plan_v4()
    policy = live.policy_for_plan(plan)

    assert plan.predecessor_charged_tcp_connects == 1
    assert plan.predecessor_v3_possible_tcp_connects == 0
    assert plan.predecessor_v3_charged_tcp_connects == 0
    assert {
        limit.ceiling
        for limit in policy.budget_limits
        if limit.counter == "tcp_connects"
    } == {2}


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reviewed_by", "approved:other-reviewer"),
        ("window_start", "2026-09-12T05:00:01.000000Z"),
        ("window_end", "2026-09-12T10:59:59.000000Z"),
    ),
)
def test_v4_plan_rejects_recomputed_approval_or_window_drift(
    tmp_path, monkeypatch, field, value
):
    document = json.loads(live._V4_PLAN_PATH.read_text())
    document[field] = value
    document.pop("plan_sha256")
    document["plan_sha256"] = hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    changed = tmp_path / "changed-plan.json"
    changed.write_text(json.dumps(document))
    monkeypatch.setattr(live, "_V4_PLAN_PATH", changed)

    with pytest.raises(PolicyError, match="v4 approval differs"):
        live.load_frozen_portcast_plan_v4()


def test_aborted_v3_snapshot_verifies_without_changing_predecessor(tmp_path):
    plan, age, ledger, predecessor, socket_path = _seed_aborted_v3(tmp_path)
    before = {
        item.relative_to(predecessor).as_posix(): (
            item.lstat().st_mode,
            item.lstat().st_mtime_ns,
            item.read_bytes() if item.is_file() else None,
        )
        for item in (predecessor, *predecessor.rglob("*"))
    }

    snapshot = live._verify_aborted_v3_state(
        tmp_path,
        ledger,
        plan,
        age_binary=age,
        age_recipient=plan.evidence_recipient,
        socket_path=socket_path,
    )

    assert snapshot["broker_socket_present"] is False
    assert snapshot["target_traffic"] is False
    after = {
        item.relative_to(predecessor).as_posix(): (
            item.lstat().st_mode,
            item.lstat().st_mtime_ns,
            item.read_bytes() if item.is_file() else None,
        )
        for item in (predecessor, *predecessor.rglob("*"))
    }
    assert after == before


@pytest.mark.parametrize("mutation", ("result", "mode", "socket", "ledger"))
def test_aborted_v3_snapshot_rejects_any_prior_state_drift(tmp_path, mutation):
    plan, age, ledger_path, predecessor, socket_path = _seed_aborted_v3(tmp_path)
    if mutation == "result":
        result = predecessor / "runtime/results/unexpected.json"
        result.write_text("{}")
        result.chmod(0o600)
    elif mutation == "mode":
        (predecessor / "runtime/reports").chmod(0o750)
    elif mutation == "socket":
        socket_path.touch(mode=0o600)
    else:
        ledger = Ledger(
            ledger_path,
            plan.engagement_id,
            plan.device_id,
            policy_revision=plan.policy_revision,
        )
        ledger._db.execute(
            "INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                plan.engagement_id,
                plan.device_id,
                plan.predecessor_v3_action_id,
                plan.workspace_id,
                plan.target_id,
                "",
                plan.workflow_id,
                "{}",
                "uncertain",
                "{}",
            ),
        )
        ledger._db.close()

    with pytest.raises(PolicyError):
        live._verify_aborted_v3_state(
            tmp_path,
            ledger_path,
            plan,
            age_binary=age,
            age_recipient=plan.evidence_recipient,
            socket_path=socket_path,
        )


def test_production_v3_predecessor_must_be_read_only(tmp_path, monkeypatch):
    plan, age, ledger, _predecessor, socket_path = _seed_aborted_v3(tmp_path)
    monkeypatch.setattr(live, "_PRODUCTION_RUNTIME_CONTAINER", tmp_path)
    monkeypatch.setattr(
        live.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_flag=0),
    )

    with pytest.raises(PolicyError, match="state is writable"):
        live._verify_aborted_v3_state(
            tmp_path,
            ledger,
            plan,
            age_binary=age,
            age_recipient=plan.evidence_recipient,
            socket_path=socket_path,
        )


def test_production_shaped_read_only_v3_mount_allows_v4_predecessor_check(
    tmp_path, monkeypatch
):
    plan, age, ledger, _predecessor, socket_path = _seed_aborted_v3(tmp_path)
    monkeypatch.setattr(live, "_PRODUCTION_RUNTIME_CONTAINER", tmp_path)
    monkeypatch.setattr(
        live.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_flag=os.ST_RDONLY),
    )

    snapshot = live._verify_aborted_v3_state(
        tmp_path,
        ledger,
        plan,
        age_binary=age,
        age_recipient=plan.evidence_recipient,
        socket_path=socket_path,
    )

    assert snapshot["schema"] == "portcast-aborted-v3-state-v1"
    assert snapshot["target_traffic"] is False


def test_v4_predecessor_check_precedes_runtime_credentials_and_listener():
    prepare_source = inspect.getsource(
        live.prepare_frozen_portcast_runtime_at_root
    )
    service_source = inspect.getsource(service.main)

    assert prepare_source.index("_verify_aborted_v3_state") < prepare_source.index(
        "return _prepare_runtime"
    )
    assert service_source.index("open_frozen_portcast_runtime_at_root") < (
        service_source.index("_load_service_credentials()")
    )
    assert service_source.index("_load_service_credentials()") < (
        service_source.index("service.serve()")
    )
