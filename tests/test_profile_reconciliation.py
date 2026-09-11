from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import re
import time

import pytest

from cptc_harness.contracts import Bounds, BudgetLimit, PolicyError
from cptc_harness.contracts import canonical_json
import cptc_harness.ledger as ledger_module
from cptc_harness.ledger import Ledger


PRED_ACTION = "cptc11-portcast-public-identity-action-v1"
PRED_PLAN = "cptc11-portcast-public-identity-wave-v1"
PRED_HASH = "1" * 64
NEXT_ACTION = "cptc11-portcast-public-identity-action-v2"
NEXT_PLAN = "cptc11-portcast-public-identity-wave-v2"
NEXT_HASH = "2" * 64
RECON_HASH = "3" * 64
OLD_ENGAGEMENT = "cptc11-dell-validation"
NEW_ENGAGEMENT = "cptc11-dell-validation-portcast-v3"
V3_ACTION = "cptc11-portcast-public-identity-action-v3"
V3_PLAN = "cptc11-portcast-public-identity-wave-v3"
V3_HASH = "7" * 64
WORKSPACE = "cptc11-portcast"
TARGET = "http://172.16.104.153:8096"
WORKFLOW = "portcast-public-identity"


def _ledger(tmp_path):
    return Ledger(tmp_path / "ledger", OLD_ENGAGEMENT, "arch-btw")


def _reconcile(ledger: Ledger, **changes):
    values = {
        "predecessor_action_id": PRED_ACTION,
        "predecessor_plan_id": PRED_PLAN,
        "predecessor_plan_sha256": PRED_HASH,
        "successor_action_id": NEXT_ACTION,
        "successor_plan_id": NEXT_PLAN,
        "successor_plan_sha256": NEXT_HASH,
        "reconciliation_sha256": RECON_HASH,
        "reason_code": "clock-source-unavailable",
    }
    values.update(changes)
    return ledger.reconcile_profile_predecessor(**values)


def _continuation_setup(tmp_path):
    predecessor = _ledger(tmp_path)
    _reconcile(predecessor)
    predecessor.reserve_attempt(
        NEXT_ACTION,
        Bounds(
            actions=1,
            request_limit=1,
            tcp_connects=1,
            protocol_requests=1,
            tx_bytes=1024,
            rx_bytes=1024,
        ),
        "portcast-attempt-v2",
        started_ns=1,
        deadline_ns=1_000_000_001,
        workspace_id=WORKSPACE,
        target_id=TARGET,
        workflow_id=WORKFLOW,
    )
    predecessor.finish_attempt(
        NEXT_ACTION,
        "portcast-attempt-v2",
        state="uncertain",
        ended_ns=2,
    )
    predecessor.finish(NEXT_ACTION, state="uncertain")
    successor = Ledger(
        predecessor.root,
        NEW_ENGAGEMENT,
        predecessor.device_id,
    )
    proof = ledger_module.ProfileContinuationProof(
        predecessor_engagement=OLD_ENGAGEMENT,
        predecessor_action_id=NEXT_ACTION,
        predecessor_plan_id=NEXT_PLAN,
        predecessor_plan_sha256=NEXT_HASH,
        predecessor_release_manifest_sha256="4" * 64,
        predecessor_profile_worker_sha256="d" * 64,
        predecessor_broker_worker_sha256="e" * 64,
        predecessor_audit_chain_tail_sha256="5" * 64,
        predecessor_audit_snapshot_sha256="6" * 64,
        predecessor_raw_failure_stage=None,
        predecessor_stage="legacy_target_open_unacknowledged",
        predecessor_attempt_count=1,
        predecessor_observed_tcp_connects=0,
        predecessor_possible_tcp_connects=1,
        predecessor_charged_tcp_connects=1,
        predecessor_observed_udp_datagrams=0,
        predecessor_charged_udp_datagrams=0,
        predecessor_observed_protocol_requests=0,
        predecessor_charged_protocol_requests=0,
        predecessor_observed_tx_bytes=0,
        predecessor_charged_tx_bytes=0,
        predecessor_observed_rx_bytes=0,
        predecessor_charged_rx_bytes=0,
        predecessor_evidence_bytes=0,
        predecessor_first_byte_at=None,
        predecessor_wire_event_count=0,
        predecessor_outcome="uncertain",
        predecessor_cleanup_status="passed",
        predecessor_stop_reason="transport outcome uncertain",
        reconciliation_sha256=RECON_HASH,
    )
    return predecessor, successor, proof


def _continue(successor: Ledger, proof, **changes):
    values = {
        "proof": proof,
        "successor_action_id": V3_ACTION,
        "successor_plan_id": V3_PLAN,
        "successor_plan_sha256": V3_HASH,
        "successor_workspace_id": WORKSPACE,
        "successor_target_id": TARGET,
        "successor_workflow_id": WORKFLOW,
    }
    values.update(changes)
    return successor.record_profile_continuation(**values)


def _predecessor_rows(ledger: Ledger):
    queries = {
        "reservations": "SELECT * FROM reservations WHERE engagement=? ORDER BY device,request_id",
        "reservation_scopes": "SELECT * FROM reservation_scopes WHERE engagement=? ORDER BY device,request_id,scope_kind,scope_key,counter",
        "reservation_attempts": "SELECT * FROM reservation_attempts WHERE engagement=? ORDER BY device,request_id,attempt_id",
        "reservation_attempt_events": "SELECT * FROM reservation_attempt_events WHERE engagement=? ORDER BY device,request_id,attempt_id,event_id",
        "profile_reconciliations": "SELECT * FROM profile_reconciliations WHERE engagement=? ORDER BY predecessor_action_id",
        "stops": "SELECT * FROM stops WHERE engagement=?",
    }
    return {
        table: ledger._db.execute(query, (OLD_ENGAGEMENT,)).fetchall()
        for table, query in queries.items()
    }


def test_profile_reconciliation_is_exact_durable_and_idempotent(tmp_path):
    ledger = _ledger(tmp_path)

    first = _reconcile(ledger)
    second = _reconcile(ledger)

    assert first["created"] is True
    assert second == {**first, "created": False}
    stored = ledger.profile_reconciliation(PRED_ACTION)
    assert stored == {key: value for key, value in first.items() if key != "created"}
    assert stored["reservation_absent"] is True
    assert stored["attempt_absent"] is True
    assert stored["target_traffic_absent"] is True
    ledger._db.close()

    reopened = _ledger(tmp_path)
    assert reopened.profile_reconciliation(PRED_ACTION) == stored


@pytest.mark.parametrize(
    "change",
    (
        {"successor_action_id": "cptc11-portcast-public-identity-action-v3"},
        {"successor_plan_sha256": "4" * 64},
        {"reconciliation_sha256": "5" * 64},
        {"reason_code": "different-reason"},
    ),
)
def test_profile_reconciliation_rejects_conflicting_rebind(tmp_path, change):
    ledger = _ledger(tmp_path)
    _reconcile(ledger)

    with pytest.raises(PolicyError, match="binding conflict"):
        _reconcile(ledger, **change)


@pytest.mark.parametrize("history", ("reservation", "attempt", "event", "scope"))
def test_profile_reconciliation_rechecks_zero_dispatch_history_atomically(
    tmp_path, history
):
    ledger = _ledger(tmp_path)
    if history == "reservation":
        ledger.reserve(PRED_ACTION, Bounds(actions=1))
    elif history == "attempt":
        ledger._db.execute(
            """INSERT INTO reservation_attempts(
                   engagement,device,request_id,attempt_id,tcp_connects,
                   udp_datagrams,request_count,request_bytes,response_bytes,
                   elapsed_ms,deadline_ns,started_ns,deadline_exceeded,state)
               VALUES (?,?,?,?,0,0,0,0,0,0,2,1,0,'failed')""",
            (ledger.engagement_id, ledger.device_id, PRED_ACTION, "attempt"),
        )
    elif history == "event":
        ledger._db.execute(
            """INSERT INTO reservation_attempt_events(
                   engagement,device,request_id,attempt_id,event_id,tcp_connects,
                   udp_datagrams,request_count,request_bytes,response_bytes)
               VALUES (?,?,?,?,?,0,0,0,0,0)""",
            (ledger.engagement_id, ledger.device_id, PRED_ACTION, "attempt", "event"),
        )
    else:
        ledger._db.execute(
            """INSERT INTO reservation_scopes(
                   engagement,device,request_id,scope_kind,scope_key,counter,
                   reserved,ceiling) VALUES (?,?,?,?,?,?,?,NULL)""",
            (
                ledger.engagement_id, ledger.device_id, PRED_ACTION,
                "device", ledger.device_id, "actions", 1,
            ),
        )

    with pytest.raises(PolicyError, match="predecessor has durable target state"):
        _reconcile(ledger)
    assert ledger.profile_reconciliation(PRED_ACTION) is None


def test_profile_reconciliation_rejects_predecessor_state_from_another_device(
    tmp_path,
):
    ledger = _ledger(tmp_path)
    other = Ledger(
        ledger.root,
        ledger.engagement_id,
        "other-device",
    )
    other.reserve(PRED_ACTION, Bounds(actions=1))

    with pytest.raises(PolicyError, match="predecessor has durable target state"):
        _reconcile(ledger)

    assert ledger.profile_reconciliation(PRED_ACTION) is None


def test_profile_reconciliation_rejects_stopped_ledger_and_invalid_metadata(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.stop("operator stop")
    with pytest.raises(PolicyError, match="stopped"):
        _reconcile(ledger)

    fresh = _ledger(tmp_path / "fresh")
    with pytest.raises(PolicyError, match="digest"):
        _reconcile(fresh, reconciliation_sha256="not-a-digest")
    with pytest.raises(PolicyError, match="reason"):
        _reconcile(fresh, reason_code="CLOCK SOURCE")


def test_reconciled_predecessor_is_a_permanent_admission_tombstone(tmp_path):
    ledger = _ledger(tmp_path)
    _reconcile(ledger)

    with pytest.raises(PolicyError, match="permanently spent"):
        ledger.reserve(PRED_ACTION, Bounds(actions=1))
    with pytest.raises(PolicyError, match="permanently spent"):
        ledger.reserve_attempt(
            PRED_ACTION,
            Bounds(actions=1, tcp_connects=1),
            "attempt",
            started_ns=time.monotonic_ns(),
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
        )

    assert ledger.reservation_state(PRED_ACTION) is None
    assert ledger.optional_attempt_receipt(PRED_ACTION) is None
    assert ledger._db.execute(
        "SELECT 1 FROM reservation_scopes WHERE request_id=?", (PRED_ACTION,)
    ).fetchone() is None
    successor = ledger.reserve(NEXT_ACTION, Bounds(actions=1))
    assert successor.request_id == NEXT_ACTION


def test_profile_continuation_is_exact_durable_idempotent_and_preserves_predecessor(
    tmp_path,
):
    predecessor, successor, proof = _continuation_setup(tmp_path)
    before = _predecessor_rows(predecessor)

    first = _continue(successor, proof)
    second = _continue(successor, proof)

    assert first["created"] is True
    assert second == {**first, "created": False}
    stored = successor.profile_continuation(OLD_ENGAGEMENT, NEXT_ACTION)
    assert stored == {key: value for key, value in first.items() if key != "created"}
    assert stored == {
        "predecessor_engagement": OLD_ENGAGEMENT,
        "predecessor_device": "arch-btw",
        "predecessor_reconciled_action_id": PRED_ACTION,
        "predecessor_action_id": NEXT_ACTION,
        "predecessor_plan_id": NEXT_PLAN,
        "predecessor_plan_sha256": NEXT_HASH,
        "predecessor_release_manifest_sha256": "4" * 64,
        "predecessor_profile_worker_sha256": "d" * 64,
        "predecessor_broker_worker_sha256": "e" * 64,
        "predecessor_audit_chain_tail_sha256": "5" * 64,
        "predecessor_audit_snapshot_sha256": "6" * 64,
        "predecessor_reconciliation_sha256": RECON_HASH,
        "predecessor_reconciliation_reason": "clock-source-unavailable",
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
        "successor_engagement": NEW_ENGAGEMENT,
        "successor_device": "arch-btw",
        "successor_workspace": WORKSPACE,
        "successor_target": TARGET,
        "successor_workflow": WORKFLOW,
        "successor_action_id": V3_ACTION,
        "successor_plan_id": V3_PLAN,
        "successor_plan_sha256": V3_HASH,
        "predecessor_proof_sha256": hashlib.sha256(
            canonical_json(asdict(proof))
        ).hexdigest(),
        "created_at": first["created_at"],
    }
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z",
        first["created_at"],
    )
    assert _predecessor_rows(predecessor) == before
    with pytest.raises(FrozenInstanceError):
        proof.predecessor_attempt_count = 2

    successor._db.close()
    reopened = Ledger(predecessor.root, NEW_ENGAGEMENT, "arch-btw")
    assert reopened.profile_continuation(OLD_ENGAGEMENT, NEXT_ACTION) == stored
    assert _predecessor_rows(reopened) == before


@pytest.mark.parametrize(
    "column",
    (
        "tcp_connects",
        "udp_datagrams",
        "request_count",
        "request_bytes",
        "response_bytes",
    ),
)
def test_profile_continuation_rejects_nonzero_durable_traffic_counter(
    tmp_path, column
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    successor._db.execute(
        f"UPDATE reservation_attempts SET {column}=1 WHERE engagement=? AND request_id=?",
        (OLD_ENGAGEMENT, NEXT_ACTION),
    )

    with pytest.raises(PolicyError, match="observed counters"):
        _continue(successor, proof)
    assert successor.profile_continuation(OLD_ENGAGEMENT, NEXT_ACTION) is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("predecessor_stage", "target_open", "predecessor stage"),
        ("predecessor_stage", "wire_exchange", "predecessor stage"),
        ("predecessor_raw_failure_stage", "target_open", "raw failure stage"),
        ("predecessor_attempt_count", 2, "attempt count"),
        ("predecessor_observed_tcp_connects", 1, "observed counters"),
        ("predecessor_possible_tcp_connects", 0, "possible TCP"),
        ("predecessor_charged_tcp_connects", 0, "charged TCP"),
        ("predecessor_observed_udp_datagrams", 1, "observed counters"),
        ("predecessor_charged_udp_datagrams", 1, "charged counters"),
        ("predecessor_observed_protocol_requests", 1, "observed counters"),
        ("predecessor_charged_protocol_requests", 1, "charged counters"),
        ("predecessor_observed_tx_bytes", 1, "observed counters"),
        ("predecessor_charged_tx_bytes", 1, "charged counters"),
        ("predecessor_observed_rx_bytes", 1, "observed counters"),
        ("predecessor_charged_rx_bytes", 1, "charged counters"),
        ("predecessor_evidence_bytes", 1, "zero evidence"),
        (
            "predecessor_first_byte_at",
            "2026-09-10T00:00:00.000000Z",
            "first byte",
        ),
        ("predecessor_wire_event_count", 1, "wire event"),
        ("predecessor_outcome", "failed", "uncertain outcome"),
        ("predecessor_cleanup_status", "failed", "cleanup"),
        ("predecessor_stop_reason", "operator stop", "stop reason"),
    ),
)
def test_profile_continuation_rejects_unadmitted_verifier_facts(
    tmp_path, field, value, message
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)

    with pytest.raises(PolicyError, match=message):
        _continue(successor, replace(proof, **{field: value}))
    assert successor.profile_continuation(OLD_ENGAGEMENT, NEXT_ACTION) is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("predecessor_engagement", "wrong-engagement", "predecessor"),
        ("predecessor_action_id", PRED_ACTION, "predecessor"),
        ("predecessor_plan_id", "wrong-plan", "reconciliation"),
        ("predecessor_plan_sha256", "8" * 64, "reconciliation"),
        ("reconciliation_sha256", "9" * 64, "reconciliation"),
        ("predecessor_release_manifest_sha256", "invalid", "digest"),
        ("predecessor_profile_worker_sha256", "invalid", "digest"),
        ("predecessor_broker_worker_sha256", "invalid", "digest"),
        ("predecessor_audit_chain_tail_sha256", "invalid", "digest"),
        ("predecessor_audit_snapshot_sha256", "invalid", "digest"),
    ),
)
def test_profile_continuation_rejects_wrong_predecessor_binding(
    tmp_path, field, value, message
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)

    with pytest.raises(PolicyError, match=message):
        _continue(successor, replace(proof, **{field: value}))


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing-attempt", "exactly one attempt"),
        ("multiple-attempts", "exactly one attempt"),
        ("attempt-not-uncertain", "uncertain outcome"),
        ("reservation-not-uncertain", "uncertain outcome"),
        ("missing-stop", "stopped predecessor"),
        ("wrong-stop-reason", "stop reason"),
        ("wire-event", "wire event"),
        ("discounted-charge", "predecessor TCP charge"),
        ("wrong-reconciliation-reason", "reconciliation reason"),
    ),
)
def test_profile_continuation_rechecks_predecessor_rows_atomically(
    tmp_path, mutation, message
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    if mutation == "missing-attempt":
        successor._db.execute(
            "DELETE FROM reservation_attempts WHERE engagement=? AND request_id=?",
            (OLD_ENGAGEMENT, NEXT_ACTION),
        )
    elif mutation == "multiple-attempts":
        successor._db.execute(
            """INSERT INTO reservation_attempts(
                   engagement,device,request_id,attempt_id,tcp_connects,
                   udp_datagrams,request_count,request_bytes,response_bytes,
                   elapsed_ms,deadline_ns,started_ns,deadline_exceeded,state)
               VALUES (?,?,?,?,0,0,0,0,0,0,3,2,0,'uncertain')""",
            (OLD_ENGAGEMENT, "arch-btw", NEXT_ACTION, "second-attempt"),
        )
    elif mutation == "attempt-not-uncertain":
        successor._db.execute(
            "UPDATE reservation_attempts SET state='failed' WHERE engagement=? AND request_id=?",
            (OLD_ENGAGEMENT, NEXT_ACTION),
        )
    elif mutation == "reservation-not-uncertain":
        successor._db.execute(
            "UPDATE reservations SET state='failed' WHERE engagement=? AND request_id=?",
            (OLD_ENGAGEMENT, NEXT_ACTION),
        )
    elif mutation == "missing-stop":
        successor._db.execute(
            "DELETE FROM stops WHERE engagement=?", (OLD_ENGAGEMENT,)
        )
    elif mutation == "wrong-stop-reason":
        successor._db.execute(
            "UPDATE stops SET reason='operator stop' WHERE engagement=?",
            (OLD_ENGAGEMENT,),
        )
    elif mutation == "wire-event":
        successor._db.execute(
            """INSERT INTO reservation_attempt_events(
                   engagement,device,request_id,attempt_id,event_id,tcp_connects,
                   udp_datagrams,request_count,request_bytes,response_bytes)
               VALUES (?,?,?,?,?,0,0,0,0,0)""",
            (
                OLD_ENGAGEMENT,
                "arch-btw",
                NEXT_ACTION,
                "portcast-attempt-v2",
                "wire-event",
            ),
        )
    elif mutation == "discounted-charge":
        successor._db.execute(
            """UPDATE reservation_scopes SET reserved=0
                WHERE engagement=? AND request_id=?
                  AND scope_kind='target' AND counter='tcp_connects'""",
            (OLD_ENGAGEMENT, NEXT_ACTION),
        )
    else:
        successor._db.execute(
            "UPDATE profile_reconciliations SET reason_code='different-reason' WHERE engagement=? AND successor_action_id=?",
            (OLD_ENGAGEMENT, NEXT_ACTION),
        )

    with pytest.raises(PolicyError, match=message):
        _continue(successor, proof)
    assert successor.profile_continuation(OLD_ENGAGEMENT, NEXT_ACTION) is None


def test_profile_continuation_rejects_conflicting_rebinds_and_successor_reuse(
    tmp_path,
):
    predecessor, successor, proof = _continuation_setup(tmp_path)
    _continue(successor, proof)

    with pytest.raises(PolicyError, match="continuation binding conflict"):
        _continue(
            successor,
            proof,
            successor_action_id="cptc11-portcast-public-identity-action-v4",
        )

    second_engagement = "second-stopped-engagement"
    second_action = "second-action-v2"
    second_plan = "second-plan-v2"
    second_reconciliation_sha256 = "c" * 64
    second = Ledger(predecessor.root, second_engagement, "arch-btw")
    second.reconcile_profile_predecessor(
        predecessor_action_id="second-spent-action",
        predecessor_plan_id="second-plan-v1",
        predecessor_plan_sha256="a" * 64,
        successor_action_id=second_action,
        successor_plan_id=second_plan,
        successor_plan_sha256="b" * 64,
        reconciliation_sha256=second_reconciliation_sha256,
        reason_code="clock-source-unavailable",
    )
    second.reserve_attempt(
        second_action,
        Bounds(tcp_connects=1),
        "second-attempt",
        started_ns=1,
        deadline_ns=100,
        workspace_id=WORKSPACE,
        target_id=TARGET,
        workflow_id=WORKFLOW,
    )
    second.finish_attempt(
        second_action,
        "second-attempt",
        state="uncertain",
        ended_ns=2,
    )
    second.finish(second_action, state="uncertain")
    second_proof = replace(
        proof,
        predecessor_engagement=second_engagement,
        predecessor_action_id=second_action,
        predecessor_plan_id=second_plan,
        predecessor_plan_sha256="b" * 64,
        reconciliation_sha256=second_reconciliation_sha256,
    )

    with pytest.raises(PolicyError, match="continuation binding conflict"):
        _continue(successor, second_proof)


@pytest.mark.parametrize(
    "changes",
    (
        {"successor_action_id": ""},
        {"successor_plan_id": ""},
        {"successor_plan_sha256": "invalid"},
        {"successor_action_id": NEXT_ACTION},
        {"successor_plan_id": NEXT_PLAN},
        {"successor_workspace_id": "different-workspace"},
        {"successor_target_id": "http://192.0.2.10:8096"},
        {"successor_workflow_id": "different-workflow"},
    ),
)
def test_profile_continuation_rejects_invalid_or_reused_successor_identity(
    tmp_path, changes
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)

    with pytest.raises(PolicyError):
        _continue(successor, proof, **changes)


def test_profile_continuation_predecessor_cannot_be_retried_in_new_engagement(
    tmp_path,
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    _continue(successor, proof)

    with pytest.raises(PolicyError, match="continuation predecessor.*permanently spent"):
        successor.reserve(NEXT_ACTION, Bounds(actions=1))
    with pytest.raises(PolicyError, match="continuation predecessor.*permanently spent"):
        successor.reserve_attempt(
            NEXT_ACTION,
            Bounds(actions=1),
            "retry-attempt",
            started_ns=10,
            deadline_ns=20,
        )
    assert successor.reservation_state(NEXT_ACTION) is None


def test_profile_continuation_reconciled_predecessor_cannot_be_retried_in_new_engagement(
    tmp_path,
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    _continue(successor, proof)

    with pytest.raises(PolicyError, match="continuation predecessor.*permanently spent"):
        successor.reserve(PRED_ACTION, Bounds(actions=1))
    assert successor.reservation_state(PRED_ACTION) is None


def test_profile_continuation_rejects_a_pre_reserved_successor_atomically(tmp_path):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    successor.reserve(
        V3_ACTION,
        Bounds(tcp_connects=1),
        workspace_id=WORKSPACE,
        target_id=TARGET,
        workflow_id=WORKFLOW,
    )
    before = successor.usage()["tcp_connects"]

    with pytest.raises(PolicyError, match="successor already has durable state"):
        _continue(successor, proof)

    assert successor.profile_continuation(OLD_ENGAGEMENT, NEXT_ACTION) is None
    assert successor.usage()["tcp_connects"] == before == 1


def _insert_successor_engagement_state(
    ledger: Ledger, action_id: str, state_kind: str
) -> None:
    common = (ledger.engagement_id, ledger.device_id, action_id)
    if state_kind == "reservation":
        ledger._db.execute(
            "INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)",
            (*common, WORKSPACE, TARGET, None, WORKFLOW, "{}", "blocked", "{}"),
        )
    elif state_kind == "scope":
        ledger._db.execute(
            "INSERT INTO reservation_scopes VALUES (?,?,?,?,?,?,?,?)",
            (*common, "engagement", ledger.engagement_id, "actions", 1, None),
        )
    elif state_kind == "attempt":
        ledger._db.execute(
            "INSERT INTO reservation_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (*common, "attempt", 0, 0, 0, 0, 0, 0, 1, 0, 0, "blocked"),
        )
    elif state_kind == "event":
        ledger._db.execute(
            "INSERT INTO reservation_attempt_events VALUES (?,?,?,?,?,?,?,?,?,?)",
            (*common, "attempt", "event", 0, 0, 0, 0, 0),
        )
    elif state_kind == "wave":
        ledger._db.execute(
            "INSERT INTO assessment_items VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                ledger.engagement_id,
                ledger.device_id,
                "wave",
                "item",
                action_id,
                action_id,
                TARGET,
                "check",
                "role",
                "module",
                "blocked",
                None,
            ),
        )
    else:
        ledger._db.execute(
            """INSERT INTO profile_reconciliations
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ledger.engagement_id,
                ledger.device_id,
                action_id,
                "spent-plan",
                "8" * 64,
                "other-action",
                "other-plan",
                "9" * 64,
                "a" * 64,
                "clock-source-unavailable",
                1,
                1,
                1,
                "2026-09-10T00:00:00.000000Z",
                1,
            ),
        )


@pytest.mark.parametrize("action_id", (PRED_ACTION, NEXT_ACTION, V3_ACTION))
@pytest.mark.parametrize(
    "state_kind", ("reservation", "scope", "attempt", "event", "wave", "reconciliation")
)
def test_profile_continuation_rejects_successor_engagement_state_for_every_bound_action(
    tmp_path, action_id, state_kind
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    _insert_successor_engagement_state(successor, action_id, state_kind)

    with pytest.raises(PolicyError, match="successor already has durable state"):
        _continue(successor, proof)

    assert successor.profile_continuation(OLD_ENGAGEMENT, NEXT_ACTION) is None


def test_profile_continuation_requires_distinct_profile_and_broker_workers(tmp_path):
    _predecessor, successor, proof = _continuation_setup(tmp_path)

    with pytest.raises(PolicyError, match="worker digests must differ"):
        _continue(
            successor,
            replace(
                proof,
                predecessor_broker_worker_sha256=(
                    proof.predecessor_profile_worker_sha256
                ),
            ),
        )

    assert successor.profile_continuation(OLD_ENGAGEMENT, NEXT_ACTION) is None


@pytest.mark.parametrize(
    "scope_change",
    (
        {"workspace_id": "different-workspace"},
        {"target_id": "http://192.0.2.10:8096"},
        {"workflow_id": "different-workflow"},
    ),
)
def test_profile_continuation_successor_cannot_escape_bound_budget_scope(
    tmp_path, scope_change
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    _continue(successor, proof)
    values = {
        "workspace_id": WORKSPACE,
        "target_id": TARGET,
        "workflow_id": WORKFLOW,
    }
    values.update(scope_change)

    with pytest.raises(PolicyError, match="continuation successor scope differs"):
        successor.reserve(V3_ACTION, Bounds(tcp_connects=1), **values)
    assert successor.reservation_state(V3_ACTION) is None


@pytest.mark.parametrize(
    ("scope", "key"),
    (
        ("engagement", NEW_ENGAGEMENT),
        ("device", "arch-btw"),
        ("workspace", WORKSPACE),
        ("workflow", WORKFLOW),
        ("target", TARGET),
    ),
)
def test_profile_continuation_carries_possible_tcp_connection_into_exact_new_budget(
    tmp_path, scope, key
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    _continue(successor, proof)

    with pytest.raises(PolicyError, match="durable scoped budget exhausted"):
        successor.reserve(
            V3_ACTION,
            Bounds(tcp_connects=1),
            workspace_id=WORKSPACE,
            target_id=TARGET,
            workflow_id=WORKFLOW,
            budget_limits=(
                BudgetLimit(scope, key, "tcp_connects", 1),
            ),
        )
    assert successor.reservation_state(V3_ACTION) is None

    admitted = successor.reserve(
        V3_ACTION,
        Bounds(tcp_connects=1),
        workspace_id=WORKSPACE,
        target_id=TARGET,
        workflow_id=WORKFLOW,
        limits={"tcp_connects": 2},
        budget_limits=(BudgetLimit(scope, key, "tcp_connects", 2),),
    )
    assert admitted.request_id == V3_ACTION
    assert admitted.remaining["tcp_connects"] == 0
    assert successor.usage()["tcp_connects"] == 2
    assert successor.usage(workflow_id=WORKFLOW)["tcp_connects"] == 2
    assert successor.usage(target_id=TARGET)["tcp_connects"] == 2


@pytest.mark.parametrize(
    "counter",
    ("udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes"),
)
def test_profile_continuation_keeps_other_carried_transport_charges_zero(
    tmp_path, counter
):
    _predecessor, successor, proof = _continuation_setup(tmp_path)
    _continue(successor, proof)

    admitted = successor.reserve(
        V3_ACTION,
        Bounds(**{counter: 1}),
        workspace_id=WORKSPACE,
        target_id=TARGET,
        workflow_id=WORKFLOW,
        budget_limits=(
            BudgetLimit("engagement", NEW_ENGAGEMENT, counter, 1),
        ),
    )
    assert admitted.request_id == V3_ACTION
