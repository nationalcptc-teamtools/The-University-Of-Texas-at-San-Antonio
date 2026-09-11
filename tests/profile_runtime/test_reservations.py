from __future__ import annotations

import threading

import pytest

from cptc_harness.contracts import Bounds, BudgetLimit, PolicyError
from cptc_harness.ledger import Ledger


def store(root):
    root.mkdir(exist_ok=True)
    root.chmod(0o700)
    return Ledger(root, "eng", "device", policy_revision="p1")


def bounds():
    return Bounds(
        timeout_s=10,
        request_limit=1,
        output_bytes=8192,
        process_limit=1,
        actions=1,
        tcp_connects=1,
        udp_datagrams=0,
        protocol_requests=1,
        tx_bytes=256,
        rx_bytes=8192,
    )


def reserve_attempt(ledger, request_id="action", attempt_id="attempt"):
    return ledger.reserve_attempt(
        request_id,
        bounds(),
        attempt_id,
        started_ns=1_000_000_000,
        deadline_ns=11_000_000_000,
        workspace_id="workspace",
        target_id="tcp://10.0.1.30:8096",
        workflow_id="wave",
    )


def test_reservation_and_attempt_intent_commit_in_one_transaction(tmp_path):
    ledger = store(tmp_path)
    receipt = reserve_attempt(ledger)
    assert receipt.request_id == "action"
    assert ledger._db.execute(
        "SELECT state FROM reservations WHERE request_id='action'"
    ).fetchone() == ("running",)
    assert ledger._db.execute(
        "SELECT state,started_ns,deadline_ns FROM reservation_attempts WHERE request_id='action'"
    ).fetchone() == ("running", 1_000_000_000, 11_000_000_000)


def test_attempt_insert_failure_rolls_back_reservation_scopes_and_assignment(tmp_path, monkeypatch):
    ledger = store(tmp_path)

    def fail(*_args, **_kwargs):
        raise OSError("synthetic insert failure")

    monkeypatch.setattr(ledger, "_begin_attempt_locked", fail)
    with pytest.raises(OSError, match="synthetic"):
        reserve_attempt(ledger)
    for table in ("reservations", "reservation_scopes", "assignments", "reservation_attempts"):
        assert ledger._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)


def test_duplicate_or_invalid_attempt_timing_creates_no_partial_reservation(tmp_path):
    ledger = store(tmp_path)
    with pytest.raises(PolicyError):
        ledger.reserve_attempt(
            "action",
            bounds(),
            "attempt",
            started_ns=10,
            deadline_ns=10,
            workspace_id="workspace",
            target_id="tcp://10.0.1.30:8096",
        )
    assert ledger._db.execute("SELECT COUNT(*) FROM reservations").fetchone() == (0,)


def test_two_connections_racing_one_device_action_ceiling_admit_once(tmp_path):
    first, second = store(tmp_path), store(tmp_path)
    gate = threading.Barrier(2)
    outcomes = []

    def run(ledger, suffix):
        try:
            gate.wait()
            ledger.reserve_attempt(
                f"action-{suffix}",
                bounds(),
                f"attempt-{suffix}",
                started_ns=1_000_000_000,
                deadline_ns=11_000_000_000,
                workspace_id=f"workspace-{suffix}",
                target_id=f"tcp://10.0.1.{30 + suffix}:8096",
                workflow_id=f"wave-{suffix}",
                budget_limits=(BudgetLimit("device", "device", "actions", 1),),
            )
            outcomes.append("admitted")
        except PolicyError as error:
            outcomes.append(str(error))

    threads = [threading.Thread(target=run, args=(ledger, index)) for index, ledger in enumerate((first, second))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads)
    assert sorted(outcomes) == ["admitted", "durable scoped budget exhausted"]
    assert first._db.execute("SELECT COUNT(*) FROM reservations").fetchone() == (1,)
    assert first._db.execute("SELECT COUNT(*) FROM reservation_attempts").fetchone() == (1,)


def test_accounting_overrun_can_only_reconcile_to_durable_uncertainty(tmp_path):
    ledger = store(tmp_path)
    reserve_attempt(ledger)
    ledger.record_attempt_event("action", "attempt", "connect", tcp_connects=1)

    with pytest.raises(PolicyError, match="allowance exceeded"):
        ledger.record_attempt_event("action", "attempt", "send", tx_bytes=257)

    assert ledger.stopped() is True
    usage = ledger.attempt_receipt("action")["usage"]
    ledger.finish("action", usage, state="uncertain")
    receipt = ledger.finish_attempt(
        "action", "attempt", state="uncertain", ended_ns=2_000_000_000
    )
    assert receipt["state"] == "uncertain"
    assert receipt["usage"]["tx_bytes"] == 257
    assert ledger._db.execute(
        "SELECT state,usage FROM reservations WHERE request_id='action'"
    ).fetchone() == (
        "uncertain",
        '{"protocol_requests": 0, "rx_bytes": 0, "tcp_connects": 1, '
        '"tx_bytes": 257, "udp_datagrams": 0}',
    )
    assert ledger.attempt_receipt("action")["attempts"][0]["state"] == "uncertain"


def test_operator_stop_can_finalize_active_attempt_without_reopening_mutations(tmp_path):
    ledger = store(tmp_path)
    reserve_attempt(ledger)
    ledger.stop("operator stop")

    ledger.finish("action", state="stopped")
    receipt = ledger.finish_attempt(
        "action", "attempt", state="stopped", ended_ns=2_000_000_000
    )
    assert receipt["state"] == "stopped"
    assert ledger._db.execute(
        "SELECT state FROM reservations WHERE request_id='action'"
    ).fetchone() == ("stopped",)
    with pytest.raises(PolicyError, match="stop"):
        reserve_attempt(ledger, request_id="another", attempt_id="another")


def test_stop_blocks_success_but_allows_only_non_success_finalization(tmp_path):
    ledger = store(tmp_path)
    reserve_attempt(ledger)
    ledger.stop("operator stop")
    with pytest.raises(PolicyError, match="stopped"):
        ledger.finish_attempt(
            "action", "attempt", state="complete", ended_ns=2_000_000_000
        )
    with pytest.raises(PolicyError, match="stopped"):
        ledger.finish("action", state="complete")

    ledger.finish("action", state="uncertain")
    receipt = ledger.finish_attempt(
        "action", "attempt", state="uncertain", ended_ns=2_000_000_000
    )
    assert receipt["state"] == "uncertain"


def test_attempt_ending_exactly_at_deadline_is_uncertain(tmp_path):
    ledger = store(tmp_path)
    reserve_attempt(ledger)

    receipt = ledger.finish_attempt(
        "action", "attempt", state="complete", ended_ns=11_000_000_000
    )

    assert receipt["state"] == "uncertain"
    assert receipt["deadline_exceeded"] is True
    assert ledger.stopped() is True


def test_restart_after_attempt_finalization_before_receipt_marks_reservation_uncertain(
    tmp_path,
):
    ledger = store(tmp_path)
    reserve_attempt(ledger)
    attempt = ledger.finish_attempt(
        "action", "attempt", state="complete", ended_ns=2_000_000_000
    )
    assert attempt["state"] == "complete"
    ledger._db.close()

    reopened = store(tmp_path)
    recovered = reopened.recover_attempts()

    assert recovered == (
        {"request_id": "action", "attempt_id": "attempt", "state": "uncertain"},
    )
    assert reopened.reservation_state("action") == "uncertain"
    assert reopened.stopped() is True
