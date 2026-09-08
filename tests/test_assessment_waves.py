"""Persistent frozen-wave accounting is synthetic and never dispatches I/O."""
from __future__ import annotations

import pytest

from cptc_harness.assessment_contracts import AssessmentItem, AssessmentPlan, assessment_request_id
from cptc_harness.contracts import Bounds, BudgetLimit, PolicyError
from cptc_harness.ledger import Ledger


def store(tmp_path):
    tmp_path.mkdir(exist_ok=True); tmp_path.chmod(0o700)
    return Ledger(tmp_path, "eng", "device", policy_revision="p1")


def plan(*, wave="wave", workspace="ws", count=2):
    entries = tuple(AssessmentItem(str(index), f"policy-{index}", f"check-{index}", "module")
                    for index in range(count))
    return AssessmentPlan(wave, "eng", workspace, "operator", "p1", "a" * 64, "b" * 64, entries)


def accounting(plan_value, *, limit=None):
    result = {}
    for item in plan_value.items:
        request_id = assessment_request_id(plan_value.wave_id, item.item_id)
        result[item.item_id] = {
            "request_id": request_id,
            "action_id": request_id,
            "bounds": Bounds(timeout_s=1.0, request_limit=1, output_bytes=0, process_limit=0, actions=1),
            "target_id": f"origin-{plan_value.wave_id}-{item.item_id}",
            "target_policy_id": item.target_id,
            "auth_realm": "",
            "workflow_id": plan_value.wave_id,
            "limits": None,
            "budget_limits": () if limit is None else (limit,),
        }
    return result


def rows(ledger, table):
    return ledger._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_aggregate_wave_failure_rolls_back_all_planned_rows(tmp_path):
    ledger = store(tmp_path); frozen = plan()
    entries = accounting(frozen, limit=BudgetLimit("device", "device", "actions", 1))
    with pytest.raises(PolicyError, match="durable scoped budget exhausted"):
        ledger.reserve_wave(frozen, entries)
    assert rows(ledger, "assessment_waves") == rows(ledger, "assessment_items") == rows(ledger, "reservations") == 0
    assert rows(ledger, "reservation_scopes") == 0


def test_planned_wave_spends_scopes_before_any_claim(tmp_path):
    ledger = store(tmp_path); frozen = plan(count=1)
    ceiling = BudgetLimit("device", "device", "actions", 1)
    ledger.reserve_wave(frozen, accounting(frozen, limit=ceiling))
    with pytest.raises(PolicyError, match="durable scoped budget exhausted"):
        ledger.reserve("other", Bounds(timeout_s=1, output_bytes=0, process_limit=0, actions=1),
                       workspace_id="other", target_id="other-origin", workflow_id="other",
                       budget_limits=(ceiling,))
    assert ledger._db.execute("SELECT state FROM reservations").fetchall() == [("planned",)]


def test_claim_order_activation_and_terminal_reclaim_are_exactly_once(tmp_path):
    ledger = store(tmp_path); frozen = plan(); ledger.reserve_wave(frozen, accounting(frozen))
    with pytest.raises(PolicyError, match="prior wave item"):
        ledger.claim_wave_item("wave", "1")
    first = ledger.claim_wave_item("wave", "0")
    assert first.state == "dispatching"
    with pytest.raises(PolicyError, match="not claimable"):
        ledger.claim_wave_item("wave", "0")
    active = ledger.activate_wave_item("wave", "0", first.request_id, frozen.sha256)
    assert active.state == "running"
    with pytest.raises(PolicyError, match="not dispatching"):
        ledger.activate_wave_item("wave", "0", first.request_id, frozen.sha256)
    # Broker records its ordinary reservation receipt before campaign stores
    # the wave receipt; the latter must bind that already-terminal charge.
    ledger.finish(first.request_id, state="complete")
    terminal = ledger.finish_wave_item("wave", "0", "complete", {"status": "complete"})
    assert terminal.result_json == '{"status":"complete"}'
    assert ledger.claim_wave_item("wave", "0") == terminal
    assert ledger.claim_wave_item("wave", "1").state == "dispatching"


def test_noncomplete_terminal_stops_remaining_wave_and_ledger(tmp_path):
    ledger = store(tmp_path); frozen = plan(); ledger.reserve_wave(frozen, accounting(frozen))
    ledger.claim_wave_item("wave", "0")
    closed = ledger.finish_wave_item("wave", "0", "uncertain", {"status": "uncertain"})
    assert closed.state == "uncertain" and ledger.stopped()
    assert ledger._db.execute("SELECT item_id,state FROM assessment_items ORDER BY item_id").fetchall() == [
        ("0", "uncertain"), ("1", "stopped")]
    assert ledger.claim_wave_item("wave", "1").state == "stopped"


def test_restart_recovers_claim_without_reclaim_and_keeps_frozen_unclaimed(tmp_path):
    first = store(tmp_path); interrupted = plan(wave="interrupted")
    frozen = plan(wave="frozen")
    first.reserve_wave(interrupted, accounting(interrupted)); first.reserve_wave(frozen, accounting(frozen))
    claim = first.claim_wave_item("interrupted", "0")
    first._db.close()
    second = store(tmp_path)
    recovered = second.recover_waves("ws")
    assert [(item.wave_id, item.item_id, item.state) for item in recovered] == [("interrupted", "0", "uncertain")]
    assert second._db.execute("SELECT state FROM assessment_items WHERE wave_id='frozen' ORDER BY item_id").fetchall() == [
        ("planned",), ("planned",)]
    assert second.claim_wave_item("interrupted", "0").state == "uncertain"
    assert second._db.execute("SELECT state FROM reservations WHERE request_id=?", (claim.request_id,)).fetchone() == ("uncertain",)


def test_recovery_is_limited_to_requested_workspace(tmp_path):
    ledger = store(tmp_path); one = plan(wave="one", workspace="one", count=1); two = plan(wave="two", workspace="two", count=1)
    ledger.reserve_wave(one, accounting(one)); ledger.reserve_wave(two, accounting(two))
    ledger.claim_wave_item("one", "0"); ledger.claim_wave_item("two", "0")
    recovered = ledger.recover_waves("one")
    assert [(value.wave_id, value.state) for value in recovered] == [("one", "uncertain")]
    assert ledger._db.execute("SELECT state FROM assessment_items WHERE wave_id='two'").fetchone() == ("dispatching",)


def test_duplicate_wave_id_and_mapping_binding_edits_are_rejected(tmp_path):
    ledger = store(tmp_path); frozen = plan(count=1); entries = accounting(frozen)
    ledger.reserve_wave(frozen, entries)
    with pytest.raises(PolicyError, match="already reserved"):
        ledger.reserve_wave(frozen, entries)
    edited = accounting(frozen); edited["0"]["target_policy_id"] = "other"
    with pytest.raises(PolicyError, match="target policy binding"):
        ledger.reserve_wave(frozen, edited)


def test_two_connections_can_only_claim_one_active_workspace_action(tmp_path):
    first, second = store(tmp_path), store(tmp_path)
    one = plan(wave="one", count=1); two = plan(wave="two", count=1)
    first.reserve_wave(one, accounting(one)); second.reserve_wave(two, accounting(two))
    assert first.claim_wave_item("one", "0").state == "dispatching"
    with pytest.raises(PolicyError, match="operation in flight"):
        second.claim_wave_item("two", "0")


def test_legacy_target_ceiling_is_persisted_across_restart(tmp_path):
    first = store(tmp_path)
    bounds = Bounds(timeout_s=1, request_limit=1, output_bytes=0, process_limit=0)
    first.reserve("one", bounds, workspace_id="ws", target_id="origin", workflow_id="one",
                  limits={"request_limit": 1})
    first.finish("one", state="complete"); first._db.close()
    second = store(tmp_path)
    with pytest.raises(PolicyError, match="durable scoped budget exhausted"):
        second.reserve("two", bounds, workspace_id="ws", target_id="origin", workflow_id="two",
                       limits={"request_limit": 6})
    assert second._db.execute("SELECT MIN(ceiling) FROM reservation_scopes WHERE scope_kind='target' AND scope_key='origin' AND counter='request_limit'").fetchone() == (1,)


@pytest.mark.parametrize("state", ["complete", "failed", "blocked", "stopped", "uncertain"])
@pytest.mark.parametrize("receipt_state", ["complete", "failed", "blocked", "stopped", "uncertain"])
def test_wave_terminal_state_and_receipt_must_agree(tmp_path, state, receipt_state):
    ledger = store(tmp_path); frozen = plan(count=1); ledger.reserve_wave(frozen, accounting(frozen))
    ledger.claim_wave_item("wave", "0")
    if state == receipt_state:
        assert ledger.finish_wave_item("wave", "0", state, {"status": receipt_state}).state == state
    else:
        with pytest.raises(PolicyError, match="receipt does not match"):
            ledger.finish_wave_item("wave", "0", state, {"status": receipt_state})
        assert ledger._db.execute("SELECT state FROM assessment_items").fetchone()[0] == "dispatching"


@pytest.mark.parametrize("tamper", ["delete", "planned", "bogus"])
def test_recovery_detects_corrupt_reservation_and_latches_stop(tmp_path, tamper):
    ledger = store(tmp_path); frozen = plan(count=1); ledger.reserve_wave(frozen, accounting(frozen))
    ledger.claim_wave_item("wave", "0")
    if tamper == "delete": ledger._db.execute("DELETE FROM reservations")
    else: ledger._db.execute("UPDATE reservations SET state=?", (tamper,))
    with pytest.raises(PolicyError, match="linkage is corrupt"): ledger.recover_waves("ws")
    assert ledger.stopped() and (tmp_path / "operator-stop.json").exists()
    assert ledger._db.execute("SELECT state FROM assessment_items").fetchone()[0] == "dispatching"


def test_broker_completion_before_wave_checkpoint_recovers_uncertain(tmp_path):
    ledger = store(tmp_path); frozen = plan(count=1); ledger.reserve_wave(frozen, accounting(frozen))
    claim = ledger.claim_wave_item("wave", "0")
    ledger.finish(claim.request_id, {"request_limit": 1}, state="complete")
    assert ledger.recover_waves("ws")[0].state == "uncertain"
    assert ledger._db.execute("SELECT state,usage FROM reservations").fetchone() == ("uncertain", '{"request_limit": 1}')


@pytest.mark.parametrize("state", ["planned", "running", "arbitrary"])
def test_ledger_rejects_nonterminal_finish_states(tmp_path, state):
    ledger = store(tmp_path); ledger.reserve("action", Bounds())
    with pytest.raises(PolicyError, match="terminal reservation state"): ledger.finish("action", state=state)
    assert ledger._db.execute("SELECT state FROM reservations").fetchone()[0] == "running"


def test_ledger_cannot_finish_unclaimed_or_rewrite_terminal_reservations(tmp_path):
    ledger = store(tmp_path); frozen = plan(count=1); ledger.reserve_wave(frozen, accounting(frozen))
    request = assessment_request_id("wave", "0")
    with pytest.raises(PolicyError, match="not active"): ledger.finish(request, state="complete")
    ledger.claim_wave_item("wave", "0"); ledger.finish(request, state="complete")
    with pytest.raises(PolicyError, match="immutable"): ledger.finish(request, state="failed")


def test_recovery_rolls_back_when_unclaimed_reservation_is_missing(tmp_path):
    ledger = store(tmp_path); frozen = plan(); ledger.reserve_wave(frozen, accounting(frozen))
    ledger.claim_wave_item("wave", "0")
    ledger._db.execute("DELETE FROM reservations WHERE request_id=?", (assessment_request_id("wave", "1"),))
    with pytest.raises(PolicyError, match="planned wave reservation linkage is corrupt"):
        ledger.recover_waves("ws")
    assert ledger._db.execute("SELECT state FROM assessment_items ORDER BY item_id").fetchall() == [("dispatching",), ("planned",)]
    assert ledger.stopped() and (tmp_path / "operator-stop.json").exists()
