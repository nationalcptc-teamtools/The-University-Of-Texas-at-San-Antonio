import json
import os

import pytest

from cptc11_readonly_wave_v1.catalog import PLAN_ID, plan_actions
from cptc11_readonly_wave_v1.ledger import LedgerError, ReadonlyWaveLedger, action_request_id
from testing.cptc11_readonly_wave_v1.wave import make_wave


def test_ledger_is_durable_and_uses_full_sync(tmp_path):
    ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64)
    ledger.initialize()
    assert ledger.db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert ledger.db.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert ledger.path.stat().st_mode & 0o077 == 0
    ledger.close()


def test_reservation_is_catalog_bound_and_idempotent(tmp_path):
    action = plan_actions(PLAN_ID)[0]
    ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64)
    ledger.initialize()
    wave = make_wave(actions=(action,)); ledger.create_wave(wave)
    first = ledger.reserve_action(wave.wave_id, PLAN_ID, action.action_id, action.profile_id)
    assert first.request_id == action_request_id(PLAN_ID, action.action_id, action.profile_id)
    assert ledger.action_state(action.action_id) == "reserved"
    assert ledger.reserve_action(wave.wave_id, PLAN_ID, action.action_id, action.profile_id) == first
    with pytest.raises(LedgerError):
        ledger.reserve_action(wave.wave_id, PLAN_ID, action.action_id, "wrong.profile")


def test_one_in_flight_and_terminal_receipt_are_immutable(tmp_path):
    actions = plan_actions(PLAN_ID)
    ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64)
    ledger.initialize()
    wave = make_wave(); ledger.create_wave(wave)
    ledger.reserve_action(wave.wave_id, PLAN_ID, actions[0].action_id, actions[0].profile_id)
    ledger.reserve_action(wave.wave_id, PLAN_ID, actions[1].action_id, actions[1].profile_id)
    ledger.claim_action(actions[0].action_id)
    with pytest.raises(LedgerError):
        ledger.claim_action(actions[1].action_id)
    ledger.activate_action(actions[0].action_id)
    action = actions[0]
    receipt_data = {"outcome": "complete", "wave_id": wave.wave_id, "plan_id": action.plan_id, "action_id": action.action_id,
                    "profile_id": action.profile_id, "target_id": action.target_id, "catalog_sha256": action.catalog_sha256,
                    "profile_sha256": action.profile_sha256, "operation_sha256": action.operation.request_sha256,
                    "parser_id": action.parser_id, "policy_sha256": "a"*64, "release_sha256": "b"*64,
                    "worker_sha256": "c"*64, "runtime_sha256": "d"*64, "evidence_sha256": "c"*64,
                    "cleanup_status": "closed", "facts": {"status": 200}}
    receipt = ledger.finish_action(action.action_id, "complete", receipt_data)
    assert receipt["outcome"] == "complete"
    assert ledger.finish_action(action.action_id, "complete", receipt_data) == receipt
    with pytest.raises(LedgerError):
        ledger.finish_action(actions[0].action_id, "failed", {})


def test_stop_sentinel_works_when_database_is_locked_and_recovery_latches_wave(tmp_path):
    root = tmp_path / "state"
    ledger = ReadonlyWaveLedger(root, "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64)
    ledger.initialize()
    action = plan_actions(PLAN_ID)[0]
    wave = make_wave(actions=(action,)); ledger.create_wave(wave)
    ledger.reserve_action(wave.wave_id, PLAN_ID, action.action_id, action.profile_id)
    ledger.claim_action(action.action_id)
    ledger.activate_action(action.action_id)
    ledger.stop("operator")
    assert ledger.stopped() is True
    assert (root / "operator-stop.json").is_file()
    ledger.recover()
    assert ledger.action_state(action.action_id) == "uncertain"
    with pytest.raises(LedgerError):
        ledger.reserve_action(wave.wave_id, PLAN_ID, plan_actions(PLAN_ID)[1].action_id, plan_actions(PLAN_ID)[1].profile_id)
