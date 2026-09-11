from cptc11_readonly_wave_v1.audit import ReadonlyAuditWriter
from cptc11_readonly_wave_v1.broker import ReadonlyWaveBroker, SyntheticChannelProvider
from cptc11_readonly_wave_v1.catalog import PLAN_ID, plan_actions
from cptc11_readonly_wave_v1.ledger import ReadonlyWaveLedger
from testing.cptc11_readonly_wave_v1.fake_channels import ScriptedChannel
from testing.cptc11_readonly_wave_v1.wave import make_wave


def test_reopen_keeps_stop_and_never_retries(tmp_path):
    action = plan_actions(PLAN_ID)[0]
    root = tmp_path / "state"
    ledger = ReadonlyWaveLedger(root, "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64); ledger.initialize()
    wave = make_wave(actions=(action,)); ledger.create_wave(wave)
    ledger.reserve_action(wave.wave_id, PLAN_ID, action.action_id, action.profile_id); ledger.claim_action(action.action_id)
    ledger.activate_action(action.action_id); ledger.stop("crash")
    ledger.close()
    reopened = ReadonlyWaveLedger(root, "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64); reopened.initialize(); reopened.recover()
    assert reopened.stopped(); assert reopened.action_state(action.action_id) == "uncertain"
    receipt = reopened.action_receipt(action.action_id)
    assert receipt is not None
    assert {"wave_id", "plan_id", "action_id", "profile_id", "target_id", "catalog_sha256", "profile_sha256",
            "operation_sha256", "parser_id", "policy_sha256", "release_sha256", "worker_sha256", "runtime_sha256",
            "evidence_sha256", "outcome", "cleanup_status"}.issubset(receipt)
    before = dict(receipt); reopened.recover(); assert reopened.action_receipt(action.action_id) == before
