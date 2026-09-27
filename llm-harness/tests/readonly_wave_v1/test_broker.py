import pytest

from cptc11_readonly_wave_v1.audit import ReadonlyAuditWriter
from cptc11_readonly_wave_v1.broker import BrokerError, ReadonlyWaveBroker, SyntheticChannelProvider
from cptc11_readonly_wave_v1.catalog import PLAN_ID, plan_actions
from cptc11_readonly_wave_v1.ledger import ReadonlyWaveLedger
from testing.cptc11_readonly_wave_v1.fake_channels import ScriptedChannel
from testing.cptc11_readonly_wave_v1.fake_encryptor import FixedEncryptor
from testing.cptc11_readonly_wave_v1.wave import make_wave


def test_broker_reserves_before_open_and_emits_typed_result(tmp_path):
    action = plan_actions(PLAN_ID)[0]
    channel = ScriptedChannel(b'{"Version":"v3.1.2","other":"secret"}', http=True)
    provider = SyntheticChannelProvider({action.action_id: channel})
    ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64)
    ledger.initialize()
    audit = ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True)
    wave = make_wave(); ledger.create_wave(wave)
    broker = ReadonlyWaveBroker(ledger, audit, provider)
    result = broker.execute(wave.wave_id, PLAN_ID, action.action_id, action.profile_id)
    assert result.outcome == "complete"
    assert result.facts.version == "3.1.2"
    assert provider.opens == [action.action_id]
    assert ledger.action_state(action.action_id) == "complete"
    assert audit.verify().valid


def test_broker_does_not_retry_or_open_after_stop(tmp_path):
    action = plan_actions(PLAN_ID)[0]
    provider = SyntheticChannelProvider({action.action_id: ScriptedChannel(b"{}", http=True)})
    ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64)
    ledger.initialize(); ledger.stop("test")
    audit = ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True)
    broker = ReadonlyWaveBroker(ledger, audit, provider)
    with pytest.raises(BrokerError):
        broker.execute("wave", PLAN_ID, action.action_id, action.profile_id)
    assert provider.opens == []


def test_post_contact_failure_becomes_uncertain_and_stops(tmp_path):
    action = plan_actions(PLAN_ID)[1]
    provider = SyntheticChannelProvider({action.action_id: ScriptedChannel(b"+PONG\r\n", close_error=True)})
    ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64); ledger.initialize()
    audit = ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True)
    wave = make_wave(); ledger.create_wave(wave)
    broker = ReadonlyWaveBroker(ledger, audit, provider)
    with pytest.raises(BrokerError):
        broker.execute(wave.wave_id, PLAN_ID, action.action_id, action.profile_id)
    assert ledger.action_state(action.action_id) == "uncertain"
    assert ledger.stopped()
