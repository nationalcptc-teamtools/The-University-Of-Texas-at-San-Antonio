import hashlib
import json
import os
import fcntl
import threading
import time
from pathlib import Path
from dataclasses import replace

import pytest

from cptc11_readonly_wave_v1.catalog import PLAN_ID, plan_actions


def test_frozen_wave_approval_binds_order_and_derives_wave_id():
    from cptc11_readonly_wave_v1.contracts import FrozenWaveApproval, build_frozen_wave

    wave = build_frozen_wave(
        engagement_id="eng", device_id="dev", workspace_id="ws", plan_id=PLAN_ID,
        catalog_sha256=plan_actions(PLAN_ID)[0].catalog_sha256,
        policy_sha256="a" * 64, release_sha256="b" * 64,
        actions=tuple(plan_actions(PLAN_ID)), approval_id="approval", operator="captain",
        approved_at="2026-01-01T00:00:00.000000Z",
    )
    assert isinstance(wave, FrozenWaveApproval)
    assert wave.wave_id == build_frozen_wave(
        engagement_id="eng", device_id="dev", workspace_id="ws", plan_id=PLAN_ID,
        catalog_sha256=wave.catalog_sha256, policy_sha256=wave.policy_sha256,
        release_sha256=wave.release_sha256, actions=wave.actions,
        approval_id=wave.approval_id, operator=wave.operator, approved_at=wave.approved_at,
    ).wave_id
    with pytest.raises(ValueError):
        replace(wave, wave_id="faked")


def test_recursive_metadata_validator_rejects_encoded_restricted_content():
    from cptc11_readonly_wave_v1.metadata import MetadataError, validate_metadata

    validate_metadata({"status": 200, "nested": ["ordinary-id", "a" * 64]})
    for value in (
        {"nested": {"PaSsWoRd": "x"}},
        {"nested": {"x": "cGFzc3dvcmQ="}},
        {"nested": {"x": "url=https%3A%2F%2Fexample.invalid"}},
    ):
        with pytest.raises(MetadataError): validate_metadata(value)


def test_typed_encrypted_record_rejects_identity_and_plaintext_ciphertext():
    from cptc11_readonly_wave_v1.audit import AuditError, AgeEncryptedRecord, SyntheticEncryptedRecord

    plaintext = b"synthetic response"
    digest = hashlib.sha256(plaintext).hexdigest()
    record = SyntheticEncryptedRecord("synthetic-v1", "test-recipient", digest, b"ciphertext-marker")
    assert record.plaintext_sha256 == digest
    with pytest.raises(AuditError): AgeEncryptedRecord("age", "recipient", digest, plaintext)


def test_service_request_is_canonical_and_contains_wave_id():
    from cptc11_readonly_wave_v1.service import _decode_request, _encode_request

    request = {"method": "execute", "wave_id": "wave", "plan_id": "p", "action_id": "a", "profile_id": "x"}
    encoded = _encode_request(request)
    assert encoded == json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    assert _decode_request(encoded)["wave_id"] == "wave"


def test_service_uses_real_seqpacket_round_trip_and_durable_stop(tmp_path):
    from cptc11_readonly_wave_v1.service import ReadonlyWaveClient, ReadonlyWaveService, ServiceConfig

    config = ServiceConfig(tmp_path / "svc" / "wave.sock", tmp_path / "svc" / "stop",
                           peer_uids=frozenset({os.getuid()}), owner_uid=os.getuid(), group_gid=os.getgid())
    service = ReadonlyWaveService(config, broker=None)
    thread = threading.Thread(target=service.serve_forever, daemon=True); thread.start()
    for _ in range(100):
        if config.socket_path.exists(): break
        time.sleep(0.01)
    assert config.socket_path.exists()
    assert ReadonlyWaveClient(config.socket_path).request({"method": "info"})["status"] == "ready"
    assert ReadonlyWaveClient(config.socket_path).request({"method": "stop"})["status"] == "stopped"
    thread.join(2); assert not thread.is_alive()


def test_response_schema_is_closed_per_method():
    from cptc11_readonly_wave_v1.service import ServiceError, _decode_response
    assert _decode_response(b'{"status":"ready","service":"x"}', method="info")["status"] == "ready"
    with pytest.raises(ServiceError):
        _decode_response(b'{"status":"ready","service":"x","actions":1}', method="info")
    with pytest.raises(ServiceError):
        _decode_response(b'{"status":"ready","stopped":false}', method="plan")
    assert _decode_response(b'{"status":"rejected","reason":"blocked"}', method="execute")["status"] == "rejected"
    malformed = (
        (b'{"status":"bogus","service":"x"}', "info"),
        (b'{"status":"ready","service":1}', "info"),
        (b'{"status":"ready","actions":true}', "plan"),
        (b'{"status":"complete","wave_id":"w","action_id":"a","profile_id":"p","target_id":"t","evidence_sha256":"UPPER"}', "execute"),
    )
    for packet, method in malformed:
        with pytest.raises(ServiceError): _decode_response(packet, method=method)


def test_file_backed_stop_gate_serializes_provider_open(tmp_path):
    from cptc11_readonly_wave_v1.audit import ReadonlyAuditWriter
    from cptc11_readonly_wave_v1.broker import ReadonlyWaveBroker, SyntheticChannelProvider, BrokerError
    from cptc11_readonly_wave_v1.catalog import PLAN_ID, plan_actions
    from cptc11_readonly_wave_v1.ledger import ReadonlyWaveLedger
    from testing.cptc11_readonly_wave_v1.fake_channels import ScriptedChannel
    from testing.cptc11_readonly_wave_v1.fake_encryptor import FixedEncryptor
    from testing.cptc11_readonly_wave_v1.wave import make_wave

    import threading
    action = plan_actions(PLAN_ID)[0]; entered = threading.Event(); release = threading.Event()
    def opener():
        entered.set(); release.wait(2); return ScriptedChannel(b'{}', http=True)
    provider = SyntheticChannelProvider({action.action_id: opener})
    ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64); ledger.initialize()
    wave = make_wave(); ledger.create_wave(wave)
    broker = ReadonlyWaveBroker(ledger, ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True), provider)
    errors = []
    def run():
        try: broker.execute(wave.wave_id, PLAN_ID, action.action_id, action.profile_id)
        except Exception as exc: errors.append(exc)
    worker = threading.Thread(target=run); worker.start()
    assert entered.wait(2)
    stopper = threading.Thread(target=ledger.stop); stopper.start(); stopper.join(0.05)
    assert stopper.is_alive() and (tmp_path / "state" / "operator-stop.json").is_file()
    release.set(); worker.join(2); stopper.join(2)
    assert not stopper.is_alive() and ledger.stopped() and errors


def test_provider_open_failure_finalizes_uncertain_and_releases_capture_allowance(tmp_path):
    from cptc11_readonly_wave_v1.audit import ReadonlyAuditWriter
    from cptc11_readonly_wave_v1.broker import BrokerError, ReadonlyWaveBroker, SyntheticChannelProvider
    from cptc11_readonly_wave_v1.catalog import PLAN_ID, plan_actions
    from cptc11_readonly_wave_v1.ledger import ReadonlyWaveLedger
    from testing.cptc11_readonly_wave_v1.fake_encryptor import FixedEncryptor
    from testing.cptc11_readonly_wave_v1.wave import make_wave

    action = plan_actions(PLAN_ID)[0]
    def fail(): raise OSError("provider did not return a channel")
    provider = SyntheticChannelProvider({action.action_id: fail})
    ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64); ledger.initialize()
    wave = make_wave(); ledger.create_wave(wave)
    audit = ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True)
    with pytest.raises(BrokerError): ReadonlyWaveBroker(ledger, audit, provider).execute(wave.wave_id, PLAN_ID, action.action_id, action.profile_id)
    assert ledger.action_state(action.action_id) == "uncertain" and ledger.stopped()
    state = json.loads((tmp_path / "audit" / ".audit-state.json").read_text())
    assert state["reservations"] == {}


def test_receipt_requires_closed_provenance_and_rejects_conflicts(tmp_path):
    from cptc11_readonly_wave_v1.catalog import PLAN_ID, plan_actions
    from cptc11_readonly_wave_v1.ledger import LedgerError, ReadonlyWaveLedger
    from testing.cptc11_readonly_wave_v1.wave import make_wave
    action = plan_actions(PLAN_ID)[0]; ledger = ReadonlyWaveLedger(tmp_path / "state", "eng", "dev", "ws", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64); ledger.initialize()
    wave = make_wave(); ledger.create_wave(wave); ledger.reserve_action(wave.wave_id, PLAN_ID, action.action_id, action.profile_id); ledger.claim_action(action.action_id); ledger.activate_action(action.action_id)
    with pytest.raises(LedgerError): ledger.finish_action(action.action_id, "complete", {"outcome": "complete", "wave_id": wave.wave_id})
    base = {"outcome": "complete", "wave_id": wave.wave_id, "plan_id": action.plan_id, "action_id": action.action_id, "profile_id": action.profile_id,
            "target_id": action.target_id, "catalog_sha256": action.catalog_sha256, "profile_sha256": action.profile_sha256,
            "operation_sha256": action.operation.request_sha256, "parser_id": action.parser_id, "policy_sha256": "a"*64,
            "release_sha256": "b"*64, "worker_sha256": "c"*64, "runtime_sha256": "d"*64, "evidence_sha256": "c"*64, "cleanup_status": "closed"}
    with pytest.raises(LedgerError): ledger.finish_action(action.action_id, "complete", {**base, "worker_sha256": "d"*64})


def test_integrity_requires_external_owner_policy_and_exact_closure(tmp_path):
    from cptc11_readonly_wave_v1.integrity import IntegrityError, TrustedReleasePolicy, verify_readonly_release

    tmp_path.chmod(0o750)
    release = tmp_path / "release"; release.mkdir(mode=0o750)
    worker = release / "worker"; worker.write_text("ok"); worker.chmod(0o640)
    digest = hashlib.sha256(worker.read_bytes()).hexdigest()
    manifest = {"schema_version": 1, "release_id": "r", "files": {"worker": digest}, "catalog_sha256": "a" * 64}
    mp = tmp_path / "manifest"; mp.write_text(json.dumps(manifest)); mp.chmod(0o640)
    policy = TrustedReleasePolicy(owner_uid=os.getuid(), group_gid=os.getgid(), trusted_parent=tmp_path, release_mode=0o750, file_mode=0o640)
    assert verify_readonly_release(release, mp, policy).release_id == "r"
    (release / "extra").write_text("x")
    with pytest.raises(IntegrityError): verify_readonly_release(release, mp, policy)


def test_audit_requires_sealed_readonly_memfd_and_serializes_writers(tmp_path):
    from cptc11_readonly_wave_v1.audit import AuditError, ReadonlyAuditWriter
    from testing.cptc11_readonly_wave_v1.fake_encryptor import FixedEncryptor

    first = ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True)
    second = ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True)
    first.emit("first", {"value": 1}); second.emit("second", {"value": 2})
    assert first.verify().sequence == 2
    first.reserve_output("descriptor", 3)
    fd = os.memfd_create("readonly-test", os.MFD_ALLOW_SEALING)
    os.write(fd, b"abc")
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    readonly_fd = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY)
    assert first.capture_descriptor("descriptor", "stdout", readonly_fd, 3)
    os.close(readonly_fd); os.close(fd)
    first.reserve_output("ordinary", 3)
    ordinary = tmp_path / "ordinary"; ordinary.write_bytes(b"abc")
    with ordinary.open("rb") as stream, pytest.raises(AuditError):
        first.capture_descriptor("ordinary", "stdout", stream, 3)


def test_audit_evidence_inventory_detects_delete_modify_and_extra(tmp_path):
    from cptc11_readonly_wave_v1.audit import AuditError, ReadonlyAuditWriter
    from testing.cptc11_readonly_wave_v1.fake_encryptor import FixedEncryptor

    root = tmp_path / "audit"; writer = ReadonlyAuditWriter(root, encryptor=FixedEncryptor(), test_only=True)
    writer.reserve_output("a", 3); writer.capture_bytes("a", "stdout", b"abc")
    artifact = root / "evidence" / "a.stdout.enc"; artifact.write_bytes(b"changed")
    assert not writer.verify().valid
    with pytest.raises(AuditError): writer.seal()

    root2 = tmp_path / "audit2"; writer2 = ReadonlyAuditWriter(root2, encryptor=FixedEncryptor(), test_only=True)
    writer2.reserve_output("a", 3); writer2.capture_bytes("a", "stdout", b"abc")
    (root2 / "evidence" / "extra.enc").write_bytes(b"x")
    assert not writer2.verify().valid


def test_malformed_audit_state_latches_durable_marker(tmp_path):
    from cptc11_readonly_wave_v1.audit import AuditError, ReadonlyAuditWriter
    from testing.cptc11_readonly_wave_v1.fake_encryptor import FixedEncryptor

    root = tmp_path / "audit"; ReadonlyAuditWriter(root, encryptor=FixedEncryptor(), test_only=True).close()
    (root / ".audit-state.json").write_text('{"sequence": "bad"}')
    with pytest.raises(AuditError): ReadonlyAuditWriter(root, encryptor=FixedEncryptor(), test_only=True)
    assert (root / "audit-stop.json").is_file()


def test_ledger_requires_nonempty_pins_and_migrates_legacy_table(tmp_path):
    from cptc11_readonly_wave_v1.ledger import LedgerError, ReadonlyWaveLedger
    with pytest.raises(LedgerError): ReadonlyWaveLedger(tmp_path / "bad", "e", "d", "w", policy_sha256="a"*64, release_sha256="b"*64)
    root = tmp_path / "legacy"; root.mkdir(); import sqlite3
    db = sqlite3.connect(root / "ledger.sqlite3")
    db.executescript("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO metadata VALUES('schema_version','1'); CREATE TABLE actions(request_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, action_id TEXT NOT NULL, profile_id TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL); INSERT INTO actions VALUES('legacy-request','old-plan','old-action','old-profile','complete','2026-01-01T00:00:00Z');")
    db.commit(); db.close()
    ledger = ReadonlyWaveLedger(root, "e", "d", "w", policy_sha256="a"*64, release_sha256="b"*64, worker_sha256="c"*64, runtime_sha256="d"*64); ledger.initialize()
    assert ledger.db.execute("PRAGMA user_version").fetchone()[0] == 2
    assert ledger.stopped() and ledger.db.execute("SELECT action_id FROM actions_legacy_v1").fetchone()[0] == "old-action"
