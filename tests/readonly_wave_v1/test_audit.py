import json

import pytest

from cptc11_readonly_wave_v1.audit import AuditError, ReadonlyAuditWriter
from testing.cptc11_readonly_wave_v1.fake_encryptor import FixedEncryptor


def test_audit_is_utc_chained_and_readable_files_have_metadata_only(tmp_path):
    writer = ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True)
    writer.emit("intent", {"action_id": "a", "secret": "hidden"})
    writer.reserve_output("a", 32)
    writer.capture_bytes("a", "stdout", b"client-body")
    writer.seal()
    assert writer.verify().valid
    readable = (tmp_path / "audit" / "audit.jsonl").read_text()
    assert "client-body" not in readable
    assert "hidden" not in readable
    event = json.loads(readable.splitlines()[0])
    assert event["time"].endswith("Z")
    assert "." in event["time"]
    assert event["sequence"] == 1
    captured = (tmp_path / "audit" / "evidence" / "a.stdout.enc").read_bytes()
    assert captured != b"client-body"


def test_capture_requires_reservation_and_encryption(tmp_path):
    writer = ReadonlyAuditWriter(tmp_path / "audit", encryptor=None)
    with pytest.raises(AuditError):
        writer.capture_bytes("a", "body", b"x")
    writer.reserve_output("a", 1)
    with pytest.raises(AuditError):
        writer.capture_bytes("a", "body", b"x")


def test_tampering_and_output_exhaustion_fail_closed(tmp_path):
    writer = ReadonlyAuditWriter(tmp_path / "audit", encryptor=FixedEncryptor(), test_only=True)
    writer.reserve_output("a", 1)
    writer.capture_bytes("a", "body", b"x")
    with pytest.raises(AuditError):
        writer.capture_bytes("a", "body2", b"y")
    (tmp_path / "audit" / "audit.jsonl").write_text("{}\n")
    assert writer.verify().valid is False
