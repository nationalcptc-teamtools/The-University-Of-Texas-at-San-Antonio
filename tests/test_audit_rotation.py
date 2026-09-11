import tempfile
import pytest
from pathlib import Path
import json
from cptc_harness.audit import AuditWriter
from cptc_harness.contracts import AuditEvent, PolicySnapshot, ScopeSpec
from cptc_harness.contracts import PolicyError
from cptc_harness.storage import write_json

def policy(): return PolicySnapshot("e","r","w","d","o",ScopeSpec())

def test_rotate_reopen_and_append():
    with tempfile.TemporaryDirectory() as root:
        audit=AuditWriter(root,policy()); audit.emit(AuditEvent("one")); seal=audit.seal(); audit.close()
        assert seal.events == 1
        reopened=AuditWriter(root,policy()); reopened.emit(AuditEvent("two")); assert reopened._seq == 2
        assert len(list((reopened.segments_root).glob("*/audit.jsonl"))) == 1

def test_missing_state_and_tampered_closed_segment_fail_closed():
    with tempfile.TemporaryDirectory() as root:
        audit=AuditWriter(root,policy()); audit.emit(AuditEvent("one")); audit.rotate(); audit.close()
        segment=next((Path(root)/"segments").glob("*/audit.jsonl")); segment.write_bytes(segment.read_bytes()+b"x")
        with pytest.raises(PolicyError): AuditWriter(root,policy())


@pytest.mark.parametrize("checkpoint", ["pending", "directory", "audit.jsonl", "transcript.log", "segment_manifest", "active_files", "pointer", "pending_removed", "committed"])
def test_each_durable_rotation_boundary_recovers_without_rewriting_events(tmp_path, checkpoint, monkeypatch):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy())
    audit.emit(AuditEvent("first"))
    audit.rotate()
    audit.emit(AuditEvent("second"))
    original = audit.path.read_bytes()
    def crash(label):
        if label == checkpoint:
            raise OSError("synthetic power-loss checkpoint")
    monkeypatch.setattr(audit, "_checkpoint", crash)
    with pytest.raises(OSError):
        audit.rotate()
    assert not audit.ready()
    audit.close()
    reopened = AuditWriter(tmp_path, policy())
    try:
        assert reopened.verify().valid and reopened.verify().events == 2
        archived = sorted(reopened.segments_root.glob("*/audit.jsonl"))
        assert archived[-1].read_bytes() == original
        assert not (tmp_path / "rotation.pending.json").exists()
        reopened.emit(AuditEvent("third"))
        assert reopened.verify().valid and reopened._seq == 3
    finally:
        reopened.close()


def test_checkpoint_failure_latches_and_reopen_refuses_inconsistent_tail(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy())
    def fail():
        raise OSError("synthetic disk failure")
    monkeypatch.setattr(audit, "_write_state", fail)
    with pytest.raises(OSError):
        audit.emit(AuditEvent("not_checkpointed"))
    assert not audit.ready()
    with pytest.raises(PolicyError):
        audit.emit(AuditEvent("must_not_append"))
    audit.close()
    with pytest.raises(PolicyError):
        AuditWriter(tmp_path, policy())


@pytest.mark.parametrize("damage", ["artifact", "manifest", "pointer", "parent", "permission", "symlink"])
def test_closed_records_evidence_and_manifest_chain_remain_verifiable(tmp_path, damage):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy())
    reference = audit.capture("fixture", "stdout", b"synthetic output\x1b[0m", "synthetic")
    audit.rotate()
    audit.emit(AuditEvent("second"))
    audit.rotate()
    assert audit.verify().valid
    if damage == "artifact":
        (tmp_path / reference.artifact_relpath).unlink()
    elif damage == "manifest":
        path = sorted(audit.segments_root.glob("*/manifest.json"))[0]
        value = json.loads(path.read_text())
        value["events"] = 999
        write_json(path, value)
    elif damage == "pointer":
        (tmp_path / "audit.manifest.json").unlink()
    elif damage == "parent":
        import hashlib
        from cptc_harness.contracts import canonical_json
        path = sorted(audit.segments_root.glob("*/manifest.json"))[1]
        value = json.loads(path.read_text())
        value["parent_sha256"] = "0" * 64
        value.pop("sha256")
        value["sha256"] = hashlib.sha256(canonical_json(value)).hexdigest()
        write_json(path, value)
        write_json(tmp_path / "audit.manifest.json", value)
    elif damage == "permission":
        (tmp_path / reference.artifact_relpath).chmod(0o644)
    else:
        path = tmp_path / reference.artifact_relpath
        saved = tmp_path / "saved-fixture"
        path.rename(saved)
        path.symlink_to(saved)
    assert not audit.verify().valid
    audit.close()
    with pytest.raises(PolicyError):
        AuditWriter(tmp_path, policy())


def test_empty_seal_is_idempotent_and_later_export_can_log(tmp_path):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy())
    first = audit.seal()
    assert audit.seal() == first
    audit.emit(AuditEvent("export_complete"))
    assert audit.seal().events == 1
    assert audit.verify().valid
    audit.close()


def test_profile_inspection_snapshot_never_probes_write_access(tmp_path):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy())
    before = {
        path.relative_to(tmp_path).as_posix(): (
            path.lstat().st_mode,
            path.lstat().st_mtime_ns,
            path.lstat().st_ctime_ns,
        )
        for path in tmp_path.rglob("*")
    }
    audit.ready = lambda: pytest.fail("inspection called the write probe")

    assert audit.profile_inspection_snapshot("synthetic-action") == {
        "action_history": [],
        "cleanup_receipt": None,
        "has_result_receipt": False,
        "wire_failure_stage": None,
        "wire_receipt": None,
    }
    after = {
        path.relative_to(tmp_path).as_posix(): (
            path.lstat().st_mode,
            path.lstat().st_mtime_ns,
            path.lstat().st_ctime_ns,
        )
        for path in tmp_path.rglob("*")
    }
    assert after == before
    audit.close()


@pytest.mark.parametrize("failure", ["cap", "classification", "encryption", "allocation"])
def test_capture_failure_remains_stopped_after_reopen(tmp_path, monkeypatch, failure):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy(), evidence_cap=3)
    with pytest.raises(PolicyError):
        if failure == "cap":
            audit.capture("failure", "stdout", b"overflow", "synthetic")
        elif failure == "classification":
            audit.capture("failure", "stdout", b"x", "unknown")
        elif failure == "encryption":
            audit.capture("failure", "stdout", b"x", "restricted_raw")
        else:
            def fail(*args):
                raise OSError("synthetic allocation failure")
            monkeypatch.setattr("os.posix_fallocate", fail)
            audit.reserve_output("failure", 3)
    audit.close()
    reopened = AuditWriter(tmp_path, policy(), evidence_cap=3)
    assert not reopened.ready()
    with pytest.raises(PolicyError):
        reopened.emit(AuditEvent("must_not_restart"))
    reopened.close()
    from cptc_harness.audit import verified_events
    from cptc_harness.exports import offline_timeline
    with pytest.raises(PolicyError):
        verified_events(tmp_path)
    with pytest.raises(PolicyError):
        offline_timeline((tmp_path,), tmp_path / "must-not-export.json")
    with tempfile.TemporaryDirectory() as root:
        audit=AuditWriter(root,policy()); audit.emit(AuditEvent("one")); audit.close()
        (Path(root)/".audit-state.json").unlink()
        with pytest.raises(PolicyError): AuditWriter(root,policy())


@pytest.mark.parametrize(
    "checkpoint",
    (
        "output_marker_created",
        "output_directory_synced",
        "output_allocated",
        "output_file_synced",
        "output_reserved_emitted",
    ),
)
def test_output_reservation_failure_rolls_back_marker_and_allowance(
    tmp_path, monkeypatch, checkpoint
):
    """A crash at any durable reservation boundary must leave no capture grant."""

    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy(), evidence_cap=16)

    def fail(label):
        if label == checkpoint:
            raise OSError("synthetic reservation checkpoint failure")

    monkeypatch.setattr(audit, "_checkpoint", fail)
    with pytest.raises(PolicyError, match="reservation"):
        audit.reserve_output("transactional-output", 8)

    marker = tmp_path / (
        ".reserve-" + __import__("hashlib").sha256(b"transactional-output").hexdigest()
    )
    assert not marker.exists()
    assert "transactional-output" not in audit._output_limits
    assert audit.ready() is False


def test_release_output_idempotently_removes_marker_and_allowance(tmp_path):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy(), evidence_cap=16)
    audit.reserve_output("released-output", 8)
    assert audit._output_limits["released-output"] == 8

    audit.release_output("released-output")
    audit.release_output("released-output")

    assert "released-output" not in audit._output_limits


def test_stale_output_marker_is_never_unlinked_by_failed_reservation(tmp_path):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy(), evidence_cap=16)
    request_id = "stale-marker"
    marker = tmp_path / (
        ".reserve-" + __import__("hashlib").sha256(request_id.encode()).hexdigest()
    )
    marker.write_bytes(b"preexisting")

    with pytest.raises(PolicyError, match="reservation"):
        audit.reserve_output(request_id, 8)

    assert marker.read_bytes() == b"preexisting"
    assert request_id not in audit._output_limits
    assert audit.ready() is False
