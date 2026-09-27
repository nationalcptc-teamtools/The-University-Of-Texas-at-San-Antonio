from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path

import pytest

from testing.cptc11_benchmark.source_allowlist import ADVERTISED_LENGTHS, build_image_source, source_descriptor
from testing.cptc11_benchmark.staging import (
    AcquisitionReceipt,
    ChunkReceipt,
    ImageLock,
    StagingRejected,
    create_private_run_dir,
    required_free_space,
    validate_free_space,
    validate_resume,
    validate_state_root,
    write_sparse_chunk,
)


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _source():
    descriptor = source_descriptor("APT-DC-01")
    return build_image_source(
        asset_id=descriptor.asset_id,
        url=descriptor.url,
        listing_sha256="a" * 64,
        headers=(("Content-Length", str(descriptor.content_length)), ("ETag", '"v1"'), ("Last-Modified", "2026-09-01T00:00:00Z"), ("Accept-Ranges", "bytes")),
    )


def _capabilities(tmp_path: Path):
    root = validate_state_root(_private_dir(tmp_path / "state"))
    run = create_private_run_dir(root, "run-0001")
    return root, run


def test_state_root_requires_owner_mode_no_symlinks_and_outside_git(tmp_path: Path):
    state = _private_dir(tmp_path / "state")
    root = validate_state_root(state)
    assert root.path == state.absolute()
    root.close()
    state.chmod(0o750)
    with pytest.raises(StagingRejected, match="0700"):
        validate_state_root(state)
    state.chmod(0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(state, target_is_directory=True)
    with pytest.raises(StagingRejected, match="symlink"):
        validate_state_root(linked)
    repository = _private_dir(tmp_path / "repo")
    (repository / ".git").mkdir()
    with pytest.raises(StagingRejected, match="Git"):
        validate_state_root(_private_dir(repository / "state"))


def test_state_root_rejects_a_different_owner(tmp_path: Path, monkeypatch):
    state = _private_dir(tmp_path / "state")
    monkeypatch.setattr(os, "geteuid", lambda: state.stat().st_uid + 1)
    with pytest.raises(StagingRejected, match="owned by the current user"):
        validate_state_root(state)


def test_run_and_sparse_image_use_fixed_owner_only_names(tmp_path: Path):
    root, run = _capabilities(tmp_path)
    try:
        assert run.path.stat().st_mode & 0o777 == 0o700
        receipt = write_sparse_chunk(run, logical_size=8192, start=0, data=b"fixture", chunk_index=0)
        assert run.image_path.name == "image.qcow2.partial"
        assert run.image_path.stat().st_mode & 0o777 == 0o600
        assert receipt.sparse_hole is False
        with pytest.raises(StagingRejected, match="run capability"):
            write_sparse_chunk(run.image_path, logical_size=8192, start=0, data=b"x", chunk_index=1)  # type: ignore[arg-type]
    finally:
        run.close()
        root.close()


def test_first_image_creation_is_exclusive_and_rejects_preplaced_file(tmp_path: Path):
    root, run = _capabilities(tmp_path)
    try:
        run.image_path.write_bytes(b"preplaced")
        run.image_path.chmod(0o600)
        with pytest.raises(StagingRejected, match="already exists"):
            write_sparse_chunk(run, logical_size=4096, start=0, data=b"x", chunk_index=0)
    finally:
        run.close()
        root.close()


def test_capabilities_detect_path_replacement_after_open(tmp_path: Path):
    root, run = _capabilities(tmp_path)
    moved = tmp_path / "moved-run"
    run.path.rename(moved)
    run.path.mkdir(mode=0o700)
    try:
        with pytest.raises(StagingRejected, match="run directory identity changed"):
            write_sparse_chunk(run, logical_size=4096, start=0, data=b"x", chunk_index=0)
    finally:
        run.close()
        root.close()


def test_state_root_capability_detects_path_replacement_after_open(tmp_path: Path):
    state = _private_dir(tmp_path / "state")
    root = validate_state_root(state)
    moved = tmp_path / "moved-state"
    state.rename(moved)
    state.mkdir(mode=0o700)
    try:
        with pytest.raises(StagingRejected, match="state root identity changed"):
            root.assert_valid()
    finally:
        root.close()


def test_one_image_lock_rejects_concurrent_different_asset(tmp_path: Path):
    root = validate_state_root(_private_dir(tmp_path / "state"))
    first = ImageLock(root, "APT-DC-01")
    second = ImageLock(root, "Penny")
    try:
        with first:
            with pytest.raises(StagingRejected, match="already active"):
                second.acquire()
        with second:
            assert second.acquired
    finally:
        root.close()


def test_sparse_writer_leaves_zero_chunk_as_a_hole_and_bounds_writes(tmp_path: Path):
    root, run = _capabilities(tmp_path)
    try:
        zero = b"\0" * 4096
        zero_receipt = write_sparse_chunk(run, logical_size=16384, start=4096, data=zero, chunk_index=1)
        data_receipt = write_sparse_chunk(run, logical_size=16384, start=0, data=b"ABCD", chunk_index=0)
        assert run.image_path.stat().st_size == 16384
        assert run.image_path.read_bytes()[:4] == b"ABCD"
        assert zero_receipt.sparse_hole is True
        assert data_receipt.sparse_hole is False
        assert zero_receipt.sha256 == hashlib.sha256(zero).hexdigest()
        with pytest.raises(StagingRejected, match="logical size"):
            write_sparse_chunk(run, logical_size=16384, start=16383, data=b"xx", chunk_index=2)
    finally:
        run.close()
        root.close()


def test_sparse_writer_rejects_zero_chunk_over_existing_nonzero_data(tmp_path: Path):
    root, run = _capabilities(tmp_path)
    try:
        write_sparse_chunk(run, logical_size=4096, start=0, data=b"data", chunk_index=0)
        with pytest.raises(StagingRejected, match="zero chunk overlaps"):
            write_sparse_chunk(run, logical_size=4096, start=0, data=b"\0" * 4, chunk_index=0)
    finally:
        run.close()
        root.close()


def test_space_reservation_math_has_exact_two_gib_safety_floor():
    length = ADVERTISED_LENGTHS["APT-DC-01"]
    required = required_free_space(advertised_content_length=length, qcow_metadata_reserve=128 * 1024 * 1024, encrypted_output_reserve=512 * 1024 * 1024)
    assert required == length + 128 * 1024 * 1024 + 512 * 1024 * 1024 + 2 * 1024**3
    assert validate_free_space(required, required) == required
    with pytest.raises(StagingRejected, match="insufficient free space"):
        validate_free_space(required - 1, required)


def _interrupted_receipt(source, chunk):
    return AcquisitionReceipt(
        source=source,
        started_at="2026-09-09T00:00:00.000000Z",
        finished_at="2026-09-09T00:00:01.000000Z",
        range_size=4,
        chunks=(chunk,),
        final_image_sha256=None,
        sparse_logical_size=source.content_length,
        allocated_bytes=4096,
        completion_state="interrupted",
        failure_reason="signal",
        tool_version="phase-a",
        audit_chain_refs=("event-1",),
    )


def test_resume_requires_interrupted_matching_source_and_verified_chunks(tmp_path: Path):
    source = _source()
    root, run = _capabilities(tmp_path)
    try:
        first = write_sparse_chunk(run, logical_size=source.content_length, start=0, data=b"abcd", chunk_index=0, etag=source.etag, last_modified=source.last_modified)
        receipt = _interrupted_receipt(source, first)
        assert validate_resume(source, receipt, run, nbd_attached=False) == (first,)
        with run.image_path.open("r+b") as stream:
            stream.write(b"wxyz")
        with pytest.raises(StagingRejected, match="chunk hash"):
            validate_resume(source, receipt, run, nbd_attached=False)
        with pytest.raises(StagingRejected, match="source identity"):
            validate_resume(source.with_identity(etag='"v2"'), receipt, run, nbd_attached=False)
        with pytest.raises(StagingRejected, match="source identity"):
            validate_resume(replace(source, listing_sha256="e" * 64), receipt, run, nbd_attached=False)
        with pytest.raises(StagingRejected, match="NBD"):
            validate_resume(source, receipt, run, nbd_attached=True)
    finally:
        run.close()
        root.close()


@pytest.mark.parametrize(
    ("state", "finished", "reason", "final_hash", "message"),
    [
        ("running", "2026-09-09T00:00:01.000000Z", None, None, "running.*finish"),
        ("running", None, "reason", None, "running.*failure"),
        ("interrupted", None, "reason", None, "interrupted.*finish"),
        ("interrupted", "2026-09-09T00:00:01.000000Z", None, None, "interrupted.*reason"),
        ("failed", None, "reason", None, "failed.*finish"),
        ("failed", "2026-09-09T00:00:01.000000Z", None, None, "failed.*reason"),
        ("complete", "2026-09-09T00:00:01.000000Z", "reason", "f" * 64, "complete.*failure"),
        ("mystery", None, None, None, "completion state"),
    ],
)
def test_receipt_enforces_exact_state_fields(state, finished, reason, final_hash, message):
    source = _source()
    with pytest.raises(StagingRejected, match=message):
        AcquisitionReceipt(
            source=source, started_at="2026-09-09T00:00:00.000000Z", finished_at=finished,
            range_size=4, chunks=(), final_image_sha256=final_hash, sparse_logical_size=source.content_length,
            allocated_bytes=0, completion_state=state, failure_reason=reason, tool_version="phase-a", audit_chain_refs=(),  # type: ignore[arg-type]
        )


def test_receipt_rejects_finish_before_start_and_nonboolean_chunk_flag():
    source = _source()
    with pytest.raises(StagingRejected, match="before start"):
        AcquisitionReceipt(
            source=source, started_at="2026-09-09T00:00:02.000000Z", finished_at="2026-09-09T00:00:01.000000Z",
            range_size=4, chunks=(), final_image_sha256=None, sparse_logical_size=source.content_length,
            allocated_bytes=0, completion_state="failed", failure_reason="reason", tool_version="phase-a", audit_chain_refs=(),
        )
    with pytest.raises(StagingRejected, match="sparse_hole.*boolean"):
        ChunkReceipt(index=0, start=0, end=0, byte_count=1, sha256="f" * 64, etag=None, last_modified=None, sparse_hole=1)  # type: ignore[arg-type]


def test_receipt_rejects_log_injection_in_tool_and_audit_fields():
    source = _source()
    common = dict(
        source=source, started_at="2026-09-09T00:00:00.000000Z", finished_at=None,
        range_size=4, chunks=(), final_image_sha256=None, sparse_logical_size=source.content_length,
        allocated_bytes=0, completion_state="running", failure_reason=None,
    )
    with pytest.raises(StagingRejected, match="tool version"):
        AcquisitionReceipt(**common, tool_version="phase-a\nforged", audit_chain_refs=())
    with pytest.raises(StagingRejected, match="audit-chain"):
        AcquisitionReceipt(**common, tool_version="phase-a", audit_chain_refs=("event\nforged",))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"audit_chain_refs": "event-1"}, "audit-chain.*tuple"),
        ({"audit_chain_refs": ["event-1"]}, "audit-chain.*tuple"),
        ({"audit_chain_refs": ("",)}, "audit-chain"),
        ({"audit_chain_refs": ("x" * 129,)}, "audit-chain"),
        ({"audit_chain_refs": (1,)}, "audit-chain"),
        ({"started_at": 1}, "start timestamp"),
        ({"finished_at": 1, "completion_state": "failed", "failure_reason": "reason"}, "finish timestamp"),
        ({"completion_state": []}, "completion state"),
        ({"failure_reason": 1, "completion_state": "failed", "finished_at": "2026-09-09T00:00:01.000000Z"}, "failure reason"),
        ({"tool_version": 1}, "tool version"),
        ({"chunks": []}, "chunks.*tuple"),
        ({"chunks": ("not-a-chunk",)}, "chunk receipt"),
        ({"final_image_sha256": 1}, "final image hash"),
    ],
)
def test_receipt_malformed_runtime_shapes_fail_closed_as_staging_rejected(changes, message):
    source = _source()
    values = {
        "source": source,
        "started_at": "2026-09-09T00:00:00.000000Z",
        "finished_at": None,
        "range_size": 4,
        "chunks": (),
        "final_image_sha256": None,
        "sparse_logical_size": source.content_length,
        "allocated_bytes": 0,
        "completion_state": "running",
        "failure_reason": None,
        "tool_version": "phase-a",
        "audit_chain_refs": (),
    }
    values.update(changes)
    with pytest.raises(StagingRejected, match=message):
        AcquisitionReceipt(**values)


def test_acquisition_receipt_canonicalization_is_deterministic():
    source = _source()
    chunk = ChunkReceipt(index=0, start=0, end=3, byte_count=4, sha256=hashlib.sha256(b"abcd").hexdigest(), etag=source.etag, last_modified=source.last_modified, sparse_hole=False)
    receipt = _interrupted_receipt(source, chunk)
    parsed = json.loads(receipt.canonical_json())
    assert parsed["schema"] == "cptc11-acquisition-receipt-v1"
    assert parsed["source_authenticity"] == "unsigned-public-http"
    assert parsed["range_requests"] == 1
    assert parsed["downloaded_bytes"] == 4


def test_complete_receipt_rejects_a_partial_prefix():
    source = _source()
    chunk = ChunkReceipt(index=0, start=0, end=3, byte_count=4, sha256="f" * 64, etag=source.etag, last_modified=source.last_modified, sparse_hole=False)
    with pytest.raises(StagingRejected, match="complete source"):
        AcquisitionReceipt(
            source=source, started_at="2026-09-09T00:00:00.000000Z", finished_at="2026-09-09T00:00:01.000000Z",
            range_size=4, chunks=(chunk,), final_image_sha256="e" * 64, sparse_logical_size=source.content_length,
            allocated_bytes=4096, completion_state="complete", failure_reason=None, tool_version="phase-a", audit_chain_refs=(),
        )
