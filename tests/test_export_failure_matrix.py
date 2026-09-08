"""Synthetic export interruption and quarantined-artifact boundaries."""
import errno
import hashlib
import os
from pathlib import Path
import stat
import subprocess

import pytest

from cptc_harness import exports
from cptc_harness.contracts import PolicyError
from cptc_harness.storage import write_json
from test_integration import age_identity, private


@pytest.mark.parametrize("component", ["quarantine", ".quarantine", "QUARANTINE", "unaccepted", ".partial", "browser-profile", "credentials"])
def test_quarantined_material_is_never_selectable_even_inside_artifact_roots(private, component):
    source = private / "artifacts" / component / "record.json"
    source.parent.mkdir(parents=True, mode=0o700); write_json(source, {"synthetic": True})
    relative = str(source.relative_to(private))
    with pytest.raises(PolicyError): exports.prepare_export(private, (relative,), operator="human")
    forged = exports.ExportReview(str(private), ({"path": relative, "bytes": source.stat().st_size,
                                                "sha256": hashlib.sha256(source.read_bytes()).hexdigest()},), "human")
    with pytest.raises(PolicyError): exports._archive(forged)


@pytest.mark.parametrize("failure", ["encrypt_error", "encrypt_timeout", "decrypt_error", "decrypt_timeout", "disk_full", "directory_sync", "destination_race"])
def test_interrupted_export_preserves_source_and_never_reports_success(private, age_identity, monkeypatch, failure):
    age, identity, recipient = age_identity
    source = private / "policy.json"; write_json(source, {"synthetic": "reviewed"})
    original = source.read_bytes()
    review = exports.prepare_export(private, ("policy.json",), operator="human")
    destination = private / "reviewed-export.age"
    real_run, real_sync, real_link = exports.subprocess.run, exports.os.fsync, exports.os.link
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        decrypt = "--decrypt" in command
        applicable = failure.startswith("decrypt") if decrypt else failure.startswith("encrypt")
        if failure == "disk_full" and not decrypt: raise OSError(errno.ENOSPC, "synthetic full storage")
        if applicable:
            if not decrypt: kwargs["stdout"].write(b"synthetic-incomplete-ciphertext")
            if failure.endswith("timeout"): raise subprocess.TimeoutExpired(command, 60)
            return subprocess.CompletedProcess(command, 1, b"", b"synthetic failure")
        return real_run(command, **kwargs)
    def fsync(fd):
        if failure == "directory_sync" and stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "synthetic directory durability failure")
        return real_sync(fd)
    def link(src, dst, **kwargs):
        if failure == "destination_race": Path(dst).write_bytes(b"synthetic existing destination")
        return real_link(src, dst, **kwargs)
    monkeypatch.setattr(exports.subprocess, "run", run)
    monkeypatch.setattr(exports.os, "fsync", fsync)
    monkeypatch.setattr(exports.os, "link", link)
    with pytest.raises((PolicyError, OSError)):
        exports.encrypted_export(review, destination, approved_hash=review.review_hash,
                                 recipient=recipient, age=age, verify_identity=identity)
    assert source.read_bytes() == original
    assert not list(private.glob(".*.partial"))
    if failure == "directory_sync":
        # A completed ciphertext may exist, but no success receipt was returned.
        assert destination.read_bytes().startswith(b"age-encryption.org/")
    elif failure == "destination_race":
        assert destination.read_bytes() == b"synthetic existing destination"
    else: assert not destination.exists()
    assert len(calls) <= 2  # No retry after an uncertain side effect.


@pytest.mark.parametrize("name", [".audit-failure.json", ".audit-state.json", ".audit.lock",
                                  "rotation.pending.json", ".reserve-" + "0" * 64])
def test_incomplete_audit_internal_is_not_exportable(private, name):
    source = private / "audit" / name
    source.parent.mkdir(parents=True, mode=0o700); source.write_bytes(b"synthetic")
    relative = str(source.relative_to(private))
    with pytest.raises(PolicyError):
        exports.prepare_export(private, (relative,), operator="human")
    forged = exports.ExportReview(str(private), ({"path": relative, "bytes": len(b"synthetic"),
                                                  "sha256": hashlib.sha256(b"synthetic").hexdigest()},), "human")
    with pytest.raises(PolicyError):
        exports._archive(forged)


def test_forged_review_cannot_bypass_aggregate_size_limit(private, monkeypatch):
    source = private / "artifacts" / "synthetic.bin"
    source.parent.mkdir(parents=True, mode=0o700); source.write_bytes(b"x")
    item = {"path": str(source.relative_to(private)), "bytes": exports.MAX_BUNDLE_BYTES // 2 + 1,
            "sha256": hashlib.sha256(b"x").hexdigest()}
    forged = exports.ExportReview(str(private), tuple({**item, "path": item["path"] + str(index)}
                                                       for index in range(2)), "human")
    with pytest.raises(PolicyError, match="allowance"):
        exports._archive(forged)
    with pytest.raises(PolicyError, match="allowance"):
        exports.verify_archive(b"", forged)


@pytest.mark.parametrize("component", ["quarantine", "unaccepted", ".partial", "result.partial"])
def test_encrypted_export_rejects_incomplete_destination_directory(private, age_identity, component):
    age, identity, recipient = age_identity
    source = private / "policy.json"; write_json(source, {"synthetic": "reviewed"})
    review = exports.prepare_export(private, ("policy.json",), operator="human")
    with pytest.raises(PolicyError, match="destination"):
        exports.encrypted_export(review, private / component / "bundle.age",
                                 approved_hash=review.review_hash, recipient=recipient,
                                 age=age, verify_identity=identity)
