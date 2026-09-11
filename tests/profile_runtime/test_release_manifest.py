from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path

import pytest

import cptc_harness.integrity as integrity
from cptc_harness.audit_service import _audit_package_root
from cptc_harness.contracts import PolicyError


def _verify(tmp_path, manifest_path=None):
    manifest = manifest_path or integrity._RELEASE_MANIFEST
    anchor = tmp_path / "portcast-live-v1.sha256"
    anchor.write_text(hashlib.sha256(manifest.read_bytes()).hexdigest() + "\n")
    return integrity._verify_portcast_release(
        release_root=integrity._RELEASE_ROOT,
        manifest_path=manifest,
        anchor_path=anchor,
        owner_uid=os.getuid(),
    )


def test_reviewed_portcast_release_covers_the_literal_enforcement_surface(tmp_path):
    verified = _verify(tmp_path)

    assert verified.release_id == "portcast-live-v1"
    assert set(verified.file_sha256) == integrity.PORTCAST_RELEASE_FILES
    assert verified.current_profile_workers[
        "web.http_jellyfin_public_identity"
    ] in verified.compatible_profile_workers["web.http_jellyfin_public_identity"]
    assert "cptc_harness/profile_runtime/capability.py" in verified.file_sha256
    for required in (
        "testing/__init__.py",
        "testing/cptc11_lab/__init__.py",
        "cptc_harness/memfd.py",
        "cptc_harness/contracts.py",
        "cptc_harness/registry.py",
        "cptc_harness/policy.py",
        "cptc_harness/storage.py",
        "cptc_harness/profile_runtime/service_client.py",
        "testing/cptc11_lab/portcast_service.py",
        "deployment/portcast-live-v1.service",
    ):
        assert required in verified.file_sha256
    assert verified.interpreter_path.is_absolute()
    assert verified.runtime_root == integrity._RELEASE_ROOT / "vendor/portcast-python3.14/site-packages"
    assert verified.runtime_file_sha256
    assert verified.runtime_packages["paramiko"] == "5.0.0"
    assert verified.runtime_packages["cryptography"] == "50.0.1"
    assert verified.native_file_sha256


def test_release_manifest_rejects_duplicate_json_fields(tmp_path, monkeypatch):
    original = integrity._RELEASE_MANIFEST.read_bytes()
    changed = original.replace(b'"version": 2', b'"version": 2, "version": 2', 1)
    path = tmp_path / "release-integrity.json"
    path.write_bytes(changed)
    with pytest.raises(PolicyError, match="manifest"):
        _verify(tmp_path, path)


@pytest.mark.parametrize("mutation", ("missing", "extra", "drift"))
def test_release_manifest_rejects_incomplete_or_drifted_file_map(
    tmp_path, monkeypatch, mutation
):
    value = json.loads(integrity._RELEASE_MANIFEST.read_text())
    files = value["portcast-live-v1"]["files"]
    if mutation == "missing":
        files.pop(next(iter(files)))
    elif mutation == "extra":
        files["unreviewed.py"] = "0" * 64
    else:
        files[next(iter(files))] = "0" * 64
    path = tmp_path / "release-integrity.json"
    path.write_text(json.dumps(value))
    with pytest.raises(PolicyError, match="release|manifest"):
        _verify(tmp_path, path)


def test_release_reader_rejects_symlinked_final_component(tmp_path, monkeypatch):
    root = tmp_path / "release"
    root.mkdir()
    target = root / "target.py"
    target.write_text("safe")
    link = root / "link.py"
    link.symlink_to(target)
    monkeypatch.setattr(integrity, "_RELEASE_ROOT", root)

    with pytest.raises(PolicyError, match="release file"):
        integrity._read_release_file("link.py")


def test_release_reader_rejects_symlinked_intermediate_component(tmp_path, monkeypatch):
    root = tmp_path / "release"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "worker.py").write_text("safe")
    (root / "component").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(integrity, "_RELEASE_ROOT", root)

    with pytest.raises(PolicyError, match="release file"):
        integrity._read_release_file("component/worker.py")


def test_release_reader_rejects_nonregular_final_component(tmp_path, monkeypatch):
    root = tmp_path / "release"
    root.mkdir()
    (root / "directory.py").mkdir()
    monkeypatch.setattr(integrity, "_RELEASE_ROOT", root)

    with pytest.raises(PolicyError, match="regular file"):
        integrity._read_release_file("directory.py")


def test_release_reader_detects_concurrent_replacement(tmp_path, monkeypatch):
    root = tmp_path / "release"
    root.mkdir()
    target = root / "worker.py"
    target.write_bytes(b"reviewed")
    replacement = root / "replacement.py"
    replacement.write_bytes(b"changed!")
    monkeypatch.setattr(integrity, "_RELEASE_ROOT", root)
    original_read = integrity.os.read
    replaced = False

    def replacing_read(descriptor, count):
        nonlocal replaced
        value = original_read(descriptor, count)
        if value and not replaced:
            replaced = True
            os.replace(replacement, target)
        return value

    monkeypatch.setattr(integrity.os, "read", replacing_read)
    with pytest.raises(PolicyError, match="changed during read"):
        integrity._read_release_file("worker.py")


@pytest.mark.parametrize("relative", sorted(integrity.PORTCAST_RELEASE_FILES))
def test_every_enforcement_file_drift_blocks_release(relative, tmp_path, monkeypatch):
    original = integrity._read_under_root

    def drifted(root, candidate, **kwargs):
        value = original(root, candidate, **kwargs)
        return value + b"\n# drift" if candidate == relative else value

    monkeypatch.setattr(integrity, "_read_under_root", drifted)
    with pytest.raises(PolicyError, match="differs"):
        _verify(tmp_path)


@pytest.mark.parametrize("mutation", ("missing", "symlink", "writable", "wrong"))
def test_external_anchor_is_mandatory_nofollow_and_nonwritable(tmp_path, mutation):
    anchor = tmp_path / "portcast-live-v1.sha256"
    expected = hashlib.sha256(integrity._RELEASE_MANIFEST.read_bytes()).hexdigest()
    if mutation == "symlink":
        target = tmp_path / "target"
        target.write_text(expected + "\n")
        anchor.symlink_to(target)
    elif mutation != "missing":
        anchor.write_text(("0" * 64 if mutation == "wrong" else expected) + "\n")
        if mutation == "writable":
            anchor.chmod(0o666)
    with pytest.raises(PolicyError, match="anchor|release file"):
        integrity._verify_portcast_release(
            release_root=integrity._RELEASE_ROOT,
            manifest_path=integrity._RELEASE_MANIFEST,
            anchor_path=anchor,
            owner_uid=os.getuid(),
        )


def test_interpreter_pin_cannot_be_self_selected(tmp_path):
    value = json.loads(integrity._RELEASE_MANIFEST.read_text())
    value["portcast-live-v1"]["interpreter"]["sha256"] = "0" * 64
    path = tmp_path / "release-integrity.json"
    path.write_text(json.dumps(value))
    with pytest.raises(PolicyError, match="manifest|interpreter"):
        _verify(tmp_path, path)


@pytest.mark.parametrize("mutation", ("missing", "drift"))
def test_release_rejects_missing_or_drifted_pinned_python_runtime(
    tmp_path, monkeypatch, mutation
):
    value = json.loads(integrity._RELEASE_MANIFEST.read_text())
    runtime = value["portcast-live-v1"]["python_runtime"]
    relative = next(iter(runtime["files"]))
    if mutation == "missing":
        runtime["files"].pop(relative)
    else:
        runtime["files"][relative] = "0" * 64
    path = tmp_path / "release-integrity.json"
    path.write_text(json.dumps(value))
    with pytest.raises(PolicyError, match="runtime|manifest"):
        _verify(tmp_path, path)


def test_release_rejects_drifted_native_runtime_dependency(tmp_path):
    value = json.loads(integrity._RELEASE_MANIFEST.read_text())
    native = value["portcast-live-v1"]["python_runtime"]["native_files"]
    native[next(iter(native))]["sha256"] = "0" * 64
    path = tmp_path / "release-integrity.json"
    path.write_text(json.dumps(value))
    with pytest.raises(PolicyError, match="native|runtime"):
        _verify(tmp_path, path)


def test_verified_audit_worker_imports_only_from_the_verified_release(tmp_path):
    release = integrity.VerifiedRelease(
        "portcast-live-v1", "1" * 64, {}, {}, {}, release_root=tmp_path
    )

    assert _audit_package_root(release) == tmp_path / "cptc_harness"
