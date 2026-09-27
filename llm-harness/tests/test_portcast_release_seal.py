from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import cptc_harness.integrity as integrity


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/seal-portcast-release.py"
SPEC = importlib.util.spec_from_file_location("portcast_release_seal", SCRIPT)
seal = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(seal)


def _bootstrap_entries(raw: bytes) -> dict[str, str]:
    lines = raw.decode("ascii").splitlines()
    assert lines.pop(0) == "PORTCAST-BOOTSTRAP-V1"
    return {
        relative: digest
        for digest, relative in (line.split("  ", 1) for line in lines)
    }


def test_release_seal_plan_is_deterministic_and_covers_installed_payload():
    current_manifest_sha256 = hashlib.sha256(
        (ROOT / seal.MANIFEST_RELATIVE).read_bytes()
    ).hexdigest()
    first = seal.build_plan(ROOT)
    second = seal.build_plan(ROOT)

    assert first == second
    assert first.current_manifest_sha256 == current_manifest_sha256
    bootstrap = _bootstrap_entries(first.bootstrap)
    manifest = json.loads(first.manifest)
    section = manifest["portcast-live-v1"]
    expected = set(integrity.PORTCAST_RELEASE_FILES) - seal.SELF_VERIFIED_FILES
    expected.update(
        f"{section['python_runtime']['root']}/{relative}"
        for relative in section["python_runtime"]["files"]
    )
    expected.update(
        f"{section['cpython_runtime']['root']}/{relative}"
        for relative in section["cpython_runtime"]["files"]
    )

    assert set(bootstrap) == expected
    assert section["bootstrap_manifest"]["sha256"] == hashlib.sha256(
        first.bootstrap
    ).hexdigest()
    assert section["files"][seal.BOOTSTRAP_RELATIVE] == hashlib.sha256(
        first.bootstrap
    ).hexdigest()
    assert section["python_runtime"] == json.loads(
        (ROOT / seal.PYTHON_LOCK_RELATIVE).read_text()
    )
    assert section["cpython_runtime"] == json.loads(
        (ROOT / seal.CPYTHON_LOCK_RELATIVE).read_text()
    )


def test_checked_in_release_seal_matches_deterministic_plan():
    plan = seal.build_plan(ROOT)

    assert (ROOT / seal.BOOTSTRAP_RELATIVE).read_bytes() == plan.bootstrap
    assert (ROOT / seal.MANIFEST_RELATIVE).read_bytes() == plan.manifest


def test_release_sealer_rejects_unreviewed_executable_pin(monkeypatch):
    original_read = seal._read
    manifest = json.loads((ROOT / seal.MANIFEST_RELATIVE).read_text())
    manifest["executables"]["/usr/bin/python3"] = "0" * 64
    changed = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()

    def read(root, relative):
        if relative == seal.MANIFEST_RELATIVE:
            return changed
        return original_read(root, relative)

    monkeypatch.setattr(seal, "_read", read)
    with pytest.raises(seal.SealError, match="executable pins differ"):
        seal.build_plan(ROOT)


def test_plan_digest_binds_current_manifest_even_when_outputs_match(monkeypatch):
    original = seal.build_plan(ROOT)
    original_read = seal._read
    manifest = json.loads((ROOT / seal.MANIFEST_RELATIVE).read_text())
    first_file = next(iter(manifest["portcast-live-v1"]["files"]))
    manifest["portcast-live-v1"]["files"][first_file] = "0" * 64
    changed = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()

    def read(root, relative):
        if relative == seal.MANIFEST_RELATIVE:
            return changed
        return original_read(root, relative)

    monkeypatch.setattr(seal, "_read", read)
    revised = seal.build_plan(ROOT)
    assert revised.bootstrap == original.bootstrap
    assert revised.manifest == original.manifest
    assert revised.current_manifest_sha256 != original.current_manifest_sha256
    assert revised.plan_sha256 != original.plan_sha256


def test_admission_rechecks_baseline_before_any_write(monkeypatch):
    original = seal.build_plan(ROOT)
    original_read = seal._read
    manifest = json.loads((ROOT / seal.MANIFEST_RELATIVE).read_text())
    first_file = next(iter(manifest["portcast-live-v1"]["files"]))
    manifest["portcast-live-v1"]["files"][first_file] = "0" * 64
    changed = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()

    def read(root, relative):
        if relative == seal.MANIFEST_RELATIVE:
            return changed
        return original_read(root, relative)

    monkeypatch.setattr(seal, "_read", read)
    monkeypatch.setattr(
        seal,
        "_atomic_write_at",
        lambda *_args: pytest.fail("admission wrote before baseline recheck"),
    )
    with pytest.raises(seal.SealError, match="inputs changed"):
        seal.admit(ROOT, original, original.plan_sha256)


def _resources_fixture(tmp_path):
    resources = tmp_path / "cptc_harness/resources"
    resources.mkdir(parents=True)
    for name in (
        Path(seal.BOOTSTRAP_RELATIVE).name,
        Path(seal.MANIFEST_RELATIVE).name,
    ):
        target = resources / name
        target.write_bytes(b"old")
        target.chmod(0o600)
    return resources


def test_atomic_write_rejects_symlink_target_and_parent(tmp_path):
    resources = _resources_fixture(tmp_path)
    target = resources / Path(seal.MANIFEST_RELATIVE).name
    target.unlink()
    target.symlink_to(tmp_path / "outside")
    descriptor = seal._open_resources_directory(tmp_path)
    try:
        with pytest.raises(seal.SealError, match="target metadata is unsafe"):
            seal._atomic_write_at(descriptor, target.name, b"new")
    finally:
        os.close(descriptor)

    other = tmp_path / "other"
    other.mkdir()
    linked = other / "cptc_harness"
    linked.symlink_to(tmp_path / "cptc_harness", target_is_directory=True)
    with pytest.raises(seal.SealError, match="release directory is unavailable"):
        seal._open_resources_directory(other)


def test_release_sealer_rejects_a_different_effective_user(tmp_path, monkeypatch):
    _resources_fixture(tmp_path)
    monkeypatch.setattr(seal.os, "geteuid", lambda: tmp_path.stat().st_uid + 1)
    with pytest.raises(seal.SealError, match="trusted checkout owner"):
        seal._open_resources_directory(tmp_path)


def test_atomic_write_stays_on_open_directory_after_parent_rename(tmp_path):
    _resources_fixture(tmp_path)
    descriptor = seal._open_resources_directory(tmp_path)
    detached = tmp_path / "detached"
    (tmp_path / "cptc_harness").rename(detached)
    active = tmp_path / "cptc_harness/resources"
    active.mkdir(parents=True)
    target_name = Path(seal.MANIFEST_RELATIVE).name
    (active / target_name).write_bytes(b"active")
    try:
        seal._atomic_write_at(descriptor, target_name, b"anchored")
    finally:
        os.close(descriptor)

    assert (detached / "resources" / target_name).read_bytes() == b"anchored"
    assert (active / target_name).read_bytes() == b"active"


def test_atomic_write_handles_short_writes_and_fails_closed(tmp_path, monkeypatch):
    resources = _resources_fixture(tmp_path)
    descriptor = seal._open_resources_directory(tmp_path)
    target_name = Path(seal.MANIFEST_RELATIVE).name
    real_write = seal.os.write

    def short_write(fd, raw):
        return real_write(fd, bytes(raw[:1]))

    monkeypatch.setattr(seal.os, "write", short_write)
    seal._atomic_write_at(descriptor, target_name, b"replacement")
    assert (resources / target_name).read_bytes() == b"replacement"
    monkeypatch.setattr(seal.os, "write", lambda *_args: (_ for _ in ()).throw(OSError("injected")))
    with pytest.raises(seal.SealError, match="cannot persist"):
        seal._atomic_write_at(descriptor, Path(seal.BOOTSTRAP_RELATIVE).name, b"new")
    assert (resources / Path(seal.BOOTSTRAP_RELATIVE).name).read_bytes() == b"old"
    os.close(descriptor)


def test_atomic_write_rejects_stale_stage_and_second_lock(tmp_path):
    resources = _resources_fixture(tmp_path)
    target_name = Path(seal.MANIFEST_RELATIVE).name
    (resources / (target_name + ".new")).write_bytes(b"stale")
    first = seal._open_resources_directory(tmp_path)
    second = seal._open_resources_directory(tmp_path)
    try:
        seal._lock_resources(first)
        with pytest.raises(seal.SealError, match="another release sealer"):
            seal._lock_resources(second)
        with pytest.raises(seal.SealError, match="stale release-seal staging"):
            seal._atomic_write_at(first, target_name, b"new")
    finally:
        os.close(first)
        os.close(second)


def test_cli_has_no_current_manifest_digest_override():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--expected-current-manifest-sha256", "0" * 64],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "unrecognized arguments" in completed.stderr


def test_release_sealer_uses_repo_integrity_module_before_pythonpath(tmp_path):
    fake = tmp_path / "fake/cptc_harness"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("")
    (fake / "integrity.py").write_text("PORTCAST_RELEASE_FILES = set()\n")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = f"{fake.parent}:{ROOT}"
    code = (
        "import runpy; "
        f"runpy.run_path({str(SCRIPT)!r}, run_name='reviewed_release_sealer'); "
        "import cptc_harness.integrity as integrity; print(integrity.__file__)"
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    assert Path(completed.stdout.strip()).resolve() == (
        ROOT / "cptc_harness/integrity.py"
    ).resolve()
