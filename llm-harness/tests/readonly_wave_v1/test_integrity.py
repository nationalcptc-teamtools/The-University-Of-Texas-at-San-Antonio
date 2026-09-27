import hashlib
import json
import os

import pytest

from cptc11_readonly_wave_v1.integrity import IntegrityError, TrustedReleasePolicy, verify_readonly_release


def test_release_manifest_hashes_regular_files_and_anchor(tmp_path):
    tmp_path.chmod(0o750)
    release = tmp_path / "release"; release.mkdir(mode=0o750); release.chmod(0o750)
    file = release / "worker.py"; file.write_text("print('ok')\n")
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    manifest = {"schema_version": 1, "release_id": "readonly-v1", "files": {"worker.py": digest}, "catalog_sha256": "a" * 64}
    manifest_path = tmp_path / "manifest.json"; manifest_path.write_text(json.dumps(manifest))
    anchor = tmp_path / "anchor"; anchor.write_text(hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n")
    verified = verify_readonly_release(release, manifest_path, TrustedReleasePolicy(os.getuid(), os.getgid(), tmp_path, file_mode=0o644), anchor)
    assert verified.release_id == "readonly-v1"


def test_release_rejects_symlink_and_hash_mismatch(tmp_path):
    tmp_path.chmod(0o750)
    release = tmp_path / "release"; release.mkdir(mode=0o750); release.chmod(0o750)
    (release / "real").write_text("x")
    (release / "link").symlink_to("real")
    manifest = {"schema_version": 1, "release_id": "x", "files": {"link": "0" * 64}, "catalog_sha256": "a" * 64}
    mp = tmp_path / "m"; mp.write_text(json.dumps(manifest))
    with pytest.raises(IntegrityError): verify_readonly_release(release, mp, TrustedReleasePolicy(os.getuid(), os.getgid(), tmp_path))
