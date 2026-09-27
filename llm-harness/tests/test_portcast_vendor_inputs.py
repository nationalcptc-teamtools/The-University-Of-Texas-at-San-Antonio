from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile

import pytest

import cptc_harness.elf as elf


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "portcast_vendor_inputs_tested", ROOT / "scripts/portcast_vendor_inputs.py"
)
vendor = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = vendor
SPEC.loader.exec_module(vendor)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _tar(path: Path, package: tuple[str, str, str], files: dict[str, tuple[bytes, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = (
        f"pkgname = {package[0]}\n"
        f"pkgver = {package[1]}\n"
        f"arch = {package[2]}\n"
    ).encode()
    with tarfile.open(path, "w:gz") as archive:
        for name, raw, mode in [
            (".PKGINFO", metadata, 0o644),
            *((name, raw, mode) for name, (raw, mode) in files.items()),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = mode
            info.mtime = 1
            archive.addfile(info, io.BytesIO(raw))


@pytest.fixture
def staged_runtime(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    stage = tmp_path / "stage"
    stage.mkdir()
    rootfs_lock_path = root / "cptc_harness/resources/portcast-cpython-runtime-v1.json"
    python_lock_path = root / "cptc_harness/resources/portcast-python-runtime-v1.json"
    inventory_path = root / "docs/harness/THIRD-PARTY-INVENTORY.json"
    manifest_path = root / "docs/harness/portcast-vendor-inputs/manifest-v1.json"

    root_component = "Arch runtime package: synthetic-root"
    python_component = "synthetic Python package"
    tool = b"synthetic tool\n"
    license_text = b"synthetic license\n"
    python_module = b"VALUE = 1\n"
    root_archive = stage / "packages/root.tar.gz"
    python_archive = stage / "packages/python.tar.gz"
    _tar(
        root_archive,
        ("synthetic-root", "1-1", "any"),
        {
            "usr/bin/tool": (tool, 0o755),
            "usr/share/licenses/synthetic-root/LICENSE": (license_text, 0o644),
        },
    )
    _tar(
        python_archive,
        ("synthetic-python", "1-1", "any"),
        {"usr/lib/python3.14/site-packages/example/__init__.py": (python_module, 0o644)},
    )
    signatures = {}
    for archive in (root_archive, python_archive):
        signature = Path(str(archive) + ".sig")
        signature.write_bytes((archive.name + " signature").encode())
        signatures[archive] = signature

    inventory = {
        "version": 2,
        "classification": "synthetic",
        "reviewed_at": "2026-01-01T00:00:00Z",
        "reviewed_by": "test",
        "copied_external_source_files": [],
        "components": [
            {
                "name": root_component,
                "version": "1-1",
                "license": "MIT",
                "source": "https://example.test/project/" + "a" * 40,
                "license_source": "https://example.test/project/" + "a" * 40 + "/LICENSE",
                "copied_files": [
                    f"{vendor.ROOTFS_ROOT}/bin/tool",
                    f"{vendor.ROOTFS_ROOT}/share/licenses/synthetic-root/LICENSE",
                    vendor.GENERATED_OFFER,
                ],
            },
            {
                "name": python_component,
                "copied_files": [f"{vendor.PYTHON_ROOT}/example/__init__.py"],
            },
        ],
    }
    root_lock = {
        "schema_version": 1,
        "python_abi": "cp314-x86_64-linux-gnu",
        "root": vendor.ROOTFS_ROOT,
        "entrypoints": {},
        "packages": {"synthetic-root": {"version": "1-1", "license": "MIT"}},
        "files": {
            "bin/tool": _sha(tool),
            "share/licenses/synthetic-root/LICENSE": _sha(license_text),
        },
        "elf_files": {},
        "build_tools": {},
        "external_tools": {},
        "transformations": [],
    }
    selected_licenses = {
        "synthetic-root": {"license": "MIT", "source_revision": "a" * 40}
    }
    offer = vendor._canonical_offer(inventory, root_lock, selected_licenses)
    root_lock["files"]["share/licenses/CORRESPONDING-SOURCE.json"] = _sha(offer)
    python_lock = {
        "schema_version": 1,
        "python_abi": "cp314-x86_64-linux-gnu",
        "root": vendor.PYTHON_ROOT,
        "packages": {"example": "1"},
        "import_roots": ["example"],
        "files": {"example/__init__.py": _sha(python_module)},
        "native_files": {},
    }
    _write_json(rootfs_lock_path, root_lock)
    _write_json(python_lock_path, python_lock)
    _write_json(inventory_path, inventory)

    def archive_record(component, archive, package):
        signature = signatures[archive]
        return {
            "component": component,
            "kind": "arch-package",
            "path": archive.relative_to(stage).as_posix(),
            "sha256": _sha(archive.read_bytes()),
            "bytes": archive.stat().st_size,
            "signature": {
                "path": signature.relative_to(stage).as_posix(),
                "sha256": _sha(signature.read_bytes()),
                "bytes": signature.stat().st_size,
                "signer_fingerprint": "0" * 40,
                "verified_at": "2026-01-01T00:00:00Z",
            },
            "attestation": None,
            "members": {
                f"{vendor.ROOTFS_ROOT}/share/licenses/synthetic-root/LICENSE":
                "usr/share/licenses/synthetic-root/LICENSE"
            }
            if package[0] == "synthetic-root"
            else {},
            "package": {
                "name": package[0],
                "version": package[1],
                "architecture": package[2],
            },
            "origin": "https://example.test/packages/",
        }

    manifest = {
        "schema_version": 1,
        "runtime_locks": {
            str(rootfs_lock_path.relative_to(root)): _sha(rootfs_lock_path.read_bytes()),
            str(python_lock_path.relative_to(root)): _sha(python_lock_path.read_bytes()),
        },
        "inventory": {
            "path": str(inventory_path.relative_to(root)),
            "sha256": _sha(inventory_path.read_bytes()),
        },
        "archives": [
            archive_record(root_component, root_archive, ("synthetic-root", "1-1", "any")),
            archive_record(python_component, python_archive, ("synthetic-python", "1-1", "any")),
        ],
        "source_files": [],
        "transformations": [],
        "generated_outputs": [
            {
                "output": vendor.GENERATED_OFFER,
                "generator": "canonical_corresponding_source_v1",
                "sha256": _sha(offer),
            }
        ],
        "selected_permissive_licenses": selected_licenses,
        "review": {
            "verified_at": "2026-01-01T00:00:00Z",
            "verified_by": "test",
            "signature_policy": "synthetic",
            "scope": "synthetic",
        },
    }
    _write_json(manifest_path, manifest)

    current = {
        f"{vendor.ROOTFS_ROOT}/bin/tool": (tool, 0o555),
        f"{vendor.ROOTFS_ROOT}/share/licenses/synthetic-root/LICENSE": (license_text, 0o444),
        vendor.GENERATED_OFFER: (offer, 0o444),
        f"{vendor.PYTHON_ROOT}/example/__init__.py": (python_module, 0o644),
    }
    for relative, (raw, mode) in current.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)

    monkeypatch.setattr(vendor, "ROOT", root)
    monkeypatch.setattr(vendor, "ROOTFS_LOCK", rootfs_lock_path)
    monkeypatch.setattr(vendor, "PYTHON_LOCK", python_lock_path)
    monkeypatch.setattr(vendor, "INVENTORY", inventory_path)
    monkeypatch.setattr(
        vendor, "SELECTED_LICENSE_PACKAGES", frozenset({"synthetic-root"})
    )
    monkeypatch.setattr(
        vendor,
        "APPROVED_SELECTED_LICENSES",
        {
            "synthetic-root": {
                "license": "MIT",
                "revision": "a" * 40,
                "source": "https://example.test/project/" + "a" * 40,
                "license_source": "https://example.test/project/"
                + "a" * 40
                + "/LICENSE",
            }
        },
    )
    monkeypatch.setattr(vendor, "APPROVED_PACKAGE_SIGNERS", frozenset({"0" * 40}))
    monkeypatch.setattr(elf, "verify_private_native_closure", lambda *_args: None)
    return root, stage, manifest_path, manifest


def test_staged_archives_reproduce_the_exact_synthetic_runtime(staged_runtime):
    root, stage, manifest, _value = staged_runtime
    plan = vendor.build_plan(stage, manifest)

    assert len(plan.files) == 4
    assert len(plan.archive_receipt) == 2
    vendor.compare_current(plan, root)


def test_staged_input_directory_rejects_extra_files(staged_runtime):
    _root, stage, manifest, _value = staged_runtime
    (stage / "unreviewed").write_text("extra")

    with pytest.raises(vendor.VendorInputError, match="file set differs"):
        vendor.build_plan(stage, manifest)


def test_staged_archive_hash_drift_fails_before_mapping(staged_runtime):
    _root, stage, manifest, _value = staged_runtime
    archive = stage / "packages/root.tar.gz"
    archive.write_bytes(archive.read_bytes() + b"drift")

    with pytest.raises(vendor.VendorInputError, match="size differs|hash differs"):
        vendor.build_plan(stage, manifest)


def test_unique_digest_at_wrong_archive_member_is_rejected(staged_runtime):
    _root, stage, manifest_path, manifest = staged_runtime
    archive = stage / "packages/root.tar.gz"
    _tar(
        archive,
        ("synthetic-root", "1-1", "any"),
        {
            "usr/lib/decoy": (b"synthetic tool\n", 0o755),
            "usr/share/licenses/synthetic-root/LICENSE": (
                b"synthetic license\n",
                0o644,
            ),
        },
    )
    record = next(
        item for item in manifest["archives"] if item["path"] == "packages/root.tar.gz"
    )
    record["sha256"] = _sha(archive.read_bytes())
    record["bytes"] = archive.stat().st_size
    _write_json(manifest_path, manifest)

    with pytest.raises(vendor.VendorInputError, match="member mapping is not exact"):
        vendor.build_plan(stage, manifest_path)


def test_vendor_manifest_rejects_duplicate_json_fields(staged_runtime):
    _root, stage, manifest, _value = staged_runtime
    raw = manifest.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1)
    manifest.write_text(raw)

    with pytest.raises(vendor.VendorInputError, match="duplicate JSON field"):
        vendor.build_plan(stage, manifest)


def test_archive_rejects_unsafe_member_even_with_reviewed_archive_hash(staged_runtime):
    _root, stage, manifest_path, manifest = staged_runtime
    archive = stage / "packages/root.tar.gz"
    _tar(
        archive,
        ("synthetic-root", "1-1", "any"),
        {
            "usr/bin/tool": (b"synthetic tool\n", 0o755),
            "usr/share/licenses/synthetic-root/LICENSE": (b"synthetic license\n", 0o644),
            "../escape": (b"unsafe", 0o644),
        },
    )
    record = next(item for item in manifest["archives"] if item["path"] == "packages/root.tar.gz")
    record["sha256"] = _sha(archive.read_bytes())
    record["bytes"] = archive.stat().st_size
    _write_json(manifest_path, manifest)

    with pytest.raises(vendor.VendorInputError, match="unsafe member"):
        vendor.build_plan(stage, manifest_path)


def test_archive_reader_enforces_limits_without_getmembers(staged_runtime, monkeypatch):
    _root, stage, manifest, _value = staged_runtime

    def forbidden(*_args, **_kwargs):
        raise AssertionError("getmembers allocated the complete archive index")

    monkeypatch.setattr(vendor.tarfile.TarFile, "getmembers", forbidden)
    vendor.build_plan(stage, manifest)
    monkeypatch.setattr(vendor, "MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(vendor.VendorInputError, match="member limit exceeded"):
        vendor.build_plan(stage, manifest)


def test_archive_member_reader_uses_bounded_chunks(monkeypatch):
    calls = []

    class Reader:
        def __init__(self, raw):
            self.raw = raw

        def read(self, size):
            calls.append(size)
            chunk, self.raw = self.raw[:size], self.raw[size:]
            return chunk

    raw = b"x" * (1024 * 1024 + 7)
    assert vendor._read_member(Reader(raw), len(raw), "fixture.tar", "member") == raw
    assert calls == [1024 * 1024, 7]
    assert all(isinstance(size, int) and 0 < size <= 1024 * 1024 for size in calls)

    monkeypatch.setattr(vendor, "MAX_ARCHIVE_MEMBER_BYTES", 4)
    with pytest.raises(vendor.VendorInputError, match="member size limit exceeded"):
        vendor._read_member(Reader(b"12345"), 5, "fixture.tar", "member")


def test_arch_package_requires_reviewed_signature_record(staged_runtime):
    _root, stage, manifest_path, manifest = staged_runtime
    record = manifest["archives"][0]
    signature_path = stage / record["signature"]["path"]
    signature_path.unlink()
    record["signature"] = None
    _write_json(manifest_path, manifest)

    with pytest.raises(vendor.VendorInputError, match="signature record is required"):
        vendor.build_plan(stage, manifest_path)


def test_signature_review_fields_are_strict(staged_runtime):
    _root, stage, manifest_path, manifest = staged_runtime
    manifest["archives"][0]["signature"]["signer_fingerprint"] = "not-a-fingerprint"
    _write_json(manifest_path, manifest)

    with pytest.raises(vendor.VendorInputError, match="fingerprint"):
        vendor.build_plan(stage, manifest_path)


def test_signature_signer_must_be_on_the_reviewed_allowlist(staged_runtime):
    _root, stage, manifest_path, manifest = staged_runtime
    manifest["archives"][0]["signature"]["signer_fingerprint"] = "F" * 40
    _write_json(manifest_path, manifest)

    with pytest.raises(vendor.VendorInputError, match="fingerprint"):
        vendor.build_plan(stage, manifest_path)


def test_release_archive_requires_reviewed_attestation(staged_runtime):
    _root, stage, manifest_path, manifest = staged_runtime
    record = manifest["archives"][0]
    (stage / record["signature"]["path"]).unlink()
    record["kind"] = "release-tar"
    record["package"] = None
    record["signature"] = None
    record["attestation"] = None
    _write_json(manifest_path, manifest)

    with pytest.raises(vendor.VendorInputError, match="attestation is required"):
        vendor.build_plan(stage, manifest_path)


def test_selected_license_requires_immutable_inventory_origin(staged_runtime):
    root, stage, manifest_path, manifest = staged_runtime
    inventory_path = root / "docs/harness/THIRD-PARTY-INVENTORY.json"
    inventory = json.loads(inventory_path.read_text())
    inventory["components"][0]["license_source"] = "https://example.test/latest/LICENSE"
    _write_json(inventory_path, inventory)
    manifest["inventory"]["sha256"] = _sha(inventory_path.read_bytes())
    _write_json(manifest_path, manifest)

    with pytest.raises(
        vendor.VendorInputError,
        match="selected permissive-license provenance differs",
    ):
        vendor.build_plan(stage, manifest_path)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/example/project/blob/main/LICENSE?revision=" + "a" * 40,
        "https://github.com/example/project/blob/main/LICENSE#" + "a" * 40,
        "https://github.com/example/project/blob/latest/" + "a" * 40 + "/LICENSE",
        "https://example.invalid/project/commit/" + "a" * 40,
        "https://github.com/example/project/commit/" + "a" * 40 + "/../../main",
        "https://github.com/example/project/blob/" + "a" * 40 + "/%2e%2e/main/LICENSE",
        "https://forge.sourceware.org/glibc/glibc-mirror/src/commit/"
        + "a" * 40
        + "/../../main",
        "https://kernel.googlesource.com/project/+/" + "a" * 40 + "/%2E%2E/main",
    ],
)
def test_source_provenance_rejects_mutable_or_unrelated_urls(url):
    assert not vendor._immutable_source_url(url, "a" * 40)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/example/project/commit/" + "a" * 40,
        "https://github.com/example/project/blob/" + "a" * 40 + "/LICENSE",
        "https://forge.sourceware.org/glibc/glibc-mirror/src/commit/"
        + "a" * 40
        + "/COPYING",
        "https://go.googlesource.com/go/+/" + "a" * 40 + "/LICENSE",
    ],
)
def test_source_provenance_accepts_reviewed_immutable_url_forms(url):
    assert vendor._immutable_source_url(url, "a" * 40)


def test_materialized_trees_are_byte_and_mode_identical(staged_runtime, tmp_path):
    _root, stage, manifest, _value = staged_runtime
    plan = vendor.build_plan(stage, manifest)
    first = tmp_path / "first"
    second = tmp_path / "second"

    vendor.materialize(plan, first)
    vendor.materialize(plan, second)

    for relative, planned in plan.files.items():
        one = first / relative
        two = second / relative
        assert one.read_bytes() == two.read_bytes() == planned.raw
        assert stat.S_IMODE(one.stat().st_mode) == stat.S_IMODE(two.stat().st_mode) == planned.mode


def test_current_runtime_mode_drift_is_visible(staged_runtime):
    root, stage, manifest, _value = staged_runtime
    plan = vendor.build_plan(stage, manifest)
    changed = root / vendor.ROOTFS_ROOT / "bin/tool"
    changed.chmod(0o755)

    with pytest.raises(vendor.VendorInputError, match="mode differs"):
        vendor.compare_current(plan, root)


def test_recorded_transform_rejects_a_different_patchelf_version(monkeypatch):
    class Completed:
        stdout = "patchelf 99.0\n"

    monkeypatch.setattr(vendor.subprocess, "run", lambda *args, **kwargs: Completed())
    record = {"tool": {"path": "/usr/bin/patchelf", "version": "patchelf 0.19.1"}}

    with pytest.raises(vendor.VendorInputError, match="version differs"):
        vendor._transform(b"input", record)


def test_legacy_entry_points_do_not_discover_host_packages():
    for relative in (
        "scripts/vendor-portcast-rootfs-runtime.py",
        "scripts/vendor-portcast-runtime.py",
    ):
        source = (ROOT / relative).read_text()
        assert "from portcast_vendor_inputs import main" in source
        assert "importlib.metadata" not in source
        assert "pacman" not in source
        assert "ldconfig" not in source


def test_cli_has_no_custom_manifest_admission_path(tmp_path):
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/portcast_vendor_inputs.py"),
            "--inputs",
            str(tmp_path),
            "--manifest",
            str(tmp_path / "forged.json"),
        ],
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "unrecognized arguments: --manifest" in completed.stderr


def test_repo_path_wins_over_pythonpath_shadow(tmp_path):
    fake = tmp_path / "fake"
    package = fake / "cptc_harness"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "elf.py").write_text("SHADOWED = True\n")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = f"{fake}:{ROOT}"
    code = (
        "import runpy; "
        f"runpy.run_path({str(ROOT / 'scripts/portcast_vendor_inputs.py')!r}, "
        "run_name='reviewed_vendor_builder'); "
        "import cptc_harness.elf as elf; print(elf.__file__)"
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
        ROOT / "cptc_harness/elf.py"
    ).resolve()
