from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct

import pytest

from cptc_harness.elf import (
    ElfValidationError,
    elf_metadata,
    verify_elf_closure,
    verify_private_native_closure,
)
import cptc_harness.integrity as integrity


ROOT = Path(__file__).parents[2]
_DEPLOYMENT_SPEC = importlib.util.spec_from_file_location(
    "elf_deployment", ROOT / "deployment/manage-portcast-service.py"
)
deployment = importlib.util.module_from_spec(_DEPLOYMENT_SPEC)
assert _DEPLOYMENT_SPEC.loader is not None
_DEPLOYMENT_SPEC.loader.exec_module(deployment)


def _closure():
    lock = json.loads(
        (ROOT / "cptc_harness/resources/portcast-cpython-runtime-v1.json").read_text()
    )
    runtime = ROOT / lock["root"]
    files = {name: (runtime / name).read_bytes() for name in lock["files"]}
    return files, dict(lock["elf_files"])


def _private_closure():
    private = json.loads(
        (ROOT / "cptc_harness/resources/portcast-python-runtime-v1.json").read_text()
    )
    cpython = json.loads(
        (ROOT / "cptc_harness/resources/portcast-cpython-runtime-v1.json").read_text()
    )
    private_root = ROOT / private["root"]
    cpython_root = ROOT / cpython["root"]
    return (
        {name: (private_root / name).read_bytes() for name in private["files"]},
        dict(private["native_files"]),
        {name: (cpython_root / name).read_bytes() for name in cpython["files"]},
    )


def test_sealed_runtime_elf_membership_hashes_and_needed_closure_are_exact():
    files, elf_files = _closure()
    verify_elf_closure(files, elf_files)
    assert "bin/age" in elf_files


def test_private_python_native_set_hashes_and_recursive_closure_are_exact():
    runtime, native, cpython = _private_closure()
    verify_private_native_closure(runtime, native, cpython)
    assert len(native) == 14
    assert all(elf_metadata(raw).interpreter is None for raw in runtime.values() if raw.startswith(b"\x7fELF"))


@pytest.mark.parametrize("mutation", ("missing", "extra", "corrupt"))
def test_private_python_native_lock_rejects_missing_extra_and_corrupt_entries(mutation):
    runtime, native, cpython = _private_closure()
    if mutation == "missing":
        native.pop(next(iter(native)))
    elif mutation == "extra":
        native["/usr/lib/libunreviewed.so.1"] = {
            "resolved_path": "/usr/lib/libunreviewed.so.1",
            "sha256": "0" * 64,
        }
    else:
        native[next(iter(native))]["sha256"] = "0" * 64
    with pytest.raises(ElfValidationError, match="native|dependency|hash"):
        verify_private_native_closure(runtime, native, cpython)


def test_private_python_native_closure_rejects_unknown_dependency():
    runtime, native, cpython = _private_closure()
    name = next(item for item, raw in runtime.items() if b"libc.so.6" in raw)
    runtime[name] = runtime[name].replace(b"libc.so.6", b"libx.so.6", 1)
    with pytest.raises(ElfValidationError, match="dependency"):
        verify_private_native_closure(runtime, native, cpython)


def _replace_first_dynamic_tag(raw: bytes, old: int, new: int) -> bytes:
    result = bytearray(raw)
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", result)
    program_offset, program_size, program_count = header[5], header[9], header[10]
    for index in range(program_count):
        values = struct.unpack_from(
            "<IIQQQQQQ", result, program_offset + index * program_size
        )
        if values[0] != 2:
            continue
        dynamic_offset, dynamic_size = values[2], values[5]
        for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
            tag, _value = struct.unpack_from("<qQ", result, offset)
            if tag == old:
                struct.pack_into("<q", result, offset, new)
                return bytes(result)
    raise AssertionError("ELF fixture has no requested dynamic tag")


def test_elf_metadata_rejects_unreviewed_interpreter():
    _files, elf_files = _closure()
    lock = json.loads(
        (ROOT / "cptc_harness/resources/portcast-cpython-runtime-v1.json").read_text()
    )
    root = ROOT / lock["root"]
    python = (root / "bin/python3.14").read_bytes()
    unsafe = python.replace(b"/lib64/", b"/tmpxx/", 1)
    files = {name: (root / name).read_bytes() for name in lock["files"]}
    files["bin/python3.14"] = unsafe
    elf_files["bin/python3.14"] = hashlib.sha256(unsafe).hexdigest()
    with pytest.raises(ElfValidationError, match="interpreter"):
        verify_elf_closure(files, elf_files)


@pytest.mark.parametrize("tag", (15, 29))
def test_elf_metadata_rejects_rpath_and_runpath(tag):
    files, elf_files = _closure()
    name = next(
        item for item in elf_files if elf_metadata(files[item]).needed
    )
    files[name] = _replace_first_dynamic_tag(files[name], 1, tag)
    elf_files[name] = hashlib.sha256(files[name]).hexdigest()
    with pytest.raises(ElfValidationError, match="RPATH|RUNPATH"):
        verify_elf_closure(files, elf_files)


@pytest.mark.parametrize("mutation", ("missing", "extra", "corrupt"))
def test_elf_manifest_rejects_missing_extra_and_corrupt_entries(mutation):
    files, elf_files = _closure()
    if mutation == "missing":
        elf_files.pop(next(iter(elf_files)))
    elif mutation == "extra":
        elf_files["lib/python3.14/os.py"] = hashlib.sha256(
            files["lib/python3.14/os.py"]
        ).hexdigest()
    else:
        elf_files[next(iter(elf_files))] = "0" * 64
    with pytest.raises(ElfValidationError, match="membership|hash"):
        verify_elf_closure(files, elf_files)


@pytest.mark.parametrize(
    ("replacement", "message"),
    ((b"libx.so.6", "incomplete"), (b"/bad.so.6", "unsafe")),
)
def test_elf_manifest_rejects_unknown_or_absolute_dependencies(replacement, message):
    files, elf_files = _closure()
    name = next(
        item for item in elf_files if b"libc.so.6" in files[item]
    )
    files[name] = files[name].replace(b"libc.so.6", replacement, 1)
    elf_files[name] = hashlib.sha256(files[name]).hexdigest()
    with pytest.raises(ElfValidationError, match=message):
        verify_elf_closure(files, elf_files)


def test_runtime_and_deployment_integrity_paths_invoke_exact_elf_verifier(
    tmp_path, monkeypatch
):
    integrity_calls = []
    original = integrity.verify_elf_closure
    original_private = integrity.verify_private_native_closure

    def record_integrity(files, elf_files):
        integrity_calls.append(
            ({name for name, raw in files.items() if raw.startswith(b"\x7fELF")}, set(elf_files))
        )
        return original(files, elf_files)

    monkeypatch.setattr(integrity, "verify_elf_closure", record_integrity)
    private_integrity_calls = []

    def record_private_integrity(runtime_files, native_files, sealed_files):
        private_integrity_calls.append((set(runtime_files), set(native_files), set(sealed_files)))
        return original_private(runtime_files, native_files, sealed_files)

    monkeypatch.setattr(
        integrity, "verify_private_native_closure", record_private_integrity
    )
    anchor = tmp_path / "portcast-live-v1.sha256"
    manifest = integrity._RELEASE_MANIFEST
    anchor.write_text(hashlib.sha256(manifest.read_bytes()).hexdigest() + "\n")
    integrity._verify_portcast_release(
        release_root=integrity._RELEASE_ROOT,
        manifest_path=manifest,
        anchor_path=anchor,
        owner_uid=os.getuid(),
    )
    assert len(integrity_calls) == 1
    assert integrity_calls[0][0] == integrity_calls[0][1]
    assert len(private_integrity_calls) == 1

    deployment_calls = []
    builtin_exec = exec

    private_deployment_calls = []

    def record_deployment(code, namespace):
        builtin_exec(code, namespace)
        verified = namespace["verify_elf_closure"]

        def wrapper(files, elf_files):
            deployment_calls.append(
                ({name for name, raw in files.items() if raw.startswith(b"\x7fELF")}, set(elf_files))
            )
            return verified(files, elf_files)

        namespace["verify_elf_closure"] = wrapper
        verified_private = namespace["verify_private_native_closure"]

        def private_wrapper(runtime_files, native_files, sealed_files):
            private_deployment_calls.append(
                (set(runtime_files), set(native_files), set(sealed_files))
            )
            return verified_private(runtime_files, native_files, sealed_files)

        namespace["verify_private_native_closure"] = private_wrapper

    monkeypatch.setitem(deployment.__dict__, "exec", record_deployment)
    deployment.verify_tree(
        ROOT,
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
        installed=False,
    )
    assert len(deployment_calls) == 1
    assert deployment_calls[0][0] == deployment_calls[0][1]
    assert len(private_deployment_calls) == 1
