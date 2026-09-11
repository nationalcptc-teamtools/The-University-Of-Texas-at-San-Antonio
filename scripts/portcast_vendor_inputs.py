#!/usr/bin/env python3
"""Reproduce the sealed PortCast runtimes from reviewed archive inputs.

The runtime locks and third-party inventory are trusted release inputs.  This
module never discovers files from the host installation.  It reads only the
operator-supplied archive directory and small, reviewed notice files that are
part of the source release.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Sequence
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path[:] = [entry for entry in sys.path if entry != str(ROOT)]
sys.path.insert(0, str(ROOT))
MANIFEST = ROOT / "docs/harness/portcast-vendor-inputs/manifest-v1.json"
ROOTFS_LOCK = ROOT / "cptc_harness/resources/portcast-cpython-runtime-v1.json"
PYTHON_LOCK = ROOT / "cptc_harness/resources/portcast-python-runtime-v1.json"
INVENTORY = ROOT / "docs/harness/THIRD-PARTY-INVENTORY.json"

ROOTFS_ROOT = "vendor/portcast-rootfs-runtime"
PYTHON_ROOT = "vendor/portcast-python3.14/site-packages"
GENERATED_OFFER = f"{ROOTFS_ROOT}/share/licenses/CORRESPONDING-SOURCE.json"
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_UNPACKED_BYTES = 1 << 30
MAX_ARCHIVE_MEMBER_BYTES = 64 << 20
SELECTED_LICENSE_PACKAGES = frozenset(
    {"libcap", "util-linux-libs", "xz", "zstd"}
)
APPROVED_SELECTED_LICENSES = {
    "libcap": {
        "license": "BSD-3-Clause",
        "revision": "a1fef85d27d0ee12729a64d1c9b2183c6007e56a",
        "source": "https://kernel.googlesource.com/pub/scm/libs/libcap/libcap.git/+/a1fef85d27d0ee12729a64d1c9b2183c6007e56a",
        "license_source": "https://kernel.googlesource.com/pub/scm/libs/libcap/libcap.git/+/a1fef85d27d0ee12729a64d1c9b2183c6007e56a/License",
    },
    "util-linux-libs": {
        "license": "BSD-3-Clause AND LicenseRef-PublicDomain",
        "revision": "6f20a5defcf9066d4d2af372424a1576bd3d495d",
        "source": "https://github.com/util-linux/util-linux/commit/6f20a5defcf9066d4d2af372424a1576bd3d495d",
        "license_source": "https://github.com/util-linux/util-linux/blob/6f20a5defcf9066d4d2af372424a1576bd3d495d/libuuid/COPYING",
    },
    "xz": {
        "license": "0BSD",
        "revision": "4b73f2ec19a99ef465282fbce633e8deb33691b3",
        "source": "https://github.com/tukaani-project/xz/commit/4b73f2ec19a99ef465282fbce633e8deb33691b3",
        "license_source": "https://github.com/tukaani-project/xz/blob/4b73f2ec19a99ef465282fbce633e8deb33691b3/COPYING",
    },
    "zstd": {
        "license": "BSD-3-Clause AND MIT",
        "revision": "f8745da6ff1ad1e7bab384bd1f9d742439278e99",
        "source": "https://github.com/facebook/zstd/commit/f8745da6ff1ad1e7bab384bd1f9d742439278e99",
        "license_source": "https://github.com/facebook/zstd/blob/f8745da6ff1ad1e7bab384bd1f9d742439278e99/LICENSE",
    },
}
APPROVED_PACKAGE_SIGNERS = frozenset(
    {
        "05C7775A9E8B977407FE08E69D4C5AA15426DA0A",
        "1519D5ABA65BF6FC2B73C7567A4E76095D8A52E4",
        "5B7E3FB71B7F10329A1C03AB771DF6627EDF681F",
        "882DCFE48E2051D48E2562ABF3B607488DB35A47",
        "B5971F2C5C10A9A08C60030F786C63F330D7CB92",
        "EB3D764FF5D87E0818A3E0E5F05E8C12131AEB5E",
    }
)
AGE_ARCHIVE_SHA256 = "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"
AGE_PROOF_SHA256 = "98402fa59b4e433426156b4a7e74a32e44902e0434c61158f7de18ffc84f1f97"
AGE_SIGSUM_KEYS_SHA256 = "ca60c0504ac65cc43ef180a34579ce6ed8f909b9136afef0ca42c88280f42cdc"
AGE_SOURCE_REVISION = "b74dce4cdbe35b5e5f66c06d9612b72f89028758"
SIGSUM_VERIFIER_SHA256 = "033d1d77a6a4e58a62f730c00749feb730ef3003a329e1041873bcb019232580"
_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class VendorInputError(ValueError):
    """A staged input cannot reproduce the reviewed runtime."""


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise VendorInputError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(), object_pairs_hook=_object_no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VendorInputError(f"cannot read reviewed JSON: {path}") from exc
    if not isinstance(value, dict):
        raise VendorInputError(f"reviewed JSON must be an object: {path}")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expect_keys(value: dict[str, Any], keys: set[str], context: str) -> None:
    if set(value) != keys:
        raise VendorInputError(f"{context} has unsupported fields")


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise VendorInputError(f"{context} must be a SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise VendorInputError(f"{context} must be a SHA-256 digest") from exc
    return value.lower()


def _relative(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise VendorInputError(f"{context} must be a relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or ".." in path.parts:
        raise VendorInputError(f"{context} is unsafe")
    return value


def _regular(path: Path, *, beneath: Path | None = None) -> Path:
    if beneath is not None:
        try:
            path.relative_to(beneath)
        except ValueError as exc:
            raise VendorInputError(f"input escapes its reviewed root: {path}") from exc
    current = path
    stop = beneath.parent if beneath is not None else path.parent.parent
    while current != stop:
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise VendorInputError(f"input is unavailable: {path}") from exc
        if stat.S_ISLNK(mode):
            raise VendorInputError(f"input path contains a symlink: {path}")
        if current == path and not stat.S_ISREG(mode):
            raise VendorInputError(f"input is not a regular file: {path}")
        current = current.parent
    return path


def _stage_root(path: Path) -> Path:
    if not path.is_absolute():
        raise VendorInputError("--inputs must be an absolute directory")
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise VendorInputError("staged input directory is unavailable") from exc
    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        raise VendorInputError("staged input directory is unsafe")
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise VendorInputError("staged package inputs must remain outside the repository")


@dataclass(frozen=True)
class PlannedFile:
    output: str
    raw: bytes
    mode: int
    source: str


@dataclass(frozen=True)
class RuntimePlan:
    files: dict[str, PlannedFile]
    state_sha256: str
    archive_receipt: tuple[dict[str, Any], ...]


def _runtime_locks(manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    locks = manifest["runtime_locks"]
    if not isinstance(locks, dict) or set(locks) != {str(ROOTFS_LOCK.relative_to(ROOT)), str(PYTHON_LOCK.relative_to(ROOT))}:
        raise VendorInputError("vendor manifest runtime lock set differs")
    for path in (ROOTFS_LOCK, PYTHON_LOCK):
        expected = _digest(locks[str(path.relative_to(ROOT))], "runtime lock hash")
        if _sha256_file(path) != expected:
            raise VendorInputError(f"runtime lock differs from vendor manifest: {path.name}")
    rootfs = _load_json(ROOTFS_LOCK)
    python = _load_json(PYTHON_LOCK)
    if rootfs.get("schema_version") != 1 or rootfs.get("root") != ROOTFS_ROOT:
        raise VendorInputError("unsupported rootfs runtime lock")
    if python.get("schema_version") != 1 or python.get("root") != PYTHON_ROOT:
        raise VendorInputError("unsupported Python runtime lock")
    if not isinstance(rootfs.get("files"), dict) or not isinstance(python.get("files"), dict):
        raise VendorInputError("runtime lock file map is invalid")
    return rootfs, python


def _inventory_owners(manifest: dict[str, Any], locked_paths: set[str]) -> tuple[dict[str, str], dict[str, Any]]:
    inventory_binding = manifest["inventory"]
    _expect_keys(inventory_binding, {"path", "sha256"}, "inventory binding")
    if inventory_binding["path"] != str(INVENTORY.relative_to(ROOT)):
        raise VendorInputError("vendor manifest inventory path differs")
    if _sha256_file(INVENTORY) != _digest(inventory_binding["sha256"], "inventory hash"):
        raise VendorInputError("third-party inventory differs from vendor manifest")
    inventory = _load_json(INVENTORY)
    if inventory.get("version") != 2 or not isinstance(inventory.get("components"), list):
        raise VendorInputError("unsupported third-party inventory")
    owners: dict[str, str] = {}
    for component in inventory["components"]:
        if not isinstance(component, dict) or not isinstance(component.get("name"), str):
            raise VendorInputError("third-party inventory component is invalid")
        files = component.get("copied_files", [])
        if not isinstance(files, list):
            raise VendorInputError("third-party inventory copied_files is invalid")
        for output in files:
            if output not in locked_paths:
                continue
            if output in owners:
                raise VendorInputError(f"runtime file has duplicate owners: {output}")
            owners[output] = component["name"]
    if set(owners) != locked_paths:
        raise VendorInputError("third-party inventory does not own the exact runtime")
    return owners, inventory


def _package_info(raw: bytes) -> dict[str, list[str]]:
    values: dict[str, list[str]] = defaultdict(list)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VendorInputError("package metadata is not UTF-8") from exc
    for line in text.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            values[key].append(value)
    return dict(values)


def _safe_tar_name(name: str) -> None:
    normalized = name[:-1] if name.endswith("/") else name
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or normalized != path.as_posix()
        or ".." in path.parts
    ):
        raise VendorInputError(f"archive contains an unsafe member: {name!r}")


def _read_member(source: Any, size: int, archive_name: str, member_name: str) -> bytes:
    if size > MAX_ARCHIVE_MEMBER_BYTES:
        raise VendorInputError(
            f"archive member size limit exceeded: {archive_name}:{member_name}"
        )
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = source.read(min(1024 * 1024, remaining))
        if not chunk:
            raise VendorInputError(f"archive member is truncated: {member_name}")
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) != size:
        raise VendorInputError(f"archive member is truncated: {member_name}")
    return raw


def _read_archive(
    path: Path,
    wanted_hashes: set[str],
    wanted_members: set[str],
) -> tuple[dict[str, list[tuple[str, bytes, int]]], dict[str, tuple[bytes, int]], dict[str, list[str]] | None]:
    by_hash: dict[str, list[tuple[str, bytes, int]]] = defaultdict(list)
    by_name: dict[str, tuple[bytes, int]] = {}
    package_metadata: dict[str, list[str]] | None = None
    names: set[str] = set()
    unpacked = 0
    try:
        archive = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError) as exc:
        raise VendorInputError(f"cannot read staged archive: {path.name}") from exc
    with archive:
        for count, member in enumerate(archive, start=1):
            if count > MAX_ARCHIVE_MEMBERS:
                raise VendorInputError(f"archive member limit exceeded: {path.name}")
            _safe_tar_name(member.name)
            if member.name in names:
                raise VendorInputError(f"archive has a duplicate member: {member.name}")
            names.add(member.name)
            if member.size < 0:
                raise VendorInputError(f"archive member has an invalid size: {member.name}")
            unpacked += member.size
            if unpacked > MAX_ARCHIVE_UNPACKED_BYTES:
                raise VendorInputError(f"archive expanded-size limit exceeded: {path.name}")
            if not member.isreg():
                continue
            source = archive.extractfile(member)
            if source is None:
                raise VendorInputError(f"archive member cannot be read: {member.name}")
            raw = _read_member(source, member.size, path.name, member.name)
            if member.name == ".PKGINFO":
                package_metadata = _package_info(raw)
            digest = _sha256(raw)
            if digest in wanted_hashes:
                by_hash[digest].append((member.name, raw, member.mode))
            if member.name in wanted_members:
                by_name[member.name] = (raw, member.mode)
    return dict(by_hash), by_name, package_metadata


def _canonical_offer(
    inventory: dict[str, Any],
    rootfs_lock: dict[str, Any],
    selected_permissive_licenses: dict[str, Any],
) -> bytes:
    source_bundles: dict[str, Any] = {}
    for component in inventory["components"]:
        source = component.get("corresponding_source")
        if source is None:
            continue
        if not isinstance(source, dict):
            raise VendorInputError("corresponding-source inventory record is invalid")
        source_bundles[component["name"]] = {
            "archive": source["archive"],
            "metadata": source["metadata_path"],
            "metadata_sha256": source["metadata_sha256"],
            "sha256": source["sha256"],
        }
    offer = {
        "arch_package_versions": rootfs_lock["packages"],
        "notice": "Exact retained source bundles accompany each distributed copyleft component in the private source release.",
        "selected_permissive_licenses": selected_permissive_licenses,
        "source_bundles": source_bundles,
    }
    return (json.dumps(offer, indent=2, sort_keys=True) + "\n").encode()


def _validate_sigsum_attestation(record: dict[str, Any]) -> None:
    attestation = record["attestation"]
    keys = {
        "artifact_sha256", "bytes", "go_version", "kind", "module",
        "module_version", "path", "policy", "sha256", "signer_keys_path",
        "signer_keys_sha256", "source_revision", "vcs_modified", "vcs_time",
        "verification_doc_path", "verification_doc_sha256",
        "verification_result", "verified_at", "verifier_binary_sha256",
        "verifier_module", "verifier_version",
    }
    if not isinstance(attestation, dict):
        raise VendorInputError("release archive attestation is required")
    _expect_keys(attestation, keys, "release archive attestation")
    if (
        record["component"] != "age"
        or attestation["kind"] != "sigsum-proof-v2"
        or record["sha256"] != AGE_ARCHIVE_SHA256
        or attestation["artifact_sha256"] != AGE_ARCHIVE_SHA256
        or attestation["sha256"] != AGE_PROOF_SHA256
        or attestation["signer_keys_sha256"] != AGE_SIGSUM_KEYS_SHA256
        or attestation["source_revision"] != AGE_SOURCE_REVISION
        or attestation["verifier_binary_sha256"] != SIGSUM_VERIFIER_SHA256
        or attestation["module"] != "filippo.io/age"
        or attestation["module_version"] != "v1.3.2"
        or attestation["go_version"] != "go1.27.0"
        or attestation["policy"] != "sigsum-generic-2025-1"
        or attestation["verification_result"] != "passed"
        or attestation["verifier_module"]
        != "sigsum.org/sigsum-go/cmd/sigsum-verify"
        or attestation["verifier_version"] != "v0.13.1"
        or attestation["vcs_modified"] is not False
        or not isinstance(attestation["source_revision"], str)
        or _COMMIT.fullmatch(attestation["source_revision"]) is None
        or not isinstance(attestation["vcs_time"], str)
        or _UTC.fullmatch(attestation["vcs_time"]) is None
        or not isinstance(attestation["verified_at"], str)
        or _UTC.fullmatch(attestation["verified_at"]) is None
        or not isinstance(attestation["bytes"], int)
        or isinstance(attestation["bytes"], bool)
        or attestation["bytes"] <= 0
    ):
        raise VendorInputError("release archive attestation metadata differs")
    for field in (
        "sha256", "signer_keys_sha256", "verification_doc_sha256",
        "verifier_binary_sha256",
    ):
        _digest(attestation[field], f"attestation {field}")
    for path_field, hash_field in (
        ("signer_keys_path", "signer_keys_sha256"),
        ("verification_doc_path", "verification_doc_sha256"),
    ):
        path = _regular(
            ROOT / _relative(attestation[path_field], f"attestation {path_field}"),
            beneath=ROOT,
        )
        if _sha256_file(path) != attestation[hash_field]:
            raise VendorInputError("retained Sigsum verification evidence differs")


def _validate_selected_licenses(
    selected: dict[str, Any],
    rootfs_lock: dict[str, Any],
    inventory: dict[str, Any],
    owners: dict[str, str],
    source_records: dict[str, dict[str, Any]],
    archives: dict[str, dict[str, Any]],
) -> None:
    if set(selected) != SELECTED_LICENSE_PACKAGES:
        raise VendorInputError("selected permissive-license package set differs")
    inventory_by_name = {
        item.get("name"): item
        for item in inventory["components"]
        if isinstance(item, dict)
    }
    archives_by_package = {
        item["package"]["name"]: item
        for item in archives.values()
        if isinstance(item.get("package"), dict)
    }
    for package_name in sorted(SELECTED_LICENSE_PACKAGES):
        record = selected[package_name]
        if not isinstance(record, dict):
            raise VendorInputError("selected permissive-license record is invalid")
        _expect_keys(
            record,
            {"license", "source_revision"},
            "selected permissive-license record",
        )
        revision = record["source_revision"]
        approved = APPROVED_SELECTED_LICENSES.get(package_name)
        component_name = f"Arch runtime package: {package_name}"
        component = inventory_by_name.get(component_name)
        archive = archives_by_package.get(package_name)
        package = rootfs_lock["packages"].get(package_name)
        if (
            not isinstance(revision, str)
            or _COMMIT.fullmatch(revision) is None
            or not isinstance(component, dict)
            or not isinstance(archive, dict)
            or not isinstance(package, dict)
            or not isinstance(approved, dict)
            or record
            != {"license": approved["license"], "source_revision": approved["revision"]}
            or component.get("version") != package.get("version")
            or archive["component"] != component_name
            or archive["package"].get("version") != package.get("version")
            or component.get("license") != record["license"]
            or package.get("license") != record["license"]
            or not isinstance(component.get("source"), str)
            or not isinstance(component.get("license_source"), str)
            or component.get("source") != approved["source"]
            or component.get("license_source") != approved["license_source"]
        ):
            raise VendorInputError(
                f"selected permissive-license provenance differs: {package_name}"
            )
        prefix = f"{ROOTFS_ROOT}/share/licenses/{package_name}/"
        evidence_outputs = {
            output
            for output, owner in owners.items()
            if owner == component_name and output.startswith(prefix)
        }
        if not evidence_outputs:
            raise VendorInputError(
                f"selected permissive-license evidence is missing: {package_name}"
            )
        for output in evidence_outputs:
            source = source_records.get(output)
            if source is not None:
                if (
                    source["component"] != component_name
                    or source["revision"] != revision
                    or not _immutable_source_url(source["origin"], revision)
                ):
                    raise VendorInputError(
                        f"selected license source evidence differs: {output}"
                    )
            elif output not in archive["members"]:
                raise VendorInputError(
                    f"selected license package member is not explicit: {output}"
                )


def _immutable_source_url(value: str, revision: str) -> bool:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
        or "\\" in parsed.path
    ):
        return False
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        return False
    if parsed.hostname == "github.com":
        return (
            len(parts) == 4 and parts[2] == "commit" and parts[3] == revision
        ) or (
            len(parts) >= 5 and parts[2] == "blob" and parts[3] == revision
        )
    if parsed.hostname == "forge.sourceware.org":
        return len(parts) >= 5 and parts[2:4] == ["src", "commit"] and parts[4] == revision
    if parsed.hostname in {"go.googlesource.com", "kernel.googlesource.com"}:
        return "+" in parts and parts.index("+") + 1 < len(parts) and parts[parts.index("+") + 1] == revision
    return False


def _expected_member(output: str) -> str | None:
    if output.startswith(PYTHON_ROOT + "/"):
        relative = output.removeprefix(PYTHON_ROOT + "/")
        return f"usr/lib/python3.14/site-packages/{relative}"
    if not output.startswith(ROOTFS_ROOT + "/"):
        return None
    relative = output.removeprefix(ROOTFS_ROOT + "/")
    if relative.startswith(("bin/", "lib/python3.14/", "share/licenses/")):
        return f"usr/{relative}"
    return None


def _mode(output: str, member_mode: int | None, rootfs_lock: dict[str, Any]) -> int:
    if output.startswith(PYTHON_ROOT + "/"):
        return 0o644
    relative = output.removeprefix(ROOTFS_ROOT + "/")
    executable = relative in rootfs_lock["elf_files"] or bool((member_mode or 0) & 0o111)
    return 0o555 if executable else 0o444


def _transform(raw: bytes, record: dict[str, Any]) -> bytes:
    tool = record["tool"]
    _expect_keys(tool, {"path", "version"}, "transformation tool")
    if tool["path"] != "/usr/bin/patchelf" or tool["version"] != "patchelf 0.19.1":
        raise VendorInputError("unsupported runtime transformation tool")
    completed = subprocess.run(
        (tool["path"], "--version"), check=True, capture_output=True, text=True
    )
    if completed.stdout.strip() != tool["version"]:
        raise VendorInputError("patchelf version differs from reviewed transformation")
    descriptor, temporary = tempfile.mkstemp(prefix="cptc-portcast-transform.", dir="/var/tmp")
    path = Path(temporary)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise VendorInputError("cannot write transformation input")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        subprocess.run(
            (tool["path"], "--remove-rpath", str(path)),
            check=True,
            capture_output=True,
        )
        return path.read_bytes()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def build_plan(inputs: Path, manifest_path: Path = MANIFEST) -> RuntimePlan:
    inputs = _stage_root(inputs)
    manifest = _load_json(manifest_path)
    _expect_keys(
        manifest,
        {
            "schema_version", "runtime_locks", "inventory", "archives",
            "source_files", "transformations", "generated_outputs",
            "selected_permissive_licenses", "review",
        },
        "vendor input manifest",
    )
    if manifest["schema_version"] != 1:
        raise VendorInputError("unsupported vendor input manifest")
    if not isinstance(manifest["review"], dict):
        raise VendorInputError("vendor input review record is invalid")
    _expect_keys(
        manifest["review"],
        {"verified_at", "verified_by", "signature_policy", "scope"},
        "vendor input review",
    )
    if not isinstance(manifest["archives"], list):
        raise VendorInputError("vendor input archives must be a list")
    if not isinstance(manifest["source_files"], list):
        raise VendorInputError("vendor input source_files must be a list")
    if not isinstance(manifest["transformations"], list):
        raise VendorInputError("vendor input transformations must be a list")
    if not isinstance(manifest["generated_outputs"], list):
        raise VendorInputError("vendor input generated_outputs must be a list")
    if not isinstance(manifest["selected_permissive_licenses"], dict):
        raise VendorInputError("selected permissive licenses must be an object")
    rootfs_lock, python_lock = _runtime_locks(manifest)
    locked: dict[str, str] = {}
    for lock in (rootfs_lock, python_lock):
        for relative, digest in lock["files"].items():
            output = f"{lock['root']}/{_relative(relative, 'runtime file')}"
            if output in locked:
                raise VendorInputError(f"duplicate runtime path: {output}")
            locked[output] = _digest(digest, "runtime file hash")
    owners, inventory = _inventory_owners(manifest, set(locked))

    source_records: dict[str, dict[str, Any]] = {}
    for record in manifest["source_files"]:
        _expect_keys(
            record,
            {
                "component", "output", "path", "sha256", "origin",
                "revision", "method", "source_member",
            },
            "source-file record",
        )
        output = _relative(record["output"], "source-file output")
        if output in source_records:
            raise VendorInputError(f"duplicate source-file output: {output}")
        if output not in locked or owners[output] != record["component"]:
            raise VendorInputError(f"source-file owner differs: {output}")
        if (
            not isinstance(record["component"], str)
            or not record["component"]
            or not isinstance(record["origin"], str)
            or not isinstance(record["revision"], str)
            or not record["revision"]
            or not _immutable_source_url(record["origin"], record["revision"])
            or record["method"]
            not in {"verbatim", "reviewed-notice", "reviewed-source-license-map"}
            or (
                record["method"] == "verbatim"
                and not isinstance(record["source_member"], str)
            )
            or (
                record["method"] != "verbatim"
                and record["source_member"] is not None
            )
        ):
            raise VendorInputError(f"source-file provenance differs: {output}")
        source_records[output] = record

    generated: dict[str, dict[str, Any]] = {}
    for record in manifest["generated_outputs"]:
        _expect_keys(record, {"output", "generator", "sha256"}, "generated-output record")
        output = _relative(record["output"], "generated output")
        if output in generated or output not in locked:
            raise VendorInputError(f"generated output differs: {output}")
        if record["generator"] != "canonical_corresponding_source_v1":
            raise VendorInputError("unsupported generated output")
        generated[output] = record
    if set(generated) != {GENERATED_OFFER}:
        raise VendorInputError("generated output set differs")

    transformations: dict[str, dict[str, Any]] = {}
    for record in manifest["transformations"]:
        _expect_keys(record, {"component", "output", "archive_member", "input_sha256", "tool", "output_sha256"}, "transformation record")
        output = _relative(record["output"], "transformation output")
        if output in transformations or output not in locked or owners[output] != record["component"]:
            raise VendorInputError(f"transformation output differs: {output}")
        if _digest(record["output_sha256"], "transformation output hash") != locked[output]:
            raise VendorInputError(f"transformation output hash differs: {output}")
        transformations[output] = record

    covered_components = set(source["component"] for source in source_records.values())
    archive_records: dict[str, dict[str, Any]] = {}
    for record in manifest["archives"]:
        _expect_keys(
            record,
            {
                "attestation", "component", "kind", "path", "sha256", "bytes",
                "signature", "members", "package", "origin",
            },
            "archive record",
        )
        component = record["component"]
        if not isinstance(component, str) or not component or component in archive_records:
            raise VendorInputError("archive component is missing or duplicated")
        if record["kind"] not in {"arch-package", "release-tar"}:
            raise VendorInputError(f"unsupported archive kind: {record['kind']}")
        members = record["members"]
        if not isinstance(members, dict):
            raise VendorInputError("archive member map is invalid")
        for output, member in members.items():
            output = _relative(output, "archive member output")
            _relative(member, "archive member input")
            if (
                output not in locked
                or owners[output] != component
                or output in source_records
                or output in generated
                or output in transformations
            ):
                raise VendorInputError(f"archive member owner differs: {output}")
        signature = record["signature"]
        if record["kind"] == "arch-package":
            if not isinstance(signature, dict):
                raise VendorInputError("arch package signature record is required")
            _expect_keys(
                signature,
                {"path", "sha256", "bytes", "signer_fingerprint", "verified_at"},
                "archive signature",
            )
            if (
                not isinstance(signature["bytes"], int)
                or isinstance(signature["bytes"], bool)
                or signature["bytes"] <= 0
                or not isinstance(signature["signer_fingerprint"], str)
                or _FINGERPRINT.fullmatch(signature["signer_fingerprint"]) is None
                or signature["signer_fingerprint"] not in APPROVED_PACKAGE_SIGNERS
            ):
                raise VendorInputError("archive signature fingerprint or size is invalid")
            if (
                not isinstance(signature["verified_at"], str)
                or _UTC.fullmatch(signature["verified_at"]) is None
            ):
                raise VendorInputError("archive signature review timestamp is invalid")
            if record["attestation"] is not None:
                raise VendorInputError("arch package attestation must be null")
        elif signature is not None:
            raise VendorInputError("release archive signature record must be null")
        else:
            _validate_sigsum_attestation(record)
        archive_records[component] = record
        covered_components.add(component)
    if set(owners.values()) - covered_components:
        raise VendorInputError("vendor manifest does not cover every inventory owner")
    _validate_selected_licenses(
        manifest["selected_permissive_licenses"],
        rootfs_lock,
        inventory,
        owners,
        source_records,
        archive_records,
    )

    expected_stage_files: set[str] = set()
    for record in archive_records.values():
        archive_relative = _relative(record["path"], "archive input")
        if archive_relative in expected_stage_files:
            raise VendorInputError(f"duplicate staged input path: {archive_relative}")
        expected_stage_files.add(archive_relative)
        signature = record["signature"]
        if signature is not None:
            if not isinstance(signature, dict):
                raise VendorInputError("archive signature record is invalid")
            signature_relative = _relative(signature.get("path"), "signature input")
            if signature_relative in expected_stage_files:
                raise VendorInputError(f"duplicate staged input path: {signature_relative}")
            expected_stage_files.add(signature_relative)
        attestation = record["attestation"]
        if attestation is not None:
            proof_relative = _relative(attestation["path"], "attestation input")
            if proof_relative in expected_stage_files:
                raise VendorInputError(f"duplicate staged input path: {proof_relative}")
            expected_stage_files.add(proof_relative)
    physical_stage_files: set[str] = set()
    for path in inputs.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise VendorInputError(f"staged input contains an unsafe entry: {path}")
        if stat.S_ISREG(mode):
            physical_stage_files.add(path.relative_to(inputs).as_posix())
    if physical_stage_files != expected_stage_files:
        raise VendorInputError("staged input file set differs from vendor manifest")

    planned: dict[str, PlannedFile] = {}
    receipts: list[dict[str, Any]] = []
    for component, record in archive_records.items():
        relative = _relative(record["path"], "archive input")
        archive_path = _regular(inputs / relative, beneath=inputs)
        expected_size = record["bytes"]
        if not isinstance(expected_size, int) or expected_size <= 0 or archive_path.stat().st_size != expected_size:
            raise VendorInputError(f"archive size differs: {relative}")
        archive_hash = _sha256_file(archive_path)
        if archive_hash != _digest(record["sha256"], "archive hash"):
            raise VendorInputError(f"archive hash differs: {relative}")
        signature = record["signature"]
        signature_receipt = None
        if signature is not None:
            signature_path = _regular(inputs / _relative(signature["path"], "signature input"), beneath=inputs)
            if signature_path.stat().st_size != signature["bytes"] or _sha256_file(signature_path) != _digest(signature["sha256"], "signature hash"):
                raise VendorInputError(f"signature differs: {relative}")
            signature_receipt = {
                "path": signature["path"],
                "sha256": signature["sha256"],
                "signer_fingerprint": signature["signer_fingerprint"],
                "verified_at": signature["verified_at"],
                "verification": "reviewed-external-signature-validation",
            }
        attestation_receipt = None
        attestation = record["attestation"]
        if attestation is not None:
            proof_path = _regular(
                inputs / _relative(attestation["path"], "attestation input"),
                beneath=inputs,
            )
            if (
                proof_path.stat().st_size != attestation["bytes"]
                or _sha256_file(proof_path)
                != _digest(attestation["sha256"], "attestation hash")
            ):
                raise VendorInputError(f"attestation differs: {relative}")
            attestation_receipt = {
                "kind": attestation["kind"],
                "path": attestation["path"],
                "policy": attestation["policy"],
                "sha256": attestation["sha256"],
                "source_revision": attestation["source_revision"],
                "verification": "reviewed-external-attestation-validation",
                "verified_at": attestation["verified_at"],
            }
        outputs = [output for output, owner in owners.items() if owner == component and output not in source_records and output not in generated and output not in transformations]
        wanted_hashes = {locked[output] for output in outputs}
        transform_records = [item for item in transformations.values() if item["component"] == component]
        wanted_members = {_relative(item["archive_member"], "transformation archive member") for item in transform_records}
        by_hash, by_name, package_info = _read_archive(archive_path, wanted_hashes, wanted_members)
        package = record["package"]
        if record["kind"] == "arch-package":
            if not isinstance(package, dict):
                raise VendorInputError(f"package metadata binding is missing: {relative}")
            _expect_keys(package, {"name", "version", "architecture"}, "package binding")
            if package_info is None:
                raise VendorInputError(f"package metadata is missing: {relative}")
            for field, manifest_field in (("pkgname", "name"), ("pkgver", "version"), ("arch", "architecture")):
                if package_info.get(field) != [package[manifest_field]]:
                    raise VendorInputError(f"package {field} differs: {relative}")
        elif package is not None or package_info is not None:
            raise VendorInputError(f"release archive carries unsupported package metadata: {relative}")
        for output in sorted(outputs):
            expected_member = record["members"].get(output, _expected_member(output))
            if expected_member is None:
                raise VendorInputError(f"archive member mapping is not exact: {output}")
            matches = [
                match
                for match in by_hash.get(locked[output], [])
                if match[0] == expected_member
            ]
            if len(matches) != 1:
                raise VendorInputError(f"archive member mapping is not exact: {output}")
            member, raw, member_mode = matches[0]
            planned[output] = PlannedFile(output, raw, _mode(output, member_mode, rootfs_lock), f"{relative}:{member}")
        for transform in transform_records:
            output = transform["output"]
            member = transform["archive_member"]
            selected = by_name.get(member)
            if selected is None or _sha256(selected[0]) != _digest(transform["input_sha256"], "transformation input hash"):
                raise VendorInputError(f"transformation input differs: {output}")
            raw = _transform(selected[0], transform)
            if _sha256(raw) != locked[output]:
                raise VendorInputError(f"transformation is not reproducible: {output}")
            planned[output] = PlannedFile(output, raw, _mode(output, selected[1], rootfs_lock), f"{relative}:{member}:patchelf-remove-rpath")
        receipts.append({
            "component": component,
            "archive": relative,
            "attestation": attestation_receipt,
            "sha256": archive_hash,
            "signature": signature_receipt,
        })

    for output, record in source_records.items():
        source_path = _regular(ROOT / _relative(record["path"], "reviewed source file"), beneath=ROOT)
        raw = source_path.read_bytes()
        if _sha256(raw) != _digest(record["sha256"], "reviewed source-file hash") or _sha256(raw) != locked[output]:
            raise VendorInputError(f"reviewed source file differs: {output}")
        planned[output] = PlannedFile(output, raw, _mode(output, None, rootfs_lock), str(source_path.relative_to(ROOT)))

    offer = _canonical_offer(inventory, rootfs_lock, manifest["selected_permissive_licenses"])
    generated_record = generated[GENERATED_OFFER]
    if _sha256(offer) != _digest(generated_record["sha256"], "generated output hash") or _sha256(offer) != locked[GENERATED_OFFER]:
        raise VendorInputError("generated corresponding-source notice differs")
    planned[GENERATED_OFFER] = PlannedFile(GENERATED_OFFER, offer, _mode(GENERATED_OFFER, None, rootfs_lock), "canonical_corresponding_source_v1")

    if set(planned) != set(locked):
        raise VendorInputError("planned runtime does not cover the exact lock")
    for output, file in planned.items():
        if _sha256(file.raw) != locked[output]:
            raise VendorInputError(f"planned runtime hash differs: {output}")

    from cptc_harness.elf import verify_elf_closure, verify_private_native_closure

    rootfs_bytes = {
        output.removeprefix(ROOTFS_ROOT + "/"): file.raw
        for output, file in planned.items()
        if output.startswith(ROOTFS_ROOT + "/")
    }
    python_bytes = {
        output.removeprefix(PYTHON_ROOT + "/"): file.raw
        for output, file in planned.items()
        if output.startswith(PYTHON_ROOT + "/")
    }
    verify_elf_closure(rootfs_bytes, rootfs_lock["elf_files"])
    verify_private_native_closure(python_bytes, python_lock["native_files"], rootfs_bytes)

    state = hashlib.sha256()
    for output, file in sorted(planned.items()):
        state.update(output.encode() + b"\0")
        state.update(f"{file.mode:04o}".encode() + b"\0")
        state.update(hashlib.sha256(file.raw).digest())
    return RuntimePlan(planned, state.hexdigest(), tuple(sorted(receipts, key=lambda item: item["component"])))


def compare_current(plan: RuntimePlan, root: Path = ROOT) -> None:
    physical: set[str] = set()
    for runtime_root in (ROOTFS_ROOT, PYTHON_ROOT):
        base = root / runtime_root
        if not base.is_dir() or base.is_symlink():
            raise VendorInputError(f"current runtime is unavailable: {runtime_root}")
        for path in base.rglob("*"):
            if path.is_symlink() or (path.exists() and not path.is_file() and not path.is_dir()):
                raise VendorInputError(f"current runtime contains an unsafe entry: {path}")
            if path.is_file():
                physical.add(path.relative_to(root).as_posix())
    if physical != set(plan.files):
        raise VendorInputError("current runtime path set differs from staged plan")
    for output, file in plan.files.items():
        path = root / output
        if _sha256_file(path) != _sha256(file.raw):
            raise VendorInputError(f"current runtime bytes differ: {output}")
        if stat.S_IMODE(path.stat().st_mode) != file.mode:
            raise VendorInputError(f"current runtime mode differs: {output}")


def materialize(plan: RuntimePlan, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise VendorInputError(f"refusing to replace output: {output}")
    resolved = output.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise VendorInputError("materialized output must remain outside the repository")
    output.mkdir(parents=True, mode=0o700)
    try:
        for relative, file in sorted(plan.files.items()):
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                file.mode,
            )
            try:
                view = memoryview(file.raw)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise VendorInputError("cannot write materialized runtime")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.chmod(destination, file.mode, follow_symlinks=False)
    except BaseException:
        shutil.rmtree(output)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True, help="absolute staged archive directory")
    parser.add_argument("--output", type=Path, help="materialize under a new external directory")
    parser.add_argument("--skip-current", action="store_true", help="do not compare with the checked-in runtime")
    args = parser.parse_args(argv)
    plan = build_plan(args.inputs, MANIFEST)
    if not args.skip_current:
        compare_current(plan)
    if args.output is not None:
        if not args.output.is_absolute():
            raise VendorInputError("--output must be absolute")
        materialize(plan, args.output)
    print(json.dumps({
        "archives": list(plan.archive_receipt),
        "files": len(plan.files),
        "materialized": str(args.output) if args.output is not None else None,
        "state_sha256": plan.state_sha256,
        "reproduced": True,
        "signature_review_bound": True,
        "signatures_reverified": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
