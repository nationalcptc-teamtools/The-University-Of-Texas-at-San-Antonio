"""Descriptor-verified release pins. Runtime code never refreshes these pins."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping

from .contracts import PolicyError
from .elf import (
    ElfValidationError,
    verify_elf_closure,
    verify_private_native_closure,
)


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RELEASE_FILE = 8 * 1024 * 1024
_RELEASE_ROOT = Path(__file__).parent.parent
_RELEASE_MANIFEST = Path(__file__).parent / "resources" / "release-integrity.json"
_PRODUCTION_RELEASE_ROOT = Path("/app")
_PRODUCTION_RELEASE_MANIFEST = (
    _PRODUCTION_RELEASE_ROOT / "cptc_harness/resources/release-integrity.json"
)
_PRODUCTION_ANCHOR = Path(
    "/etc/cptc-harness/trust/portcast-live-v1.sha256"
)
_PROFILE_ID = "web.http_jellyfin_public_identity"
_PORTCAST_RUNTIME_ROOT = Path("vendor/portcast-python3.14/site-packages")
_PORTCAST_RUNTIME_LOCK = "cptc_harness/resources/portcast-python-runtime-v1.json"
_CPYTHON_RUNTIME_ROOT = Path("vendor/portcast-rootfs-runtime")
_CPYTHON_RUNTIME_LOCK = "cptc_harness/resources/portcast-cpython-runtime-v1.json"
_PORTCAST_RUNTIME_PACKAGES = {
    "PyNaCl": "1.6.2",
    "PyYAML": "6.0.3",
    "bcrypt": "5.0.0",
    "cffi": "2.1.1",
    "cryptography": "50.0.1",
    "fluidity-sm": "0.2.1",
    "invoke": "3.0.3",
    "lexicon": "3.0.0",
    "paramiko": "5.0.0",
    "pycparser": "3.0",
}

PORTCAST_RELEASE_FILES = frozenset(
    """
cptc_harness/__init__.py
cptc_harness/__main__.py
cptc_harness/advisories.py
cptc_harness/assessment_contracts.py
cptc_harness/audit.py
cptc_harness/audit_control.py
cptc_harness/audit_readonly.py
cptc_harness/audit_service.py
cptc_harness/audit_worker.py
cptc_harness/broker.py
cptc_harness/browser.py
cptc_harness/browser_worker.py
cptc_harness/campaign.py
cptc_harness/check_catalog.py
cptc_harness/cli.py
cptc_harness/clockcheck.py
cptc_harness/collectors/__init__.py
cptc_harness/collectors/base.py
cptc_harness/collectors/bounded.py
cptc_harness/collectors/imports.py
cptc_harness/contracts.py
cptc_harness/detection.py
cptc_harness/disclosure.py
cptc_harness/elf.py
cptc_harness/exports.py
cptc_harness/host_profile_catalog.py
cptc_harness/integrity.py
cptc_harness/isolation.py
cptc_harness/ledger.py
cptc_harness/mcp_server.py
cptc_harness/memfd.py
cptc_harness/migrations.py
cptc_harness/network.py
cptc_harness/nmap_bridge.py
cptc_harness/operator_replay.py
cptc_harness/orchestrator.py
cptc_harness/parsers/__init__.py
cptc_harness/parsers/common.py
cptc_harness/parsers/host.py
cptc_harness/parsers/intake.py
cptc_harness/parsers/network.py
cptc_harness/parsers/web.py
cptc_harness/passive.py
cptc_harness/passive_worker.py
cptc_harness/platform_checks.py
cptc_harness/policy.py
cptc_harness/portcast_identity.py
cptc_harness/preambles.py
cptc_harness/profile_runtime/__init__.py
cptc_harness/profile_runtime/broker_ipc.py
cptc_harness/profile_runtime/capability.py
cptc_harness/profile_runtime/catalog.py
cptc_harness/profile_runtime/contracts.py
cptc_harness/profile_runtime/executor.py
cptc_harness/profile_runtime/harbinger.py
cptc_harness/profile_runtime/receipts.py
cptc_harness/profile_runtime/service_client.py
cptc_harness/profile_runtime/worker.py
cptc_harness/profiles/__init__.py
cptc_harness/profiles/common_mysql/__init__.py
cptc_harness/profiles/common_mysql/parser.py
cptc_harness/profiles/common_tls/__init__.py
cptc_harness/profiles/common_tls/parser.py
cptc_harness/provider_worker.py
cptc_harness/providers.py
cptc_harness/publication.py
cptc_harness/registry.py
cptc_harness/reporting.py
cptc_harness/resources/bounded-profiles-v1.json
cptc_harness/resources/portcast-python-runtime-v1.json
cptc_harness/resources/portcast-cpython-runtime-v1.json
cptc_harness/resources/portcast-bootstrap-v1.sha256
cptc_harness/response_capture.py
cptc_harness/runtime.py
cptc_harness/scanner_catalog.py
cptc_harness/scanner_catalog_v2.py
cptc_harness/scanner_contracts.py
cptc_harness/scanner_mapping.py
cptc_harness/scanner_protocols.py
cptc_harness/scanner_relay.py
cptc_harness/scanner_results.py
cptc_harness/secret_worker.py
cptc_harness/secrets.py
cptc_harness/signing.py
cptc_harness/signing_worker.py
cptc_harness/skills.py
cptc_harness/storage.py
cptc_harness/tool_catalog.py
deployment/portcast-live-v1.service
deployment/portcast-live-v1.sysusers
deployment/portcast-live-v1-acceptance@.service
deployment/portcast-bootstrap
deployment/portcast-bootstrap.go
deployment/portcast-systemd-acceptance.py
deployment/manage-portcast-service.py
docs/harness/PORTCAST-SERVICE-DEPLOYMENT.md
docs/harness/THIRD-PARTY-INVENTORY.json
docs/harness/THIRD-PARTY-LICENSES.md
testing/__init__.py
testing/cptc11_lab/__init__.py
testing/cptc11_lab/kali_portcast_relay.py
testing/cptc11_lab/portcast-live-plan-v1.json
testing/cptc11_lab/portcast-live-plan-v2.json
testing/cptc11_lab/portcast-live-plan-v3.json
testing/cptc11_lab/portcast-live-plan-v4.json
testing/cptc11_lab/portcast_broker_worker.py
testing/cptc11_lab/portcast_acceptance.py
testing/cptc11_lab/portcast_live.py
testing/cptc11_lab/portcast_service.py
testing/cptc11_lab/transport.py
""".split()
)


@dataclass(frozen=True, slots=True)
class VerifiedRelease:
    release_id: str
    manifest_sha256: str
    file_sha256: Mapping[str, str]
    current_profile_workers: Mapping[str, str]
    compatible_profile_workers: Mapping[str, tuple[str, ...]]
    interpreter_path: Path = Path("/usr/bin/python3.14")
    interpreter_sha256: str = ""
    release_root: Path = _RELEASE_ROOT
    runtime_root: Path = _RELEASE_ROOT / _PORTCAST_RUNTIME_ROOT
    runtime_file_sha256: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )
    runtime_packages: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )
    native_file_sha256: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )
    launcher_path: Path = Path("/app/deployment/portcast-bootstrap")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _safe_components(relative: str) -> tuple[str, ...]:
    if type(relative) is not str or not relative:
        raise PolicyError("release file path is invalid")
    path = PurePosixPath(relative)
    parts = path.parts
    if path.is_absolute() or not parts or any(
        part in {"", ".", ".."} or "/" in part or "\x00" in part for part in parts
    ):
        raise PolicyError("release file path is invalid")
    return parts


def _trusted_metadata(
    value: os.stat_result, *, owner_uid: int | None, directory: bool
) -> bool:
    expected_type = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
    return (
        expected_type
        and (owner_uid is None or value.st_uid == owner_uid)
        and (owner_uid is None or value.st_mode & 0o022 == 0)
    )


def _read_from_directory(
    root: Path,
    relative: str,
    *,
    owner_uid: int | None = None,
    allow_empty: bool = False,
) -> bytes:
    parts = _safe_components(relative)
    directories: list[int] = []
    descriptor = None
    try:
        current = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        if not _trusted_metadata(
            os.fstat(current), owner_uid=owner_uid, directory=True
        ):
            raise PolicyError("release directory ownership or mode differs")
        directories.append(current)
        for component in parts[:-1]:
            current = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            if not _trusted_metadata(
                os.fstat(current), owner_uid=owner_uid, directory=True
            ):
                raise PolicyError("release directory ownership or mode differs")
            directories.append(current)
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current,
        )
        before = os.fstat(descriptor)
        if (
            not _trusted_metadata(before, owner_uid=owner_uid, directory=False)
            or not (0 if allow_empty else 1) <= before.st_size <= _MAX_RELEASE_FILE
        ):
            raise PolicyError("release file is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 128 * 1024))
            if not chunk:
                raise PolicyError("release file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PolicyError("release file changed during read")
        after = os.fstat(descriptor)
        linked = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(after) != identity(linked):
            raise PolicyError("release file changed during read")
        return b"".join(chunks)
    except (OSError, ValueError):
        raise PolicyError("release file could not be opened safely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory in reversed(directories):
            os.close(directory)


def _read_release_file(relative: str) -> bytes:
    return _read_from_directory(_RELEASE_ROOT, relative)


def _read_under_root(
    root: Path,
    relative: str,
    *,
    owner_uid: int,
    absolute_components: bool,
    allow_empty: bool = False,
) -> bytes:
    if absolute_components:
        complete = root / PurePosixPath(relative)
        return _read_from_directory(
            Path("/"), complete.relative_to("/").as_posix(), owner_uid=owner_uid,
            allow_empty=allow_empty,
        )
    return _read_from_directory(
        root, relative, owner_uid=owner_uid, allow_empty=allow_empty
    )


def _load_manifest(
    release_root: Path,
    manifest_path: Path,
    *,
    owner_uid: int,
    absolute_components: bool,
) -> tuple[dict[str, Any], bytes]:
    try:
        relative = manifest_path.relative_to(release_root).as_posix()
    except ValueError:
        if absolute_components:
            raise PolicyError("production release manifest path differs") from None
        raw = _read_from_directory(
            manifest_path.parent, manifest_path.name, owner_uid=owner_uid
        )
    else:
        raw = _read_under_root(
            release_root,
            relative,
            owner_uid=owner_uid,
            absolute_components=absolute_components,
        )
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PolicyError("reviewed release integrity manifest is invalid") from None
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "executables", "workers", "portcast-live-v1"}
        or value.get("version") != 2
        or not isinstance(value.get("executables"), dict)
        or not isinstance(value.get("workers"), dict)
    ):
        raise PolicyError("reviewed release integrity manifest schema differs")
    return value, raw


def _verify_portcast_release(
    *,
    release_root: Path,
    manifest_path: Path,
    anchor_path: Path,
    owner_uid: int,
    absolute_components: bool = False,
) -> VerifiedRelease:
    manifest, raw = _load_manifest(
        release_root,
        manifest_path,
        owner_uid=owner_uid,
        absolute_components=absolute_components,
    )
    anchor = (
        _read_from_directory(
            Path("/"),
            anchor_path.relative_to("/").as_posix(),
            owner_uid=owner_uid,
        )
        if absolute_components
        else _read_from_directory(
            anchor_path.parent,
            anchor_path.name,
            owner_uid=owner_uid,
        )
    )
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    if absolute_components:
        try:
            anchor_lines = anchor.decode("ascii", "strict").splitlines(keepends=True)
        except UnicodeDecodeError:
            anchor_lines = []
        anchor_valid = (
            len(anchor_lines) == 4
            and anchor_lines[0] == "PORTCAST-TRUST-V2\n"
            and anchor_lines[1] == f"release {manifest_sha256}\n"
            and len(anchor_lines[2]) == 75
            and anchor_lines[2].startswith("bootstrap ")
            and len(anchor_lines[3]) == 74
            and anchor_lines[3].startswith("launcher ")
        )
    else:
        anchor_valid = anchor == (manifest_sha256 + "\n").encode("ascii")
    if not anchor_valid:
        raise PolicyError("external PortCast release trust anchor differs")
    section = manifest["portcast-live-v1"]
    if not isinstance(section, dict) or set(section) != {
        "release_id",
        "files",
        "current_profile_workers",
        "compatible_profile_workers",
        "interpreter",
        "python_runtime",
        "cpython_runtime",
        "launcher",
        "bootstrap_manifest",
    }:
        raise PolicyError("reviewed PortCast release manifest schema differs")
    files = section["files"]
    current = section["current_profile_workers"]
    compatible = section["compatible_profile_workers"]
    interpreter = section["interpreter"]
    python_runtime = section["python_runtime"]
    cpython_runtime = section["cpython_runtime"]
    launcher = section["launcher"]
    bootstrap_manifest = section["bootstrap_manifest"]
    if (
        section["release_id"] != "portcast-live-v1"
        or not isinstance(files, dict)
        or set(files) != PORTCAST_RELEASE_FILES
        or not isinstance(current, dict)
        or not isinstance(compatible, dict)
        or set(current) != {_PROFILE_ID}
        or set(compatible) != {_PROFILE_ID}
        or _HEX64.fullmatch(current.get(_PROFILE_ID, "")) is None
        or not isinstance(compatible.get(_PROFILE_ID), list)
        or not compatible[_PROFILE_ID]
        or len(compatible[_PROFILE_ID]) != len(set(compatible[_PROFILE_ID]))
        or any(_HEX64.fullmatch(item) is None for item in compatible[_PROFILE_ID])
        or current[_PROFILE_ID] not in compatible[_PROFILE_ID]
        or any(not isinstance(value, str) or _HEX64.fullmatch(value) is None for value in files.values())
        or current.get(_PROFILE_ID)
        != files.get("cptc_harness/profile_runtime/worker.py")
        or not isinstance(interpreter, dict)
        or set(interpreter) != {"path", "sha256"}
        or not isinstance(interpreter.get("path"), str)
        or not Path(interpreter["path"]).is_absolute()
        or _HEX64.fullmatch(interpreter.get("sha256", "")) is None
        or interpreter.get("path") != "/app/vendor/portcast-rootfs-runtime/bin/python3.14"
        or not isinstance(python_runtime, dict)
        or set(python_runtime) != {
            "schema_version", "python_abi", "root", "packages", "import_roots",
            "files", "native_files",
        }
        or python_runtime.get("schema_version") != 1
        or python_runtime.get("python_abi") != "cp314-x86_64-linux-gnu"
        or python_runtime.get("root") != _PORTCAST_RUNTIME_ROOT.as_posix()
        or python_runtime.get("packages") != _PORTCAST_RUNTIME_PACKAGES
        or not isinstance(python_runtime.get("import_roots"), list)
        or len(python_runtime["import_roots"]) != len(set(python_runtime["import_roots"]))
        or not isinstance(python_runtime.get("files"), dict)
        or not python_runtime["files"]
        or not isinstance(python_runtime.get("native_files"), dict)
        or not python_runtime["native_files"]
        or not isinstance(cpython_runtime, dict)
        or cpython_runtime.get("schema_version") != 1
        or cpython_runtime.get("root") != _CPYTHON_RUNTIME_ROOT.as_posix()
        or not isinstance(cpython_runtime.get("files"), dict)
        or not cpython_runtime["files"]
        or not isinstance(cpython_runtime.get("elf_files"), dict)
        or not isinstance(launcher, dict)
        or launcher != {
            "path": "deployment/portcast-bootstrap",
            "sha256": files.get("deployment/portcast-bootstrap"),
        }
        or not isinstance(bootstrap_manifest, dict)
        or bootstrap_manifest != {
            "path": "cptc_harness/resources/portcast-bootstrap-v1.sha256",
            "sha256": files.get("cptc_harness/resources/portcast-bootstrap-v1.sha256"),
        }
    ):
        raise PolicyError("reviewed PortCast release manifest is incomplete")
    for relative in sorted(PORTCAST_RELEASE_FILES):
        actual = hashlib.sha256(
            _read_under_root(
                release_root,
                relative,
                owner_uid=owner_uid,
                absolute_components=absolute_components,
                allow_empty=True,
            )
        ).hexdigest()
        if actual != files[relative]:
            raise PolicyError("PortCast release file differs from reviewed hash")
    try:
        runtime_lock = json.loads(
            _read_under_root(
                release_root,
                _PORTCAST_RUNTIME_LOCK,
                owner_uid=owner_uid,
                absolute_components=absolute_components,
            ),
            object_pairs_hook=_pairs,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PolicyError("reviewed PortCast Python runtime lock is invalid") from None
    if runtime_lock != python_runtime:
        raise PolicyError("PortCast Python runtime lock differs from release manifest")
    runtime_files = python_runtime["files"]
    runtime_raw: dict[str, bytes] = {}
    for relative, expected in runtime_files.items():
        _safe_components(relative)
        if not isinstance(expected, str) or _HEX64.fullmatch(expected) is None:
            raise PolicyError("reviewed PortCast Python runtime manifest is incomplete")
        raw_file = _read_under_root(
            release_root / _PORTCAST_RUNTIME_ROOT,
            relative,
            owner_uid=owner_uid,
            absolute_components=absolute_components,
            allow_empty=True,
        )
        runtime_raw[relative] = raw_file
        actual = hashlib.sha256(raw_file).hexdigest()
        if actual != expected:
            raise PolicyError("PortCast Python runtime file differs from reviewed hash")
    runtime_root = release_root / _PORTCAST_RUNTIME_ROOT
    physical_files: set[str] = set()
    try:
        for directory, directories, names in os.walk(runtime_root, followlinks=False):
            directory_path = Path(directory)
            info = directory_path.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != owner_uid
                or info.st_mode & 0o022
            ):
                raise PolicyError("PortCast Python runtime directory differs")
            for name in directories:
                child = directory_path / name
                if child.is_symlink():
                    raise PolicyError("PortCast Python runtime contains a symlink")
            for name in names:
                child = directory_path / name
                if child.is_symlink() or not child.is_file():
                    raise PolicyError("PortCast Python runtime contains an unsafe file")
                physical_files.add(child.relative_to(runtime_root).as_posix())
    except OSError:
        raise PolicyError("PortCast Python runtime tree is unavailable") from None
    if physical_files != set(runtime_files):
        raise PolicyError("PortCast Python runtime file set differs")
    try:
        cpython_lock = json.loads(
            _read_under_root(
                release_root,
                _CPYTHON_RUNTIME_LOCK,
                owner_uid=owner_uid,
                absolute_components=absolute_components,
            ),
            object_pairs_hook=_pairs,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PolicyError("reviewed CPython runtime lock is invalid") from None
    if cpython_lock != cpython_runtime:
        raise PolicyError("CPython runtime lock differs from release manifest")
    cpython_root = release_root / _CPYTHON_RUNTIME_ROOT
    cpython_files = cpython_runtime["files"]
    cpython_raw: dict[str, bytes] = {}
    physical_cpython: set[str] = set()
    try:
        for directory, directories, names in os.walk(cpython_root, followlinks=False):
            directory_path = Path(directory)
            info = directory_path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
                raise PolicyError("CPython runtime directory differs")
            if any((directory_path / name).is_symlink() for name in directories):
                raise PolicyError("CPython runtime contains a symlink")
            for name in names:
                child = directory_path / name
                if child.is_symlink() or not child.is_file():
                    raise PolicyError("CPython runtime contains an unsafe file")
                relative = child.relative_to(cpython_root).as_posix()
                physical_cpython.add(relative)
                expected = cpython_files.get(relative)
                raw_file = _read_under_root(
                    cpython_root,
                    relative,
                    owner_uid=owner_uid,
                    absolute_components=absolute_components,
                    allow_empty=True,
                )
                cpython_raw[relative] = raw_file
                if (
                    _HEX64.fullmatch(expected or "") is None
                    or hashlib.sha256(raw_file).hexdigest()
                    != expected
                ):
                    raise PolicyError("CPython runtime file differs")
    except OSError:
        raise PolicyError("CPython runtime tree is unavailable") from None
    if physical_cpython != set(cpython_files):
        raise PolicyError("CPython runtime file set differs")
    try:
        verify_elf_closure(cpython_raw, cpython_runtime["elf_files"])
        verify_private_native_closure(
            runtime_raw, python_runtime["native_files"], cpython_raw
        )
    except ElfValidationError:
        raise PolicyError("PortCast native dependency closure differs") from None
    native_hashes = dict(cpython_runtime["elf_files"])
    interpreter_path = release_root / _CPYTHON_RUNTIME_ROOT / "bin/python3.14"
    interpreter_raw = _read_under_root(
        cpython_root,
        "bin/python3.14",
        owner_uid=owner_uid,
        absolute_components=absolute_components,
    )
    if hashlib.sha256(interpreter_raw).hexdigest() != interpreter["sha256"]:
        raise PolicyError("PortCast interpreter differs from reviewed hash")
    return VerifiedRelease(
        section["release_id"],
        manifest_sha256,
        MappingProxyType(dict(files)),
        MappingProxyType(dict(current)),
        MappingProxyType({_PROFILE_ID: tuple(compatible[_PROFILE_ID])}),
        interpreter_path,
        interpreter["sha256"],
        release_root,
        runtime_root,
        MappingProxyType(dict(runtime_files)),
        MappingProxyType(dict(python_runtime["packages"])),
        MappingProxyType(native_hashes),
        release_root / "deployment/portcast-bootstrap",
    )


def verify_portcast_release() -> VerifiedRelease:
    """Verify the fixed root-owned deployment against its external anchor."""

    return _verify_portcast_release(
        release_root=_PRODUCTION_RELEASE_ROOT,
        manifest_path=_PRODUCTION_RELEASE_MANIFEST,
        anchor_path=_PRODUCTION_ANCHOR,
        owner_uid=0,
        absolute_components=True,
    )


def _manifest() -> tuple[dict[str, Any], bytes]:
    """Legacy base-worker manifest reader; grants no PortCast live authority."""

    return _load_manifest(
        _RELEASE_ROOT,
        _RELEASE_MANIFEST,
        owner_uid=os.getuid(),
        absolute_components=False,
    )


def verified_worker(name: str) -> Path:
    if Path(name).name != name:
        raise PolicyError("invalid worker identifier")
    try:
        manifest, _raw = _manifest()
        expected = manifest["workers"][name]
        worker = Path(__file__).parent / name
        if not isinstance(expected, str) or _HEX64.fullmatch(expected) is None:
            raise PolicyError("worker has no reviewed release hash")
        raw = _read_release_file(f"cptc_harness/{name}")
        if hashlib.sha256(raw).hexdigest() != expected:
            raise PolicyError("worker differs from reviewed release hash")
        return worker
    except (KeyError, TypeError):
        raise PolicyError("reviewed worker integrity manifest unavailable") from None


def verified_executable(path: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise PolicyError("executable path must be absolute")
    try:
        manifest, _raw = _manifest()
        expected = manifest["executables"][str(candidate)]
        resolved = candidate.resolve(strict=True)
        descriptor = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_RELEASE_FILE * 64:
                raise PolicyError("executable is not a regular file")
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 128 * 1024):
                digest.update(chunk)
        finally:
            os.close(descriptor)
        if digest.hexdigest() != expected:
            raise PolicyError("executable differs from reviewed deployment pin")
        return candidate
    except (OSError, KeyError, TypeError):
        raise PolicyError("executable has no reviewed deployment pin") from None


__all__ = (
    "PORTCAST_RELEASE_FILES",
    "VerifiedRelease",
    "verified_executable",
    "verified_worker",
    "verify_portcast_release",
)
