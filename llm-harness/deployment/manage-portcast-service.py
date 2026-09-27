#!/usr/bin/python3.14
"""Plan, install, verify, archive, or roll back the canonical PortCast service.

This helper never creates credentials, derives a trust anchor at service
startup, starts the service, or sends a target request. Apply requires the
independently reviewed manifest digest as an explicit argument.
"""

from __future__ import annotations

import argparse
from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import fcntl
import grp
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parents[1]
RELEASE_PATH = Path("/usr/lib/cptc-harness/portcast-live-v1")
APP_PATH = RELEASE_PATH / "app"
SERVICE_EXEC_RELEASE_PATH = Path("/app")
UNIT_SOURCE = Path("deployment/portcast-live-v1.service")
UNIT_PATH = Path("/etc/systemd/system/portcast-live-v1.service")
SYSUSERS_SOURCE = Path("deployment/portcast-live-v1.sysusers")
SYSUSERS_PATH = Path("/usr/lib/sysusers.d/cptc-harness-portcast.conf")
ANCHOR_PATH = Path("/etc/cptc-harness/trust/portcast-live-v1.sha256")
STATE_PATH = Path("/var/lib/cptc-harness/portcast-live-v1")
# Keep the failed v3 through v6 states as immutable historical inputs. The
# current admission owns a separate v7 state. v6 was never admitted and must
# remain absent on the deployment host.
V3_STATE_PATH = Path("/var/lib/cptc-harness/portcast-live-v3")
V4_STATE_PATH = Path("/var/lib/cptc-harness/portcast-live-v4")
V5_STATE_PATH = Path("/var/lib/cptc-harness/portcast-live-v5")
V6_STATE_PATH = Path("/var/lib/cptc-harness/portcast-live-v6")
V3_RUNTIME_PATH = V3_STATE_PATH / "runtime"
V4_RUNTIME_PATH = V4_STATE_PATH / "runtime"
V5_RUNTIME_PATH = V5_STATE_PATH / "runtime"
V5_ADMISSION_PATH = V5_STATE_PATH / "admission"
V5_ADMISSION_PROJECTION_PATH = V5_STATE_PATH / "admission-projection"
V6_RUNTIME_PATH = V6_STATE_PATH / "runtime"
V6_ADMISSION_PATH = V6_STATE_PATH / "admission"
V6_ADMISSION_PROJECTION_PATH = V6_STATE_PATH / "admission-projection"
V6_V5_RECEIPT_PATH = V6_STATE_PATH / "predecessors/v5/receipt.json"
V7_STATE_PATH = Path("/var/lib/cptc-harness/portcast-live-v7")
V7_RUNTIME_PATH = V7_STATE_PATH / "runtime"
V7_ADMISSION_PATH = V7_STATE_PATH / "admission"
V7_ADMISSION_PROJECTION_PATH = V7_STATE_PATH / "admission-projection"
V7_V5_RECEIPT_PATH = V7_STATE_PATH / "predecessors/v5/receipt.json"
OLD_LEDGER_PATH = STATE_PATH / "runtime/ledger/cptc11-dell-validation"
OLD_AUDIT_PATH = STATE_PATH / "runtime/runtime/audit"
OLD_RESULT_PATH = STATE_PATH / (
    "runtime/runtime/results/cptc11-portcast-public-identity-action-v2.json"
)
_DEFAULT_STATE_PATH = STATE_PATH
SOCKET_PATH = Path("/run/cptc-harness/portcast-live-v1.sock")
CREDENTIAL_PATHS = (
    Path("/etc/cptc-harness/credentials/cptc11-dell.cred"),
    Path("/etc/cptc-harness/credentials/cptc11-kali.cred"),
)
CLOCK_ATTESTATION_PATH = Path(
    "/run/cptc-harness-clock/portcast-live-v1.json"
)
CLOCK_ATTESTATION_TTL_NS = 30_000_000_000
MANIFEST_RELATIVE = Path("cptc_harness/resources/release-integrity.json")
RELEASE_ID = "portcast-live-v1"
ROOT_UID = 0
ROOT_GID = 0
OPERATOR_UID = 1000
SERVICE_ACCOUNT = "_cptc-portcast"
SERVICE_GROUP = "cptc-harness"
_HEX64 = frozenset("0123456789abcdef")
_UTC_MICROSECONDS = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_MAX_FILE = 64 * 1024 * 1024
_MAX_PACKET = 64 * 1024
_EXECUTABLE_FILES = frozenset(
    {
        "deployment/portcast-bootstrap",
        "vendor/portcast-rootfs-runtime/bin/age",
        "vendor/portcast-rootfs-runtime/bin/bwrap",
        "vendor/portcast-rootfs-runtime/bin/python3.14",
        "vendor/portcast-rootfs-runtime/lib/ld-linux-x86-64.so.2",
    }
)
_ROOTFS_ANCHOR = "/etc/cptc-harness/trust/portcast-live-v1.sha256"
_ROOTFS_DEPLOYMENT_LOCK = "/var/lib/cptc-harness/portcast-live-v1/deployment.lock"
_CLOCK_OFFSET = re.compile(r"Offset:\s*([+-]?[0-9.]+)\s*(ns|us|µs|ms|s)\b")
_V5_MARKER_NAME = "v5-start.marker"
_V5_MARKER_PAYLOAD = (
    b"PORTCAST-START-V1\n"
    b"release 4c9db1a159d7b1ca2ef38170458f32a2a17a6cd56d7c19e912a187cac138b918\n"
    b"plan dcb908436af15c0945926cabd16d12df1a78064bb85b2d0d675682da5164d08b\n"
    b"action cptc11-portcast-public-identity-action-v5\n"
)
_V5_RECEIPT = {
    "action_id": "cptc11-portcast-public-identity-action-v5",
    "admission_marker_present": True,
    "admission_marker_sha256": "6d4a1c0f18116b063bd7758e63cf3a33ca2f50f77137dbbcc7703a0126e718b5",
    "application_credentials_loaded": False,
    "broker_socket_opened": False,
    "broker_worker_sha256": "0a3a61a1e25d5381013d88938b573e7e4a3a7a2076b984ad8391a216e4fde983",
    "charged_tcp_connects": 0,
    "engagement_id": "cptc11-dell-validation-portcast-v5",
    "exec_start_pre_exit_status": 126,
    "failure_at": "2026-09-12T08:20:07.741362Z",
    "failure_stage": "start-admission-projection-write",
    "first_byte_observed": False,
    "launcher_sha256": "15deb8743ea56f07d7df0b4f98775ef7f050bf01f7aa15181ee95eaf44bd9fb0",
    "main_process_started": False,
    "plan_file_sha256": "dcb908436af15c0945926cabd16d12df1a78064bb85b2d0d675682da5164d08b",
    "plan_sha256": "8c519372e6a10b748c8dcffa128bdb00b03558594f5cd504ddd1e23f6f569ee9",
    "possible_tcp_connects": 0,
    "profile_worker_sha256": "472620e6112b00882f480ea4a0209e8dcdab9e0c54ba98ae2bef86c07342f400",
    "projection_marker_present": False,
    "release_manifest_sha256": "4c9db1a159d7b1ca2ef38170458f32a2a17a6cd56d7c19e912a187cac138b918",
    "request_sha256": "2de0bde4095f7832f225d8940d2006e83676f048f585f38c8af386c4f598c2c0",
    "result_present": False,
    "runtime_tree": [{"kind": "directory", "mode": 0o700, "path": "."}],
    "schema": "portcast-v5-predecessor-state-v1",
    "service_unit_sha256": "259ac6be5da2a11913266310fc2bd56e8d8371f392cd67db3b2757632b908f2e",
    "stop_reason": "service pre-start failed after private admission marker before projection",
    "target_capability_created": False,
    "target_sha256": "3f1663098809eddcb0187999789b7442220f6a8204d091d088b7cd2871e9eef3",
    "target_traffic": False,
}
_V5_RECEIPT_BYTES = json.dumps(
    _V5_RECEIPT, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("ascii")
_V5_RECEIPT_SHA256 = "42fdd74d5b0c99a00a3f2761c1efcc3e3a579c86caf30c85bf01d34cf9400ffe"
_V6_PLAN_FILE_SHA256 = "c2b4fad1f137d2c99a42a37f67773acdcfce9fe7a5983bf5d267082232120f71"
_V6_PLAN_SHA256 = "d21dd898329ca575f2d7848896776140c863a39d3473d4720f0c4a24352b066b"
_V6_RELEASE_MANIFEST_SHA256 = "154ad483d30f8f55cf15093a48614e37057a2c7f9e941e188d56caecccefea8f"
_V6_ACTION_ID = "cptc11-portcast-public-identity-action-v6"
_V6_ENGAGEMENT_ID = "cptc11-dell-validation-portcast-v6"
_V6_UNUSED_RECEIPT = {
    "action_id": _V6_ACTION_ID,
    "charged_tcp_connects": 0,
    "deployment_status": "never-deployed",
    "engagement_id": _V6_ENGAGEMENT_ID,
    "execution_status": "never-run",
    "first_byte_observed": False,
    "possible_tcp_connects": 0,
    "result_present": False,
    "release_manifest_sha256": _V6_RELEASE_MANIFEST_SHA256,
    "schema": "portcast-v6-unused-state-v1",
    "target_capability_created": False,
    "target_traffic": False,
    "v6_plan_file_sha256": _V6_PLAN_FILE_SHA256,
    "v6_plan_sha256": _V6_PLAN_SHA256,
}
_V6_UNUSED_RECEIPT_BYTES = json.dumps(
    _V6_UNUSED_RECEIPT, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("ascii")
_V6_UNUSED_RECEIPT_SHA256 = "6ea2a1a73384bc0a37b52c9b61b5ec624ba3142135d7883470d68e868b765947"


class DeploymentError(RuntimeError):
    pass


ServiceIdentity = namedtuple("ServiceIdentity", "account uid gid")


def _v3_state_path() -> Path:
    """Resolve the fixed historical v3 sibling for the selected state root."""

    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V3_STATE_PATH
    return STATE_PATH.parent / "portcast-live-v3"


def _v4_state_path() -> Path:
    """Resolve the fixed current v4 sibling for the selected state root."""

    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V4_STATE_PATH
    return STATE_PATH.parent / "portcast-live-v4"


def _v3_runtime_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V3_RUNTIME_PATH
    return _v3_state_path() / "runtime"


def _v4_runtime_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V4_RUNTIME_PATH
    return _v4_state_path() / "runtime"


def _v5_state_path() -> Path:
    """Resolve the fixed current v5 sibling for the selected state root."""

    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V5_STATE_PATH
    return STATE_PATH.parent / "portcast-live-v5"


def _v5_runtime_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V5_RUNTIME_PATH
    return _v5_state_path() / "runtime"


def _v5_admission_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V5_ADMISSION_PATH
    return _v5_state_path() / "admission"


def _v5_admission_projection_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V5_ADMISSION_PROJECTION_PATH
    return _v5_state_path() / "admission-projection"


def _v6_state_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V6_STATE_PATH
    return STATE_PATH.parent / "portcast-live-v6"


def _v6_runtime_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V6_RUNTIME_PATH
    return _v6_state_path() / "runtime"


def _v6_admission_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V6_ADMISSION_PATH
    return _v6_state_path() / "admission"


def _v6_admission_projection_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V6_ADMISSION_PROJECTION_PATH
    return _v6_state_path() / "admission-projection"


def _v6_v5_receipt_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V6_V5_RECEIPT_PATH
    return _v6_state_path() / "predecessors/v5/receipt.json"


def _v7_state_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V7_STATE_PATH
    return STATE_PATH.parent / "portcast-live-v7"


def _v7_runtime_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V7_RUNTIME_PATH
    return _v7_state_path() / "runtime"


def _v7_admission_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V7_ADMISSION_PATH
    return _v7_state_path() / "admission"


def _v7_admission_projection_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V7_ADMISSION_PROJECTION_PATH
    return _v7_state_path() / "admission-projection"


def _v7_v5_receipt_path() -> Path:
    if STATE_PATH == _DEFAULT_STATE_PATH:
        return V7_V5_RECEIPT_PATH
    return _v7_state_path() / "predecessors/v5/receipt.json"


def _v7_v6_unused_receipt_path() -> Path:
    return _v7_state_path() / "predecessors/v6-unused/receipt.json"


def _historical_paths() -> tuple[Path, Path, Path]:
    """Resolve only the fixed historical paths below the v1 state root."""

    if STATE_PATH == _DEFAULT_STATE_PATH:
        return OLD_LEDGER_PATH, OLD_AUDIT_PATH, OLD_RESULT_PATH
    return (
        STATE_PATH / "runtime/ledger/cptc11-dell-validation",
        STATE_PATH / "runtime/runtime/audit",
        STATE_PATH / "runtime/runtime/results/cptc11-portcast-public-identity-action-v2.json",
    )


def _resolve_service_identity() -> ServiceIdentity:
    """Resolve the sysusers-managed identity without pinning host numeric IDs."""

    try:
        account = pwd.getpwnam(SERVICE_ACCOUNT)
        group = grp.getgrnam(SERVICE_GROUP)
        groups = os.getgrouplist(account.pw_name, account.pw_gid)
    except (KeyError, OSError, AttributeError):
        raise DeploymentError("PortCast service identity is unavailable") from None
    if (
        account.pw_name != SERVICE_ACCOUNT
        or account.pw_uid in {0, 65534}
        or account.pw_gid != group.gr_gid
        or group.gr_name != SERVICE_GROUP
        or group.gr_gid in {0, 65534}
        or set(groups) != {group.gr_gid}
    ):
        raise DeploymentError("PortCast service identity differs")
    return ServiceIdentity(SERVICE_ACCOUNT, account.pw_uid, group.gr_gid)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def _is_utc_microseconds(value: object) -> bool:
    if not isinstance(value, str) or _UTC_MICROSECONDS.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise DeploymentError("release manifest contains duplicate fields")
        value[key] = item
    return value


def _parts(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} or "\x00" in part for part in path.parts)
    ):
        raise DeploymentError("release path is invalid")
    return path.parts


def _read_regular(
    root: Path,
    relative: str,
    *,
    installed: bool,
    allow_empty: bool = True,
    owner_uid: int | None = None,
    expected_mode: int | None = None,
) -> bytes:
    expected_uid = ROOT_UID if owner_uid is None else owner_uid
    directories: list[int] = []
    descriptor: int | None = None
    try:
        current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        directories.append(current)
        root_info = os.fstat(current)
        if not stat.S_ISDIR(root_info.st_mode) or (
            installed
            and (
                root_info.st_uid != expected_uid
                or root_info.st_mode & 0o022
                or expected_mode is not None
                and stat.S_IMODE(root_info.st_mode) != 0o555
            )
        ):
            raise DeploymentError("release directory metadata differs")
        parts = _parts(relative)
        for component in parts[:-1]:
            current = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            directories.append(current)
            info = os.fstat(current)
            if not stat.S_ISDIR(info.st_mode) or (
                installed
                and (
                    info.st_uid != expected_uid
                    or info.st_mode & 0o022
                    or expected_mode is not None
                    and stat.S_IMODE(info.st_mode) != 0o555
                )
            ):
                raise DeploymentError("release directory metadata differs")
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (not allow_empty and before.st_size == 0)
            or before.st_size > _MAX_FILE
            or installed
            and (
                before.st_uid != expected_uid
                or before.st_mode & 0o022
                or expected_mode is not None
                and stat.S_IMODE(before.st_mode) != expected_mode
            )
        ):
            if expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode:
                raise DeploymentError("release file mode differs")
            raise DeploymentError("release file metadata differs")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 128 * 1024))
            if not chunk:
                raise DeploymentError("release file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise DeploymentError("release file changed during read")
        after = os.fstat(descriptor)
        linked = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(after) != identity(linked):
            raise DeploymentError("release file changed during read")
        return b"".join(chunks)
    except (OSError, ValueError) as error:
        if isinstance(error, DeploymentError):
            raise
        raise DeploymentError("release file could not be read safely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory in reversed(directories):
            os.close(directory)


def _release_mode(relative: str) -> int:
    return 0o555 if relative in _EXECUTABLE_FILES else 0o444


def _manifest(root: Path, *, installed: bool) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(
        root,
        MANIFEST_RELATIVE.as_posix(),
        installed=installed,
        allow_empty=False,
        expected_mode=_release_mode(MANIFEST_RELATIVE.as_posix()) if installed else None,
    )
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise DeploymentError("release manifest is invalid") from None
    section = value.get(RELEASE_ID) if isinstance(value, dict) else None
    if (
        value.get("version") != 2
        or not isinstance(section, dict)
        or section.get("release_id") != RELEASE_ID
        or not isinstance(section.get("files"), dict)
        or not isinstance(section.get("python_runtime"), dict)
        or not isinstance(section.get("cpython_runtime"), dict)
        or not isinstance(section["python_runtime"].get("files"), dict)
        or not isinstance(section["python_runtime"].get("native_files"), dict)
        or not isinstance(section.get("interpreter"), dict)
    ):
        raise DeploymentError("release manifest schema differs")
    return value, raw


def verify_tree(root: Path, expected_manifest_sha256: str, *, installed: bool) -> dict[str, Any]:
    if not _is_hex64(expected_manifest_sha256):
        raise DeploymentError("expected manifest digest is invalid")
    manifest, raw = _manifest(root, installed=installed)
    if _digest(raw) != expected_manifest_sha256:
        raise DeploymentError("release manifest digest differs")
    section = manifest[RELEASE_ID]
    files = section["files"]
    runtime = section["python_runtime"]
    for relative, expected in files.items():
        if not _is_hex64(expected):
            raise DeploymentError("release file pin differs")
        if _digest(
            _read_regular(
                root,
                relative,
                installed=installed,
                expected_mode=_release_mode(relative) if installed else None,
            )
        ) != expected:
            raise DeploymentError("release file pin differs")
    runtime_root = runtime.get("root")
    if runtime_root != "vendor/portcast-python3.14/site-packages":
        raise DeploymentError("Python runtime root differs")
    expected_runtime = runtime["files"]
    runtime_raw: dict[str, bytes] = {}
    for relative, expected in expected_runtime.items():
        if not _is_hex64(expected):
            raise DeploymentError("Python runtime file pin differs")
        complete = f"{runtime_root}/{relative}"
        raw_file = _read_regular(
            root,
            complete,
            installed=installed,
            expected_mode=_release_mode(complete) if installed else None,
        )
        runtime_raw[relative] = raw_file
        if _digest(raw_file) != expected:
            raise DeploymentError("Python runtime file pin differs")
    runtime_path = root / runtime_root
    physical = {
        path.relative_to(runtime_path).as_posix()
        for path in runtime_path.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if physical != set(expected_runtime) or any(path.is_symlink() for path in runtime_path.rglob("*")):
        raise DeploymentError("Python runtime tree differs")
    cpython = section["cpython_runtime"]
    if cpython.get("root") != "vendor/portcast-rootfs-runtime" or not isinstance(cpython.get("files"), dict):
        raise DeploymentError("CPython runtime root differs")
    cpython_lock = "cptc_harness/resources/portcast-cpython-runtime-v1.json"
    if json.loads(
        _read_regular(
            root,
            cpython_lock,
            installed=installed,
            expected_mode=_release_mode(cpython_lock) if installed else None,
        )
    ) != cpython:
        raise DeploymentError("CPython runtime lock differs")
    cpython_path = root / cpython["root"]
    physical_cpython = {
        path.relative_to(cpython_path).as_posix()
        for path in cpython_path.rglob("*") if path.is_file() and not path.is_symlink()
    }
    if physical_cpython != set(cpython["files"]) or any(path.is_symlink() for path in cpython_path.rglob("*")):
        raise DeploymentError("CPython runtime tree differs")
    cpython_raw: dict[str, bytes] = {}
    for relative, expected in cpython["files"].items():
        complete = f"{cpython['root']}/{relative}"
        raw_file = _read_regular(
            cpython_path,
            relative,
            installed=installed,
            expected_mode=_release_mode(complete) if installed else None,
        )
        cpython_raw[relative] = raw_file
        if not _is_hex64(expected) or _digest(raw_file) != expected:
            raise DeploymentError("CPython runtime file differs")
    verifier_source = _read_regular(
        root,
        "cptc_harness/elf.py",
        installed=installed,
        allow_empty=False,
        expected_mode=_release_mode("cptc_harness/elf.py") if installed else None,
    )
    namespace: dict[str, Any] = {"__name__": "_portcast_verified_elf"}
    try:
        exec(compile(verifier_source, "<verified-portcast-elf>", "exec"), namespace)
        namespace["verify_elf_closure"](cpython_raw, cpython.get("elf_files"))
        namespace["verify_private_native_closure"](
            runtime_raw, runtime.get("native_files"), cpython_raw
        )
    except (KeyError, TypeError, ValueError):
        raise DeploymentError("PortCast native dependency closure differs") from None
    interpreter = section["interpreter"]
    if interpreter != {
        "path": "/app/vendor/portcast-rootfs-runtime/bin/python3.14",
        "sha256": cpython["files"].get("bin/python3.14"),
    }:
        raise DeploymentError("interpreter pin differs")
    return manifest


def _metadata(path: Path, *, directory: bool, mode_mask: int, allow_empty: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise DeploymentError(f"required path is unavailable: {path}") from None
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not correct_type
        or info.st_uid != ROOT_UID
        or info.st_gid != ROOT_GID
        or info.st_mode & mode_mask
        or not directory and not allow_empty and info.st_size == 0
    ):
        raise DeploymentError(f"required path metadata differs: {path}")
    return info


def _service_metadata(
    path: Path,
    identity: ServiceIdentity,
    *,
    directory: bool,
    mode: int,
    allow_empty: bool,
) -> os.stat_result:
    """Validate a historical service-owned input without changing it."""

    try:
        info = path.lstat()
    except OSError:
        raise DeploymentError(f"required historical path is unavailable: {path}") from None
    if (
        (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
        or info.st_uid != identity.uid
        or info.st_gid != identity.gid
        or stat.S_IMODE(info.st_mode) != mode
        or not allow_empty and info.st_size == 0
        or not directory and info.st_nlink != 1
    ):
        raise DeploymentError(f"historical path metadata differs: {path}")
    return info


def _root_metadata(path: Path, *, directory: bool, mode: int) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise DeploymentError(f"required root-owned path is unavailable: {path}") from None
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not correct_type
        or info.st_uid != ROOT_UID
        or info.st_gid != ROOT_GID
        or stat.S_IMODE(info.st_mode) != mode
        or not directory and info.st_nlink != 1
    ):
        raise DeploymentError(f"root-owned path metadata differs: {path}")
    return info


def _directory_names(path: Path) -> list[str]:
    try:
        return sorted(entry.name for entry in os.scandir(path))
    except OSError:
        raise DeploymentError(f"directory cannot be inspected: {path}") from None


def _read_exact(path: Path, maximum: int = 64 * 1024) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise DeploymentError(f"required file is unavailable: {path}") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise DeploymentError(f"required file differs: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > maximum:
            raise DeploymentError(f"required file differs: {path}")
        return value
    finally:
        os.close(descriptor)


def _validate_historical_inputs(identity: ServiceIdentity) -> None:
    """Check exact predecessor inputs and never create or mutate them."""

    ledger, audit, result = _historical_paths()
    for predecessor in (_v3_runtime_path(), _v4_runtime_path()):
        _service_metadata(
            predecessor, identity, directory=True, mode=0o700, allow_empty=True
        )
    _service_metadata(
        ledger, identity, directory=True, mode=0o700, allow_empty=True
    )
    _service_metadata(
        audit, identity, directory=True, mode=0o700, allow_empty=True
    )
    _service_metadata(
        result, identity, directory=False, mode=0o600, allow_empty=False
    )
    v6 = _v6_state_path()
    if v6.exists() or v6.is_symlink():
        raise DeploymentError(
            "PortCast v6 state is present; v6 was never admitted and requires review"
        )
    v5_parent = _v5_state_path()
    _root_metadata(v5_parent, directory=True, mode=0o755)
    v5_runtime = _v5_runtime_path()
    _service_metadata(
        v5_runtime, identity, directory=True, mode=0o700, allow_empty=True
    )
    if _directory_names(v5_runtime):
        raise DeploymentError("PortCast v5 runtime is not empty")
    v5_admission = _v5_admission_path()
    _root_metadata(v5_admission, directory=True, mode=0o700)
    if _directory_names(v5_admission) != [_V5_MARKER_NAME]:
        raise DeploymentError("PortCast v5 admission state differs")
    marker = v5_admission / _V5_MARKER_NAME
    _root_metadata(marker, directory=False, mode=0o600)
    if _read_exact(marker, 4096) != _V5_MARKER_PAYLOAD:
        raise DeploymentError("PortCast v5 admission marker differs")
    v5_projection = _v5_admission_projection_path()
    _root_metadata(v5_projection, directory=True, mode=0o755)
    if _directory_names(v5_projection):
        raise DeploymentError("PortCast v5 admission projection differs")


def _prepare_runtime_subtree_at(
    identity: ServiceIdentity, parent: Path, label: str
) -> Path:
    """Create one service-writable runtime subtree with exact metadata."""

    try:
        info = parent.lstat()
    except FileNotFoundError:
        try:
            parent.mkdir(mode=0o755)
            os.chown(parent, ROOT_UID, ROOT_GID)
            parent.chmod(0o755)
        except OSError:
            raise DeploymentError(f"{label} state parent cannot be created") from None
        info = parent.lstat()
    except OSError:
        raise DeploymentError(f"{label} state parent is unavailable") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_gid != ROOT_GID
        or stat.S_IMODE(info.st_mode) != 0o755
    ):
        raise DeploymentError(f"{label} state parent metadata differs")
    runtime = parent / "runtime"
    try:
        info = runtime.lstat()
    except FileNotFoundError:
        try:
            runtime.mkdir(mode=0o700)
            os.chown(runtime, identity.uid, identity.gid)
            runtime.chmod(0o700)
            info = runtime.lstat()
        except OSError:
            raise DeploymentError(f"{label} service runtime cannot be created") from None
    except OSError:
        raise DeploymentError(f"{label} service runtime is unavailable") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != identity.uid
        or info.st_gid != identity.gid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DeploymentError(f"{label} service runtime metadata differs")
    return runtime


def _prepare_runtime_subtree_v7(identity: ServiceIdentity) -> Path:
    """Create only the current v7 service-writable subtree."""

    return _prepare_runtime_subtree_at(identity, _v7_state_path(), "PortCast v7")


def _prepare_runtime_subtree(identity: ServiceIdentity) -> Path:
    """Historical v6 helper retained for offline fixture inspection."""

    return _prepare_runtime_subtree_at(identity, _v6_state_path(), "PortCast v6")


def _prepare_start_admission_at(
    admission_path: Path, projection_path: Path, label: str
) -> tuple[Path, Path]:
    """Prepare root-only one-start state outside the service runtime."""

    paths = (
        (admission_path, 0o700, f"{label} admission"),
        (projection_path, 0o755, f"{label} admission projection"),
    )
    for path, mode, label in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            try:
                path.mkdir(mode=mode)
                os.chown(path, ROOT_UID, ROOT_GID)
                path.chmod(mode)
                info = path.lstat()
            except OSError:
                raise DeploymentError(f"{label} cannot be created") from None
        except OSError:
            raise DeploymentError(f"{label} is unavailable") from None
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != ROOT_UID
            or info.st_gid != ROOT_GID
            or stat.S_IMODE(info.st_mode) != mode
        ):
            raise DeploymentError(f"{label} metadata differs")
    return admission_path, projection_path


def _prepare_start_admission_v7() -> tuple[Path, Path]:
    """Prepare the current v7 root-only one-start state."""

    return _prepare_start_admission_at(
        _v7_admission_path(), _v7_admission_projection_path(), "PortCast v7"
    )


def _prepare_start_admission() -> tuple[Path, Path]:
    """Historical v6 helper retained for offline fixture inspection."""

    return _prepare_start_admission_at(
        _v6_admission_path(), _v6_admission_projection_path(), "PortCast v6"
    )


def _prepare_v5_receipt_at(
    receipt: Path, label: str, *, allow_existing_grandparent: bool = False
) -> Path:
    """Create one immutable v5 predecessor receipt in a fresh state."""

    if _digest(_V5_RECEIPT_BYTES) != _V5_RECEIPT_SHA256:
        raise DeploymentError("PortCast v5 predecessor receipt constant differs")
    parent = receipt.parent
    grandparent = parent.parent
    if receipt.exists() or receipt.is_symlink():
        _root_metadata(grandparent, directory=True, mode=0o555)
        _root_metadata(parent, directory=True, mode=0o555)
        _root_metadata(receipt, directory=False, mode=0o444)
        expected_grandparent_names = (
            [parent.name, "v6-unused"]
            if allow_existing_grandparent
            else [parent.name]
        )
        if (
            _directory_names(grandparent) != sorted(expected_grandparent_names)
            or _directory_names(parent) != [receipt.name]
            or _read_exact(receipt) != _V5_RECEIPT_BYTES
        ):
            raise DeploymentError(f"{label} v5 predecessor receipt differs")
        return receipt
    if grandparent.exists() or grandparent.is_symlink():
        if not allow_existing_grandparent:
            raise DeploymentError(f"{label} v5 predecessor receipt state is incomplete")
        _root_metadata(grandparent, directory=True, mode=0o555)
        if _directory_names(grandparent) != ["v6-unused"]:
            raise DeploymentError(f"{label} v5 predecessor receipt state differs")
        if parent.exists() or parent.is_symlink():
            raise DeploymentError(f"{label} v5 predecessor receipt state is incomplete")
        try:
            # v7 stores the v5 receipt beside the already-created v6-unused
            # proof.  Open the root-owned predecessor directory briefly to
            # add the sibling, then restore its immutable mode.
            grandparent.chmod(0o755)
            parent.mkdir(mode=0o755)
            os.chown(parent, ROOT_UID, ROOT_GID)
            parent.chmod(0o755)
            _write(receipt, _V5_RECEIPT_BYTES, 0o444)
            parent.chmod(0o555)
            grandparent.chmod(0o555)
            _fsync_parent(receipt)
            _fsync_parent(parent)
        except OSError:
            try:
                grandparent.chmod(0o555)
            except OSError:
                pass
            raise DeploymentError(f"{label} v5 predecessor receipt cannot be created") from None
        _root_metadata(grandparent, directory=True, mode=0o555)
        _root_metadata(parent, directory=True, mode=0o555)
        _root_metadata(receipt, directory=False, mode=0o444)
        if _read_exact(receipt) != _V5_RECEIPT_BYTES:
            raise DeploymentError(f"{label} v5 predecessor receipt differs")
        return receipt
    if parent.exists() or parent.is_symlink():
        raise DeploymentError(f"{label} v5 predecessor receipt state is incomplete")
    try:
        grandparent.mkdir(mode=0o755)
        os.chown(grandparent, ROOT_UID, ROOT_GID)
        grandparent.chmod(0o755)
        parent.mkdir(mode=0o755)
        os.chown(parent, ROOT_UID, ROOT_GID)
        parent.chmod(0o755)
        _write(receipt, _V5_RECEIPT_BYTES, 0o444)
        parent.chmod(0o555)
        grandparent.chmod(0o555)
        _fsync_parent(receipt)
        _fsync_parent(parent)
    except OSError:
        raise DeploymentError(f"{label} v5 predecessor receipt cannot be created") from None
    _root_metadata(grandparent, directory=True, mode=0o555)
    _root_metadata(parent, directory=True, mode=0o555)
    _root_metadata(receipt, directory=False, mode=0o444)
    if _read_exact(receipt) != _V5_RECEIPT_BYTES:
        raise DeploymentError(f"{label} v5 predecessor receipt differs")
    return receipt


def _prepare_v5_receipt_v7() -> Path:
    """Create the current v7 immutable v5 predecessor receipt."""

    return _prepare_v5_receipt_at(
        _v7_v5_receipt_path(), "PortCast v7", allow_existing_grandparent=True
    )


def _prepare_v5_receipt() -> Path:
    """Historical v6 helper retained for offline fixture inspection."""

    return _prepare_v5_receipt_at(_v6_v5_receipt_path(), "PortCast v6")


def _require_v7_quiescent() -> None:
    """Require no active service or stale runtime socket before admission."""

    if _service_is_active():
        raise DeploymentError("PortCast service must be inactive before v7 admission")
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        raise DeploymentError("PortCast service socket must be absent before v7 admission")


def _prepare_v6_unused_receipt() -> Path:
    """Record the unused v6 admission as an immutable v7 predecessor input."""

    if hashlib.sha256(_V6_UNUSED_RECEIPT_BYTES).hexdigest() != _V6_UNUSED_RECEIPT_SHA256:
        raise DeploymentError("PortCast v6-unused receipt constant differs")
    _require_v7_quiescent()
    v6 = _v6_state_path()
    if v6.exists() or v6.is_symlink():
        raise DeploymentError(
            "PortCast v6 state is present; v6 was never admitted and requires review"
        )
    receipt = _v7_v6_unused_receipt_path()
    parent = receipt.parent
    predecessors = parent.parent
    state = predecessors.parent

    # Build the complete hierarchy while the two child directories are still
    # writable.  Tighten both directories only after the O_EXCL receipt has
    # been fsynced.  This also avoids relying on root's DAC override when a
    # non-root synthetic test creates the hierarchy.
    for path, final_mode in ((state, 0o755), (predecessors, 0o555), (parent, 0o555)):
        try:
            info = path.lstat()
        except FileNotFoundError:
            try:
                path.mkdir(mode=0o755)
                os.chown(path, ROOT_UID, ROOT_GID)
                path.chmod(0o755)
            except OSError:
                raise DeploymentError("PortCast v6-unused receipt parent is unavailable") from None
            info = path.lstat()
        except OSError:
            raise DeploymentError("PortCast v6-unused receipt parent is unavailable") from None
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != ROOT_UID
            or info.st_gid != ROOT_GID
            or stat.S_IMODE(info.st_mode) not in ({final_mode, 0o755} if path != state else {final_mode})
        ):
            raise DeploymentError("PortCast v6-unused receipt parent metadata differs")
    if receipt.exists() or receipt.is_symlink():
        _root_metadata(state, directory=True, mode=0o755)
        _root_metadata(predecessors, directory=True, mode=0o555)
        _root_metadata(parent, directory=True, mode=0o555)
        _root_metadata(receipt, directory=False, mode=0o444)
        if _read_exact(receipt) != _V6_UNUSED_RECEIPT_BYTES:
            raise DeploymentError("PortCast v6-unused receipt differs")
        return receipt
    if stat.S_IMODE(predecessors.stat().st_mode) != 0o755 or stat.S_IMODE(parent.stat().st_mode) != 0o755:
        raise DeploymentError("PortCast v6-unused receipt state is incomplete")
    try:
        _write(receipt, _V6_UNUSED_RECEIPT_BYTES, 0o444)
        parent.chmod(0o555)
        _fsync_parent(parent)
        predecessors.chmod(0o555)
        _fsync_parent(predecessors)
        _root_metadata(receipt, directory=False, mode=0o444)
    except OSError:
        raise DeploymentError("PortCast v6-unused receipt cannot be created") from None
    _root_metadata(state, directory=True, mode=0o755)
    _root_metadata(predecessors, directory=True, mode=0o555)
    _root_metadata(parent, directory=True, mode=0o555)
    if _read_exact(receipt) != _V6_UNUSED_RECEIPT_BYTES:
        raise DeploymentError("PortCast v6-unused receipt differs")
    return receipt


def _prerequisites(identity: ServiceIdentity | None = None) -> ServiceIdentity:
    identity = identity or _resolve_service_identity()
    if not isinstance(identity, ServiceIdentity):
        raise DeploymentError("PortCast service identity differs")
    _metadata(STATE_PATH, directory=True, mode_mask=0o077, allow_empty=True)
    for path in CREDENTIAL_PATHS:
        _metadata(path, directory=False, mode_mask=0o077, allow_empty=False)
    _validate_historical_inputs(identity)
    # Prove the expired v6 admission is absent before any fresh v7 state is
    # created.  A conflicting v6 tree must leave no partial v7 runtime behind.
    _prepare_v6_unused_receipt()
    _prepare_runtime_subtree_v7(identity)
    _prepare_start_admission_v7()
    _prepare_v5_receipt_v7()
    return identity


def _write(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
    finally:
        os.close(descriptor)
    _fsync_parent(path)


def _fsync_parent(path: Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _deployment_lock(*, exclusive: bool, identity: ServiceIdentity):
    """Acquire the root control lock before changing deployment state.

    The service opens this file read-only and retains a shared lock. The
    group-read bit permits that open without giving the service or an operator
    write access to control metadata.
    """

    if not isinstance(identity, ServiceIdentity):
        raise DeploymentError("PortCast service identity differs")
    lock_path = STATE_PATH / "deployment.lock"
    created = False
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o640,
        )
        created = True
    except FileExistsError:
        descriptor = os.open(
            lock_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    try:
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DeploymentError("deployment lock is held by the service") from None
        info = os.fstat(descriptor)
        legacy = (
            not created
            and stat.S_ISREG(info.st_mode)
            and info.st_uid == ROOT_UID
            and info.st_gid == ROOT_GID
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
        )
        current = (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == ROOT_UID
            and info.st_gid == identity.gid
            and stat.S_IMODE(info.st_mode) == 0o640
            and info.st_nlink == 1
        )
        if created or legacy:
            os.fchown(descriptor, ROOT_UID, identity.gid)
            os.fchmod(descriptor, 0o640)
            os.fsync(descriptor)
            _fsync_parent(lock_path)
            info = os.fstat(descriptor)
            current = (
                stat.S_ISREG(info.st_mode)
                and info.st_uid == ROOT_UID
                and info.st_gid == identity.gid
                and stat.S_IMODE(info.st_mode) == 0o640
                and info.st_nlink == 1
            )
        if not current:
            raise DeploymentError("deployment lock metadata differs")
        yield descriptor
    finally:
        os.close(descriptor)


def _journal(operation: str, step: str) -> None:
    journal = STATE_PATH / "deployment-journal.json"
    temporary = journal.with_name(journal.name + ".new")
    if temporary.exists():
        raise DeploymentError("deployment journal staging file requires review")
    _write(temporary, json.dumps({"operation": operation, "step": step}, sort_keys=True).encode() + b"\n", 0o600)
    os.replace(temporary, journal)
    _fsync_parent(journal)


def _clear_journal() -> None:
    journal = STATE_PATH / "deployment-journal.json"
    try:
        journal.unlink()
    except FileNotFoundError:
        return
    _fsync_parent(journal)


def _payloads(manifest: dict[str, Any]) -> dict[str, bytes]:
    section = manifest[RELEASE_ID]
    names = set(section["files"])
    names.add(MANIFEST_RELATIVE.as_posix())
    runtime_root = section["python_runtime"]["root"]
    names.update(f"{runtime_root}/{relative}" for relative in section["python_runtime"]["files"])
    cpython_root = section["cpython_runtime"]["root"]
    names.update(f"{cpython_root}/{relative}" for relative in section["cpython_runtime"]["files"])
    return {name: _read_regular(SOURCE_ROOT, name, installed=False) for name in sorted(names)}


def _anchor_payload(manifest: dict[str, Any], manifest_sha256: str) -> bytes:
    section = manifest[RELEASE_ID]
    return (
        "PORTCAST-TRUST-V2\n"
        f"release {manifest_sha256}\n"
        f"bootstrap {section['bootstrap_manifest']['sha256']}\n"
        f"launcher {section['launcher']['sha256']}\n"
    ).encode("ascii")


def _timedatectl_clock() -> tuple[bool, float | None]:
    """Read the host synchronization state through fixed timedatectl calls."""

    environment = {"LC_ALL": "C"}
    deadline = time.monotonic() + 30
    try:
        status = subprocess.run(
            ("/usr/bin/timedatectl", "show", "--no-pager", "--property=NTPSynchronized", "--value"),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            close_fds=True,
            timeout=30,
        )
        remaining = max(0.01, deadline - time.monotonic())
        details = subprocess.run(
            ("/usr/bin/timedatectl", "timesync-status", "--no-pager"),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            close_fds=True,
            timeout=remaining,
        )
    except (OSError, subprocess.SubprocessError):
        raise DeploymentError("host clock synchronization status is unavailable") from None
    if status.returncode != 0 or details.returncode != 0:
        raise DeploymentError("host clock synchronization status is unavailable")
    try:
        synchronized = status.stdout.decode("ascii", "strict").strip() == "yes"
        text = details.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise DeploymentError("host clock synchronization status is invalid") from None
    if not synchronized:
        raise DeploymentError("host clock is not synchronized")
    found = _CLOCK_OFFSET.search(text)
    if found is None:
        raise DeploymentError("host clock offset is unavailable")
    scale = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1}
    try:
        offset = float(found[1]) * scale[found[2]]
    except (KeyError, ValueError, OverflowError):
        raise DeploymentError("host clock offset is invalid") from None
    if not -2.0 <= offset <= 2.0:
        raise DeploymentError("host clock offset exceeds policy")
    return True, offset


def _boot_identity() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        parsed = uuid.UUID(value)
    except (OSError, UnicodeError, ValueError, AttributeError):
        raise DeploymentError("host boot identity is unavailable") from None
    if str(parsed) != value.lower():
        raise DeploymentError("host boot identity is invalid")
    return value.lower()


def _write_clock_attestation(value: bytes, service_gid: int) -> None:
    path = CLOCK_ATTESTATION_PATH
    if (
        not path.is_absolute()
        or type(service_gid) is not int
        or service_gid in {0, 65534}
    ):
        raise DeploymentError("clock attestation path is fixed")
    try:
        parent = path.parent
        parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        parent_info = parent.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != ROOT_UID
            or parent_info.st_mode & 0o022
        ):
            raise DeploymentError("clock attestation directory metadata differs")
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != ROOT_UID
                or info.st_gid != service_gid
                or stat.S_IMODE(info.st_mode) != 0o440
                or info.st_nlink != 1
            ):
                raise DeploymentError("clock attestation file metadata differs")
        temporary = path.with_name("." + path.name + ".new")
        if temporary.exists() or temporary.is_symlink():
            raise DeploymentError("clock attestation staging file requires review")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o440,
        )
        try:
            written = 0
            while written < len(value):
                written += os.write(descriptor, value[written:])
            os.fchmod(descriptor, 0o440)
            os.fchown(descriptor, ROOT_UID, service_gid)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        _fsync_parent(path)
    except DeploymentError:
        raise
    except OSError:
        raise DeploymentError("clock attestation could not be written atomically") from None
    finally:
        try:
            if 'temporary' in locals() and temporary.exists():
                temporary.unlink()
        except OSError:
            pass


def attest_clock() -> dict[str, Any]:
    """Record a root-created, 30-second host clock attestation."""

    if os.geteuid() != ROOT_UID:
        raise DeploymentError("attest-clock requires the root deployment identity")
    service_identity = _resolve_service_identity()
    synchronized, offset = _timedatectl_clock()
    observed_ns = time.monotonic_ns()
    observed_at = datetime.now(timezone.utc)
    observed_utc = observed_at.isoformat(timespec="microseconds").replace("+00:00", "Z")
    expires_utc = (observed_at + timedelta(seconds=30)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    payload = {
        "version": 1,
        "boot_id": _boot_identity(),
        "observed_utc": observed_utc,
        "expires_utc": expires_utc,
        "observed_monotonic_ns": observed_ns,
        "expires_monotonic_ns": observed_ns + CLOCK_ATTESTATION_TTL_NS,
        "synchronized": synchronized,
        "offset_s": float(offset),
        "source": "timedatectl",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    _write_clock_attestation(encoded, service_identity.gid)
    return {
        "operation": "attest-clock",
        "path": str(CLOCK_ATTESTATION_PATH),
        "expires_monotonic_ns": payload["expires_monotonic_ns"],
        "ttl_seconds": CLOCK_ATTESTATION_TTL_NS // 1_000_000_000,
        "synchronized": True,
        "offset_s": float(offset),
        "service_started": False,
        "target_traffic": False,
        "state_preserved": True,
    }


def _verified_static_generation(
    release: Path,
    unit: Path,
    sysusers: Path,
    anchor: Path,
    *,
    expected_manifest_sha256: str | None = None,
    expected_legacy_sysusers_sha256: str | None = None,
) -> dict[str, Any]:
    anchor_raw = _read_regular(
        anchor.parent, anchor.name, installed=True, allow_empty=False
    )
    try:
        lines = anchor_raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise DeploymentError("deployment generation trust anchor differs") from None
    if (
        len(lines) != 4
        or lines[0] != "PORTCAST-TRUST-V2"
        or not lines[1].startswith("release ")
        or not _is_hex64(lines[1].removeprefix("release "))
    ):
        raise DeploymentError("deployment generation trust anchor differs")
    manifest_sha256 = lines[1].removeprefix("release ")
    if (
        expected_manifest_sha256 is not None
        and manifest_sha256 != expected_manifest_sha256
    ):
        raise DeploymentError("reviewed previous manifest digest differs")
    manifest = verify_tree(release / "app", manifest_sha256, installed=True)
    if anchor_raw != _anchor_payload(manifest, manifest_sha256):
        raise DeploymentError("deployment generation trust anchor differs")
    section = manifest[RELEASE_ID]
    unit_raw = _read_regular(
        unit.parent, unit.name, installed=True, allow_empty=False
    )
    if _digest(unit_raw) != section["files"].get(UNIT_SOURCE.as_posix()):
        raise DeploymentError("deployment generation service unit differs")
    sysusers_raw = _read_regular(
        sysusers.parent, sysusers.name, installed=True, allow_empty=False
    )
    sysusers_sha256 = _digest(sysusers_raw)
    manifest_sysusers_sha256 = section["files"].get(SYSUSERS_SOURCE.as_posix())
    if manifest_sysusers_sha256 is None:
        if not _is_hex64(expected_legacy_sysusers_sha256):
            raise DeploymentError("legacy sysusers digest is required")
        if sysusers_sha256 != expected_legacy_sysusers_sha256:
            raise DeploymentError("legacy sysusers digest differs")
        sysusers_pin_source = "operator-reviewed-legacy"
    else:
        if expected_legacy_sysusers_sha256 is not None:
            raise DeploymentError("legacy sysusers digest is not permitted")
        if sysusers_sha256 != manifest_sysusers_sha256:
            raise DeploymentError("deployment generation identity policy differs")
        sysusers_pin_source = "manifest"
    return {
        "manifest_sha256": manifest_sha256,
        "unit_sha256": _digest(unit_raw),
        "sysusers_sha256": sysusers_sha256,
        "sysusers_pin_source": sysusers_pin_source,
        "anchor_sha256": _digest(anchor_raw),
    }


def _prepare_tree(path: Path, payloads: dict[str, bytes]) -> None:
    path.mkdir(mode=0o700, parents=False)
    os.chown(path, ROOT_UID, ROOT_GID)
    app = path / "app"
    app.mkdir(mode=0o700)
    directories = {path, app}
    for relative, payload in payloads.items():
        target = app / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        for parent in (target.parent, *target.parent.parents):
            if parent == path.parent:
                break
            if path == parent or path in parent.parents:
                directories.add(parent)
        _write(target, payload, _release_mode(relative))
    for relative in (
        "etc/cptc-harness/trust", "run/cptc-harness",
        "run/cptc-harness-clock",
        "var/lib/cptc-harness/portcast-live-v1/runtime/v3/runtime/audit",
        "var/lib/cptc-harness/portcast-live-v1/runtime/v3-predecessor",
        "var/lib/cptc-harness/portcast-live-v1/runtime/v4",
        "var/lib/cptc-harness/portcast-live-v1/runtime/v5-predecessor",
        "var/lib/cptc-harness/portcast-live-v1/runtime/v7/runtime/audit",
        "var/lib/cptc-harness/portcast-live-v1/runtime/v7/ledger/cptc11-dell-validation-portcast-v7",
        "var/lib/cptc-harness/portcast-live-v1/admission",
        "var/lib/cptc-harness/portcast-live-v1/admission-projection",
        "var/lib/cptc-harness/portcast-live-v1/predecessors/v5/admission",
        "var/lib/cptc-harness/portcast-live-v1/predecessors/v5/admission-projection",
        "var/lib/cptc-harness/portcast-live-v1/predecessors/v6-unused",
        "var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation",
        "var/lib/cptc-harness/portcast-live-v1/runtime/runtime/audit",
        "var/lib/cptc-harness/portcast-live-v1/runtime/runtime/results",
        "var/lib/cptc-harness/portcast-live-v4/runtime",
        "var/lib/cptc-harness/portcast-live-v5/runtime",
        "var/lib/cptc-harness/portcast-live-v5/admission",
        "var/lib/cptc-harness/portcast-live-v5/admission-projection",
        "var/lib/cptc-harness/portcast-live-v7/runtime",
        "var/lib/cptc-harness/portcast-live-v7/admission",
        "var/lib/cptc-harness/portcast-live-v7/admission-projection",
        "var/lib/cptc-harness/portcast-live-v7/predecessors/v5",
        "tmp",
    ):
        directory = path / relative
        directory.mkdir(parents=True, exist_ok=True)
        directories.update((directory, *[parent for parent in directory.parents if path == parent or path in parent.parents]))
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        os.chown(directory, ROOT_UID, ROOT_GID)
        directory.chmod(0o555)


def _replace_triplet(staged: Path, current: Path, previous: Path) -> None:
    if previous.exists() or previous.is_symlink():
        raise DeploymentError(f"previous deployment must be reconciled first: {previous}")
    moved_current = False
    if current.exists() or current.is_symlink():
        os.replace(current, previous)
        _fsync_parent(previous)
        moved_current = True
    try:
        os.replace(staged, current)
        _fsync_parent(current)
    except BaseException:
        if moved_current:
            os.replace(previous, current)
            _fsync_parent(current)
        raise


def plan(expected_manifest_sha256: str | None) -> dict[str, Any]:
    raw = _read_regular(SOURCE_ROOT, MANIFEST_RELATIVE.as_posix(), installed=False, allow_empty=False)
    actual = _digest(raw)
    expected = expected_manifest_sha256 or actual
    manifest = verify_tree(SOURCE_ROOT, expected, installed=False)
    section = manifest[RELEASE_ID]
    return {
        "operation": "plan",
        "release_id": RELEASE_ID,
        "manifest_sha256": expected,
        "interpreter": section["interpreter"],
        "release_path": str(RELEASE_PATH),
        "unit_path": str(UNIT_PATH),
        "anchor_path": str(ANCHOR_PATH),
        "clock_attestation_path": str(CLOCK_ATTESTATION_PATH),
        "clock_attestation_ttl_seconds": CLOCK_ATTESTATION_TTL_NS // 1_000_000_000,
        "state_path": str(STATE_PATH),
        "v3_state_path": str(_v3_state_path()),
        "v3_runtime_path": str(_v3_runtime_path()),
        "v4_state_path": str(_v4_state_path()),
        "v4_runtime_path": str(_v4_runtime_path()),
        "v5_state_path": str(_v5_state_path()),
        "v5_runtime_path": str(_v5_runtime_path()),
        "v5_admission_path": str(_v5_admission_path()),
        "v5_admission_projection_path": str(_v5_admission_projection_path()),
        "v6_state_path": str(_v6_state_path()),
        "v6_runtime_path": str(_v6_runtime_path()),
        "v6_admission_path": str(_v6_admission_path()),
        "v6_admission_projection_path": str(_v6_admission_projection_path()),
        "v6_v5_receipt_path": str(_v6_v5_receipt_path()),
        "v6_state_status": "must-be-absent",
        "v7_state_path": str(_v7_state_path()),
        "v7_runtime_path": str(_v7_runtime_path()),
        "v7_admission_path": str(_v7_admission_path()),
        "v7_admission_projection_path": str(_v7_admission_projection_path()),
        "v7_v5_receipt_path": str(_v7_v5_receipt_path()),
        "v7_v6_unused_receipt_path": str(_v7_v6_unused_receipt_path()),
        "v7_v6_unused_receipt_sha256": _V6_UNUSED_RECEIPT_SHA256,
        "historical_ledger_path": str(_historical_paths()[0]),
        "historical_audit_path": str(_historical_paths()[1]),
        "historical_result_path": str(_historical_paths()[2]),
        "credential_paths": [str(path) for path in CREDENTIAL_PATHS],
        "service_start_requested": False,
        "target_traffic": False,
        "state_preserved": True,
    }


def apply(expected_manifest_sha256: str) -> dict[str, Any]:
    if os.geteuid() != ROOT_UID:
        raise DeploymentError("apply requires the root deployment identity")
    manifest = verify_tree(SOURCE_ROOT, expected_manifest_sha256, installed=False)
    identity = _resolve_service_identity()
    with _deployment_lock(exclusive=True, identity=identity):
        if _service_is_active():
            raise DeploymentError("stop the service before apply")
        if (STATE_PATH / "deployment-journal.json").exists():
            raise DeploymentError("deployment journal requires recovery review")
        _prerequisites(identity)
        return _apply_locked(manifest, expected_manifest_sha256)


def _apply_locked(manifest: dict[str, Any], expected_manifest_sha256: str) -> dict[str, Any]:
    payloads = _payloads(manifest)
    RELEASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ANCHOR_PATH.parent.mkdir(parents=True, exist_ok=True)
    SYSUSERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    stage = RELEASE_PATH.with_name(f".{RELEASE_PATH.name}.stage-{os.getpid()}")
    unit_stage = UNIT_PATH.with_name(f".{UNIT_PATH.name}.stage-{os.getpid()}")
    sysusers_stage = SYSUSERS_PATH.with_name(f".{SYSUSERS_PATH.name}.stage-{os.getpid()}")
    anchor_stage = ANCHOR_PATH.with_name(f".{ANCHOR_PATH.name}.stage-{os.getpid()}")
    stages = (stage, unit_stage, sysusers_stage, anchor_stage)
    triplets = (
        (stage, RELEASE_PATH, RELEASE_PATH.with_name(RELEASE_PATH.name + ".previous")),
        (unit_stage, UNIT_PATH, UNIT_PATH.with_name(UNIT_PATH.name + ".previous")),
        (sysusers_stage, SYSUSERS_PATH, SYSUSERS_PATH.with_name(SYSUSERS_PATH.name + ".previous")),
        (anchor_stage, ANCHOR_PATH, ANCHOR_PATH.with_name(ANCHOR_PATH.name + ".previous")),
    )
    if any(path.exists() or path.is_symlink() for path in stages):
        raise DeploymentError("deployment staging path already exists")
    if any(previous.exists() or previous.is_symlink() for _, _, previous in triplets):
        raise DeploymentError("previous deployment must be reconciled first")
    installed: list[tuple[Path, Path, Path]] = []
    try:
        _journal("apply", "staging")
        _prepare_tree(stage, payloads)
        _write(unit_stage, payloads[UNIT_SOURCE.as_posix()], 0o644)
        _write(sysusers_stage, _read_regular(SOURCE_ROOT, SYSUSERS_SOURCE.as_posix(), installed=False), 0o644)
        _write(anchor_stage, _anchor_payload(manifest, expected_manifest_sha256), 0o644)
        for staged, current, previous in triplets:
            _journal("apply", f"replace:{current}")
            _replace_triplet(staged, current, previous)
            installed.append((staged, current, previous))
    except BaseException as primary:
        compensation_error = None
        try:
            for staged, current, previous in reversed(installed):
                if current.exists() or current.is_symlink():
                    os.replace(current, staged)
                    _fsync_parent(staged)
                if previous.exists() or previous.is_symlink():
                    os.replace(previous, current)
                    _fsync_parent(current)
            for path in stages:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                    _fsync_parent(path)
                elif path.exists() or path.is_symlink():
                    path.unlink()
                    _fsync_parent(path)
        except BaseException as error:
            compensation_error = error
        if compensation_error is None:
            _clear_journal()
        else:
            primary.add_note(
                "deployment compensation failed; journal retained for review: "
                + type(compensation_error).__name__
            )
        raise
    _clear_journal()
    return {
        "operation": "apply",
        "manifest_sha256": expected_manifest_sha256,
        "service_started": False,
        "target_traffic": False,
        "state_preserved": True,
    }


def _startup_smoke(manifest: dict[str, Any]) -> None:
    clock_bind = []
    try:
        clock_info = CLOCK_ATTESTATION_PATH.lstat()
    except FileNotFoundError:
        clock_info = None
    if clock_info is not None and (
        not stat.S_ISREG(clock_info.st_mode)
        or clock_info.st_uid != ROOT_UID
        or clock_info.st_nlink != 1
        or stat.S_IMODE(clock_info.st_mode) != 0o440
    ):
        raise DeploymentError("clock attestation file metadata differs")
    if clock_info is not None:
        clock_bind = [
            "--dir",
            "/run/cptc-harness-clock",
            "--ro-bind",
            str(CLOCK_ATTESTATION_PATH),
            "/run/cptc-harness-clock/portcast-live-v1.json",
        ]
    completed = subprocess.run(
        (
            "/usr/bin/bwrap",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--tmpfs",
            "/",
            "--dir",
            "/app",
            "--ro-bind",
            str(RELEASE_PATH / "app"),
            "/app",
            "--dir",
            "/etc",
            "--dir",
            "/etc/cptc-harness",
            "--dir",
            "/etc/cptc-harness/trust",
            "--tmpfs",
            "/run",
            "--ro-bind",
            str(ANCHOR_PATH),
            _ROOTFS_ANCHOR,
            *clock_bind,
            "--dir",
            "/var",
            "--dir",
            "/var/lib",
            "--dir",
            "/var/lib/cptc-harness",
            "--dir",
            "/var/lib/cptc-harness/portcast-live-v1",
            "--dir",
            "/var/lib/cptc-harness/portcast-live-v1/predecessors",
            "--dir",
            "/var/lib/cptc-harness/portcast-live-v1/predecessors/v6-unused",
            "--ro-bind",
            str(_v7_v6_unused_receipt_path()),
            "/var/lib/cptc-harness/portcast-live-v1/predecessors/v6-unused/receipt.json",
            "--ro-bind",
            str(STATE_PATH / "deployment.lock"),
            _ROOTFS_DEPLOYMENT_LOCK,
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            "/sys",
            "/sys",
            "--tmpfs",
            "/tmp",
            "--remount-ro",
            "/",
            "/app/deployment/portcast-bootstrap",
            "--verify-startup-only",
        ),
        cwd="/",
        env={},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
        close_fds=True,
    )
    if completed.returncode != 0:
        raise DeploymentError("no-target startup verification failed")


def _inspect_service() -> dict[str, Any] | None:
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.settimeout(30)
    try:
        channel.connect(str(SOCKET_PATH))
        request = json.dumps(
            {"method": "inspect", "release_id": RELEASE_ID},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        if channel.send(request) != len(request):
            raise DeploymentError("short inspect request")
        raw = channel.recv(_MAX_PACKET + 1)
    except OSError:
        raise DeploymentError("canonical service inspect is unavailable") from None
    finally:
        channel.close()
    try:
        response = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        raise DeploymentError("canonical service inspect response is invalid") from None
    if not isinstance(response, dict) or set(response) != {"ok", "result"} or response["ok"] is not True:
        raise DeploymentError("canonical service inspect was denied")
    return response["result"]


def verify(*, inspect: bool) -> dict[str, Any]:
    if inspect:
        raise DeploymentError("run inspect as the authorized operator")
    anchor = _read_regular(ANCHOR_PATH.parent, ANCHOR_PATH.name, installed=True, allow_empty=False)
    try:
        lines = anchor.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise DeploymentError("installed trust anchor differs") from None
    if (
        len(lines) != 4
        or lines[0] != "PORTCAST-TRUST-V2"
        or not lines[1].startswith("release ")
        or not _is_hex64(lines[1].removeprefix("release "))
    ):
        raise DeploymentError("installed trust anchor differs")
    expected = lines[1].removeprefix("release ")
    manifest = verify_tree(RELEASE_PATH / "app", expected, installed=True)
    if anchor != _anchor_payload(manifest, expected):
        raise DeploymentError("installed trust anchor differs")
    section = manifest[RELEASE_ID]
    installed_unit = _read_regular(UNIT_PATH.parent, UNIT_PATH.name, installed=True, allow_empty=False)
    expected_unit = section["files"].get(UNIT_SOURCE.as_posix())
    if _digest(installed_unit) != expected_unit:
        raise DeploymentError("installed service unit hash differs")
    installed_sysusers = _read_regular(
        SYSUSERS_PATH.parent, SYSUSERS_PATH.name, installed=True, allow_empty=False
    )
    expected_sysusers = section["files"].get(SYSUSERS_SOURCE.as_posix())
    if _digest(installed_sysusers) != expected_sysusers:
        raise DeploymentError("installed service identity policy hash differs")
    unit_text = installed_unit.decode("utf-8", "strict")
    expected_exec = "ExecStart=/app/deployment/portcast-bootstrap"
    if expected_exec not in unit_text:
        raise DeploymentError("installed service interpreter differs")
    _prerequisites()
    _startup_smoke(manifest)
    return {
        "operation": "verify",
        "manifest_sha256": expected,
        "installed_unit_sha256": _digest(installed_unit),
        "credentials": [
            {"path": str(path), "metadata_verified": True} for path in CREDENTIAL_PATHS
        ],
        "startup_smoke": "release-only-no-target",
        "clock_admission_checked": False,
        "inspect": "not-requested",
        "target_traffic": False,
        "state_preserved": True,
    }


def inspect_service() -> dict[str, Any]:
    if os.geteuid() != OPERATOR_UID:
        raise DeploymentError("inspect requires the authorized operator identity")
    return {
        "operation": "inspect",
        "result": _inspect_service(),
        "target_traffic": False,
    }


def _service_is_active() -> bool:
    try:
        completed = subprocess.run(
            (
                "/usr/bin/systemctl",
                "show",
                "portcast-live-v1.service",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--no-pager",
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            close_fds=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise DeploymentError("canonical service state is unknown or failed") from None
    if completed.returncode != 0 or completed.stderr:
        raise DeploymentError("canonical service state is unknown or failed")
    try:
        fields: dict[str, str] = {}
        for line in completed.stdout.decode("ascii", "strict").splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in fields or not value:
                raise ValueError
            fields[key] = value
    except (UnicodeDecodeError, ValueError):
        raise DeploymentError("canonical service state is unknown or failed") from None
    if set(fields) != {"LoadState", "ActiveState", "SubState"}:
        raise DeploymentError("canonical service state is unknown or failed")
    if fields["ActiveState"] == "active":
        return True
    if fields == {
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
    }:
        return False
    if fields == {
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "SubState": "dead",
    }:
        try:
            UNIT_PATH.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            pass
    raise DeploymentError("canonical service state is unknown or failed")


def _retirement_paths(manifest_sha256: str) -> tuple[
    tuple[Path, Path, str], ...
]:
    return tuple(
        (
            current.with_name(current.name + ".previous"),
            current.with_name(current.name + f".retired-{manifest_sha256}"),
            kind,
        )
        for current, kind in (
            (RELEASE_PATH, "release"),
            (UNIT_PATH, "unit"),
            (SYSUSERS_PATH, "sysusers"),
            (ANCHOR_PATH, "anchor"),
        )
    )


def _retirement_history_root() -> Path:
    root = STATE_PATH / "deployment-history"
    try:
        root.mkdir(mode=0o700)
        os.chown(root, ROOT_UID, ROOT_GID)
        root.chmod(0o700)
        _fsync_parent(root)
    except FileExistsError:
        pass
    except OSError:
        raise DeploymentError("deployment history cannot be created") from None
    info = _metadata(root, directory=True, mode_mask=0o077, allow_empty=True)
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise DeploymentError("deployment history metadata differs")
    return root


def _read_retirement_receipt(root: Path, name: str) -> bytes:
    if PurePosixPath(name).name != name or not name.endswith(".json"):
        raise DeploymentError("deployment retirement receipt path differs")
    directory: int | None = None
    descriptor: int | None = None
    try:
        directory = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        root_info = os.fstat(directory)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != ROOT_UID
            or root_info.st_gid != ROOT_GID
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise DeploymentError("deployment history metadata differs")
        descriptor = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != ROOT_UID
            or before.st_gid != ROOT_GID
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > 64 * 1024
        ):
            raise DeploymentError("deployment retirement receipt metadata differs")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise DeploymentError(
                    "deployment retirement receipt changed during read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise DeploymentError("deployment retirement receipt changed during read")
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory, follow_symlinks=False)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if (
            identity(before) != identity(after)
            or identity(after) != identity(linked)
        ):
            raise DeploymentError("deployment retirement receipt changed during read")
        return raw
    except (OSError, ValueError):
        raise DeploymentError("deployment retirement receipt could not be read safely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def _retirement_result(receipt: dict[str, Any], *, already_retired: bool) -> dict[str, Any]:
    return {
        "operation": "retire-previous",
        "retired_manifest_sha256": receipt["retired_manifest_sha256"],
        "current_manifest_sha256": receipt["current_manifest_sha256"],
        "retired_at_utc": receipt["retired_at_utc"],
        "archived_paths": receipt["archived_paths"],
        "sysusers_pin_source": receipt["sysusers_pin_source"],
        "already_retired": already_retired,
        "service_started": False,
        "target_traffic": False,
        "state_preserved": True,
    }


def _validate_retirement_receipt(
    raw: bytes,
    *,
    expected_manifest_sha256: str,
    current_manifest_sha256: str,
    archived_paths: dict[str, str],
) -> dict[str, Any]:
    try:
        receipt = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise DeploymentError("deployment retirement receipt is invalid") from None
    required = {
        "schema_version",
        "operation",
        "retired_manifest_sha256",
        "current_manifest_sha256",
        "retired_at_utc",
        "archived_paths",
        "artifact_sha256",
        "sysusers_pin_source",
        "service_started",
        "target_traffic",
        "state_preserved",
    }
    artifact_keys = {"release", "unit", "sysusers", "anchor"}
    if (
        not isinstance(receipt, dict)
        or set(receipt) != required
        or receipt["schema_version"] != 1
        or receipt["operation"] != "retire-previous"
        or receipt["retired_manifest_sha256"] != expected_manifest_sha256
        or receipt["current_manifest_sha256"] != current_manifest_sha256
        or not _is_utc_microseconds(receipt["retired_at_utc"])
        or receipt["archived_paths"] != archived_paths
        or not isinstance(receipt["artifact_sha256"], dict)
        or set(receipt["artifact_sha256"]) != artifact_keys
        or any(not _is_hex64(value) for value in receipt["artifact_sha256"].values())
        or receipt["sysusers_pin_source"]
        not in {"manifest", "operator-reviewed-legacy"}
        or receipt["service_started"] is not False
        or receipt["target_traffic"] is not False
        or receipt["state_preserved"] is not True
    ):
        raise DeploymentError("deployment retirement receipt differs")
    return receipt


def retire_previous(
    expected_manifest_sha256: str,
    expected_legacy_sysusers_sha256: str | None = None,
) -> dict[str, Any]:
    if os.geteuid() != ROOT_UID:
        raise DeploymentError("retire-previous requires the root deployment identity")
    if not _is_hex64(expected_manifest_sha256):
        raise DeploymentError("expected previous manifest digest is invalid")
    identity = _resolve_service_identity()
    with _deployment_lock(exclusive=True, identity=identity):
        if _service_is_active():
            raise DeploymentError("stop the service before retiring a previous deployment")
        if (STATE_PATH / "deployment-journal.json").exists():
            raise DeploymentError("deployment journal requires recovery review")
        _prerequisites(identity)
        return _retire_previous_locked(
            expected_manifest_sha256,
            expected_legacy_sysusers_sha256=expected_legacy_sysusers_sha256,
        )


def _retire_previous_locked(
    expected_manifest_sha256: str,
    *,
    expected_legacy_sysusers_sha256: str | None = None,
) -> dict[str, Any]:
    triplets = _retirement_paths(expected_manifest_sha256)
    previous_present = tuple(
        previous.exists() or previous.is_symlink()
        for previous, _retired, _kind in triplets
    )
    retired_present = tuple(
        retired.exists() or retired.is_symlink()
        for _previous, retired, _kind in triplets
    )
    if any(previous_present) and not all(previous_present):
        raise DeploymentError("previous deployment artifacts are incomplete")
    if any(retired_present) and not all(retired_present):
        raise DeploymentError("retired deployment artifacts are incomplete")
    if all(previous_present) and any(retired_present):
        raise DeploymentError("retired deployment destination already exists")
    if not any(previous_present) and not all(retired_present):
        raise DeploymentError("previous deployment artifacts are incomplete")

    current = _verified_static_generation(
        RELEASE_PATH, UNIT_PATH, SYSUSERS_PATH, ANCHOR_PATH
    )
    archived_paths = {kind: str(retired) for _previous, retired, kind in triplets}
    history_root = _retirement_history_root()
    receipt_path = history_root / f"{expected_manifest_sha256}.json"

    archived = all(retired_present)
    archived_generation = _verified_static_generation(
        next(retired for _previous, retired, kind in triplets if kind == "release"),
        next(retired for _previous, retired, kind in triplets if kind == "unit"),
        next(retired for _previous, retired, kind in triplets if kind == "sysusers"),
        next(retired for _previous, retired, kind in triplets if kind == "anchor"),
        expected_manifest_sha256=expected_manifest_sha256,
        expected_legacy_sysusers_sha256=expected_legacy_sysusers_sha256,
    ) if archived else None
    if archived:
        raw = _read_retirement_receipt(history_root, receipt_path.name)
        receipt = _validate_retirement_receipt(
            raw,
            expected_manifest_sha256=expected_manifest_sha256,
            current_manifest_sha256=current["manifest_sha256"],
            archived_paths=archived_paths,
        )
        expected_hashes = {
            "release": archived_generation["manifest_sha256"],
            "unit": archived_generation["unit_sha256"],
            "sysusers": archived_generation["sysusers_sha256"],
            "anchor": archived_generation["anchor_sha256"],
        }
        if receipt["artifact_sha256"] != expected_hashes:
            raise DeploymentError("deployment retirement receipt differs")
        if receipt["sysusers_pin_source"] != archived_generation["sysusers_pin_source"]:
            raise DeploymentError("deployment retirement receipt differs")
        return _retirement_result(receipt, already_retired=True)

    previous_generation = _verified_static_generation(
        next(previous for previous, _retired, kind in triplets if kind == "release"),
        next(previous for previous, _retired, kind in triplets if kind == "unit"),
        next(previous for previous, _retired, kind in triplets if kind == "sysusers"),
        next(previous for previous, _retired, kind in triplets if kind == "anchor"),
        expected_manifest_sha256=expected_manifest_sha256,
        expected_legacy_sysusers_sha256=expected_legacy_sysusers_sha256,
    )
    if receipt_path.exists() or receipt_path.is_symlink():
        raise DeploymentError("deployment retirement receipt already exists")
    receipt = {
        "schema_version": 1,
        "operation": "retire-previous",
        "retired_manifest_sha256": expected_manifest_sha256,
        "current_manifest_sha256": current["manifest_sha256"],
        "retired_at_utc": datetime.now(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
        "archived_paths": archived_paths,
        "artifact_sha256": {
            "release": previous_generation["manifest_sha256"],
            "unit": previous_generation["unit_sha256"],
            "sysusers": previous_generation["sysusers_sha256"],
            "anchor": previous_generation["anchor_sha256"],
        },
        "sysusers_pin_source": previous_generation["sysusers_pin_source"],
        "service_started": False,
        "target_traffic": False,
        "state_preserved": True,
    }
    payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    receipt_stage = history_root / f".{expected_manifest_sha256}.stage-{os.getpid()}"
    moved: list[tuple[Path, Path, str]] = []
    try:
        _journal("retire-previous", "begin")
        for previous, retired, kind in triplets:
            _journal("retire-previous", f"archive:{kind}")
            os.replace(previous, retired)
            _fsync_parent(retired)
            moved.append((previous, retired, kind))
        _write(receipt_stage, payload, 0o600)
        os.replace(receipt_stage, receipt_path)
        _fsync_parent(receipt_path)
        _clear_journal()
    except BaseException as primary:
        compensation_error = None
        try:
            if receipt_path.exists() or receipt_path.is_symlink():
                receipt_path.unlink()
                _fsync_parent(receipt_path)
            if receipt_stage.exists() or receipt_stage.is_symlink():
                receipt_stage.unlink()
                _fsync_parent(receipt_stage)
            for previous, retired, _kind in reversed(moved):
                os.replace(retired, previous)
                _fsync_parent(previous)
        except BaseException as error:
            compensation_error = error
        if compensation_error is None:
            _clear_journal()
        else:
            primary.add_note(
                "retirement compensation failed; journal retained for review: "
                + type(compensation_error).__name__
            )
        raise
    return _retirement_result(receipt, already_retired=False)


def rollback() -> dict[str, Any]:
    if os.geteuid() != ROOT_UID:
        raise DeploymentError("rollback requires the root deployment identity")
    identity = _resolve_service_identity()
    with _deployment_lock(exclusive=True, identity=identity):
        if _service_is_active():
            raise DeploymentError("stop the service before rollback")
        if (STATE_PATH / "deployment-journal.json").exists():
            raise DeploymentError("deployment journal requires recovery review")
        return _rollback_locked()


def _rollback_locked() -> dict[str, Any]:
    triplets = tuple(
        (current, current.with_name(current.name + ".previous"), current.with_name(current.name + ".rolled-back"))
        for current in (RELEASE_PATH, UNIT_PATH, SYSUSERS_PATH, ANCHOR_PATH)
    )
    if any(not previous.exists() or displaced.exists() for current, previous, displaced in triplets):
        raise DeploymentError("rollback artifacts are incomplete or unreconciled")
    _journal("rollback", "begin")
    completed: list[tuple[Path, Path, Path]] = []
    try:
        for current, previous, displaced in triplets:
            _journal("rollback", f"replace:{current}")
            os.replace(current, displaced)
            _fsync_parent(displaced)
            try:
                os.replace(previous, current)
                _fsync_parent(current)
            except BaseException:
                os.replace(displaced, current)
                _fsync_parent(current)
                raise
            completed.append((current, previous, displaced))
    except BaseException as primary:
        compensation_error = None
        try:
            for current, previous, displaced in reversed(completed):
                os.replace(current, previous)
                _fsync_parent(previous)
                os.replace(displaced, current)
                _fsync_parent(current)
        except BaseException as error:
            compensation_error = error
        if compensation_error is None:
            _clear_journal()
        else:
            primary.add_note(
                "rollback compensation failed; journal retained for review: "
                + type(compensation_error).__name__
            )
        raise
    _clear_journal()
    return {
        "operation": "rollback",
        "service_started": False,
        "target_traffic": False,
        "state_preserved": True,
        "displaced_release": str(RELEASE_PATH.with_name(RELEASE_PATH.name + ".rolled-back")),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="operation", required=True)
    plan_parser = subcommands.add_parser("plan")
    plan_parser.add_argument("--expected-manifest-sha256")
    subcommands.add_parser("attest-clock")
    apply_parser = subcommands.add_parser("apply")
    apply_parser.add_argument("--expected-manifest-sha256", required=True)
    subcommands.add_parser("verify")
    subcommands.add_parser("inspect")
    retire_parser = subcommands.add_parser("retire-previous")
    retire_parser.add_argument("--expected-previous-manifest-sha256", required=True)
    retire_parser.add_argument("--expected-legacy-sysusers-sha256")
    subcommands.add_parser("rollback")
    arguments = parser.parse_args(argv)
    try:
        if arguments.operation == "plan":
            result = plan(arguments.expected_manifest_sha256)
        elif arguments.operation == "attest-clock":
            result = attest_clock()
        elif arguments.operation == "apply":
            result = apply(arguments.expected_manifest_sha256)
        elif arguments.operation == "verify":
            result = verify(inspect=False)
        elif arguments.operation == "inspect":
            result = inspect_service()
        elif arguments.operation == "retire-previous":
            result = retire_previous(
                arguments.expected_previous_manifest_sha256,
                arguments.expected_legacy_sysusers_sha256,
            )
        else:
            result = rollback()
    except DeploymentError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
