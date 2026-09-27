"""Manage one fixed, privileged, synthetic-only PortCast acceptance run.

Invoke with the pinned interpreter shown in the deployment guide. This file is
deliberately non-executable. It never receives a path, command, property, or
environment override from the operator.
"""

from __future__ import annotations

import argparse
from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time
from typing import Any


SOURCE_ROOT = Path(__file__).parent.parent
SOURCE_MANIFEST = SOURCE_ROOT / "cptc_harness/resources/release-integrity.json"
TOOL_SOURCE = SOURCE_ROOT / "deployment/portcast-systemd-acceptance.py"
UNIT_SOURCE = SOURCE_ROOT / "deployment/portcast-live-v1-acceptance@.service"
SYSUSERS_SOURCE = SOURCE_ROOT / "deployment/portcast-live-v1.sysusers"
WORKER_SOURCE = SOURCE_ROOT / "testing/cptc11_lab/portcast_acceptance.py"
INSTALLED_MANIFEST = Path(
    "/usr/lib/cptc-harness/portcast-live-v1/app/cptc_harness/resources/release-integrity.json"
)
ANCHOR_PATH = Path("/etc/cptc-harness/trust/portcast-live-v1.sha256")
INSTALLED_SYSUSERS_PATH = Path("/usr/lib/sysusers.d/cptc-harness-portcast.conf")
STATE_ROOT = Path(
    "/var/lib/cptc-harness/portcast-live-v1/systemd-acceptance"
)
RUNTIME_UNIT_PATH = Path(
    "/run/systemd/system/portcast-live-v1-acceptance@.service"
)
PRODUCTION_UNIT = "portcast-live-v1.service"
UNIT_TEMPLATE = "portcast-live-v1-acceptance@.service"
RELEASE_ID = "portcast-live-v1"
SERVICE_ACCOUNT = "_cptc-portcast"
SERVICE_GROUP = "cptc-harness"
ROOT_UID = 0
ROOT_GID = 0
NOBODY_ID = 65534
MAX_WORKER_RECEIPT = 64 * 1024
INVOCATION = "/app/deployment/portcast-bootstrap --acceptance-audit %i"
INVOCATION_ID = hashlib.sha256(INVOCATION.encode("ascii")).hexdigest()
COMMANDS = frozenset(
    {"plan", "run", "verify", "cleanup", "reconcile", "recover-cleanup"}
)
_RUN_ID = re.compile(r"^accept-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PROPERTY_NAMES = (
    "Id",
    "FragmentPath",
    "LoadState",
    "ActiveState",
    "SubState",
    "RootDirectory",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "PrivateDevices",
    "PrivateTmp",
    "DevicePolicy",
    "PrivateNetwork",
    "RestrictAddressFamilies",
    "IPAddressDeny",
    "NoNewPrivileges",
    "ProtectHostname",
    "RemoveIPC",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "MountAPIVFS",
    "ProtectSystem",
    "ProtectHome",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectProc",
    "ProcSubset",
    "RestrictSUIDSGID",
    "RestrictRealtime",
    "RestrictNamespaces",
    "SystemCallArchitectures",
    "UMask",
    "Restart",
    "User",
    "Group",
    "DynamicUser",
    "Result",
    "NRestarts",
    "ExecMainCode",
    "ExecMainStatus",
    "BindPaths",
    "BindReadOnlyPaths",
)
EXPECTED_PROPERTIES = {
    "FragmentPath": str(RUNTIME_UNIT_PATH),
    "LoadState": "loaded",
    "ActiveState": "active",
    "SubState": "exited",
    "RootDirectory": "/usr/lib/cptc-harness/portcast-live-v1",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "PrivateDevices": "yes",
    "PrivateTmp": "yes",
    "DevicePolicy": "closed",
    "PrivateNetwork": "yes",
    "RestrictAddressFamilies": "AF_UNIX AF_NETLINK",
    "IPAddressDeny": "any",
    "NoNewPrivileges": "yes",
    "ProtectHostname": "no",
    "RemoveIPC": "yes",
    "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes",
    "MountAPIVFS": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "ProtectKernelTunables": "no",
    "ProtectKernelModules": "yes",
    "ProtectKernelLogs": "no",
    "ProtectControlGroups": "yes",
    "ProtectClock": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "all",
    "RestrictSUIDSGID": "no",
    "RestrictRealtime": "yes",
    "RestrictNamespaces": "mnt ipc net pid user uts",
    "SystemCallArchitectures": "native",
    "UMask": "0077",
    "Restart": "no",
    "User": SERVICE_ACCOUNT,
    "Group": SERVICE_GROUP,
    "DynamicUser": "no",
    "Result": "success",
    "NRestarts": "0",
    "ExecMainCode": "1",
    "ExecMainStatus": "0",
}

# Only these systemd properties are compared as unordered member sets. Every
# other property is compared as its recorded scalar value. The raw readback is
# retained in receipts for review; canonicalisation is comparison-only.
_SET_PROPERTIES = frozenset({
    "RestrictAddressFamilies",
    "RestrictNamespaces",
})
_CIPHERTEXT_KEYS = frozenset({
    "artifacts",
    "bytes",
    "sha256",
    "integrity_valid",
})
_JOURNAL_PHASES = frozenset({
    "prepared",
    "unit-install-uncertain",
    "unit-installed",
    "start-uncertain",
    "post-start-uncertain",
    "verified",
    "receipt-verified",
    "reconciled",
    "cleanup-uncertain",
    "cleanup-complete",
    "cleanup-recovery-uncertain",
    "cleanup-recovered",
})

_UNCERTAIN_DIAGNOSTICS = {
    ("unit-install-uncertain", "unit-install"): "unit_install_uncertain",
    ("start-uncertain", "unit-start"): "start_uncertain",
    ("post-start-uncertain", "property-readback"): "property_readback_uncertain",
    ("post-start-uncertain", "worker-receipt"): "worker_receipt_uncertain",
    ("post-start-uncertain", "receipt-finalization"): "receipt_finalization_uncertain",
    ("cleanup-uncertain", "cleanup"): "cleanup_uncertain",
    ("cleanup-recovery-uncertain", "cleanup-recovery"): "cleanup_recovery_uncertain",
}


class AcceptanceError(RuntimeError):
    pass


ServiceIdentity = namedtuple("ServiceIdentity", "account group uid gid")


def _resolve_service_identity() -> ServiceIdentity:
    """Resolve one locked, nonroot service identity from the host NSS view."""

    try:
        account = pwd.getpwnam(SERVICE_ACCOUNT)
        group = grp.getgrnam(SERVICE_GROUP)
        groups = os.getgrouplist(account.pw_name, account.pw_gid)
    except (KeyError, OSError, AttributeError):
        raise AcceptanceError("PortCast service identity is unavailable") from None
    if (
        account.pw_name != SERVICE_ACCOUNT
        or type(account.pw_uid) is not int
        or account.pw_uid in {ROOT_UID, NOBODY_ID}
        or type(account.pw_gid) is not int
        or account.pw_gid != group.gr_gid
        or group.gr_name != SERVICE_GROUP
        or type(group.gr_gid) is not int
        or group.gr_gid in {ROOT_GID, NOBODY_ID}
        or set(groups) != {group.gr_gid}
        or not isinstance(group.gr_mem, (list, tuple))
    ):
        raise AcceptanceError("PortCast service identity differs")
    return ServiceIdentity(
        SERVICE_ACCOUNT, SERVICE_GROUP, account.pw_uid, group.gr_gid
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _validate_digest(value: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise AcceptanceError("expected manifest digest is invalid")
    return value


def _validate_run_id(value: str) -> str:
    if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
        raise AcceptanceError("acceptance run identifier is invalid")
    return value


def _unit_id(run_id: str) -> str:
    return f"portcast-live-v1-acceptance@{_validate_run_id(run_id)}.service"


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"accept-{stamp}-{os.urandom(4).hex()}"


def _digest(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        raise AcceptanceError("required acceptance file is unavailable") from None
    return hashlib.sha256(raw).hexdigest()


def _read_regular(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
    maximum: int,
) -> bytes:
    """Read one bounded regular file without following its final component."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid
            or before.st_gid != owner_gid
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum
        ):
            raise AcceptanceError("required acceptance file metadata differs")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise AcceptanceError("required acceptance file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise AcceptanceError("required acceptance file changed during read")
        after = os.fstat(descriptor)
        linked = path.lstat()
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(after) != identity(linked):
            raise AcceptanceError("required acceptance file changed during read")
        return b"".join(chunks)
    except AcceptanceError:
        raise
    except OSError:
        raise AcceptanceError("required acceptance file is unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _source_manifest(expected: str) -> dict[str, Any]:
    _validate_digest(expected)
    try:
        raw = SOURCE_MANIFEST.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError):
        raise AcceptanceError("reviewed source manifest is unavailable") from None
    if hashlib.sha256(raw).hexdigest() != expected:
        raise AcceptanceError("reviewed source manifest digest differs")
    section = value.get(RELEASE_ID) if isinstance(value, dict) else None
    files = section.get("files") if isinstance(section, dict) else None
    if (
        value.get("version") != 2
        or not isinstance(section, dict)
        or section.get("release_id") != RELEASE_ID
        or not isinstance(files, dict)
        or files.get("deployment/portcast-live-v1-acceptance@.service")
        != _digest(UNIT_SOURCE)
        or files.get("deployment/portcast-systemd-acceptance.py")
        != _digest(TOOL_SOURCE)
        or files.get("testing/cptc11_lab/portcast_acceptance.py")
        != _digest(WORKER_SOURCE)
        or files.get("deployment/portcast-live-v1.sysusers")
        != _digest(SYSUSERS_SOURCE)
    ):
        raise AcceptanceError("reviewed source manifest schema differs")
    return value


def plan(expected_manifest_sha256: str) -> dict[str, Any]:
    _source_manifest(expected_manifest_sha256)
    return {
        "operation": "plan",
        "release_id": RELEASE_ID,
        "manifest_sha256": expected_manifest_sha256,
        "unit_id": UNIT_TEMPLATE,
        "unit_sha256": _digest(UNIT_SOURCE),
        "invocation_id": INVOCATION_ID,
        "synthetic_only": True,
        "credentials": False,
        "af_inet_attempts": 0,
        "target_addresses": False,
        "writes_system_state": False,
    }


def _require_root() -> None:
    if os.geteuid() != ROOT_UID or os.getegid() != ROOT_GID:
        raise AcceptanceError("acceptance operation requires root")


def _systemctl(*arguments: str) -> tuple[int, bytes, bytes]:
    completed = subprocess.run(
        ("/usr/bin/systemctl", *arguments),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        close_fds=True,
        timeout=30,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _unit_state(unit: str) -> str:
    code, output, _error = _systemctl("is-active", unit)
    state = output.strip()
    if code == 0 and state == b"active":
        return "active"
    if code == 3 and state == b"inactive":
        return "inactive"
    if code == 3 and state == b"failed":
        return "failed"
    return "unknown"


def _production_state() -> str:
    return _unit_state(PRODUCTION_UNIT)


def _verify_installed_release(expected: str) -> None:
    _validate_digest(expected)
    try:
        manifest = INSTALLED_MANIFEST.read_bytes()
        anchor = ANCHOR_PATH.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError):
        raise AcceptanceError("installed release trust files are unavailable") from None
    if (
        hashlib.sha256(manifest).hexdigest() != expected
        or len(anchor) != 4
        or anchor[0] != "PORTCAST-TRUST-V2"
        or anchor[1] != f"release {expected}"
        or not anchor[2].startswith("bootstrap ")
        or _HEX64.fullmatch(anchor[2].removeprefix("bootstrap ")) is None
        or not anchor[3].startswith("launcher ")
        or _HEX64.fullmatch(anchor[3].removeprefix("launcher ")) is None
    ):
        raise AcceptanceError("installed release manifest binding differs")
    try:
        value = json.loads(manifest)
        files = value[RELEASE_ID]["files"]
    except (KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise AcceptanceError("installed release manifest schema differs") from None
    if (
        value.get("version") != 2
        or files.get("deployment/portcast-live-v1-acceptance@.service")
        != _digest(UNIT_SOURCE)
        or files.get("deployment/portcast-bootstrap")
        != anchor[3].removeprefix("launcher ")
        or files.get("deployment/portcast-live-v1.sysusers")
        != _digest(SYSUSERS_SOURCE)
    ):
        raise AcceptanceError("installed release manifest schema differs")
    installed_sysusers = _read_regular(
        INSTALLED_SYSUSERS_PATH,
        owner_uid=ROOT_UID,
        owner_gid=ROOT_GID,
        mode=0o644,
        maximum=4096,
    )
    if hashlib.sha256(installed_sysusers).hexdigest() != files[
        "deployment/portcast-live-v1.sysusers"
    ]:
        raise AcceptanceError("installed service identity definition differs")


def _run_root(run_id: str) -> Path:
    return STATE_ROOT / _validate_run_id(run_id)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_directory(
    path: Path, *, owner_uid: int, owner_gid: int, mode: int
) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise AcceptanceError("acceptance directory is unavailable") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_gid != owner_gid
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise AcceptanceError("acceptance directory metadata differs")


@contextmanager
def _controller_lock():
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        _validate_directory(
            STATE_ROOT,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o700,
        )
    except AcceptanceError:
        raise AcceptanceError("acceptance state root metadata differs") from None
    descriptor = os.open(
        STATE_ROOT / "acceptance.lock",
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise AcceptanceError("acceptance lock metadata differs")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AcceptanceError("another acceptance operation is active") from None
        yield
    finally:
        os.close(descriptor)


def _prepare_run_tree(run_id: str, identity: ServiceIdentity) -> Path:
    """Create a root-owned run root and only two service-writable children."""

    root = _run_root(run_id)
    worker = root / "worker"
    audit = worker / "audit"
    try:
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        worker.mkdir(mode=0o700)
        audit.mkdir(mode=0o700)
        os.chown(worker, identity.uid, identity.gid)
        os.chown(audit, identity.uid, identity.gid)
        worker.chmod(0o700)
        audit.chmod(0o700)
        _validate_directory(
            root,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o700,
        )
        for path in (worker, audit):
            _validate_directory(
                path,
                owner_uid=identity.uid,
                owner_gid=identity.gid,
                mode=0o700,
            )
        _fsync_directory(audit)
        _fsync_directory(worker)
        _fsync_directory(root)
        _fsync_directory(STATE_ROOT)
    except FileExistsError:
        raise AcceptanceError("acceptance run identifier already exists") from None
    except AcceptanceError:
        raise
    except OSError:
        raise AcceptanceError("acceptance run directory setup failed") from None
    return root


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _write_phase(run_id: str, phase: str, **metadata: Any) -> None:
    root = _run_root(run_id)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / "journal.jsonl"
    event = {
        "schema_version": 1,
        "run_id": run_id,
        "phase": phase,
        "utc": _now(),
        "monotonic_ns": time.monotonic_ns(),
        **metadata,
    }
    raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise AcceptanceError("acceptance journal metadata differs")
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(root)


def _write_uncertain_phase(run_id: str, phase: str, stage: str) -> None:
    """Record one bounded reason code without exposing process diagnostics."""

    diagnostic_code = _UNCERTAIN_DIAGNOSTICS.get((phase, stage))
    if diagnostic_code is None:
        raise AcceptanceError("acceptance diagnostic stage is invalid")
    _write_phase(
        run_id,
        phase,
        uncertain_stage=stage,
        automatic_retry=False,
        diagnostic_code=diagnostic_code,
    )


def _install_ephemeral_unit() -> None:
    payload = UNIT_SOURCE.read_bytes()
    if RUNTIME_UNIT_PATH.exists() or RUNTIME_UNIT_PATH.is_symlink():
        raise AcceptanceError("an acceptance unit already requires cleanup")
    temporary = RUNTIME_UNIT_PATH.with_name(RUNTIME_UNIT_PATH.name + ".new")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o644,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, RUNTIME_UNIT_PATH)
    _fsync_directory(RUNTIME_UNIT_PATH.parent)
    code, _out, _error = _systemctl("daemon-reload")
    if code != 0:
        raise AcceptanceError("acceptance unit reload is uncertain")


def _read_properties(run_id: str) -> dict[str, str]:
    unit = _unit_id(run_id)
    arguments = ["show", unit, "--no-pager"]
    arguments.extend(f"--property={name}" for name in _PROPERTY_NAMES)
    code, output, _error = _systemctl(*arguments)
    if code != 0:
        raise AcceptanceError("acceptance unit property state is uncertain")
    result: dict[str, str] = {}
    try:
        for line in output.decode("utf-8", "strict").splitlines():
            name, value = line.split("=", 1)
            if name in result:
                raise ValueError
            result[name] = value
    except (UnicodeDecodeError, ValueError):
        raise AcceptanceError("acceptance unit property state is invalid") from None
    if not _properties_match(result, run_id):
        raise AcceptanceError("acceptance unit property state differs")
    return result


def _deny_all(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    tokens = value.split()
    if tokens == ["any"]:
        return True
    try:
        networks = {ipaddress.ip_network(token, strict=True) for token in tokens}
    except ValueError:
        return False
    return networks == {
        ipaddress.ip_network("0.0.0.0/0"),
        ipaddress.ip_network("::/0"),
    }


def _path_tokens(value: object) -> frozenset[str] | None:
    if not isinstance(value, str) or not value:
        return None
    tokens = value.split()
    if not tokens or len(tokens) != len(set(tokens)):
        return None
    return frozenset(tokens)


def _set_tokens(value: object) -> frozenset[str] | None:
    """Return unique members for an explicitly set-valued systemd property."""

    if not isinstance(value, str) or not value:
        return None
    tokens = value.split()
    if not tokens or len(tokens) != len(set(tokens)):
        return None
    return frozenset(tokens)


def _expected_bind_paths(run_id: str) -> frozenset[str]:
    worker = _run_root(run_id) / "worker"
    return frozenset(
        {
            f"{worker}:/acceptance:rbind",
            f"{worker / 'audit'}:/var/lib/cptc-harness/portcast-live-v1/runtime/v3/runtime/audit:rbind",
        }
    )


def _expected_read_only_paths() -> frozenset[str]:
    paths = (
        ANCHOR_PATH,
        Path("/var/lib/cptc-harness/portcast-live-v1/deployment.lock"),
    )
    return frozenset(f"{path}:{path}:rbind" for path in paths)


def _properties_match(value: object, run_id: str) -> bool:
    if not isinstance(value, dict):
        return False
    expected = dict(EXPECTED_PROPERTIES)
    expected["Id"] = _unit_id(run_id)
    expected["BindPaths"] = value.get("BindPaths")
    expected["BindReadOnlyPaths"] = value.get("BindReadOnlyPaths")
    if set(value) != set(expected) or not _deny_all(value.get("IPAddressDeny")):
        return False
    if (
        _path_tokens(value.get("BindPaths")) != _expected_bind_paths(run_id)
        or _path_tokens(value.get("BindReadOnlyPaths"))
        != _expected_read_only_paths()
    ):
        return False
    for name, expected_value in expected.items():
        if name in {"IPAddressDeny", "BindPaths", "BindReadOnlyPaths"}:
            continue
        if name in _SET_PROPERTIES:
            if _set_tokens(value.get(name)) != _set_tokens(expected_value):
                return False
        elif value.get(name) != expected_value:
            return False
    return True


def _properties_equivalent(
    left: object, right: object, run_id: str
) -> bool:
    if not _properties_match(left, run_id) or not _properties_match(right, run_id):
        return False
    assert isinstance(left, dict) and isinstance(right, dict)
    for name in set(EXPECTED_PROPERTIES) | {"Id", "FragmentPath"}:
        if name in _SET_PROPERTIES:
            if _set_tokens(left.get(name)) != _set_tokens(right.get(name)):
                return False
        elif left.get(name) != right.get(name):
            return False
    return (
        _deny_all(left.get("IPAddressDeny"))
        and _deny_all(right.get("IPAddressDeny"))
        and _path_tokens(left.get("BindPaths")) == _path_tokens(right.get("BindPaths"))
        and _path_tokens(left.get("BindReadOnlyPaths"))
        == _path_tokens(right.get("BindReadOnlyPaths"))
    )


def _load_json(path: Path) -> dict[str, Any]:
    try:
        raw = _read_regular(
            path,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o600,
            maximum=1024 * 1024,
        )
        value = json.loads(raw)
    except (AcceptanceError, UnicodeDecodeError, ValueError):
        raise AcceptanceError("acceptance receipt is unavailable") from None
    if not isinstance(value, dict):
        raise AcceptanceError("acceptance receipt is invalid")
    return value


def _worker_receipt(
    run_id: str, identity: ServiceIdentity
) -> dict[str, Any]:
    raw = _read_regular(
        _run_root(run_id) / "worker" / "worker-receipt.json",
        owner_uid=identity.uid,
        owner_gid=identity.gid,
        mode=0o600,
        maximum=MAX_WORKER_RECEIPT,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        raise AcceptanceError("acceptance receipt is unavailable") from None
    if not isinstance(value, dict):
        raise AcceptanceError("acceptance receipt is invalid")
    return value


def _hex(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def validate_receipt(
    value: dict[str, Any], *, identity: ServiceIdentity | None = None
) -> dict[str, Any]:
    required = {
        "schema_version", "run_id", "release_id", "manifest_sha256",
        "unit_id", "unit_sha256", "invocation_id", "started_at",
        "completed_at", "started_monotonic_ns", "completed_monotonic_ns",
        "property_readback", "service_identity", "audit_worker", "ciphertext",
        "credentials", "live_action", "af_inet_attempts", "target_addresses",
        "automatic_retry", "status", "cleanup_status", "limitations",
    }
    try:
        run_id = _validate_run_id(value["run_id"])
        worker = value["audit_worker"]
        service = value["service_identity"]
        ciphertext = value["ciphertext"]
        expected_service = {
            "account": SERVICE_ACCOUNT,
            "group": SERVICE_GROUP,
            "uid": service.get("uid"),
            "gid": service.get("gid"),
            "cap_eff": "0000000000000000",
        }
        if identity is not None:
            expected_service.update(
                {
                    "account": identity.account,
                    "group": identity.group,
                    "uid": identity.uid,
                    "gid": identity.gid,
                }
            )
        valid = (
            set(value) == required
            and value["schema_version"] == 2
            and value["release_id"] == RELEASE_ID
            and _hex(value["manifest_sha256"])
            and value["unit_id"] == _unit_id(run_id)
            and _hex(value["unit_sha256"])
            and value["invocation_id"] == INVOCATION_ID
            and isinstance(value["started_at"], str) and value["started_at"].endswith("Z")
            and isinstance(value["completed_at"], str) and value["completed_at"].endswith("Z")
            and type(value["started_monotonic_ns"]) is int
            and type(value["completed_monotonic_ns"]) is int
            and value["completed_monotonic_ns"] >= value["started_monotonic_ns"]
            and _properties_match(value["property_readback"], run_id)
            and isinstance(service, dict)
            and set(service) == {"account", "group", "uid", "gid", "cap_eff"}
            and type(service.get("uid")) is int
            and service["uid"] not in {ROOT_UID, NOBODY_ID}
            and type(service.get("gid")) is int
            and service["gid"] not in {ROOT_GID, NOBODY_ID}
            and service == expected_service
            and worker == {
                "cap_eff": "0000000000000000",
                "netns_isolated": True,
                "interfaces": worker.get("interfaces"),
                "entry_fds": [0, 1, 2],
                "traffic": {
                    "af_inet_attempts": 0,
                    "af_inet6_attempts": 0,
                    "target_bytes": 0,
                },
                "af_inet_attempts": 0,
                "credential_fds": 0,
                "target_addresses": False,
            }
            and worker.get("interfaces") in ([], ["lo"])
            and isinstance(ciphertext, dict)
            and set(ciphertext) == _CIPHERTEXT_KEYS
            and ciphertext.get("artifacts") == 1
            and type(ciphertext.get("bytes")) is int and ciphertext["bytes"] > 0
            and _hex(ciphertext.get("sha256"))
            and ciphertext.get("integrity_valid") is True
            and value["credentials"] is False
            and value["live_action"] is False
            and value["af_inet_attempts"] == 0
            and value["target_addresses"] is False
            and value["automatic_retry"] is False
            and value["status"] in {"success", "uncertain", "failed"}
            and value["cleanup_status"] in {"pending", "complete", "uncertain"}
            and isinstance(value["limitations"], list)
            and all(isinstance(item, str) and item for item in value["limitations"])
        )
    except (AttributeError, KeyError, TypeError, AcceptanceError):
        valid = False
    if not valid:
        raise AcceptanceError("acceptance receipt is invalid")
    return value


def _assemble_receipt(
    run_id: str,
    expected: str,
    properties: dict[str, str],
    worker: dict[str, Any],
    identity: ServiceIdentity,
) -> dict[str, Any]:
    result = dict(worker)
    result.update(
        {
            "run_id": run_id,
            "release_id": RELEASE_ID,
            "manifest_sha256": expected,
            "unit_id": _unit_id(run_id),
            "unit_sha256": _digest(UNIT_SOURCE),
            "invocation_id": INVOCATION_ID,
            "property_readback": properties,
            "status": "success",
            "cleanup_status": "pending",
        }
    )
    return validate_receipt(result, identity=identity)


def run(expected_manifest_sha256: str) -> dict[str, Any]:
    _require_root()
    _validate_digest(expected_manifest_sha256)
    _source_manifest(expected_manifest_sha256)
    identity = _resolve_service_identity()
    state = _production_state()
    if state != "inactive":
        raise AcceptanceError("production service is active or its state is unknown")
    with _controller_lock():
        state = _production_state()
        if state != "inactive":
            raise AcceptanceError("production service is active or its state is unknown")
        _verify_installed_release(expected_manifest_sha256)
        run_id = _new_run_id()
        root = _prepare_run_tree(run_id, identity)
        _write_phase(run_id, "prepared", manifest_sha256=expected_manifest_sha256)
        try:
            _install_ephemeral_unit()
        except Exception:
            _write_uncertain_phase(run_id, "unit-install-uncertain", "unit-install")
            raise AcceptanceError("acceptance unit install is uncertain; reconcile without retry") from None
        _write_phase(run_id, "unit-installed", unit_sha256=_digest(UNIT_SOURCE))
        try:
            code, _out, _error = _systemctl("start", _unit_id(run_id))
        except Exception:
            _write_uncertain_phase(run_id, "start-uncertain", "unit-start")
            raise AcceptanceError(
                "acceptance start is uncertain; reconcile without retry"
            ) from None
        if code != 0:
            _write_uncertain_phase(run_id, "start-uncertain", "unit-start")
            raise AcceptanceError("acceptance start is uncertain; reconcile without retry")
        try:
            properties = _read_properties(run_id)
        except Exception:
            _write_uncertain_phase(
                run_id, "post-start-uncertain", "property-readback"
            )
            raise AcceptanceError(
                "acceptance result is uncertain; reconcile without retry"
            ) from None
        try:
            worker = _worker_receipt(run_id, identity)
        except Exception:
            _write_uncertain_phase(
                run_id, "post-start-uncertain", "worker-receipt"
            )
            raise AcceptanceError(
                "acceptance result is uncertain; reconcile without retry"
            ) from None
        try:
            receipt = _assemble_receipt(
                run_id,
                expected_manifest_sha256,
                properties,
                worker,
                identity,
            )
            _atomic_json(root / "receipt.json", receipt)
            _write_phase(run_id, "verified", receipt_sha256=_digest(root / "receipt.json"))
            return receipt
        except Exception:
            _write_uncertain_phase(
                run_id, "post-start-uncertain", "receipt-finalization"
            )
            raise AcceptanceError(
                "acceptance result is uncertain; reconcile without retry"
            ) from None


def verify(run_id: str) -> dict[str, Any]:
    _require_root()
    identity = _resolve_service_identity()
    with _controller_lock():
        root = _run_root(run_id)
        receipt = validate_receipt(
            _load_json(root / "receipt.json"), identity=identity
        )
        if receipt["cleanup_status"] != "complete":
            properties = _read_properties(run_id)
            if not _properties_equivalent(
                properties, receipt["property_readback"], run_id
            ):
                raise AcceptanceError("acceptance property receipt differs")
        _write_phase(run_id, "receipt-verified")
        return receipt


def reconcile(run_id: str) -> dict[str, Any]:
    _require_root()
    run_id = _validate_run_id(run_id)
    with _controller_lock():
        if not _run_root(run_id).is_dir():
            raise AcceptanceError("acceptance run is unavailable")
        state = _unit_state(_unit_id(run_id))
        status = (
            f"resolved-{state}"
            if state in {"active", "inactive", "failed"}
            else "uncertain"
        )
        result = {
            "operation": "reconcile",
            "run_id": run_id,
            "unit_id": _unit_id(run_id),
            "status": status,
            "automatic_retry": False,
            "receipt_present": (_run_root(run_id) / "receipt.json").is_file(),
        }
        _write_phase(
            run_id,
            "reconciled",
            unit_id=result["unit_id"],
            status=status,
            automatic_retry=False,
            receipt_present=result["receipt_present"],
        )
        return result


def _last_journal_phase(run_id: str) -> str | None:
    """Read the terminal journal phase without changing cleanup state."""

    path = _run_root(run_id) / "journal.jsonl"
    if not path.exists() and not path.is_symlink():
        return None
    raw = _read_regular(
        path,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        mode=0o600,
        maximum=1024 * 1024,
    )
    try:
        events = [json.loads(line) for line in raw.splitlines()]
    except (UnicodeDecodeError, ValueError):
        raise AcceptanceError("acceptance cleanup journal is invalid") from None
    if (
        not events
        or any(not isinstance(event, dict) for event in events)
        or any(event.get("run_id") != run_id for event in events)
    ):
        raise AcceptanceError("acceptance cleanup journal is invalid")
    phase = events[-1].get("phase")
    if not isinstance(phase, str) or phase not in _JOURNAL_PHASES:
        raise AcceptanceError("acceptance cleanup journal phase is invalid")
    return phase


def cleanup(run_id: str) -> dict[str, Any]:
    _require_root()
    run_id = _validate_run_id(run_id)
    with _controller_lock():
        root = _run_root(run_id)
        receipt_path = root / "receipt.json"
        if not root.is_dir():
            raise AcceptanceError("acceptance run is unavailable")
        if _last_journal_phase(run_id) == "cleanup-uncertain":
            raise AcceptanceError(
                "acceptance cleanup is uncertain; use recover-cleanup"
            )
        receipt = (
            validate_receipt(_load_json(receipt_path))
            if receipt_path.is_file()
            else None
        )
        state = _unit_state(_unit_id(run_id))
        if state == "unknown":
            _write_uncertain_phase(run_id, "cleanup-uncertain", "cleanup")
            raise AcceptanceError("acceptance cleanup is uncertain")
        if state == "active":
            code, _out, _error = _systemctl("stop", _unit_id(run_id))
            if code != 0:
                _write_uncertain_phase(run_id, "cleanup-uncertain", "cleanup")
                raise AcceptanceError("acceptance cleanup is uncertain")
        elif state == "failed":
            code, _out, _error = _systemctl("reset-failed", _unit_id(run_id))
            if code != 0:
                _write_uncertain_phase(run_id, "cleanup-uncertain", "cleanup")
                raise AcceptanceError("acceptance cleanup is uncertain")
        if RUNTIME_UNIT_PATH.exists():
            RUNTIME_UNIT_PATH.unlink()
            _fsync_directory(RUNTIME_UNIT_PATH.parent)
            code, _out, _error = _systemctl("daemon-reload")
            if code != 0:
                _write_uncertain_phase(run_id, "cleanup-uncertain", "cleanup")
                raise AcceptanceError("acceptance unit reload is uncertain")
        if receipt is not None:
            receipt["cleanup_status"] = "complete"
            _atomic_json(receipt_path, receipt)
        _atomic_json(
            root / "cleanup.json",
            {
                "schema_version": 1,
                "run_id": run_id,
                "unit_id": _unit_id(run_id),
                "completed_at": _now(),
                "completed_monotonic_ns": time.monotonic_ns(),
                "cleanup_status": "complete",
                "receipt_preserved": receipt is not None,
                "journal_preserved": True,
                "audit_preserved": True,
            },
        )
        _write_phase(
            run_id,
            "cleanup-complete",
            preserved_receipt=receipt is not None,
        )
        return {
            "operation": "cleanup",
            "run_id": run_id,
            "cleanup_status": "complete",
            "receipt_preserved": receipt is not None,
            "audit_preserved": True,
        }


def _cleanup_recovery_unit_sha256(run_id: str) -> str:
    path = _run_root(run_id) / "journal.jsonl"
    raw = _read_regular(
        path,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
        mode=0o600,
        maximum=1024 * 1024,
    )
    try:
        events = [json.loads(line) for line in raw.splitlines()]
    except (UnicodeDecodeError, ValueError):
        raise AcceptanceError("acceptance cleanup journal is invalid") from None
    if (
        not events
        or any(not isinstance(event, dict) for event in events)
        or any(event.get("run_id") != run_id for event in events)
        or events[-1].get("phase") != "cleanup-uncertain"
    ):
        raise AcceptanceError("acceptance cleanup is not awaiting reconciliation")
    installed = [
        event.get("unit_sha256")
        for event in events
        if event.get("phase") == "unit-installed"
    ]
    if len(installed) != 1 or not _hex(installed[0]):
        raise AcceptanceError("acceptance cleanup unit binding is invalid")
    return installed[0]


def recover_cleanup(run_id: str) -> dict[str, Any]:
    """Finish only a journal-bound uncertain cleanup; never start or stop a unit."""

    _require_root()
    run_id = _validate_run_id(run_id)
    with _controller_lock():
        root = _run_root(run_id)
        if not root.is_dir():
            raise AcceptanceError("acceptance run is unavailable")
        expected_unit_sha256 = _cleanup_recovery_unit_sha256(run_id)
        state = _unit_state(_unit_id(run_id))
        if state not in {"inactive", "failed"}:
            _write_uncertain_phase(
                run_id, "cleanup-recovery-uncertain", "cleanup-recovery"
            )
            raise AcceptanceError("acceptance cleanup recovery is uncertain")
        if RUNTIME_UNIT_PATH.exists() or RUNTIME_UNIT_PATH.is_symlink():
            raw = _read_regular(
                RUNTIME_UNIT_PATH,
                owner_uid=ROOT_UID,
                owner_gid=ROOT_GID,
                mode=0o644,
                maximum=64 * 1024,
            )
            if hashlib.sha256(raw).hexdigest() != expected_unit_sha256:
                raise AcceptanceError("acceptance cleanup unit binding differs")
        if state == "failed":
            code, _out, _error = _systemctl("reset-failed", _unit_id(run_id))
            if code != 0:
                _write_uncertain_phase(
                    run_id, "cleanup-recovery-uncertain", "cleanup-recovery"
                )
                raise AcceptanceError("acceptance cleanup recovery is uncertain")
        if RUNTIME_UNIT_PATH.exists():
            RUNTIME_UNIT_PATH.unlink()
            _fsync_directory(RUNTIME_UNIT_PATH.parent)
        code, _out, _error = _systemctl("daemon-reload")
        if code != 0:
            _write_uncertain_phase(
                run_id, "cleanup-recovery-uncertain", "cleanup-recovery"
            )
            raise AcceptanceError("acceptance cleanup recovery is uncertain")
        receipt_path = root / "receipt.json"
        receipt = None
        if receipt_path.is_file():
            receipt = validate_receipt(_load_json(receipt_path))
            receipt["cleanup_status"] = "complete"
            _atomic_json(receipt_path, receipt)
        _atomic_json(
            root / "cleanup.json",
            {
                "schema_version": 1,
                "run_id": run_id,
                "unit_id": _unit_id(run_id),
                "completed_at": _now(),
                "completed_monotonic_ns": time.monotonic_ns(),
                "cleanup_status": "complete",
                "receipt_preserved": receipt is not None,
                "journal_preserved": True,
                "audit_preserved": True,
                "recovered_from_uncertain_cleanup": True,
            },
        )
        _write_phase(
            run_id,
            "cleanup-recovered",
            automatic_retry=False,
            preserved_receipt=receipt is not None,
        )
        return {
            "operation": "recover-cleanup",
            "run_id": run_id,
            "cleanup_status": "complete",
            "receipt_preserved": receipt is not None,
            "audit_preserved": True,
            "automatic_retry": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--expected-manifest-sha256", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--expected-manifest-sha256", required=True)
    for command in ("verify", "cleanup", "reconcile", "recover-cleanup"):
        command_parser = sub.add_parser(command)
        command_parser.add_argument("--run-id", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "plan":
            result = plan(arguments.expected_manifest_sha256)
        elif arguments.command == "run":
            result = run(arguments.expected_manifest_sha256)
        elif arguments.command == "recover-cleanup":
            result = recover_cleanup(arguments.run_id)
        else:
            result = globals()[arguments.command](arguments.run_id)
    except AcceptanceError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
