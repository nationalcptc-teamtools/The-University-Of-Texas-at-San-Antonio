"""Canonical local PortCast authority service.

Production uses only fixed root-owned paths. Imports that can reach LabSession
occur in ``main`` after the external trust anchor and deployment are verified.
"""

from __future__ import annotations

import json
import hashlib
import importlib
import fcntl
import ctypes
from dataclasses import dataclass
from functools import partial
import os
from pathlib import Path, PurePosixPath
import socket
import stat
import struct
import sys
import re
from typing import Any, Callable


PRODUCTION_CONTROL_ROOT = Path("/var/lib/cptc-harness/portcast-live-v1")
PRODUCTION_STATE_ROOT = PRODUCTION_CONTROL_ROOT / "runtime"
PRODUCTION_SOCKET = Path("/run/cptc-harness/portcast-live-v1.sock")
PRODUCTION_SOCKET_GROUP = "cptc-harness"
SERVICE_ACCOUNT = "_cptc-portcast"
SERVICE_GROUP = "cptc-harness"
_MAX_PACKET = 64 * 1024
_CLIENT_IDLE_TIMEOUT_S = 2.0
_PRODUCTION_RELEASE_ROOT = Path("/app")
_PRODUCTION_MANIFEST = (
    _PRODUCTION_RELEASE_ROOT / "cptc_harness/resources/release-integrity.json"
)
_PRODUCTION_ANCHOR = Path("/etc/cptc-harness/trust/portcast-live-v1.sha256")
_PRODUCTION_RUNTIME_ROOT = (
    _PRODUCTION_RELEASE_ROOT / "vendor/portcast-python3.14/site-packages"
)
_PRODUCTION_CPYTHON_ROOT = (
    _PRODUCTION_RELEASE_ROOT / "vendor/portcast-rootfs-runtime"
)
_PRODUCTION_CREDENTIAL_ROOT = Path(
    "/run/credentials/portcast-live-v1.service"
)
_PRODUCTION_CREDENTIALS = (
    _PRODUCTION_CREDENTIAL_ROOT / "cptc11-dell",
    _PRODUCTION_CREDENTIAL_ROOT / "cptc11-kali",
)
_RUNTIME_LOCK = "cptc_harness/resources/portcast-python-runtime-v1.json"
_CPYTHON_LOCK = "cptc_harness/resources/portcast-cpython-runtime-v1.json"
_PRODUCTION_OPERATOR_UID = 1000
_RUNTIME_IMPORT_ROOTS = frozenset(
    {"bcrypt", "cffi", "cryptography", "fluidity", "invoke", "lexicon", "nacl", "paramiko", "pycparser", "yaml"}
)
_F_ADD_SEALS = 1033
_READONLY_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008
_ACCEPTANCE_RUN_ID = re.compile(
    r"^accept-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$"
)


@dataclass(frozen=True)
class ServiceIdentity:
    account: str
    group: str
    uid: int
    gid: int


def _require_service_identity() -> ServiceIdentity:
    """Check systemd's resolved nonroot identity inside the sealed RootDirectory.

    NSS files are intentionally absent from the private root. The host-side
    deployment and acceptance controller resolve names before the unit starts;
    this in-root guard verifies the resulting nonroot UID/GID and exact group
    set without a numeric account pin.
    """

    uid = os.geteuid()
    gid = os.getegid()
    if uid in {0, 65534} or gid in {0, 65534} or set(os.getgroups()) != {gid}:
        raise RuntimeError("PortCast service identity differs")
    return ServiceIdentity(SERVICE_ACCOUNT, SERVICE_GROUP, uid, gid)


def _bootstrap_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError("duplicate release manifest field")
        value[key] = item
    return value


def _bootstrap_read(
    path: Path, maximum: int = 8 * 1024 * 1024, *, allow_empty: bool = False
) -> bytes:
    """Read one absolute root-owned, nonwritable path without following links."""

    if not path.is_absolute():
        raise RuntimeError("bootstrap path is not absolute")
    parts = PurePosixPath(path).parts[1:]
    directories = []
    descriptor = None
    try:
        current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directories.append(current)
        for component in parts[:-1]:
            current = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            info = os.fstat(current)
            if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
                raise RuntimeError("bootstrap directory is not trusted")
            directories.append(current)
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current
        )
        info = os.fstat(descriptor)
        if (
            info.st_uid != 0
            or info.st_mode & 0o022
            or not stat.S_ISREG(info.st_mode)
            or not (0 if allow_empty else 1) <= info.st_size <= maximum
        ):
            raise RuntimeError("bootstrap file is not trusted")
        value = bytearray()
        while len(value) < info.st_size:
            chunk = os.read(descriptor, info.st_size - len(value))
            if not chunk:
                raise RuntimeError("short bootstrap file")
            value.extend(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError("changing bootstrap file")
        return bytes(value)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory in reversed(directories):
            os.close(directory)


def _bootstrap_release() -> dict[str, Any]:
    manifest_raw = _bootstrap_read(_PRODUCTION_MANIFEST)
    anchor = _bootstrap_read(_PRODUCTION_ANCHOR, 512)
    try:
        lines = anchor.decode("ascii", "strict").splitlines(keepends=True)
    except UnicodeDecodeError:
        raise RuntimeError("PortCast external trust anchor differs") from None
    if (
        len(lines) != 4
        or lines[0] != "PORTCAST-TRUST-V2\n"
        or lines[1] != f"release {hashlib.sha256(manifest_raw).hexdigest()}\n"
        or not lines[2].startswith("bootstrap ")
        or not lines[3].startswith("launcher ")
    ):
        raise RuntimeError("PortCast external trust anchor differs")
    manifest = json.loads(manifest_raw, object_pairs_hook=_bootstrap_pairs)
    section = manifest.get("portcast-live-v1") if isinstance(manifest, dict) else None
    files = section.get("files") if isinstance(section, dict) else None
    interpreter = section.get("interpreter") if isinstance(section, dict) else None
    runtime = section.get("python_runtime") if isinstance(section, dict) else None
    cpython = section.get("cpython_runtime") if isinstance(section, dict) else None
    if (
        manifest.get("version") != 2
        or not isinstance(files, dict)
        or not isinstance(interpreter, dict)
        or not isinstance(runtime, dict)
        or not isinstance(cpython, dict)
        or "cptc_harness/integrity.py" not in files
        or _RUNTIME_LOCK not in files
        or _CPYTHON_LOCK not in files
        or "testing/__init__.py" not in files
        or "testing/cptc11_lab/__init__.py" not in files
        or "testing/cptc11_lab/portcast_service.py" not in files
        or "testing/cptc11_lab/portcast_broker_worker.py" not in files
    ):
        raise RuntimeError("PortCast bootstrap manifest is incomplete")
    for relative, expected in files.items():
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or not isinstance(expected, str):
            raise RuntimeError("PortCast bootstrap file map is invalid")
        if hashlib.sha256(_bootstrap_read(_PRODUCTION_RELEASE_ROOT / path)).hexdigest() != expected:
            raise RuntimeError("PortCast bootstrap release differs")
    runtime_root = runtime.get("root")
    runtime_files = runtime.get("files")
    native_files = runtime.get("native_files")
    if (
        runtime.get("schema_version") != 1
        or runtime.get("python_abi") != "cp314-x86_64-linux-gnu"
        or runtime_root != "vendor/portcast-python3.14/site-packages"
        or not isinstance(runtime_files, dict)
        or not runtime_files
        or not isinstance(native_files, dict)
        or not native_files
        or json.loads(_bootstrap_read(_PRODUCTION_RELEASE_ROOT / _RUNTIME_LOCK), object_pairs_hook=_bootstrap_pairs) != runtime
    ):
        raise RuntimeError("PortCast bootstrap Python runtime is incomplete")
    for relative, expected in runtime_files.items():
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or not isinstance(expected, str):
            raise RuntimeError("PortCast bootstrap Python runtime map is invalid")
        actual = hashlib.sha256(
            _bootstrap_read(_PRODUCTION_RUNTIME_ROOT / path, allow_empty=True)
        ).hexdigest()
        if actual != expected:
            raise RuntimeError("PortCast bootstrap Python runtime differs")
    physical = set()
    for directory, directories, names in os.walk(
        _PRODUCTION_RUNTIME_ROOT, followlinks=False
    ):
        directory_path = Path(directory)
        info = directory_path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("PortCast bootstrap Python runtime directory differs")
        for name in directories:
            if (directory_path / name).is_symlink():
                raise RuntimeError("PortCast bootstrap Python runtime contains a symlink")
        for name in names:
            candidate = directory_path / name
            if candidate.is_symlink() or not candidate.is_file():
                raise RuntimeError("PortCast bootstrap Python runtime contains an unsafe file")
            physical.add(candidate.relative_to(_PRODUCTION_RUNTIME_ROOT).as_posix())
    if physical != set(runtime_files):
        raise RuntimeError("PortCast bootstrap Python runtime file set differs")
    cpython_lock = json.loads(
        _bootstrap_read(_PRODUCTION_RELEASE_ROOT / _CPYTHON_LOCK),
        object_pairs_hook=_bootstrap_pairs,
    )
    if cpython_lock != cpython or cpython.get("root") != "vendor/portcast-rootfs-runtime":
        raise RuntimeError("PortCast bootstrap CPython runtime differs")
    for relative, expected in cpython["files"].items():
        if hashlib.sha256(
            _bootstrap_read(_PRODUCTION_CPYTHON_ROOT / relative, 512 * 1024 * 1024, allow_empty=True)
        ).hexdigest() != expected:
            raise RuntimeError("PortCast bootstrap CPython runtime differs")
    loader_path = _PRODUCTION_CPYTHON_ROOT / cpython["entrypoints"]["loader"]
    if Path(os.readlink("/proc/self/exe")) != loader_path:
        raise RuntimeError("PortCast service is running under another interpreter")
    return manifest


def _activate_verified_imports(manifest: dict[str, Any]) -> None:
    """Expose only the verified release and sealed runtime after bootstrap."""

    runtime = manifest["portcast-live-v1"]["python_runtime"]
    if runtime["root"] != "vendor/portcast-python3.14/site-packages":
        raise RuntimeError("PortCast Python runtime root differs")
    standard = _PRODUCTION_CPYTHON_ROOT / "lib/python3.14"
    sys.path[:] = [
        str(_PRODUCTION_RELEASE_ROOT),
        str(_PRODUCTION_RUNTIME_ROOT),
        str(standard),
        str(standard / "lib-dynload"),
    ]
    sys.dont_write_bytecode = True
    importlib.invalidate_caches()


def _under(candidate: Path, root: Path) -> str | None:
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError:
        return None


def _assert_import_paths(
    *, project_files: dict[str, str] | Any, runtime_files: dict[str, str] | Any
) -> None:
    """Reject any project or SSH module that resolved outside reviewed files."""

    runtime_roots = _RUNTIME_IMPORT_ROOTS
    for root in sorted(runtime_roots):
        importlib.import_module(root)
    for name, module in tuple(sys.modules.items()):
        path_value = getattr(module, "__file__", None)
        if not path_value:
            continue
        path = Path(path_value).resolve(strict=True)
        top = name.partition(".")[0]
        if top in {"cptc_harness", "testing"}:
            relative = _under(path, _PRODUCTION_RELEASE_ROOT)
            if relative is None or relative not in project_files:
                raise RuntimeError("PortCast project import escaped the verified release")
        elif top in runtime_roots:
            relative = _under(path, _PRODUCTION_RUNTIME_ROOT)
            if relative is None or relative not in runtime_files:
                raise RuntimeError("PortCast SSH import escaped the verified runtime")


def _assert_verified_imports(release: Any) -> None:
    _assert_import_paths(
        project_files=release.file_sha256,
        runtime_files=release.runtime_file_sha256,
    )


def _assert_verified_process_maps() -> None:
    """Reject executable file mappings outside the sealed application root."""

    with open("/proc/self/maps", "rb", buffering=0) as source:
        raw = source.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise RuntimeError("PortCast executable map exceeds allowance")
    for line in raw.splitlines():
        fields = line.decode("utf-8", "strict").split(None, 5)
        if len(fields) < 6 or "x" not in fields[1] or not fields[5].startswith("/"):
            continue
        path = Path(fields[5].removesuffix(" (deleted)"))
        if _under(path, _PRODUCTION_RELEASE_ROOT) is None:
            raise RuntimeError("PortCast executable mapping escaped the verified root")


def _seal_service_credential(path: Path, *, owner_uid: int | None = None) -> int:
    """Copy one fixed systemd credential into a sealed anonymous descriptor."""

    expected_owner = os.geteuid() if owner_uid is None else owner_uid
    source = destination = None
    try:
        source = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(source)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner
            or info.st_mode & 0o077
            or not 1 <= info.st_size <= 64 * 1024
        ):
            raise RuntimeError("PortCast service credential metadata differs")
        value = bytearray()
        while len(value) < info.st_size:
            chunk = os.read(source, info.st_size - len(value))
            if not chunk:
                raise RuntimeError("PortCast service credential changed during read")
            value.extend(chunk)
        if os.read(source, 1) or b"\x00" in value:
            raise RuntimeError("PortCast service credential content differs")
        native_memfd = getattr(os, "memfd_create", None)
        if native_memfd is not None:
            destination = native_memfd(
                "portcast-credential", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
            )
        else:
            function = ctypes.CDLL(None, use_errno=True).memfd_create
            function.argtypes = [ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
            destination = function(b"portcast-credential", 0x0001 | 0x0002)
            if destination < 0:
                raise OSError(ctypes.get_errno(), "memfd_create failed")
        offset = 0
        while offset < len(value):
            offset += os.write(destination, value[offset:])
        os.lseek(destination, 0, os.SEEK_SET)
        fcntl.fcntl(destination, _F_ADD_SEALS, _READONLY_SEALS)
        sealed = destination
        destination = None
        return sealed
    except (OSError, ValueError):
        raise RuntimeError("PortCast service credential is unavailable") from None
    finally:
        if source is not None:
            os.close(source)
        if destination is not None:
            os.close(destination)


def _load_service_credentials() -> tuple[int, int]:
    descriptors: list[int] = []
    try:
        for path in _PRODUCTION_CREDENTIALS:
            descriptors.append(_seal_service_credential(path))
        return descriptors[0], descriptors[1]
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


class _CanonicalPortcastService:
    """Sequential service whose one canonical Ledger owns replay authority."""

    def __init__(
        self,
        *,
        state_root: Path,
        socket_path: Path,
        expected_client_uid: int,
        verified_release: Any,
        wire_broker_factory: Callable[..., Any],
        test_age_binary: Path | None = None,
        test_age_recipient: str | None = None,
        provision_for_test: bool = False,
    ) -> None:
        if not provision_for_test and (
            state_root != PRODUCTION_STATE_ROOT or socket_path != PRODUCTION_SOCKET
        ):
            raise RuntimeError("production PortCast service paths are fixed")
        self._state_root = Path(state_root)
        self._socket_path = Path(socket_path)
        self._expected_client_uid = expected_client_uid
        self._verified_release = verified_release
        self._wire_broker_factory = wire_broker_factory
        self._age_binary = test_age_binary
        self._age_recipient = test_age_recipient
        self._provision = provision_for_test

    @classmethod
    def _for_test(
        cls,
        *,
        state_root: Path,
        socket_path: Path,
        expected_client_uid: int,
        verified_release: Any,
        wire_broker_factory: Callable[..., Any],
        age_binary: Path,
        age_recipient: str,
    ) -> "_CanonicalPortcastService":
        return cls(
            state_root=state_root,
            socket_path=socket_path,
            expected_client_uid=expected_client_uid,
            verified_release=verified_release,
            wire_broker_factory=wire_broker_factory,
            test_age_binary=age_binary,
            test_age_recipient=age_recipient,
            provision_for_test=True,
        )

    def _peer_uid(self, connection: socket.socket) -> int:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return uid

    def _dispatch(self, request: Any) -> dict[str, Any] | None:
        if (
            not isinstance(request, dict)
            or set(request) != {"method", "release_id"}
            or request.get("release_id") != self._verified_release.release_id
            or request.get("method") not in {"execute", "inspect"}
        ):
            raise RuntimeError("invalid canonical PortCast service request")
        from testing.cptc11_lab import portcast_live

        if request["method"] == "inspect":
            return portcast_live._inspect_frozen_portcast_state_at_root(
                state_root=self._state_root,
                age_binary=self._age_binary,
                age_recipient=self._age_recipient,
                provision=self._provision,
            )
        return portcast_live._run_frozen_portcast_action_at_root(
            state_root=self._state_root,
            age_binary=self._age_binary,
            age_recipient=self._age_recipient,
            wire_broker_factory=self._wire_broker_factory,
            provision=self._provision,
        )

    def handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(_CLIENT_IDLE_TIMEOUT_S)
            raw = connection.recv(_MAX_PACKET + 1)
            if not raw or len(raw) > _MAX_PACKET:
                raise RuntimeError("invalid canonical PortCast service packet")
            request = json.loads(raw)
            uid = self._peer_uid(connection)
            method = request.get("method") if isinstance(request, dict) else None
            if uid != self._expected_client_uid and not (uid == 0 and method == "inspect"):
                raise RuntimeError("unauthorized canonical PortCast service peer")
            result = self._dispatch(request)
            response = {"ok": True, "result": result}
        except Exception:
            response = {"ok": False, "result": None}
        encoded = json.dumps(
            response, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        try:
            if connection.send(encoded) != len(encoded):
                raise OSError("short canonical PortCast service response")
        except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
            return

    def serve(self, *, maximum_connections: int | None = None) -> None:
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        accepted = 0
        try:
            listener.bind(str(self._socket_path))
            os.chmod(self._socket_path, 0o660)
            listener.listen(4)
            while maximum_connections is None or accepted < maximum_connections:
                connection, _address = listener.accept()
                try:
                    self.handle(connection)
                finally:
                    connection.close()
                accepted += 1
        finally:
            listener.close()
            try:
                self._socket_path.unlink()
            except FileNotFoundError:
                pass


def main() -> int:
    """Start the fixed production service only after anchored verification."""

    arguments = tuple(sys.argv[1:])
    acceptance = (
        len(arguments) == 2
        and arguments[0] == "--acceptance-audit"
        and _ACCEPTANCE_RUN_ID.fullmatch(arguments[1]) is not None
    )
    if arguments not in {(), ("--broker-worker",), ("--verify-startup-only",)} and not acceptance:
        return 1
    service_identity = None
    if not arguments or acceptance:
        try:
            service_identity = _require_service_identity()
        except RuntimeError:
            return 1
    manifest = _bootstrap_release()
    _activate_verified_imports(manifest)
    if sys.argv[1:] == ["--verify-startup-only"]:
        importlib.import_module("cptc_harness.integrity")
        importlib.import_module("testing.cptc11_lab")
        section = manifest["portcast-live-v1"]
        _assert_import_paths(
            project_files=section["files"],
            runtime_files=section["python_runtime"]["files"],
        )
        return 0
    from cptc_harness.integrity import verify_portcast_release

    release = verify_portcast_release()
    _assert_verified_imports(release)
    if acceptance:
        from testing.cptc11_lab.portcast_acceptance import main as acceptance_main

        _assert_verified_imports(release)
        return acceptance_main(verified_release=release, run_id=arguments[1])
    if sys.argv[1:] == ["--broker-worker"]:
        from testing.cptc11_lab.portcast_broker_worker import main as worker_main

        _assert_verified_imports(release)
        return worker_main(verified_release=release)
    from cptc_harness.profile_runtime.broker_ipc import _service_wire_broker_factory
    from testing.cptc11_lab.portcast_live import load_frozen_portcast_plan

    plan = load_frozen_portcast_plan()
    control_info = PRODUCTION_CONTROL_ROOT.stat()
    state_info = PRODUCTION_STATE_ROOT.stat()
    if (
        not stat.S_ISDIR(control_info.st_mode)
        or control_info.st_uid != 0
        or control_info.st_gid != 0
        or stat.S_IMODE(control_info.st_mode) != 0o700
        or not stat.S_ISDIR(state_info.st_mode)
        or state_info.st_uid != service_identity.uid
        or state_info.st_gid != service_identity.gid
        or stat.S_IMODE(state_info.st_mode) != 0o700
    ):
        return 1
    expected_uid = _PRODUCTION_OPERATOR_UID
    _assert_verified_process_maps()
    credential_fds = _load_service_credentials()
    try:
        service = _CanonicalPortcastService(
            state_root=PRODUCTION_STATE_ROOT,
            socket_path=PRODUCTION_SOCKET,
            expected_client_uid=expected_uid,
            verified_release=release,
            wire_broker_factory=partial(
                _service_wire_broker_factory, credential_fds=credential_fds
            ),
        )
        service.serve()
    finally:
        for descriptor in credential_fds:
            os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
