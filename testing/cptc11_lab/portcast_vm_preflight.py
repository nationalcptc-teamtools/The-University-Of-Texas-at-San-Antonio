"""One fixed, read-only Dell host preflight for CPTC11 PortCast VM 1106.

The production entry point has no command, target, VM, or network parameter.
It connects through the existing host-key-pinned Dell connector, captures one
fixed metadata script, encrypts the raw capture before writing it, and returns
only a small typed result.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Protocol, TextIO

from .transport import (
    AgeEncryptor,
    DEFAULT_CONFIG,
    JsonlTranscript,
    PinnedParamikoConnector,
    PreflightRejected,
    TransportError,
)


VMID = 1106
VM_NAME = "PortCast"
VM_BRIDGE = "vmbr110"
VM_MAC = "52:54:00:11:01:06"
CANONICAL_SNAPSHOTS = (
    "cptc11_00_imported_verified",
    "cptc11_10_regional_clean",
)
RAW_OUTPUT_CAP = 16 * 1024
REMOTE_TIMEOUT_SECONDS = 20.0
_RUN_ROOT = Path("~/.local/state/harbinger/cptc11-diagnostics").expanduser()
_RAW_ARTIFACT = "portcast-vm-1106-preflight.raw.age"
_RESULT_ARTIFACT = "result.json"
_SAFE_FAILURE_MESSAGE = "PortCast VM preflight failed safely"
_HEADER = b"HARBINGER_PORTCAST_VM_PREFLIGHT_V1"
_TRAILER = b"HARBINGER_PORTCAST_VM_PREFLIGHT_END"
_FIELDS = (
    "hostname",
    "pveversion",
    "status",
    "config",
    "snapshots",
    "bridge_link",
    "bridge_ports",
    "bridge_addresses",
    "bridge_routes",
    "network_namespaces",
    "lifecycle_process_count",
)
_EXPECTED_BRIDGE_PORTS = frozenset(
    {
        "tap1100i1",
        "tap1101i0",
        "tap1102i0",
        "tap1103i0",
        "tap1104i0",
        "tap1105i0",
        "tap1106i0",
        "tap1107i0",
    }
)
_LIFECYCLE_PROCESS_PATTERN = (
    "(^|/)([r]ange-lifecycle|[s]tage-team01-from-rit|[m]igrate-stage-dataset)"
    "[.]sh([[:space:]]|$)"
)


# Every expansion below contains output from one fixed read-only command. The
# output is framed with base64 so arbitrary configuration text cannot add a
# field or a transcript record. The caller never appends shell text.
PORTCAST_VM_PREFLIGHT_SCRIPT = f"""set -eu
emit() {{
  label=$1
  value=$2
  /usr/bin/printf '%s\\t' "$label"
  /usr/bin/printf '%s' "$value" | /usr/bin/base64 -w0
  /usr/bin/printf '\\n'
}}
/usr/bin/printf '%s\\n' HARBINGER_PORTCAST_VM_PREFLIGHT_V1
hostname_value=$(/usr/bin/hostname)
pveversion_value=$(/usr/bin/pveversion)
status_value=$(/usr/sbin/qm status {VMID})
config_value=$(/usr/sbin/qm config {VMID})
snapshots_value=$(/usr/sbin/qm listsnapshot {VMID})
bridge_link_value=$(/usr/sbin/ip -details -json link show dev {VM_BRIDGE})
bridge_ports_value=$(/usr/sbin/bridge -json link show master {VM_BRIDGE})
bridge_addresses_value=$(/usr/sbin/ip -json address show dev {VM_BRIDGE})
bridge_routes_value=$(/usr/sbin/ip -json route show table all dev {VM_BRIDGE})
network_namespaces_value=$(/usr/sbin/ip netns list)
lifecycle_process_count_value=$(/usr/bin/pgrep -fc '{_LIFECYCLE_PROCESS_PATTERN}' || :)
emit hostname "$hostname_value"
emit pveversion "$pveversion_value"
emit status "$status_value"
emit config "$config_value"
emit snapshots "$snapshots_value"
emit bridge_link "$bridge_link_value"
emit bridge_ports "$bridge_ports_value"
emit bridge_addresses "$bridge_addresses_value"
emit bridge_routes "$bridge_routes_value"
emit network_namespaces "$network_namespaces_value"
emit lifecycle_process_count "$lifecycle_process_count_value"
/usr/bin/printf '%s\\n' HARBINGER_PORTCAST_VM_PREFLIGHT_END
"""


class _Encryptor(Protocol):
    def encrypt(self, data: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class PortcastVmPreflightResult:
    """Sanitized facts required before any separately reviewed target action."""

    pve_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "dell_hostname": "dell-prox",
            "pve_version": self.pve_version,
            "vmid": VMID,
            "name": VM_NAME,
            "status": "running",
            "bridge": VM_BRIDGE,
            "mac": VM_MAC,
            "snapshots": list(CANONICAL_SNAPSHOTS),
            "bridge_up": True,
            "portcast_tap_present": True,
            "host_ipv4": False,
            "routed_ipv4": False,
            "network_namespace_count": 0,
            "lifecycle_process_count": 0,
            "vm_locked": False,
        }


def _reject(reason: str = "PortCast VM preflight output differs") -> None:
    raise PreflightRejected(reason)


def _strict_b64(value: bytes) -> bytes:
    if len(value) > RAW_OUTPUT_CAP * 2 or re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", value) is None:
        _reject()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        _reject()
    if len(decoded) > RAW_OUTPUT_CAP:
        _reject("PortCast VM preflight field exceeded its allowance")
    return decoded


def _parse_envelope(raw: bytes) -> dict[str, bytes]:
    if type(raw) is not bytes or not 1 <= len(raw) <= RAW_OUTPUT_CAP:
        _reject("PortCast VM preflight output exceeded its allowance")
    lines = raw.splitlines()
    if len(lines) != len(_FIELDS) + 2 or lines[0] != _HEADER or lines[-1] != _TRAILER:
        _reject()
    values: dict[str, bytes] = {}
    for line in lines[1:-1]:
        if line.count(b"\t") != 1:
            _reject()
        label_raw, encoded = line.split(b"\t", 1)
        try:
            label = label_raw.decode("ascii", "strict")
        except UnicodeDecodeError:
            _reject()
        if label not in _FIELDS or label in values:
            _reject()
        values[label] = _strict_b64(encoded)
    if tuple(values) != _FIELDS:
        _reject()
    return values


def _single_line(value: bytes, *, pattern: str) -> str:
    try:
        decoded = value.decode("utf-8", "strict").strip()
    except UnicodeDecodeError:
        _reject()
    if "\n" in decoded or "\r" in decoded or re.fullmatch(pattern, decoded) is None:
        _reject()
    return decoded


def _json_list(value: bytes) -> list[Any]:
    try:
        decoded = json.loads(value.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _reject()
    if type(decoded) is not list:
        _reject()
    return decoded


def _parse_config(value: bytes) -> None:
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _reject()
    if not text or any(ord(char) < 0x20 and char not in "\n" for char in text):
        _reject()
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ": " not in line:
            _reject()
        key, item = line.split(": ", 1)
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", key) is None or not item:
            _reject()
        fields.setdefault(key, []).append(item)
    if fields.get("name") != [VM_NAME]:
        _reject()
    if fields.get("net0") != [f"virtio={VM_MAC},bridge={VM_BRIDGE}"]:
        _reject()
    if fields.get("agent") != ["0"] or fields.get("onboot") != ["0"]:
        _reject()
    if "lock" in fields or any(key.startswith("net") and key != "net0" for key in fields):
        _reject()


def _parse_snapshots(value: bytes) -> None:
    try:
        lines = value.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        _reject()
    names: list[str] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2 or parts[0] != "`->":
            _reject()
        name = parts[1]
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) is None:
            _reject()
        names.append(name)
    if len(names) != 3 or set(names) != {*CANONICAL_SNAPSHOTS, "current"}:
        _reject()


def _parse_bridge_link(value: bytes) -> None:
    rows = _json_list(value)
    if len(rows) != 1 or type(rows[0]) is not dict:
        _reject()
    row = rows[0]
    flags = row.get("flags")
    linkinfo = row.get("linkinfo")
    if (
        row.get("ifname") != VM_BRIDGE
        or type(flags) is not list
        or "UP" not in flags
        or type(linkinfo) is not dict
        or linkinfo.get("info_kind") != "bridge"
    ):
        _reject()


def _parse_bridge_ports(value: bytes) -> None:
    rows = _json_list(value)
    names: set[str] = set()
    for row in rows:
        if type(row) is not dict or row.get("master") != VM_BRIDGE:
            _reject()
        name = row.get("ifname")
        if type(name) is not str or name not in _EXPECTED_BRIDGE_PORTS or name in names:
            _reject()
        names.add(name)
    if "tap1106i0" not in names:
        _reject()


def _parse_bridge_addresses(value: bytes) -> None:
    rows = _json_list(value)
    if len(rows) != 1 or type(rows[0]) is not dict or rows[0].get("ifname") != VM_BRIDGE:
        _reject()
    addresses = rows[0].get("addr_info", [])
    if type(addresses) is not list:
        _reject()
    for address in addresses:
        if type(address) is not dict:
            _reject()
        local = address.get("local")
        if (
            address.get("family") != "inet6"
            or address.get("scope") != "link"
            or type(local) is not str
            or not local.lower().startswith("fe80:")
        ):
            _reject()


def _parse_bridge_routes(value: bytes) -> None:
    rows = _json_list(value)
    for route in rows:
        if (
            type(route) is not dict
            or ("dev" in route and route.get("dev") != VM_BRIDGE)
            or "gateway" in route
        ):
            _reject()
        destination = route.get("dst")
        if (
            type(destination) is not str
            or not destination.lower().startswith(("fe80:", "ff00:"))
        ):
            _reject()


def parse_portcast_vm_preflight(raw: bytes) -> PortcastVmPreflightResult:
    """Validate the complete fixed Dell output and discard unrestricted text."""

    values = _parse_envelope(raw)
    if _single_line(values["hostname"], pattern=r"dell-prox") != "dell-prox":
        _reject()
    pve = _single_line(
        values["pveversion"],
        pattern=(
            r"pve-manager/[0-9]+[.][0-9]+[.][0-9]+/[A-Za-z0-9._-]+"
            r"(?: [(]running kernel: [0-9A-Za-z._+-]+[)])?"
        ),
    )
    status = _single_line(values["status"], pattern=r"status: (?:running|stopped)")
    if status != "status: running":
        _reject()
    _parse_config(values["config"])
    _parse_snapshots(values["snapshots"])
    _parse_bridge_link(values["bridge_link"])
    _parse_bridge_ports(values["bridge_ports"])
    _parse_bridge_addresses(values["bridge_addresses"])
    _parse_bridge_routes(values["bridge_routes"])
    if values["network_namespaces"].strip():
        _reject()
    process_count = _single_line(values["lifecycle_process_count"], pattern=r"[0-9]{1,3}")
    if process_count != "0":
        _reject()
    return PortcastVmPreflightResult("/".join(pve.split("/", 2)[:2]))


def _private_root(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise TransportError("PortCast VM preflight run root is unsafe")
    candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = candidate.resolve(strict=True)
    info = resolved.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise TransportError("PortCast VM preflight run root permissions are unsafe")
    return resolved


def _atomic_private(path: Path, payload: bytes) -> None:
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _raw_frame(status: int, stdout: bytes, stderr: bytes) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": 1,
                "remote_status": status,
                "stdout_base64": base64.b64encode(stdout).decode("ascii"),
                "stderr_base64": base64.b64encode(stderr).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _execute_fixed(connection: Any) -> tuple[int, bytes, bytes]:
    execute = getattr(connection, "_execute_script", None)
    if not callable(execute):
        raise TransportError("Dell connector lacks the fixed read-only execution path")
    result = execute(PORTCAST_VM_PREFLIGHT_SCRIPT, timeout=REMOTE_TIMEOUT_SECONDS)
    if (
        type(result) is not tuple
        or len(result) != 3
        or type(result[0]) is not int
        or type(result[1]) is not bytes
        or type(result[2]) is not bytes
    ):
        raise TransportError("Dell preflight capture shape differs")
    return result


def _run_portcast_vm_preflight(
    *,
    run_root: Path = _RUN_ROOT,
    connector: Any | None = None,
    encryptor: _Encryptor | None = None,
) -> dict[str, Any]:
    """Run the one fixed host-only preflight and return sanitized metadata."""

    root = _private_root(run_root)
    run = Path(tempfile.mkdtemp(prefix="portcast-vm-1106-", dir=root))
    run.chmod(0o700)
    transcript_path = run / "transcript.jsonl"
    descriptor = os.open(
        transcript_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    stream: TextIO = os.fdopen(descriptor, "w", encoding="utf-8")
    transcript = JsonlTranscript(stream)
    connection: Any | None = None
    try:
        transcript.emit("vm_preflight.start", phase="dell", status="starting")
        evidence_encryptor = encryptor or AgeEncryptor.default()
        dell_connector = connector or PinnedParamikoConnector()
        connection = dell_connector.connect(
            DEFAULT_CONFIG.dell,
            DEFAULT_CONFIG.dell_credential,
            transcript,
        )
        try:
            status, stdout, stderr = _execute_fixed(connection)
        finally:
            closing_connection = connection
            connection = None
            closing_connection.close()
        if len(stdout) > RAW_OUTPUT_CAP or len(stderr) > RAW_OUTPUT_CAP:
            raise TransportError("Dell preflight output exceeded its capture allowance")
        encrypted = evidence_encryptor.encrypt(_raw_frame(status, stdout, stderr))
        if not encrypted.startswith(b"age-encryption.org/v1"):
            raise TransportError("PortCast VM preflight evidence encryption failed")
        _atomic_private(run / _RAW_ARTIFACT, encrypted)
        transcript.emit(
            "vm_preflight.capture",
            phase="dell",
            status="passed",
            bytes=len(stdout) + len(stderr),
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            capture_complete=True,
        )
        if status != 0 or stderr:
            _reject("Dell read-only PortCast VM preflight command failed")
        result = parse_portcast_vm_preflight(stdout)
        rendered = (
            json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        _atomic_private(run / _RESULT_ARTIFACT, rendered)
        transcript.emit("vm_preflight.finish", phase="dell", status="passed")
        return {
            "status": "passed",
            "run_directory": str(run),
            "result": result.to_dict(),
        }
    except BaseException as error:
        transcript.emit(
            "vm_preflight.finish",
            phase="dell",
            status="failed",
            reason=type(error).__name__,
        )
        raise
    finally:
        try:
            if connection is not None:
                closing_connection = connection
                connection = None
                closing_connection.close()
        finally:
            stream.close()


def run_portcast_vm_preflight(
    *,
    run_root: Path = _RUN_ROOT,
    connector: Any | None = None,
    encryptor: _Encryptor | None = None,
) -> dict[str, Any]:
    """Run the fixed preflight and sanitize every dependency failure."""

    try:
        return _run_portcast_vm_preflight(
            run_root=run_root,
            connector=connector,
            encryptor=encryptor,
        )
    except BaseException:
        raise TransportError(_SAFE_FAILURE_MESSAGE) from None


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    connector: Any | None = None,
    encryptor: _Encryptor | None = None,
    run_root: Path = _RUN_ROOT,
) -> int:
    """CLI with no command or target arguments."""

    supplied = list(sys.argv[1:] if argv is None else argv)
    if supplied:
        raise SystemExit("portcast-vm-preflight accepts no arguments")
    try:
        result = run_portcast_vm_preflight(
            run_root=run_root,
            connector=connector,
            encryptor=encryptor,
        )
    except TransportError:
        print(
            json.dumps({"reason": _SAFE_FAILURE_MESSAGE, "status": "failed"}),
            file=stdout or sys.stdout,
        )
        return 2
    print(json.dumps(result, sort_keys=True), file=stdout or sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "CANONICAL_SNAPSHOTS",
    "PORTCAST_VM_PREFLIGHT_SCRIPT",
    "PortcastVmPreflightResult",
    "RAW_OUTPUT_CAP",
    "main",
    "parse_portcast_vm_preflight",
    "run_portcast_vm_preflight",
)
