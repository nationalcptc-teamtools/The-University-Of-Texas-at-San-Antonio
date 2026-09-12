"""Isolated owner of the fixed CPTC11 PortCast lab and wire operation."""

from __future__ import annotations

from array import array
import base64
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import fcntl
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import time

from cptc_harness.contracts import PolicyError, canonical_json
from cptc_harness.integrity import VerifiedRelease
from cptc_harness.memfd import (
    F_GET_SEALS,
    MFD_ALLOW_SEALING,
    MFD_CLOEXEC,
    READONLY_SEALS,
    memfd_create,
    seal_readonly,
    write_all,
)
from cptc_harness.profile_runtime.catalog import load_profile, require_live_admission
from cptc_harness.profile_runtime.contracts import WireCounters
from cptc_harness.profile_runtime.worker import WireExecutionError, capture_cleartext_http11


_MAX_PACKET = 64 * 1024
_PRODUCTION_LEDGER_ROOT = Path(
    "/var/lib/cptc-harness/portcast-live-v1/runtime/v5/ledger/cptc11-dell-validation-portcast-v5"
)
_BROKER_ROUTE = "100.85.84.30/32"
_FAILURE_STAGES = frozenset(
    {
        "session_open",
        "inventory",
        "alternate_destination_control",
        "deadline_before_target_open",
        "target_open",
        "connected_ack",
        "wire_exchange",
        "session_cleanup",
    }
)


def _empty_counters() -> WireCounters:
    return WireCounters(
        tcp_connects=0,
        udp_datagrams=0,
        tls_handshakes=0,
        protocol_requests=0,
        tx_bytes=0,
        rx_bytes=0,
        capture_bytes=0,
    )


def _assert_exact_worker_descriptors() -> None:
    inherited = []
    for name in os.listdir("/proc/self/fd"):
        try:
            descriptor = int(name)
        except ValueError:
            continue
        if descriptor < 3:
            continue
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        inherited.append(descriptor)
    if inherited:
        raise PolicyError("PortCast broker inherited an unexpected descriptor")


def _sandbox_attestation() -> dict[str, object]:
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
    cap_eff = status.get("CapEff")
    if cap_eff != "0000000000000000":
        raise PolicyError("PortCast broker effective capabilities differ")
    if Path.cwd() != _PRODUCTION_LEDGER_ROOT or not Path("/app/cptc_harness").is_dir():
        raise PolicyError("PortCast broker sandbox mounts differ")
    _assert_exact_worker_descriptors()
    return {
        "kind": "sandbox_ready",
        "cap_eff": cap_eff,
        "allowed_route": _BROKER_ROUTE,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _receive(channel: socket.socket) -> dict:
    raw = channel.recv(_MAX_PACKET + 1)
    if not raw or len(raw) > _MAX_PACKET:
        raise OSError("invalid PortCast broker request")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid PortCast broker request")
    return value


def _receive_credentials(channel: socket.socket) -> tuple[int, int]:
    raw, ancillary, flags, _address = channel.recvmsg(
        _MAX_PACKET + 1, socket.CMSG_SPACE(array("i", [0, 0]).itemsize)
    )
    descriptors: list[int] = []
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array("i")
            values.frombytes(data[: len(data) - len(data) % values.itemsize])
            descriptors.extend(values)
    try:
        value = json.loads(raw)
        if (
            not raw
            or len(raw) > _MAX_PACKET
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or value != {
                "method": "credentials",
                "names": ["cptc11-dell", "cptc11-kali"],
            }
            or len(descriptors) != 2
        ):
            raise ValueError()
        for descriptor in descriptors:
            info = os.fstat(descriptor)
            if (
                not 1 <= info.st_size <= 64 * 1024
                or fcntl.fcntl(descriptor, F_GET_SEALS) & READONLY_SEALS
                != READONLY_SEALS
            ):
                raise ValueError()
            os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptors[0], descriptors[1]
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        for descriptor in descriptors:
            os.close(descriptor)
        raise PolicyError("PortCast worker credentials differ") from None


def _send(channel: socket.socket, value: dict, descriptor: int | None = None) -> None:
    raw = canonical_json(value)
    if len(raw) > _MAX_PACKET:
        raise OSError("PortCast broker response exceeds allowance")
    ancillary = []
    if descriptor is not None:
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [descriptor]))]
    if channel.sendmsg([raw], ancillary) != len(raw):
        raise OSError("short PortCast broker response")


def _exact_binding(value: object, plan) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "engagement_id",
        "device_id",
        "action_id",
        "attempt_id",
        "profile_id",
        "runtime_pinset_sha256",
        "deadline_ns",
    }:
        raise PolicyError("PortCast worker reservation binding differs")
    if (
        value["engagement_id"] != plan.engagement_id
        or value["device_id"] != plan.device_id
        or value["action_id"] != plan.action_id
        or value["profile_id"] != plan.profile_id
        or value["runtime_pinset_sha256"] != plan.runtime_pinset_sha256
    ):
        raise PolicyError("PortCast worker reservation identity differs")
    database = Path.cwd() / "ledger.sqlite3"
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        reservation = connection.execute(
            """SELECT target,state FROM reservations
                 WHERE engagement=? AND device=? AND request_id=?""",
            (value["engagement_id"], value["device_id"], value["action_id"]),
        ).fetchone()
        attempt = connection.execute(
            """SELECT state,deadline_ns FROM reservation_attempts
                 WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?""",
            (
                value["engagement_id"],
                value["device_id"],
                value["action_id"],
                value["attempt_id"],
            ),
        ).fetchone()
    finally:
        connection.close()
    if (
        reservation != (plan.target_id, "running")
        or attempt != ("running", value["deadline_ns"])
        or type(value["deadline_ns"]) is not int
        or time.monotonic_ns() >= value["deadline_ns"]
    ):
        raise PolicyError("PortCast worker requires a committed running attempt")
    return value


class _AcknowledgedChannel:
    def __init__(self, channel, ipc: socket.socket, deadline_ns: int):
        self._channel = channel
        self._ipc = ipc
        self._deadline_ns = deadline_ns
        self._send_index = 0
        self._receive_index = 0
        self._request_recorded = False
        self.first_byte_at = None

    def _check_deadline(self) -> None:
        if time.monotonic_ns() >= self._deadline_ns:
            raise OSError("PortCast canonical deadline reached")

    def _event(self, event_id: str, **values: int) -> None:
        self._check_deadline()
        _send(
            self._ipc,
            {
                "kind": "event",
                "event_id": event_id,
                "tcp_connects": values.get("tcp_connects", 0),
                "udp_datagrams": 0,
                "protocol_requests": values.get("protocol_requests", 0),
                "tx_bytes": values.get("tx_bytes", 0),
                "rx_bytes": values.get("rx_bytes", 0),
                "first_byte_at": self.first_byte_at,
            },
        )
        self._check_deadline()
        acknowledgement = _receive(self._ipc)
        if acknowledgement != {"method": "ack", "event_id": event_id}:
            raise OSError("PortCast wire event was not durably acknowledged")
        self._check_deadline()

    def connected(self) -> None:
        self._event("connect-000000", tcp_connects=1)

    def settimeout(self, value: float) -> None:
        self._channel.settimeout(value)

    def send(self, value: memoryview) -> int:
        self._check_deadline()
        count = self._channel.send(value)
        self._check_deadline()
        if type(count) is int and count > 0:
            self._send_index += 1
            event = {"tx_bytes": count}
            if not self._request_recorded:
                event["protocol_requests"] = 1
                self._request_recorded = True
            self._event(f"send-{self._send_index:06d}", **event)
        return count

    def recv(self, maximum: int) -> bytes:
        self._check_deadline()
        value = self._channel.recv(maximum)
        self._check_deadline()
        if isinstance(value, bytes) and value:
            if self.first_byte_at is None:
                self.first_byte_at = _utc_now()
            self._receive_index += 1
            self._event(f"recv-{self._receive_index:06d}", rx_bytes=len(value))
        return value

    def close(self) -> None:
        self._channel.close()


def _execute(
    ipc: socket.socket,
    profile,
    deadline_ns: int,
    credential_fds: tuple[int, int],
) -> tuple[dict, int]:
    from testing.cptc11_lab.transport import LabSession

    session = LabSession._for_portcast_service(credential_fds)
    raw = b""
    outcome = "uncertain"
    limitation = "transport_interrupted"
    first_byte_at = None
    counters = _empty_counters()
    failure_stage: str | None = None
    stage = "session_open"
    channel: _AcknowledgedChannel | None = None
    capture_started = False
    try:
        session.open()
        stage = "inventory"
        session.preflight_portcast_inventory()
        stage = "alternate_destination_control"
        if session.verify_portcast_alternate_destination_denied() is not True:
            raise PolicyError("PortCast alternate destination control differs")
        stage = "deadline_before_target_open"
        if time.monotonic_ns() >= deadline_ns:
            raise PolicyError("PortCast canonical deadline reached before target open")
        stage = "target_open"
        channel = _AcknowledgedChannel(
            session._open_portcast_channel(),
            ipc,
            deadline_ns,
        )
        stage = "connected_ack"
        channel.connected()
        try:
            stage = "wire_exchange"
            capture_started = True
            capture = capture_cleartext_http11(profile, channel)
            raw = capture.raw_response
            counters = capture.counters
            first_byte_at = channel.first_byte_at
            outcome = "complete" if raw and first_byte_at is not None else "uncertain"
            limitation = None if outcome == "complete" else "unexpected_response"
        except WireExecutionError as error:
            raw = error.raw_response
            counters = error.counters
            first_byte_at = channel.first_byte_at
            outcome = "uncertain"
            limitation = error.limitation
            failure_stage = "wire_exchange"
    except BaseException:
        failure_stage = stage
    finally:
        if channel is not None and not capture_started:
            try:
                channel.close()
            except BaseException:
                pass
        try:
            session.close()
        except BaseException:
            outcome = "uncertain"
            limitation = "transport_interrupted"
            failure_stage = "session_cleanup"
    if failure_stage is not None and failure_stage not in _FAILURE_STAGES:
        raise PolicyError("PortCast worker failure stage differs")
    descriptor = memfd_create("portcast-evidence", MFD_CLOEXEC | MFD_ALLOW_SEALING)
    try:
        write_all(descriptor, raw)
        os.lseek(descriptor, 0, os.SEEK_SET)
        seal_readonly(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    result = {
        "kind": "result",
        "outcome": outcome,
        "limitation": limitation,
        "first_byte_at": first_byte_at,
        "evidence_bytes": len(raw),
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "counters": counters.as_dict(),
    }
    if failure_stage is not None:
        result["failure_stage"] = failure_stage
    return result, descriptor


def main(*, verified_release: VerifiedRelease | None = None) -> int:
    ipc = socket.socket(fileno=0)
    descriptor = None
    credential_fds: tuple[int, int] = ()
    try:
        if os.geteuid() != 0:
            raise PolicyError("PortCast worker requires the canonical service identity")
        if Path.cwd() != _PRODUCTION_LEDGER_ROOT:
            raise PolicyError("PortCast worker canonical state root differs")
        if type(verified_release) is not VerifiedRelease:
            raise PolicyError("PortCast worker verified release is unavailable")
        from testing.cptc11_lab.portcast_live import (
            load_frozen_portcast_plan,
            validate_current_release,
        )

        plan = load_frozen_portcast_plan()
        if validate_current_release(plan) != verified_release:
            raise PolicyError("PortCast worker release verification differs")
        _send(ipc, _sandbox_attestation())
        credential_fds = _receive_credentials(ipc)
        request = _receive(ipc)
        if set(request) != {"method", "binding"} or request["method"] != "bind":
            raise PolicyError("PortCast worker requires reservation binding first")
        binding = _exact_binding(request["binding"], plan)
        nonce = secrets.token_bytes(32)
        expires_ns = min(
            time.monotonic_ns() + 30_000_000_000,
            binding["deadline_ns"],
        )
        _send(
            ipc,
            {
                "kind": "nonce",
                "value": base64.b64encode(nonce).decode("ascii"),
                "expires_ns": expires_ns,
            },
        )
        request = _receive(ipc)
        if (
            set(request) != {"method", "nonce", "expires_ns"}
            or request["method"] != "execute"
            or request["expires_ns"] != expires_ns
            or time.monotonic_ns() >= expires_ns
            or time.monotonic_ns() >= binding["deadline_ns"]
            or base64.b64decode(request["nonce"], validate=True) != nonce
        ):
            raise PolicyError("PortCast worker dispatch nonce differs")
        nonce = b""
        profile = require_live_admission(load_profile(plan.profile_id))
        response, descriptor = _execute(
            ipc, profile, binding["deadline_ns"], credential_fds
        )
        _send(ipc, response, descriptor)
        return 0
    except BaseException:
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for credential_fd in credential_fds:
            os.close(credential_fd)
        ipc.close()


if __name__ == "__main__":
    raise SystemExit(main())
