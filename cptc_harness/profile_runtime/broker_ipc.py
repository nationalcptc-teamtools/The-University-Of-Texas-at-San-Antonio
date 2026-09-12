"""Closed reservation-bound IPC client for the isolated PortCast broker."""

from __future__ import annotations

from array import array
from dataclasses import asdict, dataclass
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
from typing import Any, Callable

from ..audit_control import _request_stop
from ..contracts import PolicyError, canonical_json
from ..integrity import VerifiedRelease
from ..memfd import F_GET_SEALS, READONLY_SEALS
from .catalog import load_profile, require_live_admission
from .contracts import (
    PORTCAST_FAILURE_STAGES,
    PORTCAST_RESULT_LIMITATIONS,
    ProfileContractError,
    WireCounters,
)


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PROFILE_ID = "web.http_jellyfin_public_identity"
_TARGET_ID = "cptc11-prod-portcast"
_MAX_PACKET = 64 * 1024
_PRODUCTION_LEDGER_ROOT = Path(
    "/var/lib/cptc-harness/portcast-live-v1/runtime/v5/ledger/cptc11-dell-validation-portcast-v5"
)
_SERVICE_AUTHORITY = object()


@dataclass(frozen=True, slots=True)
class ReservationBinding:
    engagement_id: str
    device_id: str
    action_id: str
    attempt_id: str
    profile_id: str
    runtime_pinset_sha256: str
    deadline_ns: int


@dataclass(frozen=True, slots=True)
class DispatchNonce:
    value: bytes
    expires_ns: int


@dataclass(frozen=True, slots=True)
class BrokerWireEvent:
    event_id: str
    tcp_connects: int
    udp_datagrams: int
    protocol_requests: int
    tx_bytes: int
    rx_bytes: int
    first_byte_at: str | None

    def ledger_values(self) -> dict[str, int]:
        return {
            key: value
            for key, value in (
                ("tcp_connects", self.tcp_connects),
                ("udp_datagrams", self.udp_datagrams),
                ("protocol_requests", self.protocol_requests),
                ("tx_bytes", self.tx_bytes),
                ("rx_bytes", self.rx_bytes),
            )
            if value
        }


@dataclass(frozen=True, slots=True)
class BrokerWireResult:
    outcome: str
    limitation: str | None
    counters: WireCounters
    evidence_fd: int
    evidence_bytes: int
    evidence_sha256: str
    first_byte_at: str | None
    worker_sha256: str
    failure_stage: str | None = None


class PortcastBrokerFailure(PolicyError):
    """Safe broker failure with one fixed, non-sensitive execution stage."""

    def __init__(self, failure_stage: str, message: str) -> None:
        if failure_stage not in PORTCAST_FAILURE_STAGES:
            failure_stage = "ipc"
        super().__init__(message)
        self.failure_stage = failure_stage


def _validate_binding(binding: Any) -> ReservationBinding:
    if type(binding) is not ReservationBinding:
        raise PolicyError("PortCast reservation binding is unavailable")
    for name in ("engagement_id", "device_id", "action_id", "attempt_id", "profile_id"):
        if _ID.fullmatch(getattr(binding, name)) is None:
            raise PolicyError("PortCast reservation binding is invalid")
    if _HEX64.fullmatch(binding.runtime_pinset_sha256) is None:
        raise PolicyError("PortCast reservation binding is invalid")
    if type(binding.deadline_ns) is not int or binding.deadline_ns <= 0:
        raise PolicyError("PortCast reservation deadline is invalid")
    profile = require_live_admission(load_profile(binding.profile_id))
    if (
        binding.profile_id != _PROFILE_ID
        or profile.target_id != _TARGET_ID
        or binding.runtime_pinset_sha256 != profile.runtime_pinset_sha256
    ):
        raise PolicyError("PortCast reservation binding differs")
    return binding


class PortcastBrokerClient:
    """Own one broker process and expose no transport object or target input."""

    def __init__(
        self,
        ledger: Any,
        verified_release: VerifiedRelease,
        *,
        _authority: object | None = None,
        _credential_fds: tuple[int, int] | None = None,
    ) -> None:
        effective_uid = os.geteuid()
        effective_gid = os.getegid()
        if (
            _authority is not _SERVICE_AUTHORITY
            or effective_uid in {0, 65534}
            or effective_gid in {0, 65534}
            or set(os.getgroups()) != {effective_gid}
        ):
            raise PolicyError(
                "PortCast worker authority belongs to the canonical local service"
            )
        if _credential_fds is None or len(_credential_fds) != 2:
            raise PolicyError("PortCast service credentials are unavailable")
        self._initialize(ledger, verified_release, credential_fds=_credential_fds)

    def _initialize_for_test(
        self, ledger: Any, verified_release: VerifiedRelease
    ) -> None:
        self._initialize(ledger, verified_release)

    @property
    def expected_worker_sha256(self) -> str:
        return self._worker_sha256

    @property
    def uncertainty_reconciliation_required(self) -> bool:
        return self._uncertainty_reconciliation_required

    def _initialize(
        self,
        ledger: Any,
        verified_release: VerifiedRelease,
        *,
        credential_fds: tuple[int, int] | None = None,
    ) -> None:
        if type(verified_release) is not VerifiedRelease:
            raise PolicyError("verified PortCast release is required")
        try:
            current = verified_release.current_profile_workers[_PROFILE_ID]
        except (KeyError, TypeError):
            raise PolicyError("verified PortCast worker pin is unavailable") from None
        if _HEX64.fullmatch(current) is None:
            raise PolicyError("verified PortCast worker pin is invalid")
        if not hasattr(ledger, "_db") or not isinstance(getattr(ledger, "path", None), Path):
            raise PolicyError("durable Ledger is required by the PortCast broker")
        self._ledger = ledger
        self._release = verified_release
        self._worker_sha256 = current
        self._channel: socket.socket | None = None
        self._process: subprocess.Popen | None = None
        self._binding: ReservationBinding | None = None
        self._issued: DispatchNonce | None = None
        self._consumed = False
        self._inflight = False
        self._closed = False
        self._uncertainty_reconciliation_required = False
        self._credential_fds: tuple[int, ...] = ()
        if credential_fds is not None:
            duplicates: list[int] = []
            try:
                for descriptor in credential_fds:
                    info = os.fstat(descriptor)
                    if (
                        not stat_is_regular(info.st_mode)
                        or not 1 <= info.st_size <= 64 * 1024
                        or fcntl.fcntl(descriptor, F_GET_SEALS) & READONLY_SEALS
                        != READONLY_SEALS
                    ):
                        raise OSError()
                    duplicates.append(os.dup(descriptor))
                self._credential_fds = tuple(duplicates)
            except OSError:
                for descriptor in duplicates:
                    os.close(descriptor)
                raise PolicyError("PortCast service credentials are not sealed") from None

    @classmethod
    def _from_connected_socket(
        cls, ledger: Any, verified_release: VerifiedRelease, channel: socket.socket
    ) -> "PortcastBrokerClient":
        client = object.__new__(cls)
        client._initialize(ledger, verified_release)
        if not isinstance(channel, socket.socket) or channel.type & socket.SOCK_SEQPACKET == 0:
            raise PolicyError("PortCast broker IPC socket differs")
        client._channel = channel
        client._channel.settimeout(30)
        return client

    def _verify_reservation(self, binding: ReservationBinding) -> None:
        if (
            binding.engagement_id != self._ledger.engagement_id
            or binding.device_id != self._ledger.device_id
        ):
            raise PolicyError("PortCast reservation identity differs")
        reservation = self._ledger._db.execute(
            """SELECT target,state FROM reservations
                 WHERE engagement=? AND device=? AND request_id=?""",
            (binding.engagement_id, binding.device_id, binding.action_id),
        ).fetchone()
        attempt = self._ledger._db.execute(
            """SELECT state,deadline_ns FROM reservation_attempts
                 WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?""",
            (
                binding.engagement_id,
                binding.device_id,
                binding.action_id,
                binding.attempt_id,
            ),
        ).fetchone()
        if (
            reservation != (_TARGET_ID, "running")
            or attempt != ("running", binding.deadline_ns)
            or time.monotonic_ns() >= binding.deadline_ns
        ):
            raise PolicyError("PortCast broker requires an exact running reservation")

    def _start(self) -> None:
        if self._channel is not None:
            return
        parent = child = None
        process = None
        try:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            parent.settimeout(30)
            command = [
                str(self._release.launcher_path),
                "--broker-worker",
            ]
            process = subprocess.Popen(
                command,
                stdin=child,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                env={},
                cwd=self._ledger.root,
                start_new_session=True,
            )
            child.close()
            child = None
            self._channel = parent
            parent = None
            self._process = process
            process = None
            ready, descriptors = self._receive()
            if descriptors:
                for descriptor in descriptors:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                raise PolicyError("PortCast broker sandbox attestation differs")
            if ready != {
                "kind": "sandbox_ready",
                "cap_eff": "0000000000000000",
                "allowed_route": "100.85.84.30/32",
            }:
                raise PolicyError("PortCast broker sandbox attestation differs")
            self._send_with_descriptors(
                {"method": "credentials", "names": ["cptc11-dell", "cptc11-kali"]},
                self._credential_fds,
            )
            for descriptor in self._credential_fds:
                os.close(descriptor)
            self._credential_fds = ()
        except Exception:
            for resource in (parent, child):
                if resource is not None:
                    resource.close()
            if process is not None:
                process.kill()
                process.wait()
            if self._channel is not None:
                self._channel.close()
                self._channel = None
            if self._process is not None:
                try:
                    os.killpg(self._process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
                self._process.wait()
                self._process = None
            raise PolicyError("isolated PortCast broker could not start") from None

    def _send(self, value: dict[str, Any]) -> None:
        if self._channel is None:
            raise OSError("PortCast broker IPC is unavailable")
        raw = canonical_json(value)
        if len(raw) > _MAX_PACKET:
            raise PolicyError("PortCast broker IPC packet exceeds allowance")
        sent = self._channel.send(raw)
        if sent != len(raw):
            raise OSError("short PortCast broker IPC packet")

    def _send_with_descriptors(
        self, value: dict[str, Any], descriptors: tuple[int, ...]
    ) -> None:
        if self._channel is None or not descriptors:
            raise OSError("PortCast broker credential IPC is unavailable")
        raw = canonical_json(value)
        ancillary = [
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", descriptors))
        ]
        if self._channel.sendmsg([raw], ancillary) != len(raw):
            raise OSError("short PortCast broker credential IPC packet")

    def _receive(self) -> tuple[dict[str, Any], tuple[int, ...]]:
        if self._channel is None:
            raise OSError("PortCast broker IPC is unavailable")
        raw, ancillary, flags, _address = self._channel.recvmsg(
            _MAX_PACKET + 1, socket.CMSG_SPACE(array("i", [0]).itemsize)
        )
        if not raw or len(raw) > _MAX_PACKET or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise OSError("invalid PortCast broker IPC packet")
        descriptors: list[int] = []
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array("i")
                values.frombytes(data[: len(data) - len(data) % values.itemsize])
                descriptors.extend(values)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            for descriptor in descriptors:
                os.close(descriptor)
            raise OSError("invalid PortCast broker IPC JSON") from None
        if not isinstance(value, dict):
            for descriptor in descriptors:
                os.close(descriptor)
            raise OSError("invalid PortCast broker IPC value")
        return value, tuple(descriptors)

    def bind_reserved_attempt(self, binding: ReservationBinding) -> DispatchNonce:
        if self._closed or self._binding is not None or self._consumed:
            raise PolicyError("PortCast broker binding is unavailable")
        exact = _validate_binding(binding)
        self._verify_reservation(exact)
        self._start()
        try:
            self._send({"method": "bind", "binding": asdict(exact)})
            value, descriptors = self._receive()
            if descriptors:
                for descriptor in descriptors:
                    os.close(descriptor)
                raise OSError("unexpected descriptor in PortCast bind response")
            nonce = DispatchNonce(
                base64.b64decode(value.get("value", ""), validate=True),
                value.get("expires_ns"),
            )
            now = time.monotonic_ns()
            if (
                value.get("kind") != "nonce"
                or len(nonce.value) != 32
                or type(nonce.expires_ns) is not int
                or not now < nonce.expires_ns <= now + 30_000_000_000
                or nonce.expires_ns > exact.deadline_ns
            ):
                raise ValueError()
        except (OSError, ValueError, TypeError):
            self.close()
            raise PolicyError("PortCast broker reservation binding failed") from None
        self._binding = exact
        self._issued = nonce
        return nonce

    def execute_once(
        self,
        nonce: DispatchNonce,
        record_event: Callable[[BrokerWireEvent], Any],
        stopped: Callable[[], bool],
    ) -> BrokerWireResult:
        if not callable(record_event) or not callable(stopped):
            raise PolicyError("PortCast broker acknowledgements are unavailable")
        now = time.monotonic_ns()
        if (
            self._closed
            or type(nonce) is not DispatchNonce
            or self._issued is None
            or nonce != self._issued
            or self._consumed
            or now >= nonce.expires_ns
            or stopped()
        ):
            raise PolicyError("PortCast dispatch nonce is invalid, expired, or consumed")
        self._issued = None
        self._consumed = True
        self._inflight = True
        binding = self._binding
        if binding is None:
            raise PolicyError("PortCast broker reservation binding is unavailable")

        def before_deadline() -> None:
            if time.monotonic_ns() >= binding.deadline_ns:
                raise OSError("PortCast canonical deadline reached")

        failure_stage = "ipc"
        try:
            before_deadline()
            self._send(
                {
                    "method": "execute",
                    "nonce": base64.b64encode(nonce.value).decode("ascii"),
                    "expires_ns": nonce.expires_ns,
                }
            )
            while True:
                before_deadline()
                value, descriptors = self._receive()
                try:
                    before_deadline()
                except OSError:
                    for descriptor in descriptors:
                        os.close(descriptor)
                    raise
                if value.get("kind") == "event":
                    failure_stage = (
                        "connected_ack"
                        if value.get("event_id") == "connect-000000"
                        else "wire_exchange"
                    )
                    if descriptors:
                        for descriptor in descriptors:
                            os.close(descriptor)
                        raise OSError("wire event returned a descriptor")
                    event = BrokerWireEvent(
                        event_id=value.get("event_id"),
                        tcp_connects=value.get("tcp_connects"),
                        udp_datagrams=value.get("udp_datagrams"),
                        protocol_requests=value.get("protocol_requests"),
                        tx_bytes=value.get("tx_bytes"),
                        rx_bytes=value.get("rx_bytes"),
                        first_byte_at=value.get("first_byte_at"),
                    )
                    if (
                        _ID.fullmatch(event.event_id) is None
                        or any(
                            type(item) is not int or not 0 <= item <= 65536
                            for item in (
                                event.tcp_connects,
                                event.udp_datagrams,
                                event.protocol_requests,
                                event.tx_bytes,
                                event.rx_bytes,
                            )
                        )
                        or not event.ledger_values()
                        or stopped()
                    ):
                        raise OSError("invalid or stopped PortCast wire event")
                    before_deadline()
                    record_event(event)
                    before_deadline()
                    self._send({"method": "ack", "event_id": event.event_id})
                    before_deadline()
                    continue
                if value.get("kind") != "result" or len(descriptors) != 1:
                    for descriptor in descriptors:
                        os.close(descriptor)
                    raise OSError("invalid PortCast broker result")
                descriptor = descriptors[0]
                failure_stage = "ipc"
                try:
                    required_fields = {
                        "kind",
                        "outcome",
                        "limitation",
                        "first_byte_at",
                        "evidence_bytes",
                        "evidence_sha256",
                        "counters",
                    }
                    allowed_fields = required_fields | {"failure_stage"}
                    outcome = value.get("outcome")
                    limitation = value.get("limitation")
                    worker_stage = value.get("failure_stage")
                    if (
                        not required_fields <= set(value)
                        or set(value) - allowed_fields
                        or outcome
                        not in {"complete", "incomplete", "uncertain", "cancelled"}
                        or limitation is not None
                        and limitation not in PORTCAST_RESULT_LIMITATIONS
                        or worker_stage is not None
                        and worker_stage not in PORTCAST_FAILURE_STAGES
                        or outcome == "complete"
                        and (limitation is not None or worker_stage is not None)
                    ):
                        raise ValueError()
                    counters = WireCounters.from_dict(value.get("counters"))
                    failure_stage = "evidence_seal"
                    info = os.fstat(descriptor)
                    if (
                        not stat_is_regular(info.st_mode)
                        or fcntl.fcntl(descriptor, F_GET_SEALS) & READONLY_SEALS
                        != READONLY_SEALS
                        or type(value.get("evidence_bytes")) is not int
                        or info.st_size != value["evidence_bytes"]
                        or _HEX64.fullmatch(value.get("evidence_sha256", "")) is None
                    ):
                        raise ValueError()
                    os.lseek(descriptor, 0, os.SEEK_SET)
                except (OSError, ValueError, TypeError, ProfileContractError):
                    os.close(descriptor)
                    raise OSError("invalid sealed PortCast evidence descriptor") from None
                self._inflight = False
                return BrokerWireResult(
                    value["outcome"],
                    value.get("limitation"),
                    counters,
                    descriptor,
                    value["evidence_bytes"],
                    value["evidence_sha256"],
                    value.get("first_byte_at"),
                    self._worker_sha256,
                    value.get("failure_stage"),
                )
        except Exception:
            durable = self._mark_uncertain()
            detail = (
                "PortCast broker outcome is uncertain; automatic retry prohibited"
                if durable
                else "PortCast broker outcome is uncertain; durable stop is latched and reconciliation is required"
            )
            raise PortcastBrokerFailure(failure_stage, detail) from None

    def _mark_uncertain(self) -> bool:
        binding = self._binding
        self._inflight = False
        if binding is None:
            return True
        attempt_persisted = False
        reservation_persisted = False
        try:
            self._ledger.finish_attempt(
                binding.action_id,
                binding.attempt_id,
                state="uncertain",
                ended_ns=time.monotonic_ns(),
            )
            attempt_persisted = True
        except Exception:
            pass
        try:
            usage = self._ledger.attempt_receipt(binding.action_id)["usage"]
            self._ledger.finish(binding.action_id, usage, state="uncertain")
            reservation_persisted = True
        except Exception:
            pass
        stop_persisted = False
        correlation_id = hashlib.sha256(
            (
                "portcast-transport-uncertainty|"
                + binding.engagement_id
                + "|"
                + binding.device_id
                + "|"
                + binding.action_id
                + "|"
                + binding.attempt_id
            ).encode("utf-8")
        ).hexdigest()
        try:
            receipt = _request_stop(
                self._ledger.root,
                binding.engagement_id,
                binding.device_id,
                "system",
                interface="internal",
                source="system",
                reason="transport_uncertainty",
                correlation_id=correlation_id,
                ledger=self._ledger,
            )
            stop_persisted = receipt.get("stopped") is True
        except Exception:
            try:
                self._ledger.stop("isolated PortCast broker outcome uncertain")
                stop_persisted = True
            except Exception:
                stop_persisted = False
        self._uncertainty_reconciliation_required = not (
            attempt_persisted and reservation_persisted
        )
        if not stop_persisted:
            self._uncertainty_reconciliation_required = True
            raise PolicyError(
                "PortCast durable uncertainty state is unavailable; process restart and ledger recovery are required"
            )
        return not self._uncertainty_reconciliation_required

    def close(self) -> None:
        if self._closed:
            return
        failures: list[str] = []
        try:
            if self._inflight:
                try:
                    if not self._mark_uncertain():
                        self._uncertainty_reconciliation_required = True
                        failures.append("uncertainty persistence")
                except Exception:
                    self._uncertainty_reconciliation_required = True
                    failures.append("uncertainty persistence")
        finally:
            # Teardown is unconditional. A failed durable checkpoint must not
            # leave the worker, IPC socket, or credential capabilities live.
            self._closed = True
            self._inflight = False
            channel = self._channel
            self._channel = None
            if channel is not None:
                try:
                    channel.close()
                except OSError:
                    failures.append("IPC socket close")
            process = self._process
            self._process = None
            if process is not None:
                try:
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except (OSError, ProcessLookupError):
                            failures.append("broker process-group kill")
                            try:
                                process.kill()
                            except (OSError, ProcessLookupError):
                                failures.append("broker process kill")
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    failures.append("broker process reap")
            credentials = self._credential_fds
            self._credential_fds = ()
            for descriptor in credentials:
                try:
                    os.close(descriptor)
                except OSError:
                    failures.append("credential descriptor close")
        if failures:
            if "uncertainty persistence" not in failures:
                try:
                    self._mark_uncertain()
                except Exception:
                    self._uncertainty_reconciliation_required = True
            raise PolicyError("PortCast broker cleanup failed; reconciliation required")


def stat_is_regular(mode: int) -> bool:
    import stat

    return stat.S_ISREG(mode)


def _service_wire_broker_factory(
    ledger: Any,
    verified_release: VerifiedRelease,
    *,
    credential_fds: tuple[int, int],
) -> PortcastBrokerClient:
    """Root-service-only construction boundary; never used by application APIs."""

    if getattr(ledger, "root", None) != _PRODUCTION_LEDGER_ROOT:
        raise PolicyError("canonical PortCast Ledger root differs")
    return PortcastBrokerClient(
        ledger,
        verified_release,
        _authority=_SERVICE_AUTHORITY,
        _credential_fds=credential_fds,
    )


__all__ = (
    "BrokerWireEvent",
    "BrokerWireResult",
    "DispatchNonce",
    "PortcastBrokerFailure",
    "PortcastBrokerClient",
    "ReservationBinding",
)
