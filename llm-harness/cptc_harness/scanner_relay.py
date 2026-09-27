"""Deterministic in-memory foundation for a future parent-owned relay."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import math
import time
from typing import Callable, Iterable

from .scanner_protocols import ExtraRequest, HTTPGetRootValidator, MalformedMessage, SMBRelayValidator


@dataclass(frozen=True, slots=True)
class RelayLimits:
    tcp_connects: int
    udp_datagrams: int
    protocol_requests: int
    tx_bytes: int
    rx_bytes: int
    timeout_s: float
    cpu_s: float
    output_bytes: int
    process_limit: int
    auth_attempts: int

    def __post_init__(self) -> None:
        integer_fields = (
            "tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes",
            "rx_bytes", "output_bytes", "process_limit", "auth_attempts",
        )
        if any(type(getattr(self, name)) is not int or not 0 <= getattr(self, name) <= 2_147_483_647
               for name in integer_fields):
            raise ValueError("relay limits are invalid")
        if (isinstance(self.timeout_s, bool) or not isinstance(self.timeout_s, (int, float))
                or not math.isfinite(self.timeout_s) or self.timeout_s <= 0
                or isinstance(self.cpu_s, bool) or not isinstance(self.cpu_s, (int, float))
                or not math.isfinite(self.cpu_s) or self.cpu_s <= 0):
            raise ValueError("relay deadlines are invalid")


@dataclass(frozen=True, slots=True)
class RelayReceipt:
    status: str
    reason: str
    tcp_connects: int
    udp_datagrams: int
    protocol_requests: int
    tx_bytes: int
    rx_bytes: int

    def canonical_bytes(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class RelayResult:
    receipt: RelayReceipt
    forwarded_tcp: tuple[bytes, ...] = ()
    forwarded_udp: tuple[bytes, ...] = ()
    accepted_tcp: tuple[bytes, ...] = ()
    accepted_udp: tuple[bytes, ...] = ()


class _Stop(Exception):
    pass


class _Deadline(Exception):
    pass


class _Limit(Exception):
    pass


class _MissingResponse(Exception):
    pass


class ParentRelay:
    """Validate and account parent-provided bytes without opening a socket."""

    def __init__(self, host: str, port: int, validator: HTTPGetRootValidator | SMBRelayValidator,
                 limits: RelayLimits, *, clock: Callable[[], float] = time.monotonic,
                 cpu_clock: Callable[[], float] = time.process_time,
                 stopped: Callable[[], bool] = lambda: False) -> None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("relay requires one numeric loopback IPv4 endpoint") from None
        if address.version != 4 or not address.is_loopback or type(port) is not int:
            raise ValueError("relay requires one numeric loopback IPv4 endpoint")
        if not isinstance(validator, (HTTPGetRootValidator, SMBRelayValidator)):
            raise TypeError("relay requires a reviewed protocol validator")
        if str(address) != validator.host or port != validator.port:
            raise ValueError("relay and validator endpoints differ")
        if not isinstance(limits, RelayLimits):
            raise TypeError("relay requires typed limits")
        self.host, self.port = str(address), port
        self.validator, self.limits = validator, limits
        self._clock, self._cpu_clock, self._stopped = clock, cpu_clock, stopped
        self._terminal: RelayResult | None = None

    @staticmethod
    def _chunks(values: Iterable[bytes]) -> tuple[bytes, ...]:
        try:
            chunks = tuple(values)
        except Exception:
            raise MalformedMessage("relay chunks are malformed") from None
        if any(type(item) is not bytes or not item for item in chunks):
            raise MalformedMessage("relay chunks must be non-empty bytes")
        return chunks

    def _check(self, started: float, cpu_started: float) -> None:
        if self._stopped():
            raise _Stop()
        if self._clock() - started >= self.limits.timeout_s:
            raise _Deadline()
        if self._cpu_clock() - cpu_started >= self.limits.cpu_s:
            raise _Deadline()

    def _runtime_preflight(self) -> None:
        if self.limits.process_limit != 1 or self.limits.auth_attempts != 0:
            raise _Limit()

    @staticmethod
    def _status(exc: Exception, traffic: bool) -> tuple[str, str]:
        if isinstance(exc, _Stop):
            return ("uncertain" if traffic else "stopped", "operator stop")
        if isinstance(exc, _Deadline):
            return ("uncertain" if traffic else "blocked", "deadline exceeded")
        if isinstance(exc, ExtraRequest):
            return ("uncertain" if traffic else "blocked", "extra protocol request")
        if isinstance(exc, MalformedMessage):
            return ("uncertain" if traffic else "blocked", str(exc) or "protocol message malformed")
        if isinstance(exc, _MissingResponse):
            return ("uncertain" if traffic else "blocked", "required protocol response is missing")
        return ("uncertain" if traffic else "blocked", "transport limit exceeded")

    def _result(self, status: str, reason: str, *, tcp_connects: int = 0,
                udp_datagrams: int = 0, protocol_requests: int = 0,
                tx_bytes: int = 0, rx_bytes: int = 0,
                forwarded_tcp: tuple[bytes, ...] = (), forwarded_udp: tuple[bytes, ...] = (),
                accepted_tcp: tuple[bytes, ...] = (), accepted_udp: tuple[bytes, ...] = ()) -> RelayResult:
        receipt = RelayReceipt(status, reason, tcp_connects, udp_datagrams,
                               protocol_requests, tx_bytes, rx_bytes)
        return RelayResult(receipt, forwarded_tcp, forwarded_udp, accepted_tcp, accepted_udp)

    def _finish(self, result: RelayResult) -> RelayResult:
        self._terminal = result
        return result

    def _closed(self) -> RelayResult | None:
        if self._terminal is None:
            return None
        old = self._terminal.receipt
        return self._result(
            "blocked", "compound action already sealed",
            tcp_connects=old.tcp_connects,
            udp_datagrams=old.udp_datagrams,
            protocol_requests=old.protocol_requests,
            tx_bytes=old.tx_bytes,
            rx_bytes=old.rx_bytes,
        )

    def relay_tcp(self, outbound_chunks: Iterable[bytes], inbound_chunks: Iterable[bytes] = ()) -> RelayResult:
        """Validate one fixed HTTP exchange and permanently close this relay."""
        if (closed := self._closed()) is not None:
            return closed
        forwarded: tuple[bytes, ...] = ()
        accepted: list[bytes] = []
        connects = tx_bytes = rx_bytes = 0
        try:
            started, cpu_started = self._clock(), self._cpu_clock()
            if not isinstance(self.validator, HTTPGetRootValidator):
                raise MalformedMessage("SMB requires one compound relay action")
            outbound, inbound = self._chunks(outbound_chunks), self._chunks(inbound_chunks)
            self._runtime_preflight()
            if (not outbound or self.limits.tcp_connects < 1
                    or sum(map(len, outbound)) > self.limits.tx_bytes):
                raise _Limit()
            self._check(started, cpu_started)
            for chunk in outbound:
                self._check(started, cpu_started)
                self.validator.feed(chunk)
            self.validator.finish()
            if self.validator.protocol_requests != 1 or self.validator.protocol_requests > self.limits.protocol_requests:
                raise _Limit()
            self._check(started, cpu_started)
            connects = 1
            forwarded = outbound
            tx_bytes = sum(map(len, outbound))
            if not inbound:
                raise _MissingResponse()
            for chunk in inbound:
                self._check(started, cpu_started)
                rx_bytes += len(chunk)
                if rx_bytes > self.limits.rx_bytes or rx_bytes > self.limits.output_bytes:
                    raise _Limit()
                accepted.append(chunk)
            return self._finish(self._result(
                "complete", "complete", tcp_connects=connects,
                protocol_requests=self.validator.protocol_requests,
                tx_bytes=tx_bytes, rx_bytes=rx_bytes,
                forwarded_tcp=forwarded, accepted_tcp=tuple(accepted),
            ))
        except (ExtraRequest, MalformedMessage, _Stop, _Deadline, _Limit, _MissingResponse) as exc:
            status, reason = self._status(exc, bool(forwarded or accepted))
            return self._finish(self._result(
                status, reason, tcp_connects=connects,
                protocol_requests=self.validator.protocol_requests,
                tx_bytes=tx_bytes, rx_bytes=rx_bytes,
                forwarded_tcp=forwarded, accepted_tcp=tuple(accepted),
            ))
        except Exception:
            return self._finish(self._result(
                "uncertain" if forwarded or accepted else "blocked",
                "relay infrastructure failure",
                tcp_connects=connects,
                protocol_requests=self.validator.protocol_requests,
                tx_bytes=tx_bytes,
                rx_bytes=rx_bytes,
                forwarded_tcp=forwarded,
                accepted_tcp=tuple(accepted),
            ))

    def relay_compound(self, *, outbound_tcp: Iterable[bytes], inbound_tcp: Iterable[bytes],
                       outbound_udp: Iterable[bytes], inbound_udp: Iterable[bytes]) -> RelayResult:
        """Validate one complete SMB plus NBSTAT exchange under one receipt."""
        if (closed := self._closed()) is not None:
            return closed
        forwarded_tcp: tuple[bytes, ...] = ()
        forwarded_udp: tuple[bytes, ...] = ()
        accepted_tcp: tuple[bytes, ...] = ()
        accepted_udp: tuple[bytes, ...] = ()
        connects = datagrams = requests = tx_bytes = rx_bytes = 0
        try:
            started, cpu_started = self._clock(), self._cpu_clock()
            if not isinstance(self.validator, SMBRelayValidator):
                raise MalformedMessage("compound SMB data is outside the HTTP profile")
            tcp_out = self._chunks(outbound_tcp)
            tcp_in = self._chunks(inbound_tcp)
            udp_out = self._chunks(outbound_udp)
            udp_in = self._chunks(inbound_udp)
            self._runtime_preflight()
            total_tx = sum(map(len, tcp_out)) + sum(map(len, udp_out))
            if (not tcp_out or not udp_out or self.limits.tcp_connects < 1
                    or len(udp_out) > self.limits.udp_datagrams
                    or total_tx > self.limits.tx_bytes):
                raise _Limit()
            self._check(started, cpu_started)
            for datagram in udp_out:
                self._check(started, cpu_started)
                self.validator.feed_udp(datagram)
            for chunk in tcp_out:
                self._check(started, cpu_started)
                self.validator.feed_tcp(chunk)
            self.validator.finish_tcp()
            if self.validator.protocol_requests != 2 or self.validator.protocol_requests > self.limits.protocol_requests:
                raise _Limit()
            self._check(started, cpu_started)
            connects = 1
            datagrams = self.validator.udp_datagrams
            requests = self.validator.protocol_requests
            tx_bytes = total_tx
            forwarded_tcp, forwarded_udp = tcp_out, udp_out

            if not tcp_in or not udp_in:
                raise _MissingResponse()
            for datagram in udp_in:
                self._check(started, cpu_started)
                rx_bytes += len(datagram)
                if rx_bytes > self.limits.rx_bytes or rx_bytes > self.limits.output_bytes:
                    raise _Limit()
                self.validator.accept_udp_response(datagram)
                accepted_udp += (datagram,)
            for chunk in tcp_in:
                self._check(started, cpu_started)
                rx_bytes += len(chunk)
                if rx_bytes > self.limits.rx_bytes or rx_bytes > self.limits.output_bytes:
                    raise _Limit()
            self.validator.accept_tcp_response(b"".join(tcp_in))
            accepted_tcp = tcp_in
            return self._finish(self._result(
                "complete", "complete", tcp_connects=connects,
                udp_datagrams=datagrams, protocol_requests=requests,
                tx_bytes=tx_bytes, rx_bytes=rx_bytes,
                forwarded_tcp=forwarded_tcp, forwarded_udp=forwarded_udp,
                accepted_tcp=accepted_tcp, accepted_udp=accepted_udp,
            ))
        except (ExtraRequest, MalformedMessage, _Stop, _Deadline, _Limit, _MissingResponse) as exc:
            traffic = bool(forwarded_tcp or forwarded_udp or accepted_tcp or accepted_udp)
            status, reason = self._status(exc, traffic)
            return self._finish(self._result(
                status, reason, tcp_connects=connects,
                udp_datagrams=datagrams, protocol_requests=requests,
                tx_bytes=tx_bytes, rx_bytes=rx_bytes,
                forwarded_tcp=forwarded_tcp, forwarded_udp=forwarded_udp,
                accepted_tcp=accepted_tcp, accepted_udp=accepted_udp,
            ))
        except Exception:
            traffic = bool(forwarded_tcp or forwarded_udp or accepted_tcp or accepted_udp)
            return self._finish(self._result(
                "uncertain" if traffic else "blocked",
                "relay infrastructure failure",
                tcp_connects=connects,
                udp_datagrams=datagrams,
                protocol_requests=requests,
                tx_bytes=tx_bytes,
                rx_bytes=rx_bytes,
                forwarded_tcp=forwarded_tcp,
                forwarded_udp=forwarded_udp,
                accepted_tcp=accepted_tcp,
                accepted_udp=accepted_udp,
            ))

    def relay_smb(self, outbound_tcp: Iterable[bytes], inbound_tcp: Iterable[bytes],
                  outbound_udp: Iterable[bytes], inbound_udp: Iterable[bytes]) -> RelayResult:
        """Compatibility name for the canonical compound action."""
        return self.relay_compound(
            outbound_tcp=outbound_tcp,
            inbound_tcp=inbound_tcp,
            outbound_udp=outbound_udp,
            inbound_udp=inbound_udp,
        )

    def relay_udp(self, datagrams: Iterable[bytes], inbound_datagrams: Iterable[bytes] = ()) -> RelayResult:
        """Reject split UDP use so a compound profile cannot reset its counters."""
        if (closed := self._closed()) is not None:
            return closed
        del datagrams, inbound_datagrams
        return self._finish(self._result("blocked", "UDP requires one compound relay action"))
