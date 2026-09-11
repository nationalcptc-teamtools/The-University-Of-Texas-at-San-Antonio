"""Parent-owned bounded wire capture and strict HTTP/1.1 framing.

This module never resolves a name or opens a socket. A trusted route supplies
one already-connected channel for the exact sealed profile. The parent sends,
receives, counts, and closes that channel.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import time
from typing import Callable, Protocol

from .catalog import SealedProfile, validate_sealed_profile
from .contracts import (
    Http11RequestV1,
    ProfileContractError,
    WireCounters,
)


_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] ([0-9]{3}) [\x20-\x7e]{1,64}$")
_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
_MAX_HEADER_BYTES = 4096
_SIGNIFICANT_HEADERS = frozenset(
    {b"content-length", b"transfer-encoding", b"content-encoding", b"content-type", b"location"}
)


class ConnectedChannel(Protocol):
    def settimeout(self, value: float) -> None: ...
    def send(self, value: memoryview) -> int: ...
    def recv(self, maximum: int) -> bytes: ...
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class HttpWireCapture:
    raw_response: bytes
    counters: WireCounters
    first_byte_observed: bool


@dataclass(frozen=True, slots=True)
class ParsedHttpResponse:
    status_code: int
    content_type: str
    content_encoding: str
    body: bytes


class WireExecutionError(RuntimeError):
    """Safe failure carrying bounded partial accounting for durable sealing."""

    def __init__(
        self,
        outcome: str,
        limitation: str,
        counters: WireCounters,
        raw_response: bytes = b"",
    ) -> None:
        super().__init__("bounded wire operation did not complete")
        self.outcome = outcome
        self.limitation = limitation
        self.counters = counters
        self.raw_response = raw_response


def build_http11_request(operation: Http11RequestV1) -> bytes:
    if not isinstance(operation, Http11RequestV1):
        raise ProfileContractError("HTTP operation is not sealed")
    try:
        start = f"{operation.method} {operation.path} HTTP/1.1\r\n".encode("ascii")
        headers = b"".join(
            f"{name}: {value}\r\n".encode("ascii") for name, value in operation.headers
        )
    except UnicodeEncodeError:
        raise ProfileContractError("HTTP operation contains non-ASCII data") from None
    request = start + headers + b"\r\n"
    if b"\r\n\r\n" not in request or request.count(b"\r\n\r\n") != 1:
        raise ProfileContractError("HTTP request framing differs")
    return request


def _wire_counters(*, request: bool, tx: int, rx: int) -> WireCounters:
    return WireCounters(
        tcp_connects=1,
        udp_datagrams=0,
        tls_handshakes=0,
        protocol_requests=1 if request else 0,
        tx_bytes=tx,
        rx_bytes=rx,
        capture_bytes=rx,
    )


def capture_cleartext_http11(
    profile: SealedProfile,
    channel: ConnectedChannel,
    *,
    stopped: Callable[[], bool] = lambda: False,
    monotonic: Callable[[], float] = time.monotonic,
) -> HttpWireCapture:
    """Use one connected channel and count every application-protocol byte."""

    exact = validate_sealed_profile(profile)
    operation = exact.operation
    if not isinstance(operation, Http11RequestV1) or operation.tls:
        raise ProfileContractError("cleartext HTTP worker received another operation")
    request = build_http11_request(operation)
    if len(request) > exact.budget.tx_bytes:
        raise ProfileContractError("fixed request exceeds profile budget")
    deadline = monotonic() + exact.budget.timeout_s
    sent = 0
    raw = bytearray()
    request_observed = False
    try:
        channel.settimeout(exact.budget.timeout_s)
        if stopped():
            raise WireExecutionError(
                "cancelled", "stop_latched", _wire_counters(request=False, tx=0, rx=0)
            )
        view = memoryview(request)
        while view:
            if stopped():
                outcome = "uncertain" if sent else "cancelled"
                raise WireExecutionError(
                    outcome,
                    "stop_latched",
                    _wire_counters(request=request_observed, tx=sent, rx=len(raw)),
                    bytes(raw),
                )
            if monotonic() >= deadline:
                raise WireExecutionError(
                    "uncertain",
                    "timeout",
                    _wire_counters(request=request_observed, tx=sent, rx=len(raw)),
                    bytes(raw),
                )
            try:
                count = channel.send(view)
            except BaseException:
                raise WireExecutionError(
                    "uncertain",
                    "transport_interrupted",
                    _wire_counters(request=request_observed, tx=sent, rx=len(raw)),
                    bytes(raw),
                ) from None
            if type(count) is not int or not 0 < count <= len(view):
                raise WireExecutionError(
                    "uncertain",
                    "transport_interrupted",
                    _wire_counters(request=request_observed, tx=sent, rx=len(raw)),
                    bytes(raw),
                )
            request_observed = True
            sent += count
            view = view[count:]

        while True:
            if stopped():
                raise WireExecutionError(
                    "uncertain",
                    "stop_latched",
                    _wire_counters(request=True, tx=sent, rx=len(raw)),
                    bytes(raw),
                )
            if monotonic() >= deadline:
                raise WireExecutionError(
                    "uncertain",
                    "timeout",
                    _wire_counters(request=True, tx=sent, rx=len(raw)),
                    bytes(raw),
                )
            remaining = exact.budget.rx_bytes - len(raw)
            if remaining == 0:
                raise WireExecutionError(
                    "uncertain",
                    "response_truncated",
                    _wire_counters(request=True, tx=sent, rx=len(raw)),
                    bytes(raw),
                )
            try:
                chunk = channel.recv(min(4096, remaining))
            except BaseException:
                raise WireExecutionError(
                    "uncertain",
                    "transport_interrupted",
                    _wire_counters(request=True, tx=sent, rx=len(raw)),
                    bytes(raw),
                ) from None
            if not isinstance(chunk, bytes):
                raise WireExecutionError(
                    "uncertain",
                    "transport_interrupted",
                    _wire_counters(request=True, tx=sent, rx=len(raw)),
                    bytes(raw),
                )
            if not chunk:
                break
            raw.extend(chunk)
        counters = _wire_counters(request=True, tx=sent, rx=len(raw))
        counters.validate_against(exact.budget)
        return HttpWireCapture(bytes(raw), counters, bool(raw))
    finally:
        channel.close()


def parse_http11_response(
    raw: bytes, *, method: str, maximum_body_bytes: int
) -> ParsedHttpResponse:
    """Parse strict close-delimited HTTP without returning arbitrary headers."""

    if type(raw) is not bytes or not raw or type(maximum_body_bytes) is not int or maximum_body_bytes < 0:
        raise ProfileContractError("invalid HTTP response input")
    if raw.count(b"\r\n\r\n") < 1:
        raise ProfileContractError("HTTP response headers are incomplete")
    head, body = raw.split(b"\r\n\r\n", 1)
    if len(head) > _MAX_HEADER_BYTES or b"\n" in head.replace(b"\r\n", b""):
        raise ProfileContractError("HTTP response header framing is invalid")
    lines = head.split(b"\r\n")
    status_match = _STATUS_LINE.fullmatch(lines[0]) if lines else None
    if status_match is None:
        raise ProfileContractError("HTTP response status line is invalid")
    status_code = int(status_match.group(1))
    if 100 <= status_code < 200 or 300 <= status_code < 400:
        raise ProfileContractError("HTTP response status is not admitted")

    values: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise ProfileContractError("HTTP response header is invalid")
        name, content = line.split(b":", 1)
        lowered = name.lower()
        content = content.strip(b" \t")
        if _HEADER_NAME.fullmatch(name) is None or any(byte < 32 or byte == 127 for byte in content):
            raise ProfileContractError("HTTP response header is invalid")
        if lowered in _SIGNIFICANT_HEADERS:
            if lowered in values:
                raise ProfileContractError("HTTP response has duplicate framing metadata")
            values[lowered] = content

    if b"transfer-encoding" in values:
        raise ProfileContractError("HTTP transfer encoding is not admitted")
    encoding_raw = values.get(b"content-encoding", b"identity")
    if encoding_raw.lower() != b"identity":
        raise ProfileContractError("HTTP content encoding is not admitted")
    if b"content-length" in values:
        length_raw = values[b"content-length"]
        if not length_raw.isdigit() or len(length_raw) > 10:
            raise ProfileContractError("HTTP content length is invalid")
        declared = int(length_raw)
        if method == "HEAD":
            if body:
                raise ProfileContractError("HEAD response contains a body")
        elif declared != len(body):
            raise ProfileContractError("HTTP response body length differs")
    elif method == "HEAD" and body:
        raise ProfileContractError("HEAD response contains a body")
    if len(body) > maximum_body_bytes:
        raise ProfileContractError("HTTP response body exceeds allowance")
    try:
        content_type = values.get(b"content-type", b"").decode("ascii").lower()
        content_encoding = encoding_raw.decode("ascii").lower()
    except UnicodeDecodeError:
        raise ProfileContractError("HTTP response metadata is not ASCII") from None
    return ParsedHttpResponse(status_code, content_type, content_encoding, body)


__all__ = (
    "ConnectedChannel",
    "HttpWireCapture",
    "ParsedHttpResponse",
    "WireExecutionError",
    "build_http11_request",
    "capture_cleartext_http11",
    "parse_http11_response",
)
