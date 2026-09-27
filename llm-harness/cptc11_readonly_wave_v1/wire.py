"""Bounded framing over a caller-supplied, already-connected channel.

The integration supplying the channel must enforce bounded blocking for every
``send``, ``recv``, and ``close`` call.  This module deliberately adds no opener.
"""

from __future__ import annotations

import re
import time
from typing import Callable

from .contracts import HttpGetOperation, ReadOnlyAction, RedisPingOperation, WireCounters
from .parsers import ParserError
from .parsers.redis import _validate_simple_frame


_STATUS = re.compile(rb"^HTTP/1\.[01] ([0-9]{3}) ([\x20-\x7e]{1,64})$")
_TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")


class WireError(RuntimeError):
    def __init__(self, message: str, outcome: str, counters: WireCounters):
        super().__init__(message)
        self.outcome = outcome
        self.counters = counters


def _counters(contacted: bool, requests: int, tx: int, rx: int) -> WireCounters:
    return WireCounters(1 if contacted else 0, requests, tx, rx, rx)


def _guard(stopped: Callable[[], bool], clock_ns: Callable[[], int], deadline_ns: int, *, contacted: bool, requests: int, tx: int, rx: int) -> None:
    counters = _counters(contacted, requests, tx, rx)
    if stopped():
        raise WireError("operation stopped", "uncertain" if contacted else "cancelled", counters)
    now = clock_ns()
    if type(now) is not int or type(deadline_ns) is not int or now >= deadline_ns:
        raise WireError("operation deadline reached", "uncertain" if contacted else "cancelled", counters)


def _send(channel: object, request: bytes, stopped: Callable[[], bool], clock_ns: Callable[[], int], deadline_ns: int) -> tuple[int, int]:
    sent = 0
    _guard(stopped, clock_ns, deadline_ns, contacted=False, requests=0, tx=0, rx=0)
    requests = 1
    view = memoryview(request)
    while sent < len(request):
        try:
            count = channel.send(view[sent:])
        except Exception as error:
            raise WireError("channel send is uncertain", "uncertain", _counters(True, requests, sent, 0)) from error
        if type(count) is not int or count <= 0 or count > len(view) - sent:
            raise WireError("channel send is uncertain", "uncertain", _counters(True, requests, sent, 0))
        sent += count
        _guard(stopped, clock_ns, deadline_ns, contacted=True, requests=requests, tx=sent, rx=0)
    return sent, requests


def _receive(
    channel: object,
    action: ReadOnlyAction,
    stopped: Callable[[], bool],
    clock_ns: Callable[[], int],
    deadline_ns: int,
    tx: int,
    requests: int,
    *,
    redis_frame: bool = False,
) -> bytes:
    chunks: list[bytes] = []
    received = 0
    while True:
        _guard(stopped, clock_ns, deadline_ns, contacted=True, requests=requests, tx=tx, rx=received)
        remaining = min(
            action.budget.max_rx_bytes - received,
            action.budget.max_capture_bytes - received,
        )
        if remaining <= 0:
            raise WireError(
                "channel response exhausted the capture budget",
                "failed",
                _counters(True, requests, tx, received),
            )
        maximum = min(4096, remaining)
        try:
            chunk = channel.recv(maximum)
        except Exception as error:
            raise WireError("channel receive is uncertain", "uncertain", _counters(True, requests, tx, received)) from error
        if type(chunk) is not bytes:
            raise WireError("channel response type is invalid", "failed", _counters(True, requests, tx, received))
        if len(chunk) > maximum:
            raise WireError(
                "channel returned more bytes than requested",
                "failed",
                _counters(True, requests, tx, received),
            )
        if not chunk:
            _guard(stopped, clock_ns, deadline_ns, contacted=True, requests=requests, tx=tx, rx=received)
            return b"".join(chunks)
        chunks.append(chunk)
        received += len(chunk)
        if redis_frame:
            raw = b"".join(chunks)
            try:
                complete = _validate_simple_frame(raw)
            except ParserError as error:
                raise WireError(str(error), "failed", _counters(True, requests, tx, received)) from None
            _guard(
                stopped, clock_ns, deadline_ns, contacted=True,
                requests=requests, tx=tx, rx=received,
            )
            if complete:
                return raw
        else:
            _guard(stopped, clock_ns, deadline_ns, contacted=True, requests=requests, tx=tx, rx=received)


def _parse_http(raw: bytes) -> tuple[int, bytes]:
    marker = raw.find(b"\r\n\r\n")
    if marker < 0 or marker + 4 > 4096:
        raise ValueError("HTTP headers are malformed or oversized")
    head, body = raw[:marker], raw[marker + 4 :]
    lines = head.split(b"\r\n")
    match = _STATUS.fullmatch(lines[0]) if lines else None
    if match is None:
        raise ValueError("HTTP status line is invalid")
    status = int(match.group(1))
    if status < 100 or status > 599 or 100 <= status < 200 or 300 <= status < 400:
        raise ValueError("HTTP informational and redirect responses are rejected")
    headers: dict[bytes, list[bytes]] = {}
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise ValueError("HTTP header is invalid")
        name, value = line.split(b":", 1)
        if _TOKEN.fullmatch(name) is None:
            raise ValueError("HTTP header name is invalid")
        if any(byte < 32 or byte > 126 for byte in value):
            raise ValueError("HTTP header value is invalid")
        value = value.strip(b" ")
        headers.setdefault(name.lower(), []).append(value)
    if b"transfer-encoding" in headers:
        raise ValueError("HTTP transfer encoding is rejected")
    encodings = headers.get(b"content-encoding", [])
    if len(encodings) > 1 or encodings and encodings[0].lower() != b"identity":
        raise ValueError("HTTP content encoding is rejected")
    lengths = headers.get(b"content-length", [])
    if len(lengths) > 1:
        raise ValueError("duplicate HTTP content length is rejected")
    if lengths:
        if not lengths[0].isdigit() or len(lengths[0]) > 20:
            raise ValueError("HTTP content length is invalid")
        expected = int(lengths[0])
        if len(body) != expected:
            raise ValueError("HTTP body length differs")
    return status, body


def execute_http(channel: object, action: ReadOnlyAction, *, stopped: Callable[[], bool], deadline_ns: int, clock_ns: Callable[[], int] = time.monotonic_ns) -> tuple[int, bytes, WireCounters]:
    if not isinstance(action.operation, HttpGetOperation):
        raise TypeError("action is not HTTP")
    tx = requests = 0
    try:
        tx, requests = _send(channel, action.operation.request, stopped, clock_ns, deadline_ns)
        raw = _receive(channel, action, stopped, clock_ns, deadline_ns, tx, requests)
        counters = _counters(True, requests, tx, len(raw)).validate(action.budget)
        try:
            status, body = _parse_http(raw)
        except ValueError as error:
            raise WireError(str(error), "failed", counters) from None
        result = (status, body, counters)
    except BaseException:
        try:
            channel.close()
        except Exception:
            pass
        raise
    try:
        channel.close()
    except Exception as error:
        raise WireError("channel close is uncertain", "uncertain", counters) from error
    return result


def execute_redis(channel: object, action: ReadOnlyAction, *, stopped: Callable[[], bool], deadline_ns: int, clock_ns: Callable[[], int] = time.monotonic_ns) -> tuple[bytes, WireCounters]:
    if not isinstance(action.operation, RedisPingOperation):
        raise TypeError("action is not Redis")
    tx = requests = 0
    try:
        tx, requests = _send(channel, action.operation.request, stopped, clock_ns, deadline_ns)
        raw = _receive(
            channel, action, stopped, clock_ns, deadline_ns, tx, requests,
            redis_frame=True,
        )
        counters = _counters(True, requests, tx, len(raw)).validate(action.budget)
        try:
            _validate_simple_frame(raw)
        except ParserError as error:
            raise WireError(str(error), "failed", counters) from None
        result = (raw, counters)
    except BaseException:
        try:
            channel.close()
        except Exception:
            pass
        raise
    try:
        channel.close()
    except Exception as error:
        raise WireError("channel close is uncertain", "uncertain", counters) from error
    return result
