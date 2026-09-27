from __future__ import annotations

from collections import deque

import pytest

from cptc_harness.profile_runtime.catalog import load_profile
from cptc_harness.profile_runtime.contracts import ProfileContractError
from cptc_harness.profile_runtime.worker import (
    WireExecutionError,
    build_http11_request,
    capture_cleartext_http11,
    parse_http11_response,
)


class FakeChannel:
    def __init__(self, responses, *, send_limit=1_000_000, send_error_at=None):
        self.responses = deque(responses)
        self.send_limit = send_limit
        self.send_error_at = send_error_at
        self.sent = bytearray()
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def send(self, value):
        if self.send_error_at is not None and len(self.sent) >= self.send_error_at:
            raise OSError("synthetic send failure")
        size = min(len(value), self.send_limit)
        self.sent.extend(bytes(value[:size]))
        return size

    def recv(self, maximum):
        if not self.responses:
            return b""
        value = self.responses.popleft()
        if isinstance(value, BaseException):
            raise value
        if len(value) <= maximum:
            return value
        self.responses.appendleft(value[maximum:])
        return value[:maximum]

    def close(self):
        self.closed = True


def profile():
    return load_profile("web.http_jellyfin_public_identity")


def response(body=b'{"ProductName":"Jellyfin Server","Version":"10.10.7"}'):
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Encoding: identity\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )


def test_request_bytes_are_exact_small_and_have_no_body_or_authentication():
    request = build_http11_request(profile().operation)
    assert request == (
        b"GET /System/Info/Public HTTP/1.1\r\n"
        b"Accept: application/json\r\n"
        b"Connection: close\r\n"
        b"Host: 10.0.1.30:8096\r\n\r\n"
    )
    assert len(request) <= profile().budget.tx_bytes
    assert b"Authorization" not in request and b"Cookie" not in request


def test_parent_capture_counts_fragmented_partial_sends_and_all_raw_response_bytes():
    raw = response()
    channel = FakeChannel([raw[:11], raw[11:57], raw[57:], b""], send_limit=7)
    capture = capture_cleartext_http11(profile(), channel)
    assert bytes(channel.sent) == build_http11_request(profile().operation)
    assert capture.raw_response == raw
    assert capture.counters.tcp_connects == 1
    assert capture.counters.protocol_requests == 1
    assert capture.counters.tx_bytes == len(channel.sent)
    assert capture.counters.rx_bytes == len(raw)
    assert capture.counters.capture_bytes == len(raw)
    assert capture.first_byte_observed is True
    assert channel.closed and channel.timeout == profile().budget.timeout_s


def test_capture_closes_and_returns_safe_uncertainty_on_send_receive_and_cap_failures():
    cases = (
        FakeChannel([], send_limit=4, send_error_at=4),
        FakeChannel([b"HTTP/1.1", OSError("synthetic receive failure")]),
        FakeChannel([b"A" * profile().budget.rx_bytes]),
    )
    for channel in cases:
        with pytest.raises(WireExecutionError) as raised:
            capture_cleartext_http11(profile(), channel)
        assert raised.value.outcome == "uncertain"
        assert raised.value.limitation in {"transport_interrupted", "response_truncated"}
        assert "synthetic" not in str(raised.value)
        assert channel.closed
        assert raised.value.counters.tcp_connects == 1


def test_stop_before_first_send_is_cancelled_without_a_protocol_request():
    channel = FakeChannel([response(), b""])
    with pytest.raises(WireExecutionError) as raised:
        capture_cleartext_http11(profile(), channel, stopped=lambda: True)
    assert raised.value.outcome == "cancelled"
    assert raised.value.counters.protocol_requests == 0
    assert raised.value.counters.tx_bytes == 0
    assert bytes(channel.sent) == b""
    assert channel.closed


def test_parser_returns_only_bounded_protocol_metadata_and_body():
    raw = response()
    parsed = parse_http11_response(raw, method="GET", maximum_body_bytes=4096)
    assert parsed.status_code == 200
    assert parsed.content_type == "application/json"
    assert parsed.content_encoding == "identity"
    assert parsed.body == raw.split(b"\r\n\r\n", 1)[1]
    assert not hasattr(parsed, "headers")


@pytest.mark.parametrize(
    "raw",
    (
        b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
        b"HTTP/1.1 200 OK\r\n Content-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
    ),
)
def test_parser_rejects_redirect_encoding_framing_and_malformed_responses(raw):
    with pytest.raises(ProfileContractError):
        parse_http11_response(raw, method="GET", maximum_body_bytes=4096)


def test_parser_rejects_oversized_headers_or_body_and_head_body():
    oversized_header = b"HTTP/1.1 200 OK\r\nX-Fill: " + b"a" * 4097 + b"\r\n\r\n"
    oversized_body = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345"
    head_body = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"
    with pytest.raises(ProfileContractError):
        parse_http11_response(oversized_header, method="GET", maximum_body_bytes=4096)
    with pytest.raises(ProfileContractError):
        parse_http11_response(oversized_body, method="GET", maximum_body_bytes=4)
    with pytest.raises(ProfileContractError):
        parse_http11_response(head_body, method="HEAD", maximum_body_bytes=0)
