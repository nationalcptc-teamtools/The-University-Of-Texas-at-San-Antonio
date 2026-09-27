import time

import pytest

from cptc11_readonly_wave_v1.catalog import plan_actions
from cptc11_readonly_wave_v1.wire import WireError, execute_http, execute_redis


PLAN = "cptc11-readonly-wave-v1"


class Channel:
    """Immediate fake; real supplied channels must bound every blocking call."""

    def __init__(self, replies, send_limit=10_000):
        self.replies = list(replies)
        self.send_limit = send_limit
        self.sent = bytearray()
        self.closed = False
        self.recv_maxima = []

    def send(self, value):
        chunk = bytes(value)[: self.send_limit]
        self.sent.extend(chunk)
        return len(chunk)

    def recv(self, maximum):
        self.recv_maxima.append(maximum)
        if not self.replies:
            return b""
        value = self.replies.pop(0)
        if len(value) > maximum:
            self.replies.insert(0, value[maximum:])
        return value[:maximum]

    def close(self):
        self.closed = True


def test_http_partial_send_exact_request_counts_and_closes():
    action = plan_actions(PLAN)[0]
    channel = Channel([b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"Version\":\"v3\"}", b""], 7)
    status, body, counters = execute_http(
        channel, action, stopped=lambda: False, deadline_ns=time.monotonic_ns() + 1_000_000_000
    )
    assert bytes(channel.sent) == action.operation.request
    assert (status, body) == (200, b'{"Version":"v3"}')
    assert (counters.connects, counters.requests, counters.tx_bytes) == (1, 1, 123)
    assert counters.rx_bytes == counters.captured_bytes == 55
    assert channel.closed is True


@pytest.mark.parametrize(
    "response",
    (
        b"HTTP/1.1 101 Continue\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxy",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Test:\tvalue\r\n\r\n",
        b"HTTP/2 200 OK\r\n\r\n",
        b"HTTP/1.1 099 Invalid\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 600 Invalid\r\nContent-Length: 0\r\n\r\n",
    ),
)
def test_http_rejects_unsafe_or_malformed_framing(response):
    action = plan_actions(PLAN)[0]
    channel = Channel([response, b""])
    with pytest.raises(WireError):
        execute_http(channel, action, stopped=lambda: False, deadline_ns=time.monotonic_ns() + 1_000_000_000)
    assert channel.closed is True


def test_http_accepts_close_delimited_identity_body():
    action = plan_actions(PLAN)[0]
    response = b"HTTP/1.0 404 Missing\r\nContent-Encoding: identity\r\n\r\n{}"
    assert execute_http(
        Channel([response, b""]), action, stopped=lambda: False,
        deadline_ns=time.monotonic_ns() + 1_000_000_000,
    )[:2] == (404, b"{}")


def test_stop_before_send_is_cancelled_and_after_contact_is_uncertain():
    action = plan_actions(PLAN)[0]
    before = Channel([])
    with pytest.raises(WireError) as cancelled:
        execute_http(before, action, stopped=lambda: True, deadline_ns=time.monotonic_ns() + 1_000_000_000)
    assert cancelled.value.outcome == "cancelled"
    assert before.sent == b""
    calls = iter((False, True))
    after = Channel([])
    with pytest.raises(WireError) as uncertain:
        execute_http(after, action, stopped=lambda: next(calls), deadline_ns=time.monotonic_ns() + 1_000_000_000)
    assert uncertain.value.outcome == "uncertain"
    assert after.sent


def test_deadline_never_retries_and_closes_after_contact():
    action = plan_actions(PLAN)[0]
    channel = Channel([b"HTTP/1.1 200 OK\r\n\r\n"])
    clock = iter((1, 1, 3))
    with pytest.raises(WireError) as error:
        execute_http(channel, action, stopped=lambda: False, deadline_ns=2, clock_ns=lambda: next(clock))
    assert error.value.outcome == "uncertain"
    assert bytes(channel.sent) == action.operation.request
    assert channel.closed is True


def test_deadline_crossing_during_receive_is_uncertain():
    action = plan_actions(PLAN)[0]
    channel = Channel([b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"])
    clock = iter((1, 1, 1, 3))

    with pytest.raises(WireError) as error:
        execute_http(
            channel, action, stopped=lambda: False, deadline_ns=2,
            clock_ns=lambda: next(clock),
        )

    assert error.value.outcome == "uncertain"
    assert channel.closed is True


def test_redis_deadline_crossing_during_complete_frame_is_uncertain():
    channel = Channel([b"+PONG\r\n"])
    clock = iter((1, 1, 1, 3))

    with pytest.raises(WireError) as error:
        execute_redis(
            channel, plan_actions(PLAN)[1], stopped=lambda: False,
            deadline_ns=2, clock_ns=lambda: next(clock),
        )

    assert error.value.outcome == "uncertain"
    assert error.value.counters.rx_bytes == 7


def test_redis_exact_request_partial_send_and_single_frame():
    action = plan_actions(PLAN)[1]
    channel = Channel([b"+PONG\r\n", b""], 2)
    frame, counters = execute_redis(
        channel, action, stopped=lambda: False, deadline_ns=time.monotonic_ns() + 1_000_000_000
    )
    assert bytes(channel.sent) == b"*1\r\n$4\r\nPING\r\n"
    assert frame == b"+PONG\r\n"
    assert counters == counters.validate(action.budget)
    assert channel.closed is True


def test_redis_complete_frame_finishes_without_waiting_for_channel_eof():
    class PersistentChannel(Channel):
        def recv(self, maximum):
            if self.recv_maxima:
                raise AssertionError("complete frame attempted another blocking receive")
            return super().recv(maximum)

    channel = PersistentChannel([b"+PONG\r\n"])
    frame, counters = execute_redis(
        channel, plan_actions(PLAN)[1], stopped=lambda: False,
        deadline_ns=time.monotonic_ns() + 1_000_000_000,
    )
    assert frame == b"+PONG\r\n"
    assert counters.rx_bytes == 7
    assert channel.recv_maxima == [128]


@pytest.mark.parametrize(
    "response",
    (b"+PONG\r\n+OK\r\n", b"$4\r\nPONG\r\n", b"*1\r\n+PONG\r\n", b"+" + b"x" * 127 + b"\r\n"),
)
def test_redis_rejects_extra_unsupported_or_oversize_frames(response):
    with pytest.raises(WireError):
        execute_redis(
            Channel([response, b""]), plan_actions(PLAN)[1], stopped=lambda: False,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
        )


def test_redis_wire_preserves_incomplete_simple_frame_for_parser():
    channel = Channel([b"+PON", b""])

    raw, counters = execute_redis(
        channel, plan_actions(PLAN)[1], stopped=lambda: False,
        deadline_ns=time.monotonic_ns() + 1_000_000_000,
    )

    assert raw == b"+PON"
    assert counters.rx_bytes == 4


def test_receive_cap_exhaustion_fails_without_an_extra_read_and_caps_counters():
    action = plan_actions(PLAN)[1]
    channel = Channel([b"+" + b"x" * 127, b"must-not-be-read"])
    with pytest.raises(WireError) as raised:
        execute_redis(
            channel, action, stopped=lambda: False,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
        )
    assert raised.value.outcome in {"failed", "uncertain"}
    assert raised.value.counters.rx_bytes == raised.value.counters.captured_bytes == 128
    assert raised.value.counters.validate(action.budget) == raised.value.counters
    assert channel.recv_maxima == [128]


def test_receive_never_requests_or_retains_beyond_capture_budget():
    from cptc11_readonly_wave_v1.contracts import WireBudget, _sealed_action

    original = plan_actions(PLAN)[1]
    action = _sealed_action(
        plan_id=original.plan_id, action_id=original.action_id,
        profile_id=original.profile_id, target_id=original.target_id,
        order=original.order, host=original.host, port=original.port,
        operation=original.operation, budget=WireBudget(1, 1, 14, 128, 8, 5000),
        parser_id=original.parser_id, profile_sha256=original.profile_sha256,
        catalog_sha256=original.catalog_sha256,
    )

    class ContractBreakingChannel(Channel):
        def recv(self, maximum):
            self.recv_maxima.append(maximum)
            return b"+" + b"x" * (maximum + 10)

    channel = ContractBreakingChannel([])
    with pytest.raises(WireError) as raised:
        execute_redis(
            channel, action, stopped=lambda: False,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
        )
    assert channel.recv_maxima == [8]
    assert raised.value.counters.rx_bytes <= 8
    assert raised.value.counters.captured_bytes <= 8
    assert raised.value.counters.validate(action.budget) == raised.value.counters


@pytest.mark.parametrize("send_mode", ("raise", "partial-stop", "full-stop"))
def test_any_send_attempt_consumes_the_single_request_budget(send_mode):
    action = plan_actions(PLAN)[1]

    class InterruptedSend(Channel):
        def send(self, value):
            if send_mode == "raise":
                raise OSError("interrupted")
            chunk = bytes(value)[: 2 if send_mode == "partial-stop" else len(value)]
            self.sent.extend(chunk)
            return len(chunk)

    stops = iter((False, True))
    with pytest.raises(WireError) as raised:
        execute_redis(
            InterruptedSend([]), action, stopped=lambda: next(stops),
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
        )
    assert raised.value.counters.requests == 1
    assert raised.value.counters.validate(action.budget) == raised.value.counters


def test_primary_wire_error_survives_close_failure():
    class BrokenChannel(Channel):
        def recv(self, maximum):
            raise OSError("receive failed")

        def close(self):
            raise OSError("close failed")

    with pytest.raises(WireError, match="receive") as raised:
        execute_redis(
            BrokenChannel([]), plan_actions(PLAN)[1], stopped=lambda: False,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
        )
    assert raised.value.outcome == "uncertain"
    assert raised.value.counters.requests == 1


def test_close_only_failure_is_structured_uncertainty_with_counters():
    class CloseFails(Channel):
        def close(self):
            raise OSError("close failed")

    with pytest.raises(WireError, match="close") as raised:
        execute_redis(
            CloseFails([b"+PONG\r\n"]), plan_actions(PLAN)[1], stopped=lambda: False,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
        )
    assert raised.value.outcome == "uncertain"
    assert raised.value.counters.requests == 1
    assert raised.value.counters.rx_bytes == 7
