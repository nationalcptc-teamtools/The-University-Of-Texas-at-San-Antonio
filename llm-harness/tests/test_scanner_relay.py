from __future__ import annotations

from pathlib import Path

import pytest

from cptc_harness.scanner_protocols import (
    HTTPGetRootValidator,
    NMAP_NBSTAT_WILDCARD_REQUEST,
    NMAP_SMB2_NEGOTIATE_REQUEST,
    SMBRelayValidator,
)
from cptc_harness.scanner_relay import ParentRelay, RelayLimits


def _http_request():
    return b"GET / HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: close\r\n\r\n"


def _nbstat():
    return NMAP_NBSTAT_WILDCARD_REQUEST


def _smb_response():
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[16:20] = (1).to_bytes(4, "little")
    body = bytearray(65)
    body[:2] = (65).to_bytes(2, "little")
    body[4:6] = (0x0202).to_bytes(2, "little")
    payload = bytes(header + body)
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _nbstat_response():
    return (b"\x13\x37\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00" +
            NMAP_NBSTAT_WILDCARD_REQUEST[12:] + b"\x00\x21\x00\x01\x00\x00\x00\x00\x00\x01\x00")


def _limits(**overrides):
    values = dict(tcp_connects=1, udp_datagrams=1, protocol_requests=1,
                  tx_bytes=4096, rx_bytes=16384, timeout_s=10.0, cpu_s=10.0,
                  output_bytes=16384, process_limit=1, auth_attempts=0)
    values.update(overrides)
    return RelayLimits(**values)


def test_parent_relay_forwards_fragmented_http_and_accounts_wire_usage():
    request = _http_request()
    relay = ParentRelay("127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits())
    result = relay.relay_tcp((request[:4], request[4:]), (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",))
    assert result.receipt.status == "complete"
    assert result.forwarded_tcp == (request[:4], request[4:])
    assert result.receipt.tcp_connects == 1
    assert result.receipt.protocol_requests == 1
    assert result.receipt.tx_bytes == len(request)
    assert result.receipt.rx_bytes > 0


def test_parent_relay_rejects_extra_request_and_marks_prior_traffic_uncertain():
    request = _http_request()
    relay = ParentRelay("127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits())
    result = relay.relay_tcp((request, request), ())
    assert result.receipt.status == "blocked"
    assert "extra" in result.receipt.reason
    assert result.forwarded_tcp == ()
    retry = relay.relay_tcp((request,), (b"HTTP/1.1 200 OK\r\n\r\n",))
    assert retry.receipt.status == "blocked"
    assert "sealed" in retry.receipt.reason
    assert retry.receipt.protocol_requests == result.receipt.protocol_requests
    assert retry.forwarded_tcp == ()


def test_parent_relay_returns_limit_failure_before_forwarding_over_limit():
    request = _http_request()
    relay = ParentRelay("127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits(tx_bytes=len(request) - 1))
    result = relay.relay_tcp((request,), ())
    assert result.receipt.status == "blocked"
    assert result.forwarded_tcp == ()
    assert "limit" in result.receipt.reason


def test_parent_relay_stop_and_deadline_are_distinct_and_fail_closed():
    request = _http_request()
    relay = ParentRelay("127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits(), stopped=lambda: True)
    assert relay.relay_tcp((request,), ()).receipt.status == "stopped"

    now = iter((0.0, 20.0))
    relay = ParentRelay("127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits(timeout_s=10.0), clock=lambda: next(now))
    result = relay.relay_tcp((request,), ())
    assert result.receipt.status == "blocked"
    assert "deadline" in result.receipt.reason


def test_parent_relay_accounts_one_compound_smb_action_and_udp_response():
    limits = _limits(protocol_requests=2)
    relay = ParentRelay("127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445), limits)
    first = relay.relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(_nbstat(),), inbound_udp=(_nbstat_response(),),
    )
    second = ParentRelay(
        "127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445), limits,
    ).relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(_nbstat(),), inbound_udp=(_nbstat_response(),),
    )
    assert first.receipt.status == "complete"
    assert first.forwarded_tcp == (NMAP_SMB2_NEGOTIATE_REQUEST,)
    assert first.forwarded_udp == (_nbstat(),)
    assert first.accepted_tcp == (_smb_response(),)
    assert first.accepted_udp == (_nbstat_response(),)
    assert first.receipt.tcp_connects == 1
    assert first.receipt.udp_datagrams == 1
    assert first.receipt.protocol_requests == 2
    assert first.receipt.tx_bytes == len(NMAP_SMB2_NEGOTIATE_REQUEST) + len(_nbstat())
    assert first.receipt.rx_bytes == len(_smb_response()) + len(_nbstat_response())
    assert first.receipt.canonical_bytes() == second.receipt.canonical_bytes()
    assert first.receipt.sha256 == second.receipt.sha256


def test_parent_relay_marks_rx_overrun_after_forwarded_request_uncertain():
    request = _http_request()
    relay = ParentRelay("127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits(rx_bytes=3))
    result = relay.relay_tcp((request,), (b"four",))
    assert result.receipt.status == "uncertain"
    assert result.forwarded_tcp == (request,)
    assert result.accepted_tcp == ()
    assert result.receipt.rx_bytes == 4
    assert "limit" in result.receipt.reason
    retry = relay.relay_tcp((request,), ())
    assert retry.receipt.status == "blocked"
    assert "sealed" in retry.receipt.reason
    assert retry.receipt.rx_bytes == result.receipt.rx_bytes
    assert retry.forwarded_tcp == ()


def test_parent_relay_checks_stop_after_traffic_without_forwarding_more():
    calls = 0
    def stopped():
        nonlocal calls
        calls += 1
        return calls >= 4
    request = _http_request()
    relay = ParentRelay("127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits(), stopped=stopped)
    result = relay.relay_tcp((request,), (b"HTTP/1.1 200 OK\r\n\r\n",))
    assert result.receipt.status == "uncertain"
    assert result.forwarded_tcp == (request,)
    assert result.accepted_tcp == ()
    assert "stop" in result.receipt.reason


@pytest.mark.parametrize("field,value", [("tcp_connects", 0), ("process_limit", 0), ("auth_attempts", 1)])
def test_parent_relay_rejects_unavailable_or_authenticated_runtime_before_traffic(field, value):
    relay = ParentRelay("127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits(**{field: value}))
    result = relay.relay_tcp((_http_request(),), ())
    assert result.receipt.status == "blocked"
    assert result.forwarded_tcp == ()


def test_udp_limit_is_checked_before_any_datagram_is_forwarded():
    relay = ParentRelay(
        "127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445),
        _limits(protocol_requests=2, tx_bytes=len(NMAP_SMB2_NEGOTIATE_REQUEST) + len(_nbstat()) - 1),
    )
    result = relay.relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(_nbstat(),), inbound_udp=(_nbstat_response(),),
    )
    assert result.receipt.status == "blocked"
    assert result.forwarded_tcp == ()
    assert result.forwarded_udp == ()


def test_compound_smb_requires_one_outbound_and_one_inbound_udp_datagram():
    limits = _limits(protocol_requests=2)
    missing_outbound = ParentRelay(
        "127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445), limits,
    ).relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(), inbound_udp=(_nbstat_response(),),
    )
    assert missing_outbound.receipt.status == "blocked"
    assert missing_outbound.forwarded_tcp == ()

    relay = ParentRelay("127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445), limits)
    missing_response = relay.relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(_nbstat(),), inbound_udp=(),
    )
    assert missing_response.receipt.status == "uncertain"
    assert missing_response.forwarded_udp == (_nbstat(),)
    assert missing_response.accepted_udp == ()
    assert "response" in missing_response.receipt.reason


def test_compound_protocol_budget_is_cumulative_across_udp_and_tcp():
    relay = ParentRelay(
        "127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445),
        _limits(protocol_requests=1),
    )
    result = relay.relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(_nbstat(),), inbound_udp=(_nbstat_response(),),
    )
    assert result.receipt.status == "blocked"
    assert result.receipt.protocol_requests == 0
    assert result.forwarded_tcp == result.forwarded_udp == ()


def test_smb_validator_exposes_only_the_fixed_companion_udp_port():
    validator = SMBRelayValidator("127.0.0.1", 445)
    assert (validator.host, validator.port, validator.udp_port) == ("127.0.0.1", 445, 137)


def test_compound_smb_udp_rx_overrun_is_uncertain_and_terminal():
    response = _nbstat_response()
    relay = ParentRelay(
        "127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445),
        _limits(protocol_requests=2, rx_bytes=len(response) - 1),
    )
    result = relay.relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(_nbstat(),), inbound_udp=(response,),
    )
    assert result.receipt.status == "uncertain"
    assert result.accepted_tcp == ()
    assert result.accepted_udp == ()
    assert result.receipt.rx_bytes == len(response)
    retry = relay.relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(_nbstat(),), inbound_udp=(response,),
    )
    assert retry.receipt.status == "blocked"
    assert "sealed" in retry.receipt.reason
    assert retry.forwarded_tcp == retry.forwarded_udp == ()


def test_compound_smb_tcp_rx_overrun_records_the_full_received_chunk():
    udp_response = _nbstat_response()
    tcp_response = _smb_response()
    relay = ParentRelay(
        "127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445),
        _limits(protocol_requests=2, rx_bytes=len(udp_response) + len(tcp_response) - 1),
    )
    result = relay.relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(tcp_response,),
        outbound_udp=(_nbstat(),), inbound_udp=(udp_response,),
    )
    assert result.receipt.status == "uncertain"
    assert result.accepted_udp == (udp_response,)
    assert result.accepted_tcp == ()
    assert result.receipt.rx_bytes == len(udp_response) + len(tcp_response)


@pytest.mark.parametrize("failure", ["malformed", "stop", "deadline", "limit"])
def test_terminal_failures_cannot_be_resumed(failure):
    request = _http_request()
    kwargs = {}
    limits = _limits()
    outbound = (b"bad",)
    if failure == "stop":
        kwargs["stopped"] = lambda: True
        outbound = (request,)
    elif failure == "deadline":
        now = iter((0.0, 20.0))
        kwargs["clock"] = lambda: next(now)
        outbound = (request,)
        limits = _limits(timeout_s=10.0)
    elif failure == "limit":
        limits = _limits(tx_bytes=1)
        outbound = (request,)
    relay = ParentRelay(
        "127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), limits, **kwargs,
    )
    first = relay.relay_tcp(outbound, ())
    second = relay.relay_tcp((request,), (b"HTTP/1.1 200 OK\r\n\r\n",))
    assert second.receipt.status == "blocked"
    assert "sealed" in second.receipt.reason
    assert second.forwarded_tcp == second.accepted_tcp == ()


def test_iterator_failure_is_terminal_and_cannot_be_retried():
    def broken():
        yield _http_request()[:4]
        raise RuntimeError("synthetic iterator failure")

    relay = ParentRelay(
        "127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits(),
    )
    first = relay.relay_tcp(broken(), ())
    assert first.receipt.status == "blocked"
    second = relay.relay_tcp((_http_request(),), (b"HTTP/1.1 200 OK\r\n\r\n",))
    assert second.receipt.status == "blocked"
    assert "sealed" in second.receipt.reason
    assert second.forwarded_tcp == ()


@pytest.mark.parametrize("callback", ["clock", "cpu_clock", "stopped"])
def test_relay_callback_failure_is_terminal(callback):
    def broken():
        raise RuntimeError("synthetic callback failure")

    kwargs = {callback: broken}
    relay = ParentRelay(
        "127.0.0.1", 80, HTTPGetRootValidator("127.0.0.1", 80), _limits(), **kwargs,
    )
    first = relay.relay_tcp((_http_request(),), ())
    assert first.receipt.status == "blocked"
    assert "infrastructure" in first.receipt.reason
    second = relay.relay_tcp((_http_request(),), (b"HTTP/1.1 200 OK\r\n\r\n",))
    assert second.receipt.status == "blocked"
    assert "sealed" in second.receipt.reason


def test_split_udp_is_blocked_and_seals_the_compound_action():
    relay = ParentRelay(
        "127.0.0.1", 445, SMBRelayValidator("127.0.0.1", 445),
        _limits(protocol_requests=2),
    )
    first = relay.relay_udp(())
    assert first.receipt.status == "blocked"
    assert "compound" in first.receipt.reason
    second = relay.relay_compound(
        outbound_tcp=(NMAP_SMB2_NEGOTIATE_REQUEST,), inbound_tcp=(_smb_response(),),
        outbound_udp=(_nbstat(),), inbound_udp=(_nbstat_response(),),
    )
    assert second.receipt.status == "blocked"
    assert "sealed" in second.receipt.reason
    assert second.forwarded_tcp == second.forwarded_udp == ()


def test_relay_foundation_has_no_connect_resolve_spawn_or_credential_api():
    root = Path(__file__).parents[1] / "cptc_harness"
    source = (root / "scanner_relay.py").read_text() + (root / "scanner_protocols.py").read_text()
    assert "import socket" not in source
    assert "import subprocess" not in source
    assert ".connect(" not in source
    assert "getaddrinfo" not in source
    assert "credential" not in source.lower()
