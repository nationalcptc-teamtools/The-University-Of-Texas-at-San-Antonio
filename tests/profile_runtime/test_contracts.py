from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib

import pytest

from cptc_harness.profile_runtime.contracts import (
    Http11RequestV1,
    MysqlGreetingV1,
    ProfileBudget,
    ProfileContractError,
    RedisPingV1,
    TlsHelloV1,
    WireCounters,
    parse_operation,
)


def _budget() -> dict[str, object]:
    return {
        "tcp_connects": 1,
        "udp_datagrams": 0,
        "tls_handshakes": 0,
        "protocol_requests": 1,
        "tx_bytes": 512,
        "rx_bytes": 4096,
        "capture_bytes": 8192,
        "timeout_s": 8.0,
        "cpu_s": 4.0,
        "process_limit": 1,
        "auth_attempts": 0,
    }


def _http() -> dict[str, object]:
    return {
        "kind": "http11_request_v1",
        "address": "10.0.1.99",
        "port": 8080,
        "tls": False,
        "server_name": None,
        "certificate_sha256": None,
        "method": "GET",
        "path": "/api/version",
        "headers": [
            ["Accept", "application/json"],
            ["Connection", "close"],
            ["Host", "10.0.1.99:8080"],
        ],
    }


def test_http_contract_is_exact_immutable_and_has_no_runtime_escape_fields():
    operation = parse_operation(_http())
    assert isinstance(operation, Http11RequestV1)
    assert operation.method == "GET"
    assert operation.path == "/api/version"
    assert operation.headers == (
        ("Accept", "application/json"),
        ("Connection", "close"),
        ("Host", "10.0.1.99:8080"),
    )
    assert len(operation.sha256) == 64
    with pytest.raises(FrozenInstanceError):
        operation.path = "/other"

    for field, value in (
        ("url", "http://example.invalid/"),
        ("body", "x"),
        ("proxy", "http://127.0.0.1:8080"),
        ("redirects", True),
        ("retries", 1),
        ("command", ["sh"]),
        ("environment", {"HTTP_PROXY": "x"}),
        ("output_path", "/tmp/result"),
    ):
        changed = dict(_http())
        changed[field] = value
        with pytest.raises(ProfileContractError, match="field"):
            parse_operation(changed)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("address", "example.invalid"),
        ("address", "10.0.1.099"),
        ("method", "POST"),
        ("path", "http://10.0.1.99/api/version"),
        ("path", "/api/version?detail=1"),
        ("path", "/api/version#fragment"),
        ("headers", [["Authorization", "Bearer x"]]),
        ("headers", [["Cookie", "session=x"]]),
        ("headers", [["Host", "ok\r\nX-Test: x"]]),
    ),
)
def test_http_contract_rejects_unbounded_or_secret_bearing_inputs(field, replacement):
    changed = dict(_http())
    changed[field] = replacement
    with pytest.raises(ProfileContractError):
        parse_operation(changed)


@pytest.mark.parametrize("field", ("address", "method"))
@pytest.mark.parametrize("replacement", ([], {}))
def test_http_contract_rejects_unhashable_scalar_types_through_contract_error(
    field, replacement
):
    changed = dict(_http())
    changed[field] = replacement
    with pytest.raises(ProfileContractError):
        parse_operation(changed)


def test_tls_http_requires_a_server_name_and_certificate_pin():
    value = _http()
    value.update(
        tls=True,
        port=443,
        server_name="probe-a.rooms.allports.tours",
        certificate_sha256=hashlib.sha256(b"certificate").hexdigest(),
        headers=[
            ["Accept", "application/json"],
            ["Connection", "close"],
            ["Host", "probe-a.rooms.allports.tours"],
        ],
    )
    operation = parse_operation(value)
    assert isinstance(operation, Http11RequestV1)
    assert operation.tls is True
    assert operation.server_name == "probe-a.rooms.allports.tours"

    for field, replacement in (
        ("server_name", None),
        ("server_name", "*.allports.tours"),
        ("certificate_sha256", None),
        ("certificate_sha256", "0" * 63),
    ):
        changed = dict(value)
        changed[field] = replacement
        with pytest.raises(ProfileContractError):
            parse_operation(changed)


def test_protocol_contracts_have_no_caller_selected_payload():
    tls = parse_operation(
        {
            "kind": "tls_hello_v1",
            "address": "10.0.1.11",
            "port": 443,
            "server_name": "penny.allports.tours",
            "certificate_sha256": "a" * 64,
        }
    )
    redis = parse_operation(
        {"kind": "redis_ping_v1", "address": "10.0.1.14", "port": 6379}
    )
    mysql = parse_operation(
        {"kind": "mysql_greeting_v1", "address": "10.0.1.13", "port": 3306}
    )
    assert isinstance(tls, TlsHelloV1)
    assert isinstance(redis, RedisPingV1)
    assert isinstance(mysql, MysqlGreetingV1)

    for value in (
        {"kind": "redis_ping_v1", "address": "10.0.1.14", "port": 6379, "payload": "INFO"},
        {"kind": "mysql_greeting_v1", "address": "10.0.1.13", "port": 3306, "client_packet": "x"},
        {"kind": "raw_socket_v1", "address": "10.0.1.13", "port": 1},
    ):
        with pytest.raises(ProfileContractError):
            parse_operation(value)


def test_budget_and_wire_counters_are_strict_and_wire_use_cannot_exceed_reservation():
    budget = ProfileBudget.from_dict(_budget())
    counters = WireCounters.from_dict(
        {
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "tls_handshakes": 0,
            "protocol_requests": 1,
            "tx_bytes": 120,
            "rx_bytes": 800,
            "capture_bytes": 800,
        }
    )
    counters.validate_against(budget)

    over = dict(counters.as_dict())
    over["rx_bytes"] = 4097
    with pytest.raises(ProfileContractError, match="budget"):
        WireCounters.from_dict(over).validate_against(budget)

    for field, replacement in (
        ("auth_attempts", 1),
        ("process_limit", 2),
        ("timeout_s", 61),
        ("tcp_connects", True),
    ):
        changed = _budget()
        changed[field] = replacement
        with pytest.raises(ProfileContractError):
            ProfileBudget.from_dict(changed)


def test_capture_count_cannot_exceed_received_bytes():
    with pytest.raises(ProfileContractError, match="capture"):
        WireCounters.from_dict(
            {
                "tcp_connects": 1,
                "udp_datagrams": 0,
                "tls_handshakes": 0,
                "protocol_requests": 1,
                "tx_bytes": 100,
                "rx_bytes": 200,
                "capture_bytes": 201,
            }
        )
