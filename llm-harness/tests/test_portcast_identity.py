from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from cptc_harness.assessment_contracts import ComponentIdentity
from cptc_harness.contracts import PolicyError
from cptc_harness.portcast_identity import (
    PORTCAST_PROFILE_ID,
    portcast_http_request_bytes,
    validate_portcast_identity_response,
)


FIXTURES = Path(__file__).parent / "fixtures" / "portcast"


def receipt(**changes):
    body = (FIXTURES / "jellyfin-10.10.7.json").read_bytes()
    value = {
        "status": "complete", "target_ipv4": "10.0.1.30", "target_port": 8096,
        "method": "GET", "path": "/System/Info/Public", "status_code": 200,
        "content_type": "application/json; charset=utf-8", "content_encoding": "identity",
        "truncated": False, "tcp_connects": 1, "protocol_requests": 1,
        "tx_bytes": len(portcast_http_request_bytes()), "rx_bytes": len(body),
        "redirects": 0, "retries": 0, "proxy_used": False,
        "authenticated": False, "request_body_bytes": 0,
    }
    value.update(changes)
    return value


def parse(name="jellyfin-10.10.7.json", **receipt_changes):
    return validate_portcast_identity_response(
        (FIXTURES / name).read_bytes(), receipt=receipt(**receipt_changes)
    )


def test_valid_response_returns_only_exact_component_identity():
    identity = parse()
    assert identity == ComponentIdentity(
        component_id="service:10.0.1.30:8096/jellyfin",
        target_id="cptc11-prod-portcast",
        ecosystem="semver",
        product="Jellyfin Server",
        version="10.10.7",
        provenance="banner",
    )
    assert not hasattr(identity, "server_name")
    assert not hasattr(identity, "server_id")
    assert not hasattr(identity, "raw_body")
    with pytest.raises(FrozenInstanceError):
        identity.version = "10.11.7"


def test_request_is_fixed_small_unauthenticated_get():
    request = portcast_http_request_bytes()
    assert request == (
        b"GET /System/Info/Public HTTP/1.1\r\n"
        b"Accept: application/json\r\n"
        b"Connection: close\r\n"
        b"Host: 10.0.1.30:8096\r\n\r\n"
    )
    assert 0 < len(request) <= 256
    assert b"Authorization" not in request and request.endswith(b"\r\n\r\n")


@pytest.mark.parametrize("name", ["jellyfin-duplicate-product.json", "jellyfin-wrong-version.json"])
def test_parser_rejects_duplicate_keys_and_identity_drift(name):
    with pytest.raises(PolicyError):
        parse(name)


@pytest.mark.parametrize("body", [b"", b"{", b"\xff", b'{"ProductName":"Jellyfin Server"}', b"[]", b'{"ProductName":NaN,"Version":"10.10.7"}'])
def test_parser_rejects_empty_truncated_encoding_and_shape_errors_without_body_reflection(body):
    with pytest.raises(PolicyError) as error:
        validate_portcast_identity_response(body, receipt=receipt(rx_bytes=len(body)))
    assert repr(body) not in str(error.value)


@pytest.mark.parametrize("changes", [
    {"status": "uncertain"}, {"target_ipv4": "10.0.1.31"}, {"target_port": 80},
    {"method": "POST"}, {"path": "/System/Info"}, {"status_code": 302},
    {"content_type": "text/html"}, {"content_encoding": "gzip"}, {"truncated": True},
    {"tcp_connects": 2}, {"protocol_requests": 2}, {"tx_bytes": 257},
    {"rx_bytes": 8193}, {"redirects": 1}, {"retries": 1}, {"proxy_used": True},
    {"authenticated": True}, {"request_body_bytes": 1}, {"extra": 1},
    {"tcp_connects": True}, {"protocol_requests": True}, {"redirects": False},
    {"retries": False}, {"proxy_used": 0}, {"authenticated": 0},
    {"truncated": 0}, {"request_body_bytes": False},
])
def test_receipt_mismatch_or_budget_drift_is_rejected(changes):
    with pytest.raises(PolicyError):
        parse(**changes)


def test_parser_rejects_over_limit_body_and_receipt_byte_contradiction():
    with pytest.raises(PolicyError, match="allowance"):
        validate_portcast_identity_response(b" " * 8193, receipt=receipt(rx_bytes=8193))
    body_bytes = len((FIXTURES / "jellyfin-10.10.7.json").read_bytes())
    for reported_bytes in (body_bytes - 1, body_bytes + 1):
        with pytest.raises(PolicyError, match="receipt"):
            parse(rx_bytes=reported_bytes)
