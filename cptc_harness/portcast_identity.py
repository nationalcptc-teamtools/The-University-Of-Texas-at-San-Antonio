"""Typed PortCast identity parsing derived from the sealed profile catalog."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .assessment_contracts import ComponentIdentity
from .contracts import PolicyError
from .profile_runtime.catalog import (
    PROFILE_CATALOG_SHA256,
    ProfileCatalog,
    SealedProfile,
    load_catalog,
    load_profile,
    validate_sealed_profile,
)
from .profile_runtime.contracts import Http11RequestV1
from .profile_runtime.worker import build_http11_request


PORTCAST_PROFILE_ID = "web.http_jellyfin_public_identity"
PORTCAST_MODULE_ID = "web.portcast_identity"
PORTCAST_TARGET_IPV4 = "10.0.1.30"
PORTCAST_TARGET_PORT = 8096
PORTCAST_PATH = "/System/Info/Public"
PORTCAST_CANONICAL_URL = "http://10.0.1.30:8096/System/Info/Public"
EXPECTED_PORTCAST_CATALOG_SHA256 = PROFILE_CATALOG_SHA256

_MAX_BODY_BYTES = 8192
_RECEIPT_FIELDS = {
    "status", "target_ipv4", "target_port", "method", "path", "status_code",
    "content_type", "content_encoding", "truncated", "tcp_connects",
    "protocol_requests", "tx_bytes", "rx_bytes", "redirects", "retries",
    "proxy_used", "authenticated", "request_body_bytes",
}


@dataclass(frozen=True, slots=True)
class PortcastProfileView:
    """Read-only compatibility view; the sealed catalog remains authoritative."""

    sealed: SealedProfile

    @property
    def profile_id(self) -> str:
        return self.sealed.profile_id

    @property
    def module_id(self) -> str:
        return self.sealed.module_id

    @property
    def mode(self) -> str:
        return self.sealed.admission

    @property
    def target_ipv4(self) -> str:
        return self.operation.address

    @property
    def target_port(self) -> int:
        return self.operation.port

    @property
    def method(self) -> str:
        return self.operation.method

    @property
    def path(self) -> str:
        return self.operation.path

    @property
    def operation(self) -> Http11RequestV1:
        operation = self.sealed.operation
        if not isinstance(operation, Http11RequestV1):
            raise PolicyError("PortCast operation differs from reviewed profile")
        return operation

    @property
    def budget(self):
        return self.sealed.budget


def get_portcast_profile(
    profile_id: str = PORTCAST_PROFILE_ID, _path: Any | None = None
) -> PortcastProfileView:
    """Return the only sealed PortCast profile; no aliases are accepted."""

    if _path is not None:
        raise PolicyError("alternate PortCast profile catalogs are not admitted")
    try:
        profile = validate_sealed_profile(load_profile(profile_id))
    except Exception:
        raise PolicyError("unknown PortCast profile") from None
    operation = profile.operation
    if (
        profile.module_id != PORTCAST_MODULE_ID
        or profile.target_id != "cptc11-prod-portcast"
        or profile.admission != "live_admitted"
        or not isinstance(operation, Http11RequestV1)
        or operation.address != PORTCAST_TARGET_IPV4
        or operation.port != PORTCAST_TARGET_PORT
        or operation.method != "GET"
        or operation.path != PORTCAST_PATH
        or operation.tls
    ):
        raise PolicyError("PortCast profile differs from the reviewed profile")
    return PortcastProfileView(profile)


def load_portcast_profile_catalog(path: Any | None = None) -> ProfileCatalog:
    if path is not None:
        raise PolicyError("alternate PortCast profile catalogs are not admitted")
    return load_catalog()


def portcast_http_request_bytes() -> bytes:
    return build_http11_request(get_portcast_profile().operation)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def parse_portcast_identity_body(body: bytes, *, action_id: str = "") -> ComponentIdentity:
    """Retain only the exact public component identity from strict JSON."""

    if type(body) is not bytes or not 0 < len(body) <= _MAX_BODY_BYTES:
        raise PolicyError("PortCast response exceeds its collection allowance")
    try:
        value = json.loads(
            body.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise PolicyError("PortCast response is not valid strict JSON") from None
    if not isinstance(value, dict):
        raise PolicyError("PortCast response identity shape differs")
    if value.get("ProductName") != "Jellyfin Server":
        raise PolicyError("PortCast response product identity differs")
    if value.get("Version") != "10.10.7":
        raise PolicyError("PortCast response version identity differs")
    return ComponentIdentity(
        component_id="service:10.0.1.30:8096/jellyfin",
        target_id="cptc11-prod-portcast",
        ecosystem="semver",
        product="Jellyfin Server",
        version="10.10.7",
        source_actions=(action_id,) if action_id else (),
        provenance="banner",
    )


def _validate_legacy_receipt(receipt: Any, body_bytes: int) -> None:
    """Compatibility validation for saved lab captures; it grants no dispatch."""

    profile = get_portcast_profile()
    operation = profile.operation
    if not isinstance(receipt, Mapping) or set(receipt) != _RECEIPT_FIELDS:
        raise PolicyError("PortCast wire receipt shape differs")
    integer_fields = (
        "target_port", "status_code", "tcp_connects", "protocol_requests",
        "tx_bytes", "rx_bytes", "redirects", "retries", "request_body_bytes",
    )
    boolean_fields = ("truncated", "proxy_used", "authenticated")
    text_fields = (
        "status", "target_ipv4", "method", "path", "content_type",
        "content_encoding",
    )
    if (
        any(type(receipt.get(key)) is not int for key in integer_fields)
        or any(type(receipt.get(key)) is not bool for key in boolean_fields)
        or any(type(receipt.get(key)) is not str for key in text_fields)
    ):
        raise PolicyError("PortCast wire receipt types differ")
    exact = {
        "status": "complete",
        "target_ipv4": operation.address,
        "target_port": operation.port,
        "method": operation.method,
        "path": operation.path,
        "status_code": 200,
        "content_encoding": "identity",
        "truncated": False,
        "tcp_connects": 1,
        "protocol_requests": 1,
        "redirects": 0,
        "retries": 0,
        "proxy_used": False,
        "authenticated": False,
        "request_body_bytes": 0,
    }
    if any(receipt.get(key) != expected for key, expected in exact.items()):
        raise PolicyError("PortCast wire receipt differs")
    if receipt["content_type"] not in {
        "application/json", "application/json; charset=utf-8"
    }:
        raise PolicyError("PortCast response content type differs")
    if (
        receipt["tx_bytes"] != len(portcast_http_request_bytes())
        or receipt["rx_bytes"] != body_bytes
        or receipt["rx_bytes"] > profile.budget.rx_bytes
        or receipt["tx_bytes"] > profile.budget.tx_bytes
    ):
        raise PolicyError("PortCast wire receipt byte accounting differs")


def validate_portcast_identity_response(
    body: bytes,
    *,
    receipt: Mapping[str, Any],
    profile: SealedProfile | None = None,
) -> ComponentIdentity:
    """Parse a saved body only when its strict compatibility receipt matches."""

    exact = get_portcast_profile().sealed
    if profile is not None and profile != exact:
        raise PolicyError("PortCast profile differs from the reviewed profile")
    if type(body) is not bytes or not 0 < len(body) <= _MAX_BODY_BYTES:
        raise PolicyError("PortCast response exceeds its collection allowance")
    _validate_legacy_receipt(receipt, len(body))
    return parse_portcast_identity_body(body)


__all__ = (
    "EXPECTED_PORTCAST_CATALOG_SHA256",
    "PORTCAST_CANONICAL_URL",
    "PORTCAST_MODULE_ID",
    "PORTCAST_PATH",
    "PORTCAST_PROFILE_ID",
    "PORTCAST_TARGET_IPV4",
    "PORTCAST_TARGET_PORT",
    "get_portcast_profile",
    "load_portcast_profile_catalog",
    "parse_portcast_identity_body",
    "portcast_http_request_bytes",
    "validate_portcast_identity_response",
)
