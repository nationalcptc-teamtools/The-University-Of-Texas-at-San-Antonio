"""Metadata-only Keycloak OIDC discovery parser."""

from __future__ import annotations

from ..contracts import GRANT_TYPE_ORDER, SIGNING_ALGORITHM_ORDER, KeycloakFacts
from . import ParserError, _strict_json_object


GRANT_TYPES = GRANT_TYPE_ORDER
SIGNING_ALGORITHMS = SIGNING_ALGORITHM_ORDER


def _issuer(value: object) -> tuple[str, bool]:
    if value is None:
        return "missing", False
    if not isinstance(value, str):
        raise ParserError("issuer type is invalid")
    marker = value.find("://")
    if marker <= 0:
        return "other", False
    scheme = value[:marker].lower()
    remainder = value[marker + 3 :]
    slash = remainder.find("/")
    path = remainder[slash:] if slash >= 0 else ""
    path = path.split("?", 1)[0].split("#", 1)[0]
    return (scheme if scheme in {"http", "https"} else "other"), path == "/realms/gps"


def _known(value: dict[str, object], field: str, allowed: tuple[str, ...]) -> tuple[bool, tuple[str, ...], bool]:
    if field not in value:
        return False, (), False
    items = value[field]
    if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
        raise ParserError(f"{field} type is invalid")
    present = set(items)
    return True, tuple(item for item in allowed if item in present), any(item not in allowed for item in items)


def parse_keycloak(status_code: int, body: bytes) -> KeycloakFacts:
    value = _strict_json_object(body, maximum=16384)
    scheme, path_match = _issuer(value.get("issuer"))
    grants_present, grants, unknown_grant = _known(value, "grant_types_supported", GRANT_TYPES)
    signing_present, signing, unknown_signing = _known(
        value, "id_token_signing_alg_values_supported", SIGNING_ALGORITHMS
    )
    return KeycloakFacts(
        status_code, path_match, scheme, grants_present, grants, unknown_grant,
        signing_present, signing, unknown_signing,
    )
