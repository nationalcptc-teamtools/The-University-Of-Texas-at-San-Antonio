"""Metadata-only Traefik version parser."""

from __future__ import annotations

from ..contracts import TraefikFacts, _MAX_SEMVER_LENGTH, _NORMALIZED_SEMVER
from . import _strict_json_object


def parse_traefik(status_code: int, body: bytes) -> TraefikFacts:
    value = _strict_json_object(body, maximum=4096)
    version = value.get("Version")
    if not isinstance(version, str):
        return TraefikFacts(status_code, None, False)
    normalized = version[1:] if version.startswith("v") else version
    if (
        len(normalized) > _MAX_SEMVER_LENGTH
        or _NORMALIZED_SEMVER.fullmatch(normalized) is None
    ):
        return TraefikFacts(status_code, None, False)
    return TraefikFacts(status_code, normalized, True)
