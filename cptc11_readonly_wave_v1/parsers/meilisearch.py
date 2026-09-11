"""Metadata-only Meilisearch health parser."""

from __future__ import annotations

from ..contracts import MeilisearchFacts
from . import ParserError, _strict_json_object


def parse_meilisearch(status_code: int, body: bytes) -> MeilisearchFacts:
    try:
        value = _strict_json_object(body, maximum=2048)
    except ParserError:
        return MeilisearchFacts(status_code, "malformed")
    state = value.get("status")
    if not isinstance(state, str):
        return MeilisearchFacts(status_code, "malformed")
    if state in {"available", "unavailable"}:
        return MeilisearchFacts(status_code, state)
    return MeilisearchFacts(status_code, "other")
