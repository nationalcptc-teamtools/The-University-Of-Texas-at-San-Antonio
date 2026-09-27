"""Strict bounded JSON support shared by pure read-only parsers."""

from __future__ import annotations

import json
import math
from typing import Any


class ParserError(ValueError):
    pass


_MAX_NUMBER_CHARACTERS = 128
_MAX_JSON_INTEGER = (1 << 63) - 1


def _bounded_integer(value: str) -> int:
    if len(value) > _MAX_NUMBER_CHARACTERS:
        raise ParserError("JSON integer is oversized")
    try:
        parsed = int(value)
    except (ValueError, OverflowError):
        raise ParserError("JSON integer is invalid") from None
    if not -_MAX_JSON_INTEGER - 1 <= parsed <= _MAX_JSON_INTEGER:
        raise ParserError("JSON integer is out of range")
    return parsed


def _bounded_float(value: str) -> float:
    if len(value) > _MAX_NUMBER_CHARACTERS:
        raise ParserError("JSON number is oversized")
    try:
        parsed = float(value)
    except (ValueError, OverflowError):
        raise ParserError("JSON number is invalid") from None
    if not math.isfinite(parsed):
        raise ParserError("JSON number is nonfinite")
    return parsed


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ParserError("JSON contains duplicate fields")
        result[key] = value
    return result


def _strict_json_object(raw: bytes, *, maximum: int, maximum_depth: int = 16) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > maximum or raw.startswith(b"\xef\xbb\xbf"):
        raise ParserError("JSON bytes are invalid")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_bounded_integer,
            parse_float=_bounded_float,
            parse_constant=lambda _v: (_ for _ in ()).throw(ParserError("nonfinite JSON number")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, OverflowError):
        raise ParserError("JSON is invalid") from None
    if not isinstance(value, dict):
        raise ParserError("JSON top level must be an object")
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > maximum_depth:
            raise ParserError("JSON nesting is excessive")
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ParserError("JSON field name is invalid")
            stack.extend((child, depth + 1) for child in item.values() if isinstance(child, (dict, list)))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item if isinstance(child, (dict, list)))
    return value


from .keycloak import parse_keycloak
from .meilisearch import parse_meilisearch
from .redis import parse_redis
from .traefik import parse_traefik


__all__ = (
    "ParserError", "parse_keycloak", "parse_meilisearch", "parse_redis",
    "parse_traefik",
)
