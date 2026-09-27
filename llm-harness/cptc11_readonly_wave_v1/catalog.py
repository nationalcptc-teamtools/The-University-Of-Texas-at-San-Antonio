"""Strict hash-anchored catalog for exactly four read-only actions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
from typing import Any

from .contracts import (
    GRANT_TYPE_ORDER, SIGNING_ALGORITHM_ORDER, HttpGetOperation, ReadOnlyAction,
    RedisPingOperation, WireBudget, _sealed_action,
)


PLAN_ID = "cptc11-readonly-wave-v1"
_CATALOG_RESOURCE = Path(__file__).parent / "resources/catalog-v1.json"
_RULES_RESOURCE = Path(__file__).parent / "resources/parser-rules-v1.json"
_CATALOG_FILE_SHA256 = "79855b3d9f6edd16af88a018db01af24f112474cd0e3bb318fae67c128ec0ad5"
_RULES_FILE_SHA256 = "02340aa9f4d26adafa075b308b67724bf3975e659a8f40e813f4d643e5eb27ba"
_MAX_RESOURCE = 64 * 1024
_cache: tuple[ReadOnlyAction, ...] | None = None
_EXPECTED_ACTIONS = (
    (
        1, "shorepass-traefik-version", "shorepass.traefik_public_version.v1",
        "cptc11-prod-shorepass", "10.0.1.99", 8080, "traefik",
        (1, 1, 512, 4096, 4096, 8000), "http_get",
        "GET /api/version HTTP/1.1\r\nHost: 10.0.1.99:8080\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        "3f55e7ee7ebb6fe0b6f8123468c89abc1a8e93c924456e2bd0a354a301b64e2f",
    ),
    (
        2, "crewcomms-redis-ping", "crewcomms.redis_ping.v1",
        "cptc11-prod-crewcomms", "10.0.1.14", 6379, "redis",
        (1, 1, 14, 128, 128, 5000), "redis_ping", "*1\r\n$4\r\nPING\r\n",
        "a43cb6a3b9d261112714d00e36b33106d1479eb1b3d8131a07684d4d477c5989",
    ),
    (
        3, "gps-keycloak-oidc-metadata", "gps.keycloak_oidc_metadata.v1",
        "cptc11-prod-gps", "10.0.1.13", 8180, "keycloak",
        (1, 1, 512, 16384, 16384, 8000), "http_get",
        "GET /realms/gps/.well-known/openid-configuration HTTP/1.1\r\nHost: 10.0.1.13:8180\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        "73d878866168bca13988d737cf0eef2b65806ec3d8be44a6b45c2fb17d4ddce5",
    ),
    (
        4, "penny-meilisearch-health", "penny.meilisearch_health.v1",
        "cptc11-prod-penny", "10.0.1.11", 7700, "meilisearch",
        (1, 1, 384, 2048, 2048, 8000), "http_get",
        "GET /health HTTP/1.1\r\nHost: 10.0.1.11:7700\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        "fa8c6e1974fc90afc4110f570ba2e90b8e81b417b9ecbb389d3b905a8f79391e",
    ),
)


class CatalogError(RuntimeError):
    pass


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise CatalogError("catalog contains duplicate fields")
        result[key] = value
    return result


def _read(path: Path, expected_sha256: str) -> dict[str, Any]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_size > _MAX_RESOURCE:
            raise CatalogError("catalog resource metadata is invalid")
        raw = path.read_bytes()
        after = path.lstat()
    except OSError:
        raise CatalogError("catalog resource is unavailable") from None
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or len(raw) != before.st_size:
        raise CatalogError("catalog resource changed during read")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise CatalogError("catalog resource digest differs")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _v: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise CatalogError("catalog resource is invalid") from None
    if not isinstance(value, dict):
        raise CatalogError("catalog resource is invalid")
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError):
        raise CatalogError("catalog canonical form is invalid") from None


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _build() -> tuple[ReadOnlyAction, ...]:
    rules = _read(_RULES_RESOURCE, _RULES_FILE_SHA256)
    if tuple(rules) != ("schema_version", "grant_types", "signing_algorithms", "rules_sha256"):
        raise CatalogError("parser rules schema differs")
    rules_projection = {name: rules[name] for name in ("schema_version", "grant_types", "signing_algorithms")}
    if (
        type(rules["schema_version"]) is not int
        or rules["schema_version"] != 1
        or rules["grant_types"] != list(GRANT_TYPE_ORDER)
        or rules["signing_algorithms"] != list(SIGNING_ALGORITHM_ORDER)
        or rules["rules_sha256"] != _digest(rules_projection)
    ):
        raise CatalogError("parser rules digest differs")
    value = _read(_CATALOG_RESOURCE, _CATALOG_FILE_SHA256)
    if tuple(value) != ("schema_version", "plan_id", "parser_rules_sha256", "actions", "catalog_sha256"):
        raise CatalogError("catalog schema differs")
    projection = {name: value[name] for name in ("schema_version", "plan_id", "parser_rules_sha256", "actions")}
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["plan_id"] != PLAN_ID
        or value["parser_rules_sha256"] != rules["rules_sha256"]
        or value["catalog_sha256"] != _digest(projection)
        or not isinstance(value["actions"], list)
        or len(value["actions"]) != 4
    ):
        raise CatalogError("catalog identity differs")
    actions: list[ReadOnlyAction] = []
    for raw, expected in zip(value["actions"], _EXPECTED_ACTIONS, strict=True):
        if not isinstance(raw, dict) or tuple(raw) != (
            "order", "action_id", "profile_id", "target_id", "host", "port",
            "parser_id", "budget", "operation", "profile_sha256",
        ):
            raise CatalogError("catalog action schema differs")
        profile = {name: raw[name] for name in raw if name != "profile_sha256"}
        budget_raw = raw["budget"]
        operation_raw = raw["operation"]
        if not isinstance(budget_raw, dict) or tuple(budget_raw) != (
            "max_connects", "max_requests", "max_tx_bytes", "max_rx_bytes",
            "max_capture_bytes", "timeout_ms",
        ):
            raise CatalogError("catalog budget schema differs")
        if not isinstance(operation_raw, dict) or tuple(operation_raw) != ("kind", "request", "request_sha256"):
            raise CatalogError("catalog operation schema differs")
        fixed = (
            raw["order"], raw["action_id"], raw["profile_id"], raw["target_id"],
            raw["host"], raw["port"], raw["parser_id"], tuple(budget_raw.values()),
            operation_raw["kind"], operation_raw["request"],
            operation_raw["request_sha256"],
        )
        if fixed != expected or raw["profile_sha256"] != _digest(profile):
            raise CatalogError("catalog action identity differs")
        try:
            request = operation_raw["request"].encode("ascii")
            operation_type = HttpGetOperation if operation_raw["kind"] == "http_get" else RedisPingOperation
            if operation_raw["kind"] not in {"http_get", "redis_ping"}:
                raise ValueError
            operation = operation_type(request, operation_raw["request_sha256"])
            if hashlib.sha256(request).hexdigest() != operation.request_sha256:
                raise ValueError
            action = _sealed_action(
                plan_id=PLAN_ID,
                action_id=raw["action_id"], profile_id=raw["profile_id"],
                target_id=raw["target_id"], order=raw["order"], host=raw["host"],
                port=raw["port"], operation=operation, budget=WireBudget(**budget_raw),
                parser_id=raw["parser_id"], profile_sha256=raw["profile_sha256"],
                catalog_sha256=value["catalog_sha256"],
            )
        except (AttributeError, TypeError, ValueError):
            raise CatalogError("catalog action value differs") from None
        actions.append(action)
    return tuple(actions)


def _actions() -> tuple[ReadOnlyAction, ...]:
    global _cache
    if _cache is None:
        _cache = _build()
    return _cache


def _clear_cache_for_tests() -> None:
    global _cache
    _cache = None


def plan_actions(plan_id: str) -> tuple[ReadOnlyAction, ...]:
    if plan_id != PLAN_ID:
        raise CatalogError("plan identifier is not admitted")
    return _actions()


def resolve_action(plan_id: str, action_id: str, profile_id: str) -> ReadOnlyAction:
    if plan_id != PLAN_ID or not isinstance(action_id, str) or not isinstance(profile_id, str):
        raise CatalogError("action identity is not admitted")
    matches = [
        action for action in _actions()
        if action.action_id == action_id and action.profile_id == profile_id
    ]
    if len(matches) != 1:
        raise CatalogError("action identity is not admitted")
    return matches[0]
