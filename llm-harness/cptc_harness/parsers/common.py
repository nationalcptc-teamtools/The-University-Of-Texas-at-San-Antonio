"""Small, fail-closed helpers shared by offline import parsers.

Parsers deliberately copy only a small set of typed fields from an import.  A
raw import is evidence for a human review, not a general model context.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Iterable
from urllib.parse import urlsplit

from ..contracts import Observation, ParseBatch, ParseIssue, ScopeSpec, SourceRef

MAX_IMPORT = 2 * 1024 * 1024
MAX_RECORDS = 2048
MAX_STRING = 256


def raw_bytes(raw: bytes | bytearray | str) -> bytes:
    if isinstance(raw, str):
        return raw.encode("utf-8", "replace")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    raise TypeError("raw import must be bytes or text")


def source_ref(source: SourceRef | str, raw: bytes) -> SourceRef:
    if isinstance(source, SourceRef):
        return source
    return SourceRef(source_id=str(source), sha256=hashlib.sha256(raw).hexdigest())


def text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def load_json(raw: bytes) -> object:
    return json.loads(text(raw))


def bounded_string(value: object, *, maximum: int = MAX_STRING) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    return value


def bounded_int(value: object, minimum: int = 0, maximum: int = 65535) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        return None
    return value


def host_from_target(value: object) -> str | None:
    candidate = bounded_string(value)
    if candidate is None:
        return None
    try:
        parsed = urlsplit(candidate if "://" in candidate else "//" + candidate)
        host = parsed.hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def in_scope(target: object, scope: ScopeSpec) -> bool:
    host = host_from_target(target)
    if host is None:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        allowed_hosts = {
            h.encode("idna").decode("ascii").lower()
            for h in scope.allowed_hosts
            if isinstance(h, str)
        }
        return host in allowed_hosts
    try:
        allowed = tuple(ipaddress.ip_network(c, strict=False) for c in scope.allowed_cidrs)
        excluded = tuple(ipaddress.ip_network(c, strict=False) for c in scope.excluded_cidrs)
    except ValueError:
        return False
    return any(ip in network for network in allowed) and not any(ip in network for network in excluded)


def start(raw: bytes | bytearray | str, source: SourceRef | str) -> tuple[bytes, SourceRef, list[ParseIssue]]:
    payload = raw_bytes(raw)
    source_value = source_ref(source, payload)
    issues: list[ParseIssue] = []
    if len(payload) > MAX_IMPORT:
        issues.append(ParseIssue("oversized_input", "import exceeds the offline parser limit"))
        payload = payload[:MAX_IMPORT]
    return payload, source_value, issues


def finish(observations: Iterable[Observation], issues: Iterable[ParseIssue]) -> ParseBatch:
    unique: list[Observation] = []
    seen: set[tuple[object, ...]] = set()
    duplicates = 0
    for observation in observations:
        key = (observation.track, observation.target, observation.check_id,
               observation.state, json.dumps(observation.facts, sort_keys=True, separators=(",", ":")))
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(observation)
        if len(unique) >= MAX_RECORDS:
            break
    return ParseBatch(tuple(unique), tuple(issues), duplicates)


def issue(code: str, record: int | None = None) -> ParseIssue:
    return ParseIssue(code, code.replace("_", " "), record)


def json_records(value: object) -> list[dict[str, object]]:
    if isinstance(value, dict):
        records = value.get("records", value.get("observations", [value]))
    else:
        records = value
    if not isinstance(records, list):
        return []
    return [item for item in records[:MAX_RECORDS] if isinstance(item, dict)]
