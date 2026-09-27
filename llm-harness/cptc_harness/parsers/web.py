"""Offline parser for bounded web captures."""
from __future__ import annotations

from ..contracts import Observation, ParseBatch, ScopeSpec, SourceRef
from .common import bounded_int, bounded_string, finish, in_scope, issue, json_records, load_json, start, text

SAFE_HEADERS = {
    "strict-transport-security": "hsts",
    "content-security-policy": "csp",
    "x-content-type-options": "content_type_options",
    "x-frame-options": "frame_options",
    "referrer-policy": "referrer_policy",
    "permissions-policy": "permissions_policy",
    "set-cookie": "set_cookie",
}


def _header_names(value: object) -> set[str]:
    if isinstance(value, dict):
        return {str(k).lower() for k in value if isinstance(k, str)}
    if isinstance(value, list):
        return {str(item).split(":", 1)[0].strip().lower() for item in value if isinstance(item, str)}
    return set()


def parse_web_capture(raw: bytes | str, source: SourceRef | str) -> ParseBatch:
    payload, source_ref_value, issues = start(raw, source)
    observations: list[Observation] = []
    try:
        records = json_records(load_json(payload))
    except (ValueError, TypeError):
        records = []
        for number, line in enumerate(text(payload).splitlines()[:2048], 1):
            fields = [part.strip() for part in line.split("|", 3)]
            if len(fields) == 4:
                records.append({"target": fields[0], "status": fields[1], "headers": fields[2], "path": fields[3]})
            elif line.strip():
                issues.append(issue("malformed_record", number))
    for number, record in enumerate(records, 1):
        target = bounded_string(record.get("target"))
        if target is None:
            issues.append(issue("invalid_record", number))
            continue
        status = bounded_int(record.get("status"), 100, 599)
        if status is None:
            issues.append(issue("invalid_record", number))
            continue
        headers = _header_names(record.get("headers"))
        present = tuple(sorted(SAFE_HEADERS[name] for name in headers if name in SAFE_HEADERS))
        facts: dict[str, object] = {"status": status, "headers_present": present,
                                    "redirect": 300 <= status < 400}
        path = bounded_string(record.get("path"), maximum=128)
        if path is not None and path.startswith("/") and ".." not in path:
            facts["path_depth"] = path.count("/")
        state = "candidate" if status < 400 and "hsts" not in present and target.startswith("https://") else "observed"
        observations.append(Observation("web", target, "web_headers", state, facts, source_ref_value))
        if status in {200, 401, 403} and "set_cookie" in present:
            observations.append(Observation("web", target, "web_session", "candidate", {
                "status": status, "cookie_header_present": True,
            }, source_ref_value))
    if not records and payload.strip() and not issues:
        issues.append(issue("malformed_record"))
    return finish(observations, issues)
