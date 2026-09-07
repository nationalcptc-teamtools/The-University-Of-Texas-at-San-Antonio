"""Strict model skill envelopes and compact typed context helpers."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Literal

from .contracts import PolicyError

MAX_CONTEXT_BYTES = 8192
MAX_DECISION_BYTES = 2048
_FORBIDDEN = {"approval_id", "source", "policy", "classification", "credentials", "cookies", "tokens", "keys"}


@dataclass(frozen=True)
class SkillEnvelope:
    action: Literal["action", "ask_human", "finish"]
    module_id: str | None = None
    args: dict[str, Any] | None = None
    message: str | None = None
    status: str | None = None


def _json_object(raw: bytes | str) -> dict[str, Any]:
    if isinstance(raw, str):
        payload = raw.encode("utf-8", "strict")
    elif isinstance(raw, bytes):
        payload = raw
    else:
        raise PolicyError("skill envelope must be JSON text")
    if not payload or len(payload) > MAX_DECISION_BYTES:
        raise PolicyError("skill envelope exceeds decision allowance")
    try:
        decoded = payload.decode("utf-8", "strict")
        def reject_duplicates(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise PolicyError("skill envelope contains duplicate fields")
                result[key] = item
            return result
        def reject_constant(value):
            raise PolicyError("non-finite JSON is not admitted")
        value = json.loads(decoded, object_pairs_hook=reject_duplicates,
                           parse_constant=reject_constant)
    except PolicyError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise PolicyError("skill envelope is not complete JSON") from None
    if not isinstance(value, dict):
        raise PolicyError("skill envelope must be an object")
    return value


def parse_envelope(raw: bytes | str, *, allowed_module_ids: tuple[str, ...] | None = None) -> SkillEnvelope:
    value = _json_object(raw)
    if set(value) & _FORBIDDEN:
        raise PolicyError("skill envelope contains a trusted field")
    action = value.get("action")
    if action == "action":
        if set(value) != {"action", "module_id", "args"}:
            raise PolicyError("action envelope has unknown or missing fields")
        module_id, args = value.get("module_id"), value.get("args")
        if not isinstance(module_id, str) or not module_id or len(module_id) > 128:
            raise PolicyError("action envelope has an invalid module")
        if allowed_module_ids is not None and module_id not in allowed_module_ids:
            raise PolicyError("action module is not allowlisted")
        if not isinstance(args, dict):
            raise PolicyError("action arguments must be an object")
        return SkillEnvelope("action", module_id=module_id, args=args)
    if action == "ask_human":
        if set(value) != {"action", "message"} or not isinstance(value.get("message"), str):
            raise PolicyError("ask-human envelope has unknown or missing fields")
        if not value["message"].strip() or len(value["message"].encode()) > MAX_DECISION_BYTES:
            raise PolicyError("ask-human message exceeds decision allowance")
        return SkillEnvelope("ask_human", message=value["message"])
    if action == "finish":
        if set(value) != {"action", "status"} or value.get("status") not in {"complete", "blocked", "uncertain", "stopped"}:
            raise PolicyError("finish envelope has unknown or missing fields")
        return SkillEnvelope("finish", status=value["status"])
    raise PolicyError("skill envelope action is not admitted")


def parse_skill(raw: bytes | str, *, allowed_module_ids: tuple[str, ...] | None = None) -> SkillEnvelope:
    return parse_envelope(raw, allowed_module_ids=allowed_module_ids)


def compact_context(facts: dict[str, Any], limit: int = MAX_CONTEXT_BYTES) -> bytes:
    """Serialize typed facts deterministically within the context budget."""
    if not isinstance(facts, dict) or not isinstance(limit, int) or limit < 128:
        raise PolicyError("invalid context budget")
    clean = {key: facts[key] for key in sorted(facts) if isinstance(key, str) and key not in _FORBIDDEN}
    removed = []
    source_hash = hashlib.sha256(json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
    while clean:
        value = {"facts": clean, "omitted_fields": removed, "source_sha256": source_hash} if removed else clean
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        if len(encoded) <= limit:
            return encoded
        removed.append(next(reversed(clean)))
        clean.pop(removed[-1])
    marker = json.dumps({"truncated": True, "sha256": hashlib.sha256(
        json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()).hexdigest()},
        separators=(",", ":"), ensure_ascii=True).encode()
    if len(marker) > limit:
        raise PolicyError("context budget too small")
    return marker


def decision_excerpt(text: str | bytes, limit: int = MAX_DECISION_BYTES) -> bytes:
    """Bound an already approved excerpt; this function does not declassify it."""
    if not isinstance(limit, int) or limit < 1:
        raise PolicyError("invalid decision budget")
    payload = text.encode("utf-8", "strict") if isinstance(text, str) else bytes(text)
    return payload[:limit]


__all__ = ["SkillEnvelope", "compact_context", "decision_excerpt", "parse_envelope", "parse_skill"]
