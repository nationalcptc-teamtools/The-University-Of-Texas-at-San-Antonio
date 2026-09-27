"""Recursive, fail-closed validation for model-visible data."""
from __future__ import annotations
import json
import re
from typing import Any
from .contracts import PolicyError

MAX_DEPTH, MAX_ITEMS, MAX_STRING_BYTES = 8, 256, 4096
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,95}\Z")
_SENSITIVE = frozenset({"secret", "secrets", "raw", "body", "bodies", "header", "headers", "cookie", "cookies", "session", "sessions", "credential", "credentials", "password", "token", "tokens", "authorization", "api_key", "apikey", "private_key", "evidence", "response_base64"})
_FIXTURE_IDS = frozenset({"fixture", "item", "e", "facts"})

def _safe_key(key: object) -> str:
    if not isinstance(key, str) or not _KEY.fullmatch(key): raise PolicyError("model-visible data has an invalid field name")
    pieces = tuple(part.lower() for part in re.split(r"[_.-]", key))
    if any(part in _SENSITIVE for part in pieces) or "_".join(pieces) in _SENSITIVE: raise PolicyError("model-visible data contains a protected field")
    return key

def validate_value(value: Any, *, maximum_bytes: int, depth: int = 0, _items: list[int] | None = None) -> None:
    if not isinstance(maximum_bytes, int) or not 1 <= maximum_bytes <= 32768: raise PolicyError("invalid model-visible allowance")
    if depth > MAX_DEPTH: raise PolicyError("model-visible data nesting exceeds allowance")
    items = _items if _items is not None else [0]; items[0] += 1
    if items[0] > MAX_ITEMS: raise PolicyError("model-visible data has too many values")
    if value is None or type(value) in (bool, int): return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")): raise PolicyError("model-visible data contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8", "strict")) > MAX_STRING_BYTES: raise PolicyError("model-visible text field exceeds allowance")
        return
    if isinstance(value, list):
        if len(value) > 64: raise PolicyError("model-visible list exceeds allowance")
        for item in value: validate_value(item, maximum_bytes=maximum_bytes, depth=depth + 1, _items=items)
        return
    if isinstance(value, dict):
        if len(value) > 64: raise PolicyError("model-visible object exceeds allowance")
        for key, item in value.items(): _safe_key(key); validate_value(item, maximum_bytes=maximum_bytes, depth=depth + 1, _items=items)
        return
    raise PolicyError("model-visible data must be JSON")

def encoded_value(value: Any, *, maximum_bytes: int) -> bytes:
    validate_value(value, maximum_bytes=maximum_bytes)
    try: encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError): raise PolicyError("model-visible data must be canonical JSON") from None
    if len(encoded) > maximum_bytes: raise PolicyError("model-visible data exceeds allowance")
    return encoded

def reject_protected(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH: raise PolicyError("model-visible data nesting exceeds allowance")
    if isinstance(value, dict):
        for key, item in value.items(): _safe_key(key); reject_protected(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value: reject_protected(item, depth=depth + 1)
    elif value is not None and type(value) not in (str, bool, int, float): raise PolicyError("model-visible data must be JSON")

def validate_items(items: object, *, maximum_bytes: int) -> tuple:
    if not isinstance(items, tuple) or not items or len(items) > 16: raise PolicyError("provider disclosure requires a bounded item tuple")
    result = []
    for item in items:
        fields = getattr(item, "__dict__", None)
        if not isinstance(fields, dict) or set(fields) != {"item_id", "classification", "value", "source_hash", "excerpt_approval", "schema_id"}: raise PolicyError("provider disclosure contains unknown fields")
        if not isinstance(item.item_id, str) or not _KEY.fullmatch(item.item_id): raise PolicyError("provider disclosure item identifier is invalid")
        _validate_item_shape(item.item_id, item.value, item.classification, item.schema_id, maximum_bytes)
        result.append(item)
    return tuple(result)

def _exact_object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise PolicyError(label + " has unknown or missing fields")
    return value

def _trusted_facts(value: object, schema_id: object) -> None:
    if value == {} and schema_id == "": return
    if isinstance(value, dict) and set(value) == {"truncated", "sha256"} and value.get("truncated") is True and isinstance(value.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]): return
    if not isinstance(schema_id, str) or not _KEY.fullmatch(schema_id): raise PolicyError("provider facts require a trusted module schema")
    from .registry import build_registry
    spec = build_registry().get(schema_id)
    if spec is None: raise PolicyError("provider facts schema is not registered")
    from .contracts import validate_schema
    validate_schema(value, spec.output_schema)

def _validate_item_shape(item_id: str, value: Any, classification: object, schema_id: object, maximum_bytes: int) -> None:
    """Bind production disclosures to schemas; generic objects are fixture-only."""
    # An excerpt is a human-approved text selection only.  It may never take
    # the workflow/result structured branch merely because its outer category
    # was changed.
    if classification == "approved_excerpt":
        fixture_item = item_id in _FIXTURE_IDS or (item_id.startswith("part") and item_id[4:].isdigit())
        if not fixture_item or not isinstance(value, str) or schema_id:
            raise PolicyError("approved excerpts require exact selected text")
        encoded_value(value, maximum_bytes=maximum_bytes)
        return
    if item_id == "workflow":
        if not isinstance(value, dict): raise PolicyError("workflow context must be an object")
        synthetic = "objective" in value
        expected = {"objective", "modules", "facts", "facts_schema"} if synthetic else {"version", "preamble", "modules", "target_id", "facts", "facts_schema"}
        if "format_instruction" in value: expected.add("format_instruction")
        if "facts_schema" not in value and schema_id == "": expected.remove("facts_schema")
        context = _exact_object(value, expected, "workflow context")
        if not isinstance(context["modules"], list) or not context["modules"] or len(context["modules"]) > 32 or not isinstance(context["facts"], dict):
            raise PolicyError("workflow context has invalid typed fields")
        if synthetic:
            if classification != "synthetic" or not isinstance(context["objective"], str): raise PolicyError("synthetic workflow context is invalid")
            if any(not isinstance(module, str) or not _KEY.fullmatch(module) for module in context["modules"]): raise PolicyError("synthetic workflow module is invalid")
        else:
            if classification not in {"client_confidential", "approved_excerpt"} or context["version"] != 1 or not isinstance(context["preamble"], str) or not isinstance(context["target_id"], str):
                raise PolicyError("workflow context is invalid")
            for module in context["modules"]:
                module = _exact_object(module, {"id", "args"}, "workflow module")
                if not isinstance(module["id"], str) or not _KEY.fullmatch(module["id"]) or not isinstance(module["args"], dict): raise PolicyError("workflow module is invalid")
                validate_value(module["args"], maximum_bytes=maximum_bytes)
        if "format_instruction" in context and not isinstance(context["format_instruction"], str): raise PolicyError("workflow context is invalid")
        if context.get("facts_schema", "") != schema_id: raise PolicyError("workflow facts schema does not match trusted disclosure binding")
        _trusted_facts(context["facts"], schema_id)
        encoded_value(value, maximum_bytes=maximum_bytes)
        return
    if item_id == "result":
        result = _exact_object(value, {"version", "status", "facts", "reason", "facts_schema"}, "operation result")
        if result["version"] != 1 or result["status"] not in {"complete", "blocked", "failed", "stopped", "uncertain"} or not isinstance(result["facts"], dict) or result["reason"] is not None and not isinstance(result["reason"], str):
            raise PolicyError("operation result is invalid")
        if result["facts_schema"] != schema_id: raise PolicyError("operation facts schema does not match trusted disclosure binding")
        _trusted_facts(result["facts"], schema_id)
        encoded_value(value, maximum_bytes=maximum_bytes)
        return
    fixture_item = item_id in _FIXTURE_IDS or (item_id.startswith("part") and item_id[4:].isdigit())
    if not fixture_item or classification not in {"public", "synthetic"}:
        raise PolicyError("provider disclosure item is not an admitted schema")
    validate_value(value, maximum_bytes=maximum_bytes)
