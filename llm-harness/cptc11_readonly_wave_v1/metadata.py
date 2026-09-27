"""Shared bounded metadata validator for the sibling release.

This detects known restricted fields and encoded markers. It does not prove
that an accepted value is free of secrets.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from typing import Any, Mapping


class MetadataError(ValueError):
    pass


_RESTRICTED = {"raw", "body", "response", "header", "headers", "url", "uri", "path", "command", "executable", "filesystem", "credential", "credentials", "password", "passwd", "secret", "token", "cookie", "authorization", "ciphertext", "request", "socket", "proxy", "redirect", "retry", "environment"}
_MARKERS = ("password", "authorization", "cookie", "private key", "begin rsa", "bearer ", "http://", "https://")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def _norm(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _percent_decode(value: str) -> str:
    """Decode only percent octets without importing a URL client/parser."""
    out = bytearray()
    index = 0
    while index < len(value):
        if value[index] == "%" and index + 2 < len(value):
            pair = value[index + 1:index + 3]
            if re.fullmatch(r"[0-9a-fA-F]{2}", pair):
                out.append(int(pair, 16)); index += 3; continue
        out.extend(value[index].encode("utf-8")); index += 1
    return out.decode("utf-8", "replace")


def _decoded_forms(value: str) -> tuple[str, ...]:
    forms = [value, _percent_decode(value)]
    compact = "".join(value.split())
    if len(compact) >= 8 and len(compact) % 4 == 0:
        try: forms.append(base64.b64decode(compact, validate=True).decode("utf-8", "ignore"))
        except (ValueError, binascii.Error): pass
    if _HEX_RE.fullmatch(compact) and len(compact) <= 256:
        try: forms.append(bytes.fromhex(compact).decode("utf-8", "ignore"))
        except ValueError: pass
    return tuple(forms)


class MetadataGuard:
    def __init__(self, *, max_depth: int = 8, max_nodes: int = 512, max_string: int = 4096, max_total: int = 16384):
        self.max_depth, self.max_nodes, self.max_string, self.max_total = max_depth, max_nodes, max_string, max_total
        self.nodes = 0; self.total = 0; self.rolling = ""

    def feed(self, value: str) -> None:
        self.rolling = (self.rolling + value)[-256:]
        for candidate in _decoded_forms(self.rolling):
            lowered = _norm(candidate)
            if any(marker in lowered for marker in _MARKERS): raise MetadataError("restricted encoded metadata marker")

    def visit(self, value: Any, depth: int = 0, key: str = "") -> None:
        if depth > self.max_depth: raise MetadataError("metadata nesting is excessive")
        self.nodes += 1
        if self.nodes > self.max_nodes: raise MetadataError("metadata node limit exceeded")
        if key and _norm(key) in _RESTRICTED and not _norm(key).endswith("_sha256"):
            raise MetadataError("restricted metadata field")
        if isinstance(value, Mapping):
            seen: set[str] = set()
            for raw_key, child in value.items():
                if not isinstance(raw_key, str) or "\x00" in raw_key: raise MetadataError("metadata key is invalid")
                normalized = _norm(raw_key)
                if normalized in seen: raise MetadataError("duplicate metadata key")
                seen.add(normalized); self.visit(child, depth + 1, raw_key)
            return
        if isinstance(value, (list, tuple)):
            for child in value: self.visit(child, depth + 1, key)
            return
        if isinstance(value, float) and not math.isfinite(value): raise MetadataError("nonfinite metadata number")
        if type(value) in (str, int, bool) or value is None:
            if isinstance(value, str):
                if len(value) > self.max_string or any(ord(char) < 32 or ord(char) == 127 for char in value): raise MetadataError("metadata string is invalid")
                self.total += len(value); self.feed(value)
            else: self.total += 8
            if self.total > self.max_total: raise MetadataError("metadata size limit exceeded")
            return
        raise MetadataError("metadata type is not allowed")


def validate_metadata(value: Any, *, max_depth: int = 8, max_nodes: int = 512, max_string: int = 4096, max_total: int = 16384) -> Any:
    guard = MetadataGuard(max_depth=max_depth, max_nodes=max_nodes, max_string=max_string, max_total=max_total)
    guard.visit(value)
    return value
