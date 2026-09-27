"""Metadata-only parser for one bounded Redis simple frame."""

from __future__ import annotations

from ..contracts import RedisFacts
from . import ParserError


def _validate_simple_frame(frame: bytes) -> bool:
    """Validate one bounded Redis simple frame and report whether it is complete."""
    if type(frame) is not bytes or not frame or len(frame) > 128:
        raise ParserError("Redis frame is oversized or invalid")
    if frame[:1] not in {b"+", b"-"}:
        raise ParserError("Redis frame type is unsupported")
    payload = frame[1:]
    complete = payload.endswith(b"\r\n")
    content = payload[:-2] if complete else payload
    if not complete and content.endswith(b"\r"):
        content = content[:-1]
    if any(byte < 0x20 or byte > 0x7E for byte in content):
        raise ParserError("Redis simple frame contains a control byte")
    trailer = payload[len(content):]
    if trailer not in {b"", b"\r", b"\r\n"}:
        raise ParserError("Redis simple frame delimiter is invalid")
    return complete


def parse_redis(frame: bytes) -> RedisFacts:
    if not _validate_simple_frame(frame):
        return RedisFacts("incomplete")
    if frame == b"+PONG\r\n":
        return RedisFacts("pong")
    if frame.startswith(b"-NOAUTH "):
        return RedisFacts("authentication_required")
    return RedisFacts("unexpected")
