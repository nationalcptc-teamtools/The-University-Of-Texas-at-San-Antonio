"""Pure HTTP request construction and response validation; performs no I/O."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from collections.abc import Sequence

from .source_allowlist import ImageSource, SourceRejected


MAX_RANGE_SIZE = 4 * 1024 * 1024
MAX_RESPONSE_HEADER_SIZE = 64 * 1024
_CONTENT_RANGE_RE = re.compile(r"bytes ([0-9]+)-([0-9]+)/([0-9]+)\Z")


@dataclass(frozen=True)
class ResponseLimits:
    max_header_bytes: int
    max_body_bytes: int
    require_streaming: bool


@dataclass(frozen=True)
class RangeRequest:
    url: str
    headers: dict[str, str]
    response_limits: ResponseLimits
    follow_redirects: bool = False


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Sequence[tuple[str, str]]
    body: bytes
    final_url: str
    streaming_receive_cap: int
    streaming_cap_enforced: bool


@dataclass(frozen=True)
class ValidatedChunk:
    start: int
    end: int
    sha256: str
    etag: str | None
    last_modified: str
    body: bytes


def _normalize_headers(headers: Sequence[tuple[str, str]]) -> dict[str, str]:
    if isinstance(headers, (dict, str, bytes)):
        raise SourceRejected("response requires ordered header fields that preserve duplicates")
    total = 0
    result: dict[str, str] = {}
    for field in headers:
        if not isinstance(field, tuple) or len(field) != 2:
            raise SourceRejected("response requires ordered header fields")
        name, value = field
        if not isinstance(name, str) or not isinstance(value, str):
            raise SourceRejected("response headers must be strings")
        total += len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
        key = name.strip().lower()
        if not key or key in result:
            raise SourceRejected("duplicate or empty response header")
        result[key] = value.strip()
    if total > MAX_RESPONSE_HEADER_SIZE:
        raise SourceRejected("response headers exceed size limit")
    return result


def build_range_request(source: ImageSource, *, start: int, size: int) -> RangeRequest:
    if not isinstance(start, int) or isinstance(start, bool) or start < 0:
        raise SourceRejected("range start must be a non-negative integer")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise SourceRejected("range size must be a positive integer")
    if size > MAX_RANGE_SIZE:
        raise SourceRejected("range size exceeds the 4 MiB limit")
    if start >= source.content_length:
        raise SourceRejected("range starts beyond source length")
    end = min(start + size, source.content_length) - 1
    headers = {
        "Accept-Encoding": "identity",
        "Range": f"bytes={start}-{end}",
    }
    if source.etag is not None:
        headers["If-Match"] = source.etag
    return RangeRequest(
        source.url,
        dict(sorted(headers.items())),
        ResponseLimits(
            max_header_bytes=MAX_RESPONSE_HEADER_SIZE,
            max_body_bytes=end - start + 1,
            require_streaming=True,
        ),
    )


def validate_range_response(
    source: ImageSource,
    *,
    start: int,
    requested_size: int,
    response: HttpResponse,
) -> ValidatedChunk:
    """Validate a single bounded range response without persisting its body."""

    request = build_range_request(source, start=start, size=requested_size)
    expected_end = int(request.headers["Range"].split("-")[1])
    expected_count = expected_end - start + 1
    if (
        response.streaming_cap_enforced is not True
        or not isinstance(response.streaming_receive_cap, int)
        or isinstance(response.streaming_receive_cap, bool)
        or response.streaming_receive_cap != expected_count
    ):
        raise SourceRejected("exact streaming receive cap was not enforced")
    if 300 <= response.status < 400:
        raise SourceRejected("range response redirect is forbidden")
    if response.status != 206:
        raise SourceRejected("range response must be 206 Partial Content")
    if response.final_url != source.url:
        raise SourceRejected("range response final URL changed")
    if not isinstance(response.body, bytes):
        raise SourceRejected("range response body must be bytes")
    headers = _normalize_headers(response.headers)
    if headers.get("content-encoding", "identity").lower() != "identity":
        raise SourceRejected("compressed range response is forbidden")
    if "transfer-encoding" in headers:
        raise SourceRejected("range response must have an exact body length")
    match = _CONTENT_RANGE_RE.fullmatch(headers.get("content-range", ""))
    if match is None:
        raise SourceRejected("invalid Content-Range")
    actual_start, actual_end, actual_total = (int(value) for value in match.groups())
    if (actual_start, actual_end, actual_total) != (
        start,
        expected_end,
        source.content_length,
    ):
        raise SourceRejected("Content-Range does not match request or source")
    content_length = headers.get("content-length")
    if content_length is None or not content_length.isdigit():
        raise SourceRejected("range response body length is missing")
    if int(content_length) != expected_count or len(response.body) != expected_count:
        raise SourceRejected("range response body length does not match request")
    if headers.get("etag") != source.etag:
        raise SourceRejected("range response ETag changed")
    if headers.get("last-modified") != source.last_modified:
        raise SourceRejected("range response Last-Modified changed")
    return ValidatedChunk(
        start=start,
        end=expected_end,
        sha256=hashlib.sha256(response.body).hexdigest(),
        etag=source.etag,
        last_modified=source.last_modified,
        body=response.body,
    )
