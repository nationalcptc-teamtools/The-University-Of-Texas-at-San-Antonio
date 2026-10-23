"""Canonical HTTP URLs and strict origin checks shared by discovery modules."""

from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from fieldkit.core.http import origin


def normalize_url(url: str) -> str:
    if any(ord(c) < 32 for c in url) or "\\" in url:
        raise ValueError("URLs cannot contain control characters or backslashes")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Expected an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials in URLs are unsupported")
        if parsed.port == 0:
            raise ValueError("Invalid port")
        return str(httpx.URL(urldefrag(url)[0]))
    except httpx.InvalidURL as exc:
        raise ValueError("Invalid HTTP(S) URL") from exc


def resolve_url(reference: str, base: str, origins: list[str]) -> str | None:
    try:
        url = normalize_url(urljoin(base, reference))
        if origin(url) in {origin(item) for item in origins}:
            return url
    except (ValueError, TypeError):
        pass
    return None
