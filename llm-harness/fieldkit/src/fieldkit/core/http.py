"""Bounded HTTP transport, shared request scheduling, and explicit redirect scope."""

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx


@dataclass
class FetchResult:
    requested_url: str
    url: str
    status: int | None = None
    content_type: str = ""
    body: bytes = b""
    error: str | None = None
    detail: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)
    request_headers: dict[str, str] = field(default_factory=dict)
    evidence_id: str = ""


def origin(url: str) -> tuple[str, str | None, int]:
    p = urlsplit(url)
    return p.scheme.lower(), p.hostname, p.port or (443 if p.scheme == "https" else 80)


class RequestControls:
    def __init__(self, concurrency: int, rate: float = 0) -> None:
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate = rate
        self.locks: dict[tuple, asyncio.Lock] = {}
        self.next_start: dict[tuple, float] = {}

    async def pace(self, url: str) -> None:
        if not self.rate:
            return
        key = origin(url)
        async with self.locks.setdefault(key, asyncio.Lock()):
            delay = self.next_start.get(key, 0) - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self.next_start[key] = time.monotonic() + 1 / self.rate


class Fetcher:
    """Limits apply across clients when they share a RequestControls instance."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        concurrency: int,
        max_bytes: int,
        request_timeout: float,
        max_redirects: int = 5,
        controls: RequestControls | None = None,
        retries: int = 0,
    ) -> None:
        self.client = client
        self.controls = controls or RequestControls(concurrency)
        self.semaphore = self.controls.semaphore
        self.max_bytes = max_bytes
        self.request_timeout = request_timeout
        self.max_redirects = max_redirects
        self.retries = retries

    async def get(self, url: str, allowed_origin: str) -> FetchResult:
        return await self.request(url, allowed_origin)

    async def request(
        self,
        url: str,
        allowed_origin: str,
        method: str = "GET",
        headers: dict | None = None,
        data=None,
        follow_redirects: bool = True,
    ) -> FetchResult:
        attempts = self.retries + 1 if method.upper() in {"GET", "HEAD", "OPTIONS"} else 1
        for attempt in range(attempts):
            async with self.semaphore:
                try:
                    async with asyncio.timeout(self.request_timeout):
                        result = await self._request(
                            url,
                            allowed_origin,
                            method.upper(),
                            headers,
                            data,
                            follow_redirects,
                        )
                except (httpx.HTTPError, httpx.InvalidURL, TimeoutError, ValueError) as exc:
                    result = FetchResult(
                        url,
                        url,
                        error="network_error",
                        detail=str(exc) or "Timed out",
                    )
            if result.error != "network_error" and result.status not in {429, 502, 503, 504}:
                return result
            if attempt + 1 < attempts:
                delay = 0.25 * (2**attempt)
                retry_after = result.headers.get("retry-after", "")
                if retry_after.isdigit():
                    delay = min(float(retry_after), 5.0)
                await asyncio.sleep(delay)
        return result

    async def _request(self, url, allowed_origin, method, headers, data, follow_redirects):
        current, history = url, []
        initial_headers = None
        for hop in range(self.max_redirects + 1):
            await self.controls.pace(current)
            kwargs = {"headers": headers}
            if data is not None:
                kwargs["data" if isinstance(data, dict) else "content"] = data
            async with self.client.stream(method, current, **kwargs) as response:
                if initial_headers is None:
                    initial_headers = dict(response.request.headers)
                result = FetchResult(
                    url,
                    str(response.url),
                    response.status_code,
                    response.headers.get("content-type", ""),
                    headers=dict(response.headers),
                    set_cookies=response.headers.get_list("set-cookie"),
                    history=list(history),
                    request_headers=initial_headers,
                )
                if follow_redirects and response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        result.error, result.detail = (
                            "redirect_error",
                            "Redirect has no Location header",
                        )
                        return result
                    next_url = urljoin(current, location)
                    parsed = urlsplit(next_url)
                    if (
                        origin(next_url) != origin(allowed_origin)
                        or parsed.username is not None
                        or parsed.password is not None
                    ):
                        result.error = "blocked_redirect"
                        result.detail = f"Redirect leaves target origin: {next_url}"
                        return result
                    if hop == self.max_redirects:
                        result.error, result.detail = "redirect_error", "Too many redirects"
                        return result
                    history.append(
                        {
                            "url": str(response.url),
                            "status": response.status_code,
                            "method": method,
                            "request_headers": dict(response.request.headers),
                            "headers": dict(response.headers),
                            "set_cookies": response.headers.get_list("set-cookie"),
                        }
                    )
                    if response.status_code == 303 or (
                        response.status_code in {301, 302} and method == "POST"
                    ):
                        method, data = "GET", None
                        headers = {
                            k: v
                            for k, v in (headers or {}).items()
                            if k.lower() not in {"content-type", "content-length"}
                        }
                    current = next_url
                    continue
                chunks = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    if len(chunks) + len(chunk) > self.max_bytes:
                        result.error = "too_large"
                        result.detail = f"Body exceeds {self.max_bytes} decoded bytes"
                        return result
                    chunks.extend(chunk)
                result.body = bytes(chunks)
                return result
        raise AssertionError("Unreachable redirect state")
