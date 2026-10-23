"""Bounded passive HTTP receipts, with exact correlation and no retained request data.

Receipts prove a request reached a callback address. They do not identify the person,
browser, or application which caused that request. No outbound requests are made.
"""

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from fieldkit.core.assessment import write_private

_MARKER = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_HEADER = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def _methods(methods):
    if methods is None:
        return frozenset({"GET"})
    if isinstance(methods, str):
        methods = [methods]
    values = frozenset(methods)
    if not values or not values <= _METHODS:
        raise ValueError("Callback methods must be explicit uppercase HTTP methods")
    return values


def _digest(value):
    if value is not None and (not isinstance(value, str) or not _DIGEST.fullmatch(value)):
        raise ValueError("Expected body SHA256 must be 64 lowercase hexadecimal characters")
    return value


def callback_url(value, *, allow_query=False):
    """Validate an operator callback URL and remove only permitted query metadata."""
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Callback URL must be a bounded absolute HTTP(S) URL")
    if any(ord(char) <= 32 or ord(char) >= 127 for char in value) or "\\" in value:
        raise ValueError("Callback URL must contain printable ASCII without spaces")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ValueError("Malformed callback URL") from exc
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or (parts.query and not allow_query)
        or (port is not None and not 1 <= port <= 65535)
        or "%" in parts.path
        or "//" in parts.path
        or any(piece in {".", ".."} for piece in parts.path.split("/"))
    ):
        raise ValueError("Callback URL needs an HTTP(S) origin and an unambiguous path")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _timestamp(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) else None
    if isinstance(value, str) and len(value) <= 64:
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return stamp.timestamp() if stamp.tzinfo is not None else None
        except (ValueError, OverflowError, OSError):
            return None
    return None


def _peer(value):
    if not isinstance(value, dict):
        return None
    port = value.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        return None
    try:
        ip = ipaddress.ip_address(value.get("ip"))
    except ValueError:
        return None
    return {"ip": str(ip), "port": port}


def correlate_receipts(
    receipts,
    marker,
    url,
    since_epoch=0,
    *,
    methods=None,
    body_sha256=None,
    until_epoch=None,
):
    """Return only sanitized receipts matching ID, full URL/path, method, time and digest.

    Imported receipts are operator-supplied observations; correlation does not verify
    their provenance. Arbitrary headers, query values, bodies and source labels are
    discarded. Times must be epoch seconds or timezone-aware ISO timestamps.
    """
    if not isinstance(marker, str) or not _MARKER.fullmatch(marker):
        raise ValueError("Callback marker must contain 16-128 URL-safe characters")
    expected = callback_url(url)
    if urlsplit(expected).path.rsplit("/", 1)[-1] != marker:
        raise ValueError("Callback URL must end in the exact marker")
    allowed = _methods(methods)
    body_sha256 = _digest(body_sha256)
    until_epoch = time.time() if until_epoch is None else until_epoch
    if (
        isinstance(since_epoch, bool)
        or isinstance(until_epoch, bool)
        or not isinstance(since_epoch, (int, float))
        or not isinstance(until_epoch, (int, float))
        or not math.isfinite(since_epoch)
        or not math.isfinite(until_epoch)
        or since_epoch < 0
        or until_epoch < since_epoch
    ):
        raise ValueError("Callback correlation requires a finite ordered time window")
    matched = []
    for index, item in enumerate(receipts):
        if index >= 10000:
            raise ValueError("Callback correlation receipt limit is 10000")
        if not isinstance(item, dict) or item.get("callback_id") != marker:
            continue
        try:
            observed_url = callback_url(item.get("url"), allow_query=True)
        except ValueError:
            continue
        received = _timestamp(item.get("received_at"))
        method = item.get("method")
        digest = item.get("body_sha256")
        if (
            observed_url != expected
            or received is None
            or not since_epoch <= received <= until_epoch
            or not isinstance(method, str)
            or method not in allowed
            or (body_sha256 is not None and digest != body_sha256)
        ):
            continue
        record = {
            "callback_id": marker,
            "url": expected,
            "received_at": datetime.fromtimestamp(received, UTC).isoformat(),
            "source": "http_listener"
            if item.get("source") == "http_listener"
            else "imported_receipt",
            "method": method,
            "path": urlsplit(expected).path,
        }
        if isinstance(digest, str) and _DIGEST.fullmatch(digest):
            record["body_sha256"] = digest
        for name in ("body_bytes", "header_bytes", "query_bytes"):
            value = item.get(name)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1048576:
                record[name] = value
        peer = _peer(item.get("peer"))
        if peer is not None:
            record["peer"] = peer
        evidence = item.get("evidence")
        if isinstance(evidence, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", evidence):
            record["evidence"] = evidence
        matched.append(record)
    return matched


def read_receipts(filename, *, max_bytes=1048576, max_receipts=10000):
    """Read a bounded private regular JSON/JSONL receipt file without following links."""
    if not 1 <= max_bytes <= 16777216 or not 1 <= max_receipts <= 10000:
        raise ValueError("Receipt import limits exceed the fixed maximum")
    path = Path(filename).expanduser()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > max_bytes
        ):
            raise ValueError("Receipt input must be an owner-only bounded regular file")
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("Receipt input exceeds its byte limit")
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError):
        try:
            value = [json.loads(line) for line in data.splitlines() if line.strip()]
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Malformed JSON/JSONL callback receipt input") from exc
    if isinstance(value, dict):
        value = value.get("receipts")
    if not isinstance(value, list) or len(value) > max_receipts:
        raise ValueError("Receipt input must be a bounded receipt array or receipts object")
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("Every callback receipt must be an object")
    return value


def write_callback_evidence(ctx, receipt):
    """Write allowlisted receipt metadata for either a local or network context."""
    sanitized = correlate_receipts(
        [receipt],
        receipt.get("callback_id"),
        callback_url(receipt.get("url"), allow_query=True),
        methods=_METHODS,
    )
    if not sanitized:
        raise ValueError("Callback evidence requires a valid current receipt")
    receipt = sanitized[0]
    receipt.pop("evidence", None)
    entries = ctx.report.setdefault("evidence", [])
    identifier = "callback-" + secrets.token_hex(12)
    relative = Path("evidence") / f"{identifier}.json"
    data = json.dumps({"kind": "callback_receipt", "receipt": receipt}, indent=2).encode()
    write_private(ctx.store.root / relative, data)
    entries.append(
        {
            "id": identifier,
            "file": str(relative),
            "source": "callback_collector",
            "private_raw": False,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    )
    return identifier


class CallbackCollector:
    """An async HTTP listener which retains only bounded receipt metadata.

    ``PUBLIC_URL`` describes an already-forwarded address; configuring it creates no
    tunnel. Its path prefix must be preserved by the forwarder. The collector binds
    to numeric IP addresses and accepts only the exact registered callback paths.
    ``wait`` additionally enforces each registration's method and optional digest.
    """

    def __init__(
        self,
        ctx,
        bind_host="127.0.0.1",
        port=0,
        public_url="",
        max_receipts=100,
        max_bytes=16384,
        *,
        max_connections=16,
        max_connection_attempts=1000,
        request_timeout=10.0,
    ):
        try:
            address = ipaddress.ip_address(bind_host)
        except ValueError as exc:
            raise ValueError("Callback BIND_HOST must be a numeric IP address") from exc
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            raise ValueError("Callback PORT must be 0-65535")
        for value, maximum, name in (
            (max_receipts, 10000, "MAX_RECEIPTS"),
            (max_bytes, 1048576, "MAX_BYTES"),
            (max_connections, 128, "MAX_CONNECTIONS"),
            (max_connection_attempts, 100000, "MAX_CONNECTION_ATTEMPTS"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
                raise ValueError(f"Callback {name} must be 1-{maximum}")
        if (
            isinstance(request_timeout, bool)
            or not isinstance(request_timeout, (int, float))
            or not math.isfinite(request_timeout)
            or not 0 < request_timeout <= 60
        ):
            raise ValueError("Callback request timeout must be finite and at most 60 seconds")
        self.ctx = ctx
        self.bind_host = str(address)
        self.port = port
        self.public_url = callback_url(public_url).rstrip("/") if public_url else ""
        if not address.is_loopback and not self.public_url:
            raise ValueError("A non-loopback callback bind requires an explicit PUBLIC_URL")
        self.max_receipts = max_receipts
        self.max_bytes = max_bytes
        self.max_connections = max_connections
        self.max_connection_attempts = max_connection_attempts
        self.connection_attempts = 0
        self.stop_reason = ""
        self.request_timeout = request_timeout
        self.base_url = ""
        self.receipts_file = Path(ctx.store.root) / f"callback-receipts-{secrets.token_hex(8)}.json"
        self.receipts = []
        self.registrations = {}
        self._server = None
        self._tasks = set()
        self._writers = set()
        self._changed = asyncio.Event()
        self._stopped = asyncio.Event()
        self._close_lock = asyncio.Lock()
        self._expiry = None
        self._closed = False
        self._accepting = True
        self._started = False
        self._deadline = min(float(ctx.deadline), time.monotonic() + 3600)
        if not math.isfinite(self._deadline):
            raise ValueError("Callback context deadline must be finite")

    async def start(self):
        if self._started or self._closed:
            raise ValueError("Callback collector can only be started once")
        if time.monotonic() >= self._deadline:
            raise TimeoutError("Callback collector deadline expired")
        self._server = await asyncio.start_server(
            self._accept,
            self.bind_host,
            self.port,
            limit=min(self.max_bytes, 16384),
            backlog=self.max_connections,
        )
        self._started = True
        self.port = self._server.sockets[0].getsockname()[1]
        host = f"[{self.bind_host}]" if ":" in self.bind_host else self.bind_host
        origin = self.public_url or f"http://{host}:{self.port}"
        self.base_url = origin + "/callbacks"
        self._path_prefix = urlsplit(self.base_url).path
        try:
            self._save_receipts()
        except OSError:
            await self.close()
            raise
        self._expiry = asyncio.create_task(self._expire())
        return self

    def register(self, marker=None, *, methods=None, body_sha256=None):
        if not self._started or self._closed:
            raise ValueError("Start the callback collector before registering a marker")
        marker = secrets.token_urlsafe(24) if marker is None else marker
        if not isinstance(marker, str) or not _MARKER.fullmatch(marker):
            raise ValueError("Callback marker must contain 16-128 URL-safe characters")
        if marker in self.registrations:
            raise ValueError("Callback marker is already registered")
        if len(self.registrations) >= 1000:
            raise ValueError("Callback registration limit is 1000")
        url = self.base_url + "/" + marker
        self.registrations[marker] = {
            "url": url,
            "path": self._path_prefix + "/" + marker,
            "methods": _methods(methods),
            "body_sha256": _digest(body_sha256),
            "created_at": time.time(),
        }
        return url

    async def wait(self, marker, since_epoch, timeout_seconds):
        if marker not in self.registrations:
            raise ValueError("Callback marker is not registered")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 <= timeout_seconds <= 3600
        ):
            raise ValueError("Callback wait must be finite and at most 3600 seconds")
        registration = self.registrations[marker]
        if (
            isinstance(since_epoch, bool)
            or not isinstance(since_epoch, (int, float))
            or not math.isfinite(since_epoch)
            or since_epoch < 0
        ):
            raise ValueError("Callback correlation start time must be finite and nonnegative")
        since_epoch = max(since_epoch, registration["created_at"])
        expires = min(time.monotonic() + timeout_seconds, self._deadline)
        while True:
            self._changed.clear()
            now = time.time()
            matched = (
                correlate_receipts(
                    self.receipts,
                    marker,
                    registration["url"],
                    since_epoch,
                    methods=registration["methods"],
                    body_sha256=registration["body_sha256"],
                    until_epoch=now,
                )
                if now >= since_epoch
                else []
            )
            if matched or self._closed or time.monotonic() >= expires:
                return matched
            try:
                await asyncio.wait_for(self._changed.wait(), expires - time.monotonic())
            except TimeoutError:
                return []

    async def wait_closed(self):
        """Wait for the deadline, receipt cap, or explicit shutdown."""
        await self._stopped.wait()

    async def close(self):
        async with self._close_lock:
            self._closed = True
            self._accepting = False
            self.stop_reason = self.stop_reason or "closed"
            self._changed.set()
            self._stopped.set()
            if self._server is not None:
                self._server.close()
            current = asyncio.current_task()
            if self._expiry is not None and self._expiry is not current:
                self._expiry.cancel()
                await asyncio.gather(self._expiry, return_exceptions=True)
            tasks = [task for task in self._tasks if task is not current]
            for task in tasks:
                task.cancel()
            for writer in self._writers:
                writer.close()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if self._server is not None:
                await self._server.wait_closed()

    async def _expire(self):
        await asyncio.sleep(max(0, self._deadline - time.monotonic()))
        self.stop_reason = self.stop_reason or "listening_period_finished"
        await self.close()

    def _accept(self, reader, writer):
        if self._closed or not self._accepting or time.monotonic() >= self._deadline:
            writer.close()
            return
        self.connection_attempts += 1
        if self.connection_attempts >= self.max_connection_attempts:
            self._accepting = False
            self.stop_reason = "connection_limit"
            self._server.close()
        if len(self._tasks) >= self.max_connections:
            writer.close()
            return
        self._writers.add(writer)
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._handler_done)

    def _handler_done(self, task):
        self._tasks.discard(task)
        if not self._accepting and not self._tasks:
            self._closed = True
            self._changed.set()
            self._stopped.set()

    async def _reply(self, writer, status):
        names = {
            204: "No Content",
            400: "Bad Request",
            404: "Not Found",
            405: "Method Not Allowed",
            408: "Request Timeout",
            413: "Content Too Large",
            429: "Too Many Requests",
            431: "Request Header Fields Too Large",
        }
        writer.write(
            f"HTTP/1.1 {status} {names[status]}\r\nContent-Length: 0\r\n"
            "Cache-Control: no-store\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        await writer.drain()

    async def _handle(self, reader, writer):
        try:
            async with asyncio.timeout(
                max(0.001, min(self.request_timeout, self._deadline - time.monotonic()))
            ):
                await self._request(reader, writer)
        except asyncio.LimitOverrunError:
            with contextlib.suppress(OSError, RuntimeError):
                await self._reply(writer, 431)
        except TimeoutError:
            with contextlib.suppress(OSError, RuntimeError):
                await self._reply(writer, 408)
        except (asyncio.IncompleteReadError, OSError, ValueError, UnicodeError):
            with contextlib.suppress(OSError, RuntimeError):
                await self._reply(writer, 400)
        finally:
            self._writers.discard(writer)
            writer.close()
            with contextlib.suppress(OSError, TimeoutError, RuntimeError):
                await asyncio.wait_for(writer.wait_closed(), 0.5)

    async def _request(self, reader, writer):
        headers = await reader.readuntil(b"\r\n\r\n")
        if len(headers) > min(self.max_bytes, 16384):
            await self._reply(writer, 431)
            return
        lines = headers[:-4].split(b"\r\n")
        if len(lines) > 101 or len(lines[0]) > 4096:
            await self._reply(writer, 431)
            return
        pieces = lines[0].decode("ascii").split(" ")
        if len(pieces) != 3:
            raise ValueError("Malformed request line")
        method, target, version = pieces
        if (
            method not in _METHODS
            or version not in {"HTTP/1.0", "HTTP/1.1"}
            or not target.startswith("/")
            or target.startswith("//")
            or "#" in target
            or any(ord(char) <= 32 or ord(char) >= 127 for char in target)
        ):
            raise ValueError("Unsupported callback request")
        path, _, query = target.partition("?")
        marker = path.removeprefix(self._path_prefix + "/")
        registration = self.registrations.get(marker)
        if registration is None or path != registration["path"]:
            await self._reply(writer, 404)
            return
        # Only framing metadata survives header parsing. Even credential header
        # names/values are never copied into a receipt or an error message.
        seen = set()
        length = 0
        host = False
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if not separator or not _HEADER.fullmatch(name) or b"\x00" in value:
                raise ValueError("Malformed callback headers")
            if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
                raise ValueError("Malformed callback header value")
            name = name.lower()
            if name in seen:
                raise ValueError("Duplicate callback header")
            seen.add(name)
            if name in {b"transfer-encoding", b"expect"}:
                raise ValueError("Unsupported callback framing")
            if name == b"host":
                host = bool(value.strip())
            if name == b"content-length":
                value = value.strip()
                if not value.isdigit() or len(value) > 10:
                    raise ValueError("Malformed callback content length")
                length = int(value)
        if version == "HTTP/1.1" and not host:
            raise ValueError("Callback HTTP/1.1 request needs Host")
        if method not in registration["methods"]:
            await self._reply(writer, 405)
            return
        if length + len(headers) > self.max_bytes:
            await self._reply(writer, 413)
            return
        digest = hashlib.sha256()
        remaining = length
        while remaining:
            chunk = await reader.readexactly(min(4096, remaining))
            digest.update(chunk)
            remaining -= len(chunk)
        if self._closed or time.monotonic() >= self._deadline:
            return
        if len(self.receipts) >= self.max_receipts:
            await self._reply(writer, 429)
            return
        receipt = {
            "callback_id": marker,
            "url": registration["url"],
            "path": path,
            "received_at": datetime.now(UTC).isoformat(),
            "source": "http_listener",
            "method": method,
            "header_bytes": len(headers),
            "query_bytes": len(query),
            "body_bytes": length,
            "body_sha256": digest.hexdigest(),
        }
        peer = writer.get_extra_info("peername")
        if isinstance(peer, tuple) and len(peer) >= 2:
            peer = _peer({"ip": peer[0], "port": peer[1]})
            if peer is not None:
                receipt["peer"] = peer
        try:
            receipt["evidence"] = write_callback_evidence(self.ctx, receipt)
            self.receipts.append(receipt)
            self._save_receipts()
        except OSError:
            self.ctx.report.setdefault("errors", []).append(
                {"error": "callback_storage_error", "resource": "callback_collector"}
            )
            self.stop_reason = "storage_error"
            self._closed = True
            self._accepting = False
            self._server.close()
            self._changed.set()
            self._stopped.set()
            raise
        self._changed.set()
        if len(self.receipts) >= self.max_receipts:
            self._closed = True
            self._accepting = False
            self.stop_reason = "receipt_limit"
            self._stopped.set()
            self._server.close()
        await self._reply(writer, 204)

    def _save_receipts(self):
        write_private(
            self.receipts_file,
            json.dumps({"schema_version": 1, "receipts": self.receipts}, indent=2),
        )
