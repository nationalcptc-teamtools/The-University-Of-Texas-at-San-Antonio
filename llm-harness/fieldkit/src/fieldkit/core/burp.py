"""Selected Burp captures over authenticated loopback HTTP; no target requests."""

import asyncio
import base64
import hmac
import json
import math
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

from fieldkit.core.assessment import header_secrets
from fieldkit.core.http import origin
from fieldkit.core.ingest import body_request, captured_headers, load_json
from fieldkit.core.redaction import redact
from fieldkit.core.replay import register_request_secrets, validate_request
from fieldkit.core.storage import utc_now
from fieldkit.core.urls import normalize_url
from fieldkit.core.vault import Vault


def body_bytes(value, maximum):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise ValueError("Capture body exceeds the configured limit")
    try:
        body = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("Malformed capture body") from exc
    if len(body) > maximum:
        raise ValueError("Capture body exceeds the configured limit")
    return body


def metadata(document):
    context, tags = document.get("context", {}), document.get("tags", [])
    if (
        not isinstance(context, dict)
        or set(context) - {"user", "role", "host", "feature", "profile"}
        or not all(isinstance(v, str) and len(v) <= 256 for v in context.values())
        or not isinstance(tags, list)
        or len(tags) > 20
        or not all(isinstance(v, str) and len(v) <= 128 for v in tags)
    ):
        raise ValueError("Malformed capture context or tags")
    return context, tags


def capture_records(document, origins, max_entries, max_body):
    if not isinstance(document, dict) or type(document.get("schema_version")) is not int:
        raise ValueError("Capture requires schema_version 1")
    entries = document.get("exchanges")
    if document["schema_version"] != 1 or not isinstance(entries, list):
        raise ValueError("Unsupported capture schema")
    if not 1 <= len(entries) <= max_entries:
        raise ValueError("Capture entry limit exceeded")
    context, tags = metadata(document)
    records = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            raise ValueError("Capture requires a request object")
        raw = entry["request"]
        url = normalize_url(raw.get("url", ""))
        if origin(url) not in origins:
            raise ValueError("Capture URL is outside the receiver's selected origins")
        request_headers = raw.get("headers", [])
        if len(request_headers) > 200:
            raise ValueError("Capture header limit exceeded")
        headers = captured_headers(request_headers, request=True)
        request = validate_request({"url": url, "method": raw.get("method"), "headers": headers})
        content = body_bytes(raw.get("body_base64", ""), max_body)
        media = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
        encoding = next((v for k, v in headers.items() if k.lower() == "content-encoding"), "")
        if encoding and encoding.lower().strip() != "identity":
            # Preserve compressed request bytes with their original encoding header.
            request["body_base64"] = base64.b64encode(content).decode()
        else:
            try:
                request = validate_request(body_request(dict(request), content, media))
            except (ValueError, UnicodeError, RecursionError):
                # A deliberately malformed application body is still capture evidence.
                request["body_base64"] = base64.b64encode(content).decode()
        request = validate_request(request)
        raw_response = entry.get("response")
        response = None
        if raw_response is not None:
            if not isinstance(raw_response, dict):
                raise ValueError("Malformed capture response")
            status = raw_response.get("status")
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError("Invalid captured response status")
            response_headers = raw_response.get("headers", [])
            if len(response_headers) > 200:
                raise ValueError("Capture header limit exceeded")
            response_headers = captured_headers(response_headers)
            data = body_bytes(raw_response.get("body_base64", ""), max_body)
            response = {
                "status": status,
                "headers": response_headers,
                "headers_raw": raw_response.get("headers", []),
                "body_base64": base64.b64encode(data).decode(),
                "mime_type": next(
                    (v for k, v in response_headers.items() if k.lower() == "content-type"), ""
                ),
                "timestamp": utc_now(),
            }
        records.append((request, response, entry))
    return records, context, tags


class BurpReceiver:
    def __init__(self, ctx, origins):
        self.ctx, self.origins = ctx, origins
        self.token = secrets.token_hex(32)
        self.server, self.vault = None, None
        self.tasks = set()
        self.stop = asyncio.Event()
        self.count = 0
        self.configuration = None
        self.configuration_created = False
        self.configuration_identity = None

    def checkpoint(self):
        self.ctx.store.write_report(redact(self.ctx.report, self.ctx.secrets))

    async def run(self):
        settings = self.ctx.settings
        with Vault(settings["DATABASE"]) as self.vault:
            self.server = await asyncio.start_server(
                self.handle, "127.0.0.1", settings["PORT"], limit=16384
            )
            port = self.server.sockets[0].getsockname()[1]
            endpoint = f"http://127.0.0.1:{port}/capture"
            self.authorities = {f"127.0.0.1:{port}", f"localhost:{port}"}
            self.configuration = (
                Path(settings["CONFIG_FILE"]).expanduser()
                if settings["CONFIG_FILE"]
                else self.ctx.store.root / "private-burp-bridge.properties"
            )
            try:
                if self.configuration.is_symlink() or self.configuration.exists():
                    raise ValueError(
                        "Use a new CONFIG_FILE path for the receiver's private settings"
                    )
                remaining = max(0.001, self.ctx.deadline - time.monotonic())
                configuration_text = (
                    "schema_version=1\n"
                    f"endpoint={endpoint}\n"
                    f"token={self.token}\n"
                    f"expires_epoch={math.ceil(time.time() + remaining)}\n"
                    f"max_bytes={settings['MAX_BYTES']}\n"
                    f"max_entries={settings['MAX_ENTRIES']}\n"
                )
                self.configuration.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                descriptor = os.open(
                    self.configuration, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    info = os.fstat(stream.fileno())
                    self.configuration_identity = (info.st_dev, info.st_ino)
                    stream.write(configuration_text)
                self.configuration_created = True
                self.ctx.report["results"].append(
                    {
                        "kind": "burp_bridge_ready",
                        "endpoint": endpoint,
                        "config_file": str(self.configuration.resolve()),
                        "database": str(self.vault.path),
                        "capture_origins": sorted(self.origins),
                        "scope_authorizes_requests": False,
                    }
                )
                self.ctx.console.print(f"Burp configuration: {self.configuration}", markup=False)
                self.checkpoint()
                remaining = max(0.001, self.ctx.deadline - time.monotonic())
                try:
                    await asyncio.wait_for(self.stop.wait(), remaining)
                    self.ctx.report["bridge_stop"] = "capture_limit"
                except TimeoutError:
                    # A receiver's configured listening period is its normal lifecycle.
                    self.ctx.report["bridge_stop"] = "listening_period_finished"
            finally:
                self.server.close()
                await self.server.wait_closed()
                for task in self.tasks.copy():
                    task.cancel()
                await asyncio.gather(*self.tasks, return_exceptions=True)
                if self.configuration_created:
                    # Only remove the file created by this receiver, never an existing input.
                    try:
                        descriptor = os.open(
                            self.configuration, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                        )
                        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                            info = os.fstat(stream.fileno())
                            owned = (
                                stream.read(4096)
                                if stat.S_ISREG(info.st_mode)
                                and (info.st_dev, info.st_ino) == self.configuration_identity
                                else ""
                            )
                        if f"token={self.token}\n" in owned:
                            self.configuration.unlink()
                    except (OSError, UnicodeError):
                        pass

    async def respond(self, writer, status, value):
        content = json.dumps(value).encode()
        writer.write(
            f"HTTP/1.1 {status} Fieldkit\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(content)}\r\nConnection: close\r\n\r\n".encode()
            + content
        )
        await writer.drain()

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        if len(self.tasks) >= 16:
            writer.close()
            return
        self.tasks.add(task)
        try:
            async with asyncio.timeout(self.ctx.settings["TIMEOUT"]):
                head = await reader.readuntil(b"\r\n\r\n")
                if len(head) > 16384:
                    raise ValueError("Header limit exceeded")
                lines = head.decode("ascii").split("\r\n")
                if lines[0] != "POST /capture HTTP/1.1":
                    await self.respond(writer, 404, {"error": "Unsupported capture endpoint"})
                    return
                headers = {}
                for line in lines[1:-2]:
                    name, separator, value = line.partition(":")
                    name = name.lower()
                    if not separator or name in headers or not name or line[0].isspace():
                        raise ValueError("Invalid HTTP headers")
                    headers[name] = value.strip()
                if (
                    headers.get("host") not in self.authorities
                    or "origin" in headers
                    or "transfer-encoding" in headers
                    or not hmac.compare_digest(
                        headers.get("authorization", ""), "Bearer " + self.token
                    )
                ):
                    await self.respond(writer, 403, {"error": "Capture authentication failed"})
                    return
                length = headers.get("content-length", "")
                if not length.isdigit() or not 0 < int(length) <= self.ctx.settings["MAX_BYTES"]:
                    await self.respond(writer, 413, {"error": "Capture byte limit exceeded"})
                    return
                if headers.get("content-type", "").split(";", 1)[0] != "application/json":
                    raise ValueError("Capture requires application/json")
                content = await reader.readexactly(int(length))
                document = load_json(content)
                records, context, tags = capture_records(
                    document,
                    self.origins,
                    self.ctx.settings["MAX_ENTRIES"],
                    self.ctx.settings["MAX_BODY_BYTES"],
                )
                if self.count + len(records) > self.ctx.settings["MAX_CAPTURES"]:
                    await self.respond(writer, 409, {"error": "Receiver capture limit reached"})
                    return
                identifiers = []
                for request, response, original in records:
                    register_request_secrets(self.ctx, request)
                    self.ctx.secrets.extend(header_secrets((response or {}).get("headers", {})))
                    source = {"format": "burp-bridge", "received_at": utc_now()}
                    identifier = self.vault.exchange(
                        request, response, source=source, context=context, tags=tags
                    )
                    capture = self.vault.put(
                        "capture",
                        {"request_id": identifier, "private_raw": True},
                        private=original,
                        source=source,
                    )
                    self.vault.link(capture, identifier, "captured_request")
                    self.ctx.report["results"].append(
                        {
                            "kind": "burp_capture",
                            "request_id": identifier,
                            "capture_id": capture,
                            "url": request["url"],
                            "method": request["method"],
                            "status": (response or {}).get("status"),
                            "context": context,
                            "received_at": source["received_at"],
                            "private_raw": True,
                            "scope_authorizes_requests": False,
                        }
                    )
                    identifiers.append(identifier)
                self.count += len(records)
                self.checkpoint()
                await self.respond(
                    writer, 200, {"record_ids": identifiers, "captured": len(records)}
                )
                if self.count >= self.ctx.settings["MAX_CAPTURES"]:
                    self.stop.set()
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            await self.respond(writer, 400, {"error": "Invalid or unsupported capture data"})
        except sqlite3.DatabaseError:
            await self.respond(writer, 503, {"error": "Capture vault is unavailable"})
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
            pass
        finally:
            self.tasks.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


def capture_origins(values):
    if not values:
        raise ValueError("Supply explicit ORIGINS for selected Burp captures")
    origins = set()
    for value in values:
        url = normalize_url(value)
        parsed = urlsplit(url)
        if parsed.path not in {"", "/"} or parsed.query:
            raise ValueError("ORIGINS must contain origins without endpoint paths or queries")
        origins.add(origin(url))
    return origins
