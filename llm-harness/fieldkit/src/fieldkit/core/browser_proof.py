"""Instrumented browser canaries through the scoped HTTP runtime."""

import asyncio
import hashlib
import json
import time

from fieldkit.core.assessment import write_private
from fieldkit.core.redaction import redact
from fieldkit.core.storage import utc_now


def proof_evidence(ctx, value, source, *, raw=None):
    identifier = f"xss-evidence-{len(ctx.report['evidence']) + 1:06d}"
    relative = f"evidence/{identifier}.json"
    content = json.dumps(redact(value, ctx.secrets), indent=2).encode()
    write_private(ctx.store.root / relative, content)
    ctx.report["evidence"].append(
        {
            "id": identifier,
            "file": relative,
            "source": source,
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "private_raw": False,
        }
    )
    if raw is not None:
        private_path, private_content = raw
        write_private(ctx.store.root / private_path, private_content)
        ctx.report.setdefault("private_artifacts", []).append(
            {"file": private_path, "private_raw": True, "bytes": len(private_content)}
        )
    return identifier


class BrowserProof:
    """The proof callback is intercepted, never forwarded to the external listener.

    Allowed GET/HEAD requests use Fieldkit's HTTP clients. Unmanaged browser
    connections are denied by a local rejecting proxy, with direct UDP disabled.
    The canary POST must match its exact URL, body, and a scoped document frame.
    """

    def __init__(self, ctx, callback_url, proof_body, *, max_requests=64):
        self.ctx, self.callback_url, self.proof_body = ctx, callback_url, proof_body
        self.max_requests = max_requests
        self.playwright = self.browser = None
        self._proxy = None

    @staticmethod
    def _reject_connection(_reader, writer):
        # Never parse, retain, or forward browser data, including CONNECT requests.
        writer.transport.abort()

    async def start(self):
        from playwright.async_api import Error, async_playwright

        try:
            # HTTP route interception does not cover WebRTC/STUN/TURN or every
            # browser networking API. Reserve our own rejecting endpoint rather
            # than relying on an apparently unused port remaining unavailable.
            self._proxy = await asyncio.start_server(
                self._reject_connection, "127.0.0.1", 0, limit=1024, backlog=8
            )
            port = self._proxy.sockets[0].getsockname()[1]
            self.playwright = await async_playwright().start()
            try:
                self.browser = await self.playwright.chromium.launch(
                    proxy={"server": f"http://127.0.0.1:{port}"},
                    args=[
                        "--proxy-bypass-list=<-loopback>",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                        "--disable-quic",
                        "--host-resolver-rules=MAP * ~NOTFOUND",
                    ],
                    timeout=min(self.ctx.settings["TIMEOUT"], self.remaining()) * 1000,
                )
            except Error as exc:
                raise ValueError(
                    "Chromium unavailable; run python -m playwright install chromium"
                ) from exc
        except BaseException:
            await self.close()
            raise

    def remaining(self):
        remaining = self.ctx.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Run time budget exhausted")
        return remaining

    async def close(self):
        browser, self.browser = self.browser, None
        playwright, self.playwright = self.playwright, None
        proxy, self._proxy = self._proxy, None
        if proxy is not None:
            proxy.close()
        try:
            if browser:
                await browser.close()
        finally:
            try:
                if playwright:
                    await playwright.stop()
            finally:
                if proxy is not None:
                    await proxy.wait_closed()

    async def render(self, url, profile, *, wait_seconds=2, screenshot=True):
        from playwright.async_api import Error

        ctx = self.ctx
        if not ctx.in_scope(url) or profile not in ctx.profiles:
            raise ValueError("Browser URL/profile is outside supplied scope")
        record = {
            "kind": "xss-browser",
            "url": url,
            "profile": profile,
            "outcome": "not_observed",
            "marker_present_in_document": False,
            "execution_events": [],
            "blocked_requests": [],
            "requests": 0,
            "evidence": [],
        }
        context = await self.browser.new_context(
            service_workers="block", accept_downloads=False, viewport={"width": 1280, "height": 800}
        )
        execution = asyncio.Event()
        marker = self.callback_url.rstrip("/").rsplit("/", 1)[-1]

        async def route_request(route):
            request = route.request
            record["requests"] += 1
            if record["requests"] > self.max_requests:
                record["request_limit_reached"] = True
                await route.abort()
                return
            if request.url == self.callback_url:
                try:
                    frame_url = request.frame.url
                except Error:
                    frame_url = ""
                body = request.post_data_buffer or b""
                if (
                    request.method == "POST"
                    and body == self.proof_body.encode()
                    and ctx.in_scope(frame_url)
                ):
                    record["execution_events"].append(
                        {
                            "received_at": utc_now(),
                            "frame_url": frame_url,
                            "resource_type": request.resource_type,
                            "method": "POST",
                            "body_sha256": hashlib.sha256(body).hexdigest(),
                            "forwarded_to_listener": False,
                        }
                    )
                    execution.set()
                    await route.fulfill(status=204, body="")
                else:
                    await route.abort()
                return
            if request.method not in {"GET", "HEAD"} or not ctx.in_scope(request.url):
                if len(record["blocked_requests"]) < self.max_requests:
                    record["blocked_requests"].append(
                        {
                            "url": request.url[:8192],
                            "method": request.method,
                            "reason": "scope/method/limit",
                        }
                    )
                await route.abort()
                return
            try:
                response = await ctx.fetch(
                    request.url, method=request.method, profile=profile, follow_redirects=False
                )
                record["evidence"].append(response.evidence_id)
                if response.error or response.status is None:
                    await route.abort()
                    return
                if request.resource_type == "document" and marker.encode() in response.body:
                    record["marker_present_in_document"] = True
                headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower()
                    not in {"content-encoding", "content-length", "transfer-encoding", "set-cookie"}
                }
                await route.fulfill(status=response.status, headers=headers, body=response.body)
            except (TimeoutError, ValueError):
                await route.abort()
                raise

        await context.route("**/*", route_request)
        await context.route_web_socket("**/*", lambda socket: socket.close())
        page = await context.new_page()
        page.on("dialog", lambda dialog: dialog.dismiss())
        page.set_default_timeout(min(ctx.settings["TIMEOUT"], self.remaining()) * 1000)
        try:
            async with asyncio.timeout(self.remaining()):
                await page.goto(url, wait_until="load")
                if wait_seconds and not execution.is_set():
                    try:
                        await asyncio.wait_for(
                            execution.wait(), min(wait_seconds, self.remaining())
                        )
                    except TimeoutError:
                        pass
                record["outcome"] = (
                    "confirmed"
                    if execution.is_set()
                    else "inconclusive"
                    if record.get("request_limit_reached")
                    else "not_observed"
                )
                if screenshot:
                    image = await page.screenshot(
                        full_page=False,
                        animations="disabled",
                        timeout=min(ctx.settings["TIMEOUT"], self.remaining()) * 1000,
                    )
                    private_path = "private-raw/xss-browser.png"
                    write_private(ctx.store.root / private_path, image)
                    record["screenshot"] = {"file": private_path, "private_raw": True}
        except Error:
            record["outcome"] = "confirmed" if execution.is_set() else "inconclusive"
            record["error"] = "browser_render_failed"
            ctx.report["errors"].append({"error": "browser_render_failed", "url": url})
            ctx.report["partial"] = True
        finally:
            await context.close()
            if record.get("request_limit_reached"):
                ctx.report["errors"].append({"error": "browser_request_limit", "url": url})
                ctx.report["partial"] = True
            record["evidence"].append(proof_evidence(ctx, record, "instrumented-browser"))
        return record
