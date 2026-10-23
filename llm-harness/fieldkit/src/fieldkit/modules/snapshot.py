"""Page inventory and optional browser screenshots using the shared scoped transport."""

import hashlib
import html
from html.parser import HTMLParser

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule, write_private
from fieldkit.core.module import Option


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.parts.append(data)


def page_title(body):
    parser = TitleParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    return " ".join("".join(parser.parts).split())[:500]


class Snapshot(NetworkModule):
    name = "web/snapshot"
    description = "Capture titles, response metadata, screenshots, and a local visual gallery."
    options = COMMON_OPTIONS + (
        Option(
            "SCREENSHOT",
            bool,
            True,
            "Capture browser screenshots (requires browser extra)",
            "--screenshot",
        ),
        Option("WIDTH", int, 1440, "Screenshot viewport width", "--width"),
        Option("HEIGHT", int, 900, "Screenshot viewport height", "--height"),
        Option("MAX_PAGES", int, 50, "Maximum pages to capture", "--max-pages"),
    )

    def validate(self, settings):
        if not (320 <= settings["WIDTH"] <= 3840 and 200 <= settings["HEIGHT"] <= 2160):
            raise ValueError("Viewport must be width 320-3840, height 200-2160")
        if settings["MAX_PAGES"] <= 0:
            raise ValueError("MAX_PAGES must be positive")
        if settings["SCREENSHOT"]:
            try:
                import playwright.async_api  # noqa: F401
            except ImportError as exc:
                raise ValueError(
                    "Install screenshots: pip install -e '.[browser]' then "
                    "python -m playwright install chromium"
                ) from exc

    async def assess(self, ctx):
        records = []
        for url in ctx.seed_urls()[: ctx.settings["MAX_PAGES"]]:
            response = await ctx.fetch(url)
            record = {
                "url": url,
                "final_url": response.url,
                "status": response.status,
                "title": page_title(response.body),
                "bytes": len(response.body),
                "content_type": response.content_type,
                "redirects": [
                    {"url": item["url"], "status": item["status"]} for item in response.history
                ],
                "evidence": [response.evidence_id],
                "error": response.error,
            }
            ctx.report["results"].append(record)
            ctx.add_endpoint(url, title=record["title"], status=response.status)
            records.append(record)
        if ctx.settings["SCREENSHOT"]:
            await self._screenshots(ctx, records)
        cards = []
        for record in records:
            image = (
                f'<img src="{html.escape(record["screenshot"], quote=True)}" alt="Page screenshot">'
                if record.get("screenshot")
                else "<p>No screenshot</p>"
            )
            cards.append(
                f"<article><h2>{html.escape(record['title'] or 'Untitled')}</h2>"
                f"<p>{html.escape(record['url'])} — {record['status']}</p>{image}</article>"
            )
        gallery = (
            '<!doctype html><html><head><meta charset="utf-8"><title>Fieldkit snapshots</title>'
            "<style>body{font:16px system-ui;background:#111827;color:#e5e7eb;margin:2rem}"
            "main{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:1rem}"
            "article{padding:1rem;background:#1f2937;border-radius:8px;overflow-wrap:anywhere}"
            "img{width:100%}</style></head><body><h1>Fieldkit snapshots</h1><main>"
            + "".join(cards)
            + "</main></body></html>"
        )
        write_private(ctx.store.root / "gallery.html", gallery)

    async def _screenshots(self, ctx, records):
        from playwright.async_api import Error, async_playwright

        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch()
            except Error as exc:
                raise ValueError(
                    "Chromium unavailable. Run: python -m playwright install chromium"
                ) from exc
            try:
                for record in records:
                    if record["error"]:
                        continue
                    context = await browser.new_context(
                        viewport={"width": ctx.settings["WIDTH"], "height": ctx.settings["HEIGHT"]},
                        service_workers="block",
                        accept_downloads=False,
                    )
                    blocked = []

                    async def route_request(route, _request=None, blocked=blocked):
                        request = route.request
                        if request.method not in {"GET", "HEAD"} or not ctx.in_scope(request.url):
                            blocked.append({"url": request.url, "method": request.method})
                            await route.abort()
                            return
                        response = await ctx.fetch(
                            request.url, method=request.method, follow_redirects=False
                        )
                        if response.error or response.status is None:
                            await route.abort()
                            return
                        headers = {
                            k: v
                            for k, v in response.headers.items()
                            if k.lower()
                            not in {
                                "content-encoding",
                                "content-length",
                                "transfer-encoding",
                                "set-cookie",
                            }
                        }
                        # Shared client maintains cookies; don't forward browser-controlled auth.
                        await route.fulfill(
                            status=response.status, headers=headers, body=response.body
                        )

                    await context.route("**/*", route_request)
                    await context.route_web_socket("**/*", lambda socket: socket.close())
                    page = await context.new_page()
                    page.set_default_timeout(ctx.settings["TIMEOUT"] * 1000)
                    try:
                        await page.goto(record["url"], wait_until="load")
                        digest = hashlib.sha256(record["url"].encode()).hexdigest()[:20]
                        path = f"screenshots/{digest}.png"
                        screenshot = await page.screenshot(
                            full_page=False,
                            animations="disabled",
                            timeout=ctx.settings["TIMEOUT"] * 1000,
                        )
                        write_private(ctx.store.root / path, screenshot)
                        record["screenshot"] = path
                        record["rendered_title"] = await page.title()
                        record["blocked_browser_requests"] = blocked
                    except Error as exc:
                        record["screenshot_error"] = str(exc)
                        ctx.report["errors"].append(
                            {"url": record["url"], "error": "screenshot_failed"}
                        )
                    finally:
                        await context.close()
            finally:
                await browser.close()
