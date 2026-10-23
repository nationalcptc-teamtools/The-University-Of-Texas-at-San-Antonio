"""Bounded same-scope crawl of robots, sitemaps, links, and forms."""

from collections import deque
from urllib.parse import urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.modules.discovery_helpers import (
    get_seed_urls,
    is_html,
    page_base,
    parse_page,
    positive_limits,
    robots_references,
    sitemap_references,
)


class SiteMap(NetworkModule):
    name = "web/site-map"
    description = "Inventory scoped links, forms, robots entries, and sitemap URLs."
    options = COMMON_OPTIONS + (
        Option("MAX_PAGES", int, 100, "Maximum fetched URLs for the entire run", "--max-pages"),
        Option("MAX_DEPTH", int, 3, "Maximum discovery depth from seed URLs", "--max-depth"),
        Option(
            "SKIP_PATHS",
            list,
            ["logout", "signout", "delete", "remove"],
            "Skip crawling paths containing these terms; repeat flag",
            "--skip-path",
        ),
    )

    def validate(self, settings: dict) -> None:
        positive_limits(settings, "MAX_PAGES")
        if settings["MAX_DEPTH"] < 0:
            raise ValueError("MAX_DEPTH must be nonnegative")

    async def assess(self, ctx) -> None:
        queue = deque()
        queued = set()
        limit = ctx.settings["MAX_PAGES"]
        summary = {"kind": "crawl-summary", "fetched": 0, "skipped": [], "limited": False}
        # Cap both pending work and inventory growth when a page contains many links.
        inventory_limit = max(limit * 20, 100)
        discovered = set()

        def enqueue(reference, base, depth, source, kind="link", method="GET", **metadata):
            url = ctx.resolve(reference, base)
            if not url:
                return
            if len(discovered) >= inventory_limit and url not in discovered:
                summary["limited"] = True
                return
            discovered.add(url)
            ctx.add_endpoint(url, method=method, source=source, discovery=kind, **metadata)
            if method != "GET" or kind == "form":
                return
            if any(
                term.lower() in urlsplit(url).path.lower() for term in ctx.settings["SKIP_PATHS"]
            ):
                if len(summary["skipped"]) < 100:
                    summary["skipped"].append({"url": url, "reason": "skip-path"})
                return
            if depth <= ctx.settings["MAX_DEPTH"] and url not in queued:
                if len(queued) >= limit:
                    summary["limited"] = True
                    return
                queued.add(url)
                queue.append((url, depth, kind))
            elif depth > ctx.settings["MAX_DEPTH"]:
                summary["limited"] = True

        for base in ctx.targets:
            for path, kind in [
                ("/", "seed"),
                ("/robots.txt", "robots"),
                ("/sitemap.xml", "sitemap"),
            ]:
                enqueue(path, base, 0, base, kind)
        for url in get_seed_urls(ctx):
            enqueue(url, url, 0, url, "seed")
        while queue:
            url, depth, kind = queue.popleft()
            response = await ctx.fetch(url)
            summary["fetched"] += 1
            record = {
                "kind": "page",
                "url": url,
                "status": response.status,
                "depth": depth,
                "evidence": response.evidence_id,
            }
            ctx.report["results"].append(record)
            if response.status in {401, 403}:
                ctx.finding(
                    "authentication-boundary",
                    "Endpoint requires authentication or permission",
                    url,
                    evidence=response.evidence_id,
                    status=response.status,
                )
            if response.error or response.status is None or not 200 <= response.status < 300:
                continue
            current = response.url
            if is_html(response.content_type, response.body):
                page = parse_page(response.body)
                record["title"] = page.title.strip()
                base = page_base(page, current)
                for reference, tag in page.links:
                    enqueue(reference, base, depth + 1, current, tag)
                for form in page.forms:
                    # Empty action submits to document URL, unaffected by <base>.
                    enqueue(
                        form["action"] or current,
                        base,
                        depth + 1,
                        current,
                        "form",
                        form["method"],
                        parameters=form["parameters"],
                    )
                continue
            refs = []
            if urlsplit(current).path.endswith("robots.txt"):
                refs = robots_references(response.body)
            elif kind == "sitemap" or urlsplit(current).path.endswith(".xml"):
                try:
                    refs = sitemap_references(response.body)
                except ValueError as exc:
                    record["parse_error"] = str(exc)
            for reference, discovered_kind in refs:
                enqueue(reference, current, depth + 1, current, discovered_kind)
        summary["discovered"] = len(discovered)
        ctx.report["results"].append(summary)
