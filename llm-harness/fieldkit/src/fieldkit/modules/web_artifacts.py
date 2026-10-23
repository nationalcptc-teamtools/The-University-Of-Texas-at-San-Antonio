"""Collect potentially useful public web files for offline manual review."""

import asyncio
import hashlib
import html
import uuid
from collections import Counter
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from rich.console import Console

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.http import Fetcher, FetchResult, origin
from fieldkit.core.module import Option
from fieldkit.core.storage import ArtifactStore

DEFAULT_PATHS = (
    "/robots.txt",
    "/.well-known/security.txt",
    "/security.txt",
    "/secrets.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/JS",
    "/JS/",
    "/js/",
    "/.js",
    "/.bak",
    "/app.js",
    "/main.js",
    "/index.js",
    "/script.js",
    "/scripts.js",
    "/js/app.js",
    "/js/main.js",
    "/js/scripts.js",
    "/assets/app.js",
    "/assets/main.js",
    "/static/js/main.js",
    "/index.html.bak",
    "/index.php.bak",
    "/config.php.bak",
    "/web.config.bak",
)


class ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []
        self.base: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "base" and self.base is None and attributes.get("href"):
            self.base = attributes["href"]
        if tag == "script" and attributes.get("src"):
            self.references.append(attributes["src"])
        if tag == "link" and attributes.get("href"):
            href = attributes["href"]
            try:
                is_script = urlsplit(href).path.lower().endswith((".js", ".mjs"))
            except ValueError:
                return
            if is_script:
                self.references.append(href)


def discover_scripts(page: FetchResult, target: str) -> list[str]:
    parser = ScriptParser()
    parser.feed(page.body.decode("utf-8", errors="replace"))
    try:
        base = urljoin(page.url, parser.base) if parser.base else page.url
    except ValueError:
        base = page.url
    urls: list[str] = []
    for reference in parser.references:
        try:
            url = urldefrag(urljoin(base, reference))[0]
            parsed = urlsplit(url)
            if (
                origin(url) == origin(target)
                and parsed.username is None
                and parsed.password is None
                and url not in urls
            ):
                urls.append(url)
        except ValueError:
            continue
    return urls


def validate_path(path: str) -> str:
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.netloc
        or parsed.scheme
        or parsed.fragment
        or "\\" in path
        or any(c.isspace() for c in path)
    ):
        raise ValueError(f"Paths must be root-relative, e.g. /assets/site.js: {path}")
    return path


def backup_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit(parsed._replace(path=parsed.path + ".bak"))


def fingerprint(result: FetchResult) -> str:
    """Recognize a common fallback body, including reflected missing paths."""
    body = result.body
    for url in dict.fromkeys([result.requested_url, result.url]):
        path = urlsplit(url).path
        for value in [url, html.escape(url), path, html.escape(path)]:
            if value and value != "/":
                body = body.replace(value.encode(), b"<REQUEST>")
    return hashlib.sha256(body).hexdigest()


class WebArtifacts(NetworkModule):
    name = "web/artifacts"
    description = "Collect robots, security, secrets, sitemaps, JavaScript, and backup files."
    options = COMMON_OPTIONS + (
        Option("PATHS_FILE", str, "", "File of extra root-relative paths", "--paths-file"),
        Option("ONLY_CUSTOM", bool, False, "Skip built-in paths", "--only-custom"),
        Option("DISCOVER_JS", bool, True, "Discover scripts from the homepage", "--discover-js"),
        Option("BACKUPS", bool, True, "Probe .bak variants of candidate files", "--backups"),
        Option("SOFT_404", bool, True, "Compare bodies with a missing-page baseline", "--soft-404"),
        Option("MAX_JS", int, 100, "Maximum discovered script URLs per target", "--max-js"),
    )

    def validate(self, settings):
        if settings["MAX_JS"] <= 0:
            raise ValueError("MAX_JS must be positive")
        paths = list(settings["PATHS"])
        if settings["PATHS_FILE"]:
            from pathlib import Path

            paths.extend(
                line.strip()
                for line in Path(settings["PATHS_FILE"]).expanduser().read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        self._paths = list(dict.fromkeys(validate_path(path) for path in paths))
        if settings["ONLY_CUSTOM"] and not self._paths and not settings["INVENTORY"]:
            raise ValueError("--only-custom requires --path, --paths-file, or --inventory")

    async def _execute(self, ctx):
        # Collector keeps its per-target probes/manifest for backward compatibility.
        async with ctx:
            async with asyncio.timeout(ctx.settings["BUDGET"]):
                await self.assess(ctx)

    async def assess(self, ctx):
        ctx.report["targets"] = []
        queue = asyncio.Queue()
        for urls in ctx.candidates:
            queue.put_nowait(urls)

        class Transport:
            async def get(self, url, allowed_origin):
                return await ctx.fetch(url, record_errors=False)

        async def worker():
            while not queue.empty():
                urls = queue.get_nowait()
                paths = list(self._paths)
                # Imported candidates remain constrained to this target origin.
                for entry in ctx.imported_endpoints:
                    if origin(entry["url"]) in {origin(url) for url in urls}:
                        parsed = urlsplit(entry["url"])
                        paths.append(parsed.path + ("?" + parsed.query if parsed.query else ""))
                await self._scan_target(
                    urls[0],
                    list(urls),
                    paths,
                    ctx.settings,
                    Transport(),
                    ctx.store,
                    ctx.report,
                    ctx.console,
                )
                queue.task_done()

        try:
            await asyncio.gather(
                *(worker() for _ in range(min(ctx.settings["CONCURRENCY"], len(ctx.candidates))))
            )
        finally:
            for target in ctx.report["targets"]:
                ctx.targets.append(target["origin"])
                ctx.report["results"].extend(target["results"])
                if target["had_errors"]:
                    ctx.report["errors"].append(
                        {"url": target["origin"], "error": "candidate_errors"}
                    )
                for result in target["results"]:
                    if result["verdict"] == "saved":
                        ctx.add_endpoint(
                            result["requested_url"],
                            content_type=result["content_type"],
                            file=result["file"],
                        )
            ctx.report["target_origins"] = ctx.targets

    async def _scan_target(
        self,
        target: str,
        urls: list[str],
        custom_paths: list[str],
        settings: dict[str, Any],
        fetcher: Fetcher,
        store: ArtifactStore,
        report: dict,
        console: Console,
    ) -> None:
        entry: dict[str, Any] = {
            "input": target,
            "origin": None,
            "completed": False,
            "had_errors": False,
            "probes": [],
            "results": [],
            "notes": [],
        }
        report["targets"].append(entry)
        home = None
        for base in urls:
            home = await fetcher.get(base, base)
            entry["probes"].append(self._record(home, "homepage"))
            if home.error not in {"network_error", "profile_scope"}:
                break
        assert home is not None
        entry["origin"] = base
        if home.error in {"network_error", "profile_scope"} and len(urls) > 1:
            entry["had_errors"] = True
            entry["completed"] = True
            console.print(f"[error] {target}: {home.detail}", markup=False)
            return
        if len(entry["probes"]) > 1:
            entry["notes"].append("HTTPS failed; used HTTP fallback.")
        if home.error:
            entry["notes"].append(f"Homepage probe: {home.error}; explicit paths still checked.")
        console.print(f"[scan] {base}", markup=False)

        baseline = None
        if settings["SOFT_404"]:
            missing = urljoin(base, f"/.fieldkit-missing-{uuid.uuid4().hex}")
            baseline = await fetcher.get(missing, base)
            entry["probes"].append(self._record(baseline, "missing-page baseline"))
            if baseline.error:
                entry["notes"].append(
                    "Missing-page baseline unavailable; soft-404 detection limited."
                )
        paths = custom_paths if settings["ONLY_CUSTOM"] else [*DEFAULT_PATHS, *custom_paths]
        candidates = dict.fromkeys(urljoin(base, path) for path in paths)
        if settings["DISCOVER_JS"] and home.status and 200 <= home.status < 300 and not home.error:
            discovered = discover_scripts(home, base)
            candidates.update(dict.fromkeys(discovered[: settings["MAX_JS"]]))
            entry["discovered_js"] = min(len(discovered), settings["MAX_JS"])
            if len(discovered) > settings["MAX_JS"]:
                entry["notes"].append(f"Script discovery limited to {settings['MAX_JS']} URLs.")
        if settings["BACKUPS"]:
            candidates.update(
                dict.fromkeys(
                    backup_url(url)
                    for url in list(candidates)
                    if not urlsplit(url).path.endswith(("/", ".bak"))
                )
            )
        baseline_hash = (
            fingerprint(baseline) if baseline and not baseline.error and baseline.body else None
        )

        async def collect(url: str) -> None:
            result = await fetcher.get(url, base)
            record = self._record(result, "candidate")
            if result.error:
                verdict = result.error
                entry["had_errors"] = True
            elif result.status in {404, 410}:
                verdict = "missing"
            elif result.status is not None and 200 <= result.status < 300:
                if baseline_hash and result.body and fingerprint(result) == baseline_hash:
                    verdict = "soft_404"
                else:
                    verdict = "saved"
                    record.update(store.save(base, url, result.body))
                    if "html" in result.content_type.lower():
                        record["note"] = (
                            "HTML response; manually check for login or fallback pages."
                        )
                    console.print(f"[saved] {url} ({len(result.body)} bytes)", markup=False)
            else:
                verdict = "http_error"
                entry["had_errors"] = True
            record["verdict"] = verdict
            entry["results"].append(record)

        # Fixed workers prevent large path lists from creating a task per candidate.
        candidate_queue: asyncio.Queue[str] = asyncio.Queue()
        for url in candidates:
            candidate_queue.put_nowait(url)

        async def collect_worker() -> None:
            while not candidate_queue.empty():
                await collect(candidate_queue.get_nowait())
                candidate_queue.task_done()

        await asyncio.gather(
            *(collect_worker() for _ in range(min(settings["CONCURRENCY"], len(candidates))))
        )
        entry["results"].sort(key=lambda item: item["requested_url"])
        counts = dict(Counter(r["verdict"] for r in entry["results"]))
        entry["counts"] = counts
        entry["completed"] = True
        console.print(f"[done] {base} {counts}", markup=False)

    @staticmethod
    def _record(result: FetchResult, purpose: str) -> dict:
        return {
            "purpose": purpose,
            "requested_url": result.requested_url,
            "final_url": result.url,
            "status": result.status,
            "content_type": result.content_type,
            "error": result.error,
            "detail": result.detail,
            "evidence": [result.evidence_id],
        }
