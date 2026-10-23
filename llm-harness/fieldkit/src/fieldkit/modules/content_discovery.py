"""Wordlist content discovery with per-directory wildcard calibration."""

import asyncio
import hashlib
import html
import uuid
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import unquote, urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.modules.discovery_helpers import get_seed_urls, positive_limits
from fieldkit.modules.web_artifacts import validate_path

DEFAULT_WORDS = (
    "admin/",
    "login",
    "api/",
    "docs/",
    "backup/",
    "backups/",
    "config/",
    "uploads/",
    ".git/HEAD",
    ".env",
    "server-status",
    "health",
    "debug/",
    "swagger.json",
    "openapi.json",
)


def normalized_body(response) -> bytes:
    body = response.body
    for url in dict.fromkeys([response.requested_url, response.url]):
        path = urlsplit(url).path
        for value in {url, path, unquote(path), html.escape(url), html.escape(path)}:
            if value and value != "/":
                body = body.replace(value.encode(), b"<REQUEST>")
    return body


def wildcard_match(response, baseline, threshold: float) -> bool:
    if baseline.error or baseline.status != response.status:
        return False
    if response.content_type.split(";")[0] != baseline.content_type.split(";")[0]:
        return False
    # Preserve meaningful differences between empty-body redirects.
    if 300 <= (response.status or 0) < 400:
        if response.headers.get("location") != baseline.headers.get("location"):
            return False
    body, other = normalized_body(response), normalized_body(baseline)
    if body == other:
        return True
    # Diff only bounded small samples to avoid quadratic work on large documents.
    if body and other and max(len(body), len(other)) <= 8192:
        if min(len(body), len(other)) / max(len(body), len(other)) < threshold:
            return False
        return SequenceMatcher(None, body, other, autojunk=True).ratio() >= threshold
    return False


class ContentDiscovery(NetworkModule):
    name = "web/content-discovery"
    description = "Probe scoped wordlists and extension variants; filter wildcard responses."
    options = COMMON_OPTIONS + (
        Option("WORDLIST", str, "", "File of root-relative paths or words", "--wordlist"),
        Option("WORDS", list, [], "Words/paths to probe; repeat flag", "--word"),
        Option("EXTENSIONS", list, [], "Extra file suffixes, e.g. php or .bak", "--extension"),
        Option("MAX_CANDIDATES", int, 1000, "Maximum candidates per run", "--max-candidates"),
        Option("SOFT_404", bool, True, "Calibrate and filter wildcard responses", "--soft-404"),
        Option(
            "SIMILARITY", float, 0.98, "Wildcard body similarity threshold (0.8..1)", "--similarity"
        ),
    )

    def _paths(self, settings):
        words = list(settings["WORDS"])
        if settings["WORDLIST"]:
            path = Path(settings["WORDLIST"]).expanduser()
            if path.stat().st_size > 10485760:
                raise ValueError("WORDLIST must be no larger than 10 MiB")
            words.extend(
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        if not words:
            words = list(DEFAULT_WORDS)
        suffixes = [""]
        for extension in settings["EXTENSIONS"]:
            if (
                not extension
                or any(ch in extension for ch in "/\\?#")
                or any(ch.isspace() for ch in extension)
            ):
                raise ValueError("EXTENSIONS must be suffixes such as php, .js, or .bak")
            suffixes.append(extension if extension.startswith(".") else "." + extension)
        paths = []
        for word in words:
            path = validate_path(word if word.startswith("/") else "/" + word)
            paths.append(path)
            if not path.endswith("/") and "?" not in path:
                paths.extend(path + suffix for suffix in suffixes[1:])
        return list(dict.fromkeys(paths))

    def validate(self, settings):
        positive_limits(settings, "MAX_CANDIDATES")
        if not 0.8 <= settings["SIMILARITY"] <= 1:
            raise ValueError("SIMILARITY must be between 0.8 and 1")
        self._paths(settings)

    async def assess(self, ctx):
        paths = self._paths(ctx.settings)
        urls = []
        for base in ctx.targets:
            for path in paths:
                url = ctx.resolve(path, base)
                if url and url not in urls:
                    urls.append(url)
        if ctx.settings["PATHS"] or ctx.settings["INVENTORY"]:
            urls.extend(url for url in get_seed_urls(ctx) if url not in urls)
        total = len(urls)
        urls = urls[: ctx.settings["MAX_CANDIDATES"]]
        baselines = {}
        # Calibration is sequential once per distinct directory/extension shape.
        if ctx.settings["SOFT_404"]:
            for url in urls:
                key = self._shape(url)
                if key in baselines:
                    continue
                directory, suffix = key
                baselines[key] = [
                    await ctx.fetch(
                        directory + ".fieldkit-missing-" + uuid.uuid4().hex + suffix,
                        follow_redirects=False,
                    )
                    for _ in range(2)
                ]
        queue = asyncio.Queue()
        for url in urls:
            queue.put_nowait(url)
        counts = Counter()

        async def worker():
            while not queue.empty():
                url = queue.get_nowait()
                response = await ctx.fetch(url, follow_redirects=False)
                match = None
                if response.error:
                    verdict = response.error
                elif response.status in {404, 410}:
                    verdict = "missing"
                else:
                    match = next(
                        (
                            item
                            for item in baselines.get(self._shape(url), [])
                            if wildcard_match(response, item, ctx.settings["SIMILARITY"])
                        ),
                        None,
                    )
                    verdict = "wildcard" if match else "interesting"
                record = {
                    "kind": "content",
                    "url": url,
                    "status": response.status,
                    "content_type": response.content_type,
                    "bytes": len(response.body),
                    "sha256": hashlib.sha256(response.body).hexdigest(),
                    "verdict": verdict,
                    "evidence": response.evidence_id,
                }
                if match:
                    record["baseline_evidence"] = match.evidence_id
                if verdict == "interesting":
                    ctx.add_endpoint(url, status=response.status, source="content-discovery")
                    record["rank"] = (
                        3
                        if response.status is not None and 200 <= response.status < 300
                        else 2
                        if response.status in {401, 403}
                        else 1
                    )
                    ctx.finding(
                        "discovered-content",
                        "Content discovery response differs from baseline",
                        url,
                        evidence=response.evidence_id,
                        status=response.status,
                        content_type=response.content_type,
                        bytes=len(response.body),
                    )
                counts[verdict] += 1
                ctx.report["results"].append(record)
                queue.task_done()

        await asyncio.gather(
            *(worker() for _ in range(min(ctx.settings["CONCURRENCY"], len(urls))))
        )
        ctx.report["results"].append(
            {
                "kind": "discovery-summary",
                "counts": dict(counts),
                "candidates": len(urls),
                "limited": total > len(urls),
                "calibration_failures": sum(
                    response.error is not None for group in baselines.values() for response in group
                ),
            }
        )

    @staticmethod
    def _shape(url):
        parsed = urlsplit(url)
        directory, _, filename = parsed.path.rpartition("/")
        suffix = "/" if not filename else Path(filename).suffix
        return f"{parsed.scheme}://{parsed.netloc}{directory}/", suffix
