"""Static JavaScript and source-map review without executing downloaded code."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote_to_bytes, urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.core.redaction import redact_text
from fieldkit.core.results import load_report

CHECKS = {"endpoints", "routes", "hostnames", "secrets", "maps"}
QUOTED = re.compile(r"""(?P<quote>["'`])(?P<value>(?:https?://|/)[^\s"'`<>]{1,1000})(?P=quote)""")
ABSOLUTE = re.compile(r"""https?://[^\s"'`<>\\)]+""")
MAP_REFERENCE = re.compile(r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*(\S+)")
SECRET_ASSIGNMENT = re.compile(
    r"""(?i)\b(?P<name>api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|authorization)\b["']?\s*[:=]\s*["'](?P<value>[^"'\r\n]{4,500})["']"""
)
TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
)


@dataclass
class Source:
    name: str
    text: str
    url: str = ""
    path: Path | None = None
    root: Path | None = None
    is_map: bool = False


def _inside(path: Path, root: Path) -> bool:
    return path.resolve().is_relative_to(root.resolve())


def _read(path: Path, root: Path, max_bytes: int) -> str:
    if not _inside(path, root):
        raise ValueError(f"Artifact path escapes the input root: {path}")
    if not path.is_file():
        raise ValueError(f"Artifact is not a regular file: {path}")
    with path.open("rb") as stream:
        body = stream.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"Artifact exceeds MAX_BYTES: {path}")
    return body.decode("utf-8", errors="replace")


def local_sources(
    inputs: list[str], max_bytes: int, max_files: int, artifact_roots: list[str] | None = None
) -> list[Source]:
    """Read explicit files, directories, or collection reports within their input roots."""
    sources: list[Source] = []
    seen: set[Path] = set()
    allowed_roots = [Path(root).expanduser().resolve() for root in artifact_roots or []]

    def add(path: Path, root: Path, url: str = "", is_map: bool = False) -> None:
        resolved = path.resolve()
        if resolved in seen:
            return
        if len(sources) >= max_files:
            raise ValueError("Input file limit exceeded; increase --max-files or narrow --input")
        text = _read(path, root, max_bytes)
        seen.add(resolved)
        sources.append(Source(str(path), text, url, resolved, root, is_map))

    for value in inputs:
        path = Path(value).expanduser().resolve()
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.suffix.lower() in {".js", ".mjs", ".cjs", ".map"}:
                    add(candidate, path, is_map=candidate.suffix.lower() == ".map")
        elif path.suffix.lower() == ".json":
            # A report references only files under its own run directory.
            report = load_report(path)
            for result in report["results"]:
                url = (
                    result.get("requested_url") or result.get("url") or result.get("final_url", "")
                )
                location = result.get("file") or result.get("body_file")
                content_type = str(result.get("content_type", "")).lower()
                suffix = urlsplit(url).path.lower()
                if location and (
                    suffix.endswith((".js", ".mjs", ".cjs", ".map")) or "javascript" in content_type
                ):
                    candidate_root = (
                        Path(result.get("artifact_root", path.parent)).expanduser().resolve()
                    )
                    candidate = candidate_root / location
                    root = next(
                        (
                            root
                            for root in [path.parent, *allowed_roots]
                            if _inside(candidate, root)
                        ),
                        None,
                    )
                    if root is None:
                        raise ValueError(
                            "Artifact path escapes the input root; provide --artifact-root "
                            f"for the original run directory: {candidate_root}"
                        )
                    add(candidate, root, url, suffix.endswith(".map"))
        else:
            add(path, path.parent, is_map=path.suffix.lower() == ".map")
    return sources


def _observations(text: str, checks: set[str]) -> list[dict]:
    """Return heuristic leads with source locations and redacted surrounding context."""
    credentials = [(match, match["value"]) for match in SECRET_ASSIGNMENT.finditer(text)]
    credentials.extend((match, match[0]) for match in TOKEN.finditer(text))
    secrets = [value for _, value in credentials]
    output: list[dict] = []
    seen = set()

    def add(kind: str, value: str, match: re.Match, **details) -> None:
        line = text.count("\n", 0, match.start()) + 1
        key = (kind, value, line)
        if key in seen:
            return
        seen.add(key)
        beginning = text.rfind("\n", 0, match.start()) + 1
        ending = text.find("\n", match.end())
        if ending < 0:
            ending = len(text)
        # Minified bundles can have megabyte lines: retain a bounded, useful window.
        beginning = max(beginning, match.start() - 100)
        ending = min(ending, match.end() + 100)
        output.append(
            {
                "kind": kind,
                "value": redact_text(value, secrets),
                "line": line,
                "column": match.start() - text.rfind("\n", 0, match.start()),
                "context": redact_text(text[beginning:ending], secrets),
                **details,
            }
        )

    if checks & {"endpoints", "routes"}:
        for match in QUOTED.finditer(text):
            value = match["value"]
            if "endpoints" in checks:
                add("js-endpoint", value, match)
            if "routes" in checks and (
                re.search(r"[:{][A-Za-z_]", value)
                or re.search(
                    r"\b(?:path|route)\s*:\s*$", text[max(0, match.start() - 25) : match.start()]
                )
            ):
                add("js-route", value, match)
    if "hostnames" in checks:
        for match in ABSOLUTE.finditer(text):
            try:
                hostname = urlsplit(match[0]).hostname
            except ValueError:
                continue
            if hostname:
                add("js-hostname", hostname, match)
    if "secrets" in checks:
        for match, _ in credentials:
            name = match.groupdict().get("name", "credential-shaped literal")
            add("js-possible-secret", "[REDACTED]", match, name=name)
    return output


def source_map_sources(source: Source, max_bytes: int, max_sources: int) -> list[Source]:
    """Inspect embedded sourcesContent only; source names never become filesystem paths."""
    try:
        mapping = json.loads(source.text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid source map {source.name}: {exc.msg}") from exc
    output: list[Source] = []
    remaining = max_bytes

    def inspect(section: dict, depth: int = 0) -> None:
        nonlocal remaining
        if depth > 16:
            raise ValueError("Source map section nesting exceeds 16 levels")
        if not isinstance(section, dict):
            raise ValueError("Source map sections must be objects")
        contents = section.get("sourcesContent", [])
        names = section.get("sources", [])
        if not isinstance(contents, list) or not isinstance(names, list):
            raise ValueError("Source map sources and sourcesContent must be arrays")
        for index, content in enumerate(contents):
            if not isinstance(content, str):
                continue
            if len(output) >= max_sources:
                raise ValueError("Source map embedded source limit exceeded")
            remaining -= len(content.encode())
            if remaining < 0:
                raise ValueError("Source map embedded sources exceed MAX_BYTES")
            name = str(names[index]) if index < len(names) else f"source-{index}"
            output.append(Source(f"{source.name}::{name}", content, source.url))
        for nested in section.get("sections", []):
            if isinstance(nested, dict) and "map" in nested:
                inspect(nested["map"], depth + 1)

    inspect(mapping)
    return output


def _inline_map(reference: str, max_bytes: int) -> str:
    metadata, separator, payload = reference.partition(",")
    if not separator or not metadata.startswith("data:application/json"):
        raise ValueError("Only application/json inline source maps are supported")
    if len(payload) > max_bytes * 4:
        raise ValueError("Inline source map exceeds MAX_BYTES")
    try:
        raw = (
            base64.b64decode(payload, validate=True)
            if ";base64" in metadata
            else unquote_to_bytes(payload)
        )
    except ValueError as exc:
        raise ValueError("Invalid source-map encoding") from exc
    if len(raw) > max_bytes:
        raise ValueError("Inline source map exceeds MAX_BYTES")
    return raw.decode("utf-8", errors="replace")


class JSReview(NetworkModule):
    name = "web/js-review"
    description = "Extract JavaScript leads and inspect source maps without executing code."
    requires_targets = False
    options = COMMON_OPTIONS + (
        Option(
            "INPUT",
            list,
            [],
            "Local JS/map files, directories, or collector JSON reports",
            "--input",
        ),
        Option(
            "CHECKS",
            list,
            [],
            "endpoints, routes, hostnames, secrets, maps (repeat; default all)",
            "--check",
        ),
        Option(
            "FETCH_MAPS",
            bool,
            False,
            "Fetch referenced maps only on explicit target origins",
            "--fetch-maps",
        ),
        Option("MAX_FILES", int, 500, "Maximum input/embedded source files", "--max-files"),
        Option(
            "ARTIFACT_ROOTS",
            list,
            [],
            "Explicit original run roots for relocated report artifacts",
            "--artifact-root",
        ),
    )

    def validate(self, settings: dict) -> None:
        checks = set(settings["CHECKS"] or CHECKS)
        if checks - CHECKS:
            raise ValueError(f"Unknown checks: {', '.join(sorted(checks - CHECKS))}")
        if settings["MAX_FILES"] <= 0:
            raise ValueError("MAX_FILES must be positive")
        if not settings["INPUT"] and not (settings.get("TARGETS") or settings.get("TARGETS_FILE")):
            raise ValueError(
                "Supply --input files/reports or explicit target origins for remote input"
            )
        if settings["FETCH_MAPS"] and not (settings.get("TARGETS") or settings.get("TARGETS_FILE")):
            raise ValueError("--fetch-maps requires explicit --target origins")

    async def assess(self, ctx) -> None:
        settings = ctx.settings
        checks = set(settings["CHECKS"] or CHECKS)
        sources = local_sources(
            settings["INPUT"],
            settings["MAX_BYTES"],
            settings["MAX_FILES"],
            settings["ARTIFACT_ROOTS"],
        )
        seen_maps: set[str] = set()
        # Remote JavaScript candidates are explicit seeds from paths/imported inventories.
        if not settings["INPUT"]:
            for url in ctx.seed_urls():
                if not urlsplit(url).path.lower().endswith((".js", ".mjs", ".cjs", ".map")):
                    continue
                if len(sources) >= settings["MAX_FILES"]:
                    break
                result = await ctx.fetch(url)
                if not result.error and result.status and 200 <= result.status < 300:
                    sources.append(
                        Source(
                            url,
                            result.body.decode("utf-8", errors="replace"),
                            result.url,
                            is_map=urlsplit(url).path.endswith(".map"),
                        )
                    )
        if not sources:
            ctx.report["errors"].append(
                {
                    "error": (
                        "No JavaScript or source-map inputs found; "
                        "supply --input, --path, or a scoped inventory"
                    )
                }
            )
        processed = 0
        while sources and processed < settings["MAX_FILES"]:
            source = sources.pop(0)
            processed += 1
            if source.is_map:
                if "maps" not in checks:
                    continue
                try:
                    embedded = source_map_sources(
                        source, settings["MAX_BYTES"], settings["MAX_FILES"] - processed
                    )
                    sources.extend(embedded)
                    ctx.finding(
                        "js-source-map",
                        "Source map contains original source text",
                        source.url,
                        source=source.name,
                        embedded_sources=len(embedded),
                    )
                except ValueError as exc:
                    ctx.report["errors"].append({"source": source.name, "error": str(exc)})
                continue
            if hasattr(ctx, "secrets"):
                ctx.secrets.extend(
                    match["value"] for match in SECRET_ASSIGNMENT.finditer(source.text)
                )
                ctx.secrets.extend(match[0] for match in TOKEN.finditer(source.text))
            observations = _observations(source.text, checks)
            for observation in observations:
                kind = observation.pop("kind")
                title = {
                    "js-endpoint": "JavaScript endpoint reference",
                    "js-route": "JavaScript route",
                    "js-hostname": "JavaScript hostname",
                    "js-possible-secret": "Possible hardcoded credential",
                }[kind]
                ctx.finding(
                    kind,
                    title,
                    source.url,
                    source=source.name,
                    severity="low" if kind == "js-possible-secret" else "info",
                    **observation,
                )
                if (
                    kind == "js-endpoint"
                    and source.url
                    and "[REDACTED]" not in observation["value"]
                ):
                    resolved = ctx.resolve(observation["value"], source.url)
                    if resolved:
                        ctx.add_endpoint(resolved, source="javascript")
            if "maps" not in checks:
                continue
            for match in MAP_REFERENCE.finditer(source.text):
                reference = match[1].removesuffix("*/")
                key = f"{source.name}:{reference}"
                if key in seen_maps:
                    continue
                seen_maps.add(key)
                try:
                    if reference.startswith("data:"):
                        sources.append(
                            Source(
                                f"{source.name}::inline-map",
                                _inline_map(reference, settings["MAX_BYTES"]),
                                source.url,
                                is_map=True,
                            )
                        )
                        continue
                    ctx.finding(
                        "js-map-reference",
                        "JavaScript source-map reference",
                        source.url,
                        source=source.name,
                        reference=redact_text(reference),
                        line=source.text.count("\n", 0, match.start()) + 1,
                    )
                    local = None
                    if (
                        source.path
                        and source.root
                        and not urlsplit(reference).scheme
                        and not reference.startswith("//")
                    ):
                        from urllib.parse import unquote

                        local = source.path.parent / unquote(urlsplit(reference).path)
                        if not _inside(local, source.root):
                            raise ValueError("Source-map reference escapes the input root")
                        if local.is_file():
                            sources.append(
                                Source(
                                    str(local),
                                    _read(local, source.root, settings["MAX_BYTES"]),
                                    source.url,
                                    local.resolve(),
                                    source.root,
                                    True,
                                )
                            )
                            continue
                    if settings["FETCH_MAPS"] and source.url:
                        url = ctx.resolve(reference, source.url)
                        if url:
                            result = await ctx.fetch(url)
                            if not result.error and result.status and 200 <= result.status < 300:
                                sources.append(
                                    Source(
                                        url,
                                        result.body.decode("utf-8", errors="replace"),
                                        result.url,
                                        is_map=True,
                                    )
                                )
                except ValueError as exc:
                    ctx.report["errors"].append({"source": source.name, "error": str(exc)})
        if sources:
            ctx.report["errors"].append(
                {"error": "MAX_FILES reached; remaining sources were not analyzed"}
            )
        ctx.report["summary"] = {"sources_analyzed": processed, "checks": sorted(checks)}
