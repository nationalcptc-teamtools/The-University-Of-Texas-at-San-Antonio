"""Shared module runtime: scope, sessions, evidence, inventory, and bounded requests."""

import asyncio
import copy
import hashlib
import json
import math
import time
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from rich.console import Console

from fieldkit import __version__
from fieldkit.core.http import Fetcher, FetchResult, RequestControls, origin
from fieldkit.core.module import Module, Option
from fieldkit.core.profiles import jar_cookie, load_profiles
from fieldkit.core.redaction import redact
from fieldkit.core.results import stable_id
from fieldkit.core.storage import ArtifactStore, utc_now
from fieldkit.core.targets import read_targets, target_urls
from fieldkit.core.urls import normalize_url, resolve_url

COMMON_OPTIONS = (
    Option("DATABASE", str, "", "Optional private SQLite capture/correlation vault", "--database"),
    Option(
        "DRY_RUN",
        bool,
        False,
        "Validate inputs and save a plan without network/tool actions",
        "--dry-run",
    ),
    Option(
        "TARGETS", list, [], "Target origins (repeat flag or use positional targets)", "--target"
    ),
    Option("TARGETS_FILE", str, "", "File of target origins", "--targets-file"),
    Option("OUTPUT", str, "artifacts", "Parent directory for a unique run", "--output"),
    Option("SCHEME", str, "auto", "auto, https, or http for bare targets", "--scheme"),
    Option("PATHS", list, [], "Endpoint paths or scoped URLs; repeat flag", "--path"),
    Option("INVENTORY", list, [], "Prior report or inventory JSON; repeat flag", "--inventory"),
    Option(
        "PROFILES_FILE", str, "", "JSON file of origin-bound session profiles", "--profiles-file"
    ),
    Option("PROFILE", str, "anonymous", "Named session profile", "--profile"),
    Option("CONCURRENCY", int, 8, "Maximum concurrent HTTP requests", "--concurrency"),
    Option("TIMEOUT", float, 10.0, "Seconds per HTTP request including redirects", "--timeout"),
    Option("MAX_BYTES", int, 5242880, "Maximum decoded bytes per HTTP response", "--max-bytes"),
    Option("RATE", float, 5.0, "Request starts per second per origin; 0 disables pacing", "--rate"),
    Option(
        "RETRIES",
        int,
        1,
        "Extra attempts for GET/HEAD/OPTIONS network/429/502-504 errors",
        "--retries",
    ),
    Option("BUDGET", float, 300.0, "Total run time budget in seconds", "--budget"),
    Option("INSECURE", bool, False, "Disable certificate verification", "--insecure"),
)


def identifier(kind: str, *parts) -> str:
    payload = json.dumps(parts, sort_keys=True, default=str).encode()
    return f"{kind}-{hashlib.sha256(payload).hexdigest()[:20]}"


def write_private(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value, encoding="utf-8")


def header_secrets(headers: dict) -> list[str]:
    from fieldkit.core.redaction import SENSITIVE

    values = []
    for key, value in headers.items():
        if not SENSITIVE.search(key):
            continue
        values.append(value)
        if key.lower() in {"authorization", "proxy-authorization"} and " " in value:
            values.append(value.split(" ", 1)[1])
        if key.lower() in {"cookie", "set-cookie"}:
            cookie = SimpleCookie()
            try:
                cookie.load(value)
                values.extend(item.value for item in cookie.values())
            except CookieError:
                pass
    return values


def imported_endpoints(filenames: list[str]) -> list[dict]:
    entries = []
    for filename in filenames:
        path = Path(filename).expanduser()
        if path.is_dir():
            path = path / "report.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, list):
            candidates = document
        elif isinstance(document, dict):
            candidates = list(document.get("endpoints", []))
            for target in document.get("targets", []):
                if isinstance(target, dict):
                    candidates.extend(
                        {"url": record.get("requested_url"), "method": "GET"}
                        for record in target.get("results", [])
                        if record.get("verdict") == "saved"
                    )
        else:
            raise ValueError(f"Inventory must be a report object or endpoint list: {filename}")
        for record in candidates:
            if isinstance(record, str):
                record = {"url": record}
            if not isinstance(record, dict) or not isinstance(record.get("url"), str):
                raise ValueError(f"Invalid endpoint entry in {filename}")
            record = dict(record)
            record["url"] = normalize_url(record["url"])
            method = record.get("method", "GET")
            if not isinstance(method, str) or method.upper() not in {
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
                "TRACE",
                "CONNECT",
            }:
                raise ValueError(f"Invalid endpoint method in {filename}")
            record["method"] = method.upper()
            if "parameters" in record and not isinstance(record["parameters"], list):
                raise ValueError(f"Endpoint parameters must be a list in {filename}")
            entries.append(record)
    return entries


class AssessmentContext:
    def __init__(self, module: str, settings: dict, console: Console, store=None, report=None):
        self.settings, self.console = settings, console
        self.profiles = load_profiles(settings.get("PROFILES_FILE", ""))
        selected = settings.get("PROFILE", "anonymous")
        if selected not in self.profiles:
            raise ValueError(f"Unknown profile: {selected}")
        self.secrets = [
            value
            for p in self.profiles.values()
            for value in [
                *header_secrets(p.headers),
                *p.cookies.values(),
                *[c["value"] for c in p.cookie_jar],
            ]
        ]
        self.imported_endpoints = imported_endpoints(settings.get("INVENTORY", []))
        values = settings.get("TARGETS", [])
        filename = settings.get("TARGETS_FILE", "")
        raw = read_targets(values, filename) if values or filename else []
        self.candidates = [
            [normalize_url(url) for url in target_urls(target, settings.get("SCHEME", "auto"))]
            for target in raw
        ]
        self.candidates = list(dict.fromkeys(tuple(group) for group in self.candidates))
        self.scope_origins = list(dict.fromkeys(url for group in self.candidates for url in group))
        # Validate custom paths even for offline modules before creating output.
        for path in settings.get("PATHS", []):
            if not isinstance(path, str) or "\\" in path or any(ord(c) < 32 for c in path):
                raise ValueError("Invalid endpoint path")
            if path.startswith("//") or not (path.startswith("/") or "://" in path):
                raise ValueError("Endpoint paths must start with / or be an absolute scoped URL")
            if self.scope_origins and not any(
                self.resolve(path, base) for base in self.scope_origins
            ):
                raise ValueError(f"Endpoint is outside supplied target origins: {path}")
        self.targets: list[str] = []
        self.store = store or ArtifactStore(settings["OUTPUT"])
        self.report = (
            report
            if report is not None
            else {
                "schema_version": 2,
                "module": module,
                "started_at": utc_now(),
                "completed": False,
                "settings": redact(settings, self.secrets),
            }
        )
        for key in ("results", "findings", "endpoints", "errors", "evidence"):
            self.report.setdefault(key, [])
        self.controls = RequestControls(settings["CONCURRENCY"], settings["RATE"])
        self.clients: dict[str, httpx.AsyncClient] = {}
        self.fetchers: dict[str, Fetcher] = {}
        self.seeded_profiles: set[tuple[str, tuple]] = set()
        self.deadline = time.monotonic() + settings["BUDGET"]
        self._endpoints = {}
        self._findings = {}
        self._evidence_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        for client in self.clients.values():
            await client.aclose()

    async def prepare(self):
        for alternatives in self.candidates:
            chosen = alternatives[0]
            if len(alternatives) > 1:
                for chosen in alternatives:
                    response = await self.fetch(chosen, profile="anonymous", record_errors=False)
                    if response.error != "network_error":
                        break
            self.targets.append(chosen)
        self.targets = list(dict.fromkeys(self.targets))
        self.scope_origins = self.targets
        self.report["target_origins"] = self.targets
        self.imported_endpoints = [e for e in self.imported_endpoints if self.in_scope(e["url"])]
        for entry in self.imported_endpoints:
            metadata = {k: v for k, v in entry.items() if k not in {"id", "url", "method"}}
            self.add_endpoint(entry["url"], entry.get("method", "GET"), **metadata)

    def in_scope(self, url: str) -> bool:
        return resolve_url(url, url, self.scope_origins) is not None

    def resolve(self, reference: str, base: str) -> str | None:
        return resolve_url(reference, base, self.scope_origins)

    def seed_urls(self) -> list[str]:
        paths = self.settings.get("PATHS", [])
        urls = [e["url"] for e in self.imported_endpoints]
        for base in self.targets:
            for path in paths:
                resolved = self.resolve(path, base)
                if resolved:
                    urls.append(resolved)
        return list(dict.fromkeys(urls or self.targets))

    def session(self, profile: str | None = None) -> httpx.AsyncClient:
        profile = profile or self.settings["PROFILE"]
        if profile not in self.profiles:
            raise ValueError(f"Unknown profile: {profile}")
        if profile not in self.clients:
            client = httpx.AsyncClient(
                verify=not self.settings["INSECURE"],
                trust_env=False,
                follow_redirects=False,
                timeout=self.settings["TIMEOUT"],
                headers={"User-Agent": f"Fieldkit/{__version__}"},
                limits=httpx.Limits(max_connections=self.settings["CONCURRENCY"]),
            )
            self.clients[profile] = client
            self.fetchers[profile] = Fetcher(
                client,
                self.settings["CONCURRENCY"],
                self.settings["MAX_BYTES"],
                self.settings["TIMEOUT"],
                controls=self.controls,
                retries=self.settings["RETRIES"],
            )
        return self.clients[profile]

    async def clone_profile(self, source: str, name: str) -> None:
        if source not in self.profiles or name in self.profiles:
            raise ValueError("Source profile must exist and clone name must be new")
        self.profiles[name] = copy.deepcopy(self.profiles[source])
        self.profiles[name].name = name
        source_client = self.session(source)
        clone = self.session(name)
        for cookie in source_client.cookies.jar:
            clone.cookies.jar.set_cookie(copy.copy(cookie))
        for profile, site in list(self.seeded_profiles):
            if profile == source:
                self.seeded_profiles.add((name, site))

    def add_endpoint(self, url: str, method: str = "GET", **metadata) -> dict | None:
        if not self.in_scope(url):
            return None
        url = normalize_url(url)
        method = method.upper()
        key = stable_id({"url": url, "method": method}, "endpoint")
        if key in self._endpoints:
            self._endpoints[key].update(metadata)
            return self._endpoints[key]
        record = {"id": key, "url": url, "method": method, **metadata}
        self._endpoints[key] = record
        self.report["endpoints"].append(record)
        return record

    def finding(
        self,
        kind: str,
        title: str,
        url: str,
        severity: str = "info",
        confidence: str = "review",
        evidence=None,
        **details,
    ) -> dict:
        record = {
            "kind": kind,
            "title": title,
            "url": url,
            "severity": severity,
            "confidence": confidence,
            "evidence": ([evidence] if isinstance(evidence, str) else evidence) or [],
            **details,
        }
        key = stable_id(record, "finding")
        record["id"] = key
        if key in self._findings:
            existing = self._findings[key]
            existing["evidence"] = list(dict.fromkeys([*existing["evidence"], *record["evidence"]]))
            return existing
        self._findings[key] = record
        self.report["findings"].append(record)
        return record

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        profile: str | None = None,
        data=None,
        follow_redirects: bool = True,
        record_errors: bool = True,
    ) -> FetchResult:
        profile = profile or self.settings["PROFILE"]
        if profile not in self.profiles:
            raise ValueError(f"Unknown profile: {profile}")
        if not self.in_scope(url):
            result = FetchResult(
                url, url, error="out_of_scope", detail="URL leaves supplied origins"
            )
        else:
            p = self.profiles[profile]
            if (p.headers or p.cookies or p.cookie_jar or p.origins) and origin(url) not in {
                origin(o) for o in p.origins
            }:
                result = FetchResult(
                    url, url, error="profile_scope", detail="Profile does not allow this origin"
                )
            else:
                client = self.session(profile)
                merged = httpx.Headers(p.headers)
                merged.update(headers or {})
                if "host" in merged:
                    raise ValueError("Host header overrides are unsupported")
                # Seed each named cookie only once per host; subsequent server updates win.
                seed_key = (profile, origin(url))
                if seed_key not in self.seeded_profiles:
                    for cookie in p.cookie_jar:
                        client.cookies.jar.set_cookie(jar_cookie(cookie))
                    for name, value in p.cookies.items():
                        host = urlsplit(url).hostname
                        if host and ":" in host:
                            host = f"[{host}]"
                        cookie_host = host + ".local" if host and "." not in host else host
                        client.cookies.set(name, value, domain=cookie_host, path="/")
                    self.seeded_profiles.add(seed_key)
                self.secrets.extend(header_secrets(headers or {}))
                if isinstance(data, dict):
                    from fieldkit.core.redaction import SENSITIVE

                    self.secrets.extend(str(v) for k, v in data.items() if SENSITIVE.search(k))
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Run time budget exhausted")
                async with asyncio.timeout(remaining):
                    result = await self.fetchers[profile].request(
                        url,
                        url,
                        method,
                        dict(merged),
                        data,
                        follow_redirects,
                    )
                for cookie in client.cookies.jar:
                    self.secrets.append(cookie.value)
                for raw in result.set_cookies:
                    self.secrets.extend(header_secrets({"set-cookie": raw}))
                for hop in result.history:
                    for raw in hop.get("set_cookies", []):
                        self.secrets.extend(header_secrets({"set-cookie": raw}))
        self._record_evidence(result, method, profile, data)
        if result.error and record_errors:
            self.report["errors"].append(
                {
                    "url": url,
                    "error": result.error,
                    "detail": result.detail,
                    "evidence": result.evidence_id,
                }
            )
        return result

    def _record_evidence(self, result, method, profile, data):
        self._evidence_count += 1
        result.evidence_id = f"evidence-{self._evidence_count:06d}"
        text = result.body[:32768].decode("utf-8", errors="replace")
        record = {
            "id": result.evidence_id,
            "captured_at": utc_now(),
            "profile": profile,
            "request": {
                "method": method.upper(),
                "url": result.requested_url,
                "headers": result.request_headers,
                "body": data
                if not isinstance(data, bytes)
                else {
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "binary_body_omitted": True,
                },
            },
            "response": {
                "url": result.url,
                "status": result.status,
                "headers": result.headers,
                "body_preview": text,
                "preview_truncated": len(result.body) > 32768,
                "bytes": len(result.body),
                "sha256": hashlib.sha256(result.body).hexdigest(),
                "redirects": result.history,
                "error": result.error,
                "detail": result.detail,
            },
        }
        path = Path("evidence") / f"{result.evidence_id}.json"
        write_private(
            self.store.root / path, json.dumps(redact(record, self.secrets), indent=2) + "\n"
        )
        self.report["evidence"].append(
            {"id": result.evidence_id, "file": str(path), "url": result.requested_url}
        )
        if self.settings.get("DATABASE"):
            import base64

            from fieldkit.core.ingest import body_request
            from fieldkit.core.vault import Vault

            headers = {
                k: v
                for k, v in result.request_headers.items()
                if k.lower() not in {"host", "connection", "content-length", "transfer-encoding"}
            }
            request = {"url": result.requested_url, "method": method.upper(), "headers": headers}
            if isinstance(data, dict):
                request["form"] = data
            elif data is not None:
                raw = data.encode() if isinstance(data, str) else bytes(data)
                media = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
                try:
                    body_request(request, raw, media)
                except (ValueError, UnicodeError):
                    request.pop("xml", None)
                    request.pop("json", None)
                    request["body_base64"] = base64.b64encode(raw).decode()
            with Vault(self.settings["DATABASE"]) as vault:
                identifier = vault.exchange(
                    request,
                    {
                        "status": result.status,
                        "headers": result.headers,
                        "timestamp": utc_now(),
                        "mime_type": result.content_type,
                        "body_base64": base64.b64encode(result.body).decode(),
                        "error": result.error,
                    },
                    source={
                        "run": str(self.store.root),
                        "evidence": result.evidence_id,
                        "module": self.report["module"],
                    },
                    context={"profile": profile},
                )
            self.report.setdefault("vault_requests", []).append(
                {"id": identifier, "evidence": result.evidence_id, "private_raw": True}
            )

    def finish(self):
        self.report["finished_at"] = utc_now()
        # Modules can identify credentials after their original response was captured.
        metadata_by_file = {
            entry.get("file"): entry
            for entry in self.report["evidence"]
            if "sha256" in entry or "bytes" in entry
        }
        for path in (self.store.root / "evidence").glob("*.json"):
            evidence = json.loads(path.read_text(encoding="utf-8"))
            content = (json.dumps(redact(evidence, self.secrets), indent=2) + "\n").encode()
            write_private(path, content)
            relative = str(path.relative_to(self.store.root))
            if entry := metadata_by_file.get(relative):
                entry.update(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        # Inventories intentionally preserve exact URLs locally for chaining; exports redact them.
        inventory = {"schema_version": 2, "endpoints": self.report["endpoints"]}
        write_private(self.store.root / "inventory.json", json.dumps(inventory, indent=2) + "\n")
        path = self.store.write_report(redact(self.report, self.secrets))
        self.console.print(f"Report: {path}", markup=False)
        return path


class NetworkModule(Module):
    accepts_targets = True
    requires_targets = True
    options = COMMON_OPTIONS

    def validate(self, settings: dict) -> None:
        """Override for module-specific validation, invoked before output or requests."""

    def run(self, settings: dict[str, Any], console: Console) -> int:
        for key in ("CONCURRENCY", "TIMEOUT", "MAX_BYTES", "BUDGET"):
            if not math.isfinite(settings[key]) or settings[key] <= 0:
                raise ValueError(f"{key} must be finite and positive")
        for key in ("RATE", "RETRIES"):
            if not math.isfinite(settings[key]) or settings[key] < 0:
                raise ValueError(f"{key} must be finite and nonnegative")
        if settings["RETRIES"] > 5:
            raise ValueError("RETRIES cannot exceed 5")
        if settings["SCHEME"] not in {"auto", "https", "http"}:
            raise ValueError("SCHEME must be auto, https, or http")
        if self.requires_targets and not (settings["TARGETS"] or settings["TARGETS_FILE"]):
            raise ValueError(
                "Supply at least one target origin; inventory files do not authorize scope"
            )
        self.validate(settings)
        ctx = AssessmentContext(self.name, settings, console)
        console.print(f"Run directory: {ctx.store.root}", markup=False)
        code = 0
        try:
            if settings.get("DRY_RUN"):
                ctx.report["plan"] = {
                    "target_candidates": ctx.candidates,
                    "inventory": ctx.imported_endpoints,
                    "network_requests": 0,
                    "module": self.name,
                    "validated_settings": redact(settings, ctx.secrets),
                }
            else:
                asyncio.run(self._execute(ctx))
            ctx.report["completed"] = not ctx.report.get("partial", False)
            code = 1 if ctx.report["errors"] else 0
        except KeyboardInterrupt:
            ctx.report["errors"].append({"error": "interrupted", "detail": "Interrupted by user"})
            code = 130
        except TimeoutError:
            ctx.report["errors"].append(
                {"error": "budget_exhausted", "detail": "Run time budget exhausted"}
            )
            code = 1
        finally:
            ctx.finish()
        console.print(
            f"{self.name}: {len(ctx.report['findings'])} findings, "
            f"{len(ctx.report['endpoints'])} endpoints, {len(ctx.report['errors'])} errors.",
            markup=False,
        )
        return code

    async def _execute(self, ctx):
        async with ctx:
            async with asyncio.timeout(ctx.settings["BUDGET"]):
                await ctx.prepare()
                await self.assess(ctx)

    async def assess(self, ctx: AssessmentContext) -> None:
        raise NotImplementedError
