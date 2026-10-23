"""Explicit Nuclei result import and restricted HTTP template execution."""

import hashlib
import json
import math
import os
import re
import tempfile
import time
from pathlib import Path

import yaml

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule, write_private
from fieldkit.core.http import origin
from fieldkit.core.module import Option
from fieldkit.core.process import ProcessResult, run_process
from fieldkit.core.redaction import redact
from fieldkit.core.replay import string_map
from fieldkit.modules.nmap_import import read_bounded


def review_template(path, execute=False):
    body = read_bounded(path, 1048576)
    if any(
        isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for t in yaml.scan(body)
    ):
        raise ValueError("Template YAML aliases/anchors are unsupported")
    try:
        document = yaml.safe_load(body)
    except RecursionError as exc:
        raise ValueError("Template YAML nesting limit exceeded") from exc
    if not isinstance(document, dict) or not isinstance(document.get("id"), str):
        raise ValueError("Nuclei template requires an id")
    if not isinstance(document.get("info", {}), dict):
        raise ValueError("Nuclei info must be an object")
    requests = document.get("http", [])
    if not isinstance(requests, list) or any(not isinstance(r, dict) for r in requests):
        raise ValueError("Template HTTP requests must be a list of objects")
    if len(requests) > 100:
        raise ValueError("Template HTTP request list must be bounded")
    for request in requests:
        if not isinstance(request.get("method", "GET"), str):
            raise ValueError("Template HTTP methods must be strings")
        paths = request.get("path", [])
        if (
            not isinstance(paths, list)
            or len(paths) > 100
            or any(not isinstance(value, str) for value in paths)
        ):
            raise ValueError("Template HTTP paths must be a bounded list of strings")
    if execute:
        if set(document) - {"id", "info", "http"} or not isinstance(requests, list) or not requests:
            raise ValueError("Execution supports only standalone static HTTP templates")
        for request in requests:
            if not isinstance(request, dict) or set(request) - {
                "method",
                "path",
                "headers",
                "body",
                "matchers",
                "matchers-condition",
                "extractors",
                "redirects",
                "max-redirects",
                "host-redirects",
                "stop-at-first-match",
            }:
                raise ValueError(
                    "Raw, fuzz, code, headless, flow and dynamic templates are unsupported"
                )
            if request.get("redirects") or request.get("host-redirects"):
                raise ValueError("Template redirects must be disabled for bounded origin scope")
            if request.get("method", "GET").upper() not in {"GET", "HEAD", "OPTIONS", "POST"}:
                raise ValueError("Unsupported template method")
            paths = request.get("path", [])
            if not isinstance(paths, list) or not paths:
                raise ValueError("Explicit static template paths required")
            for path_value in paths:
                if not isinstance(path_value, str) or not re.fullmatch(
                    r"\{\{(?:BaseURL|RootURL)\}\}(?:/[^{}\r\n\\]*)?", path_value
                ):
                    raise ValueError("Template paths must stay under BaseURL/RootURL")
            headers = string_map(request.get("headers", {}), "template headers")
            if not isinstance(headers, dict) or any(
                str(k).lower()
                in {
                    "host",
                    "authorization",
                    "cookie",
                    "proxy-authorization",
                    "content-length",
                    "transfer-encoding",
                }
                for k in headers
            ):
                raise ValueError("Template credential/Host/framing headers are unsupported")
            if "{{" in json.dumps({"headers": headers, "body": request.get("body")}):
                raise ValueError("Dynamic template bodies/headers are unsupported")
            for group in ("matchers", "extractors"):
                items = request.get(group, [])
                if not isinstance(items, list) or len(items) > 100:
                    raise ValueError("Template matcher/extractor lists must be bounded")
                for item in items:
                    if not isinstance(item, dict) or item.get("type") not in {
                        "word",
                        "status",
                        "regex",
                        "dsl",
                        "binary",
                        "kval",
                        "json",
                        "xpath",
                    }:
                        raise ValueError("Unsupported matcher/extractor type")
                    expressions = item.get("dsl", [])
                    if (
                        not isinstance(expressions, list)
                        or len(expressions) > 100
                        or any(not isinstance(expression, str) for expression in expressions)
                    ):
                        raise ValueError("Template DSL must be a bounded list of strings")
                    for expression in expressions:
                        functions = re.findall(r"([A-Za-z_]\w*)\s*\(", expression)
                        if set(functions) - {
                            "contains",
                            "contains_any",
                            "contains_all",
                            "to_lower",
                            "to_upper",
                            "len",
                            "regex",
                            "starts_with",
                            "ends_with",
                        }:
                            raise ValueError("Unsupported DSL helper; use result import instead")
        if "interactsh" in body.decode(errors="replace").lower():
            raise ValueError("OAST templates require a separate callback workflow")
    # Names/severities do not establish vulnerability proof; classify actual traffic.
    methods = [r.get("method", "GET").upper() for r in requests if isinstance(r, dict)]
    payload = " ".join(
        str(r.get("body", "")) + " ".join(r.get("path", []))
        for r in requests
        if isinstance(r, dict)
    )
    probe = bool(
        re.search(r"(?i)(union\s+select|or\s+1\s*=|<!entity|sleep\(|waitfor|%27)", payload)
    )
    behavior = (
        "probe_match"
        if probe or any(m not in {"GET", "HEAD", "OPTIONS"} for m in methods)
        else "surface_match"
    )
    return {
        "template_id": document["id"],
        "path": str(Path(path).resolve()),
        "sha256": hashlib.sha256(body).hexdigest(),
        "behavior": behavior,
        "reported_severity": (document.get("info") or {}).get("severity", "unknown"),
        "methods": methods,
    }


class Nuclei(NetworkModule):
    name = "web/nuclei"
    description = "Import Nuclei JSONL or execute explicitly selected static HTTP templates."
    requires_targets = False
    options = COMMON_OPTIONS + (
        Option("INPUT", str, "", "Existing JSONL; import performs no requests", "--input"),
        Option(
            "IMPORT_COMPLETE",
            bool,
            False,
            "Operator attests imported run completed",
            "--import-complete",
        ),
        Option("EXECUTE", bool, False, "Explicitly execute selected templates", "--execute"),
        Option("BINARY", str, "nuclei", "Operator-installed Nuclei binary", "--binary"),
        Option("TEMPLATE_DIRS", list, [], "External template directory (repeat)", "--template-dir"),
        Option("TEMPLATES", list, [], "Explicit YAML filename/path (repeat)", "--template"),
        Option("MAX_OUTPUT", int, 16777216, "Combined tool/input output ceiling", "--max-output"),
        Option("MAX_RESULTS", int, 10000, "Maximum JSONL observations", "--max-results"),
    )

    def validate(self, settings):
        if bool(settings["INPUT"]) == bool(settings["EXECUTE"]):
            raise ValueError("Choose --input import or explicit --execute")
        if min(settings["MAX_OUTPUT"], settings["MAX_RESULTS"]) <= 0:
            raise ValueError("Output/result limits must be positive")
        if settings["EXECUTE"]:
            if not settings["TEMPLATES"] or not (settings["TARGETS"] or settings["TARGETS_FILE"]):
                raise ValueError("Execution requires explicit templates and target origins")
            if settings["RATE"] < 1 or settings["INSECURE"]:
                raise ValueError("Nuclei execution requires RATE >= 1; INSECURE is unsupported")
        if len(settings["TEMPLATES"]) > 100:
            raise ValueError("Select at most 100 explicit templates per run")
        self._templates = {}
        for value in settings["TEMPLATES"]:
            candidates = [
                Path(value).expanduser(),
                *(Path(d).expanduser() / value for d in settings["TEMPLATE_DIRS"]),
            ]
            path = next((p for p in candidates if p.is_file()), None)
            if path is None:
                raise ValueError(f"Template not found: {value}; set --template-dir")
            try:
                reviewed = review_template(path, settings["EXECUTE"])
            except yaml.YAMLError as exc:
                raise ValueError("Malformed Nuclei YAML template") from exc
            if reviewed["template_id"] in self._templates:
                raise ValueError("Template IDs must be unique")
            self._templates[reviewed["template_id"]] = reviewed

    async def _execute(self, ctx):
        async with ctx:
            if ctx.settings["INPUT"]:
                await self.assess(ctx)
            else:
                # Explicit URL targets avoid Nuclei/httpx scheme probing.
                if any(len(group) != 1 for group in ctx.candidates):
                    raise ValueError("Nuclei requires explicit http(s) targets or --scheme")
                await ctx.prepare()
                await self.assess(ctx)
            ctx.report["partial"] = bool(ctx.report["errors"])

    def accept(self, ctx, line, source, version, number):
        if not line.strip():
            return
        try:
            value = json.loads(line)
            if not isinstance(value, dict) or not isinstance(value.get("template-id"), str):
                raise ValueError("Missing template-id")
            if not isinstance(value.get("info", {}), dict):
                raise ValueError("Invalid result info")
            url = value.get("matched-at") or value.get("host")
            from fieldkit.core.urls import normalize_url

            url = normalize_url(url)
        except (ValueError, TypeError, AttributeError, RecursionError):
            ctx.report["errors"].append(
                {"error": "malformed_jsonl", "source": source, "line": number}
            )
            return
        if ctx.settings["EXECUTE"] and not ctx.in_scope(url):
            ctx.report["errors"].append(
                {"error": "out_of_scope_tool_result", "source": source, "line": number}
            )
            return
        identity = self._templates.get(value["template-id"])
        if ctx.settings["EXECUTE"] and identity is None:
            ctx.report["errors"].append({"error": "unexpected_tool_template", "line": number})
            return
        # Encoded templates can conceal credentials from text redaction. They are never retained.
        value.pop("template-encoded", None)
        record = {
            "kind": "nuclei_observation",
            "url": url,
            "template_id": value["template-id"],
            "matcher": value.get("matcher-name", ""),
            "tool_version": version or value.get("nuclei-version", "unknown"),
            "template": identity or {"behavior": "unreviewed", "sha256": None},
            "reported_severity": (value.get("info") or {}).get("severity", "unknown"),
            "outcome": "observed",
            "source": source,
            "line": number,
            "note": "A matcher observation does not prove the vulnerability in the template title.",
        }
        evidence_id = f"tool-evidence-{len(ctx.report['evidence']) + 1:06d}"
        file = f"evidence/{evidence_id}.json"
        write_private(
            ctx.store.root / file,
            json.dumps(redact({"provenance": record, "result": value}, ctx.secrets), indent=2),
        )
        ctx.report["evidence"].append(
            {"id": evidence_id, "file": file, "url": url, "source": source}
        )
        record["evidence"] = [evidence_id]
        ctx.report["results"].append(record)
        behavior = (identity or {}).get("behavior", "unreviewed")
        ctx.finding(
            "nuclei_" + behavior,
            "Nuclei " + behavior.replace("_", " "),
            url,
            evidence=[evidence_id],
            template_id=value["template-id"],
            matcher=record["matcher"],
            outcome="observed",
            template=record["template"],
            reported_severity=record["reported_severity"],
            note=record["note"],
        )
        endpoint = {"url": url, "method": "GET", "source": source, "authorized": False}
        if ctx.settings["EXECUTE"]:
            ctx.add_endpoint(url, source=source)
        elif not any(e["url"] == url for e in ctx.report["endpoints"]):
            ctx.report["endpoints"].append(endpoint)

    async def assess(self, ctx):
        ctx.report["templates"] = list(self._templates.values())
        if ctx.settings["INPUT"]:
            data = read_bounded(ctx.settings["INPUT"], ctx.settings["MAX_OUTPUT"])
            ctx.report["tool_input"] = {
                "source": ctx.settings["INPUT"],
                "sha256": hashlib.sha256(data).hexdigest(),
                "complete": ctx.settings["IMPORT_COMPLETE"],
            }
            lines = data.splitlines()
            for number, line in enumerate(lines[: ctx.settings["MAX_RESULTS"]], 1):
                self.accept(ctx, line, ctx.settings["INPUT"], "", number)
            if len(lines) > ctx.settings["MAX_RESULTS"] or not ctx.settings["IMPORT_COMPLETE"]:
                ctx.report["errors"].append(
                    {
                        "error": "partial_import",
                        "detail": "Coverage limited or completion not attested",
                    }
                )
            return
        profile = ctx.profiles[ctx.settings["PROFILE"]]
        urls = ctx.seed_urls()
        if profile.cookie_jar:
            raise ValueError(
                "Nuclei cookie_jar profiles are unsupported; use scoped header/cookies profiles"
            )
        if profile.origins and any(
            origin(u) not in {origin(o) for o in profile.origins} for u in urls
        ):
            raise ValueError(
                "Nuclei profile credentials require every target within profile origins"
            )
        if any("?" in u for u in urls):
            raise ValueError(
                "Nuclei targets containing queries are unsupported; keep credentials in profiles"
            )
        version_result = await run_process(
            [ctx.settings["BINARY"], "-version"],
            timeout=max(0.001, min(ctx.settings["TIMEOUT"], ctx.deadline - time.monotonic())),
            max_output=4096,
        )
        version = (
            (version_result.stdout + version_result.stderr).decode(errors="replace").strip()[:500]
        )
        if version_result.reason != "finished":
            ctx.report["errors"].append(
                {"error": "missing_dependency", "detail": "Install Nuclei v3 and supply --binary"}
            )
            return
        # A clean config isolates operator global config; secrets never appear in argv.
        with tempfile.TemporaryDirectory(prefix="fieldkit-nuclei-") as directory:
            os.chmod(directory, 0o700)
            config = Path(directory) / "config.yaml"
            targets = Path(directory) / "targets.txt"
            headers = dict(profile.headers)
            if profile.cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in profile.cookies.items())
            write_private(
                config, yaml.safe_dump({"header": [f"{k}: {v}" for k, v in headers.items()]})
            )
            write_private(targets, "\n".join(urls) + "\n")
            argv = [
                ctx.settings["BINARY"],
                "-config",
                str(config),
                "-l",
                str(targets),
                "-jsonl",
                "-silent",
                "-nc",
                "-duc",
                "-ni",
                "-dr",
                "-nh",
                "-rl",
                str(math.floor(ctx.settings["RATE"])),
                "-c",
                str(ctx.settings["CONCURRENCY"]),
                "-bs",
                str(ctx.settings["CONCURRENCY"]),
                "-timeout",
                str(math.ceil(ctx.settings["TIMEOUT"])),
                "-retries",
                str(ctx.settings["RETRIES"]),
                "-rsr",
                str(ctx.settings["MAX_BYTES"]),
            ]
            for template in self._templates.values():
                data = read_bounded(template["path"], 1048576)
                if hashlib.sha256(data).hexdigest() != template["sha256"]:
                    raise ValueError(
                        "Template changed after review; restart with the updated template"
                    )
                snapshot = Path(directory) / (template["sha256"] + ".yaml")
                write_private(snapshot, data)
                argv.extend(["-t", str(snapshot)])
            pending, number = bytearray(), 0
            import asyncio

            stop = asyncio.Event()

            def accept(chunk):
                nonlocal number
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending[:] = rest
                    number += 1
                    if number <= ctx.settings["MAX_RESULTS"]:
                        self.accept(ctx, line, "nuclei stdout", version, number)
                    else:
                        stop.set()

            result = ProcessResult()
            try:
                await run_process(
                    argv,
                    timeout=max(0.001, ctx.deadline - time.monotonic()),
                    max_output=ctx.settings["MAX_OUTPUT"],
                    on_stdout=accept,
                    result=result,
                    cancel=stop,
                    env={**os.environ, "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true"},
                )
                if pending:
                    number += 1
                    if number <= ctx.settings["MAX_RESULTS"]:
                        self.accept(ctx, pending, "nuclei stdout", version, number)
            finally:
                ctx.report["tool_run"] = {
                    **result.metadata(),
                    "version": version,
                    "traffic_controls": "Nuclei's own rate/concurrency/timeout; "
                    "HTTP runtime does not govern subprocess traffic",
                    "stderr": result.stderr.decode(errors="replace"),
                }
                if result.reason != "finished" or number > ctx.settings["MAX_RESULTS"]:
                    ctx.report["errors"].append(
                        {"error": "partial_tool_run", "reason": result.reason}
                    )
