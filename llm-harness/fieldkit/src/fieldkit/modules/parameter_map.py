"""Map input names and optionally locate harmless GET marker reflections."""

import re
import uuid
from collections import defaultdict
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.modules.discovery_helpers import (
    is_html,
    is_javascript,
    page_base,
    parse_page,
    positive_limits,
)

JS_URL = re.compile(r"""["'`]((?:https?://|/)[^\s"'`<>]{1,2048})["'`]""")
JS_PARAMETER = re.compile(r"""\.(?:get|set|append|has|delete)\(\s*["']([\w.-]{1,128})["']""")
SENSITIVE_NAME = re.compile(r"password|passwd|secret|token|csrf|authorization", re.I)


def query_names(url):
    return list(
        dict.fromkeys(name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True))
    )


class ParameterMap(NetworkModule):
    name = "web/parameter-map"
    description = (
        "Extract query/form/API/JavaScript input names and optionally test GET reflections."
    )
    options = COMMON_OPTIONS + (
        Option("MAX_URLS", int, 100, "Maximum pages/scripts to inspect", "--max-urls"),
        Option(
            "MAX_PARAMETERS",
            int,
            100,
            "Maximum marker requests across all URLs",
            "--max-parameters",
        ),
        Option("REFLECT", bool, False, "Send harmless markers using GET only", "--reflect"),
        Option("MARKER", str, "", "Optional alphanumeric marker (otherwise random)", "--marker"),
    )

    def validate(self, settings):
        positive_limits(settings, "MAX_URLS", "MAX_PARAMETERS")
        if settings["MARKER"] and not re.fullmatch(r"[a-zA-Z0-9_-]{8,64}", settings["MARKER"]):
            raise ValueError("MARKER must be 8..64 alphanumeric, underscore, or hyphen characters")

    async def assess(self, ctx):
        parameters = {}
        imported = list(getattr(ctx, "imported_endpoints", []))
        imported.extend(list(ctx.report.get("endpoints", [])))
        methods = defaultdict(set)
        cap = ctx.settings["MAX_PARAMETERS"] * 50

        def add(url, name, location="query", method="GET", source="url", **details):
            if not isinstance(name, str) or not name or len(name) > 256 or not ctx.in_scope(url):
                return
            key = url, method, location, name
            if key not in parameters and len(parameters) < cap:
                parameters[key] = {
                    "kind": "parameter",
                    "url": url,
                    "method": method,
                    "name": name,
                    "in": location,
                    "source": source,
                    **details,
                }

        for endpoint in imported:
            url = endpoint.get("url")
            if not isinstance(url, str):
                continue
            method = endpoint.get("method", "GET").upper()
            methods[url].add(method)
            for parameter in endpoint.get("parameters", []):
                if isinstance(parameter, dict):
                    location = parameter.get("in", "query")
                    add(
                        url,
                        parameter.get("name"),
                        location,
                        method,
                        "inventory",
                        field_type=parameter.get("type"),
                    )
            for name in query_names(url):
                add(url, name, method=method, source="inventory-url")
        urls = list(dict.fromkeys([*ctx.targets, *ctx.seed_urls()]))
        # Inventory entries known exclusively as mutating operations are not probed.
        urls = [url for url in urls if not methods[url] or "GET" in methods[url]]
        inspected = 0
        for url in urls[: ctx.settings["MAX_URLS"]]:
            for name in query_names(url):
                add(url, name)
            response = await ctx.fetch(url)
            inspected += 1
            if response.error or response.status is None or not 200 <= response.status < 300:
                continue
            if is_html(response.content_type, response.body):
                page = parse_page(response.body)
                base = page_base(page, response.url)
                for reference, _ in page.links:
                    linked = ctx.resolve(reference, base)
                    if linked:
                        names = query_names(linked)
                        if names:
                            ctx.add_endpoint(
                                linked,
                                source=response.url,
                                parameters=[{"name": name, "in": "query"} for name in names],
                            )
                        for name in names:
                            add(linked, name, source="link", evidence=response.evidence_id)
                for form in page.forms:
                    action = ctx.resolve(form["action"] or response.url, base)
                    if not action:
                        continue
                    method = form["method"]
                    ctx.add_endpoint(
                        action, method=method, source=response.url, parameters=form["parameters"]
                    )
                    for parameter in form["parameters"]:
                        add(
                            action,
                            parameter["name"],
                            "query" if method == "GET" else "form",
                            method,
                            "form",
                            field_type=parameter["type"],
                            evidence=response.evidence_id,
                        )
            if is_javascript(response.url, response.content_type):
                text = response.body.decode("utf-8", errors="replace")
                for reference in JS_URL.findall(text)[:1000]:
                    linked = ctx.resolve(reference, response.url)
                    if linked:
                        names = query_names(linked)
                        if names:
                            ctx.add_endpoint(
                                linked,
                                source=response.url,
                                parameters=[{"name": name, "in": "query"} for name in names],
                            )
                        for name in names:
                            add(
                                linked, name, source="javascript-url", evidence=response.evidence_id
                            )
                # These syntactic hints have no known receiving endpoint; do not probe.
                for name in JS_PARAMETER.findall(text)[:1000]:
                    add(
                        response.url,
                        name,
                        "unknown",
                        source="javascript-hint",
                        evidence=response.evidence_id,
                    )
        ctx.report["results"].extend(parameters.values())
        probes = 0
        if ctx.settings["REFLECT"]:
            for record in list(parameters.values()):
                if probes >= ctx.settings["MAX_PARAMETERS"]:
                    break
                if record["method"] != "GET" or record["in"] not in {"query", "form"}:
                    continue
                if SENSITIVE_NAME.search(record["name"]) or record.get("field_type") in {
                    "password",
                    "file",
                }:
                    continue
                url = record["url"]
                if any(
                    term in urlsplit(url).path.lower()
                    for term in ["logout", "signout", "delete", "remove"]
                ):
                    continue
                if re.search(r"\{[^}]+\}", url):
                    continue  # API templates need a concrete path before probing.
                marker = ctx.settings["MARKER"] or "fieldkit_" + uuid.uuid4().hex
                parsed = urlsplit(url)
                pairs = [
                    (name, value)
                    for name, value in parse_qsl(parsed.query, keep_blank_values=True)
                    if name != record["name"]
                ]
                pairs.append((record["name"], marker))
                probe_url = urlunsplit(parsed._replace(query=urlencode(pairs), fragment=""))
                baseline = await ctx.fetch(url)
                response = await ctx.fetch(probe_url)
                probes += 1
                body = response.body.decode("utf-8", errors="replace")
                offsets = [match.start() for match in re.finditer(re.escape(marker), body)][:20]
                headers = [key for key, value in response.headers.items() if marker in value]
                preexisting = marker.encode() in baseline.body or any(
                    marker in value for value in baseline.headers.values()
                )
                result = {
                    "kind": "reflection",
                    "url": url,
                    "parameter": record["name"],
                    "status": response.status,
                    "body_offsets": offsets,
                    "header_names": headers,
                    "evidence": response.evidence_id,
                    "baseline_evidence": baseline.evidence_id,
                    "preexisting_marker": preexisting,
                    "baseline_error": baseline.error,
                    "probe_error": response.error,
                }
                ctx.report["results"].append(result)
                if (
                    (offsets or headers)
                    and not preexisting
                    and not response.error
                    and not baseline.error
                ):
                    ctx.finding(
                        "input-reflection",
                        f"GET marker for {record['name']} appears in the response",
                        url,
                        evidence=response.evidence_id,
                        parameter=record["name"],
                        body_offsets=offsets,
                        header_names=headers,
                        note="Reflection alone does not establish a vulnerability.",
                    )
        ctx.report["results"].append(
            {
                "kind": "parameter-summary",
                "parameters": len(parameters),
                "inspected": inspected,
                "marker_requests": probes,
                "limited": len(urls) > ctx.settings["MAX_URLS"] or len(parameters) >= cap,
            }
        )
