"""Small non-destructive probe sets built on scoped request replay."""

import asyncio
import hashlib
import json
import re
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, write_private
from fieldkit.core.module import Option
from fieldkit.core.replay import bounded_json, edit_request, execute_request
from fieldkit.core.urls import normalize_url
from fieldkit.modules.assessment_helpers import looks_like_login, response_summary
from fieldkit.modules.request_replay import REPLAY_OPTIONS, RequestReplay

PROBE_OPTIONS = (
    Option(
        "LOCATIONS",
        list,
        [],
        "Selected query/form/header/cookie/JSON/XML field (repeat)",
        "--location",
    ),
)
CALLBACK_OPTIONS = (
    Option(
        "CALLBACK_URL", str, "", "Operator-controlled HTTP(S) callback base URL", "--callback-url"
    ),
    Option(
        "RECEIPTS_FILE",
        str,
        "",
        "Listener JSON receipts with IDs, URLs and timestamps",
        "--receipts-file",
    ),
    Option(
        "CALLBACK_WAIT",
        float,
        0.0,
        "Seconds to wait for listener receipts (max 30)",
        "--callback-wait",
    ),
)
SQL_ERRORS = re.compile(
    rb"(?i)(SQL syntax.*?MySQL|You have an error in your SQL syntax|"
    rb"unterminated quoted string|PG::SyntaxError|psycopg\w*\.errors|"
    rb"SQLite(?:3)?::SQLException|sqlite3\.OperationalError|"
    rb"ORA-009\d\d|Unclosed quotation mark after the character string|"
    rb"Microsoft.*?ODBC.*?SQL Server|SQLSTATE\[(?:42000|42601)\])"
)


class InjectionCheck(RequestReplay):
    options = COMMON_OPTIONS + REPLAY_OPTIONS + PROBE_OPTIONS
    probes_per_location = 3

    def validate(self, settings):
        super().validate(settings)
        if not settings["LOCATIONS"] or len(settings["LOCATIONS"]) > 10:
            raise ValueError("Select 1-10 explicit --location fields")
        needed = len(self._requests) * len(settings["LOCATIONS"]) * self.probes_per_location
        if needed > settings["MAX_REQUESTS"]:
            raise ValueError("Bounded probe set exceeds MAX_REQUESTS; reduce selections")
        if "CALLBACK_URL" in settings:
            if not settings["CALLBACK_URL"]:
                raise ValueError("Supply an operator-controlled --callback-url")
            settings["CALLBACK_URL"] = normalize_url(settings["CALLBACK_URL"])
            if urlsplit(settings["CALLBACK_URL"]).query:
                raise ValueError("Callback base must have no query string")
            if not 0 <= settings["CALLBACK_WAIT"] <= 30:
                raise ValueError("CALLBACK_WAIT must be 0-30 seconds")

    async def assess(self, ctx):
        prepared = self.prepared(ctx)
        # Unsupported locations produce explicit outcomes, with no partial state mutation.
        supported = []
        for baseline, edited, control in prepared:
            for location in ctx.settings["LOCATIONS"]:
                try:
                    edit_request(edited, location, "fieldkit-control")
                    if self.name == "web/xxe-check" and not location.startswith("xml:"):
                        raise ValueError("XXE requires a selected XML element")
                except ValueError as exc:
                    ctx.report["results"].append(
                        {
                            "kind": self.name,
                            "request_id": baseline["id"],
                            "url": baseline["url"],
                            "probe_location": location,
                            "outcome": "unsupported",
                            "detail": str(exc),
                        }
                    )
                else:
                    supported.append((baseline, edited, control, location))
        for baseline, edited, control, location in supported:
            base_response, _ = await execute_request(ctx, baseline, label="baseline")
            control_request = control or edit_request(edited, location, "fieldkit-control")
            control_response, _ = await execute_request(ctx, control_request, label="control")
            result = {
                "kind": self.name,
                "url": baseline["url"],
                "method": baseline["method"],
                "request_id": baseline["id"],
                "probe_location": location,
                "baseline": response_summary(base_response),
                "control": response_summary(control_response),
                "outcome": "inconclusive",
                "probes": [],
            }
            ctx.report["results"].append(result)
            if base_response.error or control_response.error:
                result["detail"] = "Baseline/control transport or coverage failure"
                continue
            await self.probe(ctx, edited, location, base_response, control_response, result)
            if result["outcome"] in {"observed", "confirmed"}:
                ctx.finding(
                    self.name.split("/")[1],
                    result.get("title", "Injection behavior"),
                    baseline["url"],
                    severity="medium" if result["outcome"] == "confirmed" else "info",
                    confidence=result["outcome"],
                    evidence=[
                        base_response.evidence_id,
                        control_response.evidence_id,
                        *[p["evidence"] for p in result["probes"]],
                    ],
                    method=baseline["method"],
                    request_id=baseline["id"],
                    probe_location=location,
                    outcome=result["outcome"],
                    detail=result.get("detail"),
                )


async def correlate_callback(ctx, callback_id, url, sent_at):
    finish = min(ctx.deadline, time.monotonic() + ctx.settings["CALLBACK_WAIT"])
    while True:
        filename = ctx.settings["RECEIPTS_FILE"]
        if filename and Path(filename).expanduser().is_file():
            document = bounded_json(filename)
            receipts = document.get("receipts", []) if isinstance(document, dict) else document
            if not isinstance(receipts, list) or len(receipts) > 10000:
                raise ValueError("Listener receipts must be a bounded array")
            for receipt in receipts:
                if (
                    not isinstance(receipt, dict)
                    or receipt.get("callback_id") != callback_id
                    or receipt.get("url") != url
                ):
                    continue
                try:
                    received = datetime.fromisoformat(receipt["received_at"].replace("Z", "+00:00"))
                    if received.tzinfo is None:
                        continue
                    received = received.timestamp()
                except (KeyError, TypeError, ValueError):
                    continue
                if (
                    not (sent_at <= received <= time.time())
                    or not receipt.get("source")
                    or receipt.get("method") not in {"GET", "POST", "HEAD"}
                ):
                    continue
                identifier = f"callback-evidence-{len(ctx.report['evidence']) + 1:06d}"
                relative = f"evidence/{identifier}.json"
                from fieldkit.core.redaction import redact

                write_private(
                    ctx.store.root / relative,
                    json.dumps(
                        redact(
                            {
                                "receipt": receipt,
                                "source_file": filename,
                                "source_sha256": hashlib.sha256(
                                    Path(filename).expanduser().read_bytes()
                                ).hexdigest(),
                            },
                            ctx.secrets,
                        ),
                        indent=2,
                    ),
                )
                ctx.report["evidence"].append(
                    {"id": identifier, "file": relative, "source": filename}
                )
                return identifier
        if time.monotonic() >= finish:
            return None
        await asyncio.sleep(min(0.2, max(0.001, finish - time.monotonic())))


def callback_plan(ctx, request, location):
    callback_id = uuid.uuid4().hex
    url = ctx.settings["CALLBACK_URL"].rstrip("/") + "/" + callback_id
    plan = {
        "request_id": request["id"],
        "probe_location": location,
        "callback_id": callback_id,
        "url": url,
        "created_at": datetime.now(UTC).isoformat(),
    }
    ctx.report.setdefault("callbacks", []).append(plan)
    write_private(ctx.store.root / "callbacks.json", json.dumps(ctx.report["callbacks"], indent=2))
    return callback_id, url


class SSRFCheck(InjectionCheck):
    name = "web/ssrf-check"
    description = "Probe selected fields with operator callback URLs; require correlated receipts."
    options = InjectionCheck.options + CALLBACK_OPTIONS

    async def probe(self, ctx, request, location, baseline, control, result):
        callback_id, url = callback_plan(ctx, request, location)
        sent = time.time()
        response, _ = await execute_request(
            ctx, edit_request(request, location, url), label="ssrf-callback"
        )
        result["probes"].append(response_summary(response))
        receipt = await correlate_callback(ctx, callback_id, url, sent)
        result.update(
            callback_id=callback_id,
            receipt_evidence=receipt,
            outcome="confirmed" if receipt else "inconclusive",
            title="Server-side callback observed" if receipt else "SSRF callback unconfirmed",
            detail="Correlated listener receipt; listener attribution is operator supplied"
            if receipt
            else "Sending a callback URL or reflecting it is insufficient to confirm SSRF",
        )
        if receipt:
            result["probes"].append({"evidence": receipt, "kind": "callback_receipt"})


class XXECheck(InjectionCheck):
    name = "web/xxe-check"
    description = "Compare internal entity control with an external operator callback entity."
    options = (
        InjectionCheck.options
        + CALLBACK_OPTIONS
        + (
            Option(
                "ENTITY_MARKER",
                str,
                "",
                "Unique content served only by callback endpoint",
                "--entity-marker",
            ),
        )
    )
    probes_per_location = 4

    @staticmethod
    def payload(request, location, declaration):
        token = "FIELDKIT_ENTITY_" + uuid.uuid4().hex
        edited = edit_request(request, location, token)
        xml = edited.pop("xml")
        root_name = re.search(r"<([\w:.-]+)(?:\s|>)", xml)[1]
        xml = xml.replace(token, "&fieldkit;")
        edited["body"] = f"<!DOCTYPE {root_name} [<!ENTITY fieldkit {declaration}>]>" + xml
        return edited

    async def probe(self, ctx, request, location, baseline, control, result):
        marker = "fieldkit-internal-" + uuid.uuid4().hex
        internal, _ = await execute_request(
            ctx,
            self.payload(request, location, json.dumps(marker)),
            label="internal-entity-control",
        )
        result["internal_entity_reflection"] = marker.encode() in internal.body
        result["probes"].append(response_summary(internal))
        callback_id, url = callback_plan(ctx, request, location)
        sent = time.time()
        external_request = self.payload(request, location, "SYSTEM " + json.dumps(url))
        external, _ = await execute_request(
            ctx,
            external_request,
            label="external-entity",
        )
        result["probes"].append(response_summary(external))
        receipt = await correlate_callback(ctx, callback_id, url, sent)
        content = ctx.settings["ENTITY_MARKER"]
        expanded = bool(
            content
            and not external.error
            and content.encode() in external.body
            and all(content.encode() not in r.body for r in (baseline, control, internal))
            and content not in request["xml"]
            and content not in external_request["body"]
        )
        result.update(
            callback_id=callback_id,
            receipt_evidence=receipt,
            external_content_observed=expanded,
            outcome="confirmed"
            if receipt or expanded
            else "observed"
            if result["internal_entity_reflection"]
            else "inconclusive",
            title="External XML entity resolution"
            if receipt or expanded
            else "Internal XML entity reflection",
            detail="External entity verification observed"
            if receipt or expanded
            else "Internal string reflection does not establish external-entity processing",
        )
        if receipt:
            result["probes"].append({"evidence": receipt, "kind": "external_entity_receipt"})


class SQLiCheck(InjectionCheck):
    name = "web/sqli-check"
    description = "Bounded error/boolean SQL comparisons and optional paired timing checks."
    options = InjectionCheck.options + (
        Option(
            "TRUE_MARKER",
            str,
            "",
            "Resource-specific marker expected on true/baseline responses",
            "--true-marker",
        ),
        Option("TIMING_DB", str, "", "Explicit mysql or postgres timing syntax", "--timing-db"),
        Option(
            "TIMING_DELAY", float, 1.0, "Controlled timing delay, 0.5-2 seconds", "--timing-delay"
        ),
    )
    probes_per_location = 7

    def validate(self, settings):
        self.probes_per_location = 11 if settings["TIMING_DB"] else 7
        super().validate(settings)
        if settings["TIMING_DB"] not in {"", "mysql", "postgres"}:
            raise ValueError("TIMING_DB must be mysql or postgres")
        if settings["TIMING_DB"] and (
            not 0.5 <= settings["TIMING_DELAY"] <= 2
            or settings["RETRIES"] != 0
            or settings["RATE"] != 0
        ):
            raise ValueError("Timing checks require delay 0.5-2, --retries 0 and --rate 0")

    async def probe(self, ctx, request, location, baseline, control, result):
        error_response, _ = await execute_request(
            ctx, edit_request(request, location, "'"), label="sql-error"
        )
        result["probes"].append(response_summary(error_response))
        error_lead = bool(
            not error_response.error
            and SQL_ERRORS.search(error_response.body)
            and not SQL_ERRORS.search(baseline.body)
            and not SQL_ERRORS.search(control.body)
        )
        result["sql_error_observed"] = error_lead
        pairs = []
        for _ in range(2):
            true, _ = await execute_request(
                ctx, edit_request(request, location, "1' OR '1'='1"), label="sql-boolean-true"
            )
            false, _ = await execute_request(
                ctx, edit_request(request, location, "1' AND '1'='2"), label="sql-boolean-false"
            )
            pairs.append((true, false))
            result["probes"].extend([response_summary(true), response_summary(false)])
        marker = ctx.settings["TRUE_MARKER"].encode()
        stable = bool(
            marker
            and marker in baseline.body
            and not looks_like_login(baseline)
            and all(
                not t.error
                and not f.error
                and t.status == f.status == baseline.status
                and 200 <= t.status < 300
                and not looks_like_login(t)
                and not looks_like_login(f)
                and marker in t.body
                and marker not in f.body
                for t, f in pairs
            )
            and pairs[0][0].body == pairs[1][0].body
            and pairs[0][1].body == pairs[1][1].body
        )
        result["repeatable_boolean_marker_difference"] = stable
        timing = False
        if ctx.settings["TIMING_DB"]:
            delay = ctx.settings["TIMING_DELAY"]
            deltas = []
            for _ in range(2):

                def timing_payload(seconds):
                    if ctx.settings["TIMING_DB"] == "mysql":
                        return f"1' AND SLEEP({seconds})=0-- "
                    return f"1' AND (SELECT 1 FROM pg_sleep({seconds}))=1-- "

                neutral = timing_payload(0)
                delayed = timing_payload(delay)
                c, ct = await execute_request(
                    ctx, edit_request(request, location, neutral), label="sql-timing-control"
                )
                p, pt = await execute_request(
                    ctx, edit_request(request, location, delayed), label="sql-timing-probe"
                )
                result["probes"].extend([response_summary(c), response_summary(p)])
                if (
                    not c.error
                    and not p.error
                    and c.status == p.status
                    and c.body == p.body
                    and ct < delay / 2
                ):
                    deltas.append(pt - ct)
            timing = len(deltas) == 2 and all(delay * 0.8 <= d <= delay * 2 for d in deltas)
            result["timing_deltas"] = deltas
        result.update(
            outcome="observed" if error_lead or stable or timing else "inconclusive",
            title="SQL injection comparison lead",
            detail="Repeatable SQL error/boolean/timing behavior requires impact validation"
            if error_lead or stable or timing
            else "No distinguishing evidence in bounded probes; absence does not establish safety",
        )
