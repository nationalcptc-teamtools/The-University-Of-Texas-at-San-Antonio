"""Passive callback collection and offline receipt correlation."""

import math
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from fieldkit.core.callbacks import (
    CallbackCollector,
    callback_url,
    correlate_receipts,
    read_receipts,
    write_callback_evidence,
)
from fieldkit.core.local import LOCAL_OPTIONS, LocalModule
from fieldkit.core.module import Option


class CallbackCollectorModule(LocalModule):
    name = "integrations/callback-collector"
    description = "Collect bounded passive HTTP callbacks or correlate private imported receipts."
    options = tuple(
        Option(
            "MAX_BYTES", int, 16384, "Maximum header plus body bytes per callback", "--max-bytes"
        )
        if option.name == "MAX_BYTES"
        else option
        for option in LOCAL_OPTIONS
    ) + (
        Option(
            "BIND_HOST", str, "127.0.0.1", "Numeric listener IP; default loopback", "--bind-host"
        ),
        Option("PORT", int, 0, "Listener port; 0 selects an unused port", "--port"),
        Option(
            "PUBLIC_URL",
            str,
            "",
            "Existing forwarded HTTP(S) origin and optional prefix",
            "--public-url",
        ),
        Option("MAX_RECEIPTS", int, 100, "Receipt cap before listener stops", "--max-receipts"),
        Option("MAX_CONNECTIONS", int, 16, "Maximum concurrent connections", "--max-connections"),
        Option(
            "MAX_CONNECTION_ATTEMPTS",
            int,
            1000,
            "Total incoming connection cap",
            "--max-connection-attempts",
        ),
        Option("CALLBACKS", int, 1, "Number of unpredictable callback URLs to mint", "--callbacks"),
        Option("METHODS", list, ["GET"], "Allowed callback HTTP methods", "--method"),
        Option(
            "BODY_SHA256", str, "", "Optional expected body SHA256 for correlation", "--body-sha256"
        ),
        Option(
            "RECEIPTS_FILE",
            str,
            "",
            "Private JSON/JSONL receipts; offline import",
            "--receipts-file",
        ),
        Option(
            "CALLBACK_URL",
            str,
            "",
            "Exact full callback URL for offline correlation",
            "--callback-url",
        ),
        Option("CALLBACK_ID", str, "", "Exact marker for offline correlation", "--callback-id"),
        Option(
            "SINCE_EPOCH", float, 0.0, "Earliest accepted receipt epoch timestamp", "--since-epoch"
        ),
        Option("DRY_RUN", bool, False, "Validate plan without opening a listener", "--dry-run"),
    )

    def validate(self, settings):
        if settings["BUDGET"] > 3600 or settings["TIMEOUT"] > 60:
            raise ValueError("Callback BUDGET is at most 3600 and TIMEOUT at most 60 seconds")
        if not 1 <= settings["CALLBACKS"] <= 1000:
            raise ValueError("CALLBACKS must be 1-1000")
        if not math.isfinite(settings["SINCE_EPOCH"]) or settings["SINCE_EPOCH"] < 0:
            raise ValueError("SINCE_EPOCH must be finite and nonnegative")
        # Core constructor validation is shared with network assessment callers.
        probe = SimpleNamespace(
            store=SimpleNamespace(root=Path(".")), deadline=time.monotonic() + 1
        )
        CallbackCollector(
            probe,
            bind_host=settings["BIND_HOST"],
            port=settings["PORT"],
            public_url=settings["PUBLIC_URL"],
            max_receipts=settings["MAX_RECEIPTS"],
            max_bytes=settings["MAX_BYTES"],
            max_connections=settings["MAX_CONNECTIONS"],
            max_connection_attempts=settings["MAX_CONNECTION_ATTEMPTS"],
            request_timeout=settings["TIMEOUT"],
        )
        self._imported = None
        if settings["RECEIPTS_FILE"]:
            url = callback_url(settings["CALLBACK_URL"])
            marker = settings["CALLBACK_ID"]
            correlate_receipts(
                [],
                marker,
                url,
                settings["SINCE_EPOCH"],
                methods=settings["METHODS"],
                body_sha256=settings["BODY_SHA256"] or None,
                until_epoch=max(time.time(), settings["SINCE_EPOCH"]),
            )
            self._imported = read_receipts(
                settings["RECEIPTS_FILE"], max_receipts=settings["MAX_RECEIPTS"]
            )
        else:
            if settings["CALLBACK_URL"] or settings["CALLBACK_ID"] or settings["SINCE_EPOCH"]:
                raise ValueError("CALLBACK_URL, CALLBACK_ID and SINCE_EPOCH require RECEIPTS_FILE")
            # Validate methods/digest without opening a socket or creating artifacts.
            correlate_receipts(
                [],
                "validation_marker_123456",
                "http://127.0.0.1/callbacks/validation_marker_123456",
                methods=settings["METHODS"],
                body_sha256=settings["BODY_SHA256"] or None,
            )

    async def assess(self, ctx):
        settings = ctx.settings
        ctx.report["callback_collector"] = {
            "network_requests": 0,
            "listener_opened": False,
            "raw_headers_or_bodies_retained": False,
            "receipt_proves": "HTTP callback only; caller identity is not established",
        }
        if self._imported is not None:
            matched = correlate_receipts(
                self._imported,
                settings["CALLBACK_ID"],
                settings["CALLBACK_URL"],
                settings["SINCE_EPOCH"],
                methods=settings["METHODS"],
                body_sha256=settings["BODY_SHA256"] or None,
            )
            ctx.report["callback_collector"].update(
                mode="import", input_receipts=len(self._imported), matched_receipts=len(matched)
            )
            if settings["DRY_RUN"]:
                ctx.report["plan"] = {"mode": "import", "network_requests": 0}
                return
            for receipt in matched:
                receipt["source"] = "imported_receipt"
                receipt.pop("evidence", None)
                evidence = write_callback_evidence(ctx, receipt)
                ctx.report["results"].append(
                    {"kind": "callback_receipt", **receipt, "evidence": [evidence]}
                )
            ctx.report["coverage"].append(
                {"category": "callback_correlation", "status": "matched" if matched else "no_match"}
            )
            return
        if settings["DRY_RUN"]:
            ctx.report["plan"] = {
                "mode": "listener",
                "bind_host": settings["BIND_HOST"],
                "port": settings["PORT"],
                "public_url": settings["PUBLIC_URL"],
                "callback_count": settings["CALLBACKS"],
                "methods": settings["METHODS"],
                "network_requests": 0,
                "listener_opened": False,
            }
            return
        collector = CallbackCollector(
            ctx,
            bind_host=settings["BIND_HOST"],
            port=settings["PORT"],
            public_url=settings["PUBLIC_URL"],
            max_receipts=settings["MAX_RECEIPTS"],
            max_bytes=settings["MAX_BYTES"],
            max_connections=settings["MAX_CONNECTIONS"],
            max_connection_attempts=settings["MAX_CONNECTION_ATTEMPTS"],
            request_timeout=settings["TIMEOUT"],
        )
        try:
            await collector.start()
            callbacks = []
            for _ in range(settings["CALLBACKS"]):
                url = collector.register(
                    methods=settings["METHODS"], body_sha256=settings["BODY_SHA256"] or None
                )
                callbacks.append({"callback_id": urlsplit(url).path.rsplit("/", 1)[-1], "url": url})
                ctx.console.print(f"Callback: {url}", markup=False)
            ctx.report["callbacks"] = callbacks
            ctx.report["callback_collector"].update(
                mode="listener",
                listener_opened=True,
                bind_host=collector.bind_host,
                port=collector.port,
                receipts_file=str(collector.receipts_file.relative_to(ctx.store.root)),
            )
            # Make addresses available to CLI/MCP artifact readers while the local
            # task remains listening. The final report uses the usual lifecycle.
            ctx.store.write_report(ctx.report)
            await collector.wait_closed()
            for receipt in collector.receipts:
                registration = collector.registrations[receipt["callback_id"]]
                matches = correlate_receipts(
                    [receipt],
                    receipt["callback_id"],
                    registration["url"],
                    registration["created_at"],
                    methods=registration["methods"],
                    body_sha256=registration["body_sha256"],
                )
                ctx.report["results"].append(
                    {
                        "kind": "callback_receipt",
                        **receipt,
                        "correlated": bool(matches),
                        "evidence": [receipt["evidence"]],
                    }
                )
            ctx.report["callback_collector"]["receipt_count"] = len(collector.receipts)
            ctx.report["callback_collector"].update(
                connection_attempts=collector.connection_attempts,
                limited=collector.stop_reason in {"receipt_limit", "connection_limit"},
            )
            ctx.report["coverage"].append(
                {
                    "category": "callback_listener",
                    "status": collector.stop_reason,
                }
            )
        finally:
            await collector.close()
