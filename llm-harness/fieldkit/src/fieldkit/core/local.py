"""Offline/host run lifecycle using the same schema and evidence contract as HTTP."""

import asyncio
import hashlib
import json
import math
import socket
import time
from pathlib import Path

from fieldkit.core.assessment import write_private
from fieldkit.core.module import Module, Option
from fieldkit.core.process import ProcessResult, run_process
from fieldkit.core.redaction import redact
from fieldkit.core.results import stable_id
from fieldkit.core.storage import ArtifactStore, utc_now

LOCAL_OPTIONS = (
    Option("OUTPUT", str, "artifacts", "Parent of a private unique run", "--output"),
    Option("HOST_ID", str, "", "Stable host identity; default local hostname", "--host-id"),
    Option("BUDGET", float, 120.0, "Total runtime ceiling in seconds", "--budget"),
    Option("TIMEOUT", float, 10.0, "Per-command/read deadline", "--timeout"),
    Option("MAX_BYTES", int, 1048576, "Per-file/command output ceiling", "--max-bytes"),
)


class LocalContext:
    def __init__(self, module, settings, console):
        self.settings, self.console = settings, console
        self.host = settings.get("HOST_ID") or socket.gethostname()
        self.store = ArtifactStore(settings["OUTPUT"])
        self.secrets = []
        self.deadline = time.monotonic() + settings["BUDGET"]
        self.report = {
            "schema_version": 2,
            "module": module,
            "started_at": utc_now(),
            "completed": False,
            "settings": redact(settings),
            "host": self.host,
            "results": [],
            "findings": [],
            "endpoints": [],
            "evidence": [],
            "errors": [],
            "coverage": [],
        }
        self._findings = {}

    def check_deadline(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Run time budget exhausted")

    def error(self, error, resource, detail=""):
        self.report["errors"].append(
            {"error": error, "resource": str(resource), "detail": str(detail)[:500]}
        )

    def evidence(self, value, *, source, raw=False):
        identifier = f"evidence-{len(self.report['evidence']) + 1:06d}"
        data = value if isinstance(value, bytes) else json.dumps(value, default=str).encode()
        relative = Path("private-raw" if raw else "evidence") / f"{identifier}.json"
        if not raw:
            data = json.dumps(redact(value, self.secrets), default=str, indent=2).encode()
        write_private(self.store.root / relative, data)
        self.report["evidence"].append(
            {
                "id": identifier,
                "file": str(relative),
                "source": str(source),
                "host": self.host,
                "private_raw": raw,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        return identifier

    def finding(self, kind, title, resource, *, evidence=None, **details):
        record = {
            "kind": kind,
            "title": title,
            "host": self.host,
            "resource": str(resource),
            "severity": "info",
            "confidence": "review",
            "evidence": evidence or [],
            **details,
        }
        record["id"] = stable_id(record)
        current = self._findings.get(record["id"])
        if current:
            current["evidence"] = list(dict.fromkeys([*current["evidence"], *record["evidence"]]))
            return current
        self._findings[record["id"]] = record
        self.report["findings"].append(record)
        return record

    async def command(self, category, argv, *, max_output=None):
        self.check_deadline()
        result = ProcessResult()
        try:
            await run_process(
                argv,
                timeout=min(self.settings["TIMEOUT"], self.deadline - time.monotonic()),
                max_output=max_output or self.settings["MAX_BYTES"],
                result=result,
            )
        finally:
            evidence = self.evidence(
                {
                    "argv": argv,
                    **result.metadata(),
                    "stdout": result.stdout.decode(errors="replace"),
                    "stderr": result.stderr.decode(errors="replace"),
                },
                source=category,
            )
            self.report["results"].append(
                {
                    "kind": category,
                    "host": self.host,
                    "resource": argv[-1] if category == "host_file" else category,
                    **result.metadata(),
                    "evidence": [evidence],
                }
            )
            self.report["coverage"].append({"category": category, "status": result.reason})
            if result.reason != "finished":
                self.error(
                    result.reason,
                    category,
                    f"Collector {argv[0]} incomplete; install it if unavailable",
                )
        return result, evidence

    def finish(self):
        for entry in self.report["evidence"]:
            if entry["private_raw"]:
                continue
            path = self.store.root / entry["file"]
            data = json.dumps(redact(json.loads(path.read_text()), self.secrets), indent=2).encode()
            write_private(path, data)
            entry.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.report["finished_at"] = utc_now()
        write_private(
            self.store.root / "inventory.json",
            json.dumps({"schema_version": 2, "endpoints": self.report["endpoints"]}, indent=2),
        )
        self.console.print(
            f"Report: {self.store.write_report(redact(self.report, self.secrets))}", markup=False
        )


class LocalModule(Module):
    options = LOCAL_OPTIONS

    def validate(self, settings):
        pass

    def run(self, settings, console):
        for name in ("BUDGET", "TIMEOUT", "MAX_BYTES"):
            if not math.isfinite(settings[name]) or settings[name] <= 0:
                raise ValueError(f"{name} must be finite and positive")
        self.validate(settings)
        ctx = LocalContext(self.name, settings, console)
        code = 0
        try:
            asyncio.run(self.assess(ctx))
            ctx.report["completed"] = not bool(ctx.report["errors"])
            code = 1 if ctx.report["errors"] else 0
        except KeyboardInterrupt:
            ctx.error("interrupted", self.name)
            code = 130
        except (TimeoutError, OSError, ValueError) as exc:
            ctx.error(
                "budget_exhausted" if isinstance(exc, TimeoutError) else "input_error",
                self.name,
                exc,
            )
            code = 1
        finally:
            ctx.finish()
        return code

    async def assess(self, ctx):
        raise NotImplementedError
