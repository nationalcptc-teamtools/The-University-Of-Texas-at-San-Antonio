"""Registry-backed Python API and isolated, persistent assessment jobs; no import I/O."""

import asyncio
import copy
import json
import math
import os
import re
import sqlite3
import stat
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from fieldkit.core.assessment import write_private
from fieldkit.core.process import ProcessResult, run_process
from fieldkit.core.redaction import redact
from fieldkit.core.storage import utc_now
from fieldkit.registry import modules

JOB_ID = re.compile(r"job-[0-9a-f]{32}\Z")
TERMINAL = {"completed", "failed", "cancelled", "timed_out", "abandoned"}
MAX_READ = 8 * 1024 * 1024
MAX_RESPONSE = 65536
MAX_SAVED_JOBS = 1000
PRIVATE_METADATA = {
    "id",
    "file",
    "body_file",
    "url",
    "method",
    "status",
    "source",
    "source_report",
    "artifact_root",
    "host",
    "resource",
    "bytes",
    "sha256",
    "private_raw",
    "kind",
    "timestamp",
    "asset",
    "format",
    "database",
    "transformation",
    "evidence",
    "profile",
    "user",
    "role",
    "identity",
    "content_type",
    "mime_type",
    "record_ids",
    "request_id",
    "capture_id",
    "received_at",
    "scope_authorizes_requests",
    "tags",
    "index",
}


class FieldkitAgentError(ValueError):
    """Fixed public diagnostic, safe for an MCP client to display."""


def object_schema(properties, required=()):
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


def option_schema(option):
    types = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array"}
    schema = {
        "type": types[option.kind],
        "description": option.description,
        "default": option.default,
    }
    if option.kind is list:
        schema.update(items={"type": "string", "maxLength": 8192}, maxItems=1000)
    elif option.kind is str:
        schema["maxLength"] = 8192
    return schema


def read_json(path, maximum=MAX_READ):
    # Owned result files can be replaced while a worker writes; refuse links/devices.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise FieldkitAgentError("Evidence input must be a regular file")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise FieldkitAgentError("Evidence JSON exceeds the read limit")
    return decode_json(data)


def decode_json(data):
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise FieldkitAgentError("Malformed evidence JSON") from exc
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if isinstance(item, float) and not math.isfinite(item):
            raise FieldkitAgentError("Evidence JSON contains a nonfinite number")
        if depth > 48 or count > 100000:
            raise FieldkitAgentError("Evidence JSON exceeds depth/node limits")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return value


def paginate(rows, offset, limit):
    """Fit complete redacted entries; never silently cut JSON or expose raw content."""
    output, size = [], 0
    for item in rows[offset : offset + limit]:
        safe = public_data(item)
        needed = len(json.dumps(safe).encode())
        if needed > MAX_RESPONSE // 2:
            safe = {
                "id": redact(str(item.get("id", ""))[:128]) if isinstance(item, dict) else None,
                "entry_omitted": True,
                "detail": "Entry exceeds MCP response size limit",
            }
            needed = len(json.dumps(safe).encode())
        if size + needed > MAX_RESPONSE - 2048:
            break
        output.append(safe)
        size += needed
    next_offset = offset + len(output)
    return {
        "items": output,
        "total": len(rows),
        "offset": offset,
        "next_offset": next_offset if next_offset < len(rows) else None,
        "untrusted_evidence": True,
    }


def public_data(value):
    """Raw-marked imported records expose known metadata, never inline payloads."""
    if isinstance(value, dict):
        if value.get("private_raw"):
            safe = {
                k: v
                for k, v in value.items()
                if k in PRIVATE_METADATA
                and (
                    v is None
                    or type(v) in {str, int, float, bool}
                    or k in {"record_ids", "tags", "evidence"}
                    and isinstance(v, list)
                    and all(isinstance(i, str) for i in v)
                )
            }
            for key, allowed in {
                "request": {"method", "url"},
                "response": {"status", "mime_type", "timestamp"},
                "context": {"user", "role", "host", "profile", "feature"},
                "source": {"file", "format", "index", "sha256", "request"},
            }.items():
                nested = value.get(key)
                if isinstance(nested, dict):
                    safe[key] = {
                        k: v
                        for k, v in nested.items()
                        if k in allowed and (v is None or type(v) in {str, int, float, bool})
                    }
            value = safe
        return redact({k: public_data(v) for k, v in value.items()})
    if isinstance(value, list):
        return [public_data(v) for v in value]
    return redact(value)


@dataclass
class Job:
    id: str
    module: str
    directory: Path
    status: str = "queued"
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    process: dict = field(default_factory=dict)
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None

    def public(self):
        return {
            "job_id": self.id,
            "module": self.module,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "directory": str(self.directory),
            "process": self.process,
        }


class FieldkitAgent:
    def __init__(
        self, workspace, output="artifacts/mcp", max_jobs=2, job_timeout=600, max_output=1048576
    ):
        self.workspace = Path(workspace).expanduser().resolve()
        if not self.workspace.is_dir():
            raise FieldkitAgentError("MCP workspace must be an existing directory")
        self.output = Path(output).expanduser()
        if not self.output.is_absolute():
            self.output = self.workspace / self.output
        self.output = self.output.resolve()
        if not isinstance(max_jobs, int) or isinstance(max_jobs, bool) or not 1 <= max_jobs <= 8:
            raise FieldkitAgentError("MAX_JOBS must be 1-8")
        if not math.isfinite(job_timeout) or not 0 < job_timeout <= 86400:
            raise FieldkitAgentError("JOB_TIMEOUT must be positive and at most one day")
        if (
            not isinstance(max_output, int)
            or isinstance(max_output, bool)
            or not 1024 <= max_output <= MAX_READ
        ):
            raise FieldkitAgentError("MAX_OUTPUT must be 1024-8388608 bytes")
        self.max_jobs, self.job_timeout, self.max_output = max_jobs, job_timeout, max_output
        self.registry = modules()
        self.jobs, self.closed = {}, False
        self._restore()

    def _restore(self):
        if not self.output.is_dir():
            return
        candidates = []
        for directory in self.output.glob("job-*"):
            try:
                if not JOB_ID.fullmatch(directory.name) or directory.is_symlink():
                    continue
                candidates.append((directory.stat().st_mtime_ns, directory))
            except OSError:
                continue
        for _, directory in sorted(candidates)[-MAX_SAVED_JOBS:]:
            try:
                data = read_json(directory / "job.json", 65536)
                if (
                    data["module"] not in self.registry
                    or bounded_timestamp(data["created_at"]) is None
                    or not isinstance(data.get("process", {}), dict)
                ):
                    continue
                job = Job(
                    directory.name,
                    data["module"],
                    directory,
                    status=data["status"] if data["status"] in TERMINAL else "abandoned",
                    created_at=data["created_at"],
                    started_at=bounded_timestamp(data.get("started_at")),
                    finished_at=bounded_timestamp(data.get("finished_at")),
                    process={
                        k: v
                        for k, v in data.get("process", {}).items()
                        if k in {"returncode", "reason", "elapsed", "bytes_seen"}
                        and (
                            v is None
                            or type(v) in {int, float}
                            or isinstance(v, str)
                            and len(v) < 64
                        )
                    },
                )
                self.jobs[job.id] = job
            except (OSError, ValueError, KeyError, TypeError):
                continue

    def module_info(self, module):
        name = module
        if name not in self.registry:
            raise FieldkitAgentError("Unknown module; use fieldkit.list_modules()")
        module = self.registry[name]
        return {
            "module": name,
            "description": module.description,
            "accepts_targets": module.accepts_targets,
            "options": [
                {
                    "name": o.name,
                    "flag": o.flag,
                    **option_schema(o),
                    "server_controlled": o.name == "OUTPUT",
                }
                for o in module.options
            ],
            "input_schema": self._module_schema(module),
        }

    def list_modules(self, query=""):
        if not isinstance(query, str):
            raise FieldkitAgentError("Query must be a string")
        return {
            "modules": [
                {"module": n, "description": m.description}
                for n, m in self.registry.items()
                if query.lower() in (n + " " + self.registry[n].description).lower()
            ],
            "total": len(self.registry),
        }

    def _module_schema(self, module):
        return object_schema(
            {
                "options": object_schema(
                    {o.name: option_schema(o) for o in module.options if o.name != "OUTPUT"}
                ),
                "wait_seconds": {
                    "type": "number",
                    "default": 0,
                    "minimum": 0,
                    "maximum": 20,
                    "description": "Optional brief wait; otherwise return a job ID",
                },
            }
        )

    def _job(self, identifier):
        if (
            not isinstance(identifier, str)
            or not JOB_ID.fullmatch(identifier)
            or identifier not in self.jobs
        ):
            raise FieldkitAgentError("Unknown job ID; use fieldkit.list_jobs()")
        return self.jobs[identifier]

    def _persist(self, job):
        path = job.directory / "job.json"
        temporary = job.directory / ".job.json.tmp"
        write_private(temporary, json.dumps(redact(job.public()), indent=2))
        temporary.replace(path)

    def _settings(self, module, options):
        if not isinstance(options, dict):
            raise FieldkitAgentError("Options must be a JSON object using uppercase option names")
        available = {o.name: o for o in module.options}
        for key, value in options.items():
            if key == "OUTPUT":
                raise FieldkitAgentError(
                    "OUTPUT is controlled by MCP; configure --output when starting the server"
                )
            if key not in available:
                raise FieldkitAgentError("Unknown option; inspect fieldkit.module_info()")
            kind = available[key].kind
            valid = (
                (
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and math.isfinite(value)
                )
                if kind is float
                else type(value) is kind
            )
            if not valid or (
                kind is list
                and (
                    len(value) > 1000
                    or not all(isinstance(x, str) and len(x) <= 8192 for x in value)
                )
            ):
                raise FieldkitAgentError(
                    f"Option {key} has the wrong JSON type or exceeds its limit"
                )
            if kind is str and (len(value) > 8192 or "\0" in value):
                raise FieldkitAgentError(f"Option {key} exceeds string limits")
        settings = {**module.defaults(), **copy.deepcopy(options)}
        if len(json.dumps(settings, allow_nan=False).encode()) > 131072:
            raise FieldkitAgentError("Options exceed the MCP configuration byte limit")
        return settings

    async def start_job(self, module_name, options):
        if self.closed:
            raise FieldkitAgentError("Server is closing")
        if module_name not in self.registry:
            raise FieldkitAgentError("Unknown module; use fieldkit.list_modules()")
        module = self.registry[module_name]
        settings = self._settings(module, options)
        if sum(j.status not in TERMINAL for j in self.jobs.values()) >= self.max_jobs:
            raise FieldkitAgentError("Active job limit reached; wait for or cancel a job")
        identifier = "job-" + uuid.uuid4().hex
        directory = self.output / identifier
        directory.mkdir(parents=True, mode=0o700)
        directory.chmod(0o700)
        settings["OUTPUT"] = str(directory / "runs")
        configuration = {
            "module": module_name,
            "settings": settings,
            "result_file": str(directory / "worker-result.json"),
        }
        write_private(directory / ".settings.json", json.dumps(configuration, allow_nan=False))
        job = Job(identifier, module_name, directory)
        self.jobs[identifier] = job
        self._persist(job)
        job.task = asyncio.create_task(self._execute(job))
        return job

    async def _execute(self, job):
        result = ProcessResult()
        try:
            if job.cancel.is_set():
                job.status = "cancelled"
                return
            job.status, job.started_at = "running", utc_now()
            self._persist(job)
            await run_process(
                [
                    sys.executable,
                    "-m",
                    "fieldkit.agent_worker",
                    str(job.directory / ".settings.json"),
                ],
                timeout=self.job_timeout,
                max_output=self.max_output,
                cwd=str(self.workspace),
                cancel=job.cancel,
                result=result,
                terminate_grace=0.5,
            )
            job.process = result.metadata()
            if result.reason == "cancelled":
                job.status = "cancelled"
            elif result.reason == "timeout":
                job.status = "timed_out"
            else:
                job.status = (
                    "completed"
                    if result.reason == "finished" and result.returncode == 0
                    else "failed"
                )
            write_private(
                job.directory / "private-process.log",
                bytes(result.stdout) + b"\n" + bytes(result.stderr),
            )
        except asyncio.CancelledError:
            job.status = "cancelled"
            job.process = result.metadata()
            raise
        except (OSError, ValueError):
            job.status = "failed"
            job.process = {"reason": "worker_error", "detail": "Cannot execute or persist job"}
        finally:
            job.finished_at = utc_now()
            (job.directory / ".settings.json").unlink(missing_ok=True)
            self._persist(job)

    def _report_path(self, job):
        base = (job.directory / "runs").resolve()
        candidates = [
            p
            for p in base.glob("*/report.json")
            if not p.is_symlink() and p.resolve().is_relative_to(job.directory.resolve())
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda p: p.stat().st_mtime_ns)

    def job_status(self, job_id):
        job = self._job(job_id)
        result = job.public()
        path = self._report_path(job)
        result["report_available"] = path is not None
        if path:
            result["report_file"] = str(path)
            try:
                result["summary"] = self.read_report(job_id)["summary"]
            except (OSError, ValueError):
                result["report_read_error"] = "Report exceeds bounds or is not readable yet"
        worker_result = job.directory / "worker-result.json"
        if worker_result.is_file():
            try:
                worker = read_json(worker_result, 16384)
                if not isinstance(worker, dict):
                    raise FieldkitAgentError("Worker outcome must be an object")
                result["worker"] = {
                    k: redact(v)
                    for k, v in worker.items()
                    if k in {"module", "error", "detail", "exit_code"}
                    and (type(v) is int or isinstance(v, str) and len(v) <= 4096)
                }
            except (OSError, ValueError):
                result["worker_read_error"] = "Worker outcome is not readable"
        return redact(result)

    def list_jobs(self, limit=20):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise FieldkitAgentError("Limit must be 1-100")
        recent = sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]
        page = paginate([self.job_status(j.id) for j in recent], 0, limit)
        return {
            "jobs": page["items"],
            "total": len(self.jobs),
            "returned": len(page["items"]),
        }

    def _read_report(self, path):
        report = read_json(path)
        if not isinstance(report, dict):
            raise FieldkitAgentError("Malformed report object or sections")
        for section in ("results", "findings", "errors", "endpoints", "evidence"):
            rows = report.get(section, [])
            if (
                report.get("module") == "results/compare"
                and section in {"results", "findings", "endpoints"}
                and isinstance(rows, dict)
                and set(rows) == {"added", "removed", "changed"}
                and all(isinstance(v, list) for v in rows.values())
            ):
                rows = [
                    {"change": change, "record": record}
                    for change in ("added", "removed", "changed")
                    for record in rows[change]
                ]
                report[section] = rows
            if not isinstance(rows, list):
                raise FieldkitAgentError("Malformed report object or sections")
        return report

    def read_report(self, job_id, section="summary", offset=0, limit=50):
        job = self._job(job_id)
        validate_page(offset, limit)
        path = self._report_path(job)
        if not path:
            return {"job_id": job.id, "available": False, "status": job.status}
        report = self._read_report(path)
        summary = {
            "module": job.module,
            "schema_version": report.get("schema_version")
            if type(report.get("schema_version")) is int
            else None,
            "completed": report.get("completed", job.status == "completed") is True,
            "started_at": bounded_timestamp(report.get("started_at")),
            "finished_at": bounded_timestamp(report.get("finished_at")),
            "counts": {
                k: len(report.get(k, []))
                for k in ("results", "findings", "errors", "endpoints", "evidence")
            },
        }
        if section == "summary":
            return {"job_id": job.id, "available": True, "summary": summary}
        if section not in summary["counts"]:
            raise FieldkitAgentError("Unknown report section")
        rows = report.get(section, [])
        if not isinstance(rows, list):
            raise FieldkitAgentError("Report section must be a list")
        return {
            "job_id": job.id,
            "available": True,
            "section": section,
            **paginate(rows, offset, limit),
        }

    def read_evidence(self, job_id, evidence_id):
        job = self._job(job_id)
        report_path = self._report_path(job)
        if not report_path:
            raise FieldkitAgentError("No saved report is available yet")
        report = self._read_report(report_path)
        matching = [
            e
            for e in report.get("evidence", [])
            if isinstance(e, dict) and e.get("id") == evidence_id
        ]
        if len(matching) != 1:
            raise FieldkitAgentError("Evidence ID must identify one report entry")
        reference = matching[0]
        public_reference = paginate([reference], 0, 1)["items"][0]
        if reference.get("private_raw"):
            return {
                "evidence": public_reference,
                "private_raw": True,
                "content_exposed": False,
            }
        relative = Path(reference.get("file", ""))
        if relative.is_absolute() or relative.parts[:1] != ("evidence",) or ".." in relative.parts:
            raise FieldkitAgentError("Only owned redacted evidence sidecars can be read")
        path = report_path.parent / relative
        if not path.resolve().is_relative_to(report_path.parent.resolve()) or path.is_symlink():
            raise FieldkitAgentError("Evidence file leaves the owned run")
        record = public_data(read_json(path, 131072))
        response = {
            "evidence": public_reference,
            "content_exposed": True,
            "record": record,
            "untrusted_evidence": True,
        }
        if len(json.dumps(response).encode()) > MAX_RESPONSE:
            return {
                "evidence": public_reference,
                "content_exposed": False,
                "detail": "Evidence record exceeds MCP response limit",
            }
        return response

    def vault_records(self, database="artifacts/fieldkit.sqlite", kind="", offset=0, limit=50):
        validate_page(offset, limit)
        path = Path(database).expanduser()
        path = path if path.is_absolute() else self.workspace / path
        if (
            path.is_symlink()
            or not path.resolve().is_relative_to(self.workspace)
            or not path.is_file()
        ):
            raise FieldkitAgentError(
                "Vault must be an existing regular database inside the workspace"
            )
        with sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1
        ) as connection:
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if not version or version[0] != "1":
                raise FieldkitAgentError("Unsupported vault schema")
            where, params = (" WHERE kind=?", (kind,)) if kind else ("", ())
            count = connection.execute("SELECT count(*) FROM records" + where, params).fetchone()[0]
            rows = connection.execute(
                "SELECT id,kind,public_json,source_json,created_at FROM records"
                + where
                + " ORDER BY created_at,id LIMIT ? OFFSET ?",
                (*params, limit, offset),
            )
            values = []
            for identifier, record_kind, public, source, created in rows:
                if len(public) + len(source) > MAX_RESPONSE // 2:
                    values.append({"id": identifier, "kind": record_kind, "entry_omitted": True})
                    continue
                values.append(
                    {
                        "id": identifier,
                        "kind": record_kind,
                        "data": decode_json(public),
                        "source": decode_json(source),
                        "created_at": created,
                    }
                )
        page = paginate(values, 0, limit)
        page.update(
            total=count,
            offset=offset,
            next_offset=offset + len(page["items"])
            if offset + len(page["items"]) < count
            else None,
        )
        return page

    async def cancel_job(self, job_id):
        job = self._job(job_id)
        if job.status not in TERMINAL:
            job.cancel.set()
            if job.task:
                await asyncio.shield(job.task)
        return self.job_status(job_id)

    async def run(self, module, options=None, wait_seconds=0):
        """Start a module job and optionally wait briefly for its public status."""
        validate_wait(wait_seconds)
        job = await self.start_job(module, {} if options is None else options)
        try:
            if wait_seconds:
                await asyncio.wait([job.task], timeout=wait_seconds)
        except asyncio.CancelledError:
            await self.cancel_job(job.id)
            raise
        return self.job_status(job.id)

    async def close(self):
        self.closed = True
        for job in self.jobs.values():
            if job.status not in TERMINAL:
                job.cancel.set()
        await asyncio.gather(
            *(j.task for j in self.jobs.values() if j.task), return_exceptions=True
        )
        for job in self.jobs.values():
            # A task cancelled before its first event-loop tick cannot run its finally.
            if job.status not in TERMINAL and job.task and job.task.done():
                job.status, job.finished_at = "cancelled", utc_now()
                (job.directory / ".settings.json").unlink(missing_ok=True)
                self._persist(job)


def validate_page(offset, limit):
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise FieldkitAgentError("Pagination requires nonnegative OFFSET and LIMIT 1-100")


def validate_wait(seconds):
    if (
        not isinstance(seconds, (int, float))
        or isinstance(seconds, bool)
        or not math.isfinite(seconds)
        or not 0 <= seconds <= 20
    ):
        raise FieldkitAgentError("WAIT_SECONDS must be finite and 0-20")


def bounded_timestamp(value):
    return value if isinstance(value, str) and len(value) <= 64 else None
