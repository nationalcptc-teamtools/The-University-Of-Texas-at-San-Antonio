"""Bounded ffuf import and explicit, scoped single-field fuzzing.

ffuf 2.1 does not verify TLS and can read unbounded response bodies even with
``-ignore-body``. Active runs therefore send its requests to a private loopback
bridge. Only the shared scoped HTTP runtime contacts the authorized origin.
"""

import asyncio
import base64
import copy
import hashlib
import json
import math
import os
import secrets
import shutil
import tempfile
import time
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import httpx

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule, write_private
from fieldkit.core.http import origin
from fieldkit.core.module import Option
from fieldkit.core.process import ProcessResult
from fieldkit.core.process import run_process as bounded_process
from fieldkit.core.profiles import jar_cookie, load_profiles
from fieldkit.core.redaction import redact
from fieldkit.core.replay import (
    edit_request,
    execute_request,
    load_requests,
    raw_request,
    resolve_request,
    select_requests,
    validate_request,
)
from fieldkit.core.targets import read_targets
from fieldkit.core.urls import normalize_url
from fieldkit.modules.assessment_helpers import response_similarity, response_summary
from fieldkit.modules.request_replay import REPLAY_OPTIONS

FFUF_OPTIONS = (
    Option("INPUT", str, "", "Offline ffuf JSON or JSONL output", "--input"),
    Option(
        "IMPORT_COMPLETE", bool, False, "Assert the imported campaign finished", "--import-complete"
    ),
    Option("EXECUTE", bool, False, "Run the selected saved request with ffuf", "--execute"),
    Option(
        "CONFIRM_FUZZ", bool, False, "Authorize the bounded active fuzz campaign", "--confirm-fuzz"
    ),
    Option("BINARY", str, "ffuf", "Operator-installed ffuf 2.1 executable", "--binary"),
    Option("WORDLIST", str, "", "Private UTF-8 wordlist, one value per line", "--wordlist"),
    Option(
        "LOCATION", str, "", "One query/header/form/JSON/body replacement location", "--location"
    ),
    Option("MAX_WORDS", int, 100, "Maximum wordlist values used", "--max-words"),
    Option("MAX_RESULTS", int, 100, "Maximum imported/tool observations", "--max-results"),
    Option("MAX_OUTPUT", int, 8388608, "Maximum combined subprocess/import bytes", "--max-output"),
)


def read_bounded(path, maximum):
    source = Path(path).expanduser()
    if not source.is_file():
        raise ValueError("Input must be a regular file")
    with source.open("rb") as stream:
        data = stream.read(maximum + 1)
    return data[:maximum], len(data) > maximum


def private_url(url, values):
    """Hide complete probe values without altering URL syntax or metadata labels."""
    parsed = urlsplit(url)
    values = {value for value in values if value}
    path = "/".join(
        "[REDACTED]" if unquote(part) in values else part for part in parsed.path.split("/")
    )
    pairs = [
        (key, "[REDACTED]" if value in values else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunsplit(parsed._replace(path=path, query=urlencode(pairs)))


def parse_output(data, maximum):
    """Parse bounded native JSON or JSONL while preserving valid partial rows."""
    records, malformed, truncated, private_values = [], 0, False, []
    try:
        document = json.loads(data)
    except (ValueError, UnicodeError, RecursionError):
        candidates = []
        for line in data.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError, RecursionError):
                malformed += 1
                continue
            candidates.append(row)
    else:
        if isinstance(document, dict) and isinstance(document.get("results"), list):
            candidates = document["results"]
        elif isinstance(document, list):
            candidates = document
        else:
            candidates = [document]
    for row in candidates:
        if not isinstance(row, dict) or not isinstance(row.get("url"), str):
            malformed += 1
            continue
        inputs = row.get("input", {})
        if isinstance(inputs, dict):
            for key, value in inputs.items():
                if key == "FFUFHASH" or not isinstance(value, str) or not value:
                    continue
                private_values.extend([value, quote(value, safe="")])
                try:
                    decoded = base64.b64decode(value, validate=True).decode("utf-8")
                except (ValueError, UnicodeError):
                    pass
                else:
                    if decoded:
                        private_values.extend([decoded, quote(decoded, safe="")])
        try:
            url = normalize_url(row["url"])
        except (ValueError, TypeError):
            malformed += 1
            continue
        status, size, position = row.get("status"), row.get("length"), row.get("position")
        if (
            not isinstance(status, int)
            or isinstance(status, bool)
            or not 100 <= status <= 599
            or (size is not None and (type(size) is not int or size < 0))
            or (position is not None and (type(position) is not int or position < 0))
        ):
            malformed += 1
            continue
        if len(records) >= maximum:
            truncated = True
            continue
        content_type = row.get("content-type", row.get("content_type", ""))
        record = {
            "kind": "ffuf_observation",
            "url": url,
            "status": status,
            "reported_length": size,
            "position": position,
            "content_type": content_type[:256] if isinstance(content_type, str) else "",
            "outcome": "observed",
            "note": "Tool metadata alone does not establish a vulnerability or body match.",
        }
        records.append(record)
    # Redact imported inputs wherever a saved URL/metadata happens to reflect them.
    for record in records:
        record["url"] = private_url(record["url"], private_values)
    return records, {"malformed_records": malformed, "results_truncated": truncated}


def private_words(path, maximum, max_bytes, location):
    data, byte_truncated = read_bounded(path, max_bytes)
    if byte_truncated and not data.endswith(b"\n"):
        data = data.rpartition(b"\n")[0]
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Wordlist must contain bounded UTF-8 values") from exc
    lines = text.split("\n") if text else []
    if lines and lines[-1] == "":
        lines.pop()
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    truncated = byte_truncated or len(lines) > maximum
    lines = lines[:maximum]
    if not lines:
        raise ValueError("WORDLIST must contain at least one value")
    if any(len(line.encode()) > 65536 or any(ord(c) < 32 for c in line) for line in lines):
        raise ValueError("Wordlist values cannot exceed 64 KiB or contain control characters")
    kind = location.partition(":")[0]
    if kind in {"query", "form"}:
        lines = [quote(line, safe="") for line in lines]
    elif kind == "json":
        lines = [json.dumps(line, ensure_ascii=True)[1:-1] for line in lines]
    kept, size = [], 0
    for line in lines:
        length = len(line.encode()) + 1
        if size + length > max_bytes:
            truncated = True
            break
        kept.append(line)
        size += length
    if not kept:
        raise ValueError("Encoded WORDLIST exceeds its byte limit")
    return kept, truncated


def request_bytes(request):
    """Serialize a validated request; credentials occur only in this private file."""
    parsed = urlsplit(request["url"])
    url = request["url"]
    if request.get("query"):
        supplied = request["query"]
        pairs = [
            (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k not in supplied
        ]
        pairs.extend(supplied.items())
        url = urlunsplit(parsed._replace(query=urlencode(pairs)))
        parsed = urlsplit(url)
    headers = httpx.Headers(request.get("headers", {}))
    if request.get("cookies"):
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in request["cookies"].items())
    body = request.get("body", request.get("data", ""))
    if request.get("form") is not None or isinstance(body, dict):
        body = urlencode(request.get("form", body))
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif "json" in request:
        body = json.dumps(request["json"], separators=(",", ":"))
        headers.setdefault("Content-Type", "application/json")
    elif "xml" in request:
        body = request["xml"]
        headers.setdefault("Content-Type", "application/xml")
    elif "body_base64" in request:
        body = base64.b64decode(request["body_base64"], validate=True)
    body = body.encode() if isinstance(body, str) else body
    body = body or b""
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    head = f"{request['method']} {target} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    # ffuf recalculates the body length after replacement.
    return (head + "\r\n").encode() + body


async def run_process(binary, args, environment, *, deadline, maximum, state=None):
    """Use the shared bounded group runner; raw diagnostics stay in memory."""
    state = state if state is not None else ProcessResult()
    await bounded_process(
        [binary, *args],
        timeout=max(0.001, deadline - time.monotonic()),
        max_output=maximum,
        env=environment,
        result=state,
    )
    return bytes(state.stdout), {
        "exit_code": state.returncode,
        "output_bytes": min(state.bytes_seen, maximum + 1),
        "stop_reason": "tool_deadline"
        if state.reason == "timeout"
        else ("" if state.reason == "finished" else state.reason),
        "partial": state.reason != "finished",
    }


def effective_request(ctx, request):
    """Merge explicit cookie values with the current scoped session snapshot."""
    output = copy.deepcopy(request)
    name = output.get("profile", ctx.settings["PROFILE"])
    profile, client = ctx.profiles[name], ctx.session(name)
    headers = httpx.Headers(profile.headers)
    headers.update(output.get("headers", {}))
    merged = SimpleCookie()
    if (name, origin(output["url"])) not in ctx.seeded_profiles:
        initial = httpx.Cookies()
        for record in profile.cookie_jar:
            initial.jar.set_cookie(jar_cookie(record))
        initial_request = httpx.Request(output["method"], output["url"], cookies=initial)
        merged.load(initial_request.headers.get("Cookie", ""))
        for key, value in profile.cookies.items():
            merged[key] = value
    current = client.build_request(output["method"], output["url"])
    merged.load(current.headers.get("Cookie", ""))
    merged.load(headers.get("Cookie", ""))
    for key, value in output.get("cookies", {}).items():
        merged[key] = value
    if merged:
        headers["Cookie"] = "; ".join(item.OutputString() for item in merged.values())
    output["headers"] = dict(headers)
    output.pop("cookies", None)
    return output


class FuzzBridge:
    """A fixed-origin local adapter; never an open proxy or CONNECT server."""

    def __init__(self, ctx, request, maximum, word_count, private_values=()):
        self.ctx, self.request, self.maximum = ctx, request, maximum
        self.word_count = word_count
        self.count, self.errors = 0, 0
        self.server = None
        self.tasks = set()
        self.url = ""
        self.token = secrets.token_hex(32)
        self.remote = urlsplit(request["url"])
        self.observations = []
        self.observations_truncated = False
        self.private_values = private_values

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0, limit=65536)
        port = self.server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        return self

    async def __aexit__(self, *_):
        self.server.close()
        await self.server.wait_closed()
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            remaining = self.ctx.deadline - time.monotonic()
            async with asyncio.timeout(max(0.001, min(remaining, self.ctx.settings["TIMEOUT"]))):
                head = await reader.readuntil(b"\r\n\r\n")
                if len(head) > 65536:
                    raise ValueError("Bridge request headers exceed limit")
                lines = head.decode("utf-8").split("\r\n")
                method, path, _version = lines[0].split(" ")
                parsed = urlsplit(path)
                if (
                    method != self.request["method"]
                    or parsed.scheme
                    or parsed.netloc
                    or parsed.path != (self.remote.path or "/")
                    or parsed.fragment
                ):
                    raise ValueError("Bridge request leaves the selected endpoint")
                content_length, clean = 0, []
                seen = set()
                authenticated = False
                for line in lines[1:]:
                    if not line:
                        continue
                    name, separator, value = line.partition(":")
                    key = name.lower()
                    if not separator or key in seen:
                        raise ValueError("Ambiguous bridge header")
                    seen.add(key)
                    if key == "x-fieldkit-relay":
                        authenticated = secrets.compare_digest(value.strip(), self.token)
                    elif key == "host":
                        if value.strip() != urlsplit(self.url).netloc:
                            raise ValueError("Bridge Host mismatch")
                    elif key == "content-length":
                        if not value.strip().isdigit():
                            raise ValueError("Invalid bridge body length")
                        content_length = int(value)
                    elif key in {"connection", "accept-encoding"}:
                        continue
                    elif key in {"transfer-encoding", "proxy-authorization", "proxy-connection"}:
                        raise ValueError("Bridge framing/proxy override")
                    else:
                        clean.append(line)
                if not authenticated or "host" not in seen or content_length > self.maximum:
                    raise ValueError("Bridge request exceeds byte limit")
                body = await reader.readexactly(content_length)
                if self.count >= self.word_count:
                    raise ValueError("Bridge request count exceeds the authorized wordlist")
                remote_head = (
                    f"{method} {path} HTTP/1.1\r\nHost: {self.remote.netloc}\r\n"
                    + "\r\n".join(clean)
                    + "\r\n\r\n"
                )
                request = raw_request(remote_head.encode() + body, self.request["url"])
                request["id"] = self.request["id"]
                request["profile"] = self.request.get("profile", self.ctx.settings["PROFILE"])
                self.count += 1
                response, elapsed = await execute_request(self.ctx, request, label="ffuf_variant")
                if response.error:
                    self.errors += 1
                # Single-character/numeric probes must not be registered as
                # global secrets: doing so corrupts unrelated labels and IDs.
                short_values = [v for v in self.private_values if 0 < len(v) < 4]
                public_url = private_url(request["url"], self.private_values)
                summary = response_summary(response)
                summary["url"] = private_url(summary["url"], self.private_values)
                if short_values:
                    evidence_path = (
                        self.ctx.store.root / "evidence" / f"{response.evidence_id}.json"
                    )
                    evidence = json.loads(evidence_path.read_text())
                    evidence["request"]["url"] = public_url
                    evidence["request"]["body"] = redact(evidence["request"]["body"], short_values)
                    field = self.ctx.settings["LOCATION"].partition(":")[2].lower()
                    for key in evidence["request"]["headers"]:
                        if key.lower() == field:
                            evidence["request"]["headers"][key] = "[REDACTED]"
                    evidence["response"]["body_preview"] = redact(
                        evidence["response"]["body_preview"], short_values
                    )
                    evidence["response"]["url"] = summary["url"]
                    write_private(evidence_path, json.dumps(evidence, indent=2) + "\n")
                if self.ctx.report.get("requests"):
                    self.ctx.report["requests"][-1]["url"] = public_url
                for evidence in self.ctx.report["evidence"]:
                    if evidence["id"] == response.evidence_id:
                        evidence["url"] = public_url
                observation = {
                    "kind": "ffuf_variant",
                    "request_id": request["id"],
                    "url": public_url,
                    "method": method,
                    "response": summary,
                    "elapsed": elapsed,
                    "outcome": "inconclusive" if response.error else "observed",
                }
                if len(self.observations) < self.ctx.settings["MAX_RESULTS"]:
                    self.observations.append(observation)
                else:
                    self.observations_truncated = True
                self.ctx.report["tool"]["executed_variants"] = self.count
                status = response.status or 502
                # A valid Content-Length is essential: ffuf 2.1 only honors
                # -ignore-body inside its successful Content-Length parse.
                writer.write(
                    f"HTTP/1.1 {status} Observed\r\nContent-Length: {len(response.body)}\r\n"
                    "Connection: close\r\n\r\n".encode()
                )
                await writer.drain()
        except (
            ValueError,
            UnicodeError,
            OSError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            TimeoutError,
        ):
            self.errors += 1
            writer.write(b"HTTP/1.1 400 Rejected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            try:
                await writer.drain()
            except OSError:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            self.tasks.discard(task)


class Ffuf(NetworkModule):
    name = "web/ffuf"
    description = "Import bounded ffuf output or fuzz one explicitly selected saved request."
    requires_targets = False
    options = (
        tuple(
            Option(o.name, o.kind, 0, o.description, o.flag) if o.name == "RETRIES" else o
            for o in COMMON_OPTIONS
        )
        + tuple(
            Option(o.name, o.kind, 102, o.description, o.flag) if o.name == "MAX_REQUESTS" else o
            for o in REPLAY_OPTIONS
            if o.name != "EDITS_FILE"
        )
        + FFUF_OPTIONS
    )

    def validate(self, settings):
        for name, ceiling in (
            ("MAX_WORDS", 10000),
            ("MAX_RESULTS", 10000),
            ("MAX_OUTPUT", 67108864),
            ("MAX_REQUESTS", 10002),
        ):
            if type(settings[name]) is not int or not 1 <= settings[name] <= ceiling:
                raise ValueError(f"{name} must be between 1 and {ceiling}")
        self._request, self._control, self._words = None, None, []
        self._word_truncated = False
        if settings["INPUT"]:
            if settings["EXECUTE"]:
                raise ValueError("Choose offline INPUT or active EXECUTE")
            self._import, self._import_truncated = read_bounded(
                settings["INPUT"], settings["MAX_OUTPUT"]
            )
            self._import_records, self._import_meta = parse_output(
                self._import, settings["MAX_RESULTS"]
            )
            return
        if not settings["EXECUTE"] or (not settings["DRY_RUN"] and not settings["CONFIRM_FUZZ"]):
            raise ValueError("Supply INPUT, or EXECUTE and CONFIRM_FUZZ for active fuzzing")
        if not (settings["TARGETS"] or settings["TARGETS_FILE"]):
            raise ValueError("Active ffuf requires explicit target origins")
        targets = read_targets(settings["TARGETS"], settings["TARGETS_FILE"])
        scopes, scope_urls = [], []
        for target in targets:
            parsed = urlsplit(normalize_url(target))
            if parsed.path not in {"", "/"} or parsed.query:
                raise ValueError("ffuf targets must be explicit HTTP(S) origins")
            scopes.append(origin(target))
            scope_urls.append(normalize_url(target).rstrip("/"))
        if settings["REQUESTS_FILE"]:
            records = load_requests(
                settings["REQUESTS_FILE"],
                raw=settings["RAW"],
                base=settings["RAW_URL"],
                max_bytes=settings["MAX_BYTES"],
            )
        elif settings["DATABASE"]:
            from fieldkit.core.vault import Vault

            with Vault(settings["DATABASE"], create=False) as vault:
                records = [vault.request(name) for name in settings["REQUEST_IDS"]]
        else:
            raise ValueError("Active ffuf requires REQUESTS_FILE or DATABASE")
        selected = select_requests(records, settings["REQUEST_IDS"])
        if len(selected) != 1:
            raise ValueError("Select exactly one saved request")
        self._request = selected[0]
        if settings["CONTROL_FILE"]:
            controls = load_requests(settings["CONTROL_FILE"], max_bytes=settings["MAX_BYTES"])
            matching = [r for r in controls if r["id"] == self._request["id"]]
            if len(matching) != 1:
                raise ValueError("CONTROL_FILE requires exactly one matching request ID")
            self._control = matching[0]
        profiles = load_profiles(settings["PROFILES_FILE"])
        for request in [self._request, *([self._control] if self._control else [])]:
            url = request["url"]
            if not urlsplit(url).scheme:
                if len(scopes) != 1 or not url.startswith("/") or url.startswith("//"):
                    raise ValueError("Relative request requires exactly one target origin")
                url = scope_urls[0] + url
            normalized = normalize_url(url)
            if origin(normalized) not in scopes:
                raise ValueError("Saved request is outside supplied target scope")
            request["url"] = normalized
            profile = profiles.get(request.get("profile", settings["PROFILE"]))
            if profile is None:
                raise ValueError("Unknown request session profile")
            if (
                profile.origins or profile.headers or profile.cookies or profile.cookie_jar
            ) and origin(normalized) not in {origin(o) for o in profile.origins}:
                raise ValueError("Session profile does not authorize the request origin")
            headers = httpx.Headers(profile.headers)
            headers.update(request.get("headers", {}))
            if "x-fieldkit-relay" in headers:
                raise ValueError("X-Fieldkit-Relay is reserved for private relay authorization")
            validate_request({**request, "headers": dict(headers)})
        kind, _, field = settings["LOCATION"].partition(":")
        if kind == "header" and field.lower() == "x-fieldkit-relay":
            raise ValueError("The private relay authorization header cannot be fuzzed")
        if kind not in {"query", "header", "form", "json", "body"} or (
            kind == "body" and field != "replace"
        ):
            raise ValueError(
                "LOCATION must be query:name, header:name, form:name, json:/pointer or body:replace"
            )
        edited = edit_request(self._request, settings["LOCATION"], "FUZZ")
        profile = profiles[self._request.get("profile", settings["PROFILE"])]
        edited["headers"] = dict(httpx.Headers(profile.headers)) | edited.get("headers", {})
        edited["cookies"] = profile.cookies | edited.get("cookies", {})
        edited = validate_request(edited)
        if request_bytes(edited).count(b"FUZZ") != 1 or any(
            "FUZZ" in str(c) for c in profile.cookie_jar
        ):
            raise ValueError("The prepared request must contain exactly one FUZZ marker")
        if not settings["WORDLIST"]:
            raise ValueError("Active ffuf requires a WORDLIST")
        self._words, self._word_truncated = private_words(
            settings["WORDLIST"],
            settings["MAX_WORDS"],
            settings["MAX_OUTPUT"],
            settings["LOCATION"],
        )
        needed = len(self._words) + 1 + bool(self._control)
        if needed > settings["MAX_REQUESTS"]:
            raise ValueError("Baseline, control and wordlist exceed MAX_REQUESTS")
        if settings["RETRIES"]:
            raise ValueError("Active ffuf requires RETRIES=0 for an exact request ceiling")

    async def _execute(self, ctx):
        async with ctx:
            async with asyncio.timeout(ctx.settings["BUDGET"]):
                if not ctx.settings["INPUT"]:
                    await ctx.prepare()
                await self.assess(ctx)

    async def assess(self, ctx):
        if ctx.settings["INPUT"]:
            partial = (
                self._import_truncated
                or bool(self._import_meta["malformed_records"])
                or self._import_meta["results_truncated"]
                or not ctx.settings["IMPORT_COMPLETE"]
            )
            metadata = {
                "mode": "import",
                "source_file": Path(ctx.settings["INPUT"]).name,
                "source_sha256": hashlib.sha256(self._import).hexdigest(),
                "source_bytes": len(self._import),
                "source_truncated": self._import_truncated,
                "completion_asserted_by_operator": ctx.settings["IMPORT_COMPLETE"],
                "partial": partial,
                **self._import_meta,
            }
            ctx.report["tool"] = metadata
            ctx.report["partial"] = partial
            for record in self._import_records:
                record["provenance"] = "imported_ffuf_metadata"
                record["evidence"] = ["ffuf-tool"]
                ctx.report["results"].append(record)
            write_private(
                ctx.store.root / "evidence" / "ffuf-tool.json",
                json.dumps(
                    redact(
                        {"id": "ffuf-tool", "tool": metadata, "observations": self._import_records},
                        ctx.secrets,
                    ),
                    indent=2,
                )
                + "\n",
            )
            ctx.report["evidence"].append({"id": "ffuf-tool", "file": "evidence/ffuf-tool.json"})
            if self._import_meta["malformed_records"]:
                ctx.report["errors"].append(
                    {
                        "error": "malformed_tool_output",
                        "detail": "Malformed ffuf records omitted; valid records preserved",
                    }
                )
            return
        request = resolve_request(ctx, self._request)
        control = resolve_request(ctx, self._control) if self._control else None
        # Resolve every active request before the first HTTP operation.
        edited = resolve_request(ctx, edit_request(request, ctx.settings["LOCATION"], "FUZZ"))
        binary = shutil.which(str(Path(ctx.settings["BINARY"]).expanduser()))
        if not binary or not Path(binary).is_file():
            ctx.report["errors"].append(
                {
                    "error": "missing_binary",
                    "detail": "Install ffuf 2.1 with your package manager or set BINARY",
                }
            )
            ctx.report["partial"] = True
            return
        digest = hashlib.sha256()
        binary_bytes, binary_truncated = read_bounded(binary, 67108864)
        digest.update(binary_bytes)
        binary_hash = digest.hexdigest() if not binary_truncated else None
        baseline, _ = await execute_request(
            ctx, effective_request(ctx, request), label="ffuf_baseline"
        )
        context = {
            "kind": "ffuf_campaign",
            "request_id": request["id"],
            "url": request["url"],
            "method": request["method"],
            "baseline": response_summary(baseline),
        }
        ctx.report["results"].append(context)
        if control:
            response, _ = await execute_request(
                ctx, effective_request(ctx, control), label="ffuf_control"
            )
            context["control"] = response_summary(response)
            context["baseline_control_similarity"] = response_similarity(baseline, response)
            if response.error:
                ctx.report["partial"] = True
                return
        if baseline.error:
            ctx.report["partial"] = True
            return
        edited = effective_request(ctx, edited)
        if request_bytes(edited).count(b"FUZZ") != 1:
            raise ValueError("Session changes introduced an additional FUZZ marker")
        # The report records positions and response metadata, never probe values.
        private_values = [*self._words, *(unquote(word) for word in self._words)]
        if ctx.settings["LOCATION"].startswith("json:"):
            private_values.extend(json.loads('"' + word + '"') for word in self._words)
        ctx.secrets.extend(word for word in private_values if len(word) >= 4)
        ctx.report["tool"] = {
            "mode": "execute",
            "planned_words": len(self._words),
            "executed_variants": 0,
            "partial": True,
            "transport": "scoped_shared_http_loopback_bridge",
            "binary_file": Path(binary).name,
            "binary_sha256": binary_hash,
        }
        with tempfile.TemporaryDirectory(prefix="fieldkit-ffuf-") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            environment = {
                k: v
                for k, v in os.environ.items()
                if not k.lower().endswith("_proxy")
                and k.lower() not in {"all_proxy", "http_proxy", "https_proxy", "no_proxy"}
            }
            environment["XDG_CONFIG_HOME"] = str(directory / "config")
            environment["XDG_CACHE_HOME"] = str(directory / "cache")
            async with FuzzBridge(
                ctx, request, ctx.settings["MAX_BYTES"], len(self._words), private_values
            ) as bridge:
                ctx.report["variants"] = bridge.observations
                tool_request = copy.deepcopy(edited)
                tool_request["headers"]["X-Fieldkit-Relay"] = bridge.token
                ctx.secrets.append(bridge.token)
                parsed = urlsplit(edited["url"])
                tool_request["url"] = bridge.url + urlunsplit(
                    ("", "", parsed.path, parsed.query, "")
                )
                raw = request_bytes(tool_request)
                request_file, word_file = directory / "request.http", directory / "words.txt"
                write_private(request_file, raw)
                write_private(word_file, "\n".join(self._words) + "\n")
                args = [
                    "-request",
                    str(request_file),
                    "-request-proto",
                    "http",
                    "-w",
                    str(word_file),
                    "-json",
                    "-s",
                    "-noninteractive",
                    "-ignore-body",
                    "-mc",
                    "all",
                    "-t",
                    str(ctx.settings["CONCURRENCY"]),
                    "-timeout",
                    str(max(1, math.ceil(ctx.settings["TIMEOUT"]))),
                    "-maxtime",
                    str(max(1, math.ceil(ctx.deadline - time.monotonic()))),
                ]
                if ctx.settings["RATE"]:
                    if ctx.settings["RATE"] >= 1:
                        args += ["-rate", str(math.floor(ctx.settings["RATE"]))]
                    else:
                        args[args.index("-t") + 1] = "1"
                        args += ["-p", str(1 / ctx.settings["RATE"])]
                state = ProcessResult()
                try:
                    output, metadata = await run_process(
                        str(binary),
                        args,
                        environment,
                        deadline=ctx.deadline,
                        maximum=ctx.settings["MAX_OUTPUT"],
                        state=state,
                    )
                except asyncio.CancelledError:
                    ctx.report["tool"]["process"] = state.metadata()
                    ctx.report["partial"] = True
                    raise
                rows, parsed_meta = parse_output(output, ctx.settings["MAX_RESULTS"])
                for row in rows:
                    parsed = urlsplit(row["url"])
                    row["url"] = urlunsplit(
                        (
                            urlsplit(request["url"]).scheme,
                            urlsplit(request["url"]).netloc,
                            parsed.path,
                            parsed.query,
                            "",
                        )
                    )
                    row["provenance"] = "ffuf_loopback_bridge_metadata"
                    row["body_omitted"] = True
                    row["evidence"] = ["ffuf-tool"]
                ctx.report["results"].extend(rows)
                ctx.report["variants"] = bridge.observations[: ctx.settings["MAX_RESULTS"]]
                partial = (
                    metadata["partial"]
                    or parsed_meta["malformed_records"]
                    or parsed_meta["results_truncated"]
                    or self._word_truncated
                    or bridge.errors
                    or bridge.count != len(self._words)
                    or bridge.observations_truncated
                )
                ctx.report["partial"] = bool(partial)
                ctx.report["tool"] = {
                    "mode": "execute",
                    "binary_file": Path(binary).name,
                    "binary_sha256": binary_hash,
                    "transport": "scoped_shared_http_loopback_bridge",
                    "tls_verification_enabled": not ctx.settings["INSECURE"],
                    "tls_verified": urlsplit(request["url"]).scheme == "https"
                    and not ctx.settings["INSECURE"],
                    "planned_words": len(self._words),
                    "executed_variants": bridge.count,
                    "baseline_requests": 1 + bool(control),
                    "wordlist_truncated": self._word_truncated,
                    "bridge_errors": bridge.errors,
                    "response_bodies_in_tool": False,
                    **metadata,
                    **parsed_meta,
                    "partial": bool(partial),
                }
                if partial:
                    ctx.report["errors"].append(
                        {
                            "error": "partial_tool_run",
                            "detail": "ffuf campaign incomplete; captured observations retained",
                        }
                    )
                evidence = {"id": "ffuf-tool", "tool": ctx.report["tool"], "observations": rows}
                write_private(
                    ctx.store.root / "evidence" / "ffuf-tool.json",
                    json.dumps(redact(evidence, ctx.secrets), indent=2) + "\n",
                )
                ctx.report["evidence"].append(
                    {"id": "ffuf-tool", "file": "evidence/ffuf-tool.json", "url": request["url"]}
                )
