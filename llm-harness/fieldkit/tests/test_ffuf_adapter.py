"""Offline imports, private execution and bounded real ffuf integration."""

import asyncio
import io
import json
import os
import signal
import stat
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from rich.console import Console

from fieldkit.core.http import FetchResult
from fieldkit.core.vault import Vault
from fieldkit.modules.ffuf import Ffuf, FuzzBridge, request_bytes, run_process


def json_file(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value))
    return str(path)


def run(tmp_path, **overrides):
    module = Ffuf()
    settings = {
        **module.defaults(),
        "OUTPUT": str(tmp_path / "runs"),
        "RATE": 0,
        "TIMEOUT": 3,
        **overrides,
    }
    code = module.run(settings, Console(file=io.StringIO()))
    path = max((tmp_path / "runs").glob("*/report.json"), key=lambda p: p.stat().st_mtime_ns)
    return code, json.loads(path.read_text()), path.parent


def active(tmp_path, url="https://lab.test", **overrides):
    requests = json_file(tmp_path, "requests.json", [{"id": "r", "url": url + "/item?q=baseline"}])
    words = tmp_path / "words.txt"
    words.write_text("alpha-private-probe\nbeta-private-probe\n")
    return {
        "EXECUTE": True,
        "CONFIRM_FUZZ": True,
        "TARGETS": [url],
        "REQUESTS_FILE": requests,
        "REQUEST_IDS": ["r"],
        "WORDLIST": str(words),
        "LOCATION": "query:q",
        **overrides,
    }


@contextmanager
def application(*, chunked=False, no_length=False, redirect=False, tls=None):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def execute(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(
                (self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, body)
            )
            self.send_response(302 if redirect else 200)
            if redirect:
                self.send_header("Location", "http://outside.invalid/private")
            self.send_header("Content-Type", "application/json")
            if len(seen) == 1:
                self.send_header("Set-Cookie", "rotated=session-private-value; Path=/")
            if chunked and len(seen) > 1:
                self.send_header("Transfer-Encoding", "chunked")
            elif no_length and len(seen) > 1:
                self.send_header("Connection", "close")
                self.close_connection = True
            else:
                self.send_header("Content-Length", "2")
            self.end_headers()
            try:
                if chunked and len(seen) > 1:
                    chunk = b"z" * 1024
                    for _ in range(100):
                        self.wfile.write(b"400\r\n" + chunk + b"\r\n")
                        self.wfile.flush()
                    self.wfile.write(b"0\r\n\r\n")
                elif no_length and len(seen) > 1:
                    self.wfile.write(b"z" * 102400)
                else:
                    self.wfile.write(b"{}")
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = do_POST = do_PUT = execute

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"{'https' if tls else 'http'}://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_import_json_and_partial_jsonl_never_run_network_or_tools(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline importer launched HTTP/tool")

    monkeypatch.setattr("fieldkit.core.assessment.httpx.AsyncClient", forbidden)
    monkeypatch.setattr("fieldkit.modules.ffuf.asyncio.create_subprocess_exec", forbidden)
    source = json_file(
        tmp_path,
        "ffuf.json",
        {
            "commandline": "ffuf -H 'Authorization: Bearer private-token'",
            "config": {"headers": {"Authorization": "Bearer private-token"}},
            "results": [
                {
                    "url": "https://lab.test/?token=private-token",
                    "status": 200,
                    "length": 17,
                    "input": {"FUZZ": "private-probe"},
                }
            ],
        },
    )
    code, report, directory = run(
        tmp_path, INPUT=source, IMPORT_COMPLETE=True, TARGETS=["lab.test"]
    )
    assert code == 0 and report["completed"]
    assert report["tool"]["source_sha256"] and report["tool"]["mode"] == "import"
    assert not report["findings"] and not report["endpoints"]
    saved = "".join(p.read_text() for p in directory.rglob("*.json"))
    assert "private-token" not in saved and "private-probe" not in saved
    source = tmp_path / "ffuf.jsonl"
    source.write_text(
        '{"url":"https://lab.test/a","status":403,"length":0}\n'
        'malformed\n{"url":"https://lab.test/b","status":200,"length":2}\n'
    )
    code, report, _ = run(tmp_path, INPUT=str(source), IMPORT_COMPLETE=True, MAX_RESULTS=1)
    assert code == 1 and report["partial"] and not report["completed"]
    assert len(report["results"]) == 1 and report["tool"]["malformed_records"] == 1
    assert report["tool"]["results_truncated"]


def test_import_without_completion_assertion_and_byte_truncation(tmp_path):
    path = tmp_path / "ffuf.jsonl"
    row = '{"url":"https://lab.test/","status":200,"length":3}\n'
    path.write_text(row * 3)
    _, report, _ = run(tmp_path, INPUT=str(path), MAX_OUTPUT=len(row.encode()) + 4)
    assert report["partial"] and report["tool"]["source_truncated"]
    assert report["tool"]["source_bytes"] == len(row.encode()) + 4
    assert len(report["results"]) == 1


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"CONFIRM_FUZZ": False}, "CONFIRM_FUZZ"),
        ({"TARGETS": []}, "explicit target"),
        ({"TARGETS": ["lab.test"]}, "absolute"),
        ({"REQUEST_IDS": []}, "selection"),
        ({"LOCATION": "header:Host"}, "field does not exist"),
        ({"LOCATION": "query:missing"}, "field does not exist"),
        ({"MAX_REQUESTS": 2}, "exceed MAX_REQUESTS"),
        ({"RETRIES": 1}, "RETRIES=0"),
    ],
)
def test_active_gates_fail_before_network(tmp_path, monkeypatch, overrides, match):
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **kwargs: pytest.fail("validation sent HTTP"),
    )
    with pytest.raises(ValueError, match=match):
        run(tmp_path, **active(tmp_path, **overrides))


def test_dry_run_checks_scope_and_no_http_or_process(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **kwargs: pytest.fail("dry-run sent HTTP"),
    )
    monkeypatch.setattr(
        "fieldkit.modules.ffuf.asyncio.create_subprocess_exec",
        lambda *args, **kwargs: pytest.fail("dry-run launched tool"),
    )
    code, report, _ = run(
        tmp_path, **active(tmp_path, DRY_RUN=True, CONFIRM_FUZZ=False, BINARY="/missing/ffuf")
    )
    assert code == 0 and report["plan"]["network_requests"] == 0
    request = json_file(tmp_path, "outside.json", [{"id": "r", "url": "https://outside.test/?q=x"}])
    with pytest.raises(ValueError, match="scope"):
        run(tmp_path, **active(tmp_path, DRY_RUN=True, REQUESTS_FILE=request))


def test_missing_binary_actionable_and_no_baseline(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **kwargs: pytest.fail("missing binary sent HTTP"),
    )
    code, report, _ = run(tmp_path, **active(tmp_path, BINARY=str(tmp_path / "missing")))
    assert code == 1 and report["partial"]
    assert report["errors"][0]["error"] == "missing_binary"


def test_reserved_relay_header_rejected_before_http(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **kwargs: pytest.fail("reserved header sent HTTP"),
    )
    requests = json_file(
        tmp_path,
        "reserved.json",
        [
            {
                "id": "r",
                "url": "https://lab.test/item?q=x",
                "headers": {"X-Fieldkit-Relay": "existing-header"},
            }
        ],
    )
    with pytest.raises(ValueError, match="reserved"):
        run(tmp_path, **active(tmp_path, REQUESTS_FILE=requests))
    profiles = json_file(
        tmp_path,
        "reserved-profile.json",
        {
            "profiles": {
                "alice": {
                    "origins": ["https://lab.test"],
                    "headers": {"x-fieldkit-relay": "existing-header"},
                }
            }
        },
    )
    with pytest.raises(ValueError, match="reserved"):
        run(tmp_path, **active(tmp_path, PROFILE="alice", PROFILES_FILE=profiles))


@pytest.mark.skipif(not Path("/usr/bin/ffuf").exists(), reason="operator ffuf unavailable")
@pytest.mark.parametrize(
    "location", ["query:q", "header:X-Probe", "form:q", "json:/q", "body:replace"]
)
def test_real_ffuf_preserves_authenticated_request_and_controls(tmp_path, location):
    with application() as (url, seen):
        request = {
            "id": "r",
            "url": url + "/item?q=baseline",
            "method": "POST",
            "profile": "alice",
            "headers": {"X-Probe": "baseline"},
            "cookies": {"explicit": "cookie-private-value"},
        }
        if location.startswith("form"):
            request["form"] = {"q": "baseline", "password": "body-private-value"}
        elif location.startswith("json"):
            request["json"] = {"q": "baseline", "password": "body-private-value"}
        else:
            request["body"] = "baseline"
        requests = json_file(tmp_path, "selected.json", [request])
        profiles = json_file(
            tmp_path,
            "profiles.json",
            {
                "profiles": {
                    "alice": {
                        "origins": [url],
                        "headers": {"Authorization": "Bearer auth-private-value"},
                        "cookies": {"profile": "profile-private-value"},
                    }
                }
            },
        )
        controls = json_file(
            tmp_path,
            "control.json",
            [{**request, "body": "control"}] if "body" in request else [request],
        )
        code, report, directory = run(
            tmp_path,
            **active(
                tmp_path,
                url,
                REQUESTS_FILE=requests,
                LOCATION=location,
                PROFILES_FILE=profiles,
                CONTROL_FILE=controls,
            ),
        )
    assert code == 0, report
    assert len(seen) == 4 and report["tool"]["executed_variants"] == 2
    assert report["tool"]["transport"] == "scoped_shared_http_loopback_bridge"
    assert report["tool"]["tls_verification_enabled"]
    assert not report["tool"]["tls_verified"] and not report["tool"]["response_bodies_in_tool"]
    assert report["results"][0]["control"]["evidence"]
    assert not report["findings"] and len(report["variants"]) == 2
    for method, path, headers, _body in seen:
        assert method == "POST" and path.startswith("/item?")
        assert headers["authorization"] == "Bearer auth-private-value"
        assert "explicit=cookie-private-value" in headers["cookie"]
        assert "profile=profile-private-value" in headers["cookie"]
    assert all("rotated=session-private-value" in row[2]["cookie"] for row in seen[1:])
    variants = seen[2:]
    for _method, path, headers, body in variants:
        if location.startswith("query"):
            assert parse_qs(urlsplit(path).query)["q"][0] in {
                "alpha-private-probe",
                "beta-private-probe",
            }
        elif location.startswith("header"):
            assert headers["x-probe"] in {"alpha-private-probe", "beta-private-probe"}
        elif location.startswith("form"):
            assert parse_qs(body.decode())["q"][0] in {"alpha-private-probe", "beta-private-probe"}
        elif location.startswith("json"):
            assert json.loads(body)["q"] in {"alpha-private-probe", "beta-private-probe"}
        else:
            assert body.decode() in {"alpha-private-probe", "beta-private-probe"}
    saved = "".join(p.read_text() for p in directory.rglob("*.json"))
    for secret in (
        "auth-private-value",
        "cookie-private-value",
        "profile-private-value",
        "session-private-value",
        "body-private-value",
        "alpha-private-probe",
        "beta-private-probe",
    ):
        assert secret not in saved


@pytest.mark.skipif(not Path("/usr/bin/ffuf").exists(), reason="operator ffuf unavailable")
@pytest.mark.parametrize("body_mode", ["chunked", "no_length"])
def test_real_ffuf_chunked_body_bound_and_redirect_scope(tmp_path, body_mode):
    with application(**{body_mode: True}) as (url, seen):
        code, report, _ = run(tmp_path, **active(tmp_path, url, MAX_BYTES=1024))
    assert len(seen) == 3 and code == 1 and report["partial"]
    assert all(v["response"]["bytes"] <= 1024 for v in report["variants"])
    assert all(v["response"]["error"] == "too_large" for v in report["variants"])
    with application(redirect=True) as (url, seen):
        code, report, _ = run(tmp_path, **active(tmp_path, url))
    assert code == 0 and len(seen) == 3
    assert all(v["response"]["status"] == 302 for v in report["variants"])
    assert "outside.invalid" not in json.dumps(report["results"])


@pytest.mark.skipif(not Path("/usr/bin/ffuf").exists(), reason="operator ffuf unavailable")
def test_real_ffuf_tls_default_verification_and_explicit_insecure(tmp_path):
    from test_platform_modules import certificate

    _, context = certificate.__wrapped__(tmp_path)
    with application(tls=context) as (url, seen):
        code, report, _ = run(tmp_path, **active(tmp_path, url))
        assert code == 1 and report["partial"] and not seen
        assert report["results"][0]["baseline"]["error"] == "network_error"
        code, report, _ = run(tmp_path, **active(tmp_path, url, INSECURE=True))
    assert code == 0 and len(seen) == 3
    assert not report["tool"]["tls_verified"]
    assert not report["tool"]["tls_verification_enabled"]


@pytest.mark.skipif(not Path("/usr/bin/ffuf").exists(), reason="operator ffuf unavailable")
@pytest.mark.parametrize("source", ["raw", "vault"])
def test_real_ffuf_selected_raw_and_vault_sources(tmp_path, source):
    with application() as (url, seen):
        if source == "raw":
            path = tmp_path / "request.http"
            path.write_text(
                f"POST /item HTTP/1.1\r\nHost: {urlsplit(url).netloc}\r\n"
                "Authorization: Bearer raw-private-token\r\n"
                "Content-Type: application/json\r\n\r\n"
                '{"q":"baseline"}'
            )
            extra = {"REQUESTS_FILE": str(path), "RAW": True, "RAW_URL": url, "REQUEST_IDS": ["1"]}
        else:
            database = tmp_path / "vault.sqlite3"
            with Vault(str(database)) as vault:
                identifier = vault.exchange(
                    {
                        "method": "POST",
                        "url": url + "/item",
                        "headers": {"Authorization": "Bearer raw-private-token"},
                        "json": {"q": "baseline"},
                    },
                    source={"index": 1},
                )
            extra = {"REQUESTS_FILE": "", "DATABASE": str(database), "REQUEST_IDS": [identifier]}
        code, report, directory = run(
            tmp_path, **active(tmp_path, url, LOCATION="json:/q", **extra)
        )
    assert code == 0 and len(seen) == 3
    assert all(
        row[0] == "POST" and row[2]["authorization"] == "Bearer raw-private-token" for row in seen
    )
    assert "raw-private-token" not in "".join(p.read_text() for p in directory.rglob("*.json"))


@pytest.mark.skipif(not Path("/usr/bin/ffuf").exists(), reason="operator ffuf unavailable")
@pytest.mark.parametrize("location", ["query:q", "form:q", "json:/q"])
def test_real_ffuf_payload_encoding_and_short_probe_metadata(tmp_path, location):
    values = ["1", 'space quote"&plus+slash/']
    words = tmp_path / "special-words.txt"
    words.write_text("\n".join(values) + "\n")
    with application() as (url, seen):
        request = {"id": "r", "url": url + "/item?q=baseline", "method": "POST"}
        if location.startswith("form"):
            request["form"] = {"q": "baseline"}
        elif location.startswith("json"):
            request["json"] = {"q": "baseline"}
        requests = json_file(tmp_path, "encoding.json", [request])
        code, report, directory = run(
            tmp_path,
            **active(tmp_path, url, REQUESTS_FILE=requests, WORDLIST=str(words), LOCATION=location),
        )
    assert code == 0 and len(seen) == 3 and report["tool"]["executed_variants"] == 2
    assert report["results"][1]["kind"] == "ffuf_observation"
    assert report["variants"][0]["outcome"] == "observed"
    if location.startswith("query"):
        observed = [parse_qs(urlsplit(row[1]).query)["q"][0] for row in seen[1:]]
    elif location.startswith("form"):
        observed = [parse_qs(row[3].decode())["q"][0] for row in seen[1:]]
    else:
        observed = [json.loads(row[3])["q"] for row in seen[1:]]
    assert set(observed) == set(values)
    evidence = [json.loads(p.read_text()) for p in (directory / "evidence").glob("evidence-*.json")]
    assert all("q=1" not in e["request"]["url"] for e in evidence)
    if location.startswith("json"):
        assert all('"q":"1"' not in (e["request"]["body"] or "") for e in evidence)


def test_relay_rejects_bad_nonce_path_authority_and_request_overflow(tmp_path, monkeypatch):
    calls = []

    async def execute(ctx, request, **kwargs):
        calls.append(request)
        assert not any(k.lower() == "x-fieldkit-relay" for k in request["headers"])
        return FetchResult(request["url"], request["url"], status=200), 0.01

    monkeypatch.setattr("fieldkit.modules.ffuf.execute_request", execute)
    context = SimpleNamespace(
        settings={"TIMEOUT": 2, "PROFILE": "anonymous", "MAX_RESULTS": 10},
        deadline=time.monotonic() + 5,
        report={"tool": {}, "evidence": []},
    )

    async def exercise():
        async with FuzzBridge(
            context,
            {"id": "r", "method": "GET", "url": "https://lab.test/item?q=baseline"},
            1024,
            1,
        ) as bridge:

            async def send(*, token=None, path="/item?q=probe", host=None, method="GET"):
                parsed = urlsplit(bridge.url)
                reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
                writer.write(
                    request_bytes(
                        {
                            "method": method,
                            "url": bridge.url + path,
                            "headers": {
                                "X-Fieldkit-Relay": bridge.token if token is None else token
                            },
                        }
                    ).replace(
                        f"Host: {parsed.netloc}".encode(), f"Host: {host or parsed.netloc}".encode()
                    )
                )
                await writer.drain()
                data = await reader.read(2048)
                writer.close()
                await writer.wait_closed()
                return data.splitlines()[0]

            assert b"400" in await send(token="invalid")
            assert b"400" in await send(path="/outside")
            assert b"400" in await send(host="outside.test")
            assert b"400" in await send(method="POST")
            assert b"200" in await send()
            assert b"400" in await send()
            assert bridge.count == 1

    asyncio.run(exercise())
    assert len(calls) == 1 and calls[0]["url"] == "https://lab.test/item?q=probe"


def executable(tmp_path, source):
    path = tmp_path / "fake-ffuf"
    path.write_text("#!/usr/bin/env python3\n" + source)
    path.chmod(0o700)
    return path


def test_process_output_deadline_and_group_cancellation(tmp_path):
    binary = executable(
        tmp_path, "import sys\nsys.stdout.write('x' * 100000)\nsys.stdout.flush()\n"
    )
    output, metadata = asyncio.run(
        run_process(str(binary), [], dict(os.environ), deadline=time.monotonic() + 3, maximum=1024)
    )
    assert len(output) <= 1024 and metadata["stop_reason"] == "output_limit"
    binary = executable(tmp_path, "import time\ntime.sleep(30)\n")
    _, metadata = asyncio.run(
        run_process(
            str(binary), [], dict(os.environ), deadline=time.monotonic() + 0.15, maximum=1024
        )
    )
    assert metadata["stop_reason"] == "tool_deadline"
    pid_file = tmp_path / "child.pid"
    binary = executable(
        tmp_path,
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(30)\n",
    )

    async def cancel():
        task = asyncio.create_task(
            run_process(
                str(binary), [], dict(os.environ), deadline=time.monotonic() + 10, maximum=1024
            )
        )
        for _ in range(100):
            if pid_file.exists():
                break
            await asyncio.sleep(0.01)
        assert pid_file.exists()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel())
    pid = int(pid_file.read_text())
    for _ in range(100):
        status = Path(f"/proc/{pid}/stat")
        if not status.exists() or status.read_text().split()[2] == "Z":
            break
        time.sleep(0.01)
    else:
        os.kill(pid, signal.SIGKILL)
        pytest.fail("subprocess descendant survived cancellation")


def test_private_files_proxy_config_isolation_and_partial_fake_tool(tmp_path, monkeypatch):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"{}")),
            **kwargs,
        ),
    )
    captured = {}

    async def fake(binary, args, environment, **kwargs):
        captured["args"] = args
        for flag in ("-request", "-w"):
            path = Path(args[args.index(flag) + 1])
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
            captured[flag] = path
        assert "proxy" not in " ".join(environment).lower()
        assert str(tmp_path / "untrusted") != environment["XDG_CONFIG_HOME"]
        assert "Bearer auth-private-value" in captured["-request"].read_text()
        assert "alpha-private-probe" in captured["-w"].read_text()
        assert "auth-private-value" not in " ".join(args)
        assert "alpha-private-probe" not in " ".join(args)
        return b'{"url":"http://127.0.0.1:1234/item?q=x","status":200,"length":2}\nmalformed', {
            "exit_code": 7,
            "output_bytes": 90,
            "stop_reason": "",
            "partial": True,
        }

    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid")
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "untrusted"))
    monkeypatch.setattr("fieldkit.modules.ffuf.run_process", fake)
    requests = json_file(
        tmp_path,
        "auth.json",
        [
            {
                "id": "r",
                "url": "https://lab.test/item?q=x",
                "headers": {"Authorization": "Bearer auth-private-value"},
            }
        ],
    )
    code, report, _ = run(tmp_path, **active(tmp_path, REQUESTS_FILE=requests, RATE=2.5))
    assert code == 1 and report["partial"] and report["tool"]["malformed_records"] == 1
    assert "-rate" in captured["args"] and "-t" in captured["args"]
    assert all(not captured[flag].exists() for flag in ("-request", "-w"))
