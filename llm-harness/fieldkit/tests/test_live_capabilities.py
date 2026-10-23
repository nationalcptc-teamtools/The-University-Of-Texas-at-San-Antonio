"""New workflows against actual loopback HTTP/TLS and optional native Chromium."""

import io
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest
from rich.console import Console
from test_platform_modules import certificate as platform_certificate
from test_platform_modules import require_chromium
from test_replay_checks import write_json

from fieldkit.modules.request_replay import RequestReplay
from fieldkit.modules.session_workflow import BrowserLogin, SessionWorkflow


@pytest.fixture
def tls_certificate(tmp_path):
    return platform_certificate.__wrapped__(tmp_path)


@contextmanager
def application(handler, tls=None):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def execute(self):
            content = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append((self.command, self.path, dict(self.headers), content))
            status, headers, body = handler(
                self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, content
            )
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = execute

        def log_message(self, *_args):
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


def run(module, tmp_path, target, **overrides):
    settings = {
        **module.defaults(),
        "TARGETS": [target],
        "RATE": 0,
        "RETRIES": 0,
        "TIMEOUT": 5,
        "OUTPUT": str(tmp_path / "runs"),
        **overrides,
    }
    code = module.run(settings, Console(file=io.StringIO()))
    path = max((tmp_path / "runs").glob("*/report.json"), key=lambda p: p.stat().st_mtime_ns)
    return code, json.loads(path.read_text()), path.parent


@pytest.mark.parametrize("tls", [False, True])
def test_replay_actual_http_tls_methods_formats_and_http_errors(tmp_path, tls_certificate, tls):
    _, context = tls_certificate

    def handler(method, path, headers, body):
        return (
            403 if path == "/denied" else 200,
            {"Content-Type": "application/json"},
            b'{"fixture":true}',
        )

    with application(handler, context if tls else None) as (url, seen):
        requests = write_json(
            tmp_path,
            "requests.json",
            [
                {"id": "json", "url": url + "/json", "method": "PUT", "json": {"x": "value"}},
                {"id": "xml", "url": url + "/xml", "method": "POST", "xml": "<r><x>value</x></r>"},
                {"id": "form", "url": url + "/form", "method": "POST", "form": {"x": "value"}},
                {"id": "denied", "url": url + "/denied"},
            ],
        )
        code, report, _ = run(
            RequestReplay(),
            tmp_path,
            url,
            REQUESTS_FILE=requests,
            REQUEST_IDS=["json", "xml", "form", "denied"],
            INSECURE=tls,
        )
    assert code == 0 and len(seen) == 4
    assert seen[0][0] == "PUT" and json.loads(seen[0][3]) == {"x": "value"}
    assert seen[1][3] == b"<r><x>value</x></r>" and seen[2][3] == b"x=value"
    assert report["results"][3]["baseline"]["status"] == 403 and not report["errors"]


def test_dynamic_workflow_actual_tls_session(tmp_path, tls_certificate):
    _, context = tls_certificate

    def handler(method, path, headers, body):
        if path == "/login" and method == "GET":
            return (
                200,
                {"Set-Cookie": "pre=fixture-pre-secret; Path=/; Secure"},
                b'<input name="nonce" value="fixture-nonce-secret">',
            )
        if path == "/login":
            fields = parse_qs(body.decode())
            valid = fields.get("nonce") == [
                "fixture-nonce-secret"
            ] and "fixture-pre-secret" in headers.get("cookie", "")
            return (
                (200 if valid else 403),
                {"Set-Cookie": "sid=fixture-session-secret; Path=/; Secure"},
                b'{"access":"fixture-token-secret"}',
            )
        valid = headers.get(
            "authorization"
        ) == "Bearer fixture-token-secret" and "fixture-session-secret" in headers.get("cookie", "")
        return (200 if valid else 403), {}, b"Known private account"

    with application(handler, context) as (url, seen):
        workflow = write_json(
            tmp_path,
            "workflow.json",
            {
                "steps": [
                    {
                        "request": {"url": "/login"},
                        "expect": {"statuses": [200]},
                        "extract": {"nonce": {"source": "html", "match": {"name": "nonce"}}},
                    },
                    {
                        "request": {
                            "url": "/login",
                            "method": "POST",
                            "form": {"nonce": "{{nonce}}"},
                        },
                        "expect": {"statuses": [200]},
                        "extract": {"access": {"source": "json", "pointer": "/access"}},
                    },
                    {
                        "request": {
                            "url": "/account",
                            "headers": {"Authorization": "Bearer {{access}}"},
                        },
                        "expect": {"statuses": [200], "contains": "Known private account"},
                    },
                ]
            },
        )
        code, report, directory = run(
            SessionWorkflow(),
            tmp_path,
            url,
            WORKFLOW_FILE=workflow,
            INSECURE=True,
            SAVE_PROFILE=True,
        )
    assert code == 0 and len(seen) == 3
    assert all(r["outcome"] == "observed" for r in report["results"])
    assert "fixture-nonce-secret" not in "".join(
        p.read_text() for p in (directory / "evidence").glob("*.json")
    )
    profile = json.loads((directory / "private-session-profile.json").read_text())["profiles"][
        "authenticated"
    ]
    assert profile["headers"]["Authorization"] == "Bearer fixture-token-secret"


def test_browser_login_actual_chromium_cookie_transfer_and_external_blocking(tmp_path):
    require_chromium()
    with application(lambda *args: (200, {}, b"external")) as (external, outside_seen):
        body = (
            f'<script src="{external}/external.js"></script>'
            '<script>document.cookie="sid=browser-private-secret;path=/";</script>'
            '<div id="signed-in">fixture</div>'
        ).encode()

        def handler(method, path, headers, content):
            if path == "/login":
                return 200, {"Content-Type": "text/html"}, body
            return (
                200,
                {},
                b"Authenticated"
                if "browser-private-secret" in headers.get("cookie", "")
                else b"Anonymous",
            )

        with application(handler) as (url, seen):
            code, report, directory = run(
                BrowserLogin(),
                tmp_path,
                url,
                LOGIN_URL="/login",
                SUCCESS_SELECTOR="#signed-in",
                HEADLESS=True,
                SAVE_PROFILE=True,
                BROWSER_TIMEOUT=10,
            )
            assert code == 0, report["errors"]
            profile = str(directory / "private-session-profile.json")
            requests = write_json(tmp_path, "request.json", {"id": "account", "url": "/account"})
            code, replay, _ = run(
                RequestReplay(),
                tmp_path,
                url,
                PROFILES_FILE=profile,
                PROFILE="authenticated",
                REQUESTS_FILE=requests,
                REQUEST_IDS=["account"],
            )
    assert code == 0 and not outside_seen
    assert seen[-1][1] == "/account" and "browser-private-secret" in seen[-1][2]["Cookie"]
    assert replay["results"][0]["baseline"]["bytes"] == len("Authenticated")
    assert "browser-private-secret" not in (directory / "report.json").read_text()
