import hashlib
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from rich.console import Console

from fieldkit.cli import main
from fieldkit.modules.web_artifacts import WebArtifacts


@pytest.fixture
def webserver():
    requested = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requested.append(self.path)
            status, content_type = 200, "text/plain"
            headers = {}
            if self.path == "/":
                content_type = "text/html"
                body = (
                    b'<base href="/assets/"><script src="bundle.js?v=1"></script>'
                    b'<script src="//outside.invalid/third-party.js"></script>'
                )
            elif self.path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /admin/\n"
            elif self.path == "/.well-known/security.txt":
                body = b"Contact: mailto:security@example.test\n"
            elif self.path == "/assets/bundle.js?v=1":
                content_type = "application/javascript"
                body = b'const endpoint = "/api";'
            elif self.path == "/assets/bundle.js.bak?v=1":
                body = b"old script"
            elif self.path == "/moved.txt":
                status, headers, body = 302, {"Location": "/robots.txt"}, b""
            elif self.path == "/external.txt":
                status, headers, body = 302, {"Location": "http://outside.invalid/file"}, b""
            elif self.path == "/large.js":
                body = b"x" * 4096
            elif self.path == "/forbidden.bak":
                status, body = 403, b"Forbidden"
            elif self.path == "/missing.txt":
                status, body = 404, b"Not found"
            else:
                # Intentionally return a soft 404 reflecting the requested path.
                content_type = "text/html"
                body = f"<html>Cannot find {self.path}</html>".encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", requested
    server.shutdown()
    server.server_close()
    thread.join()


def scan(tmp_path, targets, **overrides):
    module = WebArtifacts()
    settings = module.defaults()
    settings.update(TARGETS=targets, OUTPUT=str(tmp_path), RATE=0, RETRIES=0, **overrides)
    code = module.run(settings, Console(file=io.StringIO()))
    manifest = next(tmp_path.glob("*/report.json"))
    return code, json.loads(manifest.read_text()), manifest.parent


def test_collects_real_artifacts_and_filters_reflected_soft_404(webserver, tmp_path):
    base, requested = webserver
    code, report, root = scan(tmp_path, [base])
    assert code == 0
    target = report["targets"][0]
    saved = [r for r in target["results"] if r["verdict"] == "saved"]
    assert {r["requested_url"].removeprefix(base) for r in saved} == {
        "/robots.txt",
        "/.well-known/security.txt",
        "/assets/bundle.js?v=1",
        "/assets/bundle.js.bak?v=1",
    }
    assert target["counts"]["soft_404"] > 0
    assert len(requested) == len(set(requested))
    assert report["completed"] and target["completed"]
    for record in saved:
        content = (root / record["file"]).read_bytes()
        assert hashlib.sha256(content).hexdigest() == record["sha256"]
        assert len(content) == record["bytes"]


def test_reports_redirect_limits_missing_denied_and_oversized(webserver, tmp_path):
    base, _ = webserver
    code, report, root = scan(
        tmp_path,
        [base],
        ONLY_CUSTOM=True,
        DISCOVER_JS=False,
        BACKUPS=False,
        PATHS=["/moved.txt", "/external.txt", "/large.js", "/forbidden.bak", "/missing.txt"],
        MAX_BYTES=1024,
    )
    results = {r["requested_url"].removeprefix(base): r for r in report["targets"][0]["results"]}
    assert code == 1
    assert results["/moved.txt"]["verdict"] == "saved"
    assert results["/moved.txt"]["final_url"] == f"{base}/robots.txt"
    assert results["/external.txt"]["verdict"] == "blocked_redirect"
    assert results["/large.js"]["verdict"] == "too_large"
    assert results["/forbidden.bak"]["status"] == 403
    assert results["/forbidden.bak"]["verdict"] == "http_error"
    assert results["/missing.txt"]["verdict"] == "missing"
    saved = [r for r in results.values() if r["verdict"] == "saved"]
    assert len(saved) == 1
    assert (root / saved[0]["file"]).is_file()
    assert len(list((root / "evidence").glob("*.json"))) == 7


def test_multiple_targets_and_cli_target_file(webserver, tmp_path):
    base, _ = webserver
    targets = tmp_path / "targets.txt"
    targets.write_text(base.replace("127.0.0.1", "localhost") + "\n")
    output = tmp_path / "results"
    code = main(
        [
            "collect",
            base,
            "--targets-file",
            str(targets),
            "--output",
            str(output),
            "--only-custom",
            "--path",
            "/robots.txt",
            "--no-discover-js",
            "--no-backups",
            "--rate",
            "0",
            "--retries",
            "0",
        ]
    )
    assert code == 0
    report = json.loads(next(output.glob("*/report.json")).read_text())
    assert len(report["targets"]) == 2
    files = [t["results"][0]["file"] for t in report["targets"]]
    assert len(set(files)) == 2


def test_auto_fallback_and_explicit_scheme_precedence(webserver, tmp_path):
    base, _ = webserver
    code, report, _ = scan(
        tmp_path,
        [base.removeprefix("http://")],
        ONLY_CUSTOM=True,
        PATHS=["/robots.txt"],
        DISCOVER_JS=False,
        BACKUPS=False,
    )
    assert code == 0
    assert report["targets"][0]["origin"] == base + "/"
    assert report["targets"][0]["probes"][0]["error"] == "network_error"
    assert "fallback" in report["targets"][0]["notes"][0]


def test_validation_precedes_requests_and_output(webserver, tmp_path):
    base, requested = webserver
    with pytest.raises(ValueError):
        scan(tmp_path, [base], TIMEOUT=float("nan"))
    assert not requested
    assert not list(tmp_path.iterdir())


def test_disabling_soft_404_saves_success_body(webserver, tmp_path):
    base, _ = webserver
    code, report, _ = scan(
        tmp_path,
        [base],
        ONLY_CUSTOM=True,
        PATHS=["/absent.txt"],
        DISCOVER_JS=False,
        BACKUPS=False,
        SOFT_404=False,
    )
    assert code == 0
    assert report["targets"][0]["results"][0]["verdict"] == "saved"
