"""Exercise actual loopback TLS handshakes and optional Chromium screenshots."""

import io
import ipaddress
import json
import ssl
import struct
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from rich.console import Console

from fieldkit.modules.snapshot import Snapshot
from fieldkit.modules.tls_review import TLSReview, certificate_details, hostname_matches


@contextmanager
def local_server(routes=None, tls_context=None):
    requests = []
    routes = routes or {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(("GET", self.path))
            status, headers, body = routes.get(self.path, (404, {}, b"Missing"))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self):
            requests.append(("POST", self.path))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls_context:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    scheme = "https" if tls_context else "http"
    try:
        yield f"{scheme}://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.fixture
def certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fieldkit-local-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    return cert, context


def run(module, tmp_path, target, **settings):
    values = module.defaults()
    values.update(TARGETS=[target], OUTPUT=str(tmp_path / "runs"), RATE=0, RETRIES=0, TIMEOUT=5)
    values.update(settings)
    code = module.run(values, Console(file=io.StringIO()))
    report_path = next((tmp_path / "runs").glob("*/report.json"))
    return code, json.loads(report_path.read_text()), report_path.parent


def test_tls12_loopback_negotiation_self_signed_trust_and_san(certificate, tmp_path):
    cert, context = certificate
    with local_server(tls_context=context) as (url, requests):
        code, report, directory = run(TLSReview(), tmp_path, url, PROTOCOLS=["TLSv1.2"])
    assert code == 0
    assert not requests  # TLS assessment needs no HTTP application requests.
    result = report["results"][0]
    assert result["protocols"][0]["outcome"] == "negotiated"
    assert result["protocols"][0]["protocol"] == "TLSv1.2"
    assert result["verification"] == "failed"
    assert result["certificate"]["hostname_covered"]
    assert result["certificate"]["ip_addresses"] == ["127.0.0.1"]
    assert result["certificate"]["dns_names"] == ["localhost"]
    assert result["certificate"]["sha256"] == cert.fingerprint(hashes.SHA256()).hex()
    assert 5 <= result["certificate"]["days_remaining"] <= 7
    saved = x509.load_pem_x509_certificate((directory / result["certificate_file"]).read_bytes())
    assert saved.serial_number == cert.serial_number
    findings = {finding["kind"] for finding in report["findings"]}
    assert "certificate_trust" in findings
    assert "certificate_expiry" in findings
    assert "certificate_hostname" not in findings


def test_tls_server_rejects_tls13_and_insecure_skips_verification(certificate, tmp_path):
    _, context = certificate
    with local_server(tls_context=context) as (url, _):
        code, report, _ = run(
            TLSReview(),
            tmp_path,
            url,
            PROTOCOLS=["TLSv1.3", "TLSv1.2"],
            INSECURE=True,
        )
    assert code == 0
    result = report["results"][0]
    assert result["protocols"][0]["outcome"] == "not_negotiated"
    assert result["protocols"][1]["outcome"] == "negotiated"
    assert result["verification"] == "skipped"
    assert "certificate_trust" not in {finding["kind"] for finding in report["findings"]}


def test_certificate_hostname_matching_uses_sans(certificate):
    cert, _ = certificate
    der = cert.public_bytes(serialization.Encoding.DER)
    assert certificate_details(der, "localhost")["hostname_covered"]
    assert not certificate_details(der, "fieldkit-local-test")["hostname_covered"]
    assert hostname_matches("api.example.test", ["*.example.test"], [])
    assert not hostname_matches("deep.api.example.test", ["*.example.test"], [])
    assert not hostname_matches("example.test", ["*.example.test"], [])


def test_tls_http_targets_are_skipped(tmp_path):
    with local_server() as (url, requests):
        code, report, _ = run(TLSReview(), tmp_path, url)
    assert code == 0
    assert report["results"][0]["outcome"] == "skipped_non_https"
    assert requests == []


@pytest.mark.parametrize(
    "settings",
    [{"WIDTH": 319}, {"WIDTH": 3841}, {"HEIGHT": 199}, {"HEIGHT": 2161}, {"MAX_PAGES": 0}],
)
def test_snapshot_validates_viewport_and_page_limit(settings):
    module = Snapshot()
    values = module.defaults()
    values.update(SCREENSHOT=False, **settings)
    with pytest.raises(ValueError):
        module.validate(values)


def test_snapshot_metadata_only_includes_redirects_and_escaped_gallery(tmp_path):
    routes = {
        "/": (302, {"Location": "/landing"}, b""),
        "/landing": (
            200,
            {"Content-Type": "text/html"},
            b"<title>Inventory &amp; &lt;script&gt;</title><h1>Local application</h1>",
        ),
    }
    with local_server(routes) as (url, requests):
        code, report, directory = run(Snapshot(), tmp_path, url, SCREENSHOT=False)
    assert code == 0
    assert requests == [("GET", "/"), ("GET", "/landing")]
    result = report["results"][0]
    assert result["title"] == "Inventory & <script>"
    assert result["final_url"] == url + "/landing"
    assert result["redirects"] == [{"url": url + "/", "status": 302}]
    assert "screenshot" not in result
    gallery = (directory / "gallery.html").read_text()
    assert "Inventory &amp; &lt;script&gt;" in gallery
    assert "<p>No screenshot</p>" in gallery
    assert "<script>" not in gallery
    assert len(report["evidence"]) == 1


def require_chromium():
    playwright = pytest.importorskip("playwright.sync_api", reason="Optional browser extra absent")
    with playwright.sync_playwright() as manager:
        if not Path(manager.chromium.executable_path).exists():
            pytest.skip("Optional Chromium browser has not been installed")


def test_snapshot_real_chromium_png_gallery_and_network_controls(tmp_path):
    require_chromium()
    with local_server(
        {
            "/external.js": (
                200,
                {"Content-Type": "application/javascript"},
                b"document.title='external';",
            )
        }
    ) as (external_url, external_requests):
        body = (
            "<!doctype html><html><head><title>Fieldkit browser test</title>"
            "<style>body{font:24px system-ui;background:#153048;color:white;padding:48px}</style>"
            f'<script src="{external_url}/external.js"></script>'
            '<script src="/app.js"></script></head><body><h1>Local snapshot</h1>'
            "<p>Browser capture through shared scoped HTTP transport.</p></body></html>"
        ).encode()
        routes = {
            "/": (200, {"Content-Type": "text/html"}, body),
            "/app.js": (
                200,
                {"Content-Type": "application/javascript"},
                b"document.title='Rendered local title'; "
                b"fetch('/write',{method:'POST',body:'blocked'}).catch(()=>{});",
            ),
        }
        with local_server(routes) as (url, requests):
            code, report, directory = run(Snapshot(), tmp_path, url, WIDTH=960, HEIGHT=540)
    assert code == 0, report["errors"]
    result = report["results"][0]
    assert result["rendered_title"] == "Rendered local title"
    assert external_requests == []
    assert not any(method == "POST" for method, _ in requests)
    assert ("GET", "/app.js") in requests
    assert requests.count(("GET", "/")) == 2  # Metadata request and routed browser navigation.
    blocked = {(entry["method"], entry["url"]) for entry in result["blocked_browser_requests"]}
    assert ("GET", external_url + "/external.js") in blocked
    assert ("POST", url + "/write") in blocked
    png_path = directory / result["screenshot"]
    png = png_path.read_bytes()
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert struct.unpack(">II", png[16:24]) == (960, 540)
    assert result["screenshot"] in (directory / "gallery.html").read_text()
    assert len(report["evidence"]) >= 3
    evidence_urls = [entry["url"] for entry in report["evidence"]]
    assert url + "/app.js" in evidence_urls
    assert external_url + "/external.js" not in evidence_urls
    assert png_path.stat().st_mode & 0o777 == 0o600
