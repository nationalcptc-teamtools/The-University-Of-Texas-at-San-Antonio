"""False-positive controls and scoped replay/session authorization fixtures."""

import io
import json
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

import httpx
import pytest
from rich.console import Console

from fieldkit.cli import main
from fieldkit.console import InteractiveConsole
from fieldkit.core.replay import edit_request, load_requests, raw_request
from fieldkit.modules.auth_matrix import AuthMatrix
from fieldkit.modules.injection import SQLiCheck, SSRFCheck, XXECheck
from fieldkit.modules.request_replay import RequestReplay
from fieldkit.modules.session_workflow import BrowserLogin, SessionWorkflow
from fieldkit.registry import modules


def write_json(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value))
    return str(path)


def network_run(module, tmp_path, monkeypatch, handler, **overrides):
    real_client = httpx.AsyncClient
    seen = []

    async def tracked(request):
        seen.append(request)
        value = handler(request)
        if hasattr(value, "__await__"):
            value = await value
        return value

    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(tracked), **kw),
    )
    settings = {
        **module.defaults(),
        "TARGETS": ["https://lab.test"],
        "RATE": 0,
        "RETRIES": 0,
        "OUTPUT": str(tmp_path / "runs"),
        **overrides,
    }
    code = module.run(settings, Console(file=io.StringIO()))
    report_file = max((tmp_path / "runs").glob("*/report.json"), key=lambda p: p.stat().st_mtime_ns)
    return code, json.loads(report_file.read_text()), report_file.parent, seen


def request_file(tmp_path, request=None):
    return write_json(
        tmp_path,
        "requests.json",
        {
            "requests": [
                request
                or {
                    "id": "test",
                    "url": "https://lab.test/item",
                    "method": "POST",
                    "json": {"id": "1"},
                }
            ]
        },
    )


def test_replay_request_edits_profiles_controls_and_redaction(tmp_path, monkeypatch):
    requests = request_file(
        tmp_path,
        {
            "id": "test",
            "url": "/item?count=1",
            "method": "POST",
            "profile": "alice",
            "query": {"q": "hello"},
            "headers": {"X-Check": "control"},
            "cookies": {"custom": "cookie-private-value"},
            "json": {"id": "1", "password": "body-private-value"},
        },
    )
    profiles = write_json(
        tmp_path,
        "profiles.json",
        {
            "profiles": {
                "alice": {
                    "origins": ["https://lab.test"],
                    "headers": {"Authorization": "Bearer auth-private-value"},
                }
            }
        },
    )
    edits = write_json(
        tmp_path,
        "edits.json",
        [{"location": "json:/id", "value": "2"}, {"location": "header:X-Check", "value": "edited"}],
    )
    controls = write_json(
        tmp_path,
        "control.json",
        [{"id": "test", "url": "/item", "method": "POST", "json": {"id": "0"}}],
    )
    code, report, directory, seen = network_run(
        RequestReplay(),
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(422, json={"body": req.content.decode()}),
        REQUESTS_FILE=requests,
        REQUEST_IDS=["test"],
        EDITS_FILE=edits,
        CONTROL_FILE=controls,
        PROFILES_FILE=profiles,
    )
    assert code == 0 and len(seen) == 3
    assert json.loads(seen[1].content)["id"] == "2" and seen[1].headers["X-Check"] == "edited"
    assert seen[0].url.params["q"] == "hello" and seen[0].url.params["count"] == "1"
    assert report["results"][0]["outcome"] == "observed"  # HTTP errors are responses.
    saved = "".join(p.read_text() for p in directory.rglob("*.json"))
    assert not any(
        v in saved for v in ("body-private-value", "auth-private-value", "cookie-private-value")
    )


def test_replay_requires_selection_and_validates_all_scope_before_execution(tmp_path, monkeypatch):
    path = request_file(tmp_path)
    with pytest.raises(ValueError, match="selection"):
        network_run(
            RequestReplay(),
            tmp_path,
            monkeypatch,
            lambda r: httpx.Response(200),
            REQUESTS_FILE=path,
        )
    path = write_json(
        tmp_path,
        "outside.json",
        [
            {"id": "good", "url": "https://lab.test/post", "method": "POST"},
            {"id": "bad", "url": "https://outside.test/post", "method": "POST"},
        ],
    )
    seen = []
    with pytest.raises(ValueError, match="scope"):
        network_run(
            RequestReplay(),
            tmp_path,
            monkeypatch,
            lambda r: seen.append(r) or httpx.Response(200),
            REQUESTS_FILE=path,
            REQUEST_IDS=["good", "bad"],
        )
    assert not seen


def test_raw_format_forms_json_xml_and_fieldkit_templates(tmp_path):
    request = raw_request(
        "POST /form?q=1 HTTP/1.1\r\nHost: lab.test\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\nx=one&password=two",
        "https://lab.test",
    )
    assert request["form"]["x"] == "one"
    assert edit_request(request, "form:x", "edited")["form"]["x"] == "edited"
    request = raw_request(
        "POST https://lab.test/xml HTTP/1.1\nHost: lab.test\n"
        "Content-Type: application/xml\n\n<r><a>one</a></r>",
        "",
    )
    assert "edited" in edit_request(request, "xml:a", "edited")["xml"]
    path = write_json(
        tmp_path,
        "request-templates.json",
        [
            {
                "method": "GET",
                "url": "https://lab.test/api",
                "query": {"id": "<VALUE>"},
                "body": None,
                "executed": False,
            }
        ],
    )
    assert load_requests(path)[0]["id"] == "1"


@pytest.mark.parametrize(
    "raw",
    [
        "GET / HTTP/1.1\nHost: other.test\n\n",
        "GET / HTTP/1.1\nHost: lab.test\nTransfer-Encoding: chunked\n\n0\n",
        "GET / HTTP/1.1\nHost: lab.test\nX-Test: a\nX-Test: b\n\n",
        "POST / HTTP/1.1\nHost: lab.test\nContent-Length: 99\n\nsmall",
    ],
)
def test_raw_ambiguous_headers_are_rejected(raw):
    with pytest.raises(ValueError):
        raw_request(raw, "https://lab.test")


def test_selected_locations_reject_ambiguity_and_unknown_fields():
    with pytest.raises(ValueError, match="Ambiguous"):
        edit_request({"url": "https://lab.test/?id=1&id=2"}, "query:id", "3")
    with pytest.raises(ValueError, match="does not exist"):
        edit_request({"url": "https://lab.test/", "json": {"a": []}}, "json:/bad", "3")
    with pytest.raises(ValueError, match="exactly one"):
        edit_request({"url": "https://lab.test/", "xml": "<r><a/><a/></r>"}, "xml:a", "3")


def test_ssrf_reflection_without_receipt_is_unconfirmed(tmp_path, monkeypatch):
    code, report, _, seen = network_run(
        SSRFCheck(),
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200, content=req.content),
        REQUESTS_FILE=request_file(tmp_path),
        REQUEST_IDS=["test"],
        LOCATIONS=["json:/id"],
        CALLBACK_URL="https://callback.test/receipts",
    )
    assert code == 0 and len(seen) == 3
    assert report["results"][0]["outcome"] == "inconclusive" and not report["findings"]


@pytest.mark.parametrize("stale", [False, True])
def test_ssrf_receipts_require_actual_id_url_time_correlation(tmp_path, monkeypatch, stale):
    receipts = tmp_path / "receipts.json"

    def handler(request):
        value = json.loads(request.content)["id"]
        if value.startswith("https://callback.test/"):
            stamp = datetime.now(UTC) - (timedelta(days=1) if stale else timedelta())
            receipts.write_text(
                json.dumps(
                    {
                        "receipts": [
                            {
                                "callback_id": value.rsplit("/", 1)[-1],
                                "url": value,
                                "source": "fixture listener",
                                "method": "GET",
                                "received_at": stamp.isoformat(),
                            }
                        ]
                    }
                )
            )
        return httpx.Response(500, text="Application error")

    code, report, _, _ = network_run(
        SSRFCheck(),
        tmp_path,
        monkeypatch,
        handler,
        REQUESTS_FILE=request_file(tmp_path),
        REQUEST_IDS=["test"],
        LOCATIONS=["json:/id"],
        CALLBACK_URL="https://callback.test",
        RECEIPTS_FILE=str(receipts),
    )
    assert code == 0
    assert report["results"][0]["outcome"] == ("inconclusive" if stale else "confirmed")
    if not stale:
        finding = report["findings"][0]
        assert any(e.startswith("callback-evidence") for e in finding["evidence"])


def test_xxe_internal_reflection_is_not_external_confirmation(tmp_path, monkeypatch):
    path = request_file(
        tmp_path,
        {"id": "test", "url": "/xml", "method": "POST", "xml": "<r><field>one</field></r>"},
    )

    def handler(request):
        text = request.content.decode()
        match = re.search(r'<!ENTITY fieldkit "([^"]+)"', text)
        return httpx.Response(200, text=match[1] if match else text)

    _, report, _, _ = network_run(
        XXECheck(),
        tmp_path,
        monkeypatch,
        handler,
        REQUESTS_FILE=path,
        REQUEST_IDS=["test"],
        LOCATIONS=["xml:field"],
        CALLBACK_URL="https://callback.test",
    )
    result = report["results"][0]
    assert result["internal_entity_reflection"] and result["outcome"] == "observed"
    assert all(f["confidence"] != "confirmed" for f in report["findings"])


def test_xxe_external_marker_and_unsupported_location(tmp_path, monkeypatch):
    path = request_file(
        tmp_path,
        {"id": "test", "url": "/xml", "method": "POST", "xml": "<r><field>one</field></r>"},
    )

    def handler(request):
        return httpx.Response(
            200, text="external-only-fixture" if b"SYSTEM" in request.content else "control"
        )

    _, report, _, _ = network_run(
        XXECheck(),
        tmp_path,
        monkeypatch,
        handler,
        REQUESTS_FILE=path,
        REQUEST_IDS=["test"],
        LOCATIONS=["xml:field", "query:unknown"],
        CALLBACK_URL="https://callback.test",
        ENTITY_MARKER="external-only-fixture",
    )
    assert {r["outcome"] for r in report["results"]} == {"unsupported", "confirmed"}


def test_sqli_error_and_boolean_controls_not_http_status(tmp_path, monkeypatch):
    def handler(request):
        field = json.loads(request.content)["id"]
        if field == "'":
            return httpx.Response(500, text="You have an error in your SQL syntax")
        return httpx.Response(
            200, json={"result": "known-resource" if field != "1' AND '1'='2" else "empty"}
        )

    _, report, _, seen = network_run(
        SQLiCheck(),
        tmp_path,
        monkeypatch,
        handler,
        REQUESTS_FILE=request_file(tmp_path),
        REQUEST_IDS=["test"],
        LOCATIONS=["json:/id"],
        TRUE_MARKER="known-resource",
    )
    result = report["results"][0]
    assert (
        len(seen) == 7
        and result["sql_error_observed"]
        and result["repeatable_boolean_marker_difference"]
    )
    assert result["outcome"] == "observed"


@pytest.mark.parametrize("transport_failure", [False, True])
def test_sqli_generic_errors_and_transport_failures_are_inconclusive(
    tmp_path, monkeypatch, transport_failure
):
    def handler(request):
        if transport_failure:
            raise httpx.ConnectError("fixture unavailable")
        return httpx.Response(500, text="Error; unknown input")

    _, report, _, _ = network_run(
        SQLiCheck(),
        tmp_path,
        monkeypatch,
        handler,
        REQUESTS_FILE=request_file(tmp_path),
        REQUEST_IDS=["test"],
        LOCATIONS=["json:/id"],
    )
    assert report["results"][0]["outcome"] == "inconclusive" and not report["findings"]


def matrix_file(tmp_path):
    return write_json(
        tmp_path,
        "matrix.json",
        {
            "identities": {"owner": "owner-profile", "other": "other-profile", "missing": "absent"},
            "objects": [
                {
                    "id": "invoice",
                    "owner": "owner",
                    "request": {"url": "/invoice"},
                    "checks": {"json_pointer": "/invoice/id", "equals": "owned-42"},
                }
            ],
            "functions": [
                {
                    "id": "admin",
                    "request": {"url": "/admin"},
                    "checks": {"contains": "Admin function data"},
                }
            ],
            "rules": [
                {"id": "owner", "identity": "owner", "resource": "invoice", "expected": "allow"},
                {"id": "other", "identity": "other", "resource": "invoice", "expected": "deny"},
                {"id": "missing", "identity": "missing", "resource": "invoice", "expected": "deny"},
                {"id": "function", "identity": "other", "resource": "admin", "expected": "deny"},
            ],
        },
    )


@pytest.mark.parametrize("leak", [False, True])
def test_auth_matrix_specific_resource_rules_and_missing_sessions(tmp_path, monkeypatch, leak):
    profiles = write_json(
        tmp_path,
        "profiles.json",
        {
            "profiles": {
                n: {"origins": ["https://lab.test"], "cookies": {"sid": n}}
                for n in ["owner-profile", "other-profile"]
            }
        },
    )

    def handler(request):
        if request.url.path == "/admin":
            return httpx.Response(403, text="Forbidden")
        if "owner-profile" in request.headers.get("cookie", "") or leak:
            return httpx.Response(200, json={"invoice": {"id": "owned-42"}})
        return httpx.Response(200, json={"common_page": "Login required"})

    _, report, _, seen = network_run(
        AuthMatrix(),
        tmp_path,
        monkeypatch,
        handler,
        MATRIX_FILE=matrix_file(tmp_path),
        PROFILES_FILE=profiles,
    )
    assert len(seen) == 3
    assert (
        next(r for r in report["results"] if r["rule_id"] == "missing")["outcome"] == "inconclusive"
    )
    assert (
        next(r for r in report["results"] if r["rule_id"] == "function")["outcome"]
        == "expected_deny"
    )
    assert bool(report["findings"]) == leak
    if leak:
        assert report["findings"][0]["outcome"] == "confirmed"


def workflow_file(tmp_path):
    return write_json(
        tmp_path,
        "workflow.json",
        {
            "variables": {"user": "example-user", "pwd": "workflow-private-password"},
            "steps": [
                {
                    "id": "token",
                    "request": {"url": "/login"},
                    "expect": {"statuses": [200]},
                    "extract": {
                        "csrf": {
                            "source": "html",
                            "tag": "input",
                            "match": {"name": "csrf"},
                            "attribute": "value",
                        }
                    },
                },
                {
                    "id": "login",
                    "request": {
                        "url": "/login",
                        "method": "POST",
                        "form": {"user": "{{user}}", "credential": "{{pwd}}", "csrf": "{{csrf}}"},
                    },
                    "expect": {"statuses": [200]},
                    "extract": {"bearer": {"source": "json", "pointer": "/access/value"}},
                },
                {
                    "id": "protected",
                    "request": {
                        "url": "/account",
                        "headers": {"Authorization": "Bearer {{bearer}}"},
                    },
                    "expect": {"statuses": [200], "contains": "Known private resource"},
                },
            ],
        },
    )


def test_workflow_html_json_token_substitution_cookie_continuity_and_export(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path == "/login" and request.method == "GET":
            return httpx.Response(
                200,
                text='<form><input name="csrf" value="dynamic-private-csrf"></form>',
                headers={"Set-Cookie": "pre=private-pre-cookie; Path=/"},
            )
        if request.url.path == "/login":
            fields = parse_qs(request.content.decode())
            assert fields["csrf"] == ["dynamic-private-csrf"] and fields["credential"] == [
                "workflow-private-password"
            ]
            assert "private-pre-cookie" in request.headers["cookie"]
            return httpx.Response(
                200,
                json={"access": {"value": "dynamic-private-bearer"}},
                headers={"Set-Cookie": "sid=private-session-cookie; Path=/; Secure"},
            )
        assert request.headers["Authorization"] == "Bearer dynamic-private-bearer"
        assert "private-session-cookie" in request.headers["Cookie"]
        return httpx.Response(200, text="Known private resource")

    code, report, directory, seen = network_run(
        SessionWorkflow(),
        tmp_path,
        monkeypatch,
        handler,
        WORKFLOW_FILE=workflow_file(tmp_path),
        SAVE_PROFILE=True,
    )
    assert code == 0 and len(seen) == 3
    saved = "".join(
        p.read_text() for p in directory.rglob("*.json") if p.name != "private-session-profile.json"
    )
    assert not any(
        v in saved
        for v in (
            "dynamic-private-csrf",
            "dynamic-private-bearer",
            "private-session-cookie",
            "workflow-private-password",
        )
    )
    profile = directory / "private-session-profile.json"
    assert profile.stat().st_mode & 0o777 == 0o600
    from fieldkit.core.profiles import load_profiles

    jar = load_profiles(str(profile))["authenticated"].cookie_jar
    assert any(c["value"] == "private-session-cookie" and c["secure"] for c in jar)


def test_workflow_extraction_failure_stops_later_operations(tmp_path, monkeypatch):
    code, report, _, seen = network_run(
        SessionWorkflow(),
        tmp_path,
        monkeypatch,
        lambda r: httpx.Response(200, text="No dynamic token"),
        WORKFLOW_FILE=workflow_file(tmp_path),
    )
    assert code == 1 and len(seen) == 1 and report["errors"][0]["error"] == "workflow_failed"


def test_browser_missing_dependency_is_actionable_and_separate(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "fieldkit.modules.session_workflow.importlib.util.find_spec", lambda name: None
    )
    code, report, _, seen = network_run(
        BrowserLogin(),
        tmp_path,
        monkeypatch,
        lambda r: httpx.Response(200),
        LOGIN_URL="/login",
        SUCCESS_SELECTOR="#account",
    )
    assert code == 1 and not seen and "Fieldkit[browser]" in report["errors"][0]["detail"]


def test_all_new_modules_share_cli_console_registration(monkeypatch):
    names = [
        "linux/inventory",
        "linux/exposure-audit",
        "network/nmap-import",
        "web/nuclei",
        "web/request-replay",
        "web/ssrf-check",
        "web/xxe-check",
        "web/sqli-check",
        "web/soap-inventory",
        "web/auth-matrix",
        "web/session-workflow",
        "web/browser-login",
        "web/stored-xss",
        "integrations/callback-collector",
        "network/vantage",
        "database/mssql-export",
    ]
    registry = modules()
    assert len(registry) == 49 and set(names) <= registry.keys()
    for name in names:
        received = []
        monkeypatch.setattr(
            type(registry[name]),
            "run",
            lambda self, settings, console, received=received: received.append(settings) or 0,
        )
        assert main(["run", name, "--output", "example-output"]) == 0
        assert received[-1]["OUTPUT"] == "example-output"
        console = InteractiveConsole(Console(file=io.StringIO()))
        console.execute(f"use {name}")
        console.execute("set OUTPUT example-console-output")
        console.execute("run")
        assert received[-1]["OUTPUT"] == "example-console-output"
