"""Stored-content workflows against local HTTP and actual optional Chromium."""

import hashlib
import html
import io
import json
import re
import stat
import threading
import time
from types import SimpleNamespace
from urllib.request import Request, urlopen

import pytest
from rich.console import Console
from test_live_capabilities import application
from test_platform_modules import require_chromium

from fieldkit.core.browser_proof import BrowserProof
from fieldkit.modules.stored_xss import StoredXSS, extract_identifier


def workflow_file(tmp_path, *, source="json", url="/ticket/{{ticket_id}}"):
    path = tmp_path / "workflow.json"
    extraction = (
        {"source": "json", "pointer": "/ticket_id", "public": True}
        if source == "json"
        else {"source": "location", "part": "query", "name": "id", "public": True}
    )
    path.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "id": "submit",
                        "request": {
                            "method": "POST",
                            "url": "/support",
                            "form": {"name": "Fieldkit canary", "body": "{{payload}}"},
                        },
                        "expect": {"statuses": [201, 303]},
                        "extract": {"ticket_id": extraction},
                    }
                ],
                "browser": {"url": url},
            }
        )
    )
    return path


def run(module, tmp_path, target, workflow, **options):
    settings = {
        **module.defaults(),
        "TARGETS": [target],
        "RATE": 0,
        "RETRIES": 0,
        "OUTPUT": str(tmp_path / "runs"),
        "TIMEOUT": 5,
        "REVIEW_WAIT": 0,
        "BROWSER_WAIT": 0.1,
        "CONFIRM_SUBMISSION": True,
        "WORKFLOW_FILE": str(workflow),
        **options,
    }
    code = module.run(settings, Console(file=io.StringIO()))
    path = max((tmp_path / "runs").glob("*/report.json"), key=lambda p: p.stat().st_mtime_ns)
    return code, json.loads(path.read_text()), path.parent


def assert_evidence_checksums(report, root):
    for entry in report["evidence"]:
        if "sha256" in entry:
            data = (root / entry["file"]).read_bytes()
            assert entry["bytes"] == len(data)
            assert entry["sha256"] == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("rendering", ["execute", "escaped", "wrong-proof"])
def test_native_browser_distinguishes_execution_escaped_and_wrong_proof(tmp_path, rendering):
    require_chromium()
    from urllib.parse import parse_qs

    saved = {}

    def handler(method, path, headers, body):
        if method == "POST":
            saved["payload"] = parse_qs(body.decode())["body"][0]
            return 201, {"Content-Type": "application/json"}, b'{"ticket_id":"7"}'
        payload = saved.get("payload", "")
        if rendering == "escaped":
            payload = html.escape(payload)
        elif rendering == "wrong-proof":
            payload = payload.replace("fieldkit-execution-", "wrong-fieldkit-execution-")
        return (
            200,
            {"Content-Type": "text/html"},
            ("<html><body>" + payload + "</body></html>").encode(),
        )

    with application(handler) as (target, seen):
        code, report, root = run(StoredXSS(), tmp_path, target, workflow_file(tmp_path))
    assert code == 0
    record = report["results"][0]
    assert record["identifiers"] == {"ticket_id": "7"}
    assert record["browser"]["marker_present_in_document"] is True
    assert record["browser"]["outcome"] == (
        "confirmed" if rendering == "execute" else "not_observed"
    )
    assert record["external_callback"]["outcome"] == "not_observed"
    assert record["external_callback"]["staff_identity_verified"] is False
    assert bool(report["findings"]) == (rendering == "execute")
    assert [entry[0] for entry in seen] == ["POST", "GET"]
    assert (root / "private-raw/workflow-variables.json").exists()
    assert stat.S_IMODE((root / "private-raw/workflow-variables.json").stat().st_mode) == 0o600
    assert (root / "private-raw/xss-browser.png").exists()
    public = (root / "report.json").read_text() + "".join(
        p.read_text() for p in (root / "evidence").glob("*.json")
    )
    assert saved["payload"] not in public
    assert "fieldkit-execution-" not in public
    assert_evidence_checksums(report, root)
    if rendering == "execute":
        assert record["browser"]["execution_events"][0]["forwarded_to_listener"] is False


def test_location_ticket_capture_and_external_callback_without_claiming_staff_identity(tmp_path):
    from urllib.parse import parse_qs

    workers, callbacks = [], []

    def handler(method, path, headers, body):
        payload = parse_qs(body.decode())["body"][0]
        callback_url = json.loads(re.search(r"fetch\((\"[^\"]+\")", payload)[1])
        proof = json.loads(re.search(r"body:(\"[^\"]+\")", payload)[1])

        def delayed_receipt():
            time.sleep(0.05)
            with urlopen(
                Request(callback_url, method="POST", data=proof.encode()), timeout=3
            ) as response:
                callbacks.append(response.status)

        thread = threading.Thread(target=delayed_receipt, daemon=True)
        workers.append(thread)
        thread.start()
        return 303, {"Location": "/ticket?id=42"}, b""

    with application(handler) as (target, seen):
        code, report, root = run(
            StoredXSS(),
            tmp_path,
            target,
            workflow_file(tmp_path, source="location"),
            BROWSER=False,
            REVIEW_WAIT=1,
        )
    for worker in workers:
        worker.join(3)
    assert callbacks == [204]
    assert code == 0
    record = next(item for item in report["results"] if item["kind"] == "stored-xss-workflow")
    assert record["identifiers"] == {"ticket_id": "42"}
    assert record["outcome"] == "callback_observed"
    assert record["browser"]["outcome"] == "not_run"
    assert record["external_callback"]["staff_identity_verified"] is False
    assert report["findings"][0]["kind"] == "callback-observed"
    assert len(seen) == 1  # The POST redirect was used for extraction, not followed.
    assert (root / record["receipts_file"]).exists()
    assert_evidence_checksums(report, root)


def test_browser_request_limit_is_inconclusive_and_blocks_proof(tmp_path):
    require_chromium()
    from urllib.parse import parse_qs

    saved = {}

    def handler(method, path, headers, body):
        if method == "POST":
            saved["payload"] = parse_qs(body.decode())["body"][0]
            return 201, {"Content-Type": "application/json"}, b'{"ticket_id":"7"}'
        return 200, {"Content-Type": "text/html"}, saved["payload"].encode()

    with application(handler) as (target, seen):
        code, report, root = run(
            StoredXSS(), tmp_path, target, workflow_file(tmp_path), MAX_BROWSER_REQUESTS=1
        )
    record = report["results"][0]
    assert code == 1 and report["completed"] is False
    assert record["outcome"] == record["browser"]["outcome"] == "inconclusive"
    assert record["browser"]["request_limit_reached"] is True
    assert not record["browser"]["execution_events"] and not report["findings"]
    assert any(error["error"] == "browser_request_limit" for error in report["errors"])
    assert [entry[0] for entry in seen] == ["POST", "GET"]
    assert_evidence_checksums(report, root)


def test_browser_preflight_failure_does_not_submit(tmp_path, monkeypatch):
    async def fail(_self):
        raise ValueError("Chromium unavailable")

    monkeypatch.setattr(BrowserProof, "start", fail)
    with application(lambda *_: (200, {}, b"")) as (target, seen):
        code, report, _ = run(StoredXSS(), tmp_path, target, workflow_file(tmp_path))
    assert code == 1
    assert seen == []
    assert report["completed"] is False


def test_out_of_scope_browser_stops_before_submission(tmp_path):
    with application(lambda *_: (200, {}, b"")) as (target, seen):
        code, report, _ = run(
            StoredXSS(),
            tmp_path,
            target,
            workflow_file(tmp_path, url="https://outside.invalid/ticket"),
            BROWSER=False,
        )
    assert code == 1 and seen == []
    assert report["errors"][0]["error"] == "workflow_failed"


def test_explicit_dry_run_neither_listens_nor_submits(tmp_path, monkeypatch):
    from fieldkit.core.callbacks import CallbackCollector

    async def unexpected(*_args, **_kwargs):
        raise AssertionError("Dry run must not listen or launch Chromium")

    monkeypatch.setattr(CallbackCollector, "start", unexpected)
    monkeypatch.setattr(BrowserProof, "start", unexpected)
    with application(lambda *_: (200, {}, b"")) as (target, seen):
        code, report, _ = run(
            StoredXSS(),
            tmp_path,
            target,
            workflow_file(tmp_path),
            DRY_RUN=True,
            CONFIRM_SUBMISSION=False,
        )
    assert code == 0 and seen == []
    assert report["plan"]["network_requests"] == 0


@pytest.mark.parametrize(
    "case",
    ["authority", "proof-url", "missing-payload", "no-confirm", "too-many", "reserved-variable"],
)
def test_invalid_workflow_does_not_start_anything(tmp_path, case):
    path = workflow_file(tmp_path)
    document = json.loads(path.read_text())
    settings = {**StoredXSS().defaults(), "WORKFLOW_FILE": str(path), "CONFIRM_SUBMISSION": True}
    if case == "authority":
        document["browser"]["url"] = "https://{{ticket_id}}/"
    elif case == "proof-url":
        document["browser"]["url"] = "/ticket?payload={{payload}}"
    elif case == "missing-payload":
        document["steps"][0]["request"]["form"]["body"] = "ordinary content"
    elif case == "no-confirm":
        settings["CONFIRM_SUBMISSION"] = False
    elif case == "too-many":
        settings["MAX_STEPS"] = 101
    else:
        document["variables"] = {"proof": "not-allowed"}
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        StoredXSS().validate(settings)


def test_identifier_sources_and_ambiguous_location_rejected():
    response = SimpleNamespace(
        url="https://lab.test/support",
        headers={"x-ticket-id": "t7", "location": "/tickets/42?id=8"},
        body=b'{"ticket_id":42}',
    )
    assert extract_identifier(response, {"source": "header", "name": "X-Ticket-ID"}) == "t7"
    assert extract_identifier(response, {"source": "location", "part": "path", "index": -1}) == "42"
    assert extract_identifier(response, {"source": "location", "name": "id"}) == "8"
    response.headers["location"] = "/tickets?id=1&id=2"
    with pytest.raises(ValueError, match="exactly one"):
        extract_identifier(response, {"source": "location", "name": "id"})
