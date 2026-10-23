"""Regressions for imported formats and collector resource boundaries."""

import asyncio
import io
import json
import os
import shutil
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from rich.console import Console
from test_local_capabilities import run_local
from test_replay_checks import network_run
from test_tool_soap_capabilities import TEMPLATE, template_file, wsdl

from fieldkit.core.local_worker import candidates, regular_read
from fieldkit.core.process import ProcessResult, run_process
from fieldkit.core.xml import parse_xml
from fieldkit.modules.linux import ExposureAudit
from fieldkit.modules.nmap_import import NmapImport, read_bounded
from fieldkit.modules.nuclei import Nuclei, review_template
from fieldkit.modules.soap_inventory import SOAPInventory


def test_no_follow_reads_reject_ancestor_link_outside_explicit_roots(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "config.txt").write_text("password=outside-fixture-secret")
    (root / "directory").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="leaves explicit roots"):
        regular_read(root / "directory" / "config.txt", 1000, boundaries=(root,))


def test_extraction_stays_within_remaining_aggregate_limit(tmp_path):
    archive = tmp_path / "container.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("large.env", "password=bounded-secret\n" + "X" * 20000)
    aggregate = archive.stat().st_size + 64
    code, report, _ = run_local(
        ExposureAudit(),
        tmp_path,
        ROOTS=[str(archive)],
        ARCHIVES=True,
        MAX_TOTAL_BYTES=aggregate,
        MAX_EXTRACT_BYTES=10000,
    )
    assert code == 1 and any(e["error"] == "extraction_limit" for e in report["errors"])
    summary = next(r for r in report["results"] if r["kind"] == "filesystem_summary")
    assert summary["bytes_read"] <= aggregate


def test_private_raw_duplicate_archive_names_preserve_each_content(tmp_path):
    records = []
    config = {"raw_dir": str(tmp_path)}
    path = tmp_path / "archive.zip"
    first, second = b"password=first-fixture", b"password=second-fixture"
    candidates(path, first, config, "duplicate.env", sink=records.append)
    candidates(path, second, config, "duplicate.env", sink=records.append)
    candidates(path, first, config, "duplicate.env", sink=records.append)
    assert len(list(tmp_path.glob("*.bin"))) == 2
    assert {p.read_bytes() for p in tmp_path.glob("*.bin")} == {first, second}
    assert len([r for r in records if r["kind"] == "private_raw"]) == 3


def test_xml_namespace_mappings_share_unchanged_scopes_and_keep_overrides():
    body = b'<a xmlns:p="urn:parent"><b/><c xmlns:p="urn:child"><d/></c><e/></a>'
    root, namespaces = parse_xml(body)
    assert namespaces[id(root)] is namespaces[id(root[0])]
    assert namespaces[id(root)] is namespaces[id(root[2])]
    assert namespaces[id(root[1])]["p"] == "urn:child"
    assert namespaces[id(root[1][0])]["p"] == "urn:child"
    assert namespaces[id(root)]["p"] == "urn:parent"


@pytest.mark.parametrize("nonregular", ["fifo", "directory"])
def test_offline_import_rejects_nonregular_inputs_without_blocking(tmp_path, nonregular):
    path = tmp_path / nonregular
    if nonregular == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises((ValueError, OSError)):
        read_bounded(path, 1000)


@pytest.mark.parametrize("address", ["", 'addr="outside.example/path"'])
def test_nmap_malformed_address_is_not_promoted_to_an_endpoint(tmp_path, address):
    path = tmp_path / "nmap.xml"
    path.write_text(
        f'<nmaprun><host><address addrtype="ipv4" {address}/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host>'
        '<runstats><finished exit="success"/></runstats></nmaprun>'
    )
    code, report, _ = run_local(NmapImport(), tmp_path, INPUT=str(path))
    assert code == 1 and not report["completed"] and not report["endpoints"]
    assert report["errors"][0]["error"] == "invalid_nmap_address"
    assert report["results"][0]["ports"][0]["port"] == "80"


@pytest.mark.parametrize(
    "text",
    [
        TEMPLATE.replace("method: GET", "method: [GET]"),
        TEMPLATE.replace('path: ["{{BaseURL}}/login"]', "path: [42]"),
        TEMPLATE.replace(
            "type: word\n        words: [FixtureProduct]", "type: dsl\n        dsl: 7"
        ),
        TEMPLATE.replace(
            "type: word\n        words: [FixtureProduct]", "type: dsl\n        dsl: [42]"
        ),
    ],
)
def test_malformed_nuclei_fields_are_validation_errors(tmp_path, text):
    with pytest.raises(ValueError):
        review_template(template_file(tmp_path, text), execute=True)


def test_nuclei_static_path_count_is_bounded(tmp_path):
    text = TEMPLATE.replace('["{{BaseURL}}/login"]', json.dumps(["{{BaseURL}}/fixture"] * 101))
    with pytest.raises(ValueError, match="bounded"):
        review_template(template_file(tmp_path, text), execute=True)


def test_nuclei_deeply_nested_jsonl_preserves_following_valid_result(tmp_path, monkeypatch):
    path = tmp_path / "nuclei.jsonl"
    valid = {"template-id": "fixture", "host": "https://lab.test/"}
    path.write_text("[" * 1500 + "0" + "]" * 1500 + "\n" + json.dumps(valid) + "\n")
    code, report, _, _ = network_run(
        Nuclei(),
        tmp_path,
        monkeypatch,
        lambda r: pytest.fail("JSONL import must make no requests"),
        INPUT=str(path),
        IMPORT_COMPLETE=True,
    )
    assert code == 1 and not report["completed"]
    assert len(report["findings"]) == 1 and report["errors"][0]["error"] == "malformed_jsonl"


def test_soap_good_documents_survive_missing_input(tmp_path, monkeypatch):
    valid = tmp_path / "valid.wsdl"
    valid.write_bytes(wsdl())
    code, report, directory, seen = network_run(
        SOAPInventory(),
        tmp_path,
        monkeypatch,
        lambda r: pytest.fail("Offline SOAP import must make no requests"),
        WSDL_FILES=[str(tmp_path / "missing.wsdl"), str(valid)],
        TARGETS=[],
    )
    assert code == 1 and not report["completed"] and not seen
    assert report["errors"][0]["error"] == "wsdl_read_error"
    assert report["soap_summary"]["operations"] == 1
    assert len(json.loads((directory / "request-templates.json").read_text())) == 1


def test_soap_unsuccessful_http_input_reports_incomplete_coverage(tmp_path, monkeypatch):
    code, report, _, _ = network_run(
        SOAPInventory(), tmp_path, monkeypatch, lambda r: httpx.Response(404)
    )
    assert code == 1 and not report["completed"]
    assert report["errors"][0]["error"] == "wsdl_fetch_error"


def test_soap_document_ceiling_preserves_first_document_and_marks_partial(tmp_path, monkeypatch):
    paths = []
    for number in range(2):
        path = tmp_path / f"document-{number}.wsdl"
        path.write_bytes(wsdl())
        paths.append(str(path))
    code, report, _, _ = network_run(
        SOAPInventory(),
        tmp_path,
        monkeypatch,
        lambda r: pytest.fail("Offline SOAP import must make no requests"),
        WSDL_FILES=paths,
        TARGETS=[],
        MAX_DOCUMENTS=1,
    )
    assert code == 1 and not report["completed"]
    assert report["soap_summary"]["operations"] == 1
    assert report["errors"][0]["error"] == "wsdl_document_limit"


def test_process_callback_error_preserves_output_and_failure_reason():
    result = ProcessResult()

    def reject(_chunk):
        raise ValueError("fixture output handler")

    async def invoke():
        with pytest.raises(ValueError, match="fixture output handler"):
            await run_process(
                [sys.executable, "-c", "print('partial fixture',flush=True)"],
                on_stdout=reject,
                result=result,
            )

    asyncio.run(invoke())
    assert result.reason == "output_handler_error" and b"partial fixture" in result.stdout
    assert result.returncode is not None


@pytest.mark.skipif(not shutil.which("nuclei"), reason="Operator-installed Nuclei unavailable")
def test_real_nuclei_selected_static_template_only_hits_local_loopback(tmp_path):
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            body = b"FixtureProduct"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    module = Nuclei()
    settings = {
        **module.defaults(),
        "OUTPUT": str(tmp_path / "runs"),
        "TARGETS": [f"http://127.0.0.1:{server.server_port}/"],
        "EXECUTE": True,
        "TEMPLATES": [template_file(tmp_path)],
        "RATE": 10,
        "BUDGET": 30,
    }
    try:
        assert module.run(settings, Console(file=io.StringIO())) == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    report = json.loads(next((tmp_path / "runs").glob("*/report.json")).read_text())
    assert report["findings"][0]["kind"] == "nuclei_surface_match"
    assert paths and set(paths) <= {"/login"}
