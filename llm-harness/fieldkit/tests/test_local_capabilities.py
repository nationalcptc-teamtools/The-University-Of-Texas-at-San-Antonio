"""Bounded local collection and untrusted tool import regression coverage."""

import asyncio
import io
import json
import os
import sys
import zipfile

import pytest
from rich.console import Console

from fieldkit.core.local import LocalContext
from fieldkit.core.process import ProcessResult, run_process
from fieldkit.core.results import compare_reports, merge_reports, stable_id
from fieldkit.core.xml import parse_xml
from fieldkit.modules.linux import ExposureAudit, LinuxInventory
from fieldkit.modules.nmap_import import NmapImport
from fieldkit.modules.report_export import markdown_report


def run_local(module, tmp_path, **overrides):
    settings = {**module.defaults(), "OUTPUT": str(tmp_path / "runs"), **overrides}
    code = module.run(settings, Console(file=io.StringIO()))
    report = max((tmp_path / "runs").glob("*/report.json"), key=lambda p: p.stat().st_mtime_ns)
    return code, json.loads(report.read_text()), report.parent


def test_process_limits_and_missing_dependency():
    async def test():
        limited = await run_process(
            [sys.executable, "-c", "import os;os.write(1,b'x'*20000)"], max_output=1000, timeout=2
        )
        assert limited.reason == "output_limit" and len(limited.stdout) <= 1000
        missing = await run_process(["/nonexistent/fieldkit-tool"], timeout=1)
        assert missing.reason == "unavailable"
        stderr = await run_process(
            [sys.executable, "-c", "import os;os.write(2,b'x'*2000)"], max_output=100
        )
        assert stderr.reason == "output_limit" and len(stderr.stderr) <= 100

    asyncio.run(test())


@pytest.mark.parametrize("cancellation", ["timeout", "event", "task"])
def test_process_group_cancellation_preserves_partial_results(tmp_path, cancellation):
    marker = tmp_path / "descendant-survived"
    script = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-c',\"import time,pathlib;time.sleep(1);"
        f"pathlib.Path({str(marker)!r}).write_text('bad')\"]); "
        "print('partial-result',flush=True);time.sleep(30)"
    )

    async def test():
        result = ProcessResult()
        cancel = asyncio.Event()
        task = asyncio.create_task(
            run_process(
                [sys.executable, "-c", script],
                result=result,
                timeout=0.12 if cancellation == "timeout" else 5,
                cancel=cancel,
            )
        )
        if cancellation != "timeout":
            await asyncio.sleep(0.12)
            if cancellation == "event":
                cancel.set()
            else:
                task.cancel()
        if cancellation == "task":
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await task
        assert b"partial-result" in result.stdout
        assert result.reason == ("timeout" if cancellation == "timeout" else "cancelled")
        await asyncio.sleep(1.05)
        assert not marker.exists()

    asyncio.run(test())


def test_group_cleanup_when_parent_exits_before_descendant():
    script = (
        "import subprocess,sys;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "print('saved',flush=True)"
    )
    result = asyncio.run(run_process([sys.executable, "-c", script], timeout=0.15))
    assert result.reason == "timeout" and b"saved" in result.stdout


def test_exposure_redaction_symlinks_and_private_raw(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    (root / ".env").write_text("DB_PASSWORD=super-secret-demo\napi_key=example-key\n")
    (root / "id_rsa").write_text(
        "-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----"
    )
    (root / "skip.bak").write_text("password=excluded-value")
    outside = tmp_path / "outside.txt"
    outside.write_text("password=must-not-read")
    (root / "outside-link").symlink_to(outside)
    (root / "cycle").symlink_to(root, target_is_directory=True)
    os.mkfifo(root / "fifo")
    code, report, directory = run_local(
        ExposureAudit(),
        tmp_path,
        ROOTS=[str(root)],
        EXCLUSIONS=["skip.bak"],
        FOLLOW_SYMLINKS=True,
        RETAIN_RAW=True,
        HOST_ID="fixture-host",
    )
    assert code == 0
    assert all(f["host"] == "fixture-host" and "url" not in f for f in report["findings"])
    assert any(f["kind"] == "credential_candidate" for f in report["findings"])
    public = "".join(p.read_text() for p in directory.rglob("*.json"))
    assert not any(
        v in public
        for v in (
            "super-secret-demo",
            "example-key",
            "key-material",
            "must-not-read",
            "excluded-value",
        )
    )
    raw = list((directory / "private-raw").glob("*.bin"))
    assert raw and all(p.stat().st_mode & 0o777 == 0o600 for p in raw)
    assert directory.stat().st_mode & 0o777 == 0o700
    assert all(e["private_raw"] for e in report["evidence"] if e["file"].startswith("private-raw"))


def test_exposure_archives_office_and_limits(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    with zipfile.ZipFile(root / "backup.zip", "w") as archive:
        archive.writestr("../../never-written", "password=zip-secret")
        archive.writestr("large", "X" * 10000)
    with zipfile.ZipFile(root / "sample.docx", "w") as archive:
        archive.writestr("word/document.xml", "<document><p>token=office-secret</p></document>")
    code, report, directory = run_local(
        ExposureAudit(),
        tmp_path,
        ROOTS=[str(root)],
        ARCHIVES=True,
        OFFICE=True,
        MAX_EXTRACT_BYTES=200,
    )
    assert code == 1 and not report["completed"]
    assert any(e["error"] == "extraction_limit" for e in report["errors"])
    assert any("word/document.xml" in f["resource"] for f in report["findings"])
    assert not (tmp_path / "never-written").exists()
    assert "office-secret" not in (directory / "report.json").read_text()


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"MAX_FILES": 1}, "file_limit"),
        ({"MAX_TOTAL_BYTES": 2}, "byte_limit"),
        ({"MAX_OUTPUT": 20}, "output_limit"),
    ],
)
def test_exposure_incomplete_coverage(tmp_path, overrides, expected):
    root = tmp_path / "files"
    root.mkdir()
    for number in range(3):
        (root / f"{number}.env").write_text("password=fixture-value")
    code, report, _ = run_local(ExposureAudit(), tmp_path, ROOTS=[str(root)], **overrides)
    assert code == 1 and any(e["error"] == expected for e in report["errors"])


def test_inventory_only_runs_read_only_collectors(tmp_path, monkeypatch):
    commands = []

    async def fake_command(self, category, argv):
        commands.append(argv)
        if category == "sudo_noninteractive":
            self.error("permission_denied", category, "Noninteractive policy unavailable")
        evidence = self.evidence({"argv": argv, "fixture": True}, source=category)
        self.report["results"].append({"kind": category, "evidence": [evidence]})
        return ProcessResult(reason="finished", returncode=0), evidence

    monkeypatch.setattr(LocalContext, "command", fake_command)
    root = tmp_path / "fixture"
    root.mkdir()
    executable = root / "daemon"
    executable.write_text("fixture executable")
    (root / "demo.service").write_text(f"[Service]\nExecStart={executable}\n")
    code, report, _ = run_local(LinuxInventory(), tmp_path, ROOTS=[str(root)])
    assert code == 1 and any(e["error"] == "permission_denied" for e in report["errors"])
    assert ["sudo", "-n", "-l"] in commands
    assert not any("docker" in argv or "edamame" in " ".join(argv).lower() for argv in commands)
    assert any(f["kind"] == "writable_service_executable" for f in report["findings"])
    categories = {r["kind"] for r in report["results"]}
    assert {
        "os_kernel",
        "sudo_noninteractive",
        "processes",
        "listeners",
        "mounts",
        "nfs_exports",
        "file_capabilities",
    } <= categories


def test_missing_root_and_dependency_errors_are_reported(tmp_path):
    code, report, _ = run_local(ExposureAudit(), tmp_path, ROOTS=[str(tmp_path / "missing")])
    assert code == 1 and report["errors"][0]["error"] == "io_error"


def test_host_identity_export_compare_merge_compatibility():
    left = {
        "kind": "suid_binary",
        "title": "SUID binary",
        "host": "host-a",
        "resource": "/bin/demo",
    }
    right = {**left, "host": "host-b"}
    assert stable_id(left) != stable_id(right)
    report = {"findings": [left], "results": [], "endpoints": []}
    changed = {**report, "findings": [{**left, "mode": "4755"}]}
    assert len(compare_reports(report, changed)["findings"]["changed"]) == 1
    merged = merge_reports([report, {**report, "findings": [right]}])
    assert len(merged["findings"]) == 2
    assert "host / resource" in markdown_report(merged)


def test_nmap_import_ports_scripts_vhosts_and_no_authorization(tmp_path):
    xml = tmp_path / "nmap.xml"
    xml.write_text("""<?xml version="1.0"?><!DOCTYPE nmaprun>
      <nmaprun scanner="nmap" args="nmap -sV">
      <host><status state="up"/><address addr="192.0.2.7" addrtype="ipv4"/>
      <hostnames><hostname name="observed.example" type="PTR"/></hostnames><ports>
      <port protocol="tcp" portid="443"><state state="open"/>
      <service name="http" tunnel="ssl" product="Demo" version="1.0"/>
      <script id="http-test" output="password=script-secret">
      <table key="data"><elem key="test">value</elem></table></script></port>
      <port protocol="udp" portid="80"><state state="open"/>
      <service name="http"/></port></ports></host>
      <runstats><finished exit="success"/></runstats></nmaprun>""")
    vhosts = tmp_path / "vhosts.json"
    vhosts.write_text(json.dumps({"192.0.2.7": ["app.example.test"]}))
    code, report, directory = run_local(
        NmapImport(), tmp_path, INPUT=str(xml), VHOSTS_FILE=str(vhosts)
    )
    assert code == 0
    assert len(report["endpoints"]) == 2
    assert all(
        e["url"].startswith("https:") and e["authorized"] is False for e in report["endpoints"]
    )
    host = report["results"][0]
    assert host["ports"][0]["service"]["version"] == "1.0"
    assert host["ports"][0]["scripts"][0]["data"][0]["children"][0]["text"] == "value"
    assert "script-secret" not in (directory / "report.json").read_text()


def test_nmap_incomplete_and_malformed_scan(tmp_path):
    xml = tmp_path / "nmap.xml"
    xml.write_text("<nmaprun><host/></nmaprun>")
    code, report, _ = run_local(NmapImport(), tmp_path, INPUT=str(xml))
    assert code == 1 and report["scan"]["complete"] is False
    xml.write_text("<nmaprun><host>")
    code, report, _ = run_local(NmapImport(), tmp_path, INPUT=str(xml))
    assert code == 1 and report["errors"][0]["error"] == "input_error"


@pytest.mark.parametrize(
    "body",
    [
        b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>',
        b'<!DOCTYPE x SYSTEM "https://outside.example/dtd"><x/>',
        b'<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>',
    ],
)
def test_xml_entities_resources_are_rejected(body):
    with pytest.raises(ValueError, match="forbidden"):
        parse_xml(body)


def test_xml_node_depth_and_byte_limits():
    with pytest.raises(ValueError, match="node/depth"):
        parse_xml(b"<a><b><c/></b></a>", max_depth=2)
    with pytest.raises(ValueError, match="node/depth"):
        parse_xml(b"<a><b/><c/></a>", max_nodes=2)
    with pytest.raises(ValueError, match="byte"):
        parse_xml(b"<a/>", max_bytes=2)
