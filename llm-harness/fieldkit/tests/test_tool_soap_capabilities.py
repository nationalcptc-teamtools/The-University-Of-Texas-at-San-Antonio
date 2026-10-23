"""Captured JSONL, fake external binaries and bounded WSDL fixtures."""

import json

import httpx
import pytest
from test_replay_checks import network_run, write_json

from fieldkit.core.xml import parse_xml
from fieldkit.modules.nuclei import Nuclei, review_template
from fieldkit.modules.soap_inventory import SOAPInventory, inventory_documents

TEMPLATE = """id: CVE-fixture-surface
info:
  name: Critical command injection
  severity: critical
http:
  - method: GET
    path: ["{{BaseURL}}/login"]
    redirects: false
    matchers:
      - type: word
        words: [FixtureProduct]
"""


def template_file(tmp_path, text=TEMPLATE):
    path = tmp_path / "template.yaml"
    path.write_text(text)
    return str(path)


def test_nuclei_import_no_requests_preserves_match_semantics_provenance(tmp_path, monkeypatch):
    path = tmp_path / "results.jsonl"
    row = {
        "template-id": "CVE-fixture-surface",
        "matched-at": "https://lab.test/login",
        "matcher-name": "product",
        "info": {"severity": "critical"},
        "request": "GET / HTTP/1.1\nAuthorization: Bearer private-auth-example"
        "\nCookie: sid=private-cookie-example",
        "response": "password=private-password-example",
    }
    path.write_text(json.dumps(row) + "\ninvalid-json\n" + json.dumps(row) + "\n")
    _, report, directory, seen = network_run(
        Nuclei(),
        tmp_path,
        monkeypatch,
        lambda r: pytest.fail("Import must make no network requests"),
        INPUT=str(path),
        TEMPLATES=[template_file(tmp_path)],
        IMPORT_COMPLETE=True,
    )
    assert not seen and len(report["results"]) == 2 and len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["kind"] == "nuclei_surface_match" and finding["severity"] == "info"
    assert finding["reported_severity"] == "critical" and finding["outcome"] == "observed"
    assert finding["template"]["sha256"]
    assert report["errors"][0]["error"] == "malformed_jsonl"
    saved = "".join(p.read_text() for p in directory.rglob("*.json"))
    assert not any(
        v in saved
        for v in ("private-auth-example", "private-cookie-example", "private-password-example")
    )


def test_nuclei_unknown_template_and_partial_import(tmp_path, monkeypatch):
    path = tmp_path / "results.jsonl"
    path.write_text(json.dumps({"template-id": "unknown", "host": "https://lab.test/"}))
    code, report, _, _ = network_run(
        Nuclei(), tmp_path, monkeypatch, lambda r: httpx.Response(200), INPUT=str(path)
    )
    assert code == 1 and report["findings"][0]["kind"] == "nuclei_unreviewed"
    assert report["tool_input"]["complete"] is False


def fake_nuclei(tmp_path, extra=""):
    binary = tmp_path / "fake-nuclei"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        + """import sys,json,pathlib,time
if '-version' in sys.argv:
    print('Nuclei v3-fixture')
    raise SystemExit(0)
argv=sys.argv
config=pathlib.Path(argv[argv.index('-config')+1])
assert config.stat().st_mode & 0o777 == 0o600
assert all(v not in ' '.join(argv) for v in ['fake-private-auth', 'fake-private-cookie'])
targets=pathlib.Path(argv[argv.index('-l')+1]).read_text().splitlines()
assert '-dr' in argv and '-ni' in argv and '-duc' in argv
assert '-code' not in argv and '-headless' not in argv
print(json.dumps({'template-id':'CVE-fixture-surface','matched-at':targets[0]+'login','matcher-name':'fixture','request':config.read_text()}),flush=True)
"""
        + extra
    )
    binary.chmod(0o700)
    return str(binary)


def test_nuclei_execution_explicit_templates_private_profile_argv_and_cleanup(
    tmp_path, monkeypatch
):
    profiles = write_json(
        tmp_path,
        "profiles.json",
        {
            "profiles": {
                "session": {
                    "origins": ["https://lab.test"],
                    "headers": {"Authorization": "Bearer fake-private-auth"},
                    "cookies": {"sid": "fake-private-cookie"},
                }
            }
        },
    )
    code, report, directory, seen = network_run(
        Nuclei(),
        tmp_path,
        monkeypatch,
        lambda r: httpx.Response(200),
        EXECUTE=True,
        BINARY=fake_nuclei(tmp_path),
        TEMPLATES=[template_file(tmp_path)],
        PROFILES_FILE=profiles,
        PROFILE="session",
        RATE=1,
    )
    assert code == 0 and not seen and report["tool_run"]["reason"] == "finished"
    assert report["findings"][0]["template"]["sha256"]
    assert "Nuclei v3-fixture" in report["tool_run"]["version"]
    saved = "".join(p.read_text() for p in directory.rglob("*.json"))
    assert "fake-private-auth" not in saved and "fake-private-cookie" not in saved
    assert not any("config.yaml" == p.name for p in directory.rglob("*"))


def test_nuclei_deadline_preserves_completed_jsonl_observation(tmp_path, monkeypatch):
    code, report, _, _ = network_run(
        Nuclei(),
        tmp_path,
        monkeypatch,
        lambda r: httpx.Response(200),
        EXECUTE=True,
        BINARY=fake_nuclei(tmp_path, "time.sleep(30)\n"),
        TEMPLATES=[template_file(tmp_path)],
        RATE=1,
        BUDGET=0.4,
    )
    assert code == 1 and len(report["findings"]) == 1
    assert report["tool_run"]["reason"] == "timeout"
    assert report["errors"][0]["error"] == "partial_tool_run"


@pytest.mark.parametrize(
    "text",
    [
        TEMPLATE + "code:\n  - engine: [python3]\n",
        TEMPLATE.replace('path: ["{{BaseURL}}/login"]', 'path: ["https://outside.test/"]'),
        TEMPLATE.replace("redirects: false", "redirects: true"),
        TEMPLATE.replace("method: GET", "method: DELETE"),
        TEMPLATE.replace('path: ["{{BaseURL}}/login"]', 'raw: ["GET / HTTP/1.1"]'),
        TEMPLATE + "flow: http(1)\n",
    ],
)
def test_nuclei_unsupported_template_execution_is_rejected(tmp_path, text):
    with pytest.raises(ValueError):
        review_template(template_file(tmp_path, text), execute=True)


def test_nuclei_yaml_aliases_rejected(tmp_path):
    with pytest.raises(ValueError, match="aliases"):
        review_template(template_file(tmp_path, "id: foo\nx: &a [1]\ny: *a\n"))


def wsdl(url="https://service.test/actual", soap12=False, imported=False):
    soap_ns = (
        "http://schemas.xmlsoap.org/wsdl/soap12/"
        if soap12
        else "http://schemas.xmlsoap.org/wsdl/soap/"
    )
    types = (
        ""
        if imported
        else """<w:types><x:schema targetNamespace="urn:objects" elementFormDefault="qualified">
        <x:element name="Lookup"><x:complexType><x:sequence>
        <x:element name="id" type="x:string"/></x:sequence></x:complexType></x:element>
        </x:schema></w:types>"""
    )
    imports = '<w:import namespace="urn:objects" location="/schema.xsd"/>' if imported else ""
    return f'''<w:definitions xmlns:w="http://schemas.xmlsoap.org/wsdl/"
        xmlns:b="urn:binding" xmlns:p="urn:objects"
        xmlns:x="http://www.w3.org/2001/XMLSchema"
        xmlns:s="{soap_ns}" targetNamespace="urn:binding">
        {imports}{types}<w:message name="Input"><w:part name="parameters" element="p:Lookup"/>
        </w:message>
        <w:portType name="LookupType"><w:operation name="Lookup"><w:input message="b:Input"/>
        </w:operation></w:portType>
        <w:binding name="Binding" type="b:LookupType"><s:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
        <w:operation name="Lookup"><s:operation soapAction="urn:lookup"/>
        <w:input><s:body use="literal"/></w:input></w:operation></w:binding>
        <w:service name="Service"><w:port name="Port" binding="b:Binding">
        <s:address location="{url}"/></w:port></w:service></w:definitions>'''.encode()


@pytest.mark.parametrize("soap12", [False, True])
def test_wsdl_namespace_binding_actual_addresses_and_replay_templates(
    tmp_path, monkeypatch, soap12
):
    file = tmp_path / "document.wsdl"
    file.write_bytes(wsdl(soap12=soap12))
    code, report, directory, seen = network_run(
        SOAPInventory(),
        tmp_path,
        monkeypatch,
        lambda r: pytest.fail("Offline inventory must not execute or fetch"),
        WSDL_FILES=[str(file)],
        TARGETS=[],
    )
    assert code == 0 and not seen and report["endpoints"][0]["url"] == "https://service.test/actual"
    templates = json.loads((directory / "request-templates.json").read_text())
    assert (
        templates[0]["url"] == "https://service.test/actual" and templates[0]["executed"] is False
    )
    root, _ = parse_xml(templates[0]["xml"].encode())
    assert root.find(".//{urn:objects}Lookup/{urn:objects}id") is not None
    operation = next(r for r in report["results"] if r["kind"] == "soap_operation")
    assert operation["soap_version"] == ("1.2" if soap12 else "1.1")
    assert (
        operation["soap_action"] == "urn:lookup"
        and operation["parameters"][0]["fields"][0]["name"] == "id"
    )
    if soap12:
        assert (
            "SOAPAction" not in templates[0]["headers"]
            and 'action="urn:lookup"' in templates[0]["headers"]["Content-Type"]
        )


def test_wsdl_scoped_imports_and_reference_ceiling(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path == "/schema.xsd":
            return httpx.Response(
                200,
                content=b'<x:schema xmlns:x="http://www.w3.org/2001/XMLSchema" '
                b'targetNamespace="urn:objects">'
                b'<x:element name="Lookup" type="x:string"/></x:schema>',
            )
        return httpx.Response(
            200,
            content=wsdl("https://lab.test/service", imported=True).replace(
                b"</w:definitions>",
                b'<w:import location="https://outside.test/doc"/></w:definitions>',
            ),
        )

    _, report, _, seen = network_run(
        SOAPInventory(),
        tmp_path,
        monkeypatch,
        handler,
        PATHS=["/service.wsdl"],
        FETCH_IMPORTS=True,
        MAX_DOCUMENTS=2,
    )
    assert [r.url.path for r in seen] == ["/service.wsdl", "/schema.xsd"]
    assert any("outside" in w for w in report["soap_summary"]["warnings"])


def test_wsdl_rejects_external_entities_and_unsupported_versions(tmp_path, monkeypatch):
    path = tmp_path / "wsdl.xml"
    path.write_text('<!DOCTYPE wsdl [<!ENTITY a SYSTEM "file:///etc/passwd">]><wsdl>&a;</wsdl>')
    code, report, _, _ = network_run(
        SOAPInventory(),
        tmp_path,
        monkeypatch,
        lambda r: httpx.Response(200),
        WSDL_FILES=[str(path)],
        TARGETS=[],
    )
    assert code == 1 and report["errors"][0]["error"] == "invalid_wsdl_xml"
    root, mappings = parse_xml(b'<description xmlns="http://www.w3.org/ns/wsdl"/>')
    operations, templates, warnings = inventory_documents(
        [(root, mappings, "https://lab.test/wsdl")]
    )
    assert not operations and not templates and "Unsupported" in warnings[0]


def test_startup_import_has_no_network_or_filesystem_side_effects(tmp_path):
    # A fresh interpreter avoids cached modules disguising import-time behavior.
    import subprocess
    import sys

    script = """import socket,pathlib,os,sys
sys.dont_write_bytecode=True
def forbidden(*args,**kwargs): raise AssertionError('import side effect')
class DeniedSocket(socket.socket):
    def __init__(self,*args,**kwargs): forbidden()
socket.socket=DeniedSocket
pathlib.Path.write_text=forbidden
pathlib.Path.mkdir=forbidden
pathlib.Path.read_text=forbidden
pathlib.Path.read_bytes=forbidden
os.system=forbidden
import fieldkit.registry
assert len(fieldkit.registry.modules()) == 49
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()
