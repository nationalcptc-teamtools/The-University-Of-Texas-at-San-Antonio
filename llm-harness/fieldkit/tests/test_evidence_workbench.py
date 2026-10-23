"""Private evidence graph, typed correlation and controlled replay regression tests."""

import base64
import gzip
import io
import json
import stat
import zipfile

import httpx
import pytest
from test_local_capabilities import run_local
from test_replay_checks import network_run, write_json

from fieldkit.cli import main
from fieldkit.core.correlation import actuator, transformations
from fieldkit.core.ingest import ingest
from fieldkit.core.replay import raw_request, validate_request
from fieldkit.core.vault import Vault
from fieldkit.modules.evidence_workbench import (
    ActuatorAnalyzer,
    ArtifactTriage,
    AuthFlowMapper,
    EvidenceIngest,
    EvidenceReport,
    HypothesisQueue,
    IDMapper,
    RequestVault,
    RouteMapper,
    SecretCorrelator,
    SerializationWorkbench,
)
from fieldkit.modules.host_resolver import HostResolver
from fieldkit.modules.request_replay import RequestReplay
from fieldkit.modules.workflow_verify import WorkflowVerifier
from fieldkit.registry import modules


def response(body, **extras):
    return {"status": 200, "headers": {}, "body_base64": base64.b64encode(body).decode(), **extras}


def capture(vault, url="https://lab.test/queue", body=b"{}", **extras):
    return vault.exchange(
        {"url": url, **extras},
        response(body),
        source={"file": "sanitized.har", "index": 184 + len(vault.records("request"))},
    )


def db_settings(tmp_path):
    return {"DATABASE": str(tmp_path / "evidence.sqlite")}


def har():
    return {
        "log": {
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "serverIPAddress": "192.0.2.7",
                    "request": {
                        "method": "POST",
                        "url": "https://lab.test/replay",
                        "headers": [
                            {"name": "Host", "value": "lab.test"},
                            {"name": "X-CSRF-Token", "value": "private-csrf-fixture"},
                        ],
                        "cookies": [{"name": "sid", "value": "private-session-fixture"}],
                        "postData": {"mimeType": "application/json", "text": '{"id":"job-7"}'},
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"shipmentJobId":"job-7","orderId":42}',
                        },
                    },
                }
            ]
        }
    }


def test_har_import_private_permissions_context_and_no_authorization(tmp_path):
    path = write_json(tmp_path, "traffic.har", har())
    code, report, directory = run_local(
        EvidenceIngest(),
        tmp_path,
        INPUT=[path],
        FORMAT="har",
        USER="vendor-a",
        ROLE="vendor",
        TAGS=["shipment"],
        **db_settings(tmp_path),
    )
    assert code == 0 and not report["vault"]["authorized_scope"]
    database = tmp_path / "evidence.sqlite"
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    with Vault(database, create=False) as vault:
        public = vault.records("request")[0]
        private = vault.get(public["id"], private=True)
        assert private["data"]["request"]["cookies"]["sid"] == "private-session-fixture"
        assert private["data"]["context"]["role"] == "vendor"
        assert vault.records("asset")[0]["data"]["ip"] == "192.0.2.7"
        assert vault.records("artifact")[0]["data"]["private_raw"]
    assert "private-session-fixture" not in json.dumps(public)
    assert "private-csrf-fixture" not in (directory / "report.json").read_text()
    assert stat.S_IMODE((tmp_path / "evidence.sqlite.private").stat().st_mode) == 0o700


def test_request_vault_filter_export_and_scoped_replay(tmp_path, monkeypatch):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        ids = ingest(
            vault,
            json.dumps(har()).encode(),
            "har",
            "capture.har",
            tags=["shipment"],
            context={"user": "vendor-a", "role": "vendor"},
        )
    code, report, directory = run_local(
        RequestVault(), tmp_path, REQUEST_IDS=ids, USER="vendor-a", TAG="shipment", **database
    )
    assert code == 0 and len(report["results"]) == 1
    assert "private-session-fixture" in (directory / "private-request-templates.json").read_text()
    assert stat.S_IMODE((directory / "private-request-templates.json").stat().st_mode) == 0o600
    code, report, _, seen = network_run(
        RequestReplay(),
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200, json={"ok": True}),
        REQUEST_IDS=ids,
        **database,
    )
    assert code == 0 and len(seen) == 1
    assert "private-session-fixture" in seen[0].headers["cookie"]
    assert seen[0].headers["x-csrf-token"] == "private-csrf-fixture"
    assert report["vault_requests"][0]["private_raw"]
    with pytest.raises(ValueError, match="outside"):
        network_run(
            RequestReplay(),
            tmp_path,
            monkeypatch,
            lambda r: httpx.Response(200),
            TARGETS=["https://other.test"],
            REQUEST_IDS=ids,
            **database,
        )


def test_burp_binary_export_is_preserved_in_vault_and_replayed(tmp_path, monkeypatch):
    binary = b"\xac\xed\x00\x05\x00\xff\r\n"
    raw = (
        b"POST /replay HTTP/1.1\r\nHost: lab.test\r\n"
        b"Content-Type: application/octet-stream\r\nContent-Length: 8\r\n\r\n" + binary
    )
    xml = (
        '<items><item><url>https://lab.test/replay</url><host ip="192.0.2.7">lab.test</host>'
        '<request base64="true">' + base64.b64encode(raw).decode() + "</request>"
        '<response base64="true">'
        + base64.b64encode(b"HTTP/1.1 200 OK\r\n\r\nokay").decode()
        + "</response></item></items>"
    ).encode()
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        ids = ingest(vault, xml, "burp", "traffic.xml")
        assert base64.b64decode(vault.request(ids[0])["body_base64"]) == binary
    code, _, _, seen = network_run(
        RequestReplay(),
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200),
        REQUEST_IDS=ids,
        **database,
    )
    assert code == 0 and seen[0].content == binary


def test_raw_body_crlf_and_duplicate_framing_are_not_silently_changed():
    body = b"line1\r\nline2"
    request = raw_request(
        b"POST /x HTTP/1.1\r\nHost: lab.test\r\nContent-Length: 12\r\n\r\n" + body,
        "https://lab.test",
    )
    assert request["body"].encode() == body
    with pytest.raises(ValueError, match="Duplicate"):
        raw_request("POST / HTTP/1.1\nContent-Length: 0\nContent-Length: 0\n\n", "https://lab.test")
    with pytest.raises(ValueError, match="Base64"):
        validate_request({"url": "/x", "body_base64": "invalid!"})


def test_malformed_capture_parsed_before_any_request_is_persisted(tmp_path):
    document = har()
    document["log"]["entries"].append({"request": {}})
    with Vault(tmp_path / "db.sqlite") as vault:
        with pytest.raises((ValueError, KeyError)):
            ingest(vault, json.dumps(document).encode(), "har", "bad.har")
        assert not vault.records("request")
        with pytest.raises(ValueError, match="limit"):
            ingest(vault, json.dumps(har()).encode(), "har", "large.har", maximum=0)
        with pytest.raises(ValueError, match="DTD|Entity|entit"):
            ingest(
                vault,
                b'<!DOCTYPE items [<!ENTITY x SYSTEM "file:///etc/passwd">]><items/>',
                "burp",
                "bad.xml",
            )


def test_vault_rejects_symlinks_and_ambiguous_indexes_and_retains_host_metadata(tmp_path):
    db = tmp_path / "db.sqlite"
    with Vault(db) as vault:
        first = vault.exchange(
            {"url": "https://lab.test/a"}, metadata={"ip": "192.0.2.7"}, source={"index": 184}
        )
        second = vault.exchange({"url": "https://lab.test/b"}, source={"index": 184})
        assert vault.request(first)["url"].endswith("/a")
        assert vault.records("asset")[0]["data"]["ip"] == "192.0.2.7"
        with pytest.raises(ValueError, match="one captured"):
            vault.request("184")
        assert second != first
    link = tmp_path / "link.sqlite"
    link.symlink_to(db)
    with pytest.raises(ValueError, match="symlink"):
        Vault(link)


def test_typed_id_links_distinguish_job_uuid_from_order_number_and_other_host(tmp_path):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        capture(vault, body=b'{"shipmentJobUuid":"job-7","orderId":42}')
        capture(vault, "https://lab.test/shipment-jobs/job-7/export")
        capture(vault, "https://lab.test/shipment-jobs/42/export")
        capture(vault, "https://other.test/shipment-jobs/job-7/export")
    code, report, _ = run_local(
        IDMapper(), tmp_path, ROUTE="/shipment-jobs/{id}/export", **database
    )
    assert code == 0 and len(report["results"]) == 2
    links = {r["value"]: r for r in report["results"]}
    assert links["job-7"]["semantic_type"] == "shipment-job"
    assert links["job-7"]["type_matches_route"]
    assert links[42]["semantic_type"] == "order" and not links[42]["type_matches_route"]
    assert links["job-7"]["source_index"] == 184
    assert not report["identifier_summary"]["enumerated"]


def test_id_mapper_limits_are_reported_as_incomplete(tmp_path):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        capture(vault, body=b'{"orderId":1,"shipmentJobId":2}')
        capture(vault, "https://lab.test/jobs/2")
    code, report, _ = run_local(IDMapper(), tmp_path, MAX_RECORDS=1, **database)
    assert code == 1 and report["errors"] and not report["completed"]


def test_routes_merge_traffic_js_openapi_actuator_with_provenance(tmp_path):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        capture(vault, "https://lab.test/jobs")
        ingest(
            vault,
            b'fetch("/jobs");fetch("/candidate")',
            "js",
            "app.js",
            context={"host": "lab.test"},
        )
        ingest(
            vault,
            json.dumps(
                {
                    "servers": [{"url": "https://lab.test"}],
                    "paths": {"/jobs": {"get": {"operationId": "jobs"}}},
                }
            ).encode(),
            "openapi",
            "api.json",
            context={"host": "lab.test"},
        )
        ingest(
            vault,
            json.dumps({"mapping": {"predicate": "{POST [/jobs/{id}/replay]}"}}).encode(),
            "actuator",
            "mappings.json",
            context={"host": "lab.test"},
        )
    code, report, _ = run_local(RouteMapper(), tmp_path, HOST="lab.test", **database)
    assert code == 0
    assert {kind for r in report["results"] for kind in r["data"]["source_kinds"]} == {
        "traffic",
        "javascript",
        "openapi",
        "actuator",
    }
    assert all(r["provenance"] for r in report["results"])


def test_actuator_secret_leaf_values_are_fingerprinted_never_displayed(tmp_path):
    document = {
        "propertySources": [{"properties": {"clientSecret": {"value": "private-oauth-fixture"}}}],
        "configprops": {"clientSecret": "private-client-fixture", "password": "******"},
        "build": {"dependency": "example-lib-1.2.3.jar"},
    }
    result = actuator(document)
    assert len(result["secrets"]) >= 2
    assert "private-oauth-fixture" not in json.dumps(result)
    assert "private-client-fixture" not in json.dumps(result)
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        ingest(vault, json.dumps(document).encode(), "actuator", "env.json")
    code, report, _ = run_local(ActuatorAnalyzer(), tmp_path, **database)
    assert code == 0 and not report["results"][0]["data"]["credentials_valid"]


def test_artifact_recursive_transformations_keep_original_and_trace_java_magic(tmp_path):
    original = base64.b64encode(gzip.compress(b"\xac\xed\x00\x05fixture"))
    path = tmp_path / "export.txt"
    path.write_bytes(original)
    code, report, _ = run_local(
        ArtifactTriage(), tmp_path, INPUT=[str(path)], **db_settings(tmp_path)
    )
    assert code == 0 and path.read_bytes() == original
    formats = [r["data"]["format"] for r in report["results"]]
    assert formats == ["opaque", "gzip", "java-serialization-stream"]
    assert all(
        not r["data"]["executed"] and not r["data"]["deserialized"] for r in report["results"]
    )
    with Vault(tmp_path / "evidence.sqlite") as vault:
        assert len(vault.records("artifact")) == 3
        assert any(
            link["relation"] == "transformation"
            for link in vault.links(vault.records("artifact")[1]["id"])
        )


@pytest.mark.parametrize("archive", [False, True])
def test_decompression_limits_do_not_write_members_or_exceed_bytes(tmp_path, archive):
    if archive:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as container:
            container.writestr("../../outside", b"a" * 10000)
        data = buf.getvalue()
    else:
        data = gzip.compress(b"a" * 10000)
    with pytest.raises(ValueError, match="byte limit"):
        list(transformations(data, 100))
    assert not (tmp_path / "outside").exists()


def test_artifact_depth_and_aggregate_limits_are_visible(tmp_path):
    data = tmp_path / "a.txt"
    data.write_bytes(base64.b64encode(gzip.compress(b"a" * 1000)))
    code, report, _ = run_local(
        ArtifactTriage(), tmp_path, INPUT=[str(data)], MAX_DEPTH=0, **db_settings(tmp_path)
    )
    assert code == 0 and report["results"][0]["data"]["depth_limited"]
    code, report, _ = run_local(
        ArtifactTriage(), tmp_path, INPUT=[str(data)], MAX_TOTAL_BYTES=100, **db_settings(tmp_path)
    )
    assert code == 1 and report["errors"]


def test_correlator_attaches_provenance_without_secret_validation(tmp_path):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        capture(vault, body=b"password=private-secret-fixture example-lib-1.2.3.jar")
        ingest(vault, b"password=private-secret-fixture", "artifact", "config.env")
    code, report, _ = run_local(SecretCorrelator(), tmp_path, **database)
    assert code == 0 and all(r["provenance"] for r in report["results"])
    assert "private-secret-fixture" not in json.dumps(report)
    assert any(r["kind"] == "dependency" for r in report["results"])
    code, report, _ = run_local(HypothesisQueue(), tmp_path, **database)
    assert code == 0 and report["results"]
    assert all(r["data"]["counterevidence"] and r["data"]["next_test"] for r in report["results"])


def test_auth_flow_jwt_claims_are_unverified_and_diagram_links_context(tmp_path):
    claims = base64.urlsafe_b64encode(
        json.dumps({"sub": "vendor-a", "aud": "vendor-client"}).encode()
    )
    token = "eyJhbGciOiJub25lIn0." + claims.decode().rstrip("=") + ".c2ln"
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        capture(
            vault,
            "https://lab.test/authorize?client_id=vendor-client&scope=openid&"
            "redirect_uri=https%3A%2F%2Flab.test%2Fcallback&code_challenge=x&code_challenge_method=S256",
            body=json.dumps({"access_token": token}).encode(),
        )
    code, report, directory = run_local(AuthFlowMapper(), tmp_path, **database)
    flow = report["results"][0]["data"]
    assert code == 0 and flow["pkce"]["method"] == "S256"
    assert flow["tokens"][0]["claims"]["sub"] == "vendor-a"
    assert not flow["tokens"][0]["signature_verified"]
    assert token not in json.dumps(report)
    assert "Unverified sub=vendor-a, aud=vendor-client" in (directory / "auth-flow.mmd").read_text()


@pytest.mark.parametrize("valid,confirm", [(False, True), (True, False), (True, True)])
def test_workflow_modification_gate_requires_successful_baseline_and_explicit_flag(
    tmp_path, monkeypatch, valid, confirm
):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        request_id = capture(vault, "https://lab.test/replay", method="POST", json={"id": "job-7"})
        artifact = vault.artifact(
            b"\xac\xed\x00\x05fixture", source={"request": request_id}, asset="lab"
        )
    workflow = write_json(
        tmp_path,
        "workflow.json",
        {
            "steps": [{"request": request_id, "expect": {"contains": "Known shipment job-7"}}],
            "modification": {"location": "json:/id", "value": "job-8"},
        },
    )
    code, report, _, seen = network_run(
        WorkflowVerifier(),
        tmp_path,
        monkeypatch,
        lambda r: httpx.Response(200, content=b"Known shipment job-7" if valid else b"login page"),
        WORKFLOW_FILE=workflow,
        CONFIRM_MODIFICATION=confirm,
        ARTIFACT_ID=artifact,
        **database,
    )
    result = report["results"][0]
    assert code == 0 and result["baseline_verified"] == valid
    assert result["modification_executed"] == (valid and confirm)
    assert len(seen) == (2 if valid and confirm else 1)
    assert not report["findings"]
    with Vault(database["DATABASE"]) as vault:
        assert vault.records("workflow")[0]["data"]["artifact"] == artifact


def test_serialization_library_is_only_a_hypothesis_and_requires_artifact_baseline(tmp_path):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        artifact = vault.artifact(
            b"\xac\xed\x00\x05fixture", source={"file": "export"}, asset="lab"
        )
        vault.put("dependency", {"asset": "lab", "package": "example-lib", "version": "1.2.3"})
    run_local(ArtifactTriage(), tmp_path, ARTIFACT_IDS=[artifact], **database)
    code, report, _ = run_local(SerializationWorkbench(), tmp_path, **database)
    assert code == 0 and report["results"][0]["data"]["outcome"] == "hypothesized"
    assert not report["results"][0]["data"]["modified_test_allowed"]
    with Vault(database["DATABASE"]) as vault:
        vault.put("workflow", {"artifact": artifact, "baseline_verified": True})
    _, report, _ = run_local(SerializationWorkbench(), tmp_path, **database)
    assert report["results"][0]["data"]["modified_test_allowed"]


def test_host_properties_curl_resolve_ipv6_and_no_implicit_probe(tmp_path, monkeypatch):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        vault.exchange(
            {"url": "https://lab.test/x"}, metadata={"ip": "2001:db8::7", "tls_sni": "lab.test"}
        )
    code, report, _, seen = network_run(
        HostResolver(), tmp_path, monkeypatch, lambda r: httpx.Response(200), TARGETS=[], **database
    )
    assert code == 0 and not seen
    record = report["results"][0]
    assert record["curl_argv"] == [
        "curl",
        "--resolve",
        "lab.test:443:[2001:db8::7]",
        "https://lab.test",
    ]
    assert record["tls_sni"] == "lab.test" and not record["executed"]


def test_host_308_explanation_preserves_out_of_scope_canonical_without_following(
    tmp_path, monkeypatch
):
    code, report, _, seen = network_run(
        HostResolver(),
        tmp_path,
        monkeypatch,
        lambda r: httpx.Response(308, headers={"Location": "https://outside.test/canonical"}),
        PROBE=True,
    )
    assert code == 0 and all(r.url.host == "lab.test" for r in seen)
    record = report["results"][0]
    assert (
        record["redirect_outside_scope"]
        and record["canonical_url"] == "https://outside.test/canonical"
    )
    assert "preserves the method/body" in record["explanation"]


def test_dry_run_does_not_open_network_or_store_database(tmp_path, monkeypatch):
    request = write_json(
        tmp_path, "requests.json", {"id": "x", "url": "/x", "method": "POST", "json": {"id": 1}}
    )
    code, report, _, seen = network_run(
        RequestReplay(),
        tmp_path,
        monkeypatch,
        lambda r: pytest.fail("dry-run network traffic"),
        REQUESTS_FILE=request,
        REQUEST_IDS=["x"],
        DRY_RUN=True,
        **db_settings(tmp_path),
    )
    assert code == 0 and not seen and report["plan"]["network_requests"] == 0
    assert not (tmp_path / "evidence.sqlite").exists()


def test_report_draft_requires_evidence_and_preserves_status_impact_remediation(tmp_path):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        reference = capture(vault)
        vault.put("hypothesis", {"title": "Unverified lead", "outcome": "hypothesized"})
    annotations = write_json(
        tmp_path,
        "findings.json",
        [
            {
                "kind": "exposure",
                "title": "Observed config",
                "validation_status": "observed",
                "evidence": [reference],
                "impact": "Visible configuration",
                "remediation": "Restrict the endpoint",
            }
        ],
    )
    code, report, directory = run_local(
        EvidenceReport(), tmp_path, FINDINGS_FILE=annotations, **database
    )
    assert code == 0 and report["findings"][0]["confidence"] == "observed"
    markdown = (directory / "report.md").read_text()
    assert "Visible configuration" in markdown and "Restrict the endpoint" in markdown
    assert "Hypotheses requiring validation" in markdown
    invalid = write_json(
        tmp_path, "invalid.json", [{"validation_status": "validated", "evidence": ["missing"]}]
    )
    code, report, _ = run_local(EvidenceReport(), tmp_path, FINDINGS_FILE=invalid, **database)
    assert code == 1 and report["errors"]


def test_report_import_remaps_evidence_provenance_without_loading_external_files(tmp_path):
    document = {
        "evidence": [{"id": "evidence-1", "file": "/untrusted/external.json"}],
        "findings": [{"kind": "lead", "evidence": ["evidence-1"]}],
    }
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        ingest(vault, json.dumps(document).encode(), "report", "report.json")
        finding = vault.records("finding")[0]
        referenced = vault.get(finding["data"]["evidence"][0])
        assert referenced["data"]["raw_imported"] is False
    code, report, _ = run_local(EvidenceReport(), tmp_path, **database)
    assert code == 0 and report["evidence"]


def test_cli_shortcuts_use_same_registered_modules_options_and_console(tmp_path, monkeypatch):
    commands = [
        (["ingest", "burp", "traffic.xml"], "evidence/ingest", "INPUT", ["traffic.xml"]),
        (["web", "routes", "--host", "lab.test"], "web/routes", "HOST", "lab.test"),
        (["web", "ids", "--route", "/jobs/{id}"], "web/ids", "ROUTE", "/jobs/{id}"),
        (["inspect", "artifact", "export.txt"], "artifacts/triage", "INPUT", ["export.txt"]),
        (
            ["workflow", "baseline", "--request", "184"],
            "web/workflow-verify",
            "REQUEST_IDS",
            ["184"],
        ),
        (["findings", "draft"], "evidence/report", "DATABASE", "artifacts/fieldkit.sqlite"),
    ]
    for args, name, key, expected in commands:
        received = []
        monkeypatch.setattr(
            type(modules()[name]),
            "run",
            lambda self, settings, console, received=received: received.append(settings) or 0,
        )
        assert main(args) == 0
        assert received[0][key] == expected


def test_auth_matrix_vault_requests_and_bounded_explicit_state_checks(tmp_path, monkeypatch):
    from fieldkit.modules.auth_matrix import AuthMatrix

    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        request_id = capture(
            vault, "https://lab.test/job", method="POST", json={"action": "replay"}
        )
    matrix = write_json(
        tmp_path,
        "matrix.json",
        {
            "identities": {"vendor": "anonymous"},
            "objects": [
                {
                    "id": "job-7",
                    "owner": "vendor",
                    "request_id": request_id,
                    "checks": {"contains": "Known job-7"},
                    "state_check": {"request": {"url": "/state"}, "json_pointer": "/status"},
                }
            ],
            "rules": [{"identity": "vendor", "resource": "job-7", "expected": "allow"}],
        },
    )
    state = {"status": "queued"}

    def handler(request):
        if request.url.path == "/state":
            return httpx.Response(200, json=state)
        state["status"] = "replayed"
        return httpx.Response(200, content=b"Known job-7")

    code, report, _, seen = network_run(
        AuthMatrix(), tmp_path, monkeypatch, handler, MATRIX_FILE=matrix, MAX_REQUESTS=3, **database
    )
    assert code == 0 and len(seen) == 3
    record = report["results"][0]
    assert record["outcome"] == "expected_allow"
    assert (
        record["state_comparison"]["changed"]
        and record["state_comparison"]["outcome"] == "observed"
    )
    assert record["state_comparison"]["before"]["evidence"]
    with pytest.raises(ValueError, match="MAX_REQUESTS"):
        network_run(
            AuthMatrix(),
            tmp_path,
            monkeypatch,
            handler,
            MATRIX_FILE=matrix,
            MAX_REQUESTS=2,
            **database,
        )


def test_tar_triage_skips_symlinks_and_never_extracts_names_to_disk(tmp_path):
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        symlink = tarfile.TarInfo("outside-link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "/untrusted/external"
        archive.addfile(symlink)
        item = tarfile.TarInfo("../../outside")
        item.size = 8
        archive.addfile(item, io.BytesIO(b"\xac\xed\x00\x05demo"))
    children = list(transformations(buf.getvalue(), 100, 3))
    assert children == [("tar:../../outside", b"\xac\xed\x00\x05demo")]
    assert not (tmp_path / "outside").exists()


def test_workflow_extraction_failure_preserves_baseline_evidence_and_blocks_change(
    tmp_path, monkeypatch
):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]):
        pass
    workflow = write_json(
        tmp_path,
        "workflow.json",
        {
            "steps": [
                {
                    "request": {"url": "/job"},
                    "expect": {"contains": "job-7"},
                    "extract": {"nonce": {"source": "json", "pointer": "/absent"}},
                }
            ],
            "modification": {"location": "body:replace", "value": "one change"},
        },
    )
    code, report, _, seen = network_run(
        WorkflowVerifier(),
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200, json={"id": "job-7"}),
        WORKFLOW_FILE=workflow,
        CONFIRM_MODIFICATION=True,
        **database,
    )
    assert code == 1 and len(seen) == 1
    result = report["results"][0]
    assert not result["baseline_verified"] and not result["modification_executed"]
    assert result["evidence"] and report["errors"][0]["error"] == "extraction_failed"
    with Vault(database["DATABASE"]) as vault:
        assert not vault.records("workflow")[0]["data"]["baseline_verified"]


@pytest.mark.parametrize("data", [b"PK\x03\x04malformed", b"x\x9cmalformed", b"\x1f\x8bmalformed"])
def test_malformed_archives_are_normalized_errors(data):
    with pytest.raises((ValueError, OSError)):
        list(transformations(data, 100))


def test_har_repeated_request_fields_and_multipart_are_not_silently_rewritten(tmp_path):
    document = har()
    entry = document["log"]["entries"][0]
    entry["request"]["headers"].append({"name": "x-csrf-token", "value": "other"})
    with Vault(tmp_path / "db.sqlite") as vault:
        with pytest.raises(ValueError, match="Repeated"):
            ingest(vault, json.dumps(document).encode(), "har", "bad.har")
        entry["request"]["headers"].pop()
        entry["request"]["postData"] = {
            "mimeType": "multipart/form-data",
            "params": [{"name": "id", "value": "job-7"}],
        }
        with pytest.raises(ValueError, match="multipart"):
            ingest(vault, json.dumps(document).encode(), "har", "multipart.har")
        entry["request"]["postData"] = {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [{"name": "id", "value": "one"}, {"name": "id", "value": "two"}],
        }
        ids = ingest(vault, json.dumps(document).encode(), "har", "duplicate-form.har")
        assert vault.request(ids[0])["body"] == "id=one&id=two"


def test_public_vault_masks_prefixed_secret_response_headers(tmp_path):
    with Vault(tmp_path / "db.sqlite") as vault:
        reference = vault.exchange(
            {"url": "https://lab.test/x"},
            response(
                b"fixture",
                headers={"X-CSRF-Token": "private-csrf", "clientSecret": "private-client"},
                headers_raw=[{"name": "Set-Cookie", "value": "sid=private-session"}],
            ),
        )
        public = json.dumps(vault.get(reference))
        assert not any(
            secret in public for secret in ["private-csrf", "private-client", "private-session"]
        )
        assert vault.get(reference, private=True)["data"]["response"]["headers_raw"]


def test_excessively_nested_import_is_rejected_before_vault_writes(tmp_path):
    nested = b'{"nested":' * 40 + b"0" + b"}" * 40
    with Vault(tmp_path / "db.sqlite") as vault:
        with pytest.raises(ValueError, match="depth"):
            ingest(vault, nested, "actuator", "deep.json")
        assert not vault.records("document")


def test_identity_matrix_does_not_reuse_captured_owner_credentials(tmp_path, monkeypatch):
    from fieldkit.modules.auth_matrix import AuthMatrix

    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        request_id = capture(
            vault,
            "https://lab.test/job",
            headers={"Authorization": "Bearer owner-only", "Cookie": "sid=owner-only"},
            cookies={"sid": "owner-only"},
        )
    profiles = write_json(
        tmp_path,
        "profiles.json",
        {
            "profiles": {
                "owner": {
                    "origins": ["https://lab.test"],
                    "headers": {"Authorization": "Bearer owner-only"},
                }
            }
        },
    )
    matrix = write_json(
        tmp_path,
        "matrix.json",
        {
            "identities": {"owner": "owner", "other": "anonymous"},
            "objects": [
                {
                    "id": "job-7",
                    "owner": "owner",
                    "request_id": request_id,
                    "checks": {"json_pointer": "/id", "equals": "job-7"},
                }
            ],
            "rules": [
                {"identity": "owner", "resource": "job-7", "expected": "allow"},
                {"identity": "other", "resource": "job-7", "expected": "deny"},
            ],
        },
    )
    code, report, _, seen = network_run(
        AuthMatrix(),
        tmp_path,
        monkeypatch,
        lambda req: (
            httpx.Response(200, json={"id": "job-7"})
            if req.headers.get("authorization") == "Bearer owner-only"
            else httpx.Response(403)
        ),
        MATRIX_FILE=matrix,
        PROFILES_FILE=profiles,
        **database,
    )
    assert code == 0 and not report["findings"] and len(seen) == 2
    assert "authorization" not in seen[1].headers and "cookie" not in seen[1].headers
    assert report["results"][1]["outcome"] == "expected_deny"


def test_empty_or_mixed_resource_checks_cannot_bypass_workflow_gate(tmp_path, monkeypatch):
    from fieldkit.core.http import FetchResult
    from fieldkit.modules.auth_matrix import response_check

    result = FetchResult(
        "https://lab.test/x", "https://lab.test/x", status=200, body=b'{"id":"wrong"}'
    )
    assert (
        response_check(result, {"contains": "", "json_pointer": "/id", "equals": "job-7"}) is None
    )
    assert (
        response_check(result, {"contains": "wrong", "json_pointer": "/id", "equals": "job-7"})
        is False
    )
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]):
        pass
    workflow = write_json(
        tmp_path,
        "workflow.json",
        {
            "steps": [
                {
                    "request": {"url": "/job"},
                    "expect": {"contains": "", "json_pointer": "/id", "equals": "job-7"},
                }
            ]
        },
    )
    with pytest.raises(ValueError, match="nonempty"):
        network_run(
            WorkflowVerifier(),
            tmp_path,
            monkeypatch,
            lambda req: httpx.Response(200),
            WORKFLOW_FILE=workflow,
            **database,
        )


def test_browser_login_respects_credential_profile_origin_before_launch(tmp_path, monkeypatch):
    from fieldkit.modules.session_workflow import BrowserLogin

    profiles = write_json(
        tmp_path,
        "profiles.json",
        {
            "profiles": {
                "restricted": {
                    "origins": ["https://identity.test"],
                    "headers": {"Authorization": "Bearer restricted-private"},
                }
            }
        },
    )
    monkeypatch.setattr(
        "fieldkit.modules.session_workflow.importlib.util.find_spec",
        lambda *args: pytest.fail("browser launch must be blocked first"),
    )
    code, report, _, seen = network_run(
        BrowserLogin(),
        tmp_path,
        monkeypatch,
        lambda req: pytest.fail("restricted credential network request"),
        LOGIN_URL="/login",
        SUCCESS_SELECTOR="#authenticated",
        PROFILES_FILE=profiles,
        PROFILE="restricted",
    )
    assert code == 1 and not seen and report["errors"][0]["error"] == "profile_scope"


def test_id_mapper_uses_capture_time_instead_of_import_time_and_excludes_self(tmp_path):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        vault.exchange(
            {"url": "https://lab.test/jobs/job-7/export"},
            response(b'{"shipmentJobId":"job-7"}', timestamp="2026-03-10T00:00:00Z"),
            source={"file": "later.har", "index": 1},
        )
        vault.exchange(
            {"url": "https://lab.test/jobs/job-7/export"},
            response(b"{}", timestamp="2026-03-09T00:00:00Z"),
            source={"file": "earlier.har", "index": 1},
        )
    code, report, _ = run_local(IDMapper(), tmp_path, **database)
    assert code == 0 and not report["results"]


def test_same_artifact_bytes_preserve_both_asset_contexts(tmp_path):
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        first = vault.artifact(b"\xac\xed\x00\x05demo", source={"file": "one"}, asset="one.test")
        second = vault.artifact(b"\xac\xed\x00\x05demo", source={"file": "two"}, asset="two.test")
    code, report, _ = run_local(
        ArtifactTriage(), tmp_path, ARTIFACT_IDS=[first, second], **database
    )
    assert code == 0 and len(report["results"]) == 2
    assert {r["data"]["asset"] for r in report["results"]} == {"one.test", "two.test"}


def test_tiny_decode_limit_truncated_zlib_and_actuator_total_record_limit():
    import zlib

    with pytest.raises(ValueError, match="byte limit"):
        list(transformations(base64.b64encode(b"abcdef"), 4))
    with pytest.raises(ValueError, match="Truncated"):
        list(transformations(zlib.compress(b"abc")[:-1], 100))
    result = actuator(
        {
            "mappings": [
                {
                    "requestMappingConditions": {
                        "patterns": ["/one", "/two"],
                        "methods": ["GET", "POST"],
                    }
                }
            ]
            * 100
        },
        maximum=1,
    )
    assert result["coverage_limited"] and len(result["routes"]) <= 1


def test_numeric_secret_redaction_and_unsigned_jwt_claims(tmp_path):
    from fieldkit.core.redaction import redact

    assert redact({"password": 123456})["password"] == "[REDACTED]"
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ2ZW5kb3IifQ."
    database = db_settings(tmp_path)
    with Vault(database["DATABASE"]) as vault:
        capture(vault, body=json.dumps({"access_token": token}).encode())
    code, report, _ = run_local(AuthFlowMapper(), tmp_path, **database)
    assert code == 0 and report["results"][0]["data"]["tokens"][0]["claims"]["sub"] == "vendor"
    assert token not in json.dumps(report)


def test_xxe_reflected_callback_url_marker_does_not_confirm_entity_resolution(
    tmp_path, monkeypatch
):
    from fieldkit.modules.injection import XXECheck

    requests = write_json(
        tmp_path,
        "requests.json",
        {"id": "xml", "url": "/xml", "method": "POST", "xml": "<r><value>original</value></r>"},
    )
    code, report, _, _ = network_run(
        XXECheck(),
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200, content=req.content),
        REQUESTS_FILE=requests,
        REQUEST_IDS=["xml"],
        LOCATIONS=["xml:value"],
        CALLBACK_URL="https://operator-marker.test",
        ENTITY_MARKER="operator-marker",
    )
    assert code == 0 and not any(f["confidence"] == "confirmed" for f in report["findings"])
    assert not report["results"][0]["external_content_observed"]


def test_auth_matrix_rejects_captured_body_session_tokens(tmp_path):
    from fieldkit.modules.auth_matrix import AuthMatrix

    matrix = write_json(
        tmp_path,
        "matrix.json",
        {
            "identities": {"owner": "anonymous"},
            "objects": [
                {
                    "id": "job-7",
                    "owner": "owner",
                    "request": {
                        "url": "/replay",
                        "method": "POST",
                        "json": {"access_token": "owner-secret"},
                    },
                    "checks": {"contains": "job-7"},
                }
            ],
            "rules": [{"identity": "owner", "resource": "job-7", "expected": "allow"}],
        },
    )
    module = AuthMatrix()
    with pytest.raises(ValueError, match="per identity"):
        module.validate({**module.defaults(), "MATRIX_FILE": matrix})
