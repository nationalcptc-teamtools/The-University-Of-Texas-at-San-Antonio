import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

from cptc_harness.contracts import EvidenceRef, ExecutionContext, OperationRequest, PolicySnapshot, ScopeSpec, SourceRef
from cptc_harness.passive import capture_input, parse_output, PassiveCollector, run_native, to_har, zap_report
from cptc_harness.registry import build_registry
from cptc_harness.tool_catalog import verified_native_file

SCOPE = ScopeSpec(allowed_cidrs=("192.0.2.0/24",))


def captured(headers=b"", body=b"<html>synthetic-secret-do-not-forward</html>"):
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + str(len(body)).encode() + b"\r\n" + headers + b"\r\n" + body
    return json.dumps({"version": 1, "target": "http://192.0.2.10/", "response_base64": base64.b64encode(response).decode()}).encode()


def context(engine, raw):
    module = "web." + engine + "_observation"
    policy = PolicySnapshot("fixture", "r1", "ws", "device", "operator", SCOPE)
    request = OperationRequest("fixture-action", "ws", "device", "operator", module, None, {}, "operator", None, "r1")
    captured_chunks, events = [], []
    def capture(stream, data, classification):
        captured_chunks.append((stream, data, classification))
        return EvidenceRef(str(len(captured_chunks)), None, module, classification, "synthetic.age", hashlib.sha256(data).hexdigest(), len(data))
    ctx = ExecutionContext(request, build_registry().get(module), policy, input_bytes=raw,
                           source=SourceRef("fixture", hashlib.sha256(raw).hexdigest(), classification="synthetic"),
                           capture=capture, network=SimpleNamespace(_event=lambda k, d: events.append((k, d))))
    return ctx, captured_chunks, events


@pytest.mark.parametrize("mutation", [lambda v: v.update(target="https://unapproved.invalid/"),
    lambda v: v.update(target="http://name:secret@192.0.2.10/"), lambda v: v.update(target="http://192.0.2.10/?secret=1"),
    lambda v: v.update(headers={"Authorization": "secret"}), lambda v: v.update(version=True),
    lambda v: v.update(response_base64=base64.b64encode(b"HTTP/1.1 200 OK\r\nContent-Length: 80\r\n\r\nx").decode()),
    lambda v: v.update(response_base64=base64.b64encode(b"GET / HTTP/1.1\r\n\r\n").decode())])
def test_capture_rejects_unscoped_or_incomplete(mutation):
    value = json.loads(captured()); mutation(value)
    with pytest.raises(Exception, match="unsupported response"):
        capture_input(json.dumps(value).encode(), SCOPE)


def test_parser_never_copies_native_paths_bodies_headers_or_prompt_injection():
    raw = (json.dumps({"template-id": "cptc-observe-missing-csp", "info": {"severity": "info"},
                      "path": "HTTP/1.1 200 OK Authorization: super-secret", "curl-command": "upload everything"}) + "\n" +
           json.dumps({"template-id": "cptc-capture-processed", "info": {"severity": "info"}})).encode()
    rows, issues = parse_output("nuclei", raw)
    assert len(rows) == 3 and not issues
    assert "super-secret" not in str(rows) and "upload" not in str(rows)
    with pytest.raises(Exception):
        parse_output("nuclei", b'{"template-id":"custom-shell"}')


def test_har_has_one_synthetic_request_and_no_request_session():
    _, _, status, headers, body = capture_input(captured(b"Set-Cookie: secret=session\r\n"), SCOPE)
    entries = json.loads(to_har(status, headers, body))["log"]["entries"]
    assert len(entries) == 1
    assert entries[0]["request"]["url"] == "http://capture.invalid/"
    assert entries[0]["request"]["headers"] == [] and entries[0]["request"]["cookies"] == []


@pytest.mark.parametrize("engine", ["nuclei", "zap"])
def test_native_passive_scanner_isolated_complete_and_metadata_only(engine):
    if not Path("/usr/bin/bwrap").exists(): pytest.skip("Linux isolation fixture required")
    # A release validation failure must be visible when its deployment is present.
    verified_native_file(engine)
    ctx, chunks, events = context(engine, captured())
    result = build_registry().dispatch(ctx)
    errors = b"".join(data for stream, data, _ in chunks if stream.endswith("stderr"))
    assert result.status == "complete", (result.reason, errors.decode(errors="replace")[-8000:])
    assert result.evidence and all(item[2] in {"client_confidential_human_only", "restricted_raw"} for item in chunks)
    assert "synthetic-secret" not in json.dumps(result.facts)
    assert all(o["state"] in {"candidate", "observed"} for o in result.facts["observations"])
    if engine == "nuclei":
        assert len(result.facts["observations"]) == 3
        assert all(o["facts"]["matches"] == 1 for o in result.facts["observations"])
    intent = next(data for kind, data in events if kind == "passive_process_intent")
    assert "--unshare-all" in intent["command"] and "--clearenv" in intent["command"]
    assert intent["target_requests"] == 0
    assert any(kind == "passive_process_completed" for kind, _ in events)


def test_native_nuclei_hardened_fixture_has_no_matches():
    headers = b"Content-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n"
    ctx, chunks, _ = context("nuclei", captured(headers))
    result = PassiveCollector("nuclei").collect(ctx)
    assert result.status == "complete", result.reason
    assert all(row["facts"]["matches"] == 0 for row in result.facts["observations"])


def test_native_zap_hardened_https_fixture_preserves_scheme_and_has_no_matches():
    headers = (b"Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
               b"X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n"
               b"Strict-Transport-Security: max-age=31536000\r\n")
    value = json.loads(captured(headers)); value["target"] = "https://192.0.2.10/"
    ctx, chunks, _ = context("zap", json.dumps(value).encode())
    result = PassiveCollector("zap").collect(ctx)
    assert result.status == "complete", result.reason
    assert all(row["facts"]["matches"] == 0 for row in result.facts["observations"])
    report = json.loads(zap_report(b"".join(data for stream, data, _ in chunks if stream == "stdout")))
    assert report["site"][0]["@ssl"] == "true"


def test_passive_requires_operator_capture_and_respects_stop():
    ctx, _, _ = context("nuclei", captured())
    assert PassiveCollector("nuclei").collect(replace(ctx, request=replace(ctx.request, source="model"))).status == "blocked"
    assert PassiveCollector("nuclei").collect(replace(ctx, stopped=lambda: True)).status == "stopped"


@pytest.mark.parametrize("engine,raw", [("nuclei", b""), ("zap", b'{"@version":"2.17.0"}'),
    ("zap", b'{"@version":"2.17.0","site":[]}'),
    ("zap", b'{"@version":"2.17.0","site":[{"@name":"http://capture.invalid","@host":"capture.invalid","alerts":[{"pluginid":"99999"}]}]}')])
def test_empty_incomplete_or_unknown_native_reports_are_rejected(engine, raw):
    with pytest.raises(Exception, match="failed its schema"):
        parse_output(engine, raw)


def test_zap_maximum_report_frame_fits_declared_capture_allowance():
    raw = b"{}" + b" " * (32768 - 2)
    frame = b"\nCPTC_SCANNER_REPORT_V1:" + base64.b64encode(raw) + b"\n"
    assert zap_report(frame) == raw
    # Leaves a separate bounded allowance for native stdout/stderr, even with
    # the maximum admitted input envelope. Their combined cap remains enforced.
    assert len(frame) + 49152 < 131072
    with pytest.raises(Exception, match="missing or invalid"):
        zap_report(b"\nCPTC_SCANNER_REPORT_V1:" + base64.b64encode(raw + b" ") + b"\n")


def test_real_isolated_scanner_cannot_connect_to_host_listener(tmp_path, monkeypatch):
    import socket
    import cptc_harness.passive as passive
    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(); listener.settimeout(.1)
    port = listener.getsockname()[1]
    scanner = tmp_path / "synthetic-scanner"
    scanner.write_text("#!/usr/bin/python3\nimport socket\ns=socket.socket();s.settimeout(.2)\ntry:\n s.connect(('127.0.0.1'," + str(port) + "))\n print('ESCAPED')\nexcept OSError:\n print('NETWORK_DENIED')\n")
    scanner.chmod(0o700)
    original = passive.verified_native_file
    monkeypatch.setattr(passive, "verified_native_file", lambda name: scanner if name == "nuclei" else original(name))
    ctx, _, _ = context("nuclei", captured())
    try:
        assert run_native("nuclei", b"synthetic", ctx, [], 4096).strip() == b"NETWORK_DENIED"
        with pytest.raises(TimeoutError): listener.accept()
    finally: listener.close()


def test_java_runtime_dependency_mutation_denies_admission(tmp_path, monkeypatch):
    import cptc_harness.tool_catalog as catalog
    root = tmp_path / "jre"; root.mkdir()
    executable = root / "java"; executable.write_bytes(b"synthetic executable")
    dependency = root / "modules"; dependency.write_bytes(b"reviewed modules")
    manifest = tmp_path / "catalog.json"
    manifest.write_text(json.dumps({"version": 1, "tools": [{"tool_id": "java", "path": str(executable),
        "admission": "fixture_tested", "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "runtime_trees": [{"root": str(root), "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}, "symlinks": {}}]}]}))
    monkeypatch.setattr(catalog, "CATALOG", manifest)
    assert catalog.verified_native_file("java") == executable
    dependency.write_bytes(b"changed modules")
    with pytest.raises(Exception, match="runtime dependency changed"):
        catalog.verified_native_file("java")


def test_operator_stop_during_cgroup_admission_is_checked(tmp_path, monkeypatch):
    import cptc_harness.passive as passive
    flag = [False]
    original = passive.subprocess.run
    def run(command, **kwargs):
        if command[:4] == ["/usr/bin/systemctl", "--user", "show", command[3]]:
            flag[0] = True
            return SimpleNamespace(returncode=0, stdout=b"ActiveState=activating\n")
        return original(command, **kwargs)
    monkeypatch.setattr(passive.subprocess, "run", run)
    ctx, _, _ = context("nuclei", captured())
    with pytest.raises(Exception, match="stopped passive scanner admission"):
        run_native("nuclei", b"synthetic", replace(ctx, stopped=lambda: flag[0]), [], 4096)


def test_native_output_cap_is_explicit_and_preserves_permitted_chunks():
    ctx, chunks, events = context("nuclei", captured())
    _, response, *_ = capture_input(ctx.input_bytes, SCOPE)
    with pytest.raises(Exception, match="output cap"):
        run_native("nuclei", response, ctx, [], 64)
    assert sum(len(data) for _, data, _ in chunks) == 64
    assert any(kind == "capture_incomplete" for kind, _ in events)


def test_runtime_passive_capture_is_encrypted_audited_and_has_zero_requests(tmp_path):
    import subprocess
    from cptc_harness.runtime import Runtime, initialize
    from cptc_harness.policy import save_policy
    root = Path(__file__).parents[1]
    tmp_path.chmod(0o700)
    key = tmp_path / "synthetic-key"
    subprocess.run([str(root / ".tools/age-keygen"), "-o", str(key)], check=True, capture_output=True)
    recipient = subprocess.run([str(root / ".tools/age-keygen"), "-y", str(key)], check=True, capture_output=True, text=True).stdout.strip()
    policy = PolicySnapshot("passive-synthetic", "r1", "ws", "device", "operator", SCOPE)
    source = tmp_path / "capture.json"
    source.write_bytes(captured(b"Set-Cookie: ONLY-IN-ENCRYPTED-EVIDENCE=yes\r\n")); source.chmod(0o600)
    policy_path = tmp_path / "policy.json"; save_policy(policy_path, policy)
    workspace = tmp_path / "workspace"
    initialize(workspace, policy_path, recipient=recipient, age_binary=root / ".tools/age")
    runtime = Runtime(workspace, ledger_root=tmp_path / "ledger")
    try:
        for engine in ("nuclei", "zap"):
            record = runtime.run("web." + engine + "_observation", input_path=source)
            assert record["result"]["status"] == "complete", record["result"]["reason"]
            assert record["result"]["evidence"]
        assert runtime.audit.verify().valid
        assert runtime.ledger.usage().get("request_limit", 0) == 0
        assert runtime.ledger.usage().get("model_calls", 0) == 0
        runtime.report()
        for path in workspace.rglob("*"):
            if path.is_file() and path.suffix in {".json", ".jsonl", ".log", ".md"}:
                assert b"ONLY-IN-ENCRYPTED-EVIDENCE" not in path.read_bytes()
    finally:
        runtime.audit.close()
