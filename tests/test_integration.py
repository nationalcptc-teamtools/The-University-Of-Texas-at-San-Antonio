"""Integration tests use synthetic content, real bwrap, and real age encryption."""
from dataclasses import asdict, replace
import hashlib
import base64
from datetime import datetime, timedelta, timezone
import http.server
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import threading
import pytest
from cptc_harness.contracts import (
    ClockState,
    OperationRequest,
    PolicyError,
    PolicySnapshot,
    ScopeSpec,
    TargetPolicy,
    TargetRef,
    canonical_json,
    digest,
)
from cptc_harness.integrity import VerifiedRelease
from cptc_harness.profile_runtime.catalog import load_profile
from cptc_harness.exports import prepare_export, encrypted_export
from cptc_harness.policy import parse_policy, save_policy
from cptc_harness.providers import (ChatAdapter, DisclosureGate, DisclosureItem, ExcerptApproval,
    ProviderProfile, parse_response, render_template, validate_profile)
from cptc_harness.runtime import Runtime, initialize
from cptc_harness.storage import private_directory, write_json

ROOT = Path(__file__).parents[1]


@pytest.fixture
def private(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path


@pytest.fixture
def age_identity(private):
    age, keygen = ROOT / ".tools/age", ROOT / ".tools/age-keygen"
    if not age.exists() or not keygen.exists():
        pytest.skip("bootstrap pinned age with scripts/bootstrap-harness.py --install-age")
    identity = private / "test-identity"
    subprocess.run([str(keygen), "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.run([str(keygen), "-y", str(identity)], check=True, capture_output=True, text=True).stdout.strip()
    return age, identity, recipient


def test_policy_rejects_broadened_contract_and_limits():
    policy = PolicySnapshot("synthetic", "v1", "workspace", "device", "operator", ScopeSpec())
    assert parse_policy(asdict(policy)) == policy
    for key, value in (("model_calls", 7), ("http_rate", 2), ("model_actions", True), ("unknown", "injected"), ("encrypted_storage", "yes")):
        with pytest.raises(PolicyError):
            parse_policy({**asdict(policy), key: value})


def test_disclosure_denies_client_raw_and_split_excerpts():
    profile = ProviderProfile("synthetic", "openai", "https://provider.example", "/chat", "slow", ("192.0.2.1",))
    gate = DisclosureGate()
    for classification in ("client_confidential", "restricted_raw", "secret", "approved_excerpt"):
        with pytest.raises(PolicyError):
            gate.prepare(profile, (DisclosureItem("item", classification, {"value": "client-derived"}),))
    with pytest.raises(PolicyError):
        gate.prepare(profile, tuple(DisclosureItem(f"part{i}", "synthetic", "x" * 1024) for i in range(9)))
    with pytest.raises(PolicyError):
        validate_profile(replace(profile, approved_client=True, upstream_tools="unknown"))
    client = replace(profile, approved_client=True, upstream_tools="disabled", upstream_evidence="fixture-attestation", authorization="fixture-sow", retention="fixture-only", reviewed_by="operator", permitted_categories=("client_confidential", "approved_excerpt"))
    excerpt = "exact synthetic excerpt"
    approval = ExcerptApproval("approve1", "a" * 64, hashlib.sha256(canonical_json(excerpt)).hexdigest(), digest(asdict(client)), 128, "operator")
    gate = DisclosureGate(approvals=(approval,))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.generate()
    client = replace(client, capability_key=base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(), capability_config_sha256="b" * 64)
    approval = replace(approval, profile_hash=digest(asdict(client)))
    gate = DisclosureGate(approvals=(approval,))
    payload = {"nonce": "fixture", "origin": client.origin, "model": client.model, "config_sha256": client.capability_config_sha256,
               "retention_sha256": hashlib.sha256(client.retention.encode()).hexdigest(), "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat(),
               "tools": [], "plugins": [], "browsing": False, "uploads": False}
    gate.accept_capability(client, json.dumps({"payload": payload, "signature": base64.b64encode(key.sign(canonical_json(payload))).decode()}), "fixture")
    assert "exact synthetic excerpt" in gate.prepare(client, (DisclosureItem("e", "approved_excerpt", excerpt, "a" * 64, "approve1"),))
    for altered in (replace(client, path="/other"), replace(client, retention="changed")):
        with pytest.raises(PolicyError):
            gate.prepare(altered, (DisclosureItem("e", "approved_excerpt", excerpt, "a" * 64, "approve1"),))


def test_complete_streams_only_and_captured_template():
    profile = ProviderProfile("fixture", "openai", "https://provider.example", "/chat", "slow", ("192.0.2.1",), response_format="sse")
    raw = 'data: {"choices":[{"delta":{"content":"{}"},"finish_reason":null}]}\n\n'
    with pytest.raises(PolicyError):
        parse_response(raw, profile)
    assert parse_response(raw + 'data: [DONE]\n\n', profile)[0] == "{}"
    with pytest.raises(PolicyError):
        parse_response('data: {"choices":[{"delta":{"tool_calls":[{}]},"finish_reason":"stop"}]}\n\n', profile)
    assert render_template({"messages": "{{messages}}"}, [], "synthetic") == {"messages": []}
    for value in ({"prompt": "prefix {{prompt}}"}, {"cookie": "synthetic", "prompt": "{{prompt}}"}, {"prompt": "{{prompt}}", "tools": []}, {"prompt": "none"}):
        with pytest.raises(PolicyError):
            render_template(value, [], "synthetic")


def test_real_isolated_provider_roundtrip_and_unapproved_dns():
    if not shutil.which("bwrap"):
        pytest.skip("bwrap required for OS isolation integration test")
    requests = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            raw = json.dumps({"choices": [{"message": {"content": '{"action":"finish","status":"complete"}'}}], "model": "synthetic-actual", "usage": {"total_tokens": 10}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        profile = ProviderProfile("fixture", "openai", f"http://127.0.0.1:{server.server_port}", "/chat", "synthetic", ("127.0.0.1",), timeout_s=5)
        adapter = ChatAdapter(profile)
        session = adapter.create_session()
        response = adapter.send(session, (DisclosureItem("fixture", "synthetic", {"id": 1}),))
        assert response.reported_model == "synthetic-actual" and response.usage["total_tokens"] == 10
        assert len(requests) == 1 and "tools" not in requests[0]
        with pytest.raises(PolicyError):
            adapter.send(session, (DisclosureItem("client", "client_confidential", "do not send"),))
        assert len(requests) == 1
        adapter.cancel(session)
        with pytest.raises(PolicyError):
            adapter.send(session, (DisclosureItem("fixture", "synthetic", {}),))
        wrong = ChatAdapter(replace(profile, allowed_addresses=("127.0.0.2",)))
        with pytest.raises(PolicyError):
            wrong.send(wrong.create_session(), (DisclosureItem("fixture", "synthetic", {}),))
        assert len(requests) == 1
    finally:
        server.shutdown()
        server.server_close()


def test_encrypted_export_exact_review_wrong_key_and_source_preservation(private, age_identity):
    age, identity, recipient = age_identity
    root = private_directory(private / "engagement", create=True)
    private_directory(root / "artifacts", create=True)
    write_json(root / "artifacts/fixture.json", {"fixture": "synthetic", "status": "observed"})
    before = (root / "artifacts/fixture.json").read_bytes()
    review = prepare_export(root, ("artifacts/fixture.json",), operator="synthetic-operator")
    with pytest.raises(PolicyError):
        encrypted_export(review, private / "wrong.age", approved_hash="bad", recipient=recipient, age=age, verify_identity=identity)
    wrong_identity = private / "wrong-key"
    subprocess.run([str(ROOT / ".tools/age-keygen"), "-o", str(wrong_identity)], check=True, capture_output=True)
    with pytest.raises(PolicyError):
        encrypted_export(review, private / "wrong.age", approved_hash=review.review_hash, recipient=recipient, age=age, verify_identity=wrong_identity)
    assert not (private / "wrong.age").exists()
    result = encrypted_export(review, private / "closed.age", approved_hash=review.review_hash, recipient=recipient, age=age, verify_identity=identity)
    assert result["decryption_verified"] and result["verified"]
    assert (root / "artifacts/fixture.json").read_bytes() == before
    assert b"synthetic" not in (private / "closed.age").read_bytes()
    write_json(root / "artifacts/fixture.json", {"changed": True})
    with pytest.raises(PolicyError):
        encrypted_export(review, private / "changed.age", approved_hash=review.review_hash, recipient=recipient, age=age, verify_identity=identity)
    assert not (private / "changed.age").exists()


def test_runtime_offline_import_and_confidential_coverage(private, age_identity):
    age, identity, recipient = age_identity
    policy = PolicySnapshot("fixture", "v1", "workspace", "device", "operator", ScopeSpec(("192.0.2.0/24",)))
    source = private / "policy-source.json"
    save_policy(source, policy)
    root = private / "engagement"
    initialize(root, source, recipient=recipient, age_binary=age)
    runtime = Runtime(root, ledger_root=private / "ledger")
    fixture = private / "scan.xml"
    fixture.write_text('<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>')
    fixture.chmod(0o600)
    try:
        result = runtime.run("network.nmap_import", input_path=fixture)
        assert result["result"]["status"] == "complete", result
        assert result["classification"] == "client_confidential"
        assert runtime.coverage()["classification"] == "client_confidential"
        denied = runtime.run("exploitation.zerologon")
        assert denied["result"]["status"] == "blocked"
        assert runtime.audit.verify().valid
    finally:
        runtime.audit.close()


def test_runtime_persists_profile_wire_receipt_through_isolated_audit_service(
    private, age_identity
):
    age, _identity, recipient = age_identity
    target = TargetRef(
        "cptc11-prod-portcast",
        "http://10.0.1.30:8096/System/Info/Public",
        "http",
        "10.0.1.30",
        8096,
        "/System/Info/Public",
    )
    now = datetime.now(timezone.utc)
    policy = PolicySnapshot(
        "portcast-synthetic",
        "v1",
        "workspace",
        "device",
        "operator",
        ScopeSpec(("10.0.1.30/32",)),
        targets=(
            TargetPolicy(
                target,
                True,
                "reviewed-synthetic-portcast",
                "workspace",
                "",
                ("web.portcast_identity",),
                request_limit=1,
            ),
        ),
        window_start=(now - timedelta(minutes=1)).isoformat(),
        window_end=(now + timedelta(minutes=5)).isoformat(),
        sow_reference="synthetic-sow",
        roe_reference="synthetic-roe",
        model_calls=0,
        model_actions=0,
    )
    source = private / "portcast-policy.json"
    save_policy(source, policy)
    root = private / "portcast-runtime"
    initialize(root, source, recipient=recipient, age_binary=age)
    body = b'{"ProductName":"Jellyfin Server","Version":"10.10.7"}'
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Encoding: identity\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )

    profile = load_profile("web.http_jellyfin_public_identity")
    worker_sha256 = hashlib.sha256(
        (ROOT / "cptc_harness/profile_runtime/worker.py").read_bytes()
    ).hexdigest()
    release = VerifiedRelease(
        "portcast-live-v1",
        "3" * 64,
        {},
        {profile.profile_id: worker_sha256},
        {profile.profile_id: (worker_sha256,)},
    )
    runtime = Runtime(
        root,
        ledger_root=private / "portcast-ledger",
        verified_release=release,
    )
    from tests.profile_runtime.test_portcast_broker import SyntheticWireBroker

    runtime.attach_profile_wire_broker(SyntheticWireBroker(runtime.ledger, raw, []))
    runtime.broker.clock = ClockState(True, 0, "synthetic")
    request = OperationRequest(
        "portcast-action",
        "workspace",
        "device",
        "operator",
        "web.portcast_identity",
        target,
        {"profile_id": profile.profile_id},
        "operator",
        None,
        "v1",
        "portcast-wave",
    )
    result = runtime.broker.execute(request, actor="operator")
    assert result.status == "complete"
    receipts = runtime.audit.profile_wire_receipts()
    assert receipts["portcast-action"]["outcome"] == "complete"
    assert receipts["portcast-action"]["evidence_bytes"] == len(raw)
    runtime.close()

    reopened = Runtime(
        root,
        ledger_root=private / "portcast-ledger",
        verified_release=release,
    )
    assert reopened.audit.profile_wire_receipts() == receipts
    reopened.close()
