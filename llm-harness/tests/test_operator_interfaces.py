"""Real operator signing/MCP integration and central clock jump behavior."""
import asyncio
import base64
from dataclasses import asdict
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest
import cptc_harness.clockcheck as clockcheck
from cptc_harness.clockcheck import (
    CLOCK_ATTESTATION_TTL_NS,
    ClockService,
    parse_clock_attestation,
)
from cptc_harness.contracts import ClockState, PolicyError, PolicySnapshot, ScopeSpec, Bounds, digest, AuditEvent
from cptc_harness.policy import save_policy
from cptc_harness.providers import ProviderProfile
from cptc_harness.runtime import Runtime, initialize
from cptc_harness.signing import SigningReference, public_key
from cptc_harness.storage import atomic_write, write_json
from test_integration import age_identity, private


def test_real_signing_worker_reads_only_operator_key_reference(private):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    key_path, pub_path = private / "synthetic-key.pem", private / "synthetic-public.pem"
    atomic_write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    atomic_write(pub_path, key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    payload = b"synthetic recipient-bound handover"
    signature = SigningReference(key_path)(payload)
    key.public_key().verify(signature, payload)
    encoded, fingerprint = public_key(pub_path)
    assert hashlib.sha256(base64.b64decode(encoded)).hexdigest() == fingerprint
    assert len(signature) == 64
    key_path.chmod(0o644)
    with pytest.raises(PolicyError):
        SigningReference(key_path)(payload)


def test_stdio_mcp_exposes_bounded_tools_and_durable_stop(private, age_identity):
    mcp = pytest.importorskip("mcp")
    from mcp.client.stdio import stdio_client, StdioServerParameters
    age, identity, recipient = age_identity
    source = private / "policy.json"
    save_policy(source, PolicySnapshot("synthetic", "v1", "workspace", "device", "operator", ScopeSpec()))
    root, ledger = private / "engagement", private / "ledger"
    initialize(root, source, recipient=recipient, age_binary=age)
    runtime = Runtime(root, ledger_root=ledger)
    profile = ProviderProfile("fixture", "openai", "https://provider.example", "/chat", "synthetic", ("192.0.2.1",))
    profile_path = private / "provider.json"
    write_json(profile_path, asdict(profile))
    runtime.workflows.create("mcp-test", profile, ("network.output_import",), target_id=None, synthetic=True)
    runtime.audit.close()
    script = "from pathlib import Path; from cptc_harness.runtime import Runtime; from cptc_harness.providers import load_profile; from cptc_harness.mcp_server import serve; import sys; serve(Runtime(Path(sys.argv[1]),ledger_root=Path(sys.argv[2])), 'mcp-test', load_profile(Path(sys.argv[3])))"
    async def check():
        params = StdioServerParameters(command=sys.executable, args=["-c", script, str(root), str(ledger), str(profile_path)],
                                       cwd=str(Path(__file__).parents[1]))
        async with stdio_client(params) as (reader, writer):
            async with mcp.ClientSession(reader, writer) as session:
                await session.initialize()
                result = await session.list_tools()
                assert {t.name for t in result.tools} == {"cptc_capabilities", "cptc_action", "cptc_stop"}
                result = await session.list_resources()
                assert result.resources == []
                result = await session.call_tool("cptc_action", {"module_id": "shell", "arguments": {"command": "upload"}})
                assert "blocked" in str(result)
                result = await session.call_tool("cptc_capabilities", {})
                assert "network.output_import" in str(result)
                result = await session.call_tool("cptc_stop", {})
                assert "stopped" in str(result)
    asyncio.run(check())


def test_workspace_recreation_does_not_reset_identity_or_counters(private, age_identity):
    age, identity, recipient = age_identity
    source = private / "policy.json"
    policy = PolicySnapshot("synthetic", "v1", "workspace", "device", "operator", ScopeSpec())
    save_policy(source, policy)
    root, ledger = private / "engagement", private / "ledger"
    initialize(root, source, recipient=recipient, age_binary=age)
    runtime = Runtime(root, ledger_root=ledger)
    runtime.ledger.charge("one", "model_calls", 1, workflow_id="workflow")
    runtime.audit.close()
    copied = private / "copy"
    initialize(copied, source, recipient=recipient, age_binary=age)
    with pytest.raises(PolicyError, match="enrollment"):
        Runtime(copied, ledger_root=ledger)
    reopened = Runtime(root, ledger_root=ledger)
    assert reopened.ledger.usage("workflow")["model_calls"] == 1
    reopened.audit.close()


def test_runtime_shares_one_clock_service_between_audit_and_broker(private, age_identity):
    age, _identity, recipient = age_identity
    policy_path = private / "policy.json"
    save_policy(
        policy_path,
        PolicySnapshot("synthetic", "v1", "clock-workspace", "device", "operator", ScopeSpec()),
    )
    root = private / "engagement"
    initialize(root, policy_path, recipient=recipient, age_binary=age)
    clock = ClockService(source=lambda: ClockState(True, 0.01, "synthetic"))
    runtime = Runtime(root, ledger_root=private / "ledger", clock_service=clock)
    try:
        assert runtime.audit.clock is clock
        assert runtime.broker.clock is clock
    finally:
        runtime.close()


def test_central_clock_jumps_latch_and_never_change_host_time():
    times = {"wall": 100.0, "mono": 10.0}
    service = ClockService(source=lambda: ClockState(True, 0.01, "synthetic"), wall=lambda: times["wall"], monotonic=lambda: times["mono"])
    assert service().synchronized
    times.update(wall=101.0, mono=11.0)
    assert service().synchronized
    times.update(wall=95.0, mono=12.0)
    assert not service().synchronized and service().source == "local-clock-jump"
    times.update(wall=103.0, mono=13.0)
    assert not service().synchronized


def test_clock_attestation_is_bound_to_boot_and_monotonic_expiry():
    value = {
        "version": 1,
        "boot_id": "11111111-2222-4333-8444-555555555555",
        "observed_utc": "2026-09-11T00:00:00.000000Z",
        "expires_utc": "2026-09-11T00:00:30.000000Z",
        "observed_monotonic_ns": 100,
        "expires_monotonic_ns": 100 + CLOCK_ATTESTATION_TTL_NS,
        "synchronized": True,
        "offset_s": 0.001,
        "source": "timedatectl",
    }
    assert parse_clock_attestation(
        json.dumps(value),
        boot_id=value["boot_id"],
        monotonic_ns=101,
        utc_now=datetime.fromisoformat("2026-09-11T00:00:01+00:00"),
    ).source == "timedatectl-attestation"
    with pytest.raises(ValueError, match="expired"):
        parse_clock_attestation(
            json.dumps(value),
            boot_id=value["boot_id"],
            monotonic_ns=value["expires_monotonic_ns"],
            utc_now=datetime.fromisoformat("2026-09-11T00:00:01+00:00"),
        )
    with pytest.raises(ValueError, match="boot identity"):
        parse_clock_attestation(
            json.dumps(value),
            boot_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            monotonic_ns=101,
            utc_now=datetime.fromisoformat("2026-09-11T00:00:01+00:00"),
        )


def test_attested_clock_must_cover_the_action_and_failure_latches(monkeypatch):
    calls = {"count": 0}

    def clock_read(*, minimum_remaining_s=0.0, **_kwargs):
        calls["count"] += 1
        if minimum_remaining_s >= 12:
            raise ValueError("insufficient lifetime")
        return ClockState(True, 0.001, "timedatectl-attestation")

    monkeypatch.setattr(clockcheck, "read_clock_attestation", clock_read)
    service = ClockService(
        source=clockcheck.attested_clock,
        wall=lambda: 100.0,
        monotonic=lambda: 10.0,
    )

    assert service.valid_for(12.0) is False
    assert service().synchronized is False
    monkeypatch.setattr(
        clockcheck,
        "read_clock_attestation",
        lambda **_kwargs: ClockState(
            True, 0.001, "timedatectl-attestation"
        ),
    )
    assert service.valid_for(1.0) is False
    assert calls["count"] == 2


@pytest.mark.parametrize(
    "mutation",
    ("extra", "duplicate", "wide_expiry", "integer_offset", "bad_utc"),
)
def test_clock_attestation_parser_rejects_ambiguous_fields(mutation):
    value = {
        "version": 1,
        "boot_id": "11111111-2222-4333-8444-555555555555",
        "observed_utc": "2026-09-11T00:00:00.000000Z",
        "expires_utc": "2026-09-11T00:00:30.000000Z",
        "observed_monotonic_ns": 100,
        "expires_monotonic_ns": 100 + CLOCK_ATTESTATION_TTL_NS,
        "synchronized": True,
        "offset_s": 0.001,
        "source": "timedatectl",
    }
    raw = json.dumps(value)
    if mutation == "extra":
        value["path"] = "/etc/passwd"
        raw = json.dumps(value)
    elif mutation == "duplicate":
        raw = raw[:-1] + ',"source":"timedatectl"}'
    elif mutation == "wide_expiry":
        value["expires_monotonic_ns"] += 1
        raw = json.dumps(value)
    elif mutation == "integer_offset":
        value["offset_s"] = 1
        raw = json.dumps(value)
    else:
        value["observed_utc"] = "2026-09-11T00:00:00Z"
        raw = json.dumps(value)
    with pytest.raises(ValueError):
        parse_clock_attestation(
            raw,
            boot_id=value["boot_id"],
            monotonic_ns=101,
            utc_now=datetime.fromisoformat("2026-09-11T00:00:01+00:00"),
        )


def test_imported_accounting_survives_audit_failure_and_destination_stops(private, age_identity, monkeypatch):
    from cptc_harness.ledger import Ledger
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    source = Ledger(private / "source-ledger", "synthetic", "source", policy_revision="v1")
    source.charge("one", "model_calls", 1, workflow_id="workflow")
    source.stop("operator handover")
    seal = source.seal_for_handover("destination", "a" * 64)
    bundle = source.handover_bundle(seal, key.sign)
    age, identity, recipient = age_identity
    policy = private / "policy.json"
    save_policy(policy, PolicySnapshot("synthetic", "v1", "workspace", "destination", "operator", ScopeSpec()))
    root = private / "engagement"
    initialize(root, policy, recipient=recipient, age_binary=age)
    runtime = Runtime(root, ledger_root=private / "destination-ledger")
    emit = runtime.audit.emit
    def fail(event):
        if event.kind == "handover_import_result":
            raise OSError("synthetic audit failure after merge")
        return emit(event)
    monkeypatch.setattr(runtime.audit, "emit", fail)
    try:
        with pytest.raises(PolicyError, match="destination stopped"):
            runtime.import_handover(bundle, {"source": public}, "a" * 64, digest(asdict(bundle)))
        assert runtime.ledger.stopped() and runtime.ledger.usage()["model_calls"] == 1
        with pytest.raises(PolicyError):
            runtime.ledger.reserve("next", Bounds(), workspace_id="workspace")
    finally:
        runtime.audit.close()


def test_offline_timeline_preserves_original_events_and_rejects_tampering(private):
    from cptc_harness.audit import AuditWriter
    from cptc_harness.exports import offline_timeline
    sources = []
    originals = []
    for device in ("a", "b"):
        root = private / device
        audit = AuditWriter(root, PolicySnapshot("synthetic", "v1", "workspace-" + device, device, "operator", ScopeSpec()))
        audit.emit(AuditEvent("synthetic_complete"))
        originals.append(json.loads(audit.path.read_text()))
        audit.rotate()
        audit.close()
        sources.append(root)
    output = private / "timeline.json"
    assert offline_timeline(tuple(sources), output)["events"] == 2
    merged = json.loads(output.read_text())
    assert merged["source_integrity_verified"] and merged["events"] == sorted(originals, key=lambda x: (x["timestamp"], x["device_id"], x["seq"]))
    next(sources[0].glob("segments/*/audit.jsonl")).write_bytes(b"tampered")
    with pytest.raises(PolicyError):
        offline_timeline(tuple(sources), private / "bad.json")
