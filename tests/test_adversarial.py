"""Independent regression cases for reviewed boundary failures."""
import base64
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import pytest
from cptc_harness.audit import AuditWriter
from cptc_harness.contracts import *
from cptc_harness.ledger import Ledger
from cptc_harness.migrations import migrate_legacy
from cptc_harness.network import NetworkBroker
from cptc_harness.providers import DisclosureGate, DisclosureItem, ProviderProfile


def policy():
    target = TargetRef("app", "http://approved.example:80/app/", "http", "approved.example", 80, "/app/")
    return PolicySnapshot("fixture", "v1", "workspace", "device", "operator",
        ScopeSpec(("192.0.2.0/24",), (), ("approved.example",)),
        (TargetPolicy(target, True, "fixture", "workspace", "", ("web.headers",)),))


def test_hostname_scope_never_bypasses_addresses_or_base_path():
    p = policy()
    def resolver(address):
        return lambda *a, **k: [(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))]
    for address in ("169.254.169.254", "127.0.0.1", "203.0.113.1", "::1", "fe80::1", "2001:db8::1"):
        with pytest.raises(PolicyError):
            NetworkBroker(p, resolver=resolver(address)).target_transport(p.targets[0].target)
    network = NetworkBroker(p, resolver=resolver("192.0.2.1"))
    transport = network.target_transport(p.targets[0].target)
    for path in ("/outside", "/appish/", "//evil.example/", "/app/%252e%252e/out", "/app/?secret=x", "/app/#x", "/app/../outside"):
        with pytest.raises(PolicyError):
            transport.request(TargetRequest(path=path))
    touched = []
    invalid = replace(p, targets=(replace(p.targets[0], target=replace(p.targets[0].target, host="unapproved.example", canonical_url="http://unapproved.example:80/app/")),))
    with pytest.raises(PolicyError):
        NetworkBroker(invalid, resolver=lambda *a, **k: touched.append(a)).target_transport(invalid.targets[0].target)
    assert not touched


def test_audit_unknown_capture_class_secret_keys_transcript_and_permissions(tmp_path):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy())
    audit.emit(AuditEvent("synthetic", data={"token": "DO-NOT-LOG", "nested": {"password": "ALSO-PRIVATE"}, "literal": "\x1b[31mline\r\n"}))
    assert audit.verify().valid
    assert b"DO-NOT-LOG" not in audit.path.read_bytes() and b"ALSO-PRIVATE" not in audit.transcript_path.read_bytes()
    assert b"\x1b" not in audit.transcript_path.read_bytes()
    with pytest.raises(PolicyError):
        audit.capture("action", "stdout", b"sensitive", "restrcted_typo")
    assert not list((tmp_path / "evidence").iterdir())
    assert not audit.ready()
    audit.transcript_path.write_bytes(b"tampered\n")
    assert not audit.verify().valid
    audit.close()


def test_audit_output_reservation_disk_failure_and_shared_cap(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    audit = AuditWriter(tmp_path, policy(), evidence_cap=8)
    audit.reserve_output("action", 6)
    audit.capture("action", "stdout", b"1234", "synthetic")
    with pytest.raises(PolicyError):
        audit.capture("action", "stderr", b"5678", "synthetic")
    assert not audit.ready()
    assert b'"retained_bytes":2' in audit.path.read_bytes()
    audit.close()
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    audit = AuditWriter(other, policy())
    def full(*args):
        raise OSError("fixture disk full")
    monkeypatch.setattr("os.posix_fallocate", full)
    with pytest.raises(PolicyError):
        audit.reserve_output("action", 10)
    assert not audit.ready()
    audit.close()


def test_signed_ledger_merge_review_replay_conflicts_and_consumption(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    tmp_path.chmod(0o700)
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    origin = Ledger(tmp_path / "origin", "fixture", "device-a", policy_revision="v1")
    origin.reserve("action", Bounds(request_limit=20), workspace_id="workspace", target_id="http://192.0.2.1:80")
    origin.finish("action", state="complete")
    with pytest.raises(PolicyError):
        origin.bundle(signer=key.sign)
    origin.stop("operator handover")
    seal = origin.seal_for_handover("device-b", "b" * 64)
    bundle = origin.handover_bundle(seal, signer=key.sign)
    receiver = Ledger(tmp_path / "receiver", "fixture", "device-b", policy_revision="v1")
    assert not receiver.merge(bundle).accepted
    reviewed = digest(asdict(bundle))
    assert receiver.merge_handover(bundle, {"device-a": public}, "b" * 64, reviewed).accepted
    assert receiver.usage(target_id="http://192.0.2.1:80")["request_limit"] == 20
    assert not receiver.merge_handover(bundle, {"device-a": public}, "b" * 64, reviewed).accepted
    with pytest.raises(PolicyError):
        receiver.reserve("new", Bounds(request_limit=5), workspace_id="workspace", target_id="http://192.0.2.1:80", limits={"request_limit": 24})
    forged = replace(bundle, device_id="forged")
    assert not receiver.merge_handover(forged, {"device-a": public}, "b" * 64, digest(asdict(forged))).accepted


def test_signed_provider_capability_challenge_expiry_and_upstream_tools():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.generate()
    profile = ProviderProfile("fixture", "openai", "https://provider.example", "/chat", "weak-slow", ("192.0.2.1",),
        approved_client=True, permitted_categories=("client_confidential",), upstream_tools="disabled", upstream_evidence="synthetic-attestation", authorization="fixture", retention="none", reviewed_by="operator",
        capability_path="/capabilities", capability_key=base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(), capability_config_sha256="a" * 64)
    payload = {"nonce": "fresh", "origin": profile.origin, "model": profile.model, "config_sha256": profile.capability_config_sha256,
        "retention_sha256": hashlib.sha256(profile.retention.encode()).hexdigest(), "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat(),
        "tools": [], "plugins": [], "browsing": False, "uploads": False}
    def sign(value):
        return json.dumps({"payload": value, "signature": base64.b64encode(key.sign(canonical_json(value))).decode()})
    gate = DisclosureGate()
    with pytest.raises(PolicyError):
        gate.prepare(profile, (DisclosureItem("facts", "client_confidential", {"ports": [443]}),))
    for changed in ({**payload, "tools": ["browse"]}, {**payload, "browsing": True}, {**payload, "nonce": "old"}, {**payload, "expires_at": "2020-01-01T00:00:00Z"}):
        with pytest.raises(PolicyError):
            gate.accept_capability(profile, sign(changed), "fresh")
    gate.accept_capability(profile, sign(payload), "fresh")
    # A valid provider attestation does not bypass the registered fact schema.
    with pytest.raises(PolicyError):
        gate.prepare(profile, (DisclosureItem("facts", "client_confidential", {"ports": [443]}),))
    data = {"version": 1, "status": "complete", "reason": None, "facts_schema": "network.output_import",
            "facts": {"observations": [{"track": "network", "target": "192.0.2.10", "check_id": "network_inventory",
                                         "state": "observed", "source_sha256": "a" * 64,
                                         "facts": {"port": 443, "state": "open"}}], "issues": [], "duplicates": 0}}
    assert "443" in gate.prepare(profile, (DisclosureItem("result", "client_confidential", data,
                                                         schema_id="network.output_import"),))


def test_legacy_migration_preserves_entire_history_and_repeatability(tmp_path):
    import cptc_web as old
    from dataclasses import asdict
    tmp_path.chmod(0o700)
    root = tmp_path / "legacy"
    scope = old.Scope({"allowed_cidrs": ["192.0.2.0/24"], "allowed_hosts": [], "excluded_cidrs": []})
    with old.engagement(root, initialize=scope) as (folder, db, _):
        old.add_app(db, scope, "https://192.0.2.10", "fixture")
        before = {name: db.execute(f"SELECT * FROM {name}").fetchall() for name in ("apps", "checks", "evidence", "events", "auth_budget")}
        old.export(folder, db)
    with pytest.raises(PolicyError, match="encrypted storage"):
        migrate_legacy(root)
    result = migrate_legacy(root, encrypted_storage_verified=True)
    assert result["harness_schema"] == 2 and not result["already_migrated"]
    with old.engagement(root) as (_, db, _):
        for name, rows in before.items():
            assert [tuple(x) for x in db.execute(f"SELECT * FROM {name}")] == [tuple(x) for x in rows]
    assert migrate_legacy(root, encrypted_storage_verified=True)["already_migrated"]
    assert json.loads((root / "export/ai-brief.json").read_text())["classification"] == "client_confidential"
