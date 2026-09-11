from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cptc_harness.contracts import PolicyError, canonical_json
from cptc_harness.audit_service import AuditService
from cptc_harness.integrity import VerifiedRelease
from cptc_harness.memfd import MFD_ALLOW_SEALING, MFD_CLOEXEC, memfd_create, seal_readonly, write_all
from cptc_harness.profile_runtime.broker_ipc import (
    BrokerWireEvent,
    BrokerWireResult,
    DispatchNonce,
    PortcastBrokerClient,
)
from cptc_harness.profile_runtime.catalog import load_profile
from cptc_harness.profile_runtime.contracts import WireCounters
from cptc_harness.profile_runtime.harbinger import (
    build_portcast_harbinger_envelope,
    build_portcast_source_card,
)
from cptc_harness.runtime import Runtime
from cptc_harness.profile_runtime.worker import build_http11_request
from testing.cptc11_lab import portcast_live as live


BODY = b'{"ProductName":"Jellyfin Server","Version":"10.10.7"}'
RAW = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
    b"Content-Encoding: identity\r\n"
    + f"Content-Length: {len(BODY)}\r\n".encode("ascii")
    + b"Connection: close\r\n\r\n"
    + BODY
)


def _release(plan) -> VerifiedRelease:
    return VerifiedRelease(
        plan.release_id,
        "3" * 64,
        {},
        {plan.profile_id: plan.worker_sha256},
        {plan.profile_id: (plan.worker_sha256,)},
    )


class SyntheticClient(PortcastBrokerClient):
    def __init__(self, ledger, verified_release):
        self._initialize_for_test(ledger, verified_release)

    def bind_reserved_attempt(self, binding):
        self._verify_reservation(binding)
        return DispatchNonce(b"h" * 32, 2**63 - 1)

    def execute_once(self, _nonce, record_event, _stopped):
        request = build_http11_request(load_profile(self._binding_profile).operation)
        now = utc_now()
        record_event(BrokerWireEvent("connect-000000", 1, 0, 0, 0, 0, None))
        record_event(BrokerWireEvent("send-000001", 0, 0, 1, len(request), 0, None))
        record_event(BrokerWireEvent("recv-000001", 0, 0, 0, 0, len(RAW), now))
        descriptor = memfd_create("harbinger-test", MFD_CLOEXEC | MFD_ALLOW_SEALING)
        write_all(descriptor, RAW)
        os.lseek(descriptor, 0, os.SEEK_SET)
        seal_readonly(descriptor)
        return BrokerWireResult(
            "complete",
            None,
            WireCounters(1, 0, 0, 1, len(request), len(RAW), len(RAW)),
            descriptor,
            len(RAW),
            hashlib.sha256(RAW).hexdigest(),
            now,
            self.expected_worker_sha256,
        )

    @property
    def _binding_profile(self):
        return "web.http_jellyfin_public_identity"

    def close(self):
        return None


def age_identity(tmp_path: Path) -> tuple[Path, str]:
    root = Path(__file__).parents[2]
    age = root / ".tools" / "age"
    keygen = root / ".tools" / "age-keygen"
    identity = tmp_path / "identity.agekey"
    import subprocess

    subprocess.run([str(keygen), "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.run(
        [str(keygen), "-y", str(identity)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return age, recipient


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def synthetic_open_window_plan(monkeypatch):
    now = datetime.now(timezone.utc)
    plan = replace(
        live.load_frozen_portcast_plan(),
        window_start=(now - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        window_end=(now + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        reviewed_by="approved:synthetic-test-reviewer",
    )
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    return plan


def test_verified_complete_state_builds_signed_metadata_only_envelope(
    tmp_path, monkeypatch
):
    plan = synthetic_open_window_plan(monkeypatch)
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = age_identity(tmp_path)
    state_root = tmp_path / "state"
    result = live._run_frozen_portcast_action_at_root(
        state_root=state_root,
        age_binary=age,
        age_recipient=recipient,
        wire_broker_factory=SyntheticClient,
    )
    assert result["status"] == "complete"
    runtime_root, ledger_root = live._prepare_runtime(
        state_root, plan, age_binary=age, age_recipient=recipient
    )
    runtime = Runtime(runtime_root, ledger_root=ledger_root, verified_release=release)
    key = Ed25519PrivateKey.generate()
    reviewed_at = issued_at = utc_now()
    envelope = build_portcast_harbinger_envelope(
        runtime=runtime,
        frozen_plan=plan,
        harbinger_engagement_id="00000000-0000-4000-8000-000000000001",
        source_id="00000000-0000-4000-8000-000000000002",
        key_id="synthetic-portcast-key",
        review_id="00000000-0000-4000-8000-000000000003",
        reviewed_at=reviewed_at,
        issued_at=issued_at,
        signer=key.sign,
    )
    runtime.close()

    unsigned = {name: value for name, value in envelope.items() if name != "signature"}
    key.public_key().verify(
        base64.b64decode(envelope["signature"]["value"], validate=True),
        canonical_json(unsigned),
    )
    encoded = json.dumps(envelope, sort_keys=True)
    assert envelope["observation"]["result"]["state"] == "candidate"
    assert envelope["observation"]["result"]["vulnerability_assessment"] == "not_performed"
    assert envelope["execution"]["target_profile"]["version"] == 1
    assert envelope["execution"]["reservation"]["consumed"]["tcp_connects"] == 1
    assert envelope["execution"]["reservation"]["consumed"]["protocol_requests"] == 1
    assert envelope["execution"]["reservation"]["consumed"]["authentication_attempts"] == 0
    assert ".age" not in encoded
    assert "artifact_relpath" not in encoded
    assert RAW.decode("ascii") not in encoded
    assert "CVE-" not in encoded

    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    card = build_portcast_source_card(
        envelope=envelope,
        public_key=base64.b64encode(public).decode("ascii"),
        name="Synthetic CPTC11 broker",
    )
    assert card["profiles"] == ["web.http_jellyfin_public_identity"]
    assert card["profile_pins"][card["profiles"][0]]["worker_sha256"] == plan.worker_sha256


def test_export_refuses_complete_wire_without_cleanup_receipt(tmp_path, monkeypatch):
    plan = synthetic_open_window_plan(monkeypatch)
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    monkeypatch.setattr(AuditService, "record_profile_cleanup_receipt", lambda *args: None)
    age, recipient = age_identity(tmp_path)
    state_root = tmp_path / "no-cleanup"
    result = live._run_frozen_portcast_action_at_root(
        state_root=state_root,
        age_binary=age,
        age_recipient=recipient,
        wire_broker_factory=SyntheticClient,
    )
    assert result["status"] == "complete"
    runtime_root, ledger_root = live._prepare_runtime(
        state_root, plan, age_binary=age, age_recipient=recipient
    )
    runtime = Runtime(runtime_root, ledger_root=ledger_root, verified_release=release)

    with pytest.raises(PolicyError, match="receipts are incomplete"):
        build_portcast_harbinger_envelope(
            runtime=runtime,
            frozen_plan=plan,
            harbinger_engagement_id="00000000-0000-4000-8000-000000000001",
            source_id="00000000-0000-4000-8000-000000000002",
            key_id="synthetic-portcast-key",
            review_id="00000000-0000-4000-8000-000000000003",
            reviewed_at=utc_now(),
            issued_at=utc_now(),
            signer=Ed25519PrivateKey.generate().sign,
        )

    runtime.close()


def test_export_refuses_crash_recovered_reservation(tmp_path, monkeypatch):
    plan = synthetic_open_window_plan(monkeypatch)
    release = _release(plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    age, recipient = age_identity(tmp_path)
    state_root = tmp_path / "recovered"
    assert live._run_frozen_portcast_action_at_root(
        state_root=state_root, age_binary=age, age_recipient=recipient,
        wire_broker_factory=SyntheticClient,
    )["status"] == "complete"
    runtime_root, ledger_root = live._prepare_runtime(
        state_root, plan, age_binary=age, age_recipient=recipient
    )
    import sqlite3

    connection = sqlite3.connect(
        ledger_root / plan.engagement_id / "ledger.sqlite3"
    )
    connection.execute(
        "UPDATE reservations SET state='running' WHERE request_id=?",
        (plan.action_id,),
    )
    connection.commit()
    connection.close()
    runtime = Runtime(
        runtime_root, ledger_root=ledger_root, verified_release=release
    )
    assert runtime.ledger.reservation_state(plan.action_id) == "uncertain"
    with pytest.raises(PolicyError, match="stopped workspace"):
        build_portcast_harbinger_envelope(
            runtime=runtime,
            frozen_plan=plan,
            harbinger_engagement_id="00000000-0000-4000-8000-000000000001",
            source_id="00000000-0000-4000-8000-000000000002",
            key_id="synthetic-portcast-key",
            review_id="00000000-0000-4000-8000-000000000003",
            reviewed_at=utc_now(),
            issued_at=utc_now(),
            signer=Ed25519PrivateKey.generate().sign,
        )
    runtime.close()
