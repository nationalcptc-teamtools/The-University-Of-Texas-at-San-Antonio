from __future__ import annotations

import hashlib

import pytest

import cptc_harness.contracts as broker_contracts
from cptc_harness.contracts import Bounds, EvidenceRef
from cptc_harness.profile_runtime.catalog import load_profile
from cptc_harness.profile_runtime.contracts import ProfileContractError
from cptc_harness.profile_runtime.receipts import (
    ProfileWireReceipt,
    validate_persisted_profile_wire_receipt,
)
from cptc_harness.profile_runtime.worker import build_http11_request


PROFILE_ID = "web.http_jellyfin_public_identity"
WORKER_SHA256 = "4" * 64
RUNTIME_SHA256 = load_profile(PROFILE_ID).runtime_pinset_sha256
EVIDENCE = b"x" * 800


def _capture(raw: bytes = EVIDENCE, evidence_id: str = "artifact-0001") -> EvidenceRef:
    return EvidenceRef(
        evidence_id,
        None,
        "raw",
        "client_confidential_human_only",
        f"evidence/{evidence_id}.age",
        hashlib.sha256(raw).hexdigest(),
        len(raw),
    )


def _action():
    return broker_contracts._issue_profile_action(
        action_id="action-0001",
        wave_id="wave-0001",
        workspace_id="workspace-0001",
        target_id="cptc11-prod-portcast",
        profile_id=PROFILE_ID,
        runtime_pinset_sha256=RUNTIME_SHA256,
        bounds=Bounds(
            timeout_s=10.0,
            request_limit=1,
            output_bytes=16384,
            process_limit=1,
            tcp_connects=1,
            udp_datagrams=0,
            protocol_requests=1,
            tx_bytes=256,
            rx_bytes=8192,
        ),
        limits=(("request_limit", 1),),
        budget_limits=(),
    )


def _parse(value, expected_capture=_capture()):
    return ProfileWireReceipt.from_dict(
        value,
        expected_action=_action(),
        expected_profile=load_profile(PROFILE_ID),
        expected_worker_sha256=WORKER_SHA256,
        expected_capture=expected_capture,
    )


def _receipt() -> dict[str, object]:
    profile = load_profile(PROFILE_ID)
    return {
        "schema_version": 1,
        "wave_id": "wave-0001",
        "action_id": "action-0001",
        "profile_id": PROFILE_ID,
        "target_id": "cptc11-prod-portcast",
        "catalog_sha256": profile.catalog_sha256,
        "profile_sha256": profile.profile_sha256,
        "operation_sha256": profile.operation.sha256,
        "worker_sha256": WORKER_SHA256,
        "runtime_pinset_sha256": RUNTIME_SHA256,
        "started_at": "2026-09-09T15:00:00.000001Z",
        "first_byte_at": "2026-09-09T15:00:00.100001Z",
        "completed_at": "2026-09-09T15:00:00.200001Z",
        "outcome": "complete",
        "counters": {
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "tls_handshakes": 0,
            "protocol_requests": 1,
            "tx_bytes": len(build_http11_request(profile.operation)),
            "rx_bytes": 800,
            "capture_bytes": 800,
        },
        "evidence_sha256": hashlib.sha256(EVIDENCE).hexdigest(),
        "evidence_bytes": 800,
        "encrypted_artifact_id": "artifact-0001",
        "limitations": [],
    }


def test_complete_receipt_is_strict_bounded_and_parseable():
    receipt = _parse(_receipt())
    assert receipt.outcome == "complete"
    assert receipt.is_parseable is True
    assert receipt.counters.rx_bytes == 800
    assert receipt.as_dict() == _receipt()


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("body", "target response"),
        ("command", ["curl"]),
        ("headers", {"Set-Cookie": "x"}),
        ("credential", "x"),
        ("url", "https://example.invalid"),
        ("stderr", "error"),
    ),
)
def test_receipt_rejects_payload_and_escape_fields(field, replacement):
    value = _receipt()
    value[field] = replacement
    with pytest.raises(ProfileContractError, match="field"):
        _parse(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("started_at", "2026-09-09T15:00:00Z"),
        ("started_at", "2026-09-09T10:00:00.000001-05:00"),
        ("first_byte_at", "2026-09-09T14:59:59.000001Z"),
        ("completed_at", "2026-09-09T15:00:00.050001Z"),
    ),
)
def test_receipt_requires_ordered_microsecond_utc_timestamps(field, replacement):
    value = _receipt()
    value[field] = replacement
    with pytest.raises(ProfileContractError, match="time"):
        _parse(value)


def test_receipt_rejects_hash_substitution_and_counter_or_evidence_mismatch():
    for mutate in (
        lambda value: value.update(profile_sha256="9" * 64),
        lambda value: value.update(operation_sha256="9" * 64),
        lambda value: value["counters"].update(rx_bytes=4097),
        lambda value: value.update(evidence_bytes=799),
        lambda value: value.update(evidence_sha256="not-a-hash"),
        lambda value: value.update(evidence_sha256="9" * 64),
    ):
        value = _receipt()
        mutate(value)
        with pytest.raises(ProfileContractError):
            _parse(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("wave_id", "other-wave"),
        ("action_id", "other-action"),
        ("profile_id", "web.other-profile"),
        ("target_id", "other-target"),
        ("catalog_sha256", "7" * 64),
        ("profile_sha256", "7" * 64),
        ("operation_sha256", "7" * 64),
        ("worker_sha256", "7" * 64),
        ("runtime_pinset_sha256", "7" * 64),
    ),
)
def test_receipt_binds_every_identity_and_runtime_field(field, replacement):
    value = _receipt()
    value[field] = replacement
    with pytest.raises(ProfileContractError, match="identity|binding"):
        _parse(value)


@pytest.mark.parametrize("outcome", ([], {}, 1, True, None))
def test_receipt_rejects_non_string_outcomes_through_contract_error(outcome):
    value = _receipt()
    value["outcome"] = outcome
    with pytest.raises(ProfileContractError, match="outcome"):
        _parse(value)


def test_complete_receipt_requires_actual_operation_and_lossless_capture():
    zero = _receipt()
    zero.update(
        counters={
            "tcp_connects": 0,
            "udp_datagrams": 0,
            "tls_handshakes": 0,
            "protocol_requests": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
            "capture_bytes": 0,
        },
        evidence_sha256=hashlib.sha256(b"").hexdigest(),
        evidence_bytes=0,
        encrypted_artifact_id="none",
    )
    with pytest.raises(ProfileContractError, match="trusted capture|wire evidence"):
        _parse(zero, None)

    dropped = _receipt()
    dropped["counters"]["capture_bytes"] = 799
    dropped["evidence_bytes"] = 799
    dropped["evidence_sha256"] = hashlib.sha256(EVIDENCE[:799]).hexdigest()
    with pytest.raises(ProfileContractError, match="wire evidence"):
        _parse(dropped, _capture(EVIDENCE[:799]))

    no_request = _receipt()
    no_request["counters"]["protocol_requests"] = 0
    with pytest.raises(ProfileContractError, match="wire evidence"):
        _parse(no_request)

    short_request = _receipt()
    short_request["counters"]["tx_bytes"] = 1
    with pytest.raises(ProfileContractError, match="wire evidence"):
        _parse(short_request)


@pytest.mark.parametrize(
    ("outcome", "limitations"),
    (
        ("incomplete", ["capture_incomplete"]),
        ("uncertain", ["transport_interrupted"]),
        ("cancelled", ["stop_latched"]),
    ),
)
def test_noncomplete_receipts_are_not_parseable(outcome, limitations):
    value = _receipt()
    value["outcome"] = outcome
    value["limitations"] = limitations
    receipt = _parse(value)
    assert receipt.is_parseable is False


def test_noncomplete_receipt_may_truthfully_have_no_first_byte():
    value = _receipt()
    value.update(
        first_byte_at=None,
        outcome="uncertain",
        limitations=["transport_interrupted"],
        counters={
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "tls_handshakes": 0,
            "protocol_requests": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
            "capture_bytes": 0,
        },
        evidence_sha256=hashlib.sha256(b"").hexdigest(),
        evidence_bytes=0,
        encrypted_artifact_id="none",
    )
    receipt = _parse(value, None)
    assert receipt.first_byte_at is None
    assert receipt.is_parseable is False


def test_complete_receipt_requires_first_byte_and_present_first_byte_is_ordered():
    value = _receipt()
    value["first_byte_at"] = None
    with pytest.raises(ProfileContractError, match="first-byte"):
        _parse(value)

    value = _receipt()
    value.update(
        first_byte_at="2026-09-09T15:00:00.300001Z",
        outcome="uncertain",
        limitations=["transport_interrupted"],
    )
    with pytest.raises(ProfileContractError, match="ordered"):
        _parse(value)


def test_receipt_rejects_free_text_limitations_and_inconsistent_completion():
    for mutate in (
        lambda value: value.update(limitations=["request failed because token=secret"]),
        lambda value: value.update(outcome="complete", limitations=["timeout"]),
        lambda value: value.update(outcome="uncertain", limitations=[]),
        lambda value: value.update(completed_at=None),
    ):
        value = _receipt()
        mutate(value)
        with pytest.raises(ProfileContractError):
            _parse(value)


def test_persisted_receipt_worker_pin_must_come_from_trusted_release():
    value = _receipt()
    value["worker_sha256"] = "7" * 64

    with pytest.raises(ProfileContractError, match="persisted profile receipt"):
        validate_persisted_profile_wire_receipt(
            value, expected_worker_sha256=WORKER_SHA256
        )

    accepted = validate_persisted_profile_wire_receipt(
        _receipt(), expected_worker_sha256=WORKER_SHA256
    )
    assert accepted.worker_sha256 == WORKER_SHA256
