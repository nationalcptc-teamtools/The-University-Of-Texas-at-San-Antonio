"""Validated, metadata-only receipts for bounded profile executions."""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

from ..contracts import (
    Bounds,
    EvidenceRef,
    PolicyError,
    ProfileAction,
    _issue_profile_action,
    _validate_profile_action,
)
from .catalog import SealedProfile, load_profile, require_live_admission, validate_sealed_profile
from .contracts import (
    Http11RequestV1,
    MysqlGreetingV1,
    ProfileContractError,
    RedisPingV1,
    TlsHelloV1,
    WireCounters,
)
from .worker import build_http11_request


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_OUTCOMES = frozenset({"complete", "incomplete", "uncertain", "cancelled"})
_LIMITATIONS = frozenset(
    {
        "audit_failure",
        "capture_incomplete",
        "certificate_mismatch",
        "response_truncated",
        "stop_latched",
        "timeout",
        "transport_interrupted",
        "unexpected_response",
    }
)


def _text_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ProfileContractError(f"invalid {label}")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ProfileContractError(f"invalid {label}")
    return value


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise ProfileContractError(f"invalid {label} timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ProfileContractError(f"invalid {label} timestamp") from None
    return value, parsed


def _trusted_binding(
    action: ProfileAction,
    profile: SealedProfile,
    worker_sha256: Any,
) -> tuple[ProfileAction, SealedProfile, str, str]:
    """Validate every authority used to attribute an imported receipt."""

    try:
        action = _validate_profile_action(action)
        profile = validate_sealed_profile(profile)
    except (PolicyError, ProfileContractError):
        raise ProfileContractError("receipt expectation is not sealed") from None
    worker = _hash(worker_sha256, "expected worker hash")
    runtime = _hash(action.runtime_pinset_sha256, "expected runtime pinset hash")
    if action.profile_id != profile.profile_id or action.target_id != profile.target_id:
        raise ProfileContractError("receipt expectation binding differs")
    if runtime != profile.runtime_pinset_sha256:
        raise ProfileContractError("receipt runtime expectation differs")
    return action, profile, worker, runtime


def _trusted_capture(value: Any) -> EvidenceRef | None:
    if value is None:
        return None
    if (
        not isinstance(value, EvidenceRef)
        or _ID.fullmatch(value.evidence_id) is None
        or value.check_id != "raw"
        or value.classification != "client_confidential_human_only"
        or not isinstance(value.artifact_relpath, str)
        or not value.artifact_relpath.startswith("evidence/")
        or value.artifact_relpath.startswith("/")
        or ".." in value.artifact_relpath.split("/")
        or _HEX64.fullmatch(value.sha256) is None
        or type(value.bytes) is not int
        or value.bytes < 0
    ):
        raise ProfileContractError("trusted capture reference is invalid")
    return value


def _expected_tx_bytes(profile: SealedProfile) -> int:
    operation = profile.operation
    if isinstance(operation, Http11RequestV1):
        return len(build_http11_request(operation))
    if isinstance(operation, RedisPingV1):
        return len(b"*1\r\n$4\r\nPING\r\n")
    if isinstance(operation, MysqlGreetingV1):
        return 0
    if isinstance(operation, TlsHelloV1):
        raise ProfileContractError("complete TLS receipt validation is unavailable")
    raise ProfileContractError("complete receipt operation is unsupported")


def _validate_complete_counters(
    counters: WireCounters, profile: SealedProfile, encrypted_artifact_id: str
) -> None:
    """Require proof that the catalog operation actually ran and was captured."""

    operation = profile.operation
    expected_tls = int(
        isinstance(operation, TlsHelloV1)
        or isinstance(operation, Http11RequestV1) and operation.tls
    )
    expected_requests = int(isinstance(operation, (Http11RequestV1, RedisPingV1)))
    if (
        counters.tcp_connects != 1
        or counters.udp_datagrams != 0
        or counters.tls_handshakes != expected_tls
        or counters.protocol_requests != expected_requests
        or counters.rx_bytes <= 0
        or counters.capture_bytes != counters.rx_bytes
        or counters.tx_bytes != _expected_tx_bytes(profile)
        or encrypted_artifact_id == "none"
    ):
        raise ProfileContractError("complete receipt lacks required wire evidence")


@dataclass(frozen=True, slots=True)
class ProfileWireReceipt:
    schema_version: int
    wave_id: str
    action_id: str
    profile_id: str
    target_id: str
    catalog_sha256: str
    profile_sha256: str
    operation_sha256: str
    worker_sha256: str
    runtime_pinset_sha256: str
    started_at: str
    first_byte_at: str | None
    completed_at: str
    outcome: str
    counters: WireCounters
    evidence_sha256: str
    evidence_bytes: int
    encrypted_artifact_id: str
    limitations: tuple[str, ...]

    @classmethod
    def from_dict(
        cls,
        value: Any,
        *,
        expected_action: ProfileAction,
        expected_profile: SealedProfile,
        expected_worker_sha256: str,
        expected_capture: EvidenceRef | None,
    ) -> "ProfileWireReceipt":
        action, profile, worker_hash, runtime_hash = _trusted_binding(
            expected_action,
            expected_profile,
            expected_worker_sha256,
        )
        capture_ref = _trusted_capture(expected_capture)
        expected = {field.name for field in fields(cls)}
        if not isinstance(value, dict) or set(value) != expected:
            raise ProfileContractError("unknown or missing receipt field")
        if value["schema_version"] != 1 or type(value["schema_version"]) is not int:
            raise ProfileContractError("invalid receipt schema")
        identities = {
            "wave_id": action.wave_id,
            "action_id": action.action_id,
            "profile_id": profile.profile_id,
            "target_id": profile.target_id,
        }
        if any(_text_id(value[field], field.replace("_", " ")) != expected_value
               for field, expected_value in identities.items()):
            raise ProfileContractError("receipt identity differs from reserved action")
        expected_hashes = {
            "catalog_sha256": profile.catalog_sha256,
            "profile_sha256": profile.profile_sha256,
            "operation_sha256": profile.operation.sha256,
            "worker_sha256": worker_hash,
            "runtime_pinset_sha256": runtime_hash,
        }
        normalized_hashes = {
            field: _hash(value[field], field.replace("_", " "))
            for field in expected_hashes
        }
        if normalized_hashes != expected_hashes:
            raise ProfileContractError("receipt hash binding differs from reserved action")
        profile_hash = _hash(value["profile_sha256"], "profile hash")
        operation_hash = _hash(value["operation_sha256"], "operation hash")
        counters = WireCounters.from_dict(value["counters"])
        counters.validate_against(profile.budget)
        evidence_bytes = value["evidence_bytes"]
        if type(evidence_bytes) is not int or evidence_bytes < 0 or evidence_bytes != counters.capture_bytes:
            raise ProfileContractError("evidence byte count differs from captured bytes")

        outcome = value["outcome"]
        if type(outcome) is not str or outcome not in _OUTCOMES:
            raise ProfileContractError("invalid receipt outcome")
        started_text, started = _timestamp(value["started_at"], "start")
        completed_text, completed = _timestamp(value["completed_at"], "completion")
        first_value = value["first_byte_at"]
        if first_value is None:
            first_text = None
            if outcome == "complete":
                raise ProfileContractError("complete receipt requires a first-byte timestamp")
            if completed < started:
                raise ProfileContractError("receipt timestamps are not ordered")
        else:
            first_text, first = _timestamp(first_value, "first-byte")
            if first < started or completed < first:
                raise ProfileContractError("receipt timestamps are not ordered")
        limitations_value = value["limitations"]
        if (
            not isinstance(limitations_value, list)
            or len(limitations_value) > 8
            or any(type(item) is not str or item not in _LIMITATIONS for item in limitations_value)
            or len(limitations_value) != len(set(limitations_value))
        ):
            raise ProfileContractError("invalid receipt limitation")
        limitations = tuple(limitations_value)
        if (outcome == "complete") != (not limitations):
            raise ProfileContractError("receipt outcome and limitations disagree")

        artifact_id = _text_id(value["encrypted_artifact_id"], "encrypted artifact id")
        evidence_hash = _hash(value["evidence_sha256"], "evidence hash")
        if capture_ref is None:
            if (
                artifact_id != "none"
                or evidence_bytes != 0
                or evidence_hash != hashlib.sha256(b"").hexdigest()
            ):
                raise ProfileContractError("receipt evidence lacks a trusted capture")
        elif (
            artifact_id != capture_ref.evidence_id
            or evidence_bytes != capture_ref.bytes
            or evidence_hash != capture_ref.sha256
        ):
            raise ProfileContractError("receipt evidence differs from trusted capture")
        if outcome == "complete":
            if capture_ref is None:
                raise ProfileContractError("complete receipt lacks trusted capture")
            _validate_complete_counters(counters, profile, artifact_id)
            if evidence_bytes == 0:
                raise ProfileContractError("complete receipt lacks captured evidence")

        return cls(
            schema_version=1,
            wave_id=action.wave_id,
            action_id=action.action_id,
            profile_id=profile.profile_id,
            target_id=profile.target_id,
            catalog_sha256=profile.catalog_sha256,
            profile_sha256=profile_hash,
            operation_sha256=operation_hash,
            worker_sha256=worker_hash,
            runtime_pinset_sha256=runtime_hash,
            started_at=started_text,
            first_byte_at=first_text,
            completed_at=completed_text,
            outcome=outcome,
            counters=counters,
            evidence_sha256=evidence_hash,
            evidence_bytes=evidence_bytes,
            encrypted_artifact_id=artifact_id,
            limitations=limitations,
        )

    @property
    def is_parseable(self) -> bool:
        return self.outcome == "complete"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "wave_id": self.wave_id,
            "action_id": self.action_id,
            "profile_id": self.profile_id,
            "target_id": self.target_id,
            "catalog_sha256": self.catalog_sha256,
            "profile_sha256": self.profile_sha256,
            "operation_sha256": self.operation_sha256,
            "worker_sha256": self.worker_sha256,
            "runtime_pinset_sha256": self.runtime_pinset_sha256,
            "started_at": self.started_at,
            "first_byte_at": self.first_byte_at,
            "completed_at": self.completed_at,
            "outcome": self.outcome,
            "counters": self.counters.as_dict(),
            "evidence_sha256": self.evidence_sha256,
            "evidence_bytes": self.evidence_bytes,
            "encrypted_artifact_id": self.encrypted_artifact_id,
            "limitations": list(self.limitations),
        }


def validate_persisted_profile_wire_receipt(
    value: Any, *, expected_worker_sha256: str
) -> ProfileWireReceipt:
    """Revalidate one metadata-only audit receipt against the pinned catalog.

    This validates structure and the current release bindings. A later export
    must also compare the receipt with the durable Ledger and result record.
    """

    if not isinstance(value, dict):
        raise ProfileContractError("persisted profile receipt is not an object")
    try:
        profile = require_live_admission(load_profile(value.get("profile_id")))
        action = _issue_profile_action(
            action_id=value.get("action_id"),
            wave_id=value.get("wave_id"),
            workspace_id="audit-revalidation",
            target_id=value.get("target_id"),
            profile_id=value.get("profile_id"),
            runtime_pinset_sha256=value.get("runtime_pinset_sha256"),
            bounds=Bounds(
                timeout_s=profile.budget.timeout_s,
                request_limit=profile.budget.protocol_requests,
                output_bytes=profile.budget.capture_bytes * 2,
                process_limit=profile.budget.process_limit,
                tcp_connects=profile.budget.tcp_connects,
                udp_datagrams=profile.budget.udp_datagrams,
                protocol_requests=profile.budget.protocol_requests,
                tx_bytes=profile.budget.tx_bytes,
                rx_bytes=profile.budget.rx_bytes,
            ),
            limits=(),
            budget_limits=(),
        )
        artifact_id = value.get("encrypted_artifact_id")
        evidence_bytes = value.get("evidence_bytes")
        evidence_hash = value.get("evidence_sha256")
        capture = None
        if artifact_id != "none":
            capture = EvidenceRef(
                artifact_id,
                None,
                "raw",
                "client_confidential_human_only",
                f"evidence/{artifact_id}.age",
                evidence_hash,
                evidence_bytes,
            )
        return ProfileWireReceipt.from_dict(
            value,
            expected_action=action,
            expected_profile=profile,
            expected_worker_sha256=expected_worker_sha256,
            expected_capture=capture,
        )
    except (PolicyError, ProfileContractError, TypeError, ValueError):
        raise ProfileContractError("persisted profile receipt is invalid") from None


__all__ = ("ProfileWireReceipt", "validate_persisted_profile_wire_receipt")
