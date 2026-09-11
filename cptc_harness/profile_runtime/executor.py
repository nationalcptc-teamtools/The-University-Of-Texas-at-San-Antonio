"""Parent-side finalization for one reservation-bound PortCast broker result."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import time
from typing import Any, Callable

from ..contracts import Bounds, EvidenceRef, PolicyError, ProfileAction, _validate_profile_action
from .broker_ipc import (
    BrokerWireEvent,
    BrokerWireResult,
    PortcastBrokerFailure,
    ReservationBinding,
)
from .catalog import SealedProfile, load_profile, require_live_admission, validate_sealed_profile
from .contracts import WireCounters
from .receipts import ProfileWireReceipt


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _expected_bounds(profile: SealedProfile) -> Bounds:
    budget = profile.budget
    return Bounds(
        timeout_s=budget.timeout_s,
        request_limit=budget.protocol_requests,
        output_bytes=budget.capture_bytes * 2,
        process_limit=budget.process_limit,
        tcp_connects=budget.tcp_connects,
        udp_datagrams=budget.udp_datagrams,
        protocol_requests=budget.protocol_requests,
        tx_bytes=budget.tx_bytes,
        rx_bytes=budget.rx_bytes,
    )


def _captured_artifact(
    capture: Callable[[bytes], EvidenceRef], raw: bytes
) -> EvidenceRef:
    value = capture(raw)
    if (
        not isinstance(value, EvidenceRef)
        or _ARTIFACT_ID.fullmatch(value.evidence_id) is None
        or value.check_id != "raw"
        or value.classification != "client_confidential_human_only"
        or not isinstance(value.artifact_relpath, str)
        or not value.artifact_relpath.startswith("evidence/")
        or value.artifact_relpath.startswith("/")
        or ".." in Path(value.artifact_relpath).parts
        or value.sha256 != hashlib.sha256(raw).hexdigest()
        or value.bytes != len(raw)
    ):
        raise ValueError("encrypted capture reference differs from raw evidence")
    return value


def _receipt(
    action: ProfileAction,
    profile: SealedProfile,
    *,
    worker_sha256: str,
    started_at: str,
    first_byte_at: str | None,
    outcome: str,
    counters: WireCounters,
    raw: bytes,
    capture_ref: EvidenceRef | None,
    limitations: tuple[str, ...],
) -> ProfileWireReceipt:
    return ProfileWireReceipt.from_dict(
        {
            "schema_version": 1,
            "wave_id": action.wave_id,
            "action_id": action.action_id,
            "profile_id": profile.profile_id,
            "target_id": profile.target_id,
            "catalog_sha256": profile.catalog_sha256,
            "profile_sha256": profile.profile_sha256,
            "operation_sha256": profile.operation.sha256,
            "worker_sha256": worker_sha256,
            "runtime_pinset_sha256": action.runtime_pinset_sha256,
            "started_at": started_at,
            "first_byte_at": first_byte_at,
            "completed_at": _utc_now(),
            "outcome": outcome,
            "counters": counters.as_dict(),
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "evidence_bytes": len(raw),
            "encrypted_artifact_id": capture_ref.evidence_id if capture_ref else "none",
            "limitations": list(limitations),
        },
        expected_action=action,
        expected_profile=profile,
        expected_worker_sha256=worker_sha256,
        expected_capture=capture_ref,
    )


def _empty_counters() -> WireCounters:
    return WireCounters(0, 0, 0, 0, 0, 0, 0)


def _parent_counters(ledger: Any, action_id: str, *, capture_bytes: int) -> WireCounters:
    usage = ledger.attempt_receipt(action_id)["usage"]
    return WireCounters(
        usage["tcp_connects"],
        usage["udp_datagrams"],
        0,
        usage["protocol_requests"],
        usage["tx_bytes"],
        usage["rx_bytes"],
        capture_bytes,
    )


def _same_wire_counts(left: WireCounters, right: WireCounters) -> bool:
    return all(
        getattr(left, name) == getattr(right, name)
        for name in (
            "tcp_connects",
            "udp_datagrams",
            "tls_handshakes",
            "protocol_requests",
            "tx_bytes",
            "rx_bytes",
        )
    )


def _finish_noncomplete(
    ledger: Any, action_id: str, attempt_id: str, state: str, ended_ns: int
) -> None:
    try:
        ledger.finish_attempt(action_id, attempt_id, state=state, ended_ns=ended_ns)
    except PolicyError:
        pass
    usage = ledger.attempt_receipt(action_id)["usage"]
    try:
        ledger.finish(action_id, usage, state=state)
    except PolicyError:
        pass
    if state == "uncertain" and not ledger.stopped():
        ledger.stop("transport outcome uncertain")


def _read_evidence(result: BrokerWireResult, maximum: int) -> bytes:
    descriptor = result.evidence_fd
    if type(descriptor) is not int:
        raise PolicyError("PortCast broker evidence descriptor is unavailable")
    try:
        if not 0 <= result.evidence_bytes <= maximum:
            raise PolicyError("PortCast broker evidence exceeds allowance")
        chunks: list[bytes] = []
        remaining = result.evidence_bytes
        while remaining:
            chunk = os.read(descriptor, min(remaining, 128 * 1024))
            if not chunk:
                raise PolicyError("PortCast broker evidence is incomplete")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PolicyError("PortCast broker evidence size differs")
        raw = b"".join(chunks)
        if hashlib.sha256(raw).hexdigest() != result.evidence_sha256:
            raise PolicyError("PortCast broker evidence hash differs")
        return raw
    finally:
        os.close(descriptor)


def dispatch_profile(
    action: ProfileAction,
    profile_wire_broker: Any,
    ledger: Any,
    capture: Callable[[bytes], EvidenceRef],
    receipt_sink: Callable[[ProfileWireReceipt], Any],
    stopped: Callable[[], bool],
    *,
    failure_stage_sink: Callable[[str], Any] | None = None,
) -> ProfileWireReceipt:
    """Reserve first, consume one broker nonce, then finalize before completion."""

    exact_action = _validate_profile_action(action)
    profile = require_live_admission(
        validate_sealed_profile(load_profile(exact_action.profile_id))
    )
    if (
        exact_action.target_id != profile.target_id
        or exact_action.bounds != _expected_bounds(profile)
        or profile.profile_id != "web.http_jellyfin_public_identity"
        or exact_action.runtime_pinset_sha256 != profile.runtime_pinset_sha256
    ):
        raise PolicyError("sealed profile action differs from the reviewed profile")
    expected_worker = getattr(profile_wire_broker, "expected_worker_sha256", None)
    if (
        _HEX64.fullmatch(expected_worker or "") is None
        or not callable(getattr(profile_wire_broker, "bind_reserved_attempt", None))
        or not callable(getattr(profile_wire_broker, "execute_once", None))
        or not callable(capture)
        or not callable(receipt_sink)
        or not callable(stopped)
        or failure_stage_sink is not None
        and not callable(failure_stage_sink)
    ):
        raise PolicyError("trusted PortCast profile wire broker is unavailable")

    def record_failure_stage(stage: str | None) -> None:
        if stage is None or failure_stage_sink is None:
            return
        try:
            failure_stage_sink(stage)
        except Exception:
            try:
                ledger.stop("profile wire failure stage audit failed")
            except Exception:
                pass
            raise PolicyError("profile wire failure stage could not be recorded") from None
    started_ns = time.monotonic_ns()
    deadline_ns = started_ns + int(profile.budget.timeout_s * 1_000_000_000)
    started_at = _utc_now()
    attempt_id = hashlib.sha256(
        (exact_action.action_id + "|" + profile.profile_sha256).encode("ascii")
    ).hexdigest()
    ledger.reserve_attempt(
        exact_action.action_id,
        exact_action.bounds,
        attempt_id,
        started_ns=started_ns,
        deadline_ns=deadline_ns,
        workspace_id=exact_action.workspace_id,
        target_id=exact_action.target_id,
        workflow_id=exact_action.wave_id,
        limits=dict(exact_action.limits),
        budget_limits=exact_action.budget_limits,
    )

    stop_latched = stopped()
    if stop_latched or time.monotonic_ns() >= deadline_ns:
        ended_ns = time.monotonic_ns()
        state = "stopped" if stop_latched else "uncertain"
        limitation = "stop_latched" if stop_latched else "timeout"
        _finish_noncomplete(ledger, exact_action.action_id, attempt_id, state, ended_ns)
        receipt = _receipt(
            exact_action,
            profile,
            worker_sha256=expected_worker,
            started_at=started_at,
            first_byte_at=None,
            outcome="cancelled" if stop_latched else "uncertain",
            counters=_empty_counters(),
            raw=b"",
            capture_ref=None,
            limitations=(limitation,),
        )
        try:
            receipt_sink(receipt)
        except Exception:
            ledger.stop("profile wire receipt audit failed")
        return receipt

    binding = ReservationBinding(
        ledger.engagement_id,
        ledger.device_id,
        exact_action.action_id,
        attempt_id,
        profile.profile_id,
        exact_action.runtime_pinset_sha256,
        deadline_ns,
    )

    def record_event(event: BrokerWireEvent) -> None:
        if type(event) is not BrokerWireEvent:
            raise PolicyError("PortCast broker wire event is invalid")
        ledger.record_attempt_event(
            exact_action.action_id,
            attempt_id,
            event.event_id,
            **event.ledger_values(),
        )

    raw = b""
    result: BrokerWireResult | None = None
    try:
        nonce = profile_wire_broker.bind_reserved_attempt(binding)
        result = profile_wire_broker.execute_once(nonce, record_event, stopped)
        if type(result) is not BrokerWireResult or result.worker_sha256 != expected_worker:
            raise PolicyError("PortCast broker result worker pin differs")
        raw = _read_evidence(result, profile.budget.capture_bytes)
        measured = _parent_counters(ledger, exact_action.action_id, capture_bytes=0)
        if not _same_wire_counts(measured, result.counters):
            raise PolicyError("parent and broker wire accounting differ")
    except Exception as error:
        failure_stage = (
            error.failure_stage if isinstance(error, PortcastBrokerFailure) else None
        )
        _finish_noncomplete(
            ledger, exact_action.action_id, attempt_id, "uncertain", time.monotonic_ns()
        )
        counters = _parent_counters(ledger, exact_action.action_id, capture_bytes=0)
        receipt = _receipt(
            exact_action,
            profile,
            worker_sha256=expected_worker,
            started_at=started_at,
            first_byte_at=None,
            outcome="uncertain",
            counters=counters,
            raw=b"",
            capture_ref=None,
            limitations=("transport_interrupted",),
        )
        try:
            receipt_sink(receipt)
        except Exception:
            ledger.stop("profile wire receipt audit failed")
        else:
            record_failure_stage(failure_stage)
        return receipt

    capture_ref = None
    captured = b""
    if raw:
        try:
            capture_ref = _captured_artifact(capture, raw)
            captured = raw
        except Exception:
            _finish_noncomplete(
                ledger, exact_action.action_id, attempt_id, "uncertain", time.monotonic_ns()
            )
            receipt = _receipt(
                exact_action,
                profile,
                worker_sha256=expected_worker,
                started_at=started_at,
                first_byte_at=result.first_byte_at,
                outcome="uncertain",
                counters=_parent_counters(ledger, exact_action.action_id, capture_bytes=0),
                raw=b"",
                capture_ref=None,
                limitations=("audit_failure",),
            )
            try:
                receipt_sink(receipt)
            except Exception:
                ledger.stop("profile wire receipt audit failed")
            return receipt

    counters = _parent_counters(
        ledger, exact_action.action_id, capture_bytes=len(captured)
    )
    limitation = result.limitation
    if result.outcome != "complete" or not raw or result.first_byte_at is None:
        if limitation is None:
            limitation = "unexpected_response"
        state = "stopped" if result.outcome == "cancelled" else "uncertain"
        _finish_noncomplete(
            ledger, exact_action.action_id, attempt_id, state, time.monotonic_ns()
        )
        receipt = _receipt(
            exact_action,
            profile,
            worker_sha256=expected_worker,
            started_at=started_at,
            first_byte_at=result.first_byte_at,
            outcome=result.outcome if result.outcome != "complete" else "uncertain",
            counters=counters,
            raw=captured,
            capture_ref=capture_ref,
            limitations=(limitation,),
        )
        try:
            receipt_sink(receipt)
        except Exception:
            ledger.stop("profile wire receipt audit failed")
        else:
            record_failure_stage(result.failure_stage)
        return receipt

    ended_ns = time.monotonic_ns()
    final = ledger.finish_attempt(
        exact_action.action_id, attempt_id, state="complete", ended_ns=ended_ns
    )
    if final["state"] != "complete" or ended_ns >= deadline_ns:
        try:
            ledger.finish(exact_action.action_id, final["usage"], state="uncertain")
        except PolicyError:
            pass
        ledger.stop("transport outcome uncertain")
        receipt = _receipt(
            exact_action,
            profile,
            worker_sha256=expected_worker,
            started_at=started_at,
            first_byte_at=result.first_byte_at,
            outcome="uncertain",
            counters=counters,
            raw=captured,
            capture_ref=capture_ref,
            limitations=("timeout",),
        )
        try:
            receipt_sink(receipt)
        except Exception:
            pass
        return receipt

    completed = _receipt(
        exact_action,
        profile,
        worker_sha256=expected_worker,
        started_at=started_at,
        first_byte_at=result.first_byte_at,
        outcome="complete",
        counters=counters,
        raw=raw,
        capture_ref=capture_ref,
        limitations=(),
    )
    try:
        receipt_sink(completed)
    except Exception:
        try:
            ledger.finish(exact_action.action_id, final["usage"], state="uncertain")
        except PolicyError:
            pass
        ledger.stop("profile wire receipt audit failed")
        return _receipt(
            exact_action,
            profile,
            worker_sha256=expected_worker,
            started_at=started_at,
            first_byte_at=result.first_byte_at,
            outcome="uncertain",
            counters=counters,
            raw=raw,
            capture_ref=capture_ref,
            limitations=("audit_failure",),
        )
    return completed


__all__ = ("dispatch_profile",)
