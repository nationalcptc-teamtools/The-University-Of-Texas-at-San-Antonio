"""Fail-closed audit helpers and an operator stop path independent of audit IPC."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import re
from pathlib import Path
import time
import uuid

from .contracts import AuditEvent, PolicyError
from .policy import identifier
from .storage import atomic_write, private_directory, read_private

_REASON_CODES = frozenset({"operator_request", "suspected_lockout", "health_degradation", "audit_failure"})
_INTERFACES = frozenset({"cli", "human", "tui", "mcp", "internal"})
_MAX_PENDING = 128

def _source_valid(source, interface, actor):
    return ((source == "operator" and interface in {"cli", "human", "tui"})
            or (source == "model" and interface == "mcp")
            or (source == "system" and interface == "internal" and actor == "system"))

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

def _control_dirs(root: Path) -> tuple[Path, Path]:
    root = private_directory(Path(root), create=True)
    control = private_directory(root / "control", create=True)
    return control, private_directory(control / "reconciled", create=True)

def _receipt(value: object, *, policy=None) -> dict:
    expected = {"version", "engagement_id", "device_id", "interface", "actor", "source", "correlation_id", "reason", "received_at", "received_monotonic_ns"}
    if not isinstance(value, dict) or set(value) != expected:
        raise PolicyError("invalid operator control receipt")
    if type(value["version"]) is not int or value["version"] != 1 or value["interface"] not in _INTERFACES or value["source"] not in {"operator", "model", "system"} or value["reason"] not in _REASON_CODES:
        raise PolicyError("invalid operator control receipt")
    for key, maximum in (("engagement_id", 96), ("device_id", 96), ("actor", 96), ("correlation_id", 64)):
        identifier(value[key])
        if len(value[key]) > maximum:
            raise PolicyError("invalid operator control receipt")
    if not isinstance(value["received_at"], str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", value["received_at"]):
        raise PolicyError("invalid operator control receipt")
    try:
        received = datetime.strptime(value["received_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise PolicyError("invalid operator control receipt") from None
    if received > datetime.now(timezone.utc) + timedelta(minutes=5): raise PolicyError("invalid operator control receipt")
    if not _source_valid(value["source"], value["interface"], value["actor"]):
        raise PolicyError("invalid operator control receipt")
    if policy is not None and (value["engagement_id"] != policy.engagement_id or value["device_id"] != policy.device_id or (value["source"] in {"operator", "model"} and value["actor"] != policy.operator_id)):
        raise PolicyError("operator control receipt does not match policy")
    if type(value["received_monotonic_ns"]) is not int or value["received_monotonic_ns"] < 0:
        raise PolicyError("invalid operator control receipt")
    return value

def _read_receipt(path: Path, *, policy=None) -> dict:
    try:
        return _receipt(json.loads(read_private(path, 4096)), policy=policy)
    except (ValueError, TypeError, OSError):
        raise PolicyError("invalid operator control receipt") from None

def _request_stop(root: Path, engagement_id: str, device_id: str, actor: str, *, interface: str, source: str = "operator", reason: str = "operator_request",
                 correlation_id: str | None = None, ledger=None) -> dict:
    """Durably latch a stop without acquiring Runtime or AuditService locks."""
    identifier(engagement_id); identifier(device_id); identifier(actor)
    if not _source_valid(source, interface, actor) or reason not in _REASON_CODES:
        raise PolicyError("unrecognized operator stop interface")
    correlation_id = correlation_id or uuid.uuid4().hex
    identifier(correlation_id)
    root = private_directory(Path(root), create=True)
    value = {"version": 1, "engagement_id": engagement_id, "device_id": device_id,
             "interface": interface, "actor": actor, "source": source, "correlation_id": correlation_id,
             "reason": reason, "received_at": _utc_now(), "received_monotonic_ns": time.monotonic_ns()}
    # The sentinel is outside SQLite and is the first Ledger.stopped() check.
    # A receipt from another device/engagement must never be overwritten into
    # this ledger root.
    sentinel = root / "operator-stop.json"
    if sentinel.exists():
        prior = _read_receipt(sentinel)
        if prior["engagement_id"] != engagement_id or prior["device_id"] != device_id:
            raise PolicyError("operator stop sentinel belongs to another ledger")
    else:
        atomic_write(sentinel, json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), replace=False)
    queue_ready = True
    try:
        control, _ = _control_dirs(root)
        pending = control / (correlation_id + ".json")
        if pending.exists():
            existing = _read_receipt(pending)
            if any(existing[key] != value[key] for key in ("engagement_id", "device_id", "actor", "interface", "source", "reason")):
                raise PolicyError("operator stop correlation does not match its original receipt")
        elif len(tuple(control.glob("*.json"))) >= _MAX_PENDING:
            queue_ready = False
        else:
            atomic_write(pending, json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), replace=False)
    except PolicyError as exc:
        if "correlation" in str(exc):
            raise
        queue_ready = False
    except Exception:
        queue_ready = False
    persisted = False
    if ledger is not None:
        try:
            ledger.stop(reason)
            persisted = True
        except Exception:
            persisted = False
    return {"stopped": True, "status": "stopped" if persisted and queue_ready else "uncertain", "new_work": "blocked",
            "reason": reason, "correlation_id": correlation_id}

def operator_stop(root: Path, policy, *, interface: str, source: str = "operator", reason: str = "operator_request", ledger=None) -> dict:
    """Shared CLI/human/TUI/MCP stop entry; never opens Runtime or AuditService."""
    if source == "system": raise PolicyError("system stops require an internal failure path")
    receipt = _request_stop(root, policy.engagement_id, policy.device_id, policy.operator_id, interface=interface, source=source, reason=reason)
    try:
        if ledger is None:
            from .ledger import Ledger
            ledger = Ledger(root, policy.engagement_id, policy.device_id, policy_revision=policy.revision)
        return _request_stop(root, policy.engagement_id, policy.device_id, policy.operator_id, interface=interface, source=source, reason=reason,
                            correlation_id=receipt["correlation_id"], ledger=ledger)
    except Exception:
        # The intent and sentinel are already fsync'd.  Do not turn a failed
        # ledger update into a false durable-audit success.
        return receipt

def reconcile_stop_intents(ledger, audit, *, policy) -> tuple[dict, ...]:
    """Emit pending receipts through the central writer and durably acknowledge them."""
    try:
        control, reconciled = _control_dirs(ledger.root)
        paths = list(sorted(control.glob("*.json")))
    except Exception:
        control = reconciled = None
        paths = []
    sentinel = ledger.root / "operator-stop.json"
    if sentinel.exists():
        paths.insert(0, sentinel)
    results = []
    for path in paths:
        receipt = _read_receipt(path, policy=policy)
        if receipt["engagement_id"] != ledger.engagement_id or receipt["device_id"] != ledger.device_id:
            raise PolicyError("operator control receipt belongs to another ledger")
        done = reconciled / path.name if reconciled is not None else None
        audit_receipts = audit.control_receipts()
        if receipt["correlation_id"] in audit_receipts:
            audited = audit_receipts[receipt["correlation_id"]]
            if any(audited.get(key) != receipt[key] for key in ("interface", "actor", "source", "reason", "received_at", "received_monotonic_ns")):
                raise PolicyError("operator control audit receipt does not match intent")
        acknowledged = (done is not None and done.exists()) or ledger.control_reconciled(receipt["correlation_id"])
        if acknowledged and receipt["correlation_id"] not in audit_receipts:
            # Local bookkeeping is not evidence of a durable central event.
            # Keep the original intent for human investigation of this drift.
            raise PolicyError("operator stop acknowledgement has no verified audit receipt")
        if receipt["correlation_id"] in audit_receipts:
            if done is not None and done.exists() and _read_receipt(done, policy=policy) != receipt:
                raise PolicyError("operator stop acknowledgement does not match intent")
            if done is not None and not done.exists():
                atomic_write(done, json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), replace=False)
            if path != sentinel: path.unlink(missing_ok=True)
            continue
        try:
            audit.emit(AuditEvent("operator_stop", receipt["correlation_id"], {
                "interface": receipt["interface"], "actor": receipt["actor"], "source": receipt["source"], "reason": receipt["reason"],
                "received_at": receipt["received_at"], "received_monotonic_ns": receipt["received_monotonic_ns"]}))
            ledger.record_control_reconciled(receipt["correlation_id"], receipt["received_at"], receipt["received_monotonic_ns"])
            if done is not None: atomic_write(done, json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), replace=False)
            if path != sentinel: path.unlink(missing_ok=True)
            results.append(receipt)
        except Exception:
            raise PolicyError("operator stop is latched but audit reconciliation is unavailable") from None
    return tuple(results)

def required_emit(audit, ledger, event: AuditEvent):
    try:
        return audit.emit(event)
    except Exception:
        _latch_audit_failure(ledger)
        raise PolicyError("durable audit event could not be recorded") from None

def required_release(audit, ledger, request_id: str) -> None:
    try:
        audit.release_output(request_id)
    except Exception:
        _latch_audit_failure(ledger)
        raise PolicyError("audit output release could not be recorded") from None

def _latch_audit_failure(ledger) -> None:
    try:
        _request_stop(ledger.root, ledger.engagement_id, ledger.device_id, "system", interface="internal", source="system", reason="audit_failure", ledger=ledger)
        return
    except Exception:
        pass
    try:
        # If the filesystem cannot persist the independent intent, still try
        # to block the ledger. The original audit failure remains an error.
        ledger.stop("audit failure requires operator review")
    except Exception:
        # The original audit exception is still surfaced to the caller; this
        # branch only records that durability could not be established.
        pass
