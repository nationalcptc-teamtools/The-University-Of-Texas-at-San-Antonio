"""Durable, local-only operation accounting and assignment locks."""
from __future__ import annotations

from dataclasses import asdict
import base64
import hashlib
import os
from pathlib import Path
import json
from datetime import datetime, timezone
import math
import re
import sqlite3
import threading
import uuid
from typing import Any

from .contracts import (Bounds, BudgetLimit, MergeBundle, MergeReport,
                        PolicyError, Reservation, RESOURCE_COUNTERS)
from .contracts import canonical_json, digest
from .storage import private_directory


_COUNTERS = RESOURCE_COUNTERS
_TRANSPORT_COUNTERS = ("tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes")
_TARGET_SCOPED_COUNTERS = frozenset(("request_limit", *_TRANSPORT_COUNTERS))
_ID_RE = re.compile(r"^[^\x00-\x1f\x7f]+$")
_WAVE_TERMINAL = frozenset({"complete", "failed", "blocked", "stopped", "uncertain"})


def _safe_id(value: Any, max_length: int) -> str:
    """Validate an operator or imported identifier without accepting controls."""
    if not isinstance(value, str) or not value or len(value) > max_length or not _ID_RE.fullmatch(value):
        raise PolicyError("invalid handover identifier")
    return value


def _fingerprint(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower()):
        raise PolicyError("invalid key fingerprint")
    return value.lower()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class Ledger:
    """SQLite ledger. Reservations are intentionally spent even on a crash."""

    def __init__(self, root: str | Path, engagement_id: str, device_id: str,
                 *, limits: dict[str, int] | None = None, policy_revision: str = "") -> None:
        self.root = private_directory(Path(root), create=True)
        self.path = self.root / "ledger.sqlite3"
        if self.path.is_symlink():
            raise PolicyError("ledger symlink rejected")
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        if self.path.stat().st_mode & 0o077 or self.path.stat().st_uid != os.getuid():
            raise PolicyError("unsafe ledger permissions")
        self.engagement_id, self.device_id = engagement_id, device_id
        self.policy_revision = policy_revision
        self.limits = dict(limits or {})
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
          CREATE TABLE IF NOT EXISTS reservations(
            engagement TEXT NOT NULL, device TEXT NOT NULL, request_id TEXT NOT NULL,
            workspace TEXT NOT NULL, target TEXT, realm TEXT, workflow TEXT NOT NULL,
            bounds TEXT NOT NULL, state TEXT NOT NULL, usage TEXT NOT NULL,
            PRIMARY KEY(engagement, device, request_id));
          CREATE TABLE IF NOT EXISTS assignments(
            engagement TEXT NOT NULL, target TEXT NOT NULL, realm TEXT NOT NULL,
            workspace TEXT NOT NULL, PRIMARY KEY(engagement,target,realm));
          CREATE TABLE IF NOT EXISTS stops(engagement TEXT PRIMARY KEY, reason TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS control_reconciliations(
            correlation_id TEXT PRIMARY KEY, received_at TEXT NOT NULL, received_monotonic_ns INTEGER NOT NULL,
            reconciled_at TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS rates(engagement TEXT NOT NULL, target TEXT NOT NULL, seen REAL NOT NULL,
            PRIMARY KEY(engagement,target));
          CREATE TABLE IF NOT EXISTS merges(bundle_hash TEXT PRIMARY KEY, source_device TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS handover_seals(
            seal_id TEXT PRIMARY KEY, recipient_device TEXT NOT NULL, recipient_key_fingerprint TEXT NOT NULL,
            snapshot_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL, created TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS handover_imports(bundle_hash TEXT PRIMARY KEY, source_device TEXT NOT NULL,
            seal_id TEXT NOT NULL, imported_at TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS workspace_enrollment(
            workspace_id TEXT PRIMARY KEY, audit_origin_id TEXT NOT NULL, path_hash TEXT NOT NULL);
        """)
        # Additive scope/wave tables are maintained by the shared migration;
        # run it only after the legacy tables exist so historical reservations
        # are indexed without changing their original records.
        from .migrations import ensure_ledger_schema
        ensure_ledger_schema(self._db)

    def stop(self, reason: str = "operator stop") -> None:
        with self._tx():
            self._db.execute("INSERT OR IGNORE INTO stops VALUES (?,?)", (self.engagement_id, reason))

    def stopped(self) -> bool:
        # The operator stop sentinel is deliberately outside SQLite.  An active
        # reservation can be holding a transaction or a writer can be dead; in
        # either case cancellation must still be immediately observable.
        sentinel = self.root / "operator-stop.json"
        if sentinel.exists():
            return True
        return self._db.execute("SELECT 1 FROM stops WHERE engagement=?", (self.engagement_id,)).fetchone() is not None

    def stop_reason(self) -> str | None:
        sentinel = self.root / "operator-stop.json"
        if sentinel.exists():
            return "operator stop requested"
        row = self._db.execute("SELECT reason FROM stops WHERE engagement=?", (self.engagement_id,)).fetchone()
        return row[0] if row else None

    def record_control_reconciled(self, correlation_id: str, received_at: str, received_monotonic_ns: int) -> bool:
        """Record a central-writer acknowledgement for a durable stop receipt."""
        _safe_id(correlation_id, 64)
        if not isinstance(received_at, str) or len(received_at) > 48 or type(received_monotonic_ns) is not int or received_monotonic_ns < 0:
            raise PolicyError("invalid operator control acknowledgement")
        with self._tx():
            before = self._db.execute("SELECT 1 FROM control_reconciliations WHERE correlation_id=?", (correlation_id,)).fetchone()
            if before:
                return False
            self._db.execute("INSERT INTO control_reconciliations VALUES (?,?,?,?)",
                             (correlation_id, received_at, received_monotonic_ns, _utc_now()))
            return True

    def control_reconciled(self, correlation_id: str) -> bool:
        _safe_id(correlation_id, 64)
        return self._db.execute("SELECT 1 FROM control_reconciliations WHERE correlation_id=?", (correlation_id,)).fetchone() is not None

    def assign(self, workspace_id: str, target_id: str, auth_realm: str = "") -> None:
        self._assert_mutable()
        if not target_id:
            return
        with self._tx():
            self._assert_mutable()
            # Imports merged into this already-open ledger connection must be
            # indexed before any new cumulative admission check.
            from .migrations import backfill_reservation_scopes
            backfill_reservation_scopes(self._db)
            self._assign_locked(workspace_id, target_id, auth_realm)

    def reserve_wave(self, plan, items) -> tuple:
        """Atomically freeze a verified wave and spend every item's reservation.

        ``items`` is an internal broker-produced mapping keyed by frozen
        ``AssessmentItem.item_id``.  It deliberately holds no arbitrary plan
        JSON: each entry is the exact accounting tuple that was independently
        approved before this method is called.
        """
        from .assessment_contracts import AssessmentPlan, WaveClaim, assessment_request_id
        if not isinstance(plan, AssessmentPlan) or plan.engagement_id != self.engagement_id:
            raise PolicyError("wave does not match ledger")
        if not isinstance(items, dict) or set(items) != {item.item_id for item in plan.items}:
            raise PolicyError("wave item reservation mismatch")
        normalized = {item.item_id: self._wave_item_input(plan, item, items[item.item_id]) for item in plan.items}
        budget_sha256 = digest({item_id: [canonical_json(limit).decode("ascii") for limit in values["budget_limits"]]
                                for item_id, values in normalized.items()})
        with self._tx():
            self._assert_mutable()
            from .migrations import backfill_reservation_scopes
            backfill_reservation_scopes(self._db)
            if self.stopped():
                raise PolicyError("engagement is stopped")
            existing = self._db.execute(
                "SELECT plan_sha256 FROM assessment_waves WHERE engagement=? AND wave_id=?",
                (self.engagement_id, plan.wave_id)).fetchone()
            if existing:
                if existing[0] != plan.sha256:
                    raise PolicyError("wave id is immutable")
                raise PolicyError("wave already reserved")
            # Reserve before storing any wave record.  A limit/assignment
            # failure therefore rolls back both the frozen wave and every
            # scope charge, rather than leaving an executable-looking plan.
            for item in plan.items:
                values = normalized[item.item_id]
                self._reserve_locked(values["request_id"], values["bounds"],
                                     workspace_id=plan.workspace_id, target_id=values["target_id"],
                                     auth_realm=values["auth_realm"], workflow_id=values["workflow_id"],
                                     limits=values["limits"], budget_limits=values["budget_limits"],
                                     state="planned", enforce_inflight=False)
            now = _utc_now()
            self._db.execute("INSERT INTO assessment_waves VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                self.engagement_id, self.device_id, plan.wave_id, plan.workspace_id, plan.operator_id,
                plan.policy_revision, plan.policy_sha256, plan.release_sha256, plan.sha256,
                budget_sha256, canonical_json(plan).decode("utf-8"), "frozen", now, now, None, None, None))
            claims = []
            for item in plan.items:
                request_id = assessment_request_id(plan.wave_id, item.item_id)
                self._db.execute("INSERT INTO assessment_items VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                    self.engagement_id, self.device_id, plan.wave_id, item.item_id, request_id, request_id,
                    item.target_id, item.check_id, item.role_id, item.module_id, "planned", None))
                claims.append(WaveClaim(plan.wave_id, item.item_id, request_id, plan.sha256, "planned"))
            return tuple(claims)

    def claim_wave_item(self, wave_id: str, item_id: str):
        """Claim exactly the next frozen item; this never dispatches it."""
        from .assessment_contracts import WaveClaim, assessment_request_id
        _safe_id(wave_id, 256); _safe_id(item_id, 256)
        with self._tx():
            self._assert_mutable()
            wave = self._wave_row_locked(wave_id)
            item = self._wave_item_row_locked(wave_id, item_id)
            if item[1] in _WAVE_TERMINAL:
                return WaveClaim(wave_id, item_id, item[0], wave[0], item[1], item[2])
            if self.stopped():
                raise PolicyError("engagement is stopped")
            if wave[1] != "frozen" or item[1] != "planned":
                raise PolicyError("wave item is not claimable")
            ordered_ids = self._wave_item_order_locked(wave[2])
            index = ordered_ids.index(item_id)
            if any(self._wave_item_row_locked(wave_id, earlier)[1] != "complete" for earlier in ordered_ids[:index]):
                raise PolicyError("prior wave item is not terminal")
            if item[0] != assessment_request_id(wave_id, item_id):
                raise PolicyError("stored wave action binding is invalid")
            reservation = self._db.execute(
                "SELECT workspace,target,state FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                (self.engagement_id, self.device_id, item[0])).fetchone()
            if reservation is None or reservation[2] != "planned":
                raise PolicyError("stored wave reservation is invalid")
            if self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND request_id<>? "
                                "AND state IN ('dispatching','running') AND (workspace=? OR (? IS NOT NULL AND target=?))",
                                (self.engagement_id, item[0], reservation[0], reservation[1], reservation[1])).fetchone():
                raise PolicyError("workspace or target already has an operation in flight")
            if self._db.execute("UPDATE assessment_items SET state='dispatching' WHERE engagement=? AND device=? "
                                "AND wave_id=? AND item_id=? AND state='planned'",
                                (self.engagement_id, self.device_id, wave_id, item_id)).rowcount != 1:
                raise PolicyError("wave item claim conflict")
            if self._db.execute("UPDATE reservations SET state='dispatching' WHERE engagement=? AND device=? "
                                "AND request_id=? AND state='planned'", (self.engagement_id, self.device_id, item[0])).rowcount != 1:
                raise PolicyError("wave reservation claim conflict")
            self._db.execute("UPDATE assessment_waves SET state='dispatching',started_at=COALESCE(started_at,?) "
                             "WHERE engagement=? AND device=? AND wave_id=?", (_utc_now(), self.engagement_id, self.device_id, wave_id))
            return WaveClaim(wave_id, item_id, item[0], wave[0], "dispatching")

    def activate_wave_item(self, wave_id: str, item_id: str, request_id: str, plan_sha256: str):
        """Broker-only dispatch gate: recheck the frozen action before I/O."""
        from .assessment_contracts import WaveClaim
        _safe_id(wave_id, 256); _safe_id(item_id, 256); _safe_id(request_id, 128)
        with self._tx():
            self._assert_mutable()
            if self.stopped():
                raise PolicyError("engagement is stopped")
            wave = self._wave_row_locked(wave_id)
            item = self._wave_item_row_locked(wave_id, item_id)
            if (wave[0], item[0]) != (plan_sha256, request_id):
                raise PolicyError("wave activation binding mismatch")
            if item[1] != "dispatching":
                raise PolicyError("wave item is not dispatching")
            if self._db.execute("UPDATE assessment_items SET state='running' WHERE engagement=? AND device=? "
                                "AND wave_id=? AND item_id=? AND state='dispatching'",
                                (self.engagement_id, self.device_id, wave_id, item_id)).rowcount != 1:
                raise PolicyError("wave item activation conflict")
            if self._db.execute("UPDATE reservations SET state='running' WHERE engagement=? AND device=? "
                                "AND request_id=? AND state='dispatching'", (self.engagement_id, self.device_id, request_id)).rowcount != 1:
                raise PolicyError("wave reservation activation conflict")
            return WaveClaim(wave_id, item_id, request_id, plan_sha256, "running")

    def finish_wave_item(self, wave_id: str, item_id: str, state: str, result_json=None):
        """Persist one terminal receipt and stop this wave after any non-success."""
        from .assessment_contracts import WaveClaim
        if state not in _WAVE_TERMINAL:
            raise PolicyError("invalid terminal wave state")
        receipt = self._canonical_wave_receipt(result_json)
        parsed_receipt = json.loads(receipt)
        if set(parsed_receipt) - {"status", "facts", "evidence", "reason", "usage"} or parsed_receipt.get("status") != state:
            raise PolicyError("wave receipt does not match terminal state")
        if ("facts" in parsed_receipt and type(parsed_receipt["facts"]) is not dict
                or "evidence" in parsed_receipt and type(parsed_receipt["evidence"]) is not list
                or "reason" in parsed_receipt and not isinstance(parsed_receipt["reason"], (str, type(None)))
                or "usage" in parsed_receipt and type(parsed_receipt["usage"]) is not dict):
            raise PolicyError("invalid wave terminal receipt")
        _safe_id(wave_id, 256); _safe_id(item_id, 256)
        with self._tx():
            wave = self._wave_row_locked(wave_id)
            item = self._wave_item_row_locked(wave_id, item_id)
            if item[1] in _WAVE_TERMINAL:
                if item[1] != state or item[2] != receipt:
                    raise PolicyError("wave terminal receipt is immutable")
                return WaveClaim(wave_id, item_id, item[0], wave[0], item[1], item[2])
            if item[1] not in {"dispatching", "running"}:
                raise PolicyError("wave item is not active")
            if self._db.execute("UPDATE assessment_items SET state=?,result_json=? WHERE engagement=? AND device=? "
                                "AND wave_id=? AND item_id=? AND state IN ('dispatching','running')",
                                (state, receipt, self.engagement_id, self.device_id, wave_id, item_id)).rowcount != 1:
                raise PolicyError("wave item finish conflict")
            reservation = self._db.execute("SELECT state FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                                           (self.engagement_id, self.device_id, item[0])).fetchone()
            if reservation is None or reservation[0] not in {"dispatching", "running", state}:
                raise PolicyError("wave reservation finish binding is invalid")
            if reservation[0] in {"dispatching", "running"}:
                self._db.execute("UPDATE reservations SET state=?,usage=? WHERE engagement=? AND device=? AND request_id=? "
                                 "AND state IN ('dispatching','running')",
                                 (state, "{}", self.engagement_id, self.device_id, item[0]))
            if state != "complete":
                self._stop_wave_locked(wave_id, "wave terminal outcome")
            elif not self._db.execute("SELECT 1 FROM assessment_items WHERE engagement=? AND device=? AND wave_id=? "
                                      "AND state<>'complete'", (self.engagement_id, self.device_id, wave_id)).fetchone():
                self._db.execute("UPDATE assessment_waves SET state='complete',finished_at=? WHERE engagement=? AND device=? AND wave_id=?",
                                 (_utc_now(), self.engagement_id, self.device_id, wave_id))
            else:
                self._db.execute("UPDATE assessment_waves SET state='frozen' WHERE engagement=? AND device=? AND wave_id=?",
                                 (self.engagement_id, self.device_id, wave_id))
            return WaveClaim(wave_id, item_id, item[0], wave[0], state, receipt)

    def recover_waves(self, workspace_id: str | None = None) -> tuple:
        try:
            return self._recover_waves(workspace_id)
        except BaseException:
            from .audit_control import _latch_audit_failure
            _latch_audit_failure(self)
            raise

    def _recover_waves(self, workspace_id: str | None = None) -> tuple:
        """Turn interrupted claims into durable uncertainty; never retry them."""
        from .assessment_contracts import WaveClaim
        if workspace_id is not None:
            _safe_id(workspace_id, 256)
        recovered = []
        with self._tx():
            self._assert_mutable()
            query = "SELECT wave_id,plan_sha256,state FROM assessment_waves WHERE engagement=? AND device=?"
            params: tuple[Any, ...] = (self.engagement_id, self.device_id)
            if workspace_id is not None:
                query += " AND workspace=?"; params += (workspace_id,)
            waves = self._db.execute(query, params).fetchall()
            for wave_id, plan_sha256, wave_state in waves:
                active = self._db.execute("SELECT item_id,request_id,state FROM assessment_items WHERE engagement=? AND device=? "
                                          "AND wave_id=? AND state IN ('dispatching','running')",
                                          (self.engagement_id, self.device_id, wave_id)).fetchall()
                if not active:
                    continue  # A wholly frozen wave is deliberately resumable.
                receipt = self._canonical_wave_receipt({"reason": "recovery", "state": "uncertain"})
                for item_id, request_id, ignored in active:
                    reservation = self._db.execute("SELECT state FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                        (self.engagement_id, self.device_id, request_id)).fetchone()
                    # Broker may have completed its own durable receipt before
                    # the campaign completion checkpoint. This still becomes
                    # uncertain; it must never be automatically dispatched again.
                    if reservation is None or reservation[0] not in {"dispatching", "running", *_WAVE_TERMINAL}:
                        raise PolicyError("wave recovery reservation linkage is corrupt")
                    self._db.execute("UPDATE assessment_items SET state='uncertain',result_json=? WHERE engagement=? AND device=? "
                                     "AND wave_id=? AND item_id=?", (receipt, self.engagement_id, self.device_id, wave_id, item_id))
                    if self._db.execute("UPDATE reservations SET state='uncertain' WHERE engagement=? AND device=? AND request_id=?",
                                     (self.engagement_id, self.device_id, request_id)).rowcount != 1:
                        raise PolicyError("wave recovery lost its reservation")
                    recovered.append(WaveClaim(wave_id, item_id, request_id, plan_sha256, "uncertain", receipt))
                self._stop_wave_locked(wave_id, "wave recovery")
        return tuple(recovered)

    def _assign_locked(self, workspace_id: str, target_id: str, auth_realm: str = "") -> None:
        realm = auth_realm or "-"
        row = self._db.execute("SELECT workspace FROM assignments WHERE engagement=? AND target=?",
                               (self.engagement_id, target_id)).fetchone()
        if row and row[0] != workspace_id:
            raise PolicyError("target is assigned to another workspace")
        if realm != "-":
            row = self._db.execute("SELECT workspace FROM assignments WHERE engagement=? AND realm=?",
                                   (self.engagement_id, realm)).fetchone()
            if row and row[0] != workspace_id:
                raise PolicyError("authentication realm is assigned to another workspace")
        self._db.execute("INSERT OR REPLACE INTO assignments VALUES (?,?,?,?)",
                         (self.engagement_id, target_id, realm, workspace_id))

    def _wave_item_input(self, plan, item, raw) -> dict[str, Any]:
        """Validate the narrow broker-to-ledger accounting tuple for one item."""
        from .assessment_contracts import assessment_request_id
        required = {"request_id", "action_id", "bounds", "target_id", "target_policy_id",
                    "auth_realm", "workflow_id", "limits", "budget_limits"}
        if not isinstance(raw, dict) or set(raw) != required:
            raise PolicyError("invalid wave item reservation")
        request_id = assessment_request_id(plan.wave_id, item.item_id)
        if raw["request_id"] != request_id or raw["action_id"] != request_id:
            raise PolicyError("wave action identity mismatch")
        if raw["target_policy_id"] != item.target_id:
            raise PolicyError("wave target policy binding mismatch")
        _safe_id(raw["target_id"], 512)
        if not isinstance(raw["auth_realm"], str) or len(raw["auth_realm"]) > 256:
            raise PolicyError("invalid wave authentication realm")
        if raw["workflow_id"] != plan.wave_id:
            raise PolicyError("wave workflow binding mismatch")
        if not isinstance(raw["bounds"], Bounds):
            raise PolicyError("invalid wave reservation bounds")
        if raw["limits"] is not None and not isinstance(raw["limits"], dict):
            raise PolicyError("invalid wave durable limits")
        budget_limits = raw["budget_limits"]
        if not isinstance(budget_limits, (tuple, list)):
            raise PolicyError("invalid wave scoped limits")
        return {"request_id": request_id, "bounds": raw["bounds"], "target_id": raw["target_id"],
                "auth_realm": raw["auth_realm"], "workflow_id": raw["workflow_id"],
                "limits": raw["limits"], "budget_limits": tuple(budget_limits)}

    @staticmethod
    def _canonical_wave_receipt(value) -> str:
        if isinstance(value, str):
            if len(value.encode("utf-8")) > 65536:
                raise PolicyError("wave result exceeds allowance")
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError, RecursionError):
                raise PolicyError("wave result is not canonical") from None
            if type(parsed) is not dict or canonical_json(parsed).decode("utf-8") != value:
                raise PolicyError("wave result is not canonical")
            return value
        if type(value) is dict:
            encoded = canonical_json(value)
            if len(encoded) > 65536:
                raise PolicyError("wave result exceeds allowance")
            return encoded.decode("utf-8")
        raise PolicyError("wave result receipt is required")

    def _wave_row_locked(self, wave_id: str):
        row = self._db.execute("SELECT plan_sha256,state,plan_json FROM assessment_waves WHERE engagement=? AND device=? AND wave_id=?",
                               (self.engagement_id, self.device_id, wave_id)).fetchone()
        if row is None:
            raise PolicyError("unknown wave")
        return row

    def _wave_item_row_locked(self, wave_id: str, item_id: str):
        row = self._db.execute("SELECT request_id,state,result_json FROM assessment_items WHERE engagement=? AND device=? AND wave_id=? AND item_id=?",
                               (self.engagement_id, self.device_id, wave_id, item_id)).fetchone()
        if row is None:
            raise PolicyError("unknown wave item")
        return row

    @staticmethod
    def _wave_item_order_locked(plan_json: str) -> list[str]:
        try:
            parsed = json.loads(plan_json)
            values = [item["item_id"] for item in parsed["items"]]
            if not values or len(values) != len(set(values)) or any(type(value) is not str for value in values):
                raise ValueError()
        except (KeyError, TypeError, ValueError, RecursionError):
            raise PolicyError("stored wave plan is invalid") from None
        return values

    def _stop_wave_locked(self, wave_id: str, reason: str) -> None:
        """Stop unclaimed work without nesting a transaction through stop()."""
        receipt = self._canonical_wave_receipt({"reason": reason, "state": "stopped"})
        planned = self._db.execute("SELECT request_id FROM assessment_items WHERE engagement=? AND device=? AND wave_id=? AND state='planned'",
                                   (self.engagement_id, self.device_id, wave_id)).fetchall()
        self._db.execute("UPDATE assessment_items SET state='stopped',result_json=? WHERE engagement=? AND device=? AND wave_id=? AND state='planned'",
                         (receipt, self.engagement_id, self.device_id, wave_id))
        for (request_id,) in planned:
            if self._db.execute("UPDATE reservations SET state='stopped',usage=? WHERE engagement=? AND device=? AND request_id=? AND state='planned'",
                             ("{}", self.engagement_id, self.device_id, request_id)).rowcount != 1:
                raise PolicyError("planned wave reservation linkage is corrupt")
        self._db.execute("UPDATE assessment_waves SET state='stopped',finished_at=?,reason=? WHERE engagement=? AND device=? AND wave_id=?",
                         (_utc_now(), reason, self.engagement_id, self.device_id, wave_id))
        self._db.execute("INSERT OR IGNORE INTO stops VALUES (?,?)", (self.engagement_id, reason))

    def reserve(self, request_id: str, bounds: Bounds, *, workspace_id: str = "",
                target_id: str | None = None, auth_realm: str = "", workflow_id: str = "default",
                limits: dict[str, int] | None = None, budget_limits=()) -> Reservation:
        """Atomically reserve all declared budgets before any dispatch."""
        self._assert_mutable()
        with self._tx():
            ceiling = self._reserve_locked(request_id, bounds, workspace_id=workspace_id, target_id=target_id,
                                           auth_realm=auth_realm, workflow_id=workflow_id, limits=limits,
                                           budget_limits=budget_limits, state="running", enforce_inflight=True)
        remaining = {k: max(0, int(limit - (self.usage(target_id=target_id) if k in _TARGET_SCOPED_COUNTERS and target_id
                                           else self.usage(workflow_id)).get(k, 0)))
                     for k, limit in ceiling.items() if k in _COUNTERS}
        return Reservation(request_id, bounds, remaining)

    def _reserve_locked(self, request_id: str, bounds: Bounds, *, workspace_id: str,
                        target_id: str | None, auth_realm: str, workflow_id: str,
                        limits: dict[str, int] | None, budget_limits, state: str,
                        enforce_inflight: bool) -> dict[str, int]:
        """Reservation primitive called only while ``BEGIN IMMEDIATE`` is held."""
        _safe_id(request_id, 128)
        if state not in {"planned", "running"}:
            raise PolicyError("invalid reservation state")
        if not isinstance(bounds, Bounds):
            raise PolicyError("invalid reservation bounds")
        if not isinstance(budget_limits, (tuple, list)) or len(budget_limits) > 256 or any(not isinstance(b, BudgetLimit) for b in budget_limits):
            raise PolicyError("invalid scoped budget limits")
        if len({(b.scope, b.key, b.counter) for b in budget_limits}) != len(budget_limits):
            raise PolicyError("duplicate scoped budget limit")
        for item in budget_limits:
            if item.scope in {"engagement", "device"} and item.key != getattr(self, item.scope + "_id"):
                raise PolicyError("scoped budget identity mismatch")
        values = asdict(bounds)
        if any(type(values.get(key)) is not int or not 0 <= values[key] <= 2147483647 for key in _COUNTERS):
            raise PolicyError("invalid reservation bounds")
        if not isinstance(workspace_id, str) or not isinstance(workflow_id, str) or not isinstance(auth_realm, str):
            raise PolicyError("invalid reservation scope")
        if target_id is not None and not isinstance(target_id, str):
            raise PolicyError("invalid reservation target")
        from .migrations import backfill_reservation_scopes
        self._assert_mutable()
        backfill_reservation_scopes(self._db)
        if self.stopped():
            raise PolicyError("engagement is stopped")
        old = self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                               (self.engagement_id, self.device_id, request_id)).fetchone()
        if old:
            raise PolicyError("request id was already reserved")
        if target_id:
            self._assign_locked(workspace_id, target_id, auth_realm)
        if enforce_inflight:
            if self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND workspace=? AND state IN ('dispatching','running')",
                                (self.engagement_id, workspace_id)).fetchone():
                raise PolicyError("workspace already has an operation in flight")
            if target_id and self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND target=? AND state IN ('dispatching','running')",
                                               (self.engagement_id, target_id)).fetchone():
                raise PolicyError("target already has an operation in flight")
        ceiling = dict(self.limits)
        for key, value in (limits or {}).items():
            if key not in _COUNTERS or type(value) is not int or not 0 <= value <= 2147483647:
                raise PolicyError("invalid durable budget limit")
            ceiling[key] = min(ceiling.get(key, value), value)
        scope_keys = {"engagement": self.engagement_id, "device": self.device_id, "workspace": workspace_id or "-",
                      "workflow": workflow_id or "default", "target": target_id or "-", "realm": auth_realm or "-"}
        target_or_workflow = "target" if target_id else "workflow"
        legacy_scope = {
            "request_limit": target_or_workflow,
            "tcp_connects": target_or_workflow,
            "udp_datagrams": target_or_workflow,
            "protocol_requests": target_or_workflow,
            "tx_bytes": target_or_workflow,
            "rx_bytes": target_or_workflow,
            "auth_posts": "realm",
            "model_calls": "workflow",
            "actions": "workflow",
            "output_bytes": "workflow",
            "process_limit": "workflow",
        }
        effective_limits: dict[tuple[str, str], int] = {}
        for scope, scope_key in scope_keys.items():
            for counter in _COUNTERS:
                spent, prior_ceiling = self._db.execute(
                    "SELECT COALESCE(SUM(reserved),0),MIN(ceiling) FROM reservation_scopes WHERE engagement=? AND scope_kind=? AND scope_key=? AND counter=?",
                    (self.engagement_id, scope, scope_key, counter)).fetchone()
                candidates = [b.ceiling for b in budget_limits if (b.scope, b.key, b.counter) == (scope, scope_key, counter)]
                if legacy_scope[counter] == scope and counter in ceiling:
                    candidates.append(ceiling[counter])
                if prior_ceiling is not None:
                    candidates.append(prior_ceiling)
                if candidates:
                    effective = min(candidates)
                    effective_limits[scope, counter] = effective
                    if spent + values[counter] > effective:
                        raise PolicyError("durable scoped budget exhausted")
        if values["auth_posts"]:
            if not auth_realm:
                raise PolicyError("authentication reservation requires an exact realm")
            unknown = self._db.execute("SELECT COALESCE(SUM(reserved),0) FROM reservation_scopes WHERE engagement=? AND scope_kind='realm' AND scope_key='-' AND counter='auth_posts'",
                                       (self.engagement_id,)).fetchone()[0]
            if unknown:
                raise PolicyError("unattributed historical authentication requires human review")
        self._db.execute("INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (self.engagement_id, self.device_id, request_id, workspace_id, target_id, auth_realm,
                          workflow_id, json.dumps(values, sort_keys=True), state, "{}"))
        for scope, scope_key in scope_keys.items():
            for counter in _COUNTERS:
                self._db.execute("INSERT INTO reservation_scopes VALUES (?,?,?,?,?,?,?,?)",
                                 (self.engagement_id, self.device_id, request_id, scope, scope_key, counter,
                                  int(values[counter]), effective_limits.get((scope, counter))))
        return ceiling

    def finish(self, request_id: str, usage: dict[str, int] | None = None, *, state: str = "finished") -> None:
        self._assert_mutable()
        if state not in _WAVE_TERMINAL | {"finished"}:
            raise PolicyError("invalid terminal reservation state")
        usage = {} if usage is None else usage
        if not isinstance(usage, dict) or any(k not in _COUNTERS or type(v) is not int or v < 0 for k, v in usage.items()):
            raise PolicyError("invalid actual usage receipt")
        with self._tx():
            self._assert_mutable()
            row = self._db.execute("SELECT state,usage FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                                   (self.engagement_id, self.device_id, request_id)).fetchone()
            if not row:
                raise PolicyError("no reservation for request")
            if row[0] in _WAVE_TERMINAL | {"finished"}:
                if row[0] == state and json.loads(row[1]) == usage: return
                raise PolicyError("terminal reservation receipt is immutable")
            if row[0] not in {"running", "dispatching"}:
                raise PolicyError("reservation is not active")
            self._db.execute("UPDATE reservations SET state=?, usage=? WHERE engagement=? AND device=? AND request_id=?",
                             (state, json.dumps(usage, sort_keys=True), self.engagement_id, self.device_id, request_id))

    @staticmethod
    def _transport_values(*, tcp_connects=0, udp_datagrams=0, protocol_requests=0,
                          tx_bytes=0, rx_bytes=0) -> dict[str, int]:
        values = {
            "tcp_connects": tcp_connects,
            "udp_datagrams": udp_datagrams,
            "protocol_requests": protocol_requests,
            "tx_bytes": tx_bytes,
            "rx_bytes": rx_bytes,
        }
        if any(type(value) is not int or not 0 <= value <= 2147483647 for value in values.values()):
            raise PolicyError("invalid transport usage event")
        if not any(values.values()):
            raise PolicyError("empty transport usage event")
        return values

    def begin_attempt(self, request_id: str, attempt_id: str, *, started_ns: int, deadline_ns: int) -> None:
        """Persist one network-attempt intent before a worker can emit traffic."""
        _safe_id(request_id, 128); _safe_id(attempt_id, 128)
        if (type(started_ns) is not int or type(deadline_ns) is not int or started_ns < 0
                or deadline_ns <= started_ns):
            raise PolicyError("invalid transport attempt timing")
        self._assert_mutable()
        with self._tx():
            self._assert_mutable()
            if self.stopped():
                raise PolicyError("engagement is stopped")
            row = self._db.execute(
                "SELECT state FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                (self.engagement_id, self.device_id, request_id),
            ).fetchone()
            if row is None or row[0] not in {"running", "dispatching"}:
                raise PolicyError("transport attempt requires an active reservation")
            if self._db.execute(
                "SELECT 1 FROM reservation_attempts WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?",
                (self.engagement_id, self.device_id, request_id, attempt_id),
            ).fetchone():
                raise PolicyError("transport attempt id was already used")
            self._db.execute(
                """INSERT INTO reservation_attempts(
                    engagement,device,request_id,attempt_id,tcp_connects,udp_datagrams,
                    request_count,request_bytes,response_bytes,elapsed_ms,deadline_ns,
                    started_ns,deadline_exceeded,state)
                   VALUES (?,?,?,?,0,0,0,0,0,0,?,?,0,'running')""",
                (self.engagement_id, self.device_id, request_id, attempt_id, deadline_ns, started_ns),
            )

    def record_attempt_event(self, request_id: str, attempt_id: str, event_id: str, **raw_values) -> bool:
        """Append one idempotent measured event and preserve any overrun."""
        _safe_id(request_id, 128); _safe_id(attempt_id, 128); _safe_id(event_id, 128)
        if set(raw_values) - set(_TRANSPORT_COUNTERS):
            raise PolicyError("unknown transport usage field")
        values = self._transport_values(**raw_values)
        ordered = tuple(values[key] for key in _TRANSPORT_COUNTERS)
        failure = None
        created = False
        self._assert_mutable()
        with self._tx():
            self._assert_mutable()
            attempt = self._db.execute(
                "SELECT state FROM reservation_attempts WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?",
                (self.engagement_id, self.device_id, request_id, attempt_id),
            ).fetchone()
            if attempt is None:
                raise PolicyError("transport event requires an active attempt")
            old = self._db.execute(
                """SELECT tcp_connects,udp_datagrams,request_count,request_bytes,response_bytes
                   FROM reservation_attempt_events
                   WHERE engagement=? AND device=? AND request_id=? AND attempt_id=? AND event_id=?""",
                (self.engagement_id, self.device_id, request_id, attempt_id, event_id),
            ).fetchone()
            if old is not None:
                if tuple(old) == ordered:
                    return False
                if attempt[0] == "running":
                    self._db.execute(
                        "UPDATE reservation_attempts SET state='uncertain' WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?",
                        (self.engagement_id, self.device_id, request_id, attempt_id),
                    )
                self._db.execute("INSERT OR IGNORE INTO stops VALUES (?,?)", (self.engagement_id, "transport event receipt conflict"))
                failure = "transport event receipt conflict"
            else:
                if attempt[0] != "running":
                    raise PolicyError("transport event requires an active attempt")
                self._db.execute(
                    """INSERT INTO reservation_attempt_events(
                        engagement,device,request_id,attempt_id,event_id,tcp_connects,
                        udp_datagrams,request_count,request_bytes,response_bytes)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (self.engagement_id, self.device_id, request_id, attempt_id, event_id, *ordered),
                )
                created = True
                totals = self._attempt_totals_locked(request_id)
                encoded = self._db.execute(
                    "SELECT bounds FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                    (self.engagement_id, self.device_id, request_id),
                ).fetchone()[0]
                bounds = json.loads(encoded)
                if any(totals[key] > int(bounds.get(key, 0)) for key in _TRANSPORT_COUNTERS):
                    self._db.execute(
                        "UPDATE reservation_attempts SET state='uncertain' WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?",
                        (self.engagement_id, self.device_id, request_id, attempt_id),
                    )
                    self._db.execute("INSERT OR IGNORE INTO stops VALUES (?,?)", (self.engagement_id, "transport allowance exceeded"))
                    failure = "transport allowance exceeded"
                self._refresh_attempt_totals_locked(request_id, attempt_id)
        if failure:
            raise PolicyError(failure)
        return created

    def _attempt_totals_locked(self, request_id: str, attempt_id: str | None = None) -> dict[str, int]:
        where = "engagement=? AND device=? AND request_id=?"
        params: list[Any] = [self.engagement_id, self.device_id, request_id]
        if attempt_id is not None:
            where += " AND attempt_id=?"; params.append(attempt_id)
        row = self._db.execute(
            f"""SELECT COALESCE(SUM(tcp_connects),0),COALESCE(SUM(udp_datagrams),0),
                       COALESCE(SUM(request_count),0),COALESCE(SUM(request_bytes),0),
                       COALESCE(SUM(response_bytes),0)
                  FROM reservation_attempt_events WHERE {where}""",
            params,
        ).fetchone()
        return dict(zip(_TRANSPORT_COUNTERS, (int(value) for value in row), strict=True))

    def _refresh_attempt_totals_locked(self, request_id: str, attempt_id: str) -> dict[str, int]:
        totals = self._attempt_totals_locked(request_id, attempt_id)
        self._db.execute(
            """UPDATE reservation_attempts
                  SET tcp_connects=?,udp_datagrams=?,request_count=?,request_bytes=?,response_bytes=?
                WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?""",
            (*tuple(totals[key] for key in _TRANSPORT_COUNTERS), self.engagement_id, self.device_id, request_id, attempt_id),
        )
        return totals

    def finish_attempt(self, request_id: str, attempt_id: str, *, state: str, ended_ns: int) -> dict[str, Any]:
        """Seal an attempt; a passed deadline can never become a success."""
        _safe_id(request_id, 128); _safe_id(attempt_id, 128)
        if state not in {"complete", "failed", "blocked", "stopped", "uncertain"}:
            raise PolicyError("invalid transport attempt state")
        if type(ended_ns) is not int or ended_ns < 0:
            raise PolicyError("invalid transport completion timing")
        self._assert_mutable()
        with self._tx():
            self._assert_mutable()
            row = self._db.execute(
                """SELECT state,started_ns,deadline_ns FROM reservation_attempts
                   WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?""",
                (self.engagement_id, self.device_id, request_id, attempt_id),
            ).fetchone()
            if row is None:
                raise PolicyError("unknown transport attempt")
            if row[0] != "running":
                receipt = self._attempt_receipt_locked(request_id, attempt_id)
                if receipt["state"] == state:
                    return receipt
                raise PolicyError("terminal transport receipt is immutable")
            started_ns, deadline_ns = int(row[1]), int(row[2])
            if ended_ns < started_ns:
                raise PolicyError("transport monotonic time moved backwards")
            exceeded = ended_ns > deadline_ns
            final_state = "uncertain" if exceeded and state == "complete" else state
            totals = self._refresh_attempt_totals_locked(request_id, attempt_id)
            self._db.execute(
                """UPDATE reservation_attempts SET elapsed_ms=?,deadline_exceeded=?,state=?
                   WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?""",
                ((ended_ns - started_ns) // 1_000_000, int(exceeded), final_state,
                 self.engagement_id, self.device_id, request_id, attempt_id),
            )
            if final_state == "uncertain":
                self._db.execute("INSERT OR IGNORE INTO stops VALUES (?,?)", (self.engagement_id, "transport outcome uncertain"))
            return {
                "attempt_id": attempt_id,
                "state": final_state,
                "started_ns": started_ns,
                "deadline_ns": deadline_ns,
                "elapsed_ms": (ended_ns - started_ns) // 1_000_000,
                "deadline_exceeded": exceeded,
                "usage": totals,
            }

    def _attempt_receipt_locked(self, request_id: str, attempt_id: str) -> dict[str, Any]:
        row = self._db.execute(
            """SELECT state,started_ns,deadline_ns,elapsed_ms,deadline_exceeded,
                      tcp_connects,udp_datagrams,request_count,request_bytes,response_bytes
               FROM reservation_attempts
              WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?""",
            (self.engagement_id, self.device_id, request_id, attempt_id),
        ).fetchone()
        if row is None:
            raise PolicyError("unknown transport attempt")
        return {
            "attempt_id": attempt_id,
            "state": row[0],
            "started_ns": int(row[1]),
            "deadline_ns": int(row[2]),
            "elapsed_ms": int(row[3]),
            "deadline_exceeded": bool(row[4]),
            "usage": dict(zip(_TRANSPORT_COUNTERS, (int(value) for value in row[5:]), strict=True)),
        }

    def attempt_receipt(self, request_id: str) -> dict[str, Any]:
        _safe_id(request_id, 128)
        attempts = [
            self._attempt_receipt_locked(request_id, row[0])
            for row in self._db.execute(
                """SELECT attempt_id FROM reservation_attempts
                   WHERE engagement=? AND device=? AND request_id=? ORDER BY started_ns,attempt_id""",
                (self.engagement_id, self.device_id, request_id),
            )
        ]
        if not attempts:
            raise PolicyError("no transport attempts for request")
        usage = {key: sum(item["usage"][key] for item in attempts) for key in _TRANSPORT_COUNTERS}
        return {"request_id": request_id, "usage": usage, "attempts": attempts}

    def recover_attempts(self) -> tuple[dict[str, Any], ...]:
        """Mark every crash-interrupted parent action uncertain without retry."""
        recovered = []
        self._assert_mutable()
        with self._tx():
            self._assert_mutable()
            rows = self._db.execute(
                """SELECT request_id FROM reservations
                   WHERE engagement=? AND device=? AND state IN ('running','dispatching')
                   ORDER BY request_id""",
                (self.engagement_id, self.device_id),
            ).fetchall()
            for (request_id,) in rows:
                attempts = self._db.execute(
                    """SELECT attempt_id,state FROM reservation_attempts
                       WHERE engagement=? AND device=? AND request_id=? ORDER BY started_ns,attempt_id""",
                    (self.engagement_id, self.device_id, request_id),
                ).fetchall()
                for attempt_id, attempt_state in attempts:
                    self._refresh_attempt_totals_locked(request_id, attempt_id)
                    if attempt_state == "running":
                        self._db.execute(
                            """UPDATE reservation_attempts SET state='uncertain'
                               WHERE engagement=? AND device=? AND request_id=? AND attempt_id=?""",
                            (self.engagement_id, self.device_id, request_id, attempt_id),
                        )
                    recovered.append({"request_id": request_id, "attempt_id": attempt_id, "state": "uncertain"})
                self._db.execute(
                    """UPDATE reservations SET state='uncertain'
                       WHERE engagement=? AND device=? AND request_id=? AND state IN ('running','dispatching')""",
                    (self.engagement_id, self.device_id, request_id),
                )
                if not attempts:
                    recovered.append({"request_id": request_id, "attempt_id": None, "state": "uncertain"})
            if recovered:
                self._db.execute("INSERT OR IGNORE INTO stops VALUES (?,?)", (self.engagement_id, "interrupted active reservation"))
        return tuple(recovered)

    def charge(self, request_id: str, counter: str, amount: int, *, workflow_id: str = "default", workspace_id: str = "", limits: dict[str, int] | None = None, budget_limits=()) -> None:
        self._assert_mutable()
        if counter not in _COUNTERS or amount < 0: raise PolicyError("invalid durable charge")
        values = {counter: amount}
        bounds = Bounds(output_bytes=0, process_limit=0, **values) if counter not in {"output_bytes", "process_limit"} else Bounds(**values)
        key = "charge:" + request_id
        try:
            self.reserve(key, bounds, workspace_id=workspace_id, workflow_id=workflow_id, limits=limits, budget_limits=budget_limits)
            self.finish(key, {counter: amount})
        except PolicyError:
            raise

    def rate_gate(self, target_id: str, interval_s: float, now: float) -> None:
        self._assert_mutable()
        with self._tx():
            self._assert_mutable()
            row=self._db.execute("SELECT seen FROM rates WHERE engagement=? AND target=?",(self.engagement_id,target_id)).fetchone()
            if row and now - float(row[0]) < interval_s: raise PolicyError("HTTP rate limit")
            self._db.execute("INSERT OR REPLACE INTO rates VALUES (?,?,?)",(self.engagement_id,target_id,now))

    def usage(self, workflow_id: str | None = None, *, target_id: str | None = None) -> dict[str, int]:
        q = "SELECT bounds,usage FROM reservations WHERE engagement=?"
        params: list[Any] = [self.engagement_id]
        if workflow_id is not None:
            q += " AND workflow=?"; params.append(workflow_id)
        if target_id is not None:
            q += " AND target=?"; params.append(target_id)
        totals = {k: 0 for k in _COUNTERS}
        for b, actual in self._db.execute(q, params):
            # Reservations, not reported actuals, are charged to prevent retries from escaping caps.
            for k, v in json.loads(b).items():
                if k in totals: totals[k] += int(v)
        return totals

    def merge(self, bundle: MergeBundle, *, trusted_device_keys: dict[str, str] | None = None,
              approved_digest: str | None = None) -> MergeReport:
        # v1 had no recipient binding or all-source snapshot.  Keep the method
        # only as an archival compatibility name and never import through it.
        return MergeReport(False, "legacy v1 handover is disabled; use merge_handover")

    def bundle(self, *, signer=None) -> MergeBundle:
        # v1 had no recipient binding or all-source snapshot.  Do not create a
        # legacy bundle that could be mistaken for an authorized transfer.
        raise PolicyError("legacy v1 handover is disabled; use handover_bundle")

    def enroll_workspace(self, workspace_id: str, audit_origin_id: str, path_hash: str) -> bool:
        """Bind a logical workspace to its audit origin and immutable path hash."""
        _safe_id(workspace_id, 128)
        _safe_id(audit_origin_id, 128)
        if not isinstance(path_hash, str) or len(path_hash) != 64 or any(char not in "0123456789abcdef" for char in path_hash.lower()):
            raise PolicyError("workspace path hash is invalid")
        path_hash = path_hash.lower()
        with self._tx():
            row = self._db.execute("SELECT audit_origin_id,path_hash FROM workspace_enrollment WHERE workspace_id=?", (workspace_id,)).fetchone()
            if row:
                if row[0] != audit_origin_id or row[1] != path_hash:
                    raise PolicyError("workspace enrollment binding conflict")
                return False
            self._assert_mutable()
            duplicate = self._db.execute("SELECT workspace_id FROM workspace_enrollment WHERE path_hash=?", (path_hash,)).fetchone()
            if duplicate:
                raise PolicyError("workspace path is already enrolled")
            self._db.execute("INSERT INTO workspace_enrollment VALUES (?,?,?)", (workspace_id, audit_origin_id, path_hash))
        return True

    def seal_for_handover(self, recipient_device_id: str, recipient_key_fingerprint: str) -> str:
        """Freeze this source and persist its exact all-source snapshot."""
        _safe_id(recipient_device_id, 128)
        if recipient_device_id == self.device_id:
            raise PolicyError("handover recipient must be another device")
        _fingerprint(recipient_key_fingerprint)
        with self._tx():
            if (self._db.execute("SELECT 1 FROM reservation_scopes WHERE ceiling IS NOT NULL LIMIT 1").fetchone()
                    or self._db.execute("SELECT 1 FROM assessment_waves LIMIT 1").fetchone()):
                raise PolicyError("v2 handover cannot preserve scoped ceilings or waves")
            if not self._db.execute("SELECT 1 FROM stops WHERE engagement=?", (self.engagement_id,)).fetchone():
                raise PolicyError("handover requires a stopped ledger")
            if self._db.execute("SELECT 1 FROM reservation_attempts WHERE state='running'").fetchone():
                raise PolicyError("handover requires no running transport attempts")
            if self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND state='running'", (self.engagement_id,)).fetchone():
                raise PolicyError("handover requires no running reservations")
            existing = self._db.execute("SELECT seal_id FROM handover_seals LIMIT 1").fetchone()
            if existing:
                raise PolicyError("ledger is already sealed for handover")
            snapshot = self._snapshot_locked()
            encoded = canonical_json(snapshot)
            seal_id = uuid.uuid4().hex
            self._db.execute("INSERT INTO handover_seals VALUES (?,?,?,?,?,?)", (
                seal_id, recipient_device_id, recipient_key_fingerprint.lower(), hashlib.sha256(encoded).hexdigest(),
                encoded.decode("utf-8"), _utc_now()))
        return seal_id

    def handover_bundle(self, seal_id: str, signer) -> MergeBundle:
        _safe_id(seal_id, 128)
        if not callable(signer):
            raise PolicyError("operator-managed signing capability is required")
        row = self._db.execute("SELECT recipient_device,recipient_key_fingerprint,snapshot_sha256,snapshot FROM handover_seals WHERE seal_id=?", (seal_id,)).fetchone()
        if not row:
            raise PolicyError("handover seal is unavailable")
        snapshot = json.loads(row[3])
        if hashlib.sha256(canonical_json(snapshot)).hexdigest() != row[2]:
            raise PolicyError("handover seal snapshot integrity failure")
        if hashlib.sha256(canonical_json(self._snapshot_locked())).hexdigest() != row[2]:
            raise PolicyError("sealed ledger changed after handover checkpoint")
        self._validate_snapshot(snapshot)
        unsigned = {"version": 2, "engagement_id": self.engagement_id, "policy_revision": self.policy_revision,
                    "source_device": self.device_id, "recipient_device": row[0], "recipient_key_fingerprint": row[1],
                    "seal_id": seal_id, "stopped": True, "snapshot_sha256": row[2], "snapshot": snapshot}
        try:
            signature = signer(canonical_json(unsigned))
            if not isinstance(signature, bytes):
                raise ValueError()
            encoded = base64.b64encode(signature).decode("ascii")
        except Exception as exc:
            raise PolicyError("handover signer failed") from exc
        payload = {**unsigned, "signature": encoded}
        return MergeBundle(self.engagement_id, self.device_id, payload)

    def merge_handover(self, bundle: MergeBundle, trusted_source_keys: dict[str, str],
                       local_key_fingerprint: str, approved_digest: str | None) -> MergeReport:
        """Atomically import one signed v2 bundle without double counting."""
        self._assert_mutable()
        try:
            payload = bundle.payload
            required = {"version", "engagement_id", "policy_revision", "source_device", "recipient_device",
                        "recipient_key_fingerprint", "seal_id", "stopped", "snapshot_sha256", "snapshot", "signature"}
            if bundle.engagement_id != self.engagement_id or set(payload) != required or payload.get("version") != 2:
                return MergeReport(False, "handover contract or engagement mismatch")
            if payload["policy_revision"] != self.policy_revision or payload["source_device"] != bundle.device_id:
                return MergeReport(False, "handover policy or source mismatch")
            _safe_id(payload["source_device"], 128)
            _safe_id(payload["recipient_device"], 128)
            _fingerprint(payload["recipient_key_fingerprint"])
            _safe_id(payload["seal_id"], 128)
            _fingerprint(payload["snapshot_sha256"])
            if payload["source_device"] == self.device_id:
                return MergeReport(False, "handover source and destination must differ")
            if payload["recipient_device"] != self.device_id or payload["recipient_key_fingerprint"] != _fingerprint(local_key_fingerprint):
                return MergeReport(False, "handover recipient binding mismatch")
            if payload["stopped"] is not True or not isinstance(approved_digest, str) or approved_digest != digest(asdict(bundle)):
                return MergeReport(False, "exact human-reviewed handover digest required")
            source_key_text = trusted_source_keys.get(bundle.device_id)
            if not isinstance(source_key_text, str):
                return MergeReport(False, "source signing key is not trusted")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(source_key_text, validate=True))
            signature = base64.b64decode(payload["signature"], validate=True)
            unsigned = {name: payload[name] for name in required if name != "signature"}
            key.verify(signature, canonical_json(unsigned))
            snapshot = payload["snapshot"]
            if hashlib.sha256(canonical_json(snapshot)).hexdigest() != payload["snapshot_sha256"]:
                return MergeReport(False, "handover snapshot hash mismatch")
            if snapshot.get("source_device") != payload["source_device"]:
                return MergeReport(False, "handover snapshot source mismatch")
            reservations, assignments, totals = self._validate_snapshot(snapshot)
        except Exception:
            return MergeReport(False, "handover signature or snapshot is invalid")
        bundle_hash = digest(asdict(bundle))
        try:
            with self._tx():
                self._assert_mutable()
                if self._db.execute("SELECT 1 FROM handover_imports WHERE bundle_hash=?", (bundle_hash,)).fetchone():
                    raise PolicyError("handover replay rejected")
                if self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND state='running'", (self.engagement_id,)).fetchone():
                    raise PolicyError("destination has a running reservation")
                existing = {(row[0], row[1]) for row in self._db.execute("SELECT device,request_id FROM reservations WHERE engagement=?", (self.engagement_id,))}
                if existing & {(item["device"], item["request_id"]) for item in reservations}:
                    raise PolicyError("handover reservation overlap")
                before = self.usage()
                for counter, limit in self.limits.items():
                    if before.get(counter, 0) + totals["all"].get(counter, 0) > limit:
                        raise PolicyError("handover exceeds destination durable allowance")
                combined = [{"target": r[0], "realm": r[1], "workflow": r[2], "bounds": json.loads(r[3])}
                            for r in self._db.execute("SELECT target,realm,workflow,bounds FROM reservations WHERE engagement=?", (self.engagement_id,))] + reservations
                scoped = {}
                for item in combined:
                    values = item["bounds"]
                    for counter, grouping, ceiling in (
                        ("request_limit", "target", 24),
                        ("tcp_connects", "target", 24),
                        ("udp_datagrams", "target", 24),
                        ("protocol_requests", "target", 24),
                        ("tx_bytes", "target", 1048576),
                        ("rx_bytes", "target", 4194304),
                        ("model_calls", "workflow", 6),
                        ("actions", "workflow", 12),
                        ("auth_posts", "realm", 2),
                    ):
                        key = (counter, item[grouping])
                        scoped[key] = scoped.get(key, 0) + values.get(counter, 0)
                        if scoped[key] > ceiling:
                            raise PolicyError("handover exceeds combined target, realm, or workflow allowance")
                for item in assignments:
                    row = self._db.execute("SELECT workspace FROM assignments WHERE engagement=? AND target=? AND realm=?", (self.engagement_id, item["target"], item["realm"])).fetchone()
                    if row and row[0] != item["workspace"]:
                        raise PolicyError("handover assignment conflict")
                    row = self._db.execute("SELECT workspace FROM assignments WHERE engagement=? AND target=?", (self.engagement_id, item["target"])).fetchone()
                    if row and row[0] != item["workspace"]:
                        raise PolicyError("handover target assignment conflict")
                    if item["realm"] != "-":
                        row = self._db.execute("SELECT workspace FROM assignments WHERE engagement=? AND realm=?", (self.engagement_id, item["realm"])).fetchone()
                        if row and row[0] != item["workspace"]:
                            raise PolicyError("handover authentication realm conflict")
                for item in reservations:
                    self._db.execute("INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)", (
                        self.engagement_id, item["device"], item["request_id"], item["workspace"], item["target"], item["realm"],
                        item["workflow"], json.dumps(item["bounds"], sort_keys=True), item["state"], json.dumps(item["usage"], sort_keys=True)))
                for item in assignments:
                    self._db.execute("INSERT OR IGNORE INTO assignments VALUES (?,?,?,?)", (self.engagement_id, item["target"], item["realm"], item["workspace"]))
                from .migrations import backfill_reservation_scopes
                backfill_reservation_scopes(self._db)
                self._db.execute("INSERT INTO handover_imports VALUES (?,?,?,?)", (bundle_hash, bundle.device_id, payload["seal_id"], _utc_now()))
        except (sqlite3.Error, PolicyError) as exc:
            return MergeReport(False, str(exc), 0)
        return MergeReport(True, imported=len(reservations))

    def _snapshot_locked(self) -> dict[str, Any]:
        reservations = []
        for row in self._db.execute("SELECT device,request_id,workspace,target,realm,workflow,bounds,state,usage FROM reservations WHERE engagement=? ORDER BY device,request_id", (self.engagement_id,)):
            reservations.append({"device": row[0], "request_id": row[1], "workspace": row[2], "target": row[3], "realm": row[4],
                                 "workflow": row[5], "bounds": json.loads(row[6]), "state": row[7], "usage": json.loads(row[8])})
        assignments = [{"target": row[0], "realm": row[1], "workspace": row[2]} for row in self._db.execute(
            "SELECT target,realm,workspace FROM assignments WHERE engagement=? ORDER BY target,realm", (self.engagement_id,))]
        totals = self._totals(reservations)
        return {"version": 2, "engagement_id": self.engagement_id, "policy_revision": self.policy_revision,
                "source_device": self.device_id, "reservations": reservations, "assignments": assignments, "totals": totals}

    def _validate_snapshot(self, snapshot: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        if not isinstance(snapshot, dict) or set(snapshot) != {"version", "engagement_id", "policy_revision", "source_device", "reservations", "assignments", "totals"}:
            raise PolicyError("invalid handover snapshot")
        if snapshot["version"] != 2 or snapshot["engagement_id"] != self.engagement_id or snapshot["policy_revision"] != self.policy_revision:
            raise PolicyError("handover snapshot policy mismatch")
        _safe_id(snapshot["source_device"], 128)
        reservations = snapshot["reservations"]
        assignments = snapshot["assignments"]
        if not isinstance(reservations, list) or len(reservations) > 10000 or not isinstance(assignments, list) or len(assignments) > 10000:
            raise PolicyError("handover snapshot allowance exceeded")
        entries = []
        seen = set()
        for item in reservations:
            if not isinstance(item, dict) or set(item) != {"device", "request_id", "workspace", "target", "realm", "workflow", "bounds", "state", "usage"}:
                raise PolicyError("invalid handover reservation")
            for key in ("device", "request_id", "workflow"):
                _safe_id(item[key], 128)
            for key in ("workspace", "realm"):
                if item[key] != "":
                    _safe_id(item[key], 128)
            if item["target"] is not None: _safe_id(item["target"], 256)
            if item["state"] not in {"complete", "finished", "blocked", "stopped", "failed", "uncertain"}:
                raise PolicyError("invalid handover reservation state")
            bounds = item["bounds"]
            current_fields = set(asdict(Bounds()))
            transport_fields = set(_TRANSPORT_COUNTERS)
            bound_fields = frozenset(bounds) if isinstance(bounds, dict) else frozenset()
            if (not isinstance(bounds, dict) or bound_fields not in {frozenset(current_fields), frozenset(current_fields - transport_fields)}
                    or any(type(bounds.get(key, 0)) is not int or not 0 <= bounds.get(key, 0) <= 2147483647 for key in _COUNTERS)):
                raise PolicyError("invalid handover reservation bounds")
            timeout = bounds["timeout_s"]
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 <= timeout <= 3600:
                raise PolicyError("invalid handover reservation timeout")
            if (bounds["request_limit"] > 24 or bounds["actions"] > 12 or bounds["model_calls"] > 6
                    or bounds["auth_posts"] > 2 or bounds["output_bytes"] > 131072
                    or bounds.get("tcp_connects", 0) > 24 or bounds.get("udp_datagrams", 0) > 24
                    or bounds.get("protocol_requests", 0) > 24 or bounds.get("tx_bytes", 0) > 1048576
                    or bounds.get("rx_bytes", 0) > 4194304):
                raise PolicyError("handover reservation exceeds release ceiling")
            if not isinstance(item["usage"], dict) or any(key not in _COUNTERS or type(value) is not int or value < 0 for key, value in item["usage"].items()):
                raise PolicyError("invalid handover usage")
            origin = (item["device"], item["request_id"])
            if origin in seen: raise PolicyError("duplicate handover reservation")
            seen.add(origin); entries.append(item)
        assignment_entries = []
        assignment_keys = set()
        target_workspaces: dict[str, str] = {}
        realm_workspaces: dict[str, str] = {}
        for item in assignments:
            if not isinstance(item, dict) or set(item) != {"target", "realm", "workspace"}:
                raise PolicyError("invalid handover assignment")
            _safe_id(item["target"], 256); _safe_id(item["realm"], 128); _safe_id(item["workspace"], 128)
            key = (item["target"], item["realm"])
            if key in assignment_keys:
                raise PolicyError("duplicate handover assignment")
            assignment_keys.add(key)
            if item["target"] in target_workspaces and target_workspaces[item["target"]] != item["workspace"]:
                raise PolicyError("conflicting handover target assignment")
            target_workspaces[item["target"]] = item["workspace"]
            if item["realm"] != "-" and item["realm"] in realm_workspaces and realm_workspaces[item["realm"]] != item["workspace"]:
                raise PolicyError("conflicting handover authentication realm")
            if item["realm"] != "-":
                realm_workspaces[item["realm"]] = item["workspace"]
            assignment_entries.append(item)
        if snapshot["totals"] != self._totals(entries):
            raise PolicyError("handover totals mismatch")
        return entries, assignment_entries, snapshot["totals"]

    @staticmethod
    def _totals(reservations: list[dict[str, Any]]) -> dict[str, Any]:
        by_device: dict[str, dict[str, int]] = {}
        all_total = {key: 0 for key in _COUNTERS}
        for item in reservations:
            device = item["device"]
            current = by_device.setdefault(device, {key: 0 for key in _COUNTERS})
            for key in _COUNTERS:
                value = int(item["bounds"].get(key, 0)); current[key] += value; all_total[key] += value
        return {"by_device": {key: by_device[key] for key in sorted(by_device)}, "all": all_total}

    def _assert_mutable(self) -> None:
        if self._db.execute("SELECT 1 FROM handover_seals LIMIT 1").fetchone():
            raise PolicyError("ledger is sealed for handover")

    def _tx(self):
        class Tx:
            def __init__(s, outer): s.outer=outer
            def __enter__(s):
                s.outer._lock.acquire()
                try: s.outer._db.execute("BEGIN IMMEDIATE")
                except BaseException:
                    s.outer._lock.release()
                    raise
                return s
            def __exit__(s, typ, val, tb):
                try: s.outer._db.execute("ROLLBACK" if typ else "COMMIT")
                finally: s.outer._lock.release()
        return Tx(self)
