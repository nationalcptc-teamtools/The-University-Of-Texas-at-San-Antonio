"""Durable, source-only execution ledger for the CPTC11 read-only wave.

The ledger is deliberately independent from the main harness.  It owns the
stop latch and spends reservations before a provider can open a channel.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import threading
import re
from typing import Any

from .catalog import PLAN_ID, plan_actions, resolve_action
from .contracts import FrozenWaveApproval
from .metadata import validate_metadata


class LedgerError(RuntimeError):
    """The durable ledger rejected an operation."""


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def action_request_id(plan_id: str, action_id: str, profile_id: str) -> str:
    """Return the stable identity for one catalog action."""
    for value in (plan_id, action_id, profile_id):
        if type(value) is not str or not value or "\x00" in value or len(value) > 256:
            raise ValueError("action identity is invalid")
    return hashlib.sha256(f"{plan_id}\x00{action_id}\x00{profile_id}".encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Reservation:
    request_id: str
    wave_id: str
    engagement_id: str
    device_id: str
    workspace_id: str
    workflow_id: str
    plan_id: str
    action_id: str
    profile_id: str
    target_id: str
    state: str
    reserved_at: str


class ReadonlyWaveLedger:
    """A single-workspace SQLite ledger with crash-safe reservations."""

    def __init__(self, root: str | Path, engagement_id: str, device_id: str, workspace_id: str,
                 *, limits: dict[str, int] | None = None, policy_sha256: str = "", release_sha256: str = "",
                 worker_sha256: str | None = None, runtime_sha256: str | None = None) -> None:
        self.root = Path(root)
        self.engagement_id = self._id("engagement_id", engagement_id)
        self.device_id = self._id("device_id", device_id)
        self.workspace_id = self._id("workspace_id", workspace_id)
        self.limits = dict(limits or {})
        if any(type(key) is not str or not key or type(value) is not int or value < 0 for key, value in self.limits.items()):
            raise LedgerError("limits are invalid")
        pins = {"policy": policy_sha256, "release": release_sha256, "worker": worker_sha256, "runtime": runtime_sha256}
        if any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in pins.values()):
            raise LedgerError("policy, release, worker, and runtime pins are required")
        self.policy_sha256, self.release_sha256 = policy_sha256, release_sha256
        self.worker_sha256, self.runtime_sha256 = worker_sha256, runtime_sha256
        self.path = self.root / "ledger.sqlite3"
        self._db: sqlite3.Connection | None = None
        self._lock = threading.RLock()

    @staticmethod
    def _id(name: str, value: object) -> str:
        if type(value) is not str or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
            raise LedgerError(f"{name} is invalid")
        return value

    @property
    def db(self) -> sqlite3.Connection:
        if self._db is None:
            raise LedgerError("ledger is not initialized")
        return self._db

    def initialize(self) -> None:
        with self._lock:
            if self.root.exists() and self.root.is_symlink():
                raise LedgerError("ledger root symlink rejected")
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.root.chmod(0o700)
            if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
                raise LedgerError("ledger database is invalid")
            if not self.path.exists():
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            self.path.chmod(0o600)
            gate = self.root / "dispatch.lock"
            if gate.exists() and gate.is_symlink(): raise LedgerError("dispatch gate is invalid")
            if not gate.exists():
                fd = os.open(gate, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600); os.close(fd)
            gate.chmod(0o600)
            self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            version = int(self.db.execute("PRAGMA user_version").fetchone()[0])
            old_actions = self.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='actions'").fetchone()
            legacy_narrow = False
            if version == 0 and old_actions:
                columns = {row[1] for row in self.db.execute("PRAGMA table_info(actions)")}
                required = {"request_id", "engagement_id", "device_id", "workspace_id", "workflow_id", "plan_id",
                            "action_id", "profile_id", "target_id", "state", "reserved_at", "claimed_at",
                            "activated_at", "terminal_at", "receipt"}
                if not required.issubset(columns):
                    if self.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='actions_legacy_v1'").fetchone():
                        raise LedgerError("legacy actions table name is already occupied")
                    self.db.execute("ALTER TABLE actions RENAME TO actions_legacy_v1")
                    legacy_narrow = True
                elif "wave_id" not in columns:
                    self.db.execute("ALTER TABLE actions ADD COLUMN wave_id TEXT")
                if not legacy_narrow and "legacy_unbound" not in columns:
                    self.db.execute("ALTER TABLE actions ADD COLUMN legacy_unbound INTEGER NOT NULL DEFAULT 1")
                version = 1
            self.db.executescript("""
              CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS waves(
                wave_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, state TEXT NOT NULL,
                engagement_id TEXT NOT NULL DEFAULT '', device_id TEXT NOT NULL DEFAULT '', workspace_id TEXT NOT NULL DEFAULT '',
                approval_json TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, stopped_at TEXT);
              CREATE TABLE IF NOT EXISTS wave_actions(
                wave_id TEXT NOT NULL, action_order INTEGER NOT NULL, action_id TEXT NOT NULL,
                profile_id TEXT NOT NULL, target_id TEXT NOT NULL, operation_sha256 TEXT NOT NULL,
                budget_json TEXT NOT NULL, PRIMARY KEY(wave_id, action_order), UNIQUE(wave_id, action_id));
              CREATE TABLE IF NOT EXISTS actions(
                request_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, device_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL, workflow_id TEXT NOT NULL, plan_id TEXT NOT NULL,
                action_id TEXT NOT NULL, profile_id TEXT NOT NULL, target_id TEXT NOT NULL,
                state TEXT NOT NULL, reserved_at TEXT NOT NULL, claimed_at TEXT,
                activated_at TEXT, terminal_at TEXT, receipt TEXT, wave_id TEXT, legacy_unbound INTEGER NOT NULL DEFAULT 0);
              CREATE UNIQUE INDEX IF NOT EXISTS actions_identity
                ON actions(engagement_id, device_id, action_id);
              CREATE TABLE IF NOT EXISTS transport_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL,
                event_type TEXT NOT NULL, metadata TEXT NOT NULL, created_at TEXT NOT NULL,
                FOREIGN KEY(request_id) REFERENCES actions(request_id));
              CREATE TABLE IF NOT EXISTS attempts(
                request_id TEXT PRIMARY KEY, state TEXT NOT NULL, created_at TEXT NOT NULL,
                finished_at TEXT, FOREIGN KEY(request_id) REFERENCES actions(request_id));
              CREATE TABLE IF NOT EXISTS stops(
                id INTEGER PRIMARY KEY CHECK(id=1), reason TEXT NOT NULL, created_at TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS checkpoints(
                request_id TEXT NOT NULL, checkpoint TEXT NOT NULL, created_at TEXT NOT NULL,
                PRIMARY KEY(request_id, checkpoint));
            """)
            wave_columns = {row[1] for row in self.db.execute("PRAGMA table_info(waves)")}
            for name, definition in (("engagement_id", "TEXT NOT NULL DEFAULT ''"), ("device_id", "TEXT NOT NULL DEFAULT ''"),
                                     ("workspace_id", "TEXT NOT NULL DEFAULT ''"), ("approval_json", "TEXT NOT NULL DEFAULT ''")):
                if name not in wave_columns:
                    self.db.execute(f"ALTER TABLE waves ADD COLUMN {name} {definition}")
            if legacy_narrow or version == 1 and self.db.execute("SELECT 1 FROM actions WHERE legacy_unbound=1 LIMIT 1").fetchone():
                self.db.execute("INSERT OR REPLACE INTO stops VALUES (1,?,?)", ("legacy actions require reviewed wave migration", _utc()))
            config = {"engagement_id": self.engagement_id, "device_id": self.device_id, "workspace_id": self.workspace_id,
                      "limits": self.limits, "policy_sha256": self.policy_sha256, "release_sha256": self.release_sha256,
                      "worker_sha256": self.worker_sha256, "runtime_sha256": self.runtime_sha256}
            catalog_sha256 = plan_actions(PLAN_ID)[0].catalog_sha256
            config["catalog_sha256"] = catalog_sha256
            config_digest = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            metadata = {"schema_version": "2", "engagement_id": self.engagement_id, "device_id": self.device_id,
                        "workspace_id": self.workspace_id, "limits_json": json.dumps(self.limits, sort_keys=True, separators=(",", ":")),
                        "catalog_sha256": catalog_sha256, "policy_sha256": self.policy_sha256,
                        "release_sha256": self.release_sha256, "worker_sha256": self.worker_sha256,
                        "runtime_sha256": self.runtime_sha256, "configuration_sha256": config_digest}
            existing = {key: value for key, value in self.db.execute("SELECT key,value FROM metadata")}
            if existing and existing.get("schema_version") == "2":
                for key, value in metadata.items():
                    if existing.get(key) != value: raise LedgerError("persisted ledger identity or limits differ")
            else:
                self.db.executemany("INSERT OR REPLACE INTO metadata VALUES (?,?)", metadata.items())
            self.db.execute("PRAGMA user_version=2")

    def _transaction(self):
        class Tx:
            def __init__(inner, owner: ReadonlyWaveLedger): inner.owner = owner
            def __enter__(inner):
                inner.owner._lock.acquire()
                try:
                    inner.owner.db.execute("BEGIN IMMEDIATE")
                except Exception:
                    inner.owner._lock.release(); raise
                return inner.owner.db
            def __exit__(inner, typ, value, tb):
                try:
                    inner.owner.db.execute("ROLLBACK" if typ else "COMMIT")
                finally:
                    inner.owner._lock.release()
        return Tx(self)

    def _assert_mutable(self) -> None:
        if self.stopped():
            raise LedgerError("wave is stopped")

    @contextmanager
    def _dispatch_lock(self):
        fd = os.open(self.root / "dispatch.lock", os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)

    @contextmanager
    def contact_gate(self):
        """Serialize the final stop check with provider opening."""
        with self._dispatch_lock():
            self._assert_mutable()
            yield

    def _row_reservation(self, row: sqlite3.Row | tuple[Any, ...]) -> Reservation:
        return Reservation(*row)

    def _lookup(self, request_id: str) -> tuple[Any, ...] | None:
        return self.db.execute(
            "SELECT request_id,wave_id,engagement_id,device_id,workspace_id,workflow_id,plan_id,action_id,profile_id,target_id,state,reserved_at "
            "FROM actions WHERE request_id=? AND engagement_id=? AND device_id=?",
            (request_id, self.engagement_id, self.device_id)).fetchone()

    def create_wave(self, wave: FrozenWaveApproval) -> str:
        if not isinstance(wave, FrozenWaveApproval) or wave.plan_id != PLAN_ID:
            raise LedgerError("wave identity is not admitted")
        if (wave.engagement_id, wave.device_id, wave.workspace_id) != (self.engagement_id, self.device_id, self.workspace_id):
            raise LedgerError("wave identity differs from ledger")
        if self.policy_sha256 and wave.policy_sha256 != self.policy_sha256 or self.release_sha256 and wave.release_sha256 != self.release_sha256:
            raise LedgerError("wave policy or release differs from ledger")
        catalog_digest = plan_actions(PLAN_ID)[0].catalog_sha256
        if wave.catalog_sha256 != catalog_digest:
            raise LedgerError("wave catalog differs from ledger")
        if len(set(item.action_id for item in wave.actions)) != len(wave.actions):
            raise LedgerError("wave contains duplicate actions")
        for item in wave.actions:
            try: resolve_action(wave.plan_id, item.action_id, item.profile_id)
            except Exception as exc: raise LedgerError("wave action is not catalog-bound") from exc
        wave_id = wave.wave_id
        with self._transaction() as db:
            self._assert_mutable()
            existing = db.execute("SELECT plan_id FROM waves WHERE wave_id=?", (wave_id,)).fetchone()
            approval_json = json.dumps({"wave_id": wave.wave_id, "plan_id": wave.plan_id, "engagement_id": wave.engagement_id,
                                        "device_id": wave.device_id, "workspace_id": wave.workspace_id, "approval_id": wave.approval_id,
                                        "operator": wave.operator, "approved_at": wave.approved_at,
                                        "actions": [{"order": item.order, "action_id": item.action_id, "profile_id": item.profile_id,
                                                     "target_id": item.target_id, "operation_sha256": item.operation.request_sha256,
                                                     "budget": [item.budget.max_connects, item.budget.max_requests, item.budget.max_tx_bytes,
                                                               item.budget.max_rx_bytes, item.budget.max_capture_bytes, item.budget.timeout_ms]}
                                                    for item in wave.actions]}, sort_keys=True, separators=(",", ":"))
            if existing:
                existing_json = db.execute("SELECT approval_json FROM waves WHERE wave_id=?", (wave_id,)).fetchone()[0]
                if existing_json != approval_json: raise LedgerError("wave approval is immutable")
                return wave_id
            db.execute("INSERT INTO waves(wave_id,plan_id,state,engagement_id,device_id,workspace_id,approval_json,created_at,stopped_at) VALUES (?,?,?,?,?,?,?,?,?)", (wave_id, wave.plan_id, "frozen", wave.engagement_id, wave.device_id, wave.workspace_id, approval_json, _utc(), None))
            for item in wave.actions:
                db.execute("INSERT INTO wave_actions VALUES (?,?,?,?,?,?,?)", (wave_id, item.order, item.action_id, item.profile_id, item.target_id, item.operation.request_sha256, json.dumps([item.budget.max_connects, item.budget.max_requests, item.budget.max_tx_bytes, item.budget.max_rx_bytes, item.budget.max_capture_bytes, item.budget.timeout_ms])))
        return wave_id

    def reserve_action(self, wave_id: str, plan_id: str, action_id: str, profile_id: str, *, workflow_id: str = "default") -> Reservation:
        try:
            action = resolve_action(plan_id, action_id, profile_id)
        except Exception as exc:
            raise LedgerError("action is not admitted by the catalog") from exc
        workflow_id = self._id("workflow_id", workflow_id)
        request_id = action_request_id(plan_id, action_id, profile_id)
        with self._transaction() as db:
            self._assert_mutable()
            wave = db.execute("SELECT plan_id,engagement_id,device_id,workspace_id,state FROM waves WHERE wave_id=?", (wave_id,)).fetchone()
            if not wave or wave[0] != plan_id or wave[1:] != (self.engagement_id, self.device_id, self.workspace_id, "frozen"):
                raise LedgerError("wave approval is not valid")
            admitted = db.execute("SELECT profile_id,target_id,operation_sha256,budget_json FROM wave_actions WHERE wave_id=? AND action_id=?", (wave_id, action_id)).fetchone()
            if not admitted or admitted[0] != profile_id or admitted[1] != action.target_id or admitted[2] != action.operation.request_sha256:
                raise LedgerError("action is not in the frozen wave")
            row = self._lookup(request_id)
            if row:
                existing = self._row_reservation(row)
                if (existing.wave_id, existing.plan_id, existing.action_id, existing.profile_id, existing.workflow_id) != (wave_id, plan_id, action_id, profile_id, workflow_id):
                    raise LedgerError("conflicting duplicate action")
                return existing
            # The action budget is fixed by the sealed catalog.  Scope limits
            # are intentionally cumulative and cannot be reset after restart.
            for column, value in (("workspace_id", self.workspace_id), ("workflow_id", workflow_id),
                                  ("device_id", self.device_id), ("target_id", action.target_id)):
                limit = self.limits.get(column, self.limits.get("actions", 0))
                if limit and db.execute(f"SELECT COUNT(*) FROM actions WHERE engagement_id=? AND {column}=?", (self.engagement_id, value)).fetchone()[0] >= limit:
                    raise LedgerError(f"{column} allowance exhausted")
            now = _utc()
            db.execute("INSERT INTO actions(request_id,engagement_id,device_id,workspace_id,workflow_id,plan_id,action_id,profile_id,target_id,state,reserved_at,wave_id,legacy_unbound) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                request_id, self.engagement_id, self.device_id, self.workspace_id, workflow_id,
                plan_id, action_id, profile_id, action.target_id, "reserved", now, wave_id, 0))
            return Reservation(request_id, wave_id, self.engagement_id, self.device_id, self.workspace_id,
                               workflow_id, plan_id, action_id, profile_id, action.target_id, "reserved", now)

    def claim_action(self, action_id: str) -> Reservation:
        with self._transaction() as db:
            self._assert_mutable()
            row = db.execute("SELECT request_id FROM actions WHERE action_id=? AND engagement_id=? AND device_id=?", (action_id, self.engagement_id, self.device_id)).fetchone()
            if not row: raise LedgerError("action is not reserved")
            current = self._lookup(row[0])
            if current is None: raise LedgerError("action reservation is missing")
            reservation = self._row_reservation(current)
            if reservation.state == "claimed" or reservation.state == "active": return reservation
            if reservation.state != "reserved":
                raise LedgerError("action is not claimable")
            if db.execute("SELECT 1 FROM actions WHERE engagement_id=? AND device_id=? AND state IN ('claimed','active')", (self.engagement_id, self.device_id)).fetchone():
                raise LedgerError("another action is in flight")
            now = _utc()
            db.execute("UPDATE actions SET state='claimed',claimed_at=? WHERE request_id=?", (now, reservation.request_id))
            db.execute("INSERT OR REPLACE INTO attempts VALUES (?,?,?,NULL)", (reservation.request_id, "claimed", now))
            return self._row_reservation(self._lookup(reservation.request_id))

    def activate_action(self, action_id: str) -> Reservation:
        with self._transaction() as db:
            self._assert_mutable()
            row = db.execute("SELECT request_id FROM actions WHERE action_id=? AND engagement_id=? AND device_id=?", (action_id, self.engagement_id, self.device_id)).fetchone()
            if not row: raise LedgerError("action is not reserved")
            reservation = self._row_reservation(self._lookup(row[0]))
            if reservation.state == "active": return reservation
            if reservation.state != "claimed": raise LedgerError("action must be claimed before activation")
            now = _utc()
            db.execute("UPDATE actions SET state='active',activated_at=? WHERE request_id=?", (now, reservation.request_id))
            db.execute("UPDATE attempts SET state='active' WHERE request_id=?", (reservation.request_id,))
            return self._row_reservation(self._lookup(reservation.request_id))

    def record_transport_event(self, action_id: str, event_type: str, metadata: dict[str, Any] | None = None) -> None:
        if type(event_type) is not str or not event_type or any(ord(c) < 32 for c in event_type):
            raise LedgerError("transport event is invalid")
        data = dict(metadata or {})
        if any(key in {"body", "raw", "headers", "password", "token", "path", "url"} for key in data):
            raise LedgerError("transport event contains restricted data")
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False)
        try: validate_metadata(data)
        except Exception as exc: raise LedgerError("transport metadata is restricted") from exc
        with self._transaction() as db:
            row = db.execute("SELECT request_id FROM actions WHERE action_id=? AND engagement_id=? AND device_id=?", (action_id, self.engagement_id, self.device_id)).fetchone()
            if not row: raise LedgerError("action is not reserved")
            db.execute("INSERT INTO transport_events(request_id,event_type,metadata,created_at) VALUES (?,?,?,?)", (row[0], event_type, encoded, _utc()))

    def finish_attempt(self, action_id: str, state: str) -> None:
        if state not in {"active", "complete", "failed", "uncertain", "cancelled"}: raise LedgerError("attempt state invalid")
        with self._transaction() as db:
            row = db.execute("SELECT request_id FROM actions WHERE action_id=? AND engagement_id=? AND device_id=?", (action_id, self.engagement_id, self.device_id)).fetchone()
            if not row: raise LedgerError("action is not reserved")
            db.execute("UPDATE attempts SET state=?,finished_at=CASE WHEN ? IN ('complete','failed','uncertain','cancelled') THEN ? ELSE finished_at END WHERE request_id=?", (state, state, _utc(), row[0]))

    def finish_action(self, action_id: str, outcome: str, receipt: dict[str, Any]) -> dict[str, Any]:
        if outcome not in {"complete", "failed", "uncertain", "cancelled"} or type(receipt) is not dict:
            raise LedgerError("terminal result is invalid")
        row_identity = self.db.execute("SELECT wave_id,plan_id,action_id,profile_id,target_id FROM actions WHERE action_id=? AND engagement_id=? AND device_id=?", (action_id, self.engagement_id, self.device_id)).fetchone()
        if row_identity is None: raise LedgerError("action is not reserved")
        if row_identity[0] is None: raise LedgerError("action is not bound to a wave")
        required = {"outcome", "wave_id", "plan_id", "action_id", "profile_id", "target_id", "catalog_sha256", "profile_sha256",
                    "operation_sha256", "parser_id", "policy_sha256", "release_sha256", "worker_sha256", "runtime_sha256",
                    "evidence_sha256", "cleanup_status"}
        if not required.issubset(receipt) or receipt.get("outcome") != outcome or receipt.get("wave_id") != row_identity[0]:
            raise LedgerError("receipt provenance is incomplete or conflicting")
        try: action = resolve_action(row_identity[1], row_identity[2], row_identity[3])
        except Exception as exc: raise LedgerError("receipt action is not catalog-bound") from exc
        expected = {"plan_id": action.plan_id, "action_id": action.action_id, "profile_id": action.profile_id,
                    "target_id": action.target_id, "catalog_sha256": action.catalog_sha256, "profile_sha256": action.profile_sha256,
                    "operation_sha256": action.operation.request_sha256, "parser_id": action.parser_id,
                    "policy_sha256": self.policy_sha256, "release_sha256": self.release_sha256,
                    "worker_sha256": self.worker_sha256, "runtime_sha256": self.runtime_sha256}
        if any(receipt.get(key) != value for key, value in expected.items()): raise LedgerError("receipt provenance differs")
        if receipt.get("cleanup_status") not in {"closed", "not_started", "uncertain", "incomplete"}:
            raise LedgerError("receipt cleanup status is invalid")
        terminal = dict(receipt)
        if terminal.get("outcome") != outcome:
            raise LedgerError("receipt outcome conflicts with terminal state")
        try: validate_metadata(terminal)
        except Exception as exc: raise LedgerError("terminal receipt contains restricted metadata") from exc
        encoded = json.dumps(terminal, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._transaction() as db:
            row = db.execute("SELECT request_id,state,receipt FROM actions WHERE action_id=? AND engagement_id=? AND device_id=?", (action_id, self.engagement_id, self.device_id)).fetchone()
            if not row: raise LedgerError("action is not reserved")
            if row[1] in {"complete", "failed", "uncertain", "cancelled"}:
                if row[2] != encoded: raise LedgerError("terminal receipt is immutable")
                return json.loads(row[2])
            if row[1] not in {"active", "claimed"}: raise LedgerError("action is not in flight")
            now = _utc()
            db.execute("UPDATE actions SET state=?,terminal_at=?,receipt=? WHERE request_id=?", (outcome, now, encoded, row[0]))
            db.execute("UPDATE attempts SET state=?,finished_at=? WHERE request_id=?", (outcome, now, row[0]))
            return dict(terminal)

    def recover(self) -> None:
        legacy_ids: list[str] = []
        with self._transaction() as db:
            active = db.execute("SELECT request_id,wave_id,plan_id,action_id,profile_id,target_id FROM actions WHERE engagement_id=? AND device_id=? AND state IN ('claimed','active')", (self.engagement_id, self.device_id)).fetchall()
            for request_id, wave_id, plan_id, action_id, profile_id, target_id in active:
                if wave_id is None:
                    # A legacy row cannot satisfy the current receipt schema.
                    # Keep its action receipt null and preserve the recovery
                    # fact in a separate durable marker below.
                    db.execute("UPDATE actions SET state='uncertain',terminal_at=?,receipt=NULL WHERE request_id=?", (_utc(), request_id))
                    legacy_ids.append(request_id)
                    continue
                try: action = resolve_action(plan_id, action_id, profile_id)
                except Exception as exc: raise LedgerError("active action cannot produce a closed recovery receipt") from exc
                if action.target_id != target_id: raise LedgerError("active action target differs from catalog")
                receipt = {"outcome": "uncertain", "wave_id": wave_id, "plan_id": action.plan_id, "action_id": action.action_id,
                           "profile_id": action.profile_id, "target_id": action.target_id, "catalog_sha256": action.catalog_sha256,
                           "profile_sha256": action.profile_sha256, "operation_sha256": action.operation.request_sha256,
                           "parser_id": action.parser_id, "policy_sha256": self.policy_sha256, "release_sha256": self.release_sha256,
                           "worker_sha256": self.worker_sha256, "runtime_sha256": self.runtime_sha256,
                           "evidence_sha256": hashlib.sha256(b"").hexdigest(), "cleanup_status": "incomplete",
                           "reason": "recovered after interruption", "incomplete": True}
                validate_metadata(receipt)
                db.execute("UPDATE actions SET state='uncertain',terminal_at=?,receipt=? WHERE request_id=?", (_utc(), json.dumps(receipt, sort_keys=True, separators=(",", ":")), request_id))
                db.execute("UPDATE attempts SET state='uncertain',finished_at=? WHERE request_id=?", (_utc(), request_id))
            if active:
                db.execute("INSERT OR IGNORE INTO stops VALUES (1,?,?)", ("recovery found an active action", _utc()))
        for request_id in legacy_ids:
            self.mark_incomplete(request_id, "legacy action recovered without a wave receipt")

    def mark_incomplete(self, action_id: str, reason: str) -> None:
        """Persist a post-contact failure even when SQLite cannot commit."""
        self._id("reason", reason)
        if (type(action_id) is not str or not action_id
                or len(action_id) > 96 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in action_id)):
            raise LedgerError("action identity is invalid")
        marker = self.root / f"incomplete-{action_id}.json"
        try:
            fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"action_id": action_id, "reason": reason, "created_at": _utc()}, stream, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
            directory_fd = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(directory_fd); os.close(directory_fd)
        except FileExistsError:
            return
        except OSError as exc:
            raise LedgerError("incomplete marker could not be persisted") from exc

    def stop(self, reason: str = "operator stop") -> None:
        reason = self._id("reason", reason)
        sentinel = self.root / "operator-stop.json"
        try:
            fd = os.open(sentinel, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"reason": reason, "created_at": _utc()}, stream, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
            fd_dir = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(fd_dir); os.close(fd_dir)
        except FileExistsError:
            pass
        except OSError as exc:
            raise LedgerError("stop sentinel could not be persisted") from exc
        try:
            with self._dispatch_lock():
                with self._transaction() as db:
                    db.execute("INSERT OR IGNORE INTO stops VALUES (1,?,?)", (reason, _utc()))
        except Exception:
            # The sentinel is the primary stop mechanism.  Reconciliation can
            # add the central row after a locked or failed SQLite writer recovers.
            pass

    def stopped(self) -> bool:
        return (self.root / "operator-stop.json").exists() or (
            self._db is not None and self.db.execute("SELECT 1 FROM stops WHERE id=1").fetchone() is not None
        )

    def stop_reason(self) -> str | None:
        sentinel = self.root / "operator-stop.json"
        if sentinel.exists(): return "operator stop requested"
        row = self.db.execute("SELECT reason FROM stops WHERE id=1").fetchone()
        return row[0] if row else None

    def action_state(self, action_id: str) -> str | None:
        row = self.db.execute("SELECT state FROM actions WHERE action_id=? AND engagement_id=? AND device_id=?", (action_id, self.engagement_id, self.device_id)).fetchone()
        return row[0] if row else None

    def action_receipt(self, action_id: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT receipt FROM actions WHERE action_id=? AND engagement_id=? AND device_id=?", (action_id, self.engagement_id, self.device_id)).fetchone()
        return json.loads(row[0]) if row and row[0] else None

    def wave_state(self, wave_id: str) -> str | None:
        row = self.db.execute("SELECT state FROM waves WHERE wave_id=?", (wave_id,)).fetchone(); return row[0] if row else None

    def audit_state(self) -> dict[str, Any]:
        return {"stopped": self.stopped(), "reason": self.stop_reason()}

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close(); self._db = None
