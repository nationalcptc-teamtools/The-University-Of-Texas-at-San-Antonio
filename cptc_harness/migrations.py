"""Additive migration keeps the legacy schema and all records usable by the old CLI."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from .contracts import PolicyError
from .storage import atomic_write, exclusive, private_directory, read_private, write_json


def migrate_legacy(root: Path, *, encrypted_storage_verified: bool = False) -> dict:
    if encrypted_storage_verified is not True:
        raise PolicyError("legacy migration requires operator-verified encrypted storage before copying existing client records")
    root = private_directory(root)
    database = root / "state.sqlite3"
    if database.is_symlink() or not database.is_file():
        raise PolicyError("legacy database must be a local regular file")
    # Legacy library callers did not always set umask. Migration is an explicit
    # operator operation that may tighten metadata on these owner-held files.
    for path in (root / ".lock", database):
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise PolicyError("legacy file is not owner-held regular storage")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
    with exclusive(root / ".lock"):
        db = sqlite3.connect(database)
        try:
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise PolicyError("legacy database integrity failure")
            if db.execute("SELECT value FROM settings WHERE key='schema'").fetchone() != ("1",):
                raise PolicyError("unsupported legacy schema")
            names = ("apps", "checks", "evidence", "events", "auth_budget")
            before = {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in names}
            existing = db.execute("SELECT value FROM settings WHERE key='harness_schema'").fetchone()
            if existing and existing != ("2",):
                raise PolicyError("unsupported harness migration")
            backup_path = root / "legacy-before-harness.sqlite3"
            if not existing:
                fd = os.open(backup_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
                backup = sqlite3.connect(backup_path)
                try:
                    db.backup(backup)
                    if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                        raise PolicyError("migration backup integrity failure")
                finally:
                    backup.close()
                with backup_path.open("rb") as stream:
                    os.fsync(stream.fileno())
                with db:
                    db.execute("CREATE TABLE IF NOT EXISTS harness_records (action_id TEXT PRIMARY KEY, module_id TEXT NOT NULL, target_id TEXT, status TEXT NOT NULL, classification TEXT NOT NULL DEFAULT 'client_confidential', result_json TEXT NOT NULL)")
                    db.execute("INSERT OR REPLACE INTO settings VALUES ('harness_schema','2')")
                    db.execute("INSERT OR REPLACE INTO settings VALUES ('data_classification','client_confidential')")
            after = {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in names}
            if before != after:
                raise PolicyError("migration changed legacy record counts")
            brief = root / "export" / "ai-brief.json"
            if brief.exists():
                if brief.is_symlink() or brief.stat().st_size > 8 * 1024 * 1024:
                    raise PolicyError("invalid legacy brief")
                data = json.loads(brief.read_bytes())
                data["classification"] = "client_confidential"
                data["disclosure"] = "Approved client AI only; redaction does not declassify engagement data."
                private_directory(brief.parent)
                write_json(brief, data)
            return {"legacy_schema": 1, "harness_schema": 2, "preserved_records": after, "already_migrated": bool(existing)}
        finally:
            db.close()


LEDGER_SCHEMA_VERSION = 2
_LEDGER_DDL = (
    """CREATE TABLE IF NOT EXISTS ledger_schema_migrations(
        version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS reservation_scopes(
        engagement TEXT NOT NULL, device TEXT NOT NULL, request_id TEXT NOT NULL,
        scope_kind TEXT NOT NULL, scope_key TEXT NOT NULL, counter TEXT NOT NULL,
        reserved INTEGER NOT NULL CHECK(reserved >= 0), ceiling INTEGER,
        PRIMARY KEY(engagement,device,request_id,scope_kind,scope_key,counter))""",
    """CREATE INDEX IF NOT EXISTS reservation_scope_totals
        ON reservation_scopes(engagement,scope_kind,scope_key,counter)""",
    """CREATE TABLE IF NOT EXISTS reservation_attempts(
        engagement TEXT NOT NULL, device TEXT NOT NULL, request_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
        tcp_connects INTEGER NOT NULL, udp_datagrams INTEGER NOT NULL,
        request_count INTEGER NOT NULL, request_bytes INTEGER NOT NULL, response_bytes INTEGER NOT NULL,
        elapsed_ms INTEGER NOT NULL, deadline_ns INTEGER NOT NULL, started_ns INTEGER NOT NULL,
        deadline_exceeded INTEGER NOT NULL, state TEXT NOT NULL,
        PRIMARY KEY(engagement,device,request_id,attempt_id))""",
    """CREATE TABLE IF NOT EXISTS reservation_attempt_events(
        engagement TEXT NOT NULL, device TEXT NOT NULL, request_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL, event_id TEXT NOT NULL,
        tcp_connects INTEGER NOT NULL, udp_datagrams INTEGER NOT NULL,
        request_count INTEGER NOT NULL, request_bytes INTEGER NOT NULL,
        response_bytes INTEGER NOT NULL,
        PRIMARY KEY(engagement,device,request_id,attempt_id,event_id))""",
    """CREATE TABLE IF NOT EXISTS assessment_waves(
        engagement TEXT NOT NULL, device TEXT NOT NULL, wave_id TEXT NOT NULL,
        workspace TEXT NOT NULL, operator TEXT NOT NULL, policy_revision TEXT NOT NULL,
        policy_sha256 TEXT NOT NULL, release_sha256 TEXT NOT NULL, plan_sha256 TEXT NOT NULL,
        budget_sha256 TEXT NOT NULL, plan_json TEXT NOT NULL, state TEXT NOT NULL,
        created_at TEXT NOT NULL, frozen_at TEXT, started_at TEXT, finished_at TEXT, reason TEXT,
        PRIMARY KEY(engagement,device,wave_id), UNIQUE(engagement,wave_id))""",
    """CREATE TABLE IF NOT EXISTS assessment_items(
        engagement TEXT NOT NULL, device TEXT NOT NULL, wave_id TEXT NOT NULL, item_id TEXT NOT NULL,
        request_id TEXT NOT NULL, action_id TEXT NOT NULL, target_id TEXT NOT NULL, check_id TEXT NOT NULL,
        role_id TEXT NOT NULL, module_id TEXT NOT NULL, state TEXT NOT NULL, result_json TEXT,
        PRIMARY KEY(engagement,device,wave_id,item_id),
        UNIQUE(engagement,request_id), UNIQUE(engagement,action_id))""",
)


def backfill_reservation_scopes(db: sqlite3.Connection) -> None:
    """Derive additive accounting indexes without changing historical charges.

    Call within the caller's transaction, including after a verified legacy
    handover import. Unknown historical realms remain explicitly unattributed;
    authentication admission must not reinterpret them as a known safe realm.
    """
    from .contracts import RESOURCE_COUNTERS
    rows = db.execute("SELECT engagement,device,request_id,workspace,target,realm,workflow,bounds FROM reservations").fetchall()
    for engagement, device, request, workspace, target, realm, workflow, encoded in rows:
        try:
            bounds = json.loads(encoded)
            if not isinstance(bounds, dict): raise ValueError()
            values = {key: bounds.get(key, 0) for key in RESOURCE_COUNTERS}
            if any(type(value) is not int or not 0 <= value <= 2147483647 for value in values.values()): raise ValueError()
        except (ValueError, TypeError):
            raise PolicyError("historical reservation bounds cannot be migrated") from None
        scopes = {"engagement": engagement, "device": device, "workspace": workspace or "-",
                  "workflow": workflow or "default", "target": target or "-", "realm": realm or "-"}
        for kind, key in scopes.items():
            for counter, value in values.items():
                old = db.execute("SELECT reserved FROM reservation_scopes WHERE engagement=? AND device=? AND request_id=? AND scope_kind=? AND scope_key=? AND counter=?",
                                 (engagement, device, request, kind, key, counter)).fetchone()
                if old is not None and old[0] != value:
                    raise PolicyError("historical scope accounting conflicts with reservation")
                db.execute("INSERT OR IGNORE INTO reservation_scopes VALUES (?,?,?,?,?,?,?,NULL)",
                           (engagement, device, request, kind, key, counter, value))


def ensure_ledger_schema(db: sqlite3.Connection) -> None:
    """Transactional additive migration, separate from legacy web schema v2."""
    from datetime import datetime, timezone
    if db.in_transaction:
        raise PolicyError("ledger migration requires an idle connection")
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute(_LEDGER_DDL[0])
        versions = [row[0] for row in db.execute("SELECT version FROM ledger_schema_migrations ORDER BY version")]
        if versions not in ([], [1], [1, 2]):
            raise PolicyError("unsupported ledger migration history")
        if not versions:
            for statement in _LEDGER_DDL[1:]: db.execute(statement)
            backfill_reservation_scopes(db)
            applied = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (1, applied))
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (2, applied))
        elif versions == [1]:
            for table, columns in {
                "reservation_attempts": (
                    "tcp_connects INTEGER NOT NULL DEFAULT 0",
                    "udp_datagrams INTEGER NOT NULL DEFAULT 0",
                ),
                "reservation_attempt_events": (
                    "tcp_connects INTEGER NOT NULL DEFAULT 0",
                    "udp_datagrams INTEGER NOT NULL DEFAULT 0",
                    "request_count INTEGER NOT NULL DEFAULT 0",
                ),
            }.items():
                existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
                for definition in columns:
                    name = definition.split()[0]
                    if name not in existing:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
            backfill_reservation_scopes(db)
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                2, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
        db.commit()
    except Exception:
        db.rollback()
        raise
