"""Additive migration keeps the legacy schema and all records usable by the old CLI."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
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


LEDGER_SCHEMA_VERSION = 5
_PROFILE_RECONCILIATION_DDL = """CREATE TABLE IF NOT EXISTS profile_reconciliations(
        engagement TEXT NOT NULL, device TEXT NOT NULL,
        predecessor_action_id TEXT NOT NULL, predecessor_plan_id TEXT NOT NULL,
        predecessor_plan_sha256 TEXT NOT NULL,
        successor_action_id TEXT NOT NULL, successor_plan_id TEXT NOT NULL,
        successor_plan_sha256 TEXT NOT NULL,
        reconciliation_sha256 TEXT NOT NULL, reason_code TEXT NOT NULL,
        reservation_absent INTEGER NOT NULL CHECK(reservation_absent = 1),
        attempt_absent INTEGER NOT NULL CHECK(attempt_absent = 1),
        target_traffic_absent INTEGER NOT NULL CHECK(target_traffic_absent = 1),
        reconciled_at TEXT NOT NULL, reconciled_monotonic_ns INTEGER NOT NULL,
        PRIMARY KEY(engagement,device,predecessor_action_id),
        UNIQUE(engagement,predecessor_action_id),
        UNIQUE(engagement,successor_action_id))"""
_PROFILE_CONTINUATION_DDL = """CREATE TABLE IF NOT EXISTS profile_continuations(
        predecessor_engagement TEXT NOT NULL, predecessor_device TEXT NOT NULL,
        predecessor_reconciled_action_id TEXT NOT NULL,
        predecessor_action_id TEXT NOT NULL,
        predecessor_plan_id TEXT NOT NULL,
        predecessor_plan_sha256 TEXT NOT NULL,
        predecessor_release_manifest_sha256 TEXT NOT NULL,
        predecessor_profile_worker_sha256 TEXT NOT NULL,
        predecessor_broker_worker_sha256 TEXT NOT NULL,
        predecessor_audit_chain_tail_sha256 TEXT NOT NULL,
        predecessor_audit_snapshot_sha256 TEXT NOT NULL,
        predecessor_reconciliation_sha256 TEXT NOT NULL,
        predecessor_reconciliation_reason TEXT NOT NULL,
        predecessor_raw_failure_stage TEXT
            CHECK(predecessor_raw_failure_stage IS NULL),
        predecessor_stage TEXT NOT NULL
            CHECK(predecessor_stage = 'legacy_target_open_unacknowledged'),
        predecessor_attempt_count INTEGER NOT NULL
            CHECK(predecessor_attempt_count = 1),
        predecessor_observed_tcp_connects INTEGER NOT NULL
            CHECK(predecessor_observed_tcp_connects = 0),
        predecessor_possible_tcp_connects INTEGER NOT NULL
            CHECK(predecessor_possible_tcp_connects = 1),
        predecessor_charged_tcp_connects INTEGER NOT NULL
            CHECK(predecessor_charged_tcp_connects = 1),
        predecessor_observed_udp_datagrams INTEGER NOT NULL
            CHECK(predecessor_observed_udp_datagrams = 0),
        predecessor_charged_udp_datagrams INTEGER NOT NULL
            CHECK(predecessor_charged_udp_datagrams = 0),
        predecessor_observed_protocol_requests INTEGER NOT NULL
            CHECK(predecessor_observed_protocol_requests = 0),
        predecessor_charged_protocol_requests INTEGER NOT NULL
            CHECK(predecessor_charged_protocol_requests = 0),
        predecessor_observed_tx_bytes INTEGER NOT NULL
            CHECK(predecessor_observed_tx_bytes = 0),
        predecessor_charged_tx_bytes INTEGER NOT NULL
            CHECK(predecessor_charged_tx_bytes = 0),
        predecessor_observed_rx_bytes INTEGER NOT NULL
            CHECK(predecessor_observed_rx_bytes = 0),
        predecessor_charged_rx_bytes INTEGER NOT NULL
            CHECK(predecessor_charged_rx_bytes = 0),
        predecessor_evidence_bytes INTEGER NOT NULL
            CHECK(predecessor_evidence_bytes = 0),
        predecessor_first_byte_at TEXT
            CHECK(predecessor_first_byte_at IS NULL),
        predecessor_wire_event_count INTEGER NOT NULL
            CHECK(predecessor_wire_event_count = 0),
        predecessor_outcome TEXT NOT NULL
            CHECK(predecessor_outcome = 'uncertain'),
        predecessor_cleanup_status TEXT NOT NULL
            CHECK(predecessor_cleanup_status = 'passed'),
        predecessor_stop_reason TEXT NOT NULL
            CHECK(predecessor_stop_reason = 'transport outcome uncertain'),
        successor_engagement TEXT NOT NULL, successor_device TEXT NOT NULL,
        successor_workspace TEXT NOT NULL, successor_target TEXT NOT NULL,
        successor_workflow TEXT NOT NULL,
        successor_action_id TEXT NOT NULL, successor_plan_id TEXT NOT NULL,
        successor_plan_sha256 TEXT NOT NULL,
        predecessor_proof_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
        PRIMARY KEY(predecessor_engagement,predecessor_action_id),
        UNIQUE(successor_engagement,successor_action_id),
        UNIQUE(successor_engagement,successor_plan_id))"""
_PROFILE_CONTINUATION_V4_DDL = (
    _PROFILE_CONTINUATION_DDL.replace(
        "        predecessor_reconciled_action_id TEXT NOT NULL,\n", ""
    ).replace(
        "        predecessor_profile_worker_sha256 TEXT NOT NULL,\n"
        "        predecessor_broker_worker_sha256 TEXT NOT NULL,\n",
        "        predecessor_worker_sha256 TEXT NOT NULL,\n",
    )
)
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
    _PROFILE_RECONCILIATION_DDL,
    _PROFILE_CONTINUATION_DDL,
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


def _normalized_schema_sql(value: str) -> tuple[str, ...]:
    tokens = re.findall(
        r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|`(?:``|[^`])*`|"
        r"\[[^]]*\]|<=|>=|<>|!=|==|[(),=]|[^\s(),=<>!]+",
        value,
    )
    return tuple(
        token
        if token.startswith(("'", '"', "`", "["))
        else token.lower()
        for token in tokens
    )


def _profile_continuation_schema_signature(
    db: sqlite3.Connection,
) -> tuple[object, ...]:
    row = db.execute(
        """SELECT type,sql FROM sqlite_schema
            WHERE name='profile_continuations'"""
    ).fetchone()
    if row is None or row[0] != "table" or type(row[1]) is not str:
        raise PolicyError("profile continuation schema requires reviewed migration")
    table_info = tuple(
        db.execute("PRAGMA table_info(profile_continuations)").fetchall()
    )
    indexes = []
    for _sequence, name, unique, origin, partial in db.execute(
        "PRAGMA index_list(profile_continuations)"
    ).fetchall():
        columns = tuple(
            db.execute(
                "SELECT seqno,cid,name FROM pragma_index_info(?) ORDER BY seqno",
                (name,),
            ).fetchall()
        )
        indexes.append((unique, origin, partial, columns))
    return (
        _normalized_schema_sql(row[1]),
        table_info,
        tuple(sorted(indexes, key=repr)),
    )


def _expected_profile_continuation_schema_signature(
    ddl: str,
) -> tuple[object, ...]:
    expected = sqlite3.connect(":memory:")
    try:
        expected.execute(ddl)
        return _profile_continuation_schema_signature(expected)
    finally:
        expected.close()


def _upgrade_profile_continuation_v5(db: sqlite3.Connection) -> None:
    """Replace only an empty pre-release v4 table with the final proof schema."""

    actual = _profile_continuation_schema_signature(db)
    if actual == _expected_profile_continuation_schema_signature(
        _PROFILE_CONTINUATION_DDL
    ):
        return
    if actual != _expected_profile_continuation_schema_signature(
        _PROFILE_CONTINUATION_V4_DDL
    ):
        raise PolicyError("profile continuation schema requires reviewed migration")
    if db.execute("SELECT 1 FROM profile_continuations LIMIT 1").fetchone():
        # The old single worker digest cannot prove which broker worker made
        # the pre-ack target-open decision. Preserve the row and fail closed.
        raise PolicyError("profile continuation history requires reviewed migration")
    db.execute("DROP TABLE profile_continuations")
    db.execute(_PROFILE_CONTINUATION_DDL)


def ensure_ledger_schema(db: sqlite3.Connection) -> None:
    """Transactional additive migration, separate from legacy web schema v2."""
    from datetime import datetime, timezone
    if db.in_transaction:
        raise PolicyError("ledger migration requires an idle connection")
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute(_LEDGER_DDL[0])
        versions = [row[0] for row in db.execute("SELECT version FROM ledger_schema_migrations ORDER BY version")]
        if versions not in (
            [],
            [1],
            [1, 2],
            [1, 2, 3],
            [1, 2, 3, 4],
            [1, 2, 3, 4, 5],
        ):
            raise PolicyError("unsupported ledger migration history")
        if not versions:
            for statement in _LEDGER_DDL[1:]: db.execute(statement)
            backfill_reservation_scopes(db)
            applied = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (1, applied))
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (2, applied))
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (3, applied))
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (4, applied))
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (5, applied))
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
            db.execute(_PROFILE_RECONCILIATION_DDL)
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                3, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
            db.execute(_PROFILE_CONTINUATION_DDL)
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                4, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                5, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
        elif versions == [1, 2]:
            db.execute(_PROFILE_RECONCILIATION_DDL)
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                3, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
            db.execute(_PROFILE_CONTINUATION_DDL)
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                4, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                5, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
        elif versions == [1, 2, 3]:
            db.execute(_PROFILE_CONTINUATION_DDL)
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                4, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                5, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
        elif versions == [1, 2, 3, 4]:
            _upgrade_profile_continuation_v5(db)
            db.execute("INSERT INTO ledger_schema_migrations VALUES (?,?)", (
                5, datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")))
        else:
            _upgrade_profile_continuation_v5(db)
        db.commit()
    except Exception:
        db.rollback()
        raise
