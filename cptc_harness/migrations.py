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
