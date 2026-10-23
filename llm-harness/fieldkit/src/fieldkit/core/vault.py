"""Explicitly opened private SQLite evidence graph. Imports perform no I/O."""

import base64
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from fieldkit.core.redaction import redact
from fieldkit.core.storage import utc_now


def digest(value):
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest()


class Vault:
    """Raw requests/responses are intentionally private; public reads are redacted.

    This is an operator-local store, not an encryption boundary. SQLite and blobs
    use owner-only permissions. Never publish the database or its raw sidecars.
    """

    def __init__(self, filename, *, create=True):
        self.path = Path(filename).expanduser().absolute()
        if not create and not self.path.is_file():
            raise ValueError("Evidence database does not exist; run evidence/ingest first")
        if self.path.is_symlink():
            raise ValueError("Evidence database cannot be a symlink")
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        self.path.chmod(0o600)
        self.connection = sqlite3.connect(self.path, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
            INSERT OR IGNORE INTO metadata VALUES ('schema_version','1');
            CREATE TABLE IF NOT EXISTS records (
              id TEXT PRIMARY KEY, kind TEXT NOT NULL, public_json TEXT NOT NULL,
              private_json TEXT NOT NULL, source_json TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS record_kind ON records(kind);
            CREATE TABLE IF NOT EXISTS links (
              source TEXT REFERENCES records(id), target TEXT REFERENCES records(id),
              relation TEXT NOT NULL, details TEXT NOT NULL,
              PRIMARY KEY(source,target,relation));
        """)
        version = self.connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
        if not version or version[0] != "1":
            self.connection.close()
            raise ValueError("Unsupported evidence database schema")
        self.connection.commit()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.connection.close()

    def put(self, kind, public, *, private=None, source=None, identity=None):
        private = public if private is None else private
        identifier = (
            kind + "-" + digest(identity if identity is not None else [private, source])[:24]
        )
        self.connection.execute(
            """INSERT INTO records VALUES (?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET public_json=excluded.public_json,
            private_json=excluded.private_json, source_json=excluded.source_json""",
            (
                identifier,
                kind,
                json.dumps(redact(public)),
                json.dumps(private),
                json.dumps(redact(source or {})),
                utc_now(),
            ),
        )
        self.connection.commit()
        return identifier

    def get(self, identifier, *, private=False):
        row = self.connection.execute("SELECT * FROM records WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown evidence ID: {identifier}")
        return {
            "id": row["id"],
            "kind": row["kind"],
            "data": json.loads(row["private_json"] if private else row["public_json"]),
            "source": json.loads(row["source_json"]),
            "created_at": row["created_at"],
        }

    def records(self, kind=None, *, private=False, limit=10000):
        query = (
            "SELECT id FROM records"
            + (" WHERE kind=?" if kind else "")
            + " ORDER BY created_at,id LIMIT ?"
        )
        values = (kind, limit) if kind else (limit,)
        return [self.get(row[0], private=private) for row in self.connection.execute(query, values)]

    def link(self, source, target, relation, details=None):
        self.connection.execute(
            "INSERT OR REPLACE INTO links VALUES (?,?,?,?)",
            (source, target, relation, json.dumps(redact(details or {}))),
        )
        self.connection.commit()

    def links(self, identifier):
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT source,target,relation,details FROM links WHERE source=? OR target=?",
                (identifier, identifier),
            )
        ]

    def blob(self, content):
        fingerprint = digest(content)
        directory = self.path.parent / (self.path.name + ".private")
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink():
            raise ValueError("Private blob directory cannot be a symlink")
        directory.chmod(0o700)
        path = directory / fingerprint
        if not path.exists():
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
        elif path.is_symlink() or digest(path.read_bytes()) != fingerprint:
            raise ValueError("Private blob failed integrity verification")
        path.chmod(0o600)
        return str(path)

    def artifact(self, content, *, source, asset="", parent=None, transformation="original"):
        asset = self.context_asset(asset)
        record = {
            "sha256": digest(content),
            "bytes": len(content),
            "file": self.blob(content),
            "private_raw": True,
            "asset": asset,
            "transformation": transformation,
        }
        identifier = self.put(
            "artifact", record, source=source, identity=[record["sha256"], source, transformation]
        )
        if parent:
            self.link(parent, identifier, "transformation", {"operation": transformation})
        return identifier

    def context_asset(self, host):
        """Resolve a supplied host to one known asset; retain ambiguous context as supplied."""
        if not host or str(host).startswith("asset-"):
            return host
        matches = [
            r["id"]
            for r in self.records("asset")
            if host in {r["data"].get("dns_name"), r["data"].get("origin")}
        ]
        return matches[0] if len(matches) == 1 else host

    def exchange(
        self, request, response=None, *, source=None, tags=None, context=None, metadata=None
    ):
        from fieldkit.core.replay import validate_request

        request = validate_request(request)
        parsed = urlsplit(request["url"])
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Captured request requires an absolute HTTP(S) URL")
        identity = [
            parsed.scheme,
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        ]
        previous = self.connection.execute(
            "SELECT private_json FROM records WHERE id=?", ("asset-" + digest(identity)[:24],)
        ).fetchone()
        observed = json.loads(previous[0]) if previous else {}
        asset = self.put(
            "asset",
            {
                **observed,
                "scheme": parsed.scheme,
                "dns_name": parsed.hostname,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "origin": f"{parsed.scheme}://{parsed.netloc}",
                **{k: v for k, v in (metadata or {}).items() if v is not None},
            },
            source=source,
            identity=identity,
        )
        private = {
            "request": request,
            "response": response,
            "context": context or {},
            "tags": tags or [],
            "asset": asset,
        }
        public = {
            "request": {"method": request["method"], "url": request["url"]},
            "response": {
                k: v for k, v in (response or {}).items() if k not in {"body_base64", "headers_raw"}
            },
            "context": context or {},
            "tags": tags or [],
            "asset": asset,
            "private_raw": True,
        }
        identifier = self.put("request", public, private=private, source=source)
        self.link(asset, identifier, "request")
        name = (context or {}).get("user") or (context or {}).get("profile")
        if name:
            person = self.put("identity", context, source=source, identity=[asset, name])
            self.link(person, identifier, "session_context")
        if response and response.get("body_base64"):
            content = base64.b64decode(response["body_base64"], validate=True)
            artifact = self.artifact(content, source={"request": identifier}, asset=asset)
            self.link(identifier, artifact, "response_body")
        return identifier

    def request(self, identifier):
        try:
            record = self.get(identifier, private=True)
        except ValueError:
            matches = [
                r
                for r in self.records("request", private=True)
                if str(r["source"].get("index")) == str(identifier)
            ]
            if len(matches) != 1:
                raise ValueError("Request ID/index must identify one captured request") from None
            record = matches[0]
        if record["kind"] != "request":
            raise ValueError("Selected evidence is not a request")
        request = dict(record["data"]["request"])
        request["id"] = str(identifier)
        return request
