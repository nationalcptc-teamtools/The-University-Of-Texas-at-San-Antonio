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

from .contracts import Bounds, MergeBundle, MergeReport, PolicyError, Reservation
from .contracts import canonical_json, digest
from .storage import private_directory


_COUNTERS = ("request_limit", "output_bytes", "process_limit", "model_calls", "actions", "auth_posts")
_ID_RE = re.compile(r"^[^\x00-\x1f\x7f]+$")


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

    def stop(self, reason: str = "operator stop") -> None:
        with self._tx():
            self._db.execute("INSERT OR IGNORE INTO stops VALUES (?,?)", (self.engagement_id, reason))

    def stopped(self) -> bool:
        return self._db.execute("SELECT 1 FROM stops WHERE engagement=?", (self.engagement_id,)).fetchone() is not None

    def stop_reason(self) -> str | None:
        row = self._db.execute("SELECT reason FROM stops WHERE engagement=?", (self.engagement_id,)).fetchone()
        return row[0] if row else None

    def assign(self, workspace_id: str, target_id: str, auth_realm: str = "") -> None:
        self._assert_mutable()
        if not target_id:
            return
        with self._tx():
            self._assert_mutable()
            self._assign_locked(workspace_id, target_id, auth_realm)

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

    def reserve(self, request_id: str, bounds: Bounds, *, workspace_id: str = "",
                target_id: str | None = None, auth_realm: str = "", workflow_id: str = "default",
                limits: dict[str, int] | None = None) -> Reservation:
        """Atomically reserve all declared budgets before any dispatch."""
        self._assert_mutable()
        values = asdict(bounds)
        if any(type(values[k]) is not int or not 0 <= values[k] <= 2147483647 for k in _COUNTERS):
            raise PolicyError("invalid reservation bounds")
        with self._tx():
            self._assert_mutable()
            if self.stopped():
                raise PolicyError("engagement is stopped")
            old = self._db.execute("SELECT bounds FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                                   (self.engagement_id, self.device_id, request_id)).fetchone()
            if old:
                raise PolicyError("request id was already reserved")
            if target_id:
                self._assign_locked(workspace_id, target_id, auth_realm)
            active = self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND workspace=? AND state='running'",
                                      (self.engagement_id, workspace_id)).fetchone()
            if active:
                raise PolicyError("workspace already has an operation in flight")
            # A target cannot be in flight twice even when realm is blank.
            if target_id and self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND target=? AND state='running'",
                                               (self.engagement_id, target_id)).fetchone():
                raise PolicyError("target already has an operation in flight")
            ceiling = {**self.limits, **(limits or {})}
            current = self.usage(workflow_id)
            target_current = self.usage(target_id=target_id) if target_id else current
            for key in _COUNTERS:
                amount = int(values.get(key, 0))
                if amount < 0:
                    raise PolicyError("invalid negative budget")
                limit = ceiling.get(key)
                charged = target_current if key == "request_limit" and target_id else current
                if limit is not None and charged.get(key, 0) + amount > limit:
                    raise PolicyError("durable budget exhausted")
            self._db.execute("INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (self.engagement_id, self.device_id, request_id, workspace_id, target_id,
                              auth_realm, workflow_id, json.dumps(values, sort_keys=True), "running", "{}"))
        remaining = {k: max(0, int(limit - (self.usage(target_id=target_id) if k == "request_limit" and target_id
                                           else self.usage(workflow_id)).get(k, 0)))
                     for k, limit in ceiling.items() if k in _COUNTERS}
        return Reservation(request_id, bounds, remaining)

    def finish(self, request_id: str, usage: dict[str, int] | None = None, *, state: str = "finished") -> None:
        self._assert_mutable()
        usage = {k: max(0, int(v)) for k, v in (usage or {}).items() if k in _COUNTERS}
        with self._tx():
            self._assert_mutable()
            row = self._db.execute("SELECT 1 FROM reservations WHERE engagement=? AND device=? AND request_id=?",
                                   (self.engagement_id, self.device_id, request_id)).fetchone()
            if not row:
                raise PolicyError("no reservation for request")
            self._db.execute("UPDATE reservations SET state=?, usage=? WHERE engagement=? AND device=? AND request_id=?",
                             (state, json.dumps(usage, sort_keys=True), self.engagement_id, self.device_id, request_id))

    def charge(self, request_id: str, counter: str, amount: int, *, workflow_id: str = "default", limits: dict[str, int] | None = None) -> None:
        self._assert_mutable()
        if counter not in _COUNTERS or amount < 0: raise PolicyError("invalid durable charge")
        values = {counter: amount}
        bounds = Bounds(output_bytes=0, process_limit=0, **values) if counter not in {"output_bytes", "process_limit"} else Bounds(**values)
        key = "charge:" + request_id
        try:
            self.reserve(key, bounds, workspace_id="", workflow_id=workflow_id, limits=limits)
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
            if not self._db.execute("SELECT 1 FROM stops WHERE engagement=?", (self.engagement_id,)).fetchone():
                raise PolicyError("handover requires a stopped ledger")
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
                    for counter, grouping, ceiling in (("request_limit", "target", 24), ("model_calls", "workflow", 6),
                                                        ("actions", "workflow", 12), ("auth_posts", "realm", 2)):
                        key = (counter, item[grouping])
                        scoped[key] = scoped.get(key, 0) + values[counter]
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
            if not isinstance(bounds, dict) or set(bounds) != set(asdict(Bounds())) or any(type(bounds[k]) is not int or not 0 <= bounds[k] <= 2147483647 for k in _COUNTERS):
                raise PolicyError("invalid handover reservation bounds")
            timeout = bounds["timeout_s"]
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 <= timeout <= 3600:
                raise PolicyError("invalid handover reservation timeout")
            if bounds["request_limit"] > 24 or bounds["actions"] > 12 or bounds["model_calls"] > 6 or bounds["auth_posts"] > 2 or bounds["output_bytes"] > 131072:
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
            def __enter__(s): s.outer._lock.acquire(); s.outer._db.execute("BEGIN IMMEDIATE"); return s
            def __exit__(s, typ, val, tb):
                s.outer._db.execute("ROLLBACK" if typ else "COMMIT"); s.outer._lock.release()
        return Tx(self)
