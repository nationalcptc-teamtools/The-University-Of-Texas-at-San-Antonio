"""Durable publication journals for derived, completion-audited local reports."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from .contracts import AuditEvent, PolicyError, canonical_json
from .storage import atomic_write, exclusive, private_directory, read_private, write_json

MAX_BYTES = 128 * 1024 * 1024
DESTINATIONS = {"coverage_generated": {"coverage.json"},
                "report_complete": {"reports/observations.json", "reports/observations.md"}}


def _hash(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _summary(manifest):
    return [{k: item[k] for k in ("path", "sha256", "bytes")} for item in manifest["files"]]


def _digest(manifest):
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def _metadata(value):
    return (isinstance(value, dict) and set(value) == {"sha256", "bytes"}
            and isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
            and type(value["bytes"]) is int and 0 <= value["bytes"] <= MAX_BYTES)


def _journals(root, receipts):
    directory = private_directory(root / "reports/publications", create=True)
    journals = {}
    for path in directory.iterdir():
        # atomic_write may leave a private candidate after an abrupt process exit.
        # Candidates are never authority and cannot be exported.
        if re.fullmatch(r"\.[0-9a-f]{32}\.json\.[0-9a-f]{16}\.tmp", path.name):
            read_private(path)
            continue
        if not re.fullmatch(r"[0-9a-f]{32}\.json", path.name):
            raise PolicyError("unexpected publication journal")
        value = json.loads(read_private(path))
        if not isinstance(value, dict) or set(value) != {"manifest", "state"} or value["state"] not in {"pending", "accepted", "aborted"}:
            raise PolicyError("invalid publication journal")
        manifest = value["manifest"]
        if (not isinstance(manifest, dict) or set(manifest) != {"version", "generation", "kind", "files"}
                or manifest["version"] != 1 or manifest["generation"] != path.stem
                or manifest["kind"] not in DESTINATIONS or not isinstance(manifest["files"], list)):
            raise PolicyError("invalid publication manifest")
        items = manifest["files"]
        if (len(items) != len(DESTINATIONS[manifest["kind"]])
                or any(not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes", "previous"}
                       or not isinstance(item["path"], str)
                       or not _metadata({k: item[k] for k in ("sha256", "bytes")})
                       or (item["previous"] is not None and not _metadata(item["previous"])) for item in items)
                or {item["path"] for item in items} != DESTINATIONS[manifest["kind"]]):
            raise PolicyError("invalid publication paths or checksums")
        intent = receipts["intents"].get(path.stem)
        if intent is not None and intent != {"manifest_sha256": _digest(manifest), "kind": manifest["kind"]}:
            raise PolicyError("publication journal differs from its audit intent")
        completion = receipts["completed"].get(path.stem)
        if completion is not None and completion != {"manifest_sha256": _digest(manifest), "kind": manifest["kind"], "files": _summary(manifest), "sequence": completion["sequence"]}:
            raise PolicyError("publication journal differs from its completion")
        if value["state"] == "accepted" and completion is None:
            raise PolicyError("accepted publication has no completion")
        if value["state"] == "aborted" and completion is not None:
            raise PolicyError("aborted publication has an uncertain completion")
        journals[path.stem] = value
    if set(receipts["intents"]) - set(journals):
        raise PolicyError("audit-linked publication journal is missing")
    return journals


def accepted_files(root: Path, receipts):
    """Only latest committed destinations qualify for a reviewed export."""
    root = private_directory(root)
    with exclusive(root / "reports/.publication.lock"):
        journals = _journals(root, receipts)
        if any(value["state"] == "pending" for value in journals.values()):
            raise PolicyError("unfinished publication requires restart recovery")
        accepted = {}
        for generation, completion in sorted(receipts["completed"].items(), key=lambda pair: pair[1]["sequence"]):
            if journals[generation]["state"] != "accepted":
                raise PolicyError("publication completion is uncertain")
            accepted.update({item["path"]: item for item in completion["files"]})
        return accepted


class Publications:
    def __init__(self, root, audit, ledger):
        self.root, self.audit, self.ledger = root, audit, ledger
        for name in ("reports", "reports/publications", "reports/unaccepted", "reports/history"):
            private_directory(root / name, create=True)
            _sync((root / name).parent)

    def _journal(self, generation):
        return self.root / "reports/publications" / (generation + ".json")

    def _paths(self, manifest, item):
        generation = manifest["generation"]
        final = self.root / item["path"]
        staged = private_directory(self.root / "reports/unaccepted" / generation, create=True) / final.name
        backup = private_directory(self.root / "reports/history" / generation, create=True) / final.name
        return final, staged, backup

    def _recover(self):
        receipts = self.audit.publication_receipts()
        journals = _journals(self.root, receipts)
        for generation, value in journals.items():
            if value["state"] != "pending":
                continue
            manifest = value["manifest"]
            if generation in receipts["completed"]:
                # Completion is authoritative even if its acknowledgement or the
                # final journal checkpoint was lost. Never roll it back.
                for item in manifest["files"]:
                    final, _, _ = self._paths(manifest, item)
                    if _hash(read_private(final, MAX_BYTES)) != {k: item[k] for k in ("sha256", "bytes")}:
                        raise PolicyError("completed publication bytes are inconsistent")
                write_json(self._journal(generation), {"manifest": manifest, "state": "accepted"})
                continue
            self.ledger.stop("interrupted derived publication requires operator review")
            for item in manifest["files"]:
                final, staged, backup = self._paths(manifest, item)
                old, new = item["previous"], {k: item[k] for k in ("sha256", "bytes")}
                current = _hash(read_private(final, MAX_BYTES)) if final.exists() or final.is_symlink() else None
                if current not in (old, new, None):
                    raise PolicyError("derived output changed outside its publication")
                # Backups are copied before intent; recovery never consumes them,
                # so another crash during recovery remains recoverable.
                if old is not None and _hash(read_private(backup, MAX_BYTES)) != old:
                    raise PolicyError("previous derived output backup failed integrity")
                if current == new:
                    atomic_write(staged, read_private(final, MAX_BYTES))
                if old is None:
                    final.unlink(missing_ok=True)
                    _sync(final.parent)
                else:
                    atomic_write(final, read_private(backup, MAX_BYTES))
            write_json(self._journal(generation), {"manifest": manifest, "state": "aborted"})
        latest = {}
        for completion in sorted(receipts["completed"].values(), key=lambda item: item["sequence"]):
            latest.update({item["path"]: item for item in completion["files"]})
        for relative, item in latest.items():
            if _hash(read_private(self.root / relative, MAX_BYTES)) != {k: item[k] for k in ("sha256", "bytes")}:
                raise PolicyError("accepted derived output failed integrity verification")
        return receipts

    def recover(self):
        try:
            with exclusive(self.root / "reports/.publication.lock"):
                self._recover()
        except Exception:
            self.ledger.stop("derived publication recovery failed")
            raise PolicyError("publication recovery requires operator review") from None

    def publish(self, payloads, completion):
        with exclusive(self.root / "reports/.publication.lock"):
            try:
                self._recover()
                generation = uuid.uuid4().hex
                manifest = {"version": 1, "generation": generation, "kind": completion.kind, "files": []}
                if completion.kind not in DESTINATIONS or {str(path.relative_to(self.root)) for path, _ in payloads} != DESTINATIONS[completion.kind]:
                    raise PolicyError("unsupported publication destination")
                for path, raw in payloads:
                    if len(raw) > MAX_BYTES:
                        raise PolicyError("derived output exceeds collection allowance")
                    old = read_private(path, MAX_BYTES) if path.exists() or path.is_symlink() else None
                    item = {"path": str(path.relative_to(self.root)), **_hash(raw), "previous": _hash(old) if old is not None else None}
                    manifest["files"].append(item)
                    _, staged, backup = self._paths(manifest, item)
                    atomic_write(staged, raw, replace=False)
                    if old is not None:
                        atomic_write(backup, old, replace=False)
                _sync(self.root / "reports/unaccepted")
                _sync(self.root / "reports/history")
                write_json(self._journal(generation), {"manifest": manifest, "state": "pending"}, replace=False)
                checksum = _digest(manifest)
                self.audit.emit(AuditEvent("publication_intent", data={"generation": generation,
                    "manifest_sha256": checksum, "kind": completion.kind}))
                for item in manifest["files"]:
                    final, staged, _ = self._paths(manifest, item)
                    os.replace(staged, final)
                    _sync(final.parent)
                self.audit.emit(AuditEvent(completion.kind, completion.action_id, {**completion.data,
                    "generation": generation, "manifest_sha256": checksum, "files": _summary(manifest)}))
                write_json(self._journal(generation), {"manifest": manifest, "state": "accepted"})
            except Exception:
                self.ledger.stop("derived publication or audit failed")
                try:
                    self._recover()
                except Exception:
                    pass  # Durable pending journal blocks use until recovery succeeds.
                raise PolicyError("derived publication failed; workspace stopped for review") from None
