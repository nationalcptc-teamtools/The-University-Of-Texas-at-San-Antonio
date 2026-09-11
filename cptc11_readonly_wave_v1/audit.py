"""Metadata-only append-only audit chain and typed encrypted capture."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable, Iterator
import uuid

from .metadata import validate_metadata


class AuditError(RuntimeError):
    """Audit storage or integrity policy failed."""


@dataclass(frozen=True, slots=True)
class AuditVerification:
    valid: bool
    sequence: int
    reason: str | None = None


_SAFE = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
_SECRET = {"password", "passwd", "secret", "token", "cookie", "authorization", "private_key", "credential"}
_RAW = {"raw", "body", "response", "headers", "request", "path", "url", "ciphertext"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class AgeEncryptedRecord:
    """Validated production capture returned by an age adapter."""

    encryption_format: str
    recipient_fingerprint: str
    plaintext_sha256: str
    ciphertext: bytes

    def __post_init__(self) -> None:
        if self.encryption_format != "age-v1" or _HEX64.fullmatch(self.recipient_fingerprint or "") is None:
            raise AuditError("age record identity is invalid")
        if _HEX64.fullmatch(self.plaintext_sha256 or "") is None or type(self.ciphertext) is not bytes or not self.ciphertext:
            raise AuditError("age record fields are invalid")
        if not self.ciphertext.startswith(b"age-encryption.org/v1\n"):
            raise AuditError("age framing is invalid")


@dataclass(frozen=True, slots=True)
class SyntheticEncryptedRecord:
    """Test-only encrypted marker. It contains no plaintext."""

    encryption_format: str
    recipient_fingerprint: str
    plaintext_sha256: str
    ciphertext: bytes

    def __post_init__(self) -> None:
        if (self.encryption_format != "synthetic-v1" or type(self.recipient_fingerprint) is not str
                or not self.recipient_fingerprint or _HEX64.fullmatch(self.plaintext_sha256 or "") is None
                or type(self.ciphertext) is not bytes or not self.ciphertext):
            raise AuditError("synthetic record fields are invalid")


def _clean(value: Any, key: str = "") -> Any:
    lowered = key.casefold()
    if lowered in _SECRET:
        return None
    if lowered in _RAW:
        raise AuditError("raw or transport data is not allowed in metadata")
    if isinstance(value, dict):
        result = {}
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise AuditError("audit metadata key is invalid")
            if raw_key.casefold() in _SECRET:
                continue
            result[raw_key] = _clean(child, raw_key)
        return result
    if isinstance(value, (list, tuple)):
        return [_clean(item, key) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        if isinstance(value, str) and len(value) > 4096:
            raise AuditError("audit metadata value is oversized")
        return value
    raise AuditError("audit metadata type is not permitted")


class ReadonlyAuditWriter:
    """A durable, process-serialized, metadata-only audit writer."""

    def __init__(self, root: str | Path, *, encryptor: object | None,
                 now: Callable[[], str] = _utc, clock_ns: Callable[[], int] = time.monotonic_ns,
                 stop_callback: Callable[[str], None] | None = None, test_only: bool = False) -> None:
        self.root = Path(root)
        self.encryptor, self.now, self.clock_ns = encryptor, now, clock_ns
        self.stop_callback, self.test_only = stop_callback, test_only is True
        self._seq = 0; self._previous = "0" * 64
        self._reservations: dict[str, int] = {}; self._used: dict[str, int] = {}
        self._captured: set[tuple[str, str]] = set(); self._evidence: dict[str, dict[str, Any]] = {}; self._closed = False
        self._lock_fd: int | None = None
        self.initialize()

    def initialize(self) -> None:
        if self.root.exists() and self.root.is_symlink(): raise AuditError("audit root symlink rejected")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True); self.root.chmod(0o700)
        for name in ("evidence", "segments"):
            path = self.root / name
            if path.exists() and (path.is_symlink() or not path.is_dir()): raise AuditError("audit directory is invalid")
            path.mkdir(mode=0o700, exist_ok=True); path.chmod(0o700)
        created: set[str] = set()
        for name in ("audit.jsonl", "transcript.log", ".audit-state.json", ".audit.lock", "audit.manifest.json", "evidence-manifest.json"):
            path = self.root / name
            if path.exists() and path.is_symlink(): raise AuditError("audit file symlink rejected")
            if not path.exists():
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600); os.close(fd)
                created.add(name)
            path.chmod(0o600)
        for name, initial in ((".audit-state.json", {"sequence": 0, "previous_hash": "0" * 64, "reservations": {}, "used": {}}),
                              ("evidence-manifest.json", {"schema_version": 1, "items": {}})):
            path = self.root / name
            if name in created:
                fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(initial, stream, sort_keys=True, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
        if self._lock_fd is None:
            self._lock_fd = os.open(self.root / ".audit.lock", os.O_RDWR | os.O_NOFOLLOW)
        with self._locked():
            try:
                self._load_state_locked()
                self._load_evidence_locked()
            except AuditError:
                self._latch_failure("audit state or evidence inventory is invalid")
                raise
            self._verify_locked_or_raise()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if self._closed: raise AuditError("audit writer is closed")
        if self._lock_fd is None: raise AuditError("audit lock is unavailable")
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        except OSError as exc: raise AuditError("audit lock is unavailable") from exc
        try:
            yield
        finally:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def _load_state_locked(self) -> None:
        try:
            text = (self.root / ".audit-state.json").read_text(encoding="utf-8")
            loaded = json.loads(text) if text.strip() else {}
            if not isinstance(loaded, dict) or set(loaded) != {"sequence", "previous_hash", "reservations", "used"}:
                raise ValueError
            self._seq = loaded["sequence"]; self._previous = loaded["previous_hash"]
            if type(self._seq) is not int or self._seq < 0 or _HEX64.fullmatch(self._previous) is None:
                raise ValueError
            reservations, used = loaded["reservations"], loaded["used"]
            if not isinstance(reservations, dict) or not isinstance(used, dict) or set(reservations) != set(used): raise ValueError
            if any(_SAFE.fullmatch(key) is None or type(value) is not int or value <= 0 for key, value in reservations.items()): raise ValueError
            if any(_SAFE.fullmatch(key) is None or type(value) is not int or value < 0 or value > reservations[key] for key, value in used.items()): raise ValueError
            self._reservations = dict(reservations); self._used = dict(used)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            self._latch_failure("audit state is invalid")
            raise AuditError("audit state is invalid") from exc

    def _save_state_locked(self) -> None:
        data = {"sequence": self._seq, "previous_hash": self._previous,
                "reservations": self._reservations, "used": self._used}
        temp = self.root / ".audit-state.json.next"
        fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, self.root / ".audit-state.json"); (self.root / ".audit-state.json").chmod(0o600)
        try:
            fd = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(fd); os.close(fd)
        except OSError as exc: raise AuditError("audit state directory is not durable") from exc

    def _load_evidence_locked(self) -> None:
        try:
            text = (self.root / "evidence-manifest.json").read_text(encoding="utf-8")
            loaded = json.loads(text) if text.strip() else {"schema_version": 1, "items": {}}
            if not isinstance(loaded, dict) or loaded.get("schema_version") != 1 or not isinstance(loaded.get("items"), dict):
                raise ValueError
            self._evidence = {str(key): item for key, item in loaded["items"].items()}
            if any(not isinstance(item, dict) or item.get("key") != key for key, item in self._evidence.items()):
                raise ValueError
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise AuditError("evidence inventory is invalid") from exc

    def _save_evidence_locked(self) -> None:
        path = self.root / "evidence-manifest.json"; temp = self.root / "evidence-manifest.json.next"
        fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"schema_version": 1, "items": self._evidence}, stream, sort_keys=True, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path); path.chmod(0o600)

    def _verify_evidence_locked(self) -> AuditVerification | None:
        expected: set[str] = set()
        for key, item in self._evidence.items():
            required = {"key", "filename", "action_id", "stream", "record_format", "recipient_fingerprint",
                        "plaintext_sha256", "plaintext_bytes", "ciphertext_sha256", "ciphertext_bytes"}
            if (not isinstance(item, dict) or set(item) != required or not _SAFE.fullmatch(key) or item.get("key") != key or item.get("filename") != f"{key}.enc"
                    or not _SAFE.fullmatch(item.get("action_id", "")) or not _SAFE.fullmatch(item.get("stream", ""))
                    or item.get("record_format") not in {"age-v1", "synthetic-v1"} or not isinstance(item.get("recipient_fingerprint"), str)
                    or _HEX64.fullmatch(item.get("plaintext_sha256", "")) is None
                    or _HEX64.fullmatch(item.get("ciphertext_sha256", "")) is None
                    or type(item.get("plaintext_bytes")) is not int or item["plaintext_bytes"] < 0
                    or type(item.get("ciphertext_bytes")) is not int or item["ciphertext_bytes"] <= 0):
                return AuditVerification(False, 0, "evidence inventory entry is invalid")
            try: validate_metadata(item)
            except Exception: return AuditVerification(False, 0, "evidence inventory metadata is restricted")
            path = self.root / "evidence" / item["filename"]; expected.add(item["filename"])
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
                return AuditVerification(False, 0, "evidence artifact is missing or unsafe")
            data = path.read_bytes()
            if len(data) != item["ciphertext_bytes"] or hashlib.sha256(data).hexdigest() != item["ciphertext_sha256"]:
                return AuditVerification(False, 0, "evidence artifact differs from inventory")
        try:
            children = list((self.root / "evidence").iterdir())
            if any(path.is_symlink() or not path.is_file() for path in children):
                return AuditVerification(False, 0, "evidence directory contains an unsafe entry")
            actual = {path.name for path in children}
        except OSError as exc:
            return AuditVerification(False, 0, str(exc))
        return AuditVerification(False, 0, "evidence inventory does not match artifacts") if actual != expected else None

    def _latch_failure(self, reason: str) -> None:
        if self.stop_callback is not None:
            try: self.stop_callback(reason)
            except Exception: pass
        marker = self.root / "audit-stop.json"
        try:
            fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"reason": reason, "time": self.now()}, stream, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
        except (OSError, ValueError):
            pass

    def _emit_locked(self, event_type: str, metadata: dict[str, Any]) -> dict[str, Any]:
        timestamp = self.now()
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"): raise AuditError("UTC timestamp required")
        event = {"event_id": str(uuid.uuid4()), "event_type": event_type, "time": timestamp,
                 "monotonic_ns": int(self.clock_ns()), "sequence": self._seq + 1,
                 "previous_hash": self._previous, "metadata": metadata}
        event_hash = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        event["event_hash"] = event_hash
        try:
            with (self.root / "audit.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"); stream.flush(); os.fsync(stream.fileno())
            with (self.root / "transcript.log").open("a", encoding="utf-8") as stream:
                stream.write(f"{timestamp} seq={event['sequence']} type={event_type} id={event['event_id']} hash={event_hash}\n"); stream.flush(); os.fsync(stream.fileno())
        except OSError as exc:
            self._latch_failure("audit append failed"); raise AuditError("audit append failed") from exc
        self._seq += 1; self._previous = event_hash; self._save_state_locked(); return event

    def emit(self, event_type: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if type(event_type) is not str or not _SAFE.fullmatch(event_type): raise AuditError("event type is invalid")
        cleaned = _clean(dict(metadata or {}))
        try: validate_metadata(cleaned)
        except Exception as exc: raise AuditError("audit metadata is restricted") from exc
        with self._locked():
            self._load_state_locked(); self._verify_locked_or_raise(); return self._emit_locked(event_type, cleaned)

    def reserve_output(self, action_id: str, allowance: int) -> None:
        if not _SAFE.fullmatch(action_id) or type(allowance) is not int or allowance <= 0: raise AuditError("output allowance is invalid")
        with self._locked():
            self._load_state_locked(); self._verify_locked_or_raise()
            if action_id in self._reservations: return
            self._reservations[action_id] = allowance; self._used[action_id] = 0; self._save_state_locked()

    def release_output(self, action_id: str) -> None:
        with self._locked():
            self._load_state_locked(); self._verify_locked_or_raise()
            self._reservations.pop(action_id, None); self._used.pop(action_id, None); self._save_state_locked()

    def capture_bytes(self, action_id: str, stream: str, data: bytes) -> str:
        if self.encryptor is None or not hasattr(self.encryptor, "encrypt"): raise AuditError("a reviewed typed encryptor is required")
        if not _SAFE.fullmatch(action_id) or not _SAFE.fullmatch(stream) or type(data) is not bytes: raise AuditError("capture metadata is invalid")
        with self._locked():
            self._load_state_locked(); self._verify_locked_or_raise()
            if (action_id, stream) in self._captured: raise AuditError("capture descriptor already consumed")
            if action_id not in self._reservations: raise AuditError("output was not reserved")
            if len(data) > self._reservations[action_id] - self._used[action_id]: raise AuditError("capture allowance exhausted")
            try: record = self.encryptor.encrypt(data)
            except Exception as exc: self._latch_failure("capture encryption failed"); raise AuditError("capture encryption failed") from exc
            digest = hashlib.sha256(data).hexdigest()
            if isinstance(record, SyntheticEncryptedRecord) and self.test_only:
                if record.plaintext_sha256 != digest or record.ciphertext == data: raise AuditError("synthetic record does not bind the plaintext")
            elif isinstance(record, AgeEncryptedRecord):
                if record.plaintext_sha256 != digest or record.ciphertext == data: raise AuditError("age record does not bind the plaintext")
            else: raise AuditError("production capture requires a typed age record")
            destination = self.root / "evidence" / f"{action_id}.{stream}.enc"
            if destination.exists() or destination.is_symlink(): raise AuditError("capture destination exists")
            try:
                fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as file: file.write(record.ciphertext); file.flush(); os.fsync(file.fileno())
            except OSError as exc: self._latch_failure("encrypted capture persistence failed"); raise AuditError("encrypted capture persistence failed") from exc
            encrypted_digest = hashlib.sha256(record.ciphertext).hexdigest()
            key = f"{action_id}.{stream}"
            self._evidence[key] = {"key": key, "filename": f"{key}.enc", "action_id": action_id, "stream": stream,
                                   "record_format": record.encryption_format, "recipient_fingerprint": record.recipient_fingerprint,
                                   "plaintext_sha256": record.plaintext_sha256, "plaintext_bytes": len(data),
                                   "ciphertext_sha256": encrypted_digest, "ciphertext_bytes": len(record.ciphertext)}
            self._save_evidence_locked()
            self._used[action_id] += len(data); self._captured.add((action_id, stream)); self._save_state_locked()
            self._emit_locked("capture", {"action_id": action_id, "stream": stream, "bytes": len(data), "ciphertext_sha256": encrypted_digest})
            return encrypted_digest

    def capture_descriptor(self, action_id: str, stream: str, descriptor: Any, expected_length: int) -> str:
        if type(expected_length) is not int or expected_length < 0: raise AuditError("descriptor length is invalid")
        try:
            fd = descriptor.fileno() if hasattr(descriptor, "fileno") else int(descriptor)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_length: raise AuditError("descriptor is not a regular bounded file")
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            if flags & os.O_ACCMODE != os.O_RDONLY: raise AuditError("descriptor must be read-only")
            get_seals = getattr(fcntl, "F_GET_SEALS", None)
            required = getattr(fcntl, "F_SEAL_WRITE", 0) | getattr(fcntl, "F_SEAL_GROW", 0) | getattr(fcntl, "F_SEAL_SHRINK", 0) | getattr(fcntl, "F_SEAL_SEAL", 0)
            if get_seals is None or required == 0 or (fcntl.fcntl(fd, get_seals) & required) != required: raise AuditError("descriptor is not a sealed memfd")
            chunks = []; offset = 0
            while offset < expected_length:
                chunk = os.pread(fd, min(65536, expected_length - offset), offset)
                if not chunk: raise AuditError("descriptor ended before declared length")
                chunks.append(chunk); offset += len(chunk)
            if os.pread(fd, 1, expected_length): raise AuditError("descriptor has trailing data")
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino, after.st_size) != (before.st_dev, before.st_ino, before.st_size): raise AuditError("descriptor changed during capture")
            data = b"".join(chunks)
        except AuditError: raise
        except (OSError, ValueError, TypeError) as exc: raise AuditError("descriptor cannot be captured") from exc
        return self.capture_bytes(action_id, stream, data)

    def _verify_locked(self) -> AuditVerification:
        evidence_failure = self._verify_evidence_locked()
        if evidence_failure is not None: return evidence_failure
        previous = "0" * 64; sequence = 0
        try:
            with (self.root / "audit.jsonl").open(encoding="utf-8") as stream:
                for line in stream:
                    event = json.loads(line); sequence += 1
                    if not isinstance(event, dict) or event.get("sequence") != sequence or event.get("previous_hash") != previous:
                        return AuditVerification(False, sequence, "chain predecessor differs")
                    given = event.pop("event_hash")
                    expected = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
                    if given != expected: return AuditVerification(False, sequence, "event hash differs")
                    previous = given
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc: return AuditVerification(False, sequence, str(exc))
        if sequence != self._seq or previous != self._previous:
            return AuditVerification(False, sequence, "audit state differs from chain")
        try:
            text = (self.root / "audit.manifest.json").read_text(encoding="utf-8")
            if text.strip():
                manifest = json.loads(text)
                expected = {"schema_version": 1, "sequence": self._seq,
                            "audit_sha256": hashlib.sha256((self.root / "audit.jsonl").read_bytes()).hexdigest(),
                            "transcript_sha256": hashlib.sha256((self.root / "transcript.log").read_bytes()).hexdigest(),
                            "evidence_manifest_sha256": hashlib.sha256((self.root / "evidence-manifest.json").read_bytes()).hexdigest()}
                if manifest != expected: return AuditVerification(False, sequence, "sealed audit manifest differs")
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return AuditVerification(False, sequence, str(exc))
        return AuditVerification(True, sequence, None)

    def _verify_locked_or_raise(self) -> None:
        result = self._verify_locked()
        if not result.valid:
            self._latch_failure(result.reason or "audit chain is invalid")
            raise AuditError(result.reason or "audit chain is invalid")

    def verify(self) -> AuditVerification:
        with self._locked():
            self._load_state_locked(); return self._verify_locked()

    def verify_or_raise(self) -> None:
        with self._locked(): self._load_state_locked(); self._verify_locked_or_raise()

    def seal(self) -> dict[str, Any]:
        with self._locked():
            self._load_state_locked(); self._verify_locked_or_raise()
            manifest = {"schema_version": 1, "sequence": self._seq,
                        "audit_sha256": hashlib.sha256((self.root / "audit.jsonl").read_bytes()).hexdigest(),
                        "transcript_sha256": hashlib.sha256((self.root / "transcript.log").read_bytes()).hexdigest(),
                        "evidence_manifest_sha256": hashlib.sha256((self.root / "evidence-manifest.json").read_bytes()).hexdigest()}
            path = self.root / "audit.manifest.json"
            fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW);
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"); stream.flush(); os.fsync(stream.fileno())
            path.chmod(0o600); return manifest

    def recover(self) -> AuditVerification:
        return self.verify()

    def close(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd); self._lock_fd = None
        self._closed = True
