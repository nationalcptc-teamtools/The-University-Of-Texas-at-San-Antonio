"""Append-only local audit records with fail-closed evidence capture."""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import shutil
import subprocess
import threading
import time
import uuid
from typing import Any

from .contracts import AuditEvent, AuditSeal, AuditVerification, EvidenceRef, PolicyError, canonical_json
from .storage import private_directory, read_private, write_json, exclusive


_SECRET_KEYS = {"secret", "password", "credential", "credentials", "token", "cookie", "authorization", "api_key", "private_key", "set-cookie", "access_token", "refresh_token"}
_RAW_CLASSES = {"restricted_raw", "client_confidential", "client_confidential_human_only"}


def publication_receipts_from_events(events):
    """Return only integrity-verified publication metadata, never raw evidence."""
    intents, completed = {}, {}
    paths = {"coverage_generated": {"coverage.json"},
             "report_complete": {"reports/observations.json", "reports/observations.md"}}
    for event in events:
        kind, data = event["kind"], event["data"]
        if kind not in {"publication_intent", *paths} or "generation" not in data:
            continue  # Historical reports must be regenerated before export.
        generation = data["generation"]
        checksum = data.get("manifest_sha256")
        if (not isinstance(generation, str) or not re.fullmatch(r"[0-9a-f]{32}", generation)
                or not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum)):
            raise PolicyError("invalid publication audit metadata")
        if kind == "publication_intent":
            if generation in intents or data.get("kind") not in paths or len(intents) >= 2048:
                raise PolicyError("invalid or excessive publication intents")
            intents[generation] = {"manifest_sha256": checksum, "kind": data["kind"]}
        else:
            if intents.get(generation) != {"manifest_sha256": checksum, "kind": kind} or generation in completed:
                raise PolicyError("publication completion lacks a unique matching intent")
            files = data.get("files")
            if (not isinstance(files, list) or len(files) != len(paths[kind])
                    or any(not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"}
                           or not isinstance(item["path"], str)
                           or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                           or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= 128 * 1024 * 1024 for item in files)
                    or {item["path"] for item in files} != paths[kind]):
                raise PolicyError("invalid publication file receipts")
            if type(event.get("seq")) is not int or event["seq"] < 1:
                raise PolicyError("publication completion requires an audit sequence")
            completed[generation] = {"manifest_sha256": checksum, "kind": kind, "files": files, "sequence": event["seq"]}
    return {"intents": intents, "completed": completed}


def _safe(value: Any) -> Any:
    if is_dataclass(value): value = asdict(value)
    if isinstance(value, bytes): return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, dict): return {str(k): "[withheld]" if str(k).lower() in _SECRET_KEYS else _safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [_safe(v) for v in value]
    if isinstance(value, str): return value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\x1b", "\\u001b")
    return value


class AuditWriter:
    def __init__(self, root: str | Path, policy: Any, *, age_binary: str | Path | None = None,
                 age_recipient: str | None = None, clock: Any | None = None,
                 encrypted_volume_verified: bool = False, evidence_cap: int = 131072,
                 profile_worker_sha256: str | None = None,
                 compatible_profile_workers: tuple[str, ...] = ()) -> None:
        self.root = private_directory(Path(root), create=True)
        self.policy = policy
        self.clock = clock
        self.age_binary = Path(age_binary) if age_binary else Path(__file__).resolve().parents[1] / ".tools" / "age"
        self.age_recipient, self.encrypted_volume_verified, self.evidence_cap = age_recipient, encrypted_volume_verified, evidence_cap
        self._lock = threading.RLock()
        self._seq = 0; self._previous = "0" * 64; self._closed = False
        self._failed = False
        self._run_id = uuid.uuid4().hex
        self._session_id = uuid.uuid4().hex
        self._capture_totals = {}
        self._output_limits = {}
        self._profile_worker_sha256 = profile_worker_sha256
        self._compatible_profile_workers = tuple(compatible_profile_workers)
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.root.is_symlink() or (self.root.stat().st_mode & 0o077): raise PolicyError("audit root permissions are unsafe")
            self.evidence_root = private_directory(self.root / "evidence", create=True)
            self.path = self.root / "audit.jsonl"; self.transcript_path = self.root / "transcript.log"
            self.state_path = self.root / ".audit-state.json"; self.segments_root = private_directory(self.root / "segments", create=True)
            self._lockfd = os.open(self.root / ".audit.lock", os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try: fcntl.flock(self._lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc: raise PolicyError("another audit writer is active") from exc
            self._load_tail()
            if (self.root / ".audit-failure.json").exists() or any(self.root.glob(".reserve-*")):
                self._failed = True
            self._probe_ready()
        except Exception as exc:
            self.close()
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError("audit storage is not ready") from exc

    def _probe_ready(self) -> None:
        private_directory(self.root)
        private_directory(self.evidence_root)
        probe = self.root / ".audit-write-probe"
        try:
            fd = os.open(probe, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os,"O_NOFOLLOW",0), 0o600); self._write_all(fd,b"ok"); os.fsync(fd); os.close(fd); probe.unlink()
        except OSError as exc: raise PolicyError("audit storage is not writable") from exc

    def ready(self) -> bool:
        try: self._probe_ready(); return not self._closed and not self._failed
        except PolicyError: return False

    def _fail(self, reason):
        self._failed = True
        marker = self.root / ".audit-failure.json"
        if not marker.exists():
            try:
                write_json(marker, {"reason": reason, "operator_review_required": True}, replace=False)
            except Exception:
                # A pending reservation or inconsistent checkpoint remains on disk
                # when storage cannot accept this additional diagnostic marker.
                pass

    def encryption_ready(self) -> bool:
        if bool(getattr(self.policy, "encrypted_storage", False) and self.encrypted_volume_verified): return True
        if not self.age_recipient or not self.age_binary.is_file() or not os.access(self.age_binary, os.X_OK): return False
        try:
            run = subprocess.run([str(self.age_binary), "-r", self.age_recipient], input=b"probe", stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=10, check=False)
            return run.returncode == 0 and run.stdout.startswith(b"age-encryption.org/")
        except (OSError, subprocess.SubprocessError): return False

    def _now(self) -> tuple[str, dict[str, Any]]:
        state = self.clock() if callable(self.clock) else self.clock
        return (datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                {"synchronized": getattr(state,"synchronized",None), "offset_s": getattr(state,"offset_s",None), "source": getattr(state,"source","unknown")})

    def _load_tail(self) -> None:
        if not self.state_path.exists():
            if (self.path.exists() or self.transcript_path.exists() or
                    any(self.segments_root.iterdir()) or any(self.evidence_root.iterdir()) or
                    (self.root / "audit.manifest.json").exists() or (self.root / "rotation.pending.json").exists()):
                raise PolicyError("audit state is missing for existing records")
            self.origin_id = uuid.uuid4().hex
            self._write_state()
        state = self._read_state()
        self.origin_id, self._seq, self._previous = state["origin_id"], state["seq"], state["tail"]
        pending = self.root / "rotation.pending.json"
        if pending.exists():
            try:
                self._finish_rotation(json.loads(read_private(pending, 8 * 1024 * 1024)), pending)
            except Exception:
                raise PolicyError("incomplete audit rotation cannot be recovered") from None
        for path in (self.path, self.transcript_path):
            if not path.exists() and self._seq == 0 and not any(self.segments_root.iterdir()):
                self._append(path, b"", create=True)
                self._fsync_dir(self.root)
        check = self.verify()
        if not check.valid:
            raise PolicyError("audit integrity verification failed: " + str(check.reason))

    def _read_state(self):
        try:
            value = json.loads(read_private(self.state_path, 65536))
            if (set(value) != {"origin_id", "seq", "tail"} or
                    not isinstance(value["origin_id"], str) or len(value["origin_id"]) != 32 or
                    type(value["seq"]) is not int or value["seq"] < 0 or
                    not isinstance(value["tail"], str) or len(value["tail"]) != 64):
                raise ValueError()
            return value
        except (OSError, ValueError, KeyError, PolicyError):
            raise PolicyError("invalid audit state") from None

    def _write_state(self):
        write_json(self.state_path, {"origin_id": self.origin_id, "seq": self._seq, "tail": self._previous})

    @staticmethod
    def _fsync_dir(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _checkpoint(self, label):
        """Fault-injection seam: called only after a completed durable step."""

    def emit(self, event: AuditEvent) -> dict:
        with self._lock:
            if self._closed or self._failed: raise PolicyError("audit writer is unavailable")
            self._probe_ready(); self._seq += 1; timestamp, clock = self._now()
            record = {"event_id": uuid.uuid4().hex, "seq": self._seq, "timestamp": timestamp, "monotonic_ns": time.monotonic_ns(),
                      "device_id": getattr(self.policy,"device_id","unknown"), "workspace_id": getattr(self.policy,"workspace_id","unknown"),
                      "engagement_id": getattr(self.policy,"engagement_id","unknown"), "policy_revision": getattr(self.policy,"revision","unknown"),
                      "operator_id": getattr(self.policy,"operator_id","unknown"), "run_id": self._run_id, "session_id": self._session_id,
                      "clock": clock, "kind": event.kind, "action_id": event.action_id, "classification": event.classification,
                      "data": _safe(event.data), "previous": self._previous}
            record["hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
            line = canonical_json(record) + b"\n"
            try:
                self._append(self.path, line)
                self._append(self.transcript_path, self._render(record))
            except Exception:
                self._fail("audit append failed")
                raise
            self._previous = record["hash"]
            try: self._write_state()
            except Exception:
                self._fail("audit checkpoint failed")
                raise
            return {"seq": record["seq"], "timestamp": record["timestamp"], "event_id": record["event_id"]}

    @staticmethod
    def _render(record):
        identity = {key: record[key] for key in ("engagement_id", "device_id", "workspace_id", "operator_id", "session_id", "action_id")}
        if "run_id" in record:
            identity["run_id"] = record["run_id"]
        return (f"{record['timestamp']} {record['seq']} " + json.dumps(record["kind"], ensure_ascii=True) + " " +
                json.dumps(identity, sort_keys=True, ensure_ascii=True) + " " +
                json.dumps(record["data"], sort_keys=True, ensure_ascii=True) + "\n").encode()

    def reserve_output(self, request_id: str, maximum: int):
        if self._failed or self._closed:
            raise PolicyError("audit writer is unavailable")
        if type(maximum) is not int or maximum < 0 or maximum > self.evidence_cap:
            raise PolicyError("invalid action output allowance")
        path = self.root / (".reserve-" + hashlib.sha256(request_id.encode()).hexdigest())
        fd = None
        created = False
        try:
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            created = True
            self._checkpoint("output_marker_created")
            self._fsync_dir(self.root)
            self._checkpoint("output_directory_synced")
            os.posix_fallocate(fd, 0, maximum * 2 + 262144)
            self._checkpoint("output_allocated")
            os.fsync(fd)
            self._checkpoint("output_file_synced")
            self.emit(
                AuditEvent("output_reserved", request_id, {"output_bytes": maximum})
            )
            self._checkpoint("output_reserved_emitted")
            os.close(fd)
            fd = None
        except Exception:
            self._fail("output reservation failed")
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                fd = None
            self._output_limits.pop(request_id, None)
            if created:
                try:
                    path.unlink(missing_ok=True)
                    self._fsync_dir(self.root)
                except OSError:
                    self._fail("output reservation rollback requires manual reconciliation")
            raise PolicyError(
                "output reservation failed; insufficient durable space for complete action capture"
            ) from None
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    self._fail(
                        "output reservation rollback requires manual reconciliation"
                    )
        self._output_limits[request_id] = maximum

    def release_output(self, request_id: str):
        self._output_limits.pop(request_id, None)
        path = self.root / (".reserve-" + hashlib.sha256(request_id.encode()).hexdigest())
        try:
            path.unlink(missing_ok=True)
            self._fsync_dir(self.root)
        except OSError:
            self._fail("output reservation release requires manual reconciliation")
            raise PolicyError("output reservation release requires manual reconciliation") from None

    def capture(self, request_id: str, stream: str, data: bytes, classification: str) -> EvidenceRef:
        if self._failed or self._closed:
            raise PolicyError("audit writer is unavailable")
        if stream not in {"stdout", "stderr", "response", "response_metadata", "import", "tool_stdout", "tool_stderr", "raw"}: raise PolicyError("unknown evidence stream")
        if not isinstance(data, bytes): raise PolicyError("evidence is not raw bytes")
        if classification not in _RAW_CLASSES | {"public", "synthetic"}:
            self._fail("unrecognized capture classification")
            raise PolicyError("unrecognized raw capture classification")
        sensitive = classification in _RAW_CLASSES
        total = self._capture_totals.get(request_id, 0)
        available = max(0, self._output_limits.get(request_id, self.evidence_cap) - total)
        complete = len(data) <= available
        retained = data[:available]
        ident = hashlib.sha256((request_id + stream + str(self._seq) + uuid.uuid4().hex).encode()).hexdigest()[:24]
        protected_volume = bool(getattr(self.policy, "encrypted_storage", False) and self.encrypted_volume_verified)
        ext = ".age" if sensitive and not protected_volume else ".bin"
        rel = f"evidence/{ident}-{stream}{ext}"; dest = self.root / rel
        payload = retained
        if sensitive and not protected_volume:
            payload = self._encrypt(retained)
        self._append(dest, payload, create=True)
        ref = EvidenceRef(ident, None, stream, classification, rel, hashlib.sha256(retained).hexdigest(), len(retained))
        self.emit(AuditEvent("evidence_capture", request_id, {"evidence": asdict(ref), "stored_bytes": len(payload),
                       "actual_sha256": hashlib.sha256(data).hexdigest(), "retained_bytes": len(retained), "truncated": not complete,
                       "stored_sha256": hashlib.sha256(payload).hexdigest(), "incomplete_capture": not complete}, classification="metadata"))
        self._capture_totals[request_id] = total + len(retained)
        if not complete:
            self._fail("incomplete capture")
            raise PolicyError("capture allowance reached; action output is incomplete")
        return ref

    def _encrypt(self, data: bytes) -> bytes:
        if not self.age_recipient or not self.age_binary.is_file() or not os.access(self.age_binary, os.X_OK):
            self._fail("evidence encryption unavailable")
            raise PolicyError("sensitive evidence needs verified encrypted storage or age recipient")
        try:
            run = subprocess.run([str(self.age_binary), "-r", self.age_recipient], input=data, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, check=False, timeout=20, env={}, close_fds=True)
        except Exception:
            self._fail("evidence encryption failed")
            raise PolicyError("evidence encryption failed") from None
        if run.returncode or not run.stdout.startswith(b"age-encryption.org/"):
            self._fail("evidence encryption failed")
            raise PolicyError("evidence encryption failed")
        return run.stdout

    def _evidence(self, record, known):
        if record.get("kind") != "evidence_capture":
            return
        data = record["data"]
        relative = Path(data["evidence"]["artifact_relpath"])
        if relative.is_absolute() or len(relative.parts) != 2 or relative.parts[0] != "evidence" or ".." in relative.parts:
            raise PolicyError("invalid evidence locator")
        saved = read_private(self.root / relative, self.evidence_cap * 2 + 4096)
        checksum = hashlib.sha256(saved).hexdigest()
        if checksum != data["stored_sha256"] or len(saved) != data["stored_bytes"]:
            raise PolicyError("evidence integrity mismatch")
        if str(relative) in known:
            raise PolicyError("evidence identifier reused")
        known[str(relative)] = checksum

    def verify(self) -> AuditVerification:
        previous, count, parent = "0" * 64, 0, ""
        known, event_ids = {}, set()
        latest = None
        try:
            private_directory(self.root)
            private_directory(self.evidence_root)
            private_directory(self.segments_root)
            state = self._read_state()
            if state != {"origin_id": self.origin_id, "seq": self._seq, "tail": self._previous}:
                raise PolicyError("in-memory and durable audit checkpoints disagree")
            sources = [(directory, True) for directory in sorted(self.segments_root.iterdir())] + [(self.root, False)]
            for directory, archived in sources:
                private_directory(directory)
                audit_bytes = read_private(directory / "audit.jsonl", 128 * 1024 * 1024)
                transcript_bytes = read_private(directory / "transcript.log", 128 * 1024 * 1024)
                rendered = bytearray()
                for raw in audit_bytes.splitlines(keepends=True):
                    if not raw.endswith(b"\n"):
                        raise PolicyError("incomplete audit checkpoint")
                    record = json.loads(raw)
                    supplied = record.pop("hash")
                    if (record.get("seq") != count + 1 or record.get("previous") != previous or
                            hashlib.sha256(canonical_json(record)).hexdigest() != supplied or record["event_id"] in event_ids):
                        raise PolicyError("audit hash chain or event identity mismatch")
                    stamp = record["timestamp"]
                    if len(stamp) != 27 or not stamp.endswith("Z"):
                        raise PolicyError("audit timestamp must be microsecond UTC")
                    datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                    event_ids.add(record["event_id"])
                    rendered.extend(self._render(record))
                    self._evidence(record, known)
                    previous, count = supplied, count + 1
                if bytes(rendered) != transcript_bytes:
                    raise PolicyError("transcript integrity mismatch")
                if archived:
                    raw_manifest = read_private(directory / "manifest.json", 8 * 1024 * 1024)
                    manifest = json.loads(raw_manifest)
                    unsigned = dict(manifest)
                    checksum = unsigned.pop("sha256")
                    if (hashlib.sha256(canonical_json(unsigned)).hexdigest() != checksum or
                            manifest["segment"] != str(directory.relative_to(self.root)) or manifest["events"] != count or
                            manifest["tail"] != previous or manifest["origin_id"] != self.origin_id or
                            manifest["parent_sha256"] != parent or
                            manifest["audit_sha256"] != hashlib.sha256(audit_bytes).hexdigest() or
                            manifest["transcript_sha256"] != hashlib.sha256(transcript_bytes).hexdigest() or
                            manifest["artifacts"] != [{"path": k, "sha256": v} for k, v in sorted(known.items())]):
                        raise PolicyError("closed manifest, evidence list, or parent chain mismatch")
                    parent, latest = hashlib.sha256(raw_manifest).hexdigest(), raw_manifest
            pointer = self.root / "audit.manifest.json"
            if (latest is None and pointer.exists()) or (latest is not None and read_private(pointer, 8 * 1024 * 1024) != latest):
                raise PolicyError("latest audit manifest pointer mismatch")
            if previous != self._previous or count != self._seq:
                raise PolicyError("record tail and durable checkpoint disagree")
            if {str(p.relative_to(self.root)) for p in self.evidence_root.iterdir()} != set(known):
                raise PolicyError("unrecorded or missing evidence artifact")
        except (OSError, ValueError, KeyError, TypeError, PolicyError) as exc:
            return AuditVerification(False, count, "audit integrity, checkpoint, or permissions failure")
        return AuditVerification(True, count)

    def seal(self) -> AuditSeal:
        return self.rotate()

    def result_receipts(self):
        if not self.verify().valid or not self.ready():
            raise PolicyError("invalid audit cannot supply result receipts")
        receipts = {}
        intents = set()
        expected_actions = set()
        paths = [d / "audit.jsonl" for d in sorted(self.segments_root.iterdir())] + [self.path]
        for path in paths:
            for line in read_private(path, 128 * 1024 * 1024).splitlines():
                event = json.loads(line)
                action = event["action_id"]
                if event["kind"] in {"operation_intent", "operation_denied", "operation_result", "operation_uncertain", "result_storage_uncertain"}:
                    expected_actions.add(action)
                if event["kind"] == "result_record_intent":
                    if not isinstance(action, str) or not action or action in intents:
                        raise PolicyError("duplicate or invalid result intent")
                    intents.add(action)
                elif event["kind"] == "result_record_written":
                    if action not in intents or action in receipts:
                        raise PolicyError("result receipt lacks one preceding unique intent")
                    receipts[action] = event["data"]["record_sha256"]
        if intents != set(receipts) or expected_actions - set(receipts):
            raise PolicyError("unfinished result intent requires operator review")
        return receipts

    def record_profile_wire_receipt(self, receipt):
        """Durably append one strict metadata-only profile wire receipt."""

        from .profile_runtime.receipts import (
            ProfileWireReceipt,
            validate_persisted_profile_wire_receipt,
        )

        value = receipt.as_dict() if isinstance(receipt, ProfileWireReceipt) else receipt
        if not isinstance(self._profile_worker_sha256, str):
            raise PolicyError("trusted current profile worker pin is unavailable")
        validated = validate_persisted_profile_wire_receipt(
            value, expected_worker_sha256=self._profile_worker_sha256
        )
        if validated.action_id in self.profile_wire_receipts():
            raise PolicyError("profile wire receipt action is already recorded")
        encoded = canonical_json(validated.as_dict())
        return self.emit(
            AuditEvent(
                "profile_wire_receipt",
                validated.action_id,
                {
                    "receipt": validated.as_dict(),
                    "receipt_sha256": hashlib.sha256(encoded).hexdigest(),
                },
            )
        )

    def profile_wire_receipts(self):
        """Return integrity-verified receipt metadata keyed by action ID."""

        from .profile_runtime.receipts import validate_persisted_profile_wire_receipt

        if not self.verify().valid or not self.ready():
            raise PolicyError("invalid audit cannot supply profile wire receipts")
        receipts = {}
        evidence = {}
        paths = [d / "audit.jsonl" for d in sorted(self.segments_root.iterdir())] + [self.path]
        for path in paths:
            for line in read_private(path, 128 * 1024 * 1024).splitlines():
                event = json.loads(line)
                if event.get("kind") == "evidence_capture":
                    action = event.get("action_id")
                    data = event.get("data")
                    reference = data.get("evidence") if isinstance(data, dict) else None
                    if (
                        isinstance(action, str)
                        and isinstance(reference, dict)
                        and set(reference)
                        == {
                            "evidence_id",
                            "target_id",
                            "check_id",
                            "classification",
                            "artifact_relpath",
                            "sha256",
                            "bytes",
                        }
                    ):
                        evidence[(action, reference.get("evidence_id"))] = reference
                    continue
                if event.get("kind") != "profile_wire_receipt":
                    continue
                action = event.get("action_id")
                data = event.get("data")
                if (
                    not isinstance(action, str)
                    or not isinstance(data, dict)
                    or set(data) != {"receipt", "receipt_sha256"}
                    or action in receipts
                    or len(receipts) >= 2048
                ):
                    raise PolicyError("invalid or duplicate profile wire receipt")
                presented_worker = (
                    data["receipt"].get("worker_sha256")
                    if isinstance(data["receipt"], dict)
                    else None
                )
                trusted_worker = next(
                    (
                        candidate
                        for candidate in self._compatible_profile_workers
                        if candidate == presented_worker
                    ),
                    None,
                )
                if trusted_worker is None:
                    raise PolicyError("profile wire receipt worker is not release-compatible")
                receipt = validate_persisted_profile_wire_receipt(
                    data["receipt"], expected_worker_sha256=trusted_worker
                )
                if (
                    receipt.action_id != action
                    or not isinstance(data["receipt_sha256"], str)
                    or hashlib.sha256(canonical_json(receipt.as_dict())).hexdigest()
                    != data["receipt_sha256"]
                ):
                    raise PolicyError("profile wire receipt binding differs")
                if receipt.encrypted_artifact_id != "none":
                    reference = evidence.get((action, receipt.encrypted_artifact_id))
                    if (
                        not isinstance(reference, dict)
                        or reference.get("check_id") != "raw"
                        or reference.get("classification")
                        != "client_confidential_human_only"
                        or reference.get("sha256") != receipt.evidence_sha256
                        or reference.get("bytes") != receipt.evidence_bytes
                    ):
                        raise PolicyError("profile wire receipt lacks matching encrypted evidence")
                receipts[action] = receipt.as_dict()
        return receipts

    def record_profile_cleanup_receipt(self, action_id, status):
        """Record whether the lab transport closed after one profile action."""

        if (
            not isinstance(action_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", action_id) is None
            or type(status) is not str
            or status not in {"passed", "failed"}
        ):
            raise PolicyError("profile cleanup receipt fields differ")
        if action_id not in self.profile_wire_receipts():
            raise PolicyError("profile cleanup receipt lacks a wire receipt")
        if action_id in self.profile_cleanup_receipts():
            raise PolicyError("profile cleanup receipt is already recorded")
        return self.emit(
            AuditEvent(
                "profile_cleanup_receipt",
                action_id,
                {
                    "all_resources_closed": status == "passed",
                    "automatic_retry": False,
                    "status": status,
                },
            )
        )

    def profile_cleanup_receipts(self):
        """Return strict cleanup receipts linked to durable wire receipts."""

        if not self.verify().valid or not self.ready():
            raise PolicyError("invalid audit cannot supply profile cleanup receipts")
        wire_actions = set(self.profile_wire_receipts())
        receipts = {}
        paths = [d / "audit.jsonl" for d in sorted(self.segments_root.iterdir())] + [self.path]
        for path in paths:
            for line in read_private(path, 128 * 1024 * 1024).splitlines():
                event = json.loads(line)
                if event.get("kind") != "profile_cleanup_receipt":
                    continue
                action = event.get("action_id")
                data = event.get("data")
                if (
                    action not in wire_actions
                    or action in receipts
                    or len(receipts) >= 2048
                    or not isinstance(data, dict)
                    or set(data)
                    != {"all_resources_closed", "automatic_retry", "status"}
                    or type(data["all_resources_closed"]) is not bool
                    or data["automatic_retry"] is not False
                    or type(data["status"]) is not str
                    or data["status"] not in {"passed", "failed"}
                    or data["all_resources_closed"] != (data["status"] == "passed")
                ):
                    raise PolicyError("invalid or duplicate profile cleanup receipt")
                receipts[action] = dict(data)
        return receipts

    def profile_action_history(self, action_id: str):
        """Return durable admission-history kinds for one fixed profile action."""

        if (
            not isinstance(action_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", action_id) is None
            or not self.verify().valid
            or not self.ready()
        ):
            raise PolicyError("verified profile action history is unavailable")
        admitted = {
            "profile_release_verified",
            "output_reserved",
            "operation_intent",
        }
        kinds = []
        paths = [
            directory / "audit.jsonl"
            for directory in sorted(self.segments_root.iterdir())
        ] + [self.path]
        for path in paths:
            for line in read_private(path, 128 * 1024 * 1024).splitlines():
                event = json.loads(line)
                kind = event.get("kind")
                if event.get("action_id") == action_id and kind in admitted:
                    kinds.append(kind)
        return tuple(kinds)

    def publication_receipts(self):
        if not self.verify().valid or not self.ready():
            raise PolicyError("invalid audit cannot supply publication receipts")
        paths = [d / "audit.jsonl" for d in sorted(self.segments_root.iterdir())] + [self.path]
        return publication_receipts_from_events(json.loads(line) for path in paths
            for line in read_private(path, 128 * 1024 * 1024).splitlines())

    def control_receipts(self):
        """Return bounded, integrity-verified operator-stop acknowledgements."""
        if not self.verify().valid or not self.ready():
            raise PolicyError("invalid audit cannot supply control receipts")
        receipts = {}
        paths = [d / "audit.jsonl" for d in sorted(self.segments_root.iterdir())] + [self.path]
        for path in paths:
            for line in read_private(path, 128 * 1024 * 1024).splitlines():
                event = json.loads(line)
                if event.get("kind") != "operator_stop":
                    continue
                correlation = event.get("action_id")
                data = event.get("data")
                if (not isinstance(correlation, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", correlation)
                        or not isinstance(data, dict) or set(data) != {"interface", "actor", "source", "reason", "received_at", "received_monotonic_ns"}
                        or correlation in receipts or len(receipts) >= 128):
                    raise PolicyError("invalid operator control receipt")
                receipts[correlation] = data
        return receipts

    def rotate(self) -> AuditSeal:
        with self._lock:
            if self._failed or self._closed:
                raise PolicyError("audit writer is unavailable")
            check = self.verify()
            if not check.valid:
                raise PolicyError("cannot seal invalid audit")
            pointer = self.root / "audit.manifest.json"
            if self.path.stat().st_size == 0 and pointer.exists():
                manifest = json.loads(read_private(pointer, 8 * 1024 * 1024))
                return AuditSeal(manifest["sha256"], check.events, str(pointer))
            manifest = {"events": check.events, "audit_sha256": hashlib.sha256(read_private(self.path, 128 * 1024 * 1024)).hexdigest(),
                        "transcript_sha256": hashlib.sha256(read_private(self.transcript_path, 128 * 1024 * 1024)).hexdigest(),
                        "tail": self._previous, "engagement": self.policy.engagement_id, "origin_id": self.origin_id,
                        "policy_revision": self.policy.revision, "device_id": self.policy.device_id,
                        "artifacts": [{"path": str(p.relative_to(self.root)), "sha256": hashlib.sha256(read_private(p, self.evidence_cap * 2 + 4096)).hexdigest()}
                                      for p in sorted(self.evidence_root.iterdir())],
                        "segment": f"segments/{self._seq:020d}-{self._previous[:16]}",
                        "parent_sha256": hashlib.sha256(read_private(pointer, 8 * 1024 * 1024)).hexdigest() if pointer.exists() else ""}
            manifest["sha256"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
            pending = self.root / "rotation.pending.json"
            try:
                write_json(pending, {"manifest": manifest}, replace=False)
                self._checkpoint("pending")
                self._finish_rotation({"manifest": manifest}, pending)
            except Exception:
                self._failed = True
                raise
            return AuditSeal(manifest["sha256"], check.events, str(pointer))

    def _finish_rotation(self, pending, pending_path):
        if set(pending) != {"manifest"}:
            raise PolicyError("invalid rotation journal")
        manifest = pending["manifest"]
        unsigned = dict(manifest)
        checksum = unsigned.pop("sha256")
        expected_segment = f"segments/{self._seq:020d}-{self._previous[:16]}"
        if (hashlib.sha256(canonical_json(unsigned)).hexdigest() != checksum or manifest["segment"] != expected_segment or
                manifest["events"] != self._seq or manifest["tail"] != self._previous or manifest["origin_id"] != self.origin_id):
            raise PolicyError("rotation journal does not match durable checkpoint")
        segment = private_directory(self.root / expected_segment, create=True)
        self._fsync_dir(self.segments_root)
        self._checkpoint("directory")
        for filename, field in (("audit.jsonl", "audit_sha256"), ("transcript.log", "transcript_sha256")):
            source, destination = self.root / filename, segment / filename
            if destination.exists():
                if hashlib.sha256(read_private(destination, 128 * 1024 * 1024)).hexdigest() != manifest[field]:
                    raise PolicyError("archived rotation bytes disagree")
                if source.exists() and read_private(source, 128 * 1024 * 1024) != b"":
                    raise PolicyError("active bytes conflict with pending rotation")
            else:
                if hashlib.sha256(read_private(source, 128 * 1024 * 1024)).hexdigest() != manifest[field]:
                    raise PolicyError("active rotation bytes disagree")
                os.replace(source, destination)
                self._fsync_dir(segment)
                self._fsync_dir(self.root)
            self._checkpoint(filename)
        raw_manifest = canonical_json(manifest) + b"\n"
        destination = segment / "manifest.json"
        if destination.exists():
            if read_private(destination, 8 * 1024 * 1024) != raw_manifest:
                raise PolicyError("pending manifest differs from archived manifest")
        else:
            write_json(destination, manifest, replace=False)
        self._checkpoint("segment_manifest")
        for path in (self.path, self.transcript_path):
            if not path.exists():
                self._append(path, b"", create=True)
        self._fsync_dir(self.root)
        self._checkpoint("active_files")
        pointer = self.root / "audit.manifest.json"
        if pointer.exists():
            old = read_private(pointer, 8 * 1024 * 1024)
            if old != raw_manifest and hashlib.sha256(old).hexdigest() != manifest["parent_sha256"]:
                raise PolicyError("rotation manifest has an unexpected parent")
        elif manifest["parent_sha256"]:
            raise PolicyError("rotation parent manifest is missing")
        write_json(pointer, manifest)
        self._checkpoint("pointer")
        pending_path.unlink()
        self._checkpoint("pending_removed")
        self._fsync_dir(self.root)
        self._checkpoint("committed")

    @staticmethod
    def _append(path: Path, data: bytes, *, create: bool = False) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os,"O_NOFOLLOW",0)
        if create: flags |= os.O_EXCL
        fd = os.open(path, flags, 0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077: raise OSError("unsafe audit file")
            AuditWriter._write_all(fd, data); os.fsync(fd)
        finally: os.close(fd)

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view=memoryview(data)
        while view:
            wrote=os.write(fd,view)
            if wrote <= 0: raise OSError("short audit write")
            view=view[wrote:]

    def close(self) -> None:
        self._closed = True
        if getattr(self,"_lockfd",None) is not None:
            fcntl.flock(self._lockfd, fcntl.LOCK_UN); os.close(self._lockfd); self._lockfd = None


def verified_events(root: Path) -> list[dict]:
    """Read a complete, quiescent audit directory without initializing/recovering it."""
    root = private_directory(root)
    with exclusive(root / ".audit.lock"):
        reader = object.__new__(AuditWriter)
        reader.root = root
        reader.path, reader.transcript_path = root / "audit.jsonl", root / "transcript.log"
        reader.state_path = root / ".audit-state.json"
        reader.evidence_root, reader.segments_root = root / "evidence", root / "segments"
        reader.evidence_cap = 131072
        state = reader._read_state()
        reader.origin_id, reader._seq, reader._previous = state["origin_id"], state["seq"], state["tail"]
        if ((root / "rotation.pending.json").exists() or (root / ".audit-failure.json").exists() or
                any(root.glob(".reserve-*")) or not reader.verify().valid):
            raise PolicyError("offline source audit is incomplete or has invalid integrity")
        paths = [d / "audit.jsonl" for d in sorted(reader.segments_root.iterdir())] + [reader.path]
        events, size = [], 0
        for path in paths:
            raw = read_private(path, 128 * 1024 * 1024)
            size += len(raw)
            if size > 128 * 1024 * 1024:
                raise PolicyError("offline source audit exceeds merge allowance")
            events.extend(json.loads(line) for line in raw.splitlines())
        return events
