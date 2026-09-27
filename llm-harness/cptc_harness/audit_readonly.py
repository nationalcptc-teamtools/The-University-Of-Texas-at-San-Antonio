"""Pure read-only verification for one closed legacy profile audit action."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from .contracts import PolicyError, canonical_json
from .profile_runtime.contracts import ProfileContractError
from .profile_runtime.receipts import validate_persisted_profile_wire_receipt


_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_SEGMENT = re.compile(r"^[0-9]{20}-[0-9a-f]{16}$")

_AUDIT_CAP = 128 * 1024 * 1024
_MANIFEST_CAP = 8 * 1024 * 1024
_STATE_CAP = 64 * 1024
_EVIDENCE_CAP = 2 * 128 * 1024 + 4096
_RESULT_CAP = 8 * 1024 * 1024
_ENTRY_CAP = 4096

_ACTION_KINDS = (
    "profile_release_verified",
    "output_reserved",
    "operation_intent",
    "profile_wire_receipt",
    "operation_result",
    "result_record_intent",
    "result_record_written",
    "profile_cleanup_receipt",
)
_ACTION_HISTORY = _ACTION_KINDS[:3]
_WIRE_COUNTERS = (
    "capture_bytes",
    "protocol_requests",
    "rx_bytes",
    "tcp_connects",
    "tls_handshakes",
    "tx_bytes",
    "udp_datagrams",
)
_RESULT_USAGE = (
    "protocol_requests",
    "request_limit",
    "rx_bytes",
    "tcp_connects",
    "tx_bytes",
    "udp_datagrams",
)
_RESULT_REASON = "PortCast profile transport did not complete"


@dataclass(frozen=True, slots=True)
class ExpectedProfileContinuationIdentity:
    engagement_id: str
    device_id: str
    workspace_id: str
    operator_id: str
    policy_revision: str
    action_id: str
    plan_id: str
    plan_sha256: str
    action_sha256: str
    release_id: str
    release_manifest_sha256: str
    module_id: str
    module_source_sha256: str
    profile_id: str
    catalog_sha256: str
    profile_sha256: str
    operation_sha256: str
    runtime_pinset_sha256: str
    profile_worker_sha256: str
    broker_worker_sha256: str
    target_id: str
    target_sha256: str
    request_sha256: str
    output_bytes: int


@dataclass(frozen=True, slots=True)
class VerifiedProfileContinuationSnapshot:
    audit_chain_tail_sha256: str
    canonical_snapshot_sha256: str
    release_manifest_sha256: str
    predecessor_profile_worker_sha256: str
    predecessor_broker_worker_sha256: str
    action_history: tuple[str, ...]
    wire_outcome: str
    wire_counters: tuple[tuple[str, int], ...]
    wire_evidence_bytes: int
    wire_first_byte_present: bool
    cleanup_status: str
    result_record_sha256: str
    result_status: str
    result_usage: tuple[tuple[str, int], ...]
    result_evidence_count: int
    raw_failure_stage: str | None
    semantic_stage: str
    action_event_kinds: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ObjectIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(slots=True)
class _Capture:
    inventory: dict[str, tuple[_ObjectIdentity, str | None]]
    contents: dict[str, bytes]
    result: bytes


def _identity(info: os.stat_result) -> _ObjectIdentity:
    return _ObjectIdentity(
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _owner_only(info: os.stat_result, *, directory: bool) -> None:
    wanted = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    owner_access = 0o500 if directory else 0o400
    if (
        not wanted
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_mode & owner_access != owner_access
        or not directory
        and info.st_nlink != 1
    ):
        raise PolicyError("profile continuation storage permissions differ")


def _open_directory(path: Path) -> tuple[int, _ObjectIdentity]:
    exact = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        descriptor = os.open(os.path.sep, flags)
        for component in exact.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        _owner_only(info, directory=True)
        return descriptor, _identity(info)
    except Exception as exc:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("profile continuation directory is unavailable") from None


def _list_directory(descriptor: int, before: _ObjectIdentity) -> tuple[str, ...]:
    try:
        names = tuple(sorted(os.listdir(descriptor)))
        after = os.fstat(descriptor)
    except OSError:
        raise PolicyError("profile continuation directory read failed") from None
    if _identity(after) != before or len(names) > _ENTRY_CAP:
        raise PolicyError("profile continuation directory changed during read")
    return names


def _read_child_file(
    directory_fd: int,
    name: str,
    *,
    limit: int,
) -> tuple[bytes, _ObjectIdentity, str]:
    if not isinstance(name, str) or not name or "/" in name or name in {".", ".."}:
        raise PolicyError("profile continuation file name differs")
    try:
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(entry.st_mode):
            raise PolicyError("profile continuation storage contains a symlink")
        if not stat.S_ISREG(entry.st_mode):
            raise PolicyError("profile continuation storage contains a non-regular file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            before = os.fstat(descriptor)
            _owner_only(before, directory=False)
            if _identity(entry) != _identity(before) or before.st_size > limit:
                raise PolicyError("profile continuation file identity differs")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise PolicyError("profile continuation file exceeds its cap")
            after = os.fstat(descriptor)
            if _identity(after) != _identity(before) or total != before.st_size:
                raise PolicyError("profile continuation file changed during read")
            raw = b"".join(chunks)
            return raw, _identity(before), hashlib.sha256(raw).hexdigest()
        finally:
            os.close(descriptor)
    except PolicyError:
        raise
    except OSError:
        raise PolicyError("profile continuation file read failed") from None


def _open_child_directory(
    directory_fd: int, name: str
) -> tuple[int, _ObjectIdentity]:
    if not isinstance(name, str) or not name or "/" in name or name in {".", ".."}:
        raise PolicyError("profile continuation directory name differs")
    try:
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(entry.st_mode):
            raise PolicyError("profile continuation storage contains a symlink")
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        current = os.fstat(descriptor)
        _owner_only(current, directory=True)
        if _identity(entry) != _identity(current):
            raise PolicyError("profile continuation directory identity differs")
        return descriptor, _identity(current)
    except Exception as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("profile continuation directory read failed") from None


def _add_directory(
    inventory: dict[str, tuple[_ObjectIdentity, str | None]],
    key: str,
    identity: _ObjectIdentity,
) -> None:
    if key in inventory:
        raise PolicyError("profile continuation inventory contains a duplicate")
    inventory[key] = (identity, None)


def _add_file(
    inventory: dict[str, tuple[_ObjectIdentity, str | None]],
    contents: dict[str, bytes],
    key: str,
    value: tuple[bytes, _ObjectIdentity, str],
) -> None:
    if key in inventory:
        raise PolicyError("profile continuation inventory contains a duplicate")
    raw, identity, checksum = value
    inventory[key] = (identity, checksum)
    contents[key] = raw


def _capture_audit_tree(root: Path) -> tuple[dict[str, tuple[_ObjectIdentity, str | None]], dict[str, bytes]]:
    inventory: dict[str, tuple[_ObjectIdentity, str | None]] = {}
    contents: dict[str, bytes] = {}
    root_fd, root_identity = _open_directory(root)
    try:
        _add_directory(inventory, "audit/.", root_identity)
        names = _list_directory(root_fd, root_identity)
        required = {
            ".audit-state.json",
            ".audit.lock",
            "audit.jsonl",
            "transcript.log",
            "evidence",
            "segments",
        }
        allowed = required | {"audit.manifest.json"}
        if not required <= set(names) or set(names) - allowed:
            raise PolicyError("profile continuation audit layout differs")
        for name, limit in (
            (".audit-state.json", _STATE_CAP),
            (".audit.lock", 0),
            ("audit.jsonl", _AUDIT_CAP),
            ("transcript.log", _AUDIT_CAP),
        ):
            _add_file(
                inventory,
                contents,
                f"audit/{name}",
                _read_child_file(root_fd, name, limit=limit),
            )
        if "audit.manifest.json" in names:
            _add_file(
                inventory,
                contents,
                "audit/audit.manifest.json",
                _read_child_file(root_fd, "audit.manifest.json", limit=_MANIFEST_CAP),
            )

        evidence_fd, evidence_identity = _open_child_directory(root_fd, "evidence")
        try:
            _add_directory(inventory, "audit/evidence", evidence_identity)
            for name in _list_directory(evidence_fd, evidence_identity):
                _add_file(
                    inventory,
                    contents,
                    f"audit/evidence/{name}",
                    _read_child_file(evidence_fd, name, limit=_EVIDENCE_CAP),
                )
        finally:
            os.close(evidence_fd)

        segments_fd, segments_identity = _open_child_directory(root_fd, "segments")
        try:
            _add_directory(inventory, "audit/segments", segments_identity)
            for segment in _list_directory(segments_fd, segments_identity):
                if _SEGMENT.fullmatch(segment) is None:
                    raise PolicyError("profile continuation segment name differs")
                segment_fd, segment_identity = _open_child_directory(segments_fd, segment)
                try:
                    _add_directory(inventory, f"audit/segments/{segment}", segment_identity)
                    if set(_list_directory(segment_fd, segment_identity)) != {
                        "audit.jsonl",
                        "manifest.json",
                        "transcript.log",
                    }:
                        raise PolicyError("profile continuation segment layout differs")
                    for name, limit in (
                        ("audit.jsonl", _AUDIT_CAP),
                        ("manifest.json", _MANIFEST_CAP),
                        ("transcript.log", _AUDIT_CAP),
                    ):
                        _add_file(
                            inventory,
                            contents,
                            f"audit/segments/{segment}/{name}",
                            _read_child_file(segment_fd, name, limit=limit),
                        )
                    if _identity(os.fstat(segment_fd)) != segment_identity:
                        raise PolicyError("profile continuation segment changed during read")
                finally:
                    os.close(segment_fd)
            if _identity(os.fstat(segments_fd)) != segments_identity:
                raise PolicyError("profile continuation segments changed during read")
        finally:
            os.close(segments_fd)
        if _identity(os.fstat(root_fd)) != root_identity:
            raise PolicyError("profile continuation audit root changed during read")
    finally:
        os.close(root_fd)
    if len(inventory) > _ENTRY_CAP:
        raise PolicyError("profile continuation inventory exceeds its cap")
    return inventory, contents


def _capture_result(path: Path, expected_name: str) -> tuple[dict[str, tuple[_ObjectIdentity, str | None]], bytes]:
    exact = Path(os.path.abspath(os.fspath(path)))
    if exact.name != expected_name:
        raise PolicyError("profile continuation result locator differs")
    directory_fd, directory_identity = _open_directory(exact.parent)
    try:
        raw, file_identity, checksum = _read_child_file(
            directory_fd, exact.name, limit=_RESULT_CAP
        )
        if _identity(os.fstat(directory_fd)) != directory_identity:
            raise PolicyError("profile continuation result directory changed during read")
    finally:
        os.close(directory_fd)
    return {
        "result/.": (directory_identity, None),
        "result/file": (file_identity, checksum),
    }, raw


def _capture_inputs(
    audit_root: Path, result_path: Path, expected: ExpectedProfileContinuationIdentity
) -> _Capture:
    audit_inventory, contents = _capture_audit_tree(audit_root)
    result_inventory, result = _capture_result(
        result_path, f"{expected.action_id}.json"
    )
    return _Capture({**audit_inventory, **result_inventory}, contents, result)


def _json(raw: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    def constant(_value: str) -> None:
        raise ValueError("non-finite number")

    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise PolicyError(f"profile continuation {label} JSON differs") from None


def _canonical_document(raw: bytes, label: str) -> Any:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise PolicyError(f"profile continuation {label} checkpoint differs")
    value = _json(raw, label)
    if raw != canonical_json(value) + b"\n":
        raise PolicyError(f"profile continuation {label} encoding differs")
    return value


def _timestamp(value: Any) -> str:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise PolicyError("profile continuation timestamp differs")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise PolicyError("profile continuation timestamp differs") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise PolicyError("profile continuation timestamp differs")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise PolicyError(f"profile continuation {label} differs")
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise PolicyError(f"profile continuation {label} differs")
    return value


def _validate_expected(expected: Any) -> ExpectedProfileContinuationIdentity:
    if type(expected) is not ExpectedProfileContinuationIdentity:
        raise PolicyError("profile continuation expected identity is not frozen and typed")
    for field in (
        "engagement_id",
        "device_id",
        "workspace_id",
        "operator_id",
        "policy_revision",
        "action_id",
        "plan_id",
        "release_id",
        "module_id",
        "profile_id",
        "target_id",
    ):
        _identifier(getattr(expected, field), field.replace("_", " "))
    for field in (
        "plan_sha256",
        "action_sha256",
        "release_manifest_sha256",
        "module_source_sha256",
        "catalog_sha256",
        "profile_sha256",
        "operation_sha256",
        "runtime_pinset_sha256",
        "profile_worker_sha256",
        "broker_worker_sha256",
        "target_sha256",
        "request_sha256",
    ):
        _hash(getattr(expected, field), field.replace("_", " "))
    if expected.profile_worker_sha256 == expected.broker_worker_sha256:
        raise PolicyError("profile continuation worker digests must differ")
    if type(expected.output_bytes) is not int or not 0 <= expected.output_bytes <= 128 * 1024:
        raise PolicyError("profile continuation output allowance differs")
    return expected


def _render(record: dict[str, Any]) -> bytes:
    identity = {
        key: record[key]
        for key in (
            "engagement_id",
            "device_id",
            "workspace_id",
            "operator_id",
            "session_id",
            "action_id",
        )
    }
    identity["run_id"] = record["run_id"]
    return (
        f"{record['timestamp']} {record['seq']} "
        + json.dumps(record["kind"], ensure_ascii=True)
        + " "
        + json.dumps(identity, sort_keys=True, ensure_ascii=True)
        + " "
        + json.dumps(record["data"], sort_keys=True, ensure_ascii=True)
        + "\n"
    ).encode()


def _validate_event(
    record: Any,
    *,
    expected: ExpectedProfileContinuationIdentity,
    sequence: int,
    previous: str,
    event_ids: set[str],
) -> tuple[dict[str, Any], str]:
    fields = {
        "event_id",
        "seq",
        "timestamp",
        "monotonic_ns",
        "device_id",
        "workspace_id",
        "engagement_id",
        "policy_revision",
        "operator_id",
        "run_id",
        "session_id",
        "clock",
        "kind",
        "action_id",
        "classification",
        "data",
        "previous",
        "hash",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise PolicyError("profile continuation audit event shape differs")
    supplied = _hash(record["hash"], "event hash")
    unsigned = dict(record)
    unsigned.pop("hash")
    if (
        type(record["seq"]) is not int
        or record["seq"] != sequence
        or record["previous"] != previous
        or hashlib.sha256(canonical_json(unsigned)).hexdigest() != supplied
    ):
        raise PolicyError("profile continuation audit hash chain differs")
    event_id = record["event_id"]
    if type(event_id) is not str or _HEX32.fullmatch(event_id) is None or event_id in event_ids:
        raise PolicyError("profile continuation event identity differs")
    event_ids.add(event_id)
    _timestamp(record["timestamp"])
    if type(record["monotonic_ns"]) is not int or record["monotonic_ns"] < 0:
        raise PolicyError("profile continuation monotonic timestamp differs")
    for field in ("run_id", "session_id"):
        if type(record[field]) is not str or _HEX32.fullmatch(record[field]) is None:
            raise PolicyError("profile continuation execution identity differs")
    for field in (
        "engagement_id",
        "device_id",
        "workspace_id",
        "operator_id",
        "policy_revision",
    ):
        if record[field] != getattr(expected, field):
            raise PolicyError("profile continuation fixed audit identity differs")
    action_id = record["action_id"]
    if action_id is not None:
        _identifier(action_id, "event action")
    if (
        type(record["kind"]) is not str
        or not record["kind"]
        or len(record["kind"]) > 128
        or record["classification"]
        not in {
            "metadata",
            "public",
            "synthetic",
            "restricted_raw",
            "client_confidential",
            "client_confidential_human_only",
        }
        or not isinstance(record["data"], dict)
    ):
        raise PolicyError("profile continuation event metadata differs")
    clock = record["clock"]
    if (
        not isinstance(clock, dict)
        or set(clock) != {"synchronized", "offset_s", "source"}
        or clock["synchronized"] is not None
        and type(clock["synchronized"]) is not bool
        or clock["offset_s"] is not None
        and (isinstance(clock["offset_s"], bool) or not isinstance(clock["offset_s"], (int, float)))
        or type(clock["source"]) is not str
        or not 1 <= len(clock["source"]) <= 128
    ):
        raise PolicyError("profile continuation clock metadata differs")
    return record, supplied


def _evidence(
    record: dict[str, Any], contents: dict[str, bytes], known: dict[str, str]
) -> None:
    if record["kind"] != "evidence_capture":
        return
    data = record["data"]
    expected_data = {
        "evidence",
        "stored_bytes",
        "actual_sha256",
        "retained_bytes",
        "truncated",
        "stored_sha256",
        "incomplete_capture",
    }
    if not isinstance(data, dict) or set(data) != expected_data:
        raise PolicyError("profile continuation evidence event differs")
    reference = data["evidence"]
    reference_fields = {
        "evidence_id",
        "target_id",
        "check_id",
        "classification",
        "artifact_relpath",
        "sha256",
        "bytes",
    }
    if not isinstance(reference, dict) or set(reference) != reference_fields:
        raise PolicyError("profile continuation evidence reference differs")
    path = reference["artifact_relpath"]
    if type(path) is not str:
        raise PolicyError("profile continuation evidence locator differs")
    relative = PurePosixPath(path)
    if (
        relative.is_absolute()
        or len(relative.parts) != 2
        or relative.parts[0] != "evidence"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise PolicyError("profile continuation evidence locator differs")
    inventory_key = "audit/" + relative.as_posix()
    stored = contents.get(inventory_key)
    if stored is None or path in known:
        raise PolicyError("profile continuation evidence artifact differs")
    stored_hash = hashlib.sha256(stored).hexdigest()
    if (
        type(reference["evidence_id"]) is not str
        or _ID.fullmatch(reference["evidence_id"]) is None
        or reference["target_id"] is not None
        and (type(reference["target_id"]) is not str or _ID.fullmatch(reference["target_id"]) is None)
        or reference["check_id"] not in {
            "raw",
            "stdout",
            "stderr",
            "response",
            "response_metadata",
            "import",
            "tool_stdout",
            "tool_stderr",
        }
        or reference["classification"]
        not in {
            "public",
            "synthetic",
            "restricted_raw",
            "client_confidential",
            "client_confidential_human_only",
        }
        or _HEX64.fullmatch(reference["sha256"] or "") is None
        or type(reference["bytes"]) is not int
        or reference["bytes"] < 0
        or type(data["stored_bytes"]) is not int
        or data["stored_bytes"] != len(stored)
        or type(data["retained_bytes"]) is not int
        or data["retained_bytes"] != reference["bytes"]
        or data["truncated"] is not False
        or data["incomplete_capture"] is not False
        or _HEX64.fullmatch(data["actual_sha256"] or "") is None
        or data["actual_sha256"] != reference["sha256"]
        or data["stored_sha256"] != stored_hash
    ):
        raise PolicyError("profile continuation evidence integrity differs")
    known[path] = stored_hash


def _parse_events(
    capture: _Capture, expected: ExpectedProfileContinuationIdentity
) -> tuple[list[dict[str, Any]], dict[str, Any], tuple[str, ...]]:
    state = _canonical_document(capture.contents["audit/.audit-state.json"], "state")
    if (
        not isinstance(state, dict)
        or set(state) != {"origin_id", "seq", "tail"}
        or type(state["origin_id"]) is not str
        or _HEX32.fullmatch(state["origin_id"]) is None
        or type(state["seq"]) is not int
        or state["seq"] < 0
        or _HEX64.fullmatch(state["tail"] or "") is None
    ):
        raise PolicyError("profile continuation state differs")

    segment_names = sorted(
        key.split("/")[2]
        for key, value in capture.inventory.items()
        if key.startswith("audit/segments/")
        and key.count("/") == 2
        and value[1] is None
    )
    sources = [
        (
            f"audit/segments/{segment}/audit.jsonl",
            f"audit/segments/{segment}/transcript.log",
            f"audit/segments/{segment}/manifest.json",
            segment,
        )
        for segment in segment_names
    ]
    sources.append(("audit/audit.jsonl", "audit/transcript.log", None, None))
    events: list[dict[str, Any]] = []
    event_ids: set[str] = set()
    known: dict[str, str] = {}
    previous = "0" * 64
    parent_manifest = ""
    latest_manifest_raw: bytes | None = None
    manifest_hashes: list[str] = []

    for audit_key, transcript_key, manifest_key, segment in sources:
        audit_raw = capture.contents[audit_key]
        rendered = bytearray()
        if audit_raw and not audit_raw.endswith(b"\n"):
            raise PolicyError("profile continuation audit checkpoint is incomplete")
        for line in audit_raw.splitlines(keepends=True):
            if not line.endswith(b"\n"):
                raise PolicyError("profile continuation audit checkpoint is incomplete")
            record = _json(line[:-1], "event")
            if line != canonical_json(record) + b"\n":
                raise PolicyError("profile continuation event encoding differs")
            record, previous = _validate_event(
                record,
                expected=expected,
                sequence=len(events) + 1,
                previous=previous,
                event_ids=event_ids,
            )
            rendered.extend(_render(record))
            _evidence(record, capture.contents, known)
            events.append(record)
        if bytes(rendered) != capture.contents[transcript_key]:
            raise PolicyError("profile continuation transcript differs")
        if manifest_key is not None:
            manifest_raw = capture.contents[manifest_key]
            manifest = _canonical_document(manifest_raw, "manifest")
            fields = {
                "events",
                "audit_sha256",
                "transcript_sha256",
                "tail",
                "engagement",
                "origin_id",
                "policy_revision",
                "device_id",
                "artifacts",
                "segment",
                "parent_sha256",
                "sha256",
            }
            if not isinstance(manifest, dict) or set(manifest) != fields:
                raise PolicyError("profile continuation manifest shape differs")
            unsigned = dict(manifest)
            checksum = unsigned.pop("sha256")
            artifacts = [
                {"path": path, "sha256": checksum}
                for path, checksum in sorted(known.items())
            ]
            if (
                _HEX64.fullmatch(checksum or "") is None
                or hashlib.sha256(canonical_json(unsigned)).hexdigest() != checksum
                or manifest["events"] != len(events)
                or manifest["audit_sha256"] != hashlib.sha256(audit_raw).hexdigest()
                or manifest["transcript_sha256"]
                != hashlib.sha256(capture.contents[transcript_key]).hexdigest()
                or manifest["tail"] != previous
                or manifest["engagement"] != expected.engagement_id
                or manifest["origin_id"] != state["origin_id"]
                or manifest["policy_revision"] != expected.policy_revision
                or manifest["device_id"] != expected.device_id
                or manifest["artifacts"] != artifacts
                or manifest["segment"] != f"segments/{segment}"
                or segment != f"{len(events):020d}-{previous[:16]}"
                or manifest["parent_sha256"] != parent_manifest
            ):
                raise PolicyError("profile continuation manifest integrity differs")
            parent_manifest = hashlib.sha256(manifest_raw).hexdigest()
            latest_manifest_raw = manifest_raw
            manifest_hashes.append(parent_manifest)

    pointer = capture.contents.get("audit/audit.manifest.json")
    if (latest_manifest_raw is None) != (pointer is None) or (
        latest_manifest_raw is not None and pointer != latest_manifest_raw
    ):
        raise PolicyError("profile continuation manifest pointer differs")
    if state != {"origin_id": state["origin_id"], "seq": len(events), "tail": previous}:
        raise PolicyError("profile continuation audit state and chain differ")
    actual_artifacts = {
        key.removeprefix("audit/")
        for key, (_identity_value, checksum) in capture.inventory.items()
        if key.startswith("audit/evidence/") and checksum is not None
    }
    if actual_artifacts != set(known):
        raise PolicyError("profile continuation evidence inventory differs")
    return events, state, tuple(manifest_hashes)


def _verify_action(
    events: list[dict[str, Any]],
    result_raw: bytes,
    expected: ExpectedProfileContinuationIdentity,
) -> tuple[dict[str, Any], str, tuple[tuple[str, int], ...], tuple[tuple[str, int], ...]]:
    action_events = [event for event in events if event["action_id"] == expected.action_id]
    kinds = tuple(event["kind"] for event in action_events)
    if kinds != _ACTION_KINDS or any(
        event["classification"] != "metadata" for event in action_events
    ):
        raise PolicyError("profile continuation action event sequence differs")
    (
        release,
        reserved,
        intent,
        wire_event,
        operation_result,
        result_intent,
        result_written,
        cleanup,
    ) = action_events

    if release["data"] != {
        "release_id": expected.release_id,
        "manifest_sha256": expected.release_manifest_sha256,
    }:
        raise PolicyError("profile continuation release binding differs")
    if reserved["data"] != {"output_bytes": expected.output_bytes}:
        raise PolicyError("profile continuation output reservation differs")

    intent_data = intent["data"]
    intent_fields = {
        "module",
        "version",
        "target",
        "source_sha256",
        "args_hash",
        "validated_args",
        "bounds",
        "actor",
        "workflow_id",
        "approval_id",
        "parent_action_id",
        "remaining_budgets",
    }
    args = {"profile_id": expected.profile_id}
    action_commitment = hashlib.sha256(
        canonical_json(
            {
                "schema": "profile-continuation-legacy-action-v1",
                "plan_id": expected.plan_id,
                "plan_sha256": expected.plan_sha256,
                "release_id": expected.release_id,
                "release_manifest_sha256": expected.release_manifest_sha256,
                "module_id": expected.module_id,
                "module_source_sha256": expected.module_source_sha256,
                "profile_id": expected.profile_id,
                "catalog_sha256": expected.catalog_sha256,
                "profile_sha256": expected.profile_sha256,
                "operation_sha256": expected.operation_sha256,
                "runtime_pinset_sha256": expected.runtime_pinset_sha256,
                "profile_worker_sha256": expected.profile_worker_sha256,
                "broker_worker_sha256": expected.broker_worker_sha256,
                "target_id": expected.target_id,
                "target_sha256": expected.target_sha256,
                "request_sha256": expected.request_sha256,
                "output_bytes": expected.output_bytes,
                "operation_intent_sha256": hashlib.sha256(
                    canonical_json(intent_data)
                ).hexdigest(),
            }
        )
    ).hexdigest()
    if (
        not isinstance(intent_data, dict)
        or set(intent_data) != intent_fields
        or action_commitment != expected.action_sha256
        or intent_data["module"] != expected.module_id
        or intent_data["version"] != "1.0.0"
        or intent_data["target"] != expected.target_id
        or intent_data["source_sha256"] != expected.module_source_sha256
        or intent_data["args_hash"] != hashlib.sha256(canonical_json(args)).hexdigest()
        or intent_data["validated_args"] != args
        or not isinstance(intent_data["bounds"], dict)
        or intent_data["bounds"].get("output_bytes") != expected.output_bytes
        or intent_data["actor"] != "operator"
        or intent_data["workflow_id"] != expected.plan_id
        or intent_data["approval_id"] is not None
        or intent_data["parent_action_id"] is not None
        or intent_data["remaining_budgets"] != {}
    ):
        raise PolicyError("profile continuation action binding differs")

    wire_data = wire_event["data"]
    if not isinstance(wire_data, dict) or set(wire_data) != {"receipt", "receipt_sha256"}:
        raise PolicyError("profile continuation wire receipt shape differs")
    raw_receipt = wire_data["receipt"]
    if (
        not isinstance(raw_receipt, dict)
        or wire_data["receipt_sha256"]
        != hashlib.sha256(canonical_json(raw_receipt)).hexdigest()
    ):
        raise PolicyError("profile continuation wire receipt hash differs")
    try:
        receipt = validate_persisted_profile_wire_receipt(
            raw_receipt,
            expected_worker_sha256=expected.profile_worker_sha256,
        )
    except (ProfileContractError, PolicyError, TypeError, ValueError):
        raise PolicyError("profile continuation legacy wire receipt is invalid") from None
    expected_receipt = {
        "wave_id": expected.plan_id,
        "action_id": expected.action_id,
        "profile_id": expected.profile_id,
        "target_id": expected.target_id,
        "catalog_sha256": expected.catalog_sha256,
        "profile_sha256": expected.profile_sha256,
        "operation_sha256": expected.operation_sha256,
        "worker_sha256": expected.profile_worker_sha256,
        "runtime_pinset_sha256": expected.runtime_pinset_sha256,
    }
    if any(getattr(receipt, name) != value for name, value in expected_receipt.items()):
        raise PolicyError("profile continuation wire receipt binding differs")
    wire_counters = tuple(sorted(receipt.counters.as_dict().items()))
    if (
        receipt.schema_version != 1
        or receipt.outcome != "uncertain"
        or tuple(name for name, _value in wire_counters) != _WIRE_COUNTERS
        or any(type(value) is not int or value != 0 for _name, value in wire_counters)
        or receipt.first_byte_at is not None
        or receipt.evidence_bytes != 0
        or receipt.evidence_sha256 != hashlib.sha256(b"").hexdigest()
        or receipt.encrypted_artifact_id != "none"
        or receipt.limitations != ("transport_interrupted",)
    ):
        raise PolicyError("profile continuation legacy wire observations differ")

    if not isinstance(result_intent["data"], dict) or result_intent["data"] != {}:
        raise PolicyError("profile continuation result intent differs")
    record = _canonical_document(result_raw, "result")
    record_fields = {
        "version",
        "classification",
        "request",
        "result",
        "audit_sequence",
        "recorded_at",
    }
    if (
        not isinstance(record, dict)
        or set(record) != record_fields
        or record["version"] != 1
        or type(record["version"]) is not int
        or record["classification"] != "client_confidential"
        or record["audit_sequence"] != result_intent["seq"]
        or record["recorded_at"] != result_intent["timestamp"]
    ):
        raise PolicyError("profile continuation result record metadata differs")
    _timestamp(record["recorded_at"])

    request = record["request"]
    request_fields = {
        "request_id",
        "workspace_id",
        "device_id",
        "operator_id",
        "module_id",
        "target",
        "args",
        "source",
        "approval_id",
        "policy_revision",
        "workflow_id",
        "parent_action_id",
    }
    target = request.get("target") if isinstance(request, dict) else None
    if (
        not isinstance(request, dict)
        or set(request) != request_fields
        or hashlib.sha256(canonical_json(request)).hexdigest() != expected.request_sha256
        or request["request_id"] != expected.action_id
        or request["workspace_id"] != expected.workspace_id
        or request["device_id"] != expected.device_id
        or request["operator_id"] != expected.operator_id
        or request["module_id"] != expected.module_id
        or request["args"] != args
        or request["source"] != "operator"
        or request["approval_id"] is not None
        or request["policy_revision"] != expected.policy_revision
        or request["workflow_id"] != expected.plan_id
        or request["parent_action_id"] is not None
        or not isinstance(target, dict)
        or target.get("target_id") != expected.target_id
        or hashlib.sha256(canonical_json(target)).hexdigest() != expected.target_sha256
    ):
        raise PolicyError("profile continuation result request binding differs")

    result = record["result"]
    result_fields = {"status", "facts", "evidence", "reason", "usage"}
    usage = result.get("usage") if isinstance(result, dict) else None
    result_usage = tuple(sorted(usage.items())) if isinstance(usage, dict) else ()
    if (
        not isinstance(result, dict)
        or set(result) != result_fields
        or result["status"] != "uncertain"
        or result["facts"] != {}
        or result["evidence"] != []
        or result["reason"] != _RESULT_REASON
        or tuple(name for name, _value in result_usage) != _RESULT_USAGE
        or any(type(value) is not int or value != 0 for _name, value in result_usage)
    ):
        raise PolicyError("profile continuation legacy result observations differ")
    if operation_result["data"] != {
        "status": result["status"],
        "reason": result["reason"],
        "usage": result["usage"],
        "evidence": [],
    }:
        raise PolicyError("profile continuation audit result differs")

    result_hash = hashlib.sha256(canonical_json(record)).hexdigest()
    if result_written["data"] != {
        "record_sha256": result_hash,
        "source": "operator",
        "status": "uncertain",
    }:
        raise PolicyError("profile continuation result receipt differs")
    if cleanup["data"] != {
        "all_resources_closed": True,
        "automatic_retry": False,
        "status": "passed",
    }:
        raise PolicyError("profile continuation cleanup receipt differs")
    return record, result_hash, wire_counters, result_usage


def _verified_snapshot(
    capture: _Capture, expected: ExpectedProfileContinuationIdentity
) -> VerifiedProfileContinuationSnapshot:
    events, state, manifest_hashes = _parse_events(capture, expected)
    record, result_hash, wire_counters, result_usage = _verify_action(
        events, capture.result, expected
    )
    safe_fields = {
        "audit_chain_tail_sha256": state["tail"],
        "release_manifest_sha256": expected.release_manifest_sha256,
        "predecessor_profile_worker_sha256": expected.profile_worker_sha256,
        "predecessor_broker_worker_sha256": expected.broker_worker_sha256,
        "action_history": list(_ACTION_HISTORY),
        "wire_outcome": "uncertain",
        "wire_counters": [list(item) for item in wire_counters],
        "wire_evidence_bytes": 0,
        "wire_first_byte_present": False,
        "cleanup_status": "passed",
        "result_record_sha256": result_hash,
        "result_status": "uncertain",
        "result_usage": [list(item) for item in result_usage],
        "result_evidence_count": len(record["result"]["evidence"]),
        "raw_failure_stage": None,
        "semantic_stage": "legacy_target_open_unacknowledged",
        "action_event_kinds": list(_ACTION_KINDS),
    }
    canonical_snapshot = hashlib.sha256(
        canonical_json(
            {
                "schema": "profile-continuation-audit-snapshot-v1",
                "expected_identity_sha256": hashlib.sha256(
                    canonical_json(asdict(expected))
                ).hexdigest(),
                "origin_id": state["origin_id"],
                "event_hashes": [event["hash"] for event in events],
                "manifest_hashes": list(manifest_hashes),
                "verified": safe_fields,
            }
        )
    ).hexdigest()
    return VerifiedProfileContinuationSnapshot(
        canonical_snapshot_sha256=canonical_snapshot,
        action_history=_ACTION_HISTORY,
        wire_counters=wire_counters,
        result_usage=result_usage,
        action_event_kinds=_ACTION_KINDS,
        **{
            key: value
            for key, value in safe_fields.items()
            if key
            not in {
                "action_history",
                "wire_counters",
                "result_usage",
                "action_event_kinds",
            }
        },
    )


def verify_profile_continuation_snapshot(
    audit_root: Path,
    result_path: Path,
    expected: ExpectedProfileContinuationIdentity,
) -> VerifiedProfileContinuationSnapshot:
    """Return a frozen metadata proof without locking, probing, or writing."""

    exact_expected = _validate_expected(expected)
    try:
        before = _capture_inputs(Path(audit_root), Path(result_path), exact_expected)
        snapshot = _verified_snapshot(before, exact_expected)
        after = _capture_inputs(Path(audit_root), Path(result_path), exact_expected)
        if before.inventory != after.inventory:
            raise PolicyError("profile continuation inputs changed during read")
        return snapshot
    except PolicyError:
        raise
    except (KeyError, TypeError, ValueError, OSError, OverflowError):
        raise PolicyError("profile continuation snapshot verification failed") from None


__all__ = (
    "ExpectedProfileContinuationIdentity",
    "VerifiedProfileContinuationSnapshot",
    "verify_profile_continuation_snapshot",
)
