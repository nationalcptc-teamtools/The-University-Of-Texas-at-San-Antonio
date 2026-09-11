from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from cptc_harness.audit import AuditWriter
from cptc_harness.audit_readonly import (
    ExpectedProfileContinuationIdentity,
    VerifiedProfileContinuationSnapshot,
    verify_profile_continuation_snapshot,
)
from cptc_harness.contracts import (
    AuditEvent,
    PolicyError,
    PolicySnapshot,
    ScopeSpec,
    canonical_json,
)
from cptc_harness.profile_runtime.catalog import load_profile


ACTION_ID = "legacy-action-v2"
PLAN_ID = "legacy-plan-v2"
PROFILE_ID = "web.http_jellyfin_public_identity"
TARGET_ID = "cptc11-prod-portcast"
MODULE_ID = "web.portcast_identity"
PROFILE_WORKER_SHA256 = "4" * 64
BROKER_WORKER_SHA256 = "5" * 64
RELEASE_SHA256 = "6" * 64
PLAN_SHA256 = "7" * 64
MODULE_SHA256 = "8" * 64
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
ZERO_COUNTERS = {
    "tcp_connects": 0,
    "udp_datagrams": 0,
    "tls_handshakes": 0,
    "protocol_requests": 0,
    "tx_bytes": 0,
    "rx_bytes": 0,
    "capture_bytes": 0,
}
ZERO_USAGE = {
    "request_limit": 0,
    "tcp_connects": 0,
    "udp_datagrams": 0,
    "protocol_requests": 0,
    "tx_bytes": 0,
    "rx_bytes": 0,
}
ACTION_KINDS = (
    "profile_release_verified",
    "output_reserved",
    "operation_intent",
    "profile_wire_receipt",
    "operation_result",
    "result_record_intent",
    "result_record_written",
    "profile_cleanup_receipt",
)


@dataclass(frozen=True)
class Fixture:
    audit_root: Path
    result_path: Path
    expected: ExpectedProfileContinuationIdentity


def _policy() -> PolicySnapshot:
    return PolicySnapshot(
        "engagement-v2",
        "policy-v2",
        "workspace-v2",
        "device-v2",
        "operator-v2",
        ScopeSpec(),
        encrypted_storage=True,
    )


def _target() -> dict[str, object]:
    return {
        "target_id": TARGET_ID,
        "canonical_url": "http://10.0.1.30:8096/System/Info/Public",
        "scheme": "http",
        "host": "10.0.1.30",
        "port": 8096,
        "base_path": "/System/Info/Public",
    }


def _request() -> dict[str, object]:
    policy = _policy()
    return {
        "request_id": ACTION_ID,
        "workspace_id": policy.workspace_id,
        "device_id": policy.device_id,
        "operator_id": policy.operator_id,
        "module_id": MODULE_ID,
        "target": _target(),
        "args": {"profile_id": PROFILE_ID},
        "source": "operator",
        "approval_id": None,
        "policy_revision": policy.revision,
        "workflow_id": PLAN_ID,
        "parent_action_id": None,
    }


def _intent() -> dict[str, object]:
    args = {"profile_id": PROFILE_ID}
    return {
        "module": MODULE_ID,
        "version": "1.0.0",
        "target": TARGET_ID,
        "source_sha256": MODULE_SHA256,
        "args_hash": hashlib.sha256(canonical_json(args)).hexdigest(),
        "validated_args": args,
        "bounds": {
            "timeout_s": 10.0,
            "request_limit": 1,
            "output_bytes": 16384,
            "process_limit": 1,
            "model_calls": 0,
            "actions": 0,
            "auth_posts": 0,
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "protocol_requests": 1,
            "tx_bytes": 256,
            "rx_bytes": 8192,
        },
        "actor": "operator",
        "workflow_id": PLAN_ID,
        "approval_id": None,
        "parent_action_id": None,
        "remaining_budgets": {},
    }


def _action_sha256() -> str:
    profile = load_profile(PROFILE_ID)
    return hashlib.sha256(
        canonical_json(
            {
                "schema": "profile-continuation-legacy-action-v1",
                "plan_id": PLAN_ID,
                "plan_sha256": PLAN_SHA256,
                "release_id": "portcast-live-v1",
                "release_manifest_sha256": RELEASE_SHA256,
                "module_id": MODULE_ID,
                "module_source_sha256": MODULE_SHA256,
                "profile_id": PROFILE_ID,
                "catalog_sha256": profile.catalog_sha256,
                "profile_sha256": profile.profile_sha256,
                "operation_sha256": profile.operation.sha256,
                "runtime_pinset_sha256": profile.runtime_pinset_sha256,
                "profile_worker_sha256": PROFILE_WORKER_SHA256,
                "broker_worker_sha256": BROKER_WORKER_SHA256,
                "target_id": TARGET_ID,
                "target_sha256": hashlib.sha256(canonical_json(_target())).hexdigest(),
                "request_sha256": hashlib.sha256(canonical_json(_request())).hexdigest(),
                "output_bytes": 16384,
                "operation_intent_sha256": hashlib.sha256(
                    canonical_json(_intent())
                ).hexdigest(),
            }
        )
    ).hexdigest()


def _wire_receipt(**changes: object) -> dict[str, object]:
    profile = load_profile(PROFILE_ID)
    value: dict[str, object] = {
        "schema_version": 1,
        "wave_id": PLAN_ID,
        "action_id": ACTION_ID,
        "profile_id": PROFILE_ID,
        "target_id": TARGET_ID,
        "catalog_sha256": profile.catalog_sha256,
        "profile_sha256": profile.profile_sha256,
        "operation_sha256": profile.operation.sha256,
        "worker_sha256": PROFILE_WORKER_SHA256,
        "runtime_pinset_sha256": profile.runtime_pinset_sha256,
        "started_at": "2026-09-10T12:00:00.000001Z",
        "first_byte_at": None,
        "completed_at": "2026-09-10T12:00:00.000002Z",
        "outcome": "uncertain",
        "counters": dict(ZERO_COUNTERS),
        "evidence_sha256": EMPTY_SHA256,
        "evidence_bytes": 0,
        "encrypted_artifact_id": "none",
        "limitations": ["transport_interrupted"],
    }
    value.update(changes)
    return value


def _wire_event_data(receipt: dict[str, object]) -> dict[str, object]:
    return {
        "receipt": receipt,
        "receipt_sha256": hashlib.sha256(canonical_json(receipt)).hexdigest(),
    }


def _result() -> dict[str, object]:
    return {
        "status": "uncertain",
        "facts": {},
        "evidence": [],
        "reason": "PortCast profile transport did not complete",
        "usage": dict(ZERO_USAGE),
    }


def _expected() -> ExpectedProfileContinuationIdentity:
    policy = _policy()
    profile = load_profile(PROFILE_ID)
    return ExpectedProfileContinuationIdentity(
        engagement_id=policy.engagement_id,
        device_id=policy.device_id,
        workspace_id=policy.workspace_id,
        operator_id=policy.operator_id,
        policy_revision=policy.revision,
        action_id=ACTION_ID,
        plan_id=PLAN_ID,
        plan_sha256=PLAN_SHA256,
        action_sha256=_action_sha256(),
        release_id="portcast-live-v1",
        release_manifest_sha256=RELEASE_SHA256,
        module_id=MODULE_ID,
        module_source_sha256=MODULE_SHA256,
        profile_id=PROFILE_ID,
        catalog_sha256=profile.catalog_sha256,
        profile_sha256=profile.profile_sha256,
        operation_sha256=profile.operation.sha256,
        runtime_pinset_sha256=profile.runtime_pinset_sha256,
        profile_worker_sha256=PROFILE_WORKER_SHA256,
        broker_worker_sha256=BROKER_WORKER_SHA256,
        target_id=TARGET_ID,
        target_sha256=hashlib.sha256(canonical_json(_target())).hexdigest(),
        request_sha256=hashlib.sha256(canonical_json(_request())).hexdigest(),
        output_bytes=16384,
    )


def _build_fixture(
    tmp_path: Path,
    *,
    kinds: tuple[str, ...] = ACTION_KINDS,
    receipt: dict[str, object] | None = None,
    result_mutation=None,
    record_mutation=None,
    rotate: bool = True,
) -> Fixture:
    audit_root = tmp_path / "runtime" / "audit"
    results_root = tmp_path / "runtime" / "results"
    results_root.mkdir(parents=True, mode=0o700)
    results_root.chmod(0o700)
    writer = AuditWriter(
        audit_root,
        _policy(),
        encrypted_volume_verified=True,
        profile_worker_sha256=PROFILE_WORKER_SHA256,
        compatible_profile_workers=(PROFILE_WORKER_SHA256,),
    )
    receipt = receipt or _wire_receipt()
    result = _result()
    if result_mutation is not None:
        result_mutation(result)
    request = _request()
    result_path = results_root / f"{ACTION_ID}.json"
    result_record = None
    output_reserved = False
    for kind in kinds:
        if kind == "profile_release_verified":
            writer.emit(
                AuditEvent(
                    kind,
                    ACTION_ID,
                    {
                        "release_id": "portcast-live-v1",
                        "manifest_sha256": RELEASE_SHA256,
                    },
                )
            )
        elif kind == "output_reserved":
            if output_reserved:
                writer.emit(AuditEvent(kind, ACTION_ID, {"output_bytes": 16384}))
            else:
                writer.reserve_output(ACTION_ID, 16384)
                output_reserved = True
        elif kind == "operation_intent":
            writer.emit(AuditEvent(kind, ACTION_ID, _intent()))
        elif kind == "profile_wire_receipt":
            if receipt == _wire_receipt() and kind not in kinds[: kinds.index(kind)]:
                writer.record_profile_wire_receipt(receipt)
            else:
                writer.emit(AuditEvent(kind, ACTION_ID, _wire_event_data(receipt)))
        elif kind == "profile_wire_failure_stage":
            writer.emit(
                AuditEvent(
                    kind,
                    ACTION_ID,
                    {"stage": "target_open", "automatic_retry": False},
                )
            )
        elif kind == "operation_result":
            writer.emit(
                AuditEvent(
                    kind,
                    ACTION_ID,
                    {
                        "status": result["status"],
                        "reason": result["reason"],
                        "usage": result["usage"],
                        "evidence": [],
                    },
                )
            )
            if output_reserved:
                writer.release_output(ACTION_ID)
                output_reserved = False
        elif kind == "result_record_intent":
            event = writer.emit(AuditEvent(kind, ACTION_ID))
            result_record = {
                "version": 1,
                "classification": "client_confidential",
                "request": request,
                "result": result,
                "audit_sequence": event["seq"],
                "recorded_at": event["timestamp"],
            }
            if record_mutation is not None:
                record_mutation(result_record)
            result_path.write_bytes(canonical_json(result_record) + b"\n")
            result_path.chmod(0o600)
        elif kind == "result_record_written":
            if result_record is None:
                writer.emit(
                    AuditEvent(
                        kind,
                        ACTION_ID,
                        {
                            "record_sha256": "f" * 64,
                            "source": "operator",
                            "status": "uncertain",
                        },
                    )
                )
            else:
                writer.emit(
                    AuditEvent(
                        kind,
                        ACTION_ID,
                        {
                            "record_sha256": hashlib.sha256(
                                canonical_json(result_record)
                            ).hexdigest(),
                            "source": "operator",
                            "status": result["status"],
                        },
                    )
                )
        elif kind == "profile_cleanup_receipt":
            writer.emit(
                AuditEvent(
                    kind,
                    ACTION_ID,
                    {
                        "all_resources_closed": True,
                        "automatic_retry": False,
                        "status": "passed",
                    },
                )
            )
        else:
            writer.emit(AuditEvent(kind, ACTION_ID, {}))
    if output_reserved:
        writer.release_output(ACTION_ID)
    if rotate:
        writer.rotate()
    writer.close()
    return Fixture(audit_root, result_path, _expected())


def _filesystem_snapshot(fixture: Fixture) -> dict[str, tuple[object, ...]]:
    roots = (fixture.audit_root, fixture.result_path.parent)
    paths = []
    for root in roots:
        paths.append(root)
        paths.extend(sorted(root.rglob("*")))
    captured = {}
    for path in paths:
        info = path.lstat()
        captured[str(path)] = (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest()
            if stat.S_ISREG(info.st_mode)
            else None,
        )
    return captured


def _verify(fixture: Fixture) -> VerifiedProfileContinuationSnapshot:
    return verify_profile_continuation_snapshot(
        fixture.audit_root, fixture.result_path, fixture.expected
    )


def _rechain_active(fixture: Fixture, mutate) -> None:
    audit_path = fixture.audit_root / "audit.jsonl"
    events = [json.loads(line) for line in audit_path.read_bytes().splitlines()]
    mutate(events)
    previous = "0" * 64
    for sequence, event in enumerate(events, 1):
        event["seq"] = sequence
        event["previous"] = previous
        unsigned = dict(event)
        unsigned.pop("hash", None)
        event["hash"] = hashlib.sha256(canonical_json(unsigned)).hexdigest()
        previous = event["hash"]
    audit_path.write_bytes(b"".join(canonical_json(event) + b"\n" for event in events))
    (fixture.audit_root / "transcript.log").write_bytes(
        b"".join(AuditWriter._render(event) for event in events)
    )
    (fixture.audit_root / ".audit-state.json").write_bytes(
        canonical_json(
            {
                "origin_id": json.loads(
                    (fixture.audit_root / ".audit-state.json").read_bytes()
                )["origin_id"],
                "seq": len(events),
                "tail": previous,
            }
        )
        + b"\n"
    )


def test_valid_legacy_snapshot_is_frozen_metadata_only_and_makes_no_writes(
    tmp_path, monkeypatch
):
    fixture = _build_fixture(tmp_path)
    before = _filesystem_snapshot(fixture)
    import cptc_harness.audit_readonly as readonly

    real_open = readonly.os.open

    def read_only_open(path, flags, *args, **kwargs):
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        assert flags & write_flags == 0
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(readonly.os, "open", read_only_open)
    snapshot = _verify(fixture)

    assert _filesystem_snapshot(fixture) == before
    assert snapshot.action_history == ACTION_KINDS[:3]
    assert snapshot.action_event_kinds == ACTION_KINDS
    assert snapshot.wire_outcome == "uncertain"
    assert dict(snapshot.wire_counters) == ZERO_COUNTERS
    assert snapshot.wire_evidence_bytes == 0
    assert snapshot.wire_first_byte_present is False
    assert snapshot.cleanup_status == "passed"
    assert snapshot.result_status == "uncertain"
    assert dict(snapshot.result_usage) == ZERO_USAGE
    assert snapshot.result_evidence_count == 0
    assert snapshot.raw_failure_stage is None
    assert snapshot.semantic_stage == "legacy_target_open_unacknowledged"
    assert snapshot.release_manifest_sha256 == RELEASE_SHA256
    assert snapshot.predecessor_profile_worker_sha256 == PROFILE_WORKER_SHA256
    assert snapshot.predecessor_broker_worker_sha256 == BROKER_WORKER_SHA256
    assert len(snapshot.audit_chain_tail_sha256) == 64
    assert len(snapshot.canonical_snapshot_sha256) == 64
    assert len(snapshot.result_record_sha256) == 64
    assert not any(
        word in field
        for field in snapshot.__dataclass_fields__
        for word in ("path", "reason", "target", "command", "header", "prose", "bytes_data")
    )
    with pytest.raises(FrozenInstanceError):
        snapshot.cleanup_status = "failed"


@pytest.mark.parametrize(
    "field",
    (
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
    ),
)
def test_expected_identity_mismatch_is_rejected(tmp_path, field):
    fixture = _build_fixture(tmp_path)
    value = "other-valid-id"
    with pytest.raises(PolicyError):
        verify_profile_continuation_snapshot(
            fixture.audit_root,
            fixture.result_path,
            replace(fixture.expected, **{field: value}),
        )


@pytest.mark.parametrize(
    "field",
    (
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
    ),
)
def test_expected_hash_mismatch_is_rejected(tmp_path, field):
    fixture = _build_fixture(tmp_path)
    with pytest.raises(PolicyError):
        verify_profile_continuation_snapshot(
            fixture.audit_root,
            fixture.result_path,
            replace(fixture.expected, **{field: "a" * 64}),
        )


@pytest.mark.parametrize(
    "kinds",
    (
        ACTION_KINDS[1:],
        ACTION_KINDS[:-1],
        ACTION_KINDS[:2] + ACTION_KINDS[3:],
        ACTION_KINDS[:2] + ("operation_intent",) + ACTION_KINDS[2:],
        (ACTION_KINDS[1], ACTION_KINDS[0]) + ACTION_KINDS[2:],
        ACTION_KINDS[:4] + ("profile_wire_failure_stage",) + ACTION_KINDS[4:],
        ACTION_KINDS[:4] + ("operator_stop",) + ACTION_KINDS[4:],
    ),
)
def test_missing_duplicate_out_of_order_later_stage_and_extra_action_events_fail(
    tmp_path, kinds
):
    fixture = _build_fixture(tmp_path, kinds=kinds, rotate=False)
    with pytest.raises(PolicyError):
        _verify(fixture)


@pytest.mark.parametrize("counter", tuple(ZERO_COUNTERS))
def test_nonzero_wire_counter_is_rejected(tmp_path, counter):
    counters = dict(ZERO_COUNTERS)
    counters[counter] = 1
    fixture = _build_fixture(
        tmp_path, receipt=_wire_receipt(counters=counters), rotate=False
    )
    with pytest.raises(PolicyError):
        _verify(fixture)


def test_first_byte_or_evidence_in_legacy_receipt_is_rejected(tmp_path):
    fixture = _build_fixture(
        tmp_path,
        receipt=_wire_receipt(first_byte_at="2026-09-10T12:00:00.000001Z"),
        rotate=False,
    )
    with pytest.raises(PolicyError):
        _verify(fixture)


@pytest.mark.parametrize("counter", tuple(ZERO_USAGE))
def test_nonzero_result_counter_is_rejected(tmp_path, counter):
    def mutate(result):
        result["usage"][counter] = 1

    fixture = _build_fixture(tmp_path, result_mutation=mutate, rotate=False)
    with pytest.raises(PolicyError):
        _verify(fixture)


def test_result_requires_client_confidential_exact_request_and_complete_receipt(tmp_path):
    fixture = _build_fixture(
        tmp_path,
        record_mutation=lambda record: record.update(classification="public"),
        rotate=False,
    )
    with pytest.raises(PolicyError):
        _verify(fixture)

    wrong_request = _build_fixture(
        tmp_path / "request",
        record_mutation=lambda record: record["request"].update(module_id="other-module"),
        rotate=False,
    )
    with pytest.raises(PolicyError):
        _verify(wrong_request)

    missing_written = _build_fixture(
        tmp_path / "missing", kinds=ACTION_KINDS[:-2] + ACTION_KINDS[-1:], rotate=False
    )
    with pytest.raises(PolicyError):
        _verify(missing_written)


@pytest.mark.parametrize("mutation", ("audit", "transcript", "state", "pointer"))
def test_audit_tampering_transcript_state_and_pointer_mismatch_fail(tmp_path, mutation):
    fixture = _build_fixture(tmp_path)
    if mutation == "audit":
        segment = next((fixture.audit_root / "segments").iterdir())
        path = segment / "audit.jsonl"
        path.write_bytes(path.read_bytes().replace(b'"operator-v2"', b'"operator-v3"', 1))
    elif mutation == "transcript":
        segment = next((fixture.audit_root / "segments").iterdir())
        path = segment / "transcript.log"
        path.write_bytes(path.read_bytes() + b"x")
    elif mutation == "state":
        path = fixture.audit_root / ".audit-state.json"
        value = json.loads(path.read_bytes())
        value["seq"] += 1
        path.write_bytes(canonical_json(value) + b"\n")
    else:
        path = fixture.audit_root / "audit.manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(PolicyError):
        _verify(fixture)


def test_renamed_segment_with_resealed_manifest_is_rejected(tmp_path):
    fixture = _build_fixture(tmp_path)
    segments = fixture.audit_root / "segments"
    original = next(segments.iterdir())
    renamed = segments / "00000000000000000008-0000000000000000"
    original.rename(renamed)
    manifest_path = renamed / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["segment"] = f"segments/{renamed.name}"
    unsigned = dict(manifest)
    unsigned.pop("sha256")
    manifest["sha256"] = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    raw = canonical_json(manifest) + b"\n"
    manifest_path.write_bytes(raw)
    (fixture.audit_root / "audit.manifest.json").write_bytes(raw)

    with pytest.raises(PolicyError):
        _verify(fixture)


@pytest.mark.parametrize("mutation", ("timestamp", "event_id"))
def test_chain_valid_non_microsecond_timestamp_and_duplicate_event_id_fail(
    tmp_path, mutation
):
    fixture = _build_fixture(tmp_path, rotate=False)
    if mutation == "timestamp":
        _rechain_active(
            fixture,
            lambda events: events[0].update(timestamp="2026-09-10T12:00:00Z"),
        )
    else:
        _rechain_active(
            fixture,
            lambda events: events[1].update(event_id=events[0]["event_id"]),
        )
    with pytest.raises(PolicyError):
        _verify(fixture)


@pytest.mark.parametrize("target", ("file", "directory"))
def test_symlinks_and_non_owner_permissions_are_rejected(tmp_path, target):
    fixture = _build_fixture(tmp_path, rotate=False)
    if target == "file":
        transcript = fixture.audit_root / "transcript.log"
        saved = tmp_path / "saved-transcript"
        transcript.rename(saved)
        transcript.symlink_to(saved)
    else:
        fixture.audit_root.chmod(0o755)
    with pytest.raises(PolicyError):
        _verify(fixture)


def test_group_readable_audit_file_is_rejected(tmp_path):
    fixture = _build_fixture(tmp_path, rotate=False)
    (fixture.audit_root / "audit.jsonl").chmod(0o640)
    with pytest.raises(PolicyError):
        _verify(fixture)


def test_fifo_is_rejected_as_non_regular_before_open(tmp_path, monkeypatch):
    fixture = _build_fixture(tmp_path, rotate=False)
    transcript = fixture.audit_root / "transcript.log"
    transcript.unlink()
    os.mkfifo(transcript, mode=0o600)
    import cptc_harness.audit_readonly as readonly

    real_open = readonly.os.open
    fifo_open_attempted = False

    def reject_fifo_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal fifo_open_attempted
        if path == "transcript.log":
            fifo_open_attempted = True
            raise AssertionError("FIFO must be rejected before open")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(readonly.os, "open", reject_fifo_open)

    with pytest.raises(PolicyError):
        _verify(fixture)
    assert fifo_open_attempted is False


def test_fifo_swap_after_prestat_cannot_block_open(tmp_path, monkeypatch):
    fixture = _build_fixture(tmp_path, rotate=False)
    transcript = fixture.audit_root / "transcript.log"
    import cptc_harness.audit_readonly as readonly

    real_stat = readonly.os.stat
    real_open = readonly.os.open
    swapped = False

    def swap_after_stat(path, *args, **kwargs):
        nonlocal swapped
        info = real_stat(path, *args, **kwargs)
        if path == "transcript.log" and not swapped:
            transcript.unlink()
            os.mkfifo(transcript, mode=0o600)
            swapped = True
        return info

    def require_nonblocking_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == "transcript.log":
            assert flags & os.O_NONBLOCK
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(readonly.os, "stat", swap_after_stat)
    monkeypatch.setattr(readonly.os, "open", require_nonblocking_open)

    with pytest.raises(PolicyError):
        _verify(fixture)
    assert swapped is True


def test_audit_verifier_requires_distinct_profile_and_broker_workers(tmp_path):
    expected = replace(
        _expected(),
        broker_worker_sha256=PROFILE_WORKER_SHA256,
    )

    with pytest.raises(PolicyError, match="worker digests must differ"):
        verify_profile_continuation_snapshot(
            tmp_path / "unused-audit",
            tmp_path / "unused-result",
            expected,
        )


def test_symlinked_parent_component_is_rejected(tmp_path):
    fixture = _build_fixture(tmp_path / "real", rotate=False)
    alias = tmp_path / "alias"
    alias.symlink_to(fixture.audit_root.parent, target_is_directory=True)
    with pytest.raises(PolicyError):
        verify_profile_continuation_snapshot(
            alias / "audit", alias / "results" / fixture.result_path.name, fixture.expected
        )


def test_orphan_and_missing_evidence_artifacts_are_rejected(tmp_path):
    orphan = _build_fixture(tmp_path / "orphan", rotate=False)
    artifact = orphan.audit_root / "evidence" / "orphan.age"
    artifact.write_bytes(b"orphan")
    artifact.chmod(0o600)
    with pytest.raises(PolicyError):
        _verify(orphan)

    missing = _build_fixture(tmp_path / "missing", rotate=False)
    writer = AuditWriter(
        missing.audit_root,
        _policy(),
        encrypted_volume_verified=True,
        profile_worker_sha256=PROFILE_WORKER_SHA256,
        compatible_profile_workers=(PROFILE_WORKER_SHA256,),
    )
    ref = writer.capture("foreign-action", "raw", b"foreign", "synthetic")
    writer.close()
    (missing.audit_root / ref.artifact_relpath).unlink()
    with pytest.raises(PolicyError):
        _verify(missing)


def test_mutation_during_read_is_detected(tmp_path, monkeypatch):
    fixture = _build_fixture(tmp_path)
    import cptc_harness.audit_readonly as readonly

    real_read = readonly.os.read
    changed = False

    def mutating_read(fd, size):
        nonlocal changed
        value = real_read(fd, size)
        if not changed and os.fstat(fd).st_size == 0:
            changed = True
            lock = fixture.audit_root / ".audit.lock"
            lock.write_bytes(b"changed-by-concurrent-writer")
            lock.chmod(0o600)
        return value

    monkeypatch.setattr(readonly.os, "read", mutating_read)
    with pytest.raises(PolicyError):
        _verify(fixture)
    assert changed is True
