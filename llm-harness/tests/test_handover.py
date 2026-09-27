"""Synthetic tests for the recipient-bound, signed offline handover ledger."""

import base64
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json

import pytest

from cptc_harness.contracts import (
    Bounds,
    BudgetLimit,
    MergeBundle,
    PolicyError,
    RESOURCE_COUNTERS,
    digest,
)
from cptc_harness.ledger import Ledger, ProfileContinuationProof


def _signing_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key, base64.b64encode(raw).decode("ascii"), hashlib.sha256(raw).hexdigest()


def _bounds(**values):
    return Bounds(timeout_s=1.0, output_bytes=0, process_limit=0, **values)


def _source(tmp_path, device="source", recipient="destination", policy="policy-v2"):
    key, public, _ = _signing_key()
    _, _, recipient_fingerprint = _signing_key()
    ledger = Ledger(tmp_path / device, "engagement", device, policy_revision=policy)
    ledger.enroll_workspace("workspace-1", "audit-origin-1", "a" * 64)
    ledger.reserve("request-1", _bounds(request_limit=2, actions=1), workspace_id="workspace-1",
                   target_id="target-1", auth_realm="realm-1", workflow_id="inventory")
    ledger.finish("request-1", {"request_limit": 1, "actions": 1}, state="complete")
    ledger.stop("operator handover")
    seal_id = ledger.seal_for_handover(recipient, recipient_fingerprint)
    bundle = ledger.handover_bundle(seal_id, signer=key.sign)
    return ledger, bundle, key, public, recipient_fingerprint


def _merge(destination, bundle, source_public, local_fingerprint):
    return destination.merge_handover(
        bundle, {bundle.device_id: source_public}, local_fingerprint,
        digest(asdict(bundle)),
    )


def test_legacy_bounds_without_transport_fields_remain_handover_compatible(tmp_path):
    key, public, _ = _signing_key()
    _, _, destination_fingerprint = _signing_key()
    source = Ledger(tmp_path / "legacy-source", "engagement", "legacy", policy_revision="policy-v2")
    source.reserve("old", _bounds(request_limit=1), workspace_id="workspace", workflow_id="flow")
    source.finish("old")
    encoded = json.loads(source._db.execute("SELECT bounds FROM reservations WHERE request_id='old'").fetchone()[0])
    transport = ("tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes")
    for field in transport:
        encoded.pop(field)
    source._db.execute("UPDATE reservations SET bounds=? WHERE request_id='old'", (json.dumps(encoded, sort_keys=True),))
    source.stop()
    bundle = source.handover_bundle(source.seal_for_handover("destination", destination_fingerprint), key.sign)

    destination = Ledger(tmp_path / "destination", "engagement", "destination", policy_revision="policy-v2")
    report = _merge(destination, bundle, public, destination_fingerprint)
    assert report.accepted
    assert destination.usage()["request_limit"] == 1
    assert all(destination.usage()[field] == 0 for field in transport)


def test_combined_destination_limit_rejects_entire_handover(tmp_path):
    source, bundle, key, public, fingerprint = _source(tmp_path)
    destination = Ledger(tmp_path / "destination", "engagement", "destination", policy_revision="policy-v2", limits={"request_limit": 24})
    destination.reserve("already-spent", _bounds(request_limit=23), workspace_id="workspace-1", target_id="different-target", workflow_id="previous")
    destination.finish("already-spent", state="complete")
    result = _merge(destination, bundle, public, fingerprint)
    assert not result.accepted and result.imported == 0
    assert destination.usage()["request_limit"] == 23


@pytest.mark.parametrize("counter,ceiling", [
    ("tcp_connects", 24),
    ("udp_datagrams", 24),
    ("protocol_requests", 24),
    ("tx_bytes", 1048576),
    ("rx_bytes", 4194304),
])
def test_combined_target_transport_limit_rejects_entire_handover(tmp_path, counter, ceiling):
    key, public, _ = _signing_key()
    _, _, destination_fingerprint = _signing_key()
    source = Ledger(tmp_path / "transport-source", "engagement", "source", policy_revision="policy-v2")
    source.reserve("incoming", _bounds(**{counter: 1}), workspace_id="workspace", target_id="target-1")
    source.finish("incoming")
    source.stop("operator handover")
    bundle = source.handover_bundle(
        source.seal_for_handover("destination", destination_fingerprint), key.sign,
    )
    destination = Ledger(tmp_path / "transport-destination", "engagement", "destination", policy_revision="policy-v2")
    destination.reserve("existing", _bounds(**{counter: ceiling}), workspace_id="workspace", target_id="target-1")
    destination.finish("existing")
    before = destination.usage(target_id="target-1")[counter]
    report = _merge(destination, bundle, public, destination_fingerprint)
    assert not report.accepted and report.imported == 0
    assert destination.usage(target_id="target-1")[counter] == before
    assert destination._db.execute("SELECT COUNT(*) FROM handover_imports").fetchone()[0] == 0


@pytest.mark.parametrize("attempt_state,reservation_state", [
    ("complete", "complete"),
    ("uncertain", "uncertain"),
])
def test_terminal_transport_attempt_handover_preserves_reserved_allowance(
    tmp_path, attempt_state, reservation_state,
):
    key, public, _ = _signing_key()
    _, _, destination_fingerprint = _signing_key()
    source = Ledger(tmp_path / f"attempt-{attempt_state}", "engagement", "source", policy_revision="policy-v2")
    source.reserve(
        "network-action", _bounds(tcp_connects=1, protocol_requests=1, tx_bytes=64, rx_bytes=128),
        workspace_id="workspace", target_id="target-1", workflow_id="observation",
    )
    source.begin_attempt("network-action", "attempt-1", started_ns=1_000, deadline_ns=10_000)
    source.record_attempt_event(
        "network-action", "attempt-1", "request", tcp_connects=1,
        protocol_requests=1, tx_bytes=64, rx_bytes=128,
    )
    source.finish_attempt("network-action", "attempt-1", state=attempt_state, ended_ns=2_000)
    source.finish(
        "network-action",
        {"tcp_connects": 1, "protocol_requests": 1, "tx_bytes": 64, "rx_bytes": 128},
        state=reservation_state,
    )
    source.stop("operator handover")
    bundle = source.handover_bundle(
        source.seal_for_handover("destination", destination_fingerprint), key.sign,
    )

    destination = Ledger(tmp_path / f"destination-{attempt_state}", "engagement", "destination", policy_revision="policy-v2")
    report = _merge(destination, bundle, public, destination_fingerprint)
    assert report.accepted and report.imported == 1
    assert destination.usage(target_id="target-1")["tcp_connects"] == 1
    assert destination.usage(target_id="target-1")["tx_bytes"] == 64
    assert destination._db.execute("SELECT COUNT(*) FROM reservation_attempts").fetchone()[0] == 0


def test_running_transport_attempt_blocks_handover_seal(tmp_path):
    source = Ledger(tmp_path / "running-attempt", "engagement", "source", policy_revision="policy-v2")
    source.reserve("network-action", _bounds(tcp_connects=1), workspace_id="workspace", target_id="target-1")
    source.begin_attempt("network-action", "attempt-1", started_ns=1_000, deadline_ns=10_000)
    source.stop("operator handover")
    with pytest.raises(PolicyError, match="running transport"):
        source.seal_for_handover("destination", "a" * 64)


def _resign(bundle, key, snapshot):
    payload = deepcopy(bundle.payload)
    payload["snapshot"] = snapshot
    payload["snapshot_sha256"] = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    unsigned = {name: payload[name] for name in payload if name != "signature"}
    payload["signature"] = base64.b64encode(key.sign(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    )).decode("ascii")
    return MergeBundle(bundle.engagement_id, bundle.device_id, payload)


def test_seal_requires_stop_and_no_running_reservation_and_freezes_source(tmp_path):
    ledger = Ledger(tmp_path / "source", "engagement", "source", policy_revision="policy-v2")
    with pytest.raises(PolicyError):
        ledger.seal_for_handover("destination", "a" * 64)
    ledger.reserve("running", _bounds(actions=1), workspace_id="workspace")
    ledger.stop("first stop")
    with pytest.raises(PolicyError):
        ledger.seal_for_handover("destination", "a" * 64)
    ledger.finish("running", state="stopped")
    seal_id = ledger.seal_for_handover("destination", "a" * 64)
    assert seal_id
    ledger.stop("second stop")
    assert ledger.stop_reason() == "first stop"
    with pytest.raises(PolicyError):
        ledger.reserve("new", _bounds(actions=1), workspace_id="workspace")
    with pytest.raises(PolicyError):
        ledger.assign("workspace", "other-target")
    with pytest.raises(PolicyError):
        ledger.finish("running")
    with pytest.raises(PolicyError):
        ledger.charge("running", "actions", 1)
    with pytest.raises(PolicyError):
        ledger.rate_gate("target", 1.0, 1.0)


def test_successful_handover_preserves_origins_assignments_totals_and_two_hop(tmp_path):
    source, bundle_ab, source_key, source_public, fp_b = _source(tmp_path, "source", "device-b")
    device_b = Ledger(tmp_path / "device-b", "engagement", "device-b", policy_revision="policy-v2")
    report_ab = _merge(device_b, bundle_ab, source_public, fp_b)
    assert report_ab.accepted and report_ab.imported == 1
    expected = {key: 0 for key in RESOURCE_COUNTERS}
    expected.update(request_limit=2, actions=1)
    assert device_b.usage() == expected
    device_b.reserve("request-2", _bounds(request_limit=3, model_calls=1), workspace_id="workspace-1",
                     target_id="target-1", auth_realm="realm-1", workflow_id="followup")
    device_b.finish("request-2", state="finished")
    device_b.stop("second handover")
    key_b, public_b, _ = _signing_key()
    _, _, fp_c = _signing_key()
    seal_bc = device_b.seal_for_handover("device-c", fp_c)
    bundle_bc = device_b.handover_bundle(seal_bc, signer=key_b.sign)
    device_c = Ledger(tmp_path / "device-c", "engagement", "device-c", policy_revision="policy-v2")
    report_bc = _merge(device_c, bundle_bc, public_b, fp_c)
    assert report_bc.accepted and report_bc.imported == 2
    rows = device_c._db.execute(
        "SELECT device,request_id FROM reservations ORDER BY device,request_id"
    ).fetchall()
    assert rows == [("device-b", "request-2"), ("source", "request-1")]
    assert device_c._db.execute(
        "SELECT target,realm,workspace FROM assignments"
    ).fetchall() == [("target-1", "realm-1", "workspace-1")]
    assert device_c.usage()["request_limit"] == 5
    assert device_c.usage()["model_calls"] == 1
    assert source.stopped()


def test_handover_preserves_reconciliation_tombstone_and_rejects_tampering(
    tmp_path,
):
    key, public, _ = _signing_key()
    _, _, destination_fingerprint = _signing_key()
    source = Ledger(
        tmp_path / "reconcile-source",
        "engagement",
        "source",
        policy_revision="policy-v2",
    )
    predecessor = "spent-action"
    source.reconcile_profile_predecessor(
        predecessor_action_id=predecessor,
        predecessor_plan_id="old-plan",
        predecessor_plan_sha256="1" * 64,
        successor_action_id="successor-action",
        successor_plan_id="new-plan",
        successor_plan_sha256="2" * 64,
        reconciliation_sha256="3" * 64,
        reason_code="clock-source-unavailable",
    )
    source.reserve("successor-action", _bounds(actions=1), workspace_id="workspace")
    source.finish("successor-action", state="complete")
    expected = source.profile_reconciliation(predecessor)
    source.stop("operator handover")
    bundle = source.handover_bundle(
        source.seal_for_handover("destination", destination_fingerprint),
        key.sign,
    )
    assert bundle.payload["version"] == 3
    assert bundle.payload["snapshot"]["profile_reconciliations"]

    destination = Ledger(
        tmp_path / "reconcile-destination",
        "engagement",
        "destination",
        policy_revision="policy-v2",
    )
    report = _merge(destination, bundle, public, destination_fingerprint)
    assert report.accepted
    assert destination.profile_reconciliation(predecessor) == expected
    with pytest.raises(PolicyError, match="permanently spent"):
        destination.reserve(predecessor, _bounds(actions=1))
    with pytest.raises(PolicyError, match="successor action is already spent"):
        destination.reserve("successor-action", _bounds(actions=1))

    tampered_snapshot = deepcopy(bundle.payload["snapshot"])
    tampered_snapshot["profile_reconciliations"][0][
        "target_traffic_absent"
    ] = False
    tampered = _resign(bundle, key, tampered_snapshot)
    fresh = Ledger(
        tmp_path / "tampered-destination",
        "engagement",
        "destination",
        policy_revision="policy-v2",
    )
    assert not _merge(fresh, tampered, public, destination_fingerprint).accepted
    assert fresh.profile_reconciliation(predecessor) is None


def test_handover_cannot_reintroduce_a_locally_reconciled_predecessor(tmp_path):
    key, public, _ = _signing_key()
    _, _, destination_fingerprint = _signing_key()
    predecessor = "spent-action"
    source = Ledger(
        tmp_path / "reservation-source",
        "engagement",
        "source",
        policy_revision="policy-v2",
    )
    source.reserve(predecessor, _bounds(actions=1), workspace_id="workspace")
    source.finish(predecessor, state="blocked")
    source.stop("operator handover")
    bundle = source.handover_bundle(
        source.seal_for_handover("destination", destination_fingerprint),
        key.sign,
    )

    destination = Ledger(
        tmp_path / "reservation-destination",
        "engagement",
        "destination",
        policy_revision="policy-v2",
    )
    destination.reconcile_profile_predecessor(
        predecessor_action_id=predecessor,
        predecessor_plan_id="old-plan",
        predecessor_plan_sha256="1" * 64,
        successor_action_id="successor-action",
        successor_plan_id="new-plan",
        successor_plan_sha256="2" * 64,
        reconciliation_sha256="3" * 64,
        reason_code="clock-source-unavailable",
    )

    report = _merge(destination, bundle, public, destination_fingerprint)
    assert not report.accepted
    assert report.imported == 0
    assert destination._db.execute(
        "SELECT 1 FROM reservations WHERE request_id=?", (predecessor,)
    ).fetchone() is None


def test_handover_cannot_reintroduce_a_locally_spent_successor(tmp_path):
    key, public, _ = _signing_key()
    _, _, destination_fingerprint = _signing_key()
    successor = "successor-action"
    source = Ledger(
        tmp_path / "successor-source",
        "engagement",
        "source",
        policy_revision="policy-v2",
    )
    source.reserve(successor, _bounds(actions=1), workspace_id="workspace")
    source.finish(successor, state="complete")
    source.stop("operator handover")
    bundle = source.handover_bundle(
        source.seal_for_handover("destination", destination_fingerprint),
        key.sign,
    )

    destination = Ledger(
        tmp_path / "successor-destination",
        "engagement",
        "destination",
        policy_revision="policy-v2",
    )
    destination.reconcile_profile_predecessor(
        predecessor_action_id="spent-action",
        predecessor_plan_id="old-plan",
        predecessor_plan_sha256="1" * 64,
        successor_action_id=successor,
        successor_plan_id="new-plan",
        successor_plan_sha256="2" * 64,
        reconciliation_sha256="3" * 64,
        reason_code="clock-source-unavailable",
    )

    report = _merge(destination, bundle, public, destination_fingerprint)
    assert not report.accepted
    assert report.imported == 0
    assert destination._db.execute(
        "SELECT 1 FROM reservations WHERE request_id=?", (successor,)
    ).fetchone() is None


def test_handover_preserves_profile_continuation_charge_and_both_tombstones(
    tmp_path,
):
    key, public, _ = _signing_key()
    _, _, destination_fingerprint = _signing_key()
    shared_root = tmp_path / "continuation-source"
    old_engagement = "legacy-engagement"
    engagement = "engagement"
    v1_action = "identity-action-v1"
    v2_action = "identity-action-v2"
    v3_action = "identity-action-v3"
    workspace = "workspace"
    target = "http://192.0.2.10:8096"
    workflow = "public-identity"

    predecessor = Ledger(shared_root, old_engagement, "source", policy_revision="policy-v2")
    predecessor.reconcile_profile_predecessor(
        predecessor_action_id=v1_action,
        predecessor_plan_id="identity-plan-v1",
        predecessor_plan_sha256="1" * 64,
        successor_action_id=v2_action,
        successor_plan_id="identity-plan-v2",
        successor_plan_sha256="2" * 64,
        reconciliation_sha256="3" * 64,
        reason_code="clock-source-unavailable",
    )
    predecessor.reserve_attempt(
        v2_action,
        _bounds(
            actions=1,
            request_limit=1,
            tcp_connects=1,
            protocol_requests=1,
            tx_bytes=1024,
            rx_bytes=1024,
        ),
        "attempt-v2",
        started_ns=1,
        deadline_ns=1_000_000_001,
        workspace_id=workspace,
        target_id=target,
        workflow_id=workflow,
    )
    predecessor.finish_attempt(v2_action, "attempt-v2", state="uncertain", ended_ns=2)
    predecessor.finish(v2_action, state="uncertain")
    predecessor.stop("transport outcome uncertain")

    source = Ledger(shared_root, engagement, "source", policy_revision="policy-v2")
    proof = ProfileContinuationProof(
        predecessor_engagement=old_engagement,
        predecessor_action_id=v2_action,
        predecessor_plan_id="identity-plan-v2",
        predecessor_plan_sha256="2" * 64,
        predecessor_release_manifest_sha256="4" * 64,
        predecessor_profile_worker_sha256="5" * 64,
        predecessor_broker_worker_sha256="6" * 64,
        predecessor_audit_chain_tail_sha256="7" * 64,
        predecessor_audit_snapshot_sha256="8" * 64,
        predecessor_raw_failure_stage=None,
        predecessor_stage="legacy_target_open_unacknowledged",
        predecessor_attempt_count=1,
        predecessor_observed_tcp_connects=0,
        predecessor_possible_tcp_connects=1,
        predecessor_charged_tcp_connects=1,
        predecessor_observed_udp_datagrams=0,
        predecessor_charged_udp_datagrams=0,
        predecessor_observed_protocol_requests=0,
        predecessor_charged_protocol_requests=0,
        predecessor_observed_tx_bytes=0,
        predecessor_charged_tx_bytes=0,
        predecessor_observed_rx_bytes=0,
        predecessor_charged_rx_bytes=0,
        predecessor_evidence_bytes=0,
        predecessor_first_byte_at=None,
        predecessor_wire_event_count=0,
        predecessor_outcome="uncertain",
        predecessor_cleanup_status="passed",
        predecessor_stop_reason="transport outcome uncertain",
        reconciliation_sha256="3" * 64,
    )
    source.record_profile_continuation(
        proof=proof,
        successor_action_id=v3_action,
        successor_plan_id="identity-plan-v3",
        successor_plan_sha256="9" * 64,
        successor_workspace_id=workspace,
        successor_target_id=target,
        successor_workflow_id=workflow,
    )
    expected = source.profile_continuation(old_engagement, v2_action)
    source.stop("operator handover")
    bundle = source.handover_bundle(
        source.seal_for_handover("destination", destination_fingerprint),
        key.sign,
    )

    assert bundle.payload["version"] == 4
    assert bundle.payload["snapshot"]["profile_continuations"]
    destination = Ledger(
        tmp_path / "continuation-destination",
        engagement,
        "destination",
        policy_revision="policy-v2",
        limits={"tcp_connects": 1},
    )
    report = _merge(destination, bundle, public, destination_fingerprint)
    assert report.accepted
    assert destination.profile_continuation(old_engagement, v2_action) == expected
    assert destination.usage()["tcp_connects"] == 1
    for spent_action in (v1_action, v2_action):
        with pytest.raises(PolicyError, match="continuation predecessor.*permanently spent"):
            destination.reserve(spent_action, _bounds(actions=1))
    with pytest.raises(PolicyError, match="durable scoped budget exhausted"):
        destination.reserve(
            "fresh-action",
            _bounds(tcp_connects=1),
            workspace_id=workspace,
            target_id=target,
            workflow_id=workflow,
            budget_limits=(BudgetLimit("target", target, "tcp_connects", 1),),
        )

    tampered_snapshot = deepcopy(bundle.payload["snapshot"])
    tampered_snapshot["profile_continuations"][0][
        "predecessor_charged_tcp_connects"
    ] = 0
    tampered = _resign(bundle, key, tampered_snapshot)
    fresh = Ledger(
        tmp_path / "continuation-tampered",
        engagement,
        "destination",
        policy_revision="policy-v2",
    )
    assert not _merge(fresh, tampered, public, destination_fingerprint).accepted
    assert fresh.profile_continuation(old_engagement, v2_action) is None

    same_workers = deepcopy(bundle.payload["snapshot"])
    same_workers["profile_continuations"][0][
        "predecessor_broker_worker_sha256"
    ] = same_workers["profile_continuations"][0][
        "predecessor_profile_worker_sha256"
    ]
    same_workers_bundle = _resign(bundle, key, same_workers)
    distinct_workers = Ledger(
        tmp_path / "continuation-same-workers",
        engagement,
        "destination",
        policy_revision="policy-v2",
    )
    assert not _merge(
        distinct_workers,
        same_workers_bundle,
        public,
        destination_fingerprint,
    ).accepted
    assert distinct_workers.profile_continuation(old_engagement, v2_action) is None


def test_signature_recipient_policy_and_totals_fail_before_import(tmp_path):
    _, bundle, key, public, fp = _source(tmp_path, recipient="destination")
    destination = Ledger(tmp_path / "destination", "engagement", "destination", policy_revision="policy-v2")
    bad_signature = deepcopy(bundle.payload)
    bad_signature["signature"] = base64.b64encode(b"bad").decode("ascii")
    bad = MergeBundle(bundle.engagement_id, bundle.device_id, bad_signature)
    assert not _merge(destination, bad, public, fp).accepted
    assert not _merge(destination, bundle, public, "b" * 64).accepted
    wrong_policy = Ledger(tmp_path / "wrong-policy", "engagement", "destination", policy_revision="other")
    assert not _merge(wrong_policy, bundle, public, fp).accepted

    invalid_totals = deepcopy(bundle.payload["snapshot"])
    invalid_totals["totals"]["all"]["actions"] += 1
    tampered = _resign(bundle, key, invalid_totals)
    assert not _merge(destination, tampered, public, fp).accepted
    assert destination._db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 0


def test_replay_overlap_and_conflict_are_atomic(tmp_path):
    _, bundle, key, public, fp = _source(tmp_path, recipient="destination")
    destination = Ledger(tmp_path / "destination", "engagement", "destination", policy_revision="policy-v2")
    assert _merge(destination, bundle, public, fp).accepted
    assert not _merge(destination, bundle, public, fp).accepted
    before = destination._db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
    conflicting_snapshot = deepcopy(bundle.payload["snapshot"])
    conflicting_snapshot["reservations"][0]["bounds"]["request_limit"] = 3
    conflicting_snapshot["totals"]["all"]["request_limit"] = 3
    conflicting_snapshot["totals"]["by_device"]["source"]["request_limit"] = 3
    conflicting = _resign(bundle, key, conflicting_snapshot)
    report = _merge(destination, conflicting, public, fp)
    assert not report.accepted and "overlap" in (report.reason or "")
    assert destination._db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == before

    assignment_conflict = Ledger(tmp_path / "assignment-conflict", "engagement", "destination", policy_revision="policy-v2")
    assignment_conflict.assign("other-workspace", "target-1", "realm-1")
    report = _merge(assignment_conflict, bundle, public, fp)
    assert not report.accepted and "assignment" in (report.reason or "")
    assert assignment_conflict._db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 0


def test_workspace_enrollment_is_stable_and_legacy_paths_are_archival_only(tmp_path):
    ledger = Ledger(tmp_path / "ledger", "engagement", "device", policy_revision="policy-v2")
    assert ledger.enroll_workspace("workspace", "origin", "a" * 64)
    assert not ledger.enroll_workspace("workspace", "origin", "a" * 64)
    with pytest.raises(PolicyError):
        ledger.enroll_workspace("workspace", "moved-origin", "a" * 64)
    with pytest.raises(PolicyError):
        ledger.enroll_workspace("workspace", "origin", "b" * 64)
    with pytest.raises(PolicyError):
        ledger.bundle(signer=lambda _: b"signature")
    assert not ledger.merge(MergeBundle("engagement", "other", {"version": 1})).accepted
