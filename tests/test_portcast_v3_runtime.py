from __future__ import annotations

import hashlib
import inspect
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import testing.cptc11_lab.portcast_live as live
import testing.cptc11_lab.portcast_service as service
from cptc_harness.contracts import (
    Bounds,
    BudgetLimit,
    OperationRequest,
    PolicyError,
    PolicySnapshot,
    ScopeSpec,
    canonical_json,
    to_json,
)
from cptc_harness.ledger import Ledger
from cptc_harness.integrity import VerifiedRelease
from cptc_harness.profile_runtime.service_client import (
    PortcastServiceClient,
    validate_portcast_result,
)
from cptc_harness.registry import build_registry
from tests import test_audit_readonly as audit_fixtures
from tests import test_profile_reconciliation as ledger_fixtures


V1_FILE_SHA256 = "1de39a00a6ccbbc9d8bf7a4c8f1711d7989532b19dec99a93d808e5354147256"
V2_FILE_SHA256 = "1ebe09e1db61a573abd840d90a2fbf52d6315e7d3bdd68ea8a32a7c1b1f023ce"
V3_PLAN_SHA256 = "cb057ddfe09076b781fecb84f3172294ff3aa7409ee2544e52f30043a0dbe936"
CURRENT_MODULE_SOURCE_SHA256 = (
    "777c73f83563d261b6b88acf84fb7be915a1a6f357e4fc3cb29992c83d50ab4c"
)


def _complete_metadata(action_id: str) -> dict[str, object]:
    return {
        "action_id": action_id,
        "audit_verified": True,
        "automatic_retry": False,
        "cleanup_status": "passed",
        "execution": {
            "reservation_state": "complete",
            "attempt_count": 1,
            "attempt_state": "complete",
            "transport_counters": {
                "tcp_connects": 1,
                "udp_datagrams": 0,
                "protocol_requests": 1,
                "tx_bytes": 103,
                "rx_bytes": 282,
            },
            "wire_counters_verified": True,
            "result_receipt_present": True,
            "failure_stage": None,
        },
        "profile_id": "web.http_jellyfin_public_identity",
        "receipt_outcome": "complete",
        "status": "complete",
        "workspace": "cptc11-portcast-workspace",
    }


def test_v3_plan_binds_fixed_successor_and_exact_v2_workflow():
    plan = live.load_frozen_portcast_plan()

    assert plan.schema_version == 3
    assert plan.engagement_id == "cptc11-dell-validation-portcast-v3"
    assert plan.action_id == "cptc11-portcast-public-identity-action-v3"
    assert plan.plan_id == "cptc11-portcast-public-identity-wave-v3"
    assert plan.workflow_id == "cptc11-portcast-public-identity-wave-v1"
    assert plan.workspace_id == "cptc11-portcast-workspace"
    assert plan.target_id == "cptc11-prod-portcast"
    assert plan.request_count == 1
    assert plan.tcp_connection_limit == 1
    assert plan.output_bytes == 16384
    assert plan.plan_sha256 == V3_PLAN_SHA256
    assert plan.module_source_sha256 == CURRENT_MODULE_SOURCE_SHA256
    assert build_registry().get(plan.module_id).source_hash == (
        CURRENT_MODULE_SOURCE_SHA256
    )


def test_reviewed_v3_plan_keeps_approval_and_window_fail_closed():
    plan = live.load_frozen_portcast_plan()

    assert plan.reviewed_by == "approved:daybreak-portcast-v3-release-review-r2"
    assert plan.window_start == "2026-09-11T05:20:00.000000Z"
    assert plan.window_end == "2026-09-11T09:20:00.000000Z"
    with pytest.raises(PolicyError, match="not independently approved"):
        live._require_open_window(replace(plan, reviewed_by="pending-review"))
    with pytest.raises(PolicyError, match="operating window is closed"):
        live._require_open_window(
            replace(
                plan,
                window_start="2026-09-10T00:00:00.000000Z",
                window_end="2026-09-10T01:00:00.000000Z",
            )
        )


def test_v3_plan_preserves_and_binds_exact_v1_v2_file_bytes():
    before = {
        path: path.read_bytes()
        for path in (live._V1_PLAN_PATH, live._V2_PLAN_PATH)
    }
    plan = live.load_frozen_portcast_plan()

    assert hashlib.sha256(before[live._V1_PLAN_PATH]).hexdigest() == V1_FILE_SHA256
    assert hashlib.sha256(before[live._V2_PLAN_PATH]).hexdigest() == V2_FILE_SHA256
    assert plan.predecessor_v1_plan_file_sha256 == V1_FILE_SHA256
    assert plan.predecessor_v2_plan_file_sha256 == V2_FILE_SHA256
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("predecessor_v1_plan_file_sha256", "0" * 64),
        ("predecessor_v2_plan_file_sha256", "0" * 64),
        ("predecessor_action_sha256", "0" * 64),
        ("predecessor_release_manifest_sha256", "0" * 64),
        ("predecessor_profile_worker_sha256", "0" * 64),
        ("predecessor_broker_worker_sha256", "0" * 64),
        ("predecessor_target_sha256", "0" * 64),
        ("predecessor_request_sha256", "0" * 64),
        ("predecessor_output_bytes", 1),
        ("target_sha256", "0" * 64),
        ("request_sha256", "0" * 64),
        ("output_bytes", 1),
    ),
)
def test_plan_binding_drift_fails_before_dispatch(
    tmp_path, monkeypatch, field, value
):
    document = json.loads(live._PLAN_PATH.read_bytes())
    document[field] = value
    unsigned = dict(document)
    unsigned.pop("plan_sha256")
    document["plan_sha256"] = hashlib.sha256(
        live._canonical(unsigned)
    ).hexdigest()
    changed = tmp_path / "changed-plan.json"
    changed.write_bytes(live._canonical(document))
    monkeypatch.setattr(live, "_PLAN_PATH", changed)

    with pytest.raises(PolicyError):
        live.load_frozen_portcast_plan()


def test_removed_successor_manifest_field_is_rejected_as_unknown(
    tmp_path, monkeypatch
):
    document = json.loads(live._PLAN_PATH.read_bytes())
    document["release_manifest_sha256"] = "0" * 64
    unsigned = dict(document)
    unsigned.pop("plan_sha256")
    document["plan_sha256"] = hashlib.sha256(
        live._canonical(unsigned)
    ).hexdigest()
    changed = tmp_path / "plan-with-unknown-field.json"
    changed.write_bytes(live._canonical(document))
    monkeypatch.setattr(live, "_PLAN_PATH", changed)

    with pytest.raises(PolicyError, match="fields differ"):
        live.load_frozen_portcast_plan()


@pytest.mark.parametrize(
    "field",
    (
        "catalog_sha256",
        "profile_sha256",
        "operation_sha256",
        "parser_sha256",
        "worker_sha256",
        "profile_worker_sha256",
        "broker_worker_sha256",
        "runtime_pinset_sha256",
        "module_source_sha256",
    ),
)
def test_successor_release_binding_drift_fails_before_dispatch(
    monkeypatch, field
):
    plan = live.load_frozen_portcast_plan()
    verified = VerifiedRelease(
        plan.release_id,
        "a" * 64,
        {
            "cptc_harness/portcast_identity.py": plan.parser_sha256,
            "testing/cptc11_lab/portcast_broker_worker.py": (
                plan.broker_worker_sha256
            ),
        },
        {plan.profile_id: plan.profile_worker_sha256},
        {plan.profile_id: (plan.profile_worker_sha256,)},
    )
    monkeypatch.setattr(live, "verify_portcast_release", lambda: verified)

    assert live.validate_current_release(plan) is verified

    with pytest.raises(PolicyError, match="release binding differs"):
        live.validate_current_release(replace(plan, **{field: "0" * 64}))


def test_v3_plan_builds_exact_read_only_v2_audit_identity():
    plan = live.load_frozen_portcast_plan()
    expected = live._expected_predecessor_identity(plan)

    assert expected.engagement_id == "cptc11-dell-validation"
    assert expected.action_id == "cptc11-portcast-public-identity-action-v2"
    assert expected.plan_id == "cptc11-portcast-public-identity-wave-v1"
    assert expected.plan_sha256 == plan.predecessor_plan_sha256
    assert expected.module_source_sha256 != plan.module_source_sha256
    assert expected.action_sha256 == plan.predecessor_action_sha256
    assert expected.release_manifest_sha256 == plan.predecessor_release_manifest_sha256
    assert expected.release_manifest_sha256 == (
        "6bc14700871cb0e9aab47d056931d582507471d6d24138b533848a02f80afc0e"
    )
    assert expected.profile_worker_sha256 == plan.predecessor_profile_worker_sha256
    assert expected.broker_worker_sha256 == plan.predecessor_broker_worker_sha256
    assert expected.target_sha256 == plan.predecessor_target_sha256
    assert expected.request_sha256 == plan.predecessor_request_sha256
    assert expected.output_bytes == plan.predecessor_output_bytes == 16384


def test_predecessor_proof_verification_does_not_change_old_audit_or_result(
    tmp_path, monkeypatch
):
    fixture = audit_fixtures._build_fixture(tmp_path)
    plan = replace(
        live.load_frozen_portcast_plan(),
        predecessor_engagement_id=fixture.expected.engagement_id,
        predecessor_action_id=fixture.expected.action_id,
        predecessor_plan_id=fixture.expected.plan_id,
        predecessor_plan_sha256=fixture.expected.plan_sha256,
        predecessor_release_manifest_sha256=(
            fixture.expected.release_manifest_sha256
        ),
        predecessor_profile_worker_sha256=(
            fixture.expected.profile_worker_sha256
        ),
        predecessor_broker_worker_sha256=(
            fixture.expected.broker_worker_sha256
        ),
    )
    monkeypatch.setattr(
        live,
        "_expected_predecessor_identity",
        lambda _plan: fixture.expected,
    )

    def capture() -> tuple[tuple[str, bytes, int, int], ...]:
        paths = [
            item
            for root in (fixture.audit_root, fixture.result_path)
            for item in (
                root.rglob("*") if root.is_dir() else (root,)
            )
            if item.is_file()
        ]
        return tuple(
            (
                str(item.relative_to(tmp_path)),
                item.read_bytes(),
                item.stat().st_mtime_ns,
                item.stat().st_ctime_ns,
            )
            for item in sorted(paths)
        )

    before = capture()
    proof = live._verified_predecessor_proof(tmp_path, plan)

    assert proof.predecessor_audit_snapshot_sha256
    assert proof.predecessor_observed_tcp_connects == 0
    assert proof.predecessor_possible_tcp_connects == 1
    assert proof.predecessor_charged_tcp_connects == 1
    assert proof.predecessor_stage == "legacy_target_open_unacknowledged"
    assert capture() == before


def test_exact_v2_audit_and_ledger_record_v3_continuation_read_only(
    tmp_path, monkeypatch
):
    plan = live.load_frozen_portcast_plan()
    expected = live._expected_predecessor_identity(plan)
    predecessor_plan = live._read_predecessor_plan(plan)
    predecessor_policy = PolicySnapshot(
        expected.engagement_id,
        expected.policy_revision,
        expected.workspace_id,
        expected.device_id,
        expected.operator_id,
        ScopeSpec(),
        encrypted_storage=True,
    )
    request = to_json(
        OperationRequest(
            expected.action_id,
            expected.workspace_id,
            expected.device_id,
            expected.operator_id,
            expected.module_id,
            live._target(),
            {"profile_id": expected.profile_id},
            "operator",
            None,
            expected.policy_revision,
            expected.plan_id,
        )
    )
    spec = build_registry().get(expected.module_id)
    args = {"profile_id": expected.profile_id}
    intent = {
        "module": spec.module_id,
        "version": spec.version,
        "target": expected.target_id,
        "source_sha256": expected.module_source_sha256,
        "args_hash": hashlib.sha256(canonical_json(args)).hexdigest(),
        "validated_args": args,
        "bounds": to_json(spec.bounds),
        "actor": "operator",
        "workflow_id": expected.plan_id,
        "approval_id": None,
        "parent_action_id": None,
        "remaining_budgets": {},
    }
    patches = {
        "ACTION_ID": expected.action_id,
        "PLAN_ID": expected.plan_id,
        "PROFILE_ID": expected.profile_id,
        "TARGET_ID": expected.target_id,
        "MODULE_ID": expected.module_id,
        "PROFILE_WORKER_SHA256": expected.profile_worker_sha256,
        "BROKER_WORKER_SHA256": expected.broker_worker_sha256,
        "RELEASE_SHA256": expected.release_manifest_sha256,
        "PLAN_SHA256": expected.plan_sha256,
        "MODULE_SHA256": expected.module_source_sha256,
    }
    for name, value in patches.items():
        monkeypatch.setattr(audit_fixtures, name, value)
    monkeypatch.setattr(audit_fixtures, "_policy", lambda: predecessor_policy)
    monkeypatch.setattr(audit_fixtures, "_target", lambda: to_json(live._target()))
    monkeypatch.setattr(audit_fixtures, "_request", lambda: request)
    monkeypatch.setattr(audit_fixtures, "_intent", lambda: intent)
    monkeypatch.setattr(audit_fixtures, "_expected", lambda: expected)
    monkeypatch.setattr(
        audit_fixtures,
        "_action_sha256",
        lambda: expected.action_sha256,
    )
    fixture = audit_fixtures._build_fixture(tmp_path)
    assert fixture.expected.release_manifest_sha256 == (
        "6bc14700871cb0e9aab47d056931d582507471d6d24138b533848a02f80afc0e"
    )

    ledger_directory = (
        tmp_path / "ledger" / plan.predecessor_engagement_id
    )
    predecessor = Ledger(
        ledger_directory,
        plan.predecessor_engagement_id,
        plan.device_id,
        policy_revision=plan.policy_revision,
    )
    predecessor.reconcile_profile_predecessor(
        predecessor_action_id=predecessor_plan["predecessor_action_id"],
        predecessor_plan_id=predecessor_plan["predecessor_plan_id"],
        predecessor_plan_sha256=predecessor_plan["predecessor_plan_sha256"],
        successor_action_id=plan.predecessor_action_id,
        successor_plan_id=plan.predecessor_plan_id,
        successor_plan_sha256=plan.predecessor_plan_sha256,
        reconciliation_sha256=plan.predecessor_reconciliation_sha256,
        reason_code=plan.predecessor_reconciliation_reason,
    )
    predecessor.reserve_attempt(
        plan.predecessor_action_id,
        spec.bounds,
        "v2-attempt",
        started_ns=1,
        deadline_ns=1_000_000_001,
        workspace_id=plan.workspace_id,
        target_id=plan.target_id,
        workflow_id=plan.workflow_id,
    )
    predecessor.finish_attempt(
        plan.predecessor_action_id,
        "v2-attempt",
        state="uncertain",
        ended_ns=2,
    )
    predecessor.finish(plan.predecessor_action_id, state="uncertain")
    old_rows = ledger_fixtures._predecessor_rows(predecessor)
    old_files = tuple(
        (str(item.relative_to(tmp_path)), item.read_bytes())
        for root in (fixture.audit_root, fixture.result_path)
        for item in sorted(root.rglob("*") if root.is_dir() else (root,))
        if item.is_file()
    )

    continuation = live._record_profile_continuation(
        tmp_path,
        ledger_directory,
        plan,
    )
    successor = Ledger(
        ledger_directory,
        plan.engagement_id,
        plan.device_id,
        policy_revision=plan.policy_revision,
    )
    live._require_existing_profile_continuation(
        SimpleNamespace(ledger=successor),
        tmp_path,
        plan,
    )

    assert continuation["created"] is True
    assert predecessor.profile_reconciliation(
        predecessor_plan["predecessor_action_id"]
    ) is not None
    assert successor.profile_continuation(
        plan.predecessor_engagement_id,
        plan.predecessor_action_id,
    ) is not None
    assert predecessor.stopped()
    assert ledger_fixtures._predecessor_rows(predecessor) == old_rows
    assert tuple(
        (str(item.relative_to(tmp_path)), item.read_bytes())
        for root in (fixture.audit_root, fixture.result_path)
        for item in sorted(root.rglob("*") if root.is_dir() else (root,))
        if item.is_file()
    ) == old_files

    successor._db.execute(
        """UPDATE profile_continuations
              SET successor_plan_sha256=?
            WHERE predecessor_engagement=? AND predecessor_action_id=?""",
        (
            "0" * 64,
            plan.predecessor_engagement_id,
            plan.predecessor_action_id,
        ),
    )
    with pytest.raises(PolicyError, match="profile continuation differs"):
        live._require_existing_profile_continuation(
            SimpleNamespace(ledger=successor),
            tmp_path,
            plan,
        )
    assert tuple(
        (str(item.relative_to(tmp_path)), item.read_bytes())
        for root in (fixture.audit_root, fixture.result_path)
        for item in sorted(root.rglob("*") if root.is_dir() else (root,))
        if item.is_file()
    ) == old_files


def test_continuation_uses_shared_sqlite_and_carries_one_possible_connection(
    tmp_path, monkeypatch
):
    predecessor, unused_successor, proof = ledger_fixtures._continuation_setup(
        tmp_path
    )
    unused_successor._db.close()
    plan = replace(
        live.load_frozen_portcast_plan(),
        workspace_id=ledger_fixtures.WORKSPACE,
        target_id=ledger_fixtures.TARGET,
        workflow_id=ledger_fixtures.WORKFLOW,
        predecessor_engagement_id=proof.predecessor_engagement,
        predecessor_action_id=proof.predecessor_action_id,
        predecessor_plan_id=proof.predecessor_plan_id,
        predecessor_plan_sha256=proof.predecessor_plan_sha256,
        predecessor_reconciliation_sha256=proof.reconciliation_sha256,
        predecessor_release_manifest_sha256=(
            proof.predecessor_release_manifest_sha256
        ),
        predecessor_profile_worker_sha256=(
            proof.predecessor_profile_worker_sha256
        ),
        predecessor_broker_worker_sha256=(
            proof.predecessor_broker_worker_sha256
        ),
    )
    monkeypatch.setattr(
        live,
        "_verified_predecessor_proof",
        lambda _root, _plan: proof,
    )
    before = ledger_fixtures._predecessor_rows(predecessor)
    inode = os.stat(predecessor.path).st_ino

    created = live._record_profile_continuation(
        tmp_path,
        predecessor.root,
        plan,
    )

    assert created["created"] is True
    assert os.stat(predecessor.path).st_ino == inode
    assert predecessor.stopped()
    assert ledger_fixtures._predecessor_rows(predecessor) == before

    successor = Ledger(
        predecessor.root,
        plan.engagement_id,
        plan.device_id,
        policy_revision=plan.policy_revision,
    )
    assert successor.usage()["tcp_connects"] == 1
    tcp_limits = tuple(
        BudgetLimit(scope, key, "tcp_connects", 2)
        for scope, key in (
            ("engagement", plan.engagement_id),
            ("device", plan.device_id),
            ("workspace", plan.workspace_id),
            ("workflow", plan.workflow_id),
            ("target", plan.target_id),
        )
    )
    successor.reserve_attempt(
        plan.action_id,
        Bounds(
            actions=1,
            request_limit=1,
            tcp_connects=1,
            protocol_requests=1,
            tx_bytes=256,
            rx_bytes=8192,
        ),
        "v3-attempt",
        started_ns=1,
        deadline_ns=1_000_000_001,
        workspace_id=plan.workspace_id,
        target_id=plan.target_id,
        workflow_id=plan.workflow_id,
        limits={"tcp_connects": 2},
        budget_limits=tcp_limits,
    )
    successor.record_attempt_event(
        plan.action_id,
        "v3-attempt",
        "connect-1",
        tcp_connects=1,
    )
    successor.finish_attempt(
        plan.action_id,
        "v3-attempt",
        state="complete",
        ended_ns=2,
    )
    successor.finish(
        plan.action_id,
        {"tcp_connects": 1},
        state="complete",
    )

    assert successor.usage()["tcp_connects"] == 2
    assert successor.attempt_receipt(plan.action_id)["usage"]["tcp_connects"] == 1
    assert ledger_fixtures._predecessor_rows(predecessor) == before


def test_v3_provisions_separate_runtime_and_returns_exact_old_ledger_directory(
    tmp_path
):
    plan = live.load_frozen_portcast_plan()
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    (state_root / "ledger").mkdir(mode=0o700)
    old_ledger = Ledger(
        state_root / "ledger" / plan.predecessor_engagement_id,
        plan.predecessor_engagement_id,
        plan.device_id,
        policy_revision=plan.policy_revision,
    )
    old_runtime = state_root / "runtime"
    old_runtime.mkdir(mode=0o700)
    sentinel = old_runtime / "legacy-read-only-sentinel"
    sentinel.write_bytes(b"unchanged")
    sentinel.chmod(0o600)
    age_binary = Path(__file__).parents[1] / ".tools" / "age"

    runtime_root, ledger_directory = live._prepare_runtime(
        state_root,
        plan,
        age_binary=age_binary,
        age_recipient=plan.evidence_recipient,
        provision=True,
    )

    assert runtime_root == state_root / "v3" / "runtime"
    assert ledger_directory == old_ledger.root
    assert runtime_root.is_dir()
    assert sentinel.read_bytes() == b"unchanged"
    assert not (state_root / "v3" / "ledger").exists()


def test_v3_accepts_only_the_exact_read_only_production_mount_container(
    tmp_path, monkeypatch
):
    plan = live.load_frozen_portcast_plan()
    container = tmp_path / "runtime-container"
    container.mkdir(mode=0o700)
    (container / "v3").mkdir(mode=0o700)
    (container / "ledger").mkdir(mode=0o700)
    container.chmod(0o555)
    monkeypatch.setattr(live, "_PRODUCTION_RUNTIME_CONTAINER", container)
    monkeypatch.setattr(live, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(live, "_ROOT_GID", os.getgid())
    monkeypatch.setattr(
        live,
        "_prepare_runtime_unlocked",
        lambda root, _plan, **_kwargs: (root, root),
    )

    assert live._prepare_runtime(
        container,
        plan,
        age_binary=None,
        age_recipient=None,
        provision=False,
    ) == (container / "v3", container / "v3")

    container.chmod(0o755)
    with pytest.raises(PolicyError, match="mount container differs"):
        live._prepare_runtime(
            container,
            plan,
            age_binary=None,
            age_recipient=None,
            provision=False,
        )


@pytest.mark.parametrize("mode", (0o4700, 0o2700, 0o1700))
def test_v3_rejects_special_bits_on_the_service_runtime_directory(
    tmp_path, monkeypatch, mode
):
    plan = live.load_frozen_portcast_plan()
    container = tmp_path / "runtime-container"
    container.mkdir(mode=0o700)
    runtime = container / "v3"
    runtime.mkdir(mode=0o700)
    runtime.chmod(mode)
    monkeypatch.setattr(
        live,
        "_prepare_runtime_unlocked",
        lambda *_args, **_kwargs: pytest.fail(
            "runtime opened with special permission bits"
        ),
    )

    with pytest.raises(PolicyError, match="v3 runtime directory differs"):
        live._prepare_runtime(
            container,
            plan,
            age_binary=None,
            age_recipient=None,
            provision=False,
        )


def test_startup_records_continuation_before_runtime_credentials_or_listener(
    tmp_path, monkeypatch
):
    plan = live.load_frozen_portcast_plan()
    events: list[str] = []

    class Database:
        def execute(self, _query):
            return self

        def fetchall(self):
            return [("ok",)]

    class FakeLedger:
        _db = Database()

        def reservation_state(self, _action_id):
            return None

    class FakeAudit:
        def ready(self):
            return True

        def verify(self):
            return SimpleNamespace(valid=True)

        def profile_inspection_snapshot(self, _action_id):
            return None

    class FakeRuntime:
        def __init__(self):
            self.ledger = FakeLedger()
            self.audit = FakeAudit()

    runtime_root = tmp_path / "v3" / "runtime"
    ledger_directory = tmp_path / "ledger" / plan.predecessor_engagement_id
    monkeypatch.setattr(live, "_require_open_window", lambda _plan: None)
    monkeypatch.setattr(
        live,
        "prepare_frozen_portcast_runtime_at_root",
        lambda **_kwargs: (runtime_root, ledger_directory),
    )
    monkeypatch.setattr(
        live,
        "_validate_existing_ledger",
        lambda _root, _plan: None,
    )
    monkeypatch.setattr(
        live,
        "_record_profile_continuation",
        lambda *_args: events.append("continuation"),
    )
    monkeypatch.setattr(
        live,
        "Runtime",
        lambda *_args, **_kwargs: (
            events.append("runtime") or FakeRuntime()
        ),
    )
    monkeypatch.setattr(
        live,
        "_require_existing_profile_continuation",
        lambda *_args: events.append("continuation-required"),
    )

    live._open_frozen_portcast_runtime_at_root_core(
        state_root=tmp_path,
        plan=plan,
        verified_release=SimpleNamespace(),
        age_binary=tmp_path / "age",
        age_recipient=plan.evidence_recipient,
    )

    assert events == ["continuation", "runtime", "continuation-required"]
    main_source = inspect.getsource(service.main)
    assert main_source.index("runtime = open_frozen_portcast_runtime_at_root") < (
        main_source.index("_load_service_credentials()")
    )
    assert main_source.index("_load_service_credentials()") < main_source.index(
        "service = _CanonicalPortcastService"
    )
    assert main_source.index("service = _CanonicalPortcastService") < (
        main_source.index("service.serve()")
    )

def test_v3_policy_has_one_action_and_two_connection_cumulative_ceilings():
    plan = live.load_frozen_portcast_plan()
    policy = live.policy_for_plan(plan)
    tcp = {
        (limit.scope, limit.key): limit.ceiling
        for limit in policy.budget_limits
        if limit.counter == "tcp_connects"
    }

    assert tcp == {
        ("engagement", plan.engagement_id): 2,
        ("device", plan.device_id): 2,
        ("workspace", plan.workspace_id): 2,
        ("workflow", plan.workflow_id): 2,
        ("target", plan.target_id): 2,
    }
    assert policy.targets[0].request_limit == 1


def test_client_accepts_only_v3_metadata_and_has_no_target_or_path_inputs():
    assert validate_portcast_result(
        _complete_metadata("cptc11-portcast-public-identity-action-v3")
    )["status"] == "complete"
    with pytest.raises(PolicyError, match="invalid metadata"):
        validate_portcast_result(
            _complete_metadata("cptc11-portcast-public-identity-action-v2")
        )

    assert tuple(inspect.signature(PortcastServiceClient).parameters) == ()
    assert tuple(inspect.signature(PortcastServiceClient.execute).parameters) == (
        "self",
    )
    assert tuple(inspect.signature(PortcastServiceClient.inspect).parameters) == (
        "self",
    )


@pytest.mark.parametrize("extra", ("target", "path"))
def test_service_rejects_extra_wire_request_fields_before_dispatch(
    tmp_path, extra
):
    authority = service._CanonicalPortcastService._for_test(
        state_root=tmp_path,
        socket_path=tmp_path / "service.sock",
        expected_client_uid=os.getuid(),
        verified_release=SimpleNamespace(release_id="portcast-live-v1"),
        wire_broker_factory=lambda *_args: None,
        age_binary=tmp_path / "age",
        age_recipient=live.load_frozen_portcast_plan().evidence_recipient,
    )

    with pytest.raises(RuntimeError, match="invalid canonical.*request"):
        authority._dispatch(
            {
                "method": "inspect",
                "release_id": "portcast-live-v1",
                extra: "untrusted",
            }
        )
