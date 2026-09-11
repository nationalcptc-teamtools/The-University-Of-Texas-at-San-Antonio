"""Frozen coordinator for the first admitted CPTC11 PortCast observation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from cptc_harness.contracts import (
    AuditEvent,
    BudgetLimit,
    ClockState,
    OperationRequest,
    PolicyError,
    PolicySnapshot,
    ScopeSpec,
    TargetPolicy,
    TargetRef,
)
from cptc_harness.policy import load_policy, save_policy
from cptc_harness.integrity import VerifiedRelease, verify_portcast_release
from cptc_harness.profile_runtime.catalog import load_profile, require_live_admission
from cptc_harness.registry import build_registry
from cptc_harness.runtime import Runtime, initialize
from cptc_harness.storage import private_directory


_PLAN_PATH = Path(__file__).with_name("portcast-live-plan-v1.json")
_MAX_PLAN_BYTES = 32 * 1024
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_APPROVED_REVIEWER = re.compile(
    r"^approved:[a-z0-9][a-z0-9._-]{2,63}$"
)
_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "plan_id",
        "action_id",
        "engagement_id",
        "policy_revision",
        "workspace_id",
        "device_id",
        "operator_id",
        "profile_id",
        "module_id",
        "target_id",
        "catalog_sha256",
        "profile_sha256",
        "operation_sha256",
        "parser_sha256",
        "worker_sha256",
        "runtime_pinset_sha256",
        "module_source_sha256",
        "release_id",
        "window_start",
        "window_end",
        "sow_reference",
        "roe_reference",
        "reviewed_by",
        "reviewed_at",
        "request_count",
        "automatic_retries",
        "authentication_attempts",
        "plan_sha256",
    }
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate plan field")
        result[key] = value
    return result


def _read_plan_file() -> dict[str, Any]:
    if _PLAN_PATH.is_symlink():
        raise PolicyError("frozen PortCast plan symlink rejected")
    try:
        descriptor = os.open(_PLAN_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise PolicyError("frozen PortCast plan is unavailable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= _MAX_PLAN_BYTES:
            raise PolicyError("frozen PortCast plan file is invalid")
        raw = os.read(descriptor, _MAX_PLAN_BYTES + 1)
        if len(raw) != info.st_size:
            raise PolicyError("frozen PortCast plan changed during read")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PolicyError("frozen PortCast plan JSON is invalid") from None
    if not isinstance(value, dict) or frozenset(value) != _PLAN_FIELDS:
        raise PolicyError("frozen PortCast plan fields differ")
    return value


@dataclass(frozen=True, slots=True)
class FrozenPortcastPlan:
    schema_version: int
    plan_id: str
    action_id: str
    engagement_id: str
    policy_revision: str
    workspace_id: str
    device_id: str
    operator_id: str
    profile_id: str
    module_id: str
    target_id: str
    catalog_sha256: str
    profile_sha256: str
    operation_sha256: str
    parser_sha256: str
    worker_sha256: str
    runtime_pinset_sha256: str
    module_source_sha256: str
    release_id: str
    window_start: str
    window_end: str
    sow_reference: str
    roe_reference: str
    reviewed_by: str
    reviewed_at: str
    request_count: int
    automatic_retries: int
    authentication_attempts: int
    plan_sha256: str


def load_frozen_portcast_plan() -> FrozenPortcastPlan:
    value = _read_plan_file()
    supplied_hash = value["plan_sha256"]
    unsigned = dict(value)
    unsigned.pop("plan_sha256")
    actual_hash = hashlib.sha256(_canonical(unsigned)).hexdigest()
    if supplied_hash != actual_hash:
        raise PolicyError("frozen PortCast plan hash differs")
    try:
        plan = FrozenPortcastPlan(**value)
    except TypeError:
        raise PolicyError("frozen PortCast plan fields differ") from None
    if plan.schema_version != 1 or any(
        type(getattr(plan, name)) is not str or not getattr(plan, name)
        for name in (
            "plan_id",
            "action_id",
            "engagement_id",
            "policy_revision",
            "workspace_id",
            "device_id",
            "operator_id",
            "profile_id",
            "module_id",
            "target_id",
            "sow_reference",
            "roe_reference",
            "reviewed_by",
        )
    ):
        raise PolicyError("frozen PortCast plan identity differs")
    if (
        plan.request_count != 1
        or plan.automatic_retries != 0
        or plan.authentication_attempts != 0
        or any(type(value) is not int for value in (
            plan.request_count,
            plan.automatic_retries,
            plan.authentication_attempts,
        ))
    ):
        raise PolicyError("frozen PortCast plan allowance differs")
    for timestamp in (plan.window_start, plan.window_end, plan.reviewed_at):
        if _UTC.fullmatch(timestamp) is None:
            raise PolicyError("frozen PortCast plan timestamp differs")
    start = datetime.fromisoformat(plan.window_start.replace("Z", "+00:00"))
    end = datetime.fromisoformat(plan.window_end.replace("Z", "+00:00"))
    if start >= end:
        raise PolicyError("frozen PortCast operating window differs")

    return plan


def validate_current_release(plan: FrozenPortcastPlan) -> VerifiedRelease:
    """Require the installed release to match the plan before live dispatch.

    Historical plan loading is deliberately independent of the current source
    tree.  The live entrypoint calls this gate before it creates a Runtime or
    touches a channel capability.
    """

    verified = verify_portcast_release()
    if type(plan) is not FrozenPortcastPlan:
        raise PolicyError("frozen PortCast plan type differs")
    profile = require_live_admission(load_profile(plan.profile_id))
    spec = build_registry().get(plan.module_id)
    expected = {
        "profile_id": profile.profile_id,
        "module_id": profile.module_id,
        "target_id": profile.target_id,
        "catalog_sha256": profile.catalog_sha256,
        "profile_sha256": profile.profile_sha256,
        "operation_sha256": profile.operation.sha256,
        "parser_sha256": verified.file_sha256["cptc_harness/portcast_identity.py"],
        "worker_sha256": verified.current_profile_workers[plan.profile_id],
        "runtime_pinset_sha256": profile.runtime_pinset_sha256,
        "module_source_sha256": spec.source_hash,
        "release_id": verified.release_id,
    }
    if any(getattr(plan, name) != expected_value for name, expected_value in expected.items()):
        raise PolicyError("frozen PortCast release binding differs")
    return verified


def _target() -> TargetRef:
    return TargetRef(
        "cptc11-prod-portcast",
        "http://10.0.1.30:8096/System/Info/Public",
        "http",
        "10.0.1.30",
        8096,
        "/System/Info/Public",
    )


def policy_for_plan(plan: FrozenPortcastPlan) -> PolicySnapshot:
    target = _target()
    limits = tuple(
        BudgetLimit("workflow", plan.plan_id, counter, ceiling)
        for counter, ceiling in (
            ("request_limit", 1),
            ("tcp_connects", 1),
            ("udp_datagrams", 0),
            ("protocol_requests", 1),
            ("tx_bytes", 256),
            ("rx_bytes", 8192),
            ("output_bytes", 16384),
            ("process_limit", 1),
            ("auth_posts", 0),
        )
    )
    return PolicySnapshot(
        plan.engagement_id,
        plan.policy_revision,
        plan.workspace_id,
        plan.device_id,
        plan.operator_id,
        ScopeSpec(allowed_cidrs=("10.0.1.30/32",)),
        targets=(
            TargetPolicy(
                target,
                True,
                "reviewed-portcast-public-identity-v1",
                plan.workspace_id,
                "",
                (plan.module_id,),
                request_limit=1,
                auth_attempts=0,
            ),
        ),
        window_start=plan.window_start,
        window_end=plan.window_end,
        sow_reference=plan.sow_reference,
        roe_reference=plan.roe_reference,
        encrypted_storage=True,
        model_calls=0,
        model_actions=0,
        format_repairs=0,
        budget_limits=limits,
    )


def _prepare_runtime(
    root: Path,
    plan: FrozenPortcastPlan,
    *,
    age_binary: Path | None,
    age_recipient: str | None,
    provision: bool = True,
) -> tuple[Path, Path]:
    root = private_directory(root, create=True)
    runtime_root = root / "runtime"
    ledger_root = private_directory(root / "ledger", create=True)
    policy = policy_for_plan(plan)
    policy_source = root / "policy-source.json"
    if policy_source.exists():
        if load_policy(policy_source) != policy:
            raise PolicyError("frozen PortCast policy source differs")
    elif provision:
        save_policy(policy_source, policy)
    else:
        raise PolicyError("canonical PortCast policy source is not provisioned")
    if runtime_root.exists():
        if load_policy(runtime_root / "policy.json") != policy:
            raise PolicyError("initialized PortCast policy differs")
    elif provision and isinstance(age_binary, Path) and isinstance(age_recipient, str):
        initialize(
            runtime_root,
            policy_source,
            recipient=age_recipient,
            age_binary=age_binary,
        )
    else:
        raise PolicyError("canonical PortCast runtime is not provisioned")
    return runtime_root, ledger_root


def _require_open_window(plan: FrozenPortcastPlan) -> None:
    if _APPROVED_REVIEWER.fullmatch(plan.reviewed_by) is None:
        raise PolicyError("frozen PortCast plan is not independently approved")
    now = datetime.now(timezone.utc)
    start = datetime.fromisoformat(plan.window_start.replace("Z", "+00:00"))
    end = datetime.fromisoformat(plan.window_end.replace("Z", "+00:00"))
    if not start <= now <= end:
        raise PolicyError("frozen PortCast operating window is closed")


def _close_runtime(runtime: Runtime, primary: BaseException | None = None) -> None:
    """Close without hiding a primary failure or reporting uncertain cleanup."""

    try:
        runtime.close()
    except BaseException as cleanup_error:
        try:
            runtime.ledger.stop("PortCast runtime cleanup incomplete")
        except BaseException:
            pass
        if primary is not None:
            primary.add_note(
                "PortCast runtime cleanup also failed: "
                + type(cleanup_error).__name__
            )
            return
        raise PolicyError(
            "PortCast runtime cleanup incomplete; outcome uncertain"
        ) from cleanup_error


def _replay_metadata(
    runtime: Runtime, plan: FrozenPortcastPlan, runtime_root: Path
) -> dict[str, Any] | None:
    """Block both Ledger replay and audit-only interrupted action history."""

    history = runtime.audit.profile_action_history(plan.action_id)
    state = runtime.ledger.reservation_state(plan.action_id)
    if history:
        receipt = runtime.audit.profile_wire_receipts().get(plan.action_id)
        cleanup = runtime.audit.profile_cleanup_receipts().get(plan.action_id)
        return {
            "action_id": plan.action_id,
            "audit_verified": runtime.audit.verify().valid,
            "automatic_retry": False,
            "cleanup_status": (
                cleanup.get("status") if isinstance(cleanup, dict) else None
            ),
            "profile_id": plan.profile_id,
            "receipt_outcome": (
                receipt.get("outcome") if isinstance(receipt, dict) else None
            ),
            "status": "blocked",
            "workspace": str(runtime_root),
            "reason": "frozen action already has durable admission history",
        }

    try:
        result_receipts = runtime.audit.result_receipts()
    except PolicyError:
        runtime.ledger.stop("frozen PortCast audit history incomplete")
        return {
            "action_id": plan.action_id,
            "audit_verified": runtime.audit.verify().valid,
            "automatic_retry": False,
            "cleanup_status": None,
            "profile_id": plan.profile_id,
            "receipt_outcome": None,
            "status": "blocked",
            "workspace": str(runtime_root),
            "reason": "frozen action has incomplete durable audit history",
        }
    if state is None and plan.action_id not in result_receipts:
        return None
    receipt = runtime.audit.profile_wire_receipts().get(plan.action_id)
    cleanup = runtime.audit.profile_cleanup_receipts().get(plan.action_id)
    reason = (
        f"frozen action already has durable state {state}"
        if state is not None
        else "frozen action already has a durable result receipt"
    )
    return {
        "action_id": plan.action_id,
        "audit_verified": runtime.audit.verify().valid,
        "automatic_retry": False,
        "cleanup_status": (
            cleanup.get("status") if isinstance(cleanup, dict) else None
        ),
        "profile_id": plan.profile_id,
        "receipt_outcome": (
            receipt.get("outcome") if isinstance(receipt, dict) else None
        ),
        "status": "blocked",
        "workspace": str(runtime_root),
        "reason": reason,
    }


def _inspect_frozen_portcast_state_at_root(
    *,
    state_root: Path,
    age_binary: Path,
    age_recipient: str,
    provision: bool = True,
) -> dict[str, Any] | None:
    """Read replay state without opening the lab transport or a target channel."""

    plan = load_frozen_portcast_plan()
    verified = validate_current_release(plan)
    _require_open_window(plan)
    runtime_root, ledger_root = _prepare_runtime(
        state_root,
        plan,
        age_binary=age_binary,
        age_recipient=age_recipient,
        provision=provision,
    )
    runtime = Runtime(
        runtime_root, ledger_root=ledger_root, verified_release=verified
    )
    try:
        result = _replay_metadata(runtime, plan, runtime_root)
    except BaseException as primary:
        _close_runtime(runtime, primary)
        raise
    _close_runtime(runtime)
    return result


def _run_frozen_portcast_action_at_root(
    *,
    state_root: Path,
    age_binary: Path | None,
    age_recipient: str | None,
    clock_override: ClockState | None = None,
    wire_broker_factory=None,
    provision: bool = True,
) -> dict[str, Any]:
    """Execute the single frozen action and return metadata-only status."""

    plan = load_frozen_portcast_plan()
    verified = validate_current_release(plan)
    _require_open_window(plan)
    runtime_root, ledger_root = _prepare_runtime(
        state_root,
        plan,
        age_binary=age_binary,
        age_recipient=age_recipient,
        provision=provision,
    )
    runtime = Runtime(
        runtime_root,
        ledger_root=ledger_root,
        verified_release=verified,
    )
    if clock_override is not None:
        runtime.broker.clock = clock_override
    try:
        replay = _replay_metadata(runtime, plan, runtime_root)
        if replay is not None:
            outcome = replay
        else:
            if not callable(wire_broker_factory):
                raise PolicyError(
                    "canonical PortCast service broker factory is unavailable"
                )
            runtime.attach_profile_wire_broker(
                wire_broker_factory(runtime.ledger, verified)
            )
            runtime.audit.emit(
                AuditEvent(
                    "profile_release_verified",
                    plan.action_id,
                    {
                        "release_id": verified.release_id,
                        "manifest_sha256": verified.manifest_sha256,
                    },
                )
            )
            request = OperationRequest(
                plan.action_id,
                plan.workspace_id,
                plan.device_id,
                plan.operator_id,
                plan.module_id,
                _target(),
                {"profile_id": plan.profile_id},
                "operator",
                None,
                plan.policy_revision,
                plan.plan_id,
            )
            outcome = _execute_action(
                runtime,
                plan,
                request,
                runtime_root,
            )
    except BaseException as primary:
        _close_runtime(runtime, primary)
        raise
    _close_runtime(runtime)
    return outcome


def _execute_action(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    request: OperationRequest,
    runtime_root: Path,
) -> dict[str, Any]:
    """Execute after replay gates while the caller owns Runtime cleanup."""

    result = runtime.broker.execute(request, actor="operator")
    receipts = runtime.audit.profile_wire_receipts()
    receipt = receipts.get(plan.action_id)
    result_receipts = runtime.audit.result_receipts()
    cleanup_error = None
    try:
        runtime.close_profile_wire_broker()
    except PolicyError as error:
        cleanup_error = error
    if cleanup_error is not None:
        state = runtime.ledger.reservation_state(plan.action_id)
        if state in {"running", "dispatching"}:
            runtime.ledger.finish(plan.action_id, result.usage, state="uncertain")
        runtime.ledger.stop("PortCast broker cleanup failed")
        if isinstance(receipt, dict):
            runtime.audit.record_profile_cleanup_receipt(plan.action_id, "failed")
        return {
            "action_id": plan.action_id,
            "audit_verified": runtime.audit.verify().valid,
            "automatic_retry": False,
            "cleanup_status": "failed",
            "profile_id": plan.profile_id,
            "receipt_outcome": (
                receipt.get("outcome") if isinstance(receipt, dict) else None
            ),
            "status": "uncertain",
            "workspace": str(runtime_root),
            "reason": "PortCast broker cleanup failed; manual review required",
        }
    state = runtime.ledger.reservation_state(plan.action_id)
    if state in {"running", "dispatching"}:
        runtime.ledger.finish(plan.action_id, result.usage, state=result.status)
    if result.status == "complete":
        if (
            not isinstance(receipt, dict)
            or receipt.get("outcome") != "complete"
            or plan.action_id not in result_receipts
        ):
            runtime.ledger.stop("complete result lacks cross-checked receipts")
            raise PolicyError("complete PortCast result lacks durable receipts")
    cleanup_status = "passed"
    if isinstance(receipt, dict):
        try:
            runtime.audit.record_profile_cleanup_receipt(
                plan.action_id, cleanup_status
            )
        except Exception:
            runtime.ledger.stop("PortCast cleanup receipt audit failed")
            raise PolicyError(
                "PortCast cleanup receipt is unavailable; workspace stopped"
            ) from None
    return {
        "action_id": plan.action_id,
        "audit_verified": runtime.audit.verify().valid,
        "automatic_retry": False,
        "cleanup_status": cleanup_status,
        "profile_id": plan.profile_id,
        "receipt_outcome": receipt.get("outcome") if isinstance(receipt, dict) else None,
        "status": result.status,
        "workspace": str(runtime_root),
    }


def inspect_frozen_portcast_state() -> dict[str, Any] | None:
    """Inspect only the canonical service-owned production action state."""

    from cptc_harness.profile_runtime.service_client import PortcastServiceClient

    return PortcastServiceClient().inspect()


def run_frozen_portcast_action() -> dict[str, Any]:
    """Ask the separately deployed canonical authority to execute once."""

    from cptc_harness.profile_runtime.service_client import PortcastServiceClient

    return PortcastServiceClient().execute()


def run_frozen_portcast_session() -> dict[str, Any]:
    """Compatibility name for the metadata-only canonical service request."""

    return run_frozen_portcast_action()


__all__ = (
    "FrozenPortcastPlan",
    "inspect_frozen_portcast_state",
    "load_frozen_portcast_plan",
    "policy_for_plan",
    "run_frozen_portcast_action",
    "run_frozen_portcast_session",
    "validate_current_release",
)
