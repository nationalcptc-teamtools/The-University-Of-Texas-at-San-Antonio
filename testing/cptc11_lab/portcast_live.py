"""Frozen coordinator for the bounded CPTC11 PortCast observation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
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
    OperationResult,
    canonical_json,
    to_json,
)
from cptc_harness.policy import load_policy, policy_document
from cptc_harness.integrity import VerifiedRelease, verify_portcast_release
from cptc_harness.audit_readonly import (
    ExpectedProfileContinuationIdentity,
    verify_profile_continuation_snapshot,
)
from cptc_harness.ledger import Ledger, ProfileContinuationProof
from cptc_harness.profile_runtime.catalog import load_profile, require_live_admission
from cptc_harness.profile_runtime.contracts import PORTCAST_FAILURE_STAGES
from cptc_harness.registry import build_registry
from cptc_harness.runtime import Runtime, initialize
from cptc_harness.storage import (
    exclusive,
    private_directory,
    read_private,
    write_json,
)


_V4_PLAN_PATH = Path(__file__).with_name("portcast-live-plan-v4.json")
_V4_PLAN_CANONICAL_PATH = _V4_PLAN_PATH
_V5_PLAN_PATH = Path(__file__).with_name("portcast-live-plan-v5.json")
_V5_PLAN_CANONICAL_PATH = _V5_PLAN_PATH
_V6_PLAN_PATH = Path(__file__).with_name("portcast-live-plan-v6.json")
_V6_PLAN_CANONICAL_PATH = _V6_PLAN_PATH
_V7_PLAN_PATH = Path(__file__).with_name("portcast-live-plan-v7.json")
_V7_PLAN_CANONICAL_PATH = _V7_PLAN_PATH
_V3_PLAN_PATH = Path(__file__).with_name("portcast-live-plan-v3.json")
_PLAN_PATH = _V7_PLAN_PATH
_V1_PLAN_PATH = Path(__file__).with_name("portcast-live-plan-v1.json")
_V2_PLAN_PATH = Path(__file__).with_name("portcast-live-plan-v2.json")
_PREDECESSOR_PLAN_PATH = _V2_PLAN_PATH
_MAX_PLAN_BYTES = 32 * 1024
_PRODUCTION_RUNTIME_CONTAINER = Path(
    "/var/lib/cptc-harness/portcast-live-v1/runtime"
)
_ROOT_UID = 0
_ROOT_GID = 0
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_AGE_RECIPIENT = re.compile(r"^age1[0-9a-z]{50,80}$")
_APPROVED_REVIEWER = re.compile(
    r"^approved:[a-z0-9][a-z0-9._-]{2,63}$"
)
_V1_PLAN_FIELDS = frozenset(
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
        "evidence_recipient",
        "plan_sha256",
    }
)
_V2_PREDECESSOR_FIELDS = frozenset(
    {
        "predecessor_action_id",
        "predecessor_plan_id",
        "predecessor_plan_sha256",
        "predecessor_reconciliation_sha256",
        "predecessor_reason_code",
    }
)
_V2_PLAN_FIELDS = _V1_PLAN_FIELDS | _V2_PREDECESSOR_FIELDS
_V3_FIELDS = frozenset(
    {
        "workflow_id", "broker_worker_sha256", "profile_worker_sha256",
        "target_sha256", "request_sha256",
        "output_bytes", "tcp_connection_limit", "predecessor_engagement_id",
        "predecessor_action_sha256", "predecessor_broker_worker_sha256",
        "predecessor_profile_worker_sha256",
        "predecessor_release_manifest_sha256", "predecessor_target_sha256",
        "predecessor_request_sha256", "predecessor_output_bytes",
        "predecessor_v1_plan_file_sha256", "predecessor_v2_plan_file_sha256",
        "predecessor_reconciliation_reason", "predecessor_stop_reason",
        "predecessor_possible_tcp_connects",
        "predecessor_charged_tcp_connects",
    }
)
_V3_PLAN_FIELDS = (_V2_PLAN_FIELDS - {"predecessor_reason_code"}) | _V3_FIELDS
_V4_PREDECESSOR_FIELDS = frozenset(
    {
        "predecessor_v3_plan_file_sha256",
        "predecessor_v3_plan_sha256",
        "predecessor_v3_action_id",
        "predecessor_v3_engagement_id",
        "predecessor_v3_release_manifest_sha256",
        "predecessor_v3_worker_sha256",
        "predecessor_v3_broker_worker_sha256",
        "predecessor_v3_profile_worker_sha256",
        "predecessor_v3_target_sha256",
        "predecessor_v3_request_sha256",
        "predecessor_v3_output_bytes",
        "predecessor_v3_state_sha256",
        "predecessor_v3_failure_stage",
        "predecessor_v3_stop_reason",
        "predecessor_v3_broker_socket_opened",
        "predecessor_v3_credentials_loaded",
        "predecessor_v3_target_traffic",
        "predecessor_v3_first_byte_observed",
        "predecessor_v3_result_present",
        "predecessor_v3_possible_tcp_connects",
        "predecessor_v3_charged_tcp_connects",
    }
)
_V4_PLAN_FIELDS = _V3_PLAN_FIELDS | _V4_PREDECESSOR_FIELDS
_V5_PREDECESSOR_FIELDS = frozenset(
    {
        "predecessor_v4_plan_file_sha256",
        "predecessor_v4_plan_sha256",
        "predecessor_v4_action_id",
        "predecessor_v4_engagement_id",
        "predecessor_v4_release_manifest_sha256",
        "predecessor_v4_worker_sha256",
        "predecessor_v4_broker_worker_sha256",
        "predecessor_v4_profile_worker_sha256",
        "predecessor_v4_target_sha256",
        "predecessor_v4_request_sha256",
        "predecessor_v4_output_bytes",
        "predecessor_v4_state_sha256",
        "predecessor_v4_continuation_row_sha256",
        "predecessor_v4_failure_stage",
        "predecessor_v4_stop_reason",
        "predecessor_v4_broker_socket_opened",
        "predecessor_v4_credentials_loaded",
        "predecessor_v4_target_traffic",
        "predecessor_v4_first_byte_observed",
        "predecessor_v4_result_present",
        "predecessor_v4_possible_tcp_connects",
        "predecessor_v4_charged_tcp_connects",
    }
)
_V5_PLAN_FIELDS = _V4_PLAN_FIELDS | _V5_PREDECESSOR_FIELDS
_V6_PREDECESSOR_FIELDS = frozenset(
    {
        "predecessor_v5_plan_file_sha256",
        "predecessor_v5_plan_sha256",
        "predecessor_v5_action_id",
        "predecessor_v5_engagement_id",
        "predecessor_v5_release_manifest_sha256",
        "predecessor_v5_launcher_sha256",
        "predecessor_v5_service_unit_sha256",
        "predecessor_v5_worker_sha256",
        "predecessor_v5_broker_worker_sha256",
        "predecessor_v5_profile_worker_sha256",
        "predecessor_v5_target_sha256",
        "predecessor_v5_request_sha256",
        "predecessor_v5_output_bytes",
        "predecessor_v5_state_sha256",
        "predecessor_v5_admission_marker_sha256",
        "predecessor_v5_failure_at",
        "predecessor_v5_failure_stage",
        "predecessor_v5_stop_reason",
        "predecessor_v5_exec_start_pre_exit_status",
        "predecessor_v5_admission_marker_present",
        "predecessor_v5_projection_marker_present",
        "predecessor_v5_main_process_started",
        "predecessor_v5_application_credentials_loaded",
        "predecessor_v5_broker_socket_opened",
        "predecessor_v5_target_capability_created",
        "predecessor_v5_target_traffic",
        "predecessor_v5_first_byte_observed",
        "predecessor_v5_result_present",
        "predecessor_v5_possible_tcp_connects",
        "predecessor_v5_charged_tcp_connects",
    }
)
_V6_PLAN_FIELDS = _V5_PLAN_FIELDS | _V6_PREDECESSOR_FIELDS
_V7_SUPERSESSION_FIELDS = frozenset(
    {
        "superseded_v6_plan_file_sha256",
        "superseded_v6_plan_sha256",
        "superseded_v6_release_manifest_sha256",
        "superseded_v6_action_id",
        "superseded_v6_engagement_id",
        "superseded_v6_reviewed_at",
        "superseded_v6_reviewed_by",
        "superseded_v6_window_start",
        "superseded_v6_window_end",
        "superseded_v6_deployed",
        "superseded_v6_service_started",
        "superseded_v6_target_capability_created",
        "superseded_v6_target_traffic",
        "superseded_v6_reason",
        "superseded_v6_state_receipt_sha256",
        "superseded_v6_deployment_status",
        "superseded_v6_execution_status",
        "superseded_v6_result_present",
        "superseded_v6_possible_tcp_connects",
        "superseded_v6_charged_tcp_connects",
        "superseded_v6_first_byte_observed",
    }
)
_V7_PLAN_FIELDS = _V6_PLAN_FIELDS | _V7_SUPERSESSION_FIELDS
_PREDECESSOR_ENGAGEMENT_ID = "cptc11-dell-validation"
_PREDECESSOR_ACTION_ID = "cptc11-portcast-public-identity-action-v2"
_PREDECESSOR_PLAN_ID = "cptc11-portcast-public-identity-wave-v1"
_PREDECESSOR_RECONCILIATION_REASON = "clock-source-unavailable"
_PREDECESSOR_REASON = "clock is not safe for active work"
_PREDECESSOR_STOP_REASON = "transport outcome uncertain"
_V3_SUCCESSOR_ENGAGEMENT_ID = "cptc11-dell-validation-portcast-v3"
_V3_SUCCESSOR_ACTION_ID = "cptc11-portcast-public-identity-action-v3"
_V3_SUCCESSOR_PLAN_ID = "cptc11-portcast-public-identity-wave-v3"
_SUCCESSOR_ENGAGEMENT_ID = "cptc11-dell-validation-portcast-v4"
_SUCCESSOR_ACTION_ID = "cptc11-portcast-public-identity-action-v4"
_SUCCESSOR_PLAN_ID = "cptc11-portcast-public-identity-wave-v4"
_V5_SUCCESSOR_ENGAGEMENT_ID = "cptc11-dell-validation-portcast-v5"
_V5_SUCCESSOR_ACTION_ID = "cptc11-portcast-public-identity-action-v5"
_V5_SUCCESSOR_PLAN_ID = "cptc11-portcast-public-identity-wave-v5"
_V6_SUCCESSOR_ENGAGEMENT_ID = "cptc11-dell-validation-portcast-v6"
_V6_SUCCESSOR_ACTION_ID = "cptc11-portcast-public-identity-action-v6"
_V6_SUCCESSOR_PLAN_ID = "cptc11-portcast-public-identity-wave-v6"
_V7_SUCCESSOR_ENGAGEMENT_ID = "cptc11-dell-validation-portcast-v7"
_V7_SUCCESSOR_ACTION_ID = "cptc11-portcast-public-identity-action-v7"
_V7_SUCCESSOR_PLAN_ID = "cptc11-portcast-public-identity-wave-v7"
_WORKFLOW_ID = "cptc11-portcast-public-identity-wave-v1"
_V3_PLAN_FILE_SHA256 = (
    "bea58da1b695dc6e3d4ff681b2f784ee5d31a8466ba4a858df49afc308e3f64c"
)
_V3_PLAN_SHA256 = (
    "cb057ddfe09076b781fecb84f3172294ff3aa7409ee2544e52f30043a0dbe936"
)
_V4_PLAN_FILE_SHA256 = (
    "03aadcc20a8719f1ddfcc2f10434a9a0ec94cb1736cb94dbf5e22d1f1161648c"
)
_V4_PLAN_SHA256 = (
    "4a25ff68677a7d5d536fad3eb389b6bce0c3f131572b6e3225845d49d7921daa"
)
_V4_RELEASE_MANIFEST_SHA256 = (
    "62b8d5b369bc890e0b684c9210477b521fc47bf6aae5b0ad869bd0aa09062d09"
)
_V4_FAILURE_STAGE = "audit-worker-bind-runtime-v3"
_V4_STOP_REASON = "service startup failed before credential load"
_V4_REVIEWED_BY = "approved:luna-portcast-v4-release-review-r1"
_V4_WINDOW_START = "2026-09-12T05:00:00.000000Z"
_V4_WINDOW_END = "2026-09-12T11:00:00.000000Z"
_V5_REVIEWED_BY = "approved:luna-portcast-v5-release-review-r1"
_V5_WINDOW_START = "2026-09-12T06:00:00.000000Z"
_V5_WINDOW_END = "2026-09-12T11:00:00.000000Z"
_V5_PLAN_FILE_SHA256 = (
    "dcb908436af15c0945926cabd16d12df1a78064bb85b2d0d675682da5164d08b"
)
_V5_PLAN_SHA256 = (
    "8c519372e6a10b748c8dcffa128bdb00b03558594f5cd504ddd1e23f6f569ee9"
)
_V5_RELEASE_MANIFEST_SHA256 = (
    "4c9db1a159d7b1ca2ef38170458f32a2a17a6cd56d7c19e912a187cac138b918"
)
_V5_LAUNCHER_SHA256 = (
    "15deb8743ea56f07d7df0b4f98775ef7f050bf01f7aa15181ee95eaf44bd9fb0"
)
_V5_SERVICE_UNIT_SHA256 = (
    "259ac6be5da2a11913266310fc2bd56e8d8371f392cd67db3b2757632b908f2e"
)
_V5_ADMISSION_MARKER_SHA256 = (
    "6d4a1c0f18116b063bd7758e63cf3a33ca2f50f77137dbbcc7703a0126e718b5"
)
_V5_FAILURE_AT = "2026-09-12T08:20:07.741362Z"
_V5_FAILURE_STAGE = "start-admission-projection-write"
_V5_STOP_REASON = (
    "service pre-start failed after private admission marker before projection"
)
_V5_STATE_SHA256 = (
    "42fdd74d5b0c99a00a3f2761c1efcc3e3a579c86caf30c85bf01d34cf9400ffe"
)
_V6_PLAN_FILE_SHA256 = (
    "c2b4fad1f137d2c99a42a37f67773acdcfce9fe7a5983bf5d267082232120f71"
)
_V6_PLAN_SHA256 = (
    "d21dd898329ca575f2d7848896776140c863a39d3473d4720f0c4a24352b066b"
)
_V6_REVIEWED_BY = "approved:daybreak-portcast-v6-release-review-r1"
_V6_REVIEWED_AT = "2026-09-12T08:29:23.226576Z"
_V6_WINDOW_START = "2026-09-12T06:00:00.000000Z"
_V6_WINDOW_END = "2026-09-12T11:00:00.000000Z"
_V6_RELEASE_MANIFEST_SHA256 = (
    "154ad483d30f8f55cf15093a48614e37057a2c7f9e941e188d56caecccefea8f"
)
_V7_PLAN_FILE_SHA256 = (
    "662e32499606de86b1d2592a280f9065f791a22101c047f88bbec6c8caeaeb74"
)
_V7_PLAN_SHA256 = (
    "8cfb1e7b75f9496f235beb65f05c2577fdda4577620d58299cf90b644a3d2442"
)
_V6_UNUSED_RECEIPT_SHA256 = (
    "6ea2a1a73384bc0a37b52c9b61b5ec624ba3142135d7883470d68e868b765947"
)
_V7_REVIEWED_BY = "approved:astra-portcast-v7-release-review-r3"
_V7_REVIEWED_AT = "2026-09-22T06:16:46.000000Z"
_V7_WINDOW_START = "2026-09-22T05:00:00.000000Z"
_V7_WINDOW_END = "2026-09-23T05:00:00.000000Z"
_V7_SUPERSESSION_REASON = "operating window expired before deployment"


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


def _read_plan_file(
    path: Path = _PLAN_PATH,
    fields: frozenset[str] = _V4_PLAN_FIELDS,
) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink():
        raise PolicyError("frozen PortCast plan symlink rejected")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
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
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise PolicyError("frozen PortCast plan fields differ")
    return value, raw


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
    evidence_recipient: str
    workflow_id: str
    broker_worker_sha256: str
    profile_worker_sha256: str
    target_sha256: str
    request_sha256: str
    output_bytes: int
    tcp_connection_limit: int
    predecessor_engagement_id: str
    predecessor_action_id: str
    predecessor_plan_id: str
    predecessor_plan_sha256: str
    predecessor_reconciliation_sha256: str
    predecessor_action_sha256: str
    predecessor_broker_worker_sha256: str
    predecessor_profile_worker_sha256: str
    predecessor_release_manifest_sha256: str
    predecessor_target_sha256: str
    predecessor_request_sha256: str
    predecessor_output_bytes: int
    predecessor_v1_plan_file_sha256: str
    predecessor_v2_plan_file_sha256: str
    predecessor_reconciliation_reason: str
    predecessor_stop_reason: str
    predecessor_possible_tcp_connects: int
    predecessor_charged_tcp_connects: int
    plan_sha256: str
    predecessor_reason_code: str | None = None
    predecessor_v3_plan_file_sha256: str | None = None
    predecessor_v3_plan_sha256: str | None = None
    predecessor_v3_action_id: str | None = None
    predecessor_v3_engagement_id: str | None = None
    predecessor_v3_release_manifest_sha256: str | None = None
    predecessor_v3_worker_sha256: str | None = None
    predecessor_v3_broker_worker_sha256: str | None = None
    predecessor_v3_profile_worker_sha256: str | None = None
    predecessor_v3_target_sha256: str | None = None
    predecessor_v3_request_sha256: str | None = None
    predecessor_v3_output_bytes: int | None = None
    predecessor_v3_state_sha256: str | None = None
    predecessor_v3_failure_stage: str | None = None
    predecessor_v3_stop_reason: str | None = None
    predecessor_v3_broker_socket_opened: bool | None = None
    predecessor_v3_credentials_loaded: bool | None = None
    predecessor_v3_target_traffic: bool | None = None
    predecessor_v3_first_byte_observed: bool | None = None
    predecessor_v3_result_present: bool | None = None
    predecessor_v3_possible_tcp_connects: int | None = None
    predecessor_v3_charged_tcp_connects: int | None = None
    predecessor_v4_plan_file_sha256: str | None = None
    predecessor_v4_plan_sha256: str | None = None
    predecessor_v4_action_id: str | None = None
    predecessor_v4_engagement_id: str | None = None
    predecessor_v4_release_manifest_sha256: str | None = None
    predecessor_v4_worker_sha256: str | None = None
    predecessor_v4_broker_worker_sha256: str | None = None
    predecessor_v4_profile_worker_sha256: str | None = None
    predecessor_v4_target_sha256: str | None = None
    predecessor_v4_request_sha256: str | None = None
    predecessor_v4_output_bytes: int | None = None
    predecessor_v4_state_sha256: str | None = None
    predecessor_v4_continuation_row_sha256: str | None = None
    predecessor_v4_failure_stage: str | None = None
    predecessor_v4_stop_reason: str | None = None
    predecessor_v4_broker_socket_opened: bool | None = None
    predecessor_v4_credentials_loaded: bool | None = None
    predecessor_v4_target_traffic: bool | None = None
    predecessor_v4_first_byte_observed: bool | None = None
    predecessor_v4_result_present: bool | None = None
    predecessor_v4_possible_tcp_connects: int | None = None
    predecessor_v4_charged_tcp_connects: int | None = None
    predecessor_v5_plan_file_sha256: str | None = None
    predecessor_v5_plan_sha256: str | None = None
    predecessor_v5_action_id: str | None = None
    predecessor_v5_engagement_id: str | None = None
    predecessor_v5_release_manifest_sha256: str | None = None
    predecessor_v5_launcher_sha256: str | None = None
    predecessor_v5_service_unit_sha256: str | None = None
    predecessor_v5_worker_sha256: str | None = None
    predecessor_v5_broker_worker_sha256: str | None = None
    predecessor_v5_profile_worker_sha256: str | None = None
    predecessor_v5_target_sha256: str | None = None
    predecessor_v5_request_sha256: str | None = None
    predecessor_v5_output_bytes: int | None = None
    predecessor_v5_state_sha256: str | None = None
    predecessor_v5_admission_marker_sha256: str | None = None
    predecessor_v5_failure_at: str | None = None
    predecessor_v5_failure_stage: str | None = None
    predecessor_v5_stop_reason: str | None = None
    predecessor_v5_exec_start_pre_exit_status: int | None = None
    predecessor_v5_admission_marker_present: bool | None = None
    predecessor_v5_projection_marker_present: bool | None = None
    predecessor_v5_main_process_started: bool | None = None
    predecessor_v5_application_credentials_loaded: bool | None = None
    predecessor_v5_broker_socket_opened: bool | None = None
    predecessor_v5_target_capability_created: bool | None = None
    predecessor_v5_target_traffic: bool | None = None
    predecessor_v5_first_byte_observed: bool | None = None
    predecessor_v5_result_present: bool | None = None
    predecessor_v5_possible_tcp_connects: int | None = None
    predecessor_v5_charged_tcp_connects: int | None = None
    superseded_v6_plan_file_sha256: str | None = None
    superseded_v6_plan_sha256: str | None = None
    superseded_v6_release_manifest_sha256: str | None = None
    superseded_v6_action_id: str | None = None
    superseded_v6_engagement_id: str | None = None
    superseded_v6_reviewed_at: str | None = None
    superseded_v6_reviewed_by: str | None = None
    superseded_v6_window_start: str | None = None
    superseded_v6_window_end: str | None = None
    superseded_v6_deployed: bool | None = None
    superseded_v6_service_started: bool | None = None
    superseded_v6_target_capability_created: bool | None = None
    superseded_v6_target_traffic: bool | None = None
    superseded_v6_reason: str | None = None
    superseded_v6_state_receipt_sha256: str | None = None
    superseded_v6_deployment_status: str | None = None
    superseded_v6_execution_status: str | None = None
    superseded_v6_result_present: bool | None = None
    superseded_v6_possible_tcp_connects: int | None = None
    superseded_v6_charged_tcp_connects: int | None = None
    superseded_v6_first_byte_observed: bool | None = None


def _load_continuation_plan(
    path: Path,
    fields: frozenset[str],
    *,
    schema_version: int,
    engagement_id: str,
    action_id: str,
    plan_id: str,
    raw_sha256: str | None = None,
) -> FrozenPortcastPlan:
    value, raw = _read_plan_file(path, fields)
    if raw_sha256 is not None and hashlib.sha256(raw).hexdigest() != raw_sha256:
        raise PolicyError("frozen PortCast plan file hash differs")
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
    if plan.schema_version != schema_version or any(
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
            "workflow_id",
            "predecessor_engagement_id",
            "predecessor_action_id",
            "predecessor_plan_id",
            "predecessor_reconciliation_reason",
            "predecessor_stop_reason",
        )
    ):
        raise PolicyError("frozen PortCast plan identity differs")
    if (
        plan.request_count != 1
        or plan.automatic_retries != 0
        or plan.authentication_attempts != 0
        or plan.output_bytes != 16384
        or plan.tcp_connection_limit != 1
        or plan.predecessor_output_bytes != 16384
        or plan.predecessor_possible_tcp_connects != 1
        or plan.predecessor_charged_tcp_connects != 1
        or any(type(value) is not int for value in (
            plan.request_count,
            plan.automatic_retries,
            plan.authentication_attempts,
            plan.output_bytes,
            plan.tcp_connection_limit,
            plan.predecessor_output_bytes,
            plan.predecessor_possible_tcp_connects,
            plan.predecessor_charged_tcp_connects,
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
    if _AGE_RECIPIENT.fullmatch(plan.evidence_recipient) is None:
        raise PolicyError("frozen PortCast evidence recipient differs")
    if (
        plan.engagement_id != engagement_id
        or plan.action_id != action_id
        or plan.plan_id != plan_id
        or plan.workflow_id != _WORKFLOW_ID
        or plan.predecessor_engagement_id != _PREDECESSOR_ENGAGEMENT_ID
        or plan.predecessor_action_id != _PREDECESSOR_ACTION_ID
        or plan.predecessor_plan_id != _PREDECESSOR_PLAN_ID
        or plan.predecessor_reconciliation_reason
        != _PREDECESSOR_RECONCILIATION_REASON
        or plan.predecessor_stop_reason != _PREDECESSOR_STOP_REASON
        or plan.action_id == plan.predecessor_action_id
    ):
        raise PolicyError("frozen PortCast predecessor binding differs")
    for value in (
        plan.predecessor_plan_sha256,
        plan.predecessor_reconciliation_sha256,
        plan.predecessor_action_sha256,
        plan.predecessor_broker_worker_sha256,
        plan.predecessor_profile_worker_sha256,
        plan.predecessor_release_manifest_sha256,
        plan.predecessor_target_sha256,
        plan.predecessor_request_sha256,
        plan.predecessor_v1_plan_file_sha256,
        plan.predecessor_v2_plan_file_sha256,
        plan.broker_worker_sha256,
        plan.profile_worker_sha256,
        plan.target_sha256,
        plan.request_sha256,
    ):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise PolicyError("frozen PortCast predecessor digest differs")

    _read_predecessor_plan(plan)
    _expected_predecessor_identity(plan)
    _require_successor_request_binding(plan)
    return plan


def load_frozen_portcast_plan_v4() -> FrozenPortcastPlan:
    """Load the immutable v4 plan only for history and predecessor checks."""

    plan = _load_continuation_plan(
        _V4_PLAN_PATH,
        _V4_PLAN_FIELDS,
        schema_version=4,
        engagement_id=_SUCCESSOR_ENGAGEMENT_ID,
        action_id=_SUCCESSOR_ACTION_ID,
        plan_id=_SUCCESSOR_PLAN_ID,
        raw_sha256=(
            _V4_PLAN_FILE_SHA256
            if _V4_PLAN_PATH == _V4_PLAN_CANONICAL_PATH
            else None
        ),
    )
    if (
        _V4_PLAN_PATH == _V4_PLAN_CANONICAL_PATH
        and plan.plan_sha256 != _V4_PLAN_SHA256
    ):
        raise PolicyError("frozen PortCast v4 plan identity differs")
    if (
        plan.reviewed_by != _V4_REVIEWED_BY
        or plan.window_start != _V4_WINDOW_START
        or plan.window_end != _V4_WINDOW_END
    ):
        raise PolicyError("frozen PortCast v4 approval differs")
    digest_fields = (
        plan.predecessor_v3_plan_file_sha256,
        plan.predecessor_v3_plan_sha256,
        plan.predecessor_v3_release_manifest_sha256,
        plan.predecessor_v3_worker_sha256,
        plan.predecessor_v3_broker_worker_sha256,
        plan.predecessor_v3_profile_worker_sha256,
        plan.predecessor_v3_target_sha256,
        plan.predecessor_v3_request_sha256,
        plan.predecessor_v3_state_sha256,
    )
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in digest_fields
    ):
        raise PolicyError("frozen PortCast v3 predecessor digest differs")
    if (
        plan.predecessor_v3_plan_file_sha256 != _V3_PLAN_FILE_SHA256
        or plan.predecessor_v3_plan_sha256 != _V3_PLAN_SHA256
        or plan.predecessor_v3_action_id != _V3_SUCCESSOR_ACTION_ID
        or plan.predecessor_v3_engagement_id != _V3_SUCCESSOR_ENGAGEMENT_ID
        or plan.predecessor_v3_output_bytes != 16384
        or plan.predecessor_v3_failure_stage
        != "continuation-verification-before-credential-load"
        or plan.predecessor_v3_stop_reason
        != "service startup failed before target capability creation"
        or plan.predecessor_v3_broker_socket_opened is not False
        or plan.predecessor_v3_credentials_loaded is not False
        or plan.predecessor_v3_target_traffic is not False
        or plan.predecessor_v3_first_byte_observed is not False
        or plan.predecessor_v3_result_present is not False
        or plan.predecessor_v3_possible_tcp_connects != 0
        or plan.predecessor_v3_charged_tcp_connects != 0
        or any(
            type(value) is not int
            for value in (
                plan.predecessor_v3_output_bytes,
                plan.predecessor_v3_possible_tcp_connects,
                plan.predecessor_v3_charged_tcp_connects,
            )
        )
    ):
        raise PolicyError("frozen PortCast v3 predecessor binding differs")
    return plan


def load_frozen_portcast_plan_v5() -> FrozenPortcastPlan:
    """Load the immutable v5 plan only for history and predecessor checks."""

    path = _V5_PLAN_PATH
    plan = _load_continuation_plan(
        path,
        _V5_PLAN_FIELDS,
        schema_version=5,
        engagement_id=_V5_SUCCESSOR_ENGAGEMENT_ID,
        action_id=_V5_SUCCESSOR_ACTION_ID,
        plan_id=_V5_SUCCESSOR_PLAN_ID,
        raw_sha256=(
            _V5_PLAN_FILE_SHA256 if path == _V5_PLAN_CANONICAL_PATH else None
        ),
    )
    if (
        path == _V5_PLAN_CANONICAL_PATH
        and plan.plan_sha256 != _V5_PLAN_SHA256
    ):
        raise PolicyError("frozen PortCast v5 plan identity differs")
    digest_fields = (
        plan.predecessor_v4_plan_file_sha256,
        plan.predecessor_v4_plan_sha256,
        plan.predecessor_v4_release_manifest_sha256,
        plan.predecessor_v4_worker_sha256,
        plan.predecessor_v4_broker_worker_sha256,
        plan.predecessor_v4_profile_worker_sha256,
        plan.predecessor_v4_target_sha256,
        plan.predecessor_v4_request_sha256,
        plan.predecessor_v4_state_sha256,
        plan.predecessor_v4_continuation_row_sha256,
    )
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in digest_fields
    ):
        raise PolicyError("frozen PortCast v4 predecessor digest differs")
    if (
        plan.predecessor_v4_plan_file_sha256 != _V4_PLAN_FILE_SHA256
        or plan.predecessor_v4_plan_sha256 != _V4_PLAN_SHA256
        or plan.predecessor_v4_action_id != _SUCCESSOR_ACTION_ID
        or plan.predecessor_v4_engagement_id != _SUCCESSOR_ENGAGEMENT_ID
        or plan.predecessor_v4_output_bytes != 16384
        or plan.predecessor_v4_broker_socket_opened is not False
        or plan.predecessor_v4_credentials_loaded is not False
        or plan.predecessor_v4_target_traffic is not False
        or plan.predecessor_v4_first_byte_observed is not False
        or plan.predecessor_v4_result_present is not False
        or plan.predecessor_v4_possible_tcp_connects != 0
        or plan.predecessor_v4_charged_tcp_connects != 0
        or any(
            type(value) is not int
            for value in (
                plan.predecessor_v4_output_bytes,
                plan.predecessor_v4_possible_tcp_connects,
                plan.predecessor_v4_charged_tcp_connects,
            )
        )
    ):
        raise PolicyError("frozen PortCast v4 predecessor binding differs")
    if (
        plan.reviewed_by != _V5_REVIEWED_BY
        or plan.window_start != _V5_WINDOW_START
        or plan.window_end != _V5_WINDOW_END
    ):
        raise PolicyError("frozen PortCast v5 approval differs")
    v4 = load_frozen_portcast_plan_v4()
    for field in (
        "policy_revision", "workspace_id", "device_id", "operator_id",
        "profile_id", "module_id", "target_id", "catalog_sha256",
        "profile_sha256", "operation_sha256", "parser_sha256",
        "runtime_pinset_sha256", "release_id", "evidence_recipient",
    ):
        if getattr(plan, field) != getattr(v4, field):
            raise PolicyError("frozen PortCast v4 predecessor scope differs")
    if plan.predecessor_v4_worker_sha256 != v4.worker_sha256:
        raise PolicyError("frozen PortCast v4 predecessor worker differs")
    if plan.predecessor_v4_release_manifest_sha256 != _V4_RELEASE_MANIFEST_SHA256:
        raise PolicyError("frozen PortCast v4 predecessor release differs")
    if plan.predecessor_v4_profile_worker_sha256 != v4.profile_worker_sha256:
        raise PolicyError("frozen PortCast v4 predecessor profile worker differs")
    if plan.predecessor_v4_broker_worker_sha256 != v4.broker_worker_sha256:
        raise PolicyError("frozen PortCast v4 predecessor broker worker differs")
    if plan.predecessor_v4_target_sha256 != v4.target_sha256:
        raise PolicyError("frozen PortCast v4 predecessor target differs")
    if plan.predecessor_v4_request_sha256 != v4.request_sha256:
        raise PolicyError("frozen PortCast v4 predecessor request differs")
    if plan.predecessor_v4_failure_stage != _V4_FAILURE_STAGE:
        raise PolicyError("frozen PortCast v4 predecessor failure stage differs")
    if plan.predecessor_v4_stop_reason != _V4_STOP_REASON:
        raise PolicyError("frozen PortCast v4 predecessor stop reason differs")
    if (
        plan.predecessor_charged_tcp_connects
        + (plan.predecessor_v3_charged_tcp_connects or 0)
        + plan.predecessor_v4_charged_tcp_connects
        + plan.tcp_connection_limit
        != 2
    ):
        raise PolicyError("frozen PortCast cumulative TCP allowance differs")
    return plan


def load_frozen_portcast_plan_v6() -> FrozenPortcastPlan:
    """Load the immutable v6 admission only as superseded history."""

    path = _V6_PLAN_PATH
    plan = _load_continuation_plan(
        path,
        _V6_PLAN_FIELDS,
        schema_version=6,
        engagement_id=_V6_SUCCESSOR_ENGAGEMENT_ID,
        action_id=_V6_SUCCESSOR_ACTION_ID,
        plan_id=_V6_SUCCESSOR_PLAN_ID,
        raw_sha256=(
            _V6_PLAN_FILE_SHA256 if path == _V6_PLAN_CANONICAL_PATH else None
        ),
    )
    if (
        path == _V6_PLAN_CANONICAL_PATH
        and plan.plan_sha256 != _V6_PLAN_SHA256
    ):
        raise PolicyError("frozen PortCast v6 plan identity differs")
    digest_fields = (
        plan.predecessor_v5_plan_file_sha256,
        plan.predecessor_v5_plan_sha256,
        plan.predecessor_v5_release_manifest_sha256,
        plan.predecessor_v5_launcher_sha256,
        plan.predecessor_v5_service_unit_sha256,
        plan.predecessor_v5_worker_sha256,
        plan.predecessor_v5_broker_worker_sha256,
        plan.predecessor_v5_profile_worker_sha256,
        plan.predecessor_v5_target_sha256,
        plan.predecessor_v5_request_sha256,
        plan.predecessor_v5_state_sha256,
        plan.predecessor_v5_admission_marker_sha256,
    )
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in digest_fields
    ):
        raise PolicyError("frozen PortCast v5 predecessor digest differs")
    if (
        plan.predecessor_v5_plan_file_sha256 != _V5_PLAN_FILE_SHA256
        or plan.predecessor_v5_plan_sha256 != _V5_PLAN_SHA256
        or plan.predecessor_v5_action_id != _V5_SUCCESSOR_ACTION_ID
        or plan.predecessor_v5_engagement_id != _V5_SUCCESSOR_ENGAGEMENT_ID
        or plan.predecessor_v5_release_manifest_sha256
        != _V5_RELEASE_MANIFEST_SHA256
        or plan.predecessor_v5_launcher_sha256 != _V5_LAUNCHER_SHA256
        or plan.predecessor_v5_service_unit_sha256 != _V5_SERVICE_UNIT_SHA256
        or plan.predecessor_v5_state_sha256 != _V5_STATE_SHA256
        or plan.predecessor_v5_admission_marker_sha256
        != _V5_ADMISSION_MARKER_SHA256
        or plan.predecessor_v5_failure_at != _V5_FAILURE_AT
        or plan.predecessor_v5_failure_stage != _V5_FAILURE_STAGE
        or plan.predecessor_v5_stop_reason != _V5_STOP_REASON
        or plan.predecessor_v5_exec_start_pre_exit_status != 126
        or plan.predecessor_v5_output_bytes != 16384
        or plan.predecessor_v5_admission_marker_present is not True
        or plan.predecessor_v5_projection_marker_present is not False
        or plan.predecessor_v5_main_process_started is not False
        or plan.predecessor_v5_application_credentials_loaded is not False
        or plan.predecessor_v5_broker_socket_opened is not False
        or plan.predecessor_v5_target_capability_created is not False
        or plan.predecessor_v5_target_traffic is not False
        or plan.predecessor_v5_first_byte_observed is not False
        or plan.predecessor_v5_result_present is not False
        or plan.predecessor_v5_possible_tcp_connects != 0
        or plan.predecessor_v5_charged_tcp_connects != 0
        or any(
            type(value) is not int
            for value in (
                plan.predecessor_v5_exec_start_pre_exit_status,
                plan.predecessor_v5_output_bytes,
                plan.predecessor_v5_possible_tcp_connects,
                plan.predecessor_v5_charged_tcp_connects,
            )
        )
    ):
        raise PolicyError("frozen PortCast v5 predecessor binding differs")
    if (
        plan.reviewed_by != _V6_REVIEWED_BY
        or plan.reviewed_at != _V6_REVIEWED_AT
        or plan.window_start != _V6_WINDOW_START
        or plan.window_end != _V6_WINDOW_END
    ):
        raise PolicyError("frozen PortCast v6 approval differs")
    v5 = load_frozen_portcast_plan_v5()
    for field in (
        "policy_revision", "workspace_id", "device_id", "operator_id",
        "profile_id", "module_id", "target_id", "catalog_sha256",
        "profile_sha256", "operation_sha256", "parser_sha256",
        "runtime_pinset_sha256", "release_id", "evidence_recipient",
        "workflow_id",
    ):
        if getattr(plan, field) != getattr(v5, field):
            raise PolicyError("frozen PortCast v5 predecessor scope differs")
    for field in (
        "worker_sha256", "broker_worker_sha256", "profile_worker_sha256",
        "target_sha256", "request_sha256",
    ):
        if getattr(plan, f"predecessor_v5_{field}") != getattr(v5, field):
            raise PolicyError("frozen PortCast v5 predecessor release differs")
    if (
        plan.predecessor_charged_tcp_connects
        + (plan.predecessor_v3_charged_tcp_connects or 0)
        + (plan.predecessor_v4_charged_tcp_connects or 0)
        + plan.predecessor_v5_charged_tcp_connects
        + plan.tcp_connection_limit
        != 2
    ):
        raise PolicyError("frozen PortCast cumulative TCP allowance differs")
    return plan


def load_frozen_portcast_plan_v7() -> FrozenPortcastPlan:
    """Load the current immutable schema-v7 admission."""

    path = _V7_PLAN_PATH
    plan = _load_continuation_plan(
        path,
        _V7_PLAN_FIELDS,
        schema_version=7,
        engagement_id=_V7_SUCCESSOR_ENGAGEMENT_ID,
        action_id=_V7_SUCCESSOR_ACTION_ID,
        plan_id=_V7_SUCCESSOR_PLAN_ID,
        raw_sha256=(
            _V7_PLAN_FILE_SHA256 if path == _V7_PLAN_CANONICAL_PATH else None
        ),
    )
    if (
        path == _V7_PLAN_CANONICAL_PATH
        and plan.plan_sha256 != _V7_PLAN_SHA256
    ):
        raise PolicyError("frozen PortCast v7 plan identity differs")
    for value in (
        plan.superseded_v6_plan_file_sha256,
        plan.superseded_v6_plan_sha256,
        plan.superseded_v6_release_manifest_sha256,
        plan.superseded_v6_state_receipt_sha256,
    ):
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise PolicyError("frozen PortCast v6 supersession digest differs")
    if (
        plan.superseded_v6_plan_file_sha256 != _V6_PLAN_FILE_SHA256
        or plan.superseded_v6_plan_sha256 != _V6_PLAN_SHA256
        or plan.superseded_v6_release_manifest_sha256
        != _V6_RELEASE_MANIFEST_SHA256
        or plan.superseded_v6_action_id != _V6_SUCCESSOR_ACTION_ID
        or plan.superseded_v6_engagement_id != _V6_SUCCESSOR_ENGAGEMENT_ID
        or plan.superseded_v6_reviewed_at != _V6_REVIEWED_AT
        or plan.superseded_v6_reviewed_by != _V6_REVIEWED_BY
        or plan.superseded_v6_window_start != _V6_WINDOW_START
        or plan.superseded_v6_window_end != _V6_WINDOW_END
        or plan.superseded_v6_deployed is not False
        or plan.superseded_v6_service_started is not False
        or plan.superseded_v6_target_capability_created is not False
        or plan.superseded_v6_target_traffic is not False
        or plan.superseded_v6_reason != _V7_SUPERSESSION_REASON
        or plan.superseded_v6_state_receipt_sha256
        != _V6_UNUSED_RECEIPT_SHA256
        or plan.superseded_v6_deployment_status != "never-deployed"
        or plan.superseded_v6_execution_status != "never-run"
        or plan.superseded_v6_result_present is not False
        or plan.superseded_v6_possible_tcp_connects != 0
        or plan.superseded_v6_charged_tcp_connects != 0
        or plan.superseded_v6_first_byte_observed is not False
        or type(plan.superseded_v6_possible_tcp_connects) is not int
        or type(plan.superseded_v6_charged_tcp_connects) is not int
    ):
        raise PolicyError("frozen PortCast v6 supersession binding differs")
    if (
        plan.reviewed_by != _V7_REVIEWED_BY
        or plan.reviewed_at != _V7_REVIEWED_AT
        or plan.window_start != _V7_WINDOW_START
        or plan.window_end != _V7_WINDOW_END
    ):
        raise PolicyError("frozen PortCast v7 approval differs")
    v6 = load_frozen_portcast_plan_v6()
    for field in (
        "policy_revision", "workspace_id", "device_id", "operator_id",
        "profile_id", "module_id", "target_id", "catalog_sha256",
        "profile_sha256", "operation_sha256", "parser_sha256",
        "runtime_pinset_sha256", "release_id", "evidence_recipient",
        "workflow_id", "target_sha256",
    ):
        if getattr(plan, field) != getattr(v6, field):
            raise PolicyError("frozen PortCast v6 superseded scope differs")
    if plan.window_start <= plan.superseded_v6_window_end:
        raise PolicyError("frozen PortCast v7 window does not follow v6")
    if (
        plan.predecessor_charged_tcp_connects
        + (plan.predecessor_v3_charged_tcp_connects or 0)
        + (plan.predecessor_v4_charged_tcp_connects or 0)
        + (plan.predecessor_v5_charged_tcp_connects or 0)
        + plan.tcp_connection_limit
        != 2
    ):
        raise PolicyError("frozen PortCast cumulative TCP allowance differs")
    return plan


def load_frozen_portcast_plan() -> FrozenPortcastPlan:
    """Load the current immutable schema-v7 admission."""

    return load_frozen_portcast_plan_v7()


def load_frozen_portcast_plan_v3() -> FrozenPortcastPlan:
    """Load the immutable v3 plan only for history and predecessor checks."""

    plan = _load_continuation_plan(
        _V3_PLAN_PATH,
        _V3_PLAN_FIELDS,
        schema_version=3,
        engagement_id=_V3_SUCCESSOR_ENGAGEMENT_ID,
        action_id=_V3_SUCCESSOR_ACTION_ID,
        plan_id=_V3_SUCCESSOR_PLAN_ID,
        raw_sha256=_V3_PLAN_FILE_SHA256,
    )
    if plan.plan_sha256 != _V3_PLAN_SHA256:
        raise PolicyError("frozen PortCast v3 plan identity differs")
    return plan


def load_frozen_portcast_plan_v2() -> FrozenPortcastPlan:
    """Load the immutable v2 plan only for legacy regression fixtures."""

    path = _V2_PLAN_PATH
    if path.is_symlink():
        raise PolicyError("frozen PortCast v2 plan symlink rejected")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise PolicyError("frozen PortCast v2 plan is unavailable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= _MAX_PLAN_BYTES:
            raise PolicyError("frozen PortCast v2 plan file is invalid")
        raw = os.read(descriptor, _MAX_PLAN_BYTES + 1)
        if len(raw) != info.st_size:
            raise PolicyError("frozen PortCast v2 plan changed during read")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PolicyError("frozen PortCast v2 plan JSON is invalid") from None
    if not isinstance(value, dict) or frozenset(value) != _V2_PLAN_FIELDS:
        raise PolicyError("frozen PortCast v2 plan fields differ")
    unsigned = dict(value)
    supplied_hash = unsigned.pop("plan_sha256")
    if hashlib.sha256(_canonical(unsigned)).hexdigest() != supplied_hash:
        raise PolicyError("frozen PortCast v2 plan hash differs")
    if (
        hashlib.sha256(raw).hexdigest()
        != "1ebe09e1db61a573abd840d90a2fbf52d6315e7d3bdd68ea8a32a7c1b1f023ce"
        or value["schema_version"] != 2
        or value["engagement_id"] != _PREDECESSOR_ENGAGEMENT_ID
        or value["action_id"] != _PREDECESSOR_ACTION_ID
        or value["plan_id"] != _PREDECESSOR_PLAN_ID
        or value["predecessor_reason_code"]
        != _PREDECESSOR_RECONCILIATION_REASON
    ):
        raise PolicyError("frozen PortCast v2 plan identity differs")
    target_sha256 = hashlib.sha256(
        canonical_json(to_json(_target()))
    ).hexdigest()
    request_sha256 = hashlib.sha256(
        canonical_json(
            to_json(
                OperationRequest(
                    value["action_id"],
                    value["workspace_id"],
                    value["device_id"],
                    value["operator_id"],
                    value["module_id"],
                    _target(),
                    {"profile_id": value["profile_id"]},
                    "operator",
                    None,
                    value["policy_revision"],
                    value["plan_id"],
                )
            )
        )
    ).hexdigest()
    extensions = {
        "workflow_id": value["plan_id"],
        "broker_worker_sha256": (
            "1d304aaca61d0e6c52b30433f3fd245e56c95a6f15b26616f8571b2175454441"
        ),
        "profile_worker_sha256": value["worker_sha256"],
        "target_sha256": target_sha256,
        "request_sha256": request_sha256,
        "output_bytes": 16384,
        "tcp_connection_limit": 1,
        "predecessor_engagement_id": value["engagement_id"],
        "predecessor_action_sha256": "0" * 64,
        "predecessor_broker_worker_sha256": "0" * 64,
        "predecessor_profile_worker_sha256": "0" * 64,
        "predecessor_release_manifest_sha256": (
            "6bc14700871cb0e9aab47d056931d582507471d6d24138b533848a02f80afc0e"
        ),
        "predecessor_target_sha256": target_sha256,
        "predecessor_request_sha256": request_sha256,
        "predecessor_output_bytes": 16384,
        "predecessor_v1_plan_file_sha256": (
            "1de39a00a6ccbbc9d8bf7a4c8f1711d7989532b19dec99a93d808e5354147256"
        ),
        "predecessor_v2_plan_file_sha256": (
            "1ebe09e1db61a573abd840d90a2fbf52d6315e7d3bdd68ea8a32a7c1b1f023ce"
        ),
        "predecessor_reconciliation_reason": value[
            "predecessor_reason_code"
        ],
        "predecessor_stop_reason": _PREDECESSOR_STOP_REASON,
        "predecessor_possible_tcp_connects": 0,
        "predecessor_charged_tcp_connects": 0,
    }
    return FrozenPortcastPlan(**value, **extensions)


def _read_predecessor_plan(plan: FrozenPortcastPlan) -> dict[str, Any]:
    """Read and cross-bind every immutable predecessor plan file."""

    def read(path: Path, fields: frozenset[str], expected_sha256: str) -> dict[str, Any]:
        if path.is_symlink():
            raise PolicyError("frozen PortCast predecessor plan symlink rejected")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError:
            raise PolicyError("frozen PortCast predecessor plan is unavailable") from None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= _MAX_PLAN_BYTES:
                raise PolicyError("frozen PortCast predecessor plan file is invalid")
            raw = os.read(descriptor, _MAX_PLAN_BYTES + 1)
            if len(raw) != info.st_size:
                raise PolicyError("frozen PortCast predecessor plan changed during read")
        finally:
            os.close(descriptor)
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise PolicyError("frozen PortCast predecessor plan file hash differs")
        try:
            value = json.loads(raw, object_pairs_hook=_pairs)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise PolicyError("frozen PortCast predecessor plan JSON is invalid") from None
        if not isinstance(value, dict) or frozenset(value) != fields:
            raise PolicyError("frozen PortCast predecessor plan fields differ")
        unsigned = dict(value)
        supplied = unsigned.pop("plan_sha256", None)
        if hashlib.sha256(_canonical(unsigned)).hexdigest() != supplied:
            raise PolicyError("frozen PortCast predecessor plan hash differs")
        return value

    v1 = read(_V1_PLAN_PATH, _V1_PLAN_FIELDS, plan.predecessor_v1_plan_file_sha256)
    v2 = read(_V2_PLAN_PATH, _V2_PLAN_FIELDS, plan.predecessor_v2_plan_file_sha256)
    if plan.schema_version == 2:
        if (
            v1["schema_version"] != 1
            or v1["action_id"] != plan.predecessor_action_id
            or v1["plan_id"] != plan.predecessor_plan_id
            or v1["plan_sha256"] != plan.predecessor_plan_sha256
            or v2["schema_version"] != 2
            or v2["engagement_id"] != plan.engagement_id
            or v2["action_id"] != plan.action_id
            or v2["plan_id"] != plan.plan_id
            or v2["plan_sha256"] != plan.plan_sha256
            or v2["predecessor_action_id"] != v1["action_id"]
            or v2["predecessor_plan_id"] != v1["plan_id"]
            or v2["predecessor_plan_sha256"] != v1["plan_sha256"]
            or v2["predecessor_reconciliation_sha256"]
            != plan.predecessor_reconciliation_sha256
            or v2["predecessor_reason_code"] != plan.predecessor_reason_code
        ):
            raise PolicyError("frozen PortCast predecessor plan binding differs")
        for field in (
            "policy_revision", "workspace_id", "device_id", "operator_id",
            "profile_id", "module_id", "target_id", "catalog_sha256",
            "profile_sha256", "operation_sha256", "parser_sha256",
            "worker_sha256", "runtime_pinset_sha256", "release_id",
            "evidence_recipient",
        ):
            if v1[field] != v2[field] or v2[field] != getattr(plan, field):
                raise PolicyError("frozen PortCast predecessor scope differs")
        return v1
    if (
        v1["schema_version"] != 1
        or v1["action_id"] != "cptc11-portcast-public-identity-action-v1"
        or v1["plan_id"] != _PREDECESSOR_PLAN_ID
        or v2["schema_version"] != 2
        or v2["engagement_id"] != plan.predecessor_engagement_id
        or v2["action_id"] != plan.predecessor_action_id
        or v2["plan_id"] != plan.predecessor_plan_id
        or v2["plan_sha256"] != plan.predecessor_plan_sha256
        or v2["predecessor_action_id"] != v1["action_id"]
        or v2["predecessor_plan_id"] != v1["plan_id"]
        or v2["predecessor_plan_sha256"] != v1["plan_sha256"]
        or v2["predecessor_reconciliation_sha256"]
        != plan.predecessor_reconciliation_sha256
        or v2["predecessor_reason_code"]
        != plan.predecessor_reconciliation_reason
    ):
        raise PolicyError("frozen PortCast predecessor plan binding differs")
    for field in (
        "policy_revision", "workspace_id", "device_id", "operator_id",
        "profile_id", "module_id", "target_id", "catalog_sha256",
        "profile_sha256", "operation_sha256", "parser_sha256",
        "worker_sha256", "runtime_pinset_sha256",
        "release_id", "evidence_recipient",
    ):
        if v1[field] != v2[field] or v2[field] != getattr(plan, field):
            raise PolicyError("frozen PortCast predecessor scope differs")
    if plan.schema_version in {4, 5, 6, 7}:
        v3 = read(
            _V3_PLAN_PATH,
            _V3_PLAN_FIELDS,
            plan.predecessor_v3_plan_file_sha256 or "",
        )
        if (
            v3["schema_version"] != 3
            or v3["engagement_id"] != plan.predecessor_v3_engagement_id
            or v3["action_id"] != plan.predecessor_v3_action_id
            or v3["plan_sha256"] != plan.predecessor_v3_plan_sha256
            or v3["worker_sha256"] != plan.predecessor_v3_worker_sha256
            or v3["broker_worker_sha256"]
            != plan.predecessor_v3_broker_worker_sha256
            or v3["profile_worker_sha256"]
            != plan.predecessor_v3_profile_worker_sha256
            or v3["target_sha256"] != plan.predecessor_v3_target_sha256
            or v3["request_sha256"] != plan.predecessor_v3_request_sha256
            or v3["output_bytes"] != plan.predecessor_v3_output_bytes
            or v3["predecessor_v1_plan_file_sha256"]
            != plan.predecessor_v1_plan_file_sha256
            or v3["predecessor_v2_plan_file_sha256"]
            != plan.predecessor_v2_plan_file_sha256
            or v3["predecessor_action_id"] != v2["action_id"]
            or v3["predecessor_plan_sha256"] != v2["plan_sha256"]
        ):
            raise PolicyError("frozen PortCast v3 predecessor plan binding differs")
        for field in (
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
            "runtime_pinset_sha256",
            "release_id",
            "evidence_recipient",
            "workflow_id",
        ):
            if v3[field] != getattr(plan, field):
                raise PolicyError("frozen PortCast v3 predecessor scope differs")
    if plan.schema_version in {5, 6, 7}:
        v4 = read(
            _V4_PLAN_PATH,
            _V4_PLAN_FIELDS,
            plan.predecessor_v4_plan_file_sha256 or "",
        )
        if (
            v4["schema_version"] != 4
            or hashlib.sha256(_canonical({k: v for k, v in v4.items() if k != "plan_sha256"})).hexdigest()
            != v4["plan_sha256"]
            or v4["engagement_id"] != plan.predecessor_v4_engagement_id
            or v4["action_id"] != plan.predecessor_v4_action_id
            or v4["plan_sha256"] != plan.predecessor_v4_plan_sha256
            or v4["worker_sha256"] != plan.predecessor_v4_worker_sha256
            or v4["broker_worker_sha256"] != plan.predecessor_v4_broker_worker_sha256
            or v4["profile_worker_sha256"] != plan.predecessor_v4_profile_worker_sha256
            or v4["target_sha256"] != plan.predecessor_v4_target_sha256
            or v4["request_sha256"] != plan.predecessor_v4_request_sha256
            or v4["output_bytes"] != plan.predecessor_v4_output_bytes
            or v4["predecessor_v3_plan_file_sha256"] != plan.predecessor_v3_plan_file_sha256
            or v4["predecessor_v3_plan_sha256"] != plan.predecessor_v3_plan_sha256
        ):
            raise PolicyError("frozen PortCast v4 predecessor plan binding differs")
        for field in (
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
            "runtime_pinset_sha256",
            "release_id",
            "evidence_recipient",
            "workflow_id",
        ):
            if v4[field] != getattr(plan, field):
                raise PolicyError("frozen PortCast v4 predecessor scope differs")
    if plan.schema_version in {6, 7}:
        v5 = read(
            _V5_PLAN_PATH,
            _V5_PLAN_FIELDS,
            plan.predecessor_v5_plan_file_sha256 or "",
        )
        if (
            v5["schema_version"] != 5
            or v5["engagement_id"] != plan.predecessor_v5_engagement_id
            or v5["action_id"] != plan.predecessor_v5_action_id
            or v5["plan_sha256"] != plan.predecessor_v5_plan_sha256
            or v5["worker_sha256"] != plan.predecessor_v5_worker_sha256
            or v5["broker_worker_sha256"]
            != plan.predecessor_v5_broker_worker_sha256
            or v5["profile_worker_sha256"]
            != plan.predecessor_v5_profile_worker_sha256
            or v5["target_sha256"] != plan.predecessor_v5_target_sha256
            or v5["request_sha256"] != plan.predecessor_v5_request_sha256
            or v5["output_bytes"] != plan.predecessor_v5_output_bytes
            or v5["predecessor_v4_plan_file_sha256"]
            != plan.predecessor_v4_plan_file_sha256
            or v5["predecessor_v4_plan_sha256"]
            != plan.predecessor_v4_plan_sha256
        ):
            raise PolicyError("frozen PortCast v5 predecessor plan binding differs")
        for field in (
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
            "runtime_pinset_sha256",
            "release_id",
            "evidence_recipient",
            "workflow_id",
        ):
            if v5[field] != getattr(plan, field):
                raise PolicyError("frozen PortCast v5 predecessor scope differs")
    return v2


def _expected_predecessor_identity(
    plan: FrozenPortcastPlan,
) -> ExpectedProfileContinuationIdentity:
    """Build the exact v2 audit verifier identity from a continuation plan."""

    predecessor = _read_predecessor_plan(plan)
    target = to_json(_target())
    request = to_json(
        OperationRequest(
            predecessor["action_id"], predecessor["workspace_id"],
            predecessor["device_id"], predecessor["operator_id"],
            predecessor["module_id"], _target(),
            {"profile_id": predecessor["profile_id"]}, "operator", None,
            predecessor["policy_revision"], predecessor["plan_id"],
        )
    )
    spec = build_registry().get(predecessor["module_id"])
    args = {"profile_id": predecessor["profile_id"]}
    intent = {
        "module": spec.module_id,
        "version": spec.version,
        "target": predecessor["target_id"],
        "source_sha256": predecessor["module_source_sha256"],
        "args_hash": hashlib.sha256(canonical_json(args)).hexdigest(),
        "validated_args": args,
        "bounds": to_json(spec.bounds),
        "actor": "operator",
        "workflow_id": predecessor["plan_id"],
        "approval_id": None,
        "parent_action_id": None,
        "remaining_budgets": {},
    }
    action = {
        "schema": "profile-continuation-legacy-action-v1",
        "plan_id": predecessor["plan_id"],
        "plan_sha256": predecessor["plan_sha256"],
        "release_id": predecessor["release_id"],
        "release_manifest_sha256": plan.predecessor_release_manifest_sha256,
        "module_id": predecessor["module_id"],
        "module_source_sha256": predecessor["module_source_sha256"],
        "profile_id": predecessor["profile_id"],
        "catalog_sha256": predecessor["catalog_sha256"],
        "profile_sha256": predecessor["profile_sha256"],
        "operation_sha256": predecessor["operation_sha256"],
        "runtime_pinset_sha256": predecessor["runtime_pinset_sha256"],
        "profile_worker_sha256": plan.predecessor_profile_worker_sha256,
        "broker_worker_sha256": plan.predecessor_broker_worker_sha256,
        "target_id": predecessor["target_id"],
        "target_sha256": hashlib.sha256(canonical_json(target)).hexdigest(),
        "request_sha256": hashlib.sha256(canonical_json(request)).hexdigest(),
        "output_bytes": spec.bounds.output_bytes,
        "operation_intent_sha256": hashlib.sha256(
            canonical_json(intent)
        ).hexdigest(),
    }
    if (
        action["target_sha256"] != plan.predecessor_target_sha256
        or action["request_sha256"] != plan.predecessor_request_sha256
        or action["output_bytes"] != plan.predecessor_output_bytes
        or hashlib.sha256(canonical_json(action)).hexdigest()
        != plan.predecessor_action_sha256
    ):
        raise PolicyError("frozen PortCast predecessor action binding differs")
    return ExpectedProfileContinuationIdentity(
        engagement_id=predecessor["engagement_id"],
        device_id=predecessor["device_id"],
        workspace_id=predecessor["workspace_id"],
        operator_id=predecessor["operator_id"],
        policy_revision=predecessor["policy_revision"],
        action_id=predecessor["action_id"],
        plan_id=predecessor["plan_id"],
        plan_sha256=predecessor["plan_sha256"],
        action_sha256=plan.predecessor_action_sha256,
        release_id=predecessor["release_id"],
        release_manifest_sha256=plan.predecessor_release_manifest_sha256,
        module_id=predecessor["module_id"],
        module_source_sha256=predecessor["module_source_sha256"],
        profile_id=predecessor["profile_id"],
        catalog_sha256=predecessor["catalog_sha256"],
        profile_sha256=predecessor["profile_sha256"],
        operation_sha256=predecessor["operation_sha256"],
        runtime_pinset_sha256=predecessor["runtime_pinset_sha256"],
        profile_worker_sha256=plan.predecessor_profile_worker_sha256,
        broker_worker_sha256=plan.predecessor_broker_worker_sha256,
        target_id=predecessor["target_id"],
        target_sha256=plan.predecessor_target_sha256,
        request_sha256=plan.predecessor_request_sha256,
        output_bytes=plan.predecessor_output_bytes,
    )


def _require_successor_request_binding(plan: FrozenPortcastPlan) -> None:
    target_sha256 = hashlib.sha256(canonical_json(to_json(_target()))).hexdigest()
    request = OperationRequest(
        plan.action_id, plan.workspace_id, plan.device_id, plan.operator_id,
        plan.module_id, _target(), {"profile_id": plan.profile_id}, "operator",
        None, plan.policy_revision, plan.workflow_id,
    )
    if (
        plan.target_sha256 != target_sha256
        or plan.request_sha256
        != hashlib.sha256(canonical_json(to_json(request))).hexdigest()
        or plan.output_bytes != build_registry().get(plan.module_id).bounds.output_bytes
    ):
        raise PolicyError("frozen PortCast successor request binding differs")


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
        "profile_worker_sha256": verified.current_profile_workers[plan.profile_id],
        "broker_worker_sha256": verified.file_sha256[
            "testing/cptc11_lab/portcast_broker_worker.py"
        ],
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
    cumulative_tcp_ceiling = (
        plan.predecessor_charged_tcp_connects
        + (
            plan.predecessor_v3_charged_tcp_connects
            if plan.schema_version in {4, 5, 6, 7}
            and type(plan.predecessor_v3_charged_tcp_connects) is int
            else 0
        )
        + (
            plan.predecessor_v4_charged_tcp_connects
            if plan.schema_version in {5, 6, 7}
            and type(plan.predecessor_v4_charged_tcp_connects) is int
            else 0
        )
        + (
            plan.predecessor_v5_charged_tcp_connects
            if plan.schema_version in {6, 7}
            and type(plan.predecessor_v5_charged_tcp_connects) is int
            else 0
        )
        + plan.tcp_connection_limit
    )
    workflow_limits = tuple(
        BudgetLimit("workflow", plan.workflow_id, counter, ceiling)
        for counter, ceiling in (
            ("request_limit", 1),
            ("udp_datagrams", 0),
            ("protocol_requests", 1),
            ("tx_bytes", 256),
            ("rx_bytes", 8192),
            ("output_bytes", 16384),
            ("process_limit", 1),
            ("auth_posts", 0),
        )
    )
    tcp_limits = tuple(
        BudgetLimit(scope, key, "tcp_connects", cumulative_tcp_ceiling)
        for scope, key in (
            ("engagement", plan.engagement_id),
            ("device", plan.device_id),
            ("workspace", plan.workspace_id),
            ("workflow", plan.workflow_id),
            ("target", plan.target_id),
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
        budget_limits=workflow_limits + tcp_limits,
    )


_RUNTIME_DIRECTORIES = frozenset({"audit", "results", "reports", "policies"})
_RUNTIME_FILES = frozenset({"policy.json", "runtime.json"})
_V3_PREDECESSOR_DIRECTORY = "v3-predecessor"
_V4_PREDECESSOR_RUNTIME = "v4"
_V5_PREDECESSOR_RECEIPT = Path("predecessors/v5/receipt.json")
_V6_UNUSED_RECEIPT = Path("predecessors/v6-unused/receipt.json")
_PORTCAST_SERVICE_SOCKET = Path("/run/cptc-harness/portcast-live-v1.sock")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Publish one directory without replacing any destination object."""

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        raise PolicyError("atomic no-replace publication is unavailable") from None
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    ) == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise PolicyError("canonical PortCast runtime appeared during provisioning")
    raise OSError(error, os.strerror(error), destination)


def _age_configuration(age_binary: Path, age_recipient: str) -> dict[str, Any]:
    if (
        not isinstance(age_binary, Path)
        or not isinstance(age_recipient, str)
        or _AGE_RECIPIENT.fullmatch(age_recipient) is None
    ):
        raise PolicyError("canonical PortCast evidence encryption differs")
    try:
        descriptor = os.open(
            age_binary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError:
        raise PolicyError("canonical PortCast age executable is unavailable") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 1 <= before.st_size <= 64 * 1024 * 1024
            or before.st_mode & 0o111 == 0
        ):
            raise PolicyError("canonical PortCast age executable differs")
        remaining = before.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(descriptor, min(remaining, 128 * 1024))
            if not chunk:
                raise PolicyError("canonical PortCast age executable changed")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PolicyError("canonical PortCast age executable changed")
        after = os.fstat(descriptor)
        linked = age_binary.stat(follow_symlinks=False)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(after) != identity(linked):
            raise PolicyError("canonical PortCast age executable changed")
    except OSError:
        raise PolicyError("canonical PortCast age executable changed") from None
    finally:
        os.close(descriptor)
    return {
        "version": 1,
        "age_recipient": age_recipient,
        "age_binary": str(age_binary.resolve(strict=True)),
        "age_sha256": digest.hexdigest(),
    }


def _validate_runtime_tree(
    runtime_root: Path,
    policy: PolicySnapshot,
    *,
    age_binary: Path,
    age_recipient: str,
) -> None:
    private_directory(runtime_root)
    root_info = runtime_root.lstat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.geteuid()
        or root_info.st_gid != os.getegid()
        or stat.S_IMODE(root_info.st_mode) != 0o700
    ):
        raise PolicyError("canonical PortCast runtime metadata differs")
    expected_top = _RUNTIME_DIRECTORIES | _RUNTIME_FILES
    try:
        if {item.name for item in runtime_root.iterdir()} != expected_top:
            raise PolicyError("canonical PortCast runtime layout differs")
        for name in _RUNTIME_DIRECTORIES:
            private_directory(runtime_root / name)
        entries = 0
        for item in runtime_root.rglob("*"):
            entries += 1
            if entries > 100_000:
                raise PolicyError("canonical PortCast runtime layout exceeds allowance")
            info = item.lstat()
            if info.st_uid != os.geteuid() or info.st_gid != os.getegid() or (
                stat.S_ISDIR(info.st_mode)
                and stat.S_IMODE(info.st_mode) != 0o700
            ) or (
                stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) != 0o600
            ) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise PolicyError("canonical PortCast runtime metadata differs")
        if load_policy(runtime_root / "policy.json") != policy:
            raise PolicyError("initialized PortCast policy differs")
        archived = runtime_root / "policies" / (policy.revision + ".json")
        if {item.name for item in (runtime_root / "policies").iterdir()} != {archived.name}:
            raise PolicyError("canonical PortCast policy archive differs")
        if load_policy(archived) != policy:
            raise PolicyError("canonical PortCast policy archive differs")
        config = json.loads(
            read_private(runtime_root / "runtime.json", 8192),
            object_pairs_hook=_pairs,
        )
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise PolicyError("canonical PortCast runtime is invalid") from None
    if config != _age_configuration(age_binary, age_recipient):
        if isinstance(config, dict) and config.get("age_recipient") != age_recipient:
            raise PolicyError("canonical PortCast evidence recipient differs")
        raise PolicyError("canonical PortCast evidence encryption differs")


def _tree_snapshot(
    root: Path,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> list[dict[str, Any]]:
    """Hash one already-validated private tree without following links."""

    expected_uid = os.geteuid() if expected_uid is None else expected_uid
    expected_gid = os.getegid() if expected_gid is None else expected_gid
    records: list[dict[str, Any]] = []
    items = [root, *sorted(root.rglob("*"), key=lambda item: item.as_posix())]
    if len(items) > 100:
        raise PolicyError("aborted PortCast v3 state exceeds allowance")
    for item in items:
        info = item.lstat()
        if info.st_uid != expected_uid or info.st_gid != expected_gid:
            raise PolicyError("aborted PortCast v3 state ownership differs")
        relative = "." if item == root else item.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise PolicyError("aborted PortCast v3 state mode differs")
            records.append({"kind": "directory", "mode": 0o700, "path": relative})
            continue
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise PolicyError("aborted PortCast v3 state type differs")
        if info.st_nlink != 1 or info.st_size > _MAX_PLAN_BYTES:
            raise PolicyError("aborted PortCast v3 state file differs")
        try:
            descriptor = os.open(
                item, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                opened = os.fstat(descriptor)
                if (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_mode,
                    opened.st_size,
                    opened.st_uid,
                    opened.st_gid,
                ) != (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_size,
                    info.st_uid,
                    info.st_gid,
                ):
                    raise PolicyError("aborted PortCast v3 state changed")
                raw = os.read(descriptor, _MAX_PLAN_BYTES + 1)
                if len(raw) != info.st_size:
                    raise PolicyError("aborted PortCast v3 state changed")
            finally:
                os.close(descriptor)
        except PolicyError:
            raise
        except OSError:
            raise PolicyError("aborted PortCast v3 state changed") from None
        records.append(
            {
                "kind": "file",
                "mode": 0o600,
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        )
    return records


def _ledger_action_counts(
    ledger_directory: Path,
    action_id: str,
    *,
    ignored_tables: frozenset[str] = frozenset(),
) -> dict[str, int]:
    """Count any durable reference to one action through a read-only database."""

    database = ledger_directory / "ledger.sqlite3"
    try:
        connection = sqlite3.connect(
            database.resolve(strict=True).as_uri() + "?mode=ro",
            uri=True,
            timeout=1,
        )
        try:
            if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise PolicyError("aborted PortCast v3 ledger integrity differs")
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            if len(tables) > 64 or any(
                re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) is None
                for name in tables
            ):
                raise PolicyError("aborted PortCast v3 ledger schema differs")
            action_columns = {
                "request_id",
                "action_id",
                "predecessor_action_id",
                "predecessor_reconciled_action_id",
                "successor_action_id",
            }
            counts: dict[str, int] = {}
            for table in tables:
                if table in ignored_tables:
                    continue
                columns = [
                    row[1]
                    for row in connection.execute(f'PRAGMA table_info("{table}")')
                ]
                selected = sorted(action_columns.intersection(columns))
                if not selected:
                    continue
                where = " OR ".join(f'"{column}"=?' for column in selected)
                count = connection.execute(
                    f'SELECT COUNT(*) FROM "{table}" WHERE {where}',
                    (action_id,) * len(selected),
                ).fetchone()[0]
                counts[table] = int(count)
            return counts
        finally:
            connection.close()
    except PolicyError:
        raise
    except (OSError, sqlite3.Error):
        raise PolicyError("aborted PortCast v3 ledger integrity differs") from None


_CONTINUATION_ROW_FIELDS = (
    "predecessor_engagement", "predecessor_device",
    "predecessor_reconciled_action_id", "predecessor_action_id",
    "predecessor_plan_id", "predecessor_plan_sha256",
    "predecessor_release_manifest_sha256", "predecessor_profile_worker_sha256",
    "predecessor_broker_worker_sha256", "predecessor_audit_chain_tail_sha256",
    "predecessor_audit_snapshot_sha256", "predecessor_reconciliation_sha256",
    "predecessor_reconciliation_reason", "predecessor_raw_failure_stage",
    "predecessor_stage", "predecessor_attempt_count",
    "predecessor_observed_tcp_connects", "predecessor_possible_tcp_connects",
    "predecessor_charged_tcp_connects", "predecessor_observed_udp_datagrams",
    "predecessor_charged_udp_datagrams", "predecessor_observed_protocol_requests",
    "predecessor_charged_protocol_requests", "predecessor_observed_tx_bytes",
    "predecessor_charged_tx_bytes", "predecessor_observed_rx_bytes",
    "predecessor_charged_rx_bytes", "predecessor_evidence_bytes",
    "predecessor_first_byte_at", "predecessor_wire_event_count",
    "predecessor_outcome", "predecessor_cleanup_status",
    "predecessor_stop_reason", "successor_engagement", "successor_device",
    "successor_workspace", "successor_target", "successor_workflow",
    "successor_action_id", "successor_plan_id", "successor_plan_sha256",
    "predecessor_proof_sha256", "created_at",
)


def _read_continuation_row(
    ledger_directory: Path,
    *,
    successor_engagement: str,
    successor_action_id: str,
) -> dict[str, Any]:
    """Read one continuation row through SQLite's immutable read-only mode."""

    database = Path(ledger_directory) / "ledger.sqlite3"
    columns = ",".join(_CONTINUATION_ROW_FIELDS)
    try:
        connection = sqlite3.connect(
            database.resolve(strict=True).as_uri() + "?mode=ro",
            uri=True,
            timeout=1,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            if connection.execute("PRAGMA query_only").fetchone() != (1,):
                raise PolicyError("PortCast predecessor ledger is not read-only")
            if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise PolicyError("PortCast predecessor ledger integrity differs")
            rows = connection.execute(
                f"SELECT {columns} FROM profile_continuations "
                "WHERE successor_engagement=? AND successor_action_id=?",
                (successor_engagement, successor_action_id),
            ).fetchall()
            if len(rows) != 1:
                raise PolicyError("PortCast v4 continuation row differs")
            return dict(zip(_CONTINUATION_ROW_FIELDS, rows[0], strict=True))
        finally:
            connection.close()
    except PolicyError:
        raise
    except (OSError, sqlite3.Error):
        raise PolicyError("PortCast v4 continuation row is unavailable") from None


def _continuation_row_digest(row: dict[str, Any]) -> str:
    """Hash the complete canonical continuation row, including its timestamp."""

    if set(row) != set(_CONTINUATION_ROW_FIELDS):
        raise PolicyError("PortCast v4 continuation row schema differs")
    if type(row["created_at"]) is not str or _UTC.fullmatch(row["created_at"]) is None:
        raise PolicyError("PortCast v4 continuation row timestamp differs")
    return hashlib.sha256(canonical_json(row)).hexdigest()


def _v4_predecessor_state_snapshot(
    state_root: Path,
    ledger_directory: Path,
    plan: FrozenPortcastPlan,
    *,
    age_binary: Path,
    age_recipient: str,
) -> dict[str, Any]:
    """Capture v4 runtime and continuation state without opening it writable."""

    v4 = load_frozen_portcast_plan_v4()
    predecessor_root = private_directory(
        Path(state_root) / _V4_PREDECESSOR_RUNTIME
    )
    if predecessor_root == _PRODUCTION_RUNTIME_CONTAINER / _V4_PREDECESSOR_RUNTIME:
        try:
            if not os.statvfs(predecessor_root).f_flag & os.ST_RDONLY:
                raise PolicyError("PortCast v4 predecessor state is writable")
        except OSError:
            raise PolicyError("PortCast v4 predecessor mount is unavailable") from None
    expected_top = {".provision.lock", "policy-source.json", "runtime"}
    if {item.name for item in predecessor_root.iterdir()} != expected_top:
        raise PolicyError("PortCast v4 predecessor state layout differs")
    if read_private(predecessor_root / ".provision.lock", 1) != b"":
        raise PolicyError("PortCast v4 predecessor provision lock differs")
    if load_policy(predecessor_root / "policy-source.json") != policy_for_plan(v4):
        raise PolicyError("PortCast v4 predecessor policy source differs")
    runtime_root = predecessor_root / "runtime"
    _validate_runtime_tree(
        runtime_root,
        policy_for_plan(v4),
        age_binary=age_binary,
        age_recipient=age_recipient,
    )
    for name in ("audit", "results", "reports"):
        if any((runtime_root / name).iterdir()):
            raise PolicyError("PortCast v4 output state is not empty")
    counts = _ledger_action_counts(
        ledger_directory,
        v4.action_id,
        ignored_tables=frozenset({"profile_continuations"}),
    )
    if any(counts.values()):
        raise PolicyError("PortCast v4 has durable action state")
    row = _read_continuation_row(
        ledger_directory,
        successor_engagement=v4.engagement_id,
        successor_action_id=v4.action_id,
    )
    if (
        row["successor_engagement"] != v4.engagement_id
        or row["successor_action_id"] != v4.action_id
        or row["successor_plan_id"] != v4.plan_id
        or row["successor_plan_sha256"] != v4.plan_sha256
        or row["successor_workspace"] != v4.workspace_id
        or row["successor_device"] != v4.device_id
        or row["successor_target"] != v4.target_id
        or row["successor_workflow"] != v4.workflow_id
    ):
        raise PolicyError("PortCast v4 continuation row binding differs")
    proof = _verified_predecessor_proof(state_root, v4)
    predecessor = _read_predecessor_plan(v4)
    expected_row = {
        **{
            key: value
            for key, value in asdict(proof).items()
            if key != "reconciliation_sha256"
        },
        "predecessor_reconciliation_sha256": proof.reconciliation_sha256,
        "predecessor_device": v4.device_id,
        "predecessor_reconciled_action_id": predecessor[
            "predecessor_action_id"
        ],
        "predecessor_reconciliation_reason": (
            v4.predecessor_reconciliation_reason
        ),
        "successor_engagement": v4.engagement_id,
        "successor_device": v4.device_id,
        "successor_workspace": v4.workspace_id,
        "successor_target": v4.target_id,
        "successor_workflow": v4.workflow_id,
        "successor_action_id": v4.action_id,
        "successor_plan_id": v4.plan_id,
        "successor_plan_sha256": v4.plan_sha256,
        "predecessor_proof_sha256": hashlib.sha256(
            canonical_json(asdict(proof))
        ).hexdigest(),
    }
    if type(row["created_at"]) is not str or _UTC.fullmatch(row["created_at"]) is None:
        raise PolicyError("PortCast v4 continuation row timestamp differs")
    if any(row[key] != value for key, value in expected_row.items()):
        raise PolicyError("PortCast v4 continuation row binding differs")
    digest = _continuation_row_digest(row)
    if plan.predecessor_v4_continuation_row_sha256 != digest:
        raise PolicyError("PortCast v4 continuation row digest differs")
    snapshot = {
        "schema": "portcast-v4-predecessor-state-v1",
        "plan_file_sha256": _V4_PLAN_FILE_SHA256,
        "plan_sha256": _V4_PLAN_SHA256,
        "runtime_tree": _tree_snapshot(runtime_root),
        "ledger_action_counts": counts,
        "continuation_row_sha256": digest,
        "broker_socket_present": False,
        "credentials_loaded": False,
        "target_traffic": False,
        "first_byte_observed": False,
        "result_present": False,
        "possible_tcp_connects": 0,
        "charged_tcp_connects": 0,
    }
    if plan.predecessor_v4_failure_stage != _V4_FAILURE_STAGE:
        raise PolicyError("PortCast v4 predecessor failure stage differs")
    if plan.predecessor_v4_stop_reason != _V4_STOP_REASON:
        raise PolicyError("PortCast v4 predecessor stop reason differs")
    snapshot["failure_stage"] = _V4_FAILURE_STAGE
    snapshot["stop_reason"] = _V4_STOP_REASON
    snapshot["runtime_tree"] = _tree_snapshot(predecessor_root)
    if plan.predecessor_v4_state_sha256 != hashlib.sha256(
        canonical_json(snapshot)
    ).hexdigest():
        raise PolicyError("PortCast v4 predecessor state digest differs")
    return snapshot


def _verify_v5_predecessors(
    state_root: Path,
    plan: FrozenPortcastPlan,
    *,
    age_binary: Path,
    age_recipient: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify both immutable predecessors before creating the v5 runtime."""

    if plan.schema_version != 5:
        raise PolicyError("v5 predecessor verification requires schema v5")
    old_ledger = Path(state_root) / "ledger" / plan.predecessor_engagement_id
    if old_ledger == _PRODUCTION_RUNTIME_CONTAINER / "ledger" / plan.predecessor_engagement_id:
        try:
            if not os.statvfs(old_ledger).f_flag & os.ST_RDONLY:
                raise PolicyError("PortCast predecessor ledger is writable")
        except OSError:
            raise PolicyError("PortCast predecessor ledger mount is unavailable") from None
    _validate_existing_ledger(old_ledger, load_frozen_portcast_plan_v4())
    v3 = _verify_aborted_v3_state(
        state_root,
        old_ledger,
        plan,
        age_binary=age_binary,
        age_recipient=age_recipient,
    )
    v4 = _v4_predecessor_state_snapshot(
        state_root,
        old_ledger,
        plan,
        age_binary=age_binary,
        age_recipient=age_recipient,
    )
    return v3, v4


def _expected_v5_predecessor_receipt(
    plan: FrozenPortcastPlan,
) -> dict[str, Any]:
    """Build the byte-exact root-manager receipt accepted by schema v6."""

    return {
        "action_id": plan.predecessor_v5_action_id,
        "admission_marker_present": plan.predecessor_v5_admission_marker_present,
        "admission_marker_sha256": plan.predecessor_v5_admission_marker_sha256,
        "application_credentials_loaded": (
            plan.predecessor_v5_application_credentials_loaded
        ),
        "broker_socket_opened": plan.predecessor_v5_broker_socket_opened,
        "broker_worker_sha256": plan.predecessor_v5_broker_worker_sha256,
        "charged_tcp_connects": plan.predecessor_v5_charged_tcp_connects,
        "engagement_id": plan.predecessor_v5_engagement_id,
        "exec_start_pre_exit_status": (
            plan.predecessor_v5_exec_start_pre_exit_status
        ),
        "failure_at": plan.predecessor_v5_failure_at,
        "failure_stage": plan.predecessor_v5_failure_stage,
        "first_byte_observed": plan.predecessor_v5_first_byte_observed,
        "launcher_sha256": plan.predecessor_v5_launcher_sha256,
        "main_process_started": plan.predecessor_v5_main_process_started,
        "plan_file_sha256": plan.predecessor_v5_plan_file_sha256,
        "plan_sha256": plan.predecessor_v5_plan_sha256,
        "possible_tcp_connects": plan.predecessor_v5_possible_tcp_connects,
        "profile_worker_sha256": plan.predecessor_v5_profile_worker_sha256,
        "projection_marker_present": plan.predecessor_v5_projection_marker_present,
        "release_manifest_sha256": (
            plan.predecessor_v5_release_manifest_sha256
        ),
        "request_sha256": plan.predecessor_v5_request_sha256,
        "result_present": plan.predecessor_v5_result_present,
        "runtime_tree": [{"kind": "directory", "mode": 0o700, "path": "."}],
        "schema": "portcast-v5-predecessor-state-v1",
        "service_unit_sha256": plan.predecessor_v5_service_unit_sha256,
        "stop_reason": plan.predecessor_v5_stop_reason,
        "target_capability_created": (
            plan.predecessor_v5_target_capability_created
        ),
        "target_sha256": plan.predecessor_v5_target_sha256,
        "target_traffic": plan.predecessor_v5_target_traffic,
    }


def _verify_v5_predecessor_receipt(
    state_root: Path,
    plan: FrozenPortcastPlan,
) -> dict[str, Any]:
    """Consume the immutable root-created v5 state receipt without mutation."""

    if plan.schema_version not in {6, 7}:
        raise PolicyError("v5 predecessor receipt requires schema v6 or v7")
    state_root = Path(state_root).absolute()
    receipt_path = state_root.parent / _V5_PREDECESSOR_RECEIPT
    receipt_root = receipt_path.parent
    try:
        for component in reversed(receipt_path.parents):
            if component.is_symlink():
                raise PolicyError("symlink in v5 predecessor receipt path")
        root_info = receipt_root.lstat()
        production = state_root == _PRODUCTION_RUNTIME_CONTAINER
        expected_uid = _ROOT_UID if production else os.geteuid()
        expected_gid = _ROOT_GID if production else os.getegid()
        expected_root_mode = 0o555 if production else 0o700
        expected_file_mode = 0o444 if production else 0o600
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != expected_uid
            or root_info.st_gid != expected_gid
            or stat.S_IMODE(root_info.st_mode) != expected_root_mode
        ):
            raise PolicyError("PortCast v5 predecessor receipt directory differs")
        if receipt_path.is_symlink():
            raise PolicyError("PortCast v5 predecessor receipt symlink rejected")
        descriptor = os.open(
            receipt_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != expected_uid
                or info.st_gid != expected_gid
                or stat.S_IMODE(info.st_mode) != expected_file_mode
                or info.st_nlink != 1
                or not 1 <= info.st_size <= _MAX_PLAN_BYTES
            ):
                raise PolicyError("PortCast v5 predecessor receipt metadata differs")
            raw = os.read(descriptor, _MAX_PLAN_BYTES + 1)
            if len(raw) != info.st_size:
                raise PolicyError("PortCast v5 predecessor receipt changed")
        finally:
            os.close(descriptor)
    except PolicyError:
        raise
    except OSError:
        raise PolicyError("PortCast v5 predecessor receipt is unavailable") from None
    expected = _expected_v5_predecessor_receipt(plan)
    expected_raw = canonical_json(expected)
    if (
        raw != expected_raw
        or hashlib.sha256(raw).hexdigest() != plan.predecessor_v5_state_sha256
    ):
        raise PolicyError("PortCast v5 predecessor state digest differs")
    return expected


def _expected_v6_unused_receipt(plan: FrozenPortcastPlan) -> dict[str, Any]:
    """Build the exact root-manager proof that the v6 window expired unused."""

    if plan.schema_version != 7:
        raise PolicyError("v6 unused receipt requires schema v7")
    return {
        "action_id": plan.superseded_v6_action_id,
        "charged_tcp_connects": plan.superseded_v6_charged_tcp_connects,
        "deployment_status": plan.superseded_v6_deployment_status,
        "engagement_id": plan.superseded_v6_engagement_id,
        "execution_status": plan.superseded_v6_execution_status,
        "first_byte_observed": plan.superseded_v6_first_byte_observed,
        "possible_tcp_connects": plan.superseded_v6_possible_tcp_connects,
        "release_manifest_sha256": (
            plan.superseded_v6_release_manifest_sha256
        ),
        "result_present": plan.superseded_v6_result_present,
        "schema": "portcast-v6-unused-state-v1",
        "target_capability_created": (
            plan.superseded_v6_target_capability_created
        ),
        "target_traffic": plan.superseded_v6_target_traffic,
        "v6_plan_file_sha256": plan.superseded_v6_plan_file_sha256,
        "v6_plan_sha256": plan.superseded_v6_plan_sha256,
    }


def _verify_v6_unused_receipt(
    state_root: Path,
    plan: FrozenPortcastPlan,
) -> dict[str, Any]:
    """Consume the immutable root-created v6 unused-state proof."""

    if plan.schema_version != 7:
        raise PolicyError("v6 unused receipt requires schema v7")
    state_root = Path(state_root).absolute()
    receipt_path = state_root.parent / _V6_UNUSED_RECEIPT
    receipt_root = receipt_path.parent
    try:
        for component in reversed(receipt_path.parents):
            if component.is_symlink():
                raise PolicyError("symlink in v6 unused receipt path")
        root_info = receipt_root.lstat()
        production = state_root == _PRODUCTION_RUNTIME_CONTAINER
        expected_uid = _ROOT_UID if production else os.geteuid()
        expected_gid = _ROOT_GID if production else os.getegid()
        expected_root_mode = 0o555 if production else 0o700
        expected_file_mode = 0o444 if production else 0o600
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != expected_uid
            or root_info.st_gid != expected_gid
            or stat.S_IMODE(root_info.st_mode) != expected_root_mode
        ):
            raise PolicyError("PortCast v6 unused receipt directory differs")
        if receipt_path.is_symlink():
            raise PolicyError("PortCast v6 unused receipt symlink rejected")
        descriptor = os.open(
            receipt_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != expected_uid
                or info.st_gid != expected_gid
                or stat.S_IMODE(info.st_mode) != expected_file_mode
                or info.st_nlink != 1
                or not 1 <= info.st_size <= _MAX_PLAN_BYTES
            ):
                raise PolicyError("PortCast v6 unused receipt metadata differs")
            raw = os.read(descriptor, _MAX_PLAN_BYTES + 1)
            if len(raw) != info.st_size:
                raise PolicyError("PortCast v6 unused receipt changed")
        finally:
            os.close(descriptor)
    except PolicyError:
        raise
    except OSError:
        raise PolicyError("PortCast v6 unused receipt is unavailable") from None
    expected = _expected_v6_unused_receipt(plan)
    expected_raw = canonical_json(expected)
    if (
        raw != expected_raw
        or hashlib.sha256(raw).hexdigest()
        != plan.superseded_v6_state_receipt_sha256
    ):
        raise PolicyError("PortCast v6 unused state digest differs")
    return expected


def _verify_v7_predecessor_receipts(
    state_root: Path,
    plan: FrozenPortcastPlan,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify both immutable receipts before any v7 runtime action."""

    if plan.schema_version != 7:
        raise PolicyError("v7 predecessor verification requires schema v7")
    v5 = _verify_v5_predecessor_receipt(state_root, plan)
    v6 = _verify_v6_unused_receipt(state_root, plan)
    return v5, v6


def _aborted_v3_state_snapshot(
    predecessor_root: Path,
    ledger_directory: Path,
    *,
    age_binary: Path,
    age_recipient: str,
    socket_path: Path,
) -> dict[str, Any]:
    """Build the deterministic, read-only v3 startup-failure snapshot."""

    predecessor_root = private_directory(predecessor_root)
    if predecessor_root == _PRODUCTION_RUNTIME_CONTAINER / _V3_PREDECESSOR_DIRECTORY:
        try:
            if not os.statvfs(predecessor_root).f_flag & os.ST_RDONLY:
                raise PolicyError("aborted PortCast v3 state is writable")
        except OSError:
            raise PolicyError("aborted PortCast v3 mount state is unavailable") from None
    v3 = load_frozen_portcast_plan_v3()
    expected_top = {".provision.lock", "policy-source.json", "runtime"}
    if {item.name for item in predecessor_root.iterdir()} != expected_top:
        raise PolicyError("aborted PortCast v3 state layout differs")
    if read_private(predecessor_root / ".provision.lock", 1) != b"":
        raise PolicyError("aborted PortCast v3 provision lock differs")
    if load_policy(predecessor_root / "policy-source.json") != policy_for_plan(v3):
        raise PolicyError("aborted PortCast v3 policy source differs")
    runtime_root = predecessor_root / "runtime"
    _validate_runtime_tree(
        runtime_root,
        policy_for_plan(v3),
        age_binary=age_binary,
        age_recipient=age_recipient,
    )
    for name in ("audit", "results", "reports"):
        if any((runtime_root / name).iterdir()):
            raise PolicyError("aborted PortCast v3 output state is not empty")
    counts = _ledger_action_counts(ledger_directory, v3.action_id)
    if any(counts.values()):
        raise PolicyError("aborted PortCast v3 has durable action state")
    if socket_path.exists() or socket_path.is_symlink():
        raise PolicyError("aborted PortCast v3 broker socket is present")
    return {
        "schema": "portcast-aborted-v3-state-v1",
        "plan_file_sha256": _V3_PLAN_FILE_SHA256,
        "plan_sha256": _V3_PLAN_SHA256,
        "runtime_tree": _tree_snapshot(predecessor_root),
        "ledger_action_counts": counts,
        "broker_socket_present": False,
        "credentials_loaded": False,
        "target_traffic": False,
        "first_byte_observed": False,
        "result_present": False,
        "possible_tcp_connects": 0,
        "charged_tcp_connects": 0,
    }


def _verify_aborted_v3_state(
    state_root: Path,
    ledger_directory: Path,
    plan: FrozenPortcastPlan,
    *,
    age_binary: Path,
    age_recipient: str,
    socket_path: Path = _PORTCAST_SERVICE_SOCKET,
) -> dict[str, Any]:
    """Require the exact empty v3 admission before schema-v4 mutation."""

    if plan.schema_version not in {4, 5}:
        raise PolicyError("aborted PortCast v3 proof requires schema v4 or v5")
    snapshot = _aborted_v3_state_snapshot(
        Path(state_root) / _V3_PREDECESSOR_DIRECTORY,
        ledger_directory,
        age_binary=age_binary,
        age_recipient=age_recipient,
        socket_path=socket_path,
    )
    digest = hashlib.sha256(canonical_json(snapshot)).hexdigest()
    if digest != plan.predecessor_v3_state_sha256:
        raise PolicyError("aborted PortCast v3 state digest differs")
    return snapshot


def _initialize_runtime_atomically(
    runtime_root: Path,
    policy_source: Path,
    policy: PolicySnapshot,
    *,
    age_binary: Path,
    age_recipient: str,
) -> None:
    stage = runtime_root.with_name(
        ".runtime.provision-" + os.urandom(12).hex()
    )
    published = False
    try:
        stage.mkdir(mode=0o700)
        initialize(
            stage,
            policy_source,
            recipient=age_recipient,
            age_binary=age_binary,
        )
        _validate_runtime_tree(
            stage,
            policy,
            age_binary=age_binary,
            age_recipient=age_recipient,
        )
        _fsync_directory(stage)
        _rename_noreplace(stage, runtime_root)
        published = True
        _fsync_directory(runtime_root.parent)
        _validate_runtime_tree(
            runtime_root,
            policy,
            age_binary=age_binary,
            age_recipient=age_recipient,
        )
    except BaseException:
        if not published and stage.exists() and not stage.is_symlink():
            shutil.rmtree(stage)
            _fsync_directory(stage.parent)
        raise


def _prepare_runtime_unlocked(
    root: Path,
    plan: FrozenPortcastPlan,
    *,
    age_binary: Path | None,
    age_recipient: str | None,
    provision: bool = True,
) -> tuple[Path, Path]:
    runtime_root = root / "runtime"
    ledger_root = (
        root.parent / "ledger" / plan.predecessor_engagement_id
        if plan.schema_version in {3, 4}
        else root / "ledger"
    )
    policy = policy_for_plan(plan)
    policy_source = root / "policy-source.json"
    if policy_source.exists():
        if load_policy(policy_source) != policy:
            raise PolicyError("frozen PortCast policy source differs")
    elif provision:
        write_json(policy_source, policy_document(policy), replace=False)
        _fsync_directory(root)
    else:
        raise PolicyError("canonical PortCast policy source is not provisioned")
    if runtime_root.exists():
        _validate_runtime_tree(
            runtime_root,
            policy,
            age_binary=age_binary,
            age_recipient=age_recipient,
        )
    elif provision and isinstance(age_binary, Path) and isinstance(age_recipient, str):
        _initialize_runtime_atomically(
            runtime_root,
            policy_source,
            policy,
            age_binary=age_binary,
            age_recipient=age_recipient,
        )
    else:
        raise PolicyError("canonical PortCast runtime is not provisioned")
    ledger_root = private_directory(
        ledger_root,
        create=provision and plan.schema_version not in {3, 4},
    )
    if provision:
        _fsync_directory(root)
    return runtime_root, ledger_root


def _prepare_runtime(
    root: Path,
    plan: FrozenPortcastPlan,
    *,
    age_binary: Path | None,
    age_recipient: str | None,
    provision: bool = True,
) -> tuple[Path, Path]:
    root = Path(root).absolute()
    if plan.schema_version in {3, 4, 5, 6, 7} and root == _PRODUCTION_RUNTIME_CONTAINER:
        for component in reversed((root, *root.parents)):
            if component.is_symlink():
                raise PolicyError("symlink in protected storage path")
        info = root.stat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _ROOT_UID
            or info.st_gid != _ROOT_GID
            or stat.S_IMODE(info.st_mode) != 0o555
        ):
            raise PolicyError("canonical runtime mount container differs")
    else:
        root = private_directory(root, create=provision)
    if plan.schema_version in {3, 4, 5, 6, 7}:
        version = f"v{plan.schema_version}"
        root = private_directory(root / version, create=provision)
        info = root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise PolicyError(f"canonical {version} runtime directory differs")
    if provision:
        with exclusive(root / ".provision.lock"):
            return _prepare_runtime_unlocked(
                root,
                plan,
                age_binary=age_binary,
                age_recipient=age_recipient,
                provision=True,
            )
    return _prepare_runtime_unlocked(
        root,
        plan,
        age_binary=age_binary,
        age_recipient=age_recipient,
        provision=False,
    )


def prepare_frozen_portcast_runtime_at_root(
    *,
    state_root: Path,
    plan: FrozenPortcastPlan,
    verified_release: VerifiedRelease,
    age_binary: Path,
    age_recipient: str,
) -> tuple[Path, Path]:
    """Provision the sealed evidence runtime before the service can listen."""

    current = validate_current_release(plan)
    if (
        current.release_id != verified_release.release_id
        or current.manifest_sha256 != verified_release.manifest_sha256
        or plan.evidence_recipient != age_recipient
        or current.native_file_sha256.get("bin/age")
        != _age_configuration(age_binary, age_recipient)["age_sha256"]
    ):
        raise PolicyError("canonical PortCast startup binding differs")
    if plan.schema_version in {4, 5, 6, 7}:
        if plan.schema_version == 7:
            _verify_v7_predecessor_receipts(state_root, plan)
        elif plan.schema_version == 6:
            _verify_v5_predecessor_receipt(state_root, plan)
        elif plan.schema_version == 5:
            _verify_v5_predecessors(
                state_root,
                plan,
                age_binary=age_binary,
                age_recipient=age_recipient,
            )
        else:
            ledger_directory = (
                Path(state_root) / "ledger" / plan.predecessor_engagement_id
            )
            _validate_existing_ledger(ledger_directory, plan)
            _verify_aborted_v3_state(
                state_root,
                ledger_directory,
                plan,
                age_binary=age_binary,
                age_recipient=age_recipient,
            )
    return _prepare_runtime(
        state_root,
        plan,
        age_binary=age_binary,
        age_recipient=age_recipient,
        provision=True,
    )


def _validate_existing_ledger(
    ledger_root: Path, plan: FrozenPortcastPlan
) -> None:
    """Reject corrupt durable accounting before SQLite can open it read-write."""

    private_directory(ledger_root)
    ledger_info = ledger_root.lstat()
    if (
        not stat.S_ISDIR(ledger_info.st_mode)
        or ledger_info.st_uid != os.geteuid()
        or ledger_info.st_gid != os.getegid()
        or stat.S_IMODE(ledger_info.st_mode) != 0o700
    ):
        raise PolicyError("canonical PortCast ledger metadata differs")
    engagement_root = (
        ledger_root
        if plan.schema_version in {3, 4}
        else ledger_root / plan.engagement_id
    )
    if not engagement_root.exists() and not engagement_root.is_symlink():
        return
    private_directory(engagement_root)
    engagement_info = engagement_root.lstat()
    if (
        not stat.S_ISDIR(engagement_info.st_mode)
        or engagement_info.st_uid != os.geteuid()
        or engagement_info.st_gid != os.getegid()
        or stat.S_IMODE(engagement_info.st_mode) != 0o700
    ):
        raise PolicyError("canonical PortCast ledger metadata differs")
    allowed_top = {
        "ledger.sqlite3",
        "ledger.sqlite3-shm",
        "ledger.sqlite3-wal",
        "ledger.sqlite3-journal",
        "operator-stop.json",
        "control",
        "workflows",
    }
    try:
        entries = list(engagement_root.iterdir())
        if {item.name for item in entries} - allowed_top:
            raise PolicyError("canonical PortCast ledger layout differs")
        for item in engagement_root.rglob("*"):
            info = item.lstat()
            if (
                info.st_uid != os.geteuid()
                or info.st_gid != os.getegid()
                or stat.S_ISDIR(info.st_mode)
                and stat.S_IMODE(info.st_mode) != 0o700
                or stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) != 0o600
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            ):
                raise PolicyError("canonical PortCast ledger metadata differs")
        database = engagement_root / "ledger.sqlite3"
        if not database.exists():
            if entries or plan.schema_version in {3, 4}:
                raise PolicyError("canonical PortCast ledger database is missing")
            return
        info = database.lstat()
        if not stat.S_ISREG(info.st_mode) or not 4096 <= info.st_size <= 64 * 1024 * 1024:
            raise PolicyError("canonical PortCast ledger database differs")
        connection = sqlite3.connect(
            database.resolve(strict=True).as_uri() + "?mode=ro",
            uri=True,
            timeout=1,
        )
        try:
            if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise PolicyError("canonical PortCast ledger integrity differs")
            connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
        finally:
            connection.close()
    except PolicyError:
        raise
    except (OSError, sqlite3.Error):
        raise PolicyError("canonical PortCast ledger integrity differs") from None


def _predecessor_runtime_paths(
    state_root: Path,
    plan: FrozenPortcastPlan,
) -> tuple[Path, Path]:
    runtime_root = Path(state_root) / "runtime"
    return (
        runtime_root / "audit",
        runtime_root / "results" / (plan.predecessor_action_id + ".json"),
    )


def _verified_predecessor_proof(
    state_root: Path,
    plan: FrozenPortcastPlan,
) -> ProfileContinuationProof:
    """Verify the immutable old audit/result and project its Ledger proof."""

    audit_root, result_path = _predecessor_runtime_paths(state_root, plan)
    snapshot = verify_profile_continuation_snapshot(
        audit_root,
        result_path,
        _expected_predecessor_identity(plan),
    )
    if (
        snapshot.release_manifest_sha256
        != plan.predecessor_release_manifest_sha256
        or snapshot.predecessor_profile_worker_sha256
        != plan.predecessor_profile_worker_sha256
        or snapshot.predecessor_broker_worker_sha256
        != plan.predecessor_broker_worker_sha256
        or snapshot.raw_failure_stage is not None
        or snapshot.semantic_stage != "legacy_target_open_unacknowledged"
        or snapshot.wire_outcome != "uncertain"
        or snapshot.cleanup_status != "passed"
        or snapshot.wire_first_byte_present
        or snapshot.wire_evidence_bytes != 0
        or snapshot.result_evidence_count != 0
    ):
        raise PolicyError("profile continuation snapshot binding differs")
    counters = dict(snapshot.wire_counters)
    if set(counters) != {
        "capture_bytes",
        "protocol_requests",
        "rx_bytes",
        "tcp_connects",
        "tls_handshakes",
        "tx_bytes",
        "udp_datagrams",
    }:
        raise PolicyError("profile continuation snapshot counters differ")
    return ProfileContinuationProof(
        predecessor_engagement=plan.predecessor_engagement_id,
        predecessor_action_id=plan.predecessor_action_id,
        predecessor_plan_id=plan.predecessor_plan_id,
        predecessor_plan_sha256=plan.predecessor_plan_sha256,
        predecessor_release_manifest_sha256=(
            plan.predecessor_release_manifest_sha256
        ),
        predecessor_profile_worker_sha256=(
            plan.predecessor_profile_worker_sha256
        ),
        predecessor_broker_worker_sha256=(
            plan.predecessor_broker_worker_sha256
        ),
        predecessor_audit_chain_tail_sha256=snapshot.audit_chain_tail_sha256,
        predecessor_audit_snapshot_sha256=snapshot.canonical_snapshot_sha256,
        predecessor_raw_failure_stage=snapshot.raw_failure_stage,
        predecessor_stage=snapshot.semantic_stage,
        predecessor_attempt_count=1,
        predecessor_observed_tcp_connects=counters["tcp_connects"],
        predecessor_possible_tcp_connects=plan.predecessor_possible_tcp_connects,
        predecessor_charged_tcp_connects=plan.predecessor_charged_tcp_connects,
        predecessor_observed_udp_datagrams=counters["udp_datagrams"],
        predecessor_charged_udp_datagrams=0,
        predecessor_observed_protocol_requests=counters["protocol_requests"],
        predecessor_charged_protocol_requests=0,
        predecessor_observed_tx_bytes=counters["tx_bytes"],
        predecessor_charged_tx_bytes=0,
        predecessor_observed_rx_bytes=counters["rx_bytes"],
        predecessor_charged_rx_bytes=0,
        predecessor_evidence_bytes=snapshot.wire_evidence_bytes,
        predecessor_first_byte_at=None,
        predecessor_wire_event_count=0,
        predecessor_outcome=snapshot.wire_outcome,
        predecessor_cleanup_status=snapshot.cleanup_status,
        predecessor_stop_reason=plan.predecessor_stop_reason,
        reconciliation_sha256=plan.predecessor_reconciliation_sha256,
    )


def _record_profile_continuation(
    state_root: Path,
    ledger_directory: Path,
    plan: FrozenPortcastPlan,
) -> dict[str, Any]:
    """Record the verified continuation before any successor Runtime opens."""

    proof = _verified_predecessor_proof(state_root, plan)
    ledger = Ledger(
        ledger_directory,
        plan.engagement_id,
        plan.device_id,
        policy_revision=plan.policy_revision,
    )
    try:
        return ledger.record_profile_continuation(
            proof=proof,
            successor_action_id=plan.action_id,
            successor_plan_id=plan.plan_id,
            successor_plan_sha256=plan.plan_sha256,
            successor_workspace_id=plan.workspace_id,
            successor_target_id=plan.target_id,
            successor_workflow_id=plan.workflow_id,
        )
    finally:
        ledger._db.close()


def _require_existing_profile_continuation(
    runtime: Runtime,
    state_root: Path,
    plan: FrozenPortcastPlan,
) -> None:
    """Require the exact read-only proof stored by startup."""

    proof = _verified_predecessor_proof(state_root, plan)
    existing = runtime.ledger.profile_continuation(
        plan.predecessor_engagement_id,
        plan.predecessor_action_id,
    )
    predecessor = _read_predecessor_plan(plan)
    expected = {
        **{
            key: value
            for key, value in asdict(proof).items()
            if key != "reconciliation_sha256"
        },
        "predecessor_reconciliation_sha256": proof.reconciliation_sha256,
        "predecessor_device": plan.device_id,
        "predecessor_reconciled_action_id": predecessor[
            "predecessor_action_id"
        ],
        "predecessor_reconciliation_reason": (
            plan.predecessor_reconciliation_reason
        ),
        "successor_engagement": plan.engagement_id,
        "successor_device": plan.device_id,
        "successor_workspace": plan.workspace_id,
        "successor_target": plan.target_id,
        "successor_workflow": plan.workflow_id,
        "successor_action_id": plan.action_id,
        "successor_plan_id": plan.plan_id,
        "successor_plan_sha256": plan.plan_sha256,
        "predecessor_proof_sha256": hashlib.sha256(
            canonical_json(asdict(proof))
        ).hexdigest(),
    }
    if existing is None or any(
        existing.get(key) != value for key, value in expected.items()
    ):
        raise PolicyError("canonical PortCast profile continuation differs")


def _require_exact_loaded_plan(plan: FrozenPortcastPlan) -> None:
    """Bind a public helper to the exact plan loaded by its caller."""

    if (
        type(plan) is not FrozenPortcastPlan
        or plan.schema_version not in {2, 3, 4, 5, 6, 7}
        or plan != load_frozen_portcast_plan()
    ):
        raise PolicyError("canonical PortCast frozen plan differs")


def open_frozen_portcast_runtime_at_root(
    *,
    state_root: Path,
    plan: FrozenPortcastPlan,
    verified_release: VerifiedRelease,
    age_binary: Path,
    age_recipient: str,
    clock_service: Any = None,
) -> Runtime:
    """Open the production authority only for the exact current plan."""

    _require_exact_loaded_plan(plan)
    return _open_frozen_portcast_runtime_at_root_core(
        state_root=state_root,
        plan=plan,
        verified_release=verified_release,
        age_binary=age_binary,
        age_recipient=age_recipient,
        clock_service=clock_service,
    )


def _open_frozen_portcast_runtime_at_root_core(
    *,
    state_root: Path,
    plan: FrozenPortcastPlan,
    verified_release: VerifiedRelease,
    age_binary: Path,
    age_recipient: str,
    clock_service: Any = None,
) -> Runtime:
    """Open durable authority after a trusted caller binds the plan."""

    _require_open_window(plan)
    runtime_root, ledger_root = prepare_frozen_portcast_runtime_at_root(
        state_root=state_root,
        plan=plan,
        verified_release=verified_release,
        age_binary=age_binary,
        age_recipient=age_recipient,
    )
    _validate_existing_ledger(ledger_root, plan)
    if plan.schema_version in {3, 4}:
        _record_profile_continuation(state_root, ledger_root, plan)
    try:
        runtime = Runtime(
            runtime_root,
            **(
                {"ledger_directory": ledger_root}
                if plan.schema_version in {3, 4}
                else {"ledger_root": ledger_root}
            ),
            verified_release=verified_release,
            clock_service=clock_service,
        )
    except BaseException:
        raise PolicyError(
            "canonical PortCast operational state is invalid"
        ) from None
    runtime._portcast_verified_release = verified_release
    try:
        quick_check = runtime.ledger._db.execute("PRAGMA quick_check").fetchall()
        if quick_check != [("ok",)]:
            raise PolicyError("canonical PortCast ledger integrity differs")
        if not runtime.audit.ready() or not runtime.audit.verify().valid:
            raise PolicyError("canonical PortCast audit is not ready")
        if plan.schema_version in {3, 4}:
            _require_existing_profile_continuation(runtime, state_root, plan)
        elif plan.schema_version == 2:
            _reconcile_predecessor(runtime, plan, runtime_root)
        runtime.audit.profile_inspection_snapshot(plan.action_id)
        runtime.ledger.reservation_state(plan.action_id)
    except BaseException as primary:
        _close_runtime(runtime, primary)
        raise
    return runtime


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


_TRANSPORT_COUNTER_FIELDS = (
    "tcp_connects",
    "udp_datagrams",
    "protocol_requests",
    "tx_bytes",
    "rx_bytes",
)


def _execution_metadata(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    """Project verified one-shot accounting without exposing evidence content."""

    reservation_state = runtime.ledger.reservation_state(plan.action_id)
    attempt = runtime.ledger.optional_attempt_receipt(plan.action_id)
    attempts = [] if attempt is None else attempt.get("attempts")
    if not isinstance(attempts, list) or len(attempts) > 1:
        raise PolicyError("frozen PortCast attempt history is invalid")
    if attempts:
        attempt_state = attempts[0].get("state")
        counters = attempt.get("usage")
        if (
            not isinstance(attempt_state, str)
            or not isinstance(counters, dict)
            or set(counters) != set(_TRANSPORT_COUNTER_FIELDS)
            or any(type(counters[key]) is not int or counters[key] < 0 for key in counters)
        ):
            raise PolicyError("frozen PortCast attempt metadata is invalid")
        transport_counters: dict[str, int] | None = {
            key: counters[key] for key in _TRANSPORT_COUNTER_FIELDS
        }
    else:
        attempt_state = None
        transport_counters = None

    snapshot = snapshot or {
        "has_result_receipt": False,
        "wire_receipt": None,
    }
    wire = snapshot.get("wire_receipt")
    failure_stage = snapshot.get("wire_failure_stage")
    if failure_stage is not None and failure_stage not in PORTCAST_FAILURE_STAGES:
        raise PolicyError("frozen PortCast failure stage is invalid")
    wire_verified = False
    if wire is not None:
        wire_counters = wire.get("counters") if isinstance(wire, dict) else None
        if transport_counters is None or not isinstance(wire_counters, dict):
            raise PolicyError("frozen PortCast wire accounting is incomplete")
        if any(
            wire_counters.get(key) != transport_counters[key]
            for key in _TRANSPORT_COUNTER_FIELDS
        ):
            raise PolicyError("frozen PortCast wire and Ledger counters differ")
        wire_verified = True

    return {
        "reservation_state": reservation_state,
        "attempt_count": len(attempts),
        "attempt_state": attempt_state,
        "transport_counters": transport_counters,
        "wire_counters_verified": wire_verified,
        "result_receipt_present": snapshot.get("has_result_receipt") is True,
        "failure_stage": failure_stage,
    }


def _reconcile_predecessor(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    runtime_root: Path,
) -> dict[str, Any]:
    """Prove v1 reached no dispatch boundary, then bind the reviewed v2.

    This is a narrow recovery path for the known clock-admission failure.  It
    cannot authorize a successor after any reservation, attempt, operation
    intent, wire receipt, target traffic, cleanup receipt, or changed result.
    """

    if plan.schema_version != 2:
        raise PolicyError("profile predecessor reconciliation requires schema v2")
    predecessor = _read_predecessor_plan(plan)
    if not runtime.audit.ready() or not runtime.audit.verify().valid:
        raise PolicyError("profile predecessor audit is invalid")
    if runtime.ledger.stopped():
        raise PolicyError("stopped runtime cannot reconcile a predecessor")
    snapshot = runtime.audit.profile_inspection_snapshot(
        plan.predecessor_action_id
    )
    if snapshot != {
        "action_history": ["profile_release_verified"],
        "cleanup_receipt": None,
        "has_result_receipt": True,
        "wire_failure_stage": None,
        "wire_receipt": None,
    }:
        raise PolicyError("profile predecessor admission history differs")
    if (
        runtime.ledger.reservation_state(plan.predecessor_action_id) is not None
        or runtime.ledger.optional_attempt_receipt(plan.predecessor_action_id)
        is not None
    ):
        raise PolicyError("profile predecessor has durable target state")

    result_path = runtime_root / "results" / (
        plan.predecessor_action_id + ".json"
    )
    try:
        record = json.loads(
            read_private(result_path, 128 * 1024), object_pairs_hook=_pairs
        )
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise PolicyError("profile predecessor result is invalid") from None
    expected_request = to_json(
        OperationRequest(
            plan.predecessor_action_id,
            predecessor["workspace_id"],
            predecessor["device_id"],
            predecessor["operator_id"],
            predecessor["module_id"],
            _target(),
            {"profile_id": predecessor["profile_id"]},
            "operator",
            None,
            predecessor["policy_revision"],
            predecessor["plan_id"],
        )
    )
    expected_result = to_json(
        OperationResult("blocked", reason=_PREDECESSOR_REASON)
    )
    if (
        type(record) is not dict
        or set(record)
        != {
            "version",
            "classification",
            "request",
            "result",
            "audit_sequence",
            "recorded_at",
        }
        or record.get("version") != 1
        or record.get("classification") != "client_confidential"
        or record.get("request") != expected_request
        or record.get("result") != expected_result
        or type(record.get("audit_sequence")) is not int
        or record["audit_sequence"] < 1
        or not isinstance(record.get("recorded_at"), str)
        or _UTC.fullmatch(record["recorded_at"]) is None
    ):
        raise PolicyError("profile predecessor result binding differs")
    receipts = runtime.audit.result_receipts()
    if (
        receipts.get(plan.predecessor_action_id)
        != hashlib.sha256(canonical_json(record)).hexdigest()
    ):
        raise PolicyError("profile predecessor result receipt differs")

    stable = {
        "schema_version": 1,
        "predecessor_action_id": plan.predecessor_action_id,
        "predecessor_plan_id": plan.predecessor_plan_id,
        "predecessor_plan_sha256": plan.predecessor_plan_sha256,
        "action_history": snapshot["action_history"],
        "result_status": record["result"]["status"],
        "result_reason": record["result"]["reason"],
        "reservation_absent": True,
        "attempt_absent": True,
        "wire_receipt_absent": True,
        "cleanup_receipt_absent": True,
        "target_traffic_absent": True,
        "result_receipt_present": True,
        "stopped": False,
    }
    actual_reconciliation_sha256 = hashlib.sha256(
        _canonical(stable)
    ).hexdigest()
    if actual_reconciliation_sha256 != plan.predecessor_reconciliation_sha256:
        raise PolicyError("profile predecessor reconciliation digest differs")

    runtime.audit.emit(
        AuditEvent(
            "profile_predecessor_reconciliation_intent",
            plan.predecessor_action_id,
            {
                "reconciliation_sha256": actual_reconciliation_sha256,
                "successor_action_id": plan.action_id,
                "successor_plan_sha256": plan.plan_sha256,
            },
        )
    )
    result = runtime.ledger.reconcile_profile_predecessor(
        predecessor_action_id=plan.predecessor_action_id,
        predecessor_plan_id=plan.predecessor_plan_id,
        predecessor_plan_sha256=plan.predecessor_plan_sha256,
        successor_action_id=plan.action_id,
        successor_plan_id=plan.plan_id,
        successor_plan_sha256=plan.plan_sha256,
        reconciliation_sha256=actual_reconciliation_sha256,
        reason_code=plan.predecessor_reason_code,
    )
    runtime.audit.emit(
        AuditEvent(
            "profile_predecessor_reconciled",
            plan.predecessor_action_id,
            {
                "created": result["created"],
                "reconciliation_sha256": actual_reconciliation_sha256,
                "successor_action_id": plan.action_id,
                "successor_plan_sha256": plan.plan_sha256,
            },
        )
    )
    return result


def _require_existing_predecessor_reconciliation(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
) -> None:
    """Verify the startup-created tombstone without mutating audit or ledger."""

    existing = runtime.ledger.profile_reconciliation(
        plan.predecessor_action_id
    )
    expected = {
        "predecessor_action_id": plan.predecessor_action_id,
        "predecessor_plan_id": plan.predecessor_plan_id,
        "predecessor_plan_sha256": plan.predecessor_plan_sha256,
        "successor_action_id": plan.action_id,
        "successor_plan_id": plan.plan_id,
        "successor_plan_sha256": plan.plan_sha256,
        "reconciliation_sha256": plan.predecessor_reconciliation_sha256,
        "reason_code": plan.predecessor_reason_code,
        "reservation_absent": True,
        "attempt_absent": True,
        "target_traffic_absent": True,
    }
    if existing is None or any(
        existing.get(key) != value for key, value in expected.items()
    ):
        raise PolicyError("canonical PortCast predecessor reconciliation differs")


def _replay_metadata(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    runtime_root: Path,
    *,
    stop_on_incomplete: bool = True,
) -> dict[str, Any] | None:
    """Block both Ledger replay and audit-only interrupted action history."""

    state = runtime.ledger.reservation_state(plan.action_id)
    tombstone = runtime.ledger.profile_reconciliation(plan.action_id)
    try:
        snapshot = runtime.audit.profile_inspection_snapshot(plan.action_id)
    except PolicyError:
        if not stop_on_incomplete:
            raise PolicyError("frozen PortCast audit history is incomplete") from None
        runtime.ledger.stop("frozen PortCast audit history incomplete")
        return {
            "action_id": plan.action_id,
            "audit_verified": runtime.audit.verify().valid,
            "automatic_retry": False,
            "cleanup_status": None,
            "profile_id": plan.profile_id,
            "receipt_outcome": None,
            "status": "blocked",
            "workspace": plan.workspace_id,
            "execution": _execution_metadata(runtime, plan, None),
            "reason": "frozen action has incomplete durable audit history",
        }
    history = tuple(snapshot["action_history"])
    if tombstone is not None:
        runtime.ledger.stop("reconciled predecessor audit history differs")
        return {
            "action_id": plan.action_id,
            "audit_verified": runtime.audit.verify().valid,
            "automatic_retry": False,
            "cleanup_status": None,
            "profile_id": plan.profile_id,
            "receipt_outcome": None,
            "status": "blocked",
            "workspace": plan.workspace_id,
            "execution": _execution_metadata(runtime, plan, snapshot),
            "reason": "reconciled predecessor action is permanently spent",
        }
    if history:
        receipt = snapshot["wire_receipt"]
        cleanup = snapshot["cleanup_receipt"]
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
            "workspace": plan.workspace_id,
            "execution": _execution_metadata(runtime, plan, snapshot),
            "reason": "frozen action already has durable admission history",
        }

    if state is None and not snapshot["has_result_receipt"]:
        return None
    receipt = snapshot["wire_receipt"]
    cleanup = snapshot["cleanup_receipt"]
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
        "workspace": plan.workspace_id,
        "execution": _execution_metadata(runtime, plan, snapshot),
        "reason": reason,
    }


def _require_prepared_runtime(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    state_root: Path,
) -> Path:
    runtime_root = state_root / (
        f"v{plan.schema_version}/runtime"
        if plan.schema_version in {3, 4, 5, 6, 7}
        else "runtime"
    )
    ledger_directory = (
        state_root / "ledger" / plan.predecessor_engagement_id
        if plan.schema_version in {3, 4}
        else state_root / f"v{plan.schema_version}" / "ledger" / plan.engagement_id
        if plan.schema_version in {5, 6, 7}
        else state_root / "ledger" / plan.engagement_id
    )
    if (
        type(runtime) is not Runtime
        or runtime.root != runtime_root.absolute()
        or runtime.ledger_root != ledger_directory.absolute()
        or runtime.policy != policy_for_plan(plan)
        or not runtime.audit.verify().valid
    ):
        raise PolicyError("canonical PortCast prepared runtime differs")
    return runtime_root


def inspect_prepared_portcast_state(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    state_root: Path,
) -> dict[str, Any] | None:
    """Inspect production state only for the exact current plan."""

    _require_exact_loaded_plan(plan)
    return _inspect_prepared_portcast_state_core(runtime, plan, state_root)


def _inspect_prepared_portcast_state_core(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    state_root: Path,
) -> dict[str, Any] | None:
    """Inspect after a trusted caller has bound the plan."""

    _require_open_window(plan)
    runtime_root = _require_prepared_runtime(runtime, plan, state_root)
    if plan.schema_version in {3, 4}:
        _require_existing_profile_continuation(runtime, state_root, plan)
    elif plan.schema_version == 2:
        _require_existing_predecessor_reconciliation(runtime, plan)
    return _replay_metadata(
        runtime,
        plan,
        runtime_root,
        stop_on_incomplete=False,
    )


def run_prepared_portcast_action(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    state_root: Path,
    verified_release: VerifiedRelease,
    wire_broker_factory: Any,
) -> dict[str, Any]:
    """Run the one action through the already-open canonical authority."""

    _require_exact_loaded_plan(plan)
    _require_open_window(plan)
    _require_runtime_release_binding(runtime, plan, verified_release)
    runtime_root = _require_prepared_runtime(runtime, plan, state_root)
    if not runtime.audit.ready():
        raise PolicyError("canonical PortCast audit is not ready")
    if not runtime.clock.valid_for(12.0):
        raise PolicyError("clock is not safe for the complete bounded action")
    if plan.schema_version in {3, 4}:
        _require_existing_profile_continuation(runtime, state_root, plan)
    elif plan.schema_version == 2:
        _reconcile_predecessor(runtime, plan, runtime_root)
    return _run_prepared_portcast_action_core(
        runtime,
        plan,
        runtime_root,
        verified_release,
        wire_broker_factory,
    )


def _run_prepared_portcast_action_core(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    runtime_root: Path,
    verified_release: VerifiedRelease,
    wire_broker_factory: Any,
) -> dict[str, Any]:
    """Dispatch after the trusted caller has completed admission gates."""

    _require_runtime_release_binding(runtime, plan, verified_release)
    replay = _replay_metadata(runtime, plan, runtime_root)
    if replay is not None:
        return replay
    if not callable(wire_broker_factory):
        raise PolicyError("canonical PortCast service broker factory is unavailable")
    if plan.schema_version == 7:
        state_root = runtime_root.parents[1]
        _verify_v7_predecessor_receipts(state_root, plan)
        runtime.audit.emit(
            AuditEvent(
                "profile_predecessor_snapshot_bound",
                plan.action_id,
                {
                    "predecessor_v5_state_sha256": (
                        plan.predecessor_v5_state_sha256
                    ),
                    "superseded_v6_state_receipt_sha256": (
                        plan.superseded_v6_state_receipt_sha256
                    ),
                    "predecessor_snapshot_sha256": hashlib.sha256(
                        canonical_json(
                            {
                                "v5": plan.predecessor_v5_state_sha256,
                                "v6_unused": (
                                    plan.superseded_v6_state_receipt_sha256
                                ),
                            }
                        )
                    ).hexdigest(),
                },
            )
        )
    elif plan.schema_version == 6:
        state_root = runtime_root.parents[1]
        _verify_v5_predecessor_receipt(state_root, plan)
        runtime.audit.emit(
            AuditEvent(
                "profile_predecessor_snapshot_bound",
                plan.action_id,
                {
                    "predecessor_v5_state_sha256": (
                        plan.predecessor_v5_state_sha256
                    ),
                    "predecessor_v5_admission_marker_sha256": (
                        plan.predecessor_v5_admission_marker_sha256
                    ),
                    "predecessor_snapshot_sha256": (
                        plan.predecessor_v5_state_sha256
                    ),
                },
            )
        )
    elif plan.schema_version == 5:
        state_root = runtime_root.parents[1]
        old_ledger = state_root / "ledger" / plan.predecessor_engagement_id
        runtime_config = json.loads(
            read_private(runtime_root / "runtime.json", 8192),
            object_pairs_hook=_pairs,
        )
        v3_snapshot = _verify_aborted_v3_state(
            state_root=state_root,
            ledger_directory=old_ledger,
            plan=plan,
            age_binary=Path(runtime_config["age_binary"]),
            age_recipient=plan.evidence_recipient,
        )
        v4_snapshot = _v4_predecessor_state_snapshot(
            state_root,
            old_ledger,
            plan,
            age_binary=Path(runtime_config["age_binary"]),
            age_recipient=plan.evidence_recipient,
        )
        predecessor_snapshot_sha256 = hashlib.sha256(
            canonical_json({"v3": v3_snapshot, "v4": v4_snapshot})
        ).hexdigest()
        runtime.audit.emit(
            AuditEvent(
                "profile_predecessor_snapshot_bound",
                plan.action_id,
                {
                    "predecessor_v3_state_sha256": plan.predecessor_v3_state_sha256,
                    "predecessor_v4_state_sha256": plan.predecessor_v4_state_sha256,
                    "predecessor_v4_continuation_row_sha256": plan.predecessor_v4_continuation_row_sha256,
                    "predecessor_snapshot_sha256": predecessor_snapshot_sha256,
                },
            )
        )
    runtime.attach_profile_wire_broker(
        wire_broker_factory(runtime.ledger, verified_release)
    )
    runtime.audit.emit(
        AuditEvent(
            "profile_release_verified",
            plan.action_id,
            {
                "release_id": verified_release.release_id,
                "manifest_sha256": verified_release.manifest_sha256,
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
        plan.workflow_id,
    )
    return _execute_action(runtime, plan, request, runtime_root)


def _require_runtime_release_binding(
    runtime: Runtime,
    plan: FrozenPortcastPlan,
    verified_release: VerifiedRelease,
) -> None:
    """Bind the caller's release proof before any broker factory invocation."""

    if type(verified_release) is not VerifiedRelease:
        raise PolicyError("prepared PortCast release binding differs")
    bound = getattr(runtime, "_portcast_verified_release", None)
    if bound != verified_release:
        raise PolicyError("prepared PortCast release binding differs")
    expected = validate_current_release(plan)
    if verified_release != expected:
        raise PolicyError("prepared PortCast release binding differs")


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
    if plan.schema_version == 7:
        _verify_v7_predecessor_receipts(state_root, plan)
    elif plan.schema_version == 6:
        _verify_v5_predecessor_receipt(state_root, plan)
    elif plan.schema_version == 5:
        _verify_v5_predecessors(
            state_root,
            plan,
            age_binary=age_binary,
            age_recipient=age_recipient,
        )
    runtime_root, ledger_root = _prepare_runtime(
        state_root,
        plan,
        age_binary=age_binary,
        age_recipient=age_recipient,
        provision=provision,
    )
    _validate_existing_ledger(ledger_root, plan)
    if plan.schema_version in {3, 4}:
        _record_profile_continuation(state_root, ledger_root, plan)
    runtime = Runtime(
        runtime_root,
        **(
            {"ledger_directory": ledger_root}
            if plan.schema_version in {3, 4}
            else {"ledger_root": ledger_root}
        ),
        verified_release=verified,
    )
    try:
        if plan.schema_version in {3, 4}:
            _require_existing_profile_continuation(runtime, state_root, plan)
        elif plan.schema_version == 2:
            _reconcile_predecessor(runtime, plan, runtime_root)
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
    if plan.schema_version == 7:
        if not isinstance(age_binary, Path) or not isinstance(age_recipient, str):
            raise PolicyError("canonical PortCast predecessor verification is unavailable")
        _verify_v7_predecessor_receipts(state_root, plan)
    elif plan.schema_version == 6:
        if not isinstance(age_binary, Path) or not isinstance(age_recipient, str):
            raise PolicyError("canonical PortCast predecessor verification is unavailable")
        _verify_v5_predecessor_receipt(state_root, plan)
    elif plan.schema_version == 5:
        if not isinstance(age_binary, Path) or not isinstance(age_recipient, str):
            raise PolicyError("canonical PortCast predecessor verification is unavailable")
        _verify_v5_predecessors(
            state_root,
            plan,
            age_binary=age_binary,
            age_recipient=age_recipient,
        )
    runtime_root, ledger_root = _prepare_runtime(
        state_root,
        plan,
        age_binary=age_binary,
        age_recipient=age_recipient,
        provision=provision,
    )
    _validate_existing_ledger(ledger_root, plan)
    if plan.schema_version in {3, 4}:
        _record_profile_continuation(state_root, ledger_root, plan)
    runtime = Runtime(
        runtime_root,
        **(
            {"ledger_directory": ledger_root}
            if plan.schema_version in {3, 4}
            else {"ledger_root": ledger_root}
        ),
        verified_release=verified,
    )
    runtime._portcast_verified_release = verified
    if clock_override is not None:
        runtime.broker.clock = clock_override
    try:
        if plan.schema_version in {3, 4}:
            _require_existing_profile_continuation(runtime, state_root, plan)
        elif plan.schema_version == 2:
            _reconcile_predecessor(runtime, plan, runtime_root)
        outcome = _run_prepared_portcast_action_core(
            runtime,
            plan,
            runtime_root,
            verified,
            wire_broker_factory,
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
        snapshot = runtime.audit.profile_inspection_snapshot(plan.action_id)
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
            "workspace": plan.workspace_id,
            "execution": _execution_metadata(runtime, plan, snapshot),
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
    snapshot = runtime.audit.profile_inspection_snapshot(plan.action_id)
    outcome = {
        "action_id": plan.action_id,
        "audit_verified": runtime.audit.verify().valid,
        "automatic_retry": False,
        "cleanup_status": cleanup_status,
        "profile_id": plan.profile_id,
        "receipt_outcome": receipt.get("outcome") if isinstance(receipt, dict) else None,
        "status": result.status,
        "workspace": plan.workspace_id,
        "execution": _execution_metadata(runtime, plan, snapshot),
    }
    if result.reason is not None:
        outcome["reason"] = result.reason
    return outcome


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
    "load_frozen_portcast_plan_v2",
    "load_frozen_portcast_plan_v3",
    "load_frozen_portcast_plan_v4",
    "load_frozen_portcast_plan_v5",
    "load_frozen_portcast_plan_v6",
    "load_frozen_portcast_plan_v7",
    "policy_for_plan",
    "run_frozen_portcast_action",
    "run_frozen_portcast_session",
    "validate_current_release",
)
