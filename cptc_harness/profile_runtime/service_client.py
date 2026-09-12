"""Metadata-only client for the canonical PortCast authority service."""

from __future__ import annotations

import json
from pathlib import Path
import socket
from typing import Any

from ..contracts import PolicyError, canonical_json
from .contracts import PORTCAST_FAILURE_STAGES


PORTCAST_SERVICE_SOCKET = Path("/run/cptc-harness/portcast-live-v1.sock")
_MAX_PACKET = 64 * 1024
_RESULT_FIELDS = {
    "action_id",
    "audit_verified",
    "automatic_retry",
    "cleanup_status",
    "execution",
    "profile_id",
    "receipt_outcome",
    "status",
    "workspace",
}
_OPTIONAL_RESULT_FIELDS = {"reason"}
_EXECUTION_FIELDS_V1 = {
    "reservation_state",
    "attempt_count",
    "attempt_state",
    "transport_counters",
    "wire_counters_verified",
    "result_receipt_present",
}
_EXECUTION_FIELDS = _EXECUTION_FIELDS_V1 | {"failure_stage"}
_COUNTER_LIMITS = {
    "tcp_connects": 1,
    "udp_datagrams": 0,
    "protocol_requests": 1,
    "tx_bytes": 256,
    "rx_bytes": 8192,
}
_SAFE_REASONS = frozenset(
    {
        "PortCast broker cleanup failed; manual review required",
        "PortCast identity response did not match the reviewed parser",
        "PortCast profile dispatch was denied before connection",
        "PortCast profile transport did not complete",
        "PortCast target differs from the reviewed candidate profile",
        "audit output release failed; human review required",
        "clock is not safe for active work",
        "frozen action already has a durable result receipt",
        "frozen action already has durable admission history",
        "frozen action has incomplete durable audit history",
        "operation outcome uncertain; human review required",
        "operator stop requested",
        "reconciled predecessor action is permanently spent",
        "registered operation failed",
        "result storage or audit failed; human review required",
        "trusted PortCast profile dispatcher is unavailable",
        *(
            f"frozen action already has durable state {state}"
            for state in (
                "blocked",
                "complete",
                "dispatching",
                "failed",
                "planned",
                "running",
                "stopped",
                "uncertain",
            )
        ),
    }
)
_RESERVATION_STATES = {
    None,
    "planned",
    "dispatching",
    "running",
    "complete",
    "failed",
    "blocked",
    "stopped",
    "uncertain",
}
_ATTEMPT_STATES = {
    None,
    "running",
    "complete",
    "failed",
    "blocked",
    "stopped",
    "uncertain",
}


def _invalid_metadata() -> None:
    raise PolicyError("canonical PortCast service returned invalid metadata")


def _validate_portcast_result(
    value: Any, expected_action_id: str
) -> dict[str, Any]:
    """Validate a fixed metadata-only one-shot service result."""

    if (
        type(value) is not dict
        or not _RESULT_FIELDS <= set(value)
        or set(value) - _RESULT_FIELDS - _OPTIONAL_RESULT_FIELDS
        or value.get("action_id") != expected_action_id
        or value.get("profile_id") != "web.http_jellyfin_public_identity"
        or value.get("automatic_retry") is not False
        or type(value.get("audit_verified")) is not bool
        or value.get("cleanup_status") not in {None, "passed", "failed"}
        or value.get("receipt_outcome")
        not in {None, "complete", "incomplete", "uncertain", "cancelled"}
        or value.get("status")
        not in {"complete", "failed", "blocked", "stopped", "uncertain"}
        or value.get("workspace") != "cptc11-portcast-workspace"
        or (
            "reason" in value
            and (
                type(value["reason"]) is not str
                or value["reason"] not in _SAFE_REASONS
            )
        )
    ):
        _invalid_metadata()

    execution = value.get("execution")
    if (
        type(execution) is not dict
        or (
            set(execution) != _EXECUTION_FIELDS_V1
            and set(execution) != _EXECUTION_FIELDS
        )
    ):
        _invalid_metadata()
    attempt_count = execution.get("attempt_count")
    reservation_state = execution.get("reservation_state")
    attempt_state = execution.get("attempt_state")
    counters = execution.get("transport_counters")
    failure_stage = execution.get("failure_stage")
    if (
        reservation_state not in _RESERVATION_STATES
        or attempt_state not in _ATTEMPT_STATES
        or type(attempt_count) is not int
        or attempt_count not in {0, 1}
        or type(execution.get("wire_counters_verified")) is not bool
        or type(execution.get("result_receipt_present")) is not bool
        or failure_stage is not None
        and failure_stage not in PORTCAST_FAILURE_STAGES
    ):
        _invalid_metadata()
    if attempt_count == 0:
        if attempt_state is not None or counters is not None:
            _invalid_metadata()
        normalized_counters = None
    else:
        if attempt_state is None or type(counters) is not dict or set(counters) != set(_COUNTER_LIMITS):
            _invalid_metadata()
        if any(
            type(counters[key]) is not int
            or counters[key] < 0
            or counters[key] > _COUNTER_LIMITS[key]
            for key in _COUNTER_LIMITS
        ):
            _invalid_metadata()
        normalized_counters = {key: counters[key] for key in _COUNTER_LIMITS}

    if execution["wire_counters_verified"] and normalized_counters is None:
        _invalid_metadata()
    if value["status"] == "complete":
        if (
            "reason" in value
            or
            value["audit_verified"] is not True
            or value["cleanup_status"] != "passed"
            or value["receipt_outcome"] != "complete"
            or reservation_state != "complete"
            or attempt_count != 1
            or attempt_state != "complete"
            or normalized_counters is None
            or normalized_counters["tcp_connects"] != 1
            or normalized_counters["udp_datagrams"] != 0
            or normalized_counters["protocol_requests"] != 1
            or normalized_counters["tx_bytes"] != 103
            or normalized_counters["rx_bytes"] <= 0
            or execution["wire_counters_verified"] is not True
            or execution["result_receipt_present"] is not True
            or failure_stage is not None
        ):
            _invalid_metadata()

    normalized = {key: value[key] for key in _RESULT_FIELDS if key != "execution"}
    normalized_execution = {
        "reservation_state": reservation_state,
        "attempt_count": attempt_count,
        "attempt_state": attempt_state,
        "transport_counters": normalized_counters,
        "wire_counters_verified": execution["wire_counters_verified"],
        "result_receipt_present": execution["result_receipt_present"],
    }
    if "failure_stage" in execution:
        normalized_execution["failure_stage"] = failure_stage
    normalized["execution"] = normalized_execution
    if "reason" in value:
        normalized["reason"] = value["reason"]
    return normalized


def validate_portcast_result(value: Any) -> dict[str, Any]:
    """Validate the strict v3 metadata contract."""

    return _validate_portcast_result(
        value, "cptc11-portcast-public-identity-action-v3"
    )


def validate_portcast_result_v4(value: Any) -> dict[str, Any]:
    """Validate the strict v4 metadata contract."""

    return _validate_portcast_result(
        value, "cptc11-portcast-public-identity-action-v4"
    )


def validate_portcast_result_v5(value: Any) -> dict[str, Any]:
    """Validate the current schema-v5 metadata contract."""

    return _validate_portcast_result(
        value, "cptc11-portcast-public-identity-action-v5"
    )


def _validate_result(value: Any) -> dict[str, Any]:
    return validate_portcast_result_v5(value)


class PortcastServiceClient:
    """Connect only to the fixed production socket and accept no state path."""

    def __init__(self) -> None:
        self._socket_path = PORTCAST_SERVICE_SOCKET

    @classmethod
    def _for_test(cls, socket_path: Path) -> "PortcastServiceClient":
        client = object.__new__(cls)
        client._socket_path = Path(socket_path)
        return client

    def _request(self, method: str) -> dict[str, Any] | None:
        if method not in {"execute", "inspect"}:
            raise PolicyError("unsupported canonical PortCast service request")
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channel.settimeout(30)
        try:
            channel.connect(str(self._socket_path))
            request = canonical_json(
                {"method": method, "release_id": "portcast-live-v1"}
            )
            if channel.send(request) != len(request):
                raise OSError("short service request")
            raw = channel.recv(_MAX_PACKET + 1)
        except OSError:
            raise PolicyError("canonical PortCast authority service is unavailable") from None
        finally:
            channel.close()
        if not raw or len(raw) > _MAX_PACKET:
            raise PolicyError("canonical PortCast service response is invalid")
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            raise PolicyError("canonical PortCast service response is invalid") from None
        if not isinstance(response, dict) or set(response) != {"ok", "result"}:
            raise PolicyError("canonical PortCast service response is invalid")
        if response["ok"] is not True:
            raise PolicyError("canonical PortCast service denied the request")
        if response["result"] is None and method == "inspect":
            return None
        return _validate_result(response["result"])

    def execute(self) -> dict[str, Any]:
        result = self._request("execute")
        if result is None:
            raise PolicyError("canonical PortCast service returned no result")
        return result

    def inspect(self) -> dict[str, Any] | None:
        return self._request("inspect")


__all__ = (
    "PORTCAST_SERVICE_SOCKET",
    "PortcastServiceClient",
    "validate_portcast_result",
    "validate_portcast_result_v4",
    "validate_portcast_result_v5",
)
