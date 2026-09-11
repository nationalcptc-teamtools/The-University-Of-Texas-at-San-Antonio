"""Metadata-only client for the canonical PortCast authority service."""

from __future__ import annotations

import json
from pathlib import Path
import socket
from typing import Any

from ..contracts import PolicyError, canonical_json


PORTCAST_SERVICE_SOCKET = Path("/run/cptc-harness/portcast-live-v1.sock")
_MAX_PACKET = 64 * 1024
_RESULT_FIELDS = {
    "action_id",
    "audit_verified",
    "automatic_retry",
    "cleanup_status",
    "profile_id",
    "receipt_outcome",
    "status",
    "workspace",
}
_OPTIONAL_RESULT_FIELDS = {"reason"}


def _validate_result(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not _RESULT_FIELDS <= set(value)
        or set(value) - _RESULT_FIELDS - _OPTIONAL_RESULT_FIELDS
        or value.get("action_id") != "cptc11-portcast-public-identity-action-v1"
        or value.get("profile_id") != "web.http_jellyfin_public_identity"
        or value.get("automatic_retry") is not False
        or type(value.get("audit_verified")) is not bool
        or value.get("status")
        not in {"complete", "failed", "blocked", "stopped", "uncertain"}
    ):
        raise PolicyError("canonical PortCast service returned invalid metadata")
    return dict(value)


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


__all__ = ("PORTCAST_SERVICE_SOCKET", "PortcastServiceClient")
