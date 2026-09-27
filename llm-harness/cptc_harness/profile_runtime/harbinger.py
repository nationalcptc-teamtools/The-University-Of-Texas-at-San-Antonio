"""Build one signed, metadata-only Harbinger observation from verified state."""

from __future__ import annotations

import base64
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping
import uuid

from ..contracts import PolicyError, canonical_json
from ..storage import read_private
from .catalog import load_profile, require_live_admission


PORTCAST_HARBINGER_PROFILE = "web.http_jellyfin_public_identity"
PORTCAST_REPLAY_NAMESPACE = uuid.UUID("2d9c186e-308b-5b02-8bf1-d9c1ebea2874")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise PolicyError(f"invalid {label}")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise PolicyError(f"invalid {label}")
    return value


def _uuid(value: Any, label: str) -> str:
    if type(value) is not str:
        raise PolicyError(f"invalid {label}")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise PolicyError(f"invalid {label}") from None
    if str(parsed) != value:
        raise PolicyError(f"invalid {label}")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise PolicyError(f"invalid {label} timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise PolicyError(f"invalid {label} timestamp") from None
    return parsed


def _plan_dict(plan: Any) -> dict[str, Any]:
    if is_dataclass(plan):
        value = asdict(plan)
    elif isinstance(plan, Mapping):
        value = dict(plan)
    else:
        raise PolicyError("frozen plan is unavailable")
    required = {
        "action_id",
        "catalog_sha256",
        "engagement_id",
        "device_id",
        "module_id",
        "module_source_sha256",
        "operation_sha256",
        "parser_sha256",
        "plan_id",
        "plan_sha256",
        "policy_revision",
        "profile_id",
        "profile_sha256",
        "release_id",
        "runtime_pinset_sha256",
        "target_id",
        "operator_id",
        "workspace_id",
        "worker_sha256",
    }
    if not required <= set(value):
        raise PolicyError("frozen plan provenance is incomplete")
    for name in (
        "catalog_sha256",
        "module_source_sha256",
        "operation_sha256",
        "parser_sha256",
        "plan_sha256",
        "profile_sha256",
        "runtime_pinset_sha256",
        "worker_sha256",
    ):
        _hash(value[name], name.replace("_", " "))
    for name in (
        "action_id",
        "device_id",
        "engagement_id",
        "module_id",
        "operator_id",
        "plan_id",
        "policy_revision",
        "profile_id",
        "release_id",
        "target_id",
        "workspace_id",
    ):
        _identifier(value[name], name.replace("_", " "))
    return value


def _action_events(
    runtime: Any, action_id: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Read metadata events only after the AuditService verifies its chain."""

    if not runtime.audit.verify().valid or not runtime.audit.ready():
        raise PolicyError("verified audit is required for Harbinger export")
    root = Path(runtime.root) / "audit"
    segments = root / "segments"
    paths = []
    if segments.is_dir():
        paths.extend(path / "audit.jsonl" for path in sorted(segments.iterdir()))
    paths.append(root / "audit.jsonl")
    intents = []
    results = []
    releases = []
    for path in paths:
        for line in read_private(path, 128 * 1024 * 1024).splitlines():
            event = json.loads(line)
            if event.get("action_id") != action_id:
                continue
            if event.get("kind") == "operation_intent":
                intents.append(event)
            elif event.get("kind") == "operation_result":
                results.append(event)
            elif event.get("kind") == "profile_release_verified":
                releases.append(event)
    if len(intents) != 1 or len(results) != 1 or len(releases) != 1:
        raise PolicyError("PortCast action audit history is incomplete")
    return intents[0], results[0], releases[0]


def _semantic_observation_id(
    *,
    plan: Mapping[str, Any],
    policy_sha256: str,
    evidence_sha256: str,
    release_sha256: str,
) -> str:
    value = {
        "schema": "harbinger.portcast.replay.v1",
        "source_engagement_id": plan["engagement_id"],
        "policy_sha256": policy_sha256,
        "release_sha256": release_sha256,
        "frozen_plan_id": plan["plan_id"],
        "frozen_plan_sha256": plan["plan_sha256"],
        "action_id": plan["action_id"],
        "profile_id": plan["profile_id"],
        "target_id": plan["target_id"],
        "check_id": "portcast_public_identity",
        "evidence_sha256": evidence_sha256,
    }
    return str(
        uuid.uuid5(
            PORTCAST_REPLAY_NAMESPACE,
            canonical_json(value).decode("ascii"),
        )
    )


def _validate_execution_state(runtime: Any, plan: Mapping[str, Any]) -> dict[str, Any]:
    action_id = plan["action_id"]
    if (
        runtime.policy.engagement_id != plan["engagement_id"]
        or runtime.policy.revision != plan["policy_revision"]
        or runtime.policy.workspace_id != plan["workspace_id"]
        or runtime.policy.device_id != plan["device_id"]
        or runtime.policy.operator_id != plan["operator_id"]
    ):
        raise PolicyError("PortCast policy identity differs from the frozen plan")
    if runtime.ledger.stopped():
        raise PolicyError("stopped workspace cannot export a Harbinger observation")
    if runtime.ledger.reservation_state(action_id) != "complete":
        raise PolicyError("PortCast action is not complete")
    wire = runtime.audit.profile_wire_receipts().get(action_id)
    cleanup = runtime.audit.profile_cleanup_receipts().get(action_id)
    result_receipts = runtime.audit.result_receipts()
    if (
        not isinstance(wire, dict)
        or wire.get("outcome") != "complete"
        or wire.get("wave_id") != plan.get("workflow_id", plan["plan_id"])
        or wire.get("action_id") != plan["action_id"]
        or wire.get("profile_id") != plan["profile_id"]
        or wire.get("target_id") != plan["target_id"]
        or wire.get("catalog_sha256") != plan["catalog_sha256"]
        or wire.get("profile_sha256") != plan["profile_sha256"]
        or wire.get("operation_sha256") != plan["operation_sha256"]
        or wire.get("worker_sha256") != plan["worker_sha256"]
        or wire.get("runtime_pinset_sha256") != plan["runtime_pinset_sha256"]
        or cleanup
        != {
            "all_resources_closed": True,
            "automatic_retry": False,
            "status": "passed",
        }
        or action_id not in result_receipts
    ):
        raise PolicyError("PortCast receipts are incomplete")
    attempt = runtime.ledger.attempt_receipt(action_id)
    attempts = attempt.get("attempts")
    if (
        not isinstance(attempts, list)
        or len(attempts) != 1
        or attempts[0].get("state") != "complete"
        or attempts[0].get("deadline_exceeded") is not False
    ):
        raise PolicyError("PortCast attempt is not uniquely complete")
    wire_counters = wire.get("counters")
    usage = attempt.get("usage")
    if not isinstance(wire_counters, dict) or not isinstance(usage, dict):
        raise PolicyError("PortCast counters are unavailable")
    for wire_name, ledger_name in (
        ("tcp_connects", "tcp_connects"),
        ("udp_datagrams", "udp_datagrams"),
        ("protocol_requests", "protocol_requests"),
        ("tx_bytes", "tx_bytes"),
        ("rx_bytes", "rx_bytes"),
    ):
        if wire_counters.get(wire_name) != usage.get(ledger_name):
            raise PolicyError("PortCast wire and Ledger counters differ")
    records = [
        record
        for record in runtime._records()
        if record.get("request", {}).get("request_id") == action_id
    ]
    if len(records) != 1:
        raise PolicyError("PortCast result record is unavailable")
    record = records[0]
    request = record.get("request")
    result = record.get("result")
    if not isinstance(request, dict) or not isinstance(result, dict):
        raise PolicyError("PortCast result record is invalid")
    target = request.get("target")
    expected_request = {
        "module_id": plan["module_id"],
        "policy_revision": plan["policy_revision"],
        "workflow_id": plan.get("workflow_id", plan["plan_id"]),
        "args": {"profile_id": plan["profile_id"]},
    }
    if any(request.get(name) != expected for name, expected in expected_request.items()):
        raise PolicyError("PortCast request provenance differs")
    if (
        not isinstance(target, dict)
        or target.get("target_id") != plan["target_id"]
        or target.get("host") != "10.0.1.30"
        or target.get("port") != 8096
        or target.get("scheme") != "http"
        or target.get("base_path") != "/System/Info/Public"
    ):
        raise PolicyError("PortCast result target differs")
    observations = result.get("facts", {}).get("observations")
    evidence = result.get("evidence")
    if (
        result.get("status") != "complete"
        or result.get("reason") is not None
        or not isinstance(observations, list)
        or len(observations) != 1
        or not isinstance(evidence, list)
        or len(evidence) != 1
    ):
        raise PolicyError("PortCast result is not one complete observation")
    observation = observations[0]
    reference = evidence[0]
    expected_facts = {
        "component_id": "service:10.0.1.30:8096/jellyfin",
        "ecosystem": "semver",
        "product": "Jellyfin Server",
        "version": "10.10.7",
        "provenance": "banner",
    }
    if (
        observation
        != {
            "track": "web",
            "target": "http://10.0.1.30:8096/System/Info/Public",
            "check_id": "portcast_public_identity",
            "state": "candidate",
            "facts": expected_facts,
            "source_sha256": wire.get("evidence_sha256"),
        }
        or reference.get("evidence_id") != wire.get("encrypted_artifact_id")
        or reference.get("target_id") not in {None, plan["target_id"]}
        or reference.get("check_id") != "raw"
        or reference.get("classification") != "client_confidential_human_only"
        or reference.get("sha256") != wire.get("evidence_sha256")
        or reference.get("bytes") != wire.get("evidence_bytes")
    ):
        raise PolicyError("PortCast typed observation differs from wire evidence")
    intent, audit_result, release_event = _action_events(runtime, action_id)
    release_data = release_event.get("data")
    if (
        intent.get("data", {}).get("source_sha256")
        != plan["module_source_sha256"]
        or audit_result.get("data", {}).get("status") != "complete"
        or not isinstance(release_data, dict)
        or set(release_data) != {"release_id", "manifest_sha256"}
        or release_data.get("release_id") != plan["release_id"]
        or _HEX64.fullmatch(release_data.get("manifest_sha256", "")) is None
    ):
        raise PolicyError("PortCast audited release provenance differs")
    return {
        "wire": wire,
        "attempt": attempt,
        "observation": observation,
        "release": release_data,
    }


def build_portcast_harbinger_envelope(
    *,
    runtime: Any,
    frozen_plan: Any,
    harbinger_engagement_id: str,
    source_id: str,
    key_id: str,
    review_id: str,
    reviewed_at: str,
    issued_at: str,
    signer: Callable[[bytes], bytes],
) -> dict[str, Any]:
    """Build and sign one client-confidential observation without raw evidence."""

    plan = _plan_dict(frozen_plan)
    if plan["profile_id"] != PORTCAST_HARBINGER_PROFILE:
        raise PolicyError("Harbinger export profile differs")
    profile = require_live_admission(load_profile(plan["profile_id"]))
    if (
        profile.target_id != plan["target_id"]
        or profile.module_id != plan["module_id"]
        or profile.catalog_sha256 != plan["catalog_sha256"]
        or profile.profile_sha256 != plan["profile_sha256"]
        or profile.operation.sha256 != plan["operation_sha256"]
        or profile.runtime_pinset_sha256 != plan["runtime_pinset_sha256"]
    ):
        raise PolicyError("Harbinger export profile provenance differs")
    engagement_id = _uuid(harbinger_engagement_id, "Harbinger engagement ID")
    source_id = _uuid(source_id, "source ID")
    review_id = _uuid(review_id, "review ID")
    if type(key_id) is not str or _KEY_ID.fullmatch(key_id) is None:
        raise PolicyError("invalid signing key ID")
    if not callable(signer):
        raise PolicyError("operator signing reference is unavailable")
    state = _validate_execution_state(runtime, plan)
    wire = state["wire"]
    observed_at = wire["completed_at"]
    observed_time = _timestamp(observed_at, "observed")
    reviewed_time = _timestamp(reviewed_at, "review")
    issued_time = _timestamp(issued_at, "issue")
    if not observed_time <= reviewed_time <= issued_time:
        raise PolicyError("Harbinger export timestamps are out of order")
    policy_sha256 = hashlib.sha256(canonical_json(runtime.policy)).hexdigest()
    observation_id = _semantic_observation_id(
        plan=plan,
        policy_sha256=policy_sha256,
        evidence_sha256=wire["evidence_sha256"],
        release_sha256=state["release"]["manifest_sha256"],
    )
    envelope_id = str(
        uuid.uuid5(
            PORTCAST_REPLAY_NAMESPACE,
            f"envelope|{source_id}|{review_id}|{observation_id}",
        )
    )
    reserved = {
        "tcp_connects": profile.budget.tcp_connects,
        "udp_datagrams": profile.budget.udp_datagrams,
        "tls_handshakes": profile.budget.tls_handshakes,
        "protocol_requests": profile.budget.protocol_requests,
        "tx_bytes": profile.budget.tx_bytes,
        "rx_bytes": profile.budget.rx_bytes,
        "capture_bytes": profile.budget.capture_bytes,
        "authentication_attempts": profile.budget.auth_attempts,
    }
    consumed = {
        **wire["counters"],
        "authentication_attempts": 0,
    }
    unsigned = {
        "schema_version": 1,
        "kind": "harness_observation_v1",
        "envelope_id": envelope_id,
        "engagement_id": engagement_id,
        "producer": {
            "source_id": source_id,
            "role": "reviewed_broker",
            "key_id": key_id,
        },
        "issued_at": issued_at,
        "review": {
            "status": "reviewed",
            "review_id": review_id,
            "reviewed_at": reviewed_at,
        },
        "profile": {"name": plan["profile_id"], "version": 1},
        "execution": {
            "source_engagement_id": plan["engagement_id"],
            "policy": {"id": plan["policy_revision"], "sha256": policy_sha256},
            "release": {
                "id": plan["release_id"],
                "sha256": state["release"]["manifest_sha256"],
            },
            "frozen_plan": {"id": plan["plan_id"], "sha256": plan["plan_sha256"]},
            "target_profile": {
                "id": plan["profile_id"],
                "version": 1,
                "target_id": plan["target_id"],
                "catalog_sha256": plan["catalog_sha256"],
                "profile_sha256": plan["profile_sha256"],
                "operation_sha256": plan["operation_sha256"],
                "runtime_pinset_sha256": plan["runtime_pinset_sha256"],
            },
            "action_id": plan["action_id"],
            "module": {
                "id": plan["module_id"],
                "version": "1.0.0",
                "sha256": plan["module_source_sha256"],
            },
            "collector": {
                "id": "portcast-http-identity-v1",
                "version": 1,
                "worker_sha256": plan["worker_sha256"],
            },
            "parser": {
                "id": profile.parser_id,
                "version": 1,
                "sha256": plan["parser_sha256"],
            },
            "reservation": {
                "id": plan["action_id"],
                "reserved": reserved,
                "consumed": consumed,
            },
        },
        "observation": {
            "observation_id": observation_id,
            "observed_at": observed_at,
            "outcome": "observed",
            "asset": {
                "asset_key": "service:10.0.1.30:8096/jellyfin",
                "label": "Jellyfin Server 10.10.7",
                "kind": "service",
                "track": "web",
                "identifiers": [{"type": "ipv4", "value": "10.0.1.30"}],
                "context": {
                    "target_id": plan["target_id"],
                    "endpoint": "http://10.0.1.30:8096/System/Info/Public",
                },
            },
            "detector": {
                "name": "portcast_public_identity",
                "version": 1,
                "deterministic": True,
            },
            "result": {
                "check_id": "portcast_public_identity",
                "state": "candidate",
                "component_id": "service:10.0.1.30:8096/jellyfin",
                "ecosystem": "semver",
                "product": "Jellyfin Server",
                "version": "10.10.7",
                "provenance": "banner",
                "protocol": "http",
                "port": 8096,
                "vulnerability_assessment": "not_performed",
            },
            "evidence_refs": [
                {
                    "evidence_id": wire["encrypted_artifact_id"],
                    "sha256": wire["evidence_sha256"],
                    "size": wire["evidence_bytes"],
                    "media_type": "application/http",
                    "classification": "client_confidential_human_only",
                    "availability": "source_harness_encrypted_only",
                }
            ],
        },
    }
    signature = signer(canonical_json(unsigned))
    if type(signature) is not bytes or len(signature) != 64:
        raise PolicyError("operator signing reference returned an invalid signature")
    return {
        **unsigned,
        "signature": {
            "algorithm": "Ed25519",
            "encoding": "base64",
            "key_id": key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def build_portcast_source_card(
    *,
    envelope: Mapping[str, Any],
    public_key: str,
    name: str,
) -> dict[str, Any]:
    """Build the enrollment card that pins every PortCast release identity."""

    try:
        raw_key = base64.b64decode(public_key, validate=True)
        execution = envelope["execution"]
        producer = envelope["producer"]
        profile_id = envelope["profile"]["name"]
    except Exception:
        raise PolicyError("PortCast source card inputs are invalid") from None
    if len(raw_key) != 32 or type(name) is not str or not 1 <= len(name) <= 200:
        raise PolicyError("PortCast source card inputs are invalid")
    pins = {
        "source_engagement_id": execution["source_engagement_id"],
        "policy_sha256": execution["policy"]["sha256"],
        "release_sha256": execution["release"]["sha256"],
        "module_sha256": execution["module"]["sha256"],
        "parser_sha256": execution["parser"]["sha256"],
        "catalog_sha256": execution["target_profile"]["catalog_sha256"],
        "profile_sha256": execution["target_profile"]["profile_sha256"],
        "operation_sha256": execution["target_profile"]["operation_sha256"],
        "worker_sha256": execution["collector"]["worker_sha256"],
        "runtime_pinset_sha256": execution["target_profile"]["runtime_pinset_sha256"],
    }
    return {
        "schema_version": 1,
        "kind": "harness_source",
        "source_id": producer["source_id"],
        "name": name,
        "engagement_id": envelope["engagement_id"],
        "role": "reviewed_broker",
        "key_id": producer["key_id"],
        "algorithm": "Ed25519",
        "public_key": public_key,
        "profiles": [profile_id],
        "profile_pins": {profile_id: pins},
    }


__all__ = (
    "PORTCAST_HARBINGER_PROFILE",
    "PORTCAST_REPLAY_NAMESPACE",
    "build_portcast_harbinger_envelope",
    "build_portcast_source_card",
)
