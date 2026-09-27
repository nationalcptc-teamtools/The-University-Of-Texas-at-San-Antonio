"""Versioned internal contracts. Model input is parsed elsewhere, never deserialized here."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields, is_dataclass
from typing import Any, Callable, Literal, Mapping, Protocol
import hashlib
import json
import math
import re
from weakref import ref

CONTRACT_VERSION = 1
JSONValue = Any


class HarnessError(RuntimeError):
    """A safe, stable diagnostic; do not put raw target data in its message."""


class PolicyError(HarnessError):
    pass


def to_json(value: Any) -> Any:
    if is_dataclass(value):
        return {f.name: to_json(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        if any(not isinstance(k, str) for k in value):
            raise PolicyError("JSON object keys must be strings")
        return {k: to_json(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [to_json(v) for v in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise PolicyError("value is outside the JSON contract")


def canonical_json(value: Any) -> bytes:
    return json.dumps(to_json(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def validate_schema(value: Any, schema: Mapping[str, Any]) -> None:
    """Small deny-by-default JSON-schema subset used by the static registry."""
    kind = schema.get("type")
    kinds = {"object": dict, "array": list, "string": str, "integer": int,
             "number": (int, float), "boolean": bool, "null": type(None)}
    if kind not in kinds or not isinstance(value, kinds[kind]):
        raise PolicyError("invalid argument type")
    if kind in ("integer", "number"):
        if isinstance(value, bool) or not math.isfinite(value):
            raise PolicyError("invalid numeric argument")
        if value < schema.get("minimum", -math.inf) or value > schema.get("maximum", math.inf):
            raise PolicyError("numeric argument exceeds bounds")
    if "enum" in schema and value not in schema["enum"]:
        raise PolicyError("argument is not an admitted choice")
    if kind == "object":
        props = schema.get("properties", {})
        if set(value) - set(props) or set(schema.get("required", ())) - set(value):
            raise PolicyError("unknown or missing argument")
        for key, item in value.items():
            validate_schema(item, props[key])
    if kind in ("string", "array"):
        maximum = schema.get("maxLength" if kind == "string" else "maxItems", 4096)
        if len(value) > maximum:
            raise PolicyError("argument exceeds collection allowance")
        if kind == "array":
            for item in value:
                validate_schema(item, schema.get("items", {}))


@dataclass(frozen=True)
class ScopeSpec:
    allowed_cidrs: tuple[str, ...] = ()
    excluded_cidrs: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    allow_http_login: bool = False


@dataclass(frozen=True)
class TargetRef:
    target_id: str
    canonical_url: str
    scheme: str
    host: str
    port: int
    base_path: str = "/"


@dataclass(frozen=True)
class Bounds:
    timeout_s: float = 30.0
    request_limit: int = 0
    output_bytes: int = 131072
    process_limit: int = 1
    model_calls: int = 0
    actions: int = 0
    auth_posts: int = 0
    # Append transport counters so the original positional constructor remains
    # compatible with stored integrations and third-party callers.
    tcp_connects: int = 0
    udp_datagrams: int = 0
    protocol_requests: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0


RESOURCE_COUNTERS = (
    "request_limit",
    "tcp_connects",
    "udp_datagrams",
    "protocol_requests",
    "tx_bytes",
    "rx_bytes",
    "output_bytes",
    "process_limit",
    "model_calls",
    "actions",
    "auth_posts",
)


@dataclass(frozen=True)
class BudgetLimit:
    scope: Literal["engagement", "device", "workspace", "workflow", "target", "realm"]
    key: str
    counter: str
    ceiling: int

    def __post_init__(self):
        if self.scope not in {"engagement", "device", "workspace", "workflow", "target", "realm"} or self.counter not in RESOURCE_COUNTERS:
            raise PolicyError("invalid budget scope or counter")
        if (not isinstance(self.key, str) or not 1 <= len(self.key) <= 512
                or any(ord(c) < 32 or ord(c) == 127 for c in self.key)):
            raise PolicyError("invalid budget scope key")
        if type(self.ceiling) is not int or not 0 <= self.ceiling <= 2147483647:
            raise PolicyError("invalid budget ceiling")


@dataclass(frozen=True)
class ModuleSpec:
    module_id: str
    version: str
    track: str
    mode: Literal["offline", "bounded", "manual_only"]
    effects: tuple[str, ...]
    bounds: Bounds
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    tool_id: str | None = None
    source_hash: str = ""
    description: str = ""


@dataclass(frozen=True)
class OperationRequest:
    request_id: str
    workspace_id: str
    device_id: str
    operator_id: str
    module_id: str
    target: TargetRef | None
    args: dict[str, Any]
    source: Literal["operator", "model"]
    approval_id: str | None
    policy_revision: str
    workflow_id: str = "default"
    parent_action_id: str | None = None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ProfileAction:
    """Broker-issued, process-local authority for one sealed profile action."""

    action_id: str
    wave_id: str
    workspace_id: str
    target_id: str
    profile_id: str
    runtime_pinset_sha256: str
    bounds: Bounds
    limits: tuple[tuple[str, int], ...]
    budget_limits: tuple[BudgetLimit, ...]


_PROFILE_ACTION_SEALS: dict[int, tuple[Any, str]] = {}


def _profile_action_digest(action: ProfileAction) -> str:
    return digest({
        "action_id": action.action_id,
        "wave_id": action.wave_id,
        "workspace_id": action.workspace_id,
        "target_id": action.target_id,
        "profile_id": action.profile_id,
        "runtime_pinset_sha256": action.runtime_pinset_sha256,
        "bounds": action.bounds,
        "limits": action.limits,
        "budget_limits": action.budget_limits,
    })


def _issue_profile_action(
    *,
    action_id: str,
    wave_id: str,
    workspace_id: str,
    target_id: str,
    profile_id: str,
    runtime_pinset_sha256: str,
    bounds: Bounds,
    limits: tuple[tuple[str, int], ...],
    budget_limits: tuple[BudgetLimit, ...],
) -> ProfileAction:
    """Issue an internal action only after the broker reserves encrypted output."""

    identifiers = (action_id, wave_id, workspace_id, target_id, profile_id)
    if any(
        type(value) is not str
        or not 1 <= len(value) <= 128
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        for value in identifiers
    ):
        raise PolicyError("invalid sealed profile action identity")
    if (
        type(runtime_pinset_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", runtime_pinset_sha256) is None
    ):
        raise PolicyError("invalid sealed profile runtime identity")
    if not isinstance(bounds, Bounds):
        raise PolicyError("invalid sealed profile action bounds")
    if (
        type(limits) is not tuple
        or any(
            type(item) is not tuple
            or len(item) != 2
            or item[0] not in RESOURCE_COUNTERS
            or type(item[1]) is not int
            or item[1] < 0
            for item in limits
        )
        or len({item[0] for item in limits}) != len(limits)
    ):
        raise PolicyError("invalid sealed profile action limits")
    if type(budget_limits) is not tuple or any(
        not isinstance(item, BudgetLimit) for item in budget_limits
    ):
        raise PolicyError("invalid sealed profile action budgets")
    action = ProfileAction(
        action_id,
        wave_id,
        workspace_id,
        target_id,
        profile_id,
        runtime_pinset_sha256,
        bounds,
        limits,
        budget_limits,
    )
    identity = id(action)

    def discard(reference: Any, *, identity: int = identity) -> None:
        current = _PROFILE_ACTION_SEALS.get(identity)
        if current is not None and current[0] is reference:
            _PROFILE_ACTION_SEALS.pop(identity, None)

    reference = ref(action, discard)
    _PROFILE_ACTION_SEALS[identity] = (reference, _profile_action_digest(action))
    return action


def _validate_profile_action(value: Any) -> ProfileAction:
    if not isinstance(value, ProfileAction):
        raise PolicyError("profile action is not sealed")
    try:
        seal = _PROFILE_ACTION_SEALS.get(id(value))
        valid = (
            seal is not None
            and seal[0]() is value
            and seal[1] == _profile_action_digest(value)
        )
    except (AttributeError, TypeError, ValueError):
        valid = False
    if not valid:
        raise PolicyError("profile action is not sealed")
    return value


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    target_id: str | None
    check_id: str
    classification: str
    artifact_relpath: str | None
    sha256: str
    bytes: int


@dataclass(frozen=True)
class OperationResult:
    status: Literal["complete", "blocked", "uncertain", "stopped", "failed"]
    facts: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[EvidenceRef, ...] = ()
    reason: str | None = None
    usage: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetRequest:
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    max_bytes: int = 131072
    credential_ref: str | None = None
    session_ref: str | None = None


@dataclass(frozen=True)
class TargetResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_s: float
    address: str = ""
    truncated: bool = False
    session_ref: str | None = None


class TargetTransport(Protocol):
    def request(self, request: TargetRequest) -> TargetResponse: ...


@dataclass(frozen=True)
class ToolRequest:
    tool_id: str
    arguments: dict[str, Any] = field(default_factory=dict)
    stdin: bytes = b""


@dataclass(frozen=True)
class ToolOutput:
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int | None = None
    status: str = "blocked"
    reason: str | None = None


class ToolRunner(Protocol):
    def run(self, request: ToolRequest) -> ToolOutput: ...


@dataclass(frozen=True)
class SourceRef:
    source_id: str
    sha256: str
    tool: str = "operator-import"
    version: str = "unknown"
    classification: str = "client_confidential"


@dataclass(frozen=True)
class Observation:
    track: str
    target: str
    check_id: str
    state: str
    facts: dict[str, Any]
    source: SourceRef


@dataclass(frozen=True)
class ParseIssue:
    code: str
    message: str
    record: int | None = None


@dataclass(frozen=True)
class ParseBatch:
    observations: tuple[Observation, ...] = ()
    issues: tuple[ParseIssue, ...] = ()
    duplicates: int = 0


@dataclass(frozen=True)
class Approval:
    approval_id: str
    module_id: str
    target_id: str
    policy_revision: str
    args_hash: str
    expires_at: str
    operator_id: str
    request_id: str = ""


@dataclass(frozen=True)
class TargetPolicy:
    target: TargetRef
    eligible: bool = False
    profile: str = "unknown"
    assigned_workspace: str = ""
    auth_realm: str = ""
    permitted_modules: tuple[str, ...] = ()
    request_limit: int = 24
    auth_method: str | None = None
    auth_attempts: int = 0


@dataclass(frozen=True)
class PolicySnapshot:
    engagement_id: str
    revision: str
    workspace_id: str
    device_id: str
    operator_id: str
    scope: ScopeSpec
    targets: tuple[TargetPolicy, ...] = ()
    approvals: tuple[Approval, ...] = ()
    window_start: str = ""
    window_end: str = ""
    sow_reference: str = "unverified"
    roe_reference: str = "unverified"
    exclusions: tuple[str, ...] = ("OT", "management infrastructure", "other teams", "fragile systems")
    outside_assistance: str = "Only as explicitly permitted by the current CPTC rules and ROE."
    staging_rules: str = "No publication without the approved CPTC staging process."
    reporting: str = "Preserve evidence; distinguish observed, blocked, attempted, and confirmed outcomes."
    escalation: str = "Stop and contact the registered operator on unknown impact or scope."
    encrypted_storage: bool = False
    model_calls: int = 6
    model_actions: int = 12
    format_repairs: int = 1
    excerpt_bytes: int = 2048
    decision_bytes: int = 8192
    http_rate: float = 1.0
    contract_version: int = CONTRACT_VERSION
    budget_limits: tuple[BudgetLimit, ...] = ()


@dataclass(frozen=True)
class RuleReference:
    version: str
    sha256: str
    local_path: str
    sources: tuple[str, ...]


@dataclass(frozen=True)
class Preamble:
    text: str
    sha256: str
    rule_sha256: str
    rule_version: str = ""
    policy_revision: str = ""
    allowed_module_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionContext:
    request: OperationRequest
    spec: ModuleSpec
    policy: PolicySnapshot
    transport: TargetTransport | None = None
    tools: ToolRunner | None = None
    capture: Callable[[str, bytes, str], EvidenceRef] | None = None
    stopped: Callable[[], bool] = lambda: False
    source: SourceRef | None = None
    input_bytes: bytes = b""
    # Trusted, process-local capability. Never populated from model JSON.
    network: Any | None = None
    # Broker-issued sealed profile action and dispatcher. Model JSON cannot
    # construct either capability or select a channel destination.
    profile_action: ProfileAction | None = None
    profile_dispatch: Callable[[ProfileAction, Callable[[bytes], str]], Any] | None = None


@dataclass(frozen=True)
class AuditEvent:
    kind: str
    action_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    classification: str = "metadata"


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    events: int = 0
    reason: str | None = None


@dataclass(frozen=True)
class AuditSeal:
    sha256: str
    events: int
    manifest_path: str


@dataclass(frozen=True)
class ClockState:
    synchronized: bool
    offset_s: float | None
    source: str = "unknown"


@dataclass(frozen=True)
class Reservation:
    request_id: str
    bounds: Bounds
    remaining: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class MergeBundle:
    engagement_id: str
    device_id: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class MergeReport:
    accepted: bool
    reason: str | None = None
    imported: int = 0


@dataclass(frozen=True)
class NetworkGrant:
    purpose: str
    addresses: tuple[str, ...]
    port: int
    connected_fd: int | None = None
    grant_id: str = ""
    expires_at: str = ""


@dataclass(frozen=True)
class WorkerSpec:
    executable: str
    args: tuple[str, ...] = ()
    bounds: Bounds = field(default_factory=Bounds)
    source_hash: str = ""


@dataclass(frozen=True)
class WorkerCapture:
    status: str
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int | None = None
    reason: str | None = None
    truncated: bool = False
    elapsed_s: float = 0.0
