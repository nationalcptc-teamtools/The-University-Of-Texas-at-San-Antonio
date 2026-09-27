"""Frozen metadata contracts for the independent read-only wave."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Literal, TypeAlias


Outcome: TypeAlias = Literal["complete", "cancelled", "uncertain", "failed"]
Limitation: TypeAlias = Literal[
    "none", "cancelled-before-contact", "deadline", "transport-uncertain",
    "malformed-response", "protocol-rejected",
]
RedisState: TypeAlias = Literal[
    "pong", "authentication_required", "unexpected", "incomplete"
]
HealthState: TypeAlias = Literal["available", "unavailable", "other", "malformed"]
IssuerScheme: TypeAlias = Literal["http", "https", "other", "missing"]
GrantType: TypeAlias = Literal[
    "authorization_code", "implicit", "refresh_token", "password",
    "client_credentials", "urn:ietf:params:oauth:grant-type:device_code",
    "urn:openid:params:grant-type:ciba",
]
SigningAlgorithm: TypeAlias = Literal[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
    "ES384", "ES512", "EdDSA",
]
ParserID: TypeAlias = Literal["traefik", "redis", "keycloak", "meilisearch"]
GRANT_TYPE_ORDER: tuple[GrantType, ...] = (
    "authorization_code", "implicit", "refresh_token", "password",
    "client_credentials", "urn:ietf:params:oauth:grant-type:device_code",
    "urn:openid:params:grant-type:ciba",
)
SIGNING_ALGORITHM_ORDER: tuple[SigningAlgorithm, ...] = (
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
    "ES384", "ES512", "EdDSA",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NORMALIZED_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_MAX_SEMVER_LENGTH = 128
_CATALOG_SEAL = object()
_RESULT_SEAL = object()


def _integer(name: str, value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise TypeError(f"{name} must be an integer of at least {minimum}")
    return value


def _text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise TypeError(f"{name} must be nonempty text")
    return value


def _digest(name: str, value: object) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise TypeError(f"{name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class HttpGetOperation:
    request: bytes
    request_sha256: str

    def __post_init__(self) -> None:
        if type(self.request) is not bytes or not self.request:
            raise TypeError("request must be nonempty bytes")
        _digest("request_sha256", self.request_sha256)
        if hashlib.sha256(self.request).hexdigest() != self.request_sha256:
            raise ValueError("request_sha256 does not match request")


@dataclass(frozen=True, slots=True)
class RedisPingOperation:
    request: bytes
    request_sha256: str

    def __post_init__(self) -> None:
        if type(self.request) is not bytes or not self.request:
            raise TypeError("request must be nonempty bytes")
        _digest("request_sha256", self.request_sha256)
        if hashlib.sha256(self.request).hexdigest() != self.request_sha256:
            raise ValueError("request_sha256 does not match request")


@dataclass(frozen=True, slots=True)
class WireBudget:
    max_connects: int
    max_requests: int
    max_tx_bytes: int
    max_rx_bytes: int
    max_capture_bytes: int
    timeout_ms: int

    def __post_init__(self) -> None:
        _integer("max_connects", self.max_connects, minimum=1)
        _integer("max_requests", self.max_requests, minimum=1)
        _integer("max_tx_bytes", self.max_tx_bytes, minimum=1)
        _integer("max_rx_bytes", self.max_rx_bytes, minimum=1)
        _integer("max_capture_bytes", self.max_capture_bytes, minimum=1)
        _integer("timeout_ms", self.timeout_ms, minimum=1)
        if self.max_capture_bytes > self.max_rx_bytes:
            raise ValueError("capture budget cannot exceed receive budget")


@dataclass(frozen=True, slots=True)
class WireCounters:
    connects: int
    requests: int
    tx_bytes: int
    rx_bytes: int
    captured_bytes: int

    def __post_init__(self) -> None:
        for name in ("connects", "requests", "tx_bytes", "rx_bytes", "captured_bytes"):
            _integer(name, getattr(self, name))

    def validate(self, budget: WireBudget) -> WireCounters:
        if not isinstance(budget, WireBudget):
            raise TypeError("budget must be WireBudget")
        if (
            self.connects > budget.max_connects
            or self.requests > budget.max_requests
            or self.tx_bytes > budget.max_tx_bytes
            or self.rx_bytes > budget.max_rx_bytes
            or self.captured_bytes > budget.max_capture_bytes
            or self.captured_bytes > self.rx_bytes
        ):
            raise ValueError("wire counters exceed the fixed budget")
        return self


@dataclass(frozen=True, slots=True)
class ReadOnlyAction:
    plan_id: str
    action_id: str
    profile_id: str
    target_id: str
    order: int
    host: str
    port: int
    operation: HttpGetOperation | RedisPingOperation
    budget: WireBudget
    parser_id: ParserID
    profile_sha256: str
    catalog_sha256: str
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _CATALOG_SEAL:
            raise ValueError("read-only actions must come from the sealed catalog")
        for name in ("plan_id", "action_id", "profile_id", "target_id", "host"):
            _text(name, getattr(self, name))
        _integer("order", self.order, minimum=1)
        _integer("port", self.port, minimum=1)
        if self.port > 65535:
            raise ValueError("port is invalid")
        if not isinstance(self.operation, (HttpGetOperation, RedisPingOperation)):
            raise TypeError("operation type is invalid")
        if not isinstance(self.budget, WireBudget):
            raise TypeError("budget type is invalid")
        if self.parser_id not in {"traefik", "redis", "keycloak", "meilisearch"}:
            raise ValueError("parser identifier is invalid")
        _digest("profile_sha256", self.profile_sha256)
        _digest("catalog_sha256", self.catalog_sha256)


def _sealed_action(**values: object) -> ReadOnlyAction:
    return ReadOnlyAction(**values, _seal=_CATALOG_SEAL)


@dataclass(frozen=True, slots=True)
class TraefikFacts:
    status_code: int
    version: str | None
    product_marker: bool

    def __post_init__(self) -> None:
        _status(self.status_code)
        if type(self.product_marker) is not bool:
            raise TypeError("product_marker must be bool")
        valid_version = (
            isinstance(self.version, str)
            and len(self.version) <= _MAX_SEMVER_LENGTH
            and _NORMALIZED_SEMVER.fullmatch(self.version) is not None
        )
        if self.product_marker:
            if not valid_version:
                raise ValueError("version must be normalized bounded SemVer")
        elif self.version is not None:
            raise ValueError("version requires a product marker")


@dataclass(frozen=True, slots=True)
class RedisFacts:
    state: RedisState

    def __post_init__(self) -> None:
        if self.state not in {"pong", "authentication_required", "unexpected", "incomplete"}:
            raise ValueError("Redis state is invalid")


@dataclass(frozen=True, slots=True)
class KeycloakFacts:
    status_code: int
    realm_path_match: bool
    issuer_scheme: IssuerScheme
    grant_types_present: bool
    grant_types: tuple[GrantType, ...]
    unknown_grant_type: bool
    signing_algorithms_present: bool
    signing_algorithms: tuple[SigningAlgorithm, ...]
    unknown_signing_algorithm: bool

    def __post_init__(self) -> None:
        _status(self.status_code)
        for name in (
            "realm_path_match", "grant_types_present", "unknown_grant_type",
            "signing_algorithms_present", "unknown_signing_algorithm",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be bool")
        if self.issuer_scheme not in {"http", "https", "other", "missing"}:
            raise ValueError("issuer scheme is invalid")
        if type(self.grant_types) is not tuple or type(self.signing_algorithms) is not tuple:
            raise TypeError("known values must be tuples")
        if (
            (not self.grant_types_present and (self.grant_types or self.unknown_grant_type))
            or (
                not self.signing_algorithms_present
                and (self.signing_algorithms or self.unknown_signing_algorithm)
            )
            or (self.issuer_scheme == "missing" and self.realm_path_match)
        ):
            raise ValueError("Keycloak facts are not coherent")
        grant_set = set(self.grant_types)
        signing_set = set(self.signing_algorithms)
        if (
            len(grant_set) != len(self.grant_types)
            or any(item not in GRANT_TYPE_ORDER for item in self.grant_types)
            or self.grant_types != tuple(item for item in GRANT_TYPE_ORDER if item in grant_set)
        ):
            raise ValueError("grant types must be unique known values in catalog order")
        if (
            len(signing_set) != len(self.signing_algorithms)
            or any(item not in SIGNING_ALGORITHM_ORDER for item in self.signing_algorithms)
            or self.signing_algorithms
            != tuple(item for item in SIGNING_ALGORITHM_ORDER if item in signing_set)
        ):
            raise ValueError("signing algorithms must be unique known values in catalog order")


@dataclass(frozen=True, slots=True)
class MeilisearchFacts:
    status_code: int
    state: HealthState

    def __post_init__(self) -> None:
        _status(self.status_code)
        if self.state not in {"available", "unavailable", "other", "malformed"}:
            raise ValueError("health state is invalid")


Facts: TypeAlias = TraefikFacts | RedisFacts | KeycloakFacts | MeilisearchFacts


def _status(value: object) -> int:
    result = _integer("status_code", value, minimum=100)
    if result > 599:
        raise ValueError("status code is invalid")
    return result


@dataclass(frozen=True, slots=True)
class ActionResult:
    plan_id: str
    action_id: str
    profile_id: str
    target_id: str
    outcome: Outcome
    limitation: Limitation
    counters: WireCounters
    evidence_sha256: str
    facts: Facts | None
    _action: InitVar[ReadOnlyAction | None] = None
    _seal: InitVar[object] = None

    def __post_init__(self, _action: ReadOnlyAction | None, _seal: object) -> None:
        if _seal is not _RESULT_SEAL or not isinstance(_action, ReadOnlyAction):
            raise ValueError("action results require a sealed action")
        for name in ("plan_id", "action_id", "profile_id", "target_id"):
            _text(name, getattr(self, name))
        if (
            self.plan_id, self.action_id, self.profile_id, self.target_id
        ) != (
            _action.plan_id, _action.action_id, _action.profile_id, _action.target_id
        ):
            raise ValueError("action result identity differs from sealed action")
        if self.outcome not in {"complete", "cancelled", "uncertain", "failed"}:
            raise ValueError("outcome is invalid")
        if self.limitation not in {
            "none", "cancelled-before-contact", "deadline", "transport-uncertain",
            "malformed-response", "protocol-rejected",
        }:
            raise ValueError("limitation is invalid")
        if not isinstance(self.counters, WireCounters):
            raise TypeError("counters are invalid")
        self.counters.validate(_action.budget)
        _digest("evidence_sha256", self.evidence_sha256)
        if self.facts is not None and not isinstance(
            self.facts, (TraefikFacts, RedisFacts, KeycloakFacts, MeilisearchFacts)
        ):
            raise TypeError("facts are invalid")
        expected_fact = {
            "traefik": TraefikFacts,
            "redis": RedisFacts,
            "keycloak": KeycloakFacts,
            "meilisearch": MeilisearchFacts,
        }[_action.parser_id]
        if self.facts is not None and type(self.facts) is not expected_fact:
            raise TypeError("facts do not match the action parser")
        limitation_by_outcome = {
            "complete": {"none"},
            "cancelled": {"cancelled-before-contact"},
            "uncertain": {"deadline", "transport-uncertain"},
            "failed": {"malformed-response", "protocol-rejected"},
        }
        coherent = self.limitation in limitation_by_outcome[self.outcome]
        if self.outcome == "complete":
            coherent = coherent and self.facts is not None and (
                self.counters.connects == 1
                and self.counters.requests == 1
                and self.counters.tx_bytes == len(_action.operation.request)
                and self.counters.captured_bytes > 0
            )
            coherent = coherent and not (
                isinstance(self.facts, RedisFacts) and self.facts.state == "incomplete"
            )
        else:
            coherent = coherent and self.facts is None
        if self.outcome == "cancelled":
            coherent = coherent and self.counters == WireCounters(0, 0, 0, 0, 0)
        elif self.outcome == "uncertain":
            coherent = coherent and (
                self.counters.connects == 1
                and self.counters.requests == 1
                and (
                    self.counters.tx_bytes == len(_action.operation.request)
                    or self.counters.rx_bytes == self.counters.captured_bytes == 0
                )
            )
        elif self.outcome == "failed":
            coherent = coherent and (
                self.counters.connects == 1
                and self.counters.requests == 1
                and self.counters.tx_bytes == len(_action.operation.request)
            )
        if not coherent:
            raise ValueError("action result outcome is not coherent with its metadata")

    @classmethod
    def for_action(
        cls,
        action: ReadOnlyAction,
        outcome: Outcome,
        limitation: Limitation,
        counters: WireCounters,
        evidence_sha256: str,
        facts: Facts | None,
    ) -> ActionResult:
        if not isinstance(action, ReadOnlyAction):
            raise TypeError("action must be a validated read-only action")
        return cls(
            action.plan_id, action.action_id, action.profile_id, action.target_id,
            outcome, limitation, counters, evidence_sha256, facts,
            _action=action, _seal=_RESULT_SEAL,
        )


def _approval_projection(engagement_id: str, device_id: str, workspace_id: str,
                         plan_id: str, catalog_sha256: str, policy_sha256: str,
                         release_sha256: str, actions: tuple[ReadOnlyAction, ...],
                         approval_id: str, operator: str, approved_at: str) -> dict[str, object]:
    return {
        "schema_version": 2, "engagement_id": engagement_id, "device_id": device_id,
        "workspace_id": workspace_id, "plan_id": plan_id, "catalog_sha256": catalog_sha256,
        "policy_sha256": policy_sha256, "release_sha256": release_sha256,
        "actions": [{"order": item.order, "action_id": item.action_id, "profile_id": item.profile_id,
                      "target_id": item.target_id, "operation": item.operation.request_sha256,
                      "budget": [item.budget.max_connects, item.budget.max_requests,
                                 item.budget.max_tx_bytes, item.budget.max_rx_bytes,
                                 item.budget.max_capture_bytes, item.budget.timeout_ms]}
                     for item in actions],
        "approval_id": approval_id, "operator": operator, "approved_at": approved_at,
    }


@dataclass(frozen=True, slots=True)
class FrozenWaveApproval:
    wave_id: str
    engagement_id: str
    device_id: str
    workspace_id: str
    plan_id: str
    catalog_sha256: str
    policy_sha256: str
    release_sha256: str
    actions: tuple[ReadOnlyAction, ...]
    approval_id: str
    operator: str
    approved_at: str

    def __post_init__(self) -> None:
        for name in ("wave_id", "engagement_id", "device_id", "workspace_id", "plan_id", "approval_id", "operator", "approved_at"):
            _text(name, getattr(self, name))
        for name in ("catalog_sha256", "policy_sha256", "release_sha256"):
            _digest(name, getattr(self, name))
        if type(self.actions) is not tuple or not self.actions or any(not isinstance(item, ReadOnlyAction) for item in self.actions):
            raise TypeError("wave action manifest is invalid")
        if tuple(item.order for item in self.actions) != tuple(range(1, len(self.actions) + 1)):
            raise ValueError("wave action order is not contiguous")
        try:
            parsed = datetime.fromisoformat(self.approved_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("approval time is invalid") from exc
        if parsed.tzinfo is None or not self.approved_at.endswith("Z"):
            raise ValueError("approval time must be UTC")
        projection = _approval_projection(self.engagement_id, self.device_id, self.workspace_id, self.plan_id,
                                          self.catalog_sha256, self.policy_sha256, self.release_sha256,
                                          self.actions, self.approval_id, self.operator, self.approved_at)
        expected = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
        if self.wave_id != expected:
            raise ValueError("wave_id does not match immutable approval")


def build_frozen_wave(*, engagement_id: str, device_id: str, workspace_id: str, plan_id: str,
                      catalog_sha256: str, policy_sha256: str, release_sha256: str,
                      actions: tuple[ReadOnlyAction, ...], approval_id: str, operator: str,
                      approved_at: str) -> FrozenWaveApproval:
    projection = _approval_projection(engagement_id, device_id, workspace_id, plan_id,
                                      catalog_sha256, policy_sha256, release_sha256, actions,
                                      approval_id, operator, approved_at)
    wave_id = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    return FrozenWaveApproval(wave_id, engagement_id, device_id, workspace_id, plan_id,
                              catalog_sha256, policy_sha256, release_sha256, actions,
                              approval_id, operator, approved_at)
