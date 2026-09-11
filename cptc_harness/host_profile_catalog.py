"""Offline-only host profile contracts.

This module validates one typed Windows Defender observation profile. It does
not contain a command, socket, credential, or execution interface. The profile
stays blocked until a credential-bound, parent-owned WinRM HTTPS transport and
an exact server certificate pin are independently admitted.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from .contracts import PolicyError, canonical_json
from .scanner_contracts import TrafficBudget


HOST_PROFILE_ID = "windows_ad.defender_protection"
EXPECTED_HOST_CATALOG_SHA256 = "d685575332bb75a66a3b62accbaffb1843e07fbfd1ea19ad8153aa69f2dacc37"
_CATALOG_PATH = Path(__file__).parent / "resources" / "host-profiles-v1.json"
_RESULT_FIELDS = (
    "realtime_protection_enabled",
    "on_access_protection_enabled",
    "ioav_protection_enabled",
    "behavior_monitoring_enabled",
)
_BUDGET_FIELDS = (
    "tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes",
    "timeout_s", "cpu_s", "output_bytes", "process_limit", "auth_attempts",
)
_EXPECTED_BUDGET = (1, 0, 1, 32768, 65536, 30.0, 10.0, 16384, 1, 1)
_EXPECTED_CONTRACTS = (
    (
        "microsoft.defender.preference-fields.v1",
        "9ccafb2e6ee89af2632f184d06ffe831d8314bee546d42f6fc9a6b5b9a760e0b",
    ),
    (
        "blocked.parent-owned-winrm-https.v1",
        "60862bea8e09410b6bd0a0ef5935bddc3e938b0abf549604f4ab64a2ef271256",
    ),
    (
        "typed.defender.protection-fields.v1",
        "477dec8abbc3fd6beaca1c953f096e640b2e6b52d13df9aaa7d4d6f4f32bacae",
    ),
)
_PROFILE_FIELDS = {
    "profile_id", "platform", "kind", "mode", "required_role", "source_contract",
    "runner_contract", "query_contract", "result_contract", "budget", "runtime_options",
    "effects", "blocked_reason",
}


@dataclass(frozen=True, slots=True)
class ContractPin:
    """An opaque non-executable contract identity and its exact digest."""

    contract_id: str
    sha256: str


@dataclass(frozen=True, slots=True)
class HostProfile:
    """The exact offline-only Defender observation profile."""

    profile_id: str
    platform: str
    kind: str
    mode: str
    required_role: str
    source_contract: ContractPin
    runner_contract: ContractPin
    query_contract: ContractPin
    result_contract: tuple[tuple[str, str], ...]
    budget: TrafficBudget
    runtime_options: tuple[str, ...]
    effects: tuple[str, ...]
    blocked_reason: str

    @property
    def result_fields(self) -> tuple[str, ...]:
        return tuple(field for field, _field_type in self.result_contract)


@dataclass(frozen=True, slots=True)
class HostProfileCatalog:
    """Hash-anchored catalog envelope."""

    version: int
    catalog_sha256: str
    profiles: tuple[HostProfile, ...]
    path: Path


@dataclass(frozen=True, slots=True)
class HostProfileResult:
    """Complete four-field Defender protection state."""

    realtime_protection_enabled: bool
    on_access_protection_enabled: bool
    ioav_protection_enabled: bool
    behavior_monitoring_enabled: bool

    def as_dict(self) -> dict[str, bool]:
        return {field: getattr(self, field) for field in _RESULT_FIELDS}


def _contract_pin(value: Any, expected: tuple[str, str]) -> ContractPin:
    if not isinstance(value, dict) or set(value) != {"contract_id", "sha256"}:
        raise PolicyError("host profile contract pin differs")
    contract_id = value["contract_id"]
    sha256 = value["sha256"]
    if (type(contract_id) is not str or not contract_id.isascii()
            or type(sha256) is not str
            or hashlib.sha256(contract_id.encode("ascii")).hexdigest() != sha256
            or (contract_id, sha256) != expected):
        raise PolicyError("host profile contract pin differs")
    return ContractPin(contract_id, sha256)


def _profile_from_dict(value: Any) -> HostProfile:
    if not isinstance(value, dict) or set(value) != _PROFILE_FIELDS:
        raise PolicyError("unknown or missing host profile field")
    budget = value["budget"]
    if (not isinstance(budget, dict) or set(budget) != set(_BUDGET_FIELDS)
            or tuple(budget[field] for field in _BUDGET_FIELDS) != _EXPECTED_BUDGET):
        raise PolicyError("host profile budget differs")
    result_contract = value["result_contract"]
    if (not isinstance(result_contract, dict)
            or set(result_contract) != set(_RESULT_FIELDS)
            or any(result_contract[field] != "boolean" for field in _RESULT_FIELDS)):
        raise PolicyError("host profile result contract differs")
    if not isinstance(value["runtime_options"], list) or value["runtime_options"]:
        raise PolicyError("host profile does not accept runtime options")
    if value["effects"] != ["credentialed_read_only_observation"]:
        raise PolicyError("host profile effects differ")
    exact = (
        value["profile_id"], value["platform"], value["kind"], value["mode"],
        value["required_role"], value["blocked_reason"],
    )
    if exact != (
        HOST_PROFILE_ID, "windows_ad", "host_observation", "blocked", "admin",
        "Credential-bound parent-owned WinRM HTTPS transport and certificate pin are required.",
    ):
        raise PolicyError("host profile differs from the reviewed profile")
    try:
        parsed_budget = TrafficBudget.from_dict(budget)
    except (TypeError, ValueError):
        raise PolicyError("host profile budget differs") from None
    return HostProfile(
        value["profile_id"], value["platform"], value["kind"], value["mode"],
        value["required_role"],
        _contract_pin(value["source_contract"], _EXPECTED_CONTRACTS[0]),
        _contract_pin(value["runner_contract"], _EXPECTED_CONTRACTS[1]),
        _contract_pin(value["query_contract"], _EXPECTED_CONTRACTS[2]),
        tuple((field, "boolean") for field in _RESULT_FIELDS),
        parsed_budget, (), tuple(value["effects"]), value["blocked_reason"],
    )


def load_host_profile_catalog(path: Path | None = None) -> HostProfileCatalog:
    """Load and fully verify the single-profile offline catalog."""

    resolved = _CATALOG_PATH if path is None else Path(path)
    try:
        value = json.loads(resolved.read_bytes())
    except (OSError, TypeError, ValueError):
        raise PolicyError("host profile catalog is unavailable") from None
    if not isinstance(value, dict) or set(value) != {"version", "catalog_sha256", "profiles"}:
        raise PolicyError("unknown or missing host profile catalog field")
    if type(value["version"]) is not int or value["version"] != 1:
        raise PolicyError("host profile catalog version differs")
    if not isinstance(value["profiles"], list) or len(value["profiles"]) != 1:
        raise PolicyError("host profile catalog is not the reviewed finite set")
    actual_hash = hashlib.sha256(canonical_json({
        "version": value["version"],
        "profiles": value["profiles"],
    })).hexdigest()
    if value["catalog_sha256"] != actual_hash:
        raise PolicyError("host profile catalog hash differs")
    if actual_hash != EXPECTED_HOST_CATALOG_SHA256:
        raise PolicyError("host profile catalog anchor differs")
    profiles = tuple(_profile_from_dict(profile) for profile in value["profiles"])
    return HostProfileCatalog(1, actual_hash, profiles, resolved)


def get_host_profile(profile_id: str, path: Path | None = None) -> HostProfile:
    """Return the exact profile. Aliases, wildcards, and paths are rejected."""

    if type(profile_id) is not str or profile_id != HOST_PROFILE_ID:
        raise PolicyError("unknown host profile")
    return load_host_profile_catalog(path).profiles[0]


def validate_host_profile_result(
    value: Any,
    profile: HostProfile | None = None,
) -> HostProfileResult:
    """Validate a complete typed synthetic or independently collected result."""

    exact_profile = get_host_profile(HOST_PROFILE_ID)
    selected = exact_profile if profile is None else profile
    if not isinstance(selected, HostProfile) or selected != exact_profile:
        raise PolicyError("host profile differs from the reviewed profile")
    if not isinstance(value, dict) or set(value) != set(selected.result_fields):
        raise PolicyError("host profile result shape differs")
    if any(type(value[field]) is not bool for field in selected.result_fields):
        raise PolicyError("host profile result value differs")
    return HostProfileResult(*(value[field] for field in selected.result_fields))


__all__ = [
    "EXPECTED_HOST_CATALOG_SHA256",
    "HOST_PROFILE_ID",
    "ContractPin",
    "HostProfile",
    "HostProfileCatalog",
    "HostProfileResult",
    "get_host_profile",
    "load_host_profile_catalog",
    "validate_host_profile_result",
]
