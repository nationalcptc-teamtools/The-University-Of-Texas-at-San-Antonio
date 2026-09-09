"""Closed scanner profile catalog; it plans synthetic work but never runs it."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from .scanner_contracts import (
    ScanPlan,
    ScannerContractError,
    ScannerGrant,
    ScannerObservation,
    ScannerProfile,
    contract_hash,
    validate_grant,
)


PROFILE_IDS = (
    "network.nse_smb2_security_mode",
    "network.nse_smb2_time",
    "network.msf_http_version",
)
EXPECTED_CATALOG_SHA256 = "fba8ffdf4b7c480ca5421fca55327a9843bba8761bdb269c797a471ec7c2f8d6"
_ROOT = Path(__file__).parent
_PROFILE_PATH = _ROOT / "resources" / "scanner-profiles-v1.json"
_UPSTREAM = {
    "network.nse_smb2_security_mode": ("nse", "smb2-security-mode.nse"),
    "network.nse_smb2_time": ("nse", "smb2-time.nse"),
    "network.msf_http_version": ("msf", "auxiliary/scanner/http/http_version"),
}
_RUNNERS = {
    "network.nse_smb2_security_mode": "design.nmap.nse-smb2-security-mode-v1",
    "network.nse_smb2_time": "design.nmap.nse-smb2-time-v1",
    "network.msf_http_version": "design.msf.http-version-v1",
}
_EXPECTED_BUDGETS = {
    "network.nse_smb2_security_mode": (2, 1, 2, 4096, 16384, 15.0, 10.0, 16384, 1, 0),
    "network.nse_smb2_time": (2, 1, 2, 4096, 16384, 15.0, 10.0, 16384, 1, 0),
    "network.msf_http_version": (1, 0, 1, 4096, 16384, 10.0, 10.0, 16384, 1, 0),
}
_EXPECTED_PINS = {
    "network.nse_smb2_security_mode": ("https://github.com/nmap/nmap", "scripts/smb2-security-mode.nse", "package:nmap-7.991-1.1", "184a49f77869088d10309ae5b4c37ffa7065b984436aae2aba77ba86d4d801ae", "LicenseRef-Nmap-Public-Source-License-Version-0.95", False),
    "network.nse_smb2_time": ("https://github.com/nmap/nmap", "scripts/smb2-time.nse", "package:nmap-7.991-1.1", "10811428d078bb00427171bc7da327ff5b17a3f02db3517715cea8c853f026c4", "LicenseRef-Nmap-Public-Source-License-Version-0.95", False),
    "network.msf_http_version": ("https://github.com/rapid7/metasploit-framework", "modules/auxiliary/scanner/http/http_version.rb", "package:metasploit-6.5.0-1.1", "6e926772126818f13ff6dd1e687097d01200192731126aa267ec0d9d20da1e4f", "BSD-3-Clause", False),
}


def catalog_path() -> Path:
    return _PROFILE_PATH


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError, TypeError):
        raise ScannerContractError("scanner profile catalog is unavailable") from None
    if not isinstance(value, dict) or set(value) != {"version", "catalog_sha256", "profiles"}:
        raise ScannerContractError("unknown or missing catalog fields")
    if value["version"] != 1 or not isinstance(value["catalog_sha256"], str) or not isinstance(value["profiles"], list):
        raise ScannerContractError("invalid scanner catalog envelope")
    unsigned = {key: item for key, item in value.items() if key != "catalog_sha256"}
    if value["catalog_sha256"] != contract_hash(unsigned):
        raise ScannerContractError("scanner catalog hash drift")
    if value["catalog_sha256"] != EXPECTED_CATALOG_SHA256:
        raise ScannerContractError("scanner catalog anchor mismatch")
    return value


def load_catalog(path: str | Path = _PROFILE_PATH) -> tuple[ScannerProfile, ...]:
    value = _read(Path(path))
    profiles = tuple(ScannerProfile.from_dict(item) for item in value["profiles"])
    if tuple(item.profile_id for item in profiles) != PROFILE_IDS:
        raise ScannerContractError("scanner catalog is not the finite reviewed set")
    for profile in profiles:
        family, upstream_id = _UPSTREAM[profile.profile_id]
        if (profile.family, profile.upstream_id) != (family, upstream_id):
            raise ScannerContractError("scanner profile upstream identity drift")
        if profile.runner_id != _RUNNERS[profile.profile_id]:
            raise ScannerContractError("scanner profile runner identity drift")
        if profile.family == "nse" and profile.mode != "synthetic_only":
            raise ScannerContractError("NSE profile must remain synthetic-only")
        if profile.family == "msf" and profile.mode != "design_only":
            raise ScannerContractError("Metasploit profile requires a pinned framework closure")
        budget = profile.budget
        if tuple(getattr(budget, field) for field in (
            "tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes",
            "timeout_s", "cpu_s", "output_bytes", "process_limit", "auth_attempts",
        )) != _EXPECTED_BUDGETS[profile.profile_id]:
            raise ScannerContractError("scanner profile budget drift")
        pin = profile.source
        if (pin.repository, pin.path, pin.revision, pin.sha256, pin.license, pin.redistributable) != _EXPECTED_PINS[profile.profile_id]:
            raise ScannerContractError("scanner profile source pin drift")
    return profiles


def profile_for(profile_id: str) -> ScannerProfile:
    if not isinstance(profile_id, str) or profile_id not in PROFILE_IDS:
        raise ScannerContractError("unknown, wildcard, path, or runtime scanner profile")
    return next(profile for profile in load_catalog() if profile.profile_id == profile_id)


def plan_for(profile_id: str, observation: ScannerObservation, *, grant: ScannerGrant | None = None,
             arguments: dict[str, Any] | None = None) -> ScanPlan:
    profile = profile_for(profile_id)
    if not isinstance(observation, ScannerObservation):
        raise ScannerContractError("scanner planning requires one typed observation")
    if arguments not in (None, {}):
        raise ScannerContractError("runtime arguments are not accepted")
    if grant is None:
        raise ScannerContractError("planning requires one reviewed network grant")
    # Direct dataclass construction must pass the same canonical parser as JSON.
    validate_grant(grant, profile, observation)
    if profile.family == "nse" and (observation.port != 445 or observation.service not in {"microsoft-ds", "smb"}):
        raise ScannerContractError("NSE profile requires an SMB observation on TCP/445")
    if profile.family == "msf" and (observation.port != 80 or observation.service not in {"http", "www"} or observation.scheme != "http"):
        raise ScannerContractError("Metasploit HTTP profile requires an HTTP/80 observation")
    reason = f"fixed {profile.family} observation profile; no runtime execution or options"
    if profile.family == "nse" and ":" in observation.address:
        raise ScannerContractError("initial NSE profiles require an IPv4 target")
    plan = ScanPlan(
        EXPECTED_CATALOG_SHA256, contract_hash(profile), profile.profile_id,
        profile.family, profile.upstream_id, profile.runner_id,
        observation.target_id, observation.address, observation.port, profile.protocol,
        grant.endpoints, profile.mode, profile.tier, profile.budget, profile.source,
        profile.allowed_options, profile.effects, True, reason,
    )
    return validate_plan(plan)


def validate_plan(plan: ScanPlan) -> ScanPlan:
    """Revalidate every frozen profile semantic without accepting runtime options."""
    if not isinstance(plan, ScanPlan):
        raise ScannerContractError("frozen plan has the wrong type")
    profile = profile_for(plan.profile_id)
    expected_reason = f"fixed {profile.family} observation profile; no runtime execution or options"
    bound = (
        plan.catalog_sha256,
        plan.profile_sha256,
        plan.family,
        plan.upstream_id,
        plan.runner_id,
        plan.port,
        plan.protocol,
        plan.mode,
        plan.tier,
        plan.budget,
        plan.source,
        plan.allowed_options,
        plan.effects,
        plan.approval_required,
        plan.reason,
    )
    expected = (
        EXPECTED_CATALOG_SHA256,
        contract_hash(profile),
        profile.family,
        profile.upstream_id,
        profile.runner_id,
        profile.port,
        profile.protocol,
        profile.mode,
        profile.tier,
        profile.budget,
        profile.source,
        profile.allowed_options,
        profile.effects,
        True,
        expected_reason,
    )
    if bound != expected:
        raise ScannerContractError("frozen plan semantics do not match the reviewed catalog")
    try:
        target_id = ScannerObservation.from_dict({
            "target_id": plan.target_id,
            "address": plan.address,
            "port": plan.port,
            "service": "smb" if profile.family == "nse" else "http",
            "scheme": None if profile.family == "nse" else "http",
            "cves": [],
        }).target_id
        endpoints = ScannerGrant.from_dict({
            "profile_id": plan.profile_id,
            "target_id": plan.target_id,
            "endpoints": [
                {"protocol": item.protocol, "address": item.address, "port": item.port}
                for item in plan.endpoints
            ],
        }).endpoints
    except (AttributeError, TypeError):
        raise ScannerContractError("frozen plan target is invalid") from None
    if target_id != plan.target_id or endpoints != plan.endpoints:
        raise ScannerContractError("frozen plan target is not canonical")
    try:
        address = ipaddress.ip_address(plan.address)
    except ValueError:
        raise ScannerContractError("frozen plan target is invalid") from None
    if profile.family == "nse" and address.version != 4:
        raise ScannerContractError("initial NSE profiles require an IPv4 target")
    if str(address) != plan.address:
        raise ScannerContractError("frozen plan target is not canonical")
    actual = {(item.protocol, item.address, item.port) for item in endpoints}
    expected_endpoints = ({("tcp", plan.address, 445), ("udp", plan.address, 137)}
                          if profile.family == "nse" else {("tcp", plan.address, profile.port)})
    if actual != expected_endpoints or len(actual) != len(plan.endpoints):
        raise ScannerContractError("frozen plan network grant does not match the reviewed profile")
    return plan
