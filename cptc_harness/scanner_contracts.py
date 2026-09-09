"""Immutable, design-time contracts for the finite scanner profile catalog."""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
import hashlib
import ipaddress
import json
import math
import re
from typing import Any


class ScannerContractError(ValueError):
    """An input cannot be represented by the closed scanner contract."""


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^(?:[0-9a-f]{40}|package:[A-Za-z0-9][A-Za-z0-9._+:-]{0,127})$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_PROFILE_UPSTREAM = {
    "network.nse_smb2_security_mode": ("nse", "smb2-security-mode.nse"),
    "network.nse_smb2_time": ("nse", "smb2-time.nse"),
    "network.msf_http_version": ("msf", "auxiliary/scanner/http/http_version"),
}
_PROFILE_RUNNER = {
    "network.nse_smb2_security_mode": "design.nmap.nse-smb2-security-mode-v1",
    "network.nse_smb2_time": "design.nmap.nse-smb2-time-v1",
    "network.msf_http_version": "design.msf.http-version-v1",
}
_FORBIDDEN_TOKENS = frozenset({
    "msfconsole", "msgrpc", "rpc", "console", "resource", "forceexploit",
    "payload", "session", "credential", "password", "login", "shell",
})


def _exact(value: Any, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ScannerContractError("unknown or missing contract fields")
    return value


def _text(value: Any, label: str, *, pattern: re.Pattern[str] | None = None, maximum: int = 256) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ScannerContractError(f"invalid {label}")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ScannerContractError(f"invalid {label}")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value > 2_147_483_647:
        raise ScannerContractError(f"invalid {label}")
    return value


@dataclass(frozen=True, slots=True)
class TrafficBudget:
    tcp_connects: int
    udp_datagrams: int
    protocol_requests: int
    tx_bytes: int
    rx_bytes: int
    timeout_s: float
    cpu_s: float
    output_bytes: int
    process_limit: int
    auth_attempts: int

    @classmethod
    def from_dict(cls, value: Any) -> "TrafficBudget":
        row = _exact(value, {field.name for field in fields(cls)})
        timeout = row["timeout_s"]
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0 or timeout > 60:
            raise ScannerContractError("invalid timeout_s")
        cpu = row["cpu_s"]
        if isinstance(cpu, bool) or not isinstance(cpu, (int, float)) or not math.isfinite(cpu) or cpu <= 0 or cpu > timeout:
            raise ScannerContractError("invalid cpu_s")
        return cls(
            tcp_connects=_nonnegative_int(row["tcp_connects"], "tcp_connects"),
            udp_datagrams=_nonnegative_int(row["udp_datagrams"], "udp_datagrams"),
            protocol_requests=_nonnegative_int(row["protocol_requests"], "protocol_requests"),
            tx_bytes=_nonnegative_int(row["tx_bytes"], "tx_bytes"),
            rx_bytes=_nonnegative_int(row["rx_bytes"], "rx_bytes"),
            timeout_s=float(timeout),
            cpu_s=float(cpu),
            output_bytes=_nonnegative_int(row["output_bytes"], "output_bytes"),
            process_limit=_nonnegative_int(row["process_limit"], "process_limit"),
            auth_attempts=_nonnegative_int(row["auth_attempts"], "auth_attempts"),
        )


@dataclass(frozen=True, slots=True)
class SourcePin:
    repository: str
    path: str
    revision: str
    sha256: str
    license: str
    redistributable: bool

    @classmethod
    def from_dict(cls, value: Any) -> "SourcePin":
        row = _exact(value, {field.name for field in fields(cls)})
        repository = _text(row["repository"], "source repository", maximum=512)
        path = _text(row["path"], "source path", maximum=512)
        if "://" not in repository or path.startswith("/") or ".." in path.split("/"):
            raise ScannerContractError("invalid source locator")
        revision = _text(row["revision"], "source revision", pattern=_REVISION, maximum=160)
        sha256 = _text(row["sha256"], "source hash", pattern=_HEX64, maximum=64)
        license_name = _text(row["license"], "source license", maximum=128)
        if type(row["redistributable"]) is not bool:
            raise ScannerContractError("invalid redistribution flag")
        return cls(repository, path, revision, sha256, license_name, row["redistributable"])


@dataclass(frozen=True, slots=True)
class ScannerProfile:
    profile_id: str
    family: str
    upstream_id: str
    runner_id: str
    tier: str
    mode: str
    protocol: str
    port: int
    budget: TrafficBudget
    source: SourcePin
    allowed_options: tuple[str, ...]
    effects: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "ScannerProfile":
        row = _exact(value, {field.name for field in fields(cls)})
        profile_id = _text(row["profile_id"], "profile id", pattern=_ID)
        family = _text(row["family"], "profile family", maximum=16)
        upstream_id = _text(row["upstream_id"], "upstream module id", maximum=256)
        runner_id = _text(row["runner_id"], "runner id", pattern=_ID, maximum=128)
        tier = _text(row["tier"], "profile tier", maximum=32)
        mode = _text(row["mode"], "profile mode", maximum=32)
        protocol = _text(row["protocol"], "profile protocol", maximum=16)
        if family not in {"nse", "msf"} or tier not in {"observation", "candidate_manual"} or mode not in {"design_only", "synthetic_only"}:
            raise ScannerContractError("profile is outside the design-only contract")
        if (family == "nse" and mode != "synthetic_only") or (family == "msf" and mode != "design_only"):
            raise ScannerContractError("profile mode is incompatible with its source family")
        if _PROFILE_UPSTREAM.get(profile_id) != (family, upstream_id):
            raise ScannerContractError("profile is outside the finite reviewed set")
        if _PROFILE_RUNNER.get(profile_id) != runner_id:
            raise ScannerContractError("profile runner is outside the finite reviewed set")
        if any(token in upstream_id.lower() for token in _FORBIDDEN_TOKENS):
            raise ScannerContractError("runtime or forbidden module string")
        if protocol not in {"smb", "http"}:
            raise ScannerContractError("profile protocol is not admitted")
        port = row["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ScannerContractError("invalid profile port")
        options = row["allowed_options"]
        effects = row["effects"]
        if not isinstance(options, list) or not all(isinstance(item, str) and _ID.fullmatch(item) for item in options):
            raise ScannerContractError("invalid profile options")
        if options:
            raise ScannerContractError("runtime options are not admitted")
        if not isinstance(effects, list) or not effects or not all(isinstance(item, str) and _ID.fullmatch(item) for item in effects):
            raise ScannerContractError("invalid profile effects")
        if any(any(token in item.lower() for token in _FORBIDDEN_TOKENS) for item in effects):
            raise ScannerContractError("forbidden profile capability")
        if {"no_authentication", "no_retry", "no_fallback"} - set(effects):
            raise ScannerContractError("profile is missing a fail-closed restriction")
        return cls(profile_id, family, upstream_id, runner_id, tier, mode, protocol, port,
                   TrafficBudget.from_dict(row["budget"]), SourcePin.from_dict(row["source"]),
                   tuple(options), tuple(effects))


@dataclass(frozen=True, slots=True)
class ScannerObservation:
    target_id: str
    address: str
    port: int
    service: str
    scheme: str | None
    cves: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "ScannerObservation":
        if isinstance(value, dict) and ("grant" in value or "grants" in value):
            raise ScannerContractError("compound grants are not accepted")
        row = _exact(value, {field.name for field in fields(cls)})
        target_id = _text(row["target_id"], "target id", pattern=_TARGET)
        if "*" in target_id or "/" in target_id:
            raise ScannerContractError("target id contains a wildcard or path")
        address = _text(row["address"], "target address", maximum=64)
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            raise ScannerContractError("target address must be a numeric IP") from None
        if str(parsed_address) != address:
            raise ScannerContractError("target address must use canonical IP text")
        port = row["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ScannerContractError("invalid target port")
        service = _text(row["service"], "service", maximum=64).lower()
        if any(token in service for token in ("*", "?", "/", "\\")) or service.endswith(".nse"):
            raise ScannerContractError("service cannot be a script path or wildcard")
        scheme = row["scheme"]
        if scheme is not None and scheme not in {"http", "https"}:
            raise ScannerContractError("invalid target scheme")
        cves = row["cves"]
        if not isinstance(cves, list) or len(cves) > 16 or not all(isinstance(item, str) for item in cves):
            raise ScannerContractError("invalid CVE list")
        if len(set(cves)) != len(cves):
            raise ScannerContractError("duplicate CVE is not admitted")
        for cve in cves:
            if _CVE.fullmatch(cve) is None:
                raise ScannerContractError("malformed CVE identifier")
        return cls(target_id, address, port, service, scheme, tuple(cves))


@dataclass(frozen=True, slots=True)
class NetworkEndpoint:
    protocol: str
    address: str
    port: int

    @classmethod
    def from_dict(cls, value: Any) -> "NetworkEndpoint":
        row = _exact(value, {field.name for field in fields(cls)})
        protocol = row["protocol"]
        if protocol not in {"tcp", "udp"}:
            raise ScannerContractError("invalid grant protocol")
        address = _text(row["address"], "grant address", maximum=64)
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            raise ScannerContractError("grant address must be numeric") from None
        if str(parsed_address) != address:
            raise ScannerContractError("grant address must use canonical IP text")
        port = row["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ScannerContractError("invalid grant port")
        return cls(protocol, address, port)


@dataclass(frozen=True, slots=True)
class ScannerGrant:
    profile_id: str
    target_id: str
    endpoints: tuple[NetworkEndpoint, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "ScannerGrant":
        if isinstance(value, list):
            raise ScannerContractError("compound grants are not accepted")
        row = _exact(value, {field.name for field in fields(cls)})
        profile_id = _text(row["profile_id"], "grant profile id", pattern=_ID)
        target_id = _text(row["target_id"], "grant target id", pattern=_TARGET)
        endpoints = row["endpoints"]
        if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 2:
            raise ScannerContractError("invalid compound grant")
        parsed = tuple(NetworkEndpoint.from_dict(item) for item in endpoints)
        if len(set(parsed)) != len(parsed):
            raise ScannerContractError("invalid compound grant")
        return cls(profile_id, target_id, parsed)


@dataclass(frozen=True, slots=True)
class ScanPlan:
    catalog_sha256: str
    profile_sha256: str
    profile_id: str
    family: str
    upstream_id: str
    runner_id: str
    target_id: str
    address: str
    port: int
    protocol: str
    endpoints: tuple[NetworkEndpoint, ...]
    mode: str
    tier: str
    budget: TrafficBudget
    source: SourcePin
    allowed_options: tuple[str, ...]
    effects: tuple[str, ...]
    approval_required: bool
    reason: str


def canonical_json(value: Any) -> bytes:
    if is_dataclass(value):
        value = {field.name: getattr(value, field.name) for field in fields(value)}
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ScannerContractError("contract object keys must be strings")
        value = {key: json.loads(canonical_json(item)) for key, item in value.items()}
    elif isinstance(value, (tuple, list)):
        value = [json.loads(canonical_json(item)) for item in value]
    elif isinstance(value, (str, int, bool)) or value is None:
        pass
    elif isinstance(value, float) and math.isfinite(value):
        pass
    else:
        raise ScannerContractError("value is outside the scanner contract")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def contract_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def validate_grant(grant: ScannerGrant, profile: ScannerProfile, observation: ScannerObservation) -> None:
    if not isinstance(grant, ScannerGrant):
        raise ScannerContractError("compound grants are not accepted")
    try:
        checked_observation = ScannerObservation.from_dict({
            "target_id": observation.target_id,
            "address": observation.address,
            "port": observation.port,
            "service": observation.service,
            "scheme": observation.scheme,
            "cves": list(observation.cves),
        })
        checked_grant = ScannerGrant.from_dict({
            "profile_id": grant.profile_id,
            "target_id": grant.target_id,
            "endpoints": [
                {"protocol": item.protocol, "address": item.address, "port": item.port}
                for item in grant.endpoints
            ],
        })
    except (AttributeError, TypeError):
        raise ScannerContractError("scanner grant contains an invalid typed value") from None
    if checked_observation != observation or checked_grant != grant:
        raise ScannerContractError("scanner grant or observation is not canonical")
    if grant.profile_id != profile.profile_id or grant.target_id != observation.target_id:
        raise ScannerContractError("grant does not match one profile and one target")
    if any(endpoint.address != observation.address for endpoint in grant.endpoints):
        raise ScannerContractError("grant address does not match target")
    actual = {(endpoint.protocol, endpoint.port) for endpoint in grant.endpoints}
    if profile.family == "nse":
        if actual != {("tcp", 445), ("udp", 137)}:
            raise ScannerContractError("NSE profile requires a compound TCP/445 and UDP/137 grant")
    elif actual != {("tcp", profile.port)}:
        raise ScannerContractError("MSF profile requires one TCP grant for its fixed port")
