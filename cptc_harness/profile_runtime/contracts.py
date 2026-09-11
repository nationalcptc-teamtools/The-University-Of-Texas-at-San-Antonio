"""Strict data contracts for the finite bounded-profile worker.

These objects describe data only. This module does not open a socket, resolve a
name, execute a process, read a credential, or write an artifact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import ipaddress
import json
import math
import re
from typing import Any, TypeAlias


class ProfileContractError(ValueError):
    """Input cannot be represented by the closed profile contract."""


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$")
_SAFE_HEADER_NAMES = frozenset({"Accept", "Connection", "Host"})
_BUDGET_FIELDS = frozenset(
    {
        "tcp_connects",
        "udp_datagrams",
        "tls_handshakes",
        "protocol_requests",
        "tx_bytes",
        "rx_bytes",
        "capture_bytes",
        "timeout_s",
        "cpu_s",
        "process_limit",
        "auth_attempts",
    }
)
_COUNTER_FIELDS = frozenset(
    {
        "tcp_connects",
        "udp_datagrams",
        "tls_handshakes",
        "protocol_requests",
        "tx_bytes",
        "rx_bytes",
        "capture_bytes",
    }
)

# These values cross the isolated PortCast worker boundary and can appear in
# metadata-only audit records. Keep both sets closed so target text, exception
# text, and credentials cannot become diagnostic fields.
PORTCAST_FAILURE_STAGES = frozenset(
    {
        "alternate_destination_control",
        "connected_ack",
        "deadline_before_target_open",
        "evidence_seal",
        "inventory",
        "ipc",
        "session_cleanup",
        "session_open",
        "target_open",
        "wire_exchange",
    }
)
PORTCAST_RESULT_LIMITATIONS = frozenset(
    {
        "audit_failure",
        "capture_incomplete",
        "certificate_mismatch",
        "response_truncated",
        "stop_latched",
        "timeout",
        "transport_interrupted",
        "unexpected_response",
    }
)


def _exact_dict(value: Any, expected: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != expected:
        raise ProfileContractError("unknown or missing contract field")
    return value


def _bounded_int(value: Any, name: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ProfileContractError(f"invalid {name}")
    return value


def _port(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ProfileContractError("invalid port")
    return value


def _address(value: Any) -> str:
    if not isinstance(value, str):
        raise ProfileContractError("address must be canonical IPv4 text")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise ProfileContractError("address must be canonical IPv4 text") from None
    if parsed.version != 4 or str(parsed) != value:
        raise ProfileContractError("address must be canonical IPv4 text")
    return value


def _server_name(value: Any) -> str:
    if not isinstance(value, str) or _DNS_NAME.fullmatch(value) is None:
        raise ProfileContractError("invalid TLS server name")
    return value


def _certificate_hash(value: Any) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ProfileContractError("invalid certificate hash")
    return value


def _canonical_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProfileBudget:
    tcp_connects: int
    udp_datagrams: int
    tls_handshakes: int
    protocol_requests: int
    tx_bytes: int
    rx_bytes: int
    capture_bytes: int
    timeout_s: float
    cpu_s: float
    process_limit: int
    auth_attempts: int

    @classmethod
    def from_dict(cls, value: Any) -> "ProfileBudget":
        row = _exact_dict(value, _BUDGET_FIELDS)
        timeout = row["timeout_s"]
        cpu = row["cpu_s"]
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
        ):
            raise ProfileContractError("invalid timeout_s")
        if (
            isinstance(cpu, bool)
            or not isinstance(cpu, (int, float))
            or not math.isfinite(cpu)
            or not 0 < cpu <= timeout
        ):
            raise ProfileContractError("invalid cpu_s")
        result = cls(
            tcp_connects=_bounded_int(row["tcp_connects"], "tcp_connects", 4),
            udp_datagrams=_bounded_int(row["udp_datagrams"], "udp_datagrams", 0),
            tls_handshakes=_bounded_int(row["tls_handshakes"], "tls_handshakes", 4),
            protocol_requests=_bounded_int(row["protocol_requests"], "protocol_requests", 4),
            tx_bytes=_bounded_int(row["tx_bytes"], "tx_bytes", 64 * 1024),
            rx_bytes=_bounded_int(row["rx_bytes"], "rx_bytes", 64 * 1024),
            capture_bytes=_bounded_int(row["capture_bytes"], "capture_bytes", 128 * 1024),
            timeout_s=float(timeout),
            cpu_s=float(cpu),
            process_limit=_bounded_int(row["process_limit"], "process_limit", 1),
            auth_attempts=_bounded_int(row["auth_attempts"], "auth_attempts", 0),
        )
        if result.process_limit != 1:
            raise ProfileContractError("process_limit must be one")
        if result.capture_bytes < result.rx_bytes:
            raise ProfileContractError("capture budget cannot be below receive budget")
        return result

    def as_dict(self) -> dict[str, int | float]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class WireCounters:
    tcp_connects: int
    udp_datagrams: int
    tls_handshakes: int
    protocol_requests: int
    tx_bytes: int
    rx_bytes: int
    capture_bytes: int

    @classmethod
    def from_dict(cls, value: Any) -> "WireCounters":
        row = _exact_dict(value, _COUNTER_FIELDS)
        result = cls(
            tcp_connects=_bounded_int(row["tcp_connects"], "tcp_connects", 4),
            udp_datagrams=_bounded_int(row["udp_datagrams"], "udp_datagrams", 0),
            tls_handshakes=_bounded_int(row["tls_handshakes"], "tls_handshakes", 4),
            protocol_requests=_bounded_int(row["protocol_requests"], "protocol_requests", 4),
            tx_bytes=_bounded_int(row["tx_bytes"], "tx_bytes", 64 * 1024),
            rx_bytes=_bounded_int(row["rx_bytes"], "rx_bytes", 64 * 1024),
            capture_bytes=_bounded_int(row["capture_bytes"], "capture_bytes", 128 * 1024),
        )
        if result.capture_bytes > result.rx_bytes:
            raise ProfileContractError("capture count exceeds received bytes")
        return result

    def as_dict(self) -> dict[str, int]:
        return asdict(self)

    def validate_against(self, budget: ProfileBudget) -> None:
        for name in _COUNTER_FIELDS:
            if getattr(self, name) > getattr(budget, name):
                raise ProfileContractError(f"wire counter exceeds {name} budget")


@dataclass(frozen=True, slots=True)
class Http11RequestV1:
    kind: str
    address: str
    port: int
    tls: bool
    server_name: str | None
    certificate_sha256: str | None
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]

    @property
    def sha256(self) -> str:
        value = asdict(self)
        value["headers"] = [list(item) for item in self.headers]
        return _canonical_hash(value)


@dataclass(frozen=True, slots=True)
class TlsHelloV1:
    kind: str
    address: str
    port: int
    server_name: str
    certificate_sha256: str

    @property
    def sha256(self) -> str:
        return _canonical_hash(asdict(self))


@dataclass(frozen=True, slots=True)
class RedisPingV1:
    kind: str
    address: str
    port: int

    @property
    def sha256(self) -> str:
        return _canonical_hash(asdict(self))


@dataclass(frozen=True, slots=True)
class MysqlGreetingV1:
    kind: str
    address: str
    port: int

    @property
    def sha256(self) -> str:
        return _canonical_hash(asdict(self))


ProfileOperation: TypeAlias = Http11RequestV1 | TlsHelloV1 | RedisPingV1 | MysqlGreetingV1


def _headers(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 3:
        raise ProfileContractError("invalid HTTP headers")
    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(part, str) for part in item)
        ):
            raise ProfileContractError("invalid HTTP header pair")
        name, content = item
        if name not in _SAFE_HEADER_NAMES or name in seen:
            raise ProfileContractError("forbidden or duplicate HTTP header")
        if not content or len(content) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in content):
            raise ProfileContractError("invalid HTTP header value")
        parsed.append((name, content))
        seen.add(name)
    if seen != {"Accept", "Connection", "Host"} or dict(parsed)["Connection"] != "close":
        raise ProfileContractError("HTTP headers must be the exact bounded set")
    return tuple(parsed)


def _http(value: Any) -> Http11RequestV1:
    expected = frozenset(field.name for field in fields(Http11RequestV1))
    row = _exact_dict(value, expected)
    if row["kind"] != "http11_request_v1":
        raise ProfileContractError("invalid HTTP operation kind")
    if type(row["tls"]) is not bool:
        raise ProfileContractError("invalid TLS flag")
    tls = row["tls"]
    if tls:
        server_name = _server_name(row["server_name"])
        certificate = _certificate_hash(row["certificate_sha256"])
    else:
        if row["server_name"] is not None or row["certificate_sha256"] is not None:
            raise ProfileContractError("cleartext HTTP cannot have TLS fields")
        server_name = None
        certificate = None
    address = _address(row["address"])
    port = _port(row["port"])
    method = row["method"]
    if not isinstance(method, str) or method not in {"GET", "HEAD"}:
        raise ProfileContractError("HTTP method is not read-only")
    path = row["path"]
    if not isinstance(path, str) or _PATH.fullmatch(path) is None or "//" in path:
        raise ProfileContractError("invalid fixed HTTP path")
    headers = _headers(row["headers"])
    host = dict(headers)["Host"]
    expected_host = server_name if tls else address
    expected_with_port = f"{expected_host}:{port}"
    if host not in {expected_host, expected_with_port}:
        raise ProfileContractError("Host header does not match the pinned endpoint")
    return Http11RequestV1(
        kind="http11_request_v1",
        address=address,
        port=port,
        tls=tls,
        server_name=server_name,
        certificate_sha256=certificate,
        method=method,
        path=path,
        headers=headers,
    )


def _tls(value: Any) -> TlsHelloV1:
    row = _exact_dict(value, frozenset(field.name for field in fields(TlsHelloV1)))
    if row["kind"] != "tls_hello_v1":
        raise ProfileContractError("invalid TLS operation kind")
    return TlsHelloV1(
        kind="tls_hello_v1",
        address=_address(row["address"]),
        port=_port(row["port"]),
        server_name=_server_name(row["server_name"]),
        certificate_sha256=_certificate_hash(row["certificate_sha256"]),
    )


def _redis(value: Any) -> RedisPingV1:
    row = _exact_dict(value, frozenset(field.name for field in fields(RedisPingV1)))
    if row["kind"] != "redis_ping_v1" or row["port"] != 6379:
        raise ProfileContractError("invalid Redis PING operation")
    return RedisPingV1("redis_ping_v1", _address(row["address"]), _port(row["port"]))


def _mysql(value: Any) -> MysqlGreetingV1:
    row = _exact_dict(value, frozenset(field.name for field in fields(MysqlGreetingV1)))
    if row["kind"] != "mysql_greeting_v1" or row["port"] != 3306:
        raise ProfileContractError("invalid MySQL greeting operation")
    return MysqlGreetingV1("mysql_greeting_v1", _address(row["address"]), _port(row["port"]))


def parse_operation(value: Any) -> ProfileOperation:
    """Parse only one operation from the fixed tagged union."""

    if not isinstance(value, dict):
        raise ProfileContractError("operation must be an object")
    kind = value.get("kind")
    if kind == "http11_request_v1":
        return _http(value)
    if kind == "tls_hello_v1":
        return _tls(value)
    if kind == "redis_ping_v1":
        return _redis(value)
    if kind == "mysql_greeting_v1":
        return _mysql(value)
    raise ProfileContractError("unknown operation kind")
