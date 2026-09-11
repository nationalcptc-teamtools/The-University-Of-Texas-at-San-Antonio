"""Parse one bounded MySQL server greeting without performing I/O."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


class MysqlGreetingError(ValueError):
    """The supplied bytes are not one complete bounded greeting."""


def parse_mysql_greeting(packet: bytes) -> dict[str, object]:
    """Return allowlisted posture facts from one complete HandshakeV10 packet."""

    if type(packet) is not bytes:
        raise MysqlGreetingError("greeting must be immutable bytes")
    catalog = _catalog()
    maximum = catalog["maximum_packet_bytes"]
    if not 4 <= len(packet) <= maximum:
        raise MysqlGreetingError("greeting exceeds the bounded packet size")

    payload_length = int.from_bytes(packet[:3], "little")
    if packet[3] != 0:
        raise MysqlGreetingError("greeting packet sequence must be zero")
    if payload_length != len(packet) - 4:
        raise MysqlGreetingError("packet length does not describe exactly one greeting")
    payload = packet[4:]
    if not payload or payload[0] != 10:
        raise MysqlGreetingError("unsupported MySQL greeting protocol")

    version_end = payload.find(b"\x00", 1, 2 + catalog["maximum_version_bytes"])
    if version_end < 0:
        raise MysqlGreetingError("server version is not NUL-terminated within its bound")
    raw_version = payload[1:version_end]
    try:
        version_text = raw_version.decode("ascii")
    except UnicodeDecodeError:
        raise MysqlGreetingError("server version must be ASCII") from None
    product_family, version = _normalize_version(version_text, catalog)

    cursor = version_end + 1
    fixed_tail_bytes = 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
    if len(payload) - cursor < fixed_tail_bytes:
        raise MysqlGreetingError("greeting is missing capability fields")

    cursor += 4  # connection identifier, deliberately discarded
    cursor += 8  # first auth-plugin-data part, deliberately discarded
    if payload[cursor] != 0:
        raise MysqlGreetingError("auth-plugin-data filler must be NUL")
    cursor += 1
    capabilities = int.from_bytes(payload[cursor : cursor + 2], "little")
    cursor += 2
    cursor += 1  # character set, deliberately discarded
    cursor += 2  # status flags, deliberately discarded
    capabilities |= int.from_bytes(payload[cursor : cursor + 2], "little") << 16
    cursor += 2
    auth_data_length = payload[cursor]
    cursor += 1
    if payload[cursor : cursor + 10] != b"\x00" * 10:
        raise MysqlGreetingError("reserved capability bytes must be zero")
    cursor += 10

    capability_map = catalog["capability_names"]
    known_mask = sum(capability_map) | sum(catalog["ignored_capability_bits"])
    if capabilities & ~known_mask:
        raise MysqlGreetingError("greeting sets an unknown capability bit")
    protocol_41 = catalog["required_capabilities"]["protocol_41"]
    secure = catalog["required_capabilities"]["secure_connection"]
    plugin_auth = catalog["required_capabilities"]["plugin_auth"]
    if not capabilities & protocol_41:
        raise MysqlGreetingError("protocol_41 capability is required")
    if capabilities & plugin_auth and not capabilities & secure:
        raise MysqlGreetingError("plugin_auth requires secure_connection")

    if capabilities & plugin_auth:
        if auth_data_length < 21:
            raise MysqlGreetingError("auth capability length is too short")
        second_auth_length = auth_data_length - 8
    else:
        if auth_data_length != 0:
            raise MysqlGreetingError("auth capability length is inconsistent")
        second_auth_length = 13 if capabilities & secure else 0

    if second_auth_length:
        auth_end = cursor + second_auth_length
        if auth_end > len(payload) or payload[auth_end - 1] != 0:
            raise MysqlGreetingError("auth capability length lacks a final NUL")
        cursor = auth_end

    if capabilities & plugin_auth:
        plugin = payload[cursor:]
        if not plugin or plugin[-1] != 0 or b"\x00" in plugin[:-1]:
            raise MysqlGreetingError("auth plugin name must have one final NUL")
        try:
            plugin_text = plugin[:-1].decode("ascii")
        except UnicodeDecodeError:
            raise MysqlGreetingError("auth plugin name must be ASCII") from None
        if _PLUGIN.fullmatch(plugin_text) is None:
            raise MysqlGreetingError("auth plugin name is malformed")
        cursor = len(payload)
    if cursor != len(payload):
        raise MysqlGreetingError("packet contains trailing greeting data")

    return {
        "protocol_version": 10,
        "product_family": product_family,
        "version": version,
        "capabilities": tuple(
            name for bit, name in capability_map.items() if capabilities & bit
        ),
    }


_PLUGIN = re.compile(r"[A-Za-z0-9_]{1,64}")
CATALOG_SHA256 = "92788ec6a7549f62d2010a73932657cfef94bd1a6107914f69823595315696c6"
CATALOG_MAX_BYTES = 16_384
_CATALOG_KEYS = {
    "schema_version",
    "maximum_packet_bytes",
    "maximum_version_bytes",
    "capability_names",
    "required_capabilities",
    "ignored_capability_bits",
    "neutral_vendor_suffixes",
}


def _catalog_bytes() -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise MysqlGreetingError("MySQL parser catalog is unavailable")
    try:
        descriptor = os.open(
            Path(__file__).with_name("catalog.json"),
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | no_follow,
        )
    except OSError as error:
        raise MysqlGreetingError("MySQL parser catalog is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > CATALOG_MAX_BYTES:
            raise MysqlGreetingError("MySQL parser catalog is unavailable")
        chunks: list[bytes] = []
        remaining = CATALOG_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as error:
        raise MysqlGreetingError("MySQL parser catalog is unavailable") from error
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > CATALOG_MAX_BYTES or sha256(raw).hexdigest() != CATALOG_SHA256:
        raise MysqlGreetingError("MySQL parser catalog is unavailable")
    return raw


def _catalog() -> dict[str, Any]:
    try:
        value = json.loads(_catalog_bytes().decode("utf-8"))
    except MysqlGreetingError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MysqlGreetingError("MySQL parser catalog is unavailable") from error
    if type(value) is not dict or set(value) != _CATALOG_KEYS:
        raise MysqlGreetingError("MySQL parser catalog has an invalid schema")
    if value["schema_version"] != 1 or type(value["schema_version"]) is not int:
        raise MysqlGreetingError("MySQL parser catalog has an invalid version")
    for key, lower, upper in (
        ("maximum_packet_bytes", 64, 1024),
        ("maximum_version_bytes", 5, 80),
    ):
        if type(value[key]) is not int or not lower <= value[key] <= upper:
            raise MysqlGreetingError("MySQL parser catalog has an invalid bound")
    raw_names = value["capability_names"]
    if type(raw_names) is not dict or not raw_names:
        raise MysqlGreetingError("MySQL parser catalog lacks capability names")
    names: dict[int, str] = {}
    for raw_bit, name in raw_names.items():
        try:
            bit = int(raw_bit, 16)
        except (TypeError, ValueError):
            raise MysqlGreetingError(
                "MySQL parser catalog has an invalid capability"
            ) from None
        if (
            bit <= 0
            or bit > 0xFFFFFFFF
            or bit & (bit - 1)
            or type(name) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,47}", name) is None
            or bit in names
        ):
            raise MysqlGreetingError("MySQL parser catalog has an invalid capability")
        names[bit] = name
    required = value["required_capabilities"]
    if type(required) is not dict or set(required) != {
        "protocol_41",
        "secure_connection",
        "plugin_auth",
    }:
        raise MysqlGreetingError("MySQL parser catalog has invalid capability rules")
    required_bits: dict[str, int] = {}
    for name, raw_bit in required.items():
        try:
            bit = int(raw_bit, 16)
        except (TypeError, ValueError):
            raise MysqlGreetingError("MySQL parser catalog has invalid capability rules") from None
        if names.get(bit) != name:
            raise MysqlGreetingError("MySQL parser catalog capability rules differ")
        required_bits[name] = bit
    raw_ignored = value["ignored_capability_bits"]
    if type(raw_ignored) is not list or not raw_ignored:
        raise MysqlGreetingError("MySQL parser catalog has invalid ignored capabilities")
    ignored: set[int] = set()
    for raw_bit in raw_ignored:
        try:
            bit = int(raw_bit, 16)
        except (TypeError, ValueError):
            raise MysqlGreetingError(
                "MySQL parser catalog has invalid ignored capabilities"
            ) from None
        if (
            bit <= 0
            or bit > 0xFFFFFFFF
            or bit & (bit - 1)
            or bit in names
            or bit in ignored
        ):
            raise MysqlGreetingError(
                "MySQL parser catalog has invalid ignored capabilities"
            )
        ignored.add(bit)
    neutral = value["neutral_vendor_suffixes"]
    if (
        type(neutral) is not list
        or not neutral
        or any(type(item) is not str or not item for item in neutral)
    ):
        raise MysqlGreetingError("MySQL parser catalog has invalid version suffixes")
    value["capability_names"] = dict(sorted(names.items()))
    value["required_capabilities"] = required_bits
    value["ignored_capability_bits"] = tuple(sorted(ignored))
    value["neutral_vendor_suffixes"] = tuple(neutral)
    return value


def _normalize_version(version: str, catalog: dict[str, Any]) -> tuple[str, str]:
    if not version or len(version.encode("ascii")) > catalog["maximum_version_bytes"]:
        raise MysqlGreetingError("server version exceeds its bound")
    match = re.fullmatch(
        r"(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\."
        r"(0|[1-9][0-9]{0,2})"
        r"((?:-[A-Za-z0-9][A-Za-z0-9.+_~]{0,31}){0,6})",
        version,
    )
    if match is None:
        raise MysqlGreetingError("server version does not match the closed grammar")
    normalized = ".".join(match.group(index) for index in (1, 2, 3))
    suffix = match.group(4)
    segments = tuple(part for part in suffix.split("-") if part)

    if len(segments) >= 2 and normalized == "5.5.5":
        compatibility = re.fullmatch(
            r"(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\."
            r"(0|[1-9][0-9]{0,2})",
            segments[0],
        )
        if compatibility is not None and segments[1] == "MariaDB":
            return "mariadb", ".".join(compatibility.groups())
    if segments and segments[0] == "MariaDB":
        return "mariadb", normalized
    if segments and segments[0] == "Percona":
        return "percona", normalized
    if segments and not all(
        _is_neutral_suffix(segment, catalog) for segment in segments
    ):
        return "mysql-compatible", normalized
    return "mysql", normalized


def _is_neutral_suffix(segment: str, catalog: dict[str, Any]) -> bool:
    reviewed = catalog["neutral_vendor_suffixes"]
    if segment in reviewed:
        return True
    for prefix in ("0ubuntu", "ubuntu", "debian"):
        if prefix in reviewed and re.fullmatch(
            rf"{re.escape(prefix)}[0-9]+(?:\.[0-9]+)*", segment
        ):
            return True
    return False
