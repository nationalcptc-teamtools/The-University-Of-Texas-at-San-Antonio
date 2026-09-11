"""Validate supplied TLS receipt data without performing I/O."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping


class TlsReceiptError(ValueError):
    """The supplied receipt is outside the closed TLS parser contract."""


def parse_tls_receipt(receipt: Mapping[str, object]) -> dict[str, object]:
    """Return allowlisted posture facts from one trusted worker receipt."""

    catalog = _catalog()
    if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS:
        raise TlsReceiptError("TLS receipt has unknown or missing fields")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1:
        raise TlsReceiptError("TLS receipt schema is unsupported")
    if receipt["receipt_type"] != "trusted_tls_receipt_v1":
        raise TlsReceiptError("TLS receipt type is not trusted")
    if receipt["handshake_complete"] is not True:
        raise TlsReceiptError("TLS receipt does not describe a complete handshake")

    profile_id = receipt["profile_id"]
    if type(profile_id) is not str or _PROFILE_ID.fullmatch(profile_id) is None:
        raise TlsReceiptError("TLS receipt profile identifier is malformed")
    server_name = _dns_name(receipt["server_name"], wildcard=False)
    if catalog["profile_server_names"].get(profile_id) != server_name:
        raise TlsReceiptError("TLS receipt SNI is not catalog-pinned")
    version = receipt["tls_version"]
    if type(version) is not str or version not in catalog["tls_versions"]:
        raise TlsReceiptError("TLS protocol must be version 1.2 or later")
    cipher = receipt["cipher_name"]
    if type(cipher) is not str or cipher not in catalog["cipher_names"]:
        raise TlsReceiptError("TLS cipher name is outside the closed catalog")
    certificate = receipt["certificate_sha256"]
    if type(certificate) is not str or _SHA256.fullmatch(certificate) is None:
        raise TlsReceiptError("certificate SHA-256 is malformed")

    raw_sans = receipt["san_dns_names"]
    if (
        type(raw_sans) is not list
        or not 1 <= len(raw_sans) <= catalog["maximum_san_names"]
    ):
        raise TlsReceiptError("SAN list exceeds its closed bound")
    sans = tuple(_dns_name(value, wildcard=True) for value in raw_sans)
    if len(sans) != len(set(sans)):
        raise TlsReceiptError("SAN list contains a duplicate name")

    not_before_text, not_before = _timestamp(receipt["not_before"])
    not_after_text, not_after = _timestamp(receipt["not_after"])
    _, captured_at = _timestamp(receipt["captured_at"])
    if not_before >= not_after:
        raise TlsReceiptError("certificate validity interval is not ordered")

    return {
        "tls_version": version,
        "cipher_name": cipher,
        "certificate_sha256": certificate,
        "san_exact_match": server_name in sans,
        "valid_from": not_before_text,
        "valid_until": not_after_text,
        "valid_at_capture": not_before <= captured_at <= not_after,
    }


_RECEIPT_FIELDS = {
    "schema_version",
    "receipt_type",
    "handshake_complete",
    "profile_id",
    "server_name",
    "tls_version",
    "cipher_name",
    "certificate_sha256",
    "san_dns_names",
    "not_before",
    "not_after",
    "captured_at",
}
_CATALOG_FIELDS = {
    "schema_version",
    "profile_server_names",
    "tls_versions",
    "cipher_names",
    "maximum_san_names",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROFILE_ID = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\.v[1-9][0-9]*")
_DNS = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{6})?Z"
)
CATALOG_SHA256 = "7030d6d48cf91d97cadaff29c7c39f2de9bfe9f720ea128f76f04cbfb5349123"
CATALOG_MAX_BYTES = 16_384


def _catalog_bytes() -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise TlsReceiptError("TLS parser catalog is unavailable")
    try:
        descriptor = os.open(
            Path(__file__).with_name("catalog.json"),
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | no_follow,
        )
    except OSError as error:
        raise TlsReceiptError("TLS parser catalog is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > CATALOG_MAX_BYTES:
            raise TlsReceiptError("TLS parser catalog is unavailable")
        chunks: list[bytes] = []
        remaining = CATALOG_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as error:
        raise TlsReceiptError("TLS parser catalog is unavailable") from error
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > CATALOG_MAX_BYTES or sha256(raw).hexdigest() != CATALOG_SHA256:
        raise TlsReceiptError("TLS parser catalog is unavailable")
    return raw


def _catalog() -> dict[str, Any]:
    try:
        value = json.loads(_catalog_bytes().decode("utf-8"))
    except TlsReceiptError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise TlsReceiptError("TLS parser catalog is unavailable") from error
    if type(value) is not dict or set(value) != _CATALOG_FIELDS:
        raise TlsReceiptError("TLS parser catalog has an invalid schema")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise TlsReceiptError("TLS parser catalog has an invalid version")
    if (
        type(value["maximum_san_names"]) is not int
        or not 1 <= value["maximum_san_names"] <= 32
    ):
        raise TlsReceiptError("TLS parser catalog has an invalid SAN bound")
    profile_server_names = value["profile_server_names"]
    versions = value["tls_versions"]
    ciphers = value["cipher_names"]
    if (
        type(profile_server_names) is not dict
        or not profile_server_names
        or type(versions) is not list
        or versions != ["TLSv1.2", "TLSv1.3"]
        or type(ciphers) is not list
        or not ciphers
    ):
        raise TlsReceiptError("TLS parser catalog has invalid closed values")
    pins: dict[str, str] = {}
    for profile_id, server_name in profile_server_names.items():
        if type(profile_id) is not str or _PROFILE_ID.fullmatch(profile_id) is None:
            raise TlsReceiptError("TLS parser catalog has an invalid profile identifier")
        pins[profile_id] = _dns_name(server_name, wildcard=False)
    value["profile_server_names"] = pins
    if any(type(name) is not str for name in ciphers):
        raise TlsReceiptError("TLS parser catalog has invalid closed values")
    if any(
        re.fullmatch(r"[A-Z0-9_-]{1,64}", name) is None for name in ciphers
    ) or len(ciphers) != len(set(ciphers)):
        raise TlsReceiptError("TLS parser catalog has an invalid cipher name")
    value["cipher_names"] = tuple(ciphers)
    value["tls_versions"] = tuple(versions)
    return value


def _dns_name(value: object, *, wildcard: bool) -> str:
    if type(value) is not str:
        raise TlsReceiptError("DNS name must be canonical ASCII text")
    candidate = value
    if wildcard and candidate.startswith("*."):
        candidate = candidate[2:]
    if _DNS.fullmatch(candidate) is None:
        raise TlsReceiptError("DNS name must be canonical ASCII text")
    return value


def _timestamp(value: object) -> tuple[str, datetime]:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise TlsReceiptError("certificate time must be canonical UTC text")
    try:
        timestamp_format = (
            "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ"
        )
        parsed = datetime.strptime(value, timestamp_format).replace(tzinfo=timezone.utc)
    except ValueError:
        raise TlsReceiptError("certificate time is not a real UTC timestamp") from None
    return value, parsed
