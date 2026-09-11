from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from cptc_harness.profiles.common_mysql import parser as mysql_parser
from cptc_harness.profiles.common_mysql.parser import (
    MysqlGreetingError,
    parse_mysql_greeting,
)


FIXTURES = (
    Path(__file__).parents[2]
    / "cptc_harness"
    / "profiles"
    / "common_mysql"
    / "fixtures"
    / "cases.json"
)


def load_cases() -> dict[str, dict[str, object]]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


def packet(name: str) -> bytes:
    row = load_cases()[name]
    if "hex" in row:
        return bytes.fromhex(str(row["hex"]))
    base = packet(str(row["base"]))
    payload = base[4:] + bytes.fromhex(str(row["append_hex"])) * int(row["repeat"])
    length = int(row["payload_length"])
    assert len(payload) == length
    return length.to_bytes(3, "little") + b"\x00" + payload


def packet_with_version(version: str) -> bytes:
    original = packet("hardened")
    payload = original[4:]
    version_end = payload.index(0, 1)
    changed = payload[:1] + version.encode("ascii") + payload[version_end:]
    return len(changed).to_bytes(3, "little") + b"\x00" + changed


def install_test_catalog(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw: bytes,
) -> Path:
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_bytes(raw)
    monkeypatch.setattr(mysql_parser, "__file__", str(tmp_path / "parser.py"))
    monkeypatch.setattr(
        mysql_parser,
        "CATALOG_SHA256",
        sha256(raw).hexdigest(),
        raising=False,
    )
    return catalog_path


def test_vulnerable_greeting_returns_only_bounded_posture_facts() -> None:
    assert parse_mysql_greeting(packet("vulnerable")) == {
        "protocol_version": 10,
        "product_family": "mariadb",
        "version": "10.11.6",
        "capabilities": (
            "long_password",
            "long_flag",
            "local_files",
            "protocol_41",
            "secure_connection",
            "multi_statements",
            "plugin_auth",
        ),
    }


def test_hardened_greeting_returns_closed_capability_names() -> None:
    assert parse_mysql_greeting(packet("hardened")) == {
        "protocol_version": 10,
        "product_family": "mysql",
        "version": "8.0.36",
        "capabilities": (
            "long_password",
            "long_flag",
            "protocol_41",
            "ssl",
            "secure_connection",
            "plugin_auth",
            "connect_attrs",
            "session_track",
            "deprecate_eof",
        ),
    }


def test_ambiguous_vendor_is_not_promoted_to_a_known_product_family() -> None:
    facts = parse_mysql_greeting(packet("ambiguous"))
    assert facts["product_family"] == "mysql-compatible"
    assert facts["version"] == "8.0.36"


@pytest.mark.parametrize(
    "version",
    (
        "8.0.36-mysqlxx",
        "8.0.36-logstash",
        "8.0.36-ubuntuclone",
        "8.0.36-Foo-MariaDB",
    ),
)
def test_withheld_vendor_suffixes_remain_mysql_compatible(version: str) -> None:
    assert parse_mysql_greeting(packet_with_version(version))["product_family"] == (
        "mysql-compatible"
    )


@pytest.mark.parametrize(
    "version",
    (
        "8.0.36-log",
        "8.0.36-commercial",
        "8.0.36-cluster",
        "8.0.36-mysql",
        "8.0.36-0ubuntu0.22.04.1",
        "8.0.36-ubuntu22.04",
        "8.0.36-debian12.5",
    ),
)
def test_only_reviewed_neutral_suffix_grammar_remains_mysql(version: str) -> None:
    assert parse_mysql_greeting(packet_with_version(version))["product_family"] == "mysql"


@pytest.mark.parametrize(
    "name",
    (
        "partial",
        "wrong_protocol",
        "oversized",
        "truncated",
        "parser_confusion",
    ),
)
def test_malformed_or_non_single_greetings_fail_closed(name: str) -> None:
    with pytest.raises(MysqlGreetingError):
        parse_mysql_greeting(packet(name))


def test_packet_header_requires_sequence_zero_and_exact_payload_length() -> None:
    changed = bytearray(packet("hardened"))
    changed[3] = 1
    with pytest.raises(MysqlGreetingError, match="sequence"):
        parse_mysql_greeting(bytes(changed))


def test_version_and_plugin_fields_require_nul_termination() -> None:
    changed = bytearray(packet("hardened"))
    changed[-1] = ord("X")
    with pytest.raises(MysqlGreetingError, match="NUL"):
        parse_mysql_greeting(bytes(changed))

    version_end = changed.find(0, 5)
    changed = bytearray(packet("hardened"))
    changed[version_end] = ord("X")
    with pytest.raises(MysqlGreetingError):
        parse_mysql_greeting(bytes(changed))


def test_capability_dependent_auth_lengths_are_exact() -> None:
    changed = bytearray(packet("hardened"))
    version_end = changed.find(0, 5)
    auth_length_offset = version_end + 1 + 4 + 8 + 1 + 2 + 1 + 2 + 2
    changed[auth_length_offset] = 22
    with pytest.raises(MysqlGreetingError, match="length"):
        parse_mysql_greeting(bytes(changed))


def test_reserved_capability_bits_are_accepted_but_never_reported() -> None:
    original = packet("hardened")
    changed = bytearray(original)
    version_end = changed.find(0, 5)
    lower_capability_offset = version_end + 1 + 4 + 8 + 1
    changed[lower_capability_offset + 1] |= 0x40
    assert parse_mysql_greeting(bytes(changed)) == parse_mysql_greeting(original)


def test_credentials_in_discarded_greeting_fields_never_reach_output() -> None:
    facts = parse_mysql_greeting(packet("credential_bearing"))
    rendered = json.dumps(facts)
    assert facts["version"] == "8.0.36"
    assert "hunter2" not in rendered
    assert "mysql_native_password" not in rendered
    assert set(facts) == {
        "protocol_version",
        "product_family",
        "version",
        "capabilities",
    }


@pytest.mark.parametrize("value", (None, "not-bytes", bytearray(b"abc")))
def test_parser_accepts_only_immutable_wire_bytes(value: object) -> None:
    with pytest.raises(MysqlGreetingError):
        parse_mysql_greeting(value)  # type: ignore[arg-type]


def test_catalog_digest_rejects_altered_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = mysql_parser.Path(mysql_parser.__file__).with_name("catalog.json").read_bytes()
    altered = raw.replace(b'"schema_version": 1', b'"schema_version": 2', 1)
    assert altered != raw
    path = tmp_path / "catalog.json"
    path.write_bytes(altered)
    monkeypatch.setattr(mysql_parser, "__file__", str(tmp_path / "parser.py"))

    with pytest.raises(MysqlGreetingError, match="catalog is unavailable"):
        parse_mysql_greeting(packet("hardened"))


def test_catalog_digest_constant_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mysql_parser, "CATALOG_SHA256", "0" * 64, raising=False)

    with pytest.raises(MysqlGreetingError, match="catalog is unavailable"):
        parse_mysql_greeting(packet("hardened"))


def test_catalog_symlink_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = mysql_parser.Path(mysql_parser.__file__).with_name("catalog.json")
    (tmp_path / "catalog.json").symlink_to(original)
    monkeypatch.setattr(mysql_parser, "__file__", str(tmp_path / "parser.py"))

    with pytest.raises(MysqlGreetingError, match="catalog is unavailable"):
        parse_mysql_greeting(packet("hardened"))


def test_absent_catalog_uses_public_parser_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(mysql_parser, "__file__", str(tmp_path / "parser.py"))

    with pytest.raises(MysqlGreetingError, match="catalog is unavailable"):
        parse_mysql_greeting(packet("hardened"))


def test_catalog_size_limit_is_enforced(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = mysql_parser.Path(mysql_parser.__file__).with_name("catalog.json").read_bytes()
    oversized = raw + b" " * 20_000
    install_test_catalog(monkeypatch, tmp_path, oversized)

    with pytest.raises(MysqlGreetingError, match="catalog is unavailable"):
        parse_mysql_greeting(packet("hardened"))
