from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import socket
import ssl

import pytest

from cptc_harness.profiles.common_tls import parser as tls_parser
from cptc_harness.profiles.common_tls.parser import TlsReceiptError, parse_tls_receipt


FIXTURES = (
    Path(__file__).parents[2]
    / "cptc_harness"
    / "profiles"
    / "common_tls"
    / "fixtures"
    / "cases.json"
)


def load_cases() -> dict[str, dict[str, object]]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


def install_test_catalog(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    value: object,
) -> Path:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_bytes(raw)
    monkeypatch.setattr(tls_parser, "__file__", str(tmp_path / "parser.py"))
    monkeypatch.setattr(
        tls_parser,
        "CATALOG_SHA256",
        sha256(raw).hexdigest(),
        raising=False,
    )
    return catalog_path


def test_hardened_receipt_returns_only_certificate_posture() -> None:
    assert parse_tls_receipt(load_cases()["hardened"]) == {
        "tls_version": "TLSv1.3",
        "cipher_name": "TLS_AES_256_GCM_SHA384",
        "certificate_sha256": "a" * 64,
        "san_exact_match": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "valid_at_capture": True,
    }


def test_vulnerable_receipt_preserves_mismatch_and_expiry_as_boolean_posture() -> None:
    assert parse_tls_receipt(load_cases()["vulnerable"]) == {
        "tls_version": "TLSv1.2",
        "cipher_name": "ECDHE-RSA-AES128-SHA",
        "certificate_sha256": "b" * 64,
        "san_exact_match": False,
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_until": "2025-01-01T00:00:00Z",
        "valid_at_capture": False,
    }


def test_ambiguous_extra_sans_do_not_change_exact_match_semantics() -> None:
    facts = parse_tls_receipt(load_cases()["ambiguous"])
    assert facts["san_exact_match"] is True
    assert "san_dns_names" not in facts


@pytest.mark.parametrize(
    "name",
    (
        "partial",
        "wrong_protocol",
        "oversized",
        "truncated",
        "credential_bearing",
        "parser_confusion",
    ),
)
def test_invalid_or_expansive_receipts_fail_closed(name: str) -> None:
    with pytest.raises(TlsReceiptError):
        parse_tls_receipt(load_cases()[name])


def test_only_catalog_pinned_sni_is_accepted() -> None:
    changed = dict(load_cases()["hardened"])
    changed["server_name"] = "unlisted.example.test"
    with pytest.raises(TlsReceiptError, match="pinned"):
        parse_tls_receipt(changed)


def test_sni_pin_is_bound_to_the_receipt_profile() -> None:
    changed = dict(load_cases()["hardened"])
    changed["server_name"] = "penny.allports.tours"
    with pytest.raises(TlsReceiptError, match="pinned"):
        parse_tls_receipt(changed)


def test_cipher_name_must_be_in_closed_catalog() -> None:
    changed = dict(load_cases()["hardened"])
    changed["cipher_name"] = "TLS_FAKE_WITH_UNKNOWN_CIPHER"
    with pytest.raises(TlsReceiptError, match="cipher"):
        parse_tls_receipt(changed)


def test_certificate_validity_order_is_enforced() -> None:
    changed = dict(load_cases()["hardened"])
    changed["not_after"] = changed["not_before"]
    with pytest.raises(TlsReceiptError, match="validity"):
        parse_tls_receipt(changed)


def test_six_microsecond_digits_are_retained_as_canonical_utc() -> None:
    changed = dict(load_cases()["hardened"])
    changed["not_before"] = "2026-01-01T00:00:00.123456Z"
    changed["not_after"] = "2027-01-01T00:00:00.654321Z"
    changed["captured_at"] = "2026-06-01T00:00:00.500000Z"

    facts = parse_tls_receipt(changed)

    assert facts["valid_from"] == "2026-01-01T00:00:00.123456Z"
    assert facts["valid_until"] == "2027-01-01T00:00:00.654321Z"
    assert facts["valid_at_capture"] is True


@pytest.mark.parametrize(
    "timestamp",
    (
        "2026-01-01T00:00:00.1Z",
        "2026-01-01T00:00:00.12345Z",
        "2026-01-01T00:00:00.1234567Z",
    ),
)
def test_other_fractional_timestamp_forms_are_rejected(timestamp: str) -> None:
    changed = dict(load_cases()["hardened"])
    changed["captured_at"] = timestamp

    with pytest.raises(TlsReceiptError, match="canonical UTC"):
        parse_tls_receipt(changed)


def test_unhashable_cipher_catalog_entry_uses_public_parser_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalog = json.loads(
        tls_parser.Path(tls_parser.__file__).with_name("catalog.json").read_text(
            encoding="utf-8"
        )
    )
    catalog["cipher_names"] = [["TLS_AES_256_GCM_SHA384"]]
    install_test_catalog(monkeypatch, tmp_path, catalog)

    with pytest.raises(TlsReceiptError, match="invalid closed values"):
        parse_tls_receipt(load_cases()["hardened"])


def test_pure_parser_does_not_create_a_socket_or_tls_context(monkeypatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("network or TLS setup attempted")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    assert parse_tls_receipt(load_cases()["hardened"])["san_exact_match"] is True


def test_catalog_digest_rejects_altered_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = tls_parser.Path(tls_parser.__file__).with_name("catalog.json").read_bytes()
    altered = raw.replace(b'"schema_version": 1', b'"schema_version": 2', 1)
    assert altered != raw
    path = tmp_path / "catalog.json"
    path.write_bytes(altered)
    monkeypatch.setattr(tls_parser, "__file__", str(tmp_path / "parser.py"))

    with pytest.raises(TlsReceiptError, match="catalog is unavailable"):
        parse_tls_receipt(load_cases()["hardened"])


def test_catalog_digest_constant_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tls_parser, "CATALOG_SHA256", "0" * 64, raising=False)

    with pytest.raises(TlsReceiptError, match="catalog is unavailable"):
        parse_tls_receipt(load_cases()["hardened"])


def test_catalog_symlink_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = tls_parser.Path(tls_parser.__file__).with_name("catalog.json")
    (tmp_path / "catalog.json").symlink_to(original)
    monkeypatch.setattr(tls_parser, "__file__", str(tmp_path / "parser.py"))

    with pytest.raises(TlsReceiptError, match="catalog is unavailable"):
        parse_tls_receipt(load_cases()["hardened"])


def test_absent_catalog_uses_public_parser_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(tls_parser, "__file__", str(tmp_path / "parser.py"))

    with pytest.raises(TlsReceiptError, match="catalog is unavailable"):
        parse_tls_receipt(load_cases()["hardened"])


def test_catalog_size_limit_is_enforced(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalog = json.loads(
        tls_parser.Path(tls_parser.__file__).with_name("catalog.json").read_text(
            encoding="utf-8"
        )
    )
    catalog["padding"] = "x" * 20_000
    install_test_catalog(monkeypatch, tmp_path, catalog)

    with pytest.raises(TlsReceiptError, match="catalog is unavailable"):
        parse_tls_receipt(load_cases()["hardened"])
