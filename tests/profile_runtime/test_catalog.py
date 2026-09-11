from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path

import pytest

from cptc_harness.profile_runtime.catalog import (
    PROFILE_CATALOG_SHA256,
    SealedProfile,
    load_catalog,
    load_profile,
    validate_sealed_profile,
)
from cptc_harness.profile_runtime.contracts import Http11RequestV1, ProfileContractError


def test_builtin_catalog_returns_only_the_exact_live_admitted_portcast_profile():
    catalog = load_catalog()
    assert catalog.catalog_sha256 == PROFILE_CATALOG_SHA256
    assert tuple(profile.profile_id for profile in catalog.profiles) == (
        "web.http_jellyfin_public_identity",
    )
    profile = load_profile("web.http_jellyfin_public_identity")
    assert isinstance(profile, SealedProfile)
    assert isinstance(profile.operation, Http11RequestV1)
    assert profile.operation.address == "10.0.1.30"
    assert profile.operation.port == 8096
    assert profile.operation.method == "GET"
    assert profile.operation.path == "/System/Info/Public"
    assert profile.admission == "live_admitted"
    assert profile.runtime_options == ()
    assert validate_sealed_profile(profile) is profile
    with pytest.raises(FrozenInstanceError):
        profile.admission = "live_admitted"


@pytest.mark.parametrize(
    "profile_id",
    ("*", "web.*", "../profile", "web.http_jellyfin_public_identity/extra", ""),
)
def test_profile_lookup_rejects_alias_wildcard_and_path_forms(profile_id):
    with pytest.raises(ProfileContractError, match="unknown profile"):
        load_profile(profile_id)


def test_validation_rejects_constructed_replaced_and_forged_profiles():
    legitimate = load_profile("web.http_jellyfin_public_identity")
    with pytest.raises(ProfileContractError):
        validate_sealed_profile(replace(legitimate, admission="live_admitted"))
    with pytest.raises(ProfileContractError):
        validate_sealed_profile(object.__new__(SealedProfile))
    with pytest.raises(ProfileContractError):
        validate_sealed_profile({"profile_id": legitimate.profile_id})


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("profile_id", "other"),
        ("module_id", "web.other"),
        ("target_id", "other-target"),
        ("admission", "lab_candidate"),
        ("parser_id", "other.parser"),
        ("runtime_options", ["--proxy", "http://127.0.0.1:8080"]),
        ("limitations", []),
        ("operation", {"kind": "redis_ping_v1", "address": "10.0.1.30", "port": 8096}),
        ("extra", True),
    ),
)
def test_any_profile_edit_is_rejected_by_hash_anchor(tmp_path, field, replacement):
    source = Path(__file__).parents[2] / "cptc_harness/resources/bounded-profiles-v1.json"
    value = json.loads(source.read_text())
    value["profiles"][0][field] = replacement
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ProfileContractError):
        load_catalog(path)


def test_catalog_rejects_symlinks_duplicate_json_keys_and_unknown_envelope_fields(tmp_path):
    source = Path(__file__).parents[2] / "cptc_harness/resources/bounded-profiles-v1.json"
    link = tmp_path / "catalog-link.json"
    link.symlink_to(source)
    with pytest.raises(ProfileContractError):
        load_catalog(link)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1,"catalog_sha256":"x","profiles":[]}')
    with pytest.raises(ProfileContractError):
        load_catalog(duplicate)

    value = json.loads(source.read_text())
    value["comment"] = "not admitted"
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(value))
    with pytest.raises(ProfileContractError):
        load_catalog(changed)
