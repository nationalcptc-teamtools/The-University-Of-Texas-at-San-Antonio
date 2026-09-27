from dataclasses import FrozenInstanceError, replace
import hashlib
import json

import pytest

from cptc_harness.contracts import PolicyError, canonical_json
from cptc_harness.portcast_identity import (
    EXPECTED_PORTCAST_CATALOG_SHA256,
    PORTCAST_MODULE_ID,
    PORTCAST_PROFILE_ID,
    get_portcast_profile,
    load_portcast_profile_catalog,
)
from cptc_harness.profile_runtime.catalog import load_catalog
from cptc_harness.profile_runtime.contracts import ProfileContractError


def _rehash(value):
    value["catalog_sha256"] = hashlib.sha256(canonical_json({
        "schema_version": value["schema_version"], "profiles": value["profiles"],
    })).hexdigest()


def test_profile_is_one_hash_anchored_immutable_live_admitted_profile():
    catalog = load_portcast_profile_catalog()
    assert catalog.catalog_sha256 == EXPECTED_PORTCAST_CATALOG_SHA256
    assert len(catalog.profiles) == 1
    profile = catalog.profiles[0]
    assert profile.profile_id == PORTCAST_PROFILE_ID == "web.http_jellyfin_public_identity"
    assert profile.module_id == PORTCAST_MODULE_ID == "web.portcast_identity"
    operation = profile.operation
    assert (profile.admission, operation.address, operation.port) == ("live_admitted", "10.0.1.30", 8096)
    assert (operation.method, operation.path) == ("GET", "/System/Info/Public")
    assert operation.headers == (("Accept", "application/json"), ("Connection", "close"), ("Host", "10.0.1.30:8096"))
    assert profile.runtime_options == ()
    budget = profile.budget
    assert (budget.tcp_connects, budget.udp_datagrams, budget.protocol_requests,
            budget.tx_bytes, budget.rx_bytes, budget.timeout_s, budget.cpu_s,
            budget.capture_bytes, budget.process_limit, budget.auth_attempts) == (
                1, 0, 1, 256, 8192, 10.0, 5.0, 8192, 1, 0,
            )
    with pytest.raises(FrozenInstanceError):
        profile.admission = "live_admitted"


def test_profile_rejects_aliases_hash_drift_and_replacement(tmp_path):
    for profile_id in ("*", "web.http_*", "../identity", "web.portcast_identity"):
        with pytest.raises(PolicyError, match="unknown"):
            get_portcast_profile(profile_id)
    original = json.loads(load_portcast_profile_catalog().path.read_text())
    for index, change in enumerate((
        lambda row: row["profiles"][0].update({"admission": "lab_candidate"}),
        lambda row: row["profiles"][0]["budget"].update({"protocol_requests": 2}),
        lambda row: row["profiles"][0].update({"runtime_options": ["path"]}),
        lambda row: row["profiles"][0]["operation"]["headers"].append(["Authorization", "x"]),
    )):
        mutated = json.loads(json.dumps(original))
        change(mutated)
        _rehash(mutated)
        path = tmp_path / f"mutated-{index}.json"
        path.write_text(json.dumps(mutated))
        with pytest.raises(ProfileContractError, match="hash"):
            load_catalog(path)
    with pytest.raises(PolicyError, match="profile"):
        from cptc_harness.portcast_identity import validate_portcast_identity_response
        validate_portcast_identity_response(
            b"{}",
            profile=replace(
                get_portcast_profile(PORTCAST_PROFILE_ID).sealed,
                admission="lab_candidate",
            ),
            receipt={},
        )
