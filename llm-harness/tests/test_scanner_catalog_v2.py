from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from cptc_harness.contracts import PolicyError
from cptc_harness.scanner_catalog_v2 import (
    PROFILE_ID_V2,
    get_profile_v2,
    load_catalog_v2,
    verify_profile_runtime,
)


def test_v2_catalog_is_one_immutable_lab_candidate_with_exact_limits():
    catalog = load_catalog_v2()
    assert catalog.version == 2
    assert len(catalog.profiles) == 1
    profile = catalog.profiles[0]
    assert profile.profile_id == PROFILE_ID_V2 == "network.nse_smb2_security_mode"
    assert profile.mode == "lab_candidate"
    assert profile.dependency_closure_complete is False
    assert profile.allowed_options == ()
    assert tuple(getattr(profile.budget, name) for name in (
        "tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes",
        "timeout_s", "cpu_s", "output_bytes", "process_limit", "auth_attempts",
    )) == (2, 1, 2, 4096, 16384, 15.0, 10.0, 16384, 1, 0)
    assert profile.source.revision == "package:nmap-7.991-1.1"
    assert profile.source.sha256 == "184a49f77869088d10309ae5b4c37ffa7065b984436aae2aba77ba86d4d801ae"
    assert profile.command_template == (
        "/usr/bin/nmap", "-n", "-Pn", "-sT", "-p", "445", "--script",
        "/usr/share/nmap/scripts/smb2-security-mode.nse", "-oX", "-", "--",
        "{target_ipv4}",
    )
    dependency_paths = {item.path for item in profile.dependency_manifest}
    assert {
        "/usr/share/nmap/nselib/smb.lua",
        "/usr/share/nmap/nselib/smb2.lua",
        "/usr/share/nmap/nselib/stdnse.lua",
        "/usr/lib/libc.so.6",
        "/usr/lib/libpcap.so.1",
        "/usr/lib/liblua5.4.so.5.4",
        "/usr/lib64/ld-linux-x86-64.so.2",
    } <= dependency_paths
    assert len(dependency_paths) == 23
    with pytest.raises(FrozenInstanceError):
        profile.mode = "synthetic_only"


def test_v2_catalog_rejects_hash_drift_extra_profiles_and_unknown_ids(tmp_path):
    original = json.loads(load_catalog_v2().path.read_text())
    original["profiles"][0]["mode"] = "synthetic_only"
    path = tmp_path / "drift.json"
    path.write_text(json.dumps(original))
    with pytest.raises(PolicyError, match="hash"):
        load_catalog_v2(path)

    original = json.loads(load_catalog_v2().path.read_text())
    original["profiles"].append(original["profiles"][0])
    original["catalog_sha256"] = "0" * 64
    path.write_text(json.dumps(original))
    with pytest.raises(PolicyError):
        load_catalog_v2(path)

    for profile_id in ("*", "network.nse_*", "../smb2-security-mode.nse", "network.nse_smb2_time"):
        with pytest.raises(PolicyError):
            get_profile_v2(profile_id)


def test_runtime_verification_accepts_only_the_exact_profile_and_pin_mapping():
    profile = get_profile_v2(PROFILE_ID_V2)
    pins = dict(profile.runtime_pins)
    with pytest.raises(PolicyError, match="closure"):
        verify_profile_runtime(profile, pins)
    for bad in (
        {**pins, "nmap_version": "7.992"},
        {**pins, "extra": "value"},
        {key: value for key, value in pins.items() if key != "script_sha256"},
    ):
        with pytest.raises(PolicyError, match="pin"):
            verify_profile_runtime(profile, bad)
    with pytest.raises(PolicyError, match="profile"):
        verify_profile_runtime(replace(profile, mode="live_admitted"), pins)
