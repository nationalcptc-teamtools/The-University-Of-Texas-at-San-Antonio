"""Standalone human CLI tests use only synthetic owner-controlled inputs."""

import builtins
import base64
import json
import os
from pathlib import Path
import subprocess

import pytest

from cptc_harness.contracts import PolicySnapshot, ScopeSpec
from cptc_harness.human import main
from cptc_harness.parsers import parse_linux_output, parse_network_output, parse_nmap_xml, parse_windows_ad_output
from cptc_harness.policy import save_policy


ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize("status", ["blocked", "failed", "stopped", "uncertain"])
def test_operator_failure_is_nonzero_and_preserves_result(monkeypatch, capsys, tmp_path, status):
    import cptc_harness.human as human
    monkeypatch.setattr(human, "_execute", lambda _: {"result": {"status": status, "reason": "synthetic limitation"}})
    assert main(["run", "web.headers", "--workspace", str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out)["result"]["status"] == status


@pytest.mark.parametrize("valid", [False, None])
def test_unverified_audit_is_nonzero(monkeypatch, tmp_path, valid):
    import cptc_harness.human as human
    monkeypatch.setattr(human, "_execute", lambda _: {"valid": valid})
    assert main(["audit-verify", "--workspace", str(tmp_path)]) == 2


def _age_identity(tmp_path: Path) -> tuple[Path, str]:
    key_path = tmp_path / "synthetic-age-key"
    result = subprocess.run([str(ROOT / ".tools" / "age-keygen"), "-o", str(key_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    del result
    recipient = next(line.split(":", 1)[1].strip() for line in key_path.read_text().splitlines()
                     if line.startswith("# public key:"))
    return ROOT / ".tools" / "age", recipient


def _policy(path: Path) -> None:
    policy = PolicySnapshot(
        "human-fixture", "v1", "workspace", "device", "operator",
        ScopeSpec(("192.0.2.0/24",), (), ("ad.example.test",)),
        window_start="2025-01-01T00:00:00Z", window_end="2030-01-01T00:00:00Z",
    )
    save_policy(path, policy)


def test_help_modules_and_preflight_do_not_import_optional_ai_modules(monkeypatch, capsys):
    original_import = builtins.__import__
    blocked = {"cptc_harness.providers", "cptc_harness.orchestrator", "cptc_harness.mcp_server"}

    def guarded_import(name, *args, **kwargs):
        if name in blocked:
            raise AssertionError(f"optional AI module imported: {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    assert main(["--help"]) == 0
    assert main(["modules"]) == 0
    assert main(["preflight"]) == 0
    output = capsys.readouterr().out
    assert "network.output_import" in output and "availability is separate" in output


def test_preflight_hashes_binaries_without_executing_discovered_wrappers(monkeypatch, tmp_path):
    marker = tmp_path / "executed"
    fake = tmp_path / "nmap"
    fake.write_text(f"#!/bin/sh\nprintf touched > {marker}\n")
    fake.chmod(0o700)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    import cptc_harness.human as human
    result = human._preflight(None, None)
    nmap = next(item for item in result["binaries"] if item["name"] == "nmap")
    assert nmap["path"] == str(fake) and nmap["pinned"] is False
    assert not marker.exists()


def test_module_catalog_requires_all_profile_pins_and_never_admits_active_aliases(monkeypatch):
    import cptc_harness.human as human
    catalog = [
        {"tool_id": "nmap", "profiles": ["network.nmap_inventory"], "available": True,
         "pinned": True, "admitted": True},
        {"tool_id": "nmap-shim", "profiles": ["network.nmap_inventory"], "available": True,
         "pinned": False, "admitted": False},
        {"tool_id": "nuclei", "profiles": ["web.nuclei_observation"], "available": True,
         "pinned": True, "admitted": True},
    ]
    monkeypatch.setattr(human, "_catalog_status", lambda: catalog)
    rows = {row["module_id"]: row["catalog"] for row in human._modules()}
    assert rows["network.nmap_inventory"]["status"] == "available"
    assert rows["network.nmap_inventory"]["admitted"] is False
    assert rows["network.nmap_inventory"]["pinned"] is False
    assert rows["web.nuclei_observation"]["admitted"] is True
    assert rows["web.nuclei"]["admitted"] is False
    assert rows["exploitation.zerologon"]["status"] == "manual_only"
    catalog.pop(1)  # A missing dependency must also fail, not just a changed pin.
    rows = {row["module_id"]: row["catalog"] for row in human._modules()}
    assert rows["network.nmap_inventory"]["admitted"] is False
    assert rows["network.nmap_inventory"]["pinned"] is False
    catalog.append(catalog[-1].copy())
    rows = {row["module_id"]: row["catalog"] for row in human._modules()}
    assert rows["web.nuclei_observation"]["admitted"] is False


def test_import_rejects_bounded_and_manual_modules_before_runtime(monkeypatch, tmp_path):
    import cptc_harness.human as human

    monkeypatch.setattr(human, "_runtime", lambda _: (_ for _ in ()).throw(AssertionError("runtime opened")))
    input_path = tmp_path / "input.json"
    input_path.write_text("{}")
    input_path.chmod(0o600)
    for module in ("linux.inventory", "exploitation.dos"):
        assert main(["--workspace", str(tmp_path), "import", module, "--input", str(input_path)]) == 2


def test_profiles_are_declarative_and_examples_are_parser_inputs():
    profile_dir = ROOT / "human" / "profiles"
    nmap = json.loads((profile_dir / "nmap-connect.json").read_text())
    nuclei = json.loads((profile_dir / "nuclei-passive.json").read_text())
    zap = json.loads((profile_dir / "zap-passive.json").read_text())
    assert "--script" in nmap["forbidden"] and nmap["execution"].startswith("human")
    assert nuclei["network"] == "none" and zap["network"] == "none"
    assert json.loads((ROOT / "human/examples/controlled-account.json").read_text())["records"][0]["kind"] == "controlled_account"
    scope = ScopeSpec(("192.0.2.0/24",), (), ("ad.example.test",))
    assert parse_network_output((ROOT / "human/examples/network-inventory.json").read_bytes(), "synthetic", scope).observations
    assert parse_nmap_xml((ROOT / "human/examples/nmap-inventory.xml").read_bytes(), "synthetic", scope).observations
    assert parse_linux_output((ROOT / "human/examples/linux-vulnerable.json").read_bytes(), "synthetic", scope).observations
    windows = parse_windows_ad_output((ROOT / "human/examples/windows-inventory.json").read_bytes(), "synthetic", scope)
    account = parse_windows_ad_output((ROOT / "human/examples/controlled-account.json").read_bytes(), "synthetic", scope)
    assert windows.observations and any(item.check_id == "windows_controlled_account" for item in account.observations)
    assert any(item.check_id == "windows_service_acl" and item.state == "candidate" for item in windows.observations)
    response = base64.b64decode(json.loads((ROOT / "human/examples/web-passive-observation.json").read_text())["response_base64"])
    assert response.startswith(b"HTTP/1.1") and b"\r\n\r\n" in response


def test_human_command_lifecycle_uses_synthetic_offline_import(tmp_path, monkeypatch, capsys):
    tmp_path.chmod(0o700)
    age_binary, recipient = _age_identity(tmp_path)
    policy_path = tmp_path / "policy.json"
    _policy(policy_path)
    workspace = tmp_path / "engagement"
    assert main(["init", str(workspace), "--policy", str(policy_path), "--recipient", recipient,
                 "--age", str(age_binary)]) == 0

    import cptc_harness.runtime as runtime_module
    monkeypatch.setattr(runtime_module, "device_root", lambda: tmp_path / "device-ledger")
    source = tmp_path / "network.json"
    source.write_text((ROOT / "human/examples/network-inventory.json").read_text())
    source.chmod(0o600)
    assert main(["import", "network.output_import", "--input", str(source), "--workspace", str(workspace)]) == 0
    assert main(["coverage", "--workspace", str(workspace)]) == 0
    assert main(["report", "--workspace", str(workspace)]) == 0
    assert main(["audit-verify", "--workspace", str(workspace)]) == 0
    assert (workspace / "reports" / "observations.json").is_file()
    assert main(["stop", "--workspace", str(workspace), "--reason", "synthetic review complete"]) == 0
    assert "synthetic review complete" in capsys.readouterr().out
