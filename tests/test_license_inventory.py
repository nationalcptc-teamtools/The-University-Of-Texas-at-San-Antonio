"""Offline tests for the fail-closed third-party source and license gate."""
from pathlib import Path
import json
import tomllib


ROOT = Path(__file__).parents[1]
INVENTORY = ROOT / "docs" / "harness" / "THIRD-PARTY-INVENTORY.json"
POLICY = ROOT / "docs" / "harness" / "THIRD-PARTY-LICENSES.md"


def _inventory():
    return json.loads(INVENTORY.read_text())


def test_inventory_schema_is_complete_and_has_no_unreviewed_copied_source():
    value = _inventory()
    assert set(value) == {
        "version", "classification", "reviewed_at", "reviewed_by",
        "copied_external_source_files", "components",
    }
    assert value["version"] == 1
    assert value["classification"] == "public-development-metadata"
    assert "human release-owner review required" in value["reviewed_by"]
    assert value["copied_external_source_files"] == []
    names = [component["name"] for component in value["components"]]
    assert len(names) == len(set(names))
    required = {
        "name", "version", "use", "source", "license", "license_source",
        "copied_files", "distributed", "obligations",
    }
    for component in value["components"]:
        assert set(component) == required
        assert component["source"].startswith("https://")
        assert component["license_source"].startswith("https://")
        assert component["license"] and component["version"] and component["use"]
        assert component["copied_files"] == []
        assert component["distributed"] is False
        assert component["obligations"]
        assert all(isinstance(item, str) and item for item in component["obligations"])


def test_every_declared_python_dependency_has_an_inventory_record_at_the_pinned_version():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    declared = list(project["build-system"]["requires"])
    declared.extend(project["project"]["dependencies"])
    for requirements in project["project"]["optional-dependencies"].values():
        declared.extend(requirements)
    expected_names = {
        "cryptography": "cryptography",
        "mcp": "Model Context Protocol Python SDK",
        "playwright": "Playwright Python",
        "pytest": "pytest",
        "setuptools": "setuptools",
        "tiktoken": "tiktoken",
        "wheel": "wheel",
    }
    components = {component["name"]: component for component in _inventory()["components"]}
    for requirement in declared:
        package_name, separator, version = requirement.partition("==")
        assert separator == "==", f"dependency is not exactly pinned: {requirement}"
        assert components[expected_names[package_name]]["version"] == version


def test_nxc_helper_is_project_authored_and_external_source_lists_remain_empty():
    assert (ROOT / "nxc-fix.sh").read_bytes() == (
        ROOT / "scripts" / "fix-nxc-bloodhound-config.sh"
    ).read_bytes()
    components = {component["name"]: component for component in _inventory()["components"]}
    assert components["NetExec"]["copied_files"] == []
    assert components["BloodHound.py"]["copied_files"] == []


def test_policy_fails_closed_for_unknown_or_unrecorded_licenses():
    policy = POLICY.read_text()
    assert "Unknown or missing licensing blocks an import" in policy
    assert "exact URL, immutable revision or release" in policy
    assert "must name each repository path in `copied_files`" in policy
    assert "must not enter the repository merely because it is publicly readable" in policy
