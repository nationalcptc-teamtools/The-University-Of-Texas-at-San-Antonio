"""Offline tests for the fail-closed third-party source and license gate."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import tomllib
import pytest


ROOT = Path(__file__).parents[1]
INVENTORY = ROOT / "docs" / "harness" / "THIRD-PARTY-INVENTORY.json"
POLICY = ROOT / "docs" / "harness" / "THIRD-PARTY-LICENSES.md"
_PACKAGE_SPEC = importlib.util.spec_from_file_location(
    "license_package_harness", ROOT / "scripts/package-harness.py"
)
package = importlib.util.module_from_spec(_PACKAGE_SPEC)
assert _PACKAGE_SPEC.loader is not None
_PACKAGE_SPEC.loader.exec_module(package)


def _inventory():
    return json.loads(INVENTORY.read_text())


def test_inventory_v2_schema_is_complete_and_owns_every_copied_file():
    value = _inventory()
    assert set(value) == {
        "version", "classification", "reviewed_at", "reviewed_by",
        "copied_external_source_files", "components",
    }
    assert value["version"] == 2
    assert value["classification"] == "public-development-metadata"
    assert value["reviewed_by"]
    copied = value["copied_external_source_files"]
    assert copied == sorted(set(copied))
    assert copied
    names = [component["name"] for component in value["components"]]
    assert len(names) == len(set(names))
    required = {
        "name", "version", "use", "source", "license", "license_source",
        "copied_files", "distributed", "obligations", "distribution_basis",
        "corresponding_source", "approved_source_origins",
    }
    for component in value["components"]:
        assert set(component) == required
        assert component["source"].startswith("https://")
        assert component["license_source"].startswith("https://")
        assert component["license"] and component["version"] and component["use"]
        if component["distributed"]:
            assert component["copied_files"]
            assert set(component["copied_files"]) <= set(copied)
        else:
            assert component["copied_files"] == []
        assert component["obligations"]
        assert all(isinstance(item, str) and item for item in component["obligations"])
        assert component["distribution_basis"] in {
            "permissive", "copyleft-source-required"
        }
        origins = component["approved_source_origins"]
        assert set(origins) == {"packaging", "upstream"}
        if not component["distributed"] or component["distribution_basis"] == "permissive":
            assert component["corresponding_source"] is None
            assert origins == {"packaging": [], "upstream": []}
        else:
            assert component["corresponding_source"]
            assert origins["packaging"] and origins["upstream"]


def test_sealed_portcast_runtime_matches_the_reviewed_copied_file_inventory():
    value = _inventory()
    recorded = set(value["copied_external_source_files"])
    runtimes = (
        ROOT / "vendor/portcast-python3.14/site-packages",
        ROOT / "vendor/portcast-rootfs-runtime",
    )
    physical = {
        path.relative_to(ROOT).as_posix()
        for runtime in runtimes
        for path in runtime.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    assert physical == recorded
    assert not any(
        path.is_symlink() for runtime in runtimes for path in runtime.rglob("*")
    )
    distributed = {
        path
        for component in value["components"]
        if component["distributed"]
        for path in component["copied_files"]
    }
    assert distributed == recorded


def test_retained_license_and_provenance_notices_have_component_owners():
    value = _inventory()
    owners = {
        path: component["name"]
        for component in value["components"]
        for path in component["copied_files"]
    }
    runtimes = (
        ROOT / "vendor/portcast-python3.14/site-packages",
        ROOT / "vendor/portcast-rootfs-runtime",
    )
    notices = {
        path.relative_to(ROOT).as_posix()
        for runtime in runtimes
        for path in runtime.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and ("/share/licenses/" in path.as_posix() or ".dist-info/licenses/" in path.as_posix())
    }
    assert notices
    assert notices <= set(owners)
    assert all(owners[path] for path in notices)


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
        "paramiko": "paramiko",
        "cffi": "cffi",
        "pycparser": "pycparser",
        "bcrypt": "bcrypt",
        "PyNaCl": "PyNaCl",
        "invoke": "invoke",
        "fluidity-sm": "fluidity-sm",
        "lexicon": "lexicon",
        "PyYAML": "PyYAML",
    }
    components = {component["name"]: component for component in _inventory()["components"]}
    for requirement in declared:
        package_name, separator, version = requirement.partition("==")
        assert separator == "==", f"dependency is not exactly pinned: {requirement}"
        assert components[expected_names[package_name]]["version"] == version


def test_policy_fails_closed_for_unknown_or_unrecorded_licenses():
    policy = POLICY.read_text()
    assert "Unknown or missing licensing blocks an import" in policy
    assert "exact URL, immutable revision or release" in policy
    assert "must name each repository path in `copied_files`" in policy
    assert "must not enter the repository merely because it is publicly readable" in policy


def test_retained_corresponding_source_files_are_source_only():
    contents = package.reviewed_contents(ROOT)
    retained = {
        path
        for component in _inventory()["components"]
        if component["distributed"] and component["distribution_basis"] == "copyleft-source-required"
        for path in (
            component["corresponding_source"]["archive"],
            component["corresponding_source"]["metadata_path"],
        )
    }
    assert retained
    assert retained <= contents["source"]
    assert retained.isdisjoint(contents["runtime"])


def test_private_packaging_accepts_completed_v2_copyleft_source():
    compliance = package.verify_third_party_compliance(ROOT)
    assert compliance["verified"] is True
    assert {item["component"] for item in compliance["source_archives"]} == {
        "Arch runtime package: glibc",
        "Arch runtime package: libgcc",
        "bubblewrap",
        "paramiko",
    }


def _synthetic_legacy_inventory(source):
    component = copy.deepcopy(_inventory()["components"][0])
    component.update(
        distributed=True,
        distribution_basis="copyleft-source-required",
        corresponding_source=source,
    )
    return {"version": 1, "components": [component]}


def test_copyleft_gate_rejects_legacy_exact_archive_descriptor(tmp_path):
    archive = tmp_path / "vendor/corresponding-source/component.tar.gz"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"synthetic corresponding source")
    with pytest.raises(ValueError, match="version 2"):
        package.verify_third_party_compliance(
            tmp_path,
            _synthetic_legacy_inventory({"kind": "exact_archive", "path": str(archive), "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}),
        )


def test_copyleft_gate_rejects_legacy_written_offer(tmp_path):
    notice = tmp_path / "docs/harness/component-source-offer.md"
    notice.parent.mkdir(parents=True)
    notice.write_text("Synthetic immutable source offer.\n")
    source = {
        "kind": "immutable_verified_offer",
        "url": "https://example.invalid/source/component/0123456789abcdef",
        "revision": "0123456789abcdef",
        "notice_path": "docs/harness/component-source-offer.md",
        "notice_sha256": hashlib.sha256(notice.read_bytes()).hexdigest(),
        "verified_at": "2026-09-10T00:00:00Z",
    }
    with pytest.raises(ValueError, match="version 2"):
        package.verify_third_party_compliance(tmp_path, _synthetic_legacy_inventory(source))
