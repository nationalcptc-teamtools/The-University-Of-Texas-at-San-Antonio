"""Synthetic packaging boundaries: no private source or benchmark content."""
import importlib.util
import io
from pathlib import Path
import subprocess
import stat
import sys
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("package_harness", ROOT / "scripts/package-harness.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def _vendor_module(name):
    vendor_spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts/portcast_vendor_inputs.py"
    )
    vendor = importlib.util.module_from_spec(vendor_spec)
    assert vendor_spec.loader is not None
    sys.modules[name] = vendor
    vendor_spec.loader.exec_module(vendor)
    return vendor


@pytest.mark.parametrize("name", [
    "docs/engagements/capture.json", "scripts/private/item.txt", "skills/raw/output.log",
    "cptc_harness/resources/expected-answer.json", "cptc_harness/nested/tests/fixture.py",
])
def test_unreviewed_private_or_test_input_refused_before_build(tmp_path, name):
    source = tmp_path / name
    source.parent.mkdir(parents=True); source.write_text("synthetic only")
    with pytest.raises(ValueError, match="unreviewed distribution input"):
        package.verify_source_inputs(tmp_path, {"source": set()}, [name])


@pytest.mark.parametrize("name", [
    "cptc_harness/resources/expected-answer.json", "cptc_harness/nested/tests/fixture.py",
])
def test_nested_runtime_data_is_not_allowed_by_prefix(name):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as writer:
        writer.writestr(name, b"synthetic benchmark")
    with zipfile.ZipFile(data) as wheel, pytest.raises(ValueError, match="file allowlist"):
        package.verify_wheel(wheel, {"runtime": set()}, "0.1.0a5")


def test_runtime_wheel_rejects_symlink_entries_even_with_exact_allowlist():
    version = "0.1.0a5"
    runtime_name = "cptc_harness/runtime.py"
    expected = {runtime_name} | {
        f"cptc_guarded_harness-{version}.dist-info/{name}"
        for name in package.WHEEL_METADATA
    }
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as writer:
        for name in sorted(expected):
            if name == runtime_name:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                writer.writestr(info, "../../private")
            else:
                writer.writestr(name, b"synthetic")
    with zipfile.ZipFile(data) as wheel, pytest.raises(ValueError, match="file allowlist"):
        package.verify_wheel(wheel, {"runtime": {runtime_name}}, version)


def test_unreviewed_source_archive_member_rejected(tmp_path):
    path = tmp_path / "source.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        entry = tarfile.TarInfo("cptc_guarded_harness-0.1.0a5/docs/engagements/raw.json")
        entry.size = 2; archive.addfile(entry, io.BytesIO(b"{}"))
    with pytest.raises(ValueError, match="unreviewed source"):
        package.normalize_source(path, 1788839662, {"source": set()}, "0.1.0a5")


def test_reviewed_file_symlink_cannot_read_other_data(tmp_path):
    actual = tmp_path / "private.txt"; actual.write_text("synthetic")
    (tmp_path / "docs").mkdir(); (tmp_path / "docs/public.txt").symlink_to(actual)
    with pytest.raises(ValueError, match="symlinked"):
        package.verify_source_inputs(tmp_path, {"source": {"docs/public.txt"}}, ["docs/public.txt"])


def test_reviewed_checkout_inputs_are_complete_and_ai_only():
    contents = package.reviewed_contents(ROOT)
    package.verify_source_inputs(ROOT, contents, contents["source"])
    package.verify_source_inputs(ROOT, contents, package.physical_distribution_inputs(ROOT))
    assert set(contents) == {"version", "classification", "runtime", "source"}
    assert {
        ".gitleaks.toml", "MANIFEST.in", "README.md", "pyproject.toml"
    } <= contents["source"]
    assert "docs/harness/LIVE-TOOLING-CONTINUATION.md" in contents["source"]
    assert "cptc_harness/resources/zap-passive.yaml" in contents["runtime"]
    assert "cptc_harness/resources/scanner-profiles-v1.json" in contents["runtime"]
    assert "cptc_harness/resources/scanner-profiles-v2.json" in contents["runtime"]
    assert "cptc_harness/resources/host-profiles-v1.json" in contents["runtime"]
    assert "cptc_harness/resources/bounded-profiles-v1.json" in contents["runtime"]
    assert "cptc_harness/profile_runtime/catalog.py" in contents["runtime"]
    assert "cptc_harness/profile_runtime/service_client.py" in contents["runtime"]
    assert "cptc_harness/audit_readonly.py" in contents["runtime"]
    assert "cptc_harness/profiles/common_mysql/catalog.json" in contents["runtime"]
    assert "cptc_harness/profiles/common_tls/catalog.json" in contents["runtime"]
    assert "cptc_harness/host_profile_catalog.py" in contents["runtime"]
    assert "cptc_harness/scanner_catalog.py" in contents["runtime"]
    assert "cptc_harness/scanner_catalog_v2.py" in contents["runtime"]
    assert "cptc_harness/scanner_results.py" in contents["runtime"]
    assert "testing/cptc11_lab/transport.py" in contents["source"]
    assert "testing/cptc11_lab/portcast_service.py" in contents["source"]
    assert "testing/cptc11_lab/portcast-live-plan-v2.json" in contents["source"]
    assert "testing/cptc11_lab/portcast-live-plan-v3.json" in contents["source"]
    assert "testing/cptc11_lab/portcast-live-plan-v4.json" in contents["source"]
    assert "testing/cptc11_lab/portcast-live-plan-v5.json" in contents["source"]
    assert "testing/cptc11_lab/portcast-live-plan-v6.json" in contents["source"]
    assert "testing/cptc11_lab/portcast-live-plan-v7.json" in contents["source"]
    assert "tests/test_portcast_v5_runtime.py" in contents["source"]
    assert "tests/test_portcast_v6_runtime.py" in contents["source"]
    assert "tests/test_portcast_v7_runtime.py" in contents["source"]
    assert "deployment/portcast-live-v1.service" in contents["source"]
    assert "deployment/portcast-live-v1-acceptance@.service" in contents["source"]
    assert "deployment/portcast-live-v1.sysusers" in contents["source"]
    assert "deployment/portcast-systemd-acceptance.py" in contents["source"]
    assert "deployment/manage-portcast-service.py" in contents["source"]
    assert "testing/cptc11_lab/portcast_acceptance.py" in contents["source"]
    assert "tests/profile_runtime/test_portcast_acceptance.py" in contents["source"]
    assert "scripts/vendor-portcast-runtime.py" in contents["source"]
    assert "cptc_harness/resources/portcast-python-runtime-v1.json" in contents["runtime"]
    vendor_files = {
        name
        for name in contents["source"]
        if name.startswith("vendor/portcast-python3.14/site-packages/")
    }
    assert vendor_files
    assert not vendor_files & contents["runtime"]
    assert "recursive-include vendor/portcast-python3.14/site-packages *" in (
        ROOT / "MANIFEST.in"
    ).read_text()
    source_manifest = (ROOT / "MANIFEST.in").read_text()
    assert "include README.md pyproject.toml MANIFEST.in .gitattributes .gitleaks.toml" in source_manifest
    assert "recursive-include deployment *" in source_manifest
    assert "recursive-include docs/harness/portcast-vendor-inputs/files *" in source_manifest
    assert "recursive-include cptc11_readonly_wave_v1 *.py *.json" in source_manifest
    assert "include cptc_harness/resources/portcast-bootstrap-v1.sha256" in source_manifest
    assert "include cptc_harness/resources/portcast-cpython-runtime-v1.json" in source_manifest
    assert (
        "include testing/cptc11_lab/README.md "
        "testing/cptc11_lab/portcast-live-plan-v1.json "
        "testing/cptc11_lab/portcast-live-plan-v2.json"
        " testing/cptc11_lab/portcast-live-plan-v3.json"
        " testing/cptc11_lab/portcast-live-plan-v4.json"
        " testing/cptc11_lab/portcast-live-plan-v5.json"
        " testing/cptc11_lab/portcast-live-plan-v6.json"
        " testing/cptc11_lab/portcast-live-plan-v7.json"
    ) in source_manifest
    attributes = (ROOT / ".gitattributes").read_text()
    assert "vendor/** -text -whitespace" in attributes
    assert "deployment/portcast-bootstrap -text" in attributes
    assert "docs/harness/portcast-vendor-inputs/files/** -text -whitespace" in attributes
    assert "docs/harness/PORTCAST-SERVICE-DEPLOYMENT.md" in contents["source"]
    assert "tests/profile_runtime/test_portcast_service.py" in contents["source"]
    forbidden_benchmark = {
        "testing/benchmark.py",
        "scripts/benchmark-harness.py",
        "docs/harness/TOKEN-BENCHMARK.json",
        "docs/harness/CPTC11-IMAGE-AUDIT.md",
        "testing/cptc11_benchmark/README.md",
        "testing/cptc11_benchmark/__init__.py",
        "testing/cptc11_benchmark/__main__.py",
        "testing/cptc11_benchmark/http_source.py",
        "testing/cptc11_benchmark/qcow.py",
        "testing/cptc11_benchmark/source_allowlist.py",
        "testing/cptc11_benchmark/staging.py",
    }
    assert not forbidden_benchmark & contents["source"]
    assert not forbidden_benchmark & contents["runtime"]
    assert "tests/test_cptc11_lab_transport.py" in contents["source"]
    assert "tests/test_scanner_catalog_v2.py" in contents["source"]
    assert "tests/test_scanner_results.py" in contents["source"]
    assert "tests/test_scanner_catalog.py" in contents["source"]
    assert "tests/fixtures/scanner/relay/README.md" in contents["source"]
    assert "tests/fixtures/scanner/relay/nmap-7.991-nbstat-wildcard.bin" in contents["source"]
    assert "tests/fixtures/scanner/relay/nmap-7.991-smb2-negotiate.bin" in contents["source"]
    assert "tests/test_scanner_catalog.py" not in contents["runtime"]
    readonly_wave_source = {
        str(path.relative_to(ROOT))
        for base in (ROOT / "cptc11_readonly_wave_v1", ROOT / "tests/readonly_wave_v1")
        for path in base.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    assert readonly_wave_source
    assert readonly_wave_source <= contents["source"]
    assert not readonly_wave_source & contents["runtime"]
    assert "cptc11_readonly_wave_v1" in package.BUILD_ROOTS
    assert all(not name.startswith("human/") for name in contents["source"])
    assert "cptc_harness/human.py" not in contents["runtime"]
    assert not contents["runtime"] & {name for name in contents["source"] if name.startswith("tests/")}


def test_installed_wheel_layout_loads_packaged_scanner_catalog(tmp_path):
    contents = package.reviewed_contents(ROOT)
    wheel_path = tmp_path / "reviewed-runtime.whl"
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        for name in sorted(contents["runtime"]):
            wheel.write(ROOT / name, name)
    package.verify_installed_scanner_catalog(wheel_path)


def test_installed_wheel_smoke_requires_the_v2_scanner_catalog(tmp_path):
    contents = package.reviewed_contents(ROOT)
    wheel_path = tmp_path / "missing-v2-runtime.whl"
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        for name in sorted(contents["runtime"] - {"cptc_harness/resources/scanner-profiles-v2.json"}):
            wheel.write(ROOT / name, name)

    with pytest.raises(ValueError, match="scanner catalog"):
        package.verify_installed_scanner_catalog(wheel_path)


def test_installed_wheel_smoke_requires_the_blocked_host_catalog(tmp_path):
    contents = package.reviewed_contents(ROOT)
    wheel_path = tmp_path / "missing-host-runtime.whl"
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        for name in sorted(contents["runtime"] - {"cptc_harness/resources/host-profiles-v1.json"}):
            wheel.write(ROOT / name, name)

    with pytest.raises(ValueError, match="scanner catalog"):
        package.verify_installed_scanner_catalog(wheel_path)


@pytest.mark.parametrize("missing", [
    "cptc_harness/resources/bounded-profiles-v1.json",
    "cptc_harness/profiles/common_mysql/catalog.json",
    "cptc_harness/profiles/common_tls/catalog.json",
])
def test_installed_wheel_smoke_requires_each_bounded_runtime_catalog(tmp_path, missing):
    contents = package.reviewed_contents(ROOT)
    wheel_path = tmp_path / "missing-bounded-runtime.whl"
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        for name in sorted(contents["runtime"] - {missing}):
            wheel.write(ROOT / name, name)

    with pytest.raises(ValueError, match="scanner catalog"):
        package.verify_installed_scanner_catalog(wheel_path)


def test_tar_normalization_is_independent_of_input_order():
    a = [("b.txt", b"two", False), ("a.txt", b"one", True)]
    assert package.tar_bytes(a, 1788839662) == package.tar_bytes(list(reversed(a)), 1788839662)


def test_physical_input_listing_rejects_ignored_unreviewed_recursive_member(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / ".gitignore").write_text("ignored.json\n")
    (tmp_path / "tests" / "ignored.json").write_text("synthetic")
    paths = package.physical_distribution_inputs(tmp_path)
    assert "tests/ignored.json" in paths
    with pytest.raises(ValueError, match="unreviewed distribution input"):
        package.verify_source_inputs(tmp_path, {"source": set()}, paths)


def test_portcast_vendor_manifest_binds_current_locks_and_inventory():
    vendor = _vendor_module("portcast_vendor_manifest_binding")
    manifest = vendor._load_json(vendor.MANIFEST)

    assert manifest["schema_version"] == 1
    assert len(manifest["archives"]) == 29
    assert len(manifest["source_files"]) == 9
    for path in (vendor.ROOTFS_LOCK, vendor.PYTHON_LOCK):
        relative = str(path.relative_to(ROOT))
        assert manifest["runtime_locks"][relative] == vendor._sha256_file(path)
    assert manifest["inventory"]["sha256"] == vendor._sha256_file(vendor.INVENTORY)


def test_package_gate_accepts_completed_v2_full_compliance():
    compliance = package.verify_third_party_compliance(ROOT)
    assert compliance["verified"] is True
    assert len(compliance["source_archives"]) == 4


def test_receipt_name_is_version_derived_and_safe():
    assert package.receipt_name("0.1.0a5") == "BUILD-RECEIPT-0.1.0a5.json"
    assert package.receipt_name("release/one") == "BUILD-RECEIPT-release-one.json"


def test_portcast_materializer_removes_a_partial_new_output(tmp_path, monkeypatch):
    vendor = _vendor_module("portcast_vendor_materialize_cleanup")
    output = tmp_path / "review-tree"
    plan = vendor.RuntimePlan(
        {"vendor/example": vendor.PlannedFile("vendor/example", b"data", 0o444, "synthetic")},
        "0" * 64,
        (),
    )
    monkeypatch.setattr(vendor.os, "write", lambda *_args: (_ for _ in ()).throw(OSError("disk full")))

    with pytest.raises(OSError, match="disk full"):
        vendor.materialize(plan, output)

    assert not output.exists()


def test_portcast_materializer_never_writes_inside_the_repository():
    vendor = _vendor_module("portcast_vendor_repository_boundary")
    output = ROOT / "unreviewed-portcast-output"
    plan = vendor.RuntimePlan({}, "0" * 64, ())

    with pytest.raises(vendor.VendorInputError, match="outside the repository"):
        vendor.materialize(plan, output)

    assert not output.exists()
