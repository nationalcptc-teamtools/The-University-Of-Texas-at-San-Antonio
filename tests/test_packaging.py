"""Synthetic packaging boundaries: no private source or benchmark content."""
import importlib.util
import io
from pathlib import Path
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("package_harness", ROOT / "scripts/package-harness.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


@pytest.mark.parametrize("name", [
    "human/evidence/capture.json", "human/credentials/item.txt", "skills/raw/output.log",
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
        package.verify_wheel(wheel, {"runtime": set()}, "0.1.0a4")


def test_unreviewed_source_archive_member_rejected(tmp_path):
    path = tmp_path / "source.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        entry = tarfile.TarInfo("cptc_guarded_harness-0.1.0a4/human/evidence/raw.json")
        entry.size = 2; archive.addfile(entry, io.BytesIO(b"{}"))
    with pytest.raises(ValueError, match="unreviewed source"):
        package.normalize_source(path, 1788839662, {"source": set()}, "0.1.0a4")


def test_reviewed_file_symlink_cannot_read_other_data(tmp_path):
    actual = tmp_path / "private.txt"; actual.write_text("synthetic")
    (tmp_path / "human").mkdir(); (tmp_path / "human/public.txt").symlink_to(actual)
    with pytest.raises(ValueError, match="symlinked"):
        package.verify_source_inputs(tmp_path, {"source": {"human/public.txt"}}, ["human/public.txt"])


def test_reviewed_checkout_inputs_and_human_dependencies_are_complete():
    contents = package.reviewed_contents(ROOT)
    package.verify_source_inputs(ROOT, contents, contents["source"])
    package.verify_source_inputs(ROOT, contents, package.physical_distribution_inputs(ROOT))
    assert "human/runbooks/without-harness.md" in contents["human"]
    assert "docs/harness/LIVE-TOOLING-CONTINUATION.md" in contents["human"]
    assert "docs/harness/THIRD-PARTY-INVENTORY.json" in contents["human"]
    assert "docs/harness/THIRD-PARTY-LICENSES.md" in contents["human"]
    assert "cptc_harness/resources/zap-passive.yaml" in contents["human"]
    assert "nxc-fix.sh" in contents["human"]
    assert not contents["runtime"] & {name for name in contents["source"] if name.startswith(("tests/", "human/"))}


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
