#!/usr/bin/env python3
"""Build private deterministic evaluation artifacts locally, without downloads.

Run with the pinned build environment. This does not admit profiles or publish
anything. Source/test/live acceptance is recorded separately from packaging.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path("docs/harness/PACKAGE-CONTENTS.json")
BUILD_ROOTS = {"cptc_harness", "human", "skills", "docs", "scripts", "testing", "tests"}
EXCLUDED_BUILD_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache"}
GENERATED_SOURCE = {"PKG-INFO", "setup.cfg", *(
    "cptc_guarded_harness.egg-info/" + name for name in (
        "PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "requires.txt", "top_level.txt"))}
WHEEL_METADATA = {"METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD"}


def reviewed_contents(root):
    value = json.loads((root / MANIFEST).read_text())
    if set(value) != {"version", "classification", "runtime", "source", "human"} or value["version"] != 1:
        raise ValueError("invalid reviewed package manifest")
    for group in ("runtime", "source", "human"):
        entries = value[group]
        if not isinstance(entries, list) or len(entries) != len(set(entries)):
            raise ValueError("invalid reviewed package file list")
        for name in entries:
            path = Path(name)
            if not isinstance(name, str) or path.is_absolute() or ".." in path.parts or str(path) != name:
                raise ValueError("invalid reviewed package path")
        value[group] = set(entries)
    if not value["runtime"] <= value["source"] or not value["human"] <= value["source"]:
        raise ValueError("reviewed distribution inputs missing from source list")
    return value


def verify_source_inputs(root, contents, paths):
    """Fail before a build on unreviewed files in any distribution subtree."""
    for name in paths:
        relative = Path(name)
        if relative.parts[0] in BUILD_ROOTS and name not in contents["source"]:
            raise ValueError("unreviewed distribution input; update the file manifest only after review")
    for name in contents["source"]:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("missing or symlinked reviewed distribution input")
        if any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents):
            raise ValueError("symlinked distribution parent")


def physical_distribution_inputs(root):
    """List physical recursive-manifest inputs, including Git-ignored files."""
    names = []
    for root_name in sorted(BUILD_ROOTS):
        base = root / root_name
        if base.is_symlink():
            names.append(root_name)
            continue
        if not base.is_dir():
            continue
        for directory, dirnames, filenames in os.walk(base, followlinks=False):
            directory_path = Path(directory)
            for child in tuple(dirnames):
                candidate = directory_path / child
                if child in EXCLUDED_BUILD_PARTS:
                    dirnames.remove(child)
                elif candidate.is_symlink():
                    names.append(str(candidate.relative_to(root)))
                    dirnames.remove(child)
            for filename in filenames:
                if filename == ".DS_Store" or filename.endswith((".pyc", ".pyo", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm")):
                    continue
                names.append(str((directory_path / filename).relative_to(root)))
    return names


def verify_wheel(wheel, contents, version):
    expected = contents["runtime"] | {f"cptc_guarded_harness-{version}.dist-info/{name}" for name in WHEEL_METADATA}
    names = wheel.namelist()
    if len(names) != len(set(names)) or set(names) != expected or wheel.testzip() is not None:
        raise ValueError("runtime wheel differs from reviewed file allowlist")


def tar_bytes(entries, epoch):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, payload, executable in sorted(entries):
            member = tarfile.TarInfo(name)
            member.size = len(payload); member.mtime = epoch
            member.mode = 0o755 if executable else 0o644
            member.uid = member.gid = 0; member.uname = member.gname = "root"
            archive.addfile(member, io.BytesIO(payload))
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)


def normalize_source(path, epoch, contents, version):
    entries = []
    names = set()
    prefix = f"cptc_guarded_harness-{version}/"
    with tarfile.open(path) as archive:
        for item in archive:
            if item.isdir(): continue
            if not item.isfile() or not item.name.startswith(prefix) or ".." in Path(item.name).parts:
                raise ValueError("unexpected source archive member")
            name = item.name[len(prefix):]
            if name in names or name not in contents["source"] | GENERATED_SOURCE:
                raise ValueError("unreviewed source archive member")
            names.add(name)
            entries.append((item.name, archive.extractfile(item).read(), bool(item.mode & 0o111)))
    if names != contents["source"] | GENERATED_SOURCE:
        raise ValueError("reviewed source distribution is incomplete")
    return tar_bytes(entries, epoch)


def build(directory, epoch, contents, version):
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch), PYTHONHASHSEED="0", PIP_NO_INDEX="1")
    completed = subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(directory)],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    (directory / "build.log").write_bytes(completed.stdout)
    if completed.returncode: raise RuntimeError("local build failed; inspect build.log")
    result = {}
    for path in directory.iterdir():
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as wheel:
                verify_wheel(wheel, contents, version)
            result[path.name] = path.read_bytes()
        elif path.name.endswith(".tar.gz"):
            result[path.name] = normalize_source(path, epoch, contents, version)
    if len(result) != 2: raise ValueError("expected one wheel and one source archive")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--epoch", type=int, required=True, help="fixed SOURCE_DATE_EPOCH for both independent builds")
    args = parser.parse_args()
    if args.epoch < 315532800: parser.error("epoch must be representable by wheel ZIP timestamps")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    contents = reviewed_contents(ROOT)
    paths = physical_distribution_inputs(ROOT)
    verify_source_inputs(ROOT, contents, paths)
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cptc-private-build-") as temporary:
        base = Path(temporary); one = base / "one"; two = base / "two"; one.mkdir(); two.mkdir()
        artifacts = build(one, args.epoch, contents, version)
        repeated = build(two, args.epoch, contents, version)
        if artifacts != repeated: raise ValueError("independent builds differ")
        entries = []; manifest = {}
        for name in sorted(contents["human"]):
            relative = Path(name)
            source = ROOT / relative
            if source.is_symlink() or not source.is_file(): raise ValueError("unexpected human-kit member")
            payload = source.read_bytes(); manifest[str(relative)] = hashlib.sha256(payload).hexdigest()
            entries.append((f"cptc-human-kit-{version}/{relative}", payload, os.access(source, os.X_OK)))
        entries.append((f"cptc-human-kit-{version}/INTEGRITY.json", json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n", False))
        artifacts[f"cptc-human-kit-{version}.tar.gz"] = tar_bytes(entries, args.epoch)
        for name, data in artifacts.items():
            destination = args.output / name
            if destination.exists() and destination.read_bytes() != data:
                raise ValueError("refusing to replace a different existing build artifact")
            destination.write_bytes(data)
        receipt = {"version": version, "classification": "public-development-metadata", "source_date_epoch": args.epoch,
            "reviewed_contents_sha256": hashlib.sha256((ROOT / MANIFEST).read_bytes()).hexdigest(),
            "independent_builds_equal": True, "source_archive_normalization": "sorted regular members; fixed uid/gid/modes/mtime; deterministic gzip",
            "runtime_wheel_excludes_test_data": True, "human_kit_integrity_files": len(manifest),
            "artifacts": [{"file": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(artifacts.items())],
            "uploaded": False, "competition_accepted": False}
        (args.output / "BUILD-RECEIPT-a4.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))


if __name__ == "__main__": main()
