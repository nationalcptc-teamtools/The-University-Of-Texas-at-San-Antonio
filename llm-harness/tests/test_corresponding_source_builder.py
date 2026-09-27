"""Offline tests for the deterministic corresponding-source bundle builder."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "corresponding_source_builder", ROOT / "scripts/corresponding_source/builder.py"
)
builder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None


def _load_builder():
    SPEC.loader.exec_module(builder)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def commit_binding(revision: str, recipe_source: str | None = None) -> dict:
    return {
        "recipe_selector_type": "commit",
        "recipe_selector": revision,
        "resolved_revision": revision,
        "recipe_manifest_path": ".SRCINFO",
        "recipe_source": recipe_source
        or f"git+https://upstream.example.test/project#commit={revision}",
        "binding_evidence_member": None,
        "binding_evidence_input": None,
        "binding_evidence_sha256": None,
        "tag_object_revision": None,
    }


def tag_object(selector: str, revision: str) -> tuple[bytes, str]:
    payload = (
        f"object {revision}\n"
        "type commit\n"
        f"tag {selector}\n"
        "tagger Synthetic Owner <owner@example.test> 0 +0000\n"
        "\n"
        "Synthetic revision binding\n"
    ).encode()
    object_bytes = b"tag " + str(len(payload)).encode() + b"\0" + payload
    identity = (
        hashlib.sha1(object_bytes, usedforsecurity=False).hexdigest()
        if len(revision) == 40
        else hashlib.sha256(object_bytes).hexdigest()
    )
    return payload, identity


def tar_bytes(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode = 0o644 if data else 0o755
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return raw.getvalue()


@pytest.fixture(autouse=True)
def load_module():
    _load_builder()


def make_fixture(tmp_path, *, archive_format="tar"):
    input_dir = tmp_path / "input"
    repo_root = tmp_path / "repo"
    pcommit, ucommit = "0" * 40, "1" * 40
    srcinfo = (
        f"\tsource = git+https://upstream.example.test/project#commit={ucommit}\n"
    ).encode()
    for relative, data in {
        "evidence/example.pkg.tar.zst": b"package artifact\n",
        "evidence/example.BUILDINFO": b"build metadata\n",
        "patches/fix.patch": b"--- a/file\n+++ b/file\n",
        "sources/packaging.tar": tar_bytes([(".SRCINFO", srcinfo), ("src", b"")]),
        "sources/upstream.tar": tar_bytes([("README", b"source\n"), ("src", b"")]),
    }.items():
        target = input_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if archive_format == "tar.xz":
        for relative in ("sources/packaging.tar", "sources/upstream.tar"):
            target = input_dir / relative
            target.write_bytes(lzma.compress(target.read_bytes(), format=lzma.FORMAT_XZ))
    copied = repo_root / "vendor/example/file.txt"
    copied.parent.mkdir(parents=True, exist_ok=True)
    copied.write_bytes(b"installed file\n")

    def ref(origin, revision, member, input_path, blob):
        return {
            "origin": origin,
            "revision": revision,
            "archive_member": member,
            "input_path": input_path,
            "sha256": sha(blob),
            "archive_format": archive_format,
            "member_count": 2,
            "unpacked_bytes": len(srcinfo) if "packaging" in member else len(b"source\n"),
        }

    packaging = (input_dir / "sources/packaging.tar").read_bytes()
    upstream = (input_dir / "sources/upstream.tar").read_bytes()
    component = {
        "name": "example",
        "version": "1.0",
        "use": "fixture",
        "source": "https://upstream.example.test/project",
        "license": "GPL-2.0-only",
        "license_source": "https://upstream.example.test/license",
        "copied_files": ["vendor/example/file.txt"],
        "distributed": True,
        "obligations": ["retain"],
        "distribution_basis": "copyleft-source-required",
        "approved_source_origins": {
            "packaging": ["https://packaging.example.test/project"],
            "upstream": ["https://upstream.example.test/project"],
        },
    }
    spec = {
        "schema_version": 1,
        "component": component,
        "distribution_package": {
            "name": "example",
            "version": "1.0",
            "component_version": "1.0",
            "architecture": "x86_64",
            "package_filename": "example.pkg.tar.zst",
            "package_sha256": sha(b"package artifact\n"),
            "installed_file_hashes": {"vendor/example/file.txt": sha(b"installed file\n")},
            "archive_member": "evidence/example.pkg.tar.zst",
            "build_info_member": "evidence/example.BUILDINFO",
            "build_info_sha256": sha(b"build metadata\n"),
            "input": {
                "package": "evidence/example.pkg.tar.zst",
                "build_info": "evidence/example.BUILDINFO",
            },
        },
        "packaging_source": ref(
            f"https://packaging.example.test/project/commit/{pcommit}",
            pcommit,
            "sources/packaging.tar",
            "sources/packaging.tar",
            packaging,
        ),
        "upstream_sources": [
            ref(
                f"https://upstream.example.test/project/-/commit/{ucommit}",
                ucommit,
                "sources/upstream.tar",
                "sources/upstream.tar",
                upstream,
            )
        ],
        "patches": [{"archive_member": "patches/fix.patch", "input_path": "patches/fix.patch", "sha256": sha(b"--- a/file\n+++ b/file\n")}],
        "build": {
            "recipe_member": "sources/packaging.tar",
            "source_info_member": "sources/upstream.tar",
            "toolchain": "synthetic",
            "flags": [],
            "source_date_epoch": None,
            "build_log_member": None,
            "build_log_sha256": None,
            "reproducibility_status": "metadata-only",
        },
        "verified_at": "2026-09-10T00:00:00Z",
        "verified_by": "synthetic owner",
    }
    spec["upstream_sources"][0]["revision_binding"] = commit_binding(ucommit)
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    outputs = (tmp_path / "out/example.tar.gz", tmp_path / "out/example.json", tmp_path / "out/example.receipt.json")
    return spec, spec_path, input_dir, repo_root, outputs


def set_recipe_sources(spec, input_dir, values):
    manifest = "".join(f"\tsource = {value}\n" for value in values).encode()
    payload = tar_bytes([(".SRCINFO", manifest), ("src", b"")])
    if spec["packaging_source"]["archive_format"] == "tar.xz":
        payload = lzma.compress(payload, format=lzma.FORMAT_XZ)
    relative = spec["packaging_source"]["input_path"]
    (input_dir / relative).write_bytes(payload)
    spec["packaging_source"]["sha256"] = sha(payload)
    spec["packaging_source"]["unpacked_bytes"] = len(manifest)


def set_recipe_source(spec, input_dir, value):
    set_recipe_sources(spec, input_dir, [value])


def test_builds_canonical_source_bundle_and_strict_sidecar(tmp_path):
    _, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    receipt = builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    archive, sidecar, receipt_path = outputs
    assert receipt["verified"] is True
    assert archive.read_bytes()[:10] == builder.CANONICAL_GZIP_HEADER
    assert json.loads(sidecar.read_text())["schema_version"] == 1
    assert json.loads(receipt_path.read_text()) == receipt
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archive.read_bytes())), mode="r:") as tar:
        names = [member.name for member in tar]
    assert names == sorted(names)
    assert names == [
        "evidence/example.BUILDINFO",
        "evidence/example.pkg.tar.zst",
        "patches/fix.patch",
        "sources/packaging.tar",
        "sources/upstream.tar",
    ]


def test_tag_revision_binding_is_verified_retained_and_sanitized(tmp_path):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    reference = spec["upstream_sources"][0]
    selector = "v1.0.0"
    payload, object_revision = tag_object(selector, reference["revision"])
    member = "evidence/revision-bindings/example-v1.0.0.tag"
    evidence = input_dir / member
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_bytes(payload)
    reference["revision_binding"] = {
        "recipe_selector_type": "tag",
        "recipe_selector": selector,
        "resolved_revision": reference["revision"],
        "recipe_manifest_path": ".SRCINFO",
        "recipe_source": f"git+https://upstream.example.test/project#tag={selector}",
        "binding_evidence_member": member,
        "binding_evidence_input": member,
        "binding_evidence_sha256": sha(payload),
        "tag_object_revision": object_revision,
    }
    set_recipe_source(spec, input_dir, reference["revision_binding"]["recipe_source"])
    spec_path.write_text(json.dumps(spec, sort_keys=True))

    builder.build_bundle(spec_path, input_dir, repo_root, *outputs)

    sidecar = json.loads(outputs[1].read_text())
    retained = sidecar["upstream_sources"][0]["revision_binding"]
    assert retained["binding_evidence_member"] == member
    assert "binding_evidence_input" not in retained
    with tarfile.open(
        fileobj=io.BytesIO(gzip.decompress(outputs[0].read_bytes())), mode="r:"
    ) as archive:
        extracted = archive.extractfile(member)
        assert extracted is not None
        assert extracted.read() == payload


@pytest.mark.parametrize(
    "mutation",
    [
        "resolved_revision",
        "selector",
        "evidence_hash",
        "object_revision",
        "mixed_object_format",
    ],
)
def test_tag_revision_binding_rejects_unbound_or_tampered_evidence(tmp_path, mutation):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    reference = spec["upstream_sources"][0]
    selector = "v1.0.0"
    payload, object_revision = tag_object(selector, reference["revision"])
    member = "evidence/revision-bindings/example-v1.0.0.tag"
    evidence = input_dir / member
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_bytes(payload)
    reference["revision_binding"] = {
        "recipe_selector_type": "tag",
        "recipe_selector": selector,
        "resolved_revision": reference["revision"],
        "recipe_manifest_path": ".SRCINFO",
        "recipe_source": f"git+https://upstream.example.test/project#tag={selector}",
        "binding_evidence_member": member,
        "binding_evidence_input": member,
        "binding_evidence_sha256": sha(payload),
        "tag_object_revision": object_revision,
    }
    set_recipe_source(spec, input_dir, reference["revision_binding"]["recipe_source"])
    if mutation == "resolved_revision":
        reference["revision_binding"]["resolved_revision"] = "2" * 40
    elif mutation == "selector":
        reference["revision_binding"]["recipe_selector"] = "../v1"
    elif mutation == "evidence_hash":
        reference["revision_binding"]["binding_evidence_sha256"] = "0" * 64
    elif mutation == "object_revision":
        reference["revision_binding"]["tag_object_revision"] = "0" * 40
    else:
        object_bytes = b"tag " + str(len(payload)).encode() + b"\0" + payload
        reference["revision_binding"]["tag_object_revision"] = hashlib.sha256(
            object_bytes
        ).hexdigest()
    spec_path.write_text(json.dumps(spec, sort_keys=True))

    with pytest.raises(builder.BuildError, match="binding|hash|recipe"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    assert not any(path.exists() for path in outputs)


def test_builder_rejects_packaging_binding_and_unretained_recipe_source(tmp_path):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    packaging_revision = spec["packaging_source"]["revision"]
    spec["packaging_source"]["revision_binding"] = commit_binding(
        packaging_revision
    )
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    with pytest.raises(builder.BuildError, match="schema"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)

    spec, spec_path, input_dir, repo_root, outputs = make_fixture(
        tmp_path / "recipe"
    )
    binding = spec["upstream_sources"][0]["revision_binding"]
    binding["recipe_source"] = binding["recipe_source"].replace(
        "/project#", "/project.git#"
    )
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    with pytest.raises(builder.BuildError, match="VCS sources"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)


def test_builder_rejects_additional_unbound_vcs_recipe_source(tmp_path):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    binding = spec["upstream_sources"][0]["revision_binding"]
    extra = f"git+https://upstream.example.test/project#commit={'2' * 40}"
    set_recipe_sources(spec, input_dir, [binding["recipe_source"], extra])
    spec_path.write_text(json.dumps(spec, sort_keys=True))

    with pytest.raises(builder.BuildError, match="VCS sources"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)


@pytest.mark.parametrize("selector", ["v1..0", "v1.", "v1.lock"])
def test_builder_rejects_invalid_git_tag_refname_full_flow(tmp_path, selector):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    reference = spec["upstream_sources"][0]
    payload, object_revision = tag_object(selector, reference["revision"])
    member = "evidence/revision-bindings/example-invalid.tag"
    evidence = input_dir / member
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_bytes(payload)
    reference["revision_binding"] = {
        "recipe_selector_type": "tag",
        "recipe_selector": selector,
        "resolved_revision": reference["revision"],
        "recipe_manifest_path": ".SRCINFO",
        "recipe_source": f"git+https://upstream.example.test/project#tag={selector}",
        "binding_evidence_member": member,
        "binding_evidence_input": member,
        "binding_evidence_sha256": sha(payload),
        "tag_object_revision": object_revision,
    }
    set_recipe_source(spec, input_dir, reference["revision_binding"]["recipe_source"])
    spec_path.write_text(json.dumps(spec, sort_keys=True))

    with pytest.raises(builder.BuildError, match="tag source revision binding"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)


@pytest.mark.parametrize("header", ["unknown value", "tagger "])
def test_tag_object_rejects_unknown_or_empty_headers(tmp_path, header):
    revision = "1" * 40
    selector = "v1.0.0"
    payload = (
        f"object {revision}\n"
        "type commit\n"
        f"tag {selector}\n"
        f"{header}\n"
        "tagger Synthetic Owner <owner@example.test> 0 +0000\n"
        "\nmessage\n"
    ).encode()
    object_bytes = b"tag " + str(len(payload)).encode() + b"\0" + payload
    path = tmp_path / "tag"
    path.write_bytes(payload)
    binding = {
        "resolved_revision": revision,
        "recipe_selector": selector,
        "tag_object_revision": hashlib.sha1(
            object_bytes, usedforsecurity=False
        ).hexdigest(),
    }
    with pytest.raises(builder.BuildError, match="evidence differs"):
        builder._validate_tag_object(path, binding)


def test_tag_object_supports_sha256_git_object_identity(tmp_path):
    revision = "1" * 64
    selector = "v1.0.0"
    payload, identity = tag_object(selector, revision)
    path = tmp_path / "tag"
    path.write_bytes(payload)
    builder._validate_tag_object(
        path,
        {
            "resolved_revision": revision,
            "recipe_selector": selector,
            "tag_object_revision": identity,
        },
    )


def test_builds_tar_xz_source_bundle(tmp_path):
    _, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path, archive_format="tar.xz")
    builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    metadata = json.loads(outputs[1].read_text())
    assert metadata["packaging_source"]["archive_format"] == "tar.xz"
    assert metadata["upstream_sources"][0]["archive_format"] == "tar.xz"


@pytest.mark.parametrize("architecture", ["any", "x86_64_v3"])
def test_accepts_distinct_package_name_and_reviewed_architecture(tmp_path, architecture):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    spec["distribution_package"]["name"] = "example-bin"
    spec["distribution_package"]["version"] = "1.0-1"
    spec["distribution_package"]["architecture"] = architecture
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    package = json.loads(outputs[1].read_text())["distribution_package"]
    assert package["name"] == "example-bin"
    assert package["version"] == "1.0-1"
    assert package["architecture"] == architecture


@pytest.mark.parametrize("architecture", ["x86 64", "X86_64"])
def test_rejects_invalid_architecture_identifier(tmp_path, architecture):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    spec["distribution_package"]["architecture"] = architecture
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    with pytest.raises(builder.BuildError, match="architecture"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)


def test_builder_streams_declared_files_without_read_bytes(tmp_path, monkeypatch):
    _, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)

    def fail_read_bytes(_path):
        raise AssertionError("declared files must be streamed")

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)
    builder.build_bundle(spec_path, input_dir, repo_root, *outputs)


def test_build_is_byte_deterministic(tmp_path):
    _, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    first_archive = outputs[0].read_bytes()
    first_sidecar = outputs[1].read_bytes()
    second = tuple(tmp_path / f"out/second-{index}{suffix}" for index, suffix in enumerate((".tar.gz", ".json", ".receipt.json")))
    builder.build_bundle(spec_path, input_dir, repo_root, *second)
    assert second[0].read_bytes() == first_archive
    assert second[1].read_bytes() == first_sidecar


def test_builder_refuses_overwrite_and_leaves_existing_bytes(tmp_path):
    _, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    before = {path: path.read_bytes() for path in outputs}
    with pytest.raises(builder.BuildError, match="exists"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    assert {path: path.read_bytes() for path in outputs} == before


@pytest.mark.parametrize("mutation", [
    "missing_top_level",
    "path_traversal",
    "bad_origin",
    "bad_revision",
    "bad_hash",
    "bad_architecture",
])
def test_builder_rejects_malformed_spec_before_writing(tmp_path, mutation):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    if mutation == "missing_top_level":
        del spec["build"]
    elif mutation == "path_traversal":
        spec["packaging_source"]["input_path"] = "../escape"
    elif mutation == "bad_origin":
        spec["packaging_source"]["origin"] += "?query"
    elif mutation == "bad_revision":
        spec["packaging_source"]["revision"] = "short"
    elif mutation == "bad_hash":
        spec["distribution_package"]["package_sha256"] = "0" * 64
    else:
        spec["distribution_package"]["architecture"] = "arm 64"
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    with pytest.raises(builder.BuildError):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    assert not any(path.exists() for path in outputs)


def test_builder_rejects_symlink_and_copied_hash_mismatch(tmp_path):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    linked = input_dir / "sources/linked.tar"
    linked.symlink_to(input_dir / "sources/packaging.tar")
    spec["upstream_sources"][0]["input_path"] = "sources/linked.tar"
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    with pytest.raises(builder.BuildError, match="symlink"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path / "second")
    spec["component"]["copied_files"] = ["vendor/example/file.txt"]
    spec["distribution_package"]["installed_file_hashes"]["vendor/example/file.txt"] = "0" * 64
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    with pytest.raises(builder.BuildError, match="hash"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)


def test_builder_rejects_noncanonical_nested_tail_and_bundle_limit(tmp_path, monkeypatch):
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path)
    nested = input_dir / "sources/packaging.tar"
    nested.write_bytes(nested.read_bytes() + b"JUNK")
    spec["packaging_source"]["sha256"] = sha(nested.read_bytes())
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    with pytest.raises(builder.BuildError, match="canonical|trailing"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path / "padding")
    nested = input_dir / "sources/packaging.tar"
    nested.write_bytes(nested.read_bytes() + b"\0" * 10240)
    spec["packaging_source"]["sha256"] = sha(nested.read_bytes())
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    with pytest.raises(builder.BuildError, match="canonical"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
    spec, spec_path, input_dir, repo_root, outputs = make_fixture(tmp_path / "second")
    monkeypatch.setattr(builder, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(builder.BuildError, match="95 MiB|bundle"):
        builder.build_bundle(spec_path, input_dir, repo_root, *outputs)
