"""Synthetic adversarial tests for the v2 corresponding-source gate."""
from __future__ import annotations

import gzip
import ast
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("source_gate", ROOT / "scripts/package-harness.py")
package = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(package)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def commit_binding(revision: str) -> dict:
    return {
        "recipe_selector_type": "commit",
        "recipe_selector": revision,
        "resolved_revision": revision,
        "recipe_manifest_path": ".SRCINFO",
        "recipe_source":
            f"git+https://upstream.example.test/project#commit={revision}",
        "binding_evidence_member": None,
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
        for name, data, kind in entries:
            info = tarfile.TarInfo(name); info.mtime = 0; info.uid = info.gid = 0; info.uname = info.gname = "root"
            if kind == "file":
                info.size = len(data); info.mode = 0o644; archive.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE; info.mode = 0o755; archive.addfile(info)
            elif kind == "hard":
                info.type = tarfile.LNKTYPE; info.linkname = data.decode(); archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE; info.linkname = data.decode(); info.mode = 0o777; archive.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE; info.mode = 0o644; archive.addfile(info)
            else:
                info.type = tarfile.CHRTYPE; archive.addfile(info)
    return raw.getvalue()


def nested_bytes(entries, archive_format):
    raw = tar_bytes(entries)
    return lzma.compress(raw, format=lzma.FORMAT_XZ) if archive_format == "tar.xz" else raw


def write_outer(path, entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip_bytes(tar_bytes([(name, data, "file") for name, data in sorted(entries.items())])))


def gzip_bytes(data):
    output = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as stream:
        stream.write(data)
    return output.getvalue()


def _locks(root, files):
    age_digest = sha(files["vendor/portcast-rootfs-runtime/bin/age"])
    native_digest = sha(files["vendor/portcast-rootfs-runtime/lib/libsynthetic.so"])
    rootfs_elf = {
        Path(name).relative_to("vendor/portcast-rootfs-runtime").as_posix(): sha(data)
        for name, data in files.items()
        if name.startswith("vendor/portcast-rootfs-runtime/") and data.startswith(b"\x7fELF")
    }
    specs = [
        ("cptc_harness/resources/portcast-python-runtime-v1.json", "vendor/portcast-python3.14/site-packages", {"schema_version": 1, "python_abi": "cp314-x86_64-linux-gnu", "packages": {"example": "1.0"}, "import_roots": ["example"], "native_files": {"/usr/lib/libsynthetic.so": {"resolved_path": "/usr/lib/libsynthetic.so", "sha256": native_digest}}}),
        ("cptc_harness/resources/portcast-cpython-runtime-v1.json", "vendor/portcast-rootfs-runtime", {"schema_version": 1, "python_abi": "cp314-x86_64-linux-gnu", "entrypoints": {"age": "bin/age", "bubblewrap": "bin/bwrap", "loader": "lib/ld-linux-x86-64.so.2", "python": "bin/python3.14", "stdlib": "lib/python3.14"}, "packages": {"example": {"license": "MIT", "version": "1.0"}}, "elf_files": rootfs_elf, "build_tools": {"go": "go version go1.synthetic linux/amd64", "launcher_argv": ["/usr/sbin/go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", "deployment/portcast-bootstrap", "deployment/portcast-bootstrap.go"], "launcher_environment": {"CGO_ENABLED": "0", "GOCACHE": "operator-owned-empty-cache", "GOENV": "off", "GOTOOLCHAIN": "local", "PATH": "/usr/sbin:/usr/bin"}, "patchelf": "patchelf synthetic"}, "external_tools": {"age": {"license": "BSD-3-Clause", "sha256": age_digest, "source": "https://example.test/age", "version": "1.0"}}, "transformations": [{"operation": "remove RPATH and RUNPATH", "scope": "elf_files", "tool": "patchelf synthetic"}]}),
    ]
    for relative, runtime_root, extra in specs:
        expected = {Path(name).relative_to(runtime_root).as_posix(): sha(data) for name, data in files.items() if name.startswith(runtime_root + "/")}
        target = root / relative; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"root": runtime_root, "files": expected, **extra}))


def fixture(tmp_path, nested_format="tar"):
    files = {
        "vendor/portcast-python3.14/site-packages/example.py": b"one\n",
        "vendor/portcast-rootfs-runtime/bin/age": b"\x7fELFsynthetic-age\n",
        "vendor/portcast-rootfs-runtime/bin/bwrap": b"synthetic-bwrap\n",
        "vendor/portcast-rootfs-runtime/bin/python3.14": b"synthetic-python\n",
        "vendor/portcast-rootfs-runtime/lib/ld-linux-x86-64.so.2": b"synthetic-loader\n",
        "vendor/portcast-rootfs-runtime/lib/libsynthetic.so": b"\x7fELFsynthetic-library\n",
        "vendor/portcast-rootfs-runtime/lib/python3.14/example.py": b"synthetic-stdlib\n",
    }
    for name, data in files.items():
        target = tmp_path / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    pcommit, ucommit = "0" * 40, "1" * 40
    srcinfo = (
        f"\tsource = git+https://upstream.example.test/project#commit={ucommit}\n"
    ).encode()
    packaging_entries = [(".SRCINFO", srcinfo, "file"), ("src", b"", "dir")]
    upstream_entries = [("README", b"source\n", "file"), ("src", b"", "dir")]
    packaging_tar = nested_bytes(packaging_entries, nested_format)
    upstream_tar = nested_bytes(upstream_entries, nested_format)
    package_blob, buildinfo = b"package artifact\n", b"build metadata\n"
    suffix = ".tar.xz" if nested_format == "tar.xz" else ".tar"
    packaging_member = "sources/packaging" + suffix
    upstream_member = "sources/upstream" + suffix
    outer = {"evidence/example.BUILDINFO": buildinfo, "evidence/example.pkg.tar.zst": package_blob, packaging_member: packaging_tar, upstream_member: upstream_tar}
    archive_rel = "vendor/corresponding-source/example.tar.gz"; archive = tmp_path / archive_rel; write_outer(archive, outer)
    def ref(origin, revision, member, blob, unpacked):
        return {"origin": origin, "revision": revision, "archive_member": member, "sha256": sha(blob), "archive_format": nested_format, "member_count": 2, "unpacked_bytes": unpacked}
    metadata = {"schema_version": 1, "component": "example", "distribution_package": {"name": "example", "version": "1.0-1", "component_version": "1.0", "architecture": "x86_64", "package_filename": "example.pkg.tar.zst", "package_sha256": sha(package_blob), "installed_file_hashes": {name: sha(data) for name, data in files.items()}, "archive_member": "evidence/example.pkg.tar.zst", "build_info_member": "evidence/example.BUILDINFO", "build_info_sha256": sha(buildinfo)}, "packaging_source": ref(f"https://packaging.example.test/project/commit/{pcommit}", pcommit, packaging_member, packaging_tar, len(srcinfo)), "upstream_sources": [ref(f"https://upstream.example.test/project/-/commit/{ucommit}", ucommit, upstream_member, upstream_tar, len(b"source\n"))], "patches": [], "build": {"recipe_member": packaging_member, "source_info_member": upstream_member, "toolchain": "synthetic", "flags": [], "source_date_epoch": None, "build_log_member": None, "build_log_sha256": None, "reproducibility_status": "metadata-only"}, "archive_members": [{"path": name, "sha256": sha(data), "bytes": len(data)} for name, data in sorted(outer.items())], "verified_at": "2026-09-10T00:00:00Z", "verified_by": "synthetic owner"}
    metadata["upstream_sources"][0]["revision_binding"] = commit_binding(ucommit)
    meta_rel = "docs/harness/corresponding-source/example.json"; meta = tmp_path / meta_rel; meta.parent.mkdir(parents=True, exist_ok=True); meta.write_text(json.dumps(metadata, sort_keys=True))
    component = {"name": "example", "version": "1.0", "use": "fixture", "source": "https://upstream.example.test/project", "license": "GPL-2.0-only", "license_source": "https://upstream.example.test/license", "copied_files": sorted(files), "distributed": True, "obligations": ["retain"], "distribution_basis": "copyleft-source-required", "approved_source_origins": {"packaging": ["https://packaging.example.test/project"], "upstream": ["https://upstream.example.test/project"]}, "corresponding_source": {"method": "exact_archive", "archive": archive_rel, "sha256": sha(archive.read_bytes()), "bytes": archive.stat().st_size, "archive_format": "tar.gz", "metadata_path": meta_rel, "metadata_sha256": sha(meta.read_bytes())}}
    inventory = {"version": 2, "classification": "public-development-metadata", "reviewed_at": "2026-09-10T00:00:00Z", "reviewed_by": "synthetic owner", "copied_external_source_files": sorted(files), "components": [component]}
    _locks(tmp_path, files)
    return inventory, {"source": {archive_rel, meta_rel}, "runtime": set()}, metadata, outer


def test_v1_and_legacy_offers_are_unconditionally_rejected(tmp_path):
    with pytest.raises(ValueError, match="version 2"):
        package.verify_source_fulfillment(tmp_path, {"version": 1, "components": []}, {"source": set(), "runtime": set()})


def test_only_one_public_compliance_gate_is_defined_and_source_fulfillment_needs_no_runtime(tmp_path):
    tree = ast.parse((ROOT / "scripts/package-harness.py").read_text())
    assert [node.name for node in tree.body if isinstance(node, ast.FunctionDef)].count("verify_third_party_compliance") == 1
    inventory, contents, _, _ = fixture(tmp_path)
    for path in (tmp_path / "vendor/portcast-python3.14", tmp_path / "vendor/portcast-rootfs-runtime", tmp_path / "cptc_harness/resources"):
        if path.exists():
            import shutil; shutil.rmtree(path)
    assert package.verify_source_fulfillment(tmp_path, inventory, contents)["verified"]


def test_v2_fulfillment_and_full_compliance_bind_sources_locks_and_receipt(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    fulfillment = package.verify_source_fulfillment(tmp_path, inventory, contents)
    receipt = package.verify_third_party_compliance(tmp_path, inventory, contents, fulfillment)
    assert receipt["verified"] and receipt["source_archives"] == fulfillment["source_archives"]


def test_v2_accepts_tar_xz_nested_sources(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path, nested_format="tar.xz")
    fulfillment = package.verify_source_fulfillment(tmp_path, inventory, contents)
    assert package.verify_third_party_compliance(tmp_path, inventory, contents, fulfillment)["verified"]


def test_full_compliance_rejects_forged_fulfillment(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    forged = package.verify_source_fulfillment(tmp_path, inventory, contents)
    forged["inventory_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="recomputed"):
        package.verify_third_party_compliance(tmp_path, inventory, contents, forged)


@pytest.mark.parametrize("field,value", [
    ("classification", "private"), ("reviewed_at", "today"), ("reviewed_by", ""),
    ("copied_external_source_files", ["../escape"]), ("components", "not-a-list"),
])
def test_v2_rejects_invalid_top_level_types_and_values(tmp_path, field, value):
    inventory, contents, _, _ = fixture(tmp_path)
    inventory[field] = value
    with pytest.raises(ValueError): package.verify_source_fulfillment(tmp_path, inventory, contents)


def test_v2_rejects_duplicate_component_names_overlap_and_non_distributed_source(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    duplicate = json.loads(json.dumps(inventory["components"][0])); inventory["components"].append(duplicate)
    with pytest.raises(ValueError): package.verify_source_fulfillment(tmp_path, inventory, contents)


def _rewrite_metadata(tmp_path, inventory, metadata):
    source = inventory["components"][0]["corresponding_source"]
    sidecar = tmp_path / source["metadata_path"]
    sidecar.write_text(json.dumps(metadata, sort_keys=True))
    source["metadata_sha256"] = sha(sidecar.read_bytes())


def _rewrite_outer(tmp_path, inventory, metadata, outer):
    source = inventory["components"][0]["corresponding_source"]
    archive = tmp_path / source["archive"]
    write_outer(archive, outer)
    source["sha256"] = sha(archive.read_bytes())
    source["bytes"] = archive.stat().st_size
    metadata["archive_members"] = [
        {"path": name, "sha256": sha(data), "bytes": len(data)}
        for name, data in sorted(outer.items())
    ]
    _rewrite_metadata(tmp_path, inventory, metadata)


def _set_recipe_sources(metadata, outer, values):
    manifest = "".join(f"\tsource = {value}\n" for value in values).encode()
    packaging = metadata["packaging_source"]
    recipe_payload = nested_bytes(
        [(".SRCINFO", manifest, "file"), ("src", b"", "dir")],
        packaging["archive_format"],
    )
    outer[packaging["archive_member"]] = recipe_payload
    packaging["sha256"] = sha(recipe_payload)
    packaging["unpacked_bytes"] = len(manifest)


def _use_tag_binding(tmp_path, inventory, metadata, outer):
    reference = metadata["upstream_sources"][0]
    selector = "v1.0.0"
    payload, object_revision = tag_object(selector, reference["revision"])
    member = "evidence/revision-bindings/example-v1.0.0.tag"
    reference["revision_binding"] = {
        "recipe_selector_type": "tag",
        "recipe_selector": selector,
        "resolved_revision": reference["revision"],
        "recipe_manifest_path": ".SRCINFO",
        "recipe_source": f"git+https://upstream.example.test/project#tag={selector}",
        "binding_evidence_member": member,
        "binding_evidence_sha256": sha(payload),
        "tag_object_revision": object_revision,
    }
    _set_recipe_sources(metadata, outer, [reference["revision_binding"]["recipe_source"]])
    outer[member] = payload
    _rewrite_outer(tmp_path, inventory, metadata, outer)
    return member


def test_v2_verifies_retained_tag_revision_binding(tmp_path):
    inventory, contents, metadata, outer = fixture(tmp_path)
    member = _use_tag_binding(tmp_path, inventory, metadata, outer)

    fulfillment = package.verify_source_fulfillment(tmp_path, inventory, contents)

    assert fulfillment["verified"]
    assert member in {item["path"] for item in metadata["archive_members"]}


@pytest.mark.parametrize(
    "mutation", ["missing", "hash", "identity", "selector", "mixed_object_format"]
)
def test_v2_rejects_missing_or_tampered_tag_revision_binding(tmp_path, mutation):
    inventory, contents, metadata, outer = fixture(tmp_path)
    member = _use_tag_binding(tmp_path, inventory, metadata, outer)
    binding = metadata["upstream_sources"][0]["revision_binding"]
    if mutation == "missing":
        del outer[member]
        _rewrite_outer(tmp_path, inventory, metadata, outer)
    elif mutation == "hash":
        binding["binding_evidence_sha256"] = "0" * 64
        _rewrite_metadata(tmp_path, inventory, metadata)
    elif mutation == "identity":
        binding["tag_object_revision"] = "0" * 40
        _rewrite_metadata(tmp_path, inventory, metadata)
    elif mutation == "selector":
        binding["recipe_selector"] = "v2.0.0"
        _rewrite_metadata(tmp_path, inventory, metadata)
    else:
        payload = outer[member]
        object_bytes = b"tag " + str(len(payload)).encode() + b"\0" + payload
        binding["tag_object_revision"] = hashlib.sha256(object_bytes).hexdigest()
        _rewrite_metadata(tmp_path, inventory, metadata)

    with pytest.raises(ValueError, match="binding|identity|archive members|evidence roles|recipe"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)


def test_v2_rejects_duplicate_sidecar_keys(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    source = inventory["components"][0]["corresponding_source"]
    sidecar = tmp_path / source["metadata_path"]
    revision = "1" * 40
    needle = f'"resolved_revision": "{revision}"'
    replacement = (
        f'"resolved_revision": "{"2" * 40}", '
        f'"resolved_revision": "{revision}"'
    )
    payload = sidecar.read_text().replace(needle, replacement, 1)
    assert payload != sidecar.read_text()
    sidecar.write_text(payload)
    source["metadata_sha256"] = sha(sidecar.read_bytes())

    with pytest.raises(ValueError, match="duplicate JSON key"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)


def test_v2_rejects_packaging_binding_recipe_substitution_and_role_alias(tmp_path):
    inventory, contents, metadata, _ = fixture(tmp_path)
    metadata["packaging_source"]["revision_binding"] = commit_binding(
        metadata["packaging_source"]["revision"]
    )
    _rewrite_metadata(tmp_path, inventory, metadata)
    with pytest.raises(ValueError, match="packaging source metadata"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)

    inventory, contents, metadata, _ = fixture(tmp_path / "recipe")
    binding = metadata["upstream_sources"][0]["revision_binding"]
    binding["recipe_source"] = binding["recipe_source"].replace(
        "/project#", "/project.git#"
    )
    _rewrite_metadata(tmp_path / "recipe", inventory, metadata)
    with pytest.raises(ValueError, match="VCS sources"):
        package.verify_source_fulfillment(tmp_path / "recipe", inventory, contents)

    alias_root = tmp_path / "alias"
    inventory, contents, metadata, outer = fixture(alias_root)
    tag_member = _use_tag_binding(alias_root, inventory, metadata, outer)
    binding = metadata["upstream_sources"][0]["revision_binding"]
    dist_package = metadata["distribution_package"]
    old_package_member = dist_package["archive_member"]
    dist_package["archive_member"] = tag_member
    dist_package["package_sha256"] = binding["binding_evidence_sha256"]
    del outer[old_package_member]
    _rewrite_outer(alias_root, inventory, metadata, outer)
    with pytest.raises(ValueError, match="evidence roles"):
        package.verify_source_fulfillment(alias_root, inventory, contents)


def test_v2_rejects_additional_unbound_vcs_recipe_source(tmp_path):
    inventory, contents, metadata, outer = fixture(tmp_path)
    binding = metadata["upstream_sources"][0]["revision_binding"]
    extra = f"git+https://upstream.example.test/project#commit={'2' * 40}"
    _set_recipe_sources(metadata, outer, [binding["recipe_source"], extra])
    _rewrite_outer(tmp_path, inventory, metadata, outer)

    with pytest.raises(ValueError, match="VCS sources"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)


@pytest.mark.parametrize("selector", ["v1..0", "v1.", "v1.lock"])
def test_v2_rejects_invalid_git_tag_refname_full_flow(tmp_path, selector):
    inventory, contents, metadata, outer = fixture(tmp_path)
    member = _use_tag_binding(tmp_path, inventory, metadata, outer)
    reference = metadata["upstream_sources"][0]
    payload, object_revision = tag_object(selector, reference["revision"])
    binding = reference["revision_binding"]
    binding["recipe_selector"] = selector
    binding["recipe_source"] = (
        f"git+https://upstream.example.test/project#tag={selector}"
    )
    binding["binding_evidence_sha256"] = sha(payload)
    binding["tag_object_revision"] = object_revision
    outer[member] = payload
    _set_recipe_sources(metadata, outer, [binding["recipe_source"]])
    _rewrite_outer(tmp_path, inventory, metadata, outer)

    with pytest.raises(ValueError, match="tag binding"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)


@pytest.mark.parametrize("header", ["unknown value", "tagger "])
def test_v2_tag_object_rejects_unknown_or_empty_headers(header):
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
    with pytest.raises(ValueError, match="evidence differs"):
        package._validate_tag_object(
            payload,
            {
                "resolved_revision": revision,
                "recipe_selector": selector,
                "tag_object_revision": hashlib.sha1(
                    object_bytes, usedforsecurity=False
                ).hexdigest(),
            },
        )


def test_v2_tag_object_supports_sha256_git_object_identity():
    revision = "1" * 64
    selector = "v1.0.0"
    payload, identity = tag_object(selector, revision)
    package._validate_tag_object(
        payload,
        {
            "resolved_revision": revision,
            "recipe_selector": selector,
            "tag_object_revision": identity,
        },
    )


@pytest.mark.parametrize("mutation", ["descriptor_bool", "reference_bool", "installed_hash_type", "extra_top_level", "missing_component_field"])
def test_v2_rejects_malformed_scalar_and_schema_values_with_value_error(tmp_path, mutation):
    inventory, contents, metadata, _ = fixture(tmp_path)
    if mutation == "descriptor_bool":
        inventory["components"][0]["corresponding_source"]["bytes"] = True
    elif mutation == "reference_bool":
        metadata["packaging_source"]["member_count"] = True
        _rewrite_metadata(tmp_path, inventory, metadata)
    elif mutation == "installed_hash_type":
        name = next(iter(metadata["distribution_package"]["installed_file_hashes"]))
        metadata["distribution_package"]["installed_file_hashes"][name] = 7
        _rewrite_metadata(tmp_path, inventory, metadata)
    elif mutation == "extra_top_level":
        inventory["unexpected"] = True
    else:
        del inventory["components"][0]["use"]
    with pytest.raises(ValueError):
        package.verify_source_fulfillment(tmp_path, inventory, contents)
    inventory, contents, _, _ = fixture(tmp_path)
    component = inventory["components"][0]; component["distributed"] = False
    with pytest.raises(ValueError): package.verify_source_fulfillment(tmp_path, inventory, contents)


@pytest.mark.parametrize("byte_index,replacement", [(2, 0), (3, 1)])
def test_v2_rejects_noncanonical_gzip_method_and_flags(tmp_path, byte_index, replacement):
    inventory, contents, _, _ = fixture(tmp_path)
    source = inventory["components"][0]["corresponding_source"]; archive = tmp_path / source["archive"]
    raw = bytearray(archive.read_bytes()); raw[byte_index] = replacement; archive.write_bytes(raw)
    source["sha256"] = sha(raw); source["bytes"] = len(raw)
    with pytest.raises(ValueError, match="deterministic"): package.verify_source_fulfillment(tmp_path, inventory, contents)


@pytest.mark.parametrize("byte_index,replacement", [(8, 0), (9, 3)])
def test_v2_rejects_noncanonical_gzip_xfl_and_os(tmp_path, byte_index, replacement):
    inventory, contents, _, _ = fixture(tmp_path)
    source = inventory["components"][0]["corresponding_source"]
    archive = tmp_path / source["archive"]
    raw = bytearray(archive.read_bytes())
    raw[byte_index] = replacement
    archive.write_bytes(raw)
    source["sha256"] = sha(raw)
    source["bytes"] = len(raw)
    with pytest.raises(ValueError, match="deterministic"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)


def test_v2_rejects_trailing_gzip_data_and_nondeterministic_nested_metadata(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    source = inventory["components"][0]["corresponding_source"]
    archive = tmp_path / source["archive"]
    archive.write_bytes(archive.read_bytes() + b"JUNK")
    source["sha256"] = sha(archive.read_bytes())
    source["bytes"] = archive.stat().st_size
    with pytest.raises(ValueError, match="trailing"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as nested:
        for index, name in enumerate(("README", "source")):
            info = tarfile.TarInfo(name)
            info.size = 1
            info.mode = 0o644
            info.mtime = index
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            nested.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="deterministic"):
        package._inspect_nested(io.BytesIO(raw.getvalue()), {"member_count": 2, "unpacked_bytes": 2})


@pytest.mark.parametrize("archive_format", ["tar", "tar.xz"])
def test_nested_archives_reject_trailing_data_and_require_canonical_end(tmp_path, archive_format):
    raw = nested_bytes([("README", b"x", "file"), ("source", b"y", "file")], archive_format)
    if archive_format == "tar":
        raw += b"JUNK"
    else:
        raw += b"JUNK"
    with pytest.raises(ValueError, match="trailing|canonical|unreadable"):
        package._inspect_nested(io.BytesIO(raw), {"archive_format": archive_format, "member_count": 2, "unpacked_bytes": 2})


def test_nested_xz_rejects_truncation_unsupported_format_and_expansion(monkeypatch):
    raw = nested_bytes([("README", b"x", "file"), ("source", b"y", "file")], "tar.xz")
    with pytest.raises(ValueError, match="truncated|unreadable"):
        package._inspect_nested(io.BytesIO(raw[:-1]), {"archive_format": "tar.xz", "member_count": 2, "unpacked_bytes": 2})
    with pytest.raises(ValueError, match="unsupported"):
        package._inspect_nested(io.BytesIO(raw), {"archive_format": "tar.zst", "member_count": 2, "unpacked_bytes": 2})
    monkeypatch.setattr(package, "MAX_NESTED_UNPACKED_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        package._inspect_nested(io.BytesIO(raw), {"archive_format": "tar.xz", "member_count": 2, "unpacked_bytes": 2})


@pytest.mark.parametrize("entries", [
    [("README", b"x", "file"), ("README", b"y", "file")],
    [("../escape", b"x", "file"), ("source", b"y", "file")],
    [("source", b"x", "file"), ("link", b"../escape", "symlink")],
    [("source", b"x", "file"), ("fifo", b"", "fifo")],
])
def test_nested_archives_reject_duplicate_traversal_links_and_special_members(entries):
    with pytest.raises(ValueError, match="unsafe|unsupported|escapes"):
        package._inspect_nested(io.BytesIO(nested_bytes(entries, "tar.xz")), {"archive_format": "tar.xz", "member_count": 2, "unpacked_bytes": 1})


def test_nested_archives_reject_lfs_pointer_and_member_limit(monkeypatch):
    lfs = nested_bytes([("README", b"version https://git-lfs.github.com/spec/v1\n", "file"), ("source", b"x", "file")], "tar.xz")
    with pytest.raises(ValueError, match="LFS"):
        package._inspect_nested(io.BytesIO(lfs), {"archive_format": "tar.xz", "member_count": 2, "unpacked_bytes": 42})
    monkeypatch.setattr(package, "MAX_NESTED_ARCHIVE_MEMBERS", 1)
    regular = nested_bytes([("README", b"x", "file"), ("source", b"y", "file")], "tar.xz")
    with pytest.raises(ValueError, match="unsafe"):
        package._inspect_nested(io.BytesIO(regular), {"archive_format": "tar.xz", "member_count": 2, "unpacked_bytes": 2})


def test_nested_member_limit_is_separate_from_outer_metadata_limit(monkeypatch):
    monkeypatch.setattr(package, "MAX_SOURCE_ARCHIVE_MEMBERS", 1)
    regular = nested_bytes([("README", b"x", "file"), ("source", b"y", "file")], "tar.xz")
    package._inspect_nested(io.BytesIO(regular), {"archive_format": "tar.xz", "member_count": 2, "unpacked_bytes": 2})


def test_outer_tar_gz_rejects_junk_after_logical_eof(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    source = inventory["components"][0]["corresponding_source"]
    archive = tmp_path / source["archive"]
    archive.write_bytes(gzip_bytes(gzip.decompress(archive.read_bytes()) + b"JUNK"))
    source["sha256"] = sha(archive.read_bytes())
    source["bytes"] = archive.stat().st_size
    with pytest.raises(ValueError, match="trailing|canonical"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)


def test_outer_tar_gz_rejects_extra_zero_padding_records(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    source = inventory["components"][0]["corresponding_source"]
    archive = tmp_path / source["archive"]
    archive.write_bytes(gzip_bytes(gzip.decompress(archive.read_bytes()) + b"\0" * 10240))
    source["sha256"] = sha(archive.read_bytes())
    source["bytes"] = archive.stat().st_size
    with pytest.raises(ValueError, match="canonical"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)


@pytest.mark.parametrize("difference", [0, -1])
def test_outer_bundle_has_strict_repository_safety_cap(tmp_path, monkeypatch, difference):
    inventory, _, _, _ = fixture(tmp_path)
    archive = tmp_path / inventory["components"][0]["corresponding_source"]["archive"]
    monkeypatch.setattr(package, "MAX_SOURCE_BUNDLE_BYTES", archive.stat().st_size + difference)
    with pytest.raises(ValueError, match="repository safety"):
        package._verify_canonical_gzip(archive)


def test_v2_rejects_bad_lock_entrypoint_and_metadata_types(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    lock_path = tmp_path / "cptc_harness/resources/portcast-cpython-runtime-v1.json"
    lock = json.loads(lock_path.read_text()); lock["entrypoints"] = {"bad": "../escape"}; lock_path.write_text(json.dumps(lock))
    with pytest.raises(ValueError, match="runtime lock"): package.verify_third_party_compliance(tmp_path, inventory, contents)


def test_v2_native_dependency_must_match_the_named_rootfs_elf(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    lock_path = tmp_path / "cptc_harness/resources/portcast-python-runtime-v1.json"
    lock = json.loads(lock_path.read_text())
    digest = lock["native_files"].pop("/usr/lib/libsynthetic.so")["sha256"]
    lock["native_files"]["/usr/lib/libfake.so"] = {
        "resolved_path": "/usr/lib/libfake.so",
        "sha256": digest,
    }
    lock_path.write_text(json.dumps(lock))
    with pytest.raises(ValueError, match="native dependency"):
        package.verify_third_party_compliance(tmp_path, inventory, contents)


@pytest.mark.parametrize("lock_name,field,value", [
    ("portcast-python-runtime-v1.json", "schema_version", True),
    ("portcast-python-runtime-v1.json", "packages", {"example": 1}),
    ("portcast-python-runtime-v1.json", "import_roots", ["../escape"]),
    ("portcast-python-runtime-v1.json", "native_files", {"relative": {"resolved_path": "/usr/lib/libx.so", "sha256": "0" * 64}}),
    ("portcast-cpython-runtime-v1.json", "elf_files", {"bin/example": "0" * 64}),
    ("portcast-cpython-runtime-v1.json", "build_tools", {}),
    ("portcast-cpython-runtime-v1.json", "external_tools", {"bad": {"license": "MIT", "sha256": "0" * 64, "source": "http://example.test", "version": "1"}}),
    ("portcast-cpython-runtime-v1.json", "transformations", []),
])
def test_v2_rejects_malformed_nested_runtime_lock_metadata(tmp_path, lock_name, field, value):
    inventory, contents, _, _ = fixture(tmp_path)
    lock_path = tmp_path / "cptc_harness/resources" / lock_name
    lock = json.loads(lock_path.read_text())
    lock[field] = value
    lock_path.write_text(json.dumps(lock))
    with pytest.raises(ValueError, match="runtime lock"):
        package.verify_third_party_compliance(tmp_path, inventory, contents)


def test_v2_rejects_vendor_symlinks_and_non_distributed_file_ownership(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    (tmp_path / "vendor/escape").symlink_to(tmp_path / "outside")
    with pytest.raises(ValueError, match="symlink"):
        package.verify_third_party_compliance(tmp_path, inventory, contents)
    inventory, contents, _, _ = fixture(tmp_path / "second")
    component = inventory["components"][0]
    component["distributed"] = False
    component["corresponding_source"] = None
    component["approved_source_origins"] = {"packaging": [], "upstream": []}
    with pytest.raises(ValueError, match="non-distributed"):
        package.verify_source_fulfillment(tmp_path / "second", inventory, contents)


@pytest.mark.parametrize("mutation", ["query", "other_host", "outer_traversal", "nested_hardlink", "lfs", "missing_lock"])
def test_v2_rejects_adversarial_origins_archives_and_locks(tmp_path, mutation):
    inventory, contents, metadata, outer = fixture(tmp_path)
    if mutation == "query": metadata["packaging_source"]["origin"] += "?bad=1"
    elif mutation == "other_host": metadata["upstream_sources"][0]["origin"] = metadata["upstream_sources"][0]["origin"].replace("upstream.example.test", "other.example.test")
    elif mutation == "outer_traversal": outer["../escape"] = b"bad"
    elif mutation == "nested_hardlink": outer["sources/upstream.tar"] = tar_bytes([("a", b"data", "file"), ("b", b"a", "hard")])
    elif mutation == "lfs": outer["evidence/example.BUILDINFO"] = b"version https://git-lfs.github.com/spec/v1\n"
    else: (tmp_path / "cptc_harness/resources/portcast-python-runtime-v1.json").unlink()
    if mutation != "missing_lock":
        source = inventory["components"][0]["corresponding_source"]; archive = tmp_path / source["archive"]; write_outer(archive, outer)
        source["sha256"] = sha(archive.read_bytes()); source["bytes"] = archive.stat().st_size
        meta = tmp_path / source["metadata_path"]; meta.write_text(json.dumps(metadata, sort_keys=True)); source["metadata_sha256"] = sha(meta.read_bytes())
    with pytest.raises(ValueError): package.verify_third_party_compliance(tmp_path, inventory, contents)


def test_v2_rejects_symlinked_sidecar_parent_and_nested_device(tmp_path):
    inventory, contents, _, _ = fixture(tmp_path)
    sidecar_parent = tmp_path / "docs/harness/corresponding-source"
    retained = tmp_path / "retained-sidecar"; sidecar_parent.rename(retained)
    sidecar_parent.symlink_to(retained, target_is_directory=True)
    with pytest.raises(ValueError, match="parent"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)
    reference = {"member_count": 2, "unpacked_bytes": 1}
    nested = tar_bytes([("device", b"", "device"), ("source", b"x", "file")])
    with pytest.raises(ValueError, match="unsupported"):
        package._inspect_nested(io.BytesIO(nested), reference)

@pytest.mark.parametrize("architecture", ["any", "x86_64", "x86_64_v3"])
def test_v2_accepts_canonical_distribution_package_architectures(tmp_path, architecture):
    inventory, contents, metadata, _ = fixture(tmp_path)
    metadata["distribution_package"]["architecture"] = architecture
    _rewrite_metadata(tmp_path, inventory, metadata)
    assert package.verify_source_fulfillment(tmp_path, inventory, contents)["verified"]


@pytest.mark.parametrize("field,value", [
    ("architecture", "../escape"),
    ("architecture", "X86_64"),
    ("component_version", "different"),
])
def test_v2_rejects_invalid_package_identity_fields(tmp_path, field, value):
    inventory, contents, metadata, _ = fixture(tmp_path)
    metadata["distribution_package"][field] = value
    _rewrite_metadata(tmp_path, inventory, metadata)
    with pytest.raises(ValueError, match="distribution package"):
        package.verify_source_fulfillment(tmp_path, inventory, contents)
