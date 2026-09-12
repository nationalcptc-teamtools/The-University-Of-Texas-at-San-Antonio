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
import lzma
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import PurePosixPath
from urllib.parse import urlparse
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path("docs/harness/PACKAGE-CONTENTS.json")
BUILD_ROOTS = {
    "cptc11_readonly_wave_v1", "cptc_harness", "deployment", "skills", "docs",
    "scripts", "testing", "tests", "vendor",
}
EXCLUDED_BUILD_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache"}
GENERATED_SOURCE = {"PKG-INFO", "setup.cfg", *(
    "cptc_guarded_harness.egg-info/" + name for name in (
        "PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "requires.txt", "top_level.txt"))}
WHEEL_METADATA = {"METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD"}
SOURCE_ONLY_EXCLUDES = {
    "testing/benchmark.py", "scripts/benchmark-harness.py",
    "docs/harness/TOKEN-BENCHMARK.json", "docs/harness/CPTC11-IMAGE-AUDIT.md",
}
SOURCE_ONLY_EXCLUDED_PREFIXES = ("testing/cptc11_benchmark/",)
THIRD_PARTY_INVENTORY = Path("docs/harness/THIRD-PARTY-INVENTORY.json")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_TAGGER = re.compile(r"^tagger .+ <[^<>\r\n]+> [0-9]+ [+-][0-9]{4}$")
_RECIPE_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_SRCINFO_SOURCE = re.compile(
    r"^\t(?:source|source_[A-Za-z0-9_+-]+) = (.+)$"
)
_PACKAGE_ARCH = re.compile(r"^[a-z0-9][a-z0-9_.+-]{0,63}$")
_LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\n"
MAX_SOURCE_ARCHIVE_BYTES = 256 * 1024 * 1024
# The repository safety limit applies to each deterministic outer bundle. The
# larger archive limits below protect streaming and parsing operations inside it.
MAX_SOURCE_BUNDLE_BYTES = 95 * 1024 * 1024
MAX_SOURCE_ARCHIVE_MEMBERS = 100_000
MAX_SOURCE_UNPACKED_BYTES = 1024 * 1024 * 1024
V2_DESCRIPTOR_KEYS = {
    "method", "archive", "sha256", "bytes", "archive_format", "metadata_path", "metadata_sha256",
}
V2_METADATA_KEYS = {
    "schema_version", "component", "distribution_package", "packaging_source", "upstream_sources",
    "patches", "build", "archive_members", "verified_at", "verified_by",
}
V2_COMPONENT_KEYS = {
    "name", "version", "use", "source", "license", "license_source", "copied_files",
    "distributed", "obligations", "distribution_basis", "corresponding_source", "approved_source_origins",
}


def _no_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _strict_json_loads(payload):
    return json.loads(payload, object_pairs_hook=_no_duplicate_pairs)


def excluded_source_only(name):
    return name in SOURCE_ONLY_EXCLUDES or name.startswith(SOURCE_ONLY_EXCLUDED_PREFIXES)


def reviewed_contents(root):
    value = _strict_json_loads((root / MANIFEST).read_text())
    if set(value) != {"version", "classification", "runtime", "source"} or value["version"] != 2:
        raise ValueError("invalid reviewed package manifest")
    for group in ("runtime", "source"):
        entries = value[group]
        if not isinstance(entries, list) or len(entries) != len(set(entries)):
            raise ValueError("invalid reviewed package file list")
        for name in entries:
            path = Path(name)
            if not isinstance(name, str) or path.is_absolute() or ".." in path.parts or str(path) != name:
                raise ValueError("invalid reviewed package path")
        value[group] = set(entries)
    if not value["runtime"] <= value["source"]:
        raise ValueError("reviewed distribution inputs missing from source list")
    return value


def _safe_relative(name, prefix=None):
    if not isinstance(name, str) or not name or "\\" in name:
        return False
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and "." not in path.parts
        and ".." not in path.parts
        and path.as_posix() == name
        and (prefix is None or name.startswith(prefix) and len(name) > len(prefix))
    )


def _plain_int(value, *, minimum=0):
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _text(value):
    return isinstance(value, str) and bool(value)


def _sha256(value):
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _absolute_system_path(value):
    if not _text(value) or "\\" in value:
        return False
    path = PurePosixPath(value)
    return path.is_absolute() and "." not in path.parts and ".." not in path.parts and path.as_posix() == value


def _canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _regular_file(root, relative, *, prefix=None):
    if not _safe_relative(relative, prefix):
        raise ValueError("corresponding source path is unsafe")
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError("corresponding source file is unavailable")
    if any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents):
        raise ValueError("corresponding source parent is unsafe")
    return path



V2_REF_KEYS = {"origin", "revision", "archive_member", "sha256", "archive_format", "member_count", "unpacked_bytes"}
V2_REVISION_BINDING_KEYS = {
    "recipe_selector_type", "recipe_selector", "resolved_revision",
    "recipe_manifest_path", "recipe_source",
    "binding_evidence_member", "binding_evidence_sha256",
    "tag_object_revision",
}
V2_PACKAGE_KEYS = {"name", "version", "component_version", "architecture", "package_filename", "package_sha256", "installed_file_hashes", "archive_member", "build_info_member", "build_info_sha256"}
V2_BUILD_KEYS = {"recipe_member", "source_info_member", "toolchain", "flags", "source_date_epoch", "build_log_member", "build_log_sha256", "reproducibility_status"}
MAX_OUTER_MEMBER_BYTES = 256 * 1024 * 1024
MAX_NESTED_MEMBER_BYTES = 256 * 1024 * 1024
MAX_NESTED_ARCHIVE_MEMBERS = 250_000
MAX_NESTED_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_OUTER_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_BINDING_EVIDENCE_BYTES = 256 * 1024
MAX_RECIPE_MANIFEST_BYTES = 1024 * 1024
CANONICAL_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
PORTCAST_ENTRYPOINTS = {
    "age": "bin/age",
    "bubblewrap": "bin/bwrap",
    "loader": "lib/ld-linux-x86-64.so.2",
    "python": "bin/python3.14",
    "stdlib": "lib/python3.14",
}


def _hash_stream(stream, limit, *, copy_to=None):
    digest, total, first = hashlib.sha256(), 0, b""
    while chunk := stream.read(1024 * 1024):
        total += len(chunk)
        if total > limit:
            raise ValueError("corresponding source member exceeds size limit")
        if len(first) < len(_LFS_POINTER):
            first += chunk[:len(_LFS_POINTER) - len(first)]
        digest.update(chunk)
        if copy_to is not None:
            copy_to.write(chunk)
    if first.startswith(_LFS_POINTER):
        raise ValueError("corresponding source contains an LFS pointer")
    return digest.hexdigest(), total


def _canonical_base(value):
    parsed = urlparse(value) if isinstance(value, str) else None
    if not parsed or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path.endswith("/") or "/../" in parsed.path or "/./" in parsed.path:
        raise ValueError("approved source origin is not canonical")
    return value


def _valid_git_tag(value):
    return bool(
        isinstance(value, str)
        and _TAG.fullmatch(value)
        and ".." not in value
        and not value.endswith(".")
        and not value.endswith(".lock")
    )


def _recipe_source_base(value, binding):
    if not _text(value) or len(value.encode("utf-8")) > 4096:
        raise ValueError("corresponding source recipe source is invalid")
    source = value
    if "::" in source:
        alias, source = source.split("::", 1)
        if "::" in source or _RECIPE_ALIAS.fullmatch(alias) is None:
            raise ValueError("corresponding source recipe alias is invalid")
    if not source.startswith("git+https://"):
        raise ValueError("corresponding source recipe is not Git HTTPS")
    parsed = urlparse(source[4:])
    expected_fragment = (
        f"{binding['recipe_selector_type']}={binding['recipe_selector']}"
    )
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.fragment != expected_fragment
        or parsed.query not in {"", "signed"}
        or (parsed.query == "signed" and binding["recipe_selector_type"] != "tag")
    ):
        raise ValueError("corresponding source recipe selector differs")
    path = parsed.path[:-4] if parsed.path.endswith(".git") else parsed.path
    return _canonical_base(f"https://{parsed.netloc}{path}")


def _inside_link(member, target):
    if target.startswith("/") or "\\" in target:
        return False
    parts = []
    for part in (PurePosixPath(member).parent / target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return False
            parts.pop()
        else:
            parts.append(part)
    return bool(parts)


def _validate_xz_stream(stream, *, copy_to=None):
    """Consume one xz stream and reject truncation, concatenation, or expansion."""
    stream.seek(0)
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    expanded = 0
    while chunk := stream.read(1024 * 1024):
        pending = chunk
        while pending or not decoder.needs_input:
            if decoder.eof:
                if pending or decoder.unused_data:
                    raise ValueError("nested source xz stream has trailing data")
                break
            output = decoder.decompress(pending, max_length=1024 * 1024)
            expanded += len(output)
            if expanded > MAX_NESTED_UNPACKED_BYTES:
                raise ValueError("nested source archive exceeds size limit")
            if copy_to is not None:
                copy_to.write(output)
            if decoder.eof and decoder.unused_data:
                raise ValueError("nested source xz stream has trailing data")
            pending = b""
    while not decoder.eof:
        if decoder.needs_input:
            raise ValueError("nested source xz stream is truncated")
        output = decoder.decompress(b"", max_length=1024 * 1024)
        expanded += len(output)
        if expanded > MAX_NESTED_UNPACKED_BYTES:
            raise ValueError("nested source archive exceeds size limit")
        if copy_to is not None:
            copy_to.write(output)
        if not output:
            raise ValueError("nested source xz stream is truncated")
        if decoder.unused_data:
            raise ValueError("nested source xz stream has trailing data")


def _validate_tar_end(stream, label):
    """Require two zero blocks and canonical 10,240-byte tar padding."""
    stream.seek(0)
    logical_end = 0
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for member in archive:
            end = member.offset_data + ((member.size + 511) // 512) * 512
            logical_end = max(logical_end, end)
    stream.seek(0, os.SEEK_END)
    total = stream.tell()
    canonical_total = ((logical_end + 1024 + 10239) // 10240) * 10240
    if total != canonical_total or logical_end > total:
        raise ValueError(f"{label} is not canonical")
    stream.seek(logical_end)
    remaining = total - logical_end
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk or chunk != b"\0" * len(chunk):
            raise ValueError(f"{label} has trailing data")
        remaining -= len(chunk)


def _inspect_nested(stream, reference, capture_members=()):
    archive_format = reference.get("archive_format", "tar")
    if archive_format not in {"tar", "tar.xz"}:
        raise ValueError("unsupported nested source archive format")
    temporary = tempfile.SpooledTemporaryFile(max_size=1024 * 1024)
    _hash_stream(stream, MAX_OUTER_MEMBER_BYTES, copy_to=temporary)
    temporary.seek(0)
    count = total = regular = 0; names = []
    capture_members = set(capture_members)
    captures = {}
    expanded_tar = None
    try:
        with tarfile.open(fileobj=temporary, mode="r|xz" if archive_format == "tar.xz" else "r|") as archive:
            for member in archive:
                count += 1
                name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                if count > MAX_NESTED_ARCHIVE_MEMBERS or not _safe_relative(name) or name in names:
                    raise ValueError("nested source archive is unsafe")
                names.append(name)
                if member.mtime != 0 or member.uid != 0 or member.gid != 0 or member.uname != "root" or member.gname != "root" or member.pax_headers:
                    raise ValueError("nested source archive is not deterministic")
                if member.isdir():
                    if (member.mode & 0o777) != 0o755:
                        raise ValueError("nested source archive is not deterministic")
                    continue
                if member.issym():
                    if (member.mode & 0o777) != 0o777 or not _inside_link(name, member.linkname):
                        raise ValueError("nested source symlink escapes archive")
                    continue
                if not member.isfile():
                    raise ValueError("nested source archive contains an unsupported member")
                if (member.mode & 0o777) not in {0o644, 0o755}:
                    raise ValueError("nested source archive is not deterministic")
                if member.size > MAX_NESTED_MEMBER_BYTES:
                    raise ValueError("nested source member exceeds size limit")
                total += member.size
                if total > MAX_NESTED_UNPACKED_BYTES:
                    raise ValueError("nested source archive exceeds size limit")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("nested source archive is unreadable")
                if name in capture_members:
                    capture = io.BytesIO()
                    _hash_stream(
                        source, MAX_RECIPE_MANIFEST_BYTES, copy_to=capture
                    )
                    captures[name] = capture.getvalue()
                else:
                    _hash_stream(source, MAX_NESTED_MEMBER_BYTES)
                regular += 1
        if archive_format == "tar.xz":
            expanded_tar = tempfile.SpooledTemporaryFile(max_size=1024 * 1024)
            _validate_xz_stream(temporary, copy_to=expanded_tar)
            _validate_tar_end(expanded_tar, "nested source archive")
        else:
            _validate_tar_end(temporary, "nested source archive")
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError("nested source archive is unreadable") from error
    except lzma.LZMAError as error:
        raise ValueError("nested source xz stream is unreadable") from error
    finally:
        if expanded_tar is not None:
            expanded_tar.close()
        temporary.close()
    if count < 2 or not regular or names != sorted(names) or count != reference["member_count"] or total != reference["unpacked_bytes"]:
        raise ValueError("nested source archive differs from metadata")
    if set(captures) != capture_members:
        raise ValueError("corresponding source recipe manifest is unavailable")
    return captures


def _validate_recipe_bindings(manifests, references):
    decoded = {}
    for path, payload in manifests.items():
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise ValueError(
                "corresponding source recipe manifest is unreadable"
            ) from error
        if "\x00" in text or "\r" in text:
            raise ValueError("corresponding source recipe manifest is unreadable")
        sources = []
        for line in text.split("\n"):
            match = _SRCINFO_SOURCE.fullmatch(line)
            if match is not None:
                sources.append(match.group(1))
        decoded[path] = sources
    for path, sources in decoded.items():
        vcs_sources = []
        for value in sources:
            unaliased = value.split("::", 1)[-1]
            if unaliased.startswith(("git+", "hg+", "svn+", "bzr+")):
                if not unaliased.startswith("git+https://"):
                    raise ValueError(
                        "corresponding source recipe has an unsupported VCS source"
                    )
                vcs_sources.append(value)
        declared = [
            reference["revision_binding"]["recipe_source"]
            for reference in references
            if reference["revision_binding"]["recipe_manifest_path"] == path
        ]
        if sorted(vcs_sources) != sorted(declared):
            raise ValueError(
                "corresponding source recipe VCS sources differ from revision bindings"
            )


def _verify_canonical_gzip(path):
    if path.stat().st_size >= MAX_SOURCE_BUNDLE_BYTES:
        raise ValueError("corresponding source outer archive exceeds repository safety limit")
    decompressed = tempfile.SpooledTemporaryFile(max_size=1024 * 1024)
    try:
        with path.open("rb") as handle:
            if handle.read(10) != CANONICAL_GZIP_HEADER:
                raise ValueError("corresponding source outer archive is not deterministic")
            handle.seek(0)
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            expanded = 0
            while chunk := handle.read(16 * 1024):
                pending = chunk
                while pending:
                    data = decompressor.decompress(pending, 2 * 1024 * 1024)
                    decompressed.write(data)
                    expanded += len(data)
                    if expanded > MAX_OUTER_UNPACKED_BYTES:
                        raise ValueError("corresponding source outer archive exceeds size limit")
                    pending = decompressor.unconsumed_tail
                    if decompressor.eof:
                        if decompressor.unused_data or pending or handle.read(1):
                            raise ValueError("corresponding source outer archive has trailing data")
                        _validate_tar_end(decompressed, "corresponding source outer archive")
                        return
            if not decompressor.eof:
                raise ValueError("corresponding source outer archive is truncated")
    finally:
        decompressed.close()


def _validate_revision_binding(value, revision, role, bases):
    if (
        not isinstance(value, dict)
        or set(value) != V2_REVISION_BINDING_KEYS
        or value.get("resolved_revision") != revision
        or value.get("recipe_manifest_path") != ".SRCINFO"
        or _recipe_source_base(value.get("recipe_source"), value) not in bases
    ):
        raise ValueError(f"corresponding source {role} revision binding differs")
    selector_type = value.get("recipe_selector_type")
    if selector_type == "commit":
        if value.get("recipe_selector") != revision or any(
            value.get(key) is not None
            for key in (
                "binding_evidence_member", "binding_evidence_sha256",
                "tag_object_revision",
            )
        ):
            raise ValueError(
                f"corresponding source {role} commit binding differs"
            )
        return
    if (
        selector_type != "tag"
        or not _valid_git_tag(value.get("recipe_selector"))
        or not _safe_relative(
            value.get("binding_evidence_member"),
            "evidence/revision-bindings/",
        )
        or not _sha256(value.get("binding_evidence_sha256"))
        or not isinstance(value.get("tag_object_revision"), str)
        or _COMMIT.fullmatch(value["tag_object_revision"]) is None
        or len(value["tag_object_revision"]) != len(revision)
    ):
        raise ValueError(f"corresponding source {role} tag binding differs")


def _validate_ref(value, bases, role, *, require_binding=False):
    allowed_keys = V2_REF_KEYS | ({"revision_binding"} if require_binding else set())
    if (
        not isinstance(value, dict)
        or set(value) != allowed_keys
        or value["archive_format"] not in {"tar", "tar.xz"}
        or not _safe_relative(value["archive_member"], "sources/")
        or not _sha256(value["sha256"])
        or not _plain_int(value["member_count"], minimum=2)
        or not _plain_int(value["unpacked_bytes"], minimum=1)
    ):
        raise ValueError(f"corresponding source {role} metadata differs")
    revision = value["revision"]
    if not isinstance(revision, str) or _COMMIT.fullmatch(revision) is None:
        raise ValueError(f"corresponding source {role} revision is not immutable")
    valid = {f"{base}/commit/{revision}" for base in bases} | {f"{base}/-/commit/{revision}" for base in bases}
    parsed = urlparse(value["origin"]) if isinstance(value["origin"], str) else None
    if not parsed or parsed.query or parsed.fragment or parsed.username or parsed.password or value["origin"] not in valid:
        raise ValueError(f"corresponding source {role} origin is not approved")
    if require_binding:
        _validate_revision_binding(value["revision_binding"], revision, role, bases)


def _validate_tag_object(payload, binding):
    if not isinstance(payload, bytes) or len(payload) > MAX_BINDING_EVIDENCE_BYTES:
        raise ValueError("corresponding source tag binding evidence is too large")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ValueError(
            "corresponding source tag binding evidence is unreadable"
        ) from error
    if "\x00" in text or "\n\n" not in text:
        raise ValueError("corresponding source tag binding evidence differs")
    headers = text.split("\n\n", 1)[0].splitlines()
    expected = (
        f"object {binding['resolved_revision']}",
        "type commit",
        f"tag {binding['recipe_selector']}",
    )
    if (
        len(headers) != 4
        or tuple(headers[:3]) != expected
        or _TAGGER.fullmatch(headers[3]) is None
    ):
        raise ValueError("corresponding source tag binding evidence differs")
    object_bytes = b"tag " + str(len(payload)).encode("ascii") + b"\0" + payload
    expected_identity = binding["tag_object_revision"]
    observed_identity = (
        hashlib.sha1(object_bytes, usedforsecurity=False).hexdigest()
        if len(expected_identity) == 40
        else hashlib.sha256(object_bytes).hexdigest()
    )
    if observed_identity != expected_identity:
        raise ValueError("corresponding source tag object identity differs")


def _validate_v2_metadata_strict(root, component, descriptor, contents):
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != V2_DESCRIPTOR_KEYS
        or descriptor["method"] != "exact_archive"
        or descriptor["archive_format"] != "tar.gz"
        or not _safe_relative(descriptor["archive"], "vendor/corresponding-source/")
        or not _safe_relative(descriptor["metadata_path"], "docs/harness/corresponding-source/")
        or not _sha256(descriptor["sha256"])
        or not _sha256(descriptor["metadata_sha256"])
        or not _plain_int(descriptor["bytes"], minimum=1)
    ):
        raise ValueError("corresponding source descriptor differs")
    archive = _regular_file(root, descriptor["archive"], prefix="vendor/corresponding-source/")
    sidecar = _regular_file(root, descriptor["metadata_path"], prefix="docs/harness/corresponding-source/")
    _verify_canonical_gzip(archive)
    if descriptor["archive"] not in contents["source"] or descriptor["metadata_path"] not in contents["source"] or descriptor["archive"] in contents["runtime"] or descriptor["metadata_path"] in contents["runtime"] or descriptor["bytes"] != archive.stat().st_size or descriptor["bytes"] >= MAX_SOURCE_BUNDLE_BYTES or _file_sha256(archive) != descriptor["sha256"] or _file_sha256(sidecar) != descriptor["metadata_sha256"]:
        raise ValueError("corresponding source descriptor differs")
    try:
        metadata = _strict_json_loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("corresponding source metadata is unreadable") from error
    if not isinstance(metadata, dict) or set(metadata) != V2_METADATA_KEYS or metadata.get("schema_version") != 1 or metadata.get("component") != component["name"] or not isinstance(metadata.get("verified_by"), str) or not metadata["verified_by"] or not isinstance(metadata.get("verified_at"), str) or _UTC.fullmatch(metadata["verified_at"]) is None:
        raise ValueError("corresponding source metadata differs")
    approved = component["approved_source_origins"]
    if not isinstance(approved, dict) or set(approved) != {"packaging", "upstream"} or not all(isinstance(approved[k], list) and approved[k] for k in approved):
        raise ValueError("approved source origins differ")
    approved = {key: [_canonical_base(base) for base in values] for key, values in approved.items()}
    _validate_ref(metadata["packaging_source"], approved["packaging"], "packaging source")
    if not isinstance(metadata["upstream_sources"], list) or not metadata["upstream_sources"]:
        raise ValueError("corresponding source upstream metadata differs")
    for reference in metadata["upstream_sources"]:
        _validate_ref(
            reference,
            approved["upstream"],
            "upstream source",
            require_binding=True,
        )
    package = metadata["distribution_package"]
    if not isinstance(package, dict) or set(package) != V2_PACKAGE_KEYS or not _text(package.get("name")) or not _text(package.get("version")) or package.get("component_version") != component["version"] or not isinstance(package.get("architecture"), str) or _PACKAGE_ARCH.fullmatch(package["architecture"]) is None or not _text(package.get("package_filename")) or PurePosixPath(package["package_filename"]).name != package["package_filename"] or not isinstance(package.get("installed_file_hashes"), dict) or not _sha256(package.get("package_sha256")) or not _sha256(package.get("build_info_sha256")) or not _safe_relative(package.get("archive_member"), "evidence/") or not _safe_relative(package.get("build_info_member"), "evidence/"):
        raise ValueError("corresponding source distribution package metadata differs")
    if set(package["installed_file_hashes"]) != set(component["copied_files"]) or not all(_sha256(digest) for digest in package["installed_file_hashes"].values()):
        raise ValueError("corresponding source installed file set differs")
    build = metadata["build"]
    if not isinstance(build, dict) or set(build) != V2_BUILD_KEYS or not _safe_relative(build.get("recipe_member"), "sources/") or not _safe_relative(build.get("source_info_member"), "sources/") or not _text(build.get("toolchain")) or not isinstance(build.get("flags"), list) or not all(_text(flag) for flag in build["flags"]) or build.get("reproducibility_status") not in {"metadata-only", "reproduced"}:
        raise ValueError("corresponding source build metadata differs")
    if build["reproducibility_status"] == "metadata-only":
        if any(build[key] is not None for key in ("source_date_epoch", "build_log_member", "build_log_sha256")):
            raise ValueError("metadata-only build evidence differs")
    elif not _plain_int(build["source_date_epoch"], minimum=1) or not _safe_relative(build["build_log_member"], "evidence/") or not _sha256(build["build_log_sha256"]):
        raise ValueError("reproduced build evidence differs")
    patches = metadata["patches"]
    if not isinstance(patches, list):
        raise ValueError("corresponding source patch metadata differs")
    for patch in patches:
        if (
            not isinstance(patch, dict)
            or set(patch) != {"archive_member", "sha256"}
            or not _safe_relative(patch.get("archive_member"), "patches/")
            or not _sha256(patch.get("sha256"))
        ):
            raise ValueError("corresponding source patch metadata differs")
    declared = metadata["archive_members"]
    if not isinstance(declared, list) or len(declared) > MAX_SOURCE_ARCHIVE_MEMBERS:
        raise ValueError("corresponding source member metadata differs")
    expected = {
        item["path"]: item
        for item in declared
        if isinstance(item, dict)
        and set(item) == {"path", "sha256", "bytes"}
        and _safe_relative(item["path"])
        and _sha256(item["sha256"])
        and _plain_int(item["bytes"])
    }
    if len(expected) != len(declared) or list(expected) != sorted(expected):
        raise ValueError("corresponding source member metadata differs")
    references = [metadata["packaging_source"], *metadata["upstream_sources"]]
    wanted = {item["archive_member"]: item for item in references}
    if len(wanted) != len(references):
        raise ValueError("corresponding source reference members differ")
    tag_bindings = {
        reference["revision_binding"]["binding_evidence_member"]:
            reference["revision_binding"]
        for reference in metadata["upstream_sources"]
        if reference["revision_binding"]["recipe_selector_type"] == "tag"
    }
    expected_tag_bindings = sum(
        reference["revision_binding"]["recipe_selector_type"] == "tag"
        for reference in metadata["upstream_sources"]
    )
    if (
        len(tag_bindings) != expected_tag_bindings
        or set(tag_bindings).intersection(wanted)
    ):
        raise ValueError("corresponding source tag binding members differ")
    role_members = [
        package["archive_member"],
        package["build_info_member"],
        *(reference["archive_member"] for reference in references),
        *tag_bindings,
        *(patch["archive_member"] for patch in patches),
    ]
    if build["reproducibility_status"] == "reproduced":
        role_members.append(build["build_log_member"])
    if len(role_members) != len(set(role_members)) or set(expected) != set(role_members):
        raise ValueError("corresponding source evidence roles differ")
    recipe_manifest_paths = {
        reference["revision_binding"]["recipe_manifest_path"]
        for reference in metadata["upstream_sources"]
    }
    recipe_manifests = {}
    observed = {}
    try:
        with tarfile.open(archive, "r|gz") as outer:
            for member in outer:
                if not member.isfile() or not _safe_relative(member.name) or member.name in observed or member.name not in expected or member.size > MAX_OUTER_MEMBER_BYTES or member.mtime != 0 or member.uid != 0 or member.gid != 0 or member.uname != "root" or member.gname != "root" or (member.mode & 0o777) not in {0o644, 0o755} or member.pax_headers:
                    raise ValueError("corresponding source outer archive is unsafe")
                stream = outer.extractfile(member)
                if stream is None: raise ValueError("corresponding source outer archive is unreadable")
                temporary = (
                    tempfile.SpooledTemporaryFile(max_size=1024 * 1024)
                    if member.name in wanted or member.name in tag_bindings
                    else None
                )
                digest, size = _hash_stream(stream, MAX_OUTER_MEMBER_BYTES, copy_to=temporary)
                observed[member.name] = {"path": member.name, "sha256": digest, "bytes": size}
                if temporary is not None:
                    try:
                        if member.name in wanted:
                            if digest != wanted[member.name]["sha256"]:
                                raise ValueError("corresponding source nested archive hash differs")
                            temporary.seek(0)
                            captures = _inspect_nested(
                                temporary,
                                wanted[member.name],
                                recipe_manifest_paths
                                if member.name
                                == metadata["packaging_source"]["archive_member"]
                                else (),
                            )
                            recipe_manifests.update(captures)
                        else:
                            binding = tag_bindings[member.name]
                            if digest != binding["binding_evidence_sha256"]:
                                raise ValueError("corresponding source tag binding hash differs")
                            temporary.seek(0)
                            _validate_tag_object(
                                temporary.read(MAX_BINDING_EVIDENCE_BYTES + 1), binding
                            )
                    finally:
                        temporary.close()
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError("corresponding source outer archive is unreadable") from error
    if observed != expected or list(observed) != sorted(observed): raise ValueError("corresponding source outer archive members differ")
    if any(member not in observed for member in tag_bindings):
        raise ValueError("corresponding source tag binding evidence is unavailable")
    _validate_recipe_bindings(recipe_manifests, metadata["upstream_sources"])
    for patch in patches:
        if patch["archive_member"] not in observed or patch["sha256"] != observed[patch["archive_member"]]["sha256"]:
            raise ValueError("corresponding source patch metadata differs")
    for key in ("archive_member", "build_info_member"):
        if not _safe_relative(package[key], "evidence/") or package[key] not in observed: raise ValueError("package evidence is unavailable")
    if package["package_sha256"] != observed[package["archive_member"]]["sha256"] or package["build_info_sha256"] != observed[package["build_info_member"]]["sha256"]: raise ValueError("package evidence hash differs")
    if build["recipe_member"] != metadata["packaging_source"]["archive_member"] or build["source_info_member"] not in wanted: raise ValueError("build source evidence differs")
    if build["reproducibility_status"] == "reproduced" and (build["build_log_member"] not in observed or observed[build["build_log_member"]]["sha256"] != build["build_log_sha256"]): raise ValueError("build log evidence differs")
    return {"component": component["name"], "archive": descriptor["archive"], "archive_sha256": descriptor["sha256"], "metadata": descriptor["metadata_path"], "metadata_sha256": descriptor["metadata_sha256"]}


def _file_sha256(path):
    with path.open("rb") as handle: return _hash_stream(handle, MAX_SOURCE_ARCHIVE_BYTES)[0]


def _https(value):
    parsed = urlparse(value) if isinstance(value, str) else None
    return bool(
        parsed
        and parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )


def _validate_inventory_v2(value):
    required = {"version", "classification", "reviewed_at", "reviewed_by", "copied_external_source_files", "components"}
    if not isinstance(value, dict) or set(value) != required or value.get("version") != 2 or value.get("classification") != "public-development-metadata" or not isinstance(value.get("reviewed_at"), str) or _UTC.fullmatch(value["reviewed_at"]) is None or not isinstance(value.get("reviewed_by"), str) or not value["reviewed_by"] or not isinstance(value.get("copied_external_source_files"), list) or not isinstance(value.get("components"), list): raise ValueError("invalid third-party inventory")
    copied = value["copied_external_source_files"]
    if copied != sorted(set(copied)) or not all(_safe_relative(item, "vendor/") for item in copied): raise ValueError("invalid copied-file inventory")
    names, owners = set(), set()
    for component in value["components"]:
        if not isinstance(component, dict) or set(component) != V2_COMPONENT_KEYS: raise ValueError("invalid third-party component")
        for key in ("name", "version", "use", "license"):
            if not isinstance(component[key], str) or not component[key]: raise ValueError("invalid third-party component")
        if component["name"] in names or not _https(component["source"]) or not _https(component["license_source"]) or not isinstance(component["distributed"], bool) or component["distribution_basis"] not in {"permissive", "copyleft-source-required"}: raise ValueError("invalid third-party component")
        names.add(component["name"])
        files = component["copied_files"]
        if not isinstance(files, list) or files != sorted(set(files)) or not all(_safe_relative(item, "vendor/") for item in files) or owners.intersection(files): raise ValueError("invalid copied-file ownership")
        if component["distributed"]:
            if not files:
                raise ValueError("distributed component has no copied files")
            owners.update(files)
        elif files:
            raise ValueError("non-distributed component owns copied files")
        if not isinstance(component["obligations"], list) or not component["obligations"] or not all(isinstance(item, str) and item for item in component["obligations"]): raise ValueError("invalid third-party component")
        origins = component["approved_source_origins"]
        if not isinstance(origins, dict) or set(origins) != {"packaging", "upstream"} or not all(isinstance(origins[key], list) for key in origins): raise ValueError("invalid approved source origins")
        if not component["distributed"] or component["distribution_basis"] == "permissive":
            if component["corresponding_source"] is not None or origins["packaging"] or origins["upstream"]: raise ValueError("component has unexpected source evidence")
        elif not origins["packaging"] or not origins["upstream"] or not isinstance(component["corresponding_source"], dict): raise ValueError("distributed copyleft source compliance is incomplete")
        else:
            for role in origins:
                if origins[role] != sorted(set(origins[role])): raise ValueError("invalid approved source origins")
                for origin in origins[role]: _canonical_base(origin)
    if owners != set(copied): raise ValueError("inventory copied-file ownership differs")


def verify_source_fulfillment(root, inventory=None, contents=None):
    value = _strict_json_loads((root / THIRD_PARTY_INVENTORY).read_text()) if inventory is None else inventory
    if not isinstance(value, dict) or value.get("version") != 2: raise ValueError("release compliance requires inventory version 2")
    if contents is None: contents = reviewed_contents(root)
    _validate_inventory_v2(value)
    archives = []
    for component in value["components"]:
        if not component["distributed"]: continue
        if component.get("distribution_basis") == "permissive":
            if component.get("corresponding_source") is not None: raise ValueError("permissive component has unexpected source")
            continue
        if component.get("distribution_basis") != "copyleft-source-required" or not isinstance(component.get("corresponding_source"), dict): raise ValueError("distributed copyleft source compliance is incomplete")
        archives.append(_validate_v2_metadata_strict(root, component, component["corresponding_source"], contents))
    return {"inventory_sha256": _canonical_sha256(value), "source_archives": sorted(archives, key=lambda item: item["component"]), "verified": True}


def _string_map(value, *, nested=False):
    if not isinstance(value, dict):
        return False
    if nested:
        return all(_text(name) and isinstance(item, dict) for name, item in value.items())
    return all(_text(name) and _text(item) for name, item in value.items())


def _validate_python_runtime_metadata(lock):
    packages = lock["packages"]
    roots = lock["import_roots"]
    native = lock["native_files"]
    if not packages or not _string_map(packages) or not isinstance(roots, list) or not roots or roots != sorted(set(roots)) or not all(_text(name) and "/" not in name and "\\" not in name for name in roots):
        raise ValueError("runtime lock differs")
    if not isinstance(native, dict) or not native:
        raise ValueError("runtime lock differs")
    for requested, record in native.items():
        if not _absolute_system_path(requested) or not isinstance(record, dict) or set(record) != {"resolved_path", "sha256"} or not _absolute_system_path(record["resolved_path"]) or not _sha256(record["sha256"]):
            raise ValueError("runtime lock differs")


def _validate_rootfs_runtime_metadata(lock):
    entrypoints = lock["entrypoints"]
    packages = lock["packages"]
    elf_files = lock["elf_files"]
    build_tools = lock["build_tools"]
    external_tools = lock["external_tools"]
    transformations = lock["transformations"]
    if entrypoints != PORTCAST_ENTRYPOINTS:
        raise ValueError("runtime lock differs")
    if not isinstance(packages, dict) or not packages:
        raise ValueError("runtime lock differs")
    for name, record in packages.items():
        if not _text(name) or not isinstance(record, dict) or set(record) != {"license", "version"} or not _text(record["license"]) or not _text(record["version"]):
            raise ValueError("runtime lock differs")
    if not isinstance(elf_files, dict) or not elf_files or not all(_safe_relative(name) and _sha256(digest) and lock["files"].get(name) == digest for name, digest in elf_files.items()):
        raise ValueError("runtime lock differs")
    if not isinstance(build_tools, dict) or set(build_tools) != {"go", "launcher_argv", "launcher_environment", "patchelf"} or not _text(build_tools["go"]) or not _text(build_tools["patchelf"]):
        raise ValueError("runtime lock differs")
    if build_tools["launcher_argv"] != ["/usr/sbin/go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", "deployment/portcast-bootstrap", "deployment/portcast-bootstrap.go"] or not build_tools["go"].startswith("go version go") or not build_tools["patchelf"].startswith("patchelf "):
        raise ValueError("runtime lock differs")
    environment = build_tools["launcher_environment"]
    if environment != {"CGO_ENABLED": "0", "GOCACHE": "operator-owned-empty-cache", "GOENV": "off", "GOTOOLCHAIN": "local", "PATH": "/usr/sbin:/usr/bin"}:
        raise ValueError("runtime lock differs")
    if not isinstance(external_tools, dict) or set(external_tools) != {"age"}:
        raise ValueError("runtime lock differs")
    for name, record in external_tools.items():
        if not _text(name) or not isinstance(record, dict) or set(record) != {"license", "sha256", "source", "version"} or not _text(record["license"]) or not _text(record["version"]) or not _sha256(record["sha256"]) or not _https(record["source"]):
            raise ValueError("runtime lock differs")
        entrypoint = entrypoints.get(name)
        if entrypoint is not None and lock["files"].get(entrypoint) != record["sha256"]:
            raise ValueError("runtime lock differs")
    if not isinstance(transformations, list) or len(transformations) != 1:
        raise ValueError("runtime lock differs")
    for record in transformations:
        if record != {"operation": "remove RPATH and RUNPATH", "scope": "elf_files", "tool": build_tools["patchelf"]}:
            raise ValueError("runtime lock differs")


def _verify_runtime_locks_strict(root):
    specs = (("cptc_harness/resources/portcast-python-runtime-v1.json", "vendor/portcast-python3.14/site-packages", {"schema_version", "python_abi", "root", "packages", "import_roots", "files", "native_files"}), ("cptc_harness/resources/portcast-cpython-runtime-v1.json", "vendor/portcast-rootfs-runtime", {"schema_version", "python_abi", "root", "entrypoints", "packages", "files", "elf_files", "build_tools", "external_tools", "transformations"}))
    loaded = {}
    for relative, fixed_root, keys in specs:
        lock_path = _regular_file(root, relative)
        try: lock = _strict_json_loads(lock_path.read_text())
        except json.JSONDecodeError as error: raise ValueError("runtime lock is unreadable") from error
        if not isinstance(lock, dict) or set(lock) != keys or type(lock.get("schema_version")) is not int or lock["schema_version"] != 1 or lock.get("root") != fixed_root or lock.get("python_abi") != "cp314-x86_64-linux-gnu" or not isinstance(lock.get("files"), dict) or not lock["files"]: raise ValueError("runtime lock differs")
        if list(lock["files"]) != sorted(lock["files"]) or not all(_safe_relative(name) and _sha256(digest) for name, digest in lock["files"].items()): raise ValueError("runtime lock differs")
        if fixed_root.endswith("site-packages"):
            _validate_python_runtime_metadata(lock)
        else:
            _validate_rootfs_runtime_metadata(lock)
        runtime = root / fixed_root
        if not runtime.is_dir() or runtime.is_symlink(): raise ValueError("runtime root is unavailable")
        physical = {}
        for path in runtime.rglob("*"):
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode): continue
            if not stat.S_ISREG(mode): raise ValueError("runtime contains a symlink or special file")
            physical[path.relative_to(runtime).as_posix()] = path
        if not physical or set(physical) != set(lock["files"]): raise ValueError("runtime lock file set differs")
        for name, path in physical.items():
            if _HEX64.fullmatch(lock["files"][name]) is None or _file_sha256(path) != lock["files"][name]: raise ValueError("runtime lock file hash differs")
        if not fixed_root.endswith("site-packages"):
            for path in lock["entrypoints"].values():
                candidate = runtime / path
                if candidate.is_symlink() or not candidate.exists() or not (candidate.is_file() or candidate.is_dir()):
                    raise ValueError("runtime lock entrypoint differs")
            physical_elf = {
                name for name, path in physical.items()
                if path.open("rb").read(4) == b"\x7fELF"
            }
            if set(lock["elf_files"]) != physical_elf:
                raise ValueError("runtime lock ELF set differs")
        loaded[fixed_root] = lock
    python_lock = loaded["vendor/portcast-python3.14/site-packages"]
    rootfs_lock = loaded["vendor/portcast-rootfs-runtime"]
    for requested, record in python_lock["native_files"].items():
        runtime_name = f"lib/{PurePosixPath(requested).name}"
        if (
            rootfs_lock["elf_files"].get(runtime_name) != record["sha256"]
            or rootfs_lock["files"].get(runtime_name) != record["sha256"]
        ):
            raise ValueError("runtime native dependency evidence differs")


def verify_third_party_compliance(root, inventory=None, contents=None, fulfillment=None):
    actual = verify_source_fulfillment(root, inventory, contents)
    if fulfillment is not None and fulfillment != actual: raise ValueError("supplied source fulfillment differs from recomputed fulfillment")
    fulfillment = actual
    value = _strict_json_loads((root / THIRD_PARTY_INVENTORY).read_text()) if inventory is None else inventory
    physical = {}
    for path in (root / "vendor").rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode): continue
        if not stat.S_ISREG(mode): raise ValueError("vendor contains a symlink or special file")
        physical[path.relative_to(root).as_posix()] = path
    copied = {name for component in value["components"] if component.get("distributed") for name in component["copied_files"]}
    retained = {item["archive"] for item in fulfillment["source_archives"]}
    if set(physical) - copied - retained or copied - set(physical) or value["copied_external_source_files"] != sorted(copied): raise ValueError("unowned vendor file prevents corresponding source compliance")
    for component in value["components"]:
        if not component["distributed"] or component["distribution_basis"] != "copyleft-source-required": continue
        sidecar = _regular_file(root, component["corresponding_source"]["metadata_path"], prefix="docs/harness/corresponding-source/")
        package = _strict_json_loads(sidecar.read_text(encoding="utf-8"))["distribution_package"]
        for name, digest in package["installed_file_hashes"].items():
            if _file_sha256(_regular_file(root, name, prefix="vendor/")) != digest: raise ValueError("corresponding source installed file hash differs")
    _verify_runtime_locks_strict(root)
    return fulfillment


def receipt_name(version):
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(version)).strip(".-")
    if not safe:
        raise ValueError("unsafe package version for receipt")
    return f"BUILD-RECEIPT-{safe}.json"


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
    return [name for name in names if not excluded_source_only(name)]


def verify_wheel(wheel, contents, version):
    expected = contents["runtime"] | {f"cptc_guarded_harness-{version}.dist-info/{name}" for name in WHEEL_METADATA}
    names = wheel.namelist()
    unsafe = False
    for info in wheel.infolist():
        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if info.is_dir() or file_type not in {0, stat.S_IFREG}:
            unsafe = True
            break
    if len(names) != len(set(names)) or set(names) != expected or unsafe or wheel.testzip() is not None:
        raise ValueError("runtime wheel differs from reviewed file allowlist")


def verify_installed_scanner_catalog(path):
    """Extract the pure-Python wheel and load its packaged scanner catalog."""
    with tempfile.TemporaryDirectory(prefix="cptc-wheel-smoke-") as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(path) as wheel:
            wheel.extractall(root)
        code = (
            "import sys; "
            f"sys.path.insert(0, {str(root)!r}); "
            "from cptc_harness.host_profile_catalog import HOST_PROFILE_ID, load_host_profile_catalog; "
            "from cptc_harness.profile_runtime.catalog import load_catalog as load_bounded_catalog; "
            "from cptc_harness.profiles.common_mysql.parser import _catalog as load_mysql_catalog; "
            "from cptc_harness.profiles.common_tls.parser import _catalog as load_tls_catalog; "
            "from cptc_harness.scanner_catalog import PROFILE_IDS, load_catalog; "
            "from cptc_harness.scanner_catalog_v2 import PROFILE_ID_V2, load_catalog_v2; "
            "assert tuple(p.profile_id for p in load_host_profile_catalog().profiles) == (HOST_PROFILE_ID,); "
            "assert tuple(p.profile_id for p in load_catalog()) == PROFILE_IDS; "
            "assert tuple(p.profile_id for p in load_catalog_v2().profiles) == (PROFILE_ID_V2,); "
            "assert load_bounded_catalog().profiles; "
            "assert load_mysql_catalog()['schema_version'] == 1; "
            "assert load_tls_catalog()['schema_version'] == 1"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
        )
        if completed.returncode:
            raise ValueError("installed wheel cannot load its reviewed scanner catalog")


def tar_bytes(entries, epoch):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, payload, executable in sorted(entries):
            member = tarfile.TarInfo(name)
            member.size = len(payload); member.mtime = epoch
            member.mode = 0o755 if executable else 0o644
            member.uid = member.gid = 0; member.uname = member.gname = "root"
            archive.addfile(member, io.BytesIO(payload))
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", fileobj=compressed, mode="wb", compresslevel=9, mtime=0
    ) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue()


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
            if excluded_source_only(name) or name in names or name not in contents["source"] | GENERATED_SOURCE:
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
            verify_installed_scanner_catalog(path)
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
    third_party_compliance = verify_third_party_compliance(ROOT, contents=contents)
    paths = physical_distribution_inputs(ROOT)
    verify_source_inputs(ROOT, contents, paths)
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cptc-private-build-") as temporary:
        base = Path(temporary); one = base / "one"; two = base / "two"; one.mkdir(); two.mkdir()
        artifacts = build(one, args.epoch, contents, version)
        repeated = build(two, args.epoch, contents, version)
        if artifacts != repeated: raise ValueError("independent builds differ")
        for name, data in artifacts.items():
            destination = args.output / name
            if destination.exists() and destination.read_bytes() != data:
                raise ValueError("refusing to replace a different existing build artifact")
            destination.write_bytes(data)
        receipt = {"version": version, "classification": "public-development-metadata", "source_date_epoch": args.epoch,
            "reviewed_contents_sha256": hashlib.sha256((ROOT / MANIFEST).read_bytes()).hexdigest(),
            "third_party_compliance": third_party_compliance,
            "independent_builds_equal": True, "source_archive_normalization": "sorted regular members; fixed uid/gid/modes/mtime; deterministic gzip",
            "runtime_wheel_excludes_test_data": True, "ai_harness_only": True,
            "artifacts": [{"file": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(artifacts.items())],
            "uploaded": False, "competition_accepted": False}
        receipt_path = args.output / receipt_name(version)
        receipt_data = (json.dumps(receipt, indent=2) + "\n").encode()
        if receipt_path.exists() and receipt_path.read_bytes() != receipt_data:
            raise ValueError("refusing to replace a different existing build receipt")
        receipt_path.write_bytes(receipt_data)
        print(json.dumps(receipt, indent=2))


if __name__ == "__main__": main()
