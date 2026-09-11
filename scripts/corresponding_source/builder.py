#!/usr/bin/env python3
"""Build deterministic, source-only corresponding-source bundles offline."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tempfile
from urllib.parse import urlparse


CANONICAL_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
MAX_BUNDLE_BYTES = 95 * 1024 * 1024
MAX_INPUT_FILE_BYTES = 256 * 1024 * 1024
MAX_NESTED_MEMBERS = 250_000
MAX_NESTED_MEMBER_BYTES = 256 * 1024 * 1024
MAX_NESTED_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_OUTER_MEMBERS = 100_000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ARCHITECTURE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_TAGGER = re.compile(r"^tagger .+ <[^<>\r\n]+> [0-9]+ [+-][0-9]{4}$")
_RECIPE_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_SRCINFO_SOURCE = re.compile(
    r"^\t(?:source|source_[A-Za-z0-9_+-]+) = (.+)$"
)
_LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\n"
MAX_RECIPE_MANIFEST_BYTES = 1024 * 1024

COMPONENT_KEYS = {
    "name", "version", "use", "source", "license", "license_source", "copied_files",
    "distributed", "obligations", "distribution_basis", "approved_source_origins",
}
PACKAGE_KEYS = {
    "name", "version", "component_version", "architecture", "package_filename", "package_sha256",
    "installed_file_hashes", "archive_member", "build_info_member", "build_info_sha256", "input",
}
PACKAGE_INPUT_KEYS = {"package", "build_info"}
REF_KEYS = {
    "origin", "revision", "archive_member", "input_path", "sha256", "archive_format",
    "member_count", "unpacked_bytes",
}
REVISION_BINDING_KEYS = {
    "recipe_selector_type", "recipe_selector", "resolved_revision",
    "recipe_manifest_path", "recipe_source",
    "binding_evidence_member", "binding_evidence_input",
    "binding_evidence_sha256", "tag_object_revision",
}
BUILD_KEYS = {
    "recipe_member", "source_info_member", "toolchain", "flags", "source_date_epoch",
    "build_log_member", "build_log_sha256", "reproducibility_status",
}
PATCH_KEYS = {"archive_member", "input_path", "sha256"}
SPEC_KEYS = {
    "schema_version", "component", "distribution_package", "packaging_source", "upstream_sources",
    "patches", "build", "verified_at", "verified_by",
}


class BuildError(ValueError):
    """A refused or invalid source-bundle build."""


def _fail(message: str):
    raise BuildError(message)


def _no_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError("spec JSON is unreadable") from error


def _keys(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        _fail("spec schema differs")


def _text(value):
    return isinstance(value, str) and bool(value)


def _plain_int(value, minimum=0):
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _sha256(value):
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _safe_relative(value, prefix=None):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and "." not in path.parts
        and ".." not in path.parts
        and path.as_posix() == value
        and (prefix is None or value.startswith(prefix) and len(value) > len(prefix))
    )


def _regular_file(root: Path, relative: str):
    if not _safe_relative(relative):
        _fail("input path is unsafe")
    path = root / relative
    if not path.is_file() or path.is_symlink():
        _fail("input path is unavailable or is a symlink")
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            _fail("input path has a symlinked parent")
    if path.stat().st_size > MAX_INPUT_FILE_BYTES:
        _fail("input file exceeds size limit")
    return path


def _root(path: Path, label: str):
    if path.is_symlink() or not path.is_dir():
        _fail(f"{label} is not a real directory")
    return path


def _hash_file(path: Path, *, copy_to=None, limit=MAX_INPUT_FILE_BYTES):
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                _fail("input file exceeds size limit")
            digest.update(chunk)
            if copy_to is not None:
                copy_to.write(chunk)
    return digest.hexdigest(), total


def _canonical_base(value):
    parsed = urlparse(value) if isinstance(value, str) else None
    if (
        not parsed or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        or parsed.params or parsed.query or parsed.fragment or parsed.path.endswith("/")
        or ".." in PurePosixPath(parsed.path).parts or "." in PurePosixPath(parsed.path).parts
        or PurePosixPath(parsed.path).as_posix() != parsed.path
    ):
        _fail("approved source origin is not canonical")
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
        _fail("recipe source is invalid")
    source = value
    if "::" in source:
        alias, source = source.split("::", 1)
        if "::" in source or _RECIPE_ALIAS.fullmatch(alias) is None:
            _fail("recipe source alias is invalid")
    if not source.startswith("git+https://"):
        _fail("recipe source is not an approved Git HTTPS source")
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
        _fail("recipe source selector differs")
    path = parsed.path[:-4] if parsed.path.endswith(".git") else parsed.path
    base = f"https://{parsed.netloc}{path}"
    return _canonical_base(base)


def _validate_revision_binding(binding, revision, approved):
    _keys(binding, REVISION_BINDING_KEYS)
    if (
        binding["resolved_revision"] != revision
        or binding["recipe_manifest_path"] != ".SRCINFO"
        or _recipe_source_base(binding["recipe_source"], binding) not in approved
    ):
        _fail("source revision binding differs")
    selector_type = binding["recipe_selector_type"]
    if selector_type == "commit":
        if binding["recipe_selector"] != revision or any(
            binding[key] is not None
            for key in (
                "binding_evidence_member", "binding_evidence_input",
                "binding_evidence_sha256", "tag_object_revision",
            )
        ):
            _fail("commit source revision binding differs")
        return
    if (
        selector_type != "tag"
        or not _valid_git_tag(binding["recipe_selector"])
        or not _safe_relative(
            binding["binding_evidence_member"], "evidence/revision-bindings/"
        )
        or not _safe_relative(
            binding["binding_evidence_input"], "evidence/revision-bindings/"
        )
        or not _sha256(binding["binding_evidence_sha256"])
        or not isinstance(binding["tag_object_revision"], str)
        or _COMMIT.fullmatch(binding["tag_object_revision"]) is None
        or len(binding["tag_object_revision"]) != len(revision)
    ):
        _fail("tag source revision binding differs")


def _validate_tag_object(path, binding):
    with path.open("rb") as source:
        payload = source.read(256 * 1024 + 1)
    if len(payload) > 256 * 1024:
        _fail("tag source revision binding evidence is too large")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise BuildError("tag source revision binding evidence is unreadable") from error
    if "\x00" in text or "\n\n" not in text:
        _fail("tag source revision binding evidence differs")
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
        _fail("tag source revision binding evidence differs")
    object_bytes = b"tag " + str(len(payload)).encode("ascii") + b"\0" + payload
    expected_identity = binding["tag_object_revision"]
    observed_identity = (
        hashlib.sha1(object_bytes, usedforsecurity=False).hexdigest()
        if len(expected_identity) == 40
        else hashlib.sha256(object_bytes).hexdigest()
    )
    if observed_identity != expected_identity:
        _fail("tag source revision binding object identity differs")


def _validate_ref(ref, approved, role, *, require_binding=False):
    _keys(ref, REF_KEYS, ("revision_binding",) if require_binding else ())
    if ref["archive_format"] not in {"tar", "tar.xz"} or not _safe_relative(ref["input_path"], "sources/") or not _safe_relative(ref["archive_member"], "sources/"):
        _fail(f"{role} path or format is unsafe")
    if not _sha256(ref["sha256"]) or not _plain_int(ref["member_count"], 2) or not _plain_int(ref["unpacked_bytes"], 1):
        _fail(f"{role} hash or limits are invalid")
    if not isinstance(ref["revision"], str) or _COMMIT.fullmatch(ref["revision"]) is None:
        _fail(f"{role} revision is not immutable")
    bases = [_canonical_base(base) for base in approved]
    valid = {f"{base}/commit/{ref['revision']}" for base in bases} | {f"{base}/-/commit/{ref['revision']}" for base in bases}
    if ref["origin"] not in valid:
        _fail(f"{role} origin is not approved")
    binding = ref.get("revision_binding")
    if require_binding and binding is None:
        _fail(f"{role} has no recipe revision binding")
    if binding is not None:
        _validate_revision_binding(binding, ref["revision"], bases)


def _inside_link(member: str, target: str):
    if not isinstance(target, str) or target.startswith("/") or "\\" in target:
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


def _validate_tar_end(path: Path):
    logical_end = 0
    try:
        with path.open("rb") as stream:
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                for member in archive:
                    logical_end = max(logical_end, member.offset_data + ((member.size + 511) // 512) * 512)
            stream.seek(0, os.SEEK_END)
            total = stream.tell()
            expected_total = ((logical_end + 1024 + 10239) // 10240) * 10240
            if total != expected_total:
                _fail("nested tar is not canonical")
            stream.seek(logical_end)
            remaining = total - logical_end
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk or chunk != b"\0" * len(chunk):
                    _fail("nested tar has trailing data")
                remaining -= len(chunk)
    except (tarfile.TarError, OSError, EOFError) as error:
        raise BuildError("nested tar is unreadable") from error


def _decompress_xz(source_path: Path, output_path: Path):
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    if source_path.stat().st_size > MAX_NESTED_MEMBER_BYTES:
        _fail("nested source member exceeds size limit")
    expanded = 0
    with source_path.open("rb") as source, output_path.open("wb") as output_file:
        while chunk := source.read(1024 * 1024):
            pending = chunk
            while pending or not decoder.needs_input:
                if decoder.eof:
                    if pending or decoder.unused_data:
                        _fail("nested xz has trailing data")
                    break
                data = decoder.decompress(pending, max_length=1024 * 1024)
                output_file.write(data)
                expanded += len(data)
                if expanded > MAX_NESTED_UNPACKED_BYTES:
                    _fail("nested source exceeds unpacked size limit")
                if decoder.eof and decoder.unused_data:
                    _fail("nested xz has trailing data")
                pending = b""
        while not decoder.eof:
            if decoder.needs_input:
                _fail("nested xz is truncated")
            data = decoder.decompress(b"", max_length=1024 * 1024)
            output_file.write(data)
            expanded += len(data)
            if expanded > MAX_NESTED_UNPACKED_BYTES:
                _fail("nested source exceeds unpacked size limit")
            if not data:
                _fail("nested xz is truncated")
def _validate_nested_members(archive, ref, capture_members=()):
    count = regular = total = 0
    names = []
    capture_members = set(capture_members)
    captures = {}
    try:
        for member in archive:
            count += 1
            name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
            if count > MAX_NESTED_MEMBERS or not _safe_relative(name) or name in names:
                _fail("nested source archive is unsafe")
            names.append(name)
            if member.mtime != 0 or member.uid != 0 or member.gid != 0 or member.uname != "root" or member.gname != "root" or member.pax_headers:
                _fail("nested source archive metadata is not canonical")
            if member.isdir():
                if member.mode & 0o777 != 0o755:
                    _fail("nested directory mode is not canonical")
                continue
            if member.issym():
                if member.mode & 0o777 != 0o777 or not _inside_link(name, member.linkname):
                    _fail("nested symlink escapes archive")
                continue
            if not member.isfile():
                _fail("nested archive contains an unsupported member")
            if member.mode & 0o777 not in {0o644, 0o755}:
                _fail("nested file mode is not canonical")
            if member.size > MAX_NESTED_MEMBER_BYTES:
                _fail("nested source member exceeds size limit")
            total += member.size
            if total > MAX_NESTED_UNPACKED_BYTES:
                _fail("nested source exceeds unpacked size limit")
            source = archive.extractfile(member)
            if source is None:
                _fail("nested source member is unreadable")
            first = bytearray()
            captured = bytearray()
            while chunk := source.read(1024 * 1024):
                if len(first) < len(_LFS_POINTER):
                    first.extend(chunk[:len(_LFS_POINTER) - len(first)])
                if name in capture_members:
                    captured.extend(chunk)
                    if len(captured) > MAX_RECIPE_MANIFEST_BYTES:
                        _fail("recipe manifest exceeds size limit")
            if bytes(first).startswith(_LFS_POINTER):
                _fail("nested source contains an LFS pointer")
            if name in capture_members:
                captures[name] = bytes(captured)
            regular += 1
    except (tarfile.TarError, OSError, EOFError) as error:
        raise BuildError("nested source archive is unreadable") from error
    if count < 2 or not regular or names != sorted(names) or count != ref["member_count"] or total != ref["unpacked_bytes"]:
        _fail("nested source archive differs from expected metadata")
    if set(captures) != capture_members:
        _fail("recipe manifest is unavailable")
    return captures


def _validate_nested(path: Path, ref, capture_members=()):
    digest, _ = _hash_file(path)
    if digest != ref["sha256"]:
        _fail("input hash differs")
    try:
        with path.open("rb") as source:
            with tarfile.open(fileobj=source, mode="r|xz" if ref["archive_format"] == "tar.xz" else "r|") as archive:
                captures = _validate_nested_members(archive, ref, capture_members)
        if ref["archive_format"] == "tar.xz":
            with tempfile.NamedTemporaryFile(prefix="cptc-source-xz-", suffix=".tar", delete=False) as output:
                expanded = Path(output.name)
            try:
                _decompress_xz(path, expanded)
                _validate_tar_end(expanded)
            finally:
                expanded.unlink(missing_ok=True)
        else:
            _validate_tar_end(path)
    except lzma.LZMAError as error:
        raise BuildError("nested xz is unreadable") from error
    return captures


def _validate_recipe_bindings(manifests, references):
    decoded = {}
    for path, payload in manifests.items():
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise BuildError("recipe manifest is unreadable") from error
        if "\x00" in text or "\r" in text:
            _fail("recipe manifest is unreadable")
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
                    _fail("recipe manifest contains an unsupported VCS source")
                vcs_sources.append(value)
        declared = [
            reference["revision_binding"]["recipe_source"]
            for reference in references
            if reference["revision_binding"]["recipe_manifest_path"] == path
        ]
        if sorted(vcs_sources) != sorted(declared):
            _fail("recipe VCS sources differ from revision bindings")


def _strip_ref(ref):
    result = {key: ref[key] for key in REF_KEYS if key != "input_path"}
    binding = ref.get("revision_binding")
    if binding is not None:
        result["revision_binding"] = {
            key: value
            for key, value in binding.items()
            if key != "binding_evidence_input"
        }
    return result


def _validate_spec(spec):
    _keys(spec, SPEC_KEYS)
    if spec["schema_version"] != 1 or not _UTC.fullmatch(spec["verified_at"]) or not _text(spec["verified_by"]):
        _fail("spec header is invalid")
    component = spec["component"]
    _keys(component, COMPONENT_KEYS)
    if not all(_text(component[key]) for key in ("name", "version", "use", "source", "license", "license_source")):
        _fail("component identity is invalid")
    _canonical_base(component["source"])
    _canonical_base(component["license_source"])
    if not isinstance(component["copied_files"], list) or not all(_safe_relative(path) for path in component["copied_files"]):
        _fail("component copied-file list is invalid")
    if component["copied_files"] != sorted(set(component["copied_files"])):
        _fail("component copied-file list is invalid")
    if not isinstance(component["distributed"], bool) or not component["distributed"] or not isinstance(component["obligations"], list) or not all(_text(value) for value in component["obligations"]):
        _fail("component distribution metadata is invalid")
    if component["distribution_basis"] != "copyleft-source-required":
        _fail("component distribution basis is invalid")
    origins = component["approved_source_origins"]
    _keys(origins, {"packaging", "upstream"})
    if not all(isinstance(origins[key], list) and origins[key] and origins[key] == sorted(set(origins[key])) for key in origins):
        _fail("approved source origins are invalid")
    package = spec["distribution_package"]
    _keys(package, PACKAGE_KEYS)
    _keys(package["input"], PACKAGE_INPUT_KEYS)
    if not _text(package["name"]) or not _text(package["version"]) or not _text(package["component_version"]) or package["component_version"] != component["version"] or not _text(package["architecture"]) or not _ARCHITECTURE.fullmatch(package["architecture"]) or not _text(package["package_filename"]) or PurePosixPath(package["package_filename"]).name != package["package_filename"]:
        _fail("package identity or architecture is not exact")
    if not _sha256(package["package_sha256"]) or not _sha256(package["build_info_sha256"]):
        _fail("package hashes are invalid")
    if not _safe_relative(package["archive_member"], "evidence/") or not _safe_relative(package["build_info_member"], "evidence/") or not _safe_relative(package["input"]["package"], "evidence/") or not _safe_relative(package["input"]["build_info"], "evidence/"):
        _fail("package paths are unsafe")
    installed = package["installed_file_hashes"]
    if not isinstance(installed, dict) or set(installed) != set(component["copied_files"]) or not all(_sha256(value) for value in installed.values()):
        _fail("copied-file hashes are invalid")
    _validate_ref(spec["packaging_source"], origins["packaging"], "packaging source")
    if not isinstance(spec["upstream_sources"], list) or not spec["upstream_sources"]:
        _fail("upstream source list is invalid")
    for ref in spec["upstream_sources"]:
        _validate_ref(
            ref, origins["upstream"], "upstream source", require_binding=True
        )
    if not isinstance(spec["patches"], list):
        _fail("patch list is invalid")
    for patch in spec["patches"]:
        _keys(patch, PATCH_KEYS)
        if not _safe_relative(patch["archive_member"], "patches/") or not _safe_relative(patch["input_path"]) or not _sha256(patch["sha256"]):
            _fail("patch metadata is invalid")
    build = spec["build"]
    _keys(build, BUILD_KEYS)
    if not _safe_relative(build["recipe_member"], "sources/") or not _safe_relative(build["source_info_member"], "sources/") or not _text(build["toolchain"]) or not isinstance(build["flags"], list) or not all(_text(flag) for flag in build["flags"]):
        _fail("build metadata is invalid")
    if build["reproducibility_status"] not in {"metadata-only", "reproduced"}:
        _fail("build reproducibility status is invalid")
    if build["reproducibility_status"] == "metadata-only":
        if any(build[key] is not None for key in ("source_date_epoch", "build_log_member", "build_log_sha256")):
            _fail("metadata-only build evidence is invalid")
    elif not _plain_int(build["source_date_epoch"], 1) or not _safe_relative(build["build_log_member"], "evidence/") or not _sha256(build["build_log_sha256"]):
        _fail("reproduced build evidence is invalid")


def _collect(spec, input_dir: Path, repo_root: Path):
    _validate_spec(spec)
    for relative, expected in spec["distribution_package"]["installed_file_hashes"].items():
        path = _regular_file(repo_root, relative)
        digest, _ = _hash_file(path)
        if digest != expected:
            _fail("copied-file hash differs")
    package = spec["distribution_package"]
    members = {}

    def add(member, relative, expected):
        if member in members or not _safe_relative(member):
            _fail("archive member is duplicate or unsafe")
        path = _regular_file(input_dir, relative)
        digest, size = _hash_file(path)
        if digest != expected:
            _fail("input hash differs")
        members[member] = {"path": path, "sha256": digest, "bytes": size}

    add(package["archive_member"], package["input"]["package"], package["package_sha256"])
    add(package["build_info_member"], package["input"]["build_info"], package["build_info_sha256"])
    refs = [spec["packaging_source"], *spec["upstream_sources"]]
    manifest_paths = {
        ref["revision_binding"]["recipe_manifest_path"]
        for ref in spec["upstream_sources"]
    }
    recipe_manifests = {}
    for index, ref in enumerate(refs):
        add(ref["archive_member"], ref["input_path"], ref["sha256"])
        captures = _validate_nested(
            members[ref["archive_member"]]["path"],
            ref,
            manifest_paths if index == 0 else (),
        )
        recipe_manifests.update(captures)
        binding = ref.get("revision_binding")
        if binding is not None and binding["recipe_selector_type"] == "tag":
            add(
                binding["binding_evidence_member"],
                binding["binding_evidence_input"],
                binding["binding_evidence_sha256"],
            )
            _validate_tag_object(
                members[binding["binding_evidence_member"]]["path"], binding
            )
    _validate_recipe_bindings(recipe_manifests, spec["upstream_sources"])
    for patch in spec["patches"]:
        add(patch["archive_member"], patch["input_path"], patch["sha256"])
    build = spec["build"]
    if build["recipe_member"] != spec["packaging_source"]["archive_member"] or build["source_info_member"] not in {ref["archive_member"] for ref in spec["upstream_sources"]}:
        _fail("build source evidence differs")
    if build["reproducibility_status"] == "reproduced":
        add(build["build_log_member"], build["build_log_member"], build["build_log_sha256"])
    return members


def _outer_tar_to_path(members, path):
    if len(members) > MAX_OUTER_MEMBERS:
        _fail("outer archive exceeds member limit")
    try:
        with path.open("wb") as output, tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for name in sorted(members):
                info = tarfile.TarInfo(name)
                info.size = members[name]["bytes"]
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mode = 0o644
                with members[name]["path"].open("rb") as source:
                    archive.addfile(info, source)
    except (OSError, tarfile.TarError) as error:
        raise BuildError("outer source archive could not be written") from error


def _outer_unpacked_bytes(members):
    total = 0
    for item in members.values():
        total += 512 + ((item["bytes"] + 511) // 512) * 512
    return ((total + 1024 + 10239) // 10240) * 10240


def _gzip_path(source_path, output_path):
    try:
        with source_path.open("rb") as source, output_path.open("wb") as output:
            with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
                while chunk := source.read(1024 * 1024):
                    compressed.write(chunk)
    except OSError as error:
        raise BuildError("source bundle gzip could not be written") from error


def _canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _atomic_publish(payloads):
    paths = list(payloads)
    if len({path.resolve() for path in paths}) != len(paths):
        _fail("output paths overlap")
    if any(os.path.lexists(path) for path in paths):
        _fail("output already exists")
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        if any(parent.is_symlink() for parent in (path.parent, *path.parent.parents) if parent.exists()):
            _fail("output parent is a symlink")
    temporary = []
    published = []
    try:
        for path, data in payloads.items():
            fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            with os.fdopen(fd, "wb") as handle:
                if isinstance(data, Path):
                    with data.open("rb") as source:
                        while chunk := source.read(1024 * 1024):
                            handle.write(chunk)
                else:
                    handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.append(Path(name))
        for temp, path in zip(temporary, paths):
            os.link(temp, path)
            published.append(path)
            temp.unlink()
        for path in {path.parent for path in paths}:
            fd = os.open(path, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    except (OSError, ValueError) as error:
        for path in published:
            try:
                path.unlink()
            except OSError:
                pass
        for temp in temporary:
            try:
                temp.unlink()
            except OSError:
                pass
        raise BuildError("atomic output publication failed") from error


def build_bundle(spec_path, input_dir, repo_root, archive_path, metadata_path, receipt_path):
    spec_path, input_dir, repo_root = map(Path, (spec_path, input_dir, repo_root))
    archive_path, metadata_path, receipt_path = map(Path, (archive_path, metadata_path, receipt_path))
    _root(input_dir, "input directory")
    _root(repo_root, "repository root")
    if spec_path.is_symlink() or not spec_path.is_file():
        _fail("spec is not a real file")
    spec = _load_json(spec_path)
    members = _collect(spec, input_dir, repo_root)
    with tempfile.NamedTemporaryFile(prefix="cptc-source-outer-", suffix=".tar", delete=False) as outer_handle:
        outer_path = Path(outer_handle.name)
    with tempfile.NamedTemporaryFile(prefix="cptc-source-bundle-", suffix=".tar.gz", delete=False) as archive_handle:
        archive_temp = Path(archive_handle.name)
    try:
        _outer_tar_to_path(members, outer_path)
        _gzip_path(outer_path, archive_temp)
        archive_bytes = archive_temp.stat().st_size
        with archive_temp.open("rb") as generated:
            if generated.read(10) != CANONICAL_GZIP_HEADER:
                _fail("gzip output is not canonical")
        if archive_bytes >= MAX_BUNDLE_BYTES:
            _fail("source bundle exceeds 95 MiB limit")
        archive_sha256, _ = _hash_file(archive_temp, limit=MAX_BUNDLE_BYTES)
        outer_unpacked_bytes = _outer_unpacked_bytes(members)
        metadata = {
            "schema_version": 1,
            "component": spec["component"]["name"],
            "distribution_package": {key: spec["distribution_package"][key] for key in PACKAGE_KEYS if key != "input"},
            "packaging_source": _strip_ref(spec["packaging_source"]),
            "upstream_sources": [_strip_ref(ref) for ref in spec["upstream_sources"]],
            "patches": [{key: patch[key] for key in ("archive_member", "sha256")} for patch in spec["patches"]],
            "build": spec["build"],
            "archive_members": [{"path": name, "sha256": item["sha256"], "bytes": item["bytes"]} for name, item in sorted(members.items())],
            "verified_at": spec["verified_at"],
            "verified_by": spec["verified_by"],
        }
        metadata_bytes = _canonical_json(metadata)
        receipt = {
            "schema_version": 1,
            "component": spec["component"]["name"],
            "archive_format": "tar.gz",
            "archive_sha256": archive_sha256,
            "archive_bytes": archive_bytes,
            "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
            "outer_member_count": len(members),
            "outer_unpacked_bytes": outer_unpacked_bytes,
            "verified": True,
        }
        _atomic_publish({archive_path: archive_temp, metadata_path: metadata_bytes, receipt_path: _canonical_json(receipt)})
        return receipt
    finally:
        outer_path.unlink(missing_ok=True)
        archive_temp.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        build_bundle(args.spec, args.input_dir, args.repo_root, args.archive, args.metadata, args.receipt)
    except BuildError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
