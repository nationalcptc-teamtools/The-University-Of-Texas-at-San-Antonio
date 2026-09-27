"""Small deterministic ELF64 dependency validator for the sealed runtime."""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import re
import struct
from typing import Any, Mapping


class ElfValidationError(ValueError):
    pass


class ElfMetadata:
    __slots__ = ("needed", "interpreter", "rpath", "runpath")

    def __init__(
        self,
        needed: tuple[str, ...],
        interpreter: str | None,
        rpath: str | None,
        runpath: str | None,
    ) -> None:
        self.needed = needed
        self.interpreter = interpreter
        self.rpath = rpath
        self.runpath = runpath


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REVIEWED_INTERPRETERS = {
    "bin/bwrap": "/lib64/ld-linux-x86-64.so.2",
    "bin/python3.14": "/lib64/ld-linux-x86-64.so.2",
    "lib/libc.so.6": "/usr/lib/ld-linux-x86-64.so.2",
    "lib/libcap.so.2": "/lib64/ld-linux-x86-64.so.2",
}


def elf_metadata(raw: bytes) -> ElfMetadata:
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        raise ElfValidationError("not an ELF file")
    if raw[4:7] != b"\x02\x01\x01":
        raise ElfValidationError("ELF class, byte order, or version differs")
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    except struct.error as error:
        raise ElfValidationError("ELF header is truncated") from error
    if header[2] != 62 or header[3] != 1:
        raise ElfValidationError("ELF machine or version differs")
    program_offset, program_size, program_count = header[5], header[9], header[10]
    if program_size != 56 or program_count > 256:
        raise ElfValidationError("ELF program table differs")
    if program_offset + program_size * program_count > len(raw):
        raise ElfValidationError("ELF program table is truncated")
    loads: list[tuple[int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    interpreter: str | None = None
    for index in range(program_count):
        values = struct.unpack_from("<IIQQQQQQ", raw, program_offset + index * 56)
        kind, file_offset, virtual_address, file_size = values[0], values[2], values[3], values[5]
        if file_offset + file_size > len(raw):
            raise ElfValidationError("ELF segment is truncated")
        if kind == 1:
            loads.append((virtual_address, file_offset, file_size))
        elif kind == 2:
            if dynamic is not None:
                raise ElfValidationError("ELF has multiple dynamic segments")
            dynamic = (file_offset, file_size)
        elif kind == 3:
            if interpreter is not None or file_size < 2:
                raise ElfValidationError("ELF interpreter segment differs")
            value = raw[file_offset : file_offset + file_size]
            if not value.endswith(b"\x00") or b"\x00" in value[:-1]:
                raise ElfValidationError("ELF interpreter is malformed")
            try:
                interpreter = value[:-1].decode("ascii", "strict")
            except UnicodeDecodeError as error:
                raise ElfValidationError("ELF interpreter is not ASCII") from error
    if dynamic is None:
        return ElfMetadata((), interpreter, None, None)
    needed_offsets: list[int] = []
    rpath_offsets: list[int] = []
    runpath_offsets: list[int] = []
    string_address = string_size = None
    terminated = False
    for offset in range(dynamic[0], dynamic[0] + dynamic[1], 16):
        if offset + 16 > len(raw):
            raise ElfValidationError("ELF dynamic table is truncated")
        tag, value = struct.unpack_from("<qQ", raw, offset)
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            needed_offsets.append(value)
        elif tag == 15:
            rpath_offsets.append(value)
        elif tag == 29:
            runpath_offsets.append(value)
        elif tag == 5:
            string_address = value
        elif tag == 10:
            string_size = value
    if not terminated:
        raise ElfValidationError("ELF dynamic table is unterminated")
    if len(rpath_offsets) > 1 or len(runpath_offsets) > 1:
        raise ElfValidationError("ELF search path is duplicated")
    string_offsets = needed_offsets + rpath_offsets + runpath_offsets
    if not string_offsets:
        return ElfMetadata((), interpreter, None, None)
    if string_address is None or string_size is None or string_size > len(raw):
        raise ElfValidationError("ELF dynamic string table differs")
    string_offset = None
    for virtual_address, file_offset, file_size in loads:
        if virtual_address <= string_address < virtual_address + file_size:
            string_offset = file_offset + string_address - virtual_address
            break
    if string_offset is None or string_offset + string_size > len(raw):
        raise ElfValidationError("ELF dynamic string table is unavailable")
    def decode(offset: int) -> str:
        if offset >= string_size:
            raise ElfValidationError("ELF dynamic string offset differs")
        start = string_offset + offset
        end = raw.find(b"\x00", start, string_offset + string_size)
        if end < 0:
            raise ElfValidationError("ELF dynamic string is unterminated")
        try:
            return raw[start:end].decode("ascii", "strict")
        except UnicodeDecodeError as error:
            raise ElfValidationError("ELF dynamic string is not ASCII") from error

    result = []
    for offset in needed_offsets:
        name = decode(offset)
        if not name or "/" in name or name in {".", ".."}:
            raise ElfValidationError("ELF dependency path is unsafe")
        result.append(name)
    if len(result) != len(set(result)):
        raise ElfValidationError("ELF dependency is duplicated")
    rpath = decode(rpath_offsets[0]) if rpath_offsets else None
    runpath = decode(runpath_offsets[0]) if runpath_offsets else None
    return ElfMetadata(tuple(result), interpreter, rpath, runpath)


def elf_needed(raw: bytes) -> tuple[str, ...]:
    return elf_metadata(raw).needed


def _safe_metadata(
    raw: bytes, *, expected_interpreter: str | None
) -> ElfMetadata:
    metadata = elf_metadata(raw)
    if metadata.rpath is not None or metadata.runpath is not None:
        raise ElfValidationError("ELF RPATH or RUNPATH is forbidden")
    if metadata.interpreter != expected_interpreter:
        raise ElfValidationError("ELF interpreter differs")
    return metadata


def verify_elf_closure(
    files: Mapping[str, bytes], elf_files: Mapping[str, str]
) -> None:
    actual = {name for name, raw in files.items() if raw.startswith(b"\x7fELF")}
    if actual != set(elf_files):
        raise ElfValidationError("ELF membership differs")
    for name in sorted(actual):
        expected = elf_files.get(name)
        if not isinstance(expected, str) or hashlib.sha256(files[name]).hexdigest() != expected:
            raise ElfValidationError("ELF hash differs")
        metadata = _safe_metadata(
            files[name], expected_interpreter=_REVIEWED_INTERPRETERS.get(name)
        )
        for dependency in metadata.needed:
            if f"lib/{dependency}" not in actual:
                raise ElfValidationError("ELF dependency closure is incomplete")


def verify_private_native_closure(
    runtime_files: Mapping[str, bytes],
    native_files: Mapping[str, Mapping[str, Any]],
    sealed_files: Mapping[str, bytes],
) -> None:
    if not isinstance(native_files, Mapping) or not native_files:
        raise ElfValidationError("private native manifest is unavailable")
    by_name: dict[str, tuple[str, str]] = {}
    for original, payload in native_files.items():
        path = PurePosixPath(original) if isinstance(original, str) else None
        if (
            path is None
            or not path.is_absolute()
            or path.parent.as_posix() not in {"/usr/lib", "/usr/lib64"}
            or path.name in {"", ".", ".."}
            or not isinstance(payload, Mapping)
            or set(payload) != {"resolved_path", "sha256"}
        ):
            raise ElfValidationError("private native manifest path differs")
        resolved = payload.get("resolved_path")
        expected = payload.get("sha256")
        resolved_path = PurePosixPath(resolved) if isinstance(resolved, str) else None
        if (
            resolved_path is None
            or not resolved_path.is_absolute()
            or resolved_path.parent.as_posix() not in {"/usr/lib", "/usr/lib64"}
            or not isinstance(expected, str)
            or _HEX64.fullmatch(expected) is None
            or path.name in by_name
        ):
            raise ElfValidationError("private native manifest metadata differs")
        sealed_name = f"lib/{path.name}"
        raw = sealed_files.get(sealed_name)
        if (
            not isinstance(raw, bytes)
            or not raw.startswith(b"\x7fELF")
            or hashlib.sha256(raw).hexdigest() != expected
        ):
            raise ElfValidationError("private native hash differs")
        _safe_metadata(
            raw, expected_interpreter=_REVIEWED_INTERPRETERS.get(sealed_name)
        )
        by_name[path.name] = (sealed_name, expected)

    queue: list[str] = []
    extensions = 0
    for raw in runtime_files.values():
        if raw.startswith(b"\x7fELF"):
            extensions += 1
            queue.extend(_safe_metadata(raw, expected_interpreter=None).needed)
    if not extensions:
        raise ElfValidationError("private native extensions are unavailable")
    reached: set[str] = set()
    while queue:
        dependency = queue.pop()
        if dependency in reached:
            continue
        binding = by_name.get(dependency)
        if binding is None:
            raise ElfValidationError("private native dependency is unavailable")
        reached.add(dependency)
        queue.extend(
            _safe_metadata(
                sealed_files[binding[0]],
                expected_interpreter=_REVIEWED_INTERPRETERS.get(binding[0]),
            ).needed
        )
    if reached != set(by_name):
        raise ElfValidationError("private native dependency set differs")
