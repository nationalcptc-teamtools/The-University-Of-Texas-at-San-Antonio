"""Pure QCOW validation and unavailable-runner command contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from threading import RLock
from typing import Callable, Mapping, NamedTuple
from weakref import ReferenceType, ref

from .staging import RunCapability, StagingRejected


MAX_RAW_OUTPUT = 1024 * 1024
MAX_VIRTUAL_SIZE = 512 * 1024**3
MAX_EXTENT_SIZE = 4 * 1024**3
MAX_METADATA_OVERHEAD = 256 * 1024**2
PARSER_VERSION = "cptc11-qcow-parser-v2"
QEMU_IMG_PATH = Path("/usr/bin/qemu-img")
TOOL_LOCK_SCHEMA = "cptc11-image-tool-lock-v1"
QEMU_IMG_PACKAGE_VERSION = "11.1.1-1"
QEMU_IMG_PACKAGE_ORIGIN = "Arch extra signed system package"
QEMU_IMG_REVIEWED_SHA256 = "451668d2855d188429cf06eeea9a96cde62cf0ef835491be57b4a5f07f1b1410"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MISSING_INFO_FIELD = object()


class QcowRejected(ValueError):
    """QCOW metadata or a command specification failed a safety invariant."""


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise QcowRejected(f"invalid {field}")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise QcowRejected(f"extent {field} must be a boolean")
    return value


def _json(raw: bytes, expected: type, label: str):
    if not isinstance(raw, bytes) or len(raw) > MAX_RAW_OUTPUT:
        raise QcowRejected(f"{label} output exceeds limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QcowRejected(f"malformed {label} JSON") from error
    if not isinstance(value, expected):
        raise QcowRejected(f"malformed {label} JSON root")
    return value


def _encryption_present(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in {"encrypt", "encrypted", "encryption"} and child not in (None, False, "", "none"):
                return True
            if _encryption_present(child):
                return True
    elif isinstance(value, list):
        return any(_encryption_present(child) for child in value)
    return False


class ValidatedQcowInfo:
    """Parser-issued token. Public construction is forbidden."""

    format: str
    virtual_size: int
    actual_allocated_size: int
    cluster_size: int
    backing_file_present: bool
    encryption_present: bool
    snapshot_present: bool
    raw_info_sha256: str

    __slots__ = (
        "format",
        "virtual_size",
        "actual_allocated_size",
        "cluster_size",
        "backing_file_present",
        "encryption_present",
        "snapshot_present",
        "raw_info_sha256",
        "__weakref__",
    )

    def __init__(self, **_values: object) -> None:
        raise QcowRejected("validated QCOW info must be parser-issued")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise QcowRejected("validated QCOW info is immutable")

    @classmethod
    def _issue(
        cls,
        *,
        format: str,
        virtual_size: int,
        actual_allocated_size: int,
        cluster_size: int,
        raw_info_sha256: str,
    ) -> "ValidatedQcowInfo":
        raise QcowRejected("validated QCOW info must be parser-issued")


_INFO_FIELD_NAMES = (
    "format",
    "virtual_size",
    "actual_allocated_size",
    "cluster_size",
    "backing_file_present",
    "encryption_present",
    "snapshot_present",
    "raw_info_sha256",
)
class _ValidatedInfoFields(NamedTuple):
    format: str
    virtual_size: int
    actual_allocated_size: int
    cluster_size: int
    backing_file_present: bool
    encryption_present: bool
    snapshot_present: bool
    raw_info_sha256: str


def _validated_qcow_info_fields(info_output: bytes) -> _ValidatedInfoFields:
    info = _json(info_output, dict, "qemu-img info")
    if info.get("format") != "qcow2":
        raise QcowRejected("image format must be qcow2")
    virtual = _integer(info.get("virtual-size"), "virtual size", minimum=1)
    if virtual > MAX_VIRTUAL_SIZE:
        raise QcowRejected("virtual size exceeds safety limit")
    actual = _integer(info.get("actual-size"), "actual size", minimum=1)
    if actual > virtual + MAX_METADATA_OVERHEAD:
        raise QcowRejected("actual size is inconsistent with virtual size")
    cluster = _integer(info.get("cluster-size"), "cluster size", minimum=512)
    if cluster > 2 * 1024 * 1024 or cluster & (cluster - 1):
        raise QcowRejected("invalid cluster size")
    if any(info.get(field) not in (None, "") for field in ("backing-filename", "full-backing-filename")):
        raise QcowRejected("QCOW backing files are forbidden")
    if _encryption_present(info):
        raise QcowRejected("encrypted QCOW images are unsupported")
    snapshots = info.get("snapshots", [])
    if not isinstance(snapshots, list):
        raise QcowRejected("malformed snapshot metadata")
    if snapshots:
        raise QcowRejected("snapshot-bearing QCOW images are forbidden")
    return _ValidatedInfoFields(
        format="qcow2",
        virtual_size=virtual,
        actual_allocated_size=actual,
        cluster_size=cluster,
        backing_file_present=False,
        encryption_present=False,
        snapshot_present=False,
        raw_info_sha256=hashlib.sha256(info_output).hexdigest(),
    )


def _create_info_token_authority() -> tuple[
    Callable[[bytes], ValidatedQcowInfo],
    Callable[[object], _ValidatedInfoFields],
    Callable[[], int],
]:
    _IssuedInfo = tuple[
        int, ReferenceType[ValidatedQcowInfo], _ValidatedInfoFields
    ]
    issued_info: tuple[_IssuedInfo, ...] = ()
    issued_info_lock = RLock()

    def parse(info_output: bytes) -> ValidatedQcowInfo:
        """Reject unsafe metadata and issue an identity-bound token."""

        nonlocal issued_info
        fields = _validated_qcow_info_fields(info_output)
        value = object.__new__(ValidatedQcowInfo)
        for name, field_value in zip(_INFO_FIELD_NAMES, fields, strict=True):
            object.__setattr__(value, name, field_value)
        identity = id(value)

        def discard(reference: ReferenceType[ValidatedQcowInfo]) -> None:
            nonlocal issued_info
            with issued_info_lock:
                issued_info = tuple(
                    issued for issued in issued_info if issued[1] is not reference
                )

        reference = ref(value, discard)
        with issued_info_lock:
            issued_info = (*issued_info, (identity, reference, fields))
        return value

    def validate(info: object) -> _ValidatedInfoFields:
        if type(info) is not ValidatedQcowInfo:
            raise QcowRejected("a parser-issued safe QCOW info token is required")
        with issued_info_lock:
            issued = next(
                (
                    candidate
                    for candidate in issued_info
                    if candidate[0] == id(info) and candidate[1]() is info
                ),
                None,
            )
        if issued is None:
            raise QcowRejected("a parser-issued safe QCOW info token is required")
        original = issued[2]
        current = tuple(
            getattr(info, name, _MISSING_INFO_FIELD) for name in _INFO_FIELD_NAMES
        )
        changed = any(
            type(value) is not type(expected) or value != expected
            for value, expected in zip(current, original, strict=True)
        )
        if changed:
            raise QcowRejected("validated QCOW info differs from parser-issued metadata")
        return original

    def count() -> int:
        with issued_info_lock:
            return len(issued_info)

    return parse, validate, count


parse_qcow_info, _validate_info_token, _issued_info_count = _create_info_token_authority()
del _create_info_token_authority


@dataclass(frozen=True)
class QcowReceipt:
    format: str
    virtual_size: int
    actual_allocated_size: int
    cluster_size: int
    backing_file_present: bool
    encryption_present: bool
    snapshot_present: bool
    extent_count: int
    maximum_extent: int
    parser_version: str
    raw_info_sha256: str
    raw_map_sha256: str
    schema: str = "cptc11-qcow-receipt-v1"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"


def parse_qcow_map(info: ValidatedQcowInfo, map_output: bytes) -> QcowReceipt:
    validated = _validate_info_token(info)
    extents = _json(map_output, list, "qemu-img map")
    previous_end = 0
    maximum = 0
    for index, extent in enumerate(extents):
        if not isinstance(extent, dict):
            raise QcowRejected(f"malformed extent at index {index}")
        start = _integer(extent.get("start"), "extent start")
        length = _integer(extent.get("length"), "extent length", minimum=1)
        if length > MAX_EXTENT_SIZE:
            raise QcowRejected("oversized QCOW map extent")
        end = start + length
        if end > validated.virtual_size:
            raise QcowRejected("extent exceeds virtual size")
        if index == 0 and start != 0:
            raise QcowRejected("QCOW map must start at virtual offset zero")
        if start != previous_end:
            raise QcowRejected("QCOW map extents must be contiguous and ordered")
        depth = _integer(extent.get("depth"), "extent depth")
        if depth != 0:
            raise QcowRejected("QCOW map extent depth must be depth zero")
        _boolean(extent.get("present"), "present")
        _boolean(extent.get("data"), "data")
        _boolean(extent.get("zero"), "zero")
        if "offset" in extent:
            _integer(extent["offset"], "physical offset")
        previous_end = end
        maximum = max(maximum, length)
    if previous_end != validated.virtual_size:
        raise QcowRejected("QCOW map must cover the complete virtual size")
    receipt = QcowReceipt(
        format=validated.format,
        virtual_size=validated.virtual_size,
        actual_allocated_size=validated.actual_allocated_size,
        cluster_size=validated.cluster_size,
        backing_file_present=validated.backing_file_present,
        encryption_present=validated.encryption_present,
        snapshot_present=validated.snapshot_present,
        extent_count=len(extents),
        maximum_extent=maximum,
        parser_version=PARSER_VERSION,
        raw_info_sha256=validated.raw_info_sha256,
        raw_map_sha256=hashlib.sha256(map_output).hexdigest(),
    )
    _validate_info_token(info)
    return receipt


def parse_qcow_metadata(info_output: bytes, map_output: bytes) -> QcowReceipt:
    """Compatibility helper that always validates info before reading the map."""

    info = parse_qcow_info(info_output)
    return parse_qcow_map(info, map_output)


@dataclass(frozen=True)
class QemuImgToolPin:
    path: Path
    sha256: str
    owner_uid: int
    mode: int
    package_name: str
    package_version: str
    package_origin: str
    lock_schema: str


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    cwd: Path
    env: dict[str, str]
    timeout_seconds: int
    output_limit: int
    network_disabled: bool
    validated_info_sha256: str | None
    close_fds: bool = True
    shell: bool = False


def _verify_tool_pin(pin: QemuImgToolPin) -> None:
    if not isinstance(pin, QemuImgToolPin):
        raise QcowRejected("a typed qemu-img tool pin is required")
    if pin.lock_schema != TOOL_LOCK_SCHEMA:
        raise QcowRejected("untrusted qemu-img tool lock schema")
    if pin.path != QEMU_IMG_PATH:
        raise QcowRejected("qemu-img path must be exactly /usr/bin/qemu-img")
    if (
        pin.package_name != "qemu-img"
        or pin.package_version != QEMU_IMG_PACKAGE_VERSION
        or pin.package_origin != QEMU_IMG_PACKAGE_ORIGIN
    ):
        raise QcowRejected("invalid qemu-img package identity")
    if _SHA256_RE.fullmatch(pin.sha256) is None:
        raise QcowRejected("invalid qemu-img hash pin")
    if pin.sha256 != QEMU_IMG_REVIEWED_SHA256:
        raise QcowRejected("qemu-img hash pin differs from the checked-in reviewed digest")
    if not isinstance(pin.owner_uid, int) or isinstance(pin.owner_uid, bool) or pin.owner_uid < 0:
        raise QcowRejected("invalid qemu-img owner pin")
    if not isinstance(pin.mode, int) or isinstance(pin.mode, bool) or pin.mode < 0:
        raise QcowRejected("invalid qemu-img mode pin")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        path_metadata = pin.path.lstat()
        fd = os.open(pin.path, flags)
    except (FileNotFoundError, OSError) as error:
        raise QcowRejected("pinned qemu-img executable is unavailable") from error
    try:
        fd_metadata = os.fstat(fd)
        if path_metadata.st_dev != fd_metadata.st_dev or path_metadata.st_ino != fd_metadata.st_ino:
            raise QcowRejected("qemu-img identity changed during verification")
        if not stat.S_ISREG(fd_metadata.st_mode):
            raise QcowRejected("qemu-img must be a regular file")
        if fd_metadata.st_uid != pin.owner_uid:
            raise QcowRejected("qemu-img owner differs from trusted pin")
        if stat.S_IMODE(fd_metadata.st_mode) != pin.mode:
            raise QcowRejected("qemu-img mode differs from trusted pin")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        if digest.hexdigest() != pin.sha256:
            raise QcowRejected("qemu-img hash differs from trusted pin")
    finally:
        os.close(fd)


def _command(run: RunCapability, *, tool_pin: QemuImgToolPin, operation: str, validated_info: ValidatedQcowInfo | None) -> CommandSpec:
    if not isinstance(run, RunCapability):
        raise QcowRejected("a validated run capability is required")
    validated_fields: _ValidatedInfoFields | None = None
    if operation == "map":
        validated_fields = _validate_info_token(validated_info)
    _verify_tool_pin(tool_pin)
    try:
        image_path = run.validated_image_path()
    except StagingRejected as error:
        raise QcowRejected(str(error)) from error
    if operation == "info":
        arguments: tuple[str, ...] = ("info", "--output=json", "--force-share", "-f", "qcow2")
        validated_hash = None
    elif operation == "map":
        arguments = ("map", "--output=json", "-f", "qcow2")
        assert validated_fields is not None  # Narrowed by parser-issued validation above.
        validated_hash = validated_fields.raw_info_sha256
    else:  # pragma: no cover
        raise QcowRejected("unsupported qemu-img operation")
    command = CommandSpec(
        argv=(str(QEMU_IMG_PATH), *arguments, str(image_path)),
        cwd=run.path,
        env={"LC_ALL": "C"},
        timeout_seconds=30,
        output_limit=MAX_RAW_OUTPUT,
        network_disabled=True,
        validated_info_sha256=validated_hash,
    )
    if validated_info is not None:
        _validate_info_token(validated_info)
    return command


def build_qemu_img_info_command(run: RunCapability, *, tool_pin: QemuImgToolPin) -> CommandSpec:
    return _command(run, tool_pin=tool_pin, operation="info", validated_info=None)


def build_qemu_img_map_command(run: RunCapability, *, tool_pin: QemuImgToolPin, validated_info: ValidatedQcowInfo) -> CommandSpec:
    return _command(run, tool_pin=tool_pin, operation="map", validated_info=validated_info)
