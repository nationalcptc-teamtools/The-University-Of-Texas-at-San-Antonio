"""Restricted capability-based staging and acquisition receipts."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Literal

from .http_source import MAX_RANGE_SIZE
from .source_allowlist import ImageSource


SAFETY_RESERVE = 2 * 1024**3
IMAGE_FILENAME = "image.qcow2.partial"
LOCK_FILENAME = ".image-audit.lock"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z")
_AUDIT_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class StagingRejected(RuntimeError):
    """A local staging or resume safety invariant failed."""


def _path_components(path: Path) -> tuple[Path, ...]:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    result: list[Path] = []
    for part in absolute.parts[1:]:
        current = current / part
        result.append(current)
    return tuple(result)


def _reject_symlink_components(path: Path) -> None:
    for component in _path_components(path):
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            break
        if stat.S_ISLNK(mode):
            raise StagingRejected(f"symlink path component is forbidden: {component}")


def _inside_git_repository(path: Path) -> bool:
    for candidate in (path.absolute(), *path.absolute().parents):
        marker = candidate / ".git"
        if marker.exists() or marker.is_symlink():
            return True
    return False


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


class StateRootCapability:
    """Open owner-only state root used as the authority for relative operations."""

    def __init__(self, path: Path, fd: int, metadata: os.stat_result) -> None:
        self.path = path
        self._fd = fd
        self._metadata = metadata

    @property
    def fd(self) -> int:
        if self._fd < 0:
            raise StagingRejected("state-root capability is closed")
        return self._fd

    def assert_valid(self) -> None:
        current_path = self.path.lstat()
        current_fd = os.fstat(self.fd)
        if not _same_identity(current_path, self._metadata) or not _same_identity(current_fd, self._metadata):
            raise StagingRejected("state root identity changed")
        if not stat.S_ISDIR(current_fd.st_mode):
            raise StagingRejected("state root must remain a directory")
        if current_fd.st_uid != os.geteuid() or stat.S_IMODE(current_fd.st_mode) != 0o700:
            raise StagingRejected("state root ownership or mode changed")

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "StateRootCapability":
        self.assert_valid()
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


class RunCapability:
    """Open run directory with fixed child names and no path-selection authority."""

    def __init__(self, root: StateRootCapability, run_id: str, fd: int, metadata: os.stat_result) -> None:
        self.root = root
        self.run_id = run_id
        self.path = root.path / run_id
        self.image_path = self.path / IMAGE_FILENAME
        self._fd = fd
        self._metadata = metadata
        self._image_initialized = False

    @property
    def fd(self) -> int:
        if self._fd < 0:
            raise StagingRejected("run capability is closed")
        return self._fd

    def assert_valid(self) -> None:
        self.root.assert_valid()
        path_metadata = os.stat(self.run_id, dir_fd=self.root.fd, follow_symlinks=False)
        fd_metadata = os.fstat(self.fd)
        if not _same_identity(path_metadata, self._metadata) or not _same_identity(fd_metadata, self._metadata):
            raise StagingRejected("run directory identity changed")
        if not stat.S_ISDIR(fd_metadata.st_mode):
            raise StagingRejected("run capability no longer names a directory")
        if fd_metadata.st_uid != os.geteuid() or stat.S_IMODE(fd_metadata.st_mode) != 0o700:
            raise StagingRejected("run directory ownership or mode changed")

    def _open_image(self, *, create: bool, writable: bool) -> int:
        self.assert_valid()
        flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(IMAGE_FILENAME, flags, 0o600, dir_fd=self.fd)
        except FileExistsError as error:
            raise StagingRejected("fixed staging image already exists before exclusive creation") from error
        try:
            path_metadata = os.stat(IMAGE_FILENAME, dir_fd=self.fd, follow_symlinks=False)
            fd_metadata = os.fstat(fd)
            if not _same_identity(path_metadata, fd_metadata):
                raise StagingRejected("staging image identity changed during open")
            if not stat.S_ISREG(fd_metadata.st_mode):
                raise StagingRejected("staging image must be regular")
            if fd_metadata.st_uid != os.geteuid():
                raise StagingRejected("staging image must be owned by the current user")
            if stat.S_IMODE(fd_metadata.st_mode) != 0o600:
                raise StagingRejected("staging image must have mode 0600")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def validated_image_path(self) -> Path:
        if not self._image_initialized:
            raise StagingRejected("staging image was not created by this run capability")
        fd = self._open_image(create=False, writable=False)
        os.close(fd)
        return self.image_path

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "RunCapability":
        self.assert_valid()
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def validate_state_root(path: Path) -> StateRootCapability:
    root = Path(path).absolute()
    _reject_symlink_components(root)
    if _inside_git_repository(root):
        raise StagingRejected("state root must be outside every Git repository")
    try:
        path_metadata = root.lstat()
        fd = os.open(root, _directory_flags())
    except FileNotFoundError as error:
        raise StagingRejected("state root does not exist") from error
    try:
        fd_metadata = os.fstat(fd)
        if not _same_identity(path_metadata, fd_metadata):
            raise StagingRejected("state root identity changed during open")
        if not stat.S_ISDIR(fd_metadata.st_mode):
            raise StagingRejected("state root must be a directory")
        if fd_metadata.st_uid != os.geteuid():
            raise StagingRejected("state root must be owned by the current user")
        if stat.S_IMODE(fd_metadata.st_mode) != 0o700:
            raise StagingRejected("state root must have mode 0700")
        return StateRootCapability(root, fd, fd_metadata)
    except BaseException:
        os.close(fd)
        raise


def create_private_run_dir(state_root: StateRootCapability, run_id: str) -> RunCapability:
    if not isinstance(state_root, StateRootCapability):
        raise StagingRejected("a validated state-root capability is required")
    state_root.assert_valid()
    if _RUN_ID_RE.fullmatch(run_id) is None:
        raise StagingRejected("invalid run ID")
    try:
        os.mkdir(run_id, mode=0o700, dir_fd=state_root.fd)
    except FileExistsError as error:
        raise StagingRejected("run directory already exists") from error
    os.fsync(state_root.fd)
    fd = os.open(run_id, _directory_flags(), dir_fd=state_root.fd)
    try:
        path_metadata = os.stat(run_id, dir_fd=state_root.fd, follow_symlinks=False)
        fd_metadata = os.fstat(fd)
        if not _same_identity(path_metadata, fd_metadata):
            raise StagingRejected("run directory identity changed during open")
        if fd_metadata.st_uid != os.geteuid() or stat.S_IMODE(fd_metadata.st_mode) != 0o700:
            raise StagingRejected("run directory must be owner-only mode 0700")
        return RunCapability(state_root, run_id, fd, fd_metadata)
    except BaseException:
        os.close(fd)
        raise


class ImageLock:
    """A non-blocking state-root lock allowing only one active image."""

    def __init__(self, state_root: StateRootCapability, asset_id: str) -> None:
        if not isinstance(state_root, StateRootCapability):
            raise StagingRejected("a validated state-root capability is required")
        self.state_root = state_root
        self.asset_id = asset_id
        self._fd: int | None = None

    @property
    def acquired(self) -> bool:
        return self._fd is not None

    def acquire(self) -> None:
        if self._fd is not None:
            raise StagingRejected("image lock is already acquired by this object")
        self.state_root.assert_valid()
        flags = os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(LOCK_FILENAME, flags, dir_fd=self.state_root.fd)
        except FileNotFoundError:
            create_flags = flags | os.O_CREAT | os.O_EXCL
            try:
                fd = os.open(LOCK_FILENAME, create_flags, 0o600, dir_fd=self.state_root.fd)
                os.fsync(self.state_root.fd)
            except FileExistsError:
                fd = os.open(LOCK_FILENAME, flags, dir_fd=self.state_root.fd)
        try:
            metadata = os.fstat(fd)
            path_metadata = os.stat(LOCK_FILENAME, dir_fd=self.state_root.fd, follow_symlinks=False)
            if not _same_identity(path_metadata, metadata):
                raise StagingRejected("image lock identity changed during open")
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise StagingRejected("image lock file is not a private regular file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(fd)
            raise StagingRejected("another image audit is already active") from error
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> "ImageLock":
        self.acquire()
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.release()


@dataclass(frozen=True)
class ChunkReceipt:
    index: int
    start: int
    end: int
    byte_count: int
    sha256: str
    etag: str | None
    last_modified: str | None
    sparse_hole: bool

    def __post_init__(self) -> None:
        integer_fields = (self.index, self.start, self.end, self.byte_count)
        if any(not isinstance(value, int) or isinstance(value, bool) for value in integer_fields):
            raise StagingRejected("chunk numeric fields must be integers")
        if self.index < 0 or self.start < 0 or self.end < self.start:
            raise StagingRejected("invalid chunk index or byte range")
        if self.byte_count != self.end - self.start + 1:
            raise StagingRejected("chunk byte count does not match range")
        if self.byte_count > MAX_RANGE_SIZE:
            raise StagingRejected("chunk exceeds the 4 MiB limit")
        if _SHA256_RE.fullmatch(self.sha256) is None:
            raise StagingRejected("chunk hash must be lowercase SHA-256")
        if not isinstance(self.sparse_hole, bool):
            raise StagingRejected("chunk sparse_hole must be a boolean")

    def to_dict(self, source: ImageSource | None = None) -> dict[str, object]:
        return {
            "byte_count": self.byte_count,
            "end": self.end,
            "etag": self.etag if self.etag is not None else (source.etag if source else None),
            "index": self.index,
            "last_modified": self.last_modified if self.last_modified is not None else (source.last_modified if source else None),
            "sha256": self.sha256,
            "sparse_hole": self.sparse_hole,
            "start": self.start,
        }


def write_sparse_chunk(
    run: RunCapability,
    *,
    logical_size: int,
    start: int,
    data: bytes,
    chunk_index: int,
    etag: str | None = None,
    last_modified: str | None = None,
) -> ChunkReceipt:
    """Write one validated chunk to the fixed run image."""

    if not isinstance(run, RunCapability):
        raise StagingRejected("a validated run capability is required")
    if not isinstance(data, bytes) or not data:
        raise StagingRejected("chunk data must be non-empty bytes")
    if len(data) > MAX_RANGE_SIZE:
        raise StagingRejected("chunk exceeds the 4 MiB limit")
    if not isinstance(logical_size, int) or isinstance(logical_size, bool) or logical_size < 1:
        raise StagingRejected("invalid staging logical size")
    if not isinstance(start, int) or isinstance(start, bool) or start < 0 or start + len(data) > logical_size:
        raise StagingRejected("chunk exceeds staging logical size")
    first_open = not run._image_initialized
    fd = run._open_image(create=first_open, writable=True)
    try:
        metadata = os.fstat(fd)
        if first_open:
            os.fchmod(fd, 0o600)
            run._image_initialized = True
        elif metadata.st_size != logical_size:
            raise StagingRejected("existing staging logical size changed")
        sparse_hole = not any(data)
        if sparse_hole and not first_open:
            previous = os.pread(fd, len(data), start)
            if any(previous):
                raise StagingRejected("zero chunk overlaps existing nonzero data")
        elif not sparse_hole:
            written = 0
            while written < len(data):
                count = os.pwrite(fd, data[written:], start + written)
                if count < 1:
                    raise StagingRejected("short sparse staging write")
                written += count
        os.ftruncate(fd, logical_size)
        os.fsync(fd)
        if first_open:
            os.fsync(run.fd)
    finally:
        os.close(fd)
    return ChunkReceipt(
        index=chunk_index,
        start=start,
        end=start + len(data) - 1,
        byte_count=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        etag=etag,
        last_modified=last_modified,
        sparse_hole=sparse_hole,
    )


def required_free_space(*, advertised_content_length: int, qcow_metadata_reserve: int, encrypted_output_reserve: int) -> int:
    values = (advertised_content_length, qcow_metadata_reserve, encrypted_output_reserve)
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
        raise StagingRejected("space reservation inputs must be non-negative integers")
    if advertised_content_length == 0:
        raise StagingRejected("advertised content length must be positive")
    return sum(values) + SAFETY_RESERVE


def validate_free_space(available_bytes: int, required_bytes: int) -> int:
    if available_bytes < required_bytes:
        raise StagingRejected(f"insufficient free space: available={available_bytes} required={required_bytes}")
    return required_bytes


@dataclass(frozen=True)
class AcquisitionReceipt:
    source: ImageSource
    started_at: str
    finished_at: str | None
    range_size: int
    chunks: tuple[ChunkReceipt, ...]
    final_image_sha256: str | None
    sparse_logical_size: int
    allocated_bytes: int
    completion_state: Literal["running", "interrupted", "failed", "complete"]
    failure_reason: str | None
    tool_version: str
    audit_chain_refs: tuple[str, ...]
    schema: str = "cptc11-acquisition-receipt-v1"

    def __post_init__(self) -> None:
        if self.schema != "cptc11-acquisition-receipt-v1":
            raise StagingRejected("invalid acquisition receipt schema")
        if not isinstance(self.source, ImageSource):
            raise StagingRejected("invalid acquisition source")
        if not isinstance(self.started_at, str):
            raise StagingRejected("invalid acquisition start timestamp")
        if _TIME_RE.fullmatch(self.started_at) is None:
            raise StagingRejected("invalid acquisition start timestamp")
        if self.finished_at is not None and (
            not isinstance(self.finished_at, str) or _TIME_RE.fullmatch(self.finished_at) is None
        ):
            raise StagingRejected("invalid acquisition finish timestamp")
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise StagingRejected("acquisition finish timestamp is before start")
        if not isinstance(self.completion_state, str) or self.completion_state not in {"running", "interrupted", "failed", "complete"}:
            raise StagingRejected("invalid acquisition completion state")
        if not isinstance(self.range_size, int) or isinstance(self.range_size, bool) or not 1 <= self.range_size <= MAX_RANGE_SIZE:
            raise StagingRejected("invalid acquisition range size")
        if not isinstance(self.chunks, tuple):
            raise StagingRejected("acquisition chunks must be a tuple")
        if any(not isinstance(chunk, ChunkReceipt) for chunk in self.chunks):
            raise StagingRejected("acquisition chunks must contain chunk receipts")
        if tuple(chunk.index for chunk in self.chunks) != tuple(range(len(self.chunks))):
            raise StagingRejected("acquisition chunk indexes must be contiguous")
        next_start = 0
        for chunk in self.chunks:
            if chunk.start != next_start:
                raise StagingRejected("acquisition chunks must cover a contiguous prefix")
            expected_count = min(self.range_size, self.source.content_length - chunk.start)
            if chunk.byte_count != expected_count or chunk.end >= self.source.content_length:
                raise StagingRejected("acquisition chunk range is inconsistent with source")
            if chunk.etag != self.source.etag or chunk.last_modified != self.source.last_modified:
                raise StagingRejected("acquisition chunk source identity changed")
            next_start = chunk.end + 1
        if (
            not isinstance(self.sparse_logical_size, int)
            or isinstance(self.sparse_logical_size, bool)
            or self.sparse_logical_size != self.source.content_length
        ):
            raise StagingRejected("sparse logical size must match source length")
        if not isinstance(self.allocated_bytes, int) or isinstance(self.allocated_bytes, bool) or self.allocated_bytes < 0:
            raise StagingRejected("allocated byte count is invalid")
        if self.failure_reason is not None and (
            not isinstance(self.failure_reason, str)
            or not self.failure_reason.strip()
            or len(self.failure_reason) > 1024
            or "\n" in self.failure_reason
            or "\r" in self.failure_reason
        ):
            raise StagingRejected("invalid failure reason")
        if self.final_image_sha256 is not None and (
            not isinstance(self.final_image_sha256, str)
            or _SHA256_RE.fullmatch(self.final_image_sha256) is None
        ):
            raise StagingRejected("invalid final image hash")
        if not isinstance(self.tool_version, str) or not self.tool_version or len(self.tool_version) > 128 or "\n" in self.tool_version or "\r" in self.tool_version:
            raise StagingRejected("invalid tool version")
        if not isinstance(self.audit_chain_refs, tuple):
            raise StagingRejected("audit-chain references must be a tuple")
        if len(self.audit_chain_refs) > 256 or any(
            not isinstance(value, str) or _AUDIT_REF_RE.fullmatch(value) is None
            for value in self.audit_chain_refs
        ):
            raise StagingRejected("invalid audit-chain reference")

        if self.completion_state == "running":
            if self.finished_at is not None:
                raise StagingRejected("running receipt cannot have a finish timestamp")
            if self.failure_reason is not None:
                raise StagingRejected("running receipt cannot have a failure reason")
            if self.final_image_sha256 is not None:
                raise StagingRejected("running receipt cannot have a final image hash")
        elif self.completion_state in {"interrupted", "failed"}:
            if self.finished_at is None:
                raise StagingRejected(f"{self.completion_state} receipt requires a finish timestamp")
            if self.failure_reason is None:
                raise StagingRejected(f"{self.completion_state} receipt requires a failure reason")
            if self.final_image_sha256 is not None:
                raise StagingRejected(f"{self.completion_state} receipt cannot have a final image hash")
        else:
            if self.finished_at is None:
                raise StagingRejected("complete receipt requires finish timestamp")
            if self.failure_reason is not None:
                raise StagingRejected("complete receipt cannot have a failure reason")
            if next_start != self.source.content_length:
                raise StagingRejected("complete receipt chunks must cover the complete source")
            if self.final_image_sha256 is None or _SHA256_RE.fullmatch(self.final_image_sha256) is None:
                raise StagingRejected("complete receipt requires final image SHA-256")

    @property
    def downloaded_bytes(self) -> int:
        return sum(chunk.byte_count for chunk in self.chunks)

    def to_dict(self) -> dict[str, object]:
        return {
            "allocated_bytes": self.allocated_bytes,
            "audit_chain_refs": sorted(self.audit_chain_refs),
            "chunks": [chunk.to_dict(self.source) for chunk in self.chunks],
            "completion_state": self.completion_state,
            "downloaded_bytes": self.downloaded_bytes,
            "failure_reason": self.failure_reason,
            "final_image_sha256": self.final_image_sha256,
            "finished_at": self.finished_at,
            "range_requests": len(self.chunks),
            "range_size": self.range_size,
            "schema": self.schema,
            "source": self.source.to_dict(),
            "source_authenticity": "unsigned-public-http",
            "source_authenticity_limit": "ETag is identity metadata, not authenticity proof",
            "sparse_logical_size": self.sparse_logical_size,
            "started_at": self.started_at,
            "tool_version": self.tool_version,
        }

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"


def _same_source_identity(left: ImageSource, right: ImageSource) -> bool:
    fields = ("asset_id", "filename", "url", "origin", "listing_sha256", "content_length", "etag", "last_modified", "role")
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def validate_resume(current_source: ImageSource, receipt: AcquisitionReceipt, run: RunCapability, *, nbd_attached: bool) -> tuple[ChunkReceipt, ...]:
    if not isinstance(run, RunCapability):
        raise StagingRejected("a validated run capability is required")
    if receipt.completion_state != "interrupted":
        raise StagingRejected("only an explicitly interrupted acquisition may resume")
    if nbd_attached:
        raise StagingRejected("resume is forbidden while an NBD device is attached")
    if not _same_source_identity(current_source, receipt.source):
        raise StagingRejected("source identity changed; resume is forbidden")
    fd = run._open_image(create=False, writable=False)
    try:
        if os.fstat(fd).st_size != receipt.sparse_logical_size:
            raise StagingRejected("staging logical size changed")
        for chunk in receipt.chunks:
            body = os.pread(fd, chunk.byte_count, chunk.start)
            if len(body) != chunk.byte_count or hashlib.sha256(body).hexdigest() != chunk.sha256:
                raise StagingRejected(f"existing chunk hash changed at index {chunk.index}")
    finally:
        os.close(fd)
    return receipt.chunks
