"""Private local files with no symlink following and durable replacement."""
from __future__ import annotations
import fcntl
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from .contracts import PolicyError, canonical_json


def private_directory(path: Path, *, create=False) -> Path:
    path = Path(path).absolute()
    # Parents may be readable (e.g. /home); no component may be a symlink.
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise PolicyError("symlink in protected storage path")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PolicyError("protected directory must be owner-only")
    return path


def read_private(path: Path, limit=1048576) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PolicyError("protected file must be owner-only regular file")
        if info.st_size > limit:
            raise PolicyError("protected file exceeds allowance")
        result = b""
        while len(result) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(result)))
            if not chunk:
                return result
            result += chunk
        raise PolicyError("protected file exceeds allowance")
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, *, replace=True) -> None:
    path = Path(path)
    private_directory(path.parent)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise PolicyError("invalid protected output path")
    temporary = path.with_name("." + path.name + "." + os.urandom(8).hex() + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path: Path, value, *, replace=True):
    atomic_write(path, canonical_json(value) + b"\n", replace=replace)


@contextmanager
def exclusive(path: Path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PolicyError("invalid lock file permissions")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PolicyError("operation already in progress") from None
        yield
    finally:
        os.close(fd)
