"""Linux anonymous descriptors, including Python builds without memfd wrappers.

Both paths call the same Linux memfd_create primitive. There is no named-file,
temporary-directory or disk fallback. Flag/seal values are Linux UAPI constants
from linux/memfd.h and linux/fcntl.h, not interpreter feature guesses.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
import re
import sys

from .contracts import PolicyError

MFD_CLOEXEC = 0x0001
MFD_ALLOW_SEALING = 0x0002
F_ADD_SEALS = 1033
F_GET_SEALS = 1034
READONLY_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008


def write_all(descriptor: int, data: bytes | bytearray | memoryview) -> None:
    """Write one complete in-memory payload without accepting a short write."""
    if type(descriptor) is not int:
        raise ValueError("invalid descriptor")
    try:
        pending = memoryview(data).cast("B")
    except TypeError:
        raise TypeError("memfd payload must be bytes-like") from None
    while pending:
        try:
            written = os.write(descriptor, pending)
        except InterruptedError:
            continue
        if type(written) is not int or written <= 0 or written > len(pending):
            raise OSError("anonymous descriptor write made no progress")
        pending = pending[written:]


def memfd_create(name: str, flags: int = MFD_CLOEXEC) -> int:
    if (sys.platform != "linux" or not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name)
            or type(flags) is not int or flags not in {MFD_CLOEXEC, MFD_CLOEXEC | MFD_ALLOW_SEALING}):
        raise PolicyError("reviewed Linux anonymous descriptor parameters required")
    native = getattr(os, "memfd_create", None)
    if native is not None:
        # Never bypass an actual native/kernel failure by retrying another path.
        return native(name, flags=flags)
    try:
        function = ctypes.CDLL(None, use_errno=True).memfd_create
    except (AttributeError, OSError):
        raise PolicyError("Linux anonymous descriptors unavailable; no disk fallback") from None
    function.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    descriptor = function(name.encode("ascii"), flags)
    if descriptor < 0:
        number = ctypes.get_errno()
        raise OSError(number, "Linux anonymous descriptor creation failed")
    return descriptor


def seal_readonly(descriptor: int) -> None:
    fcntl.fcntl(descriptor, F_ADD_SEALS, READONLY_SEALS)
    if fcntl.fcntl(descriptor, F_GET_SEALS) & READONLY_SEALS != READONLY_SEALS:
        raise PolicyError("anonymous descriptor sealing failed")
