"""Actual kernel descriptors, with native and libc interpreter bindings."""
import errno
import os

import pytest

from cptc_harness import memfd
from cptc_harness.contracts import PolicyError


@pytest.mark.parametrize("binding", ["native", "libc"])
def test_anonymous_cloexec_and_kernel_readonly_seals(monkeypatch, binding):
    if binding == "libc": monkeypatch.delattr(os, "memfd_create", raising=False)
    descriptor = memfd.memfd_create("synthetic-fixture", memfd.MFD_CLOEXEC | memfd.MFD_ALLOW_SEALING)
    try:
        assert not os.get_inheritable(descriptor)
        assert os.fstat(descriptor).st_nlink == 0
        assert os.readlink(f"/proc/self/fd/{descriptor}").startswith("/memfd:synthetic-fixture")
        os.write(descriptor, b"synthetic-only")
        memfd.seal_readonly(descriptor)
        with pytest.raises(OSError) as failure: os.write(descriptor, b"changed")
        assert failure.value.errno == errno.EPERM
        os.lseek(descriptor, 0, 0)
        assert os.read(descriptor, 64) == b"synthetic-only"
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("name,flags", [("../file", 1), ("bad\0name", 1), ("fixture", 0), ("fixture", True), ("fixture", 4), (None, 1)])
def test_descriptor_parameters_cannot_select_files_or_unsafe_flags(name, flags):
    with pytest.raises(PolicyError): memfd.memfd_create(name, flags)


def test_native_failure_is_not_retried_or_written_to_disk(monkeypatch):
    def failed(*args, **kwargs): raise OSError(errno.ENOSPC, "synthetic allocation failure")
    monkeypatch.setattr(os, "memfd_create", failed, raising=False)
    monkeypatch.setattr(memfd.ctypes, "CDLL", lambda *a, **k: pytest.fail("native failure retried"))
    with pytest.raises(OSError): memfd.memfd_create("fixture")


def test_missing_linux_primitive_has_no_disk_fallback(monkeypatch):
    monkeypatch.delattr(os, "memfd_create", raising=False)
    monkeypatch.setattr(memfd.ctypes, "CDLL", lambda *a, **k: object())
    with pytest.raises(PolicyError, match="no disk fallback"): memfd.memfd_create("fixture")


def test_other_platform_is_not_admitted(monkeypatch):
    monkeypatch.setattr(memfd.sys, "platform", "synthetic-other")
    with pytest.raises(PolicyError): memfd.memfd_create("fixture")


def test_write_all_handles_short_writes_and_interruptions(monkeypatch):
    writes = []
    outcomes = iter([InterruptedError(), 2, 1, 3])
    def write(fd, data):
        outcome = next(outcomes)
        if isinstance(outcome, BaseException): raise outcome
        writes.append(bytes(data[:outcome])); return outcome
    monkeypatch.setattr(memfd.os, "write", write)
    memfd.write_all(9, b"abcdef")
    assert b"".join(writes) == b"abcdef"


@pytest.mark.parametrize("outcome", [0, -1, 99, None])
def test_write_all_rejects_no_or_invalid_progress(monkeypatch, outcome):
    monkeypatch.setattr(memfd.os, "write", lambda *_: outcome)
    with pytest.raises(OSError, match="no progress"):
        memfd.write_all(9, b"fixture")


def test_write_all_propagates_terminal_write_error(monkeypatch):
    failure = OSError(errno.ENOSPC, "synthetic terminal write error")
    monkeypatch.setattr(memfd.os, "write", lambda *_: (_ for _ in ()).throw(failure))
    with pytest.raises(OSError) as raised:
        memfd.write_all(9, b"fixture")
    assert raised.value.errno == errno.ENOSPC
