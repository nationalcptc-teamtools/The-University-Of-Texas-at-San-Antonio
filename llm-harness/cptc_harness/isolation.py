"""Bubblewrap runner for fixed, reviewed local workers."""
from __future__ import annotations
from .memfd import memfd_create, MFD_CLOEXEC, MFD_ALLOW_SEALING, seal_readonly

import hashlib
import ctypes
import ctypes.util
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import time
from typing import Any, Callable, Iterable

from .contracts import NetworkGrant, PolicyError, WorkerCapture, WorkerSpec
from .integrity import verified_executable


class IsolatedRunner:
    """Runs only exact allowlisted WorkerSpecs in a namespace with no mounts of work data."""
    def __init__(self, allowed_specs: Iterable[WorkerSpec] = (), *, bwrap: str = "bwrap",
                 grant_validator: Callable[[NetworkGrant], int | None] | None = None) -> None:
        self.allowed = tuple(allowed_specs)
        self.bwrap, self.grant_validator = bwrap, grant_validator

    def run(self, spec: WorkerSpec, stdin: bytes, grant: NetworkGrant | None = None, *, stopped=lambda: False) -> WorkerCapture:
        started = time.monotonic()
        if spec not in self.allowed:
            return WorkerCapture("blocked", reason="worker is not a fixed allowlisted specification")
        if spec.bounds.process_limit != 1 or not 0 < spec.bounds.timeout_s <= 60 or not 0 < spec.bounds.output_bytes <= 131072:
            return WorkerCapture("blocked", reason="worker bounds are outside admitted containment")
        executable = Path(spec.executable)
        try:
            if not executable.is_file() or hashlib.sha256(executable.read_bytes()).hexdigest() != spec.source_hash:
                return WorkerCapture("blocked", reason="worker hash mismatch")
            launcher = str(verified_executable("/usr/bin/bwrap"))
            socket_fd: int | None = None
            try:
                if grant is not None:
                    if self.grant_validator is None or not grant.grant_id or not grant.expires_at:
                        return WorkerCapture("blocked", reason="unverified network grant")
                    socket_fd = self.grant_validator(grant)
                    if socket_fd is None: return WorkerCapture("blocked", reason="invalid network grant")
                    # stdin is transport data only in this narrow reviewed mode; arbitrary dual inputs are rejected.
                    if stdin: return WorkerCapture("blocked", reason="network worker cannot receive arbitrary stdin")
                seccomp_fd = fork_denial_filter()
                command = [launcher, "--unshare-all", "--cap-drop", "ALL", "--seccomp", str(seccomp_fd), "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                           "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev",
                           "--die-with-parent", "--new-session", "--clearenv", "--dir", "/tmp", "--chdir", "/tmp", "--",
                           spec.executable, *spec.args]
                try:
                    process = subprocess.Popen(command, stdin=socket_fd if socket_fd is not None else subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, pass_fds=(seccomp_fd,), env={},
                        preexec_fn=self._limits(spec), start_new_session=True)
                finally:
                    os.close(seccomp_fd)
                return self._collect(process, stdin if socket_fd is None else b"", spec.bounds.output_bytes, spec.bounds.timeout_s, started, stopped)
            finally:
                if socket_fd is not None:
                    try: os.close(socket_fd)
                    except OSError: pass
        except (OSError, ValueError, PolicyError) as exc:
            return WorkerCapture("failed", reason="isolation setup failed", elapsed_s=time.monotonic()-started)

    @staticmethod
    def _limits(spec: WorkerSpec):
        def apply() -> None:
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
            resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_CPU, (max(1, int(spec.bounds.timeout_s)), max(2, int(spec.bounds.timeout_s) + 1)))
            resource.setrlimit(resource.RLIMIT_FSIZE, (max(1024, spec.bounds.output_bytes), max(1024, spec.bounds.output_bytes)))
        return apply

    @staticmethod
    def _collect(process: subprocess.Popen[bytes], stdin: bytes, maximum: int, timeout: float, started: float, stopped) -> WorkerCapture:
        selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ, "stdout"); selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        if process.stdin is not None:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        out = bytearray(); err = bytearray(); pending = memoryview(stdin); truncated = False
        try:
            while selector.get_map():
                if stopped() or time.monotonic() - started > timeout:
                    os.killpg(process.pid, signal.SIGKILL)
                    return WorkerCapture("uncertain", bytes(out), bytes(err), reason="worker stopped or deadline reached", truncated=truncated, elapsed_s=time.monotonic()-started)
                for key, _ in selector.select(0.05):
                    if key.data == "stdin":
                        if pending:
                            wrote = os.write(key.fileobj.fileno(), pending); pending = pending[wrote:]
                        if not pending: selector.unregister(key.fileobj); key.fileobj.close()
                        continue
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data: selector.unregister(key.fileobj); continue
                    available = maximum - len(out) - len(err)
                    bucket = out if key.data == "stdout" else err
                    if available <= 0 or len(data) > available:
                        bucket.extend(data[:max(0, available)]); truncated = True; os.killpg(process.pid, signal.SIGKILL)
                    else: bucket.extend(data)
                if process.poll() is not None and not selector.get_map(): break
            code = process.wait(timeout=1)
            return WorkerCapture("complete" if code == 0 and not truncated else "failed", bytes(out), bytes(err), code,
                                 "output cap exceeded" if truncated else None, truncated, time.monotonic()-started)
        except OSError:
            if process.poll() is None: os.killpg(process.pid, signal.SIGKILL)
            return WorkerCapture("uncertain", bytes(out), bytes(err), reason="worker stream failure", truncated=truncated, elapsed_s=time.monotonic()-started)
        finally:
            for item in list(selector.get_map().values()):
                try: selector.unregister(item.fileobj)
                except Exception: pass
            selector.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def fork_denial_filter() -> int:
    """Kernel denies all new processes/threads after the reviewed worker starts."""
    name = ctypes.util.find_library("seccomp")
    if not name:
        raise PolicyError("seccomp is required for the one-process worker profile")
    library = ctypes.CDLL(name, use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise PolicyError("seccomp initialization failed")
    fd = memfd_create("cptc-fork-filter", MFD_CLOEXEC)
    try:
        for call in (b"fork", b"vfork", b"clone", b"clone3", b"unshare", b"setns"):
            number = library.seccomp_syscall_resolve_name(call)
            if number >= 0 and library.seccomp_rule_add(context, 0x00050001, number, 0) != 0:  # EPERM
                raise PolicyError("seccomp rule installation failed")
        if library.seccomp_export_bpf(context, fd) != 0:
            raise PolicyError("seccomp export failed")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except Exception:
        os.close(fd)
        raise
    finally:
        library.seccomp_release(context)


def shutil_which(command: str) -> str | None:
    if os.path.sep in command: return command if os.access(command, os.X_OK) else None
    for directory in os.environ.get("PATH", "/usr/bin:/bin").split(os.pathsep):
        path = Path(directory) / command
        if os.access(path, os.X_OK): return str(path)
    return None
