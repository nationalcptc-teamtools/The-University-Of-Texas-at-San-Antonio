"""Synthetic setup faults must not retain descriptors or children."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import signal
import subprocess
import time

import pytest

from cptc_harness.contracts import Bounds, PolicySnapshot, ScopeSpec, WorkerSpec


class Channel:
    def __init__(self): self.closed = False
    def settimeout(self, _): pass
    def close(self): self.closed = True


class Process:
    pid = 424242
    def __init__(self): self.killed = self.waited = False
    def poll(self): return None
    def kill(self): self.killed = True
    def wait(self, timeout): self.waited = True; return -9


def _audit_policy():
    return PolicySnapshot("synthetic", "r", "w", "d", "operator", ScopeSpec())


@pytest.mark.parametrize("failure", ["memfd", "write", "seek", "seal", "worker", "bwrap", "python", "launch", "initial_info"])
def test_audit_setup_failure_closes_channels_memfd_and_child(monkeypatch, tmp_path, failure):
    import cptc_harness.audit_service as service
    parent, child = Channel(), Channel()
    descriptor = os.open("/dev/null", os.O_RDWR) if failure != "memfd" else None
    created = Process()
    monkeypatch.setattr(service.socket, "socketpair", lambda: (parent, child))
    if failure == "memfd":
        monkeypatch.setattr(service, "memfd_create", lambda *_: (_ for _ in ()).throw(OSError("memfd")))
    else:
        monkeypatch.setattr(service, "memfd_create", lambda *_: descriptor)
    monkeypatch.setattr(service, "write_all", lambda *_: (_ for _ in ()).throw(OSError("write")) if failure == "write" else None)
    monkeypatch.setattr(service.os, "lseek", lambda *_: (_ for _ in ()).throw(OSError("seek")) if failure == "seek" else 0)
    monkeypatch.setattr(service, "seal_readonly", lambda *_: (_ for _ in ()).throw(OSError("seal")) if failure == "seal" else None)
    monkeypatch.setattr(service, "verified_worker", lambda *_: (_ for _ in ()).throw(OSError("worker")) if failure == "worker" else tmp_path / "worker.py")
    executable_calls = []
    def executable(path):
        executable_calls.append(path)
        if (failure == "bwrap" and len(executable_calls) == 1) or (failure == "python" and len(executable_calls) == 2):
            raise OSError("executable")
        return path
    monkeypatch.setattr(service, "verified_executable", executable)
    monkeypatch.setattr(service.os, "killpg", lambda *_: None)
    if failure == "launch":
        monkeypatch.setattr(service.subprocess, "Popen", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("launch")))
    else:
        monkeypatch.setattr(service.subprocess, "Popen", lambda *_a, **_kw: created)
        monkeypatch.setattr(service.AuditService, "_request", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("info")))
    with pytest.raises(OSError):
        service.AuditService(tmp_path / "audit", _audit_policy(), age_binary="/age", age_recipient="age1fixture")
    assert parent.closed and child.closed
    if descriptor is not None:
        with pytest.raises(OSError): os.fstat(descriptor)
    if failure == "initial_info": assert created.waited


def test_isolated_runner_closes_grant_fd_after_launch_failure(monkeypatch, tmp_path):
    import cptc_harness.isolation as isolation
    executable = tmp_path / "worker"; executable.write_bytes(b"synthetic")
    spec = WorkerSpec(str(executable), (), Bounds(timeout_s=1, output_bytes=16), hashlib.sha256(b"synthetic").hexdigest())
    descriptor = os.open("/dev/null", os.O_RDONLY)
    seccomp = os.open("/dev/null", os.O_RDONLY)
    monkeypatch.setattr(isolation, "verified_executable", lambda path: path)
    monkeypatch.setattr(isolation, "fork_denial_filter", lambda: seccomp)
    monkeypatch.setattr(isolation.subprocess, "Popen", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("launch")))
    runner = isolation.IsolatedRunner((spec,), grant_validator=lambda _grant: descriptor)
    from cptc_harness.contracts import NetworkGrant
    result = runner.run(spec, b"", NetworkGrant("fixture", (), 1, grant_id="grant", expires_at="future"))
    assert result.status == "failed"
    for value in (descriptor, seccomp):
        with pytest.raises(OSError): os.fstat(value)


def test_isolated_runner_closes_grant_fd_after_successful_launch(monkeypatch, tmp_path):
    import cptc_harness.isolation as isolation
    from cptc_harness.contracts import NetworkGrant, WorkerCapture
    executable = tmp_path / "worker"; executable.write_bytes(b"synthetic")
    spec = WorkerSpec(str(executable), (), Bounds(timeout_s=1, output_bytes=16), hashlib.sha256(b"synthetic").hexdigest())
    descriptor, seccomp = os.open("/dev/null", os.O_RDONLY), os.open("/dev/null", os.O_RDONLY)
    process = object()
    monkeypatch.setattr(isolation, "verified_executable", lambda path: path)
    monkeypatch.setattr(isolation, "fork_denial_filter", lambda: seccomp)
    monkeypatch.setattr(isolation.subprocess, "Popen", lambda *_a, **_kw: process)
    monkeypatch.setattr(isolation.IsolatedRunner, "_collect", lambda self, observed, *_a: WorkerCapture("complete") if observed is process else pytest.fail("wrong child"))
    runner = isolation.IsolatedRunner((spec,), grant_validator=lambda _grant: descriptor)
    assert runner.run(spec, b"", NetworkGrant("fixture", (), 1, grant_id="grant", expires_at="future")).status == "complete"
    for value in (descriptor, seccomp):
        with pytest.raises(OSError): os.fstat(value)


def test_passive_memfd_write_failure_closes_descriptor(monkeypatch):
    import cptc_harness.passive as passive
    descriptor = os.open("/dev/null", os.O_RDWR)
    monkeypatch.setattr(passive, "memfd_create", lambda *_a, **_kw: descriptor)
    monkeypatch.setattr(passive, "write_all", lambda *_a: (_ for _ in ()).throw(OSError("write")))
    with pytest.raises(OSError, match="write"):
        passive._memfd("fixture", b"synthetic")
    with pytest.raises(OSError): os.fstat(descriptor)


def test_passive_systemd_kill_and_cleanup_event_failure_still_kills_and_reaps(monkeypatch, tmp_path):
    """A telemetry or systemd cleanup failure cannot retain the scanner group."""
    import cptc_harness.passive as passive
    scanner = tmp_path / "scanner"; worker = tmp_path / "worker.py"; rule = tmp_path / "rule.yaml"
    for path in (scanner, worker, rule): path.write_bytes(b"synthetic")
    monkeypatch.setattr(passive, "verified_native_file", lambda *_: scanner)
    monkeypatch.setattr(passive, "verified_worker", lambda *_: worker)
    monkeypatch.setattr(passive, "verified_resource", lambda *_: rule)
    monkeypatch.setattr(passive, "verified_executable", lambda path: Path(path))
    real_popen = subprocess.Popen
    child = []
    def launch(*_args, **kwargs):
        process = real_popen(["/bin/sleep", "30"], stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"],
                            start_new_session=True, close_fds=True)
        child.append(process)
        return process
    monkeypatch.setattr(passive.subprocess, "Popen", launch)
    def systemd(command, **_kwargs):
        if "show" in command:
            return SimpleNamespace(stdout=b"ActiveState=active\nMemoryMax=805306368\nTasksMax=128\nRuntimeMaxUSec=45s\n")
        raise subprocess.TimeoutExpired(command, 0.01)
    monkeypatch.setattr(passive.subprocess, "run", systemd)
    killed = []
    real_killpg = os.killpg
    def killpg(pid, sig):
        killed.append((pid, sig)); real_killpg(pid, sig)
    monkeypatch.setattr(passive.os, "killpg", killpg)
    events = []
    def event(kind, data):
        events.append(kind)
        if kind == "passive_process_cleanup": raise OSError("audit unavailable")
    ctx = SimpleNamespace(network=SimpleNamespace(_event=event), spec=SimpleNamespace(bounds=Bounds(timeout_s=1, output_bytes=4096)),
                          stopped=lambda: "passive_process_started" in events,
                          capture=lambda *_: None)
    with pytest.raises(Exception, match="stopped passive scanner"):
        passive.run_native("nuclei", b"synthetic", ctx, [], 4096)
    assert child and killed and child[0].poll() is not None
    assert child[0].stdin.closed and child[0].stdout.closed and child[0].stderr.closed
    assert "passive_process_closed" in events


def test_passive_failure_capture_error_preserves_primary_and_closes_process(monkeypatch, tmp_path):
    """Encrypted capture failure during drain cannot replace the stop result."""
    import cptc_harness.passive as passive
    from cptc_harness.contracts import PolicyError
    scanner = tmp_path / "scanner"; worker = tmp_path / "worker.py"; rule = tmp_path / "rule.yaml"
    for path in (scanner, worker, rule): path.write_bytes(b"synthetic")
    monkeypatch.setattr(passive, "verified_native_file", lambda *_: scanner)
    monkeypatch.setattr(passive, "verified_worker", lambda *_: worker)
    monkeypatch.setattr(passive, "verified_resource", lambda *_: rule)
    monkeypatch.setattr(passive, "verified_executable", lambda path: Path(path))
    real_popen = subprocess.Popen
    child = []
    ready = tmp_path / "ready"
    def launch(*_args, **kwargs):
        script = "printf failure-output >&2; : > '" + str(ready) + "'; sleep 30"
        process = real_popen(["/bin/sh", "-c", script], stdin=kwargs["stdin"],
                             stdout=kwargs["stdout"], stderr=kwargs["stderr"], start_new_session=True, close_fds=True)
        child.append(process)
        for _ in range(100):
            if ready.exists(): break
            time.sleep(.01)
        assert ready.exists()
        return process
    monkeypatch.setattr(passive.subprocess, "Popen", launch)
    def systemd(command, **_kwargs):
        if "show" in command:
            return SimpleNamespace(stdout=b"ActiveState=active\nMemoryMax=805306368\nTasksMax=128\nRuntimeMaxUSec=45s\n")
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(passive.subprocess, "run", systemd)
    events = []
    ctx = SimpleNamespace(network=SimpleNamespace(_event=lambda kind, _data: events.append(kind)),
                          spec=SimpleNamespace(bounds=Bounds(timeout_s=1, output_bytes=4096)),
                          stopped=lambda: "passive_process_started" in events,
                          capture=lambda *_: (_ for _ in ()).throw(PolicyError("synthetic capture unavailable")))
    with pytest.raises(PolicyError, match="operator stopped passive scanner"):
        passive.run_native("nuclei", b"synthetic", ctx, [], 4096)
    assert child and child[0].poll() is not None
    assert child[0].stdin.closed and child[0].stdout.closed and child[0].stderr.closed
    assert "capture_incomplete" in events and "passive_process_closed" in events


def test_provider_timeout_cleanup_is_bounded_closes_all_resources_and_keeps_primary(monkeypatch, tmp_path):
    import socket
    import cptc_harness.providers as providers
    from cptc_harness.contracts import PolicyError
    from cptc_harness.providers import IsolatedHTTP, ProviderProfile
    from cptc_harness.secrets import CredentialRef

    profile = ProviderProfile("fixture", "openai", "https://provider.example", "/chat", "synthetic",
                              ("192.0.2.1",), timeout_s=0.1)
    allocated = []
    def descriptor(*_args, **_kwargs):
        value = os.open("/dev/null", os.O_RDWR)
        allocated.append(value)
        return value
    class Broker:
        def grant(self, _reference, _profile): return descriptor()
    credential = CredentialRef(Broker(), "synthetic-reference", profile)
    class Connection:
        def __init__(self): self.closed = False
        def settimeout(self, _timeout): pass
        def connect(self, _address): pass
        def close(self): self.closed = True
    connection = Connection()
    class Stream:
        def __init__(self): self.closed = False
        def close(self): self.closed = True
    class Process:
        pid = 424243
        def __init__(self):
            self.stdin, self.stdout, self.stderr = Stream(), Stream(), Stream()
            self.returncode = None; self.communications = 0; self.waited = False; self.killed = False
        def poll(self): return self.returncode
        def communicate(self, timeout):
            self.communications += 1
            if self.communications == 1:
                raise subprocess.TimeoutExpired(["fixture"], timeout)
            raise OSError("synthetic communicate cleanup failure")
        def wait(self, timeout):
            self.waited = True
            raise subprocess.TimeoutExpired(["fixture"], timeout)
        def kill(self): self.killed = True
    process = Process()
    times = iter((0.0, 0.0, 1.0))
    monkeypatch.setattr(providers.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(providers.socket, "getaddrinfo", lambda *_a, **_kw: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))])
    monkeypatch.setattr(providers.socket, "socket", lambda *_a, **_kw: connection)
    monkeypatch.setattr(providers, "verified_executable", lambda path: Path(path))
    worker = tmp_path / "worker.py"; worker.write_bytes(b"synthetic")
    ca = tmp_path / "ca.pem"; ca.write_bytes(b"synthetic")
    monkeypatch.setattr(providers, "verified_worker", lambda *_: worker)
    monkeypatch.setattr(providers, "ssl_ca", lambda: ca)
    monkeypatch.setattr(providers, "memfd_create", descriptor)
    monkeypatch.setattr(providers, "write_all", lambda *_: None)
    monkeypatch.setattr(providers.os, "lseek", lambda *_: 0)
    monkeypatch.setattr(providers, "seal_readonly", lambda *_: None)
    monkeypatch.setattr(providers.subprocess, "Popen", lambda *_a, **_kw: process)
    killed = []
    monkeypatch.setattr(providers.os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    transport = IsolatedHTTP(profile)
    with pytest.raises(PolicyError, match="provider deadline exceeded"):
        transport.exchange({"fixture": "synthetic"}, credential=credential)
    assert transport.cancelled.is_set() and killed and process.waited
    assert connection.closed
    assert all(stream.closed for stream in (process.stdin, process.stdout, process.stderr))
    for value in allocated:
        with pytest.raises(OSError): os.fstat(value)


def test_provider_process_finalizer_bounds_reap_and_retries_every_stream_close(monkeypatch):
    import cptc_harness.providers as providers
    from cptc_harness.providers import IsolatedHTTP, ProviderProfile
    profile = ProviderProfile("fixture", "openai", "https://provider.example", "/chat", "synthetic",
                              ("192.0.2.1",), timeout_s=0.1)
    class FlakyStream:
        def __init__(self): self.close_calls = 0; self.closed = False
        def close(self):
            self.close_calls += 1
            if self.close_calls == 1: raise OSError("synthetic close failure")
            self.closed = True
    class Process:
        pid = 424244
        def __init__(self):
            self.stdin, self.stdout, self.stderr = FlakyStream(), FlakyStream(), FlakyStream()
            self.communications = 0; self.waits = 0; self.kills = 0
        def poll(self): return None
        def communicate(self, timeout):
            self.communications += 1
            raise subprocess.TimeoutExpired(["fixture"], timeout)
        def wait(self, timeout):
            self.waits += 1
            raise subprocess.TimeoutExpired(["fixture"], timeout)
        def kill(self): self.kills += 1
    process = Process()
    killed = []
    monkeypatch.setattr(providers.os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    transport = IsolatedHTTP(profile)
    transport.process = process
    assert transport._finalize_process(process) is False
    assert transport.cancelled.is_set() and killed
    assert process.communications == 2 and process.waits == 1
    assert all(stream.closed and stream.close_calls == 2
               for stream in (process.stdin, process.stdout, process.stderr))
