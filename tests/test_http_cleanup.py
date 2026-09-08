from __future__ import annotations

import os
import io
import subprocess
import time

import pytest

from cptc_harness.contracts import PolicySnapshot, ScopeSpec, TargetRef, TargetPolicy, TargetRequest, PolicyError
from cptc_harness.network import NetworkBroker


TARGET = TargetRef("loop", "http://127.0.0.1:8080/", "http", "127.0.0.1", 8080)


class Socket:
    def __init__(self): self.closed = False
    def setblocking(self, _): pass
    def close(self): self.closed = True


def test_second_memfd_failure_closes_connected_socket_and_first_fd(monkeypatch):
    broker = NetworkBroker(PolicySnapshot("e", "r", "w", "d", "o", ScopeSpec()))
    sock = Socket(); closed = []
    real_open, real_close = os.open, os.close
    monkeypatch.setattr("cptc_harness.network.verified_executable", lambda path: path)
    monkeypatch.setattr("cptc_harness.network.socket.create_connection", lambda *_args, **_kw: sock)
    monkeypatch.setattr("cptc_harness.network.seal_readonly", lambda _fd: None)
    calls = []
    def memfd(_name, **_kw):
        calls.append(1)
        if len(calls) == 2: raise OSError("second allocation failed")
        return real_open("/dev/null", os.O_RDWR)
    monkeypatch.setattr("cptc_harness.network.memfd_create", memfd)
    def close(fd):
        closed.append(fd); real_close(fd)
    monkeypatch.setattr("cptc_harness.network.os.close", close)

    with pytest.raises(OSError):
        broker._isolated_http("127.0.0.1", TARGET, "GET", "/", {"Host": "x"}, 32, 1)
    assert sock.closed and len(closed) == 1


def test_launch_failure_closes_all_setup_resources(monkeypatch):
    broker = NetworkBroker(PolicySnapshot("e", "r", "w", "d", "o", ScopeSpec()))
    sock = Socket(); closed = []
    real_open, real_close = os.open, os.close
    monkeypatch.setattr("cptc_harness.network.verified_executable", lambda path: path)
    monkeypatch.setattr("cptc_harness.network.socket.create_connection", lambda *_args, **_kw: sock)
    monkeypatch.setattr("cptc_harness.network.seal_readonly", lambda _fd: None)
    monkeypatch.setattr("cptc_harness.network.memfd_create", lambda _name, **_kw: real_open("/dev/null", os.O_RDWR))
    monkeypatch.setattr("cptc_harness.network.subprocess.Popen", lambda *_args, **_kw: (_ for _ in ()).throw(OSError("launch failed")))
    def close(fd):
        closed.append(fd); real_close(fd)
    monkeypatch.setattr("cptc_harness.network.os.close", close)

    with pytest.raises(OSError):
        broker._isolated_http("127.0.0.1", TARGET, "GET", "/", {"Host": "x"}, 32, 1)
    assert sock.closed and len(closed) == 2


@pytest.mark.parametrize("failure", ["intent", "kill", "reap", "capture"])
def test_cleanup_faults_close_pipes_and_latch_network_stop(monkeypatch, failure):
    policy = PolicySnapshot("e", "r", "w", "d", "o", ScopeSpec(("127.0.0.0/8",)),
                            targets=(TargetPolicy(TARGET, True, "fixture", "w", "", ("web.headers",)),))
    broker = NetworkBroker(policy)
    sock = Socket()
    closed, timeouts = [], []
    real_close = os.close
    monkeypatch.setattr("cptc_harness.network.socket.create_connection", lambda *a, **kw: sock)
    def close(fd):
        closed.append(fd)
        real_close(fd)
    monkeypatch.setattr("cptc_harness.network.os.close", close)
    class Process:
        pid = 123456789
        returncode = None
        def __init__(self):
            self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
            self.killed = False
        def poll(self): return self.returncode
        def kill(self): self.killed = True; self.returncode = -9
        def communicate(self, *, timeout):
            timeouts.append(timeout)
            if failure == "reap": raise subprocess.TimeoutExpired("synthetic", timeout)
            if self.returncode is None and failure != "capture": raise OSError("synthetic wait failure")
            self.returncode = 0 if failure == "capture" else -9
            return b'{"status":200,"headers":{},"body":"","elapsed":0,"truncated":false}', b""
    process = Process()
    monkeypatch.setattr("cptc_harness.network.subprocess.Popen", lambda *a, **kw: process)
    def killpg(*_):
        if failure == "kill": raise PermissionError("synthetic kill failure")
        process.returncode = -9
    monkeypatch.setattr("cptc_harness.network.os.killpg", killpg)
    class Audit:
        def emit(self, event):
            if failure == "intent" and event.kind == "process_intent": raise OSError("synthetic intent failure")
        def capture(self, *args):
            if failure == "capture": raise PolicyError("synthetic capture failure")
    broker.audit, broker.action_id = Audit(), "synthetic"
    started = time.monotonic()
    with pytest.raises(PolicyError):
        broker.target_transport(TARGET, timeout_s=.05).request(TargetRequest())
    assert time.monotonic()-started < 2
    assert broker._stopped and sock.closed and len(closed) == 2
    if failure != "intent":
        assert process.stdout.closed and process.stderr.closed
        assert timeouts and all(0 < value <= 1 for value in timeouts)
    if failure == "kill": assert process.killed


def test_actual_http_timeout_reaps_worker_without_retry():
    from test_response_capture_failures import RecordingAudit, response_server
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\npartial"
    with response_server(raw, pause=True) as (target, policy, requests):
        audit = RecordingAudit()
        broker = NetworkBroker(policy, audit=audit)
        broker.action_id = "synthetic"
        with pytest.raises(PolicyError):
            broker.target_transport(target, timeout_s=.3).request(TargetRequest(path=target.base_path))
        assert broker._stopped and len(requests) == 1
        pid = next(event.data["pid"] for event in audit.events if event.kind == "process_started")
        with pytest.raises(ProcessLookupError): os.kill(pid, 0)
        assert any(event.kind == "process_completed" for event in audit.events)
