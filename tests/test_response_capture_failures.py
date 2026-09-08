"""Adversarial synthetic transport failures exercise actual isolated workers."""
from contextlib import contextmanager
from dataclasses import replace
import os
import socket
import threading
import time

import pytest

from cptc_harness.contracts import PolicyError, PolicySnapshot, ScopeSpec, TargetPolicy, TargetRef
from cptc_harness.network import NetworkBroker
from cptc_harness.response_capture import ResponseCaptureCollector
from test_response_capture import context


class RecordingAudit:
    def __init__(self): self.chunks, self.events = [], []
    def capture(self, action, stream, raw, classification):
        self.chunks.append((stream, raw, classification, time.monotonic()))
    def emit(self, event): self.events.append(event)


@contextmanager
def response_server(payload, *, pause=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(2)
    release = threading.Event()
    requests = []
    def serve():
        try:
            channel, _ = listener.accept()
            with channel:
                channel.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request and len(request) < 4096:
                    request += channel.recv(4096)
                requests.append(request)
                # Force an odd chunk boundary around the collection limit.
                channel.sendall(payload[:30001])
                if len(payload) > 30001:
                    time.sleep(.03)
                    channel.sendall(payload[30001:])
                if pause:
                    release.wait(2)
        except (OSError, TimeoutError):
            pass
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    port = listener.getsockname()[1]
    target = TargetRef("loop", f"http://127.0.0.1:{port}/exact", "http", "127.0.0.1", port, "/exact")
    policy = PolicySnapshot("fixture", "r", "w", "d", "o", ScopeSpec(("127.0.0.0/8",)),
                           targets=(TargetPolicy(target, True, "fixture", "w", "", ("web.response_capture",), request_limit=2),))
    try:
        yield target, policy, requests
    finally:
        release.set()
        listener.close()
        thread.join(timeout=3)


@pytest.mark.parametrize("case", ["oversize", "timeout", "stop"])
def test_partial_wire_bytes_survive_worker_failure_and_no_retry(case):
    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\n"
    payload = prefix + (b"x" * 40000 if case == "oversize" else b"partial-synthetic-body")
    with response_server(payload, pause=case != "oversize") as (target, policy, requests):
        audit = RecordingAudit()
        network = NetworkBroker(policy, audit=audit)
        network.action_id = "synthetic-action"
        if case == "stop":
            class StopLedger:
                def stopped(self): return any(item[0] == "stdout" for item in audit.chunks)
                def stop(self, _): pass
                def rate_gate(self, *_): pass
            network.ledger = StopLedger()
        transport = network.target_transport(target, timeout_s=.4, request_limit=1)
        with pytest.raises(PolicyError):
            transport.capture_response()
        retained = b"".join(raw for stream, raw, _, _ in audit.chunks if stream == "stdout")
        assert retained == payload[:32768] if case == "oversize" else retained == payload
        assert all(row[2] == "client_confidential_human_only" for row in audit.chunks)
        assert network._stopped and len(requests) == 1
        assert requests[0].startswith(b"GET /exact HTTP/1.1\r\n")
        assert b"Connection: close\r\n" in requests[0]
        assert any(event.kind == "response_capture_completed" and event.data["capture_incomplete"] for event in audit.events)
        with pytest.raises(PolicyError):
            transport.capture_response()
        assert len(requests) == 1


@pytest.mark.parametrize("status", [423, 429, 500, 503])
def test_health_indicators_stop_and_keep_evidence(status):
    ctx, evidence = context(f"HTTP/1.1 {status} Synthetic\r\nContent-Length: 0\r\n\r\n".encode())
    result = ResponseCaptureCollector().collect(ctx)
    assert result.status == "uncertain" and result.evidence and evidence
    assert ctx.network.stops and ctx.transport.calls == 1


def test_missing_evidence_reference_cannot_report_completion():
    ctx, _ = context(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    ctx = replace(ctx, capture=lambda *_: None)
    assert ResponseCaptureCollector().collect(ctx).status == "uncertain"
    assert ctx.network.stops


@pytest.mark.parametrize("path", ["//other", "/../other", "/%2f", "/?token=x", "/\r\nx:y", "/" + "x" * 2048])
def test_bad_capture_path_denied_before_rate_or_connection(monkeypatch, path):
    from test_response_capture import POLICY, TARGET
    target = replace(TARGET, base_path=path)
    policy = replace(POLICY, targets=(replace(POLICY.targets[0], target=target),))
    network = NetworkBroker(policy)
    monkeypatch.setattr(network, "_rate", lambda *_: pytest.fail("must reject before rate reservation"))
    monkeypatch.setattr(network, "_isolated_response", lambda *_: pytest.fail("must not connect"))
    with pytest.raises(PolicyError, match="base path"):
        network.target_transport(target).capture_response()


def test_capture_rate_and_scope_gates_have_no_retry(monkeypatch):
    from test_response_capture import POLICY, TARGET
    policy = replace(POLICY, targets=(replace(POLICY.targets[0], request_limit=2),))
    network = NetworkBroker(policy)
    calls = []
    monkeypatch.setattr(network, "_isolated_response", lambda *_: calls.append(1) or b"synthetic")
    transport = network.target_transport(TARGET, request_limit=2)
    assert transport.capture_response() == b"synthetic"
    with pytest.raises(PolicyError, match="rate"):
        transport.capture_response()
    assert calls == [1]
    with pytest.raises(PolicyError, match="scope"):
        NetworkBroker(replace(policy, scope=ScopeSpec(("192.0.2.0/24",)))).target_transport(TARGET)


@pytest.mark.parametrize("failure", ["second_memfd", "intent", "connect", "launch"])
def test_early_failures_close_acquired_descriptors(monkeypatch, failure):
    import cptc_harness.network as module
    from test_response_capture import POLICY, TARGET
    real_create = os.memfd_create
    descriptors = []
    def allocate(*args, **kwargs):
        if failure == "second_memfd" and descriptors:
            raise OSError("synthetic allocation failure")
        descriptor = real_create(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor
    monkeypatch.setattr(module.os, "memfd_create", allocate)
    network = NetworkBroker(POLICY)
    if failure == "intent":
        monkeypatch.setattr(network, "_event", lambda *_: (_ for _ in ()).throw(OSError("synthetic audit failure")))
    peer = None
    if failure == "launch":
        local, peer = socket.socketpair()
        monkeypatch.setattr(module.socket, "create_connection", lambda *a, **kw: local)
        monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **kw: (_ for _ in ()).throw(OSError("synthetic launch failure")))
    else:
        monkeypatch.setattr(module.socket, "create_connection", lambda *a, **kw: (_ for _ in ()).throw(OSError("synthetic connect failure")))
    try:
        with pytest.raises(OSError):
            network._isolated_response("127.0.0.1", TARGET, .3)
        for descriptor in descriptors:
            with pytest.raises(OSError): os.fstat(descriptor)
        if failure == "launch": assert local.fileno() == -1
    finally:
        if peer is not None: peer.close()
