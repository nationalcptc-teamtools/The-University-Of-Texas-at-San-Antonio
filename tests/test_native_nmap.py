"""Synthetic localhost acceptance tests for the native Nmap bridge."""
from __future__ import annotations

from dataclasses import replace
import base64
from pathlib import Path
import socket
import subprocess
import threading
import time

import pytest

from cptc_harness import nmap_bridge
from cptc_harness.contracts import (Bounds, ExecutionContext, ModuleSpec,
                                    EvidenceRef, OperationRequest, PolicyError,
                                    PolicySnapshot, ScopeSpec, SourceRef,
                                    TargetPolicy, TargetRef)
from cptc_harness.nmap_bridge import NmapCollector


pytestmark = pytest.mark.skipif(
    not Path("/usr/bin/nmap").is_file() or not Path("/usr/bin/bwrap").is_file(),
    reason="native Nmap and bubblewrap are required for synthetic bridge acceptance",
)


class _SyntheticNetwork:
    def __init__(self):
        self.events = []
        self.rates = 0
        self.stops = []
        self.action_id = "native-nmap"
        self.ledger = _AttemptLedger()

    def _event(self, kind, data):
        self.events.append((kind, data))

    def _rate(self, target_id):
        self.rates += 1

    def _stop(self, reason):
        self.stops.append(reason)


class _AttemptLedger:
    def __init__(self):
        self.calls = []

    def begin_attempt(self, request_id, attempt_id, **timing):
        self.calls.append(("begin", request_id, attempt_id, timing))

    def record_attempt_event(self, request_id, attempt_id, event_id, **usage):
        self.calls.append(("event", request_id, attempt_id, event_id, usage))
        return True

    def finish_attempt(self, request_id, attempt_id, **receipt):
        self.calls.append(("finish", request_id, attempt_id, receipt))
        return receipt


class _Transport:
    def __init__(self, address):
        self._addresses = (address,)


def _spec():
    return ModuleSpec("network.nmap_inventory", "1", "network", "bounded", (),
                      Bounds(timeout_s=30.0, request_limit=1, output_bytes=131072, process_limit=1,
                             tcp_connects=1),
                      {"type": "object", "properties": {}, "required": ()},
                      {"type": "object", "properties": {}, "required": ()})


def _context(port, *, stopped=lambda: False, capture=None):
    target = TargetRef("synthetic-loopback", f"http://127.0.0.1:{port}/", "http", "127.0.0.1", port)
    policy = PolicySnapshot("synthetic", "r1", "ws", "device", "operator",
                            ScopeSpec(("127.0.0.0/8",)),
                            targets=(TargetPolicy(target, True, "synthetic", "ws", "", ("network.nmap_inventory",)),))
    request = OperationRequest("native-nmap", "ws", "device", "operator", "network.nmap_inventory",
                               target, {}, "operator", "approved", "r1")
    return ExecutionContext(request, _spec(), policy, transport=_Transport("127.0.0.1"),
                            stopped=stopped, capture=capture,
                            source=SourceRef("synthetic-native", "0" * 64))


@pytest.fixture
def shim(tmp_path):
    root = Path(__file__).parents[1]
    output = tmp_path / "nmap-connect.so"
    subprocess.run([root / "cptc_harness/native/build-nmap-shim.sh", output], check=True)
    return output


@pytest.fixture
def admitted_native(monkeypatch, shim):
    native = {"nmap": Path("/usr/bin/nmap"), "nmap-shim": shim}
    monkeypatch.setattr(nmap_bridge, "verified_native_file", lambda name: native[name])
    monkeypatch.setattr(nmap_bridge, "verified_executable", lambda path: Path(path))
    return native


@pytest.fixture
def listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(2)
    accepted = []
    done = threading.Event()

    def accept_once():
        try:
            client, _ = server.accept()
            accepted.append(client.getpeername())
            client.close()
        finally:
            done.set()

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1], accepted, done
    finally:
        server.close()
        thread.join(timeout=1)


def _unused_loopback_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _fake_nmap(tmp_path, port, body, *, delay=0, write_before_delay=False):
    """A synthetic scanner that must use the real preload bridge before output."""
    if len(body) > 4096:
        writer = f"sys.stdout.buffer.write(b\"x\"*{len(body)}); sys.stdout.buffer.flush()"
    else:
        payload = base64.b64encode(body).decode("ascii")
        writer = f"sys.stdout.buffer.write(base64.b64decode(\"{payload}\")); sys.stdout.buffer.flush()"
    action = f"{writer}; time.sleep({delay})" if write_before_delay else f"time.sleep({delay}); {writer}"
    scanner = tmp_path / "synthetic-nmap"
    scanner.write_text(
        "#!/bin/sh\nexec /usr/bin/python3 -c 'import base64,socket,sys,time; "
        f"sock=socket.socket(); sock.connect((\"127.0.0.1\",{port})); sock.close(); "
        f"{action}'\n",
        encoding="utf-8",
    )
    scanner.chmod(0o700)
    return scanner


def _evidence_capture():
    captured = []

    def capture(stream, raw, classification):
        captured.append((stream, raw, classification))
        return EvidenceRef(str(len(captured)), None, stream, classification, None, "0" * 64, len(raw))

    return captured, capture


def _two_probe_nmap(tmp_path, port):
    scanner = tmp_path / "two-probe-nmap"
    scanner.write_text(
        "#!/bin/sh\nexec /usr/bin/python3 -c 'import socket; "
        f"a=socket.socket(); a.connect((\"127.0.0.1\",{port})); a.close(); "
        f"b=socket.socket(); b.connect((\"127.0.0.1\",{port})); b.close()'\n",
        encoding="utf-8",
    )
    scanner.chmod(0o700)
    return scanner


def test_shim_builds(shim):
    assert shim.is_file() and shim.stat().st_size > 1000


def test_native_bridge_reports_real_open_listener_once(admitted_native, listener):
    port, accepted, done = listener
    network = _SyntheticNetwork()
    captured = []
    context = replace(_context(port, capture=lambda stream, raw, classification: captured.append((stream, raw, classification)),),
                      network=network)

    result = NmapCollector().collect(context)

    assert result.status == "complete"
    observation = result.facts["observations"][0]
    assert observation["target"] == "127.0.0.1"
    assert observation["facts"]["ports"][0]["port"] == port
    assert observation["facts"]["ports"][0]["state"] == "open"
    assert done.wait(1) and len(accepted) == 1
    assert network.rates == 1
    assert [call[0] for call in network.ledger.calls] == ["begin", "event", "finish"]
    assert network.ledger.calls[1][4] == {"tcp_connects": 1}
    assert network.ledger.calls[2][3]["state"] == "complete"
    assert {item[0] for item in captured} == {"stdout", "stderr"}
    assert all(item[2] == "client_confidential_human_only" for item in captured)


def test_native_bridge_reports_real_refused_port_once(admitted_native):
    port = _unused_loopback_port()
    network = _SyntheticNetwork()

    result = NmapCollector().collect(replace(_context(port), network=network))

    assert result.status == "complete"
    ports = result.facts["observations"][0]["facts"]["ports"]
    assert ports[0]["port"] == port and ports[0]["state"] == "closed"
    assert network.rates == 1


def test_pin_failure_blocks_before_any_connection(monkeypatch, listener):
    port, accepted, done = listener
    monkeypatch.setattr(nmap_bridge, "verified_native_file", lambda _name: (_ for _ in ()).throw(PolicyError("pin blocked")))
    network = _SyntheticNetwork()

    result = NmapCollector().collect(replace(_context(port), network=network))

    assert result.status == "blocked"
    assert network.rates == 0 and not done.wait(0.1) and not accepted


def test_cleanup_failure_after_probe_latches_stop_and_is_uncertain(admitted_native, listener, monkeypatch):
    port, accepted, done = listener
    network = _SyntheticNetwork()
    def fail_cleanup(_process):
        raise nmap_bridge._BridgeFailure("synthetic termination failure")
    monkeypatch.setattr(nmap_bridge, "_terminate", fail_cleanup)
    result = NmapCollector().collect(replace(_context(port), network=network))
    assert network.rates == 1 and done.wait(1) and len(accepted) == 1
    assert result.status == "uncertain" and network.stops
    assert "termination failed" in result.reason


def test_ipv6_is_explicitly_unadmitted_before_any_probe():
    ctx = _context(443)
    target = TargetRef("synthetic-loopback", "http://[::1]:443/", "http", "::1", 443)
    policy = replace(ctx.policy, scope=ScopeSpec(("::1/128",)),
                     targets=(replace(ctx.policy.targets[0], target=target),))
    network = _SyntheticNetwork()
    result = NmapCollector().collect(replace(ctx, request=replace(ctx.request, target=target),
        policy=policy, transport=_Transport("::1"), network=network))
    assert result.status == "blocked" and "IPv4 only" in result.reason
    assert network.rates == 0


def test_parent_rechecks_pinned_address_against_scope_before_any_connection(admitted_native, listener):
    port, accepted, done = listener
    network = _SyntheticNetwork()
    context = _context(port)
    context = replace(context, policy=replace(context.policy, scope=ScopeSpec(("192.0.2.0/24",))), network=network)

    result = NmapCollector().collect(context)

    assert result.status == "blocked"
    assert network.rates == 0 and not done.wait(0.1) and not accepted


def test_stop_blocks_before_any_connection(admitted_native, listener):
    port, accepted, done = listener
    network = _SyntheticNetwork()

    result = NmapCollector().collect(replace(_context(port, stopped=lambda: True), network=network))

    assert result.status == "stopped"
    assert network.rates == 0 and not done.wait(0.1) and not accepted


def test_malformed_xml_after_parent_probe_stops_the_network(admitted_native, listener, tmp_path):
    port, accepted, done = listener
    admitted_native["nmap"] = _fake_nmap(tmp_path, port, b"not XML")
    network = _SyntheticNetwork()
    captured, capture = _evidence_capture()

    result = NmapCollector().collect(replace(_context(port, capture=capture), network=network))

    assert result.status == "uncertain" and network.stops
    assert network.rates == 1 and done.wait(1) and len(accepted) == 1
    assert result.evidence and captured
    assert any(kind == "native_nmap_process_completed" for kind, _data in network.events)


def test_oversized_scanner_output_stops_the_network(admitted_native, listener, tmp_path):
    port, accepted, done = listener
    admitted_native["nmap"] = _fake_nmap(tmp_path, port, b"x" * 131073)
    network = _SyntheticNetwork()

    evidence = []
    def capture(stream, raw, classification):
        evidence.append((stream, raw, classification))
        return EvidenceRef(str(len(evidence)), None, stream, classification, None, "0" * 64, len(raw))

    result = NmapCollector().collect(replace(_context(port, capture=capture), network=network))

    assert result.status == "uncertain" and network.stops
    assert network.rates == 1 and done.wait(1) and len(accepted) == 1
    assert result.evidence and {stream for stream, _raw, _class in evidence} == {"stdout", "stderr"}
    assert result.facts == {}


def test_timeout_after_parent_probe_stops_the_network(admitted_native, listener, tmp_path, monkeypatch):
    port, accepted, done = listener
    admitted_native["nmap"] = _fake_nmap(tmp_path, port, b"partial", delay=5, write_before_delay=True)
    monkeypatch.setattr(nmap_bridge, "_PROCESS_DEADLINE_S", 0.1)
    network = _SyntheticNetwork()
    captured, capture = _evidence_capture()

    result = NmapCollector().collect(replace(_context(port, capture=capture), network=network))

    assert result.status == "uncertain" and network.stops
    assert network.ledger.calls[-1][0] == "finish"
    assert network.ledger.calls[-1][3]["state"] == "uncertain"
    assert network.rates == 1 and done.wait(1) and len(accepted) == 1
    assert result.evidence and any(raw == b"partial" for _stream, raw, _class in captured)
    assert any(kind == "native_nmap_process_completed" for kind, _data in network.events)


def test_stop_after_parent_probe_is_uncertain_and_stops_network(admitted_native, listener, tmp_path):
    port, accepted, done = listener
    admitted_native["nmap"] = _fake_nmap(tmp_path, port, b"partial", delay=5, write_before_delay=True)
    network = _SyntheticNetwork()
    captured, capture = _evidence_capture()
    started = time.monotonic()

    result = NmapCollector().collect(replace(
        _context(port, stopped=lambda: network.rates == 1 and time.monotonic() - started > 0.2, capture=capture),
        network=network,
    ))

    assert result.status == "uncertain" and network.stops
    assert network.rates == 1 and done.wait(1) and len(accepted) == 1
    assert result.evidence and any(raw == b"partial" for _stream, raw, _class in captured)
    assert any(kind == "native_nmap_process_completed" for kind, _data in network.events)


def test_second_native_connect_is_denied_without_another_parent_probe(admitted_native, listener, tmp_path):
    port, accepted, done = listener
    admitted_native["nmap"] = _two_probe_nmap(tmp_path, port)
    network = _SyntheticNetwork()

    result = NmapCollector().collect(replace(_context(port), network=network))

    assert result.status == "uncertain" and network.stops
    assert network.rates == 1 and done.wait(1) and len(accepted) == 1
