from __future__ import annotations

from array import array
from dataclasses import replace
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import time

import pytest

from cptc_harness.contracts import Bounds, PolicyError, canonical_json
from cptc_harness.integrity import VerifiedRelease
from cptc_harness.ledger import Ledger
from cptc_harness.memfd import MFD_ALLOW_SEALING, MFD_CLOEXEC, memfd_create, seal_readonly, write_all
from cptc_harness.profile_runtime.broker_ipc import (
    PortcastBrokerFailure,
    DispatchNonce,
    PortcastBrokerClient,
    ReservationBinding,
)
from cptc_harness.profile_runtime.contracts import PORTCAST_FAILURE_STAGES
from testing.cptc11_lab.portcast_broker_worker import _receive_credentials


PROFILE_ID = "web.http_jellyfin_public_identity"
RUNTIME = "9bcaeaa02a0c9f52b1b32c4259a35043b9dd0caec55f6fec150ec6f5a722df16"
WORKER = "4" * 64
RAW = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
PRODUCTION_LEDGER_ROOT = Path(
    "/var/lib/cptc-harness/portcast-live-v1/runtime/v7/ledger/cptc11-dell-validation-portcast-v7"
)
HISTORICAL_LEDGER_ROOT = Path(
    "/var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation"
)


def release() -> VerifiedRelease:
    return VerifiedRelease(
        "portcast-live-v1",
        "3" * 64,
        {},
        {PROFILE_ID: WORKER},
        {PROFILE_ID: (WORKER,)},
    )


def ledger(tmp_path) -> Ledger:
    root = tmp_path / "ledger"
    root.mkdir()
    root.chmod(0o700)
    return Ledger(root, "engagement", "device", policy_revision="revision")


def binding(deadline_ns: int | None = None) -> ReservationBinding:
    return ReservationBinding(
        "engagement",
        "device",
        "action",
        "attempt",
        PROFILE_ID,
        RUNTIME,
        deadline_ns or time.monotonic_ns() + 10_000_000_000,
    )


def reserve(store: Ledger) -> int:
    now = time.monotonic_ns()
    deadline = now + 10_000_000_000
    store.reserve_attempt(
        "action",
        Bounds(
            timeout_s=10,
            request_limit=1,
            output_bytes=16384,
            process_limit=1,
            tcp_connects=1,
            protocol_requests=1,
            tx_bytes=256,
            rx_bytes=8192,
        ),
        "attempt",
        started_ns=now,
        deadline_ns=deadline,
        workspace_id="workspace",
        target_id="cptc11-prod-portcast",
        workflow_id="wave",
    )
    return deadline


def _send(channel: socket.socket, value: dict, descriptor: int | None = None) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ancillary = [] if descriptor is None else [
        (socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptor.to_bytes(4, os.sys.byteorder))
    ]
    channel.sendmsg([raw], ancillary)


def _sealed_secret(name: str, value: bytes) -> int:
    descriptor = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING)
    write_all(descriptor, value)
    os.lseek(descriptor, 0, os.SEEK_SET)
    seal_readonly(descriptor)
    return descriptor


def test_broker_accepts_only_two_named_sealed_service_credentials():
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    originals = (
        _sealed_secret("synthetic-dell-credential", b"dell-secret\n"),
        _sealed_secret("synthetic-kali-credential", b"kali-secret\n"),
    )
    received: tuple[int, int] = ()
    try:
        raw = json.dumps(
            {
                "method": "credentials",
                "names": ["cptc11-dell", "cptc11-kali"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        parent.sendmsg(
            [raw],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", originals))],
        )
        received = _receive_credentials(child)
        assert os.pread(received[0], 64, 0) == b"dell-secret\n"
        assert os.pread(received[1], 64, 0) == b"kali-secret\n"
    finally:
        for descriptor in received + originals:
            os.close(descriptor)
        parent.close()
        child.close()


def test_production_factory_matches_worker_ledger_and_nonroot_service_identity(
    tmp_path, monkeypatch
):
    import cptc_harness.profile_runtime.broker_ipc as ipc
    import testing.cptc11_lab.portcast_broker_worker as worker

    assert ipc._PRODUCTION_LEDGER_ROOT == worker._PRODUCTION_LEDGER_ROOT == PRODUCTION_LEDGER_ROOT
    store = ledger(tmp_path)
    credentials = (
        _sealed_secret("synthetic-service-dell", b"synthetic-dell"),
        _sealed_secret("synthetic-service-kali", b"synthetic-kali"),
    )
    service_uid = 61001
    service_gid = 61002
    monkeypatch.setattr(ipc, "_PRODUCTION_LEDGER_ROOT", store.root)
    monkeypatch.setattr(ipc.os, "geteuid", lambda: service_uid)
    monkeypatch.setattr(ipc.os, "getegid", lambda: service_gid)
    monkeypatch.setattr(ipc.os, "getgroups", lambda: [service_gid])
    client = None
    try:
        client = ipc._service_wire_broker_factory(
            store, release(), credential_fds=credentials
        )
        assert isinstance(client, PortcastBrokerClient)
        assert len(client._credential_fds) == 2
    finally:
        if client is not None:
            client.close()
        for descriptor in credentials:
            os.close(descriptor)


@pytest.mark.parametrize(
    ("uid", "gid", "groups"),
    ((0, 61002, [61002]), (61001, 0, [0]), (61001, 61002, [61002, 61003])),
)
def test_production_factory_rejects_wrong_service_identity(
    tmp_path, monkeypatch, uid, gid, groups
):
    import cptc_harness.profile_runtime.broker_ipc as ipc

    store = ledger(tmp_path)
    credentials = (
        _sealed_secret("synthetic-rejected-dell", b"synthetic-dell"),
        _sealed_secret("synthetic-rejected-kali", b"synthetic-kali"),
    )
    monkeypatch.setattr(ipc, "_PRODUCTION_LEDGER_ROOT", store.root)
    monkeypatch.setattr(ipc.os, "geteuid", lambda: uid)
    monkeypatch.setattr(ipc.os, "getegid", lambda: gid)
    monkeypatch.setattr(ipc.os, "getgroups", lambda: groups)
    try:
        with pytest.raises(PolicyError, match="canonical local service"):
            ipc._service_wire_broker_factory(
                store, release(), credential_fds=credentials
            )
    finally:
        for descriptor in credentials:
            os.close(descriptor)


def test_broker_rejects_unsealed_service_credentials():
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    originals = (
        memfd_create("synthetic-unsealed-dell", MFD_CLOEXEC | MFD_ALLOW_SEALING),
        memfd_create("synthetic-unsealed-kali", MFD_CLOEXEC | MFD_ALLOW_SEALING),
    )
    try:
        for descriptor in originals:
            write_all(descriptor, b"synthetic-secret")
            os.lseek(descriptor, 0, os.SEEK_SET)
        raw = json.dumps(
            {
                "method": "credentials",
                "names": ["cptc11-dell", "cptc11-kali"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        parent.sendmsg(
            [raw],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", originals))],
        )
        with pytest.raises(PolicyError, match="credentials differ"):
            _receive_credentials(child)
    finally:
        for descriptor in originals:
            os.close(descriptor)
        parent.close()
        child.close()


def test_production_broker_launch_has_fixed_argv_empty_environment_and_no_raw_secret(
    tmp_path, monkeypatch
):
    store = ledger(tmp_path)
    originals = (
        _sealed_secret("synthetic-launch-dell", b"launch-dell-secret"),
        _sealed_secret("synthetic-launch-kali", b"launch-kali-secret"),
    )
    captured = {}

    class Process:
        pid = 99999999

        def __init__(self, channel):
            self.channel = channel

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    def popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        captured["child"] = kwargs["stdin"].dup()
        captured["child"].send(canonical_json({
            "kind": "sandbox_ready",
            "cap_eff": "0000000000000000",
            "allowed_route": "100.85.84.30/32",
        }))
        return Process(captured["child"])

    monkeypatch.setattr(
        "cptc_harness.profile_runtime.broker_ipc.subprocess.Popen", popen
    )
    client = object.__new__(PortcastBrokerClient)
    client._initialize(
        store,
        replace(
            release(),
            release_root=Path("/app"),
            interpreter_path=Path(
                "/app/vendor/portcast-rootfs-runtime/bin/python3.14"
            ),
        ),
        credential_fds=originals,
    )
    try:
        client._start()
        assert captured["command"] == [
            "/app/deployment/portcast-bootstrap",
            "--broker-worker",
        ]
        assert captured["kwargs"]["env"] == {}
        assert captured["kwargs"]["close_fds"] is True
        assert captured["kwargs"]["stdout"] is not None
        assert captured["kwargs"]["stderr"] is not None
        launch_text = repr((captured["command"], captured["kwargs"]))
        assert "launch-dell-secret" not in launch_text
        assert "launch-kali-secret" not in launch_text
        launcher_source = Path("deployment/portcast-bootstrap.go").read_text()
        assert '"--unshare-user"' in launcher_source
        assert '"--unshare-pid"' in launcher_source
        assert '"--cap-drop", "ALL"' in launcher_source
        assert '"--share-net"' in launcher_source
        assert '"--ro-bind", anchorPath, anchorPath' in launcher_source
        assert '"--bind", ledger, ledger' in launcher_source
    finally:
        if client._channel is not None:
            client._channel.close()
            client._channel = None
        if "child" in captured:
            captured["child"].close()
        client._process = None
        for descriptor in originals:
            os.close(descriptor)


def test_production_broker_and_worker_reject_historical_ledger_root(tmp_path, monkeypatch):
    import cptc_harness.profile_runtime.broker_ipc as ipc
    import testing.cptc11_lab.portcast_broker_worker as worker

    old_store = ledger(tmp_path)
    credentials = (
        _sealed_secret("synthetic-old-dell", b"synthetic-dell"),
        _sealed_secret("synthetic-old-kali", b"synthetic-kali"),
    )
    monkeypatch.setattr(ipc, "_PRODUCTION_LEDGER_ROOT", PRODUCTION_LEDGER_ROOT)
    monkeypatch.setattr(worker, "_PRODUCTION_LEDGER_ROOT", PRODUCTION_LEDGER_ROOT)
    try:
        with pytest.raises(PolicyError, match="Ledger root differs"):
            ipc._service_wire_broker_factory(
                old_store, release(), credential_fds=credentials
            )
        assert str(PRODUCTION_LEDGER_ROOT) in Path(
            "testing/cptc11_lab/portcast_broker_worker.py"
        ).read_text()
        assert str(HISTORICAL_LEDGER_ROOT) not in Path(
            "testing/cptc11_lab/portcast_broker_worker.py"
        ).read_text()
    finally:
        for descriptor in credentials:
            os.close(descriptor)


def test_unexpected_sandbox_attestation_descriptor_is_closed(tmp_path, monkeypatch):
    store = ledger(tmp_path)
    client = object.__new__(PortcastBrokerClient)
    client._initialize(store, release())
    descriptor = memfd_create(
        "synthetic-attestation-descriptor", MFD_CLOEXEC | MFD_ALLOW_SEALING
    )

    class Process:
        pid = 99999998

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(
        "cptc_harness.profile_runtime.broker_ipc.subprocess.Popen",
        lambda *_args, **_kwargs: Process(),
    )
    monkeypatch.setattr(
        "cptc_harness.profile_runtime.broker_ipc.os.killpg",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        client,
        "_receive",
        lambda: (
            {
                "kind": "sandbox_ready",
                "cap_eff": "0000000000000000",
                "allowed_route": "100.85.84.30/32",
            },
            (descriptor,),
        ),
    )

    with pytest.raises(PolicyError, match="could not start"):
        client._start()
    with pytest.raises(OSError):
        os.fstat(descriptor)
    assert client._channel is None
    assert client._process is None


def _server(channel: socket.socket, executions: list[int], *, crash=False) -> None:
    raw = channel.recv(65536)
    if not raw:
        return
    request = json.loads(raw)
    assert request["method"] == "bind"
    _send(
        channel,
        {
            "kind": "nonce",
            "value": base64.b64encode(b"n" * 32).decode(),
            "expires_ns": time.monotonic_ns() + 5_000_000_000,
        },
    )
    raw = channel.recv(65536)
    if not raw:
        return
    request = json.loads(raw)
    assert request["method"] == "execute"
    executions.append(1)
    if crash:
        channel.close()
        return
    _send(
        channel,
        {
            "kind": "event",
            "event_id": "connect-000000",
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "protocol_requests": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
            "first_byte_at": None,
        },
    )
    assert json.loads(channel.recv(65536)) == {
        "event_id": "connect-000000",
        "method": "ack",
    }
    descriptor = memfd_create("synthetic-portcast", MFD_CLOEXEC | MFD_ALLOW_SEALING)
    try:
        write_all(descriptor, RAW)
        os.lseek(descriptor, 0, os.SEEK_SET)
        seal_readonly(descriptor)
        _send(
            channel,
            {
                "kind": "result",
                "outcome": "complete",
                "limitation": None,
                "first_byte_at": "2026-09-09T15:00:00.000001Z",
                "evidence_bytes": len(RAW),
                "evidence_sha256": hashlib.sha256(RAW).hexdigest(),
                "counters": {
                    "tcp_connects": 1,
                    "udp_datagrams": 0,
                    "tls_handshakes": 0,
                    "protocol_requests": 1,
                    "tx_bytes": 1,
                    "rx_bytes": len(RAW),
                    "capture_bytes": len(RAW),
                },
            },
            descriptor,
        )
    finally:
        os.close(descriptor)


def _failure_server(channel: socket.socket, stage: object, *, outcome="uncertain") -> None:
    assert json.loads(channel.recv(65536))["method"] == "bind"
    _send(
        channel,
        {
            "kind": "nonce",
            "value": base64.b64encode(b"n" * 32).decode(),
            "expires_ns": time.monotonic_ns() + 5_000_000_000,
        },
    )
    assert json.loads(channel.recv(65536))["method"] == "execute"
    descriptor = memfd_create(
        "synthetic-portcast-failure", MFD_CLOEXEC | MFD_ALLOW_SEALING
    )
    try:
        seal_readonly(descriptor)
        _send(
            channel,
            {
                "kind": "result",
                "outcome": outcome,
                "limitation": None if outcome == "complete" else "transport_interrupted",
                "failure_stage": stage,
                "first_byte_at": None,
                "evidence_bytes": 0,
                "evidence_sha256": hashlib.sha256(b"").hexdigest(),
                "counters": {
                    "tcp_connects": 0,
                    "udp_datagrams": 0,
                    "tls_handshakes": 0,
                    "protocol_requests": 0,
                    "tx_bytes": 0,
                    "rx_bytes": 0,
                    "capture_bytes": 0,
                },
            },
            descriptor,
        )
    finally:
        os.close(descriptor)
        channel.close()


def test_bind_before_reservation_sends_no_worker_message(tmp_path):
    store = ledger(tmp_path)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    child.settimeout(0.05)
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    with pytest.raises(PolicyError, match="reservation"):
        client.bind_reserved_attempt(binding())
    with pytest.raises(TimeoutError):
        child.recv(1)
    client.close()
    child.close()


def test_unexpected_bind_descriptor_is_closed_before_cleanup(tmp_path):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    def server():
        assert json.loads(child.recv(65536))["method"] == "bind"
        descriptor = memfd_create(
            "synthetic-bind-descriptor", MFD_CLOEXEC | MFD_ALLOW_SEALING
        )
        try:
            _send(
                child,
                {
                    "kind": "nonce",
                    "value": base64.b64encode(b"n" * 32).decode(),
                    "expires_ns": time.monotonic_ns() + 5_000_000_000,
                },
                descriptor,
            )
        finally:
            os.close(descriptor)
            child.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    with pytest.raises(PolicyError, match="binding failed"):
        client.bind_reserved_attempt(binding(deadline))
    thread.join(timeout=1)

    links = []
    for path in Path("/proc/self/fd").iterdir():
        try:
            links.append(path.readlink().as_posix())
        except FileNotFoundError:
            pass
    assert not any("synthetic-bind-descriptor" in value for value in links)


def test_valid_nonce_executes_once_and_returns_only_sealed_evidence_fd(tmp_path):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    executions: list[int] = []
    thread = threading.Thread(target=_server, args=(child, executions), daemon=True)
    thread.start()
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    nonce = client.bind_reserved_attempt(binding(deadline))
    events = []
    result = client.execute_once(
        nonce,
        lambda event: events.append(event),
        lambda: False,
    )
    try:
        assert os.read(result.evidence_fd, len(RAW) + 1) == RAW
    finally:
        os.close(result.evidence_fd)
    with pytest.raises(PolicyError, match="nonce"):
        client.execute_once(nonce, lambda _event: None, lambda: False)
    thread.join(timeout=1)
    assert executions == [1]
    assert events[0].event_id == "connect-000000"
    client.close()


@pytest.mark.parametrize("stage", sorted(PORTCAST_FAILURE_STAGES))
def test_broker_accepts_only_fixed_failure_stages(tmp_path, stage):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    thread = threading.Thread(target=_failure_server, args=(child, stage), daemon=True)
    thread.start()
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    nonce = client.bind_reserved_attempt(binding(deadline))
    result = client.execute_once(nonce, lambda _event: None, lambda: False)
    try:
        assert result.failure_stage == stage
        assert result.counters.tcp_connects == 0
        assert os.read(result.evidence_fd, 1) == b""
    finally:
        os.close(result.evidence_fd)
        client.close()
    thread.join(timeout=1)


@pytest.mark.parametrize(
    ("stage", "outcome"),
    (("attacker supplied secret text", "uncertain"), (7, "uncertain"), ("target_open", "complete")),
)
def test_broker_rejects_unknown_or_complete_failure_stage(tmp_path, stage, outcome):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    thread = threading.Thread(
        target=_failure_server, args=(child, stage), kwargs={"outcome": outcome}, daemon=True
    )
    thread.start()
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    nonce = client.bind_reserved_attempt(binding(deadline))
    with pytest.raises(PortcastBrokerFailure, match="uncertain") as raised:
        client.execute_once(nonce, lambda _event: None, lambda: False)
    assert raised.value.failure_stage == "ipc"
    assert "attacker" not in str(raised.value)
    assert store.attempt_receipt("action")["attempts"][0]["state"] == "uncertain"
    client.close()
    thread.join(timeout=1)


def test_expired_or_changed_nonce_opens_no_worker_execution(tmp_path):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    executions: list[int] = []
    thread = threading.Thread(target=_server, args=(child, executions), daemon=True)
    thread.start()
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    nonce = client.bind_reserved_attempt(binding(deadline))
    expired = replace(nonce, expires_ns=time.monotonic_ns() - 1)
    with pytest.raises(PolicyError, match="nonce"):
        client.execute_once(expired, lambda _event: None, lambda: False)
    assert executions == []
    client.close()
    child.close()


def test_worker_crash_after_nonce_consumption_marks_attempt_uncertain(tmp_path):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    executions: list[int] = []
    thread = threading.Thread(
        target=_server, args=(child, executions), kwargs={"crash": True}, daemon=True
    )
    thread.start()
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    nonce = client.bind_reserved_attempt(binding(deadline))
    with pytest.raises(PolicyError, match="uncertain"):
        client.execute_once(nonce, lambda _event: None, lambda: False)
    assert store.stopped() is True
    assert store.attempt_receipt("action")["attempts"][0]["state"] == "uncertain"
    client.close()


def test_all_ledger_terminal_writes_fall_back_to_durable_stop_intent(
    tmp_path, monkeypatch
):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    client._binding = binding(deadline)

    def unavailable(*_args, **_kwargs):
        raise OSError("synthetic ledger unavailable")

    for name in ("finish_attempt", "attempt_receipt", "finish", "stop"):
        monkeypatch.setattr(store, name, unavailable)

    assert client._mark_uncertain() is False
    sentinel = store.root / "operator-stop.json"
    receipt = json.loads(sentinel.read_text())
    assert receipt["source"] == "system"
    assert receipt["interface"] == "internal"
    assert receipt["reason"] == "transport_uncertainty"
    assert client.uncertainty_reconciliation_required is True
    assert store.stopped() is True
    store._db.close()
    reopened = Ledger(
        store.root, "engagement", "device", policy_revision="revision"
    )
    recovered = reopened.recover_attempts()
    assert recovered == (
        {"request_id": "action", "attempt_id": "attempt", "state": "uncertain"},
    )
    assert reopened.reservation_state("action") == "uncertain"
    parent.close()
    child.close()


def test_total_uncertainty_persistence_failure_is_explicit(tmp_path, monkeypatch):
    import cptc_harness.profile_runtime.broker_ipc as ipc

    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    client._binding = binding(deadline)

    def unavailable(*_args, **_kwargs):
        raise OSError("synthetic persistence unavailable")

    for name in ("finish_attempt", "attempt_receipt", "finish", "stop"):
        monkeypatch.setattr(store, name, unavailable)
    monkeypatch.setattr(ipc, "_request_stop", unavailable)

    with pytest.raises(PolicyError, match="durable uncertainty state is unavailable"):
        client._mark_uncertain()
    assert client.uncertainty_reconciliation_required is True
    parent.close()
    child.close()


def test_close_reaps_resources_when_uncertainty_persistence_fails(
    tmp_path, monkeypatch
):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    client._binding = binding(deadline)
    client._inflight = True
    credentials = (
        _sealed_secret("synthetic-close-dell", b"synthetic-dell"),
        _sealed_secret("synthetic-close-kali", b"synthetic-kali"),
    )
    client._credential_fds = credentials
    calls: list[str] = []

    class Process:
        pid = 99999997

        def poll(self):
            return None

        def kill(self):
            calls.append("kill")

        def wait(self, timeout=None):
            calls.append("wait")
            return -9

    client._process = Process()
    monkeypatch.setattr(
        client,
        "_mark_uncertain",
        lambda: (_ for _ in ()).throw(OSError("synthetic persistence failure")),
    )
    monkeypatch.setattr(
        "cptc_harness.profile_runtime.broker_ipc.os.killpg",
        lambda *_args: calls.append("killpg"),
    )

    with pytest.raises(PolicyError, match="cleanup failed"):
        client.close()

    assert client._closed is True
    assert client._channel is None
    assert client._process is None
    assert client._credential_fds == ()
    assert calls == ["killpg", "wait"]
    assert child.recv(1) == b""
    for descriptor in credentials:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    child.close()


def test_close_reports_reconciliation_when_uncertainty_persistence_is_incomplete(
    tmp_path, monkeypatch
):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    client._binding = binding(deadline)
    client._inflight = True
    monkeypatch.setattr(client, "_mark_uncertain", lambda: False)

    with pytest.raises(PolicyError, match="reconciliation required"):
        client.close()

    assert client._closed is True
    assert client._inflight is False
    assert client._channel is None
    assert client.uncertainty_reconciliation_required is True
    assert child.recv(1) == b""
    child.close()


def test_changed_canonical_deadline_is_rejected_before_worker_message(tmp_path):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    child.settimeout(0.05)
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    with pytest.raises(PolicyError, match="reservation"):
        client.bind_reserved_attempt(binding(deadline - 1))
    with pytest.raises(TimeoutError):
        child.recv(1)
    client.close()
    child.close()


def test_request_cannot_start_at_canonical_deadline(tmp_path, monkeypatch):
    import cptc_harness.profile_runtime.broker_ipc as ipc

    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    executions = []
    thread = threading.Thread(target=_server, args=(child, executions), daemon=True)
    thread.start()
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    nonce = client.bind_reserved_attempt(binding(deadline))
    monkeypatch.setattr(ipc.time, "monotonic_ns", lambda: deadline)
    with pytest.raises(PolicyError, match="nonce"):
        client.execute_once(nonce, lambda _event: None, lambda: False)
    assert executions == []
    client.close()


def test_deadline_after_result_receive_closes_passed_descriptor(tmp_path, monkeypatch):
    import cptc_harness.profile_runtime.broker_ipc as ipc

    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    def server():
        assert json.loads(child.recv(65536))["method"] == "bind"
        _send(
            child,
            {
                "kind": "nonce",
                "value": base64.b64encode(b"n" * 32).decode(),
                "expires_ns": deadline - 1,
            },
        )
        assert json.loads(child.recv(65536))["method"] == "execute"
        descriptor = memfd_create(
            "synthetic-deadline-descriptor", MFD_CLOEXEC | MFD_ALLOW_SEALING
        )
        try:
            seal_readonly(descriptor)
            _send(
                child,
                {
                    "kind": "result",
                    "outcome": "complete",
                    "limitation": None,
                    "first_byte_at": "2026-09-09T15:00:00.000001Z",
                    "evidence_bytes": 0,
                    "evidence_sha256": hashlib.sha256(b"").hexdigest(),
                    "counters": {
                        "tcp_connects": 0,
                        "udp_datagrams": 0,
                        "tls_handshakes": 0,
                        "protocol_requests": 0,
                        "tx_bytes": 0,
                        "rx_bytes": 0,
                        "capture_bytes": 0,
                    },
                },
                descriptor,
            )
        finally:
            os.close(descriptor)
            child.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    nonce = client.bind_reserved_attempt(binding(deadline))
    readings = iter((deadline - 4, deadline - 3, deadline - 2, deadline))
    monkeypatch.setattr(
        ipc.time,
        "monotonic_ns",
        lambda: next(readings, deadline),
    )
    with pytest.raises(PolicyError, match="uncertain"):
        client.execute_once(nonce, lambda _event: None, lambda: False)
    thread.join(timeout=1)
    client.close()

    links = []
    for path in Path("/proc/self/fd").iterdir():
        try:
            links.append(path.readlink().as_posix())
        except FileNotFoundError:
            pass
    assert not any("synthetic-deadline-descriptor" in value for value in links)


@pytest.mark.parametrize("failure", ("close", "kill", "wait"))
def test_cleanup_failure_is_reported_and_marks_canonical_attempt_uncertain(
    tmp_path, monkeypatch, failure
):
    store = ledger(tmp_path)
    deadline = reserve(store)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = PortcastBrokerClient._from_connected_socket(store, release(), parent)
    client._binding = binding(deadline)

    if failure == "close":
        class BrokenChannel:
            def close(self):
                raise OSError("synthetic close failure")

        client._channel = BrokenChannel()
        child.close()
    else:
        child.close()

        class Process:
            pid = 424242

            def poll(self):
                return None if failure == "kill" else 0

            def kill(self):
                return None

            def wait(self, timeout):
                if failure == "wait":
                    raise OSError("synthetic wait failure")
                return -9

        client._process = Process()
        if failure == "kill":
            monkeypatch.setattr(
                "cptc_harness.profile_runtime.broker_ipc.os.killpg",
                lambda *_args: (_ for _ in ()).throw(OSError("synthetic kill failure")),
            )

    with pytest.raises(PolicyError, match="cleanup failed"):
        client.close()

    assert store.stopped() is True
    assert store.reservation_state("action") == "uncertain"
