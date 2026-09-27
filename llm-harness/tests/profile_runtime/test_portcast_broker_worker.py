from __future__ import annotations

import hashlib
import os

import pytest

from cptc_harness.memfd import F_GET_SEALS, READONLY_SEALS
from cptc_harness.profile_runtime.catalog import load_profile, require_live_admission

import testing.cptc11_lab.portcast_broker_worker as worker


class _SyntheticServiceSession:
    def __init__(self, *, target_error: BaseException | None = None) -> None:
        self.target_error = target_error
        self.closed = False
        self.inventory_calls = 0
        self.alternate_calls = 0
        self.target_calls = 0

    def open(self) -> None:
        return None

    def preflight_portcast_inventory(self) -> None:
        self.inventory_calls += 1

    def verify_portcast_alternate_destination_denied(self) -> bool:
        self.alternate_calls += 1
        return True

    def _open_portcast_channel(self):
        self.target_calls += 1
        if self.target_error is not None:
            raise self.target_error
        raise AssertionError("synthetic worker must not reach a live channel")

    def close(self) -> None:
        self.closed = True


def _profile():
    return require_live_admission(load_profile("web.http_jellyfin_public_identity"))


def test_target_open_oserror_is_uncertain_sealed_and_redacts_exception_text(monkeypatch):
    marker = "synthetic-secret-must-not-escape"
    session = _SyntheticServiceSession(target_error=OSError(marker))
    monkeypatch.setattr(
        "testing.cptc11_lab.transport.LabSession._for_portcast_service",
        lambda _fds: session,
    )

    result, descriptor = worker._execute(
        object(), _profile(), 2**63 - 1, (101, 102)
    )
    try:
        assert result["outcome"] == "uncertain"
        assert result["failure_stage"] == "target_open"
        assert result["evidence_bytes"] == 0
        assert result["evidence_sha256"] == hashlib.sha256(b"").hexdigest()
        assert result["counters"] == {
            "tcp_connects": 0,
            "udp_datagrams": 0,
            "tls_handshakes": 0,
            "protocol_requests": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
            "capture_bytes": 0,
        }
        assert marker not in repr(result)
        assert os.pread(descriptor, 1, 0) == b""
        assert os.pread(descriptor, 1, 0) == b""
        assert worker.fcntl.fcntl(descriptor, F_GET_SEALS) & READONLY_SEALS == READONLY_SEALS
    finally:
        os.close(descriptor)

    assert session.closed is True
    assert session.inventory_calls == 1
    assert session.alternate_calls == 1
    assert session.target_calls == 1


def test_open_channel_with_unacknowledged_connect_is_uncertain_and_sends_no_request(
    monkeypatch,
):
    class Channel:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class Session(_SyntheticServiceSession):
        def __init__(self, channel: Channel) -> None:
            super().__init__()
            self.channel = channel

        def _open_portcast_channel(self):
            self.target_calls += 1
            return self.channel

    class UnavailableAccountingChannel:
        def sendmsg(self, *_args, **_kwargs):
            raise OSError("synthetic accounting channel unavailable")

    channel = Channel()
    session = Session(channel)
    monkeypatch.setattr(
        "testing.cptc11_lab.transport.LabSession._for_portcast_service",
        lambda _fds: session,
    )

    result, descriptor = worker._execute(
        UnavailableAccountingChannel(), _profile(), 2**63 - 1, (101, 102)
    )
    try:
        assert result["outcome"] == "uncertain"
        assert result["failure_stage"] == "connected_ack"
        assert result["evidence_bytes"] == 0
        assert result["counters"] == {
            "tcp_connects": 0,
            "udp_datagrams": 0,
            "tls_handshakes": 0,
            "protocol_requests": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
            "capture_bytes": 0,
        }
    finally:
        os.close(descriptor)

    assert session.target_calls == 1
    assert channel.closed is True
    assert session.closed is True


def test_broker_worker_never_reaches_nested_transport_or_open_channel_source():
    source = worker.Path(worker.__file__).read_text()

    assert "._transport" not in source
    assert ".open_channel(" not in source
