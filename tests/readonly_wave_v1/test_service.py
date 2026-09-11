import json

import pytest

from cptc11_readonly_wave_v1.service import PeerIdentity, ServiceConfig, ServiceError, ReadonlyWaveService, _decode_request


def test_decode_execute_allows_identifiers_only():
    assert _decode_request('{"method":"execute","wave_id":"w","plan_id":"p","action_id":"a","profile_id":"x"}') == {
        "method": "execute", "wave_id":"w", "plan_id":"p", "action_id":"a", "profile_id":"x"
    }


def test_peer_validation_and_durable_stop(tmp_path):
    config = ServiceConfig(socket_path=tmp_path / "service.sock", stop_path=tmp_path / "stop", peer_uids=frozenset({1000}))
    service = ReadonlyWaveService(config, broker=None)
    with pytest.raises(ServiceError):
        service.handle_packet(b'{"method":"info"}', PeerIdentity(1001, 1000, 1))
    response = service.handle_packet(b'{"method":"stop"}', PeerIdentity(1000, 1000, 1))
    assert response["status"] == "stopped"
    assert config.stop_path.is_file()


def test_unknown_request_fields_are_rejected():
    with pytest.raises(ServiceError):
        _decode_request('{"method":"execute","plan_id":"p","action_id":"a","profile_id":"x","command":"id"}')
