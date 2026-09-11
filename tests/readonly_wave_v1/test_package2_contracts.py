import json

import pytest

from cptc11_readonly_wave_v1 import catalog


def test_action_request_identity_is_deterministic_and_closed():
    from cptc11_readonly_wave_v1.ledger import action_request_id

    value = action_request_id("plan", "action", "profile")
    assert value == action_request_id("plan", "action", "profile")
    with pytest.raises((ValueError, TypeError)):
        action_request_id("plan", "action", "profile", "extra")


def test_service_requests_reject_extra_fields_and_nonfinite_values():
    from cptc11_readonly_wave_v1.service import ServiceError, _decode_request

    with pytest.raises(ServiceError):
        _decode_request('{"method":"info","extra":1}')
    with pytest.raises(ServiceError):
        _decode_request('{"method":"info","x":NaN}')
    with pytest.raises(ServiceError):
        _decode_request('{"method":"execute","plan_id":"p","action_id":"a","profile_id":"x","host":"10.0.0.1"}')


def test_integrity_manifest_does_not_accept_benchmark_or_runtime_fields():
    from cptc11_readonly_wave_v1.integrity import IntegrityError, verify_manifest

    with pytest.raises(IntegrityError):
        verify_manifest({}, {"release_id": "x", "benchmark": "secret"})


def test_only_four_catalog_actions_are_admitted():
    assert len(catalog.plan_actions(catalog.PLAN_ID)) == 4
