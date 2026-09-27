import json

import pytest

from cptc11_readonly_wave_v1.parsers import ParserError
from cptc11_readonly_wave_v1.parsers.keycloak import parse_keycloak


def test_keycloak_emits_only_path_scheme_known_order_and_unknown_flags():
    body = json.dumps({
        "issuer": "http://10.0.1.13:8180/realms/gps",
        "grant_types_supported": ["password", "authorization_code", "future"],
        "id_token_signing_alg_values_supported": ["EdDSA", "RS256", "future"],
        "ignored": "secret diagnostic",
    }).encode()
    facts = parse_keycloak(200, body)
    assert facts.status_code == 200
    assert facts.realm_path_match is True
    assert facts.issuer_scheme == "http"
    assert facts.grant_types_present is True
    assert facts.grant_types == ("authorization_code", "password")
    assert facts.unknown_grant_type is True
    assert facts.signing_algorithms_present is True
    assert facts.signing_algorithms == ("RS256", "EdDSA")
    assert facts.unknown_signing_algorithm is True
    assert "10.0.1.13" not in repr(facts) and "secret diagnostic" not in repr(facts)


def test_keycloak_missing_arrays_are_distinct_from_empty_present_arrays():
    missing = parse_keycloak(200, b'{"issuer":"https://example.invalid/realms/gps"}')
    empty = parse_keycloak(200, b'{"issuer":"https://example.invalid/realms/gps","grant_types_supported":[],"id_token_signing_alg_values_supported":[]}')
    assert missing.grant_types_present is False
    assert missing.signing_algorithms_present is False
    assert missing.grant_types == missing.signing_algorithms == ()
    assert empty.grant_types_present is empty.signing_algorithms_present is True


@pytest.mark.parametrize(
    "body",
    (b'{"issuer":1}', b'{"grant_types_supported":"password"}', b'{"id_token_signing_alg_values_supported":[1]}'),
)
def test_keycloak_rejects_malformed_field_types(body):
    with pytest.raises(ParserError):
        parse_keycloak(200, body)
