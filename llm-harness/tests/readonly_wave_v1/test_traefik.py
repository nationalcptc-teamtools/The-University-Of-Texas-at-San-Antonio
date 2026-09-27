import pytest

from cptc11_readonly_wave_v1.parsers import ParserError
from cptc11_readonly_wave_v1.parsers.traefik import parse_traefik


@pytest.mark.parametrize(
    ("value", "normalized"),
    (("v3.1.2", "3.1.2"), ("3.0.0-rc.1+build.5", "3.0.0-rc.1+build.5")),
)
def test_traefik_exact_version_marker_and_semver_normalization(value, normalized):
    facts = parse_traefik(200, ('{"Version":"' + value + '","ignored":"x"}').encode())
    assert (facts.status_code, facts.product_marker, facts.version) == (200, True, normalized)


@pytest.mark.parametrize("body", (b'{"version":"3.1.2"}', b'{"Version":"03.1.2"}', b'{"Version":3}'))
def test_traefik_wrong_marker_or_version_is_not_identified(body):
    facts = parse_traefik(200, body)
    assert facts.product_marker is False and facts.version is None


@pytest.mark.parametrize(
    "body",
    (b"\xef\xbb\xbf{}", b'{"Version":"3.0.0","Version":"3.0.1"}', b'{"x":NaN}', b"\xff"),
)
def test_traefik_rejects_noncanonical_json(body):
    with pytest.raises(ParserError):
        parse_traefik(200, body)


@pytest.mark.parametrize(
    "body",
    (b'{"x":1e999}', b'{"x":' + b"9" * 200 + b"}", b'{"x":' + b"9" * 5000 + b"}"),
    ids=("exponent-overflow", "200-digit-integer", "5000-digit-integer"),
)
def test_strict_json_rejects_overflow_and_huge_numbers_as_parser_errors(body):
    with pytest.raises(ParserError):
        parse_traefik(200, body)


def test_traefik_version_length_is_bounded_before_semver_matching():
    body = ('{"Version":"3.1.2-' + ('x' * 123) + '"}').encode()
    facts = parse_traefik(200, body)
    assert facts.product_marker is False and facts.version is None
