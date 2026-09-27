import pytest

from cptc11_readonly_wave_v1.parsers.meilisearch import parse_meilisearch


@pytest.mark.parametrize(
    ("body", "state"),
    ((b'{"status":"available"}', "available"), (b'{"status":"unavailable"}', "unavailable"), (b'{"status":"degraded"}', "other"), (b'{"status":""}', "other"), (b"{}", "malformed"), (b'{"status":1}', "malformed"), (b"not-json", "malformed")),
)
def test_meilisearch_retains_only_closed_health_state(body, state):
    facts = parse_meilisearch(200, body)
    assert (facts.status_code, facts.state) == (200, state)
