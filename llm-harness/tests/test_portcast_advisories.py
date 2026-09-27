import hashlib
import json
from pathlib import Path

import pytest

from cptc_harness.advisories import (
    JELLYFIN_CVE_IDS,
    JELLYFIN_MANUAL_PREREQUISITES,
    load_catalog,
    match_components,
)
from cptc_harness.portcast_identity import validate_portcast_identity_response
from cptc_harness.portcast_identity import portcast_http_request_bytes


FIXTURES = Path(__file__).parent / "fixtures" / "portcast"


def receipt():
    body = (FIXTURES / "jellyfin-10.10.7.json").read_bytes()
    return {
        "status": "complete", "target_ipv4": "10.0.1.30", "target_port": 8096,
        "method": "GET", "path": "/System/Info/Public", "status_code": 200,
        "content_type": "application/json; charset=utf-8", "content_encoding": "identity",
        "truncated": False, "tcp_connects": 1, "protocol_requests": 1,
        "tx_bytes": len(portcast_http_request_bytes()), "rx_bytes": len(body),
        "redirects": 0, "retries": 0, "proxy_used": False,
        "authenticated": False, "request_body_bytes": 0,
    }


def test_exact_jellyfin_10107_identity_matches_seven_candidates_with_manual_limits():
    raw = (FIXTURES / "jellyfin-advisories.json").read_bytes()
    catalog = load_catalog(raw, expected_sha256=hashlib.sha256(raw).hexdigest(), release_sha256="b" * 64)
    identity = validate_portcast_identity_response(
        (FIXTURES / "jellyfin-10.10.7.json").read_bytes(), receipt=receipt()
    )
    matches = match_components([identity], catalog)
    assert tuple(item.advisory_id for item in matches) == JELLYFIN_CVE_IDS
    assert all(item.state == "affected_candidate" for item in matches)
    assert all(item.limitations == (
        "backport_unverified", "configuration_unverified",
        "manual_prerequisite_review_required", "version_only",
    ) for item in matches)
    assert set(JELLYFIN_MANUAL_PREREQUISITES) == set(JELLYFIN_CVE_IDS)
    assert all(JELLYFIN_MANUAL_PREREQUISITES[cve] for cve in JELLYFIN_CVE_IDS)


def test_other_product_cannot_match_jellyfin_advisories():
    from dataclasses import replace
    raw = (FIXTURES / "jellyfin-advisories.json").read_bytes()
    catalog = load_catalog(raw, expected_sha256=hashlib.sha256(raw).hexdigest(), release_sha256="b" * 64)
    identity = validate_portcast_identity_response(
        (FIXTURES / "jellyfin-10.10.7.json").read_bytes(), receipt=receipt()
    )
    matches = match_components([replace(identity, product="Apache HTTP Server")], catalog)
    assert all(item.state == "unsupported" for item in matches)


def test_jellyfin_records_require_the_exact_official_advisory_identity():
    original = json.loads((FIXTURES / "jellyfin-advisories.json").read_text())
    for change in (
        {"source_url": "https://example.test/CVE-2026-35031"},
        {"source_url": "https://github.com/jellyfin/jellyfin/security/advisories/GHSA-wrong-id"},
        {"publisher": "synthetic-publisher"},
        {"advisory_id": "CVE-2026-99999", "cve_ids": ["CVE-2026-99999"]},
    ):
        payload = json.loads(json.dumps(original))
        payload["records"][0].update(change)
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        with pytest.raises(ValueError, match="Jellyfin"):
            load_catalog(raw, expected_sha256=hashlib.sha256(raw).hexdigest(), release_sha256="b" * 64)
