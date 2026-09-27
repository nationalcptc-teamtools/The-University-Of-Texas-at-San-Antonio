import hashlib
import json
from pathlib import Path

import pytest

from cptc11_readonly_wave_v1 import catalog
from cptc11_readonly_wave_v1.contracts import ReadOnlyAction


PLAN = "cptc11-readonly-wave-v1"


def test_catalog_resolves_exact_frozen_order_targets_budgets_and_requests():
    actions = catalog.plan_actions(PLAN)
    assert [(action.action_id, action.profile_id, action.target_id) for action in actions] == [
        ("shorepass-traefik-version", "shorepass.traefik_public_version.v1", "cptc11-prod-shorepass"),
        ("crewcomms-redis-ping", "crewcomms.redis_ping.v1", "cptc11-prod-crewcomms"),
        ("gps-keycloak-oidc-metadata", "gps.keycloak_oidc_metadata.v1", "cptc11-prod-gps"),
        ("penny-meilisearch-health", "penny.meilisearch_health.v1", "cptc11-prod-penny"),
    ]
    assert [(action.host, action.port) for action in actions] == [
        ("10.0.1.99", 8080),
        ("10.0.1.14", 6379),
        ("10.0.1.13", 8180),
        ("10.0.1.11", 7700),
    ]
    assert [action.budget.max_rx_bytes for action in actions] == [4096, 128, 16384, 2048]
    assert [action.operation.request for action in actions] == [
        b"GET /api/version HTTP/1.1\r\nHost: 10.0.1.99:8080\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        b"*1\r\n$4\r\nPING\r\n",
        b"GET /realms/gps/.well-known/openid-configuration HTTP/1.1\r\nHost: 10.0.1.13:8180\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        b"GET /health HTTP/1.1\r\nHost: 10.0.1.11:7700\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
    ]
    assert [
        (
            action.budget.max_connects,
            action.budget.max_requests,
            action.budget.max_tx_bytes,
            action.budget.max_rx_bytes,
            action.budget.max_capture_bytes,
            action.budget.timeout_ms,
        )
        for action in actions
    ] == [
        (1, 1, 512, 4096, 4096, 8000),
        (1, 1, 14, 128, 128, 5000),
        (1, 1, 512, 16384, 16384, 8000),
        (1, 1, 384, 2048, 2048, 8000),
    ]
    expected = (
        (123, "3f55e7ee7ebb6fe0b6f8123468c89abc1a8e93c924456e2bd0a354a301b64e2f"),
        (14, "a43cb6a3b9d261112714d00e36b33106d1479eb1b3d8131a07684d4d477c5989"),
        (155, "73d878866168bca13988d737cf0eef2b65806ec3d8be44a6b45c2fb17d4ddce5"),
        (118, "fa8c6e1974fc90afc4110f570ba2e90b8e81b417b9ecbb389d3b905a8f79391e"),
    )
    assert [
        (len(action.operation.request), hashlib.sha256(action.operation.request).hexdigest())
        for action in actions
    ] == list(expected)
    for action in actions:
        assert catalog.resolve_action(PLAN, action.action_id, action.profile_id) is action


def test_catalog_rejects_wrong_mapping_and_direct_action_forgery():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve_action(PLAN, "shorepass-traefik-version", "crewcomms.redis_ping.v1")
    with pytest.raises((TypeError, ValueError)):
        ReadOnlyAction(
            PLAN, "forged", "forged", "forged", 1, "127.0.0.1", 1,
            catalog.plan_actions(PLAN)[0].operation,
            catalog.plan_actions(PLAN)[0].budget,
            "traefik", "a" * 64, "b" * 64,
        )


@pytest.mark.parametrize("mutation", ("duplicate", "extra", "reorder", "digest"))
def test_catalog_resource_fails_closed_on_schema_order_or_digest_drift(
    tmp_path, monkeypatch, mutation
):
    source = Path(catalog.__file__).parent / "resources/catalog-v1.json"
    raw = source.read_text()
    if mutation == "duplicate":
        raw = raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1)
    else:
        value = json.loads(raw)
        if mutation == "extra":
            value["unexpected"] = False
        elif mutation == "reorder":
            value["actions"][0], value["actions"][1] = value["actions"][1], value["actions"][0]
        else:
            value["catalog_sha256"] = "0" * 64
        raw = json.dumps(value)
    changed = tmp_path / "catalog.json"
    changed.write_text(raw)
    monkeypatch.setattr(catalog, "_CATALOG_RESOURCE", changed)
    catalog._clear_cache_for_tests()
    with pytest.raises(catalog.CatalogError):
        catalog.plan_actions(PLAN)


def test_catalog_rejects_symlink_resource(tmp_path, monkeypatch):
    real = tmp_path / "catalog.json"
    real.write_text("{}", encoding="utf-8")
    link = tmp_path / "catalog-link.json"
    link.symlink_to(real)
    monkeypatch.setattr(catalog, "_CATALOG_RESOURCE", link)
    catalog._clear_cache_for_tests()

    with pytest.raises(catalog.CatalogError, match="metadata"):
        catalog.plan_actions(PLAN)


def test_catalog_rejects_self_consistent_parser_rule_reordering(monkeypatch):
    resource_root = Path(catalog.__file__).parent / "resources"
    rules = json.loads((resource_root / "parser-rules-v1.json").read_text())
    value = json.loads((resource_root / "catalog-v1.json").read_text())
    rules["grant_types"][0], rules["grant_types"][1] = (
        rules["grant_types"][1], rules["grant_types"][0]
    )
    rules_projection = {
        name: rules[name] for name in ("schema_version", "grant_types", "signing_algorithms")
    }
    rules["rules_sha256"] = catalog._digest(rules_projection)
    value["parser_rules_sha256"] = rules["rules_sha256"]
    catalog_projection = {
        name: value[name]
        for name in ("schema_version", "plan_id", "parser_rules_sha256", "actions")
    }
    value["catalog_sha256"] = catalog._digest(catalog_projection)

    def fake_read(path, _expected_sha256):
        return rules if path == catalog._RULES_RESOURCE else value

    monkeypatch.setattr(catalog, "_read", fake_read)
    with pytest.raises(catalog.CatalogError, match="parser rules"):
        catalog._build()
