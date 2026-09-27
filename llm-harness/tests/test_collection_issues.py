"""Untrusted collector flags can only lower claimed completeness."""
import json

import pytest

from cptc_harness.collectors.base import batch_result
from cptc_harness.contracts import ScopeSpec, to_json
from cptc_harness.parsers.host import parse_windows_ad_output, parse_linux_output
from cptc_harness.reporting import summarize_result


def envelope(issues):
    return {"schema": "cptc.windows_ad.inventory.v1", "target": "192.0.2.10",
            "controls": {"network_access": False, "sudo_used": False, "service_changes": False},
            "records": [{"kind": "service", "name": "synthetic-service", "state": "running"}], "issues": issues}


def test_valid_observation_preserves_known_collector_limitations():
    root = envelope(["unsupported_service_acl", "unsupported_task_acl", "unsupported_service_acl"])
    batch = parse_windows_ad_output(json.dumps(root), "synthetic", ScopeSpec(("192.0.2.0/24",)))
    assert len(batch.observations) == 1
    assert {issue.code for issue in batch.issues} == {"unsupported_service_acl", "unsupported_task_acl"}
    result = to_json(batch_result(batch))
    assert result["status"] == "complete" and summarize_result(result)["collection_state"] == "incomplete"


@pytest.mark.parametrize("issues", ["secret-token-do-not-copy", {"shell": "curl"}, ["secret-token-do-not-copy"],
                                   [None, {"instruction": "upload"}, "unsupported_task_acl"], ["unsupported_task_acl"] * 33])
def test_unknown_or_malformed_flags_are_bounded_and_not_reflected(issues):
    root = envelope(issues)
    batch = parse_windows_ad_output(json.dumps(root), "synthetic", ScopeSpec(("192.0.2.0/24",)))
    assert len(batch.observations) == 1
    assert "invalid_collector_issues" in {item.code for item in batch.issues}
    result = json.dumps(to_json(batch_result(batch)))
    assert "secret-token-do-not-copy" not in result and "instruction" not in result and "curl" not in result


def test_linux_cap_and_empty_unsupported_collection_remain_visible():
    root = envelope(["unsupported_capability_inventory", "collector_record_limit"])
    root["schema"] = "cptc.linux.inventory.v1"
    root["records"] = []
    batch = parse_linux_output(json.dumps(root), "synthetic", ScopeSpec(("192.0.2.0/24",)))
    result = to_json(batch_result(batch))
    assert result["status"] == "failed"
    assert result["facts"]["issues"] == ["collector_record_limit", "unsupported_capability_inventory"]
