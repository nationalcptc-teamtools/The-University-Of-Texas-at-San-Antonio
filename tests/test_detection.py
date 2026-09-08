"""Synthetic, offline tests for the finite CPTC detector."""
from copy import deepcopy

import pytest

from cptc_harness.detection import CATALOG, CATALOG_VERSION, classify_records


HASH = "a" * 64


def record(observations, *, target="fixture-host", module="linux.output_import",
           role=None, status="complete", issues=(), evidence=("ev-1",)):
    request = {"request_id": "request-1", "module_id": module, "source": "operator",
               "operator_id": "operator-1", "target": target}
    if role is not None:
        request["role_id"] = role
    return {"request": request, "result": {
        "status": status,
        "facts": {"observations": observations, "issues": list(issues)},
        "evidence": [{"evidence_id": value, "sha256": HASH} for value in evidence],
    }}


def observation(check_id, facts, *, target="fixture-host", track="linux", state="observed",
                source_sha256=HASH):
    return {"target": target, "track": track, "check_id": check_id, "state": state,
            "facts": facts, "source_sha256": source_sha256}


def detection(result, rule_id):
    return next(item for item in result["detections"] if item["rule_id"] == rule_id)


def test_catalog_is_finite_and_immutable():
    assert CATALOG_VERSION == 1
    assert {item["rule_id"] for item in CATALOG} == {
        "linux_world_writable_critical_path", "linux_writable_service_or_task",
        "linux_suid_inventory", "linux_capability_privilege", "windows_service_acl",
        "windows_task_acl", "windows_smb_signing", "windows_ldap_signing",
        "web_missing_security_headers", "apache_httpd_path_traversal",
        "samba_shared_module_loading",
    }
    with pytest.raises(TypeError):
        CATALOG[0]["rule_id"] = "runtime-rule"


@pytest.mark.parametrize("request_target", ["fixture-host", {"host": "fixture-host", "canonical_url": "https://fixture-host/"}])
def test_another_target_cannot_borrow_the_request_action_evidence(request_target):
    facts = {"path": "/etc/passwd", "mode": "0777", "owner": "0",
             "world_writable": True, "provenance": "os_inventory"}
    row = detection(classify_records([record([observation("linux_permission", facts, target="other-host")],
                                             target=request_target)]), "linux_world_writable_critical_path")
    assert row["disposition"] == "incomplete" and not row["collection_complete"]
    assert "request_target_mismatch" in row["limitations"]


def test_typed_host_request_matches_the_exact_host_only():
    facts = {"path": "/etc/passwd", "mode": "0644", "owner": "0",
             "world_writable": False, "provenance": "os_inventory"}
    row = detection(classify_records([record([observation("linux_permission", facts)], target={
        "host": "fixture-host", "canonical_url": "https://fixture-host/"})]), "linux_world_writable_critical_path")
    assert row["disposition"] == "not_observed"


def test_linux_permission_service_capability_and_suid_boundaries():
    observations = [
        observation("linux_permission", {"path": "/etc/passwd", "mode": "0777",
                                          "owner": "root", "world_writable": True,
                                          "provenance": "os_inventory"}),
        observation("linux_permission", {"path": "/tmp", "mode": "1777",
                                          "owner": "root", "world_writable": True,
                                          "provenance": "os_inventory"}),
        observation("linux_service", {"name": "fixture.service", "state": "running",
                                       "owner": "root", "writable": True,
                                       "writable_basis": "low_privilege", "privileged": True}),
        observation("linux_capability", {"path": "/usr/bin/fixture",
                                          "capabilities": ["cap_setuid+ep"]}),
        observation("linux_suid", {"path": "/usr/bin/passwd", "owner": "root"}),
    ]
    result = classify_records([record(observations)])
    permission = detection(result, "linux_world_writable_critical_path")
    assert permission["disposition"] == "observed_condition"
    assert permission["cwe_ids"] == ["CWE-732"]
    service = detection(result, "linux_writable_service_or_task")
    assert service["disposition"] == "observed_condition"
    capability = detection(result, "linux_capability_privilege")
    assert capability["disposition"] == "candidate"
    assert capability["cwe_ids"] == ["CWE-269"]
    assert capability["attack_techniques"] == []
    suid = detection(result, "linux_suid_inventory")
    assert suid["disposition"] == "unknown"
    assert "inventory_only_no_finding" in suid["limitations"]
    assert all(item["rule_id"] != "linux_world_writable_critical_path" or item["target"] == "fixture-host"
               for item in result["detections"])


def test_missing_low_privilege_basis_is_unknown_and_sticky_tmp_is_ignored():
    observations = [
        observation("linux_service", {"name": "fixture.service", "state": "running",
                                       "owner": "root", "writable": True}),
        observation("linux_permission", {"path": "/tmp", "mode": "1777",
                                          "owner": "root", "world_writable": True,
                                          "provenance": "os_inventory"}),
    ]
    result = classify_records([record(observations)], expected_checks=[
        {"target": "fixture-host", "rule_id": "linux_writable_service_or_task",
         "role_id": "unauthenticated"},
        {"target": "fixture-host", "rule_id": "linux_world_writable_critical_path",
         "role_id": "unauthenticated"},
    ])
    assert detection(result, "linux_writable_service_or_task")["disposition"] == "unknown"
    assert detection(result, "linux_world_writable_critical_path")["disposition"] == "not_tested"


def test_windows_acl_and_signing_rows_keep_relationships_and_role():
    observations = [
        observation("windows_service_acl", {"name": "Svc", "state": "running",
                                             "owner_sid": "S-1-5-18", "non_admin_write": True,
                                             "inherited": False, "ace_count": 2},
                     track="windows_ad"),
        observation("windows_task_acl", {"name": "Task", "state": "enabled",
                                          "owner_sid": "S-1-5-18", "non_admin_write": False,
                                          "inherited": False, "ace_count": 2},
                     track="windows_ad"),
        observation("windows_smb_policy", {"signing_required": False}, track="windows_ad"),
        observation("windows_ldap_policy", {"signing_required": False,
                                             "channel_binding_required": True}, track="windows_ad"),
    ]
    result = classify_records([record(observations, module="windows_ad.output_import", role="admin")])
    service = detection(result, "windows_service_acl")
    assert service["disposition"] == "observed_condition"
    assert service["role_id"] == "admin" and service["attack_techniques"] == ["T1574.010"]
    task = detection(result, "windows_task_acl")
    assert task["disposition"] == "not_observed" and task["attack_techniques"] == ["T1053.005"]
    smb = detection(result, "windows_smb_signing")
    assert smb["disposition"] == "candidate" and smb["cve_ids"] == []
    assert "prerequisites_unverified" in smb["limitations"]
    assert detection(result, "windows_ldap_signing")["attack_techniques"] == ["T1557.001"]


def test_web_headers_are_configuration_candidates_without_cves():
    result = classify_records([record([
        observation("web_headers", {"status": 200, "headers_present": ["hsts"],
                                      "redirect": False}, track="web",
                     target="https://fixture.test/"),
    ], target="https://fixture.test/", module="web.headers")])
    row = detection(result, "web_missing_security_headers")
    assert row["disposition"] == "candidate"
    assert row["cve_ids"] == []


@pytest.mark.parametrize(("product", "version", "expected"), [
    ("Apache HTTP Server", "2.4.49", {"CVE-2021-41773", "CVE-2021-42013"}),
    ("httpd", "2.4.50", {"CVE-2021-42013"}),
    ("samba", "4.6.3", {"CVE-2017-7494"}),
    ("samba", "4.6.4", set()),
])
def test_exact_advisory_versions_and_fixed_boundaries(product, version, expected):
    result = classify_records([record([observation("package_version", {
        "product": product, "version": version, "provenance": "package_database",
    })])])
    rule = "apache_httpd_path_traversal" if "apache" in product.lower() or "httpd" in product.lower() else "samba_shared_module_loading"
    row = detection(result, rule)
    assert row["cve_ids"] == sorted(expected)
    assert row["disposition"] in {"candidate", "unknown"}
    assert row["disposition"] != "observed_condition"


def test_suffix_version_requires_backport_and_configuration_limits():
    result = classify_records([record([observation("component_identity", {
        "product": "Apache HTTP Server", "version": "2.4.49-ubuntu1",
        "provenance": "banner",
    })])])
    row = detection(result, "apache_httpd_path_traversal")
    assert row["disposition"] == "candidate"
    assert {"version_only", "backport_unverified", "configuration_unverified"} <= set(row["limitations"])
    assert row["collection_complete"] is False


def test_version_matching_uses_exact_products_and_typed_network_ports():
    apache_tomcat = classify_records([record([observation("package_version", {
        "product": "Apache Tomcat", "version": "2.4.49", "provenance": "banner",
    })])])
    proxy = classify_records([record([observation("package_version", {
        "product": "httpd-proxy", "version": "2.4.49", "provenance": "banner",
    })])])
    assert not apache_tomcat["detections"] and not proxy["detections"]
    ports = [{"port": 443, "protocol": "tcp", "state": "open",
              "product": "Apache HTTP Server", "version": "2.4.49"},
             {"port": 445, "protocol": "tcp", "state": "open",
              "product": "Samba", "version": "4.6.3"}]
    result = classify_records([record([observation("network_inventory", {
        "ports": ports,
    }, track="network")], module="network.nmap_import")])
    rows = {row["component_id"]: row for row in result["detections"]}
    assert rows["port:443/tcp"]["rule_id"] == "apache_httpd_path_traversal"
    assert rows["port:445/tcp"]["rule_id"] == "samba_shared_module_loading"
    assert rows["port:443/tcp"]["disposition"] == "candidate"
    assert rows["port:445/tcp"]["disposition"] == "candidate"


def test_missing_or_unrelated_evidence_cannot_make_conclusive_result():
    value = record([observation("linux_permission", {
        "path": "/etc/passwd", "mode": "0777", "owner": "root",
        "world_writable": True, "provenance": "os_inventory",
    })], evidence=())
    row = detection(classify_records([value]), "linux_world_writable_critical_path")
    assert row["disposition"] == "incomplete" and row["collection_complete"] is False
    unrelated = record([observation("linux_permission", {
        "path": "/etc/passwd", "mode": "0777", "owner": "root",
        "world_writable": True, "provenance": "os_inventory",
    })], evidence=("unrelated",))
    unrelated["result"]["evidence"][0]["sha256"] = "b" * 64
    row = detection(classify_records([unrelated]), "linux_world_writable_critical_path")
    assert row["disposition"] == "incomplete" and row["evidence_ids"] == []
    nested = record([observation("linux_permission", {
        "path": "/etc/passwd", "mode": "0777", "owner": "root",
        "world_writable": True, "provenance": "os_inventory",
        "source_sha256": HASH,
    })])
    nested["result"]["evidence"][0]["sha256"] = HASH
    nested["result"]["facts"]["observations"][0].pop("source_sha256")
    row = detection(classify_records([nested]), "linux_world_writable_critical_path")
    assert row["disposition"] == "incomplete"
    assert "source_sha256_missing_or_invalid" in row["limitations"]


def test_only_originating_request_id_can_be_a_source_action():
    value = record([observation("linux_permission", {
        "path": "/etc/passwd", "mode": "0777", "owner": "root",
        "world_writable": True, "provenance": "os_inventory",
    })])
    value["request"]["source_actions"] = ["forged-prior-action"]
    row = detection(classify_records([value]), "linux_world_writable_critical_path")
    assert row["source_actions"] == ["request-1"]
    assert "forged-prior-action" not in row["source_actions"]


def test_legacy_observation_fixture_remains_inventory_compatible():
    import json
    from pathlib import Path

    payload = json.loads(Path("tests/fixtures/linux_inventory_vulnerable.json").read_text())
    observations = []
    for item in payload["records"]:
        kind = item["kind"]
        check = {"permission": "linux_permission", "service": "linux_service",
                 "task": "linux_task", "suid": "linux_suid",
                 "capability": "linux_capability"}.get(kind)
        if check:
            facts = {key: value for key, value in item.items() if key != "kind"}
            observations.append(observation(check, facts))
    result = classify_records([record(observations)])
    assert any(row["rule_id"] == "linux_suid_inventory" for row in result["detections"])
    assert any(row["rule_id"] == "linux_capability_privilege" and row["disposition"] == "candidate"
               for row in result["detections"])


def test_component_identity_keeps_mixed_safe_and_vulnerable_components_separate():
    result = classify_records([record([
        observation("linux_permission", {"path": "/etc/passwd", "mode": "0777",
                                           "owner": "root", "world_writable": True,
                                           "provenance": "os_inventory"}),
        observation("linux_permission", {"path": "/etc/shadow", "mode": "0640",
                                           "owner": "root", "world_writable": False,
                                           "provenance": "os_inventory"}),
    ])])
    rows = {row["component_id"]: row for row in result["detections"]}
    assert rows["path:/etc/passwd"]["disposition"] == "observed_condition"
    assert rows["path:/etc/shadow"]["disposition"] == "not_observed"
    assert {row["component_id"] for row in result["coverage"]} >= {"path:/etc/passwd", "path:/etc/shadow"}


def test_failure_conflict_empty_and_expected_rows_are_visible():
    positive = record([observation("linux_permission", {"path": "/etc/passwd", "mode": "0777",
                                                          "owner": "root", "world_writable": True,
                                                          "provenance": "os_inventory"})])
    negative = record([observation("linux_permission", {"path": "/etc/passwd", "mode": "0644",
                                                          "owner": "root", "world_writable": False,
                                                          "provenance": "os_inventory"})])
    failed = record([], module="windows_ad.output_import", status="failed")
    expected = [{"target": "fixture-host", "rule_id": "windows_task_acl", "role_id": "reader"}]
    result = classify_records([positive, negative, failed], expected_checks=expected)
    assert detection(result, "linux_world_writable_critical_path")["disposition"] == "unknown"
    assert any(row["disposition"] == "failed" for row in result["detections"])
    assert any(row["rule_id"] == "windows_task_acl" and row["disposition"] == "not_tested"
               for row in result["detections"])
    before = deepcopy(result)
    assert classify_records([positive, negative, failed], expected_checks=expected) == before


def test_expected_checks_do_not_accept_vulnerability_answers():
    with pytest.raises(ValueError):
        classify_records([], expected_checks=[{"target": "fixture-host", "rule_id": "linux_suid_inventory",
                                              "role_id": "unauthenticated", "expectation": "vulnerable"}])
