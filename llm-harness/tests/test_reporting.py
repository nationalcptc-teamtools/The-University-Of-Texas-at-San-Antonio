"""Reports use audit-linked results and preserve conflicting human observations."""
import json
import re

import pytest

from cptc_harness.contracts import AuditEvent, PolicyError, PolicySnapshot, ScopeSpec
from cptc_harness.policy import save_policy
from cptc_harness.reporting import markdown_report, report_records, summarize_result
from cptc_harness.runtime import Runtime, initialize
from cptc_harness.storage import write_json
from test_integration import age_identity, private


def record(action="a", state="candidate", reviewed=False, reference=None, source="operator"):
    return {"request": {"request_id": action, "operator_id": "synthetic-operator", "source": source},
            "result": {"facts": {"observations": [{"target": "192.0.2.10", "track": "reporting",
                "check_id": "finding_record", "state": state, "source_sha256": "a" * 64,
                "facts": {"finding_id": "finding-1", "reviewed": reviewed, "evidence_ref": reference}}]},
                "evidence": [{"evidence_id": "known-artifact"}]}}


def test_confirmation_requires_human_review_and_linked_evidence():
    for reviewed, reference, source in ((False, "known-artifact", "operator"), (True, "unknown", "operator"),
                                        (True, "known-artifact", "model")):
        report = report_records([record(state="confirmed", reviewed=reviewed, reference=reference, source=source)])
        assert report["observations"][0]["state"] == "unverified_human_claim"
    report = report_records([record(state="confirmed", reviewed=True, reference="known-artifact")])
    assert report["observations"][0]["state"] == "confirmed_by_human"
    assert report["classification"] == "client_confidential"


def test_exact_dedup_preserves_conflicting_states_and_ownership():
    a, b, changed = record(), record("b"), record("c", state="no_issue_observed")
    b["request"]["operator_id"] = "second-operator"
    report = report_records([a, b, changed])
    assert len(report["observations"]) == 2
    matching = next(item for item in report["observations"] if item["state"] == "candidate")
    assert matching["source_actions"] == ["a", "b"]
    assert matching["contributors"] == ["second-operator", "synthetic-operator"]


def test_detector_report_preserves_cve_candidate_and_audit_evidence_link():
    value = {"request": {"request_id": "actual-action", "operator_id": "operator", "source": "operator",
                         "module_id": "network.nmap_import", "target": None},
             "result": {"status": "complete", "facts": {"issues": [], "observations": [{
                 "target": "192.0.2.10", "track": "network", "check_id": "network_inventory", "state": "observed",
                 "source_sha256": "a" * 64, "facts": {"ports": [{"port": 80, "state": "open", "protocol": "tcp",
                                                            "product": "Apache httpd", "version": "2.4.49"}]}}]},
                        "evidence": [{"evidence_id": "raw-import", "sha256": "a" * 64}]}}
    report = report_records([value], expected_checks=[{"target": "192.0.2.10", "role_id": "unauthenticated",
                                                      "rule_id": "apache_httpd_path_traversal"}])
    candidate = next(item for item in report["detections"] if item["rule_id"] == "apache_httpd_path_traversal")
    assert candidate["disposition"] == "candidate"
    assert "CVE-2021-41773" in candidate["cve_ids"]
    assert candidate["source_actions"] == ["actual-action"]
    assert report["evidence_index"] == [{"evidence_id": "raw-import", "sha256": "a" * 64, "source_action": "actual-action"}]
    assert report["model_calls"] == 0
    assert report["benchmark_status"] == "not_evaluated_external_catalog_required"
    assert "CVE-2021-41773" in markdown_report(report)


def test_coverage_reports_missing_checks_without_clean_conclusions():
    report = report_records([], expected_checks=[{"target": "192.0.2.10", "role_id": "low-privilege",
                                                 "rule_id": "windows_service_acl"}])
    assert report["check_coverage"][0]["disposition"] == "not_tested"
    assert report["check_coverage"][0]["collection_complete"] is False


def test_conflicting_evidence_identity_prevents_report():
    a, b = record(), record("b")
    a["result"]["evidence"][0]["sha256"] = "a" * 64
    b["result"]["evidence"][0]["sha256"] = "b" * 64
    with pytest.raises(PolicyError, match="conflicting captured evidence"):
        report_records([a, b])


def test_complete_import_with_limitations_remains_incomplete_collection():
    value = record()
    value["result"]["status"] = "complete"
    value["result"]["facts"]["issues"] = ["unsupported_service_acl", "collector_record_limit", "unsupported_service_acl"]
    summary = summarize_result(value["result"])
    assert summary == {"collection_state": "incomplete", "observation_count": 1,
                       "issues": ["collector_record_limit", "unsupported_service_acl"]}
    report = report_records([value])
    assert report["operations"][0]["collection_state"] == "incomplete"
    assert "unsupported_service_acl" in markdown_report(report)


@pytest.mark.parametrize("status", ["blocked", "failed", "uncertain", "stopped"])
def test_operations_without_observations_are_not_dropped(status):
    value = record()
    value["result"] = {"status": status, "facts": {}, "evidence": [], "reason": "synthetic unsupported profile"}
    report = report_records([value])
    assert report["observations"] == []
    assert report["operations"][0]["collection_state"] == status
    assert "synthetic unsupported profile" in markdown_report(report)


def test_readable_report_escapes_active_markup_and_terminal_controls():
    value = record()
    value["result"]["facts"]["observations"][0]["target"] = '<script>alert(1)</script>|[click](https://example.invalid)\x1b[2J\nnext'
    rendered = markdown_report(report_records([value]))
    assert "<script>" not in rendered and "\x1b" not in rendered and "\nnext" not in rendered
    assert "&lt;script&gt;" in rendered and "\\|" in rendered and "\\[click\\]" in rendered


@pytest.fixture
def reporting_runtime(private, age_identity):
    age, identity, recipient = age_identity
    policy = PolicySnapshot("fixture", "v1", "workspace", "device", "operator", ScopeSpec(("192.0.2.0/24",)))
    source = private / "policy.json"
    save_policy(source, policy)
    root = private / "engagement"
    initialize(root, source, recipient=recipient, age_binary=age)
    runtime = Runtime(root, ledger_root=private / "ledger")
    fixture = private / "scan.xml"
    fixture.write_text('<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>')
    fixture.chmod(0o600)
    assert runtime.run("network.nmap_import", input_path=fixture)["result"]["status"] == "complete"
    yield runtime
    runtime.audit.close()


def test_real_auditor_records_and_reports_without_model_calls(reporting_runtime):
    runtime = reporting_runtime
    report = runtime.report()
    assert report["observations"] == 1 and report["model_calls"] == 0
    records = runtime._records()
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", records[0]["recorded_at"])
    assert records[0]["audit_sequence"] > 0
    events = [json.loads(line) for line in runtime.audit.path.read_text().splitlines()]
    assert all(len(event["run_id"]) == 32 and len(event["session_id"]) == 32 for event in events)
    action_id = records[0]["request"]["request_id"]
    assert action_id in runtime.audit.transcript_path.read_text()
    intent = next(event for event in events if event["kind"] == "operation_intent")
    assert intent["data"]["remaining_budgets"]["actions"] == 12
    assert runtime.audit.verify().valid
    assert runtime.run("exploitation.zerologon")["result"]["status"] == "blocked"
    assert len(runtime._records()) == 2
    row = next(m for m in runtime.coverage()["modules"] if m["module_id"] == "exploitation.zerologon")
    assert row["latest_status"] == row["collection_state"] == "blocked"
    assert row["unsuccessful_attempts"] == 1 and row["observation_count"] == 0


@pytest.mark.parametrize("damage", ["changed", "missing", "malformed", "permission", "symlink", "extra"])
def test_result_integrity_failure_stops_reporting_and_new_work(reporting_runtime, damage):
    runtime = reporting_runtime
    path = next((runtime.root / "results").glob("*.json"))
    if damage == "changed":
        value = json.loads(path.read_text())
        value["result"]["status"] = "complete-forged"
        write_json(path, value)
    elif damage == "missing":
        path.unlink()
    elif damage == "malformed":
        path.write_text("{broken")
    elif damage == "permission":
        path.chmod(0o644)
    elif damage == "symlink":
        saved = runtime.root / "saved-fixture.json"
        path.rename(saved)
        path.symlink_to(saved)
    else:
        (runtime.root / "results/unexpected").touch(mode=0o600)
    with pytest.raises(PolicyError, match="integrity verification"):
        runtime.report()
    assert runtime.ledger.stopped()
    assert not (runtime.root / "reports/observations.json").exists()


def test_result_write_failure_survives_restart_without_silently_omitting_action(reporting_runtime, monkeypatch):
    runtime = reporting_runtime
    original = write_json
    def fail_result(path, *args, **kwargs):
        if path.parent.name == "results":
            raise OSError("synthetic result disk failure")
        return original(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr("cptc_harness.runtime.write_json", fail_result)
        result = runtime.run("exploitation.zerologon")
    assert result["result"]["status"] == "uncertain" and runtime.ledger.stopped()
    runtime.audit.close()
    reopened = Runtime(runtime.root, ledger_root=runtime.ledger_root.parent)
    try:
        assert reopened.audit.verify().valid
        with pytest.raises(PolicyError, match="integrity verification"):
            reopened._records()
        with pytest.raises(PolicyError, match="integrity verification"):
            reopened.report()
        assert reopened.ledger.stopped()
        assert not (runtime.root / "reports/observations.json").exists()
    finally:
        reopened.audit.close()


@pytest.mark.parametrize("event", ["operation_intent", "operation_result", "operation_denied"])
def test_crash_before_result_intent_still_requires_a_result_record(reporting_runtime, event):
    runtime = reporting_runtime
    runtime.audit.emit(AuditEvent(event, "interrupted-before-result-intent"))
    assert runtime.audit.verify().valid and runtime.audit.ready()
    with pytest.raises(PolicyError, match="integrity verification"):
        runtime.report()
    assert runtime.ledger.stopped()
