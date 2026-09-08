"""Synthetic provenance coverage for the local Linux inventory collector."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from cptc_harness.contracts import (EvidenceRef, ExecutionContext, OperationRequest,
                                    PolicySnapshot, ScopeSpec, SourceRef, to_json)
from cptc_harness.detection import classify_records
from cptc_harness.registry import build_registry
from cptc_harness.parsers.host import parse_linux_output


ROOT = Path(__file__).parents[1]
LINUX = ROOT / "human" / "collectors" / "collect-linux.py"


def load_linux():
    spec = importlib.util.spec_from_file_location("synthetic_collect_linux_provenance", LINUX)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def envelope(records, *, target="fixture-host", issues=()):
    return {"schema": "cptc.linux.inventory.v1", "target": target,
            "controls": {"network_access": False, "sudo_used": False, "service_changes": False},
            "records": records, "issues": list(issues)}


def _import_result(raw: bytes):
    source = SourceRef("synthetic-import", hashlib.sha256(raw).hexdigest())
    request = OperationRequest("import-action", "workspace", "device", "operator",
                               "linux.output_import", None, {}, "operator", None, "revision")
    scope = ScopeSpec(allowed_hosts=("fixture-host",))
    policy = PolicySnapshot("engagement", "revision", "workspace", "device", "operator", scope)

    def capture(stream, data, classification):
        return EvidenceRef("encrypted-import", None, stream, classification, None,
                           hashlib.sha256(data).hexdigest(), len(data))

    context = ExecutionContext(request, build_registry().get(request.module_id), policy,
                               capture=capture, source=source, input_bytes=raw)
    result = build_registry().dispatch(context)
    record = {"request": {"request_id": request.request_id, "module_id": request.module_id,
                           "source": request.source, "operator_id": request.operator_id,
                           "target": None}, "result": to_json(result)}
    return result, record


def _detector_row(record, rule_id):
    result = classify_records([record])
    return next(row for row in result["detections"] if row["rule_id"] == rule_id)


def test_collector_permission_provenance_survives_registry_and_detector(tmp_path, monkeypatch):
    collector = load_linux()
    fixture = tmp_path / "passwd"
    fixture.write_text("synthetic")
    fixture.chmod(0o777)
    info = fixture.stat()

    def synthetic_metadata(path, _issues=None):
        return (info, "/etc/passwd") if str(path) == "/etc/passwd" else None

    monkeypatch.setattr(collector, "metadata", synthetic_metadata)
    records = collector.permissions([])
    assert records == [{"kind": "permission", "path": "/etc/passwd", "mode": "0777",
                        "owner": str(info.st_uid), "world_writable": True,
                        "provenance": "os_inventory"}]
    raw = json.dumps(envelope(records), sort_keys=True, separators=(",", ":")).encode()
    result, record = _import_result(raw)
    assert result.status == "complete"
    row = _detector_row(record, "linux_world_writable_critical_path")
    assert row["disposition"] == "observed_condition"
    assert row["collection_complete"] is True
    assert row["source_actions"] == ["import-action"]
    assert row["evidence_ids"] == ["encrypted-import"]


def test_symlink_permissions_never_become_critical_file_findings(tmp_path, monkeypatch):
    collector = load_linux()
    original = tmp_path / "target"; original.write_text("synthetic")
    link = tmp_path / "link"; link.symlink_to(original)
    monkeypatch.setattr(collector, "metadata", lambda path, _issues: (link.lstat(), str(path)))
    issues = []
    assert collector.permissions(issues) == []
    assert issues == ["collector_metadata_unavailable"]


def test_hardened_critical_file_and_sticky_tmp_have_no_false_finding():
    raw = json.dumps(envelope([
        {"kind": "permission", "path": "/etc/passwd", "mode": "0644", "owner": "0",
         "world_writable": False, "provenance": "os_inventory"},
        {"kind": "permission", "path": "/tmp", "mode": "1777", "owner": "0",
         "world_writable": True, "provenance": "os_inventory"},
    ]), sort_keys=True, separators=(",", ":")).encode()
    _, record = _import_result(raw)
    result = classify_records([record])
    rows = result["detections"]
    assert [(row["component_id"], row["disposition"]) for row in rows] == [
        ("path:/etc/passwd", "not_observed")]


def test_collector_service_basis_is_principal_only_and_root_stays_unknown(monkeypatch, tmp_path):
    collector = load_linux()
    root = tmp_path / "services"
    root.mkdir()
    service = root / "fixture.service"
    service.touch()
    info = service.stat()
    monkeypatch.setattr(collector, "metadata", lambda _path, _issues=None: (info, str(service)))
    monkeypatch.setattr(collector.os, "geteuid", lambda: 0)
    records = collector.directory_records((root,), "service", [])
    assert records[0]["writable_basis"] == "administrator"
    assert "privileged" not in records[0]
    raw = json.dumps(envelope(records), sort_keys=True, separators=(",", ":")).encode()
    _, record = _import_result(raw)
    row = _detector_row(record, "linux_writable_service_or_task")
    assert row["disposition"] == "unknown"
    assert row["collection_complete"] is False

    monkeypatch.setattr(collector.os, "geteuid", lambda: 1000)
    assert collector.directory_records((root,), "service", [])[0]["writable_basis"] == "current_principal"


def test_low_privilege_operator_proof_is_accepted_but_legacy_metadata_is_unknown():
    proven = json.dumps(envelope([{
        "kind": "service", "name": "fixture.service", "state": "running", "owner": "0",
        "writable": True, "writable_basis": "low_privilege", "privileged": True,
    }]), sort_keys=True, separators=(",", ":")).encode()
    _, proven_record = _import_result(proven)
    assert _detector_row(proven_record, "linux_writable_service_or_task")["disposition"] == "observed_condition"

    legacy = json.loads((ROOT / "tests" / "fixtures" / "linux_inventory_vulnerable.json").read_text())
    legacy["target"] = "fixture-host"
    legacy_raw = json.dumps(legacy, sort_keys=True, separators=(",", ":")).encode()
    _, legacy_record = _import_result(legacy_raw)
    row = _detector_row(legacy_record, "linux_writable_service_or_task")
    assert row["disposition"] == "unknown"
    assert row["collection_complete"] is False


def test_provenance_fields_are_typed_and_restricted_to_their_record_kind():
    base = {"schema": "cptc.linux.inventory.v1", "target": "fixture-host",
            "controls": {"network_access": False, "sudo_used": False, "service_changes": False}}
    permission = {"kind": "permission", "path": "/etc/passwd", "mode": "0777", "owner": "0",
                  "world_writable": True, "provenance": "operator_reviewed"}
    parsed = parse_linux_output(json.dumps({**base, "records": [permission]}), "synthetic",
                                 ScopeSpec(allowed_hosts=("fixture-host",)))
    assert parsed.observations[0].facts["provenance"] == "operator_reviewed"
    assert "writable_basis" not in parsed.observations[0].facts

    nested_permission = {"kind": "permission", "facts": {
        "path": "/etc/passwd", "mode": "0777", "owner": "0", "world_writable": True,
        "provenance": "os_inventory"}}
    parsed = parse_linux_output(json.dumps({**base, "records": [nested_permission]}), "synthetic",
                                 ScopeSpec(allowed_hosts=("fixture-host",)))
    assert parsed.observations[0].facts["provenance"] == "os_inventory"

    top_level_injected = {"kind": "permission", "facts": {
        "path": "/etc/passwd", "mode": "0777", "owner": "0", "world_writable": True},
        "provenance": "operator_reviewed"}
    parsed = parse_linux_output(json.dumps({**base, "records": [top_level_injected]}), "synthetic",
                                 ScopeSpec(allowed_hosts=("fixture-host",)))
    assert not parsed.observations and any(item.code == "unknown_record_field" for item in parsed.issues)

    bad_permission = {**permission, "provenance": "guessed"}
    parsed = parse_linux_output(json.dumps({**base, "records": [bad_permission]}), "synthetic",
                                 ScopeSpec(allowed_hosts=("fixture-host",)))
    assert not parsed.observations and any(item.code == "invalid_permission" for item in parsed.issues)

    injected = {**permission, "privileged": True}
    parsed = parse_linux_output(json.dumps({**base, "records": [injected]}), "synthetic",
                                 ScopeSpec(allowed_hosts=("fixture-host",)))
    assert not parsed.observations and any(item.code == "unknown_record_field" for item in parsed.issues)

    bad_service = {"kind": "service", "name": "fixture.service", "state": "running", "owner": "0",
                   "writable": True, "writable_basis": "low_privilege", "privileged": "yes"}
    parsed = parse_linux_output(json.dumps({**base, "records": [bad_service]}), "synthetic",
                                 ScopeSpec(allowed_hosts=("fixture-host",)))
    assert not parsed.observations and any(item.code == "invalid_service_or_task" for item in parsed.issues)
