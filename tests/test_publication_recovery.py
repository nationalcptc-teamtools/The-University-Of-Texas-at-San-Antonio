"""Interrupted publications cannot authorize exports or lose earlier reports."""
import json
import pytest
from cptc_harness.contracts import PolicyError
from cptc_harness.exports import prepare_export, _archive, ExportReview
from cptc_harness.runtime import Runtime
from cptc_harness.storage import write_json
from test_reporting import reporting_runtime
from test_integration import age_identity, private


class Crash(BaseException):
    pass


@pytest.mark.parametrize("previous", [False, True])
@pytest.mark.parametrize("point", ["pending", "intent", "replace_first", "replace_second", "directory_sync",
                                  "before_completion", "after_completion", "accepted_checkpoint"])
def test_restart_recovers_each_publication_boundary(reporting_runtime, monkeypatch, previous, point):
    import cptc_harness.publication as module
    runtime = reporting_runtime
    paths = [runtime.root / "reports/observations.json", runtime.root / "reports/observations.md"]
    if previous:
        runtime.report()
    before = {p: p.read_bytes() for p in paths if p.exists()}
    runtime.run("network.nmap_import", input_path=runtime.root.parent / "scan.xml")
    real_write, real_replace, real_emit, real_sync = module.write_json, module.os.replace, runtime.audit.emit, module._sync
    published = []
    def write(path, value, **kwargs):
        if point == "accepted_checkpoint" and value.get("state") == "accepted":
            raise Crash()
        result = real_write(path, value, **kwargs)
        if point == "pending" and value.get("state") == "pending":
            raise Crash()
        return result
    def replace(source, destination):
        result = real_replace(source, destination)
        if source.parent.parent.name == "unaccepted" and destination in paths:
            published.append(destination)
            if (point == "replace_first" and len(published) == 1) or (point == "replace_second" and len(published) == 2):
                raise Crash()
        return result
    def sync(directory):
        real_sync(directory)
        if point == "directory_sync" and published:
            raise Crash()
    def emit(event):
        if point == "before_completion" and event.kind == "report_complete":
            raise Crash()
        result = real_emit(event)
        if (point == "intent" and event.kind == "publication_intent") or (point == "after_completion" and event.kind == "report_complete"):
            raise Crash()
        return result
    with monkeypatch.context() as patch:
        patch.setattr(module, "write_json", write)
        patch.setattr(module.os, "replace", replace)
        patch.setattr(module, "_sync", sync)
        patch.setattr(runtime.audit, "emit", emit)
        with pytest.raises(Crash):
            runtime.report()
    with pytest.raises(PolicyError):
        prepare_export(runtime.root, ("reports/observations.json",), operator="operator", publication_receipts=runtime.audit.publication_receipts)
    runtime.audit.close()
    reopened = Runtime(runtime.root, ledger_root=runtime.ledger_root.parent)
    try:
        committed = point in {"after_completion", "accepted_checkpoint"}
        assert reopened.ledger.stopped() is not committed
        assert reopened.audit.verify().valid
        states = [json.loads(p.read_text())["state"] for p in (runtime.root / "reports/publications").glob("*.json")]
        assert "pending" not in states
        if committed:
            review = prepare_export(runtime.root, ("reports/observations.json", "reports/observations.md"),
                                    operator="operator", publication_receipts=reopened.audit.publication_receipts)
            assert len(review.files) == 2
            if previous:
                assert paths[0].read_bytes() != before[paths[0]]
        else:
            for path in paths:
                assert path.read_bytes() == before[path] if path in before else not path.exists()
    finally:
        reopened.audit.close()
    # Recovery itself is repeatable, with no counter reset or implicit resume.
    reopened = Runtime(runtime.root, ledger_root=runtime.ledger_root.parent)
    try:
        assert reopened.ledger.stopped() is not committed
    finally:
        reopened.audit.close()


@pytest.mark.parametrize("relative", ["reports/unaccepted/generation/observations.json", "reports/history/generation/observations.json",
                                      "reports/publications/anything.json", "reports/custom.json", "coverage.md"])
def test_internal_or_unreviewed_report_paths_never_export(reporting_runtime, relative):
    runtime = reporting_runtime
    with pytest.raises(PolicyError):
        prepare_export(runtime.root, (relative,), operator="operator", publication_receipts=runtime.audit.publication_receipts)
    forged = ExportReview(str(runtime.root), ({"path": relative, "bytes": 0, "sha256": "0" * 64},), "operator")
    with pytest.raises(PolicyError):
        _archive(forged, runtime.audit.publication_receipts)


def test_unaudited_changed_and_missing_journal_reports_fail_export(reporting_runtime):
    runtime = reporting_runtime
    path = runtime.root / "coverage.json"
    write_json(path, {"unaudited": True})
    with pytest.raises(PolicyError):
        prepare_export(runtime.root, ("coverage.json",), operator="operator", publication_receipts=runtime.audit.publication_receipts)
    runtime.coverage()
    review = prepare_export(runtime.root, ("coverage.json",), operator="operator", publication_receipts=runtime.audit.publication_receipts)
    original = path.read_bytes()
    write_json(path, {"changed": True})
    with pytest.raises(PolicyError):
        _archive(review, runtime.audit.publication_receipts)
    path.write_bytes(original)
    next((runtime.root / "reports/publications").glob("*.json")).unlink()
    with pytest.raises(PolicyError):
        prepare_export(runtime.root, ("coverage.json",), operator="operator", publication_receipts=runtime.audit.publication_receipts)


def test_quiescent_export_uses_verified_audit(reporting_runtime):
    runtime = reporting_runtime
    runtime.coverage()
    runtime.audit.close()
    review = prepare_export(runtime.root, ("coverage.json",), operator="operator")
    assert _archive(review)


@pytest.mark.parametrize("mutation", ["changed", "deleted", "permissions", "symlink"])
def test_accepted_file_integrity_failure_stops_restart(reporting_runtime, mutation):
    runtime = reporting_runtime
    runtime.report()
    path = runtime.root / "reports/observations.json"
    if mutation == "changed":
        write_json(path, {"changed": True})
    elif mutation == "deleted":
        path.unlink()
    elif mutation == "permissions":
        path.chmod(0o644)
    elif mutation == "symlink":
        path.unlink()
        path.symlink_to(runtime.root / "policy.json")
    runtime.audit.close()
    with pytest.raises(PolicyError):
        Runtime(runtime.root, ledger_root=runtime.ledger_root.parent)
    assert runtime.ledger.stopped()


@pytest.mark.parametrize("tamper", ["path", "checksum", "state", "missing"])
def test_tampered_journal_blocks_restart_without_modifying_reports(reporting_runtime, tamper):
    runtime = reporting_runtime
    runtime.report()
    final = runtime.root / "reports/observations.json"
    original = final.read_bytes()
    journal = next((runtime.root / "reports/publications").glob("*.json"))
    value = json.loads(journal.read_text())
    if tamper == "path":
        value["manifest"]["files"][0]["path"] = "../../outside"
    elif tamper == "checksum":
        value["manifest"]["files"][0]["sha256"] = "0" * 64
    elif tamper == "state":
        value["state"] = "aborted"
    write_json(journal, value)
    if tamper == "missing":
        journal.unlink()
    runtime.audit.close()
    with pytest.raises(PolicyError):
        Runtime(runtime.root, ledger_root=runtime.ledger_root.parent)
    assert runtime.ledger.stopped() and final.read_bytes() == original


@pytest.mark.parametrize('mutation', ['duplicate_intent', 'duplicate_completion', 'missing_intent', 'wrong_hash', 'wrong_path', 'negative_bytes', 'missing_sequence'])
def test_publication_receipt_corruption_is_rejected(mutation):
    import copy
    from cptc_harness.audit import publication_receipts_from_events
    intent = {'seq': 1, 'kind': 'publication_intent', 'data': {'generation': 'a' * 32, 'manifest_sha256': 'b' * 64, 'kind': 'coverage_generated'}}
    completion = {'seq': 2, 'kind': 'coverage_generated', 'data': {'generation': 'a' * 32, 'manifest_sha256': 'b' * 64,
                   'files': [{'path': 'coverage.json', 'sha256': 'c' * 64, 'bytes': 1}]}}
    events = copy.deepcopy([intent, completion])
    if mutation == 'duplicate_intent': events.insert(1, intent)
    elif mutation == 'duplicate_completion': events.append(completion)
    elif mutation == 'missing_intent': events.pop(0)
    elif mutation == 'wrong_hash': events[1]['data']['manifest_sha256'] = 'd' * 64
    elif mutation == 'wrong_path': events[1]['data']['files'][0]['path'] = 'reports/unaccepted/file.json'
    elif mutation == 'negative_bytes': events[1]['data']['files'][0]['bytes'] = -1
    elif mutation == 'missing_sequence': del events[1]['seq']
    with pytest.raises(PolicyError): publication_receipts_from_events(events)
