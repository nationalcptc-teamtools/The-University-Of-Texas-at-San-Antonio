"""Derived reports fail closed without replacing previous accepted records."""
import pytest

from cptc_harness.contracts import PolicyError
from test_reporting import reporting_runtime
from test_integration import age_identity, private


@pytest.mark.parametrize("event", ["coverage_intent", "coverage_generated", "report_intent", "report_complete", "coverage_write", "report_write"])
@pytest.mark.parametrize("previous", [False, True])
def test_audit_and_storage_failures_stop_and_restore_outputs(reporting_runtime, monkeypatch, event, previous):
    import cptc_harness.publication as module
    runtime = reporting_runtime
    coverage = event.startswith("coverage")
    action = runtime.coverage if coverage else runtime.report
    paths = [runtime.root / "coverage.json"] if coverage else [runtime.root / "reports/observations.json", runtime.root / "reports/observations.md"]
    if previous:
        action()
    original = {path: path.read_bytes() for path in paths if path.exists()}
    real_emit, real_write = runtime.audit.emit, module.atomic_write
    def emit(value):
        if value.kind == event:
            raise OSError("synthetic audit failure")
        return real_emit(value)
    def write(path, *args, **kwargs):
        if event.endswith("_write") and "unaccepted" in path.parts:
            raise OSError("synthetic output failure")
        return real_write(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(runtime.audit, "emit", emit)
        patch.setattr(module, "atomic_write", write)
        with pytest.raises(PolicyError):
            action()
    assert runtime.ledger.stopped()
    for path in paths:
        if path in original:
            assert path.read_bytes() == original[path]
        else:
            assert not path.exists()
    fixture = runtime.root.parent / "scan.xml"
    assert runtime.run("network.nmap_import", input_path=fixture)["result"]["status"] == "stopped"
    assert runtime.audit.verify().valid


def test_report_publication_failure_preserves_previous_pair(reporting_runtime, monkeypatch):
    import cptc_harness.publication as module
    runtime = reporting_runtime
    runtime.report()
    paths = [runtime.root / "reports/observations.json", runtime.root / "reports/observations.md"]
    original = {path: path.read_bytes() for path in paths}
    rename = module.os.replace
    failed = []
    def fail_second(source, destination):
        if not failed and source.parent.parent.name == "unaccepted" and destination == paths[1]:
            failed.append(True)
            raise OSError("synthetic second-file publication failure")
        return rename(source, destination)
    with monkeypatch.context() as patch:
        patch.setattr(module.os, "replace", fail_second)
        with pytest.raises(PolicyError):
            runtime.report()
    assert failed and runtime.ledger.stopped()
    assert all(path.read_bytes() == original[path] for path in paths)
