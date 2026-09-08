"""A green pytest exit cannot hide missing, skipped or interrupted tests."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest
from testing.acceptance import evaluate

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("full_suite_runner", ROOT / "scripts/test-harness.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def events():
    return [{"kind": "collection", "nodeids": ["test::case"]},
            *({"kind": "case", "nodeid": "test::case", "phase": phase, "outcome": "passed", "duration": 0.1,
               "xfail": False, "subtest": False, "reason": "", "rendered_sections": []}
              for phase in ("setup", "call", "teardown")),
            {"kind": "session_finished", "exit_code": 0}]


def test_complete_suite_reports_exact_cases_and_subtests():
    data = events();data.insert(2, {**data[2], "subtest": True})
    result = evaluate(data, 0)
    assert result["software_passed"] and result["totals"] == {"passed": 1} and result["subtests"] == 1


@pytest.mark.parametrize("change", ["missing_collection", "missing_completion", "missing_teardown", "duplicate_call", "skip", "xfail", "failure", "unexpected", "empty", "duplicate_collection", "exit_failure", "collection_failure"])
def test_false_success_is_rejected(change):
    data = events();code = 0
    if change == "missing_collection":data.pop(0)
    elif change == "missing_completion":data.pop()
    elif change == "missing_teardown":data.pop(3)
    elif change == "duplicate_call":data.insert(2, deepcopy(data[2]))
    elif change == "skip":data[2]["outcome"] = "skipped"
    elif change == "xfail":data[2]["xfail"] = True
    elif change == "failure":data[2]["outcome"] = "failed"
    elif change == "unexpected":data[2]["nodeid"] = "other::case"
    elif change == "empty":data[0]["nodeids"] = []
    elif change == "duplicate_collection":data.insert(0, deepcopy(data[0]))
    elif change == "exit_failure":code = 1
    elif change == "collection_failure":data.insert(1, {"kind": "collection_problem", "outcome": "skipped"})
    assert evaluate(data, code)["software_passed"] is False


@pytest.mark.parametrize("mutation", ["boolean_exit", "integer_node", "nan_duration", "unknown_field", "unknown_kind"])
def test_malformed_typed_receipts_are_rejected(mutation):
    data = events(); code = 0
    if mutation == "boolean_exit":
        code = False; data[-1]["exit_code"] = False
    elif mutation == "integer_node":
        data[0]["nodeids"] = [1]; data[1]["nodeid"] = 1
    elif mutation == "nan_duration": data[1]["duration"] = float("nan")
    elif mutation == "unknown_field": data[1]["injected"] = True
    else: data.insert(1, {"kind": "synthetic_unknown"})
    assert evaluate(data, code) == {"software_passed": False, "reason": "malformed_test_receipt", "tests": []}


def test_source_snapshot_rejects_root_startup_file_and_symlinked_tree(tmp_path, monkeypatch):
    for name in RUNNER.SOURCE_FILES:
        (tmp_path / name).write_text("synthetic")
    for name in RUNNER.SOURCE_ROOTS:
        (tmp_path / name).mkdir()
    monkeypatch.setattr(RUNNER, "ROOT", tmp_path)
    (tmp_path / "sitecustomize.py").write_text("raise SystemExit")
    with pytest.raises(ValueError, match="startup"):
        RUNNER.source_snapshot()
    (tmp_path / "sitecustomize.py").unlink()
    (tmp_path / "tests").rmdir(); (tmp_path / "tests").symlink_to(tmp_path / "web", target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked"):
        RUNNER.source_snapshot()


def test_source_snapshot_never_opens_protected_engagement_files(tmp_path, monkeypatch):
    for name in RUNNER.SOURCE_FILES:
        (tmp_path / name).write_text("synthetic")
    for name in RUNNER.SOURCE_ROOTS:
        (tmp_path / name).mkdir()
    protected = tmp_path / "web" / "engagements"
    protected.mkdir()
    secret = protected / "client-output.json"
    secret.write_text("must-not-be-read")
    opened = []
    real_read = RUNNER._source_bytes
    def guarded_read(path):
        opened.append(path)
        if protected in path.parents:
            pytest.fail("protected engagement data was opened")
        return real_read(path)
    monkeypatch.setattr(RUNNER, "ROOT", tmp_path)
    monkeypatch.setattr(RUNNER, "_source_bytes", guarded_read)
    snapshot = RUNNER.source_snapshot()
    assert snapshot["files"] == len(RUNNER.SOURCE_FILES)
    assert secret not in opened


def test_event_reporter_uses_initialized_fd_despite_environment_and_write_mutation():
    import os
    from types import SimpleNamespace
    import testing.pytest_plugin as plugin
    read_fd, write_fd = os.pipe()
    original_event_fd = os.environ.get("CPTC_TEST_EVENT_FD")
    original_write = plugin.os.write
    original_descriptor = plugin._EVENT_FD
    try:
        plugin._EVENT_FD = write_fd
        os.environ["CPTC_TEST_EVENT_FD"] = "999999"
        plugin.os.write = lambda *_: pytest.fail("mutable os.write used")
        report = SimpleNamespace(nodeid="synthetic::case", when="call", outcome="passed", duration=.1,
                                 wasxfail=False, context=None, longrepr=None, sections=[])
        plugin.pytest_runtest_logreport(report)
        event = json.loads(os.read(read_fd, 4096))
        assert event["kind"] == "case" and event["nodeid"] == "synthetic::case"
    finally:
        plugin._EVENT_FD = original_descriptor
        plugin.os.write = original_write
        if original_event_fd is None:
            os.environ.pop("CPTC_TEST_EVENT_FD", None)
        else:
            os.environ["CPTC_TEST_EVENT_FD"] = original_event_fd
        os.close(read_fd)
        os.close(write_fd)


def test_clean_test_environment_drops_python_injection_variables(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/synthetic/injected")
    monkeypatch.setenv("PYTHONSTARTUP", "/synthetic/startup.py")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    environment = RUNNER.clean_environment(tmp_path)
    assert not {"PYTHONPATH", "PYTHONSTARTUP", "PYTEST_ADDOPTS", "PYTHONHOME"} & set(environment)
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["HOME"] == str(tmp_path / "test-home")


def test_integrity_manifest_covers_all_suite_artifacts(tmp_path):
    names = ("audit.jsonl", "transcript.log", "stdout.bin", "stderr.bin", "junit.xml", "results.json")
    for index, name in enumerate(names):
        (tmp_path / name).write_bytes((name + str(index)).encode())
    manifest = RUNNER.write_integrity(tmp_path)
    saved = json.loads((tmp_path / "integrity-manifest.json").read_text())
    assert saved == manifest
    assert {item["path"] for item in manifest["files"]} == set(names)
    for item in manifest["files"]:
        raw = (tmp_path / item["path"]).read_bytes()
        assert item["bytes"] == len(raw)
        assert item["sha256"] == hashlib.sha256(raw).hexdigest()
    assert oct((tmp_path / "integrity-manifest.json").stat().st_mode & 0o777) == "0o600"


def test_integrity_manifest_rejects_missing_or_symlinked_artifact(tmp_path):
    names = ("audit.jsonl", "transcript.log", "stdout.bin", "stderr.bin", "junit.xml")
    for name in names:
        (tmp_path / name).write_bytes(b"synthetic")
    with pytest.raises(ValueError, match="missing"):
        RUNNER.write_integrity(tmp_path)
    (tmp_path / "results.json").symlink_to(tmp_path / "junit.xml")
    with pytest.raises(ValueError, match="symlinked"):
        RUNNER.write_integrity(tmp_path)
