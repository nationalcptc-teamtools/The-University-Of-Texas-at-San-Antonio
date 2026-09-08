"""Synthetic coverage for the human collector bounds and limitation flags."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace


ROOT = Path(__file__).parents[1]
LINUX = ROOT / "human" / "collectors" / "collect-linux.py"
WINDOWS = ROOT / "human" / "collectors" / "collect-windows.ps1"


def load_linux():
    spec = importlib.util.spec_from_file_location("synthetic_collect_linux", LINUX)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mirrors_are_byte_identical():
    assert LINUX.read_bytes() == (ROOT / "scripts" / "collect-linux.py").read_bytes()
    assert WINDOWS.read_bytes() == (ROOT / "scripts" / "collect-windows.ps1").read_bytes()


def test_group_limit_is_reported_and_groups_keep_the_existing_shape(monkeypatch):
    collector = load_linux()
    monkeypatch.setattr(collector.os, "getgroups", lambda: list(range(65)))
    issues: list[str] = []

    result = collector.identity(issues)

    assert len(result["groups"]) == 64
    assert issues == ["collector_group_limit"]


def test_directory_entry_limit_is_reported_with_sorted_bounded_records(tmp_path):
    collector = load_linux()
    root = tmp_path / "services"
    root.mkdir()
    for index in range(97):
        (root / f"service-{index:03d}").touch()
    issues: list[str] = []

    records = collector.directory_records((root,), "service", issues)

    assert len(records) == 96
    assert records[0]["name"] == "service-000"
    assert issues == ["collector_directory_limit"]


def test_unreadable_directory_and_missing_metadata_use_bounded_codes(monkeypatch):
    collector = load_linux()

    class Unreadable:
        def iterdir(self):
            raise PermissionError("secret synthetic detail")

    issues: list[str] = []
    assert collector.directory_records((Unreadable(),), "service", issues) == []
    assert issues == ["collector_directory_unreadable"]

    def missing_stat(*_args, **_kwargs):
        raise FileNotFoundError("raw synthetic path")

    monkeypatch.setattr(collector.os, "stat", missing_stat)
    assert collector.metadata(Path("/synthetic/missing"), issues) is None
    assert issues == ["collector_directory_unreadable", "collector_metadata_unavailable"]
    assert "secret synthetic detail" not in " ".join(issues)

    long_issues: list[str] = []
    assert collector.metadata(Path("/" + "x" * 256), long_issues) is None
    assert long_issues == ["collector_metadata_unavailable"]

    class InvalidNameDirectory:
        def iterdir(self):
            return iter([Path("/synthetic/invalid/unsafe name")])

    invalid_issues: list[str] = []
    assert collector.directory_records((InvalidNameDirectory(),), "service", invalid_issues) == []
    assert invalid_issues == ["collector_metadata_unavailable"]

    class AccessDirectory:
        def iterdir(self):
            return iter([Path("/synthetic/access/safe-name")])

    monkeypatch.setattr(collector, "metadata", lambda _path, _issues=None: (os.stat_result((0, 0, 0, 1, 0, 0, 0, 0, 0, 0)), "/synthetic/access/safe-name"))
    monkeypatch.setattr(collector.os, "access", lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("raw access detail")))
    access_issues: list[str] = []
    assert collector.directory_records((AccessDirectory(),), "service", access_issues) == []
    assert access_issues == ["collector_metadata_unavailable"]


def test_walk_directory_limit_is_reported(monkeypatch):
    collector = load_linux()
    collector.SUID_ROOTS = (Path("/synthetic/root"),)
    monkeypatch.setattr(collector.Path, "is_dir", lambda _path: True)
    monkeypatch.setattr(
        collector.os,
        "walk",
        lambda *_args, **_kwargs: iter([("/synthetic/root", [f"dir-{i}" for i in range(33)], [])]),
    )
    issues: list[str] = []

    assert collector.suid_records(issues) == []
    assert issues == ["collector_walk_limit"]


def test_suid_record_limit_is_reported_without_emitting_the_65th_record(monkeypatch):
    collector = load_linux()
    collector.SUID_ROOTS = (Path("/synthetic/root"),)
    monkeypatch.setattr(collector.Path, "is_dir", lambda _path: True)
    names = [f"suid-{i:03d}" for i in range(65)]
    monkeypatch.setattr(collector.os, "walk", lambda *_args, **_kwargs: iter([("/synthetic/root", [], names)]))
    suid_mode = stat.S_IFREG | stat.S_ISUID | 0o755
    synthetic_stat = os.stat_result((suid_mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    metadata_calls: list[Path] = []

    def synthetic_metadata(path, _issues=None):
        metadata_calls.append(path)
        return synthetic_stat, "/synthetic/item"

    monkeypatch.setattr(collector, "metadata", synthetic_metadata)
    issues: list[str] = []

    records = collector.suid_records(issues)

    assert len(records) == 64
    assert len(metadata_calls) == 64
    assert issues == ["collector_suid_limit"]


def test_capability_line_and_byte_limits_are_reported(monkeypatch):
    collector = load_linux()
    monkeypatch.setattr(collector.os.path, "isfile", lambda _path: True)
    lines = b"".join(f"/usr/bin/cap-{i:03d} cap_net_raw=ep\n".encode() for i in range(65))
    monkeypatch.setattr(
        collector.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=lines),
    )
    issues: list[str] = []

    records, returned_issues = collector.capability_records(issues)

    assert len(records) == 64
    assert returned_issues is issues
    assert issues == ["collector_capability_limit"]

    oversized = lines * 4096
    monkeypatch.setattr(
        collector.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=oversized),
    )
    issues = []
    collector.capability_records(issues)
    assert issues == ["collector_capability_limit"]

    monkeypatch.setattr(
        collector.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b"/usr/bin/malformed\n"),
    )
    issues = []
    assert collector.capability_records(issues)[0] == []
    assert issues == ["collector_metadata_unavailable"]


def test_unsupported_capability_inventory_remains_visible(monkeypatch):
    collector = load_linux()
    monkeypatch.setattr(collector.os.path, "isfile", lambda _path: False)

    records, issues = collector.capability_records()

    assert records == []
    assert issues == ["unsupported_capability_inventory"]


def test_final_record_limit_and_issue_order_are_deterministic(monkeypatch, capsys):
    collector = load_linux()
    monkeypatch.setattr(collector, "identity", lambda issues: (issues.extend(["collector_group_limit", "collector_group_limit"]) or {"kind": "identity"}))
    monkeypatch.setattr(collector, "permissions", lambda _issues: [{"kind": "permission"}] * 256)
    monkeypatch.setattr(collector, "directory_records", lambda *_args: [])
    monkeypatch.setattr(collector, "suid_records", lambda _issues: [])
    monkeypatch.setattr(collector, "capability_records", lambda issues: ([], issues))

    assert collector.main(["--target", "synthetic"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert len(payload["records"]) == 256
    assert payload["issues"] == ["collector_group_limit", "collector_record_limit"]


def test_windows_mirror_contains_bounded_service_and_final_record_flags():
    source = WINDOWS.read_text()
    assert "$services.Count -ge 96" in source
    assert "collector_directory_limit" in source
    assert "$records.Count -gt 256" in source
    assert "collector_record_limit" in source
    assert "Exception.Message" not in source
