import hashlib
import importlib.util
import json
import os
import errno
import subprocess
import sys
import concurrent.futures
from types import SimpleNamespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "tools" / "team-env-setup" / "team_env_setup.py"
WRAPPER = ROOT / "team-env-setup.sh"


def load_module():
    spec = importlib.util.spec_from_file_location("team_env_setup", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixture(path, suite="kali-rolling"):
    path.write_text(json.dumps({
        "schema": "cptc.team-env.synthetic-apt.v1", "trusted": True,
        "architecture": "amd64", "origin": "Kali", "suite": suite,
        "source_metadata_sha256": "a" * 64,
        "packages": {name: {"version": "1.0-1", "component": "main"} for name in
                     ("jq", "unzip", "age", "python3", "python3-venv", "git", "docker.io", "docker-cli", "docker-compose")},
    }))


def run(*args, cwd=ROOT):
    return subprocess.run([str(WRAPPER), *args], cwd=cwd, text=True, capture_output=True, check=False)


def approved_lock(tmp_path):
    metadata, lock, review = tmp_path / "metadata.json", tmp_path / "lock.json", tmp_path / "review.json"
    fixture(metadata)
    tool = load_module()
    manifest = tool.load_manifest(tool.DEFAULT_MANIFEST)
    names = tool.profile_packages(manifest, "scribe")
    prepared = tool.fixture_metadata(metadata, names, "amd64", manifest)
    tool.write_private_json(lock, tool.lock_payload(manifest, "scribe", prepared))
    approved = run("review-lock", "--lock", str(lock), "--review", str(review), "--reviewer", "fixture-reviewer")
    assert approved.returncode == 0, approved.stderr
    return lock, review


def test_write_all_retries_interrupts_and_short_writes(tmp_path, monkeypatch):
    tool = load_module()
    target = tmp_path / "output"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    real_write = os.write
    attempts = 0

    def interrupted_short_write(fd, value):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise InterruptedError
        return real_write(fd, bytes(value[:2]))

    monkeypatch.setattr(tool.os, "write", interrupted_short_write)
    try:
        tool._write_all(descriptor, b"complete")
    finally:
        os.close(descriptor)

    assert attempts > 2
    assert target.read_bytes() == b"complete"


def test_write_all_rejects_zero_progress(tmp_path, monkeypatch):
    tool = load_module()
    target = tmp_path / "output"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    monkeypatch.setattr(tool.os, "write", lambda _fd, _value: 0)
    try:
        with pytest.raises(OSError, match="stopped"):
            tool._write_all(descriptor, b"complete")
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("failure_target", ["events.jsonl", "events.log"])
def test_append_event_rolls_back_both_files_after_partial_disk_failure(tmp_path, monkeypatch, failure_target):
    tool = load_module()
    state = tmp_path / "state"
    tool.append_event(state, "plan", "ok", "a" * 64, {"fixture": 1})
    paths = (state / "events.jsonl", state / "events.log")
    before = {path.name: path.read_bytes() for path in paths}
    real_write = os.write
    failed = False

    def failing_write(fd, value):
        nonlocal failed
        target = Path(os.readlink(f"/proc/self/fd/{fd}")).name
        if target == failure_target and not failed:
            failed = True
            real_write(fd, bytes(value[:5]))
            raise OSError(errno.ENOSPC, "synthetic full disk")
        return real_write(fd, value)

    monkeypatch.setattr(tool.os, "write", failing_write)
    with pytest.raises(OSError, match="synthetic full disk"):
        tool.append_event(state, "apply", "failed", "a" * 64, {"fixture": 2})
    assert failed
    assert {path.name: path.read_bytes() for path in paths} == before

    monkeypatch.setattr(tool.os, "write", real_write)
    tool.append_event(state, "verify", "ok", "a" * 64, {"fixture": 3})
    events = [json.loads(line) for line in paths[0].read_text().splitlines()]
    assert [event["command"] for event in events] == ["plan", "verify"]


def test_receipt_audit_failure_leaves_no_published_success_receipt(tmp_path, monkeypatch):
    tool = load_module()
    lock = {"fixture": "value"}
    monkeypatch.setattr(tool, "append_event", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("audit failed")))
    with pytest.raises(OSError, match="audit failed"):
        tool.receipt(tmp_path / "state", "verify", lock, "success", {"fixture": "safe"})
    assert not list((tmp_path / "state").glob("*.json"))
    assert not list((tmp_path / "state").glob("*.pending"))


def test_receipt_event_write_failure_rolls_back_without_success_receipt(tmp_path, monkeypatch):
    tool = load_module()
    original = tool._write_all
    def fail_event_write(descriptor, output):
        if Path(os.readlink(f"/proc/self/fd/{descriptor}")).name == "events.jsonl":
            raise OSError(errno.ENOSPC, "synthetic audit disk failure")
        original(descriptor, output)
    monkeypatch.setattr(tool, "_write_all", fail_event_write)
    with pytest.raises(OSError, match="audit disk failure"):
        tool.receipt(tmp_path / "state", "verify", {"fixture": "value"}, "success", {"fixture": "safe"})
    state = tmp_path / "state"
    assert not list(state.glob("verify-*.json"))
    assert not (state / "events.jsonl").exists() and not (state / "events.log").exists()


def test_receipt_publish_failure_rolls_back_audit_chain(tmp_path, monkeypatch):
    tool = load_module()
    monkeypatch.setattr(tool.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("publish failed")))
    with pytest.raises(OSError, match="publish failed"):
        tool.receipt(tmp_path / "state", "verify", {"fixture": "value"}, "success", {"fixture": "safe"})
    state = tmp_path / "state"
    assert not (state / "events.jsonl").exists() and not (state / "events.log").exists()
    assert not list(state.glob("*.json"))


def test_verify_release_audits_success_and_failure_without_source_paths(tmp_path):
    tool = load_module()
    source = tmp_path / "release"; source.mkdir(); (source / "compose.yaml").write_text("services: {}\n")
    state = tmp_path / "state"
    digest = tool.tree_hash(source)
    good = SimpleNamespace(manifest=str(tool.DEFAULT_MANIFEST), app="harbinger", source=str(source), archive=None,
                           expected_sha256=digest, receipt_dir=str(state))
    assert tool.command_verify_release(good) == 0
    bad = SimpleNamespace(**{**good.__dict__, "expected_sha256": "f" * 64})
    with pytest.raises(tool.TeamEnvError, match="hash does not match"):
        tool.command_verify_release(bad)
    events = [json.loads(line) for line in (state / "events.jsonl").read_text().splitlines()]
    receipts = [json.loads(path.read_text()) for path in state.glob("verify-release-*.json")]
    assert [event["status"] for event in events] == ["success", "failed"]
    assert sorted(value["status"] for value in receipts) == ["failed", "success"]
    assert str(source) not in (state / "events.jsonl").read_text()


def test_verify_release_audits_local_read_failure(tmp_path, monkeypatch):
    tool = load_module()
    archive = tmp_path / "release.tar.gz"
    archive.write_bytes(b"synthetic release")
    state = tmp_path / "state"
    args = SimpleNamespace(
        manifest=str(tool.DEFAULT_MANIFEST), app="harbinger", source=None,
        archive=str(archive), expected_sha256="a" * 64, receipt_dir=str(state),
    )
    monkeypatch.setattr(tool, "file_hash", lambda _path: (_ for _ in ()).throw(OSError("synthetic read failure")))
    with pytest.raises(OSError, match="synthetic read failure"):
        tool.command_verify_release(args)
    events = [json.loads(line) for line in (state / "events.jsonl").read_text().splitlines()]
    assert len(events) == 1 and events[0]["command"] == "verify-release" and events[0]["status"] == "failed"


def test_concurrent_appenders_preserve_one_valid_chain(tmp_path):
    state = tmp_path / "state"
    code = """
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location('team_env_setup_child', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.append_event(pathlib.Path(sys.argv[2]), 'parallel', 'success', 'a' * 64, {'worker': int(sys.argv[3])})
"""
    def append(worker):
        return subprocess.run([sys.executable, "-c", code, str(TOOL), str(state), str(worker)], capture_output=True, text=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(append, range(8)))
    assert all(result.returncode == 0 for result in results)
    events = [json.loads(line) for line in (state / "events.jsonl").read_text().splitlines()]
    assert len(events) == 8 and {event["detail"]["worker"] for event in events} == set(range(8))
    previous = ""
    for event in events:
        observed = event.pop("event_sha256")
        assert event["previous_sha256"] == previous and observed == load_module().sha256_json(event)
        previous = observed
    assert (state / ".events.lock").stat().st_mode & 0o777 == 0o600


def test_manifest_profiles_and_pending_lock_include_reviewed_packages(tmp_path):
    metadata = tmp_path / "metadata.json"; lock = tmp_path / "lock.json"; fixture(metadata)
    tool = load_module(); manifest = tool.load_manifest(tool.DEFAULT_MANIFEST)
    names = tool.profile_packages(manifest, "scribe")
    selected = tool.fixture_metadata(metadata, names, "amd64", manifest)
    tool.write_private_json(lock, tool.lock_payload(manifest, "scribe", selected))
    payload = json.loads(lock.read_text())
    assert payload["status"] == "pending_review"
    assert [entry["name"] for entry in payload["packages"]] == names
    assert {entry["origin"] for entry in payload["packages"]} == {"Kali"}
    assert {entry["suite"] for entry in payload["packages"]} == {"kali-rolling"}
    assert {"tester", "scribe", "harbinger_host", "merlin_host", "both"} <= set(manifest["profiles"])
    assert {"docker.io", "docker-cli", "docker-compose"} <= set(tool.profile_packages(manifest, "both"))


def test_plan_is_read_only_and_review_binds_exact_lock(tmp_path):
    lock, review = approved_lock(tmp_path)
    absent = tmp_path / "not-created"
    result = run("plan", "--lock", str(lock), "--review", str(review), "--receipt-dir", str(absent))
    assert result.returncode == 0
    assert not absent.exists()
    assert json.loads(result.stdout)["effects"][0] == "does not create directories"
    lock.write_text(lock.read_text().replace("1.0-1", "1.0-2", 1))
    rejected = run("plan", "--lock", str(lock), "--review", str(review))
    assert rejected.returncode == 2
    assert "does not bind" in rejected.stderr


def test_apply_is_inert_without_apply_and_verify_release_never_fetches(tmp_path):
    lock, review = approved_lock(tmp_path)
    inert = run("apply", "--lock", str(lock), "--review", str(review))
    assert inert.returncode == 2
    assert "explicit --apply" in inert.stderr
    source = tmp_path / "Harbinger"; source.mkdir(); (source / "compose.yaml").write_text("services: {}\n")
    digest = load_module().tree_hash(source)
    receipts = tmp_path / "receipts"
    verified = run("verify-release", "--app", "harbinger", "--source", str(source),
                   "--expected-sha256", digest, "--receipt-dir", str(receipts))
    assert verified.returncode == 0, verified.stderr
    receipt = json.loads(next(receipts.glob("*.json")).read_text())
    assert receipt["input_kind"] == "source" and receipt["sha256"] == digest
    assert os.stat(next(receipts.glob("*.json"))).st_mode & 0o777 == 0o600


def test_verify_requires_exact_dpkg_version_and_copyright(monkeypatch, tmp_path):
    tool = load_module(); lock, review = approved_lock(tmp_path)
    payload = tool.load_lock(lock)
    monkeypatch.setattr(tool, "installed_version", lambda name: "wrong" if name == "git" else "1.0-1")
    with pytest.raises(tool.TeamEnvError, match="version does not match"):
        tool.verify_packages(payload)


def test_live_policy_parser_rejects_non_kali_candidate():
    tool = load_module()
    with pytest.raises(tool.TeamEnvError, match="not from native Kali"):
        tool.parse_policy("Candidate: 1.0\n  500 https://deb.example stable/main amd64 Packages\n", "docker.io", "kali-rolling", ("https://http.kali.org/kali",))
    with pytest.raises(tool.TeamEnvError, match="not from native Kali"):
        tool.parse_policy("Candidate: 2.0\n  2.0 500\n  500 https://deb.example stable/main amd64 Packages\n  1.0 500\n  500 https://http.kali.org/kali kali-rolling/main amd64 Packages\n", "docker.io", "kali-rolling", ("https://http.kali.org/kali",))


def test_native_source_gate_accepts_rolling_and_last_snapshot(tmp_path):
    tool = load_module()
    rolling = tmp_path / "rolling"
    (rolling / "sources.list.d").mkdir(parents=True)
    (rolling / "sources.list").write_text(
        "deb https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware\n"
    )
    assert tool.validate_kali_sources(rolling) == (
        "kali-rolling", ("https://http.kali.org/kali",)
    )

    snapshot = tmp_path / "snapshot"
    (snapshot / "sources.list.d").mkdir(parents=True)
    (snapshot / "sources.list").write_text(
        "deb http://mirrors.rit.edu/kali kali-last-snapshot main contrib non-free\n"
    )
    assert tool.validate_kali_sources(snapshot) == (
        "kali-last-snapshot", ("http://mirrors.rit.edu/kali",)
    )


def test_native_source_gate_accepts_current_deb822_mirror_file(tmp_path):
    tool = load_module()
    apt_root = tmp_path / "apt"
    source_dir = apt_root / "sources.list.d"
    mirror = apt_root / "mirrors" / "kali.list"
    source_dir.mkdir(parents=True)
    mirror.parent.mkdir()
    mirror.write_text("http://kali.download/kali\n")
    mirror_uri = "mirror+file://" + str(mirror)
    (source_dir / "kali.sources").write_text(
        "Types: deb\n"
        f"URIs: {mirror_uri}\n"
        "Suites: kali-last-snapshot\n"
        "Components: main contrib non-free non-free-firmware\n"
        "Signed-By: /usr/share/keyrings/kali-archive-keyring.gpg\n"
    )
    assert tool.validate_kali_sources(apt_root) == (
        "kali-last-snapshot", (
            "http://kali.download/kali",
            "mirror+file:/etc/apt/mirrors/kali.list".replace("/etc/apt", str(apt_root)),
        )
    )


@pytest.mark.parametrize("line", [
    "deb https://deb.example/kali kali-rolling main\n",
    "deb-src https://http.kali.org/kali kali-rolling main\n",
    "deb [trusted=yes] https://http.kali.org/kali kali-rolling main\n",
    "deb https://http.kali.org/kali kali-experimental main\n",
    "deb https://http.kali.org/kali kali-rolling main unsupported\n",
])
def test_native_source_gate_rejects_unapproved_legacy_sources(tmp_path, line):
    tool = load_module()
    (tmp_path / "sources.list.d").mkdir()
    (tmp_path / "sources.list").write_text(line)
    with pytest.raises(tool.TeamEnvError, match="APT source"):
        tool.validate_kali_sources(tmp_path)


def test_native_source_gate_rejects_mixed_suite_and_unsafe_mirror(tmp_path):
    tool = load_module()
    (tmp_path / "sources.list.d").mkdir()
    (tmp_path / "sources.list").write_text(
        "deb https://http.kali.org/kali kali-rolling main\n"
        "deb http://mirrors.rit.edu/kali kali-last-snapshot main\n"
    )
    with pytest.raises(tool.TeamEnvError, match="one supported Kali suite"):
        tool.validate_kali_sources(tmp_path)

    apt_root = tmp_path / "deb822"
    source_dir = apt_root / "sources.list.d"
    mirrors = apt_root / "mirrors"
    source_dir.mkdir(parents=True)
    mirrors.mkdir()
    target = tmp_path / "outside-mirror"
    target.write_text("http://kali.download/kali\n")
    (mirrors / "kali.list").symlink_to(target)
    (source_dir / "kali.sources").write_text(
        "Types: deb\n"
        f"URIs: mirror+file://{mirrors / 'kali.list'}\n"
        "Suites: kali-last-snapshot\n"
        "Components: main\n"
        "Signed-By: /usr/share/keyrings/kali-archive-keyring.gpg\n"
    )
    with pytest.raises(tool.TeamEnvError, match="unsafe"):
        tool.validate_kali_sources(apt_root)


def test_native_source_gate_rejects_unsafe_deb822_fields(tmp_path):
    tool = load_module()
    source_dir = tmp_path / "sources.list.d"
    source_dir.mkdir()
    (source_dir / "kali.sources").write_text(
        "Types: deb\n"
        "URIs: https://http.kali.org/kali\n"
        "Suites: kali-last-snapshot\n"
        "Components: main\n"
        "Signed-By: /usr/share/keyrings/kali-archive-keyring.gpg\n"
        "Trusted: yes\n"
    )
    with pytest.raises(tool.TeamEnvError, match="unsupported field"):
        tool.validate_kali_sources(tmp_path)


def test_policy_parser_accepts_only_the_validated_snapshot_origin():
    tool = load_module()
    policy = (
        "Candidate: 27.5.1+dfsg4-1\n"
        "  27.5.1+dfsg4-1 500\n"
        "     500 http://mirrors.rit.edu/kali kali-last-snapshot/main amd64 Packages\n"
    )
    origins = ("http://mirrors.rit.edu/kali",)
    assert tool.parse_policy(policy, "docker.io", "kali-last-snapshot", origins) == (
        "27.5.1+dfsg4-1", "main"
    )
    assert tool.exact_version_available(
        policy, "27.5.1+dfsg4-1", "kali-last-snapshot", "main", origins
    )
    assert not tool.exact_version_available(
        policy, "27.5.1+dfsg4-1", "kali-last-snapshot", "main",
        ("https://http.kali.org/kali",),
    )


def test_snapshot_fixture_and_lock_preserve_suite(tmp_path):
    tool = load_module()
    metadata = tmp_path / "metadata.json"
    fixture(metadata, "kali-last-snapshot")
    manifest = tool.load_manifest(tool.DEFAULT_MANIFEST)
    selected = tool.fixture_metadata(
        metadata, tool.profile_packages(manifest, "scribe"), "amd64", manifest
    )
    lock_path = tmp_path / "snapshot.lock.json"
    tool.write_private_json(lock_path, tool.lock_payload(manifest, "scribe", selected))
    loaded = tool.load_lock(lock_path)
    assert loaded["metadata"]["suite"] == "kali-last-snapshot"
    assert {entry["suite"] for entry in loaded["packages"]} == {"kali-last-snapshot"}

    payload = json.loads(lock_path.read_text())
    payload["packages"][0]["suite"] = "kali-rolling"
    tool.write_private_json(lock_path, payload)
    with pytest.raises(tool.TeamEnvError, match="package suite"):
        tool.load_lock(lock_path)


def test_apt_runner_uses_isolated_configuration_and_environment(monkeypatch):
    tool = load_module()
    observed = {}

    class Result:
        returncode = 0

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["environment"] = dict(kwargs["env"])
        observed["config"] = Path(kwargs["env"]["APT_CONFIG"]).read_text()
        return Result()

    monkeypatch.setenv("APT_CONFIG", "/tmp/hostile-apt.conf")
    monkeypatch.setenv("http_proxy", "http://unapproved-proxy.invalid")
    monkeypatch.setenv("DPKG_ROOT", "/tmp/unapproved-root")
    monkeypatch.setattr(tool.subprocess, "run", fake_run)
    tool.apt_run(["apt-get", "update"], check=False)

    assert observed["command"] == ["/usr/bin/apt-get", "update"]
    assert observed["environment"]["APT_CONFIG"] != "/tmp/hostile-apt.conf"
    assert "http_proxy" not in observed["environment"]
    assert "DPKG_ROOT" not in observed["environment"]
    assert 'Dir::Etc::parts "' in observed["config"]
    assert 'Dir::Etc::trusted "' + tool.KALI_KEYRING + '";' in observed["config"]
    assert 'Acquire::AllowInsecureRepositories "false";' in observed["config"]
    assert 'Acquire::http::Proxy "DIRECT";' in observed["config"]


def test_signed_metadata_is_bound_to_validated_origin(monkeypatch, tmp_path):
    tool = load_module()
    keyring = tmp_path / "kali-keyring.gpg"
    keyring.write_bytes(b"fixture")
    verifier = tmp_path / "sqv"
    verifier.write_bytes(b"fixture")
    verifier.chmod(0o755)
    monkeypatch.setattr(tool, "KALI_KEYRING", str(keyring))
    monkeypatch.setattr(tool, "SQV", str(verifier))
    monkeypatch.setattr(tool, "GPGV", str(tmp_path / "missing-gpgv"))
    monkeypatch.setenv("PATH", str(tmp_path / "hostile-path"))
    commands = []
    monkeypatch.setattr(
        tool.subprocess, "run",
        lambda command, **kwargs: commands.append(command) or SimpleNamespace(returncode=0),
    )
    content = (
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
        b"Origin: Kali\nSuite: kali-last-snapshot\n"
        b"Date: Tue, 16 Jun 2026 10:43:36 UTC\n\n"
        b"-----BEGIN PGP SIGNATURE-----\nfixture\n"
    )
    unrelated = tmp_path / "unrelated.example_kali_dists_kali-last-snapshot_InRelease"
    unrelated.write_bytes(content)
    origins = ("http://mirrors.rit.edu/kali",)
    with pytest.raises(tool.TeamEnvError, match="No verified official Kali"):
        tool.signed_kali_release_metadata(tmp_path, "kali-last-snapshot", origins)

    approved = tmp_path / "mirrors.rit.edu_kali_dists_kali-last-snapshot_InRelease"
    approved.write_bytes(content)
    metadata = tool.signed_kali_release_metadata(tmp_path, "kali-last-snapshot", origins)
    assert metadata["release_file"] == str(approved)
    assert commands[-1][0] == str(verifier)


def test_signed_metadata_rejects_replayed_rolling_release(monkeypatch, tmp_path):
    tool = load_module()
    keyring = tmp_path / "keyring.gpg"; keyring.write_bytes(b"fixture")
    verifier = tmp_path / "sqv"; verifier.write_bytes(b"fixture"); verifier.chmod(0o755)
    monkeypatch.setattr(tool, "KALI_KEYRING", str(keyring))
    monkeypatch.setattr(tool, "SQV", str(verifier))
    monkeypatch.setattr(tool, "GPGV", str(tmp_path / "missing-gpgv"))
    monkeypatch.setattr(tool.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    release = tmp_path / "http.kali.org_kali_dists_kali-rolling_InRelease"
    release.write_bytes(
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
        b"Origin: Kali\nSuite: kali-rolling\n"
        b"Date: Tue, 16 Jun 2026 10:43:36 UTC\n\n"
        b"-----BEGIN PGP SIGNATURE-----\nfixture\n"
    )
    with pytest.raises(tool.TeamEnvError, match="stale"):
        tool.signed_kali_release_metadata(
            tmp_path, "kali-rolling", ("https://http.kali.org/kali",)
        )


def test_refresh_rejects_success_with_index_warning(monkeypatch):
    tool = load_module()
    monkeypatch.setattr(tool.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        tool, "validate_kali_sources",
        lambda: ("kali-rolling", ("https://http.kali.org/kali",)),
    )
    monkeypatch.setattr(
        tool, "apt_run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="", stderr="W: Failed to fetch a signed index\n"
        ),
    )
    with pytest.raises(tool.TeamEnvError, match="warnings"):
        tool.refresh_signed_kali_metadata()


def test_refresh_allows_only_fixed_keyring_deprecation_notice(monkeypatch):
    tool = load_module()
    origins = ("http://mirrors.rit.edu/kali",)
    monkeypatch.setattr(tool.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tool, "validate_kali_sources", lambda: ("kali-last-snapshot", origins))
    monkeypatch.setattr(
        tool, "apt_run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="",
            stderr=(
                "W: http://mirrors.rit.edu/kali/dists/kali-last-snapshot/InRelease: "
                "Loading /usr/share/keyrings/kali-archive-keyring.gpg from deprecated "
                "option Dir::Etc::Trusted\n"
            ),
        ),
    )
    checked = []
    monkeypatch.setattr(
        tool, "signed_kali_release_metadata",
        lambda lists, suite, selected: checked.append((lists, suite, selected)) or {},
    )
    assert tool.refresh_signed_kali_metadata() == ("kali-last-snapshot", origins)
    assert checked[0][1:] == ("kali-last-snapshot", origins)


def test_tester_lock_keeps_unavailable_optional_package_visible(tmp_path):
    tool = load_module(); manifest = tool.load_manifest(tool.DEFAULT_MANIFEST)
    names = tool.profile_packages(manifest, "tester")
    metadata = tmp_path / "metadata.json"
    payload = {"schema": "cptc.team-env.synthetic-apt.v1", "trusted": True, "architecture": "amd64", "origin": "Kali",
               "suite": "kali-rolling", "source_metadata_sha256": "b" * 64,
               "packages": {name: {"version": "1.0-1", "component": "main"} for name in names if name != "zaproxy"}}
    metadata.write_text(json.dumps(payload))
    selected = tool.fixture_metadata(metadata, names, "amd64", manifest)
    lock = tool.lock_payload(manifest, "tester", selected)
    review = tool.review_payload(lock, "fixture-reviewer")
    plan = tool.plan_data(manifest, lock, review)
    assert plan["optional_unavailable"] == ["zaproxy"]
    assert len(plan["required"]) == len(names) - 1


def test_refresh_runs_only_one_explicit_apt_update(monkeypatch):
    tool = load_module(); calls = []
    class Result:
        returncode = 0
        stdout = ""
        stderr = ""
    monkeypatch.setattr(tool.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tool, "validate_kali_sources", lambda: ("kali-rolling", ("https://http.kali.org/kali",)))
    monkeypatch.setattr(tool, "signed_kali_release_metadata", lambda _, suite, origins: {"suite": suite})
    monkeypatch.setattr(tool, "apt_run", lambda command, **kwargs: calls.append((command, kwargs)) or Result())
    tool.refresh_signed_kali_metadata()
    assert calls == [(["apt-get", "update"], {"text": True, "capture_output": True, "check": False})]


def test_private_lock_symlink_is_rejected(tmp_path):
    tool = load_module(); target = tmp_path / "target.json"; target.write_text("{}")
    target.chmod(0o600); link = tmp_path / "lock.json"; link.symlink_to(target)
    with pytest.raises(tool.TeamEnvError, match="symlinked"):
        tool.load_lock(link)


def test_apply_uses_one_exact_pinned_apt_install_after_atomic_preflight(monkeypatch, tmp_path):
    tool = load_module(); lock, review = approved_lock(tmp_path)
    calls = []

    class Result:
        returncode = 0
        stdout = ""

    monkeypatch.setattr(tool, "kali_host", lambda: True)
    monkeypatch.setattr(tool, "dpkg_architecture", lambda: "amd64")
    monkeypatch.setattr(tool.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tool, "allowed_private_owners", lambda: {os.getuid(), 0})
    monkeypatch.setattr(tool, "validate_kali_sources", lambda: ("kali-rolling", ("https://http.kali.org/kali",)))
    monkeypatch.setattr(tool, "signed_kali_release_metadata", lambda _, suite, origins: {"suite": suite, "source_metadata_sha256": "a" * 64})
    monkeypatch.setattr(tool, "exact_version_available", lambda *values: True)
    monkeypatch.setattr(tool, "apt_run", lambda command, **kwargs: calls.append((command, kwargs)) or Result())
    args = SimpleNamespace(manifest=str(tool.DEFAULT_MANIFEST), lock=str(lock), review=str(review), apply=True,
                           receipt_dir=str(tmp_path / "receipts"))
    assert tool.command_apply(args) == 0
    assert calls == [(["apt-cache", "policy", name], {"text": True, "capture_output": True, "check": False}) for name in ("jq", "unzip", "age", "python3", "python3-venv", "git")] + [
        (["apt-get", "install", "--assume-yes", "--no-install-recommends", "jq=1.0-1", "unzip=1.0-1", "age=1.0-1", "python3=1.0-1", "python3-venv=1.0-1", "git=1.0-1"], {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "check": False})]
    assert (tmp_path / "receipts" / "events.jsonl").is_file()
    assert (tmp_path / "receipts" / "events.log").is_file()
