"""Exercise the registry bridge, real workers, and owned public evidence boundaries."""

import asyncio
import json
import os
import sqlite3
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_live_capabilities import application
from test_tool_soap_capabilities import fake_nuclei, template_file

from fieldkit.core.agent import (
    MAX_RESPONSE,
    FieldkitAgent,
    FieldkitAgentError,
    Job,
    decode_json,
    paginate,
    read_json,
)
from fieldkit.core.vault import Vault


def saved_job(agent, tmp_path, report):
    directory = agent.output / ("job-" + "1" * 32)
    run = directory / "runs" / "fixture"
    run.mkdir(parents=True)
    (run / "report.json").write_text(json.dumps(report))
    job = Job(directory.name, "web/header-review", directory, status="completed")
    agent.jobs[job.id] = job
    agent._persist(job)
    return job, run


def test_registry_python_api_matches_options_and_public_errors(tmp_path):
    agent = FieldkitAgent(tmp_path)
    assert not agent.output.exists()
    for name, module in agent.registry.items():
        info = agent.module_info(name)
        options = info["input_schema"]["properties"]["options"]
        assert set(options["properties"]) == {o.name for o in module.options} - {"OUTPUT"}
        assert options["additionalProperties"] is False
        assert "tool" not in info
    result = agent.module_info("web/header-review")
    assert result["module"] == "web/header-review"
    assert len(agent.list_modules()["modules"]) == len(agent.registry)
    with pytest.raises(FieldkitAgentError, match="Unknown job"):
        agent.job_status("../../private")


@pytest.mark.parametrize(
    "options",
    [
        {"OUTPUT": "elsewhere"},
        {"TIMEOUT": True},
        {"TIMEOUT": float("nan")},
        {"CONCURRENCY": False},
        {"TARGETS": "https://example.test"},
        {"TARGETS": [1]},
        {"TARGETS": ["a"] * 1001},
        {"TARGETS_FILE": "a" * 8193},
        {"TARGETS_FILE": "bad\0input"},
        {"unknown-secret-name": "private-value"},
    ],
)
def test_invalid_options_do_not_launch_or_echo_inputs(tmp_path, options):
    agent = FieldkitAgent(tmp_path)
    with pytest.raises(FieldkitAgentError) as error:
        asyncio.run(agent.run("web/header-review", options=options))
    assert "private-value" not in str(error.value)
    assert "unknown-secret-name" not in str(error.value)
    assert not agent.output.exists()


def test_private_settings_argv_limits_and_close(tmp_path, monkeypatch):
    observed = []
    started = asyncio.Event()

    async def fake_process(argv, **kwargs):
        configuration = Path(argv[-1])
        observed.append((argv, json.loads(configuration.read_text())))
        assert stat.S_IMODE(configuration.stat().st_mode) == 0o600
        assert stat.S_IMODE(configuration.parent.stat().st_mode) == 0o700
        started.set()
        await kwargs["cancel"].wait()
        result = kwargs["result"]
        result.reason, result.returncode = "cancelled", 130
        result.stdout.extend(b"Bearer private-worker-secret")

    monkeypatch.setattr("fieldkit.core.agent.run_process", fake_process)

    async def exercise():
        agent = FieldkitAgent(tmp_path, max_jobs=1)
        run = await agent.run("web/header-review", options={"PROFILE": "private-profile-name"})
        await asyncio.wait_for(started.wait(), 1)
        with pytest.raises(FieldkitAgentError, match="Active job limit"):
            await agent.run("web/header-review")
        await agent.close()
        status = agent.job_status(run["job_id"])
        assert status["status"] == "cancelled"
        directory = agent.jobs[run["job_id"]].directory
        assert not (directory / ".settings.json").exists()
        assert stat.S_IMODE((directory / "private-process.log").stat().st_mode) == 0o600
        assert "private-worker-secret" not in json.dumps(status)
        with pytest.raises(FieldkitAgentError, match="closing"):
            await agent.start_job("web/header-review", {})
        return agent

    agent = asyncio.run(exercise())
    argv, configuration = observed[0]
    assert "private-profile-name" not in " ".join(argv)
    assert configuration["settings"]["PROFILE"] == "private-profile-name"
    assert Path(configuration["settings"]["OUTPUT"]).is_relative_to(agent.output)
    restored = FieldkitAgent(tmp_path)
    assert restored.list_jobs()["jobs"][0]["status"] == "cancelled"


def test_real_offline_worker_preserves_private_vault_and_redacted_report(tmp_path):
    source = tmp_path / "traffic.har"
    source.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "https://fixture.test/login",
                                "headers": [
                                    {"name": "Authorization", "value": "Bearer vault-secret"}
                                ],
                                "postData": {
                                    "mimeType": "application/json",
                                    "text": '{"password":"vault-password"}',
                                },
                            },
                            "response": {"status": 200, "headers": [], "content": {"text": "ok"}},
                        }
                    ]
                }
            }
        )
    )

    async def exercise():
        agent = FieldkitAgent(tmp_path)
        try:
            run = await agent.run(
                "evidence/ingest",
                options={"INPUT": [source.name], "FORMAT": "har", "DATABASE": "vault.sqlite"},
                wait_seconds=20,
            )
            assert run["status"] == "completed", run
            assert run["report_available"]
            report = agent.read_report(run["job_id"], section="results")
            records = agent.vault_records("vault.sqlite", "request")
            assert records["total"] == 1
            public = json.dumps([run, report, records])
            assert "vault-password" not in public and "vault-secret" not in public
            with Vault(tmp_path / "vault.sqlite", create=False) as vault:
                private = json.dumps(vault.records("request", private=True))
                assert "vault-password" in private and "vault-secret" in private
            assert not list(agent.output.glob("*/.settings.json"))
        finally:
            await agent.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("deadline", [False, True])
def test_real_http_job_cancel_and_deadline_save_partial_report(tmp_path, deadline):
    release = threading.Event()

    def handler(*args):
        release.wait(10)
        return 200, {"Content-Type": "text/html"}, b"fixture"

    with application(handler) as (target, seen):

        async def exercise():
            agent = FieldkitAgent(tmp_path, job_timeout=2 if deadline else 10)
            try:
                run = await agent.run(
                    "web/header-review",
                    options={"TARGETS": [target], "RATE": 0, "TIMEOUT": 9, "RETRIES": 0},
                )
                async with asyncio.timeout(5):
                    while not seen:
                        await asyncio.sleep(0.01)
                if deadline:
                    await asyncio.wait_for(agent.jobs[run["job_id"]].task, 5)
                    status = agent.job_status(run["job_id"])
                else:
                    status = await agent.cancel_job(run["job_id"])
                assert status["status"] == ("timed_out" if deadline else "cancelled")
                assert status["report_available"]
                report = agent.read_report(run["job_id"])
                assert report["summary"]["completed"] is False
                errors = agent.read_report(run["job_id"], "errors")["items"]
                assert any(e["error"] == "interrupted" for e in errors)
                assert len(seen) == 1
            finally:
                release.set()
                await agent.close()

        asyncio.run(exercise())


def test_worker_output_cap_is_separate_from_reports(tmp_path, monkeypatch):
    executable = tmp_path / "noisy-worker"
    executable.write_text("#!/bin/sh\nhead -c 4096 /dev/zero\nsleep 10\n")
    executable.chmod(0o700)
    monkeypatch.setattr("fieldkit.core.agent.sys", SimpleNamespace(executable=str(executable)))

    async def exercise():
        agent = FieldkitAgent(tmp_path, max_output=1024)
        try:
            job = await agent.start_job("web/header-review", {})
            await asyncio.wait_for(job.task, 3)
            assert job.status == "failed"
            assert job.process["reason"] == "output_limit"
            assert (job.directory / "private-process.log").stat().st_size <= 1025
        finally:
            await agent.close()

    asyncio.run(exercise())


def test_cancel_worker_cleans_up_nested_tool_and_grandchild(tmp_path):
    pid_file = tmp_path / "tool-pids.json"
    extra = (
        "import os,signal,subprocess\n"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
        "child=subprocess.Popen([sys.executable,'-c',"
        "'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)'])\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(json.dumps([os.getpid(),child.pid]))\n"
        "time.sleep(30)\n"
    )

    def alive(pid):
        process = Path(f"/proc/{pid}/stat")
        return process.exists() and process.read_text().rsplit(")", 1)[-1].split()[0] != "Z"

    async def exercise():
        agent = FieldkitAgent(tmp_path)
        try:
            job = await agent.start_job(
                "web/nuclei",
                {
                    "TARGETS": ["http://127.0.0.1:9"],
                    "EXECUTE": True,
                    "RATE": 1,
                    "BINARY": fake_nuclei(tmp_path, extra),
                    "TEMPLATES": [template_file(tmp_path)],
                },
            )
            async with asyncio.timeout(5):
                while not pid_file.exists():
                    await asyncio.sleep(0.01)
            pids = json.loads(pid_file.read_text())
            assert all(alive(pid) for pid in pids)
            status = await asyncio.wait_for(agent.cancel_job(job.id), 3)
            assert status["status"] == "cancelled" and status["report_available"]
            assert all(not alive(pid) for pid in pids)
            assert agent.read_report(job.id)["summary"]["completed"] is False
            results = agent.read_report(job.id, "results")["items"]
            assert len(results) == 1 and results[0]["kind"] == "nuclei_observation"
        finally:
            await agent.close()

    asyncio.run(exercise())


def test_restart_marks_unfinished_jobs_abandoned_and_ignores_links(tmp_path):
    agent = FieldkitAgent(tmp_path)
    job, _ = saved_job(agent, tmp_path, {})
    job.status = "running"
    agent._persist(job)
    linked = agent.output / ("job-" + "2" * 32)
    linked.symlink_to(job.directory, target_is_directory=True)
    malformed = agent.output / ("job-" + "3" * 32)
    malformed.mkdir()
    (malformed / "job.json").write_text("malformed")
    restored = FieldkitAgent(tmp_path)
    assert len(restored.jobs) == 1
    assert restored.job_status(job.id)["status"] == "abandoned"


@pytest.mark.parametrize("started", [False, True])
def test_task_cancellation_persists_terminal_state_and_releases_capacity(
    tmp_path, monkeypatch, started
):
    ready = asyncio.Event()

    async def fake_process(argv, **kwargs):
        ready.set()
        try:
            await asyncio.sleep(10)
        finally:
            kwargs["result"].reason = "cancelled"

    monkeypatch.setattr("fieldkit.core.agent.run_process", fake_process)

    async def exercise():
        agent = FieldkitAgent(tmp_path, max_jobs=1)
        job = await agent.start_job("web/header-review", {})
        if started:
            await asyncio.wait_for(ready.wait(), 1)
        job.task.cancel()
        await agent.close()
        assert job.status == "cancelled"
        assert not (job.directory / ".settings.json").exists()
        assert json.loads((job.directory / "job.json").read_text())["status"] == "cancelled"

    asyncio.run(exercise())


def test_output_overflow_with_zero_exit_is_still_a_failed_job(tmp_path, monkeypatch):
    async def fake_process(argv, **kwargs):
        kwargs["result"].reason, kwargs["result"].returncode = "output_limit", 0

    monkeypatch.setattr("fieldkit.core.agent.run_process", fake_process)

    async def exercise():
        agent = FieldkitAgent(tmp_path)
        job = await agent.start_job("web/header-review", {})
        await job.task
        assert job.status == "failed" and job.process["reason"] == "output_limit"
        await agent.close()

    asyncio.run(exercise())


def test_report_paging_redaction_and_malformed_sections(tmp_path):
    agent = FieldkitAgent(tmp_path)
    job, run = saved_job(
        agent,
        tmp_path,
        {"results": [{"password": "private"}, {"id": "next"}, {"id": "last"}]},
    )
    page = agent.read_report(job.id, "results", offset=1, limit=1)
    assert page["items"] == [{"id": "next"}] and page["next_offset"] == 2
    assert agent.read_report(job.id, "results")["items"][0]["password"] == "[REDACTED]"
    (run / "report.json").write_text('{"results":42}')
    with pytest.raises(FieldkitAgentError, match="Malformed report"):
        agent.read_report(job.id)
    assert "report_read_error" in agent.job_status(job.id)


def test_evidence_reads_require_owned_redacted_sidecars(tmp_path):
    agent = FieldkitAgent(tmp_path)
    entries = [
        {"id": "public", "file": "evidence/public.json"},
        {
            "id": "raw",
            "file": "/private/profile.json",
            "private_raw": True,
            "body_base64": "cmF3LWNyZWRlbnRpYWw=",
            "body": "opaque-private-credential",
        },
        {"id": "traversal", "file": "evidence/../../private.json"},
        {"id": "absolute", "file": str(tmp_path / "secret.json")},
        {"id": "linked", "file": "evidence/link.json"},
        {"id": "large", "file": "evidence/large.json"},
        {"id": "large-raw", "private_raw": True, "detail": "a" * 100000},
        {"id": "raw-string", "private_raw": "true", "body_base64": "cmF3LWNyZWRlbnRpYWw="},
    ]
    job, run = saved_job(agent, tmp_path, {"evidence": entries})
    evidence = run / "evidence"
    evidence.mkdir()
    (evidence / "public.json").write_text('{"Authorization":"Bearer raw-secret"}')
    outside = tmp_path / "secret.json"
    outside.write_text('{"password":"raw-secret"}')
    (evidence / "link.json").symlink_to(outside)
    (evidence / "large.json").write_text(json.dumps({"value": "a" * 100000}))
    read = agent.read_evidence(job.id, "public")
    assert read["record"]["Authorization"] == "[REDACTED]" and read["content_exposed"]
    assert agent.read_evidence(job.id, "raw")["content_exposed"] is False
    assert "body_base64" not in agent.read_evidence(job.id, "raw")["evidence"]
    assert "body_base64" not in agent.read_evidence(job.id, "raw-string")["evidence"]
    page = json.dumps(agent.read_report(job.id, "evidence"))
    assert "opaque-private-credential" not in page and "cmF3LWNyZWRlbnRpYWw=" not in page
    assert agent.read_evidence(job.id, "large")["content_exposed"] is False
    raw = agent.read_evidence(job.id, "large-raw")
    assert raw["content_exposed"] is False and len(json.dumps(raw).encode()) < MAX_RESPONSE
    for identifier in ("traversal", "absolute", "linked"):
        with pytest.raises(FieldkitAgentError):
            agent.read_evidence(job.id, identifier)


def test_json_read_limits_symlinks_devices_and_depth(tmp_path):
    path = tmp_path / "data.json"
    path.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        read_json(link)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(FieldkitAgentError, match="regular file"):
        read_json(fifo)
    with pytest.raises(FieldkitAgentError, match="read limit"):
        read_json(path, 1)
    with pytest.raises(FieldkitAgentError, match="depth/node"):
        decode_json("[" * 50 + "0" + "]" * 50)
    with pytest.raises(FieldkitAgentError, match="Malformed"):
        decode_json("[" * 10000)
    with pytest.raises(FieldkitAgentError, match="nonfinite"):
        decode_json('{"value":NaN}')


def test_vault_reads_are_readonly_confined_and_bounded(tmp_path):
    database = tmp_path / "vault.sqlite"
    with Vault(database) as vault:
        vault.put("request", {"password": "private"}, private={"value": "private-raw"})
        vault.put("request", {"id": "second"})
    before = (database.stat().st_mtime_ns, database.stat().st_mode, database.read_bytes())
    agent = FieldkitAgent(tmp_path)
    first = agent.vault_records("vault.sqlite", "request", 0, 1)
    assert first["total"] == 2 and first["next_offset"] == 1
    public = json.dumps(agent.vault_records("vault.sqlite"))
    assert "private-raw" not in public and '"private"' not in public
    assert before == (database.stat().st_mtime_ns, database.stat().st_mode, database.read_bytes())
    assert agent.vault_records("vault.sqlite", "request' OR 1=1--")["total"] == 0
    link = tmp_path / "vault-link.sqlite"
    link.symlink_to(database)
    with pytest.raises(FieldkitAgentError, match="inside the workspace"):
        agent.vault_records(str(link))
    with pytest.raises(FieldkitAgentError):
        agent.vault_records("/etc/passwd")
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE records SET public_json=?", ("[" * 60 + "0" + "]" * 60,))
    with pytest.raises(FieldkitAgentError, match="depth/node"):
        agent.vault_records("vault.sqlite")


def test_complete_bounded_pages_can_be_followed_without_truncation():
    rows = [{"id": str(n), "value": "a" * 31000} for n in range(4)]
    first = paginate(rows, 0, 4)
    assert len(json.dumps(first).encode()) < MAX_RESPONSE
    assert first["next_offset"] == 2
    second = paginate(rows, first["next_offset"], 4)
    assert [r["id"] for r in first["items"] + second["items"]] == ["0", "1", "2", "3"]
    omitted = paginate([{"id": "huge", "value": "a" * 100000}], 0, 1)
    assert omitted["items"][0]["entry_omitted"]


def test_real_comparison_report_preserves_change_types(tmp_path):
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_text(json.dumps({"results": [{"id": "old", "url": "https://fixture.test/old"}]}))
    after.write_text(json.dumps({"results": [{"id": "new", "url": "https://fixture.test/new"}]}))

    async def exercise():
        agent = FieldkitAgent(tmp_path)
        try:
            status = await agent.run(
                "results/compare",
                options={"BEFORE": before.name, "AFTER": after.name},
                wait_seconds=20,
            )
            assert status["status"] == "completed"
            assert "report_read_error" not in status
            summary = agent.read_report(status["job_id"])["summary"]
            assert summary["counts"]["results"] == 2 and summary["completed"]
            records = agent.read_report(status["job_id"], "results")["items"]
            assert {r["change"] for r in records} == {"added", "removed"}
            assert {r["record"]["url"] for r in records} == {
                "https://fixture.test/old",
                "https://fixture.test/new",
            }
        finally:
            await agent.close()

    asyncio.run(exercise())


def test_restore_retains_recent_jobs_instead_of_uuid_order(tmp_path, monkeypatch):
    agent = FieldkitAgent(tmp_path)
    identifiers = ["f" * 32, "b" * 32, "0" * 32]
    for number, identifier in enumerate(identifiers):
        directory = agent.output / ("job-" + identifier)
        directory.mkdir(parents=True)
        agent._persist(Job(directory.name, "web/header-review", directory, status="completed"))
        os.utime(directory, (number + 100, number + 100))
    monkeypatch.setattr("fieldkit.core.agent.MAX_SAVED_JOBS", 2)
    restored = FieldkitAgent(tmp_path)
    assert set(restored.jobs) == {"job-" + i for i in identifiers[1:]}
