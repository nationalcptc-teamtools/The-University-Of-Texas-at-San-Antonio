"""Code-mode composition, broker boundaries, hard deadlines and process cleanup."""

import asyncio
import json
import os
import sys

import pytest

from fieldkit.core.agent import MAX_RESPONSE, FieldkitAgent, FieldkitAgentError
from fieldkit.core.code_api import API, search_reference
from fieldkit.core.codemode import CodeMode


def execute(tmp_path, code, **kwargs):
    async def exercise():
        agent = FieldkitAgent(tmp_path)
        runtime = CodeMode(agent)
        try:
            return await runtime.execute(code, **kwargs)
        finally:
            await runtime.close()
            await agent.close()

    return asyncio.run(exercise())


def test_reference_search_follows_registry_and_real_signatures(tmp_path):
    agent = FieldkitAgent(tmp_path)
    for method in API:
        entry = search_reference(agent, "fieldkit." + method)["entries"][0]
        assert entry["signature"].startswith("fieldkit." + method + "(")
        assert entry["example"]
    info = search_reference(agent, "web/header-review")["entries"][0]
    assert info == agent.module_info("web/header-review")
    assert "OUTPUT" not in info["input_schema"]["properties"]["options"]["properties"]
    assert len(search_reference(agent, "web", limit=2)["entries"]) == 2
    assert search_reference(agent, "no-such-reference") == {
        "query": "no-such-reference",
        "entries": [],
        "total": 0,
    }
    agent.registry["new/header-module"] = agent.registry["web/header-review"]
    assert (
        search_reference(agent, "new/header-module")["entries"][0]["module"] == "new/header-module"
    )


@pytest.mark.parametrize("query,limit", [(" ", 1), ("x" * 257, 1), ("run", True), ("run", 11)])
def test_reference_limits(tmp_path, query, limit):
    with pytest.raises(FieldkitAgentError):
        search_reference(FieldkitAgent(tmp_path), query, limit)


def test_full_python_composes_filters_and_returns_selected_data(tmp_path):
    (tmp_path / "input.txt").write_text("workspace input")
    value = execute(
        tmp_path,
        """import math
import sys
from pathlib import Path
names = [row["module"] for row in fieldkit.list_modules("header")["modules"]]
print("modules:", len(names))
print("diagnostic", file=sys.stderr)
result = {"names": names, "computed": math.factorial(5), "cwd": Path("input.txt").read_text()}
""",
    )
    assert value["result"] == {
        "names": ["web/header-review"],
        "computed": 120,
        "cwd": "workspace input",
    }
    assert value["stdout"] == "modules: 1\n"
    assert value["stderr"] == "diagnostic\n"
    assert value["api_calls"] == 1


def test_jobs_survive_calls_but_python_variables_do_not(tmp_path):
    async def exercise():
        agent = FieldkitAgent(tmp_path)
        runtime = CodeMode(agent)
        try:
            first = await runtime.execute("""job = fieldkit.run("web/header-review", {
    "TARGETS": ["http://127.0.0.1:9/"], "DRY_RUN": True}, wait_seconds=5)
local_variable = 123
result = job["job_id"]
""")
            identifier = first["result"]
            assert first["jobs_started"] == [identifier]
            second = await runtime.execute(f"""result = {{
    "status": fieldkit.job_status({identifier!r})["status"],
    "summary": fieldkit.read_report({identifier!r})["summary"],
    "locals_persisted": "local_variable" in globals(),
}}
""")
            assert second["result"]["status"] == "completed"
            assert second["result"]["summary"]["completed"]
            assert second["result"]["locals_persisted"] is False
            restored = FieldkitAgent(tmp_path)
            assert restored.job_status(identifier)["status"] == "completed"
        finally:
            await runtime.close()
            await agent.close()

    asyncio.run(exercise())


def test_broker_redacts_private_records_before_the_script_sees_them(tmp_path):
    async def exercise():
        agent = FieldkitAgent(tmp_path)
        agent.read_report = lambda *args, **kwargs: {
            "items": [{"id": "e-1", "private_raw": True, "payload": "private-hidden-body"}],
            "password": "private-secret-password",
        }
        runtime = CodeMode(agent)
        try:
            result = await runtime.execute("""page = fieldkit.read_report("unused")
result = {"body_visible": "payload" in page["items"][0], "password": page["password"]}
print("Authorization: Bearer private-bearer-value")
""")
            assert result["result"] == {"body_visible": False, "password": "[REDACTED]"}
            assert "private-bearer-value" not in json.dumps(result)
            assert "private-hidden-body" not in json.dumps(result)
        finally:
            await runtime.close()
            await agent.close()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "code,exception",
    [
        ('raise ValueError("private-exception-value")', "ValueError"),
        ('result = "private-syntax-value', "SyntaxError"),
        ('result = fieldkit._job("private-job-id")', "AttributeError"),
        ('result = fieldkit.list_jobs(limit="private-limit")', "APIError"),
        ('result = fieldkit.run("web/header-review", {"OUTPUT": "private-output"})', "APIError"),
        ('result = fieldkit.run("web/header-review", {"TIMEOUT": True})', "APIError"),
        ('result = fieldkit.run("web/header-review", wait_seconds=True)', "APIError"),
        ('result = fieldkit.read_report(unknown="private-arg")', "APIError"),
    ],
)
def test_script_errors_are_actionable_without_echoing_input(tmp_path, code, exception):
    result = execute(tmp_path, code)
    assert result["error"]
    assert result["exception"] == exception
    assert result["line"] == 1
    assert "private-" not in json.dumps(result)
    assert not list(tmp_path.glob("artifacts/mcp/job-*"))


@pytest.mark.parametrize(
    "code",
    [
        "result = object()",
        "result = float('nan')",
        "result = b'bytes'",
        "result = 'a' * 100000",
        "print('a' * 100000)",
        "import os; os.write(1, b'a' * 1000000)",
    ],
)
def test_result_and_stdout_limits_are_bounded(tmp_path, code):
    result = execute(tmp_path, code)
    assert result["error"]
    assert len(json.dumps(result).encode()) <= MAX_RESPONSE


def test_deadline_does_not_block_another_script_or_reference_search(tmp_path):
    async def exercise():
        runtime = CodeMode(FieldkitAgent(tmp_path))
        first = asyncio.create_task(runtime.execute("while True: pass", timeout_seconds=1))
        try:
            await asyncio.sleep(0.1)
            reference = await runtime.call("fieldkit_search_reference", {"query": "run"})
            assert reference["entries"]
            other = await runtime.execute("result = 7")
            assert other["result"] == 7
            timeout = await asyncio.wait_for(first, 3)
            assert timeout["timed_out"]
            assert not runtime.tasks
        finally:
            await runtime.close()

    asyncio.run(exercise())


def test_script_deadline_keeps_and_reports_an_inflight_assessment_job(tmp_path, monkeypatch):
    async def slow_process(argv, **kwargs):
        await kwargs["cancel"].wait()
        kwargs["result"].reason = "cancelled"
        kwargs["result"].returncode = 130

    monkeypatch.setattr("fieldkit.core.agent.run_process", slow_process)

    async def exercise():
        agent = FieldkitAgent(tmp_path)
        runtime = CodeMode(agent)
        try:
            timed_out = await runtime.execute(
                'fieldkit.run("web/header-review", {"DRY_RUN": True}, wait_seconds=20)',
                timeout_seconds=1,
            )
            assert timed_out["timed_out"]
            (identifier,) = timed_out["jobs_started"]
            assert agent.job_status(identifier)["status"] == "running"
            cancelled = await runtime.execute(f"result = fieldkit.cancel_job({identifier!r})")
            assert cancelled["result"]["status"] == "cancelled"
        finally:
            await runtime.close()
            await agent.close()

    asyncio.run(exercise())


def test_script_concurrency_and_shutdown(tmp_path):
    async def exercise():
        runtime = CodeMode(FieldkitAgent(tmp_path, max_jobs=1))
        task = asyncio.create_task(runtime.execute("while True: pass"))
        await asyncio.sleep(0.2)
        with pytest.raises(FieldkitAgentError, match="execution limit"):
            await runtime.execute("result = 1")
        await runtime.close()
        assert task.cancelled()
        assert not runtime.tasks
        with pytest.raises(FieldkitAgentError, match="closing"):
            await runtime.execute("result = 1")

    asyncio.run(exercise())


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups")
def test_cancellation_stops_python_descendants(tmp_path):
    heartbeat = tmp_path / "heartbeat"
    child = (
        "import time\nfrom pathlib import Path\n"
        f"p = Path({str(heartbeat)!r})\n"
        "while True:\n p.write_text(str(time.time_ns()))\n time.sleep(0.01)\n"
    )

    async def exercise():
        runtime = CodeMode(FieldkitAgent(tmp_path))
        task = asyncio.create_task(
            runtime.execute(
                "import subprocess, time\n"
                f"subprocess.Popen([{sys.executable!r}, '-c', {child!r}])\n"
                "time.sleep(30)"
            )
        )
        try:
            async with asyncio.timeout(3):
                while not heartbeat.exists():
                    await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            stamp = heartbeat.read_text()
            await asyncio.sleep(0.1)
            assert heartbeat.read_text() == stamp
        finally:
            await runtime.close()

    asyncio.run(exercise())
