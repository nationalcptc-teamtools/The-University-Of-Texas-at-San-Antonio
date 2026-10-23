"""Exercise the two-tool code-mode contract through real SDK clients and stdio."""

import asyncio
import importlib.util
import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from fieldkit import mcp_server
from fieldkit.core.agent import FieldkitAgent, FieldkitAgentError
from fieldkit.core.codemode import CodeMode

HAS_MCP = importlib.util.find_spec("mcp") is not None
requires_mcp = pytest.mark.skipif(not HAS_MCP, reason="Install Fieldkit's mcp extra")
JOB = "job-" + "1" * 32
TOOLS = {"fieldkit_execute_python", "fieldkit_search_reference"}


class FakeAgent(FieldkitAgent):
    def __init__(self):
        super().__init__(Path.cwd(), output="artifacts/unused-test-jobs")
        self.calls = []

    async def run(self, module, options=None, wait_seconds=0):
        self.calls.append((module, options))
        if options and options.get("TARGETS") == ["raise"]:
            raise ValueError("unregistered-raw-credential-value")
        return self.job_status(JOB)

    def job_status(self, job_id):
        return {"job_id": JOB, "status": "running", "password": "do-not-publish"}

    def list_jobs(self, limit=20):
        return {"jobs": [self.job_status(JOB)]}

    def read_report(self, job_id, section="summary", offset=0, limit=50):
        if job_id != JOB:
            raise ValueError("private-data-in-error")
        return {"job_id": job_id, "section": section, "password": "do-not-publish"}


@requires_mcp
@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_sdk_discovers_code_tools_resources_and_prompt(mode):
    from mcp import Client

    agent = FakeAgent()

    async def exercise():
        async with Client(mcp_server.build_server(agent), mode=mode) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert set(tools) == TOOLS
            assert tools["fieldkit_execute_python"].annotations.open_world_hint is True
            assert tools["fieldkit_search_reference"].annotations.read_only_hint is True
            reference = await client.call_tool("fieldkit_search_reference", {"query": "run"})
            assert reference.structured_content["entries"][0]["signature"].startswith(
                "fieldkit.run("
            )
            result = await client.call_tool(
                "fieldkit_execute_python",
                {"code": 'result = fieldkit.run("web/header-review", {"TARGETS": ["fixture"]})'},
            )
            assert not result.is_error, result.structured_content
            assert result.structured_content["result"]["job_id"] == JOB
            assert result.structured_content["jobs_started"] == [JOB]
            assert result.structured_content["result"]["password"] == "[REDACTED]"
            assert "do-not-publish" not in result.model_dump_json()
            resources = await client.list_resources()
            assert {str(item.uri) for item in resources.resources} == {
                "fieldkit://modules",
                "fieldkit://jobs",
            }
            templates = await client.list_resource_templates()
            assert templates.resource_templates[0].uri_template == "fieldkit://jobs/{job_id}/report"
            catalog = await client.read_resource("fieldkit://modules")
            assert json.loads(catalog.contents[0].text)["modules"]
            jobs = await client.read_resource("fieldkit://jobs")
            assert json.loads(jobs.contents[0].text)["jobs"][0]["job_id"] == JOB
            report = await client.read_resource(f"fieldkit://jobs/{JOB}/report")
            assert json.loads(report.contents[0].text)["password"] == "[REDACTED]"
            prompts = await client.list_prompts()
            assert prompts.prompts[0].name == "fieldkit_assessment_workflow"
            prompt = await client.get_prompt("fieldkit_assessment_workflow")
            assert "untrusted data" in prompt.messages[0].content.text
            assert "DRY_RUN" in prompt.messages[0].content.text
            assert "fieldkit_execute_python" in prompt.messages[0].content.text

    asyncio.run(exercise())
    assert len(agent.calls) == 1


@requires_mcp
def test_real_modules_run_and_compose_private_offline_results(tmp_path):
    from mcp import Client

    from fieldkit.core.jwt import encode

    token = encode(b'{"alg":"none"}') + "." + encode(b'{"sub":"fixture-private-subject"}') + "."
    (tmp_path / "private-token.txt").write_text(token)
    (tmp_path / "private-token.txt").chmod(0o600)
    (tmp_path / "requests.json").write_text(
        json.dumps(
            {
                "requests": [
                    {
                        "id": "preview",
                        "url": "https://fixture.test/preview",
                        "method": "POST",
                        "json": {"url": "https://fixture.test/echo"},
                    },
                ]
            }
        )
    )
    (tmp_path / "requests.json").chmod(0o600)
    (tmp_path / "workflow.json").write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "id": "submit",
                        "request": {
                            "url": "/support",
                            "method": "POST",
                            "form": {"body": "{{payload}}"},
                        },
                        "expect": {"statuses": [200]},
                    }
                ],
                "browser": {"url": "/ticket/7"},
            }
        )
    )
    (tmp_path / "ffuf.json").write_text(
        json.dumps({"results": [{"url": "https://fixture.test/", "status": 200}]})
    )
    cases = [
        ("web/jwt-check", {"TOKEN_FILE": "private-token.txt"}),
        ("web/ffuf", {"INPUT": "ffuf.json", "IMPORT_COMPLETE": True}),
        (
            "web/parameter-discovery",
            {
                "TARGETS": ["https://fixture.test"],
                "REQUESTS_FILE": "requests.json",
                "REQUEST_IDS": ["preview"],
                "NAMES": ["method", "body", "bearer"],
                "DRY_RUN": True,
            },
        ),
        (
            "web/stored-xss",
            {
                "TARGETS": ["https://fixture.test"],
                "WORKFLOW_FILE": "workflow.json",
                "DRY_RUN": True,
            },
        ),
        ("integrations/callback-collector", {"DRY_RUN": True}),
        (
            "database/mssql-export",
            {
                "HOST": "sql.fixture.test",
                "DATABASES": ["App"],
                "DRY_RUN": True,
            },
        ),
    ]
    if sys.platform == "linux":
        cases.append(("network/vantage", {"TARGETS": ["127.0.0.1"], "DRY_RUN": True}))

    async def exercise():
        agent = FieldkitAgent(tmp_path)
        try:
            async with Client(mcp_server.build_server(agent)) as client:
                assert {t.name for t in (await client.list_tools()).tools} == TOOLS
                reference = await client.call_tool(
                    "fieldkit_search_reference", {"query": "web/jwt-check"}
                )
                assert reference.structured_content["entries"][0]["module"] == "web/jwt-check"
                for module, options in cases:
                    result = await client.call_tool(
                        "fieldkit_execute_python",
                        {
                            "code": (
                                f"job = fieldkit.run({module!r}, {options!r}, wait_seconds=10)\n"
                                'report = fieldkit.read_report(job["job_id"], section="results")\n'
                                'result = {"status": job["status"], "report": report}'
                            )
                        },
                    )
                    assert not result.is_error, result.structured_content
                    assert result.structured_content["result"]["status"] == "completed", (
                        result.structured_content
                    )
                    assert result.structured_content["result"]["report"]["available"]
                    assert token not in result.model_dump_json()
                    assert "fixture-private-subject" not in result.model_dump_json()
        finally:
            await agent.close()

    asyncio.run(exercise())


@requires_mcp
@pytest.mark.parametrize(
    "arguments,constraint",
    [
        ({}, "required"),
        ({"code": ["private-secret-value"]}, "type"),
        ({"code": "pass", "PASSWORD": "private-secret-value"}, "additionalProperties"),
    ],
)
def test_schema_rejection_does_not_echo_values(arguments, constraint):
    from mcp import Client

    agent = FakeAgent()

    async def exercise():
        async with Client(mcp_server.build_server(agent)) as client:
            result = await client.call_tool("fieldkit_execute_python", arguments)
            assert result.is_error
            assert result.structured_content["constraint"] == constraint
            assert "private-secret-value" not in result.model_dump_json()

    asyncio.run(exercise())
    assert not agent.calls


@requires_mcp
def test_removed_tools_and_unexpected_exceptions_are_public_errors():
    from mcp import Client

    async def exercise():
        async with Client(mcp_server.build_server(FakeAgent()), mode="legacy") as client:
            removed = await client.call_tool("fieldkit_run_web_header_review", {})
            assert removed.is_error
            assert removed.structured_content["error"] == "Unknown Fieldkit tool."
            failed = await client.call_tool(
                "fieldkit_execute_python",
                {"code": 'result = fieldkit.run("web/header-review", {"TARGETS": ["raise"]})'},
            )
            assert failed.is_error
            assert "unregistered-raw-credential-value" not in failed.model_dump_json()
            missing = await client.read_resource("fieldkit://jobs/missing/report")
            assert json.loads(missing.contents[0].text)["error"] == "Resource is unavailable."
            assert "private-data-in-error" not in missing.model_dump_json()
            private = await client.read_resource("file:///etc/passwd")
            assert json.loads(private.contents[0].text)["error"] == "Unknown Fieldkit resource."

    asyncio.run(exercise())


@requires_mcp
def test_explicit_public_agent_errors_are_actionable():
    from mcp import Client

    class LimitedAgent(FakeAgent):
        async def run(self, module, options=None, wait_seconds=0):
            raise FieldkitAgentError("Active job limit reached; wait for or cancel a job")

    async def exercise():
        async with Client(mcp_server.build_server(LimitedAgent())) as client:
            result = await client.call_tool(
                "fieldkit_execute_python", {"code": 'result = fieldkit.run("web/header-review")'}
            )
            assert result.is_error
            assert "Active job limit reached" in result.structured_content["detail"]

    asyncio.run(exercise())


@requires_mcp
def test_invalid_server_options_are_actionable_on_stderr(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert mcp_server.main(["--max-jobs", "0"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "MAX_JOBS must be 1-8" in captured.err


@requires_mcp
@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_subprocess_stdio_and_eof_cleanup(tmp_path, mode):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    marker = tmp_path / "closed"
    script = tmp_path / "fixture_server.py"
    script.write_text(
        "import asyncio\nfrom pathlib import Path\n"
        "from fieldkit.mcp_server import serve\nfrom test_mcp_protocol import FakeAgent\n"
        "class Agent(FakeAgent):\n"
        "    async def run(self, module, options=None, wait_seconds=0):\n"
        "        print('fixture stray handler stdout')\n"
        "        return await super().run(module, options, wait_seconds)\n"
        "    async def close(self):\n"
        f"        Path({str(marker)!r}).write_text('closed')\n"
        "asyncio.run(serve(Agent()))\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(Path(__file__).parent), str(Path.cwd() / "src")])
    params = StdioServerParameters(command=sys.executable, args=[str(script)], env=env)

    async def exercise():
        async with Client(params, mode=mode) as client:
            assert {t.name for t in (await client.list_tools()).tools} == TOOLS
            response = await client.call_tool(
                "fieldkit_execute_python",
                {"code": 'print("script output")\nresult = fieldkit.run("web/header-review")'},
            )
            assert not response.is_error, response.structured_content
            assert response.structured_content["result"]["status"] == "running"
            assert response.structured_content["stdout"] == "script output\n"

    asyncio.run(exercise())
    assert marker.read_text() == "closed"


def test_missing_optional_sdk_is_actionable_and_keeps_stdout_empty(monkeypatch, capsys):
    def unavailable():
        raise ImportError("fixture missing package")

    monkeypatch.setattr(mcp_server, "_load_sdk", unavailable)
    assert mcp_server.main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "pip install" in captured.err
    assert "Traceback" not in captured.err


def test_import_does_not_load_optional_sdk():
    import subprocess

    source = """import sys
class BlockSDK:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'mcp' or fullname.startswith('mcp.') or fullname == 'jsonschema':
            raise ImportError('SDK unavailable')
sys.meta_path.insert(0, BlockSDK())
import fieldkit.mcp_server
print('imported')
"""
    run = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True, check=True)
    assert run.stdout == "imported\n"
    assert not run.stderr


def test_server_releases_jobs_when_connection_is_cancelled(monkeypatch):
    agent = FakeAgent()
    entered = asyncio.Event()

    class Server:
        def create_initialization_options(self):
            return None

        async def run(self, read_stream, write_stream, options):
            entered.set()
            await asyncio.Event().wait()

    @asynccontextmanager
    async def transport():
        yield None, None

    monkeypatch.setattr(mcp_server, "_load_sdk", lambda: (Server, None, transport, None))
    monkeypatch.setattr(mcp_server, "build_server", lambda agent, runtime: Server())

    async def exercise():
        task = asyncio.create_task(mcp_server.serve(agent))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())
    assert agent.closed


@requires_mcp
@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_sdk_request_cancellation_releases_python_worker(tmp_path, mode):
    from mcp import Client

    async def exercise():
        agent = FieldkitAgent(tmp_path)
        runtime = CodeMode(agent)
        try:
            async with Client(mcp_server.build_server(agent, runtime), mode=mode) as client:
                task = asyncio.create_task(
                    client.call_tool(
                        "fieldkit_execute_python",
                        {
                            "code": 'from pathlib import Path\nPath("ready").touch()\n'
                            "while True: pass"
                        },
                    )
                )
                async with asyncio.timeout(3):
                    while not (tmp_path / "ready").exists():
                        await asyncio.sleep(0.01)
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                async with asyncio.timeout(3):
                    while runtime.tasks:
                        await asyncio.sleep(0.01)
                response = await client.call_tool("fieldkit_execute_python", {"code": "result = 7"})
                assert response.structured_content["result"] == 7
        finally:
            await runtime.close()
            await agent.close()

    asyncio.run(exercise())


@requires_mcp
@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_real_cli_stdio_registry_and_dry_run_job(tmp_path, mode):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "fieldkit", "mcp", "--workspace", str(tmp_path)],
    )

    async def exercise():
        async with Client(server, mode=mode) as client:
            assert {t.name for t in (await client.list_tools()).tools} == TOOLS
            info = await client.call_tool(
                "fieldkit_search_reference", {"query": "web/header-review"}
            )
            properties = info.structured_content["entries"][0]["input_schema"]["properties"][
                "options"
            ]
            assert "OUTPUT" not in properties["properties"]
            response = await client.call_tool(
                "fieldkit_execute_python",
                {
                    "code": 'job = fieldkit.run("web/header-review", '
                    '{"TARGETS": ["http://127.0.0.1:9/"], "DRY_RUN": True}, wait_seconds=5)\n'
                    'result = {"job": fieldkit.job_status(job["job_id"]), '
                    '"report": fieldkit.read_report(job["job_id"]), "jobs": fieldkit.list_jobs()}'
                },
            )
            assert not response.is_error, response.structured_content
            result = response.structured_content["result"]
            assert result["job"]["status"] == "completed"
            assert result["report"]["summary"]["completed"] is True
            job_id = result["job"]["job_id"]
            assert result["jobs"]["jobs"][0]["job_id"] == job_id
            resource = await client.read_resource(f"fieldkit://jobs/{job_id}/report")
            assert json.loads(resource.contents[0].text)["summary"]["completed"] is True
            return job_id

    job_id = asyncio.run(exercise())
    directory = tmp_path / "artifacts" / "mcp" / job_id
    assert not (directory / ".settings.json").exists()
    report = json.loads(next((directory / "runs").glob("*/report.json")).read_text())
    assert report["plan"]["validated_settings"]["DRY_RUN"] is True
    assert report["plan"]["network_requests"] == 0
