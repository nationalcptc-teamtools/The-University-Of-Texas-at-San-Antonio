"""Selected captures cross a real loopback boundary without target requests."""

import asyncio
import base64
import gzip
import io
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from fieldkit.core.agent import FieldkitAgent
from fieldkit.core.burp import BurpReceiver, capture_origins, capture_records
from fieldkit.core.local import LocalContext
from fieldkit.core.vault import Vault
from fieldkit.modules.burp_bridge import BurpBridge

ROOT = Path(__file__).resolve().parents[1]


def capture(url="https://fixture.test/account"):
    return {
        "schema_version": 1,
        "context": {"user": "fixture-user", "role": "employee", "feature": "account"},
        "tags": ["burp"],
        "exchanges": [
            {
                "request": {
                    "url": url,
                    "method": "POST",
                    "headers": [
                        {"name": "Authorization", "value": "Bearer fixture-private-auth"},
                        {"name": "Cookie", "value": "sid=fixture-private-cookie"},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "body_base64": base64.b64encode(
                        b'{"password":"fixture-private-password"}'
                    ).decode(),
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Set-Cookie", "value": "sid=fixture-response-secret"}],
                    "body_base64": base64.b64encode(b"\x00\xffprivate-response").decode(),
                },
            }
        ],
    }


def settings(tmp_path, **extra):
    return {
        **BurpBridge().defaults(),
        "ORIGINS": ["https://fixture.test"],
        "DATABASE": str(tmp_path / "vault.sqlite"),
        "OUTPUT": str(tmp_path / "runs"),
        "BUDGET": 5,
        "MAX_CAPTURES": 1,
        **extra,
    }


def properties(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


async def ready(receiver):
    async with asyncio.timeout(3):
        while not receiver.configuration_created:
            await asyncio.sleep(0.01)
    return properties(receiver.configuration)


def test_real_receiver_auth_scope_private_vault_and_shutdown(tmp_path):
    async def exercise():
        values = settings(tmp_path)
        ctx = LocalContext("integrations/burp-bridge", values, Console(file=io.StringIO()))
        receiver = BurpReceiver(ctx, capture_origins(values["ORIGINS"]))
        task = asyncio.create_task(receiver.run())
        try:
            config = await ready(receiver)
            assert stat.S_IMODE(receiver.configuration.stat().st_mode) == 0o600
            async with httpx.AsyncClient(trust_env=False) as client:
                unauthorized = await client.post(config["endpoint"], json=capture())
                assert unauthorized.status_code == 403
                headers = {"Authorization": "Bearer " + config["token"]}
                origin = await client.post(
                    config["endpoint"],
                    json=capture(),
                    headers={**headers, "Origin": "http://outside.test"},
                )
                assert origin.status_code == 403
                outside = await client.post(
                    config["endpoint"],
                    json=capture("https://outside.test/account"),
                    headers=headers,
                )
                assert outside.status_code == 400 and "outside.test" not in outside.text
                accepted = await client.post(config["endpoint"], json=capture(), headers=headers)
                assert accepted.status_code == 200
                identifier = accepted.json()["record_ids"][0]
            await asyncio.wait_for(task, 2)
            ctx.report["completed"] = True
            ctx.finish()
            assert not receiver.configuration.exists()
            public = json.dumps(ctx.report) + (ctx.store.root / "report.json").read_text()
            assert config["token"] not in public
            assert "fixture-private-auth" not in public and "fixture-private-password" not in public
            with Vault(values["DATABASE"], create=False) as vault:
                request = vault.request(identifier)
                assert request["json"]["password"] == "fixture-private-password"
                private = vault.get(identifier, private=True)
                assert (
                    base64.b64decode(private["data"]["response"]["body_base64"])
                    == b"\x00\xffprivate-response"
                )
                assert private["data"]["context"]["role"] == "employee"
        finally:
            receiver.stop.set()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())


def test_receiver_bounds_batch_validation_and_config_ownership(tmp_path):
    origins = capture_origins(["https://fixture.test"])
    document = capture()
    document["exchanges"].append(capture("https://outside.test/")["exchanges"][0])
    with pytest.raises(ValueError, match="outside"):
        capture_records(document, origins, 5, 1024)
    document = capture()
    with pytest.raises(ValueError, match="body"):
        capture_records(document, origins, 5, 2)
    with pytest.raises(ValueError, match="entry limit"):
        capture_records(document, origins, 0, 1024)
    document["exchanges"][0]["request"]["body_base64"] = "***"
    with pytest.raises(ValueError, match="Malformed"):
        capture_records(document, origins, 5, 1024)
    for url in ("https://fixture.test/path", "http://u:p@fixture.test", "fixture.test"):
        with pytest.raises(ValueError):
            capture_origins([url])
    existing = tmp_path / "private.properties"
    existing.write_text("operator-content")
    module = BurpBridge()
    assert (
        module.run(settings(tmp_path, CONFIG_FILE=str(existing)), Console(file=io.StringIO())) == 1
    )
    assert existing.read_text() == "operator-content"


def test_compressed_capture_keeps_encoded_request_bytes():
    document = capture()
    raw = document["exchanges"][0]["request"]
    compressed = gzip.compress(b'{"password":"fixture-private-password"}')
    raw["headers"].append({"name": "Content-Encoding", "value": "gzip"})
    raw["body_base64"] = base64.b64encode(compressed).decode()
    records, _, _ = capture_records(document, capture_origins(["https://fixture.test"]), 1, 1024)
    request, _, original = records[0]
    assert base64.b64decode(request["body_base64"]) == compressed
    assert request["headers"]["Content-Encoding"] == "gzip"
    assert original["request"]["body_base64"] == raw["body_base64"]


@pytest.mark.parametrize("body", [b'{"unfinished":', b"\xff\x00", b'{"number":NaN}'])
def test_malformed_json_capture_is_preserved_as_opaque_bytes(body):
    document = capture()
    document["exchanges"][0]["request"]["body_base64"] = base64.b64encode(body).decode()
    records, _, _ = capture_records(document, capture_origins(["https://fixture.test"]), 1, 1024)
    request = records[0][0]
    assert "json" not in request
    assert base64.b64decode(request["body_base64"]) == body


def test_bridge_dry_run_no_listener_or_vault(tmp_path, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Dry run opened a listener")

    monkeypatch.setattr("fieldkit.core.burp.asyncio.start_server", forbidden)
    module = BurpBridge()
    assert module.run(settings(tmp_path, DRY_RUN=True), Console(file=io.StringIO())) == 0
    assert not (tmp_path / "vault.sqlite").exists()
    report = json.loads(next((tmp_path / "runs").glob("*/report.json")).read_text())
    assert report["plan"]["network_requests"] == 0 and not report["plan"]["listener_opened"]


def test_configuration_creation_does_not_overwrite_a_racing_file(tmp_path, monkeypatch):
    configuration = tmp_path / "private.properties"
    original_open = os.open

    def racing_open(filename, flags, *args, **kwargs):
        if Path(filename) == configuration and flags & os.O_EXCL:
            configuration.write_text("operator-created-input")
        return original_open(filename, flags, *args, **kwargs)

    monkeypatch.setattr("fieldkit.core.burp.os.open", racing_open)
    assert (
        BurpBridge().run(
            settings(tmp_path, CONFIG_FILE=str(configuration)), Console(file=io.StringIO())
        )
        == 1
    )
    assert configuration.read_text() == "operator-created-input"


def test_shutdown_preserves_a_replacement_configuration(tmp_path):
    async def exercise():
        ctx = LocalContext(
            "integrations/burp-bridge", settings(tmp_path), Console(file=io.StringIO())
        )
        receiver = BurpReceiver(ctx, capture_origins(["https://fixture.test"]))
        task = asyncio.create_task(receiver.run())
        await ready(receiver)
        text = receiver.configuration.read_text()
        receiver.configuration.rename(tmp_path / "saved-original.properties")
        receiver.configuration.write_text(text)
        receiver.stop.set()
        await asyncio.wait_for(task, 2)
        assert receiver.configuration.read_text() == text

    asyncio.run(exercise())


def test_receiver_cancel_closes_socket_and_removes_private_configuration(tmp_path):
    async def exercise():
        ctx = LocalContext(
            "integrations/burp-bridge", settings(tmp_path), Console(file=io.StringIO())
        )
        receiver = BurpReceiver(ctx, capture_origins(["https://fixture.test"]))
        task = asyncio.create_task(receiver.run())
        config = await ready(receiver)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert not receiver.configuration.exists()
        async with httpx.AsyncClient(trust_env=False) as client:
            with pytest.raises(httpx.ConnectError):
                await client.post(config["endpoint"], json=capture())

    asyncio.run(exercise())


def test_mcp_capture_job_live_report_ids_and_public_vault(tmp_path):
    async def exercise():
        agent = FieldkitAgent(tmp_path)
        try:
            job = await agent.start_job(
                "integrations/burp-bridge",
                {
                    "ORIGINS": ["https://fixture.test"],
                    "DATABASE": "vault.sqlite",
                    "BUDGET": 8,
                    "MAX_CAPTURES": 1,
                },
            )
            async with asyncio.timeout(5):
                while not (
                    files := list(job.directory.glob("runs/*/private-burp-bridge.properties"))
                ):
                    await asyncio.sleep(0.01)
            config = properties(files[0])
            async with asyncio.timeout(3):
                while not agent.read_report(job.id)["available"]:
                    await asyncio.sleep(0.01)
            async with httpx.AsyncClient(trust_env=False) as client:
                sent = await client.post(
                    config["endpoint"],
                    json=capture(),
                    headers={"Authorization": "Bearer " + config["token"]},
                )
                assert sent.status_code == 200
            await asyncio.wait_for(job.task, 3)
            rows = agent.read_report(job.id, "results")["items"]
            identifier = next(row["request_id"] for row in rows if row["kind"] == "burp_capture")
            records = agent.vault_records("vault.sqlite", "request")
            assert records["items"][0]["id"] == identifier
            public = json.dumps([rows, records, agent.job_status(job.id)])
            assert "fixture-private" not in public and config["token"] not in public
            assert agent.job_status(job.id)["status"] == "completed"
        finally:
            await agent.close()

    asyncio.run(exercise())


@pytest.fixture(scope="module")
def java_client(tmp_path_factory):
    if not shutil.which("javac") or not shutil.which("java"):
        pytest.skip("Java JDK unavailable")
    root = tmp_path_factory.mktemp("java-bridge")
    harness = root / "BridgeHarness.java"
    harness.write_text(
        "import fieldkit.BridgeClient;import java.nio.file.*;"
        "public class BridgeHarness { public static void main(String[] args)throws Exception {"
        "System.out.print(BridgeClient.send(BridgeClient.Configuration.load(Path.of(args[0])),"
        "Files.readString(Path.of(args[1]))));}}"
    )
    subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-d",
            str(root),
            str(ROOT / "extensions/burp/src/main/java/fieldkit/BridgeClient.java"),
            str(harness),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return root


def test_actual_java_sender_posts_capture_and_rejects_remote_config(tmp_path, java_client):
    async def exercise():
        ctx = LocalContext(
            "integrations/burp-bridge", settings(tmp_path), Console(file=io.StringIO())
        )
        receiver = BurpReceiver(ctx, capture_origins(["https://fixture.test"]))
        task = asyncio.create_task(receiver.run())
        try:
            await ready(receiver)
            payload = tmp_path / "capture.json"
            payload.write_text(json.dumps(capture()))
            command = [
                "java",
                "-cp",
                str(java_client),
                "BridgeHarness",
                str(receiver.configuration),
                str(payload),
            ]
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == 0, stderr.decode()
            assert json.loads(stdout)["captured"] == 1
            await task
            bad = tmp_path / "bad.properties"
            bad.write_text(
                "schema_version=1\nendpoint=http://outside.test/capture\ntoken="
                + "a" * 64
                + "\nexpires_epoch=9999999999\nmax_bytes=100000\nmax_entries=1\n"
            )
            bad.chmod(0o600)
            failed = await asyncio.create_subprocess_exec(
                *command[:-2],
                str(bad),
                str(payload),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, error = await failed.communicate()
            assert failed.returncode != 0 and "Configuration is invalid" in error.decode()
        finally:
            receiver.stop.set()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())


@pytest.mark.parametrize("reply", ["oversized", "stalled"])
def test_java_sender_bounds_entire_response(tmp_path, java_client, reply):
    async def exercise():
        handlers = set()

        async def handle(reader, writer):
            task = asyncio.current_task()
            handlers.add(task)
            try:
                header = await reader.readuntil(b"\r\n\r\n")
                length = next(
                    int(line.split(b":", 1)[1])
                    for line in header.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                )
                await reader.readexactly(length)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n")
                if reply == "oversized":
                    writer.write(b"fixture-private-response" * 1000)
                await writer.drain()
                await reader.read()
            finally:
                writer.close()
                handlers.discard(task)

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        configuration = tmp_path / "private.properties"
        configuration.write_text(
            f"schema_version=1\nendpoint=http://127.0.0.1:{port}/capture\ntoken="
            + "a" * 64
            + "\nexpires_epoch=9999999999\nmax_bytes=10000\nmax_entries=1\n"
        )
        configuration.chmod(0o600)
        payload = tmp_path / "capture.json"
        payload.write_text("{}")
        started = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                "java",
                "-cp",
                str(java_client),
                "BridgeHarness",
                str(configuration),
                str(payload),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode != 0
            assert time.monotonic() - started < 19
            assert "exceeded its limits" in stderr.decode()
            assert b"fixture-private-response" not in stdout + stderr
        finally:
            server.close()
            await server.wait_closed()
            pending = list(handlers)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    asyncio.run(exercise())


def test_extension_compiles_against_actual_montoya_api_when_available(tmp_path):
    api = Path(
        os.environ.get(
            "FIELDKIT_MONTOYA_API_JAR", ROOT / "extensions/burp/build/montoya-api-2026.7.jar"
        )
    )
    if not shutil.which("javac") or not api.is_file():
        pytest.skip("Montoya API/JDK unavailable")
    compiled = subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-cp",
            str(api),
            "-d",
            str(tmp_path),
            *(str(p) for p in (ROOT / "extensions/burp/src").rglob("*.java")),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr


def test_actual_montoya_capture_serialization_and_sender(tmp_path):
    api = Path(
        os.environ.get(
            "FIELDKIT_MONTOYA_API_JAR", ROOT / "extensions/burp/build/montoya-api-2026.7.jar"
        )
    )
    if not shutil.which("javac") or not shutil.which("java") or not api.is_file():
        pytest.skip("Montoya API/JDK unavailable")
    sources = list((ROOT / "extensions/burp/src").rglob("*.java"))
    sources.append(ROOT / "extensions/burp/tests/CaptureHarness.java")
    subprocess.run(
        ["javac", "--release", "17", "-cp", str(api), "-d", str(tmp_path), *map(str, sources)],
        check=True,
        capture_output=True,
        timeout=30,
    )

    async def exercise():
        values = settings(tmp_path)
        ctx = LocalContext("integrations/burp-bridge", values, Console(file=io.StringIO()))
        receiver = BurpReceiver(ctx, capture_origins(values["ORIGINS"]))
        task = asyncio.create_task(receiver.run())
        try:
            await ready(receiver)
            process = await asyncio.create_subprocess_exec(
                "java",
                "-Djava.awt.headless=true",
                "-cp",
                os.pathsep.join((str(tmp_path), str(api))),
                "fieldkit.CaptureHarness",
                str(receiver.configuration),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == 0, stderr.decode()
            identifier = json.loads(stdout)["record_ids"][0]
            await task
            with Vault(values["DATABASE"], create=False) as vault:
                private = vault.get(identifier, private=True)["data"]
                assert private["context"]["user"] == 'user"\\\nλ'
                assert base64.b64decode(private["response"]["body_base64"]) == b"\x00\xff\r\n"
                assert len(private["response"]["headers_raw"]) == 2
                assert vault.request(identifier)["json"]["password"] == "fixture-private-password"
        finally:
            receiver.stop.set()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())
