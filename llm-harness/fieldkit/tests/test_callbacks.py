"""Passive loopback callback fixtures: exact proof, privacy, bounds and lifecycle."""

import asyncio
import hashlib
import io
import json
import stat
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from rich.console import Console

from fieldkit.core.callbacks import (
    CallbackCollector,
    correlate_receipts,
    read_receipts,
    write_callback_evidence,
)
from fieldkit.core.local import LocalContext
from fieldkit.modules.callback_collector import CallbackCollectorModule


def context(tmp_path, **settings):
    settings = {
        **CallbackCollectorModule().defaults(),
        "OUTPUT": str(tmp_path / "runs"),
        "BUDGET": 5,
        **settings,
    }
    return LocalContext("integrations/callback-collector", settings, Console(file=io.StringIO()))


async def exchange(collector, raw):
    reader, writer = await asyncio.open_connection("127.0.0.1", collector.port)
    try:
        writer.write(raw)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), 2)
    finally:
        writer.close()
        await writer.wait_closed()


def request(path, *, method="GET", body=b"", extra=b""):
    return (
        f"{method} {path} HTTP/1.1\r\nHost: fixture.test\r\n".encode()
        + f"Content-Length: {len(body)}\r\n".encode()
        + extra
        + b"\r\n"
        + body
    )


def test_real_listener_exact_path_private_metadata_and_random_markers(tmp_path):
    async def exercise():
        ctx = context(tmp_path)
        collector = CallbackCollector(ctx)
        try:
            assert await collector.start() is collector
            first = collector.register()
            second = collector.register()
            marker = first.rsplit("/", 1)[-1]
            assert first != second and len(marker) >= 32
            assert b"404" in await exchange(collector, request("/unregistered"))
            assert b"404" in await exchange(collector, request(urlsplit(first).path + "/suffix"))
            assert b"404" in await exchange(
                collector, request(urlsplit(first).path.replace(marker[0], "%41", 1))
            )
            started = time.time()
            raw = request(
                urlsplit(first).path + "?api_key=private-query-secret",
                body=b"private-body-secret",
                extra=b"Authorization: Bearer private-header-secret\r\n"
                b"Cookie: session=private-cookie-secret\r\n",
            )
            assert b"204" in await exchange(collector, raw)
            receipts = await collector.wait(marker, started, 0)
            assert len(receipts) == 1
            receipt = receipts[0]
            assert receipt["url"] == first and receipt["method"] == "GET"
            assert receipt["body_sha256"] == hashlib.sha256(b"private-body-secret").hexdigest()
            assert receipt["body_bytes"] == 19 and receipt["source"] == "http_listener"
            assert receipt["query_bytes"] > 0
            assert receipt["peer"]["ip"] == "127.0.0.1"
            assert 1 <= receipt["peer"]["port"] <= 65535
            evidence = ctx.report["evidence"][0]
            assert receipt["evidence"] == evidence["id"]
            assert not evidence["private_raw"]
            ctx.finish()
            for path in ctx.store.root.rglob("*"):
                if path.is_file():
                    assert stat.S_IMODE(path.stat().st_mode) == 0o600
                    saved = path.read_text()
                    for secret in (
                        "private-body-secret",
                        "private-header-secret",
                        "private-cookie-secret",
                        "private-query-secret",
                    ):
                        assert secret not in saved
            assert read_receipts(collector.receipts_file)[0]["callback_id"] == marker
        finally:
            await collector.close()
        assert not collector._tasks and not collector._writers

    asyncio.run(exercise())


def test_post_proof_filters_method_digest_and_time(tmp_path):
    async def exercise():
        collector = await CallbackCollector(context(tmp_path)).start()
        try:
            proof = b"constant-private-random-proof"
            url = collector.register(
                methods={"POST"}, body_sha256=hashlib.sha256(proof).hexdigest()
            )
            marker = url.rsplit("/", 1)[-1]
            path = urlsplit(url).path
            since = time.time()
            assert b"405" in await exchange(collector, request(path))
            assert not collector.receipts
            assert b"204" in await exchange(collector, request(path, method="POST", body=b"wrong"))
            assert await collector.wait(marker, since, 0.01) == []
            assert b"204" in await exchange(collector, request(path, method="POST", body=proof))
            receipts = await collector.wait(marker, since, 0)
            assert len(receipts) == 1 and receipts[0]["body_bytes"] == len(proof)
            assert await collector.wait(marker, time.time() + 10, 0) == []
            saved = collector.receipts_file.read_text()
            assert proof.decode() not in saved and '"wrong"' not in saved
        finally:
            await collector.close()

    asyncio.run(exercise())


def test_wait_wakes_for_receipt_and_close(tmp_path):
    async def exercise():
        collector = await CallbackCollector(context(tmp_path)).start()
        url = collector.register()
        marker = url.rsplit("/", 1)[-1]
        waiter = asyncio.create_task(collector.wait(marker, time.time(), 3))
        await asyncio.sleep(0)
        assert b"204" in await exchange(collector, request(urlsplit(url).path))
        assert len(await asyncio.wait_for(waiter, 1)) == 1
        waiting = asyncio.create_task(collector.wait(marker, time.time() + 10, 3))
        await asyncio.sleep(0)
        await collector.close()
        assert await asyncio.wait_for(waiting, 1) == []
        await collector.close()
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", collector.port)

    asyncio.run(exercise())


def test_public_forwarded_prefix_is_exact_and_no_forwarded_identity(tmp_path):
    async def exercise():
        collector = await CallbackCollector(
            context(tmp_path), public_url="https://callbacks.fixture.test/forwarded"
        ).start()
        try:
            url = collector.register()
            assert url.startswith("https://callbacks.fixture.test/forwarded/callbacks/")
            path = urlsplit(url).path
            assert b"404" in await exchange(collector, request(path.removeprefix("/forwarded")))
            assert b"204" in await exchange(
                collector,
                request(path, extra=b"X-Forwarded-For: privileged-staff-secret\r\n"),
            )
            assert collector.receipts[0]["url"] == url
            assert "privileged-staff-secret" not in collector.receipts_file.read_text()
            assert "source_ip" not in collector.receipts[0]
        finally:
            await collector.close()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "raw,status",
    [
        (b"GET https://outside.fixture/ HTTP/1.1\r\nHost: x\r\n\r\n", 400),
        (b"GET //outside.fixture/ HTTP/1.1\r\nHost: x\r\n\r\n", 400),
        (b"GET {path}#fragment HTTP/1.1\r\nHost: x\r\n\r\n", 400),
        (b"GET {path} HTTP/1.1\r\n\r\n", 400),
        (b"GET {path} HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n", 400),
        (b"GET {path} HTTP/1.1\r\nHost: x\r\n folded: value\r\n\r\n", 400),
        (b"GET {path} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
        (b"GET {path} HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n", 400),
        (b"GET {path} HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", 400),
        (b"GET {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 9999\r\n\r\n", 413),
        (b"GET {path} HTTP/1.1\r\nHost: x\r\nX-Large: " + b"x" * 1024 + b"\r\n\r\n", 431),
    ],
)
def test_framing_header_body_and_path_bounds(tmp_path, raw, status):
    async def exercise():
        collector = await CallbackCollector(context(tmp_path), max_bytes=1024).start()
        try:
            url = collector.register()
            raw_request = raw.replace(b"{path}", urlsplit(url).path.encode())
            response = await exchange(collector, raw_request)
            assert str(status).encode() in response.split(b"\r\n")[0]
            assert not collector.receipts and not context_evidence(collector)
        finally:
            await collector.close()

    asyncio.run(exercise())


def context_evidence(collector):
    return collector.ctx.report["evidence"]


def test_connection_timeout_concurrent_cap_and_cancelled_partial_body(tmp_path):
    async def exercise():
        collector = await CallbackCollector(
            context(tmp_path), max_connections=1, request_timeout=0.1
        ).start()
        collector.register(methods={"POST"})
        reader, writer = await asyncio.open_connection("127.0.0.1", collector.port)
        writer.write(b"GET /callbacks/")
        await writer.drain()
        await asyncio.sleep(0.02)
        second_reader, second_writer = await asyncio.open_connection("127.0.0.1", collector.port)
        assert await asyncio.wait_for(second_reader.read(), 1) == b""
        second_writer.close()
        await second_writer.wait_closed()
        assert b"408" in await asyncio.wait_for(reader.read(), 1)
        writer.close()
        await writer.wait_closed()
        collector.request_timeout = 10
        _, pending = await asyncio.open_connection("127.0.0.1", collector.port)
        pending.write(b"POST /callbacks/")
        await pending.drain()
        await asyncio.sleep(0)
        await asyncio.wait_for(collector.close(), 0.5)
        pending.close()
        await pending.wait_closed()
        assert not collector.receipts and not collector._tasks and not collector._writers

    asyncio.run(exercise())


def test_deadline_and_receipt_caps_stop_listener(tmp_path):
    async def exercise():
        ctx = context(tmp_path, BUDGET=0.06)
        collector = await CallbackCollector(ctx).start()
        marker = collector.register().rsplit("/", 1)[-1]
        assert await collector.wait(marker, time.time(), 1) == []
        await asyncio.wait_for(collector.wait_closed(), 1)
        await collector.close()
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", collector.port)

        collector = await CallbackCollector(context(tmp_path), max_receipts=1).start()
        url = collector.register()
        try:
            assert b"204" in await exchange(collector, request(urlsplit(url).path))
            await asyncio.wait_for(collector.wait_closed(), 1)
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", collector.port)
            assert len(collector.receipts) == 1
            with pytest.raises(ValueError, match="Start"):
                collector.register()
        finally:
            await collector.close()

    asyncio.run(exercise())


def imported_receipt(marker="fixture_marker_1234567890", **extra):
    return {
        "callback_id": marker,
        "url": "https://callbacks.fixture.test/callbacks/" + marker,
        "received_at": datetime.now(UTC).isoformat(),
        "method": "POST",
        "body_sha256": hashlib.sha256(b"proof").hexdigest(),
        "body_bytes": 5,
        "source": "operator-import",
        **extra,
    }


def test_import_exact_id_origin_path_time_method_digest_and_sanitization():
    good = imported_receipt(
        headers={"Authorization": "private-header"},
        body="private-body",
        cookie="private-cookie",
        url="https://callbacks.fixture.test/callbacks/fixture_marker_1234567890?token=private-query",
    )
    expected = good["url"].split("?")[0]
    bad = [
        {**good, "callback_id": "different_marker_123456789"},
        {**good, "url": expected + "suffix"},
        {**good, "url": expected.replace("callbacks.fixture.test", "outside.fixture.test")},
        {**good, "received_at": "2000-01-01T00:00:00+00:00"},
        {**good, "received_at": "2099-01-01T00:00:00+00:00"},
        {**good, "received_at": "2026-01-01T00:00:00"},
        {**good, "method": "GET"},
        {**good, "body_sha256": "0" * 64},
        {**good, "url": expected + "#fragment"},
    ]
    matched = correlate_receipts(
        [*bad, good],
        good["callback_id"],
        expected,
        time.time() - 5,
        methods={"POST"},
        body_sha256=good["body_sha256"],
    )
    assert len(matched) == 1 and matched[0]["source"] == "imported_receipt"
    assert matched[0]["url"] == expected and matched[0]["body_bytes"] == 5
    assert "private-" not in json.dumps(matched)


def test_private_receipt_import_limits_jsonl_symlink_and_permissions(tmp_path):
    path = tmp_path / "receipts.jsonl"
    path.write_text(json.dumps(imported_receipt()) + "\n" + json.dumps(imported_receipt()))
    path.chmod(0o600)
    assert len(read_receipts(path)) == 2
    with pytest.raises(ValueError, match="bounded"):
        read_receipts(path, max_receipts=1)
    with pytest.raises(ValueError, match="bounded"):
        read_receipts(path, max_bytes=1)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        read_receipts(path)
    path.chmod(0o600)
    link = tmp_path / "link.jsonl"
    link.symlink_to(path)
    with pytest.raises(OSError):
        read_receipts(link)
    path.write_text('{"receipts":[1]}')
    with pytest.raises(ValueError, match="object"):
        read_receipts(path)
    path.write_text("not json")
    with pytest.raises(ValueError, match="Malformed"):
        read_receipts(path)


@pytest.mark.parametrize(
    "values",
    [
        {"bind_host": "hostname.fixture.test"},
        {"bind_host": "0.0.0.0"},
        {"port": 65536},
        {"max_receipts": 10001},
        {"max_bytes": 1048577},
        {"max_connections": 129},
        {"max_connection_attempts": 100001},
        {"request_timeout": float("inf")},
        {"request_timeout": 61},
        {"public_url": "http://user:password@fixture.test"},
        {"public_url": "https://fixture.test/path?secret=private"},
        {"public_url": "https://fixture.test/../path"},
    ],
)
def test_fixed_core_limits_and_unambiguous_addresses(tmp_path, values):
    with pytest.raises(ValueError):
        CallbackCollector(context(tmp_path), **values)


def test_registration_contract_validation(tmp_path):
    async def exercise():
        collector = CallbackCollector(context(tmp_path))
        with pytest.raises(ValueError, match="Start"):
            collector.register()
        await collector.start()
        try:
            with pytest.raises(ValueError, match="once"):
                await collector.start()
            for marker in ("short", "unsafe/marker_123456", "x" * 129):
                with pytest.raises(ValueError, match="marker"):
                    collector.register(marker)
            with pytest.raises(ValueError, match="methods"):
                collector.register(methods=["get"])
            with pytest.raises(ValueError, match="SHA256"):
                collector.register(body_sha256="A" * 64)
            url = collector.register("known_marker_123456")
            with pytest.raises(ValueError, match="already"):
                collector.register("known_marker_123456")
            with pytest.raises(ValueError, match="not registered"):
                await collector.wait("not_registered_123456", 0, 0)
            with pytest.raises(ValueError, match="wait"):
                await collector.wait(url.rsplit("/", 1)[-1], 0, 3601)
        finally:
            await collector.close()

    asyncio.run(exercise())


def test_generic_network_context_evidence_helper(tmp_path):
    ctx = SimpleNamespace(store=SimpleNamespace(root=tmp_path), report={"evidence": []}, secrets=[])
    receipt = imported_receipt(
        body="private-body",
        headers={"Authorization": "private-header"},
        peer={"ip": "127.0.0.1", "port": 1234, "credential": "private-peer"},
    )
    evidence = write_callback_evidence(ctx, receipt)
    entry = ctx.report["evidence"][0]
    assert entry["id"] == evidence and not entry["private_raw"]
    assert (
        json.loads((tmp_path / entry["file"]).read_text())["receipt"]["callback_id"]
        == receipt["callback_id"]
    )
    assert "private-" not in (tmp_path / entry["file"]).read_text()
    assert json.loads((tmp_path / entry["file"]).read_text())["receipt"]["peer"] == {
        "ip": "127.0.0.1",
        "port": 1234,
    }


def test_start_artifact_write_failure_closes_bound_listener(tmp_path, monkeypatch):
    async def exercise():
        collector = CallbackCollector(context(tmp_path))

        def fail():
            raise OSError("fixture artifact failure")

        monkeypatch.setattr(collector, "_save_receipts", fail)
        with pytest.raises(OSError, match="fixture"):
            await collector.start()
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", collector.port)
        assert not collector._tasks and not collector._writers

    asyncio.run(exercise())


def test_total_connection_attempt_cap_counts_irrelevant_requests(tmp_path):
    async def exercise():
        collector = await CallbackCollector(context(tmp_path), max_connection_attempts=2).start()
        collector.register()
        try:
            assert b"404" in await exchange(collector, request("/irrelevant-one"))
            assert b"404" in await exchange(collector, request("/irrelevant-two"))
            await asyncio.wait_for(collector.wait_closed(), 1)
            assert collector.stop_reason == "connection_limit"
            assert collector.connection_attempts == 2 and not collector.receipts
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", collector.port)
        finally:
            await collector.close()

    asyncio.run(exercise())


def test_receipt_storage_error_is_reported_and_stops_listener(tmp_path, monkeypatch):
    async def exercise():
        ctx = context(tmp_path)
        collector = await CallbackCollector(ctx).start()
        url = collector.register()

        def fail():
            raise OSError("private-operator-path-is-not-an-error-detail")

        monkeypatch.setattr(collector, "_save_receipts", fail)
        try:
            assert b"400" in await exchange(collector, request(urlsplit(url).path))
            await asyncio.wait_for(collector.wait_closed(), 1)
            assert collector.stop_reason == "storage_error"
            assert ctx.report["errors"][0]["error"] == "callback_storage_error"
            assert "private-operator" not in json.dumps(ctx.report)
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", collector.port)
        finally:
            await collector.close()

    asyncio.run(exercise())


def test_module_import_and_dry_run_make_no_listener_or_network(tmp_path, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Import/dry-run must not open a listener")

    monkeypatch.setattr(asyncio, "start_server", forbidden)
    module = CallbackCollectorModule()
    settings = {**module.defaults(), "OUTPUT": str(tmp_path / "runs"), "DRY_RUN": True}
    assert module.run(settings, Console(file=io.StringIO())) == 0
    directory = next((tmp_path / "runs").iterdir())
    report = json.loads((directory / "report.json").read_text())
    assert report["plan"]["network_requests"] == 0 and not report["plan"]["listener_opened"]

    receipt = imported_receipt(
        headers={"Cookie": "import-private-cookie"}, body="import-private-body"
    )
    path = tmp_path / "receipts.json"
    path.write_text(json.dumps({"receipts": [receipt]}))
    path.chmod(0o600)
    settings.update(
        OUTPUT=str(tmp_path / "imports"),
        DRY_RUN=False,
        RECEIPTS_FILE=str(path),
        CALLBACK_ID=receipt["callback_id"],
        CALLBACK_URL=receipt["url"],
        METHODS=["POST"],
        BODY_SHA256=receipt["body_sha256"],
        SINCE_EPOCH=time.time() - 5,
    )
    assert module.run(settings, Console(file=io.StringIO())) == 0
    directory = next((tmp_path / "imports").iterdir())
    report = json.loads((directory / "report.json").read_text())
    assert report["completed"] and report["callback_collector"]["matched_receipts"] == 1
    assert not report["callback_collector"]["listener_opened"]
    assert report["results"][0]["source"] == "imported_receipt"
    for saved in directory.rglob("*.json"):
        assert "import-private-" not in saved.read_text()


def test_module_real_listener_publishes_urls_and_stops_normally(tmp_path):
    async def exercise():
        module = CallbackCollectorModule()
        ctx = context(tmp_path, MAX_RECEIPTS=1)
        module.validate(ctx.settings)
        task = asyncio.create_task(module.assess(ctx))
        try:
            async with asyncio.timeout(1):
                while not ctx.report.get("callbacks"):
                    await asyncio.sleep(0.005)
            url = ctx.report["callbacks"][0]["url"]
            before = json.loads((ctx.store.root / "report.json").read_text())
            assert before["callbacks"][0]["url"] == url and not before["completed"]
            reader, writer = await asyncio.open_connection("127.0.0.1", urlsplit(url).port)
            writer.write(request(urlsplit(url).path))
            await writer.drain()
            assert b"204" in await asyncio.wait_for(reader.read(), 1)
            writer.close()
            await writer.wait_closed()
            await asyncio.wait_for(task, 1)
            assert ctx.report["results"][0]["correlated"]
            assert ctx.report["coverage"][0]["status"] == "receipt_limit"
            assert not ctx.report["errors"] and not ctx.report["findings"]
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())
