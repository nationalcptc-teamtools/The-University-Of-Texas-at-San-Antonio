import asyncio
import io
import json
import time

import httpx
import pytest
from rich.console import Console

from fieldkit.core.assessment import AssessmentContext, NetworkModule
from fieldkit.core.http import Fetcher, RequestControls
from fieldkit.core.profiles import load_profiles
from fieldkit.core.redaction import redact


class Probe(NetworkModule):
    name = "test/probe"
    description = "Test runtime"

    async def assess(self, ctx):
        for url in ctx.seed_urls():
            response = await ctx.fetch(url)
            ctx.add_endpoint(url)
            ctx.report["results"].append({"url": url, "status": response.status})


def test_scope_credentials_isolation_and_late_evidence_redaction(tmp_path, monkeypatch):
    profile_file = tmp_path / "profiles.json"
    profile_file.write_text(
        json.dumps(
            {
                "profiles": {
                    "user": {
                        "origins": ["https://lab.test"],
                        "headers": {"Authorization": "Bearer private-auth"},
                        "cookies": {"sid": "private-cookie"},
                    }
                }
            }
        )
    )
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/logout":
            return httpx.Response(200, headers={"Set-Cookie": "sid=; Max-Age=0; Path=/"})
        return httpx.Response(200, text="private-auth private-cookie newly-found-secret")

    client_class = httpx.AsyncClient
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **k: client_class(transport=httpx.MockTransport(handler), **k),
    )
    settings = {
        **Probe().defaults(),
        "TARGETS": ["https://lab.test", "https://other.test"],
        "PROFILES_FILE": str(profile_file),
        "PROFILE": "user",
        "RATE": 0,
        "OUTPUT": str(tmp_path / "runs"),
    }

    async def run():
        async with AssessmentContext("test", settings, Console(file=io.StringIO())) as ctx:
            await ctx.prepare()
            await ctx.fetch("https://lab.test/")
            await ctx.fetch("https://lab.test/", profile="anonymous")
            await ctx.fetch("https://lab.test/logout")
            await ctx.clone_profile("user", "replay")
            await ctx.fetch("https://lab.test/after", profile="replay")
            outside = await ctx.fetch("https://outside.test/")
            wrong_profile = await ctx.fetch("https://other.test/")
            assert outside.error == "out_of_scope"
            assert wrong_profile.error == "profile_scope"
            ctx.secrets.append("newly-found-secret")
            ctx.finish()
            return ctx.store.root

    root = asyncio.run(run())
    assert len(seen) == 4
    assert seen[0].headers["Authorization"] == "Bearer private-auth"
    assert "private-cookie" in seen[0].headers["Cookie"]
    assert "authorization" not in seen[1].headers and "cookie" not in seen[1].headers
    assert "cookie" not in seen[-1].headers
    for path in (root / "evidence").glob("*.json"):
        text = path.read_text()
        assert not any(s in text for s in ("private-auth", "private-cookie", "newly-found-secret"))


def test_budget_writes_incomplete_report(tmp_path, monkeypatch):
    async def handler(request):
        await asyncio.sleep(1)
        return httpx.Response(200)

    client_class = httpx.AsyncClient
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **k: client_class(transport=httpx.MockTransport(handler), **k),
    )
    module = Probe()
    values = {
        **module.defaults(),
        "TARGETS": ["https://lab.test"],
        "BUDGET": 0.02,
        "RATE": 0,
        "OUTPUT": str(tmp_path),
    }
    assert module.run(values, Console(file=io.StringIO())) == 1
    report = json.loads(next(tmp_path.glob("*/report.json")).read_text())
    assert report["completed"] is False
    assert report["errors"][0]["error"] == "budget_exhausted"


def test_safe_retry_and_shared_rate_pacing():
    calls = []

    async def handler(request):
        calls.append((request.method, time.monotonic()))
        return httpx.Response(503 if len(calls) == 1 else 200)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            controls = RequestControls(4, 50)
            fetcher = Fetcher(client, 4, 1024, 2, controls=controls, retries=1)
            result = await fetcher.get("http://lab/", "http://lab/")
            assert result.status == 200
            await fetcher.request("http://lab/submit", "http://lab/", method="POST", data="x")

    asyncio.run(run())
    assert [c[0] for c in calls] == ["GET", "GET", "POST"]
    assert calls[-1][1] - calls[-2][1] >= 0.015


def test_profile_input_errors_and_redaction_preserve_metadata(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text('{"profiles":{"user":{"headers":{"Authorization":"secret"}}}}')
    with pytest.raises(ValueError, match="origins"):
        load_profiles(str(path))
    value = redact(
        {
            "Authorization": "secret",
            "cookie_name": "sid",
            "cookies": [{"name": "sid", "secure": True}],
            "session_invalidated": True,
        }
    )
    assert value["Authorization"] == "[REDACTED]"
    assert value["cookie_name"] == "sid"
    assert value["cookies"][0]["secure"] is True
