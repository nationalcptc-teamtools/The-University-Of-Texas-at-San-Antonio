import asyncio

import httpx

from fieldkit.core.http import Fetcher
from fieldkit.core.storage import ArtifactStore


def test_redirect_loop_is_bounded():
    calls = []

    async def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "/loop"})

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await Fetcher(client, 2, 1000, 1).get("http://lab/loop", "http://lab/")

    result = asyncio.run(exercise())
    assert result.error == "redirect_error"
    assert len(calls) == 6


def test_wall_clock_timeout_and_global_concurrency():
    active, peak = 0, 0

    async def handler(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.1)
        finally:
            active -= 1
        return httpx.Response(200, content=b"content")

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            fetcher = Fetcher(client, 2, 1000, 0.02)
            return await asyncio.gather(
                *(fetcher.get(f"http://lab/{i}", "http://lab/") for i in range(8))
            )

    results = asyncio.run(exercise())
    assert peak == 2
    assert all(r.error == "network_error" for r in results)


def test_storage_contains_untrusted_names_and_preserves_distinct_urls(tmp_path):
    store = ArtifactStore(str(tmp_path))
    urls = [
        "http://lab/../../robots.txt",
        "http://lab/a/robots.txt",
        "http://lab/b/robots.txt",
        "http://lab/%2e%2e%2f..%2fsecret",
        "http://lab/script.js?v=1",
        "http://lab/script.js?v=2",
    ]
    records = [store.save("http://lab", url, b"review me") for url in urls]
    assert len({r["file"] for r in records}) == len(urls)
    for record in records:
        path = (store.root / record["file"]).resolve()
        assert path.is_relative_to(store.root)
        assert path.read_bytes() == b"review me"
        assert path.stat().st_mode & 0o777 == 0o600
