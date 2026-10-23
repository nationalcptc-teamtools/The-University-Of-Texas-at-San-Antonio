"""Native browser network isolation, using only local UDP/TCP fixtures."""

import asyncio
import json
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from test_platform_modules import require_chromium

from fieldkit.core.browser_proof import BrowserProof


def proof_context(tmp_path, body):
    requests = []

    async def fetch(url, **kwargs):
        requests.append((url, kwargs))
        return SimpleNamespace(
            evidence_id="fixture-response",
            error=None,
            status=200,
            headers={"content-type": "text/html"},
            body=body,
        )

    return SimpleNamespace(
        settings={"TIMEOUT": 5},
        deadline=time.monotonic() + 20,
        profiles={"anonymous": {}},
        in_scope=lambda url: urlsplit(url).netloc == "fixture.test",
        fetch=fetch,
        requests=requests,
        report={"evidence": [], "errors": []},
        store=SimpleNamespace(root=tmp_path),
        secrets=[],
    )


def test_native_browser_blocks_stun_and_turn_while_scoped_canary_executes(tmp_path):
    require_chromium()
    from playwright.async_api import async_playwright

    async def exercise():
        udp_received, tcp_received = asyncio.Event(), asyncio.Event()

        class DatagramRecorder(asyncio.DatagramProtocol):
            def datagram_received(self, _data, _peer):
                udp_received.set()

        def accept(_reader, writer):
            tcp_received.set()
            writer.transport.abort()

        loop = asyncio.get_running_loop()
        udp, _ = await loop.create_datagram_endpoint(DatagramRecorder, local_addr=("127.0.0.1", 0))
        tcp = await asyncio.start_server(accept, "127.0.0.1", 0)
        udp_port = udp.get_extra_info("sockname")[1]
        tcp_port = tcp.sockets[0].getsockname()[1]
        rtc_script = (
            "<script>window.peers=[];for(const server of "
            + json.dumps(
                [
                    {"urls": f"stun:127.0.0.1:{udp_port}"},
                    {
                        "urls": f"turn:127.0.0.1:{tcp_port}?transport=tcp",
                        "username": "fixture",
                        "credential": "fixture",
                    },
                ]
            )
            + "){const rtc=new RTCPeerConnection({iceServers:[server]});"
            "peers.push(rtc);rtc.createDataChannel('fixture');"
            "rtc.createOffer().then(offer=>rtc.setLocalDescription(offer));}</script>"
        )
        callback = "https://callbacks.fixture.test/callbacks/fixture_marker_1234567890"
        canary = (
            "<script>setTimeout(()=>fetch("
            + json.dumps(callback)
            + ',{method:"POST",mode:"no-cors",body:"fixture-proof"}),500)</script>'
        )
        document = ("<html><body>" + rtc_script + canary + "</body></html>").encode()
        ctx = proof_context(tmp_path, document)
        proof = BrowserProof(ctx, callback, "fixture-proof")
        try:
            # Positive controls prove these listeners detect native browser traffic;
            # an inert API or malformed fixture cannot make isolation pass silently.
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch()
                try:
                    page = await browser.new_page()
                    await page.route(
                        "**/*",
                        lambda route: route.fulfill(
                            status=200, content_type="text/html", body=rtc_script
                        ),
                    )
                    await page.goto("http://fixture.test/control")
                    await asyncio.wait_for(
                        asyncio.gather(udp_received.wait(), tcp_received.wait()), 3
                    )
                finally:
                    await browser.close()
            udp_received.clear()
            tcp_received.clear()

            await proof.start()
            proxy_port = proof._proxy.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            assert await asyncio.wait_for(reader.read(), 1) == b""
            writer.close()
            await writer.wait_closed()
            result = await proof.render(
                "http://fixture.test/ticket/7", "anonymous", wait_seconds=3, screenshot=False
            )
            assert result["outcome"] == "confirmed"
            assert result["marker_present_in_document"]
            assert not result["execution_events"][0]["forwarded_to_listener"]
            assert len(ctx.requests) == 1
            assert not udp_received.is_set() and not tcp_received.is_set()
            await proof.close()
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", proxy_port)
        finally:
            await proof.close()
            udp.close()
            tcp.close()
            await tcp.wait_closed()

    asyncio.run(exercise())


def test_browser_launch_failure_closes_proxy_and_playwright(tmp_path, monkeypatch):
    playwright_api = pytest.importorskip("playwright.async_api")

    async def exercise():
        ports, stopped = [], []

        async def launch(**options):
            ports.append(urlsplit(options["proxy"]["server"]).port)
            assert "--proxy-bypass-list=<-loopback>" in options["args"]
            raise playwright_api.Error("fixture browser launch failed")

        async def stop():
            stopped.append(True)

        async def start():
            return SimpleNamespace(chromium=SimpleNamespace(launch=launch), stop=stop)

        monkeypatch.setattr(
            playwright_api, "async_playwright", lambda: SimpleNamespace(start=start)
        )
        proof = BrowserProof(proof_context(tmp_path, b""), "http://callback.test/marker", "proof")
        with pytest.raises(ValueError, match="Chromium unavailable"):
            await proof.start()
        assert stopped == [True]
        assert proof._proxy is None and proof.playwright is None and proof.browser is None
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", ports[0])
        await proof.close()

    asyncio.run(exercise())
