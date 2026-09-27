import hashlib
import http.server
import threading
from dataclasses import replace

import pytest

from cptc_harness.browser import BrowserAdapter, BrowserProfile, BrowserProxy
from cptc_harness.contracts import PolicyError
from cptc_harness.providers import DisclosureItem, ProviderProfile


class _Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/": self.send_error(404); return
        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
        self.wfile.write(b'<html><body><div id="answer">synthetic answer</div></body></html>')
    def log_message(self, *_): pass


@pytest.fixture()
def profile():
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),_Page)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    executable="/usr/lib/chromium/chromium"
    provider=ProviderProfile("synthetic-browser","browser",f"http://127.0.0.1:{server.server_port}","/","synthetic",("127.0.0.1",),max_response_bytes=32768)
    result=BrowserProfile(provider,("/",),response_selector="#answer",browser_executable=executable,browser_sha256=hashlib.sha256(open(executable,"rb").read()).hexdigest())
    yield result
    server.shutdown()


def test_real_chromium_is_bwrapped_and_uses_only_brokered_synthetic_route(profile):
    adapter=BrowserAdapter(profile); session=adapter.create_session()
    try:
        result=adapter.send(session,(DisclosureItem("facts","synthetic",{"summary":"only synthetic"}),))
        assert result.text == "synthetic answer"
    finally: adapter.close(session)


def test_proxy_rejects_cross_origin_paths_and_browser_payload(profile):
    proxy=BrowserProxy(profile)
    with pytest.raises(PolicyError): proxy.fetch({"url":"http://evil.invalid/","method":"GET"},payload="x")
    with pytest.raises(PolicyError): proxy.fetch({"url":profile.provider.origin+"/other","method":"GET"},payload="x")
    with pytest.raises(PolicyError): proxy.fetch({"url":profile.provider.origin+"/","method":"DELETE"},payload="x")
    with pytest.raises(PolicyError): proxy.fetch({"url":profile.provider.origin+"/","method":"POST"},payload="x"*40000)


def test_hash_drift_and_manual_login_are_fail_closed(profile):
    bad=BrowserProfile(profile.provider,profile.allowed_paths,response_selector="#answer",browser_executable=profile.browser_executable,browser_sha256="0"*64)
    with pytest.raises(PolicyError): BrowserAdapter(bad)
    adapter=BrowserAdapter(profile); session=adapter.create_session()
    try:
        with pytest.raises(PolicyError): adapter.manual_login(session)
    finally: adapter.close(session)


def test_bwrap_and_response_caps_are_required(profile, monkeypatch):
    tiny=BrowserProfile(replace(profile.provider,max_response_bytes=8),profile.allowed_paths,response_selector="#answer",browser_executable=profile.browser_executable,browser_sha256=profile.browser_sha256)
    with pytest.raises(PolicyError): BrowserProxy(tiny).fetch({"url":tiny.provider.origin+"/","method":"GET"},payload="x")
    monkeypatch.setenv("PATH","/hostile")
    # Absolute manifest-pinned executable paths do not consult PATH.
    assert BrowserAdapter(profile).bwrap == __import__("pathlib").Path("/usr/bin/bwrap")
