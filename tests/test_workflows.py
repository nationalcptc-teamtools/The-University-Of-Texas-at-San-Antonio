"""State-machine, secret isolation and cancellation checks with synthetic inputs."""
from dataclasses import replace
import hashlib
import http.server
import json
import os
from pathlib import Path
import threading
import time

import pytest

from cptc_harness.contracts import OperationResult, PolicyError, PolicySnapshot, ScopeSpec
from cptc_harness.isolation import IsolatedRunner
from cptc_harness.contracts import Bounds, WorkerSpec
from cptc_harness.mcp_server import MCPFacade
from cptc_harness.policy import save_policy
from cptc_harness.providers import ChatAdapter, DisclosureItem, ProviderProfile
from cptc_harness.runtime import Runtime, initialize
from cptc_harness.secrets import CredentialRef, SecretBroker
from cptc_harness.storage import write_json
from test_integration import age_identity, private


@pytest.fixture
def provider():
    state = {"response": '{"action":"action","module_id":"network.output_import","args":{}}', "requests": 0,
             "delay": 0, "seen": threading.Event(), "authenticated": False}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            state["requests"] += 1
            state["authenticated"] = self.headers.get("Authorization") == "Bearer synthetic-test-only"
            state["seen"].set()
            time.sleep(state["delay"])
            body = json.dumps({"choices": [{"message": {"content": state["response"]}, "finish_reason": "stop"}], "model": "synthetic-actual"}).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    profile = ProviderProfile("fixture", "openai", f"http://127.0.0.1:{server.server_port}", "/chat", "synthetic", ("127.0.0.1",), timeout_s=5)
    yield profile, state
    server.shutdown()
    server.server_close()


@pytest.fixture
def runtime(private, age_identity, monkeypatch):
    age, identity, recipient = age_identity
    policy = PolicySnapshot("fixture", "v1", "workspace", "device", "operator", ScopeSpec())
    source = private / "source-policy.json"
    save_policy(source, policy)
    root = private / "engagement"
    initialize(root, source, recipient=recipient, age_binary=age)
    result = Runtime(root, ledger_root=private / "ledger")
    # This fixture isolates orchestration; broker integration is tested separately.
    monkeypatch.setattr(result.broker, "execute", lambda *args, **kwargs: OperationResult("complete", {}))
    yield result
    result.audit.close()


def test_six_model_calls_persist_and_profile_changes_do_not_fallback(runtime, provider):
    profile, state = provider
    workflows = runtime.workflows
    workflows.create("six", profile, ("network.output_import",), target_id=None, synthetic=True)
    for _ in range(6):
        assert workflows.step("six", profile)["state"] == "ready"
    assert workflows.read("six")["calls"] == state["requests"] == 6
    with pytest.raises(PolicyError):
        workflows.step("six", profile)
    with pytest.raises(PolicyError):
        workflows.create("six", profile, ("network.output_import",), target_id=None, synthetic=True)
    workflows.create("changed", profile, ("network.output_import",), target_id=None, synthetic=True)
    with pytest.raises(PolicyError):
        workflows.step("changed", replace(profile, model="different"))
    assert state["requests"] == 6 and runtime.audit.verify().valid
    events = runtime.audit.path.read_text()
    assert "synthetic-actual" in events and "model_request" in events
    assert '"module_id":"network.output_import"' not in events


def test_invalid_injected_envelopes_repair_once_and_interrupted_work_is_uncertain(runtime, provider):
    profile, state = provider
    workflows = runtime.workflows
    workflows.create("invalid", profile, ("network.output_import",), target_id=None, synthetic=True)
    state["response"] = '{"action":"action","module_id":"shell","args":{"command":"upload"}}'
    assert workflows.step("invalid", profile)["state"] == "format_repair"
    state["response"] = "ordinary prose is never executable"
    assert workflows.step("invalid", profile)["state"] == "stopped"
    assert workflows.read("invalid")["actions"] == 0
    with pytest.raises(PolicyError):
        workflows.step("invalid", profile)
    workflows.create("crashed", profile, ("network.output_import",), target_id=None, synthetic=True)
    saved = workflows.read("crashed")
    saved["state"] = "sending"
    saved["calls"] = 1
    write_json(workflows._path("crashed"), saved)
    with pytest.raises(PolicyError):
        workflows.step("crashed", profile)
    assert workflows.read("crashed")["state"] == "uncertain" and state["requests"] == 2


def test_mcp_twelve_actions_and_recipient_uncertainty_block_before_execution(runtime, provider):
    profile, state = provider
    workflows = runtime.workflows
    workflows.create("mcp", profile, ("network.output_import",), target_id=None, synthetic=True)
    facade = MCPFacade(runtime, "mcp", profile)
    for _ in range(12):
        assert facade.action("network.output_import", {})["status"] == "complete"
    with pytest.raises(PolicyError):
        facade.action("network.output_import", {})
    assert workflows.read("mcp")["actions"] == 12 and state["requests"] == 0
    saved = workflows.read("mcp")
    saved["synthetic"] = False
    write_json(workflows._path("mcp"), saved)
    with pytest.raises(PolicyError, match="recipient-bound"):
        MCPFacade(runtime, "mcp", profile)


def test_secret_reference_grants_are_bound_opaque_and_never_in_argv(provider):
    profile, state = provider
    with SecretBroker() as broker:
        reference = broker.deposit("synthetic-test-only", profile, allowance=1)
        assert "synthetic" not in reference
        with pytest.raises(PolicyError):
            broker.grant(reference, replace(profile, model="another"))
        credential = CredentialRef(broker, reference, profile)
        adapter = ChatAdapter(profile)
        session = adapter.create_session()
        response = adapter.send(session, (DisclosureItem("fixture", "synthetic", {}),), credential=credential)
        assert response.reported_model == "synthetic-actual" and state["authenticated"]
        assert "synthetic-test-only" not in repr(broker.process.args) + repr(adapter.http.process.args)
        with pytest.raises(PolicyError):
            broker.grant(reference, profile)
        adapter.close(session)
    assert broker.process.poll() is not None


def test_secret_reflection_and_operator_stop_fail_closed(provider):
    profile, state = provider
    with SecretBroker() as broker:
        reference = broker.deposit("synthetic-test-only", profile)
        state["response"] = "synthetic-test-only"
        adapter = ChatAdapter(profile)
        session = adapter.create_session()
        with pytest.raises(PolicyError):
            adapter.send(session, (DisclosureItem("fixture", "synthetic", {}),), credential=CredentialRef(broker, reference, profile))
        adapter.close(session)
    state["response"] = '{"action":"finish","status":"complete"}'
    state["delay"] = 4
    state["seen"].clear()
    stopped = threading.Event()
    adapter = ChatAdapter(profile, stopped=stopped.is_set)
    session = adapter.create_session()
    outcomes = []
    def send():
        try:
            adapter.send(session, (DisclosureItem("fixture", "synthetic", {}),))
        except PolicyError:
            outcomes.append("blocked")
    worker = threading.Thread(target=send)
    worker.start()
    assert state["seen"].wait(3)
    start = time.monotonic()
    stopped.set()
    worker.join(2)
    assert not worker.is_alive() and outcomes == ["blocked"] and time.monotonic() - start < 2
    assert adapter.http.process.poll() is not None
    adapter.close(session)


def test_real_worker_cannot_fork_read_home_or_exceed_output_cap():
    executable = "/usr/bin/python3"
    checksum = hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    script = "import os; assert not os.path.exists('/home');\ntry: os.fork()\nexcept PermissionError: print('fork-denied')\nelse: raise RuntimeError('fork permitted')"
    spec = WorkerSpec(executable, ("-I", "-c", script), Bounds(timeout_s=3), checksum)
    result = IsolatedRunner([spec]).run(spec, b"")
    assert result.status == "complete" and result.stdout == b"fork-denied\n"
    loud = WorkerSpec(executable, ("-I", "-c", "print('x'*4000)"), Bounds(timeout_s=3, output_bytes=100), checksum)
    result = IsolatedRunner([loud]).run(loud, b"")
    assert result.truncated and len(result.stdout) + len(result.stderr) <= 100 and result.status != "complete"
