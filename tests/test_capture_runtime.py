"""One real contained loopback capture feeds both networkless passive tools."""
from datetime import datetime, timedelta, timezone
import http.server
import threading

from cptc_harness.contracts import ClockState, OperationRequest, PolicySnapshot, ScopeSpec, TargetPolicy, TargetRef
from cptc_harness.operator_replay import replay_capture
from cptc_harness.policy import save_policy
from cptc_harness.runtime import Runtime, initialize
from test_integration import age_identity, private


def test_operator_capture_replays_without_additional_requests(private, age_identity):
    age, identity, recipient = age_identity
    seen = []
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            seen.append((self.command, self.path))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", "synthetic-session=private; HttpOnly")
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *_): pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    target = TargetRef("loopback", f"http://127.0.0.1:{port}/fixture", "http", "127.0.0.1", port, "/fixture")
    now = datetime.now(timezone.utc)
    policy = PolicySnapshot("capture-runtime-fixture", "r1", "ws", "dev", "operator", ScopeSpec(("127.0.0.0/8",)),
        targets=(TargetPolicy(target, True, "synthetic-one-response", "ws", "", ("web.response_capture",), request_limit=1),),
        window_start=(now-timedelta(minutes=1)).isoformat(), window_end=(now+timedelta(minutes=5)).isoformat(),
        sow_reference="synthetic fixture", roe_reference="synthetic fixture")
    policy_path = private / "policy.json"
    save_policy(policy_path, policy)
    initialize(private / "workspace", policy_path, recipient=recipient, age_binary=age)
    runtime = Runtime(private / "workspace", ledger_root=private / "ledger")
    runtime.broker.clock = lambda: ClockState(True, 0, "synthetic fixture")
    try:
        denied = runtime.broker.execute(OperationRequest("model-request", "ws", "dev", "operator", "web.response_capture",
                                           target, {}, "model", None, "r1"), actor="model")
        assert denied.status == "blocked" and not seen
        record = runtime.run("web.response_capture", target_id="loopback")
        assert record["result"]["status"] == "complete", record["result"]["reason"]
        evidence = next(item for item in record["result"]["evidence"] if item["check_id"] == "response")
        assert evidence["artifact_relpath"].endswith(".age")
        for module in ("web.nuclei_observation", "web.zap_observation"):
            result = replay_capture(runtime, module_id=module, action_id=record["request"]["request_id"],
                                    evidence_id=evidence["evidence_id"], identity=identity)
            assert result["result"]["status"] == "complete", result["result"]["reason"]
            assert result["result"]["facts"]["observations"]
        assert seen == [("GET", "/fixture")]
        assert runtime.ledger.usage(target_id=f"http://127.0.0.1:{port}")["request_limit"] == 1
        assert runtime.run("web.response_capture", target_id="loopback")["result"]["status"] == "blocked"
        assert runtime.audit.verify().valid
        assert b"synthetic-session" not in runtime.audit.transcript_path.read_bytes()
        runtime.report()
    finally:
        runtime.audit.close()
        server.shutdown()
        server.server_close()
