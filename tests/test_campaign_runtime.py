"""Real encrypted audit and loopback HTTP; no lab or provider access."""
import http.server
import threading
import time

from cptc_harness.contracts import ClockState, PolicySnapshot, ScopeSpec, TargetPolicy, TargetRef
from cptc_harness.policy import save_policy
from cptc_harness.runtime import Runtime, initialize
from test_integration import age_identity, private


def test_real_wave_preserves_encrypted_evidence_and_one_second_rate(private, age_identity):
    calls = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(time.monotonic())
            self.send_response(200); self.send_header("X-Frame-Options", "DENY")
            self.end_headers(); self.wfile.write(b"synthetic wave response")
        def log_message(self, *args): pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    age, _, recipient = age_identity
    port = server.server_port
    target = TargetRef("fixture", f"http://127.0.0.1:{port}/", "http", "127.0.0.1", port, "/")
    policy = PolicySnapshot("wave-runtime", "r1", "ws", "device", "operator", ScopeSpec(("127.0.0.0/8",)),
        targets=(TargetPolicy(target, eligible=True, profile="synthetic-loopback", assigned_workspace="ws",
                              permitted_modules=("web.headers", "web.session")),),
        window_start="2025-01-01T00:00:00Z", window_end="2030-01-01T00:00:00Z",
        sow_reference="synthetic-sow", roe_reference="synthetic-roe")
    source = private / "policy.json"; save_policy(source, policy)
    root, ledger_root = private / "workspace", private / "device-ledger"
    initialize(root, source, recipient=recipient, age_binary=age)
    runtime = Runtime(root, ledger_root=ledger_root)
    try:
        # Test-only clock attestation for a synthetic loopback fixture. No
        # production CLI flag or host-clock change is introduced.
        runtime.broker.clock = lambda: ClockState(True, 0, "synthetic-fixture")
        plan = runtime.campaign.draft("observations", ["fixture"], ["web.headers", "web.session"])
        runtime.campaign.freeze(plan)
        assert not calls
        status = runtime.campaign.run(plan.wave_id, plan.sha256)
        assert status["status"] == "complete" and len(calls) == 2
        assert calls[1] - calls[0] >= 1
        assert runtime.audit.verify().valid
        report = runtime.report(include_data=True)
        assert report["evidence_index"] and report["model_calls"] == 0
        assert runtime.ledger.usage()["request_limit"] == 2
        runtime.close()
        runtime = Runtime(root, ledger_root=ledger_root)
        runtime.campaign.run(plan.wave_id, plan.sha256)
        assert len(calls) == 2 and runtime.audit.verify().valid
    finally:
        runtime.close(); server.shutdown(); server.server_close()
