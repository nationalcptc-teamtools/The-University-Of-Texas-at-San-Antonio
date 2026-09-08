"""Actual native scanner plus persistent broker, ledger and encrypted audit."""
from datetime import datetime, timedelta, timezone
import socket
import subprocess
import threading
from pathlib import Path
from cptc_harness.contracts import ClockState, PolicySnapshot, ScopeSpec, TargetPolicy, TargetRef
from cptc_harness.policy import save_policy
from cptc_harness.runtime import Runtime, initialize


def test_native_nmap_runtime_reserves_one_probe_and_keeps_audit(tmp_path):
    root = Path(__file__).parents[1]
    tmp_path.chmod(0o700)
    key = tmp_path / "synthetic-age-key"
    subprocess.run([str(root / ".tools/age-keygen"), "-o", str(key)], check=True, capture_output=True)
    recipient = subprocess.run([str(root / ".tools/age-keygen"), "-y", str(key)], check=True, capture_output=True, text=True).stdout.strip()
    server = socket.socket(); server.bind(("127.0.0.1", 0)); server.listen(); server.settimeout(5)
    port = server.getsockname()[1]
    received = []
    def accept():
        conn, _ = server.accept()
        with conn: received.append(conn.recv(1))
    thread = threading.Thread(target=accept, daemon=True); thread.start()
    target = TargetRef("loopback", f"http://127.0.0.1:{port}/", "http", "127.0.0.1", port)
    now = datetime.now(timezone.utc)
    policy = PolicySnapshot("native-synthetic", "r1", "ws", "device", "operator", ScopeSpec(("127.0.0.0/8",)),
        targets=(TargetPolicy(target, True, "synthetic-one-port", "ws", "", ("network.nmap_inventory",), request_limit=1),),
        window_start=(now-timedelta(minutes=1)).isoformat(), window_end=(now+timedelta(minutes=5)).isoformat(),
        sow_reference="synthetic test", roe_reference="synthetic test")
    policy_path = tmp_path / "policy.json"; save_policy(policy_path, policy)
    workspace = tmp_path / "workspace"
    initialize(workspace, policy_path, recipient=recipient, age_binary=root / ".tools/age")
    runtime = Runtime(workspace, ledger_root=tmp_path / "ledger")
    runtime.broker.clock = lambda: ClockState(True, 0.0, "synthetic fixture")
    try:
        result = runtime.run("network.nmap_inventory", target_id="loopback")["result"]
        assert result["status"] == "complete", result["reason"]
        assert result["evidence"] and result["facts"]["observations"][0]["facts"]["ports"][0]["state"] == "open"
        assert runtime.ledger.usage(target_id=f"http://127.0.0.1:{port}")["request_limit"] == 1
        thread.join(timeout=2); assert received == [b""]
        assert runtime.run("network.nmap_inventory", target_id="loopback")["result"]["status"] == "blocked"
        assert runtime.audit.verify().valid
        runtime.report()
    finally:
        runtime.audit.close(); server.close()
