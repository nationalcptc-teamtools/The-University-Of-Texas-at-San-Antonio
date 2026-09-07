"""Fixed audit RPC worker. Only /audit is writable; no evidence read method exists."""
import base64
import json
import resource
import socket
import struct
import sys
sys.path.insert(0, "/pkg")
from cptc_harness.audit import AuditWriter
from cptc_harness.audit_service import receive
from cptc_harness.contracts import AuditEvent, ClockState, canonical_json, to_json
from cptc_harness.policy import parse_policy

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
# age's Go runtime reserves a large virtual arena even for small payloads.
# This is a virtual-address ceiling; each capture remains at most 128 KiB.
resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
channel = socket.socket(fileno=0)
config = json.load(open("/config.json"))
clock_state = ClockState(False, None, "awaiting-host-probe")
writer = AuditWriter("/audit", parse_policy(config["policy"]), age_binary="/age", age_recipient=config["age_recipient"], clock=lambda: clock_state)
methods = {"emit", "capture", "reserve_output", "release_output", "verify", "ready", "encryption_ready", "seal", "result_receipts"}
try:
    while True:
        size = struct.unpack("!I", receive(channel, 4))[0]
        if size > 1048576:
            break
        request = json.loads(receive(channel, size))
        try:
            if set(request) != {"method", "arguments", "clock"}:
                raise ValueError()
            clock_state = ClockState(**request["clock"])
            method, arguments = request["method"], request["arguments"]
            if method == "info" and not arguments:
                result = {"origin_id": writer.origin_id, "evidence_cap": writer.evidence_cap}
            elif method == "close" and not arguments:
                result = None
            elif method in methods:
                if method == "emit":
                    arguments["event"] = AuditEvent(**arguments["event"])
                elif method == "capture":
                    arguments["data"] = base64.b64decode(arguments["data"], validate=True)
                result = getattr(writer, method)(**arguments)
            else:
                raise ValueError()
            response = {"ok": True, "result": to_json(result)}
        except Exception:
            response = {"ok": False, "error": "audit_operation_failed"}
        raw = canonical_json(response)
        channel.sendall(struct.pack("!I", len(raw)) + raw)
        if request.get("method") == "close":
            break
finally:
    writer.close()
    channel.close()
