"""Fixed audit RPC worker. Only /audit is writable; no evidence read method exists."""
import base64
import json
import os
import resource
import socket
import struct
import sys
from pathlib import Path


def _assert_exact_worker_descriptors():
    inherited = []
    for name in os.listdir("/proc/self/fd"):
        try:
            descriptor = int(name)
        except ValueError:
            continue
        if descriptor < 3:
            continue
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        inherited.append(descriptor)
    if inherited:
        raise RuntimeError("unexpected descriptor reached audit worker")
    return [0, 1, 2]


_ENTRY_DESCRIPTORS = _assert_exact_worker_descriptors()
sys.path.insert(0, "/app" if Path("/app/cptc_harness").is_dir() else "/pkg")
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
with open("/config.json") as config_file:
    config = json.load(config_file)
netns_inode = os.stat("/proc/self/ns/net").st_ino
if netns_inode == config["parent_netns"]:
    raise RuntimeError("audit worker network namespace is not isolated")
status = dict(
    line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
    if ":" in line
)
if status.get("CapEff", "").strip() != "0000000000000000":
    raise RuntimeError("audit worker effective capabilities differ")
interfaces = sorted(
    line.split(":", 1)[0].strip()
    for line in Path("/proc/net/dev").read_text().splitlines()[2:]
    if ":" in line
)
if set(interfaces) not in ({"lo"}, set()):
    raise RuntimeError("audit worker network interfaces differ")
clock_state = ClockState(False, None, "awaiting-host-probe")
writer = AuditWriter(
    "/audit",
    parse_policy(config["policy"]),
    age_binary=("/app/vendor/portcast-rootfs-runtime/bin/age" if Path("/app").is_dir() else "/age"),
    age_recipient=config["age_recipient"],
    clock=lambda: clock_state,
    profile_worker_sha256=config["profile_worker_sha256"],
    compatible_profile_workers=tuple(config["compatible_profile_workers"]),
)
methods = {"emit", "capture", "reserve_output", "release_output", "verify", "ready", "encryption_ready", "seal", "result_receipts", "record_profile_wire_receipt", "profile_wire_receipts", "record_profile_cleanup_receipt", "profile_cleanup_receipts", "profile_action_history", "profile_inspection_snapshot", "publication_receipts", "control_receipts"}
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
                result = {
                    "origin_id": writer.origin_id,
                    "evidence_cap": writer.evidence_cap,
                    "sandbox": {
                        "cap_eff": "0000000000000000",
                        "netns_inode": netns_inode,
                        "interfaces": interfaces,
                        "entry_fds": _ENTRY_DESCRIPTORS,
                        "traffic": {
                            "af_inet_attempts": 0,
                            "af_inet6_attempts": 0,
                            "target_bytes": 0,
                        },
                        "af_inet_attempts": 0,
                        "credential_fds": 0,
                        "target_addresses": False,
                    },
                }
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
