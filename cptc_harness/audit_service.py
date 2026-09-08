"""Single networkless audit process; callers have no raw-evidence read RPC."""
from __future__ import annotations
from .memfd import memfd_create, MFD_CLOEXEC, MFD_ALLOW_SEALING, seal_readonly, write_all
import base64
from dataclasses import asdict
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
from .clockcheck import ClockService
from .contracts import AuditSeal, AuditVerification, EvidenceRef, PolicyError, canonical_json, to_json
from .integrity import verified_executable, verified_worker
from .storage import private_directory


def receive(channel, count):
    result = bytearray()
    while len(result) < count:
        chunk = channel.recv(count - len(result))
        if not chunk:
            raise OSError("audit IPC closed")
        result.extend(chunk)
    return bytes(result)


class AuditService:
    def __init__(self, root, policy, *, age_binary, age_recipient):
        self.root = private_directory(Path(root), create=True)
        self.path, self.transcript_path = self.root / "audit.jsonl", self.root / "transcript.log"
        self.clock = ClockService()
        self._lock = threading.Lock()
        self._closed = False
        self.channel = None
        self.process = None
        parent = child = None
        config = None
        process = None
        try:
            parent, child = socket.socketpair()
            parent.settimeout(30)
            config = memfd_create("cptc-audit-config", MFD_CLOEXEC | MFD_ALLOW_SEALING)
            write_all(config, canonical_json({"policy": asdict(policy), "age_recipient": age_recipient}))
            os.lseek(config, 0, os.SEEK_SET)
            seal_readonly(config)
            worker = verified_worker("audit_worker.py")
            command = [str(verified_executable("/usr/bin/bwrap")), "--unshare-all", "--die-with-parent", "--cap-drop", "ALL", "--clearenv",
                       "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin",
                       "--proc", "/proc", "--dev", "/dev", "--ro-bind", str(Path(__file__).parent), "/pkg/cptc_harness",
                       "--bind", str(self.root), "/audit", "--ro-bind", str(Path(age_binary).resolve()), "/age",
                       "--ro-bind-data", str(config), "/config.json", "--ro-bind", str(worker), "/worker.py",
                       str(verified_executable("/usr/bin/python3")), "-I", "/worker.py"]
            process = subprocess.Popen(command, stdin=child, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       pass_fds=(config,), close_fds=True, env={}, start_new_session=True)
            child.close(); child = None
            os.close(config); config = None
            self.channel, parent = parent, None
            self.process, process = process, None
            info = self._request("info")
            self.origin_id, self.evidence_cap = info["origin_id"], info["evidence_cap"]
        except Exception:
            self._closed = True
            if process is not None:
                self._terminate_reap(process)
            if self.process is not None:
                self._terminate_reap(self.process)
                self.process = None
            for resource in (child, parent, self.channel):
                if resource is not None:
                    try: resource.close()
                    except OSError: pass
            self.channel = None
            if config is not None:
                try: os.close(config)
                except OSError: pass
            raise

    @staticmethod
    def _terminate_reap(process) -> None:
        try:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    try: process.kill()
                    except (ProcessLookupError, OSError): pass
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _request(self, method, **arguments):
        with self._lock:
            if self._closed:
                raise PolicyError("audit service is closed")
            raw = canonical_json({"method": method, "arguments": arguments, "clock": asdict(self.clock())})
            if len(raw) > 1048576:
                raise PolicyError("audit IPC collection allowance exceeded")
            try:
                self.channel.sendall(struct.pack("!I", len(raw)) + raw)
                size = struct.unpack("!I", receive(self.channel, 4))[0]
                if size > 1048576:
                    raise PolicyError("audit IPC response allowance exceeded")
                result = json.loads(receive(self.channel, size))
                if result.get("ok") is not True:
                    raise PolicyError("audit service rejected the operation; operator review required")
                return result["result"]
            except (OSError, ValueError):
                raise PolicyError("durable audit service unavailable") from None

    def emit(self, event):
        return self._request("emit", event=to_json(event))

    def result_receipts(self):
        return self._request("result_receipts")

    def publication_receipts(self):
        return self._request("publication_receipts")

    def control_receipts(self):
        return self._request("control_receipts")

    def capture(self, request_id, stream, data, classification):
        return EvidenceRef(**self._request("capture", request_id=request_id, stream=stream,
                            data=base64.b64encode(data).decode(), classification=classification))

    def reserve_output(self, request_id, maximum):
        self._request("reserve_output", request_id=request_id, maximum=maximum)

    def release_output(self, request_id):
        self._request("release_output", request_id=request_id)

    def verify(self):
        return AuditVerification(**self._request("verify"))

    def ready(self):
        return self._request("ready")

    def encryption_ready(self):
        return self._request("encryption_ready")

    def seal(self):
        result = self._request("seal")
        result["manifest_path"] = str(self.root / "audit.manifest.json")
        return AuditSeal(**result)

    rotate = seal

    def close(self):
        if self._closed:
            return
        try:
            self._request("close")
        except Exception:
            pass
        self._closed = True
        if self.channel is not None:
            self.channel.close()
        if self.process is not None:
            self._terminate_reap(self.process)
