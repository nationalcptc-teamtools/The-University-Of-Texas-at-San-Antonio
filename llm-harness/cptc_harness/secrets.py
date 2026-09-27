"""Operator-only ephemeral secret references, bound to one reviewed provider profile."""
from __future__ import annotations
import array
from dataclasses import asdict
import json
import os
import signal
import socket
import subprocess
from dataclasses import dataclass
from .contracts import PolicyError, canonical_json, digest
from .integrity import verified_executable, verified_worker


@dataclass(frozen=True)
class CredentialRef:
    broker: "SecretBroker"
    reference: str
    profile: object

    def open_fd(self, destination) -> int:
        primary = self.profile
        if (destination.origin != primary.origin or destination.model != primary.model or
                destination.allowed_addresses != primary.allowed_addresses or
                destination.path not in {primary.path, primary.capability_path}):
            raise PolicyError("secret reference is not authorized for this destination")
        return self.broker.grant(self.reference, primary)


class SecretBroker:
    def __init__(self):
        verified_executable("/usr/bin/python3")
        self.channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.channel.settimeout(5)
        worker = verified_worker("secret_worker.py")
        command = [str(verified_executable("/usr/bin/bwrap")), "--unshare-all", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin",
            "--proc", "/proc", "--dev", "/dev", "--ro-bind", str(worker), "/worker.py", "/usr/bin/python3", "-I", "/worker.py"]
        try:
            self.process = subprocess.Popen(command, stdin=child, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, close_fds=True, env={}, start_new_session=True)
        finally:
            child.close()

    def deposit(self, secret: str, profile, *, allowance=12) -> str:
        """Only a human credential input path may call this; no MCP method exposes it."""
        response, descriptor = self._request({"operation": "deposit", "secret": secret,
            "profile_hash": digest(asdict(profile)), "allowance": allowance})
        if descriptor is not None:
            os.close(descriptor)
            raise PolicyError("invalid secret deposit response")
        return response["reference"]

    def grant(self, reference: str, profile) -> int:
        response, descriptor = self._request({"operation": "grant", "reference": reference,
            "profile_hash": digest(asdict(profile))})
        if descriptor is None:
            raise PolicyError("secret broker did not issue an opaque descriptor")
        return descriptor

    def _request(self, request):
        try:
            self.channel.send(canonical_json(request))
            raw, ancillary, flags, address = self.channel.recvmsg(65536, socket.CMSG_SPACE(array.array("i").itemsize))
            descriptor = None
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array("i")
                    values.frombytes(data[:len(data) - len(data) % values.itemsize])
                    if len(values) != 1:
                        for value in values:
                            os.close(value)
                        raise PolicyError("invalid secret descriptor grant")
                    descriptor = values[0]
            result = json.loads(raw)
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or not result.get("ok"):
                if descriptor is not None:
                    os.close(descriptor)
                raise PolicyError("secret grant denied or expired")
            return result, descriptor
        except (OSError, ValueError):
            raise PolicyError("ephemeral secret broker unavailable") from None

    def close(self):
        try:
            self.channel.send(b'{"operation":"close"}')
        except OSError:
            pass
        self.channel.close()
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=2)
        if self.process.stderr:
            self.process.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
