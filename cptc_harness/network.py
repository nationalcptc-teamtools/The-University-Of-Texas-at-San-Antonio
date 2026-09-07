"""Pinned, direct HTTP transport. It deliberately has no general socket API."""
from __future__ import annotations

from dataclasses import asdict
import base64
import http.client
import ipaddress
import json
import hashlib
import os
import socket
import ssl
import subprocess
import threading
import time
from typing import Any
from urllib.parse import unquote, urlsplit

from .contracts import AuditEvent, NetworkGrant, PolicyError, ScopeSpec, TargetPolicy, TargetRef, TargetRequest, TargetResponse
from .integrity import verified_executable


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, address: str, host: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout); self._address = address
    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, address: str, host: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout); self._address = address
    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _Transport:
    def __init__(self, broker: "NetworkBroker", target: TargetRef, addresses: tuple[str, ...], timeout_s: float, request_limit: int) -> None:
        self._broker, self._target, self._addresses, self._timeout = broker, target, addresses, timeout_s
        self._remaining = request_limit

    def request(self, request: TargetRequest) -> TargetResponse:
        if request.method not in {"GET", "HEAD"}: raise PolicyError("HTTP method is not admitted")
        if request.credential_ref or request.session_ref: raise PolicyError("authentication requires a reviewed credential path")
        if request.body: raise PolicyError("request body is not admitted")
        if self._remaining <= 0:
            raise PolicyError("module request allowance exhausted")
        if not isinstance(request.path, str) or len(request.path) > 2048:
            raise PolicyError("invalid HTTP path")
        if (not request.path.startswith("/") or request.path.startswith("//") or
                any(c in request.path for c in "?#%\\") or any(ord(c) < 33 or ord(c) > 126 for c in request.path) or
                any(p in {".", ".."} for p in request.path.split("/"))):
            raise PolicyError("invalid HTTP path")
        base = self._target.base_path
        if request.path != base and not request.path.startswith(base.rstrip("/") + "/"):
            raise PolicyError("HTTP path is outside the approved application base")
        # No model-controlled outbound headers, query strings or bodies. New
        # profiles must extend a typed capability, never a generic header escape.
        if request.headers:
            raise PolicyError("custom HTTP headers are not admitted")
        if not isinstance(request.max_bytes, int) or isinstance(request.max_bytes, bool) or request.max_bytes <= 0:
            raise PolicyError("invalid response collection allowance")
        self._broker._rate(self._target.target_id)
        self._remaining -= 1
        maximum = min(max(0, request.max_bytes), self._broker.response_limit)
        authority = ("[" + self._target.host + "]") if ":" in self._target.host else self._target.host
        headers = {"Host": authority + ":" + str(self._target.port), "Accept": "application/json, text/plain, */*", "Connection": "close"}
        started = time.monotonic()
        try:
            # One attempt only. A connection failure after a possible request is
            # uncertain and cannot trigger an automatic second target attempt.
            output = self._broker._isolated_http(self._addresses[0], self._target, request.method, request.path, headers, maximum, self._timeout)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            self._broker._stop("network transport failure")
            raise PolicyError("target transport failed") from exc
        self._broker._event("network_response", {"target": self._target.target_id, "address": output.address, "status": output.status,
                                                   "bytes": len(output.body), "truncated": output.truncated})
        if output.status in {423, 429} or output.status >= 500:
            self._broker._stop("target throttle, lockout, or server error")
        if output.truncated: self._broker._stop("response capture cap exceeded")
        return output


class NetworkBroker:
    """Resolves scope once, then connects only to the numeric pinned result."""
    def __init__(self, policy: Any, *, audit: Any | None = None, ledger: Any | None = None,
                 resolver: Any = socket.getaddrinfo, response_limit: int = 32768) -> None:
        self.policy, self.audit, self.ledger, self.resolver = policy, audit, ledger, resolver
        self.response_limit = response_limit
        self._last: dict[str, float] = {}; self._lock = threading.Lock(); self._stopped = False
        self.action_id = None

    def _isolated_http(self, address: str, target: TargetRef, method: str, path: str, headers: dict[str, str],
                       maximum: int, timeout: float) -> TargetResponse:
        """Give the worker only fd 0 for an already-connected scoped socket.

        bwrap creates a new network namespace; inherited fd 0 continues to refer to
        exactly this TCP connection, but the worker cannot create another socket.
        """
        launcher = str(verified_executable("/usr/bin/bwrap"))
        interpreter = str(verified_executable("/usr/bin/python3"))
        self._event("connection_intent", {"address": address, "port": target.port, "target": target.target_id})
        sock = socket.create_connection((address, target.port), timeout=min(timeout, 5))
        sock.setblocking(True)
        request = json.dumps({"scheme": target.scheme, "host": target.host, "method": method, "path": path,
                              "headers": headers, "maximum": maximum, "timeout": timeout}, separators=(",", ":")).encode()
        script = _HTTP_WORKER.encode()
        reqfd = os.memfd_create("cptc-http-request", flags=os.MFD_CLOEXEC); os.write(reqfd, request); os.lseek(reqfd, 0, 0)
        codefd = os.memfd_create("cptc-http-worker", flags=os.MFD_CLOEXEC); os.write(codefd, script); os.lseek(codefd, 0, 0)
        command = [launcher, "--unshare-all", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                   "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev",
                   "--die-with-parent", "--new-session", "--clearenv", "--dir", "/tmp", "--dir", "/etc", "--dir", "/etc/ca-certificates",
                   "--dir", "/etc/ca-certificates/extracted", "--ro-bind", "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
                   "/etc/ca-certificates/extracted/tls-ca-bundle.pem", "--ro-bind-data", str(reqfd), "/request.json", "--ro-bind-data", str(codefd),
                   "/worker.py", "--", interpreter, "-I", "/worker.py"]
        self._event("process_intent", {"worker": "bounded-http-v1", "source_sha256": hashlib.sha256(script).hexdigest(),
            "command": command, "cwd": "/",
            "environment": {}, "address": address, "port": target.port, "method": method, "path": path,
            "timeout_s": timeout, "output_bytes": maximum})
        process = None
        stdout, _stderr = b"", b""
        try:
            process = subprocess.Popen(command, stdin=sock, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, pass_fds=(reqfd, codefd), start_new_session=True, env={})
            self._event("process_started", {"pid": process.pid, "worker": "bounded-http-v1"})
            deadline = time.monotonic() + timeout + 2
            while True:
                if self.ledger is not None and self.ledger.stopped():
                    os.killpg(process.pid, 9); raise OSError("operator stop")
                if time.monotonic() >= deadline:
                    os.killpg(process.pid, 9); raise OSError("network deadline exceeded")
                try:
                    stdout, _stderr = process.communicate(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    continue
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, 9)
                stdout, _stderr = process.communicate()
            sock.close(); os.close(reqfd); os.close(codefd)
            if process is not None:
                if self.audit and self.action_id:
                    self.audit.capture(self.action_id, "stdout", stdout, "restricted_raw")
                    if _stderr:
                        self.audit.capture(self.action_id, "stderr", _stderr, "restricted_raw")
                self._event("process_completed", {"exit_code": process.returncode, "stdout_bytes": len(stdout), "stderr_bytes": len(_stderr)})
        if process.returncode != 0 or len(stdout) > (maximum * 2 + 65536):
            raise OSError("isolated HTTP worker failed")
        decoded = json.loads(stdout)
        if "error" in decoded: raise OSError("isolated HTTP worker rejected response")
        body = base64.b64decode(decoded["body"], validate=True)
        return TargetResponse(int(decoded["status"]), {str(k).lower(): str(v) for k, v in decoded["headers"].items()}, body,
                              float(decoded["elapsed"]), address, bool(decoded["truncated"]))

    def target_transport(self, target: TargetRef, scope: ScopeSpec | None = None, *, timeout_s: float = 30.0, request_limit: int = 1) -> _Transport:
        policy_target = next((t for t in self.policy.targets if t.target.target_id == target.target_id), None)
        if not policy_target or policy_target.target != target:
            raise PolicyError("target does not exactly match policy")
        if target.scheme not in {"http", "https"} or target.port not in range(1, 65536):
            raise PolicyError("target is not typed HTTP")
        parsed = urlsplit(target.canonical_url)
        if parsed.scheme != target.scheme or parsed.hostname != target.host or (parsed.port or (443 if target.scheme == "https" else 80)) != target.port or parsed.username or parsed.password:
            raise PolicyError("invalid canonical target")
        active_scope = scope or self.policy.scope
        addresses = self._resolve(target.host, target.port, active_scope)
        self._event("network_grant", {"target": target.target_id, "addresses": addresses, "port": target.port})
        if type(request_limit) is not int or not 0 <= request_limit <= min(24, policy_target.request_limit):
            raise PolicyError("invalid module traffic allowance")
        return _Transport(self, target, addresses, timeout_s, request_limit)

    def _resolve(self, host: str, port: int, scope: ScopeSpec) -> tuple[str, ...]:
        allowed = tuple(ipaddress.ip_network(c, strict=True) for c in scope.allowed_cidrs)
        excluded = tuple(ipaddress.ip_network(c, strict=True) for c in scope.excluded_cidrs)
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is None:
            if host not in scope.allowed_hosts:
                raise PolicyError("hostname is not explicitly approved before DNS")
        elif any(literal in net for net in excluded) or not any(literal in net for net in allowed):
            raise PolicyError("numeric target is outside approved scope")
        if not allowed:
            raise PolicyError("resolved destinations require approved CIDRs")
        try: records = self.resolver(host, port, type=socket.SOCK_STREAM)
        except OSError as exc: raise PolicyError("DNS resolution failed") from exc
        addresses = tuple(dict.fromkeys(record[4][0] for record in records))
        if not addresses: raise PolicyError("DNS returned no address")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if any(ip in net for net in excluded) or not any(ip in net for net in allowed):
                raise PolicyError("DNS answer is outside approved scope")
        return addresses

    def _rate(self, target_id: str) -> None:
        rate = float(getattr(self.policy, "http_rate", 1.0))
        if rate <= 0 or rate > 1.0: raise PolicyError("invalid HTTP rate policy")
        with self._lock:
            now = time.monotonic(); previous = self._last.get(target_id)
            if previous is not None and now - previous < 1.0 / rate: raise PolicyError("HTTP rate limit")
            if self._stopped or (self.ledger is not None and self.ledger.stopped()): raise PolicyError("network work stopped")
            if self.ledger is not None:
                target = next(t.target for t in self.policy.targets if t.target.target_id == target_id)
                self.ledger.rate_gate(f"{target.scheme}://{target.host}:{target.port}", 1.0 / rate, time.time())
            self._last[target_id] = now

    def _stop(self, reason: str) -> None:
        self._stopped = True
        if self.ledger is not None: self.ledger.stop(reason)
        self._event("network_stop", {"reason": reason})

    def _event(self, kind: str, data: dict[str, Any]) -> None:
        if self.audit is not None: self.audit.emit(AuditEvent(kind, self.action_id, data=data))


_HTTP_WORKER = r'''import base64,http.client,json,resource,socket,ssl,time
try:
 resource.setrlimit(resource.RLIMIT_CORE,(0,0)); resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
 resource.setrlimit(resource.RLIMIT_NOFILE,(32,32)); resource.setrlimit(resource.RLIMIT_CPU,(30,30))
 http.client._MAXLINE=8192; http.client._MAXHEADERS=64
 r=json.load(open("/request.json","r",encoding="utf-8")); raw=socket.socket(fileno=0)
 raw.settimeout(r["timeout"])
 s=ssl.create_default_context(cafile="/etc/ca-certificates/extracted/tls-ca-bundle.pem").wrap_socket(raw,server_hostname=r["host"]) if r["scheme"]=="https" else raw
 lines=[r["method"]+" "+r["path"]+" HTTP/1.1"]+[k+": "+v for k,v in r["headers"].items()]+["",""]
 s.sendall("\r\n".join(lines).encode("ascii")); t=time.monotonic()
 response=http.client.HTTPResponse(s,method=r["method"]); response.begin()
 status=response.status; body=response.read(r["maximum"]+1)
 hdr={k.lower():"<value withheld>" for k,v in response.getheaders()}
 trunc=len(body)>r["maximum"]; body=body[:r["maximum"]]
 print(json.dumps({"status":status,"headers":hdr,"body":base64.b64encode(body).decode(),"truncated":trunc,"elapsed":time.monotonic()-t}))
except Exception: print(json.dumps({"error":"isolated HTTP failure"}))
'''
