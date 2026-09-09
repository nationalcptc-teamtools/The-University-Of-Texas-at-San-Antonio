"""Pinned, direct HTTP transport. It deliberately has no general socket API."""
from __future__ import annotations
from .memfd import memfd_create, MFD_CLOEXEC, MFD_ALLOW_SEALING, seal_readonly, write_all

from dataclasses import asdict
import base64
from contextlib import ExitStack
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
from .response_capture import RAW_RESPONSE_WORKER


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
        self._attempt_sequence = 0

    def _begin_attempt(self):
        ledger, action_id = self._broker.ledger, self._broker.action_id
        self._attempt_sequence += 1
        attempt_id = hashlib.sha256(
            f"{action_id or '-'}\0{self._target.target_id}\0{self._attempt_sequence}".encode("utf-8")
        ).hexdigest()[:32]
        started_ns = time.monotonic_ns()
        deadline_ns = started_ns + int(self._timeout * 1_000_000_000)
        if ledger is not None and action_id is not None:
            ledger.begin_attempt(action_id, attempt_id, started_ns=started_ns, deadline_ns=deadline_ns)
        if time.monotonic_ns() >= deadline_ns:
            self._finish_attempt(attempt_id if ledger is not None and action_id is not None else None, "blocked")
            self._broker._stop("network deadline reached before dispatch")
            raise PolicyError("network deadline reached before dispatch")
        return (attempt_id if ledger is not None and action_id is not None else None), deadline_ns

    @staticmethod
    def _remaining_timeout(deadline_ns: int) -> float:
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise PolicyError("network deadline reached before dispatch")
        return remaining

    def _record_request(self, attempt_id: str | None, size: int) -> None:
        if attempt_id is not None:
            self._broker.ledger.record_attempt_event(
                self._broker.action_id, attempt_id, "completed-request",
                tcp_connects=1, protocol_requests=1, tx_bytes=size,
            )

    def _record_response(self, attempt_id: str | None, size: int) -> None:
        if attempt_id is not None and size:
            self._broker.ledger.record_attempt_event(
                self._broker.action_id, attempt_id, "response", rx_bytes=size,
            )

    def _finish_attempt(self, attempt_id: str | None, state: str) -> None:
        if attempt_id is not None:
            self._broker.ledger.finish_attempt(
                self._broker.action_id, attempt_id, state=state, ended_ns=time.monotonic_ns(),
            )

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
        wire = ("\r\n".join([request.method + " " + request.path + " HTTP/1.1",
                              *[key + ": " + value for key, value in headers.items()], "", ""])).encode("ascii")
        attempt_id, deadline_ns = self._begin_attempt()
        try:
            # One attempt only. A connection failure after a possible request is
            # uncertain and cannot trigger an automatic second target attempt.
            output = self._broker._isolated_http(
                self._addresses[0], self._target, request.method, request.path, headers,
                maximum, self._remaining_timeout(deadline_ns),
            )
        except (OSError, ValueError, subprocess.SubprocessError, PolicyError) as exc:
            self._finish_attempt(attempt_id, "uncertain")
            self._broker._stop("network transport failure")
            raise PolicyError("target transport failed") from exc
        try:
            self._record_request(attempt_id, len(wire))
            self._record_response(attempt_id, len(output.body))
            self._finish_attempt(attempt_id, "complete")
        except PolicyError as exc:
            self._finish_attempt(attempt_id, "uncertain")
            self._broker._stop("network accounting failure")
            raise PolicyError("target transport accounting failed") from exc
        self._broker._event("network_response", {"target": self._target.target_id, "address": output.address, "status": output.status,
                                                   "bytes": len(output.body), "truncated": output.truncated})
        if output.status in {423, 429} or output.status >= 500:
            self._broker._stop("target throttle, lockout, or server error")
        if output.truncated: self._broker._stop("response capture cap exceeded")
        return output

    def capture_response(self) -> bytes:
        """Make one fixed base-path GET and return its complete raw HTTP response."""
        if self._remaining <= 0:
            raise PolicyError("module request allowance exhausted")
        path = self._target.base_path
        if (not isinstance(path, str) or len(path) > 2048 or not path.startswith("/") or path.startswith("//") or
                any(c in path for c in "?#%\\") or any(ord(c) < 33 or ord(c) > 126 for c in path) or
                any(part in {".", ".."} for part in path.split("/"))):
            raise PolicyError("response capture base path is invalid")
        self._broker._rate(self._target.target_id)
        self._remaining -= 1
        authority = ("[" + self._target.host + "]") if ":" in self._target.host else self._target.host
        wire = ("GET " + path + " HTTP/1.1\r\nHost: " + authority + ":" + str(self._target.port)
                + "\r\nConnection: close\r\n\r\n").encode("ascii")
        attempt_id, deadline_ns = self._begin_attempt()
        try:
            response = self._broker._isolated_response(
                self._addresses[0], self._target, self._remaining_timeout(deadline_ns),
            )
            self._record_request(attempt_id, len(wire))
            self._record_response(attempt_id, len(response))
            self._finish_attempt(attempt_id, "complete")
            return response
        except (OSError, ValueError, subprocess.SubprocessError, PolicyError) as exc:
            self._finish_attempt(attempt_id, "uncertain")
            self._broker._stop("response capture transport failure")
            raise PolicyError("response capture transport failed") from exc


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
        started, deadline = time.monotonic(), time.monotonic() + timeout
        launcher = str(verified_executable("/usr/bin/bwrap")); interpreter = str(verified_executable("/usr/bin/python3"))
        request = json.dumps({"scheme": target.scheme, "host": target.host, "method": method, "path": path,
                              "headers": headers, "maximum": maximum, "timeout": timeout}, separators=(",", ":")).encode()
        script = _HTTP_WORKER.encode(); process = None; stdout = _stderr = b""; completed = False
        with ExitStack() as cleanup:
            self._event("connection_intent", {"address": address, "port": target.port, "target": target.target_id})
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise OSError("network deadline exceeded")
            sock = socket.create_connection((address, target.port), timeout=min(remaining, 5)); cleanup.callback(sock.close); sock.setblocking(True)
            reqfd = memfd_create("cptc-http-request", flags=MFD_CLOEXEC | MFD_ALLOW_SEALING); cleanup.callback(os.close, reqfd); write_all(reqfd, request); os.lseek(reqfd, 0, os.SEEK_SET); seal_readonly(reqfd)
            codefd = memfd_create("cptc-http-worker", flags=MFD_CLOEXEC | MFD_ALLOW_SEALING); cleanup.callback(os.close, codefd); write_all(codefd, script); os.lseek(codefd, 0, os.SEEK_SET); seal_readonly(codefd)
            command = [launcher, "--unshare-all", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev", "--die-with-parent", "--new-session", "--clearenv", "--dir", "/tmp", "--dir", "/etc", "--dir", "/etc/ca-certificates", "--dir", "/etc/ca-certificates/extracted", "--ro-bind", "/etc/ca-certificates/extracted/tls-ca-bundle.pem", "/etc/ca-certificates/extracted/tls-ca-bundle.pem", "--ro-bind-data", str(reqfd), "/request.json", "--ro-bind-data", str(codefd), "/worker.py", "--", interpreter, "-I", "/worker.py"]
            self._event("process_intent", {"worker": "bounded-http-v1", "source_sha256": hashlib.sha256(script).hexdigest(), "command": command, "cwd": "/", "environment": {}, "address": address, "port": target.port, "method": method, "path": path, "timeout_s": timeout, "output_bytes": maximum})
            try:
                process = subprocess.Popen(command, stdin=sock, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, pass_fds=(reqfd, codefd), start_new_session=True, env={})
                cleanup.callback(process.stdout.close)
                cleanup.callback(process.stderr.close)
                self._event("process_started", {"pid": process.pid, "worker": "bounded-http-v1"})
                while True:
                    if self.ledger is not None and self.ledger.stopped(): raise OSError("operator stop")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0: raise OSError("network deadline exceeded")
                    try:
                        stdout, _stderr = process.communicate(timeout=min(0.1, remaining)); completed = True; break
                    except subprocess.TimeoutExpired: continue
            finally:
                if process is not None and not completed:
                    try:
                        if process.poll() is None:
                            try:
                                os.killpg(process.pid, 9)
                            except ProcessLookupError:
                                pass
                            except OSError:
                                process.kill()
                        stdout, _stderr = process.communicate(timeout=1)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        raise OSError("worker containment cleanup failed") from exc
                if process is not None:
                    if self.audit and self.action_id:
                        self.audit.capture(self.action_id, "stdout", stdout, "restricted_raw")
                        if _stderr: self.audit.capture(self.action_id, "stderr", _stderr, "restricted_raw")
                    self._event("process_completed", {"exit_code": process.returncode, "stdout_bytes": len(stdout), "stderr_bytes": len(_stderr), "duration_ms": int((time.monotonic()-started)*1000)})
        if time.monotonic() > deadline:
            raise OSError("network deadline exceeded")
        if process.returncode != 0 or len(stdout) > (maximum * 2 + 65536):
            raise OSError("isolated HTTP worker failed")
        decoded = json.loads(stdout)
        if "error" in decoded: raise OSError("isolated HTTP worker rejected response")
        body = base64.b64decode(decoded["body"], validate=True)
        return TargetResponse(int(decoded["status"]), {str(k).lower(): str(v) for k, v in decoded["headers"].items()}, body,
                              float(decoded["elapsed"]), address, bool(decoded["truncated"]))

    def _isolated_response(self, address: str, target: TargetRef, timeout: float) -> bytes:
        """Give a one-shot, raw-response worker only one already-connected socket."""
        launcher = str(verified_executable("/usr/bin/bwrap"))
        interpreter = str(verified_executable("/usr/bin/python3"))
        authority = ("[" + target.host + "]") if ":" in target.host else target.host
        request = json.dumps({"scheme": target.scheme, "host": target.host, "authority": authority + ":" + str(target.port),
                              "path": target.base_path or "/", "timeout": min(timeout, 30.0)}, separators=(",", ":")).encode()
        script = RAW_RESPONSE_WORKER.encode()
        started = time.monotonic()
        process = None
        stdout = stderr = captured_out = captured_err = b""
        communicated = False
        def record(stream, current, previous):
            if not current.startswith(previous):
                raise OSError("response worker stream changed unexpectedly")
            limit = 32768 if stream == "stdout" else 256
            retained = current[:limit]
            delta = retained[len(previous):]
            if delta and self.audit is not None and self.action_id is not None:
                self.audit.capture(self.action_id, stream, delta, "client_confidential_human_only")
            if len(current) > limit:
                self._event("response_capture_incomplete", {"stream": stream, "retained_bytes": len(retained)})
                raise OSError("response worker stream allowance exceeded")
            return current

        # Register cleanup immediately after each acquisition, including failures
        # in allocation, intent logging, connect, launch, capture and reaping.
        with ExitStack() as resources:
            def memfd(name, payload):
                descriptor = memfd_create(name, flags=MFD_CLOEXEC | MFD_ALLOW_SEALING)
                resources.callback(os.close, descriptor)
                write_all(descriptor, payload)
                os.lseek(descriptor, 0, os.SEEK_SET)
                seal_readonly(descriptor)
                return descriptor
            reqfd = memfd("cptc-response-request", request)
            codefd = memfd("cptc-response-worker", script)
            command = [launcher, "--unshare-all", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                       "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev",
                       "--die-with-parent", "--new-session", "--clearenv", "--dir", "/tmp", "--dir", "/etc", "--dir", "/etc/ca-certificates",
                       "--dir", "/etc/ca-certificates/extracted", "--ro-bind", "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
                       "/etc/ca-certificates/extracted/tls-ca-bundle.pem", "--ro-bind-data", str(reqfd), "/request.json", "--ro-bind-data", str(codefd),
                       "/worker.py", "--", interpreter, "-I", "/worker.py"]
            self._event("response_capture_process_intent", {"target": target.target_id, "address": address, "port": target.port,
                        "path": target.base_path or "/", "timeout_s": timeout, "raw_limit": 32768,
                        "source_sha256": hashlib.sha256(script).hexdigest(), "command": command, "cwd": "/", "environment": {}})
            self._event("response_capture_connection_intent", {"target": target.target_id, "address": address, "port": target.port})
            sock = resources.enter_context(socket.create_connection((address, target.port), timeout=min(timeout, 5)))
            try:
                process = subprocess.Popen(command, stdin=sock, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                           pass_fds=(reqfd, codefd), start_new_session=True, env={})
                resources.callback(process.stdout.close)
                resources.callback(process.stderr.close)
                self._event("response_capture_process_started", {"pid": process.pid})
                deadline = started + timeout
                while True:
                    if self.ledger is not None and self.ledger.stopped():
                        raise OSError("operator stop")
                    if time.monotonic() >= deadline:
                        raise OSError("response capture deadline exceeded")
                    try:
                        stdout, stderr = process.communicate(timeout=min(0.1, max(0.001, deadline-time.monotonic())))
                        communicated = True
                        captured_out = record("stdout", stdout, captured_out)
                        captured_err = record("stderr", stderr, captured_err)
                        break
                    except subprocess.TimeoutExpired as exc:
                        captured_out = record("stdout", exc.output or b"", captured_out)
                        captured_err = record("stderr", exc.stderr or b"", captured_err)
            finally:
                if process is not None:
                    try:
                        if process.poll() is None:
                            try:
                                os.killpg(process.pid, 9)
                            except ProcessLookupError:
                                pass
                        if not communicated:
                            stdout, stderr = process.communicate(timeout=2)
                            captured_out = record("stdout", stdout, captured_out)
                            captured_err = record("stderr", stderr, captured_err)
                    finally:
                        self._event("response_capture_completed", {"exit_code": process.poll(),
                                    "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                                    "duration_ms": int((time.monotonic()-started)*1000),
                                    "capture_incomplete": stderr != b'{"complete":true}'})
        if process is None or process.returncode != 0 or len(stdout) > 32768:
            raise OSError("response capture worker failed")
        try:
            result = json.loads(stderr)
            if result != {"complete": True}: raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise OSError("response capture worker output invalid") from None
        return stdout

    def target_transport(self, target: TargetRef, scope: ScopeSpec | None = None, *, timeout_s: float = 30.0, request_limit: int = 1) -> _Transport:
        policy_target = next((t for t in self.policy.targets if t.target.target_id == target.target_id), None)
        if not policy_target or policy_target.target != target:
            raise PolicyError("target does not exactly match policy")
        if target.scheme not in {"http", "https"} or target.port not in range(1, 65536):
            raise PolicyError("target is not typed HTTP")
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or not 0 < timeout_s <= 3600:
            raise PolicyError("invalid module network deadline")
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
