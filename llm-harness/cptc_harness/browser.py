"""Brokered Playwright sessions. The browser has no network namespace egress."""
from __future__ import annotations

from dataclasses import dataclass
import base64, hashlib, http.client, json, os, shutil, signal, socket, subprocess, threading, time, uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .contracts import PolicyError
from .providers import DisclosureGate, DisclosureItem, ProviderProfile, ProviderResponse, validate_profile
from .integrity import verified_executable, verified_worker


@dataclass(frozen=True)
class BrowserProfile:
    provider: ProviderProfile
    allowed_paths: tuple[str, ...]
    login_path: str | None = None
    prompt_selector: str = ""
    submit_selector: str = ""
    response_selector: str = ""
    browser_executable: str = "/usr/lib/chromium/chromium"
    browser_sha256: str = ""
    headed_allowed: bool = False

    def validate(self) -> "BrowserProfile":
        validate_profile(self.provider)
        if self.provider.kind != "browser" or not self.allowed_paths or not self.response_selector:
            raise PolicyError("browser profile requires a reviewed browser provider and routes")
        if self.provider.approved_client:
            raise PolicyError("browser client data requires a future signed live capability attestation")
        paths=set()
        for path in self.allowed_paths:
            if not isinstance(path,str) or not path.startswith("/") or "?" in path or "#" in path or "\\" in path or ".." in path or path in paths:
                raise PolicyError("browser route is not fixed")
            paths.add(path)
        if self.login_path is not None and self.login_path not in paths:
            raise PolicyError("browser login route is not reviewed")
        if self.provider.path not in paths:
            raise PolicyError("browser inference path is not reviewed")
        executable=Path(self.browser_executable)
        if executable != Path("/usr/lib/chromium/chromium") or not executable.is_file() or not self.browser_sha256 or hashlib.sha256(executable.read_bytes()).hexdigest()!=self.browser_sha256:
            raise PolicyError("browser executable hash does not match profile")
        for selector in (self.prompt_selector,self.submit_selector,self.response_selector):
            if not isinstance(selector,str) or len(selector)>256 or "\n" in selector or "\r" in selector:
                raise PolicyError("browser selector is invalid")
        if bool(self.prompt_selector) != bool(self.submit_selector): raise PolicyError("browser form selectors must be paired")
        return self


class BrowserProxy:
    """Parent-only exact-origin route broker; browser route payloads are discarded."""
    def __init__(self, profile: BrowserProfile) -> None:
        self.profile=profile.validate(); self.provider=self.profile.provider
        self.requests = 0
        self.posts = 0
        self.request_bytes = 0
        self.response_bytes = 0

    def fetch(self, route: dict[str, Any], *, payload: str) -> dict[str, Any]:
        parsed=urlsplit(str(route.get("url",""))); origin=urlsplit(self.provider.origin)
        port=parsed.port or (443 if parsed.scheme=="https" else 80)
        expected=origin.port or (443 if origin.scheme=="https" else 80)
        method=str(route.get("method","")).upper()
        if (parsed.scheme,parsed.hostname,port)!=(origin.scheme,origin.hostname,expected) or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in self.profile.allowed_paths or method not in {"GET", "POST"}:
            raise PolicyError("browser route is outside reviewed proxy allowlist")
        if method == "POST" and (parsed.path != self.provider.path or self.posts >= 1):
            raise PolicyError("one reviewed inference POST is allowed per browser session")
        if self.requests >= 24:
            raise PolicyError("browser route allowance exhausted")
        # Ignore browser-provided query/body/headers. The parent rebuilds the sole admitted POST payload.
        body=json.dumps({"prompt":payload},separators=(",",":"),ensure_ascii=True).encode() if method == "POST" else b""
        if self.request_bytes + len(body)>self.provider.max_request_bytes: raise PolicyError("browser request cap exceeded")
        self.requests += 1
        self.posts += method == "POST"
        self.request_bytes += len(body)
        try: answers=socket.getaddrinfo(origin.hostname,expected,type=socket.SOCK_STREAM)
        except OSError as exc: raise PolicyError("browser provider DNS failed") from exc
        if not answers or any(item[4][0] not in self.provider.allowed_addresses for item in answers):
            raise PolicyError("browser provider address pin mismatch")
        answer=answers[0]
        try:
                sock=socket.socket(answer[0],answer[1],answer[2]); sock.settimeout(min(self.provider.timeout_s,10)); sock.connect(answer[4])
                conn=http.client.HTTPSConnection(origin.hostname,expected,timeout=self.provider.timeout_s) if origin.scheme=="https" else http.client.HTTPConnection(origin.hostname,expected,timeout=self.provider.timeout_s)
                if origin.scheme=="https":
                    import ssl; conn.sock=ssl.create_default_context().wrap_socket(sock,server_hostname=origin.hostname)
                    if self.provider.certificate_sha256 and hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()!=self.provider.certificate_sha256: raise PolicyError("browser certificate pin mismatch")
                else: conn.sock=sock
                conn.request(method,parsed.path,body=body,headers={"Accept":"text/html,application/json","Content-Type":"application/json","Connection":"close"})
                response=conn.getresponse(); raw=response.read(self.provider.max_response_bytes+1); headers={k.lower():v for k,v in response.getheaders()}; conn.close()
                self.response_bytes += len(raw)
                if response.status<200 or response.status>=300 or self.response_bytes>self.provider.max_response_bytes: raise PolicyError("browser route response is not admitted")
                return {"status":response.status,"headers":{k:v for k,v in headers.items() if k in {"content-type","cache-control"}},"body":base64.b64encode(raw).decode()}
        except (OSError,http.client.HTTPException) as exc: raise PolicyError("browser proxy transport failed; no automatic retry") from exc


class BrowserAdapter:
    def __init__(self, profile: BrowserProfile, *, audit=None, stopped=lambda: False) -> None:
        self.stopped = stopped
        self.profile=profile.validate(); self.gate=DisclosureGate(); self.proxy=BrowserProxy(self.profile)
        self.sessions: dict[str,tuple[subprocess.Popen[bytes],str]]={}; self.lock=threading.Lock(); self.audit=audit
        self.events = []
        self._buffers = {}
        self._stderr_bytes = 0
        self.worker=verified_worker("browser_worker.py"); self.bwrap=verified_executable("/usr/bin/bwrap")
        self.python=verified_executable("/usr/bin/python3"); self.chromium=verified_executable("/usr/lib/chromium/chromium")

    def _event(self, kind, data):
        from .contracts import AuditEvent
        if len(self.events) >= 256:
            raise PolicyError("browser audit event allowance exceeded")
        self.events.append({"kind": kind, "data": data})
        if self.audit is not None:
            self.audit.emit(AuditEvent(kind, data=data))

    def create_session(self) -> str:
        session=uuid.uuid4().hex; worker=self.worker; unit="cptc-browser-"+session+".scope"
        runtime=f"/run/user/{os.getuid()}"; host_env={"XDG_RUNTIME_DIR":runtime,"DBUS_SESSION_BUS_ADDRESS":"unix:path="+runtime+"/bus"}
        try:
            probe=subprocess.run(["/usr/bin/systemd-run","--user","--scope","--quiet","-p","MemoryMax=256M","-p","TasksMax=32","/usr/bin/true"],env=host_env,timeout=10,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if probe.returncode: raise PolicyError("user cgroup limits are unavailable")
        except (OSError,subprocess.SubprocessError): raise PolicyError("user cgroup limits are unavailable") from None
        inner=[str(self.bwrap),"--unshare-all","--die-with-parent","--new-session","--clearenv","--setenv","HOME","/tmp","--setenv","TMPDIR","/tmp","--setenv","XDG_CACHE_HOME","/tmp/cache","--cap-drop","ALL","--ro-bind","/usr","/usr","--ro-bind","/etc/fonts","/etc/fonts","--ro-bind","/etc/ssl","/etc/ssl","--ro-bind","/sys/devices/system/cpu","/sys/devices/system/cpu","--symlink","usr/lib","/lib","--symlink","usr/lib","/lib64","--symlink","usr/bin","/bin","--proc","/proc","--dev","/dev","--tmpfs","/tmp","--ro-bind",str(worker),"/browser_worker.py","--chdir","/tmp","--",str(self.python),"-I","/browser_worker.py"]
        command=["/usr/bin/systemd-run","--user","--scope","--quiet","--unit",unit,"-p","MemoryMax=768M","-p","TasksMax=128","-p","RuntimeMaxSec=300","--",*inner]
        self._event("browser_process_intent", {"session": session, "command": command, "cwd": "/tmp", "worker_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(), "environment_keys": list(host_env), "memory_bytes": 805306368, "tasks": 128})
        try: process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=host_env,start_new_session=True)
        except OSError as exc: raise PolicyError("browser isolation could not start") from exc
        valid=False; deadline=time.monotonic()+2
        while time.monotonic()<deadline and process.poll() is None:
            check=subprocess.run(["/usr/bin/systemctl","--user","show",unit,"-p","ActiveState","-p","MemoryMax","-p","TasksMax","-p","RuntimeMaxUSec"],env=host_env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2)
            props=check.stdout
            if check.returncode==0 and b"ActiveState=active" in props and b"MemoryMax=805306368" in props and b"TasksMax=128" in props and b"RuntimeMaxUSec=" in props and b"RuntimeMaxUSec=infinity" not in props:
                valid=True; break
            time.sleep(.05)
        if not valid:
            self._kill(process,unit,host_env); raise PolicyError("browser cgroup limits were not applied")
        self._write(process,{"type":"initialize","executable":str(self.chromium)})
        self._event("browser_process_started", {"session": session, "unit": unit, "pid": process.pid})
        self.sessions[session]=(process,unit); return session

    def verify_capabilities(self, items, credential=None):
        if credential is not None: raise PolicyError("browser credentials are not admitted")
        self.gate.prepare(self.profile.provider, tuple(items))
        return {"mode":"synthetic_only","browser":"isolated route proxy"}

    def send(self, session_id: str, items: tuple[DisclosureItem, ...], *, preamble: str = "", credential=None) -> ProviderResponse:
        if credential is not None: raise PolicyError("browser credentials are not admitted")
        if preamble: raise PolicyError("browser preamble must be a classified disclosure item")
        record=self.sessions.get(session_id); process=record[0] if record else None
        if process is None or process.poll() is not None: raise PolicyError("browser session is unavailable")
        if not self.lock.acquire(blocking=False): raise PolicyError("one model request may be in flight")
        try:
            payload=self.gate.prepare(self.profile.provider,items)
            self._write(process,{"type":"send","url":self.profile.provider.origin+self.profile.provider.path,"prompt":payload,
                                 "prompt_selector":self.profile.prompt_selector,"submit_selector":self.profile.submit_selector,"response_selector":self.profile.response_selector})
            deadline=time.monotonic()+self.profile.provider.timeout_s
            while time.monotonic()<deadline:
                message=self._read(process,deadline)
                if message.get("type")=="route":
                    self._event("browser_route_requested", {"session": session_id, "method": message.get("method"), "url_hash": hashlib.sha256(str(message.get("url")).encode()).hexdigest()})
                    try:
                        reply=self.proxy.fetch(message,payload=payload)
                    except PolicyError:
                        self._event("browser_route_denied", {"session": session_id})
                        raise
                    self._event("browser_route_complete", {"session": session_id, "status": reply["status"], "request_count": self.proxy.requests, "response_bytes": self.proxy.response_bytes})
                    self._write(process,{"type":"route_response","id":message.get("id"),**reply}); continue
                if message.get("type")=="result":
                    text=message.get("text")
                    if not isinstance(text,str) or len(text.encode())>self.profile.provider.max_response_bytes: raise PolicyError("browser response cap exceeded")
                    return ProviderResponse(text,self.profile.provider.model,session_id,{})
                if message.get("type") in {"error", "blocked"}: raise PolicyError("browser worker rejected an unsupported operation")
                raise PolicyError("invalid browser worker response")
            self.cancel(session_id); raise PolicyError("browser deadline exceeded; no automatic retry")
        except Exception:
            self.cancel(session_id)
            raise
        finally: self.lock.release()

    def manual_login(self, session_id: str) -> None:
        # No isolated display channel has been proven. Do not expose credentials or host UI.
        raise PolicyError("manual browser login requires a separately proven isolated display path")

    def cancel(self, session_id: str) -> None:
        record=self.sessions.get(session_id)
        if record:
            process,unit=record; runtime=f"/run/user/{os.getuid()}"; self._kill(process,unit,{"XDG_RUNTIME_DIR":runtime,"DBUS_SESSION_BUS_ADDRESS":"unix:path="+runtime+"/bus"})

    def close(self, session_id: str) -> None:
        self.cancel(session_id); self.sessions.pop(session_id,None)
        self._event("browser_session_closed", {"session": session_id})

    @staticmethod
    def _kill(process, unit, env):
        try: subprocess.run(["/usr/bin/systemctl","--user","kill",unit,"--kill-who=all","--signal=KILL"],env=env,timeout=10,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        except (OSError,subprocess.SubprocessError): pass
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=2)
        for pipe in (process.stdin,process.stdout,process.stderr):
            if pipe: pipe.close()

    @staticmethod
    def _write(process: subprocess.Popen[bytes], value: dict[str,Any]) -> None:
        if process.stdin is None: raise PolicyError("browser IPC closed")
        raw=(json.dumps(value,separators=(",",":"),ensure_ascii=True)+"\n").encode(); process.stdin.write(raw); process.stdin.flush()

    def _read(self, process: subprocess.Popen[bytes], deadline: float) -> dict[str,Any]:
        if process.stdout is None: raise PolicyError("browser IPC closed")
        import select
        buffer = self._buffers.setdefault(process.pid, bytearray())
        while b"\n" not in buffer:
            if self.stopped():
                raise PolicyError("operator stopped browser work")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PolicyError("browser IPC deadline exceeded")
            streams = [process.stdout]
            if process.stderr and not process.stderr.closed:
                streams.append(process.stderr)
            ready,_,_=select.select(streams,[],[],min(remaining, 0.1))
            for stream in ready:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    if stream is process.stderr:
                        stream.close()
                        continue
                    raise PolicyError("browser IPC closed")
                if stream is process.stderr:
                    self._stderr_bytes += len(chunk)
                    if self.audit:
                        self.audit.capture("browser-stderr-" + str(process.pid), "stderr", chunk, "restricted_raw")
                    self._event("browser_stderr_chunk", {"bytes": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest()})
                    if self._stderr_bytes > 131072:
                        raise PolicyError("browser diagnostic allowance exhausted")
                else:
                    buffer.extend(chunk)
                    if len(buffer) > self.profile.provider.max_response_bytes * 6 + 4096:
                        raise PolicyError("browser IPC frame allowance exhausted")
        line, _, trailing = buffer.partition(b"\n")
        self._buffers[process.pid] = bytearray(trailing)
        try: value=json.loads(line)
        except (ValueError,TypeError): raise PolicyError("invalid browser IPC") from None
        if not isinstance(value,dict): raise PolicyError("invalid browser IPC")
        return value
