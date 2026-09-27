"""Operator-only, raw single-response collection for passive analysis."""
from __future__ import annotations

import base64

from .contracts import ExecutionContext, OperationResult, PolicyError, canonical_json
from .passive import capture_input


RAW_RESPONSE_WORKER = r'''import json,resource,socket,ssl,sys
try:
 resource.setrlimit(resource.RLIMIT_CORE,(0,0)); resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
 resource.setrlimit(resource.RLIMIT_NOFILE,(32,32)); resource.setrlimit(resource.RLIMIT_CPU,(30,30))
 r=json.load(open("/request.json",encoding="utf-8")); raw=socket.socket(fileno=0); raw.settimeout(r["timeout"])
 s=ssl.create_default_context(cafile="/etc/ca-certificates/extracted/tls-ca-bundle.pem").wrap_socket(raw,server_hostname=r["host"]) if r["scheme"]=="https" else raw
 s.sendall(("GET "+r["path"]+" HTTP/1.1\r\nHost: "+r["authority"]+"\r\nConnection: close\r\n\r\n").encode("ascii"))
 total=0; complete=True
 while True:
  part=s.recv(min(4096,32769-total))
  if not part: break
  retained=part[:max(0,32768-total)]
  sys.stdout.buffer.write(retained); sys.stdout.buffer.flush()
  total+=len(part)
  if total>32768: complete=False; break
 sys.stderr.write(json.dumps({"complete":complete},separators=(",",":"))); sys.stderr.flush()
except Exception: sys.stderr.write('{"complete":false}'); sys.stderr.flush()
'''


class ResponseCaptureCollector:
    """Capture one fixed base-path GET and retain only encrypted passive input."""
    def collect(self, context: ExecutionContext) -> OperationResult:
        if context.request.source != "operator":
            return OperationResult("blocked", reason="response capture is operator-only")
        if context.stopped():
            return OperationResult("stopped", reason="operator stop requested")
        if context.capture is None:
            return OperationResult("blocked", reason="encrypted response capture is required")
        if context.transport is None or context.request.target is None:
            return OperationResult("blocked", reason="brokered target transport is required")
        try:
            raw = context.transport.capture_response()
            envelope = canonical_json({"version": 1, "target": context.request.target.canonical_url,
                                       "response_base64": base64.b64encode(raw).decode("ascii")})
            parsed_target, _response, status, _headers, _body = capture_input(envelope, context.policy.scope)
            if parsed_target.canonical_url != context.request.target.canonical_url:
                raise PolicyError("captured response target changed")
            if context.network is not None:
                context.network._event("network_response", {"target": context.request.target.target_id,
                    "status": status, "bytes": len(raw), "truncated": False, "method": "GET"})
            reference = context.capture("response", envelope, "client_confidential_human_only")
            if reference is None:
                raise PolicyError("encrypted response evidence was not retained")
        except PolicyError:
            if context.network is not None:
                context.network._stop("response capture outcome uncertain")
            return OperationResult("uncertain", reason="response capture outcome uncertain; human review required")
        except Exception:
            if context.network is not None:
                context.network._stop("response capture outcome uncertain")
            return OperationResult("uncertain", reason="response capture outcome uncertain; human review required")
        if status in {423, 429} or status >= 500:
            if context.network is not None:
                context.network._stop("response capture target status requires stop")
            return OperationResult("uncertain", evidence=(reference,),
                                   reason="response capture target status requires human review")
        evidence = (reference,)
        return OperationResult("complete", facts={"observations": [{
            "track": "web", "target": context.request.target.canonical_url,
            "check_id": "web_response_capture", "state": "observed",
            "facts": {"status": status, "truncated": False},
        }], "issues": [], "duplicates": 0}, evidence=evidence)
