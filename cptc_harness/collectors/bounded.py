"""Bounded transport and contained-tool collectors."""
from __future__ import annotations

from typing import Callable

from ..contracts import (ExecutionContext, OperationResult, TargetRequest,
                         ToolRequest)
from ..parsers import parse_network_output
from .base import Collector, batch_result, blocked, stopped, tool_result


def _capture(context: ExecutionContext, stream: str, payload: bytes, classification: str):
    if context.capture is None or not payload:
        return ()
    reference = context.capture(stream, payload, classification)
    return (reference,) if reference is not None else ()


class WebCollector:
    def __init__(self, check_id: str):
        self.check_id = check_id

    def collect(self, context: ExecutionContext) -> OperationResult:
        if context.stopped():
            return stopped()
        if context.transport is None or context.request.target is None:
            return blocked("target transport and an eligible target are required")
        target = context.request.target
        path = target.base_path or "/"
        try:
            response = context.transport.request(TargetRequest(
                method="GET", path=path, max_bytes=context.spec.bounds.output_bytes,
            ))
        except Exception:
            return OperationResult(status="failed", reason="bounded web request failed")
        evidence = _capture(context, "response", response.body, "client_confidential_human_only")
        names = {str(name).lower() for name in response.headers if isinstance(name, str)}
        if self.check_id == "web_headers":
            important = {"strict-transport-security": "hsts", "content-security-policy": "csp",
                         "x-content-type-options": "content_type_options", "x-frame-options": "frame_options",
                         "referrer-policy": "referrer_policy", "permissions-policy": "permissions_policy"}
            present = sorted(important[name] for name in names if name in important)
            missing = sorted(value for key, value in important.items() if key not in names)
            facts = {"status": response.status, "headers_present": present,
                     "headers_missing": missing, "redirect": 300 <= response.status < 400,
                     "truncated": bool(response.truncated)}
            state = "candidate" if target.scheme == "https" and "hsts" not in present else "observed"
        else:
            set_cookie = "set-cookie" in names
            facts = {"status": response.status, "cookie_header_present": set_cookie,
                     "session_ref_present": bool(response.session_ref),
                     "truncated": bool(response.truncated)}
            state = "candidate" if set_cookie and not response.session_ref else "observed"
        return OperationResult(status="complete", facts={"observations": [{
            "track": "web", "target": target.canonical_url, "check_id": self.check_id,
            "state": state, "facts": facts,
        }], "issues": [], "duplicates": 0}, evidence=evidence)


class ToolCollector:
    def __init__(self, *, tool_id: str, parser: Callable[..., object] | None = None,
                 scoped: bool = False):
        self.tool_id, self.parser, self.scoped = tool_id, parser, scoped

    def collect(self, context: ExecutionContext) -> OperationResult:
        if context.stopped():
            return stopped()
        if context.tools is None:
            return blocked("contained tool runner is unavailable")
        try:
            output = context.tools.run(ToolRequest(
                tool_id=self.tool_id,
                arguments={"profile": self.tool_id},
            ))
        except Exception:
            return OperationResult(status="failed", reason="contained tool invocation failed")
        limit = context.spec.bounds.output_bytes
        evidence = _capture(context, "tool_stdout", output.stdout[:limit], "client_confidential_human_only")
        stderr_evidence = _capture(context, "tool_stderr", output.stderr[:limit], "client_confidential_human_only")
        evidence = evidence + stderr_evidence
        raw, _, reason = tool_result(output)
        if len(raw) > context.spec.bounds.output_bytes:
            return OperationResult(status="uncertain", reason="contained tool exceeded output allowance", evidence=evidence)
        if reason:
            return OperationResult(status="blocked", reason=reason, evidence=evidence)
        if self.parser is None:
            return OperationResult(status="complete", facts={"tool_completed": True,
                "bytes": len(raw), "issues": [], "observations": [], "duplicates": 0}, evidence=evidence)
        try:
            if self.scoped:
                batch = self.parser(raw, context.source or "contained-tool", context.policy.scope)
            else:
                batch = self.parser(raw, context.source or "contained-tool")
        except (TypeError, ValueError):
            return OperationResult(status="failed", reason="contained tool output was not a supported format", evidence=evidence)
        return batch_result(batch, evidence)


class UnsupportedScannerCollector:
    def __init__(self, scanner: str):
        self.scanner = scanner

    def collect(self, context: ExecutionContext) -> OperationResult:
        return blocked(f"unsupported containment for {self.scanner}; manual review required")


class ManualOnlyCollector:
    def __init__(self, card: str):
        self.card = card

    def collect(self, context: ExecutionContext) -> OperationResult:
        return blocked(f"manual-only procedure: {self.card}; submit a reviewed human result")
