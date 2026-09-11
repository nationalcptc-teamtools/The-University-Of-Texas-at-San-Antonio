"""Bounded transport and contained-tool collectors."""
from __future__ import annotations

from typing import Callable
import hashlib

from ..contracts import (ExecutionContext, OperationResult, PolicyError, TargetRequest,
                         ToolRequest, canonical_json)
from ..parsers import parse_network_output
from .base import Collector, batch_result, blocked, stopped, tool_result
from ..portcast_identity import (
    PORTCAST_CANONICAL_URL,
    PORTCAST_PROFILE_ID,
    get_portcast_profile,
    parse_portcast_identity_body,
)
from ..profile_runtime.contracts import Http11RequestV1, ProfileContractError
from ..profile_runtime.worker import parse_http11_response


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
        observation = {
            "track": "web", "target": target.canonical_url, "check_id": self.check_id,
            "state": state, "facts": facts,
        }
        # Capture the exact typed metadata that supports the check. Body-only
        # evidence cannot substantiate a header assertion. This is a new source
        # receipt; historical observations without it remain unlinked.
        metadata = canonical_json(facts)
        metadata_evidence = _capture(context, "response_metadata", metadata, "client_confidential_human_only")
        if metadata_evidence:
            observation["source_sha256"] = hashlib.sha256(metadata).hexdigest()
            evidence += metadata_evidence
        return OperationResult(status="complete", facts={"observations": [observation], "issues": [], "duplicates": 0}, evidence=evidence)


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


class PortcastIdentityCollector:
    """Execute one sealed candidate and retain only its typed identity."""

    def collect(self, context: ExecutionContext) -> OperationResult:
        if context.stopped():
            return stopped()
        profile = get_portcast_profile(PORTCAST_PROFILE_ID)
        operation = profile.operation
        target = context.request.target
        if (target is None or target.canonical_url != PORTCAST_CANONICAL_URL
                or not isinstance(operation, Http11RequestV1)
                or target.host != operation.address
                or target.port != operation.port
                or target.base_path != operation.path
                or target.scheme != "http"):
            return blocked("PortCast target differs from the reviewed candidate profile")
        if (context.profile_action is None or context.profile_dispatch is None
                or context.capture is None):
            return blocked("trusted PortCast profile dispatcher is unavailable")

        captured_raw: list[bytes] = []
        evidence = []

        def encrypted_capture(raw: bytes):
            reference = context.capture(
                "raw", raw, "client_confidential_human_only"
            )
            if reference is None:
                raise PolicyError("encrypted PortCast capture failed")
            # The audit call has returned only after the encrypted artifact is
            # durable. Retain raw bytes in memory solely for the strict parser.
            evidence.append(reference)
            captured_raw.append(raw)
            return reference

        try:
            receipt = context.profile_dispatch(context.profile_action, encrypted_capture)
        except PolicyError:
            return blocked("PortCast profile dispatch was denied before connection")
        usage = {
            "request_limit": receipt.counters.protocol_requests,
            "tcp_connects": receipt.counters.tcp_connects,
            "udp_datagrams": receipt.counters.udp_datagrams,
            "protocol_requests": receipt.counters.protocol_requests,
            "tx_bytes": receipt.counters.tx_bytes,
            "rx_bytes": receipt.counters.rx_bytes,
        }
        if receipt.outcome != "complete":
            status = "stopped" if receipt.outcome == "cancelled" else "uncertain"
            return OperationResult(
                status=status,
                evidence=tuple(evidence),
                reason="PortCast profile transport did not complete",
                usage=usage,
            )
        try:
            if len(captured_raw) != 1:
                raise PolicyError("PortCast raw capture is unavailable")
            parsed = parse_http11_response(
                captured_raw[0], method=operation.method,
                maximum_body_bytes=profile.budget.rx_bytes,
            )
            if (parsed.status_code != 200
                    or parsed.content_type not in {
                        "application/json", "application/json; charset=utf-8"
                    }
                    or parsed.content_encoding != "identity"):
                raise PolicyError("PortCast HTTP response metadata differs")
            identity = parse_portcast_identity_body(
                parsed.body, action_id=context.request.request_id
            )
        except (PolicyError, ProfileContractError):
            return OperationResult(
                status="failed",
                evidence=tuple(evidence),
                reason="PortCast identity response did not match the reviewed parser",
                usage=usage,
            )
        finally:
            captured_raw.clear()
        facts = {
            "component_id": identity.component_id,
            "ecosystem": identity.ecosystem,
            "product": identity.product,
            "version": identity.version,
            "provenance": identity.provenance,
        }
        observation = {
            "track": "web",
            "target": target.canonical_url,
            "check_id": "portcast_public_identity",
            "state": "candidate",
            "facts": facts,
            "source_sha256": receipt.evidence_sha256,
        }
        return OperationResult(
            status="complete",
            facts={"observations": [observation], "issues": [], "duplicates": 0},
            evidence=tuple(evidence),
            usage=usage,
        )


class ManualOnlyCollector:
    def __init__(self, card: str):
        self.card = card

    def collect(self, context: ExecutionContext) -> OperationResult:
        return blocked(f"manual-only procedure: {self.card}; submit a reviewed human result")
