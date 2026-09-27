from __future__ import annotations

import base64
import json

from cptc_harness.contracts import (Bounds, EvidenceRef, ExecutionContext, ModuleSpec, OperationRequest,
                                    PolicySnapshot, ScopeSpec, SourceRef, TargetPolicy, TargetRef)
from cptc_harness.response_capture import ResponseCaptureCollector


class Transport:
    def __init__(self, raw): self.raw, self.calls = raw, 0
    def capture_response(self): self.calls += 1; return self.raw


class Network:
    def __init__(self): self.stops = []
    def _stop(self, reason): self.stops.append(reason)
    def _event(self, kind, data): pass


TARGET = TargetRef("loop", "http://127.0.0.1:8080/base", "http", "127.0.0.1", 8080, "/base")
POLICY = PolicySnapshot("e", "r", "w", "d", "o", ScopeSpec(("127.0.0.0/8",)),
                        targets=(TargetPolicy(TARGET, True, "synthetic", "w", "", ("web.response_capture",)),))
SPEC = ModuleSpec("web.response_capture", "1", "web", "bounded", (), Bounds(30, 1, 131072, 1),
                  {"type":"object","properties":{},"required":()}, {"type":"object","properties":{},"required":()})


def context(raw, *, source="operator", capture=True):
    request = OperationRequest("r", "w", "d", "o", "web.response_capture", TARGET, {}, source, "a", "r")
    evidence = []
    def writer(stream, data, classification):
        evidence.append((stream, data, classification))
        return EvidenceRef(str(len(evidence)), None, stream, classification, None, "0" * 64, len(data))
    writer = writer if capture else None
    return ExecutionContext(request, SPEC, POLICY, transport=Transport(raw), capture=writer,
                            source=SourceRef("synthetic", "0" * 64), network=Network()), evidence


def test_operator_capture_is_canonical_encrypted_evidence_without_raw_facts():
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nX-Secret: value\r\n\r\nsecret"
    ctx, evidence = context(raw)
    result = ResponseCaptureCollector().collect(ctx)
    assert result.status == "complete" and ctx.transport.calls == 1
    assert result.facts["observations"][0]["facts"] == {"status": 200, "truncated": False}
    assert b"secret" not in json.dumps(result.facts).encode()
    assert evidence[0][0] == "response" and evidence[0][2] == "client_confidential_human_only"
    envelope = json.loads(evidence[0][1])
    assert envelope == {"version": 1, "target": TARGET.canonical_url, "response_base64": base64.b64encode(raw).decode()}


def test_model_and_missing_capture_block_before_transport():
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    model, _ = context(raw, source="model")
    missing, _ = context(raw, capture=False)
    assert ResponseCaptureCollector().collect(model).status == "blocked" and model.transport.calls == 0
    assert ResponseCaptureCollector().collect(missing).status == "blocked" and missing.transport.calls == 0


def test_malformed_duplicate_length_and_transfer_encoding_stop_without_raw_result():
    for raw in (b"bad", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"):
        ctx, _evidence = context(raw)
        result = ResponseCaptureCollector().collect(ctx)
        assert result.status == "uncertain" and ctx.network.stops and result.facts == {}
