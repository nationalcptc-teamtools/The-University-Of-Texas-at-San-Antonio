import pytest

from cptc_harness.contracts import (
    ExecutionContext, OperationRequest, PolicySnapshot, ScopeSpec,
    TargetPolicy, TargetRef,
)
from cptc_harness.registry import build_registry


TARGET = TargetRef(
    "cptc11-prod-portcast", "http://10.0.1.30:8096/System/Info/Public",
    "http", "10.0.1.30", 8096, "/System/Info/Public",
)


class ExplodingTransport:
    def request(self, request):
        raise AssertionError("lab candidate reached the target transport")


def dispatch(target):
    registry = build_registry()
    spec = registry.get("web.portcast_identity")
    policy = PolicySnapshot(
        "eng", "rev", "ws", "dev", "operator",
        ScopeSpec(allowed_cidrs=("10.0.1.30/32",)),
        targets=(TargetPolicy(target, True, "reviewed", "ws", "portcast", (spec.module_id,)),),
    )
    request = OperationRequest(
        "portcast-request", "ws", "dev", "operator", spec.module_id,
        target, {"profile_id": "web.http_jellyfin_public_identity"},
        "operator", None, "rev",
    )
    return registry.dispatch(ExecutionContext(
        request, spec, policy, transport=ExplodingTransport(),
    ))


def test_registry_exposes_exact_bounded_module_but_requires_broker_dispatch_capability():
    registry = build_registry()
    spec = registry.get("web.portcast_identity")
    assert spec.mode == "bounded"
    assert spec.tool_id == "portcast-http-identity-v1"
    assert spec.effects == (
        "network_observation", "no_authentication", "no_retry", "no_fallback",
        "no_redirect", "no_request_body", "no_body_reflection",
    )
    assert (spec.bounds.tcp_connects, spec.bounds.protocol_requests,
            spec.bounds.tx_bytes, spec.bounds.rx_bytes, spec.bounds.output_bytes,
            spec.bounds.request_limit) == (1, 1, 256, 8192, 16384, 1)
    result = dispatch(TARGET)
    assert result.status == "blocked"
    assert result.reason == "trusted PortCast profile dispatcher is unavailable"
    assert result.facts == {}


@pytest.mark.parametrize("canonical_url", [
    "http://10.0.1.30:8096/System/Info/Public?format=json",
    "http://10.0.1.30:8096/System/Info/Public#identity",
    "http://operator@10.0.1.30:8096/System/Info/Public",
    "http://10.0.1.30:8096/System/Info/Public/",
    "http://10.0.1.30:8096/System/Info",
])
def test_candidate_dispatch_rejects_every_noncanonical_portcast_url(canonical_url):
    target = TargetRef(
        "cptc11-prod-portcast", canonical_url, "http", "10.0.1.30", 8096,
        "/System/Info/Public",
    )
    result = dispatch(target)
    assert result.status == "blocked"
    assert result.reason == "PortCast target differs from the reviewed candidate profile"
