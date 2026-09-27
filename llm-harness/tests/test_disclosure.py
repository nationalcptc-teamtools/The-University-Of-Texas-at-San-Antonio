import base64
import pytest

from cptc_harness.contracts import PolicyError
from cptc_harness.disclosure import validate_items
from cptc_harness.providers import DisclosureItem, DisclosureGate, ProviderProfile


PROFILE = ProviderProfile("fixture", "openai", "https://provider.example", "/chat", "model", ("192.0.2.1",))


def test_nested_raw_and_aliases_are_denied_before_provider_payload():
    gate = DisclosureGate()
    for value in ({"facts": {"nested": {"headers": "x"}}}, {"facts": {"deep": {"response_base64": "x"}}}):
        with pytest.raises(PolicyError):
            gate.prepare(PROFILE, (DisclosureItem("fixture", "synthetic", value),))


def test_workflow_and_result_are_exact_versioned_shapes():
    gate = DisclosureGate()
    # The non-client synthetic shape is accepted without a capability probe.
    synthetic = {"objective": "fixture", "modules": ["network.output_import"], "facts": {}}
    assert "workflow" in gate.prepare(PROFILE, (DisclosureItem("workflow", "synthetic", synthetic),))
    with pytest.raises(PolicyError): gate.prepare(PROFILE, (DisclosureItem("workflow", "synthetic", {**synthetic, "unknown": 1}),))
    with pytest.raises(PolicyError): gate.prepare(PROFILE, (DisclosureItem("result", "synthetic", {"version": 1, "status": "complete", "facts": {}, "reason": None, "extra": 1}),))


def test_depth_item_and_size_limits_fail_closed():
    value = leaf = {}
    for _ in range(10): child = {}; leaf["nested"] = child; leaf = child
    with pytest.raises(PolicyError): validate_items((DisclosureItem("fixture", "synthetic", value),), maximum_bytes=8192)
    with pytest.raises(PolicyError): validate_items(tuple(DisclosureItem("item", "synthetic", {}) for _ in range(17)), maximum_bytes=8192)


@pytest.mark.parametrize("name", ["fixture", "item", "e", "facts", "part0"])
def test_fixture_name_cannot_bypass_client_fact_schema(name):
    with pytest.raises(PolicyError):
        validate_items((DisclosureItem(name, "client_confidential", {"description": "arbitrary target text"}),), maximum_bytes=8192)


@pytest.mark.parametrize("key", ["description", "blob", "encoded", "body", "nested"])
@pytest.mark.parametrize("envelope", ["result", "workflow"])
def test_unknown_nested_fact_keys_fail_registered_schema(key, envelope):
    schema = "network.output_import"
    facts = {"observations": [{"track": "network", "target": "192.0.2.10", "check_id": "network_inventory",
                               "state": "observed", "source_sha256": "a" * 64,
                               "facts": {key: base64.b64encode(b"synthetic fixture").decode()}}], "issues": [], "duplicates": 0}
    value = ({"version": 1, "status": "complete", "facts": facts, "reason": None, "facts_schema": schema}
             if envelope == "result" else {"version": 1, "preamble": "fixture policy", "modules": [{"id": schema, "args": {}}],
                                          "target_id": "target1", "facts": facts, "facts_schema": schema})
    with pytest.raises(PolicyError):
        validate_items((DisclosureItem(envelope, "client_confidential", value, schema_id=schema),), maximum_bytes=8192)


def test_excerpt_approval_cannot_be_used_for_untyped_object():
    with pytest.raises(PolicyError):
        validate_items((DisclosureItem("item", "approved_excerpt", {"description": "arbitrary"}),), maximum_bytes=8192)
    # This validates only the text shape; provider approval is still required.
    assert validate_items((DisclosureItem("item", "approved_excerpt", "exact selected text"),), maximum_bytes=8192)
    with pytest.raises(PolicyError):
        validate_items((DisclosureItem("result", "approved_excerpt", {"version": 1}),), maximum_bytes=8192)
