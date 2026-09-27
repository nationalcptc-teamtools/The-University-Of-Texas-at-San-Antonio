from dataclasses import FrozenInstanceError, replace
import pytest
from cptc_harness.assessment_contracts import (AssessmentItem, AssessmentPlan,
    ComponentIdentity, CheckResult, Finding, CheckDefinition, registry_digest,
    verify_assessment_plan, verify_assessment_result, assessment_request_id)
from cptc_harness.contracts import (CONTRACT_VERSION, PolicyError, PolicySnapshot,
    ScopeSpec, TargetPolicy, TargetRef, digest)


def plan(items=None):
    return AssessmentPlan("wave", "eng", "ws", "operator", "r1", "a"*64,
        "b"*64, items or (AssessmentItem("a", "target", "tls", "network.tls"),))


def test_plan_hash_binds_parameters_role_policy_and_release():
    value = plan()
    for changed in (replace(value, policy_sha256="c"*64),
                    replace(value, release_sha256="c"*64),
                    replace(value, items=(replace(value.items[0], role_id="reader"),)),
                    replace(value, items=(replace(value.items[0], args_json='{"port":443}'),))):
        assert changed.sha256 != value.sha256
    assert CONTRACT_VERSION == 1
    with pytest.raises(FrozenInstanceError):
        value.items = ()


def test_check_result_cannot_replay_an_earlier_wave_or_altered_plan():
    frozen = plan()
    result = CheckResult("target", "tls", "unauthenticated", "observed_condition", True,
                         (assessment_request_id("wave", "a"),), ("evidence",),
                         wave_id="wave", item_id="a", plan_sha256=frozen.sha256)
    action = result.source_actions[0]
    actions = {action: {"request_id": action, "target_id": "target", "check_id": "tls", "role_id": "unauthenticated",
                        "module_id": "network.tls", "plan_sha256": frozen.sha256, "item_id": "a", "status": "complete",
                        "evidence_ids": ["evidence"]}}
    evidence = {"evidence": {"source_action": action, "sha256": "a"*64}}
    def verify(value, wave=frozen, actions=actions, evidence=evidence):
        verify_assessment_result(value, wave, verified_actions=actions, verified_evidence=evidence)
    verify(result)
    for other in (replace(frozen, wave_id="new-wave"), replace(frozen, release_sha256="d"*64)):
        with pytest.raises(PolicyError): verify(result, other)
    with pytest.raises(PolicyError):
        verify(CheckResult("target", "tls", "unauthenticated", "not_tested"))
    with pytest.raises(PolicyError):
        replace(result, source_actions=("unrelated-request",))
    for empty in ({}, {"invented-action": actions[action]}):
        with pytest.raises(PolicyError): verify(result, actions=empty)
    for changed in ({"status": "running"}, {"status": "uncertain"}, {"target_id": "other-target"},
                    {"evidence_ids": []}, {"role_id": "administrator"}):
        with pytest.raises(PolicyError): verify(result, actions={action: {**actions[action], **changed}})
    for changed in ({}, {"evidence": {"source_action": "other-action", "sha256": "a"*64}}):
        with pytest.raises(PolicyError): verify(result, evidence=changed)


def test_duplicate_or_mutable_plan_inputs_rejected():
    item = plan().items[0]
    for items in ((item, item), (item, replace(item, item_id="b")), [item]):
        with pytest.raises(PolicyError):
            plan(items)
    for args in ('{"x":1,"x":2}', '{"x":NaN}', '[]', '{"x": 1}', '{"x":"'+'a'*8192+'"}'):
        with pytest.raises(PolicyError):
            replace(item, args_json=args)


def test_negative_or_positive_conclusion_needs_complete_collection():
    for state in ("not_observed", "observed_condition"):
        with pytest.raises(PolicyError):
            CheckResult("t", "c", "anonymous", state)
        with pytest.raises(PolicyError):
            CheckResult("t", "c", "anonymous", state, collection_complete=True)
        with pytest.raises(PolicyError):
            CheckResult("t", "c", "anonymous", state, True, ("action",))
        assert CheckResult("t", "c", "anonymous", state, True, ("action",), ("artifact",)).collection_complete
    with pytest.raises(PolicyError):
        CheckResult("t", "c", "anonymous", "confirmed")


def test_reviews_and_references_are_separate_from_detection():
    result = CheckResult("t", "c", "anonymous", "candidate", source_actions=("a",))
    with pytest.raises(PolicyError):
        Finding("f", result, review_state="accepted")
    with pytest.raises(PolicyError):
        Finding("f", result, cve_ids=("CVE-guess",))
    assert Finding("f", result, cve_ids=("CVE-2021-41773",)).review_state == "unreviewed"
    with pytest.raises(PolicyError):
        ComponentIdentity("c", "t", "deb", "pkg\x1b", provenance="package_database")


def test_accepted_review_binds_result_and_verified_artifact():
    result = CheckResult("t", "c", "reader", "observed_condition", True, ("a",), ("raw",))
    finding = Finding("f", result, review_state="accepted", review_artifact="review",
                      review_artifact_sha256="a"*64, review_result_sha256=digest(result))
    finding.verify_evidence({"raw":"b"*64,"review":"a"*64})
    for index in ({"review":"a"*64}, {"raw":"b"*64,"review":"c"*64}):
        with pytest.raises(PolicyError):finding.verify_evidence(index)
    with pytest.raises(PolicyError):replace(finding, result=replace(result, role_id="other"))
    with pytest.raises(PolicyError):replace(result,evidence_ids=("raw","raw"))


def bound_plan():
    from cptc_harness.registry import build_registry
    registry=build_registry()
    target=TargetPolicy(TargetRef("target","https://example.test/","https","example.test",443,"/"),
        eligible=True,profile="reviewed",assigned_workspace="ws",permitted_modules=("web.headers",))
    policy=PolicySnapshot("eng","r1","ws","dev","operator",ScopeSpec(allowed_hosts=("example.test",)),targets=(target,))
    check=CheckDefinition("headers","web",("web.headers",),("status",),mode="bounded")
    role={"method":None,"auth_realm":""}
    item=AssessmentItem("a","target","headers","web.headers",check_sha256=digest(check),
                        target_sha256=digest(target),role_sha256=digest(role))
    value=AssessmentPlan("wave","eng","ws","operator","r1",digest(policy),registry_digest(registry),(item,))
    return value,policy,registry,{"headers":check},{"unauthenticated":role}


def test_plan_verifier_rejects_stale_objects_and_inert_drafts():
    value,policy,registry,checks,roles=bound_plan()
    verify_assessment_plan(value,policy,registry,checks,roles)
    for bad in (replace(value,policy_sha256="a"*64),replace(value,release_sha256="b"*64),
                replace(value,items=(replace(value.items[0],check_sha256="c"*64),)),
                replace(value,items=(replace(value.items[0],target_sha256=""),)),
                replace(value,items=(replace(value.items[0],role_id="unapproved"),)),
                replace(value,items=(replace(value.items[0],module_id="custom.command"),))):
        with pytest.raises(PolicyError):verify_assessment_plan(bad,policy,registry,checks,roles)
    with pytest.raises(PolicyError):
        verify_assessment_plan(value,policy,registry,{"headers":replace(checks["headers"],version="2")},roles)


def test_missing_proof_approval_rejected_before_dispatch():
    value,policy,registry,checks,roles=bound_plan()
    proof=replace(registry.get("web.headers"),effects=("proof",))
    class ProofRegistry:
        def specs(self):return (proof,)
        def get(self,name):return proof
    special=ProofRegistry()
    with pytest.raises(PolicyError,match="approval"):
        verify_assessment_plan(replace(value,release_sha256=registry_digest(special)),policy,special,checks,roles)
