"""Wave integration uses fixed synthetic responses and never connects to targets."""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from cptc_harness.assessment_contracts import CheckResult, assessment_request_id
from cptc_harness.broker import Broker
from cptc_harness.campaign import AssessmentCampaign, parse_plan, request_for
from cptc_harness.contracts import (ClockState, EvidenceRef, PolicyError, PolicySnapshot,
    ScopeSpec, TargetPolicy, TargetRef, TargetResponse, canonical_json, to_json)
from cptc_harness.ledger import Ledger
from cptc_harness.registry import build_registry


class SyntheticAudit:
    def __init__(self): self.events = []; self.failed = False; self.evidence = 0
    def verify(self): return SimpleNamespace(valid=True)
    def ready(self): return True
    def encryption_ready(self): return True
    def emit(self, event):
        if self.failed: raise OSError("synthetic audit failure")
        self.events.append(event)
    def reserve_output(self, *args): pass
    def release_output(self, *args): pass
    def capture(self, action, stream, data, classification):
        self.evidence += 1
        return EvidenceRef("ev-" + str(self.evidence), None, stream, classification, None,
                           hashlib.sha256(data).hexdigest(), len(data))


class SyntheticNetwork:
    def __init__(self): self.calls = []; self.interrupt = False
    def target_transport(self, target, *args, **kwargs):
        def request(_):
            self.calls.append(target.target_id)
            if self.interrupt: raise KeyboardInterrupt()
            return TargetResponse(200, {"x-frame-options": "DENY"}, b"synthetic", 0.01, target.host, False)
        return SimpleNamespace(request=request)


def setup_campaign(tmp_path):
    registry = build_registry()
    targets = tuple(TargetPolicy(TargetRef("target-" + str(i), f"https://192.0.2.{i}/", "https", f"192.0.2.{i}", 443, "/"),
        eligible=True, profile="synthetic-reviewed", assigned_workspace="workspace",
        permitted_modules=("web.headers", "web.session")) for i in (1, 2))
    policy = PolicySnapshot("engagement", "revision", "workspace", "device", "operator", ScopeSpec(("192.0.2.0/24",)),
        targets=targets, window_start="2025-01-01T00:00:00Z", window_end="2030-01-01T00:00:00Z",
        sow_reference="synthetic-sow", roe_reference="synthetic-roe")
    ledger = Ledger(tmp_path / "ledger", policy.engagement_id, policy.device_id, policy_revision=policy.revision)
    audit = SyntheticAudit(); network = SyntheticNetwork(); records = []
    broker = Broker(policy, registry, ledger, audit, clock=ClockState(True, 0), network=network,
                    result_sink=lambda request, result: records.append({"request": to_json(request), "result": to_json(result)}))
    return AssessmentCampaign(broker), network, audit, records


def draft(campaign, name="wave"):
    return campaign.draft(name, ["target-2", "target-1"], ["web.headers"])


def test_operator_wave_freeze_run_and_repeated_run_never_duplicate_traffic(tmp_path):
    campaign, network, audit, records = setup_campaign(tmp_path); plan = draft(campaign)
    assert parse_plan(to_json(plan)) == plan
    assert campaign.estimate(plan)["reserved_upper_bounds"]["request_limit"] == 2
    frozen = campaign.freeze(plan)
    assert not network.calls and not records and len(frozen["items"]) == 2
    assert campaign.ledger.usage()["request_limit"] == 2
    result = campaign.run(plan.wave_id, plan.sha256)
    assert result["status"] == "complete" and network.calls == ["target-1", "target-2"]
    assert len(records) == 2 and all(row["state"] == "complete" for row in result["items"])
    campaign.run(plan.wave_id, plan.sha256)
    assert network.calls == ["target-1", "target-2"] and len(records) == 2
    assert campaign.ledger.usage()["request_limit"] == 2
    assert campaign.ledger.usage()["model_calls"] == 0
    kinds = [e.kind for e in audit.events]
    assert kinds.count("operation_intent") == 2 and kinds.count("assessment_item_result") == 2


def test_edited_plan_or_unreviewed_module_cannot_freeze(tmp_path):
    campaign, network, _, _ = setup_campaign(tmp_path); plan = draft(campaign)
    with pytest.raises(PolicyError): campaign.freeze(replace(plan, release_sha256="a" * 64))
    with pytest.raises(PolicyError): campaign.draft("manual", ["target-1"], ["exploitation.zerologon"])
    with pytest.raises(PolicyError): campaign.draft("scanner", ["target-1"], ["web.nuclei"])
    assert not network.calls and campaign.ledger.usage()["request_limit"] == 0


def test_fabricated_or_modified_claim_cannot_dispatch(tmp_path):
    campaign, network, _, _ = setup_campaign(tmp_path); plan = draft(campaign); campaign.freeze(plan)
    first = plan.items[0]
    from cptc_harness.assessment_contracts import WaveClaim
    fabricated = WaveClaim(plan.wave_id, first.item_id, assessment_request_id(plan.wave_id, first.item_id), plan.sha256, "dispatching")
    request = request_for(plan, first, campaign.broker.policy)
    result = campaign.broker.execute(request, actor="operator", _wave_claim=fabricated)
    assert result.status == "blocked" and not network.calls


def test_interrupt_after_target_call_is_uncertain_and_never_replayed(tmp_path):
    campaign, network, _, records = setup_campaign(tmp_path); plan = draft(campaign); campaign.freeze(plan)
    network.interrupt = True
    with pytest.raises(KeyboardInterrupt): campaign.run(plan.wave_id, plan.sha256)
    assert network.calls == ["target-1"] and not records and campaign.ledger.stopped()
    states = [i["state"] for i in campaign.status(plan.wave_id, plan.sha256)["items"]]
    assert states == ["uncertain", "stopped"]
    network.interrupt = False
    campaign.run(plan.wave_id, plan.sha256)
    assert network.calls == ["target-1"] and campaign.ledger.usage()["request_limit"] == 2


def test_frozen_actions_remain_unrunnable_when_audit_fails(tmp_path):
    campaign, network, audit, _ = setup_campaign(tmp_path); plan = draft(campaign)
    audit.failed = True
    with pytest.raises(PolicyError): campaign.freeze(plan)
    assert campaign.ledger.stopped() and not network.calls
    assert campaign.ledger.usage()["request_limit"] == 0


def test_runtime_review_boundary_rejects_fabricated_result_without_audited_action(tmp_path):
    campaign, network, audit, _ = setup_campaign(tmp_path); plan = draft(campaign); campaign.freeze(plan)
    from cptc_harness.runtime import Runtime
    runtime = Runtime.__new__(Runtime)
    runtime.audit, runtime.ledger, runtime.policy = audit, campaign.ledger, campaign.broker.policy
    runtime.campaign = campaign
    # Simulate an integrity-verified empty audit result set. The caller cannot
    # supply invented receipt dictionaries to this Runtime boundary.
    runtime._records = lambda: []
    item = plan.items[0]
    result = CheckResult(item.target_id, item.check_id, item.role_id, "observed_condition", True,
        (assessment_request_id(plan.wave_id, item.item_id),), ("invented-evidence",),
        wave_id=plan.wave_id, item_id=item.item_id, plan_sha256=plan.sha256)
    with pytest.raises(PolicyError, match="no verified dispatch receipt"): runtime.verify_check_result(result)
    with pytest.raises(TypeError): runtime.verify_check_result(result, verified_actions={})
    assert not network.calls


def test_recovery_failure_still_latches_independent_stop(tmp_path, monkeypatch):
    campaign, network, _, _ = setup_campaign(tmp_path); plan = draft(campaign); campaign.freeze(plan)
    network.interrupt = True
    monkeypatch.setattr(campaign.ledger, "recover_waves", lambda **kw: (_ for _ in ()).throw(OSError("recovery failed")))
    with pytest.raises(OSError): campaign.run(plan.wave_id, plan.sha256)
    assert campaign.ledger.stopped() and (campaign.ledger.root / "operator-stop.json").exists()
    assert network.calls == ["target-1"]


def test_invalid_collector_status_is_uncertain_and_never_confirmed(tmp_path, monkeypatch):
    from cptc_harness.contracts import OperationResult
    campaign, network, _, records = setup_campaign(tmp_path); plan = draft(campaign); campaign.freeze(plan)
    monkeypatch.setattr(type(campaign.broker.registry), "dispatch", lambda self, context: OperationResult("bogus", {}))
    result = campaign.run(plan.wave_id, plan.sha256)
    assert result["status"] == "stopped" and result["items"][0]["state"] == "uncertain"
    assert not network.calls and records[0]["result"]["status"] == "uncertain"
