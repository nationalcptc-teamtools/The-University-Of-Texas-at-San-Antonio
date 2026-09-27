"""Operator-only, frozen waves of existing single-target observations.

This module has no target transport, secret, provider, or benchmark interface.
It invokes only the normal broker after proving a prepaid ledger claim.
"""
from __future__ import annotations

from dataclasses import fields
import json
import time

from .assessment_contracts import (AssessmentItem, AssessmentPlan, CheckDefinition,
    WaveClaim, assessment_request_id, registry_digest, verify_assessment_plan)
from .audit_control import required_emit
from .contracts import (AuditEvent, OperationRequest, PolicyError, Reservation,
    canonical_json, digest, to_json)
from .policy import identifier

# Explicit release profiles, not a category that admits future modules.
OBSERVATIONS = {
    "network.nmap_inventory": "network_service_inventory",
    "web.headers": "web_missing_security_headers",
    "web.session": "web_session_metadata",
    "web.response_capture": "web_response_capture",
}
ROLES = {"unauthenticated": {"auth_realm": "", "method": None}}


def definitions(registry):
    return {check: CheckDefinition(check, registry.get(module).track, (module,),
        ("source_sha256",), mode="bounded") for module, check in OBSERVATIONS.items()}


def parse_plan(value) -> AssessmentPlan:
    try:
        if not isinstance(value, dict) or set(value) != {f.name for f in fields(AssessmentPlan)}:
            raise ValueError()
        value = dict(value)
        if type(value["items"]) is not list: raise ValueError()
        names = {f.name for f in fields(AssessmentItem)}
        if any(not isinstance(i, dict) or set(i) != names for i in value["items"]): raise ValueError()
        value["items"] = tuple(AssessmentItem(**i) for i in value["items"])
        return AssessmentPlan(**value)
    except (ValueError, TypeError, KeyError, RecursionError):
        raise PolicyError("invalid frozen assessment plan") from None


def request_for(plan, item, policy):
    target = next((entry.target for entry in policy.targets if entry.target.target_id == item.target_id), None)
    if target is None: raise PolicyError("assessment target is unavailable")
    return OperationRequest(assessment_request_id(plan.wave_id, item.item_id), policy.workspace_id,
        policy.device_id, policy.operator_id, item.module_id, target, json.loads(item.args_json),
        "operator", item.approval_id or None, policy.revision, workflow_id=plan.wave_id,
        parent_action_id=plan.wave_id)


def _stored_plan(ledger, wave_id, expected_sha256):
    identifier(wave_id)
    row = ledger._db.execute("SELECT plan_json,plan_sha256 FROM assessment_waves WHERE engagement=? AND device=? AND wave_id=?",
        (ledger.engagement_id, ledger.device_id, wave_id)).fetchone()
    if not row or row[1] != expected_sha256:
        raise PolicyError("frozen assessment identity does not match")
    plan = parse_plan(json.loads(row[0]))
    if plan.sha256 != row[1]: raise PolicyError("frozen assessment integrity failure")
    return plan


def activate_reserved_request(broker, request, claim):
    """A constructible claim is not authority: verify the ledger and full request."""
    if type(claim) is not WaveClaim or request.source != "operator":
        raise PolicyError("invalid prepaid assessment claim")
    plan = _stored_plan(broker.ledger, claim.wave_id, claim.plan_sha256)
    verify_assessment_plan(plan, broker.policy, broker.registry, definitions(broker.registry), ROLES)
    item = next((i for i in plan.items if i.item_id == claim.item_id), None)
    if item is None or request != request_for(plan, item, broker.policy):
        raise PolicyError("prepaid request does not match frozen item")
    if item.module_id not in OBSERVATIONS or item.role_id != "unauthenticated":
        raise PolicyError("assessment profile is unavailable")
    stored = broker.ledger._db.execute("SELECT bounds FROM reservations WHERE engagement=? AND device=? AND request_id=?",
        (broker.policy.engagement_id, broker.policy.device_id, request.request_id)).fetchone()
    spec = broker.registry.get(item.module_id)
    if not stored or json.loads(stored[0]) != to_json(spec.bounds):
        raise PolicyError("prepaid assessment allowance changed")
    broker.ledger.activate_wave_item(claim.wave_id, claim.item_id, request.request_id, plan.sha256)
    return Reservation(request.request_id, spec.bounds, {})


class AssessmentCampaign:
    def __init__(self, broker):
        self.broker, self.ledger = broker, broker.ledger

    def draft(self, wave_id, targets, modules):
        identifier(wave_id)
        if not targets or not modules or len(targets) * len(modules) > 256:
            raise PolicyError("assessment selection is empty or exceeds its item limit")
        if len(set(targets)) != len(targets) or len(set(modules)) != len(modules):
            raise PolicyError("duplicate assessment selection")
        checks = definitions(self.broker.registry); items = []
        for target_id in sorted(targets):
            entry = next((t for t in self.broker.policy.targets if t.target.target_id == target_id), None)
            if entry is None: raise PolicyError("unknown assessment target")
            for module in sorted(modules):
                if module not in OBSERVATIONS: raise PolicyError("module is not admitted to observation waves")
                check = checks[OBSERVATIONS[module]]
                item_id = digest({"target": target_id, "check": check.check_id, "role": "unauthenticated"})[:32]
                items.append(AssessmentItem(item_id, target_id, check.check_id, module,
                    check_sha256=digest(check), target_sha256=digest(entry), role_sha256=digest(ROLES["unauthenticated"])))
        policy = self.broker.policy
        plan = AssessmentPlan(wave_id, policy.engagement_id, policy.workspace_id, policy.operator_id,
            policy.revision, digest(policy), registry_digest(self.broker.registry), tuple(items))
        self._verify(plan)
        return plan

    def _verify(self, plan):
        verify_assessment_plan(plan, self.broker.policy, self.broker.registry, definitions(self.broker.registry), ROLES)
        for item in plan.items:
            if item.module_id not in OBSERVATIONS or item.role_id != "unauthenticated":
                raise PolicyError("assessment profile is unavailable")
            request = request_for(plan, item, self.broker.policy)
            self.broker._identity(request, "operator")
            self.broker._target(request, self.broker.registry.get(item.module_id))

    def estimate(self, plan):
        self._verify(plan)
        totals = {"request_limit": 0, "output_bytes": 0, "process_limit": 0}
        for item in plan.items:
            bounds = self.broker.registry.get(item.module_id).bounds
            for key in totals: totals[key] += getattr(bounds, key)
        return {"plan_sha256": plan.sha256, "items": len(plan.items), "reserved_upper_bounds": totals,
                "model_calls": 0, "network_requests": 0, "concurrency": 1,
                "limits_basis": "declared reviewed profiles; no estimate implies target safety"}

    def freeze(self, plan):
        self._verify(plan); self.broker._audit_ready()
        items = {}
        for item in plan.items:
            target = next(t for t in self.broker.policy.targets if t.target.target_id == item.target_id)
            ident = assessment_request_id(plan.wave_id, item.item_id)
            items[item.item_id] = {"request_id": ident, "action_id": ident,
                "bounds": self.broker.registry.get(item.module_id).bounds,
                "target_id": f"{target.target.scheme}://{target.target.host}:{target.target.port}",
                "target_policy_id": item.target_id, "auth_realm": target.auth_realm,
                "workflow_id": plan.wave_id, "limits": {"request_limit": target.request_limit,
                    "auth_posts": target.auth_attempts, "model_calls": self.broker.policy.model_calls,
                    "actions": self.broker.policy.model_actions}, "budget_limits": self.broker.policy.budget_limits}
        required_emit(self.broker.audit, self.ledger, AuditEvent("assessment_freeze_intent", plan.wave_id,
            {"plan_sha256": plan.sha256, "policy_sha256": plan.policy_sha256,
             "release_sha256": plan.release_sha256, **self.estimate(plan)}))
        claims = self.ledger.reserve_wave(plan, items)
        required_emit(self.broker.audit, self.ledger, AuditEvent("assessment_frozen", plan.wave_id,
            {"plan_sha256": plan.sha256, "items": len(claims)}))
        return self.status(plan.wave_id, plan.sha256)

    def status(self, wave_id, plan_sha256):
        plan = _stored_plan(self.ledger, wave_id, plan_sha256)
        rows = self.ledger._db.execute("SELECT item_id,request_id,target_id,check_id,role_id,module_id,state FROM assessment_items WHERE engagement=? AND device=? AND wave_id=?",
            (self.ledger.engagement_id, self.ledger.device_id, wave_id)).fetchall()
        columns = ("item_id", "request_id", "target_id", "check_id", "role_id", "module_id", "state")
        items = {r[0]: dict(zip(columns, r)) for r in rows}
        return {"classification": "client_confidential", "wave_id": wave_id, "plan_sha256": plan.sha256,
                "items": [items[i.item_id] for i in plan.items], "model_calls": 0,
                "status": self.ledger._db.execute("SELECT state FROM assessment_waves WHERE engagement=? AND device=? AND wave_id=?", (self.ledger.engagement_id, self.ledger.device_id, wave_id)).fetchone()[0],
                "stopped": self.ledger.stopped()}

    def run(self, wave_id, plan_sha256):
        plan = _stored_plan(self.ledger, wave_id, plan_sha256); self._verify(plan)
        for item in plan.items:
            if self.ledger.stopped(): break
            terminal = self.ledger._db.execute("SELECT state FROM assessment_items WHERE engagement=? AND device=? AND wave_id=? AND item_id=?",
                (self.ledger.engagement_id, self.ledger.device_id, wave_id, item.item_id)).fetchone()
            if terminal and terminal[0] == "complete": continue
            if not self._pace(plan, item): break
            claim = self.ledger.claim_wave_item(wave_id, item.item_id)
            if claim.state != "dispatching": continue
            try:
                required_emit(self.broker.audit, self.ledger, AuditEvent("assessment_item_claimed", claim.request_id,
                    {"wave_id": wave_id, "item_id": item.item_id, "plan_sha256": plan.sha256,
                     "target_id": item.target_id, "check_id": item.check_id, "role_id": item.role_id}))
                result = self.broker.execute(request_for(plan, item, self.broker.policy), actor="operator", _wave_claim=claim)
                self.ledger.finish_wave_item(wave_id, item.item_id, result.status, canonical_json(to_json(result)).decode())
                required_emit(self.broker.audit, self.ledger, AuditEvent("assessment_item_result", claim.request_id,
                    {"wave_id": wave_id, "item_id": item.item_id, "status": result.status, "plan_sha256": plan.sha256}))
                if result.status != "complete": break
            except BaseException:
                try:
                    self.ledger.recover_waves(workspace_id=self.broker.policy.workspace_id)
                finally:
                    from .audit_control import _latch_audit_failure
                    _latch_audit_failure(self.ledger)
                raise
        return self.status(wave_id, plan_sha256)

    def _pace(self, plan, item):
        """Wait for an already-consumed rate slot, without reserving or retrying I/O."""
        request = request_for(plan, item, self.broker.policy)
        target = request.target
        origin = f"{target.scheme}://{target.host}:{target.port}"
        row = self.ledger._db.execute("SELECT seen FROM rates WHERE engagement=? AND target=?",
            (self.ledger.engagement_id, origin)).fetchone()
        if not row: return True
        interval = 1.0 / self.broker.policy.http_rate
        remaining = row[0] + interval - time.time()
        if remaining <= 0: return True
        if remaining > min(interval + 2, 30):
            raise PolicyError("assessment rate wait exceeds its bounded allowance")
        required_emit(self.broker.audit, self.ledger, AuditEvent("assessment_rate_wait", request.request_id,
            {"wave_id": plan.wave_id, "wait_ms": int(remaining * 1000) + 1}))
        deadline = time.monotonic() + remaining + 0.01
        while time.monotonic() < deadline:
            if self.ledger.stopped(): return False
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        return not self.ledger.stopped()


def add_cli_commands(commands, workspace_argument=None):
    from pathlib import Path
    plan = commands.add_parser("assessment-plan", help="prepare a finite observation plan with no target traffic")
    plan.add_argument("--id", required=True); plan.add_argument("--target", action="append", required=True)
    plan.add_argument("--module", action="append", choices=tuple(OBSERVATIONS), required=True)
    plan.add_argument("--output", type=Path, required=True)
    freeze = commands.add_parser("assessment-freeze", help="atomically reserve an exact reviewed plan")
    freeze.add_argument("--plan", type=Path, required=True); freeze.add_argument("--sha256", required=True)
    run = commands.add_parser("assessment-run", help="run frozen observation items once through the broker")
    status = commands.add_parser("assessment-status", help="inspect frozen items and uncertain outcomes")
    for parser in (run, status):
        parser.add_argument("--id", required=True); parser.add_argument("--sha256", required=True)
    if workspace_argument:
        for parser in (plan, freeze, run, status): workspace_argument(parser)


def execute_cli(runtime, args):
    from .storage import read_private, write_json
    from pathlib import Path
    campaign = runtime.campaign
    if args.command == "assessment-plan":
        plan = campaign.draft(args.id, args.target, args.module)
        destination = Path(args.output).absolute()
        if any((ancestor / ".git").exists() for ancestor in (destination.parent, *destination.parents)):
            raise PolicyError("engagement plans must remain outside Git")
        required_emit(runtime.audit, runtime.ledger, AuditEvent("assessment_plan_prepared", plan.wave_id,
            {"plan_sha256": plan.sha256, "policy_sha256": plan.policy_sha256, "items": len(plan.items)}))
        write_json(destination, to_json(plan), replace=False)
        return {"classification": "client_confidential", "path": str(destination), **campaign.estimate(plan)}
    if args.command == "assessment-freeze":
        plan = parse_plan(json.loads(read_private(args.plan, 1048576)))
        if plan.sha256 != args.sha256: raise PolicyError("reviewed plan checksum changed")
        return campaign.freeze(plan)
    if args.command == "assessment-run": return campaign.run(args.id, args.sha256)
    if args.command == "assessment-status": return campaign.status(args.id, args.sha256)
    raise PolicyError("unknown assessment operation")
