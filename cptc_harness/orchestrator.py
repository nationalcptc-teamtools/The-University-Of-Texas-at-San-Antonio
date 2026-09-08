"""Operator-created workflows. Model replies can select only admitted capabilities."""
from __future__ import annotations
from dataclasses import asdict
from pathlib import Path
import hashlib
import json
import uuid
from .contracts import (AuditEvent, OperationRequest, OperationResult, PolicyError,
                        RuleReference, canonical_json, digest, to_json)
from .policy import identifier
from .providers import create_adapter, DisclosureItem, ProviderProfile
from .preambles import build_preamble
from .skills import parse_envelope, compact_context
from .storage import exclusive, private_directory, read_private, write_json
from .audit_control import required_emit, required_release


def rules_reference():
    path = Path(__file__).parent / "resources" / "CPTC-RULES-2025-10.txt"
    return RuleReference("CPTC-rules-2025-10", "49223ed970c33e74d863d092bd415c02cdc747bedf21fc573a57e6b3b3598ea3", str(path),
                         ("https://cp.tc/rules/", "https://cp.tc/support/general/", "https://cp.tc/support/competition-network/"))


class Workflows:
    def __init__(self, root: Path, broker):
        self.root = private_directory(root, create=True)
        self.broker = broker

    def _path(self, workflow_id):
        return self.root / (identifier(workflow_id) + ".json")

    def create(self, workflow_id: str, profile: ProviderProfile, module_ids: tuple[str, ...],
               *, target_id: str | None, synthetic: bool = False):
        path = self._path(workflow_id)
        if path.exists():
            raise PolicyError("workflow ID already used; counters cannot be reset")
        if not module_ids or len(set(module_ids)) != len(module_ids):
            raise PolicyError("workflow requires a unique capability selection")
        for module_id in module_ids:
            spec = self.broker.registry.get(module_id)
            if spec.mode == "manual_only":
                raise PolicyError("manual-only module cannot enter an AI workflow")
            if synthetic and spec.mode != "offline":
                raise PolicyError("synthetic workflows cannot touch client targets")
        if not synthetic:
            if not profile.approved_client or profile.upstream_tools == "unknown":
                raise PolicyError("client workflow requires an approved contained provider")
            if not any(t.target.target_id == target_id and t.eligible for t in self.broker.policy.targets):
                raise PolicyError("workflow target requires current eligibility")
        elif target_id is not None:
            raise PolicyError("synthetic workflow cannot have a target")
        state = {"version": 1, "workflow_id": workflow_id, "engagement": self.broker.policy.engagement_id,
                 "workspace": self.broker.policy.workspace_id, "policy_revision": self.broker.policy.revision,
                 "profile_hash": digest(asdict(profile)), "modules": list(module_ids), "target_id": target_id,
                 "synthetic": synthetic, "calls": 0, "actions": 0, "repairs": 0, "state": "ready", "facts": {}, "facts_schema": ""}
        required_emit(self.broker.audit, self.broker.ledger, AuditEvent("workflow_authorized", data={k: v for k, v in state.items() if k != "facts"}))
        write_json(path, state, replace=False)
        return state

    def read(self, workflow_id):
        return json.loads(read_private(self._path(workflow_id)))

    def step(self, workflow_id: str, profile: ProviderProfile, *, credential=None):
        path = self._path(workflow_id)
        with exclusive(self.root / ".model.lock"), exclusive(path.with_suffix(".lock")):
            state = self.read(workflow_id)
            if state["state"] == "sending":
                state["state"] = "uncertain"
                write_json(path, state)
            if state["state"] not in ("ready", "format_repair"):
                raise PolicyError("workflow is stopped, complete, uncertain, or awaiting a human")
            if state["profile_hash"] != digest(asdict(profile)) or state["policy_revision"] != self.broker.policy.revision:
                raise PolicyError("workflow provider or policy changed; no automatic fallback")
            if self.broker.ledger.stopped():
                raise PolicyError("engagement stopped")
            if state["calls"] >= self.broker.policy.model_calls or state["actions"] >= self.broker.policy.model_actions:
                raise PolicyError("workflow model/action allowance exhausted")
            if not self.broker.audit.verify().valid or not self.broker.audit.ready():
                self.broker.ledger.stop("audit unavailable before model request")
                raise PolicyError("audit unavailable")
            classification = "synthetic" if state["synthetic"] else "client_confidential"
            specs = tuple(self.broker.registry.get(name) for name in state["modules"])
            selected_facts = json.loads(compact_context(state["facts"], limit=1024))
            if state["synthetic"]:
                context = {"objective": "Synthetic harness evaluation; no client testing authorized.",
                           "modules": state["modules"], "facts": selected_facts, "facts_schema": state.get("facts_schema", "")}
            else:
                preamble = build_preamble(self.broker.policy, rules_reference(), specs)
                context = {"version": 1, "preamble": preamble.text, "modules": [{"id": s.module_id, "args": to_json(s.input_schema)} for s in specs], "target_id": state["target_id"], "facts": selected_facts, "facts_schema": state.get("facts_schema", "")}
            if state["state"] == "format_repair":
                context["format_instruction"] = "Previous response was invalid. Return exactly one permitted JSON envelope; do not repeat the invalid response."
            items = (DisclosureItem("workflow", classification, context, schema_id=state.get("facts_schema", "")),)
            adapter = create_adapter(profile, audit=self.broker.audit, stopped=self.broker.ledger.stopped)
            # Complete disclosure checking before reserving/requesting; no network
            # during preflight. Reserve before any provider byte can leave.
            adapter.verify_capabilities(items, credential)
            safe_payload = adapter.gate.prepare(profile, items)
            state["calls"] += 1
            state["state"] = "sending"
            write_json(path, state)
            action_id = uuid.uuid4().hex
            self.broker.ledger.charge("model-" + action_id, "model_calls", 1, workflow_id=workflow_id,
                                     workspace_id=self.broker.policy.workspace_id, budget_limits=self.broker.policy.budget_limits,
                                     limits={"model_calls": self.broker.policy.model_calls})
            self.broker.audit.reserve_output(action_id, self.broker.audit.evidence_cap)
            required_emit(self.broker.audit, self.broker.ledger, AuditEvent("model_request", action_id,
                {"workflow_id": workflow_id, "requested_model": profile.model, "provider_hash": state["profile_hash"],
                 "payload_sha256": hashlib.sha256(safe_payload.encode()).hexdigest(), "payload_bytes": len(safe_payload.encode()),
                 "call": state["calls"], "remaining_calls": self.broker.policy.model_calls - state["calls"]}))
            # Full permitted request/response are local encrypted artifacts, not
            # readable error logs or future model context.
            self.broker.audit.capture(action_id, "stdout", safe_payload.encode(), "restricted_raw")
            session = None
            try:
                session = adapter.create_session()
                response = adapter.send(session, items, credential=credential)
                self.broker.audit.capture(action_id, "stdout", response.text.encode(), "restricted_raw")
                required_emit(self.broker.audit, self.broker.ledger, AuditEvent("model_response", action_id,
                    {"requested_model": response.model, "reported_model": response.reported_model, "usage": response.usage,
                     "response_bytes": len(response.text.encode()), "response_sha256": hashlib.sha256(response.text.encode()).hexdigest()}))
                try:
                    envelope = parse_envelope(response.text, allowed_module_ids=tuple(state["modules"]))
                except PolicyError:
                    if state["repairs"] < self.broker.policy.format_repairs:
                        state["repairs"] += 1
                        state["state"] = "format_repair"
                    else:
                        state["state"] = "stopped"
                    required_emit(self.broker.audit, self.broker.ledger, AuditEvent("model_envelope_rejected", action_id,
                        {"workflow_id": workflow_id, "state": state["state"], "repairs": state["repairs"], "executed": False}))
                    write_json(path, state)
                    return {"state": state["state"], "reason": "invalid model envelope; nothing executed"}
                if envelope.action == "ask_human":
                    state["state"] = "waiting_human"
                    result = {"state": "waiting_human", "message": envelope.message}
                elif envelope.action == "finish":
                    state["state"] = "finished"
                    result = {"state": "finished", "model_claim": envelope.status, "verified_completion": False}
                else:
                    state["actions"] += 1
                    write_json(path, state)  # action charged before dispatch, even if denied
                    target = next((t.target for t in self.broker.policy.targets if t.target.target_id == state["target_id"]), None)
                    spec = self.broker.registry.get(envelope.module_id)
                    if spec.mode == "offline":
                        target = None
                    policy = self.broker.policy
                    request = OperationRequest(uuid.uuid4().hex, policy.workspace_id, policy.device_id, policy.operator_id,
                        envelope.module_id, target, envelope.args, "model", None, policy.revision, workflow_id, action_id)
                    observed = self.broker.execute(request, actor="model")
                    state["facts"] = observed.facts
                    state["facts_schema"] = spec.module_id
                    state["state"] = "ready" if observed.status == "complete" else "waiting_human"
                    result = {"state": state["state"], "action_status": observed.status, "reason": observed.reason}
                write_json(path, state)
                return result
            except Exception:
                state["state"] = "uncertain"
                write_json(path, state)
                required_emit(self.broker.audit, self.broker.ledger, AuditEvent("model_uncertain", action_id, {"reason": "provider or audit failed; no automatic retry"}))
                raise PolicyError("model request uncertain; workflow stopped for human review") from None
            finally:
                if session:
                    adapter.close(session)
                required_release(self.broker.audit, self.broker.ledger, action_id)
