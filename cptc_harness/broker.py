"""The single execution gate for registered bounded operations."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from .contracts import (Approval, AuditEvent, ExecutionContext, OperationRequest,
                        OperationResult, PolicyError, canonical_json, digest, validate_schema)


class Broker:
    def __init__(self, policy: Any, registry: Any, ledger: Any, audit: Any, *,
                 network: Any | None = None, tools: Any | None = None, clock: Any | None = None, result_sink=None) -> None:
        self.policy, self.registry, self.ledger, self.audit = policy, registry, ledger, audit
        self.network, self.tools, self.clock = network, tools, clock
        self.result_sink = result_sink

    def execute(self, request: OperationRequest, *, actor: str, handler: Any | None = None,
                input_bytes: bytes = b"", source: Any | None = None) -> OperationResult:
        """Validate, reserve, audit intent, then invoke only the registry dispatch path."""
        reserved = False
        dispatched = False
        try:
            self._identity(request, actor)
            if request.source == "model" and (input_bytes or source is not None):
                raise PolicyError("model cannot provide raw import input")
            if request.source == "operator" and input_bytes and source is None:
                raise PolicyError("raw import input needs a trusted source reference")
            self._audit_ready()
            spec = self.registry.get(request.module_id)
            if spec is None: raise PolicyError("module is not registered")
            if request.source == "model":
                self.ledger.charge(request.request_id, "actions", 1, workflow_id=request.workflow_id,
                                   limits={"actions": int(getattr(self.policy, "model_actions", 0))})
            if "operator_only" in spec.effects and request.source != "operator":
                raise PolicyError("module requires an explicit operator request")
            if spec.mode == "manual_only": raise PolicyError("manual-only module cannot be executed")
            validate_schema(request.args, spec.input_schema)
            target_policy = self._target(request, spec)
            self._window_and_clock(spec)
            if spec.mode == "bounded" and not self.audit.encryption_ready():
                raise PolicyError("evidence encryption is not ready")
            self._approval(request, spec, target_policy)
            static_handler = self.registry.handler(request.module_id)
            if handler is not None and handler is not static_handler:
                raise PolicyError("untrusted handler was rejected")
            limits = {"model_calls": int(getattr(self.policy, "model_calls", 0)),
                      "actions": int(getattr(self.policy, "model_actions", 0))}
            if target_policy is not None: limits["request_limit"] = int(target_policy.request_limit)
            reservation = self.ledger.reserve(request.request_id, spec.bounds, workspace_id=request.workspace_id,
                                target_id=(f"{request.target.scheme}://{request.target.host}:{request.target.port}" if request.target else None),
                                auth_realm=target_policy.auth_realm if target_policy else "",
                                workflow_id=request.workflow_id, limits=limits)
            reserved = True
            self.audit.reserve_output(request.request_id, spec.bounds.output_bytes)
            self.audit.emit(AuditEvent("operation_intent", request.request_id,
                {"module": spec.module_id, "version": spec.version, "target": request.target.target_id if request.target else None,
                 "source_sha256": spec.source_hash, "args_hash": digest(request.args), "validated_args": request.args,
                 "bounds": spec.bounds.__dict__, "actor": actor, "workflow_id": request.workflow_id,
                 "approval_id": request.approval_id, "parent_action_id": request.parent_action_id,
                 "remaining_budgets": reservation.remaining}))
            if self.ledger.stopped(): raise PolicyError("operator stop")
            if self.network is not None:
                self.network.action_id = request.request_id
            transport = self.network.target_transport(request.target, self.policy.scope, timeout_s=spec.bounds.timeout_s,
                request_limit=spec.bounds.request_limit) if request.target and self.network else None
            context = ExecutionContext(request, spec, self.policy, transport=transport, tools=self.tools,
                capture=lambda stream, data, classification: self.audit.capture(request.request_id, stream, data, classification),
                stopped=self.ledger.stopped, input_bytes=input_bytes, source=source, network=self.network)
            # Registry dispatch is the only normal invocation. A supplied handler cannot replace it.
            dispatched = True
            result = self.registry.dispatch(context)
            self._audit_ready()
            if not isinstance(result, OperationResult): raise PolicyError("registered module returned an invalid result")
            validate_schema(result.facts, spec.output_schema)
            if self.ledger.stopped() and result.status == "complete":
                result = OperationResult("stopped", result.facts, result.evidence, self.ledger.stop_reason(), result.usage)
            self.ledger.finish(request.request_id, result.usage, state=result.status)
            self.audit.emit(AuditEvent("operation_result", request.request_id,
                {"status": result.status, "reason": result.reason, "usage": result.usage,
                 "evidence": [e.evidence_id for e in result.evidence]}))
            self.audit.release_output(request.request_id)
            return self._record(request, result)
        except PolicyError as exc:
            if dispatched:
                self.ledger.stop("operation outcome uncertain after dispatch")
                self.ledger.finish(request.request_id, state="uncertain")
                self._best_effort("operation_uncertain", request.request_id, {"reason": "policy or collection failure after dispatch"})
                return self._record(request, OperationResult("uncertain", reason="operation outcome uncertain; human review required"))
            if reserved:
                self.ledger.finish(request.request_id, state="stopped" if self.ledger.stopped() else "blocked")
            self._best_effort("operation_denied", request.request_id, {"reason": str(exc)})
            return self._record(request, OperationResult("stopped" if self.ledger.stopped() else "blocked", reason=str(exc)))
        except Exception:
            self.ledger.stop("audit, storage, or execution outcome uncertain")
            if reserved:
                self.ledger.finish(request.request_id, state="uncertain")
            self._best_effort("operation_uncertain", request.request_id, {"reason": "registered operation failed"})
            return self._record(request, OperationResult("uncertain", reason="registered operation failed"))

    def _record(self, request, result):
        if self.result_sink is not None:
            try:
                self.result_sink(request, result)
            except Exception:
                self.ledger.stop("result storage or audit failed")
                self._best_effort("result_storage_uncertain", request.request_id, {"reason": "result record could not be checkpointed"})
                return OperationResult("uncertain", reason="result storage or audit failed; human review required")
        return result

    def _identity(self, request: OperationRequest, actor: str) -> None:
        if actor not in {"operator", "model"} or actor != request.source or request.operator_id != self.policy.operator_id:
            raise PolicyError("operator identity does not match policy")
        if (request.workspace_id != self.policy.workspace_id or request.device_id != self.policy.device_id or
                request.policy_revision != self.policy.revision): raise PolicyError("request does not match active policy")

    def _audit_ready(self) -> None:
        try: valid = self.audit.verify().valid and self.audit.ready()
        except Exception: valid = False
        if not valid:
            self.ledger.stop("audit integrity or storage failure")
            raise PolicyError("audit is not ready")

    def _target(self, request: OperationRequest, spec: Any) -> Any | None:
        if spec.mode == "offline":
            if request.target is not None: raise PolicyError("offline module cannot receive a target")
            return None
        if request.target is None: raise PolicyError("bounded module requires a target")
        found = next((item for item in self.policy.targets if item.target.target_id == request.target.target_id), None)
        if found is None or found.target != request.target: raise PolicyError("target tuple is not policy approved")
        if not found.eligible or found.assigned_workspace != request.workspace_id: raise PolicyError("target is not eligible for workspace")
        for reference in (found.profile, self.policy.sow_reference, self.policy.roe_reference):
            if (not isinstance(reference, str) or not reference.strip() or len(reference) > 512
                    or reference.strip().lower() in {"unknown", "unverified", "none", "pending"}
                    or any(ord(char) < 32 or ord(char) == 127 for char in reference)):
                raise PolicyError("active testing requires reviewed target profile and SOW/ROE references")
        if spec.module_id not in found.permitted_modules: raise PolicyError("module is not allowed for target")
        return found

    def _window_and_clock(self, spec: Any) -> None:
        if spec.mode != "bounded": return
        if self.clock is None: raise PolicyError("clock state is required for active work")
        state = self.clock() if callable(self.clock) else self.clock
        if not getattr(state, "synchronized", False) or getattr(state, "offset_s", None) is None or abs(state.offset_s) > 2:
            raise PolicyError("clock is not safe for active work")
        try:
            now = datetime.now(timezone.utc)
            start, end = (_parse_time(self.policy.window_start), _parse_time(self.policy.window_end))
            if start is None or end is None or not (start <= now <= end): raise PolicyError("active window is not open")
        except ValueError as exc: raise PolicyError("invalid active window") from exc

    def _approval(self, request: OperationRequest, spec: Any, target: Any | None) -> None:
        if spec.mode != "bounded" or "proof" not in set(spec.effects): return
        if target is None or not request.approval_id: raise PolicyError("bounded proof needs a matching approval")
        approval = next((a for a in self.policy.approvals if a.approval_id == request.approval_id), None)
        if approval is None or (approval.module_id != spec.module_id or approval.target_id != target.target.target_id or
                                approval.policy_revision != self.policy.revision or approval.operator_id != request.operator_id or
                                approval.args_hash != digest(request.args) or approval.request_id != request.request_id):
            raise PolicyError("approval does not match request")
        expiry = _parse_time(approval.expires_at)
        if expiry is None or expiry <= datetime.now(timezone.utc): raise PolicyError("approval is expired")

    def _best_effort(self, kind: str, request_id: str, data: dict[str, Any]) -> None:
        try: self.audit.emit(AuditEvent(kind, request_id, data))
        except Exception: pass


def _parse_time(text: str) -> datetime | None:
    if not text: return None
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
