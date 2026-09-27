"""Stdio MCP over an operator-bound workflow. No filesystem/resources/export tools."""
from __future__ import annotations
from dataclasses import asdict
import json
import uuid
from .contracts import OperationRequest, PolicyError, digest
from .providers import DisclosureGate, DisclosureItem
from .storage import exclusive, write_json


class MCPFacade:
    def __init__(self, runtime, workflow_id, profile):
        self.runtime, self.workflow_id, self.profile = runtime, workflow_id, profile
        self.gate = DisclosureGate()
        state = runtime.workflows.read(workflow_id)
        if state["profile_hash"] != digest(asdict(profile)):
            raise PolicyError("MCP destination does not match operator-bound workflow")
        # A stdio caller has no authenticated provider origin. A local profile
        # cannot establish where its responses are subsequently forwarded.
        if not state["synthetic"]:
            raise PolicyError("stdio MCP is synthetic-only until recipient-bound transport is admitted")

    def capabilities(self):
        state = self.runtime.workflows.read(self.workflow_id)
        return [{"module_id": name, "description": self.runtime.registry.get(name).description,
                 "mode": self.runtime.registry.get(name).mode} for name in state["modules"]]

    def stop(self):
        """Owner-bound embeddings call the same durable control path as the CLI."""
        from .audit_control import operator_stop
        return operator_stop(self.runtime.ledger_root, self.runtime.policy, interface="mcp", source="model", ledger=self.runtime.ledger)

    def action(self, module_id: str, arguments: dict):
        workflows = self.runtime.workflows
        path = workflows._path(self.workflow_id)
        with exclusive(path.with_suffix(".lock")):
            state = workflows.read(self.workflow_id)
            if state["policy_revision"] != self.runtime.policy.revision or self.runtime.ledger.stopped():
                raise PolicyError("workflow policy changed or engagement stopped")
            if state["state"] != "ready" or state["actions"] >= self.runtime.policy.model_actions:
                raise PolicyError("workflow is not ready or action allowance exhausted")
            if module_id not in state["modules"]:
                raise PolicyError("module was not selected by the operator")
            spec = self.runtime.registry.get(module_id)
            if spec.mode == "manual_only" or (state["synthetic"] and spec.mode != "offline"):
                raise PolicyError("capability cannot run in this workflow")
            state["actions"] += 1
            state["state"] = "sending"
            write_json(path, state)
            policy = self.runtime.policy
            target = next((t.target for t in policy.targets if t.target.target_id == state["target_id"]), None)
            if spec.mode == "offline":
                target = None
            request = OperationRequest(uuid.uuid4().hex, policy.workspace_id, policy.device_id, policy.operator_id,
                module_id, target, arguments, "model", None, policy.revision, self.workflow_id)
            try:
                result = self.runtime.broker.execute(request, actor="model")
                state["state"] = "ready" if result.status == "complete" else "waiting_human"
                write_json(path, state)
                # No evidence paths, raw outputs, source documents or secrets are
                # exposed through MCP. Classification inherits engagement origin.
                data = {"version": 1, "status": result.status, "facts": result.facts, "reason": result.reason, "facts_schema": spec.module_id}
                classification = "synthetic" if state["synthetic"] else "client_confidential"
                return json.loads(self.gate.prepare(self.profile, (DisclosureItem("result", classification, data, schema_id=spec.module_id),)))[0]["data"]
            except Exception:
                state["state"] = "uncertain"
                write_json(path, state)
                raise PolicyError("MCP operation uncertain; operator review required") from None


def serve(runtime, workflow_id, profile):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        raise PolicyError("install the pinned optional MCP dependency first") from None
    facade = MCPFacade(runtime, workflow_id, profile)
    server = FastMCP("cptc-guarded-harness")

    @server.tool()
    def cptc_capabilities() -> list[dict]:
        """List the operator-selected static capabilities. Does not expand scope."""
        return facade.capabilities()

    @server.tool()
    def cptc_action(module_id: str, arguments: dict) -> dict:
        """Request one bounded operation in the preauthorized workflow. No custom scripts, raw evidence, exports or policy changes."""
        try:
            return facade.action(module_id, arguments)
        except PolicyError:
            return {"status": "blocked", "reason": "workflow policy denied the request"}

    @server.tool()
    def cptc_stop() -> dict:
        """Latch a stop through the owner-only device control queue."""
        return facade.stop()

    server.run(transport="stdio")
    return 0
