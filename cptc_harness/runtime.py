"""Trusted local composition root; none of these paths come from a model reply."""
from __future__ import annotations
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import uuid
from .audit_service import AuditService
from .broker import Broker
from .clockcheck import current_clock, ClockService
from .contracts import AuditEvent, OperationRequest, PolicyError, SourceRef, canonical_json, to_json
from .ledger import Ledger
from .network import NetworkBroker
from .orchestrator import Workflows
from .policy import load_policy, save_policy
from .registry import build_registry
from .storage import private_directory, read_private, write_json
from .publication import Publications
from .audit_control import reconcile_stop_intents


def device_root():
    # Deliberately outside disposable workspace. No AI override or reset endpoint.
    return Path.home() / ".local" / "state" / "cptc-harness"


def initialize(root: Path, policy_path: Path, *, recipient: str, age_binary: Path):
    root = Path(root).absolute()
    if any((ancestor / ".git").exists() for ancestor in (root, *root.parents)):
        raise PolicyError("engagement storage must be outside Git working trees")
    if root.exists() and any(root.iterdir()):
        raise PolicyError("initialize requires an empty workspace")
    policy = load_policy(policy_path)
    if not recipient.startswith("age1") or len(recipient) > 128 or any(c.isspace() for c in recipient):
        raise PolicyError("an explicit age recipient is required for raw evidence")
    if not age_binary.is_file() or not os.access(age_binary, os.X_OK):
        raise PolicyError("pinned age executable is unavailable")
    private_directory(root, create=True)
    save_policy(root / "policy.json", policy)
    write_json(root / "runtime.json", {"version": 1, "age_recipient": recipient, "age_binary": str(age_binary.resolve()),
                                      "age_sha256": hashlib.sha256(age_binary.read_bytes()).hexdigest()})
    for name in ("audit", "results", "reports", "policies"):
        private_directory(root / name, create=True)
    save_policy(root / "policies" / (policy.revision + ".json"), policy)
    return {"workspace": str(root), "engagement_id": policy.engagement_id,
            "active_testing": "requires policy eligibility, time, scope, assignment, encryption, audit and isolation gates"}


class Runtime:
    def __init__(self, root: Path, *, ledger_root: Path | None = None):
        self.root = private_directory(root)
        self.policy = load_policy(self.root / "policy.json")
        config = json.loads(read_private(self.root / "runtime.json"))
        if set(config) != {"version", "age_recipient", "age_binary", "age_sha256"} or config["version"] != 1:
            raise PolicyError("invalid runtime configuration")
        if hashlib.sha256(Path(config["age_binary"]).read_bytes()).hexdigest() != config["age_sha256"]:
            raise PolicyError("age executable differs from initialized deployment pin")
        self.ledger_root = private_directory((ledger_root or device_root()) / self.policy.engagement_id, create=True)
        self.ledger = Ledger(self.ledger_root, self.policy.engagement_id, self.policy.device_id, policy_revision=self.policy.revision)
        self.audit = AuditService(self.root / "audit", self.policy, age_binary=config["age_binary"], age_recipient=config["age_recipient"])
        self.clock = self.audit.clock
        try:
            # Pending stop controls predate this writer.  Replay their fixed,
            # receipt-bound metadata before admitting any other Runtime work.
            reconcile_stop_intents(self.ledger, self.audit, policy=self.policy)
            interrupted = self.ledger.recover_attempts()
            if interrupted:
                from .audit_control import required_emit
                required_emit(self.audit, self.ledger, AuditEvent("transport_attempt_recovery", data={
                    "attempts": list(interrupted), "status": "uncertain", "automatic_retry": False}))
            recovered = self.ledger.recover_waves(workspace_id=self.policy.workspace_id)
            if recovered:
                from .audit_control import required_emit
                required_emit(self.audit, self.ledger, AuditEvent("assessment_recovery", data={
                    "items": [to_json(claim) for claim in recovered], "status": "uncertain", "automatic_retry": False}))
            self.ledger.enroll_workspace(self.policy.workspace_id, self.audit.origin_id, hashlib.sha256(str(self.root).encode()).hexdigest())
            self.publications = Publications(self.root, self.audit, self.ledger)
            self.publications.recover()
        except Exception:
            self.audit.close()
            raise
        self.registry = build_registry()
        self.network = NetworkBroker(self.policy, audit=self.audit, ledger=self.ledger)
        self.broker = Broker(self.policy, self.registry, self.ledger, self.audit, network=self.network, clock=self.clock, result_sink=self._record_result)
        from .campaign import AssessmentCampaign
        self.campaign = AssessmentCampaign(self.broker)
        self.workflows = Workflows(self.ledger_root / "workflows", self.broker)

    def verify_check_result(self, result) -> None:
        """Human review boundary: callers cannot provide their own audit indexes."""
        from .assessment_contracts import CheckResult, verify_assessment_result
        from .campaign import _stored_plan, request_for
        from .reporting import evidence_index
        if type(result) is not CheckResult or not self.audit.verify().valid or not self.audit.ready():
            raise PolicyError("verified audit and typed check result required")
        plan = _stored_plan(self.ledger, result.wave_id, result.plan_sha256)
        self.campaign._verify(plan)
        records = self._records(); actions = {}
        for item in plan.items:
            request = request_for(plan, item, self.policy)
            record = next((r for r in records if r["request"]["request_id"] == request.request_id), None)
            if record is None: continue
            if record["request"] != to_json(request): raise PolicyError("audited request differs from assessment plan")
            stored = self.ledger._db.execute("SELECT state,result_json FROM assessment_items WHERE engagement=? AND device=? AND wave_id=? AND item_id=?",
                (self.policy.engagement_id, self.policy.device_id, plan.wave_id, item.item_id)).fetchone()
            if not stored or not stored[1] or json.loads(stored[1]) != record["result"] or stored[0] != record["result"]["status"]:
                raise PolicyError("assessment result differs from durable audit record")
            actions[request.request_id] = {"request_id": request.request_id, "target_id": item.target_id,
                "check_id": item.check_id, "role_id": item.role_id, "module_id": item.module_id,
                "plan_sha256": plan.sha256, "item_id": item.item_id, "status": stored[0],
                "evidence_ids": [e["evidence_id"] for e in record["result"]["evidence"]]}
        index = {e["evidence_id"]: {"source_action": e["source_action"], "sha256": e["sha256"]} for e in evidence_index(records)}
        verify_assessment_result(result, plan, verified_actions=actions, verified_evidence=index)

    def close(self) -> None:
        """Reconcile durable stop intent before a clean audit shutdown."""
        try:
            reconcile_stop_intents(self.ledger, self.audit, policy=self.policy)
        except Exception:
            try:
                self.ledger.stop("operator control reconciliation failed")
            finally:
                self.audit.close()
            raise PolicyError("operator stop reconciliation failed; workspace remains stopped") from None
        self.audit.close()

    def export_handover(self, recipient_device_id, recipient_key_fingerprint, signer, *, seal_id=None):
        if not self.audit.verify().valid:
            raise PolicyError("audit must verify before handover")
        if seal_id is None:
            seal_id = self.ledger.seal_for_handover(recipient_device_id, recipient_key_fingerprint)
            self.audit.emit(AuditEvent("handover_sealed", data={"seal_id": seal_id, "recipient_device": recipient_device_id,
                                  "recipient_key_fingerprint": recipient_key_fingerprint}))
        bundle = self.ledger.handover_bundle(seal_id, signer)
        if bundle.payload["recipient_device"] != recipient_device_id or bundle.payload["recipient_key_fingerprint"] != recipient_key_fingerprint:
            raise PolicyError("sealed handover recipient cannot change")
        from .contracts import digest
        self.audit.emit(AuditEvent("handover_exported", data={"seal_id": seal_id, "bundle_hash": digest(asdict(bundle))}))
        return bundle

    def import_handover(self, bundle, trusted_source_keys, local_key_fingerprint, approved_digest):
        if not self.audit.verify().valid:
            raise PolicyError("audit must verify before handover")
        self.audit.emit(AuditEvent("handover_import_intent", data={"source_device": bundle.device_id, "approved_digest": approved_digest}))
        result = self.ledger.merge_handover(bundle, trusted_source_keys, local_key_fingerprint, approved_digest)
        try:
            self.audit.emit(AuditEvent("handover_import_result", data=to_json(result)))
        except Exception:
            self.ledger.stop("handover audit outcome uncertain")
            raise PolicyError("handover accounting preserved but audit outcome uncertain; destination stopped") from None
        return result

    def run(self, module_id: str, *, target_id: str | None = None, input_path: Path | None = None,
            args: dict | None = None, approval_id: str | None = None):
        spec = self.registry.get(module_id)
        target = None
        if target_id is not None:
            target = next((t.target for t in self.policy.targets if t.target.target_id == target_id), None)
            if target is None:
                raise PolicyError("unknown registered target")
        raw = b""
        source = None
        if input_path is not None:
            if spec.mode != "offline":
                raise PolicyError("raw imports are offline only")
            raw = read_private(input_path, min(spec.bounds.output_bytes, 131072))
            source = SourceRef(uuid.uuid4().hex, hashlib.sha256(raw).hexdigest())
        request = OperationRequest(uuid.uuid4().hex, self.policy.workspace_id, self.policy.device_id,
            self.policy.operator_id, module_id, target, args or {}, "operator", approval_id, self.policy.revision)
        result = self.broker.execute(request, actor="operator", input_bytes=raw, source=source)
        return {"version": 1, "classification": "client_confidential", "request": to_json(request), "result": to_json(result)}

    def _record_result(self, request, result):
        from .policy import identifier
        identifier(request.request_id)
        record = {"version": 1, "classification": "client_confidential", "request": to_json(request), "result": to_json(result)}
        receipt = self.audit.emit(AuditEvent("result_record_intent", request.request_id))
        record["audit_sequence"], record["recorded_at"] = receipt["seq"], receipt["timestamp"]
        private_directory(self.root / "results", create=True)
        write_json(self.root / "results" / (request.request_id + ".json"), record, replace=False)
        self.audit.emit(AuditEvent("result_record_written", request.request_id,
            {"record_sha256": hashlib.sha256(canonical_json(record)).hexdigest(), "source": request.source, "status": result.status}))

    def _publish_derived(self, payloads, completion):
        self.publications.publish(payloads, completion)

    def coverage(self):
        from .reporting import summarize_result
        from .check_catalog import capability_status, expected_checks
        from .detection import classify_records
        try:
            if not self.audit.verify().valid or not self.audit.ready():
                raise PolicyError("verified audit required before coverage")
            results = self._records()
            items = []
            for spec in self.registry.specs():
                matching = [r for r in results if r["request"]["module_id"] == spec.module_id]
                latest = summarize_result(matching[-1]["result"]) if matching else {
                    "collection_state": "not_tested", "issues": [], "observation_count": 0}
                items.append({"module_id": spec.module_id, "track": spec.track, "mode": spec.mode,
                              "attempts": len(matching), "latest_status": matching[-1]["result"]["status"] if matching else "not_tested",
                              **latest,
                              "issue_attempts": sum(bool(r["result"].get("facts", {}).get("issues")) for r in matching),
                              "unsuccessful_attempts": sum(r["result"]["status"] != "complete" for r in matching),
                              "live_validation": "unverified"})
            classified = classify_records(results, expected_checks=expected_checks(self.policy, self.registry))
            data = {"classification": "client_confidential", "modules": items,
                    "checks": classified["coverage"], "capabilities": capability_status(),
                    "detector_catalog_version": classified["catalog_version"],
                    "coverage_basis": "assigned targets and finite check catalog; explicit credentialed role plans still required",
                    "model_calls": 0, "finding_confirmation": "Requires evidence-backed human review"}
            self.audit.emit(AuditEvent("coverage_intent", data={"profiles": len(items), "records": len(results)}))
            self._publish_derived([(self.root / "coverage.json", canonical_json(data) + b"\n")],
                AuditEvent("coverage_generated", data={"profiles": len(items), "records": len(results)}))
            return data
        except Exception as exc:
            self.ledger.stop("coverage audit or storage failed")
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError("coverage incomplete; workspace stopped for review") from None

    def _records(self):
        try:
            receipts = self.audit.result_receipts()
            results = []
            private_directory(self.root / "results")
            for path in (self.root / "results").iterdir():
                if path.suffix != ".json":
                    raise PolicyError("unexpected result artifact")
                value = json.loads(read_private(path))
                if (receipts.get(path.stem) != hashlib.sha256(canonical_json(value)).hexdigest()
                        or value["request"]["request_id"] != path.stem):
                    raise PolicyError("result record does not match its audit receipt")
                results.append(value)
            if {r["request"]["request_id"] for r in results} != set(receipts):
                raise PolicyError("audit-linked result record is missing")
            return sorted(results, key=lambda r: r["audit_sequence"])
        except Exception:
            self.ledger.stop("result record integrity failure")
            raise PolicyError("result records failed integrity verification; engagement stopped") from None

    def report(self, *, include_data=False):
        from .reporting import report_records, markdown_report
        from .check_catalog import capability_status, expected_checks
        from .contracts import digest
        try:
            if not self.audit.verify().valid or not self.audit.ready():
                raise PolicyError("verified audit required before reporting")
            records = self._records()
            data = report_records(records, expected_checks=expected_checks(self.policy, self.registry))
            data["scope_sha256"] = digest(self.policy.scope)
            data["policy_sha256"] = digest(self.policy)
            data["capabilities"] = capability_status()
            # Deployment/image provenance must be supplied and independently
            # verified by the operator; policy identity cannot stand in for it.
            data["provenance_sha256"] = None
            self.audit.emit(AuditEvent("report_intent", data={"records": len(records), "observations": len(data["observations"])}))
            self._publish_derived([
                (self.root / "reports/observations.json", canonical_json(data) + b"\n"),
                (self.root / "reports/observations.md", markdown_report(data).encode()),
            ], AuditEvent("report_complete", data={"observations": len(data["observations"]),
                "sha256": hashlib.sha256(canonical_json(data)).hexdigest(), "model_calls": 0}))
            if include_data:
                return data
            return {"classification": "client_confidential", "observations": len(data["observations"]),
                    "detections": len(data["detections"]), "check_results": len(data["check_coverage"]),
                    "json": str(self.root / "reports/observations.json"), "markdown": str(self.root / "reports/observations.md"), "model_calls": 0}
        except Exception as exc:
            self.ledger.stop("report storage or audit failed")
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError("report incomplete; workspace stopped for review") from None
