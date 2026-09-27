"""Versioned assessment metadata; these types grant no execution capability.

Legacy operation contracts remain version 1. These additional contracts are
strictly additive. Expected benchmark answers are deliberately absent here.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from .contracts import PolicyError, canonical_json, digest, to_json, validate_schema

ASSESSMENT_VERSION = 1
DISPOSITIONS = frozenset({"candidate", "observed_condition", "not_observed",
                          "unknown", "incomplete", "unsupported", "not_tested",
                          "failed", "blocked", "manual_only"})


def bounded_text(value: str, limit: int = 256, *, empty: bool = False) -> str:
    if (not isinstance(value, str) or (not value and not empty) or len(value) > limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise PolicyError("invalid assessment metadata")
    return value


def identifiers(values: tuple[str, ...], limit: int = 256) -> None:
    if type(values) is not tuple or len(values) > limit or any(type(v) is not str for v in values):
        raise PolicyError("invalid assessment identifiers")
    if len(set(values)) != len(values):
        raise PolicyError("duplicate assessment identifiers")
    for value in values:
        bounded_text(value)


def checksum(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PolicyError("invalid assessment checksum")
    return value


@dataclass(frozen=True)
class ComponentIdentity:
    component_id: str
    target_id: str
    ecosystem: str
    product: str
    version: str = ""
    release: str = ""
    architecture: str = ""
    distribution: str = ""
    os_build: str = ""
    patch_ids: tuple[str, ...] = ()
    source_actions: tuple[str, ...] = ()
    provenance: str = "unknown"
    schema_version: int = ASSESSMENT_VERSION

    def __post_init__(self):
        for name in ("component_id", "target_id", "ecosystem", "product"):
            bounded_text(getattr(self, name))
        for name in ("version", "release", "architecture", "distribution", "os_build"):
            bounded_text(getattr(self, name), empty=True)
        identifiers(self.patch_ids)
        identifiers(self.source_actions)
        if self.provenance not in {"unknown", "banner", "package_database", "os_inventory", "operator_reviewed"}:
            raise PolicyError("invalid component provenance")
        if type(self.schema_version) is not int or self.schema_version != ASSESSMENT_VERSION:
            raise PolicyError("unsupported assessment schema")


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    track: str
    module_ids: tuple[str, ...]
    required_fields: tuple[str, ...]
    prerequisites: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    mode: str = "offline"
    version: str = "1"

    def __post_init__(self):
        bounded_text(self.check_id)
        bounded_text(self.track)
        bounded_text(self.version)
        for name in ("module_ids", "required_fields", "prerequisites", "references"):
            identifiers(getattr(self, name))
        if self.mode not in {"offline", "bounded", "manual_only"}:
            raise PolicyError("invalid check mode")


@dataclass(frozen=True)
class CheckResult:
    target_id: str
    check_id: str
    role_id: str
    disposition: str
    collection_complete: bool = False
    source_actions: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    wave_id: str = ""
    item_id: str = ""
    plan_sha256: str = ""

    def __post_init__(self):
        for name in ("target_id", "check_id", "role_id"):
            bounded_text(getattr(self, name))
        for name in ("source_actions", "evidence_ids", "limitations"):
            identifiers(getattr(self, name))
        if self.disposition not in DISPOSITIONS or type(self.collection_complete) is not bool:
            raise PolicyError("invalid check outcome")
        if self.disposition in {"not_observed", "observed_condition"} and (
                not self.collection_complete or not self.source_actions or not self.evidence_ids):
            raise PolicyError("check conclusion requires complete source evidence")
        if self.wave_id or self.item_id or self.plan_sha256:
            bounded_text(self.wave_id)
            bounded_text(self.item_id)
            checksum(self.plan_sha256)
            if self.source_actions != (assessment_request_id(self.wave_id, self.item_id),):
                raise PolicyError("assessment result must bind its exact action")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    result: CheckResult
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    attack_techniques: tuple[str, ...] = ()
    missing_prerequisites: tuple[str, ...] = ()
    review_state: str = "unreviewed"
    review_artifact: str = ""
    review_artifact_sha256: str = ""
    review_result_sha256: str = ""

    def __post_init__(self):
        bounded_text(self.finding_id)
        if not isinstance(self.result, CheckResult):
            raise PolicyError("finding requires typed check result")
        for name, pattern in (("cve_ids", r"CVE-[0-9]{4}-[0-9]{4,19}"),
                              ("cwe_ids", r"CWE-[0-9]{1,6}"),
                              ("attack_techniques", r"T[0-9]{4}(?:\.[0-9]{3})?")):
            identifiers(getattr(self, name))
            if any(not re.fullmatch(pattern, v) for v in getattr(self, name)):
                raise PolicyError("invalid weakness reference")
        identifiers(self.missing_prerequisites)
        if self.review_state not in {"unreviewed", "accepted", "rejected", "needs_evidence"}:
            raise PolicyError("invalid finding review state")
        bounded_text(self.review_artifact, empty=True)
        if self.review_state in {"accepted", "rejected"} and not self.review_artifact:
            raise PolicyError("human review requires an artifact reference")
        if self.review_state in {"accepted", "rejected"}:
            checksum(self.review_artifact_sha256)
            if self.review_result_sha256 != digest(self.result):
                raise PolicyError("review does not bind this exact check result")

    def verify_evidence(self, verified_artifacts: dict[str, str]) -> None:
        """Caller supplies an integrity-verified artifact index, never model data."""
        if any(ident not in verified_artifacts for ident in self.result.evidence_ids):
            raise PolicyError("finding has unlinked collection evidence")
        for ident in self.result.evidence_ids:
            checksum(verified_artifacts[ident])
        if self.review_state in {"accepted", "rejected"} and verified_artifacts.get(self.review_artifact) != self.review_artifact_sha256:
            raise PolicyError("finding review artifact failed integrity binding")


@dataclass(frozen=True)
class AssessmentItem:
    item_id: str
    target_id: str
    check_id: str
    module_id: str
    role_id: str = "unauthenticated"
    args_json: str = "{}"
    approval_id: str = ""
    check_sha256: str = ""
    target_sha256: str = ""
    role_sha256: str = ""

    def __post_init__(self):
        for name in ("item_id", "target_id", "check_id", "module_id", "role_id"):
            bounded_text(getattr(self, name))
        bounded_text(self.approval_id, empty=True)
        for name in ("check_sha256", "target_sha256", "role_sha256"):
            if getattr(self, name):
                checksum(getattr(self, name))
        if not isinstance(self.args_json, str) or len(self.args_json.encode()) > 8192:
            raise PolicyError("assessment arguments exceed allowance")
        try:
            args = json.loads(self.args_json)
            if type(args) is not dict or canonical_json(args).decode() != self.args_json:
                raise ValueError()
        except (ValueError, TypeError, RecursionError):
            raise PolicyError("assessment arguments must be a canonical object") from None


@dataclass(frozen=True)
class AssessmentPlan:
    wave_id: str
    engagement_id: str
    workspace_id: str
    operator_id: str
    policy_revision: str
    policy_sha256: str
    release_sha256: str
    items: tuple[AssessmentItem, ...]
    schema_version: int = ASSESSMENT_VERSION

    def __post_init__(self):
        for name in ("wave_id", "engagement_id", "workspace_id", "operator_id", "policy_revision"):
            bounded_text(getattr(self, name))
        checksum(self.policy_sha256)
        checksum(self.release_sha256)
        if (type(self.schema_version) is not int or self.schema_version != ASSESSMENT_VERSION or type(self.items) is not tuple
                or not 1 <= len(self.items) <= 256
                or any(not isinstance(i, AssessmentItem) for i in self.items)):
            raise PolicyError("invalid assessment wave")
        if len({i.item_id for i in self.items}) != len(self.items):
            raise PolicyError("duplicate assessment item")
        if len({(i.target_id, i.check_id, i.role_id) for i in self.items}) != len(self.items):
            raise PolicyError("duplicate target check role")

    @property
    def sha256(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class WaveClaim:
    wave_id: str
    item_id: str
    request_id: str
    plan_sha256: str
    state: str
    result_json: str | None = None

    def __post_init__(self):
        bounded_text(self.wave_id)
        bounded_text(self.item_id)
        checksum(self.plan_sha256)
        if self.request_id != assessment_request_id(self.wave_id, self.item_id):
            raise PolicyError("wave claim action identity is invalid")
        if self.state not in {"planned", "dispatching", "running", "complete", "failed", "blocked", "stopped", "uncertain"}:
            raise PolicyError("invalid wave claim state")
        if self.result_json is not None and (not isinstance(self.result_json, str) or len(self.result_json.encode()) > 1048576):
            raise PolicyError("wave result exceeds allowance")


def assessment_request_id(wave_id: str, item_id: str) -> str:
    return digest({"wave_id": bounded_text(wave_id), "item_id": bounded_text(item_id)})[:32]


def registry_digest(registry) -> str:
    return digest([to_json(spec) for spec in registry.specs()])


def verify_assessment_result(result: CheckResult, plan: AssessmentPlan, *,
                             verified_actions: dict, verified_evidence: dict) -> None:
    """Validate against integrity-verified broker receipts, never model input.

    A deterministic request ID binds intent, not execution. The caller must
    obtain these indexes from the central audit/ledger after verification.
    An empty index or a historical unbound record cannot satisfy a new wave.
    """
    if (not isinstance(result, CheckResult) or result.wave_id != plan.wave_id
            or result.plan_sha256 != plan.sha256):
        raise PolicyError("check result belongs to a different assessment")
    item = next((item for item in plan.items if item.item_id == result.item_id), None)
    if item is None or (result.target_id, result.check_id, result.role_id) != (item.target_id, item.check_id, item.role_id):
        raise PolicyError("check result does not match assessment item")
    if result.source_actions != (assessment_request_id(plan.wave_id, item.item_id),):
        raise PolicyError("check result action does not match assessment item")
    action_id = result.source_actions[0]
    receipt = verified_actions.get(action_id)
    required = {"request_id", "target_id", "check_id", "role_id", "module_id", "plan_sha256", "item_id", "status", "evidence_ids"}
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise PolicyError("assessment result has no verified dispatch receipt")
    expected = {"request_id": action_id, "target_id": result.target_id, "check_id": result.check_id,
                "role_id": result.role_id, "module_id": item.module_id, "plan_sha256": plan.sha256, "item_id": item.item_id}
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise PolicyError("assessment dispatch receipt does not match result")
    if receipt["status"] not in {"complete", "failed", "blocked", "stopped", "uncertain"}:
        raise PolicyError("assessment dispatch lacks a terminal receipt")
    if result.collection_complete and receipt["status"] != "complete":
        raise PolicyError("incomplete dispatch cannot substantiate a complete check")
    if not isinstance(receipt["evidence_ids"], (tuple, list)) or any(type(value) is not str for value in receipt["evidence_ids"]):
        raise PolicyError("assessment dispatch has an invalid evidence index")
    for ident in result.evidence_ids:
        evidence = verified_evidence.get(ident)
        if (ident not in receipt["evidence_ids"] or not isinstance(evidence, dict)
                or set(evidence) != {"source_action", "sha256"} or evidence["source_action"] != action_id):
            raise PolicyError("assessment evidence is not owned by this dispatch")
        checksum(evidence["sha256"])


def verify_assessment_plan(plan: AssessmentPlan, policy, registry,
                           checks: dict[str, CheckDefinition], roles: dict[str, dict]) -> None:
    """Resolve all frozen references before reserving; this never dispatches.

    Blank binding hashes are permitted only in inert drafts. Every executable
    item must bind the actual operator-approved policy, check, target and role.
    The broker still independently validates scope, clock, grants and budgets.
    """
    from datetime import datetime, timezone
    if (plan.engagement_id, plan.workspace_id, plan.operator_id, plan.policy_revision) != (
            policy.engagement_id, policy.workspace_id, policy.operator_id, policy.revision):
        raise PolicyError("assessment policy identity changed")
    if plan.policy_sha256 != digest(policy) or plan.release_sha256 != registry_digest(registry):
        raise PolicyError("assessment policy or release changed")
    for item in plan.items:
        spec = registry.get(item.module_id)
        check = checks.get(item.check_id)
        target = next((t for t in policy.targets if t.target.target_id == item.target_id), None)
        role = roles.get(item.role_id)
        if check is None or role is None or target is None or not isinstance(check, CheckDefinition):
            raise PolicyError("assessment reference is not approved")
        if item.check_sha256 != digest(check) or item.target_sha256 != digest(target) or item.role_sha256 != digest(role):
            raise PolicyError("assessment check, target or account role changed")
        if spec.mode == "manual_only" or check.mode == "manual_only":
            raise PolicyError("manual-only checks cannot enter an execution wave")
        if item.module_id not in check.module_ids or item.module_id not in target.permitted_modules:
            raise PolicyError("assessment module is not approved for check and target")
        if not target.eligible or target.assigned_workspace != policy.workspace_id:
            raise PolicyError("assessment target assignment is not eligible")
        unauthenticated = item.role_id == "unauthenticated" and role == {"auth_realm": "", "method": None}
        if not unauthenticated and (role.get("auth_realm", "") != target.auth_realm or role.get("method") != target.auth_method):
            raise PolicyError("assessment role does not match target authentication policy")
        arguments = json.loads(item.args_json)
        validate_schema(arguments, spec.input_schema)
        if "proof" in spec.effects:
            approval = next((a for a in policy.approvals if a.approval_id == item.approval_id), None)
            if approval is None or (approval.module_id, approval.target_id, approval.operator_id,
                    approval.policy_revision, approval.request_id, approval.args_hash) != (
                    item.module_id, item.target_id, policy.operator_id, policy.revision,
                    assessment_request_id(plan.wave_id, item.item_id), digest(arguments)):
                raise PolicyError("assessment proof lacks exact action approval")
            try:
                expiry = datetime.fromisoformat(approval.expires_at.replace("Z", "+00:00"))
                if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                    raise ValueError()
            except (ValueError, TypeError):
                raise PolicyError("assessment approval expired or invalid") from None
