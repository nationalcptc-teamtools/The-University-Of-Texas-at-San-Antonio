"""Collector interfaces and safe result helpers."""
from __future__ import annotations

from typing import Protocol

from ..contracts import (EvidenceRef, ExecutionContext, Observation, OperationResult,
                         ParseBatch, ToolOutput)


class Collector(Protocol):
    def collect(self, context: ExecutionContext) -> OperationResult: ...


def blocked(reason: str) -> OperationResult:
    return OperationResult(status="blocked", reason=reason)


def stopped() -> OperationResult:
    return OperationResult(status="stopped", reason="operator stop requested")


def safe_value(value: object) -> object:
    """Convert parser tuples into JSON-shaped values without copying raw text."""
    if isinstance(value, (tuple, list)):
        return [safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(k): safe_value(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(type(value).__name__)


def batch_result(batch: ParseBatch, evidence: tuple[EvidenceRef, ...] = ()) -> OperationResult:
    observations = []
    for item in batch.observations:
        observations.append({"track": item.track, "target": item.target,
                             "check_id": item.check_id, "state": item.state,
                             "facts": safe_value(item.facts),
                             "source_sha256": item.source.sha256})
    facts = {"observations": observations, "issues": [item.code for item in batch.issues],
             "duplicates": batch.duplicates}
    status = "complete" if observations or not batch.issues else "failed"
    return OperationResult(status=status, facts=facts, evidence=evidence,
                           reason=None if status == "complete" else "import produced no valid observations")


def tool_result(output: ToolOutput) -> tuple[bytes, tuple[EvidenceRef, ...], str | None]:
    """Return bounded tool bytes and retain the tool's status without its prose."""
    if output.status != "complete":
        return b"", (), output.reason or "contained tool did not complete"
    return output.stdout, (), None
