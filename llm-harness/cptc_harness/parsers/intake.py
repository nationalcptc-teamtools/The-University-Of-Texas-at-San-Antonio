"""Human-result and reporting import parsers."""
from __future__ import annotations

from ..contracts import Observation, ParseBatch, SourceRef
from .common import bounded_string, finish, issue, json_records, load_json, start, text
import json
import re

STATES = {"observed", "no_issue_observed", "candidate", "confirmed", "blocked", "attempted", "retest"}
SEVERITIES = {"informational", "low", "medium", "high", "critical", "unknown"}
REF_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")


def aggregate_host_observations(batches: tuple[ParseBatch, ...] | list[ParseBatch], source: SourceRef | str) -> ParseBatch:
    """Merge host batches in a stable order while retaining source provenance."""
    observations: list[Observation] = []
    issues = []
    duplicates = 0
    preferred = source if isinstance(source, SourceRef) else None
    for batch in batches:
        duplicates += batch.duplicates
        issues.extend(batch.issues)
        for observation in batch.observations:
            if observation.track in {"linux", "windows_ad"}:
                observations.append(observation if preferred is None else Observation(
                    observation.track, observation.target, observation.check_id, observation.state,
                    dict(observation.facts), preferred))
    observations.sort(key=lambda item: (item.target, item.track, item.check_id,
                                        json.dumps(item.facts, sort_keys=True, separators=(",", ":")), item.source.sha256))
    return finish(observations, sorted(issues, key=lambda item: (item.code, item.record or 0)))


def parse_exploit_intake(raw: bytes | str, source: SourceRef | str) -> ParseBatch:
    payload, source_ref_value, issues = start(raw, source)
    observations: list[Observation] = []
    try:
        records = json_records(load_json(payload))
    except (ValueError, TypeError):
        records = []
        for number, line in enumerate(text(payload).splitlines()[:2048], 1):
            fields = [part.strip() for part in line.split("|", 3)]
            if len(fields) == 4:
                records.append({"target": fields[0], "check_id": fields[1], "state": fields[2], "evidence": fields[3]})
            elif line.strip():
                issues.append(issue("malformed_record", number))
    for number, record in enumerate(records, 1):
        target = bounded_string(record.get("target"))
        check_id = bounded_string(record.get("check_id"), maximum=64)
        state = bounded_string(record.get("state"), maximum=32)
        evidence = bounded_string(record.get("evidence"), maximum=128)
        if not target or not check_id or state not in STATES:
            issues.append(issue("invalid_record", number))
            continue
        facts: dict[str, object] = {"human_result": state, "evidence_attached": bool(evidence)}
        if evidence:
            facts["evidence_ref_present"] = True
        observations.append(Observation("exploitation", target, check_id, state, facts, source_ref_value))
    return finish(observations, issues)


def parse_reporting_records(raw: bytes | str, source: SourceRef | str) -> ParseBatch:
    payload, source_ref_value, issues = start(raw, source)
    observations: list[Observation] = []
    try:
        records = json_records(load_json(payload))
    except (ValueError, TypeError):
        records = []
        issues.append(issue("malformed_json"))
    seen_ids: set[str] = set()
    for number, record in enumerate(records, 1):
        target = bounded_string(record.get("target"))
        finding_id = bounded_string(record.get("finding_id"), maximum=64)
        record_type = bounded_string(record.get("record_type"), maximum=16) or "finding"
        severity = bounded_string(record.get("severity"), maximum=16) or "unknown"
        evidence_state = bounded_string(record.get("evidence_state"), maximum=24) or "unknown"
        reviewed = record.get("reviewed") is True
        evidence_ref = bounded_string(record.get("evidence_ref"), maximum=128)
        if evidence_ref is not None and not REF_RE.fullmatch(evidence_ref):
            evidence_ref = None
        retest = bounded_string(record.get("retest"), maximum=24) or "not_tested"
        if record_type not in {"finding", "coverage", "retest"} or not target or not finding_id or severity not in SEVERITIES:
            issues.append(issue("invalid_record", number))
            continue
        duplicate = finding_id in seen_ids
        if duplicate:
            issues.append(issue("duplicate_finding_id", number))
        seen_ids.add(finding_id)
        state = "retest" if record_type == "retest" or retest in {"fixed", "open", "not_applicable"} else "observed"
        confirmation_downgraded = evidence_state == "confirmed" and (not reviewed or not evidence_ref)
        if confirmation_downgraded:
            issues.append(issue("confirmation_needs_reviewed_evidence", number))
        facts = {"finding_id": finding_id, "severity": severity,
                 "evidence_state": evidence_state, "retest_state": retest,
                 "duplicate": duplicate, "reviewed": reviewed}
        if evidence_ref:
            facts["evidence_ref"] = evidence_ref
        if record_type == "coverage":
            coverage_state = bounded_string(record.get("coverage_state"), maximum=24) or "unknown"
            facts["coverage_state"] = coverage_state
            state = "observed"
        if record_type == "retest":
            facts["retest_state"] = retest if retest in {"fixed", "open", "not_applicable"} else "not_tested"
        if confirmation_downgraded:
            state = "candidate"
        elif evidence_state == "confirmed" and reviewed and evidence_ref and record_type != "retest":
            state = "confirmed"
        observations.append(Observation("reporting", target, "finding_record", state, facts, source_ref_value))
    return finish(observations, issues)
