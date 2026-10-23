"""Stable report identities, comparisons, merging, and team review metadata.

All functions operate on copies. A stable identity describes the observation's location;
its separately compared content describes what was observed at that location.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from fieldkit.core.storage import utc_now

COLLECTIONS = ("findings", "results", "endpoints")
VOLATILE = {
    "id",
    "evidence",
    "evidence_id",
    "evidence_ids",
    "file",
    "body_file",
    "request_file",
    "response_file",
    "started_at",
    "finished_at",
    "timestamp",
    "created_at",
    "updated_at",
    "review",
    "review_conflicts",
    "review_history",
    "sources",
    "source_reports",
    "duration",
    "elapsed",
    "original_id",
    "observation_conflicts",
    "evidence_sources",
    "captured_at",
    "artifact_root",
    "source_report",
}


def _source_location(source: Any, url: Any) -> Any:
    if url and isinstance(source, str) and not source.startswith(("http://", "https://")):
        container, separator, embedded = source.partition("::")
        return container.rsplit("/", 1)[-1] + (separator + embedded if separator else "")
    return source


def stable_content(value: Any) -> Any:
    """Remove run-local metadata recursively, retaining substantive observation values."""
    if isinstance(value, dict):
        return {
            key: stable_content(
                _source_location(
                    item, value.get("url") or value.get("requested_url") or value.get("final_url")
                )
                if key == "source"
                else item
            )
            for key, item in sorted(value.items())
            if key not in VOLATILE
            and not key.endswith(("_evidence", "_evidence_id", "_evidence_ids"))
        }
    if isinstance(value, list):
        return [stable_content(item) for item in value]
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:20]


def stable_id(record: dict, kind: str = "finding") -> str:
    """Content-address an observation's semantic location, independent of run artifacts."""
    details = record.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    source = record.get("source") or details.get("source")
    url = record.get("requested_url") or record.get("url") or record.get("final_url")
    source = _source_location(source, url)
    location = {
        "kind": record.get("kind", kind),
        "url": url,
        "method": record.get("method", "GET"),
        "profile": record.get("profile"),
        "title": record.get("title") if kind == "finding" else None,
        "source": source,
        "value": (record.get("value") or details.get("value")) if kind == "finding" else None,
        "line": record.get("line") or details.get("line"),
        "name": record.get("name") or details.get("name"),
        "purpose": record.get("purpose"),
        "parameter": record.get("parameter") or details.get("parameter"),
        "location": record.get("location") or record.get("in") or details.get("location"),
        "cookie_name": record.get("cookie_name")
        or record.get("cookie")
        or details.get("cookie_name"),
        "origin": record.get("origin") or details.get("origin"),
    }
    # Add dimensions only when present, preserving all existing web identities.
    for key in (
        "host",
        "resource",
        "template_id",
        "matcher",
        "identity",
        "object_id",
        "rule_id",
        "request_id",
        "probe_location",
        "protocol",
        "port",
    ):
        if key in record or key in details:
            location[key] = record.get(key, details.get(key))
    if not any(value for key, value in location.items() if key not in {"kind", "method"}):
        location["content"] = stable_content(record)
    return f"{kind}-{_digest(location)}"


def normalize_report(report: dict) -> dict:
    """Accept collector schema v1 and assessment schema v2; return normalized copies."""
    if not isinstance(report, dict):
        raise ValueError("A report must be a JSON object")
    output = copy.deepcopy(report)
    output["schema_version"] = 2
    for collection in COLLECTIONS:
        values = output.setdefault(collection, [])
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            raise ValueError(f"Report {collection} must be an array of objects")
    if report.get("schema_version", 1) == 1:
        for target in report.get("targets", []):
            if not isinstance(target, dict):
                continue
            for result in target.get("results", []):
                output["results"].append(copy.deepcopy(result))
            for result in target.get("results", []):
                url = result.get("requested_url") or result.get("final_url")
                if url:
                    output["endpoints"].append({"url": url, "method": "GET"})
    for collection in COLLECTIONS:
        kind = collection.rstrip("s")
        seen: dict[str, dict] = {}
        for value in output[collection]:
            # Recompute to align older/module-specific IDs; preserve the original for lookup.
            identifier = stable_id(value, kind)
            original = value.get("id")
            if original and original != identifier:
                value.setdefault("original_id", original)
            value["id"] = identifier
            if identifier not in seen:
                seen[identifier] = value
            elif stable_content(value) != stable_content(seen[identifier]):
                # Multiple distinct observations at one location must remain reviewable.
                alternate = f"{identifier}-{_digest(stable_content(value))[:8]}"
                value["id"] = alternate
                seen[alternate] = value
            elif value.get("review") and value.get("review") != seen[identifier].get("review"):
                current = seen[identifier]
                if not current.get("review"):
                    current["review"] = value["review"]
                elif value["review"] not in current.setdefault("review_conflicts", []):
                    current["review_conflicts"].append(value["review"])
        output[collection] = list(seen.values())
    return output


def load_report(path: str | Path) -> dict:
    path = Path(path).expanduser()
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON report {path}: {exc.msg}") from exc
    normalized = normalize_report(report)
    normalized.setdefault("source_report", str(path.resolve()))
    for collection in (*COLLECTIONS, "evidence"):
        for record in normalized.get(collection, []):
            if record.get("file") or record.get("body_file"):
                record.setdefault("artifact_root", str(path.resolve().parent))
    return normalized


def compare_reports(before: dict, after: dict) -> dict:
    """Show added/removed/changed records, retaining both sides of each change."""
    left, right = normalize_report(before), normalize_report(after)
    output: dict[str, Any] = {"schema_version": 2, "module": "results/compare"}
    for collection in COLLECTIONS:
        old = {item["id"]: item for item in left[collection]}
        new = {item["id"]: item for item in right[collection]}
        output[collection] = {
            "added": [new[key] for key in sorted(new.keys() - old.keys())],
            "removed": [old[key] for key in sorted(old.keys() - new.keys())],
            "changed": [
                {"id": key, "before": old[key], "after": new[key]}
                for key in sorted(old.keys() & new.keys())
                if stable_content(old[key]) != stable_content(new[key])
            ],
        }
    return output


def merge_reports(reports: list[dict]) -> dict:
    """Deduplicate reports; preserve conflicting observations and team review decisions."""
    output: dict[str, Any] = {
        "schema_version": 2,
        "module": "results/merge",
        "started_at": utc_now(),
        "completed": True,
        "source_reports": [],
        "evidence": [],
        "errors": [],
        **{collection: [] for collection in COLLECTIONS},
    }
    indices: dict[str, dict[str, dict]] = {collection: {} for collection in COLLECTIONS}
    for number, report in enumerate(reports):
        normalized = normalize_report(report)
        source = report.get("source_report") or f"input-{number + 1}"
        output["source_reports"].append(source)
        for error in normalized.get("errors", []):
            output["errors"].append({"source_report": source, "observation": copy.deepcopy(error)})
        evidence_ids = {}
        for evidence in normalized.get("evidence", []):
            original = evidence.get("id", "unknown")
            evidence_ids[original] = f"input-{number + 1}:{original}"
            evidence["id"] = evidence_ids[original]
            evidence["source_report"] = evidence.get("source_report") or source
            output["evidence"].append(evidence)

        def relink(value):
            if isinstance(value, list):
                return [relink(item) for item in value]
            if isinstance(value, dict):
                return {
                    key: (
                        relink_evidence(item)
                        if key in {"evidence", "evidence_id", "evidence_ids"}
                        or key.endswith(("_evidence", "_evidence_id", "_evidence_ids"))
                        else relink(item)
                    )
                    for key, item in value.items()
                }
            return value

        def relink_evidence(value, evidence_ids=evidence_ids):
            if isinstance(value, str):
                return evidence_ids.get(value, value)
            if isinstance(value, list):
                return [relink_evidence(item) for item in value]
            return relink(value)

        normalized = relink(normalized)
        for collection in COLLECTIONS:
            for value in normalized[collection]:
                key = value["id"]
                current = indices[collection].get(key)
                if current is None:
                    value["sources"] = list(dict.fromkeys([*value.get("sources", []), source]))
                    indices[collection][key] = value
                    continue
                if source not in current["sources"]:
                    current["sources"].append(source)
                if stable_content(current) != stable_content(value):
                    variants = current.setdefault("observation_conflicts", [])
                    variant = {"source": source, "observation": value}
                    if variant not in variants:
                        variants.append(variant)
                incoming_review = value.get("review")
                if incoming_review and not current.get("review"):
                    current["review"] = incoming_review
                elif incoming_review and incoming_review != current.get("review"):
                    variants = current.setdefault("review_conflicts", [])
                    if incoming_review not in variants:
                        variants.append(incoming_review)
                for review in value.get("review_conflicts", []):
                    if review not in current.setdefault("review_conflicts", []):
                        current["review_conflicts"].append(review)
                for field in ("review_history", "observation_conflicts", "evidence_sources"):
                    for entry in value.get(field, []):
                        if entry not in current.setdefault(field, []):
                            current[field].append(entry)
                for entry in value.get("sources", []):
                    if entry not in current["sources"]:
                        current["sources"].append(entry)
                # Evidence can differ while substantive observations are identical.
                for field in ("evidence", "evidence_id", "evidence_ids"):
                    if field in value and value[field] != current.get(field):
                        variants = current.setdefault("evidence_sources", [])
                        evidence = {"source": source, field: value[field]}
                        if evidence not in variants:
                            variants.append(evidence)
    for collection, index in indices.items():
        output[collection] = list(index.values())
    output["finished_at"] = utc_now()
    return output


def update_review(
    report: dict, finding_id: str, *, status: str = "unreviewed", assignee: str = "", note: str = ""
) -> dict:
    """Return a report with a finding assigned/reviewed; never mutate source reports."""
    if status not in {"unreviewed", "in-progress", "confirmed", "dismissed", "resolved"}:
        raise ValueError("Unknown review status")
    output = normalize_report(report)
    candidates = [
        item for item in output["findings"] if finding_id in {item["id"], item.get("original_id")}
    ]
    if len(candidates) != 1:
        raise ValueError(f"Finding ID must match exactly one finding: {finding_id}")
    finding = candidates[0]
    review = {"status": status, "assignee": assignee, "note": note, "updated_at": utc_now()}
    if finding.get("review"):
        finding.setdefault("review_history", []).append(copy.deepcopy(finding["review"]))
    finding["review"] = review
    return output
