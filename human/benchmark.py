#!/usr/bin/env python3
"""External, offline expected-issue comparator. Never imported by runtime.

This human tool reads a reviewed catalog only after detector execution. The
catalog is not a runtime input, a scanner configuration, or a packaged answer
key. Hashes bind the exact operator-selected inputs, not their authenticity.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "cptc-benchmark-v1"


def text(value, maximum=256):
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("invalid benchmark metadata")
    return value


def ids(value):
    if not isinstance(value, list) or len(value) > 256 or any(not isinstance(v, str) for v in value) or len(set(value)) != len(value):
        raise ValueError("invalid benchmark identifiers")
    return [text(v) for v in value]


def validate_catalog(catalog):
    required = {"schema", "catalog_id", "reviewer", "scope_sha256", "provenance_sha256",
                "catalog_complete", "entries"}
    if type(catalog) is not dict or set(catalog) != required or catalog["schema"] != SCHEMA:
        raise ValueError("invalid benchmark catalog")
    for name in ("catalog_id", "reviewer"):
        text(catalog[name])
    for name in ("scope_sha256", "provenance_sha256"):
        if not isinstance(catalog[name], str) or not re.fullmatch(r"[0-9a-f]{64}", catalog[name]):
            raise ValueError("benchmark requires provenance and scope hashes")
    if type(catalog["catalog_complete"]) is not bool or not isinstance(catalog["entries"], list) or len(catalog["entries"]) > 10000:
        raise ValueError("invalid benchmark completeness")
    seen = set()
    fields = {"issue_id", "population", "eligibility", "target", "rule_id", "role_id",
              "cve_ids", "required_evidence_fields", "source_sha256", "expectation"}
    for entry in catalog["entries"]:
        if type(entry) is not dict or set(entry) != fields:
            raise ValueError("invalid benchmark entry")
        for name in ("issue_id", "target", "rule_id", "role_id"):
            text(entry[name])
        if entry["issue_id"] in seen:
            raise ValueError("duplicate benchmark issue")
        seen.add(entry["issue_id"])
        if entry["population"] not in {"original_scenario", "later_advisory"} or entry["eligibility"] not in {"automated", "manual_only"}:
            raise ValueError("invalid benchmark classification")
        if entry["expectation"] not in {"present", "absent"}:
            raise ValueError("invalid expected condition")
        if not isinstance(entry["source_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["source_sha256"]):
            raise ValueError("entry lacks source provenance")
        if any(not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", v) for v in ids(entry["cve_ids"])):
            raise ValueError("invalid CVE identifier")
        ids(entry["required_evidence_fields"])
    return catalog


def _evidence_index(report):
    values = report.get("evidence_index", [])
    if not isinstance(values, list) or len(values) > 100000:
        raise ValueError("invalid benchmark evidence index")
    index = {}
    for item in values:
        if type(item) is not dict or set(item) != {"evidence_id", "sha256", "source_action"}:
            raise ValueError("invalid benchmark evidence binding")
        key = text(item["evidence_id"])
        text(item["source_action"])
        if key in index or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError("duplicate or invalid evidence binding")
        index[key] = item
    return index


def _supported(row, entry, index, *, manual=False):
    if not all(row.get(k) == entry[k] for k in ("target", "rule_id", "role_id")):
        return False
    if row.get("collection_complete") is not True or row.get("limitations"):
        return False
    if manual and row.get("reviewed") is not True:
        return False
    actions, evidence = ids(row.get("source_actions", [])), ids(row.get("evidence_ids", []))
    if not actions or not evidence or any(e not in index or index[e]["source_action"] not in actions for e in evidence):
        return False
    if any(not any(index[e]["source_action"] == action for e in evidence) for action in actions):
        return False
    return (set(entry["required_evidence_fields"]).issubset(ids(row.get("evidence_fields", [])))
            and set(entry["cve_ids"]).issubset(ids(row.get("cve_ids", []))))


def score_benchmark(catalog, report):
    catalog = validate_catalog(catalog)
    if not isinstance(report, dict) or not isinstance(report.get("detections", []), list):
        raise ValueError("invalid detector report")
    index = _evidence_index(report)
    results = []
    detections = report.get("detections", [])
    manual = report.get("manual_results", [])
    if len(detections) > 100000 or not isinstance(manual, list) or len(manual) > 10000:
        raise ValueError("benchmark report exceeds allowance")
    for entry in catalog["entries"]:
        is_manual = entry["eligibility"] == "manual_only"
        rows = manual if is_manual else detections
        matching = [r for r in rows if isinstance(r, dict) and
                    all(r.get(k) == entry[k] for k in ("target", "rule_id", "role_id"))
                    and (not is_manual or r.get("issue_id") == entry["issue_id"])]
        state_key = "outcome" if is_manual else "disposition"
        valid = [r for r in matching if _supported(r, entry, index, manual=is_manual)]
        states = {r.get(state_key) for r in valid}
        wanted = "observed_condition" if entry["expectation"] == "present" else "not_observed"
        status = "manual_pending" if is_manual else "missed"
        if matching:
            status = "insufficient_evidence"
        if {"observed_condition", "not_observed"}.issubset(states):
            status = "conflicting_results"
        elif entry["expectation"] == "absent" and "observed_condition" in states:
            status = "false_positive"
        elif wanted in states:
            status = "manual_verified" if is_manual else "detected" if entry["expectation"] == "present" else "negative_control_passed"
        results.append({k: entry[k] for k in ("issue_id", "population", "eligibility", "expectation")} | {"status": status})
    passed = {"detected", "manual_verified", "negative_control_passed"}
    groups = {}
    for population in ("original_scenario", "later_advisory"):
        rows = [r for r in results if r["population"] == population]
        groups[population] = {"total": len(rows), "automated_total": sum(r["eligibility"] == "automated" for r in rows),
            "detected": sum(r["status"] == "detected" for r in rows),
            "manual_total": sum(r["eligibility"] == "manual_only" for r in rows),
            "manual_verified": sum(r["status"] == "manual_verified" for r in rows),
            "false_positives": sum(r["status"] == "false_positive" for r in rows),
            "unresolved": sum(r["status"] not in passed for r in rows)}
    # Independent ground-truth source hashes intentionally differ from fresh
    # collection hashes. Bind deployment provenance, and resolve actual evidence
    # through the operator-selected report's verified evidence index instead.
    scope_matches = report.get("scope_sha256") == catalog["scope_sha256"]
    provenance_matches = report.get("provenance_sha256") == catalog["provenance_sha256"]
    return {"schema": SCHEMA, "classification": "client_confidential", "catalog_id": catalog["catalog_id"],
            "scope_sha256": catalog["scope_sha256"], "populations": groups, "results": results,
            "scope_matches": scope_matches, "provenance_matches": provenance_matches,
            "complete": bool(results) and catalog["catalog_complete"] and scope_matches and provenance_matches and all(r["status"] in passed for r in results),
            "claim": "Covers only this independently reviewed catalog; not all unknown vulnerabilities.",
            "model_calls": 0, "target_requests": 0}


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate benchmark JSON key")
        value[key] = item
    return value


def private_json(path, expected_hash):
    path = Path(path).absolute()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("exact reviewed input hash required")
    if any(p.is_symlink() or (p / ".git").exists() for p in (path.parent, *path.parents)):
        raise ValueError("benchmark inputs must be outside Git and symlink paths")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid() or info.st_size > 16*1024*1024:
            raise ValueError("unsafe benchmark input")
        raw = bytearray()
        while block := os.read(fd, 65536):
            raw.extend(block)
            if len(raw) > 16*1024*1024:
                raise ValueError("benchmark input grew past allowance")
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("benchmark input hash mismatch")
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--catalog-sha256", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--report-sha256", required=True)
    args = parser.parse_args()
    try:
        result = score_benchmark(private_json(args.catalog, args.catalog_sha256), private_json(args.report, args.report_sha256))
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result["complete"] else 2
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({"complete": False, "error": "benchmark input rejected"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
