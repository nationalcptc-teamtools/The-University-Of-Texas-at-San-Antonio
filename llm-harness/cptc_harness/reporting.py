"""Deterministic human reports. Imported claims do not prove a finding."""
from __future__ import annotations
import hashlib
import html
import json
import re
from .contracts import PolicyError, canonical_json


def summarize_result(result: dict) -> dict:
    """Processing completion and collection completeness are different facts."""
    facts = result.get("facts", {})
    issues = sorted(set(facts.get("issues", [])))
    count = len(facts.get("observations", []))
    status = result.get("status", "complete")
    state = status if status != "complete" else ("incomplete" if issues else "complete" if count else "no_observations")
    return {"collection_state": state, "issues": issues, "observation_count": count}


def evidence_index(records: list[dict]) -> list[dict]:
    """Link permitted captured evidence to its originating audited action.

    Runtime verifies the result receipts and audit artifacts before calling us.
    Legacy references lacking a checksum remain in the legacy observations but
    cannot substantiate a new detector or benchmark conclusion.
    """
    found = {}
    for record in records:
        action = record["request"]["request_id"]
        for item in record["result"].get("evidence", []):
            ident, sha = item.get("evidence_id"), item.get("sha256")
            if not isinstance(ident, str) or not ident or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                continue
            row = {"evidence_id": ident, "sha256": sha, "source_action": action}
            if ident in found and found[ident] != row:
                raise PolicyError("conflicting captured evidence identity")
            found[ident] = row
    return [found[key] for key in sorted(found)]


def report_records(records: list[dict], *, expected_checks=()) -> dict:
    from .detection import classify_records
    classified = classify_records(records, expected_checks=expected_checks)
    evidence = {item["evidence_id"]: item for record in records for item in record["result"].get("evidence", [])}
    items = {}
    for record in records:
        request, result = record["request"], record["result"]
        for observation in result.get("facts", {}).get("observations", []):
            facts = observation.get("facts", {})
            state = observation.get("state", "observed")
            reference = facts.get("evidence_ref")
            confirmed = (state == "confirmed" and request["source"] == "operator"
                         and facts.get("reviewed") is True and reference in evidence)
            shown_state = "confirmed_by_human" if confirmed else ("unverified_human_claim" if state == "confirmed" else state)
            key = hashlib.sha256(canonical_json({k: observation.get(k) for k in ("target", "track", "check_id", "state", "facts")})).hexdigest()[:24]
            if key not in items:
                items[key] = {"id": key, "target": observation.get("target"), "track": observation.get("track"),
                              "check": observation.get("check_id"), "state": shown_state, "facts": facts,
                              "owner": request["operator_id"], "contributors": [], "source_actions": [], "source_hashes": [],
                              "evidence_id": reference if reference in evidence else None}
            entry = items[key]
            entry["contributors"].append(request["operator_id"])
            entry["source_actions"].append(request["request_id"])
            if observation.get("source_sha256"):
                entry["source_hashes"].append(observation["source_sha256"])
    for value in items.values():
        value["contributors"] = sorted(set(value["contributors"]))
        value["source_actions"] = sorted(set(value["source_actions"]))
        value["source_hashes"] = sorted(set(value["source_hashes"]))
    return {"classification": "client_confidential", "version": 1,
            "confirmation_policy": "Human-reviewed claim with a referenced, integrity-checked local artifact; scanner matches remain candidates.",
            "operations": [{"action_id": record["request"]["request_id"],
                            "module_id": record["request"].get("module_id", "legacy_unknown"),
                            "status": record["result"].get("status", "complete"),
                            "reason": record["result"].get("reason"),
                            **summarize_result(record["result"])} for record in records],
            "observations": sorted(items.values(), key=lambda item: (str(item["target"]), str(item["track"]), str(item["check"]), item["id"])),
            "detector_catalog_version": classified["catalog_version"],
            "detections": classified["detections"], "check_coverage": classified["coverage"],
            "evidence_index": evidence_index(records), "model_calls": 0,
            "benchmark_status": "not_evaluated_external_catalog_required"}


def markdown_report(report: dict) -> str:
    def escape(value):
        raw = str(value)
        raw = "".join(c if ord(c) >= 32 and ord(c) != 127 else " " for c in raw)
        return html.escape(raw).replace("|", "\\|").replace("`", "'").replace("[", "\\[").replace("]", "\\]")
    lines = ["# CPTC engagement observations", "", "Classification: client-confidential. Human review required before use or disclosure.", "",
             "| Target | Track | Check | Outcome | Owner | Evidence |", "|---|---|---|---|---|---|"]
    for item in report["observations"]:
        lines.append("| " + " | ".join(escape(item.get(k) or "unlinked") for k in ("target", "track", "check", "state", "owner", "evidence_id")) + " |")
    lines.extend(["", "## Operation and collection outcomes", "",
                  "A completed import can contain incomplete collection. Failed and blocked attempts remain visible.", "",
                  "| Action | Module | Operation | Collection | Observations | Issues / reason |",
                  "|---|---|---|---|---|---|"])
    for item in report.get("operations", []):
        detail = ", ".join(item["issues"]) or item.get("reason") or "none reported"
        lines.append("| " + " | ".join(escape(value) for value in
                     (item["action_id"], item["module_id"], item["status"], item["collection_state"], item["observation_count"], detail)) + " |")
    lines.extend(["", "## Deterministic check results", "",
                  "Version matches are candidates. Related CVEs, CWEs and ATT&CK techniques do not prove exploitation.", "",
                  "| Target | Component | Check | Role | Outcome | References | Limitations |",
                  "|---|---|---|---|---|---|---|"])
    for item in report.get("detections", []):
        refs = item["cve_ids"] + item["cwe_ids"] + item["attack_techniques"]
        lines.append("| " + " | ".join(escape(value) for value in (
            item["target"], item.get("component_id", "unspecified"), item["rule_id"], item["role_id"],
            item["disposition"], ", ".join(refs) or "none", ", ".join(item["limitations"]) or "none reported")) + " |")
    lines.extend(["", "Full typed facts, source hashes, deduplication and retest fields are in observations.json.",
                  "Unsupported or untested modules remain visible in coverage.json. Raw evidence remains encrypted in local audit storage.", ""])
    return "\n".join(lines)
