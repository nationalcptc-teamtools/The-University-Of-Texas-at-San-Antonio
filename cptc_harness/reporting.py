"""Deterministic human reports. Imported claims do not prove a finding."""
from __future__ import annotations
import hashlib
import html
import json
from .contracts import PolicyError, canonical_json


def summarize_result(result: dict) -> dict:
    """Processing completion and collection completeness are different facts."""
    facts = result.get("facts", {})
    issues = sorted(set(facts.get("issues", [])))
    count = len(facts.get("observations", []))
    status = result.get("status", "complete")
    state = status if status != "complete" else ("incomplete" if issues else "complete" if count else "no_observations")
    return {"collection_state": state, "issues": issues, "observation_count": count}


def report_records(records: list[dict]) -> dict:
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
            "observations": sorted(items.values(), key=lambda item: (str(item["target"]), str(item["track"]), str(item["check"]), item["id"]))}


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
    lines.extend(["", "Full typed facts, source hashes, deduplication and retest fields are in observations.json.",
                  "Unsupported or untested modules remain visible in coverage.json. Raw evidence remains encrypted in local audit storage.", ""])
    return "\n".join(lines)
