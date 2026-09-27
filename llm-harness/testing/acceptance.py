"""Fail-closed test accounting, separate from vulnerability/live coverage."""
from collections import Counter
import math


def _valid_event(event):
    if not isinstance(event, dict) or not isinstance(event.get("kind"), str):
        return False
    kind = event["kind"]
    if kind == "collection":
        nodes = event.get("nodeids")
        return (set(event) == {"kind", "nodeids"} and isinstance(nodes, list) and 0 < len(nodes) <= 100000
                and all(isinstance(node, str) and 0 < len(node) <= 4096 for node in nodes))
    if kind == "session_finished":
        return (set(event) == {"kind", "exit_code"} and type(event.get("exit_code")) is int
                and 0 <= event["exit_code"] <= 6)
    if kind == "collection_problem":
        return (set(event) == {"kind", "nodeid", "outcome", "reason"}
                and isinstance(event.get("nodeid"), str) and 0 < len(event["nodeid"]) <= 4096
                and event.get("outcome") in {"failed", "skipped"}
                and isinstance(event.get("reason"), str) and len(event["reason"]) <= 8 * 1024 * 1024)
    if kind == "case":
        expected = {"kind", "nodeid", "phase", "outcome", "duration", "xfail", "subtest",
                    "reason", "rendered_sections"}
        duration = event.get("duration")
        sections = event.get("rendered_sections")
        return (set(event) == expected
                and isinstance(event.get("nodeid"), str) and 0 < len(event["nodeid"]) <= 4096
                and event.get("phase") in {"setup", "call", "teardown"}
                and event.get("outcome") in {"passed", "failed", "skipped"}
                and type(duration) in {int, float} and math.isfinite(duration) and 0 <= duration <= 7200
                and type(event.get("xfail")) is bool and type(event.get("subtest")) is bool
                and isinstance(event.get("reason"), str) and len(event["reason"]) <= 8 * 1024 * 1024
                and isinstance(sections, list) and len(sections) <= 64
                and all(isinstance(section, (list, tuple)) and len(section) == 2
                        and all(isinstance(value, str) for value in section) for section in sections))
    return False


def evaluate(events, process_exit):
    if (type(process_exit) is not int or not 0 <= process_exit <= 255 or not isinstance(events, list)
            or not events or any(not _valid_event(event) for event in events)):
        return {"software_passed": False, "reason": "malformed_test_receipt", "tests": []}
    collections = [e for e in events if e.get("kind") == "collection"]
    finishes = [e for e in events if e.get("kind") == "session_finished"]
    problems = [e for e in events if e.get("kind") == "collection_problem"]
    if len(collections) != 1 or len(finishes) != 1:
        return {"software_passed": False, "reason": "collection_or_completion_receipt_missing", "tests": []}
    nodes = collections[0].get("nodeids", [])
    if not nodes or len(nodes) != len(set(nodes)):
        return {"software_passed": False, "reason": "empty_or_duplicate_collection", "tests": []}
    reports = {node: [] for node in nodes}; unexpected = []
    for event in events:
        if event.get("kind") != "case": continue
        if event.get("nodeid") not in reports: unexpected.append(event.get("nodeid")); continue
        reports[event["nodeid"]].append(event)
    rows = []
    for node, phases in reports.items():
        normal = [p for p in phases if not p.get("subtest")]
        counts = Counter(p.get("phase") for p in normal)
        if any(p.get("outcome") == "failed" for p in phases): state = "failed"
        elif any(p.get("xfail") or p.get("outcome") == "skipped" for p in phases): state = "skipped_or_xfailed"
        elif counts != {"setup": 1, "call": 1, "teardown": 1}: state = "incomplete"
        elif any(p.get("outcome") != "passed" for p in phases): state = "invalid"
        else: state = "passed"
        rows.append({"nodeid": node, "state": state, "duration_s": sum(p.get("duration", 0) for p in normal),
                     "subtests": sum(bool(p.get("subtest")) for p in phases)})
    totals = dict(Counter(row["state"] for row in rows))
    passed = (process_exit == 0 and finishes[0].get("exit_code") == 0 and not problems and not unexpected
              and all(row["state"] == "passed" for row in rows))
    return {"software_passed": passed, "totals": totals, "tests": rows,
            "collection_problems": len(problems), "unexpected_reports": len(unexpected),
            "subtests": sum(row["subtests"] for row in rows)}
