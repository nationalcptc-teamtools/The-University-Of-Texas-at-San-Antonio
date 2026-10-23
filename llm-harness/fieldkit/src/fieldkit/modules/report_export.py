"""Offline Markdown reporting, run comparisons, and team result management."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from rich.console import Console

from fieldkit.core.module import Module, Option
from fieldkit.core.redaction import redact, redact_text
from fieldkit.core.results import (
    compare_reports,
    load_report,
    merge_reports,
    normalize_report,
    update_review,
)
from fieldkit.core.storage import ArtifactStore, utc_now

INPUT = Option("INPUT", list, [], "Input JSON report (repeat for multiple)", "--input")
OUTPUT = Option("OUTPUT", str, "artifacts", "Parent of unique output directory", "--output")


def _reports(settings: dict) -> list[dict]:
    if not settings["INPUT"]:
        raise ValueError("At least one --input JSON report is required")
    reports = []
    for path in settings["INPUT"]:
        report = load_report(path)
        report["source_report"] = str(Path(path).expanduser().resolve())
        reports.append(report)
    return reports


def _inline(value: Any) -> str:
    text = redact_text(str(value or "")).replace("\n", " ").replace("\r", " ")
    for character in ("\\", "`", "*", "_", "[", "]", "|", "<", ">", "#"):
        text = text.replace(character, "\\" + character)
    return text


def _json_block(value: Any) -> list[str]:
    text = json.dumps(redact(value), indent=2, ensure_ascii=False)
    # A long enough fence keeps hostile response snippets inside their code block.
    fence = "`" * max(3, max((len(part) for part in re.findall(r"`+", text)), default=0) + 1)
    return [f"{fence}json", text, fence]


def markdown_report(report: dict) -> str:
    """Produce a draft, never treating automatic observations as confirmed findings."""
    report = redact(normalize_report(report))
    lines = [
        "# Fieldkit assessment draft",
        "",
        f"Module: {_inline(report.get('module'))}",
        "",
        "Automatic observations require manual validation. Raw evidence stays in the original "
        "run directories; the index below points to those reports and artifacts.",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.extend(
            ["No findings recorded. Review collected artifacts and request results below.", ""]
        )
    for finding in report["findings"]:
        url = (
            finding.get("url")
            or finding.get("requested_url")
            or f"{finding.get('host', 'Local artifact')}: {finding.get('resource', '')}"
        )
        lines.extend(
            [
                f"### {_inline(finding.get('title', finding.get('kind', 'Observation')))}",
                "",
                f"- ID: {_inline(finding['id'])}",
                f"- Affected {'host / resource' if finding.get('host') else 'URL'}: {_inline(url)}",
                f"- Severity: {_inline(finding.get('severity', 'info'))}",
                f"- Confidence: {_inline(finding.get('confidence', 'review'))}",
            ]
        )
        if finding.get("review"):
            review = finding["review"]
            lines.append(
                f"- Review: {_inline(review.get('status'))}; "
                f"assignee: {_inline(review.get('assignee', 'unassigned'))}"
            )
        lines.extend(
            [
                "",
                "Observation and supporting details:",
                "",
                *_json_block(finding),
                "",
                "Reproduction:",
                "",
                "1. Use the affected URL or local source listed above.",
                "2. Repeat the recorded request with the documented session profile, "
                "or inspect the cited source and line.",
                "3. Validate the behavior and impact before confirming the finding.",
                "",
                f"Impact: {_inline(finding.get('impact'))}"
                if finding.get("impact")
                else "Impact: _Add manually after validation._",
                "",
                f"Recommendation: {_inline(finding.get('remediation'))}"
                if finding.get("remediation")
                else "Recommendation: _Add remediation appropriate to the application._",
                "",
            ]
        )
    lines.extend(["## Evidence index", ""])
    sources = report.get("source_reports") or (
        [report["source_report"]] if report.get("source_report") else []
    )
    if sources:
        lines.extend([f"- Source report: {_inline(source)}" for source in sources])
        lines.append("")
    lines.extend(["| ID | URL | Status | Evidence / saved artifact |", "| --- | --- | --- | --- |"])
    for item in report["results"]:
        evidence = item.get("file") or item.get("body_file") or item.get("evidence_id")
        if evidence and (item.get("file") or item.get("body_file")) and item.get("artifact_root"):
            evidence = str(Path(item["artifact_root"]) / str(evidence))
        evidence = evidence or item.get("evidence") or "See source report"
        url = (
            item.get("requested_url")
            or item.get("url")
            or item.get("final_url")
            or f"{item.get('host', '')}: {item.get('resource', item.get('source', ''))}"
        )
        lines.append(
            f"| {_inline(item['id'])} | {_inline(url)} | "
            f"{_inline(item.get('status'))} | {_inline(evidence)} |"
        )
    for evidence in report.get("evidence", []):
        evidence_path = evidence.get("file", "")
        if evidence.get("artifact_root"):
            evidence_path = str(Path(evidence["artifact_root"]) / evidence_path)
        lines.append(
            f"| {_inline(evidence.get('id'))} | {_inline(evidence.get('url'))} | "
            f" | {_inline(evidence_path)} "
            f"(source: {_inline(evidence.get('source_report', 'this report'))}) |"
        )
    lines.extend(["", "## Endpoint inventory", ""])
    for endpoint in report["endpoints"]:
        lines.append(f"- {_inline(endpoint.get('method', 'GET'))} {_inline(endpoint.get('url'))}")
    if report.get("hypotheses"):
        lines.extend(
            ["", "## Hypotheses requiring validation", "", *_json_block(report["hypotheses"])]
        )
    if report.get("errors"):
        lines.extend(["", "## Collection errors", "", *_json_block(report["errors"])])
    return "\n".join(lines) + "\n"


def _save(report: dict, settings: dict, console: Console, markdown: str | None = None) -> int:
    store = ArtifactStore(settings["OUTPUT"])
    report["finished_at"] = utc_now()
    path = store.write_report(redact(report))
    console.print(f"Report: {path}", markup=False)
    if markdown is not None:
        draft = store.root / "report.md"
        draft.write_text(markdown, encoding="utf-8")
        draft.chmod(0o600)
        console.print(f"Draft: {draft}", markup=False)
    return 0


class ReportExport(Module):
    name = "web/report-export"
    description = "Export redacted Markdown findings and an evidence index from saved reports."
    options = (INPUT, OUTPUT)

    def run(self, settings: dict[str, Any], console: Console) -> int:
        reports = _reports(settings)
        report = reports[0] if len(reports) == 1 else merge_reports(reports)
        return _save(report, settings, console, markdown_report(report))


class RunCompare(Module):
    name = "results/compare"
    description = "Compare runs with added, removed, and changed observations."
    options = (
        Option("BEFORE", str, "", "Earlier JSON report", "--before"),
        Option("AFTER", str, "", "Later JSON report", "--after"),
        OUTPUT,
    )

    def run(self, settings: dict[str, Any], console: Console) -> int:
        if not settings["BEFORE"] or not settings["AFTER"]:
            raise ValueError("Both --before and --after are required")
        comparison = compare_reports(
            load_report(settings["BEFORE"]), load_report(settings["AFTER"])
        )
        comparison["source_reports"] = [settings["BEFORE"], settings["AFTER"]]
        lines = ["# Fieldkit run comparison", ""]
        for collection in ("findings", "results", "endpoints"):
            lines.extend([f"## {collection.capitalize()}", ""])
            for category, items in comparison[collection].items():
                lines.extend([f"### {category.capitalize()} ({len(items)})", ""])
                if items:
                    lines.extend([*_json_block(items), ""])
        return _save(comparison, settings, console, "\n".join(lines) + "\n")


class TeamMerge(Module):
    name = "results/merge"
    description = "Merge team reports with deduplication and explicit review conflicts."
    options = (INPUT, OUTPUT)

    def run(self, settings: dict[str, Any], console: Console) -> int:
        return _save(merge_reports(_reports(settings)), settings, console)


class ReviewUpdate(Module):
    name = "results/review"
    description = "Assign a finding and record a review decision in a new report."
    options = (
        Option("INPUT", str, "", "Input JSON report", "--input"),
        Option("FINDING_ID", str, "", "Finding ID from the report", "--finding-id"),
        Option(
            "STATUS",
            str,
            "unreviewed",
            "unreviewed, in-progress, confirmed, dismissed, resolved",
            "--status",
        ),
        Option("ASSIGNEE", str, "", "Team member responsible for the finding", "--assignee"),
        Option("NOTE", str, "", "Review note", "--note"),
        OUTPUT,
    )

    def run(self, settings: dict[str, Any], console: Console) -> int:
        if not settings["INPUT"] or not settings["FINDING_ID"]:
            raise ValueError("Both --input and --finding-id are required")
        report = update_review(
            load_report(settings["INPUT"]),
            settings["FINDING_ID"],
            status=settings["STATUS"],
            assignee=settings["ASSIGNEE"],
            note=settings["NOTE"],
        )
        return _save(report, settings, console)
