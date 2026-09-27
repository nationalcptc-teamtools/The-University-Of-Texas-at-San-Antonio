"""Offline collectors. They consume only trusted context.input_bytes."""
from __future__ import annotations

from collections.abc import Callable

from ..contracts import ExecutionContext, OperationResult, ParseBatch
from ..parsers import (parse_exploit_intake, parse_linux_output, parse_network_output,
                       parse_nmap_xml, parse_reporting_records, parse_web_capture,
                       parse_windows_ad_output)
from .base import Collector, batch_result, stopped


class ImportCollector:
    def __init__(self, parser: Callable[..., ParseBatch], *, scoped: bool = False):
        self._parser = parser
        self._scoped = scoped

    def collect(self, context: ExecutionContext) -> OperationResult:
        if context.stopped():
            return stopped()
        evidence = ()
        if context.input_bytes and context.capture is not None:
            classification = "synthetic" if context.source and context.source.classification == "synthetic" else "client_confidential_human_only"
            reference = context.capture("import", context.input_bytes, classification)
            evidence = (reference,) if reference is not None else ()
        try:
            if self._scoped:
                batch = self._parser(context.input_bytes, context.source or "trusted-import", context.policy.scope)
            else:
                batch = self._parser(context.input_bytes, context.source or "trusted-import")
        except (TypeError, ValueError):
            return OperationResult(status="failed", reason="offline import could not be parsed")
        return batch_result(batch, evidence)


def nmap_import() -> Collector:
    return ImportCollector(parse_nmap_xml, scoped=True)


def network_import() -> Collector:
    return ImportCollector(parse_network_output, scoped=True)


def web_import() -> Collector:
    return ImportCollector(parse_web_capture)


def linux_import() -> Collector:
    return ImportCollector(parse_linux_output, scoped=True)


def windows_import() -> Collector:
    return ImportCollector(parse_windows_ad_output, scoped=True)


def exploit_import() -> Collector:
    return ImportCollector(parse_exploit_intake)


def reporting_import() -> Collector:
    return ImportCollector(parse_reporting_records)
