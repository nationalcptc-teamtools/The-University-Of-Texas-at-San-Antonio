"""Offline network and Nmap import parsers."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..contracts import Observation, ParseBatch, ScopeSpec, SourceRef
from .common import (bounded_int, bounded_string, finish, in_scope, issue,
                     json_records, load_json, start, text)


def parse_nmap_xml(raw: bytes | str, source: SourceRef | str, scope: ScopeSpec) -> ParseBatch:
    payload, source_ref_value, issues = start(raw, source)
    if any(item.code == "oversized_input" for item in issues):
        return ParseBatch(issues=tuple(issues))
    try:
        root = ET.fromstring(payload)
    except (ET.ParseError, ValueError):
        return ParseBatch(issues=tuple(issues + [issue("malformed_xml")]))
    observations: list[Observation] = []
    for record_no, host in enumerate(root.findall(".//host"), 1):
        addresses = [a.get("addr") for a in host.findall("./address") if a.get("addr")]
        names = [n.get("name") for n in host.findall("./hostnames/hostname") if n.get("name")]
        target = next((a for a in addresses if in_scope(a, scope)), None)
        if target is None:
            target = next((n for n in names if in_scope(n, scope)), None)
        if target is None:
            issues.append(issue("out_of_scope", record_no))
            continue
        ports: list[dict[str, object]] = []
        for port in host.findall("./ports/port"):
            try:
                number = bounded_int(int(port.get("portid", "")), 1, 65535)
            except (TypeError, ValueError):
                number = None
            state_node = port.find("./state")
            state = state_node.get("state") if state_node is not None else None
            if number is None or state not in {"open", "closed", "filtered", "open|filtered"}:
                continue
            service = port.find("./service")
            item: dict[str, object] = {"port": number, "state": state}
            if service is not None:
                for key in ("name", "product", "version", "tunnel"):
                    value = bounded_string(service.get(key))
                    if value is not None:
                        item[key] = value
            ports.append(item)
        facts: dict[str, object] = {"addresses": tuple(a for a in addresses[:8] if isinstance(a, str) and in_scope(a, scope)),
                                    "ports": tuple(ports[:128])}
        scoped_names = tuple(n for n in names[:8] if isinstance(n, str) and in_scope(n, scope))
        if scoped_names:
            facts["hostnames"] = scoped_names
        observations.append(Observation("network", target, "network_inventory", "observed", facts, source_ref_value))
    return finish(observations, issues)


def parse_network_output(raw: bytes | str, source: SourceRef | str, scope: ScopeSpec) -> ParseBatch:
    payload, source_ref_value, issues = start(raw, source)
    observations: list[Observation] = []
    try:
        records = json_records(load_json(payload))
    except (ValueError, TypeError):
        records = []
        for number, line in enumerate(text(payload).splitlines()[:2048], 1):
            fields = [part.strip() for part in line.split("|", 4)]
            if len(fields) == 5:
                records.append({"target": fields[0], "port": fields[1], "protocol": fields[2],
                                "service": fields[3], "state": fields[4]})
            elif line.strip():
                issues.append(issue("malformed_record", number))
    if not records and payload.strip() and not issues:
        issues.append(issue("malformed_record"))
    for number, record in enumerate(records, 1):
        target = bounded_string(record.get("target"))
        if target is None or not in_scope(target, scope):
            issues.append(issue("out_of_scope", number))
            continue
        port = bounded_int(record.get("port"), 1, 65535)
        state = bounded_string(record.get("state"), maximum=32)
        if port is None or state not in {"open", "closed", "filtered", "unknown"}:
            issues.append(issue("invalid_record", number))
            continue
        facts: dict[str, object] = {"port": port, "state": state}
        for key in ("protocol", "service", "product", "version"):
            value = bounded_string(record.get(key), maximum=64)
            if value is not None:
                facts[key] = value
        observations.append(Observation("network", target, "service_inventory", "observed", facts, source_ref_value))
    return finish(observations, issues)
