"""Namespace-aware WSDL 1.1/SOAP inventory and unexecuted replay templates."""

import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule, write_private
from fieldkit.core.module import Option
from fieldkit.core.results import stable_id
from fieldkit.core.urls import normalize_url
from fieldkit.core.xml import parse_xml
from fieldkit.modules.nmap_import import read_bounded

WSDL = "http://schemas.xmlsoap.org/wsdl/"
XSD = "http://www.w3.org/2001/XMLSchema"
SOAP = {
    "http://schemas.xmlsoap.org/wsdl/soap/": ("1.1", "http://schemas.xmlsoap.org/soap/envelope/"),
    "http://schemas.xmlsoap.org/wsdl/soap12/": ("1.2", "http://www.w3.org/2003/05/soap-envelope"),
}


def qname(value, node, mappings, fallback=""):
    prefix, separator, local = (value or "").partition(":")
    if separator:
        uri = mappings[id(node)].get(prefix)
        if uri is None:
            raise ValueError("Unresolved QName prefix")
        return uri, local
    return mappings[id(node)].get("", fallback), prefix


def expanded(name):
    return f"{{{name[0]}}}{name[1]}" if name[0] else name[1]


def inventory_documents(documents, max_operations=1000):
    indices = {
        k: {} for k in ("message", "portType", "binding", "element", "complexType", "simpleType")
    }
    warnings, services, forms = [], [], {}
    parameter_count = 0
    for root, mappings, source in documents:
        if root.tag not in {f"{{{WSDL}}}definitions", f"{{{XSD}}}schema"}:
            warnings.append(f"Unsupported document namespace/version: {source}")
            continue
        ns = root.get("targetNamespace", "")
        for kind in ("message", "portType", "binding"):
            for node in root.findall(f"{{{WSDL}}}{kind}"):
                indices[kind][ns, node.get("name")] = node, mappings, source
        services.extend((s, mappings, source) for s in root.findall(f"{{{WSDL}}}service"))
        schemas = [root] if root.tag == f"{{{XSD}}}schema" else list(root.iter(f"{{{XSD}}}schema"))
        for schema in schemas:
            schema_ns = schema.get("targetNamespace", "")
            forms.update(
                (id(node), schema.get("elementFormDefault", "unqualified"))
                for node in schema.iter()
            )
            for kind in ("element", "complexType", "simpleType"):
                for node in schema.findall(f"{{{XSD}}}{kind}"):
                    indices[kind][schema_ns, node.get("name")] = node, mappings, source

    def parameters(element, mappings, namespace, visited=()):
        nonlocal parameter_count
        if len(visited) >= 8:
            warnings.append("Schema nesting limit; request shape requires manual completion")
            return []
        ref = element.get("ref")
        if ref:
            key = qname(ref, element, mappings, namespace)
            target = indices["element"].get(key)
            if not target or key in visited:
                warnings.append("Unresolved/cyclic schema element reference")
                return []
            return parameters(target[0], target[1], key[0], (*visited, key))
        container = element.find(f"{{{XSD}}}complexType")
        type_value = element.get("type")
        if container is None and type_value:
            key = qname(type_value, element, mappings, namespace)
            target = indices["complexType"].get(key)
            if target and key not in visited:
                container, mappings, _ = target
                visited = (*visited, key)
        if container is None:
            return []
        output = []
        # Descendant iteration would duplicate nested element shapes and can grow exponentially.
        particles = [container]
        children = []
        while particles:
            particle = particles.pop()
            for node in particle:
                if node.tag == f"{{{XSD}}}element":
                    children.append(node)
                elif node.tag in {f"{{{XSD}}}sequence", f"{{{XSD}}}choice", f"{{{XSD}}}all"}:
                    particles.append(node)
                elif node.tag in {f"{{{XSD}}}complexContent", f"{{{XSD}}}extension"}:
                    warnings.append("Schema type extension needs manual completion")
        for child in children:
            parameter_count += 1
            if len(output) >= 100 or parameter_count > max_operations * 100:
                warnings.append("Schema parameter ceiling reached")
                break
            name = child.get("name")
            uri = namespace if child.get("form", forms.get(id(child))) == "qualified" else ""
            if child.get("ref"):
                uri, name = qname(child.get("ref"), child, mappings, namespace)
            if not name:
                continue
            output.append(
                {
                    "name": name,
                    "namespace": uri,
                    "type": child.get("type", "unknown"),
                    "min_occurs": child.get("minOccurs", "1"),
                    "max_occurs": child.get("maxOccurs", "1"),
                    "children": parameters(child, mappings, uri, visited),
                }
            )
        return output

    operations, templates = [], []
    for service, mapping, source in services:
        for port in service.findall(f"{{{WSDL}}}port"):
            address = next(
                (n for n in port if n.tag.endswith("}address") and n.tag.split("}")[0][1:] in SOAP),
                None,
            )
            if address is None:
                warnings.append("Port has no SOAP address")
                continue
            soap_ns = address.tag.split("}")[0][1:]
            version, envelope = SOAP[soap_ns]
            try:
                url = normalize_url(urljoin(source, address.get("location", "")))
            except (ValueError, TypeError):
                warnings.append("SOAP address is missing or is not HTTP(S)")
                continue
            binding_key = qname(port.get("binding"), port, mapping)
            binding_entry = indices["binding"].get(binding_key)
            if not binding_entry:
                warnings.append("Unresolved SOAP binding; supply/fetch its import")
                continue
            binding, bmap, binding_source = binding_entry
            port_key = qname(binding.get("type"), binding, bmap)
            port_entry = indices["portType"].get(port_key)
            if not port_entry:
                warnings.append("Unresolved portType")
                continue
            port_type, pmap, _ = port_entry
            abstract = {n.get("name"): n for n in port_type.findall(f"{{{WSDL}}}operation")}
            style_node = binding.find(f"{{{soap_ns}}}binding")
            binding_style = (
                style_node.get("style", "document") if style_node is not None else "document"
            )
            for operation in binding.findall(f"{{{WSDL}}}operation"):
                if len(operations) >= max_operations:
                    warnings.append("Operation ceiling reached")
                    return operations, templates, warnings
                action_node = operation.find(f"{{{soap_ns}}}operation")
                name = operation.get("name", "")
                action = action_node.get("soapAction", "") if action_node is not None else ""
                style = (
                    action_node.get("style", binding_style)
                    if action_node is not None
                    else binding_style
                )
                body_node = operation.find(f"{{{WSDL}}}input/{{{soap_ns}}}body")
                abstract_input = abstract.get(name)
                abstract_input = (
                    abstract_input.find(f"{{{WSDL}}}input") if abstract_input is not None else None
                )
                message = None
                if abstract_input is not None:
                    message = indices["message"].get(
                        qname(abstract_input.get("message"), abstract_input, pmap)
                    )
                record = {
                    "kind": "soap_operation",
                    "url": url,
                    "method": "POST",
                    "operation": name,
                    "service": service.get("name"),
                    "port": port.get("name"),
                    "binding": expanded(binding_key),
                    "soap_version": version,
                    "soap_action": action,
                    "style": style,
                    "source": source,
                    "binding_source": binding_source,
                    "parameters": [],
                    "executed": False,
                }
                operations.append(record)
                if not message:
                    warnings.append("Input message unresolved; no request template generated")
                    continue
                msg, mmap, _ = message
                selected_parts = body_node.get("parts", "").split() if body_node is not None else []
                parts = [
                    p
                    for p in msg.findall(f"{{{WSDL}}}part")
                    if not selected_parts or p.get("name") in selected_parts
                ]
                env = ET.Element(f"{{{envelope}}}Envelope")
                body = ET.SubElement(env, f"{{{envelope}}}Body")
                rpc_uri = (
                    body_node.get("namespace", binding_key[0])
                    if body_node is not None
                    else binding_key[0]
                )
                wrapper = ET.SubElement(body, expanded((rpc_uri, name))) if style == "rpc" else body

                def add_params(parent, params):
                    for parameter in params:
                        node = ET.SubElement(
                            parent, expanded((parameter["namespace"], parameter["name"]))
                        )
                        if parameter["children"]:
                            add_params(node, parameter["children"])
                        else:
                            node.text = "<VALUE>"

                for part in parts:
                    key = qname(part.get("element") or part.get("type"), part, mmap, binding_key[0])
                    if part.get("element"):
                        element = indices["element"].get(key)
                        params = parameters(element[0], element[1], key[0]) if element else []
                        node = ET.SubElement(wrapper, expanded(key))
                        add_params(node, params)
                        if not params:
                            node.text = "<VALUE>"
                    else:
                        params = [
                            {
                                "name": part.get("name", "value"),
                                "namespace": "",
                                "type": expanded(key),
                                "children": [],
                            }
                        ]
                        add_params(wrapper, params)
                    record["parameters"].append(
                        {
                            "part": part.get("name"),
                            "element_or_type": expanded(key),
                            "fields": params,
                        }
                    )
                headers = (
                    {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": action}
                    if version == "1.1"
                    else {"Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"'}
                )
                template = {
                    "id": f"soap-{len(templates) + 1}",
                    "method": "POST",
                    "url": url,
                    "headers": headers,
                    "xml": ET.tostring(env, encoding="unicode"),
                    "source": source,
                    "operation": name,
                    "executed": False,
                }
                templates.append(template)
    return operations, templates, warnings


class SOAPInventory(NetworkModule):
    name = "web/soap-inventory"
    description = "Parse WSDL/SOAP namespaces, addresses and unexecuted request templates."
    requires_targets = False
    options = COMMON_OPTIONS + (
        Option("WSDL_FILES", list, [], "Explicit local WSDL/XSD file (repeat)", "--wsdl-file"),
        Option(
            "FETCH_IMPORTS",
            bool,
            False,
            "Fetch HTTP imports only within explicit target scope",
            "--fetch-imports",
        ),
        Option("MAX_DOCUMENTS", int, 10, "Document/reference count ceiling", "--max-documents"),
        Option("MAX_OPERATIONS", int, 500, "Operation ceiling", "--max-operations"),
    )

    def validate(self, settings):
        if min(settings["MAX_DOCUMENTS"], settings["MAX_OPERATIONS"]) <= 0:
            raise ValueError("Document/operation limits must be positive")
        if not settings["WSDL_FILES"] and not (settings["TARGETS"] or settings["TARGETS_FILE"]):
            raise ValueError("Supply local --wsdl-file or explicit HTTP target scope")

    async def _execute(self, ctx):
        async with ctx:
            if ctx.candidates:
                await ctx.prepare()
            await self.assess(ctx)

    async def assess(self, ctx):
        queue = [(str(Path(p).expanduser().resolve()), True) for p in ctx.settings["WSDL_FILES"]]
        queue.extend((u, False) for u in ctx.seed_urls())
        documents, seen, warnings = [], set(), []
        while queue and len(seen) < ctx.settings["MAX_DOCUMENTS"]:
            if time.monotonic() >= ctx.deadline:
                raise TimeoutError("Run time budget exhausted")
            source, local = queue.pop(0)
            if source in seen:
                continue
            seen.add(source)
            evidence = None
            if local:
                try:
                    data = read_bounded(source, ctx.settings["MAX_BYTES"])
                except (OSError, ValueError) as exc:
                    ctx.report["errors"].append(
                        {"error": "wsdl_read_error", "source": source, "detail": str(exc)}
                    )
                    continue
                source_url = Path(source).as_uri()
            else:
                response = await ctx.fetch(source)
                if response.error or response.status is None or not 200 <= response.status < 300:
                    ctx.report["errors"].append(
                        {
                            "error": "wsdl_fetch_error",
                            "source": source,
                            "status": response.status,
                            "detail": response.error or "Expected a successful WSDL response",
                        }
                    )
                    continue
                data, source_url, evidence = response.body, response.url, response.evidence_id
            try:
                root, namespaces = parse_xml(data, max_bytes=ctx.settings["MAX_BYTES"])
            except ValueError as exc:
                ctx.report["errors"].append(
                    {"error": "invalid_wsdl_xml", "source": source, "detail": str(exc)}
                )
                continue
            documents.append((root, namespaces, source_url))
            ctx.report["results"].append(
                {
                    "kind": "soap_document",
                    "source": source,
                    "evidence": [evidence] if evidence else [],
                    "namespace": root.tag,
                    "bytes": len(data),
                }
            )
            for node in root.iter():
                if node.tag not in {f"{{{WSDL}}}import", f"{{{XSD}}}import", f"{{{XSD}}}include"}:
                    continue
                reference = node.get("location") or node.get("schemaLocation")
                if not reference:
                    continue
                resolved = ctx.resolve(reference, source_url)
                if ctx.settings["FETCH_IMPORTS"] and resolved:
                    queue.append((resolved, False))
                else:
                    warnings.append(
                        "Reference not fetched (disabled, local, or outside explicit scope): "
                        + reference
                    )
        if any(source not in seen for source, _local in queue):
            warnings.append("Document ceiling reached; remaining references not fetched")
            ctx.report["errors"].append({"error": "wsdl_document_limit"})
        try:
            operations, templates, parse_warnings = inventory_documents(
                documents, ctx.settings["MAX_OPERATIONS"]
            )
        except ValueError as exc:
            ctx.report["errors"].append({"error": "invalid_wsdl_schema", "detail": str(exc)})
            operations, templates, parse_warnings = [], [], ["Unresolved QName/schema"]
        if "Operation ceiling reached" in parse_warnings:
            ctx.report["errors"].append({"error": "soap_operation_limit"})
        for record in operations:
            ctx.report["results"].append(record)
            endpoint = {
                "url": record["url"],
                "method": "POST",
                "source": record["source"],
                "authorized": False,
            }
            endpoint["id"] = stable_id(endpoint, "endpoint")
            if not any(e["id"] == endpoint["id"] for e in ctx.report["endpoints"]):
                ctx.report["endpoints"].append(endpoint)
        write_private(ctx.store.root / "request-templates.json", json.dumps(templates, indent=2))
        ctx.report["soap_summary"] = {
            "operations": len(operations),
            "templates": len(templates),
            "warnings": list(dict.fromkeys([*warnings, *parse_warnings])),
            "limitations": "WSDL 1.1; complex/encoded schemas and SOAP headers require "
            "manual request completion. No operations executed.",
        }
        ctx.report["partial"] = bool(ctx.report["errors"])
