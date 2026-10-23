"""Bounded XML with no entity expansion, DTD subsets, or resource resolution."""

import io
import xml.etree.ElementTree as ET
from collections import ChainMap
from xml.parsers import expat


def parse_xml(data: bytes, *, max_bytes=5242880, max_nodes=50000, max_depth=64):
    if len(data) > max_bytes:
        raise ValueError("XML byte limit exceeded")
    parser = expat.ParserCreate()
    depth = count = 0

    def start(_name, _attrs):
        nonlocal depth, count
        depth += 1
        count += 1
        if depth > max_depth or count > max_nodes:
            raise ValueError("XML node/depth limit exceeded")

    def end(_name):
        nonlocal depth
        depth -= 1

    def forbidden(*_args):
        raise ValueError("XML entities and external resources are forbidden")

    def doctype(_name, _system, _public, subset):
        if subset or _system or _public:
            forbidden()

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    try:
        parser.Parse(data, True)
        namespaces, stack, pending = {}, [], {}
        root = None
        for event, value in ET.iterparse(io.BytesIO(data), events=("start-ns", "start", "end")):
            if event == "start-ns":
                pending[value[0]] = value[1]
            elif event == "start":
                # Namespace declarations apply to a subtree. Keep inherited
                # mappings shared, rather than copying a large root mapping for
                # every node (which can multiply a small document into GBs).
                parent = stack[-1] if stack else {}
                mapping = ChainMap(dict(pending), parent) if pending else parent
                pending.clear()
                namespaces[id(value)] = mapping
                stack.append(mapping)
                if root is None:
                    root = value
            else:
                stack.pop()
        return root, namespaces
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError("Malformed XML document") from exc
