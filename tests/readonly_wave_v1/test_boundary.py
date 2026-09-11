import ast
from dataclasses import fields
import inspect
from pathlib import Path

import pytest

from cptc11_readonly_wave_v1 import catalog
from cptc11_readonly_wave_v1.contracts import ActionResult


ROOT = Path(__file__).parents[2]
PACKAGE = ROOT / "cptc11_readonly_wave_v1"


def test_production_has_no_openers_forbidden_imports_or_sibling_dependency():
    forbidden = {"socket", "ssl", "subprocess", "urllib", "requests", "httpx", "nmap", "cptc_harness"}
    for path in PACKAGE.rglob("*.py"):
        source = path.read_text()
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".", 1)[0])
        assert imports.isdisjoint(forbidden), (path, imports & forbidden)
        assert "cptc11_benchmark" not in source
    assert tuple(inspect.signature(catalog.resolve_action).parameters) == (
        "plan_id", "action_id", "profile_id"
    )


def test_action_results_and_facts_have_no_raw_or_runtime_control_fields():
    names = {field.name for field in fields(ActionResult)}
    forbidden = {
        "raw", "body", "headers", "path", "host", "port", "url", "ciphertext",
        "artifact_path", "credential", "proxy", "redirect", "retry", "environment",
        "executable", "filesystem",
    }
    assert names.isdisjoint(forbidden)
    action_names = {field.name for field in fields(catalog.plan_actions("cptc11-readonly-wave-v1")[0])}
    assert not {"proxy", "redirect", "retry", "environment", "executable", "filesystem"} & action_names


def test_all_json_parsers_bound_size_depth_duplicates_bom_and_nonfinite():
    from cptc11_readonly_wave_v1.parsers import ParserError, parse_keycloak, parse_traefik

    excessive_depth = (b'{"x":' * 17) + b"0" + (b"}" * 17)
    invalid_bodies = (
        b"\xef\xbb\xbf{}",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        excessive_depth,
        b"{" + (b" " * 16384) + b"}",
    )
    for body in invalid_bodies:
        with pytest.raises(ParserError):
            parse_keycloak(200, body)

    with pytest.raises(ParserError):
        parse_traefik(200, b"{" + (b" " * 4096) + b"}")
