"""Discovery tests use mock HTTP only, including hostile and malformed input."""

import io
import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from rich.console import Console

from fieldkit.core import assessment
from fieldkit.modules.api_inventory import APIInventory, local_object, parse_document
from fieldkit.modules.content_discovery import ContentDiscovery
from fieldkit.modules.discovery_helpers import parse_page, sitemap_references
from fieldkit.modules.parameter_map import ParameterMap
from fieldkit.modules.site_map import SiteMap


@pytest.fixture
def run_module(monkeypatch, tmp_path):
    original_client = httpx.AsyncClient
    runs = 0

    def run(module, handler, **settings):
        nonlocal runs
        runs += 1
        requests = []

        def route(request):
            requests.append((request.method, str(request.url)))
            return handler(request)

        def client(**kwargs):
            return original_client(**kwargs, transport=httpx.MockTransport(route))

        monkeypatch.setattr(assessment.httpx, "AsyncClient", client)
        values = module.defaults()
        values.update(
            TARGETS=["https://example.test"], OUTPUT=str(tmp_path / str(runs)), RATE=0, RETRIES=0
        )
        values.update(settings)
        code = module.run(values, Console(file=io.StringIO()))
        report_path = next(Path(values["OUTPUT"]).glob("*/report.json"))
        return code, json.loads(report_path.read_text()), requests, report_path.parent

    return run


def test_site_map_crawls_robots_sitemap_and_forms_without_leaving_scope(run_module):
    pages = {
        "/": (
            "text/html",
            '<title>Portal</title><a href="/next?a=1">Next</a>'
            '<a href="https://outside.test/x">No</a><a href="/logout">No</a>'
            '<form action="/update" method="post">'
            '<input name="password" type="password" value="DO-NOT-COPY"></form>',
        ),
        "/robots.txt": (
            "text/plain",
            "User-agent: *\nDisallow: /admin\nDisallow: /*?token=*\nSitemap: /nested.xml",
        ),
        "/sitemap.xml": (
            "application/xml",
            "<sitemapindex><sitemap><loc>https://example.test/child.xml</loc></sitemap></sitemapindex>",
        ),
        "/child.xml": (
            "application/xml",
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.test/from-map</loc></url></urlset>',
        ),
        "/nested.xml": (
            "application/xml",
            "<urlset><url><loc>https://outside.test/forbidden</loc></url></urlset>",
        ),
    }

    def handler(request):
        if request.url.path == "/admin":
            return httpx.Response(403)
        content_type, body = pages.get(request.url.path, ("text/plain", "ok"))
        return httpx.Response(200, headers={"content-type": content_type}, text=body)

    code, report, requests, _ = run_module(SiteMap(), handler)
    assert code == 0
    urls = [url for _, url in requests]
    assert "https://example.test/from-map" in urls
    assert "https://example.test/admin" in urls
    assert not any("outside.test" in url or "logout" in url or "update" in url for url in urls)
    form = next(e for e in report["endpoints"] if e["url"].endswith("/update"))
    assert form["method"] == "POST"
    assert form["parameters"][0]["name"] == "password"
    assert "DO-NOT-COPY" not in json.dumps(form)
    assert any(f["kind"] == "authentication-boundary" for f in report["findings"])


def test_site_map_honors_global_page_and_depth_bounds(run_module):
    def handler(request):
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text='<a href="/child">one</a><a href="/second">two</a>',
        )

    _, report, requests, _ = run_module(SiteMap(), handler, MAX_PAGES=2, MAX_DEPTH=0)
    assert len(requests) == 2
    assert report["results"][-1]["limited"]
    assert not any(url.endswith("/child") for _, url in requests)


def test_sitemap_dtd_is_rejected_and_forms_omit_values():
    with pytest.raises(ValueError, match="DTD"):
        sitemap_references(b'<!DOCTYPE foo [<!ENTITY x "secret">]><urlset>&x;</urlset>')
    page = parse_page(b'<form><input name="q" value="secret"><input disabled name="skip"></form>')
    assert page.forms[0]["parameters"] == [{"name": "q", "in": "form", "type": "input"}]


def test_content_discovery_filters_reflected_wildcards_but_keeps_real_and_denied(run_module):
    def handler(request):
        path = request.url.path
        if path == "/real.bak":
            return httpx.Response(
                200, headers={"content-type": "text/plain"}, text="configuration backup"
            )
        if path == "/admin":
            return httpx.Response(403, text="Access denied")
        return httpx.Response(200, headers={"content-type": "text/plain"}, text=f"Missing {path}")

    _, report, requests, _ = run_module(
        ContentDiscovery(),
        handler,
        WORDS=["real", "admin", "nope"],
        EXTENSIONS=["bak"],
        MAX_CANDIDATES=6,
    )
    results = {r["url"]: r for r in report["results"] if r["kind"] == "content"}
    assert results["https://example.test/real.bak"]["verdict"] == "interesting"
    assert results["https://example.test/admin"]["verdict"] == "interesting"
    assert results["https://example.test/nope"]["verdict"] == "wildcard"
    assert all(method == "GET" for method, _ in requests)


def test_content_discovery_does_not_collapse_distinct_redirects(run_module):
    def handler(request):
        target = "/admin-login" if request.url.path == "/admin" else "/login"
        return httpx.Response(302, headers={"location": target})

    _, report, _, _ = run_module(ContentDiscovery(), handler, WORDS=["admin"], MAX_CANDIDATES=1)
    assert report["results"][0]["verdict"] == "interesting"


def test_content_wordlist_validation_precedes_network(tmp_path):
    module = ContentDiscovery()
    settings = module.defaults()
    settings.update(WORDS=["//outside.test/path"])
    with pytest.raises(ValueError):
        module.validate(settings)
    settings.update(WORDS=["ok"], SIMILARITY=float("nan"))
    with pytest.raises(ValueError):
        module.validate(settings)


def test_api_inventory_resolves_local_refs_and_never_executes_operations(run_module):
    document = {
        "openapi": "3.0.3",
        "servers": [{"url": "/v1"}, {"url": "https://outside.test"}],
        "security": [{"bearer": []}],
        "components": {
            "parameters": {
                "Search": {"name": "search", "in": "query", "schema": {"type": "string"}}
            },
            "schemas": {
                "Create": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                }
            },
        },
        "paths": {
            "/users": {
                "get": {"parameters": [{"$ref": "#/components/parameters/Search"}]},
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Create"}}
                        }
                    }
                },
            },
            "/public": {"get": {"security": []}},
            "/empty": {"get": {}},
            "/external": {"get": {"parameters": [{"$ref": "https://outside.test/schema"}]}},
        },
    }
    _, report, requests, directory = run_module(
        APIInventory(),
        lambda _: httpx.Response(200, json=document),
        PATHS=["/openapi.json"],
        ONLY_CUSTOM=True,
    )
    assert requests == [("GET", "https://example.test/openapi.json")]
    endpoints = report["endpoints"]
    assert len(endpoints) == 5
    assert all(e["url"].startswith("https://example.test/v1/") for e in endpoints)
    search = next(e for e in endpoints if e["url"].endswith("/users") and e["method"] == "GET")
    assert search["parameters"][0]["name"] == "search"
    create = next(e for e in endpoints if e["method"] == "POST")
    assert create["parameters"][0]["name"] == "name"
    assert not create["authentication_optional"]
    assert next(e for e in endpoints if e["url"].endswith("/public"))["authentication_optional"]
    templates = json.loads((directory / "request-templates.json").read_text())
    assert all(not template["executed"] for template in templates)
    assert "External references were not fetched" in report["results"][0]["warnings"]


def test_api_supports_yaml_swagger_and_bounds_operations(run_module):
    spec = (
        b'swagger: "2.0"\nbasePath: /service\npaths:\n'
        b"  /one:\n    get: {}\n  /two:\n    delete: {}\n"
    )
    assert parse_document(spec)["swagger"] == "2.0"
    _, report, requests, _ = run_module(
        APIInventory(),
        lambda _: httpx.Response(200, content=spec),
        PATHS=["/swagger.yaml"],
        ONLY_CUSTOM=True,
        MAX_OPERATIONS=1,
    )
    assert len(report["endpoints"]) == 1
    assert report["endpoints"][0]["url"] == "https://example.test/service/one"
    assert requests == [("GET", "https://example.test/swagger.yaml")]
    assert report["results"][-1]["limited"]


def test_api_ref_cycles_and_malformed_yaml_are_handled(run_module):
    warnings = set()
    document = {"x": {"$ref": "#/x"}}
    assert local_object(document, document["x"], warnings) == {}
    assert warnings
    _, report, _, _ = run_module(
        APIInventory(),
        lambda _: httpx.Response(200, text="paths: [unclosed"),
        PATHS=["/openapi.yaml"],
        ONLY_CUSTOM=True,
    )
    assert not report["results"][0]["recognized"]


def test_parameter_map_extracts_without_submitting_by_default(run_module):
    html = (
        '<a href="/search?q=existing">Search</a>'
        '<form action="/save" method="post"><input name="note"></form>'
        '<form action="/find"><input name="term"></form>'
    )
    _, report, requests, _ = run_module(
        ParameterMap(),
        lambda _: httpx.Response(200, headers={"content-type": "text/html"}, text=html),
    )
    assert requests == [("GET", "https://example.test/")]
    names = {r["name"] for r in report["results"] if r["kind"] == "parameter"}
    assert names == {"q", "note", "term"}
    assert not report["findings"]


def test_parameter_reflections_are_get_only_and_skip_sensitive_names(run_module):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text='<form action="/find"><input name="q"><input name="csrf"></form>'
                '<form action="/save" method="post"><input name="note"></form>',
            )
        q = parse_qs(request.url.query.decode()).get("q", [""])[0]
        return httpx.Response(200, headers={"X-Value": q}, text="query: " + q)

    _, report, requests, _ = run_module(ParameterMap(), handler, REFLECT=True)
    assert all(method == "GET" for method, _ in requests)
    assert not any("csrf=" in url or "/save" in url for _, url in requests)
    finding = next(f for f in report["findings"] if f["kind"] == "input-reflection")
    assert finding["parameter"] == "q"
    assert finding["body_offsets"]
    assert finding["header_names"] == ["x-value"]


def test_parameter_imports_api_metadata_without_fetching_post_urls(run_module, tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "endpoints": [
                    {
                        "url": "https://example.test/save",
                        "method": "POST",
                        "parameters": [{"name": "title", "in": "body"}],
                    }
                ]
            }
        )
    )
    _, report, requests, _ = run_module(
        ParameterMap(),
        lambda _: httpx.Response(200, text="hello"),
        INVENTORY=[str(inventory)],
        REFLECT=True,
    )
    assert requests == [("GET", "https://example.test/")]
    assert any(r.get("name") == "title" and r["in"] == "body" for r in report["results"])


def test_parameter_javascript_hints_and_url_parameters(run_module):
    def handler(request):
        body = (
            b'fetch("/api/items?sort=asc"); params.get("page");'
            if request.url.path == "/app.js"
            else b"hello"
        )
        return httpx.Response(200, headers={"content-type": "application/javascript"}, content=body)

    _, report, _, _ = run_module(ParameterMap(), handler, PATHS=["/app.js"])
    parameters = {r["name"]: r for r in report["results"] if r["kind"] == "parameter"}
    assert parameters["sort"]["url"] == "https://example.test/api/items?sort=asc"
    assert parameters["page"]["in"] == "unknown"


def test_api_inventory_to_parameter_map_chain_preserves_method_and_parameters(run_module):
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/items": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
            "/save": {"post": {"parameters": [{"name": "title", "in": "query"}]}},
        },
    }
    _, _, _, directory = run_module(
        APIInventory(),
        lambda _: httpx.Response(200, json=document),
        PATHS=["/openapi.json"],
        ONLY_CUSTOM=True,
    )
    _, report, requests, _ = run_module(
        ParameterMap(),
        lambda _: httpx.Response(200, text="okay"),
        INVENTORY=[str(directory / "inventory.json")],
    )
    assert {url for _, url in requests} == {
        "https://example.test/",
        "https://example.test/items",
    }
    imported = [r for r in report["results"] if r.get("source") == "inventory"]
    assert {(r["name"], r["method"]) for r in imported} == {("q", "GET"), ("title", "POST")}


@pytest.mark.parametrize("module", [SiteMap(), ContentDiscovery()])
def test_discovery_does_not_fetch_mutating_inventory_entries(run_module, tmp_path, module):
    inventory = tmp_path / "post-only.json"
    inventory.write_text(json.dumps([{"url": "https://example.test/save", "method": "POST"}]))
    overrides = (
        {"WORDS": ["known"], "SOFT_404": False} if isinstance(module, ContentDiscovery) else {}
    )
    _, report, requests, _ = run_module(
        module,
        lambda _: httpx.Response(404),
        INVENTORY=[str(inventory)],
        **overrides,
    )
    assert not any(url.endswith("/save") for _, url in requests)
    assert next(e for e in report["endpoints"] if e["url"].endswith("/save"))["method"] == "POST"


def test_external_html_base_does_not_reinterpret_relative_links(run_module):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text='<base href="https://outside.test/"><a href="/external">outside</a>'
                '<a href="https://example.test/local">local</a>'
                '<form><input name="q"></form>',
            )
        return httpx.Response(404)

    _, report, requests, _ = run_module(SiteMap(), handler)
    assert "https://example.test/local" in {url for _, url in requests}
    assert not any("external" in url or "outside.test" in url for _, url in requests)
    homepage = next(e for e in report["endpoints"] if e["url"] == "https://example.test/")
    assert homepage["parameters"][0]["name"] == "q"


def test_large_wildcard_pages_with_late_differences_are_retained(run_module):
    def handler(request):
        tail = b"interesting details" if request.url.path == "/real" else b"missing generic page"
        return httpx.Response(200, content=b"same" * 40000 + tail)

    _, report, _, _ = run_module(
        ContentDiscovery(),
        handler,
        WORDS=["real"],
        MAX_CANDIDATES=1,
    )
    assert report["results"][0]["verdict"] == "interesting"
