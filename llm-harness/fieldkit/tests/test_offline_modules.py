import asyncio
import base64
import copy
import json
from io import StringIO
from types import SimpleNamespace
from urllib.parse import urljoin

import pytest
from rich.console import Console

from fieldkit.core.results import (
    compare_reports,
    merge_reports,
    normalize_report,
    stable_id,
    update_review,
)
from fieldkit.modules.js_review import (
    JSReview,
    Source,
    _inline_map,
    _observations,
    local_sources,
    source_map_sources,
)
from fieldkit.modules.report_export import (
    ReportExport,
    ReviewUpdate,
    RunCompare,
    TeamMerge,
    markdown_report,
)


def report(**overrides):
    return {
        "schema_version": 2,
        "module": "test",
        "findings": [],
        "results": [],
        "endpoints": [],
        **overrides,
    }


def finding(**overrides):
    return {
        "kind": "header",
        "title": "Header missing",
        "url": "https://example.test/",
        "severity": "info",
        **overrides,
    }


def test_stable_identity_and_changes_ignore_evidence_and_review():
    old = finding(evidence=["evidence-1"], review={"status": "unreviewed"})
    new = finding(evidence=["evidence-99"], review={"status": "confirmed"})
    assert stable_id(old) == stable_id(new)
    assert compare_reports(report(findings=[old]), report(findings=[new]))["findings"] == {
        "added": [],
        "removed": [],
        "changed": [],
    }
    new["severity"] = "medium"
    delta = compare_reports(report(findings=[old]), report(findings=[new]))
    assert len(delta["findings"]["changed"]) == 1
    assert delta["findings"]["changed"][0]["before"]["severity"] == "info"
    assert delta["findings"]["changed"][0]["after"]["severity"] == "medium"


def test_compare_status_changes_and_endpoint_additions():
    previous = report(results=[{"url": "https://example.test/", "status": 200}])
    current = report(
        results=[{"url": "https://example.test/", "status": 403}],
        endpoints=[{"url": "https://example.test/new"}],
    )
    delta = compare_reports(previous, current)
    assert len(delta["results"]["changed"]) == 1
    assert len(delta["endpoints"]["added"]) == 1


def test_normalization_is_idempotent_and_legacy_artifacts_survive():
    legacy = {
        "schema_version": 1,
        "module": "web/artifacts",
        "targets": [
            {
                "results": [
                    {
                        "requested_url": "https://example.test/main.js",
                        "status": 200,
                        "file": "example/main.js--hash",
                        "sha256": "abc",
                        "verdict": "saved",
                    }
                ]
            }
        ],
    }
    normalized = normalize_report(legacy)
    assert normalized == normalize_report(normalized)
    assert normalized["results"][0]["file"] == "example/main.js--hash"
    assert normalized["endpoints"][0]["url"].endswith("main.js")


def test_normalization_preserves_distinct_same_line_js_and_cookie_findings():
    first = finding(kind="js-endpoint", source="/run1/main.js", line=1, value="/api/a")
    second = finding(kind="js-endpoint", source="/run2/main.js", line=1, value="/api/b")
    assert stable_id(first) != stable_id(second)
    assert stable_id(first) == stable_id({**first, "source": "/different-run/main.js"})
    assert stable_id(finding(cookie_name="a")) != stable_id(finding(cookie_name="b"))


def test_merge_retains_conflicting_reviews_and_namespaces_evidence():
    a = report(
        findings=[finding(evidence=["evidence-1"], review={"assignee": "Alice"})],
        evidence=[{"id": "evidence-1", "file": "evidence/evidence-1.json"}],
    )
    b = report(
        findings=[finding(evidence=["evidence-1"], review={"assignee": "Bob"})],
        evidence=[{"id": "evidence-1", "file": "evidence/evidence-1.json"}],
    )
    merged = merge_reports([a, b])
    assert len(merged["findings"]) == 1
    assert merged["findings"][0]["review"] == {"assignee": "Alice"}
    assert merged["findings"][0]["review_conflicts"] == [{"assignee": "Bob"}]
    assert merged["findings"][0]["evidence"] == ["input-1:evidence-1"]
    assert merged["findings"][0]["evidence_sources"][0]["evidence"] == ["input-2:evidence-1"]
    assert len({item["id"] for item in merged["evidence"]}) == 2
    assert a["findings"][0]["evidence"] == ["evidence-1"]


def test_review_update_preserves_history_and_never_mutates_input():
    source = report(findings=[finding(id="old-module-id", review={"status": "unreviewed"})])
    original = copy.deepcopy(source)
    updated = update_review(
        source, "old-module-id", status="confirmed", assignee="Alice", note="Validated"
    )
    assert source == original
    assert updated["findings"][0]["review"]["assignee"] == "Alice"
    assert updated["findings"][0]["review_history"] == [{"status": "unreviewed"}]
    with pytest.raises(ValueError, match="exactly one"):
        update_review(source, "does-not-exist")


def test_markdown_export_redacts_and_keeps_evidence():
    source = report(
        findings=[
            finding(
                context='const password="real-password";',
                details={"Authorization": "Bearer abcdefgh"},
            )
        ],
        evidence=[{"id": "e1", "url": "https://example.test/", "file": "evidence/e1.json"}],
    )
    draft = markdown_report(source)
    assert "real-password" not in draft
    assert "abcdefgh" not in draft
    assert "[REDACTED]" in draft
    assert "evidence/e1.json" in draft
    assert "manual validation" in draft


def test_js_observations_provide_locations_and_redact_every_context():
    text = (
        '\nconst apiKey="abcd-sensitive-value"; fetch("/api/users"); route: "/user/:id";\n'
        'const host="https://internal.example.test/v1";'
    )
    observations = _observations(text, {"endpoints", "routes", "hostnames", "secrets"})
    assert {item["kind"] for item in observations} == {
        "js-endpoint",
        "js-route",
        "js-hostname",
        "js-possible-secret",
    }
    assert "abcd-sensitive-value" not in json.dumps(observations)
    assert next(item for item in observations if item["kind"] == "js-possible-secret")["line"] == 2
    assert any(item["value"] == "internal.example.test" for item in observations)
    assert not any(
        item["kind"] == "js-possible-secret" for item in _observations(text, {"endpoints"})
    )


def test_local_legacy_manifest_and_traversal_rejection(tmp_path):
    saved = tmp_path / "main.js--hash"
    saved.write_text('fetch("/api/users")')
    manifest = tmp_path / "report.json"
    document = {
        "schema_version": 1,
        "targets": [
            {"results": [{"requested_url": "https://example.test/main.js", "file": saved.name}]}
        ],
    }
    manifest.write_text(json.dumps(document))
    sources = local_sources([str(manifest)], 1024, 10)
    assert sources[0].url == "https://example.test/main.js"
    outside = tmp_path.parent / "outside.js"
    outside.write_text("outside")
    document["targets"][0]["results"][0]["file"] = "../outside.js"
    manifest.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="escapes"):
        local_sources([str(manifest)], 1024, 10)


def test_directory_symlink_and_size_limits(tmp_path):
    inputs = tmp_path / "input"
    inputs.mkdir()
    outside = tmp_path / "outside.js"
    outside.write_text("outside")
    (inputs / "linked.js").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes"):
        local_sources([str(inputs)], 1024, 10)
    with pytest.raises(ValueError, match="MAX_BYTES"):
        local_sources([str(outside)], 2, 10)


def test_source_map_embedded_names_are_not_read_as_paths():
    source = Source(
        "main.js.map",
        json.dumps(
            {
                "version": 3,
                "sources": ["../../etc/passwd"],
                "sourcesContent": ['fetch("/embedded")'],
            }
        ),
    )
    embedded = source_map_sources(source, 1024, 10)
    assert embedded[0].text == 'fetch("/embedded")'
    assert embedded[0].path is None
    with pytest.raises(ValueError, match="source limit"):
        source_map_sources(source, 1024, 0)
    with pytest.raises(ValueError, match="MAX_BYTES"):
        source_map_sources(source, 1, 10)


def test_inline_source_map_decode_and_encoding_limits():
    mapping = b'{"version":3,"sources":[],"sourcesContent":[]}'
    reference = "data:application/json;base64," + base64.b64encode(mapping).decode()
    assert _inline_map(reference, 1024) == mapping.decode()
    with pytest.raises(ValueError, match="MAX_BYTES"):
        _inline_map(reference, 1)
    with pytest.raises(ValueError, match="encoding"):
        _inline_map("data:application/json;base64,not-base64", 1024)


class FakeContext:
    def __init__(self, settings):
        self.settings = settings
        self.report = {"findings": [], "errors": [], "endpoints": []}
        self.fetched = []

    def seed_urls(self):
        return []

    def finding(self, kind, title, url, **details):
        self.report["findings"].append({"kind": kind, "title": title, "url": url, **details})

    def resolve(self, reference, base):
        url = urljoin(base, reference)
        return url if url.startswith("https://example.test/") else None

    def add_endpoint(self, url, **details):
        self.report["endpoints"].append({"url": url, **details})

    async def fetch(self, url):
        self.fetched.append(url)
        return SimpleNamespace(
            url=url,
            status=200,
            error=None,
            body=b'{"version":3,"sources":["src/app.js"],"sourcesContent":["fetch(\\"/mapped\\")"]}',
        )


def test_js_review_follows_only_scoped_maps_when_enabled(tmp_path):
    script = tmp_path / "saved.js"
    script.write_text(
        "//# sourceMappingURL=https://other.test/no.map\n"
        "//# sourceMappingURL=https://example.test/app.js.map"
    )
    manifest = tmp_path / "report.json"
    manifest.write_text(
        json.dumps(report(results=[{"url": "https://example.test/app.js", "file": script.name}]))
    )
    module = JSReview()
    settings = {
        **module.defaults(),
        "INPUT": [str(manifest)],
        "FETCH_MAPS": True,
        "TARGETS": ["https://example.test"],
    }
    module.validate(settings)
    ctx = FakeContext(settings)
    asyncio.run(module.assess(ctx))
    assert ctx.fetched == ["https://example.test/app.js.map"]
    assert any(item.get("value") == "/mapped" for item in ctx.report["findings"])
    assert not ctx.report["errors"]


def test_js_review_local_map_traversal_never_read(tmp_path):
    nested = tmp_path / "input"
    nested.mkdir()
    script = nested / "app.js"
    script.write_text("//# sourceMappingURL=../outside.map")
    (tmp_path / "outside.map").write_text('{"sources":[],"sourcesContent":[]}')
    module = JSReview()
    ctx = FakeContext({**module.defaults(), "INPUT": [str(script)]})
    asyncio.run(module.assess(ctx))
    assert "escapes" in ctx.report["errors"][0]["error"]
    assert not ctx.fetched


def test_offline_modules_write_new_outputs_and_leave_sources_unchanged(tmp_path):
    input_path = tmp_path / "input.json"
    data = report(findings=[finding()])
    input_path.write_text(json.dumps(data))
    console = Console(file=StringIO())
    for module, settings in [
        (ReportExport(), {"INPUT": [str(input_path)]}),
        (TeamMerge(), {"INPUT": [str(input_path), str(input_path)]}),
        (RunCompare(), {"BEFORE": str(input_path), "AFTER": str(input_path)}),
        (
            ReviewUpdate(),
            {
                "INPUT": str(input_path),
                "FINDING_ID": stable_id(finding()),
                "STATUS": "confirmed",
                "ASSIGNEE": "Alice",
            },
        ),
    ]:
        configured = {**module.defaults(), **settings, "OUTPUT": str(tmp_path / "out")}
        assert module.run(configured, console) == 0
    assert json.loads(input_path.read_text()) == data
    assert len(list((tmp_path / "out").glob("*/report.json"))) == 4
    assert len(list((tmp_path / "out").glob("*/report.md"))) == 2


def test_js_review_real_runtime_keeps_distinct_findings(tmp_path):
    script = tmp_path / "app.js"
    script.write_text('fetch("/first"); fetch("/second"); const password="secret-literal";')
    module = JSReview()
    settings = {**module.defaults(), "INPUT": [str(script)], "OUTPUT": str(tmp_path / "out")}
    assert module.run(settings, Console(file=StringIO())) == 0
    path = next((tmp_path / "out").glob("*/report.json"))
    document = json.loads(path.read_text())
    assert len([item for item in document["findings"] if item["kind"] == "js-endpoint"]) == 2
    assert "secret-literal" not in path.read_text()


def test_js_run_directory_changes_are_not_reported_as_content_changes():
    first = finding(
        kind="js-endpoint", source="/run1/app.js::src/component.js", line=1, value="/api/users"
    )
    second = {**first, "source": "/run2/app.js::src/component.js"}
    assert not compare_reports(report(findings=[first]), report(findings=[second]))["findings"][
        "changed"
    ]
    other_file = {**first, "source": "/run1/app.js::other/component.js"}
    assert stable_id(first) != stable_id(other_file)


def test_collector_v2_export_and_merge_keep_artifact_roots(tmp_path, monkeypatch):
    import httpx

    from fieldkit.core.results import load_report
    from fieldkit.modules.web_artifacts import WebArtifacts

    client_class = httpx.AsyncClient

    def reply(request):
        if request.url.path == "/app.js":
            return httpx.Response(
                200,
                text='fetch("/api/users"); const password="do-not-export";',
                headers={"Content-Type": "application/javascript"},
            )
        return httpx.Response(200, text="<html>Home</html>")

    def fake_client(*args, **kwargs):
        return client_class(*args, transport=httpx.MockTransport(reply), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", fake_client)
    collector = WebArtifacts()
    console = Console(file=StringIO())
    settings = {
        **collector.defaults(),
        "TARGETS": ["https://example.test"],
        "PATHS": ["/app.js"],
        "ONLY_CUSTOM": True,
        "DISCOVER_JS": False,
        "SOFT_404": False,
        "BACKUPS": False,
        "RATE": 0,
        "OUTPUT": str(tmp_path / "collected"),
    }
    assert collector.run(settings, console) == 0
    source = next((tmp_path / "collected").glob("*/report.json"))
    normalized = load_report(source)
    assert len(normalized["results"]) == len(normalized["targets"][0]["results"]) == 1
    assert len(local_sources([str(source)], 4096, 10)) == 1
    exporter = ReportExport()
    assert (
        exporter.run(
            {**exporter.defaults(), "INPUT": [str(source)], "OUTPUT": str(tmp_path / "exported")},
            console,
        )
        == 0
    )
    exported = next((tmp_path / "exported").glob("*/report.json"))
    assert load_report(exported)["results"][0]["artifact_root"] == str(source.parent)
    assert "do-not-export" not in exported.read_text()
    with pytest.raises(ValueError, match="artifact-root"):
        local_sources([str(exported)], 4096, 10)
    assert len(local_sources([str(exported)], 4096, 10, [str(source.parent)])) == 1
    reviewer = JSReview()
    assert (
        reviewer.run(
            {
                **reviewer.defaults(),
                "INPUT": [str(exported)],
                "ARTIFACT_ROOTS": [str(source.parent)],
                "OUTPUT": str(tmp_path / "reviewed"),
            },
            console,
        )
        == 0
    )
    reviewed = next((tmp_path / "reviewed").glob("*/report.json"))
    assert "do-not-export" not in reviewed.read_text()
    merged = merge_reports([load_report(source), load_report(exported)])
    assert len(merged["results"]) == 1
    assert not merged["results"][0].get("observation_conflicts")
    assert merged["results"][0]["artifact_root"] == str(source.parent)
    assert not compare_reports(load_report(source), load_report(exported))["results"]["changed"]


def test_remote_js_inventory_requires_explicit_origins():
    module = JSReview()
    with pytest.raises(ValueError, match="explicit target origins"):
        module.validate({**module.defaults(), "INVENTORY": ["inventory.json"]})


def test_recursive_merges_preserve_prior_conflicts_and_errors():
    first = report(
        findings=[finding(severity="info", review={"status": "unreviewed"})],
        errors=[{"error": "network_error"}],
    )
    second = report(findings=[finding(severity="medium", review={"status": "confirmed"})])
    once = merge_reports([first, second])
    twice = merge_reports([first, once])
    assert twice["findings"][0]["observation_conflicts"]
    assert twice["findings"][0]["review_conflicts"]
    assert twice["errors"]
