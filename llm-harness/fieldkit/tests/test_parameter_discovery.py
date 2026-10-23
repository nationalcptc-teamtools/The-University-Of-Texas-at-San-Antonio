"""Native unknown-field discovery controls, auth/session continuity and request limits."""

import asyncio
import io
import json
import os
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs

import httpx
import pytest
from rich.console import Console
from test_replay_checks import network_run, request_file, write_json

from fieldkit.modules.parameter_discovery import ParameterDiscovery, add_field, layout, read_names


def discover(tmp_path, monkeypatch, handler, request=None, **settings):
    return network_run(
        ParameterDiscovery(),
        tmp_path,
        monkeypatch,
        handler,
        REQUESTS_FILE=request_file(tmp_path, request),
        REQUEST_IDS=["test"],
        NAMES=["hidden", "ignored"],
        CONFIRM_PROBES=True,
        **settings,
    )


def candidate(report, name="hidden"):
    return next(r for r in report["results"][0]["candidates"] if r["name"] == name)


def test_form_discovery_preserves_session_fields_and_verifies_readback(tmp_path, monkeypatch):
    captured = {
        "id": "test",
        "url": "/post?original=yes",
        "method": "POST",
        "profile": "alice",
        "headers": {"X-App": "kept"},
        "cookies": {"special": "cookie-private-value"},
        "form": {"csrf": "csrf-private-value", "item": "123", "password": "body-private-value"},
    }
    profiles = write_json(
        tmp_path,
        "profiles.json",
        {
            "profiles": {
                "alice": {
                    "origins": ["https://lab.test"],
                    "headers": {"Authorization": "Bearer private-auth"},
                }
            }
        },
    )

    def handler(request):
        fields = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        assert request.headers["Authorization"] == "Bearer private-auth"
        assert request.headers["X-App"] == "kept" and "special=" in request.headers["Cookie"]
        assert request.url.params["original"] == "yes"
        assert fields["csrf"] == "csrf-private-value" and fields["item"] == "123"
        return httpx.Response(200, json={"value": fields.get("hidden", "original")})

    code, report, directory, seen = discover(
        tmp_path,
        monkeypatch,
        handler,
        captured,
        PROFILES_FILE=profiles,
        ACCEPTANCE_POINTER="/value",
    )
    assert code == 0 and len(seen) == 8
    assert candidate(report)["outcome"] == "confirmed_acceptance"
    assert candidate(report, "ignored")["outcome"] == "no_signal"
    assert report["findings"][0]["severity"] == "info"
    assert not report["parameter_discovery"]["vulnerability_claimed"]
    saved = "".join(p.read_text() for p in directory.rglob("*.json"))
    for value in (
        "private-auth",
        "cookie-private-value",
        "csrf-private-value",
        "body-private-value",
    ):
        assert value not in saved


def test_nested_json_strict_schema_controls_and_signal(tmp_path, monkeypatch):
    request = {
        "id": "test",
        "url": "/json",
        "method": "POST",
        "json": {
            "keep": {"signed": "yes"},
            "object": {"old": "value"},
        },
    }

    def handler(req):
        body = json.loads(req.content)
        assert body["keep"] == {"signed": "yes"} and body["object"]["old"] == "value"
        fields = body["object"]
        if any(k.startswith("fieldkit_unknown_") for k in fields):
            return httpx.Response(422, json={"error": "unknown field"})
        return httpx.Response(200, json={"bound": fields.get("hidden", "original")})

    code, report, _, seen = discover(
        tmp_path,
        monkeypatch,
        handler,
        request,
        JSON_PARENT="/object",
    )
    assert code == 0 and len(seen) == 9
    assert candidate(report)["outcome"] == "signal"
    assert all("hidden" not in json.loads(r.content) for r in seen)


def test_xml_parent_and_namespace_are_preserved(tmp_path, monkeypatch):
    request = {
        "id": "test",
        "url": "/xml",
        "method": "POST",
        "headers": {"Content-Type": "application/soap+xml; charset=UTF-8"},
        "xml": '<s:Envelope xmlns:s="urn:soap"><s:Body><s:Data><s:old>keep</s:old>'
        "</s:Data></s:Body></s:Envelope>",
    }

    def handler(req):
        root = ET.fromstring(req.content)
        parent = root.find("{urn:soap}Body/{urn:soap}Data")
        assert parent.find("{urn:soap}old").text == "keep"
        assert "application/soap+xml" in req.headers["Content-Type"]
        hidden = parent.find("{urn:soap}hidden")
        return httpx.Response(
            200, json={"value": hidden.text if hidden is not None else "original"}
        )

    code, report, _, seen = discover(
        tmp_path,
        monkeypatch,
        handler,
        request,
        XML_PARENT="{urn:soap}Body/{urn:soap}Data",
        ACCEPTANCE_POINTER="/value",
    )
    assert code == 0 and len(seen) == 8
    assert candidate(report)["outcome"] == "confirmed_acceptance"


def test_query_requires_explicit_selection_and_preserves_query_and_post_body(tmp_path, monkeypatch):
    request = {"id": "test", "url": "/query?old=keep", "method": "POST", "json": {"old": "body"}}

    def handler(req):
        assert req.url.params["old"] == "keep" and json.loads(req.content) == {"old": "body"}
        return httpx.Response(200, json={"value": req.url.params.get("hidden", "original")})

    code, report, _, _ = discover(
        tmp_path,
        monkeypatch,
        handler,
        request,
        LOCATION="query",
        ACCEPTANCE_POINTER="/value",
    )
    assert code == 0 and candidate(report)["outcome"] == "confirmed_acceptance"


@pytest.mark.parametrize(
    "behavior", ["generic_echo", "unstable", "login", "denied", "controls_auth"]
)
def test_false_positive_and_authentication_controls(tmp_path, monkeypatch, behavior):
    count = 0

    def handler(req):
        nonlocal count
        count += 1
        body = json.loads(req.content)
        if behavior == "generic_echo":
            return httpx.Response(200, json=body)
        if behavior == "unstable":
            return httpx.Response(200, json={"nonce": str(count), "data": str(count) * 40})
        if behavior == "login":
            return httpx.Response(200, text='<form><input type="password"></form>')
        if behavior == "denied" or behavior == "controls_auth" and count > 3:
            return httpx.Response(403, text="denied")
        return httpx.Response(200, json={"value": "original"})

    code, report, _, seen = discover(tmp_path, monkeypatch, handler, ACCEPTANCE_POINTER="/hidden")
    assert code == 0 and not report["findings"]
    assert report["results"][0]["outcome"] == "inconclusive"
    assert all(c["outcome"] == "inconclusive" for c in report["results"][0]["candidates"])
    assert len(seen) <= 5


def test_confirmation_instability_is_not_acceptance(tmp_path, monkeypatch):
    def handler(req):
        body = json.loads(req.content)
        return httpx.Response(
            200,
            json={
                "value": "one distinct result"
                if body.get("hidden") == "fieldkit-marker"
                else "a completely different result"
                if "hidden" in body
                else "original",
            },
        )

    code, report, _, _ = discover(tmp_path, monkeypatch, handler)
    assert code == 0 and candidate(report)["outcome"] == "inconclusive"
    assert not report["findings"]


def test_bounds_preserve_partial_result_without_extra_requests(tmp_path, monkeypatch):
    code, report, _, seen = discover(
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(
            200, json={"value": json.loads(req.content).get("hidden", "original")}
        ),
        MAX_REQUESTS=6,
    )
    assert code == 1 and len(seen) == 6
    assert not report["completed"] and report["errors"][0]["error"] == "probe_limit"
    assert candidate(report)["outcome"] == "inconclusive"
    assert report["parameter_discovery"]["requests_sent"] == 6


def test_additional_field_cap_includes_unknown_controls(tmp_path, monkeypatch):
    code, report, _, seen = discover(
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200, text="stable"),
        MAX_PROBES=2,
    )
    assert code == 1 and len(seen) == 5
    assert report["parameter_discovery"]["added_field_requests"] == 2


@pytest.mark.parametrize(
    "saved_request,settings",
    [
        ({"id": "test", "url": "/", "method": "POST", "body_base64": "AP8="}, {}),
        ({"id": "test", "url": "/", "method": "POST", "json": {"a": []}}, {"JSON_PARENT": "/a"}),
        (
            {"id": "test", "url": "/", "method": "POST", "xml": "<r><a/><a/></r>"},
            {"XML_PARENT": "a"},
        ),
    ],
)
def test_unsupported_body_or_parent_sends_nothing(tmp_path, monkeypatch, saved_request, settings):
    code, report, _, seen = discover(
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200),
        saved_request,
        **settings,
    )
    assert code == 0 and not seen and report["results"][0]["outcome"] == "unsupported"


def test_existing_names_are_never_overwritten():
    request = {"url": "https://lab.test/", "method": "POST", "json": {"hidden": "original"}}
    settings = {"LOCATION": "json", "JSON_PARENT": "", "XML_PARENT": "."}
    with pytest.raises(ValueError, match="already exists"):
        add_field(request, layout(request, settings), "hidden", "replacement")
    assert request["json"]["hidden"] == "original"


def test_active_confirmation_and_dry_run(tmp_path, monkeypatch):
    module = ParameterDiscovery()
    settings = {
        **module.defaults(),
        "TARGETS": ["https://lab.test"],
        "REQUEST_IDS": ["test"],
        "REQUESTS_FILE": request_file(tmp_path),
        "NAMES": ["hidden"],
        "OUTPUT": str(tmp_path / "plan"),
    }
    with pytest.raises(ValueError, match="CONFIRM_PROBES"):
        module.run(settings, Console(file=io.StringIO()))
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient", lambda **kw: pytest.fail("network")
    )
    assert module.run({**settings, "DRY_RUN": True}, Console(file=io.StringIO())) == 0
    report = json.loads(next((tmp_path / "plan").glob("*/report.json")).read_text())
    assert report["plan"]["network_requests"] == 0


def test_all_selected_scope_validated_before_replaying(tmp_path, monkeypatch):
    path = write_json(
        tmp_path,
        "scope.json",
        [
            {"id": "good", "url": "https://lab.test/", "method": "POST", "form": {}},
            {"id": "bad", "url": "https://outside.test/", "method": "POST", "form": {}},
        ],
    )
    seen = []
    with pytest.raises(ValueError, match="scope"):
        network_run(
            ParameterDiscovery(),
            tmp_path,
            monkeypatch,
            lambda req: seen.append(req) or httpx.Response(200),
            REQUESTS_FILE=path,
            REQUEST_IDS=["good", "bad"],
            NAMES=["hidden"],
            CONFIRM_PROBES=True,
        )
    assert not seen


def test_names_file_comments_duplicates_and_nonregular_bounds(tmp_path, monkeypatch):
    path = tmp_path / "names.txt"
    path.write_text("# candidates\nhidden\nhidden\nignored\n")
    assert read_names(path, 1024) == ["hidden", "hidden", "ignored"]
    code, report, _, _ = network_run(
        ParameterDiscovery(),
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200, text="stable"),
        REQUESTS_FILE=request_file(tmp_path),
        REQUEST_IDS=["test"],
        NAMES_FILE=str(path),
        CONFIRM_PROBES=True,
    )
    assert code == 0 and report["parameter_discovery"]["candidate_names"] == 2
    with pytest.raises(ValueError, match="exceeds"):
        read_names(path, 2)
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    with pytest.raises(ValueError, match="regular"):
        read_names(pipe, 1024)


def test_ambiguous_json_pointer_and_retries_are_rejected(tmp_path):
    module = ParameterDiscovery()
    settings = {
        **module.defaults(),
        "REQUESTS_FILE": request_file(tmp_path),
        "REQUEST_IDS": ["test"],
        "NAMES": ["hidden"],
        "CONFIRM_PROBES": True,
    }
    with pytest.raises(ValueError, match="RFC 6901"):
        module.validate({**settings, "JSON_PARENT": "/bad~2escape"})
    with pytest.raises(ValueError, match="RETRIES"):
        module.validate({**settings, "RETRIES": 1})


def test_total_budget_preserves_incomplete_baseline_evidence(tmp_path, monkeypatch):
    async def handler(req):
        await asyncio.sleep(0.03)
        return httpx.Response(200, text="working baseline")

    code, report, _, seen = discover(tmp_path, monkeypatch, handler, BUDGET=0.05)
    assert code == 1 and len(seen) <= 2 and not report["completed"]
    assert any(error["error"] == "budget_exhausted" for error in report["errors"])
    assert report["parameter_discovery"]["added_field_requests"] == 0
    assert report["results"][0]["baselines"]


def test_transport_failure_blocks_candidates(tmp_path, monkeypatch):
    def handler(req):
        raise httpx.ReadError("fixture connection failure", request=req)

    code, report, _, seen = discover(tmp_path, monkeypatch, handler)
    assert code == 1 and len(seen) == 1
    assert report["results"][0]["outcome"] == "inconclusive"
    assert not report["findings"]


def test_vault_selection_keeps_private_request_fields(tmp_path, monkeypatch):
    from fieldkit.core.vault import Vault

    path = tmp_path / "evidence.sqlite"
    with Vault(path) as vault:
        identifier = vault.exchange(
            {
                "url": "https://lab.test/vault",
                "method": "POST",
                "headers": {"Authorization": "Bearer vault-private-value"},
                "json": {"existing": "kept"},
            }
        )

    def handler(req):
        assert req.headers["Authorization"] == "Bearer vault-private-value"
        body = json.loads(req.content)
        assert body["existing"] == "kept"
        return httpx.Response(200, json={"value": body.get("hidden", "original")})

    code, report, directory, _ = network_run(
        ParameterDiscovery(),
        tmp_path,
        monkeypatch,
        handler,
        DATABASE=str(path),
        REQUEST_IDS=[identifier],
        NAMES=["hidden"],
        CONFIRM_PROBES=True,
        ACCEPTANCE_POINTER="/value",
    )
    assert code == 0 and candidate(report)["outcome"] == "confirmed_acceptance"
    assert "vault-private-value" not in "".join(p.read_text() for p in directory.rglob("*.json"))


def test_unknown_field_error_echoes_do_not_create_signals(tmp_path, monkeypatch):
    def handler(req):
        added = set(json.loads(req.content)) - {"id"}
        if added:
            return httpx.Response(422, json={"error": f"Unknown field '{next(iter(added))}'"})
        return httpx.Response(200, json={"value": "original"})

    code, report, _, seen = discover(tmp_path, monkeypatch, handler)
    assert code == 0 and len(seen) == 7
    assert candidate(report)["outcome"] == candidate(report, "ignored")["outcome"] == "no_signal"
    assert not report["findings"]


@pytest.mark.parametrize("marker", ['quote"and\\slash', "Unicode-☃", "xml-&<>marker", "x"])
def test_escaped_and_short_marker_readbacks_are_confirmed(tmp_path, monkeypatch, marker):
    code, report, _, seen = discover(
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(
            200, json={"value": json.loads(req.content).get("hidden", "original")}
        ),
        VALUE=marker,
        ACCEPTANCE_POINTER="/value",
    )
    assert code == 0 and len(seen) == 8
    assert candidate(report)["outcome"] == "confirmed_acceptance"


@pytest.mark.parametrize("fails_on", ["candidate", "confirmation"])
def test_candidate_session_failure_stops_remaining_probes(tmp_path, monkeypatch, fails_on):
    def handler(req):
        body = json.loads(req.content)
        if "hidden" in body and (fails_on == "candidate" or body["hidden"] != "fieldkit-marker"):
            return httpx.Response(401, json={"error": "expired"})
        return httpx.Response(200, json={"value": body.get("hidden", "original")})

    code, report, _, seen = discover(tmp_path, monkeypatch, handler)
    assert code == 0 and len(seen) == (6 if fails_on == "candidate" else 7)
    assert report["results"][0]["outcome"] == "inconclusive"
    assert candidate(report, "ignored")["probes"] == []
    assert not report["findings"]


def test_get_query_preserves_duplicate_captured_query_fields(tmp_path, monkeypatch):
    captured = {"id": "test", "url": "/query?old=one&old=two", "method": "GET"}

    def handler(req):
        assert req.url.params.get_list("old") == ["one", "two"]
        return httpx.Response(200, json={"value": req.url.params.get("hidden", "original")})

    code, report, _, seen = discover(
        tmp_path, monkeypatch, handler, captured, LOCATION="query", ACCEPTANCE_POINTER="/value"
    )
    assert code == 0 and len(seen) == 8
    assert candidate(report)["outcome"] == "confirmed_acceptance"


def test_automatic_scheme_probes_are_rejected_before_network(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient", lambda **kw: pytest.fail("network")
    )
    module = ParameterDiscovery()
    settings = {
        **module.defaults(),
        "TARGETS": ["lab.test"],
        "REQUESTS_FILE": request_file(tmp_path),
        "REQUEST_IDS": ["test"],
        "NAMES": ["hidden"],
        "CONFIRM_PROBES": True,
    }
    with pytest.raises(ValueError, match="explicit target schemes"):
        module.run(settings, Console(file=io.StringIO()))


def test_bare_target_with_fixed_scheme_has_no_preparation_requests(tmp_path, monkeypatch):
    code, report, _, seen = discover(
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200, text="stable"),
        TARGETS=["lab.test"],
        SCHEME="https",
        MAX_REQUESTS=5,
    )
    assert code == 1 and len(seen) == 5
    assert all(req.method == "POST" for req in seen)
    assert report["parameter_discovery"]["requests_sent"] == 5


def test_dry_run_rejects_outside_request_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient", lambda **kw: pytest.fail("network")
    )
    module = ParameterDiscovery()
    settings = {
        **module.defaults(),
        "TARGETS": ["https://lab.test"],
        "REQUESTS_FILE": request_file(
            tmp_path, {"id": "test", "url": "https://outside.test/", "method": "POST", "form": {}}
        ),
        "REQUEST_IDS": ["test"],
        "NAMES": ["hidden"],
        "DRY_RUN": True,
    }
    with pytest.raises(ValueError, match="outside supplied scope"):
        module.run(settings, Console(file=io.StringIO()))


def test_every_selected_profile_is_bound_before_any_replay(tmp_path, monkeypatch):
    profiles = write_json(
        tmp_path,
        "profiles.json",
        {
            "profiles": {
                "alice": {
                    "origins": ["https://another.test"],
                    "headers": {"Authorization": "Bearer private-value"},
                }
            }
        },
    )
    requests = write_json(
        tmp_path,
        "selected.json",
        [
            {"id": "good", "url": "/good", "method": "POST", "form": {}},
            {"id": "bad", "url": "/bad", "method": "POST", "form": {}, "profile": "alice"},
        ],
    )
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient", lambda **kw: pytest.fail("network")
    )
    module = ParameterDiscovery()
    settings = {
        **module.defaults(),
        "TARGETS": ["https://lab.test"],
        "REQUESTS_FILE": requests,
        "REQUEST_IDS": ["good", "bad"],
        "PROFILES_FILE": profiles,
        "NAMES": ["hidden"],
        "CONFIRM_PROBES": True,
    }
    with pytest.raises(ValueError, match="session profile scope"):
        module.run(settings, Console(file=io.StringIO()))


@pytest.mark.parametrize(
    "option,value",
    [
        ("MAX_NAMES", 1001),
        ("MAX_PROBES", 10001),
        ("MAX_REQUESTS", 10001),
        ("BUDGET", 3601),
        ("BUDGET", float("nan")),
        ("MIN_SIMILARITY", float("inf")),
        ("VALUE", "marker\x00value"),
        ("NAMES", ["bad\x7fname"]),
    ],
)
def test_hard_caps_and_marker_controls(tmp_path, option, value):
    module = ParameterDiscovery()
    settings = {
        **module.defaults(),
        "TARGETS": ["https://lab.test"],
        "REQUESTS_FILE": request_file(tmp_path),
        "REQUEST_IDS": ["test"],
        "NAMES": ["hidden"],
        "CONFIRM_PROBES": True,
        option: value,
    }
    with pytest.raises(ValueError):
        module.validate(settings)


def test_json_pointer_selects_object_inside_array_with_escaped_keys(tmp_path, monkeypatch):
    captured = {
        "id": "test",
        "url": "/json",
        "method": "PATCH",
        "json": {"array/key": [{"tilde~key": {"old": "kept"}}]},
    }

    def handler(req):
        assert req.method == "PATCH"
        body = json.loads(req.content)
        parent = body["array/key"][0]["tilde~key"]
        assert parent["old"] == "kept"
        return httpx.Response(200, json={"value": parent.get("hidden", "original")})

    code, report, _, _ = discover(
        tmp_path,
        monkeypatch,
        handler,
        captured,
        JSON_PARENT="/array~1key/0/tilde~0key",
        ACCEPTANCE_POINTER="/value",
    )
    assert code == 0 and candidate(report)["outcome"] == "confirmed_acceptance"


def test_request_limit_is_shared_across_selected_requests(tmp_path, monkeypatch):
    path = write_json(
        tmp_path,
        "selected.json",
        [
            {"id": "first", "url": "/one", "method": "POST", "json": {}},
            {"id": "second", "url": "/two", "method": "PUT", "form": {}},
        ],
    )
    code, report, _, seen = network_run(
        ParameterDiscovery(),
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(200, text="stable"),
        REQUESTS_FILE=path,
        REQUEST_IDS=["first", "second"],
        NAMES=["hidden"],
        CONFIRM_PROBES=True,
        MAX_REQUESTS=6,
    )
    assert code == 1 and len(seen) == 6
    assert report["parameter_discovery"]["requests_sent"] == 6
    assert report["results"][0]["candidates"][0]["outcome"] == "no_signal"
    assert report["results"][1]["baselines"] == []
    assert not report["completed"]


def test_baseline_redirect_is_not_followed_or_classified(tmp_path, monkeypatch):
    code, report, _, seen = discover(
        tmp_path,
        monkeypatch,
        lambda req: httpx.Response(302, headers={"Location": "https://outside.test/login"}),
    )
    assert code == 0 and len(seen) == 1
    assert report["results"][0]["outcome"] == "inconclusive"
    assert not report["findings"]
