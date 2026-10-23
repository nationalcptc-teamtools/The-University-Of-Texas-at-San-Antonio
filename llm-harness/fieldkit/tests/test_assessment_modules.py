"""Behavioral checks exercise modules through the shared request/evidence runtime."""

import asyncio
import json
from io import StringIO
from types import SimpleNamespace

import httpx
import pytest
from rich.console import Console

from fieldkit.core.assessment import AssessmentContext
from fieldkit.modules.auth_compare import AuthCompare
from fieldkit.modules.cors_check import CorsCheck, cors_policy
from fieldkit.modules.header_review import HeaderReview
from fieldkit.modules.session_check import SessionCheck


def write_profiles(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "profiles": {
                    "user": {
                        "origins": ["https://lab.test"],
                        "headers": {"Authorization": "Bearer user-secret-example"},
                    },
                    "admin": {
                        "origins": ["https://lab.test"],
                        "headers": {"Authorization": "Bearer admin-secret-example"},
                    },
                }
            }
        )
    )
    return str(path)


def exercise(module, tmp_path, monkeypatch, handler, **overrides):
    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    settings = {
        **module.defaults(),
        "TARGETS": ["https://lab.test"],
        "OUTPUT": str(tmp_path / "runs"),
        "RATE": 0,
        "RETRIES": 0,
        **overrides,
    }
    module.validate(settings)

    async def run():
        async with AssessmentContext(module.name, settings, Console(file=StringIO())) as ctx:
            await ctx.prepare()
            await module.assess(ctx)
            ctx.finish()
            return ctx

    return asyncio.run(run())


def test_auth_compare_finds_shared_content_but_excludes_login_templates(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path == "/login-template":
            return httpx.Response(200, text='<form><input type="password"></form>')
        return httpx.Response(200, json={"account": "shared-content", "details": "review me"})

    ctx = exercise(
        AuthCompare(),
        tmp_path,
        monkeypatch,
        handler,
        PROFILES_FILE=write_profiles(tmp_path),
        PATHS=["/account", "/login-template"],
    )
    findings = ctx.report["findings"]
    assert any(f["url"].endswith("/account") for f in findings)
    assert not any(f["url"].endswith("/login-template") for f in findings)
    summaries = ctx.report["results"][1]["profiles"]
    assert all(value["looks_like_login"] for value in summaries.values())


def test_auth_compare_does_not_equate_200_with_access(tmp_path, monkeypatch):
    def handler(request):
        if "authorization" in request.headers:
            return httpx.Response(200, json={"private": "billing records"})
        return httpx.Response(200, json={"error": "login is required to continue"})

    ctx = exercise(
        AuthCompare(),
        tmp_path,
        monkeypatch,
        handler,
        PROFILES_FILE=write_profiles(tmp_path),
        COMPARE_PROFILES=["anonymous", "admin"],
    )
    assert not ctx.report["findings"]
    assert ctx.report["results"][0]["comparisons"][0]["similarity"] < 0.95


def test_auth_compare_requires_multiple_profiles(tmp_path, monkeypatch):
    calls = []
    with pytest.raises(ValueError, match="at least two"):
        exercise(AuthCompare(), tmp_path, monkeypatch, lambda req: calls.append(req))
    assert not calls


def test_header_review_context_and_cookie_value_redaction(tmp_path, monkeypatch):
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "set-cookie": "sid=super-private-cookie; Path=/; SameSite=None",
                "server": "Demo/1.2",
                "strict-transport-security": "max-age=0",
            },
            json={"ok": True},
        )

    ctx = exercise(HeaderReview(), tmp_path, monkeypatch, handler)
    kinds = {finding["kind"] for finding in ctx.report["findings"]}
    assert {"hsts_disabled", "cookie_attributes", "cookie_samesite_none"} <= kinds
    assert "csp_missing" not in kinds
    assert "framing_policy_missing" not in kinds
    assert "super-private-cookie" not in json.dumps(ctx.report["results"])
    saved = "".join(file.read_text() for file in ctx.store.root.rglob("*.json"))
    assert "super-private-cookie" not in saved


def test_header_review_honors_csp_framing_and_authenticated_cache(tmp_path, monkeypatch):
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "strict-transport-security": "max-age=31536000",
            },
            text="<h1>Account information</h1>",
        )

    ctx = exercise(
        HeaderReview(),
        tmp_path,
        monkeypatch,
        handler,
        PROFILES_FILE=write_profiles(tmp_path),
        PROFILE="user",
    )
    assert {finding["kind"] for finding in ctx.report["findings"]} == {"authenticated_cache_policy"}


def test_cors_reflection_checks_preflight_without_credentials(tmp_path, monkeypatch):
    preflight_calls = []

    def handler(request):
        headers = {
            "access-control-allow-origin": request.headers["origin"],
            "access-control-allow-credentials": "true",
            "access-control-allow-methods": "GET",
            "access-control-allow-headers": "authorization, content-type",
            "set-cookie": "sid=should-not-reach-preflight; Path=/",
            "vary": "Origin",
        }
        if request.method == "OPTIONS":
            preflight_calls.append(request)
            return httpx.Response(204, headers=headers)
        return httpx.Response(200, headers=headers, json={"private": "example"})

    ctx = exercise(
        CorsCheck(),
        tmp_path,
        monkeypatch,
        handler,
        PROFILES_FILE=write_profiles(tmp_path),
        PROFILE="user",
    )
    assert len(preflight_calls) == 3
    assert all(
        "cookie" not in req.headers and "authorization" not in req.headers
        for req in preflight_calls
    )
    assert any(f["kind"] == "cors_credentialed_origin" for f in ctx.report["findings"])
    assert all(record["preflight_allows_credentialed_request"] for record in ctx.report["results"])


def test_cors_wildcard_credentials_is_not_reported_as_data_exposure(tmp_path, monkeypatch):
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
            text="public",
        )

    ctx = exercise(CorsCheck(), tmp_path, monkeypatch, handler, ORIGINS=["null"])
    kinds = {finding["kind"] for finding in ctx.report["findings"]}
    assert "cors_invalid_wildcard_credentials" in kinds
    assert "cors_credentialed_origin" not in kinds


def test_cors_wildcard_never_covers_authorization_preflight_header():
    response = SimpleNamespace(
        headers={
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "*",
            "access-control-allow-headers": "*",
        }
    )
    policy = cors_policy(response, "https://fieldkit.invalid", "GET", ["Authorization"])
    assert policy["preflight_method_allowed"]
    assert not policy["preflight_headers_allowed"]


def test_cors_preflight_distinguishes_credentials_and_safelisted_methods():
    response = SimpleNamespace(
        headers={
            "access-control-allow-origin": "https://fieldkit.invalid",
            "access-control-allow-headers": "authorization",
        }
    )
    policy = cors_policy(response, "https://fieldkit.invalid", "GET", ["authorization"])
    assert policy["preflight_allows_uncredentialed_shape"]
    assert not policy["preflight_allows_credentialed_shape"]
    response.headers["access-control-allow-credentials"] = "true"
    policy = cors_policy(response, "https://fieldkit.invalid", "GET", ["authorization"])
    assert policy["preflight_allows_credentialed_shape"]
    policy = cors_policy(response, "https://fieldkit.invalid", "DELETE", ["authorization"])
    assert not policy["preflight_allows_credentialed_shape"]


def test_cookie_review_covers_redirects_and_ignores_deletion_flags(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path != "/finish":
            return httpx.Response(
                302,
                headers={
                    "location": "/finish",
                    "set-cookie": "sid=example-sid; Path=/",
                },
            )
        return httpx.Response(
            200,
            headers={
                "set-cookie": "deleted_cookie=; Path=/; Max-Age=0",
            },
            text="complete",
        )

    ctx = exercise(HeaderReview(), tmp_path, monkeypatch, handler)
    cookies = ctx.report["results"][0]["cookies"]
    assert {item["name"] for item in cookies} == {"sid", "deleted_cookie"}
    flag_findings = [f for f in ctx.report["findings"] if f["kind"] == "cookie_attributes"]
    assert {f["cookie_name"] for f in flag_findings} == {"sid"}


def write_sequence(tmp_path, **extra):
    path = tmp_path / "sequence.json"
    path.write_text(
        json.dumps(
            {
                "protected_url": "/account",
                "login": {
                    "url": "/login",
                    "data": {"username": "test-user", "pword": "test-password"},
                },
                "logout": {"url": "/logout"},
                "authenticated_contains": "Private account dashboard",
                **extra,
            }
        )
    )
    return str(path)


@pytest.mark.parametrize("revokes", [False, True])
def test_session_checks_rotation_and_replays_prelogout_snapshot(tmp_path, monkeypatch, revokes):
    active = {"authenticated-token"}
    calls = []

    def handler(request):
        calls.append((request.url.path, request.headers.get("cookie", "")))
        if request.url.path == "/login":
            return httpx.Response(
                200,
                headers={"set-cookie": "sid=authenticated-token; Path=/; Secure; HttpOnly"},
                text="logged in",
            )
        if request.url.path == "/logout":
            if revokes:
                active.clear()
            return httpx.Response(
                200, headers={"set-cookie": "sid=; Max-Age=0; Path=/"}, text="logged out"
            )
        if "sid=authenticated-token" in request.headers.get("cookie", "") and active:
            return httpx.Response(200, text="Private account dashboard")
        return httpx.Response(
            401, headers={"set-cookie": "sid=guest-token; Path=/"}, text="login required"
        )

    ctx = exercise(
        SessionCheck(),
        tmp_path,
        monkeypatch,
        handler,
        SEQUENCE_FILE=write_sequence(tmp_path),
        COOKIE_NAMES=["sid"],
    )
    sequence = ctx.report["results"][-1]
    assert sequence["authenticated_baseline_verified"]
    assert sequence["cookie_rotation"]["changed"] == ["sid"]
    assert sequence["review_session_invalidation"] is (not revokes)
    assert calls[-1] == ("/account", "sid=authenticated-token")
    assert not list(ctx.session("anonymous").cookies.jar)
    saved = "".join(file.read_text() for file in ctx.store.root.rglob("*.json"))
    assert "test-password" not in saved
    assert "authenticated-token" not in saved


def test_session_public_page_cannot_validate_authentication(tmp_path, monkeypatch):
    ctx = exercise(
        SessionCheck(),
        tmp_path,
        monkeypatch,
        lambda request: httpx.Response(200, text="Private account dashboard"),
        SEQUENCE_FILE=write_sequence(tmp_path),
    )
    sequence = ctx.report["results"][-1]
    assert not sequence["authenticated_baseline_verified"]
    assert not sequence["review_session_invalidation"]
    assert not any(f["kind"] == "session_replay_after_logout" for f in ctx.report["findings"])


def test_session_out_of_scope_sequence_rejected_before_requests(tmp_path, monkeypatch):
    calls = []
    with pytest.raises(ValueError, match="outside configured"):
        exercise(
            SessionCheck(),
            tmp_path,
            monkeypatch,
            lambda req: calls.append(req),
            SEQUENCE_FILE=write_sequence(tmp_path, logout={"url": "https://elsewhere.test/logout"}),
        )
    assert not calls


def test_session_failed_logout_does_not_create_invalidation_finding(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path == "/logout":
            return httpx.Response(500, text="failed")
        if request.url.path == "/login":
            return httpx.Response(200, headers={"set-cookie": "sid=logged-in; Path=/"})
        if "sid=logged-in" in request.headers.get("cookie", ""):
            return httpx.Response(200, text="Private account dashboard")
        return httpx.Response(401, text="login required")

    ctx = exercise(
        SessionCheck(), tmp_path, monkeypatch, handler, SEQUENCE_FILE=write_sequence(tmp_path)
    )
    assert ctx.report["results"][-1]["outcome"] == "logout_request_failed"
    assert not any(f["kind"] == "session_replay_after_logout" for f in ctx.report["findings"])


def test_profile_bearer_value_echo_is_redacted(tmp_path, monkeypatch):
    ctx = exercise(
        HeaderReview(),
        tmp_path,
        monkeypatch,
        lambda request: httpx.Response(200, json={"echo": "user-secret-example"}),
        PROFILES_FILE=write_profiles(tmp_path),
        PROFILE="user",
    )
    saved = "".join(file.read_text() for file in ctx.store.root.rglob("*.json"))
    assert "user-secret-example" not in saved


def test_transient_redirect_cookie_is_redacted(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path != "/finish":
            return httpx.Response(
                302,
                headers={
                    "location": "/finish",
                    "set-cookie": "sid=transient-redirect-secret; Path=/",
                },
            )
        return httpx.Response(
            200,
            headers={"set-cookie": "sid=; Max-Age=0; Path=/"},
            text="complete",
        )

    ctx = exercise(HeaderReview(), tmp_path, monkeypatch, handler)
    assert not list(ctx.session("anonymous").cookies.jar)
    saved = "".join(file.read_text() for file in ctx.store.root.rglob("*.json"))
    assert "transient-redirect-secret" not in saved


def test_profile_cookies_are_sent_to_ipv6_targets(tmp_path, monkeypatch):
    path = tmp_path / "ipv6-profiles.json"
    path.write_text(
        json.dumps(
            {
                "profiles": {
                    "user": {
                        "origins": ["http://[::1]"],
                        "cookies": {"sid": "ipv6-secret"},
                    }
                }
            }
        )
    )
    cookies = []

    def handler(request):
        cookies.append(request.headers.get("cookie", ""))
        return httpx.Response(200, text="example")

    exercise(
        HeaderReview(),
        tmp_path,
        monkeypatch,
        handler,
        TARGETS=["http://[::1]"],
        PROFILES_FILE=str(path),
        PROFILE="user",
    )
    assert cookies == ["sid=ipv6-secret"]


def test_auth_profiles_bound_to_other_origins_are_skipped(tmp_path, monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, text="example")

    ctx = exercise(
        AuthCompare(),
        tmp_path,
        monkeypatch,
        handler,
        TARGETS=["https://different.test"],
        PROFILES_FILE=write_profiles(tmp_path),
    )
    assert len(calls) == 1
    assert "authorization" not in calls[0].headers
    assert not ctx.report["errors"]
    assert ctx.report["results"][0]["profiles_outside_origin"] == ["user", "admin"]


def test_session_report_keeps_redacted_rotation_metadata(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path == "/login":
            return httpx.Response(200, headers={"set-cookie": "sid=new-session-value; Path=/"})
        if "sid=new-session-value" in request.headers.get("cookie", ""):
            return httpx.Response(200, text="Private account dashboard")
        return httpx.Response(401, headers={"set-cookie": "sid=old-session-value; Path=/"})

    ctx = exercise(
        SessionCheck(),
        tmp_path,
        monkeypatch,
        handler,
        SEQUENCE_FILE=write_sequence(tmp_path, logout=None),
        COOKIE_NAMES=["sid"],
    )
    saved_report = json.loads((ctx.store.root / "report.json").read_text())
    result = saved_report["results"][-1]
    assert result["cookie_rotation"]["changed"] == ["sid"]
    assert result["authenticated_baseline_verified"] is True
    assert "new-session-value" not in json.dumps(saved_report)
