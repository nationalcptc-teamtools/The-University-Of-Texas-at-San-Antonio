"""Inspect browser CORS policy semantics using controlled Origin headers."""

import re
import uuid
from urllib.parse import urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.http import origin
from fieldkit.core.module import Option
from fieldkit.modules.assessment_helpers import response_summary


def cors_policy(response, sent_origin, method, request_headers):
    headers = {key.lower(): value for key, value in response.headers.items()}
    allow_origin = headers.get("access-control-allow-origin", "").strip()
    credentials = headers.get("access-control-allow-credentials", "").strip() == "true"
    methods = {
        value.strip() for value in headers.get("access-control-allow-methods", "").split(",")
    }
    allowed_headers = {
        value.strip().lower()
        for value in headers.get("access-control-allow-headers", "").split(",")
    }
    matches = allow_origin == sent_origin
    # Fetch's CORS preflight algorithm permits safelisted methods even if absent
    # from Allow-Methods. Authorization must still appear explicitly in Allow-Headers.
    exact_method = method in {"GET", "HEAD", "POST"} or method in methods
    exact_headers = all(header.lower() in allowed_headers for header in request_headers)
    public_headers = all(
        header.lower() in allowed_headers
        or ("*" in allowed_headers and header.lower() != "authorization")
        for header in request_headers
    )
    return {
        "sent_origin": sent_origin,
        "allow_origin": allow_origin,
        "allow_credentials": credentials,
        "origin_matches": matches,
        "credentialed_origin_allowed": matches and credentials,
        "wildcard_with_credentials": allow_origin == "*" and credentials,
        "preflight_method_allowed": exact_method or ("*" in methods and not credentials),
        "preflight_headers_allowed": all(
            header.lower() in allowed_headers
            or ("*" in allowed_headers and not credentials and header.lower() != "authorization")
            for header in request_headers
        ),
        "preflight_allows_credentialed_shape": (
            matches and credentials and exact_method and exact_headers
        ),
        "preflight_allows_uncredentialed_shape": (
            (matches or allow_origin == "*") and (exact_method or "*" in methods) and public_headers
        ),
        "vary_origin": "origin"
        in {value.strip().lower() for value in headers.get("vary", "").split(",")},
    }


class CorsCheck(NetworkModule):
    name = "web/cors-check"
    description = "Review controlled cross-origin requests and browser preflight policy."
    options = COMMON_OPTIONS + (
        Option("ORIGINS", list, [], "Override controlled Origin values", "--origin"),
        Option(
            "PREFLIGHT_METHOD", str, "GET", "Method advertised in OPTIONS", "--preflight-method"
        ),
        Option(
            "PREFLIGHT_HEADERS",
            list,
            ["authorization", "content-type"],
            "Header advertised in OPTIONS (repeatable)",
            "--preflight-header",
        ),
    )

    def validate(self, settings):
        if not re.fullmatch(r"[A-Z]+", settings["PREFLIGHT_METHOD"]):
            raise ValueError("PREFLIGHT_METHOD must be an uppercase HTTP method")
        for name in settings["PREFLIGHT_HEADERS"]:
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ValueError("PREFLIGHT_HEADERS must contain valid HTTP header names")
        for value in settings["ORIGINS"]:
            if value == "null":
                continue
            parsed = urlsplit(value)
            try:
                _ = parsed.port
            except ValueError as exc:
                raise ValueError("ORIGINS must contain valid ports") from exc
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or any(character.isspace() for character in value)
            ):
                raise ValueError("ORIGINS must contain HTTP(S) origins or null")

    async def assess(self, ctx):
        method = ctx.settings["PREFLIGHT_METHOD"]
        requested_headers = ctx.settings["PREFLIGHT_HEADERS"]
        preflight_profile = f"cors-preflight-{uuid.uuid4().hex}"
        await ctx.clone_profile("anonymous", preflight_profile)
        for url in ctx.seed_urls():
            hostname = urlsplit(url).hostname or "target"
            suffix = re.sub(r"[^a-z0-9.-]", "-", hostname.lower())
            origins = ctx.settings["ORIGINS"] or [
                "https://fieldkit.invalid",
                "null",
                f"https://{suffix}.fieldkit.invalid",
            ]
            for controlled_origin in dict.fromkeys(origins):
                controlled_origin = controlled_origin.rstrip("/")
                response = await ctx.fetch(
                    url, headers={"Origin": controlled_origin}, follow_redirects=False
                )
                preflight_headers = {
                    "Origin": controlled_origin,
                    "Access-Control-Request-Method": method,
                }
                if requested_headers:
                    preflight_headers["Access-Control-Request-Headers"] = ", ".join(
                        requested_headers
                    )
                # Browser preflights do not carry cookies or HTTP authentication.
                ctx.session(preflight_profile).cookies.clear()
                preflight = await ctx.fetch(
                    url,
                    method="OPTIONS",
                    profile=preflight_profile,
                    headers=preflight_headers,
                    follow_redirects=False,
                )
                actual_policy = cors_policy(response, controlled_origin, method, requested_headers)
                options_policy = cors_policy(
                    preflight, controlled_origin, method, requested_headers
                )
                successful_options = bool(
                    not preflight.error
                    and preflight.status is not None
                    and 200 <= preflight.status < 300
                )
                ctx.add_endpoint(url, status=response.status)
                ctx.add_endpoint(url, method="OPTIONS", status=preflight.status)
                ctx.report["results"].append(
                    {
                        "url": url,
                        "actual": {**response_summary(response), **actual_policy},
                        "preflight": {**response_summary(preflight), **options_policy},
                        "preflight_allows_credentialed_request": (
                            successful_options
                            and options_policy["preflight_allows_credentialed_shape"]
                        ),
                        "preflight_allows_uncredentialed_request": (
                            successful_options
                            and options_policy["preflight_allows_uncredentialed_shape"]
                        ),
                    }
                )
                if response.error:
                    continue
                if (
                    actual_policy["credentialed_origin_allowed"]
                    and (controlled_origin == "null" or origin(controlled_origin) != origin(url))
                    and response.status is not None
                    and 200 <= response.status < 300
                ):
                    ctx.finding(
                        "cors_credentialed_origin",
                        "Controlled origin allowed with credentials",
                        url,
                        severity="medium",
                        evidence=[response.evidence_id, preflight.evidence_id],
                        origin=controlled_origin,
                        note=(
                            "Review sensitive content, preflight requirements, and browser cookie "
                            "policy. Header behavior alone does not prove cross-origin data access."
                        ),
                    )
                elif actual_policy["wildcard_with_credentials"]:
                    ctx.finding(
                        "cors_invalid_wildcard_credentials",
                        "Wildcard origin combined with credentials",
                        url,
                        evidence=[response.evidence_id],
                        note=(
                            "Browsers reject wildcard origins for credentialed response sharing; "
                            "this combination alone is not a credentialed CORS exposure."
                        ),
                    )
                if actual_policy["origin_matches"] and not actual_policy["vary_origin"]:
                    ctx.finding(
                        "cors_vary_origin",
                        "Origin-specific CORS response lacks Vary: Origin",
                        url,
                        evidence=[response.evidence_id],
                        note="Review cache behavior if this response varies by Origin.",
                    )
