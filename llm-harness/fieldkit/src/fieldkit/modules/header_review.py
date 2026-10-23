"""Contextual review of response security headers, cache policy, and cookies."""

from urllib.parse import urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.modules.assessment_helpers import response_summary, review_cookies


class HeaderReview(NetworkModule):
    name = "web/header-review"
    description = "Review security headers, cookie flags, cache controls, and disclosures."
    options = COMMON_OPTIONS

    async def assess(self, ctx):
        for url in ctx.seed_urls():
            response = await ctx.fetch(url)
            ctx.add_endpoint(url, status=response.status)
            result = response_summary(response)
            if response.error:
                ctx.report["results"].append(result)
                continue
            headers = {key.lower(): value for key, value in response.headers.items()}
            result["cookies"] = review_cookies(ctx, response)
            relevant = (
                "content-security-policy",
                "content-security-policy-report-only",
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "cache-control",
                "server",
                "x-powered-by",
            )
            result["headers"] = {key: headers[key] for key in relevant if key in headers}
            evidence = [response.evidence_id]

            def finding(kind, title, url=response.url, evidence=evidence, **details):
                ctx.finding(kind, title, url, evidence=evidence, **details)

            if urlsplit(response.url).scheme == "https":
                hsts = headers.get("strict-transport-security", "")
                if not hsts:
                    finding("hsts_missing", "HTTPS response has no HSTS header")
                elif any(part.strip().lower() == "max-age=0" for part in hsts.split(";")):
                    finding("hsts_disabled", "HSTS max-age is zero")
            if headers.get("x-content-type-options", "").lower().strip() != "nosniff":
                finding(
                    "nosniff_missing", "Response does not enable X-Content-Type-Options: nosniff"
                )
            is_document = "html" in response.content_type.lower()
            if is_document and response.status is not None and 200 <= response.status < 300:
                csp = headers.get("content-security-policy", "")
                directives = {
                    parts[0].lower(): parts[1:]
                    for item in csp.split(";")
                    if (parts := item.split())
                }
                if not csp:
                    finding(
                        "csp_missing",
                        "HTML document has no enforced Content-Security-Policy",
                        note="A report-only policy does not enforce restrictions.",
                    )
                elif "'unsafe-eval'" in directives.get(
                    "script-src", directives.get("default-src", [])
                ):
                    finding("csp_unsafe_eval", "Content-Security-Policy allows unsafe-eval")
                if "frame-ancestors" not in directives and headers.get(
                    "x-frame-options", ""
                ).strip().lower() not in {"deny", "sameorigin"}:
                    finding(
                        "framing_policy_missing",
                        "HTML document has no recognized anti-framing policy",
                        note="Review whether the page contains sensitive interactive actions.",
                    )
                if not headers.get("referrer-policy"):
                    finding(
                        "referrer_policy_missing",
                        "HTML document relies on the browser's default referrer policy",
                    )
            for header in ("server", "x-powered-by"):
                if headers.get(header):
                    finding(
                        "technology_disclosure",
                        "Response discloses server technology",
                        header=header,
                        value=headers[header],
                        note="A disclosed product or version is not proof of a vulnerability.",
                    )
            if (
                ctx.settings["PROFILE"] != "anonymous"
                and response.status is not None
                and 200 <= response.status < 300
                and (is_document or "json" in response.content_type.lower())
            ):
                cache_directives = {
                    part.split("=", 1)[0].strip().lower()
                    for part in headers.get("cache-control", "").split(",")
                }
                if not cache_directives & {"private", "no-store"}:
                    finding(
                        "authenticated_cache_policy",
                        "Authenticated response lacks private or no-store cache control",
                        severity="low",
                        note=(
                            "Confirm the response contains private data and inspect intermediary "
                            "caching behavior before treating this as exposure."
                        ),
                    )
            ctx.report["results"].append(result)
