"""Inspect cookies and optionally execute an explicit login/logout test sequence."""

import json
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.modules.assessment_helpers import (
    comparable_content,
    response_similarity,
    response_summary,
    review_cookies,
    successful_content,
)


def load_sequence(filename):
    if not filename:
        return None
    try:
        sequence = json.loads(Path(filename).expanduser().read_text())
    except (OSError, ValueError) as exc:
        raise ValueError("Cannot read a valid session sequence JSON file") from exc
    if not isinstance(sequence, dict) or not isinstance(sequence.get("protected_url"), str):
        raise ValueError("Session sequence requires a protected_url string")
    if not sequence["protected_url"]:
        raise ValueError("Session sequence protected_url cannot be empty")
    if not any(sequence.get(step) for step in ("login", "logout")):
        raise ValueError("Session sequence requires login or logout")
    if "authenticated_contains" in sequence and (
        not isinstance(sequence["authenticated_contains"], str)
        or not sequence["authenticated_contains"]
    ):
        raise ValueError("authenticated_contains must be a nonempty string")
    for step in ("login", "logout"):
        request = sequence.get(step)
        if request is None:
            continue
        if not isinstance(request, dict) or not isinstance(request.get("url"), str):
            raise ValueError(f"Session {step} requires a URL string")
        if not request["url"]:
            raise ValueError(f"Session {step} URL cannot be empty")
        if request.get("method", "POST") not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError(f"Session {step} method is invalid")
        headers = request.get("headers", {})
        if not isinstance(headers, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in headers.items()
        ):
            raise ValueError(f"Session {step} headers must map strings to strings")
        if any("\r" in key + value or "\n" in key + value for key, value in headers.items()):
            raise ValueError(f"Session {step} headers cannot contain newlines")
        if any(key.lower() == "host" for key in headers):
            raise ValueError("Session requests do not support Host overrides")
        data = request.get("data")
        if data is not None and not isinstance(data, (str, dict)):
            raise ValueError(f"Session {step} data must be a form object or string")
        if isinstance(data, dict) and not all(
            isinstance(key, str) and isinstance(value, (str, int, float, bool))
            for key, value in data.items()
        ):
            raise ValueError(f"Session {step} form fields must have scalar values")
    return sequence


def cookie_state(client):
    """Keep values only in memory to compare rotation; reports receive names only."""
    return {(item.domain, item.path, item.name): item.value for item in client.cookies.jar}


class SessionCheck(NetworkModule):
    name = "web/session-check"
    description = "Inspect cookie flags and optionally test explicit login/logout sequences."
    options = COMMON_OPTIONS + (
        Option("SEQUENCE_FILE", str, "", "Explicit login/logout request JSON", "--sequence-file"),
        Option(
            "COOKIE_NAMES",
            list,
            [],
            "Known session cookie name for rotation checks (repeatable)",
            "--cookie-name",
        ),
    )

    def validate(self, settings):
        # Do not copy request credentials into settings: settings are written to the report.
        self._sequence = load_sequence(settings["SEQUENCE_FILE"])

    async def assess(self, ctx):
        sequence = getattr(self, "_sequence", None)
        sequence_urls = {}
        if sequence:
            # Sequence files contain explicitly supplied login material. Register all form
            # values, not just conventional password field names, for evidence redaction.
            for step in ("login", "logout"):
                request = sequence.get(step) or {}
                data = request.get("data")
                if isinstance(data, dict):
                    ctx.secrets.extend(str(value) for value in data.values())
                elif isinstance(data, str):
                    ctx.secrets.append(data)
                    try:
                        parsed = json.loads(data)
                    except ValueError:
                        from urllib.parse import parse_qsl

                        ctx.secrets.extend(value for _, value in parse_qsl(data))
                    else:

                        def register(value):
                            if isinstance(value, dict):
                                for item in value.values():
                                    register(item)
                            elif isinstance(value, list):
                                for item in value:
                                    register(item)
                            elif isinstance(value, str):
                                ctx.secrets.append(value)

                        register(parsed)
            # Validate every URL before the first request, including state-changing requests.
            for key, reference in [
                ("protected", sequence["protected_url"]),
                *(
                    (step, sequence[step]["url"])
                    for step in ("login", "logout")
                    if sequence.get(step)
                ),
            ]:
                if not urlsplit(reference).scheme and len(ctx.targets) != 1:
                    raise ValueError("Relative session sequence URLs require exactly one target")
                resolved = ctx.resolve(reference, ctx.targets[0])
                if not resolved:
                    raise ValueError("Session sequence URL is outside configured target scope")
                sequence_urls[key] = resolved
            sequence_origins = {
                (urlsplit(url).scheme, urlsplit(url).netloc) for url in sequence_urls.values()
            }
            if len(sequence_origins) != 1:
                raise ValueError("A session sequence must use a single origin")

        working = f"session-check-{uuid.uuid4().hex}"
        await ctx.clone_profile(ctx.settings["PROFILE"], working)
        for url in ctx.seed_urls():
            response = await ctx.fetch(url, profile=working)
            ctx.add_endpoint(url, status=response.status)
            ctx.report["results"].append(
                {**response_summary(response), "cookies": review_cookies(ctx, response)}
            )
        if not sequence:
            return

        protected_url = sequence_urls["protected"]
        anonymous = f"session-anonymous-{uuid.uuid4().hex}"
        await ctx.clone_profile("anonymous", anonymous)
        anonymous_response = await ctx.fetch(protected_url, profile=anonymous)
        before_response = await ctx.fetch(protected_url, profile=working)
        before_cookies = cookie_state(ctx.session(working))
        result = {
            "kind": "session_sequence",
            "url": protected_url,
            "anonymous": response_summary(anonymous_response),
            "before_login": response_summary(before_response),
        }

        async def execute(step):
            request = sequence[step]
            response = await ctx.fetch(
                sequence_urls[step],
                method=request.get("method", "POST"),
                headers=request.get("headers"),
                data=request.get("data"),
                profile=working,
            )
            ctx.add_endpoint(sequence_urls[step], method=request.get("method", "POST"))
            result[step] = response_summary(response)
            result[f"{step}_cookies"] = review_cookies(ctx, response)
            return response

        if sequence.get("login"):
            login_response = await execute("login")
            if (
                login_response.error
                or login_response.status is None
                or login_response.status >= 400
            ):
                result["outcome"] = "login_request_failed"
                ctx.report["results"].append(result)
                return
        authenticated = await ctx.fetch(protected_url, profile=working)
        after_cookies = cookie_state(ctx.session(working))
        marker = sequence.get("authenticated_contains")
        if marker:
            baseline_verified = (
                successful_content(authenticated) and marker.encode() in authenticated.body
            )
            # A public marker does not establish that the endpoint requires authentication.
            baseline_verified = baseline_verified and marker.encode() not in anonymous_response.body
        else:
            baseline_verified = successful_content(authenticated) and (
                not comparable_content(authenticated, anonymous_response)
                or response_similarity(authenticated, anonymous_response) < 0.95
            )
        if anonymous_response.error:
            baseline_verified = False
        result["authenticated"] = response_summary(authenticated)
        result["authenticated_baseline_verified"] = baseline_verified
        if sequence.get("login"):
            transition_verified = baseline_verified and (
                not successful_content(before_response)
                or (marker and marker.encode() not in before_response.body)
            )
            result["login_transition_verified"] = bool(transition_verified)
            considered = set(before_cookies) | set(after_cookies)
            if ctx.settings["COOKIE_NAMES"]:
                considered = {key for key in considered if key[2] in ctx.settings["COOKIE_NAMES"]}
            result["cookie_rotation"] = {
                "changed": sorted(
                    {
                        key[2]
                        for key in considered
                        if key in before_cookies
                        and key in after_cookies
                        and before_cookies[key] != after_cookies[key]
                    }
                ),
                "unchanged": sorted(
                    {
                        key[2]
                        for key in considered
                        if key in before_cookies
                        and key in after_cookies
                        and before_cookies[key] == after_cookies[key]
                    }
                ),
                "added": sorted({key[2] for key in considered if key not in before_cookies}),
                "removed": sorted({key[2] for key in considered if key not in after_cookies}),
            }
            if (
                transition_verified
                and ctx.settings["COOKIE_NAMES"]
                and result["cookie_rotation"]["unchanged"]
            ):
                ctx.finding(
                    "session_cookie_not_rotated",
                    "Selected session cookies did not change across login",
                    protected_url,
                    severity="low",
                    evidence=[before_response.evidence_id, authenticated.evidence_id],
                    cookies=result["cookie_rotation"]["unchanged"],
                    note=(
                        "Confirm these identify the authenticated session; "
                        "this alone does not prove fixation."
                    ),
                )
        if sequence.get("logout"):
            snapshot = f"session-replay-{uuid.uuid4().hex}"
            await ctx.clone_profile(working, snapshot)
            logout_response = await execute("logout")
            if (
                logout_response.error
                or logout_response.status is None
                or logout_response.status >= 400
            ):
                result["outcome"] = "logout_request_failed"
                ctx.report["results"].append(result)
                return
            replay = await ctx.fetch(protected_url, profile=snapshot)
            result["pre_logout_session_replay"] = response_summary(replay)
            similarity = response_similarity(authenticated, replay)
            replay_matches = (
                successful_content(replay) and marker.encode() in replay.body
                if marker
                else comparable_content(authenticated, replay) and similarity >= 0.95
            )
            result["replay_similarity"] = similarity
            result["review_session_invalidation"] = bool(baseline_verified and replay_matches)
            if result["review_session_invalidation"]:
                ctx.finding(
                    "session_replay_after_logout",
                    "Pre-logout credentials still return authenticated-looking content",
                    protected_url,
                    severity="medium",
                    evidence=[
                        authenticated.evidence_id,
                        logout_response.evidence_id,
                        replay.evidence_id,
                    ],
                    note=(
                        "Review server-side invalidation, bearer-token lifecycle, and expected "
                        "logout behavior. This test reuses an isolated snapshot of "
                        "pre-logout credentials."
                    ),
                )
        result["outcome"] = (
            "reviewed" if baseline_verified else "inconclusive_authentication_baseline"
        )
        ctx.report["results"].append(result)
