"""Compare explicitly supplied identities without inferring application roles."""

import math

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.http import origin
from fieldkit.core.module import Option
from fieldkit.modules.assessment_helpers import (
    comparable_content,
    response_similarity,
    response_summary,
)


class AuthCompare(NetworkModule):
    name = "web/auth-compare"
    description = "Compare endpoint responses across anonymous and named session profiles."
    options = COMMON_OPTIONS + (
        Option(
            "COMPARE_PROFILES",
            list,
            [],
            "Profile names to compare; default: all",
            "--compare-profile",
        ),
        Option(
            "REFERENCE_PROFILE", str, "", "Reference profile; default: last", "--reference-profile"
        ),
        Option("SIMILARITY", float, 0.95, "Similarity threshold from 0 to 1", "--similarity"),
    )

    def validate(self, settings):
        value = settings["SIMILARITY"]
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("SIMILARITY must be between 0 and 1")

    async def assess(self, ctx):
        names = list(dict.fromkeys(ctx.settings["COMPARE_PROFILES"] or ctx.profiles))
        if len(names) < 2:
            raise ValueError("auth-compare needs at least two profiles in --profiles-file")
        if any(name not in ctx.profiles for name in names):
            raise ValueError("Unknown comparison profile; check --profiles-file")
        reference = ctx.settings["REFERENCE_PROFILE"] or names[-1]
        if reference not in names:
            raise ValueError("REFERENCE_PROFILE must be one of the comparison profiles")
        # Each role uses a separate cookie jar. Do not infer privileges from a profile name.
        for url in ctx.seed_urls():
            responses = {}
            unavailable = []
            for name in names:
                profile = ctx.profiles[name]
                if profile.origins and origin(url) not in {
                    origin(base) for base in profile.origins
                }:
                    unavailable.append(name)
                    continue
                response = await ctx.fetch(url, profile=name)
                responses[name] = response
                ctx.add_endpoint(url, profile=name, status=response.status)
            control = responses.get(reference)
            comparisons = []
            for name, response in responses.items():
                if name == reference or control is None:
                    continue
                similarity = response_similarity(response, control)
                comparable = comparable_content(response, control)
                lead = comparable and similarity >= ctx.settings["SIMILARITY"]
                comparisons.append(
                    {
                        "profile": name,
                        "reference_profile": reference,
                        "similarity": similarity,
                        "comparable_content": comparable,
                        "review_access": lead,
                    }
                )
                if lead:
                    ctx.finding(
                        "auth_response_similarity",
                        "Similar successful content across session profiles",
                        url,
                        severity="low" if name == "anonymous" else "info",
                        evidence=[response.evidence_id, control.evidence_id],
                        profile=name,
                        reference_profile=reference,
                        similarity=similarity,
                        note=(
                            "Review the expected permissions and returned data. Public pages, "
                            "shared templates, and unrecognized login pages can match; this "
                            "does not establish an access-control vulnerability."
                        ),
                    )
            ctx.report["results"].append(
                {
                    "url": url,
                    "profiles": {
                        name: response_summary(value) for name, value in responses.items()
                    },
                    "comparisons": comparisons,
                    "profiles_outside_origin": unavailable,
                    "reference_available": control is not None,
                }
            )
