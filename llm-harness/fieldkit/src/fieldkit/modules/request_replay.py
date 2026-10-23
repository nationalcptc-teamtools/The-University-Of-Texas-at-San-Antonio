"""Explicit request replay and evidence-backed baseline/control comparison."""

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.core.replay import (
    bounded_json,
    edit_request,
    execute_request,
    load_requests,
    resolve_request,
    select_requests,
)
from fieldkit.modules.assessment_helpers import response_similarity, response_summary

REPLAY_OPTIONS = (
    Option("REQUESTS_FILE", str, "", "JSON templates or raw HTTP file", "--requests-file"),
    Option("REQUEST_IDS", list, [], "Explicit request ID/index (repeat)", "--request-id"),
    Option("RAW", bool, False, "Read raw HTTP request instead of JSON", "--raw"),
    Option("RAW_URL", str, "", "Origin for relative raw requests", "--raw-url"),
    Option(
        "EDITS_FILE",
        str,
        "",
        "JSON [{location,value}] applied to selected requests",
        "--edits-file",
    ),
    Option("CONTROL_FILE", str, "", "JSON request controls with matching IDs", "--control-file"),
    Option("MAX_REQUESTS", int, 30, "Maximum total requests including controls", "--max-requests"),
)


class RequestReplay(NetworkModule):
    name = "web/request-replay"
    description = "Execute explicitly selected requests with optional edits and controls."
    options = COMMON_OPTIONS + REPLAY_OPTIONS

    def validate(self, settings):
        if (
            not (settings["REQUESTS_FILE"] or settings.get("DATABASE"))
            or settings["MAX_REQUESTS"] <= 0
        ):
            raise ValueError("Supply --requests-file or --database and positive --max-requests")
        if settings["REQUESTS_FILE"]:
            records = load_requests(
                settings["REQUESTS_FILE"],
                raw=settings["RAW"],
                base=settings["RAW_URL"],
                max_bytes=settings["MAX_BYTES"],
            )
        else:
            from fieldkit.core.vault import Vault

            with Vault(settings["DATABASE"], create=False) as vault:
                records = [vault.request(name) for name in settings["REQUEST_IDS"]]
        self._requests = select_requests(
            records,
            settings["REQUEST_IDS"],
        )
        self._controls = {}
        if settings["CONTROL_FILE"]:
            controls = load_requests(settings["CONTROL_FILE"], max_bytes=settings["MAX_BYTES"])
            self._controls = {r["id"]: r for r in controls}
        self._edits = bounded_json(settings["EDITS_FILE"]) if settings["EDITS_FILE"] else []
        if not isinstance(self._edits, list) or any(
            not isinstance(e, dict) or not isinstance(e.get("location"), str) or "value" not in e
            for e in self._edits
        ):
            raise ValueError("Edits require a list of location/value objects")
        needed = len(self._requests) * (2 if self._edits else 1) + sum(
            r["id"] in self._controls for r in self._requests
        )
        if needed > settings["MAX_REQUESTS"]:
            raise ValueError("Selected requests, baselines and controls exceed MAX_REQUESTS")

    def prepared(self, ctx):
        requests = []
        for request in self._requests:
            base = resolve_request(ctx, request)
            edited = request
            for change in self._edits:
                edited = edit_request(edited, change["location"], change["value"])
            edited = resolve_request(ctx, edited)
            control = self._controls.get(request["id"])
            control = resolve_request(ctx, control) if control else None
            requests.append((base, edited, control))
        return requests

    async def assess(self, ctx):
        # Resolve all selected requests/edits before the first operation executes.
        for baseline, edited, control in self.prepared(ctx):
            response, _ = await execute_request(ctx, baseline, label="baseline")
            result = {
                "kind": "request_replay",
                "request_id": baseline["id"],
                "url": baseline["url"],
                "method": baseline["method"],
                "baseline": response_summary(response),
            }
            ctx.report["results"].append(result)
            compared = response
            if self._edits:
                compared, _ = await execute_request(ctx, edited, label="edited")
                result["edited"] = response_summary(compared)
                result["baseline_similarity"] = response_similarity(response, compared)
            if control:
                control_response, _ = await execute_request(ctx, control, label="control")
                result["control"] = response_summary(control_response)
                result["control_similarity"] = response_similarity(compared, control_response)
            result["outcome"] = "inconclusive" if response.error or compared.error else "observed"
            ctx.add_endpoint(baseline["url"], baseline["method"], source="explicit_request")
