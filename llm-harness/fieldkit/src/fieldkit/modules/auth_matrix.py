"""Explicit object/function authorization rules with resource-specific evidence."""

import copy
import hashlib
import json
from urllib.parse import parse_qsl, urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.core.redaction import SENSITIVE
from fieldkit.core.replay import bounded_json, execute_request, resolve_request, validate_request
from fieldkit.core.vault import Vault
from fieldkit.modules.assessment_helpers import looks_like_login, response_summary


def response_check(response, checks):
    """200 or similarity alone is never a positive resource access check."""
    if response.error or response.status is None or looks_like_login(response):
        return None
    if not isinstance(checks, dict) or not checks:
        return None
    statuses = checks.get("statuses", [200])
    if response.status not in statuses:
        return False
    outcomes = []
    if "contains" in checks:
        if not isinstance(checks["contains"], str) or not checks["contains"]:
            return None
        outcomes.append(checks["contains"].encode() in response.body)
    if "json_pointer" in checks and "equals" in checks:
        try:
            value = json.loads(response.body)
            for token in checks["json_pointer"].lstrip("/").split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                value = value[int(token)] if isinstance(value, list) else value[token]
            outcomes.append(value == checks["equals"])
        except (ValueError, KeyError, TypeError, IndexError, RecursionError):
            return None
    return all(outcomes) if outcomes else None


class AuthMatrix(NetworkModule):
    name = "web/auth-matrix"
    description = "Evaluate explicit identities, object/function requests and allow/deny rules."
    options = COMMON_OPTIONS + (
        Option("MATRIX_FILE", str, "", "Authorization matrix JSON", "--matrix-file"),
        Option(
            "MAX_REQUESTS",
            int,
            30,
            "Rules plus optional before/after check ceiling",
            "--max-requests",
        ),
    )

    def validate(self, settings):
        if not settings["MATRIX_FILE"] or settings["MAX_REQUESTS"] <= 0:
            raise ValueError("Supply --matrix-file and positive --max-requests")
        matrix = bounded_json(settings["MATRIX_FILE"], settings["MAX_BYTES"])
        if not isinstance(matrix, dict) or not isinstance(matrix.get("identities"), dict):
            raise ValueError("Matrix requires identities mapping identity -> profile")
        if not all(
            isinstance(k, str) and k and isinstance(v, str) and v
            for k, v in matrix["identities"].items()
        ):
            raise ValueError("Identities must map nonempty strings to profile names")
        resources = {}
        for collection, kind in (("objects", "object"), ("functions", "function")):
            items = matrix.get(collection, [])
            if not isinstance(items, list):
                raise ValueError("Matrix objects/functions must be lists")
            for item in items:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("id"), str)
                    or not item["id"]
                    or item["id"] in resources
                ):
                    raise ValueError("Matrix resource IDs must be unique nonempty strings")
                item = dict(item)
                if "request_id" in item:
                    if not settings["DATABASE"] or "request" in item:
                        raise ValueError("Vault request_id requires DATABASE and no inline request")
                    with Vault(settings["DATABASE"], create=False) as vault:
                        item["request"] = vault.request(str(item["request_id"]))
                item["request"] = validate_request(item.get("request"))
                reject_embedded_credentials(item["request"])
                item["kind"] = kind
                if kind == "object" and item.get("owner") not in matrix["identities"]:
                    raise ValueError("Known objects must declare an explicit owner identity")
                checks = item.get("checks", {})
                if (
                    isinstance(checks, dict)
                    and "contains" in checks
                    and (not isinstance(checks["contains"], str) or not checks["contains"])
                ):
                    raise ValueError("Resource contains checks must be nonempty strings")
                if not isinstance(checks, dict) or not (
                    isinstance(checks.get("contains"), str)
                    and checks["contains"]
                    or isinstance(checks.get("json_pointer"), str)
                    and checks["json_pointer"].startswith("/")
                    and "equals" in checks
                ):
                    raise ValueError(
                        "Resources require nonempty contains or json_pointer/equals checks"
                    )
                if not isinstance(checks.get("statuses", [200]), list) or any(
                    not isinstance(s, int) or not 100 <= s <= 599
                    for s in checks.get("statuses", [200])
                ):
                    raise ValueError("Resource check statuses must be HTTP status integers")
                state = item.get("state_check")
                if state is not None:
                    if (
                        not isinstance(state, dict)
                        or not isinstance(state.get("json_pointer"), str)
                        or not state["json_pointer"].startswith("/")
                    ):
                        raise ValueError("state_check requires request and /json_pointer")
                    state["request"] = validate_request(state.get("request"))
                    reject_embedded_credentials(state["request"])
                    if state["request"]["method"] != "GET":
                        raise ValueError("Before/after state checks must use explicit GET requests")
                resources[item["id"]] = item
        rules = matrix.get("rules")
        if not isinstance(rules, list) or not rules or len(rules) > settings["MAX_REQUESTS"]:
            raise ValueError("Matrix requires bounded explicit rules")
        seen = set()
        needed = len(rules)
        for number, rule in enumerate(rules, 1):
            if (
                not isinstance(rule, dict)
                or rule.get("identity") not in matrix["identities"]
                or rule.get("resource") not in resources
                or rule.get("expected") not in {"allow", "deny"}
            ):
                raise ValueError("Rule requires identity, resource and expected allow/deny")
            rule["id"] = str(rule.get("id", number))
            if rule["id"] in seen:
                raise ValueError("Rule IDs must be unique")
            seen.add(rule["id"])
            if not isinstance(rule.get("deny_statuses", [401, 403]), list) or any(
                not isinstance(s, int) or not 400 <= s <= 599
                for s in rule.get("deny_statuses", [401, 403])
            ):
                raise ValueError("deny_statuses must be HTTP error status integers")
            request = {
                **resources[rule["resource"]]["request"],
                "method": rule.get("method", resources[rule["resource"]]["request"]["method"]),
            }
            validate_request(request)
            needed += 2 if resources[rule["resource"]].get("state_check") else 0
        if needed > settings["MAX_REQUESTS"]:
            raise ValueError("Rules plus state checks exceed MAX_REQUESTS")
        self._matrix, self._resources = matrix, resources

    async def assess(self, ctx):
        prepared = []
        for rule in self._matrix["rules"]:
            resource = self._resources[rule["resource"]]
            profile = self._matrix["identities"][rule["identity"]]
            request = {
                **resource["request"],
                "method": rule.get("method", resource["request"]["method"]),
                "profile": profile,
                "id": rule["id"],
            }
            # Missing identities remain explicit inconclusive outcomes; no silent fallback.
            request = identity_request(ctx, request)
            if profile in ctx.profiles:
                request = resolve_request(ctx, request)
                state = resource.get("state_check")
                if state:
                    state_request = identity_request(ctx, {"profile": profile, **state["request"]})
                    # Validate URL scope even if the independent observer session is absent.
                    if state_request["profile"] not in ctx.profiles:
                        state_request["profile"] = profile
                    resolve_request(ctx, state_request)
            prepared.append((rule, resource, request, profile in ctx.profiles))
        records = []
        for rule, resource, request, available in prepared:
            record = {
                "kind": "auth_matrix",
                "rule_id": rule["id"],
                "identity": rule["identity"],
                "profile": request["profile"],
                "object_id": rule["resource"],
                "authorization_level": resource["kind"],
                "owner": resource.get("owner"),
                "method": request["method"],
                "url": request["url"],
                "expected": rule["expected"],
                "outcome": "inconclusive",
            }
            ctx.report["results"].append(record)
            if not available:
                record["detail"] = "Missing named session profile"
                continue
            state = resource.get("state_check")
            before = (
                await state_snapshot(ctx, state, request["profile"], "before") if state else None
            )
            response, _ = await execute_request(ctx, request, label="authorization-rule")
            check = response_check(response, resource["checks"])
            record.update(response=response_summary(response), resource_check=check)
            if state:
                after = await state_snapshot(ctx, state, request["profile"], "after")
                record["state_comparison"] = {
                    "before": before,
                    "after": after,
                    "outcome": "observed"
                    if before["fingerprint"] and after["fingerprint"]
                    else "inconclusive",
                    "changed": before["fingerprint"] != after["fingerprint"]
                    if before["fingerprint"] and after["fingerprint"]
                    else None,
                    "note": "Selected state difference is observed; concurrent changes and "
                    "authorization impact require review",
                }
            if response.error or check is None:
                record["detail"] = (
                    "Transport failure, login template, or unrecognized resource response"
                )
            elif check:
                record["outcome"] = (
                    "expected_allow"
                    if rule["expected"] == "allow"
                    else "unexpected_resource_access"
                )
            elif response.status in rule.get("deny_statuses", [401, 403]):
                record["outcome"] = (
                    "expected_deny" if rule["expected"] == "deny" else "unexpected_deny"
                )
            else:
                record["detail"] = (
                    "Resource check absent; status alone does not prove allowed/denied access"
                )
            records.append(record)
        for record in records:
            controls = [
                r
                for r in records
                if r["object_id"] == record["object_id"]
                and r["method"] == record["method"]
                and r["identity"] != record["identity"]
                and r["outcome"] == "expected_allow"
            ]
            record["control_rules"] = [r["rule_id"] for r in controls]
            if record["outcome"] == "unexpected_resource_access":
                evidence = [
                    record["response"]["evidence"],
                    *[r["response"]["evidence"] for r in controls],
                ]
                ctx.finding(
                    "authorization_rule_violation",
                    "Resource access violates explicit deny rule",
                    record["url"],
                    severity="medium",
                    confidence="confirmed" if controls else "observed",
                    evidence=evidence,
                    rule_id=record["rule_id"],
                    identity=record["identity"],
                    object_id=record["object_id"],
                    method=record["method"],
                    authorization_level=record["authorization_level"],
                    outcome="confirmed" if controls else "observed",
                    note="Resource-specific check and operator-supplied expected permissions; "
                    "no ID enumeration",
                )


async def state_snapshot(ctx, state, profile, label):
    if state["request"].get("profile", profile) not in ctx.profiles:
        return {"fingerprint": None, "error": "Missing state observer profile"}
    response, _ = await execute_request(
        ctx, identity_request(ctx, {"profile": profile, **state["request"]}), label="state-" + label
    )
    fingerprint = None
    if not response.error and response.status == 200 and not looks_like_login(response):
        try:
            value = json.loads(response.body)
            for token in state["json_pointer"][1:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                value = value[int(token)] if isinstance(value, list) else value[token]
            fingerprint = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
        except (ValueError, KeyError, TypeError, IndexError, RecursionError):
            pass
    return {
        **response_summary(response),
        "json_pointer": state["json_pointer"],
        "fingerprint": fingerprint,
    }


def identity_request(ctx, request):
    """Captured session credentials must not impersonate another matrix identity."""
    request = copy.deepcopy(request)
    profile_headers = {k.lower() for p in ctx.profiles.values() for k in p.headers}
    request["headers"] = {
        k: v
        for k, v in request.get("headers", {}).items()
        if not SENSITIVE.search(k) and k.lower() not in profile_headers
    }
    request.pop("cookies", None)
    return request


def reject_embedded_credentials(request):
    """Body/query session tokens cannot safely be reused across identities."""

    def visit(value):
        if isinstance(value, dict):
            for name, item in value.items():
                if (
                    SENSITIVE.search(str(name))
                    and isinstance(item, (str, int, float, bool))
                    and item
                ):
                    raise ValueError(
                        "Auth matrix body/query credentials must be supplied per "
                        "identity; use profile headers/cookies and sanitize templates"
                    )
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(dict(parse_qsl(urlsplit(request["url"]).query, keep_blank_values=True)))
    for key in ("query", "form", "json", "data"):
        visit(request.get(key))
