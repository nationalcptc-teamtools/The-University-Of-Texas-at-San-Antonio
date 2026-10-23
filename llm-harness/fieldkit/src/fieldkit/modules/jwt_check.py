"""Private-input JWT review and explicitly controlled protected-resource checks."""

import asyncio
import copy
import json
import re
import time
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit

import httpx

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.http import origin
from fieldkit.core.jwt import (
    JWTError,
    invalid_signature,
    json_object,
    load_key,
    modified,
    parse,
    read_file,
)
from fieldkit.core.module import Option
from fieldkit.core.profiles import jar_cookie, load_profiles
from fieldkit.core.replay import (
    execute_request,
    raw_request,
    register_request_secrets,
    select_requests,
    validate_request,
)
from fieldkit.core.targets import read_targets, target_urls
from fieldkit.core.urls import normalize_url, resolve_url
from fieldkit.core.vault import Vault
from fieldkit.modules.assessment_helpers import looks_like_login, response_summary

TESTS = {"signature", "none", "expired", "issuer", "audience", "claims"}
MISSING = object()


def pointer_parts(pointer):
    if (
        not isinstance(pointer, str)
        or not pointer.startswith("/")
        or re.search(r"~(?![01])", pointer)
    ):
        raise JWTError("JWT JSON locations require an RFC 6901 /pointer")
    if len(pointer) > 512:
        raise JWTError("JWT JSON pointer exceeds its limit")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def at_pointer(document, pointer, *, replace=MISSING, remove=False):
    parent = document
    parts = pointer_parts(pointer)
    try:
        for part in parts[:-1]:
            if isinstance(parent, list) and not re.fullmatch(r"0|[1-9][0-9]*", part):
                raise ValueError
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        if isinstance(parent, list) and not re.fullmatch(r"0|[1-9][0-9]*", parts[-1]):
            raise ValueError
        last = int(parts[-1]) if isinstance(parent, list) else parts[-1]
        value = parent[last]
        if remove:
            del parent[last]
        elif replace is not MISSING:
            parent[last] = replace
        return value
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise JWTError("Selected JWT JSON location does not exist") from exc


def private_json(filename, maximum=65536):
    return json_object(read_file(filename, maximum, private=True))


def private_values(value):
    if isinstance(value, dict):
        return [item for child in value.values() for item in private_values(child)]
    if isinstance(value, list):
        return [item for child in value for item in private_values(child)]
    return [str(value)] if value is not None else []


def validate_checks(checks):
    if not isinstance(checks, dict) or set(checks) - {"status", "identity", "resource"}:
        raise JWTError("Response checks support status, identity and resource assertions")
    if type(checks.get("status", 200)) is not int or not 200 <= checks.get("status", 200) < 300:
        raise JWTError("Protected response status must be a successful HTTP status integer")
    count = 0
    for category in ("identity", "resource"):
        records = checks.get(category, [])
        if not isinstance(records, list) or len(records) > 8:
            raise JWTError("Identity/resource assertions must be bounded lists")
        for record in records:
            if not isinstance(record, dict):
                raise JWTError("Identity/resource assertions must be objects")
            if set(record) == {"pointer", "equals"}:
                pointer_parts(record["pointer"])
                if isinstance(record["equals"], (dict, list)) or record["equals"] is None:
                    raise JWTError("Response JSON assertions require a non-null scalar equals")
            elif set(record) == {"contains"}:
                if (
                    not isinstance(record["contains"], str)
                    or not 1 <= len(record["contains"]) <= 512
                ):
                    raise JWTError("Response text assertions require bounded nonempty contains")
            else:
                raise JWTError("Assertions require pointer/equals or contains")
            count += 1
    if not count:
        raise JWTError("A protected baseline requires identity or resource assertions")


def check_response(response, checks):
    if response.error or response.status is None or looks_like_login(response):
        return None
    if response.status != checks.get("status", 200):
        return False
    document = None
    for category in ("identity", "resource"):
        for record in checks.get(category, []):
            if "contains" in record:
                if record["contains"].encode() not in response.body:
                    return False
            else:
                try:
                    if document is None:
                        document = json_object(response.body[:131073])
                    if len(response.body) > 131072:
                        return None
                    actual = at_pointer(document, record["pointer"])
                    expected = record["equals"]
                    if type(actual) is not type(expected) or actual != expected:
                        return False
                except JWTError:
                    return False
    return True


def flatten_request(request, profiles, default_profile):
    """Freeze effective credentials before mutation and use a fresh anonymous transport."""
    request = copy.deepcopy(request)
    name = request.get("profile", default_profile)
    if name not in profiles:
        raise JWTError("Selected JWT request names an unknown session profile")
    profile = profiles[name]
    if (profile.headers or profile.cookies or profile.cookie_jar or profile.origins) and origin(
        request["url"]
    ) not in {origin(value) for value in profile.origins}:
        raise JWTError("Selected JWT profile does not authorize the request origin")
    headers = httpx.Headers(profile.headers)
    headers.update(request.get("headers", {}))
    if request.get("cookies"):
        cookie = SimpleCookie()
        for key, value in request["cookies"].items():
            cookie[key] = value
        headers["Cookie"] = "; ".join(item.OutputString() for item in cookie.values())
    elif "cookie" not in headers:
        jar = httpx.Cookies()
        for record in profile.cookie_jar:
            jar.jar.set_cookie(jar_cookie(record))
        host = urlsplit(request["url"]).hostname
        if host and ":" in host:
            host = f"[{host}]"
        host = host + ".local" if host and "." not in host else host
        for key, value in profile.cookies.items():
            jar.set(key, value, domain=host, path="/")
        cookie = httpx.Request("GET", request["url"], cookies=jar).headers.get("cookie")
        if cookie:
            headers["Cookie"] = cookie
    request["headers"] = dict(headers)
    request.pop("cookies", None)
    request["profile"] = "anonymous"
    return validate_request(request)


def token_position(request, location, *, replacement=MISSING, remove=False, allow_add=False):
    """Read/edit one exact credential position while preserving its wire encoding."""
    kind, separator, name = location.partition(":")
    if not separator or not name or kind not in {"header", "cookie", "form", "json"}:
        raise JWTError("TOKEN_LOCATION must select header, cookie, form or json:/pointer")
    changed = copy.deepcopy(request)
    if kind == "header":
        headers = changed.setdefault("headers", {})
        keys = [key for key in headers if key.lower() == name.lower()]
        if len(keys) > 1:
            raise JWTError("Selected JWT header is ambiguous")
        if not keys and not allow_add:
            raise JWTError("Selected JWT header does not exist")
        key = keys[0] if keys else name
        value = headers.get(key, "Bearer " if name.lower() == "authorization" else "")
        prefix = "Bearer " if value.lower().startswith("bearer ") else ""
        compact = value[len(prefix) :]
        if remove:
            headers.pop(key, None)
        elif replacement is not MISSING:
            headers[key] = prefix + replacement
    elif kind == "cookie":
        headers = changed.setdefault("headers", {})
        key = next((key for key in headers if key.lower() == "cookie"), "Cookie")
        raw = headers.get(key, "")
        names = [part.strip().partition("=")[0] for part in raw.split(";") if part.strip()]
        if len(names) != len(set(names)):
            raise JWTError("Selected JWT cookies are ambiguous")
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError as exc:
            raise JWTError("Selected JWT Cookie header is malformed") from exc
        if name not in cookie:
            raise JWTError("Selected JWT cookie does not exist")
        compact = cookie[name].value
        if remove:
            del cookie[name]
        elif replacement is not MISSING:
            cookie[name] = replacement
        if cookie:
            headers[key] = "; ".join(item.OutputString() for item in cookie.values())
        else:
            headers.pop(key, None)
    elif kind == "form":
        key = "form" if "form" in changed else "data"
        form = changed.get(key)
        if not isinstance(form, dict) or name not in form:
            raise JWTError("Selected JWT form field does not exist")
        compact = form[name]
        if remove:
            del form[name]
        elif replacement is not MISSING:
            form[name] = replacement
    else:
        if "json" not in changed:
            raise JWTError("Selected JWT request has no JSON body")
        compact = at_pointer(changed["json"], name, replace=replacement, remove=remove)
    if not isinstance(compact, str):
        raise JWTError("Selected JWT credential must be a string")
    return compact, validate_request(changed)


class JWTCheck(NetworkModule):
    name = "web/jwt-check"
    description = "Review private JWTs offline or test explicitly selected protected requests."
    requires_targets = False
    options = tuple(
        Option(o.name, o.kind, 0, o.description, o.flag) if o.name == "RETRIES" else o
        for o in COMMON_OPTIONS
    ) + (
        Option("REQUESTS_FILE", str, "", "Private JSON or raw saved requests", "--requests-file"),
        Option("REQUEST_IDS", list, [], "Explicit saved request ID (repeat)", "--request-id"),
        Option("RAW", bool, False, "Read a raw HTTP request", "--raw"),
        Option("RAW_URL", str, "", "Explicit origin for a relative raw request", "--raw-url"),
        Option(
            "TOKEN_LOCATION", str, "header:Authorization", "Exact token field", "--token-location"
        ),
        Option("TOKEN_FILE", str, "", "Owner-only compact JWT file", "--token-file"),
        Option(
            "KEY_FILE", str, "", "Owner-only HMAC or PEM verification/signing key", "--key-file"
        ),
        Option("KEY_ALGORITHM", str, "", "Explicit trusted key algorithm", "--key-algorithm"),
        Option(
            "EXPECT_FILE",
            str,
            "",
            "Private issuer/audience and response assertions",
            "--expect-file",
        ),
        Option(
            "CLAIMS_FILE",
            str,
            "",
            "Private JSON mapping selected claim replacements",
            "--claims-file",
        ),
        Option(
            "TESTS",
            list,
            [],
            "Explicit signature, none, expired, issuer, audience, claims",
            "--test",
        ),
        Option("ACTIVE", bool, False, "Enable controlled HTTP JWT validation tests", "--active"),
        Option(
            "CONFIRM_ACTIVE", bool, False, "Authorize selected live JWT probes", "--confirm-active"
        ),
        Option(
            "MAX_REQUESTS",
            int,
            12,
            "Total requests including repeated baselines and controls",
            "--max-requests",
        ),
        Option("MAX_TOKEN_BYTES", int, 16384, "JWT byte ceiling (1-65536)", "--max-token-bytes"),
    )

    def validate(self, settings):
        if not 1 <= settings["MAX_TOKEN_BYTES"] <= 65536:
            raise JWTError("MAX_TOKEN_BYTES must be between 1 and 65536")
        self._maximum = settings["MAX_TOKEN_BYTES"]
        if not 1 <= settings["MAX_REQUESTS"] <= 1000:
            raise JWTError("MAX_REQUESTS must be between 1 and 1000")
        if settings["RETRIES"] != 0:
            raise JWTError("JWT checks require RETRIES=0 for exact request accounting")
        if not isinstance(settings["TESTS"], list) or any(
            not isinstance(test, str) or test not in TESTS for test in settings["TESTS"]
        ):
            raise JWTError("TESTS contains an unsupported JWT test")
        self._tests = list(dict.fromkeys(settings["TESTS"]))
        self._expect = private_json(settings["EXPECT_FILE"]) if settings["EXPECT_FILE"] else {}
        if set(self._expect) - {"issuer", "audience", "baseline", "probes", "claims_policy"}:
            raise JWTError("EXPECT_FILE contains unsupported assertion or policy members")
        if not isinstance(self._expect.get("claims_policy", "observe"), str) or self._expect.get(
            "claims_policy", "observe"
        ) not in {"observe", "deny"}:
            raise JWTError("claims_policy must be observe or an explicit operator deny policy")
        for key in ("issuer", "audience"):
            if key in self._expect and (
                not isinstance(self._expect[key], str) or not 1 <= len(self._expect[key]) <= 1024
            ):
                raise JWTError("Expected issuer/audience must be bounded nonempty strings")
        probes = self._expect.get("probes", {})
        if not isinstance(probes, dict) or set(probes) - TESTS:
            raise JWTError("Probe assertions require supported JWT test names")
        for checks in [
            *probes.values(),
            *([self._expect["baseline"]] if "baseline" in self._expect else []),
        ]:
            validate_checks(checks)
        self._claims = private_json(settings["CLAIMS_FILE"]) if settings["CLAIMS_FILE"] else {}
        if len(self._claims) > 16 or any(not key or len(key) > 128 for key in self._claims):
            raise JWTError("Selected claim replacements exceed their claim/name limit")
        self._key = (
            load_key(settings["KEY_FILE"], settings["KEY_ALGORITHM"])
            if settings["KEY_FILE"]
            else None
        )
        if settings["KEY_ALGORITHM"] and not self._key:
            raise JWTError("KEY_ALGORITHM requires KEY_FILE")
        token = None
        if settings["TOKEN_FILE"]:
            try:
                token = (
                    read_file(settings["TOKEN_FILE"], settings["MAX_TOKEN_BYTES"] + 2, private=True)
                    .decode("ascii")
                    .strip()
                )
            except UnicodeError as exc:
                raise JWTError("JWT token file must contain ASCII compact JWT text") from exc
            parse(token, settings["MAX_TOKEN_BYTES"])
        if settings["PROFILES_FILE"]:
            read_file(settings["PROFILES_FILE"], 1048576, private=True)
        profiles = load_profiles(settings["PROFILES_FILE"])
        scopes = []
        if settings["TARGETS"] or settings["TARGETS_FILE"]:
            for target in read_targets(settings["TARGETS"], settings["TARGETS_FILE"]):
                if "://" not in target:
                    raise JWTError("JWT request scope requires explicit HTTP(S) origin schemes")
                scopes.extend(target_urls(target, settings["SCHEME"]))
        self._scopes = list(dict.fromkeys(scopes))
        records = []
        if settings["REQUESTS_FILE"]:
            content = read_file(
                settings["REQUESTS_FILE"], min(settings["MAX_BYTES"], 1048576), private=True
            )
            if settings["RAW"]:
                records = [raw_request(content, settings["RAW_URL"])]
            else:
                try:
                    value = json.loads(content)
                except (ValueError, UnicodeError, RecursionError) as exc:
                    raise JWTError("Saved JWT requests must contain valid JSON") from exc
                records = value.get("requests", [value]) if isinstance(value, dict) else value
                if not isinstance(records, list) or not 1 <= len(records) <= 1000:
                    raise JWTError("Saved JWT requests require a bounded request list")
                records = [
                    dict(validate_request(record), id=str(record.get("id", index)))
                    for index, record in enumerate(records, 1)
                ]
                if len({record["id"] for record in records}) != len(records):
                    raise JWTError("Saved JWT request IDs must be unique")
        elif settings["DATABASE"] and settings["REQUEST_IDS"]:
            with Vault(settings["DATABASE"], create=False) as vault:
                records = [vault.request(name) for name in settings["REQUEST_IDS"]]
        if records:
            records = select_requests(records, settings["REQUEST_IDS"])
        elif not token:
            raise JWTError("Select TOKEN_FILE or explicit saved/vault request IDs")
        if settings["ACTIVE"]:
            if not records or not scopes or not self._tests:
                raise JWTError(
                    "Active JWT checks require saved requests, explicit origins and TESTS"
                )
            if not settings["CONFIRM_ACTIVE"] and not settings["DRY_RUN"]:
                raise JWTError("Active JWT checks require CONFIRM_ACTIVE; use DRY_RUN to plan")
            if "baseline" not in self._expect:
                raise JWTError(
                    "Active JWT checks require EXPECT_FILE protected baseline assertions"
                )
            if len(records) * (5 + len(self._tests)) > settings["MAX_REQUESTS"]:
                raise JWTError(
                    "Selected JWT probes, repeated baselines and controls exceed MAX_REQUESTS"
                )
        self._prepared = []
        self._secrets = private_values(
            {key: value for key, value in self._expect.items() if key != "claims_policy"}
        ) + private_values(self._claims)
        for record in records:
            if scopes:
                if not urlsplit(record["url"]).scheme and len(scopes) != 1:
                    raise JWTError("Relative JWT requests require exactly one explicit origin")
                resolved = resolve_url(record["url"], scopes[0], scopes)
                if not resolved:
                    raise JWTError("Selected JWT request leaves explicit target scope")
                record = {**record, "url": resolved}
            else:
                record = {**record, "url": normalize_url(record["url"])}
            request = flatten_request(record, profiles, settings["PROFILE"])
            if token is not None:
                _, request = token_position(
                    request, settings["TOKEN_LOCATION"], replacement=token, allow_add=True
                )
            compact, _ = token_position(request, settings["TOKEN_LOCATION"])
            parsed = parse(compact, settings["MAX_TOKEN_BYTES"])
            self._prepared.append((request, parsed))
        if not records:
            self._prepared.append((None, parse(token, settings["MAX_TOKEN_BYTES"])))
        self._probe_tokens = []
        for _request, parsed in self._prepared:
            self._secrets.extend([parsed.compact, *private_values(parsed.claims)])
            self._probe_tokens.append(self.make_probes(parsed) if settings["ACTIVE"] else {})
            for value in self._probe_tokens[-1].values():
                self._secrets.extend([value, *private_values(parse(value, self._maximum).claims)])

    def make_probes(self, token):
        probes = {}
        for test in self._tests:
            if test == "signature":
                probes[test] = invalid_signature(token)
            elif test == "none":
                if token.algorithm == "none":
                    raise JWTError("Algorithm-none test requires a signed baseline JWT")
                probes[test] = modified(token, unsigned=True)
            else:
                if not self._key or not self._key.can_sign or self._key.verify(token) != "verified":
                    raise JWTError(
                        "Claim probes require a verified baseline and matching signing key"
                    )
                claims = copy.deepcopy(token.claims)
                if test == "expired":
                    if token.summary()["expiration"] != "future":
                        raise JWTError(
                            "Expiration test requires a currently unexpired baseline JWT"
                        )
                    # Ordinary JWT validators allow a few minutes of clock skew.
                    claims["exp"] = int(time.time()) - 86400
                elif test in {"issuer", "audience"}:
                    key = "iss" if test == "issuer" else "aud"
                    if (
                        token.summary(
                            self._expect.get("issuer", ""), self._expect.get("audience", "")
                        )[test]
                        != "match"
                    ):
                        raise JWTError(
                            "Issuer/audience tests require a matching private expected value"
                        )
                    claims[key] = "fieldkit-invalid-" + test
                    if claims[key] == token.claims.get(key):
                        claims[key] += "-control"
                else:
                    if not self._claims or "claims" not in self._expect.get("probes", {}):
                        raise JWTError(
                            "Claims test requires CLAIMS_FILE and protected probe assertions"
                        )
                    if self._expect["probes"]["claims"] == self._expect["baseline"]:
                        raise JWTError(
                            "Claims probe assertions must differ from the protected baseline"
                        )
                    if all(
                        token.claims.get(key, MISSING) == value
                        for key, value in self._claims.items()
                    ):
                        raise JWTError("Selected claims probe must change at least one claim")
                    claims.update(self._claims)
                probes[test] = modified(token, claims=claims, key=self._key)
                parse(probes[test], self._maximum)
        return probes

    async def _execute(self, ctx):
        async with ctx:
            ctx.targets = self._scopes
            ctx.report["target_origins"] = self._scopes
            ctx.secrets.extend(self._secrets)
            async with asyncio.timeout(ctx.settings["BUDGET"]):
                await self.assess(ctx)

    async def send(self, ctx, request, label):
        # A response-set session cookie must not authenticate a later missing-token control.
        if time.monotonic() >= ctx.deadline:
            raise TimeoutError("Run time budget exhausted")
        ctx.session("anonymous").cookies.clear()
        return (await execute_request(ctx, request, label=label))[0]

    async def assess(self, ctx):
        for (request, token), probes in zip(self._prepared, self._probe_tokens, strict=True):
            if time.monotonic() >= ctx.deadline:
                raise TimeoutError("Run time budget exhausted")
            result = {
                "kind": "jwt_review",
                "mode": "active" if ctx.settings["ACTIVE"] else "offline",
                "token": token.summary(
                    self._expect.get("issuer", ""), self._expect.get("audience", "")
                ),
                "signature": self._key.verify(token) if self._key else "not_verified",
                "operator_key_strength": self._key.strength if self._key else "not_reviewed",
                "outcome": "reviewed",
            }
            ctx.report["results"].append(result)
            if request:
                register_request_secrets(ctx, request)
                result.update(request_id=request["id"], url=request["url"])
            if not ctx.settings["ACTIVE"]:
                continue
            ctx.add_endpoint(request["url"], request["method"], source="explicit_jwt_request")
            checks = self._expect["baseline"]
            expected = self._expect.get("probes", {})
            baseline = await self.send(ctx, request, "jwt-baseline")
            repeat = await self.send(ctx, request, "jwt-baseline-repeat")
            _, absent = token_position(request, ctx.settings["TOKEN_LOCATION"], remove=True)
            _, invalid = token_position(
                request, ctx.settings["TOKEN_LOCATION"], replacement="fieldkit-invalid-jwt"
            )
            missing = await self.send(ctx, absent, "jwt-missing-control")
            malformed = await self.send(ctx, invalid, "jwt-invalid-control")
            result["baseline"] = response_summary(baseline)
            result["controls"] = {
                "repeat": response_summary(repeat),
                "missing": response_summary(missing),
                "invalid": response_summary(malformed),
            }
            result["outcome"] = "inconclusive"
            if (
                check_response(baseline, checks) is not True
                or check_response(repeat, checks) is not True
            ):
                result["detail"] = (
                    "Repeated baseline did not prove the selected protected identity/resource"
                )
                continue
            if any(
                check_response(control, rule) is not False
                for control in (missing, malformed)
                for rule in [checks, *expected.values()]
            ):
                result["detail"] = "Missing/invalid-token controls did not establish protection"
                continue
            if "claims" in probes and check_response(baseline, expected["claims"]) is not False:
                result["detail"] = "Selected claim outcome is already present in the baseline"
                continue
            observations = []
            for test, compact in probes.items():
                _, changed = token_position(
                    request, ctx.settings["TOKEN_LOCATION"], replacement=compact
                )
                response = await self.send(ctx, changed, "jwt-" + test)
                matched = check_response(response, expected.get(test, checks))
                observation = {
                    "test": test,
                    "response": response_summary(response),
                    "protected_assertions": matched,
                    "outcome": "inconclusive",
                }
                if matched is False and response.status in {401, 403}:
                    observation["outcome"] = "rejected"
                observations.append(observation)
            final = await self.send(ctx, request, "jwt-baseline-after")
            result["baseline_after"] = response_summary(final)
            result["tests"] = observations
            if check_response(final, checks) is not True:
                result["detail"] = "Protected baseline changed during probes"
                continue
            for observation in observations:
                if observation["protected_assertions"] is True:
                    if (
                        observation["test"] == "claims"
                        and self._expect.get("claims_policy", "observe") != "deny"
                    ):
                        observation["outcome"] = "accepted_signed_claims"
                        observation["detail"] = (
                            "Operator-signed claim acceptance observed; no deny policy asserted"
                        )
                        continue
                    observation["outcome"] = "confirmed"
                    ctx.finding(
                        "jwt_" + observation["test"],
                        "JWT "
                        + observation["test"]
                        + " validation permits asserted protected access",
                        request["url"],
                        severity="high",
                        confidence="confirmed",
                        evidence=[
                            baseline.evidence_id,
                            repeat.evidence_id,
                            missing.evidence_id,
                            malformed.evidence_id,
                            observation["response"]["evidence"],
                            final.evidence_id,
                        ],
                        test=observation["test"],
                        policy="operator_expected_deny"
                        if observation["test"] == "claims"
                        else "registered_jwt_validation",
                        assertions="private_operator_identity_or_resource_checks",
                    )
            result["outcome"] = (
                "confirmed"
                if any(item["outcome"] == "confirmed" for item in observations)
                else "observed"
            )
