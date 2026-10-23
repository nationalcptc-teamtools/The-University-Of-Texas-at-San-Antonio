"""Bounded unknown-field discovery from explicitly selected working requests."""

import copy
import html
import json
import math
import os
import re
import stat
import uuid
import xml.etree.ElementTree as ET
from itertools import combinations
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS
from fieldkit.core.http import origin
from fieldkit.core.module import Option
from fieldkit.core.profiles import load_profiles
from fieldkit.core.replay import execute_request, resolve_request, validate_request
from fieldkit.core.targets import read_targets, target_urls
from fieldkit.core.urls import normalize_url, resolve_url
from fieldkit.core.xml import parse_xml
from fieldkit.modules.assessment_helpers import (
    looks_like_login,
    response_similarity,
    response_summary,
)
from fieldkit.modules.request_replay import REPLAY_OPTIONS, RequestReplay

MISSING = object()


def pointer_tokens(pointer):
    if pointer == "":
        return []
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValueError("JSON parent/acceptance locations require an RFC 6901 JSON pointer")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def at_pointer(value, pointer):
    for part in pointer_tokens(pointer):
        try:
            if isinstance(value, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", part):
                    return MISSING
                value = value[int(part)]
            elif isinstance(value, dict):
                value = value[part]
            else:
                return MISSING
        except (KeyError, IndexError, ValueError):
            return MISSING
    return value


def layout(request, settings):
    """Return a supported container without modifying any captured baseline field."""
    location = settings["LOCATION"]
    if location == "auto":
        location = next((k for k in ("form", "json", "xml") if k in request), "")
        if not location and isinstance(request.get("data"), dict):
            location = "form"
    if location not in {"form", "json", "xml", "query"}:
        raise ValueError("Select a supported body format or explicitly choose query discovery")
    if location != "query" and request["method"] not in {"POST", "PUT", "PATCH"}:
        raise ValueError("Body discovery requires a captured POST, PUT or PATCH request")
    if location == "form":
        key = "form" if isinstance(request.get("form"), dict) else "data"
        if not isinstance(request.get(key), dict):
            raise ValueError("Form discovery requires captured form fields")
        return location, key, set(request[key])
    if location == "json":
        if "json" not in request:
            raise ValueError("JSON discovery requires a JSON request body")
        parent = at_pointer(request["json"], settings["JSON_PARENT"])
        if not isinstance(parent, dict):
            raise ValueError("JSON_PARENT must select exactly one existing JSON object")
        return location, settings["JSON_PARENT"], set(parent)
    if location == "xml":
        if not isinstance(request.get("xml"), str):
            raise ValueError("XML discovery requires an XML request body")
        root, _ = parse_xml(request["xml"].encode())
        try:
            nodes = (
                [root] if settings["XML_PARENT"] == "." else root.findall(settings["XML_PARENT"])
            )
        except (SyntaxError, KeyError) as exc:
            raise ValueError("XML_PARENT requires an ElementTree expanded namespace path") from exc
        if len(nodes) != 1:
            raise ValueError("XML_PARENT must select exactly one existing element")
        existing = {node.tag.rsplit("}", 1)[-1] for node in nodes[0]}
        return location, settings["XML_PARENT"], existing
    names = {key for key, _ in parse_qsl(urlsplit(request["url"]).query, keep_blank_values=True)}
    names.update(request.get("query", {}))
    return location, "", names


def add_field(request, container, name, value):
    """Add a new field to a cloned container; this is distinct from replay's edit API."""
    location, parent, existing = container
    if name in existing:
        raise ValueError("Candidate already exists in the captured request")
    changed = copy.deepcopy(request)
    if location == "form":
        changed[parent][name] = value
    elif location == "json":
        at_pointer(changed["json"], parent)[name] = value
    elif location == "xml":
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", name):
            raise ValueError("XML candidates must be unqualified element names")
        root, _ = parse_xml(changed["xml"].encode())
        node = root if parent == "." else root.findall(parent)[0]
        namespace = node.tag.split("}", 1)[0] + "}" if node.tag.startswith("{") else ""
        ET.SubElement(node, namespace + name).text = value
        changed["xml"] = ET.tostring(root, encoding="unicode")
    else:
        changed.setdefault("query", {})[name] = value
    return validate_request(changed)


def working(response):
    return bool(
        not response.error
        and response.status is not None
        and 200 <= response.status < 300
        and not looks_like_login(response)
    )


def similarity(left, right, substitutions=()):
    if left.status != right.status or left.content_type.split(";", 1)[0].lower() != (
        right.content_type.split(";", 1)[0].lower()
    ):
        return 0.0
    left, right = copy.copy(left), copy.copy(right)
    # Unknown-field errors commonly echo the field name; encoded marker readbacks also
    # occur in JSON/HTML responses. Replace complete tokens in one pass so short names
    # cannot alter unrelated words or already normalized placeholders.
    variants = {
        encoded.encode()
        for value in substitutions
        for encoded in (
            value,
            json.dumps(value, ensure_ascii=True)[1:-1],
            json.dumps(value, ensure_ascii=False)[1:-1],
            html.escape(value),
            html.escape(value, quote=False),
            quote(value, safe=""),
            quote_plus(value, safe=""),
        )
        if encoded
    }
    if variants:
        pattern = re.compile(
            rb"(?<![A-Za-z0-9_.-])(?:"
            + b"|".join(re.escape(value) for value in sorted(variants, key=len, reverse=True))
            + rb")(?![A-Za-z0-9_.-])"
        )
        left.body = pattern.sub(b"FIELDKIT_MARKER", left.body)
        right.body = pattern.sub(b"FIELDKIT_MARKER", right.body)
    return 1.0 if left.body == right.body else response_similarity(left, right)


def response_value(response, pointer):
    if len(response.body) > 131072:
        return MISSING
    try:
        return at_pointer(json.loads(response.body), pointer)
    except (ValueError, UnicodeError, RecursionError):
        return MISSING


def read_names(filename, maximum):
    descriptor = os.open(Path(filename).expanduser(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Candidate names require an explicit regular file")
        content = stream.read(min(maximum, 1048576) + 1)
    if len(content) > min(maximum, 1048576):
        raise ValueError("Candidate names file exceeds MAX_BYTES or the 1 MiB wordlist cap")
    try:
        return [
            line.strip()
            for line in content.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except UnicodeError as exc:
        raise ValueError("Candidate names file must be UTF-8") from exc


class ProbeLimit(Exception):
    """Stop cleanly with existing evidence when an explicit request cap is reached."""


class ParameterDiscovery(RequestReplay):
    name = "web/parameter-discovery"
    description = (
        "Discover unknown fields in selected authenticated requests using repeated baselines "
        "and unknown-name controls; parameter acceptance does not establish a vulnerability."
    )
    options = (
        tuple(
            Option(o.name, o.kind, 0, o.description, o.flag) if o.name == "RETRIES" else o
            for o in COMMON_OPTIONS
        )
        + REPLAY_OPTIONS
        + (
            Option("NAMES", list, [], "Explicit candidate field name (repeat)", "--name"),
            Option("NAMES_FILE", str, "", "Local candidate names, one per line", "--names-file"),
            Option("LOCATION", str, "auto", "auto, form, json, xml, or query", "--location"),
            Option(
                "JSON_PARENT",
                str,
                "",
                "JSON pointer to receiving object; empty is root",
                "--json-parent",
            ),
            Option("XML_PARENT", str, ".", "XML receiving parent ElementTree path", "--xml-parent"),
            Option(
                "VALUE", str, "fieldkit-marker", "Benign scalar marker for candidates", "--value"
            ),
            Option(
                "CONFIRM_PROBES",
                bool,
                False,
                "Authorize repeated active field probes",
                "--confirm-probes",
            ),
            Option(
                "MAX_NAMES", int, 100, "Maximum selected candidate names (1-1000)", "--max-names"
            ),
            Option(
                "MAX_PROBES",
                int,
                100,
                "Maximum added-field requests, including unknown controls (1-10000)",
                "--max-probes",
            ),
            Option(
                "MIN_SIMILARITY",
                float,
                0.98,
                "Minimum repeated baseline/control similarity",
                "--min-similarity",
            ),
            Option(
                "ACCEPTANCE_POINTER",
                str,
                "",
                "Optional response JSON pointer requiring exact value readback",
                "--acceptance-pointer",
            ),
        )
    )

    def validate(self, settings):
        super().validate(settings)
        if settings["EDITS_FILE"] or settings["CONTROL_FILE"]:
            raise ValueError("Parameter discovery uses captured baselines and generated controls")
        if settings["RETRIES"] != 0:
            raise ValueError(
                "Parameter discovery requires RETRIES=0 for bounded request accounting"
            )
        if not settings["CONFIRM_PROBES"] and not settings["DRY_RUN"]:
            raise ValueError(
                "Active parameter discovery requires CONFIRM_PROBES; use DRY_RUN to plan"
            )
        if settings["LOCATION"] not in {"auto", "form", "json", "xml", "query"}:
            raise ValueError("LOCATION must be auto, form, json, xml, or query")
        for key, maximum in (("MAX_NAMES", 1000), ("MAX_PROBES", 10000), ("MAX_REQUESTS", 10000)):
            if type(settings[key]) is not int or not 1 <= settings[key] <= maximum:
                raise ValueError(f"{key} must be 1-{maximum}")
        if not math.isfinite(settings["MIN_SIMILARITY"]) or not 0 < settings["MIN_SIMILARITY"] <= 1:
            raise ValueError("MIN_SIMILARITY must be finite and greater than zero through one")
        if not math.isfinite(settings["BUDGET"]) or not 0 < settings["BUDGET"] <= 3600:
            raise ValueError("BUDGET must be finite and greater than zero through 3600 seconds")
        if (
            not isinstance(settings["VALUE"], str)
            or not 1 <= len(settings["VALUE"]) <= 256
            or any(ord(char) < 32 or ord(char) == 127 for char in settings["VALUE"])
        ):
            raise ValueError("VALUE must be a benign 1-256 character marker without controls")
        pointer_tokens(settings["JSON_PARENT"])
        if settings["ACCEPTANCE_POINTER"]:
            pointer_tokens(settings["ACCEPTANCE_POINTER"])
        names = list(settings["NAMES"])
        if settings["NAMES_FILE"]:
            names.extend(read_names(settings["NAMES_FILE"], settings["MAX_BYTES"]))
        if not names or any(
            not isinstance(name, str)
            or not 1 <= len(name) <= 128
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            for name in names
        ):
            raise ValueError("Supply bounded nonempty candidate names without control characters")
        self._names = list(dict.fromkeys(names))
        if len(self._names) > settings["MAX_NAMES"]:
            raise ValueError("Selected candidate names exceed MAX_NAMES")
        self.preflight(settings)

    def preflight(self, settings):
        """Resolve scope/profile selections even in a plan, without opening HTTP clients."""
        if not (settings["TARGETS"] or settings["TARGETS_FILE"]):
            return  # NetworkModule.run requires target scope before invoking validation.
        alternatives = [
            target_urls(target, settings["SCHEME"])
            for target in read_targets(settings["TARGETS"], settings["TARGETS_FILE"])
        ]
        if any(len(group) != 1 for group in alternatives):
            raise ValueError(
                "Parameter discovery requires explicit target schemes or SCHEME=http/https; "
                "automatic scheme probes cannot precede the request cap"
            )
        origins = list(dict.fromkeys(normalize_url(group[0]) for group in alternatives))
        profiles = load_profiles(settings["PROFILES_FILE"])
        plan = SimpleNamespace(
            settings=settings,
            targets=origins,
            profiles=profiles,
            secrets=[],
            resolve=lambda reference, base: resolve_url(reference, base, origins),
        )
        for request in self._requests:
            resolved = resolve_request(plan, request)
            profile = profiles[request.get("profile", settings["PROFILE"])]
            if profile.origins and origin(resolved["url"]) not in {
                origin(url) for url in profile.origins
            }:
                raise ValueError("Selected request origin is outside its session profile scope")

    async def assess(self, ctx):
        # Resolve every selected URL/profile before replaying any selected operation.
        prepared = [resolve_request(ctx, request) for request in self._requests]
        self._sent = 0  # Preflight prevents preparatory automatic scheme requests.
        self._probes = 0
        value = ctx.settings["VALUE"]
        second_value = "fieldkit-" + uuid.uuid4().hex
        if second_value == value:
            second_value += "-second"
        ctx.secrets.extend((value, second_value))
        try:
            for request in prepared:
                await self.discover(ctx, request, value, second_value)
        except ProbeLimit:
            ctx.report["partial"] = True
            ctx.report["errors"].append(
                {
                    "error": "probe_limit",
                    "detail": "Request/probe cap reached; discovery is incomplete",
                }
            )
        finally:
            ctx.report["parameter_discovery"] = {
                "requests_sent": self._sent,
                "added_field_requests": self._probes,
                "candidate_names": len(self._names),
                "vulnerability_claimed": False,
            }

    async def send(self, ctx, request, label, *, probe=False):
        if self._sent >= ctx.settings["MAX_REQUESTS"] or (
            probe and self._probes >= ctx.settings["MAX_PROBES"]
        ):
            raise ProbeLimit
        self._sent += 1
        self._probes += int(probe)
        response, _ = await execute_request(ctx, request, label=label)
        return response

    async def discover(self, ctx, request, value, second_value):
        result = {
            "kind": "parameter_discovery",
            "request_id": request["id"],
            "url": request["url"],
            "method": request["method"],
            "outcome": "inconclusive",
            "baselines": [],
            "controls": [],
            "candidates": [],
            "vulnerability_claimed": False,
        }
        ctx.report["results"].append(result)
        try:
            container = layout(request, ctx.settings)
        except ValueError as exc:
            result.update(outcome="unsupported", detail=str(exc))
            return
        result["location"] = container[0]
        candidates = []
        for name in self._names:
            item = {"name": name, "outcome": "inconclusive", "probes": []}
            result["candidates"].append(item)
            try:
                added = add_field(request, container, name, value)
            except ValueError as exc:
                item.update(outcome="unsupported", detail=str(exc))
            else:
                candidates.append((name, item, added))
        if not candidates:
            result.update(outcome="unsupported", detail="No unknown supported candidates")
            return
        baselines = []
        for index in range(3):
            response = await self.send(ctx, request, f"baseline-{index + 1}")
            result["baselines"].append(response_summary(response))
            baselines.append(response)
            if not working(response):
                result["detail"] = "A baseline failed, expired authentication, or resembled a login"
                return
        minimum = ctx.settings["MIN_SIMILARITY"]
        result["baseline_similarity"] = min(
            similarity(left, right) for left, right in combinations(baselines, 2)
        )
        if result["baseline_similarity"] < minimum:
            result["detail"] = "Repeated baseline responses are unstable; no candidate probes sent"
            return
        controls, control_names = [], []
        for index in range(2):
            name = "fieldkit_unknown_" + uuid.uuid4().hex
            while name in container[2] or name in self._names:
                name = "fieldkit_unknown_" + uuid.uuid4().hex
            control_names.append(name)
            response = await self.send(
                ctx,
                add_field(request, container, name, value),
                f"unknown-name-control-{index + 1}",
                probe=True,
            )
            result["controls"].append(response_summary(response))
            controls.append(response)
            if (
                response.error
                or looks_like_login(response)
                or response.status
                not in (
                    *range(200, 300),
                    400,
                    422,
                )
            ):
                result["detail"] = "Unknown-field controls failed or changed authentication"
                return
        if similarity(controls[0], controls[1], control_names) < minimum:
            result["detail"] = "Unknown-field controls are unstable; no candidate probes sent"
            return
        control = controls[0]
        if working(control) and similarity(baselines[0], control) < minimum:
            result["detail"] = (
                "Arbitrary unknown fields change responses; cannot isolate a candidate"
            )
            return
        result["outcome"] = "observed"
        ctx.add_endpoint(request["url"], request["method"], source="explicit_request")
        for name, item, added in candidates:
            first = await self.send(ctx, added, "candidate", probe=True)
            item["probes"].append(response_summary(first))
            if first.error or looks_like_login(first) or first.status in {401, 403, 429}:
                item["detail"] = "Candidate response failed or changed authentication"
                result.update(
                    outcome="inconclusive", detail="Candidate session failed; probes stopped"
                )
                return
            substitutions = (name, *control_names, value, second_value)
            signalled = similarity(first, control, substitutions) < minimum
            if not signalled:
                item.update(
                    outcome="no_signal", detail="Indistinguishable from unknown-name controls"
                )
                continue
            second = await self.send(
                ctx,
                add_field(request, container, name, second_value),
                "candidate-confirmation",
                probe=True,
            )
            item["probes"].append(response_summary(second))
            if second.error or looks_like_login(second) or second.status in {401, 403, 429}:
                item["detail"] = "Confirmation failed or changed authentication"
                result.update(
                    outcome="inconclusive", detail="Confirmation session failed; probes stopped"
                )
                return
            if (
                similarity(first, second, (value, second_value)) < minimum
                or similarity(second, control, substitutions) >= minimum
            ):
                item["detail"] = "Candidate differential did not repeat reliably"
                continue
            item.update(
                outcome="signal", detail="Repeated candidate-specific response differential"
            )
            pointer = ctx.settings["ACCEPTANCE_POINTER"]
            if (
                pointer
                and working(first)
                and working(second)
                and (
                    response_value(first, pointer) == value
                    and response_value(second, pointer) == second_value
                    and all(
                        response_value(r, pointer) not in (value, second_value)
                        for r in (*baselines, *controls)
                    )
                )
            ):
                item.update(
                    outcome="confirmed_acceptance",
                    detail="Configured response location returned both distinct candidate values",
                )
            evidence = [
                *[r.evidence_id for r in baselines],
                *[r.evidence_id for r in controls],
                first.evidence_id,
                second.evidence_id,
            ]
            ctx.finding(
                "parameter_acceptance",
                "Review candidate input behavior",
                request["url"],
                severity="info",
                confidence="observed",
                evidence=evidence,
                request_id=request["id"],
                method=request["method"],
                probe_location=f"{container[0]}:{container[1]}:{name}",
                parameter=name,
                outcome=item["outcome"],
                note=(
                    "Field recognition/readback is an observation; "
                    "exploitability and impact are unverified"
                ),
            )
