"""Local request vault, route/ID correlation, artifacts, hypotheses and report drafts."""

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from fieldkit.core.correlation import (
    actuator,
    auth_flow,
    capture_order,
    detect_format,
    javascript_routes,
    library_candidates,
    openapi_routes,
    public_secret_candidates,
    request_values,
    response_body,
    route_identifiers,
    semantic_type,
    transformations,
)
from fieldkit.core.ingest import ingest, load_json
from fieldkit.core.local import LOCAL_OPTIONS, LocalModule
from fieldkit.core.module import Option
from fieldkit.core.redaction import redact
from fieldkit.core.vault import Vault, digest
from fieldkit.modules.nmap_import import read_bounded
from fieldkit.modules.report_export import markdown_report

VAULT_OPTIONS = (
    Option(
        "DATABASE", str, "artifacts/fieldkit.sqlite", "Private SQLite evidence vault", "--database"
    ),
    Option("HOST", str, "", "Passive host/asset filter or imported artifact context", "--host"),
    Option("MAX_RECORDS", int, 1000, "Maximum records to inspect/import", "--max-records"),
)


class VaultModule(LocalModule):
    options = LOCAL_OPTIONS + VAULT_OPTIONS

    def validate(self, settings):
        if not settings["DATABASE"] or settings["MAX_RECORDS"] <= 0:
            raise ValueError("DATABASE and positive MAX_RECORDS are required")

    def observations(self, ctx, records):
        for record in records:
            ctx.check_deadline()
            reference = ctx.evidence(record, source="vault:" + record["id"])
            ctx.report["results"].append(
                {**record, "evidence": [reference], "vault_evidence": record["id"]}
            )

    def requests(self, ctx, vault):
        rows = vault.records("request", private=True, limit=ctx.settings["MAX_RECORDS"] + 1)
        if len(rows) > ctx.settings["MAX_RECORDS"]:
            ctx.error("record_limit", "vault", "Coverage limited to MAX_RECORDS")
        return [
            r
            for r in rows[: ctx.settings["MAX_RECORDS"]]
            if not ctx.settings["HOST"]
            or urlsplit(r["data"]["request"]["url"]).hostname == ctx.settings["HOST"]
        ]


class EvidenceIngest(VaultModule):
    name = "evidence/ingest"
    description = "Passively ingest HAR, Burp XML, raw HTTP, reports, documents and artifacts."
    options = VaultModule.options + (
        Option("INPUT", list, [], "Explicit local source file (repeat)", "--input"),
        Option(
            "FORMAT",
            str,
            "auto",
            "auto, har, burp, raw, report, js, openapi, actuator, oidc, artifact",
            "--format",
        ),
        Option("RAW_URL", str, "", "Origin for raw HTTP imports", "--raw-url"),
        Option("TAGS", list, [], "Operator supplied feature tags (repeat)", "--tag"),
        Option("USER", str, "", "Operator supplied user context", "--user"),
        Option(
            "ROLE", str, "", "Operator supplied role context; no permission inference", "--role"
        ),
    )

    def validate(self, settings):
        super().validate(settings)
        if not settings["INPUT"] or settings["FORMAT"] not in {
            "auto",
            "har",
            "burp",
            "raw",
            "report",
            "js",
            "openapi",
            "actuator",
            "oidc",
            "artifact",
        }:
            raise ValueError("Supply explicit input files and a supported FORMAT")

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"]) as vault:
            for filename in ctx.settings["INPUT"]:
                ctx.check_deadline()
                content = read_bounded(filename, ctx.settings["MAX_BYTES"])
                format_name = ctx.settings["FORMAT"]
                if format_name == "auto":
                    suffix = Path(filename).suffix.lower()
                    format_name = {".har": "har", ".xml": "burp", ".http": "raw", ".js": "js"}.get(
                        suffix, "artifact"
                    )
                    if suffix == ".json":
                        value = load_json(content)
                        format_name = (
                            "har" if isinstance(value, dict) and "log" in value else "report"
                        )
                try:
                    ids = ingest(
                        vault,
                        content,
                        format_name,
                        filename,
                        maximum=ctx.settings["MAX_RECORDS"],
                        tags=ctx.settings["TAGS"],
                        raw_url=ctx.settings["RAW_URL"],
                        context={
                            "user": ctx.settings["USER"],
                            "role": ctx.settings["ROLE"],
                            "host": ctx.settings["HOST"],
                        },
                    )
                except (ValueError, KeyError, TypeError, UnicodeError) as exc:
                    ctx.error("import_error", filename, str(exc))
                    continue
                ctx.report["results"].append(
                    {
                        "kind": "vault_import",
                        "source": filename,
                        "format": format_name,
                        "sha256": digest(content),
                        "record_ids": ids,
                        "database": ctx.settings["DATABASE"],
                        "private_raw": True,
                    }
                )
            ctx.report["vault"] = {
                "file": str(vault.path),
                "contains_credentials": True,
                "authorized_scope": False,
                "permissions": "0600",
            }


class RequestVault(VaultModule):
    name = "web/request-vault"
    description = "List/filter captured requests and export explicitly selected replay templates."
    options = VaultModule.options + (
        Option("REQUEST_IDS", list, [], "Explicit request ID/index to export", "--request-id"),
        Option("TAG", str, "", "Feature tag filter", "--tag"),
        Option("USER", str, "", "Captured user filter", "--user"),
        Option("ROLE", str, "", "Captured role filter", "--role"),
    )

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            records = self.requests(ctx, vault)
            selected = [
                r
                for r in records
                if (not ctx.settings["TAG"] or ctx.settings["TAG"] in r["data"]["tags"])
                and (
                    not ctx.settings["USER"]
                    or r["data"]["context"].get("user") == ctx.settings["USER"]
                )
                and (
                    not ctx.settings["ROLE"]
                    or r["data"]["context"].get("role") == ctx.settings["ROLE"]
                )
            ]
            self.observations(ctx, [vault.get(r["id"]) for r in selected])
            if ctx.settings["REQUEST_IDS"]:
                templates = [
                    vault.request(identifier) for identifier in ctx.settings["REQUEST_IDS"]
                ]
                from fieldkit.core.assessment import write_private

                write_private(
                    ctx.store.root / "private-request-templates.json",
                    json.dumps(templates, indent=2),
                )
                ctx.report["private_templates"] = {
                    "file": "private-request-templates.json",
                    "contains_credentials": True,
                    "executed": False,
                    "permissions": "0600",
                }


class RouteMapper(VaultModule):
    name = "web/routes"
    description = "Merge observed HTTP, JavaScript, OpenAPI and Actuator routes with provenance."

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            routes = []
            for row in self.requests(ctx, vault):
                request = row["data"]["request"]
                routes.append(
                    (
                        {
                            "url": request["url"],
                            "path": urlsplit(request["url"]).path,
                            "method": request["method"],
                            "source_kind": "traffic",
                            "asset": row["data"]["asset"],
                        },
                        row["id"],
                    )
                )
                try:
                    document = load_json(response_body(row))
                    routes.extend(
                        (
                            {
                                **r,
                                "url": urljoin_origin(request["url"], r["path"]),
                                "source_kind": "actuator",
                                "asset": row["data"]["asset"],
                            },
                            row["id"],
                        )
                        for r in actuator(document, ctx.settings["MAX_RECORDS"] + 1)["routes"]
                    )
                except (ValueError, UnicodeError):
                    pass
            for row in vault.records("document", private=True, limit=ctx.settings["MAX_RECORDS"]):
                format_name = row["data"]["format"]
                document = row["data"]["document"]
                found = (
                    openapi_routes(document)
                    if format_name == "openapi"
                    else actuator(document, ctx.settings["MAX_RECORDS"] + 1)["routes"]
                    if format_name == "actuator"
                    else []
                )
                routes.extend(
                    (
                        {"asset": row["data"].get("asset", ""), "source_kind": format_name, **r},
                        row["id"],
                    )
                    for r in found
                )
            for row in vault.records("artifact", limit=ctx.settings["MAX_RECORDS"]):
                if row["source"].get("format") == "js":
                    routes.extend(
                        ({**r, "asset": row["data"]["asset"]}, row["id"])
                        for r in javascript_routes(
                            read_bounded(row["data"]["file"], ctx.settings["MAX_BYTES"])
                        )
                    )
            seen = set()
            for route, source in routes[: ctx.settings["MAX_RECORDS"]]:
                asset = route.get("asset", "")
                if not route.get("url") and str(asset).startswith("asset-"):
                    route["url"] = vault.get(asset)["data"]["origin"] + route["path"]
                if (
                    ctx.settings["HOST"]
                    and route.get("url")
                    and urlsplit(route["url"]).hostname != ctx.settings["HOST"]
                ):
                    continue
                key = [
                    route.get("asset"),
                    route.get("url"),
                    route["path"],
                    route.get("method", "ANY"),
                ]
                known = "route-" + digest(key)[:24]
                try:
                    previous = vault.get(known)["data"]
                except ValueError:
                    previous = {}
                route["source_kinds"] = sorted(
                    set([*previous.get("source_kinds", []), route["source_kind"]])
                )
                identifier = vault.put("route", route, source={"evidence": source}, identity=key)
                vault.link(source, identifier, "route_source")
                seen.add(identifier)
            if len(routes) > ctx.settings["MAX_RECORDS"]:
                ctx.error("record_limit", "routes")
            self.observations(
                ctx, [{**vault.get(i), "provenance": vault.links(i)} for i in sorted(seen)]
            )


def urljoin_origin(url, path):
    parsed = urlsplit(url)
    return parsed.scheme + "://" + parsed.netloc + path


class IDMapper(VaultModule):
    name = "web/ids"
    description = "Trace typed response IDs into known captured requests without enumeration."
    options = VaultModule.options + (
        Option("ROUTE", str, "", "Route template, e.g. /shipment-jobs/{id}/export", "--route"),
    )

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            requests = self.requests(ctx, vault)
            identifiers, indexed = [], {}
            limited = False
            for row in requests:
                ctx.check_deadline()
                if len(identifiers) >= ctx.settings["MAX_RECORDS"]:
                    limited = True
                    break
                try:
                    document = load_json(response_body(row))
                except (ValueError, UnicodeError):
                    continue
                for observation in route_identifiers(
                    document, urlsplit(row["data"]["request"]["url"]).path
                ):
                    if len(identifiers) >= ctx.settings["MAX_RECORDS"]:
                        limited = True
                        break
                    identifier = vault.put(
                        "identifier",
                        {
                            **observation,
                            "asset": row["data"]["asset"],
                            "response_request": row["id"],
                            "source_index": row["source"].get("index"),
                        },
                        source={"request": row["id"], "pointer": observation["pointer"]},
                    )
                    vault.link(row["id"], identifier, "response_identifier")
                    item = (identifier, observation, row)
                    identifiers.append(item)
                    indexed.setdefault(
                        (row["data"]["asset"], str(observation["value"])), []
                    ).append(item)
            route = ctx.settings["ROUTE"]
            pattern = (
                re.compile("^" + re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(route)) + "$")
                if route
                else None
            )
            expected = semantic_type("/id", route.split("/{", 1)[0]) if route else None
            matches = []
            for request_row in requests:
                ctx.check_deadline()
                if len(matches) >= ctx.settings["MAX_RECORDS"]:
                    limited = True
                    break
                request = request_row["data"]["request"]
                if pattern and not pattern.fullmatch(urlsplit(request["url"]).path):
                    continue
                for location, value in request_values(request):
                    candidates = [
                        (i, obs, source)
                        for i, obs, source in indexed.get(
                            (request_row["data"]["asset"], str(value)), []
                        )
                        if capture_order(source, request_row) is not None
                    ]
                    for identifier, observation, source in candidates:
                        if len(matches) >= ctx.settings["MAX_RECORDS"]:
                            limited = True
                            break
                        result = {
                            "kind": "id_link",
                            "request_id": request_row["id"],
                            "url": request["url"],
                            "location": location,
                            "identifier": identifier,
                            **observation,
                            "response_request": source["id"],
                            "source_index": source["source"].get("index"),
                            "expected_type": expected,
                            "type_matches_route": expected == observation["semantic_type"]
                            if expected
                            else None,
                            "ambiguous": len({c[1]["semantic_type"] for c in candidates}) > 1,
                            "ordering": capture_order(source, request_row),
                            "note": "Value equality is an observed link; "
                            "type inference requires operator review",
                        }
                        vault.link(
                            identifier, request_row["id"], "used_in_request", {"location": location}
                        )
                        matches.append(result)
            if limited:
                ctx.error("record_limit", "identifiers", "ID/link coverage limited to MAX_RECORDS")
            for result in matches[: ctx.settings["MAX_RECORDS"]]:
                ctx.report["results"].append(result)
            ctx.report["identifier_summary"] = {
                "observed_ids": len(identifiers),
                "request_links": len(matches),
                "enumerated": False,
            }


class ActuatorAnalyzer(VaultModule):
    name = "web/actuator-analyze"
    description = "Analyze captured Actuator exposures, routes, configuration and dependency clues."

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            rows = [
                (row, row["data"]["document"])
                for row in vault.records(
                    "document", private=True, limit=ctx.settings["MAX_RECORDS"]
                )
                if row["data"]["format"] == "actuator"
            ]
            for row in self.requests(ctx, vault):
                if "actuator" in row["data"]["request"]["url"]:
                    try:
                        rows.append((row, load_json(response_body(row))))
                    except (ValueError, UnicodeError):
                        ctx.error("invalid_actuator_json", row["id"])
            for row, document in rows:
                analysis = actuator(document, ctx.settings["MAX_RECORDS"])
                if analysis["coverage_limited"]:
                    ctx.error("record_limit", row["id"], "Actuator analysis coverage limited")
                identifier = vault.put(
                    "observation",
                    {
                        "kind": "actuator_analysis",
                        "asset": row["data"].get("asset", ""),
                        **analysis,
                        "outcome": "observed",
                        "credentials_valid": False,
                    },
                    source={"evidence": row["id"]},
                )
                vault.link(row["id"], identifier, "actuator_analysis")
                for secret in analysis["secrets"]:
                    candidate = vault.put(
                        "secret",
                        {**secret, "asset": row["data"].get("asset", "")},
                        source={"evidence": row["id"]},
                    )
                    vault.link(row["id"], candidate, "secret_candidate")
                self.observations(ctx, [vault.get(identifier)])


class ArtifactTriage(VaultModule):
    name = "artifacts/triage"
    description = "Trace bounded Base64/compression/archive transformations without deserializing."
    options = VaultModule.options + (
        Option("INPUT", list, [], "Explicit artifact file (repeat)", "--input"),
        Option("ARTIFACT_IDS", list, [], "Vault artifact IDs (repeat)", "--artifact-id"),
        Option("MAX_DEPTH", int, 4, "Transformation depth ceiling", "--max-depth"),
        Option(
            "MAX_TOTAL_BYTES",
            int,
            10485760,
            "Aggregate transformed-byte ceiling",
            "--max-total-bytes",
        ),
        Option("MAX_MEMBERS", int, 100, "Archive member ceiling", "--max-members"),
    )

    def validate(self, settings):
        super().validate(settings)
        if (
            not 0 <= settings["MAX_DEPTH"] <= 10
            or min(settings["MAX_TOTAL_BYTES"], settings["MAX_MEMBERS"]) <= 0
        ):
            raise ValueError("Transformation limits must be positive; depth must be 0-10")

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"]) as vault:
            roots = list(ctx.settings["ARTIFACT_IDS"])
            for filename in ctx.settings["INPUT"]:
                content = read_bounded(filename, ctx.settings["MAX_BYTES"])
                roots.append(
                    vault.artifact(content, source={"file": filename}, asset=ctx.settings["HOST"])
                )
            if not roots:
                raise ValueError("Select explicit INPUT or ARTIFACT_IDS")
            queue = [(identifier, 0, 0) for identifier in roots]
            total, visited, count = 0, set(), 0
            while queue:
                ctx.check_deadline()
                identifier, level, _ = queue.pop(0)
                record = vault.get(identifier)
                if record["kind"] != "artifact":
                    raise ValueError("Selected ID is not an artifact")
                content = read_bounded(record["data"]["file"], ctx.settings["MAX_BYTES"])
                fingerprint = digest(content)
                expansion_key = (record["data"]["asset"], fingerprint)
                already_expanded = expansion_key in visited
                visited.add(expansion_key)
                total += len(content)
                count += 1
                if total > ctx.settings["MAX_TOTAL_BYTES"] or count > ctx.settings["MAX_RECORDS"]:
                    ctx.error("transformation_limit", identifier)
                    break
                observation = {
                    "kind": "artifact_format",
                    "artifact": identifier,
                    "format": detect_format(content),
                    "asset": record["data"]["asset"],
                    "sha256": fingerprint,
                    "bytes": len(content),
                    "depth": level,
                    "transformation": record["data"]["transformation"],
                    "outcome": "observed",
                    "executed": False,
                    "deserialized": False,
                    "expansion_deduplicated": already_expanded,
                    "depth_limited": level >= ctx.settings["MAX_DEPTH"],
                }
                observed = vault.put("observation", observation, source={"artifact": identifier})
                vault.link(identifier, observed, "format_observation")
                self.observations(ctx, [vault.get(observed)])
                if already_expanded or level >= ctx.settings["MAX_DEPTH"]:
                    continue
                try:
                    for operation, child in transformations(
                        content,
                        min(ctx.settings["MAX_BYTES"], ctx.settings["MAX_TOTAL_BYTES"] - total),
                        ctx.settings["MAX_MEMBERS"],
                    ):
                        queued_bytes = sum(size for _, _, size in queue)
                        if total + queued_bytes + len(child) > ctx.settings["MAX_TOTAL_BYTES"]:
                            raise ValueError("Aggregate queued transformation bytes exceeded")
                        if count + len(queue) >= ctx.settings["MAX_RECORDS"]:
                            raise ValueError("Transformation record limit exceeded")
                        child_id = vault.artifact(
                            child,
                            source={"artifact": identifier, "operation": operation},
                            asset=record["data"]["asset"],
                            parent=identifier,
                            transformation=operation,
                        )
                        queue.append((child_id, level + 1, len(child)))
                except (ValueError, OSError) as exc:
                    ctx.error("extraction_limit_or_error", identifier, str(exc))


class SecretCorrelator(VaultModule):
    name = "evidence/correlate"
    description = (
        "Correlate secret fingerprints and dependency candidates across captured evidence."
    )

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            sources = [
                (row, response_body(row) + json.dumps(row["data"]["request"]).encode())
                for row in self.requests(ctx, vault)
            ]
            sources.extend(
                (row, read_bounded(row["data"]["file"], ctx.settings["MAX_BYTES"]))
                for row in vault.records("artifact", limit=ctx.settings["MAX_RECORDS"])
            )
            sources.extend(
                (row, json.dumps(row["data"]["document"]).encode())
                for row in vault.records(
                    "document", private=True, limit=ctx.settings["MAX_RECORDS"]
                )
            )
            seen = set()
            for row, content in sources:
                ctx.check_deadline()
                for kind, candidates in (
                    ("secret", public_secret_candidates(content)),
                    ("dependency", library_candidates(content)),
                ):
                    for candidate in candidates:
                        if len(seen) >= ctx.settings["MAX_RECORDS"]:
                            ctx.error("record_limit", "correlation")
                            break
                        candidate["asset"] = row["data"].get("asset", "")
                        key = [
                            candidate["asset"],
                            candidate.get("fingerprint"),
                            candidate.get("package"),
                            candidate.get("version"),
                        ]
                        identifier = vault.put(
                            kind, candidate, source={"evidence": row["id"]}, identity=key
                        )
                        vault.link(row["id"], identifier, kind + "_candidate")
                        seen.add(identifier)
            self.observations(
                ctx,
                [
                    {**vault.get(identifier), "provenance": vault.links(identifier)}
                    for identifier in sorted(seen)
                ],
            )


class AuthFlowMapper(VaultModule):
    name = "web/auth-flow-map"
    description = "Map observed OIDC/redirect/PKCE/client/token claims without validating tokens."

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            observations = []
            for row in self.requests(ctx, vault):
                flow = auth_flow(row)
                if flow["client_id"] or flow["tokens"] or flow["observed_redirect"]:
                    identifier = vault.put(
                        "observation",
                        {"kind": "auth_flow", "asset": row["data"]["asset"], **flow},
                        source={"request": row["id"]},
                    )
                    vault.link(row["id"], identifier, "auth_flow")
                    observations.append(vault.get(identifier))
            for row in vault.records("document", private=True, limit=ctx.settings["MAX_RECORDS"]):
                if row["data"]["format"] == "oidc":
                    doc = row["data"]["document"]
                    if not isinstance(doc, dict):
                        raise ValueError("OIDC discovery must be an object")
                    observations.append(
                        {
                            "id": row["id"],
                            "kind": "oidc_discovery",
                            "data": {
                                k: doc.get(k)
                                for k in (
                                    "issuer",
                                    "authorization_endpoint",
                                    "token_endpoint",
                                    "jwks_uri",
                                    "scopes_supported",
                                    "code_challenge_methods_supported",
                                )
                            },
                            "fetched": False,
                        }
                    )
            self.observations(ctx, observations)
            # JSON labels prevent evidence from changing Mermaid syntax.
            edges = []
            for i, observation in enumerate(observations):
                data = observation["data"]
                client = data.get("client_id") or "Unknown client"
                edges.append(f"  request{i} --> client{i}[{json.dumps(redact(client))}]")
                for j, token in enumerate(data.get("tokens", [])):
                    claims = token["claims"]
                    subject = claims.get("sub", "Unknown subject")
                    audience = claims.get("aud", "Unknown audience")
                    label = json.dumps(redact(f"Unverified sub={subject}, aud={audience}"))
                    edges.append(f"  client{i} --> token{i}_{j}[{label}]")
            from fieldkit.core.assessment import write_private

            write_private(
                ctx.store.root / "auth-flow.mmd", "flowchart LR\n" + "\n".join(edges) + "\n"
            )


class SerializationWorkbench(VaultModule):
    name = "artifacts/serialization"
    description = "Link observed serialization formats/routes to dependency leads and replay gates."

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            dependencies = vault.records("dependency", limit=ctx.settings["MAX_RECORDS"])
            for observation in vault.records("observation", limit=ctx.settings["MAX_RECORDS"]):
                data = observation["data"]
                if (
                    data.get("kind") != "artifact_format"
                    or "serialization" not in data.get("format", "")
                    and "pickle" not in data.get("format", "")
                ):
                    continue
                associated = [
                    d["id"]
                    for d in dependencies
                    if d["data"].get("asset") and d["data"]["asset"] == data.get("asset")
                ]
                baseline = [
                    w
                    for w in vault.records("workflow", limit=ctx.settings["MAX_RECORDS"])
                    if w["data"].get("artifact") == data.get("artifact")
                    and w["data"].get("baseline_verified")
                ]
                result = {
                    "kind": "serialization_workbench",
                    "format_observation": observation["id"],
                    "artifact": data["artifact"],
                    "format": data["format"],
                    "asset": data.get("asset"),
                    "dependency_evidence": associated,
                    "baseline_verified": bool(baseline),
                    "modified_test_allowed": bool(baseline),
                    "test_family": "format/classpath compatibility review",
                    "outcome": "hypothesized",
                    "supporting_evidence": [observation["id"], *associated],
                    "counterevidence": [] if baseline else ["Unmodified replay is not verified"],
                    "next_test": "Verify an artifact-associated unmodified replay with explicit "
                    "resource checks; review format/classpath compatibility",
                    "note": "No object deserialization or gadget generation. "
                    "Dependencies alone are not vulnerabilities.",
                }
                identifier = vault.put("hypothesis", result, source={"evidence": observation["id"]})
                vault.link(observation["id"], identifier, "serialization_lead")
                self.observations(ctx, [vault.get(identifier)])


class HypothesisQueue(VaultModule):
    name = "evidence/hypotheses"
    description = "Produce reviewable evidence-backed leads, counterevidence and next tests."

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            for row in vault.records("secret", limit=ctx.settings["MAX_RECORDS"]):
                hypothesis = {
                    "title": "Captured credential-shaped value may expose a service",
                    "outcome": "hypothesized",
                    "supporting_evidence": [row["id"]],
                    "counterevidence": [
                        "Value may be stale, masked, synthetic, or restricted to a client identity"
                    ],
                    "next_test": "Review configuration ownership and expected privileges; "
                    "select an authorized control request before validation",
                }
                identifier = vault.put("hypothesis", hypothesis, source={"evidence": row["id"]})
                vault.link(row["id"], identifier, "hypothesis_support")
            self.observations(ctx, vault.records("hypothesis", limit=ctx.settings["MAX_RECORDS"]))


class EvidenceReport(VaultModule):
    name = "evidence/report"
    description = (
        "Draft evidence-linked findings with observed/validated/hypothesized status and notes."
    )
    options = VaultModule.options + (
        Option(
            "FINDINGS_FILE",
            str,
            "",
            "Explicit finding annotations JSON with evidence IDs",
            "--findings-file",
        ),
    )

    async def assess(self, ctx):
        with Vault(ctx.settings["DATABASE"], create=False) as vault:
            if ctx.settings["FINDINGS_FILE"]:
                annotations = json.loads(
                    read_bounded(ctx.settings["FINDINGS_FILE"], ctx.settings["MAX_BYTES"])
                )
                if (
                    not isinstance(annotations, list)
                    or len(annotations) > ctx.settings["MAX_RECORDS"]
                ):
                    raise ValueError("Finding annotations must be a bounded list")
                for finding in annotations:
                    if (
                        not isinstance(finding, dict)
                        or finding.get("validation_status")
                        not in {"observed", "validated", "hypothesized"}
                        or not isinstance(finding.get("evidence"), list)
                        or not finding["evidence"]
                    ):
                        raise ValueError(
                            "Findings require explicit status and nonempty existing evidence IDs"
                        )
                    for reference in finding["evidence"]:
                        vault.get(reference)
                    identifier = vault.put(
                        "finding", finding, source={"file": ctx.settings["FINDINGS_FILE"]}
                    )
                    for reference in finding["evidence"]:
                        vault.link(reference, identifier, "finding_evidence")
            for row in vault.records("finding", limit=ctx.settings["MAX_RECORDS"]):
                finding = {
                    **row["data"],
                    "id": row["id"],
                    "validation_status": row["data"].get("validation_status", "observed"),
                }
                finding["confidence"] = finding["validation_status"]
                ctx.report["findings"].append(finding)
                for reference in finding.get("evidence", []):
                    try:
                        record = vault.get(reference)
                    except ValueError:
                        ctx.error("missing_evidence", reference)
                        continue
                    entry = {
                        "id": reference,
                        "source": "vault:" + reference,
                        "file": str(vault.path),
                        "private_raw": True,
                        "context": record["data"].get("context", {}),
                    }
                    if entry not in ctx.report["evidence"]:
                        ctx.report["evidence"].append(entry)
            ctx.report["hypotheses"] = vault.records(
                "hypothesis", limit=ctx.settings["MAX_RECORDS"]
            )
            from fieldkit.core.assessment import write_private

            write_private(ctx.store.root / "report.md", markdown_report(redact(ctx.report)))
